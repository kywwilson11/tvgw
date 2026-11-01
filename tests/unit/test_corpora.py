"""The extractor against its golden corpus (tests/corpora): every reader of a hello must reach the
same hellos, names and JA4 strings the corpus expects.

Three readers are checked: `tshark.parse_row` on the rows tshark prints for each pcap (synthesised
here; real ones from the Pi under tsv/tshark-<version>/ when committed), `clienthello` on the pcap
bytes themselves, and, where tshark is installed (the Pi), `tshark.extract` on the pcaps. The last
is the differential test the R&D report asks for (state-of-the-art-2026-10, section 11): the same
input through tshark and through our parser, diffed."""

import hashlib
import json
import shutil
import struct
from pathlib import Path

import pytest
from corpus import CORPORA, build

from tvgw import clienthello, tshark

EXPECTED = json.loads((CORPORA / "expected.json").read_text(encoding="utf-8"))
CASES = sorted(EXPECTED)
COMPARED = ("src", "sport", "dst", "dport", "sni", "ech", "ja4", "transport", "partial")


def as_dicts(rows) -> list[dict]:
    return [
        {"t": round(r.t, 6), **{k: getattr(r, k) for k in COMPARED}}
        for r in rows
        if isinstance(r, tshark.TlsHello) and r.src == build.TV
    ]


def expected(case: str) -> list[dict]:
    return [{"t": round(h["t"], 6), **{k: h[k] for k in COMPARED}} for h in EXPECTED[case]["hellos"]]


def test_the_corpus_is_what_the_builder_makes(tmp_path):
    """The committed files are a pure function of build.py: a change to either shows in review."""
    (tmp_path / "expected.json").write_text((CORPORA / "expected.json").read_text(encoding="utf-8"), "utf-8")
    names = build.write(tmp_path)
    assert set(names) <= set(CASES)
    for name in names:
        for sub, ext in (("pcap", "pcap"), ("tsv/synthetic", "tsv")):
            assert (tmp_path / sub / f"{name}.{ext}").read_bytes() == (
                CORPORA / sub / f"{name}.{ext}"
            ).read_bytes()
    assert json.loads((tmp_path / "expected.json").read_text(encoding="utf-8")) == EXPECTED


def test_the_spec_example_is_fingerprinted_as_the_spec_says():
    (hello,) = EXPECTED["spec-example"]["hellos"]
    assert hello["ja4"] == build.SPEC_EXAMPLE_JA4 == "t13d1516h2_8daaf6152771_e5627efa2ab1"


def test_the_corpus_covers_each_case_the_extractor_handles():
    hellos = [h for c in CASES for h in EXPECTED[c]["hellos"]]
    assert any(h["transport"] == "quic" for h in hellos)
    assert any(h["partial"] and h["sni"] for h in hellos) and any(
        h["partial"] and not h["sni"] for h in hellos
    )
    assert any(not h["sni"] and h["ja4"].startswith("t12i") for h in hellos)
    assert any(h["ech"] and h["sni"] == "cloudflare-ech.com" for h in hellos)


@pytest.mark.parametrize("case", CASES)
def test_synthesised_tshark_rows_give_the_expected_hellos(case):
    """Through parse_row and dedupe, as `extract` runs them: the split hello's held-back first
    segment gives way to the reassembled whole, the retransmitted one is dropped."""
    lines = (CORPORA / "tsv" / "synthetic" / f"{case}.tsv").read_text(encoding="utf-8").split("\n")
    rows = [r for line in lines for r in tshark.parse_row(line)]
    assert as_dicts(tshark.dedupe(rows)) == expected(case)


def real_tsv_dirs() -> list[Path]:
    root = CORPORA / "tsv"
    return sorted(p for p in root.glob("tshark-*") if p.is_dir())


@pytest.mark.parametrize(
    "tsv_dir", real_tsv_dirs() or [None], ids=lambda p: p.name if p else "none-committed"
)
def test_rows_from_a_real_tshark_give_the_expected_hellos(tsv_dir):
    """Rows a real tshark printed for the corpus (tests/corpora/README.md says how to make them)."""
    if tsv_dir is None:
        pytest.skip("no real tshark output committed under tests/corpora/tsv/tshark-*")
    for case in CASES:
        path = tsv_dir / f"{case}.tsv"
        if path.exists():
            rows = [
                r for line in path.read_text(encoding="utf-8").split("\n") for r in tshark.parse_row(line)
            ]
            assert as_dicts(tshark.dedupe(rows)) == expected(case), (tsv_dir.name, case)


# ---- the pcap bytes, read without tshark ------------------------------------------------------


def frames(case: str) -> list[tuple[float, bytes]]:
    data = (CORPORA / "pcap" / f"{case}.pcap").read_bytes()
    magic, _, _, _, _, _, linktype = struct.unpack("<IHHiIII", data[:24])
    assert magic == 0xA1B2C3D4 and linktype == 1
    out, pos = [], 24
    while pos < len(data):
        sec, usec, incl, _ = struct.unpack("<IIII", data[pos : pos + 16])
        out.append((sec + usec / 1e6, data[pos + 16 : pos + 16 + incl]))
        pos += 16 + incl
    return out


def ip_payload(frame: bytes) -> tuple[int, bytes]:
    ip = frame[14:]
    return ip[9], ip[(ip[0] & 0x0F) * 4 : struct.unpack("!H", ip[2:4])[0]]


def tcp_stream(case: str) -> bytes:
    """The TV's bytes in sequence order, each sequence number once: what reassembly would see."""
    segs: dict[int, bytes] = {}
    for _, f in frames(case):
        proto, seg = ip_payload(f)
        assert proto == 6
        payload = seg[(seg[12] >> 4) * 4 :]
        if payload:
            segs.setdefault(struct.unpack("!I", seg[4:8])[0], payload)
    out = b""
    for seq in sorted(segs):
        out += segs[seq]
    return out


def quic_crypto(case: str) -> bytes:
    """The CRYPTO frame data of the case's one client Initial, decrypted (RFC 9001 section 5)."""
    pytest.importorskip("cryptography")
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM

    ((_, f),) = frames(case)
    proto, dgram = ip_payload(f)
    assert proto == 17
    pkt = dgram[8:]
    dcid = pkt[6 : 6 + pkt[5]]
    pos = 6 + len(dcid)
    pos += 1 + pkt[pos]  # scid
    pos += 1  # token length 0
    length = struct.unpack("!H", pkt[pos : pos + 2])[0] & 0x3FFF
    pn_at = pos + 2
    key, iv, hp = build.quic_client_keys(dcid)
    enc = Cipher(algorithms.AES(hp), modes.ECB()).encryptor()
    mask = enc.update(pkt[pn_at + 4 : pn_at + 20]) + enc.finalize()
    first = pkt[0] ^ (mask[0] & 0x0F)
    pn_len = (first & 0x03) + 1
    pn = bytes(a ^ b for a, b in zip(pkt[pn_at : pn_at + pn_len], mask[1 : 1 + pn_len], strict=True))
    header = bytes([first]) + pkt[1:pn_at] + pn
    nonce = bytes(a ^ b for a, b in zip(iv, int.from_bytes(pn, "big").to_bytes(12, "big"), strict=True))
    plain = AESGCM(key).decrypt(nonce, pkt[pn_at + pn_len : pn_at + length], header)
    assert plain[0] == 0x06 and plain[1] == 0x00  # CRYPTO at offset 0
    n = struct.unpack("!H", plain[2:4])[0] & 0x3FFF
    return plain[4 : 4 + n]


@pytest.mark.parametrize("case", CASES)
def test_the_pcap_bytes_parse_to_the_expected_hello(case):
    """Our parser on the bytes: a whole hello reaches the expected JA4 and raw form; a cut one keeps
    the name only when its extension was in the bytes kept."""
    (want,) = EXPECTED[case]["hellos"]
    if want["transport"] == "quic":
        h = clienthello.parse_handshake(quic_crypto(case))
    else:
        h = clienthello.parse_record(tcp_stream(case))
    assert h is not None and h.complete is not want["partial"]
    assert (h.sni, h.ech) == (want["sni"], want["ech"])
    if not want["partial"]:
        i = clienthello.from_hello(h, want["transport"])
        assert (clienthello.ja4(i), clienthello.ja4_r(i)) == (want["ja4"], want["ja4_r"])
        a, b, c = want["ja4_r"].split("_", 2)
        sha = hashlib.sha256  # the raw form hashes to the fingerprint, as JA4.md defines it
        hb = sha(b.encode()).hexdigest()[:12] if b else "000000000000"
        hc = sha(c.encode()).hexdigest()[:12] if c else "000000000000"
        assert want["ja4"] == f"{a}_{hb}_{hc}"


@pytest.mark.skipif(shutil.which("tshark") is None, reason="tshark is not installed (it is on the Pi)")
@pytest.mark.parametrize("case", CASES)
def test_tshark_on_the_corpus_pcaps_gives_the_expected_hellos(case):
    """The differential test: the installed tshark, through the same `extract` ingest runs."""
    rows = tshark.extract(str(CORPORA / "pcap" / f"{case}.pcap"), unprivileged=False)
    assert as_dicts(rows) == expected(case)
