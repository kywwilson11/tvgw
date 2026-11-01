"""Build the extractor's golden corpus: small pcaps holding ClientHellos, the tshark rows they should
produce, and the hellos the extractor must return for them.

Run from the checkout:  python3 tests/corpora/build.py  (writes tests/corpora/{pcap,tsv,expected.json})

Everything is synthesised here, byte by byte, so the corpus needs no capture and carries no site
identifier: the TV is 10.10.10.17, servers are in the documentation ranges, MAC addresses are
locally administered. The output is deterministic (fixed randoms, fixed times), and
tests/unit/test_corpora.py checks the committed files against a fresh build.

The expected JA4 strings are computed in this file from each case's lists, by a second
implementation written from the spec (FoxIO JA4.md) that deliberately does not import tvgw: the
extractor's own code must reach the same strings from the bytes and from tshark's fields. The first
case is the spec's own worked example, whose fingerprint is quoted from the spec, not computed.

The QUIC case needs AES (the `cryptography` package) to build, because a QUIC Initial is encrypted
with keys anyone can derive (RFC 9001 section 5.2). Without the package the committed QUIC pcap is
kept as it is.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import struct
from dataclasses import dataclass, field
from pathlib import Path

HERE = Path(__file__).resolve().parent
TV = "10.10.10.17"
AGG = "\x1f"
T0 = 1793020100.0  # 2026-10-26 08:08:20 America/Chicago, inside the unit fixtures' day
TV_MAC = bytes.fromhex("020000000011")  # locally administered: no vendor, no device
GW_MAC = bytes.fromhex("020000000001")
SPEC_EXAMPLE_JA4 = "t13d1516h2_8daaf6152771_e5627efa2ab1"  # quoted from FoxIO JA4.md
GREASE = 0x0A0A
QUIC_V1_SALT = bytes.fromhex("38762cf7f55934b34d179ae6a4c80cadccbb7f0a")  # RFC 9001 section 5.2

# ---- ClientHello bytes ----------------------------------------------------------------------


def u16(n: int) -> bytes:
    return struct.pack("!H", n)


def vec(data: bytes, n: int) -> bytes:
    return len(data).to_bytes(n, "big") + data


def ext_sni(name: str) -> bytes:
    return vec(b"\x00" + vec(name.encode("ascii"), 2), 2)


def ext_alpn(protos: list[bytes]) -> bytes:
    return vec(b"".join(vec(p, 1) for p in protos), 2)


def ext_u16_list(values: list[int], n: int = 2) -> bytes:
    return vec(b"".join(u16(v) for v in values), n)


def ext_key_share(groups: list[tuple[int, int]]) -> bytes:
    """(group, key length) pairs; the key bytes are a fixed pattern."""
    return vec(b"".join(u16(g) + vec(bytes((i * 7) & 0xFF for i in range(n)), 2) for g, n in groups), 2)


@dataclass
class Spec:
    """One ClientHello: the lists JA4 reads, and the extensions in wire order as (type, data)."""

    name: str
    sni: str
    ciphers: list[int]
    extensions: list[tuple[int, bytes]]
    alpn: list[bytes] = field(default_factory=list)
    sig_algs: list[int] = field(default_factory=list)
    supported_versions: list[int] = field(default_factory=list)
    legacy_version: int = 0x0303

    def handshake(self) -> bytes:
        body = u16(self.legacy_version) + bytes(range(32)) + vec(bytes(range(32, 64)), 1)
        body += ext_u16_list(self.ciphers) + vec(b"\x00", 1)
        body += vec(b"".join(u16(t) + vec(d, 2) for t, d in self.extensions), 2)
        return b"\x01" + vec(body, 3)

    def record(self) -> bytes:
        return b"\x16\x03\x01" + vec(self.handshake(), 2)

    def ext_types(self) -> list[int]:
        return [t for t, _ in self.extensions]

    def ext_spans(self) -> list[tuple[int, int, int]]:
        """(type, start, end) of each extension as byte offsets into `record()`."""
        pos = 5 + 4 + 2 + 32 + 1 + 32 + 2 + 2 * len(self.ciphers) + 2 + 2
        out = []
        for t, d in self.extensions:
            out.append((t, pos, pos + 4 + len(d)))
            pos += 4 + len(d)
        return out


def sig_ext_lists(spec: Spec) -> list[tuple[int, list[int]]]:
    """(extension, list) for every extension tshark reports under sig_hash_alg, in wire order."""
    out = []
    for t, d in spec.extensions:
        if t in (0x000D, 0x0032, 0x0022):
            n = int.from_bytes(d[:2], "big")
            out.append((t, [int.from_bytes(d[2 + i : 4 + i], "big") for i in range(0, n, 2)]))
    return out


def standard_exts(
    spec_sni: str | None,
    alpn: list[bytes],
    sigs: list[int],
    versions: list[int],
    extra: list[tuple[int, bytes]] = (),
    late_sni: bool = False,
) -> list[tuple[int, bytes]]:
    exts: list[tuple[int, bytes]] = []
    if spec_sni and not late_sni:
        exts.append((0x0000, ext_sni(spec_sni)))
    exts += [(0x0017, b""), (0xFF01, b"\x00"), (0x000A, ext_u16_list([0x001D, 0x0017, 0x0018]))]
    exts.append((0x000B, b"\x01\x00"))
    if alpn:
        exts.append((0x0010, ext_alpn(alpn)))
    if sigs:
        exts.append((0x000D, ext_u16_list(sigs)))
    if versions:
        exts.append((0x002B, vec(b"".join(u16(v) for v in versions), 1)))
    exts += list(extra)
    if spec_sni and late_sni:
        exts.append((0x0000, ext_sni(spec_sni)))
    return exts


CHROME_SIGS = [0x0403, 0x0804, 0x0401, 0x0503, 0x0805, 0x0501, 0x0806, 0x0601]
CHROME_CIPHERS = [GREASE, 0x1301, 0x1302, 0x1303, 0xC02B, 0xC02F, 0xC02C, 0xC030, 0xCCA9, 0xCCA8]
CHROME_CIPHERS += [0xC013, 0xC014, 0x009C, 0x009D, 0x002F, 0x0035]


def chrome_pq(name: str, sni: str, late_sni: bool) -> Spec:
    """A Chromium-style hello with an ML-KEM key share: about 1.8 kB, so two TCP segments; GREASE
    in the ciphers, the extensions and the versions; the GREASE ECH extension Chromium always sends."""
    alpn = [b"h2", b"http/1.1"]
    pq = ext_key_share([(0x2A2A, 1), (0x11EC, 1216), (0x001D, 32)])
    extra = [
        (0x0A0A, b""),
        (0x0005, b"\x01\x00\x00\x00\x00"),
        (0x0012, b""),
        (0x0023, b""),
        (0x002D, b"\x01\x01"),
        (0x0033, pq),
        (0x001B, b"\x00\x02\x00\x02"),
        (0x4469, b"\x00\x03\x02h2"),
        (0xFE0D, b"\x00\x00\x01\x00\x01\x2a" + vec(bytes(32), 2) + vec(bytes(144), 2)),
        (0x1A1A, b"\x00"),
    ]
    return Spec(
        name,
        sni,
        CHROME_CIPHERS,
        standard_exts(sni, alpn, CHROME_SIGS, [0x3A3A, 0x0304, 0x0303], extra, late_sni=late_sni),
        alpn,
        CHROME_SIGS,
        [0x3A3A, 0x0304, 0x0303],
    )


def spec_example() -> Spec:
    """The worked example of FoxIO JA4.md: 15 ciphers, 16 extensions with SNI and ALPN, h2."""
    ciphers = [0x1301, 0x1302, 0x1303, 0xC02B, 0xC02F, 0xC02C, 0xC030, 0xCCA9, 0xCCA8, 0xC013, 0xC014]
    ciphers += [0x009C, 0x009D, 0x002F, 0x0035]
    alpn = [b"h2", b"http/1.1"]
    versions = [0x0304, 0x0303]
    exts = [
        (0x0000, ext_sni("www.example.com")),
        (0x0017, b""),
        (0xFF01, b"\x00"),
        (0x000A, ext_u16_list([0x001D, 0x0017])),
        (0x000B, b"\x01\x00"),
        (0x0023, b""),
        (0x0010, ext_alpn(alpn)),
        (0x0005, b"\x01\x00\x00\x00\x00"),
        (0x000D, ext_u16_list(CHROME_SIGS)),
        (0x0012, b""),
        (0x0033, ext_key_share([(0x001D, 32)])),
        (0x002D, b"\x01\x01"),
        (0x002B, vec(b"".join(u16(v) for v in versions), 1)),
        (0x001B, b"\x00\x02\x00\x02"),
        (0x4469, b"\x00\x03\x02h2"),
        (0x0015, bytes(40)),  # padding
    ]
    return Spec("spec-example", "www.example.com", ciphers, exts, alpn, CHROME_SIGS, versions)


def firefox_like() -> Spec:
    """delegated_credentials (34) before signature_algorithms (13) and signature_algorithms_cert (50)
    after: three lists under one tshark field, of which JA4 wants the middle one."""
    alpn = [b"h2", b"http/1.1"]
    sigs = [0x0403, 0x0503, 0x0603, 0x0804, 0x0805, 0x0806, 0x0401, 0x0501, 0x0601, 0x0203, 0x0201]
    deleg = [0x0403, 0x0503, 0x0603, 0x0203]
    versions = [0x0304, 0x0303]
    exts = [
        (0x0000, ext_sni("media.example.net")),
        (0x0017, b""),
        (0xFF01, b"\x00"),
        (0x000A, ext_u16_list([0x001D, 0x0017, 0x0018, 0x0019, 0x0100, 0x0101])),
        (0x000B, b"\x01\x00"),
        (0x0010, ext_alpn(alpn)),
        (0x0005, b"\x01\x00\x00\x00\x00"),
        (0x0022, ext_u16_list(deleg)),
        (0x0033, ext_key_share([(0x001D, 32), (0x0017, 65)])),
        (0x002B, vec(b"".join(u16(v) for v in versions), 1)),
        (0x000D, ext_u16_list(sigs)),
        (0x0032, ext_u16_list([0x0403, 0x0804])),
        (0x002D, b"\x01\x01"),
        (0x001C, b"\x40\x01"),
        (0x0015, bytes(20)),
    ]
    ciphers = [0x1301, 0x1303, 0x1302, 0xC02B, 0xC02F, 0xCCA9, 0xCCA8, 0xC02C, 0xC030, 0xC00A, 0xC009]
    ciphers += [0xC013, 0xC014, 0x009C, 0x009D, 0x002F, 0x0035]
    return Spec("firefox-like", "media.example.net", ciphers, exts, alpn, sigs, versions)


def no_sni() -> Spec:
    """A hello to an address typed into the app: no server_name, no ALPN."""
    sigs = [0x0401, 0x0501, 0x0601, 0x0201]
    return Spec(
        "no-sni",
        "",
        [0xC02F, 0xC030, 0x009E, 0x009F, 0x00FF],
        standard_exts(None, [], sigs, []),
        [],
        sigs,
        [],
    )


def ech_cloudflare() -> Spec:
    """Real ECH as the wire shows it: the extension, and the provider's public name outside."""
    alpn = [b"h2"]
    versions = [0x0304]
    ech = b"\x00\x00\x01\x00\x01\x07" + vec(bytes(range(32)), 2) + vec(bytes(208), 2)
    extra = [(0x0033, ext_key_share([(0x001D, 32)])), (0xFE0D, ech)]
    return Spec(
        "ech-cloudflare",
        "cloudflare-ech.com",
        [0x1301, 0x1302, 0x1303],
        standard_exts("cloudflare-ech.com", alpn, CHROME_SIGS, versions, extra),
        alpn,
        CHROME_SIGS,
        versions,
    )


def tls12_odd_alpn() -> Spec:
    """TLS 1.2 without supported_versions and without signature_algorithms (JA4's `c` then has no
    underscore), and a first ALPN value that is not alphanumeric at its ends (JA4 takes hex)."""
    alpn = [b" a", b"http/1.1"]
    exts = [
        (0x0000, ext_sni("legacy.example.org")),
        (0xFF01, b"\x00"),
        (0x000A, ext_u16_list([0x0017, 0x0018])),
        (0x000B, b"\x01\x00"),
        (0x0010, ext_alpn(alpn)),
        (0x0023, b""),
    ]
    return Spec("tls12-odd-alpn", "legacy.example.org", [0xC02F, 0xC013, 0x002F, 0x000A], exts, alpn)


def quic_hello() -> Spec:
    """A QUIC client hello: TLS 1.3 only, h3, the transport parameters extension (57)."""
    alpn = [b"h3"]
    versions = [0x0304]
    tp = bytes.fromhex("0104800075300304800005dc0408800000000500000004")
    extra = [(0x0033, ext_key_share([(0x001D, 32)])), (0x0039, tp), (0x002D, b"\x01\x01")]
    return Spec(
        "quic-initial",
        "video.example.com",
        [0x1301, 0x1302, 0x1303],
        standard_exts("video.example.com", alpn, CHROME_SIGS, versions, extra),
        alpn,
        CHROME_SIGS,
        versions,
    )


# ---- JA4, written again from the spec -------------------------------------------------------


def _grease(v: int) -> bool:
    return (v & 0x0F0F) == 0x0A0A and (v & 0xFF) == (v >> 8)


def spec_ja4(spec: Spec, transport: str) -> tuple[str, str]:
    """(JA4, JA4_r) straight from the spec text: GREASE out everywhere; version from the highest
    supported_versions entry, else the hello's own; d/i for SNI; two-digit counts capped at 99; the
    first ALPN's first and last characters, or hex digits when either is not alphanumeric; sorted
    ciphers; sorted extensions without SNI and ALPN, an underscore and the signature algorithms."""
    versions = [v for v in spec.supported_versions if not _grease(v)]
    version = max(versions) if versions else spec.legacy_version
    names = {0x0304: "13", 0x0303: "12", 0x0302: "11", 0x0301: "10"}
    ciphers = sorted(c for c in spec.ciphers if not _grease(c))
    exts = [e for e in spec.ext_types() if not _grease(e)]
    first = spec.alpn[0] if spec.alpn else b""
    if not first:
        alpn = "00"
    elif chr(first[0]).isalnum() and chr(first[-1]).isalnum():
        alpn = chr(first[0]) + chr(first[-1])
    else:
        alpn = f"{first[0]:02x}"[0] + f"{first[-1]:02x}"[-1]
    a = f"{transport}{names.get(version, '00')}{'d' if 0 in exts else 'i'}"
    a += f"{min(len(ciphers), 99):02d}{min(len(exts), 99):02d}{alpn}"
    b = ",".join(f"{c:04x}" for c in ciphers)
    c = ",".join(f"{e:04x}" for e in sorted(e for e in exts if e not in (0x0000, 0x0010)))
    if spec.sig_algs:
        c += "_" + ",".join(f"{s:04x}" for s in spec.sig_algs)

    def h(s: str) -> str:
        return hashlib.sha256(s.encode()).hexdigest()[:12] if s else "000000000000"

    return f"{a}_{h(b)}_{h(c)}", f"{a}_{b}_{c}"


# ---- frames and pcap ------------------------------------------------------------------------


def _csum(data: bytes) -> int:
    if len(data) % 2:
        data += b"\x00"
    s = sum(struct.unpack(f"!{len(data) // 2}H", data))
    while s >> 16:
        s = (s & 0xFFFF) + (s >> 16)
    return ~s & 0xFFFF


def _ip(a: str) -> bytes:
    return bytes(int(x) for x in a.split("."))


def ipv4(src: str, dst: str, proto: int, payload: bytes, ident: int) -> bytes:
    hdr = struct.pack(
        "!BBHHHBBH4s4s", 0x45, 0, 20 + len(payload), ident, 0x4000, 64, proto, 0, _ip(src), _ip(dst)
    )
    return hdr[:10] + struct.pack("!H", _csum(hdr)) + hdr[12:] + payload


def tcp(src: str, dst: str, sport: int, dport: int, seq: int, flags: int, payload: bytes = b"") -> bytes:
    opts = b"" if payload or not flags & 0x02 else b"\x02\x04\x05\xb4\x01\x01\x04\x02"
    off = (20 + len(opts)) // 4
    hdr = struct.pack("!HHIIBBHHH", sport, dport, seq, 0 if flags & 0x02 else 1, off << 4, flags, 64240, 0, 0)
    hdr += opts
    pseudo = _ip(src) + _ip(dst) + struct.pack("!BBH", 0, 6, len(hdr) + len(payload))
    c = _csum(pseudo + hdr + payload)
    return hdr[:16] + struct.pack("!H", c) + hdr[18:] + payload


def udp(src: str, dst: str, sport: int, dport: int, payload: bytes) -> bytes:
    hdr = struct.pack("!HHHH", sport, dport, 8 + len(payload), 0)
    pseudo = _ip(src) + _ip(dst) + struct.pack("!BBH", 0, 17, 8 + len(payload))
    c = _csum(pseudo + hdr + payload) or 0xFFFF
    return hdr[:6] + struct.pack("!H", c) + payload


def ether(ip_packet: bytes) -> bytes:
    return GW_MAC + TV_MAC + b"\x08\x00" + ip_packet


def pcap(frames: list[tuple[float, bytes]]) -> bytes:
    out = struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1)
    for t, f in frames:
        sec = int(t)
        out += struct.pack("<IIII", sec, round((t - sec) * 1e6), len(f), len(f)) + f
    return out


# ---- QUIC Initial (RFC 9001 section 5) ------------------------------------------------------


def _hkdf_expand_label(secret: bytes, label: str, length: int) -> bytes:
    full = b"tls13 " + label.encode()
    info = struct.pack("!H", length) + vec(full, 1) + b"\x00"
    out, block, i = b"", b"", 1
    while len(out) < length:
        block = hmac.new(secret, block + info + bytes([i]), hashlib.sha256).digest()
        out, i = out + block, i + 1
    return out[:length]


def quic_client_keys(dcid: bytes) -> tuple[bytes, bytes, bytes]:
    """(key, iv, hp) of the client's Initial packets, from the destination connection ID alone."""
    initial = hmac.new(QUIC_V1_SALT, dcid, hashlib.sha256).digest()
    client = _hkdf_expand_label(initial, "client in", 32)
    return (
        _hkdf_expand_label(client, "quic key", 16),
        _hkdf_expand_label(client, "quic iv", 12),
        _hkdf_expand_label(client, "quic hp", 16),
    )


def _varint(n: int) -> bytes:
    if n < 0x40:
        return bytes([n])
    if n < 0x4000:
        return struct.pack("!H", 0x4000 | n)
    return struct.pack("!I", 0x80000000 | n)


def quic_initial(hello: bytes, dcid: bytes, scid: bytes, pn: int = 0) -> bytes:
    """One client Initial packet carrying `hello` in a CRYPTO frame, padded to 1200 bytes."""
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM

    key, iv, hp = quic_client_keys(dcid)
    pn_len = 4
    frames = b"\x06" + _varint(0) + _varint(len(hello)) + hello
    head_len = 1 + 4 + 1 + len(dcid) + 1 + len(scid) + 1 + 2 + pn_len
    frames += bytes(max(0, 1200 - head_len - len(frames) - 16))
    length = pn_len + len(frames) + 16
    header = bytes([0xC0 | (pn_len - 1)]) + b"\x00\x00\x00\x01" + vec(dcid, 1) + vec(scid, 1) + b"\x00"
    header += struct.pack("!H", 0x4000 | length) + pn.to_bytes(pn_len, "big")
    nonce = bytes(a ^ b for a, b in zip(iv, pn.to_bytes(12, "big"), strict=True))
    sealed = AESGCM(key).encrypt(nonce, frames, header)
    sample = sealed[4 - pn_len : 4 - pn_len + 16]
    enc = Cipher(algorithms.AES(hp), modes.ECB()).encryptor()
    mask = enc.update(sample) + enc.finalize()
    first = bytes([header[0] ^ (mask[0] & 0x0F)])
    pn_at = len(header) - pn_len
    pn_bytes = bytes(a ^ b for a, b in zip(header[pn_at:], mask[1 : 1 + pn_len], strict=True))
    return first + header[1:pn_at] + pn_bytes + sealed


# ---- tshark rows, as tshark 4.x prints them with this repo's fields --------------------------

FIELDS = (
    "frame.time_epoch",
    "ip.src",
    "tcp.srcport",
    "ip.dst",
    "tcp.dstport",
    "tcp.flags",
    "udp.srcport",
    "udp.dstport",
    "tls.handshake.extensions_server_name",
    "http.request.method",
    "http.host",
    "http.request.uri",
    "http.user_agent",
    "tls.handshake.extension.type",
    "tls.handshake.type",
    "tls.handshake.version",
    "tls.handshake.extensions.supported_version",
    "tls.handshake.ciphersuite",
    "tls.handshake.extensions_alpn_str",
    "tls.handshake.sig_hash_alg_len",
    "tls.handshake.sig_hash_alg",
    "tcp.segment_data",
)


def tsv_row(**kw: str) -> str:
    vals = dict.fromkeys(FIELDS, "")
    vals.update(kw)
    return "\t".join(vals[f] for f in FIELDS)


def hello_fields(spec: Spec) -> dict[str, str]:
    """The TLS fields of a dissected hello: integers in tshark's display base (hex for ciphers,
    versions and signature schemes, decimal for extension types and lengths), repeats joined."""
    lists = sig_ext_lists(spec)
    return {
        "tls.handshake.extensions_server_name": spec.sni,
        "tls.handshake.extension.type": AGG.join(str(t) for t in spec.ext_types()),
        "tls.handshake.type": "1",
        "tls.handshake.version": f"0x{spec.legacy_version:04x}",
        "tls.handshake.extensions.supported_version": AGG.join(f"0x{v:04x}" for v in spec.supported_versions),
        "tls.handshake.ciphersuite": AGG.join(f"0x{c:04x}" for c in spec.ciphers),
        "tls.handshake.extensions_alpn_str": AGG.join(p.decode("ascii") for p in spec.alpn),
        "tls.handshake.sig_hash_alg_len": AGG.join(str(2 * len(v)) for _, v in lists),
        "tls.handshake.sig_hash_alg": AGG.join(f"0x{s:04x}" for _, v in lists for s in v),
    }


# ---- the cases ------------------------------------------------------------------------------


@dataclass
class Case:
    name: str
    frames: list[tuple[float, bytes]]
    rows: list[str]  # the tshark rows, in frame order
    expected: list[dict]  # what tshark.extract returns for the TV, after dedupe
    why: str


def _expect(t, sport, dst, dport, sni, ja4="", transport="tcp", partial=False, ech=False, ja4_r="") -> dict:
    return {
        "t": t,
        "src": TV,
        "sport": sport,
        "dst": dst,
        "dport": dport,
        "sni": sni,
        "ech": ech,
        "ja4": ja4,
        "transport": transport,
        "partial": partial,
        "ja4_r": ja4_r,
    }


def tcp_case(
    spec: Spec,
    dst: str,
    sport: int,
    segments: int = 1,
    keep: str = "all",
    retransmit: bool = False,
    why: str = "",
) -> Case:
    """A TCP connection from the TV: SYN, then the hello in `segments` pieces (MSS 1460). `keep` is
    "all" or "first" (the capture lost the rest); `retransmit` sends the kept pieces twice.

    The rows are what tshark prints in one pass with reassembly on: a piece that leaves the hello
    unfinished shows as raw `tcp.segment_data`; the piece that completes it carries the dissected
    hello; a retransmitted piece shows as raw (retransmitted) segment data again."""
    rec = spec.record()
    mss = 1460 if segments > 1 else len(rec)
    pieces = [rec[i : i + mss] for i in range(0, len(rec), mss)]
    assert len(pieces) == segments, (spec.name, len(rec))
    offsets = [i * mss for i in range(len(pieces))]
    isn = 1000
    frames = [(T0, ether(ipv4(TV, dst, 6, tcp(TV, dst, sport, 443, isn, 0x02), 1)))]
    common = {"ip.src": TV, "tcp.srcport": str(sport), "ip.dst": dst, "tcp.dstport": "443"}
    rows = [tsv_row(**{"frame.time_epoch": f"{T0:.9f}", "tcp.flags": "0x0002"}, **common)]
    sent = list(range(len(pieces))) if keep == "all" else [0]
    if retransmit:
        sent = sent + sent
    for k, i in enumerate(sent):
        t = T0 + 0.05 + 0.01 * k
        frames.append(
            (
                t,
                ether(
                    ipv4(TV, dst, 6, tcp(TV, dst, sport, 443, isn + 1 + offsets[i], 0x18, pieces[i]), 2 + k)
                ),
            )
        )
        base = {"frame.time_epoch": f"{t:.9f}", "tcp.flags": "0x0018", **common}
        completes = keep == "all" and i == len(pieces) - 1 and k < len(pieces)
        if completes:
            rows.append(tsv_row(**base, **hello_fields(spec)))
        else:
            rows.append(tsv_row(**base, **{"tcp.segment_data": pieces[i].hex()}))
    if keep == "all":
        ja4, ja4_r = spec_ja4(spec, "t")
        t_hello = T0 + 0.05 + 0.01 * (len(pieces) - 1)
        exp = [_expect(t_hello, sport, dst, 443, spec.sni, ja4, ech=0xFE0D in spec.ext_types(), ja4_r=ja4_r)]
    else:
        seen = spec.ext_spans()
        sni = next((spec.sni for t, a, z in seen if t == 0 and z <= mss), "")
        ech = any(t == 0xFE0D and a + 2 <= mss for t, a, _ in seen)
        exp = [_expect(T0 + 0.05, sport, dst, 443, sni, partial=True, ech=ech)]
    return Case(spec.name if keep == "all" else f"{spec.name}-first-only", frames, rows, exp, why)


def quic_case(spec: Spec, dst: str, sport: int) -> Case | None:
    dcid, scid = bytes.fromhex("8394c8f03e515708"), bytes.fromhex("c0ffee0102030405")
    try:
        pkt = quic_initial(spec.handshake(), dcid, scid)
    except ImportError:
        return None
    t = T0 + 1.0
    frames = [(t, ether(ipv4(TV, dst, 17, udp(TV, dst, sport, 443, pkt), 9)))]
    base = {
        "frame.time_epoch": f"{t:.9f}",
        "ip.src": TV,
        "ip.dst": dst,
        "udp.srcport": str(sport),
        "udp.dstport": "443",
    }
    rows = [tsv_row(**base, **hello_fields(spec))]
    ja4, ja4_r = spec_ja4(spec, "q")
    return Case(
        spec.name,
        frames,
        rows,
        [_expect(t, sport, dst, 443, spec.sni, ja4, "quic", ja4_r=ja4_r)],
        "A QUIC v1 Initial (RFC 9000/9001), encrypted with the keys its connection ID gives anyone",
    )


def cases() -> list[Case]:
    out = [
        tcp_case(
            spec_example(),
            "203.0.113.10",
            40010,
            why="FoxIO's worked example; its JA4 is quoted from the spec",
        ),
        tcp_case(
            chrome_pq("chrome-pq-split", "www.example.com", late_sni=True),
            "203.0.113.11",
            40011,
            2,
            why="A post-quantum hello over two segments, both kept: reassembled, named, fingerprinted",
        ),
        tcp_case(
            chrome_pq("chrome-pq-split", "www.example.com", late_sni=True),
            "203.0.113.11",
            40012,
            2,
            "first",
            why="The same hello with only its first segment kept, the name in the second: a partial hello without a name",
        ),
        tcp_case(
            chrome_pq("chrome-pq-early", "early.example.com", late_sni=False),
            "203.0.113.12",
            40013,
            2,
            "first",
            why="Only the first segment kept, the name in it: a partial hello with its name, no JA4",
        ),
        tcp_case(
            firefox_like(),
            "198.51.100.20",
            40020,
            why="Three signature lists under one tshark field; JA4 takes signature_algorithms alone",
        ),
        tcp_case(
            no_sni(),
            "198.51.100.21",
            40021,
            why="No server_name and no ALPN: JA4 'i' and '00', a tls_noname row",
        ),
        tcp_case(
            ech_cloudflare(),
            "198.51.100.22",
            40022,
            why="Real ECH: the extension and the provider's public name",
        ),
        tcp_case(
            tls12_odd_alpn(),
            "198.51.100.23",
            40023,
            retransmit=True,
            why="TLS 1.2 without supported_versions or signature_algorithms, a non-alphanumeric ALPN, sent twice",
        ),
    ]
    q = quic_case(quic_hello(), "198.51.100.30", 50030)
    if q:
        out.append(q)
    return out


def write(root: Path = HERE) -> list[str]:
    """Write every case under `root`; returns the case names. Without `cryptography` the QUIC case
    is not built, and its committed pcap, rows and expectation are left as they are."""
    (root / "pcap").mkdir(exist_ok=True)
    (root / "tsv" / "synthetic").mkdir(parents=True, exist_ok=True)
    path = root / "expected.json"
    expected = json.loads(path.read_text(encoding="utf-8")) if path.exists() else {}
    names = []
    for c in cases():
        (root / "pcap" / f"{c.name}.pcap").write_bytes(pcap(c.frames))
        (root / "tsv" / "synthetic" / f"{c.name}.tsv").write_text("\n".join(c.rows) + "\n", encoding="utf-8")
        expected[c.name] = {"why": c.why, "hellos": c.expected}
        names.append(c.name)
    path.write_text(json.dumps(expected, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return names


if __name__ == "__main__":
    print("\n".join(write()))
