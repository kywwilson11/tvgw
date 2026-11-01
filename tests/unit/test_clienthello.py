"""The ClientHello byte parser and JA4: fixed cases from the spec, then properties over a few
hundred random hellos (seeded, so a failure reproduces).

The properties are the ones JA4 promises and the extractor relies on: the string's shape; sorting
makes it blind to cipher and extension order (Chromium permutes extensions per connection) but not
to the order of signature algorithms; GREASE never counts; counts stop at 99; the fields tshark
prints and the bytes on the wire give the same string; and a hello cut anywhere never raises and
never yields a fingerprint."""

import random
import re

import pytest
from corpus import build

from tvgw import clienthello, tshark
from tvgw.clienthello import Ja4Input, from_hello, is_grease, ja4, ja4_r, parse_handshake, parse_record

JA4_SHAPE = re.compile(
    r"^[tqd](13|12|11|10|s3|s2|s1|d1|d2|d3|00)[di]\d{2}\d{2}[0-9A-Za-z]{2}_[0-9a-f]{12}_[0-9a-f]{12}$"
)
GREASES = [0x0A0A + 0x1010 * i for i in range(16)]
EXT_POOL = [0x0005, 0x000A, 0x000B, 0x0012, 0x0015, 0x0017, 0x001B, 0x0023, 0x002D, 0x0033, 0x4469, 0xFF01]
CIPHER_POOL = [0x1301, 0x1302, 0x1303, 0xC02B, 0xC02C, 0xC02F, 0xC030, 0xCCA8, 0xCCA9, 0x009C, 0x009D]
CIPHER_POOL += [0x002F, 0x0035, 0xC013, 0xC014, 0x000A, 0x00FF]
SIG_POOL = [0x0403, 0x0503, 0x0603, 0x0804, 0x0805, 0x0806, 0x0401, 0x0501, 0x0601, 0x0201, 0x0203]


def random_spec(rng: random.Random, n_ciphers: int | None = None) -> "build.Spec":
    ciphers = rng.sample(CIPHER_POOL, rng.randint(1, len(CIPHER_POOL)))
    if n_ciphers is not None:
        ciphers = [0x1000 + i for i in range(n_ciphers)]  # none of these is GREASE
    sni = rng.choice(["", "a.example", "media.example.net"])
    # ASCII only: how tshark prints a non-ASCII protocol name is not pinned (test_alpn_characters
    # covers such names on the byte path)
    alpn = rng.choice([[], [b"h2"], [b"h2", b"http/1.1"], [b"h"], [b"http/1.1"], [b" a"], [b"#z"]])
    sigs = rng.sample(SIG_POOL, rng.randint(0, 6))
    versions = rng.choice([[], [0x0304], [0x0304, 0x0303], [0x0303]])
    exts: list[tuple[int, bytes]] = [(e, b"") for e in rng.sample(EXT_POOL, rng.randint(0, len(EXT_POOL)))]
    if sni:
        exts.append((0x0000, build.ext_sni(sni)))
    if alpn:
        exts.append((0x0010, build.ext_alpn(alpn)))
    if sigs:
        exts.append((0x000D, build.ext_u16_list(sigs)))
    if versions:
        exts.append((0x002B, build.vec(b"".join(build.u16(v) for v in versions), 1)))
    if rng.random() < 0.3:
        exts.append((0x0032, build.ext_u16_list(rng.sample(SIG_POOL, 2))))
    if rng.random() < 0.3:
        exts.insert(0, (0x0022, build.ext_u16_list(rng.sample(SIG_POOL, 3))))
    rng.shuffle(exts)
    return build.Spec("random", sni, ciphers, exts, alpn, sigs, versions, rng.choice([0x0301, 0x0303]))


def specs(n: int = 300, seed: int = 20261101):
    rng = random.Random(seed)
    return [random_spec(rng) for _ in range(n)]


def bytes_ja4(spec, transport="tcp") -> str:
    h = parse_record(spec.record())
    assert h is not None and h.complete
    return ja4(from_hello(h, transport))


def fields_row(spec) -> str:
    return build.tsv_row(
        **{"frame.time_epoch": "1.0", "ip.src": "s", "ip.dst": "d", "tcp.srcport": "1", "tcp.dstport": "443"},
        **build.hello_fields(spec),
    )


# ---- fixed cases -----------------------------------------------------------------------------


def test_the_spec_worked_example():
    ciphers = [0x1301, 0x1302, 0x1303, 0xC02B, 0xC02F, 0xC02C, 0xC030, 0xCCA9, 0xCCA8, 0xC013, 0xC014]
    ciphers += [0x009C, 0x009D, 0x002F, 0x0035]
    exts = [0x0000, 0x0017, 0xFF01, 0x000A, 0x000B, 0x0023, 0x0010, 0x0005, 0x000D, 0x0012, 0x0033]
    exts += [0x002D, 0x002B, 0x001B, 0x4469, 0x0015]
    sigs = [0x0403, 0x0804, 0x0401, 0x0503, 0x0805, 0x0501, 0x0806, 0x0601]
    i = Ja4Input("tcp", 0x0303, [0x0304, 0x0303], ciphers, exts, b"h2", sigs)
    assert ja4(i) == "t13d1516h2_8daaf6152771_e5627efa2ab1"
    raw = ja4_r(i)
    assert raw.startswith("t13d1516h2_002f,0035,009c,009d,1301,")
    assert raw.endswith("_0403,0804,0401,0503,0805,0501,0806,0601")


@pytest.mark.parametrize(
    ("alpn", "chars"),
    [
        (None, "00"),
        (b"", "00"),
        (b"h2", "h2"),
        (b"h", "hh"),
        (b"http/1.1", "h1"),
        (b" a", "21"),
        (b"\xab", "ab"),
        (b"a\x00", "60"),
    ],
)
def test_alpn_characters(alpn, chars):
    """First and last character of the first value; hex digits when either end is not alphanumeric
    (the first digit of the first byte, the last digit of the last byte, as Wireshark prints them)."""
    assert ja4(Ja4Input("tcp", 0x0303, [], [0x1301], [0x0010], alpn, []))[8:10] == chars


@pytest.mark.parametrize(
    ("transport", "legacy", "versions", "prefix"),
    [
        ("tcp", 0x0303, [], "t12"),
        ("tcp", 0x0303, [0x0A0A, 0x0304, 0x0303], "t13"),
        ("quic", 0x0303, [0x0304], "q13"),
        ("tcp", 0x0300, [], "ts3"),
        ("tcp", 0x0002, [], "ts2"),
        ("dtls", 0xFEFD, [], "dd2"),
        ("tcp", 0x7F17, [], "t00"),
        ("tcp", 0x0301, [0x2A2A], "t10"),  # only GREASE in supported_versions: the hello's own version
    ],
)
def test_transport_and_version(transport, legacy, versions, prefix):
    assert ja4(Ja4Input(transport, legacy, versions, [0x1301], [], None, [])).startswith(prefix)


def test_empty_lists_hash_to_zeros_and_no_signatures_means_no_underscore():
    assert ja4(Ja4Input("tcp", 0x0303, [], [], [], None, [])) == "t12i000000_000000000000_000000000000"
    only_sni_alpn = ja4_r(Ja4Input("tcp", 0x0303, [], [0x1301], [0x0000, 0x0010], b"h2", []))
    assert only_sni_alpn == "t12d0102h2_1301_"  # both counted, neither hashed
    no_sigs = ja4_r(Ja4Input("tcp", 0x0303, [], [0x1301], [0x000A], None, []))
    assert no_sigs.endswith("_000a") and "_000a_" not in no_sigs


def test_grease_is_recognised_exactly():
    assert all(is_grease(g) for g in GREASES)
    assert not any(is_grease(v) for v in (0x0A0B, 0x0B0A, 0x1A0A, 0x0A1A, 0x0000, 0xFE0D, 0x1301))


def test_counts_stop_at_99():
    spec = random_spec(random.Random(1), n_ciphers=120)
    assert bytes_ja4(spec)[4:6] == "99"
    i = Ja4Input("tcp", 0x0303, [], [0x1301], list(range(0x3000, 0x3000 + 150)), None, [])
    assert ja4(i)[6:8] == "99"


def test_not_a_client_hello_is_none():
    assert parse_record(b"") is None
    assert parse_record(b"\x17\x03\x03\x00\x05hello") is None  # application data
    assert parse_record(b"\x16\x03\x03\x00\x04\x02\x00\x00\x00") is None  # a ServerHello
    assert parse_handshake(b"\x02\x00\x00\x00") is None
    assert parse_handshake(b"\x01\x00") is None


def test_a_hello_fragmented_over_two_records_is_joined():
    spec = build.spec_example()
    hs = spec.handshake()
    two = b"\x16\x03\x01" + build.vec(hs[:100], 2) + b"\x16\x03\x01" + build.vec(hs[100:], 2)
    h = parse_record(two)
    assert h is not None and h.complete and h.sni == "www.example.com"
    assert ja4(from_hello(h)) == build.SPEC_EXAMPLE_JA4


def test_a_hello_without_extensions_is_whole():
    body = build.u16(0x0300) + bytes(32) + b"\x00" + build.ext_u16_list([0x000A, 0x002F]) + b"\x01\x00"
    h = parse_handshake(b"\x01" + build.vec(body, 3))
    assert h is not None and h.complete and h.extensions == ()
    assert ja4(from_hello(h)).startswith("ts3i0200")


def test_lengths_that_lie_make_an_incomplete_hello_not_an_exception():
    spec = build.spec_example()
    hs = bytearray(spec.handshake())
    hs[1:4] = (len(hs) + 50).to_bytes(3, "big")  # claims more than there is
    h = parse_handshake(bytes(hs))
    assert h is not None and not h.complete
    ext_len_at = 4 + 2 + 32 + 33 + 2 + 2 * len(spec.ciphers) + 2
    hs = bytearray(spec.handshake())
    hs[ext_len_at : ext_len_at + 2] = b"\xff\xff"  # the extensions block overruns the hello
    h = parse_handshake(bytes(hs))
    assert h is not None and not h.complete and h.sni == "www.example.com"


def test_an_oversized_claim_is_not_read():
    h = parse_handshake(b"\x01\xff\xff\xff" + bytes(64))
    assert h is not None and not h.complete


# ---- properties over random hellos -------------------------------------------------------------


def test_every_fingerprint_has_the_ja4_shape():
    for spec in specs():
        for transport in ("tcp", "quic"):
            assert JA4_SHAPE.fullmatch(bytes_ja4(spec, transport)), spec


def test_the_fields_tshark_prints_and_the_bytes_give_the_same_fingerprint():
    for spec in specs():
        (hello,) = tshark.parse_row(fields_row(spec))
        assert hello.ja4 == bytes_ja4(spec) == build.spec_ja4(spec, "t")[0], spec
        assert hello.sni == spec.sni and not hello.partial


def test_cipher_and_extension_order_do_not_change_it_and_signature_order_does():
    rng = random.Random(7)
    for spec in specs(100):
        before = bytes_ja4(spec)
        shuffled = build.Spec(
            spec.name,
            spec.sni,
            rng.sample(spec.ciphers, len(spec.ciphers)),
            rng.sample(spec.extensions, len(spec.extensions)),
            spec.alpn,
            spec.sig_algs,
            spec.supported_versions,
            spec.legacy_version,
        )
        assert bytes_ja4(shuffled) == before
        if len(set(spec.sig_algs)) > 1:
            sigs = spec.sig_algs[::-1]
            exts = [(t, build.ext_u16_list(sigs) if t == 0x000D else d) for t, d in spec.extensions]
            flipped = build.Spec(
                spec.name, spec.sni, spec.ciphers, exts, spec.alpn, sigs, spec.supported_versions
            )
            flipped.legacy_version = spec.legacy_version
            assert bytes_ja4(flipped).split("_")[2] != before.split("_")[2]


def test_grease_anywhere_changes_nothing():
    rng = random.Random(11)
    for spec in specs(100):
        before = bytes_ja4(spec)
        exts = list(spec.extensions)
        exts.insert(rng.randint(0, len(exts)), (rng.choice(GREASES), b""))
        ciphers = list(spec.ciphers)
        ciphers.insert(rng.randint(0, len(ciphers)), rng.choice(GREASES))
        greased = build.Spec(
            spec.name,
            spec.sni,
            ciphers,
            exts,
            spec.alpn,
            spec.sig_algs,
            spec.supported_versions,
            spec.legacy_version,
        )
        assert bytes_ja4(greased) == before


def test_a_hello_cut_anywhere_never_raises_and_never_has_a_fingerprint():
    rng = random.Random(13)
    for spec in specs(40):
        rec = spec.record()
        for cut in sorted({rng.randint(6, len(rec) - 1) for _ in range(25)} | {6, 10, 50, len(rec) - 1}):
            h = parse_record(rec[:cut])
            if cut < 9:  # not even the handshake header: nothing to read, nothing to tell
                assert h is None
                continue
            assert h is not None and not h.complete
            if h.sni:
                assert h.sni == spec.sni  # a name is only ever the whole name
            (row,) = tshark.parse_row(
                build.tsv_row(
                    **{
                        "frame.time_epoch": "1",
                        "ip.src": "s",
                        "ip.dst": "d",
                        "tcp.segment_data": rec[:cut].hex(),
                    }
                )
            )
            assert row.partial and row.ja4 == "" and row.sni == h.sni


def test_random_bytes_after_a_hello_header_never_raise():
    rng = random.Random(17)
    for _ in range(500):
        junk = bytes(rng.getrandbits(8) for _ in range(rng.randint(0, 300)))
        h = parse_record(b"\x16\x03\x01" + len(junk).to_bytes(2, "big") + b"\x01" + junk)
        assert h is None or isinstance(h, clienthello.Hello)
