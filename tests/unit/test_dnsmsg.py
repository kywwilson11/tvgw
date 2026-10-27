"""DNS message decoding, with the base64 answers AdGuard actually logged."""

import base64
import struct

import pytest

from tvgw.dnsmsg import DnsFormatError, answers_text, decode_answers, is_blocked_answer, rcode, read_name

# AAAA for aic.recommend.lgtvcommon.com answered :: (blocked)
BLOCKED_AAAA = (
    "80CBgAABAAEAAAAAA0FJQwlyZWNvbW1lbmQKbGd0dmNvbW1vbgNjb20AABwAAcAMABwAAQAAADwAEAAAAAAAAAAAAAAAAAAAAAA="
)
# A for us.lgtvsdp.com: CNAME us-lgtvsdp-com.aws-prd.net then A 35.166.189.68
CNAME_THEN_A = "FhyBgAABAAIAAAAAAlVTB2xndHZzZHADY29tAAABAAHADAAFAAEAAAAMABwOdXMtbGd0dnNkcC1jb20HYXdzLXByZANuZXQAwCwAAQABAAAADAAEI6a9RA=="


def test_blocked_aaaa_decodes_to_all_zero_address():
    ans = decode_answers(BLOCKED_AAAA)
    assert [(a.rtype, a.value) for a in ans] == [("AAAA", "0:0:0:0:0:0:0:0")]
    assert ans[0].ttl == 60
    assert is_blocked_answer(ans)


def test_cname_chain_with_compression_pointers():
    ans = decode_answers(CNAME_THEN_A)
    assert [(a.rtype, a.value) for a in ans] == [
        ("CNAME", "us-lgtvsdp-com.aws-prd.net"),
        ("A", "35.166.189.68"),
    ]
    assert [a.ttl for a in ans] == [12, 12]
    assert not is_blocked_answer(ans)
    assert answers_text(CNAME_THEN_A) == "CNAME:us-lgtvsdp-com.aws-prd.net,A:35.166.189.68"


def test_bytes_input_is_accepted():
    assert decode_answers(base64.b64decode(BLOCKED_AAAA))[0].rtype == "AAAA"


def test_zero_ip_a_record_is_blocked_but_mixed_is_not():
    hdr = struct.pack(">HHHHHH", 1, 0x8180, 1, 2, 0, 0)
    q = b"\x03foo\x03com\x00" + struct.pack(">HH", 1, 1)
    a_zero = b"\xc0\x0c" + struct.pack(">HHIH", 1, 1, 30, 4) + bytes([0, 0, 0, 0])
    a_real = b"\xc0\x0c" + struct.pack(">HHIH", 1, 1, 30, 4) + bytes([1, 2, 3, 4])
    both = decode_answers(hdr + q + a_zero + a_real)
    assert [a.value for a in both] == ["0.0.0.0", "1.2.3.4"]
    assert not is_blocked_answer(both)
    only_zero = decode_answers(struct.pack(">HHHHHH", 1, 0x8180, 1, 1, 0, 0) + q + a_zero)
    assert is_blocked_answer(only_zero)
    assert not is_blocked_answer([])  # no address records at all is not "blocked"


def test_unknown_record_types_are_skipped():
    hdr = struct.pack(">HHHHHH", 1, 0x8180, 1, 1, 0, 0)
    q = b"\x03foo\x03com\x00" + struct.pack(">HH", 16, 1)
    txt = b"\xc0\x0c" + struct.pack(">HHIH", 16, 1, 30, 4) + b"\x03abc"
    assert decode_answers(hdr + q + txt) == []


@pytest.mark.parametrize(
    "bad",
    [
        b"",  # no header
        struct.pack(">HHHHHH", 1, 0x8180, 1, 1, 0, 0) + b"\x03foo",  # truncated question name
        struct.pack(">HHHHHH", 1, 0x8180, 0, 1, 0, 0) + b"\xc0\x0c",  # truncated record header
        struct.pack(">HHHHHH", 1, 0x8180, 0, 1, 0, 0) + b"\x00" + struct.pack(">HHIH", 1, 1, 1, 4) + b"\x01",
    ],
)
def test_truncated_messages_raise(bad):
    with pytest.raises(DnsFormatError):
        decode_answers(bad)
    assert answers_text(bad) is None


def test_pointer_loops_are_rejected():
    msg = struct.pack(">HHHHHH", 1, 0x8180, 0, 0, 0, 0) + b"\xc0\x0c"
    with pytest.raises(DnsFormatError):
        read_name(msg, 12)


def test_read_name_returns_offset_after_pointer():
    msg = struct.pack(">HHHHHH", 0, 0, 0, 0, 0, 0) + b"\x03foo\x03com\x00" + b"\xc0\x0c"
    name, end = read_name(msg, 21)
    assert name == "foo.com" and end == 23


# ---- the decoder's edges, on synthetic messages ---------------------------------------------------------
def header(qd: int, an: int, flags: int = 0x8180) -> bytes:
    return struct.pack(">HHHHHH", 1, flags, qd, an, 0, 0)


Q = b"\x03foo\x03com\x00" + struct.pack(">HH", 1, 1)


def rr(rtype: int, rdata: bytes, ttl: int = 30) -> bytes:
    return b"\xc0\x0c" + struct.pack(">HHIH", rtype, 1, ttl, len(rdata)) + rdata


def test_rcode_reads_the_response_code():
    assert rcode(base64.b64decode(CNAME_THEN_A)) == 0
    assert rcode(header(1, 0, flags=0x8182)) == 2  # SERVFAIL
    assert rcode(header(1, 0, flags=0x8183)) == 3  # NXDOMAIN
    assert rcode(b"\x00\x01\x81") == -1


@pytest.mark.parametrize("first", [0x41, 0x81])
def test_reserved_label_types_are_rejected_not_read_as_long_labels(first):
    """0x41 decoded as a 65-byte label before; the two upper bits of a length byte are a pointer (11),
    a label (00), or a type never assigned (01, 10)."""
    with pytest.raises(DnsFormatError, match=r"^reserved label type$"):
        read_name(bytes(12) + bytes([first]) + b"a" * 70 + b"\x00", 12)


def test_a_label_cannot_forge_the_stored_answer_grammar():
    """A CNAME whose label read `A:0.0.0.0,x` was stored as `CNAME:A:0.0.0.0,x.com`: a forged A answer
    inside the `A:1.2.3.4,CNAME:x` text that unresolved_flows splits on commas and colons."""
    label = b"A:0.0.0.0,x"
    msg = header(1, 1) + Q + rr(5, bytes([len(label)]) + label + b"\x03com\x00")
    (ans,) = decode_answers(msg)
    assert ans.rtype == "CNAME" and ans.value == "A\\0580\\0460\\0460\\0460\\044x.com"
    text = answers_text(msg)
    assert text.split(",") == [text] and "A:0.0.0.0" not in text


def test_a_cname_whose_name_runs_past_its_rdata_is_rejected():
    name = b"\x03bar\x03com\x00"
    assert decode_answers(header(1, 1) + Q + rr(5, name))[0].value == "bar.com"
    short = b"\xc0\x0c" + struct.pack(">HHIH", 5, 1, 30, 1) + name  # rdlen says one byte
    with pytest.raises(DnsFormatError, match=r"^rdata overrun$"):
        decode_answers(header(1, 1) + Q + short)


def test_names_longer_than_255_octets_are_rejected():
    three = b"".join(b"\x3f" + b"a" * 63 for _ in range(3))
    longest = three + b"\x3d" + b"b" * 61 + b"\x00"  # 3 * 64 + 62 + 1 = 255 octets on the wire
    assert len(longest) == 255 and len(read_name(bytes(12) + longest, 12)[0]) == 63 * 3 + 61 + 3
    with pytest.raises(DnsFormatError, match=r"^name too long$"):
        read_name(bytes(12) + three + b"\x3e" + b"b" * 62 + b"\x00", 12)  # 256


def test_a_question_cut_before_its_type_and_class_is_rejected():
    with pytest.raises(DnsFormatError, match=r"^truncated question$"):
        decode_answers(header(1, 0) + b"\x03foo\x00\x00")  # was silently [] before


def test_aaaa_text_form_ttl_sign_and_skipped_types():
    aaaa = bytes.fromhex("26001f18") + bytes(10) + bytes.fromhex("abcd")
    (ans,) = decode_answers(header(1, 1) + Q + rr(28, aaaa, ttl=300))
    assert (ans.value, ans.ttl) == ("2600:1f18:0:0:0:0:0:abcd", 300)  # the stored form: no :: folding
    (a,) = decode_answers(header(1, 1) + Q + rr(1, bytes([1, 2, 3, 4]), ttl=0x80000000))
    assert a.ttl == 2147483648  # unsigned
    assert decode_answers(header(1, 1) + Q + rr(0x8001, bytes(4))) == []
    assert decode_answers(header(0, 0)) == []
