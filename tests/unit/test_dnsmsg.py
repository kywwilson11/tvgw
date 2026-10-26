"""DNS message decoding, with the base64 answers AdGuard actually logged."""

import base64
import struct

import pytest

from tvgw.dnsmsg import DnsFormatError, answers_text, decode_answers, is_blocked_answer, read_name

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
