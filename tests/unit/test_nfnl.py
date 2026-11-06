"""(inpath) tvgw.nfnl against fixed bytes: every message the in-path filler sends, written out here by
hand from the kernel's headers (Linux 6.18: netlink.h, nfnetlink.h, nfnetlink_queue.h, nf_tables.h), and
every message it reads. The decoders are then fed cut, flipped and random bytes: whatever arrives, they
return or raise NlError, and nothing else.

The fixtures are little-endian, as every machine tvgw runs on is (netlink headers are in the machine's
byte order); on a big-endian machine the fixed-byte tests skip and the round trips still run."""

import contextlib
import random
import struct
import sys

import pytest

from tvgw import nfnl

little_endian = pytest.mark.skipif(sys.byteorder != "little", reason="the fixtures are little-endian")


def h(text: str) -> bytes:
    """Bytes from hex with spaces and line breaks, so a fixture reads field by field."""
    return bytes.fromhex(text)


QUEUE = 53053  # 0xCF3D

BIND = h(
    "40000000 0203 0500 01000000 00000000"  # 64 bytes, NFNL_SUBSYS_QUEUE<<8 | CONFIG, REQUEST|ACK, seq 1
    "00 00 cf3d"  # nfgenmsg: AF_UNSPEC, version 0, the queue number in network order
    "0800 0100 01 00 0000"  # NFQA_CFG_CMD: BIND, pad, pf 0
    "0900 0200 0000fffb 02 000000"  # NFQA_CFG_PARAMS: copy range 65531, COPY_PACKET, padding
    "0800 0300 00000080"  # NFQA_CFG_QUEUE_MAXLEN: 128
    "0800 0400 00000001"  # NFQA_CFG_MASK: FAIL_OPEN
    "0800 0500 00000001"  # NFQA_CFG_FLAGS: FAIL_OPEN
)
MAXLEN_0 = h("1c000000 0203 0500 02000000 0000000000 00 cf3d0800 0300 00000000")
VERDICT = h(
    "20000000 0103 0100 00000000 00000000"  # 32 bytes, QUEUE<<8 | VERDICT, REQUEST only, seq 0
    "00 00 cf3d"
    "0c00 0200 00000001 0000002a"  # NFQA_VERDICT_HDR: NF_ACCEPT, packet 42
)
ADD = h(
    # batch begin, seq 10, for subsystem 10 (nf_tables)
    "14000000 1000 0100 0a000000 00000000"
    "00 00 000a"
    # NFT_MSG_NEWSETELEM, REQUEST|ACK|CREATE, seq 11, family inet
    "68000000 0c0a 0504 0b000000 00000000"
    "01 00 0000"
    "0e00 0100 747667775f6761746500 0000"  # NFTA_SET_ELEM_LIST_TABLE "tvgw_gate\0"
    "1500 0200 7265736f6c766564345f696e7061746800 000000"  # NFTA_SET_ELEM_LIST_SET "resolved4_inpath\0"
    "2c00 0380"  # NFTA_SET_ELEM_LIST_ELEMENTS, nested
    "2800 0180"  # NFTA_LIST_ELEM, nested
    "0c00 0180 0800 0100 c6336407"  # NFTA_SET_ELEM_KEY { NFTA_DATA_VALUE 198.51.100.7 }
    "0c00 0400 0000000005265c00"  # NFTA_SET_ELEM_TIMEOUT: 86 400 000 ms
    "0c00 0500 0000000005265c00"  # NFTA_SET_ELEM_EXPIRATION: the same
    # batch end, REQUEST|ACK, seq 12
    "14000000 1100 0500 0c000000 00000000"
    "00 00 000a"
)
LIVE_ON = h(
    "14000000 1000 0100 14000000 00000000"
    "00 00 000a"
    "48000000 0c0a 0506 15000000 00000000"  # REQUEST|ACK|EXCL|CREATE: nft's `create element`
    "01 00 0000"
    "0e00 0100 747667775f6761746500 0000"
    "1000 0200 696e706174685f6c69766500"  # "inpath_live\0"
    "1400 0380 1000 0180 0c00 0180 0600 0100 0035 0000"  # one element: port 53, no lifetime
    "14000000 1100 0500 16000000 00000000"
    "00 00 000a"
)
FLUSH = h(
    "14000000 1000 0100 1e000000 00000000"
    "00 00 000a"
    "34000000 0e0a 0500 1f000000 00000000"
    "01 00 0000"  # NFT_MSG_DELSETELEM, REQUEST|ACK, no elements
    "0e00 0100 747667775f6761746500 0000"
    "1000 0200 696e706174685f6c69766500"
    "14000000 1100 0500 20000000 00000000"
    "00 00 000a"
)
PAYLOAD = h("4500001c 00010000 4011 0000 0a0a0a01 0a0a0a11 0035 9c40 0008 0000")  # an empty UDP datagram
PACKET = (
    h(
        "48000000 0003 0000 00000000 00000000"  # 72 bytes, QUEUE<<8 | PACKET, from the kernel
        "02 00 cf3d"  # nfgenmsg: AF_INET
        "0b00 0100 0000002a 0800 03 00"  # NFQA_PACKET_HDR: id 42, ETH_P_IP, hook 3 (output), padding
        "0800 0600 00000002"  # NFQA_IFINDEX_OUTDEV
        "2000 0a00"  # NFQA_PAYLOAD, 28 bytes
    )
    + PAYLOAD
)
ENOENT_FOR_11 = h(
    "24000000 0200 0000 0b000000 39300000"  # NLMSG_ERROR, to seq 11
    "feffffff"  # -2
    "68000000 0c0a 0504 0b000000 00000000"  # the header of the message it answers
)


def ack_bytes(seq: int, error: int = 0) -> bytes:
    """An NLMSG_ERROR datagram as the kernel builds it: the error and the header it answers."""
    inner = nfnl.NLMSG_HDR.pack(20, 0, 0, seq, 0)
    return nfnl.NLMSG_HDR.pack(16 + 4 + 16, nfnl.NLMSG_ERROR, 0, seq, 0) + struct.pack("=i", -error) + inner


@little_endian
def test_the_bind_is_one_message_that_configures_the_queue_whole():
    assert nfnl.queue_bind(QUEUE, 1, 128) == BIND
    assert nfnl.queue_maxlen(QUEUE, 2, 0) == MAXLEN_0


@little_endian
def test_the_only_verdict_is_accept_with_no_payload():
    assert nfnl.verdict(QUEUE, 42) == VERDICT
    # nothing but the verdict header: no NFQA_PAYLOAD (a rewrite), no NFQA_MARK
    assert list(nfnl.attrs(next(nfnl.messages(nfnl.verdict(QUEUE, 7))).body[4:])) == [nfnl.NFQA_VERDICT_HDR]
    assert nfnl.NF_ACCEPT == 1


@little_endian
def test_an_add_carries_the_timeout_and_the_expiry_in_one_transaction():
    """`expires` is what moves an existing element's expiry from kernel 6.12 on (design decision 43)."""
    assert nfnl.setelem_add(10, "tvgw_gate", "resolved4_inpath", [bytes([198, 51, 100, 7])], 86400) == ADD


@little_endian
def test_the_live_switch_is_an_element_without_a_lifetime_and_a_flush():
    assert nfnl.setelem_add(20, "tvgw_gate", "inpath_live", [b"\x00\x35"], create=True) == LIVE_ON
    plain = nfnl.setelem_add(20, "tvgw_gate", "inpath_live", [b"\x00\x35"])
    assert plain != LIVE_ON and plain.replace(bytes.fromhex("0c0a0504"), bytes.fromhex("0c0a0506")) == LIVE_ON
    assert nfnl.set_flush(30, "tvgw_gate", "inpath_live") == FLUSH


def test_several_addresses_go_in_one_message():
    keys = [bytes([203, 0, 113, n]) for n in range(1, 6)]
    begin, add, end = nfnl.messages(nfnl.setelem_add(1, "tvgw_gate", "resolved4_inpath", keys, 86400))
    assert (begin.kind, end.kind) == (nfnl.NFNL_MSG_BATCH_BEGIN, nfnl.NFNL_MSG_BATCH_END)
    assert (begin.seq, add.seq, end.seq) == (1, 2, 3)
    assert add.flags & nfnl.NLM_F_ACK and end.flags & nfnl.NLM_F_ACK and not begin.flags & nfnl.NLM_F_ACK
    top = nfnl.attrs(add.body[4:])
    assert top[nfnl.NFTA_SET_ELEM_LIST_TABLE] == b"tvgw_gate\x00"
    elements = top[nfnl.NFTA_SET_ELEM_LIST_ELEMENTS]
    assert len(elements) == 5 * 40
    found = []
    for off in range(0, len(elements), 40):
        one = nfnl.attrs(elements[off + 4 : off + 40])
        found.append(nfnl.attrs(one[nfnl.NFTA_SET_ELEM_KEY])[nfnl.NFTA_DATA_VALUE])
        assert (
            one[nfnl.NFTA_SET_ELEM_TIMEOUT]
            == one[nfnl.NFTA_SET_ELEM_EXPIRATION]
            == struct.pack(">Q", 86400000)
        )
    assert found == keys


def test_an_attribute_that_cannot_carry_its_length_is_refused():
    with pytest.raises(ValueError):
        nfnl.attr(1, bytes(0x10000))


@little_endian
def test_a_queued_packet_is_read_with_its_id_and_its_payload():
    (msg,) = nfnl.messages(PACKET)
    assert nfnl.queue_packet(msg) == nfnl.Packet(42, 3, PAYLOAD, True)
    assert nfnl.ack(msg) is None


def test_a_packet_cut_at_the_copy_range_says_so():
    cut = nfnl.message(
        (nfnl.NFNL_SUBSYS_QUEUE << 8) | nfnl.NFQNL_MSG_PACKET,
        0,
        0,
        2,
        QUEUE,
        nfnl.attr(nfnl.NFQA_PACKET_HDR, struct.pack(">IHB", 9, 0x0800, 3))
        + nfnl.attr(nfnl.NFQA_CAP_LEN, struct.pack(">I", 70000))
        + nfnl.attr(nfnl.NFQA_PAYLOAD, b"\x45" * 20),
    )
    packet = nfnl.queue_packet(next(nfnl.messages(cut)))
    assert packet.id == 9 and packet.whole is False


def test_a_packet_message_without_a_payload_still_has_its_id():
    bare = nfnl.message(
        (nfnl.NFNL_SUBSYS_QUEUE << 8) | nfnl.NFQNL_MSG_PACKET,
        0,
        0,
        2,
        QUEUE,
        nfnl.attr(nfnl.NFQA_PACKET_HDR, struct.pack(">IHB", 5, 0x0800, 3)),
    )
    assert nfnl.queue_packet(next(nfnl.messages(bare))) == nfnl.Packet(5, 3, None, True)


def test_a_packet_message_without_its_header_is_an_error_not_a_packet():
    for attrs in (b"", nfnl.attr(nfnl.NFQA_PACKET_HDR, b"\x00\x00\x00"), nfnl.attr(nfnl.NFQA_PAYLOAD, b"x")):
        msg = next(nfnl.messages(nfnl.message((nfnl.NFNL_SUBSYS_QUEUE << 8), 0, 0, 2, QUEUE, attrs)))
        with pytest.raises(nfnl.NlError):
            nfnl.queue_packet(msg)


@little_endian
def test_an_error_names_the_message_it_answers():
    (msg,) = nfnl.messages(ENOENT_FOR_11)
    assert nfnl.ack(msg) == (11, 2)
    assert nfnl.queue_packet(msg) is None
    assert nfnl.ack(next(nfnl.messages(ack_bytes(12)))) == (12, 0)


def test_a_transaction_is_committed_only_when_its_end_is_acknowledged():
    ok = [ack_bytes(11), ack_bytes(12)]
    assert nfnl.batch_result(ok, 10) == 0
    assert nfnl.batch_result([b"".join(ok)], 10) == 0  # in one datagram or in two
    assert nfnl.batch_result([ack_bytes(11)], 10) == 5  # the element was taken, the commit never confirmed
    assert nfnl.batch_result([], 10) == 5
    assert nfnl.batch_result([ack_bytes(11, 2)], 10) == 2  # ENOENT: no such table or set
    assert nfnl.batch_result([ack_bytes(10, 12)], 10) == 12  # an error on the batch itself (ENOMEM)
    assert nfnl.batch_result([ack_bytes(11, 2), ack_bytes(12)], 10) == 2  # an error wins over any ack
    # answers to an earlier transaction, read late, decide nothing
    assert nfnl.batch_result([ack_bytes(8, 2), ack_bytes(9), *ok], 10) == 0
    assert nfnl.batch_result([ack_bytes(9)], 10) == 5
    assert nfnl.batch_result([b"\x10\x00\x00\x00garbage that is no message"], 10) == 5


def test_messages_stops_at_a_length_that_does_not_fit():
    two = PACKET + ack_bytes(3)
    assert [m.kind for m in nfnl.messages(two)] == [0x0300, nfnl.NLMSG_ERROR]
    assert list(nfnl.messages(b"")) == [] and list(nfnl.messages(b"\x00" * 15)) == []
    for bad in (
        struct.pack("=IHHII", 8, 0, 0, 0, 0),  # shorter than its own header
        struct.pack("=IHHII", 64, 0, 0, 0, 0) + b"\x00" * 8,  # longer than the datagram
    ):
        with pytest.raises(nfnl.NlError):
            list(nfnl.messages(bad))


def test_attrs_is_bounded_and_strict_about_lengths():
    one = nfnl.attr(7, b"abc")
    assert nfnl.attrs(one) == {7: b"abc"}
    assert nfnl.attrs(nfnl.attr(7, b"abc", nested=True)) == {7: b"abc"}  # the nested flag is not the type
    assert nfnl.attrs(nfnl.attr(7, b"first") + nfnl.attr(7, b"second")) == {7: b"first"}
    assert nfnl.attrs(one + b"\x00\x00") == {7: b"abc"}  # less than a header left: padding
    with pytest.raises(nfnl.NlError):
        nfnl.attrs(struct.pack("=HH", 3, 1))  # shorter than its header
    with pytest.raises(nfnl.NlError):
        nfnl.attrs(struct.pack("=HH", 40, 1) + b"abcd")  # longer than what is left
    with pytest.raises(nfnl.NlError):
        nfnl.attrs(nfnl.attr(1, b"") * (nfnl.MAX_ATTRS + 1))
    assert (
        len(nfnl.attrs(b"".join(nfnl.attr(n, b"") for n in range(1, nfnl.MAX_ATTRS + 1)))) == nfnl.MAX_ATTRS
    )


def decode(data: bytes) -> None:
    """Everything the filler does with a datagram from the kernel."""
    for msg in nfnl.messages(data):
        with contextlib.suppress(nfnl.NlError):
            nfnl.queue_packet(msg)
        with contextlib.suppress(nfnl.NlError):
            nfnl.ack(msg)


def test_no_bytes_make_the_decoders_raise_anything_but_nlerror():
    """Truncations and single-byte changes of every real message, and random noise: fuzzing with a
    fixed seed, so a failure names its input."""
    rng = random.Random(64)
    seeds = [PACKET, ENOENT_FOR_11, ADD, BIND, VERDICT, PACKET + ack_bytes(1) + PACKET]
    cases = [s[:n] for s in seeds for n in range(len(s) + 1)]
    for s in seeds:
        for _ in range(400):
            b = bytearray(s)
            for _ in range(rng.randint(1, 3)):
                b[rng.randrange(len(b))] = rng.randrange(256)
            cases.append(bytes(b))
    cases += [rng.randbytes(rng.randrange(0, 200)) for _ in range(2000)]
    for data in cases:
        with contextlib.suppress(nfnl.NlError):
            decode(data)
        assert isinstance(nfnl.batch_result([data], 10), int)  # an errno, whatever the bytes
