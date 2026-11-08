"""nfnetlink, the few messages the in-path gate filler speaks (design decision 64): the kernel's packet
queue (nfnetlink_queue: bind, the packets it hands over, the verdicts that release them) and nf_tables
set elements (add with a lifetime, flush), encoded and decoded by hand on the standard library; and
(namebound) the log groups the live name count reads (nfnetlink_log: bind, the copies it hands over;
design decision 70).

Everything here is a pure function over bytes, so every message is tested against fixed bytes on any
machine; the sockets that carry them are opened in `tvgw.gatefill`. The layouts are the kernel's
(`include/uapi/linux/netlink.h`, `netfilter/nfnetlink.h`, `netfilter/nfnetlink_queue.h`,
`netfilter/nf_tables.h`, read at v6.18): a netlink header in the machine's byte order, then `nfgenmsg`
(family, version, a 16-bit resource id in network order), then attributes, each a 16-bit length and a
16-bit type in the machine's order with its payload padded to four bytes. The values inside the
attributes are in network order.

The decoders read what the kernel sent, and still trust nothing: a length that does not fit ends the
walk with `NlError`, an attribute walk is bounded, and no input can make them raise anything else.
"""

from __future__ import annotations

import struct
from collections.abc import Iterator
from dataclasses import dataclass

NETLINK_NETFILTER = 12
# socket-level names Python's socket module does not carry on every platform (linux/socket.h, netlink.h)
AF_NETLINK = 16
SOL_NETLINK = 270
NETLINK_NO_ENOBUFS = 5
SO_RCVBUFFORCE = 33

NLMSG_ERROR = 2
NLMSG_MIN_TYPE = 16
NLM_F_REQUEST = 0x001
NLM_F_ACK = 0x004
NLM_F_EXCL = 0x200
NLM_F_CREATE = 0x400
NLA_F_NESTED = 0x8000
NLA_TYPE_MASK = 0x3FFF  # without NLA_F_NESTED and NLA_F_NET_BYTEORDER
NLMSG_HDR = struct.Struct("=IHHII")  # length, type, flags, sequence, port id
NLA_HDR = struct.Struct("=HH")  # length (header included, padding not), type
NFGENMSG = struct.Struct(">BBH")  # family, version, resource id (a queue number, a subsystem)
NFGENMSG_LEN = 4
MAX_ATTRS = 64  # one message's attributes: the queue sends about ten, an error none

NFNL_SUBSYS_QUEUE = 3
NFNL_SUBSYS_NFTABLES = 10
NFNL_MSG_BATCH_BEGIN = NLMSG_MIN_TYPE
NFNL_MSG_BATCH_END = NLMSG_MIN_TYPE + 1

# nfnetlink_queue
NFQNL_MSG_PACKET = 0
NFQNL_MSG_VERDICT = 1
NFQNL_MSG_CONFIG = 2
NFQA_PACKET_HDR = 1
NFQA_VERDICT_HDR = 2
NFQA_PAYLOAD = 10
NFQA_CAP_LEN = 13
NFQA_CFG_CMD = 1
NFQA_CFG_PARAMS = 2
NFQA_CFG_QUEUE_MAXLEN = 3
NFQA_CFG_MASK = 4
NFQA_CFG_FLAGS = 5
NFQNL_CFG_CMD_BIND = 1
NFQNL_COPY_PACKET = 2
NFQA_CFG_F_FAIL_OPEN = 1
NFQNL_MAX_COPY_RANGE = 0xFFFF - 4  # what the kernel caps a copy at: an attribute's 16-bit length
NF_ACCEPT = 1
PACKET_HDR = struct.Struct(">IHB")  # packet id, hardware protocol, hook

# (namebound) nfnetlink_log: the copies `log group N` hands over (netfilter/nfnetlink_log.h at v6.18)
NFNL_SUBSYS_ULOG = 4
NFULNL_MSG_PACKET = 0
NFULNL_MSG_CONFIG = 1
NFULA_PACKET_HDR = 1
NFULA_PAYLOAD = 9
NFULA_PREFIX = 10
NFULA_CFG_CMD = 1
NFULA_CFG_MODE = 2
NFULNL_CFG_CMD_BIND = 1
NFULNL_CFG_CMD_UNBIND = 2
NFULNL_COPY_PACKET = 2

# nf_tables
NFPROTO_INET = 1
NFT_MSG_NEWSETELEM = 12
NFT_MSG_DELSETELEM = 14
NFTA_SET_ELEM_LIST_TABLE = 1
NFTA_SET_ELEM_LIST_SET = 2
NFTA_SET_ELEM_LIST_ELEMENTS = 3
NFTA_LIST_ELEM = 1
NFTA_SET_ELEM_KEY = 1
NFTA_SET_ELEM_TIMEOUT = 4
NFTA_SET_ELEM_EXPIRATION = 5
NFTA_DATA_VALUE = 1


class NlError(ValueError):
    """A netlink message that does not parse."""


# --- encoding ----------------------------------------------------------------------------------------


def _pad(data: bytes) -> bytes:
    return data + b"\x00" * (-len(data) % 4)


def attr(kind: int, payload: bytes, nested: bool = False) -> bytes:
    """One attribute: the length counts the header and the payload, not the padding after it."""
    if len(payload) > 0xFFFF - NLA_HDR.size:
        raise ValueError(f"attribute payload of {len(payload)} bytes does not fit a 16-bit length")
    head = NLA_HDR.pack(NLA_HDR.size + len(payload), kind | (NLA_F_NESTED if nested else 0))
    return _pad(head + payload)


def message(kind: int, flags: int, seq: int, family: int, res_id: int, attrs: bytes = b"") -> bytes:
    """One nfnetlink message: the netlink header, nfgenmsg, the attributes. The port id is 0: the
    kernel fills in the sender's."""
    body = NFGENMSG.pack(family, 0, res_id) + attrs
    return _pad(NLMSG_HDR.pack(NLMSG_HDR.size + len(body), kind, flags | NLM_F_REQUEST, seq, 0) + body)


def queue_bind(queue: int, seq: int, maxlen: int, copy_range: int = NFQNL_MAX_COPY_RANGE) -> bytes:
    """Bind `queue` to the sending socket, whole packets copied, at most `maxlen` waiting, and failing
    open: a packet that finds the queue or the socket's buffer full is accepted by the kernel instead
    of dropped. One message, so the queue is never bound with a mode that is not yet set for longer than
    the kernel takes to read on (a bound queue with no copy mode drops what reaches it)."""
    attrs = (
        attr(NFQA_CFG_CMD, struct.pack(">BBH", NFQNL_CFG_CMD_BIND, 0, 0))
        + attr(NFQA_CFG_PARAMS, struct.pack(">IB", copy_range, NFQNL_COPY_PACKET))
        + attr(NFQA_CFG_QUEUE_MAXLEN, struct.pack(">I", maxlen))
        + attr(NFQA_CFG_MASK, struct.pack(">I", NFQA_CFG_F_FAIL_OPEN))
        + attr(NFQA_CFG_FLAGS, struct.pack(">I", NFQA_CFG_F_FAIL_OPEN))
    )
    return message((NFNL_SUBSYS_QUEUE << 8) | NFQNL_MSG_CONFIG, NLM_F_ACK, seq, 0, queue, attrs)


def queue_maxlen(queue: int, seq: int, maxlen: int) -> bytes:
    """Change how many packets may wait. 0 closes the queue to new packets while it stays bound: with
    fail-open set the kernel accepts each one itself, which is how the filler empties the queue before
    it lets go of it (the kernel drops whatever still waits in a queue that is unbound)."""
    attrs = attr(NFQA_CFG_QUEUE_MAXLEN, struct.pack(">I", maxlen))
    return message((NFNL_SUBSYS_QUEUE << 8) | NFQNL_MSG_CONFIG, NLM_F_ACK, seq, 0, queue, attrs)


def verdict(queue: int, packet_id: int, seq: int = 0) -> bytes:
    """Accept packet `packet_id` as it is. No other verdict exists here: the filler never drops and
    never rewrites, so it sends no payload, no mark and nothing but NF_ACCEPT. No acknowledgement is
    asked for; the kernel still answers an id it does not hold with an error."""
    attrs = attr(NFQA_VERDICT_HDR, struct.pack(">II", NF_ACCEPT, packet_id))
    return message((NFNL_SUBSYS_QUEUE << 8) | NFQNL_MSG_VERDICT, 0, seq, 0, queue, attrs)


def log_bind(group: int, seq: int, copy_range: int) -> bytes:
    """(namebound) Bind NFLOG group `group` to the sending socket, whole packets copied up to
    `copy_range` bytes (the rule's own snaplen cuts first). A group takes one socket: a second bind is
    refused with EBUSY. Nothing waits on a log group: the kernel copies the packet and the packet goes on,
    so a socket bound here, slow or gone, holds back no packet of anyone's."""
    attrs = attr(NFULA_CFG_CMD, struct.pack(">B", NFULNL_CFG_CMD_BIND)) + attr(
        NFULA_CFG_MODE, struct.pack(">IBB", copy_range, NFULNL_COPY_PACKET, 0)
    )
    return message((NFNL_SUBSYS_ULOG << 8) | NFULNL_MSG_CONFIG, NLM_F_ACK, seq, 0, group, attrs)


def log_unbind(group: int, seq: int) -> bytes:
    """(namebound) Let go of NFLOG group `group`."""
    attrs = attr(NFULA_CFG_CMD, struct.pack(">B", NFULNL_CFG_CMD_UNBIND))
    return message((NFNL_SUBSYS_ULOG << 8) | NFULNL_MSG_CONFIG, NLM_F_ACK, seq, 0, group, attrs)


def _name(text: str) -> bytes:
    return text.encode("ascii") + b"\x00"


def _batch(seq: int, kind: int, flags: int, family: int, attrs: bytes) -> bytes:
    """One nf_tables transaction of one message: begin (seq), the message (seq + 1), end (seq + 2).
    The message and the end both ask for an acknowledgement: the message's says whether it was taken
    (0 or an errno), the end's arrives only when the transaction was committed."""
    return transaction(seq, [(kind, flags, family, attrs)])


# (attention) one message of a transaction, before its sequence number is known: (kind, flags, family,
# attributes). The dead-man entries of design decision 69 move the TV from one state's set to another's in
# one transaction, so that the kernel never holds it in two states, nor drops it while it moves
Part = tuple[int, int, int, bytes]


def transaction(seq: int, parts: list[Part]) -> bytes:
    """One nf_tables transaction: begin (seq), each part (seq + 1 onward), end (seq + len(parts) + 1).
    Every part and the end ask for an acknowledgement, as `_batch` does; `batch_result(replies, seq,
    len(parts))` reads them. The kernel applies the parts in order and commits all of them or none."""
    if not parts:
        raise ValueError("a transaction needs at least one message")
    out = message(NFNL_MSG_BATCH_BEGIN, 0, seq, 0, NFNL_SUBSYS_NFTABLES)
    for i, (kind, flags, family, attrs) in enumerate(parts, 1):
        out += message((NFNL_SUBSYS_NFTABLES << 8) | kind, flags | NLM_F_ACK, seq + i, family, 0, attrs)
    return out + message(NFNL_MSG_BATCH_END, NLM_F_ACK, seq + len(parts) + 1, 0, NFNL_SUBSYS_NFTABLES)


def setelem_add_part(
    table: str,
    set_name: str,
    keys: list[bytes],
    ttl: int | None = None,
    family: int = NFPROTO_INET,
    create: bool = False,
) -> Part:
    """The message of `setelem_add`, for a transaction of several (see there)."""
    life = b""
    if ttl is not None:
        ms = struct.pack(">Q", ttl * 1000)
        life = attr(NFTA_SET_ELEM_TIMEOUT, ms) + attr(NFTA_SET_ELEM_EXPIRATION, ms)
    elements = b"".join(
        attr(
            NFTA_LIST_ELEM,
            attr(NFTA_SET_ELEM_KEY, attr(NFTA_DATA_VALUE, key), nested=True) + life,
            nested=True,
        )
        for key in keys
    )
    attrs = (
        attr(NFTA_SET_ELEM_LIST_TABLE, _name(table))
        + attr(NFTA_SET_ELEM_LIST_SET, _name(set_name))
        + attr(NFTA_SET_ELEM_LIST_ELEMENTS, elements, nested=True)
    )
    return NFT_MSG_NEWSETELEM, NLM_F_CREATE | (NLM_F_EXCL if create else 0), family, attrs


def setelem_add(
    seq: int,
    table: str,
    set_name: str,
    keys: list[bytes],
    ttl: int | None = None,
    family: int = NFPROTO_INET,
    create: bool = False,
) -> bytes:
    """`add element <family> <table> <set> { key [timeout ttl expires ttl], ... }` as one transaction.
    With `ttl` (seconds) each element carries both its timeout and its expiry: from kernel 6.12 an add
    that meets an element already in the set moves its expiry only when the add names one (design
    decision 43). NLM_F_CREATE without NLM_F_EXCL is `add`: an element already there is not an error.
    With `create` the message carries NLM_F_EXCL too, nft's `create element`: the kernel answers EEXIST
    for an element already there and changes nothing, which tells the sender whether it was."""
    return transaction(seq, [setelem_add_part(table, set_name, keys, ttl, family, create)])


def set_flush_part(table: str, set_name: str, family: int = NFPROTO_INET) -> Part:
    """The message of `set_flush`, for a transaction of several."""
    attrs = attr(NFTA_SET_ELEM_LIST_TABLE, _name(table)) + attr(NFTA_SET_ELEM_LIST_SET, _name(set_name))
    return NFT_MSG_DELSETELEM, 0, family, attrs


def set_flush(seq: int, table: str, set_name: str, family: int = NFPROTO_INET) -> bytes:
    """`flush set <family> <table> <set>` as one transaction: a delete that names no element."""
    return transaction(seq, [set_flush_part(table, set_name, family)])


# --- decoding ----------------------------------------------------------------------------------------


@dataclass(frozen=True)
class Msg:
    kind: int
    flags: int
    seq: int
    body: bytes  # after the netlink header: nfgenmsg and attributes, or an error's payload


def messages(data: bytes) -> Iterator[Msg]:
    """The netlink messages of one datagram. A header whose length does not fit what is left raises
    NlError; trailing bytes shorter than a header are padding and end the walk."""
    off = 0
    while len(data) - off >= NLMSG_HDR.size:
        length, kind, flags, seq, _pid = NLMSG_HDR.unpack_from(data, off)
        if length < NLMSG_HDR.size or length > len(data) - off:
            raise NlError(f"message length {length} at offset {off} of {len(data)}")
        yield Msg(kind, flags, seq, data[off + NLMSG_HDR.size : off + length])
        off += (length + 3) & ~3


def attrs(data: bytes, limit: int = MAX_ATTRS) -> dict[int, bytes]:
    """type -> payload for one level of attributes (the first of a repeated type wins). The walk stops
    with NlError at a length that does not fit, and after `limit` attributes."""
    out: dict[int, bytes] = {}
    off = n = 0
    while len(data) - off >= NLA_HDR.size:
        length, kind = NLA_HDR.unpack_from(data, off)
        if length < NLA_HDR.size or length > len(data) - off:
            raise NlError(f"attribute length {length} at offset {off} of {len(data)}")
        n += 1
        if n > limit:
            raise NlError(f"more than {limit} attributes")
        out.setdefault(kind & NLA_TYPE_MASK, data[off + NLA_HDR.size : off + length])
        off += (length + 3) & ~3
    return out


@dataclass(frozen=True)
class Packet:
    """A packet the queue handed over. `payload` is the IP packet from its header on, or None when the
    kernel sent none; `whole` is False when the kernel cut it at the copy range."""

    id: int
    hook: int
    payload: bytes | None
    whole: bool = True


def queue_packet(msg: Msg) -> Packet | None:
    """The packet in an NFQNL_MSG_PACKET message, or None for any other message. NlError when it is a
    packet message with no id: without the id there is nothing to release."""
    if msg.kind != (NFNL_SUBSYS_QUEUE << 8) | NFQNL_MSG_PACKET:
        return None
    if len(msg.body) < NFGENMSG_LEN:
        raise NlError("packet message shorter than nfgenmsg")
    found = attrs(msg.body[NFGENMSG_LEN:])
    head = found.get(NFQA_PACKET_HDR)
    if head is None or len(head) < PACKET_HDR.size:
        raise NlError("packet message without a packet header")
    packet_id, _proto, hook = PACKET_HDR.unpack_from(head)
    return Packet(packet_id, hook, found.get(NFQA_PAYLOAD), NFQA_CAP_LEN not in found)


def log_packet(msg: Msg) -> bytes | None:
    """(namebound) The packet, from its IP header on, of an NFULNL_MSG_PACKET message; None for any other
    message and for a copy that carries no payload."""
    if msg.kind != (NFNL_SUBSYS_ULOG << 8) | NFULNL_MSG_PACKET:
        return None
    if len(msg.body) < NFGENMSG_LEN:
        raise NlError("log message shorter than nfgenmsg")
    return attrs(msg.body[NFGENMSG_LEN:]).get(NFULA_PAYLOAD)


def ack(msg: Msg) -> tuple[int, int] | None:
    """(the sequence number it answers, errno) for an NLMSG_ERROR message, errno 0 being a plain
    acknowledgement; None for any other message. The kernel's error is negative; the errno returned is
    positive."""
    if msg.kind != NLMSG_ERROR:
        return None
    if len(msg.body) < 4 + NLMSG_HDR.size:
        raise NlError("error message shorter than its header")
    (error,) = struct.unpack_from("=i", msg.body)
    _length, _kind, _flags, seq, _pid = NLMSG_HDR.unpack_from(msg.body, 4)
    return seq, -error


def batch_result(replies: list[bytes], seq: int, parts: int = 1) -> int:
    """The outcome of the transaction `transaction(seq, <parts messages>)` sent (`_batch(seq, ...)` is one
    of one), from every datagram the kernel answered it with: 0 when the end's acknowledgement is there
    and nothing reported an error, else the first errno reported, else EIO (5) for an answer that never
    said the transaction was committed."""
    end = seq + parts + 1
    committed = False
    for data in replies:
        try:
            found = [a for m in messages(data) if (a := ack(m)) is not None]
        except NlError:
            return 5
        for answered, errno_ in found:
            if not seq <= answered <= end:
                continue  # an answer to an earlier transaction, read late
            if errno_:
                return errno_
            committed = committed or answered == end
    return 0 if committed else 5
