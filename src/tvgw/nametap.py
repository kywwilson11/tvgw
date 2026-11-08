"""(namebound) Name-bound egress, stage 2 (design decision 70): the live count, read beside the packet path.

With NAME_BINDING=count, tvgw-apply loads `inet tvgw_names`, whose rules copy, with nftables' `log group`
(NFLOG), every DNS answer the gateway sends the TV and the first packets the TV sends on each TCP
connection to port 443. This process binds that log group, remembers for WINDOW which names each answer
gave each address, reads the server name from each connection's first hello (`clienthello`) and counts the
connection in `tvgw.namebound`'s classes. `tvgw verify --record` stores its counts as series beside the
store's own check of the same connections (stage 1), so the two can be compared.

It never refuses, and it cannot: a log rule copies the packet and the packet goes on at once. Nothing
waits for this process. Slow, stopped, killed or not running, it costs the TV nothing: the kernel throws
away the copies nobody reads. The only verdict in the table is the base chains' policy, accept.

Two properties keep the address gate's race out of this count:

- **Order.** The answer and the hello go to the same log group, so to one socket, in the order the
  kernel copied them. An answer is copied on its way out of the gateway, and the TV cannot send a hello
  for it before it arrives, so the copy of an answer is always read before the copy of any hello that
  follows it, however late this process reads either.
- **Loss is seen.** When the socket's buffer is full the kernel drops a copy and the next read fails with
  ENOBUFS; an answer can also arrive in a form this process does not read (a TCP answer across segments,
  one over MAX_DNS bytes). Both are counted (`lost`, `answers_unread`), and for LOSS_PROTECT after either
  a connection that would count as `shared` or `never` counts as not assessed instead, by that reason:
  its answer may be the one that was not read. A cached answer the TV keeps longer than that can still
  make a later connection count `never`, which is why the losses are counted beside it.

The other two reasons a connection is not assessed, each counted on its own: the memory does not reach
back a day (`unassessed_start`), and an address answered for more than MAX_NAMES names in its day, some of
which had to be let go (`unassessed_crowded`). At start the memory is filled from AdGuard Home's query
log, the TV's answers of the last WINDOW (`adguard.records_since`). When that read reaches back the whole
window, the memory covers the day, except for the few newest lookups AdGuard Home has not written yet:
for STARTUP_GRACE a mismatch at an address no live copy has shown is not assessed either. When the read
stops short, a connection whose day before reaches past what was read is not assessed, as stage 1 counts
a connection its table does not reach back for.

With NAME_HMAC=on the names in the status file's samples are tagged as the store tags them
(`minimize.NameHasher`); a name whose key this sandboxed process cannot read is left out.

Everything that reads bytes reads the TV's packets and the answers of upstream servers, so it is bounded
and never raises: an answer over MAX_DNS bytes is not read, a hello is assembled from at most
HELLO_SEGMENTS segments and HELLO_BYTES bytes, and the memory holds at most MAX_ADDRESSES addresses of at
most MAX_NAMES names each. The loop takes its socket, its clock and its status writer as parameters, so all
of it runs in the unit tests; the netlink messages are `tvgw.nfnl`'s.
"""

from __future__ import annotations

import contextlib
import errno
import os
import select
import signal
import socket
import sqlite3
import struct
import sys
import time
from collections import OrderedDict
from collections.abc import Callable
from dataclasses import asdict, dataclass

from tvgw import adguard, clienthello, dnsmsg, nfnl
from tvgw.config import Settings
from tvgw.inpath import notify, write_status
from tvgw.namebound import BOUND, ECH, NEVER, NONAME, SHARED, UNASSESSED, WINDOW, addresses, chain
from tvgw.names import is_public_address, normalize

GROUP = 8  # the NFLOG group; tvgw-apply's NAMES_GROUP (test_deploy_lint keeps them equal)
COPY_RANGE = 4096  # bytes of each copy this socket asks for; the rules' snaplen is the same
RCVBUF = 1 << 21  # the socket's receive buffer: a burst of a few hundred copies fits
RECV_SIZE = 1 << 17
MAX_DNS = 4096  # bytes of DNS message read; a longer one is counted unparsed, as the in-path filler counts it
TCP_MESSAGES = 16  # DNS messages read from one TCP segment
MAX_ADDRESSES = 65_536  # addresses remembered, the oldest answered first out: the gate's set holds as many
# names remembered per address within their day; past it the soonest to expire goes, and while that name's
# day lasts the address is crowded: a mismatch there may be the name let go
MAX_NAMES = 64
MAX_SEEN_NAMES = 65_536  # names any answer gave, for the ECH test
HELLO_SEGMENTS = 6  # segments a split hello is assembled from (the rule copies the first 8 packets)
HELLO_BYTES = 16_384  # bytes of it
MAX_PENDING = 256  # connections whose hello is being assembled at once
SEEN_FOR = 300.0  # seconds a connection is remembered, so its retransmitted hello counts once
MAX_SEEN = 16_384
# seconds after a lost copy or an answer not read during which a mismatch counts as not assessed: an hour,
# longer than the lifetime the TV's answers mostly carry, short of the day an app's own cache can reach
LOSS_PROTECT = 3600.0
# seconds after start during which a mismatch at an address no live copy has shown is not assessed:
# AdGuard Home writes its query log in batches, so the newest lookups are not in the memory read at start
STARTUP_GRACE = 900.0
STATUS = "/run/tvgw-names/status.json"  # the unit's RuntimeDirectory; verify reads it
STATUS_EVERY = 10.0
STATUS_STALE = 60.0
SAMPLES = 5  # the last connections of the two classes that matter, in the status file only
# Every counted rule of tvgw-apply's names table has a comment that starts with RULE_PREFIX, and so does
# every series `tvgw verify --record` stores from the status file: they measure the live count, not what
# the firewall held, so the brief keeps them out of "Firewall held" and shows them in its names section
RULE_PREFIX = "names:"
COPY_RULES = (  # the table's three rules (their counters: the copies the kernel made)
    "names: DNS answers to the TV, copied",
    "names: DNS answers to the TV over TCP, copied",
    "names: first packets of the TV's TLS connections, copied",
)
# (the status file's field, its fw_counters series): counts since the process started, so a restart starts
# each again from zero, which the brief reads as a reloaded counter
SERIES = (
    (BOUND, "names: TLS connections name-bound"),
    (SHARED, "names: TLS connections to an address answered for another name"),
    (NEVER, "names: TLS connections to an address never answered"),
    (NONAME, "names: TLS hellos without a name"),
    (ECH, "names: TLS hellos with ECH"),
    (UNASSESSED, "names: TLS connections not assessed"),
    ("unassessed_start", "names: TLS connections not assessed, the memory short of a day"),
    ("unassessed_loss", "names: TLS connections not assessed, after a copy lost or not read"),
    ("unassessed_crowded", "names: TLS connections not assessed, an address of too many names"),
    ("answers", "names: DNS answers read"),
    ("answers_unread", "names: DNS answers not read"),
    ("lost", "names: copies the kernel dropped before they were read"),
    ("unparsed", "names: copies not read"),
)
# the reasons a connection is not assessed, as the Stats fields that count them
UNASSESSED_REASONS = ("unassessed_start", "unassessed_loss", "unassessed_crowded")


@dataclass
class Stats:
    bound: int = 0
    shared: int = 0
    never: int = 0
    noname: int = 0
    ech: int = 0
    unassessed: int = 0  # the three below, together
    unassessed_start: int = 0  # the memory does not reach back a day, or a start's unwritten lookups
    unassessed_loss: int = 0  # within LOSS_PROTECT of a lost copy or an answer not read
    unassessed_crowded: int = 0  # at an address whose names had to be let go within their day
    answers: int = 0  # DNS messages read
    answers_unread: int = 0  # copies of answers not read (malformed, over MAX_DNS, across TCP segments)
    copies: int = 0  # copies received
    not_tls: int = 0  # a connection whose first data was no TLS hello
    unparsed: int = 0  # copies not read at all: not IPv4, a fragment, cut, an answer counted below
    lost: int = 0  # reads that failed with ENOBUFS: the kernel dropped at least one copy each time
    errors: int = 0


# ---- reading a copy ------------------------------------------------------------------------------------
def _ip(packet: bytes) -> tuple[int, int, bytes, bytes, bytes] | None:
    """(protocol, header length, source, destination, the packet cut at its total length) of an IPv4
    packet that is not a fragment; None for anything else."""
    if len(packet) < 20 or packet[0] >> 4 != 4:
        return None
    ihl = (packet[0] & 0x0F) * 4
    total, frag = struct.unpack_from(">H", packet, 2)[0], struct.unpack_from(">H", packet, 6)[0]
    if ihl < 20 or total < ihl or total > len(packet) or frag & 0x3FFF:
        return None
    return packet[9], ihl, packet[12:16], packet[16:20], packet[:total]


def _dotted(addr: bytes) -> str:
    return ".".join(str(b) for b in addr)


def read_message(msg: bytes) -> tuple[list[str], list[str]] | None:
    """(the names the answer binds, its public A addresses) of one DNS answer; None when it cannot be
    read. A message that is no answer, or one with the truncation bit, binds nothing: ([], [])."""
    if len(msg) < 12 or len(msg) > MAX_DNS:
        return None
    if not msg[2] & 0x80 or msg[2] & 0x02:
        return [], []
    try:
        qd = struct.unpack_from(">H", msg, 4)[0]
        qname = dnsmsg.read_name(msg, 12)[0] if qd else ""
        found = dnsmsg.decode_answers(msg)
    except (dnsmsg.DnsFormatError, struct.error, ValueError):
        return None
    text = ",".join(f"{a.rtype}:{a.value}" for a in found)
    return chain(qname, text), addresses(text)


def read_answer(packet: bytes) -> list[tuple[list[str], list[str]]] | None:
    """The DNS messages of a copied answer (UDP, or a TCP segment that is exactly one or more whole
    length-prefixed messages); None when it cannot be read."""
    ip = _ip(packet)
    if ip is None:
        return None
    proto, ihl, _src, _dst, pkt = ip
    if proto == 17:
        if len(pkt) < ihl + 8:
            return None
        one = read_message(pkt[ihl + 8 :])
        return None if one is None else [one]
    if proto != 6 or len(pkt) < ihl + 20:
        return None
    doff = (pkt[ihl + 12] >> 4) * 4
    data = pkt[ihl + doff :] if doff >= 20 and len(pkt) >= ihl + doff else None
    if data is None:
        return None
    out = []
    off = 0
    while off < len(data):
        if len(out) >= TCP_MESSAGES or off + 2 > len(data):
            return None
        (length,) = struct.unpack_from(">H", data, off)
        if length == 0 or off + 2 + length > len(data):
            return None
        one = read_message(data[off + 2 : off + 2 + length])
        if one is None:
            return None
        out.append(one)
        off += 2 + length
    return out


@dataclass(frozen=True)
class Segment:
    """A TCP segment the TV sent: its connection, its sequence number and its data."""

    dst: str
    sport: int
    dport: int
    seq: int
    data: bytes


def read_segment(packet: bytes) -> Segment | None:
    ip = _ip(packet)
    if ip is None or ip[0] != 6:
        return None
    _proto, ihl, _src, dst, pkt = ip
    if len(pkt) < ihl + 20:
        return None
    sport, dport, seq = struct.unpack_from(">HHI", pkt, ihl)
    doff = (pkt[ihl + 12] >> 4) * 4
    if doff < 20 or len(pkt) < ihl + doff:
        return None
    return Segment(_dotted(dst), sport, dport, seq, pkt[ihl + doff :])


# ---- the memory ----------------------------------------------------------------------------------------
class Memory:
    """address -> {name: until}, for the answers of the last WINDOW, bounded; every name answered; and the
    addresses that had to let a name go before its day ended, until that day ends (`crowded`)."""

    def __init__(self, max_addresses: int = MAX_ADDRESSES, max_names: int = MAX_NAMES):
        self.by_addr: OrderedDict[str, dict[str, float]] = OrderedDict()
        self.names: OrderedDict[str, float] = OrderedDict()
        self.crowded: dict[str, float] = {}
        self.max_addresses, self.max_names = max_addresses, max_names

    def remember(self, names: list[str], addrs: list[str], t: float) -> None:
        until = t + WINDOW
        for name in names:
            self.names[name] = until
            self.names.move_to_end(name)
        while len(self.names) > MAX_SEEN_NAMES:
            self.names.popitem(last=False)
        for addr in addrs:
            known = self.by_addr.setdefault(addr, {})
            self.by_addr.move_to_end(addr)
            for name in [n for n, u in known.items() if u < t]:  # their day is over: they bind nothing
                del known[name]
            for name in names:
                known[name] = until
            while len(known) > self.max_names:
                gone = min(known, key=lambda n: (known[n], n))
                self.crowded[addr] = max(self.crowded.get(addr, 0.0), known.pop(gone))
        while len(self.by_addr) > self.max_addresses:
            gone, _ = self.by_addr.popitem(last=False)
            self.crowded.pop(gone, None)

    def is_crowded(self, addr: str, t: float) -> bool:
        """Whether `addr` let go of a name whose day had not ended by `t`."""
        return self.crowded.get(addr, 0.0) >= t

    def answered(self, name: str, t: float) -> bool:
        return self.names.get(name, 0) >= t

    def judge(self, name: str, addr: str, t: float) -> str:
        """BOUND, SHARED or NEVER for a hello naming `name` to `addr` at `t`."""
        known = self.by_addr.get(addr) or {}
        if known.get(name, 0) >= t:
            return BOUND
        if any(until >= t for until in known.values()):
            return SHARED
        return NEVER


# ---- the count -----------------------------------------------------------------------------------------
class Tap:
    """What the copies say: each answer remembered, each connection's first hello counted once."""

    def __init__(
        self,
        gw_ip: str,
        now: Callable[[], float],
        assessed_from: float,
        started: float | None = None,
        tag: Callable[[str, float], str | None] | None = None,
    ):
        self.gw_ip = gw_ip
        self.now = now
        self.assessed_from = assessed_from  # the memory holds every answer from here on
        # None: no start to allow for (a memory known whole); else STARTUP_GRACE runs from here
        self.started = started
        self.live_seen: set[str] = set()  # addresses a live answer copy showed, kept during the grace
        self.tag = tag or (lambda name, t: name)  # (record) a sample's name as the store would keep it
        self.memory = Memory()
        self.stats = Stats()
        self.pending: OrderedDict[tuple[str, int], tuple[int, bytearray, int]] = OrderedDict()
        self.seen: OrderedDict[tuple[str, int], float] = OrderedDict()
        self.last_loss: float | None = None
        self.samples: list[dict] = []

    def lost(self) -> None:
        """The socket said the kernel dropped a copy (ENOBUFS)."""
        self.stats.lost += 1
        self.last_loss = self.now()

    def _unread_answer(self) -> None:
        self.stats.answers_unread += 1
        self.last_loss = self.now()

    def copy(self, packet: bytes | None) -> None:
        """One copy the kernel handed over. Never raises: a fault is counted and the copy dropped."""
        self.stats.copies += 1
        try:
            self._copy(packet or b"")
        except Exception:  # a reader's fault must cost one copy, never the count
            self.stats.errors += 1

    def _copy(self, packet: bytes) -> None:
        ip = _ip(packet)
        if ip is None:
            self.stats.unparsed += 1
            return
        proto, ihl, _src, _dst, pkt = ip
        sport = struct.unpack_from(">H", pkt, ihl)[0] if len(pkt) >= ihl + 2 else -1
        if sport == 53 and proto in (6, 17):  # an answer: the hellos' rule copies TCP to port 443 only
            found = read_answer(packet)
            if found is None:
                self._unread_answer()
                return
            t = self.now()
            for names, addrs in found:
                self.stats.answers += 1
                if names and addrs:  # a blocked answer (0.0.0.0 only) binds nothing and names no answer
                    self.memory.remember(names, addrs, t)
                    if self._in_grace(t):
                        self.live_seen.update(addrs)
            return
        seg = read_segment(packet)
        if seg is None:
            self.stats.unparsed += 1
            return
        if seg.data:
            self._segment(seg)

    def _segment(self, seg: Segment) -> None:
        key = (seg.dst, seg.sport)
        t = self.now()
        self._expire(t)
        if key in self.seen:
            return
        held = self.pending.get(key)
        if held is None:
            if not clienthello.is_client_hello_record(seg.data):
                self._done(key, t)
                self.stats.not_tls += 1
                return
            held = (seg.seq + len(seg.data), bytearray(seg.data), 1)
        elif seg.seq == held[0]:
            held = (held[0] + len(seg.data), held[1] + seg.data[: HELLO_BYTES - len(held[1])], held[2] + 1)
        else:
            return  # a retransmission, or a segment out of order: the next in order is awaited
        data = bytes(held[1])
        hello = clienthello.parse_record(data)
        need = 5 + int.from_bytes(data[3:5], "big") if len(data) >= 5 else HELLO_BYTES
        whole = len(data) >= min(need, HELLO_BYTES) or held[2] >= HELLO_SEGMENTS
        if hello is not None and (hello.sni or whole):
            self.pending.pop(key, None)
            self._count(seg, hello, t)
            self._done(key, t)
            return
        if whole:  # all of it read, and still no hello in it
            self.pending.pop(key, None)
            self._done(key, t)
            self.stats.not_tls += 1
            return
        self.pending[key] = held
        self.pending.move_to_end(key)
        while len(self.pending) > MAX_PENDING:
            self.pending.popitem(last=False)

    def _count(self, seg: Segment, hello: clienthello.Hello, t: float) -> None:
        from tvgw.queries import ECH_PUBLIC_NAMES  # here: queries is a heavy import, needed for one set

        if seg.dst == self.gw_ip or not is_public_address(seg.dst):
            return
        name = normalize(hello.sni)
        if not name:
            cls = NONAME
        elif hello.ech and (name in ECH_PUBLIC_NAMES or not self.memory.answered(name, t)):
            cls = ECH
        else:
            cls = self.memory.judge(name, seg.dst, t)
            if cls != BOUND:
                why = self._cannot_vouch(seg.dst, t, cls)
                if why:
                    cls = UNASSESSED
                    setattr(self.stats, why, getattr(self.stats, why) + 1)
        setattr(self.stats, cls, getattr(self.stats, cls) + 1)
        if cls in (SHARED, NEVER):
            self.samples = [
                *self.samples[-(SAMPLES - 1) :],
                {
                    "t": round(t, 3),
                    "name": self._tagged(name, t),
                    "dst": seg.dst,
                    "dport": seg.dport,
                    "cls": cls,
                },
            ]

    def _in_grace(self, t: float) -> bool:
        if self.started is None or t - self.started >= STARTUP_GRACE:
            self.live_seen.clear()
            return False
        return True

    def _cannot_vouch(self, addr: str, t: float, cls: str) -> str | None:
        """The reason the memory cannot vouch for a mismatch (SHARED or NEVER) at `addr`, as the Stats field
        that counts it, or None: answers before what it holds or a start's unwritten lookups, a copy lost or
        an answer not read in the last LOSS_PROTECT, or an address that let a name go within its day."""
        if t - WINDOW < self.assessed_from or (self._in_grace(t) and addr not in self.live_seen):
            return "unassessed_start"
        if self.last_loss is not None and t - self.last_loss <= LOSS_PROTECT:
            return "unassessed_loss"
        if cls == SHARED and self.memory.is_crowded(addr, t):
            return "unassessed_crowded"
        return None

    def _tagged(self, name: str, t: float) -> str | None:
        try:
            return self.tag(name, t)
        except Exception:  # a key this process cannot read (or make): the sample goes without its name
            return None

    def _done(self, key: tuple[str, int], t: float) -> None:
        self.seen[key] = t
        self.seen.move_to_end(key)
        while len(self.seen) > MAX_SEEN:
            self.seen.popitem(last=False)

    def _expire(self, t: float) -> None:
        while self.seen:
            key, at = next(iter(self.seen.items()))
            if t - at <= SEEN_FOR:
                break
            del self.seen[key]

    def status(self, started: float) -> dict:
        return {
            "t": self.now(),
            "started": started,
            "assessed_from": self.assessed_from,
            "stats": asdict(self.stats),
            "addresses": len(self.memory.by_addr),
            "crowded": sum(1 for until in self.memory.crowded.values() if until >= self.now()),
            "samples": self.samples,
        }


def seed(tap: Tap, path: str, client: str, now: float) -> tuple[int, float]:
    """Fill the memory from the query log's answers to `client` over the last WINDOW: (answers read, the
    time from which the memory now holds every answer). That time is `now` when the log could not be read,
    or the oldest record read when the read stopped short of the window."""
    if not os.path.exists(path):  # a log that is not there is no proof the TV asked nothing
        return 0, now
    try:
        records, whole = adguard.records_since(path, now - WINDOW, client, answers=True)
    except OSError:
        return 0, now
    n = 0
    for r in records:
        names, addrs = chain(r.qname, r.answers), addresses(r.answers)
        if names and addrs:
            tap.memory.remember(names, addrs, r.t)
            n += 1
    if whole:
        return n, now - WINDOW
    return n, records[0].t if records else now


# ---- the socket and the loop ---------------------------------------------------------------------------
class LogSocket:
    """The netlink socket bound to the NFLOG group."""

    def __init__(self, group: int = GROUP, sock: socket.socket | None = None):
        self.group = group
        if sock is None:
            family = getattr(socket, "AF_NETLINK", nfnl.AF_NETLINK)
            sock = socket.socket(family, socket.SOCK_RAW, nfnl.NETLINK_NETFILTER)
            sock.bind((0, 0))
            try:
                sock.setsockopt(socket.SOL_SOCKET, nfnl.SO_RCVBUFFORCE, RCVBUF)
            except OSError:
                with contextlib.suppress(OSError):
                    sock.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, RCVBUF)
        self.sock = sock

    def fileno(self) -> int:
        return self.sock.fileno()

    def bind(self, wait: float = 2.0) -> int:
        """Bind the group; the errno, 0 when the kernel acknowledged it (EBUSY: another socket holds it)."""
        try:
            self.sock.send(nfnl.log_bind(self.group, 1, COPY_RANGE))
        except OSError as e:
            return e.errno or errno.EIO
        deadline = time.monotonic() + wait
        while (left := deadline - time.monotonic()) > 0:
            ready, _, _ = select.select([self.sock], [], [], left)
            if not ready:
                break
            try:
                data = self.sock.recv(RECV_SIZE)
            except OSError as e:
                return e.errno or errno.EIO
            try:
                acks = [a for m in nfnl.messages(data) if (a := nfnl.ack(m)) is not None]
            except nfnl.NlError:
                acks = []
            for seq, err in acks:
                if seq == 1:
                    return err
        return errno.ETIMEDOUT

    def recv(self, wait: float, also: tuple[int, ...] = ()) -> bytes | None:
        """The next datagram; None after `wait` seconds or when one of `also` became readable first.
        Raises ENOBUFS's OSError for the caller to count."""
        ready, _, _ = select.select([self.sock, *also], [], [], max(wait, 0.0))
        if self.sock not in ready:
            return None
        try:
            return self.sock.recv(RECV_SIZE)
        except OSError as e:
            if e.errno in (errno.EAGAIN, errno.EINTR):
                return None
            raise

    def close(self) -> None:
        with contextlib.suppress(OSError):
            self.sock.send(nfnl.log_unbind(self.group, 2))
        self.sock.close()


def run(
    sock,
    tap: Tap,
    stop: Callable[[], bool],
    publish: Callable[[dict], object],
    started: float,
    also: tuple[int, ...] = (),
    clock: Callable[[], float] = time.monotonic,
) -> None:
    """Read copies until `stop()`, publishing the status every STATUS_EVERY seconds and once at the end."""
    next_status = clock()
    while not stop():
        if clock() >= next_status:
            publish(tap.status(started))
            next_status = clock() + STATUS_EVERY
        try:
            data = sock.recv(max(next_status - clock(), 0.0), also)
        except OSError as e:
            if e.errno == errno.ENOBUFS:
                tap.lost()
                continue
            raise
        if data is None:
            continue
        try:
            msgs = list(nfnl.messages(data))
        except nfnl.NlError:
            tap.stats.errors += 1
            continue
        for msg in msgs:
            try:
                packet = nfnl.log_packet(msg)
            except nfnl.NlError:
                tap.stats.errors += 1
                continue
            if msg.kind == (nfnl.NFNL_SUBSYS_ULOG << 8) | nfnl.NFULNL_MSG_PACKET:
                tap.copy(packet)
    publish(tap.status(started))


def wanted(s: Settings) -> bool:
    return s.name_binding == "count"


def main(s: Settings, profile=None, group: int = GROUP, status_path: str = STATUS) -> int:
    if not wanted(s):
        print(f"tvgw names-tap: NAME_BINDING={s.name_binding}, nothing to count", flush=True)
        return 0
    stopping = [False]
    for sig in (signal.SIGTERM, signal.SIGINT):
        signal.signal(sig, lambda *_: stopping.__setitem__(0, True))
    sock = LogSocket(group)
    err = sock.bind()
    if err:
        why = "another process holds it" if err == errno.EBUSY else errno.errorcode.get(err, str(err))
        print(f"tvgw names-tap: could not bind NFLOG group {group} ({why})", file=sys.stderr, flush=True)
        sock.close()
        return 1
    started = time.time()
    tag = None
    if profile is not None:  # (record) the samples' names as the store keeps them under NAME_HMAC=on
        from tvgw import minimize

        names = minimize.hasher(s, profile)
        tag = names.name if names.active else None
    tap = Tap(s.gw_ip, time.time, started, started=started, tag=tag)
    n, tap.assessed_from = seed(tap, s.adguard_querylog, s.tv_ip, started)
    print(f"tvgw names-tap: counting; {n} answers of the last day remembered from the query log", flush=True)
    r, w = os.pipe()
    os.set_blocking(w, False)
    signal.set_wakeup_fd(w)
    notify("READY=1")
    try:
        run(sock, tap, lambda: stopping[0], lambda doc: write_status(status_path, doc), started, (r,))
    finally:
        notify("STOPPING=1")
        sock.close()
    st = tap.stats
    print(
        f"tvgw names-tap: stopped after {st.copies} copies ({st.answers} answers, {st.lost} losses)",
        flush=True,
    )
    return 0


# ---- the brief's line ----------------------------------------------------------------------------------
def window(conn: sqlite3.Connection, a: float, b: float) -> dict | None:
    """The live count's gains in [a, b), from the series `tvgw verify --record` stored, or None when the
    window holds no snapshot of any of them (NAME_BINDING was off). Each series counts since its process
    started, so a lower snapshot is a restart and `queries.series_gain` reads it so."""
    from tvgw.queries import series_gain  # here: queries imports namebound, which this module imports

    rules = [rule for _key, rule in SERIES] + list(COPY_RULES)
    marks = ",".join("?" * len(rules))
    if not conn.execute(
        f"SELECT 1 FROM fw_counters WHERE rule IN ({marks}) AND t >= ? AND t < ? LIMIT 1", (*rules, a, b)
    ).fetchone():
        return None
    out = {key: series_gain(conn, rule, a, b) for key, rule in SERIES}
    out["copied"] = sum(series_gain(conn, rule, a, b) for rule in COPY_RULES)
    return out
