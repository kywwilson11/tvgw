"""(mint) The minted-address shadow (design decision 96): the minting table of design decision 85 kept
live from the DNS answers the in-path filler already holds, and each new connection the TV makes put, as it
happens, in the class a strict stage would give it. It changes nothing: the TV is handed the real
addresses, and no packet is translated, refused or held for it.

`tvgw mint replay` asks the store what a strict stage would have refused. The shadow asks the traffic, with
the code that would mint. The in-path filler (`tvgw.inpath`) hands it each answer after the answer's
verdict; it reads the (name, address) pairs and mints each in a `mint.Minter`, as a stage that rewrote the
answer would. With MINT=shadow, tvgw-apply also loads `inet tvgw_mint`, whose one rule copies the first
packet of each new connection the TV makes, after every chain that could refuse it, to NFLOG group GROUP.
The filler reads those copies between answers, and the shadow puts each connection in the replay's classes
(`mintreplay.class_of`) by what the table held at that moment:

- `local`: to an address that is not public (the gateway's and the home network's are not), or to port
  53, which the gateway answers wherever the TV aims it. Not judged;
- `ticket`, `tickets`: the table held one name's ticket for the address, or several names';
- `listed`: no ticket, and the profile lists the address and port as reached without a lookup;
- `crowded`: no ticket, though an answer named the address within a ticket's lifetime (a full pool, or a
  name over its share);
- `lapsed`: no ticket, and the newest answer that named the address is older than a ticket's lifetime;
- `never`: no ticket, and no answer the shadow remembers named it (it remembers NEWEST_FOR);
- `unassessed`: no ticket, and the shadow cannot vouch that it saw the answer that would explain it.

`crowded`, `lapsed` and `never` are what a strict stage would refuse.

Why it can neither take the TV's lookups away nor slow them: an answer reaches the shadow only once its
verdict has been given, and every reader here is bounded and never raises, so a fault is counted and
the filler goes on. Its cost is the time the next answer could wait in the queue, and is measured (`us`).
Each turn of the filler's loop reads at most POLL_MAX copies, after any answer that was waiting. The
copies are the kernel's: a copy nobody reads is thrown away, and the connection it was taken from has
already gone on.

When it cannot vouch. A connection without a ticket is judged only when the shadow saw every answer that
could explain it: its memory reaches back a lifetime (`since`), and no answer was missed in the last
LOSS_PROTECT. At start the memory is filled from AdGuard Home's query log, the TV's answers of the last
lifetime, as the live name count fills its own (`nametap.seed`); a start counts as a miss, since AdGuard
Home writes its log in batches. Missed are an answer the shadow could not read, answers the kernel passed
itself while the filler's socket was full, and the answers of an apply's quiet window, which never reach
the queue. The filler learns of the last only when it finds its switch gone, up to inpath.LIVE_EVERY
later, so a miss reaches back to when the switch was last seen, at most REJUDGE_FOR, and moves the
refusals counted since then to `unassessed`. A copy the kernel dropped for want of room (ENOBUFS) is a
connection not counted (`dropped`), not a miss: the copies carry no answer.

What it keeps, and for how long: the table (each pair's name and real address for a lifetime after its
last answer), the newest answer's time for each address (NEWEST_FOR) and the connections of the last
SEEN_FOR, all in the filler's memory, bounded; no name and no address leaves it. `tvgw forget` writes
FORGET, and at its next status the shadow empties all three and starts its memory again from that moment.
"""

from __future__ import annotations

import contextlib
import errno
import ipaddress
import os
import socket
import struct
import time
from collections import OrderedDict, deque
from collections.abc import Callable
from dataclasses import asdict, dataclass, field

from tvgw import adguard, inpath, mint, mintreplay, nfnl
from tvgw.config import Settings
from tvgw.mintreplay import LISTED, LOCAL, REFUSED, UNASSESSED
from tvgw.namebound import addresses
from tvgw.names import normalize

GROUP = 9  # the NFLOG group; tvgw-apply's MINT_GROUP (test_mintshadow keeps them equal)
COPY_RANGE = 64  # bytes of each copy: an IPv4 header with options, then the ports; tvgw-apply's MINT_SNAPLEN
POLL_MAX = 64  # copies read at one turn of the filler's loop
SEEN_FOR = 120.0  # seconds: an opening sent again within them is the same connection, as the gate's tuples
MAX_SEEN = 16_384
NEWEST_FOR = mint.REST  # seconds an address's newest answer is remembered: the week an address rests
# The memory's bounds, so that the shadow can never take the filler's room (its unit's MemoryMax is
# 128 MB): a table of the whole pool took about 140 MB on a laptop. The reference made 478 pairs on its
# busiest day, so 16,384 live tickets is thirty times that, about 20 MB at most. An answer that would
# make a ticket past it gets none, and is a miss: the shadow cannot vouch for what it did not mint
MAX_TICKETS = 16_384
MAX_NEWEST = 16_384  # addresses remembered, the oldest answered first out
# seconds after a miss during which a connection without a ticket is not assessed, as the live name count's
LOSS_PROTECT = 3600.0
# seconds a refusal stays open to a miss found after it: the filler finds its switch gone up to
# inpath.LIVE_EVERY after an apply removed it, plus however long the apply held nf_tables' lock
REJUDGE_FOR = 60.0
MAX_REJUDGE = 4096  # the latest refusals kept for that; far more than a minute of the TV's connections
US_SAMPLES = 512  # the last answers' costs kept for the status's median
FORGET = "/run/tvgw-dnsgate-inpath/mint-forget"  # tvgw forget's stamp, in the filler's runtime directory
COPY_RULE = "in-path: new TV connections copied to the minting table"  # tvgw-apply's mint rule
# (the status's section and field, its fw_counters series). The prefix is the in-path filler's
# (inpath.RULE_PREFIX): these are the filler's counts, kept out of "Firewall held" with its own
SERIES = (
    ("conns", mintreplay.TICKET, "in-path: mint: connections with one name's ticket"),
    ("conns", mintreplay.TICKETS, "in-path: mint: connections with several names' tickets"),
    ("conns", LISTED, "in-path: mint: connections the profile lists"),
    ("conns", mintreplay.CROWDED, "in-path: mint: connections crowded out"),
    ("conns", mintreplay.LAPSED, "in-path: mint: connections whose ticket had lapsed"),
    ("conns", mintreplay.NEVER, "in-path: mint: connections to an address never answered"),
    ("conns", UNASSESSED, "in-path: mint: connections not assessed"),
    ("conns", LOCAL, "in-path: mint: connections not judged"),
    ("tickets", "minted", "in-path: mint: tickets made"),
    ("tickets", "refused", "in-path: mint: answers given no ticket"),
    ("tickets", "evicted", "in-path: mint: tickets ended by a name's share"),
    ("answers", "unread", "in-path: mint: answers not read"),
    ("seen", "missed", "in-path: mint: times an answer may have been missed"),
    ("seen", "dropped", "in-path: mint: connection copies the kernel dropped"),
)
NEVER_RULE = SERIES[5][2]  # the run of `tvgw status`'s counting line is read from this series


def wanted(s: Settings) -> bool:
    """Whether the settings ask for the shadow and the in-path filler that keeps it runs."""
    return getattr(s, "mint", "off") == "shadow" and inpath.wanted(s)


@dataclass
class Counts:
    """Counts since the filler started; none of it is a name or an address."""

    conns: dict[str, int] = field(default_factory=lambda: dict.fromkeys((LOCAL, *mintreplay.JUDGED), 0))
    answers: dict[str, int] = field(default_factory=lambda: dict.fromkeys(("read", "truncated", "unread"), 0))
    seen: dict[str, int] = field(
        default_factory=lambda: dict.fromkeys(
            ("copies", "again", "unparsed", "dropped", "missed", "full", "forgotten"), 0
        )
    )
    errors: int = 0


def opening(packet: bytes | None) -> tuple[int, bytes, bytes, int | None, int | None] | None:
    """(protocol, source, destination, source port, destination port) of a copy's IPv4 header; the ports
    are None for a protocol without them. None for anything that is not IPv4 or is cut inside its header."""
    if not packet or len(packet) < 20 or packet[0] >> 4 != 4:
        return None
    ihl, proto = (packet[0] & 0x0F) * 4, packet[9]
    if ihl < 20:
        return None
    sport = dport = None
    if proto in (6, 17):
        if len(packet) < ihl + 4:
            return None
        sport, dport = struct.unpack_from(">HH", packet, ihl)
    return proto, packet[12:16], packet[16:20], sport, dport


class Shadow:
    """The table, the memory beside it and the counts. `now` is the wall clock: the query log's answers
    are stamped by it. `sock` reads the copies (`nametap.LogSocket`'s `recv`), None in the tests that hand
    copies over themselves."""

    def __init__(
        self,
        now: Callable[[], float] = time.time,
        listed: frozenset[tuple[str, int]] = frozenset(),
        sock=None,
        pool: ipaddress.IPv4Network = mint.POOL,
        lifetime: float = mint.LIFETIME,
        timer: Callable[[], float] = time.perf_counter,
        forget_path: str = FORGET,
    ):
        self.now, self.listed, self.sock, self.timer = now, listed, sock, timer
        self.pool, self.lifetime, self.forget_path = pool, lifetime, forget_path
        self.counts = Counts()
        self.us: list[float] = []  # the last answers' costs to the loop, seconds
        self.forgot = _mtime(forget_path)  # a stamp from before the start forgot nothing this memory holds
        self._fresh(now())

    def _fresh(self, t: float) -> None:
        """An empty memory that holds every answer from `t` on, and cannot vouch until LOSS_PROTECT
        after it: the start of a memory is a miss."""
        self.table = mint.Minter(self.pool, lifetime=self.lifetime)
        self.newest: OrderedDict[bytes, float] = OrderedDict()  # address -> its newest answer's time
        self.recent: OrderedDict[tuple, float] = OrderedDict()  # the connections of the last SEEN_FOR
        # (when, class) of the latest refusals, which a miss found later may move to `unassessed`
        self.refusals: deque[tuple[float, str]] = deque(maxlen=MAX_REJUDGE)
        self.since = self.last_miss = t

    # ---- the answers ----------------------------------------------------------------------------------
    def answer(self, payload: bytes | None, whole: bool = True) -> None:
        """One answer the filler has released. Never raises."""
        start = self.timer()
        try:
            self._answer(inpath.read_packet(payload, whole, named=True))
        except Exception:  # a fault here must cost one answer's pairs, never the filler
            self.counts.errors += 1
        self.us.append(self.timer() - start)
        del self.us[:-US_SAMPLES]

    def _answer(self, parsed: inpath.Parsed) -> None:
        kinds = self.counts.answers
        if parsed.kind in (inpath.UNPARSED_UDP, inpath.UNPARSED_TCP):
            kinds["unread"] += 1
            self.missed()  # its addresses may be the ones a later connection uses
        elif parsed.kind == inpath.TRUNCATED:
            kinds["truncated"] += 1  # the TV asks again over TCP, and that answer is read
        elif parsed.kind == inpath.ANSWER:
            kinds["read"] += 1
            self.remember(parsed.named, self.now())

    def remember(self, pairs, t: float) -> None:
        """Mint each (name, address) an answer gave at `t`, and note the address's newest answer. A new
        pair past MAX_TICKETS is not minted, and is a miss."""
        for name, real in pairs:
            if len(self.table) >= MAX_TICKETS and (name, real) not in self.table.by_pair:
                self.table.expire(t)
            if len(self.table) >= MAX_TICKETS and (name, real) not in self.table.by_pair:
                self.counts.seen["full"] += 1
                self.missed()
            else:
                self.table.mint(name, real, t)
            self.newest[real] = t
            self.newest.move_to_end(real)
        while self.newest:
            oldest, at = next(iter(self.newest.items()))
            if len(self.newest) <= MAX_NEWEST and t - at < NEWEST_FOR:
                break
            del self.newest[oldest]

    # ---- the connections ------------------------------------------------------------------------------
    def copy(self, packet: bytes | None) -> None:
        """One copy of a new connection's first packet. Never raises."""
        self.counts.seen["copies"] += 1
        try:
            self._copy(packet)
        except Exception:
            self.counts.errors += 1

    def _copy(self, packet: bytes | None) -> None:
        head = opening(packet)
        if head is None:
            self.counts.seen["unparsed"] += 1
            return
        t = self.now()
        while self.recent and t - next(iter(self.recent.values())) > SEEN_FOR:
            self.recent.popitem(last=False)
        if head in self.recent:  # a retried opening: one connection
            self.counts.seen["again"] += 1
            return
        self.recent[head] = t
        if len(self.recent) > MAX_SEEN:
            self.recent.popitem(last=False)
        _proto, _src, dst, _sport, dport = head
        cls = self.judge(socket.inet_ntoa(dst), dport, t)
        self.counts.conns[cls] += 1
        if cls in REFUSED:
            self.refusals.append((t, cls))

    def judge(self, dst: str, dport: int | None, t: float) -> str:
        """The class of a connection to `dst`:`dport` at `t`, by what the table holds then."""
        real = mintreplay.judged_address(dst, dport)
        if real is None:
            return LOCAL
        newest = self.newest.get(real)
        age = None if newest is None or t - newest >= NEWEST_FOR else t - newest  # older is forgotten
        assessed = t - self.lifetime >= self.since and t - self.last_miss > LOSS_PROTECT
        return mintreplay.class_of(
            self.table.names_of(real, t), (dst, dport) in self.listed, assessed, age, self.lifetime
        )

    def missed(self, since: float | None = None) -> None:
        """An answer may have gone unseen, from `since` (now when not known; at most REJUDGE_FOR ago) to
        now: no connection without a ticket is assessed for LOSS_PROTECT, and the refusals counted since
        then become `unassessed`, since the answer that explains one may be the one missed."""
        t = self.now()
        self.counts.seen["missed"] += 1
        self.last_miss = max(self.last_miss, t)
        since = t if since is None else max(since, t - REJUDGE_FOR)
        while self.refusals and self.refusals[-1][0] >= since:
            _at, cls = self.refusals.pop()
            self.counts.conns[cls] -= 1
            self.counts.conns[UNASSESSED] += 1

    # ---- the socket, the forget and the status ----------------------------------------------------------
    def fds(self) -> tuple[int, ...]:
        """The descriptor the filler's loop waits on beside its queue: none once the socket has failed."""
        return () if self.sock is None else (self.sock.fileno(),)

    def poll(self) -> None:
        """Read the copies waiting, at most POLL_MAX, without waiting. Never raises: copies the kernel
        dropped are counted, and a socket that fails otherwise is closed and read no more."""
        for _ in range(POLL_MAX):
            if self.sock is None:
                return
            try:
                data = self.sock.recv(0.0)
            except OSError as e:
                if e.errno == errno.ENOBUFS:
                    self.counts.seen["dropped"] += 1
                    continue
                self.counts.errors += 1
                self.close()
                return
            if data is None:
                return
            self.datagram(data)

    def datagram(self, data: bytes) -> None:
        """The copies in one datagram of the NFLOG socket."""
        try:
            msgs = list(nfnl.messages(data))
        except nfnl.NlError:
            self.counts.errors += 1
            return
        for msg in msgs:
            try:
                packet = nfnl.log_packet(msg)
            except nfnl.NlError:
                self.counts.errors += 1
                continue
            if msg.kind == (nfnl.NFNL_SUBSYS_ULOG << 8) | nfnl.NFULNL_MSG_PACKET:
                self.copy(packet)

    def close(self) -> None:
        if self.sock is not None:
            with contextlib.suppress(OSError):
                self.sock.close()
            self.sock = None

    def tick(self) -> None:
        """At each status: empty the memory when `tvgw forget` has asked since the last look."""
        stamp = _mtime(self.forget_path)
        if stamp is not None and (self.forgot is None or stamp > self.forgot):
            self.forgot = stamp
            self._fresh(self.now())
            self.counts.seen["forgotten"] += 1

    def status(self) -> dict:
        """The status file's `mint` section: counts and times, no name and no address."""
        t = self.now()
        self.table.expire(t)
        ranked = sorted(self.us)
        at = lambda q: int(ranked[min(len(ranked) - 1, int(q * len(ranked)))] * 1e6)  # noqa: E731
        return {
            "since": self.since,
            "reading": self.sock is not None,
            "pool": mint.capacity(self.pool),
            "tickets": {"live": len(self.table), **asdict(self.table.counts)},
            **asdict(self.counts),
            "us": {"n": len(ranked), "p50": at(0.5) if ranked else 0, "p99": at(0.99) if ranked else 0},
        }


def _mtime(path: str) -> float | None:
    try:
        return os.stat(path).st_mtime
    except OSError:
        return None


def seed(shadow: Shadow, path: str, client: str) -> int:
    """Fill the memory from the query log's answers to `client` over the last lifetime, as the live name
    count fills its own: the answers read. The memory then holds every answer from the oldest one read,
    or from a lifetime ago when the read reached back that far. A log that is not there, or cannot be read,
    leaves the memory as it was: no proof that the TV asked nothing."""
    t = shadow.now()
    if not os.path.exists(path):
        return 0
    try:
        records, whole = adguard.records_since(path, t - shadow.lifetime, client, answers=True)
    except OSError:
        return 0
    n = 0
    for r in records:
        name = normalize(r.qname or "")
        pairs = [(name, socket.inet_aton(a)) for a in addresses(r.answers)] if name else []
        if pairs and r.t <= t:
            shadow.remember(pairs, r.t)
            n += 1
    if whole:
        shadow.since = t - shadow.lifetime
    elif records:
        shadow.since = records[0].t
    return n


def forget(path: str = FORGET) -> bool:
    """(forget) Ask a running shadow to empty its memory: write the stamp where the filler runs. False
    when the filler's runtime directory is not there (no filler, so no memory)."""
    if not os.path.isdir(os.path.dirname(path)):
        return False
    with open(path, "w", encoding="utf-8"):  # a new modification time is the whole message
        pass
    return True


def start(s: Settings, profile=None, group: int = GROUP) -> Shadow | None:
    """The shadow for the filler's `main`, its socket bound and its memory seeded; None, with a line to
    the journal, when the settings do not ask for it or its NFLOG group cannot be bound. Either way the
    filler goes on: the shadow is never a reason for the TV's answers to pass unheld."""
    if not wanted(s):
        return None
    from tvgw import nametap  # at the call: it imports this module's neighbour, the filler

    sock = nametap.LogSocket(group)
    err = sock.bind()
    if err:
        why = "another process holds it" if err == errno.EBUSY else errno.errorcode.get(err, str(err))
        print(
            f"tvgw dnsgate-inpath: the minted-address shadow could not bind NFLOG group {group} ({why})",
            flush=True,
        )
        sock.close()
        return None
    shadow = Shadow(listed=mintreplay.listed(profile), sock=sock)
    n = seed(shadow, s.adguard_querylog, s.tv_ip)
    print(
        f"tvgw dnsgate-inpath: the minted-address shadow counts; {n} answers remembered from the query log",
        flush=True,
    )
    return shadow
