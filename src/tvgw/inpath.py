"""DNS-gated egress, the in-path filler (design decision 64): hold each DNS answer the Pi sends the TV
until its addresses are in `inet tvgw_gate resolved4_inpath`, then let it go.

`tvgw.dnsgate` fills its set from a capture: it sees an answer as it leaves and adds the addresses a
few milliseconds later, and the TV can connect within one, so nearly every miss the gate counts is that
race. This filler stands in the answer's path instead. With `DNSGATE_FILL=inpath`, tvgw-apply loads a
rule in the output hook that hands the resolver's answers to the TV (UDP from port 53, and every TCP
segment from port 53 that neither opens nor resets the connection) to netfilter queue QUEUE. For each
one this process reads the A records, adds them to the set over netlink with a one-day timeout and
expiry, waits for the kernel's
acknowledgement, and only then gives the verdict that releases the packet. The only verdict it ever
gives is accept, with no payload: it cannot drop an answer and cannot change one. Nothing is refused
anywhere: a second rule counts, and logs a sample of, new TV connections to addresses this set does
not hold, beside the passive feeder's count, so the two can be compared.

What happens when this process is absent, slow, stopped or dead, and why none of it takes the TV's
lookups away:

- **Not running, or the queue not bound.** The rule carries `bypass`: with nobody bound to the queue
  the kernel accepts the packet itself.
- **Starting.** The rule matches only while the set `inpath_live` holds port 53. The filler empties
  that set, binds and configures the queue in one message, and only then puts the port in: no answer
  can reach a queue that is bound but not yet configured, which the kernel would drop. It puts the
  port in again every LIVE_EVERY seconds, as a create: when the port turns out to have gone (an apply
  made the table anew), it forgets every address it knew, since the set it added them to went too.
- **A full queue, or a full socket buffer.** The queue is configured fail-open: the kernel accepts
  what does not fit. At most MAXLEN answers wait at once.
- **A slow add.** The add runs on a second thread. An answer waits at most HOLD_BOUND for it and is
  then released anyway, counted `late`; until that add returns, later answers are not held at all.
- **Hostile bytes.** The answer comes from upstream servers through the resolver. It is read with
  bounded, linear work (`dnsmsg.a_rdata`), a message over MAX_DNS bytes is not read at all, and
  whatever the reading does, the packet's verdict is given in a `finally`.
- **The table or the set missing** (`DNSGATE=off` applied while this runs).
  The add fails, the answer is released and counted `failed`, and the filler tries again at the next
  answer and re-asserts `inpath_live` every LIVE_EVERY seconds.
- **A re-apply.** The kernel drops every packet waiting in any queue the moment any netfilter hook is
  removed, and every apply removes hooks (`delete table`). So tvgw-apply first takes the queue rules
  and the set `inpath_live` away, in one transaction, so that this process cannot put its port back
  in between; waits until this process has released what it held; and only then removes a hook. Its
  last load makes the rules and the set anew, and the port goes back in within LIVE_EVERY seconds.
  While an apply runs no answer is offered to the queue at all.
- **Hung.** The loop feeds systemd's watchdog; a loop that stops is killed with SIGKILL within
  WatchdogSec (2 s), the socket closes, and the kernel's bypass takes over.
- **Stopping.** It empties `inpath_live`, sets the queue's length to 0, which makes the kernel accept
  every new packet itself, releases what still waits, and only then closes the socket.

What it cannot prevent, because the kernel decides it: a queue whose socket closes while packets wait
(a kill, a crash) drops those packets (`nfqnl_flush`, NF_DROP, in every kernel to 6.18); so does a
hook that another program removes (a VPN client rebuilding its tables), for every queue at once; and
a packet the kernel cannot allocate a queue entry for is dropped. Each loses the answers in flight at
that instant, normally none or one, and the TV asks again; none outlasts the instant.

Everything that reads bytes is a pure function, and the loop takes its sockets, its clock and its
adder as parameters, so all of it runs in the unit tests; the netlink messages are `tvgw.nfnl`'s.
"""

from __future__ import annotations

import contextlib
import errno
import json
import os
import queue
import select
import signal
import socket
import struct
import sys
import threading
import time
from collections.abc import Callable
from dataclasses import asdict, dataclass

from tvgw import dnsmsg, nfnl
from tvgw.config import Settings
from tvgw.dnsgate import TTL  # a day, as the passive feeder's set
from tvgw.names import normalize

# (attention) the TV's essentials, for the attention count's platform set (design decision 69): an answer
# to a name the profile counts among them has its addresses added there too, before the answer leaves.
# attention.TABLE and attention.PLATFORM_SET, written out here so the filler never imports the store side
ESSENTIALS_TABLE, ESSENTIALS_SET = "tvgw_attn", "platform4"
ESSENTIALS_OFF = 10.0  # seconds without essentials adds after the kernel said that table is not there

TABLE = "tvgw_gate"  # in the inet family, as tvgw-apply creates it
SET = "resolved4_inpath"
LIVE_SET = "inpath_live"  # holds LIVE_PORT while a configured filler is bound: the queue rules match on it
LIVE_PORT = 53
LIVE_KEY = struct.pack(">H", LIVE_PORT)
QUEUE = 53053  # the netfilter queue number; tvgw-apply's INPATH_QUEUE (test_deploy_lint keeps them equal)
# answers that may wait at once. A healthy filler releases each within a fraction of a millisecond, so
# the queue is rarely two deep; 128 lets a burst through unharmed and bounds what a stopped filler can
# trap before the kernel starts accepting on its own (fail-open)
MAXLEN = 128
# seconds an answer may wait for its add. The add is one netlink transaction, tens of microseconds on
# an idle kernel; what can stretch it is another transaction holding nf_tables' lock (a re-apply, a
# list refresh), a few milliseconds on the gateway. 20 ms is a hundred times the normal case and a
# fiftieth of the shortest resolver retry timer (1 s), so a held answer is never a lost one
HOLD_BOUND = 0.020
# seconds an address stays "known" after its add was acknowledged: an answer naming only known
# addresses is released at once. Every other answer renews its addresses' day before it leaves, so an
# element's expiry is never more than this short of a day after the last answer that named it. Short,
# because nothing but the next add tells the filler that someone emptied the set by hand meanwhile
KNOWN_FOR = 10.0
CACHE_MAX = 4096  # addresses remembered; the oldest go first
MAX_DNS = 4096  # bytes of DNS message read; a longer one passes unread (counted unparsed)
TCP_MESSAGES = 16  # DNS messages read from one TCP segment
ADD_BACKLOG = 64  # adds that may wait for the adder once it has fallen behind; further ones are dropped
RCVBUF = 1 << 20  # the queue socket's receive buffer, so MAXLEN is the limit that is reached first
RECV_SIZE = 1 << 17  # a queued packet is at most 65531 bytes and its attributes a few hundred
PING_EVERY = 0.4  # seconds between watchdog pings: a fifth of the unit's WatchdogSec=2
# seconds between re-assertions of inpath_live: how long answers pass unheld after an apply has made
# the set anew. A create that finds the port there is refused by the kernel and commits nothing
LIVE_EVERY = 2.0
STATUS_EVERY = 10.0  # seconds between writes of the status file
STATUS = "/run/tvgw-dnsgate-inpath/status.json"  # the unit's RuntimeDirectory; verify reads it
PROC_QUEUES = "/proc/net/netfilter/nfnetlink_queue"
STATUS_STALE = 60.0  # seconds after which a status file says nothing about the filler now
HOLD_SAMPLES = 512  # the last hold times kept for the status file's median
# The names the store knows this filler's numbers by. Every counted rule tvgw-apply's in-path block
# loads has a comment that starts with RULE_PREFIX, and so does every series `tvgw verify --record`
# stores from the status file: they measure a filler under comparison, not what the firewall held, so
# the brief keeps them out of "Firewall held" and shows them in the gate's own section.
RULE_PREFIX = "in-path:"
MISS_RULE = "in-path: TV to an address the filler never added"  # the second count (forward_inpath)
OFFERED_RULES = (  # the two queue rules of the chain `answers`
    "in-path: UDP answers offered to the filler",
    "in-path: TCP answers offered to the filler",
)
LOG_PREFIX = "tvgw-inpath"  # the second count's kernel log prefix; shares no word with tvgw-gate
# (a key for the brief, the Stats fields it sums, its fw_counters series): counts since the filler
# started, so a restart starts each again from zero, which the brief reads as a reloaded counter
SERIES = (
    ("received", ("received",), "in-path: packets the filler received"),
    ("held", ("held",), "in-path: answers held until their add"),
    ("known", ("known",), "in-path: answers released at once, their addresses known"),
    ("late", ("late",), "in-path: answers released late"),
    ("failed", ("failed",), "in-path: answers released unadded"),
    ("unparsed", ("unparsed_udp", "unparsed_tcp"), "in-path: answers not parsed"),
    ("kernel_passed", ("kernel_passed",), "in-path: packets the kernel passed itself"),
    # the admitted drops and the faults, so the store sees them: a verdict the kernel refused is an
    # answer it had already dropped (a hook removed while the answer waited), the only trace one leaves
    ("verdict_errors", ("verdict_errors",), "in-path: verdicts the kernel refused (answers it had dropped)"),
    ("adds_failed", ("adds_failed",), "in-path: adds the kernel refused"),
    ("adds_dropped", ("adds_dropped",), "in-path: adds not tried, the adder behind"),
    ("errors", ("errors",), "in-path: internal errors"),
)
DROPS_WINDOW = 3600.0  # seconds: the status says how many verdicts the kernel refused in the last hour
LOG_EVERY = 60.0  # seconds between two log lines of the same kind

# Addresses that never enter the set: the blocked answer and its network (0.0.0.0/8), loopback, the
# private, shared and link-local ranges tvgw-apply's lan4 set already refuses the TV, multicast and the
# reserved block with broadcast. An answer naming one of them (a rewrite to the gateway, a rebinding
# attempt) must not make it an address "DNS handed the TV". The documentation ranges of RFC 5737 are
# not listed: nothing routes them on a real uplink, and the namespace tier's internet is made of them.
_NOT_GLOBAL = tuple(
    (int.from_bytes(bytes(net), "big"), (0xFFFFFFFF << (32 - bits)) & 0xFFFFFFFF)
    for net, bits in (
        ((0, 0, 0, 0), 8),
        ((10, 0, 0, 0), 8),
        ((100, 64, 0, 0), 10),
        ((127, 0, 0, 0), 8),
        ((169, 254, 0, 0), 16),
        ((172, 16, 0, 0), 12),
        ((192, 168, 0, 0), 16),
        ((224, 0, 0, 0), 3),
    )
)


def admissible(addr: bytes) -> bool:
    """Whether a four-byte address may enter the set (see _NOT_GLOBAL)."""
    if len(addr) != 4:
        return False
    n = int.from_bytes(addr, "big")
    return not any(n & mask == net for net, mask in _NOT_GLOBAL)


# --- reading a queued packet -------------------------------------------------------------------------

ANSWER, TRUNCATED, UNPARSED_UDP, UNPARSED_TCP, OTHER = (
    "answer",
    "truncated",
    "unparsed_udp",
    "unparsed_tcp",
    "other",
)


@dataclass(frozen=True)
class Parsed:
    """What a queued packet turned out to be. `addrs` (four bytes each, in order, no repeats) is filled
    only for ANSWER. TRUNCATED is a UDP answer with the TC bit, which the TV will ask again over TCP.
    UNPARSED_* is a DNS answer this code will not read (malformed, too long, a fragment, a TCP segment
    that is not one or more whole messages). OTHER is anything else the rule could hand over: a
    segment without data, a query-shaped message."""

    kind: str
    addrs: tuple[bytes, ...] = ()
    essential: tuple[bytes, ...] = ()  # (attention) of `addrs`, those answered for one of the TV's essentials
    # (mint) with `named`: each of `addrs` with the name its message's question asks for, (name, address)
    # in order, each pair once; the minting table's input. Read only when asked, after the verdict
    named: tuple[tuple[str, bytes], ...] = ()


def read_message(
    msg: bytes, essential: Callable[[str], bool] | None = None, named: bool = False
) -> Parsed | None:
    """One DNS message's admissible A addresses; None when it cannot be read. A message without the
    response bit is OTHER, one with the truncation bit TRUNCATED: neither is read further. (attention)
    With `essential`, a test of the name the question asks for, the addresses of an answer to one of the
    TV's essentials are also in `essential`. (mint) With `named`, each address with that name too."""
    if len(msg) < 12 or len(msg) > MAX_DNS:
        return None
    if not msg[2] & 0x80:
        return Parsed(OTHER)
    if msg[2] & 0x02:
        return Parsed(TRUNCATED)
    try:
        found = dnsmsg.a_rdata(msg)
    except dnsmsg.DnsFormatError:
        return None
    addrs = tuple(dict.fromkeys(a for a in found if admissible(a)))
    pairs = _named(msg, addrs) if named else ()
    if addrs and essential is not None and _essential(essential, dnsmsg.qname(msg)):
        return Parsed(ANSWER, addrs, addrs, pairs)
    return Parsed(ANSWER, addrs, named=pairs)


def _named(msg: bytes, addrs: tuple[bytes, ...]) -> tuple[tuple[str, bytes], ...]:
    """(mint) Each address with the name the message's question asks for, normalized as the store keeps
    names: what the TV looked up, and so what it will connect to. None of them for a message whose
    question does not read."""
    name = normalize(dnsmsg.qname(msg) or "")
    return tuple((name, a) for a in addrs) if name else ()


def _essential(test: Callable[[str], bool], name: str | None) -> bool:
    """(attention) The test's word on a name, False for no name or a test that fails: the essentials are
    a count's, and nothing about them may keep an answer."""
    if not name:
        return False
    try:
        return bool(test(name))
    except Exception:
        return False


def read_packet(
    packet: bytes | None,
    whole: bool = True,
    essential: Callable[[str], bool] | None = None,
    named: bool = False,
) -> Parsed:
    """Classify an IPv4 packet as the queue handed it over (from the IP header on). Never raises on any
    bytes: a length that does not fit is UNPARSED or OTHER, never an exception. (attention) `essential`
    and (mint) `named` as for `read_message`."""
    if not packet or len(packet) < 20 or packet[0] >> 4 != 4:
        return Parsed(OTHER)
    ihl = (packet[0] & 0x0F) * 4
    proto = packet[9]
    if proto not in (6, 17) or ihl < 20:
        return Parsed(OTHER)
    unparsed = Parsed(UNPARSED_UDP if proto == 17 else UNPARSED_TCP)
    total, frag = struct.unpack_from(">H", packet, 2)[0], struct.unpack_from(">H", packet, 6)[0]
    if not whole or frag & 0x3FFF or total < ihl or total > len(packet):
        return unparsed  # cut at the copy range, a fragment (MF set or an offset), or lengths that disagree
    if proto == 17:
        if total < ihl + 8:
            return unparsed
        return read_message(packet[ihl + 8 : total], essential, named) or unparsed
    if total < ihl + 20:
        return unparsed
    doff = (packet[ihl + 12] >> 4) * 4
    if doff < 20 or total < ihl + doff:
        return unparsed
    data = packet[ihl + doff : total]
    if not data:
        return Parsed(OTHER)
    # DNS over TCP: each message after a two-byte length. Only a segment that is exactly one or more
    # whole messages is read; a part of a longer answer passes unread
    addrs: list[bytes] = []
    essentials: list[bytes] = []
    pairs: list[tuple[str, bytes]] = []  # (mint)
    kinds: set[str] = set()
    off = n = 0
    while off < len(data):
        n += 1
        if n > TCP_MESSAGES or off + 2 > len(data):
            return unparsed
        (length,) = struct.unpack_from(">H", data, off)
        if length == 0 or off + 2 + length > len(data):
            return unparsed
        one = read_message(data[off + 2 : off + 2 + length], essential, named)
        if one is None:
            return unparsed
        kinds.add(one.kind)
        addrs += one.addrs
        essentials += one.essential
        pairs += one.named
        off += 2 + length
    if ANSWER not in kinds:
        return Parsed(OTHER)  # over TCP a truncation bit or a query is nothing this filler acts on
    return Parsed(
        ANSWER, tuple(dict.fromkeys(addrs)), tuple(dict.fromkeys(essentials)), tuple(dict.fromkeys(pairs))
    )


# --- what the filler remembers and counts ------------------------------------------------------------


class Known:
    """The addresses whose add the kernel acknowledged less than `keep` seconds ago: bounded, oldest
    first out. Only the loop's thread touches it."""

    def __init__(self, keep: float = KNOWN_FOR, limit: int = CACHE_MAX):
        self.keep, self.limit = keep, limit
        self._t: dict[bytes, float] = {}  # insertion order is the order of the adds

    def __len__(self) -> int:
        return len(self._t)

    def fresh(self, addr: bytes, now: float) -> bool:
        t = self._t.get(addr)
        return t is not None and 0 <= now - t < self.keep

    def add(self, addrs: tuple[bytes, ...] | list[bytes], now: float) -> None:
        for a in addrs:
            self._t.pop(a, None)
            self._t[a] = now
        while self._t:
            oldest = next(iter(self._t))
            if len(self._t) <= self.limit and now - self._t[oldest] < self.keep:
                break
            del self._t[oldest]

    def clear(self) -> None:
        self._t.clear()


@dataclass
class Stats:
    """Counts since the filler started; all of it reaches the status file, and none of it is an address
    or a name. Every packet received is in exactly one of held, known, empty, late, failed, truncated,
    unparsed_udp, unparsed_tcp, other and (attention) held_essentials, unless an internal error released it
    (`errors`)."""

    received: int = 0  # packets the queue handed over
    held: int = 0  # answers released after the kernel acknowledged their addresses
    known: int = 0  # answers released at once: every address added within KNOWN_FOR
    empty: int = 0  # answers with no address to add (blocked, no A record, only local addresses)
    late: int = 0  # answers released before their add finished (HOLD_BOUND passed, or the adder behind)
    failed: int = 0  # answers released without their addresses: the kernel refused the add
    truncated: int = 0  # UDP answers with the truncation bit, passed untouched
    unparsed_udp: int = 0  # UDP answers not read (malformed, over MAX_DNS, a fragment)
    unparsed_tcp: int = 0  # TCP segments with data that are not whole DNS messages
    other: int = 0  # packets that are no answer: a segment without data, a query-shaped message
    addresses: int = 0  # set elements added or renewed
    adds_failed: int = 0  # add transactions the kernel refused (a late one counts here when it fails)
    adds_dropped: int = 0  # late adds not even tried: the adder was ADD_BACKLOG behind
    kernel_passed: int = 0  # packets the kernel accepted itself because the socket's buffer was full
    verdict_errors: int = 0  # verdicts the kernel answered with an error, or that could not be sent
    errors: int = 0  # internal errors; each released its packet
    drained: int = 0  # packets released while stopping
    # (attention) the attention count's platform set (design decision 69): addresses of the TV's essentials
    # added or renewed, and adds of them the kernel refused (the attention table not loaded, mostly)
    essentials: int = 0
    essentials_failed: int = 0
    # answers held only for their essentials' add: every gate address of them was known
    held_essentials: int = 0


class Job:
    """One piece of work handed to the adder, and what became of it: the addresses of an add, or `fn`,
    any other transaction (the live switch), which returns its errno. (attention) `essential` are
    addresses for the attention count's platform set, added after `addrs` in a transaction of their own,
    so that a missing attention table never fails the gate's add; `essential_errno` is that one's."""

    __slots__ = ("addrs", "done", "errno", "essential", "essential_errno", "fn")

    def __init__(
        self,
        addrs: tuple[bytes, ...] = (),
        fn: Callable[[], int] | None = None,
        essential: tuple[bytes, ...] = (),
    ):
        self.addrs = addrs
        self.fn = fn
        self.essential = essential
        self.done = threading.Event()
        self.errno: int | None = None
        self.essential_errno: int | None = None


class Adder(threading.Thread):
    """Runs the nf_tables transactions, one at a time, off the loop's thread: a transaction waits for
    nf_tables' lock inside the kernel, where no timeout reaches it, so the loop hands each one over and
    decides for itself how long to wait."""

    def __init__(
        self,
        add: Callable[[tuple[bytes, ...]], int],
        backlog: int = ADD_BACKLOG,
        add_essential: Callable[[tuple[bytes, ...]], int] | None = None,
    ):
        super().__init__(name="tvgw-inpath-adder", daemon=True)
        self._add = add
        self._add_essential = add_essential  # (attention)
        self._jobs: queue.Queue[Job] = queue.Queue(maxsize=backlog)
        self._busy = threading.Event()

    def idle(self) -> bool:
        return not self._busy.is_set() and self._jobs.empty()

    def submit(self, addrs: tuple[bytes, ...], essential: tuple[bytes, ...] = ()) -> Job | None:
        return self._put(Job(addrs, essential=essential))

    def call(self, fn: Callable[[], int]) -> Job | None:
        """Run `fn` (a transaction that returns its errno) on this thread, in its turn."""
        return self._put(Job(fn=fn))

    def _put(self, job: Job) -> Job | None:
        try:
            self._jobs.put_nowait(job)
        except queue.Full:
            return None
        return job

    def run(self) -> None:
        while True:
            job = self._jobs.get()
            self._busy.set()
            try:
                if job.fn is not None:
                    job.errno = job.fn()
                else:
                    job.errno = self._add(job.addrs) if job.addrs else 0
                    if job.essential:  # (attention) its own transaction, after the gate's
                        job.essential_errno = self._essential(job.essential)
            except OSError as e:
                job.errno = e.errno or errno.EIO
            except Exception:
                job.errno = errno.EIO
            finally:
                self._busy.clear()
                job.done.set()

    def _essential(self, addrs: tuple[bytes, ...]) -> int:
        if self._add_essential is None:
            return errno.ENOENT
        try:
            return self._add_essential(addrs)
        except OSError as e:
            return e.errno or errno.EIO
        except Exception:
            return errno.EIO


class Filler:
    """The decision for each queued packet. `release(packet_id)` gives the accept verdict; `adder` has
    `submit(addrs) -> Job | None`; `clock` is monotonic seconds."""

    def __init__(
        self,
        release: Callable[[int], None],
        adder,
        clock: Callable[[], float] = time.monotonic,
        log: Callable[[str], None] = lambda line: print(line, file=sys.stderr, flush=True),
        hold_bound: float = HOLD_BOUND,
        essential: Callable[[str], bool] | None = None,
        shadow=None,
    ):
        self._release, self.adder, self.clock, self._log = release, adder, clock, log
        self.hold_bound = hold_bound
        self.stats = Stats()
        self.known = Known()
        # (attention) the test of an answer's name against the TV's essentials, None where the attention
        # count is not in use; the addresses whose essentials add the kernel acknowledged, as `known`
        self.essential = essential
        self.known_essential = Known()
        self.essential_off_until = -1.0
        self.pending: list[Job] = []  # adds an answer did not wait for
        self.holds: list[float] = []  # the last HOLD_SAMPLES hold times, seconds
        self.essential_holds: list[float] = []  # (attention) the same, of holds that added essentials
        self.set_missing = False  # the last add found no table or no set
        # (mint) the minted-address shadow (design decision 96), None unless MINT=shadow: handed each
        # answer once its verdict is given, so it can neither keep an answer nor make one wait
        self.shadow = shadow
        self._last_id = 0
        self._logged: dict[str, float] = {}

    def say(self, kind: str, line: str) -> None:
        """A log line, at most one of its kind per LOG_EVERY seconds."""
        now = self.clock()
        if now - self._logged.get(kind, -LOG_EVERY) >= LOG_EVERY:
            self._logged[kind] = now
            self._log(f"tvgw dnsgate-inpath: {line}")

    def handle(self, packet: nfnl.Packet, t0: float) -> None:
        """Decide one packet, received at `t0`. Its verdict is given exactly once, whatever happens."""
        released = False

        def release() -> None:
            nonlocal released
            if not released:
                released = True
                self._release(packet.id)

        try:
            self._decide(packet, t0, release)
        except Exception as e:  # nothing in the reading or the adding may keep an answer
            self.stats.errors += 1
            self.say("error", f"internal error, the answer was released: {type(e).__name__}: {e}")
        finally:
            release()
        if self.shadow is not None:  # (mint) after the verdict; the shadow never raises
            self.shadow.answer(packet.payload, packet.whole)

    def _decide(self, packet: nfnl.Packet, t0: float, release: Callable[[], None]) -> None:
        st = self.stats
        st.received += 1
        if packet.id > self._last_id:
            # ids are consecutive per queue; the kernel takes one before it finds the socket's buffer
            # full and accepts the packet itself, so a gap is what it passed without this process
            st.kernel_passed += packet.id - self._last_id - 1
            if self.shadow is not None and packet.id - self._last_id > 1:
                self.shadow.missed()  # (mint) what the kernel passed, the shadow never saw
            self._last_id = packet.id
        now = self.clock()
        test = self.essential if now >= self.essential_off_until else None
        parsed = read_packet(packet.payload, packet.whole, test)
        if parsed.kind != ANSWER:
            release()
            setattr(st, parsed.kind, getattr(st, parsed.kind) + 1)
            return
        need = tuple(a for a in parsed.addrs if not self.known.fresh(a, now))
        essential = tuple(a for a in parsed.essential if not self.known_essential.fresh(a, now))
        if not need and not essential:
            release()
            if parsed.addrs:
                st.known += 1
            else:
                st.empty += 1
            return
        if self.pending:
            # an earlier add has not come back: do not queue this answer behind it
            release()
            st.late += 1
            self._later(need, essential)
            return
        # (attention) the essentials only when there are some, so an adder that knows none is asked as before
        job = self.adder.submit(need, essential) if essential else self.adder.submit(need)
        if job is None:
            release()
            st.late += 1
            st.adds_dropped += 1
            return
        finished = job.done.wait(max(self.hold_bound - (self.clock() - t0), 0.0))
        release()
        if not finished:
            st.late += 1
            self.pending.append(job)
            self.say("late", f"an add took over {self.hold_bound * 1000:.0f} ms; the answer was released")
            return
        took = self.clock() - t0
        if self._settle(job):
            # (attention) an answer whose gate addresses were all known waited for its essentials alone:
            # counted apart, and every hold that carried an essentials add is measured apart, so the
            # gate's own hold (`hold_us`) is what it was and the essentials' cost is measured
            # (`essential_hold_us`)
            if job.addrs:
                st.held += 1
            else:
                st.held_essentials += 1
            samples = self.essential_holds if job.essential else self.holds
            samples.append(took)
            del samples[:-HOLD_SAMPLES]
        else:
            st.failed += 1

    def _later(self, addrs: tuple[bytes, ...], essential: tuple[bytes, ...] = ()) -> None:
        job = self.adder.submit(addrs, essential) if essential else self.adder.submit(addrs)
        if job is None:
            self.stats.adds_dropped += 1
        else:
            self.pending.append(job)

    def _settle(self, job: Job) -> bool:
        """Book a finished add; True when the kernel took it. (attention) The essentials add is booked
        apart, and never decides whether the answer counts as held."""
        if job.essential:
            self._settle_essential(job)
        if job.errno == 0:
            self.known.add(job.addrs, self.clock())
            self.stats.addresses += len(job.addrs)
            if job.addrs:  # (attention) a job of essentials alone says nothing about the gate's set
                self.set_missing = False
            return True
        self.stats.adds_failed += 1
        if job.errno == errno.ENOENT:
            # no table or no set: an apply is in progress, or the gate was switched off. Whatever was
            # in the set is gone with it, so nothing is known any more
            self.known.clear()
            self.set_missing = True
            self.say("missing", f"inet {TABLE} {SET} is not there; answers pass unheld until it is")
        else:
            name = errno.errorcode.get(job.errno or 0, str(job.errno))
            self.say("refused", f"the kernel refused an add ({name}); the answer was released")
        return False

    def _settle_essential(self, job: Job) -> None:
        """(attention) Book the platform set's add. A missing attention table (the count not in use, or an
        apply under way) turns those adds off for ESSENTIALS_OFF seconds, so a filler started before
        ATTENTION_WALL=off was applied costs one refused transaction now and then, not one per answer."""
        if job.essential_errno == 0:
            self.known_essential.add(job.essential, self.clock())
            self.stats.essentials += len(job.essential)
            return
        self.stats.essentials_failed += 1
        if job.essential_errno == errno.ENOENT:
            self.known_essential.clear()
            self.essential_off_until = self.clock() + ESSENTIALS_OFF
            self.say("essentials", f"inet {ESSENTIALS_TABLE} is not there; the essentials wait until it is")

    def reap(self) -> None:
        """Book the late adds that have finished since."""
        if not self.pending:
            return
        still = []
        for job in self.pending:
            if job.done.is_set():
                self._settle(job)
            else:
                still.append(job)
        self.pending = still

    def hold_micros(self, samples: list[float] | None = None) -> dict[str, int]:
        """The recent hold times in microseconds: how many, the median, the 99th percentile, the longest.
        (attention) `samples` another list of them, the essentials' holds."""
        samples = self.holds if samples is None else samples
        if not samples:
            return {"n": 0, "p50": 0, "p99": 0, "max": 0}
        ranked = sorted(samples)
        at = lambda q: int(ranked[min(len(ranked) - 1, int(q * len(ranked)))] * 1e6)  # noqa: E731
        return {"n": len(ranked), "p50": at(0.5), "p99": at(0.99), "max": int(ranked[-1] * 1e6)}


# --- the status file ---------------------------------------------------------------------------------


def status(
    filler: Filler, queue_num: int, live: bool, started: float, now: float, dropped_1h: int = 0
) -> dict:
    """What `tvgw verify` and the hardware suite read: counts and times, no address and no name.
    `dropped_1h` is how many verdicts the kernel refused in the last DROPS_WINDOW: each one an answer
    the kernel had already dropped, which its own counters never show."""
    return {
        "dropped_1h": dropped_1h,
        "v": 1,
        "pid": os.getpid(),
        "started": started,
        "t": now,
        "queue": queue_num,
        "live": live,
        "set_missing": filler.set_missing,
        "stats": asdict(filler.stats),
        "hold_us": filler.hold_micros(),
        "essential_hold_us": filler.hold_micros(filler.essential_holds),  # (attention)
    }


def write_status(path: str, doc: dict) -> bool:
    """Replace `path` with `doc`, whole. False when it could not be written (no such directory when the
    filler runs outside its unit): the status is a report, never a reason to stop. Mode 0640: its counts
    say how much the TV looked up, and the gateway has other accounts (design decision 63)."""
    tmp = f"{path}.tmp"
    try:
        with open(tmp, "w", encoding="utf-8") as fh:
            json.dump(doc, fh, sort_keys=True)
            fh.write("\n")
        os.chmod(tmp, 0o640)
        os.replace(tmp, path)
    except OSError:
        return False
    return True


def bound_queues(text: str) -> dict[int, dict[str, int]]:
    """/proc/net/netfilter/nfnetlink_queue as queue number -> its columns: the port id of the process
    bound to it, the packets waiting, the packets the kernel dropped because the queue was full
    (`dropped`) or the socket could not take them (`user_dropped`), and the last packet id. With
    fail-open both drop counts stay 0. A line that does not parse is skipped."""
    out: dict[int, dict[str, int]] = {}
    for line in text.splitlines():
        f = line.split()
        try:
            n = [int(x) for x in f[:8]]
        except ValueError:
            continue
        if len(n) == 8:
            out[n[0]] = {
                "portid": n[1],
                "waiting": n[2],
                "copy_mode": n[3],
                "dropped": n[5],
                "user_dropped": n[6],
                "last_id": n[7],
            }
    return out


# --- the sockets -------------------------------------------------------------------------------------


def _netlink() -> socket.socket:
    family = getattr(socket, "AF_NETLINK", nfnl.AF_NETLINK)
    s = socket.socket(family, socket.SOCK_RAW, nfnl.NETLINK_NETFILTER)
    s.bind((0, 0))
    return s


class NftSocket:
    """One netlink socket for nf_tables transactions, used by one thread."""

    def __init__(self, sock: socket.socket | None = None, wait: float = 0.25):
        self.sock = sock or _netlink()
        self.wait = wait
        self.seq = 1

    def _answers(self) -> list[bytes]:
        """Every datagram waiting on the socket, without waiting for more."""
        out: list[bytes] = []
        while True:
            try:
                out.append(self.sock.recv(65536, socket.MSG_DONTWAIT))
            except BlockingIOError:
                return out

    def transact(self, build: Callable[[int], bytes], parts: int = 1) -> int:
        """Send the transaction `build(seq)`, of `parts` messages between its begin and its end, and
        return its errno, 0 when it was committed. The kernel runs the whole batch inside the send and
        queues every answer before the send returns, so the answers are read without waiting; only when
        none is there does the read wait once, so that nothing here depends on that order."""
        seq = self.seq
        self.seq = seq + parts + 2 if seq < 0x7FFFFFF0 else 1
        try:
            self.sock.send(build(seq))
            replies = self._answers()
            if not replies and select.select([self.sock], [], [], self.wait)[0]:
                replies = self._answers()
        except OSError as e:  # ENOBUFS: an answer was lost, and the outcome with it
            return e.errno or errno.EIO
        return nfnl.batch_result(replies, seq, parts)

    def add(self, addrs: tuple[bytes, ...]) -> int:
        return self.transact(lambda seq: nfnl.setelem_add(seq, TABLE, SET, list(addrs), TTL))

    def add_essential(self, addrs: tuple[bytes, ...]) -> int:
        """(attention) The attention count's platform set, with the gate's own lifetime and expiry."""
        return self.transact(
            lambda seq: nfnl.setelem_add(seq, ESSENTIALS_TABLE, ESSENTIALS_SET, list(addrs), TTL)
        )

    def live(self, on: bool) -> int:
        """Put LIVE_PORT into inpath_live, or empty the set. The port is created, not added: 0 says it
        was not there (the first time, or an apply has made the table anew since), EEXIST that it
        still was."""
        if on:
            return self.transact(lambda seq: nfnl.setelem_add(seq, TABLE, LIVE_SET, [LIVE_KEY], create=True))
        return self.transact(lambda seq: nfnl.set_flush(seq, TABLE, LIVE_SET))

    def close(self) -> None:
        self.sock.close()


class QueueSocket:
    """The netlink socket bound to the packet queue."""

    def __init__(self, queue_num: int = QUEUE, maxlen: int = MAXLEN, sock: socket.socket | None = None):
        self.queue, self.maxlen = queue_num, maxlen
        self.sock = sock or _netlink()
        self.early: list[bytes] = []  # datagrams read while waiting for an acknowledgement
        if sock is None:
            # a full buffer must not turn into an error on the next read: the kernel has already
            # accepted that packet itself (fail-open), and the gap in the ids counts it
            with contextlib.suppress(OSError):
                self.sock.setsockopt(nfnl.SOL_NETLINK, nfnl.NETLINK_NO_ENOBUFS, 1)
            try:
                self.sock.setsockopt(socket.SOL_SOCKET, nfnl.SO_RCVBUFFORCE, RCVBUF)
            except OSError:
                with contextlib.suppress(OSError):
                    self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, RCVBUF)

    def fileno(self) -> int:
        return self.sock.fileno()

    def _acked(self, seq: int, wait: float) -> int:
        """Read until the acknowledgement of `seq`; every other datagram is kept for the loop."""
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
                answers = [a for m in nfnl.messages(data) if (a := nfnl.ack(m)) is not None]
            except nfnl.NlError:
                answers = []
            mine = [e for answered, e in answers if answered == seq]
            if mine:
                return mine[0]
            self.early.append(data)
        return errno.ETIMEDOUT

    def bind(self, wait: float = 2.0) -> int:
        """Bind and configure the queue; the errno, 0 when the kernel acknowledged it."""
        try:
            self.sock.send(nfnl.queue_bind(self.queue, 1, self.maxlen))
        except OSError as e:
            return e.errno or errno.EIO
        return self._acked(1, wait)

    def close_queue(self, wait: float = 1.0) -> int:
        """Stop the kernel from queueing more (length 0: with fail-open it accepts each new packet
        itself). Every packet queued before that sits ahead of the acknowledgement in this socket, and
        is left in `early` for the caller to release."""
        try:
            self.sock.send(nfnl.queue_maxlen(self.queue, 2, 0))
        except OSError as e:
            return e.errno or errno.EIO
        return self._acked(2, wait)

    def recv(self, wait: float, also: tuple[int, ...] = ()) -> bytes | None:
        """The next datagram, or None after `wait` seconds or when one of the `also` descriptors became
        readable first."""
        if self.early:
            return self.early.pop(0)
        ready, _, _ = select.select([self.sock, *also], [], [], max(wait, 0.0))
        if self.sock not in ready:
            return None
        try:
            return self.sock.recv(RECV_SIZE)
        except OSError as e:
            if e.errno in (errno.ENOBUFS, errno.EAGAIN, errno.EINTR):
                return None
            raise

    def release(self, packet_id: int) -> None:
        self.sock.send(nfnl.verdict(self.queue, packet_id))

    def close(self) -> None:
        self.sock.close()


def notify(state: str, env: dict[str, str] | None = None) -> bool:
    """sd_notify: one datagram to the socket systemd named, if it named one."""
    path = (os.environ if env is None else env).get("NOTIFY_SOCKET", "")
    if not path or path[0] not in "/@":
        return False
    address = "\0" + path[1:] if path[0] == "@" else path
    try:
        with socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM) as s:
            s.sendto(state.encode("ascii"), address)
    except OSError:
        return False
    return True


# --- the loop ----------------------------------------------------------------------------------------


class Loop:
    """The filler's main loop over a bound queue socket. `live(on) -> errno` switches inpath_live
    (switching on: 0 when the port was newly put in, EEXIST when it was still there);
    `ping()` feeds the watchdog; `publish(doc)` writes the status. All injected, so the unit tests run
    the loop itself against a scripted socket."""

    def __init__(
        self,
        qsock,
        filler: Filler,
        live: Callable[[bool], int],
        ping: Callable[[], object] = lambda: None,
        publish: Callable[[dict], object] = lambda doc: None,
        clock: Callable[[], float] = time.monotonic,
        wall: Callable[[], float] = time.time,
        adder_alive: Callable[[], bool] = lambda: True,
        defer: Callable[[Callable[[], int]], Job | None] | None = None,
    ):
        self.qsock, self.filler, self._live, self._ping, self._publish = qsock, filler, live, ping, publish
        self.clock, self.wall, self.adder_alive = clock, wall, adder_alive
        # `defer(fn)` runs a transaction off this thread (the adder's `call`); left out, it runs here
        self._defer = defer or self._here
        self._asked: Job | None = None  # a switch-on that has not come back yet
        self.live = False
        self.started = wall()
        self._next = {"ping": 0.0, "live": 0.0, "status": 0.0}
        self._refused: list[tuple[float, int]] = []  # (wall time, verdict_errors then), for dropped_1h
        self._present_at: float | None = None  # (mint) wall time the live port was last found in place

    def dropped_1h(self, now: float) -> int:
        """Verdicts the kernel refused in the last DROPS_WINDOW, from the samples the status ticks keep."""
        total = self.filler.stats.verdict_errors
        self._refused.append((now, total))
        while len(self._refused) > 1 and now - self._refused[1][0] >= DROPS_WINDOW:
            del self._refused[0]
        return total - self._refused[0][1] if now - self._refused[0][0] >= DROPS_WINDOW else total

    @staticmethod
    def _here(fn: Callable[[], int]) -> Job:
        job = Job(fn=fn)
        try:
            job.errno = fn()
        except OSError as e:
            job.errno = e.errno or errno.EIO
        job.done.set()
        return job

    def release(self, packet_id: int) -> None:
        """The accept verdict; a send that fails is tried once more, then counted."""
        for attempt in (1, 2):
            try:
                self.qsock.release(packet_id)
                return
            except OSError as e:
                if attempt == 2:
                    self.filler.stats.verdict_errors += 1
                    self.filler.say("verdict", f"a verdict could not be sent: {e}")

    def tick(self) -> None:
        """The periodic work: the watchdog ping, the live switch, the late adds, the status file."""
        now = self.clock()
        if now >= self._next["ping"]:
            self._next["ping"] = now + PING_EVERY
            self._ping()
        self.filler.reap()
        if now >= self._next["live"] and self._asked is None:
            # off this thread: a re-apply can hold nf_tables' lock for a while, and the loop must go on
            # releasing answers meanwhile
            self._next["live"] = now + LIVE_EVERY
            self._asked = self._defer(lambda: self._live(True))
        if self._asked is not None and self._asked.done.is_set():
            job, self._asked = self._asked, None
            self._switched(job.errno if job.errno is not None else errno.EIO)
        if now >= self._next["status"]:
            self._next["status"] = now + STATUS_EVERY
            wall = self.wall()
            doc = status(self.filler, self.qsock.queue, self.live, self.started, wall, self.dropped_1h(wall))
            shadow = self.filler.shadow
            if shadow is not None:  # (mint) a forget asked for, then the shadow's counts
                shadow.tick()
                doc["mint"] = shadow.status()
            self._publish(doc)

    def assert_live(self) -> None:
        """Put the port into inpath_live now, on this thread: the first time, before the loop turns."""
        self._next["live"] = self.clock() + LIVE_EVERY
        self._switched(self._live(True))

    def _switched(self, err: int) -> None:
        """Book a switch-on that came back with `err`. An apply that made the table anew made the set
        empty: whenever the port was not there any more, or the set is not, what the filler added may
        have gone with it, and nothing is known to be in resolved4_inpath."""
        was, self.live = self.live, err in (0, errno.EEXIST)
        if self.live != was:
            self._next["status"] = 0.0  # the status says so at once, not ten seconds later
        if err != errno.EEXIST:
            self.filler.known.clear()
        shadow = self.filler.shadow
        if shadow is not None:
            # (mint) the port not in place: the answers since it was last seen passed the queue unseen
            if err != errno.EEXIST:
                shadow.missed(self._present_at)
            self._present_at = self.wall() if self.live else None
        if self.live and not was:
            self.filler.set_missing = False
            self.filler._log(f"tvgw dnsgate-inpath: holding the TV's DNS answers (queue {self.qsock.queue})")
        elif was and not self.live:
            self.filler.say("live", f"inet {TABLE} {LIVE_SET} is not there; no answer is held until it is")

    def deliver(self, data: bytes, t0: float) -> None:
        """One datagram from the queue socket: packets are decided, errors counted."""
        try:
            msgs = list(nfnl.messages(data))
        except nfnl.NlError:
            self.filler.stats.errors += 1
            return
        for msg in msgs:
            try:
                packet = nfnl.queue_packet(msg)
            except nfnl.NlError:
                # a packet message without its id cannot be released; the kernel never sends one
                self.filler.stats.errors += 1
                self.filler.say("nl", "a queue message did not parse")
                continue
            if packet is not None:
                self.filler.handle(packet, t0)
                continue
            with contextlib.suppress(nfnl.NlError):
                answer = nfnl.ack(msg)
                if answer is not None and answer[1]:
                    self.filler.stats.verdict_errors += 1

    def run(self, stop: Callable[[], bool], wake: tuple[int, ...] = ()) -> None:
        """Serve until `stop()`; `wake` are descriptors that end a wait (the signal pipe)."""
        while not stop():
            self.tick()
            if not self.adder_alive():
                raise RuntimeError("the adder thread ended")
            shadow = self.filler.shadow
            data = self.qsock.recv(PING_EVERY, wake if shadow is None else (*wake, *shadow.fds()))
            if data is not None:
                self.deliver(data, self.clock())
            if shadow is not None:  # (mint) the connections' copies, after the answer that waited
                shadow.poll()

    def drain(self, wait: float = 0.25) -> None:
        """Stop without losing an answer: stop matching, stop queueing, release what waits. The first
        is a transaction and may wait for nf_tables' lock; the stop does not wait for it longer than
        `wait`, since the second step alone already keeps every answer."""
        off = self._defer(lambda: self._live(False))
        if off is not None:
            off.done.wait(wait)
        self.live = False
        err = self.qsock.close_queue()
        if err:
            self.filler.say("drain", f"the queue would not close ({errno.errorcode.get(err, err)})")
        while self.qsock.early:
            data = self.qsock.early.pop(0)
            try:
                packets = [p for m in nfnl.messages(data) if (p := nfnl.queue_packet(m)) is not None]
            except nfnl.NlError:
                continue
            for packet in packets:
                self.release(packet.id)
                self.filler.stats.drained += 1


def wanted(s: Settings) -> bool:
    """Whether the settings ask for the in-path filler: the gate counting, and DNSGATE_FILL=inpath."""
    return s.dnsgate == "count" and s.dnsgate_fill == "inpath"


def main(s: Settings, queue_num: int = QUEUE, status_path: str = STATUS, profile=None) -> int:
    if not wanted(s):
        print(
            f"tvgw dnsgate-inpath: DNSGATE={s.dnsgate} DNSGATE_FILL={s.dnsgate_fill}, nothing to hold",
            flush=True,
        )
        # the unit's ExecCondition keeps it from getting here; if it does, a notify unit that ended
        # without a word would count as failed and be restarted for ever
        notify("READY=1")
        return 0
    stopping = threading.Event()
    for sig in (signal.SIGTERM, signal.SIGINT):  # before anything is bound, so a stop at any point drains
        signal.signal(sig, lambda *_: stopping.set())
    nft = NftSocket()  # this thread's until the adder starts, the adder's from then on
    # no answer may be offered to the queue while it is bound but not yet configured, nor to a queue
    # someone else holds: the port goes first, whatever follows
    err = nft.live(False)
    if err not in (0, errno.ENOENT):
        print(
            f"tvgw dnsgate-inpath: could not empty {LIVE_SET} ({errno.errorcode.get(err, err)}); not binding",
            file=sys.stderr,
            flush=True,
        )
        return 1
    try:
        with open(PROC_QUEUES, encoding="utf-8") as fh:
            taken = queue_num in bound_queues(fh.read())
    except OSError:
        taken = False
    if taken:
        print(
            f"tvgw dnsgate-inpath: queue {queue_num} is already bound by another process; {LIVE_SET} is"
            " empty, so no answer reaches it",
            file=sys.stderr,
            flush=True,
        )
        return 1
    qsock = QueueSocket(queue_num)
    err = qsock.bind()
    if err:
        print(
            f"tvgw dnsgate-inpath: could not bind queue {queue_num} ({errno.errorcode.get(err, err)});"
            " the kernel passes the answers itself",
            file=sys.stderr,
            flush=True,
        )
        return 1
    loop: Loop
    # (attention) where the attention count is in use, the answers to the TV's essentials fill its platform
    # set too (design decision 69); the test is the profile's, read once at start
    essential = None
    if profile is not None:
        from tvgw import attention

        essential = attention.platform_check(profile) if attention.wanted(s) else None
    # (mint) the minted-address shadow, where MINT=shadow asks for it (design decision 96): None when its
    # copies' group cannot be bound, and the filler holds the answers as before
    shadow = None
    if getattr(s, "mint", "off") == "shadow":
        from tvgw import mintshadow

        shadow = mintshadow.start(s, profile)
    adder = Adder(nft.add, add_essential=nft.add_essential)
    filler = Filler(lambda packet_id: loop.release(packet_id), adder, essential=essential, shadow=shadow)
    loop = Loop(
        qsock,
        filler,
        nft.live,
        ping=lambda: notify("WATCHDOG=1"),
        publish=lambda doc: write_status(status_path, doc),
        adder_alive=adder.is_alive,
        defer=adder.call,
    )
    r, w = os.pipe()
    os.set_blocking(w, False)
    signal.set_wakeup_fd(w)
    loop.assert_live()  # here, before the adder has the socket: the queue is configured, so switch on
    adder.start()
    loop.tick()  # the first status
    notify("READY=1")
    try:
        loop.run(stopping.is_set, (r,))
    finally:
        notify("STOPPING=1")
        loop.drain()
        qsock.close()
        if shadow is not None:
            shadow.close()
    st = filler.stats
    print(
        f"tvgw dnsgate-inpath: stopped after {st.received} packets ({st.held} held, {st.late} late,"
        f" {st.drained} released while stopping)",
        flush=True,
    )
    return 0
