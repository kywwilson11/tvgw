"""(screentest) The one-second poll: what the TV sent, second by second and destination by destination,
read from the connection table (design decision 88).

The flow log writes one line for a connection when it ends, and the capture keeps packets. Neither says
how much the TV sent in each second of a connection that is still open, which is what a test of "does
anything follow the picture" needs. `Poll.tick()` lists the TV's connections (`conntrack -L`), takes
each one's counters from what it read a tick before, and adds the difference up by destination.

- **Payload, not bytes.** The counters include bare acknowledgements. A tick's payload is its bytes less
  TCP_HEADERS or UDP_HEADERS for each packet, floored at 0, so a second of acknowledgements reads as
  nothing sent. It is an estimate: the counters do not say what options a packet carried, so a packet
  without timestamps reads 12 bytes short and one with selective acknowledgements a few bytes long.
- **A destination is a `cell`:** the address's /24 and the port, as `queries.acr_cell` groups unnamed
  traffic. A client that moves among a provider's addresses stays in one series.
- **A connection is the kernel's own entry,** told apart by the id the listing gives it: two pings to
  one address are two, and an entry that replaced another on the same ports is new.
- **A connection first seen** counts its whole counters as that tick's.
- **Left out:** what did not go to a public address (the gateway's, the home network's, multicast), and
  what the gateway answered in a public address's place, as it answers every lookup wherever the TV
  aims it. IPv4 only: nothing of the TV's leaves its port over IPv6.
- **A listing that fails** is a tick in which nothing is read and nothing forgotten; the next one that
  succeeds counts what was sent since the last that did. `PollError` is for what no later tick mends:
  no tool, no counters in the table, a gateway that cannot look once a second, more failed listings
  than MISSED allows.

It holds everything in memory, keeps nothing, and asks the TV nothing.
"""

from __future__ import annotations

import ipaddress
import subprocess
import time
from dataclasses import dataclass

from tvgw.conntrack import counter, directions
from tvgw.names import is_public_address
from tvgw.screentest import TOTAL

# bytes of header an IPv4 packet carries: 20 of IP, and TCP's 20 with its 12 of timestamps, or UDP's 8
TCP_HEADERS, UDP_HEADERS = 52, 28
HEADERS = {"tcp": TCP_HEADERS, "udp": UDP_HEADERS}
LISTING = ("conntrack", "-L", "-o", "extended,id", "-f", "ipv4", "-s")  # the TV's address is added
PATIENCE = 5.0  # seconds a listing may take, and a watch may fall behind its clock
MISSED = 0.05  # the share of a watch's listings that may fail before the watch says nothing


class PollError(Exception):
    """The connection table cannot be read in a way a later tick would mend."""


@dataclass(frozen=True)
class Entry:
    """One connection as the table lists it: who to, who answered, and the counters of each direction."""

    proto: str
    src: str
    dst: str
    sport: int | None
    dport: int | None
    pkts_up: int
    bytes_up: int
    pkts_down: int
    bytes_down: int
    answered_by: str = ""  # the reply's source: the destination, unless the gateway took its place
    ids: tuple[str, ...] = ()  # every id the line carries: the kernel's for the entry, and a ping's own

    @property
    def key(self) -> tuple:
        return self.proto, self.src, self.dst, self.sport, self.dport, self.ids


def parse_entry(line: str) -> Entry | None:
    """One IPv4 line of `conntrack -L -o extended,id`; None for anything else. It never raises."""
    toks = line.split()
    try:
        fam = toks.index("ipv4")
        proto = toks[fam + 2]
        orig, reply, _extra, _state = directions(toks[fam + 4 :])
        if "src" not in orig or "dst" not in orig:
            return None
        return Entry(
            proto,
            orig["src"],
            orig["dst"],
            counter(orig, "sport") or None,
            counter(orig, "dport") or None,
            counter(orig, "packets"),
            counter(orig, "bytes"),
            counter(reply, "packets"),
            counter(reply, "bytes"),
            reply.get("src", orig["dst"]),
            tuple(t[3:] for t in toks if t.startswith("id=")),
        )
    except (IndexError, ValueError):
        return None


def cell(dst: str, dport: int | None) -> str:
    """The destination a connection is counted under: `203.0.113.0/24:443`, and no port where the
    protocol has none."""
    net = ipaddress.ip_network((ipaddress.IPv4Address(dst), 24), strict=False)
    return f"{net}" if dport is None else f"{net}:{dport}"


def payload(proto: str, packets: int, nbytes: int) -> int:
    """What a direction carried beyond its packets' headers, as near as the counters say."""
    return max(0, nbytes - packets * HEADERS.get(proto, 0))


class Poll:
    """The TV's connections, read once a tick."""

    def __init__(self, tv_ip: str):
        self.tv_ip = tv_ip
        self.seen: dict[tuple, tuple[int, int]] = {}  # an entry -> its packets and bytes up, when last read
        self.failed = 0  # listings that could not be read
        self.unread = 0  # lines of the listings that were no connection the reader knows

    def tick(self) -> dict[str, int]:
        """cell -> the payload the TV sent it since the last listing that was read."""
        try:
            listed = subprocess.run(
                [*LISTING, self.tv_ip], capture_output=True, text=True, check=False, timeout=PATIENCE
            )
        except FileNotFoundError:
            raise PollError("the conntrack tool is not installed") from None
        except (OSError, subprocess.TimeoutExpired):
            self.failed += 1
            return {}
        if listed.returncode != 0:
            self.failed += 1
            return {}
        sent: dict[str, int] = {}
        now: dict[tuple, tuple[int, int]] = {}
        for line in filter(str.strip, listed.stdout.splitlines()):
            entry = parse_entry(line)
            if entry is None:
                self.unread += 1
                continue
            if entry.src != self.tv_ip or not is_public_address(entry.dst):
                continue
            if "packets=" not in line:
                raise PollError(
                    "the connection table carries no counters (net.netfilter.nf_conntrack_acct is off)"
                )
            if entry.answered_by != entry.dst and not is_public_address(entry.answered_by):
                continue  # the gateway answered in its place: nothing went there
            packets, nbytes = self.seen.get(entry.key, (0, 0))
            if entry.pkts_up < packets or entry.bytes_up < nbytes:  # not the entry it was: count it whole
                packets = nbytes = 0
            now[entry.key] = (entry.pkts_up, entry.bytes_up)
            more = payload(entry.proto, entry.pkts_up - packets, entry.bytes_up - nbytes)
            if more:
                where = cell(entry.dst, entry.dport)
                sent[where] = sent.get(where, 0) + more
        self.seen = now
        return sent


clock, sleep = time.monotonic, time.sleep  # what `watch` tells the time by; a test stands in for both


def watch(poll: Poll, seconds: int) -> list[dict[str, int]]:
    """`seconds` ticks, one at each second of the clock, after a first that only takes the counters as
    they stand. A tick that ran late is followed at once by the next. The watch ends with PollError when
    the first listing fails, when a tick is PATIENCE behind its second (the seconds would no longer be
    the clock's), or when more than MISSED of the listings have failed."""
    poll.tick()
    if poll.failed:
        raise PollError("the connection table could not be listed")
    start = clock()
    ticks = []
    for second in range(1, seconds + 1):
        wait = start + second - clock()
        if wait > 0:
            sleep(wait)
        elif -wait > PATIENCE:
            raise PollError("the gateway was too busy to look once a second")
        ticks.append(poll.tick())
        if poll.failed > seconds * MISSED:
            raise PollError(f"the connection table could not be listed {poll.failed} times")
    return ticks


def series(ticks: list[dict[str, int]]) -> dict[str, list[float]]:
    """The payload the TV sent each cell in each tick, and TOTAL, each as long as the run."""
    out: dict[str, list[float]] = {TOTAL: [0.0] * len(ticks)}
    for t, sent in enumerate(ticks):
        for where, nbytes in sent.items():
            out.setdefault(where, [0.0] * len(ticks))[t] += nbytes
            out[TOTAL][t] += nbytes
    return out
