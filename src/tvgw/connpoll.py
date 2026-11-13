"""(screentest) The one-second poll: what the TV sent, second by second and destination by destination,
read from the connection table (design decision 88).

The flow log writes one line for a connection when it ends, and the capture keeps packets. Neither says
how much the TV sent in each second of a connection that is still open, which is what a test of "does
anything follow the picture" needs. `Poll.tick()` lists the TV's connections (`conntrack -L`), takes
each one's counters from what it read a tick before, and adds the difference up by destination.

- **Payload, not bytes.** The counters include bare acknowledgements. A tick's payload is its bytes less
  the headers of its packets (TCP_HEADERS or UDP_HEADERS each), floored at 0, so a second of
  acknowledgements reads as nothing sent.
- **A destination is a `cell`:** the address's /24 and the port, as `queries.acr_cell` groups unnamed
  traffic. A client that moves among a provider's addresses stays in one series.
- **A connection first seen** counts its whole counters as that tick's; one whose counters went down was
  replaced by the kernel, and counts what the new entry holds.
- Addresses that are not public are left out: the gateway's, the home network's, multicast.

It holds everything in memory, keeps nothing, and asks the TV nothing.
"""

from __future__ import annotations

import ipaddress
import subprocess
import time
from dataclasses import dataclass

from tvgw.conntrack import counter, directions
from tvgw.names import is_public_address

TCP_HEADERS, UDP_HEADERS = 52, 28  # bytes of IP and transport header a packet carries (TCP with timestamps)
HEADERS = {"tcp": TCP_HEADERS, "udp": UDP_HEADERS}
TOTAL = "total"  # the series of everything the TV sent, beside the cells'
LISTING = ("conntrack", "-L", "-o", "extended", "-f", "ipv4", "-s")  # and the TV's address


@dataclass(frozen=True)
class Entry:
    """One connection as the table lists it: who to, and the counters of each direction."""

    proto: str
    src: str
    dst: str
    sport: int | None
    dport: int | None
    pkts_up: int
    bytes_up: int
    pkts_down: int
    bytes_down: int

    @property
    def key(self) -> tuple:
        return self.proto, self.src, self.dst, self.sport, self.dport


def parse_entry(line: str) -> Entry | None:
    """One line of `conntrack -L -o extended`; None for anything else. It never raises."""
    toks = line.split()
    try:
        fam = next(i for i, t in enumerate(toks) if t in ("ipv4", "ipv6"))
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
        )
    except (StopIteration, IndexError, ValueError):
        return None


def cell(dst: str, dport: int | None) -> str:
    """The destination a connection is counted under: `203.0.113.0/24:443`, a /48 for IPv6, and no port
    where the protocol has none."""
    address = ipaddress.ip_address(dst)
    net = ipaddress.ip_network((address, 24 if address.version == 4 else 48), strict=False)
    return f"{net}" if dport is None else f"{net}:{dport}"


def payload(proto: str, packets: int, octets: int) -> int:
    """What a direction carried beyond its packets' headers."""
    return max(0, octets - packets * HEADERS.get(proto, 0))


class Poll:
    """The TV's connections, read once a tick."""

    def __init__(self, tv_ip: str):
        self.tv_ip = tv_ip
        self.seen: dict[tuple, tuple[int, int]] = {}  # a connection -> its packets and bytes up, last tick
        self.unread = 0  # lines of the last listing that were no connection's

    def tick(self) -> dict[str, int]:
        """cell -> the payload the TV sent it since the last tick."""
        listed = subprocess.run([*LISTING, self.tv_ip], capture_output=True, text=True, check=False)
        sent: dict[str, int] = {}
        now: dict[tuple, tuple[int, int]] = {}
        self.unread = 0
        for line in listed.stdout.splitlines():
            entry = parse_entry(line)
            if entry is None:
                self.unread += bool(line.strip())
                continue
            if entry.src != self.tv_ip or not is_public_address(entry.dst):
                continue
            now[entry.key] = (entry.pkts_up, entry.bytes_up)
            packets, octets = self.seen.get(entry.key, (0, 0))
            if entry.pkts_up < packets or entry.bytes_up < octets:  # the kernel replaced the entry
                packets = octets = 0
            more = payload(entry.proto, entry.pkts_up - packets, entry.bytes_up - octets)
            if more:
                where = cell(entry.dst, entry.dport)
                sent[where] = sent.get(where, 0) + more
        self.seen = now
        return sent


clock, sleep = time.monotonic, time.sleep  # what `watch` tells the time by; a test stands in for both


def watch(poll: Poll, seconds: int) -> list[dict[str, int]]:
    """`seconds` ticks, one at each second of the clock, after a first that only takes the counters as
    they stand. A tick that ran late is followed at once by the next: the ticks stay `seconds` in number,
    and the caller compares the clock with them to know whether they were a second apart."""
    poll.tick()
    start = clock()
    ticks = []
    for second in range(1, seconds + 1):
        wait = start + second - clock()
        if wait > 0:
            sleep(wait)
        ticks.append(poll.tick())
    return ticks


def series(ticks: list[dict[str, int]]) -> dict[str, list[float]]:
    """The payload the TV sent each cell in each tick, and TOTAL, each as long as the run."""
    out: dict[str, list[float]] = {TOTAL: [0.0] * len(ticks)}
    for t, sent in enumerate(ticks):
        for where, octets in sent.items():
            out.setdefault(where, [0.0] * len(ticks))[t] += octets
            out[TOTAL][t] += octets
    return out
