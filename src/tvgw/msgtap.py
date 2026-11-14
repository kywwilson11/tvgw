"""(msgtap) The message tap's kernel (design decision 101): what the TV sends inside one connection,
rebuilt from packet headers alone. Pure: it opens no file, reads no clock and keeps nothing.

The smallest thing the record knows of a connection is its totals at its end (the flow log). A client
that uploads on a timer inside one long connection, to a server that answers as much as it gets, passes
every test that reads totals. Its uploads still cross the wire one by one, and a packet's header says
how much it carried. So a headers-only capture of the TV's packets that carry data is rebuilt here into
messages, and a fixed test asks whether one connection's uploads keep a steady beat and a steady size.

- **A packet** (`Packet`) is what such a capture keeps: its time, its flow (the TV's port, the server's
  address and port), its TCP sequence number, how much it carried, and its PSH flag.
- **A message** (`Message`) is a flow's run of data up to a PSH, or up to a silence of GAP. Packets are
  put in sequence order before a message closes, since a capture may hold a write's last segment before
  its fellows: read in the order they came, one write would be two messages. Bytes already counted (a
  retransmission) are not counted again, and neither is a hole filled after its message closed. A packet
  FAR_BEHIND what was counted starts the count again: it is the next connection on the same ports.
- **Memory is bounded:** MAX_FLOWS flows and MAX_HELD packets a flow. Past them the flow least recently
  heard from is closed, or the flow's packets are settled without waiting for the silence, and `Counts`
  says how often.
- **The test** (`cadence`) takes the uploads of FLOOR bytes or more and cuts each flow's time into fixed
  windows of WINDOW seconds from its first upload. A window is steady when it holds MIN_UPLOADS uploads
  or more, their median gap is within PERIOD, the gaps' spread (median absolute deviation over the
  median) is at most GAP_SPREAD and the sizes' is at most SIZE_SPREAD. IN_A_ROW steady windows in a row
  flag the flow. The windows are fixed so that the test is asked once per window: asked of every
  sliding window, as a first cut was, an hour offers about a hundred chances and a timer whose sizes vary
  passes one of them by chance.

`read_pcap` reads the capture: a classic pcap of Ethernet or Linux cooked frames. Anything that is not
an IPv4 TCP packet carrying data, or that was cut short before the TCP flags, is skipped and counted.
"""

from __future__ import annotations

import struct
from collections.abc import Iterable, Iterator
from dataclasses import dataclass
from itertools import groupby, pairwise
from statistics import median
from typing import BinaryIO

GAP = 0.25  # seconds of a flow's silence that close its message, PSH or not
MAX_FLOWS = 4_096  # flows held at once
MAX_HELD = 64  # packets a flow holds before they are settled without waiting for a silence
FLOOR = 8_000  # bytes: a smaller message is no upload here (requests, heartbeats, beacons)
WINDOW = 600.0  # seconds in each of the test's windows
MIN_UPLOADS = 12  # uploads a window needs before its gaps and sizes mean anything
PERIOD = (5.0, 60.0)  # seconds: the median gap of a steady window
GAP_SPREAD = 0.20  # the most the gaps may spread, median absolute deviation over the median
SIZE_SPREAD = 0.15  # the same for the sizes: a fingerprint is a digest of one size, a batch is not
IN_A_ROW = 2  # steady windows in a row that flag a flow

SEQ_SPAN = 1 << 32  # TCP sequence numbers wrap here
# bytes: a packet this far behind what was counted is no retransmission but the next connection on the same
# ports, whose first sequence number fell behind the last one's
FAR_BEHIND = 1 << 24
PSH = 0x08
PCAP_RECORD_MAX = 0xFFFF  # bytes: a record longer than this is no record of a headers-only capture
# a classic pcap's first four bytes: the byte order of its fields, and the unit of its fractions of a second
PCAP_MAGIC = {
    b"\xd4\xc3\xb2\xa1": ("<", 1e-6),
    b"\xa1\xb2\xc3\xd4": (">", 1e-6),
    b"\x4d\x3c\xb2\xa1": ("<", 1e-9),
    b"\xa1\xb2\x3c\x4d": (">", 1e-9),
}
# link type -> (where the frame names its protocol, where the IP header begins)
LINK_HEADERS = {1: (12, 14), 113: (14, 16)}  # Ethernet; Linux cooked capture

Flow = tuple[int, str, int]  # the TV's port, the server's address, the server's port


@dataclass(frozen=True, slots=True)
class Packet:
    t: float
    flow: Flow
    seq: int
    length: int  # payload bytes
    psh: bool


@dataclass(frozen=True, slots=True)
class Message:
    flow: Flow
    t_start: float
    t_end: float
    bytes: int
    packets: int


@dataclass(frozen=True, slots=True)
class Flag:
    """A flow whose uploads kept a steady beat and size for IN_A_ROW windows in a row: `t` is when the
    last of them ended, and `period` and `size` are its median gap and upload."""

    flow: Flow
    t: float
    period: float
    size: float


@dataclass
class Counts:
    records: int = 0  # records read from the capture
    skipped: int = 0  # of those, records that are no IPv4 TCP packet carrying data, or were cut short
    repeated: int = (
        0  # packets that added no byte: retransmissions, and a hole filled after its message closed
    )
    settled: int = 0  # times a flow's packets were settled at MAX_HELD, before a silence
    evicted: int = 0  # flows closed to keep MAX_FLOWS


class _Flow:
    """One flow's state: the packets held for ordering, the message they are building, and how far the
    sequence has been counted."""

    __slots__ = ("base", "bytes", "end", "held", "last", "packets", "raw", "seq", "start")

    def __init__(self, raw: int, t: float):
        self.raw = self.seq = raw  # the last sequence number as read, and as unwrapped
        self.base: int | None = None  # bytes before this unwrapped sequence number are counted
        self.held: list[tuple[int, float, int, bool]] = []
        self.last = t
        self.start = self.end = t
        self.bytes = self.packets = 0

    def unwrap(self, raw: int) -> int:
        """The sequence number on a line that does not wrap: the nearest to the last one read."""
        self.seq += (raw - self.raw + SEQ_SPAN // 2) % SEQ_SPAN - SEQ_SPAN // 2
        self.raw = raw
        return self.seq

    def settle(self, flow: Flow, counts: Counts, final: bool) -> Iterator[Message]:
        """Count the held packets in sequence order, closing a message after each PSH, and close the
        open one too when `final`."""
        self.held.sort()
        for seq, t, length, psh in self.held:
            if self.base is not None and self.base - seq > FAR_BEHIND:
                self.base = None
            new = seq if self.base is None or seq > self.base else self.base
            if seq + length <= new:
                counts.repeated += 1
                continue
            self.base = seq + length
            if self.packets:
                self.start, self.end = min(self.start, t), max(self.end, t)
            else:
                self.start = self.end = t
            self.bytes += seq + length - new
            self.packets += 1
            if psh:
                yield self.close(flow)
        self.held.clear()
        if final and self.packets:
            yield self.close(flow)

    def close(self, flow: Flow) -> Message:
        done = Message(flow, self.start, self.end, self.bytes, self.packets)
        self.bytes = self.packets = 0
        return done


def assemble(packets: Iterable[Packet], counts: Counts | None = None) -> Iterator[Message]:
    """The messages the packets carried, each flow's in order, as each closes. Linear: a packet is held
    at most until its flow's next silence, and a flow holds at most MAX_HELD."""
    counts = Counts() if counts is None else counts
    flows: dict[Flow, _Flow] = {}  # least recently heard from first: a packet moves its flow to the end
    for p in packets:
        f = flows.pop(p.flow, None)
        if f is None:
            if len(flows) >= MAX_FLOWS:
                counts.evicted += 1
                oldest = next(iter(flows))
                yield from flows.pop(oldest).settle(oldest, counts, final=True)
            f = _Flow(p.seq, p.t)
        elif p.t - f.last > GAP:
            yield from f.settle(p.flow, counts, final=True)
        flows[p.flow] = f
        f.last = p.t
        f.held.append((f.unwrap(p.seq), p.t, p.length, p.psh))
        if len(f.held) >= MAX_HELD:
            counts.settled += 1
            yield from f.settle(p.flow, counts, final=False)
    for flow, f in flows.items():
        yield from f.settle(flow, counts, final=True)


def _spread(xs: list[float]) -> float:
    """The median absolute deviation over the median, which is never 0 here: a gap's is asked only once it
    is within PERIOD, and a size's is FLOOR or more."""
    mid = median(xs)
    return median(abs(x - mid) for x in xs) / mid


def _steady(uploads: list[tuple[float, int]]) -> tuple[float, float] | None:
    """A window's median gap and size, when its uploads keep a steady beat and size; else None."""
    if len(uploads) < MIN_UPLOADS:
        return None
    gaps = [b - a for (a, _), (b, _) in pairwise(uploads)]
    sizes = [n for _, n in uploads]
    period = median(gaps)
    if not PERIOD[0] <= period <= PERIOD[1] or _spread(gaps) > GAP_SPREAD or _spread(sizes) > SIZE_SPREAD:
        return None
    return period, median(sizes)


def cadence(messages: Iterable[Message], window: float = WINDOW) -> list[Flag]:
    """The flows whose uploads kept a steady beat and size for IN_A_ROW fixed windows in a row, each
    flagged once, at the first such run, in the order they were flagged."""
    uploads: dict[Flow, list[tuple[float, int]]] = {}
    for m in messages:
        if m.bytes >= FLOOR:
            uploads.setdefault(m.flow, []).append((m.t_start, m.bytes))
    flags = []
    for flow, ups in uploads.items():
        ups.sort()
        origin = ups[0][0]
        streak, previous = 0, None
        for k, run in groupby(ups, key=lambda u: int((u[0] - origin) // window)):
            steady = _steady(list(run))
            # a window with no upload is not in the groups: the one before it is no longer in a row
            streak = (streak + 1 if previous == k - 1 else 1) if steady else 0
            previous = k
            if streak >= IN_A_ROW:
                flags.append(Flag(flow, origin + (k + 1) * window, *steady))
                break
    return sorted(flags, key=lambda f: (f.t, f.flow))


def read_pcap(stream: BinaryIO, counts: Counts | None = None) -> Iterator[Packet]:
    """The packets carrying data in a classic pcap of Ethernet or Linux cooked frames. A record that is no
    IPv4 TCP packet carrying data, or that ends before the TCP flags, is skipped and counted; a record cut
    short by the file's end ends the reading. ValueError when the file is no such pcap."""
    counts = Counts() if counts is None else counts
    head = stream.read(24)
    if len(head) < 24 or head[:4] not in PCAP_MAGIC:
        raise ValueError("not a classic pcap file")
    order, unit = PCAP_MAGIC[head[:4]]
    link = LINK_HEADERS.get(struct.unpack(order + "I", head[20:24])[0])
    if link is None:
        raise ValueError("the capture's frames are neither Ethernet nor Linux cooked")
    record = struct.Struct(order + "IIII")
    while header := stream.read(record.size):
        counts.records += 1
        if len(header) < record.size:
            counts.skipped += 1
            return
        sec, frac, kept, _wire = record.unpack(header)
        if kept > PCAP_RECORD_MAX or len(data := stream.read(kept)) < kept:
            counts.skipped += 1
            return
        p = _packet(data, link, sec + frac * unit)
        if p is None:
            counts.skipped += 1
        else:
            yield p


def _packet(data: bytes, link: tuple[int, int], t: float) -> Packet | None:
    """One frame's IPv4 TCP packet, if it carried data and its record reaches the TCP flags."""
    proto, ip = link
    if len(data) < ip + 20 or data[proto : proto + 2] != b"\x08\x00" or data[ip] >> 4 != 4:
        return None
    ihl = (data[ip] & 0x0F) * 4
    fragment = int.from_bytes(data[ip + 6 : ip + 8]) & 0x3FFF  # more fragments, or an offset
    tcp = ip + ihl
    if data[ip + 9] != 6 or ihl < 20 or fragment or len(data) < tcp + 14:
        return None
    length = int.from_bytes(data[ip + 2 : ip + 4]) - ihl - (data[tcp + 12] >> 4) * 4
    if length <= 0:
        return None
    sport, dport, seq = struct.unpack_from("!HHI", data, tcp)
    dst = ".".join(map(str, data[ip + 16 : ip + 20]))
    return Packet(t, (sport, dst, dport), seq, length, bool(data[tcp + 13] & PSH))
