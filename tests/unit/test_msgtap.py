"""(msgtap) The message tap (design decision 101): messages rebuilt from the headers of the TV's packets,
the fixed test of a steady beat, the pcap reader, and `tvgw experiment-tap`, whose capture is held in
memory and deleted whatever ends the run.

The classes are the proof of concept's (pass 6), each 400 seeded hours from acr_synth. LG's fingerprints
inside one connection are flagged, where the upload test that reads connection totals flags none of the
same hours; an app's own interface host and an analytics library's batches are not. The thresholds are
written out as numbers, not read from the module, so a changed threshold fails a test."""

import ast
import dataclasses
import fcntl
import io
import itertools
import json
import os
import random
import signal
import sqlite3
import struct
import sys
import threading
import time
from pathlib import Path
from types import SimpleNamespace

import acr_synth as synth
import pytest
from hypothesis import given, settings
from hypothesis import strategies as st

from tvgw import cli, db, msgtap, msgtaprun, queries
from tvgw.msgtap import Counts, Flag, Message, Packet

HOURS = 400
FLOW = (40_000, synth.TAP_SERVER, 443)
TV = "10.10.10.17"


def flagged_hours(connections, shuffled: bool = False, arrival_order: bool = False) -> int:
    """Of HOURS seeded hours of a class, those in which a flow is flagged. With `arrival_order` the
    sequence numbers are renumbered in the order the packets came: what an assembler that does not put
    them in sequence order would make of them."""
    rng, hits = random.Random(7), 0
    for _ in range(HOURS):
        packets = synth.tap_hour(rng, connections(rng), shuffled)
        if arrival_order:
            ahead: dict = {}
            for i, p in enumerate(packets):
                packets[i] = dataclasses.replace(p, seq=ahead.get(p.flow, 0))
                ahead[p.flow] = packets[i].seq + p.length
        hits += bool(msgtap.cadence(msgtap.assemble(packets)))
    return hits


def fingerprints(miss: float = 0.0):
    return lambda rng: [synth.acr_writes(rng, miss)]


# ---- the classes -----------------------------------------------------------------------------------------------
def test_fingerprints_inside_one_connection_are_flagged_where_the_test_of_totals_sees_nothing(tmp_path, lg):
    """The gap the tap closes: an upload every 14 s inside one connection on port 443, to a server that
    answers as much as it gets, under a name outside every category. Read as the connection's totals,
    all the upload test reads, no hour passes; read as messages, every hour is flagged."""
    assert flagged_hours(fingerprints()) >= 395
    conn = db.connect(str(tmp_path / "acr.db"))
    rng, start = random.Random(7), queries.day_bounds("2026-10-26")[0]
    synth.insert(
        conn, [synth.tap_flow(synth.acr_writes(rng), start + h * 3600, 30_000 + h) for h in range(HOURS)]
    )
    assert queries.acr_uploader(conn, start, start + HOURS * 3600, lg) == []


CLASSES = {  # an hour's connections, and how many of the HOURS may be flagged: at least, at most
    "a tenth of the fingerprints never sent": (fingerprints(0.10), 395, HOURS),
    "a quarter never sent": (fingerprints(0.25), 395, HOURS),
    "an app's own interface host": (synth.app_writes, 0, 0),
    "an analytics library's batches": (lambda rng: [synth.sdk_writes(rng)], 0, 4),
}


@pytest.mark.parametrize(("connections", "least", "most"), CLASSES.values(), ids=CLASSES)
def test_lost_fingerprints_are_still_flagged_and_an_app_or_a_batch_timer_is_not(connections, least, most):
    """The batch timer's bound pins a fault of the proof of concept's first cut, which asked the test of
    every sliding window: an hour holds about a hundred, and a timer whose sizes vary passed one of them
    by chance in 398 of 400 hours. The windows are fixed."""
    assert least <= flagged_hours(connections) <= most


def test_a_write_whose_psh_segment_came_first_is_one_message_because_packets_are_put_in_sequence_order():
    """The proof of concept's first generator drew each segment's moment apart, so a write's PSH segment
    often came before its fellows. Read in the order they came, such a write was two messages and the
    fingerprints went unflagged (in 396 of 400 hours there, all 400 here). In sequence order none is."""
    assert flagged_hours(fingerprints(), shuffled=True) >= 395
    assert flagged_hours(fingerprints(), shuffled=True, arrival_order=True) <= 4


# ---- assembling messages ---------------------------------------------------------------------------------------
def packet(t: float, seq: int, length: int = 100, psh: bool = False, flow=FLOW) -> Packet:
    return Packet(t, flow, seq % 2**32, length, psh)


def assembled(*packets: Packet, counts: Counts | None = None) -> list[tuple]:
    return [(m.t_start, m.t_end, m.bytes, m.packets) for m in msgtap.assemble(packets, counts)]


@pytest.mark.parametrize(
    ("packets", "messages"),
    [
        (
            [packet(0, 0), packet(0.001, 100, psh=True), packet(0.002, 200)],
            [(0, 0.001, 200, 2), (0.002, 0.002, 100, 1)],
        ),
        ([packet(0, 0), packet(0.2, 100), packet(0.4, 200)], [(0, 0.4, 300, 3)]),
        ([packet(0, 0), packet(0.25, 100)], [(0, 0.25, 200, 2)]),
        ([packet(0, 0), packet(0.25 + 1e-9, 100)], [(0, 0, 100, 1), (0.25 + 1e-9, 0.25 + 1e-9, 100, 1)]),
        ([packet(0, 100), packet(0.001, 200, psh=True), packet(0.002, 0)], [(0, 0.002, 300, 3)]),
        ([packet(0, -50), packet(0.001, 50, psh=True)], [(0, 0.001, 200, 2)]),
        ([packet(0, 0, psh=True), packet(1, 2**31 - 1, psh=True)], [(0, 0, 100, 1), (1, 1, 100, 1)]),
    ],
    ids=[
        "a psh closes it",
        "a silence counts from the last packet",
        "a silence of a quarter second does not close it",
        "a longer one does",
        "in sequence order, not as they came",
        "across the sequence's wrap",
        "a jump of under half the sequence is forward",
    ],
)
def test_a_message_is_a_flows_data_in_sequence_order_up_to_a_psh_or_a_silence(packets, messages):
    assert assembled(*packets) == messages


@pytest.mark.parametrize(
    ("again", "counted", "repeated"),
    [
        (packet(1, 0, psh=True), 100, 1),
        (packet(0.001, 0, psh=True), 100, 1),
        (packet(1, 50, psh=True), 150, 0),
        (packet(1, -1, length=1, psh=True), 100, 1),
        (packet(1, 100 - 2**24, psh=True), 100, 1),
        (packet(1, 99 - 2**24, psh=True), 200, 0),
    ],
    ids=[
        "a retransmission",
        "a copy in the same run",
        "an overlap counts what is new",
        "a byte before them",
        "16 MiB behind",
        "further behind is the next connection on the ports",
    ],
)
def test_bytes_already_counted_are_not_counted_again(again, counted, repeated):
    counts = Counts()
    messages = assembled(packet(0, 0, psh=True), again, counts=counts)
    assert sum(m[2] for m in messages) == counted and counts.repeated == repeated


def test_a_flow_that_never_pauses_holds_64_packets_at_most_and_its_write_stays_whole():
    counts = Counts()
    packets = [packet(i / 100, i * 100, psh=i == 191) for i in range(192)]
    assert assembled(*packets, counts=counts) == [(0, 1.91, 19_200, 192)] and counts.settled == 3


def test_past_4096_flows_the_flow_least_recently_heard_from_is_closed_first():
    counts = Counts()
    flows = [(port, synth.TAP_SERVER, 443) for port in range(4_097)]
    packets = [packet(0, 0, flow=flows[0]), *(packet(0.001, 0, flow=f) for f in flows[1:4_096])]
    packets += [packet(0.002, 100, flow=flows[0]), packet(0.003, 0, flow=flows[4_096])]
    messages = list(msgtap.assemble(packets, counts))
    assert messages[0].flow == flows[1] and len(messages) == 4_097 and counts.evicted == 1


packets_any = st.lists(
    st.builds(
        Packet,
        st.floats(-1e6, 1e6, allow_nan=False),
        st.tuples(st.integers(0, 3), st.just(synth.TAP_SERVER), st.just(443)),
        st.integers(0, 2**32 - 1),
        st.integers(-5, 70_000),
        st.booleans(),
    ),
    max_size=300,
)


@settings(max_examples=300, deadline=None)
@given(packets_any)
def test_assembling_never_raises_and_counts_each_packet_once(packets):
    counts = Counts()
    messages = list(msgtap.assemble(packets, counts))
    assert sum(m.packets for m in messages) + counts.repeated == len(packets)


@st.composite
def streams(draw) -> tuple[list[Packet], int]:
    """One flow's writes, each cut into segments that come within a millisecond of each other in any
    order, a write closer or further than a silence after the one before, and some segments sent again
    later."""
    t, seq, out, sent = 0.0, draw(st.integers(0, 2**32 - 1)), [], 0
    for _ in range(draw(st.integers(1, 8))):
        sizes = draw(st.lists(st.integers(1, 1_500), min_size=1, max_size=12))
        starts = list(itertools.accumulate([0, *sizes]))
        for k, i in enumerate(draw(st.permutations(range(len(sizes))))):
            out.append(packet(t + k * 1e-5, seq + starts[i], sizes[i], psh=i == len(sizes) - 1))
        seq, sent = seq + starts[-1], sent + starts[-1]
        t += draw(st.sampled_from([0.01, 0.5]))
    again = draw(st.lists(st.sampled_from(out), max_size=6))
    out += [dataclasses.replace(p, t=t + draw(st.floats(0, 1))) for p in again]
    return sorted(out, key=lambda p: p.t), sent


@settings(max_examples=300, deadline=None)
@given(streams())
def test_the_bytes_of_the_messages_are_the_distinct_bytes_sent(stream):
    packets, sent = stream
    assert sum(m.bytes for m in msgtap.assemble(packets)) == sent


def test_assembling_is_linear():
    """A packet waits at most for its flow's next silence, and a flow holds 64 at most: 200,000 packets
    take a fraction of a second, and a million took about one on the laptop."""
    rng = random.Random(3)
    hours = (synth.tap_hour(rng, [synth.acr_writes(rng)]) for _ in range(50))
    packets = [
        dataclasses.replace(p, t=p.t + 3600 * h, flow=(p.flow[0] + h, *p.flow[1:]))
        for h, hour in enumerate(hours)
        for p in hour
    ][:200_000]
    start = time.process_time()
    assert sum(m.packets for m in msgtap.assemble(packets)) == 200_000
    assert time.process_time() - start < 2.0


# ---- the test of a steady beat -----------------------------------------------------------------------------
def beat(
    gaps: list[float], sizes: list[int], windows: int = 2, start: float = 1_000.0, flow=FLOW
) -> list[Message]:
    """`windows` windows of 10 minutes from `start`, each opening with an upload and holding uploads
    `gaps` apart of `sizes` bytes."""
    times = list(itertools.accumulate([0.0, *gaps]))
    return [
        Message(flow, start + w * 600 + t, start + w * 600 + t, n, 16)
        for w in range(windows)
        for t, n in zip(times, sizes, strict=True)
    ]


STEADY = ([10.0] * 11, [20_000] * 12)  # twelve uploads 10 s apart, of one size
UNSTEADY = ([10.0] * 11, [9_000, 30_000] * 6)


def test_a_steady_beat_is_flagged_once_two_windows_after_its_first_upload_in_whatever_order_it_is_read():
    messages = beat(*STEADY, windows=3)
    random.Random(1).shuffle(messages)
    assert msgtap.cadence(messages) == [Flag(FLOW, 1_000.0 + 1_200, 10.0, 20_000)]


def test_the_flag_carries_the_median_gap_and_size_not_the_mean():
    messages = beat([9.0] * 3 + [10.0] * 5 + [13.0] * 3, [19_000] * 3 + [20_000] * 6 + [23_000] * 3)
    assert [(f.period, f.size) for f in msgtap.cadence(messages)] == [(10.0, 20_000)]


@pytest.mark.parametrize(
    ("gaps", "sizes", "steady"),
    [
        ([50.0] * 11, [20_000] * 12, True),
        ([54.6] * 10, [20_000] * 11, False),
        ([5.0] * 11, [20_000] * 12, True),
        ([4.9] * 11, [20_000] * 12, False),
        ([60.0, 1.0] * 5 + [60.0], [20_000] * 12, True),
        ([60.5, 1.0] * 5 + [60.5], [20_000] * 12, False),
        ([8.0] * 3 + [10.0] * 5 + [12.0] * 3, [20_000] * 12, True),
        ([7.9375] * 3 + [10.0] * 5 + [12.0625] * 3, [20_000] * 12, False),
        ([10.0] * 11, [17_000] * 4 + [20_000] * 4 + [23_000] * 4, True),
        ([10.0] * 11, [16_999] * 4 + [20_000] * 4 + [23_001] * 4, False),
        ([10.0] * 11, [8_000] * 12, True),
        ([10.0] * 11, [7_999] * 12, False),
    ],
    ids=[
        "twelve uploads",
        "eleven",
        "a median gap of 5 s",
        "of 4.9 s",
        "of 60 s",
        "of 60.5 s",
        "gaps that spread 0.20",
        "more",
        "sizes that spread 0.15",
        "more",
        "uploads of 8,000 bytes",
        "a byte less is no upload",
    ],
)
def test_a_window_is_steady_with_enough_uploads_a_median_gap_in_range_and_little_spread(gaps, sizes, steady):
    assert bool(msgtap.cadence(beat(gaps, sizes))) is steady


@pytest.mark.parametrize(
    ("windows", "flagged_at"),
    [
        ([STEADY], None),
        ([STEADY, None, STEADY], None),
        ([STEADY, UNSTEADY], None),
        ([UNSTEADY, STEADY, STEADY], 3),
        ([STEADY, UNSTEADY, STEADY, STEADY], 4),
    ],
    ids=[
        "one window",
        "two, an empty one between",
        "one, then an unsteady one",
        "two after an unsteady one",
        "two after a break",
    ],
)
def test_it_takes_two_steady_windows_in_a_row(windows, flagged_at):
    messages = [m for w, shape in enumerate(windows) if shape for m in beat(*shape, 1, 1_000.0 + w * 600)]
    assert [f.t for f in msgtap.cadence(messages)] == (
        [] if flagged_at is None else [1_000.0 + flagged_at * 600]
    )


def test_each_flow_is_judged_alone_and_the_flags_come_in_the_order_they_were_raised():
    late, early = (40_001, "203.0.113.71", 443), (40_002, "203.0.113.72", 4431)
    messages = beat(*STEADY, start=5_000.0, flow=late) + beat(*STEADY, flow=early)
    messages.append(Message(FLOW, 1_000.0, 1_000.0, 50_000, 40))
    assert [f.flow for f in msgtap.cadence(messages)] == [early, late]


# ---- reading the capture ---------------------------------------------------------------------------------------
def frame(
    seq=7,
    payload=1_448,
    flags=0x18,
    proto=6,
    version=4,
    ihl=5,
    frag=0x4000,
    ether=b"\x08\x00",
    link=1,
    options=12,
    snap=54,
) -> bytes:
    """A frame of the TV's to FLOW as dumpcap keeps it: the link's header, IPv4, TCP with `options` bytes of
    options (12: timestamps) and `payload` bytes of a TLS record, cut at `snap` bytes."""
    tcp = struct.pack("!HHIIBBHHH", FLOW[0], FLOW[2], seq, 0, (5 + options // 4) << 4, flags, 501, 0, 0)
    tcp += bytes(options)
    total = ihl * 4 + len(tcp) + payload
    addresses = bytes(map(int, TV.split("."))) + bytes(map(int, FLOW[1].split(".")))
    ip = struct.pack("!BBHHHBBH", version << 4 | ihl, 0, total, 1, frag, 64, proto, 0) + addresses
    head = bytes(12 if link == 1 else 14) + ether
    carried = (b"\x17\x03\x03\x40\x00" + bytes(payload))[:payload]
    return (head + ip + bytes(max(0, ihl * 4 - 20)) + tcp + carried)[:snap]


# a classic pcap's first four bytes, and the byte order and unit of second they say: written out here, so
# that the reader's own table is checked and not copied
MAGICS = {
    b"\xd4\xc3\xb2\xa1": ("<", 1e-6),
    b"\xa1\xb2\xc3\xd4": (">", 1e-6),
    b"\x4d\x3c\xb2\xa1": ("<", 1e-9),
    b"\xa1\xb2\x3c\x4d": (">", 1e-9),
}


def pcap(frames: list[bytes], link: int = 1, magic: bytes = b"\xd4\xc3\xb2\xa1", times=None) -> bytes:
    """A classic pcap of the frames, at `times` or one a second from 1,800,000,000 and half a millisecond."""
    order, unit = MAGICS[magic]
    out = magic + struct.pack(order + "HHiIII", 2, 4, 0, 0, 71, link)
    for f, t in zip(frames, times or (1_800_000_000.0005 + i for i in itertools.count()), strict=False):
        out += struct.pack(order + "IIII", int(t), round((t - int(t)) / unit), len(f), len(f) + 1_000) + f
    return out


def read(data: bytes) -> tuple[list[Packet], Counts]:
    counts = Counts()
    return list(msgtap.read_pcap(io.BytesIO(data), counts)), counts


@pytest.mark.parametrize("options", [0, 12], ids=["no tcp options", "timestamps"])
@pytest.mark.parametrize("link", [1, 113], ids=["ethernet", "linux cooked"])
@pytest.mark.parametrize("magic", MAGICS, ids=["le-us", "be-us", "le-ns", "be-ns"])
def test_a_data_packet_is_read_from_its_headers_and_its_length_from_ip_not_from_what_was_kept(
    link, magic, options
):
    """Its 54 bytes: an Ethernet frame without TCP options has nothing past them but what it carries."""
    data = frame(seq=2**32 - 1, payload=22_000, link=link, options=options)
    assert len(frame(payload=0, options=0, snap=10_000)) == 54
    packets, counts = read(pcap([data], link, magic))
    assert packets == [Packet(pytest.approx(1_800_000_000.0005, abs=1e-6), FLOW, 2**32 - 1, 22_000, True)]
    assert counts == Counts(records=1)


def test_what_is_no_ipv4_tcp_packet_carrying_data_is_skipped_and_counted():
    skipped = [
        frame(payload=0, flags=0x10),
        frame(proto=17),
        frame(ether=b"\x86\xdd"),
        frame(version=6),
        frame(ihl=4),
        frame(frag=0x2000),
        frame(frag=0x0001),
        frame(snap=14 + 20 + 13),
        frame(snap=14 + 9),
    ]
    packets, counts = read(pcap([frame(flags=0x10), *skipped, frame(snap=14 + 20 + 14)]))
    assert [p.psh for p in packets] == [False, True] and counts == Counts(records=11, skipped=9)


@pytest.mark.parametrize("cut", [54 + 7, 4], ids=["in a record's header", "in its frame"])
def test_a_capture_cut_short_is_read_up_to_the_cut(cut):
    packets, counts = read(pcap([frame(), frame()])[:-cut])
    assert len(packets) == 1 and counts == Counts(records=2, skipped=1)


@pytest.mark.parametrize(("kept", "packets"), [(0xFFFF, 2), (0x10000, 1)], ids=["65,535 bytes", "65,536"])
def test_a_record_longer_than_any_headers_capture_ends_the_reading(kept, packets):
    data = pcap([frame()]) + struct.pack("<IIII", 1, 0, kept, kept) + bytes(kept) + pcap([frame()])[24:]
    got, counts = read(data)
    assert len(got) == packets and counts == Counts(records=packets + 1, skipped=1)


@pytest.mark.parametrize(
    "data",
    [
        b"",
        b"\xd4\xc3\xb2\xa1" + bytes(10),
        b"\x0a\x0d\x0d\x0a" + bytes(40),
        pcap([], link=127),
        pcap([], link=276),
    ],
    ids=["empty", "a header cut short", "pcapng", "radiotap", "cooked, second version"],
)
def test_a_file_that_is_no_classic_pcap_of_ethernet_or_cooked_frames_is_refused(data):
    with pytest.raises(ValueError):
        read(data)


# ---- the shadow run --------------------------------------------------------------------------------------------
STUB = """#!{python}
import json, os, signal, sys, time
argv = sys.argv
with open(os.environ["TAP_ARGV"], "w") as said:
    json.dump(argv, said)
with open(os.environ["TAP_SOURCE"], "rb") as src, open(argv[argv.index("-w") + 1], "wb") as out:
    out.write(src.read())
mode = os.environ["TAP_MODE"]
if mode == "fail":
    sys.exit("dumpcap: There are no interfaces on which a capture can be done.")
if mode == "silent":
    sys.exit(1)
if mode in ("SIGTERM", "SIGHUP"):
    os.kill(os.getppid(), getattr(signal, mode))
    time.sleep(60)
print("Packets received/dropped on interface 'tv0': 1441/3 (pcap:3/dumpcap:0/flushed:0) (99.8%)", file=sys.stderr)
"""


def fingerprint_frames(
    uploads: int = 90, every: float = 14.0, size: int = 22_000
) -> tuple[list[bytes], list[float]]:
    """A fingerprint every `every` seconds, each cut into full segments, PSH on the last."""
    frames, times = [], []
    for k in range(uploads):
        for off in range(0, size, 1_448):
            n = min(1_448, size - off)
            frames.append(frame(seq=k * size + off, payload=n, flags=0x18 if off + n == size else 0x10))
            times.append(1_800_000_000 + k * every + off / 1e6)
    return frames, times


class Gateway:
    """RUN_DIR under a directory the mounts call a tmpfs (`mounts` None: no mount table to read), a stub
    dumpcap that says what it was asked, copies a capture into place and then does what `mode` says, the
    TV port's counter, 1 GB of free memory, and clocks that move as a 20-minute run's would."""

    def __init__(self, tmp_path: Path, monkeypatch, mode: str = "", capture: bytes | None = None):
        frames, times = fingerprint_frames()
        source = tmp_path / "source.pcap"
        ack = frame(payload=0, flags=0x10)
        source.write_bytes(
            pcap([*frames, ack], times=[*times, times[-1] + 1]) if capture is None else capture
        )
        self.dumpcap, self.argv = tmp_path / "dumpcap", tmp_path / "argv.json"
        self.dumpcap.write_text(STUB.format(python=sys.executable), encoding="utf-8")
        self.dumpcap.chmod(0o755)
        for key, value in (("TAP_SOURCE", source), ("TAP_ARGV", self.argv), ("TAP_MODE", mode)):
            monkeypatch.setenv(key, str(value))
        monkeypatch.setattr(
            msgtaprun.os, "statvfs", lambda path: SimpleNamespace(f_bavail=1_000_000, f_frsize=1_000)
        )
        monkeypatch.setattr(msgtaprun, "clock", iter([100.0, 1_300.5]).__next__)
        monkeypatch.setattr(msgtaprun, "cpu_time", iter([10.0, 10.75]).__next__)
        monkeypatch.setattr(msgtaprun, "_children_cpu", iter([1.0, 3.5]).__next__)
        (tmp_path / "run").mkdir()
        self.run_dir = tmp_path / "run" / "tvgw-exp"
        self.mounts = f"/dev/sda2 / ext4 rw 0 0\ntmpfs {os.path.realpath(tmp_path / 'run')} tmpfs rw 0 0\n"
        self.counter = ["1000\n", "4321\n"]
        self.tmp_path = tmp_path

    def read(self, path: str) -> str:
        if path == "/proc/self/mounts" and self.mounts is not None:
            return self.mounts
        if path == msgtaprun.RX_COUNTER.format("tv0") and self.counter:
            return self.counter.pop(0)
        raise FileNotFoundError(path)

    def run(self, conn=None, euid: int = 0) -> msgtaprun.Result:
        dumpcap, run_dir = str(self.dumpcap), str(self.run_dir)
        return msgtaprun.run(
            20, "tv0", TV, conn, run_dir=run_dir, dumpcap=dumpcap, euid=lambda: euid, read=self.read
        )

    def files(self) -> set[Path]:
        return set(self.tmp_path.rglob("*")) - {self.argv}

    def unlocked(self) -> bool:
        fd = os.open(self.run_dir, os.O_RDONLY)
        try:
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            return True
        except BlockingIOError:
            return False
        finally:
            os.close(fd)


def test_a_run_rebuilds_the_capture_names_the_server_flags_its_beat_and_leaves_nothing_behind(
    tmp_path, monkeypatch
):
    gateway = Gateway(tmp_path, monkeypatch)
    conn = db.connect(str(tmp_path / "tvgw.db"))
    conn.execute(
        "INSERT INTO tls(t, dst, dport, sport, sni) VALUES (1, ?, 443, ?, ?)",
        (FLOW[1], FLOW[0], synth.TAP_NAME),
    )
    conn.commit()
    gateway.run_dir.mkdir(mode=0o755)
    gateway.run_dir.chmod(0o755)  # as another hand may have left it
    before = gateway.files()
    result = gateway.run(conn)
    assert gateway.files() == before and not any(gateway.run_dir.iterdir())
    assert gateway.run_dir.stat().st_mode & 0o777 == 0o700
    assert json.loads(gateway.argv.read_text()) == msgtaprun.dumpcap_argv(
        str(gateway.dumpcap), "tv0", TV, 20, 500_000, str(gateway.run_dir / "tap.pcap")
    )
    [row] = result.rows
    assert row == msgtaprun.Row(synth.TAP_NAME, 443, 90, 90 * 22_000, 22_000, row.flags) and result.flagged
    assert [(f.period, f.size) for f in row.flags] == [(14.0, 22_000)]
    assert (result.data_packets, result.counts.skipped, result.received, result.dropped) == (
        1_440,
        1,
        3_321,
        3,
    )
    assert (result.seconds, result.cpu_capture, result.cpu_rebuild) == (1_200.5, 2.5, 0.75)


@pytest.mark.parametrize("counter", [["1000\n"], ["?\n", "4321\n"]], ids=["after", "before"])
def test_a_counter_that_cannot_be_read_is_no_count(tmp_path, monkeypatch, counter):
    gateway = Gateway(tmp_path, monkeypatch)
    gateway.counter = counter
    assert gateway.run().received is None


def refused(match: str):
    return pytest.raises(msgtaprun.TapError, match=match)


def broken(messages):
    raise RuntimeError("a fault in the rebuild")


@pytest.mark.parametrize(
    ("mode", "capture", "breaks", "raised"),
    [
        ("fail", None, False, refused(r"dumpcap failed \(exit 1\): dumpcap: There are no interfaces")),
        ("silent", None, False, refused(r"dumpcap failed \(exit 1\): no message")),
        ("SIGTERM", None, False, pytest.raises(msgtaprun.Stopped, match="SIGTERM")),
        ("SIGHUP", None, False, pytest.raises(msgtaprun.Stopped, match="SIGHUP")),
        ("", b"not a capture", False, refused("the capture could not be read: not a classic pcap")),
        ("", None, True, pytest.raises(RuntimeError, match="the rebuild")),
    ],
    ids=[
        "dumpcap fails",
        "and says nothing",
        "a SIGTERM",
        "a SIGHUP",
        "a capture that cannot be read",
        "a fault in the rebuild",
    ],
)
def test_whatever_ends_a_run_its_capture_is_deleted_dumpcap_stopped_and_the_signals_and_lock_given_back(
    tmp_path, monkeypatch, mode, capture, breaks, raised
):
    gateway = Gateway(tmp_path, monkeypatch, mode, capture)
    if breaks:
        monkeypatch.setattr(msgtaprun.msgtap, "cadence", broken)
    handlers = [signal.getsignal(s) for s in msgtaprun.STOPS]
    start = time.monotonic()
    with raised:
        gateway.run()
    assert time.monotonic() - start < 30  # dumpcap was stopped, not waited for
    assert not any(gateway.run_dir.iterdir()) and gateway.unlocked()
    assert [signal.getsignal(s) for s in msgtaprun.STOPS] == handlers


def test_a_second_signal_during_the_deletion_waits_until_the_file_is_gone(tmp_path, monkeypatch):
    gateway = Gateway(tmp_path, monkeypatch)
    capture, seen, unlink = gateway.run_dir / msgtaprun.CAPTURE, [], os.unlink

    def signalled(path):
        signal.pthread_kill(threading.main_thread().ident, signal.SIGTERM)
        unlink(path)

    previous = signal.signal(signal.SIGTERM, lambda *_: seen.append(capture.exists()))
    try:
        monkeypatch.setattr(msgtaprun.os, "unlink", signalled)
        gateway.run()
    finally:
        signal.signal(signal.SIGTERM, previous)
    assert seen == [False]


def test_a_run_refuses_without_root_off_tmpfs_beside_another_run_and_without_dumpcap(tmp_path, monkeypatch):
    gateway = Gateway(tmp_path, monkeypatch)
    with refused("needs root"):
        gateway.run(euid=1000)
    assert not gateway.run_dir.exists()
    gateway.mounts = "/dev/sda2 / ext4 rw 0 0\n"
    with refused("not on tmpfs"):
        gateway.run()
    gateway.mounts = None
    with refused("not on tmpfs"):  # no mount table says it is memory
        gateway.run()
    gateway.mounts = f"tmpfs {os.path.realpath(tmp_path / 'run')} tmpfs rw 0 0\n"
    other = gateway.run_dir / msgtaprun.CAPTURE
    other.write_bytes(b"another run's capture")
    held = os.open(gateway.run_dir, os.O_RDONLY)
    try:
        fcntl.flock(held, fcntl.LOCK_EX)
        with refused("another run of the tap is capturing"):
            gateway.run()
        assert other.read_bytes() == b"another run's capture"  # left to the run that holds it
    finally:
        os.close(held)
    gateway.dumpcap.unlink()
    with refused("dumpcap could not start"):
        gateway.run()
    assert not any(gateway.run_dir.iterdir())  # and a capture left behind goes with the next run


def test_dumpcap_keeps_the_tvs_data_packets_headers_into_the_run_directory_until_either_stop():
    assert msgtaprun.dumpcap_argv("/usr/bin/dumpcap", "tv0", TV, 30, 1_000, "/run/tvgw-exp/tap.pcap") == [
        "/usr/bin/dumpcap", "-i", "tv0", "-q", "-P", "-s", "54",
        "-f", f"src host {TV} and tcp and (ip[2:2] - ((ip[0]&0xf)<<2) - ((tcp[12]&0xf0)>>2)) > 0",
        "-a", "duration:1800", "-a", "filesize:1000", "-w", "/run/tvgw-exp/tap.pcap",
    ]  # fmt: skip


@pytest.mark.parametrize(
    ("mounts", "tmpfs"),
    [
        ("tmpfs /run tmpfs rw 0 0\n/dev/sda2 / ext4 rw 0 0", True),
        ("/dev/sda2 / ext4 rw 0 0\n/dev/sda3 /run/tvgw-exp ext4 rw 0 0\ntmpfs /run tmpfs rw 0 0", False),
        ("tmpfs /run tmpfs rw 0 0\n/dev/sda3 /run ext4 rw 0 0", False),
        ("/dev/sda2 / ext4 rw 0 0\ntmpfs /ru tmpfs rw 0 0", False),
        ("tmpfs / tmpfs rw 0 0\nnone /run", True),
        ("", False),
    ],
    ids=[
        "under /run",
        "a disk mounted over it",
        "a disk mounted over /run later",
        "a mount whose name is a prefix",
        "the root",
        "no mounts",
    ],
)
def test_the_run_directory_is_on_tmpfs_when_the_mount_that_holds_it_is(mounts, tmpfs):
    assert msgtaprun.on_tmpfs("/run/tvgw-exp", mounts) is tmpfs


def test_a_mount_point_with_a_space_is_read_as_the_kernel_writes_it():
    assert msgtaprun.on_tmpfs("/run x/tvgw-exp", "tmpfs /run\\040x tmpfs rw 0 0")


@pytest.mark.parametrize(("free", "stop"), [(10**10, 1_000_000), (10**9, 500_000), (1_999, 0)])
def test_a_capture_stops_at_about_a_gigabyte_or_at_half_the_free_memory(free, stop):
    assert msgtaprun.size_stop(free) == stop


def test_a_flow_is_named_by_its_latest_hello_else_by_its_servers_slash_24(tmp_path):
    conn = db.connect(str(tmp_path / "tvgw.db"))
    conn.executemany(
        "INSERT INTO tls(t, dst, dport, sport, sni) VALUES (?, ?, ?, ?, ?)",
        [(1, FLOW[1], 443, FLOW[0], "old.example.com"), (2, FLOW[1], 443, FLOW[0], "new.example.com"),
         (3, FLOW[1], 4431, FLOW[0], "other.port.example.com")],
    )  # fmt: skip
    unnamed = (40_001, FLOW[1], 443)
    assert msgtaprun.names(conn, [FLOW, unnamed]) == {FLOW: "new.example.com", unnamed: "203.0.113.0/24"}
    assert msgtaprun.names(None, [FLOW]) == {FLOW: "203.0.113.0/24"}
    assert msgtaprun.names(sqlite3.connect(":memory:"), [FLOW]) == {FLOW: "203.0.113.0/24"}  # no tls table


def test_one_pass_keeps_each_flows_totals_and_its_uploads_and_the_rows_add_up_a_name_and_port():
    second, other_port = (40_001, FLOW[1], 443), (40_002, FLOW[1], 4431)
    sent = [(second, 30_000), (FLOW, 9_000), (FLOW, 7_999), (other_port, 50_000), (FLOW, 8_000)]
    messages = [Message(f, 0, 0, n, 7) for f, n in sent]
    totals, uploads = msgtaprun.tally(messages)
    assert totals == {second: [1, 30_000, 30_000], FLOW: [3, 24_999, 9_000], other_port: [1, 50_000, 50_000]}
    assert uploads == [messages[i] for i in (0, 1, 3, 4)]  # the test reads nothing under 8,000 bytes
    flag = Flag(second, 1_200.0, 14.0, 30_000)
    assert msgtaprun.rows(totals, [flag], dict.fromkeys(totals, "a.example.com")) == [
        msgtaprun.Row("a.example.com", 443, 4, 54_999, 30_000, (flag,)),
        msgtaprun.Row("a.example.com", 4431, 1, 50_000, 50_000),
    ]


# ---- the command -----------------------------------------------------------------------------------------------
def command(monkeypatch, tmp_path, outcome, root: bool = True, minutes: str = "20") -> int:
    def run(minutes, tv_if, tv_ip, conn):
        assert (minutes, tv_if, tv_ip, conn) == (20, "eth0", TV, None)  # no store: the servers go unnamed
        if isinstance(outcome, BaseException):
            raise outcome
        return outcome

    monkeypatch.setattr(cli.os, "geteuid", lambda: 0 if root else 1000)
    monkeypatch.setattr(msgtaprun, "run", run)
    conf = tmp_path / "tvgw.conf"
    conf.write_text(f"TV_IP={TV}\n", encoding="utf-8")
    return cli.main(
        ["--conf", str(conf), "--db", str(tmp_path / "none.db"), "experiment-tap", "--minutes", minutes]
    )


def result(flags=()) -> msgtaprun.Result:
    rows = [
        msgtaprun.Row(synth.TAP_NAME, 443, 90, 1_980_000, 22_000, flags),
        msgtaprun.Row("203.0.113.0/24", 4431, 3, 900, 300),
    ]
    return msgtaprun.Result(1_200.4, rows, Counts(records=1_441, skipped=1, evicted=2), 3_321, 3, 0.25, 0.5)


def test_the_command_prints_the_counts_the_cost_and_a_row_a_server_and_exits_1_on_a_steady_beat(
    monkeypatch, tmp_path, capsys
):
    assert command(monkeypatch, tmp_path, result([Flag(FLOW, 1_200.0, 14.0, 22_000)])) == 1
    out = capsys.readouterr().out.splitlines()
    assert out[:6] == [
        "Starting a capture of 20 minutes, held in memory and deleted at the end.",
        "The capture ran 20.0 minutes and is deleted: nothing was kept.",
        "Packets the TV sent with data: 1,440 (1 records skipped).",
        "Packets the TV's port received, every protocol: 3,321. Dropped by the kernel: 3.",
        "CPU seconds: 0.2 capturing, 0.5 rebuilding.",
        "2 flows were closed early to bound memory: a message of theirs may be split.",
    ]
    assert out[6].split() == ["Server", "Port", "Messages", "Bytes", "up", "Largest", "Steady", "beat"]
    assert out[7].split() == [synth.TAP_NAME, "443", "90", "1.9M", "21.5K", "every", "14.0", "s,", "21.5K"]
    assert out[8].split() == ["203.0.113.0/24", "4431", "3", "900B", "300B"]


def test_a_run_of_20_minutes_with_no_steady_beat_exits_0_and_counts_it_could_not_read_say_so(
    monkeypatch, tmp_path, capsys
):
    done = dataclasses.replace(
        result(), seconds=1_200.0, received=None, dropped=None, counts=Counts(records=5)
    )
    assert command(monkeypatch, tmp_path, done) == 0
    out = capsys.readouterr().out
    assert "received, every protocol: not read. Dropped by the kernel: not said." in out
    assert "closed early" not in out


@pytest.mark.parametrize(
    ("done", "said"),
    [
        (dataclasses.replace(result(), counts=Counts()), "Nothing is concluded: the TV sent no data."),
        (
            dataclasses.replace(result(), seconds=1_199.9),
            "Nothing is concluded: a steady beat takes 20 minutes to show.",
        ),
    ],
    ids=["no data", "under 20 minutes"],
)
def test_a_run_that_could_not_have_flagged_a_beat_says_so_after_its_table_and_exits_2(
    monkeypatch, tmp_path, capsys, done, said
):
    assert command(monkeypatch, tmp_path, done) == 2
    got = capsys.readouterr()
    assert got.err.strip() == said and "Server" in got.out


STOPPED = "The run was stopped and its capture deleted. Nothing is concluded."


@pytest.mark.parametrize(
    ("outcome", "root", "said"),
    [
        (result(), False, "the capture needs root: sudo tvgw experiment-tap"),
        (msgtaprun.TapError("/run/tvgw-exp is not on tmpfs"), True, "is not on tmpfs. Nothing is concluded."),
        (msgtaprun.Stopped("SIGTERM"), True, STOPPED),
        (KeyboardInterrupt(), True, STOPPED),
    ],
    ids=["without root", "a refusal", "a stop", "Ctrl-C"],
)
def test_a_run_that_concludes_nothing_says_why_and_exits_2(
    monkeypatch, tmp_path, capsys, outcome, root, said
):
    assert command(monkeypatch, tmp_path, outcome, root) == 2
    got = capsys.readouterr()
    assert said in got.err and "Server" not in got.out


@pytest.mark.parametrize("minutes", ["0", "481", "an evening"])
def test_a_run_is_1_to_480_minutes(monkeypatch, tmp_path, capsys, minutes):
    with pytest.raises(SystemExit) as stopped:
        command(monkeypatch, tmp_path, result(), minutes=minutes)
    assert stopped.value.code == 2 and "a whole number from 1 to 480" in capsys.readouterr().err


def test_only_the_shadow_run_imports_the_kernel_and_only_the_command_line_imports_the_run():
    """The tap is an experiment: nothing that decides, refuses or keeps may read its messages yet."""
    importers: dict[str, set[str]] = {"msgtap": set(), "msgtaprun": set()}
    for path in Path(msgtap.__file__).parent.glob("*.py"):
        for node in ast.walk(ast.parse(path.read_text(encoding="utf-8"))):
            names = [a.name for a in node.names] if isinstance(node, ast.Import | ast.ImportFrom) else []
            module = getattr(node, "module", None) or ""
            for name in importers:
                if f"tvgw.{name}" in [*names, module] or (module == "tvgw" and name in names):
                    importers[name].add(path.stem)
    assert importers == {"msgtap": {"msgtaprun"}, "msgtaprun": {"cli"}}
