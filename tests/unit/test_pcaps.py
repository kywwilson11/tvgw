"""The pcap directory as a store: which file the capture is writing (from a /proc tree), which are finished,
and which retention may delete."""

import calendar
import os
import time
from collections.abc import Callable
from pathlib import Path

import pytest

from tvgw import cli, config, db, pcaps
from tvgw.config import Settings

# bound at import, before the autouse `fake_live` fixture replaces the module attribute for ingest
from tvgw.pcaps import FREE_FLOOR, Ring, finished, live_files, prune


def test_finished_excludes_the_live_file_and_sorts_by_name(tmp_path):
    for name in ("tv-b.pcap", "tv-a.pcap", "tv-c.pcap"):
        (tmp_path / name).write_bytes(b"")
    (tmp_path / "notes.txt").write_text("not a capture")
    live = {os.path.realpath(tmp_path / "tv-b.pcap")}
    assert finished(str(tmp_path), live) == [str(tmp_path / "tv-a.pcap"), str(tmp_path / "tv-c.pcap")]
    assert finished(str(tmp_path), set()) == [str(tmp_path / f"tv-{x}.pcap") for x in "abc"]


def fake_proc(root: Path, processes: dict[str, tuple[str, dict[str, str]]]) -> str:
    """A /proc tree: pid -> (comm, {fd: link target}), plus the entries that are not processes."""
    for pid, (comm, fds) in processes.items():
        (root / pid / "fd").mkdir(parents=True)
        (root / pid / "comm").write_text(comm + "\n")
        for fd, target in fds.items():
            os.symlink(target, root / pid / "fd" / fd)
    (root / "self").mkdir(parents=True)
    (root / "meminfo").write_text("")
    return str(root)


def test_live_files_are_the_pcaps_in_the_directory_that_a_tcpdump_holds_open(tmp_path):
    pcap_dir, elsewhere = tmp_path / "pcap", tmp_path / "elsewhere"
    pcap_dir.mkdir()
    elsewhere.mkdir()
    proc = fake_proc(
        tmp_path / "proc",
        {
            "100": (
                "tcpdump",
                {
                    "0": "/dev/null",
                    "3": str(pcap_dir / "tv-live.pcap"),
                    "4": str(elsewhere / "other.pcap"),  # another capture in another directory
                    "5": f"{pcap_dir / 'tv-gone.pcap'} (deleted)",  # pruned under tcpdump: still being written
                    "6": "socket:[12345]",
                    "7": str(pcap_dir / "notes.txt"),
                },
            ),
            "200": ("bash", {"3": str(pcap_dir / "tv-read-by-a-shell.pcap")}),  # a reader, not the writer
            "300": ("tcpdump", {}),  # a second capture with nothing open yet
        },
    )
    (tmp_path / "proc" / "400").mkdir()  # ended between the listing and the read: no comm file
    assert live_files(str(pcap_dir), proc=proc) == {
        os.path.realpath(pcap_dir / "tv-live.pcap"),
        os.path.realpath(pcap_dir / "tv-gone.pcap"),
    }


def test_live_files_is_unknown_when_a_tcpdumps_descriptors_cannot_be_listed(tmp_path, monkeypatch):
    proc = fake_proc(tmp_path / "proc", {"100": ("tcpdump", {})})
    real_listdir = os.listdir

    def denied(path):
        if str(path).endswith(os.path.join("100", "fd")):
            raise PermissionError(13, "Permission denied", str(path))
        return real_listdir(path)

    monkeypatch.setattr(os, "listdir", denied)
    assert live_files(str(tmp_path / "pcap"), proc=proc) is None


def test_live_files_is_unknown_without_proc(tmp_path):
    assert live_files(str(tmp_path), proc=str(tmp_path / "no-proc")) is None


# ---- retention -----------------------------------------------------------------------------------
NOW = 1_800_000_000.0
DAY = 86400.0
WEEK = 7 * DAY


def pcap_dir(tmp_path: Path, files: dict[str, tuple[float, int]]) -> str:
    """A pcap directory: name -> (age in seconds at NOW, size in bytes)."""
    d = tmp_path / "pcap"
    d.mkdir()
    for name, (age, size) in files.items():
        (d / name).write_bytes(bytes(size))
        os.utime(d / name, (NOW - age, NOW - age))
    return str(d)


def plenty(_path: str) -> int:
    return 10 * FREE_FLOOR


def left(d: str) -> list[str]:
    return sorted(os.listdir(d))


def test_the_live_file_is_never_deleted_even_alone_and_over_budget(tmp_path):
    d = pcap_dir(tmp_path, {"tv-live.pcap": (30 * DAY, 5000)})
    live = {os.path.realpath(os.path.join(d, "tv-live.pcap"))}
    assert prune(d, {"tv-live.pcap"}, 7, 1000, live, now=NOW, disk_free=plenty) == ([], [])
    assert left(d) == ["tv-live.pcap"]


def test_age_is_measured_exactly_against_pcap_days(tmp_path):
    """The bash `find -mtime +7` deleted a file aged 8.01 days but kept one aged 7.99."""
    d = pcap_dir(tmp_path, {"tv-older.pcap": (WEEK + 60, 10), "tv-younger.pcap": (WEEK - 60, 10)})
    deleted, warnings = prune(
        d, {"tv-older.pcap", "tv-younger.pcap"}, 7, 10**9, set(), now=NOW, disk_free=plenty
    )
    assert (deleted, warnings) == (["tv-older.pcap"], [])
    assert left(d) == ["tv-younger.pcap"]


def test_a_file_ingest_has_not_read_is_kept_and_reported_until_twice_pcap_days(tmp_path):
    d = pcap_dir(tmp_path, {"tv-unread.pcap": (WEEK + 60, 10), "tv-forgotten.pcap": (2 * WEEK + 60, 10)})
    deleted, warnings = prune(d, set(), 7, 10**9, set(), now=NOW, disk_free=plenty)
    assert deleted == ["tv-forgotten.pcap"]
    assert warnings == [
        "tv-forgotten.pcap: never ingested, deleted at twice PCAP_DAYS",
        "1 finished pcap(s) older than PCAP_DAYS kept: not ingested yet",
    ]
    assert left(d) == ["tv-unread.pcap"]


def test_over_budget_deletes_the_oldest_ingested_file_first_and_never_an_unread_one(tmp_path):
    d = pcap_dir(
        tmp_path,
        {
            "tv-old-read.pcap": (3 * DAY, 600),
            "tv-mid-unread.pcap": (2 * DAY, 600),
            "tv-new-read.pcap": (DAY, 600),
        },
    )
    deletable = {"tv-old-read.pcap", "tv-new-read.pcap"}
    deleted, warnings = prune(d, deletable, 7, 1000, set(), now=NOW, disk_free=plenty)
    assert (deleted, warnings) == (["tv-old-read.pcap", "tv-new-read.pcap"], [])
    assert left(d) == ["tv-mid-unread.pcap"]


def test_over_budget_with_only_unread_files_is_a_warning_not_a_deletion(tmp_path):
    d = pcap_dir(tmp_path, {"tv-a.pcap": (2 * DAY, 600), "tv-b.pcap": (DAY, 600)})
    deleted, warnings = prune(d, set(), 7, 1000, set(), now=NOW, disk_free=plenty)
    assert deleted == [] and warnings == [
        "pcaps over PCAP_MAX_GB by 0 MB with nothing ingested left to delete"
    ]
    assert left(d) == ["tv-a.pcap", "tv-b.pcap"]


def test_the_free_space_floor_deletes_ingested_files_oldest_first(tmp_path):
    d = pcap_dir(tmp_path, {f"tv-{n}.pcap": (n * 3600, 100) for n in (1, 2, 3)})
    free = iter([FREE_FLOOR - 1, FREE_FLOOR - 1, FREE_FLOOR])

    def disk_free(_path):
        return next(free)

    deleted, warnings = prune(
        d, {"tv-1.pcap", "tv-2.pcap", "tv-3.pcap"}, 7, 10**9, set(), now=NOW, disk_free=disk_free
    )
    assert (deleted, warnings) == (["tv-3.pcap", "tv-2.pcap"], [])  # the oldest two
    assert left(d) == ["tv-1.pcap"]
    deleted, warnings = prune(d, set(), 7, 10**9, set(), now=NOW, disk_free=lambda p: FREE_FLOOR - 1)
    assert deleted == [] and warnings == [
        "under 1 GB free where the pcaps live, with nothing ingested left to delete"
    ]


def test_without_knowing_the_live_file_nothing_is_deleted(tmp_path):
    d = pcap_dir(tmp_path, {"tv-old.pcap": (30 * DAY, 10)})
    deleted, warnings = prune(d, {"tv-old.pcap"}, 7, 1, None, now=NOW, disk_free=lambda p: 0)
    assert (deleted, warnings) == ([], ["cannot tell which file the capture is writing; nothing deleted"])
    assert left(d) == ["tv-old.pcap"]


# ---- (edges) the capture's own ring (design decision 108) ---------------------------------------------
MIB = 2**20


@pytest.mark.parametrize(
    ("max_gb", "days", "ring"),
    [
        (1.5, 7, Ring(170, 9252)),  # the reference: 7 days of hours and two, about 9 MB each
        (0.01, 7, Ring(170, 1024)),  # a file is never cut below 1 MB
        (1.5, 5000, Ring(99_999, 1024)),  # dumpcap keeps fewer than 100,000 files
        (10_000, 1, Ring(26, 2_000_000)),  # nor files of 2 GB
    ],
)
def test_the_ring_holds_pcap_days_of_hours_and_cuts_a_file_at_its_share_of_the_cap(max_gb, days, ring):
    assert pcaps.ring(max_gb, days) == ring
    assert ring.env() == f"PCAP_RING_FILES={ring.files} PCAP_RING_KB={ring.filesize_kb}"


@pytest.mark.parametrize("days", [1, 7, 30])
@pytest.mark.parametrize("max_gb", [0.75, 1.5, 7.3, 40])
def test_the_ring_holds_the_cap_to_the_last_kb(max_gb, days):
    files, kb = pcaps.ring(max_gb, days)
    assert files * kb * 1024 <= max_gb * 2**30 < files * (kb + 1) * 1024


def ring_file(stamp: str, number: int, prefix: str = "tv") -> str:
    return f"{prefix}_{stamp}_{number:05d}.pcap"


def stamp(t: float) -> str:
    return time.strftime("%Y%m%d%H%M%S", time.gmtime(t))


HOURS = [stamp(NOW - h * 3600) for h in range(48, -1, -1)]  # two days of hours, oldest first


@pytest.mark.parametrize(
    ("names", "lost"),
    [
        ([ring_file(HOURS[i], i + 1) for i in range(10)], 0),  # every hour there
        ([ring_file(HOURS[i], i + 1) for i in (0, 1, 5, 6)], 3),  # 3 to 5 gone mid-run
        ([ring_file(HOURS[i], i + 1) for i in (6, 5, 1, 0)], 3),  # in any order: the names are a set
        ([ring_file(HOURS[0], 40), ring_file(HOURS[1], 1), ring_file(HOURS[2], 2)], 0),  # a restart
        ([ring_file(HOURS[0], 40), ring_file(HOURS[1], 7), ring_file(HOURS[2], 8)], 6),  # its first six gone
        ([ring_file(HOURS[0], 1), ring_file(HOURS[1], 3), ring_file(HOURS[0], 9, "tvhdr")], 1),  # by prefix
        ([ring_file(HOURS[0], 2), ring_file(HOURS[1], 1), ring_file(HOURS[1], 3)], 1),  # a stamp shared
        ([ring_file(HOURS[0], 99_999), ring_file(HOURS[1], 0)], 0),  # dumpcap's number wraps
        (["tv-20261101T120000Z.pcap", "tv-20261101T150000Z.pcap", "notes.txt"], 0),  # tcpdump's names
    ],
)
def test_a_number_missing_from_the_ring_is_a_file_gone_before_it_was_read(names, lost):
    assert pcaps.overwritten(names, NOW, 3 * DAY) == lost


def test_a_gap_older_than_the_stores_memory_of_reads_is_not_counted():
    """A read file's mark goes from the store a week after the file: a hole that old may be read files."""
    old = [ring_file(HOURS[0], 1), ring_file(HOURS[3], 4)]
    assert pcaps.overwritten(old, NOW, 48 * 3600) == 2
    assert pcaps.overwritten(old, NOW, 48 * 3600 - 1) == 0  # the file before the gap opened earlier


def gone(n: int) -> str:
    return (
        f"{n} pcap(s) were gone before ingest read them: the capture's ring overwrote them in a flood, or"
        " they were deleted by hand"
    )


def test_prune_counts_what_the_ring_overwrote_from_the_disk_the_live_file_and_the_stores_marks(tmp_path):
    d = pcap_dir(tmp_path, {ring_file(HOURS[i], i + 1): ((48 - i) * 3600, 10) for i in (4, 6)})
    live = {os.path.realpath(os.path.join(d, ring_file(HOURS[6], 7)))}  # 6 went before the live 7
    marks = frozenset(ring_file(HOURS[i], i + 1) for i in (0, 1))  # read, and pruned since: 3 and 4 went
    assert prune(d, set(), 7, 10**9, live, now=NOW, disk_free=plenty, marked=marks) == ([], [gone(3)])
    assert prune(d, set(marks), 7, 10**9, live, now=NOW, disk_free=plenty)[1] == [gone(3)]
    assert prune(d, set(), 7, 10**9, live, now=NOW, disk_free=plenty)[1] == [
        gone(1)
    ]  # nothing known before 5


def test_prune_counts_no_further_back_than_twice_pcap_days(tmp_path):
    """With PCAP_DAYS=1 prune deletes an unread file at 2 days, with a warning of its own: a gap older
    than that is no news of the ring."""
    d = pcap_dir(tmp_path, {ring_file(stamp(NOW - 60), 10): (60, 10)})
    marks = frozenset((ring_file(stamp(NOW - 3 * DAY), 1), ring_file(stamp(NOW - 3 * DAY + 3600), 3)))
    live = {os.path.realpath(os.path.join(d, ring_file(stamp(NOW - 60), 10)))}
    assert prune(d, set(), 7, 10**9, live, now=NOW, disk_free=plenty, marked=marks)[1] == [gone(7)]
    assert prune(d, set(), 1, 10**9, live, now=NOW, disk_free=plenty, marked=marks) == ([], [])


def test_the_prune_command_reads_every_mark_in_the_store_and_writes_none(tmp_path, monkeypatch, capsys):
    """A file ingest tried and failed on is a file it saw: its name is no gap. The store is opened read-only."""
    d = pcap_dir(tmp_path, {ring_file(HOURS[3], 4): (45 * 3600, 10)})
    store = str(tmp_path / "tvgw.db")
    conn = db.connect(store)
    conn.executemany(
        "INSERT INTO pcaps_done(name, done_at, error, attempts) VALUES (?, ?, ?, ?)",
        [(ring_file(HOURS[0], 1), NOW, None, 1), (ring_file(HOURS[1], 2), NOW, "tshark failed", 1)],
    )
    conn.commit()
    conn.close()
    monkeypatch.setattr(config, "load", lambda path, **kw: Settings(pcap_dir=d, db_path=store))
    opened = []
    real = db.connect
    monkeypatch.setattr(db, "connect", lambda path, **kw: opened.append(kw) or real(path, **kw))
    assert cli.main(["prune-pcaps"]) == 1
    assert capsys.readouterr().err == f"tvgw prune-pcaps: WARNING {gone(1)}\n"  # 3, never seen
    assert opened == [{"readonly": True}]


def test_the_ring_command_prints_the_units_drop_in_line(tmp_path, capsys):
    conf = tmp_path / "tvgw.conf"
    conf.write_text("PCAP_DAYS=3\nPCAP_MAX_GB=0.5\n", encoding="utf-8")
    assert cli.main(["--conf", str(conf), "pcap-ring"]) == 0
    assert capsys.readouterr().out == "PCAP_RING_FILES=74 PCAP_RING_KB=7084\n"  # 0.5 GB / 74, in KB


class Dumpcap:
    """dumpcap's ring as the capture units run it (ringbuffer.c): a new file on each hour of the clock and
    as soon as the open one reaches the ring's file size, numbered from 00001, and the run's oldest file
    removed as the one past the ring's length opens. Files are sparse: only their size and time matter,
    and `files` holds both for every file on disk. `lost` names each file it removed before the ingest had
    read it (`read`)."""

    def __init__(self, d: str, ring: Ring, t: float, read: set[str]):
        self.d, self.ring, self.read = d, ring, read
        self.run: list[str] = []
        self.lost: list[str] = []
        self.files: dict[str, tuple[int, float]] = {}  # name -> (size, mtime)
        self.opened = 0
        self.open(t)

    @property
    def live(self) -> str:
        return os.path.join(self.d, self.run[-1])

    def open(self, t: float) -> None:
        self.opened += 1
        self.hour, self.size = int(t // 3600), 0
        self.run.append(ring_file(stamp(t), self.opened))
        self.touch(t)
        if len(self.run) > self.ring.files:
            gone = self.run.pop(0)
            if gone not in self.read:
                self.lost.append(gone)
            if self.files.pop(gone, None) is not None:  # retention may have deleted it first
                os.unlink(os.path.join(self.d, gone))

    def touch(self, t: float) -> None:
        with open(self.live, "ab") as fh:
            fh.truncate(self.size)
        os.utime(self.live, (t, t))
        self.files[self.run[-1]] = (self.size, t)

    def write(self, t: float, size: int) -> None:
        """`size` bytes captured at `t`, after the hour's turn if the clock passed one."""
        if int(t // 3600) != self.hour:
            self.open(t - t % 3600)
        cap = self.ring.filesize_kb * 1024
        while size:
            take = min(size, cap - self.size)
            self.size, size = self.size + take, size - take
            self.touch(t)
            if self.size >= cap:
                self.open(t)


def run_gateway(tmp_path: Path, days: float, rate: Callable[[float], float], prune_every: int = 900):
    """The reference's capture, ingest and retention on a simulated clock from 2026-11-01 00:00 UTC, in
    steps of 5 minutes: the capture writes `rate(t)` bytes a second, the hourly ingest reads every
    finished file at five past the hour, and prune runs every `prune_every` seconds. Yields (the time,
    the capture, prune's warnings, the files it deleted with their age then) at each prune."""
    d = tmp_path / "pcap"
    d.mkdir()
    read: set[str] = set()
    t = t0 = calendar.timegm((2026, 11, 1, 0, 0, 0))
    cap = Dumpcap(str(d), pcaps.ring(1.5, 7), t0, read)
    while t < t0 + days * DAY:
        t += 300
        cap.write(t, int(rate(t) * 300))
        if t % 3600 == 300:
            read.update(os.path.basename(p) for p in finished(str(d), {cap.live}))
        if t % prune_every == 0:
            deleted, warnings = prune(
                str(d), set(read), 7, int(1.5 * 2**30), {cap.live}, now=t, disk_free=plenty
            )
            assert os.path.exists(cap.live)  # never the live file
            yield t, cap, warnings, {name: t - cap.files.pop(name)[1] for name in deleted}


def ordinary(t: float) -> float:
    """The reference's hours, as its capture directory held them: most 0.1 MB, the largest 0.8 MB."""
    return (0.8 if int(t // 3600) % 24 == 20 else 0.1) * MIB / 3600


def test_on_an_ordinary_week_every_hour_is_read_before_the_ring_turns_and_prune_keeps_pcap_days(tmp_path):
    """The package's first ring (256 MB files, PCAP_MAX_GB / 256 MB = 6 of them) kept 6 hours where
    retention keeps 7 days. Sized from both settings, the ring turns on the hour, holds 170 of them, and
    loses nothing; prune deletes only files past PCAP_DAYS, and says nothing."""
    for _, cap, warnings, deleted in run_gateway(tmp_path, 8, ordinary):
        assert warnings == [] and cap.lost == []
        assert all(age > 7 * DAY for age in deleted.values())
    assert len(os.listdir(tmp_path / "pcap")) == 7 * 24 + 1  # a week of hours and the live one
    assert cap.opened == 8 * 24 + 1 and len(cap.run) == 170  # the ring itself reaches two hours further


def test_a_flood_fills_the_ring_not_the_disk_and_prune_counts_what_it_overwrote(tmp_path):
    """The live file had no limit: 100 Mbit/s for an hour is 43.9 GB in one file. Now dumpcap cuts a file
    at its share of PCAP_MAX_GB and keeps 170 of them, so the directory never holds more than PCAP_MAX_GB
    and one file; prune counts the files the ring overwrote before the ingest read them, for as long as
    the store remembers a read (7 days), and then stops."""
    start, end = calendar.timegm((2026, 11, 1, 14, 10, 0)), calendar.timegm((2026, 11, 1, 14, 30, 0))
    cut = pcaps.ring(1.5, 7).filesize_kb * 1024

    def rate(t: float) -> float:
        return 100e6 / 8 if start < t <= end else ordinary(t)

    said = {}
    for t, cap, warnings, _ in run_gateway(tmp_path, 8, rate):
        assert sum(size for size, _ in cap.files.values()) <= 1.5 * 2**30 + cut
        said[t] = warnings
    assert len(cap.lost) > 1400  # 20 minutes cut into about 1,580 files, and 170 stayed
    after = sorted(t for t in said if said[t])
    assert said[end + DAY] == [
        f"{len(cap.lost)} pcap(s) were gone before ingest read them: the capture's ring overwrote them in"
        " a flood, or they were deleted by hand"
    ]
    # from the first prune after the ring turned, until 7 days after the last hour read before the flood
    assert start < after[0] <= end and after[-1] == calendar.timegm((2026, 11, 8, 13, 0, 0))
