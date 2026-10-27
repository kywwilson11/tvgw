"""The pcap directory as a store: which file tcpdump is writing (from a /proc tree), which are finished,
and which retention may delete."""

import os
from pathlib import Path

# bound at import, before the autouse `fake_live` fixture replaces the module attribute for ingest
from tvgw.pcaps import FREE_FLOOR, finished, live_files, prune


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
    assert (deleted, warnings) == ([], ["cannot tell which file tcpdump is writing; nothing deleted"])
    assert left(d) == ["tv-old.pcap"]
