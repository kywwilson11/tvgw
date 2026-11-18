"""The pcap directory as a store: which files the capture has finished with, and which may go.

The capture is dumpcap (tvgw-pcap.service, or tvgw-pcap-headers.service with CAPTURE_MODE=headers),
and was tcpdump until capture v2; both write pcap files into one directory, an hour each, and the
ingest reads each file once. A file is finished when no capture process (`WRITERS`) holds it open,
read from /proc. That answer is exact without a naming convention or a rename hook, so the tcpdump
names (`tv-20261101T120000Z.pcap`) and dumpcap's (`tv_20261101120000_00001.pcap`) are told apart by
nothing, and it stays right when the capture is down (every file is finished) or a clock step
reorders names. dumpcap closes the old file before it opens the next one, so at a rotation there is
a moment when it holds none; the ingest lists the directory before it asks /proc, so a file that
appears in that moment is not in its listing. Listing another process's descriptors needs root,
which ingest has on the gateway; where the answer cannot be had, callers get None and must not guess,
because reading a file the capture is still writing would record half an hour as a whole one, and
deleting it would lose the hour.

Retention (`prune`) sees the same answer and the store's marks: it deletes evidence only once the
store has it, or after a week of saying that it does not.

(edges) The writer bounds itself as well (design decision 108): dumpcap keeps a ring of `ring()` files,
so a flood that fills a file in seconds cannot fill the disk between two prunes. On a normal day each
file is an hour and the ring holds more hours than PCAP_DAYS keeps; under a flood files turn on size,
the ring overwrites its oldest, and `prune` counts the ones that went before ingest read them.
"""

from __future__ import annotations

import contextlib
import glob
import os
import re
import shutil
import time
from collections.abc import Callable, Iterable
from typing import NamedTuple

FREE_FLOOR = 1 << 30  # bytes that must stay free where the pcaps live, whatever the budget allows
# the process names (/proc/<pid>/comm) that write pcaps here: dumpcap since capture v2, tcpdump before
# it. tcpdump stays in the set for the deploy that switches (the package is installed before
# install.sh restarts the unit, so for a few seconds the new ingest runs beside the old tcpdump) and
# for a Pi rolled back to an older checkout, which runs tcpdump again
WRITERS = frozenset({"dumpcap", "tcpdump"})
# (edges) the ring: twice PCAP_DAYS of hourly files, plus the live one and one spare. Twice, because
# prune keeps an unread file that long: a stopped ingest must cost a fortnight of warnings, as before,
# and never a file the ring removes unread and unsaid
RING_SPARE = 2
# a file is cut at no less than 1 MB (the reference gateway's largest hour is 0.8 MB): a small PCAP_MAX_GB
# must not turn an ordinary hour into many files, each one more run of tshark for the ingest
RING_FLOOR_KB = 1024
# dumpcap's own bounds: a ring of fewer than 100,000 files (RINGBUFFER_MAX_NUM_FILES), and a file size
# kept under 2 GB whether it counts a kB as 1,000 or 1,024 bytes
DUMPCAP_FILES_MAX = 99_999
DUMPCAP_KB_MAX = 2_000_000
# a ring file's name under -b nametimenum:2: the -w prefix, the UTC time it was opened, its number in the run
RING_NAME = re.compile(r"(?P<prefix>.+)_(?P<stamp>\d{14})_(?P<number>\d{5})\.pcap")
# how long the store keeps a read file's mark once the file is gone (the 7 days in ingest.prune)
MARKS_KEPT = 7 * 86400


def live_files(pcap_dir: str, proc: str = "/proc") -> set[str] | None:
    """Realpaths of the `.pcap` files in `pcap_dir` that a capture process (one of `WRITERS`) holds
    open, or None when that cannot be told (no /proc, or a capture whose descriptors we may not list).
    Only the writers are asked: a reader such as tshark holds a finished file open too, and listing
    every process's descriptors would make the answer depend on processes we may not inspect."""
    here = os.path.realpath(pcap_dir)
    try:
        pids = [p for p in os.listdir(proc) if p.isdigit()]
    except OSError:
        return None
    live: set[str] = set()
    for pid in pids:
        try:
            with open(os.path.join(proc, pid, "comm"), encoding="utf-8", errors="replace") as fh:
                if fh.read().strip() not in WRITERS:
                    continue
            fds = os.listdir(os.path.join(proc, pid, "fd"))
        except PermissionError:
            return None
        except OSError:  # the process ended between the listing and the read
            continue
        for fd in fds:
            try:
                target = os.readlink(os.path.join(proc, pid, "fd", fd))
            except OSError:
                continue
            path = os.path.realpath(target.removesuffix(" (deleted)"))
            if os.path.dirname(path) == here and path.endswith(".pcap"):
                live.add(path)
    return live


def finished(pcap_dir: str, live: set[str]) -> list[str]:
    """The `.pcap` paths in `pcap_dir` that no capture is writing, sorted by name."""
    return sorted(p for p in glob.glob(os.path.join(pcap_dir, "*.pcap")) if os.path.realpath(p) not in live)


class _File(NamedTuple):
    mtime: float
    size: int
    path: str

    @property
    def name(self) -> str:
        return os.path.basename(self.path)


def _finished_files(pcap_dir: str, live: set[str]) -> list[_File]:
    out = []
    for path in finished(pcap_dir, live):
        with contextlib.suppress(FileNotFoundError):  # gone since the listing: not ours to prune
            st = os.stat(path)
            out.append(_File(st.st_mtime, st.st_size, path))
    return sorted(out)  # oldest first


def _free_bytes(path: str) -> int:
    return shutil.disk_usage(path).free


class Ring(NamedTuple):
    """dumpcap's `-b files:` and `-b filesize:` for the capture units."""

    files: int
    filesize_kb: int

    def env(self) -> str:
        """The Environment= assignments install.sh writes into both capture units' drop-ins."""
        return f"PCAP_RING_FILES={self.files} PCAP_RING_KB={self.filesize_kb}"


def ring(max_gb: float, days: int) -> Ring:
    """The ring for PCAP_MAX_GB and PCAP_DAYS: twice PCAP_DAYS of hourly files plus RING_SPARE, each cut
    at an equal share of PCAP_MAX_GB. An ordinary hour stays far below that share, so the ring turns on
    the hour and holds longer than retention keeps any file, read or not; a flood turns it on size, and
    the ring then holds at most PCAP_MAX_GB. The share is in units of 1,024 bytes: a dumpcap that counts a
    kB as 1,000 bytes cuts each file a little smaller, and the ring stays within the cap either way."""
    files = min(2 * days * 24 + RING_SPARE, DUMPCAP_FILES_MAX)
    share = int(max_gb * 2**30) // files // 1024
    return Ring(files, min(max(share, RING_FLOOR_KB), DUMPCAP_KB_MAX))


def overwritten(names: Iterable[str], now: float, window: float) -> int:
    """How many ring files went before ingest read them, from the gaps in the ring's numbers. `names` are
    the files on disk and the files the store has a mark for. dumpcap numbers a run's files from 00001 in
    the order it opens them and starts again at every start. In time order, a file belongs to the run
    whose last number is the largest below its own, or starts a run: a capture that restarted with its
    clock behind still sorts into its own run, not into a gap of the one before. A file opened after
    another closes after it, so its mark, had it been read, would be in the store as long as the file
    before it opened less than `window` seconds before `now`. Each number missing after such a file is a
    file never read: in the middle of a run, or at the start of a new one."""
    runs: dict[str, list[tuple[str, int]]] = {}
    for name in names:
        if m := RING_NAME.fullmatch(name):
            runs.setdefault(m["prefix"], []).append((m["stamp"], int(m["number"])))
    since = time.strftime("%Y%m%d%H%M%S", time.gmtime(now - window))  # the names' own UTC stamps
    lost = 0
    for files in runs.values():
        ends: list[tuple[int, str]] = []  # each run's last number so far, and when that file opened
        prior = ""  # when the file before this one, in time, opened; "" sorts before every stamp
        for stamp, number in sorted(files):
            fits = [i for i, (last, _) in enumerate(ends) if last < number]
            if fits:
                i = max(fits, key=lambda i: ends[i][0])
                before, opened = ends[i]
                missing = number - before - 1
            else:  # a start, its files before this one gone; or the number wrapped
                i, opened, missing = len(ends), prior, max(number - 1, 0)
                ends.append((0, ""))
            if opened >= since:
                lost += missing
            ends[i] = (number, stamp)
            prior = stamp
    return lost


def prune(
    pcap_dir: str,
    deletable: set[str],
    days: int,
    max_bytes: int,
    live: set[str] | None,
    now: float | None = None,
    disk_free: Callable[[str], int] = _free_bytes,
    doomed: frozenset[str] = frozenset(),
    marked: frozenset[str] = frozenset(),
) -> tuple[list[str], list[str]]:
    """Delete the finished pcaps the store has read (`deletable`, by name) once they are older than
    `days`, then the oldest of them while the directory is over `max_bytes` or the filesystem under
    FREE_FLOOR. A file the store has not read is kept and reported, and goes only at twice `days`:
    a broken ingest costs a week of warnings before it costs evidence. A file `tvgw forget` named
    (`doomed`: it was open, so forget could not delete it) goes as soon as it is finished and read,
    whatever its age. The live file is never touched, and when it cannot be told apart nothing is.
    (edges) Files the capture's ring overwrote before ingest read them are counted in a warning, from
    the names on disk and every name the store has a mark for (`marked`), over the span in which the
    store still holds a read file's mark and prune itself deletes no unread file.
    Returns (deleted names, warnings)."""
    if live is None:
        return [], ["cannot tell which file the capture is writing; nothing deleted"]
    now = time.time() if now is None else now
    files = _finished_files(pcap_dir, live)
    deleted: list[str] = []
    warnings: list[str] = []
    on_disk = {f.name for f in files} | {os.path.basename(p) for p in live}
    lost = overwritten(on_disk | deletable | marked, now, min(MARKS_KEPT, 2 * days * 86400))
    if lost:
        warnings.append(
            f"{lost} pcap(s) were gone before ingest read them: the capture's ring overwrote them in a"
            " flood, or they were deleted by hand"
        )

    def delete(f: _File) -> None:
        os.unlink(f.path)
        files.remove(f)
        deleted.append(f.name)

    def oldest_deletable() -> _File | None:
        return next((f for f in files if f.name in deletable), None)

    unread = 0
    for f in list(files):
        age = now - f.mtime
        if f.name in doomed and f.name in deletable:
            delete(f)
            continue
        if age <= days * 86400:
            continue
        if f.name in deletable:
            delete(f)
        elif age > 2 * days * 86400:
            delete(f)
            warnings.append(f"{f.name}: never ingested, deleted at twice PCAP_DAYS")
        else:
            unread += 1
    if unread:
        warnings.append(f"{unread} finished pcap(s) older than PCAP_DAYS kept: not ingested yet")
    while (over := sum(f.size for f in files) - max_bytes) > 0:
        if (f := oldest_deletable()) is None:
            warnings.append(
                f"pcaps over PCAP_MAX_GB by {over / 2**20:.0f} MB with nothing ingested left to delete"
            )
            break
        delete(f)
    while disk_free(pcap_dir) < FREE_FLOOR:
        if (f := oldest_deletable()) is None:
            warnings.append("under 1 GB free where the pcaps live, with nothing ingested left to delete")
            break
        delete(f)
    return deleted, warnings
