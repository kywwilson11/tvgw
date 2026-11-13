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
"""

from __future__ import annotations

import contextlib
import glob
import os
import shutil
import time
from collections.abc import Callable
from typing import NamedTuple

FREE_FLOOR = 1 << 30  # bytes that must stay free where the pcaps live, whatever the budget allows
# the process names (/proc/<pid>/comm) that write pcaps here: dumpcap since capture v2, tcpdump before
# it. tcpdump stays in the set for the deploy that switches (the package is installed before
# install.sh restarts the unit, so for a few seconds the new ingest runs beside the old tcpdump) and
# for a Pi rolled back to an older checkout, which runs tcpdump again
WRITERS = frozenset({"dumpcap", "tcpdump"})


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


def prune(
    pcap_dir: str,
    deletable: set[str],
    days: int,
    max_bytes: int,
    live: set[str] | None,
    now: float | None = None,
    disk_free: Callable[[str], int] = _free_bytes,
    doomed: frozenset[str] = frozenset(),
) -> tuple[list[str], list[str]]:
    """Delete the finished pcaps the store has read (`deletable`, by name) once they are older than
    `days`, then the oldest of them while the directory is over `max_bytes` or the filesystem under
    FREE_FLOOR. A file the store has not read is kept and reported, and goes only at twice `days`:
    a broken ingest costs a week of warnings before it costs evidence. A file `tvgw forget` named
    (`doomed`: it was open, so forget could not delete it) goes as soon as it is finished and read,
    whatever its age. The live file is never touched, and when it cannot be told apart nothing is.
    Returns (deleted names, warnings)."""
    if live is None:
        return [], ["cannot tell which file the capture is writing; nothing deleted"]
    now = time.time() if now is None else now
    files = _finished_files(pcap_dir, live)
    deleted: list[str] = []
    warnings: list[str] = []

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
