"""A daily, checked copy of the store beside it.

`VACUUM INTO` writes a fresh, compact copy while ingest may be running (SQLite's online copy is safe
under the rollback journal), `PRAGMA quick_check` on the copy decides whether it gets its name, and
one copy per UTC day stays for the newest `keep` days, plus the newest copy. A copy is the whole
viewing history and is protected like the original: 640, the state directory's group. A card failure
takes the original and the copies with it; `make backup` pulls them to another machine.
"""

from __future__ import annotations

import contextlib
import os
import sqlite3
import time
from dataclasses import dataclass

NAME = "tvgw-%Y%m%dT%H%M%SZ.db"  # UTC, sortable, never repeats in the fall-back hour
PREFIX, SUFFIX = "tvgw-", ".db"


@dataclass(frozen=True)
class Backup:
    path: str
    size: int
    kept: list[str]  # names now in the directory, oldest first
    removed: list[str]


def _quick_check(path: str) -> list[str]:
    conn = sqlite3.connect(f"file:{path}?mode=ro", uri=True)
    try:
        return [r[0] for r in conn.execute("PRAGMA quick_check")]
    finally:
        conn.close()


def run(db_path: str, backup_dir: str, keep: int = 7, now: float | None = None) -> Backup:
    """Copy `db_path` into `backup_dir`, check the copy, rotate: the first copy of each of the newest
    `keep` UTC days and the copy just made stay. Raises on a copy that does not check out (nothing is
    left behind) and on any I/O or SQLite error."""
    if keep < 1:
        raise ValueError("keep must be at least 1")
    os.makedirs(backup_dir, mode=0o750, exist_ok=True)
    name = time.strftime(NAME, time.gmtime(time.time() if now is None else now))
    final = os.path.join(backup_dir, name)
    tmp = os.path.join(backup_dir, f".{name}.tmp")
    for f in os.listdir(backup_dir):
        # a run killed at its timeout (SIGTERM skips the cleanup below) leaves its temp file; one over an
        # hour old is abandoned, a fresh one belongs to a run still writing it
        stale = os.path.join(backup_dir, f)
        if f.startswith(f".{PREFIX}") and f.endswith(f"{SUFFIX}.tmp") and stale != tmp:
            with contextlib.suppress(FileNotFoundError):
                if os.path.getmtime(stale) < time.time() - 3600:
                    os.unlink(stale)
    with contextlib.suppress(FileNotFoundError):
        os.unlink(tmp)
    src = sqlite3.connect(f"file:{os.path.abspath(db_path)}?mode=ro", uri=True, timeout=60)
    try:
        src.execute("VACUUM INTO ?", (tmp,))
    finally:
        src.close()
    try:
        verdict = _quick_check(tmp)
        if verdict != ["ok"]:
            raise RuntimeError("quick_check on the copy: " + "; ".join(verdict)[:200])
        # VACUUM INTO does not fsync what it wrote: without this a power cut after the rename could
        # leave a named, empty copy that rotation counts as a restore point
        with open(tmp, "rb") as fh:
            os.fsync(fh.fileno())
        os.chmod(tmp, 0o640)
        os.replace(tmp, final)
    except BaseException:
        with contextlib.suppress(OSError):
            os.unlink(tmp)
        raise
    dfd = os.open(backup_dir, os.O_RDONLY)
    try:
        os.fsync(dfd)
    finally:
        os.close(dfd)
    copies = sorted(f for f in os.listdir(backup_dir) if f.startswith(PREFIX) and f.endswith(SUFFIX))
    # by day, not by count: the newest `keep` copies by name let a burst of copies in one day (a deploy
    # took one each time) remove the day's timer copy and every earlier day. Each day keeps its first
    # copy, normally the timer's, so a later copy on the same day cannot push out the one before it.
    first: dict[str, str] = {}
    for f in copies:
        first.setdefault(f[len(PREFIX) : len(PREFIX) + 8], f)  # YYYYMMDD
    keeping = {*list(first.values())[-keep:], name}
    removed = [f for f in copies if f not in keeping]
    for old in removed:
        os.unlink(os.path.join(backup_dir, old))
    return Backup(final, os.path.getsize(final), [f for f in copies if f in keeping], removed)
