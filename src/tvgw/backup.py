"""A daily, checked copy of the store beside it.

`VACUUM INTO` writes a fresh, compact copy while ingest may be running (SQLite's online copy is safe
under the rollback journal), `PRAGMA quick_check` on the copy decides whether it gets its name, and
only the newest `keep` copies stay. A copy is the whole viewing history and is protected like the
original: 640, the state directory's group. A card failure takes the original and the copies with
it; `make backup` pulls them to another machine.
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
    """Copy `db_path` into `backup_dir`, check the copy, rotate. Raises on a copy that does not check
    out (nothing is left behind) and on any I/O or SQLite error."""
    if keep < 1:
        raise ValueError("keep must be at least 1")
    os.makedirs(backup_dir, mode=0o750, exist_ok=True)
    name = time.strftime(NAME, time.gmtime(time.time() if now is None else now))
    final = os.path.join(backup_dir, name)
    tmp = os.path.join(backup_dir, f".{name}.tmp")
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
        os.chmod(tmp, 0o640)
        os.replace(tmp, final)
    except BaseException:
        with contextlib.suppress(OSError):
            os.unlink(tmp)
        raise
    copies = sorted(f for f in os.listdir(backup_dir) if f.startswith(PREFIX) and f.endswith(SUFFIX))
    removed = copies[:-keep]
    for old in removed:
        os.unlink(os.path.join(backup_dir, old))
    return Backup(final, os.path.getsize(final), copies[-keep:], removed)
