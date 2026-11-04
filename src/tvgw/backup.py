"""A daily, checked copy of the store beside it.

`VACUUM INTO` writes a fresh, compact copy while ingest may be running (SQLite's online copy is safe
under the rollback journal), `PRAGMA quick_check` on the copy decides whether it gets its name, and
one copy per UTC day stays for the newest `keep` days, plus the newest copy. A copy is the whole
viewing history and is protected like the original: 640, the state directory's group. A card failure
takes the original and the copies with it; `make backup` pulls them to another machine.

(depth) A copy is refused unless the directory has twice the store's size plus HEADROOM free: VACUUM INTO
writes a whole second store before the old copies are rotated out, and a full disk stops the record and
the capture with it. Each run's outcome goes into the store's meta, `backup_ok_t` or `backup_error`, which
`tvgw verify`'s store_backup check reads (record()).
"""

from __future__ import annotations

import calendar
import contextlib
import json
import os
import sqlite3
import time
from collections.abc import Callable
from dataclasses import dataclass

NAME = "tvgw-%Y%m%dT%H%M%SZ.db"  # UTC, sortable, never repeats in the fall-back hour
PREFIX, SUFFIX = "tvgw-", ".db"
HEADROOM = 2**30  # (depth) bytes beyond twice the store's size that must stay free for a copy
# (depth) why a run failed, as meta.backup_error records it: fixed words, so verify's detail carries no
# path or message from the error itself
CHECK_FAILED = "the copy did not pass its integrity check"
NO_SPACE = "not enough free space for a copy"
WRITE_FAILED = "the copy could not be made"
FAILURES = (CHECK_FAILED, NO_SPACE, WRITE_FAILED)


def directory(state_dir: str) -> str:
    """Where the copies are kept: `<STATE_DIR>/backup`."""
    return os.path.join(state_dir, "backup")


class CheckFailed(RuntimeError):
    """(depth) The copy's quick_check found a fault: the store itself may be damaged."""


class NoSpace(RuntimeError):
    """(depth) The directory has less free space than a copy needs; nothing was written."""


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


def run(
    db_path: str,
    backup_dir: str,
    keep: int = 7,
    now: float | None = None,
    statvfs: Callable[[str], os.statvfs_result] = os.statvfs,
) -> Backup:
    """Copy `db_path` into `backup_dir`, check the copy, rotate: the first copy of each of the newest
    `keep` UTC days and the copy just made stay. Raises CheckFailed on a copy that does not check out
    (nothing is left behind), NoSpace when the directory has less than twice the store's size plus
    HEADROOM free (nothing is written), and the error itself on any other I/O or SQLite failure."""
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
    need = 2 * os.path.getsize(db_path) + HEADROOM
    st = statvfs(backup_dir)
    free = st.f_bavail * st.f_frsize
    if free < need:
        raise NoSpace(
            f"{free / 2**20:.0f} MiB free in {backup_dir}; a copy needs twice the store's size plus"
            f" {HEADROOM // 2**30} GiB, {need / 2**20:.0f} MiB"
        )
    src = sqlite3.connect(f"file:{os.path.abspath(db_path)}?mode=ro", uri=True, timeout=60)
    try:
        src.execute("VACUUM INTO ?", (tmp,))
    finally:
        src.close()
    try:
        verdict = _quick_check(tmp)
        if verdict != ["ok"]:
            raise CheckFailed("quick_check on the copy: " + "; ".join(verdict)[:200])
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


def failure(e: BaseException) -> str:
    """(depth) The fixed words for why a run failed (FAILURES)."""
    if isinstance(e, CheckFailed):
        return CHECK_FAILED
    if isinstance(e, NoSpace):
        return NO_SPACE
    return WRITE_FAILED


def record(db_path: str, why: str | None = None, t: float | None = None) -> None:
    """(depth) The run's outcome in the store's meta: `backup_ok_t` (the time, and `backup_error` removed)
    after a copy, or `backup_error` ({"t", "why"}, `why` one of FAILURES) after a failure, the last good
    copy's time kept. A store that does not exist is not created for it. Raises sqlite3.Error."""
    if not os.path.exists(db_path):
        return
    from tvgw import db  # the writer applies the schema; backup.run itself needs only sqlite3

    when = time.time() if t is None else t
    conn = db.connect(db_path, timeout=60)
    try:
        if why is None:
            db.set_meta(conn, "backup_ok_t", repr(float(when)))
            conn.execute("DELETE FROM meta WHERE key='backup_error'")
        else:
            db.set_meta(conn, "backup_error", json.dumps({"t": float(when), "why": why}))
        conn.commit()
    finally:
        conn.close()


def trim(backup_dir: str, keep: int) -> list[str]:
    """(depth) Remove every copy but the newest `keep`, by name (UTC-stamped, so by age), and return the
    names removed: `tvgw doctor`'s fix for a disk running out of space. A missing directory removes
    nothing; temporary files of a run in progress are not copies and stay."""
    if keep < 1:
        raise ValueError("keep must be at least 1")
    try:
        names = sorted(f for f in os.listdir(backup_dir) if f.startswith(PREFIX) and f.endswith(SUFFIX))
    except FileNotFoundError:
        return []
    removed = names[:-keep]
    for name in removed:
        with contextlib.suppress(FileNotFoundError):
            os.unlink(os.path.join(backup_dir, name))
    return removed


def newest_copy(backup_dir: str) -> float | None:
    """(depth) The time of the newest copy in `backup_dir`, from its UTC name (NAME). A copy is named only
    once its quick_check passed, so a named copy is a checked one, whether or not its run recorded its
    outcome. None when there is no copy or the directory cannot be listed."""
    try:
        names = os.listdir(backup_dir)
    except OSError:
        return None
    times = []
    for name in names:
        try:
            times.append(calendar.timegm(time.strptime(name, NAME)))
        except ValueError:  # a temporary file of a run in progress, or anything else
            continue
    return float(max(times)) if times else None
