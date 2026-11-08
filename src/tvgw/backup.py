"""A daily, checked copy of the store beside it.

`VACUUM INTO` writes a fresh, compact copy while ingest may be running (SQLite's online copy is safe
under the rollback journal), `PRAGMA quick_check` on the copy decides whether it gets its name, and
one copy per UTC day stays for the newest `keep` days, plus the newest copy. A copy is the whole
viewing history and is protected like the original: 640, the state directory's group. A card failure
takes the original and the copies with it; `make backup` pulls them to another machine.

(depth) A copy is refused unless the directory has the store's size plus HEADROOM free: VACUUM INTO
writes one whole copy before the old copies are rotated out, and a full disk stops the record and the
capture with it. Each run's outcome goes into the store's meta, `backup_ok_t` or `backup_error`, which
`tvgw verify`'s store_backup check reads (record()).
"""

from __future__ import annotations

import calendar
import contextlib
import json
import os
import re
import shutil
import sqlite3
import subprocess
import tempfile
import time
from collections.abc import Callable
from dataclasses import dataclass

NAME = "tvgw-%Y%m%dT%H%M%SZ.db"  # UTC, sortable, never repeats in the fall-back hour
PREFIX, SUFFIX = "tvgw-", ".db"
# (depth) what a copy needs free: COPIES times the store's size (VACUUM INTO writes exactly one copy before
# the rotation removes anything, so one, not two) plus HEADROOM for the hour's capture and the journal. A
# small card (16 GB, a 2 GB store) kept its daily copies under 0.2.0 and lost them to a 2x + 1 GiB rule in
# 0.3.0; tests/unit/test_backup.py pins both numbers so a change here is a decision
COPIES = 1
HEADROOM = 512 * 2**20
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
    (nothing is left behind), NoSpace when the directory has less than COPIES times the store's size plus
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
    need = COPIES * os.path.getsize(db_path) + HEADROOM
    st = statvfs(backup_dir)
    free = st.f_bavail * st.f_frsize
    if free < need:
        raise NoSpace(
            f"{free / 2**20:.0f} MiB free in {backup_dir}; a copy needs the store's size plus"
            f" {HEADROOM // 2**20} MiB, {need / 2**20:.0f} MiB"
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


# ---- (reliability) the copy that leaves the box, and the drill that proves a copy restores ---------------
# design decision 73. The copies above sit on the card that holds the store and fail with it. `tvgw backup
# --export` hands the newest checked copy to `age`, encrypted to the owner's own public key
# (BACKUP_RECIPIENT), on standard output, so `make backup` pulls it over ssh and only ciphertext leaves the
# gateway; the gateway never holds the key that opens it. `tvgw restore --check FILE` proves that a copy,
# plain or encrypted, opens, checks whole, and migrates into a scratch store that this tvgw can use.
AGE_MAGIC = (b"age-encryption.org/v1\n", b"-----BEGIN AGE ENCRYPTED FILE-----")
SQLITE_MAGIC = b"SQLite format 3\x00"
AGE_RECIPIENT = re.compile(r"age1[qpzry9x8gf2tvdw0s3jn54khce6mua7l]{58}")  # an X25519 recipient, bech32
NO_RECIPIENT = (
    "set BACKUP_RECIPIENT in /etc/tvgw/tvgw.conf to your age public key first: the copy is encrypted to it,"
    " and the key that opens it stays on your computer"
)
NO_AGE = "age is not installed on this computer: sudo apt install age (macOS: brew install age)"


def newest_path(backup_dir: str) -> str | None:
    """The newest named copy in `backup_dir` (a named copy passed its check), or None."""
    try:
        names = sorted(n for n in os.listdir(backup_dir) if n.startswith(PREFIX) and n.endswith(SUFFIX))
    except OSError:
        return None
    named = [n for n in names if _stamp(n) is not None]
    return os.path.join(backup_dir, named[-1]) if named else None


def _stamp(name: str) -> float | None:
    try:
        return float(calendar.timegm(time.strptime(name, NAME)))
    except ValueError:
        return None


def export(
    backup_dir: str,
    recipient: str,
    out: int,
    which: Callable[[str], str | None] = shutil.which,
    run: Callable[..., subprocess.CompletedProcess] = subprocess.run,
    now: float | None = None,
) -> tuple[int, str]:
    """Write the newest checked copy, encrypted with `age` to `recipient`, to the file descriptor `out`.
    Returns (exit code, the line for standard error): 0 when age wrote it, 1 with no copy, no age or a
    failed age, 2 with no recipient. Nothing is written in plain anywhere."""
    if not recipient:
        return 2, NO_RECIPIENT
    age = which("age")
    if not age:
        return 1, NO_AGE
    path = newest_path(backup_dir)
    if path is None:
        return 1, "no checked copy yet: run sudo tvgw backup first"
    p = run([age, "--encrypt", "--recipient", recipient, path], stdout=out, stderr=subprocess.PIPE)
    if p.returncode != 0:
        err = (p.stderr or b"").decode("utf-8", "replace").strip().splitlines()
        return 1, f"age could not encrypt the copy: {err[0] if err else p.returncode}"
    made = _stamp(os.path.basename(path)) or 0.0
    hours = ((time.time() if now is None else now) - made) / 3600
    return 0, f"{os.path.basename(path)}, made {hours:.0f} hours ago, encrypted to your age key"


@dataclass
class Drill:
    ok: bool
    lines: list[str]


def restore_check(
    path: str,
    identity: str | None = None,
    which: Callable[[str], str | None] = shutil.which,
    run: Callable[..., subprocess.CompletedProcess] = subprocess.run,
    scratch_root: str | None = None,
) -> Drill:
    """Restore `path` into a scratch store and say whether it works: decrypted with `age` and `identity`
    when it is an age file, or copied when it is a store; `PRAGMA integrity_check` on the copy; refused
    when a newer tvgw wrote it (db.too_new); opened as this tvgw's writer, which migrates it; checked
    again; and its rows counted. The scratch directory (0700) is removed whatever happens, and the file
    itself is only ever read."""
    from tvgw import db  # the writer applies the schema; the daily copy needs only sqlite3

    name = os.path.basename(path)
    try:
        with open(path, "rb") as fh:
            head = fh.read(64)
    except OSError as e:
        return Drill(False, [f"cannot read {name}: {e.strerror or e}"])
    scratch = tempfile.mkdtemp(prefix="tvgw-restore-check-", dir=scratch_root)
    copy = os.path.join(scratch, "tvgw.db")
    try:
        if head.startswith(AGE_MAGIC):
            if not identity:
                return Drill(
                    False, [f"{name} is encrypted: give --identity, the age key file it was made for"]
                )
            age = which("age")
            if not age:
                return Drill(False, [NO_AGE])
            p = run([age, "--decrypt", "--identity", identity, "--output", copy, path], capture_output=True)
            if p.returncode != 0:
                err = (p.stderr or b"").decode("utf-8", "replace").strip().splitlines()
                return Drill(False, [f"age could not decrypt {name}: {err[0] if err else p.returncode}"])
        elif head.startswith(SQLITE_MAGIC):
            shutil.copyfile(path, copy)
        else:
            return Drill(False, [f"{name} is neither a copy of the store nor an age-encrypted one"])
        return _drill(name, copy, db)
    except (sqlite3.Error, ValueError) as e:
        return Drill(False, [f"{name} does not open as a store: {e}"])
    finally:
        shutil.rmtree(scratch, ignore_errors=True)


def _text(raw: bytes) -> str:
    """A damaged copy's pages can hold any bytes, and integrity_check quotes them back."""
    return raw.decode("utf-8", "replace")


def _drill(name: str, copy: str, db) -> Drill:
    ro = sqlite3.connect(f"file:{copy}?mode=ro", uri=True)
    ro.text_factory = _text
    try:
        verdict = [r[0] for r in ro.execute("PRAGMA integrity_check")]
        found = db.stored_version(ro)
    finally:
        ro.close()
    if verdict != ["ok"]:
        return Drill(False, [f"{name} is damaged: " + "; ".join(verdict)[:300]])
    if db.too_new(found):
        return Drill(False, [f"{name} was written by a newer tvgw (schema {found}); this one restores up to"
                             f" schema {db.SCHEMA_VERSION}"])  # fmt: skip
    conn = db.connect(copy)  # as this tvgw's writer: the migration a restore would make
    conn.text_factory = _text
    try:
        again = [r[0] for r in conn.execute("PRAGMA integrity_check")]
        rows = db.counts(conn)
        first = conn.execute("SELECT MIN(t) FROM dns").fetchone()[0]
        last = conn.execute("SELECT MAX(t) FROM dns").fetchone()[0]
    finally:
        conn.close()
    if again != ["ok"]:
        return Drill(False, [f"{name} is damaged after this tvgw opened it: " + "; ".join(again)[:300]])
    span = (
        f", lookups from {time.strftime('%Y-%m-%d %H:%M', time.localtime(first))} to"
        f" {time.strftime('%Y-%m-%d %H:%M', time.localtime(last))} (this computer's time)"
        if first is not None and last is not None
        else ""
    )
    return Drill(
        True,
        [
            f"{name} restores: integrity ok, schema {found or 'unrecorded'} opened as {db.SCHEMA_VERSION} by"
            " this tvgw, checked again",
            f"rows: {rows['dns']:,} lookups, {rows['flows']:,} connections,"
            f" {sum(rows.values()):,} in all{span}",
            "the scratch copy is removed; nothing was written anywhere else",
        ],
    )
