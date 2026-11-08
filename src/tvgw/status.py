"""`tvgw status`: is it working now, and do I need to do anything? Three lines, then what is counting.

It reads two files and nothing else, not the settings file, not the store: `/run/tvgw/status.txt`, which
every `tvgw verify` run replaces with its verdict by check name (verify.write_status), and (counting)
`counting.txt` beside it, which every `tvgw verify --record` run replaces with the runs of the count-only
mechanisms (design decision 72). So it needs no root and no `adm` group, and it works when the settings
file cannot be read. The first line says whether the protection held at the last check, the second how
old that check is, the third what to do; then one line for each mechanism that counts and refuses nothing,
since when and when its two weeks end, and none when nothing counts or the file is not there.

The exit status is the tier of what needs doing (design 4.3): 0 nothing, 1 the gateway itself (run
`sudo tvgw doctor`), 2 something on the TV (ACT_CHECKS: a check whose fix is at the TV's own menus).
"""

from __future__ import annotations

import os
import time
from collections.abc import Callable
from datetime import datetime

from tvgw import counting, verify

STALE = 30 * 60  # tvgw-verify.timer runs every 10 minutes: three missed runs are a stopped check
ACT_CHECKS = frozenset({"tv_paths"})  # failed checks whose fix is on the TV, not on the gateway
FINE = "Nothing needs your attention."
DOCTOR = "Run: sudo tvgw doctor"
ACT = "On the TV: switch Wi-Fi and Wi-Fi Direct off and forget every saved network."
FINE_EXIT, DOCTOR_EXIT, ACT_EXIT = 0, 1, 2


def parse(text: str) -> tuple[str, float, list[str], int] | None:
    """(word, time, failed check names, checks run) from the status line, or None when it is not one
    verify writes: `ok <epoch> <n>` or `fail <epoch> <name> ...`."""
    parts = text.split()
    if len(parts) < 3 or parts[0] not in ("ok", "fail"):
        return None
    try:
        t = float(int(parts[1]))
    except ValueError:
        return None
    if parts[0] == "ok":
        if len(parts) != 3 or not parts[2].isdigit():
            return None
        return "ok", t, [], int(parts[2])
    names = parts[2:]
    if not all(n.replace("_", "").isalnum() and n.islower() for n in names):
        return None
    return "fail", t, names, 0


def _when(t: float, now: float) -> str:
    fmt = "%H:%M" if now - t < 86400 else "%Y-%m-%d %H:%M"
    return datetime.fromtimestamp(t).strftime(fmt)


def _age(seconds: float) -> str:
    seconds = max(seconds, 0)
    if seconds < 90:
        return "under a minute"
    if seconds < 2 * 3600:
        return f"{seconds / 60:.0f} minutes"
    if seconds < 2 * 86400:
        return f"{seconds / 3600:.0f} hours"
    return f"{seconds / 86400:.0f} days"


def lines(text: str | None, now: float) -> tuple[list[str], int]:
    """The three lines and the exit status for a status file's text (None: no file)."""
    if text is None:
        return [
            "tvgw: no check has run since this computer started.",
            "The first one runs a few minutes after it starts, then one every 10 minutes.",
            f"If it has been longer than that: {DOCTOR}",
        ], DOCTOR_EXIT
    got = parse(text)
    if got is None:
        return [
            "tvgw: the last check's verdict could not be read.",
            f"It is kept in {verify.STATUS}.",
            DOCTOR,
        ], DOCTOR_EXIT
    word, t, failed, n = got
    if word == "ok":
        first = f"tvgw: the protection held at {_when(t, now)} ({n} checks passed)."
    else:
        k = len(failed)
        first = f"tvgw: {k} check{'s' if k > 1 else ''} failed at {_when(t, now)}: {', '.join(failed)}."
    stale = now - t > STALE
    second = (
        f"The checks have not run for {_age(now - t)}: they may have stopped."
        if stale
        else f"The checks run every 10 minutes; this one is {_age(now - t)} old."
    )
    act = any(n in ACT_CHECKS for n in failed)
    gateway = stale or any(n not in ACT_CHECKS for n in failed)
    if act:
        return [first, second, ACT + (" Then run: sudo tvgw doctor" if gateway else "")], ACT_EXIT
    if gateway:
        return [first, second, DOCTOR], DOCTOR_EXIT
    return [first, second, FINE], FINE_EXIT


def read_status(path: str) -> str | None:
    """The file's text, None when there is none. A file that is there but cannot be read reads as text
    no verdict can be parsed from, which says so."""
    try:
        with open(path, encoding="utf-8", errors="replace") as fh:
            return fh.read()
    except FileNotFoundError:
        return None
    except OSError:
        return ""


def _file_age(path: str, now: float) -> float | None:
    """(counting) Seconds since the file was last written, or None when it cannot be told."""
    try:
        return now - os.stat(path).st_mtime
    except OSError:
        return None


def main(path: str | None = None, now: float | None = None, out: Callable[[str], None] = print) -> int:
    path = path or verify.STATUS
    now = time.time() if now is None else now
    shown, code = lines(read_status(path), now)
    # (counting) what counts and refuses nothing, from the file verify --record leaves beside the status
    beside = counting.file_beside(path)
    shown += counting.status_lines(read_status(beside), now, _file_age(beside, now))
    for line in shown:
        out(line)
    return code
