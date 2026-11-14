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
(decision 92) A finding the run holds back as a warning while its check is new, but which is of the
level of a failure, needs the same look: the first line names it and the status is the same.
"""

from __future__ import annotations

import os
import time
from collections.abc import Callable
from datetime import datetime
from typing import NamedTuple

from tvgw import counting, verify

STALE = 30 * 60  # tvgw-verify.timer runs every 10 minutes: three missed runs are a stopped check
ACT_CHECKS = frozenset({"tv_paths"})  # failed checks whose fix is on the TV, not on the gateway
FINE = "Nothing needs your attention."
DOCTOR = "Run: sudo tvgw doctor"
ACT = "On the TV: switch Wi-Fi and Wi-Fi Direct off and forget every saved network."
FINE_EXIT, DOCTOR_EXIT, ACT_EXIT = 0, 1, 2


class Verdict(NamedTuple):
    """The last check's verdict, as verify.status_line wrote it."""

    word: str  # ok | fail
    t: float
    failed: list[str]  # the checks that failed, by name
    checks: int  # how many ran, for an `ok`
    held: list[str]  # (decision 92) the checks of a passing run that hold a FAIL-level finding back


def _names(words: list[str]) -> bool:
    return bool(words) and all(w.replace("_", "").isalnum() and w.islower() for w in words)


def parse(text: str) -> Verdict | None:
    """The verdict in the status line, or None when it is not one verify writes: `ok <epoch> <n>`,
    `ok <epoch> <n> held <name> ...` or `fail <epoch> <name> ...`."""
    parts = text.split()
    if len(parts) < 3 or parts[0] not in ("ok", "fail"):
        return None
    try:
        t = float(int(parts[1]))
    except ValueError:
        return None
    if parts[0] == "fail":
        return Verdict("fail", t, parts[2:], 0, []) if _names(parts[2:]) else None
    if not parts[2].isdigit() or (parts[3:] and not (parts[3] == "held" and _names(parts[4:]))):
        return None
    return Verdict("ok", t, [], int(parts[2]), parts[4:])


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
    t, failed, needs_a_look = got.t, got.failed, [*got.failed, *got.held]
    if failed:
        k = len(failed)
        first = f"tvgw: {k} check{'s' if k > 1 else ''} failed at {_when(t, now)}: {', '.join(failed)}."
    elif got.held:  # (decision 92) a passing run that holds back what would be a failure once promoted
        first = (
            f"tvgw: the protection held at {_when(t, now)}, but {len(got.held)} of the {got.checks} checks"
            f" found something that needs a look: {', '.join(got.held)}."
        )
    else:
        first = f"tvgw: the protection held at {_when(t, now)} ({got.checks} checks passed)."
    stale = now - t > STALE
    second = (
        f"The checks have not run for {_age(now - t)}: they may have stopped."
        if stale
        else f"The checks run every 10 minutes; this one is {_age(now - t)} old."
    )
    act = any(n in ACT_CHECKS for n in needs_a_look)
    gateway = stale or any(n not in ACT_CHECKS for n in needs_a_look)
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
