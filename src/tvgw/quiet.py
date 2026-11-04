"""`tvgw tv quiet`: may a deploy that changes the network run now? (design decision 63)

The CI hardware job asks before it deploys a commit that carries `Deploy-window: tv-off`. The
answer is yes only when all three hold, each read on the gateway and nothing written anywhere:

1. the gateway's local time is inside the window: `--window`, else `DEPLOY_WINDOW`, `03:30-05:30`
   when the settings file does not set it; the start is in the window and the end is not, and an end
   before the start runs past midnight;
2. the TV's last hourly reading is not `Active`, or there is no reading younger than
   `READING_MAX_AGE` (a TV without a reader, or a reader that stopped);
3. the TV port moved under `IDLE_BYTES` in the last `--idle` minutes: the port's byte counters now
   against the newest gateway sample (`gw_samples`) at least that old, from the same boot; and, with
   `--wait SEC`, across those seconds as well. A port nothing can measure is not idle.

It prints exactly one line, `deploy: now` or `deploy: deferred`, and never which condition failed:
the line goes into a public CI log, and the reason would tell its readers when the household watches
TV. The window is fixed for the same reason: a job that waited for the TV to go quiet would publish
the hour it did.
"""

from __future__ import annotations

import re
import sqlite3
import time
from collections.abc import Callable
from dataclasses import dataclass
from datetime import datetime

from tvgw import db
from tvgw.config import Settings

NOW, DEFERRED = "deploy: now", "deploy: deferred"
IDLE_BYTES = 1 << 20  # 1 MB: what the TV port may carry in the idle minutes, both ways together
IDLE_MINUTES = 20
READING_MAX_AGE = 2 * 3600  # seconds: the hourly reading, with a missed hour's slack
ACTIVE = "Active"  # webOS's power state while the screen is on (lgwebos.POWER_STATES)
MAX_WAIT = 3600  # seconds --wait may watch the port for
BOOT_ID = "/proc/sys/kernel/random/boot_id"
_HHMM = r"(?:[01][0-9]|2[0-3]):[0-5][0-9]"
WINDOW = re.compile(f"({_HHMM})-({_HHMM})")  # the shape config.load() accepts for DEPLOY_WINDOW


def parse_window(text: str) -> tuple[int, int]:
    """`HH:MM-HH:MM` as (start, end) in minutes after midnight; ValueError for anything else, and for a
    window that starts where it ends."""
    m = WINDOW.fullmatch(text.strip())
    if not m or m.group(1) == m.group(2):
        raise ValueError(f"{text!r}: expected HH:MM-HH:MM, a start and a different end")
    start, end = (int(x[:2]) * 60 + int(x[3:]) for x in m.groups())
    return start, end


def in_window(minute: int, window: tuple[int, int]) -> bool:
    """Whether a minute of the day is inside the window, its start included and its end not."""
    start, end = window
    return start <= minute < end if start < end else minute >= start or minute < end


def last_power(history: str, now: float, max_age: float = READING_MAX_AGE) -> str | None:
    """The power state of the newest line of tvcheck-history.log (`<ISO time>\\t<power>\\t<app>`, as
    tvgw-analyze writes it), or None when there is no such line or it is older than `max_age` (or more
    than a minute ahead of the clock)."""
    lines = [ln for ln in history.splitlines() if ln.strip()]
    if not lines or "\t" not in lines[-1]:
        return None
    stamp, power = lines[-1].split("\t")[:2]
    try:
        t = datetime.fromisoformat(stamp.strip()).timestamp()
    except ValueError:
        return None
    return power.strip() if -60 <= now - t <= max_age else None


@dataclass(frozen=True)
class Counters:
    """The TV port's bytes, both ways together, and the boot they were counted in."""

    total: int
    boot: str


def port_counters(read: Callable[[str], str | None], tv_if: str) -> Counters | None:
    """The TV port's counters from sysfs now, or None when either is unreadable."""

    def number(path: str) -> int | None:
        text = (read(path) or "").strip()
        return int(text) if text.isdigit() else None

    rx = number(f"/sys/class/net/{tv_if}/statistics/rx_bytes")
    tx = number(f"/sys/class/net/{tv_if}/statistics/tx_bytes")
    boot = (read(BOOT_ID) or "").strip()
    return Counters(rx + tx, boot) if rx is not None and tx is not None and boot else None


def moved(before: Counters | None, after: Counters | None) -> int | None:
    """Bytes the port carried between two readings, or None when they cannot be compared: one is
    missing, a reboot lies between them, or the count went down."""
    if before is None or after is None or before.boot != after.boot or after.total < before.total:
        return None
    return after.total - before.total


def sample_before(conn: sqlite3.Connection, t: float) -> Counters | None:
    """The newest gateway sample taken at or before `t` that has both of the TV port's counters."""
    row = conn.execute(
        "SELECT tv_rx_bytes, tv_tx_bytes, boot_id FROM gw_samples WHERE t <= ? AND tv_rx_bytes IS NOT NULL"
        " AND tv_tx_bytes IS NOT NULL ORDER BY t DESC LIMIT 1",
        (t,),
    ).fetchone()
    return Counters(row[0] + row[1], row[2]) if row and row[2] else None


def is_quiet(
    minute: int,
    window: tuple[int, int],
    power: str | None,
    over_idle: int | None,
    over_wait: int | None,
) -> bool:
    """The verdict: inside the window, the TV not Active, and the port measured under IDLE_BYTES over
    the idle minutes, the wait, or both, with nothing measured over the limit."""
    measured = [x for x in (over_idle, over_wait) if x is not None]
    return (
        in_window(minute, window)
        and power != ACTIVE
        and bool(measured)
        and all(x < IDLE_BYTES for x in measured)
    )


def read_text(path: str) -> str | None:
    """A file's text, or None when it does not exist. Any other failure propagates: a reading that is
    there and cannot be opened is not "no reading", and main() answers deferred."""
    try:
        with open(path, encoding="utf-8", errors="replace") as fh:
            return fh.read()
    except FileNotFoundError:
        return None


def decide(
    s: Settings,
    window: str | None = None,
    idle: int = IDLE_MINUTES,
    wait: int = 0,
    *,
    clock: Callable[[], float] = time.time,
    sleep: Callable[[float], None] = time.sleep,
    read: Callable[[str], str | None] = read_text,
    connect: Callable[[str], sqlite3.Connection] = lambda path: db.connect(path, readonly=True, timeout=10),
) -> bool:
    """Whether a deploy may run now (the module docstring has the three conditions). Reads only."""
    span = parse_window(window or s.deploy_window)
    start = port_counters(read, s.tv_if) if wait > 0 else None
    if wait > 0:
        sleep(wait)
    now = clock()
    current = port_counters(read, s.tv_if)
    over_wait = moved(start, current) if wait > 0 else None
    try:
        conn = connect(s.db_path)
    except (sqlite3.Error, OSError):
        over_idle = None
    else:
        try:
            over_idle = moved(sample_before(conn, now - idle * 60), current)
        except sqlite3.Error:  # no gw_samples table yet, or a store busy past the timeout
            over_idle = None
        finally:
            conn.close()
    power = last_power(read(s.tvcheck_history) or "", now)
    local = datetime.fromtimestamp(now)
    return is_quiet(local.hour * 60 + local.minute, span, power, over_idle, over_wait)


def main(s: Settings, window: str | None, idle: int, wait: int, **seams) -> int:
    """Print the one line: 0 for now, 1 for deferred. The store and the readings are root's (or the
    `adm` group's); one that is there and cannot be read answers deferred, never quiet. `seams` go to
    decide()."""
    try:
        quiet = decide(s, window, idle, wait, **seams)
    except OSError:
        quiet = False
    print(NOW if quiet else DEFERRED)
    return 0 if quiet else 1
