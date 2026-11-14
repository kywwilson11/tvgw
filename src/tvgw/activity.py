"""Passive TV activity: when the TV was on, from the TV port's own byte counters, for any TV.

An LG answers an hourly reading over its LAN API, and a 20-minute session between two readings is
missed two times in three; a Samsung without pairing, a Roku or a Vizio answers none. The gateway's
sampler (`ledger.sample`, every 10 minutes in `tvgw verify --record`) already stores `tv_tx_bytes`, the
bytes the gateway sent the TV, in `gw_samples`. Two consecutive samples of one boot make an interval,
and the interval's download says what the TV was doing:

- `streaming`: at least `STREAM_BYTES` per 600 s, a video stream's floor;
- `awake`: at least `AWAKE_BYTES` per 600 s, or `AWAKE_STARTS` TV connections opened in it;
- `quiet`: less.

A reboot between the samples, a counter that went down, a missing counter or a gap over `MAX_GAP`
leaves the pair out: nothing is guessed across it. The thresholds are starting values. `calibrate()`
holds them against the LG's own readings over `CALIBRATION_DAYS`: the `Active` readings with an app in
front that could stream must fall in a streaming or awake interval, and the `unreachable` readings in a
quiet one, each share with a Wilson lower bound of at least `CALIBRATION_BAR` (design decision 97): 23
of 24 is 95.8%, but could be 79.8%, and asserting 90% with no miss takes 35 readings. Until a store
meets both bars, activity is reported and used for nothing (`tvgw activity calibrate`); once it does,
the brief's standby section leaves streaming intervals out of "while off" (`queries.standby_activity`).
Where the TV gives no readings at all, the hour classifier counts an hour with a streaming interval as
on with demand, and the plain brief's hours on are these, marked estimated.
"""

from __future__ import annotations

import bisect
import itertools
import sqlite3
from dataclasses import dataclass

INTERVAL = 600.0  # seconds: the sampler's period, the unit the thresholds are written in
STREAM_BYTES = 5_000_000  # bytes to the TV per 600 s: a stream
AWAKE_BYTES = 200_000  # bytes to the TV per 600 s: an app, a menu, a store page
AWAKE_STARTS = 3  # TV connections opened in the interval
MAX_GAP = 1800.0  # seconds: two samples further apart are a gap, not an interval
CALIBRATION_DAYS = 14
CALIBRATION_BAR = 0.90  # the Wilson lower bound (evidencekit.CONF) each share must reach
STREAMING, AWAKE, QUIET = "streaming", "awake", "quiet"
ON = (STREAMING, AWAKE)
OFF_READING = "unreachable"  # what tvgw-analyze records when the TV does not answer: off, or asleep


@dataclass(frozen=True)
class Interval:
    start: float
    end: float
    label: str  # STREAMING | AWAKE | QUIET
    down: int  # bytes the gateway sent the TV in it


def _samples(conn: sqlite3.Connection, a: float, b: float) -> list[tuple[float, str | None, int | None]]:
    try:
        return conn.execute(
            "SELECT t, boot_id, tv_tx_bytes FROM gw_samples WHERE t >= ? AND t <= ? ORDER BY t",
            (a - MAX_GAP, b + MAX_GAP),
        ).fetchall()
    except sqlite3.OperationalError:  # a store from before the sampler (schema 9)
        return []


def buckets(conn: sqlite3.Connection, a: float, b: float) -> list[Interval]:
    """The intervals between consecutive samples that overlap [a, b), each with its label."""
    rows = _samples(conn, a, b)
    pairs = [
        (p, c)
        for p, c in itertools.pairwise(rows)
        if c[0] > a
        and p[0] < b
        and 0 < c[0] - p[0] <= MAX_GAP
        and p[2] is not None
        and c[2] is not None
        and c[2] >= p[2]
        and not (p[1] and c[1] and p[1] != c[1])
    ]
    if not pairs:
        return []
    starts = [
        t
        for (t,) in conn.execute(
            "SELECT t_start FROM flows WHERE t_start >= ? AND t_start < ? ORDER BY t_start",
            (pairs[0][0][0], pairs[-1][1][0]),
        )
    ]
    out = []
    for (t0, _, b0), (t1, _, b1) in pairs:
        down = b1 - b0
        rate = down * INTERVAL / (t1 - t0)
        opened = bisect.bisect_left(starts, t1) - bisect.bisect_left(starts, t0)
        if rate >= STREAM_BYTES:
            label = STREAMING
        elif rate >= AWAKE_BYTES or opened >= AWAKE_STARTS:
            label = AWAKE
        else:
            label = QUIET
        out.append(Interval(t0, t1, label, down))
    return out


def overlap(iv: Interval, a: float, b: float) -> float:
    return max(0.0, min(iv.end, b) - max(iv.start, a))


def hours_on(conn: sqlite3.Connection, a: float, b: float) -> float | None:
    """Hours of [a, b) in streaming or awake intervals, or None when no interval covers any of it."""
    found = buckets(conn, a, b)
    if not found:
        return None
    return sum(overlap(iv, a, b) for iv in found if iv.label in ON) / 3600


def streaming_hours(conn: sqlite3.Connection, a: float, b: float) -> set[int]:
    """The clock hours (epoch, hour-aligned) in [a, b) that a streaming interval overlaps."""
    out: set[int] = set()
    for iv in buckets(conn, a, b):
        if iv.label != STREAMING:
            continue
        h = int(max(iv.start, a) // 3600) * 3600
        while h < min(iv.end, b):
            out.add(h)
            h += 3600
    return out


def _at(found: list[Interval], starts: list[float], t: float) -> Interval | None:
    i = bisect.bisect_right(starts, t) - 1
    return found[i] if i >= 0 and found[i].start <= t < found[i].end else None


def calibrate(
    conn: sqlite3.Connection, until: float, days: int = CALIBRATION_DAYS, bar: float = CALIBRATION_BAR
) -> dict:
    """The intervals held against the TV's own readings over the `days` before `until`: the share of
    `Active` readings with an app in front that could stream (not the launcher, not an input) that fall
    in a streaming or awake interval, and the share of `unreachable` readings that fall in a quiet one,
    each with its Wilson lower bound. `met` when both lower bounds reach `bar`: a share of a few readings
    meets nothing however well they agree. A reading no interval covers (no samples then) counts in
    neither."""
    from tvgw import autoblock, evidencekit  # here: autoblock imports queries, which imports this

    a = until - days * 86400
    found = buckets(conn, a, until)
    starts = [iv.start for iv in found]
    active = active_hit = off = off_quiet = uncovered = 0
    for t, power, app in conn.execute(
        "SELECT t, power, app FROM tvstate WHERE t >= ? AND t < ? ORDER BY t", (a, until)
    ):
        if power == "Active" and autoblock.demand_app(app):
            iv = _at(found, starts, t)
            if iv is None:
                uncovered += 1
                continue
            active += 1
            active_hit += iv.label in ON
        elif power == OFF_READING:
            iv = _at(found, starts, t)
            if iv is None:
                uncovered += 1
                continue
            off += 1
            off_quiet += iv.label == QUIET
    counts = {label: sum(1 for iv in found if iv.label == label) for label in (STREAMING, AWAKE, QUIET)}
    active_share = active_hit / active if active else None
    off_share = off_quiet / off if off else None
    active_low = evidencekit.wilson(active_hit, active)[0]
    off_low = evidencekit.wilson(off_quiet, off)[0]
    met = active_low >= bar and off_low >= bar
    return {
        "days": days,
        "until": until,
        "intervals": counts,
        "active": active,
        "active_on": active_hit,
        "active_share": active_share,
        "active_low": active_low,
        "unreachable": off,
        "unreachable_quiet": off_quiet,
        "unreachable_share": off_share,
        "unreachable_low": off_low,
        "uncovered": uncovered,
        "bar": bar,
        "met": met,
    }


def summary_lines(c: dict) -> list[str]:
    """`tvgw activity calibrate`'s report: what was compared, the two shares, and what follows."""

    def share(n: int, of: int, s: float | None, low: float) -> str:
        return f"{n} of {of}: {s:.1%} (at least {low:.1%})" if s is not None else "none to compare"

    iv = c["intervals"]
    needed = f"at least {c['bar']:.0%} needed"
    lines = [
        f"tvgw activity calibrate: {c['days']} days, {sum(iv.values())} intervals"
        f" (streaming {iv[STREAMING]}, awake {iv[AWAKE]}, quiet {iv[QUIET]})",
        f"Active readings with an app in front, in a streaming or awake interval:"
        f" {share(c['active_on'], c['active'], c['active_share'], c['active_low'])}; {needed}",
        f"unreachable readings, in a quiet interval:"
        f" {share(c['unreachable_quiet'], c['unreachable'], c['unreachable_share'], c['unreachable_low'])};"
        f" {needed}",
    ]
    if c["uncovered"]:
        lines.append(f"{c['uncovered']} reading(s) fell where no sample pair covers them and were left out")
    if c["met"]:
        lines.append("met: the brief leaves streaming intervals out of the hours the TV said it was off")
    else:
        lines.append(
            "not met (the lower bound of both shares at the bar): the brief's standby section uses the"
            " readings alone"
        )
    return lines
