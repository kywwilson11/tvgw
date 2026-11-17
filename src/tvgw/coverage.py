"""(coverage) When was a source of the record not looking? A silence in the record is not an absence in the
TV's traffic: a lookup missing from a stretch whose query log was lost says nothing about the lookup. This
module finds those stretches, per source and per window, from evidence the gateway already keeps, so that a
sentence which claims an absence ("No lookup was refused", "the TV sent these nothing") is held back across
one (`plain.absent()`, design decision 100).

Three sources are judged:

- `dns` and `flows`, the logs the hourly ingest reads, by its runs (`ingest_runs`): a stretch is not known
  when the run that ended it found lines of the log lost (rotated past what it could recover, conntrack's
  events dropped), or when no run read the log for longer than RUN_GAP, up to now included;
- `flows` again, by the one independent witness the gateway keeps, the byte counters of the TV's port
  (`gw_samples`): a sampler interval in which the port carried more than RECONCILE_FLOOR to the TV while no
  connection in the record overlaps it;
- `tvlive`, the live reading: more than three heartbeat periods without a heartbeat while an hourly reading
  says the TV was on and no recorded disconnect explains the quiet.

A source is judged over the window asked about, never by whether it is alive now. Every judgement is
additive: a stretch is judged whole, from the times either side of it, and only then cut to the window, so
the gaps of [a, c) are the gaps of [a, b) and [b, c) joined where they touch.
"""

from __future__ import annotations

import bisect
import itertools
import json
import sqlite3
import time
from collections.abc import Iterator
from dataclasses import dataclass
from datetime import datetime, timedelta

from tvgw import activity

SOURCES = ("dns", "flows", "tvlive")
INF = float("inf")

# seconds: the ingest runs hourly, so the next run reads what one missed; a log no run has read for longer
# than two and a half hours is two runs behind, and what it held then may have rotated away or never been
# written (a query log switched off writes nothing to recover)
RUN_GAP = 9000.0
# seconds between the live reading's heartbeats (tvlive.ALIVE_EVERY; a test holds the two equal), kept here
# because tvlive imports queries, which imports this module
LIVE_BEAT = 600.0
LIVE_GAP = 3 * LIVE_BEAT  # a quiet longer than this, the TV on and no disconnect recorded, is a gap
RECONCILE_FLOOR = 50_000_000  # bytes to the TV in one sampler interval: a stream the flow record must hold
AWAKE = ("Active", "Screen Off", "Screen Saver")  # queries.AWAKE, the readings of a TV that is on

# What a run of the ingest did with a log, read from its warnings (`ingest_runs.warnings`): each of a
# source's warnings begins with its step's name or its log's tail key; one with a LOSS word says a stretch of
# the log was lost before the run; a SKIPPED line costs that line only; any other is the step failing, and
# the next run reads on from the same cursor.
PREFIXES = {"dns": ("dns: ", "adguard: "), "flows": ("flows: ",)}
LOSS = ("log rotated or truncated", "conntrack lost events", "event socket dropped")
SKIPPED = "malformed"
READ, LOST = "read", "lost"

WHY_LOST = "the ingest found lines of the log lost"
WHY_UNREAD = "no run of the ingest read the log"
WHY_PORT = "the TV's port carried a stream the flow record holds no connection for"
WHY_BEAT = "no heartbeat from the live reading while the TV was on"


@dataclass(frozen=True)
class Gap:
    """A stretch [a, b) of one source's record that nothing was looking at, and why."""

    source: str
    a: float
    b: float
    why: str


def cut(gaps: list[Gap], a: float, b: float) -> list[Gap]:
    """The gaps cut to [a, b), those that lie wholly outside it dropped."""
    return [Gap(g.source, max(g.a, a), min(g.b, b), g.why) for g in gaps if max(g.a, a) < min(g.b, b)]


def join(gaps: list[Gap]) -> list[Gap]:
    """Gaps that touch or overlap and say the same thing, as one; oldest first."""
    out: list[Gap] = []
    for g in sorted(gaps, key=lambda g: (g.source, g.why, g.a, g.b)):
        last = out[-1] if out else None
        if last and (last.source, last.why) == (g.source, g.why) and g.a <= last.b:
            out[-1] = Gap(g.source, last.a, max(last.b, g.b), g.why)
        else:
            out.append(g)
    return sorted(out, key=lambda g: (g.a, g.b))


def _verdict(source: str, raw: str | None) -> str | None:
    """What one run did with `source`'s log: READ, LOST (read, and found a stretch before it lost), or None
    when its step failed and it read nothing."""
    try:
        said = json.loads(raw or "[]")
    except ValueError:
        said = []
    mine = [w for w in said if isinstance(w, str) and w.startswith(PREFIXES[source])]
    if any(word in w for w in mine for word in LOSS):
        return LOST
    return None if any(SKIPPED not in w for w in mine) else READ


def _logs(conn: sqlite3.Connection, source: str, a: float, b: float, now: float) -> list[Gap]:
    """The stretches of a log the ingest reads that its runs cannot vouch for, as they bear on [a, b): from
    the run before a run that found lines lost to that run, between two runs that read it more than RUN_GAP
    apart, and from the last run that read it to now once that is longer. Before the first run on record
    there is none, since that run read the log from its start; a log no run ever read is not known at all."""

    def reads(where: str, args: tuple) -> Iterator[tuple[float, str]]:
        for t, raw in conn.execute(f"SELECT t, warnings FROM ingest_runs WHERE {where}", args):
            seen = _verdict(source, raw)
            if seen:
                yield t, seen

    before = next(reads("t < ? ORDER BY t DESC", (a,)), None)
    after = next(reads("t >= ? ORDER BY t", (b,)), None)
    runs = [r for r in (before, *reads("t >= ? AND t < ? ORDER BY t", (a, b)), after) if r]
    if not runs:
        return [Gap(source, -INF, INF, WHY_UNREAD)]
    gaps = [
        Gap(source, p, q, WHY_LOST if seen == LOST else WHY_UNREAD)
        for (p, _), (q, seen) in itertools.pairwise(runs)
        if seen == LOST or q - p > RUN_GAP
    ]
    last = runs[-1][0]
    if now - last > RUN_GAP:  # the ingest is behind: what came since is not read yet
        gaps.append(Gap(source, last, INF, WHY_UNREAD))
    return gaps


def _holes(conn: sqlite3.Connection, a: float, b: float) -> list[Gap]:
    """The sampler's intervals overlapping [a, b) in which the TV's port carried more than RECONCILE_FLOOR to
    the TV while no connection in the record overlaps them: the flow log was not looking. A connection
    overlaps an interval when it began before the interval ended and ended after it began."""
    busy = [iv for iv in activity.buckets(conn, a, b) if iv.down > RECONCILE_FLOOR]
    if not busy:
        return []
    spans = sorted(
        conn.execute(
            "SELECT COALESCE(t_start, t_end), t_end FROM flows"
            " WHERE t_end >= ? AND COALESCE(t_start, t_end) < ?",
            (busy[0].start, busy[-1].end),
        )
    )
    starts = [s for s, _ in spans]
    reach = list(itertools.accumulate((e for _, e in spans), max))  # the latest end among the first k
    out = []
    for iv in busy:
        k = bisect.bisect_left(starts, iv.end)  # the connections that began before the interval ended
        if not k or reach[k - 1] < iv.start:  # and none of them was still open when it began
            out.append(Gap("flows", iv.start, iv.end, WHY_PORT))
    return out


def _quiet(conn: sqlite3.Connection, a: float, b: float, now: float) -> list[Gap]:
    """The live reading's quiet stretches that bear on [a, b): more than LIVE_GAP between two heartbeats, or
    from the last one to now, while an hourly reading in the stretch says the TV was on and no disconnect in
    it explains the quiet. A gateway that never ran the live reading has no heartbeat to miss, and the time
    before its first one is no gap."""
    alive = "FROM tv_events WHERE kind='alive' AND t"
    try:
        before = conn.execute(f"SELECT MAX(t) {alive} < ?", (a,)).fetchone()[0]
    except sqlite3.OperationalError:  # a store from before the live reading's table (schema 12)
        return []
    after = conn.execute(f"SELECT MIN(t) {alive} >= ?", (b,)).fetchone()[0]
    inside = [t for (t,) in conn.execute(f"SELECT t {alive} >= ? AND t < ? ORDER BY t", (a, b))]
    beats = [t for t in (before, *inside) if t is not None]
    if not beats:
        return []
    ends = [*beats[1:], now if after is None else after]
    marks = ",".join("?" * len(AWAKE))
    out = []
    for s, e in zip(beats, ends, strict=True):
        if e - s <= LIVE_GAP:
            continue
        on = conn.execute(
            f"SELECT 1 FROM tvstate WHERE t >= ? AND t < ? AND power IN ({marks}) LIMIT 1", (s, e, *AWAKE)
        ).fetchone()
        lost = conn.execute(
            "SELECT 1 FROM tv_events WHERE kind='conn' AND value='down' AND t >= ? AND t < ? LIMIT 1", (s, e)
        ).fetchone()
        if on and not lost:
            out.append(Gap("tvlive", s, e, WHY_BEAT))
    return out


def covered(conn: sqlite3.Connection, source: str, a: float, b: float, now: float | None = None) -> list[Gap]:
    """The stretches of [a, b) in which `source` was not looking, oldest first; none when it was. The
    window is judged up to `now` (the time of the reading): what is still to come is no gap."""
    now = time.time() if now is None else now
    if source in PREFIXES:
        gaps = _logs(conn, source, a, b, now) + (_holes(conn, a, b) if source == "flows" else [])
    elif source == "tvlive":
        gaps = _quiet(conn, a, b, now)
    else:
        raise ValueError(f"no source named {source!r}")
    return join(cut(gaps, a, min(b, now)))


def all_gaps(conn: sqlite3.Connection, a: float, b: float, now: float | None = None) -> dict[str, list[Gap]]:
    """Each source's gaps over [a, b); a source with none is present with an empty list."""
    return {src: covered(conn, src, a, b, now) for src in SOURCES}


def reconcile(conn: sqlite3.Connection, a: float, b: float) -> tuple[int, int, float | None]:
    """(port, flows, share): the bytes the TV's port carried to the TV in [a, b) by the sampler's counters
    (an interval across an edge by its share of time inside), the bytes to the TV of the connections the
    flow record ended in [a, b), and the second as a share of the first: None when the counters show
    nothing. The counters are the witness the flow record has to account for."""
    port = round(
        sum(iv.down * activity.overlap(iv, a, b) / (iv.end - iv.start) for iv in activity.buckets(conn, a, b))
    )
    (flows,) = conn.execute(
        "SELECT COALESCE(SUM(bytes_down), 0) FROM flows WHERE t_end >= ? AND t_end < ?", (a, b)
    ).fetchone()
    return port, flows, (flows / port if port else None)


def span(gaps: list[Gap]) -> str:
    """The gaps in words, `from 19:20 to 20:40`, those that overlap as one and several joined with `; `. A
    gap that ends at midnight ends at 24:00, and a start on another day than its end carries its weekday."""
    out = []
    for g in join([Gap("", g.a, g.b, "") for g in gaps]):
        start, end = datetime.fromtimestamp(g.a), datetime.fromtimestamp(g.b)
        last = (end - timedelta(microseconds=1)).date()  # the day the gap's last moment falls on
        until = "24:00" if end.date() != last else f"{end:%H:%M}"
        since = f"{start:%H:%M}" if start.date() == last else f"{start:%a %H:%M}"
        out.append(f"from {since} to {until}")
    return "; ".join(out)
