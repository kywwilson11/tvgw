"""(counting) What is counting: every mechanism that counts and refuses nothing, what it counts, since when,
and the earliest day its two weeks end (design decision 72).

A new wall counts for two weeks before it may refuse anything (design decision 17's two clean weeks, the
rule decision 20 and research pass 4 kept), and whether it then refuses is the owner's decision. Six
mechanisms count today (`MECHANISMS`): the clock servers the TV asks (the NTP count), the upload budget,
the address gate's in-path filler, the probe from the TV's position, the live reading of the app in
front, and the trial record's coins and app starts (design decision 98). A later one adds one
`Mechanism` to the tuple.

**The runs.** A mechanism's two weeks are one run without a break. Every 10 minutes `tvgw verify
--record` looks at what its own run shows of each (`observe()`: the counters it stored, the probe's
verdict, the live reading's switch and its stand-down marker, the budget's ceiling) and keeps, in the
store's meta under META_KEY, when the current run began and when it was last seen: times of the gateway's
own runs, never of anything the TV did. Nothing showing a mechanism for RUN_GAP breaks its run (the
gateway off, the setting turned off), and so does a stand-down of the live reading at once
(`Mechanism.breaks`); the next sight begins a new one. A mechanism the store has no row for yet takes its
start from its own record (`Mechanism.backfill`): the first snapshot of its current run in fw_counters or
gw_samples, or, for the upload budget, the time its ceiling was set, which is always its start while the
gateway's own ceiling is the one in use. The live reading has none: its record is the TV's own events,
whose times say when the TV was watched, so its run starts at the first `verify --record` that sees it on.

**The judging.** Once a run's two weeks have passed, `status()` judges them where the record can, and
holds each judgement to what there was to refuse (design decision 97): the events a wall would have
refused, the exposure in the mechanism's own unit (`Mechanism.exposure`), the local days that exposure fell
on, and the rate the count rules out (`evidencekit.bound`). The NTP count's unit is the TV's starts, a wake
from standby or a boot (`starts()`), since a TV asks for the time when it starts and not each hour it is
on; the upload budget's, on-hours (`on_hours()`); the in-path count's, connections; the probe's, its runs.
Two weeks are clean only with no event, the exposure on at least `evidencekit.MIN_DAYS` local days, and a
bound of at least 1 in CLEAN_ONE_IN; short of that the owner judges, and the words say what they hold
("14 starts on 1 day of 15"). The probe also needs a passing run on every day (a run that could not judge
is no evidence either way). The in-path count's misses and the live reading's bar are the owner's to
judge: each miss needs a cause, and decision 67's bar is what `tvgw receipt --replay` reports. Those two
say they have counted two weeks and where the numbers are, never that they are clean.

A run's two weeks are judged once. `tvgw verify --record` keeps the judgement in the run's meta row
(`keep`) once their last connections have settled (`receipt.SETTLE` after their end) and the hourly ingest
has read past them, and every report reads it back, so the brief of a run a year old reads two weeks, not
a year. Before that, a report judges the same two weeks itself and keeps nothing. While the plain brief
says a clean two weeks (SINCE_LOOK), a report also reads the days since they ended: an event there makes
them not clean, so the brief never advises a wall the TV has just met.

`write_file()` leaves the runs in `counting.txt` beside `tvgw verify`'s status file, mode 644, for `tvgw
status`, which reads no store: one line a mechanism, its key, its state and two dates, nothing else. A
report carries the runs by the day too (`Row.as_dict()`): no time of day leaves the store.

Nothing here refuses or changes anything. A count that reaches two weeks changes nothing on its own.
"""

from __future__ import annotations

import dataclasses
import itertools
import json
import os
import sqlite3
from collections.abc import Callable, Iterable
from dataclasses import dataclass, field
from datetime import date, datetime, time

from tvgw import db, evidencekit

TWO_WEEKS = 14 * 86400.0  # how long a mechanism counts before its wall may refuse, the owner deciding
RUN_GAP = 12 * 3600.0  # seconds with nothing showing a mechanism that break its run: every day has counted
# Q7's bar: two weeks with nothing in them are clean only when they rule out a rate of 1 unit in this many
# (about 60 units with no event, at evidencekit.CONF); short of it the owner judges
CLEAN_ONE_IN = 20
SINCE_LOOK = 3 * 86400.0  # the days after two weeks a report also reads: the plain brief says them that long
META_KEY = "counting"  # the meta row: {key: {"since": t, "last": t, ...}} for every mechanism seen counting
FILE = "counting.txt"  # beside verify.STATUS
COUNTING, REACHED, STOPPED, WAITING, OFF = "counting", "reached", "stopped", "waiting", "off"
STATES = (COUNTING, REACHED, STOPPED, WAITING, OFF)


@dataclass
class Observation:
    """What one `tvgw verify --record` run shows: the settings it ran with, the counter and series names
    it stored, whether the probe ran, whether the live reading stood down, and the budget's meta row."""

    s: object  # config.Settings
    counters: set[str] = field(default_factory=set)
    probed: bool = False
    stood_down: bool = False
    budget: dict | None = None


@dataclass
class Judgement:
    clean: bool | None  # None: the owner judges
    found: str  # engineering words: what the two weeks hold
    said: str  # plain words: the same, for the plain brief's line
    events: int | None = None  # what the wall would have refused in them; None: the record could not count
    exposure: float | None = None  # how much there was to refuse, in `unit`s
    unit: str = ""  # the exposure's unit, singular: start, on-hour, connection, run
    days: int = 0  # the local days the exposure fell on
    bound: str = ""  # the rate the count rules out, in words (`evidencekit.Bound.words`)


@dataclass(frozen=True)
class Mechanism:
    key: str
    label: str  # the engineering brief's name
    plain: str  # the plain brief's name, a noun phrase that begins a sentence
    counts: str  # what it counts, in plain words, for `tvgw status`
    setting: str  # what turns it on, or "" when it always runs
    active: Callable[[Observation], bool]
    backfill: Callable[[sqlite3.Connection, float], tuple[float, float] | None]
    judge: Callable[[sqlite3.Connection, float, float, object, str], Judgement]
    clean_words: str  # the plain sentence after a clean two weeks
    other_words: str  # the plain sentence after two weeks that are not clean, or that the owner judges
    # a run that is not kept by observation: (state, since, note), or None to keep it as every other is
    start: Callable[[sqlite3.Connection, str, object, float], tuple[str, float | None, str] | None] | None = (
        None
    )
    # what in a run's look ends the mechanism's run at once, beside RUN_GAP (the live reading's stand-down)
    breaks: Callable[[Observation], bool] | None = None
    # what there was to refuse in [since, until): (amount, unit, local days it fell on); None when the owner
    # judges by other means and nothing is bounded
    exposure: Callable[[sqlite3.Connection, float, float], tuple[float, str, int]] | None = None
    cut: str = ""  # what a clean bound rules out, after it: "would have been cut off"


# ---- each mechanism's own record ---------------------------------------------------------------------------
def run_start(rows) -> tuple[float, float] | None:
    """(start, newest) of the run the newest of `rows` (times, newest first) belongs to: walked back until
    two consecutive times are more than RUN_GAP apart. None without a row."""
    newest = start = None
    for (t,) in rows:
        if newest is None:
            newest = start = t
        elif start - t > RUN_GAP:
            break
        else:
            start = t
    return None if newest is None else (start, newest)


def _series(rule: str) -> Callable[[sqlite3.Connection, float], tuple[float, float] | None]:
    def backfill(conn: sqlite3.Connection, now: float) -> tuple[float, float] | None:
        return run_start(
            conn.execute(
                "SELECT DISTINCT t FROM fw_counters WHERE rule = ? AND t <= ? ORDER BY t DESC", (rule, now)
            )
        )

    return backfill


def _probe_backfill(conn: sqlite3.Connection, now: float) -> tuple[float, float] | None:
    return run_start(
        conn.execute("SELECT t FROM gw_samples WHERE tv_probe IS NOT NULL AND t <= ? ORDER BY t DESC", (now,))
    )


def _no_backfill(conn: sqlite3.Connection, now: float) -> tuple[float, float] | None:
    """The live reading's own record is the TV's events, whose times say when the TV was watched: its run
    is never read from them, and starts at the first `verify --record` that sees the reading on."""
    return None


def _budget_backfill(conn: sqlite3.Connection, now: float) -> tuple[float, float] | None:
    from tvgw import budget

    row = budget.load(conn) or {}
    set_t = row.get("set_t")
    return (set_t, now) if row.get("state") == budget.FIXED and isinstance(set_t, int | float) else None


def _budget_start(
    conn: sqlite3.Connection, ceiling: str, profile, now: float
) -> tuple[str, float | None, str] | None:
    """The budget's run is its ceiling's: set at `set_t`, or waiting for the ingest to set it (a ceiling
    set for another profile or TV waits again, as `budget.report` reads it). With the owner's
    UPLOAD_CEILING, None: the run is kept as every other is."""
    from tvgw import budget, config

    try:
        if config.upload_ceiling_bytes(ceiling) is not None:
            return None
    except ValueError:
        return None
    row = budget.load(conn) or {}
    moved = profile is not None and row and budget.changed(row, budget.identity(conn, profile, now))
    if row.get("state") == budget.FIXED and isinstance(row.get("set_t"), int | float) and not moved:
        return COUNTING, float(row["set_t"]), ""
    due = row.get("due")
    note = (
        f"its ceiling is set after {_day(due)}"
        if isinstance(due, int | float)
        else "it waits for its ceiling"
    )
    return WAITING, None, note


def _ntp_active(o: Observation) -> bool:
    from tvgw import queries

    return queries.NTP_SET_ROW in o.counters


def _inpath_active(o: Observation) -> bool:
    from tvgw import inpath

    return getattr(o.s, "dnsgate_fill", "") == "inpath" and inpath.MISS_RULE in o.counters


def _live_active(o: Observation) -> bool:
    from tvgw import tvlive

    return (
        getattr(o.s, "live_reading", "") == "on"
        and getattr(o.s, "profile", "") == tvlive.PROFILE
        and not o.stood_down
    )


def _live_stood_down(o: Observation) -> bool:
    return o.stood_down


def _budget_active(o: Observation) -> bool:
    from tvgw import budget, config

    try:
        owner = config.upload_ceiling_bytes(getattr(o.s, "upload_ceiling", "auto")) is not None
    except ValueError:
        owner = False
    return owner or (o.budget or {}).get("state") == budget.FIXED


# ---- what there was to refuse: each mechanism's exposure, by local day -------------------------------------
def _by_day(times: Iterable[float]) -> dict[str, int]:
    out: dict[str, int] = {}
    for t in times:
        d = _day(t)
        out[d] = out.get(d, 0) + 1
    return out


def _exposure(unit: str, by_day: dict[str, float]) -> tuple[float, str, int]:
    """(amount, unit, the local days with some) of a mechanism's exposure by day."""
    return float(sum(by_day.values())), unit, sum(1 for v in by_day.values() if v > 0)


def starts(conn: sqlite3.Connection, since: float, until: float) -> dict[str, int]:
    """The TV's starts in [since, until), by local day: each wake from standby and each boot. On a day the
    live reading wrote power events, a start is an event that is on or idle after one that was off; on any
    other day, the TV port's carrier changes between two samples of one boot, where a loss and its return
    are two changes. A day's odd change is not counted, so the count never says more than the record does."""
    from tvgw import appfront

    out: dict[str, int] = {}
    before = None
    for t, state, processing in conn.execute(
        "SELECT t, COALESCE(value, ''), COALESCE(detail, '') FROM tv_events WHERE kind = 'power'"
        " AND t >= ? AND t < ? ORDER BY t, id",
        (since, until),
    ):
        day, now = _day(t), appfront.power_class(state, processing)
        out[day] = out.get(day, 0) + (before == appfront.OFF and now not in (None, appfront.OFF))
        before = now or before
    changes: dict[str, int] = {}
    samples = conn.execute(
        "SELECT t, boot_id, tv_cc FROM gw_samples WHERE t >= ? AND t < ? ORDER BY t", (since, until)
    )
    for (_t0, boot0, cc0), (t1, boot1, cc1) in itertools.pairwise(samples):
        day = _day(t1)
        if day in out or cc0 is None or cc1 is None or (boot0 and boot1 and boot0 != boot1):
            continue
        changes[day] = changes.get(day, 0) + max(0, cc1 - cc0)  # a count that went down was reset
    return out | {day: n // 2 for day, n in changes.items()}


def on_hours(conn: sqlite3.Connection, since: float, until: float) -> dict[str, float]:
    """Hours the TV was on in [since, until), by local day: the clock hours with an hourly reading that
    found it awake, or, where nothing reads the TV (no reading in the window), the hours the TV port's
    counters show it streaming or awake (`activity.hours_on`, a day at a time); empty when neither says."""
    from tvgw import activity, queries

    rows = conn.execute("SELECT t, power FROM tvstate WHERE t >= ? AND t < ?", (since, until)).fetchall()
    if rows:
        awake = {int(t // 3600) * 3600 for t, power in rows if power in queries.AWAKE}
        return {day: float(n) for day, n in _by_day(awake).items()}
    out = {}
    for day in _days(since, until):
        midnight = datetime.combine(date.fromisoformat(day), time()).timestamp()
        hours = activity.hours_on(conn, max(since, midnight), min(until, midnight + 86400))
        if hours:
            out[day] = hours
    return out


def _connections(conn: sqlite3.Connection, since: float, until: float) -> dict[str, int]:
    """The TV's connections the record holds as ended in [since, until) (flows' index is on the end), by
    the local day each began."""
    return _by_day(
        t
        for (t,) in conn.execute(
            "SELECT COALESCE(t_start, t_end) FROM flows WHERE t_end >= ? AND t_end < ?", (since, until)
        )
    )


def _runs(conn: sqlite3.Connection, since: float, until: float) -> dict[str, int]:
    return _by_day(
        t
        for (t,) in conn.execute(
            "SELECT t FROM gw_samples WHERE tv_probe IS NOT NULL AND t >= ? AND t < ?", (since, until)
        )
    )


# ---- what two weeks hold ---------------------------------------------------------------------------------
def _ntp_judge(conn, since, until, profile, ceiling) -> Judgement:
    from tvgw import queries

    n = queries.ntp_servers(conn, since, until, profile)
    if not n["counted"]:
        return Judgement(None, "no snapshot of the count's table", "its record has a hole")
    req, addresses = n["requests"], n["addresses"]
    if req:
        servers = "1 time server" if addresses == 1 else f"{addresses} time servers"
        return Judgement(
            False, f"{req} requests to {addresses} addresses", f"the TV asked {servers} {req} times", req
        )
    return Judgement(True, "0 requests", "the TV asked no time server", 0)


def _budget_judge(conn, since, until, profile, ceiling) -> Judgement:
    from tvgw import budget

    rep = budget.report(conn, since, until, profile, ceiling)
    hours = len({e["hour"] for e in rep["events"]})
    found = f"{hours} destination-hours over the {rep['ceiling']}-byte ceiling"
    if hours:
        said = "1 hour went over it" if hours == 1 else f"{hours} hours went over it"
        return Judgement(False, found, said, hours)
    return Judgement(True, found, "no hour went over it", 0)


def _probe_judge(conn, since, until, profile, ceiling) -> Judgement:
    runs = fails = unknown = 0
    passed_on: set[str] = set()  # the local days with a passing run
    for t, raw in conn.execute(
        "SELECT t, tv_probe FROM gw_samples WHERE tv_probe IS NOT NULL AND t >= ? AND t < ?", (since, until)
    ):
        try:
            verdict = json.loads(raw).get("v")
        except (ValueError, AttributeError):
            verdict = None
        runs += 1
        fails += verdict == "fail"
        unknown += verdict not in ("pass", "fail")
        if verdict == "pass":
            passed_on.add(_day(t))
    would = conn.execute(
        "SELECT COUNT(*) FROM changes WHERE kind = 'apply_would_revert' AND t >= ? AND t < ?", (since, until)
    ).fetchone()[0]
    found = f"{runs} runs: {fails} failed, {unknown} could not judge; {would} applies would have been undone"
    if not runs:  # a store forgotten since, or samples that were never kept: nothing to judge by
        return Judgement(None, found, "the gateway kept no record of its tests")
    if not fails and not would:
        days = _days(since, until)
        missing = len([d for d in days if d not in passed_on])
        if missing:  # a run that could not judge is no evidence either way
            words = "1 day" if missing == 1 else f"{missing} days"
            return Judgement(
                None,
                f"{found}; {missing} days without a passing run",
                f"no test failed, but on {words} none passed",
                0,
            )
        return Judgement(True, found, "no test failed and no change would have been undone", 0)
    tests = "1 test" if fails == 1 else f"{fails} tests"
    changes = "1 change" if would == 1 else f"{would} changes"
    return Judgement(False, found, f"{tests} failed and {changes} would have been undone", fails + would)


def _inpath_judge(conn, since, until, profile, ceiling) -> Judgement:
    from tvgw import inpath, queries

    # the miss rule's own series, read alone: a reload's zero reads as a restart, as it is, and the other
    # rules' two weeks of snapshots are not read at all
    misses = queries.series_gain(conn, inpath.MISS_RULE, since, until)
    passed_rule = next(rule for key, _fields, rule in inpath.SERIES if key == "kernel_passed")
    passed = queries.series_gain(conn, passed_rule, since, until)
    conns = "1 connection" if misses == 1 else f"{misses} connections"
    return Judgement(
        None,
        f"{misses} connections to addresses the filler never added; {passed} answers the kernel passed"
        " without it",
        f"{conns} went to addresses missing from the gateway's list of looked-up addresses",
        misses,
    )


def _trials_active(o: Observation) -> bool:
    return getattr(o.s, "trial", "off") == "record"


def _trials_backfill(conn: sqlite3.Connection, now: float) -> tuple[float, float] | None:
    """(trials) The trial record's run is its own rows': from its first to its newest."""
    from tvgw import trials

    first, newest = conn.execute(
        "SELECT MIN(t), MAX(t) FROM decisions WHERE stage = ? AND t <= ?", (trials.STAGE, now)
    ).fetchone()
    return None if first is None else (first, newest)


def _trials_judge(conn, since, until, profile, ceiling) -> Judgement:
    """(trials) The record is the owner's to read: what it measured, never a day's arm."""
    from tvgw import trials

    days = [d for d in trials.record(conn) if since <= trials.day_start(d.day) < until]
    starts, bad = sum(d.exposed for d in days), sum(d.bad for d in days)
    recorded = "1 day was" if len(days) == 1 else f"{len(days)} days were"
    return Judgement(
        None,
        f"{_n(len(days), 'day')} measured, {_n(starts, 'app start')}, {_n(bad, 'day')} with a failed start",
        f"{recorded} recorded and nothing was refused",
    )


def _live_judge(conn, since, until, profile, ceiling) -> Judgement:
    return Judgement(
        None,
        "no stand-down seen in two weeks; tvgw receipt --replay holds design decision 67's bar",
        "the gateway never saw it stop on its own",
    )


def _n(amount: float, unit: str) -> str:
    """`31 starts`, `1 day`: an exposure in words, rounded to whole units."""
    n = round(amount)
    return f"{n} {unit}" if n == 1 else f"{n} {unit}s"


def judge(
    m: Mechanism, conn: sqlite3.Connection, since: float, until: float, profile, ceiling: str
) -> Judgement:
    """`m`'s judgement of [since, until), held to its exposure. With no event, the words carry the exposure
    and the rate it rules out, and a judgement the mechanism calls clean stays clean only when that
    exposure fell on `evidencekit.MIN_DAYS` local days and rules out 1 unit in CLEAN_ONE_IN; short of either
    the owner judges, and the words say what the two weeks held. A judgement with no count (a hole in the
    record) or of a mechanism with no exposure is as the mechanism gave it, except never clean."""
    j = m.judge(conn, since, until, profile, ceiling)
    if m.exposure is None or j.events is None:  # nothing to bound it by: never clean
        return dataclasses.replace(j, clean=None) if j.clean else j
    amount, unit, days = m.exposure(conn, since, until)
    b = evidencekit.bound(j.events, amount, unit)
    j = dataclasses.replace(j, exposure=amount, unit=unit, days=days, bound=b.words())
    held = f"{_n(amount, unit)} on {_n(days, 'day')}"
    of = f"{held} of {len(_days(since, until))}"
    if j.events:
        return dataclasses.replace(j, found=f"{j.found}; {of}")
    found = f"{j.found}; {of}: {b.words()}"
    if not j.clean:
        return dataclasses.replace(j, found=found)
    if evidencekit.spread_ok(days) and b.one_in() >= CLEAN_ONE_IN:
        return dataclasses.replace(j, found=found, said=f"{j.said} across {held}: {b.words()} {m.cut}")
    return dataclasses.replace(
        j,
        clean=None,
        found=f"{found}, where clean needs {evidencekit.MIN_DAYS} days and 1 {unit} in {CLEAN_ONE_IN}",
        said=f"{j.said}, but across only {of}: too few to tell",
    )


MECHANISMS: tuple[Mechanism, ...] = (
    Mechanism(
        "ntp",
        "NTP count (the clock servers the TV asks, inet tvgw_ntp)",
        "The clock-server count",
        "the TV's requests to time servers",
        "",
        _ntp_active,
        lambda conn, now: _series(_ntp_set_row())(conn, now),
        _ntp_judge,
        "So the clock port could be closed for this TV. Nothing changes unless you decide it.",
        "Closing the clock port would cut those off; tvgw brief --full names the servers.",
        exposure=lambda conn, a, b: _exposure("start", starts(conn, a, b)),
        cut="would have been cut off",
    ),
    Mechanism(
        "budget",
        "Upload budget",
        "The upload budget",
        "uploads over the upload budget",
        "",
        _budget_active,
        _budget_backfill,
        _budget_judge,
        "That is the evidence a cap would need. Nothing changes unless you decide it.",
        "Whether each was wanted is your call; the daily full reports list them.",
        _budget_start,
        exposure=lambda conn, a, b: _exposure("on-hour", on_hours(conn, a, b)),
        cut="would have been capped",
    ),
    Mechanism(
        "inpath",
        "Address gate, in-path filler",
        "The address check",
        "connections to addresses the TV never looked up",
        "DNSGATE_FILL=inpath",
        _inpath_active,
        lambda conn, now: _series(_miss_rule())(conn, now),
        _inpath_judge,
        "",
        "Whether the gateway may refuse such connections is your decision; tvgw brief --full lists them.",
        exposure=lambda conn, a, b: _exposure("connection", _connections(conn, a, b)),
    ),
    Mechanism(
        "probe",
        "Probe from the TV's position",
        "The test from the TV's place",
        "a test from the TV's place every 10 minutes",
        "TV_PROBE=on",
        lambda o: o.probed,
        _probe_backfill,
        _probe_judge,
        "Whether the gateway may undo its own bad changes is now your decision.",
        "tvgw brief --full counts them; sudo tvgw probe runs one now.",
        exposure=lambda conn, a, b: _exposure("run", _runs(conn, a, b)),
        cut="could have failed",
    ),
    Mechanism(
        "live",
        "Live reading of the app in front",
        "The reading of which app is in front",
        "which app is in front, as the TV reports it",
        "LIVE_READING=on",
        _live_active,
        _no_backfill,
        _live_judge,
        "",
        "Whether an app rule could be tried: sudo tvgw receipt --replay.",
        breaks=_live_stood_down,
    ),
    Mechanism(
        "trials",
        "Trial record (coin flips and app starts; nothing is refused)",
        "The trial record",
        "coin flips and app starts, nothing refused",
        "TRIAL=record",
        _trials_active,
        _trials_backfill,
        _trials_judge,
        "",
        "What it says so far: sudo tvgw trial aa.",
    ),
)


def _ntp_set_row() -> str:
    from tvgw import queries

    return queries.NTP_SET_ROW


def _miss_rule() -> str:
    from tvgw import inpath

    return inpath.MISS_RULE


# ---- the runs ----------------------------------------------------------------------------------------------
def _number(x) -> bool:
    return isinstance(x, int | float) and not isinstance(x, bool)


def load(conn: sqlite3.Connection) -> dict[str, dict]:
    """The meta row as {key: {"since", "last"[, "broken"][, "judged"]}}, each entry with two numbers, the
    rest dropped. "judged" is the run's two weeks as judged once: {"since": the run's start, "j": the
    Judgement's fields}."""
    try:
        raw = json.loads(db.get_meta(conn, META_KEY) or "{}")
    except ValueError:
        return {}
    out = {}
    for key, row in raw.items() if isinstance(raw, dict) else ():
        if isinstance(row, dict) and _number(row.get("since")) and _number(row.get("last")):
            out[str(key)] = {"since": float(row["since"]), "last": float(row["last"])}
            if row.get("broken") is True:
                out[str(key)]["broken"] = True
            judged = row.get("judged")
            if (
                isinstance(judged, dict)
                and _number(judged.get("since"))
                and isinstance(judged.get("j"), dict)
            ):
                out[str(key)]["judged"] = judged
    return out


def observe(conn: sqlite3.Connection, obs: Observation, now: float) -> dict[str, dict]:
    """One `tvgw verify --record` run's look at what is counting: each mechanism its run shows renews its
    row, or begins one (from its own record, when the store has none for it yet); a row last seen more
    than RUN_GAP ago, broken (`Mechanism.breaks`), or begun after `now` (a clock set back), begins again.
    A mechanism whose run the look breaks is marked broken. Rows of mechanisms the run does not show are
    left as they are, to age. Writes the meta row; the caller commits."""
    state = load(conn)
    for m in MECHANISMS:
        if m.breaks is not None and m.breaks(obs) and m.key in state:
            state[m.key]["broken"] = True
        if not m.active(obs):
            continue
        row = state.get(m.key)
        if row is None:
            found = m.backfill(conn, now)
            state[m.key] = {"since": found[0] if found else now, "last": now}
        elif row.get("broken") or now - row["last"] > RUN_GAP or now < row["since"]:
            state[m.key] = {"since": now, "last": now}
        else:
            row["last"] = max(row["last"], now)
    db.set_meta(conn, META_KEY, json.dumps(state, sort_keys=True))
    return state


@dataclass
class Row:
    key: str
    label: str
    plain: str
    counts: str
    setting: str
    state: str
    since: float | None = None
    last: float | None = None
    ends: float | None = None
    judgement: Judgement | None = None
    note: str = ""
    days_past_end: int | None = None  # whole days from the end of its two weeks to the report's window end

    def as_dict(self) -> dict:
        """The row as a report carries it: dates, never a time of day."""
        j = self.judgement
        return {
            "key": self.key,
            "label": self.label,
            "plain": self.plain,
            "setting": self.setting,
            "state": self.state,
            "since": _day(self.since),
            "last": _day(self.last),
            "ends": _day(self.ends),
            "days_past_end": self.days_past_end,
            "clean": None if j is None else j.clean,
            "found": None if j is None else j.found,
            "said": None if j is None else j.said,
            "bound": None if j is None else j.bound,
            "exposure": None if j is None else j.exposure,
            "unit": None if j is None else j.unit,
            "days": None if j is None else j.days,
            "note": self.note,
        }


def status(
    conn: sqlite3.Connection,
    now: float,
    until: float | None = None,
    profile=None,
    upload_ceiling: str = "auto",
    judge: bool = True,
    keep: bool = False,
) -> list[Row]:
    """Every mechanism's run as of `now`: off (never seen counting), waiting (the budget, for its ceiling),
    stopped (not seen for RUN_GAP), counting, or reached (its two weeks ended by `until`, the report's
    window end). A reached run is judged over its two weeks when `judge`: the judgement kept in its meta
    row, else judged now. With `keep` (`tvgw verify --record`), a reached run's judgement is made and kept
    once their last connections have settled; the caller commits. Before any `verify --record` run of this
    version kept a row, each mechanism's own record says (read-only), the live reading's never."""
    from tvgw import receipt

    until = now if until is None else min(until, now)
    kept = db.get_meta(conn, META_KEY) is not None
    try:
        ingested = float(db.get_meta(conn, "last_run") or 0)  # when the hourly ingest last began
    except ValueError:
        ingested = 0.0
    state = load(conn)
    out = []
    for m in MECHANISMS:
        row = Row(m.key, m.label, m.plain, m.counts, m.setting, OFF)
        start = m.start(conn, upload_ceiling, profile, now) if m.start else None
        run = state.get(m.key)
        if run is None and not kept:
            found = m.backfill(conn, now)
            run = {"since": found[0], "last": found[1]} if found else None
        if start is not None:
            row.state, row.since, row.note = start
            row.last = now if row.state == COUNTING else None
        elif run is not None:
            row.since, row.last = run["since"], run["last"]
            row.state = STOPPED if run.get("broken") or now - run["last"] > RUN_GAP else COUNTING
        if row.state == COUNTING and row.since is not None:
            row.ends = row.since + TWO_WEEKS
            if row.ends <= until:
                row.state = REACHED
                row.days_past_end = int((until - row.ends) // 86400)
                # kept only once the ingest has read past the last connection the two weeks can hold
                settled = min(now, ingested) >= row.ends + receipt.SETTLE
                if judge or (keep and settled):
                    row.judgement = _judged(
                        conn, m, row.since, row.ends, state, profile, upload_ceiling, keep and settled
                    )
                if judge and row.judgement.clean and until - row.ends < SINCE_LOOK:
                    row.judgement = _since(conn, m, row.judgement, row.ends, until, profile, upload_ceiling)
        out.append(row)
    return out


def _since(
    conn: sqlite3.Connection, m: Mechanism, j: Judgement, ends: float, until: float, profile, ceiling: str
) -> Judgement:
    """Clean two weeks, held to the days since they ended while the plain brief says them: a wall that has
    met something since is no longer one the owner should be told could refuse."""
    later = m.judge(conn, ends, until, profile, ceiling)
    if not later.events:
        return j
    return dataclasses.replace(
        j,
        clean=False,
        found=f"{j.found}; since they ended, {later.found}",
        said=f"{later.said} since they ended",
    )


def _judged(
    conn: sqlite3.Connection,
    m: Mechanism,
    since: float,
    ends: float,
    state: dict,
    profile,
    ceiling: str,
    keep: bool,
) -> Judgement:
    """A reached run's two weeks [since, ends), as kept in its meta row; else judged, and kept in the row
    when `keep`. A kept judgement of an earlier run, or one this version cannot read, is judged again."""
    run = state.get(m.key)
    kept = (run or {}).get("judged") or {}
    if kept.get("since") == since:
        try:
            return Judgement(**kept["j"])
        except TypeError:
            pass
    j = judge(m, conn, since, ends, profile, ceiling)
    if keep and run is not None:
        run["judged"] = {"since": since, "j": dataclasses.asdict(j)}
        db.set_meta(conn, META_KEY, json.dumps(state, sort_keys=True))
    return j


# ---- the words --------------------------------------------------------------------------------------------
def _day(t: float | None) -> str | None:
    """The local date of a time, `2026-11-07`, or None: what leaves the store of a run's times."""
    return None if t is None else datetime.fromtimestamp(t).strftime("%Y-%m-%d")


def _days(a: float, b: float) -> list[str]:
    """The local dates [a, b) touches."""
    out, d = [], datetime.fromtimestamp(a).date()
    last = datetime.fromtimestamp(max(a, b - 1)).date()
    while d <= last:
        out.append(d.isoformat())
        d = date.fromordinal(d.toordinal() + 1)
    return out


def engineering_line(r: dict) -> str:
    """One line of the brief's Counting section, from a row's `as_dict()`."""
    label, state = r["label"], r["state"]
    if state == OFF:
        return f"{label}: off" + (f" ({r['setting']} starts it)" if r.get("setting") else "")
    if state == WAITING:
        return f"{label}: waiting: {r['note']}"
    if state == STOPPED:
        return f"{label}: stopped, last seen {r['last']}; its two weeks start again when it next runs"
    head = f"{label}: counting since {r['since']}"
    if state == COUNTING:
        return f"{head}; two weeks end {r['ends']}"
    if r.get("found") is None:
        return f"{head}; two weeks ended {r['ends']}"
    clean = r.get("clean")
    verdict = " (clean)" if clean else " (not clean)" if clean is False else " (the owner judges)"
    return f"{head}; two weeks ended {r['ends']}: {r['found']}{verdict}"


def date_words(day: str, now: float) -> str:
    """`7 November` for `2026-11-07`, with the year when it is not this year's."""
    from tvgw import plain

    d, n = date.fromisoformat(day), datetime.fromtimestamp(now)
    text = f"{d.day} {plain.MONTHS[d.month - 1]}"
    return text if d.year == n.year else f"{text} {d.year}"


def plain_line(r: dict, now: float) -> str:
    """The plain brief's line for a mechanism whose two weeks have ended, from a row's `as_dict()`: what
    they hold, and what the owner may now decide. Never an action, and never a change: nothing refuses
    until the owner decides."""
    m = next(x for x in MECHANISMS if x.key == r["key"])
    since = date_words(r["since"], now)
    if r.get("clean"):
        return f"{r['plain']} has two clean weeks, since {since}: {r['said']}. {m.clean_words}"
    said = f": {r['said']}" if r.get("said") else ""
    return f"{r['plain']} has counted for two weeks, since {since}{said}. {m.other_words}"


# ---- the file `tvgw status` reads --------------------------------------------------------------------------
def file_beside(status_path: str) -> str:
    return os.path.join(os.path.dirname(status_path), FILE)


def file_text(rows: list[Row]) -> str:
    """`<key> <state> <since> <ends>` a line, each a date (`-` for none): no time of day, no name, no
    address, no detail."""
    return "".join(f"{r.key} {r.state} {_day(r.since) or '-'} {_day(r.ends) or '-'}\n" for r in rows)


def write_file(rows: list[Row], path: str) -> None:
    """Replace `path` whole, mode 644, as verify.write_status does: everyone may read it."""
    from tvgw import guard

    guard.write_atomic(path, file_text(rows), 0o644)


def parse_file(text: str) -> list[tuple[Mechanism, str, str | None, str | None]]:
    """The file's lines this version knows: (mechanism, state, since, ends), the dates as written. A line
    it cannot read, or of a mechanism it does not know, is skipped."""
    known = {m.key: m for m in MECHANISMS}
    out = []
    for line in text.splitlines():
        parts = line.split()
        if len(parts) != 4 or parts[0] not in known or parts[1] not in STATES:
            continue
        try:
            since, ends = (None if p == "-" else date.fromisoformat(p).isoformat() for p in parts[2:])
        except ValueError:
            continue
        out.append((known[parts[0]], parts[1], since, ends))
    return out


STALE = 30 * 60  # seconds: three missed 10-minute records, as status.STALE judges the checks


def status_lines(text: str | None, now: float, age: float | None = None) -> list[str]:
    """`tvgw status`'s lines about what is counting, in plain words: a heading and one a mechanism that
    counts, nothing when none does or there is no file; one line saying so when the file is older than
    STALE (`age`, in seconds), since the record that writes it has then stopped."""
    if text is not None and age is not None and age > STALE:
        hours = max(1, round(age / 3600))
        return [
            f"What is counting is not known: it was last recorded {hours} hour{'s' if hours > 1 else ''} ago."
        ]
    shown = []
    today = _day(now)
    for m, state, since, ends in parse_file(text or ""):
        if state not in (COUNTING, REACHED) or since is None or ends is None:
            continue
        verb = "ended" if state == REACHED or ends <= today else "end"
        shown.append(
            f"  {m.counts}: since {date_words(since, now)}; its two weeks {verb} on {date_words(ends, now)}"
        )
    if not shown:
        return []
    return ["Counting, and refusing nothing until you decide:", *shown]
