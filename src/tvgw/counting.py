"""(counting) What is counting: every mechanism that counts and refuses nothing, what it counts, since when,
and the earliest day its two weeks end (design decision 72).

A new wall counts for two weeks before it may refuse anything (design decision 17's two clean weeks, the
rule decision 20 and research pass 4 kept), and whether it then refuses is the owner's decision. Five
mechanisms count today (`MECHANISMS`): the clock servers the TV asks (the NTP count), the upload budget,
the address gate's in-path filler, the probe from the TV's position, and the live reading of the app in
front. A later one adds one `Mechanism` to the tuple.

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

**The judging.** Once a run's two weeks have passed, `status()` judges them where the record can: the
NTP count is clean with no request in them and the upload budget with no hour over its ceiling, each only
when the TV was on for MIN_ON_HOURS of them (a TV left off for two weeks asks nothing and uploads nothing),
and the probe with no failed test, no apply it would have undone and a passing test on every day (a run
that could not judge is no evidence either way). The in-path count's misses and the live
reading's bar are the owner's to judge: each miss needs a cause, and decision 67's bar is what `tvgw
receipt --replay` reports. Those two say they have counted two weeks and where the numbers are, never that
they are clean.

`write_file()` leaves the runs in `counting.txt` beside `tvgw verify`'s status file, mode 644, for `tvgw
status`, which reads no store: one line a mechanism, its key, its state and two dates, nothing else. A
report carries the runs by the day too (`Row.as_dict()`): no time of day leaves the store.

Nothing here refuses or changes anything. A count that reaches two weeks changes nothing on its own.
"""

from __future__ import annotations

import json
import os
import sqlite3
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import date, datetime

from tvgw import db

TWO_WEEKS = 14 * 86400.0  # how long a mechanism counts before its wall may refuse, the owner deciding
RUN_GAP = 12 * 3600.0  # seconds with nothing showing a mechanism that break its run: every day has counted
MIN_ON_HOURS = (
    14  # clock hours the TV was on in two weeks, about one a day, before "nothing happened" is clean
)
META_KEY = "counting"  # the meta row: {key: {"since": t, "last": t}} for every mechanism seen counting
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


# ---- what two weeks hold ---------------------------------------------------------------------------------
def on_hours(conn: sqlite3.Connection, since: float, until: float) -> float:
    """Hours the TV was on in [since, until): the clock hours with an hourly reading that found it awake,
    or, where nothing reads the TV (no reading in the window), the hours the TV port's counters show it
    streaming or awake (`activity.hours_on`); 0 when neither says."""
    from tvgw import activity, queries

    rows = conn.execute("SELECT t, power FROM tvstate WHERE t >= ? AND t < ?", (since, until)).fetchall()
    if rows:
        return float(len({int(t // 3600) for t, power in rows if power in queries.AWAKE}))
    return activity.hours_on(conn, since, until) or 0.0


def _too_few(found: str, hours: float) -> Judgement | None:
    """None when the TV was on enough for an empty two weeks to mean something; else the owner judges."""
    if hours >= MIN_ON_HOURS:
        return None
    h = round(hours)
    return Judgement(
        None,
        f"{found}; the TV was on about {h} hours (under {MIN_ON_HOURS})",
        f"the TV was on about {h} hours in them, too few to tell",
    )


def _ntp_judge(conn, since, until, profile, ceiling) -> Judgement:
    from tvgw import queries

    n = queries.ntp_servers(conn, since, until, profile)
    if not n["counted"]:
        return Judgement(None, "no snapshot of the count's table", "its record has a hole")
    req, addresses = n["requests"], n["addresses"]
    if req:
        servers = "1 time server" if addresses == 1 else f"{addresses} time servers"
        return Judgement(
            False, f"{req} requests to {addresses} addresses", f"the TV asked {servers} {req} times"
        )
    return _too_few("0 requests", on_hours(conn, since, until)) or Judgement(
        True, "0 requests", "the TV asked no time server"
    )


def _budget_judge(conn, since, until, profile, ceiling) -> Judgement:
    from tvgw import budget

    rep = budget.report(conn, since, until, profile, ceiling)
    hours = len({e["hour"] for e in rep["events"]})
    found = f"{hours} destination-hours over the {rep['ceiling']}-byte ceiling"
    if hours:
        return Judgement(False, found, "1 hour went over it" if hours == 1 else f"{hours} hours went over it")
    return _too_few(found, on_hours(conn, since, until)) or Judgement(True, found, "no hour went over it")


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
            )
        return Judgement(True, found, "no test failed and no change would have been undone")
    tests = "1 test" if fails == 1 else f"{fails} tests"
    changes = "1 change" if would == 1 else f"{would} changes"
    return Judgement(False, found, f"{tests} failed and {changes} would have been undone")


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
    )


def _live_judge(conn, since, until, profile, ceiling) -> Judgement:
    return Judgement(
        None,
        "no stand-down seen in two weeks; tvgw receipt --replay holds design decision 67's bar",
        "the gateway never saw it stop on its own",
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
)


def _ntp_set_row() -> str:
    from tvgw import queries

    return queries.NTP_SET_ROW


def _miss_rule() -> str:
    from tvgw import inpath

    return inpath.MISS_RULE


# ---- the runs ----------------------------------------------------------------------------------------------
def load(conn: sqlite3.Connection) -> dict[str, dict]:
    """The meta row as {key: {"since", "last"[, "broken"]}}, each entry with two numbers, the rest dropped."""
    try:
        raw = json.loads(db.get_meta(conn, META_KEY) or "{}")
    except ValueError:
        return {}
    out = {}
    for key, row in raw.items() if isinstance(raw, dict) else ():
        if isinstance(row, dict) and all(
            isinstance(row.get(k), int | float) and not isinstance(row.get(k), bool)
            for k in ("since", "last")
        ):
            out[str(key)] = {"since": float(row["since"]), "last": float(row["last"])}
            if row.get("broken") is True:
                out[str(key)]["broken"] = True
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
            "note": self.note,
        }


def status(
    conn: sqlite3.Connection,
    now: float,
    until: float | None = None,
    profile=None,
    upload_ceiling: str = "auto",
    judge: bool = True,
) -> list[Row]:
    """Every mechanism's run as of `now`: off (never seen counting), waiting (the budget, for its ceiling),
    stopped (not seen for RUN_GAP), counting, or reached (its two weeks ended by `until`, the report's
    window end, judged over [since, until) when `judge`). Before any `verify --record` run of this version
    kept a row, each mechanism's own record says (read-only), the live reading's never."""
    until = now if until is None else min(until, now)
    kept = db.get_meta(conn, META_KEY) is not None
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
                if judge:
                    row.judgement = m.judge(conn, row.since, until, profile, upload_ceiling)
        out.append(row)
    return out


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
