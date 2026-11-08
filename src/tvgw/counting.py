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
store's meta under META_KEY, when the current run began and when it was last seen. Nothing showing a
mechanism for RUN_GAP breaks its run (the gateway off, the setting turned off, the live reading stood
down), and the next sight begins a new one. A mechanism the store has no row for yet takes its start
from its own record (`Mechanism.backfill`): the first snapshot of its current run in fw_counters or
gw_samples, the oldest event of the live reading the store still keeps (TV_EVENTS_DAYS bounds it), or,
for the upload budget, the time its ceiling was set, which is always its start while the gateway's own
ceiling is the one in use.

**The judging.** Once a run's two weeks have passed, `status()` judges them where the record can: the
NTP count is clean with no request in them, the upload budget with no hour over its ceiling, the probe
with no failed test and no apply it would have undone. The in-path count's misses and the live
reading's bar are the owner's to judge: each miss needs a cause, and decision 67's bar is what `tvgw
receipt --replay` reports. Those two say they have counted two weeks and where the numbers are, never that
they are clean.

`write_file()` leaves the runs in `counting.txt` beside `tvgw verify`'s status file, mode 644, for `tvgw
status`, which reads no store: one line a mechanism, its key, its state and two times, nothing else.

Nothing here refuses or changes anything. A count that reaches two weeks changes nothing on its own.
"""

from __future__ import annotations

import json
import os
import sqlite3
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import datetime

from tvgw import db

TWO_WEEKS = 14 * 86400.0  # how long a mechanism counts before its wall may refuse, the owner deciding
RUN_GAP = 12 * 3600.0  # seconds with nothing showing a mechanism that break its run: every day has counted
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


def _live_backfill(conn: sqlite3.Connection, now: float) -> tuple[float, float] | None:
    """The live reading writes nothing while the TV is off, so its record has gaps of a day; its run is
    the whole of what the store keeps, from the oldest event to the newest."""
    try:
        oldest, newest = conn.execute("SELECT MIN(t), MAX(t) FROM tv_events WHERE t <= ?", (now,)).fetchone()
    except sqlite3.OperationalError:  # a store from before schema 12
        return None
    return None if oldest is None else (oldest, newest)


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
        f"its ceiling is set after {_when(due)}"
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


def _budget_active(o: Observation) -> bool:
    from tvgw import budget, config

    try:
        owner = config.upload_ceiling_bytes(getattr(o.s, "upload_ceiling", "auto")) is not None
    except ValueError:
        owner = False
    return owner or (o.budget or {}).get("state") == budget.FIXED


# ---- what two weeks hold ---------------------------------------------------------------------------------
def _ntp_judge(conn, since, until, profile, ceiling) -> Judgement:
    from tvgw import queries

    n = queries.ntp_servers(conn, since, until, profile)
    if not n["counted"]:
        return Judgement(None, "no snapshot of the count's table", "its record has a hole")
    req, addresses = n["requests"], n["addresses"]
    if not req:
        return Judgement(True, "0 requests", "the TV asked no time server")
    servers = "1 time server" if addresses == 1 else f"{addresses} time servers"
    return Judgement(False, f"{req} requests to {addresses} addresses", f"the TV asked {servers} {req} times")


def _budget_judge(conn, since, until, profile, ceiling) -> Judgement:
    from tvgw import budget

    rep = budget.report(conn, since, until, profile, ceiling)
    hours = len({e["hour"] for e in rep["events"]})
    found = f"{hours} destination-hours over the {rep['ceiling']}-byte ceiling"
    if not hours:
        return Judgement(True, found, "no hour went over it")
    return Judgement(False, found, "1 hour went over it" if hours == 1 else f"{hours} hours went over it")


def _probe_judge(conn, since, until, profile, ceiling) -> Judgement:
    runs = fails = unknown = 0
    for (raw,) in conn.execute(
        "SELECT tv_probe FROM gw_samples WHERE tv_probe IS NOT NULL AND t >= ? AND t < ?", (since, until)
    ):
        try:
            verdict = json.loads(raw).get("v")
        except (ValueError, AttributeError):
            verdict = None
        runs += 1
        fails += verdict == "fail"
        unknown += verdict not in ("pass", "fail")
    would = conn.execute(
        "SELECT COUNT(*) FROM changes WHERE kind = 'apply_would_revert' AND t >= ? AND t < ?", (since, until)
    ).fetchone()[0]
    found = f"{runs} runs: {fails} failed, {unknown} could not judge; {would} applies would have been undone"
    if not runs:  # a store forgotten since, or samples that were never kept: nothing to judge by
        return Judgement(None, found, "the gateway kept no record of its tests")
    if not fails and not would:
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
        f"{conns} went to addresses no lookup had given the TV",
    )


def _live_judge(conn, since, until, profile, ceiling) -> Judgement:
    return Judgement(
        None,
        "no stand-down in two weeks; tvgw receipt --replay holds design decision 67's bar",
        "it ran two weeks without stopping on its own",
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
        "The in-path address count",
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
        "The test client beside the TV",
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
        "The live reading",
        "which app is in front, as the TV reports it",
        "LIVE_READING=on",
        _live_active,
        _live_backfill,
        _live_judge,
        "",
        "Whether an app rule could be tried: sudo tvgw receipt --replay.",
    ),
)


def _ntp_set_row() -> str:
    from tvgw import queries

    return queries.NTP_SET_ROW


def _miss_rule() -> str:
    from tvgw import inpath

    return inpath.MISS_RULE


# ---- the runs ----------------------------------------------------------------------------------------------
def load(conn: sqlite3.Connection) -> dict[str, dict[str, float]]:
    """The meta row as {key: {"since", "last"}}, each entry with two numbers, the rest dropped."""
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
    return out


def observe(conn: sqlite3.Connection, obs: Observation, now: float) -> dict[str, dict[str, float]]:
    """One `tvgw verify --record` run's look at what is counting: each mechanism its run shows renews its
    row, or begins one (from its own record, when the store has none for it yet); a row last seen more
    than RUN_GAP ago, or begun after `now` (a clock set back), begins again. Rows of mechanisms the run
    does not show are left as they are, to age. Writes the meta row; the caller commits."""
    state = load(conn)
    for m in MECHANISMS:
        if not m.active(obs):
            continue
        row = state.get(m.key)
        if row is None:
            found = m.backfill(conn, now)
            state[m.key] = {"since": found[0] if found else now, "last": now}
        elif now - row["last"] > RUN_GAP or now < row["since"]:
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

    def as_dict(self) -> dict:
        j = self.judgement
        return {
            "key": self.key,
            "label": self.label,
            "plain": self.plain,
            "setting": self.setting,
            "state": self.state,
            "since": self.since,
            "last": self.last,
            "ends": self.ends,
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
    kept a row, each mechanism's own record says (read-only)."""
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
            row.state = STOPPED if now - run["last"] > RUN_GAP else COUNTING
        if row.state == COUNTING and row.since is not None:
            row.ends = row.since + TWO_WEEKS
            if row.ends <= until:
                row.state = REACHED
                if judge:
                    row.judgement = m.judge(conn, row.since, until, profile, upload_ceiling)
        out.append(row)
    return out


# ---- the words --------------------------------------------------------------------------------------------
def _when(t: float) -> str:
    return datetime.fromtimestamp(t).strftime("%Y-%m-%d %H:%M")


def engineering_line(r: dict) -> str:
    """One line of the brief's Counting section, from a row's `as_dict()`."""
    label, state = r["label"], r["state"]
    if state == OFF:
        return f"{label}: off" + (f" ({r['setting']} starts it)" if r.get("setting") else "")
    if state == WAITING:
        return f"{label}: waiting: {r['note']}"
    if state == STOPPED:
        return f"{label}: stopped, last seen {_when(r['last'])}; its two weeks start again when it next runs"
    head = f"{label}: counting since {_when(r['since'])}"
    if state == COUNTING:
        return f"{head}; two weeks end {_when(r['ends'])}"
    if r.get("found") is None:
        return f"{head}; two weeks ended {_when(r['ends'])}"
    clean = r.get("clean")
    verdict = " (clean)" if clean else " (not clean)" if clean is False else " (the owner judges)"
    return f"{head}; two weeks ended {_when(r['ends'])}: {r['found']}{verdict}"


def date_words(t: float, now: float) -> str:
    """`7 November`, with the year when it is not this year's."""
    from tvgw import plain

    d, n = datetime.fromtimestamp(t), datetime.fromtimestamp(now)
    text = f"{d.day} {plain.MONTHS[d.month - 1]}"
    return text if d.year == n.year else f"{text} {d.year}"


def plain_line(r: dict, now: float) -> str:
    """The plain brief's line for a mechanism whose two weeks have ended, from a row's `as_dict()`: what
    they hold, and what the owner may now decide. Never an action, and never a change: nothing refuses
    until the owner decides."""
    m = next(x for x in MECHANISMS if x.key == r["key"])
    since = date_words(r["since"], now)
    if r.get("clean"):
        return f"{r['plain']} has two clean weeks: {r['said']} since {since}. {m.clean_words}"
    said = f": {r['said']}" if r.get("said") else ""
    return f"{r['plain']} has counted for two weeks{said} since {since}. {m.other_words}"


# ---- the file `tvgw status` reads --------------------------------------------------------------------------
def file_beside(status_path: str) -> str:
    return os.path.join(os.path.dirname(status_path), FILE)


def file_text(rows: list[Row]) -> str:
    """`<key> <state> <since> <ends>` a line, `-` for a time not known: no name, no address, no detail."""

    def t(x: float | None) -> str:
        return "-" if x is None else str(int(x))

    return "".join(f"{r.key} {r.state} {t(r.since)} {t(r.ends)}\n" for r in rows)


def write_file(rows: list[Row], path: str) -> None:
    """Replace `path` whole, mode 644, as verify.write_status does: everyone may read it."""
    from tvgw import guard

    guard.write_atomic(path, file_text(rows), 0o644)


def parse_file(text: str) -> list[tuple[Mechanism, str, float | None, float | None]]:
    """The file's lines this version knows: (mechanism, state, since, ends). A line it cannot read, or of
    a mechanism it does not know, is skipped."""
    known = {m.key: m for m in MECHANISMS}
    out = []
    for line in text.splitlines():
        parts = line.split()
        if len(parts) != 4 or parts[0] not in known or parts[1] not in STATES:
            continue
        try:
            since, ends = (None if p == "-" else float(int(p)) for p in parts[2:])
        except ValueError:
            continue
        out.append((known[parts[0]], parts[1], since, ends))
    return out


def status_lines(text: str | None, now: float) -> list[str]:
    """`tvgw status`'s lines about what is counting, in plain words: one a mechanism that counts, nothing
    when none does or there is no file."""
    shown = []
    for m, state, since, ends in parse_file(text or ""):
        if state not in (COUNTING, REACHED) or since is None or ends is None:
            continue
        verb = "ended" if state == REACHED or ends <= now else "end"
        shown.append(
            f"  {m.counts}: since {date_words(since, now)}; its two weeks {verb} on {date_words(ends, now)}"
        )
    if not shown:
        return []
    return ["Counting, and refusing nothing until you decide:", *shown]
