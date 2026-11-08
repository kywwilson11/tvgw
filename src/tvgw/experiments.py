"""(experiments) `tvgw experiment`: the cheapest experiment of five of research pass 4's inventions, each a
report over the store that changes nothing (design decision 75).

Each answers the question a later rule would have to answer first, from what the gateway already
recorded. None of them refuses, holds, sends or writes anything: the store is opened read-only, and the
only thing built in memory is the ACR meter's positive control.

- **probation**, the evidence for new-name probation: registrable domains first seen after the record's
  first WARMUP_DAYS days, week by week (ISO weeks, local time), each with what the profile says it is,
  the company behind it, whether the filter refused it and whether the TV reached it. A domain the
  filter did not wholly refuse is one a rule that holds every new name until it is judged would have
  held; that weekly count is what such a rule would cost. A domain first reached with no lookup in the
  store is counted apart: a rule at the resolver cannot hold what was never looked up.
- **platform**, the evidence for just-in-time platform access: the lookups of, and connections to, each
  must-allow host and each clock host, by the TV's state at that moment (an app in front, the home
  screen, an input, a cast receiver, the screen saver, off, unknown), from the hourly readings and the
  live record (`appfront.timeline()`), with the hours spent in each state, so it is visible which
  platform host is needed when.
- **fanout**, fan-out association for unclassified names: for each name the profile has no category for
  and the filter answered, the classified names and the refused lookups that come within FANOUT_WINDOW
  seconds before or after it, across days, against the base rate of each neighbour. The ten most
  associated, with the sentence that this is association, not proof.
- **acr**, the "ACR uploads per viewing hour" meter: what the TV sent names in the profile's ACR
  category, beyond what came back on the same connections (`budget.net_up()`), and the uploads the ACR
  test of design decision 45 flags (`queries.acr_uploader()`), each per hour the TV was on; with the
  TV's consent readings and, beside it, a positive control: one hour shaped like IMC 2024's quietest
  measured hour of LG's screen recognition, run through the same code, so a zero reads as the meter
  seeing nothing and not as a meter that cannot see.
- **firmware**, the before-and-after report: for each change of the TV's software the hourly reading
  recorded (`queries.firmware_changes()`), the FIRMWARE_DAYS days before against the days after:
  registrable domains, ports, TLS stacks (JA4), record types and lookups a day; with an A/A comparison of
  two adjacent windows of the same length with no change between them, the noise floor the real
  comparison is read against.
"""

from __future__ import annotations

import bisect
import contextlib
import sqlite3
from collections import Counter, defaultdict
from datetime import datetime, timedelta
from fnmatch import fnmatchcase

from tvgw import appfront, budget, companies, db, lgwebos, queries
from tvgw.appfront import CAST, GAP, HOME, INPUT, NONE, SESSION
from tvgw.names import is_public_address, is_public_name, registrable_domain
from tvgw.profile import Profile, covers

DAY = 86400.0
# days of record before a domain counts as new: a store's first fortnight sees everything for the first
# time. The research's two weeks (research pass 4, "New-name probation")
WARMUP_DAYS = 14
DEFAULT_DAYS = 14  # the window of the platform, fan-out and ACR reports when --days gives none
MAX_DAYS = 400
# the TV's states, in the order the platform and ACR reports print them: the four kinds of session
# (appfront.app_kind), the screen saver (the TV on and idle, the app still in front), the TV off at both
# ends of a reading's hour, and a gap (nothing says which app was in front, or whether the TV was on)
APP_STATE, HOME_STATE, INPUT_STATE, CAST_STATE = "app", "home", "input", "cast"
IDLE_STATE, OFF_STATE, UNKNOWN_STATE = "idle", "off", "unknown"
STATES = (APP_STATE, HOME_STATE, INPUT_STATE, CAST_STATE, IDLE_STATE, OFF_STATE, UNKNOWN_STATE)
ON_STATES = (APP_STATE, HOME_STATE, INPUT_STATE, CAST_STATE, IDLE_STATE)  # the TV on: the meter's hours
STATE_WORDS = {
    APP_STATE: "an app in front",
    HOME_STATE: "the home screen",
    INPUT_STATE: "an input (HDMI, live TV)",
    CAST_STATE: "a cast receiver",
    IDLE_STATE: "the screen saver",
    OFF_STATE: "off",
    UNKNOWN_STATE: "unknown",
}
# (fanout) seconds either side of an unclassified lookup in which a neighbour counts: research pass 4's
# "within 2 s", the time an app's start or an ad call takes to ask for its next names
FANOUT_WINDOW = 2.0
# lookups of one unclassified domain this close together are one episode: retries and a page's several
# names are one moment, not several pieces of evidence
FANOUT_EPISODE_GAP = 10.0
FANOUT_MIN_DAYS = 2  # an unclassified domain is ranked only when it was looked up on this many local days
FANOUT_MIN_EPISODES = 3
FANOUT_TOP = 10
FANOUT_NEIGHBOURS = 3  # neighbours shown per unclassified domain
# a neighbour is shown, and counts toward the ranking, only when it comes next to the unclassified name at
# least this many times as often as next to the TV's other lookups: below it, two names that only share
# the TV's busy moments look associated
FANOUT_MIN_LIFT = 2.0
REFUSED = "refused"
HIT_LABELS = (REFUSED, appfront.TRACKING)  # what a neighbour must be to count toward the ranking
ASSOCIATION = (
    "Association, not proof: a name that comes shortly before or after refused or tracking lookups may be"
    " the server of the app that asks for the ads, not a tracker itself. Check each one by hand before any"
    " rule uses it."
)
# (acr) the meter's category: the profile's screen-recognition names (lg-webos: alphonso.tv, samba.tv)
ACR_CATEGORY = "ACR"
# (acr) the positive control: one clock hour of IMC 2024's quietest measured LG fingerprinting, 4,125.0 KB
# of Ethernet frames both ways (deep dive 13, section 1.3), at CONTROL_RATIO up to down and every frame
# full-size, the down side too: the corner budget.ACR_HOUR_NET is estimated at, so the control's net is
# the smallest that hour can net at that ratio. On CONTROL_CONNS connections to CONTROL_PORT, one a minute,
# as the trace's client opens them, with an input in front (where IMC measured it)
CONTROL_FRAMES = 4_125_000
CONTROL_RATIO = 7
CONTROL_CONNS = 60
CONTROL_PORT = 4431
FULL_FRAME, ETHERNET = 1_514, 14  # a full frame and its Ethernet header, which conntrack does not count
CONTROL_APP = "com.webos.app.hdmi1"
# (firmware) days either side of a software change, and the length of each A/A window
FIRMWARE_DAYS = 14
# seconds before the reading that found new software at which its after-window starts: the hourly reading
# sees an update that happened since the reading before it, as queries.firmware_changes() reads the names
# that followed one
UPDATE_LEAD = 3600.0
# a window with lookups on fewer of its days is thin, and the comparison says so: a capture or ingest gap
# makes things vanish that never left
FIRMWARE_MIN_DAYS = 10
# a count is marked "above the floor" when it is more than FLOOR_TIMES times the A/A comparison's and at
# least its feature's FLOOR_MARGIN over it: a quiet fortnight brings new registrable domains of its own (an
# app's new delivery network), so three is the least that stands out; it rarely brings a new port, TLS
# stack or record type (the reference TV asked for no type but A and AAAA to 2026-11-05), so one does
FLOOR_TIMES = 2
FLOOR_MARGIN = {"domains": 3, "ports": 1, "stacks": 1, "qtypes": 1}
FEATURES = ("domains", "ports", "stacks", "qtypes")
FEATURE_WORDS = {
    "domains": "registrable domains",
    "ports": "ports",
    "stacks": "TLS stacks (JA4)",
    "qtypes": "record types",
}
SHOWN = 8  # items listed per feature before "and N more"


# ---- shared ------------------------------------------------------------------------------------------
def local_day(t: float) -> str:
    return datetime.fromtimestamp(t).strftime("%Y-%m-%d")


def local_time(t: float) -> str:
    return datetime.fromtimestamp(t).strftime("%Y-%m-%d %H:%M")


def iso_week(t: float) -> str:
    return datetime.fromtimestamp(t).strftime("%G-W%V")


def size(n: float | None) -> str:
    """Bytes in the pages' units (powers of 1024), with a space: `1.4 MB`."""
    n = float(n or 0)
    for unit in ("B", "KB", "MB"):
        if n < 1024:
            return f"{n:.0f} B" if unit == "B" else f"{n:.1f} {unit}"
        n /= 1024
    return f"{n:.1f} GB"


def days_after(t: float, days: int) -> float:
    """The local midnight `days` calendar days after the local midnight that begins `t`'s day: a day the
    clocks change on has 23 or 25 hours and still counts as one."""
    d = datetime.fromtimestamp(t)
    return (datetime(d.year, d.month, d.day) + timedelta(days=days)).timestamp()


def plural(n: int, word: str) -> str:
    return f"{n} {word}{'' if n == 1 else 's'}"


def record_start(conn: sqlite3.Connection) -> float | None:
    """When the store's record starts: its first ingest run or the first sighting of any name, whichever
    is earlier (a first ingest can load days of the resolver's log at once). None for an empty store."""
    first = queries.first_ingest(conn)
    seen = conn.execute("SELECT MIN(first_seen) FROM hosts").fetchone()[0]
    found = [t for t in (first, seen) if t is not None]
    return min(found) if found else None


def _domain_of(cache: dict[str, str | None], name: str) -> str | None:
    """The registrable domain of an internet name, None for anything else (a home name, an address)."""
    if name not in cache:
        cache[name] = registrable_domain(name) if name and is_public_name(name) else None
    return cache[name]


# ---- 1. new-name probation -----------------------------------------------------------------------------
HELD_STATUSES = ("answered", "partly refused")  # what a rule at the resolver would have held


def _status(answered: int, refused: int) -> str:
    if answered and refused:
        return "partly refused"
    if refused:
        return "refused"
    return "answered" if answered else "no lookup"


def probation(conn: sqlite3.Connection, profile: Profile, now: float) -> dict:
    """First-seen registrable domains, week by week, after the record's first WARMUP_DAYS days.

    {"state": "empty" | "warming" | "counted", "start", "counted_from", "weeks": [...], "domains": [...],
    "summary": {...}}. A domain is new in the week of the first sighting of any name under it (`hosts`,
    which every source fills and nothing prunes); its lookups and hellos are counted from that moment to
    `now`. `held` says a rule that holds a new domain until it is judged would have held it: the filter
    answered at least one of its lookups."""
    start = record_start(conn)
    if start is None:
        return {"state": "empty"}
    counted_from = days_after(start, WARMUP_DAYS)
    if counted_from >= now:
        return {"state": "warming", "start": start, "counted_from": counted_from}
    cache: dict[str, str | None] = {}
    first: dict[str, tuple[float, str]] = {}
    for name, seen in conn.execute("SELECT name, first_seen FROM hosts WHERE first_seen IS NOT NULL"):
        d = _domain_of(cache, name)
        if d is not None and (d not in first or (seen, name) < first[d]):
            first[d] = (seen, name)
    new = {d: v for d, v in first.items() if counted_from <= v[0] < now}
    looked: dict[str, list[int]] = defaultdict(lambda: [0, 0])  # domain -> [answered, refused]
    for qname, blocked, n in conn.execute(
        "SELECT qname, blocked, COUNT(*) FROM dns WHERE t >= ? AND t < ? GROUP BY qname, blocked",
        (counted_from, now),
    ):
        d = _domain_of(cache, qname)
        if d in new:
            looked[d][1 if blocked else 0] += n
    hellos: Counter[str] = Counter()
    for sni, n in conn.execute(
        "SELECT sni, COUNT(*) FROM tls WHERE t >= ? AND t < ? GROUP BY sni", (counted_from, now)
    ):
        d = _domain_of(cache, sni)
        if d in new:
            hellos[d] += n
    domains = []
    for d, (seen, name) in sorted(new.items(), key=lambda kv: (kv[1][0], kv[0])):
        kind = appfront.classify(profile, name)
        answered, refused = looked[d]
        status = _status(answered, refused)
        domains.append(
            {
                "domain": d,
                "name": name,
                "first": seen,
                "week": iso_week(seen),
                "class": kind.cls,
                "category": kind.category,
                "company": companies.company(name),
                "status": status,
                "answered": answered,
                "refused": refused,
                "hellos": hellos[d],
                "held": status in HELD_STATUSES,
            }
        )
    weeks = _weeks(counted_from, now, domains)
    full = [w for w in weeks if not w["partial"]]
    held = [w["held"] for w in full]
    return {
        "state": "counted",
        "start": start,
        "counted_from": counted_from,
        "weeks": weeks,
        "domains": domains,
        "summary": {
            "full_weeks": len(full),
            "new": len(domains),
            "held": sum(1 for x in domains if x["held"]),
            "held_per_week": round(sum(held) / len(held), 1) if held else None,
            "held_most": max(held) if held else None,
            "platform_held": sum(1 for x in domains if x["held"] and x["class"] == appfront.PLATFORM),
            "no_lookup": sum(1 for x in domains if x["status"] == "no lookup"),
        },
    }


def _weeks(a: float, b: float, domains: list[dict]) -> list[dict]:
    """One row per ISO week that [a, b) touches, clipped to it; a week not wholly inside is partial."""
    out, t = [], a
    while t < b:
        w = iso_week(t)
        w0, w1 = queries.week_bounds(w)
        lo, hi = max(w0, a), min(w1, b)
        mine = [x for x in domains if lo <= x["first"] < hi]
        held = [x for x in mine if x["held"]]
        out.append(
            {
                "week": w,
                "from": lo,
                "to": hi,
                "days": round((hi - lo) / DAY, 1),
                "partial": lo > w0 or hi < w1,
                "new": len(mine),
                "refused": sum(1 for x in mine if x["status"] == "refused"),
                "held": len(held),
                "no_lookup": sum(1 for x in mine if x["status"] == "no lookup"),
                "held_by_class": dict(sorted(Counter(x["class"] for x in held).items())),
            }
        )
        t = w1
    return out


def render_probation(r: dict) -> list[str]:
    head = "New-name probation, evidence only: nothing is held."
    if r["state"] == "empty":
        return [head, "The store holds no record yet."]
    if r["state"] == "warming":
        return [
            head,
            f"The record starts {local_time(r['start'])}; names count as new only after its first"
            f" {WARMUP_DAYS} days, from {local_time(r['counted_from'])}.",
        ]
    s = r["summary"]
    lines = [
        head,
        f"Registrable domains first seen after the record's first {WARMUP_DAYS} days (from"
        f' {local_time(r["counted_from"])}), by ISO week. "Would hold" counts the new domains the filter'
        " answered at least once: what a rule that holds every new name until it is judged would have held.",
        "",
        f"{'week':<9} {'days':>5} {'new':>4} {'refused':>8} {'would hold':>11}  held, by class",
    ]
    for w in r["weeks"]:
        by = ", ".join(f"{k} {v}" for k, v in w["held_by_class"].items()) or "-"
        days = f"{w['days']:g}{'*' if w['partial'] else ''}"
        lines.append(f"{w['week']:<9} {days:>5} {w['new']:>4} {w['refused']:>8} {w['held']:>11}  {by}")
    lines.append("* a part week")
    if s["held_per_week"] is None:
        lines.append("No whole week has been counted yet.")
    else:
        lines.append(
            f"Over {s['full_weeks']} whole week{'s' if s['full_weeks'] != 1 else ''} a rule would have held"
            f" {s['held_per_week']:g} new domains a week, at most {s['held_most']}."
        )
    if s["platform_held"]:
        n = s["platform_held"]
        lines.append(
            f"Of them, {plural(n, 'domain')} the TV must reach: a rule would have to let"
            f" {'it' if n == 1 else 'them'} through whatever it holds."
        )
    if s["no_lookup"]:
        lines.append(
            f"{plural(s['no_lookup'], 'new domain')} reached with no lookup in the store: a rule at the"
            " resolver cannot hold such a domain."
        )
    for w in r["weeks"]:
        mine = [x for x in r["domains"] if w["from"] <= x["first"] < w["to"]]
        if not mine:
            continue
        lines += ["", f"{w['week']}:"]
        for x in mine:
            what = x["class"] if x["class"] == appfront.UNCLASSIFIED else f"{x['class']} ({x['category']})"
            who = f", {x['company']}" if x["company"] else ""
            seen = (
                f"{x['answered']} answered, {x['refused']} refused, {plural(x['hellos'], 'connection')} named"
            )
            mark = "  would hold" if x["held"] else ""
            lines.append(f"  {local_day(x['first'])}  {x['domain']}  {what}{who}; {seen}{mark}")
    return lines


# ---- 2. just-in-time platform access ----------------------------------------------------------------
def state_at(tl: appfront.Timeline, t: float) -> str:
    """The TV's state at `t`: the kind of session in front, the screen saver, off, or unknown."""
    cls, s, _lead = tl.at(t)
    if cls == NONE:
        return OFF_STATE
    if cls != SESSION or s is None:
        return UNKNOWN_STATE
    if s.is_idle(t):
        return IDLE_STATE
    return {HOME: HOME_STATE, INPUT: INPUT_STATE, CAST: CAST_STATE}.get(s.kind, APP_STATE)


def state_seconds(tl: appfront.Timeline) -> dict[str, float]:
    """Seconds of the timeline's window in each state."""
    out = dict.fromkeys(STATES, 0.0)
    for p in tl.pieces:
        span = p.t1 - p.t0
        if p.cls == NONE:
            out[OFF_STATE] += span
        elif p.cls == GAP or p.session is None:
            out[UNKNOWN_STATE] += span
        else:
            idle = sum(max(0.0, min(e, p.t1) - max(s, p.t0)) for s, e in p.session.idle)
            kind = {HOME: HOME_STATE, INPUT: INPUT_STATE, CAST: CAST_STATE}.get(p.session.kind, APP_STATE)
            out[IDLE_STATE] += idle
            out[kind] += span - idle
    return out


def timeline(conn: sqlite3.Connection, a: float, b: float) -> appfront.Timeline:
    """The window as sessions, gaps and none, from the live record and the hourly readings."""
    events = appfront.stored_events(conn, a - DAY, b)
    return appfront.timeline(events, appfront.readings(conn, a, b), a, b)


def platform_rows(profile: Profile) -> list[tuple[str, str, bool]]:
    """(pattern, why, is a clock pattern) for each must-allow host, then each clock host: the order a
    name is filed in, so a name both lists cover is counted once, under its must-allow host."""
    rows = [(host, why, False) for host, why in profile.must_allow.items()]
    rows += [(pat, "where the TV sets its clock", True) for pat in profile.clock_hosts]
    return rows


def _row_of(rows: list[tuple[str, str, bool]], name: str) -> int | None:
    for i, (pat, _why, clock) in enumerate(rows):
        if fnmatchcase(name, pat) if clock else covers(pat, name):
            return i
    return None


def platform(conn: sqlite3.Connection, profile: Profile, a: float, b: float, gw_ip: str) -> dict:
    """Lookups of, and connections to, each must-allow and clock host in [a, b), by the TV's state."""
    rows = platform_rows(profile)
    tl = timeline(conn, a, b)
    out = [
        {
            "host": pat,
            "why": why,
            "lookups": dict.fromkeys(STATES, 0),
            "connections": dict.fromkeys(STATES, 0),
            "refused": 0,
        }
        for pat, why, _clock in rows
    ]
    filed: dict[str, int | None] = {}
    for t, qname, blocked in appfront.lookups(conn, a, b):
        if qname not in filed:
            filed[qname] = _row_of(rows, qname.lower().rstrip("."))
        i = filed[qname]
        if i is None:
            continue
        out[i]["lookups"][state_at(tl, t)] += 1
        out[i]["refused"] += bool(blocked)
    for c in appfront.connections(conn, a, b, gw_ip):
        if not c.name:
            continue
        if c.name not in filed:
            filed[c.name] = _row_of(rows, c.name.lower().rstrip("."))
        i = filed[c.name]
        if i is not None:
            out[i]["connections"][state_at(tl, c.t)] += 1
    seconds = state_seconds(tl)
    return {
        "since": a,
        "until": b,
        "hours": {k: round(v / 3600, 2) for k, v in seconds.items()},
        "live": bool(tl.periods),
        "hosts": out,
    }


def render_platform(r: dict) -> list[str]:
    hours = r["hours"]
    lines = [
        "Just-in-time platform access, evidence only: nothing is scheduled or refused.",
        f"Lookups and connections of each host the TV must reach, {local_day(r['since'])} to"
        f" {local_day(r['until'])}, by what the TV was doing at that moment"
        f" ({'live record and hourly readings' if r['live'] else 'hourly readings'}). Each cell is"
        " lookups/connections.",
        "",
        "hours in each state: " + ", ".join(f"{k} {hours[k]:g}" for k in STATES),
        "",
    ]
    width = max([len(h["host"]) for h in r["hosts"]] + [4])
    lines.append(f"{'host':<{width}}  " + "  ".join(f"{k:>9}" for k in STATES))
    for h in r["hosts"]:
        cells = "  ".join(f"{h['lookups'][k]}/{h['connections'][k]}".rjust(9) for k in STATES)
        lines.append(f"{h['host']:<{width}}  {cells}")
    refused = [h for h in r["hosts"] if h["refused"]]
    for h in refused:
        lines.append(f"The filter refused {h['host']} {plural(h['refused'], 'time')}: the TV must reach it.")
    unused = [
        h["host"] for h in r["hosts"] if not any(h["lookups"].values()) and not any(h["connections"].values())
    ]
    if unused:
        lines.append(f"Not contacted in these days: {', '.join(unused)}.")
    lines.append(
        "A state with no contacts is one in which the host was not contacted in these days: few hours in"
        " that state, an answer the TV kept, or a connection opened in another state can explain it. A rule"
        " that opens a platform host only in some states would rest on this table, read over weeks."
    )
    return lines


# ---- 3. fan-out association --------------------------------------------------------------------------
def _merged(times: list[float], w: float) -> list[tuple[float, float]]:
    """The union of [t - w, t + w] over sorted `times`, as disjoint intervals."""
    out: list[tuple[float, float]] = []
    for t in times:
        if out and t - w <= out[-1][1]:
            out[-1] = (out[-1][0], t + w)
        else:
            out.append((t - w, t + w))
    return out


def base_rate(times: list[float], own: list[float], w: float) -> float | None:
    """The share of the TV's other lookups that have one of `own` within `w` seconds: how often a lookup
    of any kind comes next to this name. Anchoring on lookups rather than on time keeps the TV's bursts in
    the baseline, since a burst puts every name near every other; a time base would read two names that
    only share busy moments as associated. None when there is no other lookup."""
    others = len(times) - len(own)
    if others <= 0:
        return None
    inside = sum(bisect.bisect_right(times, hi) - bisect.bisect_left(times, lo) for lo, hi in _merged(own, w))
    return max(0, inside - len(own)) / others


def fanout(
    conn: sqlite3.Connection,
    profile: Profile,
    a: float,
    b: float,
    window: float = FANOUT_WINDOW,
    min_lift: float = FANOUT_MIN_LIFT,
    shown: int = FANOUT_NEIGHBOURS,
) -> dict:
    """For each unclassified domain the filter answered, the classified and refused lookups within
    `window` seconds of each of its episodes, across days, against each neighbour's base rate
    (`base_rate()`); `lift` is the share of the domain's episodes the neighbour comes next to over that
    rate. Only a neighbour at `min_lift` or above is shown or counts, and the top FANOUT_TOP domains are
    ranked by their episodes with such a neighbour that was refused or is filed under tracking, among the
    domains with FANOUT_MIN_EPISODES episodes on FANOUT_MIN_DAYS days."""
    cache: dict[str, str | None] = {}
    kinds: dict[str, appfront.Kind] = {}
    rows = []  # (t, domain, label, kind) of every lookup of an internet name
    for t, qname, blocked in appfront.lookups(conn, a, b):
        d = _domain_of(cache, qname)
        if d is None:
            continue
        if qname not in kinds:
            kinds[qname] = appfront.classify(profile, qname)
        kind = kinds[qname]
        rows.append((t, d, REFUSED if blocked else kind.cls, kind))
    times = [r[0] for r in rows]
    by_domain: dict[str, list[float]] = defaultdict(list)
    for t, d, _label, _kind in rows:
        by_domain[d].append(t)
    episodes: dict[str, list[float]] = defaultdict(list)  # each episode by its first lookup
    last: dict[str, float] = {}
    for t, d, label, _kind in rows:
        if label != appfront.UNCLASSIFIED:
            continue
        if d not in last or t - last[d] > FANOUT_EPISODE_GAP:
            episodes[d].append(t)
        last[d] = t
    found = []
    for u, starts in episodes.items():
        days = {local_day(t) for t in starts}
        if len(days) < FANOUT_MIN_DAYS or len(starts) < FANOUT_MIN_EPISODES:
            continue
        near: dict[str, dict] = {}
        beside: list[list[tuple[str, bool]]] = []  # per episode: (neighbour, after) once each
        for t in starts:
            lo = bisect.bisect_left(times, t - window)
            hi = bisect.bisect_right(times, t + window)
            mine: dict[str, bool] = {}
            for t2, d2, label, kind in rows[lo:hi]:
                if d2 == u or label == appfront.UNCLASSIFIED:
                    continue
                n = near.setdefault(
                    d2,
                    {"domain": d2, "label": label, "category": kind.category,
                     "company": companies.company(d2), "co": 0, "days": set(), "before": 0, "after": 0},
                )  # fmt: skip
                if label == REFUSED:
                    n["label"] = REFUSED  # a domain refused at least once next to it reads as refused
                if d2 not in mine:
                    mine[d2] = t2 >= t
                    n["co"] += 1
                    n["days"].add(local_day(t))
                    n["after" if t2 >= t else "before"] += 1
            beside.append(list(mine.items()))
        for n in near.values():
            base = base_rate(times, by_domain[n["domain"]], window)
            n["share"] = round(n["co"] / len(starts), 3)
            n["lift"] = round(n["share"] / base, 1) if base else None
            n["days"] = len(n["days"])
        strong = {d for d, n in near.items() if n["lift"] is None or n["lift"] >= min_lift}
        hits = {d for d in strong if near[d]["label"] in HIT_LABELS}
        flagged = sum(1 for ep in beside if any(d in hits for d, _after in ep))
        refused_after = sum(
            1 for ep in beside if any(after and d in hits and near[d]["label"] == REFUSED for d, after in ep)
        )
        neighbours = sorted(
            (near[d] for d in strong), key=lambda n: (-n["co"], -(n["lift"] or 0), n["domain"])
        )
        found.append(
            {
                "domain": u,
                "episodes": len(starts),
                "days": len(days),
                "flagged": flagged,
                "refused_after": refused_after,
                "neighbours": neighbours[:shown],
                "company": companies.company(u),
            }
        )
    found.sort(key=lambda x: (-x["flagged"], -x["episodes"], x["domain"]))
    return {
        "since": a,
        "until": b,
        "window": window,
        "min_lift": min_lift,
        "unclassified": len(episodes),
        "ranked": len(found),
        "top": found[:FANOUT_TOP],
        "note": ASSOCIATION,
    }


def render_fanout(r: dict) -> list[str]:
    lift = f"{r['min_lift']:g}"
    lines = [
        "Fan-out association for unclassified names, a report only: nothing is classified or refused.",
        f"{local_day(r['since'])} to {local_day(r['until'])}: {r['unclassified']} unclassified domains the"
        f" filter answered, {r['ranked']} with {FANOUT_MIN_EPISODES} episodes or more on"
        f" {FANOUT_MIN_DAYS} days or more. For each, the classified names and refused lookups within"
        f' {r["window"]:g} s of it; "lift" is how many times more often a neighbour comes next to it than'
        f" next to the TV's other lookups, and only a neighbour with a lift of {lift} or more is shown or"
        " counted.",
        "",
    ]
    if not r["top"]:
        lines.append("No unclassified domain has enough lookups yet.")
    for i, x in enumerate(r["top"], 1):
        who = f" ({x['company']})" if x["company"] else ""
        lines.append(
            f"{i}. {x['domain']}{who}: {x['episodes']} episodes on {x['days']} days; a refused or tracking"
            f" lookup with a lift of {lift} or more next to it in {x['flagged']}, a refused one after it in"
            f" {x['refused_after']}"
        )
        for n in x["neighbours"]:
            what = f"{n['label']} ({n['category']})"
            shown = f", lift {n['lift']:g}" if n["lift"] is not None else ""
            lines.append(
                f"     {n['domain']}: {what}; {n['co']} episodes on {n['days']} days,"
                f" {n['before']} before and {n['after']} after{shown}"
            )
    lines += ["", r["note"]]
    return lines


# ---- 4. the ACR meter ---------------------------------------------------------------------------------
def _is_acr(profile: Profile, name: str | None) -> bool:
    return bool(name) and profile.categorize(name).startswith(ACR_CATEGORY)


def consent(conn: sqlite3.Connection, until: float) -> dict:
    """The TV's own word on screen recognition at `until`: the Live Plus switch and the consent record's
    flags and documents as last read, each `None` where no reading holds it."""

    def last(key: str) -> str | None:
        row = conn.execute(
            "SELECT value FROM tvsettings WHERE key = ? AND t < ? ORDER BY t DESC LIMIT 1", (key, until)
        ).fetchone()
        return row[0] if row else None

    flags = {
        k.removeprefix(lgwebos.CONSENT_PREFIX): last(k)
        for (k,) in conn.execute(
            "SELECT DISTINCT key FROM tvsettings WHERE key LIKE 'eula.%' AND t < ? ORDER BY key", (until,)
        )
    }
    return {"live_plus": last(lgwebos.ACR_KEY), "flags": flags}


def acr_meter(conn: sqlite3.Connection, profile: Profile, a: float, b: float, control: bool = True) -> dict:
    """Uploads to screen-recognition destinations in [a, b), per hour the TV was on.

    `named`: connections whose TLS name the profile files under ACR, with what they sent beyond what came
    back (`budget.net_up()`, per connection) by the state the TV was in when each opened. The rate is the
    net of the connections opened while the TV was on (the screen saver included) over the hours it was
    on, the same states on both sides; what opened while it was off or in a gap is `net_outside`, apart.
    `shaped`: the ACR test's findings (`queries.acr_uploader()`) over the window, by their payload up,
    which the test buckets by hour and day, not by state, so they carry no rate. `lookups`: the lookups of
    ACR names, answered and refused (an attempt, not an upload). `record`: how much the capture and the
    ingest gave the meter to see. `control` is the same meter over the positive control's hour."""
    tl = timeline(conn, a, b)
    seconds = state_seconds(tl)
    on = sum(seconds[k] for k in ON_STATES)
    named = {"connections": 0, "net_up": 0, "by_state": dict.fromkeys(STATES, 0)}
    for row in conn.execute(
        f"""SELECT {queries.FLOW_NAME}, f.dst, f.t_start, f.bytes_up, f.pkts_up, f.bytes_down, f.pkts_down
            FROM flows f WHERE f.t_start >= ? AND f.t_start < ?""",
        (a, b),
    ):
        name, dst, t0, bu, pu, bd, pd = row
        if not is_public_address(dst) or not _is_acr(profile, name):
            continue
        net = budget.net_up(bu, pu, bd, pd)
        named["connections"] += 1
        named["net_up"] += net
        named["by_state"][state_at(tl, t0)] += net
    findings = queries.acr_uploader(conn, a, b, profile)
    shaped = {
        "findings": len(findings),
        "payload_up": sum(f["payload_up"] for f in findings),
        "cells": sorted({f["key"] for f in findings}),
    }
    answered = refused = 0
    for qname, blocked, n in conn.execute(
        "SELECT qname, blocked, COUNT(*) FROM dns WHERE t >= ? AND t < ? GROUP BY qname, blocked", (a, b)
    ):
        if _is_acr(profile, qname):
            answered, refused = answered + (0 if blocked else n), refused + (n if blocked else 0)
    hours = on / 3600
    named["net_on"] = sum(named["by_state"][k] for k in ON_STATES)
    named["net_outside"] = named["net_up"] - named["net_on"]
    out = {
        "since": a,
        "until": b,
        "hours_on": round(hours, 2),
        "hours": {k: round(v / 3600, 2) for k, v in seconds.items()},
        "named": named,
        "shaped": shaped,
        "lookups": {"answered": answered, "refused": refused},
        "net_per_hour": round(named["net_on"] / hours) if hours else None,
        "record": record(conn, a, b),
        "consent": consent(conn, b),
        "category": any(c.startswith(ACR_CATEGORY) for _p, c in profile.rules),
    }
    if control:
        out["control"] = positive_control(profile)
    return out


def record(conn: sqlite3.Connection, a: float, b: float) -> dict:
    """How much the capture and the ingest put in the store for [a, b): lookups, connections, the
    connections a hello named, and the capture files the ingest read. A meter's zero over a window with no
    connections says nothing about the TV."""

    def count(sql: str) -> int:
        return conn.execute(sql, (a, b)).fetchone()[0]

    return {
        "lookups": count("SELECT COUNT(*) FROM dns WHERE t >= ? AND t < ?"),
        "connections": count("SELECT COUNT(*) FROM flows WHERE t_start >= ? AND t_start < ?"),
        "hellos": count("SELECT COUNT(*) FROM tls WHERE t >= ? AND t < ?"),
        "capture_files": count(
            "SELECT COUNT(*) FROM pcaps_done WHERE error IS NULL AND done_at >= ? AND done_at < ?"
        ),
    }


def control_flows(hour: float, profile: Profile) -> list[tuple]:
    """The positive control's connections in the clock hour starting at `hour`: (t_start, t_end, dst,
    dport, sport, bytes_up, pkts_up, bytes_down, pkts_down, name). Named under the profile's first plain
    ACR pattern, or unnamed where the profile has none, so only the shape test can see them."""
    acr = next(
        (p for p, c in profile.rules if c.startswith(ACR_CATEGORY) and not any(ch in p for ch in "*?[")), None
    )
    n_up = round(CONTROL_FRAMES * CONTROL_RATIO / (CONTROL_RATIO + 1) / FULL_FRAME)
    n_down = round(CONTROL_FRAMES / (CONTROL_RATIO + 1) / FULL_FRAME)
    out = []
    for i in range(CONTROL_CONNS):
        up = n_up // CONTROL_CONNS + (i < n_up % CONTROL_CONNS)
        down = n_down // CONTROL_CONNS + (i < n_down % CONTROL_CONNS)
        t = hour + 1 + i * 59
        name = f"tkacr6{i % 41:02d}.{acr}" if acr else None
        ip_up, ip_down = up * (FULL_FRAME - ETHERNET), down * (FULL_FRAME - ETHERNET)
        dst = f"203.0.113.{40 + i % 8}"
        out.append((t, t + 180, dst, CONTROL_PORT, 39_000 + i, ip_up, up, ip_down, down, name))
    return out


def positive_control(profile: Profile) -> dict:
    """The meter over one hour shaped like IMC 2024's quietest measured LG fingerprinting hour, with an
    input in front, in a store held in memory and thrown away: what a TV that ran screen recognition for
    an hour would read. The hour is a fixed local midnight's first hour, so the result is the same on
    every run."""
    conn = db.connect(":memory:")
    try:
        hour = datetime(2026, 10, 26).timestamp()
        for t in (hour, hour + 3600):
            conn.execute("INSERT INTO tvstate(t, power, app) VALUES (?, 'Active', ?)", (t, CONTROL_APP))
        for t0, t1, dst, dport, sport, bu, pu, bd, pd, name in control_flows(hour, profile):
            conn.execute(
                "INSERT INTO flows(t_start,t_end,proto,dst,dport,sport,pkts_up,bytes_up,pkts_down,bytes_down,"
                "state) VALUES (?,?,'tcp',?,?,?,?,?,?,?,'TIME_WAIT')",
                (t0, t1, dst, dport, sport, pu, bu, pd, bd),
            )
            if name:
                conn.execute(
                    "INSERT INTO tls(t, dst, dport, sport, sni, ech, ja4, transport, partial)"
                    " VALUES (?, ?, ?, ?, ?, 0, '', 'tcp', 0)",
                    (t0, dst, dport, sport, name),
                )
        found = acr_meter(conn, profile, hour, hour + 3600, control=False)
        return {
            "hours_on": found["hours_on"],
            "net_per_hour": found["net_per_hour"],
            "shaped_findings": found["shaped"]["findings"],
            "shaped_payload_up": found["shaped"]["payload_up"],
        }
    finally:
        conn.close()


def render_acr(r: dict) -> list[str]:
    c = r["consent"]
    lines = [
        "ACR uploads per viewing hour, a meter only: nothing is refused.",
        f"{local_day(r['since'])} to {local_day(r['until'])}: the TV was on for {r['hours_on']:g} hours"
        f" (an input in front {r['hours'][INPUT_STATE]:g}, an app {r['hours'][APP_STATE]:g}, the home screen"
        f" {r['hours'][HOME_STATE]:g}, the screen saver {r['hours'][IDLE_STATE]:g}; unknown"
        f" {r['hours'][UNKNOWN_STATE]:g}).",
    ]
    rec = r["record"]
    lines.append(
        f"The record of these days: {plural(rec['lookups'], 'lookup')},"
        f" {plural(rec['connections'], 'connection')}, {rec['hellos']} named by a hello,"
        f" {plural(rec['capture_files'], 'capture file')} read."
    )
    if not rec["connections"]:
        lines.append("With no connection in the record, a zero below says nothing about the TV.")
    named = r["named"]
    if r["net_per_hour"] is None:
        lines.append("No hour with the TV on is in the record of these days, so the meter has no rate.")
    else:
        lines.append(
            f"Sent to screen-recognition names beyond what came back, on connections opened while the TV was"
            f" on: {size(named['net_on'])}, {size(r['net_per_hour'])} per hour on."
        )
    if named["net_outside"]:
        lines.append(
            f"On connections opened while the TV was off or in a gap: {size(named['net_outside'])}, outside"
            " the rate."
        )
    lines.append(
        f"Uploads the ACR test flags: {r['shaped']['findings']}, {size(r['shaped']['payload_up'])}"
        f" ({plural(named['connections'], 'connection')} to screen-recognition names in all)."
    )
    if not r["category"]:
        lines.append("The profile files no name under screen recognition: only the ACR test sees an upload.")
    lines.append(
        f"Lookups of screen-recognition names: {r['lookups']['answered']} answered, {r['lookups']['refused']}"
        " refused (a lookup is an attempt, not an upload)."
    )
    agreed = sorted(k for k, v in c["flags"].items() if v == "true" and k.lower().startswith("acr"))
    flags = "none read" if not c["flags"] else (", ".join(agreed) + " true" if agreed else "no ACR flag true")
    lines.append(f"The TV's readings: Live Plus {c['live_plus'] or 'not read'}; consent flags {flags}.")
    ctl = r.get("control")
    if ctl:
        lines.append(
            f"Positive control: one hour shaped like IMC 2024's quietest measured hour of LG's screen"
            f" recognition, built from published figures and run through the same arithmetic, reads"
            f" {size(ctl['net_per_hour'])} per hour on, and the ACR test flags it"
            f" {plural(ctl['shaped_findings'], 'time')}. That shows the arithmetic sees such an hour; the"
            " record line above shows how much the capture and the ingest gave it to see. It cannot see an"
            " upload inside a connection that returns as much, or one moved to a name the profile does not"
            " file under screen recognition and shaped unlike the test."
        )
    return lines


# ---- 5. firmware before and after --------------------------------------------------------------------
def features(conn: sqlite3.Connection, a: float, b: float) -> dict:
    """What the TV did in [a, b), as sets: the registrable domains it looked up or named in a hello, the
    (protocol, port) pairs it connected to on public servers, its TLS stacks (JA4) and record types;
    with its lookups and the local days that have any."""
    cache: dict[str, str | None] = {}
    domains: set[str] = set()
    qtypes: set[str] = set()
    days: set[str] = set()
    lookups = 0
    for t, qname, qtype in conn.execute("SELECT t, qname, qtype FROM dns WHERE t >= ? AND t < ?", (a, b)):
        lookups += 1
        days.add(local_day(t))
        if qtype:
            qtypes.add(qtype)
        d = _domain_of(cache, qname)
        if d:
            domains.add(d)
    stacks: set[str] = set()
    for sni, ja4 in conn.execute("SELECT sni, COALESCE(ja4,'') FROM tls WHERE t >= ? AND t < ?", (a, b)):
        d = _domain_of(cache, sni)
        if d:
            domains.add(d)
        if ja4:
            stacks.add(ja4)
    with contextlib.suppress(sqlite3.OperationalError):  # a store from before schema 8
        nameless = "SELECT ja4 FROM tls_noname WHERE t >= ? AND t < ? AND ja4 != ''"
        stacks |= {j for (j,) in conn.execute(nameless, (a, b))}
    ports = {
        f"{proto}/{dport}"
        for proto, dport, dst in conn.execute(
            "SELECT proto, dport, dst FROM flows WHERE t_start >= ? AND t_start < ? AND dport IS NOT NULL",
            (a, b),
        )
        if is_public_address(dst)
    }
    return {
        "domains": domains,
        "ports": ports,
        "stacks": stacks,
        "qtypes": qtypes,
        "lookups": lookups,
        "days": len(days),
        "span_days": round((b - a) / DAY, 1),
    }


def compare(before: dict, after: dict) -> dict:
    """New and vanished items per feature, and lookups a day on each side."""

    def per_day(f: dict) -> float | None:
        return round(f["lookups"] / f["days"], 1) if f["days"] else None

    return {
        "new": {k: sorted(after[k] - before[k]) for k in FEATURES},
        "gone": {k: sorted(before[k] - after[k]) for k in FEATURES},
        "lookups_per_day": (per_day(before), per_day(after)),
        "days": (before["days"], after["days"]),
        "span_days": (before["span_days"], after["span_days"]),
        "thin": before["days"] < FIRMWARE_MIN_DAYS or after["days"] < FIRMWARE_MIN_DAYS,
    }


def above_floor(n: int, floor: int | None, feature: str = "domains") -> bool:
    """Whether a count stands out of the A/A comparison's: at least the feature's FLOOR_MARGIN over it and
    more than FLOOR_TIMES times it. Without a floor nothing does."""
    return floor is not None and n >= floor + FLOOR_MARGIN[feature] and n > FLOOR_TIMES * floor


def firmware(conn: sqlite3.Connection, now: float, days: int = FIRMWARE_DAYS) -> dict:
    """Each software change against the days around it, and the A/A floor.

    The A/A pair is the latest two adjacent windows of `days` days, ending at `now` or at a change, with no
    change inside them and the record covering both. A change's after-window is cut at `now` and says so
    (`span_days`)."""
    span = days * DAY
    start = record_start(conn)
    changes = queries.firmware_changes(conn, 0, now)
    out_changes = []
    for ch in changes:
        t = ch["t"] - UPDATE_LEAD
        cmp = compare(features(conn, t - span, t), features(conn, t, min(t + span, now)))
        out_changes.append({"t": ch["t"], "firmware": ch["firmware"], "source": ch["source"], **cmp})
    aa = None
    for end in [now, *sorted((c["t"] - UPDATE_LEAD for c in changes), reverse=True)]:
        if start is None or end - 2 * span < start:
            continue
        if any(end - 2 * span < c["t"] - UPDATE_LEAD < end for c in changes):
            continue
        aa = {"from": end - 2 * span, "to": end, **compare(features(conn, end - 2 * span, end - span),
                                                           features(conn, end - span, end))}  # fmt: skip
        break
    floor = {k: len(aa["new"][k]) for k in FEATURES} if aa else None
    for ch in out_changes:
        ch["above"] = {k: above_floor(len(ch["new"][k]), floor[k] if floor else None, k) for k in FEATURES}
    return {"days": days, "changes": out_changes, "aa": aa, "floor": floor, "start": start}


def _items(xs: list[str]) -> str:
    shown = ", ".join(xs[:SHOWN])
    return shown + (f" and {len(xs) - SHOWN} more" if len(xs) > SHOWN else "") if xs else "none"


def render_firmware(r: dict) -> list[str]:
    days = r["days"]
    lines = ["Firmware before and after, a report only: nothing is refused or held."]
    aa = r["aa"]
    if aa is None:
        lines.append(f"No A/A floor yet: it needs {2 * days} days of record with no software change in them.")
    else:
        lines.append(
            f"A/A floor, the same firmware on both sides: {local_day(aa['from'])} to {local_day(aa['to'])},"
            f" two windows of {days} days. New in the second window: "
            + ", ".join(f"{len(aa['new'][k])} {FEATURE_WORDS[k]}" for k in FEATURES)
            + "; gone: "
            + ", ".join(f"{len(aa['gone'][k])}" for k in FEATURES)
            + f". Lookups a day {aa['lookups_per_day'][0]} then {aa['lookups_per_day'][1]}."
        )
        if aa["thin"]:
            lines.append(
                f"  One of its windows has lookups on fewer than {FIRMWARE_MIN_DAYS} days"
                f" ({aa['days'][0]} and {aa['days'][1]}): the floor counts a gap as change."
            )
        for k in FEATURES:
            if aa["new"][k]:
                lines.append(f"  new {FEATURE_WORDS[k]}: {_items(aa['new'][k])}")
    if not r["changes"]:
        lines.append(
            "No software change of the TV is in the record: the hourly reading has always found the same"
            " firmware, or a change came before the first reading, which has nothing to differ from."
        )
    for ch in r["changes"]:
        lines += [
            "",
            f"{local_time(ch['t'])}: {ch['firmware']} ({ch['source']}). {days} days before against"
            f" {ch['span_days'][1]:g} days after.",
        ]
        for k in FEATURES:
            n, g = len(ch["new"][k]), len(ch["gone"][k])
            mark = "  above the A/A floor" if ch["above"][k] else ""
            lines.append(f"  {FEATURE_WORDS[k]}: {n} new, {g} gone{mark}")
            if ch["new"][k]:
                lines.append(f"    new: {_items(ch['new'][k])}")
            if ch["gone"][k]:
                lines.append(f"    gone: {_items(ch['gone'][k])}")
        lines.append(f"  lookups a day: {ch['lookups_per_day'][0]} before, {ch['lookups_per_day'][1]} after")
        if ch["thin"]:
            lines.append(
                f"  One side has lookups on fewer than {FIRMWARE_MIN_DAYS} days ({ch['days'][0]} and"
                f" {ch['days'][1]}): part of the difference is the record's gap."
            )
    lines.append(
        "Apps and servers change on their own: read a difference against the A/A floor, and a domain"
        " above it as a lead to check, not as what the update did."
    )
    return lines


# ---- the command -------------------------------------------------------------------------------------
NAMES = ("probation", "platform", "fanout", "acr", "firmware")


def run(name: str, conn: sqlite3.Connection, profile: Profile, now: float, days: int, gw_ip: str) -> dict:
    """One experiment's result as plain data (the JSON `--json` prints)."""
    a = now - days * DAY
    if name == "probation":
        return probation(conn, profile, now)
    if name == "platform":
        return platform(conn, profile, a, now, gw_ip)
    if name == "fanout":
        return fanout(conn, profile, a, now)
    if name == "acr":
        return acr_meter(conn, profile, a, now)
    if name == "firmware":
        return firmware(conn, now)
    raise ValueError(f"no experiment named {name!r}")


RENDER = {
    "probation": render_probation,
    "platform": render_platform,
    "fanout": render_fanout,
    "acr": render_acr,
    "firmware": render_firmware,
}


def json_ready(value):
    """The result with its sets as sorted lists, for `json.dumps`."""
    if isinstance(value, dict):
        return {k: json_ready(v) for k, v in value.items()}
    if isinstance(value, list | tuple):
        return [json_ready(v) for v in value]
    if isinstance(value, set):
        return sorted(value)
    return value
