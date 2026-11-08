"""(budget) The upload budget (design decision 66): a fixed ceiling on what the TV sends one destination
in one clock hour beyond what came back, for the destinations outside the profile's expected
categories. It is count-only: a destination-hour over the ceiling is a "would have capped" line in the
brief, and nothing anywhere is capped.

What counts. A flow counts when its server is a public address, its TLS name (`queries.FLOW_NAME`) is
outside the profile's `expected_categories` or it has none, and it is not a must-allow host: by name,
the host or a name under it, as the profile's `$important` exception covers them; without a name, an
address an A answer for such a name returned in the window or the day before. A destination is
`queries.acr_cell()`: the registrable domain of the TLS name, or the server's /24 when no hello named
the flow, so rotating names and the addresses behind one name are one destination. A flow counts in the
local clock hour it opened in, as the ACR test buckets: its whole upload lands there. An upload spread
over hours, over destinations, over rotating registrable domains or, unnamed, over several /24s counts
as several smaller ones.

The measure is net, per flow (`net_up()`): the brief's payload bound up (`queries.payload_bound()`,
conntrack's bytes less HEADER_BYTES a packet) less the same bound down, never below zero, summed over
the destination-hour's flows. The gross bound up alone cannot be the measure: a bare acknowledgement
carries 12 to 40 bytes of TCP options (timestamps, SACK blocks on a lossy Wi-Fi uplink) that
HEADER_BYTES does not take off, so one long video download, a million acknowledgements, reads as tens
of megabytes "up" with nothing uploaded. Netting per flow, never per destination, means a download on
one connection never hides an upload on another. What it cannot see: an upload inside a connection
that returns at least as many bytes. The gross bound stays beside it in the report, for the reader.

Late connections. A flow reaches the store only when conntrack destroys it, and each daily file is
written once, SETTLE after its day ends, so a connection still open then is in no daily file of the day
it opened. `report()` therefore also looks at every flow that ended in its window after its own day's
file was written, however long ago it opened, and lists that flow's destination-hour under `late` when
its whole net, now known, is over the ceiling. The derivation cannot see a connection still open when
it runs.

The ceiling is not learned. The hourly ingest sets it once (`fix()`), from the BUDGET_DAYS whole local
days before the day it runs, settled for SETTLE seconds, covered by the record (the store's first
ingest run is before them, and after any change of profile or TV) and by the capture (every day has
flows, and at least CAPTURE_NAMED of its TCP 443 connections have a TLS name): `ceiling_for()` the
largest clean destination-hour, BUDGET_TIMES times it, never below BUDGET_FLOOR and never above
BUDGET_CAP, half the estimated net of the quietest published hour of LG's screen recognition. A
largest clean hour at or above the cap fixes the ceiling at the cap, and the brief says that this TV's
own uploads reach the size the budget watches for. A destination-hour is clean unless the ACR test
flagged that destination on that day; a flow under a known tracking category (`plain.is_tracking()`)
adds nothing to it. The result goes into the store's meta under META_KEY with how it was derived, the
rule's version (RULE), its measure and the profile and TV it was set for, and stays: nothing computes it
again, so it cannot drift with the data, which is the learned alarm research pass 3 rejected. A row of
another rule, profile or TV is pending again; a stored ceiling is never honoured above the current cap.
The owner changes it with UPLOAD_CEILING, the one way above the cap, or derives it again from the
latest 14 days (`rederive()`, `sudo tvgw budget --rederive`); `tvgw forget` removes it with the record
it came from, and the next clean history sets it again. Until it is set, the brief judges against the
floor. The name and hour of the largest clean destination-hour are dropped from meta once they are
older than DB_DAYS, as their rows are.

Failure. Nothing here touches the firewall or the TV's path. The brief computes its part in a try, so
a failure is a report warning and the rest of the brief stands; a failing ingest step is an ingest
warning and leaves the meta row as it was.
"""

from __future__ import annotations

import json
import sqlite3
from datetime import datetime, timedelta

from tvgw import config, db, plain, queries
from tvgw.names import is_public_address
from tvgw.profile import Profile, covers

# An estimate of the net of IMC 2024's quietest hour of LG's fingerprinting, 4,125.0 KB of Ethernet
# frames both ways on HDMI (its US table runs 4,125.0 to 4,948.3 KB: deep dive 13, section 1.3), on two
# assumptions. The ratio of up to down is 7, the lowest daily payload ratio of the fingerprint port in
# the Watching the Watchers trace, applied to IMC's domain-wide frame totals; and every upload frame is
# full-size, 1,448 bytes of payload in 1,514, with the whole down side taken off as if it were all
# payload. That gives 4,125,000 x (7/8 x 1,448/1,514 - 1/8) = 2,936,406 bytes, rounded down. At the
# trace's domain-wide ratio, which goes as low as 4.5 (deep dive 13, section 1.2), the same hour nets
# about 2.48 MB. A ceiling at or above it would not have caught such an hour, and the brief says so
ACR_HOUR_NET = 2_930_000
# bytes net in a destination-hour: no ceiling the rule sets is above this, half that estimate, so such
# an hour is twice over it at a ratio of 7 and about 1.7 times at 4.5. Only UPLOAD_CEILING goes higher
BUDGET_CAP = ACR_HOUR_NET // 2
# the ceiling is twice the largest clean destination-hour. On the reference gateway's 12-day record (to
# 2026-11-05) the largest upload-heavy hour outside the tracking categories netted 864,544 bytes and the
# hours of a sport's or a video service's own host 0.29 to 0.86 MB: ten times, the research pass's starting
# figure, would be 8.6 MB, three times the ACR hour. Twice is enough for an ordinary hour to double
# without an event, and on that record it reaches the cap, which then decides
BUDGET_TIMES = 2
# bytes net in a destination-hour: the ceiling is never below this. IMC measured LG's ACR host at 214.9
# to 240.4 KB of frames both ways in an hour without fingerprinting, which bounds that hour's net from
# above; 512 KiB is about twice the larger, and under a fifth of ACR_HOUR_NET
BUDGET_FLOOR = 512 * 1024
BUDGET_DAYS = 14  # whole local days of clean history the ceiling is set from: the project's two weeks
# seconds after midnight before a day counts as settled: an idle connection reaches the flow log 7440 s
# after its last packet, and the daily files wait the same 3 h (SETTLE in deploy/bin/tvgw-analyze)
SETTLE = 3 * 3600
# a day of the history is covered when it has flows to public servers and at least this share of its
# TCP 443 connections carry a TLS name: an hour the capture missed leaves the TV's streaming unnamed,
# counted under its /24 outside the expected categories, where it could lift the ceiling for good
CAPTURE_NAMED = 0.9
# the rule's version and its measure, stored with the ceiling: a row of another rule (1 was the first
# build's gross bound at ten times, never deployed) is computed again
RULE = 2
MEASURE = "net"
# a plain line that has come this many days running says so once, then waits for a change
REPEAT_DAYS = queries.REPEAT_DAYS
META_KEY = "upload_budget"  # the meta row: the fixed ceiling and its derivation, or the pending state
# the ceiling's source, as the report names it: set once from the clean history, the owner's
# UPLOAD_CEILING, or the floor until the history is there
FIXED, OWNER, FLOOR = "fixed", "owner", "floor"
PENDING = "pending"
# what a fixed row must hold to be honoured; a row without them (hand-edited, or foreign) is pending
_FIXED_FIELDS = ("ceiling", "largest", "since", "until", "days")


def ceiling_for(largest: int) -> int:
    """The ceiling the rule gives a clean history whose largest destination-hour netted `largest` bytes:
    BUDGET_TIMES times it, never below BUDGET_FLOOR and never above BUDGET_CAP. A largest hour at or
    above the cap gets the cap: the ceiling is never raised to fit it."""
    return min(BUDGET_CAP, max(BUDGET_FLOOR, BUDGET_TIMES * largest))


def _bound(n: int | None, pkts: int | None) -> int:
    """`queries.payload_bound()`, or the bytes whole when the packet count is unknown."""
    found = queries.payload_bound(n, pkts)
    return (n or 0) if found is None else found


def net_up(bytes_up: int | None, pkts_up: int | None, bytes_down: int | None, pkts_down: int | None) -> int:
    """What one flow sent beyond what came back on it: the payload bound up less the payload bound down,
    never below zero. A download's acknowledgements, however many options they carry, are far fewer
    bytes than the segments they acknowledge, so a download nets nothing."""
    return max(0, _bound(bytes_up, pkts_up) - _bound(bytes_down, pkts_down))


def _hour(t: float) -> float:
    return datetime.fromtimestamp(t).replace(minute=0, second=0, microsecond=0).timestamp()


def _midnight(t: float) -> float:
    d = datetime.fromtimestamp(t)
    return datetime(d.year, d.month, d.day).timestamp()


def _days_before(t: float, days: int) -> float:
    """The local midnight `days` calendar days before the local midnight `t`: a day the clocks change
    on has 23 or 25 hours, and still counts as one."""
    return (datetime.fromtimestamp(t) - timedelta(days=days)).timestamp()


def _must_allow_addresses(conn: sqlite3.Connection, a: float, b: float, profile: Profile) -> set[str]:
    """The addresses A answers for a must-allow name, or a name under one, returned in [a - 1 day, b):
    an unnamed flow to one of them may be that host, and a must-allow host is never counted."""
    hosts = tuple(profile.must_allow)
    if not hosts:
        return set()
    out: set[str] = set()
    for qname, answers in conn.execute(
        "SELECT qname, answers FROM dns WHERE t >= ? AND t < ? AND blocked = 0 AND answers LIKE '%A:%'",
        (a - 86400, b),
    ):
        if any(covers(h, qname) for h in hosts):
            out.update(rec[2:] for rec in answers.split(",") if rec.startswith("A:"))
    return out


# the columns every aggregation reads, the flow's TLS name first
_COLUMNS = (
    f"{queries.FLOW_NAME}, f.dst, f.dport, f.t_start, f.t_end, f.bytes_up, f.pkts_up, f.bytes_down,"
    " f.pkts_down"
)


def _counted(row: tuple, profile: Profile, allowed: set[str]) -> tuple[str, float] | None:
    """(destination, hour) of a flow that counts, or None (the module docstring says which)."""
    name, dst = row[0], row[1]
    if not is_public_address(dst):
        return None
    if name:
        if profile.is_expected(name) or any(covers(h, name) for h in profile.must_allow):
            return None
    elif dst in allowed:
        return None
    return queries.acr_cell(name, dst), _hour(row[3])


def _aggregate(rows, profile: Profile, allowed: set[str]) -> dict[tuple[str, float], dict]:
    out: dict[tuple[str, float], dict] = {}
    for row in rows:
        where = _counted(row, profile, allowed)
        if where is None:
            continue
        name, _dst, dport, _t0, _t1, bytes_up, pkts_up, bytes_down, pkts_down = row
        net = net_up(bytes_up, pkts_up, bytes_down, pkts_down)
        c = out.setdefault(
            where,
            {"key": where[0], "hour": where[1], "net_up": 0, "clean_net": 0, "payload_up": 0, "conns": 0,
             "ports": set(), "named": False},
        )  # fmt: skip
        c["net_up"] += net
        c["payload_up"] += _bound(bytes_up, pkts_up)
        if not (name and plain.is_tracking(profile.categorize(name))):
            c["clean_net"] += net
        c["conns"] += 1
        if dport is not None:  # ICMP has no port
            c["ports"].add(dport)
        c["named"] = c["named"] or bool(name)
    return out


def destination_hours(
    conn: sqlite3.Connection, a: float, b: float, profile: Profile
) -> dict[tuple[str, float], dict]:
    """What the TV sent each destination in each local clock hour, for the flows that opened in [a, b)
    and count (the module docstring says which): {(destination, hour): {"key", "hour", "net_up",
    "clean_net", "payload_up", "conns", "ports", "named"}}. `net_up` is the measure, `payload_up` the
    gross bound beside it, and `clean_net` the net less the flows under a known tracking category,
    which may never set the ceiling."""
    rows = conn.execute(f"SELECT {_COLUMNS} FROM flows f WHERE f.t_start >= ? AND f.t_start < ?", (a, b))
    return _aggregate(rows, profile, _must_allow_addresses(conn, a, b, profile))


def _filed(t_start: float) -> float:
    """When the daily file of the day a flow opened in was written: SETTLE after that day ended."""
    return _days_before(_midnight(t_start), -1) + SETTLE


def late_hours(
    conn: sqlite3.Connection, a: float, b: float, profile: Profile
) -> dict[tuple[str, float], dict]:
    """The destination-hours of earlier windows that a flow ending in [a, b) completed after its own
    day's file was written: each with its whole net as now known (every flow opened in that hour that
    ended before b) and `late_net`, the part of it that came late. However long ago the flow opened, it
    is found by its end, the moment it reached the store."""
    late = [
        row
        for row in conn.execute(
            f"SELECT {_COLUMNS} FROM flows f WHERE f.t_end >= ? AND f.t_end < ? AND f.t_start < ?", (a, b, a)
        )
        if row[4] > _filed(row[3])
    ]
    if not late:
        return {}
    allowed = _must_allow_addresses(conn, min(r[3] for r in late), b, profile)
    late_cells = _aggregate(late, profile, allowed)
    out = {}
    for (key, hour), part in late_cells.items():
        rows = conn.execute(
            f"SELECT {_COLUMNS} FROM flows f WHERE f.t_start >= ? AND f.t_start < ? AND f.t_end < ?",
            (hour, hour + 3600, b),
        )
        whole = _aggregate(rows, profile, allowed).get((key, hour))
        if whole:
            out[(key, hour)] = {**whole, "late_net": part["net_up"]}
    return out


def uncovered(conn: sqlite3.Connection, since: float, until: float) -> list[float]:
    """The local days of [since, until) the history may not be set from: no flow to a public server, or
    fewer than CAPTURE_NAMED of its TCP 443 connections named by a TLS hello."""
    days, d = {}, since
    while d < until:
        days[d] = [0, 0, 0]  # flows to public servers, TCP 443 ones, named TCP 443 ones
        d = _days_before(d, -1)
    for t, dst, proto, dport, named in conn.execute(
        f"""SELECT f.t_start, f.dst, f.proto, f.dport, {queries.FLOW_NAME} IS NOT NULL FROM flows f
            WHERE f.t_start >= ? AND f.t_start < ?""",
        (since, until),
    ):
        count = days.get(_midnight(t))
        if count is None or not is_public_address(dst):
            continue
        count[0] += 1
        if proto == "tcp" and dport == 443:
            count[1] += 1
            count[2] += bool(named)
    return [d for d, (n, tls, named) in days.items() if not n or named < CAPTURE_NAMED * tls]


def derive(conn: sqlite3.Connection, profile: Profile, since: float, until: float) -> dict:
    """The ceiling from the clean history [since, until): `ceiling_for()` its largest clean
    destination-hour, with what it came from. The destination-days the ACR test flagged
    (`queries.acr_uploader`, by cell and local day, any port) are not clean. `at_cap` says the largest
    clean hour itself reached the cap."""
    cells = destination_hours(conn, since, until, profile)
    flagged = {(x["key"], x["day"]) for x in queries.acr_uploader(conn, since, until, profile)}
    clean = [c for c in cells.values() if (c["key"], _midnight(c["hour"])) not in flagged and c["clean_net"]]
    best = min(clean, key=lambda c: (-c["clean_net"], c["hour"], c["key"]), default=None)
    largest = best["clean_net"] if best else 0
    return {
        "state": FIXED,
        "ceiling": ceiling_for(largest),
        "largest": largest,
        "key": best["key"] if best else None,
        "hour": best["hour"] if best else None,
        "at_cap": largest >= BUDGET_CAP,
        "since": since,
        "until": until,
        "days": BUDGET_DAYS,
        "times": BUDGET_TIMES,
        "floor": BUDGET_FLOOR,
        "cap": BUDGET_CAP,
        "acr_days": len(flagged),
    }


def identity(conn: sqlite3.Connection, profile: Profile, until: float) -> dict:
    """What a ceiling is set for: this rule and measure, the profile, and the TV as its readings name it
    (its model, or None where nothing reads one)."""
    row = conn.execute(
        "SELECT value FROM tvsettings WHERE key = 'model' AND t < ? ORDER BY t DESC LIMIT 1", (until,)
    ).fetchone()
    model = row[0] if row and row[0] and row[0] != "unknown" else None
    return {"rule": RULE, "measure": MEASURE, "profile": profile.name, "tv": model}


def changed(stored: dict, ident: dict) -> str | None:
    """What makes a stored row not this one's: `rule` (another rule or measure), `profile`, or `tv` (a
    model read before and another now); None when the row holds."""
    if stored.get("rule") != RULE or stored.get("measure") != MEASURE:
        return "rule"
    if stored.get("profile") != ident["profile"]:
        return "profile"
    if stored.get("tv") and ident["tv"] and stored["tv"] != ident["tv"]:
        return "tv"
    return None


def load(conn: sqlite3.Connection) -> dict | None:
    """The meta row as a dict, or None when there is none or it does not read as one: not JSON, not an
    object, of no known state, or a fixed row without the numbers it is honoured by."""
    raw = db.get_meta(conn, META_KEY)
    try:
        value = json.loads(raw) if raw else None
    except ValueError:
        return None
    if not isinstance(value, dict) or value.get("state") not in (FIXED, PENDING):
        return None
    if value["state"] == FIXED and not all(
        isinstance(value.get(k), int | float) and not isinstance(value.get(k), bool) for k in _FIXED_FIELDS
    ):
        return None
    return value


def fix(conn: sqlite3.Connection, profile: Profile, now: float, db_days: int) -> dict:
    """The ingest's `budget` step: set the ceiling once the clean history is there, or say why not and
    when. A fixed row of this rule, profile and TV is never computed again, and its largest
    destination-hour's name and hour go once they are older than DB_DAYS. A row of another rule is
    computed again from the 14 days before; one of another profile or TV waits for 14 days after the
    change. With DB_DAYS no longer than the history the store never holds it whole, and the floor
    stays. Returns what the meta row holds after the step."""
    ident = identity(conn, profile, now)
    stored = load(conn)
    kind = changed(stored, ident) if stored else None
    if stored and stored["state"] == FIXED and kind is None:
        if stored.get("hour") is not None and stored["hour"] < now - db_days * 86400:
            stored = {**stored, "key": None, "hour": None}
            db.set_meta(conn, META_KEY, json.dumps(stored))
        return stored
    after, why = None, None
    if kind in ("profile", "tv"):
        after, why = now, kind  # a new profile or TV: its own history, from now
    elif stored and stored["state"] == PENDING and kind is None:
        after = stored.get("after")
        why = stored.get("why") if stored.get("why") in ("profile", "tv", "owner") else None
    elif kind == "rule" and stored["state"] == FIXED:
        why = "rule"
    until = _midnight(now - SETTLE)
    since = _days_before(until, BUDGET_DAYS)
    first = queries.first_ingest(conn)
    begins = max(first, after) if first is not None and after is not None else first
    if db_days <= BUDGET_DAYS:
        state = {"state": PENDING, "due": None, "why": "db_days"}
    elif begins is None:
        state = {"state": PENDING, "due": None}
    elif begins <= since:
        gaps = uncovered(conn, since, until)
        if gaps:
            state = {"state": PENDING, "due": None, "why": "coverage", "uncovered": len(gaps)}
        else:
            state = {**derive(conn, profile, since, until), "set_t": now}
    else:  # the first whole day of the history starts at the first midnight at or after it begins
        start = _midnight(begins)
        start = start if start == begins else _days_before(start, -1)
        state = {"state": PENDING, "due": _days_before(start, -BUDGET_DAYS) + SETTLE, "since": start}
        if why:
            state["why"] = why
    state.update(ident)
    if state["state"] == PENDING and after is not None:
        state["after"] = after
    if state != stored:
        db.set_meta(conn, META_KEY, json.dumps(state))
    return state


def rederive(conn: sqlite3.Connection, profile: Profile, now: float, db_days: int) -> dict:
    """(`sudo tvgw budget --rederive`) Set the ceiling again from the 14 whole days before today, as
    `fix()` would on a new store whose record covers them: the stored row is replaced, the record is not
    touched. Returns the new row (pending when those days are not covered)."""
    stored = load(conn) or {}
    previous = stored.get("ceiling") if stored.get("state") == FIXED else None
    ident = identity(conn, profile, now)
    db.set_meta(conn, META_KEY, json.dumps({"state": PENDING, "due": None, "why": "owner", **ident}))
    state = fix(conn, profile, now, db_days)
    if previous is not None:
        state = {**state, "previous": previous}
        db.set_meta(conn, META_KEY, json.dumps(state))
    return state


def _is_day(a: float, b: float) -> bool:
    return a == _midnight(a) and b == _days_before(a, -1)


def _events(cells, ceiling: int) -> list[dict]:
    out = [
        {
            "key": c["key"],
            "hour": c["hour"],
            "net_up": c["net_up"],
            "payload_up": c["payload_up"],
            "conns": c["conns"],
            "ports": sorted(c["ports"]),
            "named": c["named"],
            **({"late_net": c["late_net"]} if "late_net" in c else {}),
        }
        for c in cells
        if c["net_up"] > ceiling
    ]
    return sorted(out, key=lambda e: (-e["net_up"], e["hour"], e["key"]))


def report(conn: sqlite3.Connection, a: float, b: float, profile: Profile, setting: str = "auto") -> dict:
    """The brief's "Upload budget" for [a, b): the ceiling, where it comes from (FIXED, OWNER or FLOOR),
    the stored derivation and, while it is pending, why and when the ingest sets it; the destination-
    hours whose net is over the ceiling, most first, each with its gross bound beside it; `late`, the
    hours of earlier days that connections ending in the window completed over it; and, on a calendar
    day with any, `days_running` (up to REPEAT_DAYS + 1, this day included) and `new_keys` (a
    destination none of those earlier days had), which the plain brief's line follows. A stored
    ceiling of another rule, profile or TV is not honoured, and none is above BUDGET_CAP."""
    stored = load(conn) or {}
    kind = changed(stored, identity(conn, profile, b)) if stored else None
    fixed = stored if stored.get("state") == FIXED and kind is None else None
    pending = stored if stored.get("state") == PENDING else None
    if stored.get("state") == FIXED and kind is not None:
        pending = {"state": PENDING, "due": None, "why": kind}
    owner = config.upload_ceiling_bytes(setting)
    if owner is not None:
        ceiling, source = owner, OWNER
    elif fixed:
        ceiling, source = min(int(fixed["ceiling"]), BUDGET_CAP), FIXED
    else:
        ceiling, source = BUDGET_FLOOR, FLOOR
    events = _events(destination_hours(conn, a, b, profile).values(), ceiling)
    late = _events(late_hours(conn, a, b, profile).values(), ceiling)
    out = {
        "ceiling": ceiling,
        "source": source,
        "fixed": fixed,
        "pending": pending,
        "events": events,
        "late": late,
    }
    if (events or late) and _is_day(a, b):
        keys, run, seen = {e["key"] for e in events + late}, 1, set()
        day = a
        while run <= REPEAT_DAYS:
            day = _days_before(day, 1)
            before = _events(destination_hours(conn, day, _days_before(day, -1), profile).values(), ceiling)
            if not before:
                break
            run, seen = run + 1, seen | {e["key"] for e in before}
        out["days_running"], out["new_keys"] = run, bool(keys - seen)
    return out
