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
local clock hour it opened in, as the ACR test buckets: its whole upload lands there, so a long
connection overstates that hour and never hides an upload.

The measure is net, per flow (`net_up()`): the brief's payload bound up (`queries.payload_bound()`,
conntrack's bytes less HEADER_BYTES a packet) less the same bound down, never below zero, summed over
the destination-hour's flows. The gross bound up alone cannot be the measure: a bare acknowledgement
carries 12 to 40 bytes of TCP options (timestamps, SACK blocks on a lossy Wi-Fi uplink) that
HEADER_BYTES does not take off, so one long video download, a million acknowledgements, reads as tens
of megabytes "up" with nothing uploaded. Netting per flow, never per destination, means a download on
one connection never hides an upload on another. What it cannot see: an upload inside a connection
that returns at least as many bytes. The gross bound stays beside it in the report, for the reader.

The ceiling is not learned. The hourly ingest sets it once (`fix()`), from the BUDGET_DAYS whole local
days before the day it runs, settled for SETTLE seconds and covered by the record (the store's first
ingest run is before them): `ceiling_for()` the largest clean destination-hour, BUDGET_TIMES times it,
never below BUDGET_FLOOR and never above BUDGET_CAP, half the net of the quietest published hour of
LG's screen recognition, so the rule can never set a ceiling such an hour would pass under. A largest
clean hour at or above the cap fixes the ceiling at the cap, and the brief says that this TV's own
uploads reach the size the budget watches for. A destination-hour is clean unless the ACR test flagged
that destination on that day; a flow under a known tracking category (`plain.is_tracking()`) adds
nothing to it. The result goes into the store's meta under META_KEY with how it was derived, and
stays: nothing computes it again, so it cannot drift with the data, which is the learned alarm research
pass 3 rejected. The owner changes it with UPLOAD_CEILING, the one way above the cap; `tvgw forget`
removes it with the record it came from, and the next clean history sets it again. Until it is set,
the brief judges against the floor. The name and hour of the largest clean destination-hour are dropped
from meta once they are older than DB_DAYS, as their rows are.

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

# IMC 2024's quietest hour of LG's fingerprinting, 4,125 KB of Ethernet frames both ways on HDMI (deep
# dive 13, section 1.3), as the net the budget measures: at the 7 times up to down of the Watching the
# Watchers trace (its lowest), the payload up is 7/8 of the frames less 66 bytes of headers in every
# 1,514, and the whole down eighth is taken off as if it were all payload (computed: 4,125 KB x
# (7/8 x 1,448/1,514 - 1/8) = 2,936,406 bytes, rounded down). Every fingerprinting hour IMC published
# nets at least this much; a ceiling at or above it would not have caught one, and the brief says so
ACR_HOUR_NET = 2_930_000
# bytes net in a destination-hour: no ceiling the rule sets is above this, half the quietest published
# ACR hour, so such an hour is always at least twice over it. Only UPLOAD_CEILING goes higher
BUDGET_CAP = ACR_HOUR_NET // 2
# the ceiling is twice the largest clean destination-hour. On the reference gateway's record (12 days to
# 2026-11-05) the largest upload-heavy hour outside the tracking categories netted 681,064 bytes: a
# multiplier over CAP / 681,064 (2.15) would put that TV's own hours at the cap, so 10, the research
# pass's starting figure, is too loose; 2 leaves that hour at half the ceiling and the ACR hour twice over
BUDGET_TIMES = 2
# bytes net in a destination-hour: the ceiling is never below this. IMC measured LG's ACR host at 215 to
# 265 KB of frames both ways in an hour without fingerprinting, which bounds that hour's net from above;
# 512 KiB is about twice that, and under a fifth of the quietest fingerprinting hour's net (ACR_HOUR_NET)
BUDGET_FLOOR = 512 * 1024
BUDGET_DAYS = 14  # whole local days of clean history the ceiling is set from: the project's two weeks
# seconds after midnight before a day counts as settled: an idle connection reaches the flow log 7440 s
# after its last packet, and the daily files wait the same 3 h (SETTLE in deploy/bin/tvgw-analyze)
SETTLE = 3 * 3600
META_KEY = "upload_budget"  # the meta row: the fixed ceiling and its derivation, or the pending state
# the ceiling's source, as the report names it: set once from the clean history, the owner's
# UPLOAD_CEILING, or the floor until the history is there
FIXED, OWNER, FLOOR = "fixed", "owner", "floor"
PENDING = "pending"


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


def destination_hours(
    conn: sqlite3.Connection, a: float, b: float, profile: Profile
) -> dict[tuple[str, float], dict]:
    """What the TV sent each destination in each local clock hour, for the flows that opened in [a, b)
    and count (the module docstring says which): {(destination, hour): {"key", "hour", "net_up",
    "clean_net", "payload_up", "conns", "ports", "named"}}. `net_up` is the measure, `payload_up` the
    gross bound beside it, and `clean_net` the net less the flows under a known tracking category,
    which may never set the ceiling."""
    allowed = _must_allow_addresses(conn, a, b, profile)
    hosts = tuple(profile.must_allow)
    out: dict[tuple[str, float], dict] = {}
    for name, dst, dport, t, bytes_up, pkts_up, bytes_down, pkts_down in conn.execute(
        f"""SELECT {queries.FLOW_NAME}, f.dst, f.dport, f.t_start, f.bytes_up, f.pkts_up, f.bytes_down,
                   f.pkts_down
            FROM flows f WHERE f.t_start >= ? AND f.t_start < ?""",
        (a, b),
    ):
        if not is_public_address(dst):
            continue
        if name:
            if profile.is_expected(name) or any(covers(h, name) for h in hosts):
                continue
        elif dst in allowed:
            continue
        net = net_up(bytes_up, pkts_up, bytes_down, pkts_down)
        key = queries.acr_cell(name, dst)
        hour = _hour(t)
        c = out.setdefault(
            (key, hour),
            {"key": key, "hour": hour, "net_up": 0, "clean_net": 0, "payload_up": 0, "conns": 0,
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


def load(conn: sqlite3.Connection) -> dict | None:
    """The meta row as a dict, or None when there is none or it does not read as one."""
    raw = db.get_meta(conn, META_KEY)
    try:
        value = json.loads(raw) if raw else None
    except ValueError:
        return None
    return value if isinstance(value, dict) else None


def fix(conn: sqlite3.Connection, profile: Profile, now: float, db_days: int) -> dict:
    """The ingest's `budget` step: set the ceiling once the clean history is there, or say when it
    will be. A fixed ceiling is never computed again; its largest destination-hour's name and hour go
    once they are older than DB_DAYS. With DB_DAYS no longer than the history the store never holds
    it whole, and the floor stays. Returns what the meta row holds after the step."""
    stored = load(conn)
    if stored and stored.get("state") == FIXED:
        if stored.get("hour") is not None and stored["hour"] < now - db_days * 86400:
            stored = {**stored, "key": None, "hour": None}
            db.set_meta(conn, META_KEY, json.dumps(stored))
        return stored
    until = _midnight(now - SETTLE)
    since = _days_before(until, BUDGET_DAYS)
    first = queries.first_ingest(conn)
    if db_days <= BUDGET_DAYS:
        state = {"state": PENDING, "due": None, "why": "db_days"}
    elif first is None:
        state = {"state": PENDING, "due": None}
    elif first <= since:
        state = {**derive(conn, profile, since, until), "set_t": now}
    else:  # the first whole day of the record starts at the first midnight at or after its first run
        start = _midnight(first)
        start = start if start == first else _days_before(start, -1)
        state = {"state": PENDING, "due": _days_before(start, -BUDGET_DAYS) + SETTLE, "since": start}
    if state != stored:
        db.set_meta(conn, META_KEY, json.dumps(state))
    return state


def report(conn: sqlite3.Connection, a: float, b: float, profile: Profile, setting: str = "auto") -> dict:
    """The brief's "Upload budget" for [a, b): the ceiling, where it comes from (FIXED, OWNER or FLOOR),
    the stored derivation and, while it is pending, when the ingest sets it, and the destination-hours
    whose net is over the ceiling, most first, each with its gross bound beside it."""
    stored = load(conn) or {}
    owner = config.upload_ceiling_bytes(setting)
    fixed = stored if stored.get("state") == FIXED else None
    if owner is not None:
        ceiling, source = owner, OWNER
    elif fixed:
        ceiling, source = int(fixed["ceiling"]), FIXED
    else:
        ceiling, source = BUDGET_FLOOR, FLOOR
    events = [
        {
            "key": c["key"],
            "hour": c["hour"],
            "net_up": c["net_up"],
            "payload_up": c["payload_up"],
            "conns": c["conns"],
            "ports": sorted(c["ports"]),
            "named": c["named"],
        }
        for c in destination_hours(conn, a, b, profile).values()
        if c["net_up"] > ceiling
    ]
    events.sort(key=lambda e: (-e["net_up"], e["hour"], e["key"]))
    return {
        "ceiling": ceiling,
        "source": source,
        "fixed": fixed,
        "pending": stored if stored.get("state") == PENDING else None,
        "events": events,
    }
