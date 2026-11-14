"""(ports) `tvgw ports`: is each port wall ready to refuse? (design decision 71)

Two walls are built and switched off: STRICT_PORTS=yes, which refuses every port but the web, the clock
and DNS (design decision 17), and the clock port's narrowing, CLOCK_PORT=none or resolved. Each may refuse
only after two clean weeks of its own count (decision 17's condition, and the two-week rule since), and
the owner decides when. This is the reading that decision needs, from what the gateway already keeps, and
it changes nothing:

- **Unusual ports.** The odd-port rules' counter (every connection attempt to a port other than TCP 80
  and 443 and UDP 123 and 443, after the walls that refuse known ports) over the last READY_DAYS, as
  `queries.fw_activity`
  steps the snapshots `tvgw verify --record` takes every ten minutes; and its kernel-log samples in
  `oddport`, which name each destination and port. Ready means: the count has run READY_DAYS, it counted
  nothing in them, and the TV was online on at least ONLINE_DAYS of them, so that a clean count is not a
  TV that was off. Decision 17 also accepts entries that were looked up and accepted; this reading cannot
  know what the owner accepted, so any entry blocks it and is listed for the owner to judge.
- **The clock port.** The NTP count (`inet tvgw_ntp`, design decision 17's note), as `queries.ntp_servers`
  reads it: the servers the TV sent NTP to, each with the names the TV's own answers gave it. Ready to
  close means: the count has run READY_DAYS, the TV sent NTP to no server in them, and it was online on
  ONLINE_DAYS of them. Servers that each came from a lookup make `resolved` the narrowing that would keep
  them; a server no lookup named blocks both.

Once a wall is on, the same reading is its probation report: what it refused in the last READY_DAYS. Its
undo is the setting back and an apply (with APPLY_CONFIRM=report the apply is probed before and after), and
`tvgw refused` ranks what it refuses with the filter's refusals. Nothing here undoes anything by itself.

A command and not a line of the daily brief: the decision is taken once, when the owner chooses, and needs
a fortnight's window the daily brief does not read; the brief's daily lines (`Unexpected ports`, `Clock
servers (NTP)`) are the evidence, and the readiness functions are here for the brief or a probation hook
to call.
"""

from __future__ import annotations

import json
import sqlite3
from dataclasses import dataclass, field
from datetime import datetime

from tvgw import db, plain, queries, walls
from tvgw.config import Settings
from tvgw.profile import Profile

READY_DAYS = 14  # a wall's count must run this long, clean, before it may refuse
# meta: the one number `tvgw forget` keeps of the TV's NTP (design decision 90): how many requests the
# count held, and when that stops vouching. No address and no time of a request
NTP_KEPT = "ntp_seen_kept"
ONLINE_DAYS = 7  # of those days, the ones the TV must have been online for a clean count to say anything
TOP = 10  # destinations or servers listed
STRICT_SERIES = (
    "STRICT_PORTS"  # both of the odd-port rule's comments begin so: the count-only accept and the reject
)
CLOCK_SERIES = walls.BY_KEY["clock"].comment  # the clock port's refusing rules
READY, WAITING, BLOCKED, ON, NOT_COUNTED = "ready", "waiting", "blocked", "on", "not_counted"


@dataclass
class Readiness:
    """One wall's reading: its state, the one line that says it, and what stands behind it."""

    wall: str  # strict | clock
    state: str  # READY, WAITING, BLOCKED, ON or NOT_COUNTED
    line: str
    in_force: str  # what the gateway builds now: no or yes; any, none or resolved
    counting_since: float | None = None
    due: float | None = None  # when READY_DAYS clean days end, if nothing comes before
    online_days: int = 0
    counted: int = 0  # connection attempts (strict) or NTP requests (clock) in the window
    refused: int = 0  # what the wall refused in the window, once it is on
    rows: list[dict] = field(default_factory=list)
    how: list[str] = field(default_factory=list)  # the next step, in plain words

    def as_dict(self) -> dict:
        return {
            "wall": self.wall,
            "state": self.state,
            "line": self.line,
            "in_force": self.in_force,
            "counting_since": self.counting_since,
            "due": self.due,
            "online_days": self.online_days,
            "counted": self.counted,
            "refused": self.refused,
            "rows": self.rows,
            "how": self.how,
        }


def _date(t: float, now: float) -> str:
    d, n = datetime.fromtimestamp(t), datetime.fromtimestamp(now)
    text = f"{d.day} {plain.MONTHS[d.month - 1]}"
    return text if d.year == n.year else f"{text} {d.year}"


def _times(n: int, word: str) -> str:
    return f"{n:,} {word if n == 1 else word + 's'}"


def online_days(conn: sqlite3.Connection, since: float, until: float) -> int:
    """The local days in [since, until) on which the TV opened a connection."""
    row = conn.execute(
        "SELECT COUNT(DISTINCT date(t_start, 'unixepoch', 'localtime')) FROM flows"
        " WHERE t_start >= ? AND t_start < ?",
        (since, until),
    ).fetchone()
    return int(row[0] or 0)


def _first(conn: sqlite3.Connection, sql: str, args: tuple = ()) -> float | None:
    row = conn.execute(sql, args).fetchone()
    return row[0] if row else None


def _activity(conn: sqlite3.Connection, since: float, until: float, prefix: str) -> int:
    return sum(n for rule, n in queries.fw_activity(conn, since, until) if rule.startswith(prefix))


def _name(answered: dict[str, float]) -> str:
    """The most recently answered name of an address, '' when no answer named it."""
    return max(answered, key=lambda q: answered[q]) if answered else ""


def ntp_seen_kept(conn: sqlite3.Connection, now: float) -> int:
    """The NTP requests a forget kept the count of, while that count still vouches (READY_DAYS after the
    forget): what `tvgw ports --ntp-seen` adds to the record's own, so that a forget cannot make the
    clock port's guard (tvgw-apply, design decision 71) read "this TV never used NTP"."""
    try:
        kept = json.loads(db.get_meta(conn, NTP_KEPT) or "null")
        return int(kept["requests"]) if now < float(kept["until"]) else 0
    except (ValueError, TypeError, KeyError):
        return 0


def ntp_seen_recorded(conn: sqlite3.Connection, floor: float) -> int:
    """The NTP requests the record holds from READY_DAYS before `floor` on, read to its newest snapshot
    wherever the clock stands now: what `tvgw forget` reads before it deletes them."""
    return queries.ntp_servers(conn, floor - READY_DAYS * 86400)["requests"]


def keep_ntp_seen(conn: sqlite3.Connection, floor: float, seen: int) -> None:
    """When `tvgw forget` deletes the NTP count at `floor`: keep, as one number, the requests `seen` (the
    record's, `ntp_seen_recorded`, or the kernel's list's where that holds more: a request made since
    the newest snapshot is in the list alone), with what an earlier forget still vouches for. The
    caller commits."""
    seen += ntp_seen_kept(conn, floor)
    if seen:
        db.set_meta(conn, NTP_KEPT, json.dumps({"requests": seen, "until": floor + READY_DAYS * 86400}))
    else:
        conn.execute("DELETE FROM meta WHERE key=?", (NTP_KEPT,))


def drop_ntp_seen(conn: sqlite3.Connection, now: float) -> None:
    """Remove the kept count once it vouches for nothing: two weeks after its forget. The caller
    commits."""
    if db.get_meta(conn, NTP_KEPT) is not None and not ntp_seen_kept(conn, now):
        conn.execute("DELETE FROM meta WHERE key=?", (NTP_KEPT,))


def strict_readiness(conn: sqlite3.Connection, now: float, in_force: str) -> Readiness:
    """STRICT_PORTS=yes: ready to refuse on probation, or what blocks it; once on, its probation report."""
    start = now - READY_DAYS * 86400
    since = _first(conn, "SELECT MIN(t) FROM fw_counters WHERE rule LIKE ?", (STRICT_SERIES + "%",))
    counted = _activity(conn, start, now, STRICT_SERIES)
    rows = []
    for proto, dport, dst, n, first, last in conn.execute(
        "SELECT lower(proto), dport, dst, COUNT(*), MIN(t), MAX(t) FROM oddport WHERE t >= ? AND t < ?"
        " GROUP BY 1, 2, 3 ORDER BY 4 DESC, 6 DESC LIMIT ?",
        (start, now, TOP),
    ):
        rows.append({"proto": proto, "dport": dport, "dst": dst, "samples": n, "first": first, "last": last})
    named = queries._answered(
        conn, sorted({r["dst"] for r in rows if r["dst"]}), now - queries.KNOWN_DAYS * 86400, now
    )
    for r in rows:
        r["name"] = _name(named.get(r["dst"], {}))
    last = _first(conn, "SELECT MAX(t) FROM oddport WHERE t >= ? AND t < ?", (start, now))
    online = online_days(conn, start, now)
    r = Readiness("strict", WAITING, "", in_force, since, online_days=online, counted=counted, rows=rows)
    undo = "To undo it: set STRICT_PORTS=no in /etc/tvgw/tvgw.conf, then run sudo tvgw-apply."
    if in_force == "yes":
        on = walls.strict_since(conn)
        r.state, r.refused = ON, counted
        began = f" since {_date(on, now)}" if on is not None else ""
        r.line = (
            f"STRICT_PORTS=yes{began}, on probation: it refused {_times(counted, 'connection attempt')} to"
            f" unusual ports in the last {READY_DAYS} days."
        )
        r.how = ["sudo tvgw refused shows what it refuses now, the likely cause of a broken app first.", undo]
        return r
    if since is None:
        r.state = NOT_COUNTED
        r.line = (
            "Not counted yet: the gateway holds no count of unusual ports. sudo tvgw verify --record keeps"
            " one every 10 minutes."
        )
        return r
    if counted or rows:
        tries = _times(counted or sum(x["samples"] for x in rows), "connection attempt")
        r.state = BLOCKED
        when = f", the last on {_date(last, now)}" if last is not None else ""
        r.due = (last if last is not None else now) + READY_DAYS * 86400
        r.line = (
            f"Not ready: the TV made {tries}"
            f" to unusual ports in the last {READY_DAYS} days{when}. {READY_DAYS} clean days would end on"
            f" {_date(r.due, now)} if no other comes."
        )
        r.how = ["Each one is listed below; one you know and accept is still listed here."]
        return r
    if now - since < READY_DAYS * 86400:
        r.due = since + READY_DAYS * 86400
        r.line = (
            f"Not ready yet: the count started on {_date(since, now)}, and its {READY_DAYS} days end on"
            f" {_date(r.due, now)}. No unusual port so far."
        )
        return r
    if online < ONLINE_DAYS:
        r.line = (
            f"Not ready: the TV was online on only {online} of the last {READY_DAYS} days, too few for a"
            " clean count to say anything."
        )
        return r
    r.state = READY
    r.line = (
        f"Ready to refuse on probation: no unusual port in the {READY_DAYS} days to {_date(now, now)} (the TV"
        f" was online on {online} of them)."
    )
    r.how = [
        "To switch: set STRICT_PORTS=yes in /etc/tvgw/tvgw.conf, then run sudo tvgw-apply. With TV_PROBE=on"
        " and APPLY_CONFIRM=report the apply is probed before and after, and the probe checks that an unusual"
        " port is refused and the web is not.",
        undo,
    ]
    return r


def clock_readiness(
    conn: sqlite3.Connection, now: float, profile: Profile | None, in_force: str
) -> Readiness:
    """The clock port: ready to close on probation, or what blocks it; once narrowed, its probation report."""
    start = now - READY_DAYS * 86400
    since = _first(conn, "SELECT MIN(t) FROM fw_counters WHERE rule = ?", (queries.NTP_SET_ROW,))
    ntp = queries.ntp_servers(conn, start, now, profile)
    online = online_days(conn, start, now)
    rows = [
        {"dst": x["dst"], "requests": x["requests"], "names": x["names"], "named": x["names_n"] > 0}
        for x in ntp["servers"][:TOP]
    ]
    r = Readiness(
        "clock", WAITING, "", in_force, since, online_days=online, counted=ntp["requests"], rows=rows
    )
    undo = (
        "To undo it: set CLOCK_PORT=any in /etc/tvgw/tvgw.conf (or profile, the default), then run sudo"
        " tvgw-apply."
    )
    if in_force in ("none", "resolved"):
        r.state, r.refused = ON, _activity(conn, start, now, CLOCK_SERIES)
        what = "closed" if in_force == "none" else "open only to servers one of the TV's lookups returned"
        r.line = (
            f"The clock port is {what}, on probation: it refused {_times(r.refused, 'NTP request')} in the"
            f" last {READY_DAYS} days."
        )
        r.how = [
            "sudo tvgw refused names a server it refuses, first of all, since the TV may need its clock.",
            undo,
        ]
        return r
    if since is None:
        r.state = NOT_COUNTED
        r.line = (
            "Not counted yet: the gateway holds no count of the TV's clock servers. sudo tvgw-apply loads it,"
            " and sudo tvgw verify --record keeps it every 10 minutes."
        )
        return r
    if ntp["requests"]:
        r.state = BLOCKED
        unnamed = [x for x in rows if not x["named"]]
        servers = _times(ntp["addresses"], "server")
        sent = _times(ntp["requests"], "NTP request")
        r.line = f"Not ready: the TV sent {sent} to {servers} in the last {READY_DAYS} days"
        if unnamed:
            r.line += (
                f", {unnamed[0]['dst']} among them, which no lookup of the TV's named: closing or narrowing"
                " the clock port would cut it off."
            )
        else:
            r.line += (
                ", each one a lookup of the TV's named. Closing the port would cut its clock off. Letting"
                " NTP go only to servers its lookups named (ntp = resolved) would keep these servers, but the"
                " gateway cannot do that safely yet."
            )
        return r
    if now - since < READY_DAYS * 86400:
        r.due = since + READY_DAYS * 86400
        r.line = (
            f"Not ready yet: the clock-server count started on {_date(since, now)}, and its {READY_DAYS} days"
            f" end on {_date(r.due, now)}. So far the TV sent NTP to no server."
        )
        return r
    if online < ONLINE_DAYS:
        r.line = (
            f"Not ready: the TV was online on only {online} of the last {READY_DAYS} days, too few for a"
            " clean count to say anything."
        )
        return r
    r.state = READY
    r.line = (
        f"Ready to close on probation: the TV sent NTP to no server in the {READY_DAYS} days to"
        f" {_date(now, now)} (it was online on {online} of them)."
    )
    r.how = [
        "To switch: set CLOCK_PORT=none in /etc/tvgw/tvgw.conf, then run sudo tvgw-apply. The apply keeps the"
        " port open, and says so, if the count holds a server by then; with TV_PROBE=on the probe checks that"
        " the port is refused.",
        undo,
    ]
    return r


def in_force(s: Settings, applied: dict[str, str]) -> tuple[str, str, str]:
    """(STRICT_PORTS, the clock port as built, what asked for it) from the record of the last apply
    (settings.applied), else from the settings file, before any apply recorded one."""
    strict = applied.get("STRICT_PORTS") or s.strict_ports
    used = applied.get("CLOCK_PORT_USED") or ("any" if s.clock_port == "profile" else s.clock_port)
    key = applied.get("CLOCK_PORT") or s.clock_port
    said = applied.get("CLOCK_PORT_PROFILE", "")
    if key == "profile":
        asked = (
            "the profile's [firewall] ntp could not be read at the last apply"
            if said == "unread"
            else f"the profile's [firewall] ntp = {said}"
            if said
            else "the profile's [firewall] ntp"
        )
    else:
        asked = f"CLOCK_PORT={key}"
    return strict, used, asked


def report(
    conn: sqlite3.Connection, now: float, profile: Profile | None, s: Settings, applied: dict
) -> list[Readiness]:
    strict, used, _asked = in_force(s, applied)
    return [strict_readiness(conn, now, strict), clock_readiness(conn, now, profile, used)]


CLOCK_WORDS = {
    "any": "NTP open to any server",
    "none": "closed",
    "resolved": "open only to servers a lookup named",
}


def render(readings: list[Readiness], now: float, s: Settings, applied: dict) -> list[str]:
    """`tvgw ports` in plain words: one block a wall, its verdict first."""
    strict, used, asked = in_force(s, applied)
    out: list[str] = []
    for r in readings:
        counting = f"; counted since {_date(r.counting_since, now)}" if r.counting_since is not None else ""
        if r.wall == "strict":
            out.append(f"Unusual ports (STRICT_PORTS={strict}{counting}):")
        else:
            out.append(f"Clock port ({CLOCK_WORDS.get(used, used)}, as {asked} says{counting}):")
        out.append(f"  {r.line}")
        for x in r.rows:
            if r.wall == "strict":
                name = f" ({x['name']})" if x["name"] else ""
                out.append(
                    f"    {x['proto'].upper()} port {x['dport']} at {x['dst']}{name}:"
                    f" {_times(x['samples'], 'sample')}, last on {_date(x['last'], now)}"
                )
            else:
                name = ", ".join(x["names"][:2]) if x["names"] else "no lookup named it"
                out.append(f"    {x['dst']} ({name}): {_times(x['requests'], 'request')}")
        out += [f"  {line}" for line in r.how]
        out.append("")
    out.append("tvgw ports read the gateway's own record; it changed nothing.")
    return out
