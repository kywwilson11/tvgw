"""(namebound) Name-bound egress, stage 1 (design decision 70): which names the filter answered with which
address, and whether each TLS connection the TV made named one of them. It reads the store and changes
nothing.

A DNS filter decides which names the TV may look up, not which servers it may talk to. The address gate
(design decision 18) binds the filter's word at the level of addresses: it counts connections to an
address no answer gave. One address can serve thousands of names on a shared cloud server, and the server
picks the site from the name in the TLS hello. So a connection whose hello names something the filter
never answered with that address passes the gate unseen. This module puts each TLS connection the capture
saw in one of five classes:

- `bound`: the hello's name is a name the filter answered with that address in the WINDOW before (the
  question or any name of the answer's CNAME chain);
- `shared`: the address was answered in the window, but only for other names: the shared-server case
  the address gate cannot see;
- `never`: no answer in the window gave the address: the address gate's own case;
- `noname`: a hello without a server name (`tls_noname`);
- `ech`: a hello with real Encrypted Client Hello, whose name is the provider's outer name
  (`queries.ech_seen`'s test).

A hello that is not name-bound and whose window reaches back before the table's coverage is `unassessed`,
never `shared` or `never`: the TV's own cache may hold an answer the store never saw.

The record is `answer_ip`: one row per public address an A answer to the TV named, with the answer's
time and its smallest A lifetime, keyed to the `dns` row, which keeps the names. The hourly ingest
writes the rows of each new answer (`record`), turns the answers stored before the table existed into
rows once, newest first, at most BACKFILL_ROWS lookups an hour (`backfill`), and keeps ANSWER_IP_DAYS
days of them (`prune`).

The same record names a connection that carried no hello (a UDP flow, a missed hello): by the newest
question answered with its address in the window, but only when every question answered with that
address there sits under one registrable domain. An address answered for names under SHARED_FROM or
more domains names nothing. A name found this way is labelled as such and stays out of everything that
decides: the categories, the upload budget, the analyst's pack and the autonomy read only names the
TV's own packets carried (design decision 12).

Stage 2, the live count beside it, is `tvgw.nametap`.
"""

from __future__ import annotations

import bisect
import sqlite3
from collections.abc import Iterable
from dataclasses import dataclass, field
from datetime import datetime, timedelta

from tvgw import db
from tvgw.dnsgate import TTL
from tvgw.names import is_public_address, normalize, registrable_domain

# seconds: an answer binds its names to its addresses for the gate's day (dnsgate.TTL), however short the
# record's own lifetime: the TV's cache, an app's cache and the gate's set all outlive it
WINDOW = TTL
# seconds a hello's capture time may come before the time AdGuard logged the answer it follows. AdGuard
# stamps an answer when the question arrives, and the TV cannot connect before the answer leaves, so on
# the gateway's one clock the answer always comes first; a second absorbs the two stamps' rounding
SLACK = 1.0
# days of rows the table keeps: the record's 28-day windows and the week queries.KNOWN_DAYS looks back,
# rounded up. A derived table: the names stay in `dns`, which DB_DAYS keeps
ANSWER_IP_DAYS = 35
BACKFILL_ROWS = 50_000  # stored lookups turned into rows per hourly run, until the table reaches back
# registrable domains answered with one address in the window from which the address names no connection:
# an address that stands for two services stands for neither
SHARED_FROM = 2
SAMPLES = 10  # rows of each class the brief lists
# (DoH-shaped, internal research note 4.5's third measure) a connection to TCP 443 that lasts longer than
# this many seconds, with more than this many packets each way, averaging under this many bytes a packet
# each way: what a resolver tunnel looks like in conntrack's counters
DOH_SECONDS, DOH_PACKETS, DOH_BYTES = 600, 500, 300

BOUND, SHARED, NEVER, NONAME, ECH, UNASSESSED = "bound", "shared", "never", "noname", "ech", "unassessed"
CLASSES = (BOUND, SHARED, NEVER, NONAME, ECH, UNASSESSED)
# how a flow is named: its hello, one service's answers, an address answered for several, nothing, or a flow
# that began before the table's coverage reached back a day (its answers may be missing, not absent)
HELLO, BY_DNS, SHARED_ADDRESS, UNNAMED = "hello", "dns", "shared", "unnamed"
NAMINGS = (HELLO, BY_DNS, SHARED_ADDRESS, UNNAMED, UNASSESSED)

FROM_KEY = "answer_ip_from"  # meta: the newest dns id stored before the table had rows of its own
DONE_KEY = "answer_ip_done"  # meta: the lowest dns id the backfill has turned into rows
SINCE_KEY = "answer_ip_since"  # meta: the table holds every answer from this time on
META_KEYS = (FROM_KEY, DONE_KEY, SINCE_KEY)  # forget removes them with the rows (forget.META_FORGET)


# ---- the record ------------------------------------------------------------------------------------------
def addresses(answers: str | None) -> list[str]:
    """The public A addresses of a stored answer (`A:1.2.3.4,CNAME:x`), in order, each once. The blocked
    answer (0.0.0.0), a rewrite to the gateway and every other address the TV cannot reach through the
    gateway are left out, as the in-path gate leaves them out of its set."""
    out: list[str] = []
    for rec in (answers or "").split(","):
        kind, _, value = rec.partition(":")
        if kind == "A" and value not in out and is_public_address(value):
            out.append(value)
    return out


def chain(qname: str | None, answers: str | None) -> list[str]:
    """The names an answer binds to its addresses: the question, then every CNAME target, normalized,
    each once."""
    out: list[str] = []
    for name in [qname or ""] + [
        value for kind, _, value in (r.partition(":") for r in (answers or "").split(",")) if kind == "CNAME"
    ]:
        n = normalize(name)
        if n and n not in out:
            out.append(n)
    return out


def record(conn: sqlite3.Connection, dns_id: int, t: float, answers: str | None, ttl: int | None) -> int:
    """The rows of one stored answer. Returns how many. The caller commits."""
    rows = [(dns_id, t, ip, ttl) for ip in addresses(answers)]
    conn.executemany("INSERT INTO answer_ip(dns_id, t, ip, ttl) VALUES (?,?,?,?)", rows)
    return len(rows)


def mark_start(conn: sqlite3.Connection, now: float) -> None:
    """Before the first answer the table records itself: every dns row up to the newest one now stored is
    the backfill's, and the table covers nothing before `now` until the backfill reaches back."""
    if db.get_meta(conn, FROM_KEY) is not None:
        return
    newest = conn.execute("SELECT COALESCE(MAX(id), 0) FROM dns").fetchone()[0]
    db.set_meta(conn, FROM_KEY, str(newest))
    db.set_meta(conn, DONE_KEY, str(newest + 1))
    db.set_meta(conn, SINCE_KEY, str(now))


def backfill(conn: sqlite3.Connection, now: float, rows: int = BACKFILL_ROWS) -> int:
    """Turn up to `rows` of the answers stored before the table existed into rows, newest first, back to
    ANSWER_IP_DAYS before `now`. Their lifetime is unknown (the stored answer kept none): NULL. The
    table's coverage moves back with each step. Returns the lookups read; 0 once done. The caller
    commits."""
    raw = db.get_meta(conn, DONE_KEY)
    if raw is None:
        return 0
    done = int(raw)
    if done <= 1:
        return 0
    cutoff = now - ANSWER_IP_DAYS * 86400
    batch = conn.execute(
        "SELECT id, t, answers FROM dns WHERE id < ? ORDER BY id DESC LIMIT ?", (done, rows)
    ).fetchall()
    kept = [(i, t, answers) for i, t, answers in batch if t >= cutoff]
    for dns_id, t, answers in kept:
        record(conn, dns_id, t, answers, None)
    since = float(db.get_meta(conn, SINCE_KEY) or now)
    if len(kept) < len(batch) or len(batch) < rows:  # reached the cutoff, or the oldest stored lookup
        oldest = conn.execute("SELECT MIN(t) FROM dns").fetchone()[0]
        since = min(since, max(cutoff, oldest if oldest is not None else now))
        db.set_meta(conn, DONE_KEY, "1")
    else:
        since = min(since, kept[-1][1])
        db.set_meta(conn, DONE_KEY, str(kept[-1][0]))
    db.set_meta(conn, SINCE_KEY, str(since))
    return len(batch)


def prune(conn: sqlite3.Connection, now: float, db_days: int | None = None) -> int:
    """Delete the rows older than ANSWER_IP_DAYS (or DB_DAYS, when that is shorter), and move the
    coverage up to the cutoff. The caller commits."""
    days = ANSWER_IP_DAYS if db_days is None else min(ANSWER_IP_DAYS, db_days)
    cutoff = now - days * 86400
    n = conn.execute("DELETE FROM answer_ip WHERE t < ?", (cutoff,)).rowcount
    since = db.get_meta(conn, SINCE_KEY)
    if since is not None and float(since) < cutoff:
        db.set_meta(conn, SINCE_KEY, str(cutoff))
    return n


def coverage(conn: sqlite3.Connection) -> float | None:
    """The time from which the table holds every answer; None when it has not started (a store no
    writer has taken to the schema, or no answer recorded yet)."""
    try:
        since = db.get_meta(conn, SINCE_KEY)
    except sqlite3.OperationalError:
        return None
    return float(since) if since is not None else None


# ---- reading it ------------------------------------------------------------------------------------------
@dataclass
class Answers:
    """The answers that named one address, oldest first: their times, and for each name they bound and
    each question's registrable domain, the times it was answered with the address."""

    times: list[float] = field(default_factory=list)
    by_name: dict[str, list[float]] = field(default_factory=dict)
    by_question: dict[str, list[tuple[float, str]]] = field(default_factory=dict)  # domain -> (t, qname)

    def any_in(self, a: float, b: float) -> bool:
        i = bisect.bisect_left(self.times, a)
        return i < len(self.times) and self.times[i] <= b

    def name_in(self, name: str, a: float, b: float) -> bool:
        ts = self.by_name.get(name)
        if not ts:
            return False
        i = bisect.bisect_left(ts, a)
        return i < len(ts) and ts[i] <= b

    def names_in(self, a: float, b: float) -> list[str]:
        """The names answered with the address in [a, b], the most recently answered first."""
        last = {n: max((t for t in ts if a <= t <= b), default=None) for n, ts in self.by_name.items()}
        return sorted((n for n, t in last.items() if t is not None), key=lambda n: (-last[n], n))

    def questions_in(self, a: float, b: float) -> dict[str, tuple[float, str]]:
        """registrable domain -> (time, question) of the newest question under it answered in [a, b]."""
        out: dict[str, tuple[float, str]] = {}
        for domain, hits in self.by_question.items():
            inside = [h for h in hits if a <= h[0] <= b]
            if inside:
                out[domain] = max(inside)
        return out


def answers_for(conn: sqlite3.Connection, ip: str, a: float, b: float) -> Answers:
    """Every answer that named `ip` in [a, b], read by the (ip, t) index and joined to its lookup."""
    out = Answers()
    for t, qname, answers in conn.execute(
        """SELECT a.t, d.qname, d.answers FROM answer_ip a JOIN dns d ON d.id = a.dns_id
           WHERE a.ip = ? AND a.t >= ? AND a.t <= ? ORDER BY a.t""",
        (ip, a, b),
    ):
        out.times.append(t)
        names = chain(qname, answers)
        for name in names:
            out.by_name.setdefault(name, []).append(t)
        if names:
            out.by_question.setdefault(registrable_domain(names[0]), []).append((t, names[0]))
    return out


def _looked_up(conn: sqlite3.Connection, name: str, a: float, b: float, blocked: int) -> bool:
    return (
        conn.execute(
            "SELECT 1 FROM dns WHERE qname = ? AND t >= ? AND t <= ? AND blocked = ? LIMIT 1",
            (name, a, b, blocked),
        ).fetchone()
        is not None
    )


@dataclass(frozen=True)
class Hello:
    """One TLS connection the capture saw, with its class."""

    t: float
    dst: str
    dport: int
    sni: str
    cls: str


def _public(dst: str | None, gw_ip: str) -> bool:
    return bool(dst) and dst != gw_ip and is_public_address(dst)


def classify(conn: sqlite3.Connection, a: float, b: float, gw_ip: str) -> list[Hello]:
    """Every TLS connection over TCP the TV made to a public address in [a, b), with its class (the
    module's docstring). A hello carried over QUIC is left out: the firewall refuses QUIC, so it opened
    nothing. Read by the tls_t index, then one read of the answers per address."""
    from tvgw.queries import ECH_PUBLIC_NAMES  # here: queries imports this module

    since = coverage(conn)
    rows = [
        r
        for r in conn.execute(
            """SELECT t, dst, COALESCE(dport, 0), sni, COALESCE(ech, 0) FROM tls
               WHERE t >= ? AND t < ? AND COALESCE(transport, 'tcp') = 'tcp' ORDER BY t""",
            (a, b),
        )
        if _public(r[1], gw_ip)
    ]
    by_dst: dict[str, list[tuple]] = {}
    for r in rows:
        by_dst.setdefault(r[1], []).append(r)
    out: list[Hello] = []
    for dst, hellos in by_dst.items():
        ans = answers_for(conn, dst, hellos[0][0] - WINDOW, hellos[-1][0] + SLACK)
        for t, _dst, dport, sni, ech in hellos:
            name = normalize(sni)
            if ech and (name in ECH_PUBLIC_NAMES or not _looked_up(conn, name, t - WINDOW, t + SLACK, 0)):
                cls = ECH
            elif ans.name_in(name, t - WINDOW, t + SLACK):
                cls = BOUND  # what the table holds proves it, however far back the table reaches
            elif since is None or t - WINDOW < since:
                cls = UNASSESSED  # an answer the table never saw may explain it
            elif ans.any_in(t - WINDOW, t + SLACK):
                cls = SHARED
            else:
                cls = NEVER
            out.append(Hello(t, dst, dport, name, cls))
    out.sort(key=lambda h: (h.t, h.dst))
    return out


def nameless(conn: sqlite3.Connection, a: float, b: float, gw_ip: str) -> int:
    """The TV's TLS hellos over TCP without a server name in [a, b), to public addresses."""
    return sum(
        1
        for (dst,) in conn.execute(
            "SELECT dst FROM tls_noname WHERE t >= ? AND t < ? AND COALESCE(transport, 'tcp') = 'tcp'", (a, b)
        )
        if _public(dst, gw_ip)
    )


def _must_allow(name: str, profile) -> bool:
    return any(name == host or name.endswith("." + host) for host in getattr(profile, "must_allow", {}) or {})


def _last_bound(conn: sqlite3.Connection, name: str, dst: str, before: float) -> float | None:
    """The newest answer, older than the window, that gave `name` the address `dst`: an answer the TV
    kept past the gate's day explains a connection the window cannot."""
    ans = answers_for(conn, dst, before - ANSWER_IP_DAYS * 86400, before)
    ts = ans.by_name.get(name) or []
    return ts[-1] if ts else None


def samples(
    conn: sqlite3.Connection, hellos: list[Hello], cls: str, profile=None, limit: int = SAMPLES
) -> list[dict]:
    """The connections of one class (SHARED or NEVER) by name, address and port, most first: what the
    owner checks by hand. `answered_for` (SHARED) is the names the address was answered for in the window
    before the first one; `same_site` is one of them under the hello name's registrable domain;
    `looked_up` and `blocked` say whether the name itself was answered (elsewhere) or blocked in that
    window; `last_bound` is the newest older answer that gave the name this address; `must_allow` marks a
    name the profile keeps reachable, which any refusal would have to exempt."""
    groups: dict[tuple[str, str, int], list[float]] = {}
    for h in hellos:
        if h.cls == cls:
            groups.setdefault((h.sni, h.dst, h.dport), []).append(h.t)
    ranked = sorted(groups.items(), key=lambda kv: (-len(kv[1]), kv[0]))[:limit]
    out = []
    for (name, dst, dport), times in ranked:
        first, last = times[0], times[-1]
        e: dict = {
            "name": name,
            "dst": dst,
            "dport": dport,
            "n": len(times),
            "first": first,
            "last": last,
            "looked_up": _looked_up(conn, name, first - WINDOW, last, 0),
            "blocked": _looked_up(conn, name, first - WINDOW, last, 1),
            "must_allow": _must_allow(name, profile),
            "last_bound": _last_bound(conn, name, dst, first - WINDOW),
        }
        if cls == SHARED:
            names = answers_for(conn, dst, first - WINDOW, first + SLACK).names_in(
                first - WINDOW, first + SLACK
            )
            e["answered_for"] = names[:3]
            e["answered_n"] = len(names)
            e["same_site"] = registrable_domain(name) in {registrable_domain(n) for n in names}
        out.append(e)
    return out


# ---- naming the flows a hello did not name ---------------------------------------------------------------
def name_flows(conn: sqlite3.Connection, a: float, b: float, gw_ip: str) -> dict:
    """The TV's connections that ended in [a, b), to public addresses, by how they are named: `hello`
    (their own TLS hello, queries.FLOW_NAME), `dns` (no hello; every question answered with the address
    in the WINDOW before the flow began sits under one registrable domain), `shared` (no hello; questions
    under SHARED_FROM or more domains), `unnamed` (no hello, no answer) and `unassessed` (no hello, and it
    began less than a WINDOW after the table's coverage starts). Connections, bytes up and bytes both ways
    for each, and `dns_names`, the registrable domains the second class was named by, with their bytes.
    Names found this way are labelled, never fed to anything that decides."""
    from tvgw.queries import FLOW_NAME  # here: queries imports this module

    keys = NAMINGS
    since = coverage(conn)
    out: dict = {
        "conns": dict.fromkeys(keys, 0),
        "bytes_up": dict.fromkeys(keys, 0),
        "bytes": dict.fromkeys(keys, 0),
    }
    named: dict[str, int] = {}
    pending: dict[str, list[tuple]] = {}
    for dst, start, end, up, down, name in conn.execute(
        f"""SELECT f.dst, f.t_start, f.t_end, COALESCE(f.bytes_up, 0), COALESCE(f.bytes_down, 0), {FLOW_NAME}
            FROM flows f WHERE f.t_end >= ? AND f.t_end < ?""",
        (a, b),
    ):
        if not _public(dst, gw_ip):
            continue
        if name:
            _add(out, HELLO, up, down)
        else:
            pending.setdefault(dst, []).append((start if start is not None else end, up, down))
    for dst, flows in pending.items():
        lo = min(f[0] for f in flows)
        hi = max(f[0] for f in flows)
        ans = answers_for(conn, dst, lo - WINDOW, hi + SLACK)
        for start, up, down in flows:
            domains = ans.questions_in(start - WINDOW, start + SLACK)
            if since is None or start - WINDOW < since:
                _add(out, UNASSESSED, up, down)
            elif not domains:
                _add(out, UNNAMED, up, down)
            elif len(domains) >= SHARED_FROM:
                _add(out, SHARED_ADDRESS, up, down)
            else:
                _add(out, BY_DNS, up, down)
                (domain,) = domains
                named[domain] = named.get(domain, 0) + up + down
    out["dns_names"] = [
        {"name": d, "bytes": n} for d, n in sorted(named.items(), key=lambda kv: (-kv[1], kv[0]))[:SAMPLES]
    ]
    return out


def _add(out: dict, key: str, up: int, down: int) -> None:
    out["conns"][key] += 1
    out["bytes_up"][key] += up
    out["bytes"][key] += up + down


def named_shares(named: dict | None) -> tuple[float, float] | None:
    """(the share of the window's bytes up whose connection's own hello named its server, the share a
    single service's answers named instead); None for a window with no bytes up, and for one with a flow
    the answers could not assess, whose share would be a guess. The two stay apart: the second is the
    TV's lookups pointing at a name, not the connection carrying one."""
    up = (named or {}).get("bytes_up") or {}
    total = sum(up.values())
    if not total or up.get(UNASSESSED):
        return None
    return up.get(HELLO, 0) / total, up.get(BY_DNS, 0) / total


# ---- DoH-shaped connections ------------------------------------------------------------------------------
def doh_shaped(conn: sqlite3.Connection, a: float, b: float, gw_ip: str, limit: int = SAMPLES) -> list[dict]:
    """Connections to TCP 443 that ended in [a, b) and look like a resolver tunnel in conntrack's counters:
    longer than DOH_SECONDS, more than DOH_PACKETS packets each way, under DOH_BYTES bytes a packet each
    way. The DoH wall resets port 443 to every address on its list, so each one reached an address the
    list does not hold. Named by their hello, else by their answers with the label `by_dns`; `blocked`
    says the name's own lookups were blocked in the window (the DoH list blocks resolver names)."""
    from tvgw.queries import FLOW_NAME  # here: queries imports this module

    out = []
    for dst, start, end, pu, bu, pd, bd, name in conn.execute(
        f"""SELECT f.dst, f.t_start, f.t_end, f.pkts_up, f.bytes_up, f.pkts_down, f.bytes_down, {FLOW_NAME}
            FROM flows f WHERE f.t_end >= ? AND f.t_end < ? AND f.dport = 443 AND f.proto = 'tcp'
              AND f.t_start IS NOT NULL AND f.t_end - f.t_start > ? AND f.pkts_up > ? AND f.pkts_down > ?
              AND f.bytes_up < f.pkts_up * ? AND f.bytes_down < f.pkts_down * ?""",
        (a, b, DOH_SECONDS, DOH_PACKETS, DOH_PACKETS, DOH_BYTES, DOH_BYTES),
    ):
        if not _public(dst, gw_ip):
            continue
        by_dns = False
        if not name:
            domains = answers_for(conn, dst, start - WINDOW, start + SLACK).questions_in(
                start - WINDOW, start + SLACK
            )
            if len(domains) == 1:
                ((_t, name),) = domains.values()
                by_dns = True
        out.append(
            {
                "name": name,
                "by_dns": by_dns,
                "dst": dst,
                "minutes": round((end - start) / 60),
                "pkts_up": pu,
                "pkts_down": pd,
                "per_packet_up": bu // pu,
                "per_packet_down": bd // pd,
                "blocked": bool(name) and _looked_up(conn, name, start - WINDOW, end, 1),
            }
        )
    out.sort(key=lambda e: (-e["minutes"], e["dst"]))
    return out[:limit]


# ---- the brief's section ---------------------------------------------------------------------------------
def counts(hellos: Iterable[Hello], noname: int) -> dict[str, int]:
    out = dict.fromkeys(CLASSES, 0)
    for h in hellos:
        out[h.cls] += 1
    out[NONAME] = noname
    return out


# the samples' fields that say when a connection was made: kept out of a persisted report (`times=False`)
TIMES = ("first", "last", "last_bound")


def section(
    conn: sqlite3.Connection,
    a: float,
    b: float,
    profile,
    gw_ip: str = "10.10.10.1",
    repeat_days: int = 3,
    times: bool = False,
) -> dict | None:
    """The brief's "Server names against the filter's answers" for [a, b): the five classes, the samples
    of the two that matter, how the window's bytes were named, the DoH-shaped connections, and, on a
    calendar day with `shared` connections, `days_running` (this day included, up to `repeat_days` + 1)
    and `new_names` for the plain line (queries.REPEAT_DAYS). None on a store whose table has not
    started, so a reader of an older store sees no section rather than a wrong one. Without `times`, the
    samples carry no time of a connection (TIMES), only `given_before`: a persisted report keeps names and
    counts, and the finer record stays in the store (design decision 67's rule for finer records)."""
    if coverage(conn) is None:
        return None
    hellos = classify(conn, a, b, gw_ip)
    shared, never = samples(conn, hellos, SHARED, profile), samples(conn, hellos, NEVER, profile)
    for e in shared + never:
        e["given_before"] = e["last_bound"] is not None
        if not times:
            for key in TIMES:
                del e[key]
    out: dict = {
        "window": WINDOW,
        "since": coverage(conn),
        "counts": counts(hellos, nameless(conn, a, b, gw_ip)),
        "shared": shared,
        "never": never,
        "named": name_flows(conn, a, b, gw_ip),
        "doh_shaped": doh_shaped(conn, a, b, gw_ip),
        "days_running": None,
        "new_names": True,
    }
    if out["counts"][SHARED]:
        out["days_running"], out["new_names"] = _streak(conn, a, b, gw_ip, hellos, repeat_days)
    return out


def _shared_domains(hellos: Iterable[Hello]) -> set[str]:
    return {registrable_domain(h.sni) for h in hellos if h.cls == SHARED}


def _streak(
    conn: sqlite3.Connection, a: float, b: float, gw_ip: str, hellos: list[Hello], repeat_days: int
) -> tuple[int | None, bool]:
    """(days running with shared connections, this day included, up to `repeat_days` + 1; whether this
    day has a registrable domain none of those days had). (None, True) for a window that is not one
    calendar day: a streak is of calendar days."""
    if b - a > 90000 or datetime.fromtimestamp(a).time() != datetime.min.time():
        return None, True
    names = _shared_domains(hellos)
    run, seen, day = 1, set(), a
    while run <= repeat_days:
        start = (datetime.fromtimestamp(day) - timedelta(days=1)).timestamp()
        earlier = _shared_domains(classify(conn, start, day, gw_ip))
        if not earlier:
            break
        seen |= earlier
        run, day = run + 1, start
    return run, bool(names - seen)


# ---- one connection explained (tvgw host) ----------------------------------------------------------------
def explain_name(conn: sqlite3.Connection, name: str, a: float, b: float, gw_ip: str) -> dict:
    """`tvgw host NAME`: the name's TLS connections in [a, b) by class, and each one that was not bound
    with what its address was answered for."""
    name = normalize(name)
    hellos = [h for h in classify(conn, a, b, gw_ip) if h.sni == name]
    out: dict = {"counts": counts(hellos, 0), "other": []}
    del out["counts"][NONAME]
    for h in hellos:
        if h.cls in (SHARED, NEVER):
            ans = answers_for(conn, h.dst, h.t - WINDOW, h.t + SLACK)
            out["other"].append(
                {
                    "t": h.t,
                    "dst": h.dst,
                    "dport": h.dport,
                    "cls": h.cls,
                    "answered_for": ans.names_in(h.t - WINDOW, h.t + SLACK)[:3],
                    "last_bound": _last_bound(conn, h.sni, h.dst, h.t - WINDOW),
                }
            )
    out["other"] = out["other"][-SAMPLES:]
    return out


def explain_address(conn: sqlite3.Connection, ip: str, a: float, b: float, gw_ip: str) -> dict:
    """`tvgw host ADDRESS`: the questions answered with the address in [a, b) (each with its CNAME chain,
    how often, the newest time and lifetime), the registrable domains behind them, whether that many
    domains make it a shared address (SHARED_FROM), and the TLS names the TV used there by class."""
    answered: dict[tuple[str, ...], list] = {}
    for t, qname, answers, ttl in conn.execute(
        """SELECT a.t, d.qname, d.answers, a.ttl FROM answer_ip a JOIN dns d ON d.id = a.dns_id
           WHERE a.ip = ? AND a.t >= ? AND a.t < ? ORDER BY a.t""",
        (ip, a, b),
    ):
        names = tuple(chain(qname, answers))
        e = answered.setdefault(names, [0, None, None])
        e[0] += 1
        e[1], e[2] = t, ttl
    domains = {registrable_domain(n[0]) for n in answered if n}
    hellos = [h for h in classify(conn, a, b, gw_ip) if h.dst == ip]
    by_name: dict[str, dict[str, int]] = {}
    for h in hellos:
        by_name.setdefault(h.sni, dict.fromkeys(CLASSES, 0))[h.cls] += 1
    return {
        "answers": [
            {"names": list(names), "n": n, "last": last, "ttl": ttl}
            for names, (n, last, ttl) in sorted(answered.items(), key=lambda kv: (-kv[1][0], kv[0]))
        ],
        "domains": sorted(domains),
        "shared": len(domains) >= SHARED_FROM,
        "hellos": {n: {k: v for k, v in c.items() if v} for n, c in sorted(by_name.items())},
        "since": coverage(conn),
    }
