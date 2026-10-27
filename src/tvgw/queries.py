"""Read-side queries over the store: the daily brief and the questions an operator asks most.

Everything returns plain data (lists of tuples / dicts); rendering lives in `tvgw.cli`. Flows are
named per connection: the TLS ClientHello captured for the same destination, destination port and
TV source port, inside the flow's lifetime. conntrack reports a flow when its garbage collector
gets to it, so the start time it implies runs late by up to a minute; a hello may therefore
precede `t_start` a little (`FLOW_SLACK`). Which names are "the TV doing its job" comes from the
profile (`expected_categories`), not from a list hidden in here.
"""

from __future__ import annotations

import json
import re
import sqlite3
import time
from datetime import datetime, timedelta

from tvgw.names import is_public_name, registrable_domain, shannon_entropy
from tvgw.profile import Profile

FLOW_SLACK = 300  # seconds a hello may precede conntrack's (late) start time
# the TLS name of the connection a flow row describes (NULL: UDP, plain HTTP, or no hello captured)
FLOW_NAME = (
    "(SELECT x.sni FROM tls x WHERE x.dst=f.dst AND x.sport=f.sport AND x.dport=f.dport"
    f" AND x.t BETWEEN f.t_start-{FLOW_SLACK} AND f.t_end ORDER BY x.t DESC LIMIT 1)"
)
LONG_NAME = 100  # a DNS name longer than this carries data (tunnelling, tracking ids)
RANDOM_LABEL = (16, 3.6)  # a label at least this long with this many bits/char looks generated
FANOUT = 200  # distinct names under one registrable domain in a day
STALE = 7200  # a source not read for this long is "not assessed", not "quiet"


def since_epoch(s: str, now: float | None = None) -> float:
    """'2h', '1d', '7d' or an ISO date/time -> epoch seconds."""
    now = now or time.time()
    m = re.fullmatch(r"(\d+(?:\.\d+)?)\s*([smhdw])", s.strip().lower())
    if m:
        return now - float(m.group(1)) * {"s": 1, "m": 60, "h": 3600, "d": 86400, "w": 604800}[m.group(2)]
    return datetime.fromisoformat(s.strip()).timestamp()


def day_bounds(day: str) -> tuple[float, float]:
    d = datetime.strptime(day, "%Y-%m-%d")
    return d.timestamp(), (d + timedelta(days=1)).timestamp()


def yesterday() -> str:
    return (datetime.now() - timedelta(days=1)).strftime("%Y-%m-%d")


def _until(until: float | None) -> float:
    return float("inf") if until is None else until


def new_hosts(conn: sqlite3.Connection, since: float, until: float | None = None) -> list[tuple]:
    """(name, category, first_seen, dns_n, tls_n, http_n, last_blocked, rule, new_domain) first seen in
    the window; `new_domain` is False when another name of the same registrable domain came earlier."""
    earliest: dict[str, float] = {}
    for name, first in conn.execute("SELECT name, first_seen FROM hosts WHERE first_seen IS NOT NULL"):
        d = registrable_domain(name)
        earliest[d] = min(earliest.get(d, first), first)
    rows = conn.execute(
        """SELECT name, category, first_seen, dns_n, tls_n, http_n, last_blocked, COALESCE(last_rule,'')
           FROM hosts WHERE first_seen >= ? AND first_seen < ? ORDER BY first_seen""",
        (since, _until(until)),
    ).fetchall()
    return [(*r, earliest[registrable_domain(r[0])] >= r[2]) for r in rows]


def blocked_retries(
    conn: sqlite3.Connection, since: float, until: float | None = None, limit: int = 40
) -> list[tuple]:
    return conn.execute(
        """SELECT qname, COUNT(*), MIN(t), MAX(t), COALESCE(rule,'') FROM dns
           WHERE blocked=1 AND t >= ? AND t < ? GROUP BY qname ORDER BY 2 DESC LIMIT ?""",
        (since, _until(until), limit),
    ).fetchall()


def allowed_unexpected(
    conn: sqlite3.Connection, since: float, until: float | None, profile: Profile, limit: int = 60
) -> list[tuple]:
    """(name, category, lookups, last, allow rule): allowed names outside the profile's expected
    categories, most asked first. Blocked-category names here are rule gaps; Other are candidates."""
    rows = conn.execute(
        """SELECT qname, COUNT(*), MAX(t), COALESCE(rule,'') FROM dns
           WHERE blocked=0 AND t >= ? AND t < ? GROUP BY qname ORDER BY 2 DESC""",
        (since, _until(until)),
    ).fetchall()
    out = []
    for qname, n, last, rule in rows:
        if not is_public_name(qname) or profile.is_expected(qname):
            continue
        out.append((qname, profile.categorize(qname), n, last, rule))
        if len(out) == limit:
            break
    return out


def top_upload(
    conn: sqlite3.Connection, since: float, until: float | None = None, limit: int = 30
) -> list[tuple]:
    """(name or None, one dst, distinct dsts, dport, conns, bytes_up, bytes_down) by bytes the TV sent,
    grouped by the connection's TLS name (or by IP when no hello was captured)."""
    return conn.execute(
        f"""WITH f AS (SELECT dst, dport, sport, t_start, t_end, bytes_up, bytes_down FROM flows
                       WHERE t_end >= ? AND t_end < ?),
                named AS (SELECT {FLOW_NAME} AS name, dst, dport, bytes_up, bytes_down FROM f)
            SELECT name, MIN(dst), COUNT(DISTINCT dst), dport, COUNT(*), SUM(bytes_up), SUM(bytes_down)
            FROM named GROUP BY COALESCE(name, dst), dport ORDER BY 6 DESC LIMIT ?""",
        (since, _until(until), limit),
    ).fetchall()


def host_detail(conn: sqlite3.Connection, name: str) -> dict | None:
    name = name.lower().rstrip(".")
    h = conn.execute("SELECT * FROM hosts WHERE name=?", (name,)).fetchone()
    if not h:
        return None
    ips = conn.execute(
        "SELECT dst, COUNT(*) FROM tls WHERE sni=? GROUP BY dst ORDER BY 2 DESC LIMIT 10", (name,)
    ).fetchall()
    conns, up, down = conn.execute(
        f"""SELECT COUNT(*), COALESCE(SUM(bytes_up),0), COALESCE(SUM(bytes_down),0) FROM flows f
            WHERE f.id IN (SELECT f2.id FROM tls x JOIN flows f2 ON f2.dst=x.dst AND f2.dport=x.dport
                           AND f2.sport=x.sport AND x.t BETWEEN f2.t_start-{FLOW_SLACK} AND f2.t_end
                           WHERE x.sni=?)""",
        (name,),
    ).fetchone()
    return {
        "name": name,
        "category": h[3],
        "first_seen": h[1],
        "last_seen": h[2],
        "dns_n": h[4],
        "tls_n": h[5],
        "http_n": h[6],
        "last_blocked": h[7],
        "rules": [
            r[0]
            for r in conn.execute("SELECT DISTINCT rule FROM dns WHERE qname=? AND rule IS NOT NULL", (name,))
        ],
        "ips": ips,
        "conns": conns,
        "bytes_up": up,
        "bytes_down": down,
        "http": conn.execute(
            "SELECT COUNT(*), MIN(status), MAX(status) FROM http WHERE host=?", (name,)
        ).fetchone(),
        "by_day": conn.execute(
            "SELECT date(t,'unixepoch','localtime'), COUNT(*), SUM(blocked) FROM dns "
            "WHERE qname=? GROUP BY 1 ORDER BY 1",
            (name,),
        ).fetchall(),
    }


def gfts_summary(conn: sqlite3.Connection, since: float, until: float | None = None) -> list[tuple]:
    """(status, biz_code, requests, bytes) for the URL-filter log."""
    rows = conn.execute(
        "SELECT status, uri, bytes FROM http WHERE src='gfts' AND t >= ? AND t < ?", (since, _until(until))
    ).fetchall()
    agg: dict[tuple[int, str], list[int]] = {}
    for status, uri, nbytes in rows:
        m = re.search(r"biz_code=([A-Za-z_]+)", uri or "")
        key = (status, m.group(1) if m else "(other)")
        a = agg.setdefault(key, [0, 0])
        a[0] += 1
        a[1] += nbytes or 0
    return sorted(((k[0], k[1], v[0], v[1]) for k, v in agg.items()), key=lambda r: (r[0], -r[2]))


def tvstate(conn: sqlite3.Connection, since: float, until: float | None = None) -> list[tuple]:
    return conn.execute(
        "SELECT t, power, COALESCE(app,'') FROM tvstate WHERE t >= ? AND t < ? ORDER BY t",
        (since, _until(until)),
    ).fetchall()


def settings_changes(conn: sqlite3.Connection, since: float) -> list[tuple]:
    return conn.execute("SELECT t, key, value FROM tvsettings WHERE t >= ? ORDER BY t", (since,)).fetchall()


def rules_history(conn: sqlite3.Connection) -> list[tuple]:
    return conn.execute(
        "SELECT kind, text, first_seen, removed_at FROM rules ORDER BY first_seen, kind, text"
    ).fetchall()


def oddports(conn: sqlite3.Connection, since: float, until: float | None = None) -> list[tuple]:
    return conn.execute(
        "SELECT proto, dst, dport, COUNT(*) FROM oddport WHERE t >= ? AND t < ? GROUP BY 1,2,3",
        (since, _until(until)),
    ).fetchall()


def lan_probes(conn: sqlite3.Connection, since: float, until: float | None = None) -> list[tuple]:
    """(dst, proto, dport, n): connections the TV opened towards private or multicast addresses that
    are not the gateway. The firewall drops them; this is the evidence it had to."""
    return conn.execute(
        "SELECT dst, proto, dport, COUNT(*) FROM lanprobe WHERE t >= ? AND t < ? GROUP BY 1,2,3 "
        "ORDER BY 4 DESC",
        (since, _until(until)),
    ).fetchall()


def dns_anomalies(
    conn: sqlite3.Connection, since: float, until: float | None, profile: Profile
) -> list[dict]:
    """Names outside the expected categories that look like data rather than names: very long,
    a long high-entropy label, or one registrable domain fanning out into hundreds of names."""
    out: list[dict] = []
    fanout: dict[str, set[str]] = {}
    for qname, n, blocked in conn.execute(
        "SELECT qname, COUNT(*), MAX(blocked) FROM dns WHERE t >= ? AND t < ? GROUP BY qname",
        (since, _until(until)),
    ):
        if not is_public_name(qname) or profile.is_expected(qname):
            continue
        fanout.setdefault(registrable_domain(qname), set()).add(qname)
        label = max(qname.split("."), key=len)
        if len(qname) > LONG_NAME:
            out.append(
                {
                    "kind": "long name",
                    "name": qname,
                    "lookups": n,
                    "blocked": blocked,
                    "detail": f"{len(qname)} chars",
                }
            )
        elif len(label) >= RANDOM_LABEL[0] and shannon_entropy(label) >= RANDOM_LABEL[1]:
            out.append(
                {
                    "kind": "random label",
                    "name": qname,
                    "lookups": n,
                    "blocked": blocked,
                    "detail": f"{shannon_entropy(label):.1f} bits/char over {len(label)} chars",
                }
            )
    for domain, names in fanout.items():
        if len(names) > FANOUT:
            out.append(
                {
                    "kind": "fan-out",
                    "name": domain,
                    "lookups": len(names),
                    "blocked": None,
                    "detail": f"{len(names)} distinct names",
                }
            )
    return out


def coverage(conn: sqlite3.Connection, since: float, until: float, now: float | None = None) -> dict:
    """Did the pipeline actually look? Last ingest run and its warnings, and per source: when it was
    last read and how many rows landed in the window. A source not read for `STALE` seconds before
    the end of the window (or before now, if the window is still open) is listed as not assessed."""
    now = now or time.time()
    last_run = conn.execute("SELECT value FROM meta WHERE key='last_run'").fetchone()
    warnings = conn.execute("SELECT value FROM meta WHERE key='last_warnings'").fetchone()
    read_raw = conn.execute("SELECT value FROM meta WHERE key='sources_read'").fetchone()
    try:
        read = json.loads(read_raw[0]) if read_raw else {}
    except ValueError:
        read = {}
    rows = {
        "flows": "SELECT COUNT(*) FROM flows WHERE t_end >= ? AND t_end < ?",
        "dns": "SELECT COUNT(*) FROM dns WHERE t >= ? AND t < ?",
        "pcaps": "SELECT COUNT(*) FROM pcaps_done WHERE done_at >= ? AND done_at < ?",
        "gfts": "SELECT COUNT(*) FROM http WHERE src='gfts' AND t >= ? AND t < ?",
        "tvstate": "SELECT COUNT(*) FROM tvstate WHERE t >= ? AND t < ?",
        "oddport": "SELECT COUNT(*) FROM oddport WHERE t >= ? AND t < ?",
    }
    stale_after = min(until, now) - STALE
    sources = {}
    for src, q in rows.items():
        last = read.get(src)
        sources[src] = {
            "rows": conn.execute(q, (since, until)).fetchone()[0],
            "last_read": last,
            "assessed": last is not None and last >= stale_after,
        }
    try:
        warn_list = json.loads(warnings[0]) if warnings else []
    except ValueError:
        warn_list = []
    return {
        "last_run": float(last_run[0]) if last_run else None,
        "warnings": warn_list,
        "sources": sources,
        "not_assessed": [s for s, v in sources.items() if not v["assessed"]],
    }


def brief(conn: sqlite3.Connection, day: str, profile: Profile, now: float | None = None) -> dict:
    """Everything worth a daily look, for one calendar day, as plain data."""
    a, b = day_bounds(day)
    o: dict = {"day": day}
    o["coverage"] = coverage(conn, a, b, now)
    o["dns"] = dict(
        zip(
            ("lookups", "blocked", "names"),
            conn.execute(
                "SELECT COUNT(*), COALESCE(SUM(blocked),0), COUNT(DISTINCT qname) FROM dns "
                "WHERE t>=? AND t<?",
                (a, b),
            ).fetchone(),
            strict=True,
        )
    )
    o["flows"] = dict(
        zip(
            ("conns", "bytes_up", "bytes_down"),
            conn.execute(
                "SELECT COUNT(*), COALESCE(SUM(bytes_up),0), COALESCE(SUM(bytes_down),0) FROM flows "
                "WHERE t_end>=? AND t_end<?",
                (a, b),
            ).fetchone(),
            strict=True,
        )
    )
    o["new_hosts"] = [
        {
            "name": r[0],
            "category": r[1],
            "dns": r[3],
            "tls": r[4],
            "http": r[5],
            "blocked": r[6],
            "new_domain": r[8],
        }
        for r in new_hosts(conn, a, b)
    ]
    o["blocked_retries"] = [
        dict(zip(("name", "lookups", "rule"), (r[0], r[1], r[4]), strict=True))
        for r in blocked_retries(conn, a, b, 15)
    ]
    o["allowed_unexpected"] = [
        {"name": r[0], "category": r[1], "lookups": r[2]} for r in allowed_unexpected(conn, a, b, profile, 25)
    ]
    o["top_upload"] = [
        dict(zip(("name", "dst", "ips", "dport", "conns", "bytes_up", "bytes_down"), r, strict=True))
        for r in top_upload(conn, a, b, 12)
    ]
    o["gfts"] = [
        dict(zip(("status", "biz_code", "requests", "bytes"), r, strict=True))
        for r in gfts_summary(conn, a, b)
    ]
    o["oddports"] = [dict(zip(("proto", "dst", "dport", "n"), r, strict=True)) for r in oddports(conn, a, b)]
    o["lan_probes"] = [
        dict(zip(("dst", "proto", "dport", "n"), r, strict=True)) for r in lan_probes(conn, a, b)
    ]
    o["dns_anomalies"] = dns_anomalies(conn, a, b, profile)
    o["tvstate"] = [
        {"time": datetime.fromtimestamp(t).strftime("%H:%M"), "power": p, "app": app}
        for t, p, app in tvstate(conn, a, b)
    ]
    o["rule_changes"] = [
        dict(zip(("kind", "text", "added", "removed"), r, strict=True))
        for r in conn.execute(
            "SELECT kind, text, first_seen, removed_at FROM rules WHERE (first_seen>=? AND first_seen<?) OR "
            "(removed_at>=? AND removed_at<?)",
            (a, b, a, b),
        )
    ]
    return o
