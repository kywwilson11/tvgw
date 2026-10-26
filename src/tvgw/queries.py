"""Read-side queries over the store: the daily brief and the questions an operator asks most.

Everything returns plain data (lists of tuples / dicts); rendering lives in `tvgw.cli`.
"""

from __future__ import annotations

import re
import sqlite3
import time
from datetime import datetime, timedelta

# names that are the TV doing its job (video, images, app APIs): hidden from "allowed" lists
STREAMING = re.compile(
    r"netflix|nflx|bamgrid|dssott|dssedge|googlevideo|ytimg|youtube|amazonvideo|pv-cdn|aiv-cdn|akamaihd|"
    r"akamaized|peacocktv\.com|nbcuott|pluto\.tv|cloudfront|ggpht|gstatic|images-amazon|media-amazon|"
    r"cdn-apple|fastly|digicert|microsoft\.com"
)


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


def new_hosts(conn: sqlite3.Connection, since: float) -> list[tuple]:
    return conn.execute(
        """SELECT name, category, first_seen, dns_n, tls_n, http_n, last_blocked, COALESCE(last_rule,'')
           FROM hosts WHERE first_seen >= ? ORDER BY first_seen""",
        (since,),
    ).fetchall()


def blocked_retries(conn: sqlite3.Connection, since: float, limit: int = 40) -> list[tuple]:
    return conn.execute(
        """SELECT qname, COUNT(*), MIN(t), MAX(t), COALESCE(rule,'') FROM dns
           WHERE blocked=1 AND t >= ? GROUP BY qname ORDER BY 2 DESC LIMIT ?""",
        (since, limit),
    ).fetchall()


def allowed_non_streaming(conn: sqlite3.Connection, since: float, limit: int = 60) -> list[tuple]:
    rows = conn.execute(
        """SELECT qname, COUNT(*), MAX(t), COALESCE(rule,'') FROM dns
           WHERE blocked=0 AND t >= ? GROUP BY qname ORDER BY 2 DESC""",
        (since,),
    ).fetchall()
    return [r for r in rows if not STREAMING.search(r[0])][:limit]


def top_upload(
    conn: sqlite3.Connection, since: float, until: float | None = None, limit: int = 30
) -> list[tuple]:
    """(name or None, dst, dport, conns, bytes_up, bytes_down) by bytes the TV sent."""
    until = until or float("inf")
    return conn.execute(
        """SELECT (SELECT name FROM v_ip_names v WHERE v.ip=f.dst ORDER BY n DESC LIMIT 1), f.dst, f.dport,
                  COUNT(*), SUM(f.bytes_up), SUM(f.bytes_down)
           FROM flows f WHERE f.t_end >= ? AND f.t_end < ? GROUP BY f.dst, f.dport ORDER BY 5 DESC LIMIT ?""",
        (since, until, limit),
    ).fetchall()


def host_detail(conn: sqlite3.Connection, name: str) -> dict | None:
    name = name.lower()
    h = conn.execute("SELECT * FROM hosts WHERE name=?", (name,)).fetchone()
    if not h:
        return None
    ips = conn.execute(
        "SELECT dst, COUNT(*) FROM tls WHERE sni=? GROUP BY dst ORDER BY 2 DESC LIMIT 10", (name,)
    ).fetchall()
    up = down = 0
    if ips:
        up, down = conn.execute(
            "SELECT COALESCE(SUM(bytes_up),0), COALESCE(SUM(bytes_down),0) FROM flows WHERE dst IN "
            "(SELECT DISTINCT dst FROM tls WHERE sni=?)",
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
    until = until or float("inf")
    rows = conn.execute(
        "SELECT status, uri, bytes FROM http WHERE src='gfts' AND t >= ? AND t < ?", (since, until)
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
    until = until or float("inf")
    return conn.execute(
        "SELECT t, power, COALESCE(app,'') FROM tvstate WHERE t >= ? AND t < ? ORDER BY t", (since, until)
    ).fetchall()


def settings_changes(conn: sqlite3.Connection, since: float) -> list[tuple]:
    return conn.execute("SELECT t, key, value FROM tvsettings WHERE t >= ? ORDER BY t", (since,)).fetchall()


def rules_history(conn: sqlite3.Connection) -> list[tuple]:
    return conn.execute(
        "SELECT kind, text, first_seen, removed_at FROM rules ORDER BY first_seen, kind, text"
    ).fetchall()


def oddports(conn: sqlite3.Connection, since: float, until: float | None = None) -> list[tuple]:
    until = until or float("inf")
    return conn.execute(
        "SELECT proto, dst, dport, COUNT(*) FROM oddport WHERE t >= ? AND t < ? GROUP BY 1,2,3",
        (since, until),
    ).fetchall()


def brief(conn: sqlite3.Connection, day: str) -> dict:
    """Everything worth a daily look, for one calendar day, as plain data."""
    a, b = day_bounds(day)
    o: dict = {"day": day}
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
        dict(zip(("name", "category", "dns", "tls", "http", "blocked"), r, strict=True))
        for r in conn.execute(
            "SELECT name, category, dns_n, tls_n, http_n, last_blocked FROM hosts "
            "WHERE first_seen>=? AND first_seen<? ORDER BY first_seen",
            (a, b),
        )
    ]
    o["blocked_retries"] = [
        dict(zip(("name", "lookups", "rule"), (r[0], r[1], r[4]), strict=True))
        for r in blocked_retries(conn, a, 15)
        if r[2] < b
    ]
    o["allowed_non_streaming"] = [
        {"name": r[0], "lookups": r[1]}
        for r in conn.execute(
            "SELECT qname, COUNT(*) FROM dns WHERE blocked=0 AND t>=? AND t<? GROUP BY qname ORDER BY 2 DESC",
            (a, b),
        )
        if not STREAMING.search(r[0])
    ][:25]
    o["top_upload"] = [
        dict(zip(("name", "dst", "dport", "conns", "bytes_up", "bytes_down"), r, strict=True))
        for r in top_upload(conn, a, b, 12)
    ]
    o["gfts"] = [
        dict(zip(("status", "biz_code", "requests", "bytes"), r, strict=True))
        for r in gfts_summary(conn, a, b)
    ]
    o["oddports"] = [dict(zip(("proto", "dst", "dport", "n"), r, strict=True)) for r in oddports(conn, a, b)]
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
