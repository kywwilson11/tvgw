"""Read-side queries over the store: the daily brief and the questions an operator asks most.

Everything returns plain data (lists of tuples / dicts); rendering lives in `tvgw.cli`. Flows are
named per connection: the TLS ClientHello captured for the same destination, destination port and
TV source port, inside the flow's lifetime. conntrack reports a flow when its garbage collector
gets to it, so the start time it implies runs late by up to a minute; a hello may therefore
precede `t_start` a little (`FLOW_SLACK`). Which names are "the TV doing its job" comes from the
profile (`expected_categories`), not from a list hidden in here.
"""

from __future__ import annotations

import itertools
import json
import re
import sqlite3
import time
from datetime import datetime, timedelta

from tvgw.names import is_public_name, registrable_domain, shannon_entropy
from tvgw.profile import Profile

# firewall counters worth a line in the brief, in the order shown (comment prefix -> label)
FW_LINES = (
    ("TV DNS aimed elsewhere", "DNS forced to AdGuard"),
    ("DoT/DoQ", "DoT/DoQ"),
    ("QUIC", "QUIC"),
    ("DoH resolvers", "DoH"),
    ("TV may not reach the home LAN", "LAN"),
    ("manual IP blocks", "IP blocks"),
    ("invalid", "invalid"),
    ("no GRE/ESP/6in4", "tunnels"),
    ("no ICMP tunnels", "ICMP"),
    ("unexpected port", "odd ports"),
    ("STRICT_PORTS", "odd ports"),
    ("TV talks to the gateway address only", "to other Pi addresses"),
    ("TV may not reach other Pi services", "other Pi services"),
    ("no NetBIOS/SSDP chatter", "Pi chatter"),
    ("nothing unsolicited from the VPN", "from VPN"),
)

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


def _like(pattern: str) -> str:
    return pattern.lower().replace("*", "%")


def must_allow_blocked(
    conn: sqlite3.Connection, since: float, until: float | None, profile: Profile
) -> list[tuple]:
    """(name, blocked lookups, rule) for must-allow names that came back blocked: a red line."""
    names = tuple(profile.must_allow)
    if not names:
        return []
    marks = ",".join("?" * len(names))
    return conn.execute(
        f"SELECT qname, COUNT(*), COALESCE(MAX(rule),'') FROM dns WHERE blocked=1 AND t >= ? AND t < ? "
        f"AND qname IN ({marks}) GROUP BY qname ORDER BY 2 DESC",
        (since, _until(until), *names),
    ).fetchall()


def clock_sync(conn: sqlite3.Connection, since: float, until: float | None, profile: Profile) -> dict:
    """Lookups of the vendor's clock hosts: webOS takes its time from LG's SDP reply, so a day the TV
    was on with no such lookup, or any blocked one, means the clock is at risk."""
    if not profile.clock_hosts:
        return {"lookups": 0, "blocked": 0, "first": None, "hosts": []}
    where = " OR ".join("qname LIKE ?" for _ in profile.clock_hosts)
    n, blocked, first = conn.execute(
        f"SELECT COUNT(*), COALESCE(SUM(blocked),0), MIN(t) FROM dns WHERE t >= ? AND t < ? AND ({where})",
        (since, _until(until), *(_like(h) for h in profile.clock_hosts)),
    ).fetchone()
    return {"lookups": n, "blocked": blocked, "first": first, "hosts": list(profile.clock_hosts)}


def fw_activity(conn: sqlite3.Connection, since: float, until: float | None = None) -> list[tuple]:
    """(rule comment, packets) stopped or counted by each firewall rule in the window: the sum of
    positive steps between consecutive counter snapshots, so a re-apply (counters back to zero)
    costs at most the packets of that one interval."""
    until_ = _until(until)
    prev: dict[str, int] = dict(
        conn.execute(
            "SELECT rule, packets FROM fw_counters c WHERE t = (SELECT MAX(t) FROM fw_counters c2 "
            "WHERE c2.rule = c.rule AND c2.t < ?)",
            (since,),
        ).fetchall()
    )
    acc: dict[str, int] = {}
    for rule, _t, packets in conn.execute(
        "SELECT rule, t, packets FROM fw_counters WHERE t >= ? AND t < ? ORDER BY rule, t", (since, until_)
    ):
        if rule in prev:
            acc[rule] = acc.get(rule, 0) + (packets - prev[rule] if packets >= prev[rule] else packets)
        else:
            acc.setdefault(rule, 0)
        prev[rule] = packets
    return sorted(acc.items(), key=lambda kv: -kv[1])


def verify_summary(conn: sqlite3.Connection, since: float, until: float | None = None) -> dict:
    runs, failed = conn.execute(
        "SELECT COUNT(*), COALESCE(SUM(ok=0),0) FROM verify WHERE t >= ? AND t < ?", (since, _until(until))
    ).fetchone()
    last = conn.execute(
        "SELECT t, failures FROM verify WHERE ok=0 AND t >= ? AND t < ? ORDER BY t DESC LIMIT 1",
        (since, _until(until)),
    ).fetchone()
    try:
        failures = json.loads(last[1]) if last else []
    except ValueError:
        failures = []
    return {
        "runs": runs,
        "failed": failed,
        "last_failure_t": last[0] if last else None,
        "last_failures": failures,
    }


def unresolved_flows(
    conn: sqlite3.Connection, since: float, until: float | None, gw_ip: str, limit: int = 20
) -> list[tuple]:
    """(dst, dport, conns, bytes_up, bytes_down) for TCP destinations the TV reached without any DNS
    answer, TLS name or HTTP host explaining them: hardcoded addresses, or a DNS bypass."""
    rows = conn.execute(
        """SELECT dst, dport, COUNT(*), SUM(bytes_up), SUM(bytes_down) FROM flows f
           WHERE proto='tcp' AND t_end >= ? AND t_end < ? AND dst != ?
             AND NOT EXISTS (SELECT 1 FROM tls x WHERE x.dst = f.dst)
           GROUP BY dst, dport ORDER BY 4 DESC""",
        (since, _until(until), gw_ip),
    ).fetchall()
    out = []
    for dst, dport, n, up, down in rows:
        if not is_public_address(dst):
            continue
        answered = conn.execute(
            "SELECT 1 FROM dns WHERE t >= ? AND t < ? AND answers LIKE ? LIMIT 1",
            (since - 86400, _until(until), f"%{dst}%"),
        ).fetchone()
        if not answered:
            out.append((dst, dport, n, up, down))
        if len(out) == limit:
            break
    return out


def is_public_address(ip: str) -> bool:
    import ipaddress

    try:
        a = ipaddress.ip_address(ip)
    except ValueError:
        return False
    return not (a.is_private or a.is_multicast or a.is_link_local or a.is_loopback or a.is_unspecified)


def ptr_sweeps(conn: sqlite3.Connection, since: float, until: float | None = None) -> tuple[int, int]:
    """(lookups, distinct names) of reverse lookups for private addresses: the TV taking inventory."""
    return conn.execute(
        "SELECT COUNT(*), COUNT(DISTINCT qname) FROM dns WHERE t >= ? AND t < ? AND qtype='PTR' "
        "AND (qname LIKE '%.10.in-addr.arpa' OR qname LIKE '%.168.192.in-addr.arpa' "
        "OR qname LIKE '%.16.172.in-addr.arpa' OR qname LIKE '%.17.172.in-addr.arpa' "
        "OR qname LIKE '%.2_.172.in-addr.arpa' OR qname LIKE '%.3_.172.in-addr.arpa')",
        (since, _until(until)),
    ).fetchone()


def firmware_changes(conn: sqlite3.Connection, since: float, until: float | None = None) -> list[dict]:
    """Firmware versions first seen in the window, each with the names that appeared in the 72 h after:
    updates are when new endpoints arrive."""
    out = []
    for t, value in conn.execute(
        "SELECT t, value FROM tvsettings WHERE key='firmware' AND t >= ? AND t < ? ORDER BY t",
        (since, _until(until)),
    ):
        names = [
            r[0]
            for r in conn.execute(
                "SELECT name FROM hosts WHERE first_seen >= ? AND first_seen < ? ORDER BY first_seen",
                (t, t + 72 * 3600),
            )
        ]
        out.append({"t": t, "firmware": value, "new_hosts": names})
    return out


def standby_activity(conn: sqlite3.Connection, since: float, until: float | None = None) -> dict:
    """Lookups and connections during hours the TV reported itself off or asleep (anything but
    Active): with instant-on off this should be nothing at all. Readings are hourly, so an hour
    counts as off only when the TV said so at both ends of it."""
    readings = conn.execute(
        "SELECT t, power FROM tvstate WHERE t >= ? AND t < ? ORDER BY t", (since, _until(until))
    ).fetchall()
    lookups = conns = up = off = 0
    for (t, power), (end, power_next) in itertools.pairwise(readings):
        if power == "Active" or power_next == "Active":
            continue
        off += 1
        lookups += conn.execute("SELECT COUNT(*) FROM dns WHERE t >= ? AND t < ?", (t, end)).fetchone()[0]
        c, u = conn.execute(
            "SELECT COUNT(*), COALESCE(SUM(bytes_up),0) FROM flows WHERE t_end >= ? AND t_end < ?", (t, end)
        ).fetchone()
        conns, up = conns + c, up + u
    return {"off_hours": off, "lookups": lookups, "conns": conns, "bytes_up": up}


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


def brief(
    conn: sqlite3.Connection, day: str, profile: Profile, now: float | None = None, gw_ip: str = "10.10.10.1"
) -> dict:
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
    o["must_allow_blocked"] = [
        dict(zip(("name", "lookups", "rule"), r, strict=True))
        for r in must_allow_blocked(conn, a, b, profile)
    ]
    o["clock"] = clock_sync(conn, a, b, profile)
    o["firewall"] = verify_summary(conn, a, b)
    o["firewall"]["activity"] = [{"rule": r, "packets": n} for r, n in fw_activity(conn, a, b)]
    o["unresolved"] = [
        dict(zip(("dst", "dport", "conns", "bytes_up", "bytes_down"), r, strict=True))
        for r in unresolved_flows(conn, a, b, gw_ip)
    ]
    o["ptr"] = dict(zip(("lookups", "names"), ptr_sweeps(conn, a, b), strict=True))
    o["firmware_changes"] = firmware_changes(conn, a, b)
    o["standby"] = standby_activity(conn, a, b)
    o["tvstate"] = [
        {"time": datetime.fromtimestamp(t).strftime("%H:%M"), "power": p, "app": app}
        for t, p, app in tvstate(conn, a, b)
    ]
    o["rule_changes"] = [
        dict(zip(("kind", "text", "added", "removed"), r, strict=True))
        for r in conn.execute(
            "SELECT kind, text, first_seen, removed_at FROM rules WHERE (first_seen>=? AND first_seen<?) OR "
            "(removed_at>=? AND removed_at<?) ORDER BY first_seen, kind, text",
            (a, b, a, b),
        )
    ]
    o["red_lines"] = red_lines(o)
    return o


def red_lines(o: dict) -> list[str]:
    """The few things that must never be true, as sentences for the top of the brief."""
    out = []
    for m in o.get("must_allow_blocked", []):
        out.append(f"must-allow name blocked: {m['name']} x{m['lookups']} by {m['rule'] or 'a list'}")
    clock = o.get("clock") or {}
    tv_on = any(s["power"] == "Active" for s in o.get("tvstate", []))
    if clock.get("blocked"):
        out.append(f"clock host lookups blocked: {clock['blocked']} (the TV's clock comes from them)")
    elif clock.get("hosts") and tv_on and not clock.get("lookups"):
        out.append("TV was on but never looked up its clock host (check the SDP hosts are reachable)")
    fw = o.get("firewall") or {}
    if fw.get("failed"):
        last = "; ".join(fw["last_failures"])
        out.append(f"firewall checks failed {fw['failed']} of {fw['runs']} times; last: {last}")
    cov = o.get("coverage") or {}
    if cov.get("warnings"):
        out.append(f"ingest warnings: {len(cov['warnings'])}")
    return out
