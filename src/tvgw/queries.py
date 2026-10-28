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
import statistics
import time
from datetime import datetime, timedelta

from tvgw import gfts
from tvgw.lgwebos import ACR_KEY
from tvgw.names import (
    is_lan_address,
    is_public_address,
    is_public_name,
    registrable_domain,
    reverse_ptr,
    shannon_entropy,
)
from tvgw.profile import Profile

# firewall counters worth a line in the brief, in the order shown (comment prefix -> label); every
# counted comment in tvgw-apply has a line here or is a listed accept (tests/unit/test_fw_lines.py)
FW_LINES = (
    ("TV DNS aimed elsewhere", "DNS forced to AdGuard"),
    ("TV DNS to the gateway", "DNS to AdGuard"),
    ("DoT/DoQ", "DoT/DoQ"),
    ("QUIC", "QUIC"),
    ("DoH resolvers", "DoH"),
    ("TV may not reach the home LAN", "LAN"),
    ("manual IP blocks", "IP blocks"),
    ("invalid", "invalid"),
    ("TV source outside its subnet", "foreign source"),
    ("no GRE/ESP/6in4", "tunnels"),
    ("no ICMP tunnels", "ICMP"),
    ("STRICT_PORTS", "odd ports"),
    ("LG firmware fallback path", "LG 8080 fallback"),  # accepted on purpose, counted and logged
    ("TV talks to the gateway address only", "to other Pi addresses"),
    ("TV may not reach other Pi services", "other Pi services"),
    ("no NetBIOS/SSDP chatter", "Pi chatter"),
    ("nothing unsolicited from the VPN", "from VPN"),
    ("nothing else into or out of the TV subnet", "other forward drops"),
    ("only via the chosen uplink", "wrong uplink"),
    ("no IPv6 from the TV", "IPv6"),
    ("TV to an address DNS never returned", "to addresses DNS never gave"),
)

FLOW_SLACK = 300  # seconds a hello may precede conntrack's (late) start time
# the TLS name of the connection a flow row describes (NULL: UDP, plain HTTP, or no hello captured)
FLOW_NAME = (
    "(SELECT x.sni FROM tls x WHERE x.dst=f.dst AND x.sport=f.sport AND x.dport=f.dport"
    f" AND x.t BETWEEN f.t_start-{FLOW_SLACK} AND f.t_end ORDER BY x.t DESC LIMIT 1)"
)
LONG_NAME = 100  # a DNS name longer than this carries data (tunnelling, tracking ids)
RANDOM_LABEL = (16, 3.6)  # a label at least this long with this many bits/char looks generated
FANOUT = 200  # distinct names under one registrable domain per day; scaled by the window length
STALE = 7200  # a source not read for this long is "not assessed", not "quiet"
STANDBY_GAP = 5400  # readings are hourly; two readings further apart hide a missed reading, not an off hour
HEADER_BYTES = 40  # IPv4 + TCP headers conntrack counts on every packet, payload or not
PERIODIC_JITTER = 0.15  # MAD/median of the intervals below this is a timer, not a person
PERIOD_RANGE = (10.0, 86400.0)  # seconds: faster is a stream's own pacing, slower is not a beacon in a day
BEACON_MIN = 12  # events before an interval statistic means anything
BURST_GAP = 5.0  # seconds: connections opened this close together are one event (a page, not a timer)
ACR_PERIOD = (10.0, 20.0)  # LG's ACR client uploads about every 15 s (Anselmi et al., IMC 2024)
ACR_PAYLOAD = 4096  # bytes per connection: fingerprints are small


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
           FROM hosts WHERE first_seen >= ? AND first_seen < ? ORDER BY first_seen, name""",
        (since, _until(until)),
    ).fetchall()
    return [(*r, earliest[registrable_domain(r[0])] >= r[2]) for r in rows]


def blocked_retries(
    conn: sqlite3.Connection, since: float, until: float | None = None, limit: int = 40
) -> list[tuple]:
    return conn.execute(
        """SELECT qname, COUNT(*), MIN(t), MAX(t), COALESCE(MAX(rule),'') FROM dns
           WHERE blocked=1 AND t >= ? AND t < ? GROUP BY qname ORDER BY 2 DESC, qname LIMIT ?""",
        (since, _until(until), limit),
    ).fetchall()


def allowed_unexpected(
    conn: sqlite3.Connection, since: float, until: float | None, profile: Profile, limit: int = 60
) -> list[tuple]:
    """(name, category, lookups, last, allow rule): allowed names outside the profile's expected
    categories, most asked first. Blocked-category names here are rule gaps; Other are candidates."""
    # the bare `rule` comes from the MAX(t) row (SQLite's bare-column rule): the latest lookup's rule
    rows = conn.execute(
        """SELECT qname, COUNT(*), MAX(t), COALESCE(rule,'') FROM dns
           WHERE blocked=0 AND t >= ? AND t < ? GROUP BY qname ORDER BY 2 DESC, qname""",
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
    conn: sqlite3.Connection,
    since: float,
    until: float | None = None,
    limit: int = 30,
    exclude_dst: str | None = None,
) -> list[tuple]:
    """(name or None, one dst, distinct dsts, dport, conns, bytes_up, bytes_down) by bytes the TV sent,
    grouped by the connection's TLS name (or by IP when no hello was captured). `exclude_dst` keeps
    the gateway itself (DNS, URL filter) out of the list."""
    return conn.execute(
        f"""WITH f AS (SELECT dst, dport, sport, t_start, t_end, bytes_up, bytes_down, pkts_up FROM flows
                       WHERE t_end >= ? AND t_end < ? AND dst != COALESCE(?, '')),
                named AS (SELECT {FLOW_NAME} AS name, dst, dport, bytes_up, bytes_down, pkts_up FROM f)
            SELECT name, MIN(dst), COUNT(DISTINCT dst), dport, COUNT(*), SUM(bytes_up), SUM(bytes_down),
                   SUM(pkts_up)
            FROM named GROUP BY COALESCE(name, dst), dport ORDER BY 6 DESC, 1, 2, 4 LIMIT ?""",
        (since, _until(until), exclude_dst, limit),
    ).fetchall()


def payload_bound(bytes_up: int | None, pkts_up: int | None) -> int | None:
    """What the TV can have sent as payload: conntrack's bytes less HEADER_BYTES per packet (a pure
    ACK is all header), never below zero; None when the packet count is unknown."""
    if bytes_up is None or pkts_up is None:
        return None
    return max(0, bytes_up - HEADER_BYTES * pkts_up)


def beacons(
    conn: sqlite3.Connection, since: float, until: float | None = None, limit: int = 12
) -> list[dict]:
    """Names (bare addresses when no hello named them) the TV connects to on a timer: at least
    BEACON_MIN events in the window (connections opened within BURST_GAP of an event's first start
    belong to it: a burst is one event) whose intervals have MAD/median under PERIODIC_JITTER and a
    median within PERIOD_RANGE.
    The size half is the median bytes per connection and its payload bound. `acr_like` marks the ACR
    client's cadence: a period in ACR_PERIOD with payload under ACR_PAYLOAD. A Poisson stream has
    MAD/median near 0.5 and never passes; a 60 s timer with 5 % jitter does. O(n log n) per name."""
    rows = conn.execute(
        f"""SELECT COALESCE({FLOW_NAME}, f.dst), {FLOW_NAME} IS NOT NULL,
                   f.t_start, f.bytes_up, f.pkts_up, f.dport
            FROM flows f WHERE f.t_start IS NOT NULL AND f.t_start >= ? AND f.t_start < ?""",
        (since, _until(until)),
    ).fetchall()
    category = dict(conn.execute("SELECT name, category FROM hosts"))
    by: dict[str, list] = {}
    for name, named, t, bu, pu, dport in rows:
        by.setdefault(name, []).append((t, bu or 0, pu or 0, dport, bool(named)))
    out = []
    for name, conns in by.items():
        starts = sorted(t for t, *_ in conns)
        events = [starts[0]]
        for t in starts[1:]:
            if t - events[-1] > BURST_GAP:
                events.append(t)
        if len(events) < BEACON_MIN:
            continue
        gaps = [b - a for a, b in itertools.pairwise(events)]
        period = statistics.median(gaps)
        jitter = statistics.median(abs(g - period) for g in gaps) / period
        if jitter >= PERIODIC_JITTER or not PERIOD_RANGE[0] <= period <= PERIOD_RANGE[1]:
            continue
        payload = statistics.median(payload_bound(bu, pu) for _, bu, pu, _, _ in conns)
        out.append(
            {
                "name": name,
                "named": conns[0][4],
                "category": category.get(name),
                "conns": len(conns),
                "period": period,
                "jitter": jitter,
                "bytes_up": statistics.median(bu for _, bu, *_ in conns),
                "payload": payload,
                "dports": sorted({c[3] for c in conns}),
                "first": events[0],
                "last": events[-1],
                "acr_like": ACR_PERIOD[0] <= period <= ACR_PERIOD[1] and payload < ACR_PAYLOAD,
            }
        )
    out.sort(key=lambda r: (r["jitter"], -r["conns"], r["name"]))
    return out[:limit]


def host_detail(conn: sqlite3.Connection, name: str) -> dict | None:
    name = name.lower().rstrip(".")
    h = conn.execute(
        "SELECT first_seen, last_seen, category, dns_n, tls_n, http_n, last_blocked FROM hosts WHERE name=?",
        (name,),
    ).fetchone()
    if not h:
        return None
    first_seen, last_seen, category, dns_n, tls_n, http_n, last_blocked = h
    ips = conn.execute(
        "SELECT dst, COUNT(*) FROM tls WHERE sni=? GROUP BY dst ORDER BY 2 DESC, dst LIMIT 10", (name,)
    ).fetchall()
    # the hello-driven join finds the candidate flows through flows_conn; the FLOW_NAME test keeps one
    # name per flow, the same one top_upload and categories use, so `tvgw host` and the brief agree
    conns, up, down = conn.execute(
        f"""SELECT COUNT(*), COALESCE(SUM(bytes_up),0), COALESCE(SUM(bytes_down),0) FROM flows f
            WHERE f.id IN (SELECT f2.id FROM tls x JOIN flows f2 ON f2.dst=x.dst AND f2.sport=x.sport
                           AND f2.dport=x.dport AND x.t BETWEEN f2.t_start-{FLOW_SLACK} AND f2.t_end
                           WHERE x.sni=?)
              AND {FLOW_NAME} = ?""",
        (name, name),
    ).fetchone()
    return {
        "name": name,
        "category": category,
        "first_seen": first_seen,
        "last_seen": last_seen,
        "dns_n": dns_n,
        "tls_n": tls_n,
        "http_n": http_n,
        "last_blocked": last_blocked,
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
        key = (status, gfts.biz_code(uri or "") or "(other)")
        a = agg.setdefault(key, [0, 0])
        a[0] += 1
        a[1] += nbytes or 0
    return sorted(((k[0], k[1], v[0], v[1]) for k, v in agg.items()), key=lambda r: (r[0], -r[2]))


def tvstate(conn: sqlite3.Connection, since: float, until: float | None = None) -> list[tuple]:
    return conn.execute(
        "SELECT t, power, COALESCE(app,'') FROM tvstate WHERE t >= ? AND t < ? ORDER BY t",
        (since, _until(until)),
    ).fetchall()


def settings_changes(conn: sqlite3.Connection, since: float, until: float | None = None) -> list[tuple]:
    """(t, key, value) of TV settings first read or changed in the window (ingest stores a value only
    when it differs from the last one)."""
    return conn.execute(
        "SELECT t, key, value FROM tvsettings WHERE t >= ? AND t < ? ORDER BY t, key", (since, _until(until))
    ).fetchall()


def rules_history(conn: sqlite3.Connection) -> list[tuple]:
    return conn.execute(
        "SELECT kind, text, first_seen, removed_at FROM rules ORDER BY first_seen, kind, text"
    ).fetchall()


def oddports(conn: sqlite3.Connection, since: float, until: float | None = None) -> list[tuple]:
    return conn.execute(
        "SELECT proto, dst, dport, COUNT(*) FROM oddport WHERE t >= ? AND t < ? GROUP BY 1,2,3 "
        "ORDER BY 4 DESC, 1, 2, 3",
        (since, _until(until)),
    ).fetchall()


def lan_probes(conn: sqlite3.Connection, since: float, until: float | None = None) -> list[tuple]:
    """(dst, proto, dport, n): connections the TV opened towards private or multicast addresses that
    are not the gateway. The firewall drops them; this is the evidence it had to."""
    return conn.execute(
        "SELECT dst, proto, dport, COUNT(*) FROM lanprobe WHERE t >= ? AND t < ? GROUP BY 1,2,3 "
        "ORDER BY 4 DESC, 1, 2, 3",
        (since, _until(until)),
    ).fetchall()


def _hex_id(label: str) -> bool:
    """An all-hex label with at least one digit: the commonest shape of a generated identifier, and one
    the entropy threshold misses for 16-character ids (no English word of 16 letters is all a-f)."""
    return set(label) <= set("0123456789abcdef") and any(c.isdigit() for c in label)


def dns_anomalies(
    conn: sqlite3.Connection, since: float, until: float | None, profile: Profile
) -> list[dict]:
    """Names outside the expected categories that look like data rather than names: very long,
    a long high-entropy or all-hex label, or one registrable domain fanning out into hundreds of names
    (FANOUT per day, so a week's report trips at the same rate as a day's)."""
    out: list[dict] = []
    fanout: dict[str, list] = {}  # domain -> [names, lookups]
    days = max(1.0, (until - since) / 86400) if until is not None else 1.0
    for qname, n, blocked in conn.execute(
        "SELECT qname, COUNT(*), MAX(blocked) FROM dns WHERE t >= ? AND t < ? GROUP BY qname",
        (since, _until(until)),
    ):
        if not is_public_name(qname) or profile.is_expected(qname):
            continue
        entry = fanout.setdefault(registrable_domain(qname), [set(), 0])
        entry[0].add(qname)
        entry[1] += n
        label = max(qname.split("."), key=len)
        if len(qname) > LONG_NAME:
            detail = f"{len(qname)} chars"
            kind = "long name"
        elif len(label) >= RANDOM_LABEL[0] and _hex_id(label):
            detail = f"all-hex {len(label)} chars"
            kind = "random label"
        elif len(label) >= RANDOM_LABEL[0] and shannon_entropy(label) >= RANDOM_LABEL[1]:
            detail = f"{shannon_entropy(label):.1f} bits/char over {len(label)} chars"
            kind = "random label"
        else:
            continue
        out.append({"kind": kind, "name": qname, "lookups": n, "blocked": blocked, "detail": detail})
    for domain, (names, lookups) in fanout.items():
        if len(names) > FANOUT * days:
            out.append(
                {
                    "kind": "fan-out",
                    "name": domain,
                    "lookups": lookups,
                    "blocked": None,
                    "detail": f"{len(names)} distinct names over {days:.3g} day(s)",
                }
            )
    return out


def _like(pattern: str) -> str:
    """fnmatch-style pattern -> SQL LIKE: `*` any run, `?` one character."""
    return pattern.lower().replace("%", "\\%").replace("_", "\\_").replace("*", "%").replace("?", "_")


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
        f"AND qname IN ({marks}) GROUP BY qname ORDER BY 2 DESC, qname",
        (since, _until(until), *names),
    ).fetchall()


def clock_sync(conn: sqlite3.Connection, since: float, until: float | None, profile: Profile) -> dict:
    """Lookups of the vendor's clock hosts: webOS takes its time from LG's SDP reply, so a day the TV
    was on with no such lookup, or any blocked one, means the clock is at risk."""
    if not profile.clock_hosts:
        return {"lookups": 0, "blocked": 0, "first": None, "hosts": []}
    where = " OR ".join("qname LIKE ? ESCAPE '\\'" for _ in profile.clock_hosts)
    n, blocked, first = conn.execute(
        f"SELECT COUNT(*), COALESCE(SUM(blocked),0), MIN(t) FROM dns WHERE t >= ? AND t < ? AND ({where})",
        (since, _until(until), *(_like(h) for h in profile.clock_hosts)),
    ).fetchone()
    return {"lookups": n, "blocked": blocked, "first": first, "hosts": list(profile.clock_hosts)}


def fw_activity(conn: sqlite3.Connection, since: float, until: float | None = None) -> list[tuple]:
    """(rule comment, packets) stopped or counted by each firewall rule in the window: the sum of
    positive steps between consecutive counter snapshots. A re-apply sets every counter back to zero;
    `verify --record` stores tvgw-apply's listings either side of the reload as snapshots of their
    own, so the reset costs nothing unless a second apply follows within the same interval (the first
    one's pair is overwritten) or the store was not reached. A comment is one series (rules sharing it are
    summed per snapshot), and snapshots are compared in the order they were taken, so a clock stepped
    back by fake-hwclock after a power loss cannot turn a snapshot into a reset. A re-apply whose new
    count already exceeds the old one reads as growth and undercounts by the old count; that is not
    knowable without an epoch marker."""
    # the latest snapshot before the window: every rule of one snapshot shares one t, so this is two
    # index seeks rather than a lookup per rule
    prev = dict(
        conn.execute(
            "SELECT rule, SUM(packets) FROM fw_counters"
            " WHERE t = (SELECT MAX(t) FROM fw_counters WHERE t < ?) GROUP BY rule",
            (since,),
        )
    )
    acc: dict[str, int] = {}
    # GROUP BY (rule, t) folds the duplicate rows the live store holds for the two DNS redirects;
    # rowid order is the order the snapshots were taken, whatever the clock said
    for rule, packets, _first_row in conn.execute(
        "SELECT rule, SUM(packets), MIN(rowid) AS first_row FROM fw_counters"
        " WHERE t >= ? AND t < ? GROUP BY rule, t ORDER BY rule, first_row",
        (since, _until(until)),
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
    """(dst, dport, conns, bytes_up, bytes_down) for TCP destinations the TV reached with no TLS hello to
    that address ever and no A answer naming it in the window or the day before: hardcoded addresses,
    or a DNS bypass."""
    rows = conn.execute(
        """SELECT dst, dport, COUNT(*), SUM(bytes_up), SUM(bytes_down) FROM flows f
           WHERE proto='tcp' AND t_end >= ? AND t_end < ? AND dst != ?
             AND NOT EXISTS (SELECT 1 FROM tls x WHERE x.dst = f.dst)
           GROUP BY dst, dport ORDER BY 4 DESC""",
        (since, _until(until), gw_ip),
    ).fetchall()
    if not rows:
        return []
    # one pass over the window's answers; `dnsmsg.answers_text` fixes the `A:1.2.3.4,CNAME:x` grammar,
    # so membership is exact where a substring match was not (`A:203.0.113.45` hid 203.0.113.4)
    answered = {
        rec[2:]
        for (answers,) in conn.execute(
            "SELECT answers FROM dns WHERE t >= ? AND t < ? AND answers IS NOT NULL",
            (since - 86400, _until(until)),
        )
        for rec in answers.split(",")
        if rec.startswith("A:")
    }
    return [r for r in rows if is_public_address(r[0]) and r[0] not in answered][:limit]


def ptr_sweeps(conn: sqlite3.Connection, since: float, until: float | None = None) -> tuple[int, int]:
    """(lookups, distinct names) of reverse lookups for LAN addresses (the firewall's lan4 set): the TV
    taking inventory."""
    rows = conn.execute(
        "SELECT qname, COUNT(*) FROM dns WHERE t >= ? AND t < ? AND qtype='PTR' GROUP BY qname",
        (since, _until(until)),
    )
    lan = [n for qname, n in rows if (ip := reverse_ptr(qname)) and is_lan_address(ip)]
    return sum(lan), len(lan)


def firmware_changes(conn: sqlite3.Connection, since: float, until: float | None = None) -> list[dict]:
    """Firmware versions first seen in the window, each with the names that appeared from the hour
    before the reading to 72 h after it: updates are when new endpoints arrive, and the hourly reading
    at t sees an update that happened since the previous reading, so the first names the new firmware
    contacted fall in the hour before t."""
    out = []
    for t, value in conn.execute(
        "SELECT t, value FROM tvsettings WHERE key='firmware' AND t >= ? AND t < ? ORDER BY t",
        (since, _until(until)),
    ):
        names = [
            r[0]
            for r in conn.execute(
                "SELECT name FROM hosts WHERE first_seen >= ? AND first_seen < ? ORDER BY first_seen, name",
                (t - 3600, t + 72 * 3600),
            )
        ]
        out.append({"t": t, "firmware": value, "new_hosts": names})
    return out


def standby_activity(conn: sqlite3.Connection, since: float, until: float | None = None) -> dict:
    """Lookups made and connections opened during hours the TV reported itself off or asleep (anything
    but Active): with instant-on off this should be nothing at all. Readings are hourly, so an hour
    counts as off only when the TV said so at both ends of it and no reading was missed in between.
    A connection belongs to the hour it was opened in: `t_end` is conntrack's destroy time, the last
    packet plus the 2 h 04 min idle timeout, so attributing by it would credit standby with the
    evening's connections; a connection the TV opens while it says it is asleep is the evidence."""
    readings = conn.execute(
        "SELECT t, power FROM tvstate WHERE t >= ? AND t < ? ORDER BY t", (since, _until(until))
    ).fetchall()
    lookups = conns = up = off = 0
    for (t, power), (end, power_next) in itertools.pairwise(readings):
        if power == "Active" or power_next == "Active" or end - t > STANDBY_GAP:
            continue
        off += 1
        lookups += conn.execute("SELECT COUNT(*) FROM dns WHERE t >= ? AND t < ?", (t, end)).fetchone()[0]
        c, u = conn.execute(
            "SELECT COUNT(*), COALESCE(SUM(bytes_up),0) FROM flows WHERE t_start >= ? AND t_start < ?",
            (t, end),
        ).fetchone()
        conns, up = conns + c, up + u
    return {"off_hours": off, "lookups": lookups, "conns": conns, "bytes_up": up}


def coverage(conn: sqlite3.Connection, since: float, until: float, now: float | None = None) -> dict:
    """Did the pipeline actually look? The last ingest run, the warnings of the runs that fed the
    window, and per source: when it was last read and how many rows landed in the window. A source
    not read for `STALE` seconds before the end of the window (or before now, if the window is still
    open) is listed as not assessed. The firewall watchdog is a source too: its last run before the
    window closed is its last read, so a dead tvgw-verify.timer shows like a dead log."""
    now = now or time.time()
    last_run = conn.execute("SELECT value FROM meta WHERE key='last_run'").fetchone()
    read_raw = conn.execute("SELECT value FROM meta WHERE key='sources_read'").fetchone()
    try:
        read = json.loads(read_raw[0]) if read_raw else {}
    except ValueError:
        read = {}
    read["verify"] = conn.execute("SELECT MAX(t) FROM verify WHERE t < ?", (until,)).fetchone()[0]
    rows = {
        "flows": "SELECT COUNT(*) FROM flows WHERE t_end >= ? AND t_end < ?",
        "dns": "SELECT COUNT(*) FROM dns WHERE t >= ? AND t < ?",
        "pcaps": "SELECT COUNT(*) FROM pcaps_done WHERE error IS NULL AND done_at >= ? AND done_at < ?",
        "gfts": "SELECT COUNT(*) FROM http WHERE src='gfts' AND t >= ? AND t < ?",
        "tvstate": "SELECT COUNT(*) FROM tvstate WHERE t >= ? AND t < ?",
        "oddport": "SELECT COUNT(*) FROM oddport WHERE t >= ? AND t < ?",
        "gate": "SELECT COUNT(*) FROM gate WHERE t >= ? AND t < ?",
        "verify": "SELECT COUNT(*) FROM verify WHERE t >= ? AND t < ?",
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
    # the runs that fed a window are those inside it and the STALE seconds after it, the same lag
    # the settle margin allows; a warning that several of them repeated is listed once
    runs = conn.execute(
        "SELECT warnings FROM ingest_runs WHERE t >= ? AND t < ?", (since, min(until, now) + STALE)
    )
    warn_list = sorted({w for (raw,) in runs for w in _json_list(raw)})
    adguard = conn.execute("SELECT value FROM meta WHERE key='adguard_version'").fetchone()
    return {
        "last_run": float(last_run[0]) if last_run else None,
        "warnings": warn_list,
        "sources": sources,
        "not_assessed": [s for s, v in sources.items() if not v["assessed"]],
        "adguard_version": adguard[0] if adguard else None,  # recorded by `tvgw verify --record`
    }


GATE_RULE = "TV to an address DNS never returned"  # the gate's counter comment (its FW_LINES prefix)
# seconds: a gate sample this soon after an answer naming its address is the feeder arriving after the
# TV's connect (it adds an address once the answer has left the Pi), not a forgotten lookup or a bypass
FEEDER_LATE = 2.0


def gate_examples(
    conn: sqlite3.Connection, since: float, until: float | None = None, limit: int = 10
) -> list[dict]:
    """The sampled connections the DNS gate logged (at most six a minute), by address and port, with
    the TLS name a hello gave that address in the window. `late` counts the samples that came within
    FEEDER_LATE of an A answer naming the address: the TV connected before the feeder had added it.
    Otherwise a name means the address was known to the TV by a lookup the gate had forgotten (a day
    old, or before the Pi last booted); no name is a hardcoded server or a resolver bypass, which is
    what the gate is for."""
    out = [
        dict(zip(("dst", "dport", "n", "first", "last", "name"), r, strict=True))
        for r in conn.execute(
            """SELECT g.dst, g.dport, COUNT(*), MIN(g.t), MAX(g.t),
                      (SELECT x.sni FROM tls x WHERE x.dst = g.dst AND x.t >= ? AND x.t < ?
                       ORDER BY x.t DESC LIMIT 1)
               FROM gate g WHERE g.t >= ? AND g.t < ?
               GROUP BY g.dst, g.dport ORDER BY 3 DESC, g.dst LIMIT ?""",
            (since, _until(until), since, _until(until), limit),
        )
    ]
    for e in out:
        # the answers of the few seconds before each sample, matched exactly (`A:203.0.113.45` must
        # not excuse 203.0.113.4); CROSS JOIN keeps the samples outside, so dns is read by its time
        # index a few seconds at a time instead of scanned
        late = {
            sample
            for sample, answers in conn.execute(
                """SELECT g.id, d.answers FROM gate g CROSS JOIN dns d ON d.t >= g.t - ? AND d.t <= g.t
                   WHERE g.dst = ? AND g.dport = ? AND g.t >= ? AND g.t < ? AND d.answers IS NOT NULL""",
                (FEEDER_LATE, e["dst"], e["dport"], since, _until(until)),
            )
            if f"A:{e['dst']}" in answers.split(",")
        }
        e["late"] = len(late)
    return out


def ech_seen(conn: sqlite3.Connection, since: float, until: float | None = None) -> dict:
    """Handshakes carrying the encrypted_client_hello extension (0xfe0d): their outer name is all the
    capture can see, so the first one is the day the per-connection naming starts going dark."""
    n, first = conn.execute(
        "SELECT COUNT(*), MIN(t) FROM tls WHERE ech=1 AND t >= ? AND t < ?", (since, _until(until))
    ).fetchone()
    names = [
        r[0]
        for r in conn.execute(
            "SELECT sni FROM tls WHERE ech=1 AND t >= ? AND t < ?"
            " GROUP BY sni ORDER BY COUNT(*) DESC, sni LIMIT 5",
            (since, _until(until)),
        )
    ]
    return {"count": n, "first": first, "outer_names": names}


def _json_list(raw: str | None) -> list:
    try:
        v = json.loads(raw or "[]")
    except ValueError:
        return []
    return v if isinstance(v, list) else []


def window_report(
    conn: sqlite3.Connection,
    a: float,
    b: float,
    profile: Profile,
    now: float | None = None,
    gw_ip: str = "10.10.10.1",
    label: str = "",
) -> dict:
    """Everything worth a look for the window [a, b), as plain data. `brief`, `weekly` and `latest`
    are the three shapes of it the gateway writes."""
    now = now or time.time()
    o: dict = {"label": label or f"{_fmt(a)} .. {_fmt(b)}", "since": a, "until": b, "generated": now}
    o["coverage"] = coverage(conn, a, b, now)
    o["categories"] = categories(conn, a, b, profile, gw_ip)
    o["plain_http"] = [
        dict(zip(("host", "method", "path", "requests", "agents"), r, strict=True))
        for r in plain_http(conn, a, b, profile)
    ]
    o["dns_bypass"] = [
        dict(zip(("dst", "flows", "pkts"), r, strict=True)) for r in dns_bypass(conn, a, b, gw_ip)
    ]
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
    o["blocked_reached"] = [
        dict(zip(("name", "hellos", "blocked", "allowed"), r, strict=True))
        for r in blocked_reached(conn, a, b)
    ]
    o["allowed_unexpected"] = [
        {"name": r[0], "category": r[1], "lookups": r[2]} for r in allowed_unexpected(conn, a, b, profile, 25)
    ]
    o["top_upload"] = [
        dict(
            zip(("name", "dst", "ips", "dport", "conns", "bytes_up", "bytes_down", "pkts_up"), r, strict=True)
        )
        for r in top_upload(conn, a, b, 12, exclude_dst=gw_ip)
    ]
    o["beacons"] = beacons(conn, a, b)
    # the ACR client's cadence under a name that is not the TV doing its job: a red line
    o["acr_cadence"] = [
        x
        for x in o["beacons"]
        if x["acr_like"] and (x["category"] or "Other") not in profile.expected_categories
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
    # runs the 10-minute timer owed in the observed part of the window, counted from the first recorded
    # run: a store that never recorded is NOT ASSESSED, not alarmed
    first = conn.execute("SELECT MIN(t) FROM verify").fetchone()[0]
    observed = min(b, now) - max(a, first) if first is not None else 0
    o["firewall"]["expected"] = int(max(observed, 0) // 600)
    o["unresolved"] = [
        dict(zip(("dst", "dport", "conns", "bytes_up", "bytes_down"), r, strict=True))
        for r in unresolved_flows(conn, a, b, gw_ip)
    ]
    o["ptr"] = dict(zip(("lookups", "names"), ptr_sweeps(conn, a, b), strict=True))
    o["firmware_changes"] = firmware_changes(conn, a, b)
    o["standby"] = standby_activity(conn, a, b)
    clock = "%H:%M" if b - a <= 90000 else "%m-%d %H:%M"  # a 25-hour DST day is still one day
    o["tvstate"] = [
        {"time": datetime.fromtimestamp(t).strftime(clock), "power": p, "app": app}
        for t, p, app in tvstate(conn, a, b)
    ]
    o["settings_changes"] = [
        dict(zip(("t", "key", "value"), r, strict=True)) for r in settings_changes(conn, a, b)
    ]
    # the last known ACR state at the window's end, so a flip last week stays red every day until fixed
    row = conn.execute(
        "SELECT t, value FROM tvsettings WHERE key=? AND t < ? ORDER BY t DESC LIMIT 1", (ACR_KEY, b)
    ).fetchone()
    o["acr"] = {"key": ACR_KEY, "value": row[1], "t": row[0]} if row else None
    o["rule_changes"] = [
        dict(zip(("kind", "text", "added", "removed"), r, strict=True))
        for r in conn.execute(
            "SELECT kind, text, first_seen, removed_at FROM rules WHERE (first_seen>=? AND first_seen<?) OR "
            "(removed_at>=? AND removed_at<?) ORDER BY first_seen, kind, text",
            (a, b, a, b),
        )
    ]
    o["ech"] = ech_seen(conn, a, b)
    from tvgw import autoblock  # here, not at module level: autoblock imports this module

    o["autonomous"] = autoblock.summary(conn, a, b)
    # every logged sample was counted first (the counter precedes the log's limit), so the samples are
    # a floor under the counter's steps, which lose what a reset took before it was recorded
    samples = conn.execute("SELECT COUNT(*) FROM gate WHERE t >= ? AND t < ?", (a, b)).fetchone()[0]
    o["gate"] = {
        "new_connections": max(
            next((x["packets"] for x in o["firewall"]["activity"] if x["rule"].startswith(GATE_RULE)), 0),
            samples,
        ),
        "examples": gate_examples(conn, a, b),
    }
    o["red_lines"] = red_lines(o)
    return o


def _fmt(t: float) -> str:
    return datetime.fromtimestamp(t).strftime("%Y-%m-%d %H:%M")


def brief(
    conn: sqlite3.Connection, day: str, profile: Profile, now: float | None = None, gw_ip: str = "10.10.10.1"
) -> dict:
    """One calendar day."""
    a, b = day_bounds(day)
    return {"day": day, **window_report(conn, a, b, profile, now, gw_ip, label=day)}


def week_bounds(week: str) -> tuple[float, float]:
    """ISO week '2026-W44' -> Monday 00:00 local to the next Monday."""
    monday = datetime.strptime(week + "-1", "%G-W%V-%u")
    return monday.timestamp(), (monday + timedelta(days=7)).timestamp()


def weekly(
    conn: sqlite3.Connection, week: str, profile: Profile, now: float | None = None, gw_ip: str = "10.10.10.1"
) -> dict:
    """One ISO week (Monday to Sunday), with a per-day table."""
    a, b = week_bounds(week)
    o = window_report(
        conn, a, b, profile, now, gw_ip, label=f"week {week} ({_fmt(a)[:10]} .. {_fmt(b - 1)[:10]})"
    )
    o["week"] = week
    o["by_day"] = [
        dict(zip(("day", "lookups", "blocked", "conns", "bytes_up", "bytes_down"), r, strict=True))
        for r in by_day(conn, a, b)
    ]
    return o


def latest(
    conn: sqlite3.Connection,
    hours: float,
    profile: Profile,
    now: float | None = None,
    gw_ip: str = "10.10.10.1",
) -> dict:
    """The last `hours` hours up to now."""
    now = now or time.time()
    return window_report(
        conn, now - hours * 3600, now, profile, now, gw_ip, label=f"last {hours:g} h to {_fmt(now)}"
    )


def by_day(conn: sqlite3.Connection, since: float, until: float) -> list[tuple]:
    """(day, lookups, blocked, conns, bytes_up, bytes_down) per local calendar day in the window."""
    days: dict[str, list] = {}
    for day, n, blocked in conn.execute(
        "SELECT date(t,'unixepoch','localtime'), COUNT(*), COALESCE(SUM(blocked),0) FROM dns "
        "WHERE t >= ? AND t < ? GROUP BY 1",
        (since, until),
    ):
        days.setdefault(day, [0, 0, 0, 0, 0])[0:2] = [n, blocked]
    for day, conns, up, down in conn.execute(
        "SELECT date(t_end,'unixepoch','localtime'), COUNT(*), COALESCE(SUM(bytes_up),0), "
        "COALESCE(SUM(bytes_down),0) FROM flows WHERE t_end >= ? AND t_end < ? GROUP BY 1",
        (since, until),
    ):
        days.setdefault(day, [0, 0, 0, 0, 0])[2:5] = [conns, up, down]
    return [(day, *vals) for day, vals in sorted(days.items())]


UNRESOLVED = "Unresolved"
GATEWAY = "Gateway"


def categories(
    conn: sqlite3.Connection, since: float, until: float, profile: Profile, gw_ip: str = "10.10.10.1"
) -> list[dict]:
    """Per profile category: lookups, blocked, distinct names, connections and bytes (flows named by
    their TLS hello; unnamed ones are Unresolved, those to the gateway itself are Gateway)."""
    agg: dict[str, dict] = {}

    def row(cat: str) -> dict:
        return agg.setdefault(
            cat,
            {
                "category": cat,
                "lookups": 0,
                "blocked": 0,
                "names": 0,
                "conns": 0,
                "bytes_up": 0,
                "bytes_down": 0,
            },
        )

    for qname, n, blocked in conn.execute(
        "SELECT qname, COUNT(*), COALESCE(SUM(blocked),0) FROM dns WHERE t >= ? AND t < ? GROUP BY qname",
        (since, until),
    ):
        r = row(profile.categorize(qname))
        r["lookups"] += n
        r["blocked"] += blocked
        r["names"] += 1
    for name, dst, conns, up, down in conn.execute(
        f"""SELECT name, dst, COUNT(*), COALESCE(SUM(bytes_up),0), COALESCE(SUM(bytes_down),0) FROM
            (SELECT {FLOW_NAME} AS name, dst, bytes_up, bytes_down FROM flows f
             WHERE t_end >= ? AND t_end < ?)
            GROUP BY name, dst""",
        (since, until),
    ):
        cat = GATEWAY if dst == gw_ip else profile.categorize(name) if name else UNRESOLVED
        r = row(cat)
        r["conns"] += conns
        r["bytes_up"] += up
        r["bytes_down"] += down
    order = {c: i for i, c in enumerate([*profile.category_order, "Other", UNRESOLVED, GATEWAY])}
    return sorted(agg.values(), key=lambda r: order.get(r["category"], len(order)))


def plain_http(
    conn: sqlite3.Connection, since: float, until: float, profile: Profile, limit: int = 30
) -> list[tuple]:
    """(host, method, path, requests, user agents) for unencrypted requests the TV made, grouped by
    path without its query string; the vendor file service (URL filter) and LAN/multicast hosts excluded."""
    skip = set(profile.url_filter.hosts) if profile.url_filter else set()
    groups: dict[tuple, list] = {}
    for host, method, uri, ua in conn.execute(
        "SELECT host, method, uri, ua FROM http WHERE src='pcap' AND t >= ? AND t < ?", (since, until)
    ):
        h = (host or "").lower().rstrip(".")
        if h in skip or not is_public_name(h):
            continue
        path = (uri or "").split("?", 1)[0][:120]
        g = groups.setdefault((h, method or "", path), [0, set()])
        g[0] += 1
        if ua:
            g[1].add(ua[:60])
    rows = [(h, m, p, n, ", ".join(sorted(uas))) for (h, m, p), (n, uas) in groups.items()]
    return sorted(rows, key=lambda r: (-r[3], r[0], r[2]))[:limit]


def blocked_reached(conn: sqlite3.Connection, since: float, until: float, limit: int = 20) -> list[tuple]:
    """(name, hellos, blocked lookups, allowed lookups): names the TV reached over TLS in the window while
    a lookup of the same name was blocked in it: a cached or hardcoded answer, or a rule that changed
    mid-window; `allowed` says which. A tls_t range scan with two dns_q_t probes per name."""
    lookups = "(SELECT COUNT(*) FROM dns d WHERE d.qname=x.sni AND d.blocked=? AND d.t>=? AND d.t<?)"
    return conn.execute(
        f"""SELECT x.sni, COUNT(*) AS hellos, {lookups} AS blocked, {lookups} AS allowed
            FROM tls x WHERE x.t>=? AND x.t<? GROUP BY x.sni HAVING blocked > 0
            ORDER BY hellos DESC, x.sni LIMIT ?""",
        (1, since, until, 0, since, until, since, until, limit),
    ).fetchall()


def dns_bypass(conn: sqlite3.Connection, since: float, until: float, gw_ip: str) -> list[tuple]:
    """(resolver address, flows, packets) for DNS the TV sent anywhere but the gateway; the firewall
    redirects these to AdGuard, so they are attempts, not leaks."""
    return conn.execute(
        "SELECT dst, COUNT(*), COALESCE(SUM(pkts_up),0) FROM flows WHERE dport=53 AND dst != ? "
        "AND t_end >= ? AND t_end < ? GROUP BY dst ORDER BY 2 DESC, dst",
        (gw_ip, since, until),
    ).fetchall()


def red_lines(o: dict) -> list[str]:
    """The few things that must never be true, as sentences for the top of the brief, in the order to
    act on them: the TV's needs, then what the firewall and its watchdog say, then the pipeline."""
    out = []
    for m in o.get("must_allow_blocked", []):
        out.append(f"must-allow name blocked: {m['name']} x{m['lookups']} by {m['rule'] or 'a list'}")
    acr = o.get("acr")
    # lgwebos stores 'ERR <type> <msg>' for a failed read: unknown, not on
    if acr and acr["value"] != "off" and not acr["value"].startswith("ERR"):
        state = f"{acr['value']} on the TV (since {_fmt(acr['t'])})"
        out.append(f"Live Plus (ACR) is {state}: General > Additional Settings")
    clock = o.get("clock") or {}
    tv_on = any(s["power"] == "Active" for s in o.get("tvstate", []))
    whole_day = o.get("until", 0) - o.get("since", 0) >= 86400  # the clock rule is per day
    if clock.get("blocked"):
        out.append(f"clock host lookups blocked: {clock['blocked']} (the TV's clock comes from them)")
    elif clock.get("hosts") and tv_on and whole_day and not clock.get("lookups"):
        out.append("TV was on but never looked up its clock host (check the SDP hosts are reachable)")
    fw = o.get("firewall") or {}
    if fw.get("failed"):
        last = "; ".join(fw["last_failures"])
        out.append(f"firewall checks failed {fw['failed']} of {fw['runs']} times; last: {last}")
    runs, expected = fw.get("runs", 0), fw.get("expected", 0)
    if expected >= 6 and runs < expected / 2:
        out.append(f"firewall checks ran {runs} of ~{expected} times (is tvgw-verify.timer alive?)")
    for x in o.get("acr_cadence") or []:
        out.append(
            f"ACR-like cadence: {x['name']} every {x['period']:.0f} s, about {x['payload']:.0f} B"
            f" per connection, {x['conns']} times (Live Plus is off: what is this?)"
        )
    ech = o.get("ech") or {}
    if ech.get("count"):
        names = ", ".join(ech.get("outer_names") or []) or "no outer name"
        out.append(
            f"Encrypted ClientHello in {ech['count']} handshakes since {_fmt(ech['first'])}"
            f" (outer names: {names}): per-connection TLS naming is going dark; keep HTTPS records stripped"
        )
    cov = o.get("coverage") or {}
    # an hour of the TV on with nothing from a producer is the producer gone quiet, not a quiet TV
    observed = min(o["until"], o["generated"]) - o["since"] if "generated" in o else 0
    if tv_on and observed >= 3600:
        producers = (("dns", "lookups", "AdGuard query log"), ("flows", "connections", "flow log"))
        for src, what, producer in producers:
            if cov["sources"][src]["rows"] == 0:
                out.append(f"TV was on but no {what} were recorded (is the {producer} being read?)")
    if cov.get("warnings"):
        out.append(f"ingest warnings: {len(cov['warnings'])}")
    return out
