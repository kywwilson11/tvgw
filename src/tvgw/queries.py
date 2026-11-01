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

from tvgw import flowlog, gfts
from tvgw.lgwebos import ACR_KEY, PATH_KEYS, SECOND_PATHS, is_second_path
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
# counted comment in tvgw-apply has a line here or is a listed accept, and every line matches a counted
# comment of tvgw-apply or the guard's template (tests/unit/test_fw_lines.py)
FW_LINES = (
    ("TV DNS aimed elsewhere", "DNS forced to AdGuard"),
    ("TV DNS to the gateway", "DNS to AdGuard"),
    ("DoT/DoQ", "DoT/DoQ"),
    ("QUIC", "QUIC"),
    ("DoH resolvers", "DoH"),
    ("TV may not reach the home LAN", "LAN"),
    ("manual IP blocks", "IP blocks"),
    ("LG adtech port", "adtech ports"),  # (acr) the port wall: its increase is the ACR red line's second form
    ("invalid", "invalid"),
    ("TV source outside its subnet", "foreign source"),  # (guard) the input chain's "(input)" too
    ("TV source is not the TV", "second TV address"),  # (guard) the pin, once TV_MAC is known
    ("TV subnet off the TV port", "off the TV port"),  # (packaging) TV_IF changed, tv-lan not moved
    ("no GRE/ESP/6in4", "tunnels"),
    ("no ICMP tunnels", "ICMP"),
    ("STRICT_PORTS", "odd ports"),
    ("LG firmware fallback path", "LG 8080 fallback"),  # accepted on purpose, counted and logged
    ("TV talks to the gateway address only", "to other Pi addresses"),
    ("TV may not reach other Pi services", "other Pi services"),
    # (fin-release) the guard's final input drop (guard.FINAL_DROP), stored by verify with inet tvgw's: it
    # stays still while inet tvgw is loaded, so a count here is what inet tvgw let through (guard_quiet)
    ("guard: TV may not reach other Pi services", "guard"),
    ("no NetBIOS/SSDP chatter", "Pi chatter"),
    ("nothing unsolicited from the VPN", "from VPN"),
    ("nothing else into or out of the TV subnet", "other forward drops"),
    ("only via the chosen uplink", "wrong uplink"),
    ("no IPv6 from the TV", "IPv6"),
    ("TV to an address DNS never returned", "to addresses DNS never gave"),
)

FW_BASELINE = 3600  # seconds: an older counter snapshot would credit a window with a stretch nobody recorded
FLOW_SLACK = 300  # seconds a hello may precede conntrack's (late) start time
# a continuation's hello can be as old as the connection it continues: when one name's flows are
# gathered through the hello join, candidates reach back this far and FLOW_NAME decides
CONT_LOOKBACK = 86400
# the TLS name of the connection a flow row describes (NULL: UDP, plain HTTP, or no hello captured).
# A flow with no hello of its own that starts within FLOW_SLACK of the end of an earlier flow on the
# same (dst, dport, sport) continues that connection (conntrack lost the entry mid-stream and opened a
# new one), so the hello is looked for from that earlier flow's start: one hop, the case seen. The
# latest hello before the flow's end wins, so a connection's own hello always beats an inherited one.
FLOW_NAME = (
    "(SELECT x.sni FROM tls x WHERE x.dst=f.dst AND x.sport=f.sport AND x.dport=f.dport"
    " AND x.t <= f.t_end AND x.t >= COALESCE((SELECT p.t_start FROM flows p WHERE p.dst=f.dst"
    " AND p.sport=f.sport AND p.dport=f.dport AND p.t_end < f.t_end AND p.t_start < f.t_start"
    f" AND p.t_end >= f.t_start-{FLOW_SLACK} ORDER BY p.t_end DESC LIMIT 1), f.t_start)-{FLOW_SLACK}"
    " ORDER BY x.t DESC LIMIT 1)"
)
LONG_NAME = 100  # a DNS name longer than this carries data (tunnelling, tracking ids)
RANDOM_LABEL = (16, 3.6)  # a label at least this long with this many bits/char looks generated
FANOUT = 200  # distinct names under one registrable domain per day; scaled by the window length
STALE = 7200  # a source not read for this long is "not assessed", not "quiet"
STANDBY_GAP = 5400  # readings are hourly; two readings further apart hide a missed reading, not an off hour
# power readings of a TV that is on: a screen saver is the TV idle with its app still in front (Peacock
# stayed behind one all night on the gateway), not asleep. (autonomy) Screen Off is the TV on with its
# panel dark, an app or its sound still running: the brief, the pack, the judge and the canary all read
# this one set, so a dark-panel evening is neither "talks while off" nor a TV hour that never happened
AWAKE = ("Active", "Screen Off", "Screen Saver")
HEADER_BYTES = 40  # IPv4 + TCP headers conntrack counts on every packet, payload or not
PERIODIC_JITTER = 0.15  # MAD/median of the intervals below this is a timer, not a person
PERIOD_RANGE = (10.0, 86400.0)  # seconds: faster is a stream's own pacing, slower is not a beacon in a day
BEACON_MIN = 12  # events before an interval statistic means anything
BURST_GAP = 5.0  # seconds: connections opened this close together are one event (a page, not a timer)
# (acr) LG's ACR client as conntrack sees it (docs/research/deep-dive-2026-11/13, sections 1.1 to 1.4): a
# fingerprint upload every 14-15 s inside connections of one to three minutes on TCP 4431, so the timer is
# invisible between connection starts, but a day carries 10-39 MB up at 7-17 times the bytes down. The
# test is that volume and ratio per cell: (registrable domain of the connection's TLS name, or the
# server's /24 when no hello named it; server port), the port because Alphonso's port-443 control plane
# would dilute the ratio of the domain as a whole. Thresholds: payload bytes up, up/down ratio, connections.
ACR_DAILY = (1_000_000, 4.0, 24)  # a local day: fired on 15 of 17 lab ACR days, 0 of 447 other cells
ACR_HOURLY = (500_000, 4.0, 5)  # a clock hour: catches a partial day (a 90-minute stub) the daily misses
ADTECH_RULE = "LG adtech port"  # tvgw-apply's port wall (ADTECH_PORT_WALL), its counter's comment
ADTECH_PORTS = (4001, 4431, 4445, 4447, 8180, 8883)  # the wall's ports, as tvgw-apply writes them


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
    The size half is the median bytes per connection and its payload bound. A Poisson stream has
    MAD/median near 0.5 and never passes; a 60 s timer with 5 % jitter does. O(n log n) per name.
    (acr) A timer is an attribute, never an alarm: captive-portal probes, a Hue bridge's polling and QoE
    heartbeats all keep one, so no row here raises a red line or buys the analyst a request. The
    `acr_like` mark is set by window_report when the row's name and port fall in an ACR-shaped upload
    cell (acr_uploader), not by the timer itself."""
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
                "dports": sorted({c[3] for c in conns if c[3] is not None}),  # ICMP has no port
                "first": events[0],
                "last": events[-1],
            }
        )
    out.sort(key=lambda r: (r["jitter"], -r["conns"], r["name"]))
    return out[:limit]


def acr_cell(name: str | None, dst: str) -> str:
    """(acr) The upload test's grouping key: the registrable domain of a connection's TLS name, or its
    server's /24 when no hello named it (`rtrim(dst,'0123456789') || '0/24'`), so LG's 41 rotating
    fingerprint names, or the addresses behind them, collapse into one row."""
    return registrable_domain(name) if name else dst.rstrip("0123456789") + "0/24"


def _passes(cell: dict, threshold: tuple[int, float, int]) -> bool:
    up, ratio, conns = threshold
    return (
        cell["payload_up"] >= up
        and cell["payload_up"] >= ratio * cell["payload_down"]
        and cell["conns"] >= conns
    )


def acr_uploader(conn: sqlite3.Connection, since: float, until: float | None, profile: Profile) -> list[dict]:
    """(acr) ACR-shaped uploads: cells (acr_cell, server port) whose payload up in a local day passes
    ACR_DAILY, or in a clock hour passes ACR_HOURLY (payload up at least that many bytes, at least that
    many times the payload down, over at least that many connections). Flows are bucketed by start, not
    end: an ACR connection lasts minutes, while `t_end` runs late by its idle timeout. Only flows to a
    public server count, and only those whose name is outside the profile's expected categories or that
    no hello named: a streaming app uploading as much is the TV doing its job.

    One finding per cell and day, the day's own cell when the daily test passes, else the hour that
    uploaded most; `hours` counts the hours of that day the hourly test passed, so a full ACR day reads as
    one line, not fifteen. Ordered by payload up. The answer drives the ACR red line's first form."""
    rows = conn.execute(
        f"""SELECT {FLOW_NAME}, f.dst, f.dport, f.t_start, f.bytes_up, f.pkts_up, f.bytes_down, f.pkts_down
            FROM flows f WHERE f.t_start >= ? AND f.t_start < ? AND f.dport IS NOT NULL""",
        (since, _until(until)),
    ).fetchall()
    cells: dict[tuple[str, float, str, int], dict] = {}
    for name, dst, dport, t, bu, pu, bd, pd in rows:
        if not is_public_address(dst) or (name and profile.is_expected(name)):
            continue
        local = datetime.fromtimestamp(t)
        day = datetime(local.year, local.month, local.day).timestamp()
        hour = local.replace(minute=0, second=0, microsecond=0).timestamp()
        key = acr_cell(name, dst)
        for bucket, start in (("day", day), ("hour", hour)):
            c = cells.setdefault(
                (bucket, start, key, dport),
                {"key": key, "named": False, "dport": dport, "bucket": bucket, "start": start, "day": day,
                 "conns": 0, "payload_up": 0, "payload_down": 0},
            )  # fmt: skip
            c["named"] = c["named"] or bool(name)
            c["conns"] += 1
            c["payload_up"] += max(0, (bu or 0) - HEADER_BYTES * (pu or 0))
            c["payload_down"] += max(0, (bd or 0) - HEADER_BYTES * (pd or 0))
    hits = [c for c in cells.values() if _passes(c, ACR_DAILY if c["bucket"] == "day" else ACR_HOURLY)]
    out: dict[tuple[str, int, float], dict] = {}
    for c in hits:
        k = (c["key"], c["dport"], c["day"])
        best = out.get(k)
        if (
            best is None
            or (c["bucket"] == "day") > (best["bucket"] == "day")
            or (c["bucket"] == best["bucket"] == "hour" and c["payload_up"] > best["payload_up"])
        ):
            out[k] = c
    for (key, dport, day), c in out.items():
        c["hours"] = sum(
            1 for h in hits if h["bucket"] == "hour" and (h["key"], h["dport"], h["day"]) == (key, dport, day)
        )
        c["ratio"] = round(c["payload_up"] / c["payload_down"], 1) if c["payload_down"] else None
    return sorted(out.values(), key=lambda c: (-c["payload_up"], c["key"], c["dport"], c["start"]))


def acr_port(
    conn: sqlite3.Connection, since: float, until: float | None, attempts: int, limit: int = 5
) -> dict:
    """(acr) What the adtech port wall stopped: `attempts` is its counter's increase in the window
    (fw_activity), floored at the samples it logged, since the wall counts every packet and logs at most
    six a minute. A rejected SYN never confirms its conntrack entry, so it leaves no flow row: the counter
    and the `tvgw-adport` samples are the only evidence. Each sampled address is named from the A answers
    the TV received in the KNOWN_DAYS before its first sample in the window (matched as a whole token,
    so `A:203.0.113.4` does not name 203.0.113.45); an address no answer named is a hardcoded server or
    a lookup the gateway never saw. Drives the ACR red line's second form."""
    until = _until(until)
    try:
        groups = conn.execute(
            """SELECT dst, dport, COUNT(*), MIN(t), MAX(t) FROM adport WHERE t >= ? AND t < ?
               GROUP BY dst, dport ORDER BY 3 DESC, dst, dport""",
            (since, until),
        ).fetchall()
    except sqlite3.OperationalError:  # a read-only reader of a store no writer has taken to schema 9 yet
        groups = []
    samples = sum(g[2] for g in groups)
    examples, names, unnamed = [], set(), 0
    for dst, dport, n, first, last in groups:
        found: set[str] = set()
        if dst:
            for qname, answers in conn.execute(
                "SELECT qname, answers FROM dns WHERE t >= ? AND t <= ?"
                " AND (answers LIKE ? OR answers LIKE ?)",
                (first - KNOWN_DAYS * 86400, last, f"%A:{dst},%", f"%A:{dst}"),
            ):
                if f"A:{dst}" in (answers or "").split(","):
                    found.add(qname)
        names |= found
        unnamed += not found
        if len(examples) < limit:
            examples.append(
                {"dst": dst, "dport": dport, "n": n, "first": first, "last": last, "names": sorted(found)[:5]}
            )
    return {
        "attempts": max(attempts, samples),
        "samples": samples,
        "ports": sorted({g[1] for g in groups if g[1] is not None}),
        "names": sorted(names)[:5],
        "unnamed": unnamed,
        "examples": examples,
    }


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
                           AND f2.dport=x.dport AND x.t BETWEEN f2.t_start-{CONT_LOOKBACK} AND f2.t_end
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


def tv_paths(conn: sqlite3.Connection, until: float) -> dict[str, dict]:
    """The last known state of each of the TV's network paths before `until`, as the hourly LAN-API
    reading stored them (`lgwebos.paths`): {key: {"value", "t"}}. A key never read is absent, so a TV
    whose firmware does not answer the question raises nothing."""
    out = {}
    for key in PATH_KEYS:
        row = conn.execute(
            "SELECT t, value FROM tvsettings WHERE key=? AND t < ? ORDER BY t DESC LIMIT 1", (key, until)
        ).fetchone()
        if row:
            out[key] = {"t": row[0], "value": row[1]}
    return out


def fw_activity(conn: sqlite3.Connection, since: float, until: float | None = None) -> list[tuple]:
    """(rule comment, packets) stopped or counted by each firewall rule in the window: the sum of positive
    steps between consecutive counter snapshots. A re-apply sets every counter back to zero; `verify
    --record` stores tvgw-apply's listings either side of the reload as snapshots of their own, so the
    reset costs nothing unless a second apply follows within the same interval (the first one's pair is
    overwritten) or the store was not reached. A comment is one series (rules sharing it are summed per
    snapshot), and snapshots are compared in the order they were taken, so a clock stepped back by fake-
    hwclock after a power loss cannot turn a snapshot into a reset. A rule missing from the snapshot
    before is new since it (the apply that created it started it at zero), so its first count is all the
    window's; only a rule in the window's first snapshot with no snapshot before it is a baseline, having
    counted for an unknown time. The snapshot before is the last one in the FW_BASELINE seconds before the
    window: after days without a snapshot (a store that would not take the write, a stopped timer) the
    first one would carry the whole gap into this window, so the window's first snapshot is the baseline
    then. The undercount of a re-apply whose new count already exceeds the old one (growth that was a
    reset) is left only when the apply's own listings never reached the store: a second apply inside one
    verify interval, or a store that would not take the write.
    """
    # the latest snapshot in the hour before the window: every rule of one snapshot shares one t, so
    # this is two index seeks rather than a lookup per rule
    prev = dict(
        conn.execute(
            "SELECT rule, SUM(packets) FROM fw_counters"
            " WHERE t = (SELECT MAX(t) FROM fw_counters WHERE t >= ? AND t < ?) GROUP BY rule",
            (since - FW_BASELINE, since),
        )
    )
    known = bool(prev)  # a snapshot came before the window's first one
    first_t = None
    acc: dict[str, int] = {}
    # GROUP BY (rule, t) folds the duplicate rows the live store holds for the two DNS redirects;
    # rowid order is the order the snapshots were taken, whatever the clock said
    for rule, packets, t, _first_row in conn.execute(
        "SELECT rule, SUM(packets), t, MIN(rowid) AS first_row FROM fw_counters"
        " WHERE t >= ? AND t < ? GROUP BY rule, t ORDER BY first_row",
        (since, _until(until)),
    ):
        first_t = t if first_t is None else first_t
        if rule in prev:
            step = packets - prev[rule] if packets >= prev[rule] else packets
        else:
            step = packets if known or t != first_t else 0
        acc[rule] = acc.get(rule, 0) + step
        prev[rule] = packets
    return sorted(acc.items(), key=lambda kv: (-kv[1], kv[0]))


def flowlog_drops(conn: sqlite3.Connection, since: float, until: float | None = None) -> int:
    """(events) Events the flow logger's event socket dropped in the window, from its own series
    (`flowlog.DROPS_RULE`) only, read as ingest._event_drops reads it: the series' last snapshot in the
    FW_BASELINE seconds before the window is the baseline (without one, the window's first snapshot
    is), then each step in the order the snapshots were stored, a lower count being a new socket (the
    logger restarted) whose whole count is new. tvgw-apply's reload listings carry no such row, so
    unlike fw_activity's shared baseline they cannot make a snapshot's whole count look new."""
    row = conn.execute(
        "SELECT packets FROM fw_counters WHERE rule=? AND t >= ? AND t < ? ORDER BY t DESC, rowid DESC",
        (flowlog.DROPS_RULE, since - FW_BASELINE, since),
    ).fetchone()
    prev = row[0] if row else None
    lost = 0
    for (packets,) in conn.execute(
        "SELECT packets FROM fw_counters WHERE rule=? AND t >= ? AND t < ? ORDER BY rowid",
        (flowlog.DROPS_RULE, since, _until(until)),
    ):
        if prev is not None:
            lost += packets - prev if packets >= prev else packets
        prev = packets
    return lost


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
    contacted fall in the hour before t. The first firmware reading the store holds (a new store, a
    new TV, a reader added later) is no update: there is nothing for it to differ from, and the TV
    settings section lists it."""
    out = []
    for t, value in conn.execute(
        "SELECT t, value FROM tvsettings WHERE key='firmware' AND t >= ? AND t < ? ORDER BY t",
        (since, _until(until)),
    ):
        before = conn.execute(
            "SELECT value FROM tvsettings WHERE key='firmware' AND t < ? ORDER BY t DESC LIMIT 1", (t,)
        ).fetchone()
        if before is None or before[0] == value:
            continue
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
    but AWAKE): with instant-on off this should be nothing at all. Readings are hourly, so an hour
    counts as off only when the TV said so at both ends of it and no reading was missed in between.
    A deploy or a run by hand adds readings between the hourly ones, so `off_hours` is the time those
    intervals span, not how many there were.
    A connection belongs to the hour it was opened in: `t_end` is conntrack's destroy time, the last
    packet plus the 2 h 04 min idle timeout, so attributing by it would credit standby with the
    evening's connections; a connection the TV opens while it says it is asleep is the evidence."""
    readings = conn.execute(
        "SELECT t, power FROM tvstate WHERE t >= ? AND t < ? ORDER BY t", (since, _until(until))
    ).fetchall()
    lookups = conns = up = off = 0
    for (t, power), (end, power_next) in itertools.pairwise(readings):
        if power in AWAKE or power_next in AWAKE or end - t > STANDBY_GAP:
            continue
        off += end - t
        lookups += conn.execute("SELECT COUNT(*) FROM dns WHERE t >= ? AND t < ?", (t, end)).fetchone()[0]
        c, u = conn.execute(
            "SELECT COUNT(*), COALESCE(SUM(bytes_up),0) FROM flows WHERE t_start >= ? AND t_start < ?",
            (t, end),
        ).fetchone()
        conns, up = conns + c, up + u
    return {"off_hours": round(off / 3600, 1), "lookups": lookups, "conns": conns, "bytes_up": up}


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
        "vpn": vpn_boundary(conn),  # (events)
    }


# (events) seconds: a gateway whose recorded runs saw a tunnel or PIA's client this long before a
# window's end still has a VPN to leak from, whatever the last run saw (design decision 44)
VPN_SEEN = 30 * 86400


def vpn_boundary(conn: sqlite3.Connection) -> dict | None:
    """(events) The VPN boundary as the last `tvgw verify --record` saw it: VPN_IF, the tunnel it
    resolved to, PIA's own state (`piactl get connectionstate`; None without the tool) and when. None
    before any recorded run. A reading, like the AdGuard version: the state at the last run, not over
    the window. `seen_t` is the last run that saw a tunnel or PIA's state (meta `vpn_seen_t`): it
    outlives a last run made with the daemon down, the very time the Pi's lookups leak."""
    row = conn.execute("SELECT value FROM meta WHERE key='vpn_boundary'").fetchone()
    seen_row = conn.execute("SELECT value FROM meta WHERE key='vpn_seen_t'").fetchone()
    try:
        value = json.loads(row[0]) if row else None
    except ValueError:
        value = None
    try:
        seen = float(seen_row[0]) if seen_row else None
    except ValueError:
        seen = None
    if not isinstance(value, dict):
        return {"seen_t": seen} if seen is not None else None
    return {**value, "seen_t": seen}


GATE_RULE = "TV to an address DNS never returned"  # the gate's counter comment (its FW_LINES prefix)
# (capture) the headers capture's counters (tvgw-apply, CAPTURE_MODE=headers) count packets handed to
# NFLOG, a measure of the capture rather than of the filter: the brief keeps them out of the firewall's
# activity, and so out of the analyst's pack, under a key of their own
CAPTURE_RULE = "capture:"
# (events) the Pi's own lookups that left by the uplink, not the tunnel (tvgw-apply's post_leaks
# chain, design decision 44): about the Pi, not the TV, so they are kept out of the firewall's
# activity too. The flow logger's dropped events (flowlog.DROPS_RULE) are kept apart for the same reason
LEAK_RULE = "pi leak:"
# seconds: a gate sample this soon after an answer naming its address is the feeder arriving after the
# TV's connect (it adds an address once the answer has left the Pi), not a forgotten lookup or a bypass
FEEDER_LATE = 2.0
# days: an address no A answer named in this long before a gate sample was never handed to the TV by its
# resolver in any memory the store keeps, so the sample is the gate's finding and not its own forgetting
KNOWN_DAYS = 7


def _late_samples(conn: sqlite3.Connection, dst: str, dport: int, since: float, until: float) -> set[int]:
    """The ids of the gate samples for (dst, dport) in the window that came within FEEDER_LATE of an A
    answer naming the address exactly (`A:203.0.113.45` must not excuse 203.0.113.4). CROSS JOIN keeps
    the samples outside, so dns is read by its time index a few seconds at a time instead of scanned."""
    return {
        sample
        for sample, answers in conn.execute(
            """SELECT g.id, d.answers FROM gate g CROSS JOIN dns d ON d.t >= g.t - ? AND d.t <= g.t
               WHERE g.dst = ? AND g.dport = ? AND g.t >= ? AND g.t < ? AND d.answers IS NOT NULL""",
            (FEEDER_LATE, dst, dport, since, until),
        )
        if f"A:{dst}" in answers.split(",")
    }


def gate_unexplained(
    conn: sqlite3.Connection, since: float, until: float | None = None, limit: int = 10, groups: int = 40
) -> list[dict]:
    """The gate samples neither the feeder's lateness nor the store explains: not within FEEDER_LATE
    of an answer naming the address, and the address in no A answer of the KNOWN_DAYS before the first
    such sample. By address and port, most samples first, with the TLS name a hello gave the address in
    the window. These are the gate's finding (a hardcoded server, a resolver bypass); the rest is the
    feeder arriving late or the gate's day-long memory running out, which must not buy a request."""
    until = _until(until)
    out: list[dict] = []
    for dst, dport, _n in conn.execute(
        """SELECT dst, dport, COUNT(*) FROM gate WHERE t >= ? AND t < ?
           GROUP BY dst, dport ORDER BY 3 DESC, dst LIMIT ?""",
        (since, until, groups),
    ).fetchall():
        late = _late_samples(conn, dst, dport, since, until)
        times = [
            t
            for i, t in conn.execute(
                "SELECT id, t FROM gate WHERE dst = ? AND dport = ? AND t >= ? AND t < ? ORDER BY t",
                (dst, dport, since, until),
            )
            if i not in late
        ]
        if not times:
            continue
        # the week before the first unexplained sample, matched as a whole token: `%A:x,%` inside the
        # list, `%A:x` at its end; the time index keeps it to a range, never a pass over the table
        known = conn.execute(
            "SELECT 1 FROM dns WHERE t >= ? AND t < ? AND (answers LIKE ? OR answers LIKE ?) LIMIT 1",
            (times[0] - KNOWN_DAYS * 86400, times[0], f"%A:{dst},%", f"%A:{dst}"),
        ).fetchone()
        if known:
            continue
        name = conn.execute(
            "SELECT sni FROM tls WHERE dst = ? AND t >= ? AND t < ? ORDER BY t DESC LIMIT 1",
            (dst, since, until),
        ).fetchone()
        out.append(
            {
                "dst": dst,
                "dport": dport,
                "n": len(times),
                "first": times[0],
                "last": times[-1],
                "name": name[0] if name else None,
            }
        )
        if len(out) == limit:
            break
    return out


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
        e["late"] = len(_late_samples(conn, e["dst"], e["dport"], since, _until(until)))
    return out


# (extractor) the public names ECH providers put in the outer hello. A hello carrying the extension
# under one of these is real ECH whatever the TV looked up (it may well have looked the public name
# up); any other outer name falls back to the lookup test below. Cloudflare's is the one that counts
# in 2026 (99.99% of deployments, state-of-the-art-2026-10 section 1.1).
ECH_PUBLIC_NAMES = frozenset({"cloudflare-ech.com"})


def ech_seen(conn: sqlite3.Connection, since: float, until: float | None = None) -> dict:
    """Handshakes carrying the encrypted_client_hello extension (0xfe0d): their outer name is all the
    capture can see, so the first one is the day the per-connection naming starts going dark.
    Chromium 117 and later send the extension as GREASE (random bytes, the real name outside) in
    every hello that has no ECH config, and the gateway withholds the HTTPS records that carry one.
    The wire cannot tell the two apart; the name can. An outer name in ECH_PUBLIC_NAMES is real ECH.
    Otherwise a hello whose name the TV looked up, in the window or the day before, names its server
    and is counted apart (`grease`): real ECH's outer name is the provider's public name, which the
    TV has no reason to ask for."""
    rows = conn.execute(
        """SELECT x.sni, x.t, EXISTS (SELECT 1 FROM dns d WHERE d.qname = x.sni AND d.t >= ? AND d.t < ?)
           FROM tls x WHERE x.ech=1 AND x.t >= ? AND x.t < ?""",
        (since - 86400, _until(until), since, _until(until)),
    ).fetchall()
    real: dict[str, int] = {}
    first: float | None = None
    for sni, t, looked_up in rows:
        if sni in ECH_PUBLIC_NAMES or not looked_up:
            real[sni] = real.get(sni, 0) + 1
            first = t if first is None else min(first, t)
    return {
        "count": sum(real.values()),
        "first": first,
        "outer_names": sorted(real, key=lambda n: (-real[n], n))[:5],
        "grease": len(rows) - sum(real.values()),
    }


def tls_noname(
    conn: sqlite3.Connection, since: float, until: float | None = None, limit: int = 10
) -> list[dict]:
    """The TV's hellos without a server name, by address, port, transport and JA4. A hello without
    SNI is either a connection to an address typed in by the app (no lookup to name it) or a stack
    that leaves the extension out; both are worth a look. JA4 is what names them: a fingerprint is a
    TLS stack, so `stack_names` lists the names the same fingerprint carried in the window and the
    week before ("the stack that talks to these, talking to an address it never named"). `partial`
    counts the hellos whose name may exist but lay in a segment the capture did not keep."""
    a, b = since, _until(until)
    out = [
        dict(zip(("dst", "dport", "transport", "ja4", "n", "partial", "first", "last"), r, strict=True))
        for r in conn.execute(
            """SELECT dst, dport, COALESCE(transport, 'tcp'), COALESCE(ja4, ''), COUNT(*),
                      COALESCE(SUM(partial), 0), MIN(t), MAX(t)
               FROM tls_noname WHERE t >= ? AND t < ?
               GROUP BY 1, 2, 3, 4 ORDER BY 5 DESC, 1, 2, 4 LIMIT ?""",
            (a, b, limit),
        )
    ]
    for e in out:
        e["stack_names"] = (
            [
                r[0]
                for r in conn.execute(
                    """SELECT sni FROM tls WHERE ja4 = ? AND t >= ? AND t < ?
                       GROUP BY sni ORDER BY COUNT(*) DESC, sni LIMIT 3""",
                    (e["ja4"], a - 7 * 86400, b),
                )
            ]
            if e["ja4"]
            else []
        )
    return out


# ---- (lists) List changes: what the blocklists' own updates changed for the TV ----------------------
# AdGuard swaps in whatever a list's URL answers (docs/adguard.md#lists-change-on-their-own), and the
# store already says which list blocked each lookup: dns.filter_id is the list's id, 0 the custom
# rules (the profile and the machine's rules) and negative ids AdGuard's own services. A list's first
# block of a name the TV had been resolving is a change nobody reviewed.
LIST_USED_BEFORE = 30 * 86400  # answered lookups this long before the first list block: the TV used it
LIST_SHAPE_DAYS = 14  # the traffic shape a newly blocked name is judged on, before its first block
# a name that carried this much was content, not telemetry: decision 20's payload gate, read in reverse
# (autoblock.MAX_TOTAL_DOWN and MAX_MEDIAN_DOWN; tests/unit/test_list_changes.py keeps them equal)
LIST_CONTENT_TOTAL = 2 * 1024 * 1024
LIST_CONTENT_MEDIAN = 16 * 1024
# an answer that carried an address: AAAA lookups come back empty here (aaaa_disabled), and an empty
# answer is not the TV using a name
_HAS_A = "(',' || COALESCE({col}, '')) LIKE '%,A:%'"


def _name_shape(conn: sqlite3.Connection, name: str, since: float, until: float) -> dict:
    """Bytes down on the TV's connections named `name` (by their TLS hello, as FLOW_NAME names them)
    that ended in [since, until): the connections, the total and the median per connection. Only the
    flows to a (dst, dport) a hello for the name went to are named, so the costly FLOW_NAME runs on a
    handful of rows, not on two weeks of flows."""
    downs = [
        r[0]
        for r in conn.execute(
            f"""WITH c AS (SELECT DISTINCT dst, dport FROM tls WHERE sni = ? AND t >= ? AND t < ?),
                     f AS (SELECT fl.* FROM flows fl JOIN c ON fl.dst = c.dst AND fl.dport = c.dport
                           WHERE fl.t_end >= ? AND fl.t_end < ?)
                SELECT COALESCE(f.bytes_down, 0) FROM f WHERE {FLOW_NAME} = ?""",
            (name, since - CONT_LOOKBACK, until, since, until, name),
        )
    ]
    return {
        "conns": len(downs),
        "down": sum(downs),
        "median_down": int(statistics.median(downs)) if downs else 0,
    }


def list_newly_blocked(
    conn: sqlite3.Connection, since: float, until: float | None = None, limit: int = 30
) -> list[dict]:
    """Names a list blocked for the first time in [since, until) that the TV had resolved to an address
    in the LIST_USED_BEFORE before that block: the list that blocked it (filter_id) and its rule, when,
    how many answered lookups came before, the lookups the list blocked in the window, and the name's
    LIST_SHAPE_DAYS shape before the block, with `content` true when it carried content. Content first,
    then the most used."""
    until = _until(until)
    has_a = _HAS_A.format(col="d.answers")
    rows = conn.execute(
        f"""WITH w AS (SELECT qname, MIN(t) AS first_t, COUNT(*) AS n FROM dns
                       WHERE t >= ? AND t < ? AND blocked = 1 AND filter_id > 0 GROUP BY qname)
            SELECT w.qname, w.first_t, w.n,
                   (SELECT d.filter_id FROM dns d WHERE d.qname = w.qname AND d.t = w.first_t
                      AND d.blocked = 1 AND d.filter_id > 0 LIMIT 1),
                   (SELECT d.rule FROM dns d WHERE d.qname = w.qname AND d.t = w.first_t
                      AND d.blocked = 1 AND d.filter_id > 0 LIMIT 1),
                   (SELECT COUNT(*) FROM dns d WHERE d.qname = w.qname AND d.blocked = 0
                      AND d.t >= w.first_t - ? AND d.t < w.first_t AND {has_a}) AS answered
            FROM w
            WHERE NOT EXISTS (SELECT 1 FROM dns p WHERE p.qname = w.qname AND p.t < ?
                              AND p.blocked = 1 AND p.filter_id > 0)""",
        (since, until, LIST_USED_BEFORE, since),
    ).fetchall()
    out = []
    for name, first_t, n, filter_id, rule, answered in rows:
        if not answered:
            continue
        shape = _name_shape(conn, name, first_t - LIST_SHAPE_DAYS * 86400, first_t)
        content = shape["down"] > LIST_CONTENT_TOTAL or shape["median_down"] > LIST_CONTENT_MEDIAN
        out.append(
            {
                "name": name,
                "filter_id": filter_id,
                "rule": rule or "",
                "first_blocked": first_t,
                "answered_before": answered,
                "blocked_lookups": n,
                **shape,
                "content": content,
            }
        )
    out.sort(key=lambda x: (not x["content"], -x["answered_before"], x["name"]))
    return out[:limit]


def list_newly_allowed(
    conn: sqlite3.Connection, since: float, until: float | None = None, limit: int = 30
) -> list[dict]:
    """The mirror: names a list blocked in the LIST_USED_BEFORE before `since` that the window answered
    with an address and no rule at all (so neither the profile's exceptions nor the machine let them
    through: a list stopped covering them), with no list block in the window."""
    until = _until(until)
    has_a = _HAS_A.format(col="answers")
    rows = conn.execute(
        f"""WITH w AS (SELECT qname, MIN(t) AS first_t, COUNT(*) AS n FROM dns
                       WHERE t >= ? AND t < ? AND blocked = 0 AND rule IS NULL AND {has_a}
                       GROUP BY qname)
            SELECT w.qname, w.first_t, w.n,
                   (SELECT MAX(p.t) FROM dns p WHERE p.qname = w.qname AND p.t < ? AND p.t >= ?
                      AND p.blocked = 1 AND p.filter_id > 0) AS last_block
            FROM w
            WHERE last_block IS NOT NULL
              AND NOT EXISTS (SELECT 1 FROM dns q WHERE q.qname = w.qname AND q.t >= ? AND q.t < ?
                              AND q.blocked = 1 AND q.filter_id > 0)
            ORDER BY w.n DESC, w.qname LIMIT ?""",
        (since, until, since, since - LIST_USED_BEFORE, since, until, limit),
    ).fetchall()
    out = []
    for name, first_t, n, last_block in rows:
        filter_id = conn.execute(
            "SELECT filter_id FROM dns WHERE qname = ? AND t = ? AND blocked = 1 AND filter_id > 0 LIMIT 1",
            (name, last_block),
        ).fetchone()[0]
        out.append(
            {
                "name": name,
                "filter_id": filter_id,
                "last_blocked": last_block,
                "first_answered": first_t,
                "answered_lookups": n,
            }
        )
    return out


def list_changes(conn: sqlite3.Connection, since: float, until: float | None = None) -> dict:
    """The brief's "List changes": both directions, as plain data."""
    return {
        "newly_blocked": list_newly_blocked(conn, since, until),
        "newly_allowed": list_newly_allowed(conn, since, until),
    }


def _size(n: int) -> str:
    """Bytes for a red line, in the brief's units (powers of 1024, like cli.hb)."""
    for unit, scale in (("M", 1024**2), ("K", 1024)):
        if n >= scale:
            return f"{n / scale:.1f}{unit}"
    return f"{n}B"


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
    ledger_on: bool | None = None,
    clean_hours: int | None = None,
) -> dict:
    """Everything worth a look for the window [a, b), as plain data. `brief`, `weekly` and `latest`
    are the three shapes of it the gateway writes. `ledger_on` and `clean_hours` are LEDGER and
    JUDGE2_CLEAN_HOURS from the caller's Settings; None is the default (on, 6)."""
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
    # (acr) the ACR red line: ACR-shaped uploads; a timer only marks a periodic row whose name and port are
    # one of their cells, and never raises anything on its own
    o["acr_upload"] = acr_uploader(conn, a, b, profile)
    uploads = {(x["key"], x["dport"]) for x in o["acr_upload"]}
    for x in o["beacons"]:
        cell = acr_cell(x["name"] if x["named"] else None, x["name"])
        x["acr_like"] = any((cell, d) in uploads for d in x["dports"])
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
    activity = dict(fw_activity(conn, a, b))
    # the gate counts a connection before it samples it (`counter limit rate 6/minute log`), so its
    # count is never below the samples it logged, whatever the re-applies that zero its counter cost
    samples = o["coverage"]["sources"]["gate"]["rows"]
    gate_rule = next((r for r in activity if r.startswith(GATE_RULE)), GATE_RULE)
    if samples > activity.get(gate_rule, 0):
        activity[gate_rule] = samples
    # (events) the Pi's leaks and the flow logger's drops are not the TV's firewall evidence
    o["vpn_leaks"] = {r[len(LEAK_RULE) :].strip(): n for r, n in activity.items() if r.startswith(LEAK_RULE)}
    o["flowlog_drops"] = flowlog_drops(conn, a, b)
    activity = {r: n for r, n in activity.items() if not r.startswith(LEAK_RULE) and r != flowlog.DROPS_RULE}
    ranked = sorted(activity.items(), key=lambda kv: (-kv[1], kv[0]))
    rows = [({"rule": r, "packets": n}, r.startswith(CAPTURE_RULE)) for r, n in ranked]
    o["firewall"]["activity"] = [x for x, capture in rows if not capture]
    o["capture_counters"] = [x for x, capture in rows if capture]  # (capture)
    o["acr_port"] = acr_port(conn, a, b, activity.get(ADTECH_RULE, 0))  # (acr) the ACR red line's second form
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
    o["tv_paths"] = tv_paths(conn, b)
    o["rule_changes"] = [
        dict(zip(("kind", "text", "added", "removed"), r, strict=True))
        for r in conn.execute(
            "SELECT kind, text, first_seen, removed_at FROM rules WHERE (first_seen>=? AND first_seen<?) OR "
            "(removed_at>=? AND removed_at<?) ORDER BY first_seen, kind, text",
            (a, b, a, b),
        )
    ]
    o["list_changes"] = list_changes(conn, a, b)  # (lists)
    o["ech"] = ech_seen(conn, a, b)
    o["tls_noname"] = tls_noname(conn, a, b)  # (extractor) schema 8
    from tvgw import autoblock  # here, not at module level: autoblock imports this module

    o["autonomous"] = autoblock.summary(conn, a, b)
    o["gate"] = {
        "new_connections": next(
            (x["packets"] for x in o["firewall"]["activity"] if x["rule"].startswith(GATE_RULE)), 0
        ),
        "examples": gate_examples(conn, a, b),
        "unexplained": gate_unexplained(conn, a, b),
    }
    _ledger_keys(o, conn, a, b, profile, now, ledger_on, clean_hours)  # (ledger)
    o["red_lines"] = red_lines(o)
    return o


def _ledger_conf(ledger_on: bool | None, clean_hours: int | None) -> tuple[bool, int]:
    """(ledger) LEDGER and JUDGE2_CLEAN_HOURS as the caller passed them, else their defaults: like every
    setting, they come from the caller's Settings and never from a file read here."""
    from tvgw import config

    d = config.Settings()
    return (
        d.ledger == "on" if ledger_on is None else ledger_on,
        d.judge2_clean_hours if clean_hours is None else clean_hours,
    )


def _ledger_keys(
    o: dict,
    conn: sqlite3.Connection,
    a: float,
    b: float,
    profile: Profile,
    now: float,
    ledger_on: bool | None,
    clean_hours: int | None,
) -> None:
    """(ledger) The brief's "Changes in effect" and the consent flips. Neither may stop the report: the
    shipped judge reads `must_allow_blocked` and `clock` from this same report, so a failure here
    becomes a warning in the report and the key is None (design decision 48)."""
    on, k = _ledger_conf(ledger_on, clean_hours)
    o["changes_in_effect"] = None
    if on:
        from tvgw import ledger  # here, not at module level: ledger imports this module

        try:
            o["changes_in_effect"] = ledger.section(conn, profile, a, b, now, k=k)  # None before the ledger
        except Exception as e:
            o.setdefault("warnings", []).append(f"changes in effect: {type(e).__name__}: {e}")
    try:
        o["consent_flips"] = consent_flips(conn, a, b)
    except Exception as e:
        o["consent_flips"] = None
        o.setdefault("warnings", []).append(f"consent flips: {type(e).__name__}: {e}")


def consent_flips(conn: sqlite3.Connection, since: float, until: float) -> list[dict]:
    """(ledger) Consent flags of the TV's `eulaStatus` record that went from false to true in the window:
    an agreement accepted on the TV. A `true` reading is compared with the flag's last definite reading
    before it (true or false), so an `unknown` in between (a partial answer, standby, a firmware
    update) neither hides a flip nor makes one. A flag first read as true, with no false before it, is
    not a flip: the owner may have accepted it on purpose before tvgw read it."""
    out = []
    rows = conn.execute(
        "SELECT t, key, value FROM tvsettings WHERE key LIKE 'eula.%' AND t >= ? AND t < ? ORDER BY t, key",
        (since, until),
    ).fetchall()
    for t, key, value in rows:
        if value != "true":
            continue
        prev = conn.execute(
            "SELECT value FROM tvsettings WHERE key = ? AND t < ? AND value IN ('true', 'false')"
            " ORDER BY t DESC LIMIT 1",
            (key, t),
        ).fetchone()
        if prev and prev[0] == "false":
            out.append({"t": t, "flag": key.removeprefix("eula.")})
    return out


def _fmt(t: float) -> str:
    return datetime.fromtimestamp(t).strftime("%Y-%m-%d %H:%M")


def brief(
    conn: sqlite3.Connection,
    day: str,
    profile: Profile,
    now: float | None = None,
    gw_ip: str = "10.10.10.1",
    **ledger_kw,
) -> dict:
    """One calendar day. `ledger_kw` is window_report's `ledger_on` and `clean_hours`."""
    a, b = day_bounds(day)
    return {"day": day, **window_report(conn, a, b, profile, now, gw_ip, label=day, **ledger_kw)}


def week_bounds(week: str) -> tuple[float, float]:
    """ISO week '2026-W44' -> Monday 00:00 local to the next Monday."""
    monday = datetime.strptime(week + "-1", "%G-W%V-%u")
    return monday.timestamp(), (monday + timedelta(days=7)).timestamp()


def weekly(
    conn: sqlite3.Connection,
    week: str,
    profile: Profile,
    now: float | None = None,
    gw_ip: str = "10.10.10.1",
    **ledger_kw,
) -> dict:
    """One ISO week (Monday to Sunday), with a per-day table."""
    a, b = week_bounds(week)
    label = f"week {week} ({_fmt(a)[:10]} .. {_fmt(b - 1)[:10]})"
    o = window_report(conn, a, b, profile, now, gw_ip, label=label, **ledger_kw)
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
    **ledger_kw,
) -> dict:
    """The last `hours` hours up to now."""
    now = now or time.time()
    label = f"last {hours:g} h to {_fmt(now)}"
    return window_report(conn, now - hours * 3600, now, profile, now, gw_ip, label=label, **ledger_kw)


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
    # (lists) a list's own update took away a name the TV pulled content from: the TV's needs come first
    for x in (o.get("list_changes") or {}).get("newly_blocked", []):
        if x["content"]:
            out.append(
                f"a list update newly blocks {x['name']}, which carried content (list {x['filter_id']},"
                f" {_size(x['down'])} down over {x['conns']} connections in the {LIST_SHAPE_DAYS} days"
                f" before, median {_size(x['median_down'])}): if the TV needs it, add it to must_allow"
            )
    acr = o.get("acr")
    # lgwebos stores 'ERR <type> <msg>' for a failed read: unknown, not on
    if acr and acr["value"] != "off" and not acr["value"].startswith("ERR"):
        state = f"{acr['value']} on the TV (since {_fmt(acr['t'])})"
        out.append(f"Live Plus (ACR) is {state}: General > Additional Settings")
    # a radio or a tethering switch the TV reports on is traffic that leaves around the gateway
    for key, label in SECOND_PATHS.items():
        p = (o.get("tv_paths") or {}).get(key)
        if p and is_second_path(key, p["value"]):
            out.append(
                f"TV has a second network path: {label} is {p['value']} (since {_fmt(p['t'])}):"
                " traffic can leave around the gateway; turn it off under Settings > Network"
            )
    clock = o.get("clock") or {}
    tv_on = any(s["power"] in AWAKE for s in o.get("tvstate", []))
    # the clock rule is per day, and the day the clocks go forward has 23 hours
    whole_day = o.get("until", 0) - o.get("since", 0) >= 82800
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
    # (acr) the ACR red line: an ACR-shaped upload, or the adtech port wall stopping something
    live_plus = (acr or {}).get("value") or "unknown (no reading)"
    if live_plus.startswith("ERR"):
        live_plus = "unknown (the last read failed)"
    for x in o.get("acr_upload") or []:
        day = datetime.fromtimestamp(x["start"]).strftime("%Y-%m-%d")
        when = (
            f"on {day}"
            if x["bucket"] == "day"
            else f"in hour {datetime.fromtimestamp(x['start']):%H} of {day}"
            + (f" (the busiest of {x['hours']})" if x.get("hours", 0) > 1 else "")
        )
        ratio = f"{x['ratio']:.1f}x down" if x.get("ratio") is not None else "nothing down"
        out.append(
            f"ACR-shaped upload: {x['key']}:{x['dport']} sent {x['payload_up'] / 1e6:.1f} MB up ({ratio})"
            f" in {x['conns']} connections {when}; Live Plus reads {live_plus}"
        )
    port = o.get("acr_port") or {}
    if port.get("attempts"):
        ports = ", ".join(map(str, port["ports"])) or "one of " + ", ".join(map(str, ADTECH_PORTS))
        names = ", ".join(port["names"]) if port.get("names") else "no lookup"
        if port.get("names") and port.get("unnamed"):
            names += f"; {port['unnamed']} address(es) no lookup named"
        out.append(f"ACR port attempts: {port['attempts']} connections to TCP {ports} rejected ({names})")
    ech = o.get("ech") or {}
    if ech.get("count"):
        names = ", ".join(ech.get("outer_names") or []) or "no outer name"
        out.append(
            f"Encrypted ClientHello in {ech['count']} handshakes since {_fmt(ech['first'])}"
            f" (outer names: {names}): per-connection TLS naming is going dark; keep HTTPS records stripped"
        )
    # (events) the Pi's own lookups left by the uplink instead of the tunnel: the DoH provider saw the
    # home address, and with port 53 the ISP's path saw the names (design decision 44). Only on a
    # gateway known to run a VPN (a tunnel, PIA's client or a VPN_IF named), so a site without one,
    # whose lookups always leave that way, is not told so every day. Known is sticky: a run in the
    # VPN_SEEN before the window's end that saw a tunnel or PIA's state counts, since the last run may
    # have been made with the daemon down (no tunnel, no answer from piactl), when the leaks happen
    leaks = {what: n for what, n in (o.get("vpn_leaks") or {}).items() if n}
    vpn = (o.get("coverage") or {}).get("vpn") or {}
    seen_t = vpn.get("seen_t")
    has_vpn = vpn.get("vpn_if") != "none" and bool(
        vpn.get("device")
        or vpn.get("pia")
        or vpn.get("vpn_if") not in (None, "auto")
        or (seen_t is not None and seen_t >= o.get("until", 0) - VPN_SEEN)
    )
    if leaks and has_vpn:
        # the VPN client's state stays on the Coverage line: red lines travel in the analyst's pack
        said = ", ".join(f"{what} {n} time(s)" for what, n in sorted(leaks.items()))
        out.append(f"the Pi's own lookups left outside the VPN: {said} (was the tunnel down? see Coverage)")
    for x in o.get("consent_flips") or []:  # (ledger) bleAdvertisingOnOff is never one: recorded only
        out.append(
            f"TV consent flag {x['flag']} turned on (at {_fmt(x['t'])}): an agreement was accepted on the TV"
        )
    for line in (o.get("changes_in_effect") or {}).get("red_lines", []):  # (ledger)
        out.append(line)
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
