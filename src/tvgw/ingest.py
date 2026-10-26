"""Incremental ingest of every source into the store. Idempotent; takes a lock; run hourly.

Sources (see each function): conntrack flows, AdGuard's query log, finished pcaps (via tshark), the
nginx URL-filter log, the hourly TV-state readings, the kernel unexpected-port log and our own
policy files (recorded as rule history). Then the `hosts` dimension is refreshed and old rows
pruned. Everything that touches the outside world (files, tshark, journalctl) is a parameter so
the logic is testable without a gateway.
"""

from __future__ import annotations

import fcntl
import glob
import os
import re
import sqlite3
import subprocess
import time
from collections.abc import Callable, Iterable
from dataclasses import dataclass, field

from tvgw import adguard, conntrack, db, gfts, tshark
from tvgw.config import Settings
from tvgw.logtail import TailState, read_new_lines
from tvgw.profile import Profile


@dataclass
class Stats:
    flows: int = 0
    dns: int = 0
    pcaps: int = 0
    tls: int = 0
    http: int = 0
    gfts: int = 0
    tvstate: int = 0
    oddport: int = 0
    rules_added: int = 0
    rules_removed: int = 0
    hosts: int = 0
    pruned: int = 0
    seconds: float = 0.0
    warnings: list[str] = field(default_factory=list)

    def summary(self) -> str:
        return (
            f"+{self.flows} flows, +{self.dns} dns, +{self.pcaps} pcaps ({self.tls} tls, {self.http} http), "
            f"+{self.gfts} gfts, +{self.tvstate} tvstate, +{self.oddport} oddport, "
            f"rules +{self.rules_added}/-{self.rules_removed}, {self.hosts} hosts touched, "
            f"pruned {self.pruned}, {self.seconds:.1f}s"
        )


# ---- tail state persisted in the store ------------------------------------------------
def _state(conn: sqlite3.Connection, source: str) -> TailState:
    row = conn.execute("SELECT inode, offset FROM ingest_state WHERE source=?", (source,)).fetchone()
    return TailState(row[0], row[1]) if row else TailState()


def _save_state(conn: sqlite3.Connection, source: str, st: TailState, last_t: float | None = None) -> None:
    conn.execute(
        "INSERT OR REPLACE INTO ingest_state(source, inode, offset, last_t) VALUES (?,?,?,?)",
        (source, st.inode, st.offset, last_t if last_t is not None else time.time()),
    )


def _tail(conn: sqlite3.Connection, source: str, path: str) -> list[str]:
    lines, st = read_new_lines(path, _state(conn, source))
    if st.inode is not None:
        _save_state(conn, source, st)
    return lines


# ---- sources ----------------------------------------------------------------------------
def ingest_flows(conn: sqlite3.Connection, s: Settings) -> int:
    rows = []
    for line in _tail(conn, "flows", s.flows_log):
        f = conntrack.parse_flow(line)
        if f and f.src == s.tv_ip:
            rows.append(
                (
                    f.t_start,
                    f.t_end,
                    f.proto,
                    f.dst,
                    f.dport,
                    f.sport,
                    f.pkts_up,
                    f.bytes_up,
                    f.pkts_down,
                    f.bytes_down,
                    f.state,
                )
            )
    conn.executemany(
        "INSERT INTO flows(t_start,t_end,proto,dst,dport,sport,pkts_up,bytes_up,pkts_down,bytes_down,state)"
        " VALUES (?,?,?,?,?,?,?,?,?,?,?)",
        rows,
    )
    return len(rows)


def ingest_dns(conn: sqlite3.Connection, s: Settings) -> int:
    rows = []
    for line in _tail(conn, "adguard", s.adguard_querylog):
        r = adguard.parse_querylog_line(line, client=s.tv_ip)
        if r:
            rows.append(
                (
                    r.t,
                    r.qname,
                    r.qtype,
                    r.answers,
                    int(r.blocked),
                    r.reason,
                    r.rule,
                    r.filter_id,
                    r.upstream,
                    int(r.cached),
                    r.elapsed_ms,
                )
            )
    conn.executemany(
        "INSERT INTO dns(t,qname,qtype,answers,blocked,reason,rule,filter_id,upstream,cached,elapsed_ms)"
        " VALUES (?,?,?,?,?,?,?,?,?,?,?)",
        rows,
    )
    return len(rows)


def ingest_pcaps(
    conn: sqlite3.Connection,
    s: Settings,
    extract: Callable[[str], list] = tshark.extract,
    warn: Callable[[str], None] = print,
) -> tuple[int, int, int]:
    """Every finished pcap exactly once. The newest file is the one tcpdump is still writing."""
    pcaps = sorted(glob.glob(os.path.join(s.pcap_dir, "*.pcap")))
    done = {r[0] for r in conn.execute("SELECT name FROM pcaps_done")}
    n_files = n_tls = n_http = 0
    for p in pcaps[:-1]:
        name = os.path.basename(p)
        if name in done:
            continue
        try:
            rows = extract(p)
        except (RuntimeError, OSError, subprocess.TimeoutExpired) as e:
            warn(f"{name}: {e}; will retry next run")
            continue
        tls = [
            (r.t, r.dst, r.dport, r.sport, r.sni)
            for r in rows
            if isinstance(r, tshark.TlsHello) and r.src == s.tv_ip
        ]
        http = [
            (r.t, r.host, r.method, r.uri[:2000], r.user_agent[:300], None, None, "pcap")
            for r in rows
            if isinstance(r, tshark.HttpRequest) and r.src == s.tv_ip
        ]
        conn.executemany("INSERT INTO tls(t,dst,dport,sport,sni) VALUES (?,?,?,?,?)", tls)
        conn.executemany(
            "INSERT INTO http(t,host,method,uri,ua,status,bytes,src) VALUES (?,?,?,?,?,?,?,?)", http
        )
        conn.execute(
            "INSERT INTO pcaps_done(name,done_at,tls_rows,http_rows) VALUES (?,?,?,?)",
            (name, time.time(), len(tls), len(http)),
        )
        n_files, n_tls, n_http = n_files + 1, n_tls + len(tls), n_http + len(http)
    return n_files, n_tls, n_http


def ingest_gfts(conn: sqlite3.Connection, s: Settings) -> int:
    rows = []
    for line in _tail(conn, "gfts", s.gfts_log):
        r = gfts.parse_line(line)
        if r and r.client == s.tv_ip:
            rows.append((r.t, r.host, "GET", r.uri[:2000], r.user_agent[:300], r.status, r.bytes, "gfts"))
    conn.executemany("INSERT INTO http(t,host,method,uri,ua,status,bytes,src) VALUES (?,?,?,?,?,?,?,?)", rows)
    return len(rows)


def ingest_tvstate(conn: sqlite3.Connection, s: Settings) -> int:
    n = 0
    for line in _tail(conn, "tvstate", s.tvcheck_history):
        parts = line.split(" ", 3)
        if len(parts) < 3:
            continue
        t = adguard.parse_time(f"{parts[0]}T{parts[1]}:00")
        if t is None:
            continue
        conn.execute(
            "INSERT OR REPLACE INTO tvstate(t,power,app) VALUES (?,?,?)",
            (t, parts[2], parts[3] if len(parts) > 3 else None),
        )
        n += 1
    try:
        with open(s.tvcheck_txt) as fh:
            lines = fh.read().splitlines()
    except OSError:
        return n
    if not lines or not lines[0].startswith("read "):
        return n
    t = adguard.parse_time(lines[0][5:].replace(" ", "T", 1) + ":00")
    if t is None:
        return n
    for ln in lines[1:]:
        k, eq, v = ln.partition(" = ")
        if not eq or k in ("power", "app"):
            continue
        last = conn.execute(
            "SELECT value FROM tvsettings WHERE key=? ORDER BY t DESC LIMIT 1", (k,)
        ).fetchone()
        if not last or last[0] != v:
            conn.execute("INSERT OR IGNORE INTO tvsettings(t,key,value) VALUES (?,?,?)", (t, k, v))
    return n


_ODD_RE = re.compile(r"DST=([0-9.]+) .*PROTO=([A-Z]+) .*DPT=(\d+)")


def journal_oddport_lines(since: str) -> list[str]:
    out = subprocess.run(
        ["journalctl", "-k", "-q", "--no-pager", "-o", "short-unix", "-g", "tvgw-oddport", "--since", since],
        capture_output=True,
        text=True,
        timeout=60,
    )
    return out.stdout.splitlines()


def ingest_oddport(
    conn: sqlite3.Connection, lines_since: Callable[[str], Iterable[str]] = journal_oddport_lines
) -> int:
    row = conn.execute("SELECT last_t FROM ingest_state WHERE source='oddport'").fetchone()
    since = f"@{int(row[0]) + 1}" if row and row[0] else "-30d"
    try:
        lines = list(lines_since(since))
    except (OSError, subprocess.TimeoutExpired):
        return 0
    n, last = 0, None
    for line in lines:
        try:
            t = float(line.split(" ", 1)[0])
        except (ValueError, IndexError):
            continue
        m = _ODD_RE.search(line)
        conn.execute(
            "INSERT INTO oddport(t,proto,dst,dport,raw) VALUES (?,?,?,?,?)",
            (
                t,
                m.group(2) if m else None,
                m.group(1) if m else None,
                int(m.group(3)) if m else None,
                line[-400:],
            ),
        )
        n, last = n + 1, t
    if last is not None:
        _save_state(conn, "oddport", TailState(0, 0), last_t=last)
    return n


def current_rules(s: Settings) -> set[tuple[str, str]]:
    """Our policy as it stands: AdGuard user rules, the URL-filter regex, manual IP blocks."""
    out: set[tuple[str, str]] = set()
    for path, kind, pattern in (
        (s.nginx_conf, "gfts-block", re.compile(r'\$request_uri ~\* "([^"]+)"')),
        (s.block4, "block4", re.compile(r"^\s*([0-9.]+(?:/\d+)?)", re.MULTILINE)),
    ):
        try:
            with open(path) as fh:
                text = fh.read()
        except OSError:
            continue
        out.update((kind, m.group(1)) for m in pattern.finditer(text))
    try:
        with open(s.adguard_yaml) as fh:
            out.update(("adguard", r) for r in adguard.user_rules_from_yaml(fh.read()))
    except OSError:
        pass
    return out


def ingest_rules(
    conn: sqlite3.Connection, current: set[tuple[str, str]], now: float | None = None
) -> tuple[int, int]:
    now = now or time.time()
    active = {
        (r[0], r[1]): r[2] for r in conn.execute("SELECT kind, text, id FROM rules WHERE removed_at IS NULL")
    }
    added = removed = 0
    for key in current:
        if key in active:
            conn.execute("UPDATE rules SET last_seen=? WHERE id=?", (now, active[key]))
        else:
            conn.execute(
                "INSERT INTO rules(kind,text,first_seen,last_seen) VALUES (?,?,?,?)", (*key, now, now)
            )
            added += 1
    for key, rid in active.items():
        if key not in current:
            conn.execute("UPDATE rules SET removed_at=? WHERE id=?", (now, rid))
            removed += 1
    return added, removed


def refresh_hosts(conn: sqlite3.Connection, profile: Profile, since: float) -> int:
    """Upsert first/last seen, counters, category and latest blocked state for names seen since `since`."""
    seen: dict[str, dict] = {}
    for table, col in (("dns", "qname"), ("tls", "sni"), ("http", "host")):
        q = f"SELECT {col}, MIN(t), MAX(t), COUNT(*) FROM {table} WHERE t >= ? AND {col} != '' GROUP BY {col}"
        for name, first, last, n in conn.execute(q, (since,)):
            d = seen.setdefault(name, {"first": first, "last": last, "dns": 0, "tls": 0, "http": 0})
            d["first"], d["last"] = min(d["first"], first), max(d["last"], last)
            d[table] += n
    for name, d in seen.items():
        row = conn.execute(
            "SELECT blocked, rule FROM dns WHERE qname=? ORDER BY t DESC LIMIT 1", (name,)
        ).fetchone()
        conn.execute(
            """INSERT INTO hosts(name,first_seen,last_seen,category,dns_n,tls_n,http_n,last_blocked,last_rule)
               VALUES (?,?,?,?,?,?,?,?,?) ON CONFLICT(name) DO UPDATE SET
               first_seen=MIN(first_seen, excluded.first_seen), last_seen=MAX(last_seen, excluded.last_seen),
               category=excluded.category, dns_n=dns_n+excluded.dns_n, tls_n=tls_n+excluded.tls_n,
               http_n=http_n+excluded.http_n, last_blocked=COALESCE(excluded.last_blocked, last_blocked),
               last_rule=COALESCE(excluded.last_rule, last_rule)""",
            (
                name,
                d["first"],
                d["last"],
                profile.categorize(name),
                d["dns"],
                d["tls"],
                d["http"],
                row[0] if row else None,
                row[1] if row else None,
            ),
        )
    return len(seen)


def prune(conn: sqlite3.Connection, days: int, now: float | None = None) -> int:
    now = now or time.time()
    cutoff = now - days * 86400
    n = 0
    for table, col in (("flows", "t_end"), ("dns", "t"), ("tls", "t"), ("http", "t"), ("oddport", "t")):
        n += conn.execute(f"DELETE FROM {table} WHERE {col} < ?", (cutoff,)).rowcount
    conn.execute("DELETE FROM pcaps_done WHERE done_at < ?", (now - 30 * 86400,))
    last = db.get_meta(conn, "last_vacuum")
    if not last or float(last) < now - 30 * 86400:
        conn.commit()
        conn.execute("VACUUM")
        db.set_meta(conn, "last_vacuum", str(now))
    return n


# ---- the hourly run -------------------------------------------------------------------------
def run(
    s: Settings,
    profile: Profile,
    extract: Callable[[str], list] = tshark.extract,
    oddport_lines: Callable[[str], Iterable[str]] = journal_oddport_lines,
    lock: bool = True,
) -> Stats:
    os.makedirs(s.state_dir, exist_ok=True)
    lock_fh = None
    if lock:
        lock_fh = open(os.path.join(s.state_dir, ".ingest.lock"), "w")  # noqa: SIM115 - held until the end
        fcntl.flock(lock_fh, fcntl.LOCK_EX)
    stats = Stats()
    t0 = time.time()
    conn = db.connect(s.db_path)
    try:
        prev = db.get_meta(conn, "last_run")
        since = float(prev) - 3600 if prev else 0.0
        stats.flows = ingest_flows(conn, s)
        stats.dns = ingest_dns(conn, s)
        stats.pcaps, stats.tls, stats.http = ingest_pcaps(conn, s, extract, stats.warnings.append)
        stats.gfts = ingest_gfts(conn, s)
        stats.tvstate = ingest_tvstate(conn, s)
        stats.oddport = ingest_oddport(conn, oddport_lines)
        stats.rules_added, stats.rules_removed = ingest_rules(conn, current_rules(s))
        stats.hosts = refresh_hosts(conn, profile, since)
        stats.pruned = prune(conn, s.db_days)
        db.set_meta(conn, "last_run", str(t0))
        conn.commit()
    finally:
        conn.close()
        if lock_fh:
            lock_fh.close()
    stats.seconds = time.time() - t0
    return stats
