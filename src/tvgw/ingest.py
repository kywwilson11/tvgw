"""Incremental ingest of every source into the store. Idempotent; takes a lock; run hourly.

Sources (see each function): conntrack flows, AdGuard's query log, finished pcaps (via tshark), the
nginx URL-filter log, the hourly TV-state readings, the kernel unexpected-port log and our own
policy files (recorded as rule history). Then the `hosts` dimension is refreshed and old rows
pruned. Each source is its own transaction: one broken source neither stops the others nor rolls
them back, and the lock is never held for long. Everything that touches the outside world (files,
tshark, journalctl) is a parameter so the logic is testable without a gateway.
"""

from __future__ import annotations

import contextlib
import fcntl
import ipaddress
import json
import os
import re
import sqlite3
import subprocess
import time
from collections.abc import Callable, Iterable
from dataclasses import dataclass, field

from tvgw import adguard, conntrack, db, gfts, pcaps, tshark
from tvgw.config import Settings
from tvgw.logtail import TailState, read_new_lines
from tvgw.names import is_public_name, normalize
from tvgw.profile import Profile

SOURCES = ("flows", "dns", "pcaps", "gfts", "tvstate", "oddport", "rules")
BATCH = 10_000  # lines per transaction: bounds memory and the write lock however long the backlog
OPTIONAL_SOURCES = ("tvstate",)  # the LAN-API history exists only for profiles with a reader
PCAP_MAX_ATTEMPTS = 24  # hourly retries: a day to fix the cause before a pcap is recorded as unreadable
PCAP_HEADER = 24  # bytes of a pcap global header: a shorter file was never a capture
SYN_CHECK = 20  # connection attempts to :443 in one file that must have produced at least one hello


class SourceMissing(Exception):
    """A source's input (a log, the pcap directory) does not exist: not read, which is not empty."""


@dataclass
class Stats:
    flows: int = 0
    dns: int = 0
    pcaps: int = 0
    tls: int = 0
    http: int = 0
    lanprobe: int = 0
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
            f"+{self.flows} flows, +{self.dns} dns, +{self.pcaps} pcaps ({self.tls} tls, {self.http} http, "
            f"{self.lanprobe} lan probes), +{self.gfts} gfts, +{self.tvstate} tvstate, "
            f"+{self.oddport} oddport, "
            f"rules +{self.rules_added}/-{self.rules_removed}, {self.hosts} hosts touched, "
            f"pruned {self.pruned}, {self.seconds:.1f}s"
            + (f"; {len(self.warnings)} warning(s)" if self.warnings else "")
        )


# ---- tail state persisted in the store ------------------------------------------------
def _state(conn: sqlite3.Connection, source: str) -> TailState:
    row = conn.execute("SELECT inode, offset, head FROM ingest_state WHERE source=?", (source,)).fetchone()
    return TailState(row[0], row[1], bytes(row[2] or b"")) if row else TailState()


def _save_state(conn: sqlite3.Connection, source: str, st: TailState, last_t: float | None = None) -> None:
    conn.execute(
        "INSERT OR REPLACE INTO ingest_state(source, inode, offset, last_t, head) VALUES (?,?,?,?,?)",
        (source, st.inode, st.offset, last_t if last_t is not None else time.time(), st.head),
    )


def _tail(
    conn: sqlite3.Connection,
    source: str,
    path: str,
    insert: Callable[[list[str]], int],
    warn: Callable[[str], None],
) -> int:
    """Feed `insert` the new lines of `path`, BATCH at a time, each batch committed together with the
    cursor that covers it: rows and cursor land as one (exactly once), a run that dies loses only the
    batch in flight, and the lock is held per batch rather than per backlog. Returns the rows stored."""
    if not os.path.exists(path):
        raise SourceMissing(path)
    st = _state(conn, source)
    n = 0
    while True:
        lines, st = read_new_lines(path, st, BATCH)
        if st.gap:
            warn(
                f"{source}: log rotated or truncated since the last run"
                " and the lines written before it could not be recovered"
            )
        if st.inode is not None:
            _save_state(conn, source, st)
        n += insert(lines)
        conn.commit()
        if len(lines) < BATCH:
            return n


# ---- sources ----------------------------------------------------------------------------
def ingest_flows(conn: sqlite3.Connection, s: Settings, warn: Callable[[str], None] = print) -> int:
    bad = 0

    def insert(lines: list[str]) -> int:
        nonlocal bad
        rows = []
        for line in lines:
            try:
                f = conntrack.parse_flow(line)
            except ValueError:  # a counter SQLite cannot store
                f = None
            if f is None:  # every line of this log is machine-written in one format
                bad += 1
            elif f.src == s.tv_ip:
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
            "INSERT INTO flows(t_start,t_end,proto,dst,dport,sport,pkts_up,bytes_up,pkts_down,"
            "bytes_down,state) VALUES (?,?,?,?,?,?,?,?,?,?,?)",
            rows,
        )
        return len(rows)

    n = _tail(conn, "flows", s.flows_log, insert, warn)
    if bad:
        warn(f"flows: {bad} malformed line(s) skipped")
    return n


def ingest_dns(conn: sqlite3.Connection, s: Settings, warn: Callable[[str], None] = print) -> int:
    bad = 0

    def insert(lines: list[str]) -> int:
        nonlocal bad
        rows = []
        for line in lines:
            try:
                r = adguard.parse_querylog_line(line, client=s.tv_ip)
            except ValueError:  # not a record (a torn or NUL-filled line): counted, never fatal to the hour
                bad += 1
                continue
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

    # state key "adguard" predates this name: renaming it would re-read the whole query log
    n = _tail(conn, "adguard", s.adguard_querylog, insert, warn)
    if bad:
        warn(f"dns: {bad} malformed query-log record(s) skipped")
    return n


def _is_local(ip: str) -> bool:
    try:
        a = ipaddress.ip_address(ip)
    except ValueError:
        return False
    return (
        a.is_private
        or a.is_multicast
        or a.is_link_local
        or a.is_unspecified
        or a == ipaddress.ip_address("255.255.255.255")
    )


def _mark_pcap(
    conn: sqlite3.Connection,
    name: str,
    *,
    tls: int = 0,
    http: int = 0,
    syn443: int = 0,
    error: str | None = None,
    attempts: int = 0,
) -> None:
    """What the store knows about one pcap: read (error NULL), or failed this many times and why."""
    conn.execute(
        "INSERT INTO pcaps_done(name,done_at,tls_rows,http_rows,syn443_rows,error,attempts)"
        " VALUES (?,?,?,?,?,?,?) ON CONFLICT(name) DO UPDATE SET done_at=excluded.done_at,"
        " tls_rows=excluded.tls_rows, http_rows=excluded.http_rows, syn443_rows=excluded.syn443_rows,"
        " error=excluded.error, attempts=excluded.attempts",
        (name, time.time(), tls, http, syn443, error, attempts),
    )


def ingest_pcaps(
    conn: sqlite3.Connection,
    s: Settings,
    extract: Callable[[str], list] = tshark.extract,
    warn: Callable[[str], None] = print,
    live: Callable[[str], set[str] | None] | None = None,
) -> tuple[int, int, int, int]:
    """Every finished pcap exactly once: a file is finished when no tcpdump holds it open (`live`,
    `pcaps.live_files` by default), and when that cannot be told nothing is read. A file tshark
    cannot read is retried on each run up to PCAP_MAX_ATTEMPTS, then recorded as unreadable, so one
    bad file cannot hold the warning line for a week or hide the next fault behind it.
    Returns (files, tls rows, http rows, lan-probe rows)."""
    if not os.path.isdir(s.pcap_dir):
        raise SourceMissing(s.pcap_dir)
    held = (live or pcaps.live_files)(s.pcap_dir)
    if held is None:
        warn("pcaps: cannot tell which file tcpdump is writing (needs /proc and root); skipped this run")
        return 0, 0, 0, 0
    marks = {r[0]: (r[1], r[2] or 0) for r in conn.execute("SELECT name, error, attempts FROM pcaps_done")}
    n_files = n_tls = n_http = n_lan = 0
    failed: list[str] = []
    for path in pcaps.finished(s.pcap_dir, held):
        name = os.path.basename(path)
        mark = marks.get(name)
        if mark and (mark[0] is None or mark[1] >= PCAP_MAX_ATTEMPTS):
            continue  # read, or given up on
        attempts = mark[1] if mark else 0
        size = os.path.getsize(path)
        if size < PCAP_HEADER:
            _mark_pcap(conn, name, error=f"not a capture file ({size} bytes)", attempts=PCAP_MAX_ATTEMPTS)
            conn.commit()
            warn(f"{name}: not a capture file ({size} bytes)")
            continue
        try:
            rows = extract(path)
        except (RuntimeError, OSError, ValueError, subprocess.TimeoutExpired) as e:
            attempts += 1
            _mark_pcap(conn, name, error=str(e)[:200], attempts=attempts)
            conn.commit()
            if attempts >= PCAP_MAX_ATTEMPTS:
                warn(f"{name}: {e}; recorded as unreadable after {attempts} attempts")
            else:
                failed.append(f"{name}: {e}")
            continue
        # names and URIs are cut, never rejected: a crafted hello or header keeps its evidence
        # without growing a row without bound
        tls = [
            (r.t, r.dst, r.dport, r.sport, r.sni[:2000])
            for r in rows
            if isinstance(r, tshark.TlsHello) and r.src == s.tv_ip
        ]
        # requests to the gateway come from nginx's log, with status and bytes; the pcap copy would
        # count them twice, and the URL-filter hosts are exactly the ones that resolve to the gateway
        http = [
            (r.t, r.host[:2000], r.method, r.uri[:2000], r.user_agent[:300], None, None, "pcap")
            for r in rows
            if isinstance(r, tshark.HttpRequest) and r.src == s.tv_ip and r.dst != s.gw_ip
        ]
        syns: dict[tuple[int, str, int], tshark.Syn] = {}
        for r in rows:
            if isinstance(r, tshark.Syn) and r.src == s.tv_ip:
                syns.setdefault((r.sport, r.dst, r.dport), r)  # a retransmitted SYN repeats the key
        lan = [(r.t, r.dst, "tcp", r.dport) for r in syns.values() if r.dst != s.gw_ip and _is_local(r.dst)]
        syn443 = sum(1 for _, _, dport in syns if dport == 443)
        if syn443 >= SYN_CHECK and not tls:
            warn(
                f"{name}: {syn443} connection attempts to :443 but no TLS hello:"
                " check the capture filter and tshark"
            )
        conn.executemany("INSERT INTO tls(t,dst,dport,sport,sni) VALUES (?,?,?,?,?)", tls)
        conn.executemany(
            "INSERT INTO http(t,host,method,uri,ua,status,bytes,src) VALUES (?,?,?,?,?,?,?,?)", http
        )
        conn.executemany("INSERT INTO lanprobe(t,dst,proto,dport) VALUES (?,?,?,?)", lan)
        _mark_pcap(conn, name, tls=len(tls), http=len(http), syn443=syn443, attempts=attempts)
        conn.commit()  # a long backlog (Pi was off) must not hold the lock for the whole run
        n_files, n_tls, n_http, n_lan = n_files + 1, n_tls + len(tls), n_http + len(http), n_lan + len(lan)
    if failed:
        warn(f"{len(failed)} pcap(s) could not be read ({failed[0]}); will retry next run")
    return n_files, n_tls, n_http, n_lan


def deletable_pcaps(conn: sqlite3.Connection) -> set[str]:
    """Names of the pcaps the store has read, or given up on: the ones retention may delete."""
    q = "SELECT name FROM pcaps_done WHERE error IS NULL OR attempts >= ?"
    return {r[0] for r in conn.execute(q, (PCAP_MAX_ATTEMPTS,))}


def ingest_gfts(conn: sqlite3.Connection, s: Settings, warn: Callable[[str], None] = print) -> int:
    bad = 0

    def insert(lines: list[str]) -> int:
        nonlocal bad
        parsed = [gfts.parse_line(line) for line in lines]
        bad += parsed.count(None)  # every line of this log is machine-written in one format
        rows = [  # method NULL: the nginx log format has no $request_method
            (r.t, r.host, None, r.uri[:2000], r.user_agent[:300], r.status, r.bytes, "gfts")
            for r in parsed
            if r and r.client == s.tv_ip
        ]
        conn.executemany(
            "INSERT INTO http(t,host,method,uri,ua,status,bytes,src) VALUES (?,?,?,?,?,?,?,?)", rows
        )
        return len(rows)

    n = _tail(conn, "gfts", s.gfts_log, insert, warn)
    if bad:
        warn(f"gfts: {bad} malformed line(s) skipped")
    return n


def ingest_tvstate(conn: sqlite3.Connection, s: Settings, warn: Callable[[str], None] = print) -> int:
    def insert(lines: list[str]) -> int:
        rows = [(t, power, app) for t, power, app in map(_history_line, lines) if t is not None and power]
        conn.executemany("INSERT OR REPLACE INTO tvstate(t,power,app) VALUES (?,?,?)", rows)
        return len(rows)

    n = _tail(conn, "tvstate", s.tvcheck_history, insert, warn)
    try:
        with open(s.tvcheck_txt) as fh:
            lines = fh.read().splitlines()
    except OSError:
        return n
    if not lines or not lines[0].startswith("read "):
        return n
    t, _ = _stamped(lines[0][5:])
    if t is None:
        return n
    for ln in lines[1:]:
        k, eq, v = ln.partition(" = ")
        # lgwebos writes 'ERR <type> <msg>' for a key the TV stalled on and an 'info' pseudo-key for
        # the version/power/app reads: those are read errors, not settings
        if not eq or k in ("power", "app", "info") or v.startswith("ERR "):
            continue
        last = conn.execute(
            "SELECT value FROM tvsettings WHERE key=? ORDER BY t DESC LIMIT 1", (k,)
        ).fetchone()
        if not last or last[0] != v:
            conn.execute("INSERT OR IGNORE INTO tvsettings(t,key,value) VALUES (?,?,?)", (t, k, v))
    return n


def _stamped(line: str) -> tuple[float | None, str]:
    """A line starting with a timestamp: '2026-10-27T05:20:00-05:00 rest' (what tvgw-analyze writes now,
    unambiguous across a DST change) or the older naive '2026-10-27 05:20 rest'. -> (epoch, rest)."""
    first, _, rest = line.partition(" ")
    if "T" in first:
        return adguard.parse_time(first), rest
    hhmm, _, rest = rest.partition(" ")
    return adguard.parse_time(f"{first}T{hhmm}:00"), rest


def _history_line(line: str) -> tuple[float | None, str, str | None]:
    """A tvcheck-history line -> (epoch, power, app). tvgw-analyze writes tab-separated fields; the
    lines from before it did are space-separated, with the power state as the first word."""
    if "\t" in line:
        stamp, power, app = [*line.split("\t", 2), "", ""][:3]
        t = adguard.parse_time(stamp)
    else:
        t, rest = _stamped(line)
        power, _, app = rest.partition(" ")
    return t, power.strip(), app.strip() or None


_ODD_RE = re.compile(r"DST=([0-9a-fA-F.:]+) .*PROTO=([A-Z0-9]+) .*DPT=(\d+)")


def journal_oddport_lines(
    since: str, run: Callable[..., subprocess.CompletedProcess] = subprocess.run
) -> list[str]:
    """The kernel's unexpected-port log lines since `since` (a journalctl --since value). The explicit
    transport match stands in for -k, which implies -b and so hides every line between the last run
    and a reboot. A failure to read the journal raises: a silent [] would look like a quiet port log."""
    out = run(
        [
            *("journalctl", "-q", "--no-pager", "-o", "short-unix", "-g", "tvgw-oddport"),
            *("--since", since, "_TRANSPORT=kernel"),
        ],
        capture_output=True,
        text=True,
        errors="replace",
        timeout=60,
    )
    # a non-zero exit with nothing on stderr is a quiet journal: some versions exit 1 for no matches
    if out.returncode and out.stderr.strip():
        raise RuntimeError(f"journalctl rc={out.returncode}: {out.stderr.strip()[:200]}")
    return out.stdout.splitlines()


def ingest_oddport(
    conn: sqlite3.Connection, lines_since: Callable[[str], Iterable[str]] = journal_oddport_lines
) -> int:
    """Kernel log lines from the unexpected-port rule. journalctl's --since has one-second granularity,
    so ask from the second of the last event and skip what is already stored. For this source
    `ingest_state.last_t` is the newest event time; for the tail sources it is the time of the read.
    A reader that fails raises, and the run turns that into a warning and withholds the read stamp."""
    row = conn.execute("SELECT last_t FROM ingest_state WHERE source='oddport'").fetchone()
    last_t = row[0] if row and row[0] else None
    since = f"@{int(last_t)}" if last_t else "-30d"
    lines = list(lines_since(since))
    n, last = 0, last_t
    for line in lines:
        try:
            t = float(line.split(" ", 1)[0])
        except (ValueError, IndexError):
            continue
        if last_t is not None and t <= last_t:
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
        n, last = n + 1, max(last or 0, t)
    if n:
        _save_state(conn, "oddport", TailState(0, 0), last_t=last)
    return n


def current_rules(
    s: Settings, warn: Callable[[str], None] = lambda message: None
) -> tuple[set[tuple[str, str]], set[str]]:
    """Our policy as it stands, as (kind, text) pairs, plus the kinds whose source could be read.
    A kind that could not be read is unknown, not empty: callers must not retire its rules, and the
    brief hears why, or the history would quietly stop tracking that kind."""
    readers: tuple[tuple[str, str, Callable[[str], list[str] | None]], ...] = (
        ("gfts-block", s.nginx_conf, lambda text: re.findall(r'\$request_uri ~\* "([^"]+)"', text)),
        ("block4", s.block4, lambda text: re.findall(r"^\s*([0-9.]+(?:/\d+)?)", text, re.MULTILINE)),
        ("adguard", s.adguard_yaml, adguard.user_rules_from_yaml),
    )
    out: set[tuple[str, str]] = set()
    readable: set[str] = set()
    for kind, path, parse in readers:
        try:
            with open(path) as fh:
                rules = parse(fh.read())
        except OSError as e:
            warn(f"rules: {kind}: {e}")
            continue
        if rules is None:
            warn(f"rules: {kind}: not in a form we can read")
            continue
        readable.add(kind)
        out.update((kind, r) for r in rules)
    return out, readable


def ingest_rules(
    conn: sqlite3.Connection,
    current: set[tuple[str, str]],
    readable: set[str] | None = None,
    now: float | None = None,
) -> tuple[int, int]:
    now = now or time.time()
    readable = {k for k, _ in current} if readable is None else readable
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
        if key not in current and key[0] in readable:
            conn.execute("UPDATE rules SET removed_at=? WHERE id=?", (now, rid))
            removed += 1
    return added, removed


# ---- the hosts dimension ----------------------------------------------------------------
_HOST_SOURCES = (("dns", "qname"), ("tls", "sni"), ("http", "host"))


def refresh_hosts(conn: sqlite3.Connection, profile: Profile) -> int:
    """Upsert first/last seen, counters, category and latest DNS verdict for every public name.

    Counters advance by row id (a watermark per source table kept in `meta`), so a row is counted
    exactly once however late it arrives. Without a watermark (first run on this schema) the
    dimension is rebuilt from the base tables. Categories are recomputed for every name each run,
    so a profile change shows up without waiting for the name to be seen again."""
    raw = db.get_meta(conn, "hosts_wm")
    try:
        wm = json.loads(raw) if raw else None
    except ValueError:
        wm = None
    if not isinstance(wm, dict):
        wm = {t: 0 for t, _ in _HOST_SOURCES}
        conn.execute("DELETE FROM hosts WHERE notes IS NULL")
        conn.execute("UPDATE hosts SET dns_n=0, tls_n=0, http_n=0, first_seen=NULL, last_seen=NULL")
    seen: dict[str, dict] = {}
    new_wm = dict(wm)
    for table, col in _HOST_SOURCES:
        new_wm[table] = conn.execute(f"SELECT COALESCE(MAX(id),0) FROM {table}").fetchone()[0]
        q = (
            f"SELECT {col}, MIN(t), MAX(t), COUNT(*) FROM {table} "
            f"WHERE id > ? AND id <= ? AND {col} != '' GROUP BY {col}"
        )
        for raw_name, first, last, n in conn.execute(q, (int(wm.get(table, 0)), new_wm[table])):
            if not is_public_name(raw_name):
                continue
            name = normalize(raw_name)
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
               first_seen=MIN(COALESCE(first_seen, excluded.first_seen), excluded.first_seen),
               last_seen=MAX(COALESCE(last_seen, 0), excluded.last_seen),
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
    for name, cat in conn.execute("SELECT name, category FROM hosts").fetchall():
        c = profile.categorize(name)
        if c != cat:
            conn.execute("UPDATE hosts SET category=? WHERE name=?", (c, name))
    db.set_meta(conn, "hosts_wm", json.dumps(new_wm))
    return len(seen)


def prune(conn: sqlite3.Connection, days: int, now: float | None = None, pcap_dir: str | None = None) -> int:
    now = now or time.time()
    cutoff = now - days * 86400
    n = 0
    for table, col in (
        ("flows", "t_end"),
        ("dns", "t"),
        ("tls", "t"),
        ("http", "t"),
        ("lanprobe", "t"),
        ("oddport", "t"),
    ):
        n += conn.execute(f"DELETE FROM {table} WHERE {col} < ?", (cutoff,)).rowcount
    # a pcap's done-mark may only go once the file itself is gone, or it would be ingested twice
    for (name,) in conn.execute(
        "SELECT name FROM pcaps_done WHERE done_at < ?", (now - 7 * 86400,)
    ).fetchall():
        if pcap_dir is None or not os.path.exists(os.path.join(pcap_dir, name)):
            conn.execute("DELETE FROM pcaps_done WHERE name=?", (name,))
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
    live: Callable[[str], set[str] | None] | None = None,
) -> Stats:
    os.makedirs(s.state_dir, exist_ok=True)
    lock_fh = None
    if lock:
        lock_path = os.path.join(s.state_dir, ".ingest.lock")
        lock_fh = open(lock_path, "w")  # noqa: SIM115 - held until the end
        with contextlib.suppress(OSError):
            os.chmod(lock_path, 0o600)
        fcntl.flock(lock_fh, fcntl.LOCK_EX)
    stats = Stats()
    t0 = time.time()
    conn = db.connect(s.db_path)
    warn = stats.warnings.append

    def step(name: str, fn: Callable[[], None]) -> None:
        """One source, one transaction; a source that fails or has no input is not stamped as read,
        so coverage calls it not assessed rather than an empty hour (design decision 14)."""
        try:
            fn()
            conn.commit()
            read[name] = t0
        except SourceMissing as e:
            conn.rollback()
            if name not in OPTIONAL_SOURCES:
                warn(f"{name}: {e} is missing")
        except Exception as e:
            conn.rollback()
            warn(f"{name}: {type(e).__name__}: {str(e)[:200]}")

    def read_pcaps() -> None:
        stats.pcaps, stats.tls, stats.http, stats.lanprobe = ingest_pcaps(conn, s, extract, warn, live)

    def rules() -> None:
        current, readable = current_rules(s, warn)
        stats.rules_added, stats.rules_removed = ingest_rules(conn, current, readable)

    try:
        try:
            read = json.loads(db.get_meta(conn, "sources_read") or "{}")
        except ValueError:
            read = {}
        step("flows", lambda: setattr(stats, "flows", ingest_flows(conn, s, warn)))
        step("dns", lambda: setattr(stats, "dns", ingest_dns(conn, s, warn)))
        step("pcaps", read_pcaps)
        step("gfts", lambda: setattr(stats, "gfts", ingest_gfts(conn, s, warn)))
        step("tvstate", lambda: setattr(stats, "tvstate", ingest_tvstate(conn, s, warn)))
        step("oddport", lambda: setattr(stats, "oddport", ingest_oddport(conn, oddport_lines)))
        step("rules", rules)
        step("hosts", lambda: setattr(stats, "hosts", refresh_hosts(conn, profile)))
        step("prune", lambda: setattr(stats, "pruned", prune(conn, s.db_days, pcap_dir=s.pcap_dir)))
        db.set_meta(conn, "sources_read", json.dumps({k: read[k] for k in SOURCES if k in read}))
        db.set_meta(conn, "last_warnings", json.dumps(stats.warnings))
        db.set_meta(conn, "last_run", str(t0))
        conn.commit()
        conn.execute("PRAGMA optimize")
    finally:
        conn.close()
        if lock_fh:
            lock_fh.close()
    stats.seconds = time.time() - t0
    return stats
