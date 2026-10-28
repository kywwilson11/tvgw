"""The store: one SQLite file, rollback journal (readers need no extra files), versioned schema.

DELETE journal mode rather than WAL on purpose: WAL needs the `-wal`/`-shm` side files to be
writable by every reader, and `tvgw brief` runs unprivileged. The schema is idempotent, so a
writer applies it on every open; the version in `meta` records what the last writer knew.
"""

from __future__ import annotations

import contextlib
import os
import sqlite3

# 2: dns(qname,t)/tls(dst,sport,t) indexes, lanprobe, verify, fw_counters, hosts watermarks
# 3: oddport(t), fw_counters(t), flows(t_start) and flows(dst, sport, t_end) indexes, ingest_runs;
#    tls_dst and flows_dst dropped
SCHEMA_VERSION = 4

SCHEMA = """
CREATE TABLE IF NOT EXISTS meta(key TEXT PRIMARY KEY, value TEXT);
CREATE TABLE IF NOT EXISTS ingest_state(source TEXT PRIMARY KEY, inode INTEGER, offset INTEGER,
  last_t REAL, head BLOB);
CREATE TABLE IF NOT EXISTS ingest_runs(t REAL PRIMARY KEY, seconds REAL, stats TEXT, warnings TEXT);
CREATE TABLE IF NOT EXISTS pcaps_done(name TEXT PRIMARY KEY, done_at REAL, tls_rows INTEGER,
  http_rows INTEGER, syn443_rows INTEGER, error TEXT, attempts INTEGER);
CREATE TABLE IF NOT EXISTS flows(id INTEGER PRIMARY KEY, t_start REAL, t_end REAL NOT NULL, proto TEXT,
  dst TEXT NOT NULL, dport INTEGER, sport INTEGER, pkts_up INTEGER, bytes_up INTEGER, pkts_down INTEGER,
  bytes_down INTEGER, state TEXT);
CREATE INDEX IF NOT EXISTS flows_t ON flows(t_end);
CREATE INDEX IF NOT EXISTS flows_start ON flows(t_start);
CREATE INDEX IF NOT EXISTS flows_conn ON flows(dst, sport, t_end);
CREATE TABLE IF NOT EXISTS dns(id INTEGER PRIMARY KEY, t REAL NOT NULL, qname TEXT NOT NULL, qtype TEXT,
  answers TEXT, blocked INTEGER NOT NULL, reason TEXT, rule TEXT, filter_id INTEGER, upstream TEXT,
  cached INTEGER, elapsed_ms REAL);
CREATE INDEX IF NOT EXISTS dns_t ON dns(t);
CREATE INDEX IF NOT EXISTS dns_q_t ON dns(qname, t);
CREATE TABLE IF NOT EXISTS tls(id INTEGER PRIMARY KEY, t REAL NOT NULL, dst TEXT, dport INTEGER,
  sport INTEGER, sni TEXT NOT NULL, ech INTEGER);
CREATE INDEX IF NOT EXISTS tls_t ON tls(t);
CREATE INDEX IF NOT EXISTS tls_sni ON tls(sni);
CREATE INDEX IF NOT EXISTS tls_conn ON tls(dst, sport, t);
CREATE TABLE IF NOT EXISTS http(id INTEGER PRIMARY KEY, t REAL NOT NULL, host TEXT, method TEXT, uri TEXT,
  ua TEXT, status INTEGER, bytes INTEGER, src TEXT NOT NULL);
CREATE INDEX IF NOT EXISTS http_t ON http(t);
CREATE INDEX IF NOT EXISTS http_host ON http(host);
CREATE TABLE IF NOT EXISTS lanprobe(id INTEGER PRIMARY KEY, t REAL NOT NULL, dst TEXT NOT NULL, proto TEXT,
  dport INTEGER);
CREATE INDEX IF NOT EXISTS lanprobe_t ON lanprobe(t);
CREATE TABLE IF NOT EXISTS tvstate(t REAL PRIMARY KEY, power TEXT, app TEXT);
CREATE TABLE IF NOT EXISTS tvsettings(t REAL NOT NULL, key TEXT NOT NULL, value TEXT, PRIMARY KEY(t, key));
CREATE TABLE IF NOT EXISTS oddport(id INTEGER PRIMARY KEY, t REAL NOT NULL, proto TEXT, dst TEXT,
  dport INTEGER, raw TEXT);
CREATE INDEX IF NOT EXISTS oddport_t ON oddport(t);
CREATE TABLE IF NOT EXISTS hosts(name TEXT PRIMARY KEY, first_seen REAL, last_seen REAL, category TEXT,
  dns_n INTEGER, tls_n INTEGER, http_n INTEGER, last_blocked INTEGER, last_rule TEXT, notes TEXT);
CREATE TABLE IF NOT EXISTS rules(id INTEGER PRIMARY KEY, kind TEXT NOT NULL, text TEXT NOT NULL,
  first_seen REAL NOT NULL, last_seen REAL NOT NULL, removed_at REAL);
CREATE TABLE IF NOT EXISTS verify(t REAL PRIMARY KEY, ok INTEGER NOT NULL, failures TEXT);
CREATE TABLE IF NOT EXISTS fw_counters(t REAL NOT NULL, rule TEXT NOT NULL, packets INTEGER, bytes INTEGER);
CREATE INDEX IF NOT EXISTS fw_counters_rule_t ON fw_counters(rule, t);
CREATE INDEX IF NOT EXISTS fw_counters_t ON fw_counters(t);
CREATE VIEW IF NOT EXISTS v_ip_names AS
  SELECT dst AS ip, sni AS name, COUNT(*) AS n, MAX(t) AS last_t FROM tls GROUP BY dst, sni;
"""

TABLES = (
    "flows",
    "dns",
    "tls",
    "http",
    "lanprobe",
    "tvstate",
    "tvsettings",
    "oddport",
    "hosts",
    "rules",
    "verify",
    "fw_counters",
    "pcaps_done",
    "ingest_runs",
)


def connect(path: str, readonly: bool = False, timeout: float = 60) -> sqlite3.Connection:
    """Open the store. Writers get the schema applied; readers open `mode=ro` and need only read access."""
    if readonly:
        return sqlite3.connect(f"file:{_uri_path(path)}?mode=ro", uri=True, timeout=timeout)
    new = not os.path.exists(path)
    conn = sqlite3.connect(path, timeout=timeout)
    conn.execute("PRAGMA journal_mode=DELETE")
    # NORMAL is corruption-safe only in WAL; with the rollback journal SQLite documents a non-zero
    # chance of corruption on power loss, and FULL costs one fsync per commit, a few dozen an hour
    conn.execute("PRAGMA synchronous=FULL")
    conn.executescript(SCHEMA)
    _migrate(conn)
    conn.execute("INSERT OR REPLACE INTO meta(key, value) VALUES ('schema', ?)", (str(SCHEMA_VERSION),))
    if new:
        with contextlib.suppress(OSError):  # the TV's whole DNS history: owner and admin group only
            os.chmod(path, 0o640)
    return conn


# columns added after a table first shipped: (table, column, type); applied when missing
ADDED_COLUMNS = (
    ("ingest_state", "head", "BLOB"),
    ("tls", "ech", "INTEGER"),  # schema 4: the ECH canary
    ("pcaps_done", "syn443_rows", "INTEGER"),
    ("pcaps_done", "error", "TEXT"),
    ("pcaps_done", "attempts", "INTEGER"),
)
# replaced by dns_q_t, tls_conn (dst, sport, t), of which tls_dst was a prefix, and flows_conn
# (dst, sport, t_end): no query leads with (dst, dport) any more
DROPPED_INDEXES = ("dns_q", "tls_dst", "flows_dst")


def _migrate(conn: sqlite3.Connection) -> None:
    for table, column, ctype in ADDED_COLUMNS:
        have = {r[1] for r in conn.execute(f"PRAGMA table_info({table})")}
        if column not in have:
            conn.execute(f"ALTER TABLE {table} ADD COLUMN {column} {ctype}")
    for index in DROPPED_INDEXES:
        conn.execute(f"DROP INDEX IF EXISTS {index}")


def _uri_path(path: str) -> str:
    """Percent-encode the characters that would be special in a `file:` URI."""
    return os.path.abspath(path).replace("%", "%25").replace("?", "%3f").replace("#", "%23")


def get_meta(conn: sqlite3.Connection, key: str) -> str | None:
    row = conn.execute("SELECT value FROM meta WHERE key=?", (key,)).fetchone()
    return row[0] if row else None


def set_meta(conn: sqlite3.Connection, key: str, value: str) -> None:
    conn.execute("INSERT OR REPLACE INTO meta(key, value) VALUES (?, ?)", (key, value))


def counts(conn: sqlite3.Connection) -> dict[str, int]:
    return {t: conn.execute(f"SELECT COUNT(*) FROM {t}").fetchone()[0] for t in TABLES}
