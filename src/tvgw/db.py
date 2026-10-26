"""The store: one SQLite file, rollback journal (readers need no extra files), versioned schema."""

from __future__ import annotations

import sqlite3

SCHEMA_VERSION = 1

SCHEMA = """
CREATE TABLE IF NOT EXISTS meta(key TEXT PRIMARY KEY, value TEXT);
CREATE TABLE IF NOT EXISTS ingest_state(source TEXT PRIMARY KEY, inode INTEGER, offset INTEGER,
  last_t REAL);
CREATE TABLE IF NOT EXISTS pcaps_done(name TEXT PRIMARY KEY, done_at REAL, tls_rows INTEGER,
  http_rows INTEGER);
CREATE TABLE IF NOT EXISTS flows(id INTEGER PRIMARY KEY, t_start REAL, t_end REAL NOT NULL, proto TEXT,
  dst TEXT NOT NULL, dport INTEGER, sport INTEGER, pkts_up INTEGER, bytes_up INTEGER, pkts_down INTEGER,
  bytes_down INTEGER, state TEXT);
CREATE INDEX IF NOT EXISTS flows_t ON flows(t_end);
CREATE INDEX IF NOT EXISTS flows_dst ON flows(dst, dport);
CREATE TABLE IF NOT EXISTS dns(id INTEGER PRIMARY KEY, t REAL NOT NULL, qname TEXT NOT NULL, qtype TEXT,
  answers TEXT, blocked INTEGER NOT NULL, reason TEXT, rule TEXT, filter_id INTEGER, upstream TEXT,
  cached INTEGER, elapsed_ms REAL);
CREATE INDEX IF NOT EXISTS dns_t ON dns(t);
CREATE INDEX IF NOT EXISTS dns_q ON dns(qname);
CREATE TABLE IF NOT EXISTS tls(id INTEGER PRIMARY KEY, t REAL NOT NULL, dst TEXT, dport INTEGER,
  sport INTEGER, sni TEXT NOT NULL);
CREATE INDEX IF NOT EXISTS tls_t ON tls(t);
CREATE INDEX IF NOT EXISTS tls_sni ON tls(sni);
CREATE INDEX IF NOT EXISTS tls_dst ON tls(dst);
CREATE TABLE IF NOT EXISTS http(id INTEGER PRIMARY KEY, t REAL NOT NULL, host TEXT, method TEXT, uri TEXT,
  ua TEXT, status INTEGER, bytes INTEGER, src TEXT NOT NULL);
CREATE INDEX IF NOT EXISTS http_t ON http(t);
CREATE INDEX IF NOT EXISTS http_host ON http(host);
CREATE TABLE IF NOT EXISTS tvstate(t REAL PRIMARY KEY, power TEXT, app TEXT);
CREATE TABLE IF NOT EXISTS tvsettings(t REAL NOT NULL, key TEXT NOT NULL, value TEXT, PRIMARY KEY(t, key));
CREATE TABLE IF NOT EXISTS oddport(id INTEGER PRIMARY KEY, t REAL NOT NULL, proto TEXT, dst TEXT,
  dport INTEGER, raw TEXT);
CREATE TABLE IF NOT EXISTS hosts(name TEXT PRIMARY KEY, first_seen REAL, last_seen REAL, category TEXT,
  dns_n INTEGER, tls_n INTEGER, http_n INTEGER, last_blocked INTEGER, last_rule TEXT, notes TEXT);
CREATE TABLE IF NOT EXISTS rules(id INTEGER PRIMARY KEY, kind TEXT NOT NULL, text TEXT NOT NULL,
  first_seen REAL NOT NULL, last_seen REAL NOT NULL, removed_at REAL);
CREATE VIEW IF NOT EXISTS v_ip_names AS
  SELECT dst AS ip, sni AS name, COUNT(*) AS n, MAX(t) AS last_t FROM tls GROUP BY dst, sni;
"""


def connect(path: str, readonly: bool = False, timeout: float = 60) -> sqlite3.Connection:
    """Open the store. Writers get the schema applied; readers open `mode=ro` and need only read access."""
    if readonly:
        conn = sqlite3.connect(f"file:{path}?mode=ro", uri=True, timeout=timeout)
        return conn
    conn = sqlite3.connect(path, timeout=timeout)
    conn.execute("PRAGMA journal_mode=DELETE")
    conn.execute("PRAGMA synchronous=NORMAL")
    conn.executescript(SCHEMA)
    conn.execute("INSERT OR IGNORE INTO meta(key, value) VALUES ('schema', ?)", (str(SCHEMA_VERSION),))
    return conn


def get_meta(conn: sqlite3.Connection, key: str) -> str | None:
    row = conn.execute("SELECT value FROM meta WHERE key=?", (key,)).fetchone()
    return row[0] if row else None


def set_meta(conn: sqlite3.Connection, key: str, value: str) -> None:
    conn.execute("INSERT OR REPLACE INTO meta(key, value) VALUES (?, ?)", (key, value))


def counts(conn: sqlite3.Connection) -> dict[str, int]:
    tables = (
        "flows",
        "dns",
        "tls",
        "http",
        "tvstate",
        "tvsettings",
        "oddport",
        "hosts",
        "rules",
        "pcaps_done",
    )
    return {t: conn.execute(f"SELECT COUNT(*) FROM {t}").fetchone()[0] for t in tables}
