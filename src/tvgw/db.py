"""The store: one SQLite file, rollback journal (readers need no extra files), versioned schema.

DELETE journal mode rather than WAL on purpose: WAL needs the `-wal`/`-shm` side files to be
writable by every reader, and `tvgw brief` runs unprivileged. The schema is idempotent, so a
writer applies it on every open; the version in `meta` records what the last writer knew.

(reliability) A writer reads that version before it writes anything, and refuses a store a newer tvgw
wrote (`StoreTooNew`): an older tvgw that relabelled it with its own lower number left the newer tables
and rows behind with nobody responsible for them. The version is written only when it rises, so an
up-to-date store's open writes nothing at all (design decision 73).
"""

from __future__ import annotations

import contextlib
import os
import sqlite3

# 2: dns(qname,t)/tls(dst,sport,t) indexes, lanprobe, verify, fw_counters, hosts watermarks
# 3: oddport(t), fw_counters(t), flows(t_start) and flows(dst, sport, t_end) indexes, ingest_runs;
#    tls_dst and flows_dst dropped
# 4: tls.ech, the ECH canary
# 5: gate, the DNS gate's sampled connections
# 6: auto_rules and judgments, the record of the autonomous blocks (design decision 20)
# 7: flows.timeout_left (an entry the kernel destroyed before its timer ran out), ingest_state.rotated
# 8: tls.ja4, tls.transport, tls.partial; tls_noname, the hellos without a server name (extractor)
# 9: research pass 2 (2026-11-01), one bump for every workstream:
#    (acr) adport, the adtech port wall's sampled rejects (tvgw-adport);
#    (autonomy) decisions, the append-only record of every gate, verifier, canary and judge outcome;
#    auto_queue, the blocks waiting their turn; auto_rules.canary and auto_rules.trial_id;
#    (ledger) changes, gw_samples and judge_shadow: the change ledger, the gateway's own 10-minute
#    samples and judge v2's shadow verdicts (design decision 48);
#    new tables migrate by their CREATE ... IF NOT EXISTS, new columns by ADDED_COLUMNS, on any writer's open
# 10: the improvement pass of 2026-11-03, one bump for every workstream: (plain) gw_samples.wan_addr_tag,
#    the sampler's keyed tag of the uplink's address and router
# 11: (inpath) research pass 4: gate_inpath, the sampled connections to addresses the DNS gate's in-path
#    set did not hold (tvgw-inpath), beside gate's (design decision 64)
# 12: (app in front) research pass 4: tv_events, the live record of the TV's power state and the app in
#    front (design decision 67)
# 13: research pass 4 (2026-11-05), the probe from the TV's position (design decision 65):
#    gw_samples.tv_probe, its verdict beside the sample of the same run (after 11, the in-path gate's,
#    and 12, the app in front's)
# 14: (reliability) research pass 5 (design decision 73): the gateway's
#    own health in gw_samples: soc_temp, throttled, mem_avail_pct, mem_psi_some, disk_dev,
#    disk_sectors_written, io_errors, io_errors_store, usb_resets
# 15: (namebound) research pass 5: answer_ip, the addresses each answer the TV received named,
#    with the answer's lifetime, so a TLS name can be checked against the answers (design decision 70)
# 16: (threats) the competitive-gap pass (2026-11-08): threat_hits, the TV's names found on a threat or
#    newly-registered-domain list, one row per day, name and list (design decision 80)
# 17: (attention) research pass 5: attention, the attention count's samples, each a
#    connection the TV opened outside its essentials while its screen saver was on or an input was in front
#    (design decision 69); kept TV_EVENTS_DAYS, as tv_events is
# 18: (exposure) judge_shadow.kernel, the exposure-gated verdict beside the two judges', as JSON
#    (design decision 99)
SCHEMA_VERSION = 18
# (reliability) EXTRA, not FULL. With a rollback journal FULL makes a commit atomic but not durable: the
# journal's unlink, which is the commit, can still be lost to a power cut, and the next open then rolls the
# committed transaction back. EXTRA fsyncs the directory after the unlink, one more fsync per commit
# (design decision 73; tools/sync_bench.py measures it, tests/virtual/test_virtual_powercut.py cuts under it)
SYNCHRONOUS = "EXTRA"

SCHEMA = """
CREATE TABLE IF NOT EXISTS meta(key TEXT PRIMARY KEY, value TEXT);
CREATE TABLE IF NOT EXISTS ingest_state(source TEXT PRIMARY KEY, inode INTEGER, offset INTEGER,
  last_t REAL, head BLOB, rotated INTEGER);
CREATE TABLE IF NOT EXISTS ingest_runs(t REAL PRIMARY KEY, seconds REAL, stats TEXT, warnings TEXT);
CREATE TABLE IF NOT EXISTS pcaps_done(name TEXT PRIMARY KEY, done_at REAL, tls_rows INTEGER,
  http_rows INTEGER, syn443_rows INTEGER, error TEXT, attempts INTEGER);
CREATE TABLE IF NOT EXISTS flows(id INTEGER PRIMARY KEY, t_start REAL, t_end REAL NOT NULL, proto TEXT,
  dst TEXT NOT NULL, dport INTEGER, sport INTEGER, pkts_up INTEGER, bytes_up INTEGER, pkts_down INTEGER,
  bytes_down INTEGER, state TEXT, timeout_left INTEGER);
CREATE INDEX IF NOT EXISTS flows_t ON flows(t_end);
CREATE INDEX IF NOT EXISTS flows_start ON flows(t_start);
CREATE INDEX IF NOT EXISTS flows_conn ON flows(dst, sport, t_end);
CREATE TABLE IF NOT EXISTS dns(id INTEGER PRIMARY KEY, t REAL NOT NULL, qname TEXT NOT NULL, qtype TEXT,
  answers TEXT, blocked INTEGER NOT NULL, reason TEXT, rule TEXT, filter_id INTEGER, upstream TEXT,
  cached INTEGER, elapsed_ms REAL);
CREATE INDEX IF NOT EXISTS dns_t ON dns(t);
CREATE INDEX IF NOT EXISTS dns_q_t ON dns(qname, t);
CREATE TABLE IF NOT EXISTS tls(id INTEGER PRIMARY KEY, t REAL NOT NULL, dst TEXT, dport INTEGER,
  sport INTEGER, sni TEXT NOT NULL, ech INTEGER, ja4 TEXT, transport TEXT, partial INTEGER);
CREATE INDEX IF NOT EXISTS tls_t ON tls(t);
CREATE INDEX IF NOT EXISTS tls_sni ON tls(sni);
CREATE INDEX IF NOT EXISTS tls_conn ON tls(dst, sport, t);
-- (namebound) one row per address an A answer to the TV named (design decision 70): the names stay in dns
-- (its qname and the CNAME targets of its answers); ttl is the smallest lifetime of the answer's A records,
-- NULL for a row made from a stored answer, which kept none. Kept namebound.ANSWER_IP_DAYS
CREATE TABLE IF NOT EXISTS answer_ip(dns_id INTEGER NOT NULL, t REAL NOT NULL, ip TEXT NOT NULL, ttl INTEGER);
CREATE INDEX IF NOT EXISTS answer_ip_ip_t ON answer_ip(ip, t);
CREATE INDEX IF NOT EXISTS answer_ip_t ON answer_ip(t);
CREATE TABLE IF NOT EXISTS tls_noname(id INTEGER PRIMARY KEY, t REAL NOT NULL, dst TEXT, dport INTEGER,
  sport INTEGER, ja4 TEXT, transport TEXT, partial INTEGER);
CREATE INDEX IF NOT EXISTS tls_noname_t ON tls_noname(t);
CREATE TABLE IF NOT EXISTS http(id INTEGER PRIMARY KEY, t REAL NOT NULL, host TEXT, method TEXT, uri TEXT,
  ua TEXT, status INTEGER, bytes INTEGER, src TEXT NOT NULL);
CREATE INDEX IF NOT EXISTS http_t ON http(t);
CREATE INDEX IF NOT EXISTS http_host ON http(host);
CREATE TABLE IF NOT EXISTS lanprobe(id INTEGER PRIMARY KEY, t REAL NOT NULL, dst TEXT NOT NULL, proto TEXT,
  dport INTEGER);
CREATE INDEX IF NOT EXISTS lanprobe_t ON lanprobe(t);
CREATE TABLE IF NOT EXISTS tvstate(t REAL PRIMARY KEY, power TEXT, app TEXT);
-- (app in front) schema 12: the live reading's events at their own times, beside the hourly readings in
-- tvstate (kind: app, power, conn, link, alive, clock, watch; design decision 67). Kept TV_EVENTS_DAYS
CREATE TABLE IF NOT EXISTS tv_events(id INTEGER PRIMARY KEY, t REAL NOT NULL, kind TEXT NOT NULL, value TEXT,
  detail TEXT);
CREATE INDEX IF NOT EXISTS tv_events_t ON tv_events(t);
CREATE TABLE IF NOT EXISTS tvsettings(t REAL NOT NULL, key TEXT NOT NULL, value TEXT, PRIMARY KEY(t, key));
CREATE TABLE IF NOT EXISTS oddport(id INTEGER PRIMARY KEY, t REAL NOT NULL, proto TEXT, dst TEXT,
  dport INTEGER, raw TEXT);
CREATE INDEX IF NOT EXISTS oddport_t ON oddport(t);
CREATE TABLE IF NOT EXISTS gate(id INTEGER PRIMARY KEY, t REAL NOT NULL, proto TEXT, dst TEXT,
  dport INTEGER, raw TEXT);
CREATE INDEX IF NOT EXISTS gate_t ON gate(t);
-- (inpath) schema 11: gate's twin for the in-path filler's count (design decision 64)
CREATE TABLE IF NOT EXISTS gate_inpath(id INTEGER PRIMARY KEY, t REAL NOT NULL, proto TEXT, dst TEXT,
  dport INTEGER, raw TEXT);
CREATE INDEX IF NOT EXISTS gate_inpath_t ON gate_inpath(t);
-- (attention) schema 17: the attention count's samples (design decision 69), read from the kernel's sets by
-- the hourly ingest: when the kernel first counted the connection, the TV's state then, and its tuple
CREATE TABLE IF NOT EXISTS attention(id INTEGER PRIMARY KEY, t REAL NOT NULL, state TEXT NOT NULL, proto TEXT,
  dst TEXT, sport INTEGER, dport INTEGER);
CREATE INDEX IF NOT EXISTS attention_t ON attention(t);
CREATE TABLE IF NOT EXISTS adport(id INTEGER PRIMARY KEY, t REAL NOT NULL, proto TEXT, dst TEXT,
  dport INTEGER, raw TEXT);
CREATE INDEX IF NOT EXISTS adport_t ON adport(t);
CREATE TABLE IF NOT EXISTS auto_rules(rule TEXT PRIMARY KEY, name TEXT, added_t REAL NOT NULL,
  source TEXT, proposer TEXT, verifier TEXT, verifier_reason TEXT, trial_until REAL, verdict TEXT,
  decided_t REAL, reason TEXT, canary TEXT, trial_id INTEGER);
CREATE TABLE IF NOT EXISTS judgments(name TEXT PRIMARY KEY, kind TEXT NOT NULL, t REAL NOT NULL, source TEXT,
  reason TEXT);
-- (autonomy) one row per gate decision, second-model answer, apply, canary and judge verdict; a later
-- outcome is a new row, never an edit, so a rule tried twice keeps both histories (schema 9)
CREATE TABLE IF NOT EXISTS decisions(id INTEGER PRIMARY KEY, t REAL NOT NULL, stage TEXT NOT NULL,
  outcome TEXT NOT NULL, rule TEXT, name TEXT, source TEXT, trial_id INTEGER, reason TEXT, margins TEXT,
  model TEXT, effort TEXT, usage TEXT);
CREATE INDEX IF NOT EXISTS decisions_t ON decisions(t);
CREATE INDEX IF NOT EXISTS decisions_name ON decisions(name, t);
CREATE TRIGGER IF NOT EXISTS decisions_append_only BEFORE UPDATE ON decisions
  BEGIN SELECT RAISE(ABORT, 'decisions is append-only'); END;
-- (autonomy) vetted blocks the code's gates cleared while another rule was on trial: one trial at a time
CREATE TABLE IF NOT EXISTS auto_queue(rule TEXT PRIMARY KEY, name TEXT NOT NULL, queued_t REAL NOT NULL,
  source TEXT, proposer TEXT, risk TEXT, since REAL NOT NULL);
CREATE TABLE IF NOT EXISTS hosts(name TEXT PRIMARY KEY, first_seen REAL, last_seen REAL, category TEXT,
  dns_n INTEGER, tls_n INTEGER, http_n INTEGER, last_blocked INTEGER, last_rule TEXT, notes TEXT);
CREATE TABLE IF NOT EXISTS rules(id INTEGER PRIMARY KEY, kind TEXT NOT NULL, text TEXT NOT NULL,
  first_seen REAL NOT NULL, last_seen REAL NOT NULL, removed_at REAL);
CREATE TABLE IF NOT EXISTS verify(t REAL PRIMARY KEY, ok INTEGER NOT NULL, failures TEXT);
CREATE TABLE IF NOT EXISTS fw_counters(t REAL NOT NULL, rule TEXT NOT NULL, packets INTEGER, bytes INTEGER);
CREATE INDEX IF NOT EXISTS fw_counters_rule_t ON fw_counters(rule, t);
CREATE INDEX IF NOT EXISTS fw_counters_t ON fw_counters(t);
-- (ledger) schema 9: the change ledger (design decision 48). Append-only; no addresses in detail
CREATE TABLE IF NOT EXISTS changes(id INTEGER PRIMARY KEY, t REAL NOT NULL, t_end REAL,
  t_precision REAL NOT NULL, source TEXT NOT NULL, kind TEXT NOT NULL, subject TEXT NOT NULL DEFAULT '',
  detail TEXT, controllable INTEGER NOT NULL, effect_class TEXT NOT NULL, metric_affecting TEXT);
CREATE INDEX IF NOT EXISTS changes_t ON changes(t);
CREATE UNIQUE INDEX IF NOT EXISTS changes_event ON changes(t, source, kind, subject);
CREATE TABLE IF NOT EXISTS gw_samples(t REAL PRIMARY KEY, boot_id TEXT, tv_cc INTEGER, wan_cc INTEGER,
  vpn_if TEXT, vpn_present INTEGER, vpn_cc INTEGER, pia_state TEXT, wlan_signal REAL, wlan_rx_mbps REAL,
  wlan_tx_mbps REAL, wlan_tx_failed INTEGER, wan_rx_bytes INTEGER, wan_tx_bytes INTEGER,
  tv_rx_bytes INTEGER, tv_tx_bytes INTEGER, ct_count INTEGER, ct_max INTEGER, ct_drop INTEGER,
  ct_early_drop INTEGER, ct_insert_failed INTEGER, agh_invocation TEXT, agh_nrestarts INTEGER,
  filter_mtimes TEXT, wan_addr_tag TEXT, tv_probe TEXT, soc_temp REAL, throttled INTEGER, mem_avail_pct REAL,
  mem_psi_some INTEGER, disk_dev TEXT, disk_sectors_written INTEGER, io_errors INTEGER,
  io_errors_store INTEGER, usb_resets INTEGER);
CREATE TABLE IF NOT EXISTS judge_shadow(t REAL NOT NULL, rule TEXT NOT NULL, added_t REAL NOT NULL,
  hour REAL NOT NULL, hour_class TEXT, v1 TEXT, v1_reason TEXT, v2 TEXT NOT NULL, v2_reason TEXT,
  clean_hours INTEGER, k INTEGER, final INTEGER NOT NULL DEFAULT 0, kernel TEXT,
  PRIMARY KEY(rule, added_t, hour));
CREATE INDEX IF NOT EXISTS judge_shadow_t ON judge_shadow(t);
-- (threats) schema 16: one row per local day, name and list (tif or nrd) of the TV's names a downloaded
-- list covers, with the entry that matched, the list's label, copy day and newly-registered band, the
-- lookups and how many the filter answered with a public address, the first and last time, and why the
-- hit is more likely the list's error than the TV's, or NULL (design decision 80)
CREATE TABLE IF NOT EXISTS threat_hits(day TEXT NOT NULL, name TEXT NOT NULL, list TEXT NOT NULL,
  entry TEXT NOT NULL, source TEXT, copy TEXT, band TEXT, lookups INTEGER NOT NULL,
  answered INTEGER NOT NULL, first REAL NOT NULL, last REAL NOT NULL, doubt TEXT,
  PRIMARY KEY(day, name, list));
CREATE INDEX IF NOT EXISTS threat_hits_last ON threat_hits(last);
CREATE VIEW IF NOT EXISTS v_ip_names AS
  SELECT dst AS ip, sni AS name, COUNT(*) AS n, MAX(t) AS last_t FROM tls GROUP BY dst, sni;
"""

# every table but the bookkeeping (meta, ingest_state): what `tvgw size` counts
TABLES = (
    "flows",
    "dns",
    "tls",
    "tls_noname",
    "http",
    "lanprobe",
    "tvstate",
    "tv_events",  # (app in front) schema 12
    "tvsettings",
    "oddport",
    "gate",
    "adport",  # (acr) schema 9
    "gate_inpath",  # (inpath) schema 11
    "answer_ip",  # (namebound) schema 15
    "attention",  # (attention) schema 17
    "hosts",
    "rules",
    "auto_rules",
    "judgments",
    "decisions",  # (autonomy) schema 9
    "auto_queue",  # (autonomy) schema 9
    "verify",
    "fw_counters",
    "pcaps_done",
    "ingest_runs",
    "changes",  # (ledger) schema 9
    "gw_samples",
    "judge_shadow",
    "threat_hits",  # (threats) schema 16
)


class StoreTooNew(sqlite3.DatabaseError):
    """(reliability) The store was written by a newer tvgw than this one, or carries a version this one
    cannot read. Nothing was written to it. A subclass of sqlite3.Error, so every caller that already
    survives a store it cannot open survives this one, and says why."""

    def __init__(self, path: str, found: str) -> None:
        self.path, self.found = path, found
        super().__init__(
            f"the store {path} was written by a newer tvgw (schema {found}); this one knows schema"
            f" {SCHEMA_VERSION} at most, so it does not write to it. Install the newer tvgw again, or put"
            " back a copy made before it (tvgw restore --check FILE tests a copy first)"
        )


def stored_version(conn: sqlite3.Connection) -> str | None:
    """(reliability) The schema version the store's `meta` records, as written; None for a store with no
    `meta` table or no version in it (new, or older than the version row)."""
    try:
        row = conn.execute("SELECT value FROM meta WHERE key='schema'").fetchone()
    except sqlite3.OperationalError:  # no meta table: a new, empty file
        return None
    return None if row is None or row[0] is None else str(row[0])


def too_new(found: str | None) -> bool:
    """(reliability) Whether a recorded version forbids this code to write: higher than SCHEMA_VERSION, or
    not a whole number at all (it cannot be shown to be lower)."""
    if found is None:
        return False
    return not found.strip().isdigit() or int(found) > SCHEMA_VERSION


def connect(path: str, readonly: bool = False, timeout: float = 60) -> sqlite3.Connection:
    """Open the store. Writers get the schema applied; readers open `mode=ro` and need only read access.
    (reliability) A writer reads the recorded version first and raises StoreTooNew, having written
    nothing, when a newer tvgw wrote the store; it writes the version only when it rises. A reader opens
    any store: reading changes nothing, and the schema only ever adds."""
    if readonly:
        return sqlite3.connect(f"file:{_uri_path(path)}?mode=ro", uri=True, timeout=timeout)
    new = not os.path.exists(path)
    conn = sqlite3.connect(path, timeout=timeout)
    try:
        # before any write, the journal mode's included: a newer tvgw may have chosen another
        found = stored_version(conn)
        if too_new(found):
            raise StoreTooNew(path, str(found))
        conn.execute("PRAGMA journal_mode=DELETE")
        # NORMAL is corruption-safe only in WAL; with the rollback journal SQLite documents a non-zero
        # chance of corruption on power loss. (reliability) SYNCHRONOUS says why EXTRA and not FULL
        conn.execute(f"PRAGMA synchronous={SYNCHRONOUS}")
        conn.executescript(SCHEMA)
        _migrate(conn)
        if found != str(SCHEMA_VERSION):  # only ever upwards: too_new() refused a higher one above
            conn.execute(
                "INSERT OR REPLACE INTO meta(key, value) VALUES ('schema', ?)", (str(SCHEMA_VERSION),)
            )
        conn.commit()  # or this connection holds the write lock until its first commit, and others wait
    except BaseException:
        conn.close()
        raise
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
    ("flows", "timeout_left", "INTEGER"),  # schema 7
    ("ingest_state", "rotated", "INTEGER"),  # schema 7: the log's .1 at the last read
    ("tls", "ja4", "TEXT"),  # schema 8 (extractor): the hello's JA4, '' when it could not be read whole
    ("tls", "transport", "TEXT"),  # schema 8: 'tcp' or 'quic'; NULL before
    ("tls", "partial", "INTEGER"),  # schema 8: 1 when read from a split hello's first segment alone
    ("auto_rules", "canary", "TEXT"),  # (autonomy) schema 9: armed, passed, reverted or unobserved
    ("auto_rules", "trial_id", "INTEGER"),  # (autonomy) schema 9: the decisions row of the apply
    ("gw_samples", "wan_addr_tag", "TEXT"),  # (plain) schema 10: the uplink's keyed tag
    ("gw_samples", "tv_probe", "TEXT"),  # (probe) schema 13: the probe's verdict, as probe.Verdict.compact()
    # (reliability) schema 14: the gateway's own health (health.py)
    ("gw_samples", "soc_temp", "REAL"),
    ("gw_samples", "throttled", "INTEGER"),
    ("gw_samples", "mem_avail_pct", "REAL"),
    ("gw_samples", "mem_psi_some", "INTEGER"),
    ("gw_samples", "disk_dev", "TEXT"),
    ("gw_samples", "disk_sectors_written", "INTEGER"),
    ("gw_samples", "io_errors", "INTEGER"),
    ("gw_samples", "io_errors_store", "INTEGER"),
    ("gw_samples", "usb_resets", "INTEGER"),
    ("judge_shadow", "kernel", "TEXT"),  # (exposure) schema 18: the exposure-gated verdict, as JSON
)
# indexes on columns ADDED_COLUMNS may have just added: created after them, or an old store's open
# would fail on a column it does not have yet
LATE_INDEXES = ("CREATE INDEX IF NOT EXISTS tls_ja4 ON tls(ja4, t)",)  # schema 8 (extractor)
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
    for statement in LATE_INDEXES:
        conn.execute(statement)


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
