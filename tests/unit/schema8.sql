-- The store at schema 8 (db.SCHEMA and LATE_INDEXES of src/tvgw/db.py as main shipped them before
-- research pass 2), frozen so tests/unit/test_schema9.py can build an old store without git.
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
CREATE TABLE IF NOT EXISTS tvsettings(t REAL NOT NULL, key TEXT NOT NULL, value TEXT, PRIMARY KEY(t, key));
CREATE TABLE IF NOT EXISTS oddport(id INTEGER PRIMARY KEY, t REAL NOT NULL, proto TEXT, dst TEXT,
  dport INTEGER, raw TEXT);
CREATE INDEX IF NOT EXISTS oddport_t ON oddport(t);
CREATE TABLE IF NOT EXISTS gate(id INTEGER PRIMARY KEY, t REAL NOT NULL, proto TEXT, dst TEXT,
  dport INTEGER, raw TEXT);
CREATE INDEX IF NOT EXISTS gate_t ON gate(t);
CREATE TABLE IF NOT EXISTS auto_rules(rule TEXT PRIMARY KEY, name TEXT, added_t REAL NOT NULL,
  source TEXT, proposer TEXT, verifier TEXT, verifier_reason TEXT, trial_until REAL, verdict TEXT,
  decided_t REAL, reason TEXT);
CREATE TABLE IF NOT EXISTS judgments(name TEXT PRIMARY KEY, kind TEXT NOT NULL, t REAL NOT NULL, source TEXT,
  reason TEXT);
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
CREATE INDEX IF NOT EXISTS tls_ja4 ON tls(ja4, t);
