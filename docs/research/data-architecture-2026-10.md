# Data architecture: capturing, organizing and analyzing what the TV does

*Design track, 2026-10-27. Status: a proposal for the owner. Nothing on this page is implemented. It synthesizes three independent reviews of the data path; every claim kept here was re-verified against the code, on temporary stores, before it was written down (section 5). [architecture.md](../architecture.md) describes the store as it is. This page says where the data layer should go and how to get there so that `tvgw brief` keeps working on every day in between.*

## 1. Where it stands

The shape of the pipeline is right and should be kept:

- Parsers are pure functions; everything that touches the Pi is injected. The ingest is testable without a gateway.
- Each source is one transaction, and its read cursor commits with the rows it covers. The hourly run is effectively exactly-once and safe to kill.
- Pcaps are read once, as `nobody`, and recorded in `pcaps_done`. Exit 2 is split by its message after the 2026-10-27 incident.
- `hosts` counters advance by row id, so a late row is counted once. Rule history treats "unreadable" as unknown, not empty.
- Coverage and red lines are first-class concepts in the brief.

What is wrong is narrower than it looks: a few evidence lines compute the wrong number, the capture's time assumptions do not hold, and "coverage" measures the wrong thing. Verified defects, most serious first:

| # | Defect | Effect on the brief | Where |
|---|---|---|---|
| 1 | The two DNS DNAT rules (udp and tcp dport 53) share one comment. `verify.record` stores both counters per snapshot and `fw_activity` differences them as one series. | "Firewall held: DNS forced to AdGuard" is inflated about 13x on the deployed ruleset (650 reported for a true 50 in a six-snapshot replay). | `queries.py` 320-335, `tvgw-apply` 90-91 |
| 2 | `flows.t_end` is conntrack's DESTROY time: last packet plus the state timeout (7440 s ESTABLISHED, 120 s TIME_WAIT). Every flow section windows by `t_end`. | A connection the TV abandons at power-off lands two hours later, inside the hours the TV reported itself off. "While off/asleep" shows real traffic every evening; end-of-day bytes move into the next day. | `queries.py` 426-443, 519-529, 640-655 |
| 3 | The naming join assumes conntrack's start time runs late. It is `t_end` that runs late; `delta-time` is `now - start` in whole seconds, so `t_start` is the SYN time to within a second. The join allows 300 s before `t_start` and takes the latest hello. | A 4-tuple reused inside the first flow's TIME_WAIT tail gives the first flow the second connection's name. The two docs state the wrong premise. | `queries.py` 42-47, 149-155; `architecture.md` "Naming a connection"; design-decisions 12 |
| 4 | `unresolved_flows` explains an address by substring (`answers LIKE '%dst%'`), exempts it on any hello to it at any time, and cannot use HTTP hosts because `http` has no `dst`. | A flow to `1.2.3.4` disappears when any answer contains `11.2.3.45`, or when a hello reached the address a year ago. Plain-HTTP flows to hardcoded addresses are listed as unresolved although their Host header is in the store. | `queries.py` 359-383, `ingest.py` 191 |
| 5 | `coverage()` calls a source assessed when its ingest step returned without raising. Missing files, a dead tcpdump or conntrack, a failing `journalctl` all return normally. `last_warnings` is overwritten each run. Pcaps are counted by `done_at`, not by the hour they cover. | A gateway with every source missing reports six sources assessed, zero warnings. Yesterday's brief shows today's warnings. | `ingest.py` 490-497, 273-295; `queries.py` 446-484 |
| 6 | Pcap names are local time (`%Y%m%d-%H%M`), rotation runs 3600 s after the last rotation (not on the hour), and tcpdump truncates a file whose name already exists. | On the fall-back night (2026-11-01 in America/Chicago) the second 01:MM file destroys the first before ingest sees it: an hour of TLS and HTTP evidence lost, silently. Daily reports are written once at 00:20, before the last pcap of the day is closed whenever the rotation phase is past :20. | `tvgw-pcap.service` 11, `tvgw-analyze` 55-68 |
| 7 | The BPF keeps any TCP segment whose first payload byte is `0x16`; ciphertext bytes are uniform, so about 1 in 256 mid-stream segments is kept whole. `tcp port 80` keeps response bodies both ways. A ClientHello longer than one segment loses its continuation. Plain HTTP on 8080 (the LG update fallback) is captured as SYNs only. | The privacy page's "never TLS application data" does not hold; at 60-70 GB/day of video the leak is on the order of 200 MB/day, which can push the pcap directory over `PCAP_MAX_GB` and shorten retention. No-SNI and split hellos are invisible. | `tvgw-pcap.service` 12; `privacy-and-retention.md` |
| 8 | `fw_counters` is never pruned and the previous-snapshot query scans all of it; `host_detail` probes `flows(dst, dport)` per hello. | 0.43 s per report at a synthetic year (1.05 M rows), growing forever; `host_detail` is quadratic: 0.19 / 0.76 / 3.05 s at 2 k / 4 k / 8 k connections to one address. | `queries.py` 320-326, 149-155 |
| 9 | A full `VACUUM` every 30 days inside the hourly run, `synchronous=NORMAL` on a rollback journal, no integrity check, no backup. | Minutes of exclusive lock on an SD card; `verify --record` waits 60 s then fails and loses a snapshot. A power cut at the wrong moment can corrupt the only copy. | `ingest.py` 461-465, `db.py` 86-87 |
| 10 | Smaller, all reproduced: `hosts` watermark loses rows after a table empties (row ids are reused without AUTOINCREMENT); GFTS requests are counted by both sensors (`http_n` 3 for one request); `ERR TimeoutError` is stored as a setting value; a half-written flow line plus the next event parses as one chimera flow; `journalctl` failures look like "no odd-port events"; the extractor drops hellos without SNI and cannot tell QUIC from TCP; UDP discovery (SSDP, mDNS) is captured but never stored; `SCHEMA_VERSION` is written and never read; the malformed-DNS test never exercises the malformed path. | | `ingest.py` 397-403, 190-194, 248-256, 274-281; `conntrack.py` 49-51; `tshark.py` 19-22, 102; `db.py` 14-16, 90 |

## 2. Target design

### 2.1 Principles

1. **Facts are immutable and arrive late.** A fact row is written once by ingest and never updated. Everything an analysis needs that is not in the source (the connection's name, the day's totals) is derived, rebuildable from facts, and advanced by a watermark exactly as `hosts` is today.
2. **One definition per fact.** A connection is named once, at ingest, by one rule. Queries read the result; they never re-derive it.
3. **Time is stored as epoch; days are resolved at the edge.** Rollups are keyed by UTC day so a time-zone move cannot re-bucket history; the brief renders local days as now.
4. **Coverage is a comparison, not a flag.** Per source: how far its data reaches, against the window's end. Per hour: two observers of the same traffic, against each other.
5. **Every analysis is a pure function** of (facts, rollups, profile, now) and writes its result as rows, so the brief can show what is new.
6. **Migrations are versioned, explicit and backed up.** A reader refuses a newer schema than it knows.

### 2.2 Layers

| Layer | Table | Key | What changes | Kept |
|---|---|---|---|---|
| Facts | `flows` | id | adds `t_last`, `assured` (from the dropped `[ASSURED]` flag), `device_id`; derived columns `name`, `name_src`, `hello_id`, `http_id`, `t_close` (section 2.3) | `DB_DAYS` |
| | `dns` | id | adds `rcode`, `ttl_min`, `device_id`; `answers` text stays for display | `DB_DAYS` |
| | `tls` | id | `sni` becomes nullable (a hello without SNI is the most suspicious kind); adds `transport` (`tcp`/`quic`), `ja3`, `alpn`, `version`, `ech`, `device_id` | `DB_DAYS` |
| | `http` | id | adds `dst`, `sport` (tshark already extracts them), `device_id`; one sensor of record per request (nginx log for URL-filter hosts, pcap for the rest) | `DB_DAYS` |
| | `lanprobe` | id | `proto` gains `udp` rows: SSDP 1900, mDNS 5353, NBNS 137, WS-Discovery 3702 | `DB_DAYS` |
| | `tcp_end`, `dns_wire`, `dhcp` | id | new, from the same tshark pass (section 2.6) | 30 d |
| | `fw_counters` | (t, rule, idx) | adds `idx` so two rules with one comment are two rows by design; index on `t` | 30 d |
| Derived | `ip_name` | (day, ip, qname) | which names resolved to which address, per UTC day, with `n`, `first_t`, `last_t`; built from the decoded answers at ingest | with facts |
| | `host_day` | (day, device_id, name) | lookups, blocked, conns, bytes up/down, first/last seen, distinct addresses | forever |
| | `fw_day` | (day, rule) | positive counter steps per day | forever |
| | `hosts` | name | unchanged role (the first-seen ledger); counters move to `host_day`; watermark immune to id reuse | forever |
| Dimensions | `device` | id | `mac`, `name`, `profile`, `first_seen`, `last_seen`; seeded from `tvgw.conf` as device 1 | forever |
| | `device_addr` | (device_id, ip, t_from) | leases from dnsmasq's `log-dhcp` lines or the DHCP packets already in the pcap | forever |
| Conclusions | `finding` | (kind, subject, day) | score, evidence JSON, first/last seen (section 2.7) | forever |
| | `ingest_run` | t | seconds, stats JSON, warnings JSON: warnings belong to the run that produced them | forever |
| Bookkeeping | `pcaps_done` | name | adds `size`, `t_first`, `t_last`, `frames`, `status` (`ok`/`partial`/`failed`), `attempts`, `extractor_version` | as now |
| | `ingest_state` | source | `last_t` becomes the newest **event** time seen, not the wall clock | as now |

Row counts stay small where it matters: `host_day` is a few hundred names times 365, `fw_day` about 20 times 365, `ip_name` a few hundred pairs a day. The facts are about 1 GB a year at the observed rates and dominate the file whatever else is added.

### 2.3 Connections: one row, resolved once

The connection table **is** `flows`. One row per conntrack flow already exists, the conntrack 4-tuple is the connection's identity, and a separate `conn` table would add a join to every query for no gain. `flows` gains derived columns filled by a `resolve(window)` pass at the end of each ingest:

- `name`, `name_src` in strict precedence: `sni` (the hello with the same `dst`, `dport`, `sport`, whose `t` lies in `[t_start - 5, t_end]`, the **first** one), then `http` (a request with the same `dst` and `sport` inside the flow), then `dns` (exactly one qname in `ip_name` for `dst` on the flow's day or the day before; several names means a shared CDN address and stays unnamed), else NULL.
- `hello_id`, `http_id`: provenance, so a report can say which packet named the flow.
- `t_close`: the FIN or RST from the TV in the pcap (`tcp_end`), when captured.

The pass is idempotent and order-independent: it recomputes every flow with `t_end` in the last 6 hours (pcaps arrive one to two hours late), and the pcap step also calls it for the interval a late pcap covers, so a file retried days later still names its flows exactly once. A one-time backfill runs the same function over the existing year. Tests: ingest the fixture with the pcap step before and after the flows step and assert identical rows; a late hello upgrades `name_src` from `dns` to `sni` once and a third run changes nothing; two flows that reuse a 4-tuple inside the first one's TIME_WAIT each carry their own name.

Once `flows.name` exists, `FLOW_NAME`, the inverse join in `host_detail` and the three disagreeing rules in `unresolved_flows` are deleted. `categories`, `top_upload` and `host_detail` become `GROUP BY name` over an index `flows(name, t_last)`.

### 2.4 Time

- `t_start = t_end - delta_time` is the SYN time within one second (conntrack prints `delta-time = now - start`). It is accurate; keep it.
- `t_end` is DESTROY time: last activity plus the state's timeout, plus the garbage collector's lag (under a minute on a table this small). It is the wrong column to window by.
- `t_last = t_end - timeout(state, assured)` is the last-activity estimate. The timeouts come from `/proc/sys/net/netfilter/nf_conntrack_*` at ingest (injected; defaults in code: ESTABLISHED 7440 as set by `tvgw-apply`, TIME_WAIT 120, CLOSE 10, FIN_WAIT 120, CLOSE_WAIT 60, LAST_ACK 30, SYN_SENT 120, SYN_RECV 60; UDP 30 unreplied, 120 assured on current kernels, 180 on older ones). Backfilled for existing rows from `state`.
- All flow windows use `t_last`. "While off/asleep" counts flows whose `[t_start, t_last]` intersects an off hour. Where `t_close` exists it supersedes `t_last`.
- The naming slack shrinks from 300 s before `t_start` to 5 s (one second of integer truncation, a margin for the two clocks), and the first hello wins. Ingest warns when more than a few percent of a run's TCP flows have zero duration, which means `nf_conntrack_timestamp` is off and no flow can be named.
- Pcap names are UTC (`Environment=TZ=UTC` on the unit), so names sort in time order and never repeat. `pcaps_done.t_first` comes from the first record header (24 + 16 bytes, pure Python); `t_last` from the file's mtime, which is the rotation time.

### 2.5 Coverage is a comparison

- **Per source, data time.** `ingest_state.last_t` holds the newest event time each source produced. A source is assessed for a window when its newest event is within `STALE` of the window's end; a source whose file is missing, whose process is dead, or whose `journalctl` failed is *not assessed*, named as such. `journal_oddport_lines` raises on a nonzero exit code or on exceptions, so the step records a warning and does not stamp the source. Pcaps count by the hour they cover (`t_first`, `t_last`), and the gaps between consecutive pcaps are listed.
- **Per hour, two observers.** SYNs from the TV to public addresses in the pcap against TCP flows started in the hour from conntrack; later, DNS on the wire against AdGuard's rows (section 2.6). A ratio below 0.95 is a line in Coverage; a TV-Active hour with zero `dns` or zero `flows` rows is a red line.
- **Warnings belong to runs.** `ingest_run(t, seconds, stats, warnings)` replaces `meta.last_warnings`; the brief's "ingest warnings" red line reads the runs inside its window.
- **Reports are final only when covered.** `tvgw-analyze` rewrites `daily/<D>` while D is within 48 h and `weekly/<W>` for two days after the week ends; `queries.finished_days(now, pcaps_done)` decides in Python (unit-testable) instead of bash date arithmetic. The AdGuard query log is buffered in memory until `querylog.size_memory` entries; `adguardcfg.plan()` owns it at 10 since 2026-10-28 (AdGuard's default of 1000 held two hours of lookups back from the store while one app ran), so rows reach the store at the next hourly ingest.
- **Failed pcaps have a status.** `pcaps_done.status` and `attempts`: after three failures a file is `failed` with its reason, its hours are a coverage gap, and the warning stops repeating every hour for a week.

### 2.6 Capture

In order of value per unit of risk:

1. **UTC names** (section 2.4). One line in the unit; a unit test asserts the template has no local-time ambiguity; a hardware test asserts the sorted names are strictly increasing. Do this before 2026-11-01.
2. **Tighten the BPF.** Replace the single-byte test with the record version and handshake type: `tcp[off:1] = 0x16 and tcp[off+1:1] = 0x03 and (tcp[off+5:1] = 0x01 or tcp[off+5:1] = 0x02 or tcp[off+5:1] = 0x0b)` with `off = ((tcp[12:1] & 0xf0) >> 2)`, so ClientHello, ServerHello and TLS 1.2 Certificate records are kept and a chance match on ciphertext falls from 1 in 256 to about 1 in 5 million. Keep `tcp dst port 80` whole (requests, including POST bodies, are evidence), keep responses only where the segment starts with `HTTP` (`tcp src port 80 and tcp[off:4] = 0x48545450`: headers, not bodies), and add `tcp dst port 8080` for the LG update fallback. The filter compiles to 80 BPF instructions. Acceptance on hardware: a streaming hour's pcap under a byte budget, and `tls` rows still arriving. State in `privacy-and-retention.md` what the filter can and cannot promise.
3. **Extend the one tshark pass.** Filter on `tls.handshake.type == 1` alone so hellos without SNI are stored (sni NULL, `dst` kept). Add `tls.handshake.ja3` (present in tshark 4.0; `ja4` needs 4.2, so compute it in Python if wanted), `tls.handshake.extensions_alpn_str`, `tls.handshake.version`, extension type `0xfe0d` as `ech`, and `transport` from the UDP ports. Add FIN/RST from the TV (`tcp_end`), UDP from the TV to multicast or private destinations (`lanprobe` with `proto='udp'`), DNS on the wire (`dns.qry.name`, `dns.flags.response`, `dns.id`, `ip.dst`: the resolver the TV aimed at, pre-DNAT, and a completeness check against AdGuard), and DHCP options 12, 55 and 60 for the device dimension. Record `extractor_version` per pcap so a new extractor re-runs over the seven retained days. Consider `-o tcp.desegment_tcp_streams:FALSE` so a hello whose continuation the filter dropped still yields its SNI when the extension is in the first segment; validate on a captured file.
4. **Prune through the store.** `tvgw-prune` deletes only files in `pcaps_done`, except above a hard cap, where it deletes the oldest un-ingested file and records the gap.
5. **Position-based capture** (`ct original packets <= N log group N` plus `tcpdump -i nflog:N`) keeps every handshake whole however it is segmented and bounds every connection's captured bytes. It changes the firewall and belongs to a later, approved experiment (section 4).
6. **Not worth it now:** certificate issuers (TLS 1.2 only, multi-segment server flights the BPF cannot express), IPv6 evidence (dropped at the wire and disabled; the compiled filter's IPv6 branch keeps only port 80 and UDP, which is fine).

### 2.7 Analyses

Each is a pure function over facts and rollups, returns rows for a brief section, and upserts `finding(kind, subject, day, score, evidence)` so the brief marks new findings and nothing re-alerts.

| Analysis | Input | Algorithm | Acceptance |
|---|---|---|---|
| Beacons | `flows.t_start` per name, n >= 12 | Inter-arrival median `m` and MAD; periodic when MAD/m < 0.15 and 10 s <= m <= 1 d; report the period. Lookups per name against `dns.ttl_min`: a median interval under half the TTL is polling that bypasses the cache. O(n log n). | A 60 s beacon with 5 % jitter is flagged; a Poisson stream of equal rate is not. The profile's QuickSet (about 45 s) and admanager (60 s) polls are the historical acceptance cases. **Implemented 2026-10-27** as `queries.beacons` over `flows` (connections within 5 s are one event; the size half is the median payload bound; the DNS/TTL variant waits for `dns.ttl_min`). |
| Upload baseline | `host_day.bytes_up` per name | `x = log1p(bytes)`; trailing 28-day median and MAD (at least 7 days of history); flag when `x > median + 3.5 * 1.4826 * MAD` and bytes > 1 MB; also `bytes_up > bytes_down` outside expected categories. | A 10x spike flags; a gradual rise within 3 MAD does not; a name with 5 days of history is "new", not flagged. |
| Firmware diff | `tvsettings.firmware` changes, `host_day` | Set difference of names (later JA3 stacks) 7 days before and after the change: added, removed, rate ratios over 3x. | The firmware fixture yields an exact added/removed list. |
| Blocked, then fallback | `dns` blocked rows, `flows` | A blocked qname followed within 60 s by a TCP flow whose `name_src` is NULL and whose `dst` no `ip_name` row explains: a hardcoded fallback, reported with the rule that blocked it. Retry intervals per blocked qname against `blocked_response_ttl`. | A blocked lookup followed by a flow to an unexplained address flags; the same flow with a hello does not. |
| DNS as data | `dns` per registrable domain per day | Distinct subdomains, label bytes beyond the registrable domain, NXDOMAIN share (`rcode = 3`), TXT/NULL share, peak lookups per 10 min; thresholds on the domain, not the name; at most three example names per domain. The per-name long/random checks stay but are capped per domain, and the expected-category exemption applies to the per-name list only. | 24- and 32-character base32 and hex streams flag at >= 95 %; a replayed normal day flags nothing; a million unique names cost one `hosts` row per domain over K = 200 names and one anomaly entry. |
| Coverage ratios | pcap SYNs, conntrack flows, wire DNS, AdGuard rows | Per hour as in section 2.5. | A 10 % shortfall is a Coverage line; a dead source while the TV is Active is a red line. |
| Standby | `tvstate`, `flows.t_last` | As today, by activity interval; plus names first seen while the TV was off. | The abandoned-at-power-off connection counts in the hour it was active, not the hour it was destroyed. |

### 2.8 Devices

`device_id INTEGER NOT NULL DEFAULT 1` on every fact table (a cheap `ADD COLUMN`), `device` seeded from `tvgw.conf`, `device_addr` from leases. Ingest resolves `src` to a device at the event's time and drops, but counts, rows from unknown clients, so a changed `TV_IP` becomes a Coverage line instead of a silent empty day. `host_day` and `finding` are keyed by device; `tvgw brief --device` selects one. The single-TV settings file stays the one-device case.

### 2.9 Store hygiene and retention

- Writers use `synchronous=FULL`; the few fsyncs an hour cost nothing on this write rate.
- The periodic `VACUUM` goes. The v3 rebuild sets `auto_vacuum=INCREMENTAL`; each run issues `incremental_vacuum(N)` only when `freelist_count` exceeds a tenth of `page_count`. `verify.record` catches `OperationalError` and reports it rather than failing the unit.
- `prune` computes its cutoff from `min(now, MAX(t))`, so a wrong clock can never delete more than the configured span of real data. `tvgw-analyze.service` gets `Wants=/After=time-sync.target`.
- Retention tiers, to be written into `privacy-and-retention.md`: pcaps 7 d; facts `DB_DAYS`; `fw_counters` and the wire-level facts 30 d; rollups, dimensions and findings kept.
- A daily backup (`VACUUM INTO` a dated copy, `quick_check` on the copy, 7 kept) is the right routine; it is a new unit and a disk budget, so it is in section 4.

### 2.10 Cost on a Pi 5

Every derived table is advanced by watermark, so per-run work is O(new rows). `resolve()` touches the last six hours of flows. Rollups upsert one day. A day's brief over a synthetic year was measured at 0.26 s and a week's at 0.74 s on a laptop by one reviewer; the two unbounded queries in section 1 (#8) are the only ones whose cost grew with history, and both become bounded. The pcap step runs last with a per-run budget (20 min) so a backlog after downtime cannot starve `hosts`, `prune` and the run record before the 45-minute unit timeout.

## 3. Migration stages

Each stage ships alone, is reversible, and leaves the existing brief working because every section keeps reading facts until its replacement has golden-test parity.

**Stage 0a: the brief tells the truth** (no schema change beyond `CREATE INDEX IF NOT EXISTS` and `ADD COLUMN`).
`fw_activity` aggregates per `(t, rule)` before differencing and bounds the previous snapshot to `[since - 3600, since)` with a new index `fw_counters(t)` (0.43 s to 0.002 s at a synthetic year). `flows.t_last` and `assured` added and backfilled; the flow sections and standby window by `t_last`. `FLOW_SLACK = 5`, first hello wins, docs corrected, index `flows(dst, sport, t_end)` so `host_detail` is linear. `unresolved_flows` matches answers as tokens (`','||answers||',' LIKE '%:'||?||',%'`), windows the TLS exemption to the connection, and uses `http.dst`, which the pcap branch now stores along with `sport`. Golden briefs change and are reviewed line by line; design-decisions 12 gets a superseding entry.

**Stage 0b: coverage and hygiene.** `ingest_run`; `ingest_state.last_t` as event time; `coverage()` by data time; `journalctl` failures raise; oddport cursor clamped to `now + 60`; `pcaps_done.status/attempts`; `ERR` values and the `info` key skipped with a warning; chimera flow lines rejected; hosts watermark clamp (`MAX(id) < wm` resets that table's watermark); zero-duration warning; GFTS requests kept from one sensor; `VACUUM` removed; `synchronous=FULL`; data-derived prune cutoff; the malformed-DNS test replaced by a record that raises (`"Answer": 5`).

**Stage 0c: units and reports.** `TZ=UTC` on `tvgw-pcap.service`; `time-sync.target` ordering on `tvgw-analyze.service`; daily and weekly reports rewritten for 48 h after they end, with `finished_days()` in Python. These are deploy changes; `install.sh` already installs the units.

**Stage 1: schema v3 under a migration framework.** `PRAGMA user_version` and an ordered `MIGRATIONS` list run by an explicit `tvgw migrate` (from `install.sh`), preceded by `VACUUM INTO` a backup, inside one transaction; readers refuse a newer version. The one table rebuild adds AUTOINCREMENT to `dns`, `tls`, `http`, makes `tls.sni` nullable, sets `auto_vacuum`, and replaces the single-column time indexes with natural-key unique indexes whose first column is still the time (`dns(t, qname, qtype)`, `flows(t_end, proto, dst, dport, sport)`, `tls(t, dst, sport)`), so `INSERT OR IGNORE` is a second line of defense against a mis-detected rotation at no extra index cost. Then `ip_name`, `dns.rcode/ttl_min`, `flows.name/name_src/hello_id/http_id` with `resolve()` and the backfill, `fw_day`, `host_day`, `device` with `device_id DEFAULT 1`. The brief switches one section at a time to `flows.name` with the old query kept as a differential test over the fixture week; `FLOW_NAME` is deleted last. A migration matrix test applies v2 -> v3 to a fixture store and diffs `sqlite_master` against a fresh install.

**Stage 2: capture.** The tightened BPF and the 8080 term (hardware acceptance, section 2.6); extractor fields, `tcp_end`, UDP probes, `dns_wire`, `dhcp`, `extractor_version` with a re-run over retained pcaps; pruning through `pcaps_done`; the hour-level coverage ratios.

**Stage 3: analyses.** `finding`, the seven analyses with their golden synthetic tests, the retention tiers and cardinality caps, the privacy page updated.

**Stage 4: devices and sessions.** `device_addr` from leases, per-device briefs; then, if approved, the SSAP subscriber for app and power transitions and per-app attribution, and the nflog capture experiment.

## 4. Open questions for the owner

1. **Retention.** Keep facts at 365 days, or 90 days of facts with rollups kept forever? The second is the privacy page's intent and loses nothing the analyses need except raw drill-down beyond 90 days.
2. **Migration execution.** An explicit `tvgw migrate` from `install.sh` (recommended: logged, backed up, run at a chosen time; the rebuild holds the lock for minutes on a 1 GB store and needs twice the file's size free) or implicit on the first writer open.
3. **The capture filter change.** Approve the text in section 2.6 and a hardware acceptance window. The nflog position-based capture changes the firewall and should be a separate, later experiment.
4. **AdGuard's `querylog.size_memory`.** Decided 2026-10-28: `plan()` owns it at 10. The flush behavior was confirmed on the gateway first: with the TV on one app all morning, the log file's last entry and its mtime sat two hours behind the clock until the next 1000-entry flush; the store, the brief and the analyst's pack were that far behind too. The cost is an append to the log file every few minutes at that pace and one resolver restart on the deploy that changed it.
5. **Daily reports.** Rewrite for 48 hours (recommended) or keep "written once" and mark provisional. Is anything diffing the files?
6. **Unique comments on the two DNS DNAT rules.** Cosmetic once Stage 0a aggregates, but it makes the schema's `(t, rule)` key true again. It edits `tvgw-apply`.
7. **Devices.** Is a second TV plausible, or is `device_id` only a hedge against a lease change? It is cheap either way.
8. **Backups.** A daily `VACUUM INTO` copy on the same card protects against corruption, not against the card. Where should copies go, and how many?
9. **The SSAP subscriber.** A persistent, read-only LAN-API connection from the Pi to the TV, for exact app sessions. Acceptable?

## 5. How the claims were checked

Read-only, on this machine, 2026-10-27; nothing on the Pi was touched. The unit suite (330 passed) and ruff were green before and after; this page is the only file added.

- **#1** Six 10-minute snapshots recorded through `verify.record` with the udp counter at 100..150 and a second row with the same comment at 0: `fw_activity` returned 650; grouping by `(t, rule)` first returns 50. The prev-snapshot query returns both rows and `dict()` keeps an arbitrary one.
- **#2** Readings Active at 20:00 and 21:00, off from 22:00; one ESTABLISHED flow with last packet 21:55 and `t_end` 7440 s later: `standby_activity` reported 1 connection and 2 MB in the off hours.
- **#3** From libnetfilter_conntrack's default printer, `delta-time` is `time(NULL) - start`; the fixture line (TIME_WAIT, `delta-time=360`) is consistent with 240 s of activity plus 120 s of TIME_WAIT. To confirm on the Pi without changing anything: `conntrack -E -e DESTROY -o timestamp,ktimestamp,extended` prints `[start=...]` next to the event time for one connection; compare `start` with the SYN time in the pcap.
- **#4** A flow to `1.2.3.4` was listed, then hidden by one answer `A:11.2.3.45`, and hidden by a hello to the address 300 days earlier. The token match keeps it listed and still explains `11.2.3.45`.
- **#5** `ingest.run` with every input path missing and a journal that raises `OSError`: six sources assessed, `not_assessed` empty, no warnings.
- **#6** By construction of `strftime` across a repeated local hour and tcpdump's `pcap_dump_open` (`fopen "wb"`); tcpdump's own source comments that `-G` rotates "on the first packet received after the specified number of seconds", not on a boundary.
- **#7** The production filter compiled with `tcpdump -d`: the IPv4 TCP branch keeps flags, first payload byte `0x16`, or port 80; the IPv6 branch keeps only port 80 and UDP. The 1-in-256 figure is arithmetic on uniform ciphertext bytes; the daily volume is a hypothesis to confirm with the sizes of pcaps written during a streaming hour. The tightened filter compiles (80 instructions).
- **#8** 1,051,200 synthetic `fw_counters` rows: current query 0.43 s (`SCAN c` with a correlated subquery); the reviewers' `(rule, t) IN (...)` form 0.061 s but still a full covering-index scan; a time-bounded form 0.002 s with an index on `t`. `host_detail` with one name on one address: 0.19 / 0.76 / 3.05 s for 2000 / 4000 / 8000 connections; under 0.01 s with `flows(dst, sport, t_end)`.
- **#9, #10** By code reading, and reproduced: `tls` emptied and refilled lost a brand-new name (`hosts` kept only the old one, watermark fell from 2 to 1); the fixture ingest gave `http_n = 3` for one GFTS request seen by both sensors; `option.livePlus = ERR TimeoutError x` landed in `tvsettings`; a line cut at `by` followed by the next event parsed as one flow with the first tuple and the second event's counters; both records in `test_malformed_dns_records_are_skipped_and_counted` parse cleanly, and the assertion's `or` passes either way.
- **Not verified here, flagged in the text:** JA3 field availability in the Pi's tshark (`tshark -G fields | grep -i ja3`), the UDP stream timeout of the Pi's kernel (`sysctl net.netfilter.nf_conntrack_udp_timeout_stream`), AdGuard's flush behavior, and the pcap leak volume.
