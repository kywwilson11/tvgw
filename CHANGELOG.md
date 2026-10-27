# Changelog

## Unreleased

Changes of 2026-10-26, after 0.1.0.

### Ingest and store: organizing the data (2026-10-27)

- The TV power history is tab-separated. webOS states contain spaces (`Active Standby`, `Screen Off`) and were split into power `Active` with an app of `Standby ...`; `unknown` now means the TV answered but the power read failed, `unreachable` that it did not answer. The old lines still read.
- Schema version 3: time indexes on `oddport` and `fw_counters`, `tls_dst` dropped (a prefix of `tls_conn`), the one index drop that lived in the schema moved into `_migrate`, and a new `ingest_runs` table with one row per run. A report's Coverage lists the warnings of the runs that fed its window instead of the last run's. Writers run `synchronous=FULL`.
- Tail sources commit every 10 000 lines together with their cursor, so a backlog neither fills memory nor holds the write lock for the whole run, and a run that dies loses only the batch in flight. The cheap sources are read first; tshark has a 20-minute budget per run and does not reassemble HTTP bodies; the analyze unit has `OOMScoreAdjust=500`.
- A source whose input is missing is a warning and `NOT ASSESSED` (the TV-state history excepted). `journalctl` failures surface instead of reading as a quiet port log, and the journal is read with `_TRANSPORT=kernel` rather than `-k`, which hid every line written before a reboot. An unreadable policy file warns. Lines the flow and URL-filter logs cannot parse are counted.
- The query-log parser is total and typed: a line that is not a record raises and is counted, oddly typed fields are coerced, so one record can no longer roll back the hour and every hour after it. `user_rules_from_yaml` returns None, not `[]`, for a file without a `user_rules` list, so it can no longer retire every rule in the history.
- The hosts watermark records its row's time and rebuilds when a table emptied and SQLite reused the ids; categories are recomputed only when the profile's rules change. `fw_counters` and `verify` are pruned under `DB_DAYS`, and the "Firewall held" line's previous-snapshot lookup is an index range per rule. `VACUUM` records its attempt first and runs only when a quarter of the file is free.
- Store only what the source says: LAN-API read errors are not settings, URL-filter rows carry no invented `GET`. Settings: integer fields parse by the default's type and `TV_IP` and `GW_IP` must be addresses. Names longer than DNS allows are not public names; pcap names and hosts are cut at 2000 characters.
- `tvgw-analyze` writes finished days and weeks once their evidence has settled (`SETTLE`, three hours), one rule for both loops. New tests pin the mutants that survived (the rollback in `step()`, the malformed count, the tvstate replace, `last_seen`, the store's file mode) and the DST reason for UTC pcap names.

### Capture: what leaves the TV and how we see it (2026-10-27)

- The capture keeps only frames the TV sends: SYN/FIN/RST, requests to port 80, UDP except QUIC short headers, a TCP segment only when it begins a TLS ClientHello record, and a segment that begins with an HTTP method (LG's :8080 firmware fallback). The old filter kept any segment whose first byte was 0x16, about one ciphertext segment in 256, and both directions of port 80 including response bodies. `tests/unit/test_capture_filter.py` runs the deployed expression through tcpdump on a synthetic hour.
- Pcap names are UTC with seconds (`tv-YYYYMMDDTHHMMSSZ.pcap`): local-time names repeat in the DST fall-back hour and tcpdump truncates a file whose name it has used before. `install.sh` restarts a capture unit only when its file changed; it never restarted `tvgw-pcap` at all.
- Which pcap tcpdump is writing is read from its open descriptors in `/proc` (`pcaps.py`), not from name order; when that cannot be told, ingest skips the pcaps and warns rather than read a half-written hour.
- `pcaps_done` records per file the error and the number of attempts: a file tshark cannot read is retried hourly for a day, then recorded as unreadable; one warning per run covers every failing file; a file too short to be a capture is recorded without running tshark. `syn443_rows` keeps the TV's connection attempts to :443, and a file with twenty or more of them and no hello raises a warning (the 2026-10-27 fault looked like twelve quiet hours).
- A connection attempt is counted once however often its SYN is retransmitted; a request to the gateway is stored once, from nginx's log, not again from the pcap.
- Pcap retention moved into the package: `tvgw prune-pcaps` (hourly) deletes only files ingest has read, never the live file, keeps and reports an un-read file until twice `PCAP_DAYS`, holds a 1 GB free-space floor, and exits 1 on any warning. `deploy/bin/tvgw-prune` is retired; `PCAP_DAYS` and `PCAP_MAX_GB` are validated settings.
- `tvgw-flowlog` honours `TV_IP` from the conf (systemd expands `${VAR}` in `ExecStart`; `$$` is the escape) and creates `flows.log` 640.
- conntrack lines that cannot be stored (NaN times, a counter past 64 bits, a nonsense duration) no longer roll the flows step back every hour; the module says what `t_start` and `t_end` are. tshark rows are framed on newline alone, must have exactly the documented fields, cap names at 255, and root without `setpriv` is refused. Log tailing reads identity, fingerprint and lines from one descriptor and warns when a rotation lost lines.
- Finished days and weeks are written from 03:20, once idle connections and the last pcap have landed.

### Fixes after the first day in production

- Profile note: LAN-API writes on webOS 5 firmware 04.64 are confirmed firmware-enforced read-only (the Luna bridge answers `isCallAllowed ... false` with the full manifest), so the TV's settings and saved Wi-Fi networks cannot be changed from the gateway.

- The unprivileged tshark could not open the pcaps once the state directory was closed (2026-10-27): tshark exits 2 for that as well as for "cut short", so twelve pcaps were marked done with zero rows. Exit 2 now counts as "cut short" only when tshark says so; pcaps are 640 root:nogroup; the hardware suite checks that finished pcaps yield rows while the TV is on.
- Log tailing keeps a fingerprint of each file's first bytes, so a copytruncate that regrew past the old offset is recognized instead of being read mid-line.
- TV readings are stamped in ISO form with the UTC offset, so November's repeated 01:20 cannot collapse two readings; the old form is still read.

### Reports from the store (legacy pipeline retired)

- `tvgw report` renders the brief over any window: `--day`, `--week YYYY-Www`, `--since/--until`, or the last 24 h. It adds the sections the legacy report still had over the brief: a by-category table (lookups, blocked, names, connections, bytes), plain-HTTP request groups, DNS the TV sent to other resolvers, and a by-day table for weeks.
- `tvgw-analyze` writes `reports/latest`, `reports/daily/<day>` and `reports/weekly/<week>` (text and JSON) from the store. `report.py`, `tvgw-extract`, the TSV archive and the `ARCHIVE_DAYS`/`REPORT_WINDOW` settings are gone; `install.sh` removes the derived files and moves pre-store reports to `reports/legacy/`. One tshark pass per pcap instead of two.

### Firewall and routing

- `tvgw-apply` is fail-closed. One apply runs at a time (lock). The ruleset loads atomically and forwarding is enabled last, so a bad rule file never leaves the TV forwarded without a filter. Stopping `tvgw.service` turns forwarding off on the TV interface first: the TV goes dark, not unfiltered.
- Fixed: after a restart the TV had no route, because `tvgw-apply` wrote only the global `ip_forward=1`, which the kernel copies to interfaces only when the value changes. The script now writes the per-interface switches for the TV interface and the uplink. Found by `tvgw verify` during the first deploy; see `docs/incidents.md`.
- New rules: invalid conntrack states dropped; GRE, ESP and 6in4 dropped; ICMP tunnels dropped (small pings allowed); DoQ alternate ports 784 and 8853 rejected; TV DNS aimed at other resolvers counted apart from DNS to the gateway; the TV may talk to the gateway address only; nothing unsolicited from the VPN side; the Pi's NetBIOS and SSDP chatter kept off the TV subnet; IPv6 dropped at the wire; LG's hardcoded firmware-fallback address logged.
- Idle TCP flows are reported after 2h04m instead of five days. `nftables.service` is masked so a `flush ruleset` can never wipe the rules.

### `tvgw verify`

- New command and a 10-minute timer (`tvgw verify --record`). Checks the ruleset and that it is unchanged since apply, forwarding, IPv6, the TV's route and policy rule, the VPN's DNAT counters, the DoH set, resolver rewrites and must-allow names, and the services. Stores the verdict and a snapshot of every firewall counter.

### Brief and store

- Red lines at the top: a must-allow name blocked, a clock host blocked or never looked up while the TV was on, failed `verify` checks, ingest warnings.
- New sections: coverage with `NOT ASSESSED`, firewall counters ("Firewall held"), clock hosts, traffic while the TV was off, private reverse lookups, LAN probes, unresolved flows, firmware changes with the names that followed, DNS oddities, allowed-but-unexpected names by category, and a `new domain` marker on new hosts.
- Rows are counted once (the hourly overlap used to double-count), flows are named by their own TLS hello, categories are recomputed every run, and "expected" names come from the profile's `expected_categories`. Schema version 2 adds indexes and the `lanprobe`, `verify` and `fw_counters` tables.
- Each ingest source commits on its own: a failing source is a warning, not a lost hour. Malformed query-log records are skipped and counted. Rule history retires rules only from a source that could be read.
- Fixed: the "Firewall held" line printed a label twice when two counters shared it.

### AdGuard Home

- `tvgw adguard apply` validates the candidate with `AdGuardHome --check-config`, writes atomically, and rolls back if the resolver stays silent. A YAML 1.2 loader keeps all-digit MACs as strings. Private reverse lookups are answered locally.

### Profile

- `lg-webos` gains `[[generations]]` (webOS 3 to 26, graded observed, community, spec or low), `[[hardware]]` (which model lines have a far-field microphone) and a `[checklist]` for audio and ACR. New command `tvgw profile [--model M] [--webos V] [--firmware F]` prints them with the must-allow list and the rules lint.
- The `@@` exceptions are generated from `[must_allow]`, the single source of truth. A lint refuses blocks over must-allow names, blocks at the apex of mixed zones, and exceptions above blocked names.
- The newer SDP hosts (`nextlgsdp.com`) are must-allow. Newer-generation ad and telemetry hosts, Samba and Nielsen ACR, `adstk`, ipify, and the Google TV audience-panel, Neustar and Chrome-ping hosts are blocked. Dead `xlgsmartad.com` dropped.
- Clock hosts are now the country SDP hosts only (`??.lgtvsdp.com`, `??.nextlgsdp.com`), because `rdx2.lgtvsdp.com` under the same zone is telemetry that we block and it raised a false red line. The query layer's pattern matching supports `?` and escapes `%` and `_`.
- Max (`max.com`, `discomax.com`, `h264.io`) is categorized as Streaming; its Telegraph event API and MediaMelon beacons as telemetry.

### Deployment

- The state directory is `root:adm` 2751 (traversable, not listable), the database 640, the pairing key 600. The analyze unit is sandboxed with a timeout. The flow log is limited to the TV and uses a larger netlink buffer. tshark runs as `nobody`.

### Tests and CI

- Unit tests pinned to a frozen clock and time zone; the reviewer's test files adapted (321 tests at the time).
- Hardware suite additions: skips off the gateway; store integrity, idempotent re-ingest, ACR silence, must-allow never blocked, live capture and disk health, DHCP reservation, nginx binding, DNAT counters, `verify`, per-interface forwarding and the TV's route.
- CI: weekly mutation run, least-privilege permissions, cancel-in-progress, `make gate`, and a self-hosted hardware job that deploys to the Pi and runs the hardware suite on push to `main`.

### Documentation

- README rewritten. New: `docs/operations.md`, `docs/adding-a-profile.md`, `docs/incidents.md`, `docs/privacy-and-retention.md`.
- Documentation pass (2026-10-27): new `docs/architecture.md`, `docs/design-decisions.md` and a README in every source, deploy and test directory; the runbook, profile guide, privacy page and incident log brought in line with the code (reports from the store, verify's per-interface forwarding check, pcap ownership, the pcap incident of 2026-10-27). Records the owner's decision to keep the TV on the direct uplink, not the VPN.

## 0.1.0 — 2026-10-26

First packaged release of what began as loose scripts on one Raspberry Pi gateway in front of an
LG CX.

- Package `tvgw` with pure parsers (conntrack, DNS messages, AdGuard query log, nginx URL-filter log,
  tshark rows, rotation-safe log tailing), TV profiles (TOML), a SQLite store with incremental
  ingest and rule history, a daily brief, and the `tvgw` CLI.
- `lg-webos` profile: categories, must-allow hosts, URL filter, and the AdGuard rules list that
  three days of capture produced.
- Deployment assets: nftables (`tvgw-apply`), dnsmasq template, systemd units, nginx URL filter and
  TLS passthrough, NetworkManager and logrotate configs, `install.sh`.
- Unit tests built from captured lines; mutation testing via mutmut; hardware tests for the live
  gateway.
- `tvgw adguard diff|apply`: AdGuard Home's blocklists, custom rules, upstreams, TV client entry and
  settings come from the profile and `tvgw.conf`; `install.sh` applies them, the hardware suite
  asserts no drift.
