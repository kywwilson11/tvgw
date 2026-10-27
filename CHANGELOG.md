# Changelog

## Unreleased

Changes of 2026-10-26, after 0.1.0.

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

- The state directory is `root:adm` 2750, the database 640, the pairing key 600. The analyze unit is sandboxed with a timeout. The flow log is limited to the TV and uses a larger netlink buffer. tshark runs as `nobody`.

### Tests and CI

- Unit tests pinned to a frozen clock and time zone; the reviewer's test files adapted (321 tests at the time).
- Hardware suite additions: skips off the gateway; store integrity, idempotent re-ingest, ACR silence, must-allow never blocked, live capture and disk health, DHCP reservation, nginx binding, DNAT counters, `verify`, per-interface forwarding and the TV's route.
- CI: weekly mutation run, least-privilege permissions, cancel-in-progress, `make gate`, and a self-hosted hardware job that deploys to the Pi and runs the hardware suite on push to `main`.

### Documentation

- README rewritten. New: `docs/operations.md`, `docs/adding-a-profile.md`, `docs/incidents.md`, `docs/privacy-and-retention.md`.

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
