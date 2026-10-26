# Changelog

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
