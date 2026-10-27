# Hardware tests

`test_gateway.py` runs on the Pi against the live gateway: the real firewall, resolver, URL filter, services and store. Each test states one operational guarantee. They change nothing, except that one test runs `tvgw ingest` twice. They also send DNS queries to AdGuard and a few requests through nginx; those come from the Pi's own address, so the ingest ignores them.

## How to run

From a workstation:

```sh
make hardware PI=<ssh-host>
```

That runs, on the Pi:

```sh
cd /opt/tvgw/src && sudo /opt/tvgw-venv/bin/python -m pytest -m hardware tests/hardware -q -p no:cacheprovider
```

The suite needs root, `nft` on the path, and `/etc/tvgw/tvgw.conf`. Without root or `nft` the whole module is skipped, so it is harmless on a laptop. A missing settings file is an error, not a skip, because the defaults would make every check meaningless. `install.sh` installs `pytest` into the venv for this.

## What each test guarantees

| Test | Guarantee | Skips when |
|---|---|---|
| `test_service_active` (6 cases) | `tvgw`, `tvgw-flowlog`, `tvgw-pcap`, AdGuard Home, dnsmasq and nginx are running. | |
| `test_timer_scheduled` (4 cases) | The analyze, prune, DoH-update and verify timers each have a next run. | |
| `test_firewall_table_and_key_rules_present` | `inet tvgw` holds the DNS DNAT, DoT/DoQ reject, invalid drop, tunnel drop, bypass counter, Pi-chatter drop, QUIC reject, DoH and LAN sets, and masquerade. | |
| `test_doh_bootstrap_ips_are_in_the_block_set` | 8.8.8.8, 8.8.4.4, 1.1.1.1, 1.0.0.1 and 9.9.9.9 are in `doh4`. | |
| `test_blocked_names_resolve_to_zero` | Three known LG tracking names resolve to `0.0.0.0`. | |
| `test_must_allow_names_resolve` | Every must-allow name resolves to a real address. | |
| `test_url_filter_names_point_at_the_gateway` | Each URL-filter host resolves to the gateway. | no `[url_filter]` |
| `test_nginx_filter_regex_matches_the_profile` | The installed nginx file contains the profile's `block_regex`. | no `[url_filter]` |
| `test_url_filter_blocks_and_passes` | An ACR and an LG Shopping URL get 403; an app icon gets 200. | no `[url_filter]` |
| `test_tls_passthrough_reaches_the_real_host` | HTTPS to `gfts.lge.com` through the Pi reaches the real host with a valid certificate. | |
| `test_store_is_fresh_sound_and_at_the_current_schema` | Ingest ran in the last two hours, `quick_check` is ok, the schema version is current, the last run had no warnings. | |
| `test_ingest_twice_adds_nothing_the_second_time` | Ingest is idempotent: an immediate second run adds no rows. | |
| `test_no_acr_name_answered_and_no_traffic_to_its_addresses_in_24h` | No `ACR`-category name was answered in the last day, and no flow went to an address seen with an ACR name. | |
| `test_must_allow_names_were_never_blocked_since_the_exceptions_were_applied` | No must-allow name came back blocked in the last day, counted from when the current exceptions appeared. | |
| `test_capture_is_live_and_the_disk_is_healthy` | With the TV on, a pcap was written in the last two hours; over 2 GB free; no disk I/O errors in the kernel log for the last hour. | |
| `test_tv_has_its_dhcp_reservation_and_acr_is_off_in_the_store` | dnsmasq pins the TV's MAC to its address, and the latest stored Live Plus reading is `off`. | no LAN-API reading stored |
| `test_nginx_listens_only_on_the_tv_facing_address` | Every listener on 80 and 443 is bound to `10.10.10.1`. | |
| `test_dns_redirect_counters_tick_while_the_tv_is_on` | The `pre_nat` counters are above zero. | TV not on in the last day, or the ruleset was applied under an hour ago |
| `test_adguard_matches_profile_and_settings` | `tvgw adguard diff` exits 0: no drift. | |
| `test_tv_isolated_from_lan_counters_exist` | The home-LAN drop rule is in `tv_out`. | |
| `test_reports_are_written_from_the_store` | `reports/latest.txt` is under two hours old and has Coverage and By category; yesterday's daily report exists when the store reaches back that far and it is past 03:20 (finished days are written then, once idle connections and the last pcap have landed); the retired pipeline is gone. | |
| `test_verify_passes_on_the_live_gateway` | `tvgw verify` exits 0 with no FAIL. | |
| `test_ipv6_guard_and_fail_closed_state` | The IPv6 drop is loaded; `ip_forward` and the per-interface forwarding of `eth0` and the uplink are 1. | |
| `test_tv_has_a_route_out` | A packet from the TV's address on its interface routes out the uplink or `tun0`; `nftables.service` is masked. | |
| `test_state_is_not_world_readable` | The state directory, store, logs, pcap directory and pcaps are not world-readable; the pairing key is 600. | |
| `test_finished_pcaps_yield_rows_while_the_tv_is_on` | A recent finished pcap that ingest read without error produced TLS rows, so the unprivileged tshark can read the files. | no finished pcap in four hours, or the TV not on |
| `test_tv_lan_api_reachable_or_asleep` | Informational: when the TV answers its LAN API, Live Plus is off. | TV unreachable |

Several of these are the regression tests for [incidents](../../docs/incidents.md): the per-interface forwarding and route checks, and the pcap-rows check.

## The self-hosted runner

CI's `hardware` job runs on a GitHub Actions runner installed on the Pi, labelled `self-hosted` and `tvgw`. On every push to `main` that touches more than Markdown, after the unit tests pass, it rsyncs the checkout to `/opt/tvgw/src` as root (earlier runs leave root-owned `__pycache__` there), runs `install.sh` (which now ends with `tvgw verify`, so a FAIL fails the deploy step before the suite runs), and runs the suite with `PYTHONDONTWRITEBYTECODE=1` as the only variable handed to root. The job times out after 90 minutes: a first analyze run can take up to 45 and the suite runs ingest twice. A running deploy is never cancelled by a newer push; the newer one queues. A push to `main` is therefore a deploy.

## Writing a new hardware test

- Read, never write. If a check needs a change to the system, it belongs in `install.sh` or `tvgw verify`, not here.
- Name the test after the guarantee, and put the reason in the assertion message.
- Skip with a reason when the precondition is outside our control (the TV is off, nothing captured yet), and fail when it is ours.
- Keep vendor-specific names in the profile where you can. Tests that hardcode LG names are listed in [../../docs/adding-a-profile.md](../../docs/adding-a-profile.md#hardware-tests).
