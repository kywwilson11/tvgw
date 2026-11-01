# Hardware tests

This folder holds the suite that runs as root on the Pi against the live gateway: the real firewall, resolver, URL filter, services and store. It runs from `make hardware` and from CI's `hardware` job after every deploy. The kinds of tests, and when each runs, are in [the tests overview](../README.md).

## Files

| File | What it is | Used by |
|---|---|---|
| `test_gateway.py` | The suite, marked `hardware`; it skips itself off the gateway. | `make hardware`, and CI's `hardware` job ([how a change reaches the gateway](../../deploy/README.md#how-a-change-reaches-the-gateway)) |

## How to run

On your workstation:

```sh
make hardware PI=<ssh-host>
```

`make hardware` runs this command on the Pi, under the install lock (`flock -w 600 /run/tvgw/install.lock`), so no deploy replaces `/opt/tvgw/src` while the suite runs; a deploy waits for it, and it waits up to 10 minutes for a deploy. The same command runs the suite by hand.

On the Pi:

```sh
cd /opt/tvgw/src && sudo flock -w 600 /run/tvgw/install.lock /opt/tvgw-venv/bin/python -m pytest -m hardware tests/hardware -q -p no:cacheprovider
```

CI's `hardware` job runs the suite as the last command of `sudo deploy/sync-install.sh`, after the rsync into `/opt/tvgw/src` and `install.sh`, all under that lock, with `PYTHONDONTWRITEBYTECODE=1` as the only variable handed to root ([how a change reaches the gateway](../../deploy/README.md#how-a-change-reaches-the-gateway)). A `make deploy` therefore cannot replace the tree the suite is checking.

The module checks its preconditions when it is imported:

- Without root or without `nft` on the path, the whole module is skipped, so it is harmless on a workstation.
- Without `/etc/tvgw/tvgw.conf` it fails with an error, not a skip, because the defaults would make every check meaningless.
- It loads the settings and the configured profile once, as `S` and `PROF`.

`install.sh` installs pytest into the virtualenv for this. The suite reads far more than it changes, but it does run these:

- `tvgw ingest`, twice, with 900 seconds (15 minutes) allowed for each.
- `tvgw analyst --dry-run --day <yesterday>`, which writes the pack and the prompt under `reports/proposals/` and sends nothing.
- `tvgw autoblock check --no-watch`, the same hourly judgement the timer runs without the armed canary, which may revert a rule the gateway added but never reads the TV or reverts from a watch. A full check with an armed canary can run 11 to over 15 minutes, past the test's 900 seconds; the timer's check runs it, and while the timer's check holds the autonomy's lock the suite's check exits 0 having judged nothing.
- DNS queries to AdGuard Home and requests through nginx from the Pi's own address, which the ingest does not store.

## What each test guarantees

The tests in file order. A test with a list in brackets runs once per item.

| Test | Guarantee | Skips when |
|---|---|---|
| `test_service_active[unit]` | `tvgw`, `tvgw-flowlog`, the capture unit `CAPTURE_MODE` picks (`tvgw-pcap` or `tvgw-pcap-headers`), `AdGuardHome`, `dnsmasq` and `nginx` are active. | never |
| `test_unit_enabled[unit]` | Every unit in `ENABLED` (`tvgw.service`, `tvgw-flowlog`, `tvgw-pcap`, `tvgw-dnsgate` and the eight timers) is `enabled`, so it comes back at boot. | never |
| `test_installed_file_matches_the_checkout[source]` | Every file in `INSTALLED` is byte-equal to the checkout: `tvgw-apply`, `tvgw-analyze`, `tvgw-doh-update`, both NetworkManager files, the logrotate file, `doh-exclude.txt`, and every unit and timer. | never |
| `test_generated_configs_match_the_templates` | `/etc/dnsmasq.d/tvgw.conf` is the template with this gateway's `TV_MAC`, `TV_IP` and `TV_NAME` and its TV side (`TV_IF`, `GW_IP`, and the pool and netmask `config.tv_side` derives from `TV_NET`); both nginx files are their templates with `URL_FILTER_RESOLVER`, or `1.1.1.1` when it is unset, and `GW_IP`; `/etc/NetworkManager/conf.d/90-tvgw.conf` is its template with `TV_IF`; the capture's drop-in `tvgw-pcap.service.d/tv-side.conf` names this gateway's `TV_IF`, `TV_NET` and `GW_IP`. | never |
| `test_tv_lan_is_where_the_settings_put_the_tv_side` | `nmcli` reports `tv-lan` on `TV_IF` with `GW_IP/<prefix>`, exactly as `install.sh` compares them, and the last apply recorded the same `TV_IF`, `TV_NET` and `GW_IP`. | never |
| `test_stock_nftables_service_is_masked` | `nftables.service` is masked, so its `flush ruleset` can never run. | never |
| `test_timer_scheduled[timer]` | The analyze, prune, DoH-update, verify, backup, analyst and weekly analyst timers each have a next run. | never |
| `test_firewall_table_and_key_rules_present` | `inet tvgw` holds every needle in `KEY_RULES`: the DNS DNAT to `10.10.10.1:53`, the DoT and DoQ ports, `ct state invalid`, the tunnel drop, the DNS bypass counter, the Pi-chatter drop, `udp dport 443`, `@doh4`, `@lan4` and `masquerade`. It requires the QUIC reject whatever `BLOCK_QUIC` says. | never |
| `test_the_adtech_port_wall_is_loaded_as_the_settings_say` | (acr) With `ADTECH_PORT_WALL=yes`, `tv_out` holds the `LG adtech port` reset and the `tvgw-adport` log sample, before the odd-port log; with `no`, neither. | never |
| `test_doh_bootstrap_ips_are_in_the_block_set` | `8.8.8.8`, `8.8.4.4`, `1.1.1.1`, `1.0.0.1` and `9.9.9.9` are in `doh4`. | never |
| `test_blocked_names_resolve_to_zero` | `alphonso.tv`, `www.ueiwsp.com` and `us.rdx2.lgtvsdp.com` resolve to `0.0.0.0`. | never |
| `test_must_allow_names_resolve` | Every must-allow host resolves to an address other than `0.0.0.0`. | never |
| `test_url_filter_names_point_at_the_gateway` | Each URL-filter host resolves to exactly `GW_IP`. | the profile has no `[url_filter]` |
| `test_nginx_filter_regex_matches_the_profile` | The installed `tvgw-gfts.conf` contains the profile's `block_regex`. | the profile has no `[url_filter]` |
| `test_url_filter_blocks_and_passes` | An ACR and an LG Shopping URL get 403 and an app icon gets 200. | the profile has no `[url_filter]` |
| `test_tls_passthrough_reaches_the_real_host` | HTTPS to `gfts.lge.com` through the gateway reaches the real host with a certificate that verifies. | never |
| `test_store_is_fresh_sound_and_at_the_current_schema` | Ingest ran in the last 2 hours, `quick_check` is `ok`, the schema version is current, and the last run had no warnings. | never |
| `test_ingest_twice_duplicates_nothing` | A second ingest stores no event the first already had, judged per table by natural key (`NATURAL_KEYS`) against the rows present before it, and leaves the rule history unchanged. Raw counts could not say this while conntrack and the query log keep arriving. | never |
| `test_no_acr_name_answered_and_no_traffic_to_its_addresses_in_24h` | No name in the `ACR` category was answered in the last day, and no flow went to an address seen with one. | never; it checks nothing without an `ACR` category |
| `test_must_allow_names_were_never_blocked_since_the_exceptions_were_applied` | No must-allow host came back blocked in the last day, counted from when the newest `@@` rule appeared. | never |
| `test_capture_is_live_and_the_disk_is_healthy` | When the latest reading says `Active`, a pcap that holds a packet (larger than its 24-byte header, which dumpcap writes every hour regardless) was written in the last 2 hours; over 2 GB is free where the store lives; the kernel logged no disk I/O error in the last hour. | never |
| `test_tv_has_its_dhcp_reservation_and_acr_is_off_in_the_store` | dnsmasq pins `TV_MAC` to `TV_IP`, and the latest stored Live Plus reading is `off`. | no LAN-API reading is stored, after the DHCP half has run |
| `test_nginx_listens_only_on_the_tv_facing_address` | nginx listens on 80 and 443, and every such listener is bound to `GW_IP`. | never |
| `test_dns_chain_counted_packets_while_the_tv_was_on` | The stored counter snapshots for the last day show TV DNS reaching the gateway, and a series for the DNS bypass counter. The live counters cannot say this, because the install re-applies the firewall and zeroes them seconds before. | the TV had no `Active` reading in the last day |
| `test_adguard_matches_profile_and_settings` | `tvgw adguard diff` exits 0: no drift. | never |
| `test_tv_isolated_from_lan_counters_exist` | `tv_out` holds the home-LAN drop. | never |
| `test_reports_are_written_from_the_store` | `reports/latest.txt` is under 2 hours old and has Coverage and By category; yesterday's daily report exists once it is past 03:20 and the store reaches back that far; the retired pipeline is gone. | never |
| `test_verify_passes_on_the_live_gateway` | `tvgw verify` exits 0 and prints no `FAIL`. | never |
| `test_doh_list_is_current` | `doh4.txt` exists, was replaced within 8 days and has at least 50 entries. | never |
| `test_ipv6_guard_and_fail_closed_state` | The IPv6 wire drop is loaded, and `ip_forward` and the `forwarding` switches of `eth0` and `WAN_IF` are 1. | never |
| `test_tv_has_a_route_out` | A packet from `TV_IP` entering on `eth0` routes out `WAN_IF` in direct mode, or `tun0` in vpn mode. | never |
| `test_state_is_not_world_readable` | The settings file, the state directory and every file in it, the store, the logs, the pcap directory and the pcaps are not world-readable; the pairing key is 600; no staged DoH list was left behind. | never |
| `test_pcaps_are_readable_by_the_extractor_and_owned_by_the_capture_user` | The newest pcap is owned by `tvgw-pcap`, and `nobody:nogroup` can read it and cannot write it. | never |
| `test_finished_pcaps_yield_rows_while_the_tv_is_on` | Of the three newest pcaps read without error in the last 4 hours, at least one yielded TLS rows, so the unprivileged tshark can read the files. (extractor) It fails, not skips, when every pcap read in those 4 hours carries an error. | no pcap read without error in the last 4 hours, or no `Active` reading in them |
| `test_the_sandboxed_tshark_reads_the_newest_finished_pcap` | (extractor) `tvgw.tshark.extract` on the newest pcap the capture has finished, through the real `systemd-run` sandbox and its `HARDENING` properties, does not fail; when the store read named hellos from that file, it finds at least one. A property the Pi's systemd or kernel refuses fails here at deploy, not silently in the hourly ingest. | no finished pcap with a capture header |
| `test_tv_lan_api_reachable_or_asleep` | When the TV answers the LG LAN API, Live Plus is off. | the TV does not answer |
| `test_backup_copy_is_fresh_and_sound` | The newest copy in `backup/` is under 36 hours old, mode 640 and owned by root, passes `quick_check` and holds DNS rows. | never |
| `test_capture_runs_as_the_capture_user_with_two_capabilities` | The capture unit `CAPTURE_MODE` picks runs as `tvgw-pcap` with exactly `CAP_NET_RAW` and `CAP_NET_ADMIN` in its bounding set. | never |
| `test_exactly_one_capture_runs_and_it_is_dumpcap` | The capture unit `CAPTURE_MODE` picks runs dumpcap, the other is not active, and the capture holds at most one pcap open. | never |
| `test_the_headers_capture_table_is_loaded_in_headers_mode_only` | `inet tvgw_capture` holds the capture rule with `CAPTURE_MODE=headers` and is absent with `full`. | never |
| `test_dns_gate_table_set_rule_and_feeder_are_in_place` | `inet tvgw_gate` holds the set and the counting rule, and `tvgw-dnsgate` is active. When the two latest readings say `Active` and the feeder has run for over 900 seconds (15 minutes), the set is not empty. | `DNSGATE=off` |
| `test_analyst_dry_run_pack_carries_no_home_identifier` | The pack `tvgw analyst --dry-run` builds from the live store holds no `TV_MAC`, no TV-subnet or home-LAN address prefix, not the Pi's host name, not `TV_NAME`, and no ZIP code or device name the store holds; it packs yesterday and the day each of those values was first read, and each pack is not world-readable. | never |
| `test_analyst_timer_follows_the_conf_schedule` | `tvgw-analyst.timer` shows the calendar `install.sh` rendered from `ANALYST_SCHEDULE`. | never |
| `test_autoblock_file_record_and_resolver_tell_one_story` | Every line of `AUTO_RULES` passes the lint beside the profile, and the store's active machine rules are exactly those lines. `tvgw autoblock check --no-watch` and `tvgw autoblock list` exit 0. With `ANALYST_APPLY=auto` the verifier model is not the proposer. The three analyst and autoblock unit files make `/opt/AdGuardHome` writable. | never |
| `test_the_guard_is_loaded_enabled_and_cannot_be_stopped` | (guard) `inet tvgw_guard` holds its input, forward and output chains at `filter + 10` and its final input drop; `tvgw-guard.service` is enabled with `RefuseManualStop=yes`; `/etc/tvgw/guard.nft` names `TV_IF` ([design decision 42](../../docs/design-decisions.md#42-guard-the-pi-is-closed-to-the-tv-whatever-nftables-holds)). Read-only. | never |
| `test_cotenant_ip_filters_are_attached_to_their_running_cgroups` | (guard) Each active co-tenant whose `IPAddressDeny` covers `TV_NET` has an ingress and an egress program attached to its own cgroup (`bpftool cgroup show`), which is the check that `install.sh`'s `daemon-reload` applied the filter without a restart. Read-only. | without `bpftool`, with no co-tenant listed, or with none carrying the filter yet |

Several of these are the regression tests for [incidents](../../docs/incidents.md): the per-interface forwarding and route checks, and the pcap ownership and rows checks.

Two edits each fail one test, a quick check that the suite still bites: a single changed byte in `/usr/local/sbin/tvgw-apply` fails `test_installed_file_matches_the_checkout[deploy/nftables/tvgw-apply]`, and `systemctl disable tvgw-pcap` fails `test_unit_enabled[tvgw-pcap.service]`. Restore each straight after.

## Writing a new hardware test

- Read, and change nothing you can avoid changing. A check that needs a change to the system belongs in `install.sh` or `tvgw verify`, not here.
- Name the test after the guarantee, and put the reason in the assertion message.
- Skip, with the reason, when the precondition is outside the gateway's control, such as the TV being off; fail when it is the gateway's own.
- Use the module's helpers: `S` and `PROF` for the settings and the profile, `sh()` for a command with a 60-second timeout, `dns_a()` for a lookup through the gateway's resolver, and `_store()` for a read-only connection to the store.
- Keep `INSTALLED` and `KEY_RULES` as module-level literals: `tests/unit/test_deploy_lint.py` parses them with `ast.literal_eval`, because it cannot import a module that skips itself off the gateway.
- A file `install.sh` copies byte for byte goes in `INSTALLED`, and a unit that must run goes in `ENABLED`.
- Keep vendor names in the profile where you can. The tests that hardcode LG names are listed in [adding a profile](../../docs/adding-a-profile.md#tests).
