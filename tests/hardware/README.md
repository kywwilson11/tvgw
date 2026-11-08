# Hardware tests

This folder holds the suite that runs as root on a gateway against what is live there: the real firewall, resolver, URL filter, services and store. It runs from `make hardware` and from CI's `hardware` job after every deploy. The kinds of tests, and when each runs, are in [the tests overview](../README.md).

## Files

| File | What it is | Used by |
|---|---|---|
| `test_gateway.py` | The suite, marked `hardware`; it skips itself off the gateway. | `make hardware`, and CI's `hardware` job ([how a change reaches the gateway](../../deploy/README.md#how-a-change-reaches-the-gateway)) |

## How to run

On your workstation:

```sh
make hardware PI=<ssh-host>
```

`make hardware` runs this command on the gateway, under the install lock (`flock -w 600 /run/tvgw/install.lock`), so no deploy replaces `/opt/tvgw/src` while the suite runs; a deploy waits for it, and it waits up to 10 minutes for a deploy. The same command runs the suite by hand.

On the gateway:

```sh
cd /opt/tvgw/src && sudo flock -w 600 /run/tvgw/install.lock /opt/tvgw-venv/bin/python -m pytest -m hardware tests/hardware -q -p no:cacheprovider
```

CI's `hardware` job runs the suite as the last command of `sudo deploy/sync-install.sh`, after the rsync into `/opt/tvgw/src` and `install.sh`, all under that lock, with `PYTHONDONTWRITEBYTECODE=1` and `PYTHONUTF8=1` the only variables handed to root, and everything it prints piped through the scrubber ([how a change reaches the gateway](../../deploy/README.md#how-a-change-reaches-the-gateway)). A deploy deferred to the quiet window runs the install and the suite once its run's wait reaches the window; a run that hands the wait over, or gives it up, runs neither ([the quiet window](../../deploy/README.md#the-quiet-window)). A `make deploy` therefore cannot replace the tree the suite is checking.

The module checks its preconditions when it is imported:

- Without root or without `nft` on the path, the whole module is skipped, so it is harmless on a workstation.
- Without `/etc/tvgw/tvgw.conf` it fails with an error, not a skip, because the defaults would make every check meaningless.
- It loads the settings and the configured profile once, as `S` and `PROF`.

`install.sh` installs pytest into the virtualenv for this. The suite reads far more than it changes, but it does run these:

- `tvgw ingest`, twice, with 900 seconds (15 minutes) allowed for each.
- `tvgw analyst --dry-run --day <yesterday>`, which writes the pack and the prompt under `reports/proposals/` and sends nothing.
- `tvgw autoblock check --no-watch`, the same hourly judgement the timer runs without the armed canary, which may revert a rule the gateway added but never reads the TV or reverts from a watch. A full check with an armed canary can run 11 to over 15 minutes, past the test's 900 seconds; the timer's check runs it, and while the timer's check holds the autonomy's lock the suite's check exits 0 having judged nothing.
- DNS queries to AdGuard Home and requests through nginx from the gateway's own address, which the ingest does not store.

## What each test guarantees

The tests in file order. A test with a list in brackets runs once per item.

| Test | Guarantee | Skips when |
|---|---|---|
| `test_service_active[unit]` | `tvgw`, `tvgw-flowlog`, the capture unit `CAPTURE_MODE` picks (`tvgw-pcap` or `tvgw-pcap-headers`), `AdGuardHome`, `dnsmasq` and `nginx` are active. | never |
| `test_unit_enabled[unit]` | Every unit in `ENABLED` (`tvgw.service`, `tvgw-flowlog`, `tvgw-pcap`, `tvgw-dnsgate`, `tvgw-tvlive`, (reliability) `tvgw-vpnseal` and the nine timers, (threats) `tvgw-threat-update.timer` among them) is `enabled`, so it comes back at boot. | never |
| `test_installed_file_matches_the_checkout[source]` | Every file in `INSTALLED` is byte-equal to the checkout: `tvgw-apply`, `tvgw-analyze`, `tvgw-doh-update`, both NetworkManager files, the logrotate file, `doh-exclude.txt`, and every unit and timer. | never |
| `test_generated_configs_match_the_templates` | `/etc/dnsmasq.d/tvgw.conf` is the template with this gateway's `TV_MAC`, `TV_IP` and `TV_NAME` and its TV side (`TV_IF`, `GW_IP`, and the pool and netmask `config.tv_side` derives from `TV_NET`); both nginx files are their templates with `URL_FILTER_RESOLVER`, or `1.1.1.1` when it is unset, and `GW_IP`; `/etc/NetworkManager/conf.d/90-tvgw.conf` is its template with `TV_IF`; the capture's drop-in `tvgw-pcap.service.d/tv-side.conf` names this gateway's `TV_IF`, `TV_NET` and `GW_IP`. | never |
| `test_table_100_routes_by_the_router_wan_gw_mode_names` | (uplink) With `WAN_GW_MODE` literal (absent on the reference) table 100's default goes via the settings file's `WAN_GW`; in either mode it is the `WAN_GW_USED` the last apply recorded, when recorded. Prints no address. | `UPLINK=vpn`, or no default in table 100 (the uplink down) |
| `test_tv_lan_is_where_the_settings_put_the_tv_side` | `nmcli` reports `tv-lan` on `TV_IF` with `GW_IP/<prefix>`, exactly as `install.sh` compares them, and the last apply recorded the same `TV_IF`, `TV_NET` and `GW_IP`. | never |
| `test_stock_nftables_service_is_masked` | `nftables.service` is masked, so its `flush ruleset` can never run. | never |
| `test_timer_scheduled[timer]` | The analyze, prune, DoH-update, verify, backup, analyst and weekly analyst timers each have a next run. | never |
| `test_firewall_table_and_key_rules_present` | `inet tvgw` holds every needle in `KEY_RULES`: the DNS DNAT to `10.10.10.1:53`, the DoT and DoQ ports, `ct state invalid`, the tunnel drop, the DNS bypass counter, the gateway-chatter drop, `udp dport 443`, `@doh4`, `@lan4` and `masquerade`. It requires the QUIC reject whatever `BLOCK_QUIC` says. | never |
| `test_the_adtech_port_wall_is_loaded_as_the_settings_say` | (acr) With `ADTECH_PORT_WALL=yes` and `PROFILE=lg-webos`, `tv_out` holds the `LG adtech port` reset and the `tvgw-adport` log sample, before the odd-port log; with `no`, or another profile, neither. | never |
| `test_the_settings_file_names_the_lg_profile_itself` | (profile) `/etc/tvgw/tvgw.conf` names `PROFILE=lg-webos` itself, and that is the profile loaded: the reference never runs on the default for an absent key or on the template's general profile ([design decision 62](../../docs/design-decisions.md#62-a-tv-gets-a-vendor-profile-only-on-evidence-or-its-owners-answer-otherwise-the-general-profile-which-isolates-records-briefs-and-blocks-only-shared-lists)). Read-only. | never |
| `test_the_last_apply_recorded_the_profile_it_applied` | (profile) `/run/tvgw/settings.applied` names `PROFILE=lg-webos`, the settings' profile, and the wall switch the settings give. | never |
| `test_doh_bootstrap_ips_are_in_the_block_set` | `8.8.8.8`, `8.8.4.4`, `1.1.1.1`, `1.0.0.1` and `9.9.9.9` are in `doh4`. | never |
| `test_blocked_names_resolve_to_zero` | `alphonso.tv`, `www.ueiwsp.com` and `us.rdx2.lgtvsdp.com` resolve to `0.0.0.0`. | never |
| `test_must_allow_names_resolve` | Every must-allow host resolves to an address other than `0.0.0.0`. | never |
| `test_url_filter_names_point_at_the_gateway` | Each URL-filter host resolves to exactly `GW_IP`. | the profile has no `[url_filter]` |
| `test_the_probes_rules_are_loaded_exactly_when_the_probe_is_on_and_record_nothing` | (probe) With `TV_PROBE=off` nothing of the probe is in `inet tvgw`; with it on, the three probe chains are there, no rule of theirs has a counter or a comment, the two the probe's packets enter by take no source but `TV_PROBE_IP` and end in a drop, and nothing of the probe (interface, route) is left between runs. Read-only. | never |
| `test_the_probe_passes_or_cannot_tell_and_moves_no_counter_it_can_reach` | (probe) NOT READ-ONLY with the probe on: runs `tvgw probe` as the 10-minute check does (a namespace and a pair for a few seconds, lookups at the resolver, one TLS handshake with the neutral target when one is due). Pass, or unknown while the uplink is down, never fail; with the TV silent no wall counter moved; a stored verdict has the four keys. | `TV_PROBE` is off |
| `test_a_transient_restore_timer_can_be_armed_and_stopped` | (probe) `systemd-run --on-active` arms a timer under a test name of its own with `/bin/true` as its payload, `list-timers` shows it, and `systemctl stop` removes it: the mechanism `tvgw-apply` arms a restore with. It starts and stops one transient unit and changes nothing else. | no systemd |
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
| `test_site_rules_are_absent_or_every_line_reaches_the_plan` | (site rules) `LOCAL_RULES` is absent and the plan's site group empty, or it is root's and `640` and every line passes the lint. Prints counts, never a rule. | never |
| `test_activity_calibrate_runs_and_says_whether_it_is_met` | (activity) `tvgw activity calibrate --json` exits 0 with both shares and a boolean verdict; it prints the verdict alone. | never |
| `test_the_upload_budget_is_set_once_or_waits_and_caps_nothing` | (budget) `meta.upload_budget` is there, of this rule, measure and profile: `pending`, or `fixed` over 14 covered days still in the store with the rule's ceiling (`ceiling_for()` its largest clean destination-hour's net: twice it, between the floor and the cap) from 14 whole local days that ended at least `SETTLE` before it was set; yesterday's report judges against the source it names, lists only hours whose net is over the ceiling, and, unless the owner set it, leaves the quietest published ACR hour twice over it; `inet tvgw` holds no `quota`. Read-only; it prints the state and the source alone. | no ingest has run since the code was installed (no row yet) |
| `test_the_threat_lists_are_fresh_and_tvgw_threats_reads_the_record` | (threats) With `THREAT_LISTS=count`, every list `THREAT_LIST_URLS` names has a copy, the newest under 8 days old (`threats.STALE_DAYS`), and `tvgw threats 1d` exits 0. It prints the number of copies, of names and of lines, never a name. | with `THREAT_LISTS=off`, or before the first download |
| `test_the_while_off_line_names_only_what_it_counts` | (tripwire) Yesterday's While off or asleep names appear exactly when the line counts a lookup or a connection, and never more of either than it counts. Read-only; it prints only whether the TV went online while off. | never |
| `test_adguard_is_tvgws_by_its_content` | (adguard) `aghinstall.state()` is `tvgw`: the marker, or the TV's client entry or the profile's must-allow exceptions in `AdGuardHome.yaml`, with the binary at the floor ([whose AdGuard it is](../../docs/how-it-works/adguard.md#whose-adguard-it-is)). Read-only. | never |
| `test_the_adguard_drop_in_follows_adguard_listen` | (adguard) `AdGuardHome.service.d/workdir.conf` is `adguardcfg.workdir_dropin()` for `ADGUARD_LISTEN`; with `keep` (the key absent) it is `WorkingDirectory=/opt/AdGuardHome` alone and the plan owns no listen address ([the listen setting](../../docs/how-it-works/adguard.md#the-listen-setting)). Read-only. | never |
| `test_tv_isolated_from_lan_counters_exist` | `tv_out` holds the home-LAN drop. | never |
| `test_reports_are_written_from_the_store` | `reports/latest.txt` is under 2 hours old and has Coverage and By category; yesterday's daily report exists once it is past 03:20 and the store reaches back that far; the retired pipeline is gone. | never |
| `test_the_brief_keeps_its_form_until_brief_style_is_set` | (plain) With `BRIEF_STYLE` absent or `full`, `tvgw brief` and the newest daily report start with the engineering brief's `=== ` line, no plain block; `reports/action.txt`, once written, is closed to others and holds at most one `act` or `doctor` line. | when the gateway set `BRIEF_STYLE=plain` |
| `test_the_uplink_tag_is_keyed_and_holds_no_address` | (plain) Every `gw_samples.wan_addr_tag` is the key id, the address tag and the router tag in hex, never an address, and `/var/lib/tvgw/name-keys/wan.salt` is root's and `600`. | until a sample carries the tag |
| `test_the_gateway_samples_its_own_health` | (reliability) Once a sample carries the health columns (schema 14), the newest such sample is under 20 minutes old and holds `soc_temp` between 0 and 150, the record's disk and its write counter, and, where `vcgencmd` exists, the throttle flags. | `LEDGER=off`, or until a sample carries the columns |
| `test_the_seal_table_is_there_only_when_the_setting_asks_for_it` | (reliability) `inet tvgw_seal` is absent unless `VPN_DNS_SEAL=on` with a VPN, and then holds the seal's one rule, naming neither `TV_IF` nor port 443. | never |
| `test_verify_passes_on_the_live_gateway` | `tvgw verify` exits 0 and prints no `FAIL`. | never |
| `test_verify_leaves_its_verdict_by_check_name_in_the_status_file` | (plain) A `tvgw verify --json` run leaves `/run/tvgw/status.txt` root's and `644`, one line from that run on: `ok <epoch> <n>` with its count of checks, or `fail <epoch>` and the names of the checks that failed. | never |
| `test_verify_prints_no_home_identifier` | (deploy window) No detail of `tvgw verify --json` holds a private address outside `TV_NET`, a MAC, an `enx` or `wlx` name, or the gateway's host name. It counts what it finds and never prints it. | never |
| `test_the_quiet_check_prints_one_line_that_agrees_with_its_exit` | (deploy window) `tvgw tv quiet --wait 0` exits 0 printing exactly `deploy: now`, or 1 printing exactly `deploy: deferred`, and nothing on stderr. | never |
| `test_the_new_checks_log_their_verdicts_and_none_fails_on_the_reference` | (depth) Each check of the gateway's blind spots (`verify.FAIL_AFTER`: `disk`, `clock_synced`, `store_backup`, `ingest_fresh`, `uplink_ipv4`, `wan_gateway` in direct mode, `forward_policy`, `input_policy`, `tv_port_neighbours`) runs and is not a FAIL. Its verdict goes to the job's log by name and level only, with `(FAIL level, held)` for a finding held at WARN while the check is new, and never its detail. | never |
| `test_the_memory_the_filter_and_the_hourly_analysis_peak_at_is_logged` | (depth) Read-only: logs the `MemoryPeak` systemd counted for `AdGuardHome.service` and `tvgw-analyze.service`, in MiB. It judges nothing. | never |
| `test_doh_list_is_current` | `doh4.txt` exists, was replaced within 8 days and has at least 50 entries. | never |
| `test_ipv6_guard_and_fail_closed_state` | The IPv6 wire drop is loaded, and `ip_forward` and the `forwarding` switches of `eth0` and `WAN_IF` are 1. | never |
| `test_tv_has_a_route_out` | A packet from `TV_IP` entering on `eth0` routes out the interface `config.uplink_interface` names: `WAN_IF` in direct mode, or in vpn mode the tunnel `VPN_IF` names or finds (`tun0` before one exists). | never |
| `test_the_gateways_own_answers_leave_by_the_tv_port` | `verify.gw_reply_route_check` passes: a packet from `GW_IP` to `TV_IP` routes out `TV_IF`, so the TV gets the resolver's answers ([design decision 49](../../docs/design-decisions.md#49-the-gateway-answers-the-tv-through-the-tv-port-table-100-carries-the-tv-subnet)). | never |
| `test_the_next_apply_finds_the_policy_routing_already_right` | Rule 60, table 100's default route and its TV-subnet route read as `tvgw-apply` compares them against the settings in `/run/tvgw/settings.applied`, so the next apply changes no routing. A second rule at priority 60 fails it, as it makes every apply delete and add the rule again. A failure names the TV side, never the router's address. | `UPLINK=vpn` |
| `test_state_is_not_world_readable` | The settings file, the state directory and every file in it, the store, the logs, the pcap directory and the pcaps are not world-readable; the pairing key is 600; no staged DoH list was left behind. | never |
| `test_pcaps_are_readable_by_the_extractor_and_owned_by_the_capture_user` | The newest pcap is owned by `tvgw-pcap`, and `nobody:nogroup` can read it and cannot write it. | never |
| `test_finished_pcaps_yield_rows_while_the_tv_is_on` | Of the three newest pcaps read without error in the last 4 hours, at least one yielded TLS rows, so the unprivileged tshark can read the files. (extractor) It fails, not skips, when every pcap read in those 4 hours carries an error. | no pcap read without error in the last 4 hours, or no `Active` reading in them |
| `test_the_sandboxed_tshark_reads_the_newest_finished_pcap` | (extractor) `tvgw.tshark.extract` on the newest pcap the capture has finished, through the real `systemd-run` sandbox and its `HARDENING` properties, does not fail; when the store read named hellos from that file, it finds at least one. A property the gateway's systemd or kernel refuses fails here at deploy, not silently in the hourly ingest. | no finished pcap with a capture header |
| `test_tv_lan_api_reachable_or_asleep` | When the TV answers the LG LAN API, Live Plus is off. | the TV does not answer |
| `test_the_live_reading_is_read_only_and_never_prompts` | (app in front) The live reading, run by its own rules for five seconds ([the live reading](../../docs/how-it-works/app-in-front.md#the-live-reading)). It passes whether the TV is on or off, so the public log never says which: it asserts only what holds either way (a session when the TV answers, nothing when it does not), that the key denies nothing (a `REFUSED` fails), and that the key file still holds the key. The event kinds only, never what the TV said. | the profile is not `lg-webos` (a static fact of the gateway, not the TV's power) |
| `test_a_gateway_that_has_read_its_tv_still_holds_the_key_for_it` | (pairing) Once the gateway has read its LG TV (`tvcheck.txt` exists), the pairing key file holds a key for `TV_IP`: without one the hourly reading asks the TV nothing and the test above only skips ([design decision 54](../../docs/design-decisions.md#54-a-tvs-lan-api-is-a-module-the-profile-names-a-reading-never-pairs-a-profile-declares-what-it-can-check)). Read-only. | `PROFILE` is not `lg-webos`, or the gateway has never read the TV |
| `test_backup_copy_is_fresh_and_sound` | The newest copy in `backup/` is under 36 hours old, mode 640 and owned by root, passes `quick_check` and holds DNS rows. | never |
| `test_capture_runs_as_the_capture_user_with_two_capabilities` | The capture unit `CAPTURE_MODE` picks runs as `tvgw-pcap` with exactly `CAP_NET_RAW` and `CAP_NET_ADMIN` in its bounding set. | never |
| `test_exactly_one_capture_runs_and_it_is_dumpcap` | The capture unit `CAPTURE_MODE` picks runs dumpcap, the other is not active, and the capture holds at most one pcap open. | never |
| `test_the_headers_capture_table_is_loaded_in_headers_mode_only` | `inet tvgw_capture` holds the capture rule with `CAPTURE_MODE=headers` and is absent with `full`. | never |
| `test_dns_gate_table_set_rule_and_feeder_are_in_place` | `inet tvgw_gate` holds the set and the counting rule, and `tvgw-dnsgate` is active. When the two latest readings say `Active` and the feeder has run for over 900 seconds (15 minutes), the set is not empty. | `DNSGATE=off` |
| `test_the_live_ntp_set_matches_what_tvgw_apply_takes_for_its_own` | (ntp) The four patterns the installed `tvgw-apply` reads `nft -t list set inet tvgw_ntp ntp4` with (type, size, flags, timeout), taken from the script and run with `grep -E` as it runs them, each match a line of this gateway's listing, so no apply remakes the table and resets its counts. Read-only. | never |
| `test_the_ntp_count_table_set_and_rule_are_in_place_and_verify_reads_them` | (ntp) `inet tvgw_ntp` holds the set `ntp4` (dynamic, with timeouts, size 1024, a timeout of 10 days) and the one rule commented `NTP from the TV, by server`, with no verdict; `verify.counters_from_table` reads that rule, and `verify.ntp_counters` reads the set's row and every element it stores as an address with its count and its expiry. Prints no address or count. | never |
| `test_the_in_path_filler_is_as_the_settings_say_and_its_hold_is_short` | (inpath) With `DNSGATE_FILL=passive`, `inet tvgw_gate` holds no in-path rule or set, no process is bound to queue 53053, and `tvgw-dnsgate-inpath` is neither active nor enabled. With `inpath`, the rules and sets are loaded, the unit is active and enabled with a 2-second watchdog, its process is bound with whole packets copied and nothing dropped, `dnsgate_inpath` passes without a warning, and once the filler has held twenty answers the median hold it measured is under 10 ms ([design decision 64](../../docs/design-decisions.md#64-the-gates-second-set-is-filled-in-the-path-of-the-answer-beside-the-passive-feeder-and-still-only-counts)). | never |
| `test_the_live_name_count_is_as_the_settings_say` | (namebound) With `NAME_BINDING=off`, the default, no names table, no process on NFLOG group 8, and `tvgw-names` neither active nor enabled. With `count`, the table's three copying rules with no verdict, the unit active and enabled, the group held, and `names_tap` passing without a warning. No count is printed. | never |
| `test_the_answer_record_covers_what_the_store_holds` | (namebound) Once an ingest has run on the schema with `answer_ip`: `meta.answer_ip_since` is set and not in the future, no row names a lookup the store no longer holds, and every address in it is public. | no ingest has run on that schema yet |
| `test_analyst_dry_run_pack_carries_no_home_identifier` | The pack `tvgw analyst --dry-run` builds from the live store holds no `TV_MAC`, no TV-subnet or home-LAN address prefix, not the gateway's host name, not `TV_NAME`, and no ZIP code or device name the store holds; it packs yesterday and the day each of those values was first read, and each pack is not world-readable. | never |
| `test_analyst_timer_follows_the_conf_schedule` | `tvgw-analyst.timer` shows the calendar `install.sh` rendered from `ANALYST_SCHEDULE`. | never |
| `test_autoblock_file_record_and_resolver_tell_one_story` | Every line of `AUTO_RULES` passes the lint beside the profile, and the store's active machine rules are exactly those lines. `tvgw autoblock check --no-watch` and `tvgw autoblock list` exit 0. With `ANALYST_APPLY=auto` the verifier model is not the proposer. The three analyst and autoblock unit files make `/opt/AdGuardHome` writable. | never |
| `test_the_guard_is_loaded_enabled_and_cannot_be_stopped` | (guard) `inet tvgw_guard` holds its input, forward and output chains at `filter + 10` and its final input drop; `tvgw-guard.service` is enabled with `RefuseManualStop=yes`; `/etc/tvgw/guard.nft` names `TV_IF` ([design decision 42](../../docs/design-decisions.md#42-the-pi-is-closed-to-the-tv-whatever-nftables-holds)). Read-only. | never |
| `test_cotenant_ip_filters_are_attached_to_their_running_cgroups` | (guard) Each active co-tenant whose `IPAddressDeny` covers `TV_NET` has an ingress and an egress program attached to its own cgroup (`bpftool cgroup show`), which is the check that `install.sh`'s `daemon-reload` applied the filter without a restart. Read-only. | without `bpftool`, with no co-tenant listed, or with none carrying the filter yet |
| `test_refused_answers_from_adguards_own_log_with_internet_names_only` | (refused) `tvgw refused --json --since 1h` reads AdGuard Home's query log back to the start of its window, and asks AdGuard's page for the lookups it has not written yet when `/etc/tvgw/adguard-admin` holds the password (without it, it asks nothing and says so in a note); it exits 0 or 1, never 2, and 1 exactly when a name it lists is new or needed; every name is an internet name or a title's zone; the output holds no home identifier (the TV's MAC and name, the gateway's host name, a MAC-shaped string, a private address outside `TV_NET`); the text ends saying it blocked nothing and changed nothing, and prints a `Fix:` line for no more names than it ranks likely. A failure prints no name. Read-only. | never |

Several of these are the regression tests for [incidents](../../docs/incidents.md): the per-interface forwarding and route checks, and the pcap ownership and rows checks.

Two edits each fail one test, a quick check that the suite still bites: a single changed byte in `/usr/local/sbin/tvgw-apply` fails `test_installed_file_matches_the_checkout[deploy/nftables/tvgw-apply]`, and `systemctl disable tvgw-pcap` fails `test_unit_enabled[tvgw-pcap.service]`. Restore each straight after.

## Writing a new hardware test

- Read, and change nothing you can avoid changing. A check that needs a change to the system belongs in `install.sh` or `tvgw verify`, not here.
- Name the test after the guarantee, and put the reason in the assertion message.
- Skip, with the reason, when the precondition is outside the gateway's control, such as the TV being off; fail when it is the gateway's own.
- Use the module's helpers: `S` and `PROF` for the settings and the profile, `sh()` for a command with a 60-second timeout, `dns_a()` for a lookup through the gateway's resolver, and `_store()` for a read-only connection to the store.
- Keep `INSTALLED` and `KEY_RULES` as module-level literals: `tests/unit/test_deploy_lint.py` parses them with `ast.literal_eval`, because it cannot import a module that skips itself off the gateway.
- A file `install.sh` copies byte for byte goes in `INSTALLED`, and a unit that must run goes in `ENABLED`.
- Keep vendor names in the profile where you can. The tests that hardcode LG names are listed in [adding a profile](../../docs/project/adding-a-profile.md#tests).
