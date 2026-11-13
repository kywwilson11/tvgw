# Adding a profile for another TV vendor

This page owns the procedure for putting a TV other than the bundled LG one behind the gateway, from the first capture to the checklist before a deploy. It is for a developer who writes that profile and its tests; every table and key of a profile, the evidence grades, the rules file and the lint are in [the profile format](../reference/profile-format.md). What the bundled profiles hold, and where their evidence came from, is in [the profiles README](../../src/tvgw/profiles/README.md).

## How a profile is used

Isolation, the DNS redirect, capture, the store, the hourly ingest, `tvgw verify` and the brief are vendor-neutral. A profile supplies what is not:

- which category each name falls in, and which categories are the TV doing its job;
- the clock hosts, the zones that must never be blocked at the apex, and the must-allow hosts with their reasons;
- the AdGuard Home blocklists, the record types withheld from the TV, and a URL filter for a plain-HTTP file service that mixes wanted and unwanted files;
- reference tables (webOS generations, hardware, a checklist, LAN APIs, privacy settings) that `tvgw profile` prints;
- the companion `.rules` file of AdGuard rules.

A profile is two files with one stem in `src/tvgw/profiles/`: `<name>.toml` and `<name>.rules`. `pyproject.toml` ships both as package data (`profiles/*.toml`, `profiles/*.rules`), so the gateway runs the profile inside the installed package, and a profile change reaches the gateway only through a deploy. The `PROFILE` setting names the bundled profile the gateway uses ([the settings file](../reference/settings.md)). `tvgw profile --profile` also takes the path of a `.toml` file, which is how you lint a profile on a workstation.

Every `tvgw` command loads the configured profile before it runs. A profile that does not load makes every command print one line, `tvgw: profile <name>: <reason>`, and exit 1 (`_load_profile` in [src/tvgw/cli.py](../../src/tvgw/cli.py)).

The code reads the profile in these places:

- `tvgw adguard apply` turns it into AdGuard's blocklists and custom rules ([the rules file](../reference/profile-format.md#the-rules-file)).
- The hourly ingest categorizes every name it stores, and recomputes the categories whenever the patterns change.
- The brief uses the categories, the expected categories and the clock hosts ([brief sections](../reference/brief-sections.md#sections)).
- `tvgw verify` resolves the must-allow and URL-filter hosts ([what tvgw verify checks](../reference/verify-checks.md)).
- The analyst's evidence pack carries the profile's name, vendor, expected categories, apex zones and must-allow hosts ([the analyst](../how-it-works/analyst-and-autonomy.md)).

Write a profile in two phases: capture with nothing blocked, then write the policy from what the TV did.

**[Phase 1](#phase-1-capture-first), capture with nothing blocked.**

1. Write a skeleton profile with an empty `.rules` file.
2. Deploy it: `make deploy`.
3. [Observe for 48 hours](#observe-for-48-hours): a cold boot, the app store, the apps the household uses, standby overnight and a setting change.
4. [Find the clock hosts](#find-the-clock-hosts).

**[Phase 2](#phase-2-write-the-profile), the policy.**

5. Write the tables: `[profile]`, `[categories]`, `[must_allow]`, `[adguard]` and `[url_filter]`.
6. Run `tvgw profile` until its lint is clean, then `make gate`.
7. Deploy again, and check that `tvgw adguard diff` exits 0.
8. Block in small batches.

## Phase 1: capture first

### Write a skeleton profile

1. On your workstation, create `src/tvgw/profiles/acme-tv.toml`. Use your vendor's name in lower case in place of `acme-tv`; the file name is what selects the profile.

   ```toml
   [profile]
   name = "acme-tv"
   vendor = "Acme"
   description = "Acme smart TVs (capture phase)"
   expected_categories = ["Streaming", "Infra"]
   clock_hosts = []
   never_block_apex = []

   [categories]
   strip_prefixes = []
   Streaming = ["netflix.*", "googlevideo.com"]
   Infra = ["ocsp.*", "digicert.com"]

   [must_allow]

   [adguard]
   filters = []
   ```

2. Create an empty `src/tvgw/profiles/acme-tv.rules` beside it. The file must exist; an empty one is the capture-phase profile.
3. Run the gate and deploy. The package on the gateway then carries the new profile, and the gateway still runs the old one.

   On your workstation:

   ```sh
   make gate
   make deploy PI=<ssh-host>
   ```

4. On the gateway, edit `/etc/tvgw/tvgw.conf` and set `PROFILE=acme-tv`. On a first install, `tvgw discover --write` leaves `PROFILE` as it was for a vendor that has no bundled profile, so set it here too.
5. Apply the profile to AdGuard Home and check the gateway.

   On the gateway:

   ```sh
   sudo tvgw adguard apply
   sudo tvgw adguard diff      # no drift
   sudo tvgw verify            # every line OK
   ```

6. Turn off, in AdGuard's web UI, every blocklist a previous profile or AdGuard's first-run wizard enabled. `tvgw adguard apply` replaces AdGuard's custom rules with the profile's, so no custom rule blocks anything now, but it never disables a list the profile does not name.

The firewall still redirects every DNS packet to AdGuard and rejects the bypasses, because none of that depends on the profile ([the firewall](../../deploy/nftables/README.md)).

### Observe for 48 hours

Use the TV as the household does, and do each of these on purpose. Write down the time of each one: without a LAN-API reader the store has no power readings ([what else is LG-specific](#what-else-is-lg-specific)), so your notes are the timeline.

- Cold-boot the TV with the power pulled, not from standby, and read what it looks up before you touch the remote. The `lg-webos` clock host is looked up at boot.
- Open the app store, install an app and update one. Note which names carry the downloads and which carry the store's pages.
- Launch each app the household uses and play something for a few minutes. Note the video CDN names and the telemetry that starts with each app.
- Leave the TV in standby overnight.
- Change a setting that should matter, such as a privacy toggle, and look for new names.

`sudo tvgw ingest` loads new data on demand. TLS names arrive only once the capture has closed the hour's pcap, because ingest reads finished pcaps only.

On the gateway:

```sh
tvgw new-hosts 2h                                   # names first seen since the last step
tvgw new-hosts 2d                                   # everything first seen, with category and counts
tvgw allowed 2d                                     # allowed names outside the expected categories
tvgw top-upload 2d                                  # destinations by bytes the TV sent
tvgw host NAME                                      # one name in depth
tvgw report --since SINCE --until UNTIL             # the brief over a stretch you noted
tvgw sql "select datetime(t,'unixepoch','localtime'), qname, blocked from dns where t >= strftime('%s','<start>','utc') order by t limit 200"
```

The last command lists the lookups from a local time you noted, such as the minute of a cold boot. Write `<start>` as `YYYY-MM-DD HH:MM`.

### Find the clock hosts

A TV without a battery clock takes its time from a vendor server; on webOS that is LG's SDP reply, which is why the `lg-webos` must-allow list starts with it. Block that server and the clock resets, and then TLS fails everywhere.

1. Read the lookups in the first minutes after a cold boot, before the first TLS connection. A TV that sets its clock from a server must do so before it can check a certificate.
2. To confirm a candidate, block it for one boot and check the TV's clock. Unblock it and restart the TV straight after, because a TV without its clock fails every TLS connection.
3. Put a pattern for each clock host in `clock_hosts` and each concrete host in `[must_allow]` ([the profile format](../reference/profile-format.md)).

## Phase 2: write the profile

1. Sort the names from Phase 1 into `[categories]`. Order the categories the way the brief's "By category" table should list them.
2. Set `expected_categories` to the categories that are the TV doing its job. An allowed name in any other category is what the brief and `tvgw allowed` show you.
3. List in `[must_allow]` every host whose block breaks the TV: the clock, firmware updates, the connectivity check, the store. Give each a reason.
4. List in `never_block_apex` the zones that carry both delivery and telemetry.
5. Choose few, curated blocklists for `[adguard] filters`. The capture is the evidence; a list is a starting point.
6. Decide on `strip_qtypes`. First check whether the TV asks for those record types at all:

   On the gateway:

   ```sh
   tvgw sql "select qtype, count(*) from dns group by qtype"
   ```

7. Add a `[url_filter]` only if the vendor serves wanted and unwanted files over plain HTTP from the same host names ([design decision 8](../design-decisions.md#8-a-url-filter-for-lgs-file-service-instead-of-a-dns-block)).
8. Write the blocks in the `.rules` file, each group under a dated reason ([the rules file](../reference/profile-format.md#the-rules-file)).
9. Run the lint, write the tests, and work through the [checklist before you deploy](#checklist-before-you-deploy).

## Let tvgw discover recognize the vendor

`tvgw discover`, which `install.sh` runs on a first install, and `tvgw setup` name the TV's vendor from three tables in src/tvgw/discover.py, and `discover.assign()` gives it a profile only on evidence ([design decision 62](../design-decisions.md#62-a-tv-gets-a-vendor-profile-only-on-evidence-or-its-owners-answer-otherwise-the-general-profile-which-isolates-records-briefs-and-blocks-only-shared-lists)). Each value is `(vendor, platform, profile name or None)`.

- `PORT_SIGNATURES` is keyed by the TCP ports the TV's LAN API listens on. Every port of a signature must accept a connection. The signatures are tried in order and the first full match wins; a partial match is listed as evidence only.
- `HOSTNAME_HINTS` is keyed by a substring of the host name the TV announced over DHCP, compared in lower case. The first substring found wins.
- `SSDP_SIGNATURES` is keyed by an SSDP search target only that vendor's TV answers. `ssdp_search()` keeps every target a device answered.

A port signature takes precedence for the vendor and platform: a hostname hint fills only what the signature left empty. When SSDP answers, the UPnP description's manufacturer fills an empty vendor too. Devices with a profile are listed first.

`assign()` gives a device the profile of a row only when the device answered that `SSDP_SIGNATURES` target, or when every port of a `PORT_SIGNATURES` row accepted a connection and a `HOSTNAME_HINTS` entry names the same profile, and only a profile the package ships. One signal alone, the ports, the host name or the UPnP manufacturer, names a vendor and no profile; a host name is only what the device says about itself. `vendor_profile()` then finds the profile whose `[profile] vendor` is that brand, and `tvgw setup` asks the TV's owner whether the TV is one ([what setup does](../install/README.md#what-setup-does)).

The shipped rows:

| Table | Key | Vendor | Platform | Profile |
|---|---|---|---|---|
| `PORT_SIGNATURES` | `(3000, 3001)` | LG | webOS | `lg-webos` |
| `PORT_SIGNATURES` | `(8001, 8002)` | Samsung | Tizen | none |
| `PORT_SIGNATURES` | `(8060,)` | Roku | Roku OS | none |
| `PORT_SIGNATURES` | `(7345, 9000)` | Vizio | SmartCast | none |
| `PORT_SIGNATURES` | `(8008, 8009)` | Google | Android TV / Cast | none |
| `HOSTNAME_HINTS` | `lgwebostv` | LG | webOS | `lg-webos` |
| `HOSTNAME_HINTS` | `samsung` | Samsung | Tizen | none |
| `HOSTNAME_HINTS` | `roku` | Roku | Roku OS | none |
| `HOSTNAME_HINTS` | `vizio` | Vizio | SmartCast | none |
| `HOSTNAME_HINTS` | `bravia` | Sony | Android TV | none |
| `HOSTNAME_HINTS` | `firetv` | Amazon | Fire TV | none |
| `HOSTNAME_HINTS` | `amazon-` | Amazon | Fire TV | none |
| `HOSTNAME_HINTS` | `chromecast` | Google | Cast | none |
| `HOSTNAME_HINTS` | `googletv` | Google | Android TV | none |
| `SSDP_SIGNATURES` | `urn:lge-com:service:webos-second-screen:1` | LG | webOS | `lg-webos` |
| `HOSTNAME_HINTS` | `tizen` | Samsung | Tizen | none |
| `SSDP_SERVER_HINTS` | `samsung upnp sdk` (an `_` in the header reads as a space) | Samsung | Tizen | none |
| `SSDP_URN_HINTS` | `urn:samsung.com:` | Samsung | Tizen | none |
| `VENDOR_CLASS_HINTS` | `vdlinux`, `samsung` (the DHCP vendor class, spaces dropped) | Samsung | Tizen | none |

(samsung) `samsung-tizen` is assigned on none of these rows. A device another signal names Samsung, and nothing names LG, is asked the hourly reading's one question, `GET /api/v2/` on port 8001 (`tizen.identify`), and gets the profile only when its reply says `type` "Samsung SmartTV": a Samsung soundbar gives the same signals (`assign()` in src/tvgw/discover.py). A host name in `NOT_NAMES`, such as the `localhost` many Samsungs announce, is no name. Nothing keys a device on its UPnP UDN, which some sets change at every boot.

With no profile assigned, `tvgw discover --write` records `TV_MAC`, `TV_IP` and `TV_NAME`, leaves `PROFILE` as it was, and says so; when the vendor has a bundled profile, it names the `PROFILE` to set. The DNS-only `roku` and `vizio-smartcast` profiles are not named in these rows, nor is `samsung-tizen` for a Samsung that does not answer as one, so `tvgw setup` asks the owner for them, and `tvgw discover --write` leaves them to be set by hand.

To add your vendor:

1. On the gateway, run `sudo tvgw discover` with the TV on. Under each device it prints its evidence: the lease and the name the TV announced, the open LAN-API ports, and the SSDP answer when there is one.
2. In src/tvgw/discover.py, put your profile's name in the row for each table you have evidence for, or add a row. For an assignment the port row and the hostname hint must both name it, or your TV must answer a search target only it answers (`SSDP_SIGNATURES`); `[profile] vendor` must be the brand the rows name.
3. Add the case to `test_fingerprint_and_hostname_hints` and `test_a_profile_is_assigned_only_on_evidence` in tests/unit/test_discover.py, with the ports and the name your TV announced.

SSDP is a bonus, never a requirement: many TVs stop answering it once their sharing features are off.

## Tests

Add unit tests to tests/unit/test_profile.py or a new file beside it, with real captured names, not invented ones. The shared `lg` fixture loads `lg-webos`; load yours with `profile.load("acme-tv")`. Fixtures and procedures are in [the unit tests README](../../tests/unit/README.md).

| Test to add | Model it on |
|---|---|
| Categorizer cases: a parametrized `(host, category)` list with a longest-match case, a stripped prefix, a wildcard and a name that falls through to `Other` | `test_lg_categories` in tests/unit/test_profile.py |
| A clean lint and an `@@\|\|host^$important` exception for every must-allow host | `test_lg_profile_lints_clean_and_generates_allow_rules` |
| The URL filter on real URIs, blocked and passed, if you have one | `test_lg_url_filter` |
| The nginx files against your profile, if you have a URL filter | `test_nginx_conf_matches_the_profile` |
| A telemetry name under the clock zone that does not count as a clock lookup | `test_telemetry_under_the_clock_zone_is_not_a_clock_host` in tests/unit/test_brief_sections.py |
| Generation and hardware lookups, and a grade on every row | `test_generations_and_hardware_tables` |
| Every record cited or observed, every `.rules` group cited, every must-allow reason graded | the tests in tests/unit/test_profile_records.py and tests/unit/test_vendor_profiles.py |
| Your discovery rows | `test_fingerprint_and_hostname_hints` in tests/unit/test_discover.py |

The hardware suite in tests/hardware/test_gateway.py is mostly vendor-neutral and reads the profile. Adapt or expect these on another vendor's TV ([what each test guarantees](../../tests/hardware/README.md#what-each-test-guarantees)):

| Test | What is LG-specific | What to do |
|---|---|---|
| `test_blocked_names_resolve_to_zero` | It hardcodes three LG names. | Replace them with names your profile blocks. |
| `test_url_filter_names_point_at_the_gateway`, `test_nginx_filter_regex_matches_the_profile`, `test_url_filter_blocks_and_passes` | They skip without a `[url_filter]`; with one, the last requests LG's file-service URLs. | Adapt the URLs, or leave the section out. |
| `test_tls_passthrough_reaches_the_real_host` | It always requests `gfts.lge.com` through the gateway and never skips. | Adapt or remove it with the nginx files. |
| `test_tv_lan_api_reachable_or_asleep` | It uses the LG LAN API reader. | It skips when the reader gets no answer. |
| `test_a_gateway_that_has_read_its_tv_still_holds_the_key_for_it` | It reads the LG pairing key file. | It skips unless `PROFILE=lg-webos`. |
| `test_tv_has_its_dhcp_reservation_and_acr_is_off_in_the_store` | Its second half reads the LG `option.livePlus` reading. | The DHCP half still runs; the rest skips without a reading. |
| `test_dns_chain_counted_packets_while_the_tv_was_on`, `test_finished_pcaps_yield_rows_while_the_tv_is_on` | They need `Active` power readings, which only the LG reader writes. | They skip without a reader. |
| `test_capture_is_live_and_the_disk_is_healthy`, `test_dns_gate_table_set_rule_and_feeder_are_in_place` | Their freshness and set-size checks run only after `Active` readings. | Those parts do not run without a reader. |
| `test_no_acr_name_answered_and_no_traffic_to_its_addresses_in_24h` | It reads the `ACR` category. | Name a category `ACR`, or it checks nothing. |

## What else is LG-specific

- **The TV readings.** `tvgw tvcheck` reads the LG webOS LAN API (src/tvgw/lgwebos.py), or (samsung) a Samsung's REST interface without pairing when `PROFILE=samsung-tizen` (src/tvgw/tizen.py), and `tvgw-analyze` runs it hourly only for those two profiles ([the shell jobs](../../deploy/bin/README.md)). For another profile there are no power readings and no TV settings in the store. Then the brief's TV line has no readings, the "While off/asleep" section does not appear, the red line for a day on without a clock lookup cannot fire, the Live Plus red line and the firmware section have nothing to read, and `tvgw profile` has no reported model to describe ([brief sections](../reference/brief-sections.md#sections)).
- **Writing your own reader.** The store reads two files, so a reader for your TV that writes them restores all of the above. `/var/lib/tvgw/tvcheck-history.log` holds one line an hour: an ISO 8601 time with its UTC offset, the power state and the foreground app, separated by tabs (the older `YYYY-MM-DD HH:MM power app` form still reads). `/var/lib/tvgw/tvcheck.txt` starts with a `read <time>` line, followed by `key = value` lines; ingest skips the keys `power`, `app` and `info` and any value that starts with `ERR `. The brief counts any power state other than `Active`, `Screen Off` and `Screen Saver` as off (`AWAKE` in src/tvgw/queries.py).
- **The autonomy watches.** The live canary after an autonomous block reads the TV's power and foreground app over the LG LAN API, and it treats the webOS home and launcher apps as the launcher. The hourly judge compares streaming per TV hour with demand: an hour with a power state in `AWAKE` and a streaming app in front, or an expected-category connection opened. Without a reader, the canary stays armed and records the TV as unobserved when the trial ends, the hourly judge sees no demand hours, every trial ends untested, and only the red-line checks can revert a block ([the analyst and autonomy](../how-it-works/analyst-and-autonomy.md)).
- **The firewall.** `tvgw-apply` accepts and logs LG's hardcoded firmware fallback, `156.147.69.32` on TCP 8080 ([the ruleset](../../deploy/nftables/README.md#the-ruleset-chain-by-chain)), and builds the wall on LG's ad-tech ports, only when `PROFILE` is `lg-webos` or unset. Your profile gets neither, whatever `ADTECH_PORT_WALL` says.
- **The URL filter.** The nginx files are written for LG's GFTS host names ([the URL filter](../../deploy/nginx/README.md)). `install.sh` installs them whenever nginx is present, and `tvgw verify` expects nginx to run.
- **Discovery.** One of the SSDP search targets in src/tvgw/discover.py is LG's second-screen service, and an answer to it is enough to assign `lg-webos` (`SSDP_SIGNATURES`); the others are generic.
- **The addressing.** Not vendor-specific: the TV port, the TV subnet and the gateway's address are the settings `TV_IF`, `TV_NET` and `GW_IP`, `eth0`, `10.10.10.0/24` and `10.10.10.1` by default, and every file reads them from the settings file except `tvgw-pcap.service`'s capture filter ([the TV side](../reference/settings.md#the-tv-side)).

## Checklist before you deploy

1. Run `tvgw profile --profile src/tvgw/profiles/<name>.toml` on your workstation. It must print `rules lint: clean`.
2. Run `make gate`. It must exit 0.
3. If the profile has a `[url_filter]`, check that the nginx files carry the same regex and hosts, and that your copy of `test_nginx_conf_matches_the_profile` passes.
4. Run `make deploy PI=<ssh-host>`. It ends with `tvgw verify`, and its exit status is verify's ([how a change reaches the gateway](../../deploy/README.md#how-a-change-reaches-the-gateway)).
5. On the gateway, run `sudo tvgw adguard diff`. It must exit 0.
6. Block in small batches. After each batch, use the affected feature and wait a few minutes before you judge it: blocked answers carry a 60-second TTL (`blocked_response_ttl: int = 60` in src/tvgw/adguardcfg.py). Then read `tvgw retries 1d` and `tvgw rules`, and keep the dated reason in the `.rules` file.
