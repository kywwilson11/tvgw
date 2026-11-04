# TV profiles

This folder holds the bundled TV profiles, each a TOML file and a companion `.rules` file, shipped inside the package: `lg-webos`, verified on an LG CX, the DNS-only `samsung-tizen`, `roku` and `vizio-smartcast`, built from lists and papers, and `generic-tv`, the general profile for any other TV. Every `tvgw` command loads the profile `PROFILE` names when it starts, and `tvgw adguard apply` turns that profile into AdGuard Home's lists and rules. What a profile is, and how to write one for another vendor, is in [adding a profile](../../../docs/project/adding-a-profile.md).

## Files

| File | What it is | Used by |
|---|---|---|
| `__init__.py` | Makes the folder a package, so `importlib.resources` finds the profiles inside the installed package. | `profile.load()` |
| `generic-tv.toml` | The general profile: the two shared blocklists with their sentinels, the shared categories, `[clock] model = "none"`, its support status and its Wi-Fi step. Nothing of a vendor. | `profile.load()`, `tvgw profile`, setup |
| `generic-tv.rules` | A header comment only: the general profile pins no block of its own. | `profile.load()`, `tvgw adguard` |
| `lg-webos.toml` | The LG webOS profile: metadata, categories, must-allow hosts, AdGuard blocklists, the URL filter, and the reference tables for webOS generations, hardware and a checklist. | `profile.load()`, `tvgw profile` |
| `lg-webos.rules` | The profile's AdGuard custom rules, one per line, in groups under dated comments. | `profile.load()`, `tvgw adguard` |
| `roku.toml` | The DNS-only Roku OS profile: categories, must-allow hosts, blocklists, LAN API and privacy settings, all unverified. | `profile.load()`, `tvgw profile` |
| `roku.rules` | Its pinned blocks, each group citing its sources. | `profile.load()`, `tvgw adguard` |
| `samsung-tizen.toml` | The DNS-only Samsung Tizen profile, all unverified, with what its no-pairing reading reads (`[support]`), the Tizen version table and the questions a set in hand must answer in its header. | `profile.load()`, `tvgw profile`, `tvgw tvcheck` (by name) |
| `samsung-tizen.rules` | Its pinned blocks, each group citing its sources. | `profile.load()`, `tvgw adguard` |
| `vizio-smartcast.toml` | The DNS-only Vizio SmartCast profile, all unverified. | `profile.load()`, `tvgw profile` |
| `vizio-smartcast.rules` | Its pinned blocks, each group citing its sources. | `profile.load()`, `tvgw adguard` |

`[tool.setuptools.package-data]` in pyproject.toml ships `profiles/*.toml` and `profiles/*.rules`. `profile.bundled_names()` lists the shipped names. `profile.load()` takes a bundled name (`lg-webos`) or the path of a `.toml` file. Either way the `.rules` file is the one with the same name beside it, found by the name asked for and never by `[profile].name`.

## Support

What each profile is, how far it is tested, and what the TV's owner checks on the TV ([design decision 62](../../../docs/design-decisions.md#62-a-tv-gets-a-vendor-profile-only-on-evidence-or-its-owners-answer-otherwise-the-general-profile-which-isolates-records-briefs-and-blocks-only-shared-lists)). `tools/docgen.py` writes the table from each profile's `[support]` table and `[[generations]]` rows, and the front page's and docs/tv/README.md's from the same rows without the Profile column ([generated tables](../../../tools/README.md#generated-tables)). A generation counts as tested only where its row is verified.

<!-- generated:profile-support -->
| TV | Profile | Status | What tvgw does | What you check on the TV yourself |
|---|---|---|---|---|
| LG, webOS 5 (2020 sets) | `lg-webos` | **Tested** on an LG CX (OLED55CX), software 04.64.00 | Blocks, reports every day, and once paired reads the TV's privacy settings and Wi-Fi state every hour | Nothing after setup |
| LG, webOS 6 and later (2021 on) | `lg-webos` | **Not yet tested** on these versions | Blocks and reports every day; once paired, reads the privacy settings, and the Wi-Fi state where the TV reports it | That the TV's Wi-Fi is off, until tvgw shows it can read it on your TV |
| LG, webOS 3 and 4 (2016 to 2019 sets) | `lg-webos` | **Not yet tested** on these versions | Blocks and reports every day; once paired, reads the privacy settings, and the Wi-Fi state where the TV reports it | That the TV's Wi-Fi is off, until tvgw shows it can read it on your TV |
| Samsung (Tizen) | `samsung-tizen` | **Not yet tested**, built from published research | Blocks and reports every day, and every hour reads whether the TV is on and whether it is on its cable or on Wi-Fi, without pairing | Its privacy and viewing-data settings, in the TV's own menus |
| Roku TV | `roku` | **Not yet tested**, built from published research | Blocks and reports every day | That the TV's Wi-Fi is off, and its privacy and viewing-data settings, in the TV's own menus |
| Vizio (SmartCast) | `vizio-smartcast` | **Not yet tested**, built from published research | Blocks and reports every day | That the TV's Wi-Fi is off, and its privacy and viewing-data settings, in the TV's own menus |
| Other TVs (Google TV, Fire TV, Sony, TCL, Hisense and more) | `generic-tv` | **Not yet tested**, with the general profile | Keeps the TV away from your other devices, reports every day, and blocks known trackers from shared lists | That the TV's Wi-Fi is off, and its privacy and viewing-data settings, in the TV's own menus |
<!-- /generated:profile-support -->

## The lg-webos profile

The profile as shipped. The format of each table is in [the profile format](../../../docs/reference/profile-format.md).

### Metadata

- `name = "lg-webos"`, `vendor = "LG"`, and the description `LG webOS smart TVs (verified on CX / webOS 5)`.
- `[support]`: `status = "tested"`, `tested_on` the CX (OLED55CX) with software 04.64.00, and `you_check` that the TV's Wi-Fi is off until tvgw shows it can read it. Only the webOS 5 row is verified, so the support table calls every other generation not yet tested.
- `expected_categories` are `Streaming`, `Infra`, `LG core` and `FAST`: the TV doing its job. An allowed name in any other category shows in the brief.
- `clock_hosts` are `??.lgtvsdp.com` and `??.nextlgsdp.com`, the country SDP hosts only. webOS takes its time from LG's SDP reply, and `rdx2.lgtvsdp.com`, under the same zone, is telemetry.
- `never_block_apex` lists `lgtvsdp.com`, `nextlgsdp.com`, `lgtvcommon.com`, `lge.com`, `lgappstv.com`, `lgeapi.com`, `aws-prd.net`, `wiselg.com` and `amagi.tv`: zones where one block at the apex took out clocks, stores, casting or firmware, or, for `amagi.tv`, would stop every Amagi channel in LG Channels.

### Categories

`strip_prefixes` removes `aic.`, `eic.`, `kic.` or `ruc.`, or the same with a hyphen, from the front of a name before it is matched. The longest matching pattern wins, and a name no pattern matches is `Other`.

| Category | What it holds | Expected |
|---|---|---|
| `ACR` | Screen fingerprinting: LG Ad Solutions (Alphonso), Samba TV, Nielsen. | no |
| `LG ads` | LG's ad, promotion, recommendation and shopping hosts, LG Channels' home-screen ad app (`lgchhomeapp.lgtvcommon.com`, which the `lgtvcommon.com` suffix put in `LG core` until 2026-11-01), and the `aws-prd.net` CNAME targets of LG's ad hosts. | no |
| `LG telemetry` | webOS telemetry: the CDP beacons, the `rdx2` hosts, the telemetry collector, and the newer generations' counters. | no |
| `LG fingerprint` | Device fingerprinting and discovery: QuickSet, Philips Hue, and Universal Electronics' Nevo Azure IoT hubs, as the pattern `*nevoai-iothub-*-prod.azure-devices.net` (a regex in the rules). | no |
| `LG IoT` | ThinQ and LG's IoT back-ends, and AWS IoT push. | no |
| `LG core` | The clock, firmware, the Content Store and the file service. | yes |
| `Voice` | Speech back-ends: Google Assistant, Alexa, Dangbei. | no |
| `3rd-party ads` | Ad servers, app analytics, audience measurement, and the browser engine's own pings. | no |
| `Streaming` | Video services and their CDNs. | yes |
| `FAST` | Free ad-supported TV delivery for LG Channels: Amagi, Wurl's `transmit.live` host for LG, NBCU's and Stingray's channel hosts. Allowed and never blocked, since a block stops the channel. Amagi's names are title-bearing: the left label carries the channel id and a channel or programme slug, so the store holds a viewing record for them ([privacy and retention](../../../docs/how-it-works/privacy-and-retention.md)). From the 2026 lab set of a newer LG; whether the CX's client uses the slug form is unverified. | yes |
| `Infra` | Certificate status, time, DRM, Google's API hosts and general CDNs. | yes |

### Must-allow hosts

Each host becomes a generated `@@||host^$important` exception in AdGuard's rules ([design decision 7](../../../docs/design-decisions.md#7-must-allow-exceptions-are-generated-from-the-toml)), and `tvgw verify`, the brief's red lines and the hardware suite check each one.

| Host | Why, from the TOML |
|---|---|
| `us.lgtvsdp.com` | Clock sync at boot; blocked, the clock resets to 2019 and TLS fails everywhere. |
| `snu.lge.com` | Firmware updates, which carry the security fixes. |
| `lgtvonline.lge.com` | The connectivity check; without it the TV thinks it is offline. |
| `us.lgrecommends.lgappstv.com` | The Content Store's landing feed; the store fails without it. |
| `aic.service.lgtvcommon.com` | Content Store and launcher services. |
| `us.tvsdp.lgeapi.com` | The Content Store API. |
| `us.nextlgsdp.com` | Clock, login and store on webOS 6 and 22 onward. |
| `ngfts.nextlgsdp.com` | Content Store icons and images on webOS 6 onward. |
| `aic-gfts.nextlgsdp.com` | Content Store downloads and updates on webOS 6 onward. |

The `us.` and `aic-` prefixes are regional, and the TOML says to swap them for another region. The last three protect newer sets against lists that block the `nextlgsdp.com` hosts, and are harmless on the CX.

### AdGuard blocklists and record types

`[adguard] filters` names three lists: HaGeZi LG webOS (AdGuard's registry `filter_72`), HaGeZi DoH/VPN bypass in its DoH-only form, and HaGeZi Pro (`filter_48`). `strip_qtypes = ["HTTPS", "SVCB"]` generates one rule that withholds those record types from the TV's address, which keeps Encrypted ClientHello keys and address hints away from it ([design decision 6](../../../docs/design-decisions.md#6-adguard-home-is-configured-as-code)). The CX has never asked for either type.

### URL filter

`[url_filter] hosts` are `ngfts.lge.com`, `aic-ngfts.lge.com`, `aic-img-ngfts.lge.com` and `gfts.lge.com`. Each gets a generated `||host^$dnsrewrite=<GW_IP>` rule, so the TV's plain-HTTP requests to them reach nginx on the gateway. nginx returns 403 when the request URI matches `block_regex = 'biz_code=(PREMIUM|CDP|LGSHOPPING|MAS|IBS)([&_]|$)'`, case-insensitively: app packages and icons pass, while the ACR config, the telemetry schedule, LG Shopping data, promo thumbnails and the LG Channels guide are refused ([design decision 8](../../../docs/design-decisions.md#8-a-url-filter-for-lgs-file-service-instead-of-a-dns-block)). The boundary after the code keeps `MAS` from matching `MASTER` or `META_IMG`.

### The rules file

`lg-webos.rules` holds the blocks and the regex rules, in groups under `! ----` headings: ACR; LG ads; LG telemetry; device fingerprinting; third-party ads; the preinstalled apps' telemetry; ThinQ and IoT; voice back-ends; home-screen declutter; audience measurement; the newer webOS generations; and the names closed after later briefs. Each group carries the date and the evidence, and a block that costs a feature says so: blocking QuickSet and Philips Hue costs device setup and Hue sync on the TV ([design decision 16](../../../docs/design-decisions.md#16-quickset-and-hue-stay-blocked-with-the-cost-written-down)). A rule tried and rejected stays as a comment: blocking Prime Video's ad-pod service, `||aiv-delivery.net^`, did not stop its ads, which are stitched into the stream. Since 2026-11-01 the Nevo hub is the regex `/^([a-z0-9]+-)?nevoai-iothub-[0-9]+-prod\.azure-devices\.net$/`, which covers the variant a 2026 lab set used and no list carries, and `rdl.`, `wiseconfig.` and `ads.lgtvcommon.com` have rules of their own instead of resting on HaGeZi's LG list alone (`tests/unit/test_acr_profile.py`).

AdGuard's custom rules are built by `Profile.adguard_rules()` in this order: the generated must-allow exceptions, the URL-filter rewrites for `GW_IP`, the record-type rule for `TV_IP`, then the lines of the `.rules` file with comments, blank lines and copies of a generated rule dropped. `tvgw adguard apply` appends the owner's site rules from `LOCAL_RULES`, then the machine's rules from `AUTO_RULES`, each after the same lint ([the analyst and autonomy](../../../docs/how-it-works/analyst-and-autonomy.md)).

### Generations

`[[generations]]` describes what changes between webOS releases. `tvgw profile --webos WEBOS` looks a row up by webOS major and `--firmware FIRMWARE` by firmware major; the rows with a firmware major are webOS 5 (`04`), 24 (`23`), 25 (`33`) and 26 (`43`).

| webOS | Years | Codename | Confidence | Verified |
|---|---|---|---|---|
| 3 | 2016, 2017 | `dreadlocks` | `community` | no |
| 4 | 2018, 2019 | `goldilocks` | `community` | no |
| 5 | 2020 | `jhericurl` | `observed` | yes |
| 6 | 2021 | `kisscurl` | `community` | no |
| 22 | 2022 | `mullet` | `community` | no |
| 23 | 2023 | `number1` | `community` | no |
| 24 | 2024 | `ombre` | `community` | no |
| 25 | 2025 | `ponytail` | `community` | no |
| 26 | 2026 | `queue` | `community` | no |

### Hardware

`[[hardware]]` records the audio-privacy facts per model line: whether the TV has a far-field microphone of its own, as opposed to the Magic Remote's push-to-talk one. `tvgw profile --model MODEL` matches the model number against the patterns.

| Year | Models | Far-field microphone | Confidence |
|---|---|---|---|
| 2019 | `OLED*B9*`, `OLED*C9*`, `OLED*E9*`, `OLED*W9*`, `*SM9*`, `*SM8*`, `*UM7*` | no | `spec` |
| 2020 | `OLED*CX*`, `OLED*BX*` | no | `observed` |
| 2020 | `OLED*GX*`, `OLED*WX*`, `OLED*ZX*`, `*NANO99*` | yes | `spec` |
| 2021 | `OLED*A1*`, `OLED*B1*`, `OLED*C1*`, `OLED*G1*`, `OLED*Z1*`, `*QNED99*`, `*QNED9*`, `*NANO9*` | no | `low` |
| 2022 | `OLED*C2*`, `OLED*G2*`, `OLED*Z2*` | yes | `spec` |
| 2022 | `OLED*A2*`, `OLED*B2*`, `*QNED8*`, `*NANO7*`, `*UQ*` | no | `spec` |
| 2023 | `OLED*C3*`, `OLED*G3*`, `OLED*Z3*` | yes | `spec` |
| 2023 | `OLED*B3*`, `OLED*A3*`, `*QNED8*`, `*UR8*`, `*UR7*` | no | `spec` |
| 2024 | `OLED*C4*`, `OLED*G4*`, `OLED*M4*` | yes | `spec` |
| 2024 | `OLED*B4*`, `*QNED85T*`, `*QNED90T*`, `*UT8*` | no | `spec` |
| 2025 | `OLED*C5*`, `OLED*G5*`, `OLED*M5*` | yes | `spec` |
| 2025 | `OLED*B5*`, `*QNED85A*`, `*QNED8*`, `*UA*` | no | `spec` |
| 2026 | `OLED*G6*`, `OLED*C6*`, `OLED*M6*` | yes | `low` |

`[checklist]` has three topics, `audio`, `network` and `acr`: the steps to take on the TV before trusting the room is private, which `tvgw profile` prints for a known model.

### LAN APIs and privacy settings

`[[lan_api]]` and `[[privacy_setting]]` are the reference records of [the profile format](../../../docs/reference/profile-format.md), each with its provenance. They block nothing.

| Record | Provenance | Evidence or grade |
|---|---|---|
| SSAP on port 3000, webOS 5: reads work, writes refused on 04.64 | verified | `lan-api` |
| SSAP over TLS on port 3001 | unverified | `community` |
| Live Plus on webOS 5, key `option.livePlus` | verified | `lan-api` |
| Live Plus on webOS 6 and later | unverified | `community` |
| Voice Information agreement on webOS 5 | verified | `capture` |
| Viewing Information agreement | unverified | `community` |
| Limit Ad Tracking and Personalized Advertising | unverified | `community` |
| Home Promotion and Content Recommendation | unverified | `community` |

The verified rows are the ones the profile already recorded as seen on the CX; `test_lg_records_are_verified_exactly_where_the_cx_showed_them` in tests/unit/test_profile_records.py keeps it that way.

## Where its evidence came from

The TOML's header and the `.rules` file's header name the sources:

- an LG CX (webOS 5.6.2, firmware 04.64.00) observed through this gateway in October 2026: its query log, its pcaps, and its LAN-API readings;
- HaGeZi's LG webOS list, Perflyst's Smart-TV list and hugobatista/lg-tv-ad-block;
- the IMC 2024 ACR study, arXiv 2409.06203;
- community captures of the newer webOS generations, gathered on 2026-10-26 from HaGeZi's and webosbrew's issue trackers, Level1Techs and the other sources the header names.

Only the CX is observed. Its rows are the one generation with `verified = true` and `confidence = "observed"`, webOS 5, and the one hardware row graded `observed`, `OLED*CX*` and `OLED*BX*`. Every other generation is `community`, and every other hardware row `spec` or `low`. In `[categories]` and the `.rules` file, an entry never seen on the CX carries "unverified" in its comment. The grades are defined in [the profile format](../../../docs/reference/profile-format.md). The code does not check them, and a row without one reads as `low` ([design decision 15](../../../docs/design-decisions.md#15-blocklist-entries-come-from-evidence-with-grades)).

## The DNS-only profiles

`samsung-tizen`, `roku` and `vizio-smartcast` were built on 2026-11-01 without a TV of those vendors behind a gateway ([design decision 32](../../../docs/design-decisions.md#32-a-vendor-profile-without-hardware-is-dns-only-cited-and-subscribed)). Every must-allow reason, record and `.rules` group in them says `unverified` and cites its source; none has a URL filter, a generation or a hardware row. Each has `[support] status = "not-yet-tested"` and the general profile's `you_check`. The rubric they are graded by, and how they become verified, is in [grading evidence](../../../docs/reference/profile-format.md#grading-evidence).

| Profile | Blocklists | Pinned blocks | Must-allow hosts | Apex-protected zones |
|---|---|---|---|---|
| `samsung-tizen` | HaGeZi Samsung native (`filter_61`), HaGeZi DoH, HaGeZi Pro | ACR (`samsungacr.com`, the `acr-<region>-prd.samsungcloud.tv` hosts), Samsung ads, two telemetry hosts | clock, firmware check and downloads, connectivity ping, apps and HbbTV, account login (two hosts, one of which both HaGeZi lists block), the app store and app updates, the Smart Hub broker, home-screen previews, Samsung TV Plus playback, the Hulu app | `samsungcloudsolution.com`, `samsungcloudsolution.net`, `samsungqbe.com`, `samsungcloudcdn.com`, `samsungosp.com`, `samsungotn.net`, `samsungcloud.tv`, `samsungnyc.com` |
| `roku` | HaGeZi Roku native, HaGeZi DoH, HaGeZi Pro | ACR (`scribe.logs.roku.com`, `acr.roku.com`), Roku ads and ad measurement | clock (`api.rokutime.com`), firmware, system API, two connectivity checks | `roku.com`, `rokutime.com`, `sr.roku.com`, `cs.roku.com`, `delivery.roku.com`, `msc.roku.com` |
| `vizio-smartcast` | HaGeZi DoH, HaGeZi Pro | ACR (`tvinteractive.tv`, Inscape), `adsmeasurement.com` | two platform hosts, the probable update host, three NTP hosts | `vizio.com`, `vudip.vizio.com`, `smartcasttv.com`, `amazonaws.com`, `amagi.tv` |

Their sources:

- HaGeZi's native Samsung and Roku tracker lists and HaGeZi Pro, subscribed, with the few hosts the profile relies on pinned in the `.rules` file;
- Perflyst's Smart-TV list, whose commented-out lines are the breakage reports behind most must-allow hosts; it is cited, and not subscribed for Samsung, because it blocks `www.samsungotn.net`, which its own comments say firmware updates need, and its regex extension takes the whole `samsungcloudsolution.net` zone;
- Anselmi et al., IMC 2024 (arXiv 2409.06203), for Samsung's ACR hosts;
- "Watching the Watchers", PoPETs 2027, for the ACR endpoints of all three and the hosts in its published captures; cited, never merged, since its list is CC BY-NC-ND 4.0;
- Mohajeri Moghaddam et al., CCS 2019, for Roku's ad tracking;
- Home Assistant's integration docs, Roku's ECP documentation and the samsungtvws library for the LAN APIs;
- the vendors' privacy pages and press guides for the menu paths.

(samsung) `samsung-tizen` was revised on 2026-11-04 from that day's Samsung research. It adds six must-allow hosts, each with its breakage report and its cost: `osb-apps-v2.samsungqbe.com`, `osb-v2.samsungqbe.com`, `img-resize-cdn-prod.samsungnyc.com`, `unified-ad-segment-cdn-ak-us-east-1.akamaized.net`, `osb.samsungqbe.com` (both subscribed HaGeZi lists block it; the reports tie it to account login) and `vortex.hulu.com` (HaGeZi Pro blocks it; OISD excludes it as breaking the Samsung Hulu app). It adds no block rule, since every 2026 tracking name is blocked already. Its categories gain `Samsung TV Plus` (expected), `SmartThings`, `Voice and AI` and `Samsung unknown` (`sesupdate.com`, `acrapiprd*.trafficmanager.net`, the Gaming Hub image host), which block nothing and name what the brief lists, each with a plain label in `[category_labels]`. Its `[[lan_api]]` records describe the no-pairing REST reply and what the reader never keeps; its five newer `[[privacy_setting]]` records are the settings the owner confirms with `sudo tvgw tv confirm`. The TV is read every hour by `tvgw tvcheck`, which runs src/tvgw/tizen.py for this profile and no other; what each reading stores is in [`tvsettings`](../../../docs/reference/data-model.md#tvsettings).

Each `.rules` group lists its URLs. The Roku ACR group records a reported cost: one 2026 report lost the antenna TV guide with `*.logs.roku.com` blocked. Vizio's suspected ACR upload goes to `kinesis.us-west-2.amazonaws.com`, shared AWS infrastructure, which the profile categorizes as `ACR suspected (shared AWS)` and does not block.

## The general profile

`generic-tv` is the profile for a TV no vendor profile fits. Its description is `Any TV tvgw has no profile for: isolated, recorded and briefed; blocks only shared tracker lists`. The gateway isolates the TV, records it and writes the brief as for any TV; what the profile adds is little on purpose, since nothing is known about the TV behind it ([design decision 62](../../../docs/design-decisions.md#62-a-tv-gets-a-vendor-profile-only-on-evidence-or-its-owners-answer-otherwise-the-general-profile-which-isolates-records-briefs-and-blocks-only-shared-lists)).

- **Blocklists.** `[adguard] filters` names HaGeZi's DoH/VPN bypass list in its DoH-only form and HaGeZi Pro (`filter_48`), the two lists every DNS-only profile already subscribes. Each entry names its sentinel, `h4g3z1-doh.web.app` and `h4g3z1-pro.web.app`, which `tvgw verify` looks up. `strip_qtypes = ["HTTPS", "SVCB"]`, as in every profile.
- **No rules of its own.** `generic-tv.rules` holds a header comment only, there is no `[must_allow]`, no `[url_filter]`, no generation or hardware row and no LAN-API record. `tvgw-apply` builds LG's port wall only for `lg-webos`, so this profile gets the firewall every TV gets and nothing more.
- **The clock.** `[clock] model = "none"` and no `clock_hosts`: the brief raises no clock red line, since nobody knows where this TV takes its time from.
- **Categories.** `3rd-party ads`, `Streaming` and `Infra`, each a subset of what the three DNS-only profiles share; they name what the brief shows and block nothing. `Infra` leaves out `googleapis.com` and `amazonaws.com`, so those names, which carry vendors' own services on such TVs, show among the allowed names worth a look.
- **Support.** `[support] status = "not-yet-tested"`, with `you_check` and `[checklist] wifi_off` in plain words, and `wifi_off_confirmed = false`.

## Checking it

On your workstation, with the package installed by `make dev`:

```sh
tvgw profile --profile src/tvgw/profiles/lg-webos.toml                    # rules lint: clean
tvgw profile --profile src/tvgw/profiles/lg-webos.toml --webos 22 --model OLED65C2PUA
tvgw profile --profile roku                                                # a bundled name works too
tvgw profile --profile generic-tv                                          # support: Not yet tested
python3 -m pytest tests/unit/test_profile.py tests/unit/test_profile_records.py tests/unit/test_vendor_profiles.py
```

On the gateway, `tvgw profile` reads the installed profile and adds the hardware facts for the model the TV reported.

## Changing it

Edit the TOML or the `.rules` file, run `tvgw profile` (above) and `make gate`, and deploy, as [block or unblock something](../../../docs/use/blocking.md) describes. What the lint refuses, `$badfilter`, regex exceptions, rule forms it cannot read and `$dnstype` rules that withhold more than HTTPS, SVCB or AAAA among them, is listed in [lint](../../../docs/reference/profile-format.md#lint); `tvgw adguard diff` and `apply` run the same lint and refuse a profile that fails it. tests/unit/test_profile.py guards the profile: `test_lg_profile_lints_clean_and_generates_allow_rules` keeps the lint clean, `test_lg_categories` pins the categorizer, and `test_nginx_conf_matches_the_profile` fails until deploy/nginx/tvgw-gfts.conf and deploy/nginx/stream.conf agree with `[url_filter]`.

## Gotchas

- **Never write the generated rules in `.rules`.** The must-allow exceptions, the URL-filter rewrites and the record-type rule are generated, and `adguard_rules()` drops a written copy that equals one.
- **AdGuard matches CNAME targets too.** Several must-allow hosts CNAME into `aws-prd.net`, which also carries ad hosts, so the `aws-prd.net` rules are regexes on specific CNAME targets, and the lint refuses a block or rewrite at the zone's apex and a regex that matches across the zone (`/\.aws-prd\.net$/`). A broad block can still catch a must-allow host through its CNAME while the lint is clean; the brief's must-allow red line shows it.
- **Browser-engine pings count as ads.** `tools.google.com` and `stun.services.mozilla.com` are in `3rd-party ads` and blocked, so they appear in the category table and never in "Allowed, outside the expected categories" unless a rule stops blocking them.
- **The rewrites follow `GW_IP`; the listeners do not.** nginx, the firewall and dnsmasq hardcode `10.10.10.1`, so changing `GW_IP` alone moves the rewrites and not the URL filter.
- **The `.rules` file must exist.** An empty file blocks nothing, which is the capture phase of a new profile; a missing or unreadable one stops every command, because a profile loaded without its rules would lint clean and block nothing.
- **The TOML is checked as it loads.** A misspelt table name is refused (`profile.TABLES`), `Other` is reserved for unmatched names, and every name in `expected_categories` must be a category.
- **The first hardware row that matches answers.** `Profile.hardware_for()` returns the first row with a matching pattern. The 2021 row's `*QNED9*` and the 2022 row's `*QNED8*` match the later QNED model numbers first, so the QNED patterns of the 2023, 2024 and 2025 rows never answer. Every row involved says no far-field microphone; only the year and the grade come out wrong.
- **The reference tables change nothing that is blocked.** `[[generations]]`, `[[hardware]]` and `[checklist]` are what `tvgw profile` prints.
- **A must-allow host must resolve.** `tvgw verify` fails a must-allow host that does not answer, so an unverified host taken from an old report is checked with a lookup before it goes in; `otn.samsungcloudcdn.com` and `time.rokulabs.com` were left out on 2026-11-01 for that reason.
- **Discovery assigns a profile only on evidence.** No discovery row names the DNS-only profiles, so `tvgw discover --write` leaves `PROFILE` as it was for Roku and Vizio, for a Samsung that did not answer as a Samsung SmartTV, and for an LG that gave one signal, and says which `PROFILE` to set; `tvgw setup` asks instead. (samsung) A Samsung whose own REST reply says `Samsung SmartTV` gets `samsung-tizen` without a question ([let tvgw discover recognize the vendor](../../../docs/project/adding-a-profile.md#let-tvgw-discover-recognize-the-vendor)).
- **Machine rules stay out of this folder.** The rules the gateway adds on its own live in `AUTO_RULES`, and nothing writes to the profile's files at run time.
