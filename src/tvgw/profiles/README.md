# TV profiles

This folder holds the bundled TV profiles, each a TOML file and a companion `.rules` file, shipped inside the package. Every `tvgw` command loads the profile `PROFILE` names when it starts, and `tvgw adguard apply` turns that profile into AdGuard Home's lists and rules. What a profile is, and how to write one for another vendor, is in [adding a profile](../../../docs/adding-a-profile.md).

## Files

| File | What it is | Used by |
|---|---|---|
| `__init__.py` | Makes the folder a package, so `importlib.resources` finds the profiles inside the installed package. | `profile.load()` |
| `lg-webos.toml` | The LG webOS profile: metadata, categories, must-allow hosts, AdGuard blocklists, the URL filter, and the reference tables for webOS generations, hardware and a checklist. | `profile.load()`, `tvgw profile` |
| `lg-webos.rules` | The profile's AdGuard custom rules, one per line, in groups under dated comments. | `profile.load()`, `tvgw adguard` |

`[tool.setuptools.package-data]` in pyproject.toml ships `profiles/*.toml` and `profiles/*.rules`. `profile.load()` takes a bundled name (`lg-webos`) or the path of a `.toml` file. Either way the `.rules` file is the one with the same name beside it, found by the name asked for and never by `[profile].name`.

## The lg-webos profile

The profile as shipped. The format of each table is in [the profile format](../../../docs/adding-a-profile.md#the-profile-format).

### Metadata

- `name = "lg-webos"`, `vendor = "LG"`, and the description `LG webOS smart TVs (verified on CX / webOS 5)`.
- `expected_categories` are `Streaming`, `Infra` and `LG core`: the TV doing its job. An allowed name in any other category shows in the brief.
- `clock_hosts` are `??.lgtvsdp.com` and `??.nextlgsdp.com`, the country SDP hosts only. webOS takes its time from LG's SDP reply, and `rdx2.lgtvsdp.com`, under the same zone, is telemetry.
- `never_block_apex` lists `lgtvsdp.com`, `nextlgsdp.com`, `lgtvcommon.com`, `lge.com`, `lgappstv.com`, `lgeapi.com`, `aws-prd.net` and `wiselg.com`: zones where one block at the apex took out clocks, stores, casting or firmware.

### Categories

`strip_prefixes` removes `aic.`, `eic.`, `kic.` or `ruc.`, or the same with a hyphen, from the front of a name before it is matched. The longest matching pattern wins, and a name no pattern matches is `Other`.

| Category | What it holds | Expected |
|---|---|---|
| `ACR` | Screen fingerprinting: LG Ad Solutions (Alphonso), Samba TV, Nielsen. | no |
| `LG ads` | LG's ad, promotion, recommendation and shopping hosts, and the `aws-prd.net` CNAME targets of LG's ad hosts. | no |
| `LG telemetry` | webOS telemetry: the CDP beacons, the `rdx2` hosts, the telemetry collector, and the newer generations' counters. | no |
| `LG fingerprint` | Device fingerprinting and discovery: QuickSet, Philips Hue, an Azure IoT hub. | no |
| `LG IoT` | ThinQ and LG's IoT back-ends, and AWS IoT push. | no |
| `LG core` | The clock, firmware, the Content Store and the file service. | yes |
| `Voice` | Speech back-ends: Google Assistant, Alexa, Dangbei. | no |
| `3rd-party ads` | Ad servers, app analytics, audience measurement, and the browser engine's own pings. | no |
| `Streaming` | Video services and their CDNs. | yes |
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

`[url_filter] hosts` are `ngfts.lge.com`, `aic-ngfts.lge.com`, `aic-img-ngfts.lge.com` and `gfts.lge.com`. Each gets a generated `||host^$dnsrewrite=<GW_IP>` rule, so the TV's plain-HTTP requests to them reach nginx on the Pi. nginx returns 403 when the request URI matches `block_regex = 'biz_code=(PREMIUM|CDP|LGSHOPPING|MAS|IBS)([&_]|$)'`, case-insensitively: app packages and icons pass, while the ACR config, the telemetry schedule, LG Shopping data, promo thumbnails and the LG Channels guide are refused ([design decision 8](../../../docs/design-decisions.md#8-a-url-filter-for-lgs-file-service-instead-of-a-dns-block)). The boundary after the code keeps `MAS` from matching `MASTER` or `META_IMG`.

### The rules file

`lg-webos.rules` holds the blocks and the regex rules, in groups under `! ----` headings: ACR; LG ads; LG telemetry; device fingerprinting; third-party ads; the preinstalled apps' telemetry; ThinQ and IoT; voice back-ends; home-screen declutter; audience measurement; the newer webOS generations; and the names closed after later briefs. Each group carries the date and the evidence, and a block that costs a feature says so: blocking QuickSet and Philips Hue costs device setup and Hue sync on the TV ([design decision 16](../../../docs/design-decisions.md#16-quickset-and-hue-stay-blocked-with-the-cost-written-down)). A rule tried and rejected stays as a comment: blocking Prime Video's ad-pod service, `||aiv-delivery.net^`, did not stop its ads, which are stitched into the stream.

AdGuard's custom rules are built by `Profile.adguard_rules()` in this order: the generated must-allow exceptions, the URL-filter rewrites for `GW_IP`, the record-type rule for `TV_IP`, then the lines of the `.rules` file with comments, blank lines and copies of a generated rule dropped. `tvgw adguard apply` appends the machine's rules from `AUTO_RULES` after the same lint ([the analyst and autonomy](../../../docs/analyst-and-autonomy.md)).

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

## Where its evidence came from

The TOML's header and the `.rules` file's header name the sources:

- an LG CX (webOS 5.6.2, firmware 04.64.00) observed through this gateway in October 2026: its query log, its pcaps, and its LAN-API readings;
- HaGeZi's LG webOS list, Perflyst's Smart-TV list and hugobatista/lg-tv-ad-block;
- the IMC 2024 ACR study, arXiv 2409.06203;
- community captures of the newer webOS generations, gathered on 2026-10-26 from HaGeZi's and webosbrew's issue trackers, Level1Techs and the other sources the header names.

Only the CX is observed. Its rows are the one generation with `verified = true` and `confidence = "observed"`, webOS 5, and the one hardware row graded `observed`, `OLED*CX*` and `OLED*BX*`. Every other generation is `community`, and every other hardware row `spec` or `low`. In `[categories]` and the `.rules` file, an entry never seen on the CX carries "unverified" in its comment. The grades are defined in [the profile format](../../../docs/adding-a-profile.md#the-profile-format). The code does not check them, and a row without one reads as `low` ([design decision 15](../../../docs/design-decisions.md#15-blocklist-entries-come-from-evidence-with-grades)).

## Checking it

On your workstation, with the package installed by `make dev`:

```sh
tvgw profile --profile src/tvgw/profiles/lg-webos.toml                    # rules lint: clean
tvgw profile --profile src/tvgw/profiles/lg-webos.toml --webos 22 --model OLED65C2PUA
python3 -m pytest tests/unit/test_profile.py
```

On the Pi, `tvgw profile` reads the installed profile and adds the hardware facts for the model the TV reported.

## Changing it

Edit the TOML or the `.rules` file, run `tvgw profile` (above) and `make gate`, and deploy, as [changing policy](../../../docs/operations.md#changing-policy) describes. What the lint refuses, `$badfilter`, regex exceptions, rule forms it cannot read and `$dnstype` rules that withhold more than HTTPS, SVCB or AAAA among them, is listed in [lint](../../../docs/adding-a-profile.md#lint); `tvgw adguard diff` and `apply` run the same lint and refuse a profile that fails it. tests/unit/test_profile.py guards the profile: `test_lg_profile_lints_clean_and_generates_allow_rules` keeps the lint clean, `test_lg_categories` pins the categorizer, and `test_nginx_conf_matches_the_profile` fails until deploy/nginx/tvgw-gfts.conf and deploy/nginx/stream.conf agree with `[url_filter]`.

## Gotchas

- **Never write the generated rules in `.rules`.** The must-allow exceptions, the URL-filter rewrites and the record-type rule are generated, and `adguard_rules()` drops a written copy that equals one.
- **AdGuard matches CNAME targets too.** Several must-allow hosts CNAME into `aws-prd.net`, which also carries ad hosts, so the `aws-prd.net` rules are regexes on specific CNAME targets, and the lint refuses a block or rewrite at the zone's apex and a regex that matches across the zone (`/\.aws-prd\.net$/`). A broad block can still catch a must-allow host through its CNAME while the lint is clean; the brief's must-allow red line shows it.
- **Browser-engine pings count as ads.** `tools.google.com` and `stun.services.mozilla.com` are in `3rd-party ads` and blocked, so they appear in the category table and never in "Allowed, outside the expected categories" unless a rule stops blocking them.
- **The rewrites follow `GW_IP`; the listeners do not.** nginx, the firewall and dnsmasq hardcode `10.10.10.1`, so changing `GW_IP` alone moves the rewrites and not the URL filter.
- **The `.rules` file must exist.** An empty file blocks nothing, which is the capture phase of a new profile; a missing or unreadable one stops every command, because a profile loaded without its rules would lint clean and block nothing.
- **The TOML is checked as it loads.** A misspelt table name is refused (`profile.TABLES`), `Other` is reserved for unmatched names, and every name in `expected_categories` must be a category.
- **The first hardware row that matches answers.** `Profile.hardware_for()` returns the first row with a matching pattern. The 2021 row's `*QNED9*` and the 2022 row's `*QNED8*` match the later QNED model numbers first, so the QNED patterns of the 2023, 2024 and 2025 rows never answer. Every row involved says no far-field microphone; only the year and the grade come out wrong.
- **The reference tables change nothing that is blocked.** `[[generations]]`, `[[hardware]]` and `[checklist]` are what `tvgw profile` prints.
- **Machine rules stay out of this folder.** The rules the gateway adds on its own live in `AUTO_RULES`, and nothing writes to the profile's files at run time.
