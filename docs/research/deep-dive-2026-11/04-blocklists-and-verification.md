# 04. Blocklists: verified instead of trusted

*Deep-dive research, 2026-11-01. Proposal only: nothing here is built. It reads with [design decision 7](../../design-decisions.md#7-must-allow-exceptions-are-generated-from-the-toml), [15](../../design-decisions.md#15-blocklist-entries-come-from-evidence-with-grades) and [20](../../design-decisions.md#20-the-gateway-blocks-on-its-own-under-three-watches), and with [the October survey](../state-of-the-art-2026-10.md) §2, which it goes past and in places disagrees with ([where this disagrees with October](#where-this-disagrees-with-the-october-survey)).*

**Method.** AdGuard Home's source at `master` (2026-11-01), its CHANGELOG and OpenAPI file; the HostlistsRegistry repository and build workflow; the lists themselves, downloaded on 2026-11-01 from every place they are published and compared with a short script (AdGuard semantics for the DNS subset: `||d^` blocks `d` and its subdomains, a hosts line blocks the exact name only); older versions from jsDelivr's archive of release tags and the Wayback Machine; maintainers' issue trackers through the GitHub API; papers. Nothing touched the gateway. **(measured)** means I ran it against the published files on 2026-11-01. **(unverified)** means one weak source or none. Test commands for the gateway are written out; none was run.

---

## Bottom line

Today the three lists in `[adguard] filters` are the one part of the gateway's policy that changes without a review, a dated reason, a canary or a probation: AdGuard Home re-downloads each one every 24 hours, measured from the last attempt, so the time of day drifts. It swaps in whatever answers `200 OK`, with no check on the rule count and no signature to check (none exists), and the brief's "Rule changes" never sees it. That is an autonomous block channel with none of the watches decision 20 puts on the gateway's own model. The upstream risk is real and recent. On 2026-09-11 HaGeZi shipped a zone-wide `nextlgsdp.com` block that broke clocks and the Content Store on webOS 6+ sets in several countries, and fixed it the next day ([HaGeZi #11438](https://github.com/hagezi/dns-blocklists/issues/11438)). Perflyst's Smart-TV list has blocked every country's `<cc>.nextlgsdp.com` since 2026-09-09, and the breakage report on it is still open ([Perflyst #172](https://github.com/Perflyst/PiHoleBlocklist/issues/172)). Three cheap facts make verification practical. Every HaGeZi list carries a sentinel name (`h4g3z1-<list>.web.app`) that proves it is loaded. jsDelivr still serves past HaGeZi releases at immutable tag URLs, even though GitHub keeps only one commit and one tag. And the store already records which list blocked each lookup (`dns.filter_id`). Build in this order: a post-hoc "Lists changed what the TV gets" section from the store, sentinel and liveness checks in `tvgw verify`, a snapshot-and-diff of AdGuard's on-disk list files, and then, with the owner's approval, a staged promotion that holds a list version which newly blocks a name the TV used to carry content, adds an exception or modifier, or widens to a zone the profile protects. Do not add OISD, 1Hosts, Perflyst or the AdGuard DNS filter: each is redundant with HaGeZi Pro or, today, blocks a name tvgw must keep. No vetted per-service allowlist of CDN and DRM hosts exists. Netflix publishes its delivery zones and Google publishes its YouTube control hostnames, but the must-allow list has to come from this TV's own evidence, recorded in a breakage ledger.

---

## Findings

### F1. How AdGuard Home fetches and applies a list (settled from source)

All from `internal/filtering/filter.go`, `rulelist/parser.go` and `home/config.go` at `master` ([filter.go](https://github.com/AdguardTeam/AdGuardHome/blob/master/internal/filtering/filter.go), [parser.go](https://github.com/AdguardTeam/AdGuardHome/blob/master/internal/filtering/rulelist/parser.go), [config.go](https://github.com/AdguardTeam/AdGuardHome/blob/master/internal/home/config.go)):

| Question | Answer | Where |
|---|---|---|
| Interval | `filters_update_interval`, default `24` hours. Since v0.107.78 (2026-07-13) any value 0–8760 is accepted; `0` disables periodic updates ([CHANGELOG](https://github.com/AdguardTeam/AdGuardHome/blob/master/CHANGELOG.md)). tvgw does not own this key (observed: no match in `adguardcfg.py`). | `config.go` default; `ValidateUpdateIvl`; `periodicallyRefreshFilters` |
| When | A loop wakes about hourly and refreshes each enabled list whose `LastUpdated + interval` has passed. `LastUpdated` is loaded from the **file's mtime** at start, and is reset (with `os.Chtimes`) even when the download changed nothing or, in a partly failed batch, failed. So the refresh time drifts and is not under tvgw's control. If every list in a batch fails, the retry interval doubles. | `listsToUpdate`, `refreshFiltersArray`, `periodicallyRefreshFilters` |
| Fetch | `HTTPClient.Get`. Anything but `200` is an error and keeps the old file. The body is read through `LimitReader(max_http_size)`, default 256 MB (new in v0.107.78), which **truncates silently**. | `readFromHTTP` |
| Validation | Only two checks: the first non-empty line must not begin `<html` or `<!doctype` (case-insensitive), and no line may hold control bytes. **There is no minimum rule count, no change-size limit and no signature.** A `200` with an empty body parses to 0 rules, its CRC differs, and the empty list replaces the old one: fail-open for that list. | `processLine`, `isHTMLLine` |
| Change detection | CRC-32 (IEEE) over the trimmed rule lines. It detects change and gives no integrity. | `processLine` |
| What lands on disk | `<DataDir>/filters/<id>.txt` holds **rule lines only**: every `!` and `#` line, `! Version:` and `! Last modified:` included, is dropped. Only `! Title:` is read, to name the list. | `processLine`, `FilterYAML.Path` |
| Swap | A pending file in the same directory, then `renameio.CloseAtomicallyReplace`: atomic on Unix. An unchanged download is discarded. | `updateIntl`, `finalizeUpdate` |
| Apply | After any changed list, `EnableFilters(false)` rebuilds the whole engine **synchronously**, custom rules first. How long a 212k-rule rebuild takes on a Pi 5 is unverified. | `refreshFiltersIntl` |
| Local files | An absolute path is read instead of a URL, but only if it matches `filtering.safe_fs_patterns` (v0.107.53, 2024-10-03; the migration default is `$DATA_DIR/userfilters/*`). | `readFromFile`, CHANGELOG v0.107.53 |
| API | `GET /control/filtering/status` gives each list's `id`, `name`, `url`, `enabled`, `rules_count` and `last_updated`, plus `interval`. `POST /control/filtering/refresh` forces a refresh. `GET /control/filtering/check_host?name=&client=&qtype=` returns `rules[].filter_list_id` and `rules[].text`. There is **no field for a list's upstream version, checksum or diff** ([openapi.yaml](https://github.com/AdguardTeam/AdGuardHome/blob/master/openapi/openapi.yaml)). The API needs the web credentials; the files do not. | |
| Modifiers in lists | `$dnsrewrite` "works in all rules" in AdGuard Home, filter lists included, and "rules with the dnsrewrite response modifier have higher priority than other rules" ([AdGuard DNS filtering syntax](https://adguard-dns.io/kb/general/dns-filtering-syntax/)). The registry strips `$dnsrewrite` from untrusted lists; a list fetched directly is not stripped. Whether `@@||host^$important` beats a list's `$dnsrewrite` for the same host is **unverified**. | |

**Consequence for tvgw.** Of the three lists, two come through AdGuard's registry and one, the DoH list, straight from jsDelivr. A compromised or broken DoH list could carry `$dnsrewrite` rules that the registry would have stripped. The must-allow `@@...$important` exceptions protect nine names against a block, and may or may not protect them against a rewrite.

### F2. Where tvgw's lists actually come from, and how fresh they are

The chain for `filter_48` (HaGeZi Pro) and `filter_72` (HaGeZi LG webOS) has four hops, each with its own cadence:

1. **HaGeZi** rebuilds "several times a day" from a private database of about 45 million domains. GitHub, GitLab and Codeberg get one build a day at 11:00 UTC; the build mirror at dnsbunker.org gets every build ([README, mirrors](https://github.com/hagezi/dns-blocklists#mirrors); [FAQ §11](https://github.com/hagezi/dns-blocklists/blob/main/FAQ.md)). The GitHub repository holds **one parentless commit and one release tag** (`37522026.305.38528` on 2026-11-01), so git keeps no history to diff (measured: `commits?per_page=5` returns 1, `parents: []`). The commits are unsigned (measured: `verification.reason = unsigned`). Each release body lists the issue numbers it closes.
2. **jsDelivr** resolves `@latest` to the newest semver tag, caches version aliases for 7 days unless the author purges, and keeps tagged files permanently ([jsDelivr README, caching](https://github.com/jsdelivr/jsdelivr#caching)). Today's `@latest` was 3 h old and matched the release (measured: `x-jsd-version: 37522026.305.38528`, `age: 11011`). **Older tags still resolve** even though GitHub deleted them (measured: `@37522026.266.58003`, the 2026-09-23 release, returned 200 with `! Version: 2026.0923.1325.47`). jsDelivr is therefore a practical, immutable archive for pinning and diffing.
3. **AdGuard HostlistsRegistry** rebuilds every hour (`cron: "0 * * * *"`) with `@adguard/hostlist-compiler`: `RemoveModifiers`, `Validate` (drops TLD-wide rules such as `||*.org^`, too-short rules, IPs, `$domain` rules), `RemoveComments`, `Deduplicate`, `Compress` (drops a subdomain rule when its parent is listed) ([workflow](https://github.com/AdguardTeam/HostlistsRegistry/blob/main/.github/workflows/workflow.yml), [configuration.json for filter 72](https://github.com/AdguardTeam/HostlistsRegistry/blob/main/filters/other/filter_72_HageziLGwebOSTrackerBlocklist/configuration.json), [compiler README](https://github.com/AdguardTeam/HostlistCompiler#transformations)). The registry writes a header of its own and bumps its version only when the content changes. Today `filter_72` says `Version: 1.0.0.6, Last modified: 2026-10-17`, while HaGeZi's file says `Version: 2026.1030.2308.00`. The 231 domains are identical (measured). **So the registry's date is when the content last changed, and HaGeZi's is when it last rebuilt.** The previous survey quoted HaGeZi's version; AdGuard never sees that header (F1).
4. **AdGuard Home** on the Pi, every 24 h from the last attempt (F1).

A HaGeZi change therefore reaches the TV between about 1 and 25 hours after 11:00 UTC, at a time of day that drifts. A bad push and its fix the next day each take that long, so a bad push can be live for close to two days, often at night when the canary has nothing to watch.

**Churn, measured from archived versions.** HaGeZi Pro went from 225,658 entries (2026-09-23) to 211,739 (2026-11-01): 55,835 removed and 41,916 added in 39 days, about 1,400 changes a day, or 0.7% a day. The LG list went from 341 entries (2026-08-21) to 229 (2026-09-25), with 171 removed and 59 added during the September LG rework, and then to 231 by 2026-10-30, with 1 removed and 3 added. Day-to-day spread is unmeasured, because I had only these snapshots.

**Redundancy, measured.** 230 of the LG list's 231 entries are already blocked by HaGeZi Pro, by the entry itself or a parent. The one left over is the sentinel `h4g3z1-native-lgwebos.web.app`. This matches HaGeZi's statement that native tracker lists are "integrated across all the standard tiers" ([README, native](https://github.com/hagezi/dns-blocklists#native)). `filter_72` adds no coverage. It does add attribution in the query log, and a second sentinel.

**Sentinels.** Each HaGeZi list carries one name of its own (measured): `h4g3z1-pro.web.app`, `h4g3z1-native-lgwebos.web.app`, `h4g3z1-doh.web.app`, `h4g3z1-pro-plus.web.app`, `h4g3z1-ultimate.web.app`. None of the other lists I downloaded contains them. I found no HaGeZi document that explains them, so their stability is unverified.

**Mirrors agree.** For `native.lgwebos.txt`, GitHub raw, jsDelivr `@latest`, Codeberg (`codeberg.org/hagezi/mirror2/raw/branch/main/dns-blocklists/...`) and GitLab (`gitlab.com/hagezi/mirror/-/raw/main/dns-blocklists/...`) served byte-identical bodies on 2026-11-01 (measured, 8,613 bytes, same version line). With no signatures, a two-of-three agreement between independently hosted copies is the strongest check on offer.

### F3. How each list is built and QA'd in 2026

| List | Built from | False-positive process | Cadence | Integrity | Licence |
|---|---|---|---|---|---|
| **HaGeZi** (Pro, LG native, DoH) | Private curated database; upstream lists are "an input to the build, not something that gets pulled in whole"; wildcards are expanded against Top-1M/10M datasets into concrete names; tiered by "expected compatibility impact" ([FAQ §11](https://github.com/hagezi/dns-blocklists/blob/main/FAQ.md)) | GitHub issues with templates (`allow`/`deny` labels, prerequisites "disabling these lists resolves the issue"); a bot closes the issue when the fix ships in a named release ([#11544](https://github.com/hagezi/dns-blocklists/issues/11544)); a public lookup tool | GitHub once a day at 11:00 UTC; build mirror every 4–8 h | None: unsigned single commit; jsDelivr tags immutable; three mirrors | GPL-3.0, plus a German-law disclaimer that requires the licence to accompany redistribution ([Disclaimer](https://github.com/hagezi/dns-blocklists#disclaimer)) |
| **AdGuard registry copies** (`filter_48`, `filter_72`) | Recompiled from jsDelivr `@latest` hourly (F2) | Registry rules: at least 10 updates a month, a place for complaints, lists with "too many problematic rules" not added ([HostlistsRegistry README](https://github.com/AdguardTeam/HostlistsRegistry#what-blocklists)) | Hourly build | `revision.json` has a `hash` field; its algorithm is undocumented (unverified) | GPL-3.0 (repository) |
| **AdGuard DNS filter** (`filter_1`) | AdGuard Base, Tracking Protection, Mobile, EasyList, EasyPrivacy, simplified for DNS ([AdGuardSDNSFilter](https://github.com/AdguardTeam/AdGuardSDNSFilter)) | `Filters/exclusions.txt` (1,100 lines) and `exceptions.txt` (448), **each exclusion preceded by the issue URL that justified it** | Many builds a day (2026-11-01 14:09 UTC build observed) | None | GPL-3.0 |
| **OISD** (big/small) | "I combine lists, remove domains that do not resolve, remove false positives"; the build process is closed ([oisd.nl/faq](https://oisd.nl/faq)) | Report form; a public excludes page; false positives are not reported upstream | "At least once every 24 hours"; dead domains pruned every 5 days | None | GPL-3.0 ([LICENSE](https://github.com/sjhgvr/oisd/blob/main/LICENSE)) |
| **1Hosts** (Lite) | Aggregated | Issues: false-positive reports still arrive (#4648–#4653, 2026-10-25 to 10-31) | **Last release v8.09.02 on 2026-09-03; nothing since in 59 days** (measured from the commit API); no announcement found | None | MPL-2.0 |
| **Perflyst Smart-TV** (`SmartTV.txt`, hosts; `SmartTV-AGH.txt`, adblock) | Community pull requests, merged by hand | Issues, slow: [#172](https://github.com/Perflyst/PiHoleBlocklist/issues/172) (Content Store and casting broken by the 2026-09-09 country-code additions) is open | Irregular: commits 2026-09-09, 2026-03-14, 2025-11-17, then 2023 | None | MIT (repository). The AGH file's header credits Dandelion Sprout, whose own repository uses the Dandelicence ([LICENSE.md](https://github.com/DandelionSprout/adfilt/blob/master/LICENSE.md)), so its provenance is ambiguous |
| **furkan-bayrak/lg-tv-blocklist** (new, not in the October survey) | Captures of one LG G1 in Germany; each entry annotated with its evidence; SAFE and STRICT tiers; a breakage issue template ([README](https://github.com/furkan-bayrak/lg-tv-blocklist)) | Issues; [methodology](https://github.com/furkan-bayrak/lg-tv-blocklist/blob/main/docs/methodology.md) | Last update 2026-10-30 | Publishes `lists/SHA256SUMS` (measured: matches), on the same origin and unsigned | CC BY 4.0 (lists), MIT (scripts) |
| **Watching the Watchers** (PoPETs 2027) | Lab study of eight US TV OSes; `[VALIDATED]`/`[SUSPECTED]` tiers; flags the one entry that breaks free channels (Amagi) and leaves it off ([Blocklist.txt](https://github.com/IlgarNEU/Watching-the-Watchers/blob/main/Blocklist/Blocklist.txt)) | Artifact, not a maintained list | Point in time | None | CC BY-NC-ND 4.0 |

### F4. Every candidate list checked against what tvgw must keep (measured)

Thirty-eight names were each checked against every list: the nine must-allow hosts, the URL-filter hosts, and a sample of Netflix, Disney+, Prime Video, YouTube, Max, Peacock and DRM hosts. The script is reproducible: AdGuard semantics for `||d^` and for hosts lines; regex and wildcard rules are counted but not evaluated.

| List | Blocks a must-allow or protected zone? | Streaming sample hits |
|---|---|---|
| HaGeZi LG (`filter_72`) | none | none |
| HaGeZi Pro (`filter_48`) | none | `ichnaea.netflix.com`, `fls-na.amazon.com`, `unagi-na.amazon.com`, `api.us-east-1.aiv-delivery.net` (all telemetry or ads by their names; the TV plays Prime Video with Pro on, observed in October) |
| HaGeZi DoH | none | none |
| Perflyst `SmartTV-AGH.txt` | **`||lgtvcommon.com^`** (an apex in `never_block_apex`) and `aic-ngfts.lge.com` (a URL-filter host); also 9 `@@` exceptions (HbbTV, Panasonic) | `ichnaea.netflix.com` |
| Perflyst `SmartTV.txt` | **`us.nextlgsdp.com`, `ngfts.nextlgsdp.com`, `aic-gfts.nextlgsdp.com`** (must-allow for webOS 6+), `aic-ngfts.lge.com` | `ichnaea.netflix.com` |
| 1Hosts Lite | **`||nextlgsdp.com^`** (apex) | `api.us-east-1.aiv-delivery.net` |
| OISD big/small | none | none |
| AdGuard DNS filter | none (373 wildcard and 495 other rules not evaluated) | `ichnaea.netflix.com` |
| furkan-bayrak SAFE | `ca.nextlgsdp.com`, `de.nextlgsdp.com` (country SDP hosts; must-allow for webOS 6+ per HaGeZi #11438, while the G1 audit reports the Content Store working) | none |
| furkan-bayrak STRICT | every LG must-allow host, by design (its README says so) | none |

Two lessons. First, community evidence about `<cc>.nextlgsdp.com` conflicts: HaGeZi #11438 and Perflyst #172 say blocking it breaks the clock, the store or casting, and the G1 audit says SAFE works. Region and firmware probably decide (unverified). Only this TV's own evidence can settle it for this TV. Second, an exception in any enabled list beats tvgw's own plain `||host^` blocks, because AdGuard gives `@@` precedence over a block without `$important` ([syntax](https://adguard-dns.io/kb/general/dns-filtering-syntax/)). The three lists in use carry **zero** exceptions and zero modifiers today (measured), which makes "a new `@@` or `$` appeared" a precise, almost free hold condition.

### F5. Known incidents of bad list pushes

| Date | List | What happened | Time to fix | Source |
|---|---|---|---|---|
| 2026-09-11 | HaGeZi native LG / Pro++ | `*.nextlgsdp.com` added; webOS 6+ sets lost automatic time ("many apps fail") and the Content Store in Spain and India; `*gfts.nextlgsdp.com` removed the same day, `in.*` the next | about 1 day | [#11438](https://github.com/hagezi/dns-blocklists/issues/11438) |
| 2026-09-23 | HaGeZi Normal (via ControlD) | LG Channels failing on three TVs in Brazil; partly unblocked, ad hosts kept; fixed in release `37522026.266.58003` | same day | [#11544](https://github.com/hagezi/dns-blocklists/issues/11544) |
| 2026-09-09 → open | Perflyst `SmartTV.txt` | every country's `<cc>.nextlgsdp.com` added; Content Store blocked and Google Cast broken | open since 2026-10-03 | [#172](https://github.com/Perflyst/PiHoleBlocklist/issues/172), [commit history](https://github.com/Perflyst/PiHoleBlocklist/commits/master/SmartTV.txt) |
| 2026-09-03 → | 1Hosts | releases stop; false-positive reports pile up unanswered (a frozen list looks healthy to AdGuard) | n/a | [commits](https://github.com/badmojr/1Hosts/commits/master), [issues](https://github.com/badmojr/1Hosts/issues) |
| 2023-05-01 | HaGeZi Normal/Pro | `aic-gfts.lge.com` broke LG app installs and updates (Netflix requires the latest version) | same day | [#995](https://github.com/hagezi/dns-blocklists/issues/995) |
| 2021-12-01 | Perflyst | `us.lgtvsdp.com` blocked: clock reset to 2019 after a cold boot, TLS failures | 15 days | [#117](https://github.com/Perflyst/PiHoleBlocklist/issues/117) |
| undated ("some years ago") | OISD | an included upstream list carried a major domain; "within hours, false positive reports rolled in" and it was excluded | hours | [oisd.nl/faq](https://oisd.nl/faq) |

I found no documented incident of an empty or truncated list being served with a 200 to AdGuard Home users (searched; unverified either way). F1 shows AdGuard would accept one, and tvgw's own `tvgw-doh-update` already refuses fewer than 50 entries for exactly that reason.

### F6. The DoH IP list: mostly handled, one gap

`tvgw-doh-update` drops every address inside `/etc/tvgw/doh-exclude.txt` (CloudFront and Cloudflare CIDRs) and keeps only prefixes of /16 or longer. Measured on 2026-11-01: HaGeZi's `ips/doh.txt` has 1,430 entries; 12 are CloudFront edge IPs, and all 12 fall inside the shipped exclusions. Six are AWS Global Accelerator addresses (`3.33.0.0/16`, `13.248.0.0/16`, `15.197.0.0/16`, `76.223.0.0/16` space) that the file does not exclude. Global Accelerator addresses are static and assigned to one accelerator ([AWS docs](https://docs.aws.amazon.com/global-accelerator/latest/dg/introduction-components.html)), so a false block is unlikely (unverified for these six). None fall in Fastly's ranges, and 17 are Google addresses, `8.8.8.8` among them. The gap: `doh-exclude.txt` is a static snapshot of [ip-ranges.json](https://ip-ranges.amazonaws.com/ip-ranges.json) (its `syncToken` was 1793532425 on 2026-11-01) and of [Cloudflare's list](https://www.cloudflare.com/ips-v4). CloudFront adds ranges, so the snapshot ages.

### F7. Detecting that a DNS block broke an app: what the literature offers

- **Varmarken et al., PoPETs 2020**, ran 10 Roku and 10 Fire TV apps once under each of four blocklists and graded breakage by eye: *none*, *minor* ("main content remains available but the application suffers from minor user interface glitches") and *major* ("the app's content becomes completely unavailable or the app fails to launch"). No list blocked every ad without breaking something ([paper](https://www.petsymposium.org/popets/2020/popets-2020-0021.pdf), [ar5iv](https://ar5iv.labs.arxiv.org/html/1911.03447)). tvgw's ledger should reuse this three-level scale so its entries compare with the literature.
- **Mandalari et al., PoPETs 2021 ("Blocking without Breaking")** automated the whole loop. Power-cycle, trigger the function, probe; for streaming devices the probe is "the maximum data over any 20-second window" compared with a threshold halfway between the activation peak and the background peak. At least 10 iterations, 80% agreement. Each destination is blocked in turn, and one whose blocking leaves the function working is non-required. 91% of the non-required destinations appear on no blocklist, and none of the required ones does. Three devices *needed* a destination that another device could do without ([PoPETs](https://www.petsymposium.org/popets/2021/popets-2021-0075.pdf), [ar5iv](https://ar5iv.labs.arxiv.org/html/2105.05162)). The probe is a sharper version of tvgw's canary (a fifth of the baseline rate, three readings). The cross-device result is why a list's "safe" entry is only a hypothesis for this TV.
- **Smith et al., PoPETs 2022 ("Blocked or Broken?")** trained a classifier on EasyList compatibility reports plus browser instrumentation (AUC 0.88, 2,662 labelled recordings), and found list maintainers to be "overly conservative and still error-prone" ([PoPETs](https://www.petsymposium.org/popets/2022/popets-2022-0096.php)). It applies to the web, not to TVs, but it supports the gate below: predict a rule's breakage risk from how the client *used* the name, before the rule ships.
- **Watching the Watchers, PoPETs 2027** reports that blocking validated ACR endpoints "does NOT affect normal streaming/playback", except the Amagi FAST host ([list header](https://github.com/IlgarNEU/Watching-the-Watchers/blob/main/Blocklist/Blocklist.txt)).
- **Pi-hole community data** is thin and old. The "Commonly Whitelisted Domains" wiki (created 2016, anyone can edit) has no LG, Netflix, Prime Video, Disney+, Max or Peacock entries. Its YouTube entries (`s.youtube.com`, `video-stats.l.google.com`) restore watch history, which is a privacy choice and not a playback need ([Pi-hole discourse](https://discourse.pi-hole.net/t/commonly-allowlisted-domains/212)). anudeepND's MIT whitelist was archived on 2024-03-19 ([repo](https://github.com/anudeepND/whitelist)).
- No 2025–2026 paper measures smart-TV blocklist breakage automatically (searched; the newest are the three above).

Signals tvgw can compute from what it already has, best first: (1) **the throughput probe after a list change**, the canary's existing logic and Mandalari's 20-second-window rule; (2) **foreground app gives way to the launcher** within minutes of a newly blocked lookup (the canary reads this already); (3) **a blocked name the TV used to download real bytes from** (the inverse of decision 20's payload gate: a block cannot be telemetry-only when the name carried content); (4) **retry storms**: an app that hammers a newly blocked name in the minutes before an app switch. Telemetry backs off on timers; a hard dependency is retried at once and then abandoned. That pattern is folklore, not measured (unverified), and worth measuring with the canary.

### F8. Vetted allowlists for streaming playback: there are none at host level

| Source | What it gives | Use as must-allow? |
|---|---|---|
| Netflix Open Connect `mobiledeliverydomains.txt` (vendor) | 7 zones: `netflix.com`, `nflxext.com`, `nflximg.net`, `nflximg.com`, `nflxsearch.net`, `nflxso.net`, `nflxvideo.net` ([file](https://openconnect.netflix.com/mobiledeliverydomains.txt), measured 200) | No. `netflix.com` covers `ichnaea.netflix.com` and `customerevents.netflix.com`, which the profile blocks. Use it as **zone provenance**: a list change inside these zones needs review |
| Google Workspace, YouTube network control | `www.youtube.com`, `m.youtube.com`, `youtubei.googleapis.com`, `youtube.googleapis.com`, `www.youtube-nocookie.com` ([Google](https://knowledge.workspace.google.com/admin/youtube/control-youtube-content-available-to-users)) | Candidates, with vendor provenance: `youtubei.googleapis.com` is the app API. Video hosts (`*.googlevideo.com`) are not named |
| AdGuard `services/*.yml` (blocked-services registry, GPL-3.0) | Apex rules per service: `disneyplus.yml` names `disney.playback.edge.bamgrid.com` and `media.dssott.com`; `amazon_streaming.yml` names `atv-ps.amazon.com`, `aiv-delivery.net`; `peacock_tv.yml` names `peacocktv.com`, `peacock.com`; **Max is under `hbomax.yml`** (`max.yml` is the Russian messenger `max.ru`) ([services](https://github.com/AdguardTeam/HostlistsRegistry/tree/main/services)) | No: built to block a whole service, so too broad, and GPL. Useful as a zone map for the collision check, cited and not copied |
| AdGuard DNS filter `exclusions.txt` | Rules removed for breakage, each with an issue URL: `||bamgrid.com^` (issue 254), `fls-na.amazon.com`, `||s.youtube.com^` ("unbreak YT search history") ([exclusions.txt](https://github.com/AdguardTeam/AdGuardSDNSFilter/blob/master/Filters/exclusions.txt)) | The best *format* to copy (rule plus provenance URL); the content is GPL |
| DRM licence servers (Widevine, PlayReady) | Per service, behind each app's own API; no public list found. Widevine needs a certificate request and a licence request to the same service ([Axinom docs](https://docs.axinom.com/services/drm/license-service/license-service-management-api/widevine-data-sets)) | Only from captures: the hosts the TV contacted in the seconds before the first large download of a session |

The must-allow list therefore has to grow from this TV: hosts that preceded the first content-sized flow of each streaming session, seen on at least N sessions. They become `must_allow` *candidates* with provenance `observed`, and the owner promotes them.

### F9. Licensing for an MIT repository (not legal advice)

- **Citing** a list by name and URL, or linking an issue, copies nothing. Always fine.
- **Individual domain names are facts.** In the US, facts are not copyrightable, and a compilation is protected only for an original "selection, coordination, or arrangement" (*Feist v. Rural*, 499 U.S. 340 (1991), [Cornell LII](https://www.law.cornell.edu/supremecourt/text/499/340)). In the EU, where HaGeZi is based, the database right of Directive 96/9/EC Art. 7 forbids extracting a *substantial part*, and Art. 7(5) also forbids "repeated and systematic extraction" of insubstantial parts that adds up to one ([Art. 7 text](https://www.legislation.gov.uk/eudr/1996/9/article/7); *Directmedia*, C-304/07, [judgment](https://www.ippt.eu/sites/ippt/files/2008/IPPT20081009_ECJ_Directmedia_v_Albert-Ludwigs-Universitat_Freiburg.pdf)). A rule tvgw writes because *this TV contacted the name* is tvgw's own observation. A rule copied because a list has it is extraction.
- **Per licence:** GPL-3.0 (HaGeZi, OISD, AdGuard DNS filter, registry, hugobatista): link only; never vendor list text into the repo or a test fixture. MPL-2.0 (1Hosts): file-level copyleft, so a copied entry makes that file MPL. MIT (Perflyst repo): copy with the notice "Copyright (c) 2018 Perflyst"; the AGH file's Dandelion credit is ambiguous, so treat it as cite-only. CC BY 4.0 (furkan-bayrak): copy with attribution. CC BY-NC-ND 4.0 (Watching the Watchers): cite only, no derivatives. Netflix's file and Google's page: cite.
- **Runtime downloads** on the Pi are use, not redistribution. Snapshots kept under `/var/lib/tvgw/lists/` stay private. A list diff printed in the brief stays private. **Test fixtures in CI must be synthetic** (example.com names), never slices of real lists.
- **One item to clean up:** `lg-webos.rules` keeps three LG ad hosts "from the Perflyst Smart-TV and hugobatista/lg-tv-ad-block lists (2026-10-25); never seen on this TV" (`ad.lgappstv.com`, `ibis.lgappstv.com`, `lgad.cjpowercast.com.edgesuite.net`). hugobatista is GPL-3.0. Three names is far from a substantial part. Even so, decision 15 already asks for evidence, so either re-ground them on this TV's evidence or mark each one `source: Perflyst (MIT)`.

---

## Design: the list-diff review

### Two stages, one evidence model

**Stage A, observe (read-only, no change to filtering).** Each hourly `tvgw ingest` gains a `lists` step:

1. For every enabled filter in `AdGuardHome.yaml`, read `<DataDir>/filters/<id>.txt` (rules only; F1) and its mtime. Hash it (SHA-256).
2. On a new hash, store the version: `list_version(filter_id, name, url, seen_t, sha256, rules, file_mtime)`. Keep the rule set gzipped under `/var/lib/tvgw/lists/<filter_id>/<sha256>.txt.gz`; 30 versions of Pro come to about 50 MB (1.7 MB each gzipped). Separately, record the upstream header: an HTTPS `Range: bytes=0-2047` request to the source URL (HaGeZi `! Version` / `! Last modified` / `! Number of entries`), at most once a day per list.
3. Compute the **effective delta on the names that matter**, not a line diff. `Compress` turns a widening into "children removed, parent added", so a line diff misleads.

   *Names that matter*, `N` = every `qname` the TV looked up in the last 30 days ∪ the CNAME targets in their answers (AdGuard matches CNAMEs too) ∪ `[must_allow]` ∪ the clock hosts instantiated for the TV's country ∪ `[url_filter].hosts` ∪ concrete names in `Streaming`, `Infra` and `LG core`.

   For each `n` in `N`, `covered_old(n)` and `covered_new(n)`: an ancestor walk over the `||d^` set, exact match over hosts lines, and compiled regexes for `/re/` (case-insensitive, as decision 7 already does). A rule with `*` or a modifier that the walk cannot evaluate makes the name `unknown`, which counts as a change.
4. Write `list_delta(filter_id, from_sha, to_sha, kind, name, rule, tv_lookups_30d, down_14d)`, where `kind` is one of:
   - `newly_blocked`: covered now, not before.
   - `newly_allowed`: the reverse. A list stopped blocking a name the TV uses. The profile's comment "upstream lists change several times a day, so anything we rely on being blocked is also here" exists because of this.
   - `widening`: an added rule `||d^` where `d` is an apex in `never_block_apex`, an ancestor of a must-allow host, the registrable domain (Public Suffix List eTLD+1) of a name in `N`, or a parent of at least 2 names in `N`, or one that replaced child rules of the previous version.
   - `must_allow`: a must-allow host is now covered. It is held by `$important`, so this is a report, not breakage; but a covered *parent* catches the siblings, such as `in.nextlgsdp.com` in #11438.
   - `exception_added`: any `@@` rule (the lists in use have none today; F4).
   - `modifier_added`: any rule containing `$` in a list that had none (F1, `$dnsrewrite`).
   - `volume`: rule count moved past the thresholds below.
5. **A post-hoc cross-check that needs no snapshot at all**, from the query log already in the store. A list addition shows as a name's *first* blocked lookup with `filter_id <> 0` (0 is the custom rules: the profile and `auto.rules`) after answered lookups of the same name:

```sql
-- names a list began blocking in the window that the TV had been resolving
WITH lb AS (
  SELECT qname, filter_id, rule, min(t) AS since
  FROM dns WHERE blocked = 1 AND filter_id IS NOT NULL AND filter_id <> 0
  GROUP BY qname, filter_id, rule)
SELECT lb.qname, lb.filter_id, lb.rule, lb.since,
       (SELECT count(*) FROM dns d
         WHERE d.qname = lb.qname AND d.blocked = 0
           AND d.t BETWEEN lb.since - 30*86400 AND lb.since) AS answered_before
FROM lb
WHERE lb.since >= :start AND lb.since < :end AND answered_before > 0;
```

   And its mirror, a name last blocked by a list before the window and answered inside it. Both are cheap enough to run in every brief.

**Stage B, gate (changes where AdGuard reads its lists; owner approval needed).** A `tvgw-lists` timer fetches each list itself, applies the holds below, and *promotes* an accepted version to a local file `$DATA_DIR/userfilters/<slug>.txt`. `tvgw adguard apply` then points each `filters[].url` at that absolute path and owns `filters_update_interval: 1`, so AdGuard re-reads only the local, already-vetted file within the hour. An unchanged file costs nothing (F1: unchanged CRC is discarded). If the promoter breaks, lists go **stale, never unvetted**, and a staleness red line says so.

- **Fetch.** HTTPS only, `--max-filesize` per list. HaGeZi lists at the **pinned tag**, `cdn.jsdelivr.net/gh/hagezi/dns-blocklists@<tag>/adblock/<list>.txt`, the tag from `api.github.com/repos/hagezi/dns-blocklists/releases/latest`. Cross-check the SHA-256 against the Codeberg and GitLab mirrors and require two of three. They publish in sync once a day, so on a mismatch retry the next hour. Registry-only lists come from `adguardteam.github.io/HostlistsRegistry/assets/filter_<n>.txt`. Keeping the registry hop for Pro and LG is worth considering, because its `Validate` drops TLD-wide rules and `$dnsrewrite`. The DoH list has no registry copy, so tvgw has to do the stripping itself.
- **Timing.** `OnCalendar=*-*-* 12:30 UTC`, `RandomizedDelaySec=20min`, an hour and a half after HaGeZi's 11:00 UTC publication, early morning in US Central time. Promotion then always happens at a known time, with a whole day of the hourly judge's probation after it. AdGuard's drifting 24-hour cycle no longer decides it.
- **Hold if** (proposed thresholds; run Stage B in report-only mode for two weeks and calibrate on its own logs):
  - parse failure, first line HTML, control bytes, **0 rules**, or a body under 50% of the previous size (fail-stale);
  - the header's `Number of entries` differs from the parsed count by more than 1%, a free self-consistency check (measured equal today: LG 231/231);
  - the sentinel name is missing from a HaGeZi list;
  - rule count changed by more than **3%** for Pro since the last promoted version (about 4 times the measured 0.7% a day), more than **10% or 15 entries** for the LG list (the September rework, −171/+59, would have been held for review, which is what you want), or more than 10% for DoH;
  - any `exception_added` or `modifier_added`;
  - any `widening` over a `never_block_apex` zone or an ancestor of a must-allow host;
  - any `newly_blocked` name whose shape over the last 14 days carried content: median down over 16 KB per connection or more than 2 MB in total. These are decision 20's payload limits read in reverse. A list cannot know what a name means to this TV; the shape can.
- **Report, don't hold:** `newly_blocked` names without content shape, `newly_allowed`, `must_allow` (held by `$important`).
- **After promotion:** if the TV is streaming, run the existing 10-minute canary (`autoblock` code) on the promotion as if it were one block. On collapse, restore the previous file. That puts list changes under the same three watches as the machine's own rules.
- **Owner commands:** `tvgw lists` (versions, holds, deltas), `tvgw lists accept <list>` (promote a held version), `tvgw lists rollback <list>` (back to the previous promoted file), `tvgw lists pin <list> <tag>`.

### How it shows in the brief

A section after "Rules the gateway added on its own", printed only when something changed, plus two red lines. Names below are illustrative:

```text
List changes:
  HaGeZi Pro   2026.1101.0947 -> promoted 07:31 (+1204 -1876 rules); TV names affected: 3
    newly blocks  api.example-cdn.net        412 lookups/30d, 3.9M down/14d   HELD: carried content
    newly blocks  beacon.example-tv.net       38 lookups/30d, 4K down/14d
    newly allows  metrics.example.com         40 lookups/30d (now answered)
  HaGeZi LG    unchanged since 2026-10-17 (content), rebuilt 2026-10-30
  HaGeZi DoH   2026.1101.1028 promoted 07:31 (+6 -2)
RED LINE: list update held: HaGeZi Pro (newly blocks a name that carried content: api.example-cdn.net)
RED LINE: blocklist stale: HaGeZi LG sentinel missing / no promoted version for 4 days
```

The analyst's pack gains `list_changes` (names, kinds, shapes; no addresses), so a held change can be judged by the same two-model process instead of by hand.

### Liveness, which would have caught 1Hosts

A list is *stale* when its upstream release (HaGeZi: `releases/latest.published_at`; others: the newest `Last modified` header or the registry's `revision.json.timeUpdated`) is older than **7 days** while the list's registry entry says `expires: "4 days"`. HaGeZi's own header says `Expires: 8 hours`; a list that legitimately stops changing content still rebuilds daily (F2). Stale is a line in the brief; at **14 days** it becomes a red line. 1Hosts would have shown stale from 2026-09-10 and red from 2026-09-17.

---

## The breakage ledger

One record per observed effect of a block, good or bad, kept as `[[breakage]]` tables in the profile. That fits profiles v2, which is in flight and is the place for it, so coordinate with that branch. The store mirrors the records into a `breakage` table so the brief, the analyst and the hourly judge can read them. Negative results ("blocked, nothing broke") are first-class: they are what lets the gate say *low risk* with evidence.

```toml
[[breakage]]
id         = "gfts-block-prime-update-2026-10-25"   # stable slug
observed   = 2026-10-25                              # date first seen
name       = "ngfts.lge.com"                         # exact host the rule hit
rule       = "||ngfts.lge.com^"                      # rule text as applied
source     = "profile"            # profile | machine | list:<filter name>@<version> | community
effect     = "major"              # none | minor | major  (Varmarken et al. 2020 scale)
feature    = "Content Store app updates"
symptom    = "Prime Video update failed to download"
detected_by = "owner"             # canary | hourly-judge | owner | community | gate
evidence   = "brief 2026-10-25; dns rows for ngfts.lge.com blocked; Prime Video update retried"  # no addresses
resolution = "url_filter"         # must_allow | url_filter | reverted | accepted_cost | none_needed
platform   = "webOS 5 / 04.64 / OLED CX"
confidence = "observed"           # observed | community | spec | low (decision 15)
upstream   = ""                   # issue URL if reported
publishable = true                # own observation, so it can go into a CC0 export

[[breakage]]
id = "peacock-telemetry-none-2026-10-25"
observed = 2026-10-25
name = "ingest.webcol.sdp.peacocktv.com"
rule = "||ingest.webcol.sdp.peacocktv.com^"
source = "profile"
effect = "none"
feature = "Peacock playback, CDN switching, token refresh, pause and resume"
symptom = ""
detected_by = "owner"
evidence = "README: verified 2026-10-25"
resolution = "none_needed"
platform = "webOS 5 / 04.64 / OLED CX"
confidence = "observed"
publishable = true

[[breakage]]
id = "nextlgsdp-zone-webos6-2026-09-11"
observed = 2026-09-11
name = "*.nextlgsdp.com"
rule = "||nextlgsdp.com^"
source = "community"
effect = "major"
feature = "clock sync, Content Store (webOS 6+)"
symptom = "time not set after power loss; apps fail TLS; store does not open"
detected_by = "community"
evidence = "cited only"
resolution = "must_allow"
platform = "webOS 6+ (Spain, India reports)"
confidence = "community"
upstream = "https://github.com/hagezi/dns-blocklists/issues/11438"
publishable = false               # cite, never copy
```

The lint should refuse a record with `effect` outside the scale, a `source = "list:..."` without a version, a missing `confidence`, or `publishable = true` on a `community` record. `tvgw breakage export` writes only `publishable` records as CC0 JSON, which is October's "must-allow and breakage ledger" with its licence hygiene enforced by code. A triage command, `tvgw broke "<what>"`, lists the blocked lookups of the 10 minutes before the report, ranked newly-list-blocked first, then first-ever-blocked, then retried. It offers a 24-hour `@@` and opens a draft record. Do this locally rather than through HaGeZi's online lookup, which would send the TV's names to a third party.

---

## Where this disagrees with the October survey

1. **"HaGeZi `native.lgwebos`. Version 2026.1023, ... built daily."** tvgw does not fetch that file. It fetches AdGuard's recompiled copy (`filter_72`), whose own header and date are what AdGuard records, and AdGuard discards both (F1, F2). And the list adds nothing over Pro except its sentinel (230/231 covered; F2).
2. **"No upstream list publishes the opposite: what must not be blocked."** Too strong. The AdGuard DNS filter publishes `exclusions.txt` with an issue URL per entry. HaGeZi publishes known-issue and unblock files (`share/`). Perflyst's AGH list carries `@@` exceptions. Netflix publishes its delivery zones, and the Watching the Watchers list marks its breaking entry. What is missing is narrower: **an LG must-allow list with breakage evidence**. That gap is real.
3. **"Perflyst SmartTV. MIT licensed, with fresh LG commits in September 2026"**, offered as a source without caveat. Those very commits block the webOS 6+ SDP hosts for every country, and the breakage report has been open since 2026-10-03. The AGH variant blocks the `lgtvcommon.com` apex (F4). Perflyst is useful evidence of what LG contacts, and harmful as a subscription.
4. **"Contribute observed LG hosts upstream ... low risk."** Agreed, with one addition. Because the native list is merged into Pro, a host tvgw contributes reaches every Pro user. Each submission therefore needs the breakage record (*effect: none*, with how it was tested), not just "seen on this TV".
5. **The survey treated lists as a quality question** (which list is best). The larger risk is operational: an unwatched update channel into the resolver. Nothing in October's top ten covers it.
6. **"Publish a must-allow and breakage ledger (CC0 or MIT)"**: agreed. The `publishable` flag and the export are the mechanism, and the GPL caution needs to cover test fixtures too.

---

## What to build here

Ranked by value per unit of risk. Effort: S (days), M (one to two weeks), L (more). Risk is to the running gateway.

1. **"List changes" from the query log alone** (F2, Design step 5). Add the two SQL views (list began blocking a name the TV resolved; list stopped blocking one), a brief section, and a red line when the newly blocked name carried content (14-day shape over 2 MB down or a median over 16 KB). Read-only. *S effort, no risk.*
   - Test: `tvgw sql "select qname, filter_id, min(t) from dns where blocked=1 and filter_id<>0 group by 1,2 order by 3 desc limit 20"` shows recent first list blocks.
   - Test: `tvgw sql "select filter_id, count(*) from dns where blocked=1 group by 1"` confirms the custom rules log as `0` and the lists by their ids.
2. **Sentinels and liveness in `tvgw verify`** (F2). Ask the resolver at `GW_IP` for `h4g3z1-pro.web.app`, `h4g3z1-native-lgwebos.web.app` and `h4g3z1-doh.web.app` and expect `0.0.0.0`. Read each list's upstream release age once a day. The brief gets a stale line at 7 days and a red line at 14. *S effort, low risk* (a renamed sentinel is a loud false alarm, not an outage).
   - Test: `dig +short @$GW_IP h4g3z1-pro.web.app` prints `0.0.0.0`.
   - Test: the same for the other two names.
   - Test: `sudo head -2 /opt/AdGuardHome/data/filters/*.txt` shows no `!` lines (F1, rules-only files).
3. **Own `filters_update_interval` in `tvgw adguard apply`** (decision 6 lists "every key that could unfilter the TV"; `0` freezes lists silently). Set `24` now and `1` once Stage B lands. *S effort, low risk.*
   - Test: `sudo grep -n filters_update_interval /opt/AdGuardHome/AdGuardHome.yaml`.
   - Test, over three days: `sudo stat -c '%y %n' /opt/AdGuardHome/data/filters/*.txt` shows the drift of F1.
4. **Stage A snapshot and effective diff** (Design steps 1–4): the `lists` ingest step, the `list_version` and `list_delta` tables, kinds `newly_blocked`, `newly_allowed`, `widening`, `must_allow`, `exception_added`, `modifier_added`, `volume`; `list_changes` in the analyst pack. Synthetic fixtures only (F9). *M effort, low risk* (read-only; about 50 MB of disk).
   - Test: the collision script of F4 run against the Pi's own `/opt/AdGuardHome/data/filters/*.txt` with `N` from `tvgw sql "select distinct qname from dns where t > strftime('%s','now','-30 days')"` agrees with item 1's post-hoc view after the next list update.
5. **Breakage ledger** (`[[breakage]]` in profiles v2, the lint, `tvgw breakage export`, `tvgw broke`). Seed it with the five observed CX records the repo already documents: the GFTS block and the Prime Video update, the Content Store needing `us.lgrecommends.lgappstv.com`, Peacock telemetry blocked with no effect, QuickSet and Hue as an accepted cost, and Prime Video's ad pod with no effect on ads. Add the community records, cited. *S–M effort, no risk.*
6. **Stage B staged promotion** (pinned tags, two-of-three mirror agreement, holds, local `userfilters/` files, `interval: 1`, post-promotion canary, `tvgw lists accept|rollback|pin`). *M–L effort, medium risk*: it changes where AdGuard reads its lists, so it needs the owner's decision. Run it in report-only mode for two weeks first, using its holds to calibrate the thresholds.
   - Test: `sudo grep -A3 safe_fs_patterns /opt/AdGuardHome/AdGuardHome.yaml` shows the pattern, expected `.../data/userfilters/*`.
   - Test in the CI virtual gateway (in flight on another branch), **never on the Pi**: serve a `200` empty body to a namespaced AdGuard Home and assert that `rules_count` falls to 0 and the sentinel resolves. That proves the fail-open of F1 and that Stage B prevents it.
   - Test in the same harness: a list carrying `||us.lgtvsdp.com^$dnsrewrite=203.0.113.1` beside the generated `@@||us.lgtvsdp.com^$important`, to settle whether the exception defeats a list rewrite (F1, unverified).
7. **Regenerate `doh-exclude.txt` at each `tvgw-doh-update`** from `ip-ranges.json` (CLOUDFRONT) and `cloudflare.com/ips-v4`, recording the `syncToken`; also report any `doh4` address that the TV's own lookups of a non-DoH name returned (the `resolved4` set). *S effort, low risk.*
   - Test: `sudo nft -j list set inet tvgw_gate resolved4` intersected with `/var/lib/tvgw/doh4.txt` should be empty.
8. **Keep the subscriptions as they are; add none.** Keep `filter_72` for attribution and its sentinel, while knowing it adds no coverage. Do not add OISD (redundant), the AdGuard DNS filter (redundant, and its wildcard and regex rules make diffs inexact), 1Hosts (frozen since 2026-09-03, blocks the `nextlgsdp.com` apex) or Perflyst (blocks must-allow names today). After item 4, optionally run OISD big as a **shadow list**: fetched and diffed against `N`, never enabled. It hedges HaGeZi's bus factor of one (its disclaimer reserves the right to "discontinue the Lists ... at any time"). *S effort after item 4, no risk.*
9. **Provenance clean-up in `lg-webos.rules`.** Re-ground or re-attribute the three list-derived LG ad hosts (F9), and add `source =` to entries whose only evidence is a list. *S effort, no risk.*
10. **Must-allow candidates from playback evidence.** Hosts contacted by TV source ports in the 30 seconds before each session's first content-sized flow, seen on at least 3 sessions of the same app, become `observed` candidates in the brief. The owner promotes them. *M effort, no risk* (report only).

---

## Open questions

- Does `@@||host^$important` defeat a `$dnsrewrite` rule from a downloaded list for the same host? It decides whether the DoH list, which skips the registry, could redirect a must-allow host. Item 6 has the harness test.
- When two lists both block a name (LG list and Pro), which `FilterListID` does AdGuard log? Test: `tvgw sql "select filter_id, count(*) from dns where qname like '%-rdx2-lgtvsdp-com.aws-prd.net' and blocked=1 group by 1"`.
- How long does a synchronous engine rebuild of about 212k rules take on a Pi 5, and are queries answered during it? Test: `journalctl -u AdGuardHome` timestamps around "saving contents" lines plus `dig` latency in a loop during a forced refresh, ideally in the CI harness.
- Are the `h4g3z1-*` sentinels a stable HaGeZi feature? Ask upstream before relying on them beyond a warning.
- `<cc>.nextlgsdp.com`: community reports conflict (F4). The CX is webOS 5 and does not use it. Keep it must-allow for newer sets, as now, and record the conflict in the ledger.
- Day-to-day churn of Pro: only snapshots weeks apart were available. Stage B's report-only fortnight measures it.
- Whether jsDelivr keeps HaGeZi tags forever. Its README says tagged files are stored permanently, and the 2026-04-19 tag still resolves, but a failed fetch of a pinned tag should fall back to the mirrors, not to `@latest`.

---

## Sources

AdGuard Home and its registry
- AdGuard Home source, `internal/filtering/filter.go`: https://github.com/AdguardTeam/AdGuardHome/blob/master/internal/filtering/filter.go
- `internal/filtering/rulelist/parser.go`: https://github.com/AdguardTeam/AdGuardHome/blob/master/internal/filtering/rulelist/parser.go
- `internal/filtering/rulelist/rulelist.go` (256 MB default): https://github.com/AdguardTeam/AdGuardHome/blob/master/internal/filtering/rulelist/rulelist.go
- `internal/filtering/http.go` (`ValidateUpdateIvl`, `validateFilterURL`): https://github.com/AdguardTeam/AdGuardHome/blob/master/internal/filtering/http.go
- `internal/home/config.go` (defaults): https://github.com/AdguardTeam/AdGuardHome/blob/master/internal/home/config.go
- `internal/aghrenameio/renameio_unix.go`: https://github.com/AdguardTeam/AdGuardHome/blob/master/internal/aghrenameio/renameio_unix.go
- AdGuard Home CHANGELOG (v0.107.53 `safe_fs_patterns`; v0.107.78 `max_http_size`, interval 0–8760): https://github.com/AdguardTeam/AdGuardHome/blob/master/CHANGELOG.md
- AdGuard Home OpenAPI: https://github.com/AdguardTeam/AdGuardHome/blob/master/openapi/openapi.yaml
- AdGuard Home configuration wiki: https://github.com/AdguardTeam/AdGuardHome/wiki/Configuration
- AdGuard DNS filtering syntax (`$important`, `$dnsrewrite`, hosts matching): https://adguard-dns.io/kb/general/dns-filtering-syntax/
- HostlistsRegistry README: https://github.com/AdguardTeam/HostlistsRegistry
- HostlistsRegistry build workflow: https://github.com/AdguardTeam/HostlistsRegistry/blob/main/.github/workflows/workflow.yml
- HostlistsRegistry filter 48: https://github.com/AdguardTeam/HostlistsRegistry/tree/main/filters/general/filter_48_HageziMultiPro
- HostlistsRegistry filter 72: https://github.com/AdguardTeam/HostlistsRegistry/tree/main/filters/other/filter_72_HageziLGwebOSTrackerBlocklist
- HostlistsRegistry filter 7: https://github.com/AdguardTeam/HostlistsRegistry/tree/main/filters/other/filter_7_SmartTVBlocklist
- HostlistsRegistry services: https://github.com/AdguardTeam/HostlistsRegistry/tree/main/services
- HostlistCompiler transformations: https://github.com/AdguardTeam/HostlistCompiler#transformations
- AdGuard DNS filter: https://github.com/AdguardTeam/AdGuardSDNSFilter
- AdGuard DNS filter `exclusions.txt`: https://github.com/AdguardTeam/AdGuardSDNSFilter/blob/master/Filters/exclusions.txt
- AdGuard DNS filter `exceptions.txt`: https://github.com/AdguardTeam/AdGuardSDNSFilter/blob/master/Filters/exceptions.txt

Lists, maintainers and incidents
- HaGeZi README (mirrors, native tiers, disclaimer): https://github.com/hagezi/dns-blocklists
- HaGeZi FAQ (build process, lookup, support, licensing): https://github.com/hagezi/dns-blocklists/blob/main/FAQ.md
- HaGeZi releases: https://github.com/hagezi/dns-blocklists/releases
- HaGeZi #11438: https://github.com/hagezi/dns-blocklists/issues/11438
- HaGeZi #11544: https://github.com/hagezi/dns-blocklists/issues/11544
- HaGeZi #995: https://github.com/hagezi/dns-blocklists/issues/995
- HaGeZi #7323 (Peacock ads on content CDNs): https://github.com/hagezi/dns-blocklists/issues/7323
- HaGeZi #186: https://github.com/hagezi/dns-blocklists/issues/186
- HaGeZi Codeberg mirror: https://codeberg.org/hagezi/mirror2
- HaGeZi GitLab mirror: https://gitlab.com/hagezi/mirror
- jsDelivr README (`@latest`, caching, permanent storage, purge): https://github.com/jsdelivr/jsdelivr#caching
- OISD FAQ: https://oisd.nl/faq
- OISD licence: https://github.com/sjhgvr/oisd/blob/main/LICENSE
- 1Hosts repository: https://github.com/badmojr/1Hosts
- 1Hosts commits: https://github.com/badmojr/1Hosts/commits/master
- 1Hosts issues: https://github.com/badmojr/1Hosts/issues
- Perflyst PiHoleBlocklist: https://github.com/Perflyst/PiHoleBlocklist
- Perflyst `SmartTV.txt` history: https://github.com/Perflyst/PiHoleBlocklist/commits/master/SmartTV.txt
- Perflyst #172: https://github.com/Perflyst/PiHoleBlocklist/issues/172
- Perflyst #117: https://github.com/Perflyst/PiHoleBlocklist/issues/117
- Dandelicence: https://github.com/DandelionSprout/adfilt/blob/master/LICENSE.md
- furkan-bayrak/lg-tv-blocklist: https://github.com/furkan-bayrak/lg-tv-blocklist
- furkan-bayrak methodology: https://github.com/furkan-bayrak/lg-tv-blocklist/blob/main/docs/methodology.md
- furkan-bayrak `SHA256SUMS`: https://raw.githubusercontent.com/furkan-bayrak/lg-tv-blocklist/main/lists/SHA256SUMS
- Watching the Watchers artifact: https://github.com/IlgarNEU/Watching-the-Watchers
- Watching the Watchers blocklist: https://github.com/IlgarNEU/Watching-the-Watchers/blob/main/Blocklist/Blocklist.txt
- anudeepND whitelist (archived): https://github.com/anudeepND/whitelist
- Pi-hole "Commonly Whitelisted Domains": https://discourse.pi-hole.net/t/commonly-allowlisted-domains/212

Address ranges
- AWS ip-ranges.json: https://ip-ranges.amazonaws.com/ip-ranges.json
- AWS Global Accelerator components: https://docs.aws.amazon.com/global-accelerator/latest/dg/introduction-components.html
- Cloudflare IPv4 ranges: https://www.cloudflare.com/ips-v4
- Fastly public IP list: https://api.fastly.com/public-ip-list
- Google IP ranges: https://www.gstatic.com/ipranges/goog.json

Streaming
- Netflix Open Connect delivery domains: https://openconnect.netflix.com/mobiledeliverydomains.txt
- Google Workspace, YouTube network control: https://knowledge.workspace.google.com/admin/youtube/control-youtube-content-available-to-users
- Axinom Widevine data sets: https://docs.axinom.com/services/drm/license-service/license-service-management-api/widevine-data-sets

Papers
- Varmarken et al., "The TV is Smart and Full of Trackers", PoPETs 2020: https://www.petsymposium.org/popets/2020/popets-2020-0021.pdf
- The same paper on ar5iv: https://ar5iv.labs.arxiv.org/html/1911.03447
- Mandalari et al., "Blocking without Breaking", PoPETs 2021: https://www.petsymposium.org/popets/2021/popets-2021-0075.pdf
- The same paper on ar5iv: https://ar5iv.labs.arxiv.org/html/2105.05162
- Smith et al., "Blocked or Broken?", PoPETs 2022: https://www.petsymposium.org/popets/2022/popets-2022-0096.php

Law
- *Feist Publications v. Rural Telephone*, 499 U.S. 340 (1991): https://www.law.cornell.edu/supremecourt/text/499/340
- Directive 96/9/EC, Art. 7: https://www.legislation.gov.uk/eudr/1996/9/article/7
- EUR-Lex consolidated Directive 96/9/EC: https://eur-lex.europa.eu/eli/dir/1996/9/2019-06-06
- CJEU C-304/07 *Directmedia*: https://www.ippt.eu/sites/ippt/files/2008/IPPT20081009_ECJ_Directmedia_v_Albert-Ludwigs-Universitat_Freiburg.pdf
