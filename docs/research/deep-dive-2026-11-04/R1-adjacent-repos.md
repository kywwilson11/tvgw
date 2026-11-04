# R1: What adjacent projects do that tvgw could learn from

*Research record, written 2026-11-04; the code that followed is in the [CHANGELOG](../../../CHANGELOG.md) under 2026-11-04.*

*Researcher R1 of the second improvement pass, 2026-11-04. I read the tvgw repository at release 0.3.0 and changed nothing in it. Every web source was read on **2026-11-04** unless the finding gives another date.*

*Tags:*

- ***VERIFIED*** *means I read it in the primary source: the list file itself, the code, the official docs, or the issue thread.*
- ***CLAIM*** *means one user's report, a forum post, a search snippet or a marketing page.*

*How the work was split:*

- *Two sub-researchers read areas 3 (TV APIs) and 4 (measurement and reports) in parallel. Their findings are re-tagged here.*
- *I re-read the one fact from them that a top-ten idea rests on: Roku's `query/device-info` fields.*

*How the lists were checked:*

- *Lists were downloaded as data into the session scratchpad (`r1-adjacent/lists/`). Nothing downloaded was run.*
- *They were compared with a short script using AdGuard semantics: `||d^` blocks `d` and its subdomains; a hosts line blocks only the exact name.*
- *The "falls in a core category" check ran each profile's own `[categories]` with longest-pattern matching.*

*What is not repeated:*

- *What R1, R6 and R8 of 2026-11-03 and deep dives 04, 05, 07 and 14 already settled is not repeated here.*
- *Where an idea was proposed there, the entry says so and adds only the new evidence.*

*No home identifiers appear in this report.*

---

## Summary: the ten most valuable ideas

**1. Protect the LG clock host of the TV's own country.**

- **What:** Generate the must-allow exception for `<cc>.nextlgsdp.com` from the country the TV reports, instead of the US-only list. tvgw already reads that country every hour as `option.country`, and setup can ask for it.
- **Who does it:** HaGeZi keeps a hand-made list of about 50 country hosts that "must therefore be allowed" and blocks every other two-letter code. furkan-bayrak's `localize.py` rewrites lists per region. OISD excludes the country names it has been told about.
- **Why it matters:** HaGeZi Pro, which every tvgw profile subscribes to, blocks **196** `<cc>.nextlgsdp.com` hosts today. Among them are Korea, Singapore, Taiwan, the UAE, Argentina, Chile, Peru, Ukraine and China.
  - On webOS 6 and later this host sets the clock.
  - The same block in September reset clocks and broke the Content Store in Spain and India.
  - tvgw's clock red line would report it, but nothing prevents it.
- **Effort:** 1–2 days. R5 already drafted the `[must_allow_templates]` table. An interim note on the LG page (`sudo tvgw allow <cc>.nextlgsdp.com`) takes 30 minutes.
- **Touches:** `src/tvgw/profiles/lg-webos.toml`, `profile.py`, `setup.py`, `adguardcfg.py`, `docs/tv/lg-webos.md`.

**2. Own AdGuard Home's rate limit, client-subnet and upstream-mode keys.**

- **What:** Have `tvgw adguard apply` set three keys:
  - `dns.ratelimit`, so the TV is exempt (`ratelimit_whitelist: [TV_IP]`, or 0, since with `ADGUARD_LISTEN=gateway` nothing else can reach the resolver);
  - `edns_client_subnet.enabled: false`;
  - `upstream_mode: load_balance`.

  Then have `tvgw verify` warn when the store shows a second close to 20 lookups.
- **Who does it:** AdGuard's own docs give the limit as 20 queries a second per /24, "silently dropped", and the issue calling that too low has been open since 2024. Pi-hole instead answers REFUSED, logs it and raises a `RATE_LIMIT` diagnosis message.
- **Why it matters:** The TV is the only client in its /24. A burst of lookups at power-on or app start can be lost with no line in the query log or the brief, which shows up as an app that stalls for no visible reason.
- **Effort:** 3–6 hours, with a namespace test.
- **Touches:** `plan()` in `src/tvgw/adguardcfg.py`, the key list of decision 6, `docs/how-it-works/adguard.md`, `src/tvgw/verify.py`.

**3. Read Roku and Vizio TVs without putting a prompt on the screen.**

- **What:**
  - Roku's `query/device-info` gives `network-type` (ethernet or wifi), `power-mode`, `software-version` and `developer-enabled` with no pairing.
  - Vizio's SmartCast API gives the model, API version and firmware version without a token.
- **Who does it:** Home Assistant's roku and vizio integrations, python-rokuecp, pyvizio and vizaio.
- **Why it matters:** On a Roku the brief says "Not checked: the TV's Wi-Fi" every day; this turns it into a checked fact. Both brands also gain a signal that the firmware changed.
- **Effort:** a day for Roku and half a day for Vizio, behind the reader seam of decision 54.
- **Touches:** new `src/tvgw/roku.py` and `vizio.py`; the guard's root-only output rule, extended to ports 8060 and 7345; `[[lan_api]]` in `roku.toml` and `vizio-smartcast.toml`; `docs/tv/roku.md`.

**4. Write the reported cost next to every block, and fix core names that the lists block.**

- **What:**
  - In the `.rules` files, note the breakage other projects report for names tvgw blocks, each marked unverified on the CX:
    - LG Channels does not launch with `lgchhomeapp` and `cdplauncher` blocked;
    - Content Store cover art fails with `lgsmartad.com` blocked;
    - the internet channel guide fails with `cdpsvc` blocked.
  - Move names that the subscribed lists block out of the vendors' core categories: `ads.vizio.com`, `al-smetrics.vizio.com`, `osb.samsungqbe.com`, and Roku's `advertising*.msc.roku.com`.
- **Who does it:**
  - HaGeZi's issue bot, which ends each report with "fixed in release …";
  - OISD's page for each name, "Why is X not included?";
  - the AdGuard DNS filter, whose exclusions each follow the issue URL that justified them.
- **Why it matters:** When an app breaks, the troubleshooting page can name the first rule to lift.
- **Effort:** 4–6 hours.
- **Touches:** `src/tvgw/profiles/*.rules`, `[categories]` in each `*.toml`, the "One app broke" row of `docs/use/troubleshooting.md`, `docs/use/blocking.md`.

**5. `tvgw check NAME`: would this name be blocked, by what, and why.**

- **What:** Ask AdGuard's `check_host` API, with `client=TV_IP`, which rule and list would answer a name. It works for a name the TV has never asked for. Print the profile's dated reason for that rule.
- **Who does it:** Pi-hole's `pihole -q`, OISD's excludes pages, and AdGuard's own `check_host`.
- **Why it matters:** Before running `tvgw allow`, the owner sees whether the name is blocked at all, and by whom.
- **Effort:** 4–6 hours.
- **Touches:** `src/tvgw/cli.py`, `src/tvgw/adguard.py`, `docs/use/blocking.md`, `docs/reference/commands.md`.

**6. Name the company in the plain brief.**

- **What:** Map hosts to their owners with AdGuard's companiesdb. It is CC-BY-SA-4.0 and was updated on 2026-11-02.
  - It already maps `alphonso.tv` to "LG Ad Solutions", `samba.tv` to "Samba TV" and `samsungacr.com` to "Samsung Ads".
  - Ship it as a data file under its own licence.
  - Add tvgw overrides for what it lacks: Roku, Vizio/Inscape and `adsmeasurement.com`.
- **Who does it:** AdGuard Home's query log, NextDNS's company roll-ups, and IoT Inspector's fixed-template summary sentence.
- **Why it matters:** "LG Ad Solutions, LG's screen-recognition business: refused 412 times" reads better than a category name.
- **Effort:** 1 day.
- **Touches:** the "Blocked most" line in `src/tvgw/plain.py`, a new `src/tvgw/data/`, `docs/reference/brief-sections.md`.

**7. Show whether an opt-out worked.**

- **What:** When a privacy setting changes (a `tvsettings` row or an `onscreen.*` answer), the plain brief's New line compares that category's daily lookups before and after. For example: "Since Live Plus went off on 3 November, LG Ad Solutions lookups fell from about 400 a day to 12."
- **Who does it:** No household product does.
  - Consumer Reports prints the menu paths, and for Samsung's ad-tracking limit it says "We haven't tested how effective this is in practice".
  - The studies measure opt-outs only in their labs.
- **Why it matters:** It answers the question an owner has right after following the TV page.
- **Effort:** 1 day.
- **Touches:** `src/tvgw/queries.py`, `plain.py`, `docs/use/daily-brief.md`.

**8. A redacted share pack and a first-day test script for "Help test a TV".**

- **What:**
  - `tvgw share` writes the report the issue form asks for, already stripped of addresses, MACs, names and viewing times. Deep dive 07 F7 already designed its schema.
  - It adds a short script for the first day: power-cycle the TV, open each app, install from the store, check for a software update, open the live guide.
- **Who does it:**
  - Home Assistant's diagnostics, a redacted JSON file the user attaches to an issue;
  - SpyGuard's advice to "interact with the analysed device during the interception";
  - furkan-bayrak's verification steps.
- **Why it matters:** Samsung, Roku and Vizio stay "Not yet tested" until owners send reports, and today owners must redact those reports by hand.
- **Effort:** 1.5–2 days.
- **Touches:** new `src/tvgw/share.py`, `.github/ISSUE_TEMPLATE/tv_report.yml`, `docs/tv/README.md`, `docs/project/adding-a-profile.md`.

**9. A page the TV itself can open.**

- **What:** The plain status, served at `http://GW_IP/`, where nginx already listens for the TV. R6 proposed it as its R9 and it is not built.
- **Who does it:** NextDNS's test.nextdns.io and AdGuard's test page, which a device opens to see whether it is protected.
- **Why it matters:** The TV's own browser is the one screen every member of the household has, and it needs no terminal.
- **Effort:** 1 day.
- **Touches:** `deploy/nginx/`, `install.sh`, `deploy/bin/tvgw-analyze`, `src/tvgw/forget.py`.

**10. Docs that ask the reader's own questions, with a version stamp.**

- **What:**
  - A short FAQ whose headings are the questions owners ask: "Nothing was flagged. Is my TV private now?" and "Why does the TV ask for the same blocked name thousands of times?"
  - Troubleshooting headings that are the exact messages.
  - A footer on every user page: "Written for tvgw 0.3.0; checked on an LG CX, <date>".
- **Who does it:** SpyGuard's "I'm safe?" FAQ, which answers "No." first; AdGuard Home's FAQ, titled with error strings; Tailscale's "Last validated"; Syncthing's "Written for v2.1.0".
- **Why it matters:** A reader arrives at the answer straight from a search, and can tell whether the page matches the release they have.
- **Effort:** 3–5 hours.
- **Touches:** new `docs/use/faq.md`, `docs/use/troubleshooting.md`, the site prebuild (R8's `site_prebuild.py`).

Smaller items, worth doing too, are listed at the end of each section below.

---

## 1. TV and IoT telemetry blocking

### 1.1 What the subscribed lists block today, measured

**HaGeZi Pro blocks most of LG's country hosts.**

- **VERIFIED.** AdGuard's registry copy of HaGeZi Pro carries 196 rules of the form `||<cc>.nextlgsdp.com^`. tvgw subscribes to this copy in every profile.
  - The copy is `filter_48` (Version 1.0.33.26, last modified 2026-11-03T11:10Z): https://adguardteam.github.io/HostlistsRegistry/assets/filter_48.txt
  - The upstream file is https://raw.githubusercontent.com/hagezi/dns-blocklists/main/adblock/pro.txt (2026.1103.0956.06).
  - **Blocked:** `kr`, `sg`, `tw`, `ua`, `ae`, `ar`, `cl`, `pe`, `cn`, `kw`, `qa`, `lu`, and every code with no reported LG market.
  - **Not blocked:** `us`, `de`, `gb`, `ca`, `fr`, `es`, `in`, `au`, `jp`, `br`, `mx`, `it`, `nl`.
  - HaGeZi's native LG list (2026.1030.2308.00) carries none of them.
- **VERIFIED.** The policy behind it is HaGeZi's, in https://github.com/hagezi/dns-blocklists/issues/11438 (2026-09-11 to 09-30):
  - A user in India needed `in.nextlgsdp.com` "For automatic time fetching".
  - HaGeZi then posted "Country-specific subdomains that must therefore be allowed". The list ran from `aj7`, `am`, `at`, `au` through `br7`, `eu7`, `gb`, `ja7` to `us`, `us7`, `vn`, `za`.
  - `ke`, `sa` and `sk` were added on 2026-09-30, after a user reported them. So a country is allowed only once someone reports it, and every other code stays blocked.
- **CLAIM (inference).** A blocked code serves the same purpose for its country as `us.` does for the US.
  - In the same thread a C3 owner on webOS 25 writes that webOS gets its time only from LG's SDP service.
  - All 18 codes I sampled resolve on Cloudflare's DoH. `kr` and `tw` resolve to the same addresses. So these are live names, not dead ones.

**What that means for tvgw.**

- The clock red line, `clock_hosts = ["??.nextlgsdp.com"]`, catches such a block. `[must_allow]` has `us.nextlgsdp.com` only, so nothing prevents one.
- HaGeZi's allowlist also names `us7.`, `eu7.`, `aj7.`, `ja7.` and `br7.`. Their prefixes have three characters, so `??.nextlgsdp.com` does not match them. **CLAIM:** what they do is not stated.

**Names in core categories that Pro blocks.**

- **VERIFIED.** Pro also blocks names that tvgw's profiles file under the vendor's core category:
  - `ads.vizio.com` and `al-smetrics.vizio.com` fall under "Vizio core", by the `vizio.com` suffix;
  - `osb.samsungqbe.com` and `osb-krsvc.samsungqbe.com` fall under "Samsung core";
  - `assets.sr.roku.com`, `cloudservices.roku.com`, `wwwimg.roku.com`, `advertising.us-east-1.msc.roku.com` and `advertising-v3.us-east-1.msc.roku.com` fall under "Roku core", with 28 more dev, qa and staging names.
  - The brief would show these as blocked core names. That is the same class of bug deep dive 05 fixed for `lgchhomeapp`.
- **VERIFIED.** Pro blocks `vortex.hulu.com` and `events.prd.api.discomax.com`, which OISD excludes as breaking apps (Appendix A.5).

### 1.2 HaGeZi: how it handles false positives

Deep dive 04 covered how the lists are built and how often they change. New here:

- **VERIFIED.** HaGeZi's issue template asks the reporter to tick two statements: "Disabling these lists resolves the issue", and that they use no block page ("blocked domains return a zero/null IP, or result in status NXDOMAIN, REFUSED, NODATA").
  - A bot answers "The issue is scheduled to be fixed in the next release", then "This issue has been fixed in release 37522026.218.30109".
  - So each fix carries its release. Source: https://github.com/hagezi/dns-blocklists/issues/11088
- **VERIFIED.** "Dead domains are not added to my lists": https://github.com/hagezi/dns-blocklists/issues/11432 (2026-09-11).
  - One of the three dead LG ad names refused there is `ad.lgappstv.com`. tvgw's `lg-webos.rules` still pins it, "kept for coverage".
  - On Cloudflare DoH, `ad.lgappstv.com` answers NXDOMAIN (a CNAME to a dead `aws-prd.net` target), and so does `lgad.cjpowercast.com.edgesuite.net`.
- **VERIFIED.** The repository has a `controld/` build directory beside `adblock/` and the other formats, and native lists for lgwebos, samsung, roku, amazon, apple, huawei, xiaomi, vivo, oppo-realme, tiktok and winoffice. There is no Vizio list. (GitHub API, repository contents.)

### 1.3 OISD

- **VERIFIED.** https://oisd.nl/excludes.php lists every name OISD excludes. Each name has its own page at `https://oisd.nl/excludes.php?w=<name>`, titled "Why is <name> not included in the oisd blocklist?".
  - The page gives one line: a reason, an issue link, or the allowlist the name was found in.
  - Reasons run from specific ("needed to download apps and updates on LG TV") to vague ("SmartTVs").
  - About 60 of the names belong to LG, Samsung or Roku; Appendix A lists them.
- **The pattern worth copying:** one reason per name, reachable on its own. tvgw keeps the reason in the comment above each `.rules` group, and nothing looks a name up there; idea 5 would.

### 1.4 The AdGuard DNS filter and the registry

**The DNS filter's exclusions.**

- **VERIFIED.** In https://github.com/AdguardTeam/AdGuardSDNSFilter/blob/master/Filters/exclusions.txt each exclusion follows the issue or comment that justified it. TV-relevant entries:
  - `ospserver.net` ("Fixing Samsung Service Server");
  - `kinesis.eu-west-1.amazonaws.com` (AdguardFilters #131918);
  - `bamgrid.com` (#254);
  - `fls-na.amazon.com`;
  - `s.youtube.com`.
- The Kinesis exclusion supports the Vizio profile's choice not to block `kinesis.us-west-2.amazonaws.com`, which is shared AWS infrastructure.

**The blocked-services registry.**

- **VERIFIED.** https://adguardteam.github.io/HostlistsRegistry/assets/services.json defines `samsung_tv_plus` as `samsungtvplus.com`, `samsung.wurl.tv`, `internetat.tv` and `samsungcloud.tv`. It also has `pluto_tv`, `plex`, `hulu`, `peacock_tv` and `netflix` (25 rules).
- It is useful to tvgw as a map of zones, never as something to switch on:
  - It confirms that `samsungcloud.tv` carries TV Plus, which `samsung-tizen` protects at its apex.
  - `samsung.wurl.tv` shows that Wurl's `wurl.tv` zone delivers free channels. `lg-webos.rules` blocks the whole `wurl.tv` zone (`||wurl.tv^`) as "LG Channels' ad partners".
  - Check on the CX that no LG channel rides `wurl.tv`. **CLAIM (inference).**

### 1.5 Perflyst, firebog and furkan-bayrak

**firebog.**

- **VERIFIED.** https://firebog.net/ gives Perflyst's SmartTV, Amazon FireTV and Android lists the class `bdCross`, and says "Lists that have a strike through them are not recommended for use".
- That backs decision 32: cite these lists, do not subscribe to them.

**Perflyst.**

- **VERIFIED.** Perflyst's `SmartTV.txt` header still reads "Version: 13July2023v1", although the file changed in 2026-09 (deep dive 04 F3). A version line inside a list proves nothing.
- **VERIFIED.** Its commented-out lines are its record of names that must stay reachable. Examples:
  - Netflix: `secure.`, `api-global.` and `appboot.netflix.com`, which "break Netflix" when blocked;
  - `api-tv.spotify.com`;
  - `announcements.vizio.com`, with "No reason to block this";
  - `osb-ussvc.samsungqbe.com`, "required for TV Plus".

  All of them are in Appendix A. Source: https://github.com/Perflyst/PiHoleBlocklist/blob/master/SmartTV.txt

**furkan-bayrak/lg-tv-blocklist** (last commit 2026-10-30): https://github.com/furkan-bayrak/lg-tv-blocklist

- **VERIFIED.** `docs/certificates.md` grades a name by three kinds of evidence: "DNS resolves", "Live LG-controlled TLS service" (62 of 65 cluster names on 2026-09-13), and "Traffic observed".
  - The `aic.` and `kic.` twins of hosts seen as `eic.` are tagged `weak`.
  - tvgw's grades (observed, community, spec, low) have no "it still resolves" step. A maintainer check that every pinned block still resolves would have caught the two dead LG names.
- **VERIFIED.** `docs/faq.md` gives AdGuard's priority as "important exception > important block > normal exception > normal block". It warns against broad `@@||lge.com^` exceptions.
  - Its STRICT carve-out names store hosts: `a.lgappstv.com`, `<cc>.ibs.nextlgsdp.com`, `<cc>.lgeapi.com`, and optionally `qt2-ngp-gl-prv-front.lge.com`, `alkas.lge.com`, `aic-updr.lge.com`, `snsu.lge.com` and `service.lgtvcommon.com`.
  - It names the firmware family as `snu`, `su`, `su-ssl`, `ngfts` and `gfts` under `lge.com`.
  - These functions are a **CLAIM**: the FAQ itself says "community-testing — not yet G1-verified".
- **CLAIM vs VERIFIED: `uk.` or `gb.`?**
  - **CLAIM:** furkan's FAQ says "LG does not always serve a country under its ISO code, for example `uk.`, not `gb.`".
  - **VERIFIED:** OISD excludes `gb.lgtvsdp.com`, `gb.nextlgsdp.com` and `gb.lgrecommends.lgappstv.com`, and HaGeZi's allowlist has `gb.`.
  - So both forms exist, and a region template must take its prefix from the TV's own lookups, not from ISO codes. The comment in `lg-webos.toml` gives the example "(us., gb., de. ...)".
- **VERIFIED.** furkan's breakage template asks for:
  - the app or feature;
  - the tier;
  - the symptom with the TV's own error text, such as "Netflix shows error nw-2-5 on launch";
  - the suspected entry;
  - "Did reverting that entry fix it?";
  - the device and webOS version.

### 1.6 NextDNS and ControlD

- **VERIFIED.** https://github.com/nextdns/native-tracking-domains returns 404 through the GitHub API, and the `nextdns` organisation's repository list no longer includes it. The per-vendor "native tracking" domain lists are no longer public.
  - NextDNS's `blocklists` repository offers `perflyst-smarttv` as a list a user can pick.
- **VERIFIED.** On https://docs.controld.com/docs/filters, "IoT Telemetry" (`iot`) is a native filter, described as "hand curated Filters maintained by Control D", which "should contain very few false positives".
  - The page gives no breakdown by vendor.
  - Third-party filters "should be used at your own risk".
- **VERIFIED** (sub-researcher). The NextDNS analytics API counts queries by status and rolls them up by root domain, country and "GAFAM" company. "A query matching multiple blocklists counts once in each list's separate ranking." https://nextdns.github.io/api/
- Both services stay rejected as the TV's resolver (state-of-the-art-2026-10: "A third party sees every lookup").

### 1.7 AdGuard Home features tvgw does not use yet

Source for the keys: https://github.com/AdguardTeam/AdGuardHome/wiki/Configuration. It was last edited 2026-07-13, and the page says it is outdated and points to AdGuard's Knowledge Base.

| Feature | What the source says | tvgw today | Verdict |
|---|---|---|---|
| `dns.ratelimit`, `ratelimit_subnet_len_ipv4` | VERIFIED: "default is `20`"; the subnet length is 24 (since v0.107.41); queries over the limit are "silently dropped". Issue [#6726](https://github.com/AdguardTeam/AdGuardHome/issues/6726), "Default ratelimit of 20 queries/sec is way too low", has been open since 2024-02-12. A maintainer called it "a sane default for most installations", and a 2024 comment asks whether anything in the logs shows a hit | Not owned. The TV is the only client in its /24 | Idea 2 |
| `dns.edns_client_subnet` | VERIFIED: "Add the ECS option to upstream requests"; `use_custom` sends "a fixed subnet instead of the real client network" | Not owned. A web-UI edit would add a subnet to every upstream query | Idea 2: own it, `false` |
| `dns.upstream_mode` | VERIFIED: `parallel` means "Parallel queries to all configured upstream servers" | Not owned | Idea 2: own it, `load_balance` |
| `check_host` API | VERIFIED in deep dive 04 F1 (read 2026-11-01): `GET /control/filtering/check_host?name=&client=&qtype=` returns the rule text and list id | Not used | Idea 5 |
| Client tags (`$ctag`) | VERIFIED: "List of client's tags" | The plan already writes `tags: ["device_tv"]`. The HTTPS/SVCB rule is scoped `$client=TV_IP`, and the plan rewrites both when the TV moves | No gain |
| DNS rewrites | | Used, as `$dnsrewrite` rules | No change |
| Safe search, parental | Rewrites search and YouTube to restricted modes | Not used | Out of scope: it changes content |
| Query log API | | The ingest reads `querylog.json`, which needs no credentials | No gain |
| DNS-over-QUIC upstreams, encrypted bootstrap | | The upstreams are DoH by address (decision 9), so bootstrap never runs for them. `DNS_FALLBACK` already accepts `quic://<address>` | No gain |
| Blocked services | See 1.4 | Not used | Zone map only; never enable one on the TV's client |
| `clients.runtime_sources.whois` | VERIFIED: only "for clients with public IP addresses" | | Irrelevant |

### 1.8 Pi-hole, blocky and Technitium

**Pi-hole.**

- **VERIFIED.** https://docs.pi-hole.net/ftldns/configfile/ sets the default rate limit at 1,000 queries in 60 seconds. "Rate-limited queries are answered with a REFUSED reply", and each limit is logged to `FTL.log`.
- **VERIFIED.** The diagnosis message types in [`src/database/message-table.c`](https://github.com/pi-hole/FTL/blob/master/src/database/message-table.c) are REGEX, SUBNET, HOSTNAME, DNSMASQ_CONFIG, RATE_LIMIT, DNSMASQ_WARN, LOAD, SHMEM, DISK, LIST, DISK_EXTENDED, CERTIFICATE_DOMAIN_MISMATCH, CONNECTION_ERROR, NTP, VERIFY, GRAVITY_RESTORED and TELEPORTER_SKIPPED. The web form reads "Client … has been rate-limited for at least N seconds (current limit: N queries per N seconds)".
- **VERIFIED.** In [`gravity.sh`](https://github.com/pi-hole/pi-hole/blob/master/gravity.sh):
  - An empty download prints "Received empty file", then falls back with "List download failed: using previously cached list".
  - Each list gets a status: updated, unchanged, download-failed-cached, or failed-no-cache.
  - A failed build restores the previous database and records `gravity_restored`.
  - AdGuard Home, by contrast, swaps an empty `200` in as the list (deep dive 04 F1).
  - This backs Stage B. The per-list status is a line the brief could print once Stage A exists: "HaGeZi Pro: unchanged since <date>".

**blocky.**

- **VERIFIED.** https://0xerr0r.github.io/blocky/latest/configuration/
  - `maxErrorsPerSource` (default 5) is the number of errors "allowed in a list before it is considered invalid".
  - `cachePath` "serves a source from disk when its host is temporarily unreachable".
  - The `failOnError` loading strategy stops blocky when initialisation fails.
  - The EDE option (RFC 8914) puts "the same reason as the query log, including the matched group and rule" into the answer.
  - `blockTTL` defaults to 6 hours.
  - It warns that "stub resolvers and forwarders commonly treat REFUSED as a server failure".

**Technitium.** Not re-read; the October survey graded it WATCH.

**Smaller items for this section:**

- Unpin the two dead LG names (1 hour).
- Give `captive.roku.com` its stronger source, HaGeZi [#271](https://github.com/hagezi/dns-blocklists/issues/271) (2023-01-29: Roku devices "fail connection test" and "refuse to download apps"), in place of "the name is the evidence" (10 minutes).
- Correct the `gb.` example in the comment (10 minutes).
- Check whether the CX uses `wurl.tv`.
- Add a maintainer script (not a test fixture, deep dive 04 F9) that runs each profile's categorizer over its subscribed lists and prints the blocked names that land in a core category.

---

## 2. Network isolation appliances and guides

Pi-hole, Home Assistant OS, PiKVM, NanoKVM, OPNsense port assignment, OpenWrt and upribox are in R8 §3.1. Images and installers are in R2. New here:

**PiRogue Tool Suite.**

- **VERIFIED.** https://pts-project.org/guides/g1
  - Ethernet "connects your PiRogue directly (or through network switch) to your ISP router". The devices under test join the Pi's own Wi-Fi access point.
  - Version 2 generates the Wi-Fi passphrase and the dashboard password, and shows them with `pirogue-admin-client wifi get-configuration`.
  - The Pi 5 has "Experimental Support".
  - Limits are given as numbers: "up to 2-3 devices connected to the Wi-Fi access point simultaneously"; Suricata off under 2.5 GB of RAM; data kept 5 days; flows take "about 4 minutes" to appear.
  - Telemetry is on by default, with an opt-out (do not copy).
- **Lesson:** say when the first data appears and how much the box can carry. tvgw already prints "Your first brief is ready tomorrow morning."

**SpyGuard.**

- **VERIFIED.** https://github.com/SpyGuard/SpyGuard (Apache-2.0, last push 2026-06-16) and its [FAQ](https://github.com/SpyGuard/SpyGuard/wiki/Frequently-Asked-Questions):
  - "SpyGuard is not a forensic tool. Therefore, it might miss malware that does not communicate during the analysis."
  - FAQ 1 asks "SpyGuard hasn't detected anything malicious, I'm safe?" and answers "No. … SpyGuard can only detect live and communicating implants".
  - FAQ 2 asks "I'm worried that Spyguard steal my device communications".
  - Its usage advice: capture for at least 30 minutes, and interact with the device during it ("reboot it, take a photo, send an SMS").
- **VERIFIED.** Its parent, KasperskyLab/TinyCheck, returns 404 through the GitHub API.

**RaspAP.**

- **VERIFIED.** [`installers/raspbian.sh`](https://github.com/RaspAP/raspap-webgui/blob/master/installers/raspbian.sh) and `uninstall.sh` (last push 2026-11-04).
  - **Installer flags:** `--yes`, `--upgrade`, `--update --path`, `--check` (connectivity check), `--minwrite` ("Configures a microSD card for minimum write operation"), `--version` and `--uninstall`. The unattended example is `curl -sL https://install.raspap.com | bash -s -- --yes --wireguard 1 --adblock 0`.
  - **Uninstaller:** for each configuration file it backed up (hostapd, dnsmasq, dhcpcd, php.ini) it asks, for example, "Restore the last hostapd configuration file? [y/N]". It restores networking "to pre-install defaults", and lists the packages before asking to remove them.
- **Against tvgw:** `apt remove` and `purge` are documented in a table, but a source install "has no remover of its own yet". avahi's original file is kept as `avahi-daemon.conf.tvgw-backup` but never offered back, and `nftables.service` stays masked.
- **Smaller idea:** a `tvgw remove` for source installs that offers each restore (half a day).

**OPNsense and pfSense guides.**

- **CLAIM.** Community guides and forum threads: https://corelab.tech/opnsense-advanced-networking-guide/ and https://forum.opnsense.org/English_Forums/General_Discussion/Possible_to_force_all_devices_to_use_the_time_server_in_OPNsense
  - Next to DNS, they redirect UDP 123 from the IoT segment to the firewall's own NTP server.
  - They warn that intercepting DNS and NTP "can occasionally cause issues with 'picky' devices" and advise to "test one change at a time".
- **For tvgw:** Samsung and Vizio take their time over NTP; their profiles' clock hosts include `pool.ntp.org`, `time.google.com` and NIST.
  - An NTP answer from the gateway would remove three must-allow hosts and make those TVs' clocks independent of the uplink.
  - It opens a port that decision 42 keeps closed, so it needs a decision first. Smaller; about a day.

**Firewalla.**

- **CLAIM.** Its help centre sits behind Cloudflare; I read it through search snippets of https://help.firewalla.com/hc/en-us/articles/360058853313.
  - "New Device Quarantine" puts every new device into a group with no internet and no other segments until someone approves it.
  - It is keyed by MAC address, so a device with a randomised MAC is quarantined again.
- tvgw already pins `TV_MAC` and, once pinned, drops every other source. No change.

**How these projects explain what they cannot stop.**

- SpyGuard asks the reader's question and answers in one word; PiRogue gives numbers; AdGuard Home has "Known limitations" (R8).
- tvgw's `what-it-stops.md`, with a status for each limit, is more complete than any of them. What it lacks is the reader's own question as a heading (idea 10).

**Casting across isolation.** The guides pair a one-way rule from the LAN to the IoT segment with an mDNS/SSDP reflector. Rejected for tvgw (Appendix B).

---

## 3. TV LAN APIs, read for depth, not for control

LG's SSAP depth is R5's, and Samsung's no-pairing REST call is R4's; neither is repeated here.

### 3.1 Roku ECP (port 8060, plain HTTP, no pairing)

- **VERIFIED, re-read.** https://developer.roku.com/docs/developer-program/dev-tools/external-control-api.md
  - **Fields:** the `query/device-info` example has `<network-type>ethernet</network-type>`, `<power-mode>PowerOn</power-mode>`, `<developer-enabled>true</developer-enabled>` and `<software-version>9.3.0</software-version>`, as well as the serial number, both MAC addresses and the device id.
  - **The setting that gates it:** since Roku OS 14.1, "Control by mobile apps" must be "Enabled" for keypress, keydown, keyup, `query/icon`, `query/tv-channels` and `query/tv-active-channel`. `query/device-info` is not on that list.
  - **SSDP:** the TV sends a NOTIFY "approximately every 20 minutes", and "The Roku device serial number is contained in the USN line after `uuid:roku:ecp`".
- **VERIFIED** (sub-researcher). The "rk ecp" page (updated 2026-10-30) still lists `advertising-id`: https://developer.roku.com/dev/docs/rsg-sdk-standing-docs-advanced-rk-ecp
- **VERIFIED** (sub-researcher). python-rokuecp 0.19.5, the library Home Assistant uses, parses `network-type` and `network-name` (the SSID). It treats any power mode other than PowerOn as standby. [models.py](https://raw.githubusercontent.com/ctalkington/python-rokuecp/master/src/rokuecp/models.py)
- **VERIFIED** (sub-researcher). https://support.roku.com/article/217288467 (updated 2026-08-20) defines the modes of "Control by mobile apps":
  - **Limited** is "restricted to text input, app launches and accessing your activity within the app itself";
  - **Enabled** answers only devices on the same local network;
  - **Permissive** answers any device.
- **CLAIM.** On Roku OS 14.1.4 in Limited mode, `query/apps` and `query/media-player` return 403, "ECP command not allowed in Limited mode", while `query/device-info` still answered: [home-assistant/core#131969](https://github.com/home-assistant/core/issues/131969).
- **CLAIM.** The default mode accepts ECP only from private addresses: [Roku developer forum](https://forum.developer.roku.com/t/ecp-returning-403-forbidden-from-aws-requests/10853).
- **CLAIM** (openHAB docs). A Roku TV turns its network off about 10 minutes after it is switched off, unless Fast TV Start is on.
- **VERIFIED: absent.** No ECP field reports Smart TV Experience (ACR) or Limit Ad Tracking.
- **For tvgw:**
  - Read `network-type`, `power-mode`, `software-version` and `developer-enabled`, and nothing else.
  - Never store the serial, the MACs, `device-id`, `advertising-id` or `network-name`, as R4 keeps Samsung's `duid` out of the store; decision 63 already bars them from anything the gateway prints.
  - Report a 403 or 401 as "the TV's Control by mobile apps setting refuses it", and never advise Permissive.

### 3.2 Vizio SmartCast (HTTPS with a self-signed certificate, port 7345 or 9000)

- **VERIFIED** (sub-researcher). pyvizio, now frozen: [`const.py`](https://raw.githubusercontent.com/raman325/pyvizio/master/pyvizio/const.py) and [`__init__.py`](https://raw.githubusercontent.com/raman325/pyvizio/master/pyvizio/__init__.py).
  - **Ports:** `DEFAULT_PORTS = [7345, 9000]`.
  - **Without a token:** `get_model_name` (from `/state/device/deviceinfo`), `get_serial_number` and `get_version`.
  - **With a token only:** power state, settings, inputs and the current app.
- **VERIFIED** (sub-researcher). The [vizaio README](https://raw.githubusercontent.com/raman325/vizaio/main/README.md); Home Assistant now uses vizaio 0.7.0.
  - An unauthenticated `GET /state/device/deviceinfo` returns `MODEL_NAME`, `NAME`, `API_VERSION` and `SCPL_CAPABILITIES`.
  - Pairing shows a 4-digit PIN on the screen, and pairing again invalidates the old token.
- **VERIFIED** (Home Assistant docs). In Eco Mode the API is offline while the TV is off.
- **CLAIM, stale.** Reading the network type or Viewing Data needs the token.
- **CLAIM.** Home Assistant's integration fetches app names from `scfs.vizio.com` over plain HTTP, and its setup times out when that host is blocked: [home-assistant/core#110232](https://github.com/home-assistant/core/issues/110232).
- **For tvgw:** read the model and firmware version with no prompt; this gives decision 57 its firmware-change signal for Vizio. Reading Viewing Data needs a one-time PIN pairing, which has the same shape as LG's pairing and is the owner's decision.

### 3.3 Home Assistant's integrations

**webostv.**

- **VERIFIED** (sub-researcher). In aiowebostv 1.0.0's [`webos_client.py`](https://raw.githubusercontent.com/home-assistant-libs/aiowebostv/main/aiowebostv/webos_client.py):
  - The client sends `hello` and keeps the reply.
  - On newer webOS it asks `system/getSystemInfo` before it registers.
  - It registers with the stored key, or with none.
  - A reply of `pairingType: PROMPT` means the prompt is on the screen.
  - It tries ws on 3000, then wss on 3001.
- **CLAIM.** webOS 26 firmware 43.21.x answered "403 blacklisted certificate". It was fixed only by deleting the TV and adding it again, which means a new prompt: [#172703](https://github.com/home-assistant/core/issues/172703).
- **CLAIM.** A TV in demo mode prompts again after every power-on: [#181741](https://github.com/home-assistant/core/issues/181741).
- **For tvgw:** R5 noted that tvgw never reads `deviceOSReleaseVersion` from the `hello` reply. Reading the `hello` reply, and `getSystemInfo` where it answers, before any registration would give the OS version of an unpaired LG with no prompt. Test it on the CX first (2 hours).

**samsungtv.**

- **VERIFIED** (https://www.home-assistant.io/integrations/samsungtv/):
  - By default, newer TVs "ask for permission on every connection attempt", unless Access Notification is changed.
  - The websocket does not work across subnets.
  - H and J series sets use encrypted manual pairing.
- **CLAIM.** A 2025 Q8F accepts the websocket while in standby. REST `PowerState` is the right signal, but once stayed "standby" for 23 minutes after a wake: [#187048](https://github.com/home-assistant/core/issues/187048).
- **CLAIM.** A 2024 DU9000 times out on the websocket at 8002 and is refused at 8001: [#179510](https://github.com/home-assistant/core/issues/179510).
- **For tvgw:** decision 57's REST-only reader is the right one. Never infer "on" from a websocket, and count the `PowerState` lag as a known error in hours on.

**roku.**

- **VERIFIED** (https://www.home-assistant.io/integrations/roku/): no pairing, and "Roku has been known to remove or restrict local control" in OS upgrades.
- **CLAIM.** Roku OS 14.1.4.7709 broke the integration: [#135142](https://github.com/home-assistant/core/issues/135142).

**vizio.** It polls every 30 seconds, and pairing shows a PIN.

### 3.4 Passive signals already on the wire

- **Already captured.** tvgw's `dumpcap` filter keeps every UDP datagram from the TV subnet that is not bound for port 443 (`deploy/systemd/tvgw-pcap.service`). So the TV's SSDP announcements (port 1900) and mDNS announcements (port 5353) are already in the hourly pcaps. Reading them opens no socket and shows no prompt.
- **What they carry:**
  - **VERIFIED:** Roku sends a NOTIFY every ~20 minutes, which is a presence signal. Drop the serial in its USN.
  - **VERIFIED** (Home Assistant manifests): Samsung and LG are discovered through `_airplay._tcp` and Vizio through `_viziocast._tcp`.
  - **CLAIM:** the AirPlay TXT record carries `fv` (firmware version) and the model ([AirPlay spec notes](https://openairplay.github.io/airplay-spec/print.html)), and `_googlecast._tcp` carries `md` and `ve`.
  - **CLAIM:** Samsung's SSDP Server header is generic. No captured LG header with a webOS version was found.
- **Smaller idea (1 day):** an ingest step that takes the model and firmware strings, never names or serials, from the TV's own announcements, and writes a "firmware changed" event for TVs with no reader. That is decision 57's missing piece.

### 3.5 What puts a prompt on the screen or writes to the TV (avoid)

| Brand | Avoid |
|---|---|
| LG | `register` without a key, or with a key the TV no longer accepts (after a factory reset, after webOS 26's certificate blacklist, or in demo mode). On `pairingType: PROMPT`, close the socket and never retry by itself |
| Samsung | Any websocket on 8001 or 8002 (the Allow pop-up), encrypted pairing on 8000 (a PIN on H, J and 2016 K sets), and the legacy port 55000 (**CLAIM**) |
| Vizio | `PUT /pairing/start` (a PIN on screen; it also invalidates the old token), `/key_command/`, app launch, and settings `PUT`s |
| Roku | keypress, keydown, keyup, launch, input and exit-app. Never tell the owner to choose Permissive, which opens ECP to any network |
| Cast | `/setup/set_eureka_info` |
| Every brand | Wake-on-LAN or a power key used "as a check": Home Assistant issues show it switching standby sets on |

---

## 4. Measurement and reporting

From the sub-researcher's reading unless marked otherwise.

### IoT Inspector

- **VERIFIED.** https://github.com/nyu-mlab/iot-inspector-client (Apache-2.0).
  - **Status:** the README now says "IoT Inspector 3". A Go rewrite, `go-v1.0.0`, came out on 2026-10-06. The landing page is stale: "Relaunching April 2025".
  - **The report** (`go/internal/report/report.go`) has one row per device: Name, Vendor/Type, Top destination, ↑ Uploaded, ↓ Downloaded. A code comment explains the choice: "No raw 'flow' counts — end users care about bytes up/down, not internal flow records (issue #305)."
  - **The summary** (`summary.go`) is one fixed-template sentence, "<name> looks like a <type>, likely made by <vendor>. It mainly communicates with A, B, C." It uses "no model, no network" and so "can't hallucinate".
  - **Other wording:** "(guess)" stands beside an inferred identity, and an empty device says "No traffic captured (this device isn't being inspected, or hasn't talked yet)."
  - **No labels:** it has no tracker or ad labels.
  - **Consent:** "Off by default. If you turn this on, when this session ends IoT Inspector uploads the full packet capture (.pcap)…".
  - **The cloud call:** device identification POSTs the OUI, the DHCP hostname, the hostnames the device contacted, the user agent and the mDNS/SSDP data to a cloud endpoint, with a per-install token (`devid.go`). That conflicts with the app's claim "Everything stays on your machine". Do not copy it.

### Mon(IoT)r

- **CLAIM** (search snippets of Northeastern's dataset pages). Its datasets are released on request only, under a "non-exclusive and non-transferable … non-profit research and education" licence. They cannot go into an MIT package.

### Consumer testing

- **Mozilla *Privacy Not Included.** **CLAIM:** it was sunset on 2026-08-11 (https://discuss.privacyguides.net/t/mozillas-privacy-not-included-has-sunsetted/39887). Mozilla's own page returned 403.
- **Consumer Reports.** **VERIFIED:** https://www.consumerreports.org/electronics/privacy/how-to-turn-off-smart-tv-snooping-features-a4840102036/ (updated 2025-10-19).
  - It gives menu paths and one plain cost: "Opting out will enhance your privacy, but you will receive less-targeted program recommendations."
  - Of Samsung's ad-tracking limit it says "We haven't tested how effective this is in practice".
  - It publishes no traffic figures.
- **Which?** **VERIFIED** (2024-11-05): its results are qualitative. Hisense "did not connect to any trackers that researchers could detect"; Samsung and LG linked to "a number of them, including Facebook and Google". Its 2018 figure, "700 distinct addresses" in 15 minutes, is stale, and it counts addresses, not trackers.
- **RTINGS.** Its tracking test (2026-07-07) is paywalled.

### Household reports

- **Apple's App Privacy Report.** **VERIFIED:** https://support.apple.com/en-us/102188
  - It uses one fixed 7-day window.
  - Its unit is the domain, "the name of a website that allows it to be found on the internet", and it hedges: "domains that may be collecting data about you".
  - It has no company mapping, no advice and no all-clear.
- **Android's privacy dashboard.** **CLAIM:** a 24-hour view, with a 7-day view added in Android 16.
- **AdGuard Home and Pi-hole dashboards.**
  - **VERIFIED:** AdGuard Home's labels (`client/src/__locales/en.json`) are "DNS Queries", "Blocked by Filters" and "Top blocked domains".
  - **VERIFIED:** Pi-hole v6.6.1 shows "Percentage Blocked" (`index.lp`).
  - **CLAIM:** on Pi-hole's forum, users report that TVs push that figure to 47–68%.
- **Firewalla.** **CLAIM:** its alarm reads "Abnormal Upload: Device [name] uploaded [size] data to [ip]". It is learning-based and delayed, and users report false positives. It groups repeats. Weekly digests exist only in the MSP product.
- **eero, Plume and Fing.** **CLAIM:** their summaries sit behind a subscription or an account.

### Datasets that map hosts to companies

- **companiesdb.** **VERIFIED by me** (GitHub API, and the `trackers.json` file): https://github.com/AdguardTeam/companiesdb is CC-BY-SA-4.0, `timeUpdated` 2026-11-02.
  - **Present:** `alphonso.tv` and `lgads.tv` map to "LG Ad Solutions" (advertising), `samba.tv` to "Samba TV", `samsungacr.com` and `samsungads.com` to "Samsung Ads", `imrworldwide.com` to Nielsen, and `conviva.com` to Conviva.
  - **"LG TV":** `lgtvsdp.com`, `lgsmartad.com` and `lgtvcommon.com` map to "LG TV" in a miscellaneous category, not advertising. So take only the names from it; tvgw's categories stay the authority.
  - **Absent:** `roku.com`, `ravm.tv`, `tvinteractive.tv` and `adsmeasurement.com`.
- **Other datasets.** **VERIFIED** (sub-researcher):
  - DuckDuckGo Tracker Radar, Disconnect and Ghostery's TrackerDB are CC BY-NC-SA 4.0, so they stay out of the repository.
  - whotracks.me is CC BY 4.0.
  - Exodus states no licence for its data.

### Smaller ideas from this section

- A 7-day comparison line: "about the same as last week; new this week: Samba TV" (half a day).
- Never print a blocked-over-total percentage.
- Say "and N more" whenever a list is cut short.
- Keep the explicit all-clear ("Action: nothing needs your attention."), which none of the dashboards have.

---

## 5. Documentation exemplars

R8 §3.1 covered the front pages and install pages of Pi-hole, AdGuard Home, Home Assistant, Tailscale, Uptime Kuma, Immich, Nextcloud AIO, PiKVM, OPNsense and OpenWrt. New here:

- **Tailscale.** **VERIFIED:** https://tailscale.com/kb/1023/troubleshooting
  - It is grouped by category: connectivity, a specific OS, mobile, containers, cloud. Each group links to its own guide.
  - It is stamped "Last validated Jan 5, 2026".
- **Syncthing.** **VERIFIED:** https://docs.syncthing.net/intro/getting-started.html
  - The footer says "Written for v2.1.0".
  - It has four screenshots and two video walkthroughs, and ends by pointing to "Firewall Setup" if devices will not connect, then "Next: An Intro to the GUI".
  - Its sample log still shows v1.7.1, so a stamp also exposes a stale example.
- **AdGuard Home's FAQ.** **VERIFIED:** https://github.com/AdguardTeam/AdGuardHome/wiki/FAQ (last edited 2024-02-26).
  - It has 13 questions, titled in the user's words or with the exact error: "Why am I getting `bind: address already in use` error when trying to install on Ubuntu?", "How to uninstall AdGuard Home?".
  - The wiki moved to a Knowledge Base and kept the old pages under the banner "This article is outdated". That is a model for moved pages, consistent with tvgw keeping GitHub complete.
- **Home Assistant diagnostics.** **VERIFIED:** https://contributors.home-assistant.io/core/integrations/diagnostics/
  - Users download "a JSON file with the data of your integration, and attach it to an issue".
  - `async_redact_data` replaces the listed keys with `**REDACTED**`, and developers are told to check the output by hand.
  - Nothing uploads by itself. This backs idea 8.
- **SpyGuard and PiRogue** (section 2): one puts the reader's worry as the heading with a one-word answer; the other gives its limits as numbers.
- **NextDNS's test page.** **VERIFIED:** https://test.nextdns.io redirects to a new random subdomain and returns JSON with a `status` field (`unconfigured` for a device that is not using NextDNS). AdGuard has an equivalent test page. This backs idea 9.
- **What tvgw already does better:**
  - the what-it-stops table, with a status for each limit;
  - a runbook for each red line;
  - troubleshooting that starts from one command, `tvgw doctor`.

  Leave these as they are.

---

## Appendix A: names other projects allow or exempt

Each table lists the names, the source's own words, and what tvgw's profiles say today.

- Unless noted, a name is **not mentioned** in `src/tvgw/profiles/*.toml` or `*.rules`, checked with grep on 2026-11-04.
- "Pro blocks" means that it is in HaGeZi Pro (`filter_48`, 2026-11-03), which every tvgw profile subscribes to.
- A source's reason is a **CLAIM** unless it comes from tvgw's own evidence.

### A.1 LG

**Names tvgw does not mention**

| Name | What the source says | Source | tvgw today |
|---|---|---|---|
| `<cc>.nextlgsdp.com` for the 196 codes outside HaGeZi's allowlist (`kr`, `sg`, `tw`, `ae`, `ar`, `cl`, `pe`, `ua`, `cn` …) | The country's clock and store host. Blocking it cost the clock and the store (`es.`, `in.`) | HaGeZi #11438 (VERIFIED thread); the list (VERIFIED) | Only `us.` is must-allow. **Pro blocks them.** The clock red line would fire |
| `us7.`, `eu7.`, `aj7.`, `ja7.`, `br7.nextlgsdp.com` | On HaGeZi's list of hosts that "must therefore be allowed"; no role given | #11438 | Not matched by `??.nextlgsdp.com` |
| `gb.lgtvsdp.com`, `gb.nextlgsdp.com`, `gb.lgrecommends.lgappstv.com`, `gb.rdx2.lgtvsdp.com`, `pl.rdx2.lgtvsdp.com` | OISD excludes them: "LG TV" | [OISD excludes](https://oisd.nl/excludes.php) | Only the `us.` forms are listed |
| `nrdp.prod.ftl.netflix.com` | "Needed when logging out of Netflix and back in again on LG TVs" | OISD | No subscribed list blocks it |
| `a.lgappstv.com`, `<cc>.ibs.nextlgsdp.com`, `<cc>.lgeapi.com` | The store and billing path; "app-update function unproven" | furkan-bayrak `docs/faq.md` | `ibs.nextlgsdp.com` and `lgeapi.com` are LG core; `a.lgappstv.com` is not mentioned |
| `qt2-ngp-gl-prv-front.lge.com`, `alkas.lge.com`, `aic-updr.lge.com`, `snsu.lge.com` | "Add only if your query log shows the store hitting them" | furkan-bayrak FAQ | Covered by the `lge.com` apex protection only |
| `su.lge.com`, `su-ssl.lge.com` | Part of the firmware family with `snu` | furkan-bayrak FAQ | Only `snu.lge.com` is must-allow |
| `us.emp.lgsmartplatform.com`, `us.lgeapi.com` | ThinQ app sign-in fails when they are blocked (a C7, 2023) | [HaGeZi #309](https://github.com/hagezi/dns-blocklists/issues/309), stale | LG core, not blocked. ThinQ is blocked by the owner's choice |
| `us.service.lgtvcommon.com` | Perflyst blocks the exact name. #309 says the `aic.` form "Prevents local OTA Channel guide data from downloading" | Perflyst `SmartTV.txt` (VERIFIED); #309 | Only `aic.service.lgtvcommon.com` is must-allow. `strip_prefixes` does not strip `us.` |

**Names tvgw blocks that others report as breaking something**

| Name | What the source says | Source | tvgw today |
|---|---|---|---|
| `aic.lgchhomeapp.lgtvcommon.com`, `aic.cdplauncher.lgtvcommon.com` | Unblocked on 2026-09-23 so that the LG Channels app launches (three TVs in Brazil). It "Remains blocked": `ads`, `adts`, `cdpbeacon`, `cdpbeacon2`, `rdl`, `recommend`, `thinqrecommend`, `videoads`, `wiseconfig` | [HaGeZi #11544](https://github.com/hagezi/dns-blocklists/issues/11544) (VERIFIED thread) | Both are blocked. The rule comment calls `lgchhomeapp` the "home-screen ad app" and records no cost |
| `us.info.lgsmartad.com`, `us.ad.lgsmartad.com` | "required to view the cover art in the LG Store on LG TVs". #309 says `info.` is "Needed for TV Service Location Area" | OISD; #309 | The whole `lgsmartad.com` zone is blocked |
| `us.rdx2.lgtvsdp.com` | "needed to download apps and updates on LG TV"; #309 says "Required for LG Cover Art" | OISD; #309 (2023) | Blocked as telemetry on the CX's evidence |
| `aic.cdpsvc.lgtvcommon.com` | "Prevents Internet Channel guide data from downloading" | #309; OISD cites #309 | Blocked |
| `us.ibs.lgappstv.com` | "Needed for Service Location Area (Settings)" | #309; OISD | Blocked |
| `wurl.tv` | AdGuard's `samsung_tv_plus` service lists `samsung.wurl.tv`, which delivers free channels | `services.json` (VERIFIED) | The whole zone is blocked as an LG Channels ad partner |
| `ad.lgappstv.com`, `lgad.cjpowercast.com.edgesuite.net` | NXDOMAIN on Cloudflare DoH, 2026-11-04 (VERIFIED). HaGeZi: dead names are "not added" | #11432 | Pinned, "kept for coverage" |

### A.2 Samsung

| Name | What the source says | Source | tvgw today |
|---|---|---|---|
| `unified-ad-segment-cdn-ak-us-east-1.akamaized.net` | Samsung TV Plus "began repeatedly freezing" with it blocked. Allowed in release 37522026.218.30109 (2026-08-06) | [HaGeZi #11088](https://github.com/hagezi/dns-blocklists/issues/11088), one report | Not mentioned |
| `tv.springserve.com` | RTVE Play+ never loads video on a 2023 CU8000 with it blocked. Allowed 2026-09-09 | [HaGeZi #11391](https://github.com/hagezi/dns-blocklists/issues/11391) | Not mentioned (the Vizio profile files `springserve.com` as ads) |
| `info.cspserver.net` | SmartThings status of a Tizen TV; "OTA Updates might be received over this Endpoint". HaGeZi declined to block it | [HaGeZi #11547](https://github.com/hagezi/dns-blocklists/issues/11547) | Not mentioned |
| `configprd.samsungcloudsolution.net` | "needed for samsung smart tv to check for internet connection" | OISD | The connectivity must-allow is `lcprd1.` only |
| `lcprd2.samsungcloudsolution.net` | "Samsung TV" | OISD | Only `lcprd1.` |
| `osb-apps-v2.samsungqbe.com` | "app store on newer samsung smart TV (Q60 and QN90 series)" | OISD | Covered by the apex protection only |
| `osb-apps.samsungqbe.com` | "installation or update of apps in samsung TV" | OISD | Covered by the apex protection only |
| `osb-ussvc.samsungqbe.com`, `osb-eusvc.samsungqbe.com` | "required for TV Plus" | Perflyst (commented out); OISD | Covered by the apex protection only. **Pro blocks** `osb.` and `osb-krsvc.samsungqbe.com`, which the profile files under Samsung core |
| `scs.samsungqbe.com`; `notice.`, `noticecdn.`, `oempprd.`, `prov.`, `sas.`, `vdterms.`, `fkp.samsungcloudsolution.com`; `oempprd.` and `fkp.samsungcloudsolution.net` | "SmartTVs", with no detail | OISD | Covered by the apex protection only |
| `multiscreen.samsung.com`, `dev-multiscreen.samsung.com`, `samsungrm.net` | "SmartTVs" (multiscreen is phone-to-TV, which tvgw cuts anyway) | OISD; Perflyst | Not mentioned |
| `otn.samsungcloudcdn.com` | Updates fail on a UE49KS7000 and a QE55Q9FNA with it blocked | Perflyst [#60](https://github.com/Perflyst/PiHoleBlocklist/issues/60); OISD | Left out on 2026-11-01 because it did not resolve |
| `infolink.pavv.co.kr`; `ns11.whois.co.kr` | The store and login on a 2013 UE40F5500; a Series 7 cannot open YouTube | Perflyst, stale | Not mentioned |
| `ospserver.net` | "Fixing Samsung Service Server" | AdGuard DNS filter exclusions, undated | Not mentioned |
| `vortex.hulu.com` | "Breaks samsung smart TV Hulu app. Shows do not load, thumbnails do not load." | OISD | **Pro blocks it** |
| `config.samsungads.com` | Excluded by OISD, citing a Reddit comment I could not read | OISD | tvgw blocks the whole `samsungads.com` zone |

### A.3 Roku

| Name | What the source says | Source | tvgw today |
|---|---|---|---|
| `prod.mobile.roku.com` | "app wouldn't connect to the roku stick without it" (the phone app) | OISD | Not mentioned. It only matters if the TV calls it too |
| `captive.roku.com` | "fail connection test", and the device "refuse[s] to download apps" | HaGeZi #271 (VERIFIED thread, 2023) | Must-allow, graded low as "the name is the evidence". Upgrade the source |
| `nrdp.nccp.netflix.com` | "Netflix on Roku" | OISD; Perflyst | Not mentioned; Pro does not block it |
| `assets.sr.roku.com`, `cloudservices.roku.com`, `wwwimg.roku.com`, `advertising.us-east-1.msc.roku.com`, `advertising-v3.us-east-1.msc.roku.com` | — | **Pro blocks them** (VERIFIED) | Filed under Roku core. `assets.sr.roku.com` sits under The Roku Channel's zone (inference: watch for missing artwork) |

### A.4 Vizio

| Name | What the source says | Source | tvgw today |
|---|---|---|---|
| `announcements.vizio.com` | "No reason to block this" | Perflyst (commented out) | Not mentioned |
| `scfs.vizio.com` | Home Assistant fetches app names from it over plain HTTP, and its setup times out when it is blocked | HA #110232 (whether the TV itself uses it is unverified) | Not mentioned |
| `ads.vizio.com`, `al-smetrics.vizio.com`, `vizio-beacons.xumo.com`, `vizio-smartcast-beacons.xumo.com`, `vizio.tt.omtrdc.net` | — | **Pro blocks them** (VERIFIED) | The first two are filed under Vizio core |
| `kinesis.eu-west-1.amazonaws.com` | Excluded by the AdGuard DNS filter (AdguardFilters #131918) | VERIFIED | Supports not blocking the `us-west-2` Kinesis host |

### A.5 Streaming apps, on any brand

| Name | What the source says | Source | tvgw today |
|---|---|---|---|
| `vortex.hulu.com` | See A.2 | OISD | **Pro blocks it** |
| `events.prd.api.discomax.com` | "Needed for Max app" | OISD | **Pro blocks it**, yet the CX plays Max with Pro on (the 2026-10-26 note in `lg-webos.rules`). Not borne out on the CX, though whether `events.prd.` was already in Pro that day is not recorded |
| `s3-iad-ww.cf.videorolls.row.aiv-cdn.net` | "Seemingly needed for Amazon Prime Video" | OISD | **Pro blocks it**; the CX plays Prime Video with Pro on |
| `p-cg64-slinganalytics.movetv.com` | "Needed for proper functionality of TV Cable service Sling?" | OISD | **Pro blocks it** |
| `ads-v-darwin.hulustream.com` | "needed for hulu" | OISD | Not blocked |
| `ingest.webcol.sdp.peacocktv.com` | "Account management" | OISD | Blocked, with CX evidence that playback works. Account management was not tested |
| `secure.netflix.com`, `api-global.netflix.com`, `appboot.netflix.com` | "secure, api-global, and appboot break Netflix" | Perflyst (commented out) | Not blocked and not must-allow, while the profile blocks other `netflix.com` names |
| `api-tv.spotify.com` | "required for TV and PS4 spotify app" | Perflyst; OISD | Not mentioned |
| `sanalytics.disneyplus.com`; `rainmaker.production-public.tubi.io` | "watch history"; "Tubi TV Android app" | OISD | Not mentioned |

---

## Appendix B: do not copy

These are practices of the projects above that tvgw's design rejects on purpose. The decision numbers refer to `docs/design-decisions.md`.

1. **Decrypting the TV's TLS** to see payloads or strip ads, as lab studies and mitmproxy recipes do: decision 3.
2. **Rooting the TV or running hooks on it**: furkan-bayrak's `examples/webos-hooks/` for rooted sets, webosbrew, RootMyTV. Decision 4.
3. **Putting the TV on the gateway's Wi-Fi access point**, as PiRogue, SpyGuard and RaspAP do. The cable is the TV's only path, and its Wi-Fi stays off: decisions 2 and 40.
4. **Sending the TV's traffic through a VPN**, as "privacy router" recipes do: decision 1 (the direct uplink).
5. **A cloud resolver, NextDNS or ControlD, as the TV's filter.** A third party would see every lookup (state-of-the-art-2026-10, REJECT).
6. **Blocking with a block page, a custom address, `REFUSED` or NXDOMAIN.** HaGeZi's template singles block pages out, and blocky warns that REFUSED reads as a server failure. tvgw answers `0.0.0.0`, as a tested invariant of decision 6.
7. **Blocking whole vendor zones, or subscribing to the lists that do**: Perflyst's regex extension, furkan-bayrak's STRICT zone anchors, 1Hosts, HaGeZi Pro++ and Ultimate. `never_block_apex` and the lint enforce this, with decisions 7 and 32 (cite, do not subscribe; firebog strikes Perflyst through).
8. **Broad `$important` exceptions** such as `@@||lge.com^$important`. Exceptions are generated per host from `[must_allow]`, and the lint refuses regex exceptions: decision 7.
9. **The AdGuard web UI, or a query log's "unblock" button, as the place to make rules**: decisions 6 and 59. Rules are made with files and `tvgw allow` / `tvgw block`.
10. **Self-updating software and unattended update pipes**: AdGuard's built-in updater, RaspAP's `--yes --update`. AdGuard runs with `--no-check-update`, and the user installs updates: decisions 46 and 53.
11. **Bundling AdGuard Home** into the package or an image: decision 25.
12. **Opening the LAN to the TV for casting**, with an mDNS/SSDP reflector and one-way pinholes: decision 2 (state-of-the-art-2026-10: REJECT by default).
13. **Push alarms, pages, and learned "abnormal upload" alarms** of Firewalla's kind: decision 14 (red lines read daily, no paging).
14. **A "percentage blocked" headline**, as Pi-hole and AdGuard Home show: retries inflate it (R8 §3.7; the plain brief, decision 58).
15. **Sending the household's data anywhere**: IoT Inspector's pcap donation and its cloud device-identification call with contacted hostnames, PiRogue's telemetry on by default, debug logs uploaded to a vendor. Only the optional analyst's scrubbed summary leaves the gateway: decisions 19 and 47 and `privacy-and-retention.md`.
16. **Failing open**: Pi-hole's `replyWhenBusy = ALLOW` default, blocky's `fast` loading strategy (it serves before the lists load). Decision 5.
17. **Hiding noisy names from the log** with AdGuard's `querylog.ignored`. `ignored_enabled` is owned as `false`, since the log is the evidence: decision 46's keys.
18. **Writing to the TV, or pairing it on a timer**: Roku keypress and launch, Vizio PIN pairing, LG Luna writes, Wake-on-LAN or a power key as a check. A reading never pairs: decision 54, and R5 item 7.
19. **Storing the identifiers the TV hands out**: Roku's serial, MACs, `device-id`, `advertising-id` and SSID; Samsung's `duid`. Nothing printed may carry a home identifier: decision 63.
20. **Bundling non-commercial or copyleft list data in the repository**: Tracker Radar, Disconnect, Ghostery, ECHAP's IOCs, the PoPETs 2027 list, or slices of GPL lists in test fixtures. Decision 32 and deep dive 04 F9. companiesdb (CC-BY-SA) may ship only as a separate data file under its own licence.
21. **A brief written by a language model.** The plain brief is built from fixed templates over the store's report (decision 58), as IoT Inspector does for its summary ("can't hallucinate"). The optional analyst proposes rules; it does not write the brief.

---

*Not reached on 2026-11-04:*

- *Firewalla's help centre (Cloudflare), so its findings rest on search snippets.*
- *RTINGS's numbers (paywall).*
- *Mozilla's sunset page (403).*
- *eero's insights page (502).*
- *Archived copies of NextDNS's removed repository: archive.org answered 429.*
- *Technitium was not re-read.*

*Downloaded data, never executed, is in the session scratchpad: `r1-adjacent/lists/`, `furkan/`, `raspap/`, `agentA/` and `agentB/`.*
