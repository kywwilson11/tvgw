# Gap 5: the gateway's own viewing record (retention, minimization, readers, legal exposure)

*Deep dive, gap pass, 2026-11-01. Research only: nothing here is built and no host was touched. It extends [privacy-and-retention.md](../../privacy-and-retention.md), deep dives [03](03-analyst-evaluation-and-safety.md) (open question 7), [05](05-tv-privacy-research-2026.md) (§1.3), [07](07-measurement-and-presentation.md) (F7 and the HTML brief), and [state-of-the-art-2026-10.md](../state-of-the-art-2026-10.md) §4.2 (called "the October pass" below). It does not repeat them. Work in flight on other branches (packaging, `tvgw setup`, the namespace gateway in CI, supply-chain pinning, capture v2, the hardened extractor, profiles v2) is taken as given. Off-box backups are tabled and are treated here only as a place data can persist. Every non-obvious claim has a URL. **(unverified)** means I found no primary source. **(estimate)** means arithmetic of mine on numbers in this repository. **(test)** gives the exact check to run on the gateway later. Addresses and the owner's machines appear only as placeholders (`TV_IP`, `<TV_CIDR>`, `<LAN_CIDR>`). This is not legal advice.*

## Bottom line

Nobody has added it up, so here is the total. Once this pass's proposals are built, viewing-derived data persists in **22 places on the Pi and 3 off it**. The largest are not the obvious ones. The code default is `DB_DAYS=365`, not the 90 days the October pass proposed, so the store keeps a year of minute-level facts. Seven full copies of the store sit beside it, which is about **7 GB of viewing history on the card at steady state** (estimate). The flow logs keep **12 weeks** whatever `DB_DAYS` says. AdGuard's query log keeps **up to 180 days** of every lookup, because it rotates to a single `.1` file only when its oldest entry passes the 90-day interval (read from the source). `tvstate`, `hosts`, the reports, the proposals and `tvcheck-history.log` are never pruned. Taken together, they hold an hour-by-hour, app-by-app record of the household that is richer than ACR. The detectors proposed this pass need far less. None of them needs raw facts older than **35 days**. The one 60-day need, 03's placebo calibration, runs on an hourly rollup by category that carries no names. Set raw facts to 35 days, name-level daily rollups to 90 days, and keep only nameless or registrable-domain rollups for a year.

I disagree with the October pass's "rollups kept forever". A per-name daily rollup kept forever is itself a permanent viewing diary. Title-bearing names (05 §1.3) should be replaced at ingest by a keyed HMAC, not redacted only in the pack. This costs the detectors almost nothing, because they need equality, not readability, inside a 90-day key epoch.

On the analyst's data at Anthropic, as of November 2026:

- **Opus 5.5:** standard API retention is up to 30 days. It is eligible for zero data retention (ZDR) by agreement.
- **Fable 5.1:** a "Covered Model" since 2026-08-31. Prompts are kept for at least 30 days and reviewed by automated safety systems, and ZDR is not available without Anthropic's express authorization.
- **Batch API:** never ZDR-eligible. It keeps data for 29 days unless the batch is deleted.

Legally, the US federal Wiretap Act and the all-party-consent states bite on *contents*, not on routing metadata. tvgw stores contents in two places: whole plain-HTTP requests with query strings, and UDP payloads in the pcaps. Minimizing those at ingest is the legal lever. Telling adults in the household is the ethical floor. `tvgw forget` is specified below with a test that enumerates every table and file tree, so a new store cannot silently escape it.

---

## Findings

### F1. The inventory: every place viewing-derived data persists once this pass is built

**Method.** I read the shipped retention table ([privacy-and-retention.md](../../privacy-and-retention.md#how-long-it-is-kept)), the code defaults (`DB_DAYS=365`, `PCAP_DAYS=7` and `PCAP_MAX_GB=1.5` in `src/tvgw/config.py` and `deploy/tvgw.conf.example`), `deploy/logrotate/tvgw`, and each deep dive's proposals. Sizes are estimates from the "about 1 GB a year" fact rate in [data-architecture-2026-10.md](../data-architecture-2026-10.md) §2.2 unless marked otherwise. The **Owner/mode** column gives the shipped or proposed value. "Viewing content" says what a reader learns about the household.

| # | Store | Origin | Viewing content | Size (estimate) | Retention today or as proposed | Owner and mode |
|---|---|---|---|---|---|---|
| 1 | `flows`, `dns`, `tls`, `http`, `lanprobe`, `oddport`, `gate` in `tvgw.db` | shipped | Minute-level: every name, connection, byte count; `http.uri` with query string up to 2000 chars | ~2.7 MB/day; **~1 GB at 365 d** | `DB_DAYS` = **365** (code default) | `root:adm 640` |
| 2 | `tvstate` | shipped | **Foreground app every hour, forever** | small | never pruned | same file |
| 3 | `hosts` | shipped | Every name ever seen, first/last seen, counters; FAST title slugs in clear (05 §1.3) | small | never pruned | same file |
| 4 | `tvsettings` | shipped | ZIP code and device name, plus settings history | tiny | never pruned | same file |
| 5 | `judgments`, `auto_rules`, `rules` | shipped | Names judged, with model-written reasons | small | never pruned | same file |
| 6 | `answer_ip(dns_id, ip, t, ttl)` | 02 #2 | Address-to-name over time | ~+20% of `dns` (estimate) | not stated; must follow `dns` | same file |
| 7 | `decisions` (append-only) | 03 #1 | Per-run proposals, gate margins, verifier text | small | not stated (append-only) | same file |
| 8 | `list_version`, `list_delta` | 04 #4 | `list_delta` names the TV's names newly blocked | small | not stated | same file |
| 9 | `host_day`, `fw_day`, `ip_name` rollups | data-architecture §2.2 / October §4.2 | **Per name per day: lookups, bytes. "Forever"** | a few hundred rows/day | forever (proposed) | same file |
| 10 | `/var/lib/tvgw/backup/*.db` | shipped | Whole store ×7 | **~7 GB at 365 d** (7 × ~1 GB) | 7 daily copies + newest | `root:adm 640` |
| 11 | `/var/lib/tvgw/pcap/*.pcap` | shipped; capture v2 in flight | Whole port-80 requests **with bodies**, all UDP payloads, DNS questions, ClientHellos | ≤ 1.5 GB | `PCAP_DAYS=7` after ingest; 14 if unread | `tvgw-pcap:nogroup 640` |
| 12 | `/var/log/tvgw/flows.log*` | shipped | Conntrack lines: TV↔destination, bytes, times | unknown (test) | **weekly × 12 = ~84 days** | `root:adm 640` |
| 13 | `/var/log/tvgw/gfts.log*`, `gfts-tls.log*` | shipped | LG file-service URLs; TLS passthrough lines that are **never ingested** | small | weekly × 12 | `root:adm 640` |
| 14 | `/opt/AdGuardHome/data/querylog.json` and `.json.1` | shipped (`interval: 90d`) | Every lookup of every client AdGuard serves | unknown (test) | **up to 2 × 90 d = 180 d** (F1a) | as AdGuard sets (unchecked) |
| 15 | `/opt/AdGuardHome/data/stats.db` | shipped | Top domains and clients | small | 90 d | as AdGuard sets |
| 16 | systemd journal `/var/log/journal` | 06 F6 | dnsmasq `log-dhcp` (TV MAC and name), `tvgw-gate`/`oddport` kernel lines with the MAC header, unit output | ≤ 256 MB | **30 days** (06 proposal) | `root:systemd-journal`; `adm` reads |
| 17 | `/var/lib/tvgw/reports/{daily,weekly,legacy}/` | shipped | The full brief per day and week, JSON included | ~tens of KB/day (test) | **never pruned** | `root:adm 640` |
| 18 | `reports/proposals/*.{md,json,pack.json,prompt.txt}` | shipped; 03 #1 makes `.pack.json` permanent | Scrubbed packs: names, apps seen, hours on; model `summary` prose | ~40 KB/day with packs (estimate) | **never pruned** | `root:adm 640` |
| 19 | `/var/lib/tvgw/eval/` and `reports/eval/` | 03 "Where the cases live" | Real packs, mutations, per-case transcripts | 30 to 60 packs, a few MB | not stated | not stated |
| 20 | `/var/lib/tvgw/lists/<filter>/<sha>.txt.gz` | 04 #4 | **None**: public lists (see F1b) | ~50 MB | 30 versions | not stated |
| 21 | `/var/lib/tvgw/www/` | 07 HTML brief | **TV-on hours (day strip) and app names, served to the LAN** | <200 KB/day; grows | **not stated** (index links 14 days; pages never pruned) | `root:www-data 0750` |
| 22 | `tvcheck.txt`, `tvcheck-history.log` | shipped | Last reading with ZIP; **one power-and-app line an hour, never rotated** | ~20 KB/month | never | `root:adm 640` |
| 23 | Owner's workstation `backups/` | shipped (`make backup`) | Whole store copies | n × store | until deleted | owner's user |
| 24 | Anthropic | shipped | Daily and weekly packs; verifier messages; eval batches | ~10 to 40 K tokens/day | F4 | Anthropic |
| 25 | GitHub Actions logs | shipped (hardware job) | A failing assertion can quote a live value | tiny | **90 days by default** ([GitHub docs](https://docs.github.com/en/repositories/managing-your-repositorys-settings-and-features/enabling-features-for-your-repository/managing-github-actions-settings-for-a-repository)) | repository readers |

Three places are not in the table on purpose. nginx's own `/var/log/nginx/access.log` stays out because tvgw's nginx sites log to `/var/log/tvgw` (`deploy/nginx/*.conf`). The 07 brief site, however, sets no `access_log`, so its readers' LAN addresses and Basic-auth user names would go to the global nginx log under Debian's logrotate (unverified; check with `cat /etc/logrotate.d/nginx`). `/run/tvgw/` holds only counters and is gone at reboot. `/etc/dnsmasq.d/tvgw.conf` holds identity, not viewing.

**F1a. AdGuard's query log keeps up to twice its interval (settled from source).** `periodicRotate` checks hourly. `checkAndRotate` reads the first entry's time in `querylog.json`. When that entry is older than `interval`, `rotate` renames the file to `querylog.json.1` and replaces any earlier `.1` ([querylogfile.go](https://github.com/AdguardTeam/AdGuardHome/blob/master/internal/querylog/querylogfile.go)). With `interval: 90d`, the `.1` file can hold lookups up to 180 days old. The interval accepts anything from `1h` to `8760h` ([AdGuard Home configuration](https://github.com/AdguardTeam/AdGuardHome/wiki/Configuration)). The API exposes `POST /control/querylog_clear` and `POST /control/stats_reset` ([openapi.yaml](https://github.com/AdguardTeam/AdGuardHome/blob/master/openapi/openapi.yaml)). tvgw uses the query log only as a transport that ingest reads every hour. Its 90-day setting gives no analytic value and doubles the record. **(test)** `sudo head -c 200 /opt/AdGuardHome/data/querylog.json.1` shows the oldest kept entry's `"T"`.

**F1b. The list snapshots are not personal data, but `list_delta` is.** The 50 MB under `/var/lib/tvgw/lists/` is HaGeZi's public rule sets. They say nothing about the household. `list_delta` rows of kind `newly_blocked`, though, are by definition names *the TV resolved* ([04 Design step 5](04-blocklists-and-verification.md)). They belong with the facts and follow the facts' retention and `forget`.

**F1c. Who can read it is wider than "root and adm".** Raspberry Pi's image generator puts the first user in `adm` by default, along with `sudo`, `video` and others ([rpi-image-gen, device user credentials](https://raspberrypi.github.io/rpi-image-gen/layer/device-user-credentials.html)). So every process running as the login user can read the store, the reports, the logs and the backups, and on trixie the journal too. That includes an xrdp desktop session, and qBittorrent or Samba if they run as that user. Deep dive 05 #5 already treats those daemons as the likeliest way into the Pi. **(test)**

```sh
getent group adm systemd-journal
ps -o user=,comm= -C qbittorrent-nox,smbd,shairport-sync,xrdp-sesman | sort -u
for u in $(ps -o user= -C qbittorrent-nox,smbd,shairport-sync | sort -u); do id "$u"; done
sudo testparm -s 2>/dev/null | grep -E '^\s*path\s*=' # no share should contain /var/lib/tvgw or /var/log
sudo ls -ld /opt/AdGuardHome /opt/AdGuardHome/data /opt/AdGuardHome/data/querylog.json*
```

A daemon user in `adm`, or a Samba share whose path contains `/var`, is a finding.

**(test) the real sizes**, to replace the estimates above:

```sh
sudo du -sh /var/lib/tvgw/{tvgw.db,backup,pcap,reports} /var/log/tvgw /opt/AdGuardHome/data /var/log/journal 2>/dev/null
tvgw size
sudo tvgw sql "select min(datetime(t,'unixepoch')) from tvstate"
```

### F2. What history each detector actually needs, and the minimum retention per table

Each row reads the proposal's own window. "Can run on" names the smallest store that answers it.

| Detector or use | Window it needs | Source | Can run on |
|---|---|---|---|
| 07 F2 upload record (per name, per awake hour vs. its 28-day record) | 28 d | 07 F2 step 5 | `host_day` (bytes up per name per day) + daily awake hours |
| 07 F3 off-hour set and hour-of-day histogram | 28 d | 07 F3 | raw `dns`/`flows` 28 d, or an `off_hour(name, day, hour)` rollup |
| 07 chart 2 (four series, 28 days) | 28 d | 07 HTML | daily nameless aggregates |
| 07 E2 firmware diff (t₀ ± 28 d, recomputed weekly until t₀ + 28 d) | 56 d back at the last recompute | 07 E2 | `host_day` |
| 07 beacon screen v3 (event times, 7-day pool) | 7 d | 07 F1 | raw `dns` + `flows` |
| 04 list-change red line (14-day shape of a newly blocked name) | 14 d | 04 F-design | raw `flows` |
| 04 list versions | 30 versions | 04 #4 | `lists/` (not personal) |
| 02 DNS-answer naming (day or day before) and the gate's `KNOWN_DAYS` | 7 d | 02 F3, decision 22 | `answer_ip` + `dns` |
| Decision 20 judge (3 days before), shapes, `days_seen ≥ 2` | 3 to 7 d | decision 20 | raw `flows`, `dns` |
| Decision 22 judged set | 7 d | decision 22 | `judgments` |
| 03 F7 shadow follow-up (7 days after a non-applied block) | 7 d | 03 F7 | raw |
| 03 F7 precedes-playback lift | not stated; 28 d is plenty | 03 F7 | raw `dns` + `flows` |
| **03 placebo calibration** (every hour of the last 60 days) | **60 d** | 03 F7 | **an hourly rollup with no names**: `hour_cat(hour, category, bytes_down, bytes_up, conns)` + `tv_hour(hour, awake)`. `judge` reads only streaming bytes per TV-hour and the awake state |
| 03 leave-one-rule-out labels (pre-rule shapes) | as old as the rule | 03 OQ6 | the eval corpus's own frozen pack, not the store |
| The brief's 14-day backfill of daily files | 14 d | reading-the-brief.md | raw |
| Conntrack's late evidence; daily files settle 3 h after the day | 2 h 4 min | reading-the-brief.md | raw |

**Result: minimum retention per store.**

| Store | Minimum that serves every detector | Proposed setting |
|---|---|---|
| Raw facts (`flows`, `dns`, `tls`, `http`, `lanprobe`, `oddport`, `gate`, `answer_ip`, `list_delta`, `ingest_runs`) | 28 d + 7 d slack | **`DB_DAYS=35`** |
| `tvstate` (hourly app) | 28 d (awake baseline) | **35 d raw**, then `tv_day(day, awake_h, readings)` with **no app** |
| `host_day` (per name per day) | 56 d (E2) | **90 d** |
| `hour_cat`, `tv_hour` (no names) | 60 d (placebo) | **400 d** (a year plus seasonality) |
| `domain_month(registrable, category, lookups, bytes)` | none; long-term trend only | **400 d**, *excluding* the `Streaming` and app categories, which are collapsed to the category. This mirrors 07 F7's share-pack vocabulary |
| `fw_day` | none; trend | forever (no viewing content) |
| `hosts` ledger | forever (the "new name" test needs it) | forever, but title-bearing names stored as HMAC (F3), and `last_seen` cut to the ISO week once older than 90 d |
| `judgments`, `auto_rules`, `rules`, `decisions` | policy history | forever for the rule; `decisions` raw strings 90 d |
| Pcaps | re-extraction after an extractor change | `PCAP_DAYS=7` now; 3 once capture v2 and the hardened extractor are stable |
| `/var/log/tvgw/*.log` | ingest reads the newest rotated copy only (privacy-and-retention.md, Logs) | **`rotate 2`** (2 to 3 weeks). `gfts-tls.log`: `rotate 1`, since it is never ingested |
| AdGuard query log | ingest every hour; slack for downtime | **`interval: 72h`** (up to 6 days with `.1`). Run 02's `answer_ip` backfill **first**, which needs the old log |
| AdGuard statistics | none used by tvgw | `7d` |
| Journal | survive a reboot until the next ingest (06 F6) | **`MaxRetentionSec=14day`**, not 30 |
| `reports/daily` | 14 d backfill; owner reading | **90 d**; `weekly` 400 d |
| `reports/proposals` | replay and eval selection (03) | `.pack.json` and `.prompt.txt` **60 d**; `.json` records (usage, cost, verdicts) 400 d with `summary` kept |
| `www/` | index links 14 days | **mirror `reports/`**: daily pages 14 d, weekly and scorecard 400 d |
| `tvcheck-history.log` | none beyond `tvstate` | logrotate daily, `rotate 35` |
| Backups on the card | corruption recovery | 7 copies, but each is now ~100 MB instead of ~1 GB (estimate: 35 d of facts + rollups) |

**Hash or roll up at ingest.** Three things can be reduced as rows arrive, at no cost to any detector above:

- **`http.uri`: keep the path, and replace each query value with its length**, as in `?id=<12>&t=<10>`. No detector reads query values. The pack already drops them. They are the part a court is most likely to call *contents* (F5).
- **Title-bearing names**: HMAC (F3).
- **`oddport.raw` and `gate.raw`: drop the `MAC=` field and the host name** before insert. privacy-and-retention.md's known gaps list them, and no query reads them.

**I disagree with the October pass §4.2 on two points.** (1) "90 days of facts" is longer than any detector needs. 35 days covers all of them, and the one 60-day need runs on nameless rollups. (2) "Rollups kept forever" includes `host_day`, which is per name per day. That is a permanent diary of which service ran on which day and how much it moved. Keep names for 90 days. After that keep only categories, and registrable domains outside Streaming and apps.

### F3. Title-bearing names: hash at ingest, and hash the channel id too

**Why the pack is the wrong place to fix it.** 05 §1.3 proposes the redaction only in `analyst.scrub`. Every local store in F1 that holds names keeps the clear slug: rows 1, 3, 6, 9, 10, 11, 14, 17, 21 and 23. On a day of LG Channels, that includes the HTML page on the LAN and the backups pulled off the box. The pack is the one copy that is already minimized.

**What to compute.** In one function, `minimize.name(qname) -> str`, called by ingest before any insert into `dns.qname`, `tls.sni`, `http.host`, `hosts.name` and `list_delta`:

```
if zone(qname) in profile.title_bearing:          # e.g. ["amagi.tv"]
    left = qname[:-len(zone)-1]                    # everything left of the zone
    tag  = hmac_sha256(NAME_KEY[epoch], left.lower())[:10]   # 40 bits
    return f"t-{epoch}-{tag}.{zone}"               # e.g. t-3-9f2c41a07b.amagi.tv
return qname
```

- **Key.** `/etc/tvgw/name.key` holds 32 random bytes, root `0600`, and stays out of every backup. It is outside `/var/lib/tvgw`, which is what `tvgw backup` copies. The epoch number is stored in `meta`. Rotate every 90 days. Keep the previous key 35 days for overlap, then destroy it. Once a key is destroyed, its hashes cannot be linked to any later sighting. That is crypto-shredding in the sense NIST SP 800-88 Rev. 2 (September 2025) uses for flash, where overwriting is unreliable ([CSRC](https://csrc.nist.gov/pubs/sp/800/88/r2/final)).
- **Why keyed.** FAST channel catalogues are public and small. An unkeyed SHA-256 of the slug can be reversed by hashing the catalogue.
- **Why hash `amgNNNNN` too (disagreeing with 05).** 05 keeps the `amg\d+` prefix. On a single-title FAST channel the Amagi feed id maps one-to-one to the title. *Watching the Watchers* shows both forms, `{slug}-{platform}` and `amgNNNNN-{slug}-{platform}` ([paper](https://watchingthewatchers.github.io/watchingthewatchers/paper.pdf), §6.3). Anyone who sees the id once next to its slug can rename every later sighting. Hash the whole left part. Whether Amagi's ids are published per title is **unverified**.

**What it costs the detectors.**

| Consumer | Effect |
|---|---|
| Beacon, upload record, off-hour set, precedes-playback lift, judge | **None inside an epoch.** They need name equality, which the HMAC keeps. Across a rotation the 28-day record restarts for title names only, which are Streaming-category content CDNs and never upload candidates |
| Novelty and "New hosts" | Every slug is new once per epoch, and every new FAST show is new anyway. **Fix:** judge `title_bearing` zones at zone level in `judgments`, so a hashed name under a judged zone is never new |
| Must-allow, profile lint, category, DNS gate | **None.** They match on the zone suffix, which is kept |
| `autoblock` | The model may still propose a block on a hashed name. A per-show block is meaningless, so the gate should refuse any `block` target under a `title_bearing` zone other than the whole zone, which 05 says breaks FAST |
| The owner's reading | Loses the show title. That is the point. The brief prints `<title hashed>` and a count of distinct titles per day |
| Raw sources | `querylog.json`, the pcaps and the journal (when AdGuard logs names) still hold clear slugs for their own retention. That is why F2 shortens those retentions to 72 h, 7 d and 14 d |

Do **not** use AdGuard's `querylog.ignored` for these zones. The lookups would vanish from `dns`, the DNS gate would then flag every Amagi connection as unexplained, and decision 22's `gate_unexplained` would buy an analyst request every viewing day.

**Generalizing past Amagi.** Add `title_bearing` to profiles v2 (in flight). Add a report-only heuristic, a new brief line "possible title-bearing names": Streaming-category names whose left part has at least 3 hyphen-separated alphabetic tokens of at least 3 letters and that occur on at most 2 days. The owner promotes a zone into the profile by hand. **(test)**, after 05's test 4 plus five minutes of LG Channels:

```sh
sudo tvgw sql "select name, dns_n, tls_n from hosts where name like '%amagi%' order by dns_n desc limit 20"
sudo grep -c -i 'amagi' /opt/AdGuardHome/data/querylog.json
sudo journalctl --since -1d | grep -c -i amagi      # expect 0
```

### F4. Anthropic's terms as of November 2026, per model and per endpoint

Read from the live documentation on 2026-11-01, not from the bundled reference:

| Path | Retention at Anthropic | ZDR possible? | Source |
|---|---|---|---|
| Messages API, standard commercial terms (the daily and weekly passes, the verifier, `claude-opus-5-5`, `claude-sonnet-5-5`, `claude-haiku-5-5`) | "we automatically delete inputs and outputs on our backend within 30 days of receipt or generation". Exceptions: Usage Policy enforcement, legal requirement, agreed terms | **Yes, by agreement**: "contact the Anthropic sales team". ZDR is enabled per organization | [Privacy Center, commercial retention](https://privacy.claude.com/en/articles/7996866-how-long-do-you-store-my-organization-s-data); [API and data retention](https://platform.claude.com/docs/en/manage-claude/api-and-data-retention) |
| `claude-fable-5-1` (the default verifier at `xhigh` and the weekly model per `tvgw.conf.example`) | A **Covered Model**, designated 2026-08-31. Prompts and completions "retained for at least 30 days" and "assessed by automated safety systems designed to flag harmful content" | **No**, "unless expressly authorized by Anthropic". On a ZDR org it needs a workspace switched to "Standard data retention" | [Covered Models](https://support.claude.com/en/articles/15425695) (dated 2026-09-01); [API and data retention, model-specific requirements](https://platform.claude.com/docs/en/manage-claude/api-and-data-retention#model-specific-data-retention-requirements) |
| Message Batches API (03's eval runner; the October pass's production proposal) | "stores request and response data for up to 29 days after batch creation". `DELETE /v1/messages/batches/{id}` is allowed "at any time after processing" | **No** ("async storage required") | [Batch processing, data retention](https://platform.claude.com/docs/en/build-with-claude/batch-processing) |
| Structured outputs (`output_config.format`, used by the analyst) | "Only the JSON schema is cached, for up to 24 hours since last use" | Yes (qualified) | API and data retention, feature table |
| Prompt caching | KV cache "held in memory for the cache TTL" | Yes | same |
| Anything flagged by trust and safety, under any arrangement | inputs and outputs "for up to 2 years"; classifier scores up to 7 years | n/a | API and data retention, "Retention regardless of arrangement"; Privacy Center |

**Two corrections to earlier sections.**

- 03 OQ7 says Fable 5.1 "requires 30-day retention". The primary text says "at least 30 days". The extra time is open-ended only for a safety investigation or legal hold.
- The docs page also says "Conversation content (your prompts and Claude's outputs) is not retained by default; the exception is Covered Models". The Privacy Center says inputs and outputs are deleted "within 30 days". These do not contradict each other, since deletion inside 30 days is not a retention period, but they leave the true standard window unstated. **Plan for 30 days.**

**What follows for tvgw.**

1. The daily Opus pass is the only path that could be zero-retention, and only if Anthropic grants ZDR to the owner's organization. Whether it grants ZDR to an individual's organization is **unverified**. Ask once.
2. The verifier and the weekly pass, both on Fable 5.1, put every candidate shape and every weekly pack into a store that is kept at least 30 days and scanned by safety classifiers. If the owner wants the shortest footprint, run the weekly pass on `claude-opus-5-5` and adopt 03's name-blind third key on Haiku 5.5. Both are outside the Covered Model list.
3. The eval suite replays *real* past packs through Batch once a month (03 tier 2). Each replay sends the household's past viewing to Anthropic **again**, for another 29 days. Have the runner call `DELETE /v1/messages/batches/{id}` as soon as the results are downloaded. Whether deletion also purges backend copies before the 29 days is up is **unverified**. Build golden cases with F3's hashed names already applied.
4. A flagged request can be kept up to 2 years. The pack's alphabet is set by the TV and by internet servers. 03's red-team families include payloads written to look like instructions. Whether such a name could trip a safety classifier and extend retention of that day's pack is **unverified**. It is one more reason to keep the instruction-shaped-name tripwire (03 #3) before the request, not after.

### F5. Legal and ethical: recording other people's use of a device the owner owns

*Not legal advice. Statutes are quoted from official or Cornell LII text where I could fetch it, and state statutes I could not fetch are marked.*

**What tvgw captures, in the statutes' terms.**

- **Routing metadata.** DNS names, TLS server names, addresses, ports, byte counts and times are "dialing, routing, addressing, or signaling information". A process that records them is a "pen register", which "shall not include the contents of any communication" ([18 U.S.C. § 3127(3)](https://www.law.cornell.edu/uscode/text/18/3127)).
- **Contents.** "Contents" means "any information concerning the substance, purport, or meaning of that communication" ([§ 2510(8)](https://www.law.cornell.edu/uscode/text/18/2510)). Whole port-80 requests with bodies and UDP payloads in the pcaps are contents. Query strings in `http.uri` may be too. The Third Circuit treated URLs that reveal substance, such as search terms, as contents, not mere addressing (*In re Google Inc. Cookie Placement*, 806 F.3d 125 (3d Cir. 2015); secondary summary at [Columbia GFoE](https://globalfreedomofexpression.columbia.edu/cases/re-google-inc-cookie-placement-consumer-privacy-litigation/)). A September 2026 California federal ruling went the other way for bare browsing URLs under CIPA (*Wiley v. Universal Music Investments*, N.D. Cal., 2026-09-14, via [Mayer Brown](https://www.mayerbrown.com/es/insights/publications/2026/10/california-district-court-draws-critical-line-between-browsing-data-and-contents-of-communications-under-cipa)). The line is unsettled, and it is drawn at search terms and similar substance.

**Federal law.**

- **Wiretap Act.** It forbids anyone who "intentionally intercepts" an electronic communication, and also anyone who "intentionally discloses ... to any other person the contents" or "uses" them ([§ 2511(1)(a), (c), (d)](https://www.law.cornell.edu/uscode/text/18/2511)). It is a felony, up to five years ([§ 2511(4)(a)](https://www.law.cornell.edu/uscode/text/18/2511)), with a civil action under § 2520.
- **Its exceptions.**
  - One-party consent covers a person "where such person is a party to the communication" (§ 2511(2)(d)). The owner is not a party to a guest's stream.
  - The provider exception, § 2511(2)(a)(i), covers an "electronic communication service" provider protecting "the rights or property of the provider". The definition is "any service which provides to users thereof the ability to send or receive" communications (§ 2510(15)). Whether a household that runs its own network counts as such a provider is **unverified**. I found no appellate case on a home LAN.
- **Pen Register Act.** "No person may install or use a pen register ... without first obtaining a court order" ([§ 3121(a)](https://www.law.cornell.edu/uscode/text/18/3121)). It is a misdemeanor, up to one year (§ 3121(d)). The exceptions are for a provider's use "relating to the operation, maintenance, and testing" of the service, "or to the protection of the rights or property of such provider, or to the protection of users of that service from abuse" (§ 3121(b)(1)), and "where the consent of the user of that service has been obtained" (§ 3121(b)(3)). A gateway that blocks a TV's telemetry for its owner fits (b)(1)'s purpose language closely, *if* the owner counts as a provider. Consent under (b)(3) does not depend on that question.
- **Minors.** The Sixth Circuit lets a parent consent vicariously for a minor child, when the parent has a good-faith, objectively reasonable belief that doing so is necessary and in the child's best interest (*Pollock v. Pollock*, 154 F.3d 601 (6th Cir. 1998); summary at [CRIN](https://legallibrary.crin.org/pollock-v-pollock/)). Michigan's courts declined the doctrine (*Williams v. Williams*, as noted in *Pollock*). There is no comparable doctrine for adult household members or guests.

**States that require every party's consent.** These statutes govern interception of communications, and most reach *electronic* communications.

| State | Statute | All-party rule | Note |
|---|---|---|---|
| California | Penal Code §§ 631, 632, 638.51 | § 631: reading contents "in transit" without consent of all parties. § 638.51: pen-register ban with provider exceptions, including "If the consent of the user of that service has been obtained" ([public.law](https://california.public.law/codes/penal_code_section_638.51)) | SB 690, signed 2026-09-30 per [WilmerHale](https://www.wilmerhale.com/en/insights/blogs/wilmerhale-privacy-and-cybersecurity-law/20261006-cipa-reform-signed-into-law) (single source), removes *private* suits under § 638.51 only for businesses' website and app conduct. It changes nothing for a household |
| Florida | § 934.03(1)(a), (2)(d) | lawful "when all of the parties to the communication have given prior consent" ([Online Sunshine](http://www.leg.state.fl.us/statutes/index.cfm?App_mode=Display_Statute&URL=0900-0999/0934/Sections/0934.03.html)) | Has a provider exception, (2)(a)1 |
| Washington | RCW 9.73.030(1)(a) | "private communication transmitted by telephone, telegraph, radio, or other device ... without first obtaining the consent of all the participants" ([RCW](https://app.leg.wa.gov/RCW/default.aspx?cite=9.73.030)) | |
| Illinois | 720 ILCS 5/14-2(a)(3) | "private electronic communication", all parties (text not fetched: unverified) | |
| Pennsylvania | 18 Pa.C.S. §§ 5703, 5704(4) | all parties (not fetched: unverified) | |
| Maryland, Massachusetts, Montana, New Hampshire | Cts. & Jud. Proc. § 10-402; G.L. c. 272 § 99; MCA 45-8-213; RSA 570-A:2 | all parties (not fetched: unverified) | Massachusetts reaches "wire or oral" only (unverified) |
| Kentucky (05's HB 692 state) | KRS 526.010, 526.020 | **one party**; "eavesdrop" covers "wire or oral communication of others" (per the 2024 re-enactment bill text, [HB 725 original](https://apps.legislature.ky.gov/recorddocuments/bill/24RS/hb725/orig_bill.pdf); whether that bill passed is unverified) | Electronic communications are not named |

**Consumer-privacy statutes do not reach the owner.**

- Kentucky's KCDPA (KRS 367.3611 to .3629, in force 2026-01-01) applies to persons that do business in Kentucky and process data of at least 100,000 consumers ([Baker Donelson guide](https://www.bakerdonelson.com/consumer-data-privacy-law-guide-kentucky)). HB 692 makes ACR data "sensitive" for those controllers, meaning TV makers ([Hunton](https://www.hunton.com/privacy-and-cybersecurity-law-blog/kentucky-classifies-smart-tv-data-as-sensitive)).
- The VPPA binds a "video tape service provider" ([18 U.S.C. § 2710(a)(4)](https://www.law.cornell.edu/uscode/text/18/2710)).
- Neither statute binds a household running its own gateway. The moral point stands, though: tvgw builds, about the household and its guests, the record those laws class as sensitive when a company builds it.

**Where the real exposure sits, in order.**

1. **Contents kept and contents passed on.** Pcaps keep whole port-80 bodies and UDP payloads. `http.uri` keeps query strings. § 2511(1)(c) and (d) make *disclosure and use* separate offences from interception. The pack already withholds paths and query strings. Keep it that way, and stop storing query values at all (F2).
2. **Guests in an all-party state.** Viewing metadata is routing information, so the exposure is under the pen-register laws, where user consent is an express exception. Notice and consent cost almost nothing.
3. **Discoverability.** A store that holds a year of a household's viewing can be demanded by subpoena or warrant in litigation the owner never imagined, a family-law case for one. Data that no longer exists cannot be produced. Retention is the control that does not depend on how a court reads "provider".
4. **Tort.** Intrusion upon seclusion, Restatement (Second) of Torts § 652B, protects adults in their own home against a covert record (background; not researched further).

**What the owner owes the household (my recommendation, not a legal rule).**

- A one-page notice to every adult who lives there, kept at `docs/household-notice.md` with blanks to fill in:
  - what is recorded (names the TV looks up, when it is on, which app is in front);
  - for how long (F2's numbers);
  - who can read it (the owner; anyone in `tvgw-read`);
  - what leaves the house (a scrubbed daily summary to Anthropic, kept there 30 days or more);
  - how to ask for a day or a name to be forgotten (`tvgw forget`).
- A sentence for guests, offered aloud or on a card by the TV: "this TV's network traffic is logged for a month for privacy filtering".
- A **privacy hold**: `tvgw hold --hours N` keeps filtering and counters but stores no names and no `tvstate` app for those hours, and makes the analyst skip them. Use it when guests are watching, or on request.
- For a minor, the owner can rely on *Pollock*'s good-faith standard where it applies. The notice still costs nothing.

### F6. `tvgw forget`: specification and the test that nothing survives

**Shape.**

```
tvgw forget --day YYYY-MM-DD [--dry-run] [--journal] [--yes]
tvgw forget --name NAME      [--dry-run] [--include-rules] [--yes]
tvgw forget --app APP_ID     [--dry-run] [--yes]
```

`--dry-run` prints, for each store in F1, what would be removed. It reports counts only and never the matched text. A real run asks for confirmation unless `--yes` is given. The run holds the same lock as `tvgw ingest` and `tvgw-apply`.

**Order matters. Get it wrong and the next ingest re-imports what was forgotten.**

1. **Catch up.** Run `tvgw ingest` so that every raw source has been read up to now.
2. **Tombstone.** Insert into `forgotten(kind, key, t_from, t_to, at)`. For `--name`, `key` is the HMAC of the name under the *tombstone key* `/etc/tvgw/forget.key`, never the name itself, or the tombstone would record what it forgets. Ingest consults `forgotten` for every row it inserts, now and later. This is what catches late evidence: conntrack's 2 h 4 min idle report, a pcap closed after its hour, a rotated log read late.
3. **Store**, in one transaction with `PRAGMA secure_delete=ON`. With it on, "SQLite overwrites deleted content with zeros" ([SQLite pragma docs](https://www.sqlite.org/pragma.html#pragma_secure_delete)). Table by table:
   - `--day`: delete every row of the raw-fact tables, `answer_ip`, `list_delta`, `ingest_runs`, `tvstate`, `host_day`, `hour_cat` and `tv_hour` whose time lies in the local day. Delete a flow if its `[t_start, t_end]` overlaps the day at all. Decrement `hosts` counters by the day's counts, computed before the delete. A `hosts` row whose `first_seen` falls in the day gets the next sighting in the remaining rows, or is deleted if it has none. Delete `decisions` rows and `judgments` whose source stem is that day. Keep `rules`, `auto_rules`, `verify`, `fw_counters` and `tvsettings`: they are gateway and policy state, not viewing.
   - `--name`: match the name exactly, together with its `minimize.name` form. Delete the matching rows from `dns`, `tls` and `http`. Delete the `flows` that `resolve()` named after it. Delete its `answer_ip` rows through `dns_id`, and its rows in `hosts`, `host_day`, `judgments`, `decisions`, `list_delta` and the `shapes` caches. If the name sits in `rules` or `auto.rules`, refuse unless `--include-rules` is given. Forgetting a policy rule changes what is blocked, so `--include-rules` must also re-run `tvgw adguard apply`.
   - `--app`: delete `tvstate` rows with that foreground app, and strip the app from `tvsettings` history if present.
   - Then run `VACUUM`. It needs free space of twice the file's size, so check first and abort cleanly. Then `PRAGMA integrity_check`.
4. **Pcaps.**
   - `--day`: delete every `tv-*.pcap` whose UTC hour overlaps the local day.
   - `--name`: delete every pcap that contains the name. Search for it in dotted form (SNI, HTTP Host) and in DNS wire form, where each label is preceded by its length byte. Pruning makes this cheap, at most 7 days of files. Rewriting a pcap frame by frame is not worth the risk.
5. **Logs under `/var/log/tvgw`.** Filter each `*.log` and `*.log.N.gz` by the day's timestamp range or by the name's addresses on the store's record. For `--name`, remove `flows.log` lines whose destination was that name's answer, and only when `answer_ip` maps that address to no other name. Write a temporary file and rename it over the original. For the live `flows.log`, stop `tvgw-flowlog` for the rewrite and record a coverage gap in `ingest_runs`, as a lost event would be. Run `nginx -s reopen` after rewriting `gfts*.log`.
6. **AdGuard.** After step 1, `POST /control/querylog_clear` and `POST /control/stats_reset`. The query log is only a transport (F1a), so clearing all of it loses nothing tvgw needs. Filtering individual lines in place while AdGuard writes the file would race.
7. **Journal.** journald cannot delete chosen entries. With `--journal`, run `journalctl --rotate` and `journalctl --vacuum-time=<seconds since the end of D>`. This removes **all** archived journal files older than that point, for every service, so the flag says so and is never the default. Without it, the run prints the date when F2's 14-day retention will take the day out.
8. **Reports, proposals, eval and `www`.** Delete `daily/D.*`. Re-render `latest.*` and the week containing D from the store, which no longer holds the forgotten rows. Delete `proposals/D*` and every eval case whose `base_pack` is D, along with its transcripts. For `--name`, walk every JSON file and replace the name with `[forgotten]`. Rewrite `.md` and `.txt` lines that contain it, then re-render `www/` from the reports. `tvcheck-history.log`: drop the day's lines for `--day`, and lines with that app for `--app`.
9. **Backups on the card.** Delete every `backup/*.db`, since each holds the day, then run `tvgw backup` to make one fresh copy. Print the list of `make backup` pulls the workstation may still hold. This needs `make backup` to append a line per pull to `/var/lib/tvgw/pulls.log` (new, one line, no content).
10. **What cannot be reached.** Print each item, with dates computed from the records:
    - Anthropic: packs sent on D and D+1, kept up to 30 days, or at least 30 days on Fable. For eval batches with a `custom_id` that touches D, call `DELETE /v1/messages/batches/{id}`.
    - GitHub Actions logs: hardware-job failures that may quote a live value, kept 1 to 90 days per the repository setting.
    - Free blocks on the card: `fstrim -v /var/lib/tvgw` is best effort. NIST SP 800-88 Rev. 2 treats overwrite ("Clear") on flash as unreliable ([CSRC](https://csrc.nist.gov/pubs/sp/800/88/r2/final)), and the old rollback journal's bytes and the replaced files' blocks may survive in the card's flash translation layer. Only encryption from the start allows a reliable erase.

**The test that nothing survives.** It lives in `tests/unit/test_forget.py`, runs in CI without a key, and builds a whole synthetic gateway tree under `tmp_path`:

- a store with **every** table from `db.SCHEMA` filled for days D−1, D and D+1, with the canary name `zz-forget-canary-7f3a.example` on D;
- three pcaps (one hour of D, one of D−1, and one of D+1 with the canary in a DNS question and an SNI);
- `flows.log`, `flows.log.1` and `flows.log.2.gz`;
- a fake AdGuard API that records calls;
- reports, proposals, eval cases, `www/` and two backups.

Its assertions:

```python
# 1. Every table is classified. A new table without a forget policy fails the test.
tables = {r[0] for r in conn.execute("select name from sqlite_master where type='table'")}
assert tables == set(forget.POLICY), tables ^ set(forget.POLICY)

# 2. --day D: no row in any table with a time column lies in D.
for t, col in forget.TIME_COLUMNS.items():
    assert conn.execute(f"select count(*) from {t} where {col} >= ? and {col} < ?", (d0, d1)).fetchone()[0] == 0

# 3. --name: the canary appears nowhere, in any encoding, in any file under the tree,
#    gz members decompressed, the SQLite file's raw bytes included
#    (this checks secure_delete + VACUUM, not just the rows).
forms = [b"zz-forget-canary-7f3a.example", b"\x15zz-forget-canary-7f3a\x07example",
         b"ZZ-FORGET-CANARY-7F3A"]
for path in tree.rglob("*"):
    data = gzip.decompress(path.read_bytes()) if path.suffix == ".gz" else path.read_bytes()
    assert not any(f.lower() in data.lower() for f in forms), path

# 4. Late evidence: re-run ingest over the original raw sources; the tombstone drops the canary again.
# 5. integrity_check == "ok"; D-1 and D+1 untouched (row counts equal to before).
# 6. The fake AdGuard saw querylog_clear and stats_reset; the backup dir holds exactly one fresh copy.
# 7. The tombstone table does not contain the canary in clear (assertion 3 already covers it).
```

**On the gateway (hardware suite).** `test_forget_on_a_copy` runs `VACUUM INTO` of the live store into a temporary root and points `tvgw forget --root <tmp>` at it. It forgets the oldest day and one name from that day, chosen at random from `hosts`, and runs assertions 2, 3 and 5 against the copy. The live gateway is never touched. Assertion 3's file walk reads the copy only.

---

## Where this disagrees with earlier sections

1. **October §4.2, "90 days of facts, rollups forever".** Raw facts need 35 days (F2). A per-name daily rollup kept forever is a diary. Keep it 90 days, then collapse it to category, or to a registrable domain outside Streaming and apps.
2. **October §5.4, "deleted within 30 days by default; ZDR by agreement".** That still holds for Opus, Sonnet and Haiku 5.5. It does not hold for Fable 5.1, a Covered Model since 2026-08-31, or for Batch (F4).
3. **03 OQ7.** Fable's retention is "at least 30 days" with automated safety review, not "30 days". Monthly real-pack replays re-disclose old days, so delete batches after download and hash titles in the corpus.
4. **05 §1.3.** Redact at ingest, not in the pack, and hash the `amgNNNNN` feed id too.
5. **06 F6.** 30 days of persistent journal is more than the stated need, which is to survive a reboot until the next hourly ingest. 14 days is enough for diagnostics.
6. **07 HTML brief.** The pages need a retention (14 days for daily pages). The day strip and the app list should be off by default (`BRIEF_HTML_DETAIL=no`). The brief site needs its own `access_log off;` or a log under `/var/log/tvgw` with the same rotation, so that the record of who read about whom is not kept longer than the brief itself.

## What to build here

Ranked by viewing data removed per unit of work. Effort: S is a day or two, M a week, L more. Risk is to the running gateway.

| # | Build | Effort | Risk | Notes |
|---|---|---|---|---|
| 1 | **Retention settings that need no new code.** `/etc/logrotate.d/tvgw`: `rotate 2`, plus a `gfts-tls.log` stanza with `rotate 1`. AdGuard `querylog.interval: 72h` and `statistics.interval: 168h` in `adguardcfg.plan`, after 02's `answer_ip` backfill has run. Journal drop-in `MaxRetentionSec=14day` (amends 06). logrotate for `tvcheck-history.log` (`daily`, `rotate 35`). GitHub Actions log retention set to 7 days. Interim `DB_DAYS=90` until #3 lands | S | Low. AdGuard restarts once on apply. Shorter logs lower the margin after a long outage (ingest warns) | Removes about 150 days of query log, about 10 weeks of flow logs and most of the backup volume at once |
| 2 | **Minimize at ingest.** `http.uri` query values replaced by their lengths. `MAC=` and the host name stripped from `oddport.raw` and `gate.raw`. `minimize.name` with `title_bearing` HMAC, `/etc/tvgw/name.key`, epoch rotation, and zone-level judgments for title zones. Migration rewrites existing rows | S-M | Low. Golden tests change. The DNS gate and must-allow match on zones | F2, F3. Closes 05's gap in every store, not just the pack |
| 3 | **Rollups, then `DB_DAYS=35`.** `hour_cat`, `tv_hour`, `tv_day` (no names, 400 d), `host_day` (90 d), `domain_month` (400 d, Streaming and apps collapsed). Prune `tvstate` at 35 d. Port 03's placebo calibration onto `hour_cat` | M | Low-medium. A schema bump; the owner loses raw drill-down beyond 35 days, which no proposed detector uses | F2. Decides the October retention question. **Owner decision** |
| 4 | **A `tvgw-read` group instead of `adm`** for `/var/lib/tvgw`, `/var/log/tvgw` and the reports. `install.sh` adds the owner's user only. The hardware suite fails if a daemon user (qBittorrent, Samba, shairport-sync) is in `tvgw-read` or `adm` | S | Medium. A mode change on every file. Read commands break for anyone not added. Prove it in the namespace CI first | F1c |
| 5 | **Report, proposal, eval and `www` pruning** in `tvgw-analyze`: daily 90 d, weekly 400 d, packs 60 d, `www` daily 14 d, eval corpus at most 30 real packs younger than 400 d. The eval runner deletes each batch after download | S | Low | F2, F4 |
| 6 | **`tvgw forget`** with the tombstone table, `secure_delete`, the rewrite of logs and pcaps, AdGuard clear, re-rendering, backup reset, the printed residue list, and the enumerate-every-table test | M-L | Medium. It stops `tvgw-flowlog` for seconds, holds the ingest lock through a `VACUUM`, and rewrites logs. `--dry-run` first | F6 |
| 7 | **`tvgw hold --hours N`** (privacy hold): filtering continues, ingest keeps counters only, the analyst skips those hours, and the brief says "held" (Coverage: NOT ASSESSED) | S-M | Low | F5, for guests |
| 8 | **Household notice** (`docs/household-notice.md`) and a brief footer that states the retention in force, read from the settings | S | None | F5 |
| 9 | **Analyst data path.** Run the weekly pass on `claude-opus-5-5` instead of Fable. Ask Anthropic once about ZDR for the organization. Record in each proposal record which model saw the pack and that model's retention class (`standard-30d`, `covered-30d+`, `batch-29d`), so `forget` can print accurate residue | S | Low. Weekly judgments may change. Run 03's tier 1 before and after | F4 |
| 10 | **`test_retention_matches_policy`** (hardware suite). For each store in F1, check that the oldest record is no older than its policy plus one day: `min(t)` per table, the oldest pcap's mtime, the oldest rotated log, the first `"T"` in `querylog.json.1`, `journalctl --list-boots`/`--header`, and the oldest `reports/daily` file | S | None | Makes the retention table in privacy-and-retention.md a tested claim |

Order: 1 → 2 → 10 in one branch. Then 4 and 5. Then 3 once the owner decides. Then 6, then 7, 8 and 9.

## Open questions

1. **The owner's decision on F2.** Is `DB_DAYS=35` with the rollups acceptable? It gives up raw drill-down past five weeks. The alternative is 90 days, which costs about 3× the store and backups.
2. **Who in the household may read the brief and the HTML,** and should app names appear in either? (07 OQ, now with retention attached.)
3. **ZDR for an individual organization.** Will Anthropic grant it, and does deleting a batch purge Anthropic's copy before 29 days? Ask Anthropic, or read the next revision of the Batch page.
4. **Does a household network operator count as a "provider of electronic communication service"** under 18 U.S.C. §§ 2510(15), 2511(2)(a)(i) and 3121(b)(1)? No appellate case was found. The design does not depend on the answer, because consent and minimization cover both readings.
5. **Does the SD card or USB disk honour discard?** Run `lsblk --discard` (non-zero `DISC-GRAN` and `DISC-MAX`) and `sudo fstrim -v /var/lib/tvgw`. Without discard, `forget` cannot even ask the card to erase the blocks. With it, erasure is still not proven (NIST SP 800-88r2).
6. **Is the Amagi form present on this CX at all** (05 test 4)? If not, F3's HMAC is a guard for the next title channel rather than a fix for today. The heuristic line in the brief would show the next one.
7. **Does AdGuard serve any client other than the TV?** If it does, the 90-day query log holds other household devices' lookups as well. **(test)** `sudo jq -r '.IP' /opt/AdGuardHome/data/querylog.json | sort | uniq -c` (prints counts per client address; do not paste the output anywhere).
8. **Could a hostile name get a pack flagged**, extending Anthropic's retention of that day to up to 2 years (F4 point 4)? Unknowable from outside. 03's tripwire is the mitigation.

## Sources

- tvgw repository, research worktree: `docs/privacy-and-retention.md`, `docs/data-model.md`, `docs/analyst-and-autonomy.md`, `docs/reading-the-brief.md`, `docs/design-decisions.md` (19 to 22), `deploy/logrotate/tvgw`, `deploy/nginx/*.conf`, `deploy/dnsmasq/tvgw.conf.template`, `deploy/tvgw.conf.example`, `src/tvgw/config.py`, `src/tvgw/analyst.py`, `src/tvgw/db.py`; deep dives 02 to 07; data-architecture-2026-10.md; state-of-the-art-2026-10.md.
- Anthropic, API and data retention (read 2026-11-01): https://platform.claude.com/docs/en/manage-claude/api-and-data-retention
- Anthropic Privacy Center, commercial data retention: https://privacy.claude.com/en/articles/7996866-how-long-do-you-store-my-organization-s-data
- Anthropic, Covered Models (2026-09-01): https://support.claude.com/en/articles/15425695
- Anthropic, Batch processing, data retention: https://platform.claude.com/docs/en/build-with-claude/batch-processing
- AdGuard Home query log rotation source: https://github.com/AdguardTeam/AdGuardHome/blob/master/internal/querylog/querylogfile.go and https://github.com/AdguardTeam/AdGuardHome/blob/master/internal/querylog/qlog.go
- AdGuard Home configuration (interval range): https://github.com/AdguardTeam/AdGuardHome/wiki/Configuration
- AdGuard Home OpenAPI (`/querylog_clear`, `/stats_reset`): https://github.com/AdguardTeam/AdGuardHome/blob/master/openapi/openapi.yaml
- SQLite `PRAGMA secure_delete` and journal modes: https://www.sqlite.org/pragma.html
- NIST SP 800-88 Rev. 2 (September 2025): https://csrc.nist.gov/pubs/sp/800/88/r2/final
- Raspberry Pi rpi-image-gen, default user groups: https://raspberrypi.github.io/rpi-image-gen/layer/device-user-credentials.html
- GitHub Actions artifact and log retention: https://docs.github.com/en/repositories/managing-your-repositorys-settings-and-features/enabling-features-for-your-repository/managing-github-actions-settings-for-a-repository
- 18 U.S.C. § 2510: https://www.law.cornell.edu/uscode/text/18/2510
- 18 U.S.C. § 2511: https://www.law.cornell.edu/uscode/text/18/2511
- 18 U.S.C. § 3121: https://www.law.cornell.edu/uscode/text/18/3121
- 18 U.S.C. § 3127: https://www.law.cornell.edu/uscode/text/18/3127
- 18 U.S.C. § 2710 (VPPA): https://www.law.cornell.edu/uscode/text/18/2710
- *In re Google Inc. Cookie Placement*, 806 F.3d 125 (3d Cir. 2015), summary: https://globalfreedomofexpression.columbia.edu/cases/re-google-inc-cookie-placement-consumer-privacy-litigation/
- *Wiley v. Universal Music Investments* (N.D. Cal. 2026-09-14), via Mayer Brown: https://www.mayerbrown.com/es/insights/publications/2026/10/california-district-court-draws-critical-line-between-browsing-data-and-contents-of-communications-under-cipa
- *Pollock v. Pollock*, 154 F.3d 601 (6th Cir. 1998), summary: https://legallibrary.crin.org/pollock-v-pollock/
- California Penal Code § 638.51: https://california.public.law/codes/penal_code_section_638.51
- California SB 690 signed (single source): https://www.wilmerhale.com/en/insights/blogs/wilmerhale-privacy-and-cybersecurity-law/20261006-cipa-reform-signed-into-law
- Florida Stat. § 934.03: http://www.leg.state.fl.us/statutes/index.cfm?App_mode=Display_Statute&URL=0900-0999/0934/Sections/0934.03.html
- Washington RCW 9.73.030: https://app.leg.wa.gov/RCW/default.aspx?cite=9.73.030
- Kentucky KRS 526.010 (2024 re-enactment bill text): https://apps.legislature.ky.gov/recorddocuments/bill/24RS/hb725/orig_bill.pdf
- Kentucky KCDPA thresholds: https://www.bakerdonelson.com/consumer-data-privacy-law-guide-kentucky
- Kentucky HB 692 (ACR as sensitive data): https://www.hunton.com/privacy-and-cybersecurity-law-blog/kentucky-classifies-smart-tv-data-as-sensitive
- *Watching the Watchers* (Amagi title slugs, §6.3): https://watchingthewatchers.github.io/watchingthewatchers/paper.pdf
