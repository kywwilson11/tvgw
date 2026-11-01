# Gap 6: one change at a time, a change ledger and a confounder model for the canary and the hourly judge

*Proposal, 2026-11-01. Nothing here is built and nothing touched the gateway. It reads `src/tvgw/autoblock.py`, `src/tvgw/adguardcfg.py`, `src/tvgw/db.py`, `src/tvgw/ingest.py`, `src/tvgw/verify.py`, `deploy/networkmanager/90-tvgw-dispatcher` and the units in `deploy/systemd/` on the research worktree (head `43b3bd9`). It extends [03 F7](03-analyst-evaluation-and-safety.md#f7-decision-quality-under-autonomy-counterfactuals-breakage-cost-cap-and-trial) (placebo trials, one trial at a time), [04 Stage B](04-blocklists-and-verification.md#two-stages-one-evidence-model) (the post-promotion canary), [06 F8](06-platform-and-kernel-depth.md#f8-sysctls-and-modules-to-adopt) (a full conntrack table) and [08 F2](08-next-build-hardware.md#f2-the-onboard-port-on-kernel-618-eee-is-on-by-default-and-flaps-with-some-partners) (EEE link flaps), and does not repeat them. **(code)** means read from the worktree's source. **(computed)** means arithmetic done here, under the assumptions stated. **(unverified)** means one weak source or none. No store copy was available off the Pi, so every number about this gateway's history is a test to run, not a result.*

## Bottom line

The hourly judge asks one question, "did streaming bytes per TV hour fall?", and blames the newest machine rule for any answer of yes. On this gateway, a 24-hour trial window *always* holds other changes. Every machine-rule apply, revert and `tvgw undo` stops and restarts AdGuard Home, so each one is a DNS gap and a cold cache **(code)**. The NetworkManager dispatcher re-runs `tvgw-apply` on every `wlan0`, `eth0` or `tun0` "up" and on every DHCP change, so PIA reconnects and Wi-Fi re-associations also run applies **(code)**. AdGuard's own list refresh, or 04's 12:30 UTC promotion, comes every day. And every push to `main` deploys through CI. The uncontrolled causes are worse. The uplink is Wi-Fi, which the torrent client shares, and streaming apps adapt their bitrate to it. The TV's DNS rides PIA, because AdGuard's DoH upstreams leave through `tun0`. The household watches HDMI sources, which count as `Active` hours with zero streaming bytes. And the judge credits each flow's bytes to the hour the connection *ended*. Two flaws in the judge's arithmetic make all this matter more than any single source. **First, the hourly check is a minimum over n TV hours.** At a 10% chance per hour that an innocent hour reads under 20% of baseline, 4 TV hours give a 34% false-revert rate and 8 give 57% **(computed)**. **Second, a revert is a verdict** that is never asked again, so a confounded revert loses a good rule for good. Build three things, in this order. (1) A `changes` ledger. Most of it comes from cumulative counters that `tvgw verify --record` already has the cadence to read: `carrier_changes`, conntrack statistics, the boot id, AdGuard's `InvocationID`, and the signal and bitrate from `iw station dump`. Add one log line in the dispatcher and in `tvgw-apply`. (2) A judge that classifies each TV hour as `clean`, `confounded` or `no-demand`. It judges only on clean hours. It *suspends* a rule instead of reverting it when the collapse falls in a confounded hour, and returns NODATA and extends probation, as Kayenta does, instead of passing. (3) A scheduler with one lock. It never runs a machine-rule trial and a list promotion that touches the TV's names in the same window. Other promotions are not trials. Promoting every list daily as an exclusive trial would make the queue unstable (utilization ρ ≥ 1). A brief section, "Changes in effect", puts everything that changed in the window on one screen.

## Contents

- [F1. What can change the judged metric, and what the store already holds](#f1-what-can-change-the-judged-metric-and-what-the-store-already-holds)
- [F2. Two of the gateway's own automatic changes are confounders by construction](#f2-two-of-the-gateways-own-automatic-changes-are-confounders-by-construction)
- [F3. The judge's arithmetic multiplies confounders: min-of-n hours, end-time accounting, no demand model](#f3-the-judges-arithmetic-multiplies-confounders-min-of-n-hours-end-time-accounting-no-demand-model)
- [F4. Placebo trials with confounder hours: the procedure, and what can be predicted before running it](#f4-placebo-trials-with-confounder-hours-the-procedure-and-what-can-be-predicted-before-running-it)
- [F5. NODATA, suspension and extension: what the canary literature does and what fits a one-TV gateway](#f5-nodata-suspension-and-extension-what-the-canary-literature-does-and-what-fits-a-one-tv-gateway)
- [F6. Scheduling: one lock, and what it costs at the arrival rates](#f6-scheduling-one-lock-and-what-it-costs-at-the-arrival-rates)
- [F7. Cheap signals that separate "the network got worse" from "the block broke it"](#f7-cheap-signals-that-separate-the-network-got-worse-from-the-block-broke-it)
- [Design: the ledger, the hour classifier, the judge, the lock, the brief](#design-the-ledger-the-hour-classifier-the-judge-the-lock-the-brief)
- [Where this disagrees with earlier sections](#where-this-disagrees-with-earlier-sections)
- [What to build here](#what-to-build-here)
- [Open questions](#open-questions)
- [Sources](#sources)

---

## F1. What can change the judged metric, and what the store already holds

The judged metric is `autoblock.streaming_rate`: the summed `bytes_down` of flows whose `t_end` falls in the window and whose name (`queries.FLOW_NAME`) joins `hosts` in the profile's expected categories, divided by the number of `tvstate` rows with `power = 'Active'` in the window **(code)**. `tvstate` is the hourly LAN-API reading, so "TV hours" are readings, one per clock hour at most. Anything that moves the numerator, the denominator or the naming is a confounder. Grouped by whether tvgw controls it:

| Source | Controlled by tvgw? | How it moves the metric | In the store today | Collector needed |
|---|---|---|---|---|
| Machine rule added or reverted | Yes | Each add, revert or undo runs `adguardcfg.apply()`, which **stops and starts AdGuard Home** ([F2](#f2-two-of-the-gateways-own-automatic-changes-are-confounders-by-construction)) | `auto_rules.added_t`, `decided_t` (one row per rule; a second trial of the same rule overwrites it, 03 F1) | Event row from `autoblock` itself |
| List version change (AdGuard's own refresh today, 04 Stage B later) | Partly | Newly blocked or allowed names; a synchronous engine rebuild (04 F1) | Post-hoc only: a name's first `dns.blocked = 1` with `filter_id <> 0` (04 Design step 5) | `filters/<id>.txt` mtime and size per sample (04 Stage A gives the effective delta on the TV's names) |
| Profile deploy (rules) | Yes | Rule changes; AdGuard restart | `rules.first_seen` / `removed_at`, at ingest granularity (one hour) | Deploy row from `install.sh`: git SHA, time, which units restarted |
| Code deploy that changes ingest, extractor or queries | Yes | **Changes the metric's definition**: more or fewer flows named into expected categories. Decision 21 (continuations named) and the extractor branch in flight (split ClientHello) both raise named streaming volume after the deploy | `meta` holds `*_version` for AdGuard and similar; no tvgw version history | The same deploy row, with a `metric_affecting` flag set when `src/tvgw/{ingest,tshark,queries,names}.py` or the capture units changed |
| `tvgw-apply` run (dispatcher, DoH update, deploy, by hand) | Yes | Since the 2026-10-30 fix it should destroy no conntrack entry. It resets counters, which `verify` handles | Indirectly: the before/after reload snapshot pair in `fw_counters`, lost when a second apply comes within 10 minutes | One log line per run with its trigger ([Design](#design-the-ledger-the-hour-classifier-the-judge-the-lock-the-brief)) |
| Unit restarts of `tvgw-pcap`, `tvgw-flowlog`, `tvgw-dnsgate` | Yes | "Every restart is a short hole in the evidence" ([deploy/systemd/README.md](../../../deploy/systemd/README.md)) | No | `InvocationID` per unit per sample |
| Conntrack event loss (ENOBUFS) | No | DESTROY lines lost, so bytes missing from the hour | **Yes**: `ingest_runs.warnings` ("conntrack lost events") **(code)** | None |
| Capture or naming failure (the 2026-10-27 incident) | No | Flows unnamed, so they drop out of the expected categories and the hour reads as a collapse | **Yes**: `pcaps_done.tls_rows = 0` while the TV was `Active`; `queries.coverage()` NOT ASSESSED | None |
| Connections destroyed early by the gateway | No | Flows split; since decision 21, bytes are kept | **Yes**: `flows.timeout_left IS NOT NULL AND state = 'ESTABLISHED'` (schema 7) **(code)** | None |
| Gateway reboot (watchdog, panic, owner) | No | TV dark for a minute; all flows cut | No (the journal has been persistent since 2026-10-31, so `journalctl --list-boots` covers from then) | `boot_id` per sample |
| AdGuard restart or crash, outside tvgw's applies | No | DNS gap; cold cache | No | `systemctl show AdGuardHome -p InvocationID,NRestarts` per sample |
| PIA reconnect | No | **AdGuard's DoH upstreams leave through `tun0`**, so a tunnel outage is a TV DNS outage for every uncached name | No. The dispatcher's `tun0 up` runs `tvgw-apply` but logs nothing | Dispatcher log line; `piactl get connectionstate` per sample |
| `eth0` link flap (08 F2) | No | Lost packets; TCP stalls; one apply per "up" | No (journal from 2026-10-31) | `/sys/class/net/eth0/carrier_changes` per sample |
| Wi-Fi uplink quality (`wlan0`) | No | Adaptive bitrate: a slower uplink means **fewer bytes for the same viewing** | No | `iw dev wlan0 station dump`, `carrier_changes`, byte counters per sample |
| Torrent load on the same uplink | No | Uplink air time; conntrack entries | No | `wlan0` bytes minus `eth0` bytes (no API), or qBittorrent's `/api/v2/transfer/info` |
| Conntrack table full or early drop (06 F8) | No | **New** TV connections refused when eviction fails ([F7](#f7-cheap-signals-that-separate-the-network-got-worse-from-the-block-broke-it)) | No | `conntrack -S` sums and `nf_conntrack_count` per sample |
| AdGuard upstream failure (any cause) | No | Lookups unanswered | **Derivable**: `dns` rows with `blocked = 0`, `answers IS NULL`, `cached = 0` and a long `elapsed_ms` (the exact encoding of a SERVFAIL is unverified) | None; a view |
| Firmware update | No | New endpoints, new behaviour | **Yes**: `tvsettings` key `firmware`; `queries.firmware_changes()` | None |
| App update | No | New endpoints or player | Partly: Content Store downloads go through the GFTS URL filter, so the `http` table (`src = 'gfts'`) holds the URI and size of each download. Which URI pattern marks a package is **(unverified)** | A view over `http`; app versions over SSAP `listApps` are unverified ([Open questions](#open-questions)) |
| LG server-side configuration | No | Telemetry schedule and ACR configuration change with no firmware change (07 F4) | Partly: a plain-HTTP fetch of a config URI with a **changed response size** (`http.bytes`) is a cheap date for a server-side change **(unverified as a reliable proxy)** | A view: per URI, a size different from the last fetch |
| What was watched (app mix, HDMI sources, Live TV) | No | An `Active` hour on an HDMI source carries zero streaming bytes | **Yes**: `tvstate.app` | None; a classification ([F3](#f3-the-judges-arithmetic-multiplies-confounders-min-of-n-hours-end-time-accounting-no-demand-model)) |

**Answer to question 1.** Nine of the twenty sources are in the store already or can be derived from it: machine rules, profile rule changes, conntrack event loss, capture failures, early-destroyed connections, AdGuard upstream failures, firmware, Content Store downloads and the foreground app. Eleven need a collector. Nine of those eleven are cumulative kernel or systemd counters that a 10-minute sample captures with no loss of events, only of exact times: `carrier_changes`, conntrack statistics, `boot_id`, `InvocationID`, `NRestarts`, filter file mtimes, interface byte counters, the station-dump fields and the PIA state. The other two are one log line each, in the dispatcher and in `install.sh`. `tvgw verify --record` already runs every 10 minutes and already writes `fw_counters`, so the sampler belongs there.

**Tests (on the gateway, read-only).**

```sh
cat /sys/class/net/eth0/carrier_changes /sys/class/net/wlan0/carrier_changes   # cumulative since boot
cat /proc/sys/kernel/random/boot_id
systemctl show AdGuardHome -p InvocationID,NRestarts,ActiveEnterTimestamp
sudo conntrack -S | head -2 ; cat /proc/sys/net/netfilter/nf_conntrack_count /proc/sys/net/netfilter/nf_conntrack_max
iw dev wlan0 station dump | grep -E 'signal|tx bitrate|rx bitrate|tx failed|tx packets'
/opt/piavpn/bin/piactl get connectionstate
tvgw sql "select count(*) from flows where state='ESTABLISHED' and timeout_left is not null and t_end > strftime('%s','2026-10-31')"
```

The last query should return 0 if the 2026-10-30 fix holds. Any row is the gateway breaking a live connection, and its `t_end` is a ledger entry.

## F2. Two of the gateway's own automatic changes are confounders by construction

**Every machine-rule apply restarts the resolver.** `adguardcfg.apply()` validates the candidate config, then calls `systemctl stop AdGuardHome`, moves the file into place, calls `systemctl start AdGuardHome`, and waits up to 30 s for `dns_ready()` to resolve `example.com` **(code)**. The analyst's apply, the canary's revert, the hourly judge's revert and `tvgw undo` all go through it ([analyst page](../../analyst-and-autonomy.md#the-machines-rules-file)). Three consequences for attribution:

- The canary's baseline is two readings taken *before* the apply. Its first readings after the apply fall in or just after the restart, when the TV's lookups go unanswered. The canary needs three low readings in a row (90 s) to revert, so a short restart alone should not trip it. A slow one (a 212k-rule rebuild on a Pi 5 has no measured duration, 04 F1) followed by a cold-cache burst could.
- AdGuard keeps its DNS cache in memory (`cache_optimistic: true` is set by tvgw, `adguardcfg.py` line 109), so every restart throws away the stale answers that would carry the TV through a PIA outage. (That the cache is not persisted across restarts is unverified; I found no persistence option in the [OpenAPI file](https://raw.githubusercontent.com/AdguardTeam/AdGuardHome/master/openapi/openapi.yaml).) A restart followed within minutes by a PIA reconnect is the worst case for the TV's DNS, and the ledger can show it.
- A revert is itself a restart. A collapse caused by a restart that a revert triggered would be blamed on the *next* rule.

AdGuard has an endpoint that changes the custom rules without a restart, `POST /control/filtering/set_rules` with a `rules` array ([OpenAPI](https://raw.githubusercontent.com/AdguardTeam/AdGuardHome/master/openapi/openapi.yaml)). Using it for machine rules would remove the restart from every add and revert. AdGuard writes its YAML itself, and `tvgw adguard diff` can confirm afterwards that the file equals the plan. That trades a little of decision 6's "configured as code by file" for no DNS gap per decision. It is an owner decision. I list it in [What to build here](#what-to-build-here) as optional, behind the ledger.

**The dispatcher turns uncontrolled events into tvgw-apply runs.** `90-tvgw-dispatcher` runs `tvgw-apply` on `up` and `dhcp4-change` for `wlan0` (the uplink), `eth0` and `tun0` **(code)**. So each PIA reconnect (`tun0 up`), Wi-Fi re-association (`wlan0 up`), DHCP renewal (every 2 hours, at the same minute, per the 2026-10-30 incident) and TV-port flap (`eth0 up`) produces an apply. Today the script logs none of its arguments. Logging `$1 $2` from the dispatcher costs one line and records three uncontrolled sources at once, with exact times. The persistent journal keeps it from 2026-10-31 on.

**The fixed schedule collides with itself.** The Pi runs on Central time, which is UTC−6 from 2026-11-01. A machine rule is applied at 03:50 local (09:50 UTC, `tvgw-analyst.timer`). 04's Stage B would promote lists at 12:30 UTC, about 06:30 local. The DoH list update runs `OnCalendar=daily` with up to an hour of random delay, so it falls between 00:00 and 01:00 local. DHCP-renewal applies come every 2 hours. With 04 and 03 both built as written, **every** rule applied at 03:50 shares its first evening of viewing, the only hours the judge can use, with a list promotion made about 3 hours after the rule. 04's post-promotion canary would also run at 06:30 local, when the TV is usually off. That is the blindness 03 F2 hole 3 found for the 03:50 canary, now repeated for lists.

## F3. The judge's arithmetic multiplies confounders: min-of-n hours, end-time accounting, no demand model

`autoblock.judge` has two tests **(code)**. Each hour during the trial, it checks the *last full clock hour*: if that hour had an `Active` reading and its rate is under `HOURLY_COLLAPSE = 0.2` of the 3-day baseline, it reverts. At the end of the trial, it compares the whole window at `STREAMING_COLLAPSE = 0.5`. Three properties of this design turn ordinary variation into reverts.

**1. The hourly test is a minimum over n TV hours.** A rule reverts if *any* TV hour in its trial falls under 20%. If an innocent TV hour falls under 20% of baseline with probability p, independently, the false-revert rate from the hourly test alone is 1 − (1 − p)ⁿ **(computed)**:

| p (innocent hour under 20%) | n = 2 TV hours | n = 4 | n = 8 | Same, but requiring 2 consecutive low hours: n = 2 / 4 / 8 |
|---|---|---|---|---|
| 0.02 | 4.0% | 7.8% | 14.9% | 0.0% / 0.1% / 0.3% |
| 0.05 | 9.8% | 18.5% | 33.7% | 0.3% / 0.7% / 1.7% |
| 0.10 | 19.0% | 34.4% | 57.0% | 1.0% / 2.8% / 6.3% |
| 0.20 | 36.0% | 59.0% | 83.2% | 4.0% / 10.4% / 22.1% |

The consecutive-hours column assumes independence. Low hours are *not* independent: an evening on an HDMI source or a PIA outage is a run of low hours. So "two in a row" helps against noise and does nothing against those confounders. Removing them needs the hour classifier below. p for this household is unknown. Three things below inflate it.

**2. Bytes are credited to the hour a connection ended.** `streaming_rate` selects flows with `t_end` in `[a, b)` **(code)**. A video connection that stays up across a clock hour puts all its bytes in the hour it closes. The hour it spans with no closing shows nothing, and with the TV `Active` that hour reads as a collapse. `nf_conntrack_tcp_timeout_established = 7440` means an idle-but-open connection can last two hours. How long this TV's streaming connections actually live is unmeasured. Test:

```sql
-- share of the TV's content-sized download bytes carried by flows that span at least one clock-hour boundary
SELECT round(100.0 * sum(CASE WHEN CAST(t_end/3600 AS INT) > CAST(t_start/3600 AS INT) THEN bytes_down ELSE 0 END)
             / sum(bytes_down), 1) AS pct_bytes_spanning_an_hour,
       round(100.0 * sum(CASE WHEN t_end - t_start > 3600 THEN bytes_down ELSE 0 END) / sum(bytes_down), 1)
             AS pct_bytes_in_flows_over_1h
FROM flows WHERE t_end > strftime('%s','now','-14 days') AND bytes_down > 1048576;
```

(Run it with `tvgw sql`. It uses every content-sized flow, not just the expected categories, which avoids pasting `queries.FLOW_NAME` into the query. For the exact judge population, join through that expression.) If the share is large, the fix is to **prorate** each flow's bytes over its `[t_start, t_end]` overlap with the hour. That is a few lines in `streaming_rate`. It changes the metric's definition, so it is itself a `metric_affecting` deploy, and the baseline after it must not be compared with judgments made before it.

**3. "Active" is not "demand".** An `Active` reading on an HDMI source, Live TV or the launcher has zero expected-category bytes by construction, and this household uses HDMI sources. On webOS the input apps are identified as `com.webos.app.hdmi1` to `hdmi4` and `com.webos.app.livetv` (common in LG integrations; **unverified** on this CX). Test: `tvgw sql "select app, count(*) from tvstate where power='Active' group by app order by 2 desc"`. Every such hour is a guaranteed "collapse" for the hourly test, and the baseline divides by them too. An hour should count as *demand* only if a streaming app was in the foreground at its reading, or if expected-category lookups or flow starts happened in it.

**What the gate-set fix and similar changes do.** 06 F2's one-word `expires` fix changes the DNS-gate counts, which feed novelty and the brief but not `streaming_rate`. It belongs in the ledger as `metric_affecting: gate`, not as a judge confounder. The rule is general: a deploy that changes how a number is computed is a confounder for every comparison that spans it, and the ledger is where that is recorded.

## F4. Placebo trials with confounder hours: the procedure, and what can be predicted before running it

03 F7 proposed placebo runs: pretend a rule was added at each hour h of the last 60 days, run `judge`'s arithmetic over `[h, h + TRIAL)`, and count reverts as the false-revert rate α. Extend it as follows. Like 03's, it is read-only and needs no API.

1. **Label every hour.** For each clock hour, compute `class ∈ {clean, confounded, no_demand, off}` from the ledger and the store with the rules in [the hour classifier](#the-hour-classifier). For history before the collectors exist, use what the store and the persistent journal hold:
   - `ingest_runs.warnings` with lost events in the hour;
   - a `pcaps_done` row with `tls_rows = 0` for an hour the TV was `Active`;
   - early-destroyed `ESTABLISHED` flows;
   - an upstream-failure share above 5% of the TV's A lookups;
   - an `auto_rules` add or decide;
   - a `rules` change;
   - a firmware change;
   - a name's first list block (04's SQL);
   - from `journalctl` since 2026-10-31: `eth0` and `wlan0` "Link is Down", AdGuardHome starts, `tvgw-apply` runs, boots and PIA daemon state changes (`/opt/piavpn/var/daemon.log`, if the app logs there, **unverified**).
2. **Run three placebo arms per h.**
   - **A, as shipped:** `judge` exactly as it is.
   - **B, confounders excluded:** the same, skipping confounded and no-demand hours in the hourly test and leaving them out of both sides of the final comparison.
   - **C, the proposed judge:** B, plus prorated bytes, plus suspension in place of revert ([F5](#f5-nodata-suspension-and-extension-what-the-canary-literature-does-and-what-fits-a-one-tv-gateway)).
3. **Report, for each arm:**
   - α, the share of h that would revert, split into reverts from the hourly test and from the final test;
   - the blind-pass rate, the share of h that would pass with "too little to compare";
   - the share of h whose trial held at least one confounded hour;
   - the share whose *reverting hour* was confounded. **This is the false-revert rate attributable to confounders.**
4. **Report the co-occurrence directly (question 2):**

```sql
-- for each controllable change, the other changes of effect class A inside its 24 h trial window
SELECT c.id, c.kind, datetime(c.t,'unixepoch','localtime') AS at,
       count(o.id) AS others_in_window, group_concat(DISTINCT o.kind) AS kinds
FROM changes c LEFT JOIN changes o
  ON o.id <> c.id AND o.t >= c.t AND o.t < c.t + 86400 AND o.effect_class = 'A'
WHERE c.controllable = 1 AND c.kind IN ('machine_rule_add','list_promote','profile_deploy')
GROUP BY c.id ORDER BY c.t;
```

**What can be said before it runs.**

- **Co-occurrence of any two changes in a trial window is effectively 100%.** It follows from the schedules (F2): about 12 DHCP-renewal applies a day, one DoH-update apply, one list refresh or more, and the analyst's own AdGuard restart. Counting all changes is therefore useless. Weight them by effect. Class A changes can move the metric: AdGuard restarts, list deltas on the TV's names, deploys, link flaps, PIA outages, reboots, conntrack drops, capture faults and app-mix hours. Class B changes are applies that touched no routing and destroyed no entry, plus verify runs. Only class A counts as a confounder.
- **Arm A's α is bounded below by the HDMI share.** If a fraction f of the TV's `Active` hours are on an input with no streaming, then in a trial with n TV hours, P(at least one HDMI hour) ≈ 1 − (1 − f)ⁿ, and each such hour reverts under arm A. At f = 0.1 and n = 4, that is 34% **(computed, from the table in F3)**. Arm B removes it entirely by construction. So arm B's α is the number that measures the judge.
- **Decision rule.** Adopt the classifier if arm B's α is at least 2 points lower than arm A's at no loss of power at f = 0.3 synthetic breakage (03 F7 step 2). Adopt the end-time proration if arm C beats B. If arm B still shows α above 5% on clean hours alone, the judge's thresholds, not its confounders, are the problem, and 03 F7's TRIAL and threshold search applies.

**Command to build** (`tvgw autoblock calibrate`, 03's item 6, extended): `sudo tvgw autoblock calibrate --days 60 --arms A,B,C --by-class`, writing `reports/calibrate/<date>.json` with the four numbers per arm and the per-hour labels.

## F5. NODATA, suspension and extension: what the canary literature does and what fits a one-TV gateway

**What Kayenta does.** Spinnaker's judge classifies each metric as `Pass`, `High`, `Low` or `Nodata` ("Insufficient data for comparison"). A `Nodata` metric "is excluded from group score calculations". If all metrics in a group are `Nodata`, the group scores 100, but "if 50% or more of all metrics are classified as `Nodata`", the canary score is set to 0, a fail ([Spinnaker, canary judge](https://spinnaker.io/guides/user/canary/judge)). A metric can instead be configured `NodataFailMetric`. So Kayenta never lets missing data pass silently in bulk. It makes it count against the canary.

**Why Kayenta does not face tvgw's problem.** Kayenta compares a canary with a baseline *deployed at the same time*. Google and Waze's guidance is "Don't compare the canary to production instances", and the baseline should be identical "in terms of time of deployment, number of instances, and type and amount of traffic" ([Google Cloud, lessons from Google and Waze](https://cloud.google.com/blog/products/devops-sre/canary-analysis-lessons-learned-and-best-practices-from-google-and-waze)). A concurrent control cancels time-varying confounders. The uplink got worse for both, the CDN slowed for both. tvgw has one TV, so its control is the TV's own past, and every time-varying cause lands on the rule. Google's SRE workbook names this: "time is one of the biggest sources of change in observed metrics", and "We strongly advise running only one canary deployment at a time", because "simultaneous canaries also increases the risk of signal contamination" ([SRE workbook, Canarying releases](https://sre.google/workbook/canarying-releases/)).

**What Azure's Gandalf adds.** For attribution among many changes, Gandalf counts a fault *after* a change as a vote for that change and a fault *before* it as a veto, over windows from 1 hour to several days, with shorter windows weighted more ([Li et al., NSDI 2020](https://www.usenix.org/conference/nsdi20/presentation/li); [summary](https://blog.acolyer.org/2020/02/28/microsoft-gandalf/)). The veto transfers directly. Suppose the symptom the judge sees started before the rule: low throughput on the uplink, or DNS failures. Or suppose it shows equally in hours whose TV activity never touched the blocked name. Then the rule is vetoed as the cause.

**Recommendation (question 3): yes to NODATA, and also a third outcome.** The costs are asymmetric. A wrongly kept rule can break the owner's viewing, and a wrongly dropped rule leaks a telemetry name for longer. So the judge should be strict in different ways for pass and for revert:

| Hour's class | Hourly test says collapse | Hourly test says fine | Counts toward the final verdict |
|---|---|---|---|
| `clean` | **Revert** (a verdict, as today) | Nothing | Yes |
| `confounded` | **Suspend**: take the rule out (the safe direction), record `suspended: <confounder>`, requeue it with a new trial after the confounder has cleared for 24 h. A second suspension of the same rule becomes a revert verdict | Nothing (NODATA for the hour) | No |
| `no_demand` (TV on an input, launcher, or no expected-category lookups or flow starts) | NODATA | NODATA | No |
| `off` | n/a | n/a | No |

- **Pass only on clean evidence.** The final verdict needs K clean demand hours (03 F7 proposes counting the trial in TV hours; K comes from its calibration). If K is not reached by `trial_until`, the result is **NODATA: extend** up to 03's 14-day ceiling, never "passed: too little to compare". At the ceiling, the rule stays on probation and is listed in the brief.
- **Hard red lines ignore class.** A must-allow name blocked, a clock lookup blocked, or 03 F7's retry storm (the blocked name's lookups at more than 10 times their pre-block rate for 2 TV hours) reverts in any hour. These signals are specific to the rule and are not explained by the uplink.
- **The canary gets the same treatment.** If `eth0` `carrier_changes` or AdGuard's `InvocationID` changed during the 10 minutes (other than the apply's own restart), or the PIA state left `Connected`, the canary ends `unobserved: <confounder>` and the hourly judge takes over.
- **A requeued rule keeps its history.** This needs 03 F1's append-only `decisions` table. `auto_rules` keyed by rule would overwrite the first trial.

**Optional and stronger: a switchback trial.** Instead of "rule on for 24 h, compare with the 3 days before", alternate the rule on and off in blocks of TV-on time, and compare on-blocks with off-blocks that share the same evening, uplink and CDN. This is the switchback design used where only one unit can be treated ([Bojinov, Simchi-Levi and Zhao, Management Science 2023](https://arxiv.org/abs/2009.00148v4)). Their analysis handles *carryover*. Here carryover is short: the blocked answer's TTL of 60 s (`blocked_response_ttl`) plus any app-level retry state. The cost is privacy: the name is unblocked for half the probation. Each switch is also an AdGuard restart under today's apply, so switchback is only sensible after the restart-free `set_rules` path ([F2](#f2-two-of-the-gateways-own-automatic-changes-are-confounders-by-construction)). Treat it as an open question, not a first build.

## F6. Scheduling: one lock, and what it costs at the arrival rates

The SRE workbook states the constraint: "If you release daily, you can't let your canary last for a week while running only one canary deployment at a time" ([SRE workbook](https://sre.google/workbook/canarying-releases/)). Model the trials as a single-server queue with Poisson arrivals at rate λ and a fixed trial length S. The mean wait before a change can start its trial is Wq = ρS / (2(1 − ρ)), where ρ = λS (M/D/1). With λ per week and S in days **(computed)**:

| Exclusive changes per week (λ) | S = 1 day (today's TRIAL) | S = 2 days (about K clean TV hours on a 3-hour viewing day) | S = 3 days |
|---|---|---|---|
| 1 | ρ = 0.14, wait about 2 h | ρ = 0.29, about 10 h | ρ = 0.43, about 27 h |
| 2 | ρ = 0.29, about 5 h | ρ = 0.57, about 32 h | ρ = 0.86, about 9 days |
| 3 | ρ = 0.43, about 9 h | ρ = 0.86, about 6 days | unstable (ρ > 1) |
| 5 | ρ = 0.71, about 30 h | unstable | unstable |
| 7 (every daily list promotion as a trial) | **ρ = 1: unstable**; a machine rule would never get a window | unstable | unstable |

**Consequences.**

- **"Never apply a list promotion and a machine rule within the same 24 h" is infeasible if every list promotion counts.** HaGeZi Pro changes about 1,400 entries a day (04 F2), so a promotion arrives every day. Treat as an exclusive trial only a promotion whose **effective delta on the TV's names is not empty** (04 Stage A's `list_delta` against N, the names that matter). A promotion that changes nothing the TV looked up in 30 days cannot move this TV's metric, except through the engine rebuild, which the ledger records as an AdGuard event. It goes ahead under any trial. How often the delta on N is non-empty is unmeasured. 04's post-hoc SQL over the store gives the historical rate today.
- **Machine-rule arrivals are low.** Decision 22's first week bought three requests, all answered "nothing to do" (the owner's notes), so λ for machine rules is under 1 a week so far. With N-touching promotions at, say, 1 to 2 a week, the table gives a mean wait of 5 to 32 h, depending on S. That is cheap: a telemetry name unblocked one more day, or a list change a day late, while Pro already covers most of it.
- **Batching is the release valve.** List promotions are not urgent. 04 marks a list stale only at 7 days. When a promotion is queued behind a trial, the next day's version supersedes it, so the queue holds at most one pending promotion per list and never grows. Machine rules queue in 03's `pending` state, at most `MAX_PER_DAY` a day.
- **Priority.** Run the machine rule first, when one is pending, because its trial is the one with a model's decision behind it. Then run the promotion. A must-allow fix from the owner (a profile deploy that only *removes* blocks) pre-empts both: unblocking cannot break the TV, and it ends any running trial as `suspended: owner deploy`.
- **Uncontrolled changes cannot be scheduled.** Firmware, app updates, LG configuration, link flaps, PIA and Wi-Fi go through NODATA and extension (F5), not the lock. The TV's automatic-update settings are the owner's lever for firmware and apps.
- **Code deploys during development.** Every push to `main` that touches code deploys through CI's hardware job ([deploy/README.md](../../../deploy/README.md#how-a-change-reaches-the-gateway)). While development is active, that is the most frequent class-A event of all. `sync-install.sh` should take the same lock in *shared* mode and record a ledger row. A deploy that restarts AdGuard or a capture unit marks the hour confounded. A deploy flagged `metric_affecting` ends every running trial as `suspended: metric changed`.

**The lock itself.** One file, `/run/tvgw/trial.lock`, plus one row per running trial in `decisions`. `analyst.autonomous`, the list promoter, `install.sh` and `tvgw undo` check it. Only `autonomous` and the promoter take it exclusively.

## F7. Cheap signals that separate "the network got worse" from "the block broke it"

The judge's metric, volume, mixes demand (what was watched) with supply (how fast the path was). A block that breaks an app removes demand that would otherwise have been met: the app stops fetching, or falls back to the launcher. A worse path removes supply: the app keeps fetching, at a lower bitrate. Streaming players adapt bitrate to measured throughput, and Netflix, for one, asks for 15 Mbps for UHD ([Netflix Help Center](https://help.netflix.com/en/node/306)). So on a Wi-Fi uplink a supply drop shows up as *less volume with the same activity*. Signals by cost, each with what it reads and its threshold (to be calibrated on the store's own distribution, as 04 does with its holds):

| Signal | Source | Cost | Points to | Starting threshold |
|---|---|---|---|---|
| Expected-category **flow starts and lookups** in the hour | `flows`, `dns` (exist) | Free | Demand present (tried) vs absent | Starts under 20% of baseline starts per TV hour means no demand or broken; at or above means demand was there |
| Foreground app at the reading | `tvstate.app` (exists) | Free | `no_demand` when an input, Live TV or the launcher | Any input or launcher app means `no_demand` |
| Per-flow **goodput** of content flows: `bytes_down / (t_end − t_start)` for flows over 4 MB | `flows` (exists) | Free | Supply: ABR stepped down for every app at once | Hourly median under 50% of the 14-day median, with starts normal, means `confounded: supply` |
| **Retries of the blocked name** after the block | `dns` (exists; 03 F7) | Free | The block | Over 10 times the pre-block rate for 2 TV hours: revert in any class |
| AdGuard **upstream failures** among the TV's lookups | `dns`: not blocked, no answer, not cached, long `elapsed_ms` | Free | DNS path (PIA, upstream) | Over 5% of the TV's A lookups in the hour means confounded |
| **PIA state** | `piactl get connectionstate`: `Connected`, `Reconnecting`, `Interrupted` and others ([PIA CLI](https://helpdesk.privateinternetaccess.com/kb/articles/pia-desktop-command-line-interface-2)); plus the dispatcher's `tun0 up` lines | One call per sample | DNS path | Any sample not `Connected`, or a `tun0 up`, in the hour means confounded |
| **Wi-Fi uplink**: signal, rx and tx bitrate, tx failed | `iw dev wlan0 station dump`. On brcmfmac in client mode, the driver fills `SIGNAL`, `TX_BITRATE`, `RX_BITRATE`, `TX_PACKETS` and `TX_FAILED`, but **not** `TX_RETRIES` or `BEACON_LOSS` ([brcmfmac cfg80211.c, v6.18](https://raw.githubusercontent.com/torvalds/linux/v6.18/drivers/net/wireless/broadcom/brcm80211/brcmfmac/cfg80211.c)), and only when the firmware reports station statistics (unverified on this Pi) | One call per sample | Supply | Signal more than 6 dB below its 14-day median, or rx bitrate under its 10th percentile, in 2 samples of the hour |
| `wlan0` **carrier changes** | `/sys/class/net/wlan0/carrier_changes`, which counts "the number of times the link has seen a change from UP to DOWN and vice versa" ([sysfs-class-net ABI](https://raw.githubusercontent.com/torvalds/linux/v6.18/Documentation/ABI/testing/sysfs-class-net)) | A file read | Supply | Any increase |
| `eth0` **carrier changes** (08 F2) | `/sys/class/net/eth0/carrier_changes` | A file read | The TV's port | Any increase while the TV was `Active` |
| **Competing upload** on the uplink | `wlan0` tx_bytes minus `eth0` rx_bytes per sample: the Pi's own upload, mostly the torrent client, inside the tunnel. No API needed. qBittorrent's `/api/v2/transfer/info` gives `up_info_speed`, `dl_info_speed` and `dht_nodes` if the owner enables `bypass_local_auth` ([qBittorrent WebUI API](https://github.com/qbittorrent/qBittorrent/wiki/WebUI-API-(qBittorrent-4.1))) | Free (counters) | Supply | The Pi's own upload above 50% of the hour's peak TV download rate means confounded (calibrate) |
| **Conntrack pressure** | `nf_conntrack_count`, `nf_conntrack_max`, and the summed `drop`, `early_drop` and `insert_failed` from `conntrack -S` | One call per sample | New connections refused | `drop` or `insert_failed` increased, or count over 75% of max: confounded |
| AdGuard **restart** outside tvgw's applies | `systemctl show AdGuardHome -p InvocationID,NRestarts` | One call | DNS gap | `InvocationID` changed with no matching apply row |
| **Gateway reboot** | `/proc/sys/kernel/random/boot_id` | A file read | Everything | Changed means confounded for 1 hour |
| Capture and naming coverage | `pcaps_done.tls_rows`, `ingest_runs.warnings` (exist) | Free | The measurement, not the TV | Zero TLS rows with the TV `Active`, or lost events: confounded (measurement) |

**What a full conntrack table actually does, read from v6.18.** `__nf_conntrack_alloc` prints "nf_conntrack: table full, dropping packet" and refuses the new entry only when `early_drop()` fails. `early_drop` skips entries with the `IPS_ASSURED` bit. The `drop` statistic is incremented by the caller, `nf_conntrack_in`, and `early_drop` only when an entry was evicted ([nf_conntrack_core.c, v6.18](https://raw.githubusercontent.com/torvalds/linux/v6.18/net/netfilter/nf_conntrack_core.c)). So a full table does not kill the TV's established, assured streams. It evicts unassured entries first, such as one-way torrent DHT probes, and refuses *new* connections only when the buckets it scans hold nothing unassured. The symptom is "a stream does not start" or "the next segment's new connection fails", which the flow-starts signal sees as fewer starts with demand present. The default size settles 06 F8's unverified point. With the size auto-derived, `nf_conntrack_max = nf_conntrack_htable_size` (`max_factor = 1`). That is 262144 on a 64-bit board with more than 4 GiB of RAM, and 65536 above 1 GiB. **The owner's 8 GB Pi 5 therefore already has 262144**, and 06's sysctl line changes nothing on it. It matters on a 4 GB board, so keep it in the package for the next build. Together with qBittorrent's default of 500 global connections (`max_connec`), this makes table-full unlikely on this board. Record it anyway: the counters are cheap, and a stuck torrent client with DHT on is the case that would surprise.

**How the signals combine** into an hour's class:

- **Demand:** a streaming app in the foreground at the reading, *or* at least `MIN_STARTS` expected-category flow starts, *or* expected-category lookups. Otherwise the hour is `no_demand`.
- **Confounded:** demand present *and* any confounder flag in the hour or the 10 minutes before it.
- **Clean:** demand present and no flag.

A clean hour with volume collapsed, starts down and app-to-launcher or retries up is the block's signature. A confounded hour with volume down, starts normal and goodput down is the network's.

## Design: the ledger, the hour classifier, the judge, the lock, the brief

### The `changes` table

```sql
CREATE TABLE IF NOT EXISTS changes(
  id INTEGER PRIMARY KEY,
  t REAL NOT NULL,              -- when it took effect (or the sample that first saw it)
  t_end REAL,                   -- for intervals: an outage's end; NULL for a point event
  t_precision REAL NOT NULL,    -- seconds of uncertainty: 0 for logged events, 600 for a counter seen between samples
  source TEXT NOT NULL,         -- autoblock | lists | deploy | apply | dispatcher | sampler | ingest | tv | journal
  kind TEXT NOT NULL,           -- machine_rule_add | machine_rule_revert | list_promote | list_refresh | profile_deploy
                                -- | code_deploy | apply | adguard_restart | unit_restart | reboot | eth0_flap | wlan0_flap
                                -- | pia_down | ct_drop | ct_pressure | wifi_degraded | uplink_contention | dns_upstream_fail
                                -- | capture_gap | ct_event_loss | early_destroy | firmware | app_update | lg_config
  subject TEXT,                 -- the rule, the list id, the git SHA, the unit, the interface
  detail TEXT,                  -- JSON: counter deltas, trigger, effective-delta counts, versions; no addresses
  controllable INTEGER NOT NULL,-- 1 if tvgw could have scheduled it
  effect_class TEXT NOT NULL,   -- A (can move the TV's metrics) | B (logged, cannot)
  metric_affecting TEXT         -- NULL | streaming | naming | gate | dns: which computed number it changes
);
CREATE INDEX IF NOT EXISTS changes_t ON changes(t);
```

- **Writers.** It is append-only and never updated. Each writer owns its kinds. `autoblock` writes rule events. The promoter writes list events, carrying its `list_delta` counts on N. `install.sh` writes deploys, with the git SHA, the restarted units and `metric_affecting` from the changed paths. `tvgw-apply` and the dispatcher append a line to `/var/lib/tvgw/changes.spool`, a file and not the database, because both are shell, and the hourly ingest loads it. The sampler (below) writes counter-derived events. Ingest writes `capture_gap`, `ct_event_loss` and `early_destroy` from the tables it already loads. The TV reader writes `firmware`. A view writes `app_update` and `lg_config`.
- **Privacy.** Nothing in it is a TV name except `subject` on rule and list events, which already appear in the brief. No address, MAC or host name goes in `detail`. It inherits the store's retention.

### The sampler (inside `tvgw verify --record`, every 10 minutes)

One row in `gw_samples(t, boot_id, eth0_cc, wlan0_cc, tun0_present, tun0_cc, pia_state, wlan_signal, wlan_rx_mbps, wlan_tx_mbps, wlan_tx_failed, wlan_rx_bytes, wlan_tx_bytes, eth0_rx_bytes, eth0_tx_bytes, ct_count, ct_max, ct_drop, ct_early_drop, ct_insert_failed, agh_invocation, agh_nrestarts, filter_mtimes)`. That is 144 rows a day, a few KB.

- **Deriving events.** The ledger events come from the difference between consecutive samples: a changed `boot_id`, a counter that rose, a changed `InvocationID`, or a PIA state other than `Connected`.
- **Counter resets.** Interface counters reset at reboot, which the `boot_id` check catches. They are 32-bit (`carrier_changes`) or 64-bit (the byte counters), so wrap is not a concern at these rates.
- **Missing tools.** Each source is optional. A missing `piactl` or `iw` gives a NULL, never a failure of `verify`.

**Test:** after a deploy, `tvgw sql "select count(*), min(t), max(t) from gw_samples where t > strftime('%s','now','-1 day')"` returns about 144. Then unplug and replug the TV's cable once, with the owner present: one `eth0_flap` row appears within 10 minutes, with `t_precision = 600`.

### The hour classifier

`classify_hour(conn, h) -> ('off'|'no_demand'|'confounded'|'clean', reasons)` applies the rules of [F7](#f7-cheap-signals-that-separate-the-network-got-worse-from-the-block-broke-it) over `[h − 600 s, h + 3600 s)`. The confounded flag is any `effect_class = 'A'` change except the rule under trial's own `machine_rule_add`. The apply's own AdGuard restart is excused only for the 5 minutes after the rule's `added_t`. The thresholds start at the values in F7's table and are calibrated by `tvgw autoblock calibrate --by-class` (F4). One function feeds the judge, the canary's end condition, the placebo runs and the brief.

### The judge, changed

`autoblock.judge` returns one of `reverted`, `suspended`, `passed`, or None (keep watching, NODATA included), following F5's table:

- **Rates.** `streaming_rate` counts only clean demand hours on both sides, and prorates each flow's bytes over its overlap with the hour if F3's test shows spanning flows matter.
- **Pass.** Needs K clean demand hours.
- **Ceiling.** At 03's 14-day ceiling the rule stays on probation and the brief lists it.
- **Suspension.** A suspended rule leaves `auto.rules` like a reverted one and returns to `pending` with a `not_before` of the confounder's end plus 24 h. A second suspension is a revert.
- **Recording.** Every hour's class and every verdict goes into 03 F1's `decisions` table, so a second trial of the same rule does not overwrite the first.

### The lock

The lock follows [F6](#f6-scheduling-one-lock-and-what-it-costs-at-the-arrival-rates): `/run/tvgw/trial.lock` and a `pending` queue.

- **Exclusive holders:** a machine-rule trial, and a list promotion whose delta on N is not empty.
- **Shared holders:** promotions with an empty delta on N, and `install.sh`. A deploy writes a ledger row and, if it is `metric_affecting` or restarts AdGuard or a capture unit, suspends the running trial.
- **Priority:** machine rule, then promotion. An owner deploy that only removes blocks pre-empts both.
- **Queue limits:** one pending version per list (newer supersedes) and `MAX_PER_DAY` machine rules.

### The brief: "Changes in effect"

This section is printed in every brief, after the red lines and before "Rules the gateway added on its own", so the owner reads what changed before reading what the machine concluded. It answers question 6. Illustrative, with no real names:

```text
Changes in effect (window 2026-11-02 00:00 - 2026-11-03 00:00, Central):
  On trial   ||beacon.example-tv.net^   added 11-02 03:50; clean TV hours 3 of 6 needed; judge: watching
  Gateway    03:50 AdGuard restart (machine rule)   07:31 list HaGeZi Pro -> 2026.1102 (TV names: 0, not a trial)
             00:37 DoH list apply (no routing change)   apply x12 (DHCP renewal, no routing change)
             deploy 14:05 a1b2c3d (restarted: tvgw-dnsgate; metric-affecting: no)
  Uplink     20:10-20:40 PIA reconnecting (2 tun0 up)   21:00-22:00 Wi-Fi signal -9 dB below its 14-day median
             upload contention 19:00-23:00 (Pi's own upload 61% of peak TV download)
  TV path    eth0 link flaps: 0   conntrack: max 262144, peak 3% full, drops 0
  TV         firmware unchanged (04.64)   app downloads: 1 (Content Store, 18:12)   LG config fetch size changed: 1
  Evidence   capture: all hours named   conntrack lost events: 0   connections broken by the gateway: 0
  Hours      TV on 6: clean 3, confounded 2 (PIA 20h; Wi-Fi 21h), no demand 1 (HDMI 22h)
```

- **Rows:** grouped by where the change acts: *On trial* (with progress toward K), *Gateway* (tvgw's own changes), *Uplink*, *TV path*, *TV*, *Evidence* (the measurement itself), and *Hours*, the classifier's summary, which says how much of the window the judge could actually use.
- **Collapsing:** class B events collapse to a count with their trigger. Class A events print with times.
- **Red line:** a trial that has spent more than half its ceiling without reaching K clean hours.
- **Analyst pack:** a counts-only copy, `changes_in_effect`, with kinds, counts and the hour classes, never `detail`. A model that sees "firmware changed, PIA was down two hours" weighs new names and gaps accordingly.

---

## Where this disagrees with earlier sections

1. **03 F7, "`MAX_CONCURRENT_TRIALS = 1` ... costs nothing at the observed arrival rate."** True for machine rules alone. It stops being true once 04 Stage B promotes a list every day under its own canary and probation: as exclusive trials, daily promotions give ρ = 1 and starve every machine rule. One lock must cover both, and only promotions that touch the TV's names may hold it exclusively (F6).
2. **03 F7's placebo** measures α over a mix of clean and confounded hours, and attributes it all to the thresholds. The HDMI share alone can give arm A an α of tens of percent, which no threshold tuning removes. Label the hours first (F4).
3. **03 F7, "Replace 'passed: too little to compare' with 'still on probation'."** Agreed, and taken further. A *revert* in a confounded hour also must not be a verdict. It becomes a suspension and a requeue, or confounders will discard good rules permanently (F5).
4. **04 Stage B, "OnCalendar 12:30 UTC ... with a whole day of the hourly judge's probation after it", and "After promotion: if the TV is streaming, run the existing 10-minute canary".** At 06:30 Central the TV is usually off, so this canary is as blind as the 03:50 one (03 F2 hole 3). The promotion also sits inside every 03:50 machine rule's trial. The fixed time should give way to the lock: promote when no exclusive trial runs, and watch the promotion at the next clean demand hour, not at the clock time.
5. **06 F8, "`nf_conntrack_max = 262144` ... headroom against the torrent client".** On the owner's 8 GB board the auto-derived default is already 262144 (v6.18 source), so the line is a no-op there, and 06's "65536 for boards with up to 4 GiB" is right for the 1-4 GiB range. Also, a full table refuses *new* connections and spares assured ones (F7). It does not collapse a running stream, so the judge sees it as fewer starts, not as a throughput drop.
6. **08 F2, "a flapping TV port would cause a stream of applies, `counters.before-apply` resets and broken flows".** Since the 2026-10-30 fix, an apply that finds routing unchanged destroys no entry, so the applies are now benign (class B) and the counter resets are handled. What remains of a flap is the physical outage. The ledger records the flap from `carrier_changes`, and the confirmation that applies broke nothing comes from the `timeout_left` query in F1.
7. **Decision 20, "a stream breaking, is caught three ways".** It is caught, and so are many things that are not the rule. The design measures the gateway's *sensitivity* (the canary, the judge) and leaves its *specificity* unmeasured. This section is about specificity.

## What to build here

Ranked by false attribution removed per unit of work. Effort: S under a day, M a few days, L a week or more. Risk is risk to the running gateway.

| # | Build | Effort | Risk | Why |
|---|---|---|---|---|
| 1 | **Log the triggers.** The dispatcher writes `$1 $2` and the time to `/var/lib/tvgw/changes.spool`. `tvgw-apply` writes one line with its caller and whether it touched routing. `install.sh` writes the git SHA, the restarted units and `metric_affecting` from the changed paths | S | None (appends to a file; the dispatcher must still `exec` the apply on any write failure) | Records PIA reconnects, Wi-Fi and TV-port flaps, DHCP, DoH applies and deploys with exact times (F1, F2) |
| 2 | **The sampler in `tvgw verify --record`** (`gw_samples`): boot id, `carrier_changes`, `wlan0` station dump, interface bytes, conntrack count, max and stats, AdGuard `InvocationID` and `NRestarts`, PIA state, filter file mtimes. Each source is optional | S | Low (read-only reads every 10 min; a hung `piactl` needs a 5 s timeout) | Nine of the eleven missing sources from cumulative counters, with no events lost (F1, F7) |
| 3 | **The `changes` table and `tvgw changes [--since]`**: ingest loads the spool, derives events from samples and existing tables, and backfills from the persistent journal since 2026-10-31 | S-M | None (a new table) | One place for every source (question 1) |
| 4 | **The hour classifier plus `calibrate --arms A,B,C --by-class`** (extends 03's item 6) | M | None (read-only) | Measures the false-revert rate with and without confounders before the judge is changed (F4, question 2) |
| 5 | **Judge v2**: clean demand hours only, suspension in place of revert in confounded hours, NODATA and extend in place of a blind pass, proration if F3's test says so; the canary ends `unobserved: <confounder>` | M | Low. It reverts less on confounded hours and passes later. Hard red lines are unchanged. Run it in shadow beside the current judge for two weeks and compare verdicts in `decisions` | Questions 3 and 5 |
| 6 | **"Changes in effect" in the brief**, plus a counts-only `changes_in_effect` in the pack | S | None | Question 6 |
| 7 | **The trial lock and `pending` queue**, shared with 04 Stage B (only N-touching promotions are exclusive) and with `sync-install.sh` (shared mode) | M | Low-medium: it delays list promotions and machine rules, and a stuck lock must expire (a `trial_until` deadline plus the 14-day ceiling) | Question 4; makes 03's one-trial rule and 04's promotion compatible |
| 8 | Optional: **machine rules through `POST /control/filtering/set_rules`** instead of a stop and start, with `tvgw adguard diff` confirming the file afterwards | S-M | Medium: a second write path into AdGuard's config, against decision 6's file-only principle (owner decision) | Removes the DNS gap and cold cache from every add, revert and undo (F2) |
| 9 | Later: **switchback probation** (alternate the rule by TV-on blocks) once #8 exists | M | Medium: the name leaks for half the probation; more applies | A concurrent control for a one-TV gateway (F5) |

Order: 1 and 2 together (one branch, both S), then 3, then 4. Read its numbers before building 5. 6 can follow 3 at any time. Build 7 only when 04 Stage B is approved. 8 and 9 are owner decisions.

## Open questions

1. **How long do this TV's streaming connections live?** F3's query decides whether proration matters. If most bytes ride connections that span a clock hour, the hourly test is mostly measuring connection close times.
2. **What share of `Active` hours is `no_demand`?** `select app, count(*) from tvstate where power='Active' group by app`. Confirm the input app ids on webOS 5 (assumed `com.webos.app.hdmi1` and the like, unverified) and whether Live TV, the Pi desktop over HDMI and screen mirroring each show distinctly.
3. **How often does a list version touch N?** Run 04's post-hoc SQL over the store's history: the share of days on which some list began or stopped blocking a name the TV resolved in the 30 days before. That is λ for exclusive promotions in F6.
4. **Does `iw dev wlan0 station dump` on this Pi's brcmfmac firmware report `tx bitrate` and `signal`?** The driver fills them only with the station-statistics flag (`BRCMF_STA_SCBSTATS`). If they are missing, fall back to `/proc/net/wireless` and the interface byte counters.
5. **Does AdGuard Home persist its DNS cache across a restart?** I found no option for it. If it does not, every apply cold-starts the TV's DNS through PIA, and #8 gains weight.
6. **Can app versions be read over SSAP?** `ssap://com.webos.applicationManager/listApps` may carry a version per app (unverified; nothing found in public client libraries). If it does, add the version to the hourly reading. If not, the GFTS download view stands in.
7. **Is the GFTS response size a reliable date for LG configuration changes?** Test: list the plain-HTTP URIs fetched on most days with their `bytes`, and check whether size changes coincide with new names or with the 07 F4 drift test's flags.
8. **Where does PIA's daemon log state changes on Linux?** For the backfill before #2 exists. `/opt/piavpn/var/` is the likely place (unverified).
9. **Should a profile deploy during a trial suspend it?** It should if the deploy adds blocks, and needn't if it only removes them. That keeps the owner's fixes from being held up by the machine's experiment.

## Sources

Standards, kernel and vendor documentation (read 2026-11-01):

- Linux v6.18, `net/netfilter/nf_conntrack_core.c` (table sizing, `max_factor`, `early_drop` skipping assured entries, `drop` and `early_drop` statistics): <https://raw.githubusercontent.com/torvalds/linux/v6.18/net/netfilter/nf_conntrack_core.c>
- Linux v6.18, `Documentation/ABI/testing/sysfs-class-net` (`carrier_changes`, `carrier_up_count`, `carrier_down_count`): <https://raw.githubusercontent.com/torvalds/linux/v6.18/Documentation/ABI/testing/sysfs-class-net>
- Linux v6.18, brcmfmac `cfg80211.c` (`brcmf_cfg80211_get_station` station-info fields): <https://raw.githubusercontent.com/torvalds/linux/v6.18/drivers/net/wireless/broadcom/brcm80211/brcmfmac/cfg80211.c>
- Debian trixie, `conntrack(8)` (conntrack-tools 1.4.8; `-S`, `-C`, `-E`): <https://manpages.debian.org/trixie/conntrack/conntrack.8.en.html>
- systemd D-Bus API (`InvocationID`, `NRestarts`, `ActiveEnterTimestamp`): <https://www.freedesktop.org/software/systemd/man/latest/org.freedesktop.systemd1.html>
- AdGuard Home OpenAPI (`/filtering/set_rules`, `/filtering/refresh`, `/cache_clear`, `cache_optimistic`): <https://raw.githubusercontent.com/AdguardTeam/AdGuardHome/master/openapi/openapi.yaml>
- Private Internet Access, Desktop command line interface (`piactl get` and `monitor connectionstate`, state values): <https://helpdesk.privateinternetaccess.com/kb/articles/pia-desktop-command-line-interface-2>
- qBittorrent WebUI API (`/api/v2/transfer/info`, `bypass_local_auth`, `max_connec`): <https://github.com/qbittorrent/qBittorrent/wiki/WebUI-API-(qBittorrent-4.1)>
- Netflix Help Center, internet connection speed recommendations: <https://help.netflix.com/en/node/306>

Canary analysis, change attribution and experiment design:

- Spinnaker, How canary judgment works (`Nodata`, `NodataFailMetric`, the 50% rule, Mann-Whitney): <https://spinnaker.io/guides/user/canary/judge>
- Google SRE workbook, Canarying releases ("only one canary deployment at a time"; time as a source of change; canary length versus release cadence): <https://sre.google/workbook/canarying-releases/>
- Google Cloud, Canary analysis: lessons learned and best practices from Google and Waze (concurrent baseline, 50 data points, retrospective mode): <https://cloud.google.com/blog/products/devops-sre/canary-analysis-lessons-learned-and-best-practices-from-google-and-waze>
- InfoQ on Kayenta (a fresh baseline cluster in parallel with the canary): <https://www.infoq.com/news/2018/04/kayenta>
- Li et al., "Gandalf: An Intelligent, End-To-End Analytics Service for Safe Deployment in Cloud-Scale Infrastructure", NSDI 2020: <https://www.usenix.org/conference/nsdi20/presentation/li>; summary of its vote and veto attribution: <https://blog.acolyer.org/2020/02/28/microsoft-gandalf/>
- Bojinov, Simchi-Levi and Zhao, "Design and Analysis of Switchback Experiments", Management Science 2023 (arXiv 2009.00148, revised 2025-09): <https://arxiv.org/abs/2009.00148v4>

Earlier sections built on: [03](03-analyst-evaluation-and-safety.md) F1, F2, F7; [04](04-blocklists-and-verification.md) F1, F2, Stage A and B; [06](06-platform-and-kernel-depth.md) F2, F8; [07](07-measurement-and-presentation.md) F4; [08](08-next-build-hardware.md) F2; [the incident log](../../incidents.md) (2026-10-27, 2026-10-30); [design decisions](../../design-decisions.md) 1, 6, 20, 21, 22.

Code read (this worktree, `43b3bd9`): `src/tvgw/autoblock.py` (constants, `streaming_rate`, `judge`, `canary`), `src/tvgw/adguardcfg.py` (`apply`, `dns_ready`, `cache_optimistic`), `src/tvgw/db.py` (schema 7, `flows.timeout_left`), `src/tvgw/ingest.py` (`ingest_rules`, lost-event warnings), `src/tvgw/verify.py` (`record`, the reload pair), `deploy/networkmanager/90-tvgw-dispatcher`, `deploy/systemd/*.timer`, `deploy/README.md`. Owner context (no identifiers): the uplink is Wi-Fi; PIA carries the Pi's own traffic and AdGuard's upstreams; the board is an 8 GB Pi 5; the journal has been persistent since 2026-10-31; the household watches HDMI sources.
