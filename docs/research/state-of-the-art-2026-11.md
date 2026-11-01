# State of the art, November 2026: the second pass, and what the gateway gets wrong about itself

*R&D synthesis, 2026-11-01. This is a proposal, not a decision: nothing here is implemented. It is the executive report over fourteen section files in [deep-dive-2026-11/](deep-dive-2026-11/README.md), and it goes past [the October report](state-of-the-art-2026-10.md) (called "October" below). Where it disagrees with October, with a section file, or with the design decisions, it says so.*

**Method.** The section files were written on 2026-11-01 against the research worktree at `43b3bd9`, which has design decisions 1 to 22. `main` has since landed decisions 23 to 40: packaging, `tvgw setup`, the namespace CI gateway, supply chain, profiles v2, the extractor (JA4 from fields, split and nameless hellos), capture v2 (dumpcap, and the first-packets prototype behind `CAPTURE_MODE`), and the hourly radio check. This report reads both trees and checks each recommendation against `main` as of 2026-11-01. A critic flagged 21 claims in the section files as weak. Each was re-checked against a primary source the same day, and the result is in [§14](#14-claims-re-verified-for-this-report). No host was touched. **(verified)** means this report read the primary source itself. **(unverified)** means it could not. **(test)** gives the exact check to run on the gateway. No site identifiers appear: `TV_IP`, `GW_IP`, `TV_NET`, `TV_IF` and `WAN_IF` stand for the settings.

---

## Bottom line up front

**What changed in the world since October.**

- *Watching the Watchers* (Northeastern, PoPETs 2027) published its LG data: a 155 MB ACR packet trace and a 1.65 GB full-traffic header set ([Zenodo 22733487](https://zenodo.org/records/22733487), [22698120](https://zenodo.org/records/22698120); CC BY-NC-ND 4.0). For the first time there is a packet-level picture of LG's real ACR client.
- LG published a privacy statement on 2026-09-12, after the Gamers Nexus investigation of a 2025 G5 ([LG](https://www.lg.com/us/newsroom/corporate/statement-understanding-privacy-on-lg-smart-tvs), verified). It confirms device discovery and access-point surveying (gated on agreements), and denies storing voice offline for later upload.
- PIA's desktop client 3.8.0 (2026-10-16) makes WireGuard (`wgpia0`) the default for new installations ([CHANGELOG](https://github.com/pia-foss/desktop/blob/3.8.0/CHANGELOG.md)).
- AdGuard Home's beta channel moved to v1.0.0-b.1 on 2026-09-30, and AdGuard warns that 1.x minor releases may break compatibility ([releases](https://github.com/AdguardTeam/AdGuardHome/releases)).
- Anthropic shipped Opus 5.5 on 2026-09-22 at $4/$20 per MTok, 20% below Opus 5, defaulting to `medium` effort ([announcement](https://www.anthropic.com/news/claude-opus-5-5), [effort](https://platform.claude.com/docs/en/build-with-claude/effort.md), verified). API version `2026-10-21` rejects `temperature`, `top_p` and `top_k` with a 400 "even at the parameter's default value" ([migration guide](https://platform.claude.com/docs/en/api/migration-2026-10-21), verified). Fable 5.1, the default verifier, is a Covered Model that requires 30-day retention and is not available under zero data retention without Anthropic's authorization ([API and data retention](https://platform.claude.com/docs/en/manage-claude/api-and-data-retention), verified).

**What changed on the gateway.** Most of October's top ten is built on `main`. So this pass did not look for new tools. It looked for places where the gateway's model of itself is wrong. It found five that are wrong today, each fixable in days:

1. **Red line 7 cannot fire on LG's ACR.** Rebuilt as conntrack sees it, the released LG trace trips the shipped `acr_like` test on 0 of 17 days. LG's client opens a connection about every 60 s and uploads a fingerprint every 14 to 15 s *inside* it, on TCP 4431 ([13 §1.1](deep-dive-2026-11/13-gap-reconcile-the-two-incompatible-acr-detec.md)). `ACR_PERIOD = (10, 20)` and `ACR_PAYLOAD = 4096` are still in `queries.py` on `main`.
2. **The flow log's 32 MB buffer was a no-op.** `conntrack -b` sets the buffer on the request socket, not the event socket ([06 F1a](deep-dive-2026-11/06-platform-and-kernel-depth.md#f1-conntrack-events-the-buffer-bug-in-kernel-selection-and-lossless-delivery); confirmed by the critic against Debian's 1.4.8 source). The cure is in the kernel: `nf_conntrack_events=0` plus one `ct event set destroy` rule for the TV's connections.
3. **The DNS gate's set never refreshes an address.** On kernel 6.12 and later an `add element` without `expires` keeps the first expiry, so an address resolved every hour still drops out 24 h after it was first seen. That is half of decision 22's "gate noise" ([06 F2](deep-dive-2026-11/06-platform-and-kernel-depth.md#f2-the-dns-gates-set-timeout-update-semantics-on-612-and-later)). `dnsgate.batch` on `main` still sends `timeout {ttl}s` alone.
4. **The autonomy fails open in three places.** A name with no observed flows has a zero shape and passes the payload gate. The 03:50 canary almost always runs with the TV off. A trial with too few TV hours *passes*. And the hourly judge reverts on the minimum of n hours, so innocent noise is enough: at a 10% chance per hour, 4 TV hours give a 34% false-revert rate ([03 F2](deep-dive-2026-11/03-analyst-evaluation-and-safety.md#f2-the-code-gates-are-the-real-defense-and-they-fail-open-in-three-places), [16 F3](deep-dive-2026-11/16-gap-one-change-at-a-time-a-change-ledger-and.md)). `SYSTEM` on `main` still tells the model "You never apply anything".
5. **The Pi is open to the TV whenever `inet tvgw` is absent.** That happens at stop, at boot, after a failed apply and during package upgrades. Even while it is loaded, the input chain never checks the source address ([11 F1, F4](deep-dive-2026-11/11-gap-the-pi-is-the-tv-s-only-neighbour-the-tv.md)). The Pi's co-tenants include xrdp, which had pre-auth CVEs in 2026, and possibly an AirPlay 2 source build outside Debian's security support.

**Three new exposure categories,** none in October: the blocklist **update channel** (AdGuard replaces a list with an empty 200 response, verified at the v0.107.79 tag), the gateway's **own viewing record** (365 days by default, seven full backup copies on the card, and up to 180 days of query log), and **attribution under confounders** (every machine-rule apply restarts the resolver; HDMI hours read as collapses).

**What not to fear, now settled:** ECH on the CX (its web engine is Chromium 68), the radios (decision 40 now checks them hourly, and BLE carries no data without a relaying app), ultrasonic beacons, and store-and-forward voice. The voice claim is secondary only. LG denies it in its own statement, and Malwarebytes reports that the alarming demonstration used a compromised TV ([Malwarebytes](https://www.malwarebytes.com/fr/blog/privacy/2026/09/lg-tv-flaws-could-let-attackers-listen-in-even-in-standby-mode), verified).

**This week:** recommendations 1 to 4 of [§16](#16-top-10-recommendations). All are S effort, all are report-only or reduce what the gateway does on its own, and together they make the brief, the flow log and the autonomy say what is true.

---

## 1. Radios and side channels

Depth: [01](deep-dive-2026-11/01-radios-and-side-channels.md), with decision 40 on `main`.

**Settled.**

- The cable isolates IP and nothing else. The CX also has 802.11ac with Wi-Fi Direct, Bluetooth 5.0 with BLE, four HDMI ports with CEC, and speakers. None reaches the internet without a second device or a network to join.
- **Decision 40 already does what 01 thought impossible.** 01 said `connectionmanager/getStatus` is for on-TV apps only. `main` now calls it over the LAN API every hour on 04.64, and measured wired connected, Wi-Fi and Wi-Fi Direct disconnected, tethering off. Association state is a checked fact.
- What it cannot show is **radio** state. "Disconnected" says nothing about probe requests or Wi-Fi Direct listen. LG's statement confirms access-point surveying when the relevant agreements are accepted ([LG, 2026-09-12](https://www.lg.com/us/newsroom/corporate/statement-understanding-privacy-on-lg-smart-tvs), verified). The one-evening RF audit on a USB monitor-mode dongle (01 §2) is still the only test, and it must never use `wlan0`, which is the uplink.
- **BLE advertising is on and stays on.** Decision 40 measured the CX advertising continuously, with no supported switch on webOS 5. So 01's proposed red line, `bleAdvertisingOnOff != off`, would fire every hour forever, which breaks decision 14's rule that a red line is a sentence that must never be true. Record the key as a setting; do not alarm on it.
- **The consent record is the valuable read.** `eulaStatus` (with `acrAllowed`, `voiceAllowed`, `customAdAllowed`, `thirdPartySharingAllowed` and others) is in the public `get_system_settings` list of the reference dump (verified: [bscpylgtv CX dump](https://github.com/chros73/bscpylgtv/blob/master/docs/available_settings_CX.md), firmware 04.63.25). A firmware update carrying the Texas consent screen would flip a flag here before `livePlus` moved.
- **Many of 01's other keys are not publicly readable.** `ueiEnable`, `quickStartMode`, every `general` key and most `option` keys are outside that list ([14 F7](deep-dive-2026-11/14-gap-live-tv-state-through-ssap-subscriptions.md#f7-which-privacy-keys-the-public-api-can-read-on-the-cx)). 01's QuickSet test therefore runs on traffic alone: `ueiwsp.com` lookups fall to zero after Universal Control is turned off.
- **Voice store-and-forward is dropped as evidence.** Only Notebookcheck relays it, LG denies it in writing, and the demonstration used a compromised set. 01 build item 5 shrinks accordingly: machine rules can only add blocks already (decision 20), so the remaining value is a lint that keeps an owner edit from accidentally lifting a voice block. That is a nice-to-have, not a priority.

**Tests.** On 04.64 the public keys may differ, so treat a missing key as `unknown`, never `off`. The read-only census in [14's 26-hour probe](deep-dive-2026-11/14-gap-live-tv-state-through-ssap-subscriptions.md#settled-the-26-hour-probe-and-its-report) asks for each key separately. T-BLE-1 needs only a phone running nRF Connect.

## 2. Naming a connection after the TLS name goes dark

Depth: [02](deep-dive-2026-11/02-naming-beyond-sni.md).

- **ECH is not the CX's 2027 problem.** Its web engine is Chromium 68, which has no ECH code ([LG web engine table](https://webostv.developer.lge.com/develop/specifications/web-api-and-web-engine)). No streaming or LG name 02 measured publishes an ECH key. Real ECH could only come from a native stack with a key it ships, which DNS stripping cannot remove (RFC 9849 §3.2).
- **The HTTPS/SVCB strip is safe because of its form, which must be pinned.** Read at the v0.107.79 tag (verified, [msg.go](https://raw.githubusercontent.com/AdguardTeam/AdGuardHome/v0.107.79/internal/dnsforward/msg.go)): under `blocking_mode: default`, a blocked HTTPS query gets NOERROR with an empty answer and **no SOA**, and a blocked SVCB query gets NODATA **with** an SOA. A `refused` mode would turn both into the resolution failures RFC 9460 lets a client treat as fatal. Make `blocking_mode: default` a tested invariant, and run 02's T4 `dig` in the namespace CI (decision 27) to confirm it on the wire.
- **The real naming losses** are flows that never carry a hello (UDP, plain HTTP, missed hellos) and shared CDN addresses. The proposal: a derived `answer_ip(dns_id, ip, t, ttl)` table, DNS-answer names with a `name_source` and an ambiguity count, and one guard. **Autonomy and the canary read only `sni`, `quic`, `http` and `dns-unique` names**, because a wrong attribution fails safe for the payload gate but not for the streaming baseline (02 F7).
- **A capture blind spot that decision 39 half-fixes.** The full-capture BPF keeps UDP/443 only with the IETF long-header bit set, so gQUIC (Q043 and older, the only QUIC Chromium 68 knew) is counted by the firewall and never captured. `CAPTURE_MODE=headers` keeps the first packets whatever the header form. The extractor still has to branch on the version field. Test T5 says whether any gQUIC is left.
- **JA4.** 02's "add `tls.handshake.ja4` now" is moot: decision 35 computes JA4 from fields on both tshark versions. 02's rejection of JA4S, JA4X, JA4T and JA4D strings stands, on licence and value.
- **A cheaper ECH canary.** On webOS 5, a type-65 query from the TV is news by itself (test T3). It comes earlier than the `0xfe0d` extension.

## 3. The analyst under autonomy

Depth: [03](deep-dive-2026-11/03-analyst-evaluation-and-safety.md), with [15 F4](deep-dive-2026-11/15-gap-the-gateway-s-own-viewing-record-retenti.md) and [16](deep-dive-2026-11/16-gap-one-change-at-a-time-a-change-ledger-and.md).

**Platform facts, verified on the live docs on 2026-11-01.**

| Fact | Status | What it changes |
|---|---|---|
| `2026-10-21`: `temperature`, `top_p` and `top_k` return 400 "even at the parameter's default value" | verified, [migration guide](https://platform.claude.com/docs/en/api/migration-2026-10-21) | Runs cannot be pinned; safety evals report pass^k |
| Opus 5.5: 2026-09-22, $4/$20, "20% less than Opus 5", default effort `medium`, thinking cannot be disabled | verified, [announcement](https://www.anthropic.com/news/claude-opus-5-5), [pricing](https://platform.claude.com/docs/en/about-claude/pricing.md), [effort](https://platform.claude.com/docs/en/build-with-claude/effort.md) | Matches `analyst.PRICES` |
| `xhigh` is for "Long-running agentic and coding tasks (over 30 minutes) with token budgets in the millions" | verified, effort page | `ANALYST_VERIFIER_EFFORT=xhigh` is not what the docs recommend for one refutation. Sweep `high` against `xhigh` before keeping it |
| Fable 5.1 is a Covered Model, "require[s] 30-day data retention", and ZDR is unavailable "unless expressly authorized by Anthropic". Batch is 29-day and never ZDR | verified, [API and data retention](https://platform.claude.com/docs/en/manage-claude/api-and-data-retention) | The verifier and the weekly pass put every candidate shape into a 30-day store. Opus 5.5 is ZDR-eligible by agreement |
| Gray Swan: "Opus 5.5 ties Fable 5.1 for the lowest prompt injection success rate of any model tested" | verified as Anthropic's own claim, no numbers given | 03's Opus 5 figures (0.2% single attempt, 2.0% at 15) remain secondary and unverified |

**Findings that change code.**

- **It cannot be replayed.** `.pack.json` is written only on `--dry-run`. `judgments` and `auto_rules` are keyed by name and by rule, so later verdicts overwrite earlier ones. The verifier's usage is discarded.
- **Three fail-open holes** (03 F2), described in the bottom line. Fix them before anything else in this theme.
- **The injection that matters is concealment.** The realistic attack is camouflage that earns a `quiet` verdict and a week of silence under decision 22, not an instruction override. That is the class LogInject finds most resistant to defences. The gates that read bytes are the real defence. On the model side: correct `SYSTEM`'s "You never apply anything" (line 123 of `analyst.py` on `main`); strip Unicode Cf, Co and Cn, the tag block, bidi controls and C1 controls in the free-text channels (03 ran `scrub()` and they pass through); never give a `quiet` verdict to a name that is instruction-shaped; make `evidence` checkable `{field, key}` citations.
- **The second key shares the first key's blind spots.** Same developer and same input, and the verifier reads the proposer's `reason`. Send the verifier only the structured fields, and measure the correlation with 03 F4's paired design instead of assuming independence.
- **The judge confuses the network with the rule** (16). Every apply, revert and `undo` stops and starts AdGuard Home. Bytes are credited to the hour a connection *ended*. An HDMI hour counts as `Active` with zero streaming bytes. A revert is a verdict that is never asked again. 16's answer is a `changes` ledger (most of it from counters `tvgw verify --record` can sample every 10 minutes), an hour classifier (`clean`, `confounded`, `no_demand`), and a judge that suspends rather than reverts in confounded hours and returns NODATA rather than passing. Two facts are verified for that design. The conntrack table on the 8 GB board defaults to 262144 entries (v6.18 source, [§6](#6-platform-and-kernel)), so a full table is unlikely. And a full table refuses *new* connections while sparing assured ones, so it shows as fewer stream starts, not as a throughput drop.
- **Cost.** October assumed about 40K tokens and $0.22 a day. The shipped config implies about 10K and $0.07. `sudo jq '.usage' /var/lib/tvgw/reports/proposals/2026-1*.json` settles it (test). The verifier on Fable at `xhigh` may cost more than the proposer, and it is unrecorded.

**The minimum eval** (03 "Settled"): a free deterministic tier 0 on every commit; then 19 Batch calls for about $0.91, made of 8 replayed packs labelled leave-one-rule-out and leave-one-must-allow-out, 8 red-team twins and 3 verifier cases, graded by code with Clopper-Pearson bounds. It needs the stored packs first.

## 4. Blocklists are an unwatched update channel

Depth: [04](deep-dive-2026-11/04-blocklists-and-verification.md).

- **AdGuard applies whatever answers 200.** At the v0.107.79 tag (verified): the parser has no minimum rule count and returns no error on an empty body ([parser.go](https://raw.githubusercontent.com/AdguardTeam/AdGuardHome/v0.107.79/internal/filtering/rulelist/parser.go)), and `updateIntl` treats any change of checksum as an update ([filter.go](https://raw.githubusercontent.com/AdguardTeam/AdGuardHome/v0.107.79/internal/filtering/filter.go)). So an empty 200 replaces the list: fail-open for that list. A non-200 keeps the old file. The harness test (an empty 200 to a namespaced AdGuard, then `rules_count` 0) is still owed before 04's Stage B is justified on this ground alone.
- **tvgw does not own `filters_update_interval`** (no match on `main`). A `0` in the UI freezes every list silently. The refresh time drifts with file mtimes, and a list change reaches the TV 1 to 25 hours after HaGeZi publishes, at an uncontrolled hour.
- **The upstream risk is recent.** HaGeZi shipped a zone-wide `nextlgsdp.com` block on 2026-09-11 that broke clocks and the Content Store on webOS 6+, fixed in about a day ([#11438](https://github.com/hagezi/dns-blocklists/issues/11438)). Perflyst's Smart-TV list has blocked must-allow names since 2026-09-09 ([#172](https://github.com/Perflyst/PiHoleBlocklist/issues/172)). 1Hosts has been frozen since 2026-09-03.
- **The LG list adds attribution, not coverage.** 230 of `filter_72`'s 231 entries are already in HaGeZi Pro; the 231st is its sentinel. Every HaGeZi list carries a sentinel (`h4g3z1-<list>.web.app`), which makes "is the list loaded" a one-line `dig`. jsDelivr serves past HaGeZi tags immutably, which makes pinning and diffing possible.
- **Build order.** First a "List changes" brief section from the query log alone, using the first list block of a name the TV used to resolve, with a red line when that name carried content. Then sentinels and a liveness line in `verify`. Then own the interval. Then a Stage A snapshot and an effective diff on the names that matter. Stage B (promote locally, with holds) comes last, with the owner's approval, and per [16 F6](deep-dive-2026-11/16-gap-one-change-at-a-time-a-change-ledger-and.md) only promotions that touch the TV's names may hold the trial lock.
- **Add no list.** OISD, the AdGuard DNS filter, 1Hosts and Perflyst are each redundant with Pro or block a must-allow name today.

## 5. LG's ACR on the wire, and one detector

Depth: [05](deep-dive-2026-11/05-tv-privacy-research-2026.md) and [13](deep-dive-2026-11/13-gap-reconcile-the-two-incompatible-acr-detec.md). 13 supersedes both 05's and 07's detector proposals.

- **The opt-out works on webOS.** *Watching the Watchers* found "no traffic consistent with ACR activity" after opt-out on webOS, against more than 60% of Tizen runs and 100% of Vizio runs. The owner's Live Plus setting is doing its job.
- **The shape, from the released trace** (05 §1.1, 13 §1.1):
  - ACR rides TCP **4431**, with 4445 and 4447 for the rest, never 443;
  - connections last 1 to 3 minutes and open on a timer of about 60 s;
  - a fingerprint burst of about 22 KB goes up every 14 to 15 s inside a connection;
  - 10 to 39 MB go up on ACR days, at 7 to 17 times the bytes down.
- **IMC 2024's numbers agree with the trace.** Its tables turn out to be frame bytes, both directions, per one-hour experiment (13 §1.3, read from the authors' scripts). 07's "17 to 19 KB per contact" and 05's "about 24 KB per burst" are the same fingerprint. The two sections disagreed about whether a contact is a connection, and it is not.
- **The merged detector** (13 §1.4):
  - Red line 7 is driven by `acr_uploader`, daily (payload up ≥ 1 MB, ≥ 4× down, ≥ 24 connections) and hourly (≥ 500 KB, ≥ 4×, ≥ 5 connections), keyed by **(registrable domain or /24, server port)**. Without the port key, Alphonso's port-443 control plane dilutes the ratio.
  - A port-wall counter also drives it.
  - Cadence becomes an attribute that never buys a request: a 10-200 s timer also marks captive-portal probes, Hue polling and QoE beacons.
  - 07's period-only and over-1-hour ACR tests are dropped. Both fire on 0 of 17 days, and the long-connection formula goes negative for FIN closes.
- **Two corrections to 05.** Alphonso's answer TTLs are a median of 1,754 s, not "6-12 s" (13 §1.5). And its "every non-80/443 port belonged to ACR, ads or IoT" is evidence from a **newer US lab set**, not from the CX. It supports decision 17's end state. It is not the CX's own two weeks, and the port wall waits on the CX's history (test below).
- **The port wall detects more than it defends.** AWS IoT and Azure IoT Hub fall back to 443, and Alphonso's provisioning host already uses 443 for two thirds of its connections. On the CX the DNS blocks contain all of these already. The wall's value is naming an attempt DNS missed. Put it before the odd-port rule, so decision 17's "Unexpected ports" counts only unknown ports.
- **Titles in plain DNS.** Amagi's FAST delivery writes channel and programme slugs into hostnames (`*.amagi.tv`), and LG Channels carries Amagi channels. Do not block them, since that breaks FAST. 15 F3 moves the fix from the pack's scrub to ingest: a keyed HMAC of the label, so no local store holds the slug either.
- **What LG said, re-checked.** LG's own statement says "LG smart TVs may use device-discovery functions to recognize and communicate with compatible external devices" and denies offline voice storage (verified). The phrase "a standard feature" comes from a 2026-09-09 statement relayed by IT-Connect and The Next Web, which IT-Connect itself presents as a paraphrase. Cite LG's own words.
- **Texas.** LG's settlement was announced on 2026-05-11. CIPAWorld posted it that day and Fox 7 reported "announced a settlement" on 2026-05-12 (verified). The October date of 05-12 is the news date. The AG's release reportedly links an agreed final judgment (search summary; the AG's page returned HTTP 402 to this pass), so **entry by the court is unverified**. 05 also corrects the profile's webOS 26 note: no source limits the consent pop-up to 2027+ models.
- **Firmware.** LG's stated security window for 2020 sets ended in 2025, yet 04.64 was published on 2026-05-13 with "minor bug fixes" (LG Romania support list, 05 §1.6). That also answers 07's open question. Keep `snu.lge.com` allowed, reword its reason, and treat each update as a re-baseline: a 72-hour red line and an immediate settings re-read.
- **Rule-set edits that need no decision:**
  - replace the exact Nevo IoT hub rule with a regex (the lab set used a variant no list carries);
  - add custom rules for `rdl.`, `wiseconfig.` and `ads.lgtvcommon.com`, which today rest on HaGeZi alone;
  - recategorize `lgchhomeapp.lgtvcommon.com` as ads;
  - add a FAST category.

**Tests.** The CX's port history (13 §1.6): `sudo tvgw sql "select dport, count(*), sum(bytes_up) from flows where dport in (4001,4431,4445,4447,8180,8883) group by dport"`. Empty means the wall costs nothing. The upload test over 30 days is 13 §3 item 1. Expect zero in-scope hits with Live Plus off.

## 6. Platform and kernel

Depth: [06](deep-dive-2026-11/06-platform-and-kernel-depth.md), with [16 F7](deep-dive-2026-11/16-gap-one-change-at-a-time-a-change-ledger-and.md#f7-cheap-signals-that-separate-the-network-got-worse-from-the-block-broke-it) and [08 F8](deep-dive-2026-11/08-next-build-hardware.md).

- **TV-only conntrack events** (06 F1b). In 6.18, `nf_conntrack_events=0` gives no connection an event extension, and `ct event set destroy` in a prerouting chain at priority −150 gives one to each new TV connection. The torrent client's churn never reaches the socket. This also closes two losses nobody had noticed: connections opened while the logger restarts, and connections opened at boot. The sysctl is namespace-wide, so first list the other listeners: `awk '$2==12 && $4!="00000000"' /proc/net/netlink`. Record the event socket's drop count (`ss -m` `d`) in `verify --record`, so lost events stop depending on a journal line.
- **`expires` in the gate's feeder** (06 F2): `f"{ip} timeout {ttl}s expires {ttl}s"`. The expected effect is a lower gate count on viewing days with `dns_gate.unexplained` unchanged. An enforce mode for DNS-gated egress (decision 18) needs this, or it will reject addresses the TV resolved minutes earlier.
- **The conntrack table is big enough on this board (verified).** In v6.18's `nf_conntrack_init_start`, a 64-bit kernel with more than 4 GiB of RAM gets 262144 buckets, and more than 1 GiB gets 65536. With the size auto-derived, `max_factor = 1`, so `nf_conntrack_max` equals the bucket count ([source](https://raw.githubusercontent.com/torvalds/linux/v6.18/net/netfilter/nf_conntrack_core.c)). 06's `nf_conntrack_max = 262144` line is a no-op on the 8 GB Pi. It matters on a 2 or 4 GB board, so keep it in the package. Check it with `sysctl net.netfilter.nf_conntrack_max`. Add count/max and the `conntrack -S` drops to `verify` anyway: they are cheap and tell "table full" from "the block broke it".
- **The journal: both sections are right, about different machines.** 06 read the vendor default from `raspberrypi-sys-mods` (`40-rpi-volatile-storage.conf`, `Storage=volatile`, since 2025-06). 08 and 16 report, from the owner's notes, that this Pi was made persistent with `ramoops` on 2026-10-31. A fresh image or a re-flash returns to volatile. **Ship tvgw's own `/etc/systemd/journald.conf.d/60-tvgw.conf`** in the package, with `MaxRetentionSec=14day` per 15 (not 06's 30). Have `verify` read the effective value. Test: `systemd-analyze cat-config systemd/journald.conf | grep -n '^Storage'` and `journalctl --list-boots | head`.
- **Already done by the vendor.** The watchdog is `RuntimeWatchdogSec=1m`. The 16 s hardware limit does not cap it, because the watchdog core pings on systemd's behalf. Keep it, and add `BOOT_WATCHDOG_TIMEOUT=120` to the EEPROM config for hangs before Linux starts (08 F8).
- **No LSM.** The Pi 5 kernel has `CONFIG_LSM=""` and no Landlock. systemd sandboxing is the only sandbox. October's Landlock prototype cannot run.
- **AdGuard Home in 2026.** Five schema bumps in eight months, and a v1.0 beta whose minor releases may break compatibility. Raise the floor to **0.107.79**: decision 25 keeps the three floors equal, and they are all 0.107.73 on `main`. Refuse `schema_version` above 34. Own `querylog.ignored_enabled` and `statistics.ignored_enabled` (`false`), `dns.cache_enabled` and `filtering.rewrites_enabled`. Add `--no-check-update` to the service. Add a `tvgw adguard upgrade NEWBIN` that runs the new binary's `--check-config` on the live YAML before swapping.
- **Unit hardening, with two verifications owed.**
  - `systemd-analyze security --offline --threshold`: the man page gives a default of 100 and an exposure display of 0.0 to 10.0, without stating how they relate ([systemd-analyze(1)](https://www.freedesktop.org/software/systemd/man/latest/systemd-analyze.html), verified). Calibrate the threshold on the first CI run; do not assume ×10.
  - `MemoryDenyWriteExecute` on the Python units: unverified. It depends on whether trixie's libffi uses static trampolines for ctypes callbacks. Test before adopting: `systemd-run --wait --pipe -p MemoryDenyWriteExecute=yes /opt/tvgw-venv/bin/python -I -c 'import ctypes; ctypes.CFUNCTYPE(None)(lambda: None)()'`.
- **Do not adopt flowtables.** A flowtable without `counter` stops conntrack's byte counts, and the payload gate would then pass content as telemetry.

## 7. Measurement and presentation

Depth: [07](deep-dive-2026-11/07-measurement-and-presentation.md), superseded on ACR by [13](deep-dive-2026-11/13-gap-reconcile-the-two-incompatible-acr-detec.md).

- **RITA cannot score this TV.** RITA v5 scores four equal parts. Duration and the 24-hour histogram need 6 to 11 active hours a day, so they mark down any TV that is on 3 hours. The weights were read from source; v5.1.2 was released 2026-05-07 (verified, GitHub API). Keep the timing and size halves, and add *awake coverage*.
- **Periodicity on event times.** Use a Rayleigh/Z² statistic whose null shuffles events inside the awake hours, not Lomb-Scargle. A daily window cannot see a timer slower than `awake_seconds / 12`, so pool weekly for slow timers.
- **Upload anomalies.** Score per name and per awake hour against the name's own 28-day record, after a producer/consumer-ratio filter that drops downloads. A firmware download and a game night then never qualify.
- **Say how sure the brief is.** Every zero carries its exposure and a rule-of-three bound. Use one fixed likelihood vocabulary (ICD 203), separate from confidence. Control the day's per-name tests with Benjamini-Hochberg.
- **A scorecard, not a grade.** No 2026 label measures behaviour: the Cyber Trust Mark still had no labelled product on 2026-10-28, and Finland's label closed on 2025-07-31. 07 specifies 18 observed fields, each with a fixed verdict word, an exposure, a confidence and the label clause it is the observed counterpart of. No composite score.
- **The share pack and the HTML brief are specified.** The share pack uses a closed public vocabulary, ISO weeks and bucketed counts. The HTML brief is static, script-free and LAN-only behind authentication. 15 adds that the detail (day strip, app names) should be off by default, and that the pages need a retention.
- **Unverified:** the RTINGS ACR result (the page did not render for this pass either).

## 8. The next build and the appliance image

Depth: [08](deep-dive-2026-11/08-next-build-hardware.md).

- **Do not buy 2.5 GbE or PoE.** This verdict rests on the load, not on the CX's port. 60 to 70 GB a day is about 6 Mb/s on average. The claim that the CX's port is 10/100 rests only on owner posts and a Best Buy answer about the 2023 C3, so it is **unverified**. Run T1 (`ethtool eth0 | grep -E 'Speed|Duplex'`). Gigabit at the TV would change nothing in the bill of materials.
- **EEE link flapping on 6.18** ([raspberrypi/linux#7511](https://github.com/raspberrypi/linux/issues/7511), open). Every flap re-runs `tvgw-apply` through the dispatcher. Run T2 (`ethtool --show-eee eth0` and the link-down count against TV-on hours) before anything else in this theme.
- **Build A** keeps the Pi 5 8 GB, the Active Cooler and the DAC. It adds an NVMe drive in a USB 3 enclosure and an RTL8153 adapter for a wired uplink if a wire exists. It moves the failing disk to a self-powered enclosure, and runs stock clocks. That respects the owner's "no HAT" decision.
- **Build A2** (the official M.2 HAT+ under the DAC) rests on the HAT+ being a stackable board at EEPROM address 0x51. That is supported only by a 2024 forum answer from two non-staff posters (verified as such), so it is **unverified until T4** (`cat /proc/device-tree/hat/product`, `i2cdetect`) on the bench.
- **Build B** is a CM5 on a carrier whose second port hangs off USB, keeping the PCIe lane for NVMe (Waveshare CM5-DUAL-ETH-BASE). October's CM5-DUAL-ETH-MINI has no M.2 slot. Build B as *the* gateway, with this Pi kept as the media box, removes every coupling behind this month's non-tvgw incidents.
- **The image pipeline.** rpi-image-gen v2.9.0 (2026-10-23) on `ubuntu-24.04-arm` runners, a non-A/B ext4 image first, rpi-preseed for the OS account, and a tvgw first-boot unit. Hosted arm64 runners in **private** repositories are verified: GitHub's changelog of 2026-01-29 gives 2 vCPUs, billed against the plan's minutes ([changelog](https://github.blog/changelog/2026-01-29-arm64-standard-runners-are-now-available-in-private-repositories)). Two corrections to 08 against `main`: decision 30 makes the answers file use the settings format, so 08's TOML sketch must follow it; and decision 26's rules on the self-hosted runner already forbid building there.
- **The RTC battery is optional.** The Pi 5's RTC runs without a battery while powered, and the owner declined one. October had ranked it ADOPT NOW.

## 9. The Pi is the TV's only neighbour

Depth: [11](deep-dive-2026-11/11-gap-the-pi-is-the-tv-s-only-neighbour-the-tv.md).

- **One chain is the wall, and it has four holes in time.** `inet tvgw`'s `input` chain is gone at `systemctl stop`, at boot until `tvgw-apply` runs, after a rejected apply, and during an upgrade that restarts the unit. Forwarding is off in every window, so the TV is dark toward the internet (decision 5). But the Pi itself is open to it.
- **Binding a daemon to the LAN address is not isolation here.** Linux uses the weak host model, so a socket bound to the Pi's LAN address is reachable from the TV port. Only `ip daddr != GW_IP drop` prevents that, and it lives in the same chain.
- **Co-tenants reachable in those windows.** xrdp: CVE-2025-68670, a pre-auth stack overflow, and DSA-6469-1 with 17 CVEs on 2026-08-27, among them a CVSS 9.8 pre-auth heap overflow in `[vnc-any]`. A shairport-sync AirPlay 2 source build is outside Debian security support, and upstream 5.5 fixed pre-auth RTSP bugs. Samba's realistic risk is configuration (guest shares). qBittorrent's is the WebUI auth whitelist.
- **Two gaps even with the firewall up.** The input chain never checks the source, and systemd's `rp_filter = 2` is loose, so the TV can spoof a LAN source and make AdGuard answer a LAN host. And the forward chain accepts any source in the /24, so a rooted TV with a second address escapes the flow log (`--orig-src TV_IP`) and the HTTPS strip (`client=TV_IP`).
- **Three fixes that hold whatever nftables holds:**
  1. a guard table, `inet tvgw_guard`, at `filter + 10`, loaded by a unit that is never stopped. A drop in any base chain is final, so it can only narrow;
  2. `IPAddressDeny=TV_NET` drop-ins on every co-tenant (cgroup BPF);
  3. dnsmasq without `CAP_NET_ADMIN`. With `dhcp-broadcast` and `no-ping`, the dnsmasq source shows it needs neither capability, and that capability is enough to rewrite the firewall.
- **nginx is not an open proxy** (read in nginx's source). Any SNI or Host outside the GFTS names fails closed. Widening either regex later would turn the passthrough into a filter bypass, so it needs a CI test, not a comment.
- 05's "TV API from root only" output rule belongs in the guard, or it disappears in exactly the window it is for.

## 10. The VPN boundary

Depth: [12](deep-dive-2026-11/12-gap-the-vpn-boundary-which-of-the-pi-s-own-f.md). Read from PIA 3.8.0's GPL source.

- **The TV's data path never depends on the tunnel.** PIA's kill switch is iptables-nft in filter `OUTPUT` only, with no `FORWARD` rules. Its forwarded-packet rule sits at priority 70, and tvgw's rule 60 sends the TV to table 100 first. When the tunnel drops, **only DNS fails**.
- **But not always the safe way.** Under `killswitch=auto`, AdGuard's DoH is rejected locally mid-run (no leak). It **leaves by the uplink** after a daemon start before the first connection, after `piactl disconnect`, and while the daemon is inactive. Tests T2 and T3 confirm it.
- **Decision 1's text is wrong about why the ISP does not see the TV's DNS.** The reason is DoH by IP address: Go sends no SNI for an IP literal. The tunnel hides the home address from the DoH provider. The ISP reads the TV's own SNIs on the direct path anyway.
- **The optimistic cache is better than feared and worse than assumed.** A failed refresh keeps the entry, for up to 12 h past its expiry. Names never asked fail at once. And **every AdGuard restart empties the cache**, which tvgw's own applies, reverts, `undo` and deploys cause. An apply during an outage restarts AdGuard twice, because readiness fails and the apply rolls back. The cheapest fix is a guard that defers restarts while the upstream fails.
- **The upstream pair is one failure domain.** `1.1.1.1` and `1.0.0.1` went down together for 62 minutes on 2025-07-14 ([Cloudflare](https://blog.cloudflare.com/cloudflare-1-1-1-1-incident-on-july-14-2025)). A second operator as `fallback_dns` covers a provider outage. It cannot cover a tunnel outage: only a resolver in a forwarded position, in a network namespace, survives PIA's kill switch.
- **`tun0` is hardcoded** in three places in `tvgw-apply`. PIA 3.8.0's WireGuard interface is `wgpia0`.
- **October's dnscrypt-proxy WATCH becomes REJECT on the main path**, because relays duplicate what the tunnel gives. It can be prototyped as the namespace resolver.
- **Identity mixing.** The proxied GFTS fetches and the analyst's API calls put LG and Anthropic traffic on the same exit address as qBittorrent. Principle: identity-bearing flows leave by the home address, anonymity-seeking flows by the tunnel, and nothing mixes them.

## 11. Live TV state

Depth: [14](deep-dive-2026-11/14-gap-live-tv-state-through-ssap-subscriptions.md).

- **The hourly reading misses whole sessions, not only edges.** A 20-minute session is missed two times in three. If both readings around it say off, `standby_activity` books its traffic as "while off", which is the very signal 07 calls the strongest.
- **`Screen Off` is counted as off today.** In that state the TV is on with a dark panel. And the judge, the canary and the pack count only `Active`, while `queries.AWAKE` also counts `Screen Saver`. One constant fixes both, and `main` still has `AWAKE = ("Active", "Screen Saver")`.
- **One session can watch power and apps live** (reported in trackers, not yet seen on this TV). On a CX at 04.64, `getForegroundAppInfo` accepts `subscribe` over `wss://:3001`, and `:3000` is refused (aiowebostv #707, 2026-08). `getPowerState` subscriptions push the whole off sequence on later webOS. The kernel's carrier events on `TV_IF` give a second, passive power signal.
- **The pairing key is not read-only.** bscpylgtv requested 28 permissions plus a signed block. Re-pair with an unsigned read-only manifest and shred the full key, once the test matrix shows firmware is still readable with the minimal key.
- **Long-lived session safety.** A session held by a dedicated user, sandboxed to `TV_IP`, with a 1 MiB frame cap, is not a new risk. Do not retry registration after a pairing error, because each retry puts a prompt on the screen.
- **An event-triggered canary fixes 03's hole 3** without moving the analyst's schedule. A block applied with the TV off is "armed", and the 10-minute watch runs when a non-launcher app has been in front for 60 s.

## 12. The gateway's own viewing record

Depth: [15](deep-dive-2026-11/15-gap-the-gateway-s-own-viewing-record-retenti.md).

- **22 stores on the Pi and 3 off it hold viewing-derived data.** The largest are not the obvious ones:
  - `DB_DAYS=365` is the default, still on `main`, not October's 90;
  - seven full copies of the store sit in `backup/`, about 7 GB at steady state (estimate);
  - `flows.log` keeps 12 weeks;
  - AdGuard's query log keeps up to **180 days**, since it rotates to one `.1` file only when its oldest entry passes the 90-day interval (read from source);
  - `tvstate`, `hosts`, the reports and `tvcheck-history.log` are never pruned.
- **No detector proposed this pass needs raw facts older than 35 days.** The one 60-day need, 03's placebo calibration, runs on a nameless hourly rollup.
- **I disagree with October's "rollups kept forever".** A per-name daily rollup kept forever is a viewing diary. Keep names for 90 days, then collapse to category, or to the registrable domain outside Streaming and apps.
- **Minimize at ingest:**
  - replace each query value in `http.uri` with its length;
  - strip `MAC=` and the host name from the raw kernel log lines;
  - HMAC the title-bearing names with an epoch key kept out of backups.
- **Anthropic** (verified, §3): Opus 5.5 is 30 days by default and ZDR by agreement; Fable 5.1 requires 30 days and is not ZDR-eligible; Batch is 29 days. Moving the weekly pass to Opus 5.5 shortens the footprint. Every monthly eval replay of a real pack sends that day to Anthropic again, so delete each batch after download.
- **Legal footing** (not legal advice). Routing metadata falls under pen-register law, where user consent is an express exception. Contents (whole port-80 bodies in pcaps, query strings) fall under the Wiretap Act and the all-party-consent states. Minimization and a one-page household notice are the levers that do not depend on how a court reads "provider".
- **`tvgw forget`** is specified, with a CI test that enumerates every table and file tree, so a new store cannot silently escape it.

## 13. Attribution: one change at a time

Depth: [16](deep-dive-2026-11/16-gap-one-change-at-a-time-a-change-ledger-and.md).

- **Co-occurrence is effectively 100%.** About 12 DHCP-renewal applies a day, a DoH apply, at least one list refresh and the analyst's own AdGuard restart fall inside every 24-hour trial. Only class-A changes, the ones that can move the metric, should count as confounders.
- **Every class-A cause is measurable.** Nine of eleven missing sources are cumulative counters a 10-minute sample loses nothing from: `carrier_changes`, `boot_id`, AdGuard's `InvocationID` and `NRestarts`, `conntrack -S`, `iw station dump`, interface bytes, PIA's state and filter mtimes. The other two are one log line each, in the dispatcher and in `install.sh`.
- **The judge should strict-pass and soft-revert.** It reverts in clean hours, suspends and requeues in confounded hours, and returns NODATA and extends probation rather than passing (Kayenta's `Nodata`; Google's SRE workbook: "only one canary deployment at a time").
- **One lock with 04's Stage B, but only promotions that touch the TV's names hold it exclusively.** If every daily promotion counted as an exclusive trial, utilization ρ = 1 and machine rules would starve (16 F6's M/D/1 table).
- **Optional, and an owner decision: `POST /control/filtering/set_rules`.** It removes the restart from every machine-rule change, at some cost to decision 6's file-only principle.

---

## 14. Claims re-verified for this report

| # | Claim (section) | Result | Source |
|---|---|---|---|
| 1 | G5 "saved voice input locally and uploaded … once network access was restored" (01 §5) | **Dropped as evidence.** Only Notebookcheck says it, without naming the unit or saying whether it was rooted. LG's statement: "Voice data is not stored for later upload when the TV is offline". Malwarebytes: the audio demonstration "was carried out on a compromised TV". 01 build item 5 is downgraded | [Notebookcheck](https://www.notebookcheck.net/LG-smart-TVs-caught-logging-audio-with-screen-off-and-snooping-on-local-devices.1391214.0.html), [LG](https://www.lg.com/us/newsroom/corporate/statement-understanding-privacy-on-lg-smart-tvs), [Malwarebytes](https://www.malwarebytes.com/fr/blog/privacy/2026/09/lg-tv-flaws-could-let-attackers-listen-in-even-in-standby-mode) |
| 2 | `network.bleAdvertisingOnOff` exists and read off; 01's key table (01 §3, §7) | Present in the dump (`"off"`) and in its public read list, **on 04.63.25**. Decision 40 measured the CX advertising on 04.64. A red line on the key is wrong; record it. The public list excludes `ueiEnable`, `quickStartMode`, all `general` keys and most `option` keys (14 F7). **04.64 unverified**: run 14's census | [bscpylgtv CX dump](https://github.com/chros73/bscpylgtv/blob/master/docs/available_settings_CX.md); decision 40 |
| 3 | MR20 FCC test report, "2402-2480 MHz, Bluetooth V4.2" (01 §1) | **Unverified.** fcc.gov and fccid.io returned 403, and no grant was found by search. Not load-bearing: LG's spec sheet and B&H already say the remote is 2.4 GHz Bluetooth | searches recorded in this pass |
| 4 | Blocked HTTPS returns NOERROR, empty, no SOA (02 F2) | **Verified at the v0.107.79 tag.** SVCB takes NODATA with an SOA. On-the-wire T4 still to run in the namespace CI | [msg.go@v0.107.79](https://raw.githubusercontent.com/AdguardTeam/AdGuardHome/v0.107.79/internal/dnsforward/msg.go) |
| 5 | Sampling parameters return 400 from `2026-10-21` (03 F5) | **Verified**, "even at the parameter's default value" | [migration guide](https://platform.claude.com/docs/en/api/migration-2026-10-21) |
| 6 | Fable 5.1 not under ZDR; 30-day retention (03 F6, OQ7) | **Verified**: "require 30-day data retention and are not available under ZDR unless expressly authorized by Anthropic". Batch: 29 days, not ZDR | [API and data retention](https://platform.claude.com/docs/en/manage-claude/api-and-data-retention) |
| 7 | Opus 5.5 on 2026-09-22, 20% below Opus 5; Gray Swan rates (03 F3, F6) | **Verified** from Anthropic's announcement and the pricing page. Gray Swan: only the "ties Fable 5.1 for the lowest" claim; the Opus 5 numbers stay secondary. One secondary source says "40%", which the price table contradicts | [announcement](https://www.anthropic.com/news/claude-opus-5-5), [pricing](https://platform.claude.com/docs/en/about-claude/pricing.md) |
| 8 | `xhigh` "for long-running agentic and coding tasks (over 30 minutes)" (03 F6) | **Verified**, with "with token budgets in the millions". Opus 5.5 defaults to `medium` | [effort](https://platform.claude.com/docs/en/build-with-claude/effort.md) |
| 9 | An empty 200 replaces a list: fail-open (04 F1) | **Verified in source at the v0.107.79 tag**: no minimum count; a checksum change is an update. Harness test still owed | [parser.go](https://raw.githubusercontent.com/AdguardTeam/AdGuardHome/v0.107.79/internal/filtering/rulelist/parser.go), [filter.go](https://raw.githubusercontent.com/AdguardTeam/AdGuardHome/v0.107.79/internal/filtering/filter.go) |
| 10 | "LG confirms scanning as 'a standard feature'" (05 §1.4) | **Paraphrase.** LG's own statement says "device-discovery functions to recognize and communicate with compatible external devices". "Standard feature" appears in IT-Connect's relay of a 2026-09-09 press statement, which IT-Connect itself calls a paraphrase | [LG](https://www.lg.com/us/newsroom/corporate/statement-understanding-privacy-on-lg-smart-tvs), [IT-Connect](https://www.it-connect.tech/lg-tvs-allegedly-scan-your-local-network-and-listen-in-standby/) |
| 11 | LG settled 2026-05-11 vs October's 05-12 (05 §1.5) | **Announced 2026-05-11** (CIPAWorld post); Fox 7 reported it 05-12. Court entry **unverified**: the AG's page returned 402 | [CIPAWorld](https://cipaworld.com/2026/05/11/texas-obtains-smart-tv-privacy-settlement-with-lg-heres-what-changes/), [Fox 7](https://www.fox7austin.com/news/lg-smart-tv-acr-data-collection-texas-settlement) |
| 12 | "Every internet port other than 80 and 443 was ACR, ads or IoT" (05 §1.2) | True of the **lab set only**. It is not CX evidence. Run the CX port history (§5) before the wall | [Zenodo 22698120](https://zenodo.org/records/22698120) |
| 13 | Trixie's journal is in RAM (06 F6) vs persistent (08 F6, F8) | **Both, about different machines**: vendor default volatile; this Pi persistent since 2026-10-31 per the owner's notes. Ship tvgw's drop-in. Test: `journalctl --list-boots` | [raspberrypi-sys-mods](https://github.com/RPi-Distro/raspberrypi-sys-mods/blob/pios/trixie/usr/lib/systemd/journald.conf.d/40-rpi-volatile-storage.conf) |
| 14 | "65536 for boards with up to 4 GiB" (06 F8) | **Verified and sharpened**: more than 1 GiB gives 65536, more than 4 GiB on 64-bit gives 262144, `max_factor = 1`. The 8 GB board already has 262144. Confirm with `sysctl net.netfilter.nf_conntrack_max` | [nf_conntrack_core.c@v6.18](https://raw.githubusercontent.com/torvalds/linux/v6.18/net/netfilter/nf_conntrack_core.c) |
| 15 | `--threshold` on a ×10 scale; libffi and MDWE (06 F7) | Threshold: default 100 and display 0.0-10.0 are documented, their relation is not, so calibrate. libffi trampolines on trixie: **unverified**; the test is in §6 | [systemd-analyze(1)](https://www.freedesktop.org/software/systemd/man/latest/systemd-analyze.html), [libffi static trampolines](https://github.com/libffi/libffi/pull/603) |
| 16 | `conntrack -b` sets the wrong socket (06 F1a) | Confirmed by the critic against Debian's 1.4.8 source. Still run `ss -f netlink -a -p -m` on the gateway | [conntrack.c 1.4.8](https://sources.debian.org/src/conntrack-tools/1:1.4.8-2/src/conntrack.c/) |
| 17 | IMC 2024 implies 17-19 KB per 15 s; mark `acr_like` on period alone (07 F1) | **Settled by 13** from the authors' scripts and the trace: same quantity as 05's burst; period-only marking fires on 0 of 17 days. Dropped | [13 §1.3](deep-dive-2026-11/13-gap-reconcile-the-two-incompatible-acr-detec.md#13-imc-2024s-units-and-whether-07s-17-19-kb-is-05s-24-kb-settled-from-the-authors-code-cross-checked-on-the-trace) |
| 18 | "Will the CX get another firmware?" (07 OQ) | **Answered by 05 §1.6**: 04.64 published 2026-05-13 after the security window closed | [LG RO support](https://www.lg.com/ro/suport/produs/lg-OLED55CX3LA) |
| 19 | RTINGS ACR result; RITA v5.1.2 year (07 F1, F6) | RTINGS **unverified** (did not render). RITA v5.1.2 **verified** 2026-05-07 | [RITA releases API](https://api.github.com/repos/activecm/rita/releases?per_page=5) |
| 20 | The CX's port is 100 Mb/s (08 F1) | **Unverified**: owner posts and a C3 answer only. The BOM verdict stands on load alone. Run T1 | [Best Buy C3 answer](https://www.bestbuy.com/site/questions/lg-65-class-c3-series-oled-evo-4k-uhd-smart-webos-tv-2023/6535929/question/b5321f4e-1f50-3cfa-a9fc-94302c0fadbc) |
| 21 | arm64 standard runners in private repositories (08 F10) | **Verified**: GitHub changelog 2026-01-29; 2 vCPUs; billed against the plan's minutes | [changelog](https://github.blog/changelog/2026-01-29-arm64-standard-runners-are-now-available-in-private-repositories) |
| 22 | M.2 HAT+ is stackable at 0x51 (08 F4) | **Unverified**: one 2024 forum post by a non-staff user; no official document. Run T4 before Build A2 | [forum thread](https://forums.raspberrypi.com/viewtopic.php?t=372508) |

## 15. What the October report got wrong or incomplete

**Wrong.**

1. **The ACR cadence canary** (October §5.1, built in Analysis v2). It read IMC's "every 15 s" as the period between connections, so its 10-20 s and 4 KB thresholds cannot fire on LG's client (§5).
2. **"Hardware watchdog `RuntimeWatchdogSec=10s`, ADOPT NOW"** (§7). Trixie already ships 1 minute, and 10 s only adds false resets (§6, 08 F8).
3. **"Landlock self-restriction, PROTOTYPE"** (§10). The Pi kernel has no Landlock and no active LSM (06 F6).
4. **AdGuard version floor 0.107.73** (§2.2). It should be 0.107.79. The v1.0 beta was published 2026-09-30, not 10-02 (06 F5).
5. **"The Pi's tshark cannot produce JA4"** (§1.1). It could from trixie. Decision 35 then made the question moot (02).
6. **"No upstream list publishes what must not be blocked"** (§2.1). Too strong: AdGuard's DNS filter publishes `exclusions.txt` with an issue URL per entry. And Perflyst, offered as a source, blocks must-allow names (04).
7. **The HaGeZi LG version it quoted** is a header AdGuard never sees. tvgw fetches the registry copy (04 F2).
8. **"Only the Pi can reach the TV's ports, so the isolation already contains this"** (§3.1, §10). It holds for IP over the cable only, and only while `inet tvgw` is loaded (01, 11).
9. **The CM5-DUAL-ETH-MINI as the appliance board** (§7). It has no M.2 slot. The RTC battery is optional, not ADOPT NOW. 2.5 GbE is REJECT, not PROTOTYPE (08).
10. **"90 days of facts, rollups kept forever"** (§4.2). 35 days of raw facts covers every proposed detector, and a per-name rollup kept forever is a diary (15).
11. **"Deleted within 30 days by default; ZDR by agreement"** (§5.4). True for Opus, Sonnet and Haiku 5.5. Not for Fable 5.1 or Batch (§3).
12. **dnscrypt-proxy WATCH** (§2.2). It is REJECT on the main path (12 F7).
13. **The VPN generalization** (§8.4 item 6) assumed the routing mark was what protects the TV. Rule ordering is, and the tunnel is not always `tun0` (12 F1).
14. **"rpi-image-gen emits an SBOM and CVE list"** (§9). It emits an SBOM; no CVE scanner was found (08 F10).

**Incomplete.**

1. **The model of the TV was network-only.** Add a `[radios]` block and a consent key beside the feature key (01).
2. **The HTTPS strip** is safe only in AdGuard's `default` form, and is no defence against shipped ECH keys (02).
3. **QUIC Initial names.** The CX's web engine speaks only gQUIC, which the full-capture filter drops (02).
4. **DNS-gated egress** assumed plain set timeouts. They do not refresh on 6.12 and later (06 F2).
5. **Position-based capture.** Continuations restart the packet count, so a first-N rule captures mid-stream ciphertext unless keyed to a seen SYN (06 F4). Decision 39 records the ciphertext cost.
6. **RITA's weights, and Lomb-Scargle on event times** (07).
7. **The share pack** named arbitrary domains by day, which identifies a household (07 F7).
8. **Lists as an update channel** were not considered at all (04).
9. **The analyst's proposal-only stance** was overruled by decision 20 without answering its warning. `SYSTEM` still says nothing is applied (03).
10. **Per-app attribution** from an hourly sample is not attribution (14).
11. **The Pi's co-tenants, the VPN boundary's failure modes, the gateway's own record and confounded trials** were all missing (11, 12, 15, 16).

## 16. Top 10 recommendations

Ranked by risk removed per unit of work. Effort: S (days), M (one to two weeks), L (more). Risk is to the running gateway. Each names the decision or workstream it touches; numbers 23 to 40 refer to decisions on `main`.

1. **Close the autonomy's fail-open paths, and keep the evidence that proves it.**
   - Refuse a `block` whose shape has `conns == 0`, unless every A answer the name received went unused.
   - Replace "passed: too little to compare" with NODATA and an extension, up to a 14-day ceiling.
   - Set `MAX_CONCURRENT_TRIALS = 1` with a `pending` queue, and change `RETRY_PREFIXES` with it.
   - Revert hourly only on two consecutive low hours with demand present (a streaming app in front, or expected-category starts).
   - Write `<stem>.pack.json` for every sent request. Add an append-only `decisions` table with gate margins and the verifier's usage.
   - Correct `SYSTEM`'s "You never apply anything", send the verifier no proposer prose, and canonicalize Unicode Cf, Co and Cn, tags, bidi and C1.

   *Touches decisions 20 and 22 (`analyst.py`, `autoblock.py`). S-M effort, low risk:* every change can only refuse or delay a block. *First step:* `sudo jq -r '.proposals[]?.applied // empty' /var/lib/tvgw/reports/proposals/*.json | grep -o 'canary [a-z]*' | sort | uniq -c`, and `sudo sqlite3 /var/lib/tvgw/tvgw.db "select verdict, reason from auto_rules where reason like '%too little%'"`. These measure how blind the watches have been.

2. **Keep the Pi closed to the TV at all times.**
   - `inet tvgw_guard` at `filter + 10`, loaded by a `tvgw-guard.service` that is `RefuseManualStop` and has no `ExecStop`.
   - In `input`, `ip saddr != { 0.0.0.0, $TV_NET } drop`. Set `net.ipv4.conf.$TV_IF.rp_filter = 1`. In `forward`, `ip saddr != $TV_IP drop` once `TV_IP` is pinned.
   - `IPAddressDeny=$TV_NET` drop-ins for smbd, nmbd, xrdp, qBittorrent, shairport-sync, nqptp, avahi-daemon and ssh, plus avahi's `deny-interfaces`.
   - `dhcp-broadcast` and `no-ping`, so dnsmasq drops `CAP_NET_ADMIN`.
   - Move the "TV API from root only" rule into the guard, and `tvgw discover`'s SSDP hole with it.
   - The .deb's maintainer scripts reload rather than restart.

   *Touches decisions 2, 5, 23 and 27 (the namespace CI proves it first). S-M effort, low risk:* the guard only narrows, and a mistake stops DHCP or DNS and leaves the TV dark, which is fail-closed. *First step:* `sudo ss -H -ltnup | awk '$5 ~ /^(0\.0\.0\.0|\*|\[::\]):/ {print $1, $5, $7}' | sort -u` and `shairport-sync -V`, then 11 F6's acceptance test in the namespace CI.

3. **Make red line 7 able to fire.**
   - Add `acr_uploader`, daily and hourly, keyed by (registrable domain or /24, `dport`), with 13 §1.4's thresholds.
   - Delete `ACR_PERIOD` and `ACR_PAYLOAD`, and remove `acr_cadence` from `analyst.novelty`.
   - Generate fixtures from published statistics only (`tests/unit/acr_synth.py`), never from the CC BY-NC-ND trace.
   - Then add the "LG adtech port" reject for TCP 4001, 4431, 4445, 4447, 8180 and 8883, with its own counter and log prefix driving the red line, before the odd-port rule.

   *Touches decisions 14, 17 and 22, and the Analysis v2 cadence canary it replaces. S effort; no risk for the detector (report-only), low for the wall (a firewall change the owner approves). First step:* the CX port history in §5 and 13 §3 test 1. Both should come back empty with Live Plus off.

4. **Make the flow log and the gate tell the truth.**
   - Set `net.netfilter.nf_conntrack_events = 0` in `sysctl.d` and in `tvgw-apply`.
   - Add a `ct_events` chain (prerouting, priority −150): `iifname $TV_IF ip saddr $TV_NET ct state new ct event set destroy`.
   - Store the event socket's drop counter in `verify --record`, with an ingest warning when it grows.
   - Correct the 2026-10-31 changelog note: the 32 MB buffer did nothing.
   - Add `expires {ttl}s` in `dnsgate.batch`.

   *Touches decisions 13, 18 and 21, and the DNS-gated egress workstream, whose enforce mode needs the refresh. S effort, low-medium risk:* the sysctl applies to every listener in the namespace. *First step:* `pid=$(systemctl show -p MainPID --value tvgw-flowlog); sudo ss -f netlink -a -p -m | grep -A1 "pid=$pid,"` (expect one socket at `rb212992`) and `awk '$2==12 && $4!="00000000"' /proc/net/netlink` (other listeners). Then 06 F2's `nft add element … expires` test in the namespace CI.

5. **Put the blocklist update channel under watch.**
   - Own `filters_update_interval: 24` in `adguardcfg.plan`.
   - `verify` asks the resolver for `h4g3z1-pro.web.app`, `h4g3z1-native-lgwebos.web.app` and `h4g3z1-doh.web.app` and expects `0.0.0.0`.
   - A brief section, "List changes", built from the query log (04's SQL), with a red line when a newly list-blocked name carried content (14-day shape over 2 MB down, or a median over 16 KB).
   - Stage A snapshot and diff later. Stage B only after the namespace harness proves the empty-200 fail-open.

   *Touches decisions 6, 7, 15 and 32. S effort for the first three, M for Stage A; low risk. First step:* `tvgw sql "select filter_id, count(*) from dns where blocked=1 group by 1"` and `dig +short @"$GW_IP" h4g3z1-pro.web.app`.

6. **AdGuard upgrade and outage discipline.**
   - Floor 0.107.79 in `verify.ADGUARD_MIN`, `install.sh` and the preinst.
   - Refuse `schema_version > 34`.
   - Own `querylog.ignored_enabled: false`, `statistics.ignored_enabled: false`, `dns.cache_enabled: true` and `filtering.rewrites_enabled`, and pin `cache_optimistic_answer_ttl: 30s` and `cache_optimistic_max_age: 12h`.
   - Add `--no-check-update` to the service, and a `tvgw adguard upgrade NEWBIN` that runs the new binary's `--check-config` on the live YAML first.
   - A restart guard: no machine-rule apply, revert or `undo` while the must-allow probe SERVFAILs ("deferred: upstream down").
   - Make `blocking_mode: default` a tested invariant, with 02's T4 in CI.

   *Touches decisions 6, 9, 25 and 27. S-M effort, low risk:* one AdGuard restart on apply. *First step:* `grep -n schema_version /opt/AdGuardHome/AdGuardHome.yaml`, then 12's T4 (the cache-wipe demonstration) in the namespace CI.

7. **Shrink the gateway's own viewing record.**
   - logrotate `rotate 2`, and `rotate 1` for `gfts-tls.log`, which is never ingested.
   - `querylog.interval: 72h` and `statistics.interval: 168h`, after deciding whether 02's `answer_ip` backfill needs the old log.
   - tvgw's journald drop-in with `Storage=persistent` and `MaxRetentionSec=14day`.
   - Daily rotation of `tvcheck-history.log`, `rotate 35`.
   - An interim `DB_DAYS=90`, until the nameless rollups allow 35 (owner decision).
   - At ingest, replace query values in `http.uri` with their lengths and strip `MAC=` from raw log lines. HMAC the `title_bearing` zones.
   - Run the weekly pass on Opus 5.5, or accept Fable's 30 days in writing.
   - A household notice.

   *Touches decisions 10 and 19, `privacy-and-retention.md`, and the storage-resilience workstream that carried October's 90 days. S-M effort, low risk. First step:* `sudo du -sh /var/lib/tvgw/{tvgw.db,backup,pcap,reports} /var/log/tvgw /opt/AdGuardHome/data`, `sudo head -c 200 /opt/AdGuardHome/data/querylog.json.1` and `tvgw sql "select min(datetime(t,'unixepoch')) from tvstate"`.

8. **Get the TV's state right before building on it.**
   - `AWAKE = ("Active", "Screen Off", "Screen Saver")`, and `power IN AWAKE` in `autoblock` and the pack.
   - A carrier-event log for `TV_IF`.
   - 14's 26-hour read-only probe: subscriptions, the power vocabulary, and the key census including `eulaStatus`.
   - Then a read-only re-pair with the full key shredded, `tvcheck` v2 limited to the public read list (with `eulaStatus` flags as red lines, `bleAdvertisingOnOff` recorded only), and the event-triggered canary.

   *Touches decisions 4, 20 (the canary), 31 (`[[privacy_setting]]` records) and 40. S effort for the first steps, M for the watcher; low risk. First step:* `tvgw sql "select power, count(*) from tvstate group by 1"`, then the probe in 14 "Settled".

9. **A change ledger and an hour classifier, then judge v2 in shadow.**
   - The dispatcher, `tvgw-apply` and `install.sh` append one line each to a spool.
   - `gw_samples` in `verify --record` (16 F7's list).
   - A `changes` table, and `tvgw autoblock calibrate --arms A,B,C --by-class` over 60 days.
   - "Changes in effect" in the brief.
   - The new judge runs beside the old one for two weeks before it decides anything.

   *Touches decisions 13 and 20. S-M effort for the ledger, M for the judge; no risk until adopted. First step:* 16 F3's SQL (the share of content bytes in flows that span an hour) and `tvgw sql "select app, count(*) from tvstate where power='Active' group by app order by 2 desc"` (the HDMI share).

10. **Make the VPN boundary explicit.**
    - A `VPN_IF` setting (auto-detected; `tun0` or `wgpia0`) in place of the three hardcoded `tun0`s.
    - Count-only postrouting rules for DoH (`@doh4` TCP 443) and for the Pi's own port 53 leaving `WAN_IF`, with a red line when they rise.
    - PIA's state on the Coverage line.
    - Corrected texts for decisions 1 and 9.
    - A note in the settings example that `URL_FILTER_RESOLVER=1.1.1.1` cannot work behind PIA.
    - Optionally a `DNS_FALLBACK` second operator by address.

    *Touches decisions 1, 6 and 9. S effort, low risk:* the counters only count. *First step:* 12's T1 (`ip rule show`, `ip route get 1.1.1.1 from "$TV_IP" iif "$TV_IF" mark 0x3214`) and T6 (`piactl get protocol; ip -br link | grep -E 'tun0|wgpia0'`).

**The next five, in order:**

- the hardware tests T1, T2, T6 and T8, then NVMe boot over USB with the SD card kept as rollback (08 items 1, 5);
- unit hardening one unit per deploy, with the AdGuard non-root drop-in after item 6 (06 F7);
- DNS-answer naming with `answer_ip` and the autonomy guard (02 items 2 to 4);
- the RF audit runbook and the consent-flag red lines (01);
- the scorecard and the HTML brief, with detail off by default (07, 15).

## 17. Do not do

Carried from October, still right:

- **Do not containerize the firewall core.**
- **Do not move the store** to WAL, Litestream, DuckDB or a time-series database (decision 10).
- **Do not replace AdGuard Home.**
- **Do not root the CX** (decision 4).
- **Add no push alerts.**
- **Do not merge CC BY-NC-ND or GPL list text** into the repository. That now includes fixtures derived from the *Watching the Watchers* trace.

New in this pass:

- **Firewall and kernel.**
  - No flowtables: without `counter` they blind the payload gate.
  - No `nf_conntrack_tcp_loose=0`: it kills continuations.
  - No bigger `conntrack -b`: it does nothing.
  - No secure-boot OTP locks, no AppArmor turned on by kernel command line, no Landlock on this kernel.
  - No first-N packet capture that is not keyed to a seen SYN.
- **DNS.**
  - Never `blocking_mode: refused`.
  - Never rewrite only the `ech` parameter with `$dnsrewrite`.
  - Never `querylog.ignored` for title zones: the DNS gate would flag every connection to them.
  - No `$dnsrewrite` "survival zone" of stale addresses.
- **Lists.** Do not subscribe to OISD, 1Hosts, Perflyst or the AdGuard DNS filter. Do not block `*.amagi.tv`.
- **ACR.**
  - Do not make cadence a red line or a source of analyst requests.
  - Do not build 07's period-only or long-connection ACR tests.
  - Do not flip `STRICT_PORTS` early: the port wall is the cheaper step, and decision 17's process stands.
- **Autonomy.**
  - Do not let a revert in a confounded hour be a verdict.
  - Do not run list promotions as exclusive trials every day.
  - Do not keep `xhigh` on the verifier without a sweep.
  - Do not send a second vendor the pack without the owner's privacy decision.
- **The TV's LAN API.**
  - No channel or programme subscriptions, no pointer input socket, no Wake-on-LAN, no `set*` call.
  - No reconnect loop faster than 5 s, and no registration retry after a pairing error.
  - Do not keep the full-permission key on a long-lived watcher.
  - Do not put raw app events in the pack.
- **Radios.**
  - Never monitor mode on `wlan0`.
  - No continuous scanning on the onboard Bluetooth, which shares the uplink's radio.
  - No raw room or TV audio, no Developer Mode app on the TV, no jamming.
  - No red line on `bleAdvertisingOnOff`.
- **VPN.**
  - Do not slip past PIA's kill switch with its `piavpn` group or its `0x3213` mark.
  - Do not move to `killswitch=on` before a forwarded fallback resolver exists.
  - Do not route LG's core names into the tunnel.
- **Hardware and image.**
  - No PoE HATs, no 2.5 GbE, no PCIe Gen 3, no overclock in the image.
  - No Raspberry Pi Connect OTA on the gateway.
  - No cloud-init together with rpi-preseed.
  - No secrets in the answers file.
  - Do not override trixie's 1-minute watchdog.
- **Supply chain.** No keyless cosign while the repository is private: Rekor would publish its name. No release builds on the Pi's runner.
- **Tools.** No IoT Inspector on the Pi: it ARP-spoofs.

## 18. Open questions

The owner decides:

1. `DB_DAYS=35` with nameless rollups, or 90 (15).
2. Whether the weekly pass leaves Fable (15 F4).
3. Stage B list promotion (04).
4. `set_rules` instead of AdGuard restarts (16).
5. The `tvgw-egress` namespace (12 F4).
6. Whether "no HAT" covers a board under the Pi (08).
7. Who may read the HTML brief (07, 15).

The gateway answers, with the tests above:

1. Does the CX use 4431 at all? Only passively: the port history and the wall's counter.
2. Which keys and subscriptions answer on 04.64 (14's probe)?
3. Is the CX's port 100 Mb/s, and does it flap (T1, T2)?
4. How many canaries were `unobserved` (recommendation 1's first step)?
5. What is the HDMI share of `Active` hours?
6. Is there any gQUIC (02 T5)?
7. Does the CX ask for type 65 at all (02 T3)?

## 19. Index of the section files

The full list with one line each is in [deep-dive-2026-11/README.md](deep-dive-2026-11/README.md).

| File | Theme | Report section |
|---|---|---|
| [01-radios-and-side-channels.md](deep-dive-2026-11/01-radios-and-side-channels.md) | Wi-Fi, BLE, HDMI-CEC, microphone, ultrasonic; tvcheck v2 keys | §1 |
| [02-naming-beyond-sni.md](deep-dive-2026-11/02-naming-beyond-sni.md) | ECH, the HTTPS/SVCB strip, DNS-answer naming, QUIC, JA4 | §2 |
| [03-analyst-evaluation-and-safety.md](deep-dive-2026-11/03-analyst-evaluation-and-safety.md) | Evals, prompt injection, correlated models, gates, cost | §3 |
| [04-blocklists-and-verification.md](deep-dive-2026-11/04-blocklists-and-verification.md) | The list update channel, sentinels, staged promotion, breakage ledger | §4 |
| [05-tv-privacy-research-2026.md](deep-dive-2026-11/05-tv-privacy-research-2026.md) | *Watching the Watchers*, LG 2026, regulation, rule-set changes | §5 |
| [06-platform-and-kernel-depth.md](deep-dive-2026-11/06-platform-and-kernel-depth.md) | conntrack events, set timeouts, AdGuard churn, trixie, unit hardening | §6 |
| [07-measurement-and-presentation.md](deep-dive-2026-11/07-measurement-and-presentation.md) | Beacons, upload anomalies, uncertainty, scorecard, HTML brief | §7 |
| [08-next-build-hardware.md](deep-dive-2026-11/08-next-build-hardware.md) | Bill of materials, EEE, power, watchdog, the image pipeline | §8 |
| [11-gap-the-pi-is-the-tv-s-only-neighbour-the-tv.md](deep-dive-2026-11/11-gap-the-pi-is-the-tv-s-only-neighbour-the-tv.md) | The guard table, co-tenants, source pinning, dnsmasq capabilities | §9 |
| [12-gap-the-vpn-boundary-which-of-the-pi-s-own-f.md](deep-dive-2026-11/12-gap-the-vpn-boundary-which-of-the-pi-s-own-f.md) | PIA's kill switch, DoH failure modes, fallback resolver | §10 |
| [13-gap-reconcile-the-two-incompatible-acr-detec.md](deep-dive-2026-11/13-gap-reconcile-the-two-incompatible-acr-detec.md) | One ACR detector, settled on the released trace | §5 |
| [14-gap-live-tv-state-through-ssap-subscriptions.md](deep-dive-2026-11/14-gap-live-tv-state-through-ssap-subscriptions.md) | SSAP subscriptions, power states, read-only key, the 26-hour probe | §11 |
| [15-gap-the-gateway-s-own-viewing-record-retenti.md](deep-dive-2026-11/15-gap-the-gateway-s-own-viewing-record-retenti.md) | Retention inventory, minimization, Anthropic terms, `tvgw forget` | §12 |
| [16-gap-one-change-at-a-time-a-change-ledger-and.md](deep-dive-2026-11/16-gap-one-change-at-a-time-a-change-ledger-and.md) | Confounders, the change ledger, judge v2, the trial lock | §13 |

## Sources

This list covers what this report itself read on 2026-11-01. Each section file carries its own sources.

- Anthropic: [Claude Opus 5.5 announcement](https://www.anthropic.com/news/claude-opus-5-5); [pricing](https://platform.claude.com/docs/en/about-claude/pricing.md); [effort](https://platform.claude.com/docs/en/build-with-claude/effort.md); [API version 2026-10-21 migration](https://platform.claude.com/docs/en/api/migration-2026-10-21); [API and data retention](https://platform.claude.com/docs/en/manage-claude/api-and-data-retention)
- AdGuard Home at the v0.107.79 tag: [internal/dnsforward/msg.go](https://raw.githubusercontent.com/AdguardTeam/AdGuardHome/v0.107.79/internal/dnsforward/msg.go); [internal/filtering/filter.go](https://raw.githubusercontent.com/AdguardTeam/AdGuardHome/v0.107.79/internal/filtering/filter.go); [internal/filtering/rulelist/parser.go](https://raw.githubusercontent.com/AdguardTeam/AdGuardHome/v0.107.79/internal/filtering/rulelist/parser.go)
- Linux v6.18: [net/netfilter/nf_conntrack_core.c](https://raw.githubusercontent.com/torvalds/linux/v6.18/net/netfilter/nf_conntrack_core.c)
- systemd: [systemd-analyze(1)](https://www.freedesktop.org/software/systemd/man/latest/systemd-analyze.html); libffi: [static trampolines PR](https://github.com/libffi/libffi/pull/603)
- LG: [Understanding privacy on LG smart TVs, 2026-09-12](https://www.lg.com/us/newsroom/corporate/statement-understanding-privacy-on-lg-smart-tvs); [OLED55CX3LA software list](https://www.lg.com/ro/suport/produs/lg-OLED55CX3LA)
- bscpylgtv: [available settings, OLED CX, 04.63.25](https://github.com/chros73/bscpylgtv/blob/master/docs/available_settings_CX.md)
- Press on the LG investigation: [Notebookcheck](https://www.notebookcheck.net/LG-smart-TVs-caught-logging-audio-with-screen-off-and-snooping-on-local-devices.1391214.0.html); [Malwarebytes](https://www.malwarebytes.com/fr/blog/privacy/2026/09/lg-tv-flaws-could-let-attackers-listen-in-even-in-standby-mode); [IT-Connect](https://www.it-connect.tech/lg-tvs-allegedly-scan-your-local-network-and-listen-in-standby/)
- Texas v. LG: [CIPAWorld, 2026-05-11](https://cipaworld.com/2026/05/11/texas-obtains-smart-tv-privacy-settlement-with-lg-heres-what-changes/); [Fox 7, 2026-05-12](https://www.fox7austin.com/news/lg-smart-tv-acr-data-collection-texas-settlement); Texas AG release (HTTP 402 to this pass): https://texasattorneygeneral.gov/news/releases/attorney-general-ken-paxton-secures-major-agreement-lg-protect-texans-privacy-and-stop-data-being
- GitHub: [arm64 standard runners in private repositories, 2026-01-29](https://github.blog/changelog/2026-01-29-arm64-standard-runners-are-now-available-in-private-repositories); [RITA releases](https://api.github.com/repos/activecm/rita/releases?per_page=5)
- Raspberry Pi: [M.2 HAT+ forum thread](https://forums.raspberrypi.com/viewtopic.php?t=372508); [raspberrypi-sys-mods journald drop-in](https://github.com/RPi-Distro/raspberrypi-sys-mods/blob/pios/trixie/usr/lib/systemd/journald.conf.d/40-rpi-volatile-storage.conf)
- CX Ethernet speed (indirect only): [Best Buy, C3](https://www.bestbuy.com/site/questions/lg-65-class-c3-series-oled-evo-4k-uhd-smart-webos-tv-2023/6535929/question/b5321f4e-1f50-3cfa-a9fc-94302c0fadbc)
- Not reachable to this pass: fcc.gov equipment authorization and fccid.io (HTTP 403), and the RTINGS ACR page (did not render).
- The repository: `main` at `fba2b79` (`docs/design-decisions.md` 23 to 40, `src/tvgw/queries.py`, `src/tvgw/analyst.py`, `src/tvgw/dnsgate.py`, `src/tvgw/verify.py`, `deploy/systemd/tvgw-flowlog.service`, `CHANGELOG.md`), and the research worktree at `43b3bd9`.
