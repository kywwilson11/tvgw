# Gap 3: one ACR detector, reconciled from sections 05 and 07

*Deep dive 13, written 2026-11-01. Research only: nothing here is implemented, and no host was touched. It extends [05 §1.1 and build item 1](05-tv-privacy-research-2026.md#11-what-lgs-acr-looks-like-on-the-wire-and-why-tvgws-canary-misses-it-settled-measured-here) and [07 F1, "The ACR canary", and build item 3](07-measurement-and-presentation.md#the-acr-canary-checked-against-the-numbers-it-was-built-from), and does not repeat them. **(measured here)** means this pass computed it from the *Watching the Watchers* data, read privately under CC BY-NC-ND 4.0 with stdlib Python and DuckDB 1.1.3 in a scratch directory outside the repository. Only summary statistics appear below: no rows, lists or fixtures derived from the data. **(unverified)** means one secondary source or none. **(test)** gives the exact check to run on the gateway later. No site identifiers appear: the lab set's own MACs and addresses were read and are not reproduced.*

## Bottom line

Neither proposal is right as written, and the evidence settles which parts of each to keep. Rebuilt as conntrack would see it, the released LG trace (10,795 connections, 17 local days) never trips **any** of 07's tests: its 10-20 s period test fires on 0 of 17 days, on flows and on DNS alike, and its over-1-hour long-connection check finds 0 ACR connections (the longest lasts 951 s). Over the lab set's full 16-day, 148,026-connection history, the same long-connection check fires 64 times, all on `www.youtube.com`. The shipped `acr_like` fires on nothing at all. 05's daily volume-and-ratio test does the job: it fires on every full ACR day, on `alphonso.tv` alone, and on none of 447 other day-and-domain cells with 24 or more connections. It needs two repairs. First, key it by **(registrable domain, server port)**, because Alphonso's control plane rides port 443 and drags the domain-wide ratio down to 4.5 on some days. Second, add an **hourly** twin, which catches a partial day. IMC 2024's "kilobytes" turn out to be summed Ethernet frame bytes, both directions, per one-hour experiment: the trace's fingerprinting hours carry a median of 4,812 KB on the same basis, against IMC's 4,125-4,948 KB. So 07's 17-19 KB "per contact" and 05's roughly 24 KB "per burst" are the same quantity, one fingerprint upload every 14-15 s. The two sections never disagreed about size. They disagreed about whether a contact is a connection, and it is not: a connection carries a median of 3 bursts. **Merged spec:** red line 7 is driven by the upload test (daily or hourly), by name, and by a new port-wall counter. Cadence only marks a row and never buys an analyst request. 07's period-only and long-connection ACR tests are dropped. The port wall should land **before** decision 17's `STRICT_PORTS` and stay after it, but it is a detector more than a defence. Alphonso's provisioning host makes two of every three of its connections on 443, so the DNS block, not the wall, is what contains the control plane.

---

## 1. Findings

### 1.1 The trace as conntrack would see it: which tests fire (settled, measured here)

**Method.** In `tkacr.csv` ([Zenodo 22733487](https://zenodo.org/records/22733487)), each row is a frame: time, frame length, MACs, addresses, ports and DNS fields. There are no TCP flags, so connection boundaries are inferred:

- A connection is one (TV port, server address, server port) tuple, split after 600 s of silence, which catches source-port reuse. That gives 10,795 connections; 05 counted 10,174 without the split.
- IP bytes are frame length less 14, because conntrack counts IP bytes.
- Payload is `max(0, bytes − 40·pkts)`, as `payload_bound()` computes it.
- Days are US Eastern dates, the lab's local time.

Every test was implemented exactly as specified: the shipped `beacons()` with its constants, 07's period-only `acr_like` (10-20 s, payload not gated) on flows and on DNS, 07's long-connection check (over 3,600 s, 0.5-40 KB a minute), and 05's daily test (at least 1 MB payload up, at least 4× down, at least 24 connections).

| Day (local) | Conns | Conns with ACR bursts | Max duration (s) | Payload up (MB) | Up:down | 05 daily | Shipped `acr_like` | 07 period 10-20 s | 07 > 1 h |
|---|---|---|---|---|---|---|---|---|---|
| 04-22 (trace starts 22:24) | 52 | 6 | 181 | 0.7 | 6.8 | no | no | no | 0 |
| 04-23 | 648 | 207 | 276 | 30.0 | 16.7 | **yes** | no | no | 0 |
| 04-24 | 755 | 243 | 545 | 31.6 | 14.2 | **yes** | no | no | 0 |
| 04-25 | 784 | 218 | 525 | 29.8 | 13.1 | **yes** | no | no | 0 |
| 04-26 | 877 | 244 | 531 | 33.6 | 14.2 | **yes** | no | no | 0 |
| 04-27 | 598 | 119 | 461 | 17.5 | 11.9 | **yes** | no | no | 0 |
| 04-28 | 83 | 24 | 743 | 3.1 | 11.1 | **yes** | no | no | 0 |
| 04-29 | 671 | 201 | 399 | 26.2 | 13.6 | **yes** | no | no | 0 |
| 04-30 | 1,771 | 213 | 524 | 34.2 | 11.5 | **yes** | no | no | 0 |
| 05-01 | 907 | 220 | 951 | 31.1 | 15.6 | **yes** | no | no | 0 |
| 05-02 | 749 | 147 | 928 | 22.8 | 11.6 | **yes** | no | no | 0 |
| 05-03 | 405 | 109 | 420 | 14.6 | 12.4 | **yes** | no | no | 0 |
| 05-04 | 352 | 156 | 790 | 21.0 | 13.2 | **yes** | no | no | 0 |
| 05-06 | 81 | 4 | 223 | 0.6 | 3.0 | no | no | no | 0 |
| 05-07 | 741 | 107 | 289 | 13.9 | 7.5 | **yes** | no | no | 0 |
| 05-08 | 843 | 138 | 389 | 17.3 | 9.0 | **yes** | no | no | 0 |
| 05-09 | 478 | 47 | 321 | 6.5 | 7.1 | **yes** | no | no | 0 |

(The trace has no 05-05 rows. "ACR bursts" means at least three upload bursts over 2 KB, two of them 13-16 s apart.)

What the table settles:

1. **07's period-only test never fires on LG's real ACR client.** The flow-start series for the whole zone is periodic on 8 days, always at about **60 s**: the client's connection timer, not the fingerprint timer. The per-FQDN series is periodic on 0 to 3 names a day, also at 58-60 s. The 14-15 s cadence exists only inside connections: 9,818 of the in-connection burst gaps are 14 s.
2. **07's long-connection check cannot fire on it either.** Connections with more than 10 KB up last a median of 113 s (IQR 46-165 s, p99 381 s, maximum 951 s). The over-1-hour branch therefore sees no ACR connection at all. The formula `payload_bound / (t_end − t_start − 7440)` has a second problem. tvgw's `t_end` is the conntrack destroy time, which is the last packet plus 120 s for a connection closed with FIN (TIME_WAIT), not plus 7440 s ([conntrack.py docstring](../../../src/tvgw/conntrack.py), [architecture, naming a connection](../../architecture.md#naming-a-connection)). For every connection that closes normally, the denominator goes negative.
3. **05's daily test fires on every full ACR day and misses two.** 04-22 is a 90-minute stub of a day (0.7 MB). 05-06 has 4 ACR connections and 0.6 MB, a ratio of 3.0, and is effectively an ACR-off day. The hourly twin in §1.4 catches 04-22.
4. **The shipped `acr_like` is dead code for LG.** It fires on 0 of 17 days, as 05 found, and the full lab history below confirms it.

### 1.2 The test the other way round: false positives on the lab set's whole network life (settled for the lab set, measured here)

The full-traffic parquet ([Zenodo 22698120](https://zenodo.org/records/22698120), 75,326,750 headers, 2026-04-21 to 05-09) was rebuilt the same way. It gives 148,026 connections to public addresses, 99.3% of them named by a preceding DNS answer, grouped by registrable domain (or by /24 when unnamed).

| Test | Fires on `alphonso.tv` | Fires on anything else | Denominator |
|---|---|---|---|
| Shipped `acr_like` (10-20 s, < 4 KB) | 0 days | 0 | 38 FQDNs and 15 domains periodic on some day |
| 07 period-only, per FQDN or per domain | 0 days | 0 | same |
| 07 long connection, > 1 h and 0.5-40 KB/min | 0 connections | **64 connections, all `www.youtube.com`** (median 3,624 s, 3.7 KB/min) | 230 connections over 1 h |
| 05 daily, per registrable domain | 15 of 17 days | **0 of 447** day-and-domain cells with ≥ 24 connections | 1,130 cells in all |
| 05 hourly twin (≥ 500 KB, ≥ 4×, ≥ 5 conns) | 151 hours on 16 days | 7 hours `youtube.com`, 1 hour `netflix.com` (both `Streaming`) | 9,236 hour cells |
| 05's widened cadence (10-200 s, jitter against multiples) | 9 of 17 days | **15 other domains on 57 day cells**: `avsxappcaptiveportal.com` every 30 s (17 days), `meethue.com` 90 s (11), `youboranqs01.com`, `tubitv.com`, `conviva.com`, `nflxvideo.net` 60 s, `amagi.tv`, and others | 1,130 cells |

The upload tests separate ACR from everything else by a wide margin on everything except one ratio. YouTube uploaded 11-12 MB a day (on `www.youtube.com` port 443, roughly equal up and down) and reached a ratio of 3.07 on its best day. That is 77% of the threshold. The scope rule keeps it out on the CX, because `youtube.com` is in `Streaming`, an expected category. Without the scope rule the threshold would be uncomfortably close. **Cadence, by contrast, is a poor discriminator:** a 10-200 s timer is what captive-portal probes, Hue bridges, QoE beacons and streaming heartbeats all look like. On the CX most of those names are blocked and have no flows, but any that are allowed and outside the expected categories would mark every day. Under [decision 22](../../design-decisions.md#22-a-pass-that-proposes-nothing-is-remembered), a mark that recurs by construction must not buy a request.

**One correction to 05's grouping.** Alphonso's provisioning host `prov-lg.alphonso.tv` made **1,192 connections on TCP 443** and 597 on TCP 4001 (median 32 s, about 1.1-1.4 KB up and 3.7-6.8 KB down). Grouped domain-wide, these pull the `alphonso.tv` daily ratio down to **5.2 on 05-07 and 4.5 on 05-09** (the tkacr-only ratio is 7-17). Keying the test by (registrable domain, server port) puts the fingerprint traffic on 4431 in a cell of its own, with a ratio between 7 and 17, and costs nothing for other names.

### 1.3 IMC 2024's units, and whether 07's 17-19 KB is 05's 24 KB (settled from the authors' code, cross-checked on the trace)

The paper's Tables 2 and 4 say only "Number of kilobytes sent/received to/from ACR domains" for each scenario, in the logged-in, opted-in phase. The US LG row reads idle 215.3, antenna 4,583.2, FAST 4,948.3, OTT 214.9, HDMI 4,125.0 and screen cast 240.4 ([arXiv 2409.06203](https://arxiv.org/html/2409.06203v1)). The text says the core experiment runs "for a duration of one hour". The paper is silent on per-hour versus per-experiment and on direction. The authors' repository answers both ([SafeNetIoT/ACR](https://github.com/SafeNetIoT/ACR), commit `bdc56aa`, 2024-09-09):

- `trigger_validation_scripts/experiment.sh` stays on the scenario for `$2 * 60` seconds, so one experiment is one pcap of the stated length.
- `analysis_scripts/extract_csv_from_pcap.sh` exports `frame.len`: Ethernet frame bytes, headers included.
- `analysis_scripts/print_most_contacted_domains.py` sums `frame_len` grouped by `dns_resp_name` **with no direction filter**, so sent and received are added together.
- Which script produced the tables is **unverified** (no table script is in the repository). `print_most_contacted_domains.py` is the only one that totals per domain.

**Cross-check (measured here).** On the same basis (frame bytes, both directions, per clock hour), the trace's 20 hours with at least 150 fingerprint bursts carry a median of **4,812 KB** (IQR 3,988-5,380). IMC's US antenna, HDMI and FAST figures are 4,125-4,948 KB. The trace's near-idle hours (fewer than 5 bursts) carry 116 KB, against IMC's 215 KB idle. Agreement within the spread is strong evidence that the tables are **per one-hour experiment, both directions, frame bytes**. 07's reading of them "as KB per hour" was right.

**Same quantity?** Yes. 07's 17-19 KB per contact is 4,125-4,583 KB divided by 240 fifteen-second slots, and it includes headers and the download. The trace's fingerprint bursts carry a median of **22.1 KB of payload** (p10 6.4 KB, p90 24.2 KB), with at most 216 bursts in a clock hour, and about 21 KB of payload per burst over busy hours. 05's "about 24 KB" is the same quantity measured with a different header deduction. Both are one fingerprint upload. The real disagreement was the event unit: a contact is a burst inside a connection, and a connection carries a median of 3 bursts (p90 9). 07 hedged exactly this case in F1 blind spot 2; the trace shows the hedge was needed.

**Asking the authors.** The repository settles the unit well enough to proceed, so no message was sent; this pass contacts no one. If the owner wants the table script confirmed, the question for the IMC authors (contact through the paper's DOI page, [10.1145/3646547.3689013](https://doi.org/10.1145/3646547.3689013)) is one line: "Were Tables 2 and 4 computed with `print_most_contacted_domains.py`, that is frame bytes summed over both directions for the whole one-hour pcap?"

### 1.4 The merged detector (settled design; thresholds from §1.1-1.2)

| Signal | What it computes | Drives red line 7? | Novelty (requests)? | Lab trace recall | Lab false positives (in scope) |
|---|---|---|---|---|---|
| **A. `acr_port`**: the port wall's counter | New TCP connections from the TV to 4001, 4431, 4445, 4447, 8180 or 8883, rejected and counted (§1.6) | **Yes**: any increment in the window | Yes, through the red line | 16 of 16 ACR-endpoint days used 4431/4445/4447 | 0 (every non-80/443 port in 16 days was ad tech or IoT, 05 §1.8) |
| **B. `acr_uploader`, daily** | Per day, per (registrable domain or /24, `dport`): payload up ≥ 1,000,000 B, up ≥ 4 × down, ≥ 24 connections; name outside `expected_categories` or unnamed | **Yes** | Yes, through the red line | 15 of 17 days (misses a 90-minute stub and a 4-connection day) | 0 of 447 cells |
| **B'. `acr_uploader`, hourly** | The same per clock hour: ≥ 500,000 B, ≥ 4×, ≥ 5 connections | **Yes** | Yes, through the red line | 16 of 17 days (151 hours) | 0 in scope (8 hours, all `Streaming`, out of scope) |
| **C. Cadence mark** | `beacons()` period and jitter as today, shown as an attribute; optionally 05's harmonic jitter | **No** | **No** | 8-9 of 17 days, at 60 s | 15 domains on 57 cells: why it must not alarm |
| **D. ACR DNS series** | Lookups of category-`ACR` names, allowed and blocked, with their rhythm (§1.5) | Allowed lookup: **yes** (as A1 "reached"). Blocked only: no | A **change** in rate (07 F4 two-Poisson test, q 0.10): yes | n/a | n/a |
| ~~07 period-only `acr_like`~~ | 10-20 s period, flows or DNS | Dropped | Dropped | 0 of 17 | 0 |
| ~~07 long-connection ACR~~ | > 1 h, 0.5-40 KB/min | Dropped as ACR. Keep RITA-style long connections as a plain listing | No | 0 connections | 64 (YouTube), and the formula is wrong for FIN closes |

How the red line reads, replacing [operations.md's line for red line 7](../../operations.md):

```text
ACR-shaped upload: <name or /24>:<dport> sent <X> MB up (<R>x down) in <N> connections <today|in hour HH>; Live Plus reads <state>
ACR port attempts: <N> connections to TCP <ports> rejected (<names from DNS answers for those addresses, or "no lookup">)
```

Implementation notes for `queries.py`:

- Group with `names.registrable_domain(FLOW_NAME)` when named, otherwise `rtrim(dst,'0123456789') || '0/24'`, and always with `dport`. The 41 rotating `tkacrNNN` names then collapse into one row, and the hello on 4431 is still captured: the pcap filter matches a ClientHello on any TCP port, and tshark's TLS heuristic dissector `tls_tcp` is enabled by default ([packet-tls.c, `heur_dissector_add(... HEURISTIC_ENABLE)`](https://gitlab.com/wireshark/wireshark/-/blob/master/epan/dissectors/packet-tls.c)). Confirm with a golden pcap of a hello on 4431 (**test**, §3 item 6).
- Bucket by `t_start`, not `t_end`. A flow's `t_end` is late by its idle timeout, and ACR connections are short enough that `t_start` puts them in the right hour.
- Keep `beacons()` and its `PERIODIC_JITTER` screen. Delete `ACR_PERIOD` and `ACR_PAYLOAD`, rename `acr_cadence` to `acr_upload`, and stop counting `acr_cadence` in `analyst.novelty`. The red line already counts.

### 1.5 What the blocked `alphonso.tv` DNS series should look like on the CX (prediction settled from the lab set; the CX reading is a test)

**05's "short answer TTLs (6-12 s seen)" is wrong** (measured here). In `tkacr.csv`, A answers carry a median TTL of 1,754 s, with a p90 of 3,582 s and a mode of 3,600 s. CNAMEs carry a median of 2,319 s. Values of 6-12 s appear, but they are the bottom of a resolver cache counting down from 3,600 s. The lab set asked 1.1.1.1 and 1.0.0.1 in parallel, so cached answers decay. Each `tkacrNNN` name is re-resolved about every 30 minutes (gaps cluster at 1,780-1,830 s). Zone-wide, lookups are **aperiodic**: the beacon test's MAD/median is 0.6-0.95 every day. The control-plane names are short-lived by comparison (`bl-server` 143-282 s, `clockskew` 4-227 s), and they run on **a clean timer**: `prov-lg`, `bl-server` and `clockskew.alphonso.tv` are looked up together every **1,094-1,144 s** (about 19 minutes), with jitter 0.01-0.04, on 15 of 17 days. 05 §1.8 found them "whatever the ACR state".

**The answer to 07's question.** AdGuard answers a blocked name with `0.0.0.0` or `::` in `blocking_mode: default` ([AdGuard Home configuration](https://github.com/AdguardTeam/AdGuardHome/wiki/Configuration)), with the 60 s TTL tvgw sets. That floor is shorter than every timer the client runs (19 minutes for the control plane, about 30 minutes per tkacr name), so **it cannot shape the series** unless the client retries a failed connect faster than its own timer. 07 predicted 60 s lookups from a 15 s ACR timer. That presumed one lookup per fingerprint, which the trace rules out: the fingerprint timer runs inside an open connection, not through DNS.

**Expected on the CX with Live Plus off:** no `tkacr` lookups (the opt-out stops ACR, 05 §1.1), and blocked control-plane lookups about every 1,140 s while the TV is on, if webOS 5 runs the same client (unverified). **(test)** 07 F1's SQL needs two fixes before it means anything here. The TV's parallel queries to two resolvers, both DNAT'd to AdGuard, plus the A and AAAA pairs, would make the `0` bin dominate. So keep A only and drop gaps under 2 s:

```sh
sudo tvgw sql "WITH e AS (SELECT qname, t, LAG(t) OVER (PARTITION BY qname ORDER BY t) p FROM dns
  WHERE qname LIKE '%alphonso.tv' AND qtype='A' AND t >= strftime('%s','now','-30 days'))
  SELECT qname, CAST((t-p)/30 AS INT)*30 AS gap_s, COUNT(*) n FROM e
  WHERE p IS NOT NULL AND t-p > 2 AND t-p < 7200 GROUP BY 1,2 ORDER BY n DESC LIMIT 15"
```

Reading it:

- Dominant bins at 1,080-1,140 s mean the client's own timer, the same client as the lab set's.
- Bins at 60-90 s mean the client retries on failure and the TTL floor paces it.
- `tkacr` names with Live Plus off would be a red line under signal D.

The `qtype` column holds AdGuard's type string. If the values stored are numeric, use `qtype IN ('A','1')`.

### 1.6 The port wall: the CX history, legitimate users of 8883 and 4001, and its order relative to `STRICT_PORTS` (partly settled; the CX history is a test)

**Registry and vendor facts.**

| Port | IANA | Known legitimate use by anything on this TV | Lab LG use |
|---|---|---|---|
| 4001 | `newoak` (tcp/udp) ([IANA](https://www.iana.org/assignments/service-names-port-numbers/service-names-port-numbers.xhtml?search=4001)) | None found | Alphonso provisioning (`prov-lg`), 597 conns |
| 4431 | `wspipe`, "adWISE Pipe", tcp, 2009 ([IANA](https://www.iana.org/assignments/service-names-port-numbers/service-names-port-numbers.xhtml?search=4431)) | None found | ACR fingerprints, 10,609 conns |
| 4445, 4447 | `upnotifyp`, `n1-rmgmt` ([IANA](https://www.iana.org/assignments/service-names-port-numbers/service-names-port-numbers.xhtml?search=444)) | None found | ACR, 186 conns (heartbeat-sized) |
| 8180 | Unassigned (inside 8163-8180) ([IANA](https://www.iana.org/assignments/service-names-port-numbers/service-names-port-numbers.xhtml?search=8180)) | None found | LG ads (`aic.ads.lgtvcommon.com`), 24 conns |
| 8883 | `secure-mqtt`, OASIS ([IANA](https://www.iana.org/assignments/service-names-port-numbers/service-names-port-numbers.xhtml?search=8883)) | MQTT over TLS: AWS IoT Core (LG ThinQ's push channel, already blocked by name) and Azure IoT Hub (UEI Nevo/QuickSet, blocked by name) | Nevo hub, 176 conns, median 3,758 s, 0.5 MB over 16 days |

The household's apps on the TV are Netflix, YouTube, Prime Video, Peacock, Max, Disney+, Pluto and GeForce NOW (`lg-webos.toml` `Streaming`). No vendor documentation or registry entry found ties any of them to these six ports. GeForce NOW's documented client ports are UDP 49003-49006 and TCP 49006, though that comes only from secondhand forum reproductions of NVIDIA's article, **unverified** ([NVIDIA developer forum](https://forums.developer.nvidia.com/t/geforce-now-ip-for-firewall/302167)). The Pi's own services (qBittorrent, Samba, AirPlay, xrdp, the PIA tunnel) never pass through `tv_out`, so the wall cannot touch them.

**8883 has a fallback, and that changes what the wall is for.** AWS IoT Core accepts the same X.509 MQTT session on 443 with ALPN `x-amzn-mqtt-ca` ([AWS IoT protocols](https://docs.aws.amazon.com/iot/latest/developerguide/protocols.html)). Azure IoT Hub serves MQTT over WebSockets on 443, its docs tell clients to use it when 8883 is blocked, and the C# SDK's `TransportType.Mqtt` falls back to it automatically ([Microsoft Learn, updated 2026-08-27](https://learn.microsoft.com/en-us/azure/iot/iot-mqtt-connect-to-iot-hub)). Alphonso's provisioning host already uses 443 for two of every three connections (§1.2). Whether the fingerprint client falls back to 443 after a reset on 4431 is unknown. So:

- The wall **contains nothing that the DNS block does not already contain** on this CX: `alphonso.tv`, the Nevo hub regex in 05 and LG's ad hosts are all name-blocked.
- Its value is **naming an attempt that DNS missed**: a hardcoded address, a resolver the gateway did not see, or a firmware with a new ACR host on an old port. A rejected SYN never confirms its conntrack entry, so it leaves **no `flows` row**. The evidence is the counter, plus a rate-limited log sample like `tvgw-oddport`. That is why the counter itself must drive red line 7 (signal A).

**(test) The CX's history** (05 test 1, unchanged; owner-run, read-only). An empty result on both queries means the wall is free:

```sh
sudo tvgw sql "select dport, count(*), sum(bytes_up), datetime(min(t_start),'unixepoch'), datetime(max(t_start),'unixepoch') from flows where dport in (4001,4431,4445,4447,8180,8883) group by dport"
sudo tvgw sql "select dport, count(*) from oddport group by dport order by 2 desc limit 20"
```

**Order relative to decision 17: before it, and kept after it.**

1. **It unblocks decision 17's own evidence process.** Decision 17 flips `STRICT_PORTS` after two weeks of `Unexpected ports: none`. A TV that pings 4001 or 8883 on a timer would keep that line from ever being empty. With the wall rejecting the known ad-tech ports *before* the `tvgw-oddport` rule, "Unexpected ports" counts only the unknown ports, which is what decision 17 meant to measure.
2. **The lab evidence supports the end state but is not this TV's evidence.** The lab set is a 2025-26 US model on a newer webOS. 16 days with no legitimate port beyond 80 and 443 is strong support for `STRICT_PORTS=yes` eventually. It does not replace two weeks of the CX's own briefs.
3. **After the flip, keep the wall as its own rule.** `STRICT_PORTS` would reject these ports anyway, but under "odd ports". A separate counter keeps "the TV tried an ad-tech port" (a red line) apart from "the TV tried an unknown port" (a breakage risk).

The rule, in `tv_out` after `manual IP blocks` and before the LG 8080 line, written as `log` and `reject` rules of their own, as the file already does for protocols:

```nft
tcp dport { 4001, 4431, 4445, 4447, 8180, 8883 } limit rate 6/minute log prefix "tvgw-adport: "
tcp dport { 4001, 4431, 4445, 4447, 8180, 8883 } counter reject with tcp reset comment "LG adtech port"
```

Add `("LG adtech port", "adtech ports")` to `queries.FW_LINES`, ingest `tvgw-adport:` samples into the `oddport` table with a `kind` column (or a table of its own), and name each sample's address from `dns.answers` over the 7 days before.

### 1.7 Synthetic fixtures, from published statistics only

The licence forbids committing the trace or anything derived row by row. Fixtures are generated in the test with a seeded `random.Random` from **summary numbers** (05 §1.1, this section, *Watching the Watchers* §5.1 and IMC 2024 Table 4), never from rows:

| Fixture | Generator | Must |
|---|---|---|
| `lg_acr_day` | 14 h awake. Connection opens on a 60 s timer, the next gap drawn from {56: 0.15, 60: 0.45, 120: 0.25, 180: 0.15}. One open in three is a fingerprint connection: lognormal duration (median 113 s, σ 0.8, cap 950 s), bursts every 14 s ± 1 of N(22 KB, 3 KB) payload, down = up / U(8, 17). The rest are heartbeats: 1.1-1.8 KB up, 3 KB down. Port 4431, names `tkacr6NN.alphonso.tv` (41 rotating) | Fire B and B'; not fire 07's tests; C marks at about 60 s |
| `lg_acr_stub` | The same, 90 minutes only | B' fires and B does not (the 04-22 case) |
| `lg_control_plane` | 3 names looked up together every 1,140 s ± 1%; one 443 connection and one 4001 connection each time (1.2 KB up, 3.7-6.8 KB down) | B and B' silent; with the 4001 connection rejected, A fires |
| `streaming_heavy_up` | `youtube.com` in `Streaming`, 250 connections, 11.8 MB up, ratio 3.07 | B and B' silent: out of scope, and the ratio is under 4 |
| `telemetry_burst` | Unexpected category, 9 connections, 961 KB up in one hour, ratio 20 | B silent (9 connections); B' fires (an upload-heavy hour, a true "ACR-shaped" alarm on a telemetry name) |
| `mqtt_long` | 8883, one connection per day of 3,758 s, 0.02 KB/min | B silent; A fires once the wall is in |
| `timer_noise` | 30 s and 90 s timers, 0.2-1.1 KB, unexpected category | C marks; no red line; no novelty reason |
| `firmware_download` | 400 MB down, ACKs up (40 B × packets) | Payload up about 0: B and B' silent |

---

## 2. What to build here

Ranked by value against risk. Effort: S is a day or two, M a week. Risk is to the running gateway.

1. **Replace red line 7 with `acr_uploader` (B and B').** *S effort, no risk* (report-only; golden brief tests change).
   - Use the §1.4 keys and thresholds and delete `ACR_PERIOD`/`ACR_PAYLOAD`.
   - Remove `acr_cadence` from `analyst.novelty`.
   - Run beside the old output for a week; with Live Plus off, both must stay silent on the CX.
   - Acceptance: every fixture in §1.7 behaves as its row says, and §3 items 1-2 show 0 in-scope hits over 30 days.
2. **Synthetic fixture generator** (`tests/unit/acr_synth.py`), with the summary numbers as named constants and their sources in comments. *S effort, no risk.* Build it first and use it for item 1.
3. **The `LG adtech port` wall with its own counter, log sample and signal A.** *S effort, low risk; a firewall change the owner approves.*
   - Prerequisite: the §1.6 history test comes back empty.
   - Prove it in the namespace harness (in flight): from the TV namespace, `nc -z -w 2 <public test address> 4431` must fail with a reset and the counter must read 1.
   - The rule touches `tv_out` only, so the Pi's own services cannot be affected.
4. **Fix 07 F1's DNS-gap SQL and add signal D's rate-change test for category `ACR`.** *S effort for the SQL, M for D. No risk.* D fires on a change in the control plane's blocked-lookup rate across a firmware update (07 F4), which is where the Texas-settlement consent screen would show (05 §1.5).
5. **A golden pcap: a ClientHello on TCP 4431 and on 8883.** It must yield `tls` rows with SNI. *S effort, no risk.* Fold it into the hardened-extractor corpus already in flight.
6. **Long connections as a plain brief listing (RITA-style, ≥ 1 h), never labelled ACR.** *S effort, no risk.* On the CX, YouTube and Netflix keep-alives would fill it: list it under expected categories collapsed.

**Do not build:** 07's period-only `acr_like` and its long-connection ACR check, which are inert on the real client and noisy on YouTube. Do not build cadence as a red line, nor as a source of analyst requests: 05's widened cadence marks 15 non-ACR domains. Do not let the wall stand in for `STRICT_PORTS` or for the DNS block.

## 3. Tests to run on the gateway (owner, read-only)

1. **Daily upload test, 30 days, by /24 and port:**
   ```sh
   sudo tvgw sql "SELECT date(t_start,'unixepoch','localtime') d, rtrim(dst,'0123456789')||'0/24' net, dport, COUNT(*) n,
     SUM(MAX(0,bytes_up-40*pkts_up)) pu, SUM(MAX(0,bytes_down-40*pkts_down)) pd FROM flows
     WHERE proto='tcp' AND t_start >= strftime('%s','now','-30 days')
     GROUP BY d, net, dport HAVING pu >= 1000000 AND pu >= 4*pd AND n >= 24 ORDER BY pu DESC LIMIT 30"
   ```
   Name each `net` with `tvgw host` on an address in it. **False-positive rate** = flagged cells outside `Streaming`/`Infra`/`LG core` ÷ `SELECT COUNT(*) FROM (SELECT 1 FROM flows WHERE t_start >= strftime('%s','now','-30 days') GROUP BY date(t_start,'unixepoch','localtime'), rtrim(dst,'0123456789'), dport HAVING COUNT(*) >= 24)`. Expect 0, which gives a 95% upper bound of 3/denominator.
2. **Hourly twin, same window:** the same query with `strftime('%Y-%m-%d %H',t_start,'unixepoch','localtime')` as the bucket and `HAVING pu >= 500000 AND pu >= 4*pd AND n >= 5`. Expect hits only on streaming CDNs (out of scope). Any in-scope hit is a real finding to read with `tvgw host`.
3. **What 07's tests would have flagged** (to retire them on the CX's own evidence): `sudo tvgw report --json --since 30d | jq '[.beacons[] | select(.period>=10 and .period<=20)] | length'` should print 0. Then `sudo tvgw sql "SELECT dst, dport, COUNT(*) FROM flows WHERE t_end - t_start > 3600 + 7440 AND t_start >= strftime('%s','now','-30 days') GROUP BY 1,2 ORDER BY 3 DESC LIMIT 10"` should list only keep-alives of expected services.
4. **Port history**, §1.6.
5. **Blocked `alphonso.tv` rhythm**, §1.5.
6. **Hello on 4431 is named:** in the namespace harness (or on a laptop with tshark 4.4, the trixie version), run `tshark -r hello-4431.pcap -Y 'tls.handshake.type==1' -T fields -e tls.handshake.extensions_server_name`. It must print the name with no `-d` option.

## 4. Open questions

- **Does the CX's ACR client use 4431, and does it fall back to 443 after a reset?** Only a deliberate Live Plus-on run answers it, which this project should not do. The wall's counter and signal D are the passive substitutes.
- **Does webOS 5 run the 19-minute Alphonso control-plane timer with Live Plus off?** §1.5's query answers it. If it does, that series is the CX's best ACR-health indicator: a rate change after firmware is the alarm.
- **Do IMC's tables come from `print_most_contacted_domains.py`?** This is inferred from code. The cross-check makes any other unit unlikely. The authors can confirm (§1.3).
- **Ratio margin on other TVs.** The 4× ratio has a wide margin for LG's ACR (7-17×, port-keyed). Samsung and Vizio profiles (in flight) need their own check: *Watching the Watchers* reports Tizen and Vizio ACR shapes that this pass did not measure.
- **Partial-day stubs.** B' covers a stub with at least 500 KB in an hour. A shorter ACR blip (a firmware re-enabling ACR for minutes) would show only as signal D or A.

## Sources

Data and code read directly:

- *Watching the Watchers* data: [Zenodo 22733487 (`tkacr.csv`, published 2026-09-13)](https://zenodo.org/records/22733487), [Zenodo 22698120 (`merged_all.parquet`)](https://zenodo.org/records/22698120), CC BY-NC-ND 4.0; paper [PDF](https://watchingthewatchers.github.io/watchingthewatchers/paper.pdf) and [page](https://watchingthewatchers.github.io/watchingthewatchers/paper.html)
- IMC 2024: Anselmi, Vekaria et al., [arXiv 2409.06203](https://arxiv.org/html/2409.06203v1), [DOI 10.1145/3646547.3689013](https://doi.org/10.1145/3646547.3689013); code [SafeNetIoT/ACR](https://github.com/SafeNetIoT/ACR) (`experiment.sh`, `extract_csv_from_pcap.sh`, `print_most_contacted_domains.py`, commit `bdc56aa`)
- Wireshark TLS heuristic: [`epan/dissectors/packet-tls.c`](https://gitlab.com/wireshark/wireshark/-/blob/master/epan/dissectors/packet-tls.c)
- tvgw at `43b3bd9`: `src/tvgw/queries.py` (`beacons`, `ACR_PERIOD`, `acr_cadence`, red lines), `src/tvgw/analyst.py` (`novelty`), `src/tvgw/conntrack.py`, `src/tvgw/adguardcfg.py` (`blocking_mode`, `blocked_response_ttl`), `deploy/nftables/tvgw-apply` (`tv_out`), `deploy/systemd/tvgw-pcap.service` (capture filter), `src/tvgw/tshark.py`

Registries and vendor documentation:

- IANA service names and ports: [4001](https://www.iana.org/assignments/service-names-port-numbers/service-names-port-numbers.xhtml?search=4001), [4431](https://www.iana.org/assignments/service-names-port-numbers/service-names-port-numbers.xhtml?search=4431), [4445/4447](https://www.iana.org/assignments/service-names-port-numbers/service-names-port-numbers.xhtml?search=444), [8180](https://www.iana.org/assignments/service-names-port-numbers/service-names-port-numbers.xhtml?search=8180), [8883](https://www.iana.org/assignments/service-names-port-numbers/service-names-port-numbers.xhtml?search=8883)
- [AWS IoT Core: protocols, port mappings and authentication](https://docs.aws.amazon.com/iot/latest/developerguide/protocols.html)
- [Azure IoT Hub: MQTT (updated 2026-08-27)](https://learn.microsoft.com/en-us/azure/iot/iot-mqtt-connect-to-iot-hub)
- [AdGuard Home configuration (blocking modes, `blocked_response_ttl`)](https://github.com/AdguardTeam/AdGuardHome/wiki/Configuration)
- GeForce NOW ports, secondhand: [NVIDIA developer forum](https://forums.developer.nvidia.com/t/geforce-now-ip-for-firewall/302167), [PCGH forum](https://extreme.pcgameshardware.de/threads/geforcenow-qos-einstellungen-fuer-fritzbox-7530.648684/)

Earlier tvgw research this extends: [05](05-tv-privacy-research-2026.md), [07](07-measurement-and-presentation.md), [the October pass §5.1](../state-of-the-art-2026-10.md#51-beaconing-and-periodicity).
