# Deep dive 7: turning the store into judgments people can read

*Proposal, 2026-11-01. Nothing here is built. It reads `src/tvgw/queries.py` and the docs as they stand on the research worktree (head `43b3bd9`) and extends [the October survey](../state-of-the-art-2026-10.md), §5.1, §5.3 and moonshots A, B and E. Where it disagrees with that survey it says so in [Where this disagrees with the October survey](#where-this-disagrees-with-the-october-survey). Claims marked **(unverified)** rest on one secondary source or on background knowledge; **(computed)** marks arithmetic of mine on published numbers; **(test)** gives the exact check to run on the gateway later. Addresses and names of the owner's machines are written as placeholders (`GW_IP`, `TV_IP`, `<LAN_CIDR>`).*

## Bottom line

The store already holds what a per-TV privacy scorecard and an honest daily judgment need; what is missing is statistics that respect how a TV lives (on three or four hours a day, off the rest) and a way to say how sure the gateway is. Four things settle it. **(1) Measurement.** RITA's beacon score, which the October survey told us to copy, is four equally weighted parts, and two of them (duration and the 24-hour histogram) need at least 6 to 11 hours of activity a day, so they mark a TV's timers down by construction; keep only its timing and size halves, replace the rest with *coverage of the TV's awake hours*, and test periodicity on event times with a Rayleigh/Z² statistic against a null that shuffles events inside the awake hours, not with Lomb-Scargle. The ACR canary's `ACR_PAYLOAD = 4096` is likely too small for the uploads IMC 2024 measured during HDMI and antenna viewing (about 17 to 19 KB per 15-second contact, computed from its tables), and a blocked ACR client shows up only as DNS retries, so the canary needs a DNS-timing input. Upload anomalies are scored per name, per awake hour, against that name's own 28-day record, after a producer/consumer-ratio filter that drops downloads. A firmware download and a game night then never qualify. **(2) Uncertainty.** Every judgment in the brief uses one ICD 203 likelihood word or one confidence word, never both in a sentence. Every zero carries its exposure and a rule-of-three bound ("0 connections in 112 off-hours; at most 0.027 an hour, 95%"). Every daily set of per-name tests is controlled for false discoveries. **(3) The scorecard.** No 2026 label measures behaviour. The FCC Cyber Trust Mark has no labelled products yet. Singapore's CLS, Germany's BSI label (granted to Samsung's 2026 TVs) and the EU CRA are security declarations, and Finland closed its scheme on 2025-07-31. So tvgw's scorecard is the *observed* counterpart of the declared label: 18 fields, each computed from existing tables, each with a fixed verdict word, an exposure, a confidence and a pointer to the label attribute or standard clause it checks. There is no composite grade. The firmware behavioural diff is one of its sections. **(4) The share pack and the HTML.** The share pack may only name domains from a public vocabulary, at ISO-week granularity with log-bucketed counts, and leaves out the Streaming and Apps categories. The DAP standard is still a draft (DAP -20, waiting for write-up; VDAF -22 in IRSG poll), so the pack goes by hand. The brief becomes a static, script-free HTML page that `tvgw-analyze` writes beside the text brief and nginx serves read-only to the LAN, with four inline-SVG charts, each paired with a data table and a one-sentence takeaway.

## Contents

- [F1. Beacons with few samples on a device that is off most of the day](#f1-beacons-with-few-samples-on-a-device-that-is-off-most-of-the-day)
- [F2. Upload anomalies that survive a game night and a firmware download](#f2-upload-anomalies-that-survive-a-game-night-and-a-firmware-download)
- [F3. Standby and off baselines](#f3-standby-and-off-baselines)
- [F4. Drift: firmware windows and undated change](#f4-drift-firmware-windows-and-undated-change)
- [F5. Saying how sure the gateway is](#f5-saying-how-sure-the-gateway-is)
- [F6. Labels in 2026: what they declare and what nobody measures](#f6-labels-in-2026-what-they-declare-and-what-nobody-measures)
- [Settled: the scorecard specification](#settled-the-scorecard-specification)
- [F7. The local share pack](#f7-the-local-share-pack)
- [F8. How comparable projects present this kind of data](#f8-how-comparable-projects-present-this-kind-of-data)
- [Settled: the brief's HTML form](#settled-the-briefs-html-form)
- [Where this disagrees with the October survey](#where-this-disagrees-with-the-october-survey)
- [What to build here](#what-to-build-here)
- [Open questions](#open-questions)
- [Sources](#sources)

---

## F1. Beacons with few samples on a device that is off most of the day

### What the code does now

`queries.beacons()` takes each name's flow start times in the window, merges starts within `BURST_GAP = 5.0` s into one event, needs `BEACON_MIN = 12` events, and accepts the name when the median absolute deviation (MAD) of the intervals over their median is under `PERIODIC_JITTER = 0.15`, with the median interval in `PERIOD_RANGE = (10, 86400)` s. `acr_like` adds a period in `ACR_PERIOD = (10, 20)` s and a median payload under `ACR_PAYLOAD = 4096` bytes. That is the robust half of RITA's timing score, and it is sound for a fast timer on a TV that was on for a long session. It has four blind spots, each of which matters on this TV.

### What RITA v5 actually scores (read from its source)

The October survey left "RITA's exact weights unverified". They are in the source ([`analysis/beacons.go`](https://github.com/activecm/rita/blob/main/analysis/beacons.go), [`config/config.go`](https://github.com/activecm/rita/blob/main/config/config.go); latest release v5.1.2, dated 7 May, year not shown on the [releases page](https://github.com/activecm/rita/releases), 2026 inferred from the order of releases):

| Part | Computation in RITA | Default weight | Fits a TV? |
|---|---|---|---|
| Timestamp score | Mean of a Bowley-skew score `1 - \|(Q3+Q1-2Q2)/(Q3-Q1)\|` and a MAD score `(median - MAD)/median` over the intervals; needs at least 4 timestamps and 3 non-zero intervals | 0.25 | Yes |
| Data-size score | The same two scores over bytes per connection | 0.25 | Yes |
| Duration score | Zero unless the pair was seen in at least `DurationMinHoursSeen = 6` hourly bins; then the larger of span coverage and `longest consecutive run / 12 h` | 0.25 | **No**: a TV on 3 h a day scores 0 |
| Histogram score | Over 24 hourly bins of the span: the larger of `1 - CV` of all 24 bin heights, zeros included (0 when CV > 1), and a bimodal-fit score that needs `HistogramBimodalMinHoursSeen = 11` non-empty bars | 0.25 | **No**: 3 equal bars and 21 empty bins give CV = √7 ≈ 2.6, so 0 |

Thresholds: base 50, low 75, medium 90, high 100 on a 0-100 scale. RITA also adds `+15%` for a host first seen within 7 days, `-15%` after 30 days, and `+15%` for a domain queried with no direct connection ("C2 over DNS").

**Consequence for tvgw** **(computed)**. A timer that runs only during a 3-hour evening scores 0 on duration and 0 on histogram, so its beacon score is capped at 0.5, RITA's lowest threshold (base 50), however perfect its timing and size. Adopt the timing and size halves, which `beacons()` mostly has. Drop duration and histogram. Replace them with a term that is about the TV: **awake coverage**, the fraction of awake hours in the window in which the name had at least one event. A timer that fires in 11 of 12 awake hours is a timer of the TV; one that fired in 1 of 12 is something the viewer did. RITA's "queried but never connected" bonus is worth copying as a separate signal. On a filtered TV it is the normal state of a blocked client, which is the next point.

### Blind spot 1: a blocked client has no flows, only lookups

A name that AdGuard blocks gets no connection, so it never reaches `beacons()`, but its client keeps its timer and retries the lookup. The brief's "Blocked and still retried" section counts those retries; nothing measures their rhythm. Lookups are a second event series per name, and for blocked telemetry they are the only one. Two things shape that series. AdGuard answers blocked names with a 60-second TTL (`blocked_response_ttl = 60` in `src/tvgw/adguardcfg.py`), so a client that honours TTLs cannot look up faster than once a minute: a 15-second ACR timer would show as about 60-second lookups (unverified for webOS's resolver cache). And a client that backs off on failure stretches its intervals, which shows as a rising period, not jitter.

**(test)** The rhythm of the TV's lookups of a blocked name over a week, in 10-second bins:

```sh
sudo tvgw sql "WITH e AS (SELECT t, LAG(t) OVER (PARTITION BY qname ORDER BY t) p FROM dns
  WHERE blocked=1 AND qname LIKE '%alphonso.tv' AND t >= strftime('%s','now','-7 days'))
  SELECT CAST((t-p)/10 AS INT)*10 AS gap_s, COUNT(*) n FROM e
  WHERE p IS NOT NULL AND t-p < 3600 GROUP BY 1 ORDER BY n DESC LIMIT 10"
```

A dominant bin at 60 to 70 s means the TTL floor is shaping it. A dominant bin elsewhere is the client's own retry timer.

### Blind spot 2: missed beats and kept-alive connections

`beacons()` sees a beat only when the client opens a new connection. A client that reuses a kept-alive TLS connection sends several beats in one flow, and the flow-start series shows intervals of 2P, 3P and so on. The MAD/median test fails once about a quarter of the beats are missing, because the median interval itself moves. A client that holds one connection open for the whole session shows no beats at all, only one long flow whose upload grows steadily. RITA treats that as a separate class, "long connections", with thresholds at 1, 4, 8 and 12 hours (`LongConnectionScoreThresholds` in `config.go`). tvgw has the inputs for the same check: `flows.t_start`, `t_end` and `bytes_up`. One caveat is that `t_end` includes the 7440-second idle timeout ([naming a connection](../../how-it-works/architecture.md#naming-a-connection)).

### Blind spot 3: period detection on event times

The October survey proposed Lomb-Scargle as a confirming step. Lomb-Scargle is built for sampled values at uneven times. Its false-alarm machinery (Baluev's approximation, astropy's default) is computed "relative to a particular set of observing times" and assumes a noise model for the values. astropy's own documentation warns that the false-alarm probability "say[s] nothing quantitative about whether the data are actually consistent with a periodic model" and recommends bootstrap where it is affordable ([astropy LombScargle](https://docs.astropy.org/en/stable/timeseries/lombscargle.html)). tvgw has arrival times, not samples. The tool high-energy astronomy uses for arrival times is the Rayleigh test and its multi-harmonic form Z²ₙ (Buccheri et al. 1983, unverified citation details):

```
phi_j = 2*pi*t_j / P            for each event time t_j and trial period P
Z2_n(P) = (2/N) * sum_{k=1..n} [ (sum_j cos(k*phi_j))^2 + (sum_j sin(k*phi_j))^2 ]
```

Phase coherence is what it measures, so a missed beat costs one term and does not move the period estimate. Long gaps when the TV is off do not matter either, which fixes blind spot 2 for the flow series. Belanger showed that the classical statistics' components become correlated when the span is not a whole number of cycles, and recommends modified forms for all event data ([Belanger 2016, ApJ 822:14](https://arxiv.org/abs/1712.00734)). For tvgw the practical answer is to calibrate empirically. Asymptotic χ² tables are unreliable with tens of events, so build the null from the TV's own exposure:

1. Take the name's events in the window, after the `BURST_GAP` merge.
2. Compute `Zmax = max over the period grid of Z2_2(P)`. Search 0.9× to 1.1× the median interval and its halves and doubles, 200 trial periods in all.
3. Repeat 199 times with the same number of events placed uniformly at random **inside the awake intervals** (the `tvstate` runs `queries` already builds), recomputing `Zmax` over the same grid each time. This charges the search over periods to the statistic (the look-elsewhere effect), and it means a cluster of events in the evening is not mistaken for a period.
4. `p = (1 + #{null Zmax >= observed}) / 200`.

This is pure Python. The cost is N × 200 × 200 trigonometric pairs, 2 million for N = 50: about a second per candidate name on a Pi 5 (unverified timing). Run it only for names the MAD screen or the DNS screen flags, at most 20 a day.

### Blind spot 4: a daily window cannot see slow timers on a TV that is on three hours

With `BEACON_MIN = 12` events, a timer that fires only while the TV is awake for A hours is detectable in one day only if its period is at most `A × 3600 / 12` seconds **(computed)**:

| Awake hours in the window | Longest detectable period |
|---|---|
| 3 h (one evening) | 900 s (15 min) |
| 6 h | 1800 s |
| 21 h (a week of evenings) | 6300 s (1 h 45 min) |
| 24 h (a timer that also runs while off) | 7200 s |

So an hourly telemetry upload that runs only while the TV is on can never be found by a daily brief. **Pool**: run the screen on the trailing 7 days for periods above `A × 3600 / 12` and report it in the daily brief as "weekly evidence", with its window stated.

### The ACR canary, checked against the numbers it was built from

IMC 2024 measured LG's US ACR endpoint (`tkacrX.alphonso.tv`) over one-hour experiments ([Anselmi et al., Tables 2 and 4](https://arxiv.org/html/2409.06203v1)). It reports contacts every 15 s, and in the US logged-in, opted-in phase, about 4583 KB in the antenna scenario, 4125 KB on HDMI and 4948 KB on FAST channels, against about 215 KB idle and on OTT. Read as KB per hour, which is how I read the tables (the paper does not label the unit per hour), 240 contacts an hour gives **(computed)** about 17 to 19 KB per contact while fingerprinting and about 0.9 KB per contact as a keep-alive. `ACR_PAYLOAD = 4096` therefore marks the idle heartbeat and misses the fingerprint uploads, which are the case the owner cares about. That holds if each contact is its own connection. If it is one kept-alive connection, the flow series sees no cadence at all (blind spot 2).

**Change.** Mark `acr_like` on period alone (10 to 20 s, from either the flow series or the DNS series) for a name outside `expected_categories`. Keep payload as a displayed attribute, not a gate. Add a long-connection ACR check: a flow to a name outside `expected_categories` lasting over 1 h whose `payload_bound / (t_end - t_start - 7440)` falls between 0.5 and 40 KB a minute (the idle and fingerprinting rates above). With Live Plus off and `alphonso.tv` blocked, all of this should stay silent. Its value is a firmware update that brings a new ACR host or turns Live Plus back on, the case the Texas settlement makes plausible ([October survey §6.3](../state-of-the-art-2026-10.md#63-regulation)).

### Specification: beacon screen v3

| Constant | Value | Why |
|---|---|---|
| `BURST_GAP` | 5.0 s (unchanged) | A page load is one event |
| `BEACON_MIN` | 12 events (unchanged) | Below this, MAD and Z² are noise |
| `PERIODIC_JITTER` | 0.15 (unchanged), as a screen only | Fast first pass |
| `Z_HARMONICS` | 2 | Z²₂ tolerates a non-sinusoidal duty cycle |
| `Z_PERMS` | 199 | Smallest reportable p is 0.005 |
| `Z_GRID` | 200 periods, 0.45× to 2.2× the median interval | Covers halves and doubles for missed beats |
| `AWAKE_COVERAGE_MIN` | 0.6 | The name has events in at least 60% of awake hours |
| `FDR_Q` | 0.10 | Benjamini-Hochberg across the day's tested names (F5) |
| Event series | Flow starts **and** lookups (allowed and blocked), scored apart | Blocked clients only show in DNS |
| Window | The day for `P <= A*3600/12`; else the trailing 7 days | Blind spot 4 |

Each finding prints its period, p, awake coverage, the series it came from (`flows` or `dns`) and its window. **(test)** Unit-test with three synthetic series: a 15 s timer with 40% of beats removed, which v3 must find and MAD/median must miss; a Poisson stream at the same rate, which must not pass (p > 0.1 in 95 of 100 seeds); and a 20-minute timer seen over 7 evenings of 3 hours, which the weekly pool must find and the daily window must not.

## F2. Upload anomalies that survive a game night and a firmware download

The brief's Top upload is a ranking, not a judgment: it says who sent most, not whether that is unusual. Three ordinary events make a raw "upload went up" test fire. A **firmware or app download** sends hundreds of MB down and, through ACKs, tens of MB "up" (the October survey's 550 MB of ACKs on a 40 GB day). A **game night** on GeForce NOW (`nvidiagrid.net` is in the profile's Streaming category) sends controller input up for hours. A **long viewing day** sends more of everything. The scorer below is built so that none of these qualify.

1. **Scope.** Score only names outside `expected_categories` plus the `Unresolved` bucket. Game streaming and video CDNs are expected; their bytes are the TV doing its job.
2. **Payload, both ways.** `up = Σ max(0, bytes_up − 40·pkts_up)` and `down = Σ max(0, bytes_down − 40·pkts_down)` per name per day. This is the existing `payload_bound()`, applied in both directions.
3. **Direction filter: the producer/consumer ratio.** `PCR = (up − down) / (up + down)`, from −1 (pure download) to +1 (pure upload) (Bullard and Gerth, FloCon 2014; the formula as relayed by a [threat-hunting note](https://github.com/w8mej/ThreatPlays/blob/master/analyze_producer_consumer_ratio.md) and the [FloCon 2014 proceedings](https://www.cert.org/flocon/2014/proceedings-2014.html); the original slides were not read). A download sits near −1 and is dropped. Score a name only when `PCR > −0.5` or `up > 1 MiB`.
4. **Exposure.** Divide by awake hours that day (at least 1), so a long viewing day is not an anomaly.
5. **The name's own record.** Over the trailing 28 days, take the daily rates `r_d = up_d / awake_d` on days with at least 1 awake hour. Flag today when all three hold:
   - `up_today > 256 KiB` (an absolute floor, so tiny names never flag);
   - `up_today > 2 × max(up_d)` over the 28 days (a record day by a clear margin, which anyone can check);
   - `(log1p(r_today) − median(log1p r)) / (1.4826 · MAD(log1p r)) > 4` (robust z on the log scale; when the MAD is 0, use the record rule alone).
6. **New names** have no record. They are reported under New hosts with their absolute payload bound, never as anomalies.

The sentence it prints: `unagi-na.amazon.com: up to 3.1 MiB in 4.0 awake hours, 2.4× its largest day in 28 days (PCR +0.82)`. The numbers are illustrative.

**(test)** That downloads sit near PCR −1 and telemetry above 0, by address, over two weeks, on the gateway:

```sh
sudo tvgw sql "SELECT date(t_start,'unixepoch','localtime') d, dst,
  SUM(MAX(0,bytes_up-40*pkts_up)) up, SUM(MAX(0,bytes_down-40*pkts_down)) down,
  ROUND(1.0*(SUM(MAX(0,bytes_up-40*pkts_up))-SUM(MAX(0,bytes_down-40*pkts_down)))
       /(SUM(MAX(0,bytes_up-40*pkts_up))+SUM(MAX(0,bytes_down-40*pkts_down))+1),2) pcr
  FROM flows WHERE t_start >= strftime('%s','now','-14 days')
  GROUP BY d, dst HAVING up+down > 1048576 ORDER BY d, up DESC"
```

Expect CDN addresses near −0.99. Expect the blocked-now Prime Video telemetry host's address from 2026-10-25 (before its block) far above −0.5. If a firmware day shows a CDN address above −0.5, the header correction is too small: TCP timestamps make a pure ACK 52 bytes, not 40, and the threshold must move.

## F3. Standby and off baselines

The brief's "While off/asleep" line counts lookups, connections and bytes in off hours. Three changes turn it into a baseline and a judgment.

**A zero needs its exposure.** When nothing happens in H hours, the 95% one-sided upper bound on the hourly rate is `−ln(0.05)/H ≈ 3/H`, the rule of three ([Hanley and Lippman-Hand, JAMA 1983;249:1743](https://pubmed.ncbi.nlm.nih.gov/6827763/)). It treats off hours as independent exposure, which is an approximation. For k > 0 events, use the exact Poisson (Garwood) interval: lower `= ½·χ²(0.025; 2k)` and upper `= ½·χ²(0.975; 2k+2)`, divided by H. A pure-Python bisection on the Poisson CDF (`math.lgamma`) computes it without SciPy. The line becomes:

```text
While off/asleep (112 h): 0 connections (at most 0.027/h, 95%); 14 lookups of 2 names (0.07 to 0.21/h)
```

**A new name while off is the strongest single signal the gateway has.** Nobody pressed anything. Keep a set of names seen in off hours over the trailing 28 days, with each name's off-hour rate. A name outside that set, in an off hour, goes to the top of the TV section, and to the scorecard's field C2 (below).

**Off-hour activity has a clock.** Firmware checks and telemetry flushes tend to run at fixed local times. For each off-hour name, print the hour-of-day histogram over 28 days (24 numbers), which shows "every night at 03:xx" at a glance.

**The classification is only as good as the hourly reading.** An off interval is two consecutive non-awake readings at most `STANDBY_GAP = 5400` s apart, so up to an hour at each edge can be misclassified. Do not count the first and last 10 minutes of an off interval as off. The longer-term fix is an SSAP power-state subscription (October survey §5.3), which is outside this pass. **(test)** `sudo tvgw sql "SELECT power, COUNT(*) FROM tvstate WHERE t >= strftime('%s','now','-28 days') GROUP BY power"` gives the mix of readings. If `Active Standby` (network kept up while off) is absent, Quick Start+ is off and the off baseline is the TV fully asleep. That is worth stating on the scorecard, because it changes what "off" means.

## F4. Drift: firmware windows and undated change

Two kinds of change matter. **Firmware updates** are dated by the `tvsettings` key `firmware`. **Undated changes** have no date. On the CX, LG's file service delivers the telemetry schedule and the ACR configuration as files ([README findings](../../tv/lg-cx-measured.md)), so behaviour can change with no firmware change. App updates are a third source, as the Prime Video update of 2026-10-25 showed. The literature says before-and-after studies of IoT firmware are rare: a 2024 survey lists the effect of updates on traffic as under-researched ([arXiv 2403.16149](https://arxiv.org/pdf/2403.16149)). The Blocking-without-Breaking authors saw no destination change in six months but expect it over longer periods ([Mandalari et al., PoPETs 2021](https://arxiv.org/pdf/2105.05162)). A 2026 profiling paper finds that static models degrade on data from outside their training period ([arXiv 2602.24047](https://arxiv.org/pdf/2602.24047)). Nobody publishes a behavioural diff for TVs, and the gateway can.

**Comparing rates fairly.** For one name, with k₁ events in E₁ awake hours before and k₂ in E₂ after, equal rates imply `k₂ | (k₁+k₂) ~ Binomial(k₁+k₂, E₂/(E₁+E₂))`. That is the exact conditional test for two Poisson rates. It needs no SciPy and is valid for small counts. Report the rate ratio `(k₂/E₂)/(k₁/E₁)` with its two-sided p.

**A name has vanished** only if the old rate predicted it. With a pre-update rate λ per awake hour and E₂ awake hours after, `P(0 events) = exp(−λ·E₂)`. Call the name gone only when `λ·E₂ ≥ 3` (p ≤ 0.05). Before that, say "not seen yet (expected about λ·E₂ by now)".

**Many names, one day.** About 300 names are tested each week. At p < 0.05 each, about 15 would "change" by chance. Apply Benjamini-Hochberg at q = 0.10 across the names tested in one comparison ([Benjamini and Hochberg 1995](https://doi.org/10.1111/j.2517-6161.1995.tb02031.x)). Test only names with expected count `(k₁+k₂)·E₂/(E₁+E₂) ≥ 5`. The rest are described, not tested.

**Undated drift, weekly.** In `tvgw report --week`, compare the last 7 days with the 28 before, per name, with the same test and FDR. Print the names that changed with their rate ratio. Bayesian online change-point detection ([Adams and MacKay 2007](https://arxiv.org/abs/0710.3742)) or PELT ([`ruptures`](https://github.com/deepcharles/ruptures), whose 1.1.10 release of 2025-09 needs NumPy and Python below 3.14) would date a change. A weekly two-window test is enough to notice one, adds no dependency, and its output can be explained in one sentence. Keep change-point dating as an open question.

The firmware diff that uses these tests is specified as section E of the scorecard below.

## F5. Saying how sure the gateway is

The brief already separates "not assessed" from "zero" (design decision 14). The next step borrows from a discipline that has written down how to state uncertainty to readers who will act on it: US intelligence analytic standards, [ICD 203](https://archive.dni.gov/files/documents/ICD/ICD-203.pdf) (signed 2015-01-02, amended 2022 and 2023). The parts that fit a daily brief:

- **One likelihood scale, fixed:** almost no chance (1-5%), very unlikely (5-20%), unlikely (20-45%), roughly even chance (45-55%), likely (55-80%), very likely (80-95%), almost certain (95-99%). ICD 203 says not to mix this row with its alternative wording.
- **Confidence is separate from likelihood.** A product "must not combine a confidence level and a degree of likelihood ... in the same sentence".
- **Distinguish information from judgment.** State the assumptions a judgment rests on, and the indicators that would change it.
- **Recurrent products note changes only.** "Recurrent products such as daily crisis reports should note any changes in judgments; absent changes, recurrent products need not confirm consistency." This matches the owner's rule that a quiet day costs nothing.

**How tvgw maps it.** Measured facts (counts, bytes, bounds) are printed as numbers, never as likelihood words. Judgments (a name is telemetry, a block will not break playback, a timer is ACR) get a likelihood word chosen by a rule, never by the model's adjectives. Confidence is computed from the evidence base:

| Confidence | All of |
|---|---|
| High | Every source the judgment uses was assessed for at least 95% of the window's awake hours; exposure at least 10 awake hours (or 50 events); no ingest warning about those sources |
| Moderate | Sources assessed for at least 75% of awake hours; exposure at least 3 awake hours (or 12 events) |
| Low | Anything less, or the judgment rests on one source that has a known blind spot (ECH, a kept-alive connection, a missed pcap) |

A judgment block in the brief:

```text
JUDGMENT  rdx2.lgtvsdp.com is telemetry on a timer: very likely.
  Basis   dns: 41 blocked lookups, period 300 s (p = 0.005, Z2 test, 3 awake h); flows: none (blocked).
  Confidence  moderate: 3 awake hours; pcaps and dns assessed all day.
  Would change  a flow to it while blocked (rule not holding); a period change after firmware.
  Changed since yesterday  new (first judged today).
```

(The example values are illustrative.) When nothing changed, the block is not printed. A line under the header says `Judgments unchanged since <day>: 7`.

**Late evidence is part of the uncertainty.** A day's file is written at 03:20 the next day, while flows keep landing for up to 7440 s after their last packet. The brief can say how provisional it is from its own history. **(test)** The share of each day's flows reported after the next 03:20:

```sh
sudo tvgw sql "SELECT date(t_start,'unixepoch','localtime') d, COUNT(*) n,
  SUM(t_end > CAST(strftime('%s', date(t_start,'unixepoch','localtime','+1 day'),'utc') AS REAL) + 12000) late
  FROM flows WHERE t_start >= strftime('%s','now','-14 days') GROUP BY d"
```

If `late/n` is reliably under 1%, the archived file can say so. If not, the HTML (below) should be regenerated after 06:00 as well.

**What never to do.** No percentages of confidence ("87% sure"). No colour as the only carrier of a judgment. No composite "privacy score". No sentence that converts "not assessed" into "fine".

## F6. Labels in 2026: what they declare and what nobody measures

| Scheme | State in 2026 | What it covers | Measures behaviour? |
|---|---|---|---|
| US Cyber Trust Mark (FCC) | UL Solutions withdrew as lead administrator on 2025-12-19 after an FCC national-security review; the FCC reopened applications in January 2026 and picked ioXt in April ([Cybersecurity Dive](https://www.cybersecuritydive.com/news/fcc-cyber-trust-mark-iot-labeling-ul-withdraw/808732/), [Broadband Breakfast](https://broadbandbreakfast.com/fcc-picks-ioxt-alliance-to-head-cyber-trust-mark-program/)). On 2026-10-28 no product carried the mark; technical requirements, lab accreditation and the registry are still pending ([Nextgov](https://www.nextgov.com/cybersecurity/2026/10/fcc-commissioner-hopes-cyber-trust-mark-products-reach-shoppers-within-year/416878/)) | Security. Registry fields include the support period, whether updates are automatic, and default-password instructions (per a law-firm summary of the 2024 order, [Pillsbury](https://pillsburylaw.com/en/news-and-insights/fcc-iot-labeling-program.html); the order itself not read) | No |
| Singapore CLS | Live, levels 1 to 4. Mutual recognition with Japan's JC-STAR took effect 2026-06-01; the other partners are Finland, Germany, South Korea and the UK ([CSA, 2026-03-18](https://www.csa.gov.sg/news-events/press-releases/singapore-signs-memorandum-of-cooperation-with-japan-on-mutual-recognition-of-internet-of-things-cybersecurity-schemes/)) | Security, based on ETSI EN 303 645 | No |
| Finland (Traficom) | **Discontinued 2025-07-31** (same CSA release) | Security | No |
| Germany, BSI IT-Sicherheitskennzeichen | Live. Samsung's whole 2026 TV line-up was granted it, valid to 2031-06-29 ([Samsung DE, 2026-07-29](https://news.samsung.com/de/mehr-transparenz-beim-tv-kauf-samsung-smart-tv-line-up-erhalt-erneut-it-sicherheitskennzeichen-des-bsi)). The BSI positions it as preparation for the CRA ([BSI](https://www.bsi.bund.de/dok/sik-cra_en)) | A manufacturer declaration against EN 303 645 plus BSI product requirements | No |
| EU Cyber Resilience Act | Reporting duties since 2026-09-11, full obligations from 2027-12-11 (October survey §6.3). CE marking, no consumer label | Annex I Part I (2): (c) security updates, (e) confidentiality of data in transit, (g) **data minimisation**, (j) limited attack surface, (m) removing all data ([Annex I text](https://streamlex.eu/annexes/cra-en-annex-i/)) | No, but (e) and (g) are things a gateway can observe failing |
| ETSI EN 303 645 V3.1.3 (2024-09) | The baseline under CLS, the BSI label and the CRA guidance | 5.5-1 secure communication; 6-3A withdraw consent at any time; **6-4** telemetry processing limited to what the stated function needs; **6-5** consumers told what telemetry is collected, by whom and why. Its annex uses a smart TV with a device telemetry service as the worked example ([ETSI PDF](https://www.etsi.org/deliver/etsi_en/303600_303699/303645/03.01.03_60/en_303645v030103p.pdf)) | No |
| Consumer Reports Digital Standard | TV privacy sub-scores since the 2019 models ([CR Innovation](https://innovation.consumerreports.org/smart-tvs-a-digital-standard-case-study/)); no 2025-26 TV scorecard found | Policy review plus lab tests | Partly, in a lab |
| RTINGS ACR testing | 2026 captures on a Samsung S95F, Sony Bravia 8 II and LG G5: turning ACR off generally stopped the ACR traffic it could identify ([RTINGS](https://www.rtings.com/tv/learn/research/smart-tv-tracking), as relayed by a search summary; the page did not render for me) | ACR only | Yes, in a lab, one firmware |
| Academic | The CMU IoT label (Emami-Naeini et al., IEEE S&P 2020): a primary layer (data types, purpose, who data is shared with or sold to, update policy, firmware date and version) and a secondary layer (data-collection frequency, frequency of sharing, whether the device works offline or with smart features off, user controls) ([arXiv 2002.04631](https://ar5iv.labs.arxiv.org/html/2002.04631)). Lalaine checked 5,102 iOS apps' privacy labels against observed behaviour and flagged 3,423 non-compliances, typed as contrary, inadequate or neglected disclosure ([USENIX Security 2023](https://www.usenix.org/conference/usenixsecurity23/presentation/xiaoyue)) | Declared practice | Lalaine does, for apps |

**What follows for tvgw.** Every 2026 scheme is a declaration made at sale. None says what a particular TV did last week in a particular home, with a particular set of settings. Lalaine shows the useful form: put a declared attribute next to an observed one and type the mismatch. The CMU label's secondary layer names three attributes a gateway can observe directly and a manufacturer rarely discloses: data-collection frequency, frequency of sharing, and behaviour when smart features are off. EN 303 645 6-4 and CRA (g) give the normative hook ("limited to what is necessary"), and CRA (e) gives the hook for plaintext traffic. The scorecard below is built around those fields.

## Settled: the scorecard specification

`tvgw scorecard --week WEEK [--json|--html]` and `tvgw scorecard --firmware VERSION` read the store read-only, like `tvgw report`. They are written weekly by `tvgw-analyze` to `reports/scorecard/<week>.{txt,json,html}`.

**Rules for every field.**

1. **A fixed verdict word**, one of `none observed`, `attempted, contained`, `reached`, `changed`, `unchanged`, `not assessed`, or `—` for a descriptive field. No grade and no composite score: a composite's weights are arbitrary (RITA's are 0.25 each, F1), and it hides a `not assessed` inside a number.
2. **A value with its exposure**: awake hours, off hours, or events, and a 95% bound for any rate (F3).
3. **A confidence word** from the F5 table. It is never a likelihood word: fields are measurements.
4. **A basis**: the tables and the sources' coverage.
5. **A mapping** to the label attribute or clause it is the observed counterpart of. It says what is compared, not that anything is compliant.
6. **A change marker** against the previous week (ICD 203: note changes).

The **primary layer**, one screen, holds A1, A2, B3, B4, C1, D1, D2, E1 and Q1. The rest is the secondary layer, following the CMU two-layer design.

### A. Consent and settings

| Field | Question | Computation from the store | Verdict rule | Observed counterpart of |
|---|---|---|---|---|
| A1 | Is the ACR opt-out holding? | Last `tvsettings` value of `ACR_KEY` before the window's end; `dns` rows whose name is in category `ACR`, split by `blocked`; flows named in `ACR` (`FLOW_NAME`); beacon v3 `acr_like` findings from either series | `none observed` with no ACR lookups; `attempted, contained` with lookups that were all blocked and no flows; `reached` with any allowed lookup or any flow; `not assessed` if `dns` was not assessed or Live Plus has no reading | CMU "user controls"; EN 303 645 6-3A; CRA (g) |
| A2 | Is the declined voice agreement holding? | The same over category `Voice` | Same words | CMU "user controls"; EN 303 645 6-2 |
| A3 | Did a privacy setting change? | `tvsettings` rows in the window for the profile's `[[privacy_setting]]` keys (profiles v2, in flight), with time and the firmware reading before | `unchanged` / `changed` (each key, old to new) / `not assessed` | EN 303 645 6-3B |

### B. Who it talks to while in use

| Field | Question | Computation | Verdict rule | Counterpart |
|---|---|---|---|---|
| B1 | Which parties did it contact? | Distinct registrable domains in `dns` (allowed and blocked) by profile category, grouped by organization: a profile-side `org` per category entry. DuckDuckGo's Tracker Radar entity map is CC BY-NC-SA 4.0 ([repo](https://github.com/duckduckgo/tracker-radar)), so cite it and do not merge it | `—` (descriptive): N organizations, M of them third parties, K blocked | CMU "who data is shared with"; EN 303 645 6-5 |
| B2 | How often does it try to reach telemetry, ads and ACR? | Lookups per awake hour of names in non-expected categories, with blocked share | `none observed` / `attempted, contained` (blocked share 100%) / `reached` | CMU "frequency of data sharing" |
| B3 | What runs on a timer? | Beacon v3 findings (F1) outside `expected_categories`: name, period, series, p, awake coverage | `none observed` / list with verdict per name | CMU "data-collection frequency" |
| B4 | How much did it send to parties that are not the service? | Σ `payload_bound` up for non-expected names plus `Unresolved`, per awake hour, as a range from 0 to the bound; the F2 anomalies | `none observed` (0 bytes) / `reached` with the range | EN 303 645 6-4; CRA (g) |

### C. When not in use

| Field | Question | Computation | Verdict rule | Counterpart |
|---|---|---|---|---|
| C1 | Does it talk while off? | `queries` off intervals (trimmed 10 min at each end, F3); lookups, connections and payload up in them; Garwood or rule-of-three bounds per off hour; whether any `Active Standby` reading exists (Quick Start+) | `none observed` with its bound / `reached` with names and the hour-of-day clock | CMU "works when smart features are off" |
| C2 | Did a new name appear while off? | Names in off hours absent from the 28-day off-hour set | `none observed` / list | none (nobody declares this) |

### D. Network conduct

| Field | Question | Computation | Verdict rule | Counterpart |
|---|---|---|---|---|
| D1 | Does anything go out unencrypted? | `http` rows to public hosts outside the URL filter's hosts; distinct hosts; query-parameter *names* matching `(?i)^(mac\|serial\|duid\|device_?id\|uuid\|udid\|ifa\|adid)$`, with keys only and never values | `none observed` / `reached` (hosts, and whether identifier-named keys appeared) | CRA (e); EN 303 645 5.5-1 |
| D2 | Does it try to get around the resolver? | Flows to port 53 not at `GW_IP`; `fw_counters` for `DNS forced to AdGuard`, `DoT/DoQ`, `DoH` and `QUIC`; `gate_unexplained` samples | `none observed` / `attempted, contained` (all redirected or rejected) / `reached` (a gate sample with no explanation is a connection that left) | none |
| D3 | Does it survey the home network? | `lanprobe` distinct address and port pairs; private PTR lookups; the `LAN` counter | `none observed` / `attempted, contained` | CRA (j), indirectly |
| D4 | How much can the gateway see? | Real ECH hellos (`ech_seen()`), the `IPv6` and `odd ports` counters, the share of bytes in `Unresolved` | `—` (descriptive). ECH helps the user against the ISP, so it is not scored as bad | none |

### E. Maintenance

| Field | Question | Computation | Verdict rule | Counterpart |
|---|---|---|---|---|
| E1 | Which firmware, since when? | Latest `tvsettings` `firmware` value, its first reading, days since the previous change; the `LG 8080 fallback` counter and the URL filter's 200s in the window | `—` (descriptive), plus `changed` in an update week | CMU "date and version of the latest firmware"; CRA (c) |
| E2 | What changed with the last firmware? | The behavioural diff below | `unchanged` / `changed` / `provisional` | none: nobody publishes this |

### R, Q. Cost of control and quality of evidence

| Field | Question | Computation | Verdict rule |
|---|---|---|---|
| R1 | What does controlling it cost, and did the controls hold? | Rules in force by kind (`rules` with `removed_at IS NULL`); machine rules `passed` and `reverted` (`auto_rules`); must-allow names; red lines 1, 3 and 4 in the window; blocked names still reached over TLS; the profile's dated breakage notes. The gateway cannot measure breakage itself, only reverts, red lines and the owner's notes, and the field says so | `held` / `not held` (any blocked name reached, any must-allow blocked) |
| Q1 | How complete is the evidence? | Share of awake hours in which every source was assessed; days with ingest warnings; `verify` runs owed and recorded; flow-logger lost events (`ENOBUFS` warnings); pcaps that failed | `—`, with the confidence word it implies for every other field |
| Q2 | How much was there to see? | Awake hours, off hours, days with data, and the firmware(s) in the window | `—` |

### Section E2: the firmware behavioural diff (moonshot B)

Triggered by a change of the `tvsettings` key `firmware`. Let `t₀` be the first reading of the new version, less 1 h (the hourly reading lags the update, as `firmware_changes()` already assumes).

- **Windows.** *Before* is from the later of `t₀ − 28 d` and the previous firmware's first reading, to `t₀`. *After* is from `t₀` to `t₀ + 28 d`. The diff is marked `provisional` until both windows hold at least 10 awake hours, and it is recomputed weekly until `t₀ + 28 d`.
- **New names**: `hosts.first_seen` in *after*, with category, state and `new domain`. This is what the brief's Firmware section prints today.
- **Gone names**: names with `λ_before · E_after ≥ 3` and no event in *after* (F4). Fewer expected events print as "not seen yet".
- **Rate changes**: the exact conditional test per name on lookups and on flows, Benjamini-Hochberg at q = 0.10, only for names with at least 5 expected events. Print the rate ratio with its p.
- **Timer changes**: beacon v3 findings that appear, disappear, or change period by more than 10%.
- **Conduct changes**: D1 to D3 before and after: new plaintext hosts, new odd ports, new LAN-probe ports, resolver bypass, unexplained gate samples, real ECH.
- **Settings**: any `tvsettings` change within 72 h of `t₀`. A Live Plus reset is already red line 2. The diff repeats it, because a reset is the most likely visible effect of LG's 2026 Texas settlement (October survey §6.3).
- **TLS stack**: new and gone JA4 values per name, once the hardened extractor (in flight) stores them.
- **Confounders**, printed with the diff and never hidden: rule changes in either window (`rules`), machine rules (`auto_rules`), app-package downloads through the URL filter, and other firmware readings. The diff says "changed across the update", never "changed because of it". The CX's file service delivers configuration too (F4).

**(test)** On the gateway, the firmware history the diff will start from:

```sh
sudo tvgw sql "SELECT value, datetime(MIN(t),'unixepoch','localtime') first, datetime(MAX(t),'unixepoch','localtime') last, COUNT(*) FROM tvsettings WHERE key='firmware' GROUP BY value ORDER BY MIN(t)"
```

In CI, a fixture with two firmware values 14 days apart, one name that triples its rate, one that vanishes with λE₂ = 6, and one with λE₂ = 1. The diff must report the first as changed (q < 0.1), the second as gone and the third as "not seen yet".

### JSON shape

```json
{
  "schema": "tvgw-scorecard/1",
  "window": {"week": "2026-W44", "awake_h": 21.0, "off_h": 147.0, "firmware": ["04.64.xx"]},
  "fields": [
    {"id": "C1", "question": "Does it talk while off?", "verdict": "none observed",
     "value": {"connections": 0, "off_hours": 147.0, "rate_upper_95_per_h": 0.020},
     "confidence": "high", "basis": {"sources": ["tvstate", "flows", "dns"], "assessed_share": 0.99},
     "maps": ["CMU label, secondary layer: works when smart features are off"],
     "change": "unchanged"}
  ],
  "firmware_diff": null
}
```

(The values are illustrative.) The `.txt` form prints one line per field, `C1  none observed  0 connections in 147 off-hours (≤0.020/h)  [high]`, so the scorecard reads in a terminal as well as in the HTML.

## F7. The local share pack

**The state of the art in 2026.**

- **k-anonymity at web scale was retired.** Chrome's Protected Audience required an ad to be seen by k = 50 users over 30 days ([Privacy Sandbox docs](https://privacysandbox.google.com/relevance/protected-audience-api/k-anonymity)). After Chrome kept third-party cookies, the API was deprecated in Chrome 144, with removal planned for Chrome 150 ([blink-dev intent](https://groups.google.com/a/chromium.org/g/blink-dev/c/k_nubsMb97g)).
- **DAP is still a draft.** draft-ietf-ppm-dap is at -20 (2026-10-20), "WG Consensus: Waiting for Write-Up". taskprov has expired ([PPM WG documents](https://datatracker.ietf.org/wg/ppm/documents/)). VDAF, which defines Prio3, is at -22 (2026-08-14) and in IRSG poll ([draft-irtf-cfrg-vdaf](https://datatracker.ietf.org/doc/draft-irtf-cfrg-vdaf/)). Mastic, the weighted heavy-hitters VDAF that would let a collector *discover* new names privately, is an expired individual draft (-04, 2025-01) ([datatracker](https://datatracker.ietf.org/doc/draft-mouris-cfrg-mastic/)).
- **Divvi Up runs.** Its latest posts are on production MPC (2026-07-22) and post-quantum work (2026-10-23) ([blog](https://divviup.org/blog/)). It aggregates for Firefox ([Divvi Up](https://divviup.org/blog/divvi-up-in-firefox/)).
- **Differential privacy guidance is final.** NIST SP 800-226 was published 2025-03-06 ([CSRC](https://csrc.nist.gov/pubs/sp/800/226/final)). Local noise on one household's counts would destroy their use, and a hand-sent pack from tens of households is not where differential privacy pays.
- **Sets of domains identify people.** 99% of 48,919 browsing profiles were unique, and about half of users with 50 or more domains were re-identifiable from top-10k sites alone ([Bird et al., SOUPS 2020](https://www.usenix.org/conference/soups2020/presentation/bird)). A TV's set of streaming and app names is the same kind of quasi-identifier: it lists the household's subscriptions.

**Conclusion.** What protects the owner is not k. It is a **closed vocabulary**: the pack may only name endpoints that are already public, the vendor's and the ad industry's, so it describes the TV and not the household. Counts are bucketed and time is coarsened to the ISO week. A collector later applies its own k before publishing any cell (k ≥ 5 for a hobby observatory; the owner's choice, open question). DAP with Prio3Histogram over the same closed vocabulary is the upgrade path once DAP is an RFC and an operator exists. OHTTP ([RFC 9458](https://www.rfc-editor.org/rfc/rfc9458)) would hide the sender's address.

### The exact schema

```json
{
  "schema": "tvgw-share/1",
  "week": "2026-W44",
  "device": {"profile": "lg-webos", "vendor": "LG", "platform": "webOS 5",
             "model_family": "CX", "model_year": "2020", "firmware": "04.64"},
  "settings": {"acr_opt_out": true, "voice_agreement": "declined", "quick_start": "unknown"},
  "exposure": {"awake_h": "10-29", "off_h": "100+"},
  "endpoints": [
    {"domain": "alphonso.tv", "category": "ACR", "lookups": "10-99",
     "blocked": true, "reached": false, "timer_s": "10-99", "while_off": false}
  ],
  "unlisted": {"domains": "1-9", "lookups": "10-99"},
  "conduct": {"plaintext_hosts_listed": ["snu.lge.com"], "plaintext_hosts_unlisted": "0",
              "resolver_bypass": "0", "gate_unexplained": "0", "lan_probes": "1-9", "ech_real": "0"},
  "firmware_diff": {"from": "04.60", "to": "04.64", "new_listed": ["..."], "gone_listed": [], "new_unlisted": "1-9"}
}
```

(Every value is illustrative, and `firmware_diff` is `null` in most weeks.) Its rules, each enforced in code with a unit test:

- **Vocabulary.** `endpoints[].domain` and every listed host must be a registrable domain or name in the profile's categories **other than** `Streaming` and any app category, or in a pinned public list snapshot named in the pack. Everything else is counted in `unlisted` and never named.
- **Buckets.** Counts go into `0`, `1-9`, `10-99`, `100-999` or `1000+`. Exposure goes into `0`, `1-9`, `10-29`, `30-99` or `100+` hours. Periods go into the same decades of seconds.
- **Time.** The ISO week only; no day, hour or timestamp.
- **Identity.** Model family and year, not the model number. Firmware is cut to `major.minor`. No device name, MAC, serial, address, public IP, ZIP, LAN probe target or app name.
- **Settings.** Only privacy settings the profile declares, as enums.
- **Delivery.** `tvgw share-pack --week W` writes `reports/share/<week>.json` and prints it. Nothing is sent. The owner reads it and sends it by hand.

**(test)** Each must print nothing:

```sh
P=/var/lib/tvgw/reports/share/2026-W44.json
sudo jq -r '.. | strings' "$P" | grep -E '([0-9]{1,3}\.){3}[0-9]{1,3}|([0-9a-f]{2}:){5}[0-9a-f]{2}'
sudo jq -r '.endpoints[].domain' "$P" | grep -vxF -f <(tvgw profile --vocabulary)
sudo jq -r '.. | numbers' "$P"
```

The last line checks that no raw count survived. `tvgw profile --vocabulary` is a small new subcommand.

## F8. How comparable projects present this kind of data

| Project | What it shows | Borrow | Avoid |
|---|---|---|---|
| Pi-hole v6 (released 2025-02-18; web server and REST API inside FTL, Basic and Expert settings) ([Pi-hole blog](https://pi-hole.net/blog/2025/02/18/introducing-pi-hole-v6/)) | Summary tiles (total queries, blocked, percent blocked, list size), a 24-hour stacked bar chart of queries, top lists, a paginated query log (from the UI; tile labels not re-checked for this pass) | The 24-hour bar chart as the day's shape | **Percent blocked as a headline.** On this TV, blocked clients retry, so the share measures the retry loop, not protection. The brief's "Blocked and still retried" exists for that reason |
| AdGuard Home 0.107 | General statistics with blocked counts, top queried and top blocked domains, top clients, upstream response time (from the UI, unverified for the exact labels) | Nothing new beyond Pi-hole | Same as Pi-hole, plus top *clients*, which is meaningless with one client |
| Home Assistant energy dashboard | Daily bars with a "compare with previous period" overlay; only the previous period, a long-standing user request ([community thread](https://community.home-assistant.io/t/wth-why-can-i-only-compare-periods-in-the-energy-dashboard-with-the-previous-period/467189)) | Ghosted comparison bars for the same metric's trailing period | Cards that need JavaScript and a live backend |
| NetAlertX | Device list, presence, events; notifications to 80+ services through Apprise; recommends running behind an authenticating reverse proxy ([repo](https://github.com/jokob-sk/NetAlertX)) | The access advice: put authentication in front of any LAN dashboard | The notification model, which the owner has ruled out |
| IoT Inspector 3 (NYU) | Per device: bytes sent and received, "which companies they are communicating with", and whether devices send data "when they are not supposed to"; relaunch announced for April 2025, still behind a waitlist on the project page ([inspector.engineering.nyu.edu](https://inspector.engineering.nyu.edu/), [client repo](https://github.com/nyu-mlab/iot-inspector-client)) | Grouping by organization (B1); "sending when it should not" (C1) as a first-class question | Live ARP-style interception of other devices, which tvgw does not need |
| RITA v5 | A beacon table with a composite score and its parts | Showing the parts | An opaque composite score |

## Settled: the brief's HTML form

**What it is.** A static HTML rendering of the same `window_report()` dict the text brief and the JSON use. It is a pure function `html.render(report) -> str` with a golden test like `tests/unit/test_cli_golden.py`. There is no JavaScript, no external font, stylesheet or CDN, and no auto-refresh. A LAN page that loaded Google Fonts would tell Google when the owner reads about their TV.

**Files.** `tvgw-analyze` writes, beside the text and JSON reports, atomically (temp file and `rename`):

```
/var/lib/tvgw/www/              root:www-data 0750
  index.html                    latest 24 h, then links to the last 14 days, weeks and scorecards
  daily/<day>.html  weekly/<week>.html  scorecard/<week>.html
  brief.css                     the only stylesheet (CSP style-src 'self')
```

The `www` tree is separate from `reports/`, so nginx's `www-data` can read the pages and nothing else. **(test)** `sudo -u www-data cat /var/lib/tvgw/www/index.html >/dev/null && ! sudo -u www-data ls /var/lib/tvgw/reports`.

**Page order**, which is the text brief's reading order (["How to read it"](../../use/daily-brief.md#your-daily-check)):

1. `<h1>` the day. Under it, one sentence: what changed since the last brief, from the judgments (F5). When nothing changed, it says so.
2. **Coverage** as a row of labelled items, each with the word `assessed` or `NOT ASSESSED`. Colour may repeat the word but never replace it.
3. **Red lines**, each a sentence with its runbook link ([operations](../../use/daily-brief.md#red-lines)).
4. **Judgments** that changed (F5 blocks).
5. **Chart 1, the day strip** (below).
6. Every brief section in its current order, each a `<details>` element whose `<summary>` carries the count, as in `New hosts (4)`. Native disclosure needs no script and works from the keyboard. Sections with red-line content are `open`.
7. A footer with the generation time, the tvgw version, and "provisional until" (F5's late-evidence share).

**Four charts, all inline SVG generated in Python.** Each chart has a headline title that states its message, direct labels instead of a legend, no dual axes, bars from zero, and no more than four series. Each is followed by a one-sentence takeaway and a `<details>` data table (the UK Government Analysis Function's chart guidance ([2022](https://analysisfunction.civilservice.gov.uk/policy-store/data-visualisation-charts/)) and Chartability's critical tests ([Elavsky et al., EuroVis 2022](https://chartability.fizz.studio/), [workbook](https://chartability.github.io/POUR-CAF/))).

| Chart | Encoding | Answers |
|---|---|---|
| 1. Day strip | 24 h on x; a band for awake and off from `tvstate`; lookups per 10 min as bars, blocked bars hatched (pattern plus lightness, not hue alone); connections opened per 10 min as ticks | When was the TV on, and did anything happen while it was off? |
| 2. Four small multiples, 28 days | Upload to non-service parties per awake hour, new names, blocked lookups per awake hour, off-hour connections; a grey band for median ± 1.4826·MAD; today's point labelled with its value | Is today unusual for this TV? |
| 3. Timer phase plot, one per beacon finding | x: time across the window; y: phase `(t mod P)/P`. A timer is a horizontal row of dots; chance is scatter. This is the Z² test made visible | Is this really a timer? |
| 4. Firmware dumbbell (scorecard E2) | Per changed name, the rate before and after on a labelled log scale | What changed across the update? |

**Accessibility floor.** WCAG 2.2 AA, which is now also ISO/IEC 40500:2025 ([W3C, 2025-10-21](https://www.w3.org/WAI/news/2025-10-21/wcag22-iso)). 4.5:1 contrast for text and 3:1 for marks (1.4.3, 1.4.11); no colour-only meaning (1.4.1); reflow at 320 CSS px (1.4.10); real `<table>` markup with `<caption>` and `scope` (1.3.1); no text under 12 px; sizes in `rem` so user styles win. Each SVG gets `role="img"`, a `<title>` and `aria-describedby` pointing at its takeaway sentence. There is a `prefers-color-scheme: dark` palette and a print stylesheet. Names from the TV can be 100+ characters (the DNS-oddities section), so table cells use `overflow-wrap: anywhere`.

**Hostile strings.** Every name, URI and user agent passes through the existing `cli.clean()` (control and bidi characters) and then `html.escape(s, quote=True)`. None goes into an `href`, a `style` or an unquoted attribute. **(test)** A golden fixture whose qname is `<script>x</script>‮.example` must render as escaped text, and `grep -c '<script' /var/lib/tvgw/www/daily/*.html` must print 0 for every file.

**Serving.** Off by default. `BRIEF_HTTP=8686` in `tvgw.conf` makes `install.sh` write `/etc/nginx/sites-available/tvgw-brief` and link it. It is a file of its own, so a mistake in it cannot take the TV's URL filter down without `nginx -t` failing first:

```nginx
server {
    listen 8686;                      # every address; access is limited below
    server_name _;
    root /var/lib/tvgw/www;
    index index.html;
    autoindex off;
    allow <LAN_CIDR>;                 # the home LAN only
    deny all;                         # the TV subnet, the VPN, everything else
    auth_basic "tvgw";                # BRIEF_HTTP_AUTH=yes, the default
    auth_basic_user_file /etc/tvgw/brief.htpasswd;
    add_header Content-Security-Policy "default-src 'none'; style-src 'self'; img-src 'self'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'" always;
    add_header X-Content-Type-Options nosniff always;
    add_header Referrer-Policy no-referrer always;
    add_header Cache-Control "no-cache" always;
    location / {
        limit_except GET HEAD { deny all; }
        try_files $uri $uri/ =404;
    }
}
```

The TV cannot reach it twice over: the `input` chain accepts only DNS, 80, 443 and pings from the TV, and nginx denies its subnet. Port 8686 is chosen to stay clear of the Pi's other services. Confirm with `ss -ltnp` before enabling. Basic authentication over plain HTTP on a LAN only stops casual access. The page shows when the TV was on and which apps ran, so the owner decides whether household members and guests on the LAN may read it (open question).

**(test)** After enabling:

```sh
sudo nginx -t && sudo ss -ltnp 'sport = :8686'
curl -sI -u <user> http://<pi-lan-address>:8686/ | grep -i -e content-security-policy -e x-content-type-options
curl -s -o /dev/null -w '%{http_code}\n' -u <user> -X POST http://<pi-lan-address>:8686/    # 403
# in the CI namespace gateway (in flight): from the TV namespace this must fail
ip netns exec tv curl -m 3 -s http://GW_IP:8686/ ; echo "exit=$?"            # non-zero
```

In CI, run an accessibility checker (axe-core's CLI or pa11y, both Node tools, so CI only and never on the Pi) over the golden HTML with WCAG 2.2 AA rules, and fail on any violation. A daily page should stay under 200 KB.

**What to avoid.** Gauges, donuts and 3-D. Percent-blocked headlines. A composite score. Animation. Pages that need the store live (a CGI or API). Anything that pushes: no web notifications, no RSS, no email. The page is read when the owner chooses to read it.

## Where this disagrees with the October survey

1. **"RITA-style" scoring.** The survey said to copy RITA's two halves and left the weights unverified. RITA v5 has four parts at 0.25 each, and two of them structurally penalise a device that is on a few hours a day (F1). Copy the two halves and replace the other two with awake coverage.
2. **Lomb-Scargle as the confirming step.** For arrival times, the Rayleigh/Z² test with a null built by shuffling events inside the awake hours is the better tool. Lomb-Scargle's false-alarm figures assume sampled values and fixed observing times (F1).
3. **The ACR cadence canary.** The survey set a payload ceiling of 4 KB per connection. IMC 2024's own volumes imply about 17 to 19 KB per 15-second contact while fingerprinting (computed). A blocked ACR client produces only DNS retries, and a kept-alive one produces no cadence in flows. Use the period alone, the DNS series and a long-connection check (F1).
4. **Upload.** The survey's "report a range" stands. A range alone does not say whether today is unusual: add the PCR filter and the per-name record rule (F2).
5. **Scorecard breakage cost.** The survey listed "the breakage cost of each block" as a scorecard measure. The gateway cannot observe breakage, only reverts, red lines and the owner's notes. Field R1 says exactly that.
6. **Share pack fields.** The survey's pack had any registrable domain, by day. Arbitrary domains and daily presence identify a household (Bird et al.). Use a closed public vocabulary, leave out Streaming and apps, coarsen to ISO weeks and bucket the counts (F7).
7. **Label landscape.** Finland's label ended on 2025-07-31. The BSI label now covers a major TV maker's 2026 range. The Cyber Trust Mark still had no labelled product on 2026-10-28 (F6).

## What to build here

Ranked by what each unlocks. Effort: S is days, M is one to two weeks, L is more. Risk is to the running gateway. Everything here is read-only over the store except the nginx site.

1. **Exposure and uncertainty primitives** (`src/tvgw/stats.py`): awake and off intervals as a reusable function; Garwood and rule-of-three bounds; the exact two-Poisson test; Benjamini-Hochberg; ICD 203 word tables; the F5 confidence rule. Pure Python, unit-tested against SciPy values in CI only. *S effort, no risk.*
2. **Upload anomaly scorer and off-hour baseline** (F2, F3): PCR filter, record-day rule and robust z; new-while-off names; bounds on the While-off line. *S effort, low risk* (new brief lines; golden tests change).
3. **Beacon screen v3** (F1): the DNS series including blocked lookups, awake coverage, Z² with the exposure-shuffle null, the 7-day pool, `acr_like` on period only, and the long-connection ACR check. *M effort, low-medium risk.* `acr_like` feeds red line 7 and the analyst's novelty, so require `p < 0.01` and awake coverage ≥ 0.6 before red line 7 fires, and run it in parallel with the current scorer for two weeks, both printed.
4. **Judgment blocks in the brief** (F5): fixed vocabulary, basis, "would change", changes only. *M effort, low risk.*
5. **`tvgw scorecard --week`** with the 18 fields, text and JSON first ([the specification](#settled-the-scorecard-specification)). *M effort, low risk.*
6. **Firmware behavioural diff (E2) and weekly undated drift** (F4). *M effort, low risk.* On a 2020 set the firmware diff may seldom fire, while undated drift fires on LG's server-side configuration changes.
7. **HTML brief and the LAN nginx site.** *M effort, low-medium risk*: a new listening port, and an nginx shared with the TV-side URL filter, so the site is a separate file behind `nginx -t`.
8. **`tvgw share-pack --week`**, local only (F7). *S effort, no risk* (nothing leaves the Pi).
9. **Later:** change-point dating (BOCPD) for undated drift; DAP once the draft is an RFC and an operator exists. *M effort each, low risk.*

## Open questions

- **Does webOS honour the 60-second TTL of blocked answers?** The F1 SQL test answers it. If it does not, blocked-name lookup timing is the client's own timer, which is better evidence.
- **Are LG's ACR uploads separate connections or one kept-alive connection, and is IMC 2024's table unit per hour?** The owner will not turn Live Plus on, so the answer has to come from the IMC or PoPETs 2027 authors' data. Until then the long-connection check is a hedge.
- **Does `tvstate` ever read `Active Standby` on this CX?** The F3 SQL test answers it. It decides whether "off" means asleep with the network up.
- **Which confidence thresholds are right?** 10 awake hours for "high" is a guess. Calibrate on placebo days: run the F2 and F4 tests on pairs of ordinary days and check that about 10% or fewer of the flags are false at q = 0.10.
- **Who may read the HTML?** Basic authentication or none; and should app names and TV-on hours appear on a LAN page at all?
- **Who receives a share pack, and with what k?** Candidates from the October survey: Northeastern's Mon(IoT)r lab, IMDEA, NYU (IoT Inspector), HaGeZi's tracker. The owner decides.
- **How fast is Z² with 199 shuffles on the Pi 5** for 20 candidates a day? Measure before scheduling it in the hourly job, or run it only in the daily pass.
- **Will the CX get another firmware?** It is a 2020 model on 04.64. If updates have stopped, the firmware diff is for the next TV and undated drift is for this one (unverified; LG's update policy for 2020 sets was not checked).

## Sources

Code and standards read directly:

- RITA v5 beacon scoring: [`analysis/beacons.go`](https://github.com/activecm/rita/blob/main/analysis/beacons.go), [`config/config.go`](https://github.com/activecm/rita/blob/main/config/config.go), [releases](https://github.com/activecm/rita/releases)
- astropy, Lomb-Scargle false-alarm guidance: <https://docs.astropy.org/en/stable/timeseries/lombscargle.html>
- Belanger, *On More Sensitive Periodogram Statistics*, ApJ 822:14 (2016): <https://arxiv.org/abs/1712.00734>
- Adams and MacKay, *Bayesian Online Changepoint Detection* (2007): <https://arxiv.org/abs/0710.3742>
- `ruptures`: <https://github.com/deepcharles/ruptures>
- Benjamini and Hochberg (1995): <https://doi.org/10.1111/j.2517-6161.1995.tb02031.x>
- Hanley and Lippman-Hand, rule of three, JAMA 1983: <https://pubmed.ncbi.nlm.nih.gov/6827763/>
- ICD 203, Analytic Standards (2015, amended 2022 and 2023): <https://archive.dni.gov/files/documents/ICD/ICD-203.pdf>
- ETSI EN 303 645 V3.1.3 (2024-09): <https://www.etsi.org/deliver/etsi_en/303600_303699/303645/03.01.03_60/en_303645v030103p.pdf>
- EU CRA Annex I: <https://streamlex.eu/annexes/cra-en-annex-i/>
- DAP and PPM WG documents: <https://datatracker.ietf.org/wg/ppm/documents/>; VDAF: <https://datatracker.ietf.org/doc/draft-irtf-cfrg-vdaf/>; Mastic: <https://datatracker.ietf.org/doc/draft-mouris-cfrg-mastic/>; OHTTP, RFC 9458: <https://www.rfc-editor.org/rfc/rfc9458>
- WCAG 2.2 as ISO/IEC 40500:2025: <https://www.w3.org/WAI/news/2025-10-21/wcag22-iso>
- Chartability: <https://chartability.fizz.studio/>, <https://chartability.github.io/POUR-CAF/>
- UK Government Analysis Function, charts: <https://analysisfunction.civilservice.gov.uk/policy-store/data-visualisation-charts/>

Measurement studies and papers:

- Anselmi et al., *Watching TV with the Second-Party*, IMC 2024: <https://arxiv.org/html/2409.06203v1>
- Emami-Naeini et al., *Ask the Experts: What Should Be on an IoT Privacy and Security Label?*, IEEE S&P 2020: <https://ar5iv.labs.arxiv.org/html/2002.04631>
- Xiao et al., *Lalaine*, USENIX Security 2023: <https://www.usenix.org/conference/usenixsecurity23/presentation/xiaoyue>
- Mandalari et al., *Blocking without Breaking*, PoPETs 2021: <https://arxiv.org/pdf/2105.05162>
- Consumer IoT traffic survey (2024): <https://arxiv.org/pdf/2403.16149>; IoT profiling drift (2026): <https://arxiv.org/pdf/2602.24047>
- Bird, Segall and Lopatka, SOUPS 2020: <https://www.usenix.org/conference/soups2020/presentation/bird>
- Producer/consumer ratio: <https://www.cert.org/flocon/2014/proceedings-2014.html>, <https://github.com/w8mej/ThreatPlays/blob/master/analyze_producer_consumer_ratio.md>
- RTINGS ACR testing: <https://www.rtings.com/tv/learn/research/smart-tv-tracking>
- Consumer Reports Digital Standard TV case study: <https://innovation.consumerreports.org/smart-tvs-a-digital-standard-case-study/>

Labels and programmes:

- Cyber Trust Mark: <https://www.cybersecuritydive.com/news/fcc-cyber-trust-mark-iot-labeling-ul-withdraw/808732/>, <https://broadbandbreakfast.com/fcc-picks-ioxt-alliance-to-head-cyber-trust-mark-program/>, <https://www.nextgov.com/cybersecurity/2026/10/fcc-commissioner-hopes-cyber-trust-mark-products-reach-shoppers-within-year/416878/>, <https://pillsburylaw.com/en/news-and-insights/fcc-iot-labeling-program.html>
- Singapore CLS, JC-STAR and Finland: <https://www.csa.gov.sg/news-events/press-releases/singapore-signs-memorandum-of-cooperation-with-japan-on-mutual-recognition-of-internet-of-things-cybersecurity-schemes/>
- BSI label: <https://news.samsung.com/de/mehr-transparenz-beim-tv-kauf-samsung-smart-tv-line-up-erhalt-erneut-it-sicherheitskennzeichen-des-bsi>, <https://www.bsi.bund.de/dok/sik-cra_en>
- Privacy Sandbox k-anonymity and its deprecation: <https://privacysandbox.google.com/relevance/protected-audience-api/k-anonymity>, <https://groups.google.com/a/chromium.org/g/blink-dev/c/k_nubsMb97g>
- NIST SP 800-226: <https://csrc.nist.gov/pubs/sp/800/226/final>
- Divvi Up: <https://divviup.org/blog/>, <https://divviup.org/blog/divvi-up-in-firefox/>
- DuckDuckGo Tracker Radar licence: <https://github.com/duckduckgo/tracker-radar>

Comparable projects:

- Pi-hole v6: <https://pi-hole.net/blog/2025/02/18/introducing-pi-hole-v6/>
- Home Assistant energy comparison: <https://community.home-assistant.io/t/wth-why-can-i-only-compare-periods-in-the-energy-dashboard-with-the-previous-period/467189>
- NetAlertX: <https://github.com/jokob-sk/NetAlertX>
- IoT Inspector 3: <https://inspector.engineering.nyu.edu/>, <https://github.com/nyu-mlab/iot-inspector-client>
