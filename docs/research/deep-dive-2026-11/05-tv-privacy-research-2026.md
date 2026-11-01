# What the field learned about smart-TV surveillance in 2025-2026, and what it changes in tvgw

*Deep dive 05, written 2026-11-01. Research only: nothing here is implemented, and no host was touched. It reads with [state-of-the-art-2026-10.md](../state-of-the-art-2026-10.md) (called "the October pass" below), [design-decisions.md](../../design-decisions.md), [analyst-and-autonomy.md](../../analyst-and-autonomy.md) and [reading-the-brief.md](../../reading-the-brief.md). Every non-obvious claim carries a URL. **(unverified)** means one secondary source or none. **(measured here)** means this pass computed it from a public dataset, with the script described in the text. Site identifiers are left out on purpose: no MACs, private addresses or host names.*

## Bottom line

The one 2026 paper that matters most for this gateway, Northeastern's *Watching the Watchers* (PoPETs 2027, data dated April 2026), confirms that LG's Live Plus opt-out really does stop ACR (automatic content recognition, the screen fingerprinting), so the owner's settings are doing their job. It also publishes a packet-level trace of a US LG set's ACR traffic, and running tvgw's own ACR detector over that trace shows **the detector does not fire on LG's real ACR on any of the 15 days**. LG's ACR client sends a fingerprint burst every 14 to 15 s, but inside TLS connections that each last one to three minutes, on **TCP port 4431, not 443**, carrying a median of about 94 KB up per connection. The brief's `ACR-like` mark (connection starts 10 to 20 s apart, under 4 KB each) and red line 7 are tuned to a shape that conntrack never sees. That is the one finding that changes code. Two more change the rule set. (1) On the lab set's full 16-day trace, every internet port other than 80 and 443 belonged to ACR, ads or IoT: TCP 4001, 4431, 4445 and 4447 (Alphonso), 8180 (LG ads) and 8883 (an IoT hub variant `lg-webos.rules` misses). So a narrow port reject stops ACR whatever DNS does. (2) The paper finds program titles written into plain DNS names (`*.amagi.tv`) by free ad-supported (FAST) channel delivery. Those names would land in tvgw's store and in the analyst's evidence pack, which leaves the Pi. The must-allow list does not change. The reason for keeping `snu.lge.com` changes, though: the CX (2020) is past LG's published security-update window, yet LG still shipped it firmware in September 2025 and May 2026. The Texas settlement (May 2026) makes a new ACR consent screen arriving by firmware likely. So a firmware update should be treated as a re-baseline event, not routine. The September 2026 Gamers Nexus investigation of a 2025 G5 adds LAN mapping and Wi-Fi surveying that LG does not deny. tvgw's isolation already contains most of it, but it makes the Pi, the only LAN neighbour the TV has, the thing to harden.

---

## 1. Findings

### 1.1 What LG's ACR looks like on the wire, and why tvgw's canary misses it (settled, measured here)

**The source.** *Watching the Watchers: Privacy Analysis of U.S. Smart TV Automatic Content Recognition*, Mammadov, Joshi, Dubois and Choffnes (Northeastern), Proceedings on Privacy Enhancing Technologies 2027. It ran 5,943 automated experiments on 12 TVs covering 8 OSes, captured with Mon(IoT)r at a gateway ([paper PDF](https://watchingthewatchers.github.io/watchingthewatchers/paper.pdf), [landing page](https://watchingthewatchers.github.io/watchingthewatchers/paper.html)). The October pass relayed this paper second-hand. This pass read the PDF and the released data.

**What the paper says about webOS** (from the PDF; section and table numbers are the paper's):

- **One ACR endpoint.** `tkacrNNN.alphonso.tv`, with 41 rotating FQDNs, recommended block `*.alphonso.tv` (Table 8). That matches IMC 2024 ([Anselmi et al.](https://arxiv.org/html/2409.06203v1)), whose US hosts were `tkacrX.alphonso.tv` and UK hosts `eu-acrX.alphonso.tv`. The paper notes that "ACR domains found two years ago remained unchanged in this study" (§7).
- **Audio fingerprinting.** Dynamic video with no audio cuts ACR traffic by 97.3% (σ = 11.1%), while a black screen with audio cuts nothing (§5.2, Fig. 6). This is relevant because Alphonso's own policy says it does not recognize "ambient sounds", and the authors flag the gap (Table 5 footnote).
- **Where ACR runs.** On webOS: antenna, HDMI and LG's own first-party streaming (LG Channels). Not Netflix, YouTube, Tubi, screen mirroring or the idle home screen (Table 5).
- **Opt-out works on webOS.** "No traffic consistent with ACR activity" after opt-out, against suspected ACR after opt-out in more than 60% of Tizen runs and 100% of Vizio runs (Table 1, §6.2). The endpoint still gets residual traffic, about 5% of tracked volume, in scenarios that are not tracked (§6.1).
- **Shape.** ACR endpoints receive about 7× more bytes from the TV than they send back, with periodic bursts about every 14 s on webOS (§5.1, Figs. 4 and 5).

**What the released data adds.** The authors published the LG ACR-endpoint packets as a CSV: `tkacr.csv`, 155 MB, 881,143 packets from 2026-04-22 over about 400 hours. It is on [Zenodo record 22733487](https://zenodo.org/records/22733487) under CC BY-NC-ND 4.0, with an index in the [repository](https://github.com/IlgarNEU/Watching-the-Watchers). Reading it here with a 60-line stdlib script (the TV identified by MAC, connections keyed by TV port, server address and server port) gives:

| Property | Value (measured here) | What tvgw assumes today |
|---|---|---|
| Server port | **TCP 4431** for 9,988 of 10,174 connections; 4445 and 4447 for the rest; **never 443** | Nothing; any port other than 80 and 443 is logged as `tvgw-oddport` and allowed while `STRICT_PORTS=no` |
| Connection lifetime | Median 113 s, interquartile 47-168 s, for connections carrying more than 10 KB up | `ACR_PERIOD = (10, 20)` s between connection **starts** |
| Bursts inside a connection | Every 14-15 s (6,192 gaps of 15 s, 5,943 of 14 s), median about 24 KB per burst | Invisible to conntrack, which reports one row per connection |
| Gap between connection starts | Peaks at 56, 60, 125 and 181 s (multiples of about a minute) | 10-20 s |
| Upload per ACR connection | Median 94 KB, 90th percentile 217 KB | `ACR_PAYLOAD = 4096` bytes |
| Upload to the ACR endpoint per day | 10-39 MB on days with ACR active | No volume test |
| Payload ratio up:down | 8-17× per day | No ratio test |
| Small "heartbeat" connections | About 1.8 KB up, one every 60 s, with no ACR bursts | These would look like a 60 s beacon |
| DNS | 41 names, A and AAAA queries, short answer TTLs (6-12 s seen) | The DNS gate holds addresses for a day: fine |

**Running tvgw's detector over it.** The script `canary_sim.py` copies `beacons()` from `src/tvgw/queries.py` with its constants (`BURST_GAP = 5`, `BEACON_MIN = 12`, `PERIODIC_JITTER = 0.15`, `ACR_PERIOD = (10, 20)`, `ACR_PAYLOAD = 4096`, `HEADER_BYTES = 40`) and feeds it the trace as conntrack would see it: one flow per connection, IP bytes up and packets up, named by the DNS answer that preceded it. Day by day:

- **Named per FQDN, as tvgw does:** the beacon test passes on 8 of 15 days, always with a period of about 60 s. **`acr_like` is false on all 15 days.**
- **Grouped by registrable domain:** periodic on 6 of 15 days, `acr_like` on 0 of 15.
- **Where it fails:** on many days the jitter test fails (MAD/median 0.3-0.7), because new connections open at 1, 2 or 3 times the base period. The payload test fails every day.

So red line 7 (`ACR-like cadence`) cannot fire on the ACR client LG actually ships, even if Alphonso turned up under a name no list knows or at an address reached without DNS. The October pass's §5.1 "ACR cadence canary" took IMC 2024's "uploads every 15 s" as the period between connections. The IMC paper never measured connections: the authors say they did not decrypt and did not report connection behaviour ([arXiv 2409.06203](https://arxiv.org/html/2409.06203v1)). **This pass disagrees with the October pass on this point, and with `ACR_PERIOD` and `ACR_PAYLOAD` as built.**

**Caveats.**

- The trace is from an unnamed 2025-26 US LG set in a lab, not this CX on webOS 5.
- IMC 2024 also did not give the model or webOS version.
- Whether the CX's ACR client uses port 4431 is **unverified**. It is testable (§3).
- The CC BY-NC-ND licence allows reading the data privately. It does not allow committing derived lists or fixtures into tvgw's MIT repository, so tests must use synthetic flows built from the published statistics, not the trace.

**What a detector that would have fired looks like.** On every ACR day in the trace, the endpoint's registrable domain shows:

- at least 1 MB of payload up in the day (sum over flows of `max(0, bytes_up - 40*pkts_up)`);
- payload up at least 4× payload down;
- at least 24 connections.

The ACR-free day in the trace (4 connections, 10 KB) does not meet those thresholds. For calibration on this CX, the biggest non-video uploader the profile records is `unagi-na.amazon.com`, at 961 KB in 9 connections on 2026-10-25 ([lg-webos.rules](../../../src/tvgw/profiles/lg-webos.rules)): under every threshold, and blocked anyway. Whether any allowed CX name crosses the thresholds is the first test in §3.

### 1.2 The firewall can reject ACR by port, independent of DNS (settled for the lab set, test pending for the CX)

Every ACR connection in the trace used TCP 4431, 4445 or 4447 (measured here). The full trace (§1.8) adds Alphonso's control plane on TCP 4001, LG ads on 8180 and the UEI Nevo MQTT hub on 8883. On the lab set, **every internet TCP port other than 80 and 443 belonged to ACR, ads or IoT**. tvgw's `tv_out` already logs and counts any other port (`tvgw-oddport`), and `STRICT_PORTS=yes` would reject them all ([architecture.md, step 8](../../architecture.md#the-packet-path)). Decision 17 keeps `STRICT_PORTS` off until two clean weeks.

A narrow rule closes these channels on day one, independent of DNS, the gate and the blocklists: a reject for TCP 4001, 4431, 4445, 4447, 8180 and 8883 from the TV, with a counter and a comment so `tvgw verify` and the brief see it. A hardcoded address, a DoH lookup the gateway missed, or a renamed host would all still meet this wall. The DNS-gated egress set (decision 18) would only count such a connection.

The costs:

- A firewall change needs the owner's approval.
- Port 8883 is generic MQTT over TLS, and an app could use it. On this TV, ThinQ's MQTT is already blocked by name (lg-webos.rules, 2026-10-25).
- No streaming app is known to use the other ports (unverified; check the CX's own flow history first, §3).

This pass does not propose `STRICT_PORTS=yes` early. The narrow rule is cheaper and keeps decision 17's evidence process intact. The lab trace does count as evidence for decision 17's end state: no legitimate internet port beyond 80 and 443 appeared in 16 days.

### 1.3 Program titles in plain DNS: the Amagi channel (settled for the mechanism; CX exposure untested)

*Watching the Watchers* §6.3 documents that Amagi's FAST delivery puts the **program or channel title in the DNS name and the SNI**. The forms are `{title-slug}-{platform-token}.amagi.tv` and `amgNNNNN-{title-slug}-{platform-token}.amagi.tv`, for example `soul-5mincrafteng-vizio.amagi.tv`. Any observer between the TV and its resolver can rebuild an ordered viewing history this way, whatever the ACR opt-out ([paper](https://watchingthewatchers.github.io/watchingthewatchers/paper.pdf)). The paper saw it on Vizio's WatchFree+. It names Amagi as a filter keyword because Amagi delivery showed up across OSes (Table 7), and it recommends **not** blocking `*.amagi.tv`, because that breaks FAST playback (Table 8).

**LG Channels carries Amagi-delivered channels.** Examples:

- Amagi delivers Banijay's FAST channels to LG Channels, among other platforms ([Advanced Television, 2022-05-25](https://www.advanced-television.com/2022/05/25/banijay-rights-collaborates-with-amagi-to-go-fast/)).
- A 2025 Atrangii launch "powered by Amagi" on LG ([Filmibeat](https://filmibeat.com/television/news/2025/atrangii-launches-fast-channels-on-lg-and-xiaomi-smart-tvs-powered-by-amagi-470985.html)).
- 4Fangs on LG Channels via Amagi CLOUDPORT in November 2025 ([Señal News](https://senalnews.com/es/digital/amagi-lanzo-4fangs-nuevo-canal-fast-disponible-en-mexico-a-traves-de-lg-channels)).

Whether the webOS LG Channels client uses the title-slug host form is **unverified**.

**Consequences for tvgw:**

- **The gateway mostly closes the on-path leak** for DNS. AdGuard forwards over DoH through the VPN (decision 9). The SNI still leaves on the direct uplink (decision 1), so the ISP can read titles from Amagi SNIs. No setting changes that short of blocking LG Channels.
- **The leak moves into tvgw's own records.** The query log, `dns.qname`, `tls.sni` and `hosts.name` would hold a viewing history in plain text. That history is exactly what [decision 19](../../design-decisions.md#19-a-daily-analyst-that-only-proposes) promises the analyst never receives (the pack carries "never ... an hourly timeline", and [privacy-and-retention.md](../../privacy-and-retention.md) calls the store's `dns`, `tls` and `flows` rows "a minute-by-minute record of what the household watched"). Yet the daily evidence pack sends names, and the scrub in `analyst.py` redacts MACs, private addresses and the TV's own settings values, not title slugs. A day of LG Channels would send Anthropic a list of the shows watched. **This is a gap in decision 19's minimization.**
- **The fix is a name redactor, not a block.** In the pack, rewrite any label under `amagi.tv` that is not `amg\d+` to `<title>`. More generally, any name the profile marks `title_bearing` gets the same treatment. Do the same in the brief's New hosts section, optionally.

### 1.4 LG's own 2026 behaviour, by the investigation LG partly confirmed (partly settled)

Gamers Nexus published "216,000,000 Spy TVs" on 2026-09-06, a 135-minute video made with Level1Techs and others. The tests used retail US LG OLEDs, chiefly a **2025 G5 (webOS 25)**: Wireshark captures, firmware decryption, and rooted units for logs ([CyberInsider, 2026-09-07](https://cyberinsider.com/lg-smart-tvs-found-scanning-home-networks-for-nearby-devices/), [IT-Connect, 2026-09-10](https://www.it-connect.tech/lg-tvs-allegedly-scan-your-local-network-and-listen-in-standby/), [Notebookcheck](https://www.notebookcheck.net/LG-smart-TVs-caught-logging-audio-with-screen-off-and-snooping-on-local-devices.1391214.0.html)). No coverage found names a hostname, port or firmware build. The primary source is the video itself.

| Claim | Status | What it means for a CX behind tvgw |
|---|---|---|
| The TV sweeps the LAN and lists up to 38 devices (names, internal addresses, MAC-derived IDs), including server BMCs | **LG confirms** scanning as "a standard feature" ([LG statement via IT-Connect](https://www.it-connect.tech/lg-tvs-allegedly-scan-your-local-network-and-listen-in-standby/), [The Next Web, 2026-09-09](https://thenextweb.com/news/lg-smart-tv-acr-denial-industry-standard-eu)) | Contained. The TV's segment holds only the Pi, and `tv_out` drops TV→LAN (decision 2). The brief's LAN probes section is the evidence. The Pi is now the one device the TV can fingerprint (§1.6). |
| The TV records nearby Wi-Fi SSIDs, signal strength and channel ("could improve geolocation") | Reported from firmware analysis; not denied | **Unverified for the CX with Wi-Fi switched off.** Whether webOS 5 stops scanning when Wi-Fi is disabled in the menu cannot be seen from the wire, and any upload would be inside TLS to an allowed LG host. |
| LG Ad Solutions claims 363 million "secondary addressable devices" in the US | Single-sourced figure ([Economie Matin, 2026-09](https://www.economiematin.fr/?p=231476); [The Cyber Sec Guru](https://thecybersecguru.com/?p=25090)) | Cross-device matching in connected TV runs on the household's public address plus device IDs. Decision 1 accepts that LG sees the public address. Blocking LG's ad and ACR hosts removes the TV-side signal; any allowed LG host still sees the address. |
| Audio captured with the screen off, transcribed, held offline and uploaded on reconnect | **LG denies**: voice only on button hold or with Far-Field "Hi LG" enabled, wake word local ([CyberInsider summary of LG's 2026-09-09 statement](https://thecybersecguru.com/?p=25090)). Malwarebytes notes the most alarming demos used a compromised TV ([Malwarebytes](https://www.malwarebytes.com/fr/blog/privacy/2026/09/lg-tv-flaws-could-let-attackers-listen-in-even-in-standby-mode)) | The CX has **no far-field microphone** (profile `[[hardware]]`, observed). Its remote mic is push-to-talk, and with the Voice Information agreement declined, a press sent nothing (observed 2026-10-26). Not applicable, except through an exploit (next row). |
| ACR "about 4 GB per TV per month" | Reported ([CyberInsider](https://cyberinsider.com/lg-smart-tvs-found-scanning-home-networks-for-nearby-devices/)), unverified | The lab trace gives 10-39 MB/day on ACR days, so roughly 0.3-1.2 GB a month: the same order of magnitude, with more hours of HDMI or antenna use. |
| LG Channels requests reveal the channel watched | Reported ([CyberInsider](https://cyberinsider.com/lg-smart-tvs-found-scanning-home-networks-for-nearby-devices/)) | Consistent with §1.3 |
| Remote code execution in network-facing webOS services, under disclosure | Unpublished | Watch LG's TV bulletins. On this network only the Pi can reach the TV's ports (§1.6). |

**Disagreement with secondary coverage.** One outlet wrote that LG "later admitted its smart TVs continued collecting data even when users had opted out." This pass found no such admission. LG's statement says the opposite, and the only primary measurement, *Watching the Watchers*, found the webOS opt-out effective ([search trail](https://www.techradar.com/televisions/lgs-denial-over-tv-spying-claims-does-not-address-the-full-privacy-picture-experts-say-after-report-accuses-it-of-making-216-000-000-spy-tvs)). Treat the claim as unsupported.

### 1.5 Regulation in 2025-2026 that changes what the TV will do (partly settled)

- **Texas v. LG.** Texas sued on 2025-12-15 ([Texas AG](https://texasattorneygeneral.gov/news/releases/attorney-general-paxton-sues-five-major-tv-companies-including-some-ties-ccp-spying-texans)). LG settled on 2026-05-11. The terms ([Fox 7, 2026-05-12](https://www.fox7austin.com/news/lg-smart-tv-acr-data-collection-texas-settlement), [CIPAWorld](https://cipaworld.com/2026/05/11/texas-obtains-smart-tv-privacy-settlement-with-lg-heres-what-changes/), [Bloomberg Law](https://news.bloomberglaw.com/litigation/lg-changes-data-collection-consent-to-end-texas-tv-spy-suit)):
  - no ACR without informed consent;
  - a software update to LG smart TVs adding a pop-up disclosure, with consent taken at or just after the disclosure;
  - a clear opt-out and the same disclosure on LG's website;
  - no viewing data to the CCP.

  Two points remain open. Court approval: an agreed judgment was submitted in state court, and approval is **unverified**. Which models get the pop-up is also unverified. **This pass disagrees with the profile's webOS 26 note** ("ACR opt-in pop-up mandated for 2027+ models; older sets keep the agreement flow"): no source found limits the update to 2027+ models, and the reporting says LG must update "its smart TVs". The pop-up is the event most likely to put ACR back on through one careless press of OK. tvgw's defences against that are red line 2 (Live Plus) and the `alphonso.tv` block, which are already in place.
- **LG's terms, 2026.** LG updated its US Terms of Use, mainly the arbitration agreement, effective 2026-08-28 ([LG support](https://www.lg.com/us/support/help-library/how-to-accept-the-updated-user-agreements-on-your-lg-tv-CT10000018-20155426555618)). The TV asks the user to accept updated agreements on screen. A September 2026 review counts about 50,000 words across the TV's agreements and lists the optional ones: viewing information and interest-based advertising, removable under Settings → Support → Privacy & Terms → User Agreements ([Pillitteri, 2026-10-30](https://pasqualepillitteri.it/en/news/28655/lg-smart-tv-what-you-agree-to-terms)).
- **Kentucky HB 692.** Signed 2026-04-13, in force 2027-07-01. It makes ACR data from smart TVs **and smart monitors** "sensitive data" under the KCDPA, which requires opt-in consent ([Hunton](https://www.hunton.com/privacy-and-cybersecurity-law-blog/kentucky-classifies-smart-tv-data-as-sensitive), [Communications Daily, 2026-04-15](https://communicationsdaily.com/news/2026/04/15/Kentucky-Amends-Privacy-Law-to-Regulate-TV-Automated-Content-Recognition-2604140049)). It is the first US statute naming ACR. It changes US firmware behaviour from mid-2027 at the latest.
- **UK.** The ICO said in June 2026 that it would contact smart-TV makers in 2026 about compliance ([Cybernews, 2026-06-16](https://cybernews.com/privacy/uk-watchdog-smart-tvs-collect-personal-data/); ICO primary source not read: unverified). PSTI (in force since 2024-04-29) requires a stated support period for products sold after that date. The CX predates it.
- **EU.** No DPA decision, noyb complaint or DSA/DMA action against a TV maker over ACR was found in 2025-2026 ([The Next Web](https://thenextweb.com/news/lg-smart-tv-acr-denial-industry-standard-eu) says the question "no one has publicly asked"). The CRA dates are in the October pass §6.3.
- **US federal.** No FTC ACR action in 2025-2026 was found. The 2017 Vizio decree remains the precedent ([FTC](https://www.ftc.gov/news-events/news/press-releases/2017/02/vizio-pay-22-million-ftc-state-new-jersey-settle-charges-it-collected-viewing-histories-11-million)). Michigan sued Roku over COPPA in 2025 (cited in *Watching the Watchers* §7).
- **India.** The DPDP Rules were notified on 2025-11-13. The consent-manager rule starts 2026-11-13 and the core consent, security and rights rules on 2027-05-13 ([Deccan Herald](https://www.deccanherald.com/amp/story/india%2Fcentre-notifies-dpdp-rules-implementation-planned-in-phases-spread-over-12-18-months-3798465), [Mondaq](https://www.mondaq.com/dpdp-act-and-rules-2025-the-2026-compliance-milestones-businesses-cant-afford-to-miss/1830402)). **Korea:** no PIPC action on TV viewing data found (unverified absence).

**What regulation does to this CX in practice.** It makes **firmware updates with new consent screens and terms** the main source of change in 2026-2027. That ties into the next point.

### 1.6 The CX's firmware and security position (settled from LG's own pages)

- **LG's stated security window.** LG commits to updates "at least once a year for a minimum period of 2 years after the product launch", and "where possible ... security updates up to 5 years in the case of a critical security vulnerability" ([LG UK, 2022-04-19](https://www.lg.com/uk/support/announcement/GBNTC20220419152260/)). For a 2020 set that window closed in 2025. Re:New covers 2022 and later sets only ([TechRadar](https://www.techradar.com/televisions/lg-promises-to-look-after-your-webos-tv-for-years-to-come)).
- **LG still ships CX firmware.** LG's Romanian support page for the OLED55CX3LA lists 40 builds up to **04.64.00, file dated 2026-05-13**, and 04.63.25 dated 2025-09-17. Every 04.5x and 04.6x note reads "minor bug fixes" ([LG RO support](https://www.lg.com/ro/suport/produs/lg-OLED55CX3LA)). The European build numbering matches this CX's 04.64. The US release date is **unverified**.
- **The last named CX security fix.** Bitdefender's CVE-2023-6317 to -6320 (secondscreen.gateway, ports 3000/3001; account creation without the PIN, then root) listed **OLED55CXPUA on webOS 5.5.0 / 04.50.51** as affected. LG fixed it on 2024-03-22 ([CVE record](https://cveawg.mitre.org/api/cve/CVE-2023-6317), [Bitdefender](https://www.bitdefender.com/blog/labs/vulnerabilities-identified-in-lg-webos)). 04.64 is later.
- **The 2025-26 webOS bugs** are LAN-side and need a host on the TV's network:
  - **SMR-SEP-2025:** a path traversal in the browser service on port 18888, open only while **USB storage is attached**, that leaks the secondscreen keys. Tested on a webOS 24 43UT8050 ([SSD](https://ssd-disclosure.com/lg-webos-tv-path-traversal-authentication-bypass-and-full-device-takeover/), [TechWorm](https://www.techworm.net/2025/09/lg-webos-flaw-local-attackers-take-over-smart-tvs.html)).
  - **The TyphoonPWN 2026 chain:** port 3001, the sync-demo signed manifest replayed to skip the PIN, then cmp-client, then pmlogd command injection. Tested on webOS 7.5.7 firmware 04.54.40 and fixed; webOS 5 is not mentioned; no CVE ([SSD, 2026-10-12](https://ssd-disclosure.com/lg-webos-sync-demo-preauth-rce/), [The Hacker News](https://thehackernews.com/2026/10/lg-smart-tvs-vulnerable-to-pre-auth.html)).
  - **The Gamers Nexus RCE:** undisclosed.
  - **CVE-2025-38352** (kernel UAF): a local root needing code on the TV ([chronomaly](https://github.com/AnalyticETH/chronomaly-webos)).

**What this implies for an unrooted CX behind tvgw.**

1. **The LAN attack surface is the Pi alone.** The TV's ports are reachable only from the TV segment, where the Pi is the one other host. The Pi also runs qBittorrent, Samba, xrdp and an AirPlay receiver: four internet- or LAN-facing services on the one host that can reach TV:3000/3001. A compromise of any of them is one hop from the TV's pre-auth bugs. The October pass (§3.1, §10) named the Pi as that host but proposed only keeping the pairing key at mode 0600. This pass goes further: the Pi's *output* toward the TV should be limited to what tvgw needs (§2, item 5).
2. **Keep USB storage off the TV.** Port 18888 opens only with USB storage attached.
3. **Keep `snu.lge.com` allowed, but change its reason.** The reason is no longer "security fixes" as such: LG makes no security promise for this set any more, and the notes say only "minor bug fixes". The reason is still sound: an internet-facing browser engine and apps on an unpatched set are worse than a set that takes LG's occasional fixes. But every update must now be expected to bring new consent screens, terms and possibly endpoints. A firmware change should raise a red line and trigger a full settings re-read (§2, item 4). Holding firmware (blocking `snu.lge.com` and the 8080 fallback, then updating by USB after reading each release) stays available as an owner decision. This pass does not recommend it.

### 1.7 Public datasets with LG traces to compare against

| Dataset | LG content | Access and licence | Use for tvgw |
|---|---|---|---|
| *Watching the Watchers* (Northeastern, 2026) | US LG, April-May 2026: ACR-endpoint packet CSV (155 MB); all-traffic header parquet (1.65 GB); raw pcaps over 1 TB | [Zenodo CSV](https://zenodo.org/records/22733487), [Zenodo parquet](https://zenodo.org/records/22698120), [repo](https://github.com/IlgarNEU/Watching-the-Watchers); **CC BY-NC-ND 4.0** | The ACR shape (§1.1, measured here); a private oracle for "names a lab LG contacts that the profile does not categorize" (§1.8). Do not commit derived lists into the MIT repository. |
| IMC 2024 (Anselmi et al., UCL, Imperial and others) | LG UK and US ACR byte tables | [arXiv 2409.06203](https://arxiv.org/html/2409.06203v1); data on request (unverified) | Volumes only |
| Mon(IoT)r lab | 2019 packet headers, 34,586 experiments plus 112 h idle; data-sharing agreement ([intl-iot](https://github.com/NEU-SNS/intl-iot)) | Agreement | Old firmware; low value |
| IoT Inspector v3 (NYU) | Crowdsourced; v3 on PyPI (3.0.18) for Linux including Raspberry Pi ([PyPI](https://pypi.org/project/iot-inspector/3.0.18/), [NYU](https://inspector.engineering.nyu.edu/)) | Tool, not a public LG dataset | Do **not** run it on this Pi: it ARP-spoofs the LAN it sits on |
| Dalhousie NIMS 2024, Deakin 2024 | IoT idle pcaps; no LG TV listed | IEEE DataPort | None |

### 1.8 Comparing the lab LG's full destination set with the CX profile (measured here)

The full-traffic parquet for the lab LG (75.3 million packet headers, 2026-04-22 to 2026-05-09, 16 days, DNS names but no SNI) was read here with DuckDB. Each name the TV looked up was run through tvgw's own categorizer (`profile._categorize` on the bundled `lg-webos` profile) and checked against the profile's custom rules and HaGeZi's LG list (filter_72, fetched 2026-11-01). The script reads the file locally and writes nothing. The **results are summarized here and not committed as lists** (CC BY-NC-ND). Of 1,023 distinct names, 476 fall in `Other`; 253 of those are reverse lookups (below).

**What the profile already handles.** Every LG ad, telemetry, IoT and ACR name the lab set contacted is categorized and blocked by a custom rule or by HaGeZi. That includes the `aic.` and `us.` regional forms (`aic.cdpbeacon2.lgtvcommon.com`, `us.rdx2.lgtvsdp.com`, `aic.sports.lgtviot.com`, `aic.commonpush.lgtviot.com`, `us.ibsstat.lgappstv.com`) and Alphonso's control-plane hosts (`prov-lg.`, `bl-server.` and `clockskew.alphonso.tv`), which were contacted on 15 of 16 days whatever the ACR state. The clock and core hosts match the must-allow list: `us.lgtvsdp.com`, `snu.lge.com` and `lgtvonline.lge.com` were seen every day. **The must-allow list needs nothing added or removed.**

**Gaps found (measured here):**

1. **A Universal Electronics "Nevo" IoT hub variant the rule misses.** The lab set kept an MQTT session (TCP 8883, 1.1 MB up over 14 days) to `qs2-nevoai-iothub-12-prod.azure-devices.net`. `lg-webos.rules` blocks only the exact `nevoai-iothub-54-prod.azure-devices.net` (decision 16's QuickSet family), and neither HaGeZi list carries any `nevoai` host. The categorizer puts the variant in `Other`. Fix: replace the exact rule with `/^([a-z0-9]+-)?nevoai-iothub-[0-9]+-prod\.azure-devices\.net$/`, and give the category the pattern `*nevoai-iothub-*-prod.azure-devices.net`.
2. **Three LG blocks rest on HaGeZi alone.** `rdl.lgtvcommon.com`, `wiseconfig.lgtvcommon.com` and `ads.lgtvcommon.com` (all contacted daily as `aic.` names) are categorized but have no custom rule. The rules file's own principle is that "anything we rely on being blocked is also here". Add `||rdl.lgtvcommon.com^`, `||wiseconfig.lgtvcommon.com^` and `||ads.lgtvcommon.com^`. None is in `[must_allow]`, and the apex rule `never_block_apex` is unaffected.
3. **`aic.lgchhomeapp.lgtvcommon.com` is blocked but categorized `LG core`** (by the `lgtvcommon.com` suffix). Move `lgchhomeapp.lgtvcommon.com` into `LG ads` so the brief does not show a blocked "core" name.
4. **LG Channels' FAST plumbing is all `Other`:** `wurllg.global.transmit.live` (Wurl; 28 MB of TV-sent packets, mostly acknowledgements of a stream), `*.amagi.tv` (10 names), `lgcp-xumoent-nbcnn-*.fast.nbcuni.com` and `lgchannels.ott-channels.stingray.com`. The Amagi names carry **channel identifiers and slugs** for the channel being watched: `amg01874-nhl-…-lg-us-…` and `amg00497-lgelectronicsus-fantasylife-…`, alongside opaque `amgNNNNN-…c30-amgplt0023` forms. This confirms §1.3 for LG, at channel rather than program granularity. Add a `FAST` category (or file these under `Streaming`) so they stop counting as surprises. Do not block them.
5. **Alexa's connectivity probe.** `avsxappcaptiveportal.com` was the most-queried name of all (80,146 lookups, 16 MB of plain HTTP on port 80). It is uncategorized and on neither HaGeZi list. Its function on an Alexa-built-in set is the voice stack's captive-portal check (**unverified**). The CX is "works with Alexa" and may never send it (test 7 in §3). If it appears, categorize it `Voice`. Block it only after a test: Alexa features are already walled off, but the probe may also gate the voice consent screen.

**Non-443 internet ports on the lab LG** (TCP, TV to public addresses, measured here):

| Port | Destination | Function |
|---|---|---|
| 4431, 4445, 4447 | `tkacrNNN.alphonso.tv` | ACR fingerprints (358 MB to 4431 over 16 days) |
| 4001 | `prov-lg.`, `bl-server.`, `clockskew.alphonso.tv` | Alphonso provisioning and control |
| 8180 | `aic.ads.lgtvcommon.com` | LG ads |
| 8883 | `qs2-nevoai-iothub-12-prod.azure-devices.net` | UEI Nevo MQTT |
| 80 | LG file service, `avsxappcaptiveportal.com`, others | Mixed |

No NTP (UDP/TCP 123), DoT (853) or 8080 traffic appeared. **Every internet port other than 80 and 443 was ACR, ads or IoT.** That is direct support for decision 17's `STRICT_PORTS=yes`, and the evidence behind the targeted port wall in §2.

**DNS bypass and LAN behaviour** (supports existing rules; nothing new to build):

- 67,810 of the lab set's DNS queries went to `8.8.8.8` directly, although its DHCP resolver was 1.1.1.1. tvgw's `pre_nat` DNAT handles that.
- The set swept PTR lookups for every address in its own /24 (253 names) on 14-15 of 16 days.
- It sent SSDP (239.255.255.250:1900, plus UDP 1902 to the same group), mDNS (5353), TP-Link Kasa discovery (UDP/TCP 9999, broadcast and unicast), LIFX discovery (UDP 56700, broadcast) and DIAL/Cast (8008) probes.

That is the LAN mapping Gamers Nexus described, with protocols named (§1.4). Behind tvgw these reach only the Pi, which answers none of them, and the PTR sweep reaches AdGuard (test 5).

### 1.9 LG's data business in 2025-2026: what is new and what is not

- **ACR data sold through clean rooms.** LG Ad Solutions put its US ACR data on the Databricks Marketplace via Delta Sharing in October 2025 ([Advanced Television, 2025-10-22](https://www.advanced-television.com/2025/10/22/lg-ad-solutions-partners-with-databricks/)). Other 2025-26 deals: Magnite ([The Drum](https://www.thedrum.com/news/lg-s-ad-team-brings-automatic-content-recognition-data-magnite-new-deal)), Aarki CTV-to-mobile gaming in Q1 2026 ([Yahoo Finance](https://finance.yahoo.com/news/aarki-lg-ad-solutions-launch-130000239.html)), and CCR Media and AdImpact for local markets. At the 2026 NewFronts, LG claimed "ACR data from 200 million smart TVs globally" ([Ad Measurement Weekly](https://www.admeasurementweekly.com/posts/lg-ad-solutions-own-the-outcome-ctv-measurement-newfronts)).
- **Purchase linkage** (LoopIQ with Affinity Solutions, card transactions) dates from 2023 and is unchanged ([LG Ads](https://lgads.tv/affinity-solutions/)).
- **For tvgw** these are server-side. None adds an endpoint the TV contacts. They raise the value of each ACR event, which raises the value of the port wall and the canary fix. They change no rule.
- **Copilot (December 2025)** was a home-screen shortcut to Microsoft's site in the browser, pushed to webOS 24/25 sets; LG promised to make it deletable ([Tom's Hardware](https://tomshardware.com/monitors/televisions/lg-says-microsoft-copilot-on-webos-tvs-is-a-browser-shortcut-not-a-built-in-app), [PCWorld](https://www.pcworld.com/article/3018846/lg-will-let-tv-owners-remove-microsofts-copilot-app-after-backlash.html)). No report puts it on webOS 5 (unverified absence).
- **webOS 26 "LG Shield"** is LG's marketing for platform security ([LG IFA 2026](https://www.lg.com/us/press-release/lg-electronics-introduces-an-award-winning-ai-tv-experience-at-ifa-2026)). It is not on the CX.

### 1.10 What changes in the rule set and the must-allow list

| Item | Change? | Evidence |
|---|---|---|
| `\|\|alphonso.tv^` | Keep. It already covers all 41 `tkacrNNN` hosts, and HaGeZi's LG and Pro lists carry it too (checked 2026-11-01: [filter_72](https://adguardteam.github.io/HostlistsRegistry/assets/filter_72.txt), [filter_48](https://adguardteam.github.io/HostlistsRegistry/assets/filter_48.txt)) | §1.1 |
| **New firewall rule:** reject TCP 4001, 4431, 4445, 4447, 8180, 8883 from the TV, counted, comment `LG adtech port` | **Add**, after the CX history check | §1.2, §1.8 |
| `\|\|nevoai-iothub-54-prod.azure-devices.net^` | **Replace** with `/^([a-z0-9]+-)?nevoai-iothub-[0-9]+-prod\.azure-devices\.net$/`; same for the category pattern | §1.8 (lab set used `qs2-nevoai-iothub-12-prod`, not on any list) |
| `rdl.`, `wiseconfig.`, `ads.lgtvcommon.com` | **Add** custom `\|\|host^` rules (today they rest on HaGeZi alone) | §1.8 |
| `lgchhomeapp.lgtvcommon.com` category | **Move** from `LG core` (by suffix) to `LG ads` | §1.8 |
| LG Channels FAST hosts (`transmit.live`, `amagi.tv`, `fast.nbcuni.com`, `ott-channels.stingray.com`) | **Categorize** (new `FAST` category, or `Streaming`); do not block | §1.8 |
| `*.amagi.tv` | **Do not block** (breaks LG Channels); redact titles in the pack | §1.3 |
| `ACR_PERIOD` / `ACR_PAYLOAD` / red line 7 | **Replace** with the upload-heavy test, keeping the cadence test as a secondary mark | §1.1 |
| `[must_allow]` | **No change.** Reword `snu.lge.com`'s reason | §1.6 |
| Profile webOS 26 note on the Texas pop-up | **Correct** to "LG must update its smart TVs; model scope unverified" | §1.5 |
| `lgads.tv`, `lgsmartad.com`, LG IoT hosts | Keep | §1.4 and §1.9 add no new hosts |
| QuickSet, Hue, voice back-ends | Keep | Unchanged by 2026 findings |

---

## 2. What to build here

Ranked by value to the owner against risk. Effort: S is a day or two, M a week, L more. Risk is to the running gateway.

1. **Fix the ACR detector (red line 7).** *S effort, no risk (report-only).*
   - In `queries.py`, add `acr_uploader`: per registrable domain, or per /24 for unnamed flows, per day, flag when payload up ≥ `ACR_UP_MIN = 1_000_000` bytes, payload up ≥ `ACR_RATIO = 4` × payload down, and connections ≥ 24, in a category outside `expected_categories`.
   - Keep `acr_like`, but widen it to a base period of 10-200 s with jitter measured against the nearest multiple of the median, so 60/120/180 s opens count as one timer.
   - Feed the new flag into red line 7 and into the analyst's novelty check.
   - Test with synthetic flows built from the published statistics (1-3 min connections, 94 KB median, 60 s spacing). Do not use the trace, which is NoDerivatives.
   - Acceptance: the synthetic LG ACR day fires; the CX's last 30 days fire only on names already blocked (test 3 in §3).
2. **The `LG adtech port` wall, plus the rule-set fixes in §1.10.** *S effort, low risk; the firewall part is a change the owner approves.*
   - In `tv_out`, before the odd-port log rule: `tcp dport { 4001, 4431, 4445, 4447, 8180, 8883 } counter reject with tcp reset comment "LG adtech port"`.
   - In `lg-webos.rules`: the Nevo regex, and the `rdl.`, `wiseconfig.` and `ads.lgtvcommon.com` rules. In `lg-webos.toml`: the `lgchhomeapp` and FAST categories.
   - Add the comment prefix to `queries.FW_LINES` and to `verify`'s expected rules.
   - Prerequisite: test 1 in §3 shows the CX never used these ports for anything that worked.
   - Prove the rule in the namespace harness already in flight before it reaches the Pi.
3. **Title redaction for FAST hostnames.** *S effort, low risk.*
   - Add a profile key `title_bearing = ["amagi.tv"]`.
   - In `analyst.scrub`, rewrite any label under those zones that is not `amg\d+` to `title`. Apply the same rewrite in the brief's text output when `--redact-titles` is set.
   - Unit test: `amg01234-some-show-lg.amagi.tv` becomes `amg01234-title.amagi.tv`.
   - Note in privacy-and-retention.md that the store keeps the names in full, as it keeps all query names.
4. **Treat firmware changes as re-baseline events.** *S-M effort, low risk.*
   - Promote the Firmware section to a red line for 72 h after a version change: "firmware changed: re-check settings".
   - Run `tvgw tvcheck` at once (the hourly run already notes the change).
   - Pin the new hosts that follow an update into the analyst's pack with the label `post_firmware`.
   - Reword `snu.lge.com`'s `[must_allow]` reason to "firmware: occasional fixes; LG's stated security window for 2020 sets has ended; each update may add consent screens and endpoints".
   - Fix the webOS 26 generation note (§1.5).
5. **Limit what the Pi itself may send to the TV.** *S effort, low-medium risk* (a mistake breaks `tvgw tvcheck`, not the TV's internet).
   - In the `output` chain: `oifname "eth0" ip daddr $TV_IP tcp dport { 3000, 3001 } meta skuid != 0 counter drop comment "TV API from non-root"`.
   - Drop all other new TCP and UDP from the Pi to the TV, except DHCP replies and ICMP.
   - This is what stands between a compromised qBittorrent, Samba, xrdp or AirPlay daemon and the TV's 3001 pre-auth bugs. tvcheck runs as root in `tvgw-analyze` (architecture.md, trust boundaries), so it keeps working.
   - Prove it in the namespace harness, then on the Pi: `sudo -u nobody curl -m 3 http://$TV_IP:3000/` must time out, and the hourly `tvgw tvcheck` must still read.
6. **Read every privacy toggle the LAN API exposes, not only Live Plus.** *M effort, no risk (reads only).*
   - The settings IMC 2024 needed for a full LG opt-out: Limit Ad Tracking; Do Not Sell; the Viewing Information, Voice Information and Interest-Based & Cross-Device Advertising agreements; Who.Where.What; Home Promotion; Content Recommendation; AI Recommendation; Live Plus ([arXiv 2409.06203](https://arxiv.org/html/2409.06203v1), Table 1).
   - Gamers Nexus reports "Do Not Sell" off by default ([Decrypt](https://decrypt.co/377637/lg-tv-might-be-listening-even-when-off)).
   - Which of these webOS 5's `getSystemSettings` returns is **unverified**. Probe once (test 6 in §3) and store whatever answers, as `[[privacy_setting]]` records for profiles v2 (in flight).
7. **A private lab-comparison command.** *M effort, no risk.*
   - `tvgw compare-lab PARQUET` reads a locally downloaded *Watching the Watchers* parquet with DuckDB, outside the Pi, on the workstation.
   - It prints names the lab LG contacted that `lg-webos` puts in `Other`, and blocked names the lab LG never contacted.
   - It writes nothing into the repository, which respects the NoDerivatives licence.
   - The first run's output is in §1.8.

**Do not build:**

- A `*.amagi.tv` block: it breaks FAST.
- An early `STRICT_PORTS=yes`: item 2 is cheaper and decision 17's evidence process stands.
- IoT Inspector on the Pi: it ARP-spoofs.
- Any audio or standby "detection": the CX has no far-field microphone, and nothing on the wire can see an offline audio queue.

---

## 3. Tests to run on the gateway (owner, read-only unless stated)

1. **Has the CX ever used the ad-tech ports?**
   `sudo tvgw sql "select dport, count(*), sum(bytes_up), min(datetime(t_start,'unixepoch')), max(datetime(t_start,'unixepoch')) from flows where dport in (4001,4431,4445,4447,8180,8883) group by dport"`
   Then the odd-port log: `sudo tvgw sql "select dport, count(*) from oddport group by dport order by 2 desc limit 20"`.
   Empty means item 2 is free.
2. **Does the CX still look up Alphonso with Live Plus off?**
   `sudo tvgw sql "select qname, count(*), sum(blocked), datetime(min(t),'unixepoch'), datetime(max(t),'unixepoch') from dns where qname like '%alphonso%' group by qname order by 2 desc limit 30"`
   Lookups that keep coming with Live Plus off match the paper's residual traffic and are harmless while blocked. A rising count after a firmware change is a signal.
3. **Would the new detector fire on normal days?**
   `sudo tvgw sql "select dst, count(*) n, sum(max(0,bytes_up-40*pkts_up)) pu, sum(max(0,bytes_down-40*pkts_down)) pd from flows where t_start > strftime('%s','now','-30 days') group by dst, date(t_start,'unixepoch') having pu > 1000000 and pu > 4*pd and n >= 24 order by pu desc limit 20"`
   Then name each address with `tvgw host`. Expect nothing, or only blocked telemetry.
4. **Is there an Amagi title channel on this TV?**
   `sudo tvgw sql "select name, dns_n, tls_n, datetime(last_seen,'unixepoch') from hosts where name like '%amagi%' order by dns_n desc limit 20"`
   Hyphenated title slugs mean item 3 is urgent. If none appear, play an LG Channels channel for five minutes and run it again.
5. **Does the gateway hand the TV the Pi's name?**
   `dig +short -x <GW_IP> @<GW_IP>` must print nothing (NXDOMAIN). A name there is one more "secondary device" fact for the TV to upload.
6. **Which privacy toggles can the LAN API read?** (Reads only.)
   `sudo /opt/tvgw-venv/bin/bscpylgtvcommand -p /var/lib/tvgw/lgtv-keys.sqlite <TV_IP> get_system_settings general '["dnt","limitAdTracking","doNotSell","homePromotion","contentRecommendation"]'`
   The key names are guesses (**unverified**). Record which return values and which error.
7. **Does the CX send the Alexa probe or the Nevo variant?**
   `sudo tvgw sql "select qname, count(*), sum(blocked) from dns where qname like '%avsxappcaptiveportal%' or qname like '%nevoai%' or qname like '%transmit.live' group by 1"`
   A `nevoai` name that was not blocked means the regex in item 2 is needed now.
8. **Which Pi processes talk to the TV?**
   `sudo ss -tnp state established dst <TV_IP>` once an hour for a day. Only tvgw's own Python should appear. This is the evidence for item 5.

---

## 4. Open questions

- **Port 4431 on webOS 5.** Does the CX's ACR client (if Live Plus were on) use 4431 like the 2026 lab set? The only way to know is a deliberate, owner-approved run with Live Plus on, which this project should not do. Test 1 and the odd-port history are the passive substitute.
- **The Texas pop-up.** Will it reach webOS 5 / 04.6x firmware, and with what default? Watch the Firmware section and red line 2 after each update.
- **Wi-Fi off.** With Wi-Fi switched off in the menu, does webOS 5 still survey nearby SSIDs (Gamers Nexus's geolocation vector)? This cannot be answered from the wire, and the upload would ride an allowed LG host inside TLS. Unanswerable without root, and decision 4 stands.
- **US 04.64 date.** Is the US build of 04.64 the same as the EU file dated 2026-05-13, and what changed? "Minor bug fixes" hides it. The brief's post-firmware host diff is the only evidence tvgw can get.
- **The Gamers Nexus RCE.** Which services and webOS generations? Watch LG's [TV bulletins](https://lgsecurity.lge.com/bulletins/tv) (the page did not render for this pass's fetcher).
- **Court approval.** Was the Texas agreed judgment entered, and does it bind beyond Texas? (Reporting says Texas only.)

---

## Sources

Primary research and data:

- Mammadov, Joshi, Dubois, Choffnes. *Watching the Watchers*, PoPETs 2027. [PDF](https://watchingthewatchers.github.io/watchingthewatchers/paper.pdf), [page](https://watchingthewatchers.github.io/watchingthewatchers/paper.html), [repository](https://github.com/IlgarNEU/Watching-the-Watchers), [Zenodo LG ACR CSV 22733487](https://zenodo.org/records/22733487), [Zenodo LG parquet 22698120](https://zenodo.org/records/22698120)
- Anselmi et al. *Watching TV with the Second-Party*, IMC 2024. [arXiv 2409.06203](https://arxiv.org/html/2409.06203v1)
- CVE-2023-6317: [CVE record](https://cveawg.mitre.org/api/cve/CVE-2023-6317), [Bitdefender](https://www.bitdefender.com/blog/labs/vulnerabilities-identified-in-lg-webos)
- SSD advisories: [sync-demo pre-auth RCE, 2026-10-12](https://ssd-disclosure.com/lg-webos-sync-demo-preauth-rce/), [path traversal / SMR-SEP-2025](https://ssd-disclosure.com/lg-webos-tv-path-traversal-authentication-bypass-and-full-device-takeover/)
- [chronomaly-webos (CVE-2025-38352)](https://github.com/AnalyticETH/chronomaly-webos)
- HaGeZi lists via AdGuard registry: [filter_72](https://adguardteam.github.io/HostlistsRegistry/assets/filter_72.txt), [filter_48](https://adguardteam.github.io/HostlistsRegistry/assets/filter_48.txt)
- [IoT Inspector 3.0.18 on PyPI](https://pypi.org/project/iot-inspector/3.0.18/), [NYU IoT Inspector](https://inspector.engineering.nyu.edu/), [Mon(IoT)r intl-iot](https://github.com/NEU-SNS/intl-iot)

LG primary pages:

- [Security update policy for webOS TV (2022-04-19)](https://www.lg.com/uk/support/announcement/GBNTC20220419152260/)
- [OLED55CX3LA software list (LG Romania)](https://www.lg.com/ro/suport/produs/lg-OLED55CX3LA)
- [Updated user agreements (US)](https://www.lg.com/us/support/help-library/how-to-accept-the-updated-user-agreements-on-your-lg-tv-CT10000018-20155426555618)
- [LG IFA 2026 release](https://www.lg.com/us/press-release/lg-electronics-introduces-an-award-winning-ai-tv-experience-at-ifa-2026)
- [LG Ads LoopIQ](https://lgads.tv/affinity-solutions/)

Regulation:

- [Texas AG complaint release, 2025-12-15](https://texasattorneygeneral.gov/news/releases/attorney-general-paxton-sues-five-major-tv-companies-including-some-ties-ccp-spying-texans)
- LG settlement: [Fox 7](https://www.fox7austin.com/news/lg-smart-tv-acr-data-collection-texas-settlement), [CIPAWorld](https://cipaworld.com/2026/05/11/texas-obtains-smart-tv-privacy-settlement-with-lg-heres-what-changes/), [Bloomberg Law](https://news.bloomberglaw.com/litigation/lg-changes-data-collection-consent-to-end-texas-tv-spy-suit)
- Kentucky HB 692: [Hunton](https://www.hunton.com/privacy-and-cybersecurity-law-blog/kentucky-classifies-smart-tv-data-as-sensitive), [Communications Daily](https://communicationsdaily.com/news/2026/04/15/Kentucky-Amends-Privacy-Law-to-Regulate-TV-Automated-Content-Recognition-2604140049)
- [ICO via Cybernews](https://cybernews.com/privacy/uk-watchdog-smart-tvs-collect-personal-data/)
- [FTC Vizio 2017](https://www.ftc.gov/news-events/news/press-releases/2017/02/vizio-pay-22-million-ftc-state-new-jersey-settle-charges-it-collected-viewing-histories-11-million)
- DPDP Rules: [Deccan Herald](https://www.deccanherald.com/amp/story/india%2Fcentre-notifies-dpdp-rules-implementation-planned-in-phases-spread-over-12-18-months-3798465), [Mondaq](https://www.mondaq.com/dpdp-act-and-rules-2025-the-2026-compliance-milestones-businesses-cant-afford-to-miss/1830402)

Investigation coverage (secondary; the primary is the Gamers Nexus video of 2026-09-06):

- [CyberInsider](https://cyberinsider.com/lg-smart-tvs-found-scanning-home-networks-for-nearby-devices/)
- [IT-Connect](https://www.it-connect.tech/lg-tvs-allegedly-scan-your-local-network-and-listen-in-standby/)
- [Notebookcheck](https://www.notebookcheck.net/LG-smart-TVs-caught-logging-audio-with-screen-off-and-snooping-on-local-devices.1391214.0.html)
- [The Cyber Sec Guru](https://thecybersecguru.com/?p=25090)
- [The Next Web](https://thenextweb.com/news/lg-smart-tv-acr-denial-industry-standard-eu)
- [Latin Times](https://www.latintimes.com/lg-denies-tv-spying-claims-these-are-questions-its-statement-doesnt-answer-599148)
- [Decrypt](https://decrypt.co/377637/lg-tv-might-be-listening-even-when-off)
- [Malwarebytes](https://www.malwarebytes.com/fr/blog/privacy/2026/09/lg-tv-flaws-could-let-attackers-listen-in-even-in-standby-mode)
- [Economie Matin (363 million)](https://www.economiematin.fr/?p=231476)
- [TechRadar](https://www.techradar.com/televisions/lgs-denial-over-tv-spying-claims-does-not-address-the-full-privacy-picture-experts-say-after-report-accuses-it-of-making-216-000-000-spy-tvs)
- [Pillitteri on LG terms](https://pasqualepillitteri.it/en/news/28655/lg-smart-tv-what-you-agree-to-terms)

Industry:

- [Databricks deal](https://www.advanced-television.com/2025/10/22/lg-ad-solutions-partners-with-databricks/)
- [Magnite](https://www.thedrum.com/news/lg-s-ad-team-brings-automatic-content-recognition-data-magnite-new-deal)
- [Aarki](https://finance.yahoo.com/news/aarki-lg-ad-solutions-launch-130000239.html)
- [NewFronts 2026](https://www.admeasurementweekly.com/posts/lg-ad-solutions-own-the-outcome-ctv-measurement-newfronts)
- Copilot: [Tom's Hardware](https://tomshardware.com/monitors/televisions/lg-says-microsoft-copilot-on-webos-tvs-is-a-browser-shortcut-not-a-built-in-app), [PCWorld](https://www.pcworld.com/article/3018846/lg-will-let-tv-owners-remove-microsofts-copilot-app-after-backlash.html)
- Amagi on LG Channels: [Advanced Television](https://www.advanced-television.com/2022/05/25/banijay-rights-collaborates-with-amagi-to-go-fast/), [Filmibeat](https://filmibeat.com/television/news/2025/atrangii-launches-fast-channels-on-lg-and-xiaomi-smart-tvs-powered-by-amagi-470985.html), [Señal News](https://senalnews.com/es/digital/amagi-lanzo-4fangs-nuevo-canal-fast-disponible-en-mexico-a-traves-de-lg-channels)
- [Re:New (TechRadar)](https://www.techradar.com/televisions/lg-promises-to-look-after-your-webos-tv-for-years-to-come)
- [Help Net Security on Bitdefender's 2026 IoT report](https://helpnetsecurity.com/2026/10/30/bitdefender-smart-tvs-vulnerabilities-report)
