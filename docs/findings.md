# What an LG CX does on the network, measured

This page owns what one LG CX did on the network behind a tvgw gateway over the week of 2026-10-25 to 2026-11-01, written up on 2026-11-01: a day and a week in numbers, what the apps brought, four findings the project did not find in the public record, and what the gateway still lets through. It is for a reader who wants the measurements before the machinery, and for anyone comparing another TV. How each number is made is in [how it was measured](#how-it-was-measured), and what each section of the brief means is in [the brief's sections](reading-the-brief.md#sections).

## The set and the week

One TV: an LG OLED55CX (`OLED55CXPUA`), webOS 5.6.2, firmware 04.64.00, the set the `lg-webos` profile was built on. It is cabled to the gateway's TV port with its Wi-Fi network forgotten, and on 2026-11-01 its own LAN API reported wired connected, Wi-Fi and Wi-Fi Direct disconnected and tethering off. Live Plus, LG's automatic content recognition (ACR), is off, and the TV's consent record reads `eula.acrAllowed false`, `eula.voiceAllowed false`, `eula.customAdAllowed false` and `eula.thirdPartySharingAllowed false`.

The numbers below come from two briefs run on 2026-11-01: the last 24 hours (2026-10-31 to 2026-11-01) and the last 7 days, over a store that held 6.8 days of data. Sizes are as the brief prints them, in powers of 1024 (`cli.hb()`). That day `sudo tvgw verify` passed every check, `tv_paths` and `flowlog_events` among them.

## A day in numbers

In 24 hours the TV made 4,595 lookups of 96 distinct names. The resolver blocked 4,029 of them, 88%. The TV opened 813 connections and moved 840.9 MB up and 62.1 GB down, almost all of it video.

Lookups by the profile's categories:

| Category | Lookups | Blocked | Names |
|---|---|---|---|
| LG ads | 29 | 29 | 3 |
| LG telemetry | 155 | 155 | 3 |
| LG fingerprint | 1056 | 1056 | 2 |
| LG core | 85 | 0 | 4 |
| 3rd-party ads | 2743 | 2743 | 16 |
| Streaming | 441 | 8 | 37 |
| Infra | 6 | 0 | 3 |
| Other | 80 | 38 | 28 |

Connections by category. A blocked name gets no address, so the blocked categories open none:

| Category | Connections | Up | Down |
|---|---|---|---|
| LG core | 76 | 177.1 KB | 794.3 KB |
| Streaming | 602 | 804.5 MB | 59.4 GB |
| Infra | 14 | 226.4 KB | 13.7 MB |
| Other | 58 | 35.7 MB | 2.7 GB |
| Unresolved | 7 | 3.0 KB | 20.5 KB |
| Gateway | 56 | 275.4 KB | 8.8 MB |

Most blocked lookups are a few names asked again and again. A blocked answer carries a 60-second TTL (`blocked_response_ttl` in src/tvgw/adguardcfg.py), and each client retries on a timer of its own. The busiest, from the brief's "Blocked and still retried", with the blocked lookups per hour the TV was on:

| Name | Lookups | Per hour on | What it is |
|---|---|---|---|
| `global.telemetry.insights.video.a2z.com` | 931 | 40.5 | Prime Video telemetry |
| `unagi-na.amazon.com` | 931 | 40.5 | Prime Video client telemetry |
| `www.ueiwsp.com` | 925 | 40.2 | Universal Electronics QuickSet, which identifies HDMI devices |
| `browser-intake-datadoghq.com` | 538 | 23.4 | Datadog's browser-SDK intake, used by an app |
| `cws.conviva.com` | 228 | 9.9 | Conviva video analytics |
| `us.rdx2.lgtvsdp.com` | 149 | 6.5 | LG telemetry |
| `discovery.meethue.com` | 131 | 5.7 | Philips Hue bridge discovery |

The two Prime Video names were asked exactly as often as each other, about 40 times an hour each, and the profile files them with the preinstalled apps' background telemetry. QuickSet kept the same pace. A third Prime Video name, `<device-hash>.us-east-1.prod.service.minerva.devices.a2z.com` (77 lookups, blocked), carries a 63-character hexadecimal label, so the lookup alone tells any resolver on the path which device is asking; the brief's DNS oddities list it as a 110-character name. QuickSet and Hue stay blocked with their cost written down ([design decision 16](design-decisions.md#16-quickset-and-hue-stay-blocked-with-the-cost-written-down)).

The rest of the day, from "Firewall held": the firewall rejected 13 QUIC packets, so the apps fell back to TCP, and the TV tried no DoT, DoQ or DoH. It dropped 2,740 packets toward the home LAN, where the brief's LAN probes section lists five home-LAN addresses tried on port 80, 266 times each, and 1,522 aimed at the Pi's other addresses. Nothing went over IPv6. The clock hosts were looked up 52 times and never blocked. Among the allowed names, the timers the brief found were heartbeats of half an hour to an hour (`api.amazon.com` every 3011 s, Peacock's config every 1808 s); none ran near 15 seconds.

## The week in numbers

Over the 7 days the TV made 36,235 lookups of 270 distinct names, and 30,729 were blocked, 85%. It opened 8,059 connections and moved 5.6 GB up and 398.0 GB down (in decimal units, 6 billion and 427 billion bytes).

The finding of the week is the line for the hours the TV was off or in standby:

```text
While off/asleep (27 h): 0 lookups, 0 connections, up 0B
```

This CX is silent when it is off: no lookup, no connection and no byte in 27 hours of off time. The line counts the intervals between readings outside `AWAKE` (`Active`, `Screen Off` and `Screen Saver` in src/tvgw/queries.py), so a TV that talks in standby shows here ([while off or asleep](reading-the-brief.md#while-off-or-asleep)).

The week's other red lines, in the brief's order:

- One lookup of the Content Store's feed, `us.lgrecommends.lgappstv.com`, came back blocked. It is a must-allow host because the store fails without it, which the profile records from 2026-10-26.
- Four of 806 recorded `tvgw verify` runs failed, the last with `tvgw-dnsgate` down.
- Two ACR-shaped uploads on the first day, described under [what the detectors found on day one](#what-the-detectors-found-on-day-one).
- Ingest warnings: on 2026-10-31 conntrack lost events six times (ENOBUFS), so connections that ended then are missing and the connection counts are a floor. Since 2026-11-01 the flow log hears the TV alone ([design decision 43](design-decisions.md#43-the-flow-log-hears-the-tv-alone-and-the-gates-day-starts-at-each-answer)), and `flowlog_events` reported no dropped events that day.

Over the week the firewall redirected 6 DNS packets aimed at another resolver to AdGuard Home and rejected 57 QUIC packets. The DNS gate counted 401 new connections to addresses no lookup had returned; in the day's brief, every logged sample was "just looked up", the TV connecting within seconds of an answer before the feeder had added the address, not a hardcoded server.

## What the apps bring

The TV's own background is small and steady. The apps are where the names come from.

**The NFL app.** The day it was first used behind the gateway, the brief's New hosts table filled with names that, by their domains, belong to its stack:

- its own hosts: `api.nfl.com`, `flags.api.nfl.com`, `static.www.nfl.com`, `imagecomposer.nfl.com`;
- video delivery from Lura (`dcs.mp.lura.live` and its regional names, with an Akamai front) and the THEOplayer player (`license.theoplayer.com`, `discovery.theo.live`, `fastly.cdn.theo.live`);
- PubNub's realtime channel (`ps6.pndsn.com`) and two SDK services, `app-us2.namiml.com` and `claspws.tv` (`sdk.`, `config.`, `ip.`);
- blocked by the lists in force: Adobe Analytics (`smetrics.nfl.com`, `edge.adobedc.net`), Adobe Audience Manager (`dpm.demdex.net`), Sentry's ingest, Bitmovin's analytics ingress, `events.claspws.tv` (asked 25 times) and Nielsen (`cdn-gl.imrworldwide.com`).

Two names under the app's own domains, `p.nfltags.com` and `sedge.nfl.com`, read like a tag server and an edge collector. They resolved, were allowed, and sit in "Allowed, outside the expected categories": a first-party name in front of a third-party service passes a name-based filter until someone judges it. The CNAME answers that would show what is behind them are not part of this write-up.

**YouTube.** Its panel-research names are per device: `<uuid>-panelresearch.googlevideo.com`, whose label the brief's DNS oddities flag as random (4.1 bits per character over 50 characters), and `eligibility-panelresearch.googlevideo.com`. Both are blocked by the profile's rule for Google's TV viewing panel.

**Disney+.** Its edge API, `disney.api.edge.bamgrid.com`, carried 33.9 MB up and 2.3 MB down in 47 connections in the day: more than 14 times as much up as down, to an API host, not a video host. It is in the Streaming category, which the profile expects, so the ACR upload test does not look at it ([design decision 45](design-decisions.md#45-the-acr-red-line-is-an-upload-test-and-a-port-wall)). An expected category is a judgment, and this is the kind of traffic it lets pass.

## Four findings not in the public record

The project's two research passes did not find these in the published record. Each is stated with its evidence and its status.

### BLE advertises with no switch

**Evidence.** On 2026-11-01 a nearby phone saw the TV advertising over Bluetooth Low Energy continuously, while the TV's own LAN API reports `network.bleAdvertisingOnOff off` (the brief's TV settings, 2026-11-01). webOS 5 offers no supported way to stop it; the known method needs a rooted set ([design decision 40](design-decisions.md#40-the-tvs-radios-are-checked-not-assumed)).

**Status.** A presence leak, not a data path: the advertisement carries nothing to anyone without a relaying app on a nearby device. The gateway records the key as a setting and raises no red line on it, because a line that is true every hour is not an alarm ([the November report, section 1](research/state-of-the-art-2026-11.md#1-radios-and-side-channels)).

### Wi-Fi disconnected is not Wi-Fi off

**Evidence.** The TV reports Wi-Fi disconnected, which is its association state. LG's own privacy statement of 2026-09-12 confirms that its TVs survey access points when the relevant agreements are accepted, and nothing on the LAN API reports whether the radio is listening or probing ([the November report, section 1](research/state-of-the-art-2026-11.md#1-radios-and-side-channels)).

**Status.** Since 2026-11-01 the gateway reads the association state every hour, and `tv_paths` in `tvgw verify` fails when Wi-Fi, Wi-Fi Direct or tethering is on ([design decision 40](design-decisions.md#40-the-tvs-radios-are-checked-not-assumed)). The radio itself stays unknown: a radio switched on between two readings, or a probe while disconnected, is not seen. The test for it is an RF audit with a separate monitor-mode adapter, not yet run.

### A firmware after the security window

**Evidence.** LG's stated security-update window for its 2020 sets ended in 2025, yet firmware 04.64 was published on 2026-05-13 with "minor bug fixes", according to LG's Romanian support list for the model as read by [the November report, section 5](research/state-of-the-art-2026-11.md#5-lgs-acr-on-the-wire-and-one-detector) (row 18 of [its re-verified claims](research/state-of-the-art-2026-11.md#14-claims-re-verified-for-this-report)). This CX runs 04.64.00.

**Status.** LG's update host, `snu.lge.com`, stays on the must-allow list, since a 2020 set still receives firmware. A new firmware is a change the brief reports: its Changes in effect section read `firmware unchanged (04.64.00)` on 2026-11-01.

### The 15-second ACR timer is inside a connection

**Evidence.** LG's ACR is often said to upload every 15 seconds, and that is read as a connection cadence. Rebuilt as conntrack sees it, the released *Watching the Watchers* trace of a newer LG shows the client opening a connection about every 60 seconds on TCP 4431 and sending a fingerprint of about 22 KB every 14 to 15 seconds inside it, for 10 to 39 MB up on an ACR day at 7 to 17 times the bytes down. A detector keyed on a 10 to 20 second period between connections cannot fire on it: tvgw's own earlier test was such a detector and fired on 0 of 17 days of the trace ([design decision 45](design-decisions.md#45-the-acr-red-line-is-an-upload-test-and-a-port-wall)).

**Status.** Since 2026-11-01 the ACR red line is an upload test keyed by name and port, plus a wall on LG's ad-tech ports, TCP 4001, 4431, 4445, 4447, 8180 and 8883 (`ADTECH_PORT_WALL=yes`). On this CX, with Live Plus off, the store holds no connection to any of those ports in the whole record (measured 2026-11-01), and the week's "adtech ports" counter is 0.

## What the detectors found on day one

The upload test of [design decision 45](design-decisions.md#45-the-acr-red-line-is-an-upload-test-and-a-port-wall), run on 2026-11-01 over the stored week, fired twice, both on 2026-10-25, the first day of the record, when both names still resolved:

```text
RED LINE: ACR-shaped upload: browser-intake-datadoghq.com:443 sent 2.7 MB up (17.6x down) in 7 connections in hour <HH> of 2026-10-25; Live Plus reads off
RED LINE: ACR-shaped upload: amazon.com:443 sent 1.1 MB up (16.3x down) in 17 connections in hour <HH> of 2026-10-25; Live Plus reads off
```

Both are upload-heavy telemetry, not ACR. They went to port 443, to an analytics intake and to Amazon's registrable domain, where `unagi-na.amazon.com`, Prime Video's client telemetry, was that day's biggest non-video uploader (961 KB in 9 connections, from the comment on its rule in [lg-webos.rules](../src/tvgw/profiles/lg-webos.rules)). Live Plus read off throughout. The test fires on this shape whatever the name: the line says what it saw, and the owner decides. Both names are blocked now, and the 24-hour brief lists them under "Blocked and still retried".

## What gets through, by design

- **Prime Video's ads.** They are stitched into the stream from the same CDNs as the show; blocking the ad-pod service did not remove them (tried 2026-10-25).
- **Everything inside TLS.** tvgw decrypts nothing. It sees names, sizes and timing, never content ([design decision 3](design-decisions.md#3-no-tls-interception)).
- **First-party telemetry until judged.** A collector under an app's own domain resolves until the owner or the analyst blocks it, and the brief lists such names under "Allowed, outside the expected categories" every day.
- **The lifelines.** The clock host `us.lgtvsdp.com`, the firmware host `snu.lge.com` and the connectivity check stay allowed on purpose: webOS takes its time from LG, and a blocked clock host breaks TLS everywhere. LG sees the TV each time it starts.
- **The consent flags.** The gateway reads them every hour and cannot change them: on 04.64 the LAN API refuses writes, so settings change only with the remote ([design decision 4](design-decisions.md#4-no-rooting-of-the-tv)).
- **The home's public address.** LG, the CDNs and the streaming services see it, and the ISP sees each destination and its TLS server name.
- **Bluetooth.** The BLE advertisement above reaches any phone in range.

## How it was measured

Every number here comes from the gateway's own record. `tvgw-flowlog` logs each finished connection from conntrack's events with its bytes each way; dumpcap keeps the TV's packets in hourly files, and the hourly ingest reads each connection's TLS ClientHello so that every connection is named by its own hello ([naming a connection](architecture.md#naming-a-connection)); AdGuard Home's query log gives every lookup and whether it was blocked; `tvgw tvcheck` reads the TV's settings, consent flags and network paths over its LAN API every hour; and `tvgw brief` reports them from the store ([what the capture keeps](privacy-and-retention.md#what-the-capture-keeps)). The BLE observation is the one measurement made off the gateway, with a phone.

The limits: one TV, one firmware, one household's apps and one week. Connections that ended during the lost-event bursts of 2026-10-31 are missing. The per-hour rates average over the hours the TV was on, not the hours an app was open. Apps are attributed by domain name, not by process. Nothing here carries over to another model or firmware without its own measurement ([grading evidence](adding-a-profile.md#grading-evidence)).
