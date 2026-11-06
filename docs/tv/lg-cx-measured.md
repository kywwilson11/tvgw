# What an LG CX does on the network, measured

You can see here what one LG CX did behind a tvgw gateway over the week of 2026-10-25 to 2026-11-01, in numbers. The page covers a day and a week, what the apps brought, four findings the project did not find in the public record, and what the gateway still lets through. It also shows how the upload budget was tried on this TV's record. It is for anyone who wants the measurements first, or who is comparing another TV.

## The set and the week

One TV: an LG OLED55CX (`OLED55CXPUA`), webOS 5.6.2, software 04.64.00, the set the LG profile was built on. It is cabled to the gateway's TV port with its Wi-Fi turned off. On 2026-11-01 the TV itself reported its wired port connected, Wi-Fi and Wi-Fi Direct disconnected, and tethering off.

Live Plus, LG's screen recognition (ACR), is off. The TV's record of its agreements says Viewing Information, Voice Information, custom ads and third-party sharing are all declined.

The numbers below come from two briefs run on 2026-11-01: the last 24 hours, and the last 7 days, over a record that held 6.8 days of data. Sizes are as the brief prints them, in powers of 1024. That day `sudo tvgw verify` passed every check, including the one that reads the TV's network paths.

## A day in numbers

In 24 hours the TV made 4,595 lookups of 96 distinct names. The filter blocked 4,029 of them. The TV opened 813 connections and moved 840.9 MB up and 62.1 GB down, almost all of it video.

The four blocked categories are LG ads, LG telemetry, LG fingerprint and third-party ads. Between them the TV made 3,983 lookups, every one was refused, and none led to a connection.

<picture>
  <source media="(prefers-color-scheme: dark)" srcset="../diagrams/fig-21-tv-day.dark.png">
  <img alt="One bar per category of the LG CX's lookups in the 24 hours to 2026-11-01, on one scale from 0, the refused part in brick and the part let through in grey. Ad and tracking companies: 2,743 lookups, all refused. Device fingerprinting: 1,056, all refused. Streaming: 441, 8 refused. LG usage reports: 155, all refused. LG's core services: 85, none refused. Not classified: 80, 38 refused. LG ads: 29, all refused. Network basics: 6, none refused. A card says what got through: 813 connections and 62.1 GB down, 59.4 GB of it streaming and 2.7 GB to the 28 names no category covers." src="../diagrams/fig-21-tv-day.light.png" width="960">
</picture>

*Every lookup of the known tracking categories was refused, and what got through was the streaming, LG's core services and names no category covers.*

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

The lookups the filter answered were for the streaming services (433 of 441), LG's core services, the infrastructure, and 42 of the 80 in Other, the names no category covers.

Connections by category. A blocked name gets the answer `0.0.0.0`, which leads nowhere, so none of the 3,983 led to a connection and the blocked categories have no row:

| Category | Connections | Up | Down |
|---|---|---|---|
| LG core | 76 | 177.1 KB | 794.3 KB |
| Streaming | 602 | 804.5 MB | 59.4 GB |
| Infra | 14 | 226.4 KB | 13.7 MB |
| Other | 58 | 35.7 MB | 2.7 GB |
| Unresolved | 7 | 3.0 KB | 20.5 KB |
| Gateway | 56 | 275.4 KB | 8.8 MB |

Most blocked lookups are a few names asked again and again. A blocked answer may be kept for 60 seconds, and each app retries on a timer of its own. The busiest, from the brief's "Blocked and still retried", with the blocked lookups per hour the TV was on:

| Name | Lookups | Per hour on | What it is |
|---|---|---|---|
| `global.telemetry.insights.video.a2z.com` | 931 | 40.5 | Prime Video telemetry |
| `unagi-na.amazon.com` | 931 | 40.5 | Prime Video client telemetry |
| `www.ueiwsp.com` | 925 | 40.2 | Universal Electronics QuickSet, which identifies HDMI devices |
| `browser-intake-datadoghq.com` | 538 | 23.4 | Datadog's browser-SDK intake, used by an app |
| `cws.conviva.com` | 228 | 9.9 | Conviva video analytics |
| `us.rdx2.lgtvsdp.com` | 149 | 6.5 | LG telemetry |
| `discovery.meethue.com` | 131 | 5.7 | Philips Hue bridge discovery |

The two Prime Video names were asked exactly as often as each other, about 40 times an hour each. QuickSet kept the same pace. QuickSet and Hue stay blocked, with their cost written down in the profile: the TV cannot set up other remotes or devices by itself, and Hue sync does not work.

A third Prime Video name, `<device-hash>.us-east-1.prod.service.minerva.devices.a2z.com`, was looked up 77 times and blocked. It carries a 63-character code that identifies the device, so the lookup alone tells any resolver on the path which device is asking.

The rest of the day, from the brief's "Firewall held":

- The firewall refused 13 packets of the newer UDP web transport, so the apps fell back to ordinary connections. The TV tried no encrypted lookups around the filter.
- It dropped 2,740 packets toward the home network. The brief lists five home addresses tried on port 80, 266 times each. Another 1,522 packets aimed at the gateway's own other addresses were dropped too.
- Nothing went over IPv6.
- The TV looked up its clock server 52 times, and it was never blocked.
- The regular timers the brief found among the allowed names were heartbeats of half an hour to an hour. None ran near 15 seconds.

## The week in numbers

Over the 7 days the TV made 36,235 lookups of 270 distinct names, and 30,729 were blocked. It opened 8,059 connections and moved 5.6 GB up and 398.0 GB down.

The finding of the week is the line for the hours the TV was off or in standby:

```text
While off/asleep (27 h): 0 lookups, 0 connections, up 0B
```

This CX is silent when it is off: no lookup, no connection and no byte in 27 hours of off time. A TV that talks in standby shows on this line.

Measured again on 2026-11-05, over 2026-10-26 to 2026-11-05: in the 29 hours between two hourly checks that both found the TV off, it made no lookup and opened no connection. So cutting the TV's connection while it is off would stop nothing on this TV today. A software update or a standby setting could change that, and the brief now names what the TV reaches when it does.

The week's red lines, in the brief's order:

- One lookup of the Content Store's feed, `us.lgrecommends.lgappstv.com`, came back blocked. The Content Store fails without it, so it is one of the names the profile keeps reachable, recorded since 2026-10-26.
- Four of 806 recorded `tvgw verify` runs failed. The last failure was a stopped background service.
- Two uploads shaped like screen recognition on the first day, described under [what the detectors found on day one](#what-the-detectors-found-on-day-one).
- Warnings while reading the logs: on 2026-10-31 the connection log lost events six times, so the connection counts are a floor. Since 2026-11-01 the log hears the TV alone, and it reported no lost events that day.

Over the week the firewall sent 6 DNS packets aimed at another server to the filter instead, and refused 57 packets of the newer UDP web transport. The gateway counted 401 new connections to addresses no lookup had returned. Every one the day's brief logged came within seconds of an answer that named the address, not from a server written into the TV's software.

## What the apps bring

The TV's own background is small and steady. The apps are where the names come from.

**The NFL app.** The day it was first used behind the gateway, the brief's New hosts table filled with names that, by their domains, belong to its stack:

- its own hosts: `api.nfl.com`, `flags.api.nfl.com`, `static.www.nfl.com`, `imagecomposer.nfl.com`;
- video delivery from Lura (`dcs.mp.lura.live` and its regional names, with an Akamai front) and the THEOplayer player (`license.theoplayer.com`, `discovery.theo.live`, `fastly.cdn.theo.live`);
- PubNub's realtime channel (`ps6.pndsn.com`) and two SDK services, `app-us2.namiml.com` and `claspws.tv` (`sdk.`, `config.`, `ip.`);
- blocked by the lists in force: Adobe Analytics (`smetrics.nfl.com`, `edge.adobedc.net`), Adobe Audience Manager (`dpm.demdex.net`), Sentry's ingest, Bitmovin's analytics, `events.claspws.tv` (asked 25 times) and Nielsen (`cdn-gl.imrworldwide.com`).

Two names under the app's own domains, `p.nfltags.com` and `sedge.nfl.com`, read like a tag server and an edge collector. They resolved, were allowed, and sit in "Allowed, outside the expected categories". A first-party name in front of a third-party service passes a name-based filter until someone decides to block it.

**YouTube.** Its panel-research names are per device: `<uuid>-panelresearch.googlevideo.com`, whose label the brief flags as random, and `eligibility-panelresearch.googlevideo.com`. Both are blocked by the profile's rule for Google's TV viewing panel.

**Disney+.** Its edge interface, `disney.api.edge.bamgrid.com`, carried 33.9 MB up and 2.3 MB down in 47 connections in the day. That is more than 14 times as much up as down, to an interface host, not a video host. It is in the Streaming category, which the profile expects, so the upload test for screen recognition does not look at it. An expected category is a judgment, and this is the kind of traffic it lets pass.

## Four findings not in the public record

The project's two research passes did not find these in the published record. Each is stated with its evidence and its status.

### Bluetooth advertises with no switch

**Evidence.** On 2026-11-01 a nearby phone saw the TV advertising over Bluetooth Low Energy continuously. Meanwhile the TV's own reading of its settings says Bluetooth advertising is off. webOS 5 offers no supported way to stop it; the known method needs a rooted set.

**Status.** It leaks the TV's presence, not data: the advertisement carries nothing to anyone without a relaying app on a nearby device. The gateway records the setting and raises no red line on it, because a line that is true every hour is not an alarm ([the November report, section 1](../research/state-of-the-art-2026-11.md#1-radios-and-side-channels)).

### Wi-Fi disconnected is not Wi-Fi off

**Evidence.** The TV reports Wi-Fi disconnected, which says only that it has not joined a network. LG's own privacy statement of 2026-09-12 confirms that its TVs survey nearby access points when the relevant agreements are accepted. Nothing the TV reports says whether the radio is listening or probing.

**Status.** Since 2026-11-01 the gateway reads the connection state every hour, and `tvgw verify` fails when Wi-Fi, Wi-Fi Direct or tethering is on. The radio itself stays unknown. A radio switched on between two readings, or a probe while disconnected, is not seen. The test for it is a radio audit with a separate wireless adapter, not yet run.

### A software update after the security window

**Evidence.** LG's stated security-update window for its 2020 sets ended in 2025. Yet software 04.64 was published on 2026-05-13 with "minor bug fixes", according to LG's Romanian support list for the model ([the November report, section 5](../research/state-of-the-art-2026-11.md#5-lgs-acr-on-the-wire-and-one-detector)). This CX runs 04.64.00.

**Status.** LG's update server, `snu.lge.com`, stays reachable, since a 2020 set still receives software. A new version is a change the brief reports: on 2026-11-01 it read `firmware unchanged (04.64.00)`.

### The 15-second screen-recognition timer is inside a connection

**Evidence.** LG's screen recognition is often said to upload every 15 seconds, and that is read as a new connection every 15 seconds. The released trace of a newer LG from the *Watching the Watchers* study shows otherwise.

The client opens a connection about every 60 seconds on TCP 4431, and sends a fingerprint of about 22 KB every 14 to 15 seconds inside it. On a day of screen recognition that is 10 to 39 MB up, at 7 to 17 times the bytes down.

A detector that looks for a new connection every 10 to 20 seconds cannot fire on it. tvgw's own earlier test was such a detector, and fired on 0 of the trace's 17 days.

**Status.** Since 2026-11-01 the red line is an upload test keyed by name and port. The firewall also refuses LG's ad-tech ports: TCP 4001, 4431, 4445, 4447, 8180 and 8883. On this CX, with Live Plus off, the record holds no connection to any of those ports (measured 2026-11-01), and the week's counter for them is 0.

## What the detectors found on day one

The upload test, run on 2026-11-01 over the recorded week, fired twice. Both were on 2026-10-25, the first day of the record, when both names still resolved:

```text
RED LINE: ACR-shaped upload: browser-intake-datadoghq.com:443 sent 2.7 MB up (17.6x down) in 7 connections in hour <HH> of 2026-10-25; Live Plus reads off
RED LINE: ACR-shaped upload: amazon.com:443 sent 1.1 MB up (16.3x down) in 17 connections in hour <HH> of 2026-10-25; Live Plus reads off
```

Both are upload-heavy telemetry, not screen recognition. They went to port 443: one to an analytics service, one to Amazon, where Prime Video's client telemetry was that day's biggest non-video upload (961 KB in 9 connections). Live Plus read off throughout. The test fires on this shape whatever the name: the line says what it saw, and you decide. Both names are blocked now, and the 24-hour brief lists them under "Blocked and still retried".

## The upload budget, measured on its own record

The gateway holds what the TV uploads each hour to a service outside its everyday ones to a budget. Before the budget went in, its first design was run on this TV's own record of 12 days, on 2026-11-05. That run changed the design.

Counted by the bytes the TV sent, the biggest upload of the 12 days went to a live-video host of the NFL app's player. It was one connection with a very large download, and 56 MB counted as sent. Those 56 MB were the TV's own replies saying what it had received. A budget of ten times that hour would have been 559 MB, and would never have caught anything.

Counted by what each connection sent beyond what came back, the video host sent nothing, and only real uploads were left:

| What | Sent beyond what came back, in its busiest hour |
|---|---|
| The analytics service of the record's first day, blocked since | 2.45 MB |
| A second tracker the same day, blocked since | 0.99 MB |
| The NFL app's own host | 0.68 MB |
| Everything else | under 0.5 MB |

So on this TV its ordinary uploads and an hour of screen recognition are only about five times apart. The budget now counts this way, and its limit always leaves an hour of screen recognition well over it. On this record that limit comes to 1.3 MB an hour.

## What gets through, by design

- **Prime Video's ads.** They are stitched into the stream from the same servers as the show. Blocking the ad service did not remove them (tried 2026-10-25).
- **Everything inside encrypted connections.** tvgw decrypts nothing. It sees names, sizes and timing, never content.
- **First-party telemetry until judged.** A collector under an app's own domain resolves until you or the analyst block it. The brief lists such names under "Allowed, outside the expected categories" every day.
- **What the TV needs.** The clock server `us.lgtvsdp.com`, the update server `snu.lge.com` and the connectivity check stay reachable on purpose. webOS takes its time from LG, and a blocked clock server breaks every secure connection. LG sees the TV each time it starts.
- **The agreements.** The gateway reads them every hour and cannot change them: on 04.64 the TV refuses changes from the network, so settings change only with the remote.
- **Your home's public address.** LG, the video servers and the streaming services see it. Your internet provider sees each destination and the name of each secure server.
- **Bluetooth.** The advertisement above reaches any phone in range.

## How it was measured

Every number here comes from the gateway's own record, which the daily brief reports:

- a log of each finished connection, with its bytes each way;
- the TV's packets, kept in hourly files, from which each connection is named by the server name it asked for;
- the filter's log of every lookup, and whether it was blocked;
- the TV's settings, agreements and network paths, read every hour.

The Bluetooth observation is the one measurement made off the gateway, with a phone. How each part works is in [the architecture](../how-it-works/architecture.md#naming-a-connection).

The limits: one TV, one software version, one household's apps and one week. Connections that ended during the lost-event bursts of 2026-10-31 are missing. The per-hour rates average over the hours the TV was on, not the hours an app was open. Apps are matched to names by domain, not by process. Nothing here carries over to another model or software version without its own measurement.
