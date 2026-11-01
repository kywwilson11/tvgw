# Upstream submissions to HaGeZi and Perflyst

Date: 2026-11-01. Status: proposal; nothing has been filed. This page lists the additions and corrections that the rules verified on the CX suggest for HaGeZi's LG webOS list and Perflyst's Smart-TV list, with the evidence each submission needs, for the owner to file when the evidence is pulled from the store ([the R&D survey](state-of-the-art-2026-10.md#22-verdicts), section 2.2: "Contribute observed LG hosts upstream", adopted).

## What was compared

- `src/tvgw/profiles/lg-webos.rules` and `lg-webos.toml` at the commit that adds this page.
- HaGeZi's `native.lgwebos` list, version 2026.1030.2308, 231 entries, in adblock syntax.
- Perflyst's `SmartTV.txt` (hosts format, exact names) and its `regex.list` extension, as on 2026-11-01, and AdGuard's registry build of them, `filter_7` ("Perflyst and Dandelion Sprout's Smart-TV Blocklist", version 1.0.14.55), which Dandelion Sprout compiles.

A rule counts as covered when the list blocks the host or a parent of it. HaGeZi's LG list covers `alphonso.tv`, `lgsmartad.com`, `lgads.tv`, `recommend.lgtvcommon.com`, `rdx2.lgtvsdp.com`, both CDP beacons, `videoads` and `adts.lgtvcommon.com`, and every `aws-prd.net` CNAME target the profile's two regexes match. It blocks none of the nine must-allow hosts.

## Which rules count as verified

Only rules the CX itself showed this project are submitted. `lg-webos.rules` says which those are:

- its header says the file "adds to HaGeZi's LG webOS list, which missed most of what this TV actually contacted on 2026-10-25";
- groups that say otherwise are excluded: the Perflyst and hugobatista hosts "never seen on this TV yet, kept for coverage", and the "newer webOS generations (unverified on this CX)" group;
- owner decisions that are not tracking (ThinQ, the voice back-ends, the home-screen declutter of other services' thumbnails) are excluded, because a list maintainer serves households that use those features.

The file's comments are a lead, not the evidence a maintainer needs. Before filing, pull each name's record from the store, as below.

## The evidence each submission needs

For every host, from the store on the Pi, and nothing site-specific:

| Field | Where it comes from |
|---|---|
| The exact names the TV looked up, with their regional prefix (`us.`, `aic.`) | the `dns` table, query below |
| First and last lookup, and lookups per day | `tvgw host NAME` |
| What the TV sent before the block, if anything reached it | `tvgw host NAME`, `tvgw top-upload SINCE` |
| When the block went in, and since then what it cost | `tvgw rules`, and the dated comment in `lg-webos.rules` |
| The set | LG OLED55CXPUA, webOS 5.6.2, firmware 04.64.00, US region |

On the Pi:

```sh
tvgw host NAME
tvgw sql "select qname, count(*) as n, date(min(t),'unixepoch') as first, date(max(t),'unixepoch') as last from dns where qname like '%NAME' group by qname order by n desc"
tvgw rules
```

Leave out anything that identifies the home: the TV's and the gateway's addresses, MAC addresses, the device name, the ZIP code the TV reports, and account-specific host names such as the AWS IoT endpoint in the ThinQ group, which names one account's broker.

## Submission 1: HaGeZi's LG webOS list

File each as a "domain to block" issue on [HaGeZi's issue tracker](https://github.com/hagezi/dns-blocklists/issues), asking for the `native.lgwebos` list. HaGeZi's native lists carry the vendor's own hosts, so only LG's zones are proposed here.

| Host | What it is, from `lg-webos.rules` | Category | Recorded cost |
|---|---|---|---|
| `homeprv.lgtvcommon.com` | home-screen promotions | LG ads | none recorded |
| `nudge.lgtvcommon.com` | promotional nudges | LG ads | none recorded |
| `ibs.lgappstv.com` | LG's ad and promotion service | LG ads | none recorded |
| `ibsstat.lgappstv.com` | its statistics host | LG ads | none recorded |
| `cdpsvc.lgtvcommon.com` | CDP telemetry service (the list has the CDP beacons) | LG telemetry | none recorded |
| `cdplauncher.lgtvcommon.com` | CDP launcher telemetry | LG telemetry | none recorded |
| `lgchhomeapp.lgtvcommon.com` | the LG Channels home app (ad-supported free TV) | LG ads | LG Channels' home screen; say so in the issue |
| `netflixvoice.lgtvcommon.com` | LG's speech service for voice search in Netflix | LG telemetry | voice search; say so in the issue |

Held back until the store shows them:

- `elastic.lgwebostv.com`: the rules file names it from community lists (`pt.elastic.lgwebostv.com`); file it only if the CX looked a name under it up.

Issue text, one issue for the six without a cost and one each for the two with a cost:

```text
List: native.lgwebos
Domains: <exact names from the store>
Device: LG OLED55CXPUA (2020 CX), webOS 5.6.2, firmware 04.64.00, US
Seen: first <date>, last <date>, about <n> lookups a day, from the TV's own resolver log
Purpose: <from the table above>
Blocked since <date> with no breakage after using <the features exercised, from the owner's notes>.
(For lgchhomeapp / netflixvoice: blocking costs <feature>.)
Not blocked by native.lgwebos as of 2026.1030.2308; the parents lgtvcommon.com and lgappstv.com also carry
the clock, store and launcher services, so a zone-level rule would break the TV.
```

## Submission 2: Perflyst's Smart-TV list

Open a pull request against `SmartTV.txt` (and `regex.list` for the correction) in [Perflyst's repository](https://github.com/Perflyst/PiHoleBlocklist). The list is in hosts format, so each line is one exact name: submit the names as the store shows them. AdGuard's `filter_7` is compiled from it by Dandelion Sprout ([adfilt](https://github.com/DandelionSprout/adfilt)), so a correction there follows.

### Additions to the LG section

Not in the list or its regexes on 2026-11-01:

| Host | What it is | Recorded cost |
|---|---|---|
| `cdplauncher.lgtvcommon.com` | CDP launcher telemetry | none recorded |
| `ibsstat.lgappstv.com` | LG ad statistics | none recorded |
| `lgchhomeapp.lgtvcommon.com` | LG Channels home app | LG Channels' home screen |
| `netflixvoice.lgtvcommon.com` | LG speech service for Netflix voice search | voice search |
| `itsmy.tv` | LG Channels promo thumbnails over plain HTTP, from the 2026-10-25 capture | the thumbnails themselves |
| `www.ueiwsp.com`, `quicksetcloud.com` | Universal Electronics QuickSet device fingerprinting, polled about every 45 seconds | automatic setup of other devices and remotes ([design decision 16](../design-decisions.md#16-quickset-and-hue-stay-blocked-with-the-cost-written-down)) |

### Additions for the preinstalled apps

Perflyst's list already has a Netflix section with `ichnaea.netflix.com` and `customerevents.netflix.com`. The CX's other preinstalled apps sent telemetry to these hosts, and the rules file records the block as free:

| Host | App | Evidence in `lg-webos.rules` |
|---|---|---|
| `unagi-na.amazon.com` | Prime Video | the TV's biggest non-video uploader, 961K in 9 connections on 2026-10-25 |
| `telemetry.insights.video.a2z.com`, `minerva.devices.a2z.com` | Prime Video | background telemetry |
| `sonar.prime-video.amazon.dev` | Prime Video | "Sonar" client telemetry, blocked without breakage |
| `ingest.webcol.sdp.peacocktv.com` | Peacock | 86K uploaded in a 45-minute session; playback, CDN switching, token refresh and pause and resume fine with it blocked (2026-10-25) |
| `userpaneltv-pa.googleapis.com` | YouTube | Google's TV user-panel API |
| `<id>-panelresearch.googlevideo.com` | YouTube | per-device panel research; a regex, `-panelresearch\.googlevideo\.com$`, for `regex.list` |
| `d.agkn.com` | Peacock's ad stack | Neustar ad-data pixel |

### Corrections

- **`lgtvcommon.com` as a whole zone.** `regex.list` has `(^|\.)lgtvcommon\.com`, and `filter_7` carries it as `||lgtvcommon.com^`. That zone also serves `aic.service.lgtvcommon.com`, which the profile keeps allowed for the Content Store and launcher services, and the profile lists the zone among those where one block at the apex took out clocks, stores or casting. Propose replacing the zone rule with the hosts the list already names one by one. Evidence needed first: block `aic.service.lgtvcommon.com` alone for one test on the CX, note what fails in the store or the launcher, and lift it.
- **`jp.lgtvsdp.com`.** The list blocks it while it already exempts `us.lgtvsdp.com` (`# #117`), the clock host. On webOS the country SDP host sets the clock (the profile's `clock_hosts` are `??.lgtvsdp.com`), and the profile's must-allow reason for `us.lgtvsdp.com` is that, blocked, the clock resets to 2019 and TLS fails everywhere. The case for Japanese sets is by analogy and unverified; say so in the pull request.
- **`us.service.lgtvcommon.com`.** The list blocks it. The CX used the `aic.` form, so file this only if the store shows the CX looking up `us.service.lgtvcommon.com`.

Found while building the Samsung profile, not on hardware, and offered as a note in the same pull request: `SmartTV.txt` blocks `www.samsungotn.net` while its own comments say software updates need it, and `regex.list` blocks the whole `samsungcloudsolution.net` zone, where the same comments put `otnprd8` to `otnprd11`, "required for software update".

## Not proposed

- **Must-allow hosts as allowlist requests.** HaGeZi's LG list blocks none of them, and Perflyst already exempts the clock host.
- **The GFTS file service.** It carries app packages and the ACR configuration under the same host names, so only a URL filter can split it ([design decision 8](../design-decisions.md#8-a-url-filter-for-lgs-file-service-instead-of-a-dns-block)); a DNS list cannot express that.
- **Rules the rules file marks unverified,** and the owner's choices that are not tracking: ThinQ (`lgtviot.com`, `lgthinq.com`), the voice back-ends, Philips Hue discovery, and the thumbnails of other services.

## Licensing

A submission is host names and this project's own description of them. Nothing from HaGeZi's GPL-3.0 lists, Perflyst's list or the PoPETs 2027 list (CC BY-NC-ND 4.0) is copied back into tvgw, which is MIT; the profiles cite them and subscribe to the first two ([design decision 24 (profiles)](../design-decisions.md#24-profiles-a-vendor-profile-without-hardware-is-dns-only-cited-and-subscribed)).
