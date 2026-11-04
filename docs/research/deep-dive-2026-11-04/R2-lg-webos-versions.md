# R2. LG webOS after webOS 5: what a gateway has to know (November 2026)

*Research record, written 2026-11-04; the code that followed is in the [CHANGELOG](../../../CHANGELOG.md) under 2026-11-04.*

*Research report, 2026-11-04. Web and repository read only; no TV was contacted and no TV software was downloaded or run. The bscpylgtv settings dumps (markdown files) and the Watching the Watchers PDF were fetched into a scratch folder and read as text. Two helper researchers swept GitHub trackers and LG's help library in parallel; I re-read the load-bearing items myself: aiowebostv #718, #720, #744, PR #501, #685, #719, LGTVCompanion #351, HaGeZi #11432, #11544, #8696, Perflyst #148, #167, the HA integration page, LG's 2026-09-12 statement, the webOS 25 US manual, the LG Italy and LG UAE help pages, and the dumps. Grades: **VERIFIED** (read in a primary source: LG page or manual, library source, the issue itself, a dump from a real set), **REPORTED** (secondary source, or one or more forum or issue reports not confirmed by a maintainer or LG), **UNCERTAIN**. "Known" marks material already in R5 (`tmp/next/R5-lg-depth.md`) or the deep dive, restated only where this pass changes or confirms it. No site identifier of the owner's home appears here.*

---

## One page: the ten findings that change what tvgw does or says

| # | Finding | Confidence | Touches |
|---|---|---|---|
| 1 | **LG's blacklist of the signed "LG Remote App" manifest is not webOS 26 only, and it breaks keys that already work.** A 2024 LCD on webOS 25 (`deviceOSReleaseVersion` 10.3.2) answers the signed manifest with `403 Pairing rejected: blacklisted certificate detected` and shows no prompt (aiowebostv #720, 2026-10-25). On a 2025 G5, an existing pairing stopped working by itself after the 43.21.71 update (#718, 2026-08-19). The behaviour moves with firmware, not with OS line: 43.11.73 still accepted it, 43.20.85 and 43.21.60 refused it. Permissions are evaluated per connection, from the manifest sent, not stored with the key (#728). So tvgw's hourly reading, which sends bscpylgtv's signed default manifest, fails on an updated set even with a good key. R5's rule (read-only manifest only when the OS major is 11 or more) is too narrow. | VERIFIED (several issues; maintainers' code changes) | SSAP reader (manifest for every new pairing, and for reads after a 403); setup's failure text; brief coverage line "the TV stopped accepting the gateway after its update" |
| 2 | **With an unsigned manifest, webOS 26 refuses `getCurrentSWInformation` (401), so the firmware number is lost.** Home Assistant ships with that error suppressed and "no solution for fetching the TV software version" (aiowebostv PR #719, 2026-08-21; HA #179669). tvgw keys a re-baseline, and the re-asking of `wifi-forgotten` (decision 57), on a firmware change. On these sets the substitute is the `hello` reply's `deviceOSReleaseVersion` (for example 11.2.0), sent before registration. Note `deviceOSVersion` reads 4.1.0 on webOS 25 and 26 sets: it is not the release. | VERIFIED for webOS 26; UNCERTAIN whether 22-25 lose it too | SSAP reader (`hello`); brief's firmware line; decision 57's "after the TV's last firmware change"; R5 R1 (already proposes `hello`) |
| 3 | **What the TV will say over SSAP is fixed per generation, and the ad switches are not in it on any generation.** The public `getSystemSettings` list in the dumps is unchanged in its privacy keys from webOS 24 to 25 (new: the G5 list, which R5 could not read). It adds Always Ready and QuickSet from webOS 6, and Home Promotion, Power On Screen, Quick Start+ and Auto Update by webOS 24 (no dump of a set on 22 or 23 exists). webOS 26 adds the standby light and automatic standby. The keys behind Limit AD Tracking (`general.lmt`, by its name), Do Not Sell, customized ads, the ad cookie, Screen Saver Promotion, Content Recommendation, Smart Tips and watched-list collection exist on every set from the CX to the G6, and none of them is in any public list. The brief can never read those. They stay the owner's dated word (decision 57). | VERIFIED that the keys exist and which lists hold them (dumps from real sets); REPORTED that a key outside the list is refused (the dump author's list, not tested by tvgw) | SSAP reader (`READS` per generation); `onscreen.py` settings (add `limit-ad-tracking`, `screen-saver-promotion`, `content-recommendation`); docs "what tvgw can check" |
| 4 | **Live Plus is still its own switch on webOS 25, beside the Viewing Information agreement, and gained a "Live Promotion" toggle.** `option.livePlus` is in every public list from webOS 5 to 26. LG says ACR is off by default, needs the Viewing Information Agreement, runs on Live TV, HDMI and LG Channels, uses audio fingerprints, and that nearby Wi-Fi access-point data "may be used to help estimate the TV's approximate location in support of ACR services" (2026-09-12). Watching the Watchers measured a 97.3% drop in ACR traffic with the sound removed, and an opt-out that works on webOS. Today's two red lines, Live Plus not off and `acrAllowed` true, hold on every generation. | VERIFIED (LG statement and manual; dumps; peer-reviewed paper) | brief red lines unchanged; docs: one more line, "Live Plus off also stops LG's use of Wi-Fi survey data for ACR" (LG's words, not measured) |
| 5 | **The menus moved: the agreements and the advertising switches live under Support > Privacy & Terms from webOS 23 on, and LG's own pages disagree about webOS 23.** webOS 25 adds App Permissions (Camera, Microphone, Nearby Devices) and Delete Viewing / Voice Information / Voice ID. Settings were renamed: Home Auto Launch became Power On Screen (23/24), Mobile TV On became TV On With Mobile, and "LG Connect Apps" vanished after the 2023 firmware wave (lgtv2 #48), with Support > IP Control Settings in its place on 2025 sets. Several of the profile's paths are wrong or webOS-5-only (section 2). | VERIFIED (LG pages and manuals), with the conflicts named | `lg-webos.toml` `[[privacy_setting]]` menus; `docs/tv/lg-webos.md` privacy table and radios block; setup's pairing hint |
| 6 | **Port 3000 (`ws`) is dead on every 2022+ set on current firmware; worse, it can accept the connection and hang.** It ended on the C2 at 03.30.16 (January 2023) and spread in the 2023 firmware wave. On 43.21.71 port 3000 accepts TCP and resets the WebSocket handshake. A 2025 QNED leaves it open and silent for minutes after power-on (aiowebostv #744, still open). The profile's one verified `[[lan_api]]` record says port 3000/ws. tvgw's code already uses 3001; the record and any fallback logic must never try 3000 first. | VERIFIED | `lg-webos.toml` `[[lan_api]]` (swap, as R5 F4 says); any future reader: 3001 only, with a connect timeout |
| 7 | **On some newer sets, LG Channels will not open with `cdplauncher` and `lgchhomeapp.lgtvcommon.com` blocked, and HaGeZi unblocked both on 2026-09-23.** A Brazilian owner of three LG TVs traced a failing LG Channels app to `aic.cdplauncher`, `aic.cdpbeacon` and `aic.lgchhomeapp.lgtvcommon.com`. HaGeZi kept `cdpbeacon` and eight other `lgtvcommon.com` names blocked and released the other two (HaGeZi #11544). The 2023 case is the same failure with `lgtvcommon.com` blocked whole (error -102, Perflyst #148). tvgw blocks both names in its own rules. On the CX, LG Channels was not reported broken. | REPORTED (one owner, models not given; the list maintainer acted on it) | `lg-webos.rules` and `[categories]`: an owner decision, either a cost written down (decision 16's pattern) or a per-generation exception; docs "What you may notice" |
| 8 | **Standby is a network state on newer sets, and three readable switches say which.** Always Ready (2022+; LG says off by default) keeps the TV answering "Hi LG", playing Bluetooth audio and taking AI-speaker commands with the screen dark, at about 6.5 W instead of 0.5 W. Quick Start+ keeps it in a warm standby, and TV On With Mobile keeps Wi-Fi or Bluetooth listening. `general.alwaysOn` (from webOS 6), `option.quickStartMode` (24+) and `network.wolwowlOnOff` (5+) are readable. The CX's finding "silent while off" (0 lookups in 27 h) cannot be assumed for a set with these on. | VERIFIED for the features (LG Canada, webOS 25 manual); UNCERTAIN what crosses the wire in that standby | SSAP reader (read the three keys where the list has them); brief: explain a non-zero "While off/asleep" line with these values; docs radios block |
| 9 | **The consent record has a second, per-document half that is readable on every generation.** `eulaInfoNetwork` sits beside `eulaStatus` in every public list (5-26). On a set that has downloaded its agreements it holds one entry per document, with `id`, `version`, `accepted` and `updated` flags. The document IDs seen on webOS 25 are S_ADG (ACR and viewing), S_VNG (voice), S_TAG (interest-based ads), S_MKT (marketing) and S_PRG (privacy). LG re-shows updated agreements after a terms change, as it did for the 2026-08-28 terms, through a restart and a "Go to Terms and Conditions" screen. With this record the brief could say "the TV is asking for agreement X again" before anyone presses OK, and tell a Terms of Use acceptance from a Viewing Information one, which R5 F7 needs. | REPORTED (the field is in the dumps; its contents on a networked set come from a rooted G5 write-up) | SSAP reader (read `eulaInfoNetwork`, keep `id`/`version`/`accepted`/`updated` only); consent classes (R5 F7); brief TV-settings line |
| 10 | **Which webOS a set runs is no longer a property of its model year, and LG says so.** LG's January 2024 release names 2022 OLED, OLED Flex, Posé and QNED Mini LED 8K for Re:New. LG's regional pages say "four upgrades over five years" and "upgrades available for 2023 include UHD and above models". webOS 26 (43.21.71) reached the 2025 G5 first and is rolling down to 2022 sets "later this year or possibly early 2027", with no way back (HDTVTest 2026-08-24). A 2022 C2 is in the dumps on webOS 26 (43.21.74). The marketing names map to SDK numbers 22 = 7.x, 23 = 8.x, 24 = 9.x on LG's developer site, with 25 = 10.x and 26 = 11.x from the sets themselves. | VERIFIED (LG developer site, LG releases, dumps); per-model schedule REPORTED | profile `[[generations]]` keyed by the OS the TV reports (R5 R1 stands); `docs/tv/lg-webos.md` "Models and versions" note |

Two smaller corrections. LG's own help page gives the webOS 5 user-agreements path as Support > Additional Settings > User Agreements; the profile says Support > Privacy & Terms. Check it on the CX. And the profile's note that the Texas ACR pop-up is "on 2027+ models" rests on one blog (Lon.tv, 2026-07-21). No source shows the pop-up shipping on any firmware as of today (UNCERTAIN).

---

## 1. Version matrix

### 1.1 Names, numbers and firmware

| Model year | LG's name | OS the TV reports (`deviceOSReleaseVersion`) | SDK line (LG developer site) | Web engine | Firmware majors seen | Re:New |
|---|---|---|---|---|---|---|
| 2020 | webOS 5 | 5.x (CX 5.6.1 at 04.63.25; this CX 5.6.2 at 04.64.00) | not listed | Chromium 68 (known) | 04 | No. Stays on 5 |
| 2021 | webOS 6.0 | 6.x (C1 6.5.3 at 03.53.45) | 6.x.x | Chromium 79 | 03 | No (BGR cites Reddit users for "at least one major overhaul": UNCERTAIN) |
| 2022 | webOS 22 | 7.x (32LQ636BPSA 7.5.7 at 04.54.40) | 7.x.x | Chromium 87 | 03 (OLED), 04 (LCD) | Yes, to 26 (LG BR); first named in LG's 2024-01-03 release |
| 2023 | webOS 23 | 8.x | 8.x.x | Chromium 94 | 03 (UNCERTAIN) | Yes; LG AE: "2023 include UHD and above models" |
| 2024 | webOS 24 | 9.x (G3 9.2.2 at 23.25.55; G4 9.2.4 at 23.23.30) | 9.x.x (SDK 9.0.0, April 2024) | Chromium 108 | 23 | Yes |
| 2025 | webOS 25 | 10.x (G5 10.2.0 at 33.21.81; 10.2.1 Level1Techs; 10.3.2 on a 65UT73006LA) | SDK 10.0.0 (March 2025, webOS 25 simulator) | Chromium 120 | 33 | Yes |
| 2026 | webOS 26 | 11.x (G6 11.1.0 at 43.11.77; C2 11.2.0 at 43.21.74; G5 11.2.0 at 43.21.71) | not listed yet | Chromium 132 | 43 | (current) |

- **VERIFIED**: the web-engine table and the SDK lines for 6.0, 22, 23 and 24, from webostv.developer.lge.com. The developer site says to read the version at Settings > General > TV Information > webOS TV version, or from `sdkVersion` in `getSystemInfo()`. The 25 = 10 and 26 = 11 mapping comes from the sets (dumps, aiowebostv #718 and #720), not from LG.
- **Firmware naming.** The firmware is `MM.mm.pp`. Before 2024 the major is not unique (03 is webOS 6 and 22; 04 is webOS 5 and a webOS 22 LCD line; known, R5 F1). From 2024 on, the major names the OS line on any model year: 23 = webOS 24, 33 = webOS 25, 43 = webOS 26 (VERIFIED in the dumps and press). Firmware-specific behaviour inside one line is real: within 43.x, signed pairing worked on 43.11.73 and failed from 43.20.85 (finding 1).
- **webOS 26 on old sets, by date.** A C2 on 43.00.74 in March 2026 (webosbrew HBC #234; REPORTED, possibly a pre-release); the G5 first (43.21.71, HDTVTest 2026-08-24); C3, G3, C4 and G4 at 43.21.71 in Spain (Xataka, 2026-09-04, REPORTED); a C2 updated on 2026-11-04 (ColorControl #601, REPORTED). webOS 26 removed the ColourSpace and bscpylgtv calibration options and VR in the browser (HDTVTest, VERIFIED as reported).
- **The Open Source Code Distribution site** (opensource.lge.com) renders its product list by script and returned no model data to a fetch. Nothing from it is used here (UNCERTAIN, not read).

### 1.2 Features per generation that matter to a gateway

| Feature | 5 (2020) | 6 (2021) | 22 | 23 | 24 | 25 | 26 | Grade |
|---|---|---|---|---|---|---|---|---|
| Live Plus (ACR, Alphonso / LG Ad Solutions) | yes | yes | yes | yes | yes | yes, plus a Live Promotion toggle | key present | VERIFIED (LG IT page, w25 manual, dumps) |
| Alphonso ownership | LG took control in January 2021 (about $80 M) and rebranded it LG Ads in March 2021, later LG Ad Solutions. Alphonso's smart-TV policy, updated May 2026, "governs LG webOS ACR" | | | | | | | REPORTED (press); policy VERIFIED |
| Home Promotion (home-screen ads) | yes | yes | yes | yes | yes, readable | yes | yes | VERIFIED (LG AE page for 6/22; w25 manual) |
| Content Recommendation | key absent on CX | from C1 | yes | yes | yes | yes | yes | VERIFIED (dumps); menu VERIFIED for 6/22 and 25 |
| Screen Saver Promotion (ads on the idle screen) | rolled out September 2024, older OLEDs included; on by default | | | | | | | REPORTED (TechRadar, What Hi-Fi, iPhoneInCanada) |
| Advertising ID (Limit AD Tracking, Reset AD ID) | yes | yes | yes | yes | yes | yes | key present | VERIFIED (LG IT page, w23 and w25 manuals) |
| "Do Not Sell My Personal Information" (US) | key present on every dump | | | | | menu on 2025 sets per Consumer Reports | | key VERIFIED; menu REPORTED |
| Always Ready | no | key only | yes (2022 sets) | yes | yes | yes | yes | VERIFIED (LG CA, w25) |
| Far-field "Hi LG" | some 2020 models | | some | | | | | known (profile `[[hardware]]`) |
| Google Cast built in | no | no | via webOS 24 | via 24 | yes | yes | yes | known (R5) |
| Copilot shortcut | no | no | | | Dec 2025 | Dec 2025 | Microsoft retires it 2026-12-01 | REPORTED |
| Privacy & Terms: App Permissions and Delete Viewing/Voice Information | no | no | | | | yes | UNCERTAIN | VERIFIED (w25 manual) |
| IP Control Settings menu (Wake on LAN on 2025+) | hidden menu | hidden | hidden | menu (w23) | | menu | | VERIFIED (w23, w25 manuals; HA docs) |
| "LG Shield" (marketing name for platform security) | | | | | | | yes | VERIFIED (LG page names it; nothing on SSAP) |

Not found in any LG source: "Additional Ad" as a setting name, and a dated "Home Dashboard" feature row. LG's UAE webOS page lists Quick Card, Home Hub, Sports Portal, AI Concierge and Always Ready as current features without years (UNCERTAIN per generation).

---

## 2. Privacy settings per version

### 2.1 Menu paths (all start at Settings > All Settings)

| Setting | webOS 5 | webOS 6 and 22 | webOS 23 | webOS 24 | webOS 25 | webOS 26 | Grade, source |
|---|---|---|---|---|---|---|---|
| Live Plus | General > Additional Settings > Live Plus | General > System > Additional Settings > Live Plus | same as 6 | same (UNCERTAIN) | General > System > Additional Settings > Live Plus; Live Promotion "Off will remove advertisements from Live Plus" | UNCERTAIN | VERIFIED: LG IT (2026-09-17), w25 manual |
| User Agreements (Viewing Information, Voice Information, Interest-Based Cross Device Advertising, Terms, Privacy) | Support > Additional Settings > User Agreements (LG IT; **the profile says Support > Privacy & Terms**) | Support > Privacy & Terms > User Agreements | same | same, with "Select All (if available)" > Agree (LG UK, 2026-04-24) | same; Privacy & Terms also holds Advertisement, App Permissions, Delete My Personal Information; EU edition adds CMP Settings | UNCERTAIN | VERIFIED |
| Limit AD Tracking, Reset AD ID | General > Additional Settings > Advertisement | General > System > Additional Settings > Advertisement | **conflict**: LG IT says Support > Privacy & Terms > Advertisement; LG's w23 manual says General > System > Additional Settings > Advertisement, with a frequency-capping cookie item | UNCERTAIN | Support > Privacy & Terms > Advertisement: "If set to On, personalized advertisements based on user interests may not be provided" | UNCERTAIN | VERIFIED (conflict noted) |
| Do Not Sell My Personal Information (US) | | | | | Support > Privacy & Terms on 2025 sets (Consumer Reports, 2025-10-19); not in the US w25 manual list | | REPORTED |
| Home Promotion; Content Recommendation; Power On Screen | General > Home Settings (Home Auto Launch) | General > System > Additional Settings > Home Settings > Home Promotion / Content recommendation / Power On Screen | same; "Home Auto Launch" renamed "Power on screen" | same | same, plus General > AI Service > AI Recommendation > Smart Tips | UNCERTAIN | VERIFIED (LG AE for 6/22, LG US default-input page, w25) |
| Screen Saver Promotion | | | | General > System > Additional Settings > Screen Saver Promotion (press) | Screen Saver Settings section exists (w25 6.13.7) | | REPORTED |
| Always Ready | none | key only | General > Always Ready Mode > Enable | General > Always Ready > "Enable the function" | same | | VERIFIED (LG CA, 2024-10-07) |
| Quick Start+ | General > Additional Settings > Q Start+ | General > Devices > TV Management > Q Start+ | General > System > Additional Settings > Quick Start+ | same | same (w25 6.13.5: "puts your device in standby mode when it's turned off") | | VERIFIED |
| TV On With Mobile (Turn on via Wi-Fi / Bluetooth) | General > Mobile TV On (HA docs, 2017+) | General > Devices > External Devices > TV On With Mobile | General > External Devices > TV On With Mobile | same | same (w25 6.12.4); EU editions: Networked Standby Mode variants | | VERIFIED / REPORTED |
| IP Control, Wake on LAN | hidden menu (82888 with focus on Connection) | hidden | Support > IP Control Settings (w23) | | Support > IP Control Settings > Wake on LAN (HA docs, 2025+) | | VERIFIED (manuals, HA docs); hidden menu REPORTED (lgtv-ip-control) |
| Hands-free Voice Control | General > AI Service > Voice Recognition (REPORTED) | General > AI Service > Voice Recognition Settings (REPORTED) | | | General > AI Service > Voice Recognition Settings > Use Hands-free Voice Control; needs the mic switch on and voice terms accepted | | VERIFIED for 25 |
| Wi-Fi | Connection > Network Connection Settings > Wi-Fi Connection | General > Network > Wi-Fi Connection | same | same | same; "Manage Saved Wi-Fi Network": "select and delete the corresponding wireless network" | | VERIFIED; no LG wording found for a Wi-Fi off switch on 6+ (UNCERTAIN) |
| Auto Update | Support > Software Update > Allow Automatic Updates (REPORTED) | 6: Customer Support > Software Update > Allow Auto Update; 22: Support > Software Update > Allow Automatic Updates | Support > Software Update > Auto Update | | same: "updates are automatically made without a separate confirmation procedure" | | VERIFIED |

### 2.2 Defaults and re-asking

- **LG, 2026-09-12 (VERIFIED):** ACR is "turned off by default" and needs the Viewing Information Agreement. Voice recognition is off by default, and the wake word is detected locally. With Hands-free on, the TV "may continue monitoring only for the wake word while in standby mode". LG uses ACR for interest-based ads only with both the Viewing Information and the Interest-Based Cross Device Advertising agreements. Declining the optional agreements "does not prevent users from using core smart TV functionality". Security updates come "for up to five years" from the release of the webOS version. Always Ready is off by default (LG CA, VERIFIED; Pocket-lint says on: conflict).
- **Values in the dumps (VERIFIED as values; that they are factory defaults is UNCERTAIN, though the device name is the factory "[LG] webOS TV" and `countPowerOn` is 0):**
  - on: `homePromotion`, `contentRecommendation`, `screenSaverAd`, `adCookie`, `aiNudge`, `livePromotion`, `webOSPromotionVideo`, `watchedListCollection`, `thirdPartyCookie`, `voiceLongDistance`, `network.ipv6Enable`, `allowMobileDeviceAccess`;
  - off: `livePlus`, `lmt` (Limit AD Tracking off), `customizedAd`, `doNotSellMyPersonalInformation`, `alwaysOn`, `quickStartMode`, `ueiEnable`, `automaticUpdate`, `enableIpControl`, `bleAdvertisingOnOff`;
  - every `eulaStatus` flag is false except `networkAllowed`.
- **Re-asking.** LG re-shows the agreements after a terms change: the 2026-08-28 update (mainly arbitration), with a restart, "Go to Terms and Conditions" and the updated documents highlighted. Declining the required terms brings the screen back at the next use of a smart service (REPORTED: LG US page through a search summary). In 2018, webOS 4.0 required agreement to revised terms after a reboot (VERIFIED, LG CA). No LG page says an update resets an optional switch. Reports that Live Plus or Wi-Fi come back on after updates are owners' word only (REPORTED/UNCERTAIN). The "Reset Advertising ID" item is an action, with no readable state.
- **Texas.** Settled 2026-05-11: a pop-up disclosure with consent, a clear opt-out, the same text on LG's website (REPORTED, press). No firmware or model carrying it was found (UNCERTAIN).

### 2.3 The Luna keys behind them, and what SSAP returns

`getSystemSettings` takes a `category` and a list of `keys`. The bscpylgtv dumps (from real sets: CX 5.6.1, C1 6.5.3, G3 9.2.2, G4 9.2.4, G5 10.2.0, G6 11.1.0, C2 11.2.0) list every key in each category, then the subset "that can be retrieved by the public API". A non-rooted TV answers only that subset (REPORTED: the dump author's list). Counts: CX 31, C1 47, G3/G4 117, G5 136, G6/C2 149 (computed here).

| Setting | Key (category.key) | In the public read list | Grade of the key-to-menu mapping |
|---|---|---|---|
| Live Plus | `option.livePlus` | 5, 6, 24, 25, 26 | VERIFIED (tvgw reads it on the CX) |
| Live Promotion | `option.livePromotion` | never | inferred from the name and the w25 text |
| Viewing Information agreement | `eulaStatus.acrAllowed` (+ `acrOnAllowed`, `acrAdAllowed`, `acrGdprAllowed`); document S_ADG in `eulaInfoNetwork` | 5-26 | flags: tvgw reads them on the CX; S_ADG REPORTED (Level1Techs, G5) |
| Voice Information agreement | `eulaStatus.voiceAllowed`, `voice2Allowed` (also `option.voiceAllowed` on 25); S_VNG | 5-26 (eulaStatus) | REPORTED |
| Interest-based ads agreement | `eulaStatus.customAdAllowed` / `customadsAllowed` (UNCERTAIN which); S_TAG | 5-26 | UNCERTAIN |
| Marketing; privacy policy; terms | `marketingOnAllowed` / S_MKT; S_PRG; `generalTermsAllowed` | 5-26 | REPORTED |
| New flags | 6+: `shoppingOnAllowed`, `veranceOnAllowed`, `wasuOnAllowed`; 26: `installerTermsOnAllowed`. Counts 22 (CX), 25 (C1-G5), 26 (G6, C2) | | VERIFIED counts (computed here) |
| Limit AD Tracking | `general.lmt` | never | inferred ("lmt" is the OpenRTB name for limit ad tracking) |
| Do Not Sell | `general.doNotSellMyPersonalInformation` | never | name |
| Customized ads; ad cookie | `general.customizedAd`; `general.adCookie` | never | name |
| Screen Saver Promotion | `general.screenSaverAd` | never | name |
| Home Promotion | `general.homePromotion` | 24, 25, 26 | VERIFIED (name and menu) |
| Power On Screen | `general.homeAutoLaunch` | 24, 25, 26 | VERIFIED |
| Content Recommendation | `other.contentRecommendation` (6+) | never | name |
| Personal recommendation; Smart Tips | `general.personalRecommend`; `general.aiNudge` | never | inferred |
| Watched-list collection | `option.watchedListCollection` | never | name |
| Always Ready | `general.alwaysOn` | 6, 24, 25, 26 | VERIFIED |
| Quick Start+ | `option.quickStartMode` | 24, 25, 26 | VERIFIED |
| TV On With Mobile (Wi-Fi) | `network.wolwowlOnOff` | 5-26 | inferred (WoL/WoWLAN) |
| Auto device detection (QuickSet) | `other.ueiEnable` | 6, 24, 25, 26 | known (R5) |
| Auto Update | `support.automaticUpdate` | 24, 25, 26 | VERIFIED |
| Hands-free voice; mic | `general.voiceLongDistance`; `voiceframework.voice_mic` (26) | never | inferred |
| BLE advertising | `network.bleAdvertisingOnOff` | 5-26 | known: the CX reads `off` while it advertises (observed) |
| IPv6 | `network.ipv6Enable` (`"true"` on every dump) | never | VERIFIED value |
| IP Control | `option.enableIpControl` (`off`), `IPControlSecureKey` | never | VERIFIED value |
| Standby light; automatic standby | `option.standByLight`; `time.automaticStandBy` | 26 only | VERIFIED |
| Network paths | `ssap://com.webos.service.connectionmanager/getstatus` (CX, observed); `.../getinfo` (aiowebostv 0.8.0, works unsigned on a webOS 26 G5; 404 on webOS 2) | n/a (a service, not a key) | VERIFIED for CX and webOS 26 G5 |

**Do not read:** `option.addressInfo`, `option.zipcode` and `localeInfo` are in every public list and hold a postal address or locale (known; R5 "do not do").

---

## 3. Pairing and the LAN API across versions

| Item | Finding | Grade, source |
|---|---|---|
| ws on 3000 | Ended on the C2 at 03.30.16 around 2023-01-18 (homebridge-webos-tv #474, LGWebOSRemote #107, PyWebOSTV #83, ColorControl changelog 2023-01-19, bscpylgtv 0.4.3). Then spread: NANO916NA (lgtv2 #48, 2023-10-30); lgtv2's maintainer: "since the 2023 firmware wave TVs only accept wss://<tv>:3001" (#49, 2026-08-21). CX at 04.64.00 refuses it (known). A C8 (webOS 4) still answers on 3000 (HA #182555 comment, 2026-10-11) | VERIFIED |
| 3000 on current firmware | G5 at 43.21.71: TCP accepted, WebSocket handshake reset (aiowebostv #718). 2025 QNED on Wi-Fi: TCP accepted, no answer for minutes after power-on, then refused (#744, open); a wired G4 was not affected | VERIFIED |
| TLS on 3001 | One static leaf on every TV, "LGE TV SSG", issued by "LGE SSG Intermediate CA", valid 2018-03-12 to 2034-08-15 (lgtv2 source). A webOS 26 C6 still needs certificate checks off. No TLS version or cipher change reported. Pinning that leaf adds nothing, since every LG presents it | VERIFIED (source); no-change REPORTED |
| Handshake changes | webOS 25 (33.20.6x beta, June 2025): `hello` must carry `"payload": {}`, and `getSystemInfo` must be sent before `register` (HA #147557; aiowebostv PR #501, 2025-07-06). bscpylgtv 0.5.1 added connect retries "(WebOS 25)" | VERIFIED |
| Pairing types | `hello` advertises them: PIN, PROMPT, COMBINED on webOS 25 (10.2.0); plus LGSWITCH-PIN on webOS 26 (11.2.0). bscpylgtv 0.5.3 supports all four (`ssap://pairing/setPin`). With the signed manifest all four are rejected alike. No report confirms PIN pairing works on new firmware. Every client sends `forcePairing: false` | VERIFIED (source, issues); PIN UNCERTAIN |
| The signed-manifest blacklist | 403 "blacklisted certificate detected", no prompt: 43.00.92 (LGTVC #347, 2026-04-17), 43.20.85 (a B4, BetterDisplay #5665), 43.21.60/62/71/73; also webOS 25 10.3.2 (aiowebostv #720). Accepted: 43.11.73 (OLED77C67LA, until its update to 43.21.60), G4 on 33.31.68. A factory reset did not help on an OLED42C6 | VERIFIED |
| Unsigned manifest | Pairs with the on-screen prompt. Reads work (`getSystemSettings`, `listApps`, `connectionmanager/getinfo`). `settings/setSystemSettings` answers 401. `getCurrentSWInformation` answers 401. The pointer socket needs `CONTROL_MOUSE_AND_KEYBOARD` and is still refused on some firmware. Permissions that existed only in the signed block are not granted without a new pairing (PR #719). Moving them to the outer block does not restore software info (reported by an HA user). | VERIFIED |
| Key lifetime | "Once (lifetime)", per the HA maintainer; repeated prompts come from demo mode, or a "memory problem" fixed by a factory reset (HA #181741, 2026-09-17). Owners report re-authorisation every few months (HA #153151) and a TV re-asking by itself (ColorControl #601). LGWebOSRemote #158 (2024-04-19): "403 too many pairing requests", cleared only by unplugging the TV. Existing keys survived the 33.20.6x handshake change. Under webOS 26 they fail with the signed manifest, then "401 … not registered" | VERIFIED / REPORTED |
| Reading a TV that is off | SSAP answers only while the TV is on, or in a standby that keeps the network up: Quick Start+, Always Ready, TV On With Mobile. Wake-on-LAN: HA docs give General > Mobile TV On > Turn On Via WiFi (2017+) and Support > IP control settings > Wake on LAN (2025+), recommend Ethernet, and say the old "LG Connect Apps" switch must be on. LGTV Companion says "Turn on via Wi-Fi" must be on even on Ethernet, and the magic packet is layer 2, same subnet. lgtv2 1.9.0 sends to both the wired and Wi-Fi MACs (C1 at 03.53.45 came back about 2 s after the packet) | VERIFIED |
| LG IP Control (port 9761, raw TCP) | A second LAN control API: the hidden menu (focus on Connection, then 82888) enables "Network IP Control" and generates an 8-character keycode. Commands are AES-encrypted; on 2025 sets it is a visible Support > IP Control Settings menu. Off by default (`option.enableIpControl: off`). An owner uses it on webOS 26 where SSAP writes fail (LGTVC #351) | REPORTED (lgtv-ip-control, LGTVC #351); default VERIFIED (dumps) |
| Developer Mode app | Needs an LG developer account; opens SSH on 9922 (user `prisoner`); time-limited; disabled after 10 reboots without network or when the session ends. No tracker reports that it changes SSAP pairing or permissions. It is a precondition for the chronomaly root on 33.22.65-33.30.97 (known) | VERIFIED (LG developer site); no SSAP effect: UNCERTAIN (absence of reports) |

**Consequences for tvgw's reader:**

1. **Pair every new TV with an unsigned, read-only manifest.** R5 R2 proposes one, but switches to it only from OS major 11. Use it from webOS 22 up at least, and for every new pairing if the owner's CX can be tested. Keep reads after a 403 on the same manifest.
2. **Expect no firmware number on webOS 26 with that manifest.** Read `hello` before `register`, and track `deviceOSReleaseVersion`. Treat its change as the software-change event where `firmware` reads `ERR 401`.
3. **Stop the hourly reading after a refusal.** After `401 not registered`, a 403, or a prompt reply on a stored key, stop reading until `sudo tvgw tv pair`, as `tvprobe` already does. Decision 54 lets the hourly reading try again each hour. On a TV that has forgotten the gateway, that is a prompt on the screen every hour, and it risks "403 too many pairing requests", which only unplugging the TV clears.
4. **Use 3001 only, with a connect timeout.** Never fall back from 3000 (#744).
5. **Never send Wake-on-LAN, and never touch IP Control.** Both are known; this pass found nothing to change that.

---

## 4. Network behaviour per version

### 4.1 Hosts by function

| Function | 5 | 6 | 22-26 | Blockable without breaking the TV? | In tvgw today | Grade, source |
|---|---|---|---|---|---|---|
| Clock (`X-Server-Time` from SDP; NTP off) | `<cc>.lgtvsdp.com` | both | `<cc>.nextlgsdp.com` | **No.** A wildcard block of `nextlgsdp.com` cost the clock and the store (Perflyst #167, 2026-09-24); Canada needed `ca.nextlgsdp.com` for the store, voice and login (2026-10-25) | `clock_hosts` patterns; must-allow `us.` only | REPORTED; R5 F5 templates confirmed |
| Store and downloads | `<cc>.lgrecommends.lgappstv.com`, `<cc>.tvsdp.lgeapi.com`, `ngfts.lge.com` | + `ngfts.nextlgsdp.com`, `<rg>-gfts.nextlgsdp.com` | same; `kic-ngfts.lge.com`, `qt2-ngfts.lge.com` | No | must-allow (US) | known |
| Firmware | `snu.lge.com` | same | + `su.lge.com`, `su-ssl.lge.com`, `nsu.lge.com`, `snu-dev`/`su-dev.lge.com`; hard-coded fallback `156.147.69.32:8080` | Yes, but then no security fixes (LG: up to five years) | `snu.lge.com` must-allow; the others are `LG core` by suffix; the fallback is counted | REPORTED (Level1Techs, G5 webOS 10.2.1) |
| ACR | `tkacrNNN.alphonso.tv`, `prov-lg.`, `bl-server.`, `clockskew.alphonso.tv`; TCP 4001/4431/4445/4447 | same | same; 41 Alphonso FQDNs on the lab set | Yes (the paper recommends `*.alphonso.tv`) | blocked, plus the port wall | VERIFIED (PoPETs 2027) |
| LG ads | `<cc>.ad`/`<cc>.info.lgsmartad.com`, `ads`/`adts`/`videoads.lgtvcommon.com` (8180) | same | same | Yes | blocked | known |
| LG telemetry and launcher | `rdx2.lgtvsdp.com`, `cdpbeacon`, `cdpsvc`, `cdplauncher`, `rdl`, `wiseconfig.lgtvcommon.com` | same | + `rdx2.nextlgsdp.com`; GN list: `aic.cdpsvc`, `aic.cdpbeacon`, `aic.rdl` with no agreement accepted | Mostly. **`cdplauncher` and `lgchhomeapp` may be needed by LG Channels** (finding 7) | all blocked | REPORTED (HaGeZi #11544, Perflyst #167) |
| LG Channels (FAST) | `amagi.tv`, `wurllg.global.transmit.live`, Stingray, NBCU | same | same | No, if the household watches it; the Amagi names carry the channel | `FAST`, allowed | known |
| ThinQ, IoT, push | `lgtviot.com`, `lgthinq.com`, AWS IoT `:8883` | same | + `ocp.lgtviot.com` (counters), `aic.commonpush`, `aic.sports` | Yes (ThinQ app control lost) | blocked | known |
| Voice | Alexa AVS; Google Assistant ended 2025-05-01 | same | + `lgsmartweb.com` (voice search, Level1Techs) | Yes (voice lost) | `Voice` blocked; `lgsmartweb.com` not categorised | REPORTED |
| Setup telemetry | | | `initscr.lge.com` (boot-time setup telemetry, one audit) | Unknown: setup flows not tested by its reporter | not categorised | UNCERTAIN |
| Ad domains claimed for a G1 | | `ad.lgappstv.com`, `adsdtvc.com`, `smart.adtvc.app` | | all NXDOMAIN on 2026-09-11 | n/a | VERIFIED dead (HaGeZi #11432) |

### 4.2 What newer versions do to resist a DNS filter

| Behaviour | Evidence | Grade | What tvgw does |
|---|---|---|---|
| Hard-coded resolvers | The CX tried 8.8.8.8 (observed here). A rooted-G1 audit says webOS daemons use 8.8.8.8 and 1.1.1.1 directly, and some ignore the hosts file | observed (CX); REPORTED (G1) | DNAT of port 53 already |
| DoT and DoH | Only low-grade guides claim a DoH, then DoT, then 53 order on LG firmware, and their tables contradict each other. The CX sent no encrypted lookups in a week. LG's Chromium engines (87-132) could do DoH for the browser only if it were enabled (UNCERTAIN) | UNCERTAIN | 853 refused; QUIC refused |
| Hard-coded IPs | `156.147.69.32:8080` OTA fallback in `/usr/sbin/update`; `54.186.247.229:443` AWS telemetry, ephemeral (Level1Techs, webOS 25) | REPORTED | counted; do not hard-code the AWS address |
| Certificate pinning | None reported. On webOS 3, SDP's `initservices` checks no certificate at all, because the clock is not set yet (wisq/lgtv-sdp). Nothing for newer versions | UNCERTAIN | tvgw decrypts nothing, so pinning would not matter to it |
| IPv6 | `network.ipv6Enable` is `"true"` on every dump, 5 to 26. Nothing went over IPv6 on the CX here | VERIFIED value | keep the TV segment IPv4-only, or filter IPv6 the same way |
| Wi-Fi while wired | No report found either way. LG says nearby access-point data serves ACR location estimates, so the radio scans when it is on | UNCERTAIN | getstatus every hour (CX); the RF audit is open (deep dive 01) |
| Radios when "off" | Always Ready plays Bluetooth audio and listens for the wake word with the screen off. TV On With Mobile listens on Wi-Fi or Bluetooth in standby. The CX advertises BLE with no switch (observed). The rest of the Gamers Nexus claims are known (deep dive 05 §1.4) | VERIFIED features; traffic UNCERTAIN | read `alwaysOn`, `quickStartMode` and `wolwowlOnOff` (finding 8) |
| LAN scanning | LG calls it "device-discovery functions", "not used for household profiling" (2026-09-12). webOS 25 adds a per-app Nearby Devices permission | VERIFIED (LG's words) | contained: the TV segment holds only the Pi (known) |

Which?, Mozilla Privacy Not Included and rtings were searched and yielded no LG-specific network measurement from 2024 to 2026 (UNCERTAIN, absence). The one 2026 peer-reviewed measurement of LG remains Watching the Watchers (unnamed US LG set, April-May 2026, controlled with aiowebostv). The paper adds that LG's ACR endpoint keeps receiving about 5% of tracked traffic after opt-out, of unknown purpose.

---

## 5. What the gateway should do per generation

| Generation | Pairing to expect | Settings readable over SSAP | Brief: alarm on | Hosts: block / must-allow | Tell the user to check on the TV | Confidence |
|---|---|---|---|---|---|---|
| **webOS 5** (2020; CX) | PROMPT on wss 3001. A key made with the signed manifest works today on 04.64.00. 3000 refused | `option.livePlus`, `eulaStatus`, `eulaInfoNetwork`, `network.bleAdvertisingOnOff`, `network.wolwowlOnOff`, getstatus paths, software info | Red: Live Plus not off; any privacy-class flag true; a second path. TV settings: firmware change, `wolwowlOnOff` on | as today | Limit AD Tracking (General > Additional Settings > Advertisement), Home Promotion, the agreements path (check: LG says Support > Additional Settings > User Agreements) | observed; paths VERIFIED (LG) |
| **webOS 6** (2021) | as webOS 5; signed manifest accepted (no blacklist report) | + `general.alwaysOn` (key only, no feature), `other.ueiEnable` | + QuickSet on as a TV-settings line | both SDP families must stay reachable; must-allow templates by region | menus under General > System > Additional Settings (Live Plus, Advertisement, Home Settings > Home Promotion and Content recommendation); agreements under Support > Privacy & Terms; Wi-Fi under General > Network | dumps VERIFIED; behaviour on the wire REPORTED (EU C1 captures) |
| **webOS 22** (2022 sets, before Re:New) | wss 3001 required since 03.30.16; signed manifest accepted (no report against it) | as webOS 6 | + Always Ready on (TV settings; red only if the owner decides, R5 question 6) | as webOS 6 | as webOS 6; Always Ready under General > Always Ready Mode | REPORTED (no dump of a set still on 22) |
| **webOS 23** | as webOS 22 | UNCERTAIN (no dump on 23); expect webOS 22's list | as 22 | as 22 | Advertisement may be under Support > Privacy & Terms or General > System > Additional Settings (LG conflict); Power On Screen replaces Home Auto Launch | UNCERTAIN |
| **webOS 24** | PROMPT; the signed manifest is still accepted on reported 23.x firmware | + `general.homePromotion`, `general.homeAutoLaunch`, `option.quickStartMode`, `support.automaticUpdate` | + Home Promotion on, Quick Start+ on, Auto Update off (TV settings lines, not red) | + Google Cast needs `<cc>.nextlgsdp.com` | Screen Saver Promotion; Limit AD Tracking; Always Ready; Quick Start+ | VERIFIED (G3, G4 dumps); behaviour REPORTED |
| **webOS 25** (2025 sets; 2022-2024 sets updated) | PROMPT; `hello` with an empty payload and pre-registration system info. **The signed manifest is refused on some 10.3.x firmware** (#720): pair unsigned | as 24 (G5 list VERIFIED, same privacy keys) | as 24; plus "TV refused the gateway's pairing" as a coverage line | as 24; `lgsmartweb.com` to Voice; firmware hosts `su`/`su-ssl`/`nsu.lge.com` to LG core | Support > Privacy & Terms: Advertisement (Limit AD Tracking, Reset AD ID), App Permissions (Microphone, Nearby Devices), Delete Viewing Information; Live Promotion off; Support > IP Control Settings left off | VERIFIED (G5 dump, w25 manual); pairing VERIFIED for one model |
| **webOS 26** (2026 sets; Re:New sets on 43.x) | **unsigned manifest only**; a key made under 25 may stop working after the update; a factory reset does not help; one prompt per new pairing | as 25, + `option.standByLight`, `time.automaticStandBy`; **no software info** (401) | as 25; software change from `deviceOSReleaseVersion`; a new consent flag (`installerTermsOnAllowed`) classed `unknown` until known | as 25 | as 25; the microphone switch on far-field models; after the update, re-check the agreements screen | VERIFIED (G6, C2 dumps, HA and aiowebostv); menus UNCERTAIN (no LG webOS 26 manual found) |
| **Unknown or webOS 27** | unsigned; one prompt | base list; ask nothing outside the profile's list | as 26 | as 26 | the owner's word for every switch the TV does not report | inference |

**Every generation:**

- Read `eulaInfoNetwork` with the flags, and keep only `id`, `version`, `accepted` and `updated` per document (finding 9).
- Never read `addressInfo`, `zipcode` or `localeInfo`, and never store `deviceUUID`.
- Keep the TV segment IPv4-only.
- Count the OTA fallback address.
- For LG Channels, ask the owner (finding 7).

---

## Sources (all read 2026-11-04)

**LG (vendor, primary)**
- webOS TV web engine table: https://webostv.developer.lge.com/develop/specifications/web-api-and-web-engine
- SDK introduction (22 = 7.x.x, 23 = 8.x.x, 24 = 9.x.x): https://webostv.developer.lge.com/develop/tools/sdk-introduction
- SDK release notes (SDK 10.0.0, March 2025, webOS 25 simulator): https://webostv.developer.lge.com/develop/tools/sdk-release-notes
- Developer Mode app: https://webostv.developer.lge.com/develop/getting-started/developer-mode-app
- LG statement, "Understanding privacy on LG smart TVs", 2026-09-12: https://www.lg.com/global/newsroom/news/statements/statement-understanding-privacy-on-lg-smart-tvs/ (US copy: https://www.lg.com/us/newsroom/corporate/statement-understanding-privacy-on-lg-smart-tvs)
- LG Re:New release, 2024-01-03 (via CNW): https://newswire.ca/news-releases/more-lg-smart-tv-owners-set-to-enjoy-the-latest-webos-upgrade-making-their-tvs-feel-brand-new-802691695.html
- LG UAE webOS page (four upgrades over five years; 2023 UHD and above): https://www.lg.com/ae/webos-smart-tv/webos
- LG Brazil, Re:New (known; R5): https://www.lg.com/br/sobre-a-lg/press-media/a-nova-era-do-lg-webos/
- LG Italy, ads and Live Plus paths per version, page dated 2026-09-17: https://www.lg.com/it/supporto/supporto-prodotto/risoluzione-anomalie/help-library/cs-CT52001071-20153387508381/
- LG UAE, home screen settings, webOS 6.0 and 22: https://www.lg.com/ae/support/product-help/CT20076005-20153529296767LST
- webOS 25 US manual: https://www.lgappstv.com/manual/w25/w25_u01/enga.html ; EU: https://www.lgappstv.com/manual/w25/w25_eu03/eng.html
- webOS 23 manual, Advertisement: https://www.lgappstv.com/manual/w23_mr2/global/Contents/settings/system/advertisement_k_u_b_e_c_a_t_j/enga/w23__settings__system__advertisement_k_u_b_e_c_a_t_j__enga.html ; TV On With Mobile: https://www.lgappstv.com/manual/w23_mr2/global/Contents/settings/externaldevice/tvonmobile_e_a/eng/w23__settings__externaldevice__tvonmobile_e_a__eng.html
- Read by the help-library sweep (VERIFIED by it; not re-read by me): LG UK agreements https://www.lg.com/uk/support/product-support/troubleshoot/help-library/cs-CT00008333-20155142857269/ ; LG CA Always Ready https://www.lg.com/ca_en/support/product-support/troubleshoot/help-library/cs-CT52001643-20153280995350/ ; LG CA webOS 4.0 agreements https://www.lg.com/ca_en/support/product-support/troubleshoot/help-library/cs-CT20098005-20150814211607/ ; LG US default input https://www.lg.com/us/support/help-library/lg-tv-how-to-set-the-default-input--20153711388714 ; LG NZ software update https://www.lg.com/nz/support/product-support/troubleshooting/help-library/cs-CT52007864-20153265672601LST/ ; LG US Always Ready webOS 22 https://www.lg.com/us/support/help-library/lg-tv-settings-i-would-like-to-learn-about-the-features-of-the-always-ready-mode-webos22--20154857966614 ; LG US updated agreements (search summary only) https://www.lg.com/us/support/help-library/how-to-accept-the-updated-user-agreements-on-your-lg-tv--20155426555618
- LG Shield page: https://lgshield.lge.com/en/product/b2c/416d89a3-32d9-4150-95ae-0838442b8dc7
- Not readable: opensource.lge.com (script-rendered list)

**Library source and dumps (community; real sets)**
- bscpylgtv dumps: https://github.com/chros73/bscpylgtv/blob/master/docs/available_settings_CX.md and the C1, C2, G3, G4, G5 and G6 files beside it
- bscpylgtv CHANGELOG, `webos_client.py`, `constants.py` (pairing types), `docs/manifests/manifest-comp.json`: https://github.com/chros73/bscpylgtv
- aiowebostv `webos_client.py`, `handshake.py`, `endpoints.py` and releases (1.0.0 on 2026-11-03; 0.9.2 on 2026-08-21): https://github.com/home-assistant-libs/aiowebostv
- aiowebostv PR #501 (pre-registration system info): https://github.com/home-assistant-libs/aiowebostv/pull/501 ; #685 (connection info): https://github.com/home-assistant-libs/aiowebostv/pull/685 ; #719 (webOS 26 handshake; software info 401): https://github.com/home-assistant-libs/aiowebostv/pull/719
- lgtv2 source and CHANGELOG (static TLS leaf; 2.0.1 signed-then-unsigned; WOL to both MACs): https://github.com/hobbyquaker/lgtv2

**Trackers**
- aiowebostv #718: https://github.com/home-assistant-libs/aiowebostv/issues/718 ; #720: https://github.com/home-assistant-libs/aiowebostv/issues/720 ; #728: https://github.com/home-assistant-libs/aiowebostv/issues/728 ; #744: https://github.com/home-assistant-libs/aiowebostv/issues/744
- Home Assistant core #172703, #147557, #153151, #178294, #179669, #180025, #181741, #182555: https://github.com/home-assistant/core/issues/172703 (and the same path with each number)
- LGTV Companion #347, #351, README: https://github.com/JPersson77/LGTVCompanion/issues/351
- Orishas/webostv-webos26-fix: https://github.com/Orishas/webostv-webos26-fix
- lgtv2 #48, #49: https://github.com/hobbyquaker/lgtv2/issues/48
- LGWebOSRemote #107, #158: https://github.com/klattimer/LGWebOSRemote/issues/107
- PyWebOSTV #83: https://github.com/supersaiyanmode/PyWebOSTV/issues/83
- homebridge-webos-tv #474: https://github.com/merdok/homebridge-webos-tv/issues/474
- ColorControl #601: https://github.com/Maassoft/ColorControl/issues/601 ; LG_Buddy #76: https://github.com/Staphylococcus/LG_Buddy/issues/76 ; BetterDisplay #5665: https://github.com/waydabber/BetterDisplay/issues/5665 ; webosbrew HBC #234: https://github.com/webosbrew/webos-homebrew-channel/issues/234
- HaGeZi #11544 (LG Channels unblock, 2026-09-23): https://github.com/hagezi/dns-blocklists/issues/11544 ; #11432: https://github.com/hagezi/dns-blocklists/issues/11432 ; #8696, #5622 (same path)
- Perflyst #167 (2026-09-07 to 10-25): https://github.com/Perflyst/PiHoleBlocklist/issues/167 ; #148: https://github.com/Perflyst/PiHoleBlocklist/issues/148
- furkan-bayrak/lg-tv-blocklist and docs/methodology.md (rooted G1, Germany): https://github.com/furkan-bayrak/lg-tv-blocklist
- Level1Techs, "LG TV Block Mini-How-to" (OLED65G5WUA, webOS 10.2.1, 2026-09-05): https://forum.level1techs.com/t/lg-tv-block-mini-how-to/255178
- WesSouza/lgtv-ip-control: https://github.com/WesSouza/lgtv-ip-control
- wisq/lgtv-sdp: https://github.com/wisq/lgtv-sdp
- Home Assistant webostv integration page: https://www.home-assistant.io/integrations/webostv/

**Peer-reviewed and policy**
- Mammadov, Joshi, Dubois, Choffnes, "Watching the Watchers", PoPETs 2027 (PDF): https://watchingthewatchers.github.io/watchingthewatchers/paper.pdf
- Alphonso, Smart TV Privacy Policy (US), updated May 2026: https://alphonso.tv/privacy/smart-tvs/smart-tv-privacy/

**Press (REPORTED)**
- HDTVTest, webOS 26 to older TVs, 2026-08-24: https://www.hdtvtest.co.uk/news/lg-starts-bringing-web-os-26-to-older-t-vs-starting-with-the-lg-g5-oled
- Xataka (known; R5): https://www.xatakahome.com/televisores/tienes-tele-lg-2023-2024-ahora-parecera-2026-puedes-descargar-version-webos-modelos-modernos
- Screen Saver Promotion: https://www.techradar.com/televisions/your-lg-tv-will-now-show-screensaver-ads-even-on-oleds-but-here-s-how-to-turn-them-off ; https://www.iphoneincanada.ca/2024/09/26/lg-tv-screensaver-ads-how-to-disable/
- Alphonso deal: https://nexttv.com/news/lg-buys-controlling-stake-in-alphonso-for-dollar80-million ; https://digitaltveurope.com/2021/03/02/alphonso-rebrands-as-lg-ads
- Texas settlement: https://www.fox7austin.com/news/lg-smart-tv-acr-data-collection-texas-settlement ; https://blog.lon.tv/2026/07/21/ken-paxtons-texas-settlement-on-lg-tv-spying-is-barely-a-slap-on-the-wrist/
- Consumer Reports, smart TV snooping (updated 2025-10-19): https://www.consumerreports.org/electronics/privacy/how-to-turn-off-smart-tv-snooping-features-a4840102036/
- CyberSecurityNews, 2026-09-07 (Gamers Nexus coverage): https://cybersecuritynews.com/lg-smart-tvs-caught-scanning-networks/

---

## Open questions only a newer LG set in hand can answer

1. **The read-only manifest on the CX.** Does a key paired with an unsigned, read-only manifest read `firmware`, `eulaStatus`, `eulaInfoNetwork` and getstatus on a webOS 5 CX? And does switching the CX's existing key to that manifest put a prompt on the screen? (Owner, about 10 minutes.)
2. **Software info by generation.** On webOS 22 to 25 with an unsigned manifest, does `getCurrentSWInformation` answer, or 401 as on 26? Is any other unsigned call left that returns the firmware number?
3. **getstatus by generation.** Does `connectionmanager/getstatus` (lower case) answer on webOS 6 to 26? Is `getinfo` the only path on 26, and what are its state words for Wi-Fi off, on and disconnected, and for Wi-Fi Direct?
4. **`eulaInfoNetwork` on a networked set.** What does it hold on a set that has downloaded its agreements? Which ID is the Interest-Based Cross Device Advertising agreement, and which `eulaStatus` flag goes with it (`customAdAllowed` or `customadsAllowed`)? Do `updated` and `version` change when LG pushes new terms, before anyone accepts them?
5. **Keys outside the public list.** Does a key outside the public list, such as `general.lmt`, `general.screenSaverAd` or `other.contentRecommendation`, get refused, get silently dropped, or answer? Each case means something different for "unknown".
6. **The standby state word.** Which power state does the TV report in Always Ready, and with Quick Start+? What crosses the wire in each standby mode, as measured by tvgw's own "While off/asleep" line?
7. **LG Channels.** Does it open on a webOS 24 to 26 set with `cdplauncher` and `lgchhomeapp.lgtvcommon.com` blocked, and on the CX?
8. **Region.** Which `<cc>` and `<rg>` hosts does a non-US set need on first boot behind the gateway, and does Google Cast fail without them?
9. **The Texas pop-up.** On which firmware does the ACR disclosure arrive, does it ask once or after every update, and which flag does pressing OK set?
10. **Wi-Fi while wired, and radios when off.** With Wi-Fi switched off in the menu, does the radio still probe or scan? Check with a separate monitor-mode adapter, on the CX and a 2024+ set. With the TV off, does Bluetooth stay up when Always Ready or "Turn on via Bluetooth" is on?
11. **PIN pairing.** Does PIN pairing work on webOS 25 and 26? It would let setup confirm that the person at the TV is the person at the gateway.
12. **Too many pairing requests.** Does LG's "too many pairing requests" counter trip on a stored key refused every hour? This decides how fast tvgw must stop after a refusal.
