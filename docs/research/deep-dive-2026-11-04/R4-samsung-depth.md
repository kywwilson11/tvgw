# R4, pass 2: Samsung Tizen TVs of 2019 to 2026, deeper and newer

*Research record, written 2026-11-04; the code that followed is in the [CHANGELOG](../../../CHANGELOG.md) under 2026-11-04.*

*Researcher R4, 2026-11-04. Builds on pass 1 (2026-11-03; the session file `next/R4-samsung-depth.md`, not in the repository) and the v2 drafts beside it (`samsung-tizen.v2.toml`, `samsung-tizen.v2.rules`); repeats them only where a fact changed. Read-only on the repository (main at 31ef8e1). No TV was contacted. Downloads (papers, manuals, lists, the PoPETs endpoint CSV) sit in the session scratchpad as untrusted data. Host lookups were made from a workstation on 2026-11-04.*

*Grades. **VERIFIED**: read today in a primary source (Samsung's own pages or documents, a paper, a list file, a first-hand GitHub issue with the raw reply). **REPORTED**: one secondary or community source, or a primary page that could not be read and is known from search-engine summaries. **UNCERTAIN**: claims without evidence, or sources that conflict. Identifiers in quoted TV replies (DUIDs, MACs, BSSIDs, addresses, names) are left out on purpose.*

---

## 0. One page: the ten findings that change the profile, discovery or the Samsung page

1. **The no-pairing reply says more than W11 assumes, and one field is a location identifier.** `GET :8001/api/v2/` on 2019 to 2025 sets carries `networkType` (`wired`/`wireless`), `wifiMac` **even when wired** (so it is not a Wi-Fi signal), and, only when the TV is on Wi-Fi, an `ssid` field that holds the **access point's BSSID**. `firmwareVersion` is `Unknown` on every sample from 2019 to 2025. The model code starts with the year and, after an OS upgrade, ends in `_T09` (three samples: `23_X22U_UHD_T09`, `24_KSUE_UB_T09`, `24_PTM_FTV_T09`), so tvgw can say "2024 set, now running Tizen 9" without a tester typing it. **Change:** second path = `networkType == wireless` *or* `ssid` present; never store `ssid` or `wifiMac` (a BSSID geolocates a home through public Wi-Fi databases). VERIFIED (raw replies in GitHub issues), the `_T09` reading REPORTED.
2. **The foreground-app reading planned in W11 does not hold up.** `GET /api/v2/applications/<id>` returns 404 for an app not installed. Netflix's `visible` flips; YouTube's and Disney+'s never do. On a 2025 Tizen 9 set it answers without a token only to callers on the TV itself. And `POST` to the same path **launches** apps without pairing on some sets. **Change:** drop `app` from the hourly reading, or record it as "Netflix in front: yes/no, else unknown". Never send anything but GET. REPORTED (cleanyourtv #441, five owners, October 2026).
3. **Pairing is broken on current firmware, so REST-only is not just cautious, it is the only path.** 2024 Tizen devices (a TV and a smart monitor) on One UI Tizen 9 builds 2115 and 2130 answer the remote channel with `ms.channel.timeOut` or `unauthorized` and **show no prompt**. Home Assistant's maintainer calls it a firmware glitch: "there's nothing we can do to fix it on our side". On 2020 and 2022 sets, `ms.remote.touchEnable` events break the handshake. VERIFIED (HA #179510, samsungtvws #184, #193). **Change:** park D19's optional pairing; do not plan any feature on it.
4. **Correct the opt-out sentence.** Three tests disagree. IMC 2024 (VIS, IBA and Customization Service off, Do Not Track on) and RTINGS 2026 (an S95F) saw Samsung's ACR traffic stop. PoPETs 2027 (a 32-inch QLED on Wi-Fi, April to May 2026, Viewing Information Services off only) counted traffic "consistent with ACR" (periodic, at least 5% of the opted-in volume) after opt-out in **30/30 TV Plus, 41/60 antenna, 18/30 HDMI and 6/30 Tubi runs**, and also in 9 idle, 2 Netflix and 3 YouTube runs that had none when opted in. The authors say they cannot see the contents. "Failed in most lab scenarios" (docs/what-it-stops.md:45) overstates it; the plain truth is "a 2027 study saw traffic like it continue in most of its tests; two others saw it stop". The block stays whatever the setting says. Every published trace is of a Samsung **on Wi-Fi**; none is wired. VERIFIED (both papers read), RTINGS REPORTED.
5. **Four must-allow gaps now have breakage reports, and HaGeZi still blocks one host the profile relies on.** `osb-apps-v2.samsungqbe.com` (the app store says "Server down for maintenance", app updates fail: Perflyst #150 on a 2020 Q70T, again in a 2026-10 comment; blocklistproject #227 on Q60 and QN90 sets), `osb-v2.samsungqbe.com` (installs fail after a firmware update; possibly first setup), `img-resize-cdn-prod.samsungnyc.com` (home-screen previews; HaGeZi #3228), `unified-ad-segment-cdn-ak-us-east-1.akamaized.net` (**Samsung TV Plus freezes** with "Something went wrong"; HaGeZi #11088, August 2026). Both subscribed HaGeZi lists block `osb.samsungqbe.com` on 2026-11-04, which Perflyst #79 ties to Samsung account login on a 2018 set. `cdn.samsungcloudsolution.com` has a 2018 (Tizen 4) report too, not only the 2013 one. REPORTED (community reports), lists VERIFIED.
6. **Standby is not "off", and the page must say what tvgw cannot hear.** A Frame in Art Mode reports `standby`. Samsung's own IP-control sheet says the IP server goes offline about a minute after standby, *unless* "Keep Bixby in Standby" keeps it open on far-field sets. Pet Care listens for barking **while the TV is off** and reports through SmartThings (the cloud capability `samsungvd.soundDetection` lists `dogBarking`, `babyCrying`). October 2026 allegations (unverified) add sound-event counters and use of a soundbar's microphone. **Change:** a REST reply of `standby` that persists for more than about two minutes becomes the brief line "the TV kept its network on while in standby"; the checklist gains Keep Bixby in Standby off, Pet Care off, Power On with Mobile off, and the microphone switch. VERIFIED (Samsung sheet, HA #187048, samsungtvws #185), sound features REPORTED, allegations UNCERTAIN.
7. **Wi-Fi off is a real menu item on newer sets, and some Samsungs have no network socket.** Samsung's support page: Settings > All Settings > Connection > Network > **Expert Settings > Wi-Fi** (switch it off), from 2022; Settings > General > Network > Expert Settings from 2017 to 2021. The 32-inch Frame (2020 to 2023) has no LAN port, and Samsung writes "wired networks are not supported on some models". **Change:** the radio steps name the Wi-Fi switch, and the Samsung page says before installation: "Some Samsung TVs, such as the 32-inch Frame, have no network socket. The gateway cannot protect them." (A USB network adapter on such a set is untested.) VERIFIED (Samsung PH and AU pages), no-port list REPORTED.
8. **The version matrix moved.** 2026 sets ship **Tizen 10** (Chromium M130). One UI Tizen 9 reached 2024 sets in 2025 and 2023 sets from late 2025 into 2026 (firmware 2220), with a YouTube failure on IPv6 networks (tvgw drops IPv6, so it is immune). Google Cast arrives by firmware on 2024 to 2026 sets in 2026, a new LAN service and new Google hosts. Daily+ is switched off after 2026-10-30. Vision AI Companion (select 2025 sets, the 2026 range) carries Perplexity, Copilot and Gemini, with its consent in **its own settings**, not under Privacy Choices. VERIFIED (Samsung Developers), rest REPORTED.
9. **DNS: no current Samsung is shown to use DoH or a hard-coded resolver, but Samsung tells owners to type 8.8.8.8.** The PoPETs lab list has no DoH name; the 8.8.8.8:443 claims rest on one unverified guide. Samsung's own support page tells owners whose apps fail to set DNS manually to 8.8.8.8 or 8.8.4.4. tvgw's port-53 redirect makes that harmless; the page should say so in one sentence, so a user does not "fix" an app that way and think the gateway was bypassed. VERIFIED (Samsung CZ page, PoPETs list), DoH claims UNCERTAIN.
10. **Discovery signals, corrected.** Every published port scan (2021 to 2024 sets) found 8001, 8002, 9197 (UPnP renderer) and 7678 (`nservice`) open, and 8080 returning 403 `Server: WebServer`. The SSDP `SERVER` header appears in two forms, `Samsung UPnP SDK/1.0` and `Samsung_UPnP_SDK/1.0`; the v2 draft matches only the first. Samsung **soundbars** advertise `_airplay._tcp` with `manufacturer=Samsung` and were taken for TVs by Home Assistant in 2026, so the profile is picked only on REST `device.type == "Samsung SmartTV"`. Some sets regenerate their UPnP UUID at every boot, so nothing keys on the UDN. dnsmasq refuses the `localhost` host name many Samsungs send. No sample of a 2026 (Tizen 10) reply exists yet. VERIFIED/REPORTED as marked in section 3.

---

## 1. Version matrix

### 1.1 Model years, OS and engines

| Year (letter) | Tizen at launch | OS later (in place) | Web engine (Samsung) | REST `model` samples | Confidence |
|---|---|---|---|---|---|
| 2019 (R) | 5.0 | none (security firmware only) | M63 | `19_MUSEL_UHD_BASIC` | spec VERIFIED; sample REPORTED |
| 2020 (T) | 5.5 | none | M69 | `20_NIKEL_UHD` | VERIFIED (spec), sample from pass 1 |
| 2021 (A) | 6.0 | none | M76 | `21_KANTSU2E_UHD_VOICE`, `21_KANTSU2E_UHD_BASIC`, `21_NIKEM2_QTV` | VERIFIED (spec), samples REPORTED |
| 2022 (B) | 6.5 | none | M85 | `22_NIKEL_UHD`, `22_PONTUSM_FTV` | VERIFIED (spec), samples REPORTED |
| 2023 (C) | 7.0 | Tizen 8 (One UI, Oct to Nov 2024, firmware 20xx, e.g. 2011 on an S90C); Tizen 9 (late 2025 into 2026; firmware 2211, then 2220.4) | M94 | `23_KANTSU2E_UB` (never upgraded), `23_X22U_UHD_T09` (Tizen 9) | spec VERIFIED; upgrades REPORTED |
| 2024 (D) | 8.0 | Tizen 9 (2025 into 2026; builds 2115, 2130) | M108 | `24_KSUE_UB_T09`, `24_PTM_FTV_T09` | spec VERIFIED; upgrades REPORTED |
| 2025 (F) | 9.0 | Tizen 10 "eventually" (no date, no model list) | M120 | `25_PTM_QTV`, `25_PTM_FTV` | VERIFIED (spec, samples); Tizen 10 upgrade UNCERTAIN |
| 2026 (H) | 10.0 | seven years of upgrades promised | M130 | none published | spec VERIFIED; REST unknown |

- The seven-year OS promise began with 2024 sets and was extended to 2023 sets "with the hardware to support it" (REPORTED, press). 2022 and older sets get no OS upgrades.
- Firmware strings follow `T-<platform><region>-<field>-<build>`. The field reads `0080` on a 2023 Q80C reported in November 2024 (`T-PTMCDEUC-0080-2013.1`; whether that build was the Tizen 8 update is disputed in the thread) and `0090` on Tizen 9 builds (`0090-2115`, `0090-2130.0`, `T-KSU2EFUABC-0090`); a 2023 set never upgraded shows none (`T-KSU2ECAKUC-1222.0`). So `0090` probably means Tizen 9. UNCERTAIN (five samples), but useful on the tester's form, since REST never gives the firmware.
- The upgrades broke things for LAN tools. The 2024 Tizen 8 update stopped Home Assistant's Wake-on-LAN on 2023 sets (HA #130951). Tizen 9 builds broke YouTube on IPv6 networks (Samsung's workaround: IPv4) and broke third-party pairing (section 3.3). REPORTED.

### 1.2 Features per generation

| Feature | Where | Network effect | Grade |
|---|---|---|---|
| Samsung TV Plus (FAST) | every year in scope; built in, cannot be removed | `sis-global.prod.samsungtv.plus`, `tvpn*.samsungcloud.tv` (logos, line-up), CloudFront streams, `unified-ad-segment-cdn-ak-us-east-1.akamaized.net` (ad segments), `qoe.samsungcloud.tv` (quality beacons) | VERIFIED (lab list), ad host REPORTED |
| ACR ("Viewing Information Services") | every year in scope; Samsung Ads' guide: "glass-level screenshots every 500 milliseconds", matched against linear TV, ads, **video games** and TV Plus | `acr-<cc>-prd.samsungcloud.tv`, `log-config.` and `log-ingestion.samsungacr.com` | VERIFIED (Samsung Ads ACR guide, 2022) |
| Interest-based ads, TIFA, PSID | TIFA since 2019 (rolled out to 2015 to 2018 sets too); resetting the PSID resets the TIFA; Samsung says "Reset PSID" may become "Reset Advertising ID" | `samsungads.com` hosts, AdGear `adgrx.com` | VERIFIED (Samsung Developers) |
| SmartThings | every year; built-in SmartThings hub (Zigbee, Thread, Matter) on many 2022+ sets | the cloud receives the TV's state: input source, channel, picture mode, firmware version, sound detection (`samsungvd.*` capabilities) | capabilities VERIFIED (schema); hub radios REPORTED |
| Bixby, far-field microphone, microphone switch | far-field sets from 2021 (Neo QLED and up); switch on the lower edge; 2026 remotes start Bixby by holding the mic button | `provisioning-*.mgmt.aibixby.com`; `bixbyllm.com` on phones (on TVs UNCERTAIN) | REPORTED |
| Keep Bixby in Standby | far-field sets | keeps the IP server, and the microphone, awake in standby | VERIFIED (Samsung IP-control sheet, 2023) |
| Active Voice Amplifier, Adaptive Sound, SpaceFit | sets with the sound sensor; run only while the switch is on | none known (on the TV) | REPORTED (Samsung support pages) |
| Pet Care, Family Care (sound sensing) | 2025 Vision AI sets; works while the TV is **off**; Family Care reported discontinued | SmartThings alerts | REPORTED |
| Daily+ hub | 2024 sets and some 2023 sets by update | switched off after 2026-10-30 | REPORTED (GIGA, 2026-10-25) |
| Vision AI Companion (generative Bixby, Perplexity, Copilot, Gemini) | select 2025 sets (Q7F and up) by update; the 2026 range; Copilot from 2025-08, Perplexity from 2025-10; "Click to Search" folded in | partner LLM hosts, unverified on Tizen; consent in Vision AI Companion > Settings > Terms and Conditions | REPORTED |
| AirPlay 2, Spotify Connect | 2019 on (the lab set advertised both) | mDNS on the LAN only | VERIFIED (lab list) |
| Google Cast | 2024 to 2026 sets by firmware (2115 on 2024 sets), 2026 | `_googlecast._tcp`, Google hosts | REPORTED |
| Smart Hub terms and privacy notice | every year; required for apps; cannot be unticked at setup; agreeing turns **Auto update** on | the consent service (`api.samsungconsent.com`) | VERIFIED (Consumer Reports 2025-10-19; 2020 manual) |

### 1.3 What survives a firmware update

| Setting | After an update | Grade |
|---|---|---|
| Picture and sound settings | "reset to their defaults after a software update" (Samsung's 2020 e-Manual) | VERIFIED |
| Auto update | set On automatically when the Smart Hub terms are accepted | VERIFIED (2020 e-Manual) |
| Viewing Information Services, Interest-Based Advertisements | no documented reset; owners report re-consent prompts after updates and a US wave (February 2025) of a Smart Hub privacy notice every two hours that one owner stopped only by accepting a prompt on samsung.com | UNCERTAIN (reset); REPORTED (re-prompts) |
| Network settings, Wi-Fi switch | no report of a reset | UNCERTAIN |
| Pairing tokens | a 2026 report of re-authorization after a power loss, answered with the Access Notification setting, not an update | REPORTED |

So the brief's "check again after a software download" (decision 57) is right, and should say the *picture* reset is certain while the privacy reset is a precaution.

---

## 2. Privacy settings per version

### 2.1 Menu paths and defaults

| Setting | 2017 to 2021 | 2022 to 2024 | 2025 and 2026 | Default, can it be off | Read over the LAN | Grade |
|---|---|---|---|---|---|---|
| **Viewing Information Services** (ACR) | Settings > Support > Terms & Privacy (or Terms & Policy) > Privacy Choices; also Home > the left menu > Privacy Choices (2020 e-Manual) | Settings > All Settings > General & Privacy > Terms & Privacy > Privacy Choices | Home > Menu > Settings > All Settings > General & Privacy > Terms & Privacy; a "Privacy Choices" link under Settings | offered at setup; Samsung: "only runs if you opted in"; can be unticked | no | VERIFIED (Consumer Reports, Samsung FAQ, 2020 e-Manual) |
| **Interest-Based Advertisements** | the same screen; on older sets labelled "make content and advertising more interactive", unticking sends Limit Ad Tracking | the same screen | the same screen | can be unticked; generic ads stay (Samsung: opt-out "does not prevent the delivery of generic advertisements") | no (apps read `isLATEnabled()` on the TV) | VERIFIED |
| **Reset PSID** | in the TV menu (path not published by Samsung) | guides: Terms & Privacy, after unticking the two above | unknown | resets the advertising ID; ads continue | no | VERIFIED (exists), path REPORTED |
| **Voice Recognition Services**, Bixby, Alexa | Support > Terms & Privacy > Voice Recognition Services | General & Privacy > Voice > Voice Wake-up | Settings > All Settings > Advanced Features > Voice (greyed out while the mic switch is off); not listed under the privacy terms; no assistant agreed by default | can be declined | `VoiceSupport` says only whether the set supports voice | VERIFIED (2025 and pre-2022 paths, Consumer Reports); 2022 to 2024 path REPORTED |
| **Keep Bixby in Standby** | unknown | Settings > General > Voice > Voice Assistant (Bixby) > Bixby Wake-up Options (Samsung, "as of 2023") | unknown | keeps the mic and network awake in standby | no; inferable when REST answers in standby | VERIFIED (Samsung IP-control sheet) |
| **Microphone switch** | lower edge of far-field sets | same | same | physical; when off, "all voice recognition features and some sound features" stop | no | VERIFIED (Samsung support) |
| **Power On with Mobile**, **IP Remote** | Settings > General > Network > Expert Settings | Settings > All Settings > Connection(s) > Network > Expert Settings | same as 2022 | Samsung: IP Remote "may allow other IP control devices to control your TV" | no | VERIFIED (Samsung AU page; 2020 e-Manual) |
| **Wi-Fi switch** | Expert Settings (where offered) | Expert Settings > Wi-Fi | same | wired is picked automatically; Wireless greys out with a cable in | `networkType`, `ssid` | VERIFIED (Samsung PH page), greying REPORTED |
| **Smart Hub terms**, **Smart Hub privacy notice** | required for apps; cancel by Reset Smart Hub (Support > Device Care > Self Diagnosis) | same | same | cannot be unticked at setup | `smartHubAgreement` | VERIFIED |
| **Vision AI Companion consent** | – | – | Vision AI Companion > Settings > Terms and Conditions > withdraw | per feature | no | REPORTED (Samsung SG support, via search) |
| **Pet Care / sound sensing** | – | – | SmartThings app, on the TV or a phone | off until enabled | no | REPORTED |
| **Customization Service** (account) | account.samsung.com > Privacy | same | same | only with a Samsung account | no | VERIFIED (IMC 2024's opt-out set) |

Three plain facts for the page: the Terms and the Smart Hub privacy notice cannot be declined if you want apps; the viewing-data and ad settings can; and none of them can be read by the gateway.

### 2.2 Does the opt-out work: the three tests

| Test | Data | Samsung set, network | What was switched off | How ACR was counted | Result |
|---|---|---|---|---|---|
| IMC 2024, Anselmi et al. | before 2024-09 (the preprint date), UK and US | model not named, Wi-Fi to a capture server | VIS, IBA, Customization Service off; Do Not Track on | contact with ACR domains | ACR traffic stopped |
| RTINGS, "Testing Smart TV Tracking" (updated 2026-07-07) | 2026 | S95F (2025), capture by Wireshark | the consent setting | ACR spikes to `log-ingestion.samsungacr.com`, `acr-us-prd.samsungcloud.tv` | stopped "in that narrow sense"; Netflix's own logging continued | 
| PoPETs 2027, *Watching the Watchers* | 2026-04 to 2026-05, US | a 32-inch QLED (the paper names no model or firmware), **Wi-Fi** | VIS only (on-device toggle) | periodic outgoing traffic to `acr-us-prd.samsungcloud.tv`; an opted-out run counts when it carries at least 5% of the opted-in volume | consistent with ACR in 30/30 TV Plus, 41/60 antenna, 18/30 HDMI, 6/30 Tubi runs; also 9 idle, 2 Netflix, 3 YouTube |

- Grades: IMC and PoPETs VERIFIED (read); RTINGS REPORTED (its page body would not load; known from search summaries of it).
- Why they differ is open: firmware about two years apart, different settings switched off, and different thresholds (contact versus 5% of volume). PoPETs' own words: "potentially ineffective", "we cannot know for certain without access to payload content".
- Samsung's statement of 2026-10-29: ACR is optional, not enabled automatically, and disabling it stops viewing information being collected or sent (REPORTED, press). The Texas settlement of 2026-02-26 (express consent, clear consent screens, Texans only) and a US class action filed in California on 2026-10-06 (one source, UNCERTAIN) are the legal context; no national consent change is documented.

**Wording for docs/what-it-stops.md and docs/tv/samsung-tizen.md:** "Samsung's viewing-data setting may not stop everything. A 2027 study saw traffic like screen recognition continue after the setting was switched off in most of its tests; two other tests saw it stop. Nobody outside Samsung can see what that traffic contains. So the gateway blocks the screen-recognition services whatever the setting says."

---

## 3. The LAN API

### 3.1 `GET /api/v2/` on ports 8001 (http) and 8002 (https, self-signed)

No pairing, no prompt, nothing on the screen, with the TV's default settings (IP Remote off). Fields seen in raw replies from 2019 to 2025 sets; `version` is `2.0.25` on every one.

| Field | What it holds | tvgw use | Store? | Grade |
|---|---|---|---|---|
| `device.type` | `Samsung SmartTV` | the identification test (soundbars must not pass) | yes | VERIFIED |
| `device.OS` | `Tizen` | platform | yes | VERIFIED |
| `device.model` | `YY_PLATFORM_CLASS[_T09]` | shipped year from `YY`; `_T09` = upgraded to Tizen 9 | yes | VERIFIED (field), `_T09` REPORTED |
| `device.modelName` | retail model, e.g. a QN-, UN-, QE- or GU- number | the page and the support row | yes | VERIFIED |
| `device.PowerState` | `on` or `standby`; absent before 2019; **`standby` during Frame Art Mode** | power, and "network kept on in standby" | yes | VERIFIED (HA #187048, samsungtvws #185) |
| `device.networkType` | `wired` or `wireless` | second path when `wireless` | yes | VERIFIED |
| `device.ssid` | **BSSID of the access point**, present only on Wi-Fi | second path by presence only | **never** (it locates the home) | VERIFIED (2024 Frame sample) |
| `device.wifiMac` | the Wi-Fi radio's MAC, present even when wired | none | never | VERIFIED |
| `device.ip` | the address the TV thinks it has | second path when not `TV_IP` | as `matches`/`other` | VERIFIED |
| `device.firmwareVersion` | `Unknown` on every sample 2019 to 2025 | none: ask the tester (About This TV) | – | VERIFIED |
| `device.smartHubAgreement` | `true`/`false` | the one consent flag readable | yes | VERIFIED |
| `device.developerMode`, `developerIP` | `0`/`1`; `0.0.0.0` when unset | WARNING line if on with an address | as `set`/`none` | VERIFIED |
| `device.countryCode`, `Language` | e.g. `US`, `en_US` | warn when the must-allow list (US hosts) does not fit the country | country yes | VERIFIED |
| `device.VoiceSupport`, `isSupport.remote_voiceControl` | whether the set takes voice | show the voice and microphone steps only when true | yes | VERIFIED |
| `device.FrameTVSupport` | Frame | say "standby includes Art Mode" | yes | VERIFIED |
| `device.TokenAuthSupport` | `true` on 2018+ samples | none | – | VERIFIED |
| `device.name` | owner-editable, HTML-escaped (`55&quot; The Frame`) | display after cleaning, or not at all | no | VERIFIED |
| `duid`, `id`, `udn` | the same UUID; on some sets regenerated at every boot (HA #169628, a 2017 set) | never as identity | never | VERIFIED |

**Not in the reply, on any sample:** Viewing Information Services, Interest-Based Advertisements, voice consent, the microphone switch, whether the Wi-Fi radio is switched off while wired, Bluetooth, Pet Care, SmartThings registration. VERIFIED by absence in the three full replies published (2020, 2024 and 2025 sets) and consistent with seven partial ones.

**Availability.** The reply answers while the TV is on. In standby it answers for about a minute (Samsung), longer with Keep Bixby in Standby or similar (a 2025 Q8F on Wi-Fi answered `standby` in HA #187048), and not at all after that on many sets; one owner reports the Ethernet port unpowered in standby on a 2018 set. So: `on` is on; `standby` is "asleep, network kept on"; no answer is off. A Frame in Art Mode reads `standby` with its screen lit.

### 3.2 Other ports and endpoints

| Port, path | Seen | What it is | tvgw | Grade |
|---|---|---|---|---|
| 8001 `/api/v2/applications/<id>` GET | 2021 Q75A: 200 with `running`, `visible`; 2023 CU7000 (never online): 404; 2025 Tizen 9: answers without a token **only to callers on the TV**; `visible` flips for Netflix only | app status | at most Netflix yes/no; record refusals as `unknown` | REPORTED |
| same path POST / PUT / DELETE | POST launched apps on a 2023 set | writes | never | REPORTED |
| 8001 / 8002 `/api/v2/channels/samsung.remote.control` | on-screen Allow; token; full remote control | WebSocket remote | never on the hourly path; pairing parked | VERIFIED |
| 8080 | `403 Forbidden`, `Server: WebServer`, `Access-Control-Allow-Origin: *`; `/ws/apps` (old DIAL path) 404 on 2021 and 2023 sets; DIAL from the TV itself 401 on a 2025 set | unidentified web server | a discovery signal only | REPORTED |
| 9197 `/dmr` | open on every sample | UPnP media renderer | a discovery signal; nothing on the home LAN can reach it through the gateway | VERIFIED (HA logs), REPORTED (scans) |
| 7678 `nservice` | open on every sample | Samsung's SSDP description service | a discovery signal | REPORTED |
| 9080 | open on one 2021 set, closed on others | unknown | none | REPORTED |
| 26101 | open only with Developer Mode on | `sdb` (no root shell on retail firmware) | WARNING when open | REPORTED |
| 5555 | closed on every sample | no ADB | none | REPORTED |

### 3.3 Pairing on 2023 to 2026 firmware

| Report | Set, firmware | Symptom |
|---|---|---|
| HA #179510, 2026-08-18; maintainer 2026-08-29: "a firmware glitch"; another owner 2026-10-15: "same issue on multiple Samsung TVs that had been working" | 2024 98" Crystal UHD, `0090-2130.0` | 8002 refused or `ms.channel.timeOut`, then 8001 `ms.channel.unauthorized`; **no prompt ever shown**; REST works |
| samsungtvws #184, 2026-04-16 | 2024 Odyssey G8 monitor, `0090-2115` | `ms.channel.timeOut`, no prompt; REST works |
| samsungtvws #193, 2026-10-25 and 2026-10-27 | 2022 Frame (`22_PONTUSM_FTV`), 2020 Q80T | `ms.remote.touchEnable` before `ms.channel.connect` aborts the library; HA then falls back to 8001 and gets `unauthorized` |
| cleanyourtv #441, 2026-10-25 | 2023 CU8000 on Tizen 9 (`2220`), Developer Mode on | the remote channel completes only from the developer host PC; other LAN hosts get TLS and HTTP 101, then nothing |
| HA #187048, 2026-10-17 | 2025 Q8F | after a reload HA reports `on` for one poll, because its first check opens the WebSocket instead of reading `PowerState`; a `KEY_POWER` sent then would turn the set on |

Grade VERIFIED (first-hand issues). The lesson for tvgw is the one HA's code states: "On some TVs, opening a websocket turns on the TV, so first check PowerState".

### 3.4 Discovery signals

| Signal | Value | Strength | Grade |
|---|---|---|---|
| REST | `device.type == "Samsung SmartTV"` and `device.OS == "Tizen"` | decisive | VERIFIED |
| Ports | 8001, 8002, 9197, 7678 together (8080 too) | strong; 8001/8002 alone name the vendor only | REPORTED (six scans) |
| SSDP `SERVER` | `Samsung-Linux/4.1, UPnP/1.0, Samsung_UPnP_SDK/1.0` (2021) and `SHP, UPnP/1.0, Samsung UPnP SDK/1.0` (older) | strong for the vendor | REPORTED |
| SSDP ST (HA) | `urn:samsung.com:device:RemoteControlReceiver:1`, `urn:samsung.com:service:MainTVAgent2:1`, `RenderingControl:1` with manufacturer Samsung | vendor | VERIFIED (HA manifest, 2026-11-04) |
| mDNS | `_airplay._tcp` with `manufacturer=samsung*` (also soundbars), `_spotify-connect._tcp`, from 2026 `_googlecast._tcp` | weak: soundbars match | VERIFIED (HA, lab list), soundbar confusion VERIFIED (HA #170287, #171990) |
| DHCP host name | often `localhost` (dnsmasq refuses it as it is in /etc/hosts), else a TV name; HA matches `tizen*` | weak | REPORTED |
| DHCP vendor class | one old capture shows a `VD Linux VDLinux` string; nothing published for Tizen | none yet | UNCERTAIN |
| MAC prefix | HA lists six; two 2024 and 2025 Frame samples carry prefixes outside them | vendor at most | VERIFIED |
| UPnP UDN | regenerated at boot on some sets | never identity | VERIFIED |

### 3.5 SmartThings

There is no local SmartThings API for the TV that tvgw could use; the TV talks to Samsung's cloud (`api.`, `client.smartthings.com`), and third parties read it there with an account token. What the cloud holds about a registered TV is itself the finding: the `samsungvd.*` capabilities include `mediaInputSource`, `tvChannel` (number and name), `pictureMode`, `firmwareVersion`, `soundDetection` (`noSound`, `dogBarking`, `babyCrying`), `aiAction`, `remoteControl` and `launchService` (VERIFIED: the published capability schemas). A TV signed in to SmartThings therefore reports its input and channel to Samsung by design, separate from ACR. The profile should keep SmartThings watched and say plainly that blocking it breaks phone control and Pet Care.

### 3.6 Red lines for tvgw on the LAN

- GET only, to `TV_IP` only, on 8001 (http) and 8002 (https), no redirects, a size cap, a deadline. Never POST, PUT or DELETE (a POST launches apps on some sets without pairing).
- Never open the WebSocket on the hourly path (it can wake the set); never send `KEY_POWER` (a toggle that turns a standby set on); never Wake-on-LAN.
- Never store `ssid`, `wifiMac`, `duid`/`id`/`udn`, `ip` or `name`. A BSSID is a location key.
- Never pair without the owner asking; a refused prompt is never retried; on 2024+ builds pairing may fail with no prompt at all, so its failure text must not blame the owner.
- Never use SmartThings' cloud.

---

## 4. Network behaviour

### 4.1 Hosts by function: what is new since pass 1

Pass 1's inventory (its F1) still stands. Additions and changes, with today's DNS answer where it matters:

| Function | Host | Evidence | Today | Grade |
|---|---|---|---|---|
| App store, app installs and updates | `osb-apps-v2.samsungqbe.com` | Perflyst #150 (2023-09, 2020 Q70T: "Server down for maintenance"; 2026-10-12: "needed for updating apps too"); blocklistproject #227 (2022-04, Q60 and QN90); Perflyst #130 (2022-05: also serves the home-row ads) | resolves (CloudFront); no subscribed list blocks it | REPORTED |
| Service broker, installs, first setup | `osb-v2.samsungqbe.com` | blocklistproject #227 ("possibly" first setup); a Samsung Community owner: unblocking it restored installs on a Frame after a firmware update | resolves; not blocked | REPORTED |
| Account login (older sets) | `osb.samsungqbe.com` | Perflyst #79 (2020-10, 2018 NU8000: "required for Samsung Account login") | **blocked by HaGeZi Samsung and HaGeZi Pro on 2026-11-04** | REPORTED; block VERIFIED |
| Home-screen previews | `img-resize-cdn-prod.samsungnyc.com` | HaGeZi #3228 (2024-07: previews of shows, films and channels; allowlisted) | resolves (Cloudflare); lab set used it | REPORTED |
| TV Plus ad segments, playback | `unified-ad-segment-cdn-ak-us-east-1.akamaized.net` | HaGeZi #11088 (2026-08-05: blocked by Ultimate, TV Plus froze, "Something went wrong"; allowlisted, fixed) | resolves (Akamai); lab set used it | REPORTED |
| Connectivity, clock | `cdn.samsungcloudsolution.com`, `time.samsungcloudsolution.com` | Perflyst #142 (2022-12, a 2018 NU set: Wi-Fi dropped and YouTube stuck until both were allowed) | resolve (Akamai; Azure Traffic Manager) | REPORTED |
| Unknown, in the lab set | `api.sesupdate.com`, `gpms.sesupdate.com` | PoPETs lab list; owner hidden by privacy registration; name suggests an update service | resolve (CloudFront) | UNCERTAIN |
| Gaming Hub images (probable) | `ghsimgstore.samsungcloud.tv` | PoPETs lab list | resolves (CloudFront) | UNCERTAIN role |
| Proposed as Samsung tracking | `acrapiprd.trafficmanager.net`, `acrapiprdnew.trafficmanager.net` | HaGeZi #12163 (2026-11-03, a block request naming "samsung"); "acr api prd" in the name | resolve (Azure) | UNCERTAIN |
| Bixby LLM | `scs-use2.`, `scs-config-use2.bixbyllm.com` | HaGeZi #9806, #11796: on Galaxy phones; blocking breaks Bixby and the AI keyboard; on TVs unknown | resolve (Google Cloud) | REPORTED (phones) |
| Xumo app telemetry | `samsung-beacons.xumo.com` | HaGeZi #8536 (Pro blocks it) | blocked by Pro | VERIFIED (list) |
| Galaxy only, not TV | `apps.samsung.com`, `config-api.internet.apps.samsung.com`, `orsplc.di.runestone.samsung.com`, `sspapi-prd.samsungrs.com` | HaGeZi issues about phones; none in the lab TV set | – | REPORTED |

### 4.2 DNS, DoH, DoT

| Question | Finding | Grade | What tvgw already does |
|---|---|---|---|
| Hard-coded 8.8.8.8 on port 53 | forum anecdotes only; none for a current Tizen set | UNCERTAIN | every port-53 packet from the TV goes to AdGuard (DNAT) |
| Owners told to type 8.8.8.8 | Samsung's own support: when Smart Hub apps fail, set DNS manually to 8.8.8.8 or 8.8.4.4 (Settings > General > Network > Network Status > IP Settings > DNS Settings > Enter manually) | VERIFIED | harmless under the DNAT; say so on the page |
| DoH (`dns.google` and others) | no DoH name in the PoPETs Tizen list (579 names); claims of TLS to 8.8.8.8:443 at boot on a 2023 CU8000 come from one unverified guide | UNCERTAIN | HaGeZi DoH list; `doh4` set rejects TCP 443 to known resolvers |
| DoT, DoQ | no report | UNCERTAIN | 784, 853, 8853 rejected |
| Hard-coded IPs, no lookup at all | none reported; PoPETs groups such IPs by prefix and found the ACR endpoint by name | UNCERTAIN | the DNS gate (count mode) records flows to addresses never answered |
| HTTPS/SVCB records | Chromium M120/M130 can ask | – | stripped for the TV (`strip_qtypes`) |
| Reverse lookups of private addresses | the lab set asked one PTR for a private address | REPORTED | check that AdGuard answers private PTR locally and never forwards it |

The lab captures were made with the TV on the capture box's Wi-Fi, so "DHCP resolver ignored" could not be seen there either way. This is an open question for a wired set (section 8).

### 4.3 Transport, time, firmware, IPv6

- **QUIC.** Tizen's engines (M108 to M130) can speak HTTP/3; no Tizen capture shows it. tvgw rejects UDP 443 by default, and apps fall back to TCP. UNCERTAIN (no measurement), harmless either way.
- **IPv6.** One UI Tizen 9 broke YouTube on "certain ISP and router setups tied to IPv6" (Samsung's workaround: IPv4; REPORTED). tvgw disables IPv6 on the TV side and drops IPv6 frames, so a Samsung behind it is immune. Worth one line on the page.
- **Time.** `time.samsungcloudsolution.com` (CNAME `time.trafficmanager.net`, then an Azure address) and `pool.ntp.org`, both in the lab set. NTP on 123 is allowed. VERIFIED (DNS, lab list).
- **Firmware.** `www.samsungotn.net` (Azure), `otnprd8-11.samsungcloudsolution.net`, `otn2.samsungcloudcdn.com` (CloudFront), `cdn.samsungcloudsolution.com` (Akamai); all resolve. Auto update turns on with the Smart Hub terms (2020 e-Manual). The `firmware_events` volume test (50 MB a day) stands; Tizen 9 upgrade images are larger than routine builds (UNCERTAIN size).
- **Samsung TV Plus streams.** In the lab set: CloudFront distributions for segments, `sis-global.prod.samsungtv.plus`, the `tvpn*` logo and line-up hosts, `qoe.samsungcloud.tv` (an AWS balancer named `tvplus-qoe-api`), and the Akamai ad-segment host above. No Amagi name appeared for the Samsung set. VERIFIED (lab list, DNS).

### 4.4 What over-blocking broke (Samsung TV reports, newest first)

| Date | Source | List | Host | Symptom | Set |
|---|---|---|---|---|---|
| 2026-09-17 | AdGuard Filters #241698 | AdGuard DNS filter | not identified | the My5 app spins forever | Tizen (UK) |
| 2026-08-05 | HaGeZi #11088 | Ultimate | `unified-ad-segment-cdn-ak-us-east-1.akamaized.net` | TV Plus freezes, "Something went wrong" | US |
| 2026-03-13 | Perflyst #142 comment | Perflyst on Technitium | `cdn.samsungcloudsolution.com` (caught by a partial match) | Wi-Fi drops | – |
| 2024-07-21 | HaGeZi #3228 | Pro++, Ultimate | `img-resize-cdn-prod.samsungnyc.com` | no previews | – |
| 2023-09-22 | Perflyst #150 | Perflyst | `osb-apps-v2.samsungqbe.com` | store "Server down for maintenance"; app updates fail (2026 comment) | 2020 Q70T |
| 2022-12-17 | Perflyst #142 | Perflyst | `cdn.`, `time.samsungcloudsolution.com` | Wi-Fi disconnects, YouTube stuck | 2018 NU |
| 2022-04-01 | blocklistproject #227 | Blocklist Project | `osb-apps-v2.`, `osb-v2.samsungqbe.com` | store broken; setup possibly | Q60, QN90 |
| 2020-11-29 | Perflyst #82 | Perflyst | ten hosts incl. `gpm.`, `osb.samsungqbe.com` | YouTube, Prime would not open | 2016 to 2020 |
| 2020-10-24 | Perflyst #79 | Perflyst | `osb.samsungqbe.com` | Samsung Account login | 2018 NU8000 |

The common thread: the store, login and TV Plus sit under `samsungqbe.com` and CDN names that lists treat as ad infrastructure. Every one of these hosts belongs in must-allow (section 6).

### 4.5 Radios and standby

| Question | Finding | Grade |
|---|---|---|
| Does Wi-Fi stay on with a cable in? | The TV switches to wired by itself and greys out Wireless; the radio's MAC stays in the REST reply; newer menus offer an explicit Wi-Fi switch under Expert Settings. Whether the radio still scans is not measured. One support vendor writes that some Samsung models need Wi-Fi enabled for network power-on even when wired | REPORTED / UNCERTAIN |
| Network in standby | about a minute, then off (Samsung), unless Power On with Mobile, Keep Bixby in Standby, Art Mode or SmartThings duties keep it up; a 2022 S95B owner reports about 1 W with the network off and over 30 W with it on | VERIFIED (Samsung), REPORTED (watts) |
| "Instant On" | an owner says it can no longer be switched off on current sets | REPORTED |
| Microphones in standby | Keep Bixby in Standby (far-field sets); Pet Care listens while off; October 2026 allegations of sound-event telemetry and of finding a microphone on a soundbar or Bluetooth device when the TV has none | VERIFIED / REPORTED / UNCERTAIN |
| Bluetooth, Thread, Zigbee | Bluetooth for the remote and audio; a SmartThings hub radio on many 2022+ sets. None of them is an internet path by itself; all are outside the gateway's view | REPORTED |
| TVs with no LAN port | 32-inch Frame (2020 to 2023; retailer specs and owners); Samsung: "wired networks are not supported on some models" | REPORTED; Samsung sentence VERIFIED |
| LAN mapping by the TV | October 2026 allegation: a service that "maps devices on the local network" | UNCERTAIN; isolation means it sees only the gateway |

---

## 5. What the gateway should do, per generation

Common to every row: identify by REST `type`/`OS` plus one more signal (ports 8001+8002+9197, or the SSDP `SERVER` or ST); read REST only, hourly, GET only; block the profile's pins (ACR, Samsung Ads, AdGear, crash logs) whatever any setting says; keep the must-allow list of section 6; watch mode (no autonomous blocks) while the profile is not tested; never pair, never store `ssid`/`wifiMac`/UUIDs.

| Generation | Recognize | Read without pairing | Tell the owner to check on the TV | Block beyond the common set | Must stay allowed (beyond the common set) | Red lines for the brief | Confidence |
|---|---|---|---|---|---|---|---|
| **2019 (R), 2020 (T)**: Tizen 5.0, 5.5 | REST `model` `19_`/`20_`; ports; SSDP `Samsung UPnP SDK`; host name often `localhost` | power (`PowerState` from 2019), `networkType`, `ssid` presence, `smartHubAgreement`, developer mode, country, `VoiceSupport` | Settings > General > Network > Reset Network, then Open Network Settings > Wired; Expert Settings: Power On with Mobile off, IP Remote off, Wi-Fi off where offered; Settings > Support > Terms & Privacy > Privacy Choices: untick VIS and IBA; Voice Recognition Services: decline | none | `osb.samsungqbe.com` (account login on 2018 to 2020 sets) | `wireless` or `ssid` present; `ip` other than `TV_IP`; developer mode on with an address | menus VERIFIED (2020 e-Manual); REST REPORTED (one sample each) |
| **2021 (A)**: Tizen 6.0 | `21_`; first year with far-field Neo QLEDs | as above; `VoiceSupport` decides the mic steps | as 2019 to 2020 (2021 is the last year of the General > Network family); microphone switch on far-field sets; Bixby Wake-up off | none | as above | as above | REPORTED (three 2021 replies, three regions) |
| **2022 (B)**: Tizen 6.5 | `22_` | as above | Settings > All Settings > Connection > Network > Reset Network, then Wired; Expert Settings: Wi-Fi off, Power On with Mobile off, IP Remote off; General & Privacy > Terms & Privacy > Privacy Choices: untick VIS and IBA; Voice Wake-up off; mic switch | none | `osb-v2.`, `osb-apps-v2.samsungqbe.com` | as above | menus VERIFIED (Samsung AU, PH); REST REPORTED |
| **2023 (C)**: Tizen 7.0, upgraded to 8 (late 2024) and 9 (2026) | `23_`; `_T09` once on Tizen 9 | as above, plus "now runs Tizen 9" from `_T09` | the 2022 steps; **after the Tizen 9 upgrade, check every setting again** (new consent screens possible); Keep Bixby in Standby off on far-field sets | none | as 2022 | firmware event plus `_T09` appearing = an OS upgrade: re-check banner | spec VERIFIED; upgrade markers REPORTED |
| **2024 (D)**: Tizen 8.0, upgraded to 9 (2025 to 2026) | `24_`, often `_T09` | as above; pairing **broken** on builds 2115 and 2130 | the 2022 steps; Daily+ is gone after 2026-10-30 (nothing to switch off); Google Cast arrives by firmware: nothing on the home network can cast through the gateway | none | as 2022, plus `img-resize-cdn-prod.samsungnyc.com` | as 2023 | REPORTED |
| **2025 (F)**: Tizen 9.0 | `25_`; type `Samsung SmartTV` (Samsung soundbars also answer AirPlay discovery: require REST) | as above; app status from the LAN refused on at least one set | Home > Menu > Settings > All Settings > General & Privacy > Terms & Privacy (or the Privacy Choices link): untick VIS and IBA; Advanced Features > Voice: agree to no assistant; mic switch off; Vision AI Companion > Settings > Terms and Conditions: withdraw; SmartThings: Pet Care off | none (AI hosts watched: their cost of blocking is unknown) | as 2024, plus `unified-ad-segment-cdn-ak-us-east-1.akamaized.net` for TV Plus | as above; `standby` answering for long periods: "network kept on in standby" | menus VERIFIED (Consumer Reports); rest REPORTED |
| **2026 (H)**: Tizen 10.0 | `26_` expected; no reply published | unknown: treat a missing or changed reply as "this TV does not report", never as an error | as 2025 (unverified for this year) | none | as 2025 | none from REST until a sample exists | UNCERTAIN |
| **The Frame, any year** | `FrameTVSupport: true`, `_FTV` in `model` | as above; **`standby` includes Art Mode with the screen lit** | as its year; Art Mode keeps the network on | none | as its year | do not report Art Mode as off | VERIFIED (samsungtvws #185, Frame replies) |
| **No LAN port** (32-inch Frame 2020 to 2023, others) | never appears on the gateway's cable | – | the page says, before purchase or install: the gateway cannot protect it; a USB adapter is untested | – | – | – | REPORTED |

---

## 6. Concrete changes to samsung-tizen.toml and .rules

Against the shipped files (main 31ef8e1). "v2" marks what the v2 drafts already have; the rest is new in this pass. Every must-allow host below resolved on 2026-11-04, and none is blocked by a subscribed list except `osb.samsungqbe.com`.

### 6.1 `[must_allow]`

```diff
 # keep all 11 shipped hosts; v2 already adds us-auth2.samsungosp.com, osb.samsungqbe.com, osb-ussvc.samsungqbe.com
-"cdn.samsungcloudsolution.com" = "system update check (unverified; Perflyst, on a UE40F5500)"
+"cdn.samsungcloudsolution.com" = "system update check and connectivity (unverified; Perflyst, on a 2013 UE40F5500; Perflyst #142, 2022: on a 2018 NU set, Wi-Fi dropped and YouTube stuck until it and time. were allowed)"
-"time.samsungcloudsolution.com" = "clock (unverified; Perflyst: blocked, Plex, YouTube and Prime Video stop working on some sets)"
+"time.samsungcloudsolution.com" = "clock (unverified; Perflyst: blocked, Plex, YouTube and Prime Video stop working on some sets; Perflyst #142, 2022, a 2018 set; PoPETs 2027 lab set)"
 # v2's osb.samsungqbe.com: strengthen the reason, since both subscribed HaGeZi lists block it on 2026-11-04
+"osb.samsungqbe.com" = "Samsung account login and the Smart Hub broker on 2016-2020 sets (unverified; Perflyst #79, 2020: required for Samsung Account login on a 2018 NU8000; Perflyst #82: with it and nine others blocked, YouTube and Prime would not open; HaGeZi Samsung and Pro block it)"
+"osb-apps-v2.samsungqbe.com" = "the app store, app installs and app updates (unverified; Perflyst #150, 2023: blocked, a 2020 Q70T's store showed 'Server down for maintenance', and a 2026 comment says app updates need it; blocklistproject #227, 2022: blocked, the store broke on Q60 and QN90 sets; PoPETs 2027 lab set; cost: Perflyst #130 says the home-row ads come from it too)"
+"osb-v2.samsungqbe.com" = "the Smart Hub service broker on newer sets (unverified; blocklistproject #227, 2022: blocked with osb-apps-v2, first setup possibly failed; a Samsung Community report: unblocking it restored app installs on a Frame after a firmware update; PoPETs 2027 lab set)"
+"img-resize-cdn-prod.samsungnyc.com" = "home-screen previews of shows, films and channels (unverified; HaGeZi #3228, 2024: allowlisted on that report; PoPETs 2027 lab set)"
+"unified-ad-segment-cdn-ak-us-east-1.akamaized.net" = "Samsung TV Plus playback (unverified; HaGeZi #11088, 2026-08: blocked, TV Plus froze with 'Something went wrong'; allowed, it played; PoPETs 2027 lab set). US host; other regions unknown"
```

Kept as candidates, not must-allow (no breakage report): `osb-ussvc-v2.`, `osb-auth-v2.`, `osb-auth-ussvc-v2.`, `osb-tnc-v2-appsacc.`, `osb-mc-v2.samsungqbe.com`, `apps-multi-cdn.samsungcloudcdn.com` (CNAME `apps-aws-cdn.samsungcloudcdn.com`, CloudFront), `api.samsungconsent.com`. The apex protection on `samsungqbe.com` and `samsungcloudcdn.com` already stops a careless zone block. For `api.samsungconsent.com`: on Galaxy phones a blocked Samsung consent host (`sspapi-prd.samsungrs.com`, HaGeZi #2349) caused an endless re-consent loop; promote it on the first TV report of a re-prompt loop.

### 6.2 `[profile]`, `[categories]`

```diff
 never_block_apex = [ ...shipped..., "samsung.com", "samsungcloud.com", "samsungtv.plus", "amagi.tv" ]   # v2
+  # add: "samsungnyc.com" (previews; one host known, the zone's other roles unknown)
 consent_hosts = ["api.samsungconsent.com", "eula.samsungiotcloud.com"]                               # v2
 firmware_hosts = ["www.samsungotn.net", "otn2.samsungcloudcdn.com", "otnprd*.samsungcloudsolution.net"] # v2
+  # add: "cdn.samsungcloudsolution.com" (update check; small) only as a lookup marker, not for the 50 MB test

 "Samsung core" = [ ...v2..., ]
+  "samsungnyc.com",
 "Samsung TV Plus" = ["samsungtv.plus", "tvpn*.samsungcloud.tv"]                                       # v2
+  "unified-ad-segment-cdn-ak-*.akamaized.net",      # TV Plus ad segments: expected, never blocked
 "Voice and AI" = [ ...v2... ]
+  "bixbyllm.com", "gemini.google.com", "generativelanguage.googleapis.com",   # the last two unverified on Tizen
 "SmartThings" = ["smartthings.com", "samsungiotcloud.com"]                                           # v2
+  # comment: a signed-in TV reports input source, channel, picture mode, firmware and sound detection here
+"Samsung unknown" = ["sesupdate.com", "acrapiprd*.trafficmanager.net", "ghsimgstore.samsungcloud.tv"]
+  # not expected, not blocked: listed in the brief whenever contacted, so a tester's report can classify them
```

`akamaized.net` is a shared CDN: the category pattern is the one host family, never the zone. Check that the categorizer's `akamai*` Infra pattern does not win over the longer TV Plus pattern (longest match wins, so it should not).

### 6.3 `[discovery]` (v2 table)

```diff
-ssdp_server = ["Samsung UPnP SDK"]
+ssdp_server = ["Samsung UPnP SDK", "Samsung_UPnP_SDK"]          # both forms seen (2021 AU8000 uses the underscore)
-ports = [[8001, 8002]]
+ports = [[8001, 8002, 9197], [8001, 8002]]                      # the first is the stronger signature (every published scan, 2021-2024 sets)
-http_probe = { port = 8001, path = "/api/v2/", match = { "device.type" = "Samsung SmartTV", "device.OS" = "Tizen" } }
+http_probe = { port = 8001, path = "/api/v2/", match_all = { "device.type" = "Samsung SmartTV", "device.OS" = "Tizen" } }
+  # all fields, not any one: Samsung soundbars answer AirPlay discovery as manufacturer Samsung (HA #170287, #171990)
 hostname_hints = ["tizen*", "samsung*", "*samsung*"]
+  # "localhost" is common and dnsmasq refuses it (it is in /etc/hosts): no signal, and no warning either
+  # never key a TV on the UPnP UDN or the REST duid: some sets regenerate it at every boot (HA #169628)
```

### 6.4 `[tv_api]` and the reader

```diff
-reads = ["power", "device", "network", "app (unverified on 2021+ sets)"]
+reads = ["power", "device", "network"]
+app = "netflix-only"          # GET /applications/3201907018807 'visible'; any other answer or refusal = unknown (cleanyourtv #441)
+never_store = ["ssid", "wifiMac", "duid", "id", "udn", "ip", "name", "developerIP"]
+second_path = ["networkType=wireless", "ssid present", "ip != TV_IP"]
+standby_network_note_after = 120   # seconds of 'standby' answers before the brief says "network kept on in standby"
+os_upgrade_suffix = { "_T09" = "Tizen 9" }   # REST model suffix after an in-place upgrade (three samples)
```

### 6.5 `[[generations]]`, `[[lan_api]]`, `[[privacy_setting]]`, `[checklist]`

- Generations (v2 rows stand), with these edits: 2023 notes "Tizen 8 by update late 2024 (firmware 20xx); Tizen 9 in 2026 (firmware 2211, 2220)"; 2024 notes "Tizen 9 in 2025-2026 (builds 2115, 2130); third-party pairing broken on those builds; Google Cast by firmware"; 2025 notes "Vision AI Companion by update on Q7F and up; Daily+ ended 2026-10-30"; 2026 notes "Chromium M130; no REST sample yet". Add a `wifi_off` per family: 2017-2021 "Settings > General > Network > Expert Settings: Wi-Fi off where offered; Reset Network; Open Network Settings > Wired"; 2022 on "Settings > All Settings > Connection > Network > Expert Settings > Wi-Fi off; Reset Network; Open Network Settings > Wired" (still `wifi_off_confirmed = false`).
- `[[lan_api]]` REST record: add `device.ssid (BSSID, only when on Wi-Fi; never stored)`, `isSupport`, `Language`, `VoiceSupport`; `firmwareVersion` "Unknown on every sample 2019-2025"; `notes` "PowerState reads standby during Frame Art Mode". Application-status record: grade stays `low`; notes "404 when not installed; visible flips for Netflix only; refused from the LAN on a 2025 Tizen 9 set; POST launches apps on some sets". Both WebSocket records: notes "pairing fails without a prompt on 2024 builds 2115 and 2130 (HA #179510, samsungtvws #184)".
- `[[privacy_setting]]` Viewing Information Services: replace `opt_out_effective` with "disputed: IMC 2024 and RTINGS 2026 (S95F) saw ACR traffic stop after opting out; PoPETs 2027 (2026 data, Wi-Fi, VIS only) saw traffic consistent with ACR, at 5% or more of the opted-in volume, in 30/30 TV Plus, 41/60 antenna, 18/30 HDMI and 6/30 Tubi runs; contents unseen". Add `menu` key "2025-2026 sets" = "Home > Menu > Settings > All Settings > General & Privacy > Terms & Privacy (or the Privacy Choices link)".
- New `[[privacy_setting]]` records (no `key`, so the brief shows them as "unknown" plus the owner's date): **Keep Bixby in Standby** (Samsung IP-control sheet), **Power On with Mobile and IP Remote** (Samsung AU page, 2020 e-Manual), **Vision AI Companion consent** (Samsung SG support), **Pet Care / sound sensing** (SmartThings; works while the TV is off), **Reset PSID** (Samsung Developers; ads continue).
- `[checklist] network`: add "Expert Settings: Wi-Fi off, Power On with Mobile off, IP Remote off" and "if the TV has no network socket (the 32-inch Frame), the gateway cannot protect it". `audio`: add "Keep Bixby in Standby off" and "SmartThings: Pet Care off". `acr`: unchanged.

### 6.6 `samsung-tizen.rules`

```diff
 ! ---- ACR (Samsung-operated, video fingerprinting) ----
-! ... PoPETs 2027 found the opt-out failing in more than 60% of its scenarios ...
+! IMC 2024 and RTINGS 2026 (an S95F) saw the opt-out stop this traffic; PoPETs 2027 saw traffic consistent with ACR
+! continue after opting out in 30/30 TV Plus, 41/60 antenna and 18/30 HDMI runs (2026 data, a set on Wi-Fi). Blocked
+! whatever the setting says. Samsung Ads' own guide: screenshots every 500 ms, matched against TV, ads, games, TV Plus.
+! Source: https://iabcanada.com/wp-content/uploads/2022/09/Samsung-Ads-ACR-Guide-CA.pdf
 ||samsungacr.com^
 /^acr-[a-z]{2}-prd\.samsungcloud\.tv$/
 ||acr0.samsungcloudsolution.com^            # v2
 ||adgrx.com^                                 # v2
 ||dls.di.atlas.samsung.com^                  # v2

 ! ---- Watched, not blocked ----
+!   acrapiprd.trafficmanager.net, acrapiprdnew.trafficmanager.net: proposed to HaGeZi as Samsung tracking on
+!   2026-11-03 (#12163); role unknown, shared Azure zone: never a zone rule.
+!   api.sesupdate.com, gpms.sesupdate.com: in the PoPETs lab set; owner hidden; possibly an update service.
+!   bixbyllm.com: Bixby's LLM configuration on phones (HaGeZi #9806: blocking breaks Bixby and the AI keyboard).
+!   qoe.samsungcloud.tv: TV Plus quality beacons; unblocked until a tester shows TV Plus plays without it.
+!   *.smartthings.com: carries the TV's input source and channel when it is signed in; blocking ends phone control.

 ! ---- Rejected: not used as rules ----
+! Never pin or allow by zone: akamaized.net (the TV Plus ad-segment host is one name in a shared CDN).
+! HaGeZi Samsung and Pro also block osb-krsvc.samsungqbe.com (Korea service) and sspapi-prd.samsungrs.com (a
+! Galaxy consent host); neither appears in a US TV capture, so neither is excepted.
```

No new pins: every ACR, ad and telemetry name seen in 2026 data is already blocked by the pins or both subscribed lists (checked 2026-11-04: `log-config.`/`log-ingestion.samsungacr.com`, the `samsungads.com` hosts, `samsungads.adsmeasurement.com`, `adgrx.com`, `dls.di.atlas.samsung.com`, `reverselookup.quicksetcloud.com`, `samsung-beacons.xumo.com`). Not blocked by either list and left watched: `qoe.samsungcloud.tv`, `noticecdn.`/`oempprd.samsungcloudsolution.com`, `www.ueiwsp.com`, the Bixby hosts.

---

## 7. Changes for docs/tv/samsung-tizen.md and docs/what-it-stops.md

1. Replace the opt-out sentence in both pages with the wording at the end of section 2.2.
2. Radio steps: add the Expert Settings Wi-Fi switch, Power On with Mobile off and IP Remote off, by menu family (2017-2021, 2022 on). Add "Some Samsung TVs, such as the 32-inch Frame, have no network socket; the gateway cannot protect them."
3. "What you may notice": "If you set the TV's DNS to 8.8.8.8, as Samsung's support sometimes suggests, the gateway still answers it." "Casting from a phone, AirPlay and, on 2024 and newer sets, Google Cast do not work: nothing on your home network can reach the TV." "YouTube's IPv6 problem after the Tizen 9 update does not happen behind the gateway."
4. "What tvgw can check" (once W11's reader lands): model and year, whether the TV has moved to Tizen 9, on or standby (and that a Frame in Art Mode counts as standby), wired or Wi-Fi, whether it says it is joined to a Wi-Fi network, the Smart Hub agreement, developer mode. "What it cannot": the viewing-data and ad settings, the microphone switch, Keep Bixby in Standby, Pet Care, whether the Wi-Fi radio still scans while the cable is in, Bluetooth, SmartThings.
5. Microphones, in plain words: "Some Samsung TVs can listen while in standby (Bixby wake-up, Pet Care). The gateway cannot hear or stop that. The switch on the TV's lower edge is the only control you can trust."
6. Pairing: "The gateway does not pair with a Samsung TV. On some 2024 and newer software, pairing fails without showing anything on the screen."
7. Must-allow list: the four new rows of 6.1, each with its plain reason ("the app store and app updates", "previews on the home screen", "Samsung TV Plus playback").

---

## 8. Sources (all read 2026-11-04 unless marked)

Papers and research data:
- Mammadov, Joshi, Dubois, Choffnes, *Watching the Watchers*, PoPETs 2027: <https://watchingthewatchers.github.io/watchingthewatchers/paper.pdf> (§§4.1-4.3, 5.1, 6.1-6.3, 7; Tables 1, 5, 8, 9, 10). VERIFIED.
- Its artifacts: <https://github.com/IlgarNEU/Watching-the-Watchers> (README; `Blocklist/Blocklist.txt`; `Endpoints remaining after each filtering step/Tizen OS (Samsung TV)/Initial set.csv`, read privately, CC BY-NC-ND). VERIFIED.
- Anselmi et al., *Watching TV with the Second-Party*, IMC 2024: <https://arxiv.org/pdf/2409.06203> (§3, Appendix B Table 1). VERIFIED.
- RTINGS, *Testing Smart TV Tracking* (updated 2026-07-07): <https://www.rtings.com/tv/learn/research/smart-tv-tracking> (body not readable; via search summaries). REPORTED.
- Samsung Ads, *ACR Guide* (IAB Canada, 2022): <https://iabcanada.com/wp-content/uploads/2022/09/Samsung-Ads-ACR-Guide-CA.pdf>. VERIFIED.

Samsung:
- General specifications: <https://developer.samsung.com/smarttv/develop/specifications/general-specifications.html>. VERIFIED.
- Web engine specifications: <https://developer.samsung.com/smarttv/develop/specifications/web-engine-specifications.html>. VERIFIED.
- Tizen ID for Advertising: <https://developer.samsung.com/smarttv/develop/guides/unique-identifiers-for-smarttv/tizen-id-for-advertising.html>. VERIFIED.
- Consumer IP Control Worksheet (as of 2023): <https://image-us.samsung.com/SamsungUS/samsungbusiness/tv-ci-resources/Samsung-IP-Control.pdf>. VERIFIED.
- ACR FAQ: <https://www.samsung.com/us/support/answer/ANS10010616/>. VERIFIED.
- Power On with Mobile (AU): <https://www.samsung.com/au/support/tv-audio-video/power-on-tv-smartthings-app/>. VERIFIED.
- SmartThings offline when off (AU): <https://www.samsung.com/au/support/apps-services/my-samsung-tv-is-connected-to-smartthings-but-appears-offline-when-i-power-off-the-tv/>. VERIFIED.
- Network setup, Expert Settings Wi-Fi (PH): <https://www.samsung.com/ph/support/tv-audio-video/set-up-a-network-connection-on-your-samsung-smart-tv/>. VERIFIED.
- Connect to the internet (AU): <https://www.samsung.com/au/support/tv-audio-video/connect-your-samsung-tv-to-the-internet/>. VERIFIED.
- DNS change advice (CZ): <https://www.samsung.com/cz/support/tv-audio-video/jak-provest-zmenu-serveru-dns>. VERIFIED.
- Microphone switch (CA): <https://www.samsung.com/ca/support/tv-audio-video/how-to-enable-or-disable-the-microphone-switch-on-samsung-smart-tvs>. VERIFIED.
- Samsung Ads privacy policy (US; effective 2026-07-20): <https://www.samsung.com/us/account/privacy-policy/SamsungAds>. VERIFIED.
- 2020 e-Manual, UE32T5300 (EU), mirrored by a retailer: <https://www.appliancesdirect.co.uk/PDFs/UE32T5300AKXXU_UserManual1.PDF>. VERIFIED.
- Vision AI Companion support page (SG): <https://www.samsung.com/sg/support/tv-audio-video/what-is-the-vision-ai-companion-on-your-samsung-tv/> (via search summary). REPORTED.

LAN API and community:
- Home Assistant samsungtv manifest and bridge: <https://raw.githubusercontent.com/home-assistant/core/dev/homeassistant/components/samsungtv/manifest.json>, <https://raw.githubusercontent.com/home-assistant/core/dev/homeassistant/components/samsungtv/bridge.py>. VERIFIED.
- Home Assistant docs: <https://www.home-assistant.io/integrations/samsungtv/>. VERIFIED.
- Home Assistant core issues #187048, #179510, #169628, #189160, #170287, #171990, #162056, #166226, #138445, #130951: <https://github.com/home-assistant/core/issues/187048> and siblings. VERIFIED.
- samsungtvws issues #185, #184, #193, #179, #131: <https://github.com/xchwarze/samsung-tv-ws-api/issues/185> and siblings. VERIFIED.
- Raw REST replies: NickWaterton/samsung-tv-ws-api #29 (2025 Frame, wired), viet241/EzFrame #2 (2024 Frame, Wi-Fi, `_T09`). VERIFIED.
- cleanyourtv #441 and its device page: <https://github.com/Gathin23/cleanyourtv/issues/441>, `docs/devices/samsung-tizen.md`. REPORTED.
- SmartThings capability schemas: <https://github.com/pySmartThings/capabilities/tree/master/yaml/samsungvd>. VERIFIED.
- Pi-hole discourse, `localhost`: <https://discourse.pi-hole.net/t/tv-on-lan-using-localhost-as-the-network-name/53125>. REPORTED.

Lists and breakage reports:
- HaGeZi Samsung native v2026.1028.0504.46 (AdGuard `filter_61`) and HaGeZi Pro (`filter_48`), downloaded 2026-11-04: <https://adguardteam.github.io/HostlistsRegistry/assets/filter_61.txt>, <https://adguardteam.github.io/HostlistsRegistry/assets/filter_48.txt>. VERIFIED.
- HaGeZi issues #11088, #3228, #12163, #9806, #11796, #8536, #2349, #10760: <https://github.com/hagezi/dns-blocklists/issues/11088> and siblings. VERIFIED (as reports).
- Perflyst issues #150, #142, #130, #79, #82: <https://github.com/Perflyst/PiHoleBlocklist/issues/150> and siblings. VERIFIED (as reports).
- Blocklist Project discussion #227: <https://github.com/blocklistproject/Lists/discussions/227>. VERIFIED (as a report).
- AdGuard Filters #241698: <https://github.com/AdguardTeam/AdguardFilters/issues/241698>. VERIFIED (as a report).

Press and versions:
- SamMobile, One UI Tizen on 2023 sets (2026-04-30): <https://www.sammobile.com/news/samsung-quietly-pushes-a-follow-up-patch-after-one-ui-tizen-9/>. REPORTED.
- Tech-ish, Google Cast and the Tizen 9 rollout (2026-04-07): <https://tech-ish.com/2026/04/07/samsung-tv-google-cast-support-one-ui-tizen-9-update>. REPORTED.
- GIGA, Daily+ shutdown (2026-10-25): <https://www.giga.de/tech/wer-einen-samsung-fernseher-hat-muss-bald-auf-dieses-feature-verzichten--01M5EZ499H46RZQD5S833Q6GQZ>. REPORTED.
- SamMobile, repeated privacy pop-ups (2025-02-28): <https://sammobile.com/news/samsung-tvs-displaying-repeated-privacy-pop-ups>. REPORTED.
- Consumer Reports, smart TV snooping (updated 2025-10-19): <https://www.consumerreports.org/electronics/privacy/how-to-turn-off-smart-tv-snooping-features-a4840102036/>. VERIFIED.
- Techlicious on PoPETs (2026-10-22): <https://www.techlicious.com/blog/samsung-tv-still-watching-after-acr-opt-out/>. REPORTED.
- Fox 7 Austin, Texas settlement (2026-02-26): <https://www.fox7austin.com/news/samsung-updates-tv-data-consent-settings-after-texas-sues-over-spying>. REPORTED; the AG release was read in pass 1.
- October 2026 allegations: Android Authority (2026-10-28) <https://www.androidauthority.com/samsung-smart-tv-spying-allegations-2-3728880/>, ProPakistani (2026-10-30, Samsung's 2026-10-29 statement) <https://propakistani.pk/2026/10/30/samsung-tvs-could-be-listening-to-your-home/>, Decrypt <https://decrypt.co/381801/privacy-horror-researcher-uncovers-extent-of-samsung-smart-tv-user-tracking>. UNCERTAIN (claims unverified).
- 32-inch Frame without a LAN port: Digitec Q&A on QE32LS03C <https://www.digitec.ch/en/s1/questionandanswer/i-bought-the-samsung-the-frame-32-from-you-a-few-weeks-ago-as-the-wlan-module-is-unfortunately-very--851507> (via search summary). REPORTED.
- privacysmarthome.com DoH guide <https://www.privacysmarthome.com/guides/block-samsung-lg-smart-tv-hardcoded-doh-opnsense-2026/> (claims unverified). UNCERTAIN.

---

## 9. Open questions only a Samsung set in hand can answer

1. **Wired DNS.** With the cable as the only path, does any 2023+ set send DNS anywhere but the DHCP resolver, try DoH or DoT, or open TLS to a resolver address at boot? (Every published capture was on Wi-Fi.) tvgw's counters answer it in a day: DNAT hits from addresses other than the gateway, `DoT/DoQ` and `DoH resolvers` rejects, DNS-gate counts.
2. **The opt-out on a wired set.** With Viewing Information Services off, do lookups of `acr-us-prd.samsungcloud.tv` continue during TV Plus and HDMI? (`tvgw tv acr-test`, blocked lookups only; the setting is never switched on.)
3. **Tizen 10.** Does a 2026 set answer `/api/v2/` without pairing, with which fields, and does the model carry a `_T10`-style suffix after upgrades?
4. **Standby.** How long does `/api/v2/` keep answering after standby on a wired set with Power On with Mobile off, and with Keep Bixby in Standby on? Is the Ethernet port powered in standby?
5. **Wi-Fi while wired.** With the cable in and Expert Settings > Wi-Fi off, does the radio still probe (a Wi-Fi scanner near the TV), and does `ssid` ever appear?
6. **Must-allow costs.** One at a time, for ten minutes each: does blocking `qoe.samsungcloud.tv`, `oempprd.`/`noticecdn.samsungcloudsolution.com`, `api.samsungconsent.com` or `api.sesupdate.com` break anything, and does a blocked consent host cause a re-prompt loop?
7. **Firmware events.** How large is a routine build and a Tizen 9 upgrade on the wire, and from which host, so `firmware_events` can tell them apart?
8. **Settings across an update.** Do Viewing Information Services and Interest-Based Advertisements stay unticked across a build change (photograph the screen before and after)?
9. **The `0090` firmware field.** Does About This TV show `0080`/`0090`/`0100` matching Tizen 8/9/10 on every set?
10. **Regions.** Which TV Plus, store and login hosts does a European set use (`osb-eusvc`, `-eu` ACR and logging), so the must-allow list can say more than "US hosts"?
