# Gap 4: live TV state through SSAP subscriptions, not hourly polls

*Deep dive, 2026-11-01. Research only: nothing here is implemented or decided. It extends [01 § 7](01-radios-and-side-channels.md#7-what-the-lan-api-already-offers-the-cheapest-win) (the tvcheck v2 keys), [03 F2 hole 3](03-analyst-evaluation-and-safety.md#f2-the-code-gates-are-the-real-defense-and-they-fail-open-in-three-places) (the blind canary), [07 F3](07-measurement-and-presentation.md#f3-standby-and-off-baselines) (off baselines and `STANDBY_GAP`), [05 § 2 items 5 and 6](05-tv-privacy-research-2026.md#2-what-to-build-here) (the output-chain rule and the privacy toggles) and [the October survey § 5.3](../state-of-the-art-2026-10.md#53-per-app-attribution-and-what-left-the-house) (per-app attribution). Work in flight on other branches is taken as given: packaging, `tvgw setup`, the namespace CI gateway, supply-chain pinning, capture v2, the hardened extractor with JA4, and profiles v2.*

**Method.** I downloaded and read the source of the three libraries the question names: `bscpylgtv` master (the one tvgw uses), `aiowebostv` main, and Home Assistant's `webostv` integration on `dev`. I also read three other maintained webOS clients: homebridge-webos-tv, LGTV Companion and ColorControl. I read their issue trackers through the GitHub API, along with LG's support pages and developer forum, on 2026-11-01. I read tvgw's own code at head `43b3bd9` on the research worktree. No host was touched, and no TV was contacted. Labels used below:

- **(read from source)**: I read it in a library's code.
- **(observed)**: tvgw's repository says it.
- **(reported)**: one user's log in a tracker.
- **(unverified)**: no primary source confirms it, or it is my own inference.

Placeholders such as `<TV_IP>` stand for site values. None are given here.

---

## Bottom line

The hourly `tvcheck` gets more wrong than the edges. It misses whole sessions:

- Readings are taken once an hour at :20, so a session shorter than an hour falls entirely between two readings with probability (60 − L)/60. A 20-minute session is missed two times in three.
- When both readings around it say off or unreachable, `queries.standby_activity` books that session's lookups and connections as "while off". That is the signal 07 F3 calls the strongest one the gateway has, and trimming 10 minutes at each edge does not fix it.

One read-only WebSocket session would fix all of this:

- **Transport.** On an OLED55CXPUA at firmware 04.64.00, the TV refuses `ws://:3000` and serves `wss://:3001`.
- **Foreground app.** On that same model and firmware, `getForegroundAppInfo` accepts `subscribe` (a 2026-08 Home Assistant debug log).
- **Power state.** `getPowerState` answers there. Every maintained client subscribes to it. On webOS 22 and webOS 26 it pushes the whole power-off sequence (`Request Power Off` → `Active Standby` → `Suspend`), with a `reason` field.

Three defects need no subscriber and can be fixed now:

- tvgw counts `Screen Off` as off. In that state the TV is on and only the panel is dark.
- The judge, the canary and the pack count only `Active`, while the standby code also counts `Screen Saver` as awake.
- Each of the canary's 20 samples opens a new TLS session and makes about 13 requests.

01 § 7's key list is too long. The same bscpylgtv CX dump it cites also lists which keys the public `getSystemSettings` may read:

- **Outside that list:** `ueiEnable`, `quickStartMode`, every `general` key (`lmt`, `doNotSellMyPersonalInformation`, `adCookie`, `customizedAd`, `homePromotion`, `personalRecommend`) and most `option` keys.
- **Inside it:** `eulaStatus` (22 consent flags), `bleAdvertisingOnOff`, `soundOutput` and `eArcSupport`.

A long-lived session adds no capability to the gateway, but the pairing key it would use can do much more than read:

- bscpylgtv pairs with `CONTROL_POWER`, `LAUNCH`, keyboard and mouse input and, through a signed block, `WRITE_SETTINGS`.
- **Fix:** re-pair with an unsigned read-only manifest, and run the watcher as its own user. Systemd limits that user to the TV's address, and nftables to port 3001.

Build order:

1. Fix the state taxonomy (S).
2. Run the 26-hour probe in [Settled](#settled-the-26-hour-probe-and-its-report) (S). It answers every open key and subscription question.
3. Log `eth0` carrier changes (S).
4. Build the watcher with `tv_events` (M).
5. Add an event-triggered canary (S-M).

---

## Contents

- [F1. What the hourly reading gets wrong, from tvgw's own code](#f1-what-the-hourly-reading-gets-wrong-from-tvgws-own-code)
- [F2. Which subscriptions work on webOS 5, firmware 04.64](#f2-which-subscriptions-work-on-webos-5-firmware-0464)
- [F3. Power states and what each means for "off" and the canary](#f3-power-states-and-what-each-means-for-off-and-the-canary)
- [F4. Sessions across idle, standby and Quick Start+](#f4-sessions-across-idle-standby-and-quick-start)
- [F5. Is a long-lived session a new risk?](#f5-is-a-long-lived-session-a-new-risk)
- [F6. `tv_events`, intervals and per-app attribution](#f6-tv_events-intervals-and-per-app-attribution)
- [F7. Which privacy keys the public API can read on the CX](#f7-which-privacy-keys-the-public-api-can-read-on-the-cx)
- [Settled: the 26-hour probe and its report](#settled-the-26-hour-probe-and-its-report)
- [Where this disagrees with earlier sections](#where-this-disagrees-with-earlier-sections)
- [What to build here](#what-to-build-here)
- [Open questions](#open-questions)
- [Sources](#sources)

---

## F1. What the hourly reading gets wrong, from tvgw's own code

All of the following is **(observed)** in `src/tvgw` and `deploy/`.

- **Sampling.** `tvgw-analyze.timer` runs at `*:20`. It writes one line to `tvcheck-history.log`: time, power and app. That is the only TV state the store has (`tvstate(t, power, app)`).
- **What counts as awake.**
  - `queries.AWAKE = ("Active", "Screen Saver")`.
  - `autoblock.streaming_rate` counts TV hours as `power = 'Active'` rows.
  - `autoblock.shapes` maps hours to apps from `Active` rows only.
  - The analyst pack's `readings_on` counts `Active` only.
  - `Screen Off` is in none of these sets, so the store treats it as off.
- **The off baseline.** `standby_activity` books an interval [t, u) as off when neither end reading is in `AWAKE` and u − t ≤ `STANDBY_GAP` (5400 s). It then counts every lookup in the interval, and every connection that started in it.
- **The canary's sampler.** `analyst.live_sample` calls `lgwebos.read()` every 30 s. Each call is a full session:
  - TCP and TLS connect, then registration;
  - eight `getSystemSettings` calls, `getCurrentSWInformation`, `getSystemInfo`, `getPowerState` and `getForegroundAppInfo`;
  - then disconnect.
  
  The per-call timeout is 15 s, and a whole reading may take up to 60 s. One canary is about 20 sessions and 260 requests. Because of the sleeps, it lasts longer than its nominal 10 minutes.

**The sampling error is whole sessions, not edges.** Readings fall at a fixed minute, so the start of a session is uniform relative to them:

| Session length L | Chance no reading falls inside it | What the store then does |
|---|---|---|
| 10 min | 83% | If the readings on both sides are off or unreachable, every lookup and connection of the session counts as "while off" |
| 20 min | 67% | same |
| 30 min | 50% | same |
| 45 min | 25% | same |
| ≥ 60 min | 0% | Seen; each edge is late by U(0, 60) min, 30 min on average |

So the "new name while off" signal (07 F3), the scorecard's C1, and the analyst's "talks while off" evidence all take false positives from short evening sessions. The 10-minute edge trim in 07 F3 does not help, because no edge reading exists to trim against. The judge has a second bias: a short session's bytes count, while its hours count as zero. The streaming baseline rises, and a later collapse becomes easier to declare. That points toward false reverts, not false passes.

**The canary at 03:50.** The canary needs `Active` at the second baseline sample, and the scheduled pass runs at 03:50. 03 F2 predicts that nearly every canary is `unobserved`, and its test settles that. A watcher changes the fix. Instead of moving the schedule, the canary arms itself and runs at the next real use (F6, build item 6).

---

## F2. Which subscriptions work on webOS 5, firmware 04.64

**Transport.** On an OLED55CXPUA at 04.64.00, `ws://:3000` is refused with "Connection reset by peer", and `wss://:3001` works with LG's self-signed certificate ([aiowebostv #707](https://github.com/home-assistant-libs/aiowebostv/issues/707), 2026-08-01, **reported**). This matches LG's 2023 move to TLS-only ([LGWebOSRemote](https://www.github.com/klattimer/LGWebOSRemote), [openHAB thread](https://community.openhab.org/t/lgwebos-binding-not-working-since-latest-tv-firmware-update/150331)). bscpylgtv defaults to `wss` on 3001 unless `without_ssl=True`, so tvgw already uses 3001 **(read from source)**. The October survey's "3000 and 3001" is two ports in general; on this TV it is one.

**Subscriptions.** The SSAP framing is `{"id": n, "type": "subscribe", "uri": "ssap://<uri>", "payload": {...}}`. The TV answers once with `"subscribed": true` and then pushes messages with the same id. To stop, send `{"type": "unsubscribe", "id": n}` (aiowebostv `subscribe`/`unsubscribe`, **read from source**).

| URI | `subscribe` on CX 04.64? | Evidence | Use in tvgw |
|---|---|---|---|
| `com.webos.applicationManager/getForegroundAppInfo` | **Yes** | #707's debug log on the OLED55CXPUA, 04.64.00: `{"type":"response","id":5,"payload":{"appId":"com.webos.app.livetv","subscribed":true,...}}` | App starts and stops |
| `com.webos.service.tvpower/power/getPowerState` | **Very likely**. The request answers on that TV (`state: Active`, #707). The subscription is not separately logged for a CX | HA subscribes on every TV (`aiowebostv._get_states_and_subscribe_state_updates`); so do bscpylgtv (`subscribe_power`), homebridge (`subscribeToPowerStatusChange`) and ColorControl (**read from source**). Pushes are seen on webOS 26 over SSAP ([HA core #181890](https://github.com/home-assistant/core/issues/181890)) | Power transitions with `processing` and `reason` |
| `settings/getSystemSettings` with `subscribe` | **Yes for `picture`**; unknown for `""`, `option`, `network` | `bscpylgtv.subscribe_picture_settings`, and homebridge's picture and sound subscriptions (**read from source**) | Instant red line on `option.livePlus` or `eulaStatus` changes, if the category allows it |
| `com.webos.service.apiadapter/audio/getSoundOutput` | Very likely | HA subscribes (`subscribe_sound_output`) | Bluetooth or eARC audio (01 § 3) |
| `com.webos.media/getForegroundAppInfo` | **No**: `404 no such service or method` on 04.64.00 | #707 | Do not use |
| `tv/getCurrentChannel`, `tv/getChannelProgramInfo` | Hangs with no tuned channels on that CX | #707. It also records programme titles | **Never** |
| `com.webos.service.networkinput/getPointerInputSocket` | n/a | HA and aiowebostv open it on every connect (`_create_input_ws`) | **Never**: it is a control channel |

**Two library traps for a subscriber.**

1. **bscpylgtv's power state machine disconnects by itself.** With `states=["power"]`, `set_power_state` calls `self.disconnect()` as soon as the state leaves "on" (`Active Standby`, `Suspend`, `Power Off`) **(read from source)**. A subscriber built on it would never see the end of the power-off sequence. Keep `states=[]`, as `lgwebos.py` does, and call `client.subscribe(callback, uri, payload)` directly.
2. **The subscribe call waits for its callback.** In both libraries, `callback_handler` resolves the subscribe future only after the first callback returns. A slow callback times out the subscribe itself; that was #707's root cause. Callbacks must only queue or write a line.

bscpylgtv's `ping_handler` pings only while `is_on`, and with `states=[]` that is never. A subscriber must send its own pings (F4).

---

## F3. Power states and what each means for "off" and the canary

A `getPowerState` payload carries:

- `state`;
- `processing` while a transition runs;
- `onOff` and `reason` (`remoteKey`, `wakeOnWiFi`, `hdmiCec`) during transitions;
- sometimes `powerOnReason`.

Field names come from homebridge's handler and ColorControl's `PowerStateChanged` **(read from source)**, and from captures below.

**A complete sequence, captured on the TV** (65QNED866QA, webOS 22, 04.60.91, Quick Start+ on, `luna-send … getPowerState '{"subscribe":true}'`; [cleanyourtv #53](https://github.com/lasharor/cleanyourtv-WebOS/issues/53), 2026-10-30, **reported**):

```text
{ "state": "Active", "processing": "Request Power Off", "onOff": "off", "reason": "remoteKey" }
{ "state": "Active", "processing": "Request Active Standby", "onOff": "off", "reason": "remoteKey" }
{ "state": "Active", "processing": "Prepare Active Standby", "onOff": "off", "reason": "remoteKey" }
{ "state": "Active Standby" }
{ "state": "Active Standby", "processing": "Request Suspend", ... }
{ "state": "Active Standby", "processing": "Prepare Suspend", ... }
{ "state": "Suspend" }
{ "state": "Suspend", "processing": "Prepare Resume", "onOff": "on", "reason": "wakeOnWiFi" }
{ "state": "Suspend", "processing": "LastInput Ready", ... }
{ "state": "Suspend", "processing": "Screen On", ... }
{ "state": "Active" }
```

The same reporter adds three observations:

- a scripted `powerOff` is still reported as `remoteKey`;
- a second power-off a minute after a wake skipped the `Active Standby` steps;
- the on-TV subscription survived `Suspend`.

Over SSAP on webOS 26, a real power-off shows `Request Power Off`, `Request Active Standby`, then `Active Standby` ([HA #181890](https://github.com/home-assistant/core/issues/181890), **reported**). A 2024 homebridge log shows `state: Active, processing: Prepare Active Standby, reason: hdmiCec` ([homebridge-webos-tv #546](https://github.com/merdok/homebridge-webos-tv/issues/546)).

| State (`processing`) | Meaning | Sources | tvgw today | Proposed class |
|---|---|---|---|---|
| `Active` (none) | On, picture up | All clients | Awake | `on` |
| `Active` + `Request Power Off`, `Request Active Standby` or `Prepare Active Standby` | Switching off, within seconds | Captures above; ColorControl reads `Request Power Off` as the off edge | Awake (if the hourly reading lands there) | `going_off`; the off edge is the first such event |
| `Screen Off` | **On with the panel dark**: audio or an app keeps running (the "screen off" option, or energy saving) | aiowebostv/bscpylgtv: `is_on` true, `is_screen_on` false; LGTV Companion: "Device is ON, but screen is blanked" | **Off** (not in `AWAKE`), and not `Active` for the canary or the judge | `on_dark`: on |
| `Screen Saver` | On and idle; the screen saver runs. The CX has `general.screenSaverAd` ("on" in the dump) | homebridge | Awake for standby, **not** for the judge or the canary | `idle`: on |
| `Active Standby` | Off to the user, system up. Two cases: (a) the OLED compensation cycle after power-off, which homebridge labels "Pixel refresher" and which lasts about 8 minutes, reported on a CX ([#334](https://github.com/merdok/homebridge-webos-tv/issues/334)); (b) the step before `Suspend` with Quick Start+ | Captures above | Off | `off_awake`: off, network up |
| `Suspend` | Quick Start+ standby (warm); wakes by network or CEC | Capture above | Off (unreachable, probably) | `off_suspended` |
| `Power Off` | Off, in some firmware's vocabulary | aiowebostv/bscpylgtv `is_on` lists | n/a | `off` |
| *(no answer)* plus carrier down | Deep standby with Quick Start+ off | F4 | `unreachable`, counted as off | `off_deep` |

**Consequences.**

- **Screen Off is a misclassification today.** A `Screen Off` reading opens an off interval in `standby_activity`, and the user's streaming during it becomes "talks while off". **Fix now (S):**
  - `AWAKE = ("Active", "Screen Off", "Screen Saver")`;
  - `autoblock` and the pack use `power IN AWAKE` instead of `= 'Active'`;
  - the canary's "TV not on" test uses the same set.
  
  `Screen Off` readings are probably rare. The SQL in 07 F3 shows whether they occur at all.
- **The baseline should split "off" three ways**: `off_awake`, `off_suspended`, `off_deep`, each with its own exposure hours. `off_awake` is when an OLED does its compensation with the network up: the most natural time for background fetches, and the one to watch. A new name in `off_deep` would be a contradiction, which can happen only if the carrier and the API disagree. That is a red line of its own.
- **`reason` gives a self-wake signal.** A wake whose reason is neither `remoteKey` nor `hdmiCec`, while nobody is home, would mean the TV woke itself or was woken (Wake-on-LAN, Cast). Keep it in `tv_events` for the brief. It is not proof of who acted, because a script's power-off also reads `remoteKey`.
- **07 F3's test cannot detect Quick Start+.** `Active Standby` occurs with Quick Start+ off, as the compensation cycle and as a transition. `quickStartMode` is not in the public read list (F7). With Quick Start+ on, the steady state is `Suspend`, and the hourly poll probably sees it as `unreachable`, the same as deep standby. The owner reads it from the menu: Settings > General > Additional Settings > Quick Start+ ([LG CA help](https://www.lg.com/ca_en/support/product-support/troubleshoot/help-library/cs-CT52001643-20153130708440/)). LG warns that "standby power consumption may increase" ([LG IN](https://www.lg.com/in/support/product-help/CT20150005-20153130708490)).

---

## F4. Sessions across idle, standby and Quick Start+

**Idle sessions.**

- No tracker or source reports a webOS TV closing an idle, authenticated session.
- Home Assistant holds one session per TV indefinitely: `iot_class: local_push`, aiohttp `heartbeat=5` (a pong is expected within 2.5 s), and a reconnect attempt every 10 s while disconnected (`coordinator.SCAN_INTERVAL = timedelta(seconds=10)`) ([manifest](https://raw.githubusercontent.com/home-assistant/core/dev/homeassistant/components/webostv/manifest.json), [coordinator](https://raw.githubusercontent.com/home-assistant/core/dev/homeassistant/components/webostv/coordinator.py), **read from source**).
- bscpylgtv's defaults are a 1 s ping with a 20 s pong timeout, sent only while on.
- Whether a CX on 04.64 closes a session that sends no pings is **unverified**. Probe T-P3 runs one evening without pings to find out.

**Losing the transport does not mean the TV is off.**

- On webOS 26, HA saw `No PONG received after 2.5 seconds` and marked the TV off for about 10 s while the picture stayed up. A 20 s heartbeat did not help ([HA #181890](https://github.com/home-assistant/core/issues/181890), 2026-09). HA #138215 (2025) shows the same.
- **Rule for tvgw:** the power state changes only on a power event.
  - A dropped session opens an `unobserved` interval.
  - The first power event after the reconnect closes it.
  - If the last state before the drop was `on` and the TV answers `Active` with no off sequence seen, the gap counts as `on (unobserved)`. If an off sequence was seen, the gap is off.
  - Carrier state (below) settles the rest.

**Power-off with Quick Start+ off (the owner's case).**

- The TV's network goes down. `deploy/networkmanager/90-tvgw.conf` sets `ignore-carrier=yes` to keep the gateway address on `eth0` "while the TV is off" **(observed)**, which implies that `eth0` loses carrier when the TV powers off. That is my inference; test T-P2 checks it.
- The WebSocket then dies without a close frame. The Pi learns of it from the carrier, at once, or from a ping timeout.
- So the kernel's carrier events on the TV interface are a second, passive, sub-second power signal that needs no pairing. Watch `ip -ts monitor link dev eth0`, or the counters `/sys/class/net/eth0/carrier_up_count` and `carrier_down_count`.
- The two signals split the work: carrier gives deep standby against everything else, and SSAP gives the states inside "carrier up".

**Quick Start+ on.** An on-TV luna subscription survives `Suspend` (cleanyourtv #53). Whether a TCP session from the Pi survives `Suspend` is **unverified**: the TV's stack is frozen, so it depends on the Pi's TCP timeouts. Test it only if the owner wants Quick Start+ anyway; this section does not recommend turning it on.

**Does holding a session change power state or standby draw?**

- No source shows SSAP traffic waking a TV or holding it awake.
- The one 2026 claim that a reconnect woke the TV ([HA #182486](https://github.com/home-assistant/core/issues/182486), webOS 26 G-series) was traced by its own reporter to an automation that woke an Apple TV, which then woke the LG over HDMI-CEC. HA's maintainer adds that a reload should only ever show off → unavailable.
- With Quick Start+ off, the CX's network is down in deep standby, so the Pi cannot hold a session there. There is nothing to keep open.
- T-P2 measures the one place a session could matter: the time from power-off to carrier loss, with and without a session. If a power meter is at hand, read the standby watts too.

**Reconnect hygiene. These rules matter more than the ping interval.**

1. **Never retry registration after a pairing error.** If the TV rejects the key, it shows a pairing prompt on screen. bscpylgtv then waits for a reply after the `PROMPT` response **(read from source)**, so a reconnect loop would put a prompt on the screen every few seconds. Stop instead, raise "pairing key rejected" as a coverage line, and wait for `tvgw setup`.
2. **Back off.** HA's maintainer has seen TVs block a source address ("Connection reset by peer") after repeated bad-key attempts ([HA #166971](https://github.com/home-assistant/core/issues/166971), maintainer's comment, **unverified**). Schedule: on carrier up, try at +5 s, +15 s and +30 s, then every 60 s. On carrier down, stop trying.
3. **Close properly.** On webOS 10.3.1, a close without a close handshake (code 1006) was followed by minutes of handshake timeouts on 3001 ([aiowebostv PR #736](https://github.com/home-assistant-libs/aiowebostv/pull/736), open). Send a close frame before cancelling receive tasks.
4. **Never send Wake-on-LAN, never open the input socket, never subscribe to channels.**

---

## F5. Is a long-lived session a new risk?

**The key is not read-only.** "Read-only" is a property of tvgw's code, not of the pairing.

- **What the key was granted.** `bscpylgtv/manifest.py` requests 28 unsigned permissions, among them `CONTROL_POWER`, `LAUNCH`, `LAUNCH_WEBAPP`, `CONTROL_INPUT_TEXT`, `CONTROL_MOUSE_AND_KEYBOARD`, `CONTROL_TV_SCREEN` and `WRITE_NOTIFICATION_TOAST`. A signed block (`com.lge.test`) adds `WRITE_SETTINGS`, `READ_LGE_TV_INPUT_EVENTS`, `UPDATE_FROM_REMOTE_APP` and more **(read from source)**.
- **What that reaches.** bscpylgtv's endpoints include `system/turnOff`, `system.launcher/launch`, `tv/executeOneShot` (a screenshot), `com.webos.service.devicereset/requestReboot` and `system.notifications/createAlert`.
- **What 04.64 refuses.** Per `lgwebos.py`'s docstring **(observed)**, firmware 04.64 refuses the Luna side door. Whether the SSAP-level control and screenshot calls work with this key on 04.64 is **unverified**. HA controls CX sets with an equivalent key, so assume they do.

A thief of `/var/lib/tvgw/lgtv-keys.sqlite` can therefore switch the TV off, launch apps, type, put up prompts and perhaps take screenshots. That risk exists today, with or without a watcher.

**Minimal key (forward-compatible as well).**

- **The TV enforces per-manifest permissions.** In 2026, webOS 26 began rejecting the signed manifest ("403 Pairing rejected: blacklisted certificate detected", [HA #172703](https://github.com/home-assistant/core/issues/172703)), and aiowebostv 0.9.2 dropped the signed block. With the unsigned tier, `setSystemSettings` returns `401 insufficient permissions` ([aiowebostv #728](https://github.com/home-assistant-libs/aiowebostv/issues/728), 2026-09).
- **So a key paired with only read permissions cannot control the TV.**
- **Tooling exists.** bscpylgtv takes `-m <manifest.json>` (v0.5.1), and ships an unsigned example, `docs/manifests/manifest-comp.json` ([bscpylgtv manifests](https://github.com/chros73/bscpylgtv/tree/master/docs/manifests)).

Proposed `tvgw-readonly.json` (the permission each URI needs is undocumented, so this is a starting set the test matrix below must confirm):

```json
{ "appVersion": "1.1", "manifestVersion": 1, "deviceName": "tvgw (read-only)",
  "permissions": ["READ_POWER_STATE", "READ_RUNNING_APPS", "READ_APP_STATUS", "READ_SETTINGS",
                  "READ_INPUT_DEVICE_LIST", "READ_NETWORK_STATE", "READ_COUNTRY_INFO", "READ_INSTALLED_APPS"] }
```

**Risk in the minimal key.** `getCurrentSWInformation` may need the signed tier. aiowebostv's comment says software info is "most likely to fail with new handshake". If it fails, tvgw loses its firmware tracking (05 item 4). Fallbacks are the `hello` payload (`deviceOSReleaseVersion`, a webOS release, not 04.64.xx) and `getSystemInfo`. Decide after the test; do not drop the full key until firmware is still readable.

**Test matrix (owner at the TV once, about 10 minutes).**

1. Pair with the minimal manifest: `sudo /opt/tvgw-venv/bin/bscpylgtvcommand -m /root/tvgw-readonly.json -p /var/lib/tvgw/tvwatch-key.sqlite <TV_IP> get_power_state`, and accept the prompt.
2. With that key, run `get_current_app`, `get_software_info`, `get_system_info`, `get_inputs`, `get_system_settings option '["livePlus"]'` and `get_connection_info`. Each should succeed.
3. Run `button HOME` and `show_message hi`. Each must fail with `401`.

**What the long-lived session itself changes.**

1. **Fewer authentications.** One registration per TV wake, instead of 24 or more a day plus about 20 per canary. That is a small net gain.
2. **A daemon that parses TV-controlled bytes all the time.** bscpylgtv opens its socket with `websockets.connect(..., max_size=None)` **(read from source)**, so a hostile TV could make the Pi buffer an arbitrarily large frame. Cap it at 1 MiB: patch the call or use a 60-line client of tvgw's own.
3. **TV-controlled strings reach the store and the pack.** An `appId` is a string the TV chooses: an injection channel of the kind 03 F3 maps. Accept `^[a-z0-9][a-z0-9._+-]{0,127}$` and store anything else as `invalid`. Accept power fields only from the vocabulary in F3, else `other`.
4. **05 item 5's output rule has to admit the watcher's uid, and can be narrower:**

```nft
# output chain, before any general accept
oifname "eth0" ip daddr $TV_IP tcp dport 3001 meta skuid { 0, $TVWATCH_UID } counter accept comment "TV API from root or tvwatch"
oifname "eth0" ip daddr $TV_IP tcp dport { 3000, 3001 } counter drop comment "TV API from anyone else"
```

**Unit hardening.** `User=tvgw-tv`, with the key file `0600 tvgw-tv`.

```ini
[Service]
User=tvgw-tv
NoNewPrivileges=yes
ProtectSystem=strict
ProtectHome=yes
PrivateTmp=yes
CapabilityBoundingSet=
SystemCallFilter=@system-service
RestrictAddressFamilies=AF_INET AF_UNIX
IPAddressDeny=any
IPAddressAllow=<TV_IP>/32
MemoryMax=64M
ReadWritePaths=/var/lib/tvgw/tv-events /run/tvgw
Restart=always
RestartSec=30
```

`IPAddressAllow` is enforced by cgroup BPF (cgroup v2, as on trixie's 6.18). Even a watcher compromised through its parser could reach nothing but the TV.

**Verdict.**

- A long-lived session is **not a new risk** if it runs as above.
- The real exposure is the full-permission key, which exists today. Re-pairing with the minimal manifest is worth doing whether or not the watcher is built.
- A residual: the root-run hourly `tvcheck` and the canary would use the same minimal key. The full key should be removed from the Pi: `shred -u` the old file once the matrix passes.
- I found no documented way to revoke one client key on webOS 5 short of a factory reset **(unverified)**, so the old key stays valid on the TV. It is harmless once no copy is left.

---

## F6. `tv_events`, intervals and per-app attribution

**Schema.** The schema is additive, and `tv_intervals` is derived from the events and can be rebuilt.

```sql
CREATE TABLE IF NOT EXISTS tv_events(
  t REAL NOT NULL,            -- Pi receive time (chrony); the TV's messages carry no timestamps
  kind TEXT NOT NULL,         -- 'power' | 'app' | 'setting' | 'sound' | 'session' | 'link'
  state TEXT,                 -- power state, appId, 'up'/'down', setting key=value
  processing TEXT,            -- power.processing
  reason TEXT,                -- power.reason or powerOnReason
  src TEXT NOT NULL,          -- 'ssap' | 'carrier' | 'tvcheck'
  PRIMARY KEY (t, kind, src));
CREATE TABLE IF NOT EXISTS tv_intervals(
  t0 REAL PRIMARY KEY, t1 REAL NOT NULL,
  class TEXT NOT NULL,        -- on | on_dark | idle | going_off | off_awake | off_suspended | off_deep | unobserved
  app TEXT,                   -- app in front for on-classes, else NULL
  observed INTEGER NOT NULL); -- 0 when the interval was inferred across a dropped session
CREATE INDEX IF NOT EXISTS tv_intervals_t1 ON tv_intervals(t1);
```

**Ingest.**

- The watcher appends JSON lines to `/var/lib/tvgw/tv-events/events.jsonl`. It also replaces `/run/tvgw/tvstate.json` atomically on each event (for the canary).
- `ingest` tails the log the way it tails `tvcheck-history.log` today (`_tail`), then rebuilds `tv_intervals` from the last 48 h of events.
- The hourly `tvcheck` lines go in as `src='tvcheck'`, which keeps the two sources cross-checkable.

**Attribution: the app in front when the flow started.**

```sql
-- per flow: the interval that contains its start
SELECT f.id, i.class, i.app, i.observed
FROM flows f
LEFT JOIN tv_intervals i
  ON i.t0 = (SELECT MAX(t0) FROM tv_intervals WHERE t0 <= COALESCE(f.t_start, f.t_end))
 AND COALESCE(f.t_start, f.t_end) < i.t1
WHERE f.t_end >= :since;
```

**Rules and caveats.**

- **A connection that inherits its name** under decision 21 also inherits its app from the flow it continues.
- **Lead time.** An app opens connections slightly before its foreground event, and the launcher prefetches. A flow that starts in the 3 s before an app event belongs to the new app; mark it `attr = lead`. The 3 s is a guess to calibrate with T-P5.
- **Background traffic is not the foreground app's.**
  - LG's own services (`*.lgtvcommon.com`, `snu.lge.com`, `ngfts`) run under any app.
  - The CX's config namespaces include `com.webos.service.preloadmanager.*` **(read from the CX dump)**, so apps may be preloaded and talk before they reach the front. Whether that happens on 04.64 is **unverified**.
  - So the foreground app is an attribution only for the profile's app categories (Streaming, the app's own CDNs). For `LG`, `Ads` and `Telemetry` names, the brief shows "while X was in front", never "X sent".
- **Privacy.**
  - `tv_events` with `app` is a viewing diary at app granularity, to the second. Keep it root-only, like the store, and prune it on the store's schedule.
  - The analyst pack gets only per-day aggregates: app → minutes on screen, power transitions per class, and wakes per `reason`. It never gets raw events.
  - Never subscribe to channel or program information (F2).

**JA4 cross-check (Q5).** This becomes measurable once the hardened extractor writes JA4. The prediction below is mine and **unverified**:

- **YouTube** runs on Cobalt, which vendors BoringSSL ([youtube/cobalt `third_party/boringssl`](https://github.com/youtube/cobalt/tree/main/third_party/boringssl)).
- **Netflix** is a native app with its own stack.
- **Web apps** share webOS 5's web engine, Chromium 68 ([LG web engine table](https://webostv.developer.lge.com/develop/specifications/web-api-and-web-engine)).
- **LG's system services** use yet other stacks.
- Expectation: high agreement for native apps, none between web apps (they share one JA4), and a "system stack" that appears under every foreground app.

The metric, on 02 F5's stack key (JA4_b plus tvgw's extension hash):

```sql
-- purity of each stack: the share of its flows that started under its most common foreground app
WITH a AS (SELECT x.stack_key, i.app FROM flow_ja4 x JOIN flows f ON f.id = x.flow_id
           JOIN tv_intervals i ON COALESCE(f.t_start,f.t_end) >= i.t0 AND COALESCE(f.t_start,f.t_end) < i.t1
           WHERE i.class IN ('on','on_dark','idle') AND i.app IS NOT NULL)
SELECT stack_key, COUNT(*) n, COUNT(DISTINCT app) apps,
       MAX(c) * 1.0 / COUNT(*) purity
FROM (SELECT stack_key, app, COUNT(*) c FROM a GROUP BY stack_key, app) JOIN a USING (stack_key)
GROUP BY stack_key ORDER BY n DESC;
```

(`flow_ja4(flow_id, stack_key)` is whatever the extractor branch lands. Rename it to match.)

**Decision rule.**

- A stack with purity ≥ 0.9 over ≥ 200 flows names its app. The brief may then attribute that stack's flows to the app even while the watcher is down.
- A stack seen under ≥ 3 apps with purity < 0.5 is a system stack. Its flows are never attributed to the foreground app.
- **Agreement**, the number Q5 asks for: the share of Streaming-category flows whose stack is pure for the app in front. Report it monthly on the Coverage line.

---

## F7. Which privacy keys the public API can read on the CX

bscpylgtv's CX dump (OLED CX, firmware 04.63.25, webOS 5.6.1; updated 2025-10-12, commit `b48cd402`) lists every setting through the Luna side door. It then lists, separately, **"some of the settings above can be retrieved by the public API (used by `get_system_settings` method)"** ([available_settings_CX.md](https://github.com/chros73/bscpylgtv/blob/master/docs/available_settings_CX.md), **read from source**).

`tvgw tvcheck` uses that public method. On 04.64 the Luna side door is closed **(observed)**. So the public list, not the full dump, is what 04.64 can be expected to answer. tvgw's current `READS` are all inside it, which fits. homebridge reads only listed keys too, though it subscribes to `sound.soundMode`, which is not listed. So treat the list as known-good, not as complete.

| Key | Category | In the public read list (04.63.25)? | Value in the dump's TV (not the owner's) | Use |
|---|---|---|---|---|
| `eulaStatus` (flags: `acrAllowed`, `acrOnAllowed`, `acrAdAllowed`, `acrGdprAllowed`, `voiceAllowed`, `voice2Allowed`, `customAdAllowed`, `customadsAllowed`, `thirdPartySharingAllowed`, `cookiesAllowed`, `marketingOnAllowed`, `remoteDiagAllowed`, `chpAllowed`, `takeOnAllowed`, `generalTermsAllowed`, `additionalDataAllowed`, `additional1Allowed` to `additional5Allowed`, `networkAllowed`) | `""` | **Yes** | all false except `networkAllowed: true` | The consent record. Flatten it; any flag other than `networkAllowed` turning true is a red line |
| `eulaInfoNetwork`, `mobileSetupStatus` | `""` | Yes | | Which legal notices were accepted; setup state |
| `localeInfo` | `""` | Yes | | Skip: locale only |
| `bleAdvertisingOnOff` | `network` | **Yes** | `off` | 01's BLE switch |
| `deviceName`, `wolwowlOnOff` | `network` | Yes | | Already read |
| `allowMobileDeviceAccess` | `network` | **No** | `true` | The SSAP on/off switch itself ([webosbrew](https://www.webosbrew.org/pages/hidden-system-settings)) |
| `ipv6Enable` | `network` | No | `"true"` | |
| `livePlus`, `storeMode`, `audioGuidance`, `country`, `zipcode` | `option` | Yes | `livePlus: off` | Already read |
| `syncMode`, `smartServiceCountryCode3` | `option` | Yes | `off`, `other` | Service-region code: shows region-dependent behaviour |
| `addressInfo` | `option` | Yes | | **Do not read**: a postal address |
| `quickStartMode`, `turnOnByVoice`, `enableIpControl`, `enableSDDP` | `option` | **No** | `off` each | |
| `simplinkEnable` | `other` | Yes | | Already read |
| `ueiEnable`, `simplinkAutoPowerOn` | `other` | **No** | `off`, `on` | |
| `lmt` (Limit Ad Tracking, by name; **unverified**), `doNotSellMyPersonalInformation`, `adCookie`, `customizedAd`, `homePromotion`, `personalRecommend` (`{changedByUser, value}`), `screenSaverAd`, `aiNudge`, `voiceLongDistance` | `general` | **No** (no `general` key is listed) | `off`, `off`, `on`, `off`, `on`, `off`, `on`, `on`, `on` | 05 item 6's candidates. They exist, but probably not over the public API |
| `soundOutput`, `eArcSupport` | `sound` | **Yes** | | Bluetooth or eARC audio |
| `btSpeakerMode`, `btDotAutoScan` | `sound` | No | `off`, `off` | |
| `irBlaster` | **`commercial`** (not `option`, as 01 § 7 has it) | No | `"0"` | |

**What this settles and what it leaves.**

- `tvcheck` v2 (01 item 1) should read `eulaStatus` (flattened), `bleAdvertisingOnOff`, `soundOutput`, `eArcSupport`, `syncMode` and `smartServiceCountryCode3`, and probe the rest once.
- The candidates outside the list are expected to fail. That expectation is **unverified for 04.64** and is answered by the census in the probe below, which asks for each key separately and records each value or error text.
- **Mapping the settings in IMC 2024's Table 1 to keys is my inference throughout:** Limit Ad Tracking → `lmt`, Do Not Sell → `doNotSellMyPersonalInformation`, Home Promotion → `homePromotion`, Content and AI Recommendation → `personalRecommend` and `aiNudge`, Viewing Information → `eulaStatus.acrAllowed`, Voice Information → `voiceAllowed`, Interest-Based Advertising → `customAdAllowed` or `customadsAllowed`. Confirm each by flipping it on screen while the probe's settings subscription is running. Only flip settings that are already on, and only toward off.
- **Fallback for keys the API cannot read:** record them once by hand as profiles v2 `[[privacy_setting]]` entries with `source = "owner, on screen, <date>"`. Re-read them by hand after every firmware change (05 item 4). Better a dated human reading than a silent "unknown".

---

## Settled: the 26-hour probe and its report

One read-only session answers Q1, Q2 (partly), Q3 and Q6, and measures the edge error. It needs no change to tvgw and no new pairing, because it uses the current key. Run it after the minimal-key matrix if that has been done.

**`/root/tv-probe.py`** (kept outside the repository; run with the venv's Python and `-I`):

```python
#!/usr/bin/env python3
"""Read-only SSAP probe: subscribe to power, app, sound output and some settings; log one JSON line per
event; on the first session, ask for each census key separately. Never writes to the TV.
Usage: tv-probe.py TV_IP KEY_FILE OUT.jsonl [HOURS=26] [PING_S=30]"""
import asyncio, json, sys, time
from bscpylgtv import WebOsClient
from bscpylgtv.exceptions import PyLGTVPairException

ip, key, out = sys.argv[1], sys.argv[2], sys.argv[3]
hours = float(sys.argv[4]) if len(sys.argv) > 4 else 26.0
ping_s = float(sys.argv[5]) if len(sys.argv) > 5 else 30.0
fh = open(out, "a", buffering=1)

def pick(kind, p):
    if not isinstance(p, dict):
        return p
    if kind == "power":
        return {k: p[k] for k in ("state", "processing", "onOff", "reason", "powerOnReason") if k in p}
    if kind == "app":
        return {"appId": p.get("appId")}
    if kind == "sound":
        return {"soundOutput": p.get("soundOutput")}
    if kind.startswith("set."):
        return p.get("settings", p)
    return p

def log(kind, p=None):
    fh.write(json.dumps({"t": round(time.time(), 3), "kind": kind, "p": pick(kind, p)}, default=str)[:4000] + "\n")

SUBS = [
    ("power", "com.webos.service.tvpower/power/getPowerState", None),
    ("app", "com.webos.applicationManager/getForegroundAppInfo", None),
    ("sound", "com.webos.service.apiadapter/audio/getSoundOutput", None),
    ("set.picture", "settings/getSystemSettings", {"category": "picture", "keys": ["backlight"]}),  # positive control
    ("set.option", "settings/getSystemSettings", {"category": "option", "keys": ["livePlus"]}),
    ("set.eula", "settings/getSystemSettings", {"category": "", "keys": ["eulaStatus"]}),
    ("set.network", "settings/getSystemSettings", {"category": "network", "keys": ["bleAdvertisingOnOff"]}),
]
CENSUS = {  # no zipcode, addressInfo, localeInfo or deviceName: site values stay out of the log
    "": ["eulaStatus", "eulaInfoNetwork", "mobileSetupStatus"],
    "network": ["bleAdvertisingOnOff", "wolwowlOnOff", "allowMobileDeviceAccess", "ipv6Enable"],
    "option": ["livePlus", "storeMode", "syncMode", "smartServiceCountryCode3", "quickStartMode",
               "turnOnByVoice", "enableIpControl", "enableSDDP"],
    "other": ["simplinkEnable", "ueiEnable", "simplinkAutoPowerOn"],
    "general": ["lmt", "doNotSellMyPersonalInformation", "adCookie", "customizedAd", "homePromotion",
                "personalRecommend", "screenSaverAd", "aiNudge", "voiceLongDistance"],
    "sound": ["soundOutput", "eArcSupport", "btSpeakerMode", "btDotAutoScan"],
    "commercial": ["irBlaster"],
}

async def census(c):
    try:
        log("services", await asyncio.wait_for(c.request("api/getServiceList"), 15))
    except Exception as e:
        log("services.err", repr(e)[:300])
    for cat, keys in CENSUS.items():
        for k in keys:
            try:
                r = await asyncio.wait_for(c.get_system_settings(cat, [k]), 15)
                log("key", {"cat": cat, "key": k, "value": r.get("settings", {}).get(k, "<absent>")})
            except Exception as e:
                log("key", {"cat": cat, "key": k, "error": repr(e)[:300]})

async def session(first):
    c = await WebOsClient.create(ip, states=[], key_file_path=key, ping_interval=None)
    await asyncio.wait_for(c.connect(), 20)
    log("session.up")
    try:
        for kind, uri, payload in SUBS:
            async def cb(p, kind=kind):  # must not block: the subscribe call waits for it (F2)
                log(kind, p)
            try:
                await asyncio.wait_for(c.subscribe(cb, uri, payload), 15)
                log("sub.ok", kind)
            except Exception as e:
                log("sub.err", {"sub": kind, "error": repr(e)[:300]})
        if first:
            await census(c)
        while c.is_connected():
            await asyncio.sleep(ping_s if ping_s > 0 else 5)
            if ping_s > 0:
                await asyncio.wait_for(await c.connection.ping(), 10)
    except Exception as e:
        log("session.err", repr(e)[:200])
    finally:
        log("session.down")
        await c.disconnect()

async def main():
    end, first, fails = time.time() + hours * 3600, True, 0
    while time.time() < end:
        try:
            await session(first)
            first, fails = False, 0
        except PyLGTVPairException as e:  # a rejected key: stop, never loop on a pairing prompt
            log("pair.rejected", repr(e)[:200])
            return
        except Exception as e:
            fails += 1
            log("session.fail", repr(e)[:200])
        await asyncio.sleep(10 if fails < 3 else 60)

asyncio.run(main())
```

**Run it** as root, because of the root-only key and 05 item 5's rule, beside a passive carrier log:

```sh
sudo install -d -m 0700 /var/lib/tvgw/probe
sudo systemd-run --unit=tvgw-ssap-probe -p RuntimeMaxSec=27h -p NoNewPrivileges=yes \
  /opt/tvgw-venv/bin/python -I /root/tv-probe.py <TV_IP> /var/lib/tvgw/lgtv-keys.sqlite \
  /var/lib/tvgw/probe/events.jsonl 26 30
sudo systemd-run --unit=tvgw-link-probe -p RuntimeMaxSec=27h \
  sh -c 'exec ip -ts -o monitor link dev eth0 >>/var/lib/tvgw/probe/link.log'
# during the run, at the TV, once each:
#  - change OLED Light by one step and back (positive control for settings subscriptions)
#  - press the remote's Power off, wait 15 min, Power on (power sequence, carrier edge)
#  - open and close two apps, switch to an HDMI input and back
#  - if offered: "Screen Off" from the quick menu for 1 min (the Screen Off state)
#  - do NOT turn Live Plus or any agreement on to test it
sudo journalctl -u tvgw-ssap-probe -u tvgw-link-probe --no-pager | tail
```

Abort conditions:

- The TV shows a pairing prompt: decline it, then `sudo systemctl stop tvgw-ssap-probe`.
- The hourly `tvcheck` starts reading `unreachable` while the probe logs `Active`. Concurrent sessions with one key then conflict, which is itself an answer.

**`/root/tv-probe-report.py`** compares the probe with the hourly history and the store. It opens the store read-only.

```python
#!/usr/bin/env python3
"""Usage: tv-probe-report.py events.jsonl /var/lib/tvgw/tvcheck-history.log /var/lib/tvgw/tvgw.db"""
import collections, datetime as dt, json, sqlite3, statistics, sys

ON = {"Active", "Screen Off", "Screen Saver"}
GOING = {"Request Power Off", "Request Active Standby", "Prepare Active Standby", "Request Suspend",
         "Prepare Suspend"}
AWAKE_SHIPPED = ("Active", "Screen Saver")   # queries.AWAKE at 43b3bd9
STANDBY_GAP = 5400

ev = [json.loads(line) for line in open(sys.argv[1])]
segs, cur, t_cur = [], "unobserved", None
for e in ev:
    k, t, p, new = e["kind"], e["t"], e["p"], None
    if k == "power" and isinstance(p, dict) and p.get("state"):
        new = "on" if p["state"] in ON and p.get("processing") not in GOING else "off"
    elif k in ("session.down", "session.fail") and cur != "off":
        new = "unobserved"          # a drop after an off sequence stays off (deep standby)
    if new and new != cur:
        if t_cur is not None:
            segs.append((t_cur, t, cur))
        cur, t_cur = new, t
if t_cur is not None:
    segs.append((t_cur, ev[-1]["t"], cur))

def truth(t):
    return next((c for a, b, c in segs if a <= t < b), "unobserved")

rd = []
for line in open(sys.argv[2], encoding="utf-8"):
    f = line.rstrip("\n").split("\t")
    try:
        t = dt.datetime.fromisoformat(f[0]).timestamp()
    except (ValueError, IndexError):
        continue
    if segs and segs[0][0] <= t <= segs[-1][1]:
        rd.append((t, f[1] if len(f) > 1 else ""))

judged = [(t, p) for t, p in rd if truth(t) != "unobserved"]
agree = sum((p in ON) == (truth(t) == "on") for t, p in judged)
ons = [(a, b) for a, b, c in segs if c == "on"]
unseen = [(a, b) for a, b in ons if not any(a <= t < b for t, _ in rd)]

db = sqlite3.connect(f"file:{sys.argv[3]}?mode=ro", uri=True)
booked = wrong_s = wrong_dns = wrong_conns = 0.0
for (t, p), (u, q) in zip(rd, rd[1:]):
    if p in AWAKE_SHIPPED or q in AWAKE_SHIPPED or u - t > STANDBY_GAP:
        continue
    booked += u - t
    for a, b in ons:
        lo, hi = max(a, t), min(b, u)
        if lo < hi:
            wrong_s += hi - lo
            wrong_dns += db.execute("SELECT COUNT(*) FROM dns WHERE t >= ? AND t < ?", (lo, hi)).fetchone()[0]
            wrong_conns += db.execute("SELECT COUNT(*) FROM flows WHERE t_start >= ? AND t_start < ?",
                                      (lo, hi)).fetchone()[0]

delays = []
for (_, _, c), (a2, _, c2) in zip(segs, segs[1:]):
    if {c, c2} == {"on", "off"}:
        nxt = next((t for t, p in rd if t >= a2 and (p in ON) == (c2 == "on")), None)
        if nxt is not None:
            delays.append((nxt - a2) / 60)

print(f"probe span {(segs[-1][1] - segs[0][0]) / 3600:.1f} h; unobserved "
      f"{sum(b - a for a, b, c in segs if c == 'unobserved') / 3600:.2f} h")
print(f"hourly readings {len(rd)}; judged {len(judged)}; agree with events {agree}")
print(f"on sessions {len(ons)}; never seen by an hourly reading {len(unseen)} "
      f"({sum(b - a for a, b in unseen) / 60:.0f} min)")
print(f"booked off by standby_activity {booked / 3600:.1f} h; of it truly on {wrong_s / 60:.0f} min, "
      f"{wrong_dns:.0f} lookups, {wrong_conns:.0f} connections")
if delays:
    print(f"edge delay min: median {statistics.median(delays):.0f}, max {max(delays):.0f} (n={len(delays)})")
print("readings of Screen Off:", sum(p == "Screen Off" for _, p in rd))
print("power vocabulary:", collections.Counter(
    (e["p"].get("state"), e["p"].get("processing"), e["p"].get("reason"))
    for e in ev if e["kind"] == "power" and isinstance(e["p"], dict)).most_common())
print("subscriptions:", [(e["kind"], e["p"]) for e in ev if e["kind"] in ("sub.ok", "sub.err")][:16])
print("census:")
for e in ev:
    if e["kind"] == "key":
        print("  ", e["p"])
```

**Reading the result.**

| Probe output | Answers |
|---|---|
| `sub.ok power`, `sub.ok app`, then pushes on power-off and app changes | Q1: subscriptions work with the current key |
| `sub.ok set.picture`, and an event when OLED Light changes | Settings subscriptions work on 04.64 |
| `sub.ok set.option`, `set.eula`, `set.network` | Those categories can be watched live. If they fail, the hourly read stays the settings path |
| The power vocabulary, with `processing` and `reason` | Q3, for this CX. Expect `Active Standby` after power-off on days the compensation cycle runs |
| The time from `Request Power Off` to carrier down in `link.log` | Q2 and T-P2: how long the CX stays reachable after power-off |
| `session.down` while the events say on, with no power event | The TV closes idle sessions, or a ping failed. Repeat with `PING_S=0` (T-P3) |
| "never seen by an hourly reading", "truly on" minutes and lookups | The edge error and the false "while off" evidence of the shipped classification |
| The census | Q6: which keys exist on 04.64, with values or error text |

---

## Where this disagrees with earlier sections

1. **01 § 7** ("all read-only through the same `settings/getSystemSettings` call"). The dump it cites lists a public read set that leaves out `ueiEnable`, `quickStartMode`, `turnOnByVoice`, `enableIpControl`, `enableSDDP`, `simplinkAutoPowerOn`, `allowMobileDeviceAccess`, `ipv6Enable`, `voiceLongDistance`, `blueToothSpeakerMode`, `btSpeakerMode` and `btDotAutoScan`. `irBlaster` is in `commercial`, not `option`. `tvcheck` v2 must treat these as probe-once keys, not as expected readings. 01 item 3's acceptance test (`ueiEnable` read over the API) will probably not run. Its traffic-side half (`ueiwsp.com` lookups fall to about zero) does.
2. **05 item 6** ("which of these webOS 5's `getSystemSettings` returns is unverified"). Most are now located: they live in `general` as `lmt`, `doNotSellMyPersonalInformation`, `adCookie`, `customizedAd`, `homePromotion` and `personalRecommend`, which the public list does not include. The consent agreements are readable as `eulaStatus` flags. The probe settles 04.64, and the fallback is a dated record made by hand.
3. **05 item 5's rule** (`meta skuid != 0 drop` on 3000 and 3001). It is right in spirit. A watcher running as its own user needs its uid added, and on this CX the accept can be limited to 3001 (F5).
4. **07 F3** ("if `Active Standby` is absent, Quick Start+ is off"). `Active Standby` is also the OLED compensation state and a transition step, so it can appear with Quick Start+ off. With Quick Start+ on, the steady state is `Suspend`. Quick Start+ is not readable over the public API; the owner reads it from the menu. 07's 10-minute trim does not address the larger error, whole short sessions booked as off (F1).
5. **The October survey § 5.3** ("the CX already reports [the foreground app] hourly"; "the strongest signal"). An hourly sample is not attribution, and it misses short sessions outright. The foreground app is strong for the app's own streaming flows and wrong for LG's background services, which run under every app. JA4 purity (F6) is what separates the two.
6. **Design decision 4 and `architecture.md`** ("the TV's read-only LAN API"). The API session is read-only in practice. The pairing key behind it is not (F5). The docs should say "tvgw only reads", and the key should be re-paired read-only.
7. **The canary** (03 F2 hole 3). Instead of moving the analyst's schedule to an evening hour, make the canary event-triggered, so the schedule stops mattering (build item 6).

---

## What to build here

Ranked by value for the risk. Effort: S under two days, M about a week. Risk is to the running gateway.

| # | What | Effort | Risk | Acceptance test |
|---|---|---|---|---|
| 1 | **State taxonomy fix, no watcher needed.** `AWAKE = ("Active", "Screen Off", "Screen Saver")` in `queries`. `autoblock.streaming_rate`, `autoblock.shapes`, the pack's `readings_on` and the canary all use `power IN AWAKE`. The brief's "While off" line carries a footnote: "hourly sampling: sessions under an hour can be counted as off" | S | Low: report numbers move a little; a `Screen Off` evening no longer reads as "talks while off" | A unit test with a synthetic `tvstate` holding `Screen Off`: `standby_activity` excludes it, and `streaming_rate` counts it |
| 2 | **Run the 26-hour probe and report** above, then record the census in the profile as dated `[[lan_api]]` evidence (profiles v2) | S, plus about 10 minutes at the TV | Low: read-only; a pairing prompt is the one way it could annoy, and the probe stops on it | The report prints sub.ok/err, the power vocabulary, the census and the edge-error numbers |
| 3 | **Carrier events into `tv_events`** (`src='carrier'`): a tiny unit running `ip -ts -o monitor link dev eth0`, or a NetworkManager dispatcher line, appended to `/var/lib/tvgw/tv-events/link.log` and ingested. The `off_deep` class comes from carrier down | S | None: passive and kernel-side | T-P2: carrier down within N s of power-off and up within a few seconds of power-on, both in the store |
| 4 | **Re-pair read-only.** `tvgw-readonly.json` (F5), the permission matrix, then `shred -u` the full key. `tvgw setup` (in flight) pairs with this manifest by default | S, plus the owner at the TV | Low-medium: if `getCurrentSWInformation` needs the signed tier, firmware tracking breaks. Keep the old key until the matrix passes | The control calls return 401, the read calls succeed, and the firmware is still read |
| 5 | **`tvgw tvwatch`, the subscriber.** `User=tvgw-tv`, the sandbox in F5, wss on 3001, a 1 MiB frame cap, its own 30 s pings, the F4 reconnect rules (no registration retry, backoff gated on carrier), and appId and vocabulary validation. It writes `events.jsonl` and `/run/tvgw/tvstate.json`; `ingest` builds `tv_events` and `tv_intervals`. The hourly `tvcheck` stays, as a settings read and a cross-check (`src='tvcheck'`). The 05 item 5 rule gains the watcher's uid | M | Low-medium: a new long-running service. If it is down, the canary falls back to `lgwebos.read` and the brief shows "TV state: hourly only" on the Coverage line | Over 7 days, hourly readings agree with the event state ≥ 99% of the time, excluding `unobserved`; every carrier edge has a matching power event within 30 s |
| 6 | **Use the intervals.** `standby_activity` from `tv_intervals`, with off split three ways (F3) and no `STANDBY_GAP`; judge TV hours = seconds in `on`, `on_dark` and `idle` divided by 3600; **event-triggered canary**: a block applied with the TV off is "armed", and a 2-minute timer `tvgw canary --if-armed` runs the 10-minute watch when the TV has been `on` with a non-launcher app for 60 s. Its baseline is that app's 3-day download rate from `tv_intervals` × flows. It reads `/run/tvgw/tvstate.json` instead of opening sessions | S-M | Medium-low: same actions as today's canary (it can revert); fewer `unobserved` | 03 F2's test: the canary `unobserved` share falls from "most" to under 20% over two weeks of autonomous blocks |
| 7 | **Per-app attribution columns and the JA4 purity report** (F6), once the extractor writes JA4. The brief's Top-talkers rows show "app in front" for Streaming names only. The pack gets per-day app minutes, never events | M | Low: reports | The purity table renders; a Netflix evening shows Netflix's CDN flows under one stack with purity ≥ 0.9 (a prediction to confirm) |
| 8 | **`tvcheck` v2, trimmed to the public read list** (F7). Settings subscriptions for `option.livePlus`, `eulaStatus` and `bleAdvertisingOnOff` go into the watcher if probe item 2 shows those categories subscribe | S | None: reads | Unit test with recorded replies; with the probe's census as the fixture |

**Do not build:**

- channel or program subscriptions (they record titles and hang on this CX);
- the pointer input socket;
- Wake-on-LAN from any tvgw component;
- any `set*` call;
- a reconnect loop faster than 5 s;
- a full-permission key on the watcher;
- raw app events in the analyst pack;
- inferring off from a dropped session.

---

## Open questions

1. **Does `getPowerState` with `subscribe` push on the CX at 04.64, and with what vocabulary?** The probe answers this. The CX might report `Power Off` rather than stopping at `Active Standby` before the network goes.
2. **Do settings subscriptions work outside `picture` on webOS 5?** The probe answers this for `option`, `""` and `network`.
3. **Does the CX close a session that sends no pings, and after how long?** Run T-P3: the probe with `PING_S=0` for one evening.
4. **How long after power-off does the CX keep its link and API up (compensation cycle or not), and does an open session change that?** Run T-P2: three power-offs with the probe running, three without, and compare the carrier-down delays.
5. **Which permission does each read URI need, and is `getCurrentSWInformation` behind the signed tier on 04.64?** The test matrix in F5 answers this.
6. **Do LG apps on the CX talk while not in front (preload)?** Run T-P5: launch Netflix once after a cold boot, return to Home, and look for Netflix-CDN flows in the 10 minutes after the app event that ended it.
7. **What are `lmt`, `customAdAllowed` and `customadsAllowed` exactly?** They are named, not documented. Flip the matching on-screen setting while the settings subscription runs, only on settings already on and only toward off, and watch which key changes. If the key is not readable, the question stays open.
8. **Two sessions, one key.** Does the hourly `tvcheck` keep working while the watcher holds a session with the same key? The probe answers this. If not, `tvcheck` asks the watcher for power and app, and opens its own session only for settings.

---

## Sources

Library source, read 2026-11-01 (raw files from the default branches):

- bscpylgtv: [webos_client.py](https://github.com/chros73/bscpylgtv/blob/master/bscpylgtv/webos_client.py) (`connect_handler`, `ping_handler`, `set_power_state`, `subscribe`, `subscribe_picture_settings`), [manifest.py](https://github.com/chros73/bscpylgtv/blob/master/bscpylgtv/manifest.py), [endpoints.py](https://github.com/chros73/bscpylgtv/blob/master/bscpylgtv/endpoints.py), [available_settings_CX.md](https://github.com/chros73/bscpylgtv/blob/master/docs/available_settings_CX.md) (04.63.25; public read list near the end; commit `b48cd402`, 2025-10-12), [docs/manifests](https://github.com/chros73/bscpylgtv/tree/master/docs/manifests), [CHANGELOG](https://github.com/chros73/bscpylgtv/blob/master/CHANGELOG.md), [PR #5, custom manifest](https://github.com/chros73/bscpylgtv/pull/5), [PR #10, get_connection_info](https://github.com/chros73/bscpylgtv/pull/10)
- aiowebostv: [webos_client.py](https://github.com/home-assistant-libs/aiowebostv/blob/main/aiowebostv/webos_client.py) (`HEARTBEAT = 5`, `_create_main_ws`, `_get_states_and_subscribe_state_updates`, `_is_tv_on`), [handshake.py](https://github.com/home-assistant-libs/aiowebostv/blob/main/aiowebostv/handshake.py), [endpoints.py](https://github.com/home-assistant-libs/aiowebostv/blob/main/aiowebostv/endpoints.py)
- Home Assistant webostv: [manifest.json](https://github.com/home-assistant/core/blob/dev/homeassistant/components/webostv/manifest.json) (`local_push`, aiowebostv 0.10.0), [coordinator.py](https://github.com/home-assistant/core/blob/dev/homeassistant/components/webostv/coordinator.py) (`SCAN_INTERVAL = 10 s`), [media_player.py](https://github.com/home-assistant/core/blob/dev/homeassistant/components/webostv/media_player.py)
- [homebridge-webos-tv LgTvController.js](https://github.com/merdok/homebridge-webos-tv/blob/master/lib/LgTvController.js) (`checkTvPowerState`, settings subscriptions)
- [LGTV Companion web_os_client.cpp](https://github.com/JPersson77/LGTVCompanion/blob/master/LGTV%20Companion%20Service/web_os_client.cpp) (power-state handling)
- [ColorControl LgDevice.cs](https://github.com/Maassoft/ColorControl/blob/master/ColorControl/Services/LG/LgDevice.cs) (`PowerState` enum, `Request Power Off`)
- [youtube/cobalt third_party/boringssl](https://github.com/youtube/cobalt/tree/main/third_party/boringssl)

Trackers (dates are when each issue was opened):

- [aiowebostv #707](https://github.com/home-assistant-libs/aiowebostv/issues/707), 2026-08-01: OLED55CXPUA, 04.64.00; `getForegroundAppInfo` subscribed; `com.webos.media` 404; 3000 refused, 3001 required; `getCurrentChannel` hangs
- [aiowebostv #728](https://github.com/home-assistant-libs/aiowebostv/issues/728), 2026-09-04: the unsigned tier returns 401 on `setSystemSettings`
- [aiowebostv PR #736](https://github.com/home-assistant-libs/aiowebostv/pull/736), 2026-09-15: close order; minutes of handshake timeouts after a 1006 close (webOS 10.3.1)
- [aiowebostv #744](https://github.com/home-assistant-libs/aiowebostv/issues/744), 2026-10-03: port 3000 hanging rather than refusing on a 2025 set
- [aiowebostv PR #631](https://github.com/home-assistant-libs/aiowebostv/pull/631), 2026-03-31
- [HA core #172703](https://github.com/home-assistant/core/issues/172703), 2026-06-01: webOS 26 rejects the signed manifest
- [HA core #181890](https://github.com/home-assistant/core/issues/181890), 2026-09-10: false offs from pong timeouts; the real off sequence over SSAP
- [HA core #182486](https://github.com/home-assistant/core/issues/182486), 2026-09-17: "reconnect wakes TV", traced to HDMI-CEC by the reporter
- [HA core #166971](https://github.com/home-assistant/core/issues/166971), 2026-03-31: the maintainer on reconnects and on source-address blocking after bad keys
- [HA core #138215](https://github.com/home-assistant/core/issues/138215), 2025-02-10: false offs on transport loss
- [cleanyourtv-WebOS #53](https://github.com/lasharor/cleanyourtv-WebOS/issues/53), 2026-10-28 and 2026-10-30: full power-off, `Suspend` and wake capture, with reasons (webOS 22)
- [homebridge-webos-tv #334](https://github.com/merdok/homebridge-webos-tv/issues/334) (CX, "Pixel refresher") and [#546](https://github.com/merdok/homebridge-webos-tv/issues/546) (`Prepare Active Standby`, `reason: hdmiCec`)
- [LGTV Companion #208](https://github.com/JPersson77/LGTVCompanion/issues/208): `Active Standby` error payload

LG and other references:

- LG Quick Start+: [LG CA help](https://www.lg.com/ca_en/support/product-support/troubleshoot/help-library/cs-CT52001643-20153130708440/), [LG IN help](https://www.lg.com/in/support/product-help/CT20150005-20153130708490), [LG AU help](https://www.lg.com/au/support/product-help/CT20088015-20153130708413)
- [LG webOS TV web engine versions](https://webostv.developer.lge.com/develop/specifications/web-api-and-web-engine) (webOS TV 5.x: Chromium 68)
- [LG developer forum: valid keys for getSystemSettings](https://forum.webostv.developer.lge.com/t/valid-categories-and-keys-for-getsystemsettings/3550) (2023-08: "we only provide the keys in the document")
- [webosbrew: hidden system settings](https://www.webosbrew.org/pages/hidden-system-settings) (`allowMobileDeviceAccess` exposes SSAP)
- [LGWebOSRemote README](https://www.github.com/klattimer/LGWebOSRemote) (ws deprecated, SSL from 2023-01-25); [openHAB thread](https://community.openhab.org/t/lgwebos-binding-not-working-since-latest-tv-firmware-update/150331)
- [webOS OSE com.webos.service.settings](https://webosose.org/docs/reference/ls2-api/com-webos-service-settings) (nonexistent keys are processed as errors)
- [arXiv 2409.06203](https://arxiv.org/html/2409.06203v1) (IMC 2024, Table 1: the settings for a full LG opt-out), via 05 item 6

tvgw, at head `43b3bd9`:

- `src/tvgw/lgwebos.py`, `src/tvgw/queries.py` (`AWAKE`, `STANDBY_GAP`, `standby_activity`), `src/tvgw/autoblock.py` (`streaming_rate`, `shapes`, `canary`, `HOME_APPS`), `src/tvgw/analyst.py` (`live_sample`)
- `deploy/bin/tvgw-analyze`, `deploy/systemd/tvgw-analyze.timer` (`*:20`), `deploy/systemd/tvgw-analyst.timer` (`03:50`), `deploy/networkmanager/90-tvgw.conf` (`ignore-carrier=yes`)
