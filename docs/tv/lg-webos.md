# LG TVs

You can set up an LG TV behind the gateway here. The page says what to switch off on the TV, how to pair it, and what stays reachable on purpose. tvgw is tested on an LG CX with webOS 5, the 2020 sets.

## What works

On webOS 5 everything works, and it is **Tested** on an LG CX. The gateway blocks LG's advertising, tracking and screen-recognition services and reports every day. Once paired, it reads the TV's privacy settings and Wi-Fi state every hour.

On webOS 6 and later, the 2021 sets on, the profile is **Not yet tested**. The blocks apply, and the readings work where the TV answers the same requests.

LG moves 2022 and later sets to newer webOS versions through updates, so the version the TV reports decides what the gateway does, not the year it was sold. The gateway asks the TV for its version every hour and keeps it with the TV's record. On webOS 25 and 26, LG's software refuses the permission list older pairing tools send, without showing a prompt. The gateway now pairs with its own read-only list instead.

## Turn the radios off

The gateway filters only the cable, so the TV's other connections must be off ([what it assumes](../what-it-stops.md#what-it-assumes)).

- **Wi-Fi on webOS 5:** Settings > Connection > Wi-Fi Connection. With the Wi-Fi switch on, select the saved home network and press the X on its entry to forget it; the list is hidden while the switch is off. Then turn Wi-Fi off.
- **Wi-Fi on webOS 6 and later:** not yet confirmed for these versions. Look for Wi-Fi Connection in the TV's network or connection settings, forget every saved network, then turn Wi-Fi off.
- **Wi-Fi Direct and Screen Share:** turn them off under the TV's network settings, where the TV offers them.
- **Bluetooth:** the CX keeps advertising over Bluetooth Low Energy, and webOS 5 has no switch for it. It tells nearby phones that the TV is there, but carries no internet connection.

The TV's own settings cannot be changed from the gateway: on the CX's software they change only with the remote.

## What tvgw can check on this TV

<!-- generated:can-check profile=lg-webos -->
Once the TV is paired, the gateway reads it every hour:

- whether the TV is on, and which app is in front;
- Live Plus, LG's screen recognition (ACR);
- the TV's data agreements, such as Viewing Information and Voice Information;
- the state of its wired port, Wi-Fi and Wi-Fi Direct, and whether tethering is on;
- the model and the software version.
<!-- /generated:can-check -->

On 2021 and later sets it also reads the standby switches: Always Ready, Quick Start+ and TV On With Mobile. Each keeps the TV's network up while the screen is dark, so the brief notes them when they are on. It is a note, not a red line. Where the TV reports its agreements one by one, the brief also says when the TV asks you to accept one again.

The brief raises a red line when Live Plus is not off, when Wi-Fi or Wi-Fi Direct is anything but disconnected, and when an agreement is accepted on the TV. To read the TV now, on the gateway:

```sh
sudo tvgw tvcheck
```

What it cannot see: whether the Wi-Fi radio is scanning while disconnected, a radio switched on and off between two readings, and Bluetooth. The TV also keeps its advertising switches to itself on every version: Limit AD Tracking, Screen Saver Promotion and Content Recommendation. For those, the brief relies on what you confirm.

## Before you connect the TV

1. Turn the radios off, as above.
2. Leave every data agreement declined. The gateway needs none of them.
3. Set each privacy setting below as the table says. A software update may reset them, and the brief tells you when Live Plus or an agreement changes.

| Setting | What it controls | Set it to | Where on the TV |
|---|---|---|---|
| Live Plus | Screen recognition (ACR): a fingerprint of what is on screen, HDMI inputs included, sent every few seconds | Off | webOS 5: Settings > General > Additional Settings > Live Plus. webOS 6 and later: Settings > All Settings > General > System > Additional Settings > Live Plus |
| Voice Information (user agreement) | Whether the remote's microphone may record and send speech | Declined | webOS 5: Settings > Support > Additional Settings > User Agreements > Voice Information |
| Viewing Information (user agreement) | LG's collection of viewing history for recommendations and advertising | Declined | webOS 6 and later: Settings > All Settings > Support > Privacy & Terms > User Agreements > Viewing Information |
| Limit Ad Tracking / Personalized Advertising | The advertising identifier LG and apps use to target ads | Limit Ad Tracking on; Personalized Advertising off | webOS 5 and later: Settings > All Settings > General > Additional Settings > Advertisement (or Support > Privacy & Terms) |
| Home Promotion / Content Recommendation | Promotional rows and recommendations on the home screen | Off | webOS 5 and later: Settings > All Settings > General > Additional Settings > Home Settings |

On a model with a microphone in the TV itself, also turn Hands-free Voice Control off under Settings > General > AI Service. Turn AI Voice ID off there too, and leave Alexa, Google Assistant and Copilot signed out.

## Pair the TV

Pairing lets the gateway read the TV's settings every hour. It is read-only, and optional.

Setup offers it on an LG TV:

```text
Pair the TV's LAN API now? [Y/n]:
```

When you answer yes, the TV shows a prompt asking whether to allow a connection from the gateway. Accept that prompt with the remote within a minute. It is not one of the TV's data agreements: leave those declined.

Setup then says what the TV reports about Live Plus. If Live Plus is on, turn it off as the table above says.

The key that pairing creates controls the TV, so it is created readable by the administrator only, and kept that way.

If you say no, the TV does not ask again later. Without a key, the hourly reading asks the TV nothing. The gateway then cannot see Live Plus, the TV's Wi-Fi, or when the TV is on. To pair later, or again after the TV forgot the gateway, switch the TV on and run this on the gateway:

```sh
sudo tvgw tv pair
```

It says what the TV's prompt is, as setup does. Accept the prompt with the remote, and it prints the TV's first reading.

The gateway asks the TV for read-only permissions, with a list of its own. The reference LG CX was paired with LG's own remote-app list, which still works on webOS 5, and the gateway keeps using it there. To pair with that list on purpose, add `--manifest signed` to the command above.

### If the TV stops accepting the gateway

After a software update, an LG TV on webOS 25 or 26 can refuse the key the gateway holds, without showing a prompt. The gateway then stops asking: sending a refused key every hour would put a prompt on the screen every hour. The brief says `The gateway can no longer read the TV since <date>`, the gateway's own check shows a warning, and `sudo tvgw doctor` names the fix. With the TV on, run `sudo tvgw tv pair` and accept the prompt. Nothing pairs again on its own.

An unattended setup does not pair unless its answers ask for it, since nobody may be at the TV to accept the prompt ([install with no one at the keyboard](../install/advanced.md#install-with-no-one-at-the-keyboard)).

## What stays reachable on purpose

These names are never blocked, whatever a blocklist says, because the TV stops working properly without them.

| Name | Why it stays reachable |
|---|---|
| `us.lgtvsdp.com` | The TV's clock at boot. Blocked, the clock resets to 2019 and every secure connection fails |
| `snu.lge.com` | Software updates, which carry security fixes |
| `lgtvonline.lge.com` | The TV's connectivity check; without it the TV thinks it is offline |
| `us.lgrecommends.lgappstv.com` | The Content Store's landing page; the store fails without it |
| `aic.service.lgtvcommon.com` | Content Store and launcher services |
| `us.tvsdp.lgeapi.com` | The Content Store's interface |
| `us.nextlgsdp.com` | The clock, login and store on webOS 6 and later |
| `ngfts.nextlgsdp.com` | Content Store icons and images on webOS 6 and later |
| `aic-gfts.nextlgsdp.com` | Content Store downloads and updates on webOS 6 and later |

These names are for US sets. Elsewhere the `us.` part is your country's: LG names its clock and store servers by country, and shared blocklists block most of them. On a new install, setup records the TV's country when it pairs, and the gateway lets that country's names through. When the TV later reports a country the gateway does not yet cover, the brief says so and gives the exact command to run, such as `sudo tvgw allow de.nextlgsdp.com` ([block or unblock something](../use/blocking.md)).

LG's file service also stays reachable, through a filter that looks at each request. App packages and icons pass. The screen-recognition settings file, the telemetry schedule, LG Shopping data and promotional images are refused.

## What you may notice

- **Casting from a phone and phone remote apps do not work.** Nothing on your home network can reach the TV.
- **Voice assistants do not answer.** Their back-ends are blocked, so a declined voice agreement stays a wall rather than a checkbox.
- **The LG ThinQ app cannot control the TV.** LG's ThinQ servers are blocked.
- **The TV cannot set up other remotes or devices by itself**, and Philips Hue sync does not work. Both services are blocked by name, with that cost written down in the profile.
- **Prime Video's ads still play.** They come inside the video stream from the same servers as the show.
- **LG's home-screen promotions and LG Shopping may stay empty.** Their data is refused.
- **LG Channels may not open on some 2024 and later sets.** Two LG service names it uses there stay blocked while the project decides. The CX played LG Channels with them blocked.

If an app stops working after a change, see [fix a problem](../use/troubleshooting.md).

## What was found on an LG CX

The profile was built on an LG CX with webOS 5 in October 2026. Each finding is a dated comment in the profile's rules file.

- LG's file service carries app packages and icons, and also the screen-recognition settings file and telemetry. Blocking it whole broke a Prime Video update on 2026-10-25, so since 2026-10-26 a filter splits it by request.
- The Content Store fails outright without its landing-page feed (found 2026-10-26).
- Prime Video's client telemetry was the TV's biggest non-video upload on 2026-10-25. It is blocked.
- Peacock played normally with its telemetry blocked, through playback, pause and resume (2026-10-25).
- Blocking Prime Video's ad service did not remove its ads (tried 2026-10-25).
- The TV kept a push channel open to LG's ThinQ servers. It is blocked (2026-10-25).
- The CX has no microphone in the TV. With Voice Information declined, the remote's mic button showed a consent prompt and sent nothing (2026-10-26).

The week behind these findings, in numbers, is in [what an LG CX does, measured](lg-cx-measured.md).

## Models and versions

<!-- generated:generations profile=lg-webos -->
| webOS | Years | Models | Status |
|---|---|---|---|
| 3 | 2016, 2017 | | Not yet tested |
| 4 | 2018, 2019 | B8, C8, E8, W8, SK, UK, B9, C9, E9, W9, SM, UM | Not yet tested |
| 5 | 2020 | BX, CX, GX, WX, ZX, NANO, UN | **Tested** on an LG CX (OLED55CX), software 04.64.00 |
| 6 | 2021 | A1, B1, C1, G1, Z1, QNED, NANO, UP | Not yet tested |
| 22 | 2022 | A2, B2, C2, G2, Z2, QNED, NANO, UQ | Not yet tested |
| 23 | 2023 | B3, C3, G3, Z3, QNED, UR | Not yet tested |
| 24 | 2024 | B4, C4, G4, M4, QNED, UT | Not yet tested |
| 25 | 2025 | B5, C5, G5, M5, QNED, UA | Not yet tested |
| 26 | 2026 | B6, C6, G6, M6, QNED | Not yet tested |
<!-- /generated:generations -->

Some sets from 2022 on have moved to newer webOS versions through LG's updates, so the version the TV reports matters more than its year. For each version the profile also records the version number the TV reports, where its menus are, which pairing works, and which settings the TV will report. To see what the profile knows about yours, on the gateway:

```sh
tvgw profile --model <model number>
tvgw profile --release <version the TV reports>
```

<!-- W12 (2026-11-04): a generated block for this section should also show, per row, the release the TV reports (release_range), the pairing that works (manifest), the menu paths (menu: wifi, agreements, live_plus, advertising, standby) and the support word (support); the data is in the profile's [[generations]] rows. docgen renders webOS, years, models and status today. -->

## Help test it

If your LG runs webOS 6 or later, a week of your gateway's brief is the most useful report the project can get. [Which TVs work](README.md#help-test-a-tv) says how to send one.
