# Samsung TVs

You can set up a Samsung TV behind the gateway here, and help test the Samsung profile. The profile is built from published blocklists and research, and has not yet run on a Samsung behind a gateway.

## What works

The Samsung profile is **Not yet tested**. The gateway blocks Samsung's advertising, telemetry and screen-recognition services by name, closes the known ways around the filter, keeps the TV away from your other devices, and reports every day.

The gateway reads nothing on a Samsung TV yet. You check its Wi-Fi and its privacy settings yourself, on the TV's own menus.

Setup does not choose the Samsung profile by itself yet: it keeps the LG profile in the settings. After setup, switch the profile on the gateway:

```sh
sudoedit /etc/tvgw/tvgw.conf      # change the PROFILE line to PROFILE=samsung-tizen
sudo tvgw adguard apply           # the filter takes the Samsung profile's blocks
sudo tvgw verify                  # every line should start with OK
```

## Turn the radios off

The gateway filters only the cable, so the TV's other connections must be off ([what it assumes](../what-it-stops.md#what-it-assumes)). These menu paths are from Samsung's own support page, read on 2026-11-03 ([connect your Samsung TV to the internet](https://www.samsung.com/au/support/tv-audio-video/connect-your-samsung-tv-to-the-internet/)). Menus vary by year and region.

<!-- generated:radios profile=samsung-tizen -->
1. Plug the gateway's cable into the TV first.
2. **Reset the network settings, so the TV forgets your Wi-Fi:** Settings > All Settings > Connection > Network > Reset Network, then Reset. On older menus: Settings > General > Network > Reset Network.
3. **Use the cable:** Settings > All Settings > Connection > Network > Network Settings, then Wired.
4. **Wi-Fi Direct and screen mirroring:** turn them off where the network menu offers them. The profile has not confirmed where they are.
5. **Bluetooth:** the profile records nothing about Bluetooth on Samsung sets yet.
<!-- /generated:radios -->

Afterwards, check that the TV's network status shows the wired connection, and that it no longer joins your home Wi-Fi.

## What tvgw can check on this TV

<!-- generated:can-check profile=samsung-tizen -->
Nothing yet. The gateway does not read a Samsung TV's settings, its Wi-Fi state or whether it is on.
<!-- /generated:can-check -->

So the brief cannot warn you if Wi-Fi comes back on, or if a software update turns a privacy setting back on. Check both after every update of the TV.

Until you tell the gateway, each brief ends with a line saying the TV's Wi-Fi was not checked. Once the TV's Wi-Fi is off and its saved networks are gone, run this once on the gateway:

```sh
sudo tvgw tv confirm wifi-forgotten yes
```

## Before you connect the TV

1. Turn the radios off, as above.
2. Set each privacy setting below as the table says.
3. Decline the TV's data agreements. The gateway needs none of them.

<!-- generated:privacy-settings profile=samsung-tizen -->
| Setting | What it controls | Set it to | Where on the TV |
|---|---|---|---|
| Viewing Information Services | Samsung's screen recognition (ACR): viewing history from apps, the tuner and HDMI inputs | Off | Newer menus: Settings > All Settings > General & Privacy > Terms & Privacy > Privacy Choices > Viewing Information Services. Older menus: Settings > Support > Terms & Policy > Viewing Information Services |
| Interest-Based Advertisement | Use of the viewing data and the advertising ID to target ads | Off | Newer menus: Settings > All Settings > General & Privacy > Terms & Privacy > Privacy Choices > Interest-Based Advertisement |
| Voice Recognition Services | Whether speech from the remote's microphone, and the TV's on models with one, goes to Samsung's speech services | Off (decline the agreement) | Newer menus: Settings > All Settings > General & Privacy > Terms & Privacy > Privacy Choices > Voice Recognition Services |
<!-- /generated:privacy-settings -->

The viewing-data setting may not do what it says. One 2024 study saw screen recognition stop after opting out, and a 2027 study found the opt-out failing in most of its scenarios. That is why the profile blocks the screen-recognition services whatever the setting says.

## Pair the TV

Nothing to pair yet. The gateway does not read a Samsung TV.

## What stays reachable on purpose

These names are never blocked, whatever a blocklist says. None has been checked on a Samsung behind a gateway yet: each reason comes from a published report of what broke without it.

<!-- generated:must-allow profile=samsung-tizen -->
| Name | Why it stays reachable |
|---|---|
| `time.samsungcloudsolution.com` | The TV's clock; reported blocked, Plex, YouTube and Prime Video stop working on some sets |
| `www.samsungotn.net` | The software update check |
| `otn2.samsungcloudcdn.com` | Software downloads |
| `otnprd8.samsungcloudsolution.net` | Software updates |
| `otnprd9.samsungcloudsolution.net` | Software updates |
| `otnprd10.samsungcloudsolution.net` | Software updates |
| `otnprd11.samsungcloudsolution.net` | Software updates |
| `cdn.samsungcloudsolution.com` | The system update check |
| `lcprd1.samsungcloudsolution.net` | The connectivity check |
| `gpm.samsungqbe.com` | Apps and HbbTV; reported blocked, the YouTube and Prime Video apps failed |
| `auth.samsungosp.com` | Samsung account login, which the app store needs |
<!-- /generated:must-allow -->

These names are for US sets. Another region may use other names, and something may stop working until an engineer adds them ([block or unblock something](../use/blocking.md)).

## What you may notice

Nothing has been measured on a Samsung yet, so this is what to expect rather than what was seen.

- **Casting from a phone and phone remote apps do not work.** Nothing on your home network can reach the TV.
- **The brief's Coverage line always says the TV readings are not assessed.** The gateway does not read a Samsung, so that part of the brief stays empty.
- **An app may stop working** if a shared blocklist blocks something it needs. See [fix a problem](../use/troubleshooting.md).

## What was measured

Nothing yet. No Samsung has been behind a tvgw gateway.

## Models and versions

The profile does not tell Samsung's years or Tizen versions apart yet: every Samsung TV is **Not yet tested**. Its menu paths come in two forms, newer and older, as the table above shows.

To see everything the profile knows, on the gateway:

```sh
tvgw profile --profile samsung-tizen
```

## Help test it

A week of your gateway's brief with a Samsung behind it is the most useful report the project can get. It turns this profile from **Not yet tested** into **Reported**. [Which TVs work](README.md#help-test-a-tv) says how to send one.
