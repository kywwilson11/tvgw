# Samsung TVs

You can set up a Samsung TV behind the gateway here, and help test the Samsung profile. The profile is built from published blocklists and research, and has not yet run on a Samsung behind a gateway.

## What works

The Samsung profile is **Not yet tested**. The gateway blocks Samsung's advertising, telemetry and screen-recognition services by name, closes the known ways around the filter, keeps the TV away from your other devices, and reports every day.

Every hour the gateway also reads the TV's model, whether it is on, and whether it is on its cable or on Wi-Fi. It needs no pairing for that, and nothing appears on the TV's screen. You check the privacy settings yourself, on the TV's own menus.

Some Samsung TVs, such as the 32-inch Frame, have no network socket. The gateway cannot protect them, because it filters only the cable.

When the TV answers as a Samsung TV, setup gives it the Samsung profile without asking. When setup sees only signs of a Samsung, it asks: `This looks like a Samsung TV. Is it? [Y/n]`. Answer `y`, and setup gives the TV the Samsung profile. A Samsung soundbar shows the same signs, so answer `n` for one. If setup did not ask, it gave the TV the general profile. Switch to the Samsung profile after setup, on the gateway:

```sh
sudoedit /etc/tvgw/tvgw.conf      # change the PROFILE line to PROFILE=samsung-tizen
sudo tvgw adguard apply           # the filter takes the Samsung profile's blocks
sudo tvgw-apply                   # the firewall takes the profile too
sudo tvgw verify                  # every line should start with OK
```

## Turn the radios off

The gateway filters only the cable, so the TV's other connections must be off ([what it assumes](../what-it-stops.md#what-it-assumes)). These menu paths are from Samsung's own support page, read on 2026-11-03 ([connect your Samsung TV to the internet](https://www.samsung.com/au/support/tv-audio-video/connect-your-samsung-tv-to-the-internet/)). Menus vary by year and region.

1. Plug the gateway's cable into the TV first.
2. **Reset the network settings, so the TV forgets your Wi-Fi:** Settings > All Settings > Connection > Network > Reset Network, then Reset. On older menus: Settings > General > Network > Reset Network.
3. **Use the cable:** Settings > All Settings > Connection > Network > Network Settings, then Wired.
4. **Wi-Fi Direct and screen mirroring:** turn them off where the network menu offers them. The profile has not confirmed where they are.
5. **Bluetooth:** the profile records nothing about Bluetooth on Samsung sets yet.

Newer sets also have a switch for Wi-Fi itself. On 2022 and newer sets, switch it off under Settings > All Settings > Connection > Network > Expert Settings > Wi-Fi. On 2017 to 2021 sets, look under Settings > General > Network > Expert Settings. In the same menu, switch off Power On with Mobile and IP Remote. These paths are from Samsung's support page, read on 2026-11-04 ([set up a network connection](https://www.samsung.com/ph/support/tv-audio-video/set-up-a-network-connection-on-your-samsung-smart-tv/)).

With the cable in, the TV chooses the wired connection by itself. Afterwards, check what the TV reports, on the gateway:

```sh
sudo tvgw tvcheck                 # network.wifi.state = disconnected: not joined to any Wi-Fi network
```

## What tvgw can check on this TV

<!-- generated:can-check profile=samsung-tizen -->
Nothing yet. The gateway does not read this TV's settings, its Wi-Fi state or whether it is on.
<!-- /generated:can-check -->

Every hour the gateway asks the TV one question that needs no pairing and shows nothing on its screen. From the answer it keeps:

- the model, the year it was made, and whether it has moved to Tizen 9;
- whether it is on or asleep (a Frame showing art counts as asleep);
- whether it is on its cable or joined to a Wi-Fi network;
- whether it accepted the Smart Hub terms.

When the TV is on Wi-Fi, the answer also carries the hardware address of your Wi-Fi access point. Public Wi-Fi maps can turn that address into your home's location. So the gateway never keeps it, prints it or sends it anywhere: it keeps only whether the TV is on Wi-Fi.

The gateway cannot read the viewing-data and advertising settings, the microphone switch, Keep Bixby in Standby or Pet Care. It cannot tell whether the Wi-Fi radio still searches for networks while the cable is in. It sees neither Bluetooth nor what the TV tells SmartThings, Samsung's smart-home service.

If the TV joins a Wi-Fi network, the next brief opens with a red line, a warning that something must never happen. Until the first reading arrives, each brief ends with a line saying the TV's Wi-Fi was not checked.

A software update can turn a privacy setting back on, and the gateway cannot see that. Check the settings again after every update of the TV.

## Before you connect the TV

1. Turn the radios off, as above.
2. Decline the TV's data agreements. The gateway needs none of them.
3. Set each privacy setting below as the table says.

| Setting | What it controls | Set it to | Where on the TV |
|---|---|---|---|
| Viewing Information Services | Samsung's screen recognition (ACR): viewing history from apps, the tuner and HDMI inputs | Off | Newer menus: Settings > All Settings > General & Privacy > Terms & Privacy > Privacy Choices > Viewing Information Services. Older menus: Settings > Support > Terms & Policy > Viewing Information Services |
| Interest-Based Advertisement | Use of the viewing data and the advertising ID to target ads | Off | Newer menus: Settings > All Settings > General & Privacy > Terms & Privacy > Privacy Choices > Interest-Based Advertisement |
| Voice Recognition Services | Whether speech from the remote's microphone, and the TV's on models with one, goes to Samsung's speech services | Off (decline the agreement) | Newer menus: Settings > All Settings > General & Privacy > Terms & Privacy > Privacy Choices > Voice Recognition Services |

Samsung's viewing-data setting may not stop everything. A 2024 study and a 2026 test saw screen-recognition traffic stop after the setting was switched off. A study for the 2027 Privacy Enhancing Technologies Symposium saw traffic like it continue in most of its tests, all on a TV using Wi-Fi. Nobody outside Samsung can see what that traffic contains. So the gateway blocks the screen-recognition services whatever the setting says.

On 2025 and 2026 sets, Vision AI Companion has an agreement of its own, outside the privacy menu. Withdraw it under Vision AI Companion > Settings > Terms and Conditions.

The gateway keeps your word on each setting, with its date. Once you have set them, record them on the gateway:

```sh
sudo tvgw tv confirm viewing-info off
sudo tvgw tv confirm interest-ads off
sudo tvgw tv confirm voice off
```

## Microphones and standby

Some Samsung TVs can listen while in standby, for Bixby's wake word or for Pet Care. The gateway cannot hear or stop that. The switch on the TV's lower edge is the only control you can trust. When it is off, Samsung says voice features and some sound features stop ([the microphone switch](https://www.samsung.com/ca/support/tv-audio-video/how-to-enable-or-disable-the-microphone-switch-on-samsung-smart-tvs)).

1. Slide the microphone switch on the TV's lower edge off, if your TV has one.
2. Switch Keep Bixby in Standby off. On 2023 sets it sits under Settings > General > Voice > Voice Assistant (Bixby) > Bixby Wake-up Options.
3. Check that Power On with Mobile is off, as under the radios above. With it on, the TV keeps its network awake in standby.
4. In the SmartThings app, switch Pet Care off for the TV. It listens for barking while the TV is off.
5. Record the microphone switch on the gateway:

```sh
sudo tvgw tv confirm mic-switch off
```

A Samsung that answers while it is asleep has kept its network on. The brief counts that time as off, and lists what the TV did then. A Frame showing art counts as asleep, with its screen lit.

## Pair the TV

Nothing to pair. The gateway reads a Samsung TV without pairing. On some 2024 and newer software, pairing fails without showing anything on the screen, so the gateway never tries.

## What stays reachable on purpose

These names are never blocked, whatever a blocklist says. None has been checked on a Samsung behind a gateway yet: each reason comes from a published report of what broke without it.

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

These names are for US sets. Another region may use other names, and something may stop working until an engineer adds them ([block or unblock something](../use/blocking.md)).

## What you may notice

Nothing has been measured on a Samsung yet, so this is what to expect rather than what was seen.

- **Casting does not work.** Casting from a phone, AirPlay, phone remote apps and, on 2024 and newer sets, Google Cast do not work. Nothing on your home network can reach the TV.
- **The brief shows when the TV was on.** The hourly reading records on and asleep. A TV that is off does not answer, and the brief counts it as off.
- **Typing 8.8.8.8 into the TV changes nothing.** When an app fails, Samsung's support sometimes suggests setting the TV's DNS to 8.8.8.8. The gateway answers those lookups all the same, so the filter still applies.
- **YouTube's fault after the Tizen 9 update does not happen here.** That update broke YouTube on some home networks that use IPv6. The gateway gives the TV no IPv6, so a Samsung behind it is not affected.
- **An app may stop working** if a shared blocklist blocks something it needs. See [fix a problem](../use/troubleshooting.md).

## What was measured

Nothing yet. No Samsung has been behind a tvgw gateway.

## Models and versions

Every Samsung TV is **Not yet tested**. The gateway reads the year from the TV's model code, and from the year the Tizen version it shipped with:

| Year | Tizen when sold | Later |
|---|---|---|
| 2019 | 5.0 | none |
| 2020 | 5.5 | none |
| 2021 | 6.0 | none |
| 2022 | 6.5 | none |
| 2023 | 7.0 | 8, then 9, by updates |
| 2024 | 8.0 | 9, by an update |
| 2025 | 9.0 | 10 promised, no date |
| 2026 | 10.0 | upgrades promised for seven years |

When a 2023 or 2024 set moves to Tizen 9, its model code changes, and the gateway reads that too. The menus come in two forms, one for 2017 to 2021 sets and one for 2022 and newer sets.

To see everything the profile knows, on the gateway:

```sh
tvgw profile --profile samsung-tizen
```

## Help test it

A week of your gateway's brief with a Samsung behind it is the most useful report the project can get. It turns this profile from **Not yet tested** into **Reported**. [Which TVs work](README.md#help-test-a-tv) says how to send one.

An engineer finds the questions a Samsung in hand can answer first at the top of [the Samsung profile](../../src/tvgw/profiles/samsung-tizen.toml).
