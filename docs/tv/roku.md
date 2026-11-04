# Roku TVs

You can set up a Roku TV or a Roku player with a network port behind the gateway here, and help test the Roku profile. The profile is built from published blocklists and research, and has not yet run on a Roku behind a gateway.

## What works

The Roku profile is **Not yet tested**. The gateway blocks Roku's advertising and screen-recognition services by name, and more through shared blocklists. It closes the known ways around the filter, keeps the TV away from your other devices, and reports every day.

The gateway reads nothing on a Roku yet. You check its network and its privacy settings yourself, on the TV's own menus.

Setup does not choose the Roku profile by itself yet: it keeps the LG profile in the settings. After setup, switch the profile on the gateway:

```sh
sudoedit /etc/tvgw/tvgw.conf      # change the PROFILE line to PROFILE=roku
sudo tvgw adguard apply           # the filter takes the Roku profile's blocks
sudo tvgw verify                  # every line should start with OK
```

## Turn the radios off

The gateway filters only the cable, so the TV's other connections must be off ([what it assumes](../what-it-stops.md#what-it-assumes)). The reset path is from Roku's own support page, read on 2026-11-03 ([improve your Wi-Fi](https://support.roku.com/article/improve-your-wifi)).

<!-- generated:radios profile=roku -->
1. Plug the gateway's cable into the TV first.
2. **Make the Roku forget your Wi-Fi:** Settings > System > Advanced system settings > Network connection reset > Reset connection. The Roku restarts.
3. **Use the cable:** in the Roku's network settings, set up the wired connection, and do not join a wireless network again.
4. **Other radios:** the profile records nothing yet about Wi-Fi Direct or Bluetooth on Roku devices.
<!-- /generated:radios -->

## What tvgw can check on this TV

<!-- generated:can-check profile=roku -->
Nothing yet. The gateway does not read a Roku's settings, its network state or whether it is on.
<!-- /generated:can-check -->

So the brief cannot warn you if Wi-Fi comes back, or if a software update turns a privacy setting back on. Check both after every update.

## Before you connect the TV

1. Turn the radios off, as above.
2. Set each privacy setting below as the table says.

<!-- generated:privacy-settings profile=roku -->
| Setting | What it controls | Set it to | Where on the TV |
|---|---|---|---|
| Smart TV Experience: Use info from TV inputs | Roku's screen recognition (ACR) on Roku TVs: what plays on the antenna tuner and HDMI inputs. Players have no such setting | Off | Roku TVs: Settings > Privacy > Smart TV experience > Use info from TV inputs |
| Advertising: Limit ad tracking | Use of the Roku advertising ID for targeted ads | On (on newer menus, personalized ads off) | Roku OS: Settings > Privacy > Advertising > Limit ad tracking |
<!-- /generated:privacy-settings -->

Neither setting does all it says. A 2027 study found that turning screen recognition off does not stop it for Roku's own channel, while blocking its service does. A 2019 study found that limiting ad tracking did not stop channels from tracking. The profile blocks those services whatever the settings say.

## Pair the TV

Nothing to pair yet. The gateway does not read a Roku.

## What stays reachable on purpose

These names are never blocked, whatever a blocklist says. None has been checked on a Roku behind a gateway yet: each reason comes from a published report.

<!-- generated:must-allow profile=roku -->
| Name | Why it stays reachable |
|---|---|
| `api.rokutime.com` | The clock: only Roku's own time server sets it, and without it a Roku boots with its software's build date |
| `sw-update.cs.roku.com` | Software updates; reported that setup requires an update and stops without one |
| `api.roku.com` | The Roku's own system services |
| `image.roku.com` | The connectivity check |
| `captive.roku.com` | The connectivity check; seen in a 2027 study's capture, and the name is the only evidence |
<!-- /generated:must-allow -->

## What you may notice

Nothing has been measured on a Roku yet, so this is what to expect rather than what was seen.

- **Casting from a phone and the Roku phone app do not work.** Nothing on your home network can reach the TV.
- **The brief's Coverage line always says the TV readings are not assessed.** The gateway does not read a Roku, so that part of the brief stays empty.
- **An app may stop working** if a shared blocklist blocks something it needs. See [fix a problem](../use/troubleshooting.md).

## What was measured

Nothing yet. No Roku has been behind a tvgw gateway.

## Models and versions

The profile covers Roku OS on Roku TVs, on TVs of other brands that run Roku OS, and on Roku players. It does not tell versions apart yet: every Roku is **Not yet tested**.

To see everything the profile knows, on the gateway:

```sh
tvgw profile --profile roku
```

## Help test it

A week of your gateway's brief with a Roku behind it is the most useful report the project can get. It turns this profile from **Not yet tested** into **Reported**. [Which TVs work](README.md#help-test-a-tv) says how to send one.
