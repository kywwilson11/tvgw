# Vizio TVs

You can set up a Vizio TV behind the gateway here, and help test the Vizio profile. The profile is built from published research, and has not yet run on a Vizio behind a gateway.

## What works

The Vizio profile is **Not yet tested**. The gateway blocks Vizio's known screen-recognition and advertising services by name. It closes the known ways around the filter, keeps the TV away from your other devices, and reports every day. No maintained blocklist exists for Vizio, so the profile relies on its own rules and a general list.

The gateway reads nothing on a Vizio TV yet. You check its network and its privacy settings yourself, on the TV's own menus.

Setup does not choose the Vizio profile by itself yet: it keeps the LG profile in the settings. After setup, switch the profile on the gateway:

```sh
sudoedit /etc/tvgw/tvgw.conf      # change the PROFILE line to PROFILE=vizio-smartcast
sudo tvgw adguard apply           # the filter takes the Vizio profile's blocks
sudo tvgw verify                  # every line should start with OK
```

## Turn the radios off

The gateway filters only the cable, so the TV's other connections must be off ([what it assumes](../what-it-stops.md#what-it-assumes)).

<!-- generated:radios profile=vizio-smartcast -->
1. Plug the gateway's cable into the TV first.
2. **Use the cable:** in the TV's network menu, choose the wired connection.
3. **Forget the saved networks:** remove your home Wi-Fi from the network menu, so the TV cannot rejoin it.
4. **Other radios:** the profile has not confirmed the menu paths for Wi-Fi, Wi-Fi Direct or Bluetooth on Vizio sets yet.
<!-- /generated:radios -->

Afterwards, check that the TV's network status shows the wired connection.

## What tvgw can check on this TV

<!-- generated:can-check profile=vizio-smartcast -->
Nothing yet. The gateway does not read a Vizio's settings, its network state or whether it is on.
<!-- /generated:can-check -->

So the brief cannot warn you if Wi-Fi comes back, or if a software update turns a privacy setting back on. Check both after every update.

## Before you connect the TV

1. Turn the radios off, as above.
2. Set each privacy setting below as the table says.

<!-- generated:privacy-settings profile=vizio-smartcast -->
| Setting | What it controls | Set it to | Where on the TV |
|---|---|---|---|
| Viewing Data | Vizio's screen recognition (ACR): what is on screen from any input, sold for audience measurement and ads | Off | Current menus: Menu > Admin & Privacy > Viewing Data. Older menus: Menu > System > Reset & Admin > Viewing Data. Older sets: Menu > System > Reset & Admin > Smart Interactivity |
| Personalized Ads | Use of viewing data for targeted ads, which works even with Viewing Data off | Off | Current menus: Menu > Admin & Privacy (or System > Privacy Settings) > Personalized Ads |
<!-- /generated:privacy-settings -->

The viewing-data setting may not do what it says. A 2027 study saw uploads that followed what was on screen continue in every opted-out scenario on the one model it tested.

The profile blocks Vizio's known screen-recognition service whatever the setting says. The study's uploads went to a shared Amazon server that other services use, so the profile does not block it. The brief lists the TV's traffic there, and raises a red line if it uploads the way screen recognition does.

## Pair the TV

Nothing to pair yet. The gateway does not read a Vizio.

## What stays reachable on purpose

These names are never blocked, whatever a blocklist says. None has been checked on a Vizio behind a gateway yet: each reason comes from a published report.

<!-- generated:must-allow profile=vizio-smartcast -->
| Name | Why it stays reachable |
|---|---|
| `api.vizio.com` | SmartCast features |
| `images.vizio.com` | SmartCast features |
| `osu.vudip.vizio.com` | Probably the software update service; seen in a 2027 study's capture, and the name is the only evidence |
| `time-a.timefreq.bldrdoc.gov` | The TV's clock |
| `time.google.com` | The TV's clock |
| `pool.ntp.org` | The TV's clock, every server under this name |
<!-- /generated:must-allow -->

## What you may notice

Nothing has been measured on a Vizio yet, so this is what to expect rather than what was seen.

- **Casting from a phone and the Vizio phone app do not work.** Nothing on your home network can reach the TV.
- **The brief's Coverage line always says the TV readings are not assessed.** The gateway does not read a Vizio, so that part of the brief stays empty.
- **An app may stop working** if the general blocklist blocks something it needs. See [fix a problem](../use/troubleshooting.md).

## What was measured

Nothing yet. No Vizio has been behind a tvgw gateway.

## Models and versions

The profile does not tell Vizio's years or software versions apart yet: every Vizio is **Not yet tested**. Its menu paths come in three forms, as the table above shows.

To see everything the profile knows, on the gateway:

```sh
tvgw profile --profile vizio-smartcast
```

## Help test it

A week of your gateway's brief with a Vizio behind it is the most useful report the project can get. It turns this profile from **Not yet tested** into **Reported**. [Which TVs work](README.md#help-test-a-tv) says how to send one.
