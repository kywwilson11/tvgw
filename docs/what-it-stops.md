# What it stops, and what it cannot

tvgw controls only the traffic that passes through the gateway. It may not stop everything: how much it stops depends on the TV. This page says what the gateway assumes, what it is known to stop, what it is known not to stop, and what you can do about each.

<picture>
  <source media="(prefers-color-scheme: dark)" srcset="diagrams/fig-19-what-it-stops.dark.png">
  <img alt="The TV's cable runs through the gateway, where known trackers are stopped. Two things stay outside the gateway's reach: the TV's own Wi-Fi radio, which must be off, and Bluetooth, which the gateway cannot see." src="diagrams/fig-19-what-it-stops.light.png" width="960">
</picture>

*Only the cable is filtered. Wi-Fi must be off, and Bluetooth stays outside the gateway's reach.*

## What it assumes

One cable is the TV's only connection to anything:

- the TV's Wi-Fi is off, and every saved Wi-Fi network is forgotten, so the TV cannot rejoin one by itself;
- Wi-Fi Direct and screen sharing are off;
- nothing else is plugged into the TV's network port, and the cable runs to the gateway, not to your router.

Setup asks you to do this when the TV is connected. If you cannot find a setting on your TV, say so: the brief then shows that the Wi-Fi state is not checked, instead of pretending it is.

## What it stops

Measured on the LG CX the project was built on, over one day ([the measurements](findings.md)):

- **Known tracking names are refused.** The TV asked for known advertising, tracking and screen-recognition services 3,983 times. Every one was refused, and because a refused name gets no address, none led to a connection.
- **The TV cannot reach your other devices.** When the TV sweeps the home network, it finds only the gateway. Your phones, laptops and other devices are not visible to it.
- **The known ways around the filter are refused.** Other DNS servers, DNS over TLS, QUIC and the known DNS-over-HTTPS servers all get no answer.
- **The record stays at home.** What the TV did is written to a database on the gateway and nowhere else, and `sudo tvgw forget` deletes it.

What got through that day: the streaming itself, LG's own services, and the names the profile does not classify, which carried 2.7 GB.

## What it cannot stop

| Limit | Status | What you can do |
|---|---|---|
| The TV's Wi-Fi left on, or a saved network it can rejoin | Mitigated by the assumption above. On LG webOS 5 the gateway checks every hour that only the cable is connected; on newer LG sets only where the TV answers the same question; not checked on Samsung, Roku, Vizio or TVs without a profile | Forget the networks and switch Wi-Fi off. Where the TV reports its Wi-Fi, the brief raises a red line if it comes back on |
| The TV joining an open Wi-Fi network nearby by itself | Not shown on webOS; mitigated by Wi-Fi off | Keep Wi-Fi off |
| The Wi-Fi radio scanning nearby networks while "disconnected" | Known, not addressed: the gateway cannot see a radio | Leave the TV's data agreements declined |
| Bluetooth advertising (the LG CX has no switch for it on webOS 5) | Known, not addressed: it announces the TV's presence, but carries no internet path by itself | None on webOS 5 |
| Ads stitched into the video stream | Known, not addressed: the gateway decrypts nothing | None |
| What your internet provider and the services see: your home's address and which services the TV uses | Known, not addressed | An optional VPN on the gateway's own connection |
| A privacy setting that does not do what the menu says (Samsung's viewing-data opt-out failed in most lab scenarios of a 2027 study) | Mitigated: the blocks refuse the names the service is known to use, whatever the setting says | Keep the profile's blocks |
| A tracking name the profile does not know | Partly addressed: shared blocklists catch some; the brief lists every new name | Read the "New" lines in the brief |
| A TV software version the project has not tested | Partly checked: the blocks apply, but the TV's own reports may not be readable | Help test it: report what your TV does |
| The TV noticing that it is behind a filter | By design: a refused name gets no address, which the TV can tell | None needed |
| The contents of encrypted traffic | Known, not addressed: the gateway sees names and volumes, never contents | None |

## What it does not need

Nothing is installed on the TV, and nothing on the TV is changed. There is no rooting and no modified firmware, so none of the warranty risk that rooting carries. Everything happens at the network, which is why the same approach should apply to newer sets and other brands.

## Check your TV

- **LG webOS 5 (tested):** once paired during setup, the gateway reads the TV's privacy settings and its Wi-Fi state every hour. You check nothing yourself after setup.
- **LG webOS 6 and later:** the same readings, where the TV answers them. Until the brief shows it can read your TV, check on the TV's menus that Wi-Fi is off.
- **Samsung, Roku, Vizio and other TVs:** the gateway cannot read their settings. Check on the TV's own menus that Wi-Fi is off and that the viewing-data, advertising and voice settings are off. [The TV profiles](../src/tvgw/profiles/README.md) list the settings for each brand.
