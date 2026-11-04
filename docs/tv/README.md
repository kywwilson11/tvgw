# Which TVs work

You can find your TV's support level here, and what tvgw does for a TV it has no profile for. Your brand's page then says what to switch off on the TV, and what the gateway can check for you.

## What the support words mean

| Word | What it means |
|---|---|
| **Tested** | The project ran this TV behind a gateway. The model, the software version and the dates are named on its page. |
| **Reported** | Someone sent a report with data from their own gateway, and the project reviewed it. No TV is at this level yet. |
| **Not yet tested** | The profile is built from published blocklists and research, each entry with its source. Nobody has run it behind a gateway yet. |

## Which TVs work

<!-- generated:support-table -->
| TV | Status | What tvgw does | What you check on the TV yourself |
|---|---|---|---|
| LG, webOS 5 (2020 sets) | **Tested** on an LG CX | Blocks, reports every day, and once paired reads the TV's privacy settings and Wi-Fi state every hour | Nothing after setup |
| LG, webOS 6 and later (2021 on) | **Not yet tested** on these versions | Blocks and reports every day; once paired, reads the privacy settings, and the Wi-Fi state where the TV reports it | That Wi-Fi is off, until tvgw shows it can read it on your TV |
| Samsung (Tizen) | **Not yet tested**, built from published research | Blocks and reports every day | That Wi-Fi is off, and the privacy settings, on the TV's own menus |
| Roku TV | **Not yet tested**, built from published research | Blocks and reports every day | That Wi-Fi is off, and the privacy settings |
| Vizio (SmartCast) | **Not yet tested**, built from published research | Blocks and reports every day | That Wi-Fi is off, and the privacy settings |
<!-- /generated:support-table -->

Each brand has a page:

- [LG TVs](lg-webos.md)
- [What an LG CX does, measured](lg-cx-measured.md)
- [Samsung TVs](samsung-tizen.md)
- [Roku TVs](roku.md)
- [Vizio TVs](vizio-smartcast.md)

## How setup picks your TV's profile

A profile is the list of what to block and what to keep reachable for one brand. Setup looks at the device on the TV's cable and names its brand when it can tell.

Today setup chooses a profile by itself only for an LG TV. For a Samsung, Roku or Vizio TV, setup still installs the gateway but keeps the LG profile in the settings. Your brand's page shows the two commands that switch to the right profile.

## Other TVs

tvgw has no profile yet for Google TV, Fire TV, Sony and other brands. A TCL or Hisense TV that runs Roku OS uses the Roku profile. Behind the gateway, a TV without a profile still gets most of the protection:

- it cannot reach your phones, laptops or other devices;
- the known ways around the filter are closed;
- the gateway records what it does and writes the daily brief.

The blocks are those of the profile in the settings, the LG profile unless you change it. Its two shared blocklists catch many trackers whatever the brand. Its LG names do nothing for another brand.

Before you connect such a TV, do what [What it stops, and what it cannot](../what-it-stops.md#what-it-assumes) asks:

1. Connect the TV's network cable to the gateway.
2. In the TV's network settings, choose the wired connection.
3. Delete every saved Wi-Fi network, then switch Wi-Fi off if the menu offers it.
4. Switch off Wi-Fi Direct and screen sharing, if the TV has them.
5. Turn off the viewing-data, advertising and voice settings in the TV's privacy menus.

The gateway cannot read these settings on a TV without a profile. Check them again after every software update of the TV.

## Help test a TV

A report of what your TV does behind a gateway is how a profile goes from **Not yet tested** to **Reported**. Run the gateway with your brand's profile for a week, then fill in the [TV report form](https://github.com/kywwilson11/tvgw/issues/new?template=tv_report.yml). It asks for the model, the software version, what you measured and an excerpt of the brief.

Remove what identifies your home before you paste anything: device addresses, network names, host names, and anything that shows when your household watches TV. The form lists each one.

To turn what you measured into a profile yourself, see [add a profile for another TV](../project/adding-a-profile.md).
