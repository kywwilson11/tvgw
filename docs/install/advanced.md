# Other ways to install

This page covers the installs that are not the guided one: by hand from a source checkout, from the package, with nobody at the keyboard, and as a dry run that changes nothing. It also says what the one-line installer changes on the computer, and covers running setup again. Most of it is for an engineer; [install tvgw](README.md) is the way for everyone else.

## Install from a source checkout

The install guide runs setup from a checkout, and setup drives the installer. These steps do the same by hand, as the reference gateway was first installed.

1. Do the install guide's steps up to and including [install from source](README.md#install-from-source).
2. On the gateway, install the settings template, then set the uplink in it: the interface toward your router, and the router's address. On a gateway with no VPN client, also say so.
   ```sh
   sudo install -D -m 640 -g adm /opt/tvgw/src/deploy/tvgw.conf.example /etc/tvgw/tvgw.conf
   sudoedit /etc/tvgw/tvgw.conf      # WAN_IF, WAN_GW, and VPN_IF=none without a VPN client
   ```
3. Cable the TV to the gateway's TV port and make it forget its Wi-Fi networks, so it has no unfiltered way out ([connect the TV](README.md#connect-the-tv)).
4. On the gateway, run the installer. It finds the TV, finishes the install and ends with `tvgw verify`:
   ```sh
   cd /opt/tvgw/src/deploy
   sudo ./install.sh
   ```
5. On the gateway, check it at any time. Every line must start with `OK`:
   ```sh
   sudo tvgw verify
   ```
6. On an LG TV, pair once and accept the TV's prompt with the remote. The key controls the TV, so it is created readable by the administrator only:
   ```sh
   sudo tvgw tv pair
   ```
7. Optionally, add the analyst's key, as [add the analyst](README.md#add-the-analyst-if-you-want-it) shows.
8. The next day, on the gateway, read the brief for the day before:
   ```sh
   tvgw brief
   ```

To change the code later, an engineer deploys from a checkout on a workstation. On your workstation:

```sh
make deploy PI=<ssh-host>
```

How a change reaches the gateway, by hand or through CI, is in [deploy a change](../project/deploying.md).

## Install from the package

Each release carries a package and its `SHA256SUMS`: one for 64-bit ARM computers, such as a Raspberry Pi, and since 0.3.0 one for Intel and AMD computers too. The same releases carry a one-line installer that picks the package and checks its fingerprint. Neither the packages nor the installer has been installed on a real gateway yet.

The package needs the filter installed first, with its first-run page done, and it finishes only once the TV is cabled and found.

1. Do [prepare the gateway](README.md#prepare-the-gateway) of the install guide, including the filter's first-run page.
2. Download the package for this computer's kind of processor and `SHA256SUMS` from the release, and check them. `dpkg --print-architecture` names the kind, `arm64` or `amd64`:
   ```sh
   sha256sum -c SHA256SUMS --ignore-missing
   ```
3. Install it. The first line answers a packaging question in advance, so that tvgw's capture account can run the capture:
   ```sh
   echo 'wireshark-common wireshark-common/install-setuid boolean false' | sudo debconf-set-selections
   sudo apt install ./tvgw_<version>-1_<arch>.deb
   ```
   On a new gateway the install stops on purpose before it loads the firewall, because the TV is not known yet. It prints `installed but not finished`, and the package is installed.
4. Set the uplink in the settings file the install created:
   ```sh
   sudoedit /etc/tvgw/tvgw.conf      # WAN_IF, WAN_GW; TV_IF, TV_NET, GW_IP only if not eth0 and 10.10.10.0/24
   ```
5. Cable the TV, make it forget its Wi-Fi networks, switch it on, and run the package's installer. It finds the TV, finishes the install and ends with `tvgw verify`:
   ```sh
   sudo /usr/lib/tvgw/deploy/install.sh
   ```
6. Every line of `sudo tvgw verify` must start with `OK`. Pairing and the analyst's key are as in steps 6 and 7 of [install from a source checkout](#install-from-a-source-checkout).

Instead of steps 4 to 6, you can run setup, as the install guide does. Since 0.3.1 setup finds the package's installer by itself. With 0.3.0 it stopped with `install.sh not found`; name the installer, on the gateway:

```sh
sudo tvgw setup --installer /usr/lib/tvgw/deploy/install.sh
```

The one-line installer can take the place of steps 2 and 3. It checks the computer, downloads the package made for it, and installs it only when its fingerprint matches the one written into the installer. It then starts setup. With 0.3.0's installer, setup stopped the same way.

To run setup yourself, stop the installer after the package with `TVGW_NO_SETUP=1`. It then names `sudo tvgw setup` as the next step; the second line below names the installer too, which 0.3.0 needed. On the gateway:

```sh
curl -fsSL https://github.com/kywwilson11/tvgw/releases/latest/download/get.sh | sudo env TVGW_NO_SETUP=1 sh
sudo tvgw setup --installer /usr/lib/tvgw/deploy/install.sh
```

An install in an image build, with no running system manager, unpacks the package and does nothing else. Run the package's installer on the first boot.

## What the installer changes

The one-line installer runs as the computer's administrator, and it changes the computer. It installs tvgw's package and the programs tvgw needs: an address server, a web server, a network manager and packet-capture tools. It gives one network port to the TV and adds firewall rules. It also takes over the filter (AdGuard Home) on that computer, so that only the TV and the computer itself use it.

Install it on a computer that does nothing else important on your network. Install the filter first and finish its first-run page. Sometimes that computer already runs a DNS server, a web site or a filter that the rest of the house uses. Then tvgw stops and says so, or setup asks you first, before it changes that program.

The installer downloads the package over HTTPS only. It installs the package only when the package's fingerprint matches the one written into the installer. To read the installer before it runs, download it first. On the gateway:

```sh
curl -fsSLO https://github.com/kywwilson11/tvgw/releases/latest/download/get.sh
less get.sh
sudo sh get.sh
```

When you pair an LG TV, the key the TV hands over could control the TV. tvgw keeps it in a file only the administrator can read. The same goes for the optional Claude API key.

To remove tvgw, run `sudo apt remove tvgw`. The TV then has no internet through this computer, and your record of the TV stays under `/var/lib/tvgw` until you delete it. To give the computer back to ordinary use, purge tvgw instead, which also gives the network port back. [Remove tvgw](../use/maintenance.md#remove-tvgw) lists what stays and what comes back.

## Install with no one at the keyboard

For an install with nobody at the keyboard, give the answers in a file and pass `--yes`. On the gateway:

```sh
sudo tvgw setup --answers /root/tvgw-answers.conf --yes
```

The answers file uses the settings file's own format: one setting per line, `#` comments, and quotes around a value with a space. A copy of a working settings file is a valid answers file. Every line is checked before anything runs, so a typo stops the install at the start instead of leaving a gateway half set up.

The TV is always a device setup found on the cable, never one the file makes up:

| In the answers file | What setup does |
|---|---|
| A real `TV_MAC` | It names the TV, as `SETUP_TV` does. Setup must find that device; when it does not, setup looks again until `SETUP_WAIT` runs out, then stops. When `SETUP_TV` names a device too, the two must agree. |
| `TV_MAC=00:00:00:00:00:00`, the template's placeholder | It names no TV, and the template's `PROFILE=generic-tv` names no brand, so a copy of the template lets setup pick the TV and its profile. |
| `TV_IP` | Used only when the answers name the TV, with `TV_MAC` or `SETUP_TV`. Otherwise setup says it is not used. |
| Any other key of [the settings](../reference/settings.md) | Written to the settings file. |
| A `SETUP_` key | Steers the run and is never written. The keys are below. |

| Key | Values | Default | What it does |
|---|---|---|---|
| `SETUP_TV` | `auto`, `configured`, an IP address or a MAC address | `auto`, or the answers' `TV_MAC` | Which device is the TV. `auto` takes the configured TV, the only device, or the only device a profile is given to on its evidence, and stops when that is still ambiguous. `configured` skips the search and uses the TV the answers or the settings already name. |
| `SETUP_PAIR` | `auto`, `yes`, `no` | `auto` | Whether to pair an LG TV. `auto` asks when someone is at the keyboard; unattended, it only reads the TV with a key that already exists, which puts no prompt on the TV. `yes` pairs without asking, and the TV's prompt then needs someone to accept it within a minute. `no` skips pairing and the reading. |
| `SETUP_PROFILE` | `auto`, a bundled profile, or the full path of a profile's `.toml` file | `auto` | The TV's profile. `auto` takes the profile the TV's evidence gives. When only a hint names a brand that has a profile, `auto` asks the brand question when someone is at the keyboard. Unattended, it writes `generic-tv` and says which value would name the brand's profile. A `PROFILE` line in the answers must agree with this key. On a re-run, the TV the settings already name keeps its profile. |
| `SETUP_APPLY` | `auto`, `yes`, `no` | `auto` | Whether to run the installer. `auto` runs it when the settings changed or the gateway was never installed. `no` never runs it, not even to set up the TV's port: then setup goes on only when the answers or the settings already name the TV. |
| `SETUP_SSDP` | `yes`, `no` | `yes` | Whether the search for the TV includes the network announcement search, which opens a short firewall exemption while it runs. |
| `SETUP_WAIT` | seconds, 0 to 3600 | `120` | How long to keep looking for the TV, every 10 seconds, before stopping. |
| `SETUP_INSTALLER` | a path | found | The installer to run. By default, the one in the checkout setup runs from, else `/opt/tvgw/src/deploy/install.sh`. |

An example for a gateway whose TV is known in advance:

```sh
# /root/tvgw-answers.conf
SETUP_TV=b4:b2:91:aa:bb:cc
SETUP_PAIR=no
WAN_IF=wlan0
WAN_GW=192.0.2.1
UPLINK=direct
```

`--yes` without `--answers` takes every default. An unattended run never installs a guess. It stops when several devices could be the TV. It also stops when the gateway has no default route to read the uplink from and the answers do not give it. Run without a terminal and without `--yes`, setup stops and says how to run it unattended.

Exit status: 0 when the gateway holds; 1 on a stop, a failed install or any `FAIL`; 130 when interrupted.

### Every message setup can stop with

| Message | What it means | What to do |
|---|---|---|
| `setup changes the system and needs root` | Run as an ordinary user. | `sudo tvgw setup`, or `--dry-run`. |
| `no terminal to ask on` | No terminal and no `--yes`. | Add `--answers FILE --yes`. |
| `answers file ...: ...` | A key or value in the answers file is not usable. | Fix the named line. |
| `no TV found and none configured` | Nothing answered on the TV's port within `SETUP_WAIT`, or you declined to look again. | Check the cable and that the TV is on; run again. |
| `the installer ran but eth0 still does not carry 10.10.10.1` | The installer could not set up the TV's port. | Read its output above; see [the TV interface](../../deploy/networkmanager/README.md). |
| `several devices could be the TV` | An unattended run with more than one candidate. | Set `SETUP_TV` to the TV's MAC or address. |
| `... has no MAC address in the lease or neighbour table yet` | The TV answered but has not finished getting its address. | Wait a minute and run again. |
| `refused, nothing written: ...` | A value the settings file cannot take, or a line of a changed key the writer cannot read plainly (`not a plain KEY=VALUE line`), or a result the shell's syntax check rejects. | Fix the named key or line by hand. |
| `the answers say TV_MAC=..., but the TV picked is ...` | The answers name one device and another was picked. | Correct `TV_MAC` or `SETUP_TV` in the answers. |
| `the TV side is not up and SETUP_APPLY=no` | The installer would have to run to set up the TV's port, and the answers forbid it. | Set `SETUP_APPLY=auto`, or name the TV in the answers. |
| `install.sh not found` | Setup runs neither from a checkout nor next to `/opt/tvgw/src`, nor from the 0.3.1 package. A package install of 0.3.0 met this. | Pass `--installer PATH`; for the package, `--installer /usr/lib/tvgw/deploy/install.sh`. |
| `another install is running` | A deploy held the install lock for ten minutes. | Wait for it and run again. |
| `the installer stopped (exit N)` | `install.sh` stopped; its output says why. | Fix the cause and run again. |
| `this AdGuard Home serves other devices, so tvgw leaves it as it is` | AdGuard Home here was not set up by tvgw, and the answer to `Does anything else in the house use this AdGuard Home?` was yes: the default, which an unattended run takes, when its log answered another device in the last 7 days ([taking over one that is not tvgw's](../how-it-works/adguard.md#taking-over-one-that-is-not-tvgws)). One whose log shows no other device defaults to no, and an unattended run goes on. | Use a computer of its own for tvgw; or, when nothing else uses it, answer `n`, or put `ADGUARD_TAKE_OVER=yes` in the answers file. |
| `ADGUARD_TAKE_OVER=no in the settings, so tvgw leaves this AdGuard Home as it is` | The settings or the answers say never to take over an AdGuard Home tvgw did not set up, and this one may serve more than the TV. | Set it to `ask` or `yes` if nothing else uses it, or use a computer of its own. |
| `the TV did not answer over its LAN API` | The TV was off, or the prompt was not accepted in time. Setup goes on. | Pair later with `sudo tvgw tv pair`. |

## See what setup would change

On the gateway:

```sh
tvgw setup --dry-run
```

The dry run goes through the same questions and prints every change: the lines of the settings file, whether it would pair, and whether it would run the installer. It writes nothing, pairs nothing, takes no lock and runs no installer. It also skips the network announcement search, because that opens a firewall exemption for a few seconds. It runs without `sudo`, and then sees only what an ordinary account can.

## Run setup again

Setup is safe to repeat. A second run finds the same TV and offers the values already set as its defaults. When nothing differs, it says `already holds these settings; nothing to write`, and the installer then defaults to not running. With a pairing key already there, it reads the TV once to report Live Plus, with no new prompt on the TV.

Run it again after a fix, after replacing the TV, or to pair a TV you skipped the first time. To change one setting by hand, edit the settings file directly; setup keeps every comment and line you add there.

```sh
sudoedit /etc/tvgw/tvgw.conf
```

## What setup does not do

- It adds no install steps of its own. The installer is still `install.sh`, which deploys and CI also run, and setup only decides when to call it.
- It does not install the filter or complete its first-run page.
- It does not change any setting on the TV, and never asks you to accept a TV agreement.
- It never writes a value the gateway's scripts would read as a command, or one the settings check would refuse, or a TV port and subnet the installer would refuse.
