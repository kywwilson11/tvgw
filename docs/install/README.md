# Install tvgw

This guide takes you from an empty Raspberry Pi to a working gateway, and to your first daily brief the next morning. It is the install as it works today, from the source code. Since 0.3.0, each release also carries a one-line installer, which this guide does not use until it has been run on a real gateway.

## What you need

- **A Raspberry Pi 5**, with its power supply and a microSD card of 32 GB or more. This is the reference computer. A Pi 4 with 2 GB or more should work too, but has not been tested. Other computers are in [choose a gateway computer](choosing-a-gateway.md).
- **An Ethernet cable** from the Pi to the TV. The Pi's own network port is for the TV; the Pi reaches your router over Wi-Fi.
- **Your own computer**, with Windows, macOS or Linux, on the same home network. You type the gateway's commands from it.
- **The TV**, within cable reach of the Pi.
- **The TV's network port.** The TV needs a socket for a network cable. A TV that can only use Wi-Fi cannot sit behind the gateway.

You need no networking knowledge. Copy every command below as it is written. A word in angle brackets, such as `<username>`, is yours to fill in: replace it, brackets included.

The install has five parts, each a section below: prepare the gateway, install from source, connect the TV, run setup, and check that it worked.

## Prepare the gateway

1. On your own computer, install [Raspberry Pi Imager](https://www.raspberrypi.com/software/) and put the microSD card in.
2. In Imager, choose your Pi, then the operating system **Raspberry Pi OS Lite (64-bit)**, then the card.
3. When Imager offers to customize the system, set a hostname (for example `tvgw`), a username and a password. Set **your Wi-Fi network and its password**, and your time zone. Under remote access, turn on **SSH** with password login.
4. Write the card, put it in the Pi, and power the Pi on. **Leave the Pi's network port empty for now**: it is for the TV.
5. After two minutes, open a terminal on your own computer:
   - **Windows:** open PowerShell from the Start menu.
   - **macOS:** open Terminal, in Applications > Utilities.
   - **Linux:** open your terminal.
6. In that terminal, connect to the Pi. Use the username and hostname you chose:
   ```sh
   ssh <username>@tvgw.local
   ```
   If the terminal says the name is not known, wait a minute and try again. If it still fails, your router's app or web page lists the Pi under its hostname, with an address: use `ssh <username>@<address>` instead.

   Answer `yes` to the first-time question and give the password. You are now typing on the gateway, and every command below runs there.

`sudo` at the start of a command runs it as the administrator. It may ask for your password.

### Install what tvgw needs

On the gateway, paste these lines one at a time. The first one answers a question about packet capture in advance, so that tvgw's own capture account can run it:

```sh
echo 'wireshark-common wireshark-common/install-setuid boolean false' | sudo debconf-set-selections
sudo apt update
sudo apt install -y tcpdump conntrack dnsmasq tshark wireshark-common nginx libnginx-mod-stream python3-venv python3-yaml git
```

Then install the filter tvgw sets up for the TV (AdGuard Home), from the release tvgw is tested with. The second line checks the download against the fingerprint tvgw expects. It must print `OK`; if it does not, stop and run the lines again later:

```sh
curl -fsSLO https://github.com/AdguardTeam/AdGuardHome/releases/download/v0.107.79/AdGuardHome_linux_arm64.tar.gz
echo '3f7893c18e8aaadc456d0452839190561c306ca95175a2254958be80a769c1ae  AdGuardHome_linux_arm64.tar.gz' | sha256sum -c
sudo tar -xzf AdGuardHome_linux_arm64.tar.gz -C /opt
sudo /opt/AdGuardHome/AdGuardHome -s install
```

The filter needs its first-run page completed once. The address server you installed above holds the port the filter needs, so stop it first; tvgw sets it up again later, to hand out the TV's address only:

```sh
sudo systemctl stop dnsmasq
```

Then open the first-run page from your own computer. In a second terminal on your own computer, open a tunnel to the gateway, and leave it open:

```sh
ssh -L 3000:127.0.0.1:3000 <username>@tvgw.local
```

In a browser on your own computer, go to <http://127.0.0.1:3000> and follow the wizard:

- let the DNS server listen on **all interfaces**, port 53;
- give the web interface port **8080**, since the web server you installed above already uses port 80;
- choose an admin username and password.

Finish the wizard and close the browser tab and the tunnel. tvgw takes over the filter's configuration from here, and you do not need its page again.

## Install from source

On the gateway:

```sh
sudo install -d -o "$USER" /opt/tvgw
git clone https://github.com/kywwilson11/tvgw.git /opt/tvgw/src
```

## Connect the TV

1. Plug the Ethernet cable into the Pi's network port and into the TV's network port.
2. Switch the TV on.
3. On the TV, first make it **forget every saved Wi-Fi network**, then turn **Wi-Fi off**, so its only connection is the cable. On some TVs the saved networks are hidden once Wi-Fi is off. Turn Wi-Fi Direct and screen sharing off as well. [Your TV's page](../tv/README.md) says where each switch is.

This step matters: the gateway can only filter what passes through it. [What it stops, and what it cannot](../what-it-stops.md) explains why.

## Run setup

On the gateway:

```sh
cd /opt/tvgw/src
sudo PYTHONPATH=src python3 -m tvgw setup
```

On a first install, the gateway's TV port is not set up yet, so the TV has had nowhere to get an address. Setup says so and asks to run the installer first. Answer yes. The installer takes a few minutes, then stops because it does not know the TV yet. That stop is expected, and setup then looks for the TV again.

If setup does not find the TV, check the cable and that the TV is on. Unplug the TV's cable for five seconds and plug it back in, then answer `y` to look again.

## What setup does

Setup asks a handful of questions. Each shows its default in brackets, and pressing Enter takes it:

```text
Which one is the TV? (1-2) [1]:
Name for the TV (DHCP and logs) [lgwebostv]:
Interface toward the home router (WAN_IF) [wlan0]:
Home router's address (WAN_GW) [192.0.2.1]:
Does anything else in the house use this AdGuard Home? [Y/n]:
Pair the TV's LAN API now? [Y/n]:
Write these changes to /etc/tvgw/tvgw.conf? [Y/n]:
Run the installer to apply them now? [Y/n]:
```

What each one means:

1. **Which device is the TV.** Setup lists what answered on the TV's cable, with what it found out about each, and offers the likeliest one.
2. **A name for the TV.** It shows up in the gateway's own logs.
3. **Your router.** Setup offers the connection and the router address the Pi already uses. On a Pi set up as above, the defaults are right. When your router lends this computer its address, setup also tells the gateway to follow the router if that address moves.
4. **The filter.** Setup asks this only when the filter was set up through its own first-run page, as above. tvgw then makes the filter answer the TV and this computer alone, so any other device that uses it loses it. Answer `n` when you installed the filter for tvgw just now. A yes, the default, stops setup and writes nothing: then give tvgw a computer of its own.
5. **Pairing**, on an LG TV only. Say yes, and accept the prompt the TV then shows with the remote, within a minute. That prompt is not one of the TV's data agreements: leave those declined. [LG TVs](../tv/lg-webos.md#pair-the-tv) says more.
6. **The changes.** Setup shows the lines it would write to the settings file, and asks before it writes them.
7. **Apply.** Setup runs the installer again, which takes a few minutes, and then checks its own work.

It ends with one of two lines:

- `Result: the gateway holds.` Everything works. The TV has internet again, filtered.
- `Result: NOT done.` The `FAIL` lines above it say what is wrong. Run `sudo tvgw doctor`: it explains each one in plain words and offers the fixes it can make. Then run setup again: it is safe to repeat.

When your router lends this computer its address, the line that says the gateway holds adds a tip: reserve this computer's address in your router's settings. A router that gives the gateway a new address cuts every stream the TV has open.

tvgw has a profile for each TV brand it knows: what to block and what to keep working. Setup picks your TV's profile when the TV shows its brand clearly. When it is not sure, it may ask you, for example: `This looks like a Samsung TV. Is it? [Y/n]`. Any other TV gets the general profile. It keeps the TV away from your other devices, reports every day, and blocks known trackers from shared lists. [Which TVs work](../tv/README.md) says more.

## If setup stops

| Message | What it means | What to do |
|---|---|---|
| `setup changes the system and needs root` | It ran without `sudo`. | Run it again with `sudo`. |
| `no TV found and none configured` | Nothing answered on the TV's cable in time, or you declined to look again. | Check the cable and that the TV is on, then run setup again. |
| `... has no MAC address in the lease or neighbour table yet` | The TV answered, but has not finished getting its address. | Wait a minute and run setup again. |
| `the installer ran but eth0 still does not carry 10.10.10.1` | The installer could not set up the TV's port. | Read the installer's output above the message. |
| `install.sh not found` | Setup ran from another folder. | Run it from `/opt/tvgw/src`, as above. |
| `another install is running` | Another install held the lock for ten minutes. | Wait for it to finish and run setup again. |
| `the installer stopped (exit N)` | The installer stopped; its output above says why. | Fix the cause and run setup again. |
| `this AdGuard Home serves other devices, so tvgw leaves it as it is` | You said something else in the house uses the filter on this computer. tvgw would cut it off. | Put tvgw on a computer of its own. If nothing else uses the filter after all, run setup again and answer `n`. |
| `the TV did not answer over its LAN API` | The TV was off, or its prompt was not accepted in time. Setup goes on without pairing. | Pair later with `sudo tvgw tv pair`. |
| `refused, nothing written: ...` | A value the settings file cannot take. | Run setup again and give another answer. |
| `cannot read /opt/AdGuardHome/AdGuardHome.yaml` | The filter is not installed, or its first-run page was not finished. | Do [install what tvgw needs](#install-what-tvgw-needs) again. |

Every other message, with the unattended ones, is in [other ways to install](advanced.md#every-message-setup-can-stop-with).

## How to tell it worked

At any time, on the gateway:

```sh
tvgw status
```

It answers in three lines: whether the protection held at the last check, how long ago that was, and what to do. It needs no `sudo`. On a working gateway it prints:

```text
tvgw: the protection held at 21:40 (<N> checks passed).
The checks run every 10 minutes; this one is 4 minutes old.
Nothing needs your attention.
```

If it says no check has run yet, wait 10 minutes and run it again. Then check the TV itself: open a streaming app and play something. It plays as it did before.

When `tvgw status` says to run the doctor, run:

```sh
sudo tvgw doctor
```

The doctor says what is wrong in plain words and offers to fix each problem it can. Type `y` to let it. [Fix a problem](../use/troubleshooting.md) has the rest.

If the TV ever has no internet, the quick fix is to move its cable from the gateway to your router. The TV then works without the gateway's protection, and tvgw keeps its settings for when you move the cable back.

The next morning, read the first brief:

```sh
tvgw brief
```

It says whether the protection held, what the TV tried to reach, what was refused, and anything you should do. [Read your daily brief](../use/daily-brief.md) explains it.

## Add the analyst, if you want it

With an Anthropic API key, a Claude model reads a scrubbed summary of each day and proposes what to block. Nothing is applied on its own unless you switch that on.

Make the key on the API keys page of Anthropic's [Claude Console](https://platform.claude.com/settings/keys) (address read on 2026-11-04). Each request is billed to that account.

The key lives in one file on the gateway that only the administrator can read, and nowhere else:

```sh
sudo install -m 600 -o root -g root /dev/null /etc/tvgw/claude.key
sudoedit /etc/tvgw/claude.key      # paste the API key on one line, save, close
```

`sudoedit` opens a text editor in the terminal. Its bottom lines list its keys, where ^ means the Ctrl key: save, then exit. The next nightly run uses the key. [Turn on the analyst](../use/analyst.md) says what is sent, to whom, and what it costs.

## Install the package

Each release also carries a package for 64-bit ARM computers, and since 0.3.0 one for Intel and AMD computers and a one-line installer that picks the right one. Neither the packages nor the installer has been run on a real gateway yet. Both still need the filter installed first. For now they suit an engineer: [install from the package](advanced.md#install-from-the-package) has the steps.

To check a downloaded package against its release, put the package and the release's `SHA256SUMS` file in one folder, and in that folder:

```sh
sha256sum -c SHA256SUMS --ignore-missing
```

It prints `OK` after the package's name when the file is the one the release published.

Next: [read your daily brief](../use/daily-brief.md).
