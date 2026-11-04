# Install guide

This page takes you from an empty Raspberry Pi to a working gateway and your first daily brief. It is the install as it works today, from the source code; a one-command install that does these steps for you is being built. Allow about an hour, most of it waiting.

## What you need

- **A Raspberry Pi 5** (a Pi 4 also works) with a power supply and a microSD card of 16 GB or more. This is the reference computer. Another small 64-bit computer with Debian 13 and two network connections can work too, but has not been tested yet.
- **An Ethernet cable** from the Pi to the TV. The Pi's own network port is for the TV; the Pi reaches your router over Wi-Fi.
- **Your own computer** (Windows, macOS or Linux) on the same home network, to type commands on the Pi.
- **The TV** within cable reach of the Pi.

You need no networking knowledge. Every command below is copied as it is.

## Step 1: prepare the Pi

1. On your own computer, install [Raspberry Pi Imager](https://www.raspberrypi.com/software/) and put the microSD card in.
2. In Imager choose your Pi, then the operating system **Raspberry Pi OS Lite (64-bit)**, then the card.
3. Before writing, open Imager's settings and set: a hostname (for example `tvgw`), a username and password, **your Wi-Fi network and its password**, your time zone, and under Services turn on **SSH** with password login.
4. Write the card, put it in the Pi, and power the Pi on. **Leave the Pi's network port empty for now**: it is for the TV.
5. After two minutes, open a terminal on your own computer and connect to the Pi:
   - **Windows:** open PowerShell and type `ssh USERNAME@tvgw.local` (use the username and hostname you chose).
   - **macOS or Linux:** open Terminal and type the same.

   Answer `yes` to the first-time question and give the password. You are now typing on the Pi. Everything below is typed there.

## Step 2: install what tvgw needs

Paste these lines one at a time. The first one pre-answers a question about packet capture so that tvgw's own capture user can run it:

```sh
echo 'wireshark-common wireshark-common/install-setuid boolean false' | sudo debconf-set-selections
sudo apt update
sudo apt install -y tcpdump conntrack dnsmasq tshark wireshark-common nginx libnginx-mod-stream python3-venv python3-yaml git
```

Then install AdGuard Home, the DNS filter tvgw configures for the TV:

```sh
curl -s -S -L https://raw.githubusercontent.com/AdguardTeam/AdGuardHome/master/scripts/install.sh | sh -s -- -v
```

AdGuard Home needs its first-run page completed once. From your own computer, in a second terminal, open a tunnel to the Pi:

```sh
ssh -L 3000:127.0.0.1:3000 USERNAME@tvgw.local
```

Leave that terminal open and go to <http://127.0.0.1:3000> in a browser on your own computer. In the wizard, let the DNS server listen on **all interfaces**, keep the web interface's default address, and choose an admin username and password. Finish the wizard and close the browser tab; tvgw takes over the configuration from here, and you will not need the AdGuard page again.

## Step 3: get tvgw

Back on the Pi:

```sh
sudo install -d -o "$USER" /opt/tvgw
git clone https://github.com/kywwilson11/tvgw.git /opt/tvgw/src
```

## Step 4: connect the TV

1. Plug the Ethernet cable into the Pi's network port and into the TV's network port.
2. Switch the TV on.
3. On the TV, turn **Wi-Fi off** and make it **forget every saved Wi-Fi network**, so its only connection is the cable. On an LG: Settings, General, Network, Wi-Fi Connection; delete the saved networks, then switch Wi-Fi off. Turn Wi-Fi Direct and screen sharing off as well.

This step matters: the gateway can only filter what passes through it. [What it stops, and what it cannot](what-it-stops.md) explains why.

## Step 5: run setup

```sh
cd /opt/tvgw/src
sudo PYTHONPATH=src python3 -m tvgw setup
```

Setup finds the TV on the cable, asks you to confirm which device it is, and asks a few questions with a sensible default in brackets; pressing Enter takes the default. It then installs the gateway, which takes a few minutes, and checks its own work.

On an LG TV, setup offers to pair with the TV so the gateway can read its privacy settings every hour. Say yes, and when the TV shows a prompt asking whether to allow the connection, accept it with the remote within a minute. This prompt is not one of the TV's data agreements; leave those declined.

Setup ends with one of two lines:

- `Result: the gateway holds.` Everything works. The TV has internet again, filtered.
- `Result: NOT done.` The lines above it say what is wrong and what to do. [When setup stops](setup.md#when-it-stops) lists every message.

## Step 6: check it, now and tomorrow

At any time, on the Pi:

```sh
sudo tvgw verify
```

Every line should start with `OK`. If the TV ever has no internet, the quick fix is to move its cable from the Pi to your router; tvgw keeps its settings.

The next morning, read the first brief:

```sh
tvgw brief
```

It says whether the protection held, what the TV tried to reach, what was refused, and anything you should do. [Read your daily brief](reading-the-brief.md) explains each section.

## Optional: let the analyst read the brief

With an Anthropic API key, a Claude model reads a minimized summary of each day and proposes rules in plain words; nothing is applied on its own unless you switch that on. The key lives in one root-only file on the Pi and nowhere else:

```sh
sudo install -m 600 /dev/null /etc/tvgw/claude.key
sudoedit /etc/tvgw/claude.key
```

Paste the key, save, and the next nightly run uses it. [The analyst](analyst-and-autonomy.md) says what is sent, to whom, and what it costs.

## More

- [tvgw setup in detail](setup.md): every question, the unattended mode, the dry run.
- [Installing from the package](packaging.md): the `.deb` for people who prefer it. It still needs AdGuard Home installed first.
- [Everything else](README.md): how it works, the runbook, the design.
