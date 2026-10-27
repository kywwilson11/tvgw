# tvgw: a Raspberry Pi between a smart TV and your network

tvgw turns a Raspberry Pi into the only way a smart TV can reach the internet. The Pi keeps the TV off your home network, forces its DNS through a filter, blocks the ways around that filter, and records what the TV does in a small database you can query. It is built and run in front of an LG CX (2020, webOS 5).

**In one line:** TV → Pi `eth0` (10.10.10.1/24) → nftables + AdGuard Home + an nginx URL filter → Pi `wlan0` → home router, with tcpdump and conntrack feeding a SQLite store that `tvgw brief` and `tvgw verify` read.

The TV's traffic leaves straight through the home router, not through the VPN the Pi uses for itself. Streaming services refuse VPN addresses, and the trackers are blocked either way. The trade-off is written down in [docs/design-decisions.md](docs/design-decisions.md#1-the-tv-uses-the-direct-uplink-not-the-vpn).

## What it does

- **Isolation.** nftables keeps the TV off the home LAN and redirects every DNS packet to AdGuard Home on the Pi, whatever address it was aimed at. DoT, DoQ, QUIC, known DoH resolvers and tunnel protocols are rejected. IPv6 is dropped at the wire.
- **Filtering.** AdGuard Home is configured from a TOML profile: blocklists, custom rules, upstreams, the TV as a named client. An nginx URL filter handles LG's plain-HTTP file service, which carries both app downloads and the ACR config, so DNS cannot split it.
- **Observation.** tcpdump keeps what the TV sends and the analysis needs: TLS ClientHellos, the TV's plain-HTTP requests, DNS and connection flags; nothing the TV receives and no encrypted payload. conntrack logs every finished connection with byte counts. AdGuard logs every query with the rule that matched. All of it is loaded hourly into one SQLite file.
- **Reporting.** `tvgw brief` is a one-screen daily summary with red lines at the top. `tvgw verify` runs every 10 minutes and checks that the firewall, routing, resolver and services still hold. The TV's privacy settings are read hourly over its LAN API (LG only).
- **Profiles.** Vendor knowledge lives in a profile file, not in code. The bundled profile is `lg-webos`.

## What it is not

- It cannot remove ads stitched into a video stream. Prime Video's ads come from the same CDN as the show.
- It does not root the TV and cannot change the TV's settings. On webOS 5 the LAN API is read-only.
- It does not decrypt TLS. It sees names, sizes and timing, not content.
- It does not hide your address from LG or the streaming services, and your ISP sees which servers the TV talks to.

## Quick start

You need a Raspberry Pi (built on a Pi 5) with Raspberry Pi OS (Debian 12), NetworkManager and Python 3.11 or newer; its Ethernet port (`eth0`) for the TV and an uplink to your router (Wi-Fi `wlan0` by default); AdGuard Home installed natively in `/opt/AdGuardHome`; and the TV's wired MAC address. Keep everything on the SD card. A VPN client on the Pi is optional.

1. Install the packages:
   ```sh
   sudo apt install tcpdump conntrack dnsmasq tshark nginx libnginx-mod-stream python3-venv
   ```
2. Install AdGuard Home with AdGuard's own install script and finish its first-run wizard through an SSH port-forward to port 3000. The wizard creates the admin user. From then on tvgw owns the config.
3. Clone the repo and write the settings before installing, or the TV gets a placeholder MAC:
   ```sh
   git clone <repo-url> /opt/tvgw/src && cd /opt/tvgw/src
   sudo install -d /etc/tvgw
   sudo install -m 644 deploy/tvgw.conf.example /etc/tvgw/tvgw.conf
   sudo nano /etc/tvgw/tvgw.conf        # TV_MAC, TV_IP, TV_NAME, WAN_IF, WAN_GW
   ```
4. Install: `cd deploy && sudo ./install.sh`. What it does, step by step: [deploy/README.md](deploy/README.md).
5. Plug the TV into the Pi's Ethernet port and set it to wired DHCP. Make it forget its Wi-Fi networks so it has no unfiltered fallback. Power-cycle it.
6. Run `sudo tvgw verify`. Every line should say `OK`.
7. For an LG, pair the LAN API once and accept the prompt on the TV. The key can control the TV, so make it root-only (the installer also does this on every run):
   ```sh
   sudo /opt/tvgw-venv/bin/bscpylgtvcommand -p /var/lib/tvgw/lgtv-keys.sqlite <TV_IP> get_software_info
   sudo chmod 600 /var/lib/tvgw/lgtv-keys.sqlite
   ```
8. Use the TV for a day, then read `tvgw brief`. It shows yesterday by default; `tvgw brief $(date +%F)` shows today.

After that, deploy from your workstation with `make deploy PI=<ssh-host>`; see [docs/operations.md](docs/operations.md#deploying-and-rolling-back).

## Documentation map

| Read | For |
|---|---|
| [docs/README.md](docs/README.md) | The index of the docs. |
| [docs/architecture.md](docs/architecture.md) | Data path, control and data planes, the store's tables, cadences, trust boundaries. |
| [docs/design-decisions.md](docs/design-decisions.md) | Why it is built this way, including the direct-uplink decision. |
| [docs/operations.md](docs/operations.md) | The runbook: daily routine, red lines, deploy and rollback, `verify` checks, breakages. |
| [docs/adding-a-profile.md](docs/adding-a-profile.md) | Writing a profile for another TV vendor. |
| [docs/privacy-and-retention.md](docs/privacy-and-retention.md) | What the store holds, for how long, who can read it, backups. |
| [docs/incidents.md](docs/incidents.md) | What broke in production and what changed. |
| [docs/lg-cx-deployment.md](docs/lg-cx-deployment.md) | The original CX bring-up log (superseded). |
| [src/tvgw/README.md](src/tvgw/README.md) | The Python package: module map, how to add a query, brief section, check or command. |
| [src/tvgw/profiles/README.md](src/tvgw/profiles/README.md) | The `lg-webos` profile, its sources and evidence grades. |
| [deploy/README.md](deploy/README.md) | `install.sh` and the settings file. |
| [deploy/nftables/README.md](deploy/nftables/README.md) | The firewall, chain by chain. |
| [deploy/systemd/README.md](deploy/systemd/README.md) | Every unit and timer. |
| [deploy/nginx/README.md](deploy/nginx/README.md) | The URL filter and TLS passthrough. |
| [deploy/dnsmasq/README.md](deploy/dnsmasq/README.md), [deploy/networkmanager/README.md](deploy/networkmanager/README.md), [deploy/logrotate/README.md](deploy/logrotate/README.md), [deploy/bin/README.md](deploy/bin/README.md) | DHCP, the TV interface, log rotation, the shell jobs. |
| [tests/README.md](tests/README.md), [tests/unit/README.md](tests/unit/README.md), [tests/hardware/README.md](tests/hardware/README.md) | The three kinds of tests and when each runs. |
| [CHANGELOG.md](CHANGELOG.md) | What changed. |

## CLI reference

Global options: `--conf PATH` (default `/etc/tvgw/tvgw.conf`), `--db PATH`, `--version`. `SINCE` is a number with `s`, `m`, `h`, `d` or `w` (`2h`, `7d`), or an ISO date or time; the default is `1d`. The commands that read the store work for any member of the `adm` group. `ingest`, `prune-pcaps`, `verify`, `tvcheck` and `adguard apply` need root.

| Command | What it does |
|---|---|
| `tvgw ingest` | Load new logs and pcaps into the store. Root. Runs hourly; safe by hand. Exit 1 on warnings. |
| `tvgw prune-pcaps` | Delete raw pcaps past `PCAP_DAYS` or `PCAP_MAX_GB`: only files ingest has read, never the one tcpdump is writing; an un-read file is kept and reported until twice `PCAP_DAYS`. Root. Runs hourly. Exit 1 on any warning. |
| `tvgw brief [DAY] [--json]` | The daily brief for `YYYY-MM-DD` (default yesterday). |
| `tvgw report [--day D \| --week YYYY-Www \| --since S [--until U]] [--json]` | The brief over any window; default the last 24 h. Weeks add a by-day table. |
| `tvgw new-hosts [SINCE]` | Names first seen in the window, with category, counts, state and rule. |
| `tvgw retries [SINCE]` | Blocked names the TV keeps asking for. |
| `tvgw allowed [SINCE]` | Allowed names outside the profile's expected categories: candidates for rules. |
| `tvgw top-upload [SINCE]` | Destinations by bytes the TV sent, grouped by TLS name. |
| `tvgw gfts [SINCE]` | URL-filter requests by HTTP status and `biz_code`. |
| `tvgw tvstate [SINCE]` | Hourly power state and app, then changes in the TV's settings. |
| `tvgw host NAME` | One name: first and last seen, category, rules, addresses, bytes, lookups per day. Exit 1 if never seen. |
| `tvgw rules` | Policy history: every AdGuard rule, URL-filter regex and manual IP block, with when it appeared and left. |
| `tvgw size` | Row count per table, oldest DNS row, file size. |
| `tvgw sql QUERY...` | Read-only SQL starting with `select`, `with`, `explain`, `pragma` or `values`. |
| `tvgw profile [--profile P] [--model M] [--webos V] [--firmware F]` | Must-allow list, rules lint, matching generation, and for `--model` the hardware facts and checklist. Exit 1 if the lint finds problems. |
| `tvgw verify [--record] [--json]` | Check firewall, routing, resolver and services. Root. Exit 1 on any FAIL. `--record` stores the verdict and the firewall counters. |
| `tvgw tvcheck [--key-file F]` | Read the TV's settings over the LG LAN API. Exit 1 if unreachable, 2 if Live Plus (ACR) is on. |
| `tvgw adguard diff` | Drift between AdGuard Home and the profile plus settings. Exit 1 if any. |
| `tvgw adguard apply [--dry-run]` | Validate the planned config, stop AdGuard, back up its YAML, swap the file in, start it. Rolls back if the resolver stays silent. Root. |

## The daily brief

`tvgw brief` is run by hand. The hourly job writes the same report for the last 24 hours, each finished day and each finished ISO week to `/var/lib/tvgw/reports/`. Read it top to bottom: the first lines say whether the rest can be trusted. Some sections appear only when they have something to show.

| Section | What it shows and how to read it |
|---|---|
| Header | Lookups (blocked, distinct names), connections, bytes up and down. |
| Coverage | Rows per source and the last ingest. `NOT ASSESSED` means a source was not read for 2 hours: its sections are unknown, not clean. `ingest warning:` lines are ingest errors. |
| `RED LINE:` | Things that must never be true: a must-allow name blocked, a clock host blocked, the TV on without looking up its clock host, failed `verify` runs, ingest warnings. |
| Firewall held | Packets each firewall rule stopped (DNS forced to AdGuard, DoT/DoQ, QUIC, DoH, LAN, and so on) and how many `verify` runs failed. |
| Clock hosts | Lookups of the vendor's clock hosts, how many were blocked, the first one's time. |
| While off/asleep | Lookups and connections in hours the TV reported itself not Active. Should be near nothing. |
| Private reverse lookups | The TV taking inventory of private addresses. |
| By day | Weekly reports only: one row per day. |
| By category | Lookups, blocks, names, connections and bytes per profile category. `Unresolved` flows had no TLS name; `Gateway` is traffic to the Pi. |
| DNS sent to other resolvers | Resolvers the TV tried directly. The firewall redirected these to AdGuard. |
| New hosts | Names first seen. `new domain` means nothing else under the same registered domain was seen before. Read these first. |
| Blocked and still retried | Blocked names by lookups, with the rule. The rules working. |
| Allowed, outside the expected categories | Allowed public names that are not the TV doing its job. Rule gaps and candidates. |
| Top upload | Destinations by bytes sent, per TLS name (address when no hello was captured). `+N` means N more addresses. |
| GFTS URL filter | Requests as `status biz_code: count`. 403 was blocked by tvgw. |
| Plain HTTP | Unencrypted requests outside the file service, grouped by path. |
| Unexpected ports | Traffic to ports other than 80, 123 and 443. `none` is the goal. |
| LAN probes (dropped) | TCP connection attempts to private or multicast addresses (a retransmitted SYN is the same attempt). The firewall dropped them. |
| Unresolved flows | TCP destinations that no DNS answer, TLS name or HTTP host explains: hardcoded addresses or a DNS bypass. |
| Firmware | A new firmware version and the names first seen in the 72 hours after it. |
| DNS oddities | Names that look like data: over 100 characters, a long random-looking label, or over 200 names under one domain. |
| TV | Hourly power readings (`14:20=Active`). |
| Rule changes | Rules added or removed. |

What to do about each red line: [docs/operations.md](docs/operations.md#red-lines).

## Changing policy

The repo is the source of truth. Do not edit AdGuard in its web UI; the next `apply` reverts it.

1. Edit `src/tvgw/profiles/lg-webos.toml` (categories, must-allow, filters, URL filter) or `lg-webos.rules` (AdGuard rules, each with a dated reason).
2. Run `make gate`: lint, format check and unit tests, which include the profile lint.
3. Run `make deploy PI=<ssh-host>`. It rsyncs the tree and runs `install.sh`, which runs `tvgw adguard apply`.
4. `sudo tvgw adguard diff` must exit 0.

Never write the `@@||host^` exceptions for `[must_allow]` hosts; they are generated. If you change the URL filter's `block_regex`, change `deploy/nginx/tvgw-gfts.conf` too. More in [src/tvgw/profiles/README.md](src/tvgw/profiles/README.md).

## Threat model

The TV is treated as an untrusted device that reports on its owner. tvgw targets ACR (screen fingerprints sent to the vendor or an ad partner), telemetry and ad measurement from the vendor and preinstalled apps, device fingerprinting by remote-control and smart-home vendors, LAN scanning and probes of remembered networks, voice back-ends (blocked, so a declined consent is a wall), and DNS bypass (DoH, DoT, QUIC, hardcoded resolvers).

One dependency runs the other way. webOS has no battery clock and takes the time from LG's SDP reply. Block that host and the clock resets, then TLS fails everywhere. The profile lists these hosts as must-allow, and the brief raises a red line if they are blocked or never looked up.

## What it found on an LG CX (October 2026)

- ACR calls its provisioning host even with Live Plus off, and fetches its config over plain HTTP from LG's file service.
- A device-fingerprinting host (QuickSet) was polled about every 45 seconds.
- The TV sweeps the LAN and probes remembered networks. No menu setting stops this; isolation does.
- The Content Store needs `us.lgrecommends.lgappstv.com`, and app installs need the GFTS hosts, which is why the URL filter exists.
- Telemetry from the Netflix, Prime Video and Peacock apps is blocked. The rules record Peacock and Prime Video playing normally with it blocked.
- The CX has no built-in microphone. With the Voice Information agreement declined, a press of the remote's mic button sent nothing.

The evidence is in the dated comments of [lg-webos.rules](src/tvgw/profiles/lg-webos.rules).

## Testing

`make gate` is what CI runs: ruff check, ruff format check, and about 330 unit tests on Python 3.11 and 3.13. `make hardware PI=<ssh-host>` runs 35 hardware tests as root on the Pi against the live gateway. `make mutmut` runs mutation testing, weekly in CI. On every push to `main`, a self-hosted runner on the Pi deploys the checkout and runs the hardware suite. Details: [tests/README.md](tests/README.md).

Repo rules: parsers are pure functions tested with real captured lines. Anything that touches the Pi (files, tshark, journalctl, nft) is injected. Site identifiers (MACs, home-LAN addresses, ZIP codes) never go in the repo; they live in `/etc/tvgw/tvgw.conf`.

## Repository layout

```
src/tvgw/            the package: parsers, config, profile, store, ingest, queries, verify,
                     AdGuard config, CLI, LG LAN API reader
src/tvgw/profiles/   lg-webos.toml + lg-webos.rules
deploy/              install.sh, tvgw.conf.example, nftables/, systemd/, nginx/, dnsmasq/,
                     networkmanager/, logrotate/, bin/
tests/unit/          pytest from captured lines; mutation-tested
tests/hardware/      pytest -m hardware, run as root on the Pi
docs/                architecture, decisions, runbook, profile guide, privacy, incidents
```

## License

MIT.
