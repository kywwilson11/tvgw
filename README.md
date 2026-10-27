# tvgw: a Raspberry Pi between a smart TV and your network

A smart TV plugs into the Pi's Ethernet port. The Pi is its only way out. From there tvgw does five things:

- **Isolation.** nftables keeps the TV off your home LAN and forces every DNS lookup to a local AdGuard Home. DNS-over-HTTPS, DNS-over-TLS and (by default) QUIC are rejected so the TV cannot route around the filter. IPv6 is dropped.
- **Filtering.** AdGuard Home is configured as code from a TOML TV profile: blocklists, custom rules, upstreams, and the TV as a named client. An nginx URL filter handles the vendor's plain-HTTP file service, which DNS cannot split into wanted and unwanted.
- **Observation.** tcpdump keeps TLS handshakes, DNS and plain HTTP. conntrack keeps byte counts per connection. AdGuard keeps every query with the rule that matched. nginx logs the file-service requests. All of it is loaded hourly into one SQLite database (about 1 MB per day).
- **Reporting.** `tvgw brief` is a one-screen daily summary with red lines at the top. `tvgw verify` runs every 10 minutes and proves the firewall, routing, resolver and services still hold. The TV's own privacy settings are read hourly over its LAN API (LG webOS only).
- **Vendor knowledge in profiles.** A different TV is a new profile file, not a new program. The bundled profile is `lg-webos`.

## What it is not

- It cannot remove ads stitched into a video stream. Prime Video's ads come from the same CDN as the show.
- It does not root the TV, and it cannot change the TV's settings. On webOS 5 the LAN API is read-only.
- It does not decrypt TLS. It sees names, sizes and timing, not content.

## Threat model

The TV is treated as an untrusted device that reports on its owner. tvgw targets:

- **ACR** (automatic content recognition): screen fingerprints sent to a vendor or ad partner.
- **Telemetry and ad measurement** from the vendor and from preinstalled apps.
- **Device fingerprinting** by third parties, such as remote-control and smart-home vendors.
- **LAN scanning**: SSDP, mDNS and other discovery sweeps, and probes of networks the TV remembers.
- **Voice back-ends**: speech services are blocked, so a declined consent is a wall and not a checkbox.
- **DNS bypass**: DoH, DoT, QUIC, and hardcoded resolvers such as 8.8.8.8. Plain DNS to any address is redirected to AdGuard. The rest is rejected.

One dependency runs the other way. webOS has no battery clock and takes the time from the vendor's SDP host. Block that host and the clock resets, then TLS fails everywhere. The profile lists these hosts as must-allow, and the brief raises a red line if they are blocked or never looked up.

## What it found on an LG CX (October 2026)

- ACR phones its provisioning host even with Live Plus off, and re-fetches its config over plain HTTP on every boot.
- A device-fingerprinting host is tried about once a minute.
- The TV sweeps the LAN constantly and probes remembered networks. No menu setting stops this. Isolation does.
- The Content Store needs `us.lgrecommends.lgappstv.com`, and app installs need the GFTS hosts. Blocking either breaks installs, which is why the URL filter exists.
- Telemetry endpoints of Netflix, Prime, Peacock and Disney+ can be blocked without breaking playback (each tested).
- The CX has no built-in microphone. With the Voice Information agreement declined, a press of the remote's mic button sends nothing.

More in the original CX bring-up notes (partly stale): [docs/lg-cx-deployment.md](docs/lg-cx-deployment.md).

## Requirements

- A Raspberry Pi with two network paths: the built-in Ethernet port for the TV (the scripts assume `eth0`) and an uplink to your router (Wi-Fi `wlan0` by default; set `WAN_IF`). Built and run on a Pi 5.
- Raspberry Pi OS (Debian 12) with NetworkManager and Python 3.11 or newer. Keep everything on the SD card; do not put the store on a failing USB disk.
- Packages: `tcpdump conntrack dnsmasq tshark nginx libnginx-mod-stream python3-venv`. The scripts also use `nft`, `nmcli` and `curl`.
- AdGuard Home installed natively in `/opt/AdGuardHome` (not Docker).
- The TV's wired MAC address, to pin its DHCP lease.
- Optional: a VPN client on the Pi. `UPLINK=vpn` sends TV traffic through `tun0`.

## Quick start

1. Flash Raspberry Pi OS, enable SSH keys, and connect the Pi's uplink to your home network.
2. Install the packages:
   ```sh
   sudo apt install tcpdump conntrack dnsmasq tshark nginx libnginx-mod-stream python3-venv
   ```
3. Install AdGuard Home natively with AdGuard's own install script. Finish its first-run wizard through an SSH port-forward to port 3000; the wizard creates the admin user. After that, tvgw owns the config.
4. Clone the repo and write the settings. Edit them before installing, or the TV gets a placeholder MAC:
   ```sh
   git clone <repo-url> /opt/tvgw/src && cd /opt/tvgw/src
   sudo install -d /etc/tvgw
   sudo install -m 644 deploy/tvgw.conf.example /etc/tvgw/tvgw.conf
   sudo nano /etc/tvgw/tvgw.conf        # TV_MAC, TV_IP, TV_NAME, WAN_IF, WAN_GW
   ```
5. Install: `cd deploy && sudo ./install.sh`. It builds the venv, installs the scripts and units, creates the `tv-lan` connection (10.10.10.1/24 on eth0), configures nginx and dnsmasq, applies the AdGuard config from the profile, starts everything, and runs `tvgw verify`.
6. Plug the TV into the Pi's Ethernet port and set it to wired DHCP. Make the TV forget its Wi-Fi networks so it has no unfiltered fallback. Power-cycle it.
7. Run `sudo tvgw verify`. Every line should say OK.
8. For an LG, pair the LAN API once: `sudo /opt/tvgw-venv/bin/bscpylgtvcommand -p /var/lib/tvgw/lgtv-keys.sqlite <TV_IP> get_software_info`, then accept the prompt on the TV.
9. Use the TV for a day, then read `tvgw brief`. It shows yesterday by default; `tvgw brief $(date +%F)` shows today.

## CLI reference

Global options: `--conf PATH` (default `/etc/tvgw/tvgw.conf`), `--db PATH`, `--version`. `SINCE` is `2h`, `1d`, `7d`, `2w` or an ISO date or time; the default is `1d`.

| Command | What it does |
|---|---|
| `tvgw ingest` | Load new logs and pcaps into the store. Needs root. Runs hourly; safe by hand. Exit 1 on warnings. |
| `tvgw brief [DAY] [--json]` | The daily brief for `YYYY-MM-DD` (default yesterday). |
| `tvgw new-hosts [SINCE]` | Names first seen in the window, with category, counts, state and rule. |
| `tvgw retries [SINCE]` | Blocked names the TV keeps asking for. |
| `tvgw allowed [SINCE]` | Allowed names outside the profile's expected categories: candidates for new rules. |
| `tvgw top-upload [SINCE]` | Destinations by bytes the TV sent, grouped by TLS name. |
| `tvgw gfts [SINCE]` | URL-filter requests by HTTP status and `biz_code`. |
| `tvgw tvstate [SINCE]` | Hourly power state and app, plus changes in the TV's settings. |
| `tvgw host NAME` | Everything about one name: first and last seen, rules, IPs, bytes, lookups per day. Exit 1 if never seen. |
| `tvgw rules` | Policy history: every AdGuard rule, URL-filter regex and manual IP block, with when it appeared and left. |
| `tvgw size` | Row count per table, oldest DNS row, file size. |
| `tvgw sql QUERY...` | Read-only SQL (`select`, `with`, `explain`, `pragma`, `values`). |
| `tvgw profile [--profile P] [--model M] [--webos V] [--firmware F]` | Print the must-allow list, rules lint, matching generation, and hardware facts plus checklist for a model. Exit 1 if the lint finds problems. |
| `tvgw verify [--record] [--json]` | Check the firewall, routing, resolver and services. Needs root. Exit 1 on any FAIL. `--record` stores the verdict and the firewall counters. |
| `tvgw tvcheck [--key-file F]` | Read the TV's settings over the LG LAN API. Exit 1 if unreachable, 2 if Live Plus (ACR) is on. |
| `tvgw adguard diff` | Show drift between AdGuard Home and the profile plus settings. Exit 1 if any. |
| `tvgw adguard apply [--dry-run]` | Stop AdGuard, back up its YAML, write the planned config, restart. Rolls back if the resolver stays silent. |
| `tvgw report [--day D \| --week YYYY-Www \| --since S [--until U]] [--json]` | The brief over any window (default: the last 24 h). The hourly job writes `reports/latest`, `reports/daily/<day>` and `reports/weekly/<week>` with it. |

## The daily brief

`tvgw brief` is run by hand; no timer produces it. Read it top to bottom. The first lines say whether the rest can be trusted.

| Section | What it shows and how to read it |
|---|---|
| Header | Lookups (blocked, distinct names), connections, bytes up and down for the day. |
| Coverage | Rows per source and the last ingest. `NOT ASSESSED` means a source was not read for 2 hours: its sections are unknown, not clean. `ingest warning:` lines are ingest errors. |
| `RED LINE:` | Things that must never be true: a must-allow name blocked, a clock host blocked, the TV on without ever looking up its clock host, failed `verify` checks, ingest warnings. |
| Firewall held | Packets each firewall rule stopped that day (DNS forced to AdGuard, DoT/DoQ, QUIC, DoH, LAN, and so on) and how many `verify` runs failed. A counter above zero proves the rule fires. |
| Clock hosts | Lookups of the vendor's clock hosts, how many were blocked, and when the first one happened. |
| While off/asleep | Lookups and connections during hours the TV reported itself not Active. Should be near nothing. |
| Private reverse lookups | The TV taking inventory of private addresses. |
| New hosts | Names first seen that day. `new domain` means no other name under the same registered domain was seen before. Read these first: a new domain in `Other` that is allowed needs a decision. |
| Blocked and still retried | Blocked names by lookups, with the matching rule. The rules working. A new name here is worth a look. |
| Allowed, outside expected categories | Allowed public names the profile does not count as the TV doing its job. Rule gaps and candidates. |
| Top upload | Destinations by bytes sent, per TLS name (IP when no hello was captured). `+N` means N more addresses behind the name. |
| GFTS URL filter | Requests as `status biz_code: count`. 403 was blocked by tvgw; 200 passed. |
| Unexpected ports | Traffic to ports other than 80, 123 and 443. `none` is the goal; it is the criterion for enabling `STRICT_PORTS`. |
| LAN probes (dropped) | TCP connection attempts to private or multicast addresses. The firewall dropped them; this is the evidence. |
| Unresolved flows | TCP destinations that no DNS answer, TLS name or HTTP host explains: hardcoded IPs or a DNS bypass. |
| Firmware | A new firmware version and the names that first appeared in the 72 hours after it. |
| DNS oddities | Names that look like data: over 100 characters, a long random-looking label, or hundreds of names under one domain. |
| TV | Hourly power readings (`14:20=Active`). Anything but Active counts as off or asleep. |
| Rule changes | Rules added or removed that day. |

What to do about each red line is in [docs/operations.md](docs/operations.md).

## Changing policy

The repo is the source of truth. Do not edit AdGuard in its web UI; the next `apply` reverts it.

1. Edit `src/tvgw/profiles/lg-webos.toml` (categories, must-allow, filters, URL filter) or `lg-webos.rules` (AdGuard rules, with a dated reason per block).
2. Run `make gate` (lint and unit tests; the tests include the profile lint).
3. Run `make deploy` (rsync to the Pi, then `install.sh`, which runs `tvgw adguard apply`).
4. `sudo tvgw adguard diff` must exit 0. The hardware suite enforces zero drift.

The `@@||host^` exception for every `[must_allow]` host is generated, never hand-written. The lint (`tvgw profile`) refuses a block that covers a must-allow name, a block at the apex of a zone listed in `never_block_apex`, and an exception that sits above a blocked name. The nginx regex in `deploy/nginx/tvgw-gfts.conf` is not generated from the profile; keep the two in step by hand.

## Profiles

A profile is a TOML file plus a companion `.rules` file in `src/tvgw/profiles/`. It holds the expected categories, clock hosts, `never_block_apex`, hostname categories (longest match wins), must-allow hosts with reasons, the AdGuard blocklists and the URL filter. The LG profile also carries three reference tables: `[[generations]]` (webOS 3 to 26: clock hosts, LAN-API behavior, DNS-bypass habits, each graded observed, community, spec or low), `[[hardware]]` (which model lines have a far-field microphone) and a `[checklist]` for audio and ACR.

`tvgw profile --model OLED65C2PUA` prints what the profile knows about a model before you plug it in. `--webos` and `--firmware` pick the generation. To write a profile for another vendor, see [docs/adding-a-profile.md](docs/adding-a-profile.md).

## Testing

| Layer | Command | Notes |
|---|---|---|
| Unit | `make test` | pytest; fixtures are verbatim captured lines. Needs no gateway. |
| Gate | `make gate` | What CI runs: ruff check, format check, unit tests. |
| Mutation | `make mutmut` | Slow. Weekly in CI. `lgwebos.py` (needs a TV) is excluded. |
| Hardware | `make hardware PI=host` | pytest `-m hardware` on the Pi against the live gateway. Changes nothing, except that it runs `tvgw ingest` twice. Skips off the gateway. |

CI (`.github/workflows/ci.yml`): the `test` job runs `make gate` on Python 3.11 and 3.13. On a push to `main`, the `hardware` job runs on a self-hosted runner on the Pi: it deploys the checkout with `install.sh`, then runs the hardware suite. A `mutation` job runs mutmut weekly and on demand. A push to `main` therefore restarts the firewall.

Repo rules: parsers are pure functions with real captured lines as fixtures. Anything that touches the Pi (files, tshark, journalctl) is injected. Site identifiers (MACs, LAN addresses, ZIP codes) never go in the repo; they live in `/etc/tvgw/tvgw.conf`.

## Repository layout

```
src/tvgw/            the package: parsers, config, profile, db, ingest, queries, verify,
                     adguardcfg, cli, lgwebos
src/tvgw/profiles/   lg-webos.toml + lg-webos.rules
deploy/              install.sh, nftables/tvgw-apply, systemd units, nginx, dnsmasq template,
                     NetworkManager, logrotate, shell glue (bin/), tvgw.conf.example
tests/unit/          pytest; mutation-tested with mutmut
tests/hardware/      pytest -m hardware, run on the Pi
docs/                runbook, profile guide, incident log, privacy notes, original CX notes
```

## Documentation

- [docs/operations.md](docs/operations.md): runbook, deploy and rollback, `verify` checks, timers, common breakages.
- [docs/adding-a-profile.md](docs/adding-a-profile.md): writing a profile for another TV vendor.
- [docs/incidents.md](docs/incidents.md): what broke in production and what changed.
- [docs/privacy-and-retention.md](docs/privacy-and-retention.md): what the store holds, for how long, and who can read it.
- [docs/lg-cx-deployment.md](docs/lg-cx-deployment.md): the original CX bring-up notes (partly stale).
- [CHANGELOG.md](CHANGELOG.md)

## License

MIT.
