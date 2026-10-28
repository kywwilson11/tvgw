# Deployment assets

Everything that runs on the Pi outside the Python package: the installer, the settings template, the firewall script, systemd units, and the configs for nginx, dnsmasq, NetworkManager and logrotate. `install.sh` copies them into place.

From a workstation, `make deploy PI=<ssh-host>` rsyncs the working tree (uncommitted changes included) to `/opt/tvgw/src` with `--delete` and runs `sudo ./install.sh` there. The CI `hardware` job does the same on the Pi itself. See [../docs/operations.md](../docs/operations.md#deploying-and-rolling-back).

## Files

| Path | What it is | Installed as |
|---|---|---|
| `install.sh` | The idempotent installer, below. | run from `deploy/` |
| `tvgw.conf.example` | The settings template. | `/etc/tvgw/tvgw.conf`, first install only |
| `rsync.exclude` | What `make deploy` and the CI deploy leave out of the rsync to the Pi (`.git`, databases, build and cache directories). | not installed |
| [`nftables/`](nftables/README.md) | `tvgw-apply`, `block4.txt`, `doh-exclude.txt`. | `/usr/local/sbin/tvgw-apply`, `/etc/tvgw/` |
| [`systemd/`](systemd/README.md) | Eleven services and seven timers. | `/etc/systemd/system/` |
| [`bin/`](bin/README.md) | `tvgw-analyze`, `tvgw-doh-update`. | `/usr/local/sbin/` |
| [`nginx/`](nginx/README.md) | The URL filter and the TLS passthrough. | `/etc/nginx/conf.d/tvgw-gfts.conf`, `/etc/nginx/tvgw/stream.conf` |
| [`dnsmasq/`](dnsmasq/README.md) | The DHCP template. | `/etc/dnsmasq.d/tvgw.conf` |
| [`networkmanager/`](networkmanager/README.md) | Keep `eth0` up; re-apply on link changes. | `/etc/NetworkManager/conf.d/90-tvgw.conf`, `/etc/NetworkManager/dispatcher.d/90-tvgw` |
| [`logrotate/`](logrotate/README.md) | Weekly rotation of `/var/log/tvgw/*.log`. | `/etc/logrotate.d/tvgw` |

## What install.sh does, step by step

It runs with `set -euo pipefail`, so the first failing step stops it, and it exits with `tvgw verify`'s status, so a FAIL after the install fails `make deploy` and the CI deploy step. It first takes `/run/tvgw/install.lock` (waiting up to ten minutes), so `make deploy` and a CI deploy never interleave.

1. **Directories and modes.** `/etc/tvgw` (755). `/var/log/tvgw` as `2750 root:adm`, and every existing log there set to `640` group `adm`. `/var/lib/tvgw` as `2751 root:adm`: others may traverse it, because tshark runs as `nobody` and must reach the pcaps, but not list it. `/var/lib/tvgw/pcap` as `2750 tvgw-pcap:nogroup`, existing pcaps `640` group `nogroup`. The store `640` group `adm`, the LG pairing key `600`.
2. **Settings.** Copies `tvgw.conf.example` to `/etc/tvgw/tvgw.conf` and `nftables/block4.txt` to `/etc/tvgw/block4.txt`, each only if missing; the settings file is made `640 root:adm` on every run (it holds the TV's MAC and the router's address). Copies `nftables/doh-exclude.txt` to `/etc/tvgw/` every time. Reads the settings and stops unless `TV_IP`, `TV_NAME` and `URL_FILTER_RESOLVER` are well-formed: they are written into the dnsmasq and nginx configs. A `TV_MAC` that is missing or still the template's placeholder is not an error here; it means "find the TV" (step 7).
3. **The package.** Creates `/opt/tvgw-venv` if needed, upgrades pip, installs this checkout with the `lgwebos` extra plus `pytest` (the hardware suite runs on the Pi), and links `/usr/local/bin/tvgw`.
4. **Scripts.** Installs `tvgw-apply`, `tvgw-doh-update` and `tvgw-analyze` into `/usr/local/sbin`.
5. **Legacy cleanup.** Removes the retired text-report pipeline: `tvgw-extract`, the TSV files, the copied query log, `/var/lib/tvgw/archive`, the old brief files; and the retired bash prune, `/usr/local/sbin/tvgw-prune` (`tvgw prune-pcaps` replaced it). Once, it moves pre-store reports into `reports/legacy/` and leaves a `.from-the-store` marker.
6. **Configs.** Writes the dnsmasq config from the template with `TV_MAC`, `TV_IP` and `TV_NAME`; while the TV is unknown the pin line is left out, so the TV gets a pool address and can be found. Installs the NetworkManager config and dispatcher, the logrotate config, and every unit and timer.
7. **The TV interface.** Reloads NetworkManager's config. If there is no `tv-lan` connection, it turns off autoconnect on the stock "Wired connection 1" and creates `tv-lan`: `eth0`, `10.10.10.1/24`, never the default route, IPv6 disabled. Then `nmcli con up tv-lan`, only when the connection is not already active: re-activating it drops `10.10.10.1` for a moment and fires a dispatcher apply. **If the TV is unknown**, dnsmasq is restarted now and `tvgw discover --write` runs: it lists the devices on the TV side (DHCP lease and the name the TV announced, neighbour table, the vendor LAN-API ports it listens on, SSDP when the TV still answers it), asks which one is the TV when there are several, and writes `TV_MAC`, `TV_IP`, `TV_NAME` and, for a known vendor, `PROFILE` into the settings. Without a terminal the install stops and prints the two commands to run. The pin is then written and the install continues.
8. **nginx** (if installed). Writes both nginx files with `__RESOLVER__` replaced by `URL_FILTER_RESOLVER` (default `1.1.1.1`), adds the stream include to `/etc/nginx/nginx.conf` once, removes the default site, adds a drop-in (start after the network is online, restart on failure), then `systemctl daemon-reload`, `nginx -t` (a rejected config stops the install with the old one still live), enable, and `reload-or-restart`: a reload keeps the TLS passthrough and downloads in progress, and the drop-in takes effect at the next restart or boot, which is all it is for.
9. **AdGuard Home** (if `/opt/AdGuardHome/AdGuardHome.yaml` exists). Adds a drop-in that sets `WorkingDirectory=/opt/AdGuardHome`, then runs `tvgw adguard apply`. If the wizard has not been run yet, it prints a reminder instead.
10. **nftables.service** is masked unless it is enabled. Its `flush ruleset` would wipe the VPN client's rules and ours.
11. **The DoH list.** On a gateway with no `/var/lib/tvgw/doh4.txt` yet, runs `tvgw-doh-update` once (it fetches the list and applies), so a new gateway does not wait up to a day for the daily timer; offline, it prints a note and the set stays empty until the timer runs. On an existing gateway this does nothing.
12. **The firewall.** Enables `tvgw.service` (a failure stops the install). If it is already active, runs `tvgw-apply` in place; otherwise starts it with a restart. A restart would run the stop path (forwarding off) and black out the TV for a moment.
13. **Services.** Restarts dnsmasq; enables and starts the flow log, the capture and the seven timers; restarts `tvgw-pcap` or `tvgw-flowlog` only when its unit file changed (`enable --now` does not restart a running unit, and every restart is a sub-second hole in the evidence).
14. **Checks.** Runs one `tvgw-analyze` (a failure there prints a message), prints the installed version, and ends by running `tvgw verify`: its exit status is the installer's, so any FAIL fails the deploy.

### What is idempotent

Run it as often as you like. It keeps `/etc/tvgw/tvgw.conf` and `/etc/tvgw/block4.txt`, creates `tv-lan` and the nginx include only once, moves legacy reports only once, and re-applies the firewall without a restart. `tvgw adguard apply` changes nothing, and does not restart AdGuard, when the config already matches.

What a re-run does disturb: nginx reloads (downloads in progress continue) and dnsmasq restarts, a capture unit restarts when its file changed (what ends or passes in that second is not recorded, and that hour's pcap is split in two), and AdGuard restarts if its config changed. `tv-lan` is left alone while it is active. Local edits to `/etc/tvgw/doh-exclude.txt` are overwritten; make them in the repo.

## The settings file

`/etc/tvgw/tvgw.conf` is shell-style `KEY=VALUE`, read by the shell scripts with `.` and by Python with `config.parse_conf`. A value with a space in it must be quoted (`ANALYST_WEEKLY_SCHEDULE="Mon 04:10"`): unquoted, the shell runs the rest of the line as a command and `install.sh`, `tvgw-apply` and `tvgw-doh-update` stop there, so `config.load` refuses it too. It is site-specific: never commit a real one.

| Key | Example value | Read by | Meaning |
|---|---|---|---|
| `TV_MAC` | placeholder | `install.sh` (dnsmasq), Python (AdGuard client) | The TV's wired MAC, pinned by DHCP. |
| `TV_IP` | `10.10.10.17` | `install.sh`, `tvgw-flowlog.service`, Python | The TV's fixed address. |
| `TV_NAME` | `tv` | `install.sh`, Python | DHCP host name and AdGuard client name. |
| `PROFILE` | `lg-webos` | Python, `tvgw-analyze` | Which bundled profile to use. `tvgw-analyze` reads the TV over the LAN API only for `lg-webos`. |
| `WAN_IF` | `wlan0` | `tvgw-apply`, `verify` | The uplink interface. |
| `WAN_GW` | the router's address | `tvgw-apply` | Default route in table 100. Required in direct mode: `tvgw-apply` stops before loading anything when it is unset. |
| `UPLINK` | `direct` | `tvgw-apply`, `verify` | `direct` (in use) or `vpn`. See [../docs/design-decisions.md](../docs/design-decisions.md#1-the-tv-uses-the-direct-uplink-not-the-vpn). |
| `BLOCK_QUIC` | `yes` | `tvgw-apply`, `verify` | Reject UDP 443 so server names stay visible. |
| `STRICT_PORTS` | `no` | `tvgw-apply` | `yes` rejects ports other than 80, 123 and 443. |
| `DOH_LIST_URL` | HaGeZi `doh.txt` | `tvgw-doh-update` | The DoH resolver address list. |
| `URL_FILTER_RESOLVER` | `1.1.1.1` | `install.sh` (nginx) | What nginx resolves the real file-service names with. Use the VPN provider's resolver if the VPN client blocks other DNS. |
| `DB_DAYS` | `365` | Python | Rows kept in the store. |
| `PCAP_DAYS`, `PCAP_MAX_GB` | `7`, `1.5` | Python (`tvgw prune-pcaps`) | Pcap retention: a whole number of days and a number of GiB, both above 0; anything else is refused at load. |

Python also reads `GW_IP`, `DNS_UPSTREAMS`, `DNS_BOOTSTRAP`, `STATE_DIR` and `DB_PATH`, which are not in the template. Leave `GW_IP` and `STATE_DIR` alone: the shell scripts and the nginx and dnsmasq files hardcode `10.10.10.1` and `/var/lib/tvgw`.

After changing a firewall setting, run `sudo tvgw-apply`. After changing `TV_MAC`, `TV_IP`, `TV_NAME` or `URL_FILTER_RESOLVER`, re-run `install.sh`.

## Gotchas

- `eth0`, `10.10.10.1` and `10.10.10.0/24` are fixed in `tvgw-apply`, `tvgw.service`, `tvgw-pcap.service`, the dnsmasq template, the nginx files and the dispatcher.
- `install.sh` stops at an unusable identity setting (before anything is written), at a config nginx rejects, and at a failed `tvgw adguard apply`; nothing after the failing step has run, including the firewall re-apply. It exits non-zero when the final `tvgw verify` has a FAIL.
- The NetworkManager dispatcher and `tvgw-doh-update` both run `tvgw-apply`, so either can bring the TV back online after you stop `tvgw.service` by hand.
