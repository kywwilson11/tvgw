# Deployment assets

Everything that runs on the Pi outside the Python package: the installer, the settings template, the firewall script, systemd units, and the configs for nginx, dnsmasq, NetworkManager and logrotate. `install.sh` copies them into place.

From a workstation, `make deploy PI=<ssh-host>` rsyncs the working tree (uncommitted changes included) to `/opt/tvgw/src` with `--delete` and runs `sudo ./install.sh` there. The CI `hardware` job does the same on the Pi itself. See [../docs/operations.md](../docs/operations.md#deploying-and-rolling-back).

## Files

| Path | What it is | Installed as |
|---|---|---|
| `install.sh` | The idempotent installer, below. | run from `deploy/` |
| `tvgw.conf.example` | The settings template. | `/etc/tvgw/tvgw.conf`, first install only |
| [`nftables/`](nftables/README.md) | `tvgw-apply`, `block4.txt`, `doh-exclude.txt`. | `/usr/local/sbin/tvgw-apply`, `/etc/tvgw/` |
| [`systemd/`](systemd/README.md) | Seven services and four timers. | `/etc/systemd/system/` |
| [`bin/`](bin/README.md) | `tvgw-analyze`, `tvgw-prune`, `tvgw-doh-update`. | `/usr/local/sbin/` |
| [`nginx/`](nginx/README.md) | The URL filter and the TLS passthrough. | `/etc/nginx/conf.d/tvgw-gfts.conf`, `/etc/nginx/tvgw/stream.conf` |
| [`dnsmasq/`](dnsmasq/README.md) | The DHCP template. | `/etc/dnsmasq.d/tvgw.conf` |
| [`networkmanager/`](networkmanager/README.md) | Keep `eth0` up; re-apply on link changes. | `/etc/NetworkManager/conf.d/90-tvgw.conf`, `/etc/NetworkManager/dispatcher.d/90-tvgw` |
| [`logrotate/`](logrotate/README.md) | Weekly rotation of `/var/log/tvgw/*.log`. | `/etc/logrotate.d/tvgw` |

## What install.sh does, step by step

It runs with `set -euo pipefail`, so the first failing step stops it.

1. **Directories and modes.** `/etc/tvgw` (755). `/var/log/tvgw` as `2750 root:adm`, and every existing log there set to `640` group `adm`. `/var/lib/tvgw` as `2751 root:adm`: others may traverse it, because tshark runs as `nobody` and must reach the pcaps, but not list it. `/var/lib/tvgw/pcap` as `2750 root:nogroup`, existing pcaps `640` group `nogroup`. The store `640` group `adm`, the LG pairing key `600`.
2. **Settings.** Copies `tvgw.conf.example` to `/etc/tvgw/tvgw.conf` and `nftables/block4.txt` to `/etc/tvgw/block4.txt`, each only if missing. Copies `nftables/doh-exclude.txt` to `/etc/tvgw/` every time. Reads the settings and stops if `TV_MAC` is unset.
3. **The package.** Creates `/opt/tvgw-venv` if needed, upgrades pip, installs this checkout with the `lgwebos` extra plus `pytest` (the hardware suite runs on the Pi), and links `/usr/local/bin/tvgw`.
4. **Scripts.** Installs `tvgw-apply`, `tvgw-prune`, `tvgw-doh-update` and `tvgw-analyze` into `/usr/local/sbin`.
5. **Legacy cleanup.** Removes the retired text-report pipeline: `tvgw-extract`, the TSV files, the copied query log, `/var/lib/tvgw/archive`, the old brief files. Once, it moves pre-store reports into `reports/legacy/` and leaves a `.from-the-store` marker.
6. **Configs.** Writes the dnsmasq config from the template with `TV_MAC`, `TV_IP` and `TV_NAME`. Installs the NetworkManager config and dispatcher, the logrotate config, and every unit and timer.
7. **The TV interface.** Reloads NetworkManager's config. If there is no `tv-lan` connection, it turns off autoconnect on the stock "Wired connection 1" and creates `tv-lan`: `eth0`, `10.10.10.1/24`, never the default route, IPv6 disabled. Then `nmcli con up tv-lan`.
8. **nginx** (if installed). Writes both nginx files with `__RESOLVER__` replaced by `URL_FILTER_RESOLVER` (default `1.1.1.1`), adds the stream include to `/etc/nginx/nginx.conf` once, removes the default site, adds a drop-in (start after the network is online, restart on failure), then `nginx -t` and restart.
9. **AdGuard Home** (if `/opt/AdGuardHome/AdGuardHome.yaml` exists). Adds a drop-in that sets `WorkingDirectory=/opt/AdGuardHome`, then runs `tvgw adguard apply`. If the wizard has not been run yet, it prints a reminder instead.
10. **nftables.service** is masked unless it is enabled. Its `flush ruleset` would wipe the VPN client's rules and ours.
11. **The firewall.** Enables `tvgw.service`. If it is already active, runs `tvgw-apply` in place; otherwise starts it with a restart. A restart would run the stop path (forwarding off) and black out the TV for a moment.
12. **Services.** Restarts dnsmasq; enables and starts the flow log, the capture and the four timers; restarts `tvgw-pcap` or `tvgw-flowlog` only when its unit file changed (`enable --now` does not restart a running unit, and every restart is a sub-second hole in the evidence).
13. **Checks.** Runs `tvgw verify` and one `tvgw-analyze`. Failures there print a message but do not fail the install. Prints the installed version.

### What is idempotent

Run it as often as you like. It keeps `/etc/tvgw/tvgw.conf` and `/etc/tvgw/block4.txt`, creates `tv-lan` and the nginx include only once, moves legacy reports only once, and re-applies the firewall without a restart. `tvgw adguard apply` changes nothing, and does not restart AdGuard, when the config already matches.

What a re-run does disturb: nginx and dnsmasq restart, a capture unit restarts when its file changed (what ends or passes in that second is not recorded), `nmcli con up` re-activates `tv-lan`, and AdGuard restarts if its config changed. Local edits to `/etc/tvgw/doh-exclude.txt` are overwritten; make them in the repo.

## The settings file

`/etc/tvgw/tvgw.conf` is shell-style `KEY=VALUE`, read by the shell scripts with `.` and by Python with `config.parse_conf`. It is site-specific: never commit a real one.

| Key | Example value | Read by | Meaning |
|---|---|---|---|
| `TV_MAC` | placeholder | `install.sh` (dnsmasq), Python (AdGuard client) | The TV's wired MAC, pinned by DHCP. |
| `TV_IP` | `10.10.10.17` | `install.sh`, `tvgw-flowlog.service`, Python | The TV's fixed address. |
| `TV_NAME` | `tv` | `install.sh`, Python | DHCP host name and AdGuard client name. |
| `PROFILE` | `lg-webos` | Python, `tvgw-analyze` | Which bundled profile to use. `tvgw-analyze` reads the TV over the LAN API only for `lg-webos`. |
| `WAN_IF` | `wlan0` | `tvgw-apply`, `verify` | The uplink interface. |
| `WAN_GW` | the router's address | `tvgw-apply` | Default route in table 100. |
| `UPLINK` | `direct` | `tvgw-apply`, `verify` | `direct` (in use) or `vpn`. See [../docs/design-decisions.md](../docs/design-decisions.md#1-the-tv-uses-the-direct-uplink-not-the-vpn). |
| `BLOCK_QUIC` | `yes` | `tvgw-apply`, `verify` | Reject UDP 443 so server names stay visible. |
| `STRICT_PORTS` | `no` | `tvgw-apply` | `yes` rejects ports other than 80, 123 and 443. |
| `DOH_LIST_URL` | HaGeZi `doh.txt` | `tvgw-doh-update` | The DoH resolver address list. |
| `URL_FILTER_RESOLVER` | `1.1.1.1` | `install.sh` (nginx) | What nginx resolves the real file-service names with. Use the VPN provider's resolver if the VPN client blocks other DNS. |
| `DB_DAYS` | `365` | Python | Rows kept in the store. |
| `PCAP_DAYS`, `PCAP_MAX_GB` | `7`, `1.5` | `tvgw-prune` | Pcap retention. |

Python also reads `GW_IP`, `DNS_UPSTREAMS`, `DNS_BOOTSTRAP`, `STATE_DIR` and `DB_PATH`, which are not in the template. Leave `GW_IP` and `STATE_DIR` alone: the shell scripts and the nginx and dnsmasq files hardcode `10.10.10.1` and `/var/lib/tvgw`.

After changing a firewall setting, run `sudo tvgw-apply`. After changing `TV_MAC`, `TV_IP`, `TV_NAME` or `URL_FILTER_RESOLVER`, re-run `install.sh`.

## Gotchas

- `eth0`, `10.10.10.1` and `10.10.10.0/24` are fixed in `tvgw-apply`, `tvgw.service`, `tvgw-pcap.service`, the dnsmasq template, the nginx files and the dispatcher.
- `install.sh` stops at a failed `tvgw adguard apply`; nothing after it has run, including the firewall re-apply.
- The NetworkManager dispatcher and `tvgw-doh-update` both run `tvgw-apply`, so either can bring the TV back online after you stop `tvgw.service` by hand.
