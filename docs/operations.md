# Operations runbook

Day-to-day work on a running gateway. `$PI` means the Pi's SSH host alias. Commands marked `sudo` need root; the read-only `tvgw` queries (`brief`, `new-hosts`, `host`, `sql` and so on) run as any user in the `adm` group.

For what the brief sections mean, see the table in the [README](../README.md#the-daily-brief). For how the pieces fit, see [architecture.md](architecture.md). For what the store holds and who can read it, see [privacy-and-retention.md](privacy-and-retention.md).

The TV uses the direct uplink (`UPLINK=direct`): its traffic leaves through the home router, not the Pi's VPN. That is a recorded decision, not an oversight; see [design-decisions.md](design-decisions.md#1-the-tv-uses-the-direct-uplink-not-the-vpn) before changing it.

## Daily routine

1. `tvgw brief` (yesterday). Read the Coverage line first. `NOT ASSESSED` means that source was not read recently, so its sections are unknown.
2. Act on every `RED LINE:` (next section).
3. Skim New hosts, Blocked and still retried, and Allowed outside expected categories. Decide on each new name: block it (edit the profile), allow it (add to the expected categories or leave it), or watch it.
4. Once a week: `tvgw allowed 7d`, `tvgw top-upload 7d`, `tvgw retries 7d`.
5. `systemctl --failed` should list nothing. A failed `tvgw-verify.service` means the last `verify` run found a FAIL.

The hourly job writes the same report to `/var/lib/tvgw/reports/` (last 24 hours, each finished day, each finished week), all from the store. The store lags real time: a pcap is ingested only after tcpdump finishes the hour's file, and ingest runs at :20, so TLS names and plain-HTTP rows can arrive up to about two hours late. DNS, flows and firewall counters are fresher.

## Red lines

| Red line | What it means | What to do |
|---|---|---|
| `must-allow name blocked: NAME xN by RULE` | A name the TV needs came back blocked. The `@@||NAME^` exception should have won, so a rule or list changed, or the AdGuard config drifted. | `tvgw host NAME` shows the rule. `sudo tvgw adguard diff`; if it shows drift, `sudo tvgw adguard apply`. If the diff is empty, run `tvgw profile` (lint), then check the answer's CNAME chain: AdGuard matches rules against CNAME targets too, and several must-allow hosts CNAME into zones that also carry telemetry. Fix in the repo and deploy. |
| `clock host lookups blocked: N` | The TV's clock source was blocked. The clock will reset on the next boot or power loss and TLS fails everywhere after that. | Same as above, for the clock host. Then restart the TV so it asks again. |
| `TV was on but never looked up its clock host` | The TV had an Active reading that day and no lookup matched the profile's `clock_hosts`. | Check other days: `tvgw host us.lgtvsdp.com` (use your country's host). If lookups appear on other days, the TV may simply not have rebooted; watch it. If they never appear, the pattern does not match this firmware's host: check `tvgw profile --webos V` and `tvgw allowed 7d`, then fix `clock_hosts`. |
| `firewall checks failed X of Y times; last: ...` | `tvgw verify` failed during the day. | Run `sudo tvgw verify` now and see the table below. If it passes now, find when it failed: `tvgw sql "select datetime(t,'unixepoch','localtime'), failures from verify where ok=0 order by t desc limit 10"`. Treat every FAIL that follows a deploy as an outage (see [incidents.md](incidents.md)). |
| `ingest warnings: N` | A source failed during ingest. The lines are printed under Coverage as `ingest warning:`. | `sudo tvgw ingest` prints the warnings to stderr. `journalctl -u tvgw-analyze -n 100`. A failed pcap is retried on the next run. The same warning every hour is a real problem. |

Other lines worth a quick answer:

- **Unresolved flows**: a hardcoded IP, or DNS bypass. Look up the address, and if it is vendor telemetry, add it to `/etc/tvgw/block4.txt` and run `sudo tvgw-apply`. Existing connections survive; see "Established connections".
- **Firewall held: DNS forced to AdGuard > 0**: the TV tried another resolver and was redirected. Expected for some firmware. A rise after a firmware change is worth noting.
- **Unexpected ports**: see "STRICT_PORTS".
- **While off/asleep** with real traffic: instant-on or a wake timer is running; check the TV's settings with `tvgw tvstate 2d`.

## Deploying and rolling back

### Deploy

1. `make gate` locally.
2. `make deploy PI=$PI`. It rsyncs the working tree (including uncommitted changes) to `/opt/tvgw/src` with `--delete`, then runs `install.sh` over SSH.
3. Watch the end of `install.sh`: it runs `tvgw verify`. Any FAIL is an outage until proven otherwise.
4. `make hardware PI=$PI` for the full suite (`tvgw adguard diff` must be clean).

A push to `main` runs the same deploy and the hardware suite on the self-hosted runner, so a push is a deploy.

What `install.sh` does that you will notice (step by step in [../deploy/README.md](../deploy/README.md#what-installsh-does-step-by-step)):

- nginx restarts, so an app download in progress may fail and retry.
- If the AdGuard config changed, AdGuard is stopped for a few seconds and TV DNS fails briefly. If nothing changed, AdGuard is not touched.
- The firewall is re-applied in place when `tvgw.service` is already running. The TV does not lose its route; counters reset.
- dnsmasq and the flow log restart. Connections that end during those seconds are not logged.

`tvgw adguard apply` run by itself uses the profile inside the installed package, not the files in `/opt/tvgw/src`. To change policy, deploy; do not edit the repo copy on the Pi and run `apply`.

### Roll back the code

Check out the last good commit locally and run `make deploy PI=$PI` again. `rsync --delete` replaces the tree on the Pi and `install.sh` reinstalls the package, units and scripts, and re-applies AdGuard from the older profile.

### Roll back AdGuard alone

Every `tvgw adguard apply` that changes something writes `AdGuardHome.yaml.bak-YYYYMMDDHHMMSS` next to the config (default `/opt/AdGuardHome/`). Nothing prunes them. To restore one:

```sh
sudo systemctl stop AdGuardHome
sudo cp /opt/AdGuardHome/AdGuardHome.yaml.bak-<stamp> /opt/AdGuardHome/AdGuardHome.yaml
sudo systemctl start AdGuardHome
```

This leaves AdGuard out of line with the repo. `tvgw adguard diff` will report drift and the hardware suite will fail until the repo matches too. Roll the repo back as well, or apply again.

`apply` protects itself. It writes a candidate file, validates it with `AdGuardHome --check-config` before touching the service, and refuses a bad one ("nothing changed"). After the restart it waits up to 30 seconds for the resolver to answer. If it does not, `apply` stops AdGuard, puts the backup back, starts it again, and fails. Because `install.sh` runs with `set -e`, a failed `apply` stops the install at that step; nothing after it has run.

`tvgw adguard apply --dry-run` and `tvgw adguard diff` show the changes without making them.

### Roll back a firewall setting

Edit `/etc/tvgw/tvgw.conf` and run `sudo tvgw-apply`. The settings are `UPLINK`, `BLOCK_QUIC`, `STRICT_PORTS`, `WAN_IF`, `WAN_GW`. IP blocks live in `/etc/tvgw/block4.txt`; run `sudo tvgw-apply` after editing it too.

## Fail-closed behavior

`tvgw-apply` is built so the TV is never forwarded without the filter:

- It takes a lock, so two applies never interleave.
- It loads the whole ruleset in one atomic `nft` transaction (the old table is deleted and the new one created together).
- It enables forwarding only after that succeeds: `ip_forward`, and the per-interface switches for the TV interface and the uplink. The script stops on the first error, so a ruleset that fails to load never reaches the forwarding step.
- It writes `/run/tvgw/ruleset.applied`, the listing that `tvgw verify` later compares against.

`systemctl stop tvgw` (also the first half of a restart) turns forwarding off on the TV interface, removes the policy-routing rule, and deletes the `inet tvgw` and `netdev tvgw_l2` tables. A stopped service leaves the TV dark, not unfiltered. Stopping it also stops `tvgw-flowlog` and `tvgw-pcap`, which require it, so capture has a gap.

To reload the firewall, prefer `sudo tvgw-apply` to `systemctl restart tvgw`. The script is idempotent and atomic, so re-running it never opens a gap; a restart runs the stop path first and blacks the TV out for a moment. `install.sh` re-applies in place for the same reason. Chain-by-chain detail: [../deploy/nftables/README.md](../deploy/nftables/README.md).

Two cautions:

- While the service is stopped, the input chain is gone with the table. The Pi's own services that listen on all interfaces (SSH, for example) can be reached from the TV subnet.
- `tvgw-apply` is also run by the NetworkManager dispatcher when `wlan0`, `eth0` or `tun0` comes up or changes DHCP, and by `tvgw-doh-update` daily. Either can bring the TV back online after you stopped the service.

Each apply resets the firewall counters. The brief sums positive steps between 10-minute snapshots, so a re-apply costs at most one interval of packets.

## What `tvgw verify` checks

`sudo tvgw verify` prints one line per check and exits 1 if any FAIL. `--record` (used by the timer) also stores the verdict and a snapshot of every firewall counter.

| Check | What it proves | What a FAIL means |
|---|---|---|
| `ruleset` | Table `inet tvgw` is loaded and contains the key rules: DNS DNAT to the gateway, DoT/DoQ reject, the DoH set, the home-LAN set, masquerade, invalid-state drop, and the QUIC reject when `BLOCK_QUIC=yes`. | The table is missing (service stopped or table deleted) or lacks a rule. The detail names what is missing. Run `sudo tvgw-apply`. |
| `ruleset_unchanged` | The live ruleset equals what `tvgw-apply` last wrote. Only runs if `/run/tvgw/ruleset.applied` exists. | Someone changed the rules by hand, or something else rewrote them. Re-apply. |
| `forwarding` | The global `net.ipv4.ip_forward` is 1, and so is the per-interface `forwarding` switch of the TV interface and of the uplink (`WAN_IF`, or `tun0` for `UPLINK=vpn`). | Forwarding is off and the TV is offline: the service is stopped, never applied, or stopped and restarted the way that once left the TV dark ([incidents.md](incidents.md)). The detail names the switch that is off. |
| `ipv6_off` | `disable_ipv6` is 1 on the TV interface. | IPv6 could reach the TV. Re-apply. |
| `tv_route` | A packet from the TV's address entering on the TV interface routes out the chosen uplink (`WAN_IF`, or `tun0` for `UPLINK=vpn`). | `via nothing` means no route: the TV is dark (see the incident log). `via` another device means traffic would leave the wrong way. Check the uplink is up and re-apply. |
| `policy_rule` | Direct mode only: `ip rule` priority 60 sends the TV subnet to table 100. | The TV may take the VPN's routes. Re-apply; check the uplink is up (its table 100 route vanishes when it drops). |
| `vpn_dnat_idle` | The VPN client's split-DNS DNAT chain (a chain with `fwdsplitdns` in its name) has counted no packets. Passes with a note if no such chain exists. | TV DNS reached the VPN's redirect before ours: a DNS bypass of AdGuard. |
| `doh4_loaded` | The DoH block set has at least 50 elements. | The set is empty or short. Run `sudo tvgw-doh-update`; read `journalctl -u tvgw-doh-update`. |
| `resolver_rewrite` | Each URL-filter host resolves to exactly the gateway address. | The `$dnsrewrite` rules are missing or AdGuard is down. The URL filter is bypassed or the file service is unreachable. `sudo tvgw adguard diff`. |
| `resolver_must_allow` | Each must-allow host resolves and is not `0.0.0.0`. | A must-allow name is blocked or the resolver or its upstream is down. Detail lists `no answer` or `blocked` per host. |
| `services` | `AdGuardHome`, `dnsmasq`, `nginx`, `tvgw-pcap` and `tvgw-flowlog` are active. | The detail lists what is down. `systemctl status` and `journalctl -u` for each. |

## Timers and what runs when

| Unit | Schedule | What it does |
|---|---|---|
| `tvgw.service` | At boot, after NetworkManager; stays "active" | Runs `tvgw-apply`. Stop turns the TV dark. |
| `tvgw-flowlog.service` | Always | `conntrack -E -e DESTROY` for the TV, appended to `/var/log/tvgw/flows.log`. |
| `tvgw-pcap.service` | Always | tcpdump on the TV interface, one file per hour in `/var/lib/tvgw/pcap/`. |
| `tvgw-verify.timer` | 3 min after boot, then every 10 min | `tvgw verify --record`. |
| `tvgw-analyze.timer` | Hourly at :20 (catches up after downtime) | `tvgw-analyze`: read the TV's settings (`tvgw tvcheck`, LG only), run `tvgw ingest`, then write `reports/latest`, one `reports/daily/<day>` per finished day and one `reports/weekly/<week>` per finished ISO week from the store. Times out after 45 minutes. |
| `tvgw-prune.timer` | Hourly | `tvgw-prune`: delete pcaps older than `PCAP_DAYS`, then oldest first until under `PCAP_MAX_GB`. |
| `tvgw-doh-update.timer` | Daily, up to 1 hour random delay | Fetch `DOH_LIST_URL`, drop CDN ranges in `doh-exclude.txt`, refuse a list under 50 entries, write `/var/lib/tvgw/doh4.txt`, run `tvgw-apply`. |
| NetworkManager dispatcher | Interface up or DHCP change on `wlan0`, `eth0`, `tun0` | Runs `tvgw-apply` (routes in table 100 vanish when the uplink drops). |

`systemctl list-timers 'tvgw-*'` shows the next and last runs.

## Logs and paths

| Path | Contents |
|---|---|
| `/etc/tvgw/tvgw.conf` | Settings: TV identity, uplink, `STRICT_PORTS`, retention. Site-specific; never commit. |
| `/etc/tvgw/block4.txt` | Manual IP blocks. Apply with `sudo tvgw-apply`. |
| `/etc/tvgw/doh-exclude.txt` | CIDRs never added to the DoH block set. Overwritten by every install; edit `deploy/nftables/doh-exclude.txt` instead. |
| `/var/lib/tvgw/tvgw.db` | The store (`640 root:adm`). Tables: [architecture.md](architecture.md#the-data-model). |
| `/var/lib/tvgw/pcap/` | Hourly captures, `tv-YYYYMMDDTHHMMSSZ.pcap` (named in UTC, so no two files can share a name). The directory is `2750 root:nogroup` and each file `640`, so only root and the unprivileged tshark can read them. |
| `/var/lib/tvgw/reports/` | `latest.txt/.json` (last 24 h), `daily/`, `weekly/`, all written from the store; `legacy/` holds reports from before the store existed. |
| `/var/lib/tvgw/doh4.txt` | The current DoH block list. |
| `/var/lib/tvgw/tvcheck.txt`, `tvcheck-history.log` | Last LAN-API reading; one line per hour of power state and app. |
| `/var/lib/tvgw/lgtv-keys.sqlite` | The LG pairing key (mode 600). It can control the TV. |
| `/var/log/tvgw/` | `flows.log`, `gfts.log` (URL filter), `gfts-tls.log`. `2750 root:adm`, logs `640`. Rotated weekly, 12 kept. |
| `/run/tvgw/ruleset.applied` | What `tvgw-apply` last loaded. Gone after reboot until the next apply. |
| `/opt/AdGuardHome/` | `AdGuardHome.yaml`, its `.bak-*` backups, `data/querylog.json`. |
| `/opt/tvgw-venv/`, `/usr/local/bin/tvgw`, `/usr/local/sbin/tvgw-*` | The installed package and scripts. |
| `/etc/dnsmasq.d/tvgw.conf`, `/etc/nginx/conf.d/tvgw-gfts.conf`, `/etc/nginx/tvgw/stream.conf` | Generated or installed by `install.sh`. |

Journals:

```sh
journalctl -u tvgw-analyze -n 50           # hourly ingest
journalctl -u tvgw-verify -n 20            # verify runs
journalctl -u tvgw -u AdGuardHome -u nginx # firewall apply, resolver, URL filter
journalctl -k -g tvgw-oddport              # TV traffic to unexpected ports
journalctl -k -g 'tvgw-proto|tvgw-lg8080'  # blocked tunnel protocols; LG firmware fallback
```

## The AdGuard web UI

AdGuard's UI is bound to `127.0.0.1:3000` on the Pi. Reach it with a port-forward:

```sh
ssh -L 3000:127.0.0.1:3000 $PI
# then open http://127.0.0.1:3000
```

Use it to browse the query log and statistics. Do not change filters, custom rules, upstreams or settings there. `tvgw adguard apply` owns those keys and will overwrite your change; until then `tvgw adguard diff` reports drift and the hardware suite fails. Make the change in the profile instead.

## Common breakages

| Symptom | Likely cause | Check and fix |
|---|---|---|
| TV clock is wrong or reset; apps show certificate or TLS errors | The vendor's SDP host is blocked | Red line `clock host lookups blocked`. `tvgw host us.lgtvsdp.com` (your country). Find the rule, fix it in the profile, deploy, restart the TV. |
| Content Store is blank or fails (error 202) | `us.lgrecommends.lgappstv.com` blocked, or the GFTS names unreachable | `tvgw host us.lgrecommends.lgappstv.com` must show allowed. `tvgw gfts 1d` for 403s. `systemctl status nginx`. |
| An app will not install or update | The install needs a `biz_code` the URL filter refuses, or nginx is down | `tvgw gfts 1d`. Only the codes in the regex get 403 (`PREMIUM`, `CDP`, `LGSHOPPING`, `MAS`, `IBS`); a new code passes. A 403 that lines up with the failed install is the cause. To allow a code, change the regex in both `deploy/nginx/tvgw-gfts.conf` and the profile's `block_regex`, then deploy. If nginx is down, `sudo systemctl restart nginx`. |
| TV says "no internet" or "network not connected" | `lgtvonline.lge.com` blocked, or the resolver is down | `sudo tvgw verify`: `resolver_must_allow` or `services` will FAIL. `tvgw host lgtvonline.lge.com`. |
| Everything is dead, the TV has no network | Forwarding off, no route, firewall not applied, or uplink down | `sudo tvgw verify`. Then `cat /proc/sys/net/ipv4/conf/eth0/forwarding` (must be 1), `ip route get 1.1.1.1 from <TV_IP> iif eth0` (must name the uplink device), and `systemctl status tvgw AdGuardHome`. `sudo tvgw-apply` repairs forwarding and routing. Confirm the uplink is connected. |
| One app broke after a policy change | A new block or a changed list | `tvgw rules`, the brief's Rule changes, and `tvgw host NAME` for names the app uses. Revert the rule in the profile and deploy. |

## STRICT_PORTS

The TV has only ever used TCP 80 and 443 and DNS. With `STRICT_PORTS=no` (default), other ports are logged (6 per minute) and counted, but allowed. With `yes`, they are rejected with `admin-prohibited` so apps fail fast. NTP (123) is allowed either way. LG's firmware-update fallback (the fixed address on TCP 8080 in `tvgw-apply`) is accepted and logged separately in both modes.

The owner's rule is two clean weeks ([design-decisions.md](design-decisions.md#17-strict_ports-stays-off-until-two-clean-weeks)); the comment in the config template still says "a week or so". Before changing it:

- Fourteen consecutive briefs with `Unexpected ports: none`, or only entries you have looked up and decided to cut.
- Those days include a cold boot, each app the household uses, and no pending firmware update (a new firmware brings new endpoints; see the brief's Firmware section).
- The `odd ports` counter in `Firewall held` is zero or explained.

To flip: set `STRICT_PORTS=yes` in `/etc/tvgw/tvgw.conf`, run `sudo tvgw-apply`, then `sudo tvgw verify`. Use the TV for a few hours across the apps. The `odd ports` counter now counts rejected packets. To revert, set it back to `no` and apply again.

## Established connections

The forward chain accepts established and related traffic before it reaches the TV rules. New blocks (an entry in `block4.txt`, a refreshed DoH set) therefore stop only new connections. The TV's idle TCP connections are kept for up to about two hours. To cut one now:

```sh
sudo conntrack -D -d <ip>
```

The TV opens a new connection and meets the new rule. The flushed connection shows up in the flow log as ended.

## After unblocking something

Blocked answers are given a 60-second TTL (`blocked_response_ttl`, set by `tvgw adguard apply`), and some LG web apps hold sockets for about a minute. After you unblock a name, wait about five minutes before you decide whether it fixed anything. Retry before then and you may be testing the old answer.
