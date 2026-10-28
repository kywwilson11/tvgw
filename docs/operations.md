# Operations runbook

Day-to-day work on a running gateway. `$PI` means the Pi's SSH host alias. Commands marked `sudo` need root; the read-only `tvgw` queries (`brief`, `new-hosts`, `host`, `sql` and so on) run as any user in the `adm` group.

For what the brief sections mean, see the table in the [README](../README.md#the-daily-brief). For how the pieces fit, see [architecture.md](architecture.md). For what the store holds and who can read it, see [privacy-and-retention.md](privacy-and-retention.md).

The TV uses the direct uplink (`UPLINK=direct`): its traffic leaves through the home router, not the Pi's VPN. That is a recorded decision, not an oversight; see [design-decisions.md](design-decisions.md#1-the-tv-uses-the-direct-uplink-not-the-vpn) before changing it.

## Daily routine

1. `tvgw brief` (yesterday). Read the Coverage line first. `NOT ASSESSED` means that source was not read recently, so its sections are unknown.
2. Act on every `RED LINE:` (next section).
3. Skim New hosts, Blocked and still retried, and Allowed outside expected categories. Decide on each new name: block it (edit the profile), allow it (add to the expected categories or leave it), or watch it.
4. Once a week: `tvgw allowed 7d`, `tvgw top-upload 7d`, `tvgw retries 7d`.
5. `systemctl --failed` should list nothing. A failed `tvgw-verify.service` means the last `verify` run found a FAIL; a failed `tvgw-prune.service` means retention kept a file it should have deleted (not ingested yet), could not tell which file tcpdump is writing, or ran out of ingested files to delete: `journalctl -u tvgw-prune -n 5` says which.

The hourly job writes the same report to `/var/lib/tvgw/reports/` (last 24 hours, each finished day, each finished week), all from the store. The store lags real time: tcpdump rotates a pcap 3600 s after the file opened and only when the next packet arrives, ingest runs at :20, and conntrack reports an idle connection 2 h 04 min after its last packet, so TLS names, plain-HTTP rows and the last flows of a day can arrive up to about two hours late. Finished days and weeks are therefore written from 03:20, not 00:20. DNS and firewall counters are fresher.

## Red lines

| Red line | What it means | What to do |
|---|---|---|
| `must-allow name blocked: NAME xN by RULE` | A name the TV needs came back blocked. The `@@||NAME^$important` exception should have won, so a rule or list changed, or the AdGuard config drifted. | `tvgw host NAME` shows the rule. `sudo tvgw adguard diff`; if it shows drift, `sudo tvgw adguard apply`. If the diff is empty, run `tvgw profile` (lint), then check the answer's CNAME chain: AdGuard matches rules against CNAME targets too, and several must-allow hosts CNAME into zones that also carry telemetry. Fix in the repo and deploy. |
| `Live Plus (ACR) is on on the TV (since ...)` | The TV's own setting for ACR, read hourly over its LAN API, is not off. Someone turned it on, or a firmware update reset it. This is the threat the project exists for. | Turn it off on the TV: General > Additional Settings > Live Plus. `tvgw tvstate 2d` shows when it flipped; the TV settings section of the brief lists the reading. The line stays until a reading says `off`. |
| `clock host lookups blocked: N` | The TV's clock source was blocked. The clock will reset on the next boot or power loss and TLS fails everywhere after that. | Same as above, for the clock host. Then restart the TV so it asks again. |
| `TV was on but never looked up its clock host` | The TV had an Active reading that day and no lookup matched the profile's `clock_hosts`. | Check other days: `tvgw host us.lgtvsdp.com` (use your country's host). If lookups appear on other days, the TV may simply not have rebooted; watch it. If they never appear, the pattern does not match this firmware's host: check `tvgw profile --webos V` and `tvgw allowed 7d`, then fix `clock_hosts`. |
| `firewall checks failed X of Y times; last: ...` | `tvgw verify` failed during the day. | Run `sudo tvgw verify` now and see the table below. If it passes now, find when it failed: `tvgw sql "select datetime(t,'unixepoch','localtime'), failures from verify where ok=0 order by t desc limit 10"`. Treat every FAIL that follows a deploy as an outage (see [incidents.md](incidents.md)). |
| (not a red line) `DNS-gated egress (count-only): N new connections to addresses no lookup had returned` | The gate (design decision 18) counted connections to addresses outside the day's lookups. Read the samples: an address with a TLS name was known by a lookup the gate had forgotten (a reboot, or a day-old answer); one with `(none)` is a hardcoded server or a resolver bypass. Look it up (`sudo tvgw host`, `whois`), and if it is a tracker add its address to `block4.txt`. After two clean weeks the count is the evidence for an enforce mode. |
| `ACR-like cadence: NAME every 15 s, about N B per connection, K times` | A connection pattern like LG's ACR client (small uploads every 10 to 20 s) under a name that is not the TV doing its job. Confirm Live Plus is off (`sudo tvgw tvcheck`), look the name up (`sudo tvgw host NAME`), and block it if it is a tracker. A streaming app's own heartbeat is listed in Periodic connections but is not a red line. |
| `firewall checks ran N of ~M times (is tvgw-verify.timer alive?)` | Fewer than half the 10-minute `verify` runs the window owed were recorded, counted from the first run the store ever saw. A dead timer looks like a clean day otherwise. | `systemctl list-timers 'tvgw-*'` must show `tvgw-verify.timer` with a next run; `journalctl -u tvgw-verify -n 20`. If the timer is fine, the runs could not reach the store: look for `could not record the run` in that journal. |
| `TV was on but no lookups were recorded (is the AdGuard query log being read?)` | The TV had an Active reading and the window holds not one DNS row. The TV cannot be on without resolving something, so the query log is not being written or not being read. | `tvgw brief` Coverage: is `dns` `NOT ASSESSED`? `journalctl -u tvgw-analyze -n 50` for the ingest step; `ls -l /opt/AdGuardHome/data/querylog.json` and AdGuard's query-log setting; `systemctl status AdGuardHome`. |
| `TV was on but no connections were recorded (is the flow log being read?)` | As above for conntrack: an Active TV and not one flow row. | `systemctl status tvgw-flowlog`; `tail /var/log/tvgw/flows.log` should be growing; Coverage says whether `flows` was read. `tvgw tvstate 2d` to see when the TV was on. |
| `ingest warnings: N` | A source failed during ingest. The lines are printed under Coverage as `ingest warning:`. | `sudo tvgw ingest` prints the warnings to stderr. `journalctl -u tvgw-analyze -n 100`. A pcap tshark could not read is retried hourly for a day (one warning per run covers every failing file), then recorded as unreadable in `pcaps_done.error` and left alone; a pcap with many connection attempts to :443 and no hello says so. The same warning every hour is a real problem. A pcap recorded as unreadable stays so; after fixing the cause, `sudo sqlite3 /var/lib/tvgw/tvgw.db "DELETE FROM pcaps_done WHERE error IS NOT NULL"` (or delete the file) makes the next run retry it. `SOURCE: /path is missing` means that input does not exist (a capture or log unit is down, or a path in `tvgw.conf` is wrong); the source is `NOT ASSESSED` until it is back. `pcaps: N file(s) deferred to the next run (time budget)` is a backlog being worked off, 20 minutes of tshark an hour, and clears by itself. The brief lists the warnings of the runs that fed its window, so yesterday's brief does not carry this morning's. |

Other lines worth a quick answer:

- **Unresolved flows**: a hardcoded IP, or DNS bypass. Look up the address, and if it is vendor telemetry, add it to `/etc/tvgw/block4.txt` and run `sudo tvgw-apply`. Existing connections survive; see "Established connections".
- **Firewall held: DNS forced to AdGuard > 0**: the TV tried another resolver and was redirected. Expected for some firmware. A rise after a firmware change is worth noting.
- **Unexpected ports**: see "STRICT_PORTS".
- **While off/asleep** with real traffic: instant-on or a wake timer is running; check the TV's settings with `tvgw tvstate 2d`.
- **Encrypted ClientHello seen.** A TLS hello from the TV carried the ECH extension (the brief lists the outer names). The server names of those connections are hidden from the capture from now on; keep HTTPS/SVCB records stripped (`strip_qtypes`) and watch whether the count grows.

## Deploying and rolling back

### Deploy

1. `make gate` locally.
2. `make deploy PI=$PI`. It rsyncs the working tree (including uncommitted changes) to `/opt/tvgw/src` with `--delete`, then runs `install.sh` over SSH.
3. `install.sh` ends by running `tvgw verify` and exits with its status, so a FAIL fails the deploy. Any FAIL is an outage until proven otherwise.
4. `make hardware PI=$PI` for the full suite (`tvgw adguard diff` must be clean).

A push to `main` runs the same deploy and the hardware suite on the self-hosted runner, so a push is a deploy; a push that changes only Markdown runs nothing. A deploy in progress is never cancelled by a newer push (it queues behind it).

What `install.sh` does that you will notice (step by step in [../deploy/README.md](../deploy/README.md#what-installsh-does-step-by-step)):

- nginx reloads; downloads in progress continue.
- If the AdGuard config changed, AdGuard is stopped for a few seconds and TV DNS fails briefly. If nothing changed, AdGuard is not touched.
- The firewall is re-applied in place when `tvgw.service` is already running. The TV does not lose its route; counters reset.
- dnsmasq restarts. A capture unit (`tvgw-flowlog`, `tvgw-pcap`) restarts only when its unit file changed; connections that end in that second are not logged and the hour's pcap is split in two. `tv-lan` is re-activated only when it is down.

`tvgw adguard apply` run by itself uses the profile inside the installed package, not the files in `/opt/tvgw/src`. To change policy, deploy; do not edit the repo copy on the Pi and run `apply`.

### Roll back the code

Check out the last good commit locally and run `make deploy PI=$PI` again. `rsync --delete` replaces the tree on the Pi and `install.sh` reinstalls the package, units and scripts, and re-applies AdGuard from the older profile.

### Roll back AdGuard alone

Every `tvgw adguard apply` that changes something writes `AdGuardHome.yaml.bak-<UTC stamp>Z-<pid>` (for example `AdGuardHome.yaml.bak-20261027151500Z-4242`) next to the config (default `/opt/AdGuardHome/`), copied before AdGuard is stopped and never written over an earlier backup. Nothing prunes them. To restore one:

```sh
sudo systemctl stop AdGuardHome
sudo cp /opt/AdGuardHome/AdGuardHome.yaml.bak-<stamp> /opt/AdGuardHome/AdGuardHome.yaml
sudo systemctl start AdGuardHome
```

This leaves AdGuard out of line with the repo. `tvgw adguard diff` will report drift and the hardware suite will fail until the repo matches too. Roll the repo back as well, or apply again.

`apply` protects itself. One apply runs at a time (a lock beside the file; a second one fails with `another tvgw adguard apply is running`). It refuses an empty or truncated config rather than complete one from the template. It writes a candidate file, validates it with `AdGuardHome --check-config` before touching the service, and refuses a bad one with AdGuard's own reason ("nothing changed"). It copies the live file to the backup before stopping AdGuard, holds off SIGTERM, SIGHUP and SIGINT while the service is down, and moves the candidate into place atomically. After the restart it waits up to 30 seconds for the resolver to resolve the first must-allow name (NOERROR or NXDOMAIN); SERVFAIL counts as not ready, so a deploy while the DoH upstreams are unreachable rolls back and fails loudly instead of leaving the TV without names. If the resolver does not come back, or anything fails from the stop onwards, `apply` stops AdGuard, puts the backup back the same atomic way (a whole file or nothing, never a partial copy), starts it again, and fails naming the backup. Because `install.sh` runs with `set -e`, a failed `apply` stops the install at that step; nothing after it has run.

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
- `tvgw-apply` is also run by the NetworkManager dispatcher when `WAN_IF`, `eth0` or `tun0` comes up or changes DHCP, and by `tvgw-doh-update` daily. Either can bring the TV back online after you stopped the service.

Each apply resets the firewall counters. The brief sums positive steps between 10-minute snapshots, so a re-apply costs at most one interval of packets.

## What `tvgw verify` checks

`sudo tvgw verify` prints one line per check and exits 1 if any FAIL. `--record` (used by the timer) also stores the verdict and a snapshot of every firewall counter.

| Check | What it proves | What a FAIL means |
|---|---|---|
| `ruleset` | Table `inet tvgw` is loaded and contains the key rules: DNS DNAT to the gateway, DoT/DoQ reject, the DoH set, the home-LAN set, masquerade, invalid-state drop, and the QUIC reject when `BLOCK_QUIC=yes`. | The table is missing (service stopped or table deleted) or lacks a rule. The detail names what is missing. Run `sudo tvgw-apply`. |
| `ruleset_unchanged` | The live ruleset equals what `tvgw-apply` last wrote to `/run/tvgw/ruleset.applied`. Runs whenever the table is loaded. | Someone changed the rules by hand, or something else rewrote them. `no baseline` means the table is loaded but the listing is missing, so nothing can vouch for the rules. Re-apply. |
| `applied_current` | None of `tvgw-apply`'s inputs (`/etc/tvgw/tvgw.conf`, `block4.txt`, `doh4.txt`) was modified more than two minutes after the last successful apply. Runs whenever the baseline exists. | An input changed and no apply has succeeded since: a `block4.txt` line nft rejects leaves the old set loaded and this is the only check that sees it, or someone edited the conf and did not re-apply. Run `sudo tvgw-apply` and read its error. The two-minute grace covers `tvgw-doh-update`'s write-then-apply and an edit in progress. |
| `forwarding` | The global `net.ipv4.ip_forward` is 1, and so is the per-interface `forwarding` switch of the TV interface and of the uplink (`WAN_IF`, or `tun0` for `UPLINK=vpn`). | Forwarding is off and the TV is offline: the service is stopped, never applied, or stopped and restarted the way that once left the TV dark ([incidents.md](incidents.md)). The detail names the switch that is off. |
| `ipv6_off` | `disable_ipv6` is 1 on the TV interface. | IPv6 could reach the TV. Re-apply. |
| `tv_route` | A packet from the TV's address entering on the TV interface routes out the chosen uplink (`WAN_IF`, or `tun0` for `UPLINK=vpn`). | `via nothing` means no route: the TV is dark (see the incident log). `via` another device means traffic would leave the wrong way. Check the uplink is up and re-apply. |
| `policy_rule` | Direct mode only: `ip rule` priority 60 sends the TV subnet to table 100. | The TV may take the VPN's routes. Re-apply; check the uplink is up (its table 100 route vanishes when it drops). |
| `vpn_dnat_idle` | The VPN client's split-DNS DNAT chain (a chain with `fwdsplitdns` in its name) has counted no packets. Passes with a note if no such chain exists. | TV DNS reached the VPN's redirect before ours: a DNS bypass of AdGuard. |
| `doh4_loaded` | The DoH block set covers at least 50 addresses (nft merges neighbours into prefixes and ranges, so elements are not addresses). | The set is empty or short. Run `sudo tvgw-doh-update`; read `journalctl -u tvgw-doh-update`. |
| `doh4_fresh` | `/var/lib/tvgw/doh4.txt` was written less than eight days ago. | The daily updater has not replaced the list for over a week (or the file is missing), so the set is whatever it was: `journalctl -u tvgw-doh-update` says why (download refused, under 50 entries, exclude file missing); `systemctl list-timers tvgw-doh-update.timer`. |
| `resolver_rewrite` | Each URL-filter host resolves to exactly the gateway address. | The `$dnsrewrite` rules are missing or AdGuard is down. The URL filter is bypassed or the file service is unreachable. `sudo tvgw adguard diff`. |
| `resolver_must_allow` | Each must-allow host resolves to at least one address that is not `0.0.0.0`. | A must-allow name is blocked or the resolver or its upstream is down. Detail lists `no answer` (the resolver did not reply), `blocked` (`0.0.0.0`) or `empty answer` (NXDOMAIN, REFUSED, SERVFAIL or no A record: AdGuard's other blocking modes, or an upstream outage) per host. |
| `adguard_version` | AdGuard Home reports at least v0.107.73, the release that fixed an authentication bypass over h2c. The version is recorded in the store and shown in the brief's Coverage line. | The resolver on the TV segment has a known hole: update AdGuard Home (its own `-u` updater or the install script). `could not read it` means the binary is not where `ADGUARD_YAML` points. |
| `services` | `AdGuardHome`, `dnsmasq`, `nginx`, `tvgw`, `tvgw-pcap`, `tvgw-flowlog` and the seven timers (`tvgw-analyze`, `tvgw-prune`, `tvgw-doh-update`, `tvgw-verify`, `tvgw-backup`, `tvgw-analyst`, `tvgw-analyst-weekly`) are active. | The detail lists what is down. `systemctl status` and `journalctl -u` for each; a timer that is not active never fires. |

## Timers and what runs when

| Unit | Schedule | What it does |
|---|---|---|
| `tvgw.service` | At boot, after NetworkManager; stays "active" | Runs `tvgw-apply`. Stop turns the TV dark. |
| `tvgw-flowlog.service` | Always | `conntrack -E -e DESTROY` for the TV, appended to `/var/log/tvgw/flows.log`. |
| `tvgw-pcap.service` | Always | tcpdump on the TV interface, one file per hour in `/var/lib/tvgw/pcap/`. |
| `tvgw-dnsgate.service` | Always (with `DNSGATE=count`) | tcpdump on the resolver's answers to the TV; every IPv4 address goes into `inet tvgw_gate resolved4` for a day. |
| `tvgw-verify.timer` | 3 min after boot, then every 10 min | `tvgw verify --record`. |
| `tvgw-analyze.timer` | Hourly at :20 (catches up after downtime) | `tvgw-analyze`: read the TV's settings (`tvgw tvcheck`, LG only), run `tvgw ingest`, then write `reports/latest`, one `reports/daily/<day>` per finished day and one `reports/weekly/<week>` per finished ISO week from the store. Times out after 45 minutes. |
| `tvgw-backup.timer` | Daily at 03:40 (catches up after downtime) | `tvgw backup`: `VACUUM INTO` a fresh copy in `/var/lib/tvgw/backup/`, `quick_check` it, keep the newest seven. `make backup` pulls the copies to your machine. |
| `tvgw-analyst.timer` | Daily at 03:50 (with the key file; catches up after downtime) | `tvgw analyst`: yesterday's minimized evidence pack to Claude, proposals to `reports/proposals/`; with `ANALYST_APPLY=auto`, blocks that pass the gates, the second model and the live canary are applied on probation (design decision 20). Not asked on a day with nothing new. |
| `tvgw-analyst-weekly.timer` | Monday 04:10 (the week that just ended; `ANALYST_WEEKLY_SCHEDULE`) | `tvgw analyst --weekly`: the whole ISO week to the weekly model (`claude-fable-5-1` by default), proposals to `reports/proposals/<YYYY-Www>.md`. |
| `tvgw-autoblock.timer` | Hourly at :25 (catches up after downtime) | `tvgw autoblock check`: re-judges every rule the gateway added on its own against the fresh store; a revert takes the rule out of the machine's file and AdGuard. A rule the owner removed from the file is recorded as reverted. Quick when nothing is on probation. |
| `tvgw-prune.timer` | Hourly | `tvgw prune-pcaps`: delete pcaps ingest has read once older than `PCAP_DAYS`, then the oldest read ones while over `PCAP_MAX_GB` or under 1 GB free; never the live file, never an un-read file before twice `PCAP_DAYS`. Fails (`systemctl --failed`) when it had to keep or warn. |
| `tvgw-doh-update.timer` | Daily, up to 1 hour random delay | Fetch `DOH_LIST_URL`, drop CDN ranges in `doh-exclude.txt`, refuse a list under 50 entries, write `/var/lib/tvgw/doh4.txt`, run `tvgw-apply`. |
| NetworkManager dispatcher | Interface up or DHCP change on `WAN_IF` (from `tvgw.conf`), `eth0`, `tun0` | Runs `tvgw-apply` (routes in table 100 vanish when the uplink drops). |

`systemctl list-timers 'tvgw-*'` shows the next and last runs.

## Logs and paths

| Path | Contents |
|---|---|
| `/etc/tvgw/tvgw.conf` | Settings: TV identity, uplink, `STRICT_PORTS`, retention. `640 root:adm`; site-specific; never commit. |
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

## Upgrading the OS in place

The reference gateway went from Raspberry Pi OS bookworm (Debian 12) to trixie (Debian 13) in place on 2026-10-27, keeping every local configuration file. Raspberry Pi recommends a fresh image; in place works, with three things to know.

1. **Run it detached from your SSH session** (`systemd-run --unit=os-upgrade -p StandardOutput=append:/var/log/os-upgrade.log ... /root/upgrade.sh`, or inside `tmux`). NetworkManager and sshd restart during the run; a dropped session must not take apt with it.
2. **`needrestart` restarts the runner.** If it is installed, its apt hook restarts every service whose libraries changed at the end of each apt run, including the detached runner itself, which then starts over from its first step. Exclude the unit first: `/etc/needrestart/conf.d/90-upgrade.conf` containing `$nrconf{override_rc}{qr(^os-upgrade\.service$)} = 0;`.
3. **Pi desktop packages collide.** Bookworm's `lxplug-*` and `pi-greeter` ship files that trixie's `lxpanel` and `raspberrypi-ui-mods` own without a Replaces relation, so `apt full-upgrade` stops on "trying to overwrite". Finish with `dpkg --configure -a`, then `apt-get -f install` and `apt-get full-upgrade` with `-o Dpkg::Options::=--force-overwrite`. A gateway without the desktop will not see this.

The order that worked: `apt full-upgrade` on the current release; replace `bookworm` with `trixie` in `/etc/apt/sources.list` and `/etc/apt/sources.list.d/raspi.list`; `apt update`; simulate with `apt-get -s full-upgrade` and stop if any of network-manager, openssh-server, nftables, dnsmasq, nginx, python3, python3-venv, tcpdump, tshark or conntrack is in the removal list; `apt upgrade --without-new-pkgs`; `apt full-upgrade`; `apt autoremove --purge`; `dpkg --audit`; reboot. Use `DEBIAN_FRONTEND=noninteractive` with `--force-confdef --force-confold` so the gateway's edited files (`/etc/default/dnsmasq`, sshd, nginx) stay as they are.

After the reboot the Python major version has changed and the virtualenv is stale. `rm -rf /opt/tvgw-venv`, then `cd /opt/tvgw/src/deploy && sudo ./install.sh` (it creates the venv on the new interpreter and ends with `tvgw verify`), then `make hardware`. The TV is dark from the reboot until `install.sh` finishes, about three minutes. Check `systemctl --failed`, the VPN client and the CI runner afterwards. tshark went from 4.0 to 4.4 and the parser tests passed unchanged.

## The daily analyst (proposals; autonomous blocks with `ANALYST_APPLY=auto`)

`tvgw-analyst.timer` runs at 03:50 when `/etc/tvgw/claude.key` exists (root, mode 600, the API key on one line). It reads yesterday's evidence pack and writes `/var/lib/tvgw/reports/proposals/<day>.md` (for you) and `.json` (the record: model, tokens, cost, every proposal with its verdict). `sudo tvgw analyst --show` prints the newest.

Each proposal is `block`, `allow`, `unblock`, `watch` or `question`, with one AdGuard rule where one applies, the reason, the pack fields it rests on, the risk to the TV's working, and a rollback. `Vetted: ok` means the rule passes the same lint the profile must pass; `Vetted: refused: ...` says why it does not (a must-allow host, an apex, already in place, not a rule). To adopt a proposal, add the rule to `src/tvgw/profiles/<profile>.rules` with a dated comment, run `make gate`, deploy; the next brief's rule history shows it. Nothing happens on its own unless `ANALYST_APPLY=auto` (below).

`ANALYST_MODEL` and `ANALYST_EFFORT` in `tvgw.conf` choose the model (default `claude-opus-5-5`, about $0.07 a day; `claude-sonnet-5-5` is half the price, `claude-haiku-5-5` a twentieth, `claude-fable-5-1` two and a half times) and the reasoning depth (`low`, `medium`, `high`, `xhigh`, `max`; default `high`). A change takes effect at the next run; each run's `.json` records the model, the effort and the cost. For one run by hand: `sudo tvgw analyst --day 2026-10-27 --model claude-fable-5-1 --effort max`; a model other than the configured one writes its file beside the usual one (`<day>.<model>.md`), which is how to compare two models on the same evidence. `ANALYST_SCHEDULE` (a time of day, `hourly`, or a systemd calendar expression such as `*-*-* 06,18:00:00`) sets the cadence, rendered into a timer drop-in by `install.sh`; `ANALYST_WINDOW` (`day`, or `6h` for the last six hours) sets what each run reads, and `--since 6h` does the same for one run. A second timer, `tvgw-analyst-weekly`, reads the whole ISO week that just ended on Monday at 04:10 with its own model and effort (`ANALYST_WEEKLY_MODEL`, default `claude-fable-5-1`, `off` to disable; `ANALYST_WEEKLY_EFFORT`; `ANALYST_WEEKLY_SCHEDULE` as `Day HH:MM` or a calendar expression); its file is `reports/proposals/<YYYY-Www>.md`, and `sudo tvgw analyst --weekly` or `--week 2026-W43` runs one by hand.

To see exactly what would be sent before anything is sent: `sudo tvgw analyst --dry-run --day YYYY-MM-DD` writes `<day>.pack.json` and `<day>.prompt.txt` beside the proposals and calls nothing. To stop the analyst, remove the key file (the timer then logs "no key" and exits 0) or disable the timer. The key file must be root-only; a key readable by others is refused.

### Autonomous blocks (`ANALYST_APPLY=auto`)

Set `ANALYST_APPLY=auto` in `/etc/tvgw/tvgw.conf`; the next analyst run reads it, no deploy needed. From then on a `block` the daily model proposes is applied by the gateway itself when it passes every gate of design decision 20: vetted and low risk; a name seen on two or more days whose connections carried no payload (median under 16 KB down per connection, under 2 MB in the window); cleared by a second model asked to refute it (`ANALYST_VERIFIER_MODEL`, `claude-fable-5-1` at `ANALYST_VERIFIER_EFFORT` xhigh by default, never the proposer); at most three a day. The rule goes into `/var/lib/tvgw/auto.rules` (`AUTO_RULES`), a file the machine owns and `tvgw adguard apply` appends to the profile's rules; your `.rules` file is never edited. The TV is then watched for ten minutes (bytes sent to it and, on LG, the foreground app), and the rule is on probation for a day: `tvgw-autoblock.timer` re-judges it hourly against streaming volume per TV hour and the red lines, and reverts on a collapse. Everything shows in the proposals file (`Applied: ...`), in `sudo tvgw autoblock list` (every machine rule: when, verdict, why) and in the brief's "Rules the gateway added on its own" section.

Three ways to take a rule out. `sudo tvgw undo` removes the newest machine rule from the file and AdGuard (`--all` removes every one). `sudo rm /var/lib/tvgw/auto.rules` removes them all at the next hourly check or apply, and the record follows. `ANALYST_APPLY=off` stops new ones; the existing ones keep their probation. After a revert the TV may hold the blocked answer for up to a minute (`blocked_response_ttl`). If a machine rule broke something you want: `sudo tvgw undo` first, then `sudo tvgw analyst --show` to read why two models took it for telemetry; a name that must stay reachable belongs as an `@@` exception in the profile, where the lint then refuses any machine rule covering it.

The analyst is not asked on a day with nothing new: the TV off with no lookups, or only names judged within the last week doing what they always do, with no red line, blocked name reached, ACR-like cadence, gate sample, unresolved destination or firmware change. Such a day writes a one-line `<day>.md` and costs nothing; `sudo tvgw analyst --force --day YYYY-MM-DD` asks anyway. `journalctl -u tvgw-autoblock` shows the hourly judgements. The unit fails (`systemctl --failed`) when a revert could not reach AdGuard; the remedy is `sudo tvgw adguard apply`.

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
