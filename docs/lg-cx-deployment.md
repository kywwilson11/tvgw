# LG CX privacy gateway: Pi 5 between the TV and the eero

The TV is wired to the Pi's eth0 and has no other path out. The Pi filters DNS with
AdGuard Home, forwards everything else through nftables (`tvgw`), and records what the
TV does. Last updated 2026-10-25; see the headers in `pi/tvgw/` for the details.

```
LG CX  --eth--  Pi 5 "kylepi5"  --wlan0--  eero  --  internet
10.10.10.17     eth0 10.10.10.1             192.0.2.1
                wlan0 192.0.2.48
```

## 1. Layout

| Piece | Where | Role |
|---|---|---|
| NetworkManager `tv-lan` | eth0, 10.10.10.1/24, IPv6 off, never-default | TV subnet; `ignore-carrier` keeps it up while the TV is off |
| dnsmasq | `/etc/dnsmasq.d/tvgw.conf` (`port=0`) | DHCP only; CX pinned to 10.10.10.17 by MAC |
| AdGuard Home v0.107.x | `/opt/AdGuardHome`, systemd `AdGuardHome` | DNS filter on :53; admin UI on 127.0.0.1:3000 |
| tvgw nftables | `tvgw-apply`, `/etc/tvgw/tvgw.conf` | NAT, DNS redirect, DoH/DoT/QUIC blocks, LAN isolation |
| tvgw-flowlog | `/var/log/tvgw/flows.log` | every TV connection with byte counts (conntrack) |
| tvgw-pcap | `/var/lib/tvgw/pcap/` (hourly, 14 d / 3 GiB) | handshakes, DNS, plain HTTP; no bulk TLS payload |
| tvgw-doh-update.timer | `/var/lib/tvgw/doh4.txt` | daily refresh of the DoH resolver IP set |
| tvgw-analyze.timer | `/var/lib/tvgw/archive/`, `/var/lib/tvgw/reports/` | hourly: pcaps → 90-day text archive → latest/daily/weekly reports |
| nginx (GFTS filter) | `/etc/nginx/conf.d/tvgw-gfts.conf`, `/etc/nginx/tvgw/stream.conf` | 10.10.10.1:80 URL filter + :443 TLS passthrough for LG's file service; log `/var/log/tvgw/gfts.log` |

PIA runs on the Pi with `routedPacketsOnVPN` on. The TV's own traffic goes **direct**
via wlan0 (`UPLINK=direct`); AdGuard's upstream lookups ride the VPN (PIA's rules force
that). Keep everything on the SD card: the USB disk at `/media/usb` is failing SMART.

## 2. Install / refresh

```
scp -r pi/tvgw kylepi5:~/        # or rsync
ssh kylepi5 'cd ~/tvgw && sudo ./install.sh'
```
`install.sh` is idempotent and keeps local edits to `/etc/tvgw/tvgw.conf` and `block4.txt`.
Prereqs on the Pi: `apt install tcpdump conntrack dnsmasq tshark`, plus AdGuard Home
installed natively (official script; not Docker). `pi/docker-compose.yml` is from the
earlier design and is no longer used.

AdGuard settings that matter (all in `/opt/AdGuardHome/AdGuardHome.yaml`; stop the
service before editing it by hand, the UI otherwise overwrites your change):
- `http.address: 127.0.0.1:3000` — reach the UI with `ssh -L 3000:localhost:3000 kylepi5`
- upstreams `https://1.1.1.1/dns-query`, `https://1.0.0.1/dns-query`; bootstrap 1.1.1.1 / 1.0.0.1.
  DoH **by IP only**: PIA blocks plain DNS to anything but its resolver. Quad9 and
  Mullvad do not work through PIA (TLS handshake dies).
- `cache_optimistic: true` so the TV keeps resolving while PIA reconnects
- query log and stats 90 days, client IPs kept (`anonymize_client_ip: false`)
- filters: HaGeZi LG webOS, HaGeZi DoH/VPN bypass, HaGeZi Pro (since 2026-10-25; ~210k rules,
  blocked nothing the TV had used in its first 2 h); custom rules = `pi/lg-custom-rules.txt`
- systemd drop-in `AdGuardHome.service.d/workdir.conf` sets `WorkingDirectory=/opt/AdGuardHome`
  (the installer's unit pointed at a vanished /tmp dir and would not restart)

SSH to the Pi is keys only (`~/.ssh/id_ed25519_kylepi5`, host alias `kylepi5`).

## 3. Firewall knobs (`/etc/tvgw/tvgw.conf`, then `sudo tvgw-apply`)

- `UPLINK=direct|vpn` — direct = via eero; vpn = via PIA tun0 (blackholed if VPN drops)
- `BLOCK_QUIC=yes` — reject UDP/443 so apps fall back to TLS and SNI stays visible
- `STRICT_PORTS=no|yes` — the TV has only ever used tcp/80, tcp/443 and DNS. `no` logs
  anything else (`journalctl -k -g tvgw-oddport`); `yes` drops it. Flip after a quiet week.
- `/etc/tvgw/block4.txt` — manual IP/CIDR blocks for endpoints reached without DNS

Always on: all TV DNS (including its hardcoded 8.8.8.8) is DNAT'd to AdGuard; DoT/DoQ
(853) and the DoH resolver set are rejected; the TV cannot reach the home LAN or any Pi
service except DHCP, DNS and ping.

## 4. Analyze traffic, then tighten

`tvgw-analyze.timer` runs hourly at :20 with no help needed. Each run extracts every
*finished* pcap exactly once into a durable archive (`/var/lib/tvgw/archive/{sni,http,dns}.tsv`,
kept `ARCHIVE_DAYS`=90, long after the pcaps are pruned), refreshes the files `tvgw-report`
reads by default (last `REPORT_WINDOW`=8d plus the pcap still being written), and writes:

```
/var/lib/tvgw/reports/latest.txt            last 24 h, refreshed hourly (+ .json)
/var/lib/tvgw/reports/daily/YYYY-MM-DD.txt  one per finished day, written once at ~00:20;
                                            ends with that day's kernel tvgw-oddport log
/var/lib/tvgw/reports/weekly/YYYY-Www.txt   one per finished Mon-Sun week
```
Missed runs are made up on the next one (persistent timer; days backfilled 14 deep).
Check on it: `systemctl list-timers tvgw-\*` and `journalctl -u tvgw-analyze -n 20`.
By hand: `tvgw-report --since 2h` any time; for a longer look than 8 days,
`sudo tvgw-extract --window 30d && tvgw-report --since 30d`.

Read a report in this order:
3. **Unresolved / hardcoded-IP flows** → candidates for `block4.txt`
4. **DNS bypass attempts** → should all be "redirected"; a LEAKED row means the redirect broke
5. **Plain HTTP** → what the TV sends in the clear
2. **Top hosts by upload** → new telemetry; add to `lg-custom-rules.txt` and the AdGuard UI
6. **DNS by category** → `conns 0` with blocks = rule working; unblocked LG names = gaps

Never block `us.lgtvsdp.com` (clock; TLS breaks without it) or `snu.lge.com` (firmware).
After adding rules, use the TV for a day and re-run the report to see what broke.

## 4b. LG's plain-HTTP file service (GFTS) is URL-filtered, not DNS-blocked

`ngfts.lge.com`, `aic-ngfts.lge.com`, `aic-img-ngfts.lge.com` and `gfts.lge.com` deliver app
packages and icons (needed) **and** the ACR config file, the CDP telemetry schedule, LG Shopping
data and home-screen promo thumbnails (not wanted), all over plain HTTP. DNS can't tell them
apart, so AdGuard answers those four names with the Pi's address (`$dnsrewrite` rules in
`lg-custom-rules.txt`) and nginx on 10.10.10.1 does the rest:

- port 80: forwards to the real host; returns **403** when the URL has
  `biz_code=PREMIUM|CDP|LGSHOPPING|MAS|IBS`. Edit the regex in
  `/etc/nginx/conf.d/tvgw-gfts.conf`, then `sudo systemctl reload nginx`.
- port 443: TLS passthrough by SNI (the Content Store also uses HTTPS to gfts.lge.com); nothing
  is decrypted.
- upstream lookups use PIA's resolver (10.0.0.243) and leave via the VPN, like all Pi traffic.
- logs: `/var/log/tvgw/gfts.log` (one line per request with status and URL) and
  `gfts-tls.log`; the daily report's section 9 tallies them by biz_code.

If the Content Store ever fails to install something, check the log for a 403 on a new
biz_code before suspecting anything else.

## 5. The TV's LAN API (read-only on firmware 04.64)

The CX answers LG's SSAP control protocol on tcp/3000 from the Pi (paired once on
2026-10-25; key in `/var/lib/tvgw/lgtv-keys.sqlite`, library `bscpylgtv` in `/opt/tvgw-venv`).
It can read a few settings (Live Plus/ACR, ZIP, device name, Wake-on-LAN, CEC), firmware and
config flags, power state and the running app, and can launch/close apps and power the TV off
(on via WoL from the Pi, since `wolwowlOnOff` is left on). It **cannot write settings**: this
firmware's `isCallAllowed` guard rejects the Luna side-door every LAN tool uses, so Quick
Start+, agreements, home promotion etc. are remote-only (or root).

`tvgw-tvcheck` reads the privacy-relevant keys; `tvgw-analyze` runs it hourly, keeps the last
good reading in `/var/lib/tvgw/tvcheck.txt`, appends it to each daily report as section 8, and
logs a WARNING line if Live Plus is ever on again (the 2026 Texas-settlement firmware update
may re-ask for consent). By hand:

    sudo tvgw-tvcheck
    sudo /opt/tvgw-venv/bin/bscpylgtvcommand -p /var/lib/tvgw/lgtv-keys.sqlite 10.10.10.17 get_apps_all

Re-pair after a factory reset: run the second command and accept the prompt on the TV.

## 6. Things to know

- The TV still remembers the eero Wi-Fi. Make it forget the network so it cannot fall
  back to an unfiltered path if the cable drops. Its Wi-Fi MAC is <tv-wifi-mac>.
- The TV broadcasts SSDP/mDNS/LIFX/CoAP/Kasa discovery on eth0 and probes a remembered
  192.168.8.0/24 network; both are dropped on the Pi and are harmless.
- Routes in table 100 vanish when wlan0 drops; the NM dispatcher re-runs `tvgw-apply`.
- On Debian, `/etc/default/dnsmasq` must keep `CONFIG_DIR` or `/etc/dnsmasq.d` is ignored.
- `analyze.py` is the old per-client query-log summarizer; `tvgw-report` supersedes it.
