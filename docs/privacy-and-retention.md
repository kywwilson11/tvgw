# Privacy and retention

tvgw exists to watch a device that watches its owner, so the store it builds is itself sensitive. This page says what is recorded, how long it is kept, who can read it, and how to back it up without making things worse.

## What the store holds

The store is one SQLite file, `/var/lib/tvgw/tvgw.db`. Only the TV's own traffic goes in: rows are filtered to the TV's address.

| Table | What a row is |
|---|---|
| `dns` | Every DNS query from the TV: time, name, record type, the answers, whether it was blocked, the matching rule and list, the upstream used, cache hit, latency. |
| `tls` | Every TLS ClientHello the capture saw: time, destination address and port, and the server name (SNI). |
| `http` | Every plain-HTTP request: time, host, method, URL including the query string (first 2000 characters), user agent (first 300). Requests handled by the URL filter also carry status and bytes. |
| `flows` | Every TCP/UDP connection the TV opened: start and end time, destination, ports, packets and bytes each way, final state. |
| `lanprobe` | TCP connection attempts to private or multicast addresses other than the gateway: time, address, port. These can include addresses of your own devices. |
| `oddport` | Traffic to ports other than 80, 123 and 443, from the kernel log. |
| `tvstate` | One reading an hour: power state and the foreground app. |
| `tvsettings` | The TV's settings as read over its LAN API (LG), stored when a value changes: the Live Plus (ACR) switch, the location setting (ZIP code) the TV holds, country, device name, Wake-on-LAN, CEC, store mode, audio guidance, firmware. |
| `hosts`, `rules` | Derived: one row per name seen, with first and last seen and its category; the history of our own policy rules. |
| `verify`, `fw_counters` | The results of `tvgw verify` and a snapshot of every firewall counter every 10 minutes. |
| `pcaps_done`, `ingest_state`, `ingest_runs`, `meta` | Bookkeeping: which pcaps were read, the log cursors, one row per ingest run with its counters and warnings. |

Column-level detail is in [architecture.md](architecture.md#the-data-model).

Together, `dns`, `tls` and `flows` are a minute-by-minute record of what the household watched and when: which streaming services, which apps, when the TV was on. Treat the file as personal data.

## What is captured but not stored

The capture (`tvgw-pcap`) writes hourly pcap files of frames the TV sends. Nothing the TV receives is kept: no response body, no server certificate, no ciphertext. Of the TV's frames it keeps exactly five classes:

- TCP segments with SYN, FIN or RST set: when a connection was attempted and when it ended,
- requests to TCP port 80, whole, so the plain-HTTP request line, headers and any request body are in the file,
- UDP to any port other than 443, whole (DNS, SSDP, mDNS, NTP), and QUIC long-header packets (the handshake) on UDP 443; the firewall rejects QUIC, so these record the attempts,
- a TCP segment only when it begins a TLS ClientHello record (`0x16 0x03 .. 0x01`), which carries the server name; no other TLS record is kept, so the capture holds no encrypted application data,
- a TCP segment that begins with an HTTP method (`GET`, `POST`, `HEAD`, `PUT`) on any port, so LG's firmware fallback on TCP 8080 is seen.

Plain HTTP the TV sends is captured in full, because that is what the URL filter and the plain-HTTP log exist to examine; what the servers answer is not. UDP the TV sends to other ports stays whole because `STRICT_PORTS=no` allows that traffic and the brief lists it under Unexpected ports. ICMP is not captured. The ingest reads names, hosts and URLs from the pcaps; it does not store packet bodies in the database, but the pcap files do hold the TV's request bodies until pruned.

## How long it is kept

| Data | Where | Kept for | Setting |
|---|---|---|---|
| `dns`, `flows`, `tls`, `http`, `lanprobe`, `oddport`, `verify`, `fw_counters`, `ingest_runs` rows | `tvgw.db` | 365 days | `DB_DAYS` |
| `tvstate`, `tvsettings`, `hosts`, `rules` | `tvgw.db` | Not pruned. They grow slowly. | none |
| Raw pcaps | `/var/lib/tvgw/pcap/` | 7 days exactly (not 8: a file goes on the first hourly run after it turns 7 days old), and no more than 1.5 GB, oldest first. Only files ingest has read; a file it has not read is kept and reported, and deleted at 14 days at the latest. The file tcpdump is writing is never deleted. | `PCAP_DAYS`, `PCAP_MAX_GB` |
| Reports written from the store, and `reports/legacy/` from before the store | `/var/lib/tvgw/reports/` | Not pruned | none |
| Hourly TV power history | `/var/lib/tvgw/tvcheck-history.log` | Not pruned | none |
| Flow, URL-filter and TLS-passthrough logs | `/var/log/tvgw/` | About 12 weeks (rotated weekly, 12 kept, compressed) | `logrotate` config |
| AdGuard Home query log and statistics | `/opt/AdGuardHome/` | 90 days | set by `tvgw adguard apply` |
| AdGuard config backups (`AdGuardHome.yaml.bak-*`) | `/opt/AdGuardHome/` | Not pruned; one per apply that changed something. They hold the TV's MAC and address. | none |
| Kernel log lines for unexpected ports | the systemd journal | Per the journal's own limits | `journald` |

The settings are in `/etc/tvgw/tvgw.conf`. Pruning of the database happens at the end of each hourly ingest; every 30 days the file is checked and vacuumed when at least a quarter of it is free, so lowering `DB_DAYS` takes effect within the hour but the file shrinks at the next check. Raw pcaps are pruned hourly by `tvgw prune-pcaps` (`tvgw-prune.timer`).

The store keeps DNS for longer (365 days) than AdGuard does (90 days). To keep less, lower `DB_DAYS`. There is no purge command; to delete a specific span, delete the rows by hand in SQLite as root.

## Who can read it

| Path | Owner and mode | Who can read |
|---|---|---|
| `/var/lib/tvgw/` | `root:adm`, 2751 | root and the `adm` group can list it. Others can pass through it but not list it: tshark runs as `nobody` and must reach the pcaps. New files inherit the `adm` group. |
| `/var/lib/tvgw/tvgw.db` | `root:adm`, 640 | root and `adm`. |
| `/var/lib/tvgw/reports/` | `root:adm`, 2750 | root and `adm`. |
| `/var/lib/tvgw/pcap/` and each pcap | `root:nogroup`, 2750 and 640 | root, and the unprivileged tshark through the `nogroup` group. |
| `/var/log/tvgw/` and its logs | `root:adm`, 2750 and 640 | root and `adm`. |
| `/var/lib/tvgw/lgtv-keys.sqlite` | 600 | root only. This is the TV pairing key and it can control the TV. |

`install.sh` sets these on every run, and `tvgw-pcap.service` creates each pcap `640`. On Raspberry Pi OS the first user you create is normally in `adm`; check with `id`. Anyone in `adm` can run `tvgw brief` and `tvgw sql`. The hardware suite fails if the settings file (it holds the TV's MAC and the router's address; `install.sh` makes it `640 root:adm`), the state directory, the store, a log, the pcap directory or a pcap is world-readable, or if the pairing key is not 600.

**Known gap.** Because others may pass through `/var/lib/tvgw`, any file in it that is itself world-readable can be read by a user who knows its name. `tvgw-analyze` runs with `umask 027`, so `tvcheck.txt` (which includes the ZIP code the TV holds) and `tvcheck-history.log` (power state and foreground app every hour) are created `640`; `install.sh` sets that mode on every run, and the hardware suite fails on any world-readable file in the directory. Two things stay outside that: a pairing key written by the pairing command carries that command's umask until `install.sh` next sets it to `600`, and AdGuard Home's own files under `/opt/AdGuardHome/` (its query log holds every lookup) are outside what `install.sh` sets. Check both with `sudo ls -l`, and `sudo chmod 640` anything readable by others.

## Where to keep it

Everything stays on the SD card: the store, pcaps, logs and backups. Do not put any of it on a USB disk that is failing its SMART checks, and do not move it to removable media you may lose. A failing disk loses data and may leak it later when it is thrown away or handed on.

## Backup

Backups are not automated. Nothing in the repo takes one. The store is a SQLite file in rollback-journal mode, so SQLite's online backup is safe while ingest runs. A suggested routine, run as root (install `sqlite3` first with `sudo apt install sqlite3`):

```sh
#!/bin/bash
# /usr/local/sbin/tvgw-backup (suggested; not installed by install.sh)
set -euo pipefail
umask 077
DEST=/var/lib/tvgw/backup
install -d -m 2750 -g adm "$DEST"
OUT="$DEST/tvgw-$(date +%Y%m%d).db"
sqlite3 /var/lib/tvgw/tvgw.db ".timeout 60000" ".backup '$OUT'"
[ "$(sqlite3 "$OUT" 'pragma quick_check')" = ok ]
find "$DEST" -name 'tvgw-*.db' -mtime +14 -delete
```

Run it from a systemd timer or cron, daily. Keep it on the SD card, inside the protected state directory. A backup on the same card does not protect against the card failing. If you copy it elsewhere, copy it to a machine you control and treat the copy exactly as sensitive as the original: it is the whole viewing history. Delete old copies when you lower `DB_DAYS`, or your retention setting means nothing.

To restore: stop `tvgw-analyze.timer`, copy the backup over `/var/lib/tvgw/tvgw.db`, set it to `root:adm` and 640, then start the timer. The restored file carries the read offsets of the logs, so ingest resumes from there; log rotation may have discarded older lines, which leaves a gap.
