# Shell jobs

Two scripts that the timers run, plus one package command. `install.sh` copies the scripts to `/usr/local/sbin/`. Each reads `/etc/tvgw/tvgw.conf`.

| Job | Run by | What it does |
|---|---|---|
| `tvgw-analyze` | `tvgw-analyze.timer`, hourly at :20 | Reads the TV, ingests, writes the reports. |
| `tvgw prune-pcaps` (the package, not a script here) | `tvgw-prune.timer`, hourly | Pcap retention: only files ingest has read, never the one tcpdump is writing. Below. |
| `tvgw-doh-update` | `tvgw-doh-update.timer`, daily | Refreshes the DoH resolver block set and re-applies the firewall. |

## tvgw-analyze

1. Takes `/run/lock/tvgw-analyze.lock`. If another run holds it, exits 0 at once.
2. Creates `reports/`, `reports/daily/` and `reports/weekly/` as `2750` group `adm`.
3. **LG only** (`PROFILE=lg-webos`): runs `tvgw tvcheck`. Unless the TV was unreachable (exit 1), it rewrites `tvcheck.txt` with a `read YYYY-MM-DD HH:MM` header, so the last good reading survives while the TV sleeps. If Live Plus is on (exit 2), it logs the `WARNING` line. Either way it appends one line, `YYYY-MM-DD HH:MM power app`, to `tvcheck-history.log`, with `unreachable` when there was no reading.
4. Runs `tvgw ingest`. A failure is logged as a warning and the run goes on.
5. Writes `reports/latest.txt` and `.json` (`tvgw report`, the last 24 hours) every run, replacing them atomically.
6. For each of the last 14 finished days that ends after the oldest DNS row in the store, writes `reports/daily/<day>.txt` and `.json` once.
7. For the last finished ISO week (Monday to Sunday), under the same condition, writes `reports/weekly/<YYYY-Www>.txt` and `.json` once. Older weeks are not backfilled.

Daily and weekly files are never rewritten. To regenerate one, delete it and let the next run write it again, or run `tvgw report --day D` by hand.

## tvgw prune-pcaps

Retention moved into the package (`src/tvgw/pcaps.py`) because the shell script could see neither the store's `pcaps_done` marks nor which file tcpdump holds open: it deleted a lone live file that was over the cap, exited 1 under `set -e` when no pcap was present, and `find -mtime +7` kept a file aged 7.99 days. The command, as root:

1. Asks `/proc` which pcap tcpdump holds open. If that cannot be told, it deletes nothing and warns.
2. Deletes files ingest has read once they are older than `PCAP_DAYS` (default 7, measured exactly). A finished file ingest has not read is kept and counted in a warning, and deleted only at twice `PCAP_DAYS`, so a broken ingest costs a week of warnings before it costs evidence.
3. While the directory is over `PCAP_MAX_GB` (default 1.5), deletes the oldest file ingest has read; warns when only un-read files are left.
4. While the filesystem has under 1 GB free, the same, so a full disk cannot stop the capture or the store.

It prints `tvgw prune-pcaps: deleted N, kept M (X MB)`, each warning to stderr, and exits 1 on any warning so the oneshot shows in `systemctl --failed`. Everything useful is in the store within the hour; pcaps are raw evidence. The store's `pcaps_done` mark for a file is dropped only after the file is gone, so a pruned pcap is never ingested twice.

## tvgw-doh-update

1. Does nothing if `DOH_LIST_URL` is unset.
2. Downloads the list with `curl` (60 s timeout).
3. Keeps the IPv4 addresses and networks of `/16` or narrower that do not fall inside a CIDR in `/etc/tvgw/doh-exclude.txt`. The excluded ranges are shared CDN edges that also serve ordinary sites.
4. Refuses a result under 50 entries and keeps the old list (exit 1), so a truncated download never unblocks everything.
5. Writes `/var/lib/tvgw/doh4.txt` and runs `tvgw-apply`.

`tvgw verify` fails `doh4_loaded` if the set has fewer than 50 elements, and the hardware suite checks that the well-known resolvers (8.8.8.8, 1.1.1.1, 9.9.9.9 and their pairs) are in it.

## Gotchas

- `tvgw-analyze` runs inside the sandboxed unit: it can write only `/var/lib/tvgw`, `/var/log/tvgw` and `/run/lock`. A new output path elsewhere needs a `ReadWritePaths=` entry ([../systemd/README.md](../systemd/README.md)).
- For a profile other than `lg-webos`, no TV reading is taken and `tvcheck-history.log` gets no lines, so the brief shows `TV: no readings`.
- `tvgw-doh-update` re-applies the firewall, which resets the counters and can re-enable forwarding after a manual stop.
- `tvgw prune-pcaps` with no store yet treats every file as un-read: nothing goes before twice `PCAP_DAYS`.
