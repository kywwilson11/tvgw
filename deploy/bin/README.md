# Shell jobs

Three scripts that the timers run. `install.sh` copies them to `/usr/local/sbin/`. Each reads `/etc/tvgw/tvgw.conf`.

| Script | Run by | What it does |
|---|---|---|
| `tvgw-analyze` | `tvgw-analyze.timer`, hourly at :20 | Reads the TV, ingests, writes the reports. |
| `tvgw-prune` | `tvgw-prune.timer`, hourly | Keeps the pcap directory under its age and size limits. |
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

## tvgw-prune

Deletes pcaps older than `PCAP_DAYS` (default 7), then deletes the oldest until the directory is under `PCAP_MAX_GB` (default 1.5). Everything useful is in the store within the hour; pcaps are raw evidence. The store's `pcaps_done` mark for a file is dropped only after the file is gone, so a pruned pcap is never ingested twice.

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
