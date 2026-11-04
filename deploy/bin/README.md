# The shell jobs

This folder holds the two shell scripts the timers run: `tvgw-analyze`, the hourly TV reading, ingest and reports, and `tvgw-doh-update`, the daily DoH resolver list. `install.sh` copies both to `/usr/local/sbin/`, and both read `/etc/tvgw/tvgw.conf`. Their schedules, users and sandboxes are in [the units table](../systemd/README.md#units).

## Files

| File | What it is | Installed as and run by |
|---|---|---|
| `tvgw-analyze` | Reads the TV (LG only), runs `tvgw ingest`, and writes the reports from the store. | `/usr/local/sbin/tvgw-analyze`, run by `tvgw-analyze.service` |
| `tvgw-doh-update` | Fetches the DoH resolver list, writes `/var/lib/tvgw/doh4.txt`, and re-applies the firewall. | `/usr/local/sbin/tvgw-doh-update`, run by `tvgw-doh-update.service` and once by `install.sh` on a gateway with no list |

## tvgw-analyze, step by step

The script runs with `set -euo pipefail` and `umask 027`, so nothing it writes is readable by other users.

1. **Settings.** Sources `/etc/tvgw/tvgw.conf`, ignoring a failure.
2. **Lock.** Takes `/run/lock/tvgw-analyze.lock` without waiting. When another run holds it, it prints `tvgw-analyze: already running` and exits 0.
3. **Directories.** Creates `reports/`, `reports/daily/` and `reports/weekly/` under `/var/lib/tvgw` ([where it lives and who can read it](../../docs/how-it-works/privacy-and-retention.md#where-it-lives-and-who-can-read-it)).
4. **The TV reading, LG and Samsung.** When `PROFILE` is `lg-webos` (or unset) or (samsung) `samsung-tizen`, it runs `tvgw tvcheck` into `.tvcheck.tmp`; for `samsung-tizen` that reads the TV without pairing (src/tvgw/tizen.py):
   - Unless `tvcheck` exited 1, the TV unreachable, 4, the gateway not paired with the TV, or 5, the TV having refused the gateway's key at an earlier reading (in both of the last two `tvcheck` asks the TV nothing, so no pairing prompt reaches its screen: [design decision 54](../../docs/design-decisions.md#54-a-tvs-lan-api-is-a-module-the-profile-names-a-reading-never-pairs-a-profile-declares-what-it-can-check)), it rewrites `tvcheck.txt` as a `read <ISO time>` line followed by the reading, so the last good reading survives while the TV sleeps.
   - When `tvcheck` exited 2, Live Plus on, 3, a second network path (Wi-Fi, Wi-Fi Direct or tethering on), or (samsung) 5, a device that answered but not as a Samsung TV, it prints the reading's `WARNING` line. A reading with exit 5 holds only `rest.reply`, which the store records once.
   - Either way it appends one line to `tvcheck-history.log`: the ISO 8601 time with its UTC offset, the power state and the foreground app, separated by tabs. The power state is `unreachable` when the TV did not answer, and `unknown` when it answered without a power state or was not asked (not paired, or the key refused).
   - The fields are tab-separated because webOS power states contain spaces (`Active Standby`, `Screen Off`) and `lgwebos.clean` turns tabs in a value into spaces. The time carries its offset because a local 01:20 happens twice on the night the clocks fall back.
5. **Ingest.** Runs `tvgw ingest`. A failure prints `tvgw-analyze: WARNING: tvgw ingest reported problems` and the run goes on.
6. **Latest.** Writes `reports/latest.txt` and `reports/latest.json` with `tvgw report`, the last 24 hours, into temporary files that replace the old ones only when both rendered. A failure prints `tvgw-analyze: WARNING: tvgw report ... failed`.
7. **Finished days.** For each of the last 14 days, it writes `reports/daily/<day>.txt` and `.json` with `tvgw report --day`, once: only when the day ended at least `SETTLE=10800` seconds (3 hours) ago, ended after the oldest DNS row in the store, and has no file yet. (plain) With `BRIEF_STYLE=plain` it adds `--with-plain`, so the text starts with [the plain brief](../../docs/reference/brief-sections.md#the-plain-brief); with the key absent or `full` the files are what they were.
8. **The action.** (plain) For the newest daily file of those 14 days, when `reports/action.txt` is missing or older than it, it writes `tvgw brief <day> --action` there: the plain brief's action as the tier, a tab and the text, or an empty file when nothing needs a person. A failure prints `tvgw-analyze: WARNING: tvgw brief <day> --action failed` and keeps the old file.
9. **The finished week.** For the last finished ISO week, Monday to Sunday, it writes `reports/weekly/<YYYY-Www>.txt` and `.json` with `tvgw report --week`, under the same three conditions. Older weeks are not backfilled.
10. **Summary.** Prints `tvgw-analyze: latest refreshed; new reports: <list or none>; see /var/lib/tvgw/reports`.

The `SETTLE` wait exists because a day's evidence lands late: conntrack reports an idle connection only after its established-TCP timeout ([the firewall's order of operations](../nftables/README.md#order-of-operations)), and dumpcap closes each pcap only when its clock hour ends. With the hourly timer ([the units](../systemd/README.md#units)), a finished day is first written at 03:20.

Daily and weekly files are never rewritten. To regenerate one, delete it and let the next run write it, or run `tvgw report --day DAY` by hand.

## tvgw-doh-update, step by step

1. **Settings.** Sources `/etc/tvgw/tvgw.conf` under `set -euo pipefail`.
2. **No URL.** When `DOH_LIST_URL` is unset, it prints `tvgw: DOH_LIST_URL not set` and exits 0 ([the settings file](../../docs/reference/settings.md)).
3. **No exclusions.** When `/etc/tvgw/doh-exclude.txt` is missing or empty, it exits 1 and keeps the old list, because without the exclusions the next apply would block every CDN edge in the list.
4. **Download.** Fetches the list with `curl -fsSL --proto '=https' --proto-redir '=https' --max-filesize 8000000 --max-time 60`: HTTPS only, redirects to HTTPS only, at most 8,000,000 bytes (about 7.6 MB), 60 seconds at most.
5. **Filter.** A `python3 -I` step reads the leading `a.b.c.d` or `a.b.c.d/n` of each line of the download and of the exclusions. It keeps the networks with a prefix length of 16 or more that do not fall inside an excluded CIDR, sorted.
6. **Floor and ceiling.** Over 50,000 entries, or over 4,000,000 addresses in all (sixty /16 networks), the filter prints `tvgw: the DoH list names N networks covering M addresses, more than a resolver list can ...; keeping old list` and exits 1: every address in the list is reset for the TV on port 443, so a list that grew past anything a resolver list can be, from a compromised or broken source, would black out the TV's HTTPS rather than block resolvers (the list in use has about 1,500 addresses). Under 50 entries, it prints `tvgw: only N DoH IPs fetched; keeping old list` and exits 1, so a truncated download never unblocks everything.
7. **Swap.** Writes the result to a staged file `/var/lib/tvgw/.doh4.XXXXXX`, sets its group and mode, and renames it over `/var/lib/tvgw/doh4.txt`. The rename is atomic on one filesystem, so an apply that runs meanwhile, from the dispatcher or a deploy, reads the old list or the new one, never an empty or half-written file. A trap removes the staged file on any exit.
8. **Apply.** Prints `tvgw: N DoH IPs loaded` and runs `exec /usr/local/sbin/tvgw-apply`.

`tvgw verify` fails `doh4_loaded` and `doh4_fresh` when the set is short or the list is stale ([what tvgw verify checks](../../docs/reference/verify-checks.md)). The hardware suite checks the list's age and size, that the well-known resolvers are in the set, and that no staged list was left behind.

## Pcap retention

`tvgw-prune.timer` runs the package command `tvgw prune-pcaps`, not a script here; it replaced the retired `deploy/bin/tvgw-prune`, which `install.sh` deletes. The policy is in [how long it is kept](../../docs/how-it-works/privacy-and-retention.md#how-long-it-is-kept), and the command in [commands](../../docs/reference/commands.md).

## Checking it

On the gateway:

```sh
systemctl list-timers tvgw-analyze.timer tvgw-doh-update.timer   # last and next runs
journalctl -u tvgw-analyze -n 50                                 # warnings and the summary line
ls /var/lib/tvgw/reports/daily | tail -n 3                       # the newest finished days
tail -n 3 /var/lib/tvgw/tvcheck-history.log                      # the last TV readings (LG)
journalctl -u tvgw-doh-update -n 20                              # "N DoH IPs loaded", or why not
sudo wc -l /var/lib/tvgw/doh4.txt                                # entries in the current list
```

## Changing it

1. Edit the script here and run `make gate`. `tests/unit/test_deploy_lint.py` runs `bash -n` on both scripts. `tests/unit/test_deploy_files.py` checks `tvgw-analyze`'s `SETTLE` gate on finished days and weeks and its tab-separated history line with both absent states, and runs its TV reading against a stub `tvgw` for each `tvcheck` exit: only a reading replaces `tvcheck.txt`, and every run adds one history line. (plain) `tests/unit/test_plain.py` runs the report writing against a stub `tvgw` and a stub `date` with `BRIEF_STYLE` absent, `full` and `plain`: the daily file is what `tvgw report --day` printed, with `--with-plain` only for `plain`, and the action file is written once for the newest day.
2. Deploy. The hardware suite checks that each installed script equals the checkout and that the reports are written from the store.

A new output path for `tvgw-analyze` outside `/var/lib/tvgw`, `/var/log/tvgw` and `/run/lock` needs a `ReadWritePaths=` entry in its unit ([hardening](../systemd/README.md#hardening)).

## Gotchas

- For a profile other than `lg-webos` and `samsung-tizen`, no TV reading is taken and `tvcheck-history.log` gets no lines ([what else is LG-specific](../../docs/project/adding-a-profile.md#what-else-is-lg-specific)).
- `tvgw-analyze` exits 0 when ingest reports problems, so they show in the brief's Coverage, not in `systemctl --failed`.
- `tvgw-doh-update` re-applies the firewall, which switches forwarding back on after a manual stop of `tvgw.service`, and resets the counters; `tvgw-apply` lists them either side of its reload for the next `tvgw verify --record`, so the reset costs the brief nothing ([design decision 13](../../docs/design-decisions.md#13-counters-not-logs-prove-the-firewall-held)).
- `tvgw-doh-update` needs the settings file: under `set -e`, a file that does not source cleanly stops it before the download.
