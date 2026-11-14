# The shell jobs

This folder holds the two shell scripts the timers run: `tvgw-analyze`, the hourly TV reading, ingest and reports, and `tvgw-doh-update`, the daily DoH resolver list. `install.sh` copies both to `/usr/local/sbin/`, and both read `/etc/tvgw/tvgw.conf`. Their schedules, users and sandboxes are in [the units table](../systemd/README.md#units).

## Files

| File | What it is | Installed as and run by |
|---|---|---|
| `tvgw-analyze` | Reads the TV (LG only), runs `tvgw ingest`, and writes the reports from the store. | `/usr/local/sbin/tvgw-analyze`, run by `tvgw-analyze.service` |
| `tvgw-doh-update` | Fetches the DoH resolver list, writes `/var/lib/tvgw/doh4.txt`, and re-applies the firewall; (listguard) `--accept` takes a refresh the shrink bound would hold back. | `/usr/local/sbin/tvgw-doh-update`, run by `tvgw-doh-update.service` and once by `install.sh` on a gateway with no list |

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

1. **Settings.** Takes one option, `--accept` (any other argument prints `usage: tvgw-doh-update [--accept]` and exits 2), then sources `/etc/tvgw/tvgw.conf` under `set -euo pipefail` and defaults `DOH_DROP_MAX` to `20`.
2. **No URL.** When `DOH_LIST_URL` is unset, it prints `tvgw: DOH_LIST_URL not set` and exits 0 ([the settings file](../../docs/reference/settings.md)).
3. **No exclusions.** When `/etc/tvgw/doh-exclude.txt` is missing or empty, it exits 1 and keeps the old list, because without the exclusions the next apply would block every CDN edge in the list. (dohguard) The owner's own `/etc/tvgw/doh-exclude.local.txt` may be missing or empty; the installer never writes it, where it replaces `doh-exclude.txt` on every install.
4. **Download.** Fetches the list with `curl -fsSL --proto '=https' --proto-redir '=https' --max-filesize 8000000 --max-time 60`: HTTPS only, redirects to HTTPS only, at most 8,000,000 bytes (about 7.6 MB), 60 seconds at most.
5. **Filter.** A `python3 -I` step reads the leading `a.b.c.d` or `a.b.c.d/n` of each line of the download and of the exclusions, the shipped ones and (dohguard) the owner's, merged; a line that holds no network is passed over in either file. It keeps the networks with a prefix length of 16 or more that do not fall inside an excluded CIDR, sorted. (dohguard) It also leaves out a network that holds an address the TV fetches from: one the TV pulled at least `USED_BYTES` (50 MiB) from over TCP 443 in the last `USED_DAYS` (14) days, summed over the connections it began within `ANSWERED_WITHIN` (a day) after the filter answered the TV with that address ([design decision 95](../../docs/design-decisions.md#95-a-doh-list-refresh-leaves-out-a-network-that-holds-an-address-the-tv-fetches-payload-from-and-says-how-many)). It reads them from the store's `flows` and `answer_ip`, opening `/var/lib/tvgw/tvgw.db` read-only. With no store yet, as before the first hourly ingest, nothing is left out. A store it cannot read prints `tvgw: the store cannot be read (<why>); keeping old list` and exits 1. When a refresh it goes on to take or hold leaves networks out, it prints `tvgw: N networks of the refreshed DoH list left out: the TV fetches from them` and writes the count to `/var/lib/tvgw/doh4.spared` (JSON: `spared`, `t`; mode 640, the group from the state directory). It never names the networks. It removes the file when such a refresh leaves none out; a refresh under the floor below leaves it as it was. A spare lasts only while the store shows the TV pulling from the network: after 14 days without that, after `tvgw forget`, or with `DB_DAYS` under 14, the next refresh blocks it again, and while it is blocked it cannot be in use again, since the TV's new connections to it are reset and bring nothing down. A line for the network in `/etc/tvgw/doh-exclude.local.txt` keeps it out of the list whatever the store shows.
6. **Floor and ceiling.** Over 50,000 entries, or over 4,000,000 addresses in all (sixty /16 networks), the filter prints `tvgw: the DoH list names N networks covering M addresses, more than a resolver list can ...; keeping old list` and exits 1: every address in the list is reset for the TV on port 443, so a list that grew past anything a resolver list can be, from a compromised or broken source, would black out the TV's HTTPS rather than block resolvers (the list in use has about 1,500 addresses). Under 50 entries, it prints `tvgw: only N DoH IPs fetched; keeping old list` and exits 1, so a truncated download never unblocks everything.
7. **The shrink bound.** (listguard) The step also reads the last refresh taken through the same filter: `/var/lib/tvgw/doh4.txt`, or, while a hold goes on, `/var/lib/tvgw/doh4.base`, the copy kept when it began. An entry today's exclusions free, or (dohguard) one that holds an address the TV fetches from, never counts as a drop. It counts that refresh's entries no entry of this one covers, by address or by a covering network of /16 or longer ([design decision 68](../../docs/design-decisions.md#68-a-lists-plain-exception-no-longer-lifts-the-profiles-red-line-blocks-the-lists-are-scanned-for-lines-that-act-on-the-tvs-rules-each-update-is-previewed-against-the-tvs-lookups-and-a-doh-list-refresh-that-drops-more-than-a-set-share-is-held-back)). When the last refresh taken has at least 50 entries and the share dropped is over `DOH_DROP_MAX` percent (1 to 100; a value out of range keeps the old list and exits 1), it holds the refresh back. It keeps the last refresh taken in `doh4.base` (once, when the hold begins), writes `/var/lib/tvgw/doh4.held` (JSON: `since`, the first hold of a run of them, `t`, `accepted`, when the last refresh was taken, `in_force`, `fetched`, `dropped`, `max`; mode 640, the group from the state directory), prints `tvgw: the refreshed DoH list would drop N of the M entries of the last refresh taken (P%, over DOH_DROP_MAX=20%); keeping them blocked and adding its new entries (tvgw-doh-update --accept takes it)`, and exits 1. When the last refresh taken plus this one's new entries, both through today's filter, differ from the list in force, it writes that as the list in force and runs `tvgw-apply` first: a hold blocks a resolver the source added, unblocks nothing the source dropped, and never keeps blocked an address the exclusions free for the TV's streaming. With `--accept` it says `tvgw: taking the refresh on request: it drops N of M entries` and goes on; a network the TV fetches from stays out. HaGeZi's list dropped 1.7 to 2.1% of its entries a day from 2026-11-01 to 2026-11-08, and 4.5% over the week.
8. **Swap.** Writes the result to a staged file `/var/lib/tvgw/.doh4.XXXXXX`, sets its group and mode, and renames it over `/var/lib/tvgw/doh4.txt`. The rename is atomic on one filesystem, so an apply that runs meanwhile, from the dispatcher or a deploy, reads the old list or the new one, never an empty or half-written file. A trap removes the staged file on any exit.
9. **Apply.** Removes `/var/lib/tvgw/doh4.held` and `doh4.base`, prints `tvgw: N DoH IPs loaded` and runs `exec /usr/local/sbin/tvgw-apply`.

`tvgw verify` fails `doh4_loaded` and `doh4_fresh` when the set is short or the list is stale, and (listguard) warns `doh4_held` while a refresh is held back; while one is, `doh4_fresh` measures the last refresh taken, not the file ([what tvgw verify checks](../../docs/reference/verify-checks.md)). (dohguard) While `doh4.spared` is there, `doh4_loaded`'s detail says how many networks were left out, and still passes. The hardware suite checks the list's age and size, that the well-known resolvers are in the set, and that no staged list was left behind.

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
