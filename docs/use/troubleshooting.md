# Fix a problem

You can go from a symptom, such as "the TV has no internet", to its fix here. Start with one command, then look up what it says. The tables further down list every message the gateway's background jobs print, for an engineer.

## Start here

Run the doctor first. It runs every check the gateway has, says what each problem means in plain words, and offers to fix it. To see only whether the gateway is working, run `tvgw status`. It answers in three lines and needs no `sudo`.

On the gateway:

1. Run `sudo tvgw doctor`. It prints each check that did not pass, with what it means, what you notice on the TV, and the fix. It asks before each fix it can make itself: type `y` to let it.
2. If the doctor finds nothing, run `systemctl --failed`. It must list nothing. Look a listed service up in [failed units](#failed-units).
3. If nothing failed, run `tvgw brief --full` and read its Coverage line. A source marked `NOT ASSESSED`, or an `ingest warning:` line, leads to [ingest warnings](#ingest-warnings).
4. If all of that is clean, start from the symptom in [the TV](#the-tv).

```sh
tvgw status           # three lines: did it hold, how old is that, what to do
sudo tvgw doctor      # every problem in plain words, and the fix for each
systemctl --failed    # must list nothing
tvgw brief --full     # read Coverage first
```

On a healthy gateway the doctor prints:

```text
tvgw doctor: all <N> checks pass. The gateway holds.
If the TV still has no internet: move its cable from the gateway to your router; tvgw keeps its settings.
```

The doctor runs the same checks as `sudo tvgw verify`, which prints one `OK`, `WARN` or `FAIL` line per check. [What tvgw verify checks](../reference/verify-checks.md) says what each check proves.

A `RED LINE:` in the brief has its own fix in [the red lines](daily-brief.md#red-lines).

## If the TV still has no internet

Move the TV's cable from the gateway to your router. The TV then works, without the gateway's protection, while you find the cause, and tvgw keeps its settings for when you move the cable back.

Then look for the cause, on the gateway:

1. **A check that fails.** Run `sudo tvgw doctor` and do what it says for each problem.
2. **A name the TV needs, blocked.** Run `sudo tvgw refused --since 1h`. It names what the filter refused the TV in the hour before you moved the cable ([if an app stopped working](#if-an-app-stopped-working)). Then run `tvgw brief --full` and look for a red line about a blocked name or the TV's clock.

## If an app stopped working

When one app fails and the rest of the TV works, the filter may have refused a name the app needs. Ask the gateway right away, while the app's failed lookups are minutes old.

On the gateway:

1. Run `sudo tvgw refused`. It reads what the filter refused the TV in the last 10 minutes. It changes nothing.
2. If its first line starts with `Most likely cause:`, it names a name the TV needs, or one the filter never refused before. It is never a tracker. Read why it is first, then run the command on its `Fix:` line.
3. Wait a minute, then try the app again. The TV keeps a refusal for up to a minute.
4. If the first line says nothing new, or nothing likely to break an app, was refused, the filter probably did not cause it. Run `sudo tvgw doctor`, which checks the rest of the gateway. To be sure the blocklists are not the cause, [pause them for a few minutes](#pause-the-blocklists-for-a-few-minutes).

```sh
sudo tvgw refused                # the last 10 minutes, the likely cause first
sudo tvgw refused --since 1h     # a longer window, up to a day
```

A report that found the cause starts like this one, from the project's tests:

```text
Most likely cause: es.nextlgsdp.com, refused 14 times since 09:52.
  Why it is first: the TV sets its clock from names like it; the filter let it through until 09:21, and its rule refused no name under nextlgsdp.com in the record since 26 September.
  Fix: sudo tvgw allow es.nextlgsdp.com
  Rule: ||nextlgsdp.com^, from the shared list HaGeZi LG webOS
  Kind: LG's own services
  After the fix, wait a minute, then try the app again.
```

A fix that says `run sudo tvgw doctor` means the name is one the TV always needs, so the gateway's own setup is wrong: the doctor says how to put it right.

The other names it lists are trackers the gateway refuses on purpose, or names it refused on earlier days as well. They are rarely why an app stopped, so the report gives them no fix. A tracker never counts as the likely cause, even one the TV never asked for before.

To see why one is refused, or how to let it through if you mean to, run `sudo tvgw check <name>` ([find out why a name is blocked](blocking.md#find-out-why-a-name-is-blocked)). `sudo tvgw refused --all` lists every name with its fix.

## If the TV buffers or is slow

The gateway keeps an eye on its own link to your router, and on the TV's cable. Every 10 minutes it notes the Wi-Fi signal, the link's speed and any drop. It never tests your internet connection, because a test would load the line while you watch. So it can tell you whether its own link was the problem, not how fast your internet is.

On the gateway:

1. Run `tvgw uplink`. It prints one row for each recent day, today first. The last column is that day's verdict.
2. Find the day the TV buffered, and look its verdict up in the table below.
3. If the verdict is `good`, the gateway's link was fine that day. Restart the TV and your router, then ask your internet provider if it goes on.

```sh
tvgw uplink             # one row a day, today first
tvgw uplink --days 14   # two weeks
```

A day with a weak evening looks like this, from the project's tests:

```text
day                  TV in use  signal       weak     slowest link  drops  most of link       verdict
2026-10-26 (so far)  2.0 h      -45/-45 dBm  0 min    300 Mbit/s    0/0    6.0 of 300 Mbit/s  good
2026-10-25           4.0 h      -79/-79 dBm  120 min  300 Mbit/s    0/0    6.0 of 300 Mbit/s  weak
```

| Verdict | What it means | What to do |
|---|---|---|
| `good` | The gateway's link to your router was fine while the TV was on. | Look at the TV, the router or your internet connection. |
| `weak` | The Wi-Fi signal between the gateway and your router was weak for a good part of the time the TV was on. | Move the gateway closer to the router, or connect it to the router by cable. |
| `near its limit` | For a while the TV downloaded close to what the gateway's link to the router could carry. | On Wi-Fi, move the gateway closer or use a cable. On a cable, try another cable or another port on the router. |
| `dropped` | The gateway lost its link to your router while the TV was on, or just after. | If the signal was good, look at the router first, and restart it if it keeps happening. If the signal was weak, as for `weak`. On a cable, check it at both ends, or try another. |
| `TV cable dropped` | The TV's cable to the gateway lost its connection more than once while the TV was on. | If nobody switched the TV off or restarted it then, check that cable at both ends, or try another. |
| `TV not in use` | The TV's traffic says it was off. | Nothing: there was nothing to judge. |
| `no samples` | The gateway kept no figures that day. | Run `sudo tvgw doctor`. |

A day with a problem also gets one note in the daily brief, and the doctor warns when the last hour's link was weak or dropped. The gateway never changes its own Wi-Fi or your router. The figures behind each verdict are in [the Uplink section of the full brief](../reference/brief-sections.md#uplink).

### Pause the blocklists for a few minutes

If `sudo tvgw refused` names nothing likely and the app still fails, find out whether the shared blocklists are the cause at all. The gateway can switch them off for a few minutes and bring them back on its own.

On the gateway:

1. Run `sudo tvgw pause`. It says what stays blocked and what does not, then asks before it changes anything. It pauses for 10 minutes, and `sudo tvgw pause 5` for 5. An hour is the most.
2. Try the app while the lists are off.
3. Wait for the end, or run `sudo tvgw pause --end` once you know.
4. Read what it prints at the end. If the app worked, it names the likely cause and the command that lets it through.

```sh
sudo tvgw pause            # the shared blocklists off for 10 minutes, after a question
sudo tvgw pause --status   # whether a pause is on, and until when
sudo tvgw pause --end      # bring them back now
sudo tvgw pause --report   # what they would have stopped, again
```

A pause that found the cause ends like this one, from the project's tests:

```text
During the pause, from 09:40 to 09:50, the TV reached 1 name the shared blocklists block again now:
  api.example.net, looked up 3 times: HaGeZi Pro. Kind: other services.
If the app worked during the pause, the likely cause is api.example.net (HaGeZi Pro): sudo tvgw allow api.example.net
If the app failed during the pause too, the shared lists were not the cause: run sudo tvgw refused right after it fails.
```

While the lists are off, the TV can reach the trackers that only they block. The blocks your TV's profile adds stay, and so do your own rules and the firewall. A TV on the general profile has no blocks of its own, so for those minutes nothing stops its maker's trackers.

The lists come back even if the gateway restarts during a pause: its hourly check brings them back within an hour of the pause's end. When the gateway keeps no password for the filter, the end asks you to run `sudo tvgw pause --report` at a terminal, which asks for it.

## The TV

Start from the symptom. Rows are in alphabetical order.

| Symptom | Likely cause | Check | Fix |
|---|---|---|---|
| An app does not install or update (LG) | The install needs a part of LG's file service that the gateway's filter refuses, or that filter is down. | `tvgw gfts 1d` lists the file service's refusals (status 403). Only the codes the profile names are refused: `PREMIUM`, `CDP`, `LGSHOPPING`, `MAS`, `IBS`. `systemctl status nginx` shows whether the filter runs. | A refusal that lines up with the failed install is the cause: an engineer changes the profile and the filter's files together ([the URL filter](../../deploy/nginx/README.md)). If the filter is down, run `sudo systemctl restart nginx`. |
| Buffering, or a stream that stops for a moment | The gateway's link to your router is weak or drops, or your internet connection is slow. | `tvgw uplink`: the verdict of the day it happened. | Do what [if the TV buffers or is slow](#if-the-tv-buffers-or-is-slow) says for that verdict. |
| Casting from a phone, or a phone remote app, does not work | By design: nothing on your home network can reach the TV. | | None. Use the TV's own apps and remote. |
| Clock wrong or reset; apps show certificate or security errors | The TV's clock server is blocked. Without it, every secure connection fails. | The red line `clock host lookups blocked`. On LG, `tvgw host us.lgtvsdp.com`. | Do what [that red line](daily-brief.md#the-tvs-clock-lookups-were-blocked) says, then restart the TV. |
| Content Store blank or failing (LG, error 202) | The store's feed, `us.lgrecommends.lgappstv.com`, is blocked, or LG's file service is unreachable. | `tvgw host us.lgrecommends.lgappstv.com` must show `state=allowed`. `tvgw gfts 1d` for refusals. `systemctl status nginx`. | Do what [the red line for a blocked name](daily-brief.md#a-name-the-tv-needs-was-blocked) says; restart the filter if it is down. |
| No network at all | The gateway does not pass the TV's traffic: forwarding is off, a route is missing, the gateway's own answers do not reach the TV, the firewall is not loaded, or the gateway lost its own connection. | `sudo tvgw verify`: the `forwarding`, `tv_route`, `gw_reply_route`, `policy_rule` and `ruleset` lines. | If `systemctl status tvgw` says inactive, run `sudo systemctl start tvgw`; otherwise run `sudo tvgw-apply`. Check that the gateway reaches your router. If the TV has no address, run `systemctl status dnsmasq`. |
| One app broke after a rule changed | A new block, or a blocklist that changed. | `sudo tvgw refused` within a few minutes of the failure: its first line names the likely cause ([if an app stopped working](#if-an-app-stopped-working)). Later, `tvgw rules` and the brief's Rule changes, and `sudo tvgw check <name>` for what blocks one name. | Run the `Fix:` command it prints, often `sudo tvgw allow <name>` ([unblock a name](blocking.md#unblock-a-name)), then wait a minute before you retry. |
| Streaming broke after the gateway blocked something on its own | A block the gateway added on its own took out something the stream needs. | `sudo tvgw autoblock list`, and the brief's Rules the gateway added on its own. | Run `sudo tvgw undo` ([taking a rule out](analyst.md#taking-a-rule-out)). |
| The TV says it has no internet | The TV's connectivity check is blocked, or the filter is down. On LG the check is `lgtvonline.lge.com`. | `sudo tvgw verify`: the `resolver_must_allow` and `services` lines. `tvgw host lgtvonline.lge.com`. | Do what [the red line for a blocked name](daily-brief.md#a-name-the-tv-needs-was-blocked) says. |

The sections from here on list every message the gateway's background jobs print. They are for an engineer, and you need them only when the doctor or the brief sends you here.

## Failed units

`systemctl --failed` lists each background service whose last run failed. Read its log first, with `journalctl -u <service> -n 20` ([reading the journals](../../deploy/systemd/README.md#reading-the-journals)). Rows are in alphabetical order.

| Unit | Fails when | What it means | What to do |
|---|---|---|---|
| `tvgw.service` | `tvgw-apply` exits non-zero on a start: `BLOCK_QUIC`, `STRICT_PORTS` or `ADTECH_PORT_WALL` not exactly `yes` or `no`, `UPLINK` or `DNSGATE` out of range, `WAN_GW` unset with `UPLINK=direct`, `VPN_IF` not `auto`, `none` or an interface name other than `lo`, `TV_IF` and `WAN_IF`, `UPLINK=vpn` with `VPN_IF=none`, nft rejecting the ruleset, or its start timeout running out. | Forwarding is switched on last, so after a failed start the TV is dark: it fails closed. | `journalctl -u tvgw -n 20` shows the `tvgw:` error. Fix `/etc/tvgw/tvgw.conf` or `/etc/tvgw/block4.txt`, then run `sudo systemctl start tvgw`. |
| `tvgw-analyst.service`, `tvgw-analyst-weekly.service` | A request failed (the key refused, the API unavailable, the answer cut off at `MAX_TOKENS`, another client error), the key file is readable by others, or its start timeout runs out. | No proposals for that window. A failed window is not asked again: the next scheduled run reads its own window. | Read the message in [the analyst and autonomous blocks](#the-analyst-and-autonomous-blocks). Ask again for the missed window by hand ([run a pass](analyst.md#run-a-pass)). |
| `tvgw-analyze.service` | Its start timeout runs out, or a step outside ingest and the report writes fails under `set -e`. Ingest warnings and a failed report print `tvgw-analyze: WARNING: ...` and do not fail it. | The hourly ingest and reports may be behind. Coverage shows `NOT ASSESSED` once a source goes unread. | Read `journalctl -u tvgw-analyze -n 50`. Run `sudo tvgw ingest` to see its warnings. |
| `tvgw-autoblock.service` | A revert could not re-apply AdGuard, or another error. | A reverted machine rule is out of `auto.rules` but still in AdGuard. | Run `sudo tvgw adguard apply`, then `sudo tvgw autoblock check`. |
| `tvgw-backup.service` | `tvgw backup: FAILED: <reason>`: the copy failed `quick_check`, the disk has less than twice the record's size plus 1 GiB free (nothing is written then), the disk is full, or the record stayed locked. Each run's outcome is kept for the `store_backup` check. | No copy today; older copies remain. The hardware suite fails once the newest copy is more than 36 hours old. | Free space, or check the store with `sudo tvgw sql "PRAGMA quick_check"`, then run `sudo systemctl start tvgw-backup`. A store that fails its own check needs [back up and restore](maintenance.md#back-up-and-restore). |
| `tvgw-dnsgate.service` | tcpdump ends. The unit restarts on failure with a growing delay, so it shows as restarting more often than as failed. | The gate set stops filling, so the gate's count overstates. `services` in `tvgw verify` reports it down. | `journalctl -u tvgw-dnsgate` carries tcpdump's own error and `tvgw dnsgate: tcpdump ended (rc=<N>)`. |
| `tvgw-dnsgate-inpath.service` | Only with `DNSGATE_FILL=inpath`: it could not bind its queue, it was killed by its watchdog after its loop stopped for 2 seconds, or it crashed. The unit restarts on failure with a growing delay. | Nothing on the TV: its lookups are answered without it. The brief's in-path count rises, and `dnsgate_inpath` in `tvgw verify` warns. | `journalctl -u tvgw-dnsgate-inpath -n 20`; then `sudo tvgw-apply` and `sudo systemctl restart tvgw-dnsgate-inpath`. To do without it, set `DNSGATE_FILL=passive` and run the installer. |
| `tvgw-doh-update.service` | The download failed, the list had under 50 entries (`tvgw: only <N> DoH IPs fetched; keeping old list`) or more than a resolver list can hold (over 50,000 entries or 4,000,000 addresses: `tvgw: the DoH list names <N> networks covering <M> addresses ...; keeping old list`), `/etc/tvgw/doh-exclude.txt` is missing or empty, the final `tvgw-apply` failed, or its start timeout ran out. With `DOH_LIST_URL` unset it prints `tvgw: DOH_LIST_URL not set` and succeeds. | The old list stays loaded; `doh4_fresh` fails once it is 8 days old. | Read `journalctl -u tvgw-doh-update -n 20`, fix the cause, and run `sudo systemctl start tvgw-doh-update`. `doh-exclude.txt` comes from the repository: run the installer again. |
| `tvgw-guard.service` | `nft -f /etc/tvgw/guard.nft` fails at boot or at a reload: the file is missing or nft rejects it, or the load takes over a minute. | At boot the guard table is not loaded, so the gateway is open to the TV whenever `inet tvgw` is absent; `guard_present` FAILs. A failed reload leaves the table that was loaded. | `journalctl -u tvgw-guard -n 20`. Re-run `install.sh`, which renders `/etc/tvgw/guard.nft` again, checks it with `nft -c` and reloads the unit ([open the gateway to the TV in an emergency](#removing-the-guard-in-an-emergency) has the restore). |
| `tvgw-pcap.service`, `tvgw-pcap-headers.service` | `CAPTURE_MODE` is neither `full` nor `headers`, or the settings file cannot be sourced: both fail in `ExecCondition`. Or `/usr/bin/dumpcap` is missing or not executable by `tvgw-pcap`: the start fails with `... install wireshark-common ...`. | No capture at all. | Fix the setting, or install dumpcap as [what dumpcap needs](../how-it-works/capture.md#what-dumpcap-needs) says, then `sudo systemctl restart tvgw-pcap`. |
| `tvgw-flowlog.service`, `tvgw-pcap.service` | They restart whenever they exit (`Restart=always`), so a fault shows as repeated restarts. They start after `tvgw.service` (`After=`, `Wants=`) but are not bound to it: a stopped or failed apply does not stop the capture. | A gap in the flow log or in the captures. The brief's red line `TV was on but no connections were recorded` names a dead flow log. | Read `journalctl -u tvgw-pcap -u tvgw-flowlog`. |
| `tvgw-prune.service` | `tvgw prune-pcaps` printed a warning. | Retention kept a file it should have deleted, deleted an unread one, or could not tell which file the capture is writing. | Look the warning up in [retention warnings](#retention-warnings). |
| `tvgw-verify.service` | A check failed, the run could not be stored, or its start timeout ran out. | The last check found a FAIL. | Run `sudo tvgw verify` and see [what tvgw verify checks](../reference/verify-checks.md). |

AdGuard Home, the address server and the web filter are not tvgw's own services, but `tvgw verify` checks them. Read `systemctl status` for each.

## Ingest warnings

Every hour the gateway reads its logs into its record, and prints a warning for anything it could not read. The brief lists the warnings of the day under Coverage, as `ingest warning:` lines, and the red line `ingest warnings: <N>` counts them. A source that could not be read shows as `NOT ASSESSED`.

To see the warnings now, on the gateway:

```sh
sudo tvgw ingest
```

Rows follow the order in which the hourly job reads its sources.

| Warning | What it means | What to do |
|---|---|---|
| `<source>: <path> is missing` | The source's input does not exist: the unit that writes it is down, or a path is wrong. The TV-state history is exempt, since only profiles with a LAN-API reader write it. | For `flows`, run `systemctl status tvgw-flowlog`. For `dns`, check AdGuard's query log (`sudo tvgw adguard diff` shows whether `querylog.file_enabled` drifted). For `gfts`, check nginx. For `pcaps`, the installer creates `/var/lib/tvgw/pcap`. |
| `<source>: log rotated or truncated since the last run and the lines written before it could not be recovered` | Lines were lost between two reads of a log: it rotated more than once between reads, or was truncated. | A one-off costs that gap. If it repeats, check that the hourly ingest runs. |
| `flows: <N> malformed line(s) skipped` | conntrack lines that do not parse, or hold a value SQLite cannot store. | A one-off needs nothing. Every hour means conntrack's output changed. |
| `flows: conntrack lost events <N> time(s) since the last run (ENOBUFS, first at <time>): connections that ended then are not in the store` | conntrack's netlink buffer overflowed: it dropped events, said `We have hit ENOBUFS! We are losing events.` in `tvgw-flowlog`'s journal, and carried on. The flow sections undercount around that time, and nothing else shows it, since `flows.log` reads as whole. | `journalctl -u tvgw-flowlog -g ENOBUFS` shows when. A card or CPU saturated at that moment (a backup, an upgrade) is the usual cause; repeated losses under ordinary use are a fault to report. If the journal itself cannot be read, the flows step fails with a `flows:` error instead and is checked again next run. |
| `flows: the flow logger's event socket dropped <N> event(s) since the last run (first seen by tvgw verify at <time>): connections that ended then are not in the store` | The kernel's count of events it could not queue to `tvgw-flowlog`'s socket grew between two `tvgw verify --record` snapshots (`flowlog: event socket drops` in `fw_counters`). The same loss as the `ENOBUFS` warning above, counted by the kernel, so it survives a reboot that erases the journal. A lower count than before is a restarted logger, and all of it is new. | As for the `ENOBUFS` warning. With only the TV's connections making events, a loss means the logger itself stalled: check `systemctl status tvgw-flowlog` and the card. |
| `dns: <N> malformed query-log record(s) skipped` | Torn or NUL-filled lines in AdGuard's query log; counted, never fatal to the hour. | A one-off needs nothing. Every hour means the query log's format changed. |
| `gfts: <N> malformed line(s) skipped` | URL-filter log lines not in the `tvgw_gfts` format. | Check that the installed nginx config carries `log_format tvgw_gfts` from `deploy/nginx/tvgw-gfts.conf`; a unit test ties the parser to it. |
| `onscreen: <N> line(s) that are not an answer skipped` | Lines of the record of your `tvgw tv confirm` answers that cannot be read: a line a full disk cut short, or one this version does not know. The answers around them are kept. | A one-off needs nothing. |
| `rules: <kind>: <error>` | A policy file could not be read: `gfts-block` (the nginx config), `block4` or `adguard` (`AdGuardHome.yaml`). That kind's rules stay in the history unretired. | Fix the path or the permissions. |
| `rules: <kind>: not in a form we can read` | The file holds no rules in the shape ingest parses, such as an `AdGuardHome.yaml` without a `user_rules` list. | Check the file. |
| `pcaps: cannot tell which file the capture is writing (needs /proc and root); skipped this run` | Ingest ran without root or without `/proc`, so no pcap was read. The pcaps are not stamped as read (`SourceSkipped`), so Coverage says `NOT ASSESSED` for them rather than an hour with no rows. | Run ingest as root; the unit does. |
| `pcaps: <N> file(s) deferred to the next run (time budget)` | A backlog: tshark gets `PCAP_BUDGET = 20 * 60` seconds per run. | Nothing; it clears by itself. |
| `<pcap>: not a capture file (<size> bytes)` | A finished file shorter than a pcap header (`PCAP_HEADER = 24` bytes), recorded as unreadable without running tshark. | Nothing; retention deletes it. |
| `<pcap>: <error>; recorded as unreadable after 24 attempts` | tshark failed on the file in `PCAP_MAX_ATTEMPTS = 24` attempts, counted at most once per clock hour, so a day of failures however often ingest ran; the store gave up on it. It is never retried, and retention may delete it. | After fixing the cause, delete its mark so the next run retries it (below). |
| `<pcap>: <N> connection attempts to :443 but no TLS hello: check the capture filter and tshark` | At least `SYN_CHECK = 20` connection attempts to port 443 and no hello: an extraction fault, which otherwise looks like a quiet hour. | Check that the installed `tvgw-pcap.service` matches the repository (`tests/unit/test_capture_filter.py` guards its filter) and that tshark reads the file. |
| `<N> pcap(s) could not be read (<pcap>: <error>); will retry next run` | tshark failed on these files: `tshark rc=<N>: <stderr>`, `refusing to run tshark as root: systemd-run not found`, or a timeout. Each is retried on every run, its failures counted at most once per clock hour, up to 24 attempts. When no pending file could be read in the run, the pcaps are not stamped as read and Coverage says `NOT ASSESSED`. | Fix the cause. In the 2026-10-27 incident the extractor, running as `nobody:nogroup`, could not read the files ([incidents](../incidents.md)). |
| `<source>: <exception>: <message>` | Any other failure of a step, such as `oddport: RuntimeError: journalctl rc=<N>: ...` when the journal cannot be read. The step rolled back. | Run `sudo tvgw ingest` to see it again, and read the message. |

To have the hourly job read a packet capture again after it gave up on one, delete its mark while the file is still in place. On the gateway:

```sh
sudo /opt/tvgw-venv/bin/python -c 'import sqlite3; c = sqlite3.connect("/var/lib/tvgw/tvgw.db", timeout=60); c.execute("DELETE FROM pcaps_done WHERE name = ?", ("<pcap>",)); c.commit()'
```

### Retention warnings

The job that deletes old packet captures prints these, and fails, so it shows in `systemctl --failed`. They are not in the brief. What the gateway keeps, and for how long, is in [raw pcaps](../how-it-works/privacy-and-retention.md#raw-pcaps).

| Warning | What it means | What to do |
|---|---|---|
| `cannot tell which file the capture is writing; nothing deleted` | Prune could not read the capture's open files: not root, or no `/proc`. | Run it as root; the unit does. |
| `<pcap>: never ingested, deleted at twice PCAP_DAYS` | Evidence was lost: the file was never read into the store. | Fix ingest; the hour in that file is gone. |
| `<N> finished pcap(s) older than PCAP_DAYS kept: not ingested yet` | Files due to go have not been read yet. | Find why ingest is not reading pcaps in the table above. |
| `pcaps over PCAP_MAX_GB by <N> MB with nothing ingested left to delete` | Every read file is gone and the unread ones still exceed the budget. | Fix ingest, or raise `PCAP_MAX_GB`. |
| `under 1 GB free where the pcaps live, with nothing ingested left to delete` | The filesystem is nearly full and only unread files remain. | Free space on that filesystem and fix ingest. |

## The analyst and autonomous blocks

The analyst, the gateway's own blocks and `tvgw undo` print one line for each outcome, to the terminal or to their service's log. How they work is in [the analyst and autonomy](../how-it-works/analyst-and-autonomy.md).

| Message | What it means | What to do |
|---|---|---|
| `tvgw analyst: no key at /etc/tvgw/claude.key; nothing sent (use --dry-run to see the pack)` | There is no key file. The run succeeds and sends nothing. | Expected without a key. |
| `PermissionError: /etc/tvgw/claude.key is readable by others (mode <mode>); chmod 600 it` | The key file has a group or other bit set. The run stops with a traceback and the unit fails. | Run `sudo chmod 600 /etc/tvgw/claude.key`. |
| `tvgw analyst: the key at /etc/tvgw/claude.key was refused (AuthenticationError)` | The API rejected the key. | Replace the key in the file. |
| `tvgw analyst: the API was unavailable (<error>); the next run will try again` | A rate limit, a connection failure, a timeout or a server error (`RateLimitError`, `APIConnectionError`, `APITimeoutError`, `InternalServerError`). The next scheduled run reads its own window, not this one. | Ask again for this window by hand ([run a pass](analyst.md#run-a-pass)). |
| `tvgw analyst: the answer was cut off at max_tokens; its cost is in <base>.json` | The answer reached `MAX_TOKENS` (64000, thinking included) before it was complete. It was billed: the `.json` record keeps the usage, the cost and `cut_off: true`, and the `.md` says nothing was proposed. The run exits 1, so the unit fails. | Ask again by hand; a lower `--effort` leaves more of the budget for the answer. |
| `tvgw analyst: <error>: <message>` | Any other failure. | Read the message, then ask again by hand. |
| `tvgw analyst: the model declined (<category>); see <file>.md` | The model's safety layer refused the window. The day's file says so, its `.json` records `refused` with the usage and the cost, nothing is proposed, and the run succeeds. | Read the file. |
| `tvgw analyst: <window>: nothing new, no request sent (use --force to ask anyway)` | `novelty` found nothing the store does not already know. A one-line file is written and nothing is spent. | Nothing; `--force` asks anyway. |
| `tvgw analyst: the weekly pass is off (ANALYST_WEEKLY_MODEL=off)` | The weekly pass is switched off in the settings. | Set `ANALYST_WEEKLY_MODEL` to a model to turn it on. |
| `tvgw analyst: no proposals yet` | `--show` found no proposals file. | Wait for the first run, or run one by hand. |
| `tvgw report: error: <reason>` from `tvgw analyst` | A usage error in the analyst's flags, such as `--day, --since, --week and --weekly exclude each other`. The prefix names `tvgw report` although the command was `tvgw analyst`. | Fix the flags ([commands](../reference/commands.md)). |
| `tvgw autoblock: <verdict> <rule> (<reason>)` | The hourly check decided on a machine rule: `passed`, or `reverted` with the reason. | For `reverted`, the rule is already out of the file and AdGuard; read the reason. |
| `` tvgw autoblock: WARNING: a reverted rule is still in AdGuard; run `tvgw adguard apply` `` | A revert took the rule out of the file, but AdGuard's re-apply failed. The decision's reason in the store says so, and the unit fails. The hourly check applies again every hour until it takes. | Run `sudo tvgw adguard apply` to do it now; if that fails, see [AdGuard apply failures](#adguard-apply-failures). |
| `tvgw autoblock: pushed (the owed re-apply took)` | A revert that had not reached AdGuard has now: the hour after the WARNING above, or after a run that was stopped. | Nothing. |
| `tvgw autoblock: <N> rule(s) on probation, nothing to decide` | Nothing was due this hour. | Nothing. |
| `tvgw undo: <rules> removed and AdGuard re-applied` | `tvgw undo` took the rules out. | Wait out the blocked answer's TTL before you test ([after unblocking something](blocking.md#after-unblocking-something)). |
| `tvgw undo: no machine rule to remove` | The record holds no active machine rule. | Nothing. A line in `/var/lib/tvgw/auto.rules` that no record names is taken out by the next hourly check, which prints the line below. |
| `` tvgw autoblock: reverted <rule> (no record of this rule: taken out of the machine's file) `` | The hourly check found a rule in the machine's file that no record on probation or passed names: a run that died between applying a rule and recording it, or a line written by hand. It took the rule out and applied AdGuard. | Nothing. To block the name yourself, run `sudo tvgw block <name>`. |
| `tvgw undo: the rules file was changed but AdGuard was not re-applied (<error>)` | The rule is out of the file, but AdGuard still has it. The next hourly check applies it again, and every one after until it takes. | Run `sudo tvgw adguard apply` to do it now. |
| `tvgw adguard: machine rule dropped: <rule>: <problem>` | A line in `auto.rules` fails the profile's lint beside the profile's rules, for example because it covers a must-allow host, so it never reaches AdGuard. Any apply prints this to stderr. | Delete the line from `/var/lib/tvgw/auto.rules`. The hardware test `test_autoblock_file_record_and_resolver_tell_one_story` fails while it is there. |

## AdGuard apply failures

`sudo tvgw adguard apply` writes the profile's rules and settings into the filter. The installer runs it, and so do the analyst and `tvgw undo` after a change. It checks the new settings first, keeps a copy of the old ones, and puts that copy back if the filter does not answer within 30 seconds. How it works is in [the architecture](../how-it-works/architecture.md#how-tvgw-adguard-apply-works). Rows follow the order in which the command can fail.

| Message | What it means | What to do |
|---|---|---|
| `tvgw adguard: the profile does not lint: <problems>` | The profile fails its lint, so nothing was planned. | Fix the profile; `tvgw profile` lists the problems. |
| `tvgw adguard: DNS_UPSTREAMS is empty` | The setting names no upstream. | Set `DNS_UPSTREAMS` ([the settings file](../reference/settings.md)). |
| `cannot read /opt/AdGuardHome/AdGuardHome.yaml: <error> (is AdGuard Home installed and set up?)` | There is no config to merge into. | Run `sudo tvgw adguard install` ([installing it without the wizard](../how-it-works/adguard.md#installing-it-without-the-wizard)), or install AdGuard Home and finish its first-run wizard ([install what tvgw needs](../install/README.md#install-what-tvgw-needs)). |
| `tvgw adguard: AdGuard Home on this computer was not set up by tvgw, and it serves more than the TV: ...`, exit 4; from the installer, `tvgw: this AdGuard Home serves other devices, ...`, exit 77 | The filter here was set up by someone else, and its log shows other devices that used it in the last 7 days. Taking it over would cut them off. Nothing changed ([taking over one that is not tvgw's](../how-it-works/adguard.md#taking-over-one-that-is-not-tvgws)). The same refusal, with `ADGUARD_TAKE_OVER=no refuses`, comes when the settings say never and the filter only listens on every address. | If other devices use it, put tvgw on a computer of its own. If nothing else does, add `ADGUARD_TAKE_OVER=yes` to `/etc/tvgw/tvgw.conf`, then run the command the message names again (`sudo dpkg --configure -a` after a package install, `sudo tvgw setup`, or `sudo tvgw adguard apply`). |
| `tvgw adguard: AdGuard Home listens on every address of this computer but served no other device in the last 7 days: tvgw takes it over; ...` | Not a failure: the filter was set up by its own first-run page, which answers every interface, and nothing else has used it. tvgw takes it over and goes on. | Nothing, if you installed the filter for tvgw. If something else does use it, set `ADGUARD_TAKE_OVER=no` before the next apply. |
| `tvgw adguard: another tvgw adguard apply is running` | The lock beside the config, `.tvgw-adguard.lock`, is held by a deploy, the analyst, the hourly check, `tvgw undo` or another hand run. Nothing changed. | Wait for the other apply to finish, then run it again. |
| `tvgw adguard: <path> has no schema_version (empty or truncated); restore a .bak-* file or rerun AdGuard's wizard; nothing changed` | The live config is damaged; apply refuses to complete it from a template. | Restore the newest good copy ([rolling back AdGuard alone](../project/deploying.md#rolling-back-adguard-alone)) or rerun AdGuard's wizard. |
| `tvgw adguard: <path> is at schema_version <N>, above 34, the newest this tvgw release has been tested with; nothing changed. ...` | (lists) AdGuard Home is newer than tvgw has been tested with (it updated itself, or a 1.x release was installed) and migrated its config past schema 34 (`SCHEMA_CEILING` in src/tvgw/adguardcfg.py). The resolver runs as it is; nothing is written. | Update tvgw to a release that knows the schema, or go back by hand: stop AdGuardHome, copy the `AdGuardHome.bak-*` binary and the `AdGuardHome.yaml.bak-*` of the same stamp into place, start it, run `sudo tvgw adguard diff` ([the schema ceiling](../how-it-works/adguard.md#the-schema-ceiling)). `tvgw adguard upgrade` refuses this state too. |
| `tvgw adguard: cannot read one ExecStart from <unit file>; add --no-check-update by hand` | (lists) `tvgw adguard service` found no `ExecStart=` in the unit's `[Service]` section, or more than one, so it cannot know which command to repeat with the flag. Nothing was written. | Read the unit with `systemctl cat AdGuardHome` and write the drop-in by hand: an empty `ExecStart=`, then the full command with `--no-check-update`; then `sudo systemctl daemon-reload && sudo systemctl restart AdGuardHome`, and `sudo tvgw verify` shows `adguard_pinned`. |
| `tvgw adguard: deferred: upstream down (a fresh lookup under <name> SERVFAILs, or goes unanswered while AdGuard answers its own rules); ...`, exit 3 | (lists) The restart guard: the upstreams answer nothing (SERVFAIL, or silence past AdGuard's own upstream timeout while its filter still answers), so a restart would empty the cache the TV is living on. Nothing was staged or restarted ([the restart guard](../how-it-works/adguard.md#the-restart-guard)). The analyst, the hourly check and `tvgw undo` report the same text. | Check that the gateway reaches the DoH upstreams (`journalctl -u AdGuardHome`, the VPN client), then run the command again. |
| `tvgw adguard: not validated: <binary> not found; the planned config was not validated before writing` | Not a failure: there is no `AdGuardHome` binary beside the config, so the check was skipped. | Check where AdGuard Home is installed. |
| `tvgw adguard: AdGuard Home rejected the planned <path>; nothing changed`, then AdGuard's own reason | `AdGuardHome --check-config` refused the candidate before the service was touched, or did not finish in 120 seconds. | Fix what AdGuard's reason names, in the profile or the settings. |
| `tvgw adguard: <error>; the previous config (<backup>) was put back` | A step from the stop onwards failed and the rollback worked. `AdGuardHome did not answer DNS after the change` means the resolver did not resolve the must-allow name within 30 seconds; SERVFAIL counts as not ready, so a deploy while the DoH upstreams are unreachable ends here. | Check that the gateway reaches the upstreams, then apply again. |
| `tvgw adguard: <error>; restoring <backup> also failed: <error>` | The rollback failed too. AdGuard may be stopped, or running the planned file. | Restore the named backup by hand ([rolling back AdGuard alone](../project/deploying.md#rolling-back-adguard-alone)) and run `sudo tvgw verify`. |

## AdGuard install failures

`sudo tvgw adguard install` installs the filter and sets it up for you. When it stops, it prints one line and leaves nothing half done. A stop after the filter's first start also says what it took back, such as `removed <files>; the binary in /opt/AdGuardHome stays`. Fix the cause, then run the command again. How the install works is in [installing it without the wizard](../how-it-works/adguard.md#installing-it-without-the-wizard). The rows follow the order in which the command can stop.

| Message | What it means | What to do |
|---|---|---|
| `tvgw adguard: another tvgw adguard install is running` | The lock `/var/lib/tvgw/.adguard-install.lock` is held. Nothing changed. | Wait for the other run to finish. |
| `tvgw adguard: AdGuard Home is already set up on this computer, and not by tvgw, ...` | tvgw's marker is missing, and its `AdGuardHome.yaml` holds neither the TV's client entry nor the profile's must-allow exceptions, or cannot be read. It may serve other devices ([whose AdGuard it is](../how-it-works/adguard.md#whose-adguard-it-is)). Nothing changed. | If other devices use it, use a separate computer for tvgw. If nothing else does, run `sudo tvgw adguard apply`, which takes it over; when it finds signs of other devices it stops, and `ADGUARD_TAKE_OVER=yes` in `/etc/tvgw/tvgw.conf` is the yes. |
| `tvgw adguard: AdGuard Home in /opt/AdGuardHome is tvgw's but below v0.107.79; run sudo tvgw adguard upgrade --fetch` | The binary is older than `verify.ADGUARD_MIN`. Nothing changed. | Run `sudo tvgw adguard upgrade --fetch` ([upgrading AdGuard Home](../how-it-works/adguard.md#upgrading-adguard-home)). |
| `tvgw adguard: tvgw pins AdGuard Home for 64-bit arm64 and amd64 Linux; this computer is <machine> with a <bits>-bit system; nothing was installed` | `aghinstall.PIN` has no asset for this computer, or the system is 32-bit on a 64-bit processor. | Use a 64-bit system on an arm64 or amd64 computer. |
| `tvgw adguard: could not download AdGuard Home from <url>: <error>; nothing was installed` | GitHub did not answer, or the system's certificates could not check its answer (`certificate verify failed`). | Check the uplink, and that the `ca-certificates` package is installed. |
| `tvgw adguard: the downloaded AdGuard Home does not match tvgw's pinned hash; nothing was installed` | The file that arrived is not the release tvgw pins. It was deleted. | Do not install it another way. Run the command again later; if it repeats, open an issue with the message. |
| `tvgw adguard: the download from <url> is over 64 MB; nothing was installed`, or `tvgw adguard: the AdGuard Home archive holds <member> ...` | The answer, or the archive in it, does not have the shape of the pinned release (`MAX_DOWNLOAD`, and the member filter of `aghinstall.extract()`). Nothing was written to `/opt/AdGuardHome`. | As for the hash. |
| `tvgw adguard: systemd-run could not start AdGuard Home's first run: <error>; ...` | systemd refused the transient unit `tvgw-adguard-firstrun`. | Read the error; `systemctl status tvgw-adguard-firstrun` shows a unit left by an earlier run. |
| `tvgw adguard: AdGuard Home did not start its first run within 30 seconds (journalctl -u tvgw-adguard-firstrun); ...`, or `... stopped before its wizard answered ...` | The binary did not serve its wizard on loopback within `WIZARD_WAIT`. | Read the journal it names. |
| `tvgw adguard: port 53 on 127.0.0.1 is not free for AdGuard Home: <reason>; port 53 is held by <holder>; ...` | Another DNS server holds `127.0.0.1:53`, and AdGuard's own check refused the address before anything was configured. The holders come from `ss`, each as `<name> (pid <pid>) on <address>`, every socket on port 53 among them: systemd-resolved's on `127.0.0.53` is listed too, and is not the one in the way. | Stop or remove the program on `127.0.0.1:53` or on `0.0.0.0:53`, or use a separate computer for tvgw. |
| `tvgw adguard: port 3000 on 127.0.0.1 is not free for AdGuard Home's page: <reason>; ...` | Another program holds the page's address. | Stop it, or use a separate computer for tvgw. |
| `tvgw adguard: AdGuard Home refused tvgw's first-run settings (<status>): <reason>; ...`, or `... did not take tvgw's first-run settings ...` | AdGuard's install API answered with an error; the reason is AdGuard's own. | Fix what the reason names. |
| `tvgw adguard: <yaml> holds <n> user(s) (<names>), not tvgw's one 'admin': something else may have answered AdGuard Home's wizard first; ...`, or `... the password tvgw set does not open AdGuard Home's page ...` | The YAML AdGuard wrote is not the answer tvgw gave: another process on this computer answered the open wizard first, or changed its user. The run removed that YAML. | Find what else runs on the computer before you run the command again. |
| `tvgw adguard: AdGuard Home's page did not come up at http://127.0.0.1:3000 after its wizard; ...` | After the wizard, AdGuard did not move its page to `127.0.0.1:3000` within `LOGIN_WAIT` (10 s). | Read `journalctl -u tvgw-adguard-firstrun`. |
| `tvgw adguard: AdGuard Home's service did not start: <error>; ...` | AdGuard's own `-s install`, or the start of the unit its install script left, failed. That unit is left stopped, so no open wizard stays on AdGuard's default address. | Read `journalctl -u AdGuardHome`. |
| `tvgw adguard: ADGUARD_LISTEN is keep, so AdGuard Home answers DNS on 127.0.0.1 alone and the TV, which asks <GW_IP>, gets no answer: ...` | Not a failure: the install worked, and with `keep` the apply leaves DNS where the wizard put it ([the listen setting](../how-it-works/adguard.md#the-listen-setting)). | Set `ADGUARD_LISTEN=gateway` in `/etc/tvgw/tvgw.conf`, then run `sudo tvgw adguard apply`. |

<a id="removing-the-guard-in-an-emergency"></a>

## Open the gateway to the TV in an emergency

The gateway keeps its own services closed to the TV at all times, even while its firewall is stopped. This wall only narrows what the firewall allows, so it is never why the TV is offline, unless someone edited it. Lift it only for a test, or when a broken install drops what it should not.

On the gateway:

```sh
sudo systemctl disable tvgw-guard.service    # the next start of the gateway does not load it again
sudo nft delete table inet tvgw_guard        # the only thing that removes it now
sudo tvgw verify                             # guard_present fails until it is back
```

The next deploy loads it again, so hold deploys while it is off. To bring it back, on the gateway:

```sh
sudo systemctl enable tvgw-guard.service && sudo systemctl reload-or-restart tvgw-guard.service
sudo tvgw verify                             # guard_present is OK again
```

Running the installer again brings it back too. Why these commands and no others is on [the firewall's page](../../deploy/nftables/README.md#lifting-it-in-an-emergency).
