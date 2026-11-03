# Operations runbook

This page is the owner's runbook for a running gateway: the daily routine, the action for every red line, and the procedures for deploying, rolling back, changing policy, restoring a backup and upgrading the OS. It holds procedures; the mechanisms behind them are on the pages it links, and symptoms are in [troubleshooting](troubleshooting.md).

## Daily routine

Read the brief top to bottom, because its first lines say whether the rest can be trusted. The read commands run on the Pi as any member of `adm` ([privileges](../src/tvgw/README.md#commands)).

1. On the Pi, run `tvgw brief`. It shows yesterday; `tvgw brief <day>` shows another day. What each section means is in [the brief's sections](reading-the-brief.md#sections).
2. Read the Coverage line. A source marked `NOT ASSESSED` was not read recently, so its sections are unknown, not clean. Find out why in [ingest warnings](troubleshooting.md#ingest-warnings). On a gateway with PIA the line ends with PIA's state as the last `tvgw verify` run saw it (`PIA Connected`); any other state explains a red line about the Pi's own lookups leaving outside the VPN ([Coverage](reading-the-brief.md#coverage)).
3. Act on every `RED LINE:` line as [Red lines](#red-lines) says.
4. Read "Changes in effect": what changed on the gateway in the window and which TV hours were clean, before you judge anything the TV or the machine did in them ([Changes in effect](#changes-in-effect)).
5. Read New hosts, Blocked and still retried, and Allowed, outside the expected categories. Decide on each new name: block it ([changing policy](#changing-policy)), allow it (leave it, or put it in an expected category in the profile), or watch it.
6. When the brief has a List changes section, a blocklist's own update changed what the TV may resolve. Act on each row as [lines worth an answer](#lines-worth-an-answer) says.
7. With `ANALYST_APPLY=auto`, read Rules the gateway added on its own: a rule `on probation, untested` waits for your decision, and a `queued` one waits its turn. If a machine rule broke something, take it out with `sudo tvgw undo` ([taking a rule out](analyst-and-autonomy.md#taking-a-rule-out)).
8. Read the day's proposals: `sudo tvgw analyst --show` prints the proposals file written last, and `/var/lib/tvgw/reports/proposals/<day>.md` is the day's by name.
9. Run `systemctl --failed`. It must list nothing; for a listed unit, see [failed units](troubleshooting.md#failed-units).
10. Run `sudo tvgw verify`. A `FAIL` also fails `tvgw-verify.service`, but a `WARN` fails nothing and shows only in this output and the unit's journal, never in the brief, so this is where you see one ([the checks to watch](#the-checks-to-watch)).

On the Pi:

```sh
tvgw brief                                       # yesterday's brief
sudo tvgw analyst --show                         # the analyst's newest proposals
systemctl --failed                               # must list nothing
sudo tvgw verify | grep -v '^OK'                 # every WARN and FAIL
```

### The checks to watch

These `tvgw verify` checks came with design decisions 42, 43 and 46. What each proves, and the detail of each message, is in [what tvgw verify checks](troubleshooting.md#what-tvgw-verify-checks). The first step when one is not `OK`:

| Check | Not OK means | First step |
|---|---|---|
| `guard_present` (`FAIL`) | `inet tvgw_guard` is missing, partial or not what `tvgw-guard.service` loaded: the Pi is open to the TV whenever `inet tvgw` is absent. | `sudo systemctl reload-or-restart tvgw-guard`, then `journalctl -u tvgw-guard`; if `/etc/tvgw/guard.nft` is missing, re-run `install.sh`. |
| `guard_quiet` (`WARN`) | The guard dropped packets that `inet tvgw`'s input chain accepted since the last apply: the two tables disagree. | Compare `sudo nft list chain inet tvgw input` with `sudo nft list chain inet tvgw_guard input`, then `sudo tvgw-apply`. |
| `cotenants_denied` (`WARN`) | A unit `CO_TENANT_UNITS` names has no `IPAddressDeny` covering `TV_NET`: it relies on nftables alone. | Re-run `install.sh`, which writes the drop-ins and reloads systemd. |
| `dnsmasq_caps` (`WARN`) | dnsmasq holds `net_admin` or `net_raw`, or its bounding set keeps them because the hardening drop-in is not in place. | `systemctl cat dnsmasq`, then look for a refused stamp (below) and `journalctl -u dnsmasq`. |
| `flowlog_events` (`FAIL`, or `WARN` when only the switch is not `0`) | The flow log records nothing (no `ct_events` rule with the switch at `0`, or no logger socket), or it hears every connection on the Pi again. | `sudo tvgw-apply`; for a dead logger, `systemctl status tvgw-flowlog`. After a rollback to an older release, see [rolling back the code](#rolling-back-the-code). |
| `list_sentinels` (`FAIL`) | A HaGeZi list's sentinel no longer answers `0.0.0.0`: the list was emptied by its last download or never loaded. | `sudo head -3 /opt/AdGuardHome/data/filters/*.txt` and `journalctl -u AdGuardHome`; a whole list file with a failing sentinel means HaGeZi renamed it. |
| `adguard_pinned` (`FAIL`) | AdGuard Home's unit, or the running process, lacks `--no-check-update`, so it may replace its own binary. | `sudo tvgw adguard service`. |

**The refused stamps.** When dnsmasq or nginx will not serve with its hardening, `install.sh` prints a `WARNING`, takes the hardening out, and records the refused text in `/var/lib/tvgw/.unit-stamps/dnsmasq-refused` or `nginx-refused`, so later deploys run that daemon unhardened instead of restarting it twice each time, until the hardening text itself changes ([what install.sh does](../deploy/README.md#what-installsh-does), steps 11 and 18). Each later deploy prints `WARNING: ... runs unhardened`. After a deploy, on the Pi:

```sh
sudo ls /var/lib/tvgw/.unit-stamps/ | grep refused   # must print nothing
```

A stamp is a finding: read the daemon's journal from the deploy that wrote it for why it would not start. Once the cause is fixed, delete the stamp and re-run `install.sh`, which tries the hardening again with its health check.

### Once a week

The hourly job writes a report for each finished ISO week to `/var/lib/tvgw/reports/weekly/<week>.txt`, and the weekly analyst pass writes `/var/lib/tvgw/reports/proposals/<week>.md` (`<week>` looks like `2026-W43`). Read both, then look at the week's names on the Pi:

```sh
tvgw allowed 7d       # allowed names outside the expected categories
tvgw top-upload 7d    # destinations by bytes the TV sent
tvgw retries 7d       # blocked names the TV keeps asking for
```

## Red lines

A red line is a sentence that must never be true, printed as `RED LINE:` near the top of the brief ([design decision 14](design-decisions.md#14-red-lines-are-the-alarm-model)). `red_lines` in `src/tvgw/queries.py` writes them in the order to act on them: the TV's needs, then the firewall and its watchdog, then the pipeline. Nothing pages anyone, so each row below is the whole response. The table follows the code's order; `<...>` marks a value the line fills in.

| Red line | What it means | What to do |
|---|---|---|
| `must-allow name blocked: <name> x<N> by <rule>` | A name in the profile's `[must_allow]` came back blocked. Its generated `@@\|\|<name>^$important` exception should have won, so a rule, a list or AdGuard's config changed. `by a list` means the log row named no rule. | `tvgw host <name>` shows the rule. Run `sudo tvgw adguard diff`; on drift, run `sudo tvgw adguard apply`. With no drift, run `tvgw profile` for the lint, then read the answer's CNAME chain with `tvgw sql "select answers, rule from dns where qname='<name>' and blocked=1 order by t desc limit 1"`: AdGuard matches a rule against CNAME targets too (`src/tvgw/profiles/lg-webos.toml`). Fix the rule in the profile and deploy ([changing policy](#changing-policy)). |
| `a list update newly blocks <name>, which carried content (list <id>, <bytes> down over <N> connections in the 14 days before, median <bytes>): if the TV needs it, add it to must_allow` | (lists) A subscribed blocklist's own update began blocking a name the TV had been resolving, and that name carried content, not telemetry, in the two weeks before ([List changes](reading-the-brief.md#list-changes)). Nobody reviewed the change: AdGuard applies whatever the list's URL serves ([lists change on their own](adguard.md#lists-change-on-their-own)). | Find what broke: `tvgw host <name>` shows the rule and the apps on at the time. If an app the household uses depends on the name, add it to the profile's `[must_allow]` with the reason and deploy ([changing policy](#changing-policy)); the generated `@@\|\|<name>^$important` beats the list. If nothing broke, leave it and note it. Look up the list with `sudo grep -B1 -A3 'id: <id>' /opt/AdGuardHome/AdGuardHome.yaml`, and report a false positive to its maintainer. |
| `Live Plus (ACR) is <value> on the TV (since <time>): General > Additional Settings` | The TV's own ACR switch, read hourly over its LAN API, is not `off`: someone turned it on, or a firmware update reset it. The brief reads the last known value at the window's end, so the line stays until a reading says `off`. | Turn Live Plus off with the remote, under General > Additional Settings; the CX's LAN API refuses writes ([design decision 4](design-decisions.md#4-no-rooting-of-the-tv)). `tvgw tvstate 2d` shows when it changed, and `sudo tvgw tvcheck` reads it again now. |
| `TV has a second network path: <path> is <state> (since <time>): traffic can leave around the gateway; turn it off under Settings > Network` | The TV's own network status, read hourly over its LAN API with the settings, says Wi-Fi or Wi-Fi Direct is in any state but `disconnected`, or Wi-Fi or Bluetooth tethering is on. Whatever leaves that way never crosses the gateway: no filter, no record. One line per path; it stays until a reading says the path is off again. | On the TV: Settings > Network: turn Wi-Fi off and delete the saved network, turn Wi-Fi Direct (Screen Share) off. Then `sudo tvgw tvcheck` must print no second-path warning. If the TV did this on its own, after an update or a reset, write it in [the incident log](incidents.md). |
| `clock host lookups blocked: <N> (the TV's clock comes from them)` | A lookup of a clock host (`clock_hosts` in the profile) was blocked. webOS takes its time from LG's SDP reply; blocked, the clock resets and TLS fails everywhere (the `[must_allow]` reason in `src/tvgw/profiles/lg-webos.toml`). | Do what the must-allow row says for the clock host, then restart the TV so it asks again. |
| `TV was on but never looked up its clock host (check the SDP hosts are reachable)` | A whole-day window (at least 82800 s, so the 23-hour day the clocks go forward counts) had a reading in `queries.AWAKE` (`Active`, `Screen Off` or `Screen Saver`) and no lookup matching `clock_hosts`. The TV syncs its clock at boot, so a day without a boot can pass without one. | Check other days with `tvgw host <clock-host>`. If lookups appear there, watch the next day. If they never appear, the pattern does not match this firmware's host: `tvgw profile --webos <version>` lists the generation's clock hosts and `tvgw new-hosts 7d` the recent names. Fix `clock_hosts` in the profile and deploy. |
| `firewall checks failed <N> of <M> times; last: <failures>` | Recorded `tvgw verify` runs failed in the window. | Run `sudo tvgw verify` and act on each FAIL ([what tvgw verify checks](troubleshooting.md#what-tvgw-verify-checks)). If it passes now, find when it failed with `tvgw sql "select datetime(t,'unixepoch','localtime'), failures from verify where ok=0 order by t desc limit 10"`. Treat every FAIL after a deploy as an outage ([incidents](incidents.md)). |
| `firewall checks ran <N> of ~<M> times (is tvgw-verify.timer alive?)` | Fewer than half the verify runs the window owed were recorded: one per 600 s, counted from the first run the store ever saw, once at least six are owed. A dead watchdog otherwise looks like a clean day. | `systemctl list-timers 'tvgw-*'` must show `tvgw-verify.timer` with a next run. Read `journalctl -u tvgw-verify -n 20`. If the timer runs, look in that journal for `tvgw verify: could not record the run`. |
| `ACR-shaped upload: <cell>:<port> sent <X> MB up (<R>x down) in <N> connections <on day \| in hour HH of day>; Live Plus reads <state>` | Red line 7 of the November report, first form. A cell (the registrable domain of the connections' TLS name, or the server's /24 when no hello named them, and the server port) outside the profile's expected categories uploaded as LG's ACR client does: in a day at least 1 MB of payload at 4 times the bytes down over 24 connections, or in an hour 500 KB, 4 times and 5 connections (`ACR_DAILY`, `ACR_HOURLY` in `src/tvgw/queries.py`). With Live Plus off, ACR itself should send nothing; an upload-heavy telemetry name fires the hourly form too ([design decision 45](design-decisions.md#45-the-acr-red-line-is-an-upload-test-and-a-port-wall)). | Confirm Live Plus with `sudo tvgw tvcheck`; if it reads anything but `off`, turn it off with the remote as for the Live Plus line. Look the cell up: `tvgw host <name>` for a domain, or for a /24 `tvgw sql "select dst, dport, count(*), sum(bytes_up) from flows where dst like '<a.b.c>.%' and dport=<port> group by 1 order by 4 desc limit 5"` and `tvgw host` on the top address. A tracker or ACR host: block it in the profile's `.rules` file (by address in `block4.txt` when it has no name) and deploy. A streaming app's own upload: add its name to the right expected category. |
| `ACR port attempts: <N> connections to TCP <ports> rejected (<names>)` | Red line 7, second form. The adtech port wall (`ADTECH_PORT_WALL=yes`) reset TV connections to LG's ad-tech ports 4001, 4431, 4445, 4447, 8180 or 8883: the counter `adtech ports` rose by N in the window, or the `tvgw-adport` samples say so. The names are the lookups whose A answers in the week before named a sampled address; `no lookup` means a hardcoded address or a resolver the gateway never saw, because DNS blocks every name known to use these ports. | `sudo journalctl -k -g tvgw-adport -n 20` shows the samples. Look up each address with `tvgw host <address>` and `tvgw sql "select qname, datetime(t,'unixepoch','localtime') from dns where answers like '%A:<address>%' order by t desc limit 5"`. A name that was not blocked is a rule gap: add it to the profile's `.rules` file and deploy. If a feature the household uses broke at the same time, set `ADTECH_PORT_WALL=no`, run `sudo tvgw-apply`, and write it in [the incident log](incidents.md). |
| `Encrypted ClientHello in <N> handshakes since <time> (outer names: <names>): per-connection TLS naming is going dark; keep HTTPS records stripped` | TLS hellos from the TV carried the ECH extension under a known ECH public name (`ECH_PUBLIC_NAMES` in src/tvgw/queries.py: `cloudflare-ech.com`), or under an outer name the TV never looked up in the window or the day before: real ECH. The capture sees only the outer name of those connections, so they can no longer be named one by one ([design decision 12](design-decisions.md#12-each-flow-is-named-by-its-own-tls-hello)). Any other hello with the extension whose name the TV did look up is GREASE (random bytes with the real name outside, which Chromium 117 and later send whenever they have no ECH config); it names its server and is counted apart, as `grease` in the report's JSON, not as this line. | Run `sudo tvgw adguard diff` and confirm it exits 0, so the generated rule that withholds HTTPS and SVCB records from the TV is live (`[adguard] strip_qtypes`). Look up each outer name with `tvgw host <name>`, and watch whether the count grows. |
| `the Pi's own lookups left outside the VPN: <what> <N> time(s), ... (was the tunnel down? see Coverage)` | The Pi's own new connections to a DoH resolver on TCP 443 (`DoH left by the uplink`) or to port 53 (`DNS left by the uplink`) left by `WAN_IF` instead of the tunnel in the window, as the count-only `post_leaks` chain counted them ([design decision 44](design-decisions.md#44-the-tunnel-is-a-setting-and-the-pis-own-leaks-are-counted)). The DoH provider saw the home address, and plain DNS went to whatever resolver the Pi was using, in the clear. Under PIA's `killswitch=auto` this happens after a daemon start before its first connection, after `piactl disconnect` and while the daemon is not active. The TV's own traffic is not affected: it never depends on the tunnel. Shown only on a gateway with a VPN: the last `tvgw verify` run found a tunnel or PIA's state, `VPN_IF` names one, or a run in the 30 days before the window's end saw one, so the line holds while the PIA daemon is down; `VPN_IF=none` turns it off. PIA's state, as the last `tvgw verify` run saw it, is on the Coverage line; the red line leaves it out, since red lines travel in the analyst's pack. | Run `piactl get connectionstate` and `ip -br link \| grep -E 'tun0\|wgpia0'`. If PIA was disconnected or restarting at the time, the line is that window, and it ends once PIA connects. If PIA reports `Connected` and the DNS count still rises, check PIA's remote port: an OpenVPN transport on port 53 is counted as DNS. `sudo nft list chain inet tvgw post_leaks` shows the counters. |
| `TV consent flag <flag> turned on (at <time>): an agreement was accepted on the TV` | (ledger) A flag of the TV's consent record (`eula.<flag>` in the TV settings, read hourly from `eulaStatus`) went from `false` to `true`: an agreement, such as Viewing Information (`acrAllowed`) or Voice Information (`voiceAllowed`), was accepted on the TV, by someone at the remote or by an update. Each `true` reading is compared with the flag's last definite reading before it (`true` or `false`), so an `unknown` in between (a partial answer, standby, a firmware update) neither hides a flip nor makes one: `false`, `unknown`, `true` is a flip. A flag first read as `true`, with no `false` before it, is not a flip and raises nothing. `network.bleAdvertisingOnOff` is recorded and never a red line. | `tvgw tvstate 2d` shows the change. Decline the agreement again with the remote under Settings > General > System > Additional Settings > User Agreements, and write it in [the incident log](incidents.md) if nobody in the household did it. |
| `machine rule <rule> has spent more than half of judge v2's 14-day ceiling with <N> of <K> clean TV hours` | (ledger) Judge v2, in shadow, has not seen enough clean demand hours in a week to judge the rule: the TV was off, on an input, or every evening was confounded. The shipped judge may have passed it long ago; v2 would still hold it on probation. | Read "Changes in effect" for what confounded the hours. Nothing to do while v2 is in shadow; the line is the evidence for [the owner's decision on judge v2](analyst-and-autonomy.md#judge-v2-in-shadow). |
| `TV was on but no lookups were recorded (is the AdGuard query log being read?)` | The TV had a reading in `queries.AWAKE` (`Active`, `Screen Off` or `Screen Saver`), an hour or more of the window was observed, and the store holds no DNS row for it. A TV that is on resolves names, so the query log is not being written or not being read. | In Coverage, check whether `dns` is `NOT ASSESSED`. Read `journalctl -u tvgw-analyze -n 50` for the ingest step. Check `sudo ls -l /opt/AdGuardHome/data/querylog.json` and `systemctl status AdGuardHome`. `sudo tvgw adguard diff` shows whether the query-log settings drifted. |
| `TV was on but no connections were recorded (is the flow log being read?)` | The same for conntrack: a reading in `queries.AWAKE` (`Active`, `Screen Off` or `Screen Saver`) and no flow row. | Run `systemctl status tvgw-flowlog`. `tail /var/log/tvgw/flows.log` must be growing. Coverage says whether `flows` was read. |
| `ingest warnings: <N>` | The ingest runs that fed the window produced N distinct warnings, printed under Coverage as `ingest warning:` lines. | Look each text up in [ingest warnings](troubleshooting.md#ingest-warnings). `sudo tvgw ingest` runs ingest now and prints its warnings to stderr. The same warning every hour is a real fault. |

### Lines worth an answer

These are not red lines, but each deserves a look when it appears. Rows follow the brief's render order.

| Line | What it means | What to do |
|---|---|---|
| `NOT ASSESSED` in Coverage | That source was not read recently or its input is missing, so its sections are unknown. | Find the cause in [ingest warnings](troubleshooting.md#ingest-warnings). |
| Firewall held: `DNS forced to AdGuard` above 0 | The TV sent DNS to another resolver and the firewall redirected it to AdGuard. The TV has hardcoded resolvers ([design decision 2](design-decisions.md#2-isolate-first-then-filter)). | Note a rise after a firmware change. |
| While off/asleep with traffic | Lookups or connections in hours the TV reported itself neither `Active`, nor on with its panel dark (`Screen Off`), nor in its screen saver at both hourly readings; the hours shown are the time those readings span. | `tvgw tvstate 2d` shows the readings and the TV's settings. |
| Blocked names still reached over TLS | A name with blocked lookups that the TV still sent a TLS hello for: a cached or hardcoded answer, or a rule that changed in the window. | If its allowed lookups are 0, the TV reached it by address. `tvgw host <name>` lists the addresses; add them to `block4.txt` ([manual IP blocks](#manual-ip-blocks)). |
| DNS-gated egress (count-only) | New connections to addresses no lookup in the last day returned ([design decision 18](design-decisions.md#18-dns-gated-egress-starts-as-a-count-in-its-own-table)); the count is never below the samples. Samples under `just looked up` came within two seconds of an answer naming the address: the TV connected before the feeder, a few milliseconds behind the answer, had added it. Of the rest, a sample with a TLS name was known to a lookup the gate had forgotten; `(none)` is a hardcoded server or a resolver bypass. A second table, `unexplained:`, lists the samples no answer of the week before explains; the analyst is asked only about those ([design decision 22](design-decisions.md#22-a-pass-that-proposes-nothing-is-remembered)). | Look at the address's connections with `tvgw sql "select datetime(t_start,'unixepoch','localtime'), dport, bytes_up, bytes_down from flows where dst='<address>' order by t_start desc limit 10"`. If it is a tracker, add it to `block4.txt`. |
| List changes: `newly blocks` without `CARRIED CONTENT` | (lists) A list began blocking a name the TV used, with a telemetry-sized shape. Usually what the list is for. | Read the row; if an app misbehaved since `since`, treat it as the red line above. |
| List changes: `newly allows` | (lists) A list stopped blocking a name the TV now resolves. | If it is a tracker you want kept out, add a rule to the profile's `.rules` file and deploy; the profile's rules do not depend on any list. |
| Rules the gateway added on its own, verdict `reverted` | A watch took a machine rule out; the reason says which. | Read the proposal's `Applied:` line and [taking a rule out](analyst-and-autonomy.md#taking-a-rule-out). |
| Rules the gateway added on its own, `on probation, untested` | A machine rule's trial reached 14 days without two TV hours with demand, or the days before it held nothing to compare with ([design decision 41](design-decisions.md#41-the-autonomy-refuses-what-it-cannot-see-and-keeps-what-it-decided)). It stays in place and watched for harm, and it is listed every day until you decide. | Keep it, adopt it into the profile's `.rules` with a dated comment and then `sudo tvgw undo` the machine's copy, or `sudo tvgw undo` it. `tvgw sql "select * from decisions where rule='<rule>' order by id"` shows its history. |
| Rules the gateway added on its own, `queued` | A block that cleared the code's gates while another rule was on trial. It waits its turn; then the gates run again on fresh evidence and the second model is asked. | Nothing. `sudo tvgw autoblock list` shows the queue. |
| Unexpected ports | TV traffic to ports other than 80, 123 and 443. | See [STRICT_PORTS](#strict_ports). |
| Unresolved flows | TCP destinations no DNS answer or TLS name explains: a hardcoded address or a DNS bypass. | Look the address up as for DNS-gated egress; if it is vendor telemetry, add it to `block4.txt`. |
| Firmware | A firmware version that differs from the reading before it, and the names first seen around it. The first firmware reading a store holds is not an update and is not shown. | Judge the new names as New hosts; each firmware update can bring new endpoints ([design decision 4](design-decisions.md#4-no-rooting-of-the-tv)). |

## Changes in effect

(ledger) The brief prints "Changes in effect" after the red lines and the summary lines, before the tables and before "Rules the gateway added on its own", so what changed is read before what the machine concluded ([design decision 48](design-decisions.md#48-one-ledger-of-changes-one-hour-classifier-and-a-second-judge-that-only-watches)). It appears once the change ledger has anything for the window: a sample, a change, or a machine rule on trial. An example, with no real names:

```text
Changes in effect (11-02 00:00 .. 11-03 00:00; ~ marks a time known to 10 minutes):
  On trial   ||beacon.example^   added 11-02 03:50; clean TV hours 3 of 6 needed; judge: watching; judge v2 (shadow): watching
  Gateway    ~03:50 AdGuard restart   14:05 deploy (metric-affecting)   DHCP change (wlan0) x12   apply (nm-dispatcher) x12
  Uplink     ~20:10-20:40 PIA not connected (Reconnecting)   21:02 VPN up (tun0)
  TV path    TV link flaps: 0   conntrack: max 262144, peak 3% full
  TV         firmware unchanged (04.64.00)
  Evidence   capture: no hour without names   conntrack lost events: 0 run(s)   connections broken by the gateway: 0
  Hours      TV on 6: clean 3, confounded 2 (PIA not connected 20h; Wi-Fi degraded 21h), no demand 1 (input or launcher in front 22h)
```

- **On trial**: each machine rule on probation in the window, with its clean TV hours toward judge v2's K, the shipped judge's state and judge v2's latest shadow verdict.
- **Gateway, Uplink, TV path**: class-A changes with their times (a `~` time comes from a 10-minute sample), class-B changes as counts with their trigger. Class A can move what the judge measures: an AdGuard restart, a deploy that changed the code, an apply that touched routing, a VPN or link event, a reboot, conntrack drops or pressure. Class B cannot: an apply that left routing alone, a DHCP renewal, a list refresh.
- **TV**: the firmware read in the window.
- **Evidence**: hours whose capture named nothing, ingest runs that reported lost conntrack events, connections the gateway broke.
- **Hours**: the hour classifier's count of the window's TV hours, with the reason of up to four hours of each kind. Only clean hours can judge a rule.

`tvgw changes 1d` lists the rows behind it, and `tvgw sql "select * from gw_samples order by t desc limit 3"` the latest samples. A line `(no gateway samples in this window: ...)` means `tvgw verify --record` did not sample: check `LEDGER` and `systemctl list-timers tvgw-verify.timer`.

## Deploying and rolling back

### Deploying

On your workstation:

1. Run `make gate` and check that it exits 0. CI runs the same.
2. Run `make deploy PI=<ssh-host>`. It copies the working tree, uncommitted changes included, to a staging copy on the Pi, `~/tvgw-deploy/`, leaving out what `deploy/rsync.exclude` lists, then runs `sudo tvgw-deploy/deploy/sync-install.sh` there. That script takes the install lock (`/run/tvgw/install.lock`, waiting up to 10 minutes), copies the staging tree to `/opt/tvgw/src/` with `rsync --delete` and runs `install.sh` with the lock handed down, so a CI deploy cannot replace the tree under it, nor it under a CI run. The installer's steps are in [what install.sh does](../deploy/README.md#what-installsh-does).
3. Read the end of the output. The installer ends by running `tvgw verify` and exits with its status, so a FAIL fails the deploy. Treat any FAIL as an outage until it is explained ([incidents](incidents.md)).
4. Run `make hardware PI=<ssh-host>` for the hardware suite. It runs under the same install lock, so no deploy replaces the tree while it runs.
5. On the Pi, run `sudo tvgw adguard diff`. It must exit 0.

On your workstation:

```sh
make gate
make deploy PI=<ssh-host>
make hardware PI=<ssh-host>
```

A push to `main` deploys the same way from CI ([how a change reaches the gateway](../deploy/README.md#how-a-change-reaches-the-gateway)). During a deploy AdGuard Home restarts only when its config changed, and the firewall is re-applied in place rather than restarted: the counters reset, and the stop path's blackout is avoided.

`tvgw adguard apply` run by itself uses the profile inside the installed package, not the files in `/opt/tvgw/src` ([design decision 6](design-decisions.md#6-adguard-home-is-configured-as-code)). Change policy by deploying; editing the copy on the Pi changes nothing.

### Rolling back the code

On your workstation:

1. Check out the last good commit, and check with `git status` that nothing uncommitted would go with it.
2. Run `make deploy PI=<ssh-host>`. `sync-install.sh` replaces the tree on the Pi with `rsync --delete`, and the installer reinstalls the package, scripts and units and re-applies AdGuard from the older profile.
3. Finish with steps 3 to 5 of [deploying](#deploying).

Rolling back to a commit from before the `ct_events` chain (2026-11-01) takes two more commands on the Pi, since the older installer and `tvgw-apply` leave the conntrack events switch at `0` with no rule to mark the TV, and the flow log would record nothing ([design decision 43](design-decisions.md#43-the-flow-log-hears-the-tv-alone-and-the-gates-day-starts-at-each-answer)):

```sh
sudo rm /etc/sysctl.d/60-tvgw.conf
sudo sysctl -w net.netfilter.nf_conntrack_events=2
```

### Rolling back AdGuard alone

Each `tvgw adguard apply` that changes something first copies the live config to `AdGuardHome.yaml.bak-<stamp>-<pid>` beside it, where `<stamp>` is the UTC time such as `20261027151500Z`, and never over an earlier copy (`_backup` in `src/tvgw/adguardcfg.py`). The newest copy is the config from before the newest apply. Nothing prunes them.

On the Pi:

1. List the copies and pick one.
2. Stop AdGuard Home, put the copy back, and start it.
3. Run `sudo tvgw verify`; `resolver_rewrite` and `resolver_must_allow` must pass.

On the Pi:

```sh
sudo ls -l /opt/AdGuardHome/AdGuardHome.yaml.bak-*
sudo systemctl stop AdGuardHome
sudo cp /opt/AdGuardHome/AdGuardHome.yaml.bak-<stamp>-<pid> /opt/AdGuardHome/AdGuardHome.yaml
sudo systemctl start AdGuardHome
sudo tvgw verify
```

To go back to the previous binary as well, with the service stopped, copy the `AdGuardHome.bak-<stamp>-<pid>` an upgrade left over `/opt/AdGuardHome/AdGuardHome` together with the `AdGuardHome.yaml.bak-<stamp>-<pid>` of the same stamp, start it, and run `sudo tvgw adguard diff`. Passing the `.bak` binary to `sudo tvgw adguard upgrade` works too, but only while the live YAML is at schema 34 or below: above it, upgrade refuses the live file like apply does ([the schema ceiling](adguard.md#the-schema-ceiling)).

This leaves AdGuard out of line with the repository: `tvgw adguard diff` reports drift and the hardware suite fails until they match. The next apply of AdGuard's config puts the profile's back, whoever runs it: a deploy or `tvgw adguard apply`, `tvgw undo`, or, with `ANALYST_APPLY=auto`, the analyst after an autonomous block or the hourly check after a revert. Roll the repository back as well, or apply again. `tvgw adguard apply --dry-run` and `tvgw adguard diff` show the changes without making them, and an apply that fails rolls itself back ([AdGuard apply failures](troubleshooting.md#adguard-apply-failures)).

### Rolling back a firewall setting

On the Pi:

1. Edit `/etc/tvgw/tvgw.conf` and put the old value back. `tvgw-apply` reads `UPLINK`, `WAN_IF`, `WAN_GW`, `BLOCK_QUIC`, `STRICT_PORTS`, `DNSGATE`, `TV_IF`, `TV_NET`, `GW_IP`, `CAPTURE_MODE`, `VPN_IF` and `ADTECH_PORT_WALL`, and `TV_IP` with `TV_MAC` for the forward pin ([the settings file](../deploy/README.md#the-settings-file)).
2. Run `sudo tvgw-apply`. Prefer it to `systemctl restart tvgw`, because a restart runs the stop path first and the TV is dark for a moment ([the firewall](../deploy/nftables/README.md)).
3. Run `sudo tvgw verify`.

### Removing the guard in an emergency

The guard table `inet tvgw_guard` keeps the Pi closed to the TV subnet at all times ([the guard](../deploy/nftables/README.md#the-guard)). It only narrows what `inet tvgw` allows, so it is never the reason the TV is offline unless it was edited. If you must lift it, for a test or because a broken render drops what it should not, on the Pi:

```sh
sudo systemctl disable tvgw-guard.service    # the next boot does not load it again
sudo nft delete table inet tvgw_guard        # the only thing that removes it now
sudo tvgw verify                             # guard_present FAILs until it is back
```

The unit is disabled rather than masked: `install.sh` installs it into `/etc/systemd/system`, and `systemctl mask` refuses a unit whose file is there. The next deploy enables and loads it again, so hold deploys (or set the CI job aside) while it is off.

This is the only way, by design. `tvgw-guard.service` has no `ExecStop`, so a stop could not remove the table, and it refuses a manual stop or restart (`RefuseManualStop=yes`), so an upgrade, a typo or a script cannot open the Pi for even a second. Removing the package leaves the table in the kernel too, until the next boot. While it is gone, the Pi is open to the TV whenever `inet tvgw` is not loaded, as it was before decision 42; the co-tenants' `IPAddressDeny` drop-ins still hold.

To bring it back:

```sh
sudo systemctl enable tvgw-guard.service && sudo systemctl reload-or-restart tvgw-guard.service
sudo tvgw verify                             # guard_present is OK again
```

Not `enable --now`: after `nft delete table` the oneshot unit is still active (`RemainAfterExit=yes`), and a start of an active unit does nothing, so the table would stay gone. `reload-or-restart` reloads an active unit (its `ExecReload`, one `nft -f`) and starts an inactive one; a plain `restart` is refused (`RefuseManualStop=yes`). Re-running `install.sh` does the same: it renders `/etc/tvgw/guard.nft` again, enables the unit, and reloads it whenever the table is missing or differs from what the unit loaded. A drop-in of the hardening that took a co-tenant or dnsmasq down comes out the same way: delete the file `install.sh` names in its `WARNING`, `sudo systemctl daemon-reload`, and restart that service.

## Changing policy

The repository is the source of truth for what AdGuard Home blocks and allows ([design decision 6](design-decisions.md#6-adguard-home-is-configured-as-code)). The owner's rules live in the profile, the gateway's own rules in a file it owns on the Pi, and manual IP blocks in `/etc/tvgw/block4.txt`.

<picture>
  <source media="(prefers-color-scheme: dark)" srcset="diagrams/fig-5-policy-files.dark.png">
  <img alt="Six files hold policy: lg-webos.toml, lg-webos.rules and block4.txt, edited by the owner; auto.rules, written by the machine; tvgw.conf, the site settings; and doh4.txt, fetched. tvgw adguard apply turns the profile's generated rules, the owner's blocks and the machine's blocks into AdGuard Home's configuration; tvgw-apply turns the IP blocks and the DoH addresses into the firewall; both read tvgw.conf." src="diagrams/fig-5-policy-files.light.png" width="960">
</picture>

*Which file holds which rule: the owner edits two repository files and one file on the Pi, and the machine edits only auto.rules.*

### The owner's rules

On your workstation:

1. Edit `src/tvgw/profiles/lg-webos.toml` (categories, must-allow hosts, blocklists, the URL filter, `strip_qtypes`) or `src/tvgw/profiles/lg-webos.rules` (AdGuard rules). Give each new block a dated reason and, when blocking it breaks a feature, its cost ([design decision 15](design-decisions.md#15-blocklist-entries-come-from-evidence-with-grades)). The file format is in [the profile format](adding-a-profile.md#the-profile-format).
2. Run `make gate`. The unit tests include the profile lint.
3. Run `make deploy PI=<ssh-host>`. The installer runs `tvgw adguard apply`.
4. On the Pi, run `sudo tvgw adguard diff`. It must exit 0.

The next brief's Rule changes section shows the change.

### Generated rules

`tvgw adguard apply` builds three kinds of rule from the TOML (`adguard_rules` in `src/tvgw/profile.py`). Never write them by hand: a hand-written copy in the `.rules` file is dropped as a duplicate, and the TOML stays the one place to edit ([design decision 7](design-decisions.md#7-must-allow-exceptions-are-generated-from-the-toml)).

| Rule | Generated from |
|---|---|
| `@@\|\|<host>^$important`, one per host | `[must_allow]` |
| `\|\|<host>^$dnsrewrite=<GW_IP>`, one per host | `[url_filter] hosts` and `GW_IP` |
| `\|\|*^$dnstype=HTTPS\|SVCB,client=<TV_IP>` | `[adguard] strip_qtypes` and `TV_IP` |

`tvgw adguard diff` and `tvgw adguard apply` run the profile lint first and refuse a profile that fails it.

### The URL filter and nginx

If you change `[url_filter] block_regex` or `hosts`, change `deploy/nginx/tvgw-gfts.conf` and `deploy/nginx/stream.conf` to match. `test_nginx_conf_matches_the_profile` in `tests/unit/test_profile.py` fails `make gate` until the block regex, the `server_name` list and the passthrough map agree with the profile ([design decision 8](design-decisions.md#8-a-url-filter-for-lgs-file-service-instead-of-a-dns-block)).

### Manual IP blocks

Use `block4.txt` for an endpoint the TV reaches by a hardcoded address, which DNS cannot stop. It is a site file: `install.sh` creates it once and never overwrites it.

On the Pi:

1. Add one IPv4 address or CIDR per line to `/etc/tvgw/block4.txt`.
2. Run `sudo tvgw-apply`. It loads the lines into the nft set `block4`, whose rule rejects new connections to them. It must end with `tvgw: applied (...)`. An nft error means it rejected a line, and the old set stays loaded.
3. Run `sudo tvgw verify`.

Open connections survive a new block ([established connections](#established-connections)).

### The machine's rules

With `ANALYST_APPLY=auto` the gateway adds blocks to `/var/lib/tvgw/auto.rules` on its own, and `tvgw adguard apply` appends them to the profile's rules after the same lint. The machine never edits the profile. To take one of its rules out, see [taking a rule out](analyst-and-autonomy.md#taking-a-rule-out).

Never make these changes in AdGuard's web UI ([the AdGuard web UI](#the-adguard-web-ui)).

## Restoring a backup

Restore a checked copy when the store is damaged or lost. The copies are in `/var/lib/tvgw/backup/`, and pulled copies are in `backups/` on your workstation ([backups](privacy-and-retention.md#backups)). Copy a workstation copy to the Pi first.

On the Pi:

1. List the copies. Their names are UTC times.
2. Stop the timers of every unit that writes the store.
3. Wait until none of those units is running: no line of `systemctl is-active` may say `active` or `activating`.
4. Move the current store aside, with its journal file if there is one. A leftover journal would be rolled back into whichever file carries the store's name.
5. Install the copy with the store's owner and mode.
6. Check it: `PRAGMA quick_check` must print `ok`, and `tvgw size` shows the row counts and the oldest DNS row.
7. Start the timers again.
8. Run `sudo tvgw ingest`. The copy carries the log read positions of the moment it was made, so ingest picks up from there. A `log rotated or truncated` warning means lines written since then are gone, and Coverage shows the gap. Pcaps still on disk that the copy has not read are read again; rows from pcaps pruned since the copy are gone.

On the Pi:

```sh
sudo ls -l /var/lib/tvgw/backup/
sudo systemctl stop tvgw-analyze.timer tvgw-verify.timer tvgw-autoblock.timer tvgw-analyst.timer tvgw-analyst-weekly.timer tvgw-backup.timer
systemctl is-active tvgw-analyze tvgw-verify tvgw-autoblock tvgw-analyst tvgw-analyst-weekly tvgw-backup
sudo mv /var/lib/tvgw/tvgw.db /var/lib/tvgw/tvgw.db.old
sudo mv /var/lib/tvgw/tvgw.db-journal /var/lib/tvgw/tvgw.db-journal.old   # only if it exists
sudo install -m 640 -o root -g adm /var/lib/tvgw/backup/<copy> /var/lib/tvgw/tvgw.db
sudo tvgw sql "PRAGMA quick_check"                                         # must print ok
tvgw size
sudo systemctl start tvgw-analyze.timer tvgw-verify.timer tvgw-autoblock.timer tvgw-analyst.timer tvgw-analyst-weekly.timer tvgw-backup.timer
sudo tvgw ingest
```

9. With `ANALYST_APPLY=auto`, compare the record with the machine's file: `sudo tvgw autoblock list` against `sudo cat /var/lib/tvgw/auto.rules`. A rule the restored record lacks is neither judged hourly nor removed by `tvgw undo`: delete its line from the file and run `sudo tvgw adguard apply`. A recorded rule that is not in the file is recorded as reverted at the next hourly check.
10. Once the restored store checks out, delete the old one, which holds the same personal data: `sudo rm /var/lib/tvgw/tvgw.db.old`.

## Forgetting the viewing record

`tvgw forget` deletes the gateway's record of what the household watched and keeps the gateway itself ([forgetting](privacy-and-retention.md#forgetting)). Use it when someone in the household asks, after guests, or before the Pi or its card changes hands. It is all or nothing: there is no per-day or per-name form.

What goes: the store's rows that hold names, addresses or times of use (`flows`, `dns`, `tls`, `tls_noname`, `http`, `lanprobe`, `tvstate`, `oddport`, `gate`, `adport`, `hosts`, `judgments`, `decisions`, `auto_queue`, `changes`, `gw_samples`, `judge_shadow`, `ingest_runs`, `pcaps_done`), every finished pcap, every report, proposal and pack, `tvcheck.txt`, the copies in `backup/`, the name keys, the change ledger's unread spool (`changes.spool` and `.1`), `tvgw tvprobe`'s `probe/` directory, and the flow, URL-filter, TLS-passthrough and TV-reading logs with their rotations. The live logs are emptied in place, because their writers keep them open. With `--querylog`, AdGuard Home's query log is emptied too.

What stays: the settings, `rules`, `auto_rules` and `auto.rules`, `verify` and `fw_counters`, `tvsettings`, the schema and the bookkeeping in `meta`, the pairing key, the DoH list, and the pcap the capture is writing.

On the Pi:

1. Read what would go. It prints counts and sizes, never a name:
   ```sh
   sudo tvgw forget --dry-run
   ```
2. Pick a time outside the analyst's runs (`ANALYST_SCHEDULE`, 03:50, and `ANALYST_WEEKLY_SCHEDULE`, Monday 04:10, by default): a pass that read the store before the forget writes its proposals after it.
3. Run it. It asks you to type `forget`; `--yes` skips the question, and without a terminal it refuses unless given:
   ```sh
   sudo tvgw forget
   ```
4. Check the result: the rows are gone, the store is sound, and one fresh copy is in `backup/`:
   ```sh
   tvgw size
   sudo tvgw sql "PRAGMA integrity_check"                      # ok
   sudo ls -l /var/lib/tvgw/backup/ /var/lib/tvgw/pcap/ /var/log/tvgw/
   ```
5. Delete the copies pulled to your workstation with `make backup`, in `backups/` of your checkout.

How it works, in order, under the ingest lock so no ingest writes in between:

- The store: every forgotten table is emptied with `PRAGMA secure_delete=ON`, which overwrites deleted content with zeros, in one transaction that also records `meta.forget_before` and resets the read positions of the logs about to be emptied. Then `VACUUM`, when the filesystem has twice the file's size free, and `PRAGMA integrity_check`.
- The files: deleted or emptied as listed above. A file in the state or log directory that `forget` does not know is kept and named in a warning.
- One fresh copy of the store goes into `backup/`, and any other copy there is removed.
- For 7 days every ingest deletes rows older than `forget_before`, then removes it. Evidence of the forgotten time keeps arriving for a while: conntrack reports an idle connection two hours after its last packet and an established one at most 5 days after, the capture's open file holds up to an hour, AdGuard flushes its query log in batches, and the journal's lines wait out an ingest that was down. A connection that began before the forget goes too.

What it cannot reach, which it prints on every run:

- the systemd journal, `JOURNAL_DAYS` days: journald cannot delete chosen entries, and `journalctl --vacuum-time` would delete every service's history;
- AdGuard Home's statistics, and its query log without `--querylog`;
- the copies on your workstation;
- the analyst's requests at Anthropic, 30 days on the standard API and at least 30 on a Covered Model such as `claude-fable-5-1` ([at Anthropic](privacy-and-retention.md#at-anthropic));
- GitHub Actions logs, if a failing hardware test quoted a live value;
- the card's freed blocks.

After a forget, the brief, the analyst and the hourly judge start from nothing. The hardware suite's data checks need an hour of the TV in use before they pass again; `test_backup_copy_is_fresh_and_sound` accepts the emptied copy for 36 hours.

## Upgrading the OS in place

The reference gateway went from Debian 12 (bookworm) to Debian 13 (trixie) in place on 2026-10-27 ([CHANGELOG](../CHANGELOG.md), Platform: Debian 13). Nothing in tvgw changed for it; the virtualenv was rebuilt on the new Python, and the hardware suite then passed unchanged. Two snags came up: needrestart restarted the upgrade's own runner, and Pi desktop packages collided.

On the Pi:

1. Run the upgrade detached from your ssh session, with `systemd-run` or inside `tmux`. NetworkManager and sshd restart during the run, and a dropped session must not take apt with it.
2. If needrestart is installed, exclude the runner's unit first. Its apt hook restarts every service whose libraries changed, the detached runner included, which then starts over from its first step. For a runner unit named `os-upgrade`, create `/etc/needrestart/conf.d/90-upgrade.conf` holding `$nrconf{override_rc}{qr(^os-upgrade\.service$)} = 0;`.
3. Bring the current release fully up to date with `apt full-upgrade`.
4. Replace `bookworm` with `trixie` in `/etc/apt/sources.list` and `/etc/apt/sources.list.d/raspi.list`, then run `apt update`.
5. Simulate with `apt-get -s full-upgrade`. Stop if the removal list holds a package the gateway needs: `network-manager`, `openssh-server`, `nftables`, `dnsmasq`, `nginx`, `libnginx-mod-stream`, `python3`, `python3-venv`, `tcpdump`, `tshark`, `wireshark-common` (dumpcap) or `conntrack`.
6. Run `apt upgrade --without-new-pkgs`, then `apt full-upgrade`, then `apt autoremove --purge` and `dpkg --audit`. Run them with `DEBIAN_FRONTEND=noninteractive` and `-o Dpkg::Options::=--force-confdef -o Dpkg::Options::=--force-confold`, so the gateway's edited files keep their contents.
7. If `apt full-upgrade` stops on "trying to overwrite", bookworm's `lxplug-*` and `pi-greeter` packages ship files that trixie's `lxpanel` and `raspberrypi-ui-mods` own. Finish with `dpkg --configure -a`, `apt-get -f install` and `apt-get full-upgrade -o Dpkg::Options::=--force-overwrite`. A gateway without the desktop does not meet this.
8. Reboot.
9. Rebuild the virtualenv, which was built for the old Python: delete `/opt/tvgw-venv` and run the installer. It creates the virtualenv when `/opt/tvgw-venv/bin/python` is missing, and ends with `tvgw verify`.
10. From your workstation, run `make hardware PI=<ssh-host>`. Then check `systemctl --failed`, the VPN client and the CI runner.

On the Pi, for step 9:

```sh
sudo rm -rf /opt/tvgw-venv
cd /opt/tvgw/src/deploy
sudo ./install.sh
```

## STRICT_PORTS

`STRICT_PORTS` decides what happens to TV traffic to ports other than 80, 123 and 443 (`ODDPORT` in `deploy/nftables/tvgw-apply`). LG's ad-tech ports (4001, 4431, 4445, 4447, 8180 and 8883) never reach it while `ADTECH_PORT_WALL=yes`: the wall resets them first under its own counter, so "Unexpected ports" lists only ports nobody has explained ([design decision 45](design-decisions.md#45-the-acr-red-line-is-an-upload-test-and-a-port-wall)). With `STRICT_PORTS=no`, that traffic is logged as `tvgw-oddport:` (`limit rate 6/minute`), counted and allowed. With `STRICT_PORTS=yes`, it is rejected with `admin-prohibited`, so apps fail fast instead of hanging. NTP on port 123 is allowed either way. LG's firmware fallback to `156.147.69.32` on TCP 8080 is accepted and logged, before the port rule, in both modes.

The owner's rule is 2 clean weeks before the flip ([design decision 17](design-decisions.md#17-strict_ports-stays-off-until-two-clean-weeks)). Flip it only when:

- 2 consecutive weeks of briefs show `Unexpected ports: none`, or only entries you looked up and accepted;
- those weeks cover a firmware check, a cold boot, a Content Store install and every app the household uses (the comment in `deploy/tvgw.conf.example`);
- the `odd ports` counter in Firewall held is zero or explained.

To flip it, on the Pi:

1. Set `STRICT_PORTS=yes` in `/etc/tvgw/tvgw.conf`.
2. Run `sudo tvgw-apply`, then `sudo tvgw verify`.
3. Use the TV for a few hours across its apps. The `odd ports` counter now counts rejected packets.

To revert, set `STRICT_PORTS=no` and run `sudo tvgw-apply` again.

## Established connections

The forward chain accepts established and related traffic before it reaches the TV's rules (`ct state established,related accept` in `deploy/nftables/tvgw-apply`). A new entry in `block4.txt`, a refreshed DoH set or `STRICT_PORTS=yes` therefore stops only new connections, and so does a new DNS block. An idle TCP connection lasts up to 7440 s (2 h 04 min), the established timeout `tvgw-apply` sets.

To cut the connections to one address now, on the Pi:

```sh
sudo conntrack -D -d <address>
```

The TV opens a new connection and meets the new rule. The cut connection appears in the flow log as ended.

## The blocklists and AdGuard Home's binary

(lists) The lists AdGuard subscribes to update themselves every 24 hours and nobody reviews those updates ([lists change on their own](adguard.md#lists-change-on-their-own)). Three things watch them: the brief's List changes and its red line, and `tvgw verify`'s `list_sentinels`, which fails when a list's sentinel name stops resolving to `0.0.0.0`. On the Pi, to see which list is blocking what:

```sh
tvgw sql "select filter_id, count(*) from dns where blocked=1 group by 1"
tvgw sql "select qname, filter_id, datetime(min(t),'unixepoch','localtime') from dns where blocked=1 and filter_id>0 group by 1,2 order by 3 desc limit 20"
sudo tvgw verify | grep list_sentinels
```

AdGuard Home's binary changes only with `sudo tvgw adguard upgrade`, which checks the live config with the new binary first and rolls back on its own ([upgrading AdGuard Home](adguard.md#upgrading-adguard-home)). `sudo tvgw adguard upgrade --fetch` takes the release this tvgw pins, downloaded and checked by its SHA-256; `sudo tvgw adguard upgrade <new AdGuardHome binary>` takes one you downloaded yourself. The service runs with `--no-check-update`, so the web UI offers no update. A command that would restart AdGuard while its upstreams are down says `deferred: upstream down` and changes nothing ([the restart guard](adguard.md#the-restart-guard)): run it again once lookups resolve.

## After unblocking something

Blocked answers carry a TTL of 60 seconds (`blocked_response_ttl = 60` in `src/tvgw/adguardcfg.py`), so the TV can keep a blocked answer for up to 60 seconds after its rule is gone. After an unblock is deployed, or after `sudo tvgw undo`, wait at least that long and retry the app before you judge whether the change fixed anything. A test before then can meet the old answer.

## The AdGuard web UI

AdGuard Home's web UI listens on `127.0.0.1:3000` on the Pi only (`http.address`, set by `tvgw adguard apply`). On the Pi, `sudo tvgw adguard ui` prints how to reach it and where its password is. Reach it through an ssh port-forward. On your workstation:

```sh
ssh -L 3000:127.0.0.1:3000 <ssh-host>
```

Then open `http://127.0.0.1:3000` in a browser. When `tvgw adguard install` set AdGuard up, its user and password are in `/etc/tvgw/adguard-admin`, which only root can read. On the Pi:

```sh
sudo cat /etc/tvgw/adguard-admin
```

On a gateway whose AdGuard was set up through its own wizard, they are the ones chosen there.

Use it to browse the query log and the statistics. Do not change filters, allowlists, custom rules, upstreams or settings there: `tvgw adguard apply` owns those keys ([design decision 6](design-decisions.md#6-adguard-home-is-configured-as-code)) and writes them back at its next run, and until then `tvgw adguard diff` reports drift and `test_adguard_matches_profile_and_settings` in the hardware suite fails. Make the change in the profile instead ([changing policy](#changing-policy)).

## Post-deploy validation, 2026-11-01

The checks for the deploy of research pass 2 (design decisions 41 to 48), from every workstream's report, in the order to run them. Run them on the Pi as the owner's operator. Values in angle brackets come from `/etc/tvgw/tvgw.conf` or from an earlier step; never type a site's address in from memory. Everything is read-only unless it says otherwise, and no step changes what the TV can reach beyond what the deploy itself changes. A step whose result differs from what it expects is a finding to report, not a step to repeat until it passes. The choices these checks inform are in [owner decisions pending](design-decisions.md#owner-decisions-pending-2026-11-01).

This section is the record of what was checked. On 2026-11-01, steps 1 to 9 ran before and during the deploy, and steps 10 to 28 passed on the gateway right after it. Steps 29 to 58 remain: they need the first hour, the first days, two weeks of use, or the owner at the TV, and each subsection below says which.

### Before the deploy

Run on 2026-11-01, before the deploy.

1. **The live analyst switch** (41). `sudo grep '^ANALYST_APPLY' /etc/tvgw/tvgw.conf`. Record the value. With `auto` the gates, the queue, the armed canary and the judge go live at the deploy; with `off` only the brief's TV hours, the stored packs, the held verdicts and the prompt's wording change.
2. **The TV's pin** (42). `grep -E '^(TV_MAC|TV_IP)=' /etc/tvgw/tvgw.conf; sudo cat /var/lib/misc/dnsmasq.leases`. Expect a real MAC whose lease carries `TV_IP`. Another address still deploys: the apply keeps that lease's address in the pin until the lease moves.
3. **The co-tenants** (42). `systemctl list-unit-files --no-legend --plain smbd.service nmbd.service xrdp.service shairport-sync.service nqptp.service avahi-daemon.service ssh.service jupyterhub.service 'qbittorrent-nox@.service'`. Note which exist (`nqptp` should be absent on an AirPlay 1 build). If JupyterHub's unit has another name, set `CO_TENANT_UNITS` to match, quoted.
4. **Information only** (42). `sysctl net.ipv4.conf.all.rp_filter net.ipv4.conf.eth0.rp_filter; nginx -T 2>/dev/null | grep -nE 'pcre_jit|listen +\['; ls -l /sbin/resolvconf; grep nameserver /etc/resolv.conf; command -v bpftool || echo 'no bpftool'`. The last command says whether the bpftool hardware test will run or skip.
5. **The CX's port history** (45). Both must print nothing: `sudo tvgw sql "select dport, count(*), sum(bytes_up), datetime(min(t_start),'unixepoch'), datetime(max(t_start),'unixepoch') from flows where dport in (4001,4431,4445,4447,8180,8883) group by dport"` and `sudo tvgw sql "select dport, count(*) from oddport where dport in (4001,4431,4445,4447,8180,8883) group by dport"`.
6. **The new DNS rules change nothing today** (45). Only `blocked=1` rows, or none: `sudo tvgw sql "select qname, blocked, count(*) from dns where qname like '%rdl.lgtvcommon.com' or qname like '%wiseconfig.lgtvcommon.com' or qname like '%ads.lgtvcommon.com' or qname like '%nevoai%' group by 1,2"`. Then `sudo tvgw adguard diff` shows the Nevo regex replacing the exact rule and the three new `||` rules.
7. **The virtual CI** (46, 45, 42). Run the virtual workflow on the integration branch (a pull request or `workflow_dispatch`) with `TVGW_VIRTUAL_REQUIRED=1`: all five `test_virtual_adguard.py` tests pass, and keep the `adguard/` artifacts (`check-config.txt`, `AdGuardHome.planned.yaml`, `AdGuardHome.saved.yaml`, `AdGuardHome.after.yaml`, `dns_config.txt`). A failure of `test_adguard_keeps_the_owned_keys_as_the_plan_wrote_them` after the forced save (for example `90d` written back as `2160h`) is the answer to deep dive 06 F5: the plan should then write durations as AdGuard does. The 64 `--check` variants pass, and in the `[direct]` and `[strict]` matrix rows TCP 4431 from the TV is `reject` with only the `LG adtech port` counter moving.

### The deploy

Run on 2026-11-01, during the deploy.

8. **The install log** (CI's hardware job: `install.sh`, then the suite). Expect:
   - no `tvgw: WARNING: dnsmasq ...` and no `tvgw: WARNING: nginx ...` (42);
   - a `tvgw: wrote /etc/systemd/system/<unit>.service.d/10-tvgw-not-from-tv.conf` line per installed co-tenant, and `tvgw: changed /etc/avahi/avahi-daemon.conf` (42);
   - `tvgw adguard: AdGuardHome restarted with --no-check-update (...20-tvgw-no-update.conf)` on the first deploy, `... is in place` later, then `tvgw adguard: applied N change(s)` with N of 1 or more on the first deploy (46);
   - `tvgw: journald: /etc/systemd/journald.conf.d/50-persistent.conf sets MaxRetentionSec=<the owner's span>; ... keeps the journal 14day instead, for every service (JOURNAL_DAYS in tvgw.conf)`, or `which tvgw cannot compare with its own`, never "longer" or "shorter", for a span it cannot parse (47);
   - the apply's summary ending in `adtech_wall=yes, dnsgate=..., doh4=<n> entries, tv_pin=<TV_IP>)` (42, 45);
   - the install ending with `tvgw verify` exiting 0.
9. **The hardware suite passes**, including `test_store_is_fresh_sound_and_at_the_current_schema`, `test_the_guard_is_loaded_enabled_and_cannot_be_stopped`, `test_cotenant_ip_filters_are_attached_to_their_running_cgroups` (passes, or skips with "bpftool is not installed"), `test_verify_passes_on_the_live_gateway`, `test_url_filter_blocks_and_passes`, `test_tls_passthrough_reaches_the_real_host`, `test_the_adtech_port_wall_is_loaded_as_the_settings_say`, `test_ingest_twice_duplicates_nothing` (now with `adport` and `changes`), `test_installed_file_matches_the_checkout[deploy/sysctl/60-tvgw.conf]`, `test_installed_files_match_checkout` for `/etc/logrotate.d/tvgw`, `test_backup_copy_is_fresh_and_sound`, `test_state_is_not_world_readable`, and `test_autoblock_file_record_and_resolver_tell_one_story`, which runs `tvgw autoblock check --no-watch` (it never watches the TV, and exits 0 having judged nothing when the timer's check holds the lock).

### Right after the deploy

Passed on the gateway on 2026-11-01.

10. **Schema 9** (41, 45, 48). `tvgw sql "select value from meta where key='schema'"` prints 9. `tvgw sql "select name from sqlite_master where name in ('decisions','auto_queue','decisions_append_only','adport','changes','gw_samples','judge_shadow') order by 1"` gives 7 rows. `tvgw sql "select name from pragma_table_info('auto_rules') where name in ('canary','trial_id')"` gives 2. `tvgw size` lists `adport 0`, `decisions`, `auto_queue`, `changes`, `gw_samples` and `judge_shadow`.
11. **`decisions` is append-only**, on a scratch copy only (41): `sudo cp /var/lib/tvgw/tvgw.db /tmp/t.db && sqlite3 /tmp/t.db "insert into decisions(t,stage,outcome) values(0,'gate','ok'); update decisions set outcome='x';"; rm -f /tmp/t.db`. Expect `decisions is append-only`.
12. **`sudo tvgw verify`**: no FAIL, and among the lines:
    - `OK   guard_present`, `OK   guard_quiet: ...`, `OK   cotenants_denied: <installed units>`, `OK   dnsmasq_caps: CapEff 0000000000000000: none` with no "bounding set keeps" (42);
    - `OK   flowlog_events: TV connections only; N events dropped since the logger started`, and `dnsgate` OK, not WARN (43);
    - `OK   adguard_version: v0.107.79`, `OK   list_sentinels: 3 lists in force`, `OK   adguard_pinned` (46);
    - `ruleset_unchanged` and `applied_current` OK, also with a conf that never names `ADTECH_PORT_WALL` (45).
13. **The guard** (42). `systemctl status tvgw-guard --no-pager; systemctl is-enabled tvgw-guard; sudo nft list table inet tvgw_guard`: `active (exited)`, `enabled`, three chains at `priority filter + 10`, and the counter of `guard: TV may not reach other Pi services` at 0, staying 0 while the TV is in use. Then `sudo systemctl stop tvgw-guard; echo $?; sudo nft list tables | grep tvgw_guard`: `Operation refused, unit tvgw-guard.service may be requested by dependency only`, exit 1, the table still listed. Then `sudo cmp <(sudo nft -s list table inet tvgw_guard) /run/tvgw/guard.applied && echo same` prints `same`.
14. **Source pinning** (42). `sudo nft list chain inet tvgw input | grep 'TV source outside its subnet (input)'; sudo nft list chain inet tvgw forward | grep 'TV source is not the TV'; sysctl net.ipv4.conf.eth0.rp_filter`: both rules, the forward one reading `ip saddr != { <TV_IP> }`, and `rp_filter = 1`.
15. **The adtech port wall** (45). `sudo nft list chain inet tvgw tv_out`: after the `manual IP blocks` line and before the `156.147.69.32` 8080 line and the `tvgw-oddport` line, `tcp dport { 4001, 4431, 4445, 4447, 8180, 8883 } limit rate 6/minute burst 5 packets log prefix "tvgw-adport: "` and `... counter packets N bytes M reject with tcp reset comment "LG adtech port"`. `grep ADTECH /run/tvgw/settings.applied` prints `ADTECH_PORT_WALL=yes`; `journalctl -u tvgw -n 5` shows `adtech_wall=yes`.
16. **The flow log's kernel switch and rule** (43). `sysctl net.netfilter.nf_conntrack_events net.netfilter.nf_conntrack_acct net.netfilter.nf_conntrack_timestamp` gives 0, 1, 1; `cat /etc/sysctl.d/60-tvgw.conf` holds the same three keys; `sudo nft list chain inet tvgw ct_events` shows `iifname "<TV_IF>" ip saddr <TV_NET> ct state new ct event set destroy comment "flow log: TV connections only"`.
17. **The flow log's listeners** (43). `awk '$2==12 && $4!="00000000"' /proc/net/netlink` lists only `tvgw-flowlog`'s conntrack (map the Pids with `ps -p`). `pid=$(systemctl show -p MainPID --value tvgw-flowlog); sudo ss -f netlink -a -p -m | grep -A1 "pid=$pid,"`: two sockets near `rb212992`, the event socket at `d0` or a small `d` after an evening of torrents.
18. **The VPN boundary** (44). `sudo nft list chain inet tvgw input | grep unsolicited` shows `iifname { "tun0", "wgpia0" } ct state new counter drop`. `sudo nft list chain inet tvgw post_leaks`: two counters, both 0 while PIA is Connected. `sudo timeout 5 piactl get connectionstate` prints exactly `Connected` (this also shows whether piactl answers as root). `ip rule show`: 50, then 60 (tvgw), then 70 (PIA's fwmark 0x3214). `ip route get 1.1.1.1 from "<TV_IP>" iif "<TV_IF>" mark 0x3214`: `dev <WAN_IF> table 100`. `piactl get protocol; ip -br link | grep -E 'tun0|wgpia0'`: `openvpn` and `tun0`.
19. **The co-tenants' walls** (42). `for u in smbd nmbd xrdp shairport-sync avahi-daemon ssh jupyterhub; do systemctl show -p Id -p IPAddressDeny -p ControlGroup $u.service; done`: each installed unit shows `IPAddressDeny=<TV_NET>`. With bpftool: `sudo bpftool cgroup show /sys/fs/cgroup/system.slice/smbd.service` lists `cgroup_inet_ingress` and `cgroup_inet_egress`, the proof that the daemon-reload applied the filter without a restart. If it lists nothing, report it: the co-tenants need a restart.
20. **avahi** (42). `grep -n -B1 deny-interfaces /etc/avahi/avahi-daemon.conf; ls /etc/avahi/avahi-daemon.conf.tvgw-backup; systemctl is-active avahi-daemon shairport-sync`: `deny-interfaces=eth0` directly under the `# tvgw: avahi neither answers...` comment, the backup present, both active. Owner: the Pi still appears as an AirPlay target on a phone on the home LAN.
21. **dnsmasq** (42). `systemctl cat dnsmasq | grep -c 20-tvgw-hardening` gives 1. `grep -E 'CapEff|CapBnd' /proc/$(pidof dnsmasq)/status` gives `CapEff 0000000000000000` and `CapBnd 00000000000004c3` (`capsh --decode=00000000000004c3`: chown, dac_override, setgid, setuid, net_bind_service). `sudo ss -ulnp 'sport = :67'` shows dnsmasq. `journalctl -u dnsmasq -b | grep -c 'missing required capability'` gives 0. `ls /var/lib/tvgw/.unit-stamps/ | grep refused` prints nothing.
22. **nginx** (42). `systemctl cat nginx | grep -E 'ProtectSystem|MemoryDenyWriteExecute|RestrictAddressFamilies'; sudo ss -ltn | grep -E '<GW_IP>:(80|443) '; systemd-analyze security nginx.service dnsmasq.service`: the sandbox lines, both listeners, lower exposure scores than before. Then `sudo systemctl reload nginx` succeeds, and `gfts.log` keeps growing while the TV uses the app store.
23. **AdGuard Home** (46).
    - `systemctl show -P ExecStart AdGuardHome` ends with `--no-check-update`; `systemctl cat AdGuardHome` shows `workdir.conf` and `20-tvgw-no-update.conf`, the latter with an empty `ExecStart=` before the full one; `tr '\0' ' ' < /proc/$(systemctl show -P MainPID AdGuardHome)/cmdline` ends with `--no-check-update`; `systemctl is-active AdGuardHome` is `active`.
    - `sudo grep -n -E 'schema_version|filters_update_interval|ignored_enabled|cache_enabled|cache_optimistic|rewrites_enabled|blocking_mode|fallback_dns|upstream_timeout' /opt/AdGuardHome/AdGuardHome.yaml`: `schema_version: 34`, `filters_update_interval: 24`, `ignored_enabled: false` twice, `cache_enabled: true`, `cache_optimistic: true`, `cache_optimistic_answer_ttl: 30s`, `cache_optimistic_max_age: 12h`, `rewrites_enabled: true`, `blocking_mode: default`, `fallback_dns: []`, and `upstream_timeout` as it is (the guard's first probe waits that plus 2 s).
    - `sudo tvgw adguard diff` prints `AdGuard Home matches the profile and settings` and exits 0; run it again after any save in the web UI: drift it did not cause is a finding and must match the virtual test's result (step 7).
    - `sudo tvgw adguard apply` with nothing to change prints `AdGuard Home already matches; nothing to do` and does not probe; `sudo tvgw adguard apply --dry-run` exits 0; `sudo tvgw adguard service` a second time prints `... is in place` and does not restart. Never simulate an upstream outage on the live gateway.
    - `sudo grep -c tvgw-probe /opt/AdGuardHome/data/querylog.json`: up to 3 per apply from 127.0.0.1; `tvgw sql "select count(*) from dns where qname like 'tvgw-probe-%'"` is 0.
24. **The profile's DNS rules** (45). `sudo tvgw adguard diff` exits 0 and `tvgw profile` lints clean. With `dig +short @127.0.0.1` where dig exists (it is not on the Pi; `tvgw verify` resolves the sentinels instead): `aic.rdl.lgtvcommon.com`, `aic.wiseconfig.lgtvcommon.com`, `aic.ads.lgtvcommon.com`, `qs2-nevoai-iothub-12-prod.azure-devices.net` and `nevoai-iothub-54-prod.azure-devices.net` give `0.0.0.0`; `us.lgtvsdp.com` and `lgtvonline.lge.com` give real addresses; no `amagi.tv` name gives `0.0.0.0`.
25. **The journal and the logs** (47).
    - `sudo logrotate -d /etc/logrotate.d/tvgw 2>&1 | grep -E 'error|duplicate|rotating pattern|log needs|rotate'`: no `error` or `duplicate`; three patterns: `flows.log` with `gfts.log` (weekly, 2), `gfts-tls.log` (weekly, 1), `/var/lib/tvgw/tvcheck-history.log` (daily, 35).
    - `ls /var/log/tvgw/`: only `flows.log`, `gfts.log` and `gfts-tls.log`, with at most `.1` and `.2.gz` for the first two and `.1` for the third.
    - `cat /etc/systemd/journald.conf.d/60-tvgw.conf`: `Storage=persistent`, `MaxRetentionSec=14day`, `MaxFileSec=1day`; `systemd-analyze cat-config systemd/journald.conf | grep -E '^# /|MaxRetentionSec|Storage'` lists `60-tvgw.conf` after `50-persistent.conf`.
    - `systemctl is-active systemd-journald` is `active`; `journalctl -u dnsmasq --since -10min | tail -3` and `journalctl -u AdGuardHome --since -10min | tail -3` show recent lines; `journalctl --list-boots | head -3` works.
26. **The change ledger's spool** (48). `sudo stat -c '%a %U:%G' /var/lib/tvgw/changes.spool` gives `640 root:adm`, also after `sudo tvgw-apply`. `sudo tail -n 3 /var/lib/tvgw/changes.spool` shows `<epoch>\tdeploy\ttvgw_<version>\t<12hex>\t<12hex>` <!-- (fin-release) -->; after the apply, `sudo tail -n1 /var/lib/tvgw/changes.spool` gives `<epoch>\tapply\tsudo\tunchanged`.
27. **The hourly judge** (41, 48). `sudo tvgw autoblock check` and `sudo tvgw autoblock check --no-watch` exit 0 and print `tvgw autoblock: 0 rule(s) on probation, nothing to decide` (auto_rules is empty today); `sudo tvgw autoblock list` exits 0; `sudo ls -l /var/lib/tvgw/autoblock.lock` is root's, `-rw-------`. `systemctl show -p TimeoutStartUSec tvgw-autoblock.service` gives `25min`. Optional: `sudo flock -n /var/lib/tvgw/autoblock.lock -c 'tvgw autoblock check'` prints `another check or the analyst's trial is running; the next run judges` and exits 0. `tvgw sql "select count(*) from judge_shadow"` is 0 with no machine rule.
28. **The forget dry run** (47); never a real forget on the live gateway. `sudo tvgw forget --dry-run; echo rc=$?`: `rc=0`, a "would go" table with counts and sizes, the pcap being written under "kept", the three logs and their rotations, the spool and `probe/` as emptied or deleted, a "not reached by tvgw" list, and no WARNING (a log under `/var/log/tvgw` other than the three shows as not classified and must be reported). `stat -c '%a' /var/lib/tvgw/.ingest.lock` gives 600.

### After the first hour

Not yet recorded as run.

29. **The ingest** (45, 47, 48). `sudo tvgw ingest` prints no warning. `tvgw sql "select value from meta where key='last_warnings'"` is `[]`, with no `changes:` warning. `tvgw sql "select count(*) from adport"` is 0. Kernel lines are stored scrubbed: `tvgw sql "select count(*) from oddport where raw like '%MAC=__:%'"` and the same for `gate` and `adport` give 0; `tvgw sql "select value from meta where key='minimized_raw'"` is 1; the Pi's host name is absent from `tvgw sql "select raw from oddport order by t desc limit 3"`. With the defaults: `tvgw sql "select count(*) from http where uri like '%=<%>%'"` is 0, `ls -ld /var/lib/tvgw/name-keys` says "No such file", and `tvgw sql "select value from meta where key='forget_before'"` has no row. After the ingest at :20, `tvgw changes 1d` shows a `code_deploy` row of class A.
30. **The gateway sampler** (48), 20 minutes after the deploy. `tvgw sql "select count(*), min(datetime(t,'unixepoch','localtime')), max(datetime(t,'unixepoch','localtime')) from gw_samples where t > strftime('%s','now','-1 hour')"`: 5 to 7 rows (about 144 a day). `tvgw sql "select boot_id is not null, tv_cc, wan_cc, vpn_if, vpn_present, pia_state, wlan_signal, ct_count, ct_max, ct_drop, agh_invocation is not null, agh_nrestarts, filter_mtimes is not null from gw_samples order by t desc limit 1"`: `vpn_if` `tun0` with `vpn_present` 1, `pia_state` `Connected`, `ct_max` 262144. `journalctl -u tvgw-verify -n 50 | grep -c 'gateway sample'` is 0; `systemctl --failed` is empty.
31. **The flow log's drop series and the VPN record** (43, 44). `sudo tvgw sql "select datetime(t,'unixepoch','localtime'), packets from fw_counters where rule='flowlog: event socket drops' order by t desc limit 3"`: a row every 10 minutes. `sudo tvgw sql "select value from meta where key='vpn_boundary'"`: `{"vpn_if": "auto", "device": "tun0", "pia": "Connected", ...}`. `sudo tvgw sql "select datetime(value,'unixepoch','localtime') from meta where key='vpn_seen_t'"`: within the last 10 minutes.
32. **The brief** (44, 45, 46, 48, 41). `tvgw brief | sed -n 2p` ends `..., AdGuard v0.107.79, PIA Connected; last ingest ...`. `tvgw brief` shows no `ACR-shaped upload` and no `ACR port attempts` line, and Firewall held shows `adtech ports 0`. A List changes section appears only when a list update changed something for the TV. `tvgw report --since 30d --json | jq '.acr_upload | length'` gives 0 and `jq '.acr_port.attempts'` 0. `tvgw report --json | python3 -c 'import json,sys; print(json.load(sys.stdin)["list_changes"])'` prints both lists. `tvgw report --since 6h | sed -n '/Changes in effect/,/Hours/p'` shows the Gateway, TV path, TV and Evidence rows and an `Hours      TV on N: ...` line, no `(no gateway samples ...)`, and `TV path    TV link flaps: 0   conntrack: max 262144, peak <1-3>% full`; `tvgw report --since 6h | grep -c 'report warning'` is 0.
33. **The TV's state and consent record** (41, 48), after the next :20 tvcheck. `tvgw sql "select power, count(*) from tvstate group by 1"`: record whether any `Screen Off` rows exist (expect `Active`, `Screen Saver` and unreachable today). `sudo grep -E '^(eula\.|network\.bleAdvertisingOnOff)' /var/lib/tvgw/tvcheck.txt`: 22 or more `eula.*` lines (`true`, `false` or `unknown`) and `network.bleAdvertisingOnOff = on|off|unknown`. `sudo grep -E '^(power|app|network\.wired\.state) ' /var/lib/tvgw/tvcheck.txt` still has values. `tvgw sql "select key, value from tvsettings where key like 'eula.%' order by key"` matches. No `TV consent flag` red line on the first day.
34. **The judge's timer** (41, 48). `journalctl -u tvgw-autoblock -n 5`: success; the decision or "nothing to decide" line first, no `judge v2 (shadow) failed`, no `judge v2 (shadow) stopped after`.

### In the first days

Not yet recorded as run.

35. **The flow log's acceptance test** (43), with the owner, in the same session as the deploy when possible. With qBittorrent running, `sudo timeout 600 conntrack -E -e DESTROY -o extended | wc -l` gives far fewer lines than before the change, and `sudo timeout 120 conntrack -E -e DESTROY -o extended | grep -vc "src=<first three octets of TV_NET>"` gives 0. With the TV playing, `sudo systemctl restart tvgw-flowlog`: a TV connection opened during the seconds the logger was down appears in `flows.log` when it ends (`tail -f /var/log/tvgw/flows.log`, or `tvgw sql` on `flows.t_start` around the restart).
36. **The DNS gate refresh** (43), after an hour of TV use: `sudo nft list set inet tvgw_gate resolved4 | grep -o 'expires [^,}]*' | sort | tail -3` shows about 23 h for recently resolved addresses.
37. **The TV in use** (45, 42). For a few hours: the household's apps work, `sudo nft list ruleset | grep 'LG adtech port'` shows packets 0 (non-zero is the red line; follow [its runbook](#red-lines)), and the guard's input counter stays 0.
38. **DHCP with the real TV** (42). Owner: power-cycle the TV, or wait for its next renewal. `journalctl -u dnsmasq --since -1h -g 'DHCPACK|broadcast response'` shows `DHCPACK(eth0) <TV_IP> <TV_MAC>`, the TV online, and `sudo tvgw tvcheck` answering.
39. **The dispatcher's line** (48). At the next DHCP renewal (about every 2 h), `sudo grep -c dispatcher /var/lib/tvgw/changes.spool` is 1 or more, with lines like `\tdispatcher\t<WAN_IF>\tdhcp4-change`; after the next ingest `tvgw changes 3h` lists `dhcp_change` (class B) and `apply` rows. After a PIA reconnect, `journalctl -u NetworkManager-dispatcher -n 20` shows a `tvgw-apply` run.
40. **The analyst's dry run** (41). `D=$(date -d yesterday +%F); sudo tvgw analyst --dry-run --day $D`. Then `sudo jq '[.shapes | to_entries[] | select(.value.conns == 0) | .key]' /var/lib/tvgw/reports/proposals/$D.pack.json` lists the names the gate now refuses unless their answers went unused; `sudo jq '.tv.readings_on' ...` is at least the number of `Active` readings; `sudo jq '[.previous_judgments[] | select(.kind=="held")]' ...` lists held names, each with a reason starting `held for another look`; `sudo jq '.changes_in_effect' ...` is counts only.
41. **After the next real analyst request** (41). `sudo ls /var/lib/tvgw/reports/proposals/*.pack.json | wc -l` grows with each non-quiet record. `sudo jq '.pack_sha256_16, .verifier_usage, .never_quiet' /var/lib/tvgw/reports/proposals/<stem>.json`, and, as root, `python3 -c 'import json,hashlib,sys;print(hashlib.sha256(json.dumps(json.load(open(sys.argv[1])),sort_keys=True).encode()).hexdigest()[:16])' <stem>.pack.json` equals `pack_sha256_16`. When `never_quiet` was not empty, `tvgw sql "select name, kind, reason from judgments where kind='held'"` shows those names, and the next day's run with the same evidence prints `nothing new, no request sent` unless something else is new.
42. **Calibration** (48), read-only, 1.5 to 4 minutes. First `tvgw sql "select app, count(*) from tvstate where power='Active' group by app order by 2 desc"` to confirm the input app ids (`com.webos.app.hdmi*`, `livetv`). Then `sudo tvgw autoblock calibrate --days 7 --arms A,B,C,D --by-class`: a table of arms A to D and the line `bytes: A end-time; B end-time; C prorated; D end-time (...)`, written to `/var/lib/tvgw/reports/calibrate/<date>.json`. <!-- (fin-release) --> Record arm A's alpha (the shipped judge's false-revert rate) and its NODATA rate, arm B's `revert_hour_no_demand` (how often the single-hour rule reverts on an input hour; arm A counts only demand hours, so its own is near 0 by construction), and arm D's alpha.
43. **Measurements to record, not assert** (47). `sudo du -sh /var/lib/tvgw/{tvgw.db,backup,pcap,reports} /var/log/tvgw /opt/AdGuardHome/data /var/log/journal`; `sudo head -c 200 /opt/AdGuardHome/data/querylog.json.1`; `tvgw sql "select min(datetime(t,'unixepoch')) from tvstate"`; `getent group adm systemd-journal`; `lsblk --discard`.
44. **A redeploy does not restart journald again** (47). On the next deploy, `journalctl -u systemd-journald --since -15min | grep -c 'Journal started'` is 0.

### Over two weeks

Not yet recorded as run.

45. **The gate's counts** (43). Compare with the two weeks before the deploy: the brief's "to addresses DNS never gave" on viewing days falls, and `dns_gate.unexplained` stays the same.
46. **The shadow judge and the machine's blocks** (41, 48), meaningful only once `ANALYST_APPLY=auto` has applied blocks.
    - `sudo jq -r '.proposals[]?.applied // empty' /var/lib/tvgw/reports/proposals/*.json | grep -o 'canary [a-z]*' | sort | uniq -c`: `canary armed` or `canary passed`, never `canary unobserved` at apply time.
    - `sudo sqlite3 /var/lib/tvgw/tvgw.db "select verdict, reason from auto_rules where reason like '%too little%'"` returns no new rows.
    - `sudo sqlite3 /var/lib/tvgw/tvgw.db "select stage, outcome, count(*) from decisions group by 1,2"` and `"select count(*), count(distinct name) from decisions"` (rows exceed names once a name is judged twice); `"select margins from decisions where stage='judge' order by id desc limit 1"` is JSON with `before`, `n_before`, `after`, `n_after`, `low_run` and the thresholds.
    - Once a block is armed and the TV is next watched with an app: `journalctl -u tvgw-autoblock --since today` shows one run of about 11 minutes, never the 25-minute timeout; `tvgw sql "select datetime(t,'unixepoch','localtime'), outcome, reason from decisions where stage='canary' order by id"` shows `armed`, then `passed` or `reverted`.
    - `judge_shadow` fills; after two weeks and a calibration, the owner decides whether judge v2 replaces the shipped one.
47. **The blocklists over time** (46). Over three days, `sudo stat -c '%y %n' /opt/AdGuardHome/data/filters/*.txt` shows the refresh time drifting; `sudo head -2 /opt/AdGuardHome/data/filters/*.txt` shows no `!` lines. At the next AdGuard upgrade, through `sudo tvgw adguard upgrade <new binary>`, `grep schema_version /opt/AdGuardHome/AdGuardHome.yaml` before and after.

### Owner-run, at a time the owner chooses

Not yet recorded as run; each needs the owner.

48. **TV-port flap** (48), owner present: unplug and replug the TV's cable once. Within 10 minutes and the next ingest, `tvgw changes 1h` shows `tv_flap` (sampler) and `tv_link_up` and `tv_link_down` (dispatcher) rows, class A.
49. **Neighbours unharmed** (42). In an SSH session, `cat /proc/self/cgroup` shows `user.slice/.../session-N.scope`. An RDP login with the Windows App works, JupyterHub on :8000 answers from the LAN, Samba shares mount from the LAN.
50. **The read-only probe** (48), owner at the TV. `sudo systemd-run --unit=tvgw-ssap-probe -p RuntimeMaxSec=27h -p NoNewPrivileges=yes /usr/local/bin/tvgw tvprobe --hours 26`. During the run: power off, wait 15 minutes, power on; open and close two apps; switch to an HDMI input and back; Screen Off for a minute if offered; turn on no agreement. Afterwards `sudo jq -c 'select(.kind|test("sub|power|app|link|pair|session"))' /var/lib/tvgw/probe/tvprobe.jsonl | head -50`: `sub.ok` (or `sub.err` with the TV's text), power lines with state, processing and reason, app lines, link edges around the power cycle, no `pair.rejected`, no prompt on the screen. If a prompt appears, decline it; the probe exits 2 by itself; then `sudo systemctl stop tvgw-ssap-probe`. Delete the file once read: `sudo shred -u /var/lib/tvgw/probe/tvprobe.jsonl`.
51. **The leak counter, live** (44), owner-approved, TV off, outside viewing hours. Note the counters; `piactl disconnect; sleep 60; dig @"<GW_IP>" t3-$(date +%s).example.com | grep status`; while still disconnected, `sudo systemctl start tvgw-verify`; then `piactl connect`. `sudo nft list chain inet tvgw post_leaks` shows the DoH counter above 0 (predicted from PIA's source, not yet seen); `vpn_boundary` may show `device`/`pia` null, but `vpn_seen_t` keeps the earlier time; the next brief carries `the Pi's own lookups left outside the VPN: DoH left by the uplink N time(s)`.
52. **After the next reboot** (42). `journalctl -b -u tvgw-guard -u NetworkManager -o short-monotonic | head` shows `tvgw-guard` finishing before NetworkManager starts; `sudo nft list table inet tvgw_guard` is present; `tvgw verify` passes.
53. **The guard's emergency restore** (42), TV idle. `sudo nft delete table inet tvgw_guard`, then `sudo systemctl enable tvgw-guard.service && sudo systemctl reload-or-restart tvgw-guard.service`; the table is back and `sudo tvgw verify` shows `OK   guard_present`.
54. **The stop window** (42), TV idle. `sudo systemctl stop tvgw` (the TV goes dark); from a laptop on the TV port, `nmap -Pn -sT --top-ports 200 <GW_IP>` shows only 53, 80 and 443 open, and the guard's final input drop counter has grown; `sudo systemctl start tvgw`, after which that counter stays still.
55. **Forget on a copy** (47), never on the live store. `T=$(sudo mktemp -d); sudo mkdir -p $T/state $T/log $T/pcap; sudo sqlite3 /var/lib/tvgw/tvgw.db "VACUUM INTO '$T/state/tvgw.db'"`, then from a Python shell `forget.run(Settings(state_dir=..., db_path=..., pcap_dir=..., flows_log=..., gfts_log=..., reports_dir=..., tvcheck_history=..., tvcheck_txt=..., adguard_querylog=...), lock=False)` with every path under `$T`. `sqlite3 $T/state/tvgw.db 'select count(*) from dns'` gives 0, `PRAGMA integrity_check` gives `ok`, and a `hosts` name taken from the live store is not found in the copy with `grep -c`. Finally `sudo rm -rf $T`.
56. **A ClientHello on TCP 4431** (45), needs tshark 4.4 or the namespace CI: `tshark -r hello-4431.pcap -Y 'tls.handshake.type==1' -T fields -e tls.handshake.extensions_server_name` prints the name with no `-d` option. A test of hello naming on that port, not of the wall.
57. **The .deb's removal** (43), only on a spare box, never on the gateway: after `apt remove tvgw`, `sysctl net.netfilter.nf_conntrack_events` reads 2.
58. **The read-only re-pair** (48), owner at the TV, not built: pair with the minimal manifest into a separate key file, check the reads succeed and that `button HOME` and `show_message` return 401, and only then shred the full key.
