# The brief, section by section

This page owns the daily brief and the reports built from the same data: what each line counts, in the order it prints, the thresholds behind it, and the JSON. It is for anyone interpreting a brief, a report or its JSON; the daily check and what to do about each red line are in [read your daily brief](../use/daily-brief.md). The terms it uses are defined in [the glossary](glossary.md).

## The plain brief

The plain brief is the day in seven lines, for a reader who gives it five seconds ([design decision 58](../design-decisions.md#58-the-brief-has-a-plain-form-with-three-tiers-the-login-message-shows-its-status-and-action-and-tvgw-doctor-explains-every-check)). `tvgw brief --plain` prints it. With `BRIEF_STYLE=plain`, which the settings template sets for new installs, `tvgw brief` prints it and `tvgw brief --full` prints the engineering brief below it on this page. With the key absent, as on a gateway set up before it, or with `full`, `tvgw brief` prints the engineering brief as before ([settings](settings.md)). `plain_brief()` in src/tvgw/plain.py writes it from the same data as the engineering brief, so the two never disagree.

```text
tvgw brief, Wednesday 4 November (yesterday, 24 hours)
  Protection: held all day (144 of 144 checks passed).
  The TV: on about 5 hours. It asked for known tracking services 3,983 times; every one was refused.
  Blocked most: other advertisers, device fingerprinting, LG usage reporting.
  New: nothing new.
  Action: nothing needs your attention.
Engineering report: tvgw brief --full
```

The lookup counts are one measured day of the LG CX ([what an LG CX does, measured](../tv/lg-cx-measured.md)); the hours and the check count are the illustration in tests/unit/test_plain.py.

| Line | What it says | From the report's |
|---|---|---|
| Title | The day, `yesterday` when it is, and its length: 23 or 25 hours on the days the clocks change. | `day`, `since`, `until`, `generated` |
| Protection | `held all day` when every recorded `tvgw verify` run passed and at least 90% of the runs owed were recorded (`HELD_ALL_DAY = 0.9`); `held whenever it was checked` when fewer were; `held most of the day` or `failed for most of the day` with the count of failed runs; `not checked` with none. It adds `Part of the day's record is missing.` when Coverage lists a source as `NOT ASSESSED`, other than `tvstate` and `verify` (`NOT_A_GAP`). | `firewall`, `coverage` |
| The TV | The hours on: the clock hours with a reading that says `Active`, `Screen Off` or `Screen Saver`, so the extra readings of a deploy or a reading by hand add no hour. (activity) When no reading says anything (no LAN-API reader, or not paired), the hours the TV port's counters show streaming or awake, marked `(estimated from its traffic)`, and left out when the gateway has no samples of the day either. Then the lookups in the known tracking categories and how many were refused. | `tvstate`, `categories` |
| Blocked most | The three categories with the most blocked lookups, in plain words. | `categories` |
| New | A firmware update; the new registrable domains, up to three by name; a list update that took away a name the TV downloaded from. A new name under a domain seen before is churn, a rotating video node most days, and is left out. | `firmware_changes`, `new_hosts` (`new_domain`), `list_changes` |
| Action | The first thing that needs a person, by [tier](#the-three-tiers), and how many more there are; `nothing needs your attention.` when there is none. (uplink) A day on which the router gave the gateway a new address is an act item too, after the act-tier red lines: `Your router gave the gateway a new address, and N of the TV's connections were cut. To stop this, reserve this computer's address in your router's settings.` (`uplink_moved()`). | `red_lines`, `coverage`, `changes_in_effect` |
| Not checked | After the Action line, one `Not checked:` line for each sentence in the report's `not_checked` list, where the report carries one: what the brief cannot vouch for, such as the TV's Wi-Fi when nothing reads it and the owner has not confirmed it off. It is never the Action, so `action.txt` never holds it. | `not_checked` |
| While off | (tripwire) After the Not checked lines and the [TV notes](#tv-notes), on a day the [While off or asleep](#while-off-or-asleep) line counts a lookup or a connection and the TV port's counters do not say the TV was in use then: `While off: Between two hourly checks that found it switched off, the TV went online: N lookups and C connections (<names>).`, then, with quiet counters, `The gateway saw too little traffic for anyone to have been watching, so it goes online while off.`, and with no samples, `Either it was switched on in between, or it goes online while it is off.` The names are up to three of `standby_names`, each as its registrable domain (a server's address as it is), then `and <N> more`. It follows the same three-days-running rule as Uploads, a new name counting as a change. It is never the Action ([design decision 66](../design-decisions.md#66-an-upload-budget-with-a-ceiling-set-once-count-only-and-the-names-of-a-tv-that-goes-online-while-off)). | `standby`, `standby_names`, `standby_notice` |
| Uploads | (budget) After them, on a day with a destination-hour over the [upload budget](#upload-budget)'s ceiling, late ones included: `Uploads: In one hour the TV sent <destination> <X> MB more than came back on the same connections, over the <C> MB upload budget for services outside its everyday ones. Nothing was stopped.` With several, `In <N> hours`, counting clock hours, `the TV sent <N> services (<up to three> and <M> more)` or the one destination. It adds `Part of it is from an earlier day: connections that ended only now.` for a late hour, and, when the TV's own clean hour reached the cap, `The TV's own uploads reached this size in the two weeks the budget was set from, so such hours are listed.` On the third calendar day running (`REPEAT_DAYS = 3`) it says `This has come 3 days running, so the short brief leaves it out until it changes (tvgw brief --full keeps it).`, and after that it is left out until a day without one or a new destination. It is never the Action. | `upload_budget` |

The known tracking categories are `ACR` and every category whose name starts with `ACR`, `3rd-party ads`, and a vendor's `ads`, `telemetry` and `fingerprint` categories (`is_tracking()`). Categories print in plain words from `CATEGORY_PLAIN` and the vendor suffixes in src/tvgw/plain.py (`LG telemetry` is `LG usage reporting`), or from the profile's `[category_labels]` table ([the profile format](profile-format.md#category_labels)). Text that came from the TV or from a server passes through `cli.clean()`, as in the engineering brief.

### The three tiers

Each red line has a tier in the plain brief; [the red lines](#in-the-plain-brief) give each line's.

- **act**: a person at the TV or the router has something to do. The Action line says what. For Live Plus and the ACR lines the menu path comes from the profile's `[[privacy_setting]]` record for the TV's ACR switch: the record the LAN API reads as `option.livePlus`, else the first whose `controls` names ACR, a verified one first. A profile with no such record gets "On the TV: turn this setting off (tvgw brief --full names it)."
- **doctor**: the gateway's own trouble. The Action line ends `Run sudo tvgw doctor.`, which explains in plain words each check that did not pass and offers its fix (`doctor_action()`; [the doctor](verify-checks.md#the-doctor)). A red line that no row names is in this tier (`UNKNOWN_TIER`), never in detail, so a red line added later cannot vanish from the plain view. A source not read in the day is in it too.
- **detail**: engineering only, shown in the engineering brief alone: ingest warnings, Encrypted ClientHello, the gateway's own lookups outside the VPN and a machine rule's stalled trial.

The act tier comes first, then doctor, each in the red lines' order. `RED_LINE_PLAIN` in src/tvgw/plain.py holds one row per red line: its prefix, tier, plain sentence and action. tests/unit/test_plain.py fails when `queries.red_lines()` can write a line no row names, when a row names no line, and when an action names a command this version lacks.

### The first day

On a store younger than a day (`STORE_DAY = 86400` seconds after its first ingest run, `queries.first_ingest()`), or one nothing has ingested yet, the plain brief prints `Your first brief is ready tomorrow morning.` between its title and its footer, in place of a day that is mostly `NOT ASSESSED`. `tvgw forget` empties the ingest runs with the rest of the record, so the next brief is a first day again.

## The brief and the reports

`tvgw brief` covers one calendar day and `tvgw report` covers any window. Both print the same sections, from one function, `queries.window_report()`, which computes everything from the store when the command runs; with `BRIEF_STYLE=plain`, `tvgw brief` prints [the plain brief](#the-plain-brief) instead, and `--full` these sections. The syntax of both is in [Commands](commands.md).

| Command | Window | First line |
|---|---|---|
| `tvgw brief [DAY]` | One local calendar day, yesterday by default (`queries.brief()`). | `=== 2026-10-26: ...` |
| `tvgw report --day DAY` | The same day, with the same output. `--with-plain` prints the plain brief first, then a blank line. | `=== 2026-10-26: ...` |
| `tvgw report --week WEEK` | One ISO week, Monday 00:00 to Monday 00:00 (`queries.weekly()`), with a By day table. | `=== week 2026-W44 (2026-10-26 .. 2026-11-01): ...` |
| `tvgw report` | The last 24 h up to now (`queries.latest()`). | `=== last 24 h to 2026-10-26 10:00: ...` |
| `tvgw report --since SINCE [--until UNTIL]` | Any window. | `=== 2026-10-26 00:00 .. 2026-10-27 00:00: ...` |

Days are the gateway's local calendar days, so a day on which the clocks change has 23 or 25 hours, and the ISO week 2026-W44 has 169 hours. Times are the gateway's local time. `cli.hb()` prints every size in powers of 1024 with a one-letter unit: `B`, `K`, `M` or `G`, as in `2.2K`.

### The files the hourly job writes

`tvgw-analyze` writes the same reports, as text and as JSON, under `/var/lib/tvgw/reports/` ([where it lives and who can read it](../how-it-works/privacy-and-retention.md#where-it-lives-and-who-can-read-it)). How it decides is in [the shell jobs](../../deploy/bin/README.md).

| Files | Window | When they appear |
|---|---|---|
| `latest.txt`, `latest.json` | The last 24 h. | At every run, replacing the previous pair. |
| `daily/<day>.txt`, `daily/<day>.json` | One finished calendar day. With `BRIEF_STYLE=plain` the text starts with the plain brief and a blank line; with the key absent or `full` it is the engineering brief alone, as before. The JSON carries the plain brief as `plain` either way. | Once, at the first run at least `SETTLE=10800` (3 h, in deploy/bin/tvgw-analyze) after the day ends: 03:20 with the shipped timer. Any of the last 14 finished days that has data in the store and no file yet is written at the next run. |
| `weekly/<week>.txt`, `weekly/<week>.json` | The last finished ISO week. | Once, on the same rule, from Monday 03:20. Older weeks are not written later. |
| `action.txt` | The plain brief's Action for the newest daily file, for the login message: one line, the tier (`act` or `doctor`), a tab and the text, or empty when nothing needs a person. It never holds a name, an address or a time from the record. | With that daily file, and again whenever the daily file is newer (`tvgw brief DAY --action`). |

A daily or weekly file is never rewritten, and its evidence keeps arriving after it is written: conntrack reports an idle connection 7440 seconds (2 hours 4 minutes) after its last packet, and dumpcap closes each pcap only when its clock hour ends. The archived file can therefore list a day's last connections as unnamed while `tvgw brief DAY`, computed again from the store, names them.

The analyst's proposals are not part of the brief. They are separate files in `reports/proposals/`, described in [the analyst and autonomy](../how-it-works/analyst-and-autonomy.md).

## Coverage

The Coverage line says whether the pipeline looked. It names each source with the rows it put in the window, then the AdGuard Home version once `tvgw verify --record` has recorded one, then PIA's state (`PIA Connected`, from `piactl get connectionstate` at the last recorded `verify` run) on a gateway where that command answers, then the time of the last ingest run. Under it come the `NOT ASSESSED` line, when a source qualifies, and one `ingest warning:` line per warning.

```text
Coverage: flows 2, dns 2, pcaps 1, gfts 2, tvstate 2, oddport 1, gate 0, verify 0; last ingest 10-26 10:00
NOT ASSESSED (source not read recently): verify
```

| Source | Rows it counts in the window | Its last read |
|---|---|---|
| `flows` | Connections whose conntrack report (`t_end`) falls in the window. | The last ingest run that read `flows.log` without failing. |
| `dns` | The TV's lookups. | The same, for AdGuard's query log. |
| `pcaps` | Captures read without error whose `done_at` falls in the window. | The same, for the pcap directory. |
| `gfts` | URL-filter requests from nginx's log. | The same, for `gfts.log`. |
| `tvstate` | The TV's hourly power readings. | The same, for `tvcheck-history.log`. |
| `oddport` | The unexpected-port rule's kernel-log lines. | The same, for the kernel log. |
| `gate` | The DNS gate's logged samples. | The same, for the kernel log. |
| `verify` | Recorded `tvgw verify` runs. | The last run recorded before the window's end. |

### The NOT ASSESSED rule

An ingest step stamps its source as read only when its input exists and the step finishes without failing, so a source that failed or is missing is never stamped ([design decision 14](../design-decisions.md#14-red-lines-are-the-alarm-model)). A source is `NOT ASSESSED` when it was never read, or when its last read is more than `STALE = 7200` seconds (2 hours, in src/tvgw/queries.py) before the end of the window, or before now while the window is still open. A source that is assessed with 0 rows was read and was empty.

Two sources behave differently:

- **`tvstate` on a profile without a LAN-API reader.** The history file never exists, ingest does not warn about it (`OPTIONAL_SOURCES` in src/tvgw/ingest.py), and the source is `NOT ASSESSED` every day.
- **`pcaps` in a run that could read none of them.** When ingest cannot tell which file the capture holds open, or every pending file failed, it warns and raises `SourceSkipped`, so the source is not stamped as read and becomes `NOT ASSESSED` once its last read is `STALE`, rather than an assessed hour with no rows. The warning and its red line carry the news meanwhile.

### The verify runs

The `verify` count is the `tvgw verify --record` runs recorded in the window. The brief also works out how many it should hold: one per 600 seconds of the observed window, which runs from the later of the window's start and the first run the store ever recorded, to the earlier of the window's end and now (`window_report()` in src/tvgw/queries.py). A store that never recorded a run therefore owes none: `verify` shows as `NOT ASSESSED` and no red line follows. The red lines below compare the two numbers.

### Ingest warnings

Each `ingest warning:` line is one distinct warning from the ingest runs that fed the window: the runs that started inside it or within `STALE` after its end, or after now while it is open. A brief for yesterday therefore carries the warnings of the runs up to 02:00 today, and not this morning's.

## Red lines

Each `RED LINE:` line is a sentence that must never be true ([design decision 14](../design-decisions.md#14-red-lines-are-the-alarm-model)). `queries.red_lines()` writes them in the order to act on them: the TV's needs first, then what the firewall and its watchdog say, then the pipeline. What each line means and what to do about it is in [the red lines](../use/daily-brief.md#red-lines). Each line's [tier](#the-three-tiers) in the plain brief, and its plain words, are [in the plain brief](#in-the-plain-brief) below: `act` puts it on the Action line with what to do at the TV or the router, `doctor` sends the reader to `sudo tvgw doctor`, and `detail` leaves it to the engineering brief.

| Order | The line begins | What puts it there |
|---|---|---|
| 1 | `must-allow name blocked:` | A lookup of a `[must_allow]` host came back blocked in the window. One line per name, with the count and the rule. |
| 1 | `a list update newly blocks` | (lists) A row of [List changes](#list-changes) marked `CARRIED CONTENT`: a list blocked a name for the first time that the TV had resolved, and the name's connections in the 14 days before that block carried more than 2 MB down, or a median over 16 KB per connection (decision 20's payload limits, `LIST_CONTENT_TOTAL` and `LIST_CONTENT_MEDIAN` in src/tvgw/queries.py). One line per name. |
| 2 | `Live Plus (ACR) is` | The last Live Plus reading before the window's end (`ACR_KEY` in src/tvgw/lgwebos.py) is neither `off` nor a read error. The reading may be older than the window, so the line stays on every brief until a reading says `off`. |
| 3 | `TV has a second network path:` | The last reading of a path in `SECOND_PATHS` (src/tvgw/lgwebos.py) before the window's end says Wi-Fi or Wi-Fi Direct is not `disconnected`, or Wi-Fi or Bluetooth tethering is on. One line per path. (samsung) A Samsung's reading reports Wi-Fi alone: `connected` when its reply says `networkType` wireless or carries `ssid`. |
| 4 | `clock host lookups blocked:` | A lookup matching the profile's `clock_hosts` was blocked in the window, and the profile's `[clock] model` is not `none`. |
| 5 | `TV was on but never looked up its clock host` | The profile's `[clock] model` is not `none`, no lookup matched `clock_hosts`, the TV had an `Active`, `Screen Off` or `Screen Saver` reading (`AWAKE` in src/tvgw/queries.py), and the window is at least 82800 s (23 h) long, so the day the clocks go forward counts as a whole day. Not shown with line 3. |
| 6 | `firewall checks failed` | At least one recorded `tvgw verify` run failed. The line ends with the last failure's checks. |
| 7 | `firewall checks ran` | The window owed at least 6 runs and fewer than half were recorded. |
| 8 | `ACR-shaped upload:` | `acr_uploader()` in src/tvgw/queries.py found a cell, the registrable domain of the connections' TLS name or the server's /24 when no hello named them, with the server port, that is outside `expected_categories` and uploaded at least `ACR_DAILY = (1_000_000, 4.0, 24)` in a local day (payload bytes up, times the payload down, connections) or `ACR_HOURLY = (500_000, 4.0, 5)` in a clock hour. Flows count by their start. One line per cell and day: the day when it passes, else its busiest hour, with how many hours passed. The line ends with the last Live Plus reading. This is red line 7 of the November report ([design decision 45](../design-decisions.md#45-the-acr-red-line-is-an-upload-test-and-a-port-wall)). |
| 8 | `ACR port attempts:` | The `LG adtech port` counter rose in the window, or `tvgw-adport` samples were logged in it: the TV tried TCP 4001, 4431, 4445, 4447, 8180 or 8883 and was reset. The count is the counter's increase, never below the samples. The line names the sampled ports, and the names whose A answers in the `KNOWN_DAYS = 7` days before named a sampled address, or `no lookup`. |
| 9 | `Encrypted ClientHello in` | A TLS hello in the window carried the ECH extension (`ECH_EXTENSION = 0xFE0D` in src/tvgw/tshark.py) under a known ECH public name (`ECH_PUBLIC_NAMES`: `cloudflare-ech.com` and `vercel-ech.com`), whatever the TV looked up, or under an outer name the TV never looked up in the window or the 86400 s before it: real ECH, whose outer name is the provider's public name (`ech_seen()` in src/tvgw/queries.py). Any other hello whose name the TV did look up is GREASE, the extension with random bytes and the real name outside, which Chromium 117 and later send whenever they have no ECH config; it is counted apart as `grease` and raises nothing. The line names up to 5 of the outer names. |
| 10 | `the Pi's own lookups left outside the VPN:` | The gateway's own new connections to a DoH resolver on TCP 443 or to port 53 left by `WAN_IF` in the window (the `pi leak:` counters of `post_leaks`), on a gateway with a VPN: the last recorded `verify` run found a tunnel or PIA's state, `VPN_IF` names one, or a recorded run in the 30 days before the window's end saw one, and `VPN_IF` is not `none` ([design decision 44](../design-decisions.md#44-the-tunnel-is-a-setting-and-the-pis-own-leaks-are-counted)). The counters are not in Firewall held. |
| 11 | `TV consent flag` | A flag of the TV's consent record (`eula.<flag>` in the `tvsettings` table) read `true` in the window, and its last reading of `true` or `false` before that was `false` (`consent_flips()` in src/tvgw/queries.py): an agreement accepted on the TV. A flag first read as `true` is not a flip. One line per flag. |
| 12 | `machine rule` | (ledger) A machine rule on trial whose verdict is still watching or passed has fewer clean TV hours than it needs, more than half of judge v2's 14-day ceiling (`CEILING`) after it was added: a line of [Changes in effect](#changes-in-effect) (`section()` in src/tvgw/ledger.py). |
| 13 | `TV was on but no lookups were recorded` | The TV had an `Active`, `Screen Off` or `Screen Saver` reading, at least 3600 s (1 h) of the window has passed, and the window holds no `dns` row. |
| 13 | `TV was on but no connections were recorded` | The same, with no `flows` row. |
| 14 | `ingest warnings:` | Coverage lists at least one ingest warning. |

Three things look like alarms and are not red lines. Blocked names still reached over TLS is a section, because AdGuard gives blocked answers a 60-second TTL (`blocked_response_ttl` in src/tvgw/adguardcfg.py) and a rule that changes during the day would raise false alarms. A periodic connection is listed and raises nothing, whatever its interval: a timer is an attribute, since captive-portal probes, a Hue bridge's polling and streaming heartbeats all keep one. The DNS gate's count is evidence, not an alarm.

### In the plain brief

Each red line's tier and its plain words, in the order `queries.red_lines()` writes the lines, then what the lines about screen recognition ask on each profile (`RED_LINE_PLAIN` and `action_text()` in src/tvgw/plain.py; `tools/docgen.py` writes the tables).

<!-- generated:red-lines -->
| The line begins | Plain brief | What the plain brief says | What it asks |
|---|---|---|---|
| `must-allow name blocked:` | doctor | Something the TV needs in order to work was blocked. | Run `sudo tvgw doctor`. |
| `a list update newly blocks` | act | A blocklist update started blocking a service the TV downloaded from, so an app may have stopped working. | If one did, the full report names the service and how to let it through (`tvgw brief --full`). |
| `Live Plus (ACR) is` | act | Live Plus (LG's viewing-data collection) is on. | The menu path of the TV's screen-recognition setting, from its profile (below). |
| `TV has a second network path:` | act | The TV's Wi-Fi, or another of its radios, is on, so it can reach the internet around the gateway. | On the TV: switch Wi-Fi off, forget every saved network, and switch off Wi-Fi Direct and any tethering. |
| `clock host lookups blocked:` | doctor | The TV could not set its clock, so its apps may fail to connect. | Run `sudo tvgw doctor`. |
| `TV was on but never looked up its clock host` | doctor | The TV did not check its clock while it was on. | Run `sudo tvgw doctor`. |
| `firewall checks failed` | doctor | The gateway's self-check failed at least once. | Run `sudo tvgw doctor`. |
| `firewall checks ran` | doctor | The gateway's self-check did not run as often as it should. | Run `sudo tvgw doctor`. |
| `ACR-shaped upload:` | act | The TV sent what looks like screen fingerprints to the internet. | The menu path of the TV's screen-recognition setting, from its profile (below). |
| `ACR port attempts:` | act | The TV tried to send viewing data on ports the gateway keeps closed, and was stopped. | The menu path of the TV's screen-recognition setting, from its profile (below). |
| `Encrypted ClientHello in` | detail | Nothing: the line stays in the engineering brief. | |
| `the Pi's own lookups left outside the VPN:` | detail | Nothing: the line stays in the engineering brief. | |
| `TV agreement` | act | One of the TV's data agreements was accepted, at the remote or by a software update. | On the TV: open its privacy or user-agreement settings and decline it again (`tvgw brief --full` names it). |
| `TV consent flag` | act | One of the TV's data agreements was accepted, at the remote or by a software update. | On the TV: open its privacy or user-agreement settings and decline it again (`tvgw brief --full` names it). |
| `machine rule` | detail | Nothing: the line stays in the engineering brief. | |
| `TV was on but no` | doctor | Part of the gateway's record stopped while the TV was on. | Run `sudo tvgw doctor`. |
| `ingest warnings:` | detail | Nothing: the line stays in the engineering brief. | |

| Profile | What the Live Plus and ACR lines ask |
|---|---|
| `lg-webos` | On the TV: Settings > General > Additional Settings > Live Plus: off. |
| `samsung-tizen` | On the TV: Settings > All Settings > General & Privacy > Terms & Privacy > Privacy Choices > Viewing Information Services: off. |
| `roku` | On the TV: Settings > Privacy > Smart TV experience > Use info from TV inputs: off. |
| `vizio-smartcast` | On the TV: Menu > Admin & Privacy > Viewing Data: off. |
| `generic-tv` | On the TV: turn this setting off (`tvgw brief --full` names it). |
<!-- /generated:red-lines -->

### Looking into a red line

What each line means and what the household does about it is in [the red lines](../use/daily-brief.md#red-lines). These are the commands an engineer runs to look deeper, in the brief's order.

| The line | What an engineer looks at |
|---|---|
| `must-allow name blocked: <name> x<N> by <rule>` | `tvgw host <name>` shows the rule. Run `sudo tvgw adguard diff`; on drift, run `sudo tvgw adguard apply`. With no drift, run `tvgw profile` for the lint, then read the answer's CNAME chain with `tvgw sql "select answers, rule from dns where qname='<name>' and blocked=1 order by t desc limit 1"`: AdGuard matches a rule against CNAME targets too (`src/tvgw/profiles/lg-webos.toml`). Fix the rule in the profile and deploy ([block or unblock something](../use/blocking.md)). |
| `a list update newly blocks <name>, which carried content (list <id>, <bytes> down over <N> connections in the 14 days before, median <bytes>): if the TV needs it, add it to must_allow` | Find what broke: `tvgw host <name>` shows the rule and the apps on at the time. If an app the household uses depends on the name, run `sudo tvgw allow <name>` on the gateway ([your own rules](../use/blocking.md#your-own-rules)), or add it to the profile's `[must_allow]` with the reason and deploy; either exception carries `$important` and beats the list. If nothing broke, leave it and note it. Look up the list with `sudo grep -B1 -A3 'id: <id>' /opt/AdGuardHome/AdGuardHome.yaml`, and report a false positive to its maintainer. |
| `Live Plus (ACR) is <value> on the TV (since <time>): General > Additional Settings` | Turn Live Plus off with the remote, under General > Additional Settings; the CX's LAN API refuses writes ([design decision 4](../design-decisions.md#4-no-rooting-of-the-tv)). `tvgw tvstate 2d` shows when it changed, and `sudo tvgw tvcheck` reads it again now. |
| `TV has a second network path: <path> is <state> (since <time>): traffic can leave around the gateway; turn it off under Settings > Network` | On the TV: Settings > Network: turn Wi-Fi off and delete the saved network, turn Wi-Fi Direct (Screen Share) off. Then `sudo tvgw tvcheck` must print no second-path warning. If the TV did this on its own, after an update or a reset, write it in [the incident log](../incidents.md). |
| `clock host lookups blocked: <N> (the TV's clock comes from them)` | Do what the must-allow row says for the clock host, then restart the TV so it asks again. |
| `TV was on but never looked up its clock host (check the SDP hosts are reachable)` | Check other days with `tvgw host <clock-host>`. If lookups appear there, watch the next day. If they never appear, the pattern does not match this firmware's host: `tvgw profile --webos <version>` lists the generation's clock hosts and `tvgw new-hosts 7d` the recent names. Fix `clock_hosts` in the profile and deploy. |
| `firewall checks failed <N> of <M> times; last: <failures>` | Run `sudo tvgw verify` and act on each FAIL ([what tvgw verify checks](verify-checks.md)). If it passes now, find when it failed with `tvgw sql "select datetime(t,'unixepoch','localtime'), failures from verify where ok=0 order by t desc limit 10"`. Treat every FAIL after a deploy as an outage ([incidents](../incidents.md)). |
| `firewall checks ran <N> of ~<M> times (is tvgw-verify.timer alive?)` | `systemctl list-timers 'tvgw-*'` must show `tvgw-verify.timer` with a next run. Read `journalctl -u tvgw-verify -n 20`. If the timer runs, look in that journal for `tvgw verify: could not record the run`. |
| `ACR-shaped upload: <cell>:<port> sent <X> MB up (<R>x down) in <N> connections <on day \| in hour HH of day>; Live Plus reads <state>` | Confirm Live Plus with `sudo tvgw tvcheck`; if it reads anything but `off`, turn it off with the remote as for the Live Plus line. Look the cell up: `tvgw host <name>` for a domain, or for a /24 `tvgw sql "select dst, dport, count(*), sum(bytes_up) from flows where dst like '<a.b.c>.%' and dport=<port> group by 1 order by 4 desc limit 5"` and `tvgw host` on the top address. A tracker or ACR host: block it in the profile's `.rules` file (by address in `block4.txt` when it has no name) and deploy. A streaming app's own upload: add its name to the right expected category. |
| `ACR port attempts: <N> connections to TCP <ports> rejected (<names>)` | `sudo journalctl -k -g tvgw-adport -n 20` shows the samples. Look up each address with `tvgw host <address>` and `tvgw sql "select qname, datetime(t,'unixepoch','localtime') from dns where answers like '%A:<address>%' order by t desc limit 5"`. A name that was not blocked is a rule gap: add it to the profile's `.rules` file and deploy. If a feature the household uses broke at the same time, set `ADTECH_PORT_WALL=no`, run `sudo tvgw-apply`, and write it in [the incident log](../incidents.md). |
| `Encrypted ClientHello in <N> handshakes since <time> (outer names: <names>): per-connection TLS naming is going dark; keep HTTPS records stripped` | Run `sudo tvgw adguard diff` and confirm it exits 0, so the generated rule that withholds HTTPS and SVCB records from the TV is live (`[adguard] strip_qtypes`). Look up each outer name with `tvgw host <name>`, and watch whether the count grows. |
| `the Pi's own lookups left outside the VPN: <what> <N> time(s), ... (was the tunnel down? see Coverage)` | Run `piactl get connectionstate` and `ip -br link \| grep -E 'tun0\|wgpia0'`. If PIA was disconnected or restarting at the time, the line is that window, and it ends once PIA connects. If PIA reports `Connected` and the DNS count still rises, check PIA's remote port: an OpenVPN transport on port 53 is counted as DNS. `sudo nft list chain inet tvgw post_leaks` shows the counters. |
| `TV consent flag <flag> turned on (at <time>): an agreement was accepted on the TV` | `tvgw tvstate 2d` shows the change. Decline the agreement again with the remote under Settings > General > System > Additional Settings > User Agreements, and write it in [the incident log](../incidents.md) if nobody in the household did it. |
| `machine rule <rule> has spent more than half of judge v2's 14-day ceiling with <N> of <K> clean TV hours` | Read "Changes in effect" for what confounded the hours. Nothing to do while v2 is in shadow; the line is the evidence for [the owner's decision on judge v2](../how-it-works/analyst-and-autonomy.md#judge-v2-in-shadow). |
| `TV was on but no lookups were recorded (is the AdGuard query log being read?)` | In Coverage, check whether `dns` is `NOT ASSESSED`. Read `journalctl -u tvgw-analyze -n 50` for the ingest step. Check `sudo ls -l /opt/AdGuardHome/data/querylog.json` and `systemctl status AdGuardHome`. `sudo tvgw adguard diff` shows whether the query-log settings drifted. |
| `TV was on but no connections were recorded (is the flow log being read?)` | Run `systemctl status tvgw-flowlog`. `tail /var/log/tvgw/flows.log` must be growing. Coverage says whether `flows` was read. |
| `ingest warnings: <N>` | Look each text up in [ingest warnings](../use/troubleshooting.md#ingest-warnings). `sudo tvgw ingest` runs ingest now and prints its warnings to stderr. The same warning every hour is a real fault. |

## Sections

Every section, in the order `cli.render_brief()` prints it. A section marked "always" prints `(none)` or `none` when it has nothing to show; the others are left out. Every string that came from the TV or from a server passes through `cli.clean()`, which escapes control and formatting characters before they reach the terminal.

### The header line

Always. `=== <label>: N lookups (B blocked, D names), C connections, up X down Y`. The lookups, the blocked lookups and the distinct names come from the TV's DNS rows in the window. The connections and bytes come from the connections conntrack reported in it, by `t_end`, which runs late by the idle timeout ([the tables](data-model.md#tables)). Up is what the TV sent; down is what it received.

### The coverage block

Always. The Coverage line, the `NOT ASSESSED` line and the `ingest warning:` lines, described in [Coverage](#coverage).

### The red-line block

When any line qualifies. One `RED LINE:` line each, in the order of [Red lines](#red-lines).

### Not checked

(depth) After the red lines, when the brief cannot vouch for something. Today one line, `Not checked: the TV's Wi-Fi. When you have switched it off on the TV, run: sudo tvgw tv confirm wifi-forgotten yes`, printed when no TV reading before the window's end reports the TV's network paths (no reader for the TV, not paired, firmware that does not answer, or (samsung) a Samsung not yet read, or whose reply gave no network type) and the owner's latest answer for `onscreen.wifi-forgotten` is not a current `yes`: no answer, `no`, `unknown`, or a `yes` older than the TV's last firmware change, which gets its own wording asking for the check again (`queries.not_checked`, [design decision 57](../design-decisions.md#57-consent-the-tv-will-not-report-is-the-owners-dated-word-including-unknown-asked-again-after-a-software-download-samsung-is-read-without-pairing)). A gateway whose TV reports its paths, the reference among them, never prints it. (tripwire) A second line, `Not checked: whether the TV went online while it was off, in <N> hours when the hourly check could not tell whether it was on`, names the hours between readings whose power state could not be read (`unknown`, or none), which the [While off or asleep](#while-off-or-asleep) line cannot judge (`standby_unread()`). The JSON carries both as `not_checked`, an empty list when there is nothing to say.

### TV notes

(W12) After the Not checked lines, the lines about the TV that are neither red lines nor "Not checked" (`cli.tv_notes`), each when its data is there: `Pairing: the gateway can no longer read the TV since <date>: run sudo tvgw tv pair`, from the key store's refusal as the ingest copies it (`lan_api.pairing`); `Standby: <switches> on: the TV keeps its network up while the screen is off`, the standby switches the TV last reported on (Always Ready, Quick Start+, TV On With Mobile: `STANDBY_KEYS` in src/tvgw/lgwebos.py), which explain a non-zero "While off or asleep" line; `Agreements: the TV asks you to accept <agreement> again; it is not accepted`, from the per-document consent record (`agreement.<id>.updated` true and `eula.doc.<id>` not true); and `TV country: the TV reports <country> (<cc>); <host> is not on the must-allow list: run sudo tvgw allow <host>, or set TV_COUNTRY=<cc> ...`, when the TV reports a country whose hosts the profile as loaded does not name. The plain brief carries each as its own line after Not checked (`plain._tv_notes`); none is an action.

### Firewall held

Always. `Firewall held: <label> <packets>, ...; N checks, F failed`. Each count is the packets a counted firewall rule matched in the window: the sum of the positive steps between the counter snapshots `tvgw verify --record` takes. A re-apply zeroes the counters, but `tvgw-apply` lists them just before and just after its reload and the next `verify --record` stores both listings as snapshots, so the reset costs nothing unless a second apply follows within the same 10 minutes ([design decision 13](../design-decisions.md#13-counters-not-logs-prove-the-firewall-held)). The first step is taken from the last snapshot in the `FW_BASELINE = 3600` seconds (in src/tvgw/queries.py) before the window, or, when there is none, from the window's own first snapshot, so days nobody recorded are not credited to the window after them. The gate's count, `to addresses DNS never gave`, is never below the samples the gate logged in the window, since the rule counts a connection before it samples it. `FW_LINES` in src/tvgw/queries.py turns a rule's comment into its label: the first prefix that matches wins, labels print in `FW_LINES` order, and a rule that had a snapshot in the window shows even at 0. `no counter snapshots yet` means no snapshot fell in the window, and `no checks recorded` means no run did. What each rule does is in [the firewall](../../deploy/nftables/README.md).

| Label | Counter comment begins |
|---|---|
| `DNS forced to AdGuard` | `TV DNS aimed elsewhere` |
| `DNS to AdGuard` | `TV DNS to the gateway` |
| `DoT/DoQ` | `DoT/DoQ` |
| `QUIC` | `QUIC` |
| `DoH` | `DoH resolvers` |
| `LAN` | `TV may not reach the home LAN` |
| `IP blocks` | `manual IP blocks` |
| `invalid` | `invalid` |
| `foreign source` | `TV source outside its subnet` |
| `second TV address` <!-- (fin-release) --> | `TV source is not the TV` |
| `off the TV port` | `TV subnet off the TV port` |
| `tunnels` | `no GRE/ESP/6in4` |
| `ICMP` | `no ICMP tunnels` |
| `adtech ports` | `LG adtech port` |
| `odd ports` | `STRICT_PORTS` |
| `LG 8080 fallback` | `LG firmware fallback path` |
| `to other Pi addresses` | `TV talks to the gateway address only` |
| `other Pi services` | `TV may not reach other Pi services` |
| `guard` <!-- (fin-release) --> | `guard: TV may not reach other Pi services` |
| `Pi chatter` | `no NetBIOS/SSDP chatter` |
| `from VPN` | `nothing unsolicited from the VPN` |
| `other forward drops` | `nothing else into or out of the TV subnet` |
| `wrong uplink` | `only via the chosen uplink` |
| `IPv6` | `no IPv6 from the TV` |
| `to addresses DNS never gave` | `TV to an address DNS never returned` |

`DNS to AdGuard` and `LG 8080 fallback` count traffic the firewall accepts, `odd ports` counts accepted traffic while `STRICT_PORTS=no`, and `to addresses DNS never gave` counts without dropping anything. The rest count packets the firewall dropped, rejected or redirected. <!-- (fin-release) --> `guard` is the final input drop of the guard's own table, `inet tvgw_guard`, and stays at 0 while `inet tvgw` is loaded, because `inet tvgw` drops first; a count there means `inet tvgw` let something through that the guard refused (`guard_quiet` in [troubleshooting](verify-checks.md)).

### Clock hosts

When the profile has `clock_hosts`. `Clock hosts: N lookups (B blocked), first at HH:MM`: the lookups whose name matches a `clock_hosts` pattern (`*` matches any run of characters, `?` one character), how many of them were blocked, and the time of the first. webOS sets its clock from LG's SDP reply, which follows these lookups, so a blocked one is red line 4, and a whole day with the TV on and none is red line 5.

### Clock servers

(ntp) When the TV sent NTP in the window. `Clock servers (NTP): R requests to N addresses: <address> (<name>) <requests>, ...`: the requests the TV sent to UDP 123, how many addresses they went to, and the `NTP_TOP = 3` most used (in src/tvgw/queries.py), each with the first name the TV's A answers of the `KNOWN_DAYS = 7` days before the window's end gave it, `+K` for further names, or `no lookup` for an address no answer named: a server written into the TV's software, or a lookup the gateway did not see. `, M more` counts the rest. The counts come from `inet tvgw_ntp`, which counts each address in a dynamic set with a counter per element and refuses nothing ([the NTP count table](../../deploy/nftables/README.md#the-ntp-count-table)): `tvgw verify --record` stores one series per address, `ntp: <address>`, and `queries.ntp_servers()` sums each one's increases between snapshots, an address that left the set and came back counting from zero. A re-apply keeps the counts. The first step is taken from the last snapshot of the count in the `FW_BASELINE = 3600` seconds before the window, or from the window's own first one, as in [Firewall held](#firewall-held). The count is not firewall evidence, since the filter accepts NTP by design ([design decision 17](../design-decisions.md#17-strict_ports-stays-off-until-two-clean-weeks)): it is not in Firewall held, in `firewall.activity` or in the analyst's pack. Without NTP in the window the line is left out.

### While off or asleep

When the window holds an off hour. `While off/asleep (H h): N lookups, C connections, up X`, then `; names: <name> xN, ...` when it counts anything. An off interval lies between two consecutive readings that are both outside `AWAKE` (`Active`, `Screen Off` and `Screen Saver`, in src/tvgw/queries.py: a screen saver is the TV on and idle with its app still in front, and Screen Off is the TV on with its panel dark, an app or its sound still running) and outside `NO_POWER` (`unknown` and no power at all), so `Active Standby`, `Suspend` and `unreachable` count as off, and that are at most `STANDBY_GAP = 5400` seconds (90 minutes, in src/tvgw/queries.py) apart, so a missed reading never makes an hour look off. (tripwire) `unknown` is a TV that answered without a power state, or one nothing could be asked of (not paired, or its key refused), which may well be on: an hour with it at either end is not off. Until 2026-11-05 it was. `H` is the time those intervals span, not how many there are, so the extra readings a deploy or a run by hand adds do not inflate it. The line counts the lookups made in those hours, the connections opened in them (by `t_start`, which the idle timeout does not inflate) and the bytes those connections sent. With instant-on off this is nothing at all; a connection the TV opens while it says it is asleep is the evidence.

(tripwire) When it counts anything, the line names up to `STANDBY_NAMES = 5` (in src/tvgw/queries.py) of what the TV reached in those hours, most first, each with its lookups and connections added up: the names it looked up, and each connection's TLS name, or its server's address when no hello named it (`standby_names()`). It then adds `; the TV port's counters show it in use then` when a 10-minute sample of the TV port overlapping a stretch it talked in carried at least `AWAKE_BYTES = 200_000` bytes (in src/tvgw/activity.py) to the TV (`standby_port()`), and `; <N> days running` from the second calendar day running. The plain brief carries one `While off:` line unless those counters say the TV was in use ([the plain brief](#the-plain-brief)). It is not a red line: the hourly readings miss a short session, and a TV whose LAN API stops answering while it is on reads unreachable ([design decision 66](../design-decisions.md#66-an-upload-budget-with-a-ceiling-set-once-count-only-and-the-names-of-a-tv-that-goes-online-while-off)). Hours between two readings with `unknown` or no power at either end are listed under [Not checked](#not-checked): `whether the TV went online while it was off, in <N> hours when the hourly check could not tell whether it was on`. On the reference CX it has read 0 lookups and 0 connections ([what an LG CX does, measured](../tv/lg-cx-measured.md#the-week-in-numbers)).

(activity) The hourly readings miss a short session two times in three, and its traffic then reads as the TV's own while off. Once the TV port's byte counters are calibrated against the readings (`tvgw activity calibrate` meets both of its 95% bars over the 14 days before the window's end, [passive TV activity](../how-it-works/analyst-and-autonomy.md#passive-tv-activity)), a 10-minute interval in which the TV downloaded at least 5 MB inside such an hour is left out: its time, lookups, connections and names, and the line ends `; S h of streaming between readings left out`. On a store that does not meet the bars the line is what it was.

### Private reverse lookups

When any. `Private reverse lookups (LAN inventory): N for D names`: PTR lookups for addresses in the firewall's `lan4` set (`LAN_NETS` in src/tvgw/names.py). This is the TV taking inventory of the network around it.

### Changes in effect

(ledger) What changed on the gateway in the window, grouped by where it acts (Gateway, Uplink, TV path, TV, Evidence), with the machine rules on trial and both judges' verdicts, and how many of the TV's hours were clean, confounded or without demand. The brief prints "Changes in effect" after the red lines and the summary lines, before the tables and before "Rules the gateway added on its own", so what changed is read before what the machine concluded ([design decision 48](../design-decisions.md#48-one-ledger-of-changes-one-hour-classifier-and-a-second-judge-that-only-watches)). It appears once the change ledger has anything for the window: a sample, a change, or a machine rule on trial. An example, with no real names:

```text
Changes in effect (11-02 00:00 .. 11-03 00:00; ~ marks a time known to 10 minutes):
  On trial   ||beacon.example^   added 11-02 03:50; clean TV hours 3 of 6 needed; judge: watching; judge v2 (shadow): watching
  Gateway    ~03:50 AdGuard restart   14:05 deploy (metric-affecting)   DHCP change (wlan0) x12   apply (nm-dispatcher) x12
  Uplink     ~20:10-20:40 PIA not connected (Reconnecting)   21:02 VPN up (tun0)
  TV path    TV link flaps: 0   conntrack: max 262144, peak 3% full
  TV         firmware unchanged (04.64.00)
  Evidence   capture: no hour without names   conntrack lost events: 0 run(s)   connections cut early: 0
  Hours      TV on 6: clean 3, confounded 2 (PIA not connected 20h; Wi-Fi degraded 21h), no demand 1 (input or launcher in front 22h)
```

- **On trial**: each machine rule on probation in the window, with its clean TV hours toward judge v2's K, the shipped judge's state and judge v2's latest shadow verdict.
- **Gateway, Uplink, TV path**: class-A changes with their times (a `~` time comes from a 10-minute sample), class-B changes as counts with their trigger. Class A can move what the judge measures: an AdGuard restart, a deploy that changed the code, an apply that touched routing, a VPN or link event, a reboot, conntrack drops or pressure, (site rules) an owner's `tvgw allow`, `block`, `unallow` or `unblock`. Class B cannot: an apply that left routing alone, a DHCP renewal, a list refresh.
- **TV**: the firmware read in the window.
- **Evidence**: hours whose capture named nothing, ingest runs that reported lost conntrack events, and (plain) the connections cut early: the TV's connections the kernel destroyed while their timer still ran, each with its cause and the time of its first cut. The cause is the nearest class-A change within `max(30, its t_precision)` seconds before the time it was seen, or 30 seconds after it (`CUT_NEAR`); the changes that end connections by themselves (`CUT_CAUSES`: a reboot, the uplink's address or router, the uplink or the TV port going down or flapping, conntrack pressure or drops, the VPN going) come before every other kind, so an apply that reacted to an address change is never named for it. Among them the nearest wins, and at the same distance the first in that list. `cause unknown` means no change was near. On the reference gateway on 2026-11-02 the home router gave the gateway a new address at 19:46 and five of the TV's connections were cut, which the line reads as `connections cut early: 5 (uplink address changed 19:46)`; a reservation for the gateway's address in the router's settings stops it.
- **Hours**: the hour classifier's count of the window's TV hours, with the reason of up to four hours of each kind. Only clean hours can judge a rule.

`tvgw changes 1d` lists the rows behind it, and `tvgw sql "select * from gw_samples order by t desc limit 3"` the latest samples. A line `(no gateway samples in this window: ...)` means `tvgw verify --record` did not sample: check `LEDGER` and `systemctl list-timers tvgw-verify.timer`.

### By day

Weekly reports only. One row per local day: lookups, blocked lookups, connections, bytes up and bytes down. A day with connections and no lookups still has a row, and the rows add up to the header.

### By category

When the window has a lookup or a connection. One row per profile category, in the profile's order, then `Other`, `Unresolved` and `Gateway`: lookups, blocked lookups, distinct names, connections, bytes up and bytes down. A lookup takes the category of its name. A connection takes the category of the TLS name in its own hello ([naming a connection](../how-it-works/architecture.md#naming-a-connection), [design decision 12](../design-decisions.md#12-each-flow-is-named-by-its-own-tls-hello)). `Unresolved` holds the connections no hello named: UDP, plain HTTP, a missed packet, or a pcap not ingested yet. `Gateway` holds the connections to the gateway itself.

### DNS sent to other resolvers

When any. `DNS sent to other resolvers (redirected to AdGuard): <address> xN, ...`: connections the TV opened to port 53 of an address other than the gateway, by address. The firewall redirected them to AdGuard, so they are attempts, not leaks.

### New hosts

Always. `New hosts (N):`, one row per name first seen in the window, in first-seen order: category, the `dns`, `tls` and `http` counters, state, and `new domain` when no name under the same registrable domain was seen earlier. The counters are the `hosts` table's and count every row the store holds for the name, not only the window's. The state is `BLOCKED` or `allowed` from the name's last lookup, and `?` for a name seen only in a hello or a plain-HTTP request. A new name is where change shows first, and `new domain` most of all.

### Blocked and still retried

Always. The 15 blocked names the TV looked up most in the window, with the count and the rule that blocked each. Most of this is the rules working while the TV keeps asking.

### Blocked names still reached over TLS

When any. Up to 20 names the TV sent a TLS hello for in the window while a lookup of the same name was blocked in it: hellos, blocked lookups and allowed lookups. The TV used a cached or hardcoded answer, or the rule changed during the window; an allowed count above 0 says the rule changed. Why this is not a red line is under [Red lines](#red-lines).

### Allowed, outside the expected categories

Always. Up to 25 allowed public names whose category is not among the profile's `expected_categories`, most looked up first. A name in a blocked category here is a gap in the rules; a name in `Other` is a candidate for a rule or for a category.

### Top upload

Always. The 12 destinations the TV sent the most bytes to, with the gateway left out, grouped by the TLS name of each connection's own hello, or by address when no hello named it (`(no TLS name)`), and by port. `+N` after an address counts the further addresses under one name. `payload<=` is the most the TV can have sent as data: conntrack's bytes less `HEADER_BYTES = 40` (in src/tvgw/queries.py) per packet for the IPv4 and TCP headers, never below 0, and `?` when the packet count is unknown (`payload_bound()`). A download's own ACKs count as bytes up, and `payload<=` takes them out.

### Upload budget

(budget) Once the ceiling is set, or `UPLOAD_CEILING` names one; before that, only on a window with an hour over the floor. A fixed ceiling on what the TV sends one destination outside the profile's `expected_categories` in one local clock hour beyond what came back on the same connections, count-only: nothing is capped ([design decision 66](../design-decisions.md#66-an-upload-budget-with-a-ceiling-set-once-count-only-and-the-names-of-a-tv-that-goes-online-while-off)). `budget.report()` in src/tvgw/budget.py writes it. An example, with invented names and times:

```text
Upload budget (count-only; nothing is capped): ceiling 1.3M net per destination-hour outside the expected categories (net: what each connection sent beyond what came back)
  set 03-15 03:20 from the 14 days 03-01 .. 03-14: 2 x 665.1K, the largest clean destination-hour (collector.example.net, 03-09 19:00)
  would have capped:
destination                   hour         net   payload<=  conns  ports
203.0.113.0/24 (no TLS name)  03-18 20:00  3.4M  3.8M       60     4431
```

- **What counts.** A connection to a public address whose TLS name is outside `expected_categories`, or that no hello named, in the hour it opened in. A must-allow host is never counted, by its name or a name under it, nor at an address an A answer for it returned in the window or the day before. A destination is the registrable domain of the TLS name, or the server's /24 marked `(no TLS name)`, as the ACR test groups them (`acr_cell()`). An upload spread across hours, across destinations, across registrable domains that rotate or, unnamed, across several /24s counts as several smaller ones, each judged alone. `tvgw host` takes a destination as the section prints it ([commands](commands.md)).
- **Net, per connection.** Each connection's [Top upload](#top-upload) `payload<=` less the same bound of what came back on it, never below 0 (`net_up()`), summed over the destination-hour. The gross `payload<=` is the column beside it. A download nets nothing however many options its acknowledgements carry, where its gross bound can read tens of megabytes "up"; a download on another connection never offsets an upload, so an hour can net more than the destination as a whole sent beyond what it returned. A connection whose packet count is unknown counts its bytes whole. An upload inside a connection that returns as many bytes is not seen.
- **The ceiling.** `ceiling_for()` the largest clean destination-hour of the `BUDGET_DAYS = 14` whole local days before the day it was set: `BUDGET_TIMES = 2` times it, never under `BUDGET_FLOOR`, 512 KiB, and never over `BUDGET_CAP`, half of `ACR_HOUR_NET`, 2,930,000 bytes, an estimate of what the quietest hour of LG's screen recognition IMC 2024 published nets (all in src/tvgw/budget.py; the estimate's two assumptions are in the decision). A destination-hour is clean unless the ACR test flagged that destination on that day; a connection under a known tracking category adds nothing to it. The hourly ingest sets it once, at its first run `SETTLE` (3 hours) after a midnight that ends 14 whole days its record covers, each of them with flows and at least `CAPTURE_NAMED` (90%) of its TCP 443 connections named, and records the rule, the measure, the profile and the TV's model with it ([the store's meta](data-model.md#meta)). A row of another rule, profile or TV is not honoured, nor a stored ceiling above the cap. `sudo tvgw budget --rederive` sets it again from the 14 days before today ([commands](commands.md)).
- **How it was set.** The second line says: from which days and which destination-hour (`2 x <net>`), `the floor, since ... is less`, `the cap, since ... is more`, or, when the largest clean hour itself reached the cap, `the cap: this TV's own uploads reach the size the budget watches for, <net> net in its largest clean destination-hour (<destination>, <hour>), and every hour like it is listed; look at it`. Or `set by the owner (UPLOAD_CEILING)`; or the floor while the ingest has not set it, with why: `until the hourly ingest sets the ceiling from 14 whole days of the record, after <time>` (adding `for the new profile`, `for the new TV` or `again, as asked`), `<N> of the 14 days before the last hourly run have no flows, or under 90% of their TCP 443 connections named`, `the stored ceiling was set by another rule`, or `the store keeps too few days (DB_DAYS)`. A third line, `at or above 2.8M, ...`, appears only for an owner's ceiling of at least `ACR_HOUR_NET`: an hour of LG's screen recognition would not count.
- **Would have capped.** Every destination-hour whose net is over the ceiling, most first: the destination, the hour, the net, the gross `payload<=`, the connections and the server ports. `none` when there is none. The hour the clocks go back comes twice and carries its zone (`01:00 CDT`, `01:00 CST`). It is never a red line, and the plain brief carries one `Uploads:` line for them ([the plain brief](#the-plain-brief)).
- **Late.** A connection reaches the store only when it ends, and each daily file is written once, 3 hours after its day ends. Every connection that ended in the window after its own day's file was written, however long ago it opened, puts its destination-hour under `late:` when the hour's whole net, now known, is over the ceiling, with the part that came late in a last column.

### DNS-gated egress

When the gate counted a connection or logged a sample. `DNS-gated egress (count-only): N new connections to addresses no lookup had returned`. N is the window's count on the gate's rule (`GATE_RULE` in src/tvgw/queries.py), floored at the samples it logged: new connections the TV opened to an address that is not among those its lookups returned within the set's timeout (`TTL = 86400` in src/tvgw/dnsgate.py, one day), each flow's tuple counted once in two minutes (`seen4`) ([design decision 18](../design-decisions.md#18-dns-gated-egress-starts-as-a-count-in-its-own-table)). The table lists up to 10 of the samples the firewall logged, by address and port, with the columns `address`, `port`, `samples`, `just looked up`, `first` and `TLS name seen`. `just looked up` counts the samples that came within `FEEDER_LATE = 2.0` seconds (in src/tvgw/queries.py) of an A answer naming the address exactly: the feeder adds an address a few milliseconds after the answer leaves the gateway, and the TV connected sooner. Of the rest, a TLS name means a lookup the gate had forgotten, a day old or from before the gateway last booted; `(none)` is a hardcoded server or a resolver bypass. Nothing is blocked. When any sample is neither `just looked up` nor explained by an A answer naming its address in the 7 days before it (`KNOWN_DAYS` in src/tvgw/queries.py), a second table follows, headed `unexplained:`, with `address`, `port`, `samples`, `first` and `TLS name seen` (`gate_unexplained`): these are the gate's own finding, and the only gate evidence that buys the analyst a request ([design decision 22](../design-decisions.md#22-a-pass-that-proposes-nothing-is-remembered)).

### Rules the gateway added on its own

When a machine rule was added or decided in the window, when a rule is on probation untested, or when a block waits its turn. One row per rule: the rule, when it was added, its state (`on probation` until it is decided, `on probation, canary armed` while its canary waits for the TV to be watched, then `passed` or `reverted`; `on probation, untested` for a trial that ran out of days without TV hours with demand, listed every day until the owner decides), and why, cut to 70 characters: the decision's reason, or else the second model's. Waiting blocks follow as `queued`, with when they were queued. The heading names `tvgw undo`, which takes the newest out. The watches that judge these rules are in [the analyst and autonomy](../how-it-works/analyst-and-autonomy.md) and [design decision 20](../design-decisions.md#20-the-gateway-blocks-on-its-own-under-three-watches).

### List changes

(lists) When a list's own update changed what the TV gets ([lists change on their own](../how-it-works/adguard.md#lists-change-on-their-own)). `List changes (a list's own update; 14-day shape before the first block):`, then one row per name, columns `change`, `name`, `by`, `since`, `lookups`, `shape` and a mark:

- `newly blocks`: a list (`by list <filter_id>`, never the custom rules, which are 0) blocked the name for the first time in the window (`since`), and the TV had resolved it to an address in the 30 days before (`LIST_USED_BEFORE` in src/tvgw/queries.py; `lookups` counts those answers). `shape` is the TV's connections to the name, named by their TLS hello, in the 14 days before the block (`LIST_SHAPE_DAYS`): bytes down, connections and the median per connection. `CARRIED CONTENT` marks one over 2 MB down or a median over 16 KB, which is also a red line. Content rows first, then the most used, up to 30 (`list_newly_blocked()`).
- `newly allows`: a list blocked the name in the 30 days before the window, and the window answered it with an address and no rule at all, so neither the profile's exceptions nor the machine let it through (`list_newly_allowed()`). `since` is the first such answer and `shape` when a list last blocked it.

The name in each row came from the TV, through `clean()`. The JSON carries both lists under `list_changes`.

### Periodic connections

When any. Up to 12 names the TV connects to on a timer, or addresses marked `(no TLS name)` when no hello named them, most regular first: category, connections, the median start-to-start interval (`every`), the jitter, the median payload per connection (`payload<=`) and the `ACR-like` mark. All the constants are in src/tvgw/queries.py:

- connections opened within `BURST_GAP = 5.0` seconds of an event's first start belong to that event, so a page load is one event, not a timer;
- the name needs at least `BEACON_MIN = 12` events in the window;
- the jitter, the median absolute deviation of the intervals divided by their median, must be under `PERIODIC_JITTER = 0.15`, which is 15%; random arrivals, a Poisson stream, sit near 0.5 and never pass;
- the median interval must fall within `PERIOD_RANGE = (10.0, 86400.0)`, from 10 seconds to a day;
- `ACR-like` marks a row whose name (its registrable domain, or the address's /24 when it has no TLS name) and one of whose ports are a cell red line 8 named as an ACR-shaped upload in the window. The timer itself marks nothing: LG's ACR client uploads every 14 to 15 s inside connections that open about once a minute, so its cadence never shows between connection starts.

A regular timer with small payloads under a name that is not the TV doing its job is how telemetry looks. It is a row to read, never a red line, and it never asks the analyst anything on its own.

### GFTS URL filter

Always. `status biz_code: requests` for the requests the URL filter's nginx logged in the window, by HTTP status and `biz_code`, with `(other)` for a URI that carries no `biz_code`. A 403 for a code the profile's `block_regex` names is the filter refusing a side channel; a 200 is a download that passed ([design decision 8](../design-decisions.md#8-a-url-filter-for-lgs-file-service-instead-of-a-dns-block)).

### Plain HTTP

When any. Up to 30 groups of unencrypted requests the TV made to the internet, read from the pcaps, by host, method and path without its query string (the path cut to 120 characters), with the count and the user agents, each cut to 60 characters. The vendor file service, which is the URL filter's hosts, and names that are not public, such as SSDP's, are left out.

### Unexpected ports

Always. `Unexpected ports: <PROTO>/<port> -> <address> xN, ...`, or `none`: the kernel-log lines of the firewall's unexpected-port rule, by protocol, port and address ([the firewall](../../deploy/nftables/README.md)). `none` is the goal, and two weeks of it is the evidence [design decision 17](../design-decisions.md#17-strict_ports-stays-off-until-two-clean-weeks) asks for before `STRICT_PORTS` changes.

### LAN probes

Always. `LAN probes (dropped): <address>:<port> xN, ...`, or `none`: TCP connection attempts from the TV, read from the pcaps, to an address no internet host answers from, other than the gateway: the home-LAN ranges, loopback, multicast and broadcast (`is_local_address()` in src/tvgw/names.py). A retransmitted SYN is the same attempt. The first 12 print, then `+N more`. The firewall dropped them, and this is the evidence that it had to.

### Unresolved flows

When any. Up to 20 TCP destinations, by address and port, that the TV reached in the window with no TLS hello to that address ever and no A answer naming it in the window or the 86400 seconds (one day) before. Only public addresses count, and the gateway is left out. Each is a hardcoded address or a DNS bypass. The section is stricter than the `Unresolved` category, which only means that no hello named the connection.

### Firmware

One block per firmware reading in the window whose version differs from the reading before it (`firmware_changes()` in src/tvgw/queries.py): the first firmware reading a store holds has nothing to differ from, so it is no update, and the TV settings section lists it instead. (W12) The release the TV reports in its `hello` reply (`webos.release`) counts the same way, for a TV whose software call answers 401 (webOS 26 with the unsigned manifest): its block reads `Firmware webOS 11.2.0 seen ...`, and a reading in which both change is one block, named by the firmware. Each block reads `Firmware <version> seen <time>; new names from the hour before to 72 h after:`, then the names first seen from 3600 seconds before the reading to 72 hours after it, or `(none yet)`. The hourly reading sees an update made since the reading before, so the new firmware's first names fall in the hour before it. New endpoints arrive with updates ([design decision 4](../design-decisions.md#4-no-rooting-of-the-tv)).

### DNS oddities

When any. Names outside the expected categories that look like data rather than names. All the constants are in src/tvgw/queries.py:

- `long name`: a name over `LONG_NAME = 100` characters;
- `random label`: a label of at least 16 characters (`RANDOM_LABEL = (16, 3.6)`) that is all hexadecimal with a digit, or that carries at least 3.6 bits of entropy per character;
- `fan-out`: a registrable domain with more than `FANOUT = 200` distinct names per day of the window.

Tunnelled data and tracking identifiers look like this.

### TV

Always. `TV:` and the hourly power readings collapsed into runs, as in `08:20=unreachable, 09:19=Active`. (W12) When the readings have named the TV, the line carries it in parentheses, `TV (OLED55CXPUA, webOS 5 (5.6.2), firmware 04.64.00):` (`tv_card`: the last `model`, `webos.generation`, `webos.release` and `firmware` values). In a window longer than 90000 seconds (25 hours) the times carry the date, as in `10-26 08:20`. `unreachable` means the TV did not answer and `unknown` that it answered without a power state. `no readings` means the window has none, which is every day on a profile without a LAN-API reader.

### TV settings

When any. Each setting first read or changed in the window, with the time of the reading: `option.livePlus` (Live Plus) and the other keys the TV's LAN API reports. A read error is not a value and is not stored. Red line 2 reads the last Live Plus reading before the window's end, not this list.

### Rule changes

When any. The rules added or removed in the window: the kind (`adguard`, `gfts-block` or `block4`), the rule, when it was added and when it was removed. Ingest reads the rule history each run from AdGuard's `user_rules`, the nginx regex and `block4.txt`, so a rule appears here in the hour ingest first or last saw it.

## JSON output

`--json` on `tvgw brief` and `tvgw report` prints the dict `window_report()` built, as `json.dumps(o, indent=1)`: the same data the text renders, before any formatting. `tvgw-analyze` writes it beside each text report. `tvgw report --day DAY --json`, which writes the daily JSON, adds the key `plain`, the plain brief's lines; `tvgw brief --json` does not. It differs from the text in four ways:

- Times are epoch seconds, except `tvstate[].time`, which is the formatted local time the TV line uses.
- Bytes are integers, not `cli.hb()` text.
- Lists are whole where the text shortens them: every LAN probe, every TV reading, and the firewall counters by rule comment rather than by label.
- Some keys reach the text only through a red line or not at all, such as `must_allow_blocked`, `acr`, `acr_upload`, `acr_port`, `ech` and `autonomous.pending`.

The JSON is not minimized. It holds the LAN probe targets and the TV's settings, so treat a JSON report as private as the store. The analyst's evidence pack is built from the same report and minimized: [the analyst and autonomy](../how-it-works/analyst-and-autonomy.md).

The keys, in the order `window_report()` adds them:

| Key | Holds |
|---|---|
| `day` | The day; `tvgw brief` and `report --day` only, as the first key. |
| `label` | The window's name on the first line. |
| `since`, `until`, `generated` | The window's bounds and when the report was built. |
| `coverage` | `last_run`, `warnings`, `sources` (per source `rows`, `last_read`, `assessed`), `not_assessed` and `adguard_version`. |
| `categories` | The By category rows. |
| `plain_http` | The Plain HTTP groups: `host`, `method`, `path`, `requests`, `agents`. |
| `dns_bypass` | DNS sent to other resolvers: `dst`, `flows`, `pkts`. |
| `dns` | The header's `lookups`, `blocked` and `names`. |
| `flows` | The header's `conns`, `bytes_up` and `bytes_down`. |
| `new_hosts` | New hosts, with `new_domain`. |
| `blocked_retries` | Blocked and still retried. |
| `blocked_reached` | Blocked names still reached over TLS: `hellos`, `blocked`, `allowed`. |
| `allowed_unexpected` | Allowed, outside the expected categories. |
| `top_upload` | Top upload, with `pkts_up` for the payload bound. |
| `beacons` | Periodic connections, with `period`, `jitter`, `payload`, `dports`, `first`, `last` and `acr_like`. |
| `acr_upload` | The ACR-shaped upload cells behind red line 8: `key`, `named`, `dport`, `bucket` (`day` or `hour`), `start`, `day`, `conns`, `payload_up`, `payload_down`, `ratio` (`null` when nothing went down) and `hours`. |
| `gfts` | GFTS URL filter: `status`, `biz_code`, `requests`, `bytes`. |
| `oddports` | Unexpected ports. |
| `lan_probes` | Every LAN probe. |
| `dns_anomalies` | DNS oddities: `kind`, `name`, `lookups`, `blocked`, `detail`. |
| `must_allow_blocked` | The names behind red line 1. |
| `clock` | Clock hosts: `lookups`, `blocked`, `first`, `hosts`. |
| `ntp` | (ntp) Clock servers: `addresses`, `requests` and `servers`, every address the TV sent NTP to in the window, the most used first, each with `dst`, `requests` and up to 5 `names`. |
| `firewall` | `runs`, `failed`, `last_failure_t`, `last_failures`, `activity` (a list of `rule` and `packets` per counter comment, the gate's floored at its samples) and `expected`. |
| `capture_counters` | (capture) The headers capture's counters, `rule` and `packets`: what the firewall handed to NFLOG with `CAPTURE_MODE=headers` ([the capture](../how-it-works/capture.md)). A measure of the capture, so it is not in `firewall.activity` or the analyst's pack. Empty in full mode. |
| `acr_port` | (acr) The adtech port wall behind red line 8's second form: `attempts` (the counter's increase, floored at the samples), `samples`, `ports`, `names`, `unnamed` (sampled addresses no answer named) and up to 5 `examples` by address and port, each with `n`, `first`, `last` and its `names`. |
| `unresolved` | Unresolved flows. |
| `ptr` | Private reverse lookups: `lookups`, `names`. |
| `firmware_changes` | Firmware: `t`, `firmware`, `new_hosts`; (W12) `source` (`firmware` or `webos.release`) and, when both changed in one reading, `release`. |
| `standby` | While off or asleep: `off_hours` (the time the off intervals span), `lookups`, `conns`, `bytes_up`; (activity) `streaming_left_out_hours`, only when calibrated streaming intervals were left out. |
| `standby_names` | (tripwire) What the TV reached in those hours, up to 5: `name`, `lookups`, `conns`; empty when the line counts nothing. Not in the analyst's pack. |
| `standby_notice` | (tripwire) `null` when the line counts nothing; else `port` (`active`, `quiet` or `unsampled`), `days_running` (on a calendar day, up to 4) and `new_names`. Not in the analyst's pack. |
| `tvstate` | Every reading: `time`, `power`, `app`. |
| `settings_changes` | TV settings: `t`, `key`, `value`. |
| `acr` | The last Live Plus reading before the window's end, `key`, `value` and `t`, or `null`. |
| `tv_card` | (W12) The TV as its readings name it: `model`, `generation`, `release`, `firmware`, each when read. |
| `pairing` | (W12) `state` (`ok` or `refused`) and `t` from the key store's record as the ingest copies it, or `null`. |
| `standby_features` | (W12) The standby switches last read on: `key`, `label`, `value`, `t`. |
| `agreements_pending` | (W12) The agreements the TV marks updated and not accepted: `doc`, `name`, `t`. |
| `tv_country` | (W12) `reported`, `code`, `t`, `missing` (the must-allow hosts for that country the profile does not name) and `allow` (the command), or `null`. |
| `rule_changes` | Rule changes: `kind`, `text`, `added`, `removed`. |
| `ech` | `count`, `first` and `outer_names` behind red line 9, and `grease`, the hellos with the extension whose name the TV looked up. |
| `autonomous` | `blocked` and `decided`, the machine-rule rows, and `pending`. |
| `gate` | `new_connections` (floored at the samples), `examples` for DNS-gated egress, each with `dst`, `dport`, `n`, `first`, `last`, `name` and `late`, the samples counted under `just looked up`, and `unexplained`, the samples neither late nor explained by an answer of the week before, with `dst`, `dport`, `n`, `first`, `last` and `name`. |
| `upload_budget` | (budget) The upload budget: `ceiling` (bytes net in a destination-hour), `source` (`fixed`, `owner` or `floor`), `fixed` (the stored derivation: `ceiling`, `largest`, `key`, `hour`, `at_cap`, `since`, `until`, `days`, `times`, `floor`, `cap`, `acr_days`, `set_t`, `rule`, `measure`, `profile`, `tv`, and `previous` after a rederive) or `null`, `pending` (`due`, `since`, `why`, `after`, `uncovered` as they apply, while the ingest has not set it) or `null`, `events`, the destination-hours whose net is over the ceiling, each with `key`, `hour`, `net_up`, `payload_up` (the gross bound), `conns`, `ports` and `named`, `late`, the same for the late hours with `late_net`, and on a calendar day with any, `days_running` and `new_keys`. `null` when it could not be computed, with a report warning. Not in the analyst's pack. |
| `red_lines` | The red lines, as strings. |
| `week`, `by_day` | Weekly reports only, as the last keys: the week and the By day rows. |
| `plain` | (plain) `tvgw report --day` only, as the last key: [the plain brief](#the-plain-brief), one string per line. |
