# Read your daily brief

You can check the gateway in a minute a day by reading its brief. This page gives the daily check, what to do when the brief says RED LINE, and a sample brief with what to notice in it.

## Your daily check

1. Open a terminal on your own computer and connect to the gateway with `ssh <username>@tvgw.local`, as when you installed it.
2. On the gateway, run `tvgw brief`. It shows yesterday in seven short lines; `tvgw brief <day>` shows another day, such as `tvgw brief 2026-10-26`.
3. Read the Action line. When it says nothing needs your attention, you are done. Otherwise, do what it says. When it says to run `sudo tvgw doctor`, run it: the doctor explains the problem and offers the fix.
4. If a `Not checked:` line follows, do what it asks once. For example, it may ask you to confirm that the TV's Wi-Fi is off.

On the gateway:

```sh
tvgw brief
```

If it says permission denied, your account cannot read the gateway's record; run `sudo tvgw brief` instead.

A brief looks like this one, from the project's tests:

```text
tvgw brief, Wednesday 4 November (yesterday, 24 hours)
  Protection: held all day (144 of 144 checks passed).
  The TV: on about 5 hours. It asked for known tracking services 3,983 times; every one was refused.
  Blocked most: other advertisers, device fingerprinting, LG usage reporting.
  New: nothing new.
  Action: nothing needs your attention.
Engineering report: tvgw brief --full
```

If the Protection line says part of the day's record is missing, part of the brief is unknown, not clean. [Fix a problem](troubleshooting.md#ingest-warnings) says why that happens. On the first day there is no brief yet: it says that your first brief is ready tomorrow morning.

Between briefs, `tvgw status` says in three lines whether the last check held. The gateway checks itself every 10 minutes, and `tvgw status` needs no `sudo`.

That is the whole daily check. `tvgw brief --full` prints the full brief: what the TV looked up, what was blocked, and which names are new. [The brief, section by section](../reference/brief-sections.md#sections) explains every line of it.

A gateway set up before the short brief existed prints the full brief every day. To switch it to the short one, run this once on the gateway:

```sh
echo 'BRIEF_STYLE=plain' | sudo tee -a /etc/tvgw/tvgw.conf
```

## Once a week

Each week, on the gateway, look a little further:

1. Run `sudo tvgw doctor`. It explains every check that did not pass, in plain words. A warning shows only here and in `sudo tvgw verify`, never in the brief.
2. Run `systemctl --failed`. It must list nothing; for a listed service, see [failed units](troubleshooting.md#failed-units).
3. Read the week's new names, and decide on each: block it, leave it allowed, or watch it.
4. If the analyst is on, read its proposals.

On the gateway:

```sh
sudo tvgw doctor                      # every WARN and FAIL, in plain words
systemctl --failed                    # must list nothing
tvgw new-hosts 7d                     # names first seen this week
tvgw allowed 7d                       # allowed names outside the expected categories
tvgw retries 7d                       # blocked names the TV keeps asking for
sudo tvgw analyst --show              # the analyst's newest proposals
```

The gateway also writes a report for each finished week to `/var/lib/tvgw/reports/weekly/`, named like `2026-W43.txt`.

## Red lines

A red line is a sentence that must never be true. The full brief prints each one as `RED LINE:` near its top, in the order to act on them: what the TV needs first, then the gateway's own checks, then the record. The short brief puts the first one that needs a person on its Action line. Nobody is alerted any other way, so the brief is the alarm.

Each red line below starts with the line as the brief prints it; `<...>` marks a value the brief fills in. A few need an engineer. The commands an engineer uses to look deeper are in [the brief's reference](../reference/brief-sections.md#looking-into-a-red-line).

### A name the TV needs was blocked

```text
must-allow name blocked: <name> x<N> by <rule>
```

**What it means.** One of the names the TV needs to keep working came back blocked. Your TV's page lists them under "What stays reachable on purpose". A rule, a blocklist or the filter's settings changed, and the TV may lose its clock, its store or its updates.

**What to do.** On the gateway, run `sudo tvgw adguard diff`. If it lists differences, run `sudo tvgw adguard apply` to put the filter back as tvgw set it. If it prints `AdGuard Home matches the profile and settings`, a rule in the profile blocks the name, and an engineer fixes it ([block or unblock something](blocking.md)).

### A blocklist update blocked a name that carried content

```text
a list update newly blocks <name>, which carried content (list <id>, <bytes> down over <N> connections in the 14 days before, median <bytes>): if the TV needs it, add it to must_allow
```

**What it means.** A shared blocklist updated itself and now blocks a name that carried real content, not tracking, in the two weeks before. Nobody reviewed the change: the lists update on their own.

**What to do.** Check whether an app stopped working. If one did, run `sudo tvgw allow <name>` on the gateway to let the name through ([unblock a name](blocking.md#unblock-a-name)). If nothing broke, leave it.

### Live Plus is on

```text
Live Plus (ACR) is <value> on the TV (since <time>): General > Additional Settings
```

**What it means.** On an LG TV, Live Plus is LG's screen recognition (ACR): it sends a fingerprint of what is on screen to LG's partners. Someone turned it on, or a software update did. The line stays until a reading says it is off.

**What to do.** Turn it off with the remote, under Settings > General > Additional Settings > Live Plus. Then read the TV again on the gateway with `sudo tvgw tvcheck`.

### The TV has a second way out

```text
TV has a second network path: <path> is <state> (since <time>): traffic can leave around the gateway; turn it off under Settings > Network
```

**What it means.** The TV reports that its Wi-Fi or Wi-Fi Direct is on, or that it shares a connection. A Samsung TV reports that it is joined to a Wi-Fi network. Whatever leaves that way never crosses the gateway: no filter and no record.

**What to do.** On the TV, turn Wi-Fi off, forget the saved networks, and turn Wi-Fi Direct off, as [your TV's page](../tv/README.md) shows. Then run `sudo tvgw tvcheck` on the gateway: it must report no second path. If the TV did this by itself after an update, report it to the project.

### The TV's clock lookups were blocked

```text
clock host lookups blocked: <N> (the TV's clock comes from them)
```

**What it means.** The TV sets its clock from its maker's server. Blocked, the clock resets and every secure connection fails, so most apps stop working.

**What to do.** Do what the first red line says, then restart the TV so it asks again.

### The TV never looked up its clock

```text
TV was on but never looked up its clock host (check the SDP hosts are reachable)
```

**What it means.** The TV was on during a whole day and never asked for its clock. It sets its clock when it starts, so a day without a restart can pass without one.

**What to do.** Watch the next day. If the line comes back every day, an engineer checks the clock names in the profile.

### Some of the gateway's checks failed

```text
firewall checks failed <N> of <M> times; last: <failures>
```

**What it means.** The gateway checks itself every 10 minutes, and some of those checks failed during the day.

**What to do.** Run `sudo tvgw verify` and act on each `FAIL` line, as [fix a problem](troubleshooting.md#start-here) says. If every line is `OK` now, a check failed earlier and has recovered.

### The gateway's checks stopped running

```text
firewall checks ran <N> of ~<M> times (is tvgw-verify.timer alive?)
```

**What it means.** Fewer than half of the day's checks ran. A day with no checks would otherwise look clean.

**What to do.** Run `systemctl list-timers 'tvgw-*'`: `tvgw-verify.timer` must be listed with a next run. If it is missing, run `sudo tvgw setup` again and answer `y` when it asks to run the installer, which puts the timer back. If it is listed, an engineer reads `journalctl -u tvgw-verify -n 20`.

### An upload shaped like screen recognition

```text
ACR-shaped upload: <cell>:<port> sent <X> MB up (<R>x down) in <N> connections <on day | in hour HH of day>; Live Plus reads <state>
```

**What it means.** Something the profile does not expect sent far more than it received, the way screen recognition does. It is often an app's own telemetry: that is what both such lines were on the LG CX's first day.

**What to do.** On an LG, confirm with `sudo tvgw tvcheck` that Live Plus is off. Look the name up with `tvgw host <name>`. An engineer then decides whether to block it.

### The TV tried LG's advertising ports

```text
ACR port attempts: <N> connections to TCP <ports> rejected (<names>)
```

**What it means.** The TV tried the ports LG's screen recognition and advertising use. The gateway refused every attempt, so nothing got through.

**What to do.** Nothing, unless a feature you use broke at the same time. Then an engineer looks at what the TV tried.

### Server names started to hide

```text
Encrypted ClientHello in <N> handshakes since <time> (outer names: <names>): per-connection TLS naming is going dark; keep HTTPS records stripped
```

**What it means.** Some of the TV's connections now hide which server they are for, so the gateway can no longer name them one by one.

**What to do.** Run `sudo tvgw adguard diff`. It must print `AdGuard Home matches the profile and settings`, so the setting that stops this is in place. Then watch whether the count grows from day to day.

### The gateway's own lookups left outside its VPN

```text
the Pi's own lookups left outside the VPN: <what> <N> time(s), ... (was the tunnel down? see Coverage)
```

**What it means.** This line appears only on a gateway that runs a VPN client. The gateway's own lookups, not the TV's, went out without the VPN, so your internet provider could see them. The TV is not affected.

**What to do.** Check that the VPN client is connected. If it was restarting at the time, the line ends once it connects.

### An agreement was accepted on the TV

```text
TV consent flag <flag> turned on (at <time>): an agreement was accepted on the TV
```

On a TV that reports each agreement by document, the line names it instead:

```text
TV agreement Viewing Information (S_ADG) accepted (at <time>): an agreement was accepted on the TV
```

**What it means.** One of the TV's data agreements, such as Viewing Information or Voice Information, was accepted: by someone with the remote, or by a software update.

**What to do.** Run `tvgw tvstate 2d` to see when it changed. Decline the agreement again with the remote, where [LG TVs](../tv/lg-webos.md#before-you-connect-the-tv) shows it. If nobody in your household accepted it, report it to the project.

### A rule the gateway added has not been judged yet

```text
machine rule <rule> has spent more than half of judge v2's 14-day ceiling with <N> of <K> clean TV hours
```

**What it means.** This line appears only when the analyst may block on its own. A second, trial way of checking the gateway's own blocks has not yet seen enough ordinary TV hours to decide on one of them. That trial decides nothing.

**What to do.** Nothing. The line is information for the project's decision about the trial.

### No lookups were recorded

```text
TV was on but no lookups were recorded (is the AdGuard query log being read?)
```

**What it means.** The TV was on for at least an hour, and the gateway recorded none of its lookups. A TV that is on looks names up, so the filter's log is not being written or not being read.

**What to do.** Run `sudo tvgw verify` and `systemctl status AdGuardHome`. If both look fine, an engineer reads the hourly job's log.

### No connections were recorded

```text
TV was on but no connections were recorded (is the flow log being read?)
```

**What it means.** The same, for the log of the TV's connections.

**What to do.** Run `systemctl status tvgw-flowlog`. If it is not running, an engineer reads its log.

### Warnings while reading the logs

```text
ingest warnings: <N>
```

**What it means.** The hourly job that reads the gateway's logs printed warnings. Each one is listed under the Coverage line as an `ingest warning:` line.

**What to do.** Look each one up in [ingest warnings](troubleshooting.md#ingest-warnings). The same warning every hour is a real fault.

### Lines worth an answer

These are not red lines, but each deserves a look when it appears. Rows follow the brief's order.

| Line | What it means | What to do |
|---|---|---|
| `NOT ASSESSED` in Coverage | That source was not read recently, or its input is missing, so its sections are unknown. | Find the cause in [ingest warnings](troubleshooting.md#ingest-warnings). |
| Firewall held: `DNS forced to AdGuard` above 0 | The TV sent lookups to another DNS server, and the gateway sent them to its filter instead. The TV has servers written into its software. | Note a rise after a software update of the TV. |
| While off/asleep with traffic | Lookups or connections in hours the TV reported itself off or in standby. | `tvgw tvstate 2d` shows the TV's readings. |
| Blocked names still reached over TLS | A name with blocked lookups that the TV still connected to: an answer it kept from before, an address written into its software, or a rule that changed during the day. | If its allowed lookups are 0, the TV reached it by address; an engineer can block the address ([block an address](blocking.md#block-an-address)). |
| DNS-gated egress (count-only) | New connections to addresses no lookup in the last day returned. Samples under `just looked up` came within two seconds of an answer, before the gateway had noted it. The others are a server written into the TV's software, or a way around the filter. On a gateway set to hold each lookup answer until its addresses are noted (`DNSGATE_FILL=inpath`), a line below the table gives a second count made that way, beside the first; it should stay near zero. | Look the address up with `tvgw host <address>`. If it is a tracker, an engineer can block the address. |
| List changes: `newly blocks` without `CARRIED CONTENT` | A list began blocking a name the TV used, with a tracking-sized shape. Usually what the list is for. | Read the row; if an app misbehaved since then, treat it as the red line above. |
| List changes: `newly allows` | A list stopped blocking a name the TV now looks up. | If it is a tracker you want kept out, run `sudo tvgw block <name>` ([block a name](blocking.md#block-a-name)). |
| Rules the gateway added on its own, verdict `reverted` | The gateway took one of its own blocks out; the reason says why. | Read [taking a rule out](analyst.md#taking-a-rule-out). |
| Rules the gateway added on its own, `on probation, untested` | One of the gateway's own blocks has been on trial for 14 days without enough TV use to judge it. It stays in place, and it is listed every day until you decide. | Keep it, or take it out with `sudo tvgw undo`. |
| Rules the gateway added on its own, `queued` | A block that waits its turn, since the gateway tries one at a time. | Nothing. `sudo tvgw autoblock list` shows the queue. |
| Unexpected ports | TV traffic to ports other than 80, 123 and 443. | See [refuse unusual ports](blocking.md#refuse-unusual-ports). |
| Unresolved flows | Connections no lookup or server name explains: an address written into the TV's software, or a way around the filter. | Look the address up as for DNS-gated egress. |
| Firmware | A software version that differs from the reading before it, and the names first seen around it. | Judge the new names as you judge new hosts: an update can bring new ones. |

## A sample brief

This is a full brief, as `tvgw brief --full` prints it, from the project's tests: a made-up gateway's 2026-10-26, with one hour of data. Two values are placeholders, a home address and a postal code, because neither belongs in the repository.

```text
=== 2026-10-26: 2 lookups (1 blocked, 2 names), 2 connections, up 2.3K down 10.6K
Coverage: flows 2, dns 2, pcaps 1, gfts 2, tvstate 2, oddport 1, gate 0, verify 0; last ingest 10-26 10:00
NOT ASSESSED (source not read recently): verify
Firewall held: no counter snapshots yet; no checks recorded
Clock hosts: 1 lookups (0 blocked), first at 09:14

By category:
category    lookups  blocked  names  conns  up    down
LG ads      1        1        1      0      0B    0B
LG core     1        0        1      0      0B    0B
Unresolved  0        0        0      1      2.2K  10.5K
Gateway     0        0        0      1      64B   145B

New hosts (4):
name                          category  dns  tls  http  state
gfts.lge.com                  LG core   0    1    0     ?        new domain
ngfts.lge.com                 LG core   0    0    3     ?
us.lgtvsdp.com                LG core   1    0    0     allowed  new domain
aic.recommend.lgtvcommon.com  LG ads    1    0    0     BLOCKED  new domain

Blocked and still retried:
name                          lookups  rule
aic.recommend.lgtvcommon.com  1        ||recommend.lgtvcommon.com^

Allowed, outside the expected categories:
name  category  lookups
(none)

Top upload (per TLS name; IP when no hello was captured; payload<= strips 40 B of headers per packet):
name           dst            port  conns  up    payload<=  down
(no TLS name)  142.251.219.1  443   1      2.2K  1.5K       10.5K

GFTS URL filter (status biz_code: requests):
  200 APP_STORE: 1, 403 PREMIUM: 1

Unexpected ports: TCP/8080 -> 156.147.69.32 x1
LAN probes (dropped): <lan-address>:80 x1

Unresolved flows (no DNS answer or TLS name explains the address):
dst            port  conns  up    down
142.251.219.1  443   1      2.2K  10.5K

TV: 08:20=unreachable, 09:19=Active

TV settings (first reading or change):
time         key              value
10-26 09:19  option.livePlus  off
10-26 09:19  option.zipcode   <zip>

Rule changes:
kind        rule                                               added        removed
adguard     @@||us.lgtvsdp.com^$important                      10-26 10:00
adguard     ||alphonso.tv^                                     10-26 10:00
adguard     ||ngfts.lge.com^$dnsrewrite=10.10.10.1             10-26 10:00
block4      203.0.113.9                                        10-26 10:00
gfts-block  biz_code=(PREMIUM|CDP|LGSHOPPING|MAS|IBS)([&_]|$)  10-26 10:00
```

What to notice:

1. **Coverage first.** `verify` is `NOT ASSESSED`, because the sample gateway never recorded a check. So Firewall held says `no counter snapshots yet; no checks recorded`. Nothing that day shows the firewall held, and the brief says so instead of showing zeros.
2. **No red line.** The TV was `Active` at 09:19, and its one clock lookup, `us.lgtvsdp.com`, was allowed. The record holds both lookups and connections, so none of the red lines about missing records appears either.
3. **One connection, seen twice.** The `Unresolved` row of By category and the Unresolved flows table describe the same connection to `142.251.219.1`. No lookup and no server name explained it.
4. **A blocked name the TV asked for.** `aic.recommend.lgtvcommon.com` appears in New hosts as `BLOCKED`, and again under Blocked and still retried, with the rule that blocked it.
