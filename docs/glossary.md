# Glossary

This page defines each tvgw term in a sentence or two and links to the page that owns its details. It is for any reader who meets a term for the first time, on any page. Terms are in alphabetical order, under their first letter.

## A

### ACR and Live Plus

ACR is screen fingerprinting: the TV reports what is on its screen to an ad company, and the `lg-webos` profile files those hosts under the `ACR` category. Live Plus is LG's setting for it, which `tvgw tvcheck` reads and the brief raises as a red line when it is not off. See [the red lines](operations.md#red-lines).

### analyst

`tvgw analyst`: a Claude model reads one window's evidence pack and answers with proposals, which land under the reports directory with each one's vetting verdict. It runs as a daily pass and as a weekly pass over the ISO week that ended most recently. See [the analyst and autonomy](analyst-and-autonomy.md).

### auto.rules

The machine's rules file: the file the `AUTO_RULES` setting names, which only the gateway writes and which `tvgw adguard apply` adds to the profile's rules after the same lint. Deleting it takes every machine rule out at the next hourly check. See [the analyst and autonomy](analyst-and-autonomy.md).

### autonomous block

A block rule the gateway applies on its own with `ANALYST_APPLY=auto`, under [design decision 20](design-decisions.md#20-the-gateway-blocks-on-its-own-under-three-watches): a block that passes the code's gates and a second model is applied, watched live for 10 minutes by the [canary](#canary), and kept on [probation](#probation) for a day. The machine can only add blocks, and each one stays on probation until the hourly judge passes it. See [the analyst and autonomy](analyst-and-autonomy.md).

## B

### biz_code

The query parameter in the URLs of LG's file service that says what a request is for. The URL filter blocks by it, and `tvgw gfts` counts requests by it. See [the URL filter](../deploy/nginx/README.md).

### block4

The nftables set of addresses the owner blocks by hand, loaded from `block4.txt`; the firewall rejects the TV's traffic to them. See [the firewall](../deploy/nftables/README.md).

### brief

`tvgw brief`: the one-screen report on one calendar day, with Coverage and the red lines first. See [the brief's sections](reading-the-brief.md#sections).

## C

### canary

The live watch that follows an autonomous block while the TV is on. It reads the bytes the Pi sends the TV and the foreground app, and takes the rule out again when the downloads collapse or the app gives way to the launcher. See [the analyst and autonomy](analyst-and-autonomy.md).

### capture filter

The tcpdump expression that decides which of the TV's frames go into a pcap. See [what the capture keeps](privacy-and-retention.md#what-the-capture-keeps).

### category

The group a name falls into under the profile, such as `Streaming`, `LG telemetry` or `Other`; the longest matching pattern wins. See [the profile format](adding-a-profile.md#the-profile-format).

### clock host

A name the TV must look up to set its clock, because webOS has no battery clock and takes the time from LG's SDP reply. The profile lists the patterns in `clock_hosts`, and the brief raises a red line when one is blocked or never looked up. See [the red lines](operations.md#red-lines).

### Coverage

The line near the top of the brief that says, per source, how many rows landed in the window and whether the source was read recently enough to judge. A source that was not is listed as NOT ASSESSED. See [the brief's sections](reading-the-brief.md#sections).

## D

### DNS-gated egress, gate and gate sample

The count-only check of [design decision 18](design-decisions.md#18-dns-gated-egress-starts-as-a-count-in-its-own-table): `tvgw-dnsgate` adds every IPv4 address the resolver hands the TV to the set `resolved4` in table `inet tvgw_gate`, and the gate counts each new connection to an address the set does not hold. A gate sample is one such connection, logged with the `tvgw-gate:` prefix and stored in the `gate` table; nothing is blocked. See [the firewall](../deploy/nftables/README.md).

### DoH set

The nftables set `doh4` of DNS-over-HTTPS resolver addresses, which `tvgw-doh-update` refreshes from `DOH_LIST_URL`. The firewall resets the TV's HTTPS connections to them. See [the firewall](../deploy/nftables/README.md).

## E

### ECH

Encrypted ClientHello, a TLS extension that hides the server name from the capture. The profile withholds the HTTPS and SVCB records that carry its keys, and the brief raises a red line when a hello carries it under an outer name the TV never looked up. A hello whose name the TV did look up is GREASE, the extension sent with random bytes and the real name outside, and is counted apart. See [the red lines](operations.md#red-lines).

### evidence grade

The confidence a profile gives a generation or hardware row, one of `observed`, `community`, `spec` or `low`, under [design decision 15](design-decisions.md#15-blocklist-entries-come-from-evidence-with-grades). The code does not check it; review does. See [the profile format](adding-a-profile.md#the-profile-format).

### evidence pack

The JSON the analyst sends to the model: a window's names, counts, categories, rules and public server addresses, minimized and then scrubbed of the home's identifiers. See [the analyst and autonomy](analyst-and-autonomy.md).

### expected categories

The profile's categories that are the TV doing its job (`expected_categories`). The brief shows an allowed name outside them as a candidate for a rule. See [the profile format](adding-a-profile.md#the-profile-format).

## F

### fail-closed

How the firewall fails: a rule set that does not load, or a stopped `tvgw.service`, leaves the TV with no route out rather than an unfiltered one, under [design decision 5](design-decisions.md#5-fail-closed). See [the firewall](../deploy/nftables/README.md).

### Firewall held

The brief's line of packets each counted firewall rule stopped in the window, summed from the counter snapshots that `tvgw verify --record` stores, under [design decision 13](design-decisions.md#13-counters-not-logs-prove-the-firewall-held). See [the brief's sections](reading-the-brief.md#sections).

### flow

One finished connection of the TV as conntrack reports it: a row in the `flows` table with its packets and bytes each way. A flow takes its name from its own TLS hello. See [naming a connection](architecture.md#naming-a-connection).

## G

### gateway

The Pi running tvgw. In the brief, `Gateway` is also the category of the TV's traffic to the Pi's own address. See [the brief's sections](reading-the-brief.md#sections).

### GFTS

LG's plain-HTTP file service, whose hosts carry app packages and icons as well as the ACR config file and other side channels. tvgw splits it with the URL filter instead of blocking it, under [design decision 8](design-decisions.md#8-a-url-filter-for-lgs-file-service-instead-of-a-dns-block). See [the URL filter](../deploy/nginx/README.md).

## H

### hello and SNI

A hello is the TLS ClientHello, the first message of a TLS connection, and SNI is the server name it carries in clear. The capture keeps the TV's hellos, and each becomes a row in the `tls` table. See [what the capture keeps](privacy-and-retention.md#what-the-capture-keeps).

### hosts

The first-seen ledger: the `hosts` table, with one row per public name seen in `dns`, `tls` or `http`, its first and last sighting, its category and its counters. The hourly ingest refreshes it by watermark. See [the tables](data-model.md#tables).

### hourly judge

`tvgw autoblock check`, which `tvgw-autoblock.timer` runs every hour. It judges every rule on probation against the fresh store, and reverts one when a must-allow or clock red line appears or streaming volume collapses. See [the analyst and autonomy](analyst-and-autonomy.md).

## I

### ingest

`tvgw ingest`, the hourly load of new log lines and finished pcaps into the store, which `tvgw-analyze` runs. See [the commands](../src/tvgw/README.md#commands).

## J

### judgment

The verdict the analyst gave a name, kept by name in the `judgments` table so that a recently judged name does not make a day new again. A block refused for too little evidence, the daily cap or a transient failure is not kept. See [the analyst and autonomy](analyst-and-autonomy.md).

## K

### KB, MB and GB

Sizes in powers of 1024, as `hb()` in `src/tvgw/cli.py` prints them in the brief (`K`, `M` and `G`) and as `tvgw prune-pcaps` applies `PCAP_MAX_GB`. `tvgw ingest`, `tvgw size` and `tvgw backup` print the store's file size in MB of 1,000,000 bytes. See [how these pages are written](README.md#how-these-pages-are-written).

## L

### LAN API and tvcheck

The LAN API is the TV's own control interface on the local network, on webOS the SSAP protocol on port 3000, and on the CX's firmware it refuses writes. `tvgw tvcheck` reads the TV's power state, foreground app and privacy settings through it with a paired key. See [the commands](../src/tvgw/README.md#commands).

### LAN probe

A TCP connection attempt from the TV to an address no internet host answers from, such as a home-LAN, loopback, multicast or broadcast address, other than the gateway. The firewall drops it, and the store keeps it in `lanprobe`. See [the brief's sections](reading-the-brief.md#sections).

### lint

The profile's own check (`Profile.lint` in `src/tvgw/profile.py`), which refuses a rule or regex that covers a must-allow host, a block at the apex of a `never_block_apex` zone, and an exception over a blocked name. It runs in the unit tests, in `tvgw adguard` and `tvgw profile`, on every proposal and on every machine rule. See [the profile format](adding-a-profile.md#the-profile-format).

## M

### machine rule

A block rule in the machine's rules file, put there by the gateway itself and recorded in the `auto_rules` table. `tvgw undo` takes the newest one out. See [the analyst and autonomy](analyst-and-autonomy.md).

### must-allow

A host in the profile's `[must_allow]` table, which the TV needs to work. Each one becomes a generated `@@||host^$important` exception that outranks any list's block, under [design decision 7](design-decisions.md#7-must-allow-exceptions-are-generated-from-the-toml). See [the profile format](adding-a-profile.md#the-profile-format).

## N

### NOT ASSESSED

The Coverage word for a source that was not read recently or whose input was missing: its sections are unknown, not clean. See [the brief's sections](reading-the-brief.md#sections).

### novelty and quiet day

Novelty is the list of reasons a window deserves a request to the model, such as names first seen, red lines or blocked names still reached (`novelty()` in `src/tvgw/analyst.py`). A window with none is a quiet day: the analyst writes a one-line file and sends nothing. See [the analyst and autonomy](analyst-and-autonomy.md).

## O

### odd port

A destination port the firewall does not expect from the TV. The firewall logs that traffic with the `tvgw-oddport:` prefix and counts it, and rejects it only with `STRICT_PORTS=yes`. See [the firewall](../deploy/nftables/README.md).

## P

### payload bound

The most the TV can have sent as data on a connection: conntrack's bytes up less the header bytes of each packet (`payload_bound()` in `src/tvgw/queries.py`). The brief prints it as `payload<=`. See [the brief's sections](reading-the-brief.md#sections).

### pcap

A packet-capture file. `tvgw-pcap` writes one an hour, named in UTC, holding only the frames the capture filter keeps. See [what the capture keeps](privacy-and-retention.md#what-the-capture-keeps).

### periodic connection

A name the TV connects to on a timer, found from the spread of the intervals between its connections. One with the cadence of LG's ACR client and small payloads is marked `ACR-like`. See [the brief's sections](reading-the-brief.md#sections).

### policy

What the TV may reach: the profile, its `.rules` file and the firewall settings, kept in the repository and changed by a deploy. See [changing policy](operations.md#changing-policy).

### probation

The trial an autonomous block is on after it lands, judged every hour until it passes or is reverted. A rule on probation has no verdict in `auto_rules` yet. See [the analyst and autonomy](analyst-and-autonomy.md).

### profile

Everything vendor-specific about a TV, kept as data: a TOML file of categories, must-allow hosts, clock hosts, blocklists and the URL filter, and a companion `.rules` file of AdGuard rules. The `PROFILE` setting picks one. See [the profile format](adding-a-profile.md#the-profile-format).

### proposal

One item of the analyst's answer: a `block`, `allow`, `unblock`, `watch` or `question` about one name, with one rule, the evidence, the risk to the TV, a rollback and the vetting verdict. See [the analyst and autonomy](analyst-and-autonomy.md).

## R

### red line

A sentence at the top of the brief that must never be true, such as a must-allow name blocked or the firewall watchdog not running, under [design decision 14](design-decisions.md#14-red-lines-are-the-alarm-model). See [the red lines](operations.md#red-lines).

### report

The brief over any window. `tvgw report` prints one, and `tvgw-analyze` writes one for the last 24 hours, each finished day and each finished ISO week under the reports directory. See [the brief's sections](reading-the-brief.md#sections).

## S

### scrub

The last step in building the evidence pack (`scrub()` in `src/tvgw/analyst.py`). Every string, dictionary keys included, loses the TV's MAC address, name and address, the gateway's address and host name, every ZIP code and device name the TV has reported, any MAC address and any private, link-local, loopback or multicast IPv4 address, and long strings and lists are cut. See [the analyst and autonomy](analyst-and-autonomy.md).

### SDP

LG's server for the TV, reached at the [clock hosts](#clock-host) (`<cc>.lgtvsdp.com` up to webOS 5 and 6, `<cc>.nextlgsdp.com` from webOS 6 and 22 on, where `<cc>` is the country). Its reply carries the time (`X-Server-Time`), which webOS sets its clock from, because it has no battery clock and NTP is off by default (the comment above `clock_hosts` in `src/tvgw/profiles/lg-webos.toml`). See [the bundled profiles](../src/tvgw/profiles/README.md).

### second model

The verifier: a different model, `ANALYST_VERIFIER_MODEL`, asked to refute each autonomous block before it lands, and never the model that proposed it. A veto, low confidence, a refusal or an error leaves the rule out. See [the analyst and autonomy](analyst-and-autonomy.md).

### settings file

The gateway's one file of `KEY=value` site settings, created from `deploy/tvgw.conf.example` and read by the package and the shell scripts alike. See [the settings file](../deploy/README.md#the-settings-file).

### store

The SQLite file that holds everything tvgw records. The report commands open it read-only, and ingest, `tvgw verify --record`, the analyst, `tvgw autoblock` (the hourly judge, and `list` too, which opens it for writing) and `tvgw undo` write it. See [the tables](data-model.md#tables).

### STRICT_PORTS

The setting that turns odd-port counting into rejection, which stays off until two clean weeks of briefs under [design decision 17](design-decisions.md#17-strict_ports-stays-off-until-two-clean-weeks). See [STRICT_PORTS](operations.md#strict_ports).

## T

### three watches

What judges an autonomous block once it is applied, in the title of [design decision 20](design-decisions.md#20-the-gateway-blocks-on-its-own-under-three-watches): the live [canary](#canary) for the first 10 minutes, the [hourly judge](#hourly-judge) for the day of [probation](#probation), and the owner's `sudo tvgw undo` at any time. See [taking a rule out](analyst-and-autonomy.md#taking-a-rule-out).

### traffic shape

How the TV used a name in a window: its connections, bytes down and up per connection, how long they lasted, the apps on at the time and the days the name was looked up (`shapes()` in `src/tvgw/autoblock.py`). The machine never blocks a name whose shape shows payload. See [the analyst and autonomy](analyst-and-autonomy.md).

### TV subnet

The network on the Pi's TV-side Ethernet port, which holds only the TV and the gateway's own address. Nothing in it reaches the home LAN. See [the firewall](../deploy/nftables/README.md).

## U

### unit

A systemd service or timer from `deploy/systemd/`; tvgw runs as twelve services and eight timers. See [the units](../deploy/systemd/README.md#units).

### Unresolved

The brief's category for flows that no TLS hello named, often only until the next ingest names them. The brief's Unresolved flows section is stricter: TCP destinations that no hello and no DNS answer explain. See [naming a connection](architecture.md#naming-a-connection).

### uplink

The way the TV's traffic leaves the Pi, set by `UPLINK`. `direct` sends it through `WAN_IF` to the home router, and `vpn` sends it into the tunnel `tun0` and drops it while the tunnel is down; the gateway uses `direct` under [design decision 1](design-decisions.md#1-the-tv-uses-the-direct-uplink-not-the-vpn). See [the settings file](../deploy/README.md#the-settings-file).

### URL filter

nginx on the Pi in front of LG's file service. AdGuard Home answers the file-service names with the gateway's address, and nginx forwards each request or returns 403 when its URL matches the profile's `block_regex`. See [the URL filter](../deploy/nginx/README.md).

## V

### verifier

Another name for the second model. See [second model](#second-model).

### verify

`tvgw verify`, the checks that the firewall, routing, resolver and services still hold. With `--record` it also stores the verdict and a snapshot of every firewall counter. See [what tvgw verify checks](troubleshooting.md#what-tvgw-verify-checks).

## W

### watermark

The entry `hosts_wm` in the `meta` table, which holds, per source table, the highest row id already counted into `hosts` and that row's time, so that a late row is counted once, under [design decision 11](design-decisions.md#11-row-id-watermarks-for-the-hosts-counters). See [the tables](data-model.md#tables).
