# Glossary

This page defines each tvgw term in a sentence or two and links to the page that owns its details. It is for any reader who meets a term for the first time, on any page. Terms are in alphabetical order, under their first letter.

## A

### ACR and Live Plus

ACR is screen fingerprinting: the TV reports what is on its screen to an ad company, and the `lg-webos` profile files those hosts under the `ACR` category. Live Plus is LG's setting for it, which `tvgw tvcheck` reads and the brief raises as a red line when it is not off. The brief looks for ACR on the wire too, with the [acr_uploader](#acr_uploader) test and the [adtech port wall](#adtech-port-wall). See [the red lines](../use/daily-brief.md#red-lines).

### acr_uploader

The brief's ACR test (`queries.acr_uploader` in `src/tvgw/queries.py`). It groups the TV's flows into cells, the registrable domain of the TLS name (or the server's /24 when no hello named it) and the server port, and flags a cell outside the expected categories that uploads as LG's ACR client does: in a day at least 1 MB of payload up at 4 times the payload down over 24 connections (`ACR_DAILY`), or in a clock hour 500 KB, 4 times and 5 connections (`ACR_HOURLY`). Each hit is an `ACR-shaped upload` red line. See [design decision 45](../design-decisions.md#45-the-acr-red-line-is-an-upload-test-and-a-port-wall).

### adtech port wall

The firewall rule that resets the TV's TCP connections to the ports LG's ad tech used in a published 2026 lab trace of a newer LG: 4001, 4431, 4445, 4447, 8180 and 8883. With `ADTECH_PORT_WALL=yes`, the default, and `PROFILE=lg-webos`, it sits in `tv_out` before the odd-port rules, counts as `LG adtech port` and logs a sample with the `tvgw-adport:` prefix into the `adport` table; the counter's rise is the `ACR port attempts` red line. `no`, or any other profile, leaves the ports to the odd-port rules. See design decisions [45](../design-decisions.md#45-the-acr-red-line-is-an-upload-test-and-a-port-wall) and [62](../design-decisions.md#62-a-tv-gets-a-vendor-profile-only-on-evidence-or-its-owners-answer-otherwise-the-general-profile-which-isolates-records-briefs-and-blocks-only-shared-lists).

### analyst

`tvgw analyst`: a Claude model reads one window's evidence pack and answers with proposals, which land under the reports directory with each one's vetting verdict. It runs as a daily pass and as a weekly pass over the ISO week that ended most recently. See [the analyst and autonomy](../how-it-works/analyst-and-autonomy.md).

### armed canary

A [canary](#canary) waiting for someone to watch: a block applied while the TV is not awake with a streaming app in front, as at the 03:50 analyst run, is recorded with its canary `armed`, and the hourly check runs the 10-minute watch at the first reading that shows the TV so, one watch per run. A watch the process does not finish stays armed for the next check. See [design decision 41](../design-decisions.md#41-the-autonomy-refuses-what-it-cannot-see-and-keeps-what-it-decided).

### auto.rules

The machine's rules file: the file the `AUTO_RULES` setting names, which only the gateway writes and which `tvgw adguard apply` adds to the profile's rules after the same lint. Deleting it takes every machine rule out at the next hourly check. See [the analyst and autonomy](../how-it-works/analyst-and-autonomy.md).

### autonomous block

A block rule the gateway applies on its own with `ANALYST_APPLY=auto`, under [design decision 20](../design-decisions.md#20-the-gateway-blocks-on-its-own-under-three-watches): a block that passes the code's gates and a second model is applied, watched live for 10 minutes by the [canary](#canary), and kept on [probation](#probation) for at least a day, one rule at a time. The machine can only add blocks, and each one stays on probation until the hourly judge passes it, or untested when the TV was hardly watched. See [the analyst and autonomy](../how-it-works/analyst-and-autonomy.md).

## B

### biz_code

The query parameter in the URLs of LG's file service that says what a request is for. The URL filter blocks by it, and `tvgw gfts` counts requests by it. See [the URL filter](../../deploy/nginx/README.md).

### block4

The nftables set of addresses the owner blocks by hand, loaded from `block4.txt`; the firewall rejects the TV's traffic to them. See [the firewall](../../deploy/nftables/README.md).

### brief

`tvgw brief`: the one-screen report on one calendar day, with Coverage and the red lines first. See [the brief's sections](brief-sections.md#sections). The plain brief is the same day in seven plain lines, with each red line in one of three tiers, act, doctor or detail; `BRIEF_STYLE` picks which form `tvgw brief` prints ([the plain brief](brief-sections.md#the-plain-brief)).

## C

### canary

The live 10-minute watch of an autonomous block while the TV is on with an app in front. It reads the bytes the gateway sends the TV and the foreground app, and takes the rule out again when the downloads collapse or the app gives way to the launcher. A block applied with nobody watching arms the canary, and the hourly judge runs the watch the first time it finds the TV so ([design decision 41](../design-decisions.md#41-the-autonomy-refuses-what-it-cannot-see-and-keeps-what-it-decided)). See [the analyst and autonomy](../how-it-works/analyst-and-autonomy.md).

### capture filter

The BPF expression dumpcap applies with `CAPTURE_MODE=full` to decide which of the TV's frames go into a pcap. See [what the capture keeps](../how-it-works/privacy-and-retention.md#what-the-capture-keeps).

### category

The group a name falls into under the profile, such as `Streaming`, `LG telemetry` or `Other`; the longest matching pattern wins. See [the profile format](profile-format.md).

### change ledger

(ledger) The `changes` table: one row per change on the gateway (a deploy, an apply, a link or VPN event, an AdGuard restart, a machine rule), class A when it can move what the hourly judge measures and class B when it cannot. Read in the brief's "Changes in effect" and by `tvgw changes`. `tvgw-apply`, the NetworkManager dispatcher and `install.sh` append to its spool, `/var/lib/tvgw/changes.spool`, and the hourly ingest loads it with `LEDGER=on`. See [the change ledger](../how-it-works/analyst-and-autonomy.md#the-change-ledger).

### Changes in effect

(ledger) The brief's section after the red lines: the change ledger's class-A changes in the window with their times, class B as counts, each machine rule on trial with both judges' verdicts, and the [hour classes](#hour-class) of the window's TV hours. It appears once the ledger has anything for the window, and never with `LEDGER=off`. See [Changes in effect](brief-sections.md#changes-in-effect).

### clock host

A name the TV must look up to set its clock, because webOS has no battery clock and takes the time from LG's SDP reply. The profile lists the patterns in `clock_hosts`, and the brief raises a red line when one is blocked or never looked up. See [the red lines](../use/daily-brief.md#red-lines).

### co-tenant

(guard) A unit of other software on the gateway that never talks to the TV, such as Samba, xrdp, shairport-sync, avahi, sshd or JupyterHub, named in `CO_TENANT_UNITS`. Each installed one gets the drop-in `10-tvgw-not-from-tv.conf` with `IPAddressDeny=TV_NET` and `IPAddressAllow=GW_IP/32`, a cgroup filter that keeps the TV subnet off it with every nftables table gone. dnsmasq, nginx, AdGuard Home and tvgw's own units are refused, since they serve the TV. See [design decision 42](../design-decisions.md#42-the-pi-is-closed-to-the-tv-whatever-nftables-holds).

### conntrack event mark

(events) What the `ct_events` chain of `inet tvgw` gives each new connection from the TV subnet: `ct event set destroy`, so conntrack reports it when it ends. `tvgw-apply` sets `nf_conntrack_events=0` once the chain is loaded, so no unmarked connection makes events and `tvgw-flowlog` hears the TV alone. See [design decision 43](../design-decisions.md#43-the-flow-log-hears-the-tv-alone-and-the-gates-day-starts-at-each-answer).

### Coverage

The line near the top of the brief that says, per source, how many rows landed in the window and whether the source was read recently enough to judge. A source that was not is listed as NOT ASSESSED. It ends with the AdGuard Home version and, where `piactl` answers, PIA's state (`PIA Connected`), both as the last `tvgw verify --record` run saw them. See [Coverage](brief-sections.md#coverage).

## D

### decisions table

(autonomy) The append-only `decisions` table: one row per gate decision, queue event, second-model answer, apply, canary outcome, judge verdict and owner revert, with the margins each decision was made on, the verifier's model, effort and tokens, and the trial id. A trigger refuses any update. `DECISIONS_DAYS` sets how long rows are kept (`keep` by default). See [the tables](data-model.md#tables).

### DNS-gated egress, gate and gate sample

The count-only check of [design decision 18](../design-decisions.md#18-dns-gated-egress-starts-as-a-count-in-its-own-table): `tvgw-dnsgate` adds every IPv4 address the resolver hands the TV to the set `resolved4` in table `inet tvgw_gate`, and the gate counts each new connection to an address the set does not hold. A gate sample is one such connection, logged with the `tvgw-gate:` prefix and stored in the `gate` table; nothing is blocked. See [the firewall](../../deploy/nftables/README.md).

### DoH set

The nftables set `doh4` of DNS-over-HTTPS resolver addresses, which `tvgw-doh-update` refreshes from `DOH_LIST_URL`. The firewall resets the TV's HTTPS connections to them. See [the firewall](../../deploy/nftables/README.md).

## E

### ECH

Encrypted ClientHello, a TLS extension that hides the server name from the capture. The profile withholds the HTTPS and SVCB records that carry its keys, and the brief raises a red line when a hello carries it under a known ECH public name (`cloudflare-ech.com` or `vercel-ech.com`) or an outer name the TV never looked up. Any other hello whose name the TV did look up is GREASE, the extension sent with random bytes and the real name outside, and is counted apart. See [the red lines](../use/daily-brief.md#red-lines) and [the ECH canary](../how-it-works/extractor.md#the-ech-canary).

### evidence grade

The confidence a profile gives a generation or hardware row, one of `observed`, `community`, `spec` or `low`, under [design decision 15](../design-decisions.md#15-blocklist-entries-come-from-evidence-with-grades). The code does not check it; review does. See [the profile format](profile-format.md).

### evidence pack

The JSON the analyst sends to the model: a window's names, counts, categories, rules and public server addresses, minimized and then scrubbed of the home's identifiers. See [the analyst and autonomy](../how-it-works/analyst-and-autonomy.md).

### expected categories

The profile's categories that are the TV doing its job (`expected_categories`). The brief shows an allowed name outside them as a candidate for a rule. See [the profile format](profile-format.md).

### evening

(app in front) The viewing day the receipt groups sessions by: 05:00 local time to 05:00 the next morning (`DAY_START_HOUR` in `src/tvgw/appfront.py`), so a film that runs past midnight belongs to the evening it started in. See [the app in front](../how-it-works/app-in-front.md#pictures).

## F

### fail-closed

How the firewall fails: a rule set that does not load, or a stopped `tvgw.service`, leaves the TV with no route out rather than an unfiltered one, under [design decision 5](../design-decisions.md#5-fail-closed). See [the firewall](../../deploy/nftables/README.md).

### Firewall held

The brief's line of packets each counted firewall rule stopped in the window, summed from the counter snapshots that `tvgw verify --record` stores, under [design decision 13](../design-decisions.md#13-counters-not-logs-prove-the-firewall-held). See [the brief's sections](brief-sections.md#sections).

### flow

One finished connection of the TV as conntrack reports it: a row in the `flows` table with its packets and bytes each way. A flow takes its name from its own TLS hello. See [naming a connection](../how-it-works/architecture.md#naming-a-connection).

### forget

(record) `tvgw forget`: deletes every viewing-derived row and file (the flows, lookups, hellos, TV readings, reports, pcaps, backups and the change ledger among them) and keeps the gateway's settings, rules, verify history and schema. It is all or nothing, and for 7 days afterwards every ingest drops late evidence of the forgotten time. See [forgetting the viewing record](../use/privacy.md#forget-the-viewing-record).

## G

### gateway

The computer running tvgw; the reference gateway is the owner's Raspberry Pi 5, where a fact is true of it alone. In the brief, `Gateway` is also the category of the TV's traffic to the gateway's own address. See [the brief's sections](brief-sections.md#sections).

### general profile

The bundled profile `generic-tv`, for a TV no vendor profile is assigned to on evidence or by its owner's answer. It blocks only what two shared lists block, has no must-allow hosts, URL filter or LAN-API reader, gets no LG port wall and raises no clock red line. The settings template names it. See [the general profile](../../src/tvgw/profiles/README.md#the-general-profile) and [design decision 62](../design-decisions.md#62-a-tv-gets-a-vendor-profile-only-on-evidence-or-its-owners-answer-otherwise-the-general-profile-which-isolates-records-briefs-and-blocks-only-shared-lists).

### GFTS

LG's plain-HTTP file service, whose hosts carry app packages and icons as well as the ACR config file and other side channels. tvgw splits it with the URL filter instead of blocking it, under [design decision 8](../design-decisions.md#8-a-url-filter-for-lgs-file-service-instead-of-a-dns-block). See [the URL filter](../../deploy/nginx/README.md).

### guard

(guard) The nftables table `inet tvgw_guard`, which `tvgw-guard.service` loads at boot from `/etc/tvgw/guard.nft`, before the TV port comes up, and never unloads: the unit has no stop path and refuses a manual stop. Its input, forward and output chains run after `inet tvgw`'s and can only narrow what it allows, so the gateway stays closed to the TV, but for DHCP, DNS, nginx and pings, whether or not `inet tvgw` is loaded. See [the guard](../../deploy/nftables/README.md#the-guard) and [design decision 42](../design-decisions.md#42-the-pi-is-closed-to-the-tv-whatever-nftables-holds).

### gap (app in front)

(app in front) A stretch in which the TV may have been on and nothing says which app was in front: the live session was lost, the hourly readings either side disagree, or the gateway's clock was set. A connection that started in a gap is nobody's; the receipt says what started there and which TLS fingerprint it carried. See [the app in front](../how-it-works/app-in-front.md#sessions-gaps-and-none).

## H

### hello and SNI

A hello is the TLS ClientHello, the first message of a TLS connection, and SNI is the server name it carries in clear. The capture keeps the TV's hellos, and each becomes a row in the `tls` table. See [what the capture keeps](../how-it-works/privacy-and-retention.md#what-the-capture-keeps).

### hosts

The first-seen ledger: the `hosts` table, with one row per public name seen in `dns`, `tls` or `http`, its first and last sighting, its category and its counters. The hourly ingest refreshes it by watermark. See [the tables](data-model.md#tables).

### hour class

(ledger) What the hour classifier calls one clock hour: `off`, `no_demand` (the TV on an input or the launcher, nothing streaming), `confounded` (demand, and a class-A change or a bad sample against it) or `clean`. Only clean hours can judge a rule. See [the hour classifier](../how-it-works/analyst-and-autonomy.md#the-hour-classifier).

### hourly judge

`tvgw autoblock check`, which `tvgw-autoblock.timer` runs every hour. It judges every rule on probation against the fresh store, and reverts one when a must-allow or clock red line appears or streaming collapses for two TV hours running with demand. It runs an armed canary when the TV is next watched. See [the analyst and autonomy](../how-it-works/analyst-and-autonomy.md).

## I

### ingest

`tvgw ingest`, the hourly load of new log lines and finished pcaps into the store, which `tvgw-analyze` runs. See [the commands](commands.md).

## J

### judge v2 and shadow

(ledger) Judge v2 is the judge the November research proposes (`src/tvgw/judge2.py`): it judges only clean demand hours, passes a rule only after `JUDGE2_CLEAN_HOURS` of them, suspends a rule instead of reverting it when the low hours were confounded, and returns [NODATA](#nodata) instead of passing a trial it could not see. It runs in shadow: every hour, after the shipped judge has decided, `tvgw autoblock check` records both judges' verdicts in `judge_shadow`, and nothing reads them to decide. Whether v2 replaces the shipped judge is an owner decision. See [judge v2, in shadow](../how-it-works/analyst-and-autonomy.md#judge-v2-in-shadow).

### judgment

The verdict the analyst gave a name, kept by name in the `judgments` table so that a recently judged name does not make a day new again. A block refused for too little evidence, no observed connections, the daily cap or a transient failure is not kept. Every decision on the way is also a row in the append-only `decisions` table. See [the analyst and autonomy](../how-it-works/analyst-and-autonomy.md).

### JA4

A fingerprint of a TLS client's ClientHello, `t13d1516h2_8daaf6152771_e5627efa2ab1` in shape: transport, version, counts and ALPN, then hashes of the sorted cipher and extension lists. It names a TLS stack, not a server, which is what makes a hello without a server name readable. Stored in `tls.ja4` and `tls_noname.ja4`. See [JA4](../how-it-works/extractor.md#ja4).

## K

### KB, MB and GB

Sizes in powers of 1024, as `hb()` in `src/tvgw/cli.py` prints them in the brief (`K`, `M` and `G`) and as `tvgw prune-pcaps` applies `PCAP_MAX_GB`. `tvgw ingest`, `tvgw size` and `tvgw backup` print the store's file size in MB of 1,000,000 bytes. See [writing these pages](../project/writing-docs.md).

## L

### LAN API and tvcheck

The LAN API is the TV's own control interface on the local network, on webOS the SSAP protocol over TLS on port 3001 (port 3000, without TLS, is gone on 2022 and later sets and refused by the CX), and on the CX's firmware it refuses writes. `tvgw tvcheck` reads the TV's power state, foreground app and privacy settings through it with a paired key, and asks the TV nothing without one, since a connection with no key is the pairing prompt on the TV's screen; `tvgw setup` and `tvgw tv pair` pair. (samsung) On a Samsung it is the REST interface on port 8001, which answers `GET /api/v2/` without pairing: `tvgw tvcheck` reads the model, the power state and whether the TV is on its cable or on Wi-Fi there, and sends nothing else. See [the commands](commands.md).

### LAN probe

A TCP connection attempt from the TV to an address no internet host answers from, such as a home-LAN, loopback, multicast or broadcast address, other than the gateway. The firewall drops it, and the store keeps it in `lanprobe`. See [the brief's sections](brief-sections.md#sections).

### ledger

Short for the [change ledger](#change-ledger).

### List changes

(lists) The brief's section on what a blocklist's own update changed for the TV: names a list began blocking that the TV had resolved, with their recent traffic, and names a list stopped blocking. See [List changes](brief-sections.md#list-changes).

### lint

The profile's own check (`Profile.lint` in `src/tvgw/profile.py`), which refuses a rule or regex that covers a must-allow host, a block at the apex of a `never_block_apex` zone, and an exception over a blocked name. It runs in the unit tests, in `tvgw adguard` and `tvgw profile`, on every proposal and on every machine rule. See [the profile format](profile-format.md).

### local.rules

The owner's site rules: the file the `LOCAL_RULES` setting names, `/etc/tvgw/local.rules` by default, which only `tvgw allow`, `tvgw block`, `tvgw unallow` and `tvgw unblock` write and which `tvgw adguard apply` puts after the profile's rules and before the machine's, under the same lint. It does not exist until the first of those commands. See [your own rules](../use/blocking.md#your-own-rules) and [design decision 59](../design-decisions.md#59-site-rules-etctvgwlocalrules-written-by-tvgw-allow-and-tvgw-block-applied-after-the-profile-and-before-machine-rules-under-the-same-lint).

### live reading

(app in front) `tvgw-tvlive.service`, off unless `LIVE_READING=on`: one read-only session to an LG TV that reports each change of its power state and of the app in front, so sessions are timed to the second. It connects only under [its connection rules](../how-it-works/app-in-front.md#before-every-connection), and stands down (stops until `sudo tvgw tvlive --resume`) when it would cost the hourly reading an answer.

## M

### machine rule

A block rule in the machine's rules file, put there by the gateway itself and recorded in the `auto_rules` table. `tvgw undo` takes the newest one out. See [the analyst and autonomy](../how-it-works/analyst-and-autonomy.md).

### minted address

(mint) An address made up for one name at one real address, from a range that exists nowhere else (`198.18.0.0/15`), which a later version could hand the TV in place of the real one, so that the address of every connection says which name it means. No TV is handed one today: `tvgw mint replay` only asks the record what such a table would have held for each connection. A minted address with its name, its real address and its end is a ticket. See [design decision 85](../design-decisions.md#85-one-address-per-name-the-minting-table-first-as-a-replay-over-the-record-that-changes-nothing).

### must-allow

A host in the profile's `[must_allow]` table, which the TV needs to work. Each one becomes a generated `@@||host^$important` exception that outranks any list's block, under [design decision 7](../design-decisions.md#7-must-allow-exceptions-are-generated-from-the-toml). See [the profile format](profile-format.md).

## N

### name-bound

(namebound) A TLS connection whose hello names something the filter answered with that connection's address in the day before it: the question or any name of the answer's CNAME chain. The brief's server names section puts every other TLS connection in a class of its own: an address answered only for other names (a server shared by many names), an address never answered, no name, ECH, or not assessed. Counted, never refused. See [design decision 70](../design-decisions.md#70-each-tls-connection-is-checked-against-the-names-the-filter-answered-with-its-address-a-report-from-the-store-a-live-count-from-copies-and-nothing-refused) and [the brief's sections](brief-sections.md#server-names-against-the-filters-answers).

### NODATA

(autonomy) The hourly judge's answer when a trial has ended with fewer than two TV hours with demand in it: not a verdict. The trial runs a day longer, up to 14 days after the block (`TRIAL_CEILING` in `src/tvgw/autoblock.py`), and a rule still without the hours there ends [untested](#untested). Judge v2 answers NODATA the same way for clean hours. See [design decision 41](../design-decisions.md#41-the-autonomy-refuses-what-it-cannot-see-and-keeps-what-it-decided).

### NOT ASSESSED

The Coverage word for a source that was not read recently or whose input was missing: its sections are unknown, not clean. See [the brief's sections](brief-sections.md#sections).

### novelty and quiet day

Novelty is the list of reasons a window deserves a request to the model, such as names first seen, red lines or blocked names still reached (`novelty()` in `src/tvgw/analyst.py`). A window with none is a quiet day: the analyst writes a one-line file and sends nothing. A routine name, first seen under a domain the store knew, in an expected category, allowed and carrying content, is no reason for the daily pass ([when no request is made](../how-it-works/analyst-and-autonomy.md#when-no-request-is-made)). A quiet verdict is the `judgments` row a pass leaves for a name it looked at and proposed nothing about; it keeps the daily pass from asking about the same name for a week, and the weekly review ignores it. A name that reads like an instruction gets a held verdict instead, which keeps the daily pass quiet only while the name's evidence is unchanged ([design decision 22](../design-decisions.md#22-a-pass-that-proposes-nothing-is-remembered)). See [the analyst and autonomy](../how-it-works/analyst-and-autonomy.md).

## O

### odd port

A destination port the firewall does not expect from the TV. The firewall logs that traffic with the `tvgw-oddport:` prefix and counts it, and rejects it only with `STRICT_PORTS=yes`. See [the firewall](../../deploy/nftables/README.md).

## P

### payload bound

The most the TV can have sent as data on a connection: conntrack's bytes up less the header bytes of each packet (`payload_bound()` in `src/tvgw/queries.py`). The brief prints it as `payload<=`. See [the brief's sections](brief-sections.md#sections).

### partial hello

A ClientHello read from the first TCP segment alone, because the capture did not keep the rest. It keeps its server name when the name was in that segment, never a JA4. See [how a hello is read](../how-it-works/extractor.md#how-a-hello-is-read).

### pcap

A packet-capture file. `tvgw-pcap` writes one an hour, named in UTC, holding only the frames the capture filter keeps. See [what the capture keeps](../how-it-works/privacy-and-retention.md#what-the-capture-keeps).

### periodic connection

A name the TV connects to on a timer, found from the spread of the intervals between its connections. A timer is an attribute, never an alarm; a row whose name and port also uploaded as LG's ACR client does is marked `ACR-like`. See [the brief's sections](brief-sections.md#sections).

### policy

What the TV may reach: the profile, its `.rules` file and the firewall settings, kept in the repository and changed by a deploy, and (site rules) the owner's own allows and blocks in [local.rules](#localrules), written on the gateway. See [block or unblock something](../use/blocking.md).

### probation

The trial an autonomous block is on after it lands, judged every hour until it passes or is reverted. A rule on probation has no verdict in `auto_rules` yet, or the verdict `untested`. A trial passes only on enough TV hours with demand; one without them runs longer ([NODATA](#nodata)), up to 14 days, and then stays in place as [untested](#untested), shown as `on probation, untested`. One rule is on trial at a time; the next is [queued](#queued). See [the analyst and autonomy](../how-it-works/analyst-and-autonomy.md).

### profile

Everything vendor-specific about a TV, kept as data: a TOML file of categories, must-allow hosts, clock hosts, blocklists and the URL filter, and a companion `.rules` file of AdGuard rules. The `PROFILE` setting picks one; setup writes it from the TV's evidence or its owner's answer, else the [general profile](#general-profile). See [the profile format](profile-format.md).

### proposal

One item of the analyst's answer: a `block`, `allow`, `unblock`, `watch` or `question` about one name, with one rule, the evidence, the risk to the TV, a rollback and the vetting verdict. See [the analyst and autonomy](../how-it-works/analyst-and-autonomy.md).

### picture (of an app)

(app in front) What has been seen with an app on earlier evenings, by site and kind: in the picture from the day after a name was first seen with the app, with the number of days shown (one day is "only"). The TV's own services and its maker's names are never in a picture. See [the app in front](../how-it-works/app-in-front.md#pictures).

## Q

### queued

(autonomy) The state of a block that cleared the code's gates while another rule was on trial, or while older blocks waited: it waits in the `auto_queue` table. When its turn comes, at an analyst run, the vetting and the gates run again on the evidence read up to then before the second model is asked; a block that waits over 14 days is dropped. The brief and `tvgw autoblock list` show it as `queued`. See [design decision 41](../design-decisions.md#41-the-autonomy-refuses-what-it-cannot-see-and-keeps-what-it-decided).

## R

### red line

A sentence at the top of the brief that must never be true, such as a must-allow name blocked or the firewall watchdog not running, under [design decision 14](../design-decisions.md#14-red-lines-are-the-alarm-model). See [the red lines](../use/daily-brief.md#red-lines).

### refused stamp

(guard) A file `install.sh` writes in `/var/lib/tvgw/.unit-stamps/`, `dnsmasq-refused` or `nginx-refused`, holding the hash of a hardening text the daemon would not serve with. The installer took that hardening out again, and it does not try the same text on later deploys, which print `WARNING: ... runs unhardened`. Delete the stamp to have the next deploy try again. See [what tvgw verify checks](verify-checks.md).

### report

The brief over any window. `tvgw report` prints one, and `tvgw-analyze` writes one for the last 24 hours, each finished day and each finished ISO week under the reports directory. See [the brief's sections](brief-sections.md#sections).

### restart guard

(lists) The check before any AdGuard Home restart: a made-up lookup under a must-allow name, which only a working upstream can answer. While it gets SERVFAIL, or no answer past AdGuard's own upstream timeout while AdGuard still answers a name the profile's rules block, the restart is deferred (`deferred: upstream down`) and nothing changes, because a restart would empty the cache the TV lives on. See [the restart guard](../how-it-works/adguard.md#the-restart-guard).

### receipt

(app in front) `tvgw receipt`: the newest evening, one block per app in front, with what was new for it, the advertising and measurement names reached meanwhile and the blocked names asked for; with `--since`, each session's full list. See [what the TV reached while each app was in front](../use/receipt.md).

## S

### scrub

The last step in building the evidence pack (`scrub()` in `src/tvgw/analyst.py`). Every string, dictionary keys included, loses the TV's MAC address, name and address, the gateway's address and host name, every ZIP code and device name the TV has reported, any MAC address and any private, link-local, loopback or multicast IPv4 address, and long strings and lists are cut. See [the analyst and autonomy](../how-it-works/analyst-and-autonomy.md).

### SDP

LG's server for the TV, reached at the [clock hosts](#clock-host) (`<cc>.lgtvsdp.com` up to webOS 5 and 6, `<cc>.nextlgsdp.com` from webOS 6 and 22 on, where `<cc>` is the country). Its reply carries the time (`X-Server-Time`), which webOS sets its clock from, because it has no battery clock and NTP is off by default (the comment above `clock_hosts` in `src/tvgw/profiles/lg-webos.toml`). See [the bundled profiles](../../src/tvgw/profiles/README.md).

### second model

The verifier: a different model, `ANALYST_VERIFIER_MODEL`, asked to refute each autonomous block before it lands, and never the model that proposed it. It sees the proposal's name and rule and the evidence, never the proposer's argument. A veto, low confidence, a refusal or an error leaves the rule out. See [the analyst and autonomy](../how-it-works/analyst-and-autonomy.md).

### sentinel

(lists) A name each HaGeZi list carries and no other list does, such as `h4g3z1-pro.web.app`. A loaded list answers it with `0.0.0.0`, so `tvgw verify` asks for each one to know the list is in force. See [the sentinels](../how-it-works/adguard.md#the-sentinels).

### settings file

The gateway's one file of `KEY=value` site settings, created from `deploy/tvgw.conf.example` and read by the package and the shell scripts alike. See [the settings file](settings.md).

### store

The SQLite file that holds everything tvgw records. The report commands open it read-only, and ingest, `tvgw verify --record`, the analyst, `tvgw autoblock` (the hourly judge, and `list` too, which opens it for writing) and `tvgw undo` write it. See [the tables](data-model.md#tables).

### STRICT_PORTS

The setting that turns odd-port counting into rejection, which stays off until two clean weeks of briefs under [design decision 17](../design-decisions.md#17-strict_ports-stays-off-until-two-clean-weeks). See [STRICT_PORTS](../use/blocking.md#strict_ports).

### session (app in front)

(app in front) One app in front of the TV from start to end, timed to the second by the live reading or to the hour by two hourly readings that saw the same app. See [the app in front](../how-it-works/app-in-front.md#sessions-gaps-and-none).

### settling

(app in front) A session that ended less than about three hours ago, whose numbers still fill in: conntrack logs a connection only when it lets it go, up to 2 h 04 min after its last packet, and the ingest runs hourly (`SETTLE` in `src/tvgw/receipt.py`).

### site

(app in front) The receipt's word for a registrable domain: the part of a name its owner registered, such as `nflxvideo.net` for `ipv4-c012-sea001-ix.1.oca.nflxvideo.net`. Advertising, measurement and refused names are shown by their full name instead, because one site can hold an app's video and its beacon.

### stood down

(app in front) The live reading's state after an hourly reading failed to reach a TV it was holding, after the TV refused a subscription, or after twelve failed attempts: it leaves a marker and attempts nothing until `sudo tvgw tvlive --resume`.

## T

### threat list

(threats) A public list of names of known malware, botnet and phishing servers (the `tif` kind), or of domains registered in the last days (the `nrd` kind), which the gateway downloads with `THREAT_LISTS=count` and matches the TV's lookups against itself, counting only. A threat-list name the TV reached, which the list is not likely wrong about, is a red line. See [known-bad names](brief-sections.md#known-bad-names).

### three watches

What judges an autonomous block once it is applied, in the title of [design decision 20](../design-decisions.md#20-the-gateway-blocks-on-its-own-under-three-watches): the live [canary](#canary) for the first 10 minutes, the [hourly judge](#hourly-judge) for the [probation](#probation), and the owner's `sudo tvgw undo` at any time. See [taking a rule out](../use/analyst.md#taking-a-rule-out).

### traffic shape

How the TV used a name in a window: its connections, bytes down and up per connection, how long they lasted, the apps on at the time and the days the name was looked up (`shapes()` in `src/tvgw/autoblock.py`). The machine never blocks a name whose shape shows payload. See [the analyst and autonomy](../how-it-works/analyst-and-autonomy.md).

### TV subnet

The network on the gateway's TV-side Ethernet port, which holds only the TV and the gateway's own address. Nothing in it reaches the home LAN. See [the firewall](../../deploy/nftables/README.md).

### TLS fingerprint

(app in front) The [JA4](#ja4) of a hello, read as a sign of which software opened a connection: a fingerprint with nine tenths of at least 100 hellos under one app names that app, and the receipt says "opened like YouTube's software". It suggests the software; it does not say which app was in front. See [the app in front](../how-it-works/app-in-front.md#the-tls-stack).

## U

### unit

A systemd service or timer from `deploy/systemd/`; tvgw runs as twenty-three services and ten timers. See [the units](../../deploy/systemd/README.md#units).

### Unresolved

The brief's category for flows that no TLS hello named, often only until the next ingest names them. The brief's Unresolved flows section is stricter: TCP destinations that no hello and no DNS answer explain. See [naming a connection](../how-it-works/architecture.md#naming-a-connection).

### untested

(autonomy) The verdict of a machine rule whose trial reached 14 days without two TV hours with demand, or whose three days before the block held nothing to compare with. The rule stays in place, is judged for harm every hour, never passes on its own, and is listed in the brief every day as `on probation, untested` until the owner keeps it, adopts it into the profile or undoes it. See [design decision 41](../design-decisions.md#41-the-autonomy-refuses-what-it-cannot-see-and-keeps-what-it-decided).

### upload budget

(budget) A fixed ceiling on what the TV sends one destination outside the profile's expected categories in one clock hour beyond what came back on the same connections, set once by the hourly ingest from the gateway's own clean history, never over a cap that keeps an hour of LG's screen recognition twice over it, and changed only by the owner (`UPLOAD_CEILING`). Count-only: an hour over it is a `would have capped` row in the brief, and nothing is capped. See [the upload budget](brief-sections.md#upload-budget).

### uplink

The way the TV's traffic leaves the gateway, set by `UPLINK`. `direct` sends it through `WAN_IF` to the home router, and `vpn` sends it into the tunnel `VPN_IF` names or finds (`tun0` or `wgpia0`) and drops it while the tunnel is down; the gateway uses `direct` under [design decision 1](../design-decisions.md#1-the-tv-uses-the-direct-uplink-not-the-vpn). See [the settings file](settings.md).

### URL filter

nginx on the gateway in front of LG's file service. AdGuard Home answers the file-service names with the gateway's address, and nginx forwards each request or returns 403 when its URL matches the profile's `block_regex`. See [the URL filter](../../deploy/nginx/README.md).

## V

### verifier

Another name for the second model. See [second model](#second-model).

### verify

`tvgw verify`, the checks that the firewall, routing, resolver and services still hold. With `--record` it also stores the verdict and a snapshot of every firewall counter. See [what tvgw verify checks](verify-checks.md).

### virtual gateway

A copy of the gateway built from Linux network namespaces, with a namespace TV and a namespace internet, that CI loads the real `tvgw-apply` into and probes against the reachability matrix before a firewall change reaches the gateway. See [the virtual gateway](../../tests/virtual/README.md).

### VPN_IF

(events) The setting that names the VPN client's tunnel. `auto`, the default, takes `tun0` (PIA's OpenVPN interface) if it exists when `tvgw-apply` runs, else `wgpia0` (its WireGuard one); `none` says the gateway runs no VPN client, so the leak counters count nothing, the leak red line is off and `UPLINK=vpn` is refused; any other value is the tunnel's interface name. The input chain drops new connections from `tun0` and `wgpia0` whatever it says. See [the settings file](settings.md) and [design decision 44](../design-decisions.md#44-the-tunnel-is-a-setting-and-the-pis-own-leaks-are-counted).

## W

### watermark

The entry `hosts_wm` in the `meta` table, which holds, per source table, the highest row id already counted into `hosts` and that row's time, so that a late row is counted once, under [design decision 11](../design-decisions.md#11-row-id-watermarks-for-the-hosts-counters). See [the tables](data-model.md#tables).
