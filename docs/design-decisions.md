# Design decisions

A log of the choices that shape tvgw, in the style of architecture decision records. Each entry gives the context, the decision, and its consequences, good and bad. Add an entry when you make a choice that someone would otherwise undo by accident. If a decision is reversed, keep the old entry and add a new one that says so.

The overview is in [architecture.md](architecture.md).

## 1. The TV uses the direct uplink, not the VPN

*Decided by the owner, 2026-10-27.*

**Context.** The Pi runs a VPN client for its own traffic. tvgw can send the TV's traffic either straight to the home router (`UPLINK=direct`, through policy-routing table 100) or into the tunnel (`UPLINK=vpn`, out `tun0`, dropped while the tunnel is down, MSS clamped to the tunnel's MTU). Both modes are in `deploy/nftables/tvgw-apply`.

**Decision.** The TV stays on the direct uplink. `UPLINK=vpn` stays in the code and is not used. The reasons:

- Streaming services (Peacock, Max, Netflix, Prime Video) flag VPN exit ranges and refuse to play.
- vpn mode fails dark. Every time the tunnel reconnects, the TV loses its network.
- The TV moves 60 to 70 GB of video a day. Pushing that through the tunnel on a Wi-Fi uplink costs throughput for no gain.
- The trackers are blocked either way. DNS filtering, the firewall and the URL filter all act before routing. And the services know the account whatever the source address.

**Consequences.** Direct mode exposes two things:

- The ISP sees the destination addresses and TLS server names of the TV's connections. It does not see the TV's DNS: AdGuard Home forwards over DNS-over-HTTPS, and as the Pi's own traffic that leaves through the VPN.
- LG, the CDNs and the streaming services see the home's public address.

In direct mode tvgw-apply clears the VPN client's routing mark on TV packets (`undo PIA routed-packet tag`) and adds `ip rule` priority 60 to table 100. `tvgw verify` checks both the route and the rule. To revisit the decision, set `UPLINK=vpn` in `/etc/tvgw/tvgw.conf` and run `sudo tvgw-apply`. `verify` then expects the TV's route to leave by `tun0`.

## 2. Isolate first, then filter

**Context.** The TV sweeps the LAN, probes networks it remembers, and tries hardcoded resolvers such as 8.8.8.8. A DNS filter on its own can be bypassed by any device that ignores the DHCP-assigned resolver.

**Decision.** The TV gets its own subnet on its own cable, and the Pi is its only route out. The firewall forces every DNS packet to AdGuard and rejects the known bypasses (DoT, DoQ, QUIC, DoH resolver addresses, tunnels). Filtering is layered on top of that.

**Consequences.** The Pi needs two network paths. The TV must forget its Wi-Fi networks, or it has an unfiltered fallback. Devices on the home network cannot open connections to the TV, so casting and remote apps that need a LAN connection do not work across the gateway. The LAN probes become evidence in the brief instead of a risk.

## 3. No TLS interception

**Context.** Decrypting the TV's TLS would need a certificate the TV trusts. Apps pin their certificates, and installing a CA on the TV would need root (entry 4).

**Decision.** tvgw does not decrypt anything. It sees names (DNS, TLS server names, plain-HTTP hosts), sizes and timing. QUIC is rejected (`BLOCK_QUIC=yes`) so apps fall back to TCP and their server names stay visible.

**Consequences.** Ads stitched into a video stream cannot be removed: Prime Video's come from the same CDN as the show (recorded in `lg-webos.rules`). Telemetry is judged by where it goes and how much, not by what it says. The capture never holds encrypted payload.

## 4. No rooting of the TV

**Context.** Root exploits exist for several webOS generations; the profile's `[[generations]]` table lists them. On the CX's firmware (04.64, webOS 5) the LAN API refuses writes.

**Decision.** tvgw leaves the TV's software alone. Settings are changed by hand with the remote. tvgw reads them hourly over the LAN API (`tvgw tvcheck`), stores changes, and warns if Live Plus (ACR) comes back on.

**Consequences.** Settings that only the remote can change stay manual. Firmware updates keep arriving, since `snu.lge.com` is must-allow for security fixes, and each one may bring new endpoints; the brief's Firmware section lists the names that follow an update.

## 5. Fail closed

*2026-10-26.*

**Context.** A firewall that half-loads, or a stop that removes the rules before forwarding is off, leaves the TV online without a filter.

**Decision.** `tvgw-apply` takes a lock, loads the whole ruleset in one atomic `nft` transaction, and switches forwarding on last, globally and for both interfaces. Stopping `tvgw.service` turns forwarding off on the TV interface before it deletes the rules.

**Consequences.** A stopped service leaves the TV dark, never unfiltered. The stop path changes state the start path must restore; missing that once left the TV with no route ([incidents.md](incidents.md)). `install.sh` therefore re-applies in place when the service is already up. While the service is stopped, the input chain is gone too, so the Pi's own services can be reached from the TV subnet.

## 6. AdGuard Home is configured as code

**Context.** Changes made in AdGuard's web UI leave no history and drift silently from what the repo says.

**Decision.** `tvgw adguard apply` builds AdGuard's lists, custom rules, upstreams, the TV client entry and a few settings from the profile and `tvgw.conf`. It owns only those keys, and every key that could unfilter the TV is among them: the HTTP bind address; under `dns` the upstreams, bootstrap servers, `upstream_dns_file` (empty), optimistic cache, client-address anonymization, the private-PTR settings, the allowed and disallowed clients and `fallback_dns` (all empty); the query log and statistics; under `filtering` the enabled flags, `protection_disabled_until` (null), `blocking_mode` (`default`, the `0.0.0.0` answers that `verify` and the brief read as blocked), the blocked TTL and the legacy rewrites (empty); the filter entries it adds; the DNS allowlists (`whitelist_filters`, empty: AdGuard checks them before any rule); `user_rules` wholesale; and the TV's client entry (ids, tags, global settings, no per-client upstreams, logging on). It validates the candidate with `AdGuardHome --check-config`, swaps it in atomically under a lock, and restores the backup (taken before the stop, written back atomically) unless the resolver resolves a must-allow name within 30 seconds. `tvgw adguard diff` shows drift, and a hardware test allows none. Since 2026-10-27 it also owns `dns.aaaa_disabled` (true: the TV segment is v4-only with IPv6 dropped at the wire, so AAAA answers are withheld locally instead of fetched) and `dns.handle_ddr`, and generates one type-scoped rule withholding HTTPS/SVCB records from the TV's address (`[adguard] strip_qtypes`), which keeps Encrypted ClientHello keys and address hints away from it.

**Consequences.** A change made in the UI is reverted on the next apply. The one manual step is AdGuard's first-run wizard. Each apply that changes something leaves a `.bak-` file that nothing prunes. `apply` uses the profile inside the installed package, so policy changes go through a deploy.

## 7. Must-allow exceptions are generated from the TOML

**Context.** Blocking the wrong LG host breaks the TV: the clock host, firmware updates, the connectivity check, the Content Store. Blocklists change several times a day.

**Decision.** Every host in `[must_allow]` becomes an `@@||host^$important` exception, generated into AdGuard's custom rules. The modifier, not the position, is what makes the exception hold: AdGuard gives a `$important` block precedence over a plain exception whatever the order, and only an exception carrying `$important` outranks it. Nobody writes these by hand. The `$dnsrewrite` rules for the URL-filter hosts are generated the same way, from `[url_filter].hosts` and the `GW_IP` setting. The profile lint refuses a block, rewrite or regex that covers a must-allow host, a block or rewrite at the apex of a `never_block_apex` zone (or a wildcard-only chain above it) and a regex matching across one, and an exception that sits above or equals a blocked name or is a regex (which names it lifts cannot be checked). It also refuses the rules that switch others off: any `$badfilter`, and an `@@...$dnsrewrite` exception over a URL-filter host or a rewrite. `tvgw verify`, the brief's red line and the hardware suite all check the must-allow names.

**Consequences.** There is one place to edit. The lint runs in CI through the unit tests and again in `tvgw adguard` before anything is planned, so a profile loaded from a path is never applied unlinted. Regex rules are compiled case-insensitively, as AdGuard compiles them, and matched against every must-allow host; a rule in any other form than `||host^`, a one-name hosts line or a regex is refused, because AdGuard reads a pattern without `||` as a substring and one without `^` as a prefix; hosts-syntax blocks, `$dnsrewrite` rules and `$dnstype` rules that withhold any type but HTTPS, SVCB or AAAA are read as the blocks they are.

## 8. A URL filter for LG's file service instead of a DNS block

*2026-10-26.*

**Context.** LG's GFTS hosts carry app packages and icons, which the TV needs, and the ACR config file, the telemetry schedule, LG Shopping data, promo thumbnails and the LG Channels guide, which it does not. Blocking the hosts broke a Prime Video update on 2026-10-25. DNS cannot split one host.

**Decision.** AdGuard answers the GFTS names with the gateway address. nginx on the Pi forwards plain-HTTP requests and returns 403 when the URI matches `block_regex` (`biz_code=PREMIUM|CDP|LGSHOPPING|MAS|IBS`). HTTPS to the same names is passed through by server name, undecrypted.

**Consequences.** The regex lives in two places, the profile and `deploy/nginx/tvgw-gfts.conf`; a hardware test checks that the nginx file contains the profile's. nginx becomes a dependency of app installs, and `tvgw verify` checks it is up. The filter is a deny list: a new `biz_code` passes until it is added. HTTPS content from those hosts is not filtered.

## 9. DoH upstreams by IP address

**Context.** The Pi's VPN client blocks plain DNS to anything but its own resolver. A DoH upstream given by name needs a plain-DNS bootstrap first.

**Decision.** AdGuard's upstreams are DoH URLs with literal addresses (`DNS_UPSTREAMS`, default `https://1.1.1.1/dns-query,https://1.0.0.1/dns-query`; bootstrap `1.1.1.1,1.0.0.1`). nginx resolves the real GFTS names with `URL_FILTER_RESOLVER`, which should be the VPN provider's resolver when the client blocks other DNS.

**Consequences.** The TV's lookups are encrypted on the way out and leave through the tunnel. The DoH provider sees them. AdGuard's optimistic cache keeps answering while the tunnel reconnects.

## 10. A rollback journal, not WAL

**Context.** WAL mode needs `-wal` and `-shm` side files that every reader can write. `tvgw brief` and the other read commands run unprivileged.

**Decision.** The store uses `journal_mode=DELETE`. Readers open it `mode=ro` and need read access to one file.

**Consequences.** A reader can block briefly behind the hourly writer; connections wait up to 60 seconds. Ingest commits per batch of 10 000 log lines (with the cursor that covers them) and per pcap, so the lock is held per batch, never for a whole backlog. Backups with SQLite's online backup are safe while ingest runs. Writers run `synchronous=FULL`: with a rollback journal, `NORMAL` leaves a window for corruption on power loss, and the cost is one fsync per commit, a few dozen an hour.

## 11. Row-id watermarks for the hosts counters

**Context.** Counting rows by time window double-counted rows that fell in the overlap between hourly runs, and missed rows that arrived late.

**Decision.** `refresh_hosts` keeps, per source table, the highest row id already counted (`meta.hosts_wm`) and counts only rows above it.

**Consequences.** A row is counted once, however late it arrives. Without a watermark, the first run rebuilds the table from the base tables. The watermark also records its row's time: when that row is gone or re-stamped (a table emptied by prune or by hand, after which SQLite reuses the ids), the table is rebuilt too, and the counters then mean the retained rows. Deleting old rows by hand otherwise does not lower the counters.

## 12. Each flow is named by its own TLS hello

**Context.** CDN addresses serve many names. Naming a flow by its destination address mixes, say, a streaming service's video with the same CDN's telemetry.

**Decision.** A flow takes the name of the TLS hello with the same destination, destination port and TV source port, inside its lifetime, with 300 seconds of slack because conntrack's start times run late. See [architecture.md](architecture.md#naming-a-connection).

**Consequences.** Upload attribution is per connection. A flow without a captured hello (UDP, plain HTTP, a missed packet) is unnamed and shows as Unresolved or by address.

## 13. Counters, not logs, prove the firewall held

**Context.** A rule that matched nothing looks exactly like a rule that works, and a quiet log is not evidence.

**Decision.** Every rule worth reporting has a `counter` and a `comment`. `tvgw verify --record` snapshots every counter every 10 minutes. The brief's "Firewall held" line sums the positive steps per rule.

**Consequences.** Rule comments are an interface: `queries.FW_LINES` matches them by prefix and `verify` looks for key rules by their text. Renaming a comment silently drops its line from the brief. A re-apply resets counters; `tvgw-apply` lists them either side of the reload and the next `verify --record` stores both listings, so a reset costs nothing unless a second apply follows within the same interval. The gate's headline is never below the samples it logged, each of which was counted first.

## 14. Red lines are the alarm model

**Context.** The brief is long, and most of it is context. A silent source can look like a clean day.

**Decision.** A few sentences that must never be true go at the top as `RED LINE:` lines: a must-allow name blocked, a clock host blocked or never looked up while the TV was on, failed `verify` runs, ingest warnings. A Coverage line comes first and says `NOT ASSESSED` for any source not read in the last two hours.

**Consequences.** Nothing pages anyone. The brief is read by hand, and a failed `verify` shows in `systemctl --failed`. Each red line has a runbook entry in [operations.md](operations.md#red-lines).

## 15. Blocklist entries come from evidence, with grades

**Context.** Community lists disagree, and a wrong block breaks a TV in ways that are hard to trace.

**Decision.** Every custom rule in `lg-webos.rules` carries a dated reason: what the host is, how it was seen, what blocking it cost. Rules tried and rejected stay as comments. Entries not seen on the CX are marked "unverified". Generation and hardware rows carry a confidence grade: `observed`, `community`, `spec` or `low`.

**Consequences.** The profile can cover newer webOS releases while being honest about what was only reported. The code does not validate the grade; review does. See [../src/tvgw/profiles/README.md](../src/tvgw/profiles/README.md).

## 16. QuickSet and Hue stay blocked, with the cost written down

**Context.** Universal Electronics' QuickSet hosts identify HDMI-connected devices; the CX polled them about every 45 seconds. Philips Hue bridge discovery polled about every 5 minutes.

**Decision.** `ueiwsp.com`, `quicksetcloud.com` and `meethue.com` stay blocked.

**Consequences.** The TV cannot detect or set up other remotes and devices through QuickSet, and Hue sync and control on the TV do not work. The costs are recorded next to the rules. To change this, remove the rule in `lg-webos.rules` and deploy.

## 17. STRICT_PORTS stays off until two clean weeks

**Context.** The TV has only been seen using TCP 80 and 443 and DNS. NTP (UDP 123) stays open in case a firmware uses it. Rejecting every other port makes apps fail fast instead of hanging, but a dependency nobody has seen yet would break.

**Decision.** `STRICT_PORTS=no` until two consecutive weeks of briefs show `Unexpected ports: none` or only entries that were looked up and accepted. Until then, other ports are logged, counted and allowed.

**Consequences.** The `odd ports` counter and the brief's "Unexpected ports" line are the evidence. The criteria and the steps to flip it are in [operations.md](operations.md#strict_ports). The comment in `deploy/tvgw.conf.example` still says "a week or so"; this entry supersedes it.


## 18. DNS-gated egress starts as a count, in its own table

**Context.** Every rule so far judges a destination by name or by list. A TV that connects to a hardcoded address, or resolves a name through a channel the gateway does not see, is invisible to both. The October 2026 R&D survey's one new idea was to allow only addresses the TV's own lookups returned; enforcing that on day one would break anything that legitimately uses a cached or embedded address.

**Decision.** `DNSGATE=count` (the default): `tvgw-dnsgate` adds every IPv4 address AdGuard hands the TV to the set `inet tvgw_gate resolved4` with a one-day timeout, and a rule in that table counts, and logs a sample of (six a minute), each new connection the TV opens to an address the set does not hold. Nothing is dropped. The table is separate from `inet tvgw` so its dynamic set does not disturb the baseline `tvgw verify` compares, and it is created with `add` statements so a re-apply keeps the addresses. The brief carries the count and the logged samples with the TLS name a hello gave each address, which tells a forgotten lookup (a day old, or before the Pi last booted) from a hardcoded server. An enforce mode is a later decision, after two weeks of counts, and it must fail closed only when the feeder is proven to see every answer.

**Consequences.** One more root service holding `CAP_NET_RAW` and `CAP_NET_ADMIN`. conntrack calls every packet of a flow new until a reply is seen, so the rule counts a flow's tuple once (a dynamic set, `seen4`, holds it for two minutes) rather than every retransmitted SYN to a server that is down. The first day after a Pi reboot overstates: the TV's cache outlives the Pi's set. The feeder is passive: it adds an address a few milliseconds after the answer leaves the Pi, and the TV can connect sooner, so the first connection to an address new to the set may be counted too; the brief marks a sample that came within two seconds of an answer naming its address (`just looked up`). `DNSGATE=off` removes the table and the count. The feeder reads every UDP answer the Pi sends the TV, including those to DNS the TV aimed at another resolver (the redirect makes them leave with that resolver's address); a TCP answer (a truncated response retried over TCP) is not added and its address would count once.

## 19. A daily analyst that only proposes

**Context.** The brief is thorough and the owner reads it once a day. Judging a new name (telemetry or the app doing its job?) takes context about vendors, SDKs and how the TV behaved, which an analyst model has and a rule list does not. The owner asked for the analysis to be built once API access existed, and the standing rule is that policy changes are approved one at a time.

**Decision.** `tvgw-analyst.timer` runs `tvgw analyst` at 03:50: one streamed request to `claude-opus-5-5` (effort high, adaptive thinking) with yesterday's evidence pack, answered inside a JSON schema. The pack is built from the day report and minimized on purpose: names, counts, categories, the current rules, public server addresses, hours on and the apps seen; never the TV's or the LAN's addresses, MAC addresses, device or host names, LAN probe targets, reverse-lookup names, request paths or query strings, or an hourly timeline. A scrub over every string enforces it whatever the queries return, and the hardware suite checks the real pack. Every proposed rule is vetted exactly as a profile rule would be (the lint, the must-allow hosts, rules already in place, an unblock of a rule that exists) and the verdict is kept next to the proposal. Nothing is applied: proposals land in `reports/proposals/<day>.md` and `.json` for the owner, who adopts a rule by editing the profile's `.rules` file and deploying. The API key is one root-only file, `/etc/tvgw/claude.key`; without it the job skips quietly, and `--dry-run` writes the pack and the prompt and sends nothing.

**Consequences.** About $0.05 to $0.15 a day at the model's list price (the pack is a few thousand tokens; the record keeps each day's usage and cost). What leaves the Pi is readable before it leaves (`tvgw analyst --dry-run`) and documented in [privacy-and-retention.md](privacy-and-retention.md). The model's text is data too: a proposal that fails the lint is shown as refused, never silently dropped, and a refusal by the model's safety layer is a line in the day's file. Strings in the pack come from the TV and the internet; the system prompt says so and the vetting does not trust the answer either.

## 20. The gateway blocks on its own, under three watches

**Context.** Decision 19 left every rule to the owner, and the owner said that was the wrong shape: either the proposals go unread and nothing happens, or they arrive every day and are more trouble than they are worth. The gateway should act on its own. But a rule list cannot tell telemetry from the connection a stream rides on, one model's confident mistake could undo months of work, a mistake has to be fixed within minutes rather than at the next report, and a day with nothing new should cost nothing.

**Decision.** With `ANALYST_APPLY=auto`, a `block` the daily model proposes is applied by the gateway itself when every one of these agrees, in this order.

1. *The code's gates.* The proposal is vetted (the profile's lint) and rated low risk by the proposer; the name was looked up on at least two distinct days; its traffic shape in the window, read from the flows the TLS hello named, carried no payload: a median under 16 KB down per connection and under 2 MB down in the window; and fewer than three autonomous blocks were made in the last 24 hours. A shape is evidence the model cannot talk its way around: a name that moved 300 MB is content, whatever it is called.
2. *A second key.* A different model (`ANALYST_VERIFIER_MODEL`, `claude-fable-5-1` at xhigh effort by default; `verifier_for` never returns the proposer, whatever the settings say) is handed the proposal, the shape and the context and asked to refute it. A veto, low confidence, a refusal or an error leaves the rule unapplied.
3. *A file the machine owns.* The rule goes into `AUTO_RULES` (`/var/lib/tvgw/auto.rules`), which `tvgw adguard apply` appends to the profile's rules after the same lint, so a machine rule can never cover a must-allow host. The profile's `.rules` file is never edited by the machine; the owner's work and the machine's are separate files with separate histories.
4. *A live canary.* Two readings of the bytes the Pi has sent the TV, a minute apart before the block, give the download rate; for ten minutes after it, a reading every 30 s. Three readings running under a fifth of that rate while the TV stays on and was streaming (at least 1 MB a minute), or the streaming app in the foreground giving way to the launcher, take the rule out again and re-apply AdGuard, within minutes of the block. With the TV off there is nothing to watch, and the hourly judge takes over.
5. *A day of probation.* `tvgw-autoblock.timer` runs `tvgw autoblock check` every hour. A must-allow or clock red line since the block, or the last full TV hour's streaming volume (bytes down in the expected categories per hour the TV was on) under a fifth of the three days before, reverts. When the day is up, the whole window is judged the same way at a half, and the rule passes when the TV was on too little to tell.
6. *The owner's hand.* `sudo tvgw undo` takes the newest machine rule out of the file and AdGuard (`--all` for every one); deleting the file does the same at the next hourly check, and the record follows. Every step is recorded: `auto_rules` in the store, `Applied:` on the proposal, `tvgw autoblock list`, and a section in the brief.

A request is made only when the window holds something the store does not already know. The analyst is not asked when the TV was off and nothing was looked up, nor when the only names seen were judged within the last week (every proposal's verdict is remembered by name in `judgments`; a block refused for too few days of evidence, the daily cap or a transient failure is not a verdict and is asked again) and no red line, blocked name reached, ACR-like cadence, gate sample, unresolved destination or firmware change appeared. Such a day writes a one-line file and spends nothing; `--force` asks anyway. (Decision 22 narrows this: only a gate sample nothing explains counts, a blocked oddity never does, and a pass that proposes nothing is remembered.) The pack carries each candidate's shape and the previous judgements, so the model reasons from how the TV used a name, not from the name alone.

**Consequences.** The machine can only add blocks, only of names whose connections look like telemetry, only with two models agreeing, and only three a day; it cannot touch the owner's rules, allow anything, or change the firewall. The failure the owner feared, a stream breaking, is caught three ways: live within minutes when the TV is on, hourly when it is not, and by one command. The second request costs about as much as the first on the days it happens; quiet days cost nothing, and the longer the gateway runs the more days are quiet. The verifier sees the same minimized, scrubbed evidence as the proposer and nothing more ([privacy-and-retention.md](privacy-and-retention.md)). The gates are code and are tested without a model; the model calls are tested with fakes; the hardware suite checks that the file, the store and the live resolver tell one story and that the hourly check runs clean. The check has its own unit rather than a line in `tvgw-analyze`, whose read-only system would have made a revert's re-apply fail silently; a re-apply that fails is recorded on the decision and fails the unit. Known limits: a name blocked as telemetry can still be one an app checks before it plays (the canary and the hourly judge answer that, not the gate); the download-rate canary needs the TV to have been streaming before the block; an effect that shows only days later (a feature that stops working) is the owner's to notice, and `tvgw undo` the remedy.

## 21. A continuation inherits its name

**Context.** Decision 12 names a flow by its own TLS hello, inside its lifetime with 300 seconds of slack. When conntrack loses the entry of a live connection (the policy-route churn of the 2026-10-30 incident, a deploy, a table-full eviction), the kernel picks the connection up again and the flow log gets a second row for the same `dst`, `dport` and TV source port, starting seconds after the first ended, with no hello of its own. That row was unnamed and the brief showed its bytes by address.

**Decision.** A flow with no hello in its own window, whose start falls within `FLOW_SLACK` of the end of an earlier flow on the same tuple, looks for the hello from that earlier flow's start: one hop back. The latest hello before the flow's end still wins, so a connection with a hello of its own is never renamed by an inherited one. `tvgw host` gathers one name's flows with the same rule.

**Consequences.** Continuations join the connection they belong to in Top upload, the categories and the autonomy judge's streaming volume (an unnamed continuation used to drop out of that volume, which could have read as a collapse). The caveat is a reused source port: a new connection to the same address and port, within 300 seconds of the old one ending, whose own hello was not captured, inherits the old name. It is the same server, so the name is probably right, and it was shown as a bare address before. Chains of two or more continuations are not followed.

## 22. A pass that proposes nothing is remembered

**Context.** The novelty check of decision 20 was meant to keep a day that looks like yesterday free of requests, and it did not. In its first week every viewing day bought a request, each answered "nothing to do", for three reasons that recur by construction: the DNS gate's samples, most of which are the feeder losing its race with the TV's connect or the gate's day-long memory running out; the same three fixed hostnames flagged as DNS oddities every day (a long hex label and two "random" labels that are the same every day), all already blocked; and an allowed name outside the expected categories, `www.google.com`, that the model looked at and dismissed, then was shown again the next day because a dismissal left no verdict in `judgments`. The owner's rule is that a request is made only when something changed.

**Decision.** Three narrowings, in `novelty`, `asked_about` and `gate_unexplained`. 1. A pass that proposes nothing about a name it was asked about (a new host, an allowed name outside the expected categories, an unblocked oddity) leaves a `quiet` verdict in `judgments`, so the daily pass treats the name as judged for a week; a real verdict younger than a week is never overwritten by it. The weekly review ignores quiet verdicts and looks again at what the daily passes waved through, with the stronger model, so a wrong dismissal lasts at most a week. 2. The gate counts toward novelty only through `dns_gate.unexplained`: a sample neither within `FEEDER_LATE` of an answer naming its address nor with that address in any A answer of the `KNOWN_DAYS = 7` before it. A name in such a sample or none, it is a hardcoded server or a resolver bypass, which is what the gate is for. The brief lists these under the gate's table. 3. An oddity a rule already blocks never counts: the model is told never to re-propose a rule in place, so there is nothing it could say. Red lines about the TV (a must-allow name blocked, the clock, Live Plus, an ACR-like cadence, Encrypted ClientHello), blocked names reached, unresolved destinations and firmware or settings changes still buy a request whenever they appear; red lines about the gateway's own health (`HEALTH_RED_LINES`: firewall checks, ingest warnings, a producer gone quiet) do not, since the model cannot act on them and the brief and `tvgw verify` already carry them. The first run under this decision, 2026-11-01, was bought in part by "ingest warnings: 2", the flow logger's own lost events, which is how the exception was found.

**Consequences.** A steady week costs the daily pass nothing after its first request about each name; the weekly review still runs once when anything was waved through. The price is a week's blindness to a name the daily model wrongly dismissed, bounded by the weekly review and lifted by any other reason. The whole judged set, not the 40 verdicts the model is shown, decides novelty (`_judged`, stripped by `analyst.public` before anything is written or sent), so a long quiet list can never hide a verdict or buy a request. `tvgw analyst --dry-run` now says what a real run would ask about, so the gate can be read without spending.

## 23 (extractor). Parse the held-back first segment of a split hello

*R&D state of the art 2026-10, sections 1.1 and 10.*

**Context.** A ClientHello with a post-quantum key share is about 1.8 kB, two TCP segments, and Chromium-family stacks shuffle their extensions, so the server name can sit in either. The capture filter keeps the segment that begins a hello and drops the rest. tshark, with reassembly on, then holds that first segment back as an unfinished PDU and never dissects it: the hello was lost even when its name was in the bytes kept. Turning reassembly off (data-architecture section 2.2's suggestion) would rescue that case but cut every hello whose segments were all captured, the case position-based capture is meant to make normal, down to its first segment, and with it the full lists JA4 needs.

**Decision.** Keep reassembly on, stated on the command line, and add the held-back data to the same tshark pass: the display filter also keeps `tcp.segment_data`, and `clienthello.parse_record`, a small parser that never raises, reads a ClientHello from those bytes. A name wholly inside them is stored with `partial = 1` and no JA4; a hello whose name is not there goes to `tls_noname` with `partial = 1`. `tshark.dedupe` keeps one hello per transport and four-tuple within 30 seconds and lets a whole hello replace a partial one, so a split hello that was captured whole is one row, and so are a retransmitted hello and a repeated QUIC Initial.

**Consequences.** Hellos lost to the capture's cut now show, named when the name was early, counted when it was not, so the size of the problem can be read off the store. The one-pass design holds. Stored hello counts drop by the repeats the old extractor kept; `pcaps_done.tls_rows` keeps meaning named hellos, and `extract(keep_repeats=True)` reproduces the old count for a comparison. The parser is a second reader of hostile input, and it runs inside the ingest process, not the sandbox; it is bounded (`MAX_HELLO`) and the property tests feed it cut and random input. A name in a segment that was not captured stays lost until the capture keeps whole handshakes.

## 24 (extractor). A hello without a name gets its own table

**Context.** The old display filter required a server name, so a hello without one, the most suspicious kind (an app connecting where no lookup named), was never stored. `tls.sni` is `NOT NULL`, and a dozen readers (`FLOW_NAME` and through it the categories, Top upload and the autonomy judge; Unresolved flows; the DNS-gate samples; `v_ip_names`; `hosts`) take a `tls` row's `sni` for the connection's name. Data-architecture section 2.2 proposed a nullable `sni`.

**Decision.** Hellos without a name go to a new table, `tls_noname`, with the same address and port columns and the JA4, transport and partial flags. `tls` keeps meaning "a hello that named its server", and no reader of it changes. `queries.tls_noname` reads the new table and, for each JA4, the names the same fingerprint carried.

**Consequences.** No existing query can take an empty name for a name, and a nameless hello on a named connection cannot shadow it. A nullable `sni` would have needed a table rebuild (SQLite cannot drop `NOT NULL` in place) and a guard in every reader. The cost is a second table to prune, count and document, and a query that wants every hello must read both.

## 25 (extractor). JA4 is computed from the fields, not taken from tshark

**Context.** JA4 is the stable TLS stack fingerprint (BSD-3-Clause) the R&D survey adopts in place of JA3, which Chromium's extension shuffling broke. tshark has a native `tls.handshake.ja4` field from 4.2. Debian 12 ships 4.0.17 and Debian 13 4.4.19, and tshark refuses to start when asked for a field it does not have, so using the native field means probing the version and running two field lists.

**Decision.** `clienthello.ja4` computes JA4 from fields that exist in both versions (cipher list, extension types, `supported_versions`, ALPN, the signature lists), and from the bytes for a hello the parser read. The signature list is told apart from `signature_algorithms_cert` and `delegated_credentials`, which tshark prints under the same field, by walking their lengths in extension order; when they do not add up, no fingerprint is stored. The computation follows Wireshark's own and is pinned by the spec's worked example and the golden corpus, which on the Pi is also run through the installed tshark.

**Consequences.** One code path on every supported release, and the same string from either reader. If our implementation and FoxIO's ever disagree, our stored values are the ones that are wrong, and a re-read of the retained pcaps is the only repair for the last `PCAP_DAYS` days. JA4 names a stack, not an app, and nothing blocks on it.

## 26 (extractor). A known ECH public name is real ECH

**Context.** The ECH canary (schema 4) tells real ECH from GREASE ECH by the name alone: a hello whose name the TV looked up is GREASE. A stack that really uses ECH may also look its provider's public name up, and then the canary would call real ECH GREASE and stay quiet on the day it should fire. Cloudflare's `cloudflare-ech.com` is the outer name of 99.99% of ECH deployments in 2026.

**Decision.** `queries.ECH_PUBLIC_NAMES` lists the known public names. A hello carrying the extension under one of them is real ECH whatever the TV looked up; any other name falls back to the lookup test. The list is applied when the brief runs, not at extraction, so a name added later applies to the stored history. The outer name is `tls.sni` itself: it is the only name on the wire, so no separate column holds it.

**Consequences.** The canary cannot be silenced by the TV resolving the public name. A provider whose public name is not listed is still caught by the lookup test, unless the TV looked that name up too; a new provider means a line in the list.

## 27 (extractor). The tshark sandbox has no weaker fallback

**Context.** Wireshark published dozens of dissector advisories in 2026 (R&D section 10), and the dissectors read packets from the TV and the internet. tshark already ran as `nobody` in a `systemd-run` unit with no network, a read-only system, the service system calls and memory and time limits; before that, `setpriv` dropped the user and nothing else.

**Decision.** The unit gains the rest of the usual hardening (`tshark.HARDENING`): private IPC, protected kernel logs, clock, hostname and process list, no namespaces, realtime or set-id files, locked personality, a private keyring, `umask 077`, no core dumps and 64 tasks. `SystemCallErrorNumber=` is not set, so a refused call kills tshark, which ingest sees as a failed file and retries, instead of returning `EPERM` and letting tshark finish the file with rows silently missing. As root without `systemd-run`, ingest still refuses to run tshark; the old `setpriv` drop does not come back as a fallback.

**Consequences.** A dissector bug gets less to work with, and a crash leaves no core with the TV's packets in it. A property that blocks something tshark needs shows as an ingest warning on the first hourly run after a deploy, which is why the Pi validation in [the extractor](extractor.md#validating-on-the-pi) runs one file by hand. A host without systemd cannot ingest pcaps as root.
