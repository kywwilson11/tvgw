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

**Decision.** `tvgw adguard apply` builds AdGuard's lists, custom rules, upstreams, the TV client entry and a few settings from the profile and `tvgw.conf`. It owns only those keys, and every key that could unfilter the TV is among them: the HTTP bind address; under `dns` the upstreams, bootstrap servers, `upstream_dns_file` (empty), optimistic cache, client-address anonymization and the private-PTR settings; the query log and statistics; under `filtering` the enabled flags, `protection_disabled_until` (null), `blocking_mode` (`default`, the `0.0.0.0` answers that `verify` and the brief read as blocked), the blocked TTL and the legacy rewrites (empty); the filter entries it adds; `user_rules` wholesale; and the TV's client entry (ids, tags, global settings, no per-client upstreams, logging on). It validates the candidate with `AdGuardHome --check-config`, swaps it in atomically, and restores the backup unless the resolver resolves a must-allow name within 30 seconds. `tvgw adguard diff` shows drift, and a hardware test allows none.

**Consequences.** A change made in the UI is reverted on the next apply. The one manual step is AdGuard's first-run wizard. Each apply that changes something leaves a `.bak-` file that nothing prunes. `apply` uses the profile inside the installed package, so policy changes go through a deploy.

## 7. Must-allow exceptions are generated from the TOML

**Context.** Blocking the wrong LG host breaks the TV: the clock host, firmware updates, the connectivity check, the Content Store. Blocklists change several times a day.

**Decision.** Every host in `[must_allow]` becomes an `@@||host^$important` exception, generated into AdGuard's custom rules. The modifier, not the position, is what makes the exception hold: AdGuard gives a `$important` block precedence over a plain exception whatever the order, and only an exception carrying `$important` outranks it. Nobody writes these by hand. The `$dnsrewrite` rules for the URL-filter hosts are generated the same way, from `[url_filter].hosts` and the `GW_IP` setting. The profile lint refuses a block, rewrite or regex that covers a must-allow host, a block at the apex of a `never_block_apex` zone (or a wildcard-only chain above it), and an exception that sits above or equals a blocked name. `tvgw verify`, the brief's red line and the hardware suite all check the must-allow names.

**Consequences.** There is one place to edit. The lint runs in CI through the unit tests and again in `tvgw adguard` before anything is planned, so a profile loaded from a path is never applied unlinted. Regex rules are compiled and matched against every must-allow host; hosts-syntax blocks and `$dnsrewrite` rules are read as the blocks they are.

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

**Consequences.** Rule comments are an interface: `queries.FW_LINES` matches them by prefix and `verify` looks for key rules by their text. Renaming a comment silently drops its line from the brief. A re-apply resets counters and costs at most one interval.

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
