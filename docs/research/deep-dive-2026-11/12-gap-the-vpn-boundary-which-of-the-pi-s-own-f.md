# Deep dive 12: the VPN boundary

*Which of the Pi's own flows carry the TV's data, and what happens when PIA or the DoH upstream fails. Proposal, 2026-11-01. Nothing here is built and nothing here touched the gateway. Primary sources: the PIA desktop client's source at tag `3.8.0` (commit `13fc29e1`, 2026-10-16), AdGuard's `dnsproxy` at `master` (`f9d00e7`, 2026-10-29) with its history, the Go standard library, Cloudflare's own incident report and resolver policy, and the tvgw research worktree (`deploy/nftables/tvgw-apply`, `src/tvgw/adguardcfg.py`, `deploy/nginx/`). It extends [design decisions 1 and 9](../../design-decisions.md#1-the-tv-uses-the-direct-uplink-not-the-vpn) and [the October survey's §2.2](../state-of-the-art-2026-10.md#22-verdicts) (the dnscrypt-proxy WATCH), and does not repeat them. It does not re-research the branches in flight (packaging, `tvgw setup`, the namespace CI, supply chain, capture v2, the extractor, profiles v2). Facts read from source are marked **(source)**. Claims I could not confirm are marked **(unverified)**. Predictions to be confirmed on the gateway are marked **(predicted; test T*n*)**.*

## Bottom line

Decision 9's one claim is true but for the wrong reason, and decision 1's failure story is incomplete. **The ISP never sees the TV's DNS because it is DoH by IP address, not because of the tunnel.** Go's TLS client sends no server name for an IP literal (source), so on either path the ISP sees only a TLS session to 1.1.1.1. What the tunnel adds is hiding the home address from Cloudflare. And the ISP learns nearly the same names from the TV's own direct-path SNIs anyway. The PIA 3.8.0 Linux client is an iptables (iptables-nft) kill switch in the filter `OUTPUT` chain only, with no `FORWARD` rules. Its routing marks are `0x3211`–`0x3214`, and its policy rules sit at priorities 50, 70, 100–102 (source). tvgw's priority-60 rule therefore keeps the TV's data path entirely independent of the tunnel. When the tunnel drops, **only DNS fails**, never the TV's connections. Under the gateway's `killswitch=auto` it fails in two different ways. Mid-run, a tunnel loss rejects AdGuard's DoH locally: no leak, and the TV lives on the optimistic cache. But at every PIA daemon start before the first connection, after a user disconnect, and whenever the daemon is inactive, the kill switch is off and DoH leaves directly by `WAN_IF` (source; test T2). The optimistic cache is better than feared and worse than assumed. A failed refresh no longer evicts an entry (since 2022), so each name the TV already asked keeps answering, with a 30 s TTL, for up to 12 h past its own expiry (source). A name it never asked fails at once, though. And **every AdGuard restart empties the cache**, and tvgw's own automation causes those restarts: the analyst's apply, the hourly judge's revert, `tvgw undo` and a deploy. An apply during an outage restarts AdGuard twice, because readiness fails and the apply rolls back. So the cheapest fix is a guard, not a fallback. Separately, the upstream pair `1.1.1.1`/`1.0.0.1` is the exact failure domain Cloudflare lost for 62 minutes on 2025-07-14, while `cloudflare-dns.com` stayed up. A second provider as `fallback_dns` covers that, but it cannot cover a tunnel outage: PIA's kill switch rejects any host-originated packet that does not leave by the tunnel, and tvgw cannot override a `REJECT` from its own nftables table. Only a resolver in a *forwarded* position, in a network namespace, can survive the tunnel. The same namespace would also move the identity-bearing flows off the VPN exit: the proxied GFTS fetches and the analyst's API calls, which today put LG and Anthropic traffic on the same exit address that qBittorrent uses. Selective routing of TV flows into the tunnel is feasible without colliding with `undo PIA routed-packet tag`, but it is not worth building for LG's core names. The October survey's dnscrypt-proxy WATCH should become a REJECT on the main path, because anonymized relays duplicate what the tunnel already gives. They have one niche left: as the resolver inside that namespace.

## Contents

- [F1. How PIA 3.8.0 builds its kill switch on Linux](#f1-how-pia-380-builds-its-kill-switch-on-linux) (settled from source)
- [F2. Which of the Pi's own flows carry TV-derived data](#f2-which-of-the-pis-own-flows-carry-tv-derived-data) (settled for the routing; the linkage risk is plausible but unverified)
- [F3. What happens when the tunnel or the DoH provider fails](#f3-what-happens-when-the-tunnel-or-the-doh-provider-fails) (settled from source; the TV's side is untested)
- [F4. A fallback resolver: what AdGuard can do, and what only a namespace can](#f4-a-fallback-resolver-what-adguard-can-do-and-what-only-a-namespace-can)
- [F5. LG and the two addresses](#f5-lg-and-the-two-addresses) (mostly unverified; tests given)
- [F6. Selective routing of TV flows into the tunnel](#f6-selective-routing-of-tv-flows-into-the-tunnel) (feasible; not recommended for LG's core names)
- [F7. Anonymized relays and ODoH, late 2026](#f7-anonymized-relays-and-odoh-late-2026)
- [Where this disagrees with earlier sections](#where-this-disagrees-with-earlier-sections)
- [Tests on the gateway](#tests-on-the-gateway)
- [What to build here](#what-to-build-here)
- [Open questions](#open-questions)
- [Sources](#sources)

---

## F1. How PIA 3.8.0 builds its kill switch on Linux

*Settled from source: PIA's desktop client is GPL-3.0 and public. Version 3.8.0 was tagged 2026-10-16. Its changelog makes WireGuard "the default protocol for new installations" and adds a WireGuard Amnezia obfuscation driver on Linux ([CHANGELOG](https://github.com/pia-foss/desktop/blob/3.8.0/CHANGELOG.md)).*

### iptables, not nftables, and only `OUTPUT`

The firewall is built by shelling out to `iptables`/`ip6tables` ([iptables_firewall.cpp](https://github.com/pia-foss/desktop/blob/3.8.0/kapps_net/src/linux/iptables_firewall.cpp)). On trixie the `iptables` command is the nft backend, so PIA's rules appear in `nft list ruleset` as tables `ip filter`, `ip nat`, `ip mangle` and `ip raw`, with chains named `piavpn.*`. The client tells users to install "the iptables or iptables-nft package" (source, `ClientNotifications.qml`). Each logical rule group is an *anchor*: a chain linked into `piavpn.<CHAIN>` in descending priority order. Iptables stops at the first match, so the highest number wins. The filter-table anchors that decide the Pi's own egress are these (source, lines 738–813):

| Anchor (filter `OUTPUT`) | Rule | Enabled when ([linux_firewall.cpp](https://github.com/pia-foss/desktop/blob/3.8.0/kapps_net/src/linux/linux_firewall.cpp) L82–L129) |
|---|---|---|
| `999.allowLoopback` | `-o lo+` accept (port 53 returns to the chain) | `allowLoopback` |
| `400.allowPIA` | `-m owner --gid-owner piavpn -j ACCEPT` | `allowPIA` |
| `390.allowWg` | `-m mark --mark 0x3213 -j ACCEPT` | `allowPIA` |
| `320.allowDNS` | the PIA DNS server on the tunnel interface, plus `-o lo+ --dport 53` | `hasConnected` |
| `310.blockDNS` | `-p udp/tcp --dport 53 -j REJECT` | `blockDNS` |
| `300.allowLAN` | accept to the three RFC 1918 ranges, link-local and multicast | `allowLAN` |
| `200.allowVPN` | `-o <tunnel> -j ACCEPT` | `blockAll` |
| `100.blockAll` | `-j REJECT` | `blockAll` (the kill switch) |

**There is no `FORWARD` anchor at all.** The `ChainEnum` allows one, but none is defined. For forwarded packets the kill switch is a route, not a filter. The mangle anchor `100.tagFwd` marks every packet in `PREROUTING` with `0x3214` (source, L848). Policy rule 70 sends that mark to table `piavpnFwdrt`. That table holds `default dev <tunnel>` once connected, and `blackhole default metric 32000` whenever leak protection is on ([linux_firewall.cpp L462–L492](https://github.com/pia-foss/desktop/blob/3.8.0/kapps_net/src/linux/linux_firewall.cpp)).

### Marks, tables and rule priorities

| Item | Value | Source |
|---|---|---|
| Mark base (`linuxFwmarkBase`) | `12817` = `0x3211` | [brandinfo.json](https://github.com/pia-foss/desktop/blob/3.8.0/brands/pia/brandinfo.json) |
| Exclude (bypass apps) | `0x3211` | [linux_fwmark.cpp](https://github.com/pia-foss/desktop/blob/3.8.0/kapps_net/src/linux/linux_fwmark.cpp) |
| VPN-only apps | `0x3212` | same |
| WireGuard socket mark | `0x3213` | same |
| Forwarded packets | `0x3214` | same; matches the gateway notes |
| Rule 50 | `from all lookup main suppress_prefixlength 1` | [linux_routing.h](https://github.com/pia-foss/desktop/blob/3.8.0/kapps_net/src/linux/linux_routing.h), [iptables_firewall.cpp L903](https://github.com/pia-foss/desktop/blob/3.8.0/kapps_net/src/linux/iptables_firewall.cpp) |
| Rule 70 | `from all fwmark 0x3214 lookup piavpnFwdrt` | same, L907 |
| Rules 100 / 101 / 102 | `vpnOnly`, `bypass`, `sourceIp`; WireGuard's `not fwmark 0x3213 lookup piavpnWgrt` also at 102 | `linux_routing.h` |
| Table names | `piavpnrt`, `piavpnOnlyrt`, `piavpnWgrt`, `piavpnFwdrt` | [rt_tables_initializer.cpp](https://github.com/pia-foss/desktop/blob/3.8.0/kapps_net/src/linux/rt_tables_initializer.cpp) |

Rule 50 suppresses every route with a prefix length of 1 or less, which means OpenVPN's `0/1` and `128/1` overrides and the default route. It "has no effect for OpenVPN without split tunnel" (source comment, L890–L902) except to send LAN destinations through `main`. That is why the gateway's own replies to the TV subnet work today, as recorded on 2026-11-01. The other consequence is the one decision 1 depends on: **tvgw's rule 60 (`from 10.10.10.0/24 lookup 100`) sits between PIA's 50 and 70, so the TV's forwarded traffic reaches table 100 before PIA's forwarded-packet rule can see its mark.** Clearing the mark (`undo PIA routed-packet tag`) is therefore belt and braces for routing. It matters only if rule 60 is ever missing, and then the TV still fails closed: `tv_out` drops what does not leave by `WAN_IF`.

PIA uses **no connmark anywhere** (`CONNMARK`, `--save-mark` and `--restore-mark` do not appear in `kapps_net` or `daemon`; source grep). That settles [deep dive 06's open question 4](06-platform-and-kernel-depth.md#open-questions) for this client: `ct mark` is free for tvgw. Confirm it on the box with T5.

### When the kill switch is on

The decision is in `Daemon::reapplyFirewallRules` ([daemon.cpp L3062–L3181](https://github.com/pia-foss/desktop/blob/3.8.0/daemon/src/daemon.cpp)):

- `hasConnected` is true only when the VPN is enabled and `connectedConfig` holds a location. `connectedConfig` is runtime `DaemonState`, not a persisted setting ([daemonstate.h](https://github.com/pia-foss/desktop/blob/3.8.0/clientlib/src/model/daemonstate.h)).
- If the daemon is not active, or the user is not logged in, `leakProtectionEnabled = false`. "Active" means a GUI client is attached, or background mode (`persistDaemon`) is on, or a client exited abnormally (`isActive`, L777). The CLI says so: disabling background mode "will disconnect the VPN and deactivate killswitch if the GUI client is not running" ([backgroundcommand.cpp](https://github.com/pia-foss/desktop/blob/3.8.0/cli/src/backgroundcommand.cpp)).
- `killswitch=on` (the UI's "Advanced Kill Switch") blocks always.
- `killswitch=auto`, the default ([daemonsettings.h L76](https://github.com/pia-foss/desktop/blob/3.8.0/common/src/settings/daemonsettings.h)) and the gateway's recorded setting, blocks only once the VPN is enabled *and has connected*. The UI text is "Once the VPN is turned on, prevent leaks by blocking traffic from going outside the VPN, including during connection loss" ([PrivacyPage.qml](https://github.com/pia-foss/desktop/blob/3.8.0/client/res/components/settings/pages/privacy/PrivacyPage.qml)).
- `blockAll = leakProtectionEnabled && !bypassDefaultApps`, and `blockDNS` also needs `hasConnected` (L3173–L3181).

The resulting state table, for the Pi's own traffic. The TV's forwarded traffic is unaffected in every row, because rule 60 sends it to table 100.

| PIA state | `100.blockAll` | AdGuard's DoH to 1.1.1.1 | Plain DNS to non-PIA servers |
|---|---|---|---|
| Connected | on | leaves by the tunnel | rejected (`310.blockDNS`) |
| Tunnel lost, reconnecting (`hasConnected` stays true) | on | **rejected locally**, nothing on `WAN_IF` | rejected |
| Daemon (re)started or Pi booted, before the first successful connect | **off** (auto) | **leaves by `WAN_IF`** | allowed |
| `piactl disconnect` (VPN disabled) | **off** (auto) | **leaves by `WAN_IF`** | allowed |
| Daemon inactive (no GUI client, background mode off) or logged out | **off**, VPN down | **leaves by `WAN_IF`** | allowed |
| `killswitch=on`, any of the above | on | rejected | rejected |

*(Predicted from source; tests T2 and T3.)*

### Two traps for tvgw in the same source

- **The tunnel's name is not stable.** OpenVPN gives `tun0`. PIA's WireGuard interface is `wgpia0` (source comment, [wireguardbackend.cpp](https://github.com/pia-foss/desktop/blob/3.8.0/daemon/src/wireguardbackend.cpp)), and since 3.8.0 WireGuard is the default for new installations. `tvgw-apply` hardcodes `tun0` in three places: `iifname "tun0" ct state new drop` in the input chain, `OUT_IF=tun0` in vpn mode, and the dispatcher trigger. After a PIA reinstall or a settings reset, the first silently stops protecting anything, and vpn mode would leave the TV dark.
- **tvgw cannot carve an exception into PIA's kill switch from its own table.** In nftables an `accept` in one base chain "is only guaranteed to be final" when no later base chain shares the hook, while a drop "take[s] immediate effect" ([nftables wiki, Configuring chains](https://wiki.nftables.org/wiki-nftables/index.php/Configuring_chains)). PIA's `REJECT` in `ip filter OUTPUT` therefore applies whatever `inet tvgw` accepts. Only PIA's own exemptions get a host-originated packet past it to `WAN_IF`: group `piavpn`, mark `0x3213`, LAN destinations, or a bypass cgroup. Borrowing the first two would be impersonating the client. The third, PIA's split tunnel, needs the iptables `-m cgroup` match. `NETFILTER_XT_MATCH_CGROUP` is not in the Pi 5 kernel's `bcm2712_defconfig` for `rpi-6.18.y` ([defconfig](https://raw.githubusercontent.com/raspberrypi/linux/rpi-6.18.y/arch/arm64/configs/bcm2712_defconfig)), so PIA split tunnel probably cannot load its rules on this kernel **(unverified; T6)**. F4's network namespace is the way around all of this that needs no cooperation from PIA.

A smaller note: PIA numbers its routing tables one above the highest index in `/etc/iproute2/rt_tables`, then `/usr/lib/...`, then `/usr/share/...`, and falls back to **100** ([rt_tables_initializer.cpp L30](https://github.com/pia-foss/desktop/blob/3.8.0/kapps_net/src/linux/rt_tables_initializer.cpp)). That is tvgw's `RT_TABLE`. With trixie's stock `/usr/share/iproute2/rt_tables` (highest entry `255 local`), PIA gets 256 and up, so there is no collision unless `/etc/iproute2/rt_tables` exists with low entries only. T1 checks it.

---

## F2. Which of the Pi's own flows carry TV-derived data

*The routing is settled from F1 and the worktree. Who-sees-what follows from it.*

The Pi's own resolver is PIA's `10.0.0.243` (the gateway notes, matching `piaModernDnsVpn` in [vpn.cpp](https://github.com/pia-foss/desktop/blob/3.8.0/daemon/src/vpn.cpp)). So every Pi-side lookup also rides the tunnel, and is rejected when the tunnel is down.

| Flow | TV-derived content | Leaves by | Who sees what | When the tunnel is lost (kill switch on) |
|---|---|---|---|---|
| AdGuard DoH upstreams (`DNS_UPSTREAMS`) | every allowed TV lookup, with its timing | tunnel | Cloudflare: names and timing from a shared PIA exit. ISP: nothing | rejected locally; the optimistic cache answers (F3) |
| nginx URL filter, port 80 (GFTS) | the TV's file-service URIs, its user agent and timing | tunnel | LG: the **VPN exit**. PIA: the plain-HTTP URIs | fails within `valid=300s` of the resolver cache, and every connect is rejected |
| nginx stream, port 443 (GFTS by server name) | TLS from the TV to LG, with whatever device credentials it carries (unverified) | tunnel | LG: the VPN exit. PIA: the SNI | rejected |
| nginx `resolver` (`URL_FILTER_RESOLVER`) | the GFTS names | tunnel, to PIA DNS | PIA | rejected; with the example default `1.1.1.1:53` it never works on a PIA box at all (`310.blockDNS`) |
| `tvgw analyst` API calls | the minimized evidence pack, under the owner's API key | tunnel | Anthropic: the account and the VPN exit | the run fails and exits 1 ([analyst errors](../../analyst-and-autonomy.md)) |
| `tvgw-doh-update`, list fetches (04 Stage B), org labels (02 #12) | none (public lists), only fetch timing | tunnel | the list hosts | fail; lists go stale (`verify` flags DoH after 8 days) |
| PTR lookups (02, proposed) | the TV's destination addresses | tunnel, to PIA DNS | PIA | rejected |
| **The TV's own connections** | everything else | `WAN_IF`, table 100 | ISP: addresses and SNIs, Amagi titles included ([05 §1.3](05-tv-privacy-research-2026.md)). LG and CDNs: the home address | **unaffected** |

### What the tunnel actually hides from the ISP

AdGuard's DoH upstream is `https://1.1.1.1/dns-query`, and Go's `crypto/tls` drops the server name when it is an IP address: `hostnameInSNI` returns `""` for anything `net.ParseIP` accepts ([handshake_client.go](https://raw.githubusercontent.com/golang/go/master/src/crypto/tls/handshake_client.go)). RFC 6066 §3 forbids IP literals in SNI anyway ([RFC 6066](https://www.rfc-editor.org/rfc/rfc6066#section-3)). On a direct path the ISP would see an unnamed TLS session to 1.1.1.1. It sees that same session's ciphertext inside the tunnel's ciphertext now. Meanwhile it reads, in the clear, the SNI of every TLS connection the TV opens directly. And because tvgw strips HTTPS/SVCB records, there is no ECH to hide them (decision 6). **Against the ISP the tunnel hides only the lookups the TV makes without then connecting to the name over TLS.** Those are mostly names it resolves and abandons, and names it reaches by plain HTTP, whose `Host` the ISP reads anyway. Its real job is to hide the home address from the DoH provider. Decision 1's text ("It does not see the TV's DNS ... as the Pi's own traffic that leaves through the VPN") should say that.

### The split identity, and why it matters more than LG's view

LG sees the TV on two addresses at once: the home address for everything direct, and the PIA exit for the GFTS files that nginx fetches on the TV's behalf. The fetch happens seconds after the TV's direct request that prompted it. So even if the GFTS URLs carry no device identifier (unverified: the worktree's fixtures keep only the user agent, `Mozila/4.0 (Web0S)`), timing alone links the two. The HTTPS GFTS sessions passed through on 443 very likely carry device credentials **(plausible, unverified)**. The costly part is not LG's view of the TV, which LG ties to the account anyway. It is that **the same exit address carries qBittorrent**. A party holding LG's request logs (LG itself, a partner, a subpoena) can map "PIA exit X at time T" to an LG device and its account. The Anthropic API calls do the same with an account-bearing key. PIA exits are shared, which dilutes this, but a port-forwarded torrent session on an exit at a given time is narrow. The principle to adopt: **identity-bearing flows leave by the home address; anonymity-seeking flows leave by the tunnel; no flow mixes the two.** Today tvgw puts two identity-bearing flows, GFTS and the analyst, on the anonymity side.

---

## F3. What happens when the tunnel or the DoH provider fails

### The optimistic cache, read from source

AdGuard Home 0.107.x embeds `dnsproxy`. Its behaviour today:

- **An expired entry is served with a short TTL and refreshed in the background.** `unpackItem` returns an expired item while `now < expire + optimisticMaxAge`, rewriting its TTL to `optimisticTTL` ([cache.go L116–L133](https://github.com/AdguardTeam/dnsproxy/blob/master/proxy/cache.go)). The defaults are 30 s and 12 h (`DefaultOptimisticAnswerTTL`, `DefaultOptimisticMaxAge`, [config.go](https://github.com/AdguardTeam/dnsproxy/blob/master/proxy/config.go)). AdGuard Home exposes them as `cache_optimistic_answer_ttl` and `cache_optimistic_max_age` since v0.107.71 (2025-12-08) ([Configuration wiki](https://github.com/AdguardTeam/AdGuardHome/wiki/Configuration); [06 F5](06-platform-and-kernel-depth.md#f5-adguard-home-in-2026-schema-churn-v10-and-config-as-code)). The bound arrived in dnsproxy on 2025-11-19 ([commit 314ac48](https://github.com/AdguardTeam/dnsproxy/commit/314ac48191be912b1f19aac3978b1bb93bb693c1)). Before it, an expired entry lived until LRU eviction.
- **A failed refresh keeps the entry.** `resolveOnce` caches the response only `if ok`, and does nothing on failure ([optimisticresolver.go L48–L70](https://github.com/AdguardTeam/dnsproxy/blob/master/proxy/optimisticresolver.go)). Until 2022-02-07 it deleted the entry on failure. The fix, "make optimistic actually optimistic", removed that delete ([commit 5956b6d](https://github.com/AdguardTeam/dnsproxy/commit/5956b6d33d2452b2161f993ff7f3613fe86d1119), for AdGuardHome#4254).
- **The bound is per name, counted from that record's own expiry.** For CDN names with TTLs of a minute or a few, the TV's last refresh happened just before the outage began. So in practice each previously seen name keeps answering for about 12 h after the outage starts.
- **The cache is an in-memory LRU** (`glcache.New`, `EnableLRU: true`, [cache.go L316](https://github.com/AdguardTeam/dnsproxy/blob/master/proxy/cache.go)). A restart empties it.
- **SERVFAIL answers are cached for up to 30 s** (`ServFailMaxCacheTTL`, same file). That applies only when an upstream *answers* SERVFAIL. A refused connection produces no message and caches nothing.

So during a tunnel outage with the kill switch on *(predicted; T2)*:

1. Names the TV asked in the last ~12 h answer from cache with TTL 30. The TV re-asks every 30 s, and each re-ask starts one background refresh. With `REJECT` the refresh fails in milliseconds, so it costs nothing.
2. Names the TV never asked, or asked more than ~12 h before, fail. The query waits on the upstream timeout (`upstream_timeout`, default 10 s, not owned by tvgw) or on a fast reject, and the TV gets SERVFAIL. This is the realistic breakage: a new app, a new CDN shard, and services that hand out per-session host names. The TV-side behaviour is **unverified**: whether webOS retries, falls back to its hardcoded resolvers (DNAT'd back to AdGuard anyway), or declares the network down.
3. **Any AdGuard restart turns case 1 into case 2 at once.** tvgw restarts AdGuard on `tvgw adguard apply`, on the analyst's `adguardcfg.apply()` after a machine rule, on `tvgw autoblock check`'s revert, on `tvgw undo`, and on every deploy. Debian's `needrestart` can do it too, after a library upgrade. During an outage it is worse: the readiness probe gets SERVFAIL ([how tvgw adguard apply works](../../architecture.md#how-tvgw-adguard-apply-works), step 8), the apply rolls back, and AdGuard is stopped and started a second time. The analyst's own API call fails through a dead tunnel first, so the risk is the local paths: the hourly judge's revert, `undo` and deploys.

The store can measure how much of a day would survive. The share of names the TV asked that it had *not* asked in the previous 12 h is the share an outage starting then would break at once:

```sh
sudo tvgw sql "with d as (select qname, min(t) t0 from dns where blocked=0 and t >= strftime('%s','now','-1 day') group by qname)
select count(*) as names,
       sum(not exists (select 1 from dns p where p.qname=d.qname and p.t < d.t0 and p.t >= d.t0-43200)) as new_within_12h
from d"
```

### The clock and a cold boot

webOS sets its clock from LG's SDP reply after looking up a `clock_hosts` name (the brief's [clock hosts](../../reading-the-brief.md#clock-hosts)). The TV's connection to SDP is direct and survives the outage. Only its lookup is at risk:

- **TV power-cycled mid-outage, Pi up, AdGuard not restarted:** the clock host is answered from cache if it was asked within ~12 h. The TV gets its clock and works on cached names. *(predicted)*
- **Power cut: the Pi and the TV boot together.** AdGuard starts with an empty cache, but under `killswitch=auto` PIA's kill switch is off until the first connection (F1). AdGuard's DoH therefore leaves directly, DNS works, and the clock is set. This is a privacy leak and an availability win. *(predicted; T3)* If PIA then connects and later drops, the cache is warm.
- **Advanced kill switch (`killswitch=on`) plus a cold boot while PIA cannot connect:** DoH is rejected, the cache is empty, the clock host fails, and per the README's clock dependency TLS then fails everywhere on the TV. Do not move to `killswitch=on` without F4's fallback. Whether the Pi itself can get NTP time before the tunnel is up under `killswitch=on` (timesyncd is not in group `piavpn`) is **unverified**. The 2026-10-31 notes record an RTC seeded by hand, so check whether the RTC battery is fitted.

### When the DoH provider fails, not the tunnel

On 2025-07-14 Cloudflare withdrew the 1.1.1.1 resolver prefixes globally from 21:52 to 22:54 UTC. They included **`1.1.1.0/24` and `1.0.0.0/24`**, so both of tvgw's upstreams went down together. "DoH remained available and traffic was mostly unaffected" for users reaching it by name, because "cloudflare-dns.com uses a different set of IP addresses" ([Cloudflare, 2025-07-15](https://blog.cloudflare.com/cloudflare-1-1-1-1-incident-on-july-14-2025)). Decision 9 picked DoH by address to avoid a plain-DNS bootstrap, and that choice put both upstreams in one failure domain. Such an outage looks like a tunnel outage, except that the refresh waits up to `upstream_timeout` instead of failing fast.

---

## F4. A fallback resolver: what AdGuard can do, and what only a namespace can

**AdGuard's `fallback_dns`** is used only when the primary exchange returns an error (`if err != nil && !isPrivate && p.fallbacks != nil`, [proxy.go L825–L840](https://github.com/AdguardTeam/dnsproxy/blob/master/proxy/proxy.go)). That is the right semantics. But a fallback configured in AdGuard is still AdGuard's own traffic, so it hits `100.blockAll` like the primary. **A second DoH provider in `fallback_dns` covers a provider outage (F3), never a tunnel outage.**

- **Candidate:** AdGuard DNS non-filtering by address, `https://94.140.14.140/dns-query` ([AdGuard DNS providers](https://adguard-dns.io/kb/general/dns-providers/)). It is a different operator and failure domain. The gateway's own 2026-10-25 test found it works through PIA, while Quad9 by address died after the ClientHello and Mullvad by address failed.
- **Exposure:** AdGuard DNS sees the TV's lookups only during Cloudflare failures, from the PIA exit.
- **Cost:** decision 6 owns `fallback_dns` as empty on purpose. The comment in `adguardcfg.py` says it keeps out "a resolver nobody configured", and a fallback named in `tvgw.conf` is configured. The owner decides.

**Surviving a tunnel outage** needs a resolver whose packets are *forwarded*, not locally originated, because PIA's kill switch has no `FORWARD` rules (F1). The minimal design:

- A network namespace `tvgw-egress` with a veth pair: the host end `10.10.11.1/30`, the namespace end `10.10.11.2/30`. These are placeholders; template them like `TV_NET`.
- Inside it, a small resolver: `dnsproxy` (AdGuard's own, the same code as AdGuard's upstream path) or dnscrypt-proxy (F7). It listens on `10.10.11.2:5353` and forwards over DoH by address.
  - Not port 53: PIA's `310.blockDNS` rejects AdGuard's packets to any port-53 destination it did not allow. Port 5353 to a `10.0.0.0/8` address passes through `300.allowLAN` (F1 table). **(predicted; T7)**
- On the host, give the namespace's subnet the TV's treatment:
  - `iifname "veth-egress" meta mark set 0` beside the existing `ZERO_MARK`.
  - `ip rule add priority 61 from 10.10.11.0/30 lookup 100`.
  - Masquerade out `WAN_IF`, and a `tv_out`-style accept for that source.
- In AdGuard, `fallback_dns: ["10.10.11.2:5353"]`.
  - Normal operation is unchanged: the tunnel and Cloudflare carry everything.
  - When the tunnel is lost, the primary fails fast (`REJECT`) and the fallback answers directly. Cached names still answer from cache first, and their background refresh now succeeds.
- systemd joins a unit to a namespace with `NetworkNamespacePath=/run/netns/tvgw-egress` ([systemd.exec](https://www.freedesktop.org/software/systemd/man/latest/systemd.exec.html#NetworkNamespacePath=)).

**What it exposes:** during a tunnel outage only, the fallback provider sees the TV's new lookups from the home address. The ISP sees an unnamed TLS session to that provider (Go, F2), which tells it almost nothing it does not already get from the TV's SNIs. Cloudflare's resolver policy, if Cloudflare is chosen, is to keep no source address in non-volatile storage outside a sampled 0.05% and to delete logs within 25 hours. The page header shows a 2026-05-06 update ([Cloudflare resolver policy](https://developers.cloudflare.com/1.1.1.1/privacy/public-dns-resolver/)). A different operator for the fallback means no single provider ever sees both the exit and the home address for the TV's pattern.

**The same namespace fixes F2's split identity.** Run the nginx URL filter's upstream side there with its own resolver (the namespace's `dnsproxy`, not AdGuard, so there is no rewrite loop). Then the GFTS fetches leave by the home address, consistent with the rest of the TV, and they stop depending on the tunnel. Today, an outage that leaves the TV's data path up still breaks app installs once nginx's 300 s resolver cache runs out. The analyst's API calls could be moved there too; that is the owner's choice. Effort M to L, risk medium: nginx is on the must-allow path, which is why this needs the CI namespace harness that is already in flight.

---

## F5. LG and the two addresses

*Mostly unverified. LG documents the setting, not the mechanism.*

- **Region comes from the "LG Services Country" setting.** For webOS 5 the path is All Settings → General → Location → LG Services Country. LG says available "apps and services vary by the selected region", and recommends updating the setting "after moving or changing your Internet Service Provider" ([LG help library](https://www.lg.com/us/support/help-library/lg-tv-how-to-change-location-settings-and-set-lg-services-country-CT10000030-20155051195628)). The ISP remark hints that the setting is *not* re-derived from the address on its own. I found **no primary source** that webOS's "Set Automatically" option, where present, geolocates by source address. Third-party guides say the Content Store follows this setting, not the address (low authority; [thetechgorilla](https://thetechgorilla.com/lg-content-store-missing/)).
- **GFTS through a VPN exit:** nginx fetches the files the TV asked for. If LG geolocated GFTS by address, a US exit would serve US content anyway. I found nothing showing LG's file service is region-selected by source address **(unverified)**.
- **One device on two addresses:** LG's privacy policies list the IP address beside device identifiers, country and location among collected device data ([LG privacy policy, a regional edition](https://www.lg.com/sa_en/privacy/)). The Smart TV policy is a separate document I could not retrieve. Whether LG joins the two addresses is unknowable from outside. F2 explains why the join is cheap if it wants one.

**What to do:** check that the TV's LG Services Country is set to the real country by hand, not "Set Automatically". Then a VPN exit in any country can never move the Content Store's region. `tvgw tvcheck` already stores the country it reads, so the brief can warn when it changes (T8).

---

## F6. Selective routing of TV flows into the tunnel

**Mechanism (feasible).** It follows the DNS gate's pattern:

- `tvgw-dnsgate` adds the A records of names marked `vpn_route` in the profile to an nft set `vpn4 { type ipv4_addr; flags timeout; }`. Use `expires`, per [06 F2](06-platform-and-kernel-depth.md#f2-the-dns-gates-set-timeout-update-semantics-on-612-and-later).
- In `pre_mangle`, after the existing `meta mark set 0`:
  - `ct state new ip daddr @vpn4 ct mark set 0x7476`
  - `ct mark 0x7476 meta mark set 0x7476`
- `ip rule add priority 59 fwmark 0x7476 lookup 101`, with table 101 holding `default dev <tunnel>`. Alternatively, leave PIA's `0x3214` in place for those flows and add `priority 59 from TV_NET fwmark 0x3214 lookup piavpnFwdrt`, inheriting PIA's blackhole when it is down.
- Masquerade and an MSS clamp out the tunnel, and a `tv_out` accept for marked flows.

**No collision with `undo PIA routed-packet tag`.** PIA's mangle `PREROUTING` runs at iptables' mangle priority, −150. tvgw's `pre_mangle` runs at `mangle + 10` (−140), so the last writer before the routing decision is tvgw. `0x7476` is outside PIA's `0x3211`–`0x3214`, PIA uses no connmark (F1), and priority 59 is below PIA's 70. The `ct mark` pins the route for the whole connection. Without it, a connection whose first SYN beat the set update would leave by `WAN_IF` and be masqueraded there, then have later packets routed into the tunnel and break. With it, a lost race means one connection leaks its SNI to the ISP and keeps working. The DNS gate's feeder race, seen in the 2026-10-31 analyst notes, shows the race is real.

**Is it worth it? Not for LG's core names; maybe for titles.**

- **LG core** (`lgtvsdp.com`, `lgappstv.com`, GFTS): LG knows the account and device whatever the source address. Moving those flows to the exit only creates F2's split identity on purpose and risks region effects (F5). REJECT.
- **Title-bearing names** (`*.amagi.tv`, [05 §1.3](05-tv-privacy-research-2026.md)): this is the one place where the tunnel hides something real from the ISP, namely program and channel slugs in the SNI. But Amagi names are the FAST stream itself, so the video moves through the tunnel too. Whether Amagi or LG Channels refuse VPN exits is **unverified**. FAST rights are territorial, so a same-country exit is the minimum.
- **Do streaming services flag VPN exits on hosts other than their own?** Their checks are made by their own API and licence servers on the address those servers see. I found no primary source of a service geochecking through an LG or third-party host **(unverified)**. Flows not routed into the tunnel keep the home address, so selective routing does not trigger decision 1's playback refusals as long as the streaming services' own names stay direct.
- **Measure first.** Volume per day, and what share of the TV's FAST viewing it is:

  ```sh
  sudo tvgw sql "select date(t_start,'unixepoch','localtime') d, count(*) flows, sum(bytes_in+bytes_out)/1048576 mb from flows f where exists (select 1 from tls where tls.dst=f.dst and tls.sni like '%.amagi.tv') group by 1 order by 1 desc limit 14"
  ```

  (Adjust the column names to the store's `flows` schema; the join is approximate, by address.)

Verdict: PROTOTYPE only if the owner wants FAST titles hidden from the ISP and the measured volume is small. Effort L, risk medium to high: a new routing class on a box where routing changes have already destroyed live connections ([2026-10-30 incident](../../incidents.md)).

---

## F7. Anonymized relays and ODoH, late 2026

The October survey kept dnscrypt-proxy as a WATCH: "Anonymized relays if DoH-by-address over the VPN becomes a problem." The state of play:

- **dnscrypt-proxy** is at 2.1.20 (2026-10-22). 2.1.17 (2026-07-13) added post-quantum DNSCrypt, "enabled by default", and rotates key material when the network changes "reducing linkability" ([releases](https://github.com/DNSCrypt/dnscrypt-proxy/releases)).
- **Anonymization works only with DNSCrypt servers.** "Anonymization only works with DNSCrypt servers"; DoH is not relayed. Relays and servers must have different operators ([Anonymized DNS wiki](https://github.com/DNSCrypt/dnscrypt-proxy/wiki/Anonymized-DNS)). Cloudflare runs no DNSCrypt service, so adopting it means changing provider.
- **ODoH** (RFC 9230, Experimental) still has Cloudflare as a target at `odoh.cloudflare-dns.com`. I found no current public relay list or 2025–2026 status change ([Cloudflare ODoH docs](https://developers.cloudflare.com/1.1.1.1/encryption/oblivious-dns-over-https/); [dnscrypt-proxy ODoH wiki](https://github.com/dnscrypt/dnscrypt-proxy/wiki/Oblivious-DoH)).

**My view: a single DoH provider through the tunnel is still the right trade for the main path.**

- Relays and ODoH hide the client's address from the resolver, which the PIA exit already does. Running them on the Pi puts them behind the same kill switch, so they fix neither failure mode in F3.
- A single provider sees the whole lookup pattern either way. Spreading queries across providers (AdGuard's `load_balance` mode over two operators) gives each a half-view, which is little privacy for a TV whose lookups are mostly LG and CDN names, at the cost of more parties.
- What matters in late 2026 is **failure domains**: one operator's prefixes went down whole in July 2025, so use a second operator as `fallback_dns`.
- **Where anonymization does earn a place is F4's namespace resolver**, which by design leaves by the home address. There, dnscrypt-proxy with two anonymized routes (relay operators distinct from the servers) keeps the home address from the fallback provider at no cost to the main path. Its UDP fragmentation sensitivity ("a router blocking UDP fragments is a likely cause" of failures, same wiki) is a reason to test it before relying on it.

Verdict: change the October WATCH to **REJECT on the main path**, and **PROTOTYPE as the namespace resolver** if F4 is built.

---

## Where this disagrees with earlier sections

1. **Decision 1** says the ISP "does not see the TV's DNS ... as the Pi's own traffic that leaves through the VPN". The DoH-by-address encryption is what hides it, and the SNIs on the direct path give most of it back (F2). The tunnel hides the home address from the DoH provider. And under `killswitch=auto` there are windows in which DoH does not use the tunnel at all (F1).
2. **Decision 9** says "AdGuard's optimistic cache keeps answering while the tunnel reconnects". That is true, and better than a reader might fear: failed refreshes keep the entry, for up to 12 h per name. But it covers only names already asked, and tvgw's own restarts erase it (F3). The pair `1.1.1.1`/`1.0.0.1` is also one failure domain (F3).
3. **The October survey §2.2 (dnscrypt-proxy WATCH)**: relays duplicate the tunnel's protection and fix neither outage. REJECT on the main path, PROTOTYPE inside the namespace (F7).
4. **The October survey §8.4 item 6** proposes to generalize by detecting fwmark policy routing and clearing marks. For PIA, rule ordering is what protects the TV, not the mark (F1). The generalization should check that tvgw's rule sits below the VPN client's forwarded-packet rule, and that the tunnel interface is discovered rather than assumed `tun0`, since PIA 3.8.0 defaults to `wgpia0`.
5. **Deep dive 06, open question 4** (does the VPN client use `ct mark`?): settled from source as no, for PIA 3.8.0. 06 F4's caution against `ct mark` can be lifted for this client after T5.
6. **Deep dive 02** says rDNS "should stay the VPN". Agreed. Note that this makes PTR lookups fail closed during an outage, so org labelling must tolerate missing answers.

---

## Tests on the gateway

Run them with the TV off unless a step says otherwise, and outside viewing hours. Interface and address values come from `/etc/tvgw/tvgw.conf`, never typed in.

**T1. Routing as PIA and tvgw left it (read-only).**

```sh
eval "$(sudo sh -c '. /etc/tvgw/tvgw.conf; echo TV_IP=$TV_IP WAN_IF=$WAN_IF')"
ip rule show
ip route show table 100
ip route show table piavpnFwdrt
cat /etc/iproute2/rt_tables /usr/share/iproute2/rt_tables 2>/dev/null | grep -v '^#'
ip route get 1.1.1.1                                   # Pi's own traffic
ip route get 1.1.1.1 mark 0x3214                       # a forwarded-tagged packet
ip route get 1.1.1.1 from "$TV_IP" iif eth0            # the TV
ip route get 1.1.1.1 from "$TV_IP" iif eth0 mark 0x3214
```

Expect:
- Rules 0, **50** (`suppress_prefixlength 1`), **60** (tvgw), **70** (`fwmark 0x3214 lookup piavpnFwdrt`), then 32766 and 32767. With WireGuard there is also rule 102.
- `1.1.1.1` → `dev tun0` (or `wgpia0`); with `mark 0x3214` → `dev tun0`, via table `piavpnFwdrt`.
- Both TV lines → `via <WAN_GW> dev $WAN_IF table 100`. The marked one proves rule 60 beats rule 70.
- PIA's table indices are not 100.

**T2. Tunnel lost with the kill switch engaged (the realistic outage), 5 minutes.** This drops the Pi's own packets to the internet in the output hook, so PIA's tunnel dies and it keeps reconnecting with `hasConnected` true. The TV's forwarded path is not in the output hook and is untouched. The DoH addresses are exempted, so PIA's kill switch, not the test, decides their fate.

```sh
LAN_CIDR=$(ip -4 route show dev "$WAN_IF" scope link proto kernel | awk 'NR==1{print $1}')   # the uplink's own subnet, so ssh survives
sudo nft -f - <<EOF
table ip tvgw_t2 {
  chain o {
    type filter hook output priority -200; policy accept;
    ip daddr { 1.1.1.1, 1.0.0.1 } tcp dport 443 counter accept comment "let PIA decide"
    oifname "$WAN_IF" ip daddr != $LAN_CIDR counter drop
  }
}
EOF
sudo timeout 300 tcpdump -ni "$WAN_IF" 'host 1.1.1.1 or host 1.0.0.1' -w /tmp/t2.pcap &
piactl get connectionstate                     # expect Reconnecting / Connecting
for i in 1 2 3; do dig +tries=1 +time=12 @10.10.10.1 us.lgtvsdp.com | grep -E 'status|IN\s+A'; sleep 40; done
dig +tries=1 +time=12 @10.10.10.1 "t2-$(date +%s).example.com" | grep status
sleep 120; sudo nft list table ip tvgw_t2; sudo nft delete table ip tvgw_t2
tcpdump -r /tmp/t2.pcap | wc -l
```

Pass if:
- The pcap is empty: no DoH left by `WAN_IF`, because PIA rejected it.
- The cached name answers `NOERROR` with TTL ≤ 30.
- The never-seen name gets `SERVFAIL`.
- The first counter shows the attempts PIA rejected.
- If `us.lgtvsdp.com` was not cached, ask the TV-side name list from `tvgw sql` for one that was.
- Record how long the never-seen name took to fail (fast `REJECT` or 10 s).

**T3. Kill switch off (user disconnect, and daemon start), 5 minutes each.**

```sh
sudo timeout 300 tcpdump -ni "$WAN_IF" 'host 1.1.1.1 or host 1.0.0.1' -w /tmp/t3a.pcap &
piactl disconnect; sleep 60; dig @10.10.10.1 "t3-$(date +%s).example.com" | grep status; sleep 230; piactl connect
# then the boot window:
sudo timeout 120 tcpdump -ni "$WAN_IF" 'tcp port 443 and (host 1.1.1.1 or host 1.0.0.1)' -w /tmp/t3b.pcap &
sudo systemctl restart piavpn; sleep 2; dig @10.10.10.1 "t3b-$(date +%s).example.com" | grep status
```

Predicted from source:
- `t3a.pcap` holds DoH sessions on `WAN_IF` (a leak) and the query answers `NOERROR`.
- `t3b.pcap` holds DoH until PIA reports Connected.
- If either pcap is empty, PIA's behaviour differs from its source and F1's state table must be corrected.
- Note: the same window exposes every other Pi process, qBittorrent included, unless the torrent client is bound to the tunnel interface. That is outside tvgw.

**T4. The cache wipe (TV off; do not run during an outage).** Ask a name twice, restart AdGuard, block the upstreams as in T2, and ask again: `dig @10.10.10.1 us.lgtvsdp.com` gives `NOERROR`, then after `sudo systemctl restart AdGuardHome` under the T2 table, `SERVFAIL`. This demonstrates F3's point 3 and is the regression test for the restart guard (build item 1).

**T5. Is `ct mark` free?** `sudo nft list ruleset | grep -c 'ct mark'` and `sudo iptables-save | grep -ci connmark`. Expect 0 for both from PIA. Any hit names its owner.

**T6. Which PIA, which tunnel, and can split tunnel load?**

```sh
piactl --version; piactl get protocol; piactl get connectionstate
ip -br link | grep -E 'tun0|wgpia0'
sudo jq '{killswitch, routedPacketsOnVPN, method, persistDaemon, allowLAN, splitTunnelEnabled}' /opt/piavpn/etc/settings.json
modinfo xt_cgroup 2>&1 | head -1
```

The settings path comes from source: `InstallationDir/etc` = `/opt/piavpn/etc`, [path.cpp](https://github.com/pia-foss/desktop/blob/3.8.0/common/src/builtin/path.cpp). `modinfo` failing confirms F1's split-tunnel doubt.

**T7. Port 5353 passes PIA's DNS block** (before building F4). Run `nc -u -l 10.10.11.2 5353` in a scratch namespace, then `dig -p 5353 @10.10.11.2 example.com` from the host. The packet should arrive, while the same to port 53 is rejected by `310.blockDNS`.

**T8. The TV's country setting.** `sudo tvgw sql "select * from tv_state where key like '%country%' order by t desc limit 5"`, adjusting to the store's table for tvcheck readings. Then check on the TV that LG Services Country is a fixed country, not automatic.

---

## What to build here

Ranked by value for effort. Risk means risk to the running gateway.

1. **Restart guard for AdGuard during an upstream outage.** Before `adguardcfg.apply()` stops AdGuard, probe the live resolver for the profile's first must-allow name. If the answer is SERVFAIL, or a cached answer with TTL ≤ `cache_optimistic_answer_ttl`, postpone: the analyst and the hourly judge record "deferred: upstream down" and retry next hour, and `tvgw undo` and deploys warn and need `--force`. Also own `dns.cache_enabled: true` (06 F5) and pin `cache_optimistic_max_age: 12h` and `cache_optimistic_answer_ttl: 30s` explicitly, so a default change upstream shows as drift. *Effort S. Risk low.* Test: T4.
2. **Prove the boundary with counters (decision 13 style).** Add to `inet tvgw` a postrouting chain at priority 300, `oifname "$WAN_IF" ip daddr @doh4 tcp dport 443 counter comment "DoH left by the uplink"`. Postrouting is after PIA's `REJECT`, so the counter counts real leaks, not attempts. Add a second counter for UDP/TCP 53 leaving by `WAN_IF` from the Pi. `tvgw verify --record` stores both. The brief gets a red line when they rise, and a Coverage line with PIA's state (`piactl get connectionstate`, protocol, kill-switch mode from T6). *Effort S. Risk low* (count-only, in a chain tvgw already replaces atomically).
3. **Tunnel-agnostic tvgw.** Add a `VPN_IF` setting, defaulting to auto-detection from PIA's `piavpnFwdrt` default route or `piactl get protocol`. Use it for the input-chain drop (`iifname { "tun0", "wgpia0" }` until detection lands), `UPLINK=vpn`, the dispatcher and `verify`. Add a hardware test that rule 60's priority is below the VPN client's forwarded rule (70 for PIA). This replaces the October survey's mark-detection idea. *Effort S. Risk low.*
4. **A second operator as `fallback_dns`** (`https://94.140.14.140/dns-query`), by address, through the tunnel. It covers a provider outage like 2025-07-14. This changes decision 6's "fallback empty" for a resolver that *is* configured: one new setting, `DNS_FALLBACK`, owned by `adguard apply`, empty by default. *Effort S. Risk low. Owner decision.*
5. **Fix the decision texts.** Decision 1's ISP consequence (F2), decision 9's cache claim (F3), and a note in `tvgw.conf.example` that `URL_FILTER_RESOLVER=1.1.1.1` cannot work behind PIA (`310.blockDNS`). Also record the kill-switch state table (F1) in the operations guide. *Effort S. Risk none.*
6. **The `tvgw-egress` namespace** (F4). It holds a direct-path fallback resolver on `:5353` for `fallback_dns`, and nginx's upstream side with its own resolver, so GFTS leaves by the home address and survives a tunnel outage. Optionally it also takes the analyst's API calls. The routing reuses the TV's model: mark zeroed, a rule at priority 61, masquerade, flow log. Build it and its reachability matrix in the CI namespace harness first, and take T7 before anything reaches the Pi. *Effort M–L. Risk medium:* it puts app installs on new plumbing and adds a routing rule, so use compare-before-write per the 2026-10-30 incident. *Owner decision; it changes decisions 1 and 9.*
7. **dnscrypt-proxy with anonymized DNSCrypt as that namespace's resolver** (F7), only after item 6 has run for two weeks with `dnsproxy`. *Effort S on top of 6. Risk low* (it is used only during outages).
8. **Selective routing of `title_bearing` names into the tunnel** (F6). Measure Amagi volume first, and build it only if the owner wants FAST titles hidden from the ISP. Use `ct mark 0x7476`, a rule at priority 59, an MSS clamp, and a race counter. Never for LG's core names. *Effort L. Risk medium-high.*

Not to build: a `$dnsrewrite` "survival zone" of last-known addresses for must-allow names (CDN addresses move, and a stale answer breaks more than SERVFAIL); any use of PIA's `piavpn` group or `0x3213` mark to slip past its kill switch; moving to `killswitch=on` before item 6 exists (F3, the cold-boot case).

---

## Open questions

1. **What does webOS 5 do on SERVFAIL?** Does it retry, fail over to hardcoded resolvers, or mark the network down, and after how long? It can only be measured with the TV on during T2, as an owner-approved second phase: watch the brief's DNS sections and `tvgw sql "select qname, count(*) from dns where t > strftime('%s','now','-10 minutes') group by 1 order by 2 desc"`.
2. **Should tvgw own `upstream_timeout`?** The default 10 s exceeds a typical stub resolver's first retry, so a hanging upstream (packets dropped, not rejected) could look like DNS loss to the TV even when `fallback_dns` would answer. Calibrate from `dns.elapsed_ms` before choosing a value, perhaps 3–4 s.
3. **Does a PIA daemon crash leave its iptables rules in place,** keeping the kill switch until restart, or does the unit's stop path remove them, opening it? The source shows `uninstall()` in the destructor only. A killed daemon probably leaves the rules **(unverified)**.
4. **Do LG's HTTPS GFTS sessions carry a device credential?** If yes, F2's linkage is certain, not plausible. It is not observable without decryption (decision 3). Indirect evidence: whether LG ever serves different files to the same URL from the two addresses.
5. **Does `||host^$dnsrewrite=…,client=<TV_IP>` work** to scope the GFTS rewrites to the TV alone, so the namespace's nginx could use AdGuard as its resolver? The syntax is plausible from AdGuard's documentation but no example confirms it. Check it with `AdGuardHome --check-config` and a query from the namespace.
6. **Is `NETFILTER_XT_MATCH_CGROUP` built for the running kernel?** T6. It decides whether PIA's own split tunnel is even an option on this Pi.

---

## Sources

PIA desktop client, tag 3.8.0 (2026-10-16):
- [CHANGELOG.md](https://github.com/pia-foss/desktop/blob/3.8.0/CHANGELOG.md)
- [kapps_net/src/linux/iptables_firewall.cpp](https://github.com/pia-foss/desktop/blob/3.8.0/kapps_net/src/linux/iptables_firewall.cpp)
- [kapps_net/src/linux/linux_firewall.cpp](https://github.com/pia-foss/desktop/blob/3.8.0/kapps_net/src/linux/linux_firewall.cpp)
- [kapps_net/src/linux/linux_routing.h](https://github.com/pia-foss/desktop/blob/3.8.0/kapps_net/src/linux/linux_routing.h)
- [kapps_net/src/linux/linux_fwmark.cpp](https://github.com/pia-foss/desktop/blob/3.8.0/kapps_net/src/linux/linux_fwmark.cpp)
- [kapps_net/src/linux/rt_tables_initializer.cpp](https://github.com/pia-foss/desktop/blob/3.8.0/kapps_net/src/linux/rt_tables_initializer.cpp)
- [brands/pia/brandinfo.json](https://github.com/pia-foss/desktop/blob/3.8.0/brands/pia/brandinfo.json)
- [daemon/src/daemon.cpp](https://github.com/pia-foss/desktop/blob/3.8.0/daemon/src/daemon.cpp)
- [daemon/src/vpn.cpp](https://github.com/pia-foss/desktop/blob/3.8.0/daemon/src/vpn.cpp)
- [daemon/src/wireguardbackend.cpp](https://github.com/pia-foss/desktop/blob/3.8.0/daemon/src/wireguardbackend.cpp)
- [common/src/settings/daemonsettings.h](https://github.com/pia-foss/desktop/blob/3.8.0/common/src/settings/daemonsettings.h)
- [common/src/builtin/path.cpp](https://github.com/pia-foss/desktop/blob/3.8.0/common/src/builtin/path.cpp)
- [clientlib/src/model/daemonstate.h](https://github.com/pia-foss/desktop/blob/3.8.0/clientlib/src/model/daemonstate.h)
- [client/res/components/settings/pages/privacy/PrivacyPage.qml](https://github.com/pia-foss/desktop/blob/3.8.0/client/res/components/settings/pages/privacy/PrivacyPage.qml)
- [cli/src/backgroundcommand.cpp](https://github.com/pia-foss/desktop/blob/3.8.0/cli/src/backgroundcommand.cpp)

AdGuard dnsproxy and AdGuard Home:
- dnsproxy `master` at `f9d00e7` (2026-10-29): [proxy/cache.go](https://github.com/AdguardTeam/dnsproxy/blob/master/proxy/cache.go), [proxy/optimisticresolver.go](https://github.com/AdguardTeam/dnsproxy/blob/master/proxy/optimisticresolver.go), [proxy/proxycache.go](https://github.com/AdguardTeam/dnsproxy/blob/master/proxy/proxycache.go), [proxy/config.go](https://github.com/AdguardTeam/dnsproxy/blob/master/proxy/config.go), [proxy/proxy.go](https://github.com/AdguardTeam/dnsproxy/blob/master/proxy/proxy.go)
- dnsproxy [commit 5956b6d, 2022-02-07, "make optimistic actually optimistic"](https://github.com/AdguardTeam/dnsproxy/commit/5956b6d33d2452b2161f993ff7f3613fe86d1119)
- dnsproxy [commit 314ac48, 2025-11-19, optimistic max age](https://github.com/AdguardTeam/dnsproxy/commit/314ac48191be912b1f19aac3978b1bb93bb693c1)
- [AdGuard Home Configuration wiki](https://github.com/AdguardTeam/AdGuardHome/wiki/Configuration)
- [AdGuard DNS filtering syntax](https://adguard-dns.io/kb/general/dns-filtering-syntax/)
- [AdGuard DNS providers list](https://adguard-dns.io/kb/general/dns-providers/)

Cloudflare:
- [1.1.1.1 incident on July 14, 2025](https://blog.cloudflare.com/cloudflare-1-1-1-1-incident-on-july-14-2025) (published 2025-07-15)
- [Public resolver privacy commitments](https://developers.cloudflare.com/1.1.1.1/privacy/public-dns-resolver/)
- [Oblivious DoH](https://developers.cloudflare.com/1.1.1.1/encryption/oblivious-dns-over-https/)

dnscrypt-proxy:
- [releases (2.1.17 to 2.1.20, 2026)](https://github.com/DNSCrypt/dnscrypt-proxy/releases)
- [Anonymized DNS wiki](https://github.com/DNSCrypt/dnscrypt-proxy/wiki/Anonymized-DNS)
- [Oblivious DoH wiki](https://github.com/dnscrypt/dnscrypt-proxy/wiki/Oblivious-DoH)

TLS, netfilter, systemd and the kernel:
- Go [crypto/tls handshake_client.go (`hostnameInSNI`)](https://raw.githubusercontent.com/golang/go/master/src/crypto/tls/handshake_client.go)
- [RFC 6066 §3](https://www.rfc-editor.org/rfc/rfc6066#section-3)
- [nftables wiki: Configuring chains](https://wiki.nftables.org/wiki-nftables/index.php/Configuring_chains)
- [systemd.exec: NetworkNamespacePath=](https://www.freedesktop.org/software/systemd/man/latest/systemd.exec.html#NetworkNamespacePath=)
- [Raspberry Pi kernel bcm2712_defconfig, rpi-6.18.y](https://raw.githubusercontent.com/raspberrypi/linux/rpi-6.18.y/arch/arm64/configs/bcm2712_defconfig)

LG:
- [How to change location settings and LG Services Country](https://www.lg.com/us/support/help-library/lg-tv-how-to-change-location-settings-and-set-lg-services-country-CT10000030-20155051195628)
- [LG privacy policy (regional edition)](https://www.lg.com/sa_en/privacy/)
- [thetechgorilla on the Content Store and the country setting](https://thetechgorilla.com/lg-content-store-missing/) (third-party, low authority)

tvgw, read in the research worktree:
- `deploy/nftables/tvgw-apply`, `src/tvgw/adguardcfg.py`, `deploy/nginx/`, `deploy/tvgw.conf.example`, `src/tvgw/db.py`
- [design decisions](../../design-decisions.md), [architecture](../../architecture.md), [the October survey](../state-of-the-art-2026-10.md)
- deep dives [02](02-naming-beyond-sni.md), [04](04-blocklists-and-verification.md), [05](05-tv-privacy-research-2026.md) and [06](06-platform-and-kernel-depth.md)
- the gateway's operating notes of 2026-10-25 to 2026-11-01 (PIA mark `0x3214`, `killswitch=auto`, the providers tested through PIA, rule 50's role)
