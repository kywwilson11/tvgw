# The firewall

This folder holds `tvgw-apply`, the one script that decides what the TV can reach, the two address lists it reads, and the guard, the table that keeps the Pi closed to the TV whether or not `tvgw-apply`'s table is loaded. It runs at boot from `tvgw.service`, when a link comes up, after the daily DoH list refresh, from `install.sh`, and by hand as `sudo tvgw-apply`. Why the TV is isolated first and why a failure leaves it dark is in design decisions [2](../../docs/design-decisions.md#2-isolate-first-then-filter) and [5](../../docs/design-decisions.md#5-fail-closed).

## Files

| File | What it is | Installed as |
|---|---|---|
| `tvgw-apply` | The ruleset, the sysctls and the policy routing, as one bash script. | `/usr/local/sbin/tvgw-apply` |
| `block4.txt` | A template for manual IPv4 blocks: one address or CIDR per line, `#` comments. | `/etc/tvgw/block4.txt`, installed only when missing; edit that copy |
| `doh-exclude.txt` | AWS CloudFront and Cloudflare CIDRs that are never put in the DoH block set, because they also serve ordinary sites. | `/etc/tvgw/doh-exclude.txt`, replaced on every install; read by [`tvgw-doh-update`](../bin/README.md) |
| `guard.nft.template` | The guard table `inet tvgw_guard`, with `__TV_IF__`, `__TV_NET__` and `__GW_IP__` for the TV side ([the guard](#the-guard)). | `/etc/tvgw/guard.nft`, rendered by `install.sh` on every run; loaded by `tvgw-guard.service` |

`tvgw-apply` reads three inputs: the settings `UPLINK`, `WAN_IF`, `WAN_GW`, `BLOCK_QUIC`, `STRICT_PORTS`, `DNSGATE`, `TV_IF`, `TV_NET`, `GW_IP`, `TV_IP` and `TV_MAC` from `/etc/tvgw/tvgw.conf` ([the settings file](../README.md#the-settings-file)); `/etc/tvgw/block4.txt`; and `/var/lib/tvgw/doh4.txt`, the DoH resolver list `tvgw-doh-update` writes. The TV side comes from the settings, defaulted to `TV_IF=eth0`, `TV_NET=10.10.10.0/24` and `GW_IP=10.10.10.1` (the script's `TV_ADDR`), with `TV_BCAST` derived from `TV_NET` ([the TV side](../README.md#the-tv-side)). Fixed in the script are `RT_TABLE=100` and `LG_UPDATE_IP=156.147.69.32`. The rules on this page are shown with the default TV side.

## Order of operations

The script runs with `set -euo pipefail`, so it stops at the first command that fails, and the order below is what keeps a failure from leaving the TV forwarded without a filter.

1. **Settings.** Sources the settings file and fills a missing `UPLINK`, `WAN_IF`, `BLOCK_QUIC`, `STRICT_PORTS`, `DNSGATE`, `TV_IF`, `TV_NET` or `GW_IP` with the same default as `config.Settings`. It exits 1 unless `BLOCK_QUIC` and `STRICT_PORTS` are exactly `yes` or `no`, `DNSGATE` is exactly `off` or `count` and `CAPTURE_MODE` is exactly `full` or `headers` (missing means `full`), because a near miss such as `BLOCK_QUIC=Yes` once dropped the QUIC rule silently, and unless the TV side passes the `tvgw-net` checks it shares with `install.sh`: a subnet such as `0.0.0.0/0` would masquerade, and route by table 100, everything the Pi forwards.
2. **Lock.** Takes `/run/lock/tvgw-apply.lock` with `flock`, so two applies never interleave. It waits for the lock; `tvgw.service`'s start timeout bounds a hang at boot ([timeouts](../systemd/README.md#timeouts)).
3. **The TV port.** Reads the `TV_IF` the previous apply recorded in `/run/tvgw/settings.applied`, then asks `ip -4 -o addr show to <GW_IP>` which interface holds `GW_IP`. When that is not `TV_IF`, the settings name a port `tv-lan` is not on yet (`TV_IF` edited, `install.sh` not run again): it prints `tvgw: GW_IP <GW_IP> is on <dev>, not TV_IF=<TV_IF>; run install.sh to move tv-lan, then apply again` and exits 1 with nothing loaded. It first turns forwarding off on that interface unless the filter loaded now was built for it, so a boot with no filter leaves the TV dark rather than unfiltered. `GW_IP` on no interface yet (`tv-lan` still coming up at boot) is not a stop; the forward chain's `TV subnet off the TV port` drop covers that case ([`forward`](#forward)).
4. **Uplink.** `UPLINK=direct` sends the TV out `WAN_IF` and requires `WAN_GW`, or the script exits 1 before it loads anything. `UPLINK=vpn` sends it out `tun0`. Any other value exits 1.
5. **Kernel settings.** Loads `nf_conntrack`, turns on per-connection byte counts and timestamps (`nf_conntrack_acct`, `nf_conntrack_timestamp`), which the flow log needs, and sets `nf_conntrack_tcp_timeout_established=7440`: 7440 s (2 h 04 min), so an idle connection is reported within hours instead of days. It disables IPv6 on `TV_IF`, and sets `net.ipv4.conf.<TV_IF>.rp_filter=1` (strict reverse-path filtering) when that key exists. The kernel uses the larger of `conf.all.rp_filter` and the interface's value, and systemd sets `all` to 2 (loose), so on a stock system this changes nothing until `all` is lowered; the input chain's source rule is the layer that holds either way.
6. **Address lists.** `ip_elements` keeps the leading `a.b.c.d` or `a.b.c.d/n` of each line of `doh4.txt` and `block4.txt`, drops duplicates, and ignores the rest of the line.
7. **`inet tvgw`, atomically.** First every counter of the five tables (the four this script loads, and the guard) is listed to `/run/tvgw/counters.before-apply.tmp` (`nft -j -t list table`, one line per table). Then one `nft -f` transaction declares the table, deletes it, creates the new one and adds the set elements. When it fails, nothing changes, and the script stops before forwarding, with the listing unpublished.
8. **`netdev tvgw_l2`.** Loaded the same way. A failure prints `tvgw: netdev IPv6 guard not loaded (<TV_IF> down?)` and the script goes on, because the ingress hook cannot load while the TV interface is down.
9. **`inet tvgw_gate`.** With `DNSGATE=count`, adds the gate table and its sets and chain and replaces the chain's rule ([the DNS gate table](#the-dns-gate-table)); a failure prints a warning and the script goes on, since the gate only counts. With `DNSGATE=off`, deletes the table. Then, with `CAPTURE_MODE=headers`, replaces `inet tvgw_capture` ([the capture table](#the-capture-table)); a failure prints a warning and the script goes on, since the table only logs. With `CAPTURE_MODE=full`, deletes the table.
10. **Counters after.** Lists every counter again, to `counters.after-apply.tmp`, and renames both listings into place together as `/run/tvgw/counters.before-apply` and `/run/tvgw/counters.after-apply`. The next `tvgw verify --record` stores them as snapshots, so the brief sees the reset this apply caused instead of losing what the counters gained since the last snapshot ([design decision 13](../../docs/design-decisions.md#13-counters-not-logs-prove-the-firewall-held)).
11. **Forwarding, last.** Writes `net.ipv4.ip_forward=1` and the per-interface `forwarding=1` for `TV_IF`, and for the uplink once `/proc/sys/net/ipv4/conf/<uplink>` exists: in vpn mode `tun0` appears when the VPN connects, after the boot apply, and `sysctl` fails on a key it cannot find, which would stop the script half done. Until then `tv_out` drops what cannot leave by the uplink, the script prints `tvgw: <uplink> not there yet; the dispatcher switches it on when it comes up`, and the dispatcher re-runs it when it does. The per-interface switches are written explicitly because the kernel copies the global value to the interfaces only when the global value changes, and a stop turns `TV_IF` off ([incidents](../../docs/incidents.md)). Then, when the previous apply's `TV_IF` differs from this one and is not the uplink now, it turns that port's forwarding off again: a global switch from 0 to 1 has just turned it on, and this filter no longer covers it.
12. **Baseline.** Writes `nft -s list table inet tvgw` to `/run/tvgw/ruleset.applied`, the listing `tvgw verify` compares the live table against, and the twelve settings it used, defaults filled in, to `/run/tvgw/settings.applied`, which `verify`'s `applied_current` compares the settings file with ([what tvgw verify checks](../../docs/troubleshooting.md#what-tvgw-verify-checks)).
13. **Policy routing.** In direct mode, makes sure `ip rule` priority 60 reads `from <TV_NET> lookup 100` and that table 100's default route goes via `WAN_GW` on `WAN_IF`, and touches neither when it is already right: deleting and re-adding the rule, or replacing an unchanged route, destroyed the conntrack entry of a connection with data in flight ([incident log](../../docs/incidents.md#2026-10-30-live-connections-lost-their-conntrack-entry-at-every-dhcp-renewal)). In vpn mode it removes the rule.
14. **Summary.** Prints `tvgw: applied (uplink=<mode> via <interface>, quic_block=..., strict_ports=..., dnsgate=..., doh4=<n> entries, tv_pin=<addresses or none>)`.

<picture>
  <source media="(prefers-color-scheme: dark)" srcset="../../docs/diagrams/fig-12-fail-closed.dark.png">
  <img alt="The firewall's states in direct mode: Down, with the TV dark; tvgw-apply loads the filter atomically (Loaded, nothing forwarded); the sysctls switch forwarding on (Forwarding, no route yet); the uplink coming up adds rule 60 (Routed, the TV online and filtered). With the uplink down the state is No route, where tv_out drops the TV's traffic, and the dispatcher re-applies when it returns. systemctl stop tvgw switches forwarding off, deletes rule 60 and then inet tvgw, back to Down, where the guard table keeps the Pi closed to the TV. A load that fails changes nothing, and the guard stays loaded in every state." src="../../docs/diagrams/fig-12-fail-closed.light.png" width="960">
</picture>

*The firewall's states in direct mode: a load that fails leaves the previous state, and forwarding is the last thing switched on and the first thing switched off.*

## Stopping

`systemctl stop tvgw` runs the four `ExecStop` lines of `tvgw.service`, in order:

1. `sysctl -q -w net.ipv4.conf.<TV_IF>.forwarding=0`, through `sh -c`. The interface is the `TV_IF` the loaded filter was built for, from `/run/tvgw/settings.applied`; without that file or key, the settings file's `TV_IF`, and `eth0` when that is missing too. A stop between a `TV_IF` edit and the install that moves `tv-lan` so darkens the port the TV is still on. The TV is dark before any rule goes.
2. `ip rule del priority 60`, with errors ignored.
3. `nft delete table netdev tvgw_l2`, with errors ignored.
4. `nft delete table inet tvgw`.

A stopped service leaves the TV dark, never unfiltered ([design decision 5](../../docs/design-decisions.md#5-fail-closed)). The stop leaves `inet tvgw_gate` in place; that table only counts. It leaves `inet tvgw_guard` in place too, which no stop ever deletes ([the guard](#the-guard)). `tvgw-flowlog`, `tvgw-pcap` and `tvgw-dnsgate` start after `tvgw.service` (`After=`, `Wants=`) but are not bound to it, so they keep recording while it is stopped, and the store holds what the dark TV tries.

While the service is stopped, `inet tvgw`'s input chain is gone with its table, and the guard's input chain holds the same line: from the TV subnet only DHCP, DNS, nginx's 80 and 443 and rate-limited pings reach the Pi, and its other services do not. Anything that runs `tvgw-apply` brings the TV back online: the NetworkManager dispatcher on a link change, `tvgw-doh-update` once a day, and `install.sh`.

To reload the firewall, run `sudo tvgw-apply`, not `systemctl restart tvgw`. The script is idempotent and atomic, so a re-run opens no gap; a restart runs the stop path first and blacks the TV out for a moment.

## The ruleset, chain by chain

The rules are listed in the order `tvgw-apply` writes them. A rule's comment is part of an interface ([design decision 13](../../docs/design-decisions.md#13-counters-not-logs-prove-the-firewall-held)): `tvgw verify --record` snapshots every rule that has a `counter` and a `comment`, and the brief's "Firewall held" line matches the comments by prefix (`queries.FW_LINES` in src/tvgw/queries.py; [brief sections](../../docs/reading-the-brief.md#sections)).

### Sets

| Set | Holds | Filled from |
|---|---|---|
| `lan4` | The three RFC 1918 private ranges, CGNAT `100.64.0.0/10` and link-local `169.254.0.0/16`. | The script itself |
| `doh4` | Known DoH resolver addresses; interval set with `auto-merge`. | `/var/lib/tvgw/doh4.txt` |
| `block4` | Manual IPv4 blocks; interval set with `auto-merge`. | `/etc/tvgw/block4.txt` |

### Hooks and priorities

| Chain | Hook | Priority |
|---|---|---|
| `pre_mangle` | prerouting | `mangle + 10` |
| `pre_nat` | prerouting | `dstnat - 10` |
| `input` | input | `filter - 10` |
| `forward` | forward | `filter - 10` |
| `output` | output | `filter - 10` |
| `post_nat` | postrouting | `srcnat - 10` |

`pre_mangle` runs 10 after the standard mangle priority. The other chains run 10 before their standard priority, so they come ahead of other chains at the same hook: `pre_nat` runs before the VPN client's NAT chain, which would otherwise send the TV's DNS to the VPN's resolver.

### `pre_mangle`

| Rule | Comment | Why |
|---|---|---|
| Direct mode only: `iifname "eth0" meta mark set 0 counter` | `undo PIA routed-packet tag` | The VPN client marks every forwarded packet to route it into the tunnel. Clearing the mark lets table 100 send the TV's packets out the uplink. |

In vpn mode the chain is empty.

### `pre_nat`

| Rule | Comment | Why |
|---|---|---|
| `iifname "eth0" ip daddr != 10.10.10.1 udp dport 53 counter dnat ip to 10.10.10.1:53` | `TV DNS aimed elsewhere -> AdGuard` | DNS the TV aims at any other resolver, such as a hardcoded `8.8.8.8`, lands on AdGuard Home. |
| The same for `tcp dport 53` | `TV DNS aimed elsewhere -> AdGuard` | The same, over TCP. |

A nat chain sees only the first packet of each connection, so these counters count redirected flows, not packets.

### `input`

What may reach the Pi itself from the TV.

| Rule | Comment | Why |
|---|---|---|
| `iifname "tun0" ct state new counter drop` | `nothing unsolicited from the VPN side` | Nothing may open a connection to the Pi from the tunnel. |
| `iifname != "eth0" accept` | none | This table polices the TV side only. |
| `ip saddr != { 0.0.0.0, 10.10.10.0/24 } counter drop` | `TV source outside its subnet (input)` | A source outside the TV subnet can only be forged. With a home-LAN host's address as the source, a query to the resolver would make the Pi answer that host over the uplink, a path `tv_out` never sees. `0.0.0.0` is a DHCPDISCOVER. The brief adds it to `foreign source`. |
| `meta l4proto { tcp, udp } th dport 53 counter` | `TV DNS to the gateway` | Counts the TV's DNS before the established shortcut, because webOS keeps one UDP source port for its resolver all day. |
| `ct state established,related accept` | none | Replies. |
| `udp sport 68 udp dport 67 accept` | `DHCP` | DHCP requests go to the broadcast address, which the next rule would drop. |
| `ip daddr != 10.10.10.1 counter drop` | `TV talks to the gateway address only` | The TV may use the gateway's address and no other address of the Pi. |
| `meta l4proto { tcp, udp } th dport 53 accept` | `DNS -> AdGuard` | AdGuard Home. |
| `tcp dport { 80, 443 } accept` | `GFTS URL filter / TLS passthrough (nginx)` | The [URL filter](../nginx/README.md). |
| `icmp type echo-request limit rate 5/second accept` | none | Reachability checks, at up to 5 a second. |
| `counter drop` | `TV may not reach other Pi services` | Everything else on the Pi stays out of the TV's reach. |

### `forward`

| Rule | Comment | Why |
|---|---|---|
| `ip saddr 10.10.10.0/24 iifname != "eth0" counter drop` | `TV subnet off the TV port` | The TV's subnet arriving on another port: `TV_IF` was edited and `tv-lan` not moved yet, and the next rule would accept it unfiltered. The brief's label is `off the TV port`. |
| `iifname != "eth0" oifname != "eth0" accept` | none | Not TV traffic; left to the rest of the system. |
| `ct state invalid counter drop` | `invalid: would leave un-NATed` | An invalid packet would leave without NAT, carrying the TV's own address. |
| `iifname "eth0" ip saddr != 10.10.10.0/24 counter drop` | `TV source outside its subnet` | Masquerade covers only the TV subnet, and the capture, the flow log and the gate all key on its addresses, so a packet from another source would leave un-NATed and unrecorded. The brief's label is `foreign source`. |
| Once the TV is pinned: `iifname "eth0" ip saddr != { 10.10.10.17 } counter drop` | `TV source is not the TV` | Only the TV's own address forwards. A second address in the subnet (a rooted TV's alias) would be outside the flow log (`--orig-src TV_IP`) and the HTTPS/SVCB strip (`client=TV_IP`). The rule is there only when `TV_MAC` is a real MAC, which is what puts the DHCP pin in dnsmasq's config; on a fresh install, before `tvgw discover --write`, the TV holds a pool address and any address in the subnet forwards. When the TV still holds an unexpired lease for another address under `TV_MAC` (`TV_IP` was just edited), that address is in the set too, with a warning, until an apply after the lease moved. The brief's label is `second TV address`. |
| Vpn mode only: `oifname "tun0" tcp flags syn tcp option maxseg size set rt mtu` | `tunnel MTU` | The tunnel's MTU is smaller. |
| `ct state established,related accept` | none | Replies, and connections that were allowed when they started. |
| `iifname "eth0" meta nfproto ipv4 jump tv_out` | none | The TV's new connections. |
| `counter drop` | `nothing else into or out of the TV subnet` | Devices on the home network cannot open connections to the TV. |

### `tv_out`

The TV's new outbound connections. `<uplink>` is `WAN_IF` in direct mode and `tun0` in vpn mode.

| Rule | Comment | Why |
|---|---|---|
| `oifname != "<uplink>" counter drop` | `only via the chosen uplink` | In vpn mode this is what drops the TV's traffic while the tunnel is down. |
| `ip daddr @lan4 counter drop` | `TV may not reach the home LAN` | Isolation ([design decision 2](../../docs/design-decisions.md#2-isolate-first-then-filter)). |
| `meta l4proto != { tcp, udp, icmp } limit rate 6/minute log prefix "tvgw-proto: "` | none | A sample of the packets the next rule drops, at most 6 log lines a minute. Every such packet reaches this rule (a dropped packet never confirms its conntrack entry), and the kernel log is the journal ingest reads its samples from, so an unlimited log could flood it. The limit is a rule of its own because on the drop it would let the packets over the rate through. |
| `meta l4proto != { tcp, udp, icmp } counter drop` | `no GRE/ESP/6in4 tunnels` | No tunnel protocols. The counter keeps the full number. |
| `icmp type echo-request ip length <= 128 limit rate 2/second counter accept` | `small pings only` | Pings of at most 128 bytes, at 2 a second. |
| `meta l4proto icmp counter drop` | `no ICMP tunnels` | Any other ICMP could carry a tunnel. |
| `meta l4proto { tcp, udp } th dport { 784, 853, 8853 } counter reject` | `DoT/DoQ` | DNS over TLS and QUIC. A reject, not a drop, so the TV falls back at once. |
| With `BLOCK_QUIC=yes`: `udp dport 443 counter reject` | `QUIC: force TCP+TLS so SNI is visible` | Apps fall back to TCP and TLS, and the server name stays visible ([design decision 3](../../docs/design-decisions.md#3-no-tls-interception)). |
| `tcp dport 443 ip daddr @doh4 counter reject with tcp reset` | `DoH resolvers` | Known DNS-over-HTTPS resolvers. |
| `ip daddr @block4 counter reject` | `manual IP blocks` | Endpoints the TV reaches by hardcoded address, which DNS cannot stop. |
| `ip daddr 156.147.69.32 tcp dport 8080 counter log prefix "tvgw-lg8080: " accept` | `LG firmware fallback path` | LG's hardcoded firmware-update fallback: allowed so updates work, logged so it shows. |
| `meta l4proto { tcp, udp } th dport != { 80, 123, 443 } limit rate 6/minute log prefix "tvgw-oddport: "` | `unexpected port` | Evidence for the brief, at most 6 log lines a minute; the rule has no counter. |
| With `STRICT_PORTS=no`: the same match, `counter accept` | `STRICT_PORTS=no: count only` | Other ports are counted and allowed. |
| With `STRICT_PORTS=yes`: the same match, `counter reject with icmpx admin-prohibited` | `STRICT_PORTS: only web, NTP and DNS` | Apps fail fast instead of hanging ([STRICT_PORTS](../../docs/operations.md#strict_ports), [design decision 17](../../docs/design-decisions.md#17-strict_ports-stays-off-until-two-clean-weeks)). |
| `accept` | none | Everything else. |

NTP on UDP 123 stays open in both modes in case a firmware uses it; webOS takes its clock from LG's SDP reply over 443.

### `output`

| Rule | Comment | Why |
|---|---|---|
| `oifname "eth0" ip daddr { 10.10.10.255, 255.255.255.255, 224.0.0.0/4 } udp dport != { 67, 68 } counter drop` | `no NetBIOS/SSDP chatter from the Pi into the TV subnet` | The Pi's own broadcast and multicast stay off the TV subnet; DHCP is the exception. |

`tvgw discover` opens holes for the length of its SSDP search, each commented `tvgw-discover`, and deletes them all again whatever happens (src/tvgw/discover.py): at the top of this chain `oifname "eth0" udp dport 1900 counter accept`, for the search, and, once its socket is bound, at the top of `input`, and of the guard's `input`, `iifname "eth0" ip daddr 10.10.10.1 udp dport <the socket's port> counter accept`, for the TV's unicast answer, which conntrack sees as a new flow and `TV may not reach other Pi services` (and the guard's final drop) would otherwise drop. Each hole goes only into a table that is loaded: on a first install, before `tvgw-apply` has run, only the guard's.

The rule "the TV's LAN API from root only" (TCP 3000 and 3001 to the TV subnet from any user but root) is not here but in the guard's `output` chain, so it holds when this table is gone ([the guard](#the-guard)).

### `post_nat`

| Rule | Comment | Why |
|---|---|---|
| `iifname "eth0" oifname "<uplink>" ip saddr 10.10.10.0/24 masquerade` | none | The TV's traffic leaves with the uplink's address; only what came in on the TV port, so the TV subnet on any other port is never translated. |

### `netdev tvgw_l2`

| Rule | Comment | Why |
|---|---|---|
| Chain `in`, ingress hook on `eth0` at priority `-500`: `ether type ip6 counter drop` | `no IPv6 from the TV` | IPv6 is dropped at the wire as well as disabled on the interface. The counter ticks with neighbor-discovery noise; that is not a breach. |

## The guard

`inet tvgw_guard` keeps the Pi closed to the TV subnet at the moments `inet tvgw` is not loaded: at boot until `tvgw-apply` runs, while `tvgw.service` is stopped, after an apply nft rejected, and if anything deletes the table ([design decision 42](../../docs/design-decisions.md#42-guard-the-pi-is-closed-to-the-tv-whatever-nftables-holds)). `install.sh` renders `guard.nft.template` into `/etc/tvgw/guard.nft`, and `tvgw-guard.service` loads it with `nft -f` before `network-pre.target`, so the table is in the kernel before NetworkManager brings the TV port up. The unit has no `ExecStop` and refuses a manual stop (and so a restart): nothing but `nft delete table inet tvgw_guard` removes the table ([operations](../../docs/operations.md#removing-the-guard-in-an-emergency)). `systemctl reload tvgw-guard` loads the file again.

The file is one transaction. `add table` and `add chain` keep what exists, `flush chain` empties each chain and the `add rule` lines fill it again, so a reload never leaves a moment without the chains, and a failure changes nothing. The three base chains run at priority `filter + 10`, after `inet tvgw`'s `filter - 10`. A drop in any base chain is final and an accept is not: the next base chain on the hook still sees the packet. So the guard can only narrow what `inet tvgw` (or the VPN client's tables) let through, never widen it. While `inet tvgw` is loaded it drops first and keeps its counters, and the guard sees only what it accepted.

| Chain | Rule | Comment | Why |
|---|---|---|---|
| `input` | `iifname != "eth0" accept` | none | The TV side only. |
| `input` | `meta nfproto ipv6 counter drop` | `guard: no IPv6 from the TV side` | IPv6 is off on the port; this holds if it ever comes back. |
| `input` | `ip saddr != { 0.0.0.0, 10.10.10.0/24 } counter drop` | `guard: spoofed source` | As `inet tvgw`'s input source rule. |
| `input` | `ct state established,related accept` | none | Replies. |
| `input` | `udp sport 68 udp dport 67 accept` | `guard: DHCP` | DHCP, to the broadcast address too. |
| `input` | `ip daddr != 10.10.10.1 counter drop` | `guard: the gateway address only (weak host)` | Linux owns an address for the whole host, so a socket bound to the Pi's Wi-Fi address is reachable from the TV port by the gateway's MAC. Binding a service to the LAN address is not isolation; this rule is. |
| `input` | `meta l4proto { tcp, udp } th dport 53 accept` | `guard: DNS` | AdGuard Home. |
| `input` | `tcp dport { 80, 443 } accept` | `guard: nginx` | The URL filter and the passthrough. |
| `input` | `icmp type echo-request limit rate 5/second accept` | `guard: pings` | As `inet tvgw`. |
| `input` | `icmp type echo-request counter drop` | `guard: pings over the rate` | Its own counter, so two rate limits drifting apart never reach the final one. |
| `input` | `counter drop` | `guard: TV may not reach other Pi services` | Everything else. While `inet tvgw` is loaded this counter should not move; `tvgw verify`'s `guard_quiet` warns when it does. |
| `forward` | `iifname "eth0" ip saddr != 10.10.10.0/24 counter drop` | `guard: TV source outside its subnet` | Forwarding is off whenever `tvgw.service` deleted `inet tvgw`. These three hold if something else deleted it with forwarding still on: without its `post_nat` the TV's packets would leave un-NATed toward the home LAN. |
| `forward` | `iifname "eth0" ip daddr { 10.0.0.0/8, 100.64.0.0/10, 169.254.0.0/16, 172.16.0.0/12, 192.168.0.0/16 } counter drop` | `guard: TV never to the LAN` | The same ranges as `lan4`. |
| `forward` | `iifname "eth0" meta nfproto ipv6 counter drop` | `guard: no IPv6 forwarded from the TV` | |
| `output` | `oifname "eth0" ip daddr 10.10.10.0/24 tcp dport { 3000, 3001 } meta skuid != 0 counter drop` | `guard: TV API from root only` | The TV's LAN API (webOS SSAP) only from root: tvgw's readers run as root, and a co-tenant's process (a desktop session, a notebook) must not drive the TV. A packet with no socket has no owner and does not match. |

`tvgw-guard.service` writes `nft -s list table inet tvgw_guard` to `/run/tvgw/guard.applied` after each load, and `tvgw verify`'s `guard_present` compares the live table with it. `tvgw-apply` lists the guard's counters with its own before and after each reload, so `tvgw verify --record` stores them in `fw_counters` and `guard_quiet` compares the final drop counter with its value just after the last apply.

The guard does not stop a process with root or `CAP_NET_ADMIN` from deleting it; nft's `owner` and `persist` table flags do not either, since an orphaned table accepts a new owner. Two things narrow that: dnsmasq, the daemon that parses the TV's DHCP, runs without `CAP_NET_ADMIN` ([DHCP for the TV](../dnsmasq/README.md#the-hardening-drop-in)), and the co-tenants carry `IPAddressDeny=TV_NET`, a cgroup filter that holds with every nftables table gone ([the settings file](../README.md#the-settings-file), `CO_TENANT_UNITS`).

## The DNS gate table

With `DNSGATE=count`, `tvgw-apply` keeps the table `inet tvgw_gate` ([design decision 18](../../docs/design-decisions.md#18-dns-gated-egress-starts-as-a-count-in-its-own-table)):

| Object | Definition | Why |
|---|---|---|
| Set `resolved4` | `type ipv4_addr; flags timeout; size 65536;` | The addresses the TV's lookups returned. `tvgw-dnsgate` adds each with a one-day timeout ([the units](../systemd/README.md#units)). |
| Set `seen4` | `type ipv4_addr . ipv4_addr . inet_proto . inet_service . inet_service; flags dynamic, timeout; timeout 2m; size 65536;` | Each counted flow's tuple, for two minutes. conntrack calls every packet of a flow new until a reply is seen, so without it each retransmitted SYN to a server that is down, or each datagram of an unanswered UDP flow, would count again. |
| Chain `forward` | `type filter hook forward priority filter - 5; policy accept;` | It runs after `inet tvgw`'s forward chain, so it sees only what the filter accepted. |
| Its one rule | `iifname "eth0" ip saddr 10.10.10.0/24 ct state new ip daddr != 10.10.10.1 ip daddr != @resolved4 ip saddr . ip daddr . meta l4proto . th sport . th dport != @seen4 add @seen4 { ip saddr . ip daddr . meta l4proto . th sport . th dport } counter limit rate 6/minute log prefix "tvgw-gate: "`, comment `TV to an address DNS never returned` | Counts each new connection to an address no lookup returned, once per tuple (it adds the tuple to `seen4` as it counts it), and logs a sample of at most 6 a minute. It never drops. |

The table is separate from `inet tvgw` so its changing set does not disturb the baseline `tvgw verify` compares. It is written with `add` statements, so a re-apply keeps the addresses already collected and the tuples seen; only the chain is flushed and its rule written again. A failure to load it prints `tvgw: DNS gate table not loaded` and leaves the TV forwarded, because the gate only counts. With `DNSGATE=off` the script deletes the table.

## The capture table

With `CAPTURE_MODE=headers`, `tvgw-apply` replaces the table `inet tvgw_capture` in one transaction, after the filter and the gate ([design decision 39](../../docs/design-decisions.md#39-the-first-packets-of-each-connection-behind-a-switch)). The script's block for it sits between `# ---- (capture) begin` and `# ---- (capture) end ----`.

| Object | Definition | Why |
|---|---|---|
| Chain `pre` | `type filter hook prerouting priority mangle - 5; policy accept;` | After conntrack (-200) has counted the packet, before the DNS redirect (`dstnat - 10`) and the rejects in `tv_out`: it sees what the TV sent, to where it sent it, attempts the filter refuses included. |
| First rule | `iifname "eth0" ip saddr 10.10.10.0/24 ip saddr != 10.10.10.1 ct original packets != 0 ct original packets <= 8 counter log group 7 snaplen 4096 queue-threshold 1`, comment `capture: the first packets of each TV connection` | The first 8 packets of each connection the TV opens, at most 4096 bytes each, to NFLOG group 7. A connection conntrack has no counters for reads 0 and is skipped. `queue-threshold 1` sends each packet at once, so its time is not a batch's. |
| Second rule | `... tcp dport 80 ct original packets > 8 counter log group 7 queue-threshold 1`, comment `capture: plain HTTP after them` | Plain HTTP after the first 8 packets, whole, as the full capture keeps it. |

Neither rule has a verdict, so the table can lose evidence but never let a packet through or stop one. `tvgw-pcap-headers.service` reads group 7 ([the capture](../../docs/capture.md#the-headers-mode)); the counters are evidence of the capture, not of the filter, so the brief does not list them. A failure to load the table prints `tvgw: capture table not loaded; tvgw-pcap-headers records nothing`, and `tvgw verify`'s `capture` check fails until it is loaded.

## Checking it

On the Pi:

```sh
sudo nft list table inet tvgw                 # the live ruleset with its counters
sudo nft list table inet tvgw_gate            # the DNS gate, with DNSGATE=count
sudo nft list table inet tvgw_capture         # the headers capture's rule, with CAPTURE_MODE=headers
sudo nft list table netdev tvgw_l2            # the IPv6 wire drop
sudo nft list table inet tvgw_guard           # the guard, with its counters (the last should stay at 0)
systemctl status tvgw-guard                   # active (exited); a stop is refused
sudo nft -c -f /run/tvgw/ruleset.applied      # the last applied listing still parses
ip rule show priority 60                      # direct mode: from 10.10.10.0/24 lookup 100
ip route show table 100                       # the default route via the router on WAN_IF
journalctl -u tvgw -n 20                      # the applies and their summary lines
journalctl -k -g 'tvgw-oddport|tvgw-proto|tvgw-lg8080|tvgw-gate'   # the logged rules
sudo tvgw verify                              # the checks against this ruleset
```

## Changing it

1. Edit `deploy/nftables/tvgw-apply` in the repository.
2. When you add, rename or remove a counted rule's comment, update `queries.FW_LINES` in src/tvgw/queries.py. When you change the text of a key rule, update `KEY_RULES` in src/tvgw/verify.py and `KEY_RULES` in tests/hardware/test_gateway.py.
3. When you add a setting, give it the same default in the script's `${KEY:=value}` line as in `config.Settings`, and the same accepted values in its `case` as in `config.CHOICES`.
4. Run `make gate`. These tests guard the script:
   - `tests/unit/test_fw_lines.py` fails when a counted drop or reject has no line in the brief, or a line in `FW_LINES` matches no rule. A counted accept that is not evidence goes in its `ACCEPT_COUNTERS`.
   - `tests/unit/test_deploy_lint.py` runs `bash -n` on the script, checks that every needle in `verify.KEY_RULES` and in the hardware suite's `KEY_RULES` is in its text, and checks its defaults and `case` arms against `config.Settings` and `config.CHOICES`.
5. Run the virtual suite, or let the `virtual` workflow run it on the pull request: it checks every variant with `nft -c` and probes the loaded firewall against `tests/virtual/matrix.txt`. A change to what the TV can reach is a change to a row of that file ([the virtual gateway](../../tests/virtual/README.md)).
6. Deploy, then test the change on the Pi (next section).

## Testing a change

`nft -c` checks a ruleset against the running kernel without loading it, and `tvgw-apply --check` renders the tables the settings file would load (two with `DNSGATE=off`, three otherwise), with every shell variable filled in, and has `nft -c` check each. It changes nothing: no sysctl, no table, no route, nothing under `/run/tvgw`. It prints the rulesets on standard output, exits 0 when nft accepts every one and 1 otherwise; unlike an apply, it fails on a side table (`netdev tvgw_l2`, `inet tvgw_gate`) nft refuses.

On the Pi:

```sh
sudo tvgw-apply --check > /tmp/tvgw.nft   # render and check, change nothing
sudo tvgw-apply                           # then load it for real
sudo tvgw verify
```

A ruleset that fails to load leaves the previous one in place. A new block stops only new connections, because established traffic is accepted first; `sudo conntrack -D -d <ip>` cuts an existing one, and the TV's next connection meets the new rule.

## Gotchas

- Every apply resets the counters, because the table is created again. The script lists them just before and just after the reload (`/run/tvgw/counters.before-apply` and `counters.after-apply`, published only when `inet tvgw` loaded) and the next `tvgw verify --record` stores both ([the units](../systemd/README.md#units)), so a reset costs the brief nothing unless a second apply follows within the same 10 minutes and overwrites the first one's listings.
- The firmware-fallback address and table 100 are fixed in the script; the TV side is not ([the TV side](../README.md#the-tv-side)).
- `ip_elements` reads only a leading `a.b.c.d` or `a.b.c.d/n` from each line of `block4.txt`, so anything after it is a comment. A line `nft` refuses leaves the old set loaded, and only `tvgw verify`'s `applied_current` check notices it ([what tvgw verify checks](../../docs/troubleshooting.md#what-tvgw-verify-checks)).
- While `tvgw.service` is stopped, the dispatcher and `tvgw-doh-update` can still run the script and switch forwarding back on.
- The QUIC rule's text, `udp dport 443`, is a key rule for `tvgw verify` only with `BLOCK_QUIC=yes`, but the hardware suite looks for it whatever `BLOCK_QUIC` says.
