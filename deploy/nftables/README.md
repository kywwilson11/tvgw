# The firewall

This folder holds `tvgw-apply`, the one script that decides what the TV can reach, the two address lists it reads, and the guard, the table that keeps the gateway closed to the TV whether or not `tvgw-apply`'s table is loaded. It runs at boot from `tvgw.service`, when a link comes up, after the daily DoH list refresh, from `install.sh`, and by hand as `sudo tvgw-apply`. Why the TV is isolated first and why a failure leaves it dark is in design decisions [2](../../docs/design-decisions.md#2-isolate-first-then-filter) and [5](../../docs/design-decisions.md#5-fail-closed).

## Files

| File | What it is | Installed as |
|---|---|---|
| `tvgw-apply` | The ruleset, the sysctls and the policy routing, as one bash script. | `/usr/local/sbin/tvgw-apply` |
| `block4.txt` | A template for manual IPv4 blocks: one address or CIDR per line, `#` comments. | `/etc/tvgw/block4.txt`, installed only when missing; edit that copy |
| `doh-exclude.txt` | AWS CloudFront and Cloudflare CIDRs that are never put in the DoH block set, because they also serve ordinary sites. | `/etc/tvgw/doh-exclude.txt`, replaced on every install; read by [`tvgw-doh-update`](../bin/README.md) |
| `guard.nft.template` | The guard table `inet tvgw_guard`, with `__TV_IF__`, `__TV_NET__` and `__GW_IP__` for the TV side ([the guard](#the-guard)). | `/etc/tvgw/guard.nft`, rendered by `install.sh` on every run; loaded by `tvgw-guard.service` |

`tvgw-apply` reads three inputs: the settings `UPLINK`, `WAN_IF`, `WAN_GW`, `BLOCK_QUIC`, `STRICT_PORTS`, `ADTECH_PORT_WALL`, `PROFILE`, `DNSGATE`, `TV_IF`, `TV_NET`, `GW_IP`, `CAPTURE_MODE`, `VPN_IF`, `TV_IP` and `TV_MAC` from `/etc/tvgw/tvgw.conf` ([the settings file](../../docs/reference/settings.md)); `/etc/tvgw/block4.txt`; and `/var/lib/tvgw/doh4.txt`, the DoH resolver list `tvgw-doh-update` writes. The TV side comes from the settings, defaulted to `TV_IF=eth0`, `TV_NET=10.10.10.0/24` and `GW_IP=10.10.10.1` (the script's `TV_ADDR`), with `TV_BCAST` derived from `TV_NET` ([the TV side](../../docs/reference/settings.md#the-tv-side)). Fixed in the script are `RT_TABLE=100` and `LG_UPDATE_IP=156.147.69.32`. The rules on this page are shown with the default TV side.

## Order of operations

The script runs with `set -euo pipefail`, so it stops at the first command that fails, and the order below is what keeps a failure from leaving the TV forwarded without a filter.

1. **Settings.** Sources the settings file and fills a missing `UPLINK`, `WAN_IF`, `BLOCK_QUIC`, `STRICT_PORTS`, `ADTECH_PORT_WALL`, `DNSGATE`, `TV_IF`, `TV_NET` or `GW_IP` with the same default as `config.Settings`. It exits 1 unless `BLOCK_QUIC`, `STRICT_PORTS` and `ADTECH_PORT_WALL` are exactly `yes` or `no`, `DNSGATE` is exactly `off` or `count`, `CAPTURE_MODE` is exactly `full` or `headers` (missing means `full`) and (uplink) `WAN_GW_MODE` is exactly `literal` or `auto` (missing means `literal`), because a near miss such as `BLOCK_QUIC=Yes` once dropped the QUIC rule silently, and unless the TV side passes the `tvgw-net` checks it shares with `install.sh`: a subnet such as `0.0.0.0/0` would masquerade, and route by table 100, everything the gateway forwards. `VPN_IF` (missing means `auto`) must be `auto`, `none` or an interface name other than `lo`, `TV_IF` and `WAN_IF`; `auto` resolves to `tun0` if `/proc/sys/net/ipv4/conf/tun0` exists, else `wgpia0` if it does, else no tunnel ([design decision 44](../../docs/design-decisions.md#44-the-tunnel-is-a-setting-and-the-pis-own-leaks-are-counted)). A missing `PROFILE` means `lg-webos`, and any other profile turns `ADTECH_PORT_WALL` to `no` for the apply: the wall is LG's ([design decision 62](../../docs/design-decisions.md#62-a-tv-gets-a-vendor-profile-only-on-evidence-or-its-owners-answer-otherwise-the-general-profile-which-isolates-records-briefs-and-blocks-only-shared-lists)).
2. **Lock.** Takes `/run/lock/tvgw-apply.lock` with `flock`, so two applies never interleave. It waits for the lock; `tvgw.service`'s start timeout bounds a hang at boot ([timeouts](../systemd/README.md#timeouts)).
3. **The TV port.** Reads the `TV_IF` the previous apply recorded in `/run/tvgw/settings.applied`, then asks `ip -4 -o addr show to <GW_IP>` which interface holds `GW_IP`. When that is not `TV_IF`, the settings name a port `tv-lan` is not on yet (`TV_IF` edited, `install.sh` not run again): it prints `tvgw: GW_IP <GW_IP> is on <dev>, not TV_IF=<TV_IF>; run install.sh to move tv-lan, then apply again` and exits 1 with nothing loaded. It first turns forwarding off on that interface unless the filter loaded now was built for it, so a boot with no filter leaves the TV dark rather than unfiltered. `GW_IP` on no interface yet (`tv-lan` still coming up at boot) is not a stop; the forward chain's `TV subnet off the TV port` drop covers that case ([`forward`](#forward)).
4. **Uplink.** `UPLINK=direct` sends the TV out `WAN_IF` by the home router `wan_router` (in the `tvgw-net` block) finds. (uplink) With `WAN_GW_MODE=literal`, or the key missing, that is `WAN_GW`, which is then required, or the script exits 1 before it loads anything. With `auto` it is the first `via` of `ip -4 -o route show default dev <WAN_IF>` (the main table's route the uplink's DHCP installed), else the address in `/run/tvgw/wan_gw.last` (the router an earlier apply took from that route; gone at reboot), else `WAN_GW`; with none of the three the script goes on and step 13 leaves table 100's route to the dispatcher's next apply. `UPLINK=vpn` sends it out the tunnel `VPN_IF` resolved to, or `tun0` when none exists yet, and exits 1 with `VPN_IF=none`. Any other value exits 1.
5. **Kernel settings.** Loads `nf_conntrack`, turns on per-connection byte counts and timestamps (`nf_conntrack_acct`, `nf_conntrack_timestamp`), which the flow log needs, and sets `nf_conntrack_tcp_timeout_established=7440`: 7440 s (2 h 04 min), so an idle connection is reported within hours instead of days. It disables IPv6 on `TV_IF`, and sets `net.ipv4.conf.<TV_IF>.rp_filter=1` (strict reverse-path filtering) when that key exists. The kernel uses the larger of `conf.all.rp_filter` and the interface's value, and systemd sets `all` to 2 (loose), so on a stock system this changes nothing until `all` is lowered; the input chain's source rule is the layer that holds either way. When `/proc/sys/net/netfilter/nf_conntrack_events` exists it renders the `ct_events` rule; on a kernel built without conntrack events it leaves the rule out and prints `tvgw: this kernel has no conntrack events ...`, because nft would refuse the whole table for it ([`ct_events`](#ct_events)).
6. **Address lists.** `ip_elements` keeps the leading `a.b.c.d` or `a.b.c.d/n` of each line of `doh4.txt` and `block4.txt`, drops duplicates, and ignores the rest of the line.
7. **`inet tvgw`, atomically.** First every counter of five tables (`inet tvgw`, `netdev tvgw_l2`, `inet tvgw_gate`, `inet tvgw_capture` and the guard) is listed to `/run/tvgw/counters.before-apply.tmp` (`nft -j -t list table`, one line per table). (ntp) `inet tvgw_ntp` is not listed: its counts live in its set's elements, which a reload keeps. Then one `nft -f` transaction declares the table, deletes it, creates the new one and adds the set elements. When it fails, nothing changes, and the script stops before forwarding, with the listing unpublished. When it loads, and it holds the `ct_events` rule, the script sets `net.netfilter.nf_conntrack_events=0`, so that only the connections the rule marks make events; set before the load, the TV's connections opened in between would make none. A failure to set it only warns ([the kernel switches](../sysctl/README.md)).
8. **`netdev tvgw_l2`.** Loaded the same way. A failure prints `tvgw: netdev IPv6 guard not loaded (<TV_IF> down?)` and the script goes on, because the ingress hook cannot load while the TV interface is down.
9. **`inet tvgw_gate`.** With `DNSGATE=count`, adds the gate table and its sets and chain and replaces the chain's rule ([the DNS gate table](#the-dns-gate-table)); a failure prints a warning and the script goes on, since the gate only counts. With `DNSGATE=off`, deletes the table. (ntp) Then it adds `inet tvgw_ntp` and its set and chain and replaces the chain's rule, in every mode ([the NTP count table](#the-ntp-count-table)); a failure prints `tvgw: NTP count table not loaded` and the script goes on, since the table only counts. Then, with `CAPTURE_MODE=headers`, replaces `inet tvgw_capture` ([the capture table](#the-capture-table)); a failure prints a warning and the script goes on, since the table only logs. With `CAPTURE_MODE=full`, deletes the table.
10. **Counters after.** Lists every counter again, to `counters.after-apply.tmp`, and renames both listings into place together as `/run/tvgw/counters.before-apply` and `/run/tvgw/counters.after-apply`. The next `tvgw verify --record` stores them as snapshots, so the brief sees the reset this apply caused instead of losing what the counters gained since the last snapshot ([design decision 13](../../docs/design-decisions.md#13-counters-not-logs-prove-the-firewall-held)).
11. **Forwarding, last.** Writes `net.ipv4.ip_forward=1` and the per-interface `forwarding=1` for `TV_IF`, and for the uplink once `/proc/sys/net/ipv4/conf/<uplink>` exists: in vpn mode the tunnel appears when the VPN connects, after the boot apply, and `sysctl` fails on a key it cannot find, which would stop the script half done. Until then `tv_out` drops what cannot leave by the uplink, the script prints `tvgw: <uplink> not there yet; the dispatcher switches it on when it comes up`, and the dispatcher re-runs it when it does. The per-interface switches are written explicitly because the kernel copies the global value to the interfaces only when the global value changes, and a stop turns `TV_IF` off ([incidents](../../docs/incidents.md)). Then, when the previous apply's `TV_IF` differs from this one and is not the uplink now, it turns that port's forwarding off again: a global switch from 0 to 1 has just turned it on, and this filter no longer covers it.
12. **Baseline.** Writes `nft -s list table inet tvgw` to `/run/tvgw/ruleset.applied`, the listing `tvgw verify` compares the live table against, and the fifteen settings it used, defaults filled in and the wall as the profile left it, to `/run/tvgw/settings.applied`, which `verify`'s `applied_current` compares the settings file with ([what tvgw verify checks](../../docs/reference/verify-checks.md)). (uplink) The file also holds `WAN_GW_USED`, the router address table 100's route uses (with `literal`, `WAN_GW`), which no check compares, and when `auto` took the router from the uplink's own route, that address goes to `/run/tvgw/wan_gw.last` when it differs from the one there.
13. **Policy routing.** In direct mode, makes sure `ip rule` priority 60 reads `from <TV_NET> lookup 100`, that table 100's default route goes via the router step 4 found (`WAN_GW` with `literal`) on `WAN_IF`, and that table 100 also holds `<TV_NET> dev <TV_IF> scope link src <GW_IP>`, and touches none of the three when it is already right: deleting and re-adding the rule, or replacing an unchanged route, destroyed the conntrack entry of a connection with data in flight ([incident log](../../docs/incidents.md#2026-10-30-live-connections-lost-their-conntrack-entry-at-every-dhcp-renewal)). A route on a port without carrier prints with a trailing `linkdown` and still counts as right. The TV-subnet route is there because rule 60 also matches what the gateway itself sends to the TV from `GW_IP` (the resolver's answers, nginx's replies, the ICMP of a reject); without it those packets leave by the uplink and the TV gets an address but no answers ([design decision 49](../../docs/design-decisions.md#49-the-gateway-answers-the-tv-through-the-tv-port-table-100-carries-the-tv-subnet)). While `GW_IP` is not on `TV_IF` yet (`tv-lan` still coming up at boot) the route cannot be written: the script prints `tvgw: <TV_IF> not up yet; the dispatcher adds the TV subnet to table 100` and goes on, and the dispatcher's apply when `TV_IF` comes up adds it. In vpn mode it removes the rule and asks nothing of table 100, since without rule 60 the main table's route on `TV_IF` answers the TV.
14. **Summary.** Prints `tvgw: applied (uplink=<mode> via <interface>, quic_block=..., strict_ports=..., adtech_wall=..., dnsgate=..., doh4=<n> entries, tv_pin=<addresses or none>)`.
15. **The change ledger's line.** (ledger) Appends `<epoch>\tapply\t<caller>\t<changed|unchanged>` to `/var/lib/tvgw/changes.spool`: the name of the process that ran it (`nm-dispatcher`, `tvgw-doh-update`, `install.sh`, `systemd`) and whether step 13 touched the rule or a route. A write that fails is ignored. The hourly ingest turns the line into a row of `changes`, class A when routing changed and class B when it did not ([design decision 48](../../docs/design-decisions.md#48-one-ledger-of-changes-one-hour-classifier-and-a-second-judge-that-only-watches)).

<picture>
  <source media="(prefers-color-scheme: dark)" srcset="../../docs/diagrams/fig-12-fail-closed.dark.png">
  <img alt="The firewall's states in direct mode, all inside the guard: Down, no firewall and the TV dark; tvgw-apply loads the filter atomically (Loaded, nothing forwarded); the sysctls switch forwarding on (Forwarding, no route yet); the uplink coming up adds rule 60 (Routed, the TV online and filtered). With the uplink down the state is No route, where tv_out drops the TV's traffic, and the dispatcher re-applies when it returns. systemctl stop tvgw switches forwarding off, deletes rule 60 and then inet tvgw, back to Down. The guard, inet tvgw_guard, is loaded by tvgw-guard.service before the network and never unloaded, so in every state only DHCP, DNS, nginx and pings reach the gateway from the TV. A load that fails changes nothing." src="../../docs/diagrams/fig-12-fail-closed.light.png" width="960">
</picture>

*The firewall's states in direct mode, every one inside the guard: a load that fails leaves the previous state, and forwarding is the last thing switched on and the first thing switched off.*

## Stopping

`systemctl stop tvgw` runs the four `ExecStop` lines of `tvgw.service`, in order:

1. `sysctl -q -w net.ipv4.conf.<TV_IF>.forwarding=0`, through `sh -c`. The interface is the `TV_IF` the loaded filter was built for, from `/run/tvgw/settings.applied`; without that file or key, the settings file's `TV_IF`, and `eth0` when that is missing too. A stop between a `TV_IF` edit and the install that moves `tv-lan` so darkens the port the TV is still on. The TV is dark before any rule goes.
2. `ip rule del priority 60`, with errors ignored.
3. `nft delete table netdev tvgw_l2`, with errors ignored.
4. `nft delete table inet tvgw`.

A stopped service leaves the TV dark, never unfiltered ([design decision 5](../../docs/design-decisions.md#5-fail-closed)). The stop leaves `inet tvgw_gate` and (ntp) `inet tvgw_ntp` in place; those tables only count. It leaves `inet tvgw_guard` in place too, which no stop ever deletes ([the guard](#the-guard)). `tvgw-flowlog`, `tvgw-pcap` and `tvgw-dnsgate` start after `tvgw.service` (`After=`, `Wants=`) but are not bound to it, so they keep recording while it is stopped, and the store holds what the dark TV tries.

While the service is stopped, `inet tvgw`'s input chain is gone with its table, and the guard's input chain holds the same line: from the TV subnet only DHCP, DNS, nginx's 80 and 443 and rate-limited pings reach the gateway, and its other services do not. Anything that runs `tvgw-apply` brings the TV back online: the NetworkManager dispatcher on a link change, `tvgw-doh-update` once a day, and `install.sh`.

To reload the firewall, run `sudo tvgw-apply`, not `systemctl restart tvgw`. The script is idempotent and atomic, so a re-run opens no gap; a restart runs the stop path first and blacks the TV out for a moment.

## The ruleset, chain by chain

The rules are listed in the order `tvgw-apply` writes them. A rule's comment is part of an interface ([design decision 13](../../docs/design-decisions.md#13-counters-not-logs-prove-the-firewall-held)): `tvgw verify --record` snapshots every rule that has a `counter` and a `comment`, and the brief's "Firewall held" line matches the comments by prefix (`queries.FW_LINES` in src/tvgw/queries.py; [brief sections](../../docs/reference/brief-sections.md#sections)).

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
| `ct_events` | prerouting | `-150` |
| `pre_nat` | prerouting | `dstnat - 10` |
| `input` | input | `filter - 10` |
| `forward` | forward | `filter - 10` |
| `output` | output | `filter - 10` |
| `post_nat` | postrouting | `srcnat - 10` |
| `post_leaks` | postrouting | `srcnat - 20` |

`pre_mangle` runs 10 after the standard mangle priority. `ct_events` runs after conntrack (-200) and before the connection is confirmed, which is when the kernel takes its event mask; `post_leaks` runs before the masquerade, so the TV's packets still carry its subnet. The other chains run 10 before their standard priority, so they come ahead of other chains at the same hook: `pre_nat` runs before the VPN client's NAT chain, which would otherwise send the TV's DNS to the VPN's resolver.

### `pre_mangle`

| Rule | Comment | Why |
|---|---|---|
| Direct mode only: `iifname "eth0" meta mark set 0 counter` | `undo PIA routed-packet tag` | The VPN client marks every forwarded packet to route it into the tunnel. Clearing the mark lets table 100 send the TV's packets out the uplink. |

In vpn mode the chain is empty.

### `ct_events`

| Rule | Comment | Why |
|---|---|---|
| `iifname "eth0" ip saddr 10.10.10.0/24 ct state new ct event set destroy` | `flow log: TV connections only` | With `nf_conntrack_events=0` no connection makes conntrack events unless a rule asks; this one asks for the TV's, in both uplink modes, so `tvgw-flowlog` hears the TV alone and the gateway's own churn never fills its socket ([design decision 43](../../docs/design-decisions.md#43-the-flow-log-hears-the-tv-alone-and-the-gates-day-starts-at-each-answer)). Prerouting holds both of the TV's paths: the connections it forwards and the ones it opens to the gateway (DNS, nginx). No counter: it marks, it does not judge. |

On a kernel without conntrack events the chain is empty.

### `pre_nat`

| Rule | Comment | Why |
|---|---|---|
| `iifname "eth0" ip daddr != 10.10.10.1 udp dport 53 counter dnat ip to 10.10.10.1:53` | `TV DNS aimed elsewhere -> AdGuard` | DNS the TV aims at any other resolver, such as a hardcoded `8.8.8.8`, lands on AdGuard Home. |
| The same for `tcp dport 53` | `TV DNS aimed elsewhere -> AdGuard` | The same, over TCP. |

A nat chain sees only the first packet of each connection, so these counters count redirected flows, not packets.

### `input`

What may reach the gateway itself from the TV.

| Rule | Comment | Why |
|---|---|---|
| `iifname { "tun0", "wgpia0" } ct state new counter drop`, plus `VPN_IF` when it names a third tunnel | `nothing unsolicited from the VPN side` | Nothing may open a connection to the gateway from the tunnel: PIA's OpenVPN interface and its WireGuard one, whatever `VPN_IF` says. |
| `iifname != "eth0" accept` | none | This table polices the TV side only. |
| `ip saddr != { 0.0.0.0, 10.10.10.0/24 } counter drop` | `TV source outside its subnet (input)` | A source outside the TV subnet can only be forged. With a home-LAN host's address as the source, a query to the resolver would make the gateway answer that host over the uplink, a path `tv_out` never sees. `0.0.0.0` is a DHCPDISCOVER. The brief adds it to `foreign source`. |
| `meta l4proto { tcp, udp } th dport 53 counter` | `TV DNS to the gateway` | Counts the TV's DNS before the established shortcut, because webOS keeps one UDP source port for its resolver all day. |
| `ct state established,related accept` | none | Replies. |
| `udp sport 68 udp dport 67 accept` | `DHCP` | DHCP requests go to the broadcast address, which the next rule would drop. |
| `ip daddr != 10.10.10.1 counter drop` | `TV talks to the gateway address only` | The TV may use the gateway's address and no other address of the gateway. |
| `meta l4proto { tcp, udp } th dport 53 accept` | `DNS -> AdGuard` | AdGuard Home. |
| `tcp dport { 80, 443 } accept` | `GFTS URL filter / TLS passthrough (nginx)` | The [URL filter](../nginx/README.md). |
| `icmp type echo-request limit rate 5/second accept` | none | Reachability checks, at up to 5 a second. |
| `counter drop` | `TV may not reach other Pi services` | Everything else on the gateway stays out of the TV's reach. |

### `forward`

| Rule | Comment | Why |
|---|---|---|
| `ip saddr 10.10.10.0/24 iifname != "eth0" counter drop` | `TV subnet off the TV port` | The TV's subnet arriving on another port: `TV_IF` was edited and `tv-lan` not moved yet, and the next rule would accept it unfiltered. The brief's label is `off the TV port`. |
| `iifname != "eth0" oifname != "eth0" accept` | none | Not TV traffic; left to the rest of the system. |
| `ct state invalid counter drop` | `invalid: would leave un-NATed` | An invalid packet would leave without NAT, carrying the TV's own address. |
| `iifname "eth0" ip saddr != 10.10.10.0/24 counter drop` | `TV source outside its subnet` | Masquerade covers only the TV subnet, and the capture, the flow log and the gate all key on its addresses, so a packet from another source would leave un-NATed and unrecorded. The brief's label is `foreign source`. |
| Once the TV is pinned: `iifname "eth0" ip saddr != { 10.10.10.17 } counter drop` | `TV source is not the TV` | Only the TV's own address forwards. A second address in the subnet (a rooted TV's alias) would be outside the flow log (`--orig-src TV_IP`) and the HTTPS/SVCB strip (`client=TV_IP`). The rule is there only when `TV_MAC` is a real MAC, which is what puts the DHCP pin in dnsmasq's config; on a fresh install, before `tvgw discover --write`, the TV holds a pool address and any address in the subnet forwards. When the TV still holds an unexpired lease for another address under `TV_MAC` (`TV_IP` was just edited), that address is in the set too, with a warning, until an apply after the lease moved. The brief's label is `second TV address`. |
| Vpn mode only: `oifname "<tunnel>" tcp flags syn tcp option maxseg size set rt mtu` | `tunnel MTU` | The tunnel's MTU is smaller. |
| `ct state established,related accept` | none | Replies, and connections that were allowed when they started. |
| `iifname "eth0" meta nfproto ipv4 jump tv_out` | none | The TV's new connections. |
| `counter drop` | `nothing else into or out of the TV subnet` | Devices on the home network cannot open connections to the TV. |

### `tv_out`

The TV's new outbound connections. `<uplink>` is `WAN_IF` in direct mode and the tunnel `VPN_IF` resolved to (`tun0` before one exists) in vpn mode.

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
| With `ADTECH_PORT_WALL=yes` and `PROFILE=lg-webos`: `tcp dport { 4001, 4431, 4445, 4447, 8180, 8883 } limit rate 6/minute log prefix "tvgw-adport: "` | none | (acr) A sample of the attempts the next rule resets, at most 6 log lines a minute, which ingest stores in `adport`. A rule of its own for the reason the `tvgw-proto` sample is. |
| With `ADTECH_PORT_WALL=yes` and `PROFILE=lg-webos`: the same match, `counter reject with tcp reset` | `LG adtech port` | (acr) LG's ad-tech ports: ACR fingerprints (4431, 4445, 4447), Alphonso provisioning (4001), LG ads (8180) and an IoT hub (8883), every non-web port a newer LG used in a published lab trace and none the CX has used. DNS blocks the hosts behind them already; the counter names an attempt DNS missed, and drives the brief's ACR red line. Before the odd-port rules, so "Unexpected ports" counts only unknown ports ([design decision 45](../../docs/design-decisions.md#45-the-acr-red-line-is-an-upload-test-and-a-port-wall)). |
| `ip daddr 156.147.69.32 tcp dport 8080 counter log prefix "tvgw-lg8080: " accept` | `LG firmware fallback path` | LG's hardcoded firmware-update fallback: allowed so updates work, logged so it shows. |
| `meta l4proto { tcp, udp } th dport != { 80, 123, 443 } limit rate 6/minute log prefix "tvgw-oddport: "` | `unexpected port` | Evidence for the brief, at most 6 log lines a minute; the rule has no counter. |
| With `STRICT_PORTS=no`: the same match, `counter accept` | `STRICT_PORTS=no: count only` | Other ports are counted and allowed. |
| With `STRICT_PORTS=yes`: the same match, `counter reject with icmpx admin-prohibited` | `STRICT_PORTS: only web, NTP and DNS` | Apps fail fast instead of hanging ([STRICT_PORTS](../../docs/use/blocking.md#strict_ports), [design decision 17](../../docs/design-decisions.md#17-strict_ports-stays-off-until-two-clean-weeks)). |
| `accept` | none | Everything else. |

NTP on UDP 123 stays open in both modes in case a firmware uses it; webOS takes its clock from LG's SDP reply over 443.

### `output`

| Rule | Comment | Why |
|---|---|---|
| `oifname "eth0" ip daddr { 10.10.10.255, 255.255.255.255, 224.0.0.0/4 } udp dport != { 67, 68 } counter drop` | `no NetBIOS/SSDP chatter from the Pi into the TV subnet` | The gateway's own broadcast and multicast stay off the TV subnet; DHCP is the exception. |

`tvgw discover` opens holes for the length of its SSDP search, each commented `tvgw-discover`, and deletes them all again whatever happens (src/tvgw/discover.py): at the top of this chain `oifname "eth0" udp dport 1900 counter accept`, for the search, and, once its socket is bound, at the top of `input`, and of the guard's `input`, `iifname "eth0" ip daddr 10.10.10.1 udp dport <the socket's port> counter accept`, for the TV's unicast answer, which conntrack sees as a new flow and `TV may not reach other Pi services` (and the guard's final drop) would otherwise drop. Each hole goes only into a table that is loaded: on a first install, before `tvgw-apply` has run, only the guard's.

The rule "the TV's LAN API from root only" (TCP 3000 and 3001 to the TV subnet from any user but root) is not here but in the guard's `output` chain, so it holds when this table is gone ([the guard](#the-guard)).

### `post_nat`

| Rule | Comment | Why |
|---|---|---|
| `iifname "eth0" oifname "<uplink>" ip saddr 10.10.10.0/24 masquerade` | none | The TV's traffic leaves with the uplink's address; only what came in on the TV port, so the TV subnet on any other port is never translated. |

### `post_leaks`

The gateway's own lookups that leave by the uplink instead of the tunnel, counted and never dropped ([design decision 44](../../docs/design-decisions.md#44-the-tunnel-is-a-setting-and-the-pis-own-leaks-are-counted)). Postrouting sees a packet after every output-hook verdict, the VPN client's kill switch included, so the counters count what really left. Each rule counts a connection once, at its first packet. With `VPN_IF=none` the chain is empty.

| Rule | Comment | Why |
|---|---|---|
| `oifname "wlan0" ip saddr != 10.10.10.0/24 ct state new tcp dport 443 ip daddr @doh4 counter` | `pi leak: DoH left by the uplink` | AdGuard's DoH outside the tunnel: the provider sees the home address. Under PIA's `killswitch=auto` this happens after a daemon start before its first connection, after `piactl disconnect` and while the daemon is not active. |
| `oifname "wlan0" ip saddr != 10.10.10.0/24 ct state new meta l4proto { tcp, udp } th dport 53 counter` | `pi leak: DNS left by the uplink` | Plain DNS from the gateway outside the tunnel, which PIA's DNS block stops while it is connected. A VPN transport on remote port 53 would count here too. |

The brief keeps both out of "Firewall held" and raises a red line when either rises on a gateway with a VPN ([red lines](../../docs/use/daily-brief.md#red-lines)).

### `netdev tvgw_l2`

| Rule | Comment | Why |
|---|---|---|
| Chain `in`, ingress hook on `eth0` at priority `-500`: `ether type ip6 counter drop` | `no IPv6 from the TV` | IPv6 is dropped at the wire as well as disabled on the interface. The counter ticks with neighbor-discovery noise; that is not a breach. |

## The guard

`inet tvgw_guard` keeps the gateway closed to the TV subnet at the moments `inet tvgw` is not loaded: at boot until `tvgw-apply` runs, while `tvgw.service` is stopped, after an apply nft rejected, and if anything deletes the table ([design decision 42](../../docs/design-decisions.md#42-the-pi-is-closed-to-the-tv-whatever-nftables-holds)). `install.sh` renders `guard.nft.template` into `/etc/tvgw/guard.nft`, and `tvgw-guard.service` loads it with `nft -f` before `network-pre.target`, so the table is in the kernel before NetworkManager brings the TV port up. The unit has no `ExecStop` and refuses a manual stop (and so a restart): nothing but `nft delete table inet tvgw_guard` removes the table ([removing the guard in an emergency](../../docs/use/troubleshooting.md#removing-the-guard-in-an-emergency)). `systemctl reload tvgw-guard` loads the file again.

The file is one transaction. `add table` and `add chain` keep what exists, `flush chain` empties each chain and the `add rule` lines fill it again, so a reload never leaves a moment without the chains, and a failure changes nothing. The three base chains run at priority `filter + 10`, after `inet tvgw`'s `filter - 10`. A drop in any base chain is final and an accept is not: the next base chain on the hook still sees the packet. So the guard can only narrow what `inet tvgw` (or the VPN client's tables) let through, never widen it. While `inet tvgw` is loaded it drops first and keeps its counters, and the guard sees only what it accepted.

| Chain | Rule | Comment | Why |
|---|---|---|---|
| `input` | `iifname != "eth0" accept` | none | The TV side only. |
| `input` | `meta nfproto ipv6 counter drop` | `guard: no IPv6 from the TV side` | IPv6 is off on the port; this holds if it ever comes back. |
| `input` | `ip saddr != { 0.0.0.0, 10.10.10.0/24 } counter drop` | `guard: spoofed source` | As `inet tvgw`'s input source rule. |
| `input` | `ct state established,related accept` | none | Replies. |
| `input` | `udp sport 68 udp dport 67 accept` | `guard: DHCP` | DHCP, to the broadcast address too. |
| `input` | `ip daddr != 10.10.10.1 counter drop` | `guard: the gateway address only (weak host)` | Linux owns an address for the whole host, so a socket bound to the gateway's Wi-Fi address is reachable from the TV port by the gateway's MAC. Binding a service to the LAN address is not isolation; this rule is. |
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

The guard does not stop a process with root or `CAP_NET_ADMIN` from deleting it; nft's `owner` and `persist` table flags do not either, since an orphaned table accepts a new owner. Two things narrow that: dnsmasq, the daemon that parses the TV's DHCP, runs without `CAP_NET_ADMIN` ([DHCP for the TV](../dnsmasq/README.md#the-hardening-drop-in)), and the co-tenants carry `IPAddressDeny=TV_NET`, a cgroup filter that holds with every nftables table gone ([the settings file](../../docs/reference/settings.md), `CO_TENANT_UNITS`).

<picture>
  <source media="(prefers-color-scheme: dark)" srcset="../../docs/diagrams/fig-17-two-walls.dark.png">
  <img alt="Two walls stand between the TV and the gateway. Wall 1 is the guard, inet tvgw_guard, loaded before the network and never unloaded: its input chain lets DHCP, DNS, nginx's 80 and 443 and pings reach the gateway address and drops the rest of the gateway, its forward chain lets nothing through to the home LAN, and its output chain lets only root open the TV's API. Behind it, dnsmasq runs without CAP_NET_ADMIN and CAP_NET_RAW and nginx in a sandbox; each co-tenant service the settings name (CO_TENANT_UNITS) carries wall 2, IPAddressDeny for the TV subnet, so a port of one of those services is dropped by both walls." src="../../docs/diagrams/fig-17-two-walls.light.png" width="960">
</picture>

*The TV reaches the gateway's DHCP, DNS and URL filter and nothing else on the gateway, whatever the firewall holds.*

### Lifting it in an emergency

The commands are in [fix a problem](../../docs/use/troubleshooting.md#removing-the-guard-in-an-emergency): disable `tvgw-guard.service`, then `nft delete table inet tvgw_guard`; to restore, `enable` and `reload-or-restart`. Why those and no others:

The unit is disabled rather than masked: `install.sh` installs it into `/etc/systemd/system`, and `systemctl mask` refuses a unit whose file is there. The next deploy enables and loads it again, so hold deploys (or set the CI job aside) while it is off.

This is the only way, by design. `tvgw-guard.service` has no `ExecStop`, so a stop could not remove the table, and it refuses a manual stop or restart (`RefuseManualStop=yes`), so an upgrade, a typo or a script cannot open the gateway for even a second. Removing the package leaves the table in the kernel too, until the next boot. While it is gone, the gateway is open to the TV whenever `inet tvgw` is not loaded, as it was before [design decision 42](../../docs/design-decisions.md#42-the-pi-is-closed-to-the-tv-whatever-nftables-holds); the co-tenants' `IPAddressDeny` drop-ins still hold.

Not `enable --now`: after `nft delete table` the oneshot unit is still active (`RemainAfterExit=yes`), and a start of an active unit does nothing, so the table would stay gone. `reload-or-restart` reloads an active unit (its `ExecReload`, one `nft -f`) and starts an inactive one; a plain `restart` is refused (`RefuseManualStop=yes`). Re-running `install.sh` does the same: it renders `/etc/tvgw/guard.nft` again, enables the unit, and reloads it whenever the table is missing or differs from what the unit loaded. A drop-in of the hardening that took a co-tenant or dnsmasq down comes out the same way: delete the file `install.sh` names in its `WARNING`, `sudo systemctl daemon-reload`, and restart that service.

## The DNS gate table

With `DNSGATE=count`, `tvgw-apply` keeps the table `inet tvgw_gate` ([design decision 18](../../docs/design-decisions.md#18-dns-gated-egress-starts-as-a-count-in-its-own-table)):

| Object | Definition | Why |
|---|---|---|
| Set `resolved4` | `type ipv4_addr; flags timeout; size 65536;` | The addresses the TV's lookups returned. `tvgw-dnsgate` adds each with a one-day timeout and the same expiry (`timeout 86400s expires 86400s`), so on kernel 6.12 and later each answer starts the address's day again; with the timeout alone the kernel kept the first expiry ([the units](../systemd/README.md#units)). `tvgw verify` warns when it holds more than half its size. |
| Set `seen4` | `type ipv4_addr . ipv4_addr . inet_proto . inet_service . inet_service; flags dynamic, timeout; timeout 2m; size 65536;` | Each counted flow's tuple, for two minutes. conntrack calls every packet of a flow new until a reply is seen, so without it each retransmitted SYN to a server that is down, or each datagram of an unanswered UDP flow, would count again. |
| Chain `forward` | `type filter hook forward priority filter - 5; policy accept;` | It runs after `inet tvgw`'s forward chain, so it sees only what the filter accepted. |
| Its one rule | `iifname "eth0" ip saddr 10.10.10.0/24 ct state new ip daddr != 10.10.10.1 ip daddr != @resolved4 ip saddr . ip daddr . meta l4proto . th sport . th dport != @seen4 add @seen4 { ip saddr . ip daddr . meta l4proto . th sport . th dport } counter limit rate 6/minute log prefix "tvgw-gate: "`, comment `TV to an address DNS never returned` | Counts each new connection to an address no lookup returned, once per tuple (it adds the tuple to `seen4` as it counts it), and logs a sample of at most 6 a minute. It never drops. |

The table is separate from `inet tvgw` so its changing set does not disturb the baseline `tvgw verify` compares. It is written with `add` statements, so a re-apply keeps the addresses already collected and the tuples seen; only the chain is flushed and its rule written again. A failure to load it prints `tvgw: DNS gate table not loaded` and leaves the TV forwarded, because the gate only counts. With `DNSGATE=off` the script deletes the table.

## The NTP count table

(ntp) `tvgw-apply` keeps the table `inet tvgw_ntp` in every mode: it counts the TV's NTP by the address it goes to, because UDP 123 is the one port open to any address by design ([design decision 17](../../docs/design-decisions.md#17-strict_ports-stays-off-until-two-clean-weeks), its note of 2026-11-05). The script's block for it sits between `# ---- (ntp) begin` and `# ---- (ntp) end ----`.

| Object | Definition | Why |
|---|---|---|
| Set `ntp4` | `type ipv4_addr; flags dynamic, timeout; timeout 1d; size 1024;` (`NTP_SIZE`) | The addresses the TV sent NTP to, each with a counter of its own. An address leaves a day after its last request, and the set holds at most 1024. |
| Chain `forward` | `type filter hook forward priority filter + 20; policy accept;` | After `inet tvgw`'s forward chain and the guard's (`filter + 10`), so it counts only what the filter let out. |
| Its one rule | `iifname "eth0" ip saddr 10.10.10.0/24 udp dport 123 counter update @ntp4 { ip daddr counter }`, comment `NTP from the TV, by server` | Counts the request in its own total, then adds its address to `ntp4`, or starts that address's day again, and counts it there. No verdict. |

It is written with `add` statements, so a re-apply keeps every address and its count; only the chain is flushed and its rule written again, which zeroes the rule's total. When the set is full, the update adds nothing and the rule ends there, and the packet goes on by the chain's policy, as it does when the table is missing: the count can lose evidence, never the TV's NTP. A failure to load it prints `tvgw: NTP count table not loaded`. `tvgw verify --record` stores the rule's total and one series per address, `ntp: <address>` ([the tables](../../docs/reference/data-model.md#fw_counters)), and the brief's Clock servers line reads them ([brief sections](../../docs/reference/brief-sections.md#clock-servers)). The counter is a measure of where the TV's clock goes, not of what the filter held, so the brief keeps it out of Firewall held (`ACCEPT_COUNTERS` in tests/unit/test_fw_lines.py).

## The capture table

With `CAPTURE_MODE=headers`, `tvgw-apply` replaces the table `inet tvgw_capture` in one transaction, after the filter and the gate ([design decision 39](../../docs/design-decisions.md#39-the-first-packets-of-each-connection-behind-a-switch)). The script's block for it sits between `# ---- (capture) begin` and `# ---- (capture) end ----`.

| Object | Definition | Why |
|---|---|---|
| Chain `pre` | `type filter hook prerouting priority mangle - 5; policy accept;` | After conntrack (-200) has counted the packet, before the DNS redirect (`dstnat - 10`) and the rejects in `tv_out`: it sees what the TV sent, to where it sent it, attempts the filter refuses included. |
| First rule | `iifname "eth0" ip saddr 10.10.10.0/24 ip saddr != 10.10.10.1 ct original packets != 0 ct original packets <= 8 counter log group 7 snaplen 4096 queue-threshold 1`, comment `capture: the first packets of each TV connection` | The first 8 packets of each connection the TV opens, at most 4096 bytes each, to NFLOG group 7. A connection conntrack has no counters for reads 0 and is skipped. `queue-threshold 1` sends each packet at once, so its time is not a batch's. |
| Second rule | `... tcp dport 80 ct original packets > 8 counter log group 7 queue-threshold 1`, comment `capture: plain HTTP after them` | Plain HTTP after the first 8 packets, whole, as the full capture keeps it. |

Neither rule has a verdict, so the table can lose evidence but never let a packet through or stop one. `tvgw-pcap-headers.service` reads group 7 ([the capture](../../docs/how-it-works/capture.md#the-headers-mode)); the counters are evidence of the capture, not of the filter, so the brief does not list them. A failure to load the table prints `tvgw: capture table not loaded; tvgw-pcap-headers records nothing`, and `tvgw verify`'s `capture` check fails until it is loaded.

## Checking it

On the gateway:

```sh
sudo nft list table inet tvgw                 # the live ruleset with its counters
sudo nft list table inet tvgw_gate            # the DNS gate, with DNSGATE=count
sudo nft list table inet tvgw_ntp             # the NTP count: each address with its own counter
sudo nft list table inet tvgw_capture         # the headers capture's rule, with CAPTURE_MODE=headers
sudo nft list table netdev tvgw_l2            # the IPv6 wire drop
sudo nft list table inet tvgw_guard           # the guard, with its counters (the last should stay at 0)
systemctl status tvgw-guard                   # active (exited); a stop is refused
sudo nft -c -f /run/tvgw/ruleset.applied      # the last applied listing still parses
ip rule show priority 60                      # direct mode: from 10.10.10.0/24 lookup 100
ip route show table 100                       # direct mode: the default via the router, and 10.10.10.0/24 on eth0
journalctl -u tvgw -n 20                      # the applies and their summary lines
journalctl -k -g 'tvgw-oddport|tvgw-adport|tvgw-proto|tvgw-lg8080|tvgw-gate'   # the logged rules
sudo tvgw verify                              # the checks against this ruleset
```

## Changing it

1. Edit `deploy/nftables/tvgw-apply` in the repository.
2. When you add, rename or remove a counted rule's comment, update `queries.FW_LINES` in src/tvgw/queries.py. When you change the text of a key rule, update `KEY_RULES` in src/tvgw/verify.py and `KEY_RULES` in tests/hardware/test_gateway.py.
3. When you add a setting, give it the same default in the script's `${KEY:=value}` line as in `config.Settings`, and the same accepted values in its `case` as in `config.CHOICES`. When the script starts to read a reserved key ([the settings file](../../docs/reference/settings.md)), take the key out of `RESERVED_IN` in tests/unit/test_deploy_lint.py, which fails while the script reads a key listed there. When the script checks that key with a `case`, move it from `config.MODES` to `config.CHOICES`.
4. Run `make gate`. These tests guard the script:
   - `tests/unit/test_fw_lines.py` fails when a counted drop or reject has no line in the brief, or a line in `FW_LINES` matches no rule. A counted accept that is not evidence goes in its `ACCEPT_COUNTERS`.
   - `tests/unit/test_deploy_lint.py` runs `bash -n` on the script, checks that every needle in `verify.KEY_RULES` and in the hardware suite's `KEY_RULES` is in its text, and checks its defaults and `case` arms against `config.Settings` and `config.CHOICES`.
5. Run the virtual suite, or let the `virtual` workflow run it on the pull request: it checks every variant with `nft -c` and probes the loaded firewall against `tests/virtual/matrix.txt`. A change to what the TV can reach is a change to a row of that file ([the virtual gateway](../../tests/virtual/README.md)).
6. Deploy, then test the change on the gateway (next section).

## Testing a change

`nft -c` checks a ruleset against the running kernel without loading it, and `tvgw-apply --check` renders the tables the settings file would load (three with `DNSGATE=off`, four otherwise, one more with `CAPTURE_MODE=headers`), with every shell variable filled in, and has `nft -c` check each. It changes nothing: no sysctl, no table, no route, nothing under `/run/tvgw`. It prints the rulesets on standard output, exits 0 when nft accepts every one and 1 otherwise; unlike an apply, it fails on a side table (`netdev tvgw_l2`, `inet tvgw_gate`, `inet tvgw_ntp`) nft refuses.

On the gateway:

```sh
sudo tvgw-apply --check > /tmp/tvgw.nft   # render and check, change nothing
sudo tvgw-apply                           # then load it for real
sudo tvgw verify
```

A ruleset that fails to load leaves the previous one in place. A new block stops only new connections, because established traffic is accepted first; `sudo conntrack -D -d <ip>` cuts an existing one, and the TV's next connection meets the new rule.

## Gotchas

- Every apply resets the counters, because the table is created again. The script lists them just before and just after the reload (`/run/tvgw/counters.before-apply` and `counters.after-apply`, published only when `inet tvgw` loaded) and the next `tvgw verify --record` stores both ([the units](../systemd/README.md#units)), so a reset costs the brief nothing unless a second apply follows within the same 10 minutes and overwrites the first one's listings.
- The firmware-fallback address and table 100 are fixed in the script; the TV side is not ([the TV side](../../docs/reference/settings.md#the-tv-side)).
- `ip_elements` reads only a leading `a.b.c.d` or `a.b.c.d/n` from each line of `block4.txt`, so anything after it is a comment. A line `nft` refuses leaves the old set loaded, and only `tvgw verify`'s `applied_current` check notices it ([what tvgw verify checks](../../docs/reference/verify-checks.md)).
- While `tvgw.service` is stopped, the dispatcher and `tvgw-doh-update` can still run the script and switch forwarding back on.
- The QUIC rule's text, `udp dport 443`, is a key rule for `tvgw verify` only with `BLOCK_QUIC=yes`, but the hardware suite looks for it whatever `BLOCK_QUIC` says.
