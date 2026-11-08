# Architecture

This page owns how tvgw works: the components on the gateway, the path a packet takes, how policy becomes configuration, how evidence becomes a block, how a connection is named, how often each job runs, and what each component may touch. It is for a technical reader who wants to understand tvgw before changing it, operating it or auditing it.

## Components on the gateway

The TV has one cable, to the gateway's `eth0`, and no other way out: isolation comes first and filtering is layered on it ([design decision 2](../design-decisions.md#2-isolate-first-then-filter)). The gateway reaches the home router through `WAN_IF`. This page names the TV side by its defaults, `eth0`, `10.10.10.0/24` and `10.10.10.1`; they are the settings `TV_IF`, `TV_NET` and `GW_IP` ([the TV side](../reference/settings.md#the-tv-side)). Its components:

- **nftables** holds the firewall in three tables ([the packet path](#the-packet-path)), and beside them the guard, a fourth that keeps the gateway closed to the TV whether or not the firewall is loaded ([the guard](#the-guard)).
- **dnsmasq** serves DHCP only on `eth0`: it pins the TV's address and names `10.10.10.1` as router and DNS server. It runs without `CAP_NET_ADMIN`, the capability that could rewrite the firewall ([DHCP for the TV](../../deploy/dnsmasq/README.md#the-hardening-drop-in)).
- **AdGuard Home** is the TV's resolver on `10.10.10.1:53`. It forwards what it allows over DNS-over-HTTPS to upstreams given by address ([design decision 9](../design-decisions.md#9-doh-upstreams-by-ip-address)) and logs every query to `querylog.json`. Its configuration is generated ([the control plane](#the-control-plane)), and it runs with `--no-check-update`, so its binary changes only through `tvgw adguard upgrade` ([design decision 46](../design-decisions.md#46-the-blocklists-are-watched-and-adguard-changes-only-on-purpose)).
- **nginx** listens on `10.10.10.1:80` as the URL filter for LG's plain-HTTP file service ([design decision 8](../design-decisions.md#8-a-url-filter-for-lgs-file-service-instead-of-a-dns-block)) and on `10.10.10.1:443`, where it passes TLS for the same names through by server name without decrypting it. It logs to `gfts.log`.
- **NetworkManager** keeps `10.10.10.1/24` on `eth0` (never a default route, IPv6 off), and keeps it while the TV is off. Its dispatcher re-runs `tvgw-apply` when a link comes up.
- **The capture units**: `tvgw-pcap` runs `dumpcap` into hourly pcaps of what the TV sends (or, with `CAPTURE_MODE=headers`, `tvgw-pcap-headers` writes the first packets of each connection the firewall hands it: [the capture](capture.md)); `tvgw-flowlog` runs `conntrack` and writes one line per finished TV connection to `flows.log`; `tvgw-dnsgate` reads the resolver's answers to the TV and feeds the DNS gate's address set.
- **The tvgw jobs**: `tvgw-analyze` (hourly: the TV's settings, `tvgw ingest`, the reports), `tvgw-prune`, `tvgw-verify` (which also samples the gateway's own counters for the change ledger), `tvgw-backup`, `tvgw-analyst`, `tvgw-analyst-weekly`, `tvgw-autoblock` and `tvgw-doh-update`, each started by its timer. With `tvgw.service`, `tvgw-guard.service` and the four capture units, `deploy/systemd` holds fourteen services and eight timers ([units](../../deploy/systemd/README.md#units)).
- **The store**, `tvgw.db`: one SQLite file that every report reads ([the store](../reference/data-model.md)).
- **A VPN client**, when the gateway runs one, carries the gateway's own traffic, AdGuard's DoH included. In direct mode it does not carry the TV's ([design decision 1](../design-decisions.md#1-the-tv-uses-the-direct-uplink-not-the-vpn)).

<picture>
  <source media="(prefers-color-scheme: dark)" srcset="../diagrams/fig-2-data-path.dark.png">
  <img alt="Every packet from the TV meets the gateway's firewall first, which drops IPv6, the home LAN, DoT, DoQ, QUIC and known DoH. DHCP reaches dnsmasq, DNS to any resolver is redirected to AdGuard Home, with the LG profile LG's file-service requests reach the nginx URL filter, and the allowed rest is policy-routed out the uplink to the home router. AdGuard's encrypted lookups and nginx's proxied downloads leave on the gateway's own route." src="../diagrams/fig-2-data-path.light.png" width="960">
</picture>

*The components on the TV side: every packet meets the firewall first, and each of the gateway's services answers one kind of request.*

## The packet path

The firewall is three nftables tables, all loaded by [deploy/nftables/tvgw-apply](../../deploy/nftables/tvgw-apply). `inet tvgw` is the filter, replaced whole on every apply. `netdev tvgw_l2` drops IPv6 at the wire. `inet tvgw_gate` counts connections to addresses no lookup returned; it is a table of its own, created with `add` statements, so a re-apply keeps its set and `tvgw verify`'s baseline of `inet tvgw` stays fixed ([design decision 18](../design-decisions.md#18-dns-gated-egress-starts-as-a-count-in-its-own-table)). The rules one by one, with their reasons, are in [the firewall](../../deploy/nftables/README.md).

A packet from the TV meets them in this order:

1. **`netdev tvgw_l2`**, on `eth0`'s ingress, drops every IPv6 frame. IPv6 is also disabled on `eth0`.
2. **`ct_events`** (prerouting, priority -150) marks each new connection from the TV subnet on `eth0` to make a conntrack event when it ends (`ct event set destroy`). `tvgw-apply` sets `nf_conntrack_events=0` once it is loaded, so no other connection on the gateway makes events and the flow log hears the TV alone ([design decision 43](../design-decisions.md#43-the-flow-log-hears-the-tv-alone-and-the-gates-day-starts-at-each-answer)). It never drops.
3. **`pre_mangle`**, in direct mode, sets the packet's mark to `0`: the gateway's VPN client marks forwarded packets to send them into its tunnel.
4. **`pre_nat`** rewrites DNS (UDP or TCP port 53) aimed at any address but `10.10.10.1` to `10.10.10.1:53`, so a hardcoded resolver lands on AdGuard Home. It runs before the VPN client's own NAT chain.
5. **Routing.** Traffic for the gateway goes to the `input` chain. In direct mode, policy rule priority 60 (`from 10.10.10.0/24 lookup 100`) sends the TV's other traffic to routing table 100, whose default route is `WAN_GW` on `WAN_IF`. The rule also matches the gateway's own replies to the TV, from `10.10.10.1`, so table 100 holds the TV subnet on `eth0` as well, and those replies leave by `eth0` ([design decision 49](../design-decisions.md#49-the-gateway-answers-the-tv-through-the-tv-port-table-100-carries-the-tv-subnet)).
6. **`input`** first drops any source outside `10.10.10.0/24` (`0.0.0.0` excepted, for DHCP): only a forged packet has one, and it could make the resolver answer a home-LAN host. It accepts from the TV established traffic and DHCP, and, addressed to `10.10.10.1` only, DNS, TCP 80 and 443 for nginx, and pings at up to 5 a second. It drops the rest, and counts the TV's DNS to the gateway per packet. The guard's input chain then sees what it accepted, and holds the same line again.
7. **The forwarding switch.** Nothing from `eth0` is forwarded while `net.ipv4.conf.eth0.forwarding` is off.
8. **`forward`** first drops the TV subnet arriving on any port but `eth0` (`TV subnet off the TV port`, for a `TV_IF` edited before `tv-lan` moved), and accepts what is not TV traffic. It drops packets with an invalid connection state, then any packet from `eth0` whose source is outside `10.10.10.0/24` (`TV source outside its subnet`): masquerade covers only the TV subnet, and the capture, the flow log and the gate all key on its addresses, so such a packet would leave un-NATed and unrecorded. Once the TV is pinned (`TV_MAC` known), it also drops any source but `TV_IP` (`TV source is not the TV`), so a second address in the subnet cannot escape the flow log and the HTTPS strip, which key on `TV_IP`. It accepts established and related traffic, sends each new IPv4 connection from `eth0` to `tv_out`, and drops everything else into or out of the TV subnet.
9. **`tv_out`** drops anything not leaving by the chosen uplink, anything for the home LAN (`lan4`) and protocols other than TCP, UDP and ICMP, which a rule of its own logs as `tvgw-proto` at most 6 times a minute (every such packet reaches the rule, and an unlimited log could flood the journal ingest reads its samples from). It keeps small pings and drops other ICMP, and rejects DoT and DoQ ports, QUIC when `BLOCK_QUIC=yes` ([design decision 3](../design-decisions.md#3-no-tls-interception)), known DoH resolvers (`doh4`) and manual IP blocks (`block4`). With `ADTECH_PORT_WALL=yes` and the `lg-webos` profile it resets TCP connections to LG's ad-tech ports (4001, 4431, 4445, 4447, 8180, 8883), counted as `LG adtech port` and sampled as `tvgw-adport` lines, a detector for an attempt DNS missed ([design decision 45](../design-decisions.md#45-the-acr-red-line-is-an-upload-test-and-a-port-wall)). It accepts and logs LG's firmware fallback to `156.147.69.32:8080`, and logs other ports; with `STRICT_PORTS=yes` it also rejects them ([STRICT_PORTS](../use/blocking.md#strict_ports)). It accepts the rest.
10. **`inet tvgw_gate`**'s forward chain runs after the filter. It counts each new connection to an address outside `resolved4` and logs a sample, at most 6 a minute. `tvgw-dnsgate` adds each address the resolver hands the TV with a one-day timeout and the same expiry, so on kernel 6.12 and later an address answered again starts its day again ([design decision 43](../design-decisions.md#43-the-flow-log-hears-the-tv-alone-and-the-gates-day-starts-at-each-answer)). conntrack calls every packet of a flow new until a reply comes, so the dynamic set `seen4` holds each flow's tuple for two minutes and the rule counts a tuple only when it is not there yet: a retransmitted SYN to a server that is down is one connection. It never drops.
11. **`post_nat`** masquerades the TV subnet out of the uplink.

The `output` chain also stops the gateway's own broadcast and multicast chatter into the TV subnet, DHCP excepted. The guard's `output` chain lets only root open the TV's LAN API (TCP 3000 and 3001).

<picture>
  <source media="(prefers-color-scheme: dark)" srcset="../diagrams/fig-4-packet-path.dark.png">
  <img alt="Where a packet from the TV can end. Before routing, the wire table drops IPv6, ct_events marks the TV's new connections for the flow log, and pre_nat sends DNS for anywhere to the gateway. Routing, rule 60, sends it to the gateway or onward. For the gateway, the input chain accepts DNS, DHCP, nginx and pings and drops the rest, and what it accepts passes the guard on its way to the gateway's services. Onward, only while the forwarding switch is on, the forward and tv_out chains drop invalid and off-subnet packets, the home LAN, DoT, DoQ, QUIC, known DoH and LG's ad-tech ports, and the gate counts but never drops; then the guard, which keeps the gateway and the home LAN closed whether or not the firewall is loaded, and post_nat, which masquerades the packet out to the home router." src="../diagrams/fig-4-packet-path.light.png" width="960">
</picture>

*A TV packet ends at the gateway's own services, out at the home router only while the forwarding switch is on, or at one of the drops; the guard after the firewall refuses nothing the firewall lets through, and the numbered list above gives the order of every chain.*

### The fail-closed gate

`tvgw-apply` takes `/run/lock/tvgw-apply.lock`, so one apply runs at a time, and refuses a switch setting that is not exactly one of its values. It then sets the conntrack sysctls (accounting, timestamps, `nf_conntrack_tcp_timeout_established=7440`), lists every counter of the three tables, and loads `inet tvgw` in one `nft` transaction; under `set -e`, a rejected ruleset stops the script there. Once that table, which holds the `ct_events` chain, is in, it sets `nf_conntrack_events=0`, so that only the TV's connections make conntrack events for the flow log ([design decision 43](../design-decisions.md#43-the-flow-log-hears-the-tv-alone-and-the-gates-day-starts-at-each-answer)); the same switches are in `/etc/sysctl.d/60-tvgw.conf` ([the kernel switches](../../deploy/sysctl/README.md)). Then it loads `netdev tvgw_l2` and `inet tvgw_gate`, each of which only warns when it fails, lists the counters again and publishes both listings together (`/run/tvgw/counters.before-apply` and `counters.after-apply`, which the next `tvgw verify --record` stores, so the brief sees the reset). Only then does it turn forwarding on, globally, for `eth0` and for the uplink once the uplink exists (in vpn mode the tunnel appears after the boot apply, and the dispatcher re-runs the script when it does), write the applied ruleset to `/run/tvgw/ruleset.applied` and the settings it used to `/run/tvgw/settings.applied` for `tvgw verify`, and add rule 60 and table 100's two routes. Between the switch and rule 60, the TV's traffic follows the main table, and `tv_out` drops whatever does not leave by the uplink.

Stopping `tvgw.service` turns `eth0`'s forwarding off first, then deletes rule 60, `netdev tvgw_l2` and `inet tvgw`; `inet tvgw_gate` stays. A stopped or half-applied gateway leaves the TV dark, never unfiltered ([design decision 5](../design-decisions.md#5-fail-closed)). While the service is stopped its `input` chain is gone too, and the guard holds the gateway closed in its place.

### The guard

`inet tvgw_guard` is loaded at boot by `tvgw-guard.service`, before NetworkManager brings `eth0` up, and nothing deletes it: the unit has no stop path and refuses a manual stop ([design decision 42](../design-decisions.md#42-the-pi-is-closed-to-the-tv-whatever-nftables-holds)). Its chains hook input, forward and output at priority `filter + 10`, after `inet tvgw`. A drop in any base chain is final and an accept is not, so the guard can only narrow what `inet tvgw` allows. From the TV side it lets through DHCP, DNS, nginx's 80 and 443 and rate-limited pings to `10.10.10.1`, the same as `inet tvgw`'s input chain, and drops the rest; in forward it drops what would leave toward the home LAN if `inet tvgw` went with forwarding still on. While `inet tvgw` is loaded the guard's last counter stays still, and `tvgw verify` warns when it moves ([the guard, rule by rule](../../deploy/nftables/README.md#the-guard)).

Linux owns an address for the whole host, not for one interface, so binding a service to the gateway's LAN address does not keep the TV out: `ip daddr != 10.10.10.1 drop` does, in both tables. The gateway's other services get a second wall that holds even with every nftables table gone: systemd's `IPAddressDeny=10.10.10.0/24`, a cgroup filter written as a drop-in for each unit `CO_TENANT_UNITS` names ([the settings file](../reference/settings.md)). dnsmasq, which parses the TV's DHCP, runs without `CAP_NET_ADMIN`, the capability that could rewrite the firewall ([DHCP for the TV](../../deploy/dnsmasq/README.md#the-hardening-drop-in)).

<picture>
  <source media="(prefers-color-scheme: dark)" srcset="../diagrams/fig-17-two-walls.dark.png">
  <img alt="Two walls stand between the TV and the gateway. Wall 1 is the guard, inet tvgw_guard, loaded before the network and never unloaded: its input chain lets DHCP, DNS, nginx's 80 and 443 and pings reach the gateway address and drops the rest of the gateway, its forward chain lets nothing through to the home LAN, and its output chain lets only root open the TV's API. Behind it, dnsmasq runs without CAP_NET_ADMIN and CAP_NET_RAW and nginx in a sandbox; each co-tenant service the settings name (CO_TENANT_UNITS) carries wall 2, IPAddressDeny for the TV subnet, so a port of one of those services is dropped by both walls." src="../diagrams/fig-17-two-walls.light.png" width="960">
</picture>

*The TV reaches the gateway's DHCP, DNS and URL filter and nothing else on the gateway, whatever the firewall holds.*

### Uplink modes

`UPLINK=direct`, the mode in use, sends the TV out of `WAN_IF` through table 100. `UPLINK=vpn` exists and is not used ([design decision 1](../design-decisions.md#1-the-tv-uses-the-direct-uplink-not-the-vpn)): it sends the TV out of the tunnel `VPN_IF` names or finds (`auto`: `tun0`, PIA's OpenVPN, else `wgpia0`, its WireGuard; `tun0` before either exists), clamps the TCP MSS to the route's MTU, adds no rule 60 and clears no mark. In that mode `tv_out` drops the TV's traffic whenever the tunnel is down.

### The VPN boundary

The VPN client protects only the gateway's own traffic. PIA's kill switch filters the gateway's output and nothing it forwards, and rule 60 routes the TV before PIA's forwarded-packet rule can, so in direct mode the TV's data path never depends on the tunnel ([design decision 1](../design-decisions.md#1-the-tv-uses-the-direct-uplink-not-the-vpn)). What does depend on it is the gateway's own traffic: AdGuard Home's DoH upstreams, nginx's fetches for the URL filter, the analyst's API calls. The `post_leaks` chain counts, and never drops, the gateway's new connections to a DoH resolver on TCP 443 and to port 53 that leave by `WAN_IF` instead, and the brief raises a red line when they rise, with PIA's state from `piactl` beside it on the Coverage line ([design decision 44](../design-decisions.md#44-the-tunnel-is-a-setting-and-the-pis-own-leaks-are-counted)). With `VPN_IF=none` the chain counts nothing and the red line is off. The input chain drops every new connection from `tun0` and `wgpia0` whatever `VPN_IF` says, and from a third tunnel it names.

## The control plane

Policy lives in files, and three commands turn them into running configuration ([design decision 6](../design-decisions.md#6-adguard-home-is-configured-as-code)):

| File | Where | Read by |
|---|---|---|
| `lg-webos.toml`, `lg-webos.rules` | The profile, in the installed package ([the profile format](../reference/profile-format.md)) | `tvgw adguard apply` |
| `local.rules` | The owner's site rules, `LOCAL_RULES`, written by `tvgw allow` and `tvgw block` ([your own rules](../use/blocking.md#your-own-rules), [design decision 59](../design-decisions.md#59-site-rules-etctvgwlocalrules-written-by-tvgw-allow-and-tvgw-block-applied-after-the-profile-and-before-machine-rules-under-the-same-lint)) | `tvgw adguard apply` |
| `auto.rules` | The machine's rules file, `AUTO_RULES` ([the machine's rules file](analyst-and-autonomy.md#the-machines-rules-file)) | `tvgw adguard apply` |
| `tvgw.conf` | The site settings ([the settings file](../reference/settings.md)) | `tvgw adguard apply`, `tvgw-apply`, `install.sh` |
| `block4.txt` | Manual IP blocks | `tvgw-apply` |
| `doh4.txt` | DoH resolver addresses, written by `tvgw-doh-update` | `tvgw-apply` |

`tvgw-apply` loads the firewall, the sysctls and the policy routing. `tvgw adguard apply` writes `AdGuardHome.yaml`. `install.sh` writes the dnsmasq and nginx files from their templates and installs the units, then runs the other two. How a commit reaches the gateway through `make deploy` or CI is in [how a change reaches the gateway](../../deploy/README.md#how-a-change-reaches-the-gateway).

| Command | Triggered by |
|---|---|
| `tvgw-apply` | `tvgw.service` at boot; the NetworkManager dispatcher when `WAN_IF`, `eth0` or the tunnel comes up (the one `VPN_IF` names; with the default `auto`, `tun0` or `wgpia0`; none with `VPN_IF=none`) or renews its address, since table 100's route vanishes with the uplink; `tvgw-doh-update` after a new list; `install.sh`, in place when the service is already up; by hand after a firewall setting changes |
| `tvgw adguard apply` | `install.sh`; by hand; `tvgw allow`, `tvgw block`, `tvgw unallow` and `tvgw unblock` after they change `local.rules` (through `analyst.adguardcfg_apply`) |
| `tvgw adguard service`, which writes AdGuard's `--no-check-update` drop-in | `install.sh`, before `tvgw adguard apply`; by hand |
| `tvgw adguard upgrade NEWBIN`, the one way AdGuard's binary changes | By hand ([upgrading AdGuard Home](adguard.md#upgrading-adguard-home)) |
| `adguardcfg.apply()`, the same apply without the profile lint | `tvgw analyst` after it appends a machine rule and after a canary revert; `tvgw autoblock check` after a revert; `tvgw undo` (all through `analyst.adguardcfg_apply`) |
| `install.sh` | `make deploy PI=<ssh-host>` and the CI deploy |

### How tvgw adguard apply works

1. **Lint.** The profile must pass its own lint, or nothing is planned ([design decision 7](../design-decisions.md#7-must-allow-exceptions-are-generated-from-the-toml)).
2. **Desired state.** `adguardcfg.desired` takes the profile's lists and builds the custom rules: an `@@||host^$important` exception per must-allow host, the URL filter's `$dnsrewrite` rules to `GW_IP`, one rule withholding the profile's `strip_qtypes` records (HTTPS and SVCB) from `TV_IP`, then the `.rules` file. The owner's site rules follow (`localrules.admissible`, design decision 59), then the machine's (`autoblock.admissible`), each only if it passes the lint beside the profile; one that fails is left out with a message, and a rule an earlier group holds is not repeated (`adguardcfg.rule_groups`). With no `LOCAL_RULES` file the site group is empty and the plan is the one before the file existed. An unreadable `LOCAL_RULES` file stops the apply: a plan without the owner's allows would block again what the owner let through. The upstreams, the bootstrap servers and the TV as a named client come from the settings.
3. **Lock.** The apply takes `.tvgw-adguard.lock` beside the YAML without waiting; a second apply fails at once.
4. **Plan.** It refuses a YAML with no `schema_version`, which means an empty or truncated file, and one above schema 34 (`SCHEMA_CEILING`), which a newer AdGuard Home than this release knows wrote. Then `plan` sets only the keys tvgw owns on a copy of AdGuard's current YAML, and `changes` lists the differences. With none, nothing happens and AdGuard is not restarted.
5. **Restart guard.** Before anything is staged, it asks the resolver for a made-up name under a must-allow name, which no cache can answer. SERVFAIL, or silence past AdGuard's own upstream timeout while AdGuard still answers a name the profile blocks, defers the apply (`deferred: upstream down`, exit 3) with nothing changed, because a restart would empty the cache the TV lives on while the upstreams are down ([the restart guard](adguard.md#the-restart-guard)).
6. **Check.** The candidate is written beside the live file and passed to `AdGuardHome --check-config`, which has 120 seconds. A rejection changes nothing. When the binary is missing, the apply goes on and says the file was not validated.
7. **Backup.** The live file is copied to `AdGuardHome.yaml.bak-<stamp>Z-<pid>` (UTC), never over an earlier copy, before AdGuard is stopped.
8. **Swap.** With SIGTERM, SIGHUP and SIGINT held off, the apply stops AdGuard, renames the candidate over the live file, syncs the directory and starts AdGuard.
9. **Readiness.** It waits up to 30 seconds for the resolver to answer the profile's first must-allow name (`us.lgtvsdp.com` in `lg-webos`, the clock host) with NOERROR or NXDOMAIN; the analyst's, the hourly judge's and `tvgw undo`'s applies probe `example.com`, the default of `adguardcfg.dns_ready`. SERVFAIL or REFUSED means not ready, so an apply while the DoH upstreams are unreachable rolls back.
10. **Rollback.** Any failure from the stop on puts the backup back the same atomic way and starts AdGuard, and the command fails saying which file is live.

`tvgw adguard diff` prints the same differences and writes nothing; when the custom rules differ it also lists them by source (the profile, the site rules, the machine's), each group with the file it comes from. The analyst, the hourly judge and `tvgw undo` call `adguardcfg.apply()` directly through `analyst.adguardcfg_apply`: steps 2 to 10 run, step 1 does not, and the machine's rules are still linted one by one in step 2.

<picture>
  <source media="(prefers-color-scheme: dark)" srcset="../diagrams/fig-5-policy-files.dark.png">
  <img alt="Seven files hold policy: the profile and its rules file and block4.txt, edited by the owner; local.rules, the owner's site rules, written by tvgw allow and tvgw block; auto.rules, written by the machine; tvgw.conf, the site settings; and doh4.txt, fetched. tvgw adguard apply turns the profile, the rules file, local.rules and auto.rules, in that order, into AdGuard Home's configuration, and tvgw-apply turns block4.txt and doh4.txt into the firewall; both read tvgw.conf." src="../diagrams/fig-5-policy-files.light.png" width="960">
</picture>

*Policy lives in files, and two commands turn it into running configuration; the owner's commands write local.rules, and the machine writes only auto.rules.*

## From capture to block

Evidence moves through the gateway in stages, each written down before the next reads it:

- **Capture.** `dumpcap` keeps the frames the TV sends that the analysis needs, one pcap per clock hour ([what the capture keeps](privacy-and-retention.md#what-the-capture-keeps)).
- **Connections.** `conntrack` writes one line per finished TV connection to `flows.log`, with packets and bytes each way. The kernel sends it only the TV's connections, which the firewall's `ct_events` chain marks. When its netlink socket overflows it drops events and says so only in `tvgw-flowlog`'s journal (`We have hit ENOBUFS!`), which ingest reads and turns into a warning; the kernel counts the same loss in the socket's `Drops` column of `/proc/net/netlink`, which `tvgw verify --record` stores and ingest also warns about.
- **Lookups.** AdGuard Home logs every query with the rule that matched to `querylog.json`, in batches: it appends to the file once `querylog.size_memory` lookups have built up, 10 since `tvgw adguard apply` owns the key (`log_buffer` in `adguardcfg.Desired`).
- **The URL filter.** nginx logs each request to the file-service names to `gfts.log`.
- **The kernel log.** The unexpected-port rule logs `tvgw-oddport` lines, the adtech port wall `tvgw-adport` lines and the DNS gate `tvgw-gate` lines, at most 6 a minute each, to the journal.
- **The TV's own report.** For the `lg-webos` profile, `tvgw-analyze` runs `tvgw tvcheck` every hour over the TV's read-only LAN API ([design decision 4](../design-decisions.md#4-no-rooting-of-the-tv)) and keeps `tvcheck.txt` and `tvcheck-history.log`. The reading includes the TV's consent record (`eula.<flag>`), whose flags turning on are a red line.
- **The firewall's record.** `tvgw verify --record` stores its verdict and every firewall counter in the store itself ([design decision 13](../design-decisions.md#13-counters-not-logs-prove-the-firewall-held); the checks are in [what tvgw verify checks](../reference/verify-checks.md)), with the VPN boundary it saw: `VPN_IF`, the tunnel it resolved to and PIA's state.
- **The change ledger.** With `LEDGER=on`, the default, `tvgw verify --record` also stores a sample of the gateway's own counters in `gw_samples`, and `tvgw-apply`, the NetworkManager dispatcher and `install.sh` each append one line per change to `/var/lib/tvgw/changes.spool`. The hourly ingest loads the spool once and derives the change ledger, `changes`, from it and the samples; the brief's "Changes in effect" and the hour classifier read it ([design decision 48](../design-decisions.md#48-one-ledger-of-changes-one-hour-classifier-and-a-second-judge-that-only-watches)).
- **The store.** `tvgw ingest` reads every other source into `tvgw.db` each hour, pcaps through a sandboxed tshark, and stores kernel log lines without the gateway's host name and with `MAC=` emptied ([how rows arrive](../reference/data-model.md#how-rows-arrive)).
- **Reports.** `tvgw-analyze` writes the latest, daily and weekly reports from the store with `tvgw report`; `tvgw brief` computes the same from the store by hand ([sections](../reference/brief-sections.md#sections)).
- **The upload budget.** (budget) The ingest's `budget` step sets the upload budget's ceiling once, from the 14 whole days before it that the record and the capture cover, and keeps it in the store's `meta` with how it was derived; it never computes it again. Every report counts what the TV sent each destination outside the profile's expected categories in each hour, beyond what came back on each connection, against it, and lists the hours over it. Nothing is capped, and no rule in the firewall reads it ([the upload budget](../reference/brief-sections.md#upload-budget), [design decision 66](../design-decisions.md#66-an-upload-budget-with-a-ceiling-set-once-count-only-and-the-names-of-a-tv-that-goes-online-while-off)).
- **The analyst.** `tvgw analyst` reads the store read-only, builds a minimized evidence pack and writes proposals ([the analyst and autonomous blocking](analyst-and-autonomy.md)).
- **An autonomous block.** With `ANALYST_APPLY=auto`, a block that passes [the gates](analyst-and-autonomy.md#the-gates) and a second model goes into `auto.rules` and to AdGuard Home (`adguardcfg.apply()`), the live canary watches it for 10 minutes (at once, or armed until the TV is next watched), and `tvgw autoblock check` judges it against the store every hour for at least a day, one rule at a time; a block that clears the gates during another's trial waits in `auto_queue`. Every gate decision, apply, canary outcome and verdict is a row in the append-only `decisions` table ([design decisions 20](../design-decisions.md#20-the-gateway-blocks-on-its-own-under-three-watches) and [41](../design-decisions.md#41-the-autonomy-refuses-what-it-cannot-see-and-keeps-what-it-decided)). After the shipped judge has decided, the hourly check runs judge v2 in shadow and records both verdicts in `judge_shadow`; nothing reads them to decide ([design decision 48](../design-decisions.md#48-one-ledger-of-changes-one-hour-classifier-and-a-second-judge-that-only-watches)).

<picture>
  <source media="(prefers-color-scheme: dark)" srcset="../diagrams/fig-6-capture-to-store.dark.png">
  <img alt="Six recorders write down what the TV does: dumpcap to pcap files, conntrack to flows.log, AdGuard Home to querylog.json, nginx to gfts.log, the firewall's log rules (oddport, adport and gate samples) to the journal, and tvgw tvcheck to its history log. tvgw-apply, the NetworkManager dispatcher and install.sh each append a line to the change spool. tvgw ingest reads them all into the store every hour; tvgw verify --record writes its verdict, the firewall counters and a gateway sample (gw_samples) to the store itself every 10 minutes." src="../diagrams/fig-6-capture-to-store.light.png" width="960">
</picture>

*Every source reaches the store through tvgw ingest, the change spool included, except what tvgw verify writes itself: the firewall's verdict and counters and the gateway's own samples.*

<picture>
  <source media="(prefers-color-scheme: dark)" srcset="../diagrams/fig-3-judgement.dark.png">
  <img alt="The store feeds a daily analyst, which asks Claude only when something is new; a second model tries to refute each proposal, and a block both agree on becomes a machine rule on probation in AdGuard Home. An hourly judge reverts a rule that hurt streaming, the owner reads the brief and can undo any rule, and the verifier only records verdicts and counters." src="../diagrams/fig-3-judgement.light.png" width="960">
</picture>

*Every report and every machine rule is computed from the store, never from live logs: three actors may change the machine's rules, and the verifier only records.*

## Naming a connection

A CDN address serves many names, so the destination address alone says little. tvgw names each flow by its own TLS hello ([design decision 12](../design-decisions.md#12-each-flow-is-named-by-its-own-tls-hello)). `FLOW_NAME` in `src/tvgw/queries.py` takes the `tls` row with the flow's `dst`, `dport` and TV source port `sport` whose time falls between the flow's `t_start` less `FLOW_SLACK = 300` seconds and its `t_end`; when several match, the latest wins. The index `tls_conn` on `tls(dst, sport, t)` makes this one index seek per flow. A flow with no hello of its own that starts within `FLOW_SLACK` of the end of an earlier flow on the same tuple is a continuation (conntrack lost the entry mid-connection and opened a new one) and takes that flow's name, one hop back ([design decision 21](../design-decisions.md#21-a-continuation-inherits-its-name)).

The slack exists because the code takes conntrack's start time to run up to a minute late. `t_end` is when the kernel expired the entry, one idle timeout after the last packet: 120 seconds in `TIME_WAIT`, 7440 s (2 h 04 min) for an established connection that went quiet, which `tvgw-apply` sets, and 30 or 120 seconds for UDP, plus up to about a minute of garbage-collector lag (`src/tvgw/conntrack.py`). An entry the kernel destroyed before its timer ran out (a reused tuple, a flush) ends when it was destroyed, and the seconds it had left are in `flows.timeout_left`. What this premise gets wrong is in [known limits](../reference/data-model.md#known-limits).

Names are computed when a report runs, never stored. A flow whose pcap is not ingested yet has no name until the next ingest, and a later report names it. A flow without a captured hello (UDP, plain HTTP, a missed packet) stays unnamed: By category counts it as `Unresolved`, and Top upload lists it by address.

## Cadences

Each job runs as often as its evidence changes and no more. The exact schedules and timeouts are in [units](../../deploy/systemd/README.md#units).

| Job | Cadence | Why that often |
|---|---|---|
| Capture, flows, DNS, URL filter, kernel log | Continuous | Evidence is written as it happens |
| `tvgw verify --record` | Every 10 minutes | Counters reset on every apply. The brief sums the positive steps between snapshots, and `tvgw-apply`'s listings either side of each reload are stored as snapshots of their own, so a reset costs nothing unless a second apply follows within the same interval ([design decision 13](../design-decisions.md#13-counters-not-logs-prove-the-firewall-held)). A window's first step is taken from the last snapshot in the hour before it (`FW_BASELINE = 3600` in `src/tvgw/queries.py`), so days nobody recorded are not credited to it. A failed check shows within 10 minutes |
| `tvgw-analyze` | Hourly | The pcaps and the TV readings are hourly, and an incremental ingest stays small |
| `tvgw prune-pcaps` | Hourly | It keeps the pcap directory within its limits, deleting only files the store has read |
| `tvgw autoblock check` | Hourly, after the ingest | The hourly judge needs the store the ingest has refreshed |
| `tvgw backup` | Daily, after the daily report | One checked copy a day |
| `tvgw analyst` | Daily, after the daily report and the backup; set by `ANALYST_SCHEDULE` | It reads a finished day, once its evidence has settled |
| `tvgw analyst --weekly` | Weekly, after the daily pass | It reads the ISO week that ended most recently |
| `tvgw-doh-update` | Daily, with a random delay of up to 1 hour | `tvgw verify` calls the list stale after 8 days |
| `tvgw-apply` from the dispatcher | When a link comes up | Table 100's route vanishes when the uplink drops |

The figure below is generated from the timer files themselves, so it shows their defaults ([units](../../deploy/systemd/README.md#units)); `ANALYST_SCHEDULE` and `ANALYST_WEEKLY_SCHEDULE` move the analyst's two passes, and the day's report comes at the first hourly run once the day has settled, 03:20.

<picture>
  <source media="(prefers-color-scheme: dark)" srcset="../diagrams/fig-23-day.dark.png">
  <img alt="One day of the gateway on a clock from 00:00 to 24:00. It records what the TV does all the time. It checks itself every 10 minutes, files the hour's record every hour at 20 minutes past, and rechecks the blocks it added every hour at 25 past. Once a day, at a random time in the first hour, it updates its DNS server list. Overnight it writes the day before's report at 03:20, backs up its record at 03:40 and asks the analyst at 03:50 if it has a key, and on Mondays at 04:10 it asks about the week." src="../diagrams/fig-23-day.light.png" width="960">
</picture>

*The gateway works on a clock: it records all the time, checks itself every 10 minutes, files its record every hour, and does its daily work overnight.*

Evidence reaches the store late, and by different amounts:

| Evidence | Reaches the store | Why |
|---|---|---|
| URL-filter requests, kernel log lines | At the next hourly ingest | They are logged as they happen |
| Lookups | Once AdGuard has written them, then the next hourly ingest | AdGuard Home appends to `querylog.json` only when `querylog.size_memory` lookups (10, set by `tvgw adguard apply`, every client together) have built up, or when it stops. That is a write every few minutes while an app runs, so on a quiet night the TV's last few lookups can land after 03:20 and miss the day's file and the analyst's pack; they are in the store and the weekly file |
| Flows | One idle timeout after the last packet, then the next ingest | conntrack reports a connection when it expires: 7440 s (2 h 04 min) after an established connection went quiet |
| TLS hellos, plain HTTP, LAN probes | Once the hour's pcap is finished, then the next ingest | `dumpcap` starts a new file on every exact hour of the clock, so an hour's pcap closes when the hour ends |
| TV state | Every hour, before the ingest | `tvgw-analyze` reads the TV and then ingests |
| Firewall verdicts and counters | Every 10 minutes | `tvgw verify --record` writes them itself |

Because flows and pcaps land late, `tvgw-analyze` writes a finished day or week once, at the first hourly run at least `SETTLE=10800` seconds (3 hours, in `deploy/bin/tvgw-analyze`) after it ends. `tvgw brief <day>` recomputes from the store at any time.

## Trust boundaries

The TV is untrusted. It reaches DHCP, DNS, ports 80 and 443 and pings on `10.10.10.1`, nothing else on the gateway, and nothing on the home LAN: `inet tvgw` holds that line while it is loaded, and `inet tvgw_guard` holds the same line at all times. The gateway's other services also refuse the TV subnet by their own cgroup filter. Text that came from the TV or the servers it talks to (names, URIs, user agents, the TV's device name) is escaped before it reaches a terminal (`cli.clean`, `lgwebos.clean`). File owners and modes are in [where it lives and who can read it](privacy-and-retention.md#where-it-lives-and-who-can-read-it).

| Component | Runs as | Can touch |
|---|---|---|
| `tvgw-apply` (`tvgw.service`, the dispatcher, `tvgw-doh-update`, `install.sh`) | root | The firewall, the sysctls and the routes |
| `tvgw-guard.service` | root | Loads `inet tvgw_guard` from `/etc/tvgw/guard.nft`; never deletes it |
| `tvgw-doh-update` | root | Fetches the DoH list over HTTPS only, at most `8000000` bytes; refuses fewer than 50 entries, and more than 50,000 entries or 4,000,000 addresses; writes `doh4.txt` |
| `dumpcap` (`tvgw-pcap`, `tvgw-pcap-headers`) | The system user `tvgw-pcap`, group `nogroup`, with `CAP_NET_RAW` and `CAP_NET_ADMIN` only; read-only system | The TV's frames, into the pcap directory, its only writable path |
| `conntrack` (`tvgw-flowlog`) | root | Connection events for `TV_IP`, appended to `flows.log` |
| `tvgw-dnsgate` | root, bounded to `CAP_NET_RAW` and `CAP_NET_ADMIN`; read-only system; 128 MB of memory | The resolver's answers to the TV, and the set `inet tvgw_gate resolved4`; writes no file |
| `tvgw-analyze` | root; no new privileges; read-only system but the state, log and lock directories | Reads every log and the TV's LAN API; writes the store, the TV history and the reports |
| tshark | `nobody:nogroup` in a transient `systemd-run` unit with the properties in `tshark.HARDENING`: no network, read-only system, no devices, no capabilities, no namespaces, the service system calls, no core dumps, 64 tasks, 512 MB and a time limit ([the sandbox](extractor.md#the-sandbox)) | One pcap, read-only. As root without `systemd-run`, ingest refuses to run it |
| `tvgw verify --record` | root | Reads the firewall, the routes, the resolver and the gateway's own counters, and runs `piactl` read-only; writes `verify`, `fw_counters`, `gw_samples` and `meta` |
| `tvgw-analyst`, `tvgw-analyst-weekly` | root; no new privileges; read-only system but the state directory and `/opt/AdGuardHome` | Read the store and the API key; reach Anthropic's API and the TV; write proposals, the machine's rules file, the store and, with `ANALYST_APPLY=auto`, AdGuard's config |
| `tvgw-autoblock` | The same sandbox | Reads the store; writes the machine's rules file, the store and, on a revert, AdGuard's config |
| `tvgw-backup` | root; read-only system but the state directory | Copies the store |
| `tvgw prune-pcaps` (`tvgw-prune`) | root | Deletes pcaps the store has read |
| `tvgw adguard apply` | root | Stops and starts AdGuard Home and rewrites its YAML |
| The read-only commands (`brief`, `report`, `host`, `sql`) | Any member of `adm` | Open the store `mode=ro`; `sql` also sets `query_only` |
| dnsmasq | Its package's unit, as the `dnsmasq` user after start; bounded without `CAP_NET_ADMIN` and `CAP_NET_RAW`, read-only system, DHCP addresses only | Gives the TV its lease; tvgw writes its configuration and the hardening drop-in, which `install.sh` takes out again if dnsmasq will not serve with it |
| nginx | Its package's unit, workers as `www-data`; read-only system but its logs and state, no new privileges, the service system calls | The URL filter and the passthrough; tvgw writes its configuration and a drop-in with the restart and the sandbox |
| AdGuard Home | Its own unit, with `--no-check-update` | tvgw writes its configuration, a working-directory drop-in and the `--no-check-update` drop-in |
| The co-tenants (`CO_TENANT_UNITS`: Samba, xrdp, shairport-sync, avahi, sshd, JupyterHub and the like) | Their own units | Nothing of tvgw's; each carries `IPAddressDeny=10.10.10.0/24` with `IPAddressAllow=10.10.10.1/32`, so it can neither be reached from the TV subnet nor send to it, the gateway's own address there excepted |
