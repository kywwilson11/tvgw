# The firewall

`tvgw-apply` builds the TV's firewall and routing from `/etc/tvgw/tvgw.conf`. It is the one script that decides what the TV can reach. It runs at boot (`tvgw.service`), when a link changes (the NetworkManager dispatcher), after the daily DoH list refresh, from `install.sh`, and by hand with `sudo tvgw-apply`.

## Files

| File | What it is | Lives on the Pi as |
|---|---|---|
| `tvgw-apply` | The ruleset, sysctls and policy routing, as one fail-closed script. With `DNSGATE=count` it also keeps the table `inet tvgw_gate`: the set `resolved4` (addresses the TV's lookups returned, fed by `tvgw-dnsgate`, one-day timeout) and one rule that counts and samples new connections to any other address. That table is created with `add` so re-applies keep the set, and lives apart from `inet tvgw` so `tvgw verify`'s baseline stays static. | `/usr/local/sbin/tvgw-apply` |
| `block4.txt` | A template for manual IPv4 blocks: one address or CIDR per line, `#` comments. | `/etc/tvgw/block4.txt` (installed only if missing; edit that copy) |
| `doh-exclude.txt` | CloudFront and Cloudflare CIDRs, about 230 lines, that are never put in the DoH block set because they also serve ordinary sites. | `/etc/tvgw/doh-exclude.txt` (overwritten on every install) |

The DoH block set itself comes from `/var/lib/tvgw/doh4.txt`, which [`tvgw-doh-update`](../bin/README.md) writes daily.

## Order of operations

1. Take the lock `/run/lock/tvgw-apply.lock`, so two applies never interleave.
2. Load `nf_conntrack` and turn on per-connection byte counts and timestamps (the flow log needs both). Set the established-TCP timeout to 7440 s (2 h 04 min), so idle connections are reported within hours instead of five days. Disable IPv6 on `eth0`.
3. List every counter of the three tables to `/run/tvgw/counters.before-apply.tmp`. Load table `inet tvgw` in one `nft -f` transaction: the old table is deleted and the new one created together. If the file fails to load, nothing changes and the script stops.
4. Load table `netdev tvgw_l2`. A failure here only prints a warning, because it fails when `eth0` is down. Then the DNS gate's table, and the counters again: both listings are renamed into place together.
5. Switch forwarding on: `net.ipv4.ip_forward`, and the per-interface switch for `eth0` and for the uplink. This comes last so the TV is never forwarded without the filter. The per-interface switches are written explicitly because the global write only propagates when its value changes ([../../docs/incidents.md](../../docs/incidents.md)).
6. Write `/run/tvgw/ruleset.applied`, the listing `tvgw verify` compares against.
7. Policy routing. Delete `ip rule` priority 60. In direct mode, add it back (`from 10.10.10.0/24 lookup 100`) and set table 100's default route via `WAN_GW` on `WAN_IF`. If the uplink is down that route fails with a message; the dispatcher adds it when the link comes up.

## The ruleset, chain by chain

`pre_mangle` hooks in just after the mangle priority. The other chains hook in 10 before their standard priority, so they run ahead of other chains at the same hook, such as the VPN client's.

**Sets.** `lan4` holds the private, CGNAT (`100.64.0.0/10`) and link-local (`169.254.0.0/16`) ranges. `doh4` and `block4` are filled from the files above.

**`pre_mangle`** (prerouting, `mangle + 10`). Direct mode only: clear the packet mark on everything from `eth0` (`undo PIA routed-packet tag`). The VPN client marks forwarded packets to route them into the tunnel; clearing the mark lets table 100 send them out the uplink.

**`pre_nat`** (prerouting, `dstnat - 10`). DNS from the TV, UDP or TCP, aimed at any address but the gateway is rewritten to `10.10.10.1:53` (`TV DNS aimed elsewhere -> AdGuard`). This runs before the VPN client's NAT chain, which would otherwise send TV DNS to the VPN's resolver. DNS sent to the gateway is counted separately, so the brief can show bypass attempts.

**`input`** (input, `filter - 10`). What may reach the Pi itself.

| Rule | Why |
|---|---|
| New connections from `tun0`: drop | Nothing unsolicited from the VPN side. |
| Anything not from `eth0`: accept | This table only polices the TV side. |
| Established, related: accept | Replies. |
| DHCP (UDP 68 to 67): accept | DHCP requests go to the broadcast address, which the next rule would drop. |
| Not to `10.10.10.1`: drop | The TV talks to the gateway address only. |
| DNS (53): accept | AdGuard Home. |
| TCP 80 and 443: accept | The nginx URL filter and TLS passthrough. |
| Ping, up to 5 a second: accept | Reachability checks. |
| Everything else: drop | The TV may not reach other Pi services. |

**`forward`** (forward, `filter - 10`).

| Rule | Why |
|---|---|
| Neither side is `eth0`: accept | Not TV traffic; left to the rest of the system. |
| Invalid conntrack state: drop | An invalid packet would leave without NAT and leak the TV's address. |
| From `eth0` with a source outside `10.10.10.0/24`: drop | Masquerade covers only the TV subnet, and the capture, the flow log and the gate all key on its addresses, so such a packet would leave un-NATed and unrecorded. |
| vpn mode: clamp TCP MSS to the route MTU on `tun0` | The tunnel's MTU is smaller. |
| Established, related: accept | Replies, and connections that were allowed when they started. |
| From `eth0`: jump to `tv_out` | The TV's new connections. |
| Everything else: drop | Nothing else into or out of the TV subnet. Devices on the home network cannot open connections to the TV. |

**`tv_out`**, the TV's new outbound connections, in order:

| Rule | Why |
|---|---|
| Not leaving by the chosen uplink: drop | `WAN_IF` in direct mode, `tun0` in vpn mode. In vpn mode this is what drops TV traffic while the tunnel is down. |
| To `lan4`: drop | The TV may not reach the home LAN. |
| Not TCP, UDP or ICMP: log `tvgw-proto:` and drop | No GRE, ESP or 6in4 tunnels. |
| Ping of at most 128 bytes, 2 a second: accept | Small pings only. |
| Other ICMP: drop | No ICMP tunnels. |
| TCP or UDP to 784, 853, 8853: reject | DoT and DoQ. Reject, not drop, so the TV falls back at once. |
| UDP 443: reject (when `BLOCK_QUIC=yes`) | QUIC. Apps fall back to TCP and TLS, and the server name stays visible. |
| TCP 443 to `doh4`: reject with TCP reset | Known DoH resolvers. |
| To `block4`: reject | Manual IP blocks for endpoints reached by hardcoded address. |
| `156.147.69.32` TCP 8080: log `tvgw-lg8080:` and accept | LG's hardcoded firmware-update fallback. Allowed so updates work, logged so we see it. |
| Ports other than 80, 123, 443: log `tvgw-oddport:` (6 a minute) | Evidence for the brief's "Unexpected ports". |
| Same ports: count and accept, or reject with `admin-prohibited` when `STRICT_PORTS=yes` | See [../../docs/operations.md](../../docs/operations.md#strict_ports). |
| Everything else: accept | |

**`output`** (output, `filter - 10`). The Pi's own broadcast and multicast UDP onto `eth0` (other than DHCP) is dropped. Its NetBIOS and SSDP chatter stays off the TV subnet.

**`post_nat`** (postrouting, `srcnat - 10`). Masquerade the TV subnet out the chosen uplink.

**`netdev tvgw_l2`**. An ingress hook on `eth0` at priority -500 drops every IPv6 frame. This counter ticks with neighbor-discovery noise; that is not a breach.

Rules with a `counter` and a `comment` are snapshotted by `tvgw verify --record`, and the brief's "Firewall held" line matches them by comment prefix (`queries.FW_LINES`). If you rename a comment, update `FW_LINES`, `KEY_RULES` in `src/tvgw/verify.py` and `KEY_RULES` in `tests/hardware/test_gateway.py`. `tests/unit/test_fw_lines.py` reads this script and fails when a counted comment has no line in the brief or a line matches no rule, and `tests/unit/test_deploy_lint.py` fails when a key rule `verify` or the hardware suite looks for is no longer in the script, so a rename cannot drop its evidence silently.

## Testing a change

`nft -c` checks a ruleset against the running kernel without loading it:

```sh
sudo nft -c -f /run/tvgw/ruleset.applied     # the live listing still parses
```

To check an edit before loading it, copy the `table inet tvgw { ... }` block from the script into a file, replace the shell variables (`$TV_IF`, `$TV_ADDR`, `$ZERO_MARK` and so on) with their values, and run `sudo nft -c -f thatfile`. Then load it for real with `sudo tvgw-apply` and run `sudo tvgw verify`. A ruleset that fails to load leaves the previous one in place.

New blocks stop only new connections, because established traffic is accepted first. `sudo conntrack -D -d <ip>` cuts an existing one.

## Gotchas

- `eth0`, `10.10.10.1`, `10.10.10.0/24` and the firmware-fallback address are fixed in the script.
- Every apply resets the counters. The script lists them just before and just after the reload (`/run/tvgw/counters.before-apply`, `counters.after-apply`, published only when the inet table loaded) and the next `tvgw verify --record` stores both, so a reset costs nothing unless a second apply follows within the same 10 minutes.
- While `tvgw.service` is stopped, the input chain is gone with the table, so the Pi's services are reachable from the TV subnet; but forwarding is off on `eth0`.
- `ip_elements` takes only a leading `a.b.c.d` or `a.b.c.d/n` from each line, so anything after it is a comment.
