# NetworkManager: the TV interface and re-applies

The Pi's interfaces are managed by NetworkManager. Two files here keep the TV side stable and make sure the firewall's routes come back when a link does.

## Files

| File | Installed as | What it does |
|---|---|---|
| `90-tvgw.conf` | `/etc/NetworkManager/conf.d/90-tvgw.conf` | `ignore-carrier=yes` on `eth0`: keep `10.10.10.1` on the interface while the TV is off, so dnsmasq, AdGuard and nginx stay bound to it. |
| `90-tvgw-dispatcher` | `/etc/NetworkManager/dispatcher.d/90-tvgw` | On `up` or `dhcp4-change` for `wlan0`, `eth0` or `tun0`, runs `tvgw-apply`. |

The connection itself is not a file here. `install.sh` creates it with `nmcli` if it does not exist: a connection named `tv-lan` on `eth0`, `10.10.10.1/24`, manual addressing, never the default route, IPv6 disabled, autoconnect on. It also turns off autoconnect on the stock "Wired connection 1", which would otherwise fight it with DHCP.

## Why the dispatcher matters

In direct mode the TV's default route lives in table 100 and points at the uplink. When the uplink drops, the kernel removes that route. When it comes back, nothing restores it, and the TV would have no route out. The dispatcher re-runs `tvgw-apply`, which re-adds the route and re-applies the rest. A VPN reconnect (`tun0` up) re-applies too.

## Checking it

```sh
nmcli con show tv-lan | grep -E 'ipv4.addresses|ipv4.never-default|ipv6.method'
ip -4 addr show eth0                            # 10.10.10.1/24, even with the TV off
ip rule show priority 60                        # direct mode: from 10.10.10.0/24 lookup 100
ip route show table 100                         # default via the router on WAN_IF
cat /proc/sys/net/ipv4/conf/eth0/forwarding     # 1 while tvgw.service is up
journalctl -u NetworkManager-dispatcher -n 20   # the dispatcher's runs
```

`sudo tvgw verify` covers the same ground in its `tv_route`, `policy_rule` and `forwarding` checks.

## Changing it

Edit the files here and deploy; `install.sh` reinstalls both and reloads NetworkManager's config. The `tv-lan` connection is created only when it does not exist, so to change its address or options, change it with `nmcli con modify tv-lan ...` or delete it and re-run `install.sh`. The address must stay `10.10.10.1/24`, which the firewall, dnsmasq and nginx assume.

## Gotchas

- The dispatcher re-runs `tvgw-apply` even if you stopped `tvgw.service` by hand, which switches forwarding back on. A link change while you work on a stopped gateway brings the TV back online.
- The interface names are fixed in the dispatcher: if `WAN_IF` is not `wlan0`, add it to the `case` line.
- After editing `90-tvgw.conf`, `sudo nmcli general reload conf` (the installer does this).

More on the routing: [../nftables/README.md](../nftables/README.md).
