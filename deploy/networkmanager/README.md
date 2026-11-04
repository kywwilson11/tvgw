# The TV interface and link re-applies

This folder holds the NetworkManager config that keeps the gateway's address on the TV interface (`TV_IF`, `eth0` by default) and the dispatcher script that re-runs the firewall when a link comes up. `install.sh` installs both on every run and creates the `tv-lan` connection the first time. The TV side comes from the settings file ([the TV side](../../docs/reference/settings.md#the-tv-side)); the values below are the defaults. The routing they protect is in [the firewall's order of operations](../nftables/README.md#order-of-operations).

## Files

| File | What it is | Installed as |
|---|---|---|
| `90-tvgw.conf` | `[device-tvgw-<TV_IF>]` with `match-device=interface-name:<TV_IF>` and `ignore-carrier=yes`; `install.sh` fills in `__TV_IF__`. | `/etc/NetworkManager/conf.d/90-tvgw.conf`, written by `install.sh` on every run |
| `90-tvgw-dispatcher` | A POSIX `sh` script that runs `tvgw-apply` on link events. | `/etc/NetworkManager/dispatcher.d/90-tvgw`, mode 755 |

## Keeping the address while the TV is off

`ignore-carrier=yes` keeps `GW_IP` on `TV_IF` while the TV is off, so dnsmasq, AdGuard Home and nginx stay bound to it.

## The tv-lan connection

The connection is not a file here. `install.sh` creates it with `nmcli` when no connection named `tv-lan` exists:

| Option | Value | Why |
|---|---|---|
| type and interface | `ethernet` on `TV_IF` | The TV's cable. |
| `ipv4.method` | `manual` | The gateway's address is fixed. |
| `ipv4.addresses` | `GW_IP/<prefix of TV_NET>`, `10.10.10.1/24` by default | The address the firewall, dnsmasq and nginx use. |
| `ipv4.never-default` | `yes` | The TV side is never the gateway's default route. |
| `ipv6.method` | `disabled` | The TV segment carries no IPv6. |
| `connection.autoconnect` | `yes` | It comes up at boot. |

Before it creates `tv-lan`, `install.sh` turns off autoconnect on the stock `Wired connection 1` when `TV_IF` is `eth0` and that connection exists, and on any connection active on `TV_IF`, so DHCP on the same port cannot fight the static address. When `tv-lan` exists on another interface or with another address, because `TV_IF`, `TV_NET` or `GW_IP` changed, it prints `tvgw: tv-lan moves to ...`, turns off autoconnect on the other connections of the new port the same way (never on `tv-lan` itself), modifies the connection and brings it up again. Otherwise it brings `tv-lan` up only when it is not already active: re-activating it drops `GW_IP` for a moment and fires a dispatcher apply.

## The dispatcher

The script sources `/etc/tvgw/tvgw.conf` when it can read it. On the events `up` and `dhcp4-change`, for the interface `WAN_IF` (`wlan0` when unset), `TV_IF` (`eth0` when unset) or the VPN's tunnel, it runs `exec /usr/local/sbin/tvgw-apply`. The tunnel comes from `VPN_IF` as `tvgw-apply` reads it: with `auto` (or unset) both of PIA's interfaces, `tun0` for OpenVPN and `wgpia0` for WireGuard; with a name, that interface; with `none`, no tunnel ([design decision 44](../../docs/design-decisions.md#44-the-tunnel-is-a-setting-and-the-pis-own-leaks-are-counted)).

(ledger) Before that, for every event on `WAN_IF`, `TV_IF`, PIA's tunnel (`tun0` for OpenVPN, `wgpia0` for WireGuard) or the tunnel `VPN_IF` names, it appends `<epoch>\tdispatcher\t<interface>\t<event>` to `/var/lib/tvgw/changes.spool`, so a VPN reconnect, a Wi-Fi re-association, a TV-port flap or a DHCP renewal is in the change ledger with its time ([design decision 48](../../docs/design-decisions.md#48-one-ledger-of-changes-one-hour-classifier-and-a-second-judge-that-only-watches)). The line is written under umask 027, so the spool is never readable by others, and a failed write is ignored and the apply runs as before. The apply itself runs for the tunnels `VPN_IF` watches, as below.

In direct mode the TV's default route lives in table 100 and points at the uplink. When the uplink drops, the kernel removes that route, and nothing else puts it back. The dispatcher re-runs `tvgw-apply` when the link returns, which adds the route again; a VPN reconnect (the tunnel up) re-applies too, which is also when `VPN_IF=auto` picks up a tunnel that changed from `tun0` to `wgpia0`. Table 100 also holds the TV subnet on `TV_IF` with `GW_IP` as its source, the route the gateway's own answers to the TV take ([design decision 49](../../docs/design-decisions.md#49-the-gateway-answers-the-tv-through-the-tv-port-table-100-carries-the-tv-subnet)). It survives the TV being off, because `tv-lan` keeps its address without carrier; re-activating `tv-lan` takes `GW_IP` off the port for a moment, the kernel removes the route with it, and the dispatcher's apply on `TV_IF` up adds it again.

## Checking it

On the gateway:

```sh
nmcli con show tv-lan | grep -E 'ipv4.addresses|ipv4.never-default|ipv6.method'
ip -4 addr show eth0                            # 10.10.10.1/24, even with the TV off
ip rule show priority 60                        # direct mode: from 10.10.10.0/24 lookup 100
ip route show table 100                         # direct mode: the default via the router, and 10.10.10.0/24 on eth0
cat /proc/sys/net/ipv4/conf/eth0/forwarding     # 1 while tvgw.service is up
journalctl -u NetworkManager-dispatcher -n 20   # the dispatcher's runs
```

`sudo tvgw verify` covers the same ground with its route, reply-route, policy-rule and forwarding checks ([what tvgw verify checks](../../docs/reference/verify-checks.md)).

## Changing it

1. Edit the files here, run `make gate` and deploy. `install.sh` installs both and runs `nmcli general reload conf`.
2. `tv-lan` is created only when it does not exist, and its interface and address follow `TV_IF`, `TV_NET` and `GW_IP` on every run. To change its other options, run `nmcli con modify tv-lan ...`, or delete it and run `install.sh` again.

`tests/unit/test_deploy_lint.py` runs `sh -n` on the dispatcher, with dash on CI, so it must stay a POSIX script, and `tests/unit/test_events_apply.py` runs it on each kind of event to check which ones apply. The hardware suite checks that the dispatcher equals the checkout and that `90-tvgw.conf` is the template with `TV_IF` filled in.

## Gotchas

- The dispatcher runs `tvgw-apply` even when you stopped `tvgw.service` by hand, which switches forwarding back on. A link change while you work on a stopped gateway brings the TV back online.
- The dispatcher reads `WAN_IF`, `TV_IF` and `VPN_IF` from the settings file, so a renamed uplink, TV port or tunnel needs no edit here.
