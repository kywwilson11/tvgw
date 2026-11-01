# The TV interface and link re-applies

This folder holds the NetworkManager config that keeps the gateway's address on the TV interface (`TV_IF`, `eth0` by default) and the dispatcher script that re-runs the firewall when a link comes up. `install.sh` installs both on every run and creates the `tv-lan` connection the first time. The TV side comes from the settings file ([the TV side](../README.md#the-tv-side)); the values below are the defaults. The routing they protect is in [the firewall's order of operations](../nftables/README.md#order-of-operations).

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
| `ipv4.never-default` | `yes` | The TV side is never the Pi's default route. |
| `ipv6.method` | `disabled` | The TV segment carries no IPv6. |
| `connection.autoconnect` | `yes` | It comes up at boot. |

Before it creates `tv-lan`, `install.sh` turns off autoconnect on the stock `Wired connection 1` when `TV_IF` is `eth0` and that connection exists, and on any connection active on `TV_IF`, so DHCP on the same port cannot fight the static address. When `tv-lan` exists on another interface or with another address, because `TV_IF`, `TV_NET` or `GW_IP` changed, it prints `tvgw: tv-lan moves to ...`, turns off autoconnect on the other connections of the new port the same way (never on `tv-lan` itself), modifies the connection and brings it up again. Otherwise it brings `tv-lan` up only when it is not already active: re-activating it drops `GW_IP` for a moment and fires a dispatcher apply.

## The dispatcher

The script sources `/etc/tvgw/tvgw.conf` when it can read it. On the events `up` and `dhcp4-change`, for the interface `WAN_IF` (`wlan0` when unset), `TV_IF` (`eth0` when unset) or `tun0`, it runs `exec /usr/local/sbin/tvgw-apply`.

(ledger) Before that, for every event on `WAN_IF`, `TV_IF` or `VPN_IF` (`tun0` when unset), it appends `<epoch>\tdispatcher\t<interface>\t<event>` to `/var/lib/tvgw/changes.spool`, so a VPN reconnect, a Wi-Fi re-association, a TV-port flap or a DHCP renewal is in the change ledger with its time ([design decision 48](../../docs/design-decisions.md)). A failed write is ignored and the apply runs as before.

In direct mode the TV's default route lives in table 100 and points at the uplink. When the uplink drops, the kernel removes that route, and nothing else puts it back. The dispatcher re-runs `tvgw-apply` when the link returns, which adds the route again; a VPN reconnect (`tun0` up) re-applies too.

## Checking it

On the Pi:

```sh
nmcli con show tv-lan | grep -E 'ipv4.addresses|ipv4.never-default|ipv6.method'
ip -4 addr show eth0                            # 10.10.10.1/24, even with the TV off
ip rule show priority 60                        # direct mode: from 10.10.10.0/24 lookup 100
ip route show table 100                         # the default route via the router on WAN_IF
cat /proc/sys/net/ipv4/conf/eth0/forwarding     # 1 while tvgw.service is up
journalctl -u NetworkManager-dispatcher -n 20   # the dispatcher's runs
```

`sudo tvgw verify` covers the same ground with its route, policy-rule and forwarding checks ([what tvgw verify checks](../../docs/troubleshooting.md#what-tvgw-verify-checks)).

## Changing it

1. Edit the files here, run `make gate` and deploy. `install.sh` installs both and runs `nmcli general reload conf`.
2. `tv-lan` is created only when it does not exist, and its interface and address follow `TV_IF`, `TV_NET` and `GW_IP` on every run. To change its other options, run `nmcli con modify tv-lan ...`, or delete it and run `install.sh` again.

`tests/unit/test_deploy_lint.py` runs `sh -n` on the dispatcher, with dash on CI, so it must stay a POSIX script. The hardware suite checks that the dispatcher equals the checkout and that `90-tvgw.conf` is the template with `TV_IF` filled in.

## Gotchas

- The dispatcher runs `tvgw-apply` even when you stopped `tvgw.service` by hand, which switches forwarding back on. A link change while you work on a stopped gateway brings the TV back online.
- The dispatcher reads `WAN_IF` and `TV_IF` from the settings file, so a renamed uplink or TV port needs no edit here; `tun0` is fixed.
