# DHCP for the TV

This folder holds the dnsmasq template that gives the TV its address and nothing else (DNS is AdGuard Home's job), and the systemd drop-in that runs dnsmasq with the least it needs. `install.sh` writes both on every run and restarts dnsmasq with a health check. How the TV is found and pinned on a first install is in [what install.sh does](../README.md#what-installsh-does).

## Files

| File | What it is | Installed as |
|---|---|---|
| `tvgw.conf.template` | The DHCP config, with the placeholders `__TV_MAC__`, `__TV_IP__` and `__TV_NAME__` for the TV and `__TV_IF__`, `__GW_IP__`, `__DHCP_FIRST__`, `__DHCP_LAST__` and `__TV_NETMASK__` for the TV side. | `/etc/dnsmasq.d/tvgw.conf`, written by `install.sh` on every run |
| `20-tvgw-hardening.conf.template` | The sandbox for `dnsmasq.service`, with `__TV_NET__` ([the hardening drop-in](#the-hardening-drop-in)). | `/etc/systemd/system/dnsmasq.service.d/20-tvgw-hardening.conf`, written by `install.sh` and taken out again when dnsmasq will not serve with it |

## The config, line by line

As written with the default TV side (`TV_IF=eth0`, `TV_NET=10.10.10.0/24`, `GW_IP=10.10.10.1`):

| Line | Why |
|---|---|
| `port=0` | dnsmasq serves no DNS; AdGuard Home owns port 53. |
| `interface=eth0` | It serves the TV side only. |
| `bind-dynamic` | It binds to `eth0` as the interface comes and goes. |
| `dhcp-authoritative` | It is the only DHCP server on the subnet. |
| `dhcp-range=10.10.10.10,10.10.10.20,255.255.255.0,12h` | A pool of the 10th to the 20th host of `TV_NET` with 12-hour leases. |
| `dhcp-option=option:router,10.10.10.1` | The Pi is the TV's gateway. |
| `dhcp-option=option:dns-server,10.10.10.1` | The Pi is the TV's resolver. DNS the TV sends anywhere else is redirected by the firewall anyway ([the ruleset](../nftables/README.md#the-ruleset-chain-by-chain)). |
| `dhcp-host=__TV_MAC__,__TV_IP__,__TV_NAME__` | Pins the TV by its wired MAC, so every log line, query-log record and AdGuard client entry belongs to one address. |
| `log-dhcp` | DHCP exchanges go to the journal, where `tvgw discover` reads the name the TV announced. |
| `dhcp-broadcast` | Every reply is broadcast. Untagged, it is unconditional (dnsmasq(8)), so dnsmasq never writes the ARP cache for a unicast offer, the one thing it keeps `CAP_NET_ADMIN` for. Every RFC 2131 client accepts a broadcast reply. A renewal from an address the TV already holds is still answered by unicast. |
| `no-ping` | No ICMP check before an offer, the one thing it keeps `CAP_NET_RAW` for. One host on the segment has no address conflict to find. |

`install.sh` fills the placeholders from `TV_MAC`, `TV_IP`, `TV_NAME`, `TV_IF` and `GW_IP`, and the pool and netmask from `TV_NET` ([the settings file](../README.md#the-settings-file)). While the TV is unknown, it writes the file without the `dhcp-host` line, so the TV gets a pool address and `tvgw discover` can find it. `tvgw.service` is ordered before dnsmasq, so the firewall is loaded before the TV gets a lease ([the units](../systemd/README.md#units)).

`tvgw discover` reads the leases from `/var/lib/misc/dnsmasq.leases` and the last 2,000 lines of dnsmasq's journal (`LEASES` and `gather()` in src/tvgw/discover.py).

## The hardening drop-in

dnsmasq parses every DHCP packet the TV sends, and `CAP_NET_ADMIN` is enough to rewrite the firewall. With `dhcp-broadcast` and `no-ping`, dnsmasq 2.91 (`src/dnsmasq.c` in Debian's trixie source) asks for neither `CAP_NET_ADMIN` nor `CAP_NET_RAW`, and the drop-in takes both out of the bounding set ([design decision 42](../../docs/design-decisions.md#42-the-pi-is-closed-to-the-tv-whatever-nftables-holds)):

| Line | Why |
|---|---|
| `CapabilityBoundingSet=CAP_NET_BIND_SERVICE CAP_SETUID CAP_SETGID CAP_CHOWN CAP_DAC_OVERRIDE` | What dnsmasq uses as root before it drops to the `dnsmasq` user: port 67, the switch of user and group, the helper's `chown` of `/run/dnsmasq`, and writing its pid file into `/run/dnsmasq`, which belongs to `dnsmasq` with mode 755 (Debian's tmpfiles line), so root needs `CAP_DAC_OVERRIDE` there. After the drop it keeps none of them. |
| `NoNewPrivileges`, `ProtectSystem=strict` with `ReadWritePaths=-/var/lib/misc -/run`, `ProtectHome`, `PrivateTmp`, `PrivateDevices` | Only the lease file and `/run` are writable. |
| `ProtectKernelTunables`, `ProtectKernelModules`, `ProtectKernelLogs`, `ProtectControlGroups`, `ProtectClock`, `ProtectHostname`, `RestrictNamespaces`, `RestrictRealtime`, `RestrictSUIDSGID`, `LockPersonality`, `MemoryDenyWriteExecute`, `SystemCallArchitectures=native`, `SystemCallFilter=@system-service` | The kernel and the rest of the system out of reach. |
| `RestrictAddressFamilies=AF_INET AF_INET6 AF_NETLINK AF_UNIX` | IP, the interface watch (`bind-dynamic`) and the journal. |
| `IPAddressDeny=any` and `IPAddressAllow=localhost 0.0.0.0/32 255.255.255.255/32 10.10.10.0/24` | DHCP on the TV subnet only: a DISCOVER from `0.0.0.0`, replies to `255.255.255.255`, renewals by unicast. |

`install.sh` writes the drop-in, restarts dnsmasq and checks that it is active and holds UDP 67 (`ss -ulnp`). If it is not, the drop-in comes out, dnsmasq restarts without it, the install prints a `WARNING`, and `/var/lib/tvgw/.unit-stamps/dnsmasq-refused` records that this exact drop-in failed, so the next deploy does not try it again (delete the file to retry). A capability dnsmasq still needs makes it stop at start with `process is missing required capability`, which is the check that the two config lines took effect. `tvgw verify`'s `dnsmasq_caps` reads the running daemon's `CapEff` and warns when it holds `net_admin` or `net_raw` (a config line missing), and reads its bounding set `CapBnd` and warns when that still holds them (the drop-in missing: with both config lines `CapEff` is empty either way). The stamp is written only once dnsmasq serves without the drop-in; a dnsmasq that fails both ways has a fault of its own, the install stops, and the drop-in is tried again once that is fixed.

## Checking it

On the Pi:

```sh
cat /etc/dnsmasq.d/tvgw.conf                  # the generated file, with the TV's MAC filled in
journalctl -u dnsmasq -n 30                   # DHCPDISCOVER and DHCPACK lines for the TV
cat /var/lib/misc/dnsmasq.leases              # the lease the TV holds
ss -lunp | grep dnsmasq                       # UDP 67 only, not 53
grep -E 'CapEff|CapBnd' /proc/$(pidof dnsmasq)/status   # capsh --decode=<value>: no cap_net_admin, no cap_net_raw in either
systemctl cat dnsmasq | grep -A1 tvgw         # the hardening drop-in, when it is in place
```

If the TV shows an address other than `TV_IP`, its wired MAC does not match `TV_MAC`. Check the MAC in the TV's network settings; the TV's Wi-Fi MAC is a different one.

## Changing it

1. To change the TV's identity, edit `/etc/tvgw/tvgw.conf` on the Pi, not the generated file, and run `install.sh` again.
2. To change the config itself, edit `tvgw.conf.template` here, run `make gate` and deploy.

The hardware suite checks that `/etc/dnsmasq.d/tvgw.conf` is exactly this template with the gateway's `TV_MAC`, `TV_IP` and `TV_NAME` filled in, and that it pins the TV's MAC to its address ([hardware tests](../../tests/hardware/README.md#what-each-test-guarantees)). `tests/unit/test_deploy_lint.py` checks that the template exists.

## Gotchas

- On Debian, `/etc/default/dnsmasq` must keep its `CONFIG_DIR` line, or dnsmasq ignores `/etc/dnsmasq.d`.
- A hand edit of `/etc/dnsmasq.d/tvgw.conf` is overwritten by the next install, and fails the hardware suite until then.
- `install.sh` stops unless `TV_IP` is in `10.10.10.0/24` and `TV_NAME` is letters, digits, `-` and `_`, because both are written into this file with `sed`.
