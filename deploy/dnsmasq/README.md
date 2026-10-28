# DHCP for the TV

This folder holds the dnsmasq template that gives the TV its address and nothing else; DNS is AdGuard Home's job. `install.sh` writes it to `/etc/dnsmasq.d/tvgw.conf` on every run and restarts dnsmasq. How the TV is found and pinned on a first install is in [what install.sh does](../README.md#what-installsh-does).

## Files

| File | What it is | Installed as |
|---|---|---|
| `tvgw.conf.template` | The DHCP config, with the placeholders `__TV_MAC__`, `__TV_IP__` and `__TV_NAME__`. | `/etc/dnsmasq.d/tvgw.conf`, written by `install.sh` on every run |

## The config, line by line

| Line | Why |
|---|---|
| `port=0` | dnsmasq serves no DNS; AdGuard Home owns port 53. |
| `interface=eth0` | It serves the TV side only. |
| `bind-dynamic` | It binds to `eth0` as the interface comes and goes. |
| `dhcp-authoritative` | It is the only DHCP server on the subnet. |
| `dhcp-range=10.10.10.10,10.10.10.20,255.255.255.0,12h` | A pool of `10.10.10.10` to `10.10.10.20` with 12-hour leases. |
| `dhcp-option=option:router,10.10.10.1` | The Pi is the TV's gateway. |
| `dhcp-option=option:dns-server,10.10.10.1` | The Pi is the TV's resolver. DNS the TV sends anywhere else is redirected by the firewall anyway ([the ruleset](../nftables/README.md#the-ruleset-chain-by-chain)). |
| `dhcp-host=__TV_MAC__,__TV_IP__,__TV_NAME__` | Pins the TV by its wired MAC, so every log line, query-log record and AdGuard client entry belongs to one address. |
| `log-dhcp` | DHCP exchanges go to the journal, where `tvgw discover` reads the name the TV announced. |

`install.sh` fills the placeholders from `TV_MAC`, `TV_IP` and `TV_NAME` ([the settings file](../README.md#the-settings-file)). While the TV is unknown, it writes the file without the `dhcp-host` line, so the TV gets a pool address and `tvgw discover` can find it. `tvgw.service` is ordered before dnsmasq, so the firewall is loaded before the TV gets a lease ([the units](../systemd/README.md#units)).

`tvgw discover` reads the leases from `/var/lib/misc/dnsmasq.leases` and the last 2,000 lines of dnsmasq's journal (`LEASES` and `gather()` in src/tvgw/discover.py).

## Checking it

On the Pi:

```sh
cat /etc/dnsmasq.d/tvgw.conf                  # the generated file, with the TV's MAC filled in
journalctl -u dnsmasq -n 30                   # DHCPDISCOVER and DHCPACK lines for the TV
cat /var/lib/misc/dnsmasq.leases              # the lease the TV holds
ss -lunp | grep dnsmasq                       # UDP 67 only, not 53
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
