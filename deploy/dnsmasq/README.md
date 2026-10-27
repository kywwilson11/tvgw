# dnsmasq: DHCP for the TV

dnsmasq hands the TV its address and nothing else. DNS is AdGuard Home's job, so dnsmasq's DNS server is off (`port=0`). The TV always gets the same address, so every log line, query-log record and AdGuard client entry is attributable to it.

## Files

| File | Installed as |
|---|---|
| `tvgw.conf.template` | `/etc/dnsmasq.d/tvgw.conf`, written by `install.sh` on every run |

## What the config says

| Line | Why |
|---|---|
| `port=0` | No DNS from dnsmasq; AdGuard Home owns port 53. |
| `interface=eth0`, `bind-dynamic` | Serve only the TV side, and cope with `eth0` coming and going. |
| `dhcp-authoritative` | dnsmasq is the only DHCP server on the subnet, so a client asking for a lease it does not know is corrected at once. |
| `dhcp-range=10.10.10.10,10.10.10.20,255.255.255.0,12h` | A small pool; the TV is pinned inside it. |
| `dhcp-option=option:router,10.10.10.1` and `option:dns-server,10.10.10.1` | The Pi is the TV's gateway and resolver. DNS sent anywhere else is redirected by the firewall anyway. |
| `dhcp-host=__TV_MAC__,__TV_IP__,__TV_NAME__` | Pins the TV by its wired MAC. |
| `log-dhcp` | DHCP exchanges go to the journal. |

`install.sh` fills the placeholders from `TV_MAC`, `TV_IP` (default `10.10.10.17`) and `TV_NAME` (default `tv`) in `/etc/tvgw/tvgw.conf`, then restarts dnsmasq. `tvgw.service` is ordered before dnsmasq, so the firewall is in place before the TV gets a lease.

## Changing it

Edit `/etc/tvgw/tvgw.conf`, not the generated file, and re-run `install.sh`; it rewrites `/etc/dnsmasq.d/tvgw.conf` each time. Check the result with `journalctl -u dnsmasq -n 20` after the TV renews its lease. The hardware suite checks that the generated file holds the TV's MAC and address.

## Checking it

```sh
cat /etc/dnsmasq.d/tvgw.conf                 # the generated file, with the TV's MAC filled in
journalctl -u dnsmasq -n 30                  # DHCPDISCOVER / DHCPACK lines for the TV (log-dhcp)
ss -lunp | grep dnsmasq                      # listening on UDP 67 only, not 53
```

If the TV shows a different address than `TV_IP`, its wired MAC does not match `TV_MAC`. Check the MAC in the TV's network settings; the TV's Wi-Fi MAC is a different one.

## Gotchas

- On Debian, `/etc/default/dnsmasq` must keep its `CONFIG_DIR` line, or `/etc/dnsmasq.d` is ignored (noted during the original bring-up, [../../docs/lg-cx-deployment.md](../../docs/lg-cx-deployment.md)).
- If you change `TV_IP`, keep it inside the DHCP range and in `10.10.10.0/24`, and re-run `install.sh` so the DHCP pin, the flow log's filter and AdGuard's client entry follow. Ingest reads `TV_IP` on every run.
- `install.sh` stops if `TV_MAC` is unset; the template's placeholder MAC never reaches dnsmasq.
