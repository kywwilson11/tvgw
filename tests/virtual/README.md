# The virtual gateway

This folder holds a copy of the gateway built from Linux network namespaces: a namespace TV, a namespace gateway that runs the real `tvgw-apply`, and a namespace internet. The suite checks every ruleset variant with `nft -c` and probes the loaded firewall from the TV's side, so a firewall change is exercised on a kernel before it reaches the Pi. It runs as root on a Linux machine or VM, and in CI's `virtual` workflow on every pull request and every push to `main`. It is for developers changing `deploy/nftables/tvgw-apply` or anything the firewall reads. The kinds of tests and where each runs are in [the tests overview](../README.md); why the suite exists and how it stays off the host's files is [design decision 27](../../docs/design-decisions.md#27-a-namespace-copy-of-the-gateway-in-ci).

## What it checks

| Test file | What it checks |
|---|---|
| `test_virtual_rulesets.py` | `tvgw-apply --check` renders every combination of `UPLINK`, `BLOCK_QUIC`, `STRICT_PORTS`, `DNSGATE`, `CAPTURE_MODE` and `ADTECH_PORT_WALL` (64 today; the probes run with `CAPTURE_MODE` and `ADTECH_PORT_WALL` unset, so `full` and `yes`), and `nft -c` accepts each one. The values come from the script's own `case` arms, so a value added there is checked without anyone listing it here. The check must leave its namespace as it found it: no table, forwarding off, no rule 60, nothing under `/run/tvgw`. Each switch must render the rule it names (the adtech port wall's log sample and its `LG adtech port` reject in every variant with `ADTECH_PORT_WALL=yes`, neither without), every variant must carry the `ct_events` chain, the two leak counters and the drop of both PIA tunnels, and every counted rule of the script must appear in at least one variant. |
| `test_virtual_guard.py` | The guard of [design decision 42](../../docs/design-decisions.md#42-guard-the-pi-is-closed-to-the-tv-whatever-nftables-holds), section file 11 F6's acceptance test. `deploy/nftables/guard.nft.template` is rendered as `install.sh` renders it and loaded over the `direct` scenario; canary listeners stand for the co-tenants (TCP and UDP 3389, 445, 22, 5353 and 67, besides the gateway's own 8000 and 5000), bound to the wildcard and to a second address on a dummy `lan0` (198.51.100.200, the Pi's home-LAN address), which the TV routes by the gateway. With `inet tvgw` loaded only DNS, DHCP from source port 68, 80 and 443 answer, and no guard counter moves; after `nft delete table inet tvgw` the same holds and the guard's final drop and weak-host counters grow; a forged source ends at the guard; re-applying leaves its final counter still; `verify.guard_quiet_check` reads it quiet against the apply's own listing. Where systemd runs (CI's runner), a canary under `systemd-run --scope -p IPAddressDeny=10.10.10.0/24` answers the LAN side and never the TV, with both tables gone. The module removes the guard and re-applies when it ends. |
| `test_virtual_gate.py` | (events) The DNS gate's set on the kernel: built as `tvgw-apply` builds it in the scratch namespace, an address added with a one-hour expiry keeps it under a `timeout`-only add and gets a fresh day from what `dnsgate.batch` sends ([design decision 43 (events)](../../docs/design-decisions.md#43-events-the-flow-log-hears-the-tv-alone-and-the-gates-day-starts-at-each-answer)). The refresh needs kernel 6.12 or later; on an older kernel that last step is skipped. The namespace is left empty. |
| `test_virtual_gateway.py` | Each scenario of `matrix.txt` is applied to the gateway namespace in turn, as the dispatcher re-applies on the Pi, and each row is probed (next section). Per scenario it also checks that the counters loaded are exactly the counted rules rendered, that the policy route sends the TV out by the chosen uplink while the main table's default stays on `tun0`, that `verify.KEY_RULES` and the IPv6 guard are found in the kernel's own listing, and that `/run/tvgw/ruleset.applied` and `settings.applied` are what `tvgw verify` will compare against. A re-apply with nothing changed must emit no routing event and keep a live connection on the same conntrack entry (the [2026-10-30 incident](../../docs/incidents.md#2026-10-30-live-connections-lost-their-conntrack-entry-at-every-dhcp-renewal)). The gateway itself must reach every service a row expects to be blocked, so a refused probe means the firewall refused it. |

| `test_virtual_adguard.py` | (lists) The real AdGuard Home, given the YAML `adguardcfg.plan` writes for the shipped profile, in a namespace pair of its own (`tvgwv-<pid>-agh` on 10.10.10.1 and `tvgwv-<pid>-aghtv` on 10.10.10.50, no upstream reachable). The binary's own `--check-config` must accept the plan. From the TV's address, through `dnsprobe.py`: a blocked HTTPS query is NOERROR with no answer and no SOA, a blocked SVCB query is NOERROR with an SOA (NODATA), and a name one of the profile's rules blocks answers `0.0.0.0`, which together pin `blocking_mode: default`. AdGuard must leave every key the plan owns as the plan wrote it. It needs the binary named by `TVGW_VIRTUAL_ADGUARD`: CI downloads the pinned v0.107.79 release and checks its SHA-256; without it the file skips, or fails under `TVGW_VIRTUAL_REQUIRED=1`. |

The pure parts (the matrix parser, the conf, the variants, the counter parser and the probes over loopback) are unit-tested in [`tests/unit/test_virtual_harness.py`](../unit/test_virtual_harness.py), and `tvgw-apply --check` itself in [`tests/unit/test_apply_check.py`](../unit/test_apply_check.py); both run in every `make gate`.

## The topology

| Namespace | Interfaces and addresses | What runs there |
|---|---|---|
| `tv` | `eth0` 10.10.10.50/24, plus 10.99.0.5/32 as a foreign source and 10.10.10.200/32 as a second address in the TV subnet (the pin's case); default via 10.10.10.1 | The probes; a TCP service on 8000 for the unsolicited-inbound row |
| `gw` | `eth0` 10.10.10.1/24 to the TV; `wlan0` 198.51.100.2/24 and `tun0` 192.0.2.2/24 to the internet; main default via `tun0`, as the VPN client's routes are on the Pi | `tvgw-apply`; a stand-in AdGuard (answers every query with 198.51.100.153), nginx (TCP 80 and 443) and one other Pi service (TCP 8000, UDP 5000) |
| `wan` | `up0` 198.51.100.1/24 (the router), `vpn0` 192.0.2.1/24, and on `lo` 203.0.113.10 (web), .20 (a DoH resolver), .30 (a manual block), .53 (a public resolver), 10.20.30.40 (a home-LAN host) and 156.147.69.32 (LG's firmware fallback) | A public resolver (answers 203.0.113.153), TCP and UDP services on every port a row names, a GRE echo |
| `chk` | dummy `eth0` and `wlan0` | Only `tvgw-apply --check` |

The gateway namespace keeps reverse-path filtering loose (`net.ipv4.conf.all.rp_filter=2`, as systemd leaves it on the Pi), so the `rp_filter=1` `tvgw-apply` sets on `eth0` stays loose in effect, as there, and a forged source reaches the firewall rule that must drop and count it. The gateway namespace uses the interface names `tvgw-apply` hardcodes; a namespace has names of its own, so nothing on the host is renamed. Every service reports the source address it saw, so a probe knows whether its connection left by `wlan0` (198.51.100.2), by `tun0` (192.0.2.2) or was not NATed at all. The stand-ins are one stdlib-only script, `agent.py`, run inside each namespace.

`tvgw-apply` sources `/etc/tvgw/tvgw.conf` and writes `/run/tvgw`, with no override for either. The suite runs it under `unshare --mount` inside the gateway namespace with a temporary directory bind-mounted over each of `/etc/tvgw`, `/var/lib/tvgw` and `/run/tvgw`, and a tmpfs over `/run/lock`. The host's own files are never written, so the suite cannot overwrite a real gateway's settings or the baseline `tvgw verify` reads, even when it is run on one. The conf holds `WAN_IF=wlan0`, `WAN_GW=198.51.100.1`, `TV_IP=10.10.10.50` and `TV_MAC=02:00:00:00:00:50` (a locally administered placeholder, so the forward pin is loaded) and the scenario's switches; `block4.txt` holds 203.0.113.30 and `doh4.txt` holds 203.0.113.20. When `/etc/tvgw`, `/var/lib/tvgw` or `/run/tvgw` does not exist, the suite creates it as an empty mount point and removes it afterwards.

## The reachability matrix

`matrix.txt` is the expected behaviour of the firewall, as data. A `[name] KEY=value ...` line opens a scenario; each row after it is one probe:

```text
[direct] UPLINK=direct BLOCK_QUIC=yes STRICT_PORTS=no DNSGATE=count
tv          tcp      203.0.113.20   443   reject           DoH resolvers
```

| Field | Values |
|---|---|
| source | `tv`, `tv-foreign` (the TV's link with source 10.99.0.5), `tv-alias` (source 10.10.10.200) or `wan` |
| probe | `dns-udp`, `dns-tcp`, `tcp`, `udp`, `ping` (the port field is the payload size), `gre`, `udp6` |
| target, port | the address and port probed; `-` for none |
| verdict | `pass:tv`, `pass:wlan0`, `pass:tun0` (where the far end saw the connection come from), `pass` (ping, GRE), `answer:gateway` or `answer:wan` (which resolver answered), `reject` (refused at once: a reset or an ICMP unreachable), `drop` (silence for 1.5 s), `sent` (only the counter can judge) |
| counter | the comment of the rule whose counter must gain at least one packet, or `-` |

A row passes when the probe saw the verdict, the named counter moved, and no other drop or reject counter moved; `no IPv6 from the TV` is exempt from the last check, because neighbour discovery on the TV link ticks it on its own. The three scenarios are the shipped default (`direct`), QUIC open with `STRICT_PORTS=yes` and the gate off (`strict`), and the VPN as the uplink (`vpn`). The rows cover the guarantees the hardware suite trusts: DNS to any resolver lands on the gateway's resolver, DoT, DoQ, DoH-by-IP, QUIC and manual blocks are refused, TCP 4431 is reset by the adtech port wall before the odd-port rules see it (in `direct` and in `strict`, where the `STRICT_PORTS` counter must stay still), the home LAN and the gateway's other ports are dropped, a foreign source is dropped (forwarded, and at the gateway's input), a second address in the TV subnet is not forwarded, tunnels and large pings are dropped, the web is reached by the chosen uplink only, and nothing unsolicited gets in from the internet or the VPN side.

A firewall change that changes what the TV can reach changes a row, so it arrives as a reviewed diff of `matrix.txt`. Every run writes the matrix as it saw it, with the counters each probe moved, to `matrix.observed.txt` beside the rendered rulesets.

To add a row, add the line under its scenario; when it needs a service that is not there yet, add the port to `GW_SERVE`, `WAN_SERVE` or `TV_SERVE` in `vnet.py`, and add a line to `test_every_service_a_row_expects_blocked_answers_the_gateway_itself` so the row's refusal means something.

## The gap the suite found

Rule 60 (`from 10.10.10.0/24 lookup 100`) matches what the gateway itself sends to the TV from 10.10.10.1, not just what it forwards: a DNS answer from a resolver bound to 10.10.10.1, nginx's half of a TCP handshake, the ICMP of a `reject`. Table 100 holds only the default route, so on a kernel with nothing else those packets leave by `wlan0` and the TV never sees them. On the Pi the TV is answered regardless, by a route or rule from outside tvgw, probably the VPN client's, that this suite cannot see; a new gateway without that VPN client would not be. The suite adds `10.10.10.0/24 dev eth0 table 100` after each apply that leaves the gap (`vnet.HELPER_ROUTE`), so the matrix tests the firewall rather than the gap, and `test_the_gateway_reaches_the_tv_by_the_apply_alone` records it as a strict xfail. When `tvgw-apply` closes the gap itself, that test passes, strict mode fails the run, and the helper and the mark should go.

## Running it

It needs Linux, root, `nft`, `ip`, `unshare`, `mount` and `bash`; `conntrack` is optional (without it the re-apply test does not compare conntrack entries). Without them every test is skipped; with `TVGW_VIRTUAL_REQUIRED=1`, as CI sets it, a missing one is an error instead. It takes about a minute and a half; the guard's module probes two dozen closed ports four times, each silent for half a second.

In a Linux VM (a Multipass, Lima or UTM Ubuntu guest works; the suite never needs the VM's own network):

```sh
sudo apt-get install -y nftables iproute2 conntrack python3-venv
python3 -m venv .venv && .venv/bin/pip install -e ".[dev]"
sudo env PYTHONDONTWRITEBYTECODE=1 TVGW_VIRTUAL_ARTIFACTS=/tmp/virtual \
    .venv/bin/python -m pytest -m virtual tests/virtual -p no:cacheprovider -rxX
ls /tmp/virtual                  # rulesets/, scenarios/, services/, matrix.observed.txt
```

In a privileged container, on a workstation with Docker (Docker Desktop's kernel has conntrack built in and the container has no `/lib/modules`, so `modprobe` is replaced by a no-op):

```sh
docker run --rm --privileged -v "$PWD":/src:ro -w /src ubuntu:24.04 sh -c '
  apt-get update -qq && apt-get install -y -qq python3-pytest python3-yaml nftables iproute2 conntrack >/dev/null &&
  ln -sf /bin/true /usr/local/sbin/modprobe &&
  PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=src python3 -m pytest -m virtual tests/virtual -p no:cacheprovider -rxX'
```

To include the resolver test, download AdGuard Home's `linux_amd64` release (the version and SHA-256 are in `.github/workflows/virtual.yml`), unpack it, and pass `TVGW_VIRTUAL_ADGUARD=<path to AdGuardHome>` through `sudo env` with the other variables.

Use `debian:trixie` in place of `ubuntu:24.04` for the nftables release the Pi runs (1.1.3); `ubuntu-latest` in CI has 1.0.9. The suite also runs on the gateway itself without harm, since its namespaces and mounts are its own, but there is no reason to.

## Artifacts

`TVGW_VIRTUAL_ARTIFACTS` names the directory (a pytest temporary directory when unset). CI uploads it as `virtual-gateway`, kept 30 days.

| Path | What it is |
|---|---|
| `rulesets/<variant>.nft` | What `tvgw-apply --check` printed for one variant: the rulesets it would load (three, four with `CAPTURE_MODE=headers`). `nft -c -f` reads each on its own. |
| `scenarios/<name>/` | `apply.log`, the files the apply wrote under `/run/tvgw` (`ruleset.applied`, `settings.applied`, the counter listings) and `ruleset.nft`, the gateway namespace's whole ruleset after the apply. |
| `services/<namespace>.log` | Each stand-in service's stderr. |
| `adguard/` | (lists) The YAML the plan wrote (`AdGuardHome.planned.yaml`), the binary's `--check-config` output and the YAML as AdGuard left it (`AdGuardHome.after.yaml`); AdGuard's own log is `services/adguard.log`. |
| `matrix.observed.txt` | The matrix as the run saw it, with every probe's moved counters, and `# expected ...` on a row that failed. |

## Cleaning up

Everything the suite creates is named `tvgwv-<pid>-<role>`. The session fixture kills the services and deletes the namespaces on any exit pytest sees, including a failure or Ctrl-C, and `atexit` covers one it does not. A run killed with `kill -9` leaves its namespaces behind; the next run deletes every `tvgwv-` namespace whose process is gone, and CI's workflow deletes any that remain in an `always()` step. By hand:

```sh
for ns in $(ip netns list | awk '{print $1}' | grep '^tvgwv-'); do sudo ip netns del "$ns"; done
```

A killed run can also leave the empty mount points it created; `sudo rmdir /etc/tvgw /var/lib/tvgw /run/tvgw` removes them where no gateway is installed.

## Files

| File | What it is |
|---|---|
| `vnet.py` | The topology, the sandboxed apply, the matrix parser and the counter parser. |
| `agent.py` | The probes and the stand-in services, run inside the namespaces. |
| `matrix.txt` | The reachability matrix. |
| `conftest.py` | The skip-or-fail rule and the session-wide topology. |
| `__init__.py` | Makes the folder a package, so its `conftest.py` and the unit suite's do not shadow each other when both are collected. |
| `test_virtual_rulesets.py`, `test_virtual_gate.py`, `test_virtual_gateway.py` | The three test files above. |
| `test_virtual_adguard.py`, `dnsprobe.py` | (lists) The resolver test above, and its standard-library DNS client, run with `python -I` inside the TV namespace; its pure parts are unit-tested in [`tests/unit/test_virtual_dnsprobe.py`](../unit/test_virtual_dnsprobe.py). |
