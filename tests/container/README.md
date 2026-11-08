# The container tier

This folder holds a whole gateway in one privileged Docker container: Debian 13 booted with systemd as PID 1, NetworkManager, dnsmasq and nginx, and a TV in a network namespace behind its TV port. The tests install AdGuard Home from the pin, run the real `install.sh` through its two setup passes and a deploy (and, on a second new computer, with no pass at all), boot the gateway with its TV port unplugged, and require `tvgw verify` to exit 0, so the installer meets systemd and NetworkManager off the Pi. They run in CI's `container` workflow on every pull request and every push to `main` that changes more than the docs. They report and hold nothing back: `main` has no branch protection, so a pull request can be merged while they run, a push to `main` deploys to the gateway beside them, and `make deploy` reaches it with no CI at all. They also run on any computer with Docker ([running it](#running-it)). The kinds of tests and where each runs are in [the tests overview](../README.md), and why the tier exists is [design decision 27](../../docs/design-decisions.md#27-a-namespace-copy-of-the-gateway-in-ci) and its note.

## Files

| File | What it is | Who uses it |
|---|---|---|
| `Dockerfile` | The gateway's image: `debian:13` by digest, the package's dependencies from `packaging/nfpm.yaml`, udev, D-Bus, busybox and rsync, and `image/` copied over `/`. `CMD` is `/sbin/init`. | `.github/workflows/container.yml`, and `conftest.py` when `TVGW_CONTAINER_IMAGE` names no image |
| `.dockerignore` | Keeps the build context to the Dockerfile and `image/`. | `docker build` |
| `image/etc/dnsmasq.d/tvgw.conf` | `port=0`: dnsmasq serves neither DNS nor DHCP until `install.sh` writes this file. | dnsmasq, at boot |
| `image/etc/NetworkManager/conf.d/10-tvgw-container.conf` | `dns=none`: NetworkManager leaves Docker's `/etc/resolv.conf` alone. | NetworkManager |
| `image/etc/sysctl.d/10-tvgw-container.conf` | `net.ipv4.ip_forward = 0`, a new computer's default. | `systemd-sysctl`, at boot |
| `conftest.py` | The `container` marker, the skip or failure without Docker, the image, one booted gateway per test module, and the skip of a module's later stages after a failure. | pytest |
| `ctr.py` | The harness: the `docker run` line, the settings file, the TV and its port, the listener sampler, the installer, a reboot, verify's settle loop and the captures for CI's artifact. | the tests, and `tests/unit/test_container_harness.py` for its pure parts |
| `guest/tv-dhcp.sh` | The TV's DHCP hook: busybox `udhcpc` runs it with the lease, and it sets the TV's address and default route and writes the lease to `/run/tvgw-container/tv-lease`. | `udhcpc`, in the TV's namespace |
| `guest/listeners.py` | Reads `/proc/net` every 0.1 s and keeps every listening socket it has seen in `/run/tvgw-container/listeners`. | a transient unit in the container |
| `test_container_first_run.py` | A first install on a new computer, stage by stage. | pytest, `-m container` |
| `test_container_no_pass.py` | A first install with no setup pass, as the package's postinst and `sudo ./install.sh` run it, on a container of its own. | pytest, `-m container` |

## The gateway and the TV

| Where | Interfaces | What runs there |
|---|---|---|
| the container | `eth0`, Docker's bridge, as `WAN_IF`; `eth1`, the TV port, as `TV_IF`, a veth with a MAC from RFC 7042's documentation range, the same each time it is plugged in | systemd, udev, NetworkManager, dnsmasq, nginx, AdGuard Home once installed, and everything `install.sh` installs |
| the namespace `tv` | `tvnic`, the other end of the veth, with a MAC from RFC 7042's documentation range | busybox `udhcpc`, kept running by a transient unit with `NetworkNamespacePath=/run/netns/tv`, from before the bringup pass |

The settings file is `deploy/tvgw.conf.example` with the keys setup writes once it has found the TV: `TV_MAC`, `TV_IP=10.10.10.17`, `TV_IF=eth1`, `WAN_IF=eth0`, `WAN_GW` (the container's own default gateway), `UPLINK=direct`, `VPN_IF=none`, `PROFILE=lg-webos` (so nginx and the URL filter are part of the install) and `ADGUARD_LISTEN=gateway`. The TV port is named `eth1` because NetworkManager's own udev rules manage a veth only under an `ethN` name, so the bringup pass meets NetworkManager's automatic DHCP profile on the port, as on a computer with a second network port. Before the first stage the harness copies the checkout to `/opt/tvgw/src` with `deploy/rsync.exclude`, as `deploy/sync-install.sh` does, and installs tvgw into `/opt/tvgw-venv`, so that `tvgw adguard install` can run before the installer, as setup's order has it; `install.sh` installs into the same virtualenv later.

The container runs `--privileged` with its own cgroup namespace and tmpfs on `/run` and `/run/lock`, which systemd needs as PID 1, the checkout read-only at `/mnt/checkout`, and the runner's `/lib/modules` read-only: `tvgw-apply` runs `modprobe nf_conntrack`, and `modprobe` fails without the kernel's module index even when the module is loaded. Two of the three files under `image/` put back what a new computer has and the container would not: Docker's network namespace starts with the runner's `ip_forward=1`, and Docker writes `/etc/resolv.conf` for the container. The third does what the owner of a new computer must do before `tvgw adguard install`: the dnsmasq package starts answering DNS on port 53, which AdGuard Home needs and `tvgw adguard install` refuses to share ([AdGuard install failures](../../docs/use/troubleshooting.md#adguard-install-failures)), and `port=0` keeps dnsmasq off it until `install.sh` writes its own file there.

## What it checks

`test_container_first_run.py` takes a first install in setup's order. Each test is one stage and needs the stages before it; after a failure the rest of the module is skipped, naming the stage that failed.

| Stage | What must hold |
|---|---|
| The computer at the start | No AdGuard Home (`aghinstall.state()` is `absent`), no `inet tvgw` table, `ip_forward` 0, nothing on port 53 or 67. |
| AdGuard Home | `tvgw adguard install` installs the pinned release checked by its SHA-256 and seeds it without the wizard: `state()` is `tvgw`, the marker holds the pinned version, `/etc/tvgw/adguard-admin` is `600 root root`, the YAML has exactly the user `admin` and `http.address: 127.0.0.1:3000`, `AdGuardHome.service` is enabled, active and runs with `--no-check-update`, and DNS answers on 127.0.0.1. A second run does nothing. |
| The bringup pass | Exits 0 with `tvgw: TV side up on eth1 (10.10.10.1)`; `tv-lan` is active on `eth1` with `10.10.10.1/24`; every other profile bound to `eth1` has autoconnect off; dnsmasq holds UDP 67; AdGuard Home's YAML is unchanged; no nginx file, no dispatcher, `tvgw.service` not enabled, no firewall. |
| The TV's lease | The TV holds 10.10.10.17 with 10.10.10.1 as router and DNS server, and dnsmasq's lease file names its MAC. |
| No route out | `ip_forward` and `eth1`'s forwarding are 0, no firewall is loaded, `ip route get <outside> from 10.10.10.17 iif eth1` fails, and a TCP connection from the TV to `github.com` on 443 does not open. |
| The apply pass | Exits 0, or 76 while a check still fails; the firewall is loaded and forwarding on, `tvgw.service` is enabled, nginx listens on 10.10.10.1:80 and :443, and the dispatcher is installed. |
| Verify | `tvgw verify --json` is run until it exits 0, waiting on the checks `verify.SETTLING` names for up to 900 s (15 min) and on any other failure for three runs. |
| AdGuard Home after the apply | DNS on 10.10.10.1:53 and 127.0.0.1:53 over UDP and TCP, the page on 127.0.0.1:3000, and no wildcard listener on 53, 3000 or `aghinstall.FIRSTRUN_PORTS` at any moment since before AdGuard Home was installed; the first must-allow name of the profile, in sorted order, resolves at both; `tvgw adguard diff` has nothing to change; `state()` is `tvgw` without the marker, from the YAML alone. |
| The TV after the apply | The TV opens a connection to `github.com`, a must-allow name resolves for it at 10.10.10.1, and a list's sentinel name answers `0.0.0.0`. |
| A deploy | `deploy/sync-install.sh` from the checkout, as the hardware job runs it, exits 0 with `tvgw verify`'s last line `OK`, and the TV keeps its address. |
| A boot with the TV port unplugged | `docker restart` boots the gateway again without its TV port, since the veth does not survive it, and `10.10.10.1` is on no interface. Plugged in again with the MAC it had, AdGuard Home answers a must-allow name at `10.10.10.1` within 30 s: with `ADGUARD_LISTEN=gateway` its drop-in restarts it every 5 s until the address exists. |
| After the boot | The TV holds 10.10.10.17 again, and `tvgw verify` exits 0 within 600 s (10 min), with nothing done by hand. |

`test_container_no_pass.py` takes the installer's own full run on a second new computer, with the template's placeholder MAC, as the package's postinst and `sudo ./install.sh` meet it:

| Stage | What must hold |
|---|---|
| AdGuard Home | `tvgw adguard install` exits 0. |
| No pass, no TV named | The installer exits 75 with `TV not identified and no terminal to ask on`; `tv-lan` is active; the TV holds a pool address in `TV_NET` with 10.10.10.1 as router and DNS server; no dispatcher, no firewall, `ip_forward` and the TV port's forwarding 0, and the TV's connection to the outside does not open. |
| Discovery | `tvgw discover --write --yes --no-ssdp` exits 0 and writes the TV's MAC and the address it holds. |
| No pass, the TV named | The installer prints `tvgw: installed (tvgw ` and ends in `exec tvgw verify` (0, or 1 while the lists load); the dispatcher is installed and the firewall loaded; `tvgw verify` settles to 0 within 900 s (15 min); the TV keeps its address and opens a connection to the outside. |

The tier does not run `tvgw setup`, `tvgw doctor`, a gateway with another profile, a TV that answers a LAN API, or a status page.

## What it found

- **The bringup pass switched forwarding on.** `install.sh` installed NetworkManager's dispatcher before bringing `tv-lan` up, and the dispatcher runs `tvgw-apply` whenever the TV port comes up, so the firewall loaded and the TV was forwarded before the apply pass. The stubbed `tests/unit/test_install_passes.py` cannot see a dispatcher run. The bringup pass now leaves the dispatcher out ([the setup passes](../../deploy/README.md#the-setup-passes)).
- **The TV lost the gateway after the first apply.** On a computer with no VPN client, rule 60 sends what the gateway itself sends to the TV into table 100, which held only the default route (the gap [design decision 27](../../docs/design-decisions.md#27-a-namespace-copy-of-the-gateway-in-ci) records). Debian 13 leaves `net.ipv4.conf.all.rp_filter` at 0, so the strict reverse-path filtering `tvgw-apply` sets on the TV port is in effect, and the TV's ARP request for 10.10.10.1 fails that check: the TV reaches neither the gateway nor the internet. "The TV after the apply" was a strict xfail while `tvgw-apply` lacked the TV subnet in table 100 (`ctr.reply_route_in_apply`); since [design decision 49](../../docs/design-decisions.md#49-the-gateway-answers-the-tv-through-the-tv-port-table-100-carries-the-tv-subnet) `tvgw-apply` has it, so the test runs as any other.
- **A boot without the TV port leaves the firewall unit failed.** `tvgw-apply` sets `net.ipv6.conf.<TV_IF>.disable_ipv6` with no check that the port exists, so at a boot with the TV's adapter unplugged it stops there, before any table or forwarding: nothing is forwarded, and `tvgw.service` is `failed`. When the port is back, the NetworkManager dispatcher applies the firewall, and `tvgw.service` starts again only because `tvgw-pcap.service`, which restarts every 5 seconds and wants it, pulls it in. "After the boot" passes by that path.

## Running it

The tier needs a Docker daemon and nothing of tvgw on the computer that runs it: the harness drives the container with the `docker` CLI. On Linux the containers share the host's kernel; Docker Desktop runs them in its own Linux VM. On your workstation, from the checkout:

```sh
python3 -m pytest -m container tests/container -rxXs
```

| Variable | Meaning |
|---|---|
| `TVGW_CONTAINER_IMAGE` | An image built from `tests/container` already; without it the harness builds one tagged by the hash of the Dockerfile and `image/`, once. |
| `TVGW_CONTAINER_ARTIFACTS` | Where each container's captures go: the journal, NetworkManager's profiles, the ruleset, the routes, the TV's addresses, the listeners, the settings, the installer's output per pass and a last `tvgw verify --json`. Without it, a pytest temporary directory. |
| `TVGW_CONTAINER_REQUIRED=1` | A missing Docker daemon fails the run instead of skipping it; CI sets it. |

AdGuard Home, pip and the blocklists are fetched from the internet inside the container, so the run needs a network that lets them through. A run takes a few minutes once the image is built. Each container is named `tvgwc-<pid>-<module>` and labelled `tvgw.container`, and is removed when its module ends; a later run removes the ones a killed run left, and CI's cleanup step removes every labelled one.

## Changing it

- A new scenario is a new `test_container_*.py` with `pytestmark = pytest.mark.container` and a module fixture that writes its settings through `Gateway.write_settings(extra)`: each module gets its own container.
- A package added to `packaging/nfpm.yaml`'s `depends` or `recommends` goes into the Dockerfile's `apt-get install` line too, or `tests/unit/test_container_harness.py` fails.
- The image's digest is the `debian:13` index that `release.yml` installs the package into, and the unit test keeps the two equal. Refresh both together, with the date read in the comment ([adding or changing a workflow](../../docs/project/supply-chain.md#adding-or-changing-a-workflow)).
- `tests/unit/test_container_harness.py` checks the `docker run` line, the settings file against `config.load`, the parsers, the settle loop, the image's files and the workflow's shape in every `make gate`.

## Gotchas

- A setting that `install.sh` or `tvgw-apply` reads from the template and the tier does not set is the template's value: `CO_TENANT_UNITS` names units the image does not have, and `tvgw guard cotenants` skips them.
- The listener sampler sees only the container's own network namespace, and a socket that lived for less than 0.1 seconds can escape it. It stops at the reboot, with everything else under `/run`.
- `github.com` stands for the outside because a GitHub-hosted runner always reaches it and it is not a DNS resolver, which the firewall would refuse.
