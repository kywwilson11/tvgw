# Packaging

tvgw installs two ways: from a checkout with `deploy/install.sh`, as the reference gateway and CI do, or from an arm64 .deb. This page owns the .deb: what it holds, how to install, upgrade and remove it, how it relates to `install.sh`, how to build it, how a release is made, and the signed apt repository that is still to come. It is for the owner setting up a second gateway and for whoever cuts a release. It implements §8.2 and §8.4 item 1 of [the 2026-10 survey](research/state-of-the-art-2026-10.md#8-packaging-and-distro-compatibility); the decisions are [23](design-decisions.md#23-packaging-the-deb-runs-installsh), [24](design-decisions.md#24-packaging-the-tv-side-comes-from-the-settings-file) and [25](design-decisions.md#25-packaging-adguard-home-is-a-checked-dependency-never-bundled), all marked (packaging).

## What the package is

The .deb is a carrier for the installer. It holds the same `deploy/` tree a checkout has, an offline wheelhouse of every Python dependency pinned by hash, and four maintainer scripts; its postinst runs that tree's `install.sh`. So a package install, a source install and a CI deploy are one sequence of steps, and the gateway they produce is the same: the virtualenv in `/opt/tvgw-venv`, `tvgw` in `/usr/local/bin`, the scripts in `/usr/local/sbin`, the units in `/etc/systemd/system`, the settings in `/etc/tvgw/tvgw.conf` and the state in `/var/lib/tvgw` ([what install.sh does](../deploy/README.md#what-installsh-does)).

| Path in the package | What it is |
|---|---|
| `/usr/lib/tvgw/deploy/` | The tracked files of `deploy/`, with their modes: `install.sh`, the templates, the units, the scripts and their READMEs. |
| `/usr/lib/tvgw/wheels/` | The tvgw wheel and one wheel per dependency and interpreter: CPython 3.11 (Debian 12), 3.12 (Ubuntu 24.04), 3.13 (Debian 13, Raspberry Pi OS trixie) and 3.14, for aarch64. |
| `/usr/lib/tvgw/requirements.lock` | `packaging/requirements.lock`, plus the hash of each wheel the build made from a source archive. |
| `/usr/lib/tvgw/SHA256SUMS` | The hash of every file in `wheels/`, made by the build. |
| `/usr/share/doc/tvgw/` | The license (`copyright`) and this page. |

The package depends on `python3 (>= 3.11)`, `python3-venv`, `nftables`, `iproute2`, `procps`, `kmod`, `util-linux`, `network-manager`, `dnsmasq`, `nginx`, `libnginx-mod-stream`, `tcpdump`, `conntrack`, `tshark`, `curl`, `ca-certificates` and `systemd`, and recommends `logrotate`. It does not depend on AdGuard Home, which has no .deb ([AdGuard Home](#adguard-home)).

```mermaid
flowchart LR
  subgraph source["From a checkout"]
    checkout["/opt/tvgw/src<br/>make deploy, CI"] --> sync["sync-install.sh<br/>install lock"]
  end
  subgraph deb["From the .deb"]
    apt["apt install ./tvgw_*.deb"] --> preinst["preinst<br/>AdGuard Home check"]
    preinst --> postinst["postinst<br/>TVGW_POSTINST=1"]
  end
  sync --> installSrc["deploy/install.sh<br/>pip install the checkout"]
  postinst --> installPkg["/usr/lib/tvgw/deploy/install.sh<br/>pip install --no-index --require-hashes"]
  installSrc --> gateway(["the same gateway:<br/>/opt/tvgw-venv, units, firewall, tvgw verify"])
  installPkg --> gateway
```

*Both paths end in the same installer. Only step 5, where the Python package comes from, differs.*

### How install.sh tells the two apart

`install.sh` runs in package mode when it finds `requirements.lock` and `wheels/` beside its tree, which is the package's layout and never a checkout's. In package mode, step 5 checks the wheelhouse against `SHA256SUMS` (a card that corrupts a file fails here, not in a running unit), installs the dependencies with `pip install --no-index --find-links /usr/lib/tvgw/wheels --require-hashes -r /usr/lib/tvgw/requirements.lock`, and installs the tvgw wheel with `--no-deps --force-reinstall`. Nothing is fetched from the network. Every other step is the same in both modes.

The postinst sets `TVGW_POSTINST=1` and closes stdin, so `install.sh` never prompts, and it reads the installer's exit status ([design decision 23 (packaging)](design-decisions.md#23-packaging-the-deb-runs-installsh)):

| `install.sh` ends with | From a checkout | Under the postinst |
|---|---|---|
| 0, verify passed | exit 0 | the package is configured |
| 75, the TV is not identified | exit 75 without a terminal; with one, it runs discovery instead | the package is configured; the postinst says to cable the TV and run `sudo /usr/lib/tvgw/deploy/install.sh` |
| 76, verify reported a `FAIL` | not used: `exec tvgw verify` exits 1 | the package is configured; the postinst says to fix what verify named |
| 1, a step stopped the install | exit 1 | the configuration fails; dpkg marks the package half-configured and `sudo dpkg --configure -a` runs the install again |

Any other status also fails the configuration. A stop is always 1: `install.sh` traps `ERR` (with `set -E`, so in functions and subshells too) and exits 1 whatever the failing command returned. Under `set -e` alone the command's own status became the installer's, and nmcli exits 3 on a timeout and 4 when an activation fails, so a half-done install once read as one of the deliberate exits and dpkg called it configured. The two deliberate exits are 75 and 76 for the same reason: no command `install.sh` runs returns them.

## Before you install

- An arm64 machine with Raspberry Pi OS trixie or Debian 12 or 13, booted with systemd and NetworkManager. Debian 13 and Raspberry Pi OS trixie are the tested base; Ubuntu 24.04 and 26.04 have the interpreters but are untested ([the survey's support policy](research/state-of-the-art-2026-10.md#83-compatibility-matrix)).
- A TV port and an uplink. The defaults are `eth0` for the TV and `wlan0` for the uplink; another port is the setting `TV_IF` ([the TV side](../deploy/README.md#the-tv-side)).
- AdGuard Home, installed natively in `/opt/AdGuardHome`, at least v0.107.73, with its first-run wizard done ([AdGuard Home](#adguard-home)). Without it the package refuses to install and changes nothing.

## AdGuard Home

AdGuard Home is a checked dependency and is never bundled ([design decision 25 (packaging)](design-decisions.md#25-packaging-adguard-home-is-a-checked-dependency-never-bundled)). It is the resolver every TV lookup goes through, its security fixes come from its own project, and a copy inside tvgw's package would be patched only as fast as tvgw is released. It has no .deb to depend on, so three places check it, each against the floor `verify.ADGUARD_MIN`, v0.107.73, the release that fixed an authentication bypass over h2c:

| Where | When | What a missing or old AdGuard Home does |
|---|---|---|
| The package's preinst | before dpkg unpacks anything, on install and upgrade | refuses, prints the command below, and leaves the system as it was |
| `install.sh`, step 1 | on every install, from a checkout or the package | stops right after taking the install lock, before it writes anything else |
| `tvgw verify`, `adguard_version` | every 10 minutes and at the end of every install | `FAIL` with the install command, or with the update command when it is below the floor |

To install it, as its project documents (<https://github.com/AdguardTeam/AdGuardHome#getting-started>):

```sh
curl -s -S -L https://raw.githubusercontent.com/AdguardTeam/AdGuardHome/master/scripts/install.sh | sh -s -- -v
```

Then finish its wizard on port 3000, through an ssh tunnel (`ssh -L 3000:127.0.0.1:3000 <ssh-host>`). Give the DNS server a listen address that covers both `GW_IP` (`10.10.10.1` by default) and `127.0.0.1` on port 53; all interfaces does. To update it, use its web UI or `sudo /opt/AdGuardHome/AdGuardHome --update`.

## Installing from the .deb

1. Download `tvgw_<version>-1_arm64.deb` and `SHA256SUMS` from the release, and check them:
   ```sh
   sha256sum -c SHA256SUMS
   ```
2. Install it; apt pulls in the dependencies:
   ```sh
   sudo apt install ./tvgw_<version>-1_arm64.deb
   ```
   On a new gateway the install stops by design before it loads the firewall: the TV is not identified yet, and the settings still hold the template's uplink. The postinst prints `installed but not finished`, and the package is installed.
3. Set the uplink, and the TV side if it is not the default, in the settings file the install created:
   ```sh
   sudoedit /etc/tvgw/tvgw.conf      # WAN_IF, WAN_GW; TV_IF, TV_NET, GW_IP only if not eth0 and 10.10.10.0/24
   ```
4. Cable the TV to the TV port, make it forget its Wi-Fi networks, switch it on, and run the installer from a terminal. It finds the TV with `tvgw discover`, finishes the install and ends with `tvgw verify`:
   ```sh
   sudo /usr/lib/tvgw/deploy/install.sh
   ```
5. Every line of `sudo tvgw verify` must start with `OK`. The remaining first-day steps, pairing the TV's LAN API and the analyst's key, are the same as from a checkout ([the quick start](../README.md#quick-start), steps 8 and 9).

An install in an image build or a chroot, with no running systemd, unpacks the package and does nothing else; run `sudo /usr/lib/tvgw/deploy/install.sh` on the first boot.

## Upgrading

```sh
sha256sum -c SHA256SUMS
sudo apt install ./tvgw_<new-version>-1_arm64.deb
```

The old prerm stops nothing on an upgrade, and the new postinst runs `install.sh`, which keeps the settings file and `block4.txt`, re-applies the firewall in place without a gap, and restarts a long-running unit only when what it started with changed ([what is idempotent](../deploy/README.md#what-is-idempotent)). An upgrade disturbs what any re-run of `install.sh` disturbs: nginx reloads, dnsmasq restarts, and the firewall's counters reset, which the next `tvgw verify --record` accounts for. Once the signed repository exists, `sudo apt update && sudo apt upgrade` does the same.

## Removing

```sh
sudo apt remove tvgw      # or: sudo apt purge tvgw
```

| | `remove` | `purge` |
|---|---|---|
| The timers, the capture units, then `tvgw.service` | stopped and disabled; the firewall's stop turns forwarding off first, so the TV is dark, never unfiltered | the same |
| What `install.sh` wrote: `/usr/local/sbin/tvgw-*`, `/usr/local/bin/tvgw`, the units and their drop-ins, the dnsmasq, nginx, NetworkManager and logrotate files, the `include` line in `nginx.conf`, `/opt/tvgw-venv` | removed | removed |
| `/etc/tvgw` (settings, `block4.txt`, the analyst's key) and `/var/log/tvgw` | kept | removed |
| The `tv-lan` connection | kept | deleted |
| `/var/lib/tvgw`: the store, the pcaps, the reports, the TV pairing key | kept | kept, with a message: `sudo rm -rf /var/lib/tvgw` deletes it |
| AdGuard Home, its configuration, its `workdir.conf` drop-in, the `tvgw-pcap` user, the mask on `nftables.service` | left as they are | left as they are |

Purge keeps the store because it is up to a year of evidence and a habitual purge must not destroy it ([design decision 23 (packaging)](design-decisions.md#23-packaging-the-deb-runs-installsh)). AdGuard Home keeps the rules tvgw last applied; change them in its UI or reinstall it. `nftables.service` stays masked: unmask it with `sudo systemctl unmask nftables` if you want it.

## How the .deb and install.sh relate

- `install.sh` remains the from-source path and the CI deploy path: `make deploy` and the hardware job run `sync-install.sh`, which runs `install.sh` from `/opt/tvgw/src` ([how a change reaches the gateway](../deploy/README.md#how-a-change-reaches-the-gateway)). The reference gateway stays on that path.
- Both paths take the install lock, `/run/tvgw/install.lock`, so a package install and a CI deploy never interleave.
- Both write the same files, so whichever ran last owns the gateway. A `make deploy` or a CI deploy on a gateway installed from the .deb replaces its Python package with the checkout's until the next package install, and the next package install does the reverse. Keep each gateway on one path.
- A source install resolves the dependencies at install time, unpinned; the package installs exactly the lock. Moving the source path onto the lock is a follow-up, not done here, because it would change the reference gateway's dependency versions on the next deploy.
- `tests/unit/test_packaging.py` keeps the two in step: the layout `install.sh` looks for, the shared AdGuard Home check, and the paths postrm removes against the paths `install.sh` writes.

## Building the .deb

You need Python 3.11 or newer with pip, git, and nfpm (`brew install nfpm`, or a release from <https://github.com/goreleaser/nfpm/releases>). Build from a checkout with nothing untracked under `deploy/`, `src/` or `packaging/`:

```sh
make deb               # dist/tvgw_<version>-1_arm64.deb
```

`make deb` runs `packaging/build-deb.sh`, which the release workflow runs too:

1. Refuses untracked files under `deploy/`, `src/` or `packaging/`, because `deploy/local/` holds a site's real settings; only what git tracks is packaged.
2. Creates a build venv, `build/venv`, and installs the build backend into it from `packaging/build-requirements.lock` with `--require-hashes`: setuptools, wheel and wheel's one dependency, packaging. Both wheel builds below run in that venv with `--no-build-isolation`, so pip never fetches an unpinned backend into an isolated build environment, and a changed backend cannot reach a release unhashed.
3. Builds the tvgw wheel from a fresh build directory.
4. Runs `packaging/wheelhouse.py`, which fetches every dependency in `packaging/requirements.lock` with `pip download --require-hashes`, one wheel per target interpreter for aarch64 ([packaging/README.md](../packaging/README.md)). A file PyPI serves that the lock does not list is refused. A dependency with no wheel at all, today only `sqlitedict`, is fetched as its source archive against the lock's hash and built into a pure-Python wheel; that wheel's hash is added to the lock the package carries, so the gateway's pip checks it too.
5. Writes `SHA256SUMS` of the wheelhouse and copies the tracked `deploy/` tree.
6. Runs `nfpm package` with `packaging/nfpm.yaml`.

`TVGW_ARCH=amd64` builds an amd64 package from the same steps. Build releases on Linux: pip judges a dependency's environment markers by the machine it runs on.

### The lock

`packaging/requirements.lock` pins every runtime dependency of the `lgwebos` and `analyst` extras, the ones `install.sh` installs, with every published file's hash, resolved for Python 3.11 and later on any platform. Regenerate it after a change to `pyproject.toml`'s dependencies, and to take dependency updates, with uv at the version the Makefile pins (`UV_VERSION`; `pip install uv==<that version>`). `make lock` refuses any other uv, since another version may resolve or annotate the lock differently. It also regenerates `packaging/build-requirements.lock` from `packaging/build-requirements.in`, the pinned build backend; raise those pins on purpose, once a release is two weeks old:

```sh
make lock
git diff packaging/requirements.lock   # review what moved
```

## Releases

A tag `vX.Y.Z` on a commit whose `pyproject.toml` says `version = "X.Y.Z"` runs `.github/workflows/release.yml`:

1. It runs `make gate`, so the package is what passed the unit tests.
2. It installs nfpm 2.48.0, checked against its published SHA-256.
3. It runs `packaging/build-deb.sh` with `TVGW_TAG` set, which refuses a tag that does not match the version.
4. It writes `SHA256SUMS` for the package and attaches both to the GitHub Release of the tag, creating the release when it does not exist.

A manual run (`workflow_dispatch`) on any ref builds the same package and keeps it as the workflow artifact `tvgw-deb`, without a release. The job has `contents: write` and nothing else, every action is pinned by commit with its version in a comment, and the checkout keeps no credentials. A tag never deploys: `ci.yml` runs only for pushes to `main`.

```sh
git tag -s v0.2.0 -m "tvgw 0.2.0"    # after bumping the version in pyproject.toml and the CHANGELOG
git push origin v0.2.0
```

## A signed apt repository

Not built yet: it needs a signing key that only the owner may create and hold. Whoever holds that key can change the firewall of every gateway that runs `apt upgrade`, so it is made on a trusted machine, its secret half stays offline, and its public half is the only part that goes anywhere. These are the steps, in order; nothing in the repository generates a key.

1. **Make the key**, once, on a trusted machine:
   ```sh
   gpg --quick-generate-key "tvgw archive signing key <owner@example.org>" ed25519 sign 2y
   FPR=$(gpg --list-secret-keys --with-colons | awk -F: '/^fpr/ {print $10; exit}')
   gpg --export "$FPR" >tvgw-archive-keyring.pgp                       # the public keyring
   gpg --export-secret-keys --armor "$FPR" >tvgw-archive-signing.asc    # the backup: offline media only
   ```
2. **Make the repository** with reprepro, in a directory published as static files (a GitHub Pages branch of a separate repository, say):
   ```sh
   mkdir -p apt/conf
   cat >apt/conf/distributions <<EOF
   Origin: tvgw
   Label: tvgw
   Codename: stable
   Architectures: arm64
   Components: main
   Description: tvgw gateway packages
   SignWith: $FPR
   EOF
   reprepro -b apt includedeb stable dist/tvgw_<version>-1_arm64.deb
   ```
   Publish `apt/dists` and `apt/pool`, never `apt/conf` or `apt/db`, and publish `tvgw-archive-keyring.pgp` beside them.
3. **On each gateway**, add the key and a deb822 source with `Signed-By`, as Debian asks of third-party repositories (<https://wiki.debian.org/DebianRepository/UseThirdParty>):
   ```sh
   sudo install -D -m 644 tvgw-archive-keyring.pgp /etc/apt/keyrings/tvgw-archive-keyring.pgp
   sudo tee /etc/apt/sources.list.d/tvgw.sources >/dev/null <<EOF
   Types: deb
   URIs: https://<repository-host>/apt
   Suites: stable
   Components: main
   Architectures: arm64
   Signed-By: /etc/apt/keyrings/tvgw-archive-keyring.pgp
   EOF
   sudo apt update && sudo apt install tvgw
   ```
4. **To sign in CI** instead of by hand, store the armored secret key as a secret of a GitHub environment that requires the owner's approval, and add a job after `deb` in `release.yml` that imports it, runs `reprepro includedeb` and pushes the published tree. Until then, add each release by hand with step 2.
5. **Before the key expires** (two years with the command above), extend it with `gpg --quick-set-expire "$FPR" 2y`, export the keyring again and replace it on every gateway. A key that may have leaked is replaced, not extended: make a new one, publish its keyring, and sign the repository again.

## Limits

- Not yet run on hardware: the package was built and inspected on a workstation, and its offline, hash-checked install was resolved for Linux aarch64 with pip's dry run, but no gateway has installed it ([checking a package on a gateway](#checking-a-package-on-a-gateway)).
- arm64 only, and no .rpm or Arch package yet; nfpm builds both from the same YAML when a tier-3 distribution is wanted ([the survey's verdicts](research/state-of-the-art-2026-10.md#82-packaging-verdicts)).
- The firewall front-end is not detected: on a host running firewalld or ufw, their drops still apply to the TV's traffic (§8.4 item 3).
- Whether `nmcli con add` makes a keyfile or netplan YAML on Raspberry Pi OS images from November 2025 on is unverified (§8.1).
- `make wheel`, a developer convenience, still builds with pip's isolated, unpinned backend; `make deb` and the release do not ([building the .deb](#building-the-deb)).

## Checking a package on a gateway

On a spare gateway, or on the reference one with the owner's go-ahead (the package replaces the source install's Python package until the next deploy):

```sh
sudo apt install ./tvgw_<version>-1_arm64.deb                # install.sh's output, then verify's lines
sudo tvgw verify                                             # every line OK
dpkg -s tvgw | grep Status                                   # install ok installed
sudo apt install --reinstall ./tvgw_<version>-1_arm64.deb    # a second run restarts only what install.sh documents
sudo apt remove tvgw
cat /proc/sys/net/ipv4/conf/eth0/forwarding                  # 0: the TV is dark
sudo nft list table inet tvgw                                # gone
ls /usr/local/bin/tvgw /opt/tvgw-venv                        # gone; /etc/tvgw and /var/lib/tvgw are still there
```
