# Packaging files

This folder holds what builds the arm64 .deb: the nfpm configuration, the four maintainer scripts, the hash-pinned lock of the Python dependencies, the wheelhouse builder and the build script that ties them together. How to build, install, upgrade and remove the package, and how it relates to `deploy/install.sh`, is in [docs/packaging.md](../docs/packaging.md); this page is for whoever changes a file here.

## Files

| File | What it is | Used by |
|---|---|---|
| `build-deb.sh` | The build: refuses untracked files, builds the tvgw wheel, runs `wheelhouse.py`, writes `SHA256SUMS`, copies the tracked `deploy/` tree into `build/deb/`, runs nfpm. `TVGW_ARCH` (`arm64` or `amd64`), `TVGW_PYTHONS` (`3.11 3.12 3.13 3.14`) and `TVGW_TAG` (a release tag that must match the version) change what it builds. | `make deb`, `.github/workflows/release.yml` |
| `nfpm.yaml` | The package: name, version and architecture from the build, the dependencies, what goes where, the scripts. | `build-deb.sh` |
| `requirements.lock` | Every runtime dependency of the `lgwebos` and `analyst` extras, pinned with every published file's hash, made by `make lock` (uv). | `wheelhouse.py`; in the package, `install.sh` |
| `wheelhouse.py` | Fetches each locked dependency with `pip download --require-hashes`, one wheel per target interpreter, builds the few that publish only a source archive, and writes the lock the package carries with those wheels' hashes added. Standard library only. | `build-deb.sh` |
| `scripts/preinst` | Refuses an install or upgrade when AdGuard Home is missing or below the floor, before anything is unpacked. | dpkg |
| `scripts/postinst` | Runs `/usr/lib/tvgw/deploy/install.sh` with `TVGW_POSTINST=1`, and reads its exit status: 0, 3 (TV not identified) and 4 (verify `FAIL`) leave the package configured, anything else fails it. Skips the install when systemd is not running. | dpkg |
| `scripts/prerm` | On removal, stops and disables the timers, then the capture units, then `tvgw.service`; on an upgrade, nothing. | dpkg |
| `scripts/postrm` | On removal, deletes what `install.sh` wrote outside the package; on purge, also `/etc/tvgw`, `/var/log/tvgw` and `tv-lan`. Keeps `/var/lib/tvgw` either way. | dpkg |

## Shared text

Two blocks of shell exist in more than one file and must stay identical; `tests/unit/test_tv_side.py` and `tests/unit/test_packaging.py` fail when they differ:

- `tvgw-adguard`, the AdGuard Home check, in `scripts/preinst` and `deploy/install.sh`. Its `AGH_MIN` must equal `verify.ADGUARD_MIN`. It is POSIX `sh`, since preinst runs under `sh`.
- `tvgw-net`, the TV-side checks, in `deploy/install.sh` and `deploy/nftables/tvgw-apply`, with `config.tv_side` as its Python twin.

Change a block in one file, copy it to the other, and run `make gate`.

## Changing it

- **A new dependency** in `pyproject.toml`: run `make lock`, review the diff, commit both. A dependency with no wheel for aarch64 and no source archive fails the build, by name.
- **A new file `install.sh` writes outside the package**: add its removal to `scripts/postrm`; `test_every_path_install_writes_is_one_postrm_knows` fails until you do, or until the test lists it as kept.
- **A new apt package `install.sh` needs**: add it to the `# Prerequisites (apt):` line of `install.sh` and to `depends` in `nfpm.yaml`; the tests compare the two.
- **The maintainer scripts** run on the gateway as root inside dpkg. Keep them POSIX `sh`, idempotent, and silent unless something needs the owner. The tests run each of them with stubs and their paths moved under a temporary directory.
- **The release job**: pin every action by commit with its version in a comment, as in `ci.yml`; `test_every_release_action_is_pinned_by_commit_with_its_version_named` checks it.

Run `make deb` after a change here and look inside the result: `ar x dist/tvgw_*.deb && tar -tvf data.tar.xz`.
