# Packaging files

This folder holds what builds the .deb for arm64 and amd64 and what a release carries beside it: the nfpm configuration, the four maintainer scripts, the hash-pinned lock of the Python dependencies, the wheelhouse builder and the build script that ties them together, then the installer template, the release scripts and the notes writer. How to build, install, upgrade and remove the package, how it relates to `deploy/install.sh`, and how a release is made and checked, is in [docs/project/packaging.md](../docs/project/packaging.md); this page is for whoever changes a file here.

## Files

| File | What it is | Used by |
|---|---|---|
| `build-deb.sh` | The build: refuses untracked files, installs the pinned build backend into `build/venv`, builds the tvgw wheel, runs `wheelhouse.py`, writes `SHA256SUMS`, copies the tracked `deploy/` tree into `build/deb/`, runs nfpm. `TVGW_ARCH` (`arm64` or `amd64`), `TVGW_PYTHONS` (`3.11 3.12 3.13 3.14`) and `TVGW_TAG` (a release tag that must match the version) change what it builds. | `make deb`, `.github/workflows/release.yml` |
| `nfpm.yaml` | The package: name, version and architecture from the build, the dependencies, what goes where, the scripts. | `build-deb.sh` |
| `requirements.lock` | Every runtime dependency of the `lgwebos` and `analyst` extras, pinned with every published file's hash, made by `make lock` (uv). | `wheelhouse.py`; in the package, `install.sh` |
| `build-requirements.in`, `build-requirements.lock` | The build backend (setuptools, wheel, and wheel's dependency packaging), pinned with hashes; `make lock` compiles the lock from the `.in`. `build-deb.sh` installs it into `build/venv` with `--require-hashes` and builds both wheels there with `--no-build-isolation`. | `build-deb.sh`, `wheelhouse.py` |
| `wheelhouse.py` | Fetches each locked dependency with `pip download --require-hashes`, one wheel per target interpreter, builds the few that publish only a source archive, and writes the lock the package carries with those wheels' hashes added. Standard library only. | `build-deb.sh` |
| `scripts/preinst` | Refuses an install or upgrade when AdGuard Home is missing or below the floor, before anything is unpacked. | dpkg |
| `scripts/postinst` | Runs `/usr/lib/tvgw/deploy/install.sh` with `TVGW_POSTINST=1`, and reads its exit status: 0, 75 (TV not identified) and 76 (verify `FAIL`) leave the package configured, anything else fails it; `install.sh`'s `ERR` trap makes every other stop 1. Skips the install when systemd is not running. | dpkg |
| `scripts/prerm` | On removal, stops and disables the timers, then the capture units, then `tvgw.service`; on an upgrade, nothing. | dpkg |
| `scripts/postrm` | On removal, deletes what `install.sh` wrote outside the package; on purge, also `/etc/tvgw`, `/var/log/tvgw` and `tv-lan`. Keeps `/var/lib/tvgw` either way. | dpkg |
| `get.sh.in` | The one-line installer, with `@VERSION@`, `@SHA256_ARM64@` and `@SHA256_AMD64@` for the release to fill: checks the computer, downloads the package from its own release, refuses it unless its hash matches, installs it with apt while a `policy-rc.d` of its own holds the services, and hands over to `tvgw setup` ([the installer](../docs/project/packaging.md#the-installer-getsh)). POSIX `sh`, everything inside `main`. | `release-assets.sh`; the released `get.sh` runs on a user's computer |
| `release-assets.sh` | Writes `SHA256SUMS` of a release's two packages, renders `get.sh` from `get.sh.in` with `sed` (refusing a field left unfilled) and adds `get.sh` to `SHA256SUMS`. Reads nothing from the network. | `release.yml`'s `assets` job, `tests/unit/test_get_sh.py` |
| `release_notes.py` | Writes the release notes from `CHANGELOG.md`'s section for the version (its `### Highlights` and `### Status`), the release's `SHA256SUMS` and `.github/release-notes.md.in`; refuses a section that is missing either block, a highlight in an engineer's words, or notes over 60 lines. Standard library only. | `release.yml`'s `gate` and `assets` jobs |
| `install-check.sh` | Installs a built package in a clean container as a user would (AdGuard Home at the floor first, while the preinst requires it), then the package's wheelhouse with `install.sh`'s commands into a scratch virtualenv, and checks `tvgw --version` and the imports. | `release.yml`'s `install-check-<arch>` jobs |
| `publish-release.sh` | Creates a tag's release as a draft, uploads every file to it, then publishes it, latest only when no newer version is published; refreshes a draft a failed run left and refuses a published release; stops on any GitHub error other than "release not found". | `release.yml`'s `publish` job |

## Shared text

Two blocks of shell exist in more than one file and must stay identical; `tests/unit/test_tv_side.py` and `tests/unit/test_packaging.py` fail when they differ:

- `tvgw-adguard`, the AdGuard Home check, in `scripts/preinst` and `deploy/install.sh`. Its `AGH_MIN` must equal `verify.ADGUARD_MIN`. It is POSIX `sh`, since preinst runs under `sh`.
- `tvgw-net`, the TV-side checks, in `deploy/install.sh` and `deploy/nftables/tvgw-apply`, with `config.tv_side` as its Python twin.

Change a block in one file, copy it to the other, and run `make gate`.

## Changing it

- **A new dependency** in `pyproject.toml`: run `make lock` with the pinned uv (`UV_VERSION` in the Makefile), review the diff, commit both.
- **A newer build backend**: raise the pins in `build-requirements.in` once the release is two weeks old, run `make lock`, and build a .deb to check it. A dependency with no wheel for aarch64 and no source archive fails the build, by name.
- **A new file `install.sh` writes outside the package**: add its removal to `scripts/postrm`; `test_every_path_install_writes_is_one_postrm_knows` fails until you do, or until the test lists it as kept.
- **A new apt package `install.sh` needs**: add it to the `# Prerequisites (apt):` line of `install.sh` and to `depends` in `nfpm.yaml`; the tests compare the two.
- **The maintainer scripts** run on the gateway as root inside dpkg. Keep them POSIX `sh`, idempotent, and silent unless something needs the owner. The tests run each of them with stubs and their paths moved under a temporary directory.
- **The release job**: pin every action by commit with its version in a comment, as in `ci.yml`, and every container image by digest; `test_every_release_action_is_pinned_by_commit_with_its_version_named` and `test_every_container_image_is_pinned_by_digest` check them. Keep the build's third-party code out of the job that signs, and `contents: write` on the tag-only `publish` job ([supply chain](../docs/project/supply-chain.md#adding-or-changing-a-workflow)).
- **The installer**: a new step in `get.sh.in` goes inside a function that `main` calls, never at the top level, so a cut download still runs nothing; a new field `@NAME@` needs `release-assets.sh` to fill it, or the render fails. `tests/unit/test_get_sh.py` runs the rendered script under `sh` and `dash` with stubs, and through shellcheck when it is installed.
- **The release notes**: `.github/release-notes.md.in` is the page a user reads first. Its links into the repository at the tag must exist at the tree a tag is cut from (`test_every_page_the_template_links_at_the_tag_exists_with_its_heading`).
- **The maintainer scripts and the POSIX scripts**: `make gate` runs `shellcheck -s sh -S warning` over the Makefile's `SH_PATHS` when shellcheck is installed; a new `#!/bin/sh` script under `deploy/` or `packaging/` is listed there (`test_every_posix_script_is_shellchecked_by_the_gate`).

Run `make deb` after a change here and look inside the result: `ar x dist/tvgw_*.deb && tar -tvf data.tar.xz`.
