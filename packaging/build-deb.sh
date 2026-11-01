#!/bin/bash
# Build the tvgw .deb from this checkout: the wheel, the hash-pinned wheelhouse, the deploy tree, then
# nfpm. `make deb` and .github/workflows/release.yml both run this, so a local build and a release
# are the same steps (docs/packaging.md).
#   packaging/build-deb.sh [out-dir]       (default dist/)
# Needs python3 with pip and venv, nfpm and git, and network for PyPI: the wheelhouse, and the build
# backend from its own hash-pinned lock.
# Run it on Linux for a release: pip judges a dependency's environment markers by the machine it
# runs on, and the lock's markers are written for Linux.
set -euo pipefail
export PYTHONUTF8=1
cd "$(dirname "$0")/.."
OUT=${1:-dist}
STAGE=build/deb
ARCH=${TVGW_ARCH:-arm64}
# the interpreters the .deb serves: Debian 12 (3.11), Ubuntu 24.04 (3.12), Debian 13 and Raspberry
# Pi OS trixie (3.13), Ubuntu 26.04 (3.14); pure-Python wheels serve all of them, the compiled ones
# (pydantic-core, jiter, pyyaml, websockets) need one wheel per version
PYTHONS=${TVGW_PYTHONS:-3.11 3.12 3.13 3.14}
case $ARCH in
	arm64) machine=aarch64 ;;
	amd64) machine=x86_64 ;;
	*) echo "build-deb: TVGW_ARCH must be arm64 or amd64" >&2; exit 1 ;;
esac

VERSION=$(python3 -c 'import tomllib; print(tomllib.load(open("pyproject.toml", "rb"))["project"]["version"])')
# a release tag must name the version it packages: v0.1.0 builds 0.1.0 and nothing else
if [ -n "${TVGW_TAG:-}" ] && [ "$TVGW_TAG" != "v$VERSION" ]; then
	echo "build-deb: tag $TVGW_TAG does not match the version in pyproject.toml ($VERSION)" >&2
	exit 1
fi
# only what git tracks goes into the package: deploy/local/ holds a site's real settings, never shipped
if [ -n "$(git ls-files --others --exclude-standard deploy src packaging)" ] && [ -z "${TVGW_ALLOW_UNTRACKED:-}" ]; then
	echo "build-deb: untracked files under deploy/, src/ or packaging/; commit or remove them first" >&2
	git ls-files --others --exclude-standard deploy src packaging >&2
	exit 1
fi

rm -rf "$STAGE" build/lib build/venv # setuptools never prunes build/lib: a deleted module would ship again
install -d "$STAGE/wheels" "$OUT"

# 0. (packaging) the build backend, setuptools and wheel, from packaging/build-requirements.lock into
# a venv of its own, hash-checked; both wheel builds below run in it with --no-build-isolation, so pip
# never fetches an unpinned backend into an isolated build environment
python3 -m venv build/venv
PY=build/venv/bin/python
"$PY" -m pip install -q --disable-pip-version-check --require-hashes -r packaging/build-requirements.lock

# 1. the package itself, built from the tracked sources
"$PY" -m pip wheel -q --disable-pip-version-check --no-build-isolation --no-deps --wheel-dir "$STAGE/wheels" .

# 2. every dependency, from the committed lock: pip refuses any file whose hash the lock does not list,
# and the few dependencies with no wheel are built from their checked source archive
# (packaging/wheelhouse.py); the lock the package carries adds those wheels' hashes
read -r -a pythons <<<"$PYTHONS"
"$PY" packaging/wheelhouse.py --lock packaging/requirements.lock --dest "$STAGE" --machine "$machine" \
	"${pythons[@]/#/--python=}"
(cd "$STAGE/wheels" && { sha256sum -- *.whl 2>/dev/null || shasum -a 256 -- *.whl; } >../SHA256SUMS)

# 3. the deploy tree install.sh runs from, tracked files only, modes as git records them
install -d "$STAGE/deploy"
git ls-files -z deploy | tar --null -T - -cf - | tar -xf - -C "$STAGE"

# 4. the package
TVGW_VERSION=$VERSION TVGW_ARCH=$ARCH nfpm package --config packaging/nfpm.yaml --packager deb --target "$OUT/"
ls -l "$OUT"/tvgw_"$VERSION"*_"$ARCH".deb
