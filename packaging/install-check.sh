#!/bin/sh
# Install a built package on a clean system the way a user would, then check that what it carries runs
# there. release.yml runs it as root in Debian 13 and Ubuntu 24.04 containers on arm64 and amd64 before a
# release is published (docs/project/packaging.md#releases).
#   packaging/install-check.sh <path to tvgw_<version>-1_<arch>.deb>
# A container runs no systemd, so the package's postinst leaves the install for the first boot. The check
# then installs the package's wheelhouse with install.sh's own commands (offline, hash-checked, on this
# system's python3) into a scratch virtualenv, and runs tvgw and its imports from there.
set -eu

die() {
	printf 'install-check: %s\n' "$*" >&2
	exit 1
}

[ $# -eq 1 ] || die "usage: install-check.sh <path to tvgw_<version>-1_<arch>.deb>"
[ -f "$1" ] || die "no package at $1"
DEB=$(cd "$(dirname "$1")" && pwd)/${1##*/}
V=${DEB##*/tvgw_} V=${V%%-1_*}
ARCH=$(dpkg --print-architecture)
case $DEB in
*/tvgw_"$V"-1_"$ARCH".deb) ;;
*) die "$DEB is not a tvgw package for this computer's architecture ($ARCH)" ;;
esac
REPO=/usr/lib/tvgw
export DEBIAN_FRONTEND=noninteractive
apt_get() { apt-get -o DPkg::Lock::Timeout=300 -q "$@" </dev/null; }

# shellcheck source=/dev/null
echo "install-check: tvgw $V on $(. /etc/os-release && echo "$PRETTY_NAME"), $ARCH"
apt_get update
# dumpcap must stay usable by the capture user: answer No to capture by other users before apt asks
echo 'wireshark-common wireshark-common/install-setuid boolean false' | debconf-set-selections

# ---- AdGuard Home first: the package's preinst refuses a system without it at the floor (design
# decision 25). The floor release, checked against the hash its checksums.txt published (the same two as
# aghinstall.PIN's while the pin is the floor); tests/unit/test_release_publish.py keeps the version equal to
# install.sh's AGH_MIN ----
AGH_VERSION=0.107.79
case $ARCH in
arm64) AGH_SHA256=3f7893c18e8aaadc456d0452839190561c306ca95175a2254958be80a769c1ae ;;
amd64) AGH_SHA256=c48f4a43000665484c5ec28177de11a004759b620dae8f77b2aabefc9ef3687f ;;
*) die "no AdGuard Home hash for $ARCH" ;;
esac
apt_get install -y --no-install-recommends ca-certificates curl
AGH_TAR=$(mktemp)
curl --proto '=https' --tlsv1.2 -fsSL --retry 3 -o "$AGH_TAR" \
	"https://github.com/AdguardTeam/AdGuardHome/releases/download/v$AGH_VERSION/AdGuardHome_linux_$ARCH.tar.gz"
echo "$AGH_SHA256  $AGH_TAR" | sha256sum -c -
tar -xzf "$AGH_TAR" -C /opt
rm -f "$AGH_TAR"
/opt/AdGuardHome/AdGuardHome --version
# ---- end AdGuard Home ----

apt_get install -y "$DEB"
# shellcheck disable=SC2016 # ${db:Status-Status} is dpkg-query's field, not the shell's
[ "$(dpkg-query -W -f '${db:Status-Status}' tvgw)" = installed ] || die "dpkg does not have tvgw installed"

# the wheelhouse, exactly as install.sh installs it from the package
(cd "$REPO/wheels" && sha256sum --quiet --strict -c ../SHA256SUMS)
VENV=$(mktemp -d)/venv
python3 -m venv "$VENV"
"$VENV"/bin/pip install -q --no-index --find-links "$REPO/wheels" --require-hashes -r "$REPO/requirements.lock"
"$VENV"/bin/pip install -q --no-index --no-deps --force-reinstall "$REPO"/wheels/tvgw-*.whl
have=$("$VENV"/bin/tvgw --version)
[ "$have" = "tvgw $V" ] || die "the package's tvgw says '$have', not 'tvgw $V'"
"$VENV"/bin/python -c 'import bscpylgtv, anthropic, yaml'
echo "install-check: tvgw $V installs on $ARCH with $("$VENV"/bin/python -V), and its imports load"
