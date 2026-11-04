#!/bin/sh
# Write a release's own files beside its two packages: SHA256SUMS of both, then get.sh, rendered from
# packaging/get.sh.in with the version and both packages' hashes written in, then get.sh's own line in
# SHA256SUMS. release.yml runs it once both .deb files are built (docs/project/packaging.md#releases), and the
# unit tests run it to make the get.sh they test.
#   packaging/release-assets.sh <version> <dir>    (dir holds tvgw_<version>-1_arm64.deb and _amd64.deb)
# Nothing here reads the network.
set -eu

die() {
	printf 'release-assets: %s\n' "$*" >&2
	exit 1
}

[ $# -eq 2 ] || die "usage: release-assets.sh <version> <dir>"
V=$1 DIR=$2
# the version goes into a sed replacement and a file name: dotted numbers only
case $V in
"" | .* | *. | *..* | *[!0-9.]*) die "the version must be dotted numbers such as 0.3.0, not '$V'" ;;
esac
TEMPLATE=$(cd "$(dirname "$0")" && pwd)/get.sh.in
[ -f "$TEMPLATE" ] || die "no template at $TEMPLATE"
cd "$DIR"
ARM64=tvgw_${V}-1_arm64.deb AMD64=tvgw_${V}-1_amd64.deb
for deb in "$ARM64" "$AMD64"; do
	[ -f "$deb" ] || die "no $deb in $DIR"
done

sha256sum "$ARM64" "$AMD64" >SHA256SUMS
A=$(awk -v f="$ARM64" '$2 == f { print $1 }' SHA256SUMS)
B=$(awk -v f="$AMD64" '$2 == f { print $1 }' SHA256SUMS)
for h in "$A" "$B"; do
	case $h in
	*[!0-9a-f]* | "") die "sha256sum gave '$h', not a SHA-256" ;;
	esac
	[ ${#h} -eq 64 ] || die "sha256sum gave '$h', not a SHA-256"
done

sed -e "s/@VERSION@/$V/g; s/@SHA256_ARM64@/$A/; s/@SHA256_AMD64@/$B/" "$TEMPLATE" >get.sh.new
if grep -n '@[A-Z][A-Z0-9_]*@' get.sh.new >&2; then
	rm -f get.sh.new
	die "get.sh.in has a field this script does not fill (the lines above)"
fi
chmod 755 get.sh.new
mv -f get.sh.new get.sh
sha256sum get.sh >>SHA256SUMS
cat SHA256SUMS
