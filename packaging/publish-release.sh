#!/bin/sh
# Publish a tag's GitHub release from the files release.yml made: create the release as a draft, upload
# every file to the draft, then publish it, marked latest only when no newer release is published.
# Draft first because, once immutable releases are on, a published release's files can never change:
# it is never public with a file missing (docs/packaging.md#releases). A draft left by a failed run is
# refreshed and published; a release that is already published is refused.
#   GH_TOKEN=<token> GH_REPO=<owner>/<repo> packaging/publish-release.sh <tag> <dir>
# <dir> holds tvgw_<version>-1_arm64.deb, tvgw_<version>-1_amd64.deb, get.sh, SHA256SUMS and
# RELEASE_NOTES.md, as packaging/release-assets.sh and packaging/release_notes.py write them.
set -eu

die() {
	printf 'publish-release: %s\n' "$*" >&2
	exit 1
}

version_at_least() { # is dotted version $1 at least $2? (the same test as install.sh's AdGuard check)
	_have=$1. _want=$2.
	case $_have$_want in *[!0-9.]* | *..*) return 1 ;; esac
	while [ -n "$_want" ]; do
		_a=${_have%%.*} _b=${_want%%.*}
		_have=${_have#*.} _want=${_want#*.}
		[ "${_a:-0}" -gt "$_b" ] && return 0
		[ "${_a:-0}" -lt "$_b" ] && return 1
	done
	return 0
}

[ $# -eq 2 ] || die "usage: publish-release.sh <tag> <dir>"
TAG=$1 DIR=$2
V=${TAG#v}
[ "v$V" = "$TAG" ] || die "a release tag is v and the version, such as v0.3.0, not '$TAG'"
case $V in
"" | .* | *. | *..* | *[!0-9.]*) die "a release tag is v and the version, such as v0.3.0, not '$TAG'" ;;
esac
NOTES=$DIR/RELEASE_NOTES.md
set -- "$DIR/tvgw_${V}-1_arm64.deb" "$DIR/tvgw_${V}-1_amd64.deb" "$DIR/get.sh" "$DIR/SHA256SUMS"
for f in "$@" "$NOTES"; do
	[ -f "$f" ] || die "no $f: nothing was created or changed"
done

ERR=$(mktemp)
trap 'rm -f "$ERR"' EXIT
view() { # gh release view "$@": its answer, or nothing when GitHub has no such release
	# any other failure (a timeout, a 5xx, a rate limit) is not "no release": a second draft for the tag,
	# or an older release marked latest, would follow from reading it as one
	if gh release view "$@" 2>"$ERR"; then
		return 0
	fi
	if grep -Fqx 'release not found' "$ERR"; then
		return 0
	fi
	cat "$ERR" >&2
	return 1
}

state=$(view "$TAG" --json isDraft --jq .isDraft) ||
	die "could not ask GitHub about $TAG's release (the line above); nothing was created or changed"
case ${state:-none} in
none) gh release create "$TAG" --verify-tag --draft --title "tvgw $V" --notes-file "$NOTES" ;;
true)
	echo "publish-release: $TAG has a draft from an earlier run; its notes and files are replaced"
	gh release edit "$TAG" --title "tvgw $V" --notes-file "$NOTES"
	;;
*) die "$TAG is already published, and a published release is never changed: release a new version" ;;
esac
gh release upload "$TAG" "$@" --clobber

# GitHub's latest release is what releases/latest/download/get.sh serves: a fix released for an older
# line must not take it from a newer one
latest=--latest
current=$(view --json tagName --jq .tagName) ||
	die "could not ask GitHub which release is the latest (the line above); $TAG is still a draft with every file"
if [ -n "$current" ] && ! version_at_least "$V" "${current#v}"; then
	echo "publish-release: $current stays the latest release; $TAG is older"
	latest=--latest=false
fi
gh release edit "$TAG" --draft=false "$latest"
gh release view "$TAG" --json url --jq .url
