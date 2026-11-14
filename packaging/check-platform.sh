#!/bin/sh
# Check that one distribution's own programs run what tvgw installs (docs/project/packaging.md#the-platform-check).
# distro.yml runs it as root in Debian 12 and 13 and Ubuntu 24.04 and 26.04 containers, on arm64 and amd64,
# for every pull request and push (--source); release.yml runs it on each package it builds (--package).
#
#   packaging/check-platform.sh --source              the checkout this script is in
#   packaging/check-platform.sh --package <file.deb>  tvgw_<version>-1_<arch>.deb, built in the job
#   packaging/check-platform.sh --package v<version>  that release's package for this computer, downloaded
#   packaging/check-platform.sh --list-depends        print the package's Depends and stop (needs nothing)
#
# What it does, in order:
#   1. installs what the package depends on, with no service started: --source, packaging/nfpm.yaml's
#      Depends through `apt-get satisfy`, so a name or a version this distribution lacks fails here;
#      --package, the package itself through packaging/install-check.sh, which also installs its
#      wheelhouse offline and hash-checked and runs `tvgw --version` and the imports;
#   2. records the versions of nft, systemd, python3, dnsmasq, nginx, dumpcap, conntrack and the kernel;
#   3. --source: the unit suite, in a virtualenv on this distribution's python3, as an unprivileged user,
#      with git, which its tests of the repository's tools run on throwaway repositories (the suite's
#      own tool, not a Depends); every test it skips is listed with its reason;
#   4. `tvgw-apply --check` with this distribution's nft against the running kernel, with the TV on dummy0
#      and the uplink on dummy1, for settings that between them give every switch each of its values, and
#      the container's nftables tables after it as they were before;
#   5. one second of dumpcap with tvgw-pcap.service's own ring options, whose file must be named
#      tv_<14 digits>_00001.pcap, and dumpcap executable by the capture user;
#   6. `nginx -t` of the URL filter's files, with the stream include appended to nginx.conf (what install.sh
#      writes today) and as modules-enabled/99-tvgw-stream.conf (nginx.conf left as shipped);
#   7. `dnsmasq --test` of the DHCP file: open with the TV not yet known, open with it pinned, and pinned
#      (TV_DHCP=pinned: the pinned TV alone is answered);
#   8. `systemd-analyze verify` of tvgw's units and of its drop-ins for dnsmasq and nginx; a finding on a
#      tvgw file fails the check unless ALLOWED below names it for this distribution, with its reason.
# Every check runs, and the run fails at the end when any failed. It writes system files, so it runs only
# in a throwaway container: outside one, or beside an /etc/tvgw it did not make (a gateway's), it stops
# before it changes anything. TVGW_PLATFORM_OUT names the folder it writes the versions, the rendered files
# and the logs to (the job's artifact). TVGW_ROOT (a directory the system paths are read and written under)
# and TVGW_RELEASE_BASE (where --package v<version> downloads from) exist for the tests.
set -eu

HERE=$(cd "$(dirname "$0")" && pwd)
SRC=$(cd "$HERE/.." && pwd)
ROOT=${TVGW_ROOT:-}
OUT=${TVGW_PLATFORM_OUT:-$ROOT/tmp/tvgw-platform}
BASE=${TVGW_RELEASE_BASE:-https://github.com/kywwilson11/tvgw/releases/download}
BASE=${BASE%/}
POLICY=$ROOT/usr/sbin/policy-rc.d
POLICY_MARK='# tvgw platform check: no service starts while apt runs; removed when the check ends'
MARK=$ROOT/etc/tvgw/.made-by-check-platform
CI_USER=tvgwci # runs the unit suite: as root, the tests that need an unreadable file are skipped
# the settings of the checks: the template's TV side, the ports the dummies stand for, an uplink router in
# a documentation range, and a placeholder MAC (locally administered), so the TV's pin is rendered
TV_IF=dummy0 WAN_IF=dummy1 TV_NET=10.10.10.0/24 GW_IP=10.10.10.1 TV_NETMASK=255.255.255.0
DHCP_FIRST=10.10.10.10 DHCP_LAST=10.10.10.20 TV_IP=10.10.10.17 TV_NAME=tv TV_MAC=02:00:00:00:00:17
WAN_GW=198.51.100.1 URL_FILTER_RESOLVER=1.1.1.1
# what `tvgw-apply --check` is run with, beside the template: name and settings. Between them every
# switch takes each of its values (tests/virtual checks every combination on the runner's own nft)
# (attention) LIVE_READING=on rides with inpath: the attention count's table, at its default count
# (inpath) DNSGATE_FILL=inpath has a variant of its own, so headers is still rendered passive as it always
# was: its queue rules are read by this distribution's nft and the runner's kernel, which loads nft_queue.
# (namebound) NAME_BINDING=count rides with headers, the other variant whose rules copy to NFLOG
# (mint) MINT=shadow rides with inpath, the only variant whose filler keeps its table
VARIANTS='default:
vpn:UPLINK=vpn
headers:CAPTURE_MODE=headers TV_PROBE=on NAME_BINDING=count
open:BLOCK_QUIC=no STRICT_PORTS=yes DNSGATE=off ADTECH_PORT_WALL=no
inpath:DNSGATE_FILL=inpath LIVE_READING=on MINT=shadow'
# The findings `systemd-analyze verify` may report on a tvgw file on one distribution, each with the reason
# it is accepted there, one per line: <ID>-<VERSION_ID>|<the finding's text>|<why>
ALLOWED="debian-12|Unknown key 'RestartSteps' in section [Service], ignoring.|systemd 252 predates RestartSteps (254): tvgw-dnsgate restarts every 5 s instead of backing off to 5 min
debian-12|Unknown key 'RestartMaxDelaySec' in section [Service], ignoring.|systemd 252 predates RestartMaxDelaySec (254), the other half of the same back-off"
FAILED=
TMP=

say() { printf 'check-platform: %s\n' "$*"; }

stop() {
	printf 'check-platform: %s\n' "$*" >&2
	exit 1
}

not_installed() { # nothing can be checked without the programs: the verdict, and stop
	printf 'fail: install\n' >"$OUT/result.txt"
	stop "$1"
}

failed() { # a check failed: say why and carry on with the next one
	printf 'check-platform: FAIL: %s: %s\n' "$1" "$2" >&2
	FAILED="$FAILED $1"
}

usage() {
	stop "usage: check-platform.sh --source | --package <tvgw_<version>-1_<arch>.deb | v<version>> | --list-depends"
}

list_depends() { # packaging/nfpm.yaml's depends, one Debian dependency per line, comments dropped
	sed -n '/^depends:/,/^[^[:space:]#]/s/^  - //p' "$SRC/packaging/nfpm.yaml" | sed 's/[[:space:]]*#.*//'
}

cleanup() {
	if [ -f "$POLICY" ] && [ "$(sed -n 2p "$POLICY")" = "$POLICY_MARK" ]; then
		rm -f "$POLICY"
	fi
	[ -z "$TMP" ] || rm -rf "$TMP"
}

check_computer() {
	[ "$(id -u)" = 0 ] || stop "run it as root, in a throwaway container"
	[ -e "$ROOT/.dockerenv" ] || [ -e "$ROOT/run/.containerenv" ] ||
		stop "this is not a container: the check writes system files, so it runs only in a throwaway one"
	[ ! -e "$ROOT/etc/tvgw" ] || [ -e "$MARK" ] ||
		stop "this computer has /etc/tvgw, a gateway's settings: the check would overwrite them, so it stops here"
	[ -r "$ROOT/etc/os-release" ] || stop "cannot tell which system this is: /etc/os-release is missing"
	# read in a subshell, so no name it sets can replace one of this script's
	# shellcheck source=/dev/null
	DISTRO=$(. "$ROOT/etc/os-release" && printf '%s-%s' "${ID:-}" "${VERSION_ID:-}") ||
		stop "cannot tell which system this is: /etc/os-release could not be read"
	# shellcheck source=/dev/null
	OS_NAME=$(. "$ROOT/etc/os-release" && printf '%s' "${PRETTY_NAME:-$DISTRO}") || OS_NAME=$DISTRO
	ARCH=$(dpkg --print-architecture) || stop "dpkg could not name this computer's architecture"
}

apt_get() { DEBIAN_FRONTEND=noninteractive apt-get -o DPkg::Lock::Timeout=300 -q "$@" </dev/null; }

hold_services() { # what apt installs is configured, never started (deb-systemd-invoke and invoke-rc.d ask this)
	[ -e "$POLICY" ] && return 0
	install -d "$ROOT/usr/sbin"
	printf '#!/bin/sh\n%s\nexit 101\n' "$POLICY_MARK" >"$POLICY"
	chmod 755 "$POLICY"
}

fetch_release() { # $1 = v<version>: that release's package for this computer, checked against its SHA256SUMS
	_v=${1#v}
	case $_v in
	"" | *[!0-9.]* | .* | *. | *..*) stop "a release is v and its version, such as v0.3.0, not $1" ;;
	esac
	_name=tvgw_${_v}-1_$ARCH.deb
	apt_get install -y --no-install-recommends ca-certificates curl ||
		not_installed "apt could not install curl, which downloads the release (above)"
	for _file in "$_name" SHA256SUMS; do
		curl --proto '=https' --tlsv1.2 -fsSL --retry 3 -o "$TMP/$_file" "$BASE/$1/$_file" ||
			stop "could not download $_file from $BASE/$1"
	done
	_want=$(awk -v n="$_name" '$2 == n || $2 == "*" n { print $1 }' "$TMP/SHA256SUMS")
	_have=$(sha256sum "$TMP/$_name" | cut -d ' ' -f 1)
	[ -n "$_want" ] && [ "$_want" = "$_have" ] ||
		stop "$_name does not match its line in the release's SHA256SUMS; nothing was installed"
	DEB=$TMP/$_name
}

install_source() { # the Depends of packaging/nfpm.yaml, as apt resolves a dependency line
	_deps=$(list_depends | paste -sd, - | sed 's/,/, /g')
	say "installing the package's Depends: $_deps"
	apt_get satisfy -y "$_deps" || not_installed "apt could not install the package's Depends on $OS_NAME (above)"
	DEPLOY=$SRC/deploy
}

install_package() { # the package, as a user installs it, then its wheelhouse into a virtualenv
	VENV=$ROOT/opt/tvgw-platform-venv
	TVGW_CHECK_VENV=$VENV sh "$HERE/install-check.sh" "$DEB" ||
		not_installed "packaging/install-check.sh could not install $DEB on $OS_NAME (above)"
	TVGW=$VENV/bin/tvgw
	DEPLOY=$ROOT/usr/lib/tvgw/deploy
}

version_of() { # "<name>: <first line of its version>", or "<name>: missing"
	_tool=$1
	shift
	if ! command -v "$_tool" >/dev/null 2>&1; then
		printf '%s: missing\n' "$_tool"
		return 0
	fi
	# the version is on stdout, or on stderr for those that print it there (nginx -v); stdout first, so a
	# warning on stderr (tshark's, run as root) is not taken for it
	_seen=$("$_tool" "$@" 2>/dev/null | head -n 1) || _seen=
	[ -n "$_seen" ] || _seen=$("$_tool" "$@" 2>&1 | head -n 1) || _seen=
	printf '%s: %s\n' "$_tool" "$_seen"
}

record_versions() {
	{
		printf 'system: %s (%s, %s)\n' "$OS_NAME" "$DISTRO" "$ARCH"
		printf 'kernel: %s\n' "$(uname -r)"
		version_of nft --version
		version_of systemctl --version
		version_of python3 -V
		version_of dnsmasq --version
		version_of nginx -v
		version_of dumpcap --version
		version_of conntrack --version
		version_of tshark --version
		version_of NetworkManager --version
	} >"$OUT/versions.txt"
	sed 's/^/  /' "$OUT/versions.txt"
	! grep -q ': missing$' "$OUT/versions.txt" || failed versions "a program the package needs is missing"
}

unit_suite() { # the checkout's unit tests, on this distribution's python3, as an unprivileged user
	_home=$ROOT/home/$CI_USER
	TVGW=$_home/venv/bin/tvgw
	# git: the tests of the deploy window, the pull request's build, the link check and the docs tools
	# make throwaway repositories with it. The suite's tool, not the package's, installed after the
	# Depends; without it those tests fail, as they would on a workstation without git
	if ! apt_get install -y --no-install-recommends git; then
		failed unit-suite "apt could not install git, which the unit suite runs (above)"
		return 0
	fi
	# the user and its own copy of the checkout; a step that fails here fails this check, not the run
	if ! { id -u "$CI_USER" >/dev/null 2>&1 || useradd --create-home --shell /bin/sh "$CI_USER"; } ||
		! { rm -rf "$_home/src" "$_home/venv" && mkdir -p "$_home/src" && cp -R "$SRC/." "$_home/src/" &&
			chown -R "$CI_USER:" "$_home"; }; then
		failed unit-suite "could not give the user $CI_USER its own copy of the checkout"
		return 0
	fi
	# -rfEs: the summary names each failure and error, as by default, and each skipped test with its reason
	# shellcheck disable=SC2016 # expanded by the user's shell, from its arguments
	if runuser -u "$CI_USER" -- env HOME="$_home" sh -c 'cd "$1" && python3 -m venv ../venv &&
		../venv/bin/python -m pip install -q --no-warn-script-location -e ".[dev]" &&
		../venv/bin/python -m pytest -p no:cacheprovider -rfEs' \
		sh "$_home/src"; then
		say "ok: the unit suite on $(python3 -V 2>&1)"
	else
		failed unit-suite "the unit suite failed on $(python3 -V 2>&1)"
	fi
}

apply_check() { # tvgw-apply --check with this distribution's nft, every switch at each of its values
	for _dev in "$TV_IF" "$WAN_IF"; do
		if ! { ip link show "$_dev" >/dev/null 2>&1 || ip link add "$_dev" type dummy; } ||
			! ip link set "$_dev" up; then
			failed apply "could not make the dummy port $_dev (a container needs --cap-add=NET_ADMIN)"
			return 0
		fi
	done
	if ! ip addr replace "$GW_IP/24" dev "$TV_IF"; then
		failed apply "could not give the dummy port $TV_IF the gateway's address $GW_IP"
		return 0
	fi
	install -d -m 755 "$ROOT/etc/tvgw" "$ROOT/var/lib/tvgw" "$ROOT/run/lock" "$OUT/apply"
	: >"$MARK"
	# the tables the container holds before the check: on a user-defined network, as GitHub's container
	# jobs are, Docker's embedded DNS puts NAT rules of its own in the container's namespace
	nft list tables >"$OUT/apply/tables.before" 2>/dev/null || : >"$OUT/apply/tables.before"
	cp "$DEPLOY/nftables/block4.txt" "$ROOT/etc/tvgw/block4.txt"
	printf '# a DoH resolver, from a documentation range\n203.0.113.20\n' >"$ROOT/var/lib/tvgw/doh4.txt"
	_bad=
	_variants=$(printf '%s\n' "$VARIANTS" | cut -d : -f 1)
	for _name in $_variants; do
		_settings=$(printf '%s\n' "$VARIANTS" | sed -n "s/^$_name://p")
		{
			cat "$DEPLOY/tvgw.conf.example"
			printf '%s\n' "TV_IF=$TV_IF" "WAN_IF=$WAN_IF" "WAN_GW=$WAN_GW" "TV_IP=$TV_IP" "TV_MAC=$TV_MAC"
			for _kv in $_settings; do printf '%s\n' "$_kv"; done
		} >"$ROOT/etc/tvgw/tvgw.conf"
		cp "$ROOT/etc/tvgw/tvgw.conf" "$OUT/apply/$_name.conf"
		if bash "$DEPLOY/nftables/tvgw-apply" --check >"$OUT/apply/$_name.nft" 2>"$OUT/apply/$_name.log" &&
			[ "$(head -n 1 "$OUT/apply/$_name.nft")" = "table inet tvgw" ]; then
			say "ok: tvgw-apply --check, $_name settings"
		else
			sed 's/^/  /' "$OUT/apply/$_name.log" >&2
			_bad="$_bad $_name"
		fi
	done
	# the check loads nothing: an apply that left a table behind would hide the next variant's errors
	nft list tables >"$OUT/apply/tables.after" 2>/dev/null || : >"$OUT/apply/tables.after"
	cmp -s "$OUT/apply/tables.before" "$OUT/apply/tables.after" || _bad="$_bad (a table was left loaded)"
	[ -z "$_bad" ] || failed apply "tvgw-apply --check failed:$_bad"
}

dumpcap_check() { # tvgw-pcap.service's ring options on this distribution's dumpcap
	_unit=$DEPLOY/systemd/tvgw-pcap.service
	# shellcheck disable=SC2016 # ${TV_IF} is the unit's own text
	_opts=$(sed -n 's/^ExecStart=\/usr\/bin\/dumpcap -i ${TV_IF} \(.*\) -w [^ ]*.*$/\1/p' "$_unit")
	[ -n "$_opts" ] || {
		failed dumpcap "cannot read the ring options from $_unit"
		return 0
	}
	_dir=$TMP/pcap
	mkdir -p "$_dir"
	# shellcheck disable=SC2086 # the unit's options, one word each
	if ! dumpcap -i lo $_opts -a duration:1 -w "$_dir/tv.pcap" >"$OUT/dumpcap.log" 2>&1; then
		sed 's/^/  /' "$OUT/dumpcap.log" >&2
		failed dumpcap "dumpcap refused tvgw-pcap.service's options: $_opts"
		return 0
	fi
	_files=$(cd "$_dir" && ls)
	_d='[0-9][0-9][0-9][0-9][0-9][0-9][0-9]'
	# the ring rotates on the clock's hour, so a one-second capture that crosses it writes a second file:
	# tv_<stamp>_00001.pcap alone, or that and a tv_<stamp>_00002.pcap begun on the hour, and nothing else
	_first=$(printf '%s\n' "$_files" | sed -n 1p)
	_second=$(printf '%s\n' "$_files" | sed -n 2p)
	_more=$(printf '%s\n' "$_files" | sed -n 3p)
	_ring_ok=no
	# shellcheck disable=SC2254 # a pattern: the time stamp is fourteen digits
	case $_first in
	tv_$_d${_d}_00001.pcap)
		case $_second in
		"") _ring_ok=yes ;;
		tv_$_d${_d}_00002.pcap)
			# only across the hour: the first began in its last three seconds, the second on the hour
			_m1=$(printf '%s' "$_first" | cut -c14-17)
			_m2=$(printf '%s' "$_second" | cut -c14-17)
			case $_m1:$_m2:$_more in 5957:0000: | 5958:0000: | 5959:0000:) _ring_ok=yes ;; esac
			;;
		esac
		;;
	esac
	if [ "$_ring_ok" = yes ]; then
		say "ok: dumpcap $_opts wrote $(printf '%s' "$_files" | tr '\n' ' ')"
	else
		failed dumpcap "the ring file is not tv_<14 digits>_00001.pcap: $(printf '%s' "$_files" | tr '\n' ' ')"
	fi
	# install.sh's own check: the capture user can run dumpcap, so the debconf answer No took
	if ! getent passwd tvgw-pcap >/dev/null &&
		! useradd --system --no-create-home --shell /usr/sbin/nologin -g nogroup tvgw-pcap; then
		failed dumpcap "could not create the capture user tvgw-pcap"
	elif ! runuser -u tvgw-pcap -- test -x /usr/bin/dumpcap; then
		failed dumpcap "/usr/bin/dumpcap is not executable by tvgw-pcap: the wireshark-common answer did not take"
	fi
}

nginx_check() { # the URL filter's files as install.sh writes them, in both forms of the stream include
	_etc=$ROOT/etc/nginx
	[ -f "$_etc/nginx.conf" ] || {
		failed nginx "no $_etc/nginx.conf"
		return 0
	}
	install -d -m 755 "$OUT/nginx" "$_etc/tvgw" "$_etc/conf.d" "$ROOT/var/log/tvgw"
	[ -f "$OUT/nginx/nginx.conf.shipped" ] || cp "$_etc/nginx.conf" "$OUT/nginx/nginx.conf.shipped"
	ngx="s/__RESOLVER__/$URL_FILTER_RESOLVER/; s/__GW_IP__/$GW_IP/"
	sed "$ngx" "$DEPLOY/nginx/tvgw-gfts.conf" >"$_etc/conf.d/tvgw-gfts.conf"
	sed "$ngx" "$DEPLOY/nginx/stream.conf" >"$_etc/tvgw/stream.conf"
	rm -f "$_etc/sites-enabled/default"
	# today's form: the include appended to the nginx.conf conffile, as install.sh does
	cp "$OUT/nginx/nginx.conf.shipped" "$_etc/nginx.conf"
	grep -q 'tvgw/stream.conf' "$_etc/nginx.conf" || echo 'include /etc/nginx/tvgw/stream.conf;' >>"$_etc/nginx.conf"
	if nginx -t >"$OUT/nginx/appended.log" 2>&1; then
		say "ok: nginx -t, the stream include appended to nginx.conf"
	else
		sed 's/^/  /' "$OUT/nginx/appended.log" >&2
		failed nginx "nginx -t refused the files with the include appended to nginx.conf"
	fi
	# the form for new installs: nginx.conf as shipped, the include among the modules, after the stream
	# module's own file, so it is read at the top level once the module is loaded
	cp "$OUT/nginx/nginx.conf.shipped" "$_etc/nginx.conf"
	_module=
	for _f in "$_etc"/modules-enabled/*mod-stream.conf; do
		[ -e "$_f" ] && _module=${_f##*/} && break
	done
	if [ -z "$_module" ]; then
		failed nginx "no stream module in $_etc/modules-enabled: libnginx-mod-stream did not enable it"
		return 0
	fi
	echo 'include /etc/nginx/tvgw/stream.conf;' >"$_etc/modules-enabled/99-tvgw-stream.conf"
	if nginx -t >"$OUT/nginx/modules-enabled.log" 2>&1; then
		say "ok: nginx -t, the stream include as modules-enabled/99-tvgw-stream.conf after $_module"
	else
		sed 's/^/  /' "$OUT/nginx/modules-enabled.log" >&2
		failed nginx "nginx -t refused the files with the include as modules-enabled/99-tvgw-stream.conf"
	fi
	rm -f "$_etc/modules-enabled/99-tvgw-stream.conf"
}

render_dhcp() { # $1 = open-unknown, open-pinned or pinned: the DHCP file install.sh writes for that case
	side="s/__TV_IF__/$TV_IF/g; s/__GW_IP__/$GW_IP/g; s/__TV_NETMASK__/$TV_NETMASK/g; s/__DHCP_FIRST__/$DHCP_FIRST/g; s/__DHCP_LAST__/$DHCP_LAST/g"
	case $1 in
	open-unknown) sed -e "$side; /__TV_MAC__/d" "$DEPLOY/dnsmasq/tvgw.conf.template" ;;
	open-pinned)
		sed -e "$side; s/__TV_MAC__/$TV_MAC/; s/__TV_IP__/$TV_IP/g; s/__TV_NAME__/$TV_NAME/" \
			"$DEPLOY/dnsmasq/tvgw.conf.template"
		;;
	pinned)
		# TV_DHCP=pinned (design decision 51): the pool line becomes a static range for the TV's address,
		# and every host without a dhcp-host line is ignored, so only the pinned TV gets an answer
		awk '/^dhcp-range=/ { print "dhcp-range=__TV_IP__,static,__TV_NETMASK__,12h"; print "dhcp-ignore=tag:!known"; next }
			{ print }' "$DEPLOY/dnsmasq/tvgw.conf.template" |
			sed -e "$side; s/__TV_MAC__/$TV_MAC/; s/__TV_IP__/$TV_IP/g; s/__TV_NAME__/$TV_NAME/"
		;;
	esac
}

dnsmasq_check() {
	install -d -m 755 "$OUT/dnsmasq"
	_bad=
	for _form in open-unknown open-pinned pinned; do
		_file=$OUT/dnsmasq/tvgw.conf.$_form
		render_dhcp "$_form" >"$_file"
		if grep -q '__[A-Z_]*__' "$_file"; then
			_bad="$_bad $_form (a placeholder is left)"
		elif dnsmasq --test --conf-file="$_file" >"$OUT/dnsmasq/$_form.log" 2>&1; then
			say "ok: dnsmasq --test, the $_form file"
		else
			sed 's/^/  /' "$OUT/dnsmasq/$_form.log" >&2
			_bad="$_bad $_form"
		fi
	done
	[ -z "$_bad" ] || failed dnsmasq "dnsmasq --test refused:$_bad"
}

judge() { # $1 = systemd-analyze's output: each line with its verdict; status 1 for a tvgw finding not allowed here
	printf '%s\n' "$ALLOWED" | awk -F '|' -v distro="$DISTRO" '
		NR == FNR { if ($1 == distro) { n++; text[n] = $2; why[n] = $3 }; next }
		/^[[:space:]]*$/ { next }
		{
			verdict = ""
			for (i = 1; i <= n; i++) if (index($0, text[i])) { verdict = "allowed on " distro ": " why[i]; break }
			if (verdict == "" && $0 ~ /tvgw/) { verdict = "FAIL"; bad = 1 }
			if (verdict == "") verdict = "note: a file of the distribution"
			print "  " $0 "\n    -> " verdict
		}
		END { exit bad }' - "$1"
}

systemd_check() { # tvgw's units and drop-ins as install.sh installs them, read by this distribution's systemd
	_sd=$ROOT/etc/systemd/system
	install -d -m 755 "$_sd/tvgw-pcap.service.d" "$_sd/dnsmasq.service.d" "$_sd/nginx.service.d" \
		"$ROOT/usr/local/sbin" "$ROOT/usr/local/bin"
	install -m 644 "$DEPLOY"/systemd/*.service "$DEPLOY"/systemd/*.timer "$_sd/"
	printf '[Service]\nEnvironment=TV_IF=%s TV_NET=%s GW_IP=%s\n' "$TV_IF" "$TV_NET" "$GW_IP" \
		>"$_sd/tvgw-pcap.service.d/tv-side.conf"
	sed "s|__TV_NET__|$TV_NET|g" "$DEPLOY/dnsmasq/20-tvgw-hardening.conf.template" \
		>"$_sd/dnsmasq.service.d/20-tvgw-hardening.conf"
	{
		printf '[Unit]\nAfter=network-online.target\nWants=network-online.target\n[Service]\nRestart=on-failure\nRestartSec=5\n'
		grep -v '^#' "$DEPLOY/nginx/tvgw-hardening.conf"
		echo "RestrictAddressFamilies=AF_INET AF_NETLINK AF_UNIX"
		echo "MemoryDenyWriteExecute=yes"
	} >"$_sd/nginx.service.d/tvgw.conf"
	# the programs the units start, where install.sh puts them
	install -m 755 "$DEPLOY/nftables/tvgw-apply" "$DEPLOY/bin/tvgw-doh-update" "$DEPLOY/bin/tvgw-analyze" \
		"$ROOT/usr/local/sbin/"
	ln -sf "$TVGW" "$ROOT/usr/local/bin/tvgw"
	_log=$OUT/systemd-analyze.log
	_rc=0
	systemd-analyze verify --man=no "$_sd"/tvgw*.service "$_sd"/tvgw*.timer dnsmasq.service nginx.service \
		>"$_log" 2>&1 || _rc=$?
	if ! judge "$_log"; then
		failed systemd "systemd-analyze verify found a tvgw file this distribution does not accept (above)"
	elif [ "$_rc" != 0 ]; then
		failed systemd "systemd-analyze verify exited $_rc"
	else
		say "ok: systemd-analyze verify, every tvgw unit and drop-in"
	fi
}

main() {
	MODE=${1:-}
	case $MODE in
	--list-depends)
		[ $# -eq 1 ] || usage
		list_depends
		return 0
		;;
	--source) [ $# -eq 1 ] || usage ;;
	--package) [ $# -eq 2 ] || usage ;;
	*) usage ;;
	esac
	check_computer
	trap cleanup EXIT
	trap 'exit 1' INT TERM
	TMP=$(mktemp -d)
	mkdir -p "$OUT"
	DEB=
	if [ "$MODE" = --package ]; then
		case $2 in
		v*) ;;
		*)
			[ -f "$2" ] || stop "no package at $2"
			DEB=$2
			;;
		esac
	fi
	say "$OS_NAME ($DISTRO), $ARCH, $MODE"
	hold_services
	echo 'wireshark-common wireshark-common/install-setuid boolean false' | debconf-set-selections
	apt_get update || not_installed "apt could not read its package lists (above)"
	if [ "$MODE" = --source ]; then
		install_source
	else
		[ -n "$DEB" ] || fetch_release "$2"
		install_package
	fi
	record_versions
	[ "$MODE" != --source ] || unit_suite
	apply_check
	dumpcap_check
	nginx_check
	dnsmasq_check
	systemd_check
	if [ -n "$FAILED" ]; then
		printf 'fail:%s\n' "$FAILED" >"$OUT/result.txt"
		stop "$OS_NAME, $ARCH: failed:$FAILED (the lines above say why; $OUT holds the files)"
	fi
	echo ok >"$OUT/result.txt"
	say "$OS_NAME, $ARCH: every check passed"
}

main "$@"
