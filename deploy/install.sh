#!/bin/bash
# Install or refresh the TV gateway on the Pi from this repository checkout:
#   sudo ./install.sh            (run from deploy/)
# or, from the .deb, the same steps from its copy of this tree (docs/project/packaging.md):
#   sudo /usr/lib/tvgw/deploy/install.sh   (the package's postinst runs it with TVGW_POSTINST=1)
# Prerequisites (apt): tcpdump conntrack dnsmasq tshark wireshark-common nginx libnginx-mod-stream python3-venv
# plus AdGuard Home installed natively (see docs/install/README.md#prepare-the-gateway). wireshark-common is dumpcap, the
# capture: preseed it to leave dumpcap 755 root:root before apt installs it, with
#   echo 'wireshark-common wireshark-common/install-setuid boolean false' | sudo debconf-set-selections
# (docs/how-it-works/capture.md#what-dumpcap-needs). Settings live in
# /etc/tvgw/tvgw.conf (created from tvgw.conf.example on first install; edit TV_MAC/TV_IP/TV_NAME).
# Exits non-zero, with nothing after the failing step done, on an unusable setting, a config nginx
# rejects, a failed `tvgw adguard apply`, or a FAIL from the `tvgw verify` it ends with. Three exits
# are distinct for the package's postinst: 75, the TV is not identified yet and there is no terminal
# to ask on; 76, with TVGW_POSTINST=1 or TVGW_SETUP_PASS=apply only, the install completed and
# `tvgw verify` reported a FAIL; 77, (adguard) AdGuard Home was not set up by tvgw and serves other
# devices, so `tvgw adguard apply` refused to take it over and the install stopped there. (setup)
# TVGW_SETUP_PASS names one of the two passes of a guided first install
# (deploy/README.md#the-setup-passes): `bringup` stops once the TV side is up and exits 0; `apply`
# runs everything and ends as under the postinst. Unset or empty, nothing changes.
set -euo pipefail
# (packaging) any other stop exits 1, whatever the failing command returned: under set -e alone a
# command's own status became the script's (nmcli exits 3 on a timeout and 4 when an activation
# fails, GNU sed 4 on an I/O error), and the postinst read a half-done install as one of the two
# deliberate exits above. -E carries the trap into functions and subshells.
set -E
trap 'exit 1' ERR
export PYTHONUTF8=1 # every tvgw call below reads and writes UTF-8 whatever the system locale says
die() { echo "tvgw: $*" >&2; exit 1; }
# (setup) the pass is read before anything else is done, so a misspelt one runs nothing
case ${TVGW_SETUP_PASS:=} in
	"" | bringup | apply) ;;
	*) die "TVGW_SETUP_PASS=$TVGW_SETUP_PASS: the passes are bringup and apply" ;;
esac
cd "$(dirname "$0")"
REPO=$(cd .. && pwd)
VENV=/opt/tvgw-venv
# (packaging) the .deb ships this tree as /usr/lib/tvgw/deploy with the hash-pinned wheelhouse and its
# lock beside it, and installs from those, offline; from a checkout the package is built from ../src
MODE=source AGAIN="sudo ./install.sh"
if [ -f "$REPO/requirements.lock" ] && [ -d "$REPO/wheels" ]; then
	MODE=package AGAIN="sudo $REPO/deploy/install.sh"
fi
# one install at a time: `make deploy` and a CI deploy must never interleave. Both go through
# sync-install.sh, which takes the lock before it replaces the tree and hands it down open on
# descriptor 8 (flock on the open file that holds the lock returns at once); run by hand, this opens it
install -d -m 755 /run/tvgw
[ -n "${TVGW_INSTALL_LOCKED:-}" ] || exec 8>/run/tvgw/install.lock
flock -w 600 8 || die "another install is running"

# ---- tvgw-adguard: AdGuard Home is a checked dependency, never bundled (design decision 25).
# POSIX sh, the same block in install.sh and packaging/scripts/preinst; AGH_MIN is
# verify.ADGUARD_MIN (tests/unit/test_packaging.py keeps the three equal). ----
AGH=/opt/AdGuardHome/AdGuardHome
AGH_MIN=0.107.79
# AdGuard Home's own release, the one tvgw pins (aghinstall.PIN: its version and the SHA-256 of each
# tarball, which tests/unit/test_packaging.py keeps equal here), never its unpinned install script
AGH_PIN=0.107.80
AGH_HINT="install the release tvgw pins, v$AGH_PIN, from https://github.com/AdguardTeam/AdGuardHome/releases/tag/v$AGH_PIN into /opt/AdGuardHome, then finish its first-run page"
case $(dpkg --print-architecture 2>/dev/null || true) in
arm64) AGH_TAR=AdGuardHome_linux_arm64.tar.gz AGH_SUM=d5e17d0d724418ddef8b7723ed8ade7eef4e621ec5b0e43a341859cca71a3d8f ;;
amd64) AGH_TAR=AdGuardHome_linux_amd64.tar.gz AGH_SUM=28593bc761d71469abdbc6f39ca42cbed763ec92b63082c729177b037ed51d18 ;;
*) AGH_TAR='' AGH_SUM='' ;;
esac
[ -z "$AGH_TAR" ] || AGH_HINT="install the release tvgw pins, checked by its SHA-256, then finish its first-run page (https://github.com/AdguardTeam/AdGuardHome#getting-started):
  curl -fsSLO https://github.com/AdguardTeam/AdGuardHome/releases/download/v$AGH_PIN/$AGH_TAR
  echo '$AGH_SUM  $AGH_TAR' | sha256sum -c
  sudo tar -xzf $AGH_TAR -C /opt
  sudo $AGH -s install"
version_at_least() { # is dotted version $1 at least $2? (a leading v is ignored)
	_have=${1#v}. _want=${2#v}.
	case $_have$_want in *[!0-9.]* | *..*) return 1 ;; esac
	while [ -n "$_want" ]; do
		_a=${_have%%.*} _b=${_want%%.*}
		_have=${_have#*.} _want=${_want#*.}
		[ "${_a:-0}" -gt "$_b" ] && return 0
		[ "${_a:-0}" -lt "$_b" ] && return 1
	done
	return 0
}
adguard_ok() { # AdGuard Home at $AGH, at AGH_MIN or later; otherwise AGH_ERR says what to do
	AGH_ERR=
	if [ ! -x "$AGH" ]; then
		AGH_ERR="AdGuard Home is not installed ($AGH is missing); $AGH_HINT"
		return 1
	fi
	AGH_VERSION=$("$AGH" --version 2>/dev/null | sed -n 's/.*v\([0-9][0-9.]*[0-9]\).*/\1/p' | head -n 1) || true
	if [ -z "$AGH_VERSION" ]; then
		AGH_ERR="could not read AdGuard Home's version from $AGH --version; reinstall it: $AGH_HINT"
		return 1
	fi
	if ! version_at_least "$AGH_VERSION" "$AGH_MIN"; then
		# once tvgw is installed the binary changes only through it (it checks the live config first)
		if [ -n "$(command -v tvgw)" ]; then
			_agh_up="download the new release and run: sudo tvgw adguard upgrade <its AdGuardHome binary>"
		else
			_agh_up="update it with its own updater before tvgw is installed: sudo $AGH --update"
		fi
		AGH_ERR="AdGuard Home v$AGH_VERSION is below v$AGH_MIN, the release with the 2026 DoH and DoQ fixes; $_agh_up"
		return 1
	fi
}
# ---- end tvgw-adguard ----
# (setup) the bring-up pass runs before AdGuard Home is set up, and stops before the steps that need it
[ "$TVGW_SETUP_PASS" = bringup ] || adguard_ok || die "$AGH_ERR"

# State holds the TV's whole DNS/connection history and the LAN-API pairing key: root plus the
# admin group may read it (setgid so files created later inherit the group), nobody else
install -d -m 755 /etc/tvgw
install -d -m 2750 -g adm /var/log/tvgw
for f in /var/log/tvgw/*.log; do [ -f "$f" ] && chgrp adm "$f" && chmod 640 "$f"; done
# the state dir is traversable (x) but not listable or readable by others. dumpcap runs as the
# system user tvgw-pcap (primary group nogroup) and owns the pcap directory and files; tshark runs
# as nobody (in nogroup) and can read them but not change them
getent passwd tvgw-pcap >/dev/null || useradd --system --no-create-home --shell /usr/sbin/nologin -g nogroup tvgw-pcap
# (capture) tvgw-pcap.service runs dumpcap as this user. Answered Yes to letting non-superusers capture,
# wireshark-common makes dumpcap 0754 root:wireshark and the unit fails in a loop, so stop here, before
# any unit is installed and while the running capture is still the old one
DUMPCAP=/usr/bin/dumpcap
[ -x "$DUMPCAP" ] && runuser -u tvgw-pcap -- test -x "$DUMPCAP" ||
	die "$DUMPCAP is missing or not executable by tvgw-pcap: install wireshark-common answering No to non-superuser capture, or run 'sudo dpkg-reconfigure wireshark-common' and answer No (docs/how-it-works/capture.md#what-dumpcap-needs)"
install -d -m 2751 -g adm /var/lib/tvgw
# (ledger) the change ledger's spool, made 0640 before tvgw-apply or the dispatcher could create it under
# umask 022 (world-readable under /var/lib/tvgw); a spool or rotated copy from an older deploy is closed up
[ -e /var/lib/tvgw/changes.spool ] || install -m 640 -g adm /dev/null /var/lib/tvgw/changes.spool
chmod 640 /var/lib/tvgw/changes.spool /var/lib/tvgw/changes.spool.1 2>/dev/null || true
install -d -m 2750 -o tvgw-pcap -g nogroup /var/lib/tvgw/pcap
for f in /var/lib/tvgw/pcap/*.pcap; do [ -f "$f" ] && chown tvgw-pcap:nogroup "$f" && chmod 640 "$f"; done
[ ! -f /var/lib/tvgw/tvgw.db ] || { chgrp adm /var/lib/tvgw/tvgw.db; chmod 640 /var/lib/tvgw/tvgw.db; }
[ ! -f /var/lib/tvgw/lgtv-keys.sqlite ] || chmod 600 /var/lib/tvgw/lgtv-keys.sqlite
for f in /var/lib/tvgw/tvcheck.txt /var/lib/tvgw/tvcheck-history.log /var/lib/tvgw/doh4.txt /var/lib/tvgw/reports/*.txt /var/lib/tvgw/reports/*.json; do
	[ -f "$f" ] && chgrp adm "$f" && chmod 640 "$f"
done
[ -f /etc/tvgw/tvgw.conf ] || install -m 640 -g adm tvgw.conf.example /etc/tvgw/tvgw.conf
# the one file holding the TV's MAC and the router's address: root and the admin group only
chgrp adm /etc/tvgw/tvgw.conf; chmod 640 /etc/tvgw/tvgw.conf
[ -f /etc/tvgw/block4.txt ] || install -m 644 nftables/block4.txt /etc/tvgw/block4.txt
# repository data (shared CDN ranges), not a site setting: replaced on every install
install -m 644 nftables/doh-exclude.txt /etc/tvgw/doh-exclude.txt
. /etc/tvgw/tvgw.conf
: "${TV_IP:=10.10.10.17}" "${TV_NAME:=tv}"
: "${TV_IF:=eth0}" "${TV_NET:=10.10.10.0/24}" "${GW_IP:=10.10.10.1}" "${WAN_IF:=wlan0}" # (packaging) as tvgw-apply has them
: "${URL_FILTER_RESOLVER:=1.1.1.1}" # what nginx resolves the vendor's file-service names with (not AdGuard: it rewrites them to us)
: "${ADGUARD_LISTEN:=keep}" # (adguard) keep, as config.Settings has it: AdGuard's drop-in stays as it was (step 12)
# (reserved) settings for steps this script does not have yet, defaulted as config.Settings defaults them
# (tests/unit/test_deploy_lint.py keeps the two equal); each default is today's behaviour, and nothing
# below reads them yet
: "${TV_DHCP:=open}" "${UPDATE_CHECK:=off}"
: "${WAN_GW_MODE:=literal}" # (uplink) checked below; the tvgw-net block's wan_router reads it
: "${TV_PORT_MANAGER:=auto}" "${NETWATCH:=auto}"
# the values sed writes into the dnsmasq, nginx and NetworkManager configs are refused here, before
# anything is written, rather than installed: `${TV_MAC:?}` let the template's all-zero MAC through to
# dnsmasq, and a name with `/` or `&` broke or rewrote the sed expression
mac='^([0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}$'
name='^[A-Za-z0-9_-]{1,63}$' ipv4='^[0-9]{1,3}(\.[0-9]{1,3}){3}$'
# ---- tvgw-net: the TV side from TV_IF, TV_NET and GW_IP. The same block is in install.sh and
# tvgw-apply, and config.tv_side applies the same rules (tests/unit/test_packaging.py keeps all three
# equal). A wrong subnet here would masquerade, or route by table 100, more than the TV. ----
ip4_int() { # a dotted quad as a number, or status 1; no leading zeros, which Python refuses too
	local o='(0|[1-9][0-9]{0,2})'
	[[ $1 =~ ^$o\.$o\.$o\.$o$ ]] || return 1
	local a=${BASH_REMATCH[1]} b=${BASH_REMATCH[2]} c=${BASH_REMATCH[3]} d=${BASH_REMATCH[4]}
	((a <= 255 && b <= 255 && c <= 255 && d <= 255)) || return 1
	echo $(((a << 24) | (b << 16) | (c << 8) | d))
}
int_ip4() { echo "$(($1 >> 24 & 255)).$(($1 >> 16 & 255)).$(($1 >> 8 & 255)).$(($1 & 255))"; }
in_tv_net() { # is $1 an address inside TV_NET? (after tv_side)
	local n
	n=$(ip4_int "$1") || return 1
	(((n & TV_MASK_INT) == TV_NET_INT))
}
tv_side() { # checks TV_IF, TV_NET, GW_IP; sets TV_PREFIX TV_NETMASK TV_BCAST DHCP_FIRST DHCP_LAST, or TV_SIDE_ERR
	local base gw first last
	TV_SIDE_ERR=
	# (events) not lo, nor either PIA tunnel name: the input chain drops new connections from both
	if ! [[ $TV_IF =~ ^[A-Za-z0-9][A-Za-z0-9_.-]{0,14}$ ]] || [ "$TV_IF" = lo ] || [ "$TV_IF" = tun0 ] ||
		[ "$TV_IF" = wgpia0 ]; then
		TV_SIDE_ERR="TV_IF=$TV_IF is not an interface name for the TV"
		return 1
	fi
	if [ "$TV_IF" = "${WAN_IF:-}" ]; then
		TV_SIDE_ERR="TV_IF=$TV_IF: the TV and the uplink need different interfaces"
		return 1
	fi
	if [ "${WAN_IF:-}" = tun0 ] || [ "${WAN_IF:-}" = wgpia0 ]; then # (events) as for TV_IF
		TV_SIDE_ERR="WAN_IF=$WAN_IF is a VPN tunnel's name: the uplink is the home network's interface"
		return 1
	fi
	if ! [[ $TV_NET =~ ^([0-9.]+)/([1-9][0-9]?)$ ]] || ! base=$(ip4_int "${BASH_REMATCH[1]}"); then
		TV_SIDE_ERR="TV_NET=$TV_NET is not an IPv4 network such as 10.10.10.0/24"
		return 1
	fi
	TV_PREFIX=${TV_NET#*/}
	if ((TV_PREFIX < 16 || TV_PREFIX > 27)); then
		TV_SIDE_ERR="TV_NET=$TV_NET: the prefix must be /16 to /27"
		return 1
	fi
	TV_MASK_INT=$(((0xFFFFFFFF << (32 - TV_PREFIX)) & 0xFFFFFFFF))
	if (((base & TV_MASK_INT) != base)); then
		TV_SIDE_ERR="TV_NET=$TV_NET is not an IPv4 network such as 10.10.10.0/24"
		return 1
	fi
	if ! (((base >> 24) == 10 || (base >> 20) == (172 << 4 | 1) || (base >> 16) == (192 << 8 | 168))); then
		TV_SIDE_ERR="TV_NET=$TV_NET: must be inside 10/8, 172.16/12 or 192.168/16"
		return 1
	fi
	TV_NET_INT=$base
	TV_NETMASK=$(int_ip4 "$TV_MASK_INT")
	TV_BCAST=$(int_ip4 $((base | (~TV_MASK_INT & 0xFFFFFFFF))))
	first=$((base + 10)) last=$((base + 20))
	DHCP_FIRST=$(int_ip4 "$first") DHCP_LAST=$(int_ip4 "$last")
	if ! gw=$(ip4_int "$GW_IP"); then
		TV_SIDE_ERR="GW_IP=$GW_IP is not an IPv4 address"
		return 1
	fi
	if ! in_tv_net "$GW_IP" || [ "$GW_IP" = "$(int_ip4 "$base")" ] || [ "$GW_IP" = "$TV_BCAST" ]; then
		TV_SIDE_ERR="GW_IP=$GW_IP must be a host address in TV_NET $TV_NET"
		return 1
	fi
	if ((gw >= first && gw <= last)); then
		TV_SIDE_ERR="GW_IP=$GW_IP is inside the DHCP pool $DHCP_FIRST to $DHCP_LAST"
		return 1
	fi
}
tv_ip_ok() { # TV_IP is a host address in TV_NET other than GW_IP (after tv_side)
	if ! in_tv_net "$TV_IP" || [ "$TV_IP" = "$(int_ip4 "$TV_NET_INT")" ] || [ "$TV_IP" = "$TV_BCAST" ] ||
		[ "$TV_IP" = "$GW_IP" ]; then
		TV_SIDE_ERR="TV_IP=$TV_IP must be a host address in TV_NET $TV_NET, not GW_IP"
		return 1
	fi
}
# (uplink) what wan_router sets is tvgw-apply's: install.sh shares the block and never routes the TV
# shellcheck disable=SC2034
wan_router() { # (uplink) sets WAN_GW_USED, the home router's address, and WAN_GW_FROM (literal, route or last)
	# by WAN_GW_MODE: literal is WAN_GW as written; auto is the first `via` of WAN_IF's default route in the
	# main table, else the address an apply last took from it (/run/tvgw/wan_gw.last, gone at reboot), else
	# WAN_GW. WAN_GW_USED is empty when none of them holds an IPv4 address
	local via
	WAN_GW_USED=${WAN_GW:-} WAN_GW_FROM=literal
	[ "${WAN_GW_MODE:-literal}" = auto ] || return 0
	via=$({ ip -4 -o route show default dev "$WAN_IF" 2>/dev/null || true; } |
		awk '{ for (i = 1; i < NF; i++) if ($i == "via") { print $(i + 1); exit } }')
	if ip4_int "$via" >/dev/null; then
		WAN_GW_USED=$via WAN_GW_FROM=route
		return 0
	fi
	via=$(head -n 1 /run/tvgw/wan_gw.last 2>/dev/null || true)
	if ip4_int "$via" >/dev/null; then
		WAN_GW_USED=$via WAN_GW_FROM=last
	fi
}
# ---- end tvgw-net ----
# an unknown TV is not an error yet: the network side is brought up first, then `tvgw discover`
# finds the TV and records it (interactively), and the pin is applied below
have_tv=yes
[[ ${TV_MAC:-} =~ $mac && $TV_MAC != 00:00:00:00:00:00 ]] || have_tv=no
# (setup) setup runs its apply pass once it has found the TV and written it down: no TV here is its fault
[ "$have_tv" = yes ] || [ "$TVGW_SETUP_PASS" != apply ] || die "setup's apply pass needs TV_MAC"
tv_side || die "$TV_SIDE_ERR"
tv_ip_ok || die "$TV_SIDE_ERR"
[[ $TV_NAME =~ $name ]] || die "TV_NAME may contain letters, digits, - and _ only"
[[ $URL_FILTER_RESOLVER =~ $ipv4 ]] || die "URL_FILTER_RESOLVER must be an IPv4 address"
# (adguard) which AdGuard drop-in step 12 writes; config.load checks the same
[[ $ADGUARD_LISTEN =~ ^(keep|gateway)$ ]] || die "ADGUARD_LISTEN must be keep or gateway"
# (uplink) how tvgw-apply finds the router (wan_router); refused here before anything is written, as there
[[ $WAN_GW_MODE =~ ^(literal|auto)$ ]] || die "WAN_GW_MODE must be literal or auto"
# (record) the journal's span, written into the journald drop-in below; config.load checks the same
: "${JOURNAL_DAYS:=14}"
if ! [[ $JOURNAL_DAYS =~ ^(off|[1-9][0-9]{0,3})$ ]] || { [ "$JOURNAL_DAYS" != off ] && ((JOURNAL_DAYS > 3650)); }; then
	die "JOURNAL_DAYS must be 1 to 3650 days, or off"
fi
# a TV subnet that overlaps the home network would route the home's own addresses to the TV port
wan_overlap() { # prints the first address of WAN_IF whose network overlaps TV_NET
	local cidr n p m
	for cidr in $(ip -4 -o addr show dev "$WAN_IF" 2>/dev/null | awk '{print $4}' || true); do
		n=$(ip4_int "${cidr%/*}") || continue
		p=${cidr#*/}
		[[ $p =~ ^[0-9]{1,2}$ ]] || continue
		((p < TV_PREFIX)) || p=$TV_PREFIX
		m=$(((0xFFFFFFFF << (32 - p)) & 0xFFFFFFFF))
		(((n & m) != (TV_NET_INT & m))) || { echo "$cidr"; return 0; }
	done
	return 1
}
if lan=$(wan_overlap); then
	die "TV_NET=$TV_NET overlaps the network of $WAN_IF ($lan); pick a TV subnet the home network does not use"
fi

# The Python package: its own venv, the `tvgw` CLI on PATH, LG LAN-API extra included
[ -x $VENV/bin/python ] || python3 -m venv $VENV
if [ "$MODE" = package ]; then
	# offline and hash-checked: every dependency is in the wheelhouse, pinned by the lock, and pip
	# refuses a file whose hash differs; the package itself is the wheel built with the .deb, checked
	# against the sums made with it (a card that corrupts a file fails here, not in a running unit)
	(cd "$REPO/wheels" && sha256sum --quiet --strict -c ../SHA256SUMS) ||
		die "the wheelhouse in $REPO/wheels does not match its SHA256SUMS; reinstall the package"
	$VENV/bin/pip install -q --no-index --find-links "$REPO/wheels" --require-hashes -r "$REPO/requirements.lock"
	$VENV/bin/pip install -q --no-index --no-deps --force-reinstall "$REPO"/wheels/tvgw-*.whl
else
	$VENV/bin/pip install -q --upgrade pip
	# from a fresh build directory: pip builds the checkout in place, setuptools never prunes build/lib,
	# and rsync --delete leaves build/ alone, so a module deleted from src/ kept shipping in every wheel
	rm -rf "$REPO/build"
	$VENV/bin/pip install -q "${REPO}[lgwebos,analyst]" pytest # pytest: the hardware suite runs on the Pi
fi
ln -sf $VENV/bin/tvgw /usr/local/bin/tvgw

# Shell glue and services
install -m 755 nftables/tvgw-apply bin/tvgw-doh-update bin/tvgw-analyze /usr/local/sbin/
# The text-report pipeline (tvgw-extract, the TSV archive, the legacy report script) is retired:
# everything it produced is in the store. Its files go; the old reports move aside once. The bash
# pcap prune is retired too: `tvgw prune-pcaps` can see the store's marks and the live file.
rm -f /usr/local/sbin/tvgw-extract /usr/local/sbin/tvgw-prune /var/lib/tvgw/sni.tsv /var/lib/tvgw/http.tsv /var/lib/tvgw/querylog.json
rm -rf /var/lib/tvgw/archive /var/lib/tvgw/reports/brief /var/lib/tvgw/reports/brief-latest.txt
if [ -d /var/lib/tvgw/reports ] && [ ! -f /var/lib/tvgw/reports/.from-the-store ]; then
	install -d -m 2750 -g adm /var/lib/tvgw/reports/legacy
	for f in /var/lib/tvgw/reports/latest.* /var/lib/tvgw/reports/daily/* /var/lib/tvgw/reports/weekly/*; do
		[ -e "$f" ] && mv -f "$f" /var/lib/tvgw/reports/legacy/
	done
	touch /var/lib/tvgw/reports/.from-the-store
fi
# ---- (guard) begin: the guard table, the co-tenant filters, and dnsmasq and nginx with less to lose
# (design decision 42). A hardening line that could stop a service the TV depends on goes in with a
# health check, and comes out again on its own when the check fails: the TV must never lose DHCP or
# its URL filter to a sandbox line. A sandbox that failed once is not tried again until it changes
# (its stamp under .unit-stamps), so a deploy does not restart a daemon twice every time. ----
GUARD=/etc/tvgw/guard.nft
GUARD_APPLIED=/run/tvgw/guard.applied # tvgw-guard.service's listing of what it loaded (verify reads it)
REFUSED=/var/lib/tvgw/.unit-stamps
render_guard() { # the guard with this gateway's TV side, by the placeholders render_dnsmasq uses
	sed -e "s|__TV_IF__|$TV_IF|g; s|__TV_NET__|$TV_NET|g; s|__GW_IP__|$GW_IP|g" nftables/guard.nft.template
}
guard_drifted() { # the live table differs from what the unit loaded: a hole a killed `tvgw discover` left,
	# or a hand edit. No baseline (a boot that could not write /run) is not drift
	[ -s "$GUARD_APPLIED" ] && ! cmp -s <(nft -s list table inet tvgw_guard 2>/dev/null || true) "$GUARD_APPLIED"
}
guard_load() { # checked by nft first; loaded only when it changed, drifted or is missing, so a deploy keeps its counters
	render_guard >"$GUARD.new"
	nft -c -f "$GUARD.new" || { rm -f "$GUARD.new"; die "nft rejected the rendered guard (nftables/guard.nft.template)"; }
	local changed=no
	cmp -s "$GUARD.new" "$GUARD" || changed=yes
	chmod 644 "$GUARD.new" && mv -f "$GUARD.new" "$GUARD"
	systemctl daemon-reload
	systemctl -q enable tvgw-guard.service
	# reload-or-restart reloads an active unit (ExecReload, one atomic nft -f) and starts an inactive
	# one; a plain restart is refused, since the unit refuses a manual stop
	if [ "$changed" = yes ] || ! systemctl is-active -q tvgw-guard.service ||
		! nft list table inet tvgw_guard >/dev/null 2>&1 || guard_drifted; then
		systemctl reload-or-restart tvgw-guard.service
	fi
}
guard_cotenants() { # IPAddressDeny=TV_NET on every co-tenant unit installed; avahi off the TV port
	local out
	out=$(tvgw guard cotenants)
	if [ -n "$out" ]; then
		sed 's/^/tvgw: /' <<<"$out"
		systemctl daemon-reload # a reload applies a running unit's new IP filter at once (no restart)
	fi
	out=$(tvgw guard avahi)
	if [ -n "$out" ]; then
		sed 's/^/tvgw: /' <<<"$out"
		systemctl try-restart avahi-daemon.service || echo "tvgw: WARNING: avahi-daemon did not restart; deny-interfaces applies at its next start" >&2
	fi
}
refused() { # $1 a sandbox's name, $2 its text: did that exact text fail its health check before?
	[ "$(cat "$REFUSED/$1-refused" 2>/dev/null)" = "$(sha256sum <<<"$2")" ]
}
refuse() { install -d -m 700 "$REFUSED" && sha256sum <<<"$2" >"$REFUSED/$1-refused"; }
DNSMASQ_HARDENING=/etc/systemd/system/dnsmasq.service.d/20-tvgw-hardening.conf
dnsmasq_up() { # active, and holding the DHCP socket (read whole: grep -q ending a pipe early is a
	# SIGPIPE, and under pipefail a false "no")
	systemctl is-active -q dnsmasq.service && [[ $(ss -H -ulnp 'sport = :67' 2>/dev/null || true) == *'"dnsmasq"'* ]]
}
restart_dnsmasq() { # with the hardening drop-in, or, when dnsmasq will not serve with it, without
	local want
	want=$(sed "s|__TV_NET__|$TV_NET|g" dnsmasq/20-tvgw-hardening.conf.template)
	if refused dnsmasq "$want"; then
		rm -f "$DNSMASQ_HARDENING"
		echo "tvgw: WARNING: dnsmasq runs unhardened: this drop-in failed its check before; delete $REFUSED/dnsmasq-refused to try again" >&2
	else
		install -d /etc/systemd/system/dnsmasq.service.d
		printf '%s\n' "$want" >"$DNSMASQ_HARDENING"
	fi
	systemctl daemon-reload
	systemctl restart dnsmasq.service || true
	dnsmasq_up && return 0
	if [ -e "$DNSMASQ_HARDENING" ]; then
		echo "tvgw: WARNING: dnsmasq is not serving DHCP with the hardening drop-in; removing it and restarting (journalctl -u dnsmasq says why)" >&2
		rm -f "$DNSMASQ_HARDENING"
		systemctl daemon-reload
		systemctl restart dnsmasq.service || true
		# the stamp only once dnsmasq serves without the drop-in: a dnsmasq that fails both ways has
		# another fault, and the drop-in is tried again once that is fixed
		if dnsmasq_up; then
			refuse dnsmasq "$want"
			return 0
		fi
	fi
	die "dnsmasq is not serving DHCP on UDP 67 (journalctl -u dnsmasq)"
}
NGINX_DROPIN=/etc/systemd/system/nginx.service.d/tvgw.conf
nginx_dropin() { # start order and restarts; then, unless $1 is base, the sandbox nginx -T allows
	printf '[Unit]\nAfter=network-online.target\nWants=network-online.target\n[Service]\nRestart=on-failure\nRestartSec=5\n'
	[ "${1:-}" != base ] || return 0
	local conf
	conf=$(nginx -T 2>/dev/null | sed 's/#.*//' || true)
	echo "# (guard) the sandbox: deploy/nginx/tvgw-hardening.conf"
	grep -v '^#' nginx/tvgw-hardening.conf
	if grep -Eq '(^|[;{[:space:]])listen[[:space:]]+\[' <<<"$conf"; then
		echo "RestrictAddressFamilies=AF_INET AF_INET6 AF_NETLINK AF_UNIX"
	else
		echo "RestrictAddressFamilies=AF_INET AF_NETLINK AF_UNIX"
	fi
	grep -Eq '(^|[;{[:space:]])pcre_jit[[:space:]]+on[[:space:]]*;' <<<"$conf" || echo "MemoryDenyWriteExecute=yes"
}
nginx_up() { # active, and listening on the TV-facing address for both ports
	systemctl is-active -q nginx.service &&
		[[ $(ss -H -ltn 'sport = :80' 2>/dev/null || true) == *"$GW_IP:80 "* ]] &&
		[[ $(ss -H -ltn 'sport = :443' 2>/dev/null || true) == *"$GW_IP:443 "* ]]
}
nginx_service() { # a sandbox reaches nginx only at a start: restart once when the drop-in changed
	local old want
	old=$(cat "$NGINX_DROPIN" 2>/dev/null || true)
	want=$(nginx_dropin)
	refused nginx "$want" && { want=$(nginx_dropin base); echo "tvgw: WARNING: nginx runs unhardened: this drop-in failed its check before; delete $REFUSED/nginx-refused to try again" >&2; }
	install -d /etc/systemd/system/nginx.service.d
	printf '%s\n' "$want" >"$NGINX_DROPIN"
	systemctl daemon-reload
	systemctl -q enable nginx
	if [ "$want" = "$old" ] && systemctl is-active -q nginx.service; then
		systemctl reload nginx.service # a reload keeps the TLS passthrough and downloads in progress
		return 0
	fi
	systemctl restart nginx.service || true
	nginx_up && return 0
	if [ "$want" != "$(nginx_dropin base)" ]; then
		echo "tvgw: WARNING: nginx is not serving GW_IP:80 and :443 with the hardening lines; restoring the drop-in without them (journalctl -u nginx says why)" >&2
		nginx_dropin base >"$NGINX_DROPIN"
		systemctl daemon-reload
		systemctl restart nginx.service || true
		if nginx_up; then # the stamp only when the sandbox was the fault, as for dnsmasq
			refuse nginx "$want"
			return 0
		fi
	fi
	die "nginx is not listening on $GW_IP:80 and :443 (journalctl -u nginx)"
}
# ---- (guard) end ----
render_dnsmasq() { # the pin line only once the TV is known
	local side="s/__TV_IF__/$TV_IF/g; s/__GW_IP__/$GW_IP/g; s/__TV_NETMASK__/$TV_NETMASK/g"
	side+="; s/__DHCP_FIRST__/$DHCP_FIRST/g; s/__DHCP_LAST__/$DHCP_LAST/g"
	if [ "$have_tv" = yes ]; then
		sed -e "$side; s/__TV_MAC__/$TV_MAC/; s/__TV_IP__/$TV_IP/g; s/__TV_NAME__/$TV_NAME/" dnsmasq/tvgw.conf.template
	else
		sed -e "$side; /__TV_MAC__/d" dnsmasq/tvgw.conf.template
	fi >/etc/dnsmasq.d/tvgw.conf
}
render_dnsmasq
sed "s/__TV_IF__/$TV_IF/g" networkmanager/90-tvgw.conf >/etc/NetworkManager/conf.d/90-tvgw.conf
# (setup) the dispatcher runs tvgw-apply whenever the TV port or the uplink comes up or renews its lease,
# and step 9 brings the TV port up. An earlier install's is replaced here, as every deploy does (never in
# the bring-up pass). A first install's comes only just before the firewall itself is started, below: up to
# there the install can still stop (an unknown TV at 75, AdGuard Home refused at 77, nginx -t), and a
# dispatcher installed before would load the firewall and forward the TV through a resolver tvgw never set
# up (deploy/README.md#the-setup-passes)
DISPATCHER=/etc/NetworkManager/dispatcher.d/90-tvgw
install_dispatcher() { install -m 755 networkmanager/90-tvgw-dispatcher "$DISPATCHER"; }
if [ "$TVGW_SETUP_PASS" != bringup ] && [ -e "$DISPATCHER" ]; then install_dispatcher; fi
install -m 644 logrotate/tvgw /etc/logrotate.d/tvgw
# ---- tvgw-journald (record): the logs' and the journal's retention (docs/how-it-works/privacy-and-retention.md).
# tests/unit/test_record_deploy.py runs this block's functions on fixtures. ----
JOURNALD_DROPIN=/etc/systemd/journald.conf.d/60-tvgw.conf
trim_rotations() { # the copies past each log's `rotate`: logrotate removes only the next one, never the rest
	local logdir=${1:-/var/log/tvgw} statedir=${2:-/var/lib/tvgw} f base n keep
	for f in "$logdir"/*.log.* "$statedir"/tvcheck-history.log.* "$statedir"/tvlive-events.log.*; do
		[ -f "$f" ] || continue
		base=${f%.log.*}.log n=${f##*.log.}
		n=${n%.gz}
		[[ $n =~ ^[0-9]+$ ]] || continue
		case ${base##*/} in gfts-tls.log) keep=1 ;; tvcheck-history.log) keep=35 ;; *) keep=2 ;; esac
		((n <= keep)) || rm -f "$f"
	done
}
journald_note() { # stdin: `systemd-analyze cat-config systemd/journald.conf`; prints a note for every
	# other file that sets MaxRetentionSec= to another span, saying which one is in effect
	awk -v ours="$JOURNALD_DROPIN" '
		function secs(v, total, tok, num, unit, mult) { # a systemd time span in seconds; -1 unlimited, -2 unknown
			gsub(/[[:space:]]/, "", v)
			if (v == "" || v ~ /^0+$/ || v == "infinity") return -1
			total = 0
			while (match(v, /^[0-9.]+[A-Za-z]*/)) {
				tok = substr(v, 1, RLENGTH); v = substr(v, RLENGTH + 1)
				num = tok + 0; unit = tok; sub(/^[0-9.]+/, "", unit)
				if (unit == "" || unit ~ /^(s|sec|second|seconds)$/) mult = 1
				else if (unit ~ /^(m|min|minute|minutes)$/) mult = 60
				else if (unit ~ /^(h|hr|hour|hours)$/) mult = 3600
				else if (unit ~ /^(d|day|days)$/) mult = 86400
				else if (unit ~ /^(w|week|weeks)$/) mult = 604800
				else if (unit ~ /^(M|month|months)$/) mult = 2629800
				else if (unit ~ /^(y|year|years)$/) mult = 31557600
				else return -2
				total += num * mult
			}
			return v == "" ? total : -2
		}
		function longer(a, b) { return (a == -1 && b != -1) || (a >= 0 && b >= 0 && a > b) }
		/^# \/.*\.conf$/ { file = substr($0, 3); next }
		/^[[:space:]]*MaxRetentionSec[[:space:]]*=/ {
			v = $0; sub(/^[^=]*=[[:space:]]*/, "", v); sub(/[[:space:]]+$/, "", v)
			n++; files[n] = file; vals[n] = v; if (file == ours) mine = n
		}
		END {
			if (!mine) exit
			b = secs(vals[mine])
			for (i = 1; i <= n; i++) {
				a = secs(vals[i])
				if (i == mine || vals[i] == vals[mine] || (a != -2 && b != -2 && a == b)) continue
				span = (a == -1) ? "no limit" : vals[i]
				# a span this cannot parse is named as it is, never called longer or shorter
				if (a == -2 || b == -2) how = "which tvgw cannot compare with its own"
				else how = longer(a, b) ? "longer than tvgw'"'"'s" : "shorter than tvgw'"'"'s"
				if (i > mine)
					printf "tvgw: journald: %s, read after %s, sets MaxRetentionSec=%s, %s; the journal keeps %s\n", files[i], ours, vals[i], how, span
				else
					printf "tvgw: journald: %s sets MaxRetentionSec=%s; %s is read after it and keeps the journal %s instead, for every service (JOURNAL_DAYS in tvgw.conf)\n", files[i], span, ours, vals[mine]
			}
		}'
}
journald_dropin() { # 60-tvgw.conf as JOURNAL_DAYS asks; journald restarted only when it changed
	local want="" have=""
	[ "$JOURNAL_DAYS" = off ] || want=$(sed "s/__JOURNAL_DAYS__/$JOURNAL_DAYS/" journald/60-tvgw.conf.template)
	[ ! -f "$JOURNALD_DROPIN" ] || have=$(cat "$JOURNALD_DROPIN")
	[ "$want" != "$have" ] || return 0
	if [ -n "$want" ]; then
		install -d -m 755 "${JOURNALD_DROPIN%/*}"
		printf '%s\n' "$want" >"$JOURNALD_DROPIN.tmp"
		chmod 644 "$JOURNALD_DROPIN.tmp"
		mv -f "$JOURNALD_DROPIN.tmp" "$JOURNALD_DROPIN"
	else
		rm -f "$JOURNALD_DROPIN"
	fi
	# journald keeps every service's log stream across a restart (systemd-journald.service(8)); it reads
	# its configuration only at start on this systemd, and vacuums at start and at each daily rotation
	systemctl restart systemd-journald.service ||
		echo "tvgw: systemd-journald did not restart; $JOURNALD_DROPIN applies at the next boot" >&2
}
# ---- end tvgw-journald ----
trim_rotations
journald_dropin
systemd-analyze cat-config systemd/journald.conf 2>/dev/null | journald_note || true
install -D -m 644 sysctl/60-tvgw.conf /etc/sysctl.d/60-tvgw.conf # (events) conntrack's switches from boot (deploy/sysctl)
install -m 644 systemd/*.service systemd/*.timer /etc/systemd/system/
# (packaging) the capture's TV side: systemd reads this as root and fills in dumpcap's interface and
# filter; the capture user cannot read the settings file, and the values passed tv_side above
install -d /etc/systemd/system/tvgw-pcap.service.d
printf '[Service]\nEnvironment=TV_IF=%s TV_NET=%s GW_IP=%s\n' "$TV_IF" "$TV_NET" "$GW_IP" \
	>/etc/systemd/system/tvgw-pcap.service.d/tv-side.conf
# (app in front) the live reading may reach the TV and nothing else: its unit denies every address, and
# this is the one it is allowed (design decision 67)
install -d /etc/systemd/system/tvgw-tvlive.service.d
printf '[Service]\nIPAddressAllow=%s\n' "$TV_IP" >/etc/systemd/system/tvgw-tvlive.service.d/tv.conf
# (guard) the Pi closed to the TV before the TV side comes up, and the co-tenants' own wall
guard_load
guard_cotenants

# (packaging) NetworkManager may have come with the package minutes ago, held from starting by the
# installer's policy-rc.d (apt's hooks ask it; systemctl does not), or be installed and stopped: every
# nmcli call below needs it running. Started here; one that will not start stops the install
systemctl -q is-active NetworkManager.service || systemctl start NetworkManager.service ||
	die "NetworkManager is not running and did not start (journalctl -u NetworkManager); tvgw needs it for the TV port (docs/install/choosing-a-gateway.md)"
# TV side: static GW_IP/prefix on TV_IF, no IPv6, never a default route; stop the stock DHCP profile
# fighting it
stand_aside() { # every other profile that would take TV_IF stops autoconnecting
	if [ "$TV_IF" = eth0 ]; then # literal on purpose: the stock profile of a Pi's built-in port
		nmcli -t -f NAME con show | grep -qx "Wired connection 1" &&
			nmcli con modify "Wired connection 1" connection.autoconnect no
	fi
	# (packaging) on another TV port, whatever profile holds it now (a stock DHCP one) stands aside
	nmcli -t -f NAME,DEVICE con show --active | while IFS=: read -r cname cdev; do
		if [ "$cdev" = "$TV_IF" ] && [ "$cname" != tv-lan ]; then
			nmcli con modify "$cname" connection.autoconnect no
		fi
	done
}
tv_lan_up() { # nmcli con up tv-lan; when it fails on a port with no cable link, what to do, in plain words
	local rc=0 again=${AGAIN:-sudo ./install.sh}
	nmcli con up tv-lan || rc=$?
	[ "$rc" -ne 0 ] || return 0
	[ -z "${TVGW_SETUP_PASS:-}" ] || again="sudo tvgw setup"
	if ip -o link show dev "$TV_IF" 2>/dev/null | grep -q NO-CARRIER; then
		echo "tvgw: the TV's port ($TV_IF) has no cable link: plug the TV's cable into it and switch the TV on, then run $again" >&2
	fi
	return "$rc" # nmcli's status; the ERR trap makes it 1
}
tv_lan() { # tv-lan made, or moved to where the settings put the TV side, and up
	nmcli general reload conf
	if ! nmcli -t -f NAME con show | grep -qx tv-lan; then
		stand_aside
		nmcli con add type ethernet ifname "$TV_IF" con-name tv-lan \
			ipv4.method manual ipv4.addresses "$GW_IP/$TV_PREFIX" ipv4.never-default yes \
			ipv6.method disabled connection.autoconnect yes
	elif [ "$(nmcli -g connection.interface-name con show tv-lan)" != "$TV_IF" ] ||
		[ "$(nmcli -g ipv4.addresses con show tv-lan)" != "$GW_IP/$TV_PREFIX" ]; then
		# (packaging) TV_IF, TV_NET or GW_IP changed since tv-lan was made: the profile on the new port
		# stands aside as on a first install, then tv-lan moves and comes up again
		echo "tvgw: tv-lan moves to $TV_IF with $GW_IP/$TV_PREFIX"
		stand_aside
		nmcli con modify tv-lan connection.interface-name "$TV_IF" ipv4.addresses "$GW_IP/$TV_PREFIX"
		tv_lan_up
	fi
	# bringing an active connection up again drops GW_IP for a moment and fires a dispatcher apply
	nmcli -g GENERAL.STATE con show tv-lan | grep -qx activated || tv_lan_up
}
tv_lan

# (setup) the bring-up pass ends here, the TV side up and DHCP served whether the TV is known or not:
# setup finds the TV itself, then runs the apply pass. nginx, AdGuard Home's config, tvgw.service and the
# other units are the apply pass's
if [ "$TVGW_SETUP_PASS" = bringup ]; then
	# nothing the TV sends is passed on in this pass, even on a computer that already forwards (a VPN client,
	# Docker): the apply pass's tvgw-apply switches the TV port's forwarding on with the firewall
	sysctl -q -w "net.ipv4.conf.$TV_IF.forwarding=0"
	restart_dnsmasq # (guard) with the health check
	echo "tvgw: TV side up on $TV_IF ($GW_IP)"
	exit 0
fi

# First install with no TV identity: the TV side is up and dnsmasq hands out pool addresses, so the
# TV can be found now. Interactive runs ask; unattended ones stop here with the two commands to run.
if [ "$have_tv" = no ]; then
	restart_dnsmasq # (guard) with the health check
	# the package's postinst never prompts (an apt run may have no one at the terminal); it reports 75
	if [ -t 0 ] && [ -z "${TVGW_POSTINST:-}" ]; then
		echo "tvgw: the TV is not identified yet. Plug it into the gateway's TV port, switch it on, then pick it:"
		until tvgw discover --write; do
			read -r -p "tvgw: retry discovery? [Y/n] " ans
			[ "${ans:-y}" = n ] && die "TV not identified; run 'sudo tvgw discover --write' then '$AGAIN'"
		done
	else
		echo "tvgw: TV not identified and no terminal to ask on; run 'sudo tvgw discover --write' then '$AGAIN'" >&2
		exit 75
	fi
	. /etc/tvgw/tvgw.conf
	[[ ${TV_MAC:-} =~ $mac && $TV_MAC != 00:00:00:00:00:00 ]] || die "discovery did not record a usable TV_MAC"
	tv_ip_ok || die "$TV_SIDE_ERR"
	[[ $TV_NAME =~ $name ]] || die "TV_NAME may contain letters, digits, - and _ only"
	have_tv=yes
	render_dnsmasq
fi

# URL filter for the vendor's plain-HTTP file service (profile url_filter); AdGuard must rewrite
# those names to the gateway (`tvgw adguard apply` generates the $dnsrewrite rules from the profile and GW_IP)
if command -v nginx >/dev/null; then
	ngx="s/__RESOLVER__/$URL_FILTER_RESOLVER/; s/__GW_IP__/$GW_IP/"
	sed "$ngx" nginx/tvgw-gfts.conf >/etc/nginx/conf.d/tvgw-gfts.conf
	install -d -m 755 /etc/nginx/tvgw && sed "$ngx" nginx/stream.conf >/etc/nginx/tvgw/stream.conf
	grep -q 'tvgw/stream.conf' /etc/nginx/nginx.conf || echo 'include /etc/nginx/tvgw/stream.conf;' >>/etc/nginx/nginx.conf
	rm -f /etc/nginx/sites-enabled/default
	nginx -t || die "nginx rejected the generated config (see nginx -t output)"
	nginx_service # (guard) the drop-in, its sandbox, and a restart with a health check only when it changed
else
	echo "tvgw: nginx not installed; URL filter skipped (apt install nginx libnginx-mod-stream)"
fi

# AdGuard Home: blocklists, custom rules, upstreams and settings come from the profile + tvgw.conf.
# Its first run is `tvgw adguard install`, which answers AdGuard's wizard on loopback, or the wizard by
# hand on a gateway set up before it (design decision 52); after that this owns the config.
if [ -f /opt/AdGuardHome/AdGuardHome.yaml ]; then
	install -d /etc/systemd/system/AdGuardHome.service.d
	# (adguard) with ADGUARD_LISTEN=gateway AdGuard binds GW_IP, which exists only once the TV port has its
	# address: it starts after the network and is restarted every 5 s, without a limit, until it binds,
	# so a late port (a USB adapter) costs seconds of DNS. With keep the drop-in is what it always was.
	# adguardcfg.WORKDIR_GATEWAY and WORKDIR_KEEP are the same two texts (tests/unit/test_adguard_listen.py)
	if [ "$ADGUARD_LISTEN" = gateway ]; then
		printf '[Unit]\nAfter=network-online.target\nWants=network-online.target\nStartLimitIntervalSec=0\n\n[Service]\nWorkingDirectory=/opt/AdGuardHome\nRestart=always\nRestartSec=5\n' >/etc/systemd/system/AdGuardHome.service.d/workdir.conf
	else
		printf '[Service]\nWorkingDirectory=/opt/AdGuardHome\n' >/etc/systemd/system/AdGuardHome.service.d/workdir.conf
	fi
	systemctl daemon-reload
	# (lists) AdGuard never updates itself: its own ExecStart plus --no-check-update, in a drop-in written
	# only when it differs, then a restart that must resolve a must-allow name or the old unit comes
	# back. Status 3 is the restart guard (the upstreams are down): reported, and the next deploy retries.
	# A failure here leaves AdGuard as it was and does not stop the install; tvgw verify says so.
	agh_rc=0
	tvgw adguard service || agh_rc=$?
	case $agh_rc in
		0) ;;
		3) echo "tvgw: AdGuard Home's --no-check-update drop-in deferred: upstream down" >&2 ;;
		*) echo "tvgw: AdGuard Home's --no-check-update drop-in not applied (see above); AdGuard runs as before" >&2 ;;
	esac
	# (lists) status 3: the restart guard held the apply back (upstreams down, nothing changed); any other
	# failure stops the install, as before
	agh_rc=0
	tvgw adguard apply || agh_rc=$?
	case $agh_rc in
		0) ;;
		3) echo "tvgw: tvgw adguard apply deferred: upstream down; run sudo tvgw adguard apply once lookups resolve" >&2 ;;
		4)
			# (adguard) not tvgw's AdGuard Home, and it serves other devices: the lines above say what the
			# apply found, and nothing of AdGuard changed. The way on is the owner's yes, then this again
			agh_again=$AGAIN agh_moves="its page to this computer alone"
			[ -z "${TVGW_POSTINST:-}" ] || agh_again="sudo dpkg --configure -a"
			[ -z "$TVGW_SETUP_PASS" ] || agh_again="sudo tvgw setup"
			[ "$ADGUARD_LISTEN" != gateway ] || agh_moves="its DNS and its page to this computer and the TV alone"
			echo "tvgw: this AdGuard Home serves other devices, and tvgw would move $agh_moves. If nothing else depends on it, set ADGUARD_TAKE_OVER=yes in /etc/tvgw/tvgw.conf and run $agh_again; otherwise put tvgw on a computer of its own, with an AdGuard Home for the TV alone (docs/install/choosing-a-gateway.md)" >&2
			exit 77
			;;
		*) die "tvgw adguard apply failed (exit $agh_rc)" ;;
	esac
else
	echo "tvgw: AdGuard Home not set up yet; run sudo tvgw adguard install, then sudo tvgw adguard apply"
fi

# The stock nftables.service starts with `flush ruleset`, which would wipe PIA's rules and ours if
# anyone ever enabled it; mask it while it is disabled (reversible: systemctl unmask nftables)
systemctl is-enabled nftables.service 2>/dev/null | grep -qx enabled || systemctl mask nftables.service >/dev/null 2>&1 || true
systemctl daemon-reload
# a new gateway has no DoH list until the daily timer first fires (up to ~25 h): fetch it now, best effort
[ -s /var/lib/tvgw/doh4.txt ] || systemctl start tvgw-doh-update.service ||
	echo "tvgw: DoH list not fetched (offline?); doh4 stays empty until tvgw-doh-update.timer runs" >&2
systemctl -q enable tvgw.service
# the analyst's cadence from the conf: a time of day (daily), hourly, or a systemd calendar expression,
# as a drop-in over the shipped timer; systemd itself judges the expression before anything is written
case "${ANALYST_SCHEDULE:=03:50}" in
	hourly) cal=hourly ;;
	[0-9][0-9]:[0-9][0-9]) cal="*-*-* $ANALYST_SCHEDULE:00" ;;
	*) cal=$ANALYST_SCHEDULE ;;
esac
systemd-analyze calendar "$cal" >/dev/null 2>&1 || { echo "tvgw: ANALYST_SCHEDULE=$ANALYST_SCHEDULE is not a schedule systemd understands" >&2; exit 1; }
install -d /etc/systemd/system/tvgw-analyst.timer.d
printf '[Timer]\nOnCalendar=\nOnCalendar=%s\n' "$cal" >/etc/systemd/system/tvgw-analyst.timer.d/schedule.conf
# the weekly pass: "Day HH:MM" or a systemd calendar expression
case "${ANALYST_WEEKLY_SCHEDULE:=Mon 04:10}" in
	[A-Z][a-z][a-z]\ [0-9][0-9]:[0-9][0-9]) wcal="${ANALYST_WEEKLY_SCHEDULE% *} *-*-* ${ANALYST_WEEKLY_SCHEDULE#* }:00" ;;
	*) wcal=$ANALYST_WEEKLY_SCHEDULE ;;
esac
systemd-analyze calendar "$wcal" >/dev/null 2>&1 || { echo "tvgw: ANALYST_WEEKLY_SCHEDULE=$ANALYST_WEEKLY_SCHEDULE is not a schedule systemd understands" >&2; exit 1; }
install -d /etc/systemd/system/tvgw-analyst-weekly.timer.d
printf '[Timer]\nOnCalendar=\nOnCalendar=%s\n' "$wcal" >/etc/systemd/system/tvgw-analyst-weekly.timer.d/schedule.conf
systemctl daemon-reload
# everything the next boot reads is written by now. `install` unlinks the old file and writes a new
# one, which ext4 may keep in memory for half a minute: a power cut then could leave tvgw-apply or a
# unit empty, and the TV dark at boot until the next deploy
sync

# (setup) a first install's dispatcher, now that the firewall starts anyway (see step 8)
[ -e "$DISPATCHER" ] || install_dispatcher
# re-apply in place when the firewall is already up: a restart would run ExecStop (forwarding off)
# and black out the TV for a second; tvgw-apply itself is idempotent and atomic
if systemctl is-active -q tvgw.service; then /usr/local/sbin/tvgw-apply; else systemctl restart tvgw.service; fi
restart_dnsmasq # (guard) with the hardening drop-in and the health check that can take it out
systemctl enable --now tvgw-flowlog.service tvgw-pcap.service tvgw-dnsgate.service tvgw-tvlive.service tvgw-prune.timer tvgw-doh-update.timer tvgw-analyze.timer tvgw-verify.timer tvgw-backup.timer tvgw-analyst.timer tvgw-analyst-weekly.timer tvgw-autoblock.timer tvgw-threat-update.timer
# A long-running unit keeps what it read when it started: its unit file, the flow log the TV's address
# as well, and the DNS-gate feeder the settings and the package it runs. Each is restarted when that
# differs from the stamp written here after its last restart, so a changed TV_IP or a feeder fix
# reaches the running process; restarting only on a changed unit file left both waiting for a reboot.
# Every restart is a sub-second hole in the evidence, so an unchanged unit is left alone.
STAMPS=/var/lib/tvgw/.unit-stamps
started_with() {
	cat "systemd/$1.service"
	case $1 in
		tvgw-pcap)
			echo "TV_IF=$TV_IF TV_NET=$TV_NET GW_IP=$GW_IP" # (packaging) its drop-in
			# (capture) the headers unit stops and starts with it (PartOf=), and each unit's ExecCondition
			# reads CAPTURE_MODE at start: a change to either reaches the capture at the next deploy
			cat systemd/tvgw-pcap-headers.service
			grep -E '^[[:space:]]*CAPTURE_MODE=' /etc/tvgw/tvgw.conf || true
			;;
		tvgw-flowlog) echo "TV_IP=$TV_IP" ;;
		# (inpath) the in-path filler reads the same two things; (app in front) the live reading reads
		# LIVE_READING, TV_IP and TV_IF at start
		tvgw-dnsgate | tvgw-dnsgate-inpath | tvgw-tvlive | tvgw-names)
			cat /etc/tvgw/tvgw.conf
			# the package it runs: the checkout's sources, or the wheel the .deb carries (packaging)
			if [ "$MODE" = package ]; then
				(cd "$REPO/wheels" && sha256sum tvgw-*.whl)
			else
				(cd "$REPO/src" && find tvgw -type f ! -path '*/__pycache__/*' -exec sha256sum {} + | LC_ALL=C sort)
			fi
			;;
	esac
}
restart_changed() {
	install -d -m 700 "$STAMPS"
	for u in "$@"; do
		now=$(started_with "$u" | sha256sum)
		[ "$now" != "$(cat "$STAMPS/$u" 2>/dev/null)" ] || continue
		systemctl restart "$u.service"
		echo "$now" >"$STAMPS/$u"
	done
}
restart_changed tvgw-pcap tvgw-flowlog tvgw-dnsgate tvgw-tvlive
# (inpath) The DNS gate's in-path filler runs only with DNSGATE=count and DNSGATE_FILL=inpath (design
# decision 64): enabled here and nowhere else, and disabled again when the settings say passive, so a
# gateway that never asked for it has no such unit running. It never fails the install: without it the
# kernel passes the TV's DNS answers itself and the passive gate counts as before.
if [ "${DNSGATE:-count}" = count ] && [ "${DNSGATE_FILL:-passive}" = inpath ]; then
	if systemctl enable --now tvgw-dnsgate-inpath.service; then
		restart_changed tvgw-dnsgate-inpath ||
			echo "tvgw: WARNING: tvgw-dnsgate-inpath did not restart (journalctl -u tvgw-dnsgate-inpath); the TV's DNS answers pass unheld" >&2
	else
		echo "tvgw: WARNING: tvgw-dnsgate-inpath did not start (journalctl -u tvgw-dnsgate-inpath); the TV's DNS answers pass unheld" >&2
	fi
else
	systemctl disable --now tvgw-dnsgate-inpath.service >/dev/null 2>&1 || true
fi
# (reliability) With VPN_DNS_SEAL=on, tvgw-vpnseal holds this computer's own plain lookups off the uplink
# when the VPN client stops (design decision 73); with it off, its start and its stop remove that table.
# Restarted on every install, so a changed setting takes effect now; it never stops the install
systemctl -q enable tvgw-vpnseal.service 2>/dev/null || true
systemctl restart tvgw-vpnseal.service ||
	echo "tvgw: WARNING: tvgw-vpnseal did not start (journalctl -u tvgw-vpnseal); this computer's own lookups are not held" >&2
# (namebound) The live name count runs only with NAME_BINDING=count (design decision 70), enabled here and
# disabled again when the settings say off. It never fails the install: without it nothing is counted
# and nothing else changes, since the firewall's copies wait for no reader.
if [ "${NAME_BINDING:-off}" = count ]; then
	if systemctl enable --now tvgw-names.service; then
		restart_changed tvgw-names ||
			echo "tvgw: WARNING: tvgw-names did not restart (journalctl -u tvgw-names); the live name count is stale" >&2
	else
		echo "tvgw: WARNING: tvgw-names did not start (journalctl -u tvgw-names); the live name count reads nothing" >&2
	fi
else
	systemctl disable --now tvgw-names.service >/dev/null 2>&1 || true
fi
tvgw changes --note-deploy "$(tvgw --version 2>/dev/null || echo unknown)" >/dev/null 2>&1 || echo "tvgw: could not note this deploy in the change ledger (design decision 48)" # (ledger)
systemctl start tvgw-analyze.service || echo "tvgw: first analyze run reported problems (journalctl -u tvgw-analyze)"
# the first copy only: the timer makes the daily ones, and a copy on every deploy pushed them out
compgen -G '/var/lib/tvgw/backup/tvgw-*.db' >/dev/null || systemctl start tvgw-backup.service || echo "tvgw: first backup reported problems (journalctl -u tvgw-backup)"
echo "tvgw: installed ($(tvgw --version)); verifying:"
# the package's postinst tells a FAIL (76) from a step that stopped the install (1): it reports the
# first and fails on the second (design decision 23). (setup) So does setup's apply pass: a FAIL while
# AdGuard Home is still loading its lists is a wait for setup, not a stop
if [ -n "${TVGW_POSTINST:-}" ] || [ "$TVGW_SETUP_PASS" = apply ]; then
	tvgw verify || exit 76
	exit 0
fi
# the installer's exit status is the gateway's verdict: a FAIL after a deploy is an outage
exec tvgw verify
