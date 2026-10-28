#!/bin/bash
# Install or refresh the TV gateway on the Pi from this repository checkout:
#   sudo ./install.sh            (run from deploy/)
# Prerequisites (apt): tcpdump conntrack dnsmasq tshark nginx libnginx-mod-stream python3-venv
# plus AdGuard Home installed natively (see docs/lg-cx-deployment.md). Settings live in
# /etc/tvgw/tvgw.conf (created from tvgw.conf.example on first install; edit TV_MAC/TV_IP/TV_NAME).
# Exits non-zero, with nothing after the failing step done, on an unusable setting, a config nginx
# rejects, a failed `tvgw adguard apply`, or a FAIL from the `tvgw verify` it ends with.
set -euo pipefail
die() { echo "tvgw: $*" >&2; exit 1; }
cd "$(dirname "$0")"
REPO=$(cd .. && pwd)
VENV=/opt/tvgw-venv
# one install at a time: `make deploy` and a CI deploy must never interleave
install -d -m 755 /run/tvgw
exec 8>/run/tvgw/install.lock
flock -w 600 8 || die "another install is running"

# State holds the TV's whole DNS/connection history and the LAN-API pairing key: root plus the
# admin group may read it (setgid so files created later inherit the group), nobody else
install -d -m 755 /etc/tvgw
install -d -m 2750 -g adm /var/log/tvgw
for f in /var/log/tvgw/*.log; do [ -f "$f" ] && chgrp adm "$f" && chmod 640 "$f"; done
# the state dir is traversable (x) but not listable or readable by others. tcpdump runs as the
# system user tvgw-pcap (primary group nogroup) and owns the pcap directory and files; tshark runs
# as nobody (in nogroup) and can read them but not change them
getent passwd tvgw-pcap >/dev/null || useradd --system --no-create-home --shell /usr/sbin/nologin -g nogroup tvgw-pcap
install -d -m 2751 -g adm /var/lib/tvgw
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
: "${URL_FILTER_RESOLVER:=1.1.1.1}" # what nginx resolves the vendor's file-service names with (not AdGuard: it rewrites them to us)
# the four values sed writes into the dnsmasq and nginx configs are refused here, before anything is
# written, rather than installed: `${TV_MAC:?}` let the template's all-zero MAC through to dnsmasq,
# and a name with `/` or `&` broke or rewrote the sed expression
mac='^([0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}$' subnet='^10\.10\.10\.[0-9]{1,3}$'
name='^[A-Za-z0-9_-]{1,63}$' ipv4='^[0-9]{1,3}(\.[0-9]{1,3}){3}$'
# an unknown TV is not an error yet: the network side is brought up first, then `tvgw discover`
# finds the TV and records it (interactively), and the pin is applied below
have_tv=yes
[[ ${TV_MAC:-} =~ $mac && $TV_MAC != 00:00:00:00:00:00 ]] || have_tv=no
[[ $TV_IP =~ $subnet ]] || die "TV_IP must be an address in 10.10.10.0/24"
[[ $TV_NAME =~ $name ]] || die "TV_NAME may contain letters, digits, - and _ only"
[[ $URL_FILTER_RESOLVER =~ $ipv4 ]] || die "URL_FILTER_RESOLVER must be an IPv4 address"

# The Python package: its own venv, the `tvgw` CLI on PATH, LG LAN-API extra included
[ -x $VENV/bin/python ] || python3 -m venv $VENV
$VENV/bin/pip install -q --upgrade pip
$VENV/bin/pip install -q "$REPO[lgwebos,analyst]" pytest  # pytest: the hardware suite runs on the Pi
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
render_dnsmasq() { # the pin line only once the TV is known
	if [ "$have_tv" = yes ]; then
		sed -e "s/__TV_MAC__/$TV_MAC/; s/__TV_IP__/$TV_IP/g; s/__TV_NAME__/$TV_NAME/" dnsmasq/tvgw.conf.template
	else
		sed -e "/__TV_MAC__/d" dnsmasq/tvgw.conf.template
	fi >/etc/dnsmasq.d/tvgw.conf
}
render_dnsmasq
install -m 644 networkmanager/90-tvgw.conf /etc/NetworkManager/conf.d/90-tvgw.conf
install -m 755 networkmanager/90-tvgw-dispatcher /etc/NetworkManager/dispatcher.d/90-tvgw
install -m 644 logrotate/tvgw /etc/logrotate.d/tvgw
# a capture unit is restarted only when its file changed: every restart is a sub-second hole in the
# evidence, and tvgw-pcap was never restarted at all, so unit changes waited for a reboot
restart=""
for u in tvgw-pcap tvgw-flowlog tvgw-dnsgate; do
	cmp -s "systemd/$u.service" "/etc/systemd/system/$u.service" || restart="$restart $u.service"
done
install -m 644 systemd/*.service systemd/*.timer /etc/systemd/system/

# TV side: static 10.10.10.1/24, no IPv6, never a default route; stop the stock DHCP profile fighting it
nmcli general reload conf
if ! nmcli -t -f NAME con show | grep -qx tv-lan; then
	nmcli -t -f NAME con show | grep -qx "Wired connection 1" &&
		nmcli con modify "Wired connection 1" connection.autoconnect no
	nmcli con add type ethernet ifname eth0 con-name tv-lan \
		ipv4.method manual ipv4.addresses 10.10.10.1/24 ipv4.never-default yes \
		ipv6.method disabled connection.autoconnect yes
fi
# bringing an active connection up again drops 10.10.10.1 for a moment and fires a dispatcher apply
nmcli -g GENERAL.STATE con show tv-lan | grep -qx activated || nmcli con up tv-lan

# First install with no TV identity: the TV side is up and dnsmasq hands out pool addresses, so the
# TV can be found now. Interactive runs ask; unattended ones stop here with the two commands to run.
if [ "$have_tv" = no ]; then
	systemctl restart dnsmasq.service
	if [ -t 0 ]; then
		echo "tvgw: the TV is not identified yet. Plug it into the gateway's TV port, switch it on, then pick it:"
		until tvgw discover --write; do
			read -r -p "tvgw: retry discovery? [Y/n] " ans
			[ "${ans:-y}" = n ] && die "TV not identified; run 'sudo tvgw discover --write' then 'sudo ./install.sh'"
		done
	else
		die "TV not identified and no terminal to ask on; run 'sudo tvgw discover --write' then 'sudo ./install.sh'"
	fi
	. /etc/tvgw/tvgw.conf
	[[ ${TV_MAC:-} =~ $mac && $TV_MAC != 00:00:00:00:00:00 ]] || die "discovery did not record a usable TV_MAC"
	[[ $TV_IP =~ $subnet ]] || die "TV_IP must be an address in 10.10.10.0/24"
	[[ $TV_NAME =~ $name ]] || die "TV_NAME may contain letters, digits, - and _ only"
	have_tv=yes
	render_dnsmasq
fi

# URL filter for the vendor's plain-HTTP file service (profile url_filter); AdGuard must rewrite
# those names to the gateway (`tvgw adguard apply` generates the $dnsrewrite rules from the profile and GW_IP)
if command -v nginx >/dev/null; then
	sed "s/__RESOLVER__/$URL_FILTER_RESOLVER/" nginx/tvgw-gfts.conf >/etc/nginx/conf.d/tvgw-gfts.conf
	install -d -m 755 /etc/nginx/tvgw && sed "s/__RESOLVER__/$URL_FILTER_RESOLVER/" nginx/stream.conf >/etc/nginx/tvgw/stream.conf
	grep -q 'tvgw/stream.conf' /etc/nginx/nginx.conf || echo 'include /etc/nginx/tvgw/stream.conf;' >>/etc/nginx/nginx.conf
	rm -f /etc/nginx/sites-enabled/default
	install -d /etc/systemd/system/nginx.service.d
	printf '[Unit]\nAfter=network-online.target\nWants=network-online.target\n[Service]\nRestart=on-failure\nRestartSec=5\n' \
		>/etc/systemd/system/nginx.service.d/tvgw.conf
	systemctl daemon-reload
	nginx -t || die "nginx rejected the generated config (see nginx -t output)"
	systemctl -q enable nginx
	# a reload keeps the TLS passthrough and downloads in progress; the drop-in is for the next boot
	systemctl reload-or-restart nginx
else
	echo "tvgw: nginx not installed; URL filter skipped (apt install nginx libnginx-mod-stream)"
fi

# AdGuard Home: blocklists, custom rules, upstreams and settings come from the profile + tvgw.conf.
# The one manual step is AdGuard's own first-run wizard (admin user); after that this owns the config.
if [ -f /opt/AdGuardHome/AdGuardHome.yaml ]; then
	install -d /etc/systemd/system/AdGuardHome.service.d
	printf '[Service]\nWorkingDirectory=/opt/AdGuardHome\n' >/etc/systemd/system/AdGuardHome.service.d/workdir.conf
	systemctl daemon-reload
	tvgw adguard apply
else
	echo "tvgw: AdGuard Home not set up yet; install it, finish its wizard, then run: sudo tvgw adguard apply"
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

# re-apply in place when the firewall is already up: a restart would run ExecStop (forwarding off)
# and black out the TV for a second; tvgw-apply itself is idempotent and atomic
if systemctl is-active -q tvgw.service; then /usr/local/sbin/tvgw-apply; else systemctl restart tvgw.service; fi
systemctl restart dnsmasq.service
systemctl enable --now tvgw-flowlog.service tvgw-pcap.service tvgw-dnsgate.service tvgw-prune.timer tvgw-doh-update.timer tvgw-analyze.timer tvgw-verify.timer tvgw-backup.timer tvgw-analyst.timer tvgw-analyst-weekly.timer tvgw-autoblock.timer
[ -z "$restart" ] || systemctl restart $restart
systemctl start tvgw-analyze.service || echo "tvgw: first analyze run reported problems (journalctl -u tvgw-analyze)"
systemctl start tvgw-backup.service || echo "tvgw: first backup reported problems (journalctl -u tvgw-backup)"
echo "tvgw: installed ($(tvgw --version)); verifying:"
# the installer's exit status is the gateway's verdict: a FAIL after a deploy is an outage
exec tvgw verify
