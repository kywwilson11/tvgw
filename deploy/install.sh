#!/bin/bash
# Install or refresh the TV gateway on the Pi from this repository checkout:
#   sudo ./install.sh            (run from deploy/)
# Prerequisites (apt): tcpdump conntrack dnsmasq tshark nginx libnginx-mod-stream python3-venv
# plus AdGuard Home installed natively (see docs/lg-cx-deployment.md). Settings live in
# /etc/tvgw/tvgw.conf (created from tvgw.conf.example on first install; edit TV_MAC/TV_IP/TV_NAME).
set -euo pipefail
cd "$(dirname "$0")"
REPO=$(cd .. && pwd)
VENV=/opt/tvgw-venv

# State holds the TV's whole DNS/connection history and the LAN-API pairing key: root plus the
# admin group may read it (setgid so files created later inherit the group), nobody else
install -d -m 755 /etc/tvgw
install -d -m 2750 -g adm /var/log/tvgw
for f in /var/log/tvgw/*.log; do [ -f "$f" ] && chgrp adm "$f" && chmod 640 "$f"; done
# the state dir is traversable (x) but not listable or readable by others: tshark runs as nobody
# and must reach the pcaps, which belong to group nogroup (tvgw-pcap.service writes them 640)
install -d -m 2751 -g adm /var/lib/tvgw
install -d -m 2750 -g nogroup /var/lib/tvgw/pcap
for f in /var/lib/tvgw/pcap/*.pcap; do [ -f "$f" ] && chgrp nogroup "$f" && chmod 640 "$f"; done
[ ! -f /var/lib/tvgw/tvgw.db ] || { chgrp adm /var/lib/tvgw/tvgw.db; chmod 640 /var/lib/tvgw/tvgw.db; }
[ ! -f /var/lib/tvgw/lgtv-keys.sqlite ] || chmod 600 /var/lib/tvgw/lgtv-keys.sqlite
for f in /var/lib/tvgw/tvcheck.txt /var/lib/tvgw/tvcheck-history.log /var/lib/tvgw/doh4.txt /var/lib/tvgw/reports/*.txt /var/lib/tvgw/reports/*.json; do
	[ -f "$f" ] && chgrp adm "$f" && chmod 640 "$f"
done
[ -f /etc/tvgw/tvgw.conf ] || install -m 644 tvgw.conf.example /etc/tvgw/tvgw.conf
[ -f /etc/tvgw/block4.txt ] || install -m 644 nftables/block4.txt /etc/tvgw/block4.txt
[ -f /etc/tvgw/doh-exclude.txt ] || install -m 644 nftables/doh-exclude.txt /etc/tvgw/doh-exclude.txt
. /etc/tvgw/tvgw.conf
: "${TV_MAC:?set TV_MAC in /etc/tvgw/tvgw.conf}" "${TV_IP:=10.10.10.17}" "${TV_NAME:=tv}"
: "${URL_FILTER_RESOLVER:=1.1.1.1}" # what nginx resolves the vendor's file-service names with (not AdGuard: it rewrites them to us)

# The Python package: its own venv, the `tvgw` CLI on PATH, LG LAN-API extra included
[ -x $VENV/bin/python ] || python3 -m venv $VENV
$VENV/bin/pip install -q --upgrade pip
$VENV/bin/pip install -q "$REPO[lgwebos]" pytest  # pytest: the hardware suite runs on the Pi
ln -sf $VENV/bin/tvgw /usr/local/bin/tvgw

# Shell glue and services
install -m 755 nftables/tvgw-apply bin/tvgw-prune bin/tvgw-doh-update bin/tvgw-analyze /usr/local/sbin/
# The text-report pipeline (tvgw-extract, the TSV archive, the legacy report script) is retired:
# everything it produced is in the store. Its files go; the old reports move aside once.
rm -f /usr/local/sbin/tvgw-extract /var/lib/tvgw/sni.tsv /var/lib/tvgw/http.tsv /var/lib/tvgw/querylog.json
rm -rf /var/lib/tvgw/archive /var/lib/tvgw/reports/brief /var/lib/tvgw/reports/brief-latest.txt
if [ -d /var/lib/tvgw/reports ] && [ ! -f /var/lib/tvgw/reports/.from-the-store ]; then
	install -d -m 2750 -g adm /var/lib/tvgw/reports/legacy
	for f in /var/lib/tvgw/reports/latest.* /var/lib/tvgw/reports/daily/* /var/lib/tvgw/reports/weekly/*; do
		[ -e "$f" ] && mv -f "$f" /var/lib/tvgw/reports/legacy/
	done
	touch /var/lib/tvgw/reports/.from-the-store
fi
sed -e "s/__TV_MAC__/$TV_MAC/; s/__TV_IP__/$TV_IP/g; s/__TV_NAME__/$TV_NAME/" dnsmasq/tvgw.conf.template >/etc/dnsmasq.d/tvgw.conf
install -m 644 networkmanager/90-tvgw.conf /etc/NetworkManager/conf.d/90-tvgw.conf
install -m 755 networkmanager/90-tvgw-dispatcher /etc/NetworkManager/dispatcher.d/90-tvgw
install -m 644 logrotate/tvgw /etc/logrotate.d/tvgw
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
nmcli con up tv-lan

# URL filter for the vendor's plain-HTTP file service (profile url_filter); AdGuard must rewrite
# those names to the gateway (the profile's .rules file carries the $dnsrewrite rules)
if command -v nginx >/dev/null; then
	sed "s/__RESOLVER__/$URL_FILTER_RESOLVER/" nginx/tvgw-gfts.conf >/etc/nginx/conf.d/tvgw-gfts.conf
	install -d -m 755 /etc/nginx/tvgw && sed "s/__RESOLVER__/$URL_FILTER_RESOLVER/" nginx/stream.conf >/etc/nginx/tvgw/stream.conf
	grep -q 'tvgw/stream.conf' /etc/nginx/nginx.conf || echo 'include /etc/nginx/tvgw/stream.conf;' >>/etc/nginx/nginx.conf
	rm -f /etc/nginx/sites-enabled/default
	install -d /etc/systemd/system/nginx.service.d
	printf '[Unit]\nAfter=network-online.target\nWants=network-online.target\n[Service]\nRestart=on-failure\nRestartSec=5\n' \
		>/etc/systemd/system/nginx.service.d/tvgw.conf
	nginx -t && systemctl enable nginx >/dev/null 2>&1 && systemctl restart nginx
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
systemctl enable tvgw.service >/dev/null 2>&1 || true
# re-apply in place when the firewall is already up: a restart would run ExecStop (forwarding off)
# and black out the TV for a second; tvgw-apply itself is idempotent and atomic
if systemctl is-active -q tvgw.service; then /usr/local/sbin/tvgw-apply; else systemctl restart tvgw.service; fi
systemctl restart dnsmasq.service
systemctl enable --now tvgw-flowlog.service tvgw-pcap.service tvgw-prune.timer tvgw-doh-update.timer tvgw-analyze.timer tvgw-verify.timer
systemctl restart tvgw-flowlog.service
tvgw verify || echo "tvgw: verify reported failures (see above)"
systemctl start tvgw-analyze.service || echo "tvgw: first analyze run reported problems (journalctl -u tvgw-analyze)"
echo "tvgw: installed ($(tvgw --version))"
