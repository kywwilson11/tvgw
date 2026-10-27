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
install -d -m 755 /etc/tvgw /var/log/tvgw
install -d -m 2750 -g adm /var/lib/tvgw
install -d -m 755 /var/lib/tvgw/pcap
[ ! -f /var/lib/tvgw/tvgw.db ] || { chgrp adm /var/lib/tvgw/tvgw.db; chmod 640 /var/lib/tvgw/tvgw.db; }
[ ! -f /var/lib/tvgw/lgtv-keys.sqlite ] || chmod 600 /var/lib/tvgw/lgtv-keys.sqlite
[ -f /etc/tvgw/tvgw.conf ] || install -m 644 tvgw.conf.example /etc/tvgw/tvgw.conf
[ -f /etc/tvgw/block4.txt ] || install -m 644 nftables/block4.txt /etc/tvgw/block4.txt
install -m 644 nftables/doh-exclude.txt /etc/tvgw/doh-exclude.txt
. /etc/tvgw/tvgw.conf
: "${TV_MAC:?set TV_MAC in /etc/tvgw/tvgw.conf}" "${TV_IP:=10.10.10.17}" "${TV_NAME:=tv}"

# The Python package: its own venv, the `tvgw` CLI on PATH, LG LAN-API extra included
[ -x $VENV/bin/python ] || python3 -m venv $VENV
$VENV/bin/pip install -q --upgrade pip
$VENV/bin/pip install -q "$REPO[lgwebos]" pytest  # pytest: the hardware suite runs on the Pi
ln -sf $VENV/bin/tvgw /usr/local/bin/tvgw

# Shell glue and services
install -m 755 nftables/tvgw-apply bin/tvgw-extract bin/tvgw-prune bin/tvgw-doh-update bin/tvgw-analyze /usr/local/sbin/
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
	install -m 644 nginx/tvgw-gfts.conf /etc/nginx/conf.d/tvgw-gfts.conf
	install -d -m 755 /etc/nginx/tvgw && install -m 644 nginx/stream.conf /etc/nginx/tvgw/stream.conf
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
systemctl enable --now tvgw.service
systemctl restart tvgw.service dnsmasq.service
systemctl enable --now tvgw-flowlog.service tvgw-pcap.service tvgw-prune.timer tvgw-doh-update.timer tvgw-analyze.timer tvgw-verify.timer
systemctl restart tvgw-flowlog.service
tvgw verify || echo "tvgw: verify reported failures (see above)"
echo "tvgw: installed ($(tvgw --version))"
