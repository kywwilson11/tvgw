#!/bin/sh
# The TV's DHCP client hook: busybox udhcpc runs it in the TV's namespace with $1 the event and the lease
# in its environment (interface, ip, mask, router, dns). A TV takes what the gateway offers: its address
# and the default route. The lease is written to $TV_LEASE, a key=value line each, for the tests to read
# (tests/container/ctr.py, Gateway.add_tv).
set -eu
# udhcpc sets these; a missing one is the event that carries none of it
interface=${interface:?udhcpc names the interface} ip=${ip:-}
lease=${TV_LEASE:-/run/tvgw-container/tv-lease}
case "$1" in
deconfig)
	ip -4 addr flush dev "$interface"
	ip link set "$interface" up
	rm -f "$lease"
	;;
bound | renew)
	ip -4 addr flush dev "$interface"
	ip -4 addr add "$ip/${mask:-24}" dev "$interface"
	if [ -n "${router:-}" ]; then
		ip -4 route replace default via "${router%% *}" dev "$interface"
	fi
	printf 'ip=%s\nmask=%s\nrouter=%s\ndns=%s\n' "$ip" "${mask:-}" "${router:-}" "${dns:-}" >"$lease.tmp"
	mv -f "$lease.tmp" "$lease"
	;;
esac
exit 0
