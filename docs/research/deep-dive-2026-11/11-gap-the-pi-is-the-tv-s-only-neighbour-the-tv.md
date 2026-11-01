# Gap 11: the Pi is the TV's only neighbour

*Proposal, 2026-11-01. Nothing here is built. It reads the research worktree at head `43b3bd9`: `deploy/nftables/tvgw-apply`, `deploy/systemd/tvgw.service`, `deploy/nginx/stream.conf`, `deploy/nginx/tvgw-gfts.conf`, `deploy/dnsmasq/tvgw.conf.template`, `src/tvgw/discover.py`, `src/tvgw/profile.py` and `src/tvgw/adguardcfg.py`. It extends [05 §1.6 and build item 5](05-tv-privacy-research-2026.md#16-the-cxs-firmware-and-security-position-settled-from-lgs-own-pages) and [06 F7](06-platform-and-kernel-depth.md#f7-unit-hardening-the-lines-to-adopt) and does not repeat them. Those sections treat the TV as hostile toward the internet and the home LAN, and the Pi's co-tenants as a danger to the TV. This one treats the TV as hostile toward the Pi. Work in flight on other branches (packaging, `tvgw setup`, the namespace CI, supply-chain pinning, capture v2, the hardened extractor, profiles v2) comes in only where this changes its design. Nothing here was run on the gateway. Every claim about the live box comes with a test to run.*

## Bottom line

One nftables chain, `inet tvgw`'s `input`, is all that stands between the TV and every socket on the Pi. That chain is deleted whenever `tvgw.service` stops. It is also missing at boot until `tvgw-apply` runs, and after any apply that fails. Its own rule, `ip daddr != 10.10.10.1 drop`, is what really protects the Pi. Linux uses the weak host model: "IP addresses are owned by the complete host on Linux, not by particular interfaces". So a socket bound to the Pi's LAN address can still be reached from `eth0`. The usual advice, "bind Samba, xrdp and qBittorrent to the LAN interface", is therefore not isolation here. The co-tenants are a live target. Debian shipped two xrdp advisories in 2026, including a pre-auth stack overflow (CVE-2025-68670) and 17 CVEs in DSA-6469-1 on 2026-08-27. nginx and dnsmasq each had a burst of 2026 CVEs. The AirPlay 2 receiver, if it was built from source, is outside Debian security support, and its upstream shipped pre-auth fixes in 5.5. Three fixes work no matter what nftables holds:

1. **A guard table that is never deleted.** `inet tvgw_guard` runs after `inet tvgw` on the same hooks, and a drop in any base chain is final.
2. **cgroup filters on each co-tenant unit.** `IPAddressDeny=10.10.10.0/24` on each one.
3. **dnsmasq without `CAP_NET_ADMIN`.** `dhcp-broadcast` and `no-ping` let it run without that capability, and that capability is enough to rewrite the firewall.

The pass found two more gaps, and both exist while the firewall is up:

- **The input chain never checks the source address.** The TV can spoof a LAN source and make AdGuard answer a home-LAN host.
- **The forward chain accepts any source in the /24.** A rooted TV that adds a second address gets out without a flow record and without the HTTPS/SVCB strip.

The nginx passthrough is not an open proxy: an SNI or Host outside the GFTS names fails closed, as read in nginx's own source.

## Findings

### F1. The TV-to-Pi wall is one chain, and it has four holes in time (settled from the repository)

`inet tvgw input` (tvgw-apply) accepts from `eth0` only established traffic, DHCP, and DNS, 80, 443 and rate-limited pings to `10.10.10.1`. It drops everything else, including `ip daddr != 10.10.10.1`. That last rule stops the TV from reaching the Pi's Wi-Fi or `tun0` addresses through the gateway MAC. It is the only defence the weak host model leaves ([ip-sysctl.rst, `arp_filter`](https://raw.githubusercontent.com/torvalds/linux/master/Documentation/networking/ip-sysctl.rst)). The chain is missing at four times:

| Window | Why the input chain is missing | How long |
|---|---|---|
| `systemctl stop tvgw` | `ExecStop` deletes `inet tvgw` (architecture.md says so) | until someone starts it |
| Boot | `tvgw.service` is `After=NetworkManager.service`; NM brings `eth0` up with `10.10.10.1` first, and the co-tenants start in parallel | seconds |
| A failed apply | under `set -e`, a rejected `inet tvgw` stops the script; a boot-time failure leaves no table at all | until fixed |
| Package upgrade | a `.deb` whose maintainer scripts `restart` the unit goes through `ExecStop` (packaging is in flight) | about a second per upgrade |

Forwarding is off in every one of these windows, so the TV stays dark toward the internet, as design decision 5 intends. The Pi itself is open. `netdev tvgw_l2` is deleted by the same `ExecStop`, so in the stop window only the `disable_ipv6` sysctl keeps IPv6 out.

**What faces the TV in those windows.** These are each daemon's defaults, from upstream sources. The live list is **unverified**, so run the test below.

| Service | Default listener | Can it be bound to one address? | Does binding stop the TV? |
|---|---|---|---|
| smbd | 0.0.0.0 and [::] on 445 and 139 | `interfaces = lo <LAN_IF>` plus `bind interfaces only = yes` | No (weak host). `hosts deny = 10.10.10.0/24` does filter by source |
| nmbd | UDP 137 and 138 on 0.0.0.0 **always** | No. It "also binds to the 'all addresses' interface (0.0.0.0) on ports 137 and 138" and filters by source, which "IP Source address spoofing does defeat" ([smb.conf(5)](https://www.samba.org/samba/docs/current/man-html/smb.conf.5.html)) | No. `disable netbios = yes` removes it |
| xrdp | `port=3389`, all interfaces | `port=tcp://<LAN_IP>:3389`, but "specifying interfaces requires said interfaces to be UP before xrdp starts" ([xrdp.ini](https://raw.githubusercontent.com/neutrinolabs/xrdp/devel/xrdp/xrdp.ini.in), [xrdp.ini(5)](https://raw.githubusercontent.com/neutrinolabs/xrdp/devel/docs/man/xrdp.ini.5.in)). With Wi-Fi as `WAN_IF` that is a boot race | No |
| xrdp-sesman | a UNIX socket in 0.10 (`ListenPort` = `sesman.socket`) ([sesman.ini(5)](https://raw.githubusercontent.com/neutrinolabs/xrdp/devel/docs/man/sesman.ini.5.in)) | n/a | n/a |
| qBittorrent WebUI | `Preferences/WebUI/Address` defaults to `*`, `WebUI/Port` to 8080 (preferences.cpp, release-5.1.0) | `WebUI\Address=127.0.0.1` (reach it over SSH) or `<LAN_IP>` | 127.0.0.1 yes (the kernel drops 127/8 arriving on `eth0` unless `route_localnet`); `<LAN_IP>` no |
| qBittorrent peers | `0.0.0.0` and `::` when `BitTorrent\Session\Interface` and `InterfaceAddress` are empty (`SessionImpl::getListeningIPs`, release-5.1.0) | `Session\Interface=tun0`; libtorrent then accepts "on any IP address bound to device" ([libtorrent settings](https://www.libtorrent.org/reference-Settings.html)) | Only the address part; the TV can still send to the `tun0` address through `eth0` |
| qBittorrent auth bypass | `WebUI/AuthSubnetWhitelist` (off by default) and `LocalHostAuth` | Check that the whitelist does not include `10.0.0.0/8` or the TV /24 | A whitelist that includes the TV's /24 means the TV needs no password |
| shairport-sync | RTSP on all addresses, port 7000 (AirPlay 2) or 5000 (classic) | `address = "a.b.c.d"` binds the RTSP socket; `interface` "only scopes the mDNS advertisement" (current upstream conf; whether 4.3.7 has `address` is **unverified**) ([sample conf](https://github.com/mikebrady/shairport-sync/blob/master/scripts/shairport-sync.conf)) | No |
| nqptp | UDP 319 and 320 on the wildcard: `open_sockets_at_port(NULL, 319, …)` with `AI_PASSIVE`; control port 9000 on `"localhost"` ([nqptp.c](https://raw.githubusercontent.com/mikebrady/nqptp/main/nqptp.c), [nqptp-utilities.c](https://raw.githubusercontent.com/mikebrady/nqptp/main/nqptp-utilities.c)) | No option | No. It ignores PTP from IPs that are not registered clocks, which limits it |
| avahi-daemon | UDP 5353 on every non-loopback interface, `eth0` included | `deny-interfaces=eth0` "takes precedence over allow-interfaces" ([avahi-daemon.conf(5)](https://manpages.debian.org/trixie/avahi-daemon/avahi-daemon.conf.5.en.html)) | Yes; it stops both answering and announcing |
| sshd | 0.0.0.0:22 and [::]:22 | `ListenAddress` | No |
| AdGuard Home UI | `127.0.0.1:3000`, owned by `tvgw adguard apply` (`adguardcfg.http_address`) | already | Yes |
| AdGuard DNS | `dns.bind_hosts`, **not** among the keys tvgw owns | Bind it to `10.10.10.1` and `127.0.0.1` (the October survey §2) | Port 53 is allowed from the TV anyway |
| dnsmasq | UDP 0.0.0.0:67 (the DHCP socket is a wildcard; `interface=eth0` filters in software) | n/a | expected |
| nginx | `10.10.10.1:80` and `:443` only | already | Yes |

In the stop window the `output` chain's rule "no NetBIOS/SSDP chatter from the Pi into the TV subnet" is gone too. avahi then announces the Pi's name and its `_smb`, `_airplay` and `_raop` services on `eth0`. What the TV learns from that is the Pi's host name and what it runs. Whether qBittorrent's Local Service Discovery multicast (info-hashes) also reaches `eth0` when peers are bound to `tun0` is **unverified**.

**Test on the gateway (read-only):**

```sh
sudo ss -H -ltnup | awk '$5 ~ /^(0\.0\.0\.0|\*|\[::\]):/ {print $1, $5, $7}' | sort -u
grep -rn pcre_jit /etc/nginx; nginx -V 2>&1 | tr ' ' '\n' | grep -c stream
shairport-sync -V    # "AirPlay2" in the string means a source build: no Debian security support
grep -n 'AuthSubnetWhitelist\|WebUI\\Address\|Session\\Interface' ~qbtuser/.config/qBittorrent/qBittorrent.conf
```

Every line the first command prints is something the TV could reach in a window from the table above. The ones not in this table (the PIA daemon, the runner, CUPS, rpcbind) are the open question.

### F2. The co-tenants' 2025-2026 CVEs, and which ones the TV could reach (settled from the Debian tracker)

| Package (trixie) | 2025-26 items that matter | Fixed in trixie | Reachable from the TV segment? |
|---|---|---|---|
| **xrdp** 0.10.1 | CVE-2025-68670: an unauthenticated stack overflow in the domain field during connection, before 0.10.5; DSA-6123-1 ([tracker](https://security-tracker.debian.org/tracker/CVE-2025-68670)). **DSA-6469-1, 2026-08-27: 17 CVEs** (CVE-2026-32105 … CVE-2026-55645), among them CVE-2026-41252, a pre-auth heap overflow in `[vnc-any]` rated CVSS 9.8 ([GHSA-w5vg-6qmv-j63j](https://github.com/neutrinolabs/xrdp/security/advisories/GHSA-w5vg-6qmv-j63j)). The DSA also comments out `[vnc-any]` and rejects client alternate shells by default ([LWN](https://lwn.net/Articles/1090861/), [DSA-6469-1](https://security-tracker.debian.org/tracker/DSA-6469-1)) | `0.10.1-3.1+deb13u2` | **Yes, pre-auth, in every window.** The most dangerous co-tenant listener |
| **nginx** 1.26.3 | CVE-2026-42533 and CVE-2026-93479: worker heap overflows when a regex `map`'s capture variables are referenced before its output; DSA-6496-1 and DSA-6575-1 ([42533](https://security-tracker.debian.org/tracker/CVE-2026-42533), [93479](https://security-tracker.debian.org/tracker/CVE-2026-93479)). CVE-2026-28755: `ngx_stream_ssl_module` with `ssl_verify_client` and `ssl_ocsp` ([tracker](https://security-tracker.debian.org/tracker/CVE-2026-28755)) | `1.26.3-3+deb13u10` (trixie-security) | Always reachable, since nginx is the TV's own service. **tvgw's config does not meet the trigger.** The stream `map` is a regex with no captures, and the log format references `$ssl_preread_server_name`, not a capture. No `ssl_verify_client`. Patch anyway; see the CI lint in "What to build here" |
| **dnsmasq** 2.91 | Fixed: CVE-2026-4892 (DHCPv6 heap write, DSA-6264-1), CVE-2026-6507 (`--dhcp-split-relay`), CVE-2026-2291 and CVE-2026-5172 (DNS name parsing). Open in trixie: CVE-2026-93010 (leasequery without a source list), CVE-2026-93009 (DHCPv6 hostname parser), CVE-2026-93006 (TFTP), CVE-2026-93007 and -93008 (DNS) ([source package](https://security-tracker.debian.org/tracker/source-package/dnsmasq), [93010](https://security-tracker.debian.org/tracker/CVE-2026-93010), [6507](https://security-tracker.debian.org/tracker/CVE-2026-6507), [4892](https://security-tracker.debian.org/tracker/CVE-2026-4892)) | `2.91-1+deb13u2` | DHCPv4 is reachable by design. tvgw's config uses none of the open triggers (`port=0`, so no DNS or TFTP; no leasequery, DHCPv6 or relay). Keep it that way: CI should fail on `dhcp-range` with an IPv6 address, `leasequery`, `enable-tftp` or `dhcp-relay` |
| **samba** 4.22 | 2026 brought 10+ fixes, mostly for the AD DC, CTDB, winbind and WINS. For a plain file server the relevant ones are CVE-2026-4408 (RCE through `check password script` with `%u`, mainly when `samba-dcerpcd` runs as a system service; DSA-6297-1) and CVE-2026-1933 (authenticated reparse points on `read only` shares) ([4408](https://security-tracker.debian.org/tracker/CVE-2026-4408), [1933](https://security-tracker.debian.org/tracker/CVE-2026-1933), [package](https://security-tracker.debian.org/tracker/source-package/samba)). CVE-2025-10230 (WINS hook) needs the AD DC role | `2:4.22.11+dfsg-0+deb13u1` | Reachable in a window. The realistic risk is **configuration, not CVEs**: a guest share (`map to guest = bad user`) is readable and writable by the TV in any window |
| **qbittorrent** 5.1.0 | CVE-2025-54310: a local file link in the RSS and search widgets (GUI); CVE-2024-51774 (TLS verification) ([tracker](https://security-tracker.debian.org/tracker/source-package/qbittorrent)) | `5.1.0-2` | The WebUI is reachable in a window; neither CVE is a WebUI pre-auth bug. The risk is the auth whitelist (F1) |
| **shairport-sync** | Debian has **4.3.7-1** (2025-02-22). Its changelog first says "Enable AirPlay 2 mode" in the 5.1~dev upload of 2026-05-23 to unstable, so trixie's build appears to be classic AirPlay only (**unverified**; check `-V`) ([changelog](https://tracker.debian.org/media/packages/s/shairport-sync/changelog-5.1devgit20260518-1)). Upstream **5.5** (released "04 Sep"; the year is **unverified**, almost certainly 2026 given the May 2026 5.1 snapshot) fixed an unauthenticated stack overflow in RTSP, an unauthenticated crash from a two-byte pairing message, an AirPlay 2 SETUP out-of-bounds read, and a heap overflow in the classic Hammerton decoder ([release 5.5](https://github.com/mikebrady/shairport-sync/releases/tag/5.5)) | Not tracked; no CVEs assigned | **Yes, pre-auth, in every window.** AirPlay 2 on trixie means a source build, and `nqptp` is not in trixie at all (only forky and sid, 1.2.6) ([tracker](https://security-tracker.debian.org/tracker/source-package/nqptp)), so neither gets Debian security updates. A source build older than 5.5 is exposed |

**Rule of thumb this table supports:** xrdp and an AirPlay 2 source build are the two pre-auth C parsers on the box that the TV can reach. Both are fixed by one of three things: a firewall that is always present (F6), a cgroup filter (F6), or a version floor that `tvgw verify` warns on ("What to build here", item 7).

### F3. nginx is not an open proxy; SNI and Host outside GFTS fail closed (settled from config and nginx source)

- **Port 443.** `map $ssl_preread_server_name $tvgw_upstream` sends only the names matching `~^(aic-|aic-img-)?n?gfts\.lge\.com$` to the SNI's own host, and every other name to `""`. The proxy target is then `":443"`.
  - In trixie's nginx, `ngx_stream_proxy_eval` calls `ngx_parse_url`, which sets `u->err = "no host"` when the host is empty.
  - The session ends with `NGX_STREAM_INTERNAL_SERVER_ERROR` (status 500 in `gfts-tls.log`) before any upstream connection (src/stream/ngx_stream_proxy_module.c, src/core/ngx_inet.c, nginx 1.26.3-3+deb13u7 on sources.debian.org).
  - That covers `-servername example.com`, `-servername localhost`, no SNI at all, and non-TLS bytes.
  - The regex is case-sensitive and anchored, so `GFTS.LGE.COM` or a trailing dot also fail closed.
- **Port 80.** `if ($host !~* "^(aic-|aic-img-)?n?gfts\.lge\.com$") { return 444; }` runs before `proxy_pass http://$host$request_uri`. `$host` is taken from the absolute request-URI when there is one, and from Host otherwise. So the check and the proxy always read the same value, and `Host: localhost`, `Host: 127.0.0.1` or `GET http://example.com/` all get 444. The `biz_code` 403 runs first, which is harmless.
- **The residual bypass is narrow, but it is real.** An allowed GFTS connection leaves as the Pi's own traffic: through the VPN, past `tv_out`, `doh4`, `STRICT_PORTS` and the DNS gate, and outside the flow log's `--orig-src TV_IP` view of the upstream leg. Today it reaches only LG's GFTS addresses, resolved by `URL_FILTER_RESOLVER`, which the TV cannot influence. **Any future widening of either regex turns this into a filter bypass**, so it needs a CI test, not a comment.
- **A small DoS.** ssl_preread waits up to `preread_timeout`, 30 s by default ([ngx_stream_core_module](https://nginx.org/en/docs/stream/ngx_stream_core_module.html#preread_timeout)), against `worker_connections 768` in Debian's `nginx.conf`. The TV can hold the passthrough busy. `preread_timeout 5s;` and `limit_conn` per address bound it.

**Tests from the CI `tv` namespace** (the namespace harness is in flight; these are the cases to add):

```sh
# each must print no certificate: nginx closes the session before any upstream connect
for sni in example.com localhost 127.0.0.1 GFTS.LGE.COM gfts.lge.com.; do
  ip netns exec tv timeout 5 openssl s_client -connect GW_IP:443 -servername "$sni" </dev/null 2>&1 | grep -q 'BEGIN CERTIFICATE' && echo "FAIL $sni"
done
ip netns exec tv timeout 5 openssl s_client -connect GW_IP:443 -noservername </dev/null 2>&1 | grep -q 'BEGIN CERTIFICATE' && echo "FAIL no-SNI"
ip netns exec tv curl -s -o /dev/null -w '%{http_code}' -H 'Host: example.com' http://GW_IP/        # 000 (444 closes without a reply)
ip netns exec tv curl -s -o /dev/null -w '%{http_code}' -H 'Host: 127.0.0.1' http://GW_IP/          # 000
ip netns exec tv curl -s -o /dev/null -w '%{http_code}' --request-target 'http://example.com/' -H 'Host: gfts.lge.com' http://GW_IP/   # 000
grep -c ' 500 0 0 ' /var/log/tvgw/gfts-tls.log   # in the pi namespace: one line per refused SNI
```

In the namespace, put a canary listener on the Pi's loopback (`python3 -m http.server 8443 --bind 127.0.0.1`) and assert that its access log stays empty.

### F4. The input chain never checks the source address, so the TV can make the Pi talk to the LAN (settled from the repository and systemd's defaults)

`forward` drops a source outside `10.10.10.0/24`. `input` does not check the source at all. The kernel will not drop a spoofed source arriving on `eth0` either: systemd ships `net.ipv4.conf.default.rp_filter = 2` and `net.ipv4.conf.*.rp_filter = 2` ([50-default.conf, systemd 257.13 in trixie](https://sources.debian.org/data/main/s/systemd/257.13-1~deb13u1/sysctl.d/50-default.conf)). Loose mode accepts any source that is routable through any interface, and a home-LAN source is routable through `WAN_IF`.

So a TV, rooted or merely running a raw-socket-capable app, can send UDP to `10.10.10.1:53` with a home-LAN host's address as the source. AdGuard Home then answers that host over the Wi-Fi, carrying text the TV chose (the query name). That is a one-way TV-to-LAN path that `tv_out`'s `lan4` rule never sees, because it is the Pi's own output. AdGuard's per-client rate limit bounds it, but it does not close it. TCP to 80 and 443 cannot be spoofed this way, since the handshake replies go elsewhere.

**Fix, two layers:**

- **nftables.** In `inet tvgw input`, after `iifname != "$TV_IF" accept`: `ip saddr != { 0.0.0.0, $TV_NET } counter drop comment "TV source outside its subnet (input)"`. The 0.0.0.0 is for DHCPDISCOVER. The same rule goes in the guard (F6).
- **The kernel.** `/etc/sysctl.d/60-tvgw.conf`: `net.ipv4.conf.eth0.rp_filter = 1`. Strict mode works here because the TV's reverse route is the connected `eth0` route. The kernel uses the maximum of `all` and the interface value, so check that `net.ipv4.conf.all.rp_filter` is not 2: PIA may set it (**unverified**).

**Test (CI):** from `tv`, `ip netns exec tv nping --udp -p 53 -S 192.0.2.10 GW_IP --data-string x` (TEST-NET source standing for a LAN host). In the `pi` namespace, `tcpdump -ni lan host 192.0.2.10` must stay silent, and the new counter must tick.

### F5. Identity: a second address in the TV subnet escapes the flow log and the HTTPS strip; most L2 tricks gain nothing (settled from the repository and kernel source)

**The real gap is at L3.** `forward` accepts any source in `10.10.10.0/24`, but several pieces of evidence and policy key on `TV_IP` alone:

- `tvgw-flowlog` runs `conntrack … --orig-src "$TV_IP"`, so the alias's connections are never written to `flows.log`.
- The HTTPS/SVCB strip is `||*^$dnstype=HTTPS|SVCB,client=<TV_IP>` (`profile.py`). An alias gets ECH keys and address hints again.
- AdGuard's TV client entry is matched by IP or MAC. Whether MAC matching works without AdGuard's own DHCP is **unverified**.
- The pcap filter (`ip src net 10.10.10.0/24`) and the DNS gate (`ip saddr $TV_NET`) do cover the alias.

A TV with root, through the webOS kernel LPE 05 cites (CVE-2025-38352), can `ip addr add 10.10.10.200/24 dev eth0` and use the internet with no flow records and no ECH strip. No DHCP is needed.

- **Fix A (always).** Once `TV_IP` is known, `forward`'s source rule becomes `iifname "$TV_IF" ip saddr != $TV_IP counter drop comment "TV source is not the TV"`. That is one word, and `tvgw verify` checks it as part of `inet tvgw`'s baseline.
- **Fix B (dnsmasq).** Once the TV is pinned, `dhcp-range=10.10.10.0,static,255.255.255.0,12h`. Static mode means "only hosts which have static addresses given via --dhcp-host … will be served" (dnsmasq(8), 2.91). DHCPDISCOVERs with forged client MACs then get no lease and cannot exhaust the pool. The installer's discovery phase keeps today's dynamic range.

**L2, question by question:**

| Trick | Effect on this Pi | Defence |
|---|---|---|
| ARP spoofing toward the Pi | The Pi has nothing to poison. `eth0`'s neighbour table holds only the TV, routing chooses the interface, and `arp_accept=0` (the default) does not create entries from gratuitous ARP | None needed; the L2 pin below counts it |
| ARP probing for the Pi's other addresses | With `arp_ignore=0` (the default) the Pi answers ARP for its Wi-Fi and `tun0` addresses on `eth0` | `net.ipv4.conf.eth0.arp_ignore=1` ("reply only if the target IP address is local address configured on the incoming interface"), `arp_announce=2` ([ip-sysctl.rst](https://raw.githubusercontent.com/torvalds/linux/master/Documentation/networking/ip-sysctl.rst)). This is cosmetic: the TV can still reach those addresses through the gateway MAC, and only `ip daddr != 10.10.10.1 drop` stops that |
| Rogue DHCP server on the TV | No effect: the Pi's `eth0` is static under NetworkManager, and there is no other client | none |
| Forged source MACs | Multiple identities (above); dnsmasq pool exhaustion | Fix B; the L2 pin below |
| VLAN-tagged frames | A frame with a non-zero VID and no VLAN device "couldn't [be] receive[d]" and is marked `PACKET_OTHERHOST`, so the stack never delivers it (`__netif_receive_skb_core`, net/core/dev.c, linux-6.18.y) | Drop and count it in the L2 pin |
| LLDP, 802.1X EAPOL | Nothing on the Pi parses them unless NetworkManager has `connection.lldp` enabled for the `eth0` profile (valid values `default`, `disable`, `enable-rx`) ([nm-settings-nmcli(5)](https://manpages.debian.org/trixie/network-manager/nm-settings-nmcli.5.en.html)); there is no 802.1X authenticator | `nmcli -g connection.lldp con show <eth0 profile>` must not say `enable-rx` |
| Any frame vs. the capture | AF_PACKET taps run **before** the netdev ingress hook: `ptype_all` delivery, then `skip_taps:`, then `sch_handle_ingress`, then `nf_ingress` (dev.c, 6.18). An L2 drop does not keep frames away from tcpdump or dumpcap; the BPF filter and the sandboxed tshark do | already in place (capture v2, extractor) |

**Should `netdev tvgw_l2` admit only IPv4 and ARP from `TV_MAC`?** Yes. Do it when `TV_MAC` is known, count first, and keep the existing IPv6 counter first so `tvgw verify`'s reading of it does not change. The nft keywords used are documented in the ARP and Ethernet header tables of [nft(8)](https://www.netfilter.org/projects/nftables/manpage.html):

```nft
table netdev tvgw_l2 {
	chain in {
		type filter hook ingress device "eth0" priority -500; policy accept;
		ether type ip6 counter drop comment "no IPv6 from the TV"
		ether saddr != $TV_MAC limit rate 6/minute log prefix "tvgw-l2: "
		ether saddr != $TV_MAC counter drop comment "frame not from the TV's MAC"
		ether type != { ip, arp } counter drop comment "only IPv4 and ARP from the TV"
		arp saddr ether != $TV_MAC counter drop comment "ARP sender is not the TV"
		arp saddr ip != { 0.0.0.0, $TV_IP } counter drop comment "ARP for an address that is not the TV's"
		ip saddr != { 0.0.0.0, $TV_IP } counter drop comment "IPv4 source is not the TV"
	}
}
```

`0.0.0.0` covers DHCPDISCOVER and RFC 5227 ARP probes. With hardware VLAN offload, the kernel rebuilds the tag for payload matches, so `ether type` should read `8021q` for a tagged frame. That is **unverified on the Pi 5's RP1 Ethernet**, so test it in CI with `ip -n tv link add link veth-tv name veth-tv.5 type vlan id 5`. **Risk:** a wrong `TV_MAC` makes the TV dark. That is fail-closed, but it is an outage, so ship the rules behind a known `TV_MAC` and watch the counters for a week before relying on them. `tvgw_l2` only warns when it fails to load, so Fix A, in `inet tvgw`, remains the enforced layer.

### F6. A guard table the stop never deletes (designed here; nftables semantics settled from the wiki)

**Why it works.** "Drops take immediate effect, with no further rules or chains being evaluated". An accept "isn't necessarily final": a later base chain on the same hook still runs. Base chains run in priority order, lower first, and two chains with the same priority have no guaranteed order ([nftables wiki, Configuring chains](https://wiki.nftables.org/wiki-nftables/index.php/Configuring_chains)). So a separate table can only narrow what `inet tvgw` (or PIA's `iptables-nft` tables) accept. It can never widen it. That is the same property that makes `inet tvgw_gate` safe.

**Priority `filter + 10`, after `inet tvgw` (`filter - 10`).** While `inet tvgw` is loaded it drops first and keeps its counters, so decision 13's evidence is unchanged. The guard sees only what tvgw accepted, and its final drop counter should stay at zero. A non-zero value while `inet tvgw` is present means tvgw's input chain regressed, and `tvgw verify` can say so. While `inet tvgw` is absent, the guard catches everything.

`/usr/lib/tvgw/guard.nft`, rendered by `install.sh` like the other templates. It is one `nft -f` transaction: `add` plus `flush chain` re-applies atomically and never leaves a gap. It matches `iifname`, a string compare that works even before `eth0` exists at early boot, where `iif` needs the ifindex:

```nft
add table inet tvgw_guard
add chain inet tvgw_guard input { type filter hook input priority filter + 10; policy accept; }
add chain inet tvgw_guard forward { type filter hook forward priority filter + 10; policy accept; }
add chain inet tvgw_guard output { type filter hook output priority filter + 10; policy accept; }
flush chain inet tvgw_guard input
flush chain inet tvgw_guard forward
flush chain inet tvgw_guard output

add rule inet tvgw_guard input iifname != "eth0" accept
add rule inet tvgw_guard input meta nfproto ipv6 counter drop comment "guard: no IPv6 from the TV side"
add rule inet tvgw_guard input ip saddr != { 0.0.0.0, 10.10.10.0/24 } counter drop comment "guard: spoofed source"
add rule inet tvgw_guard input ct state established,related accept
add rule inet tvgw_guard input udp sport 68 udp dport 67 accept comment "guard: DHCP"
add rule inet tvgw_guard input ip daddr != 10.10.10.1 counter drop comment "guard: the gateway address only (weak host)"
add rule inet tvgw_guard input meta l4proto { tcp, udp } th dport 53 accept comment "guard: DNS"
add rule inet tvgw_guard input tcp dport { 80, 443 } accept comment "guard: nginx"
add rule inet tvgw_guard input icmp type echo-request limit rate 5/second accept
add rule inet tvgw_guard input counter drop comment "guard: TV may not reach other Pi services"

# if inet tvgw vanishes with forwarding still on (a flush, a CAP_NET_ADMIN attacker), the LAN stays closed
add rule inet tvgw_guard forward iifname "eth0" ip saddr != 10.10.10.0/24 counter drop comment "guard: TV source outside its subnet"
add rule inet tvgw_guard forward iifname "eth0" ip daddr { 10.0.0.0/8, 100.64.0.0/10, 169.254.0.0/16, 172.16.0.0/12, 192.168.0.0/16 } counter drop comment "guard: TV never to the LAN"
add rule inet tvgw_guard forward iifname "eth0" meta nfproto ipv6 counter drop

# 05 build item 5 moves here, so it survives the stop too
add rule inet tvgw_guard output oifname "eth0" ip daddr 10.10.10.0/24 tcp dport { 3000, 3001 } meta skuid != 0 counter drop comment "guard: TV API from root only"
```

The forward rules matter for one case. If `inet tvgw` is deleted while `net.ipv4.conf.eth0.forwarding` is still 1, there is no `post_nat`, and the TV's packets would leave un-NATed by rule 60 toward the home router. That is a one-way fail-open toward the LAN, and the guard stops it. The normal `ExecStop` order (forwarding off first) never gets there. A `nft flush ruleset` or a process holding `CAP_NET_ADMIN` would (F7).

**The unit.** It is modelled on Debian's `nftables.service`, which `install.sh` masks. The ordering lines are from memory of that unit, so read it with `systemctl cat nftables` before copying.

```ini
# /usr/lib/systemd/system/tvgw-guard.service
[Unit]
Description=tvgw: keep the Pi closed to the TV subnet (never removed)
DefaultDependencies=no
Wants=network-pre.target
Before=network-pre.target tvgw.service shutdown.target
After=systemd-modules-load.service local-fs.target
RefuseManualStop=yes

[Service]
Type=oneshot
RemainAfterExit=yes
ExecStart=/usr/sbin/nft -f /usr/lib/tvgw/guard.nft
ExecReload=/usr/sbin/nft -f /usr/lib/tvgw/guard.nft
# no ExecStop: stopping or removing the unit leaves the table in place

[Install]
WantedBy=sysinit.target
```

This closes all four windows in F1, including boot, where today the Pi is open from NetworkManager's `eth0` up until `tvgw-apply`.

**Three things that must change with it:**

1. **`tvgw discover`'s temporary holes.** Today it inserts an `output` accept for UDP 1900 and an `input` accept for the search socket's port into `inet tvgw` for the length of an SSDP search (`discover.py`, "Open exactly those two"). An accept in `inet tvgw` no longer gets a packet past the guard. Discover must insert the same input accept into `inet tvgw_guard input`, at its head, and delete it in the same `finally`. The output accept needs no change: the guard's output chain drops only TCP to 3000 and 3001 from non-root.
2. **`tvgw verify`.** Add two checks: `guard_present` (the table and the three chains exist, compared against a baseline listing like `inet tvgw`'s), and `guard_quiet`, a warning when the final drop counter grew while `inet tvgw` was loaded. Store the guard's counters in `fw_counters` like the others.
3. **The table is not invulnerable.** Table flags `owner` and `persist` exist ("table shall outlive the owning process", [nft(8)](https://www.netfilter.org/projects/nftables/manpage.html)). But an orphaned persistent table "will accept a new owner", so they protect against nothing a root or `CAP_NET_ADMIN` attacker can do. WATCH, do not adopt. The defence against `CAP_NET_ADMIN` is to hold fewer of them (F7).

**A second layer that does not depend on nftables.** systemd's `IPAddressDeny=` "turn[s] on network traffic filtering for IP packets sent and received over AF_INET and AF_INET6 sockets". Ingress is checked by source address and egress by destination. It is cgroup BPF, which the Pi kernel has (06 F6) ([systemd.resource-control(5)](https://www.freedesktop.org/software/systemd/man/latest/systemd.resource-control.html)). None of the co-tenants ever needs to talk to the TV, so one drop-in per unit closes them even with every nftables table flushed:

```ini
# /etc/systemd/system/<unit>.d/10-tvgw-not-from-tv.conf
# for smbd, nmbd, xrdp, qbittorrent-nox@<user>, shairport-sync, nqptp, avahi-daemon, ssh
[Service]
IPAddressDeny=10.10.10.0/24
```

- **Socket-activated sshd.** "A socket unit's list does not cover sockets created by the service it activates". If `ssh.socket` is in use, put the same line under `[Socket]` in `ssh.socket.d/`.
- **avahi.** Also set `deny-interfaces=eth0` in `/etc/avahi/avahi-daemon.conf`, so it does not announce the Pi there.
- **Do not put this drop-in on tvgw's own units, AdGuard, nginx or dnsmasq.** They talk to the TV by design.

**Acceptance test (namespace CI, then the gateway):**

```sh
# in CI: the pi namespace gets a second interface "lan" with 192.0.2.1/24 standing for the Wi-Fi address
systemctl stop tvgw.service            # or: nft delete table inet tvgw   (the half-apply case)
ip netns exec tv nmap -Pn -n -sT --top-ports 200 GW_IP               # open: 53, 80, 443 only
ip netns exec tv nmap -Pn -n -sU --top-ports 200 GW_IP               # open: 53; everything else open|filtered with no reply
ip netns exec tv nmap -Pn -n -sU -g 68 -p 67 GW_IP                   # DHCP answers only from source port 68
ip netns exec tv ip route add 192.0.2.0/24 via GW_IP
ip netns exec tv nmap -Pn -n -sT -sU --top-ports 200 192.0.2.1       # nothing open: the weak-host case
nft list chain inet tvgw_guard input | grep 'TV may not reach'       # counter > 0 now
systemctl start tvgw.service && sleep 60 && nft list chain inet tvgw_guard input | grep 'TV may not reach'   # counter unchanged after the start
```

One correction to the acceptance criterion as posed: with the guard, `nmap -sU` reports 67 as `open|filtered` unless the probe comes from port 68. That is the guard working, not a failure. Put canary listeners in the `pi` namespace on the co-tenants' ports (8080, 3389, 445, 7000, 319/udp, 5353/udp, 22), bound to `0.0.0.0` and to the `lan` address, so the scan proves something in CI where the real daemons do not run.

### F7. Who parses the TV's bytes, as whom, and the drop-ins for nginx and dnsmasq (settled from Debian sources)

| Process | Reads from the TV | Runs as (trixie) | Sandbox today |
|---|---|---|---|
| AdGuard Home | DNS queries | root | none; 06 F7 has the drop-in |
| nginx workers | HTTP, TLS ClientHello | `www-data` (`user www-data;` in Debian's `nginx.conf`); the master is root | **none**: Debian's `nginx.service` is plain `Type=forking` with no sandboxing directives ([nginx-common.nginx.service](https://sources.debian.org/data/main/n/nginx/1.26.3-3%2Bdeb13u7/debian/nginx-common.nginx.service)) |
| dnsmasq | DHCPv4 | user `dnsmasq` (`DNSMASQ_USER` defaults to it in `init-system-common`), but it **keeps `CAP_NET_ADMIN` and `CAP_NET_RAW`** while doing DHCP: "We keep CAP_NETADMIN (for ARP-injection) and CAP_NET_RAW (for icmp)" (src/dnsmasq.c, 2.91-1+deb13u2) | **none**: `dnsmasq.service` wraps `systemd-helper exec` with no sandboxing directives |
| tvgw-analyze | the TV's LAN-API JSON, through tvcheck | root, read-only system (architecture.md); 06 F7 narrows it | Python, memory-safe; the danger is logic, which `lgwebos.clean` handles |
| tshark | pcaps of TV frames | `nobody`, fully sandboxed | done |

No seccomp filter exists in either daemon. The Pi kernel runs no LSM (06 F6), so systemd is the only sandbox available.

**dnsmasq's `CAP_NET_ADMIN` is the firewall.** nftables changes need exactly that capability. A DHCP-parser bug in dnsmasq would let an attacker delete `inet tvgw` and the guard. The source shows how to avoid it:

```c
/* Need NET_ADMIN to change ARP cache if not always broadcasting. */
if (daemon->force_broadcast == NULL || daemon->force_broadcast->list != NULL)
  need_cap_net_admin = 1;
```

and, just above it, `if (!option_bool(OPT_NO_PING)) need_cap_net_raw = 1;`. So two lines in `/etc/dnsmasq.d/tvgw.conf` remove both capabilities:

```
dhcp-broadcast        # untagged = unconditional: no ARP-cache injection, so no CAP_NET_ADMIN
no-ping               # no ICMP check before an offer (one host on the segment), so no CAP_NET_RAW
```

dnsmasq(8) says `--dhcp-broadcast` with no tags "is unconditional". Then the drop-in:

```ini
# /etc/systemd/system/dnsmasq.service.d/20-tvgw-hardening.conf
[Service]
CapabilityBoundingSet=CAP_NET_BIND_SERVICE CAP_SETUID CAP_SETGID CAP_CHOWN
NoNewPrivileges=yes
ProtectSystem=strict
ReadWritePaths=/var/lib/misc /run
ProtectHome=yes
PrivateTmp=yes
PrivateDevices=yes
ProtectKernelTunables=yes
ProtectKernelModules=yes
ProtectKernelLogs=yes
ProtectControlGroups=yes
ProtectClock=yes
ProtectHostname=yes
RestrictAddressFamilies=AF_INET AF_INET6 AF_NETLINK AF_UNIX
RestrictNamespaces=yes
RestrictRealtime=yes
RestrictSUIDSGID=yes
LockPersonality=yes
MemoryDenyWriteExecute=yes
SystemCallArchitectures=native
SystemCallFilter=@system-service
IPAddressDeny=any
IPAddressAllow=localhost 0.0.0.0/32 255.255.255.255/32 10.10.10.0/24
```

- `CAP_CHOWN` is for the helper's `chown dnsmasq:nogroup /run/dnsmasq`.
- `IPAddressAllow` covers DISCOVER from 0.0.0.0, broadcast replies and unicast renewals.
- If a capability is missing, dnsmasq dies at start with "process is missing required capability". That is the test that the two config lines took effect.
- **Test:** `systemctl restart dnsmasq`, then `grep CapEff /proc/$(pidof dnsmasq)/status` (must decode to no `cap_net_admin`, through `capsh --decode`). Then power-cycle the TV and watch it take `TV_IP` (`journalctl -u dnsmasq -g DHCPACK`). Then `systemd-analyze security dnsmasq.service` before and after.

**nginx drop-in.** Add these lines to the `nginx.service.d/tvgw.conf` that `install.sh` already writes:

```ini
[Service]
CapabilityBoundingSet=CAP_NET_BIND_SERVICE CAP_SETUID CAP_SETGID CAP_CHOWN CAP_DAC_OVERRIDE
NoNewPrivileges=yes
ProtectSystem=strict
ReadWritePaths=/var/log/nginx /var/log/tvgw /var/lib/nginx /run
ProtectHome=yes
PrivateTmp=yes
PrivateDevices=yes
ProtectKernelTunables=yes
ProtectKernelModules=yes
ProtectKernelLogs=yes
ProtectControlGroups=yes
ProtectClock=yes
ProtectHostname=yes
RestrictAddressFamilies=AF_INET AF_UNIX
RestrictNamespaces=yes
RestrictRealtime=yes
RestrictSUIDSGID=yes
LockPersonality=yes
MemoryDenyWriteExecute=yes
SystemCallArchitectures=native
SystemCallFilter=@system-service
```

- **`MemoryDenyWriteExecute` is safe only while `pcre_jit` stays off.** It is off by default, and Debian's `nginx.conf` does not set it. PCRE2's JIT needs writable executable memory. The F1 `grep` proves it is off.
- **`AF_INET6` is left out** because tvgw listens and resolves on IPv4 only (`ipv6=off`). If nginx serves anything else on the box, add it back.
- **`NoNewPrivileges` is safe here.** The master drops to `www-data` with `setuid()`, which NNP allows; NNP blocks only privilege gained through `execve`.
- **Test:** `nginx -t`, `systemctl restart nginx`, and the F3 tests. The 403 and 200 `curl` lines in `deploy/nginx/README.md` must still pass. Then `systemd-analyze security nginx.service`.

### Where this disagrees with earlier sections

- **05 §1.6, point 1, and build item 5.** They frame the danger as co-tenant to TV and limit only the Pi's output toward the TV. The more direct path runs the other way: TV to co-tenant in any F1 window, plus the DNS reflection of F4, which works with the firewall up. Item 5's rule also lives in `inet tvgw`, so it disappears in exactly the window it is meant for. It belongs in the guard (F6).
- **The October survey, §10.** "From the TV side only DHCP, DNS, nginx on 80 and 443, and rate-limited pings reach the Pi (observed)". That is true only while `tvgw.service` is up, and it ignores source spoofing.
- **architecture.md, Trust boundaries.** "It reaches DHCP, DNS, ports 80 and 443 and pings on `10.10.10.1`, nothing else on the Pi". Same correction. Add "while `inet tvgw` is loaded; `inet tvgw_guard` holds the same line at all times" once F6 is built.
- **06 F7.** It hardens tvgw's units and AdGuard and treats dnsmasq as a package default not worth touching. dnsmasq is the one daemon that parses TV input while holding the capability that controls the firewall, and two config lines take that capability away.
- **The assignment's own question 1.** Binding a co-tenant to the LAN interface is not isolation on Linux (F1). Use the cgroup filter and the guard. Bind to 127.0.0.1 only where the service is reached through SSH anyway (the qBittorrent WebUI).

## What to build here

Ranked by exposure closed per hour of work. The risk column is risk to the running gateway.

1. **`inet tvgw_guard` and `tvgw-guard.service`** (F6), with discover's hole added to the guard and two `tvgw verify` checks. *Effort S-M. Risk low.* The guard runs after tvgw and only narrows, so a mistake in it can at worst stop DHCP or DNS, which leaves the TV dark (fail-closed). Prove it in the namespace CI with the acceptance test, then on the Pi: `systemctl stop tvgw` and an `nmap` from a laptop plugged into `eth0` (owner-run).
2. **`IPAddressDeny=10.10.10.0/24` drop-ins for the co-tenants**, plus avahi's `deny-interfaces=eth0` (F6). *Effort S. Risk low:* none of them talks to the TV. Test: `systemctl show smbd -p IPAddressDeny`, then the CI canary listener under `systemd-run -p IPAddressDeny=10.10.10.0/24` must not answer the `tv` namespace and must answer the `lan` namespace.
3. **Source pinning.**
   - `input`: `ip saddr != { 0.0.0.0, $TV_NET } drop` (F4).
   - `forward`: `ip saddr != $TV_IP drop` once known (F5, Fix A).
   - `rp_filter=1` on `eth0`.
   - dnsmasq `static` range once pinned (Fix B).

   *Effort S. Risk low-medium:* a wrong `TV_IP` darkens the TV, but `TV_IP` is already the DHCP pin. Tests: the F4 `nping` case, and an alias address in the `tv` namespace that must get no forwarding (`ip -n tv addr add 10.10.10.200/24 dev veth-tv; ip netns exec tv curl --interface 10.10.10.200 -m 5 http://198.51.100.1/` must time out).
4. **dnsmasq without `CAP_NET_ADMIN` and `CAP_NET_RAW`:** `dhcp-broadcast`, `no-ping`, and the drop-in (F7). *Effort S. Risk low-medium:* a DHCP client that ignores broadcast replies would fail to get a lease. Every RFC 2131 client accepts them, but test with the real TV over a power cycle and a lease renewal before keeping it.
5. **The nginx drop-in, plus `preread_timeout 5s;` and `limit_conn_zone $binary_remote_addr zone=tv:1m; limit_conn tv 64;`** in `stream.conf`, plus the F3 CI cases. Add a lint that fails if either GFTS regex changes without a matching test update, or if a regex `map` with captures appears. *Effort S. Risk low.* Test: the F3 commands and the README's 403/200 lines.
6. **The L2 pin in `netdev tvgw_l2`** (F5), behind a known `TV_MAC`. Count for a week, then rely on it. *Effort S. Risk medium:* a wrong MAC darkens the TV, and the existing "warn only" load means it is not an enforced layer. Test: in CI, frames from a second MAC (`ip -n tv link set veth-tv address 02:00:00:00:00:02`) and a VLAN subinterface must both tick their counters and get no DHCP lease.
7. **A co-tenant posture check in `tvgw verify`** (report-only). Warn when:
   - xrdp is older than `0.10.1-3.1+deb13u2`, or `[vnc-any]` is uncommented in `/etc/xrdp/xrdp.ini`;
   - nginx is older than `1.26.3-3+deb13u10`;
   - `shairport-sync -V` shows `AirPlay2` with a version below 5.5;
   - qBittorrent's `AuthSubnetWhitelist` contains the TV subnet;
   - Samba has a guest-accessible share or `disable netbios = no`;
   - any wildcard listener appears that is not on an allowlist (the F1 `ss` command, diffed).

   *Effort M. Risk none.* Test: run it on the gateway and read the list.
8. **Package upgrades reload instead of restarting.** In nfpm's maintainer scripts, `systemctl reload tvgw.service` (with 06 F7's `ExecReload=`), never `restart`, so an upgrade does not open the F1 window even for a second. *Effort S. Risk low.* Test: `apt install --reinstall ./tvgw.deb` while the CI namespace pings `10.10.10.1:445` in a loop: no SYN-ACK.

## Open questions

- **What else listens.** The PIA daemon, the GitHub runner, CUPS, rpcbind, systemd-resolved: none is documented to listen on a wildcard, but that is **unverified**. Answer it with the F1 `ss` command.
- **Does PIA ever flush or reorder nftables?** It drives `iptables-nft`. If a reconnect ever ran `nft flush ruleset`, both `inet tvgw` and the guard would go, and only the cgroup drop-ins (build item 2) would remain. Test: `nft monitor ruleset` across a PIA reconnect, owner-run.
- **Does the CX send any non-IPv4, non-ARP frame?** LLDP, EAPOL-Start, IPv6 ND (already counted). The L2 counters (build item 6) answer this in a week.
- **qBittorrent LSD in the stop window.** Does Local Service Discovery multicast leave on `eth0` when peers are bound to `tun0`? Test: `tcpdump -ni eth0 udp port 6771` during a stop window in CI, with qBittorrent in the `pi` namespace.
- **cgroup ingress filtering on a listening TCP socket.** Does it stop the SYN (no SYN-ACK), or only data after the handshake? The design does not depend on which, but the CI canary test (build item 2) should record which one happens.
- **`ether type` and the RP1 VLAN offload.** Does `ether type != { ip, arp }` see `8021q` on the Pi 5 with `rx-vlan-offload` on? Test as in F5, then on the Pi with `ethtool -k eth0 | grep vlan`.
- **AdGuard `dns.bind_hosts`.** tvgw does not own it. Should it, given the October survey's advice to bind to `10.10.10.1` and loopback? It does not change TV reachability (port 53 is allowed), but it does change who on the LAN can use the TV's resolver.

## Sources

Kernel and netfilter:

- nftables wiki, Configuring chains (verdicts across base chains, priority order): https://wiki.nftables.org/wiki-nftables/index.php/Configuring_chains
- nftables wiki, Matching routing information: https://wiki.nftables.org/wiki-nftables/index.php/Matching_routing_information
- nft(8) (fib example "drop packets if the destination ip address is not configured on the incoming interface"; table flags owner/persist/dormant; ARP, Ethernet and VLAN expressions): https://www.netfilter.org/projects/nftables/manpage.html
- ip-sysctl.rst (`arp_ignore`, `arp_announce`, `arp_filter` and "IP addresses are owned by the complete host on Linux", `route_localnet`): https://raw.githubusercontent.com/torvalds/linux/master/Documentation/networking/ip-sysctl.rst
- net/core/dev.c, linux-6.18.y (`__netif_receive_skb_core`: taps, `skip_taps`, `sch_handle_ingress`, `nf_ingress`, VLAN `PACKET_OTHERHOST`): https://git.kernel.org/pub/scm/linux/kernel/git/stable/linux.git/plain/net/core/dev.c?h=linux-6.18.y
- systemd 257.13 (trixie) `sysctl.d/50-default.conf` (`rp_filter = 2`): https://sources.debian.org/data/main/s/systemd/257.13-1~deb13u1/sysctl.d/50-default.conf
- systemd.resource-control(5) (`IPAddressAllow/Deny`, `RestrictNetworkInterfaces`): https://www.freedesktop.org/software/systemd/man/latest/systemd.resource-control.html

Debian security tracker:

- xrdp: https://security-tracker.debian.org/tracker/source-package/xrdp ; CVE-2025-68670: https://security-tracker.debian.org/tracker/CVE-2025-68670 ; CVE-2026-55645: https://security-tracker.debian.org/tracker/CVE-2026-55645 ; DSA-6469-1: https://security-tracker.debian.org/tracker/DSA-6469-1 ; LWN copy, 2026-08-27: https://lwn.net/Articles/1090861/
- xrdp advisories: https://github.com/neutrinolabs/xrdp/security/advisories ; GHSA-w5vg-6qmv-j63j (CVE-2026-41252): https://github.com/neutrinolabs/xrdp/security/advisories/GHSA-w5vg-6qmv-j63j
- nginx: https://security-tracker.debian.org/tracker/source-package/nginx ; CVE-2026-42533: https://security-tracker.debian.org/tracker/CVE-2026-42533 ; CVE-2026-93479: https://security-tracker.debian.org/tracker/CVE-2026-93479 ; CVE-2026-28755: https://security-tracker.debian.org/tracker/CVE-2026-28755
- dnsmasq: https://security-tracker.debian.org/tracker/source-package/dnsmasq ; CVE-2026-93010: https://security-tracker.debian.org/tracker/CVE-2026-93010 ; CVE-2026-6507: https://security-tracker.debian.org/tracker/CVE-2026-6507 ; CVE-2026-4892: https://security-tracker.debian.org/tracker/CVE-2026-4892
- samba: https://security-tracker.debian.org/tracker/source-package/samba ; CVE-2026-4408: https://security-tracker.debian.org/tracker/CVE-2026-4408 ; CVE-2026-1933: https://security-tracker.debian.org/tracker/CVE-2026-1933
- qbittorrent: https://security-tracker.debian.org/tracker/source-package/qbittorrent ; CVE-2025-54310: https://security-tracker.debian.org/tracker/CVE-2025-54310
- shairport-sync: https://security-tracker.debian.org/tracker/source-package/shairport-sync ; nqptp: https://security-tracker.debian.org/tracker/source-package/nqptp

Daemon sources and documentation:

- nginx 1.26.3 (trixie) sources: src/stream/ngx_stream_proxy_module.c, src/core/ngx_inet.c, debian/nginx-common.nginx.service, debian/conf/nginx.conf under https://sources.debian.org/data/main/n/nginx/1.26.3-3%2Bdeb13u7/
- nginx stream core (`preread_timeout`): https://nginx.org/en/docs/stream/ngx_stream_core_module.html#preread_timeout
- dnsmasq 2.91 (trixie) sources: src/dnsmasq.c (capability logic), man/dnsmasq.8 (`static` mode, `--dhcp-broadcast`, `--no-ping`), debian/dnsmasq.service, debian/init-system-common under https://sources.debian.org/data/main/d/dnsmasq/2.91-1%2Bdeb13u2/
- smb.conf(5): https://www.samba.org/samba/docs/current/man-html/smb.conf.5.html
- xrdp.ini.in (port syntax): https://raw.githubusercontent.com/neutrinolabs/xrdp/devel/xrdp/xrdp.ini.in ; xrdp.ini(5): https://raw.githubusercontent.com/neutrinolabs/xrdp/devel/docs/man/xrdp.ini.5.in ; sesman.ini(5): https://raw.githubusercontent.com/neutrinolabs/xrdp/devel/docs/man/sesman.ini.5.in
- qBittorrent release-5.1.0: src/base/preferences.cpp (`WebUI/Address` default `*`, port 8080, `AuthSubnetWhitelist`), src/base/bittorrent/sessionimpl.cpp (`Session/Interface`, `InterfaceAddress`, `getListeningIPs`): https://github.com/qbittorrent/qBittorrent/tree/release-5.1.0/src/base
- libtorrent settings (`listen_interfaces`, `outgoing_interfaces`): https://www.libtorrent.org/reference-Settings.html
- shairport-sync sample configuration: https://github.com/mikebrady/shairport-sync/blob/master/scripts/shairport-sync.conf ; release 5.5: https://github.com/mikebrady/shairport-sync/releases/tag/5.5 ; Debian changelog: https://tracker.debian.org/media/packages/s/shairport-sync/changelog-5.1devgit20260518-1
- nqptp README and sources: https://github.com/mikebrady/nqptp , https://raw.githubusercontent.com/mikebrady/nqptp/main/nqptp.c , https://raw.githubusercontent.com/mikebrady/nqptp/main/nqptp-utilities.c
- avahi-daemon.conf(5), trixie: https://manpages.debian.org/trixie/avahi-daemon/avahi-daemon.conf.5.en.html
- nm-settings-nmcli(5), trixie (`connection.lldp`): https://manpages.debian.org/trixie/network-manager/nm-settings-nmcli.5.en.html

Repository (head `43b3bd9`): `deploy/nftables/tvgw-apply`, `deploy/systemd/tvgw.service`, `deploy/systemd/tvgw-pcap.service`, `deploy/systemd/tvgw-flowlog.service`, `deploy/nginx/stream.conf`, `deploy/nginx/tvgw-gfts.conf`, `deploy/dnsmasq/tvgw.conf.template`, `deploy/install.sh`, `src/tvgw/discover.py`, `src/tvgw/profile.py`, `src/tvgw/adguardcfg.py`, `docs/architecture.md`.
