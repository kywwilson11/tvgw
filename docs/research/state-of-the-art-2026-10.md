# State of the art, October 2026: every tool tvgw uses, and what to do next

*R&D survey, 2026-10-27. This is a proposal, not a decision: nothing here is implemented. It checks each tool tvgw depends on against what exists in late 2026 and proposes new ones. It reads with [architecture.md](../architecture.md), [design-decisions.md](../design-decisions.md) and [data-architecture.md](../data-architecture.md); where it disagrees with them, it says so.*

**Method.** Web research (2025 and 2026 sources preferred), the repo at commit `24ec546` (including `tvgw discover`, added the same day), and no access to the Pi. Every non-obvious claim carries a URL. **(unverified)** means only one secondary source, or our own background knowledge, supports it. **(observed)** means the CX or the repo shows it. The shared web-search budget ran out near the end, so a few late items rest on page fetches or prior knowledge and are marked that way.

**Verdicts.** **ADOPT NOW**: do it next. **PROTOTYPE**: try it on a branch or in a network namespace with an acceptance test. **WATCH**: revisit when the named trigger happens. **REJECT**: not for tvgw, with the reason. Each verdict covers Pi 5 feasibility (CPU, RAM, storage wear, power), migration cost from what exists, and risk.

---

## Bottom line up front

- **The architecture is right for 2026.** Keep the dedicated wired segment, nftables, AdGuard Home and SQLite with a rollback journal. Nothing found is a better replacement for any of them. One finding strengthens a current decision: the WAL-reset corruption bug, fixed in SQLite 3.51.3, affects only WAL mode.
- **The gains are at the edges.** Ship tvgw as a real package. Let the installer find the TV, which has now started with `tvgw discover`. Capture handshakes by their position in the connection instead of by byte patterns. Replace tshark with a small sandboxed parser that also yields JA4 fingerprints and the names inside QUIC Initial packets. Harden DNS against HTTPS records and Encrypted ClientHello (ECH). Test the firewall in a network namespace on every push. Add a propose-only LLM analyst.
- **The one big new idea is DNS-gated egress.** The TV may connect only to addresses its own lookups returned. That makes hardcoded-address bypass and unknown DoH impossible rather than merely reported.

---

## 1. Capture

**Today.** tcpdump runs a BPF filter on `eth0` that keeps only frames the TV sends: SYN, FIN and RST; requests to TCP 80; UDP except QUIC short headers; segments that begin a TLS ClientHello record; segments that begin with an HTTP method. It writes hourly pcap files named in UTC. Each finished file is read once by tshark, running as `nobody`. Defects already listed in data-architecture §1 (#6, #7, #10) are not repeated here.

### 1.1 Findings

- **Post-quantum ClientHellos span several TCP segments.** Chromium-family TLS stacks now send ML-KEM key shares, so the ClientHello no longer fits in one packet, and Chrome randomizes extension order, so the server name can land in the second segment ([tldr.fail](https://tldr.fail/)). The current filter keeps only the segment that starts the record, so for those stacks it can miss the server name.
  - This is unlikely for the CX's webOS 5 browser engine. It is plausible for apps that bundle a current BoringSSL, such as YouTube's Cobalt (unverified for the CX).
  - Detection already exists: `pcaps_done.syn443_rows` against `tls_rows`, the check added after the 2026-10-27 incident.
- **nftables can pick packets by their position in the connection.** `ct original packets <= N` combined with `log group N` hands only the first N packets of each connection to nfnetlink_log, and `tcpdump -i nflog:N` or dumpcap writes them to a file ([nft(8)](https://man.archlinux.org/man/nft.8.en), [Wireshark NFLOG](https://wiki.wireshark.org/CaptureSetup/NFLOG), [worked example](https://covert.sh/2021/02/02/tcpdump-nflog-nftables/)). Gotchas:
  - **Counters need conntrack accounting.** Without it the counter reads 0 and every packet matches. `tvgw-apply` already sets `nf_conntrack_acct=1` (observed).
  - **Where the filter runs.** libpcap's nflog backend runs any BPF filter in userspace, does not set the queue threshold, and counts ENOBUFS overruns as drops ([libpcap source](https://raw.githubusercontent.com/the-tcpdump-group/libpcap/master/pcap-netfilter-linux.c)).
  - **One reader per group.** Only one process can subscribe to a group; to feed two readers, write two log statements.
  - **Link type 239.** Files have link type NFLOG, which tshark reads natively. A pure-Python reader needs about 20 lines to unwrap it.
  - **No prior art.** No public write-up combines a `ct packets` threshold with NFLOG capture (unverified that anyone runs this in production).
- **dumpcap rotates on the clock.** `-b interval:3600` rolls the file "when the time is an exact multiple" of the interval, so files start on the hour. `-b printname` prints each closed file name, which gives an event hook for the extractor ([dumpcap(1)](https://www.wireshark.org/docs/man-pages/dumpcap.html)). tcpdump `-G` rotates relative to its start and only when the next packet arrives (data-architecture #6).
  - Debian installs dumpcap with `cap_net_raw,cap_net_admin` file capabilities for the `wireshark` group, so it needs no root ([Debian postinst](https://git.lekensteyn.nl/peter/wireshark/tree/debian/wireshark-common.postinst)).
  - Wireshark 4.6 can compress files while capturing ([4.6.0 notes](https://www.wireshark.org/docs/relnotes/wireshark-4.6.0.html)).
- **The OS release decides which tshark we get.** Debian 12 has tshark 4.0.17; Debian 13 has 4.4.19 ([packages.debian.org](https://packages.debian.org/search?keywords=tshark&searchon=names&exact=1&suite=all&section=all)). Native JA4 fields arrived in the 4.2 line ([4.2.9 notes](https://wireshark.org/update/relnotes/wireshark-4.2.9.html)), so the Pi's current OS cannot produce JA4 from tshark.
- **eBPF is impractical on Pi kernels.** Raspberry Pi kernels ship without BTF, and a maintainer expects that to stay so ([raspberrypi/linux#6622](https://github.com/raspberrypi/linux/issues/6622)). The Pi 5 kernel also uses 16K pages ([pimylifeup](https://pimylifeup.com/raspberry-pi-page-size/)).
  - pwru needs BTF ([cilium/pwru](https://github.com/cilium/pwru)).
  - eCapture hooks TLS libraries on the local host, and the TV's TLS ends on the TV ([gojue/ecapture](https://github.com/gojue/ecapture)).
  - Cilium/Hubble and Retina are built around Kubernetes.
- **Zeek 8.0 LTS (Aug 2025), 8.1, 8.2 and 9.0 LTS (Sept 2026)** are current ([zeek.org](https://zeek.org/category/release/)). Its QUIC analyzer has been built in since 6.1 and logs `server_name`, ALPN and version ([quic.log](https://docs.zeek.org/en/current/logs/quic.html)). FoxIO's JA4 plugin writes JA4, JA4S, JA4H, JA4T and JA4L ([zeek.org, 2026-01](https://zeek.org/2026/01/how-to-use-ja4-network-fingerprints-in-zeek/)). Debian 12 arm64 packages exist on openSUSE's build service ([OBS security:zeek](https://download.opensuse.org/repositories/security:/zeek/Debian_12/)).
- **Suricata 8.0** (July 2025; trixie-backports has 8.0.7) logs `tls` and `quic` EVE events with SNI, JA3 and JA4 ([EVE format](https://docs.suricata.io/en/latest/output/eve/eve-json-format.html)). It can read from NFLOG directly ([source-nflog](https://doxygen.openinfosecfoundation.org/source-nflog_8c_source.html)).
- **nDPI 5.0** (Nov 2025, LGPLv3) adds a combined TCP, JA4 and certificate fingerprint, and detection when no DNS was seen ([ntop](https://www.ntop.org/?p=45295)).
- **Arkime 6.x** needs OpenSearch or Elasticsearch ([arkime.com](https://arkime.com/install)).
- **JA3 versus JA4.**
  - JA3 is broken for Chromium stacks: extension permutation changes the hash on every connection ([Fastly](https://fastly.com/blog/a-first-look-at-chromes-tls-clienthello-permutation-in-the-wild)).
  - JA4 sorts extensions and ciphers, so it is stable, and it is BSD-3 licensed.
  - JA4S, JA4H, JA4X, JA4T, JA4L and the rest are under the FoxIO License 1.1: internal and academic use only, patent pending ([FoxIO-LLC/ja4](https://github.com/FoxIO-LLC/ja4)). The database is at [ja4db.com](https://ja4db.com).
  - FoxIO's own Python and Rust JA4 tools shell out to tshark.
- **QUIC Initial packets can be read without any secret.** Their keys derive from the client's connection ID and a published salt; QUIC v2 uses a different salt and labels ([RFC 9369](https://www.rfc-editor.org/rfc/rfc9369.html), [Python walkthrough](https://tex2e.github.io/blog/protocol/quic-initial-packet-decrypt)). tvgw already keeps QUIC long-header packets (`udp[8] & 0x80`) and rejects the connection. Each Initial still names what the app tried to reach, and nothing reads it today.
- **ECH is now a standard, but not on TVs.**
  - It is RFC 9849, a Proposed Standard (2026) ([RFC 9849](https://www.rfc-editor.org/rfc/rfc9849)).
  - Cloudflare turns it on by default for free zones, with outer name `cloudflare-ech.com` ([Cloudflare](https://developers.cloudflare.com/ssl/edge-certificates/ech/)).
  - An IFIP 2026 study counts about 1.1M ECH deployments, 99.99% on Cloudflare, and finds GREASE ECH (a decoy extension with no real config behind it) outnumbering real ECH by two orders of magnitude ([paper](https://vaibhavbajpai.com/documents/papers/proceedings/2026-ifip-nw-ech.pdf)).
  - Android 17 enables ECH by default, fetching configs through HTTPS-record lookups in `DnsResolver` ([Android](https://developer.android.com/privacy-and-security/encrypted-client-hello)). Android TV is not mentioned.
  - Nothing shows webOS or TV streaming apps using ECH (unverified). It is very unlikely on webOS 5.
  - To tell real ECH from GREASE: both carry extension `0xfe0d`, but real ECH shows the provider's public name as the outer SNI.

### 1.2 Verdicts

| Option | Verdict | Why | Pi 5 | Migration | Risk |
|---|---|---|---|---|---|
| Keep tcpdump + BPF | ADOPT NOW, as the interim | Works, tested by `test_capture_filter.py`. | Negligible | None | Misses split ClientHellos; rotation phase |
| **dumpcap `-b interval:3600 -b printname`** in place of tcpdump | **ADOPT NOW** | Files start on the hour (fixes the rotation-phase half of data-architecture #6), pcapng, capability-based (no root), a close hook the extractor can follow. Same BPF syntax. | Same as tcpdump | One unit file and its test; the extractor reads pcapng already through tshark | Low. Watch file permissions (the 2026-10-27 incident) with the existing hardware test |
| **Position-based capture**: `ct original packets <= 8 log group 1` in the forward chain, placed before the QUIC/DoT rejects so attempts are kept too; dumpcap on `nflog:1` | **PROTOTYPE** | Keeps every handshake whole however it is segmented. Puts a hard bound on bytes captured per connection, so the privacy page's promise holds by construction rather than by byte matching. Captures DoT and QUIC attempts before they are rejected. Supersedes the BPF tightening in data-architecture §2.6. | Tens of packets/s; netlink cost negligible (no benchmark found) | Firewall change: needs the owner's approval (data-architecture §4 Q3); run in parallel with tcpdump for a week and compare `tls_rows` | Medium: a mistake in the log rule is a firewall change; ENOBUFS drops must be counted in Coverage |
| eBPF/XDP capture (bpftrace, pwru, Hubble, Retina, netobserv) | REJECT; WATCH #6622 | No BTF on Pi kernels; adds nothing that conntrack plus NFLOG lacks for forwarded traffic | External BTF file, about 5 MB | High | High |
| eCapture | REJECT | TLS terminates on the TV, not the Pi | n/a | n/a | n/a |
| Zeek 9 + JA4 plugin, offline over the hourly pcaps | PROTOTYPE, as a **differential oracle**, not in production | Run Zeek and our extractor over the same retained pcaps weekly and diff the server-name sets. That catches extraction faults like the 2026-10-27 incident. | A few hundred MB RSS (unverified); one batch a week | OBS repository plus a weekly unit | Low; adds a C++ dissector set (run unprivileged, as with tshark) |
| Suricata 8, no rules, EVE `tls`/`quic` only | PROTOTYPE | The best "metadata without pcaps" engine if we ever want to stop keeping pcaps | 128k AF_PACKET blocks in 8.0 raise memory ([upgrade notes](https://docs.suricata.io/en/latest/upgrade.html)); Pi numbers unverified | New ingest source | Medium: another large parser on hostile input |
| nDPI `ndpiReader` on flows with no name | PROTOTYPE | Classification for the "Unresolved" residue | Light | Small | Low |
| ntopng | REJECT | A web UI with Redis and dashboards; the brief is the interface | Moderate | High | Exposure |
| Arkime | REJECT | Needs an OpenSearch/Elasticsearch JVM cluster | Too heavy for an SD-card Pi | n/a | n/a |
| JA4 (BSD) | **ADOPT NOW**, computed by our extractor | Stable stack fingerprint; firmware diffs by stack; DoH from unknown stacks | Trivial | `tls.ja4` column (data-architecture §2.2 already plans `ja3`; use `ja4` instead) | Low |
| JA3 | REJECT | Chromium permutation breaks it | | | |
| JA4+ (S, H, X, T, L) | WATCH | Useful, but the FoxIO License limits redistribution; fine for private internal use | | | Licence |
| **QUIC Initial server-name extraction** | **ADOPT NOW** | The data is already in every pcap; it names what apps tried over HTTP/3 before they fell back | Needs AES-GCM and AES-ECB (`python3-cryptography`) | New `transport='quic'` rows (data-architecture §2.2) | Low |
| ECH canary: store extension `0xfe0d` and the outer server name | **ADOPT NOW** | Tells us the day ECH reaches the TV; outer name equal to a known public name means real ECH | Trivial | One column | Low |

---

## 2. DNS filtering

### 2.1 Findings

**AdGuard Home (current).** The stable release is v0.107.79 (2026-08-18) ([CHANGELOG](https://raw.githubusercontent.com/AdguardTeam/AdGuardHome/refs/heads/master/CHANGELOG.md)). Releases that matter here:

- **v0.107.73:** an authentication bypass through HTTP/2 cleartext (h2c) upgrades was fixed. The changelog: "Authentication is now applied to requests that have been upgraded from HTTP/2 Cleartext (H2C)". NVD lists it as CVE-2026-32136, rated critical ([NVD](https://nvd.nist.gov/vuln/detail/CVE-2026-32136)).
- **v0.107.74:** the config schema moved from 33 to 34.
- **v0.107.78:** the h2c upgrade path was removed entirely, and `$dnsrewrite` learned the HTTPS record `ech` parameter.
- **v1.0 beta (announced 2026-10-02)** warns that minor releases "may include backward-incompatible changes" ([AdGuard blog](https://adguard.com/en/blog/adguard-home-beta-version-1-0.html)).

Its query log stores both the answer and the original answer as wire bytes ([entry.go](https://raw.githubusercontent.com/AdguardTeam/AdGuardHome/master/internal/querylog/entry.go)), which is the best evidence fidelity of any self-hosted filter. Response-side CNAME checking catches CNAME cloaking ([FAQ](https://adguard-dns.io/kb/adguard-home/faq)). The `aaaa_disabled` option empties AAAA answers and, since 0.107.37, strips IPv6 hints from HTTPS answers. `handle_ddr` answers Discovery of Designated Resolvers queries locally ([Configuration wiki](https://github.com/AdguardTeam/AdGuardHome/wiki/Configuration)). tvgw owns neither key today (observed: `adguardcfg.py`).

**The alternatives:**

- **Pi-hole v6.** Current release is FTL v6.8, Web v6.6.1, Core v6.5 (2026-10-17). Scalar settings live in `pihole.toml`, but adlists, groups and clients stay in `gravity.db`. It has had a heavy 2026 advisory load, including remote code execution through newline injection in `dns.interface` (CVE-2026-39849) ([release](https://discourse.pi-hole.net/t/pi-hole-ftl-v6-8-web-v6-6-1-and-core-v6-5-released/87951), [CVE](https://db.gcve.eu/vuln/CVE-2026-39849)). It does not keep full answers (unverified).
- **Blocky 0.35** (Sept 2026). One schema-validated YAML file, stateless, with Prometheus metrics, query logs to SQLite or dnstap, DoQ and DoH3 upstreams, and DDR. It has no adblock modifiers, so there is no `$important` and no `$dnstype` ([releases](https://github.com/0xERR0R/blocky/releases)).
- **Technitium 15.** Runs on .NET 10, with a rich API and apps ([blog](https://blog.technitium.com/2026/04/technitium-dns-server-v15-released.html)).
- **Unbound with RPZ.** Clean and standard, but logs little about which rule matched.
- **CoreDNS.** Has no first-party blocking plugin.
- **dnscrypt-proxy 2.1.20.** Supports post-quantum DNSCrypt and anonymized relays ([releases](https://github.com/DNSCrypt/dnscrypt-proxy/releases)).
- **NextDNS and ControlD.** Good APIs, but a third party sees every lookup the TV makes ([NextDNS API](https://nextdns.github.io/api/)).

**DNS trends and how TVs bypass resolvers:**

- **HTTPS records.** HTTPS/SVCB records (type 65) are published by more than 20% of the top million domains, almost all on Cloudflare ([OARC 44](https://indico.dns-oarc.net/event/52/contributions/1156/attachments/1092/2234/OARC44_%20DNSHTTPSStudy.pdf)). They carry ECH configs and `alpn=h3` hints. One vendor now sells a control that blocks ECH-capable record types ([Palo Alto](https://docs.paloaltonetworks.com/whats-new/new-features/february-2026/dns-resource-record-type-control-for-advanced-dns-security)).
- **Hardcoded resolvers.** 68% of smart TVs in one field study queried Google DNS directly ([arXiv 2001.08288](https://arxiv.org/pdf/2001.08288)).
- **Browser DoH.** Chrome upgrades to DoH only when the configured resolver is on its same-provider list ([Chromium blog](https://blog.chromium.org/2020/09/a-safer-and-more-private-browsing.html)).
- **Android Private DNS** in automatic mode tries DoT on port 853 and falls back silently. tvgw already rejects 853.
- **DoH in apps.** Apps using DoH is reported anecdotally ([LWN comment](https://lwn.net/Articles/1021832)).

**Blocklists:**

- **HaGeZi `native.lgwebos`.** Version 2026.1023, 231 entries, GPL-3.0, built daily ([list](https://raw.githubusercontent.com/hagezi/dns-blocklists/main/adblock/native.lgwebos.txt), [README](https://raw.githubusercontent.com/hagezi/dns-blocklists/main/README.md)).
- **Perflyst SmartTV.** MIT licensed, with fresh LG commits in September 2026 ([commits](https://api.github.com/repos/Perflyst/PiHoleBlocklist/commits?path=SmartTV.txt&per_page=5)).
- **OISD.** Has no TV list ([oisd.nl](https://oisd.nl)).
- **The Northeastern "Watching the Watchers" study** (PoPETs 2027) publishes a tested ACR (automatic content recognition) blocklist under CC BY-NC-ND 4.0 ([paper](https://watchingthewatchers.github.io/watchingthewatchers/paper.html), [repo](https://github.com/IlgarNEU/Watching-the-Watchers)). Its licence forbids derivatives, so we can cite it but not merge it.
- **No upstream list publishes the opposite: what must not be blocked.** tvgw's `[must_allow]` list, with breakage notes, is that.

### 2.2 Verdicts

| Option | Verdict | Why | Pi 5 | Migration | Risk |
|---|---|---|---|---|---|
| **AdGuard Home, pinned** | **ADOPT NOW (keep)** | Best log fidelity, adblock modifiers, CNAME checks | Light | None | 2026 CVE cadence; mitigated by the loopback-bound UI (observed) |
| Add a **version floor** to `tvgw verify` (≥ 0.107.73) and the installed version to the brief's Coverage | **ADOPT NOW** | The h2c bypass is fixed only from 0.107.73 | n/a | Small | Low |
| Own `aaaa_disabled: true` and `handle_ddr: true` in `adguard apply` | **ADOPT NOW** | IPv6 is dropped at the wire; this also strips v6 hints | n/a | Two keys plus a diff test | Low |
| **Strip HTTPS/SVCB answers for the TV** (`$dnstype=HTTPS\|SVCB` scoped to the TV client) | **ADOPT NOW**, after one check | Keeps the server name visible, removes ECH configs and h3 hints; clients fall back to A records (RFC 9460) | n/a | One generated rule. Check first: `tvgw sql "select qtype, count(*) from dns group by 1"` shows whether the CX asks for type 65 at all | Low; test the exact rule syntax (design, not a documented recipe) |
| Track AdGuard v1.0; CI test of `adguardcfg` against each schema | WATCH | v1.0 may break config-as-code on minor releases | | Test harness | Medium at upgrade time |
| Blocky | WATCH | Best config-as-code model, but would lose `$important`, the mechanism behind must-allow; reconsider only if AdGuard v1.0 breaks config-as-code | Trivial | Moderate (rules port) | Medium |
| Pi-hole v6 | REJECT | Lists outside the TOML; worse logs; heavy 2026 advisory load | | | |
| Technitium | WATCH | Capable, but more than one TV needs | .NET footprint (unverified) | | |
| Unbound RPZ / CoreDNS as the filter | REJECT | Weak rule-match logging; no blocking plugin | | | |
| dnscrypt-proxy as AdGuard's upstream | WATCH | Anonymized relays if DoH-by-address over the VPN becomes a problem (decision 9) | Light | Small | Low |
| NextDNS / ControlD | REJECT | A third party sees every lookup | | | |
| **Publish our own general blocklist** | REJECT | HaGeZi does it better, daily | | | |
| **Contribute observed LG hosts upstream** (HaGeZi issues, Perflyst PRs) with the evidence in `lg-webos.rules` | **ADOPT NOW** | Our dated evidence is exactly what list maintainers need | | | Low |
| **Publish a must-allow and breakage ledger** (CC0 or MIT, generated from the TOML) | PROTOTYPE | New information no list carries: which hosts break what; must stay free of GPL list text | | Small | Low |

---

## 3. Firewall and network position

### 3.1 Findings

- **Versions.** nftables 1.1.7 was released 2026-09-01; trixie ships 1.1.3 and Ubuntu 26.04 ships 1.1.6 ([nftables news](https://nftables.org/news.html), [Debian tracker](https://security-tracker.debian.org/nftables), [Launchpad](https://launchpad.net/ubuntu/resolute/+source/nftables)).
- **bpfilter** is being revived as a userspace daemon with a DSL, packaged for Fedora and Ubuntu, with no stable release ([facebook/bpfilter](https://github.com/facebook/bpfilter)).
- **OpenWrt and OPNsense.** OpenWrt 25.12 (March 2026) moved to apk and its fw4 firewall is nftables ([Help Net Security](https://www.helpnetsecurity.com/2026/03/09/openwrt-25-12-0-released/)). OPNsense 26.1 added multi-source Unbound blocklists ([release notes](https://docs.opnsense.org/releases/CE_26.1.html)). Neither runs the Debian tool chain tvgw is built on.
- **VLANs on the home mesh.** The consumer mesh router in use documents no per-SSID VLANs ([Firewalla community](https://help.firewalla.com/hc/en-us/community/posts/52619301261075/comments/52619594199443)). That makes the dedicated cable the right isolation.
- **Casting across isolation.** Casting needs more than a multicast reflector. SSDP replies come back unicast, DIAL endpoints may refuse other subnets, and AirPlay needs a Bonjour reflector plus open return paths ([MikroTik thread](https://forum.mikrotik.com/t/letting-an-lgtv-in-other-vlan-castable/178738), [Lawrence Systems](https://forums.lawrencesystems.com/t/airplay-across-vlans-only-works-with-firewall-wide-open/8896)).
- **The LG pairing port is exploitable.** A TyphoonPWN 2026 chain goes from no authentication to root on webOS 7.5.7 through the pairing service on TCP 3001, fixed per an SSD advisory dated 2026-10-12 ([The Hacker News](https://thehackernews.com/2026/10/lg-smart-tvs-vulnerable-to-pre-auth.html)). In tvgw's design only the Pi can reach the TV's ports, so the isolation already contains this. The Pi itself, which holds the pairing key, becomes the one host whose compromise reaches the TV.
- **IPv6.** 29% of dual-stack requests used IPv6 in 2025 ([Cloudflare Radar 2025](https://blog.cloudflare.com/radar-2025-year-in-review)). Dropping v6 at ingress with no router advertisements means the TV never tries it. No app is known to require it.
- **QUIC.** HTTP/3 carries 21% of requests (same source). No 2025-26 report was found of YouTube, Netflix, Prime Video, Disney+, Peacock, Max or Apple TV refusing to fall back to TCP when UDP 443 is blocked. YouTube's fallback is known to dip quality during the switch ([arXiv 2203.11977](https://ar5iv.labs.arxiv.org/html/2203.11977)). Rejecting rather than dropping, as tvgw does, makes the fallback fast. MASQUE and iCloud Private Relay ride QUIC, so the UDP 443 reject covers them ([Apple](https://developer.apple.com/icloud/prepare-your-network-for-icloud-private-relay/)).
- **DoQ** (RFC 9250) uses UDP 853, which tvgw already rejects.
- **dnsmasq can fill nftables sets from DNS answers** before it replies, via its `nftset=` option (since 2.87, from memory) ([dnsmasq man page](https://thekelleys.org.uk/dnsmasq/docs/dnsmasq-man.html)). AdGuard cannot.

### 3.2 DNS-gated egress (the big idea)

Today, "Unresolved flows" is a report: connections to addresses no lookup explains. Make it a rule instead: **the TV may open a connection only to an address that a lookup by the TV returned within the record's TTL plus slack.** That closes several bypasses at once: hardcoded addresses, DoH to resolvers not on the list, and IP-literal endpoints. `STRICT_PORTS` becomes a special case of it.

**Mechanism.** An nftables set `dns_ok4 { type ipv4_addr; flags timeout; }`, and in `tv_out` the rule `ip daddr != @dns_ok4 counter log group 2 comment "no lookup explains this address"`. Two ways to fill the set:

- **Reply-side.** The Pi's own DNS replies to the TV leave on `eth0`. An output-chain `log group` hands them to a small daemon, which adds the A records to the set. This works with AdGuard unchanged. It races the TV's SYN by milliseconds, which is fine for count-only mode and unproven for enforcement.
- **In-path.** dnsmasq, already installed for DHCP, answers the TV with `nftset=` and forwards to AdGuard on loopback. The address is in the set before the TV sees the answer. AdGuard would then see one client, unless dnsmasq passes the client through in EDNS0 and AdGuard maps it (unverified that this works end to end).

**Exceptions.** The known LG firmware fallback address on 8080 (observed in `tvgw-apply`) and the gateway itself.

**Verdict: PROTOTYPE.**

- Phase 1 is count-only for two weeks. Its acceptance test: the counter equals the brief's Unresolved list, and the clock, firmware, store and streaming hosts are never caught.
- Phase 2 enforces, with REJECT.
- Pi cost: negligible (set lookups).
- Migration: one daemon or a dnsmasq role change, plus three rules.
- Risk: medium to high in enforce mode. A cached answer that outlives our TTL, or a CDN that hands out addresses by other means, breaks playback. That is why there is a two-week count-only phase and a per-host override list.

### 3.3 Verdicts

| Option | Verdict | Why | Pi 5 | Migration | Risk |
|---|---|---|---|---|---|
| nftables as is | **ADOPT NOW (keep)** | Atomic loads, sets, counters; the whole design rests on them | Trivial | None | |
| `nft -c -f` of the rendered ruleset in CI | **ADOPT NOW** | Catches a syntax error before it reaches the Pi (see §11) | n/a | Small | Low |
| bpfilter / eBPF firewall | WATCH | No need at TV packet rates; no stable release | | | |
| OpenWrt, OPNsense or pfSense as the gateway | REJECT (for this Pi) | Loses the Debian tool chain, the VPN client and every unit test's assumptions | | High | High |
| VLAN isolation instead of a cable | REJECT now; WATCH if more IoT devices join | The current mesh has no per-SSID VLANs; the cable is stronger anyway | | | |
| mDNS/SSDP reflector for casting | REJECT by default; PROTOTYPE only on request | Each hole weakens the LAN block (decision 2); a gated profile pinned to one phone is possible | | Medium | Medium |
| IPv6 drop at ingress plus `aaaa_disabled` | **ADOPT NOW (keep, plus the DNS half)** | Cleanest; no app needs v6 | | | |
| QUIC reject | **ADOPT NOW (keep)** | Fallback works; keep the QUIC Initial names as evidence (§1) | | | |
| A per-app QUIC exception set | WATCH | Only if an app is ever seen refusing to fall back | | | |
| **DNS-gated egress** | **PROTOTYPE** (§3.2) | Turns a report into a guarantee | Negligible | Medium | Medium to high |
| `STRICT_PORTS` per decision 17 | Keep the decision | Still a cheap step while §3.2 is proven | | | |

---

## 4. Storage and analytics

### 4.1 Findings

- **The WAL-reset bug supports decision 10.** Through 3.51.2, SQLite can lose data and corrupt a database in **WAL mode** when two connections write or checkpoint at the same instant. Every version from 3.7.0 is affected, the fix is in 3.51.3 (2026-03-13), and there are backports to 3.44.6 and 3.50.7 ([Antithesis](https://antithesis.com/blog/2026/wal-reset-bug/), [summary](https://gigazine.net/gsc_news/en/20260920-sqlite-wal-reset-bug/)). tvgw uses the rollback journal, so it is not exposed. Any proposal to move to WAL, or to adopt Litestream (which needs WAL), now carries this history.
- **Litestream 0.5** (Oct 2025) added point-in-time recovery ([Fly.io](https://fly.io/blog/litestream-v050-is-here/)). It still replicates WAL only.
- **`sqlite3_rsync`** copies a live database over ssh. Since 3.50.0 (2025-05-29) it no longer requires WAL or matching page sizes ([sqlite.org/rsync](https://www.sqlite.org/rsync.html)). Debian 12's SQLite predates it (3.40, from memory).
- **DuckDB.** The 1.4 line is LTS (1.4.3, Dec 2025) ([duckdb.org](https://duckdb.org/2025/12/09/announcing-duckdb-143.html)). It wants 125 MB per thread at minimum ([environment guide](https://duckdb.org/docs/lts/guides/performance/environment.html)). A database file is opened either by one read-write process or by several read-only ones; writing from several processes needs its remote protocol ([concurrency](https://duckdb.org/docs/2.0/connect/concurrency.html)). That breaks tvgw's pattern of hourly root ingest alongside any `adm` user reading at any time. DuckDB reads SQLite files in place and reads hive-partitioned Parquet with partition pruning ([sqlite extension](https://duckdb.org/docs/extensions/sqlite), [hive partitioning](https://duckdb.org/docs/current/data/partitioning/hive_partitioning)).
- **ClickHouse** is what RITA v5 uses ([intro](https://www.activecountermeasures.com/intro-to-rita-v5/)). It wants 4 to 16 GB of RAM ([Altinity](https://kb.altinity.com/altinity-kb-setup-and-maintenance/cluster-production-configuration-guide/hardware-requirements/)).
- **SD card flash.** A 2026 guide warns that a card's brand or endurance rating does not prove that it flushes correctly ([OneUptime](https://oneuptime.com/blog/post/2026-09-08-sqlite-power-loss-sd-cards-flash-storage/view)). Raspberry Pi's own A2 cards publish IOPS but no endurance rating ([Mouser](https://www.mouser.com/new/raspberry-pi/raspberry-pi-a2-class-micro-sd-cards/)).

### 4.2 Design for a year on a card

Keep data-architecture §2 (facts, rollups by watermark, `fw_day`, `host_day`) and answer its retention question (§4 Q1) this way:

- **90 days of facts, rollups kept forever.** At the observed rates the facts cost about 1 GB a year; 90 days is about 250 MB. `host_day` and `fw_day` cost kilobytes a day.
- **A daily `VACUUM INTO` copy, then `PRAGMA quick_check` on the copy.** Keep 7 copies on the same card; they protect against corruption, not against the card failing.
- **An off-box copy.** Encrypt it (the store is a viewing history; [privacy-and-retention.md](../privacy-and-retention.md)) with `age` or restic, and have a workstation pull it. Push nothing; no alerts.
- **Optionally, freeze each finished UTC day as Parquet** (`/var/lib/tvgw/archive/day=YYYY-MM-DD/*.parquet`). These files are immutable and read-only by nature, any DuckDB on the workstation can query a year of them, and they make the LLM evidence pack (§5) a file rather than a query.

### 4.3 Verdicts

| Option | Verdict | Why | Pi 5 | Migration | Risk |
|---|---|---|---|---|---|
| SQLite, rollback journal, `synchronous=FULL` | **ADOPT NOW (keep)** | Right concurrency model; the WAL-reset bug skips it | A few fsyncs an hour | None | |
| 90 d facts plus rollups forever | **ADOPT NOW** (owner's call) | Privacy intent and card budget | Smaller file, faster prune | Stage 1 of data-architecture | Low |
| Daily `VACUUM INTO` plus `quick_check`, encrypted off-box pull | **ADOPT NOW** | No backup exists today (data-architecture #9) | One read of the file a day | One unit | Low |
| `sqlite3_rsync` for the off-box copy | WATCH | Needs SQLite ≥ 3.50 on both ends; trixie ships 3.46 (unverified) | | | |
| Litestream | REJECT | WAL only, which conflicts with decision 10 | | | |
| DuckDB as the store | REJECT | One writer **or** many readers | | High | High |
| DuckDB reading daily Parquet (and the SQLite file read-only) for heavy analysis | PROTOTYPE | Columnar scans of a year in seconds; queries off the Pi | 125 MB per thread; run off the Pi or at night | Additive | Low |
| ClickHouse-local, TimescaleDB | REJECT | Server-class RAM, or a database server, for one TV | | | |
| VictoriaMetrics / Prometheus for the counters | REJECT | `fw_day` covers it; a time-series database is a daemon and a dashboard, and the brief is the interface | | | |

---

## 5. Analysis algorithms

### 5.1 Beaconing and periodicity

- **RITA v5** imports Zeek logs into ClickHouse and scores beacons from two halves, averaged: inter-arrival timing (Bowley skew, median absolute deviation (MAD), connection count against the interval range) and data size (skew, dispersion, smallness) ([RITA v5](https://www.activecountermeasures.com/intro-to-rita-v5/), [scoring described in a patent](https://image-ppubs.uspto.gov/dirsearch-public/print/downloadPdf/12401665); RITA's exact weights unverified).
- **BAYWATCH** (IBM, DSN 2016) filters 30 billion proxy events through eight stages, using popularity and allowlisting to drop legitimate periodic traffic ([record](https://pure.psu.edu/en/publications/baywatch-robust-beaconing-detection-to-identify-infected-hosts-in/)).
- **Lomb-Scargle** finds periods in irregular, gappy timestamps without resampling ([astropy docs](https://astro-docs.readthedocs.io/en/latest/stats/lombscargle.html)). The TV's off hours are exactly such gaps.
- **Practitioner heuristics** treat a coefficient of variation below about 0.2 as periodic, and 20% as the jitter tolerance ([Fortinet rule](https://detections.ai/detections/777f7314-0e51-4088-9ebf-4e9335e1c0bf)).

**For tvgw:**

- **ADOPT NOW: the robust scorer data-architecture §2.7 already specifies** (median and MAD of intervals, n ≥ 12), extended RITA-style with a data-size half: the median and MAD of `bytes_up` per connection, plus a smallness term. Score per name, not per address, so CDNs do not hide a beacon. Add the DNS-side variant: lookups per name against `ttl_min`.
- **PROTOTYPE: Lomb-Scargle as a confirming step** for names the robust scorer flags, so that two periods (say 45 s and 15 min) and gaps are handled. A pure-Python periodogram over at most 10,000 timestamps and a few hundred trial periods is cheap. scipy's aarch64 wheels also work, but they are a heavy dependency for one function.
- **ADOPT NOW: an ACR cadence canary.** IMC 2024 measured LG's ACR uploading roughly every 15 s, including on HDMI input ([Anselmi et al., IMC 2024](https://arxiv.org/html/2409.06203v1)). A new name that shows small, periodic uploads at a 10-20 s period while the TV is Active is a red-line candidate, even under a name no list knows.

### 5.2 Smart TV and IoT research to calibrate against

- **"Watching the Watchers"** (Mammadov, Joshi, Dubois, Choffnes; PoPETs 2027) studied 12 TVs from 10 brands ([paper](https://watchingthewatchers.github.io/watchingthewatchers/paper.html)). Per the authors' repo and press, as relayed by our sub-researcher:
  - The ACR opt-out stopped ACR traffic on LG webOS, Fire TV, Sony and VIDAA.
  - It did not fully stop it on Samsung, Vizio or the Roku Channel.
  - Samsung kept ACR-consistent traffic after opt-out in 30 of 30 built-in streaming runs ([allaboutcookies summary](https://allaboutcookies.org/smart-tv-tracking-privacy-opt-out)).
  - Our own fetch of the paper page confirmed the title, authors and venue only.
  - This fits the CX observation that the provisioning host is still called with Live Plus off, which tvgw blocks (observed).
- **IMC 2024** (Anselmi et al.): ACR runs even as a "dumb display" on HDMI, with LG UK sending about 4.3 MB an hour, and opting out stopped it ([arXiv 2409.06203](https://arxiv.org/html/2409.06203v1)).
- **Older baselines:**
  - Roku and Fire TV channel tracking ([Moghaddam et al., CCS 2019](https://mlab.engineering.nyu.edu/static/ccs-19.pdf); [Varmarken et al., PoPETs 2020](https://petsymposium.org/popets/2020/popets-2020-0021.php)).
  - Regional differences across 81 devices ([Ren et al., IMC 2019](https://moniotrlab.khoury.northeastern.edu/publications/imc19/)).
  - HbbTV tracking before consent on more than 70% of channels ([NDSS 2023](https://www.ndss-symposium.org/wp-content/uploads/2023/02/ndss2023_f102_paper.pdf)). This matters only for EU broadcast.
- **IoT Inspector** gathered labelled traffic from 44,956 devices and found about 350 tracker domains on smart TVs ([USENIX node](https://www.usenix.org/node/282907)). Version 3 for Linux and Raspberry Pi is announced but still waitlisted ([inspector.engineering.nyu.edu](https://inspector.engineering.nyu.edu/)).
- **MUD (RFC 8520)** is barely deployed. RFC 9726 (2025) says operators are only "beginning to deploy" it ([datatracker](https://datatracker.ietf.org/doc/rfc9726/history/)). tvgw's profile is a richer MUD file. Exporting a MUD-like ACL is a WATCH, not an input format.

### 5.3 Per-app attribution and "what left the house"

**Attribution.** Combine three signals:

1. The foreground app, from an SSAP subscription (data-architecture §4 Q9). This is the strongest signal; the CX already reports it hourly.
2. The JA4 stack: the webOS web engine shares one fingerprint; native players have their own (unverified for the CX).
3. The server name.

Without the subscription, attribution is a guess, and the brief should say so.

**Measuring what left the house, honestly.** Conntrack's `bytes_up` counts IP and TCP headers and every ACK. A 40 GB streaming day shows about 550 MB "up" at about 54 bytes a packet, all of it acknowledgements (observed). Three changes:

- **Report a range, not one number.** The upper bound is `bytes_up`. The payload estimate is `bytes_up - pkts_up × (IP + TCP header)`. The floor is the TLS records the server's window could have carried. Label the floor "estimate".
- **Count blocked attempts separately from delivered bytes.** A blocked lookup or a rejected connection sent nothing beyond the name.
- **Name the channels that carry data in names.** DNS labels themselves (the "DNS as data" check) and plain-HTTP query strings, which the URL filter sees.

**Verdict: ADOPT NOW** in the brief's Top upload section. The cost is one SQL expression and an honest heading.

### 5.4 An LLM analyst over a daily evidence pack

**Prices** (Anthropic's model table as of October 2026: [pricing](https://platform.claude.com/docs/en/about-claude/pricing.md)):

| Model | Input | Output | Cache reads |
|---|---|---|---|
| Claude Opus 5.5 | $4 / MTok | $20 / MTok | $0.20 / MTok |
| Claude Sonnet 5.5 | $2 / MTok | $10 / MTok | |
| Claude Haiku 5.5 | $0.10 / MTok | $0.50 / MTok | |

Other pricing facts:

- The Batch API halves the price ([batch processing](https://platform.claude.com/docs/en/build-with-claude/batch-processing.md)).
- Cache writes cost 1.25× for the 5-minute TTL and 2× for the 1-hour TTL, so a once-a-day call gets nothing from caching. Caching pays only when one run makes several calls over the same prefix, for example a tool loop that asks `tvgw host NAME` about a few names ([prompt caching](https://platform.claude.com/docs/en/build-with-claude/prompt-caching.md)).
- Structured outputs (`output_config.format` with a JSON schema) constrain the reply to a schema ([structured outputs](https://platform.claude.com/docs/en/build-with-claude/structured-outputs.md)).
- API inputs and outputs are deleted within 30 days by default; zero data retention is available by agreement ([privacy center](https://privacy.claude.com/en/articles/7996866-how-long-do-you-store-personal-data), [API retention](https://platform.claude.com/docs/en/manage-claude/api-and-data-retention)).

**Cost.** A pack of about 40k input tokens and 3k output tokens costs about $0.22 a day on Opus 5.5 ($80 a year), about $40 a year through the Batch API, and roughly half that again on Sonnet 5.5. Haiku is cheap, but this is a judgment task.

**What to send** (generated by `tvgw report --json` plus derived findings):

- New names, with category, counts and first-seen time.
- Retried blocked names, with rule and filter.
- Allowed names outside the expected categories.
- Top upload, as the range from §5.3.
- Beacon findings with periods.
- The firmware diff.
- Coverage and the red lines.
- The profile's categories, must-allow hosts and the dated rule reasons. This is the stable prefix.

**What never to send:**

- The ZIP code, the TV's device name, MACs, the home's public address, and LAN-probe destinations (an inventory of the household's devices).
- Minute-level viewing timelines: aggregate to hourly at most.
- Raw URIs with query strings, unless one is needed as evidence and has been redacted.

**Prompt injection is the central risk.** Every name, URI and user agent in the pack was chosen by the TV or by a server. 2026 work shows log fields carrying instructions that hijack an LLM analyst ([arXiv 2605.24421](https://www.emergentmind.com/papers/2605.24421); a July 2026 paper, arXiv 2607.14493, reports combined defenses cutting attacks by about 90%, as relayed by a search summary; the paper was not read). Defenses:

- Send fields as JSON data under a system prompt that says the data is untrusted.
- Constrain the output to a schema: `{action: add_block|add_allow|recategorize|investigate|none, target, evidence_ids[], confidence, breakage_risk, rationale}`.
- Run every proposal through the profile lint, so it can never touch a must-allow host.
- Show the proposals in the brief under "Analyst proposals (unreviewed)". Never apply them.

**Never automate:**

- Applying or removing rules.
- Anything touching must-allow hosts, the firewall or the TV's settings.
- Deleting evidence.
- Red-line decisions.
- Any notification. The owner has ruled out alerts; the brief file is the interface.

**Verdict: PROTOTYPE** with Opus 5.5 at medium effort through the Batch API, written to `reports/llm/<day>.json`.

- Pi cost: one HTTPS call a day.
- Migration: a new command and a brief section.
- Risk: medium (prompt injection, data sharing), held down by the constraints above.

---

## 6. TV control and knowledge

### 6.1 LAN APIs by vendor (2025-26)

| Vendor | API | Power and foreground app | ACR setting readable? | Notes |
|---|---|---|---|---|
| LG webOS | SSAP WebSocket, `ws://:3000` and `wss://:3001` (self-signed), on-screen pairing ([HA webostv](https://www.home-assistant.io/integrations/webostv/)) | Yes | **Yes on the CX** (`option.livePlus`, observed in `lgwebos.py`); writes refused on firmware 04.64 (observed) | 3001 had a pre-auth root chain in 2026 (fixed) |
| Samsung Tizen | WebSocket `:8001` and `:8002`, token after on-screen approval ([samsungtvws](https://pypi.org/project/samsungtvws)) | Power yes; app partly | No read path for Viewing Information Services found (unverified) | Opt-out unreliable (PoPETs 2027): **DNS-only profile** |
| Roku | ECP, HTTP `:8060` ([ECP docs](https://developer.roku.com/docs/developer-program/dev-tools/external-control-api.md)) | `query/device-info` gives `power-mode`; `query/active-app` | No ECP field found (unverified) | From Roku OS 14.1, "Control by mobile apps" gates many endpoints ([Roku support](https://support.roku.com/article/360000281788)) |
| Vizio SmartCast | HTTPS `:7345` (older `:9000`), PIN pairing ([HA vizio](https://www.home-assistant.io/integrations/vizio/)) | Yes | Unverified | No measurable drop after opt-out (one model, PoPETs 2027) |
| Amazon Fire TV (Fire OS) | ADB `:5555` after approval ([HA androidtv](https://www.home-assistant.io/integrations/androidtv/)) | Yes (dumpsys) | `settings get` plausible (unverified) | **Vega OS** devices drop network ADB and sideloading ([Amazon](https://developer.amazon.com/docs/vega/0.24/developer-mode)) |
| Android TV / Google TV (Sony, TCL, Streamer) | Android TV Remote v2, TLS pairing `:6467`, control `:6466` ([androidtvremote2](https://github.com/tronikos/androidtvremote2)) | Yes (`current_activity`) | Via ADB only (unverified) | Sony's ACR is "Samba Interactive TV" |
| Hisense VIDAA | MQTT `:36669`, with community-extracted certificates ([ha_hisense_tv](https://github.com/sehaas/ha_hisense_tv)) | Partly | No | Unofficial; ACR traffic unencrypted per PoPETs 2027 coverage |

### 6.2 Rooting

- **Status by method** (webosbrew, [rooting page](https://www.webosbrew.org/rooting/)):
  - RootMyTV: patched in 2022.
  - crashd: patched April 2024.
  - DejaVuln: webOS 9 release builds patched ([dejavuln-autoroot](https://github.com/throwaway96/dejavuln-autoroot)).
  - faultmanager-autoroot: as of 2025-08 the latest firmware for essentially all webOS 5, 6, 7 and 9 models is patched; only factory webOS 10.0 remains open ([faultmanager-autoroot](https://github.com/throwaway96/faultmanager-autoroot)).
  - Chronomaly, a kernel use-after-free (CVE-2025-38352), roots some 2022-24 firmware ([chronomaly-webos](https://github.com/AnalyticETH/chronomaly-webos)).
- **The CX on 04.64 is probably patched** (unverified; check [cani.rootmy.tv](https://cani.rootmy.tv)).
- **What root would give a gateway:** stopping telemetry and ACR services at the source, a Luna bus without the `isCallAllowed` gate (so settings could be enforced, not just read), logs, and a CA for decrypting the TV's own traffic. It does not reliably survive firmware updates. Decision 4 stands: **WATCH**.

### 6.3 Regulation

- **Texas v. five TV makers.** Texas sued Samsung, LG, Sony, Hisense and TCL over ACR on 2025-12-15.
  - Samsung settled on 2026-02-26.
  - LG announced a settlement on 2026-05-12: consent before ACR, a pop-up disclosure, an easy opt-out, and no viewing data to the CCP. Court approval is unverified.
  - Hisense has been under a temporary restraining order since 2025-12-17.
  - Sony and TCL are still in litigation.
  - Sources: [Fox 7](https://www.fox7austin.com/news/lg-smart-tv-acr-data-collection-texas-settlement), [Secure Privacy](https://secureprivacy.ai/blog/samsung-lg-texas-acr-settlements-smart-tv-consent-ctv-publishers).
- **Kentucky HB 692** requires consent for ACR from 2027-07-01; the governor's signature is unverified ([Sourcepoint](https://sourcepoint.com/blog/kentucky-smart-tv-consent-law-ftc-childrens-privacy/)).
- **The US Supreme Court** took *Salazar v. Paramount* on the Video Privacy Protection Act's definition of "consumer" ([MoFo](https://www.mofo.com/resources/insights/260128-supreme-court-takes-up-key-vppa-consumer-question)).
- **The FCC Cyber Trust Mark** was paused in 2025. ioXt was picked as lead administrator on 2026-04-13 ([Broadband Breakfast](https://broadbandbreakfast.com/fcc-picks-ioxt-alliance-to-head-cyber-trust-mark-program/)). It covers security, not privacy.
- **The EU Cyber Resilience Act's** vulnerability reporting duties began 2026-09-11; full obligations apply from 2027-12-11 ([NCSC Ireland](https://ncsc.gov.ie/cra/)).

**What this means for tvgw.** A firmware update may bring LG's consent pop-up and may reset Live Plus. tvgw already makes Live Plus a red line. Add a re-read of the TV's settings within the hour after any firmware change. The brief's Firmware section already marks that change.

### 6.4 A profile registry for many vendors

A registry needs these record types (schema sketch):

- **`[platform]`**: vendor, OS, OS version range, model pattern, firmware range tested, region.
- **`[[lan_api]]`**: port, transport, TLS (and whether it is self-signed), how to pair, discovery (SSDP search target or mDNS type), readable fields (`power`, `foreground_app`, `acr_setting` key path or null), `write = refused|ok|root`, and the setting that gates access.
- **`[[privacy_setting]]`**: the localized name (Live Plus, Viewing Information Services, Viewing Data, Samba Interactive TV, Smart TV Experience), menu path, API key, default, `resets_on_update`, and `opt_out_effective` with a citation.
- **`[[endpoint]]`**: pattern, purpose, region, breakage note, first seen, last verified, firmware seen.
- **`[[source]]`**: URL, licence, date. This is the field that keeps CC BY-NC-ND and GPL text out.
- **Attack surface** (for example, port 3001 in 2026) and **legal context**.

Two grade changes: add a **`peer-reviewed`** evidence grade between `observed` and `community`, and make CI fail any entry without a source.

**Verdict: PROTOTYPE.** Start with DNS-only `samsung-tizen`, `roku` and `vizio` profiles graded from HaGeZi's native lists and PoPETs 2027, plus `[[lan_api]]` records taken from Home Assistant's integration docs. Home Assistant is the most current readable source of LAN API facts.

---

## 7. Hardware

| Option | Verdict | Facts | Feasibility, migration, risk |
|---|---|---|---|
| Pi 5 (2-4 GB), onboard Ethernet for the TV, Wi-Fi uplink | **ADOPT NOW (keep)** | Idle about 3.0-3.6 W ([raspberry.tips](https://raspberry.tips/en/raspberrypi-tutorials/raspberry-pi-power-consumption-update-2026-all-models-compared)). Memory prices pushed the 16 GB board to $305 in 2026 ([Raspberry Pi](https://www.raspberrypi.com/news/more-memory-driven-price-rises/)); tvgw needs at most 2 GB. | None |
| **NVMe (M.2 HAT) or CM5 eMMC instead of the SD card** | **ADOPT NOW** for new builds; PROTOTYPE a migration of this Pi | SD cards publish no endurance rating; the attached USB disk is already failing (observed) | NVMe boot is standard on the Pi 5. The HAT shares the single PCIe lane with any NIC HAT. Migration: an image copy. Low risk. |
| **RTC battery** (`dtparam=rtc_bbat_vchg` only for rechargeable cells) | **ADOPT NOW** | A correct clock before NTP protects prune cutoffs, TLS and timers ([note](https://gigazine.net/gsc_news/en/20231109-raspberry-pi-5-rtc)) | A few dollars; no code |
| **Hardware watchdog** (`RuntimeWatchdogSec=10s`; bcm2835 maximum about 15 s, from the driver) | **ADOPT NOW** | A hung kernel recovers unattended, which suits "no alerts" | One drop-in. Low risk: a watchdog reset leaves the TV dark (fail closed) for a minute. |
| Read-only root (overlayroot) | PROTOTYPE | In Debian ([overlayroot](https://packages.debian.org/overlayroot)); bookworm quirks reported ([#137](https://github.com/raspberrypi/bookworm-feedback/issues/137)) | Needs the store and AdGuard's data on a persistent mount. Medium cost. |
| Wired uplink with a second NIC: USB 3 RTL8153 or AX88179 | PROTOTYPE | Mixed driver reports; disable USB autosuspend ([LibreELEC](https://forum.libreelec.tv/thread/28119-usb3-to-gigabit-ethernet-adapter-on-rpi4-5-troubles/?postID=188299)) | Wi-Fi carries 60-70 GB a day today. A cable to the router is the biggest reliability gain if one can be run. |
| PCIe dual 2.5G HAT (Waveshare 2×RTL8125, Radxa) | PROTOTYPE | [Waveshare](https://www.waveshare.com/product/raspberry-pi/hats/pcie-to-2-ch-2.5g-eth-hat-plus.htm), [Radxa](https://docs.radxa.com/en/accessories/network/dual-2.5-router-hat) | Shares the PCIe lane with NVMe (Radxa has both) |
| CM5 dual-Ethernet box (Waveshare CM5-DUAL-ETH-MINI-BOX, about $49 without the module) | PROTOTYPE, as the "appliance" build | eMMC, metal case, two NICs ([CNX](https://www.cnx-software.com/2025/04/19/cm5-dual-eth-mini-box-is-a-dual-gigabit-ethernet-router-box-for-the-raspberry-pi-cm5/)) | Same OS; interface names differ, which is why §8 matters |
| x86 N100/N150 with 4×i226 | PROTOTYPE, as the second CI target | $180-250; about 6-7 W idle measured on a close relative ([STH](https://www.servethehome.com/new-fanless-4x-2-5gbe-intel-n5105-i226-v-firewall-tested/3/)) | Proves portability; double the Pi's power |
| GL.iNet Flint 3, NanoPi R76S, BPI-R4 | WATCH / WATCH / REJECT | Vendor OpenWrt forks; Python is a poor fit there | A "tvgw-lite" would be an nft and uci port, not this codebase |

---

## 8. Packaging and distro compatibility

### 8.1 Facts that drive the design

- **Debian 13 "trixie"** was released 2025-08-09 with Python 3.13, systemd 257 and nftables 1.1.3 ([Debian](https://www.debian.org/News/2025/20250809)). Its release notes change four things that matter here ([issues](https://www.debian.org/releases/trixie/release-notes/issues.en.html)):
  - `/tmp` is a tmpfs.
  - `systemd-sysctl` no longer reads `/etc/sysctl.conf`.
  - Interface names can change on upgrade.
  - apt 3 brings deb822 `.sources` files.
  - Third-party repositories are expected to use a keyring with `Signed-By:` ([Debian wiki](https://wiki.debian.org/DebianRepository/UseThirdParty)).
- **Raspberry Pi OS** moved to trixie on 2025-10-02 and recommends a fresh flash. Bookworm gets only critical kernel fixes for about two more years ([Raspberry Pi](https://www.raspberrypi.com/news/trixie-the-new-version-of-raspberry-pi-os/)).
  - From the 2025-11-24 image, cloud-init is included and **"Netplan is now the primary source of truth for networking"**, with NetworkManager as the renderer ([Raspberry Pi](https://www.raspberrypi.com/news/cloud-init-on-raspberry-pi-os/)).
  - Whether a connection made with `nmcli con add`, as `install.sh` creates `tv-lan`, persists as a keyfile or as netplan YAML on those images is unverified. Test it on a fresh image before claiming support.
- **AdGuard Home** has no official .deb or .rpm, only the install script, Docker and Snap ([KB](https://adguard-dns.io/kb/adguard-home/getting-started/)).
- **Prior art:**
  - Tailscale, CrowdSec and Netdata ship signed apt and yum repositories.
  - Zeek builds packages on openSUSE's build service ([Zeek docs](https://docs.zeek.org/en/lts/install.html)).
  - Pi-hole still uses `curl | bash` ([docs](https://docs.pi-hole.net/main/basic-install/)).
  - Home Assistant **deprecated** its generic-Linux installs in 2025 because testing many distros cost too much ([HA blog](https://home-assistant.io/blog/2025/05/22/deprecating-core-and-supervised-installation-methods-and-32-bit-systems/)). Lesson: publish a narrow, tested support matrix.
- **firewalld coexistence.** firewalld owns its nftables table. **An accept in one base chain is not final, while a drop in any base chain at the same hook is** ([nftables wiki](https://wiki.nftables.org/wiki-nftables/index.php/Configuring_chains)). So on a firewalld host, tvgw must also emit a firewalld zone and policy for the TV interface, or its forward rules mean nothing. ufw has the same problem.

### 8.2 Packaging verdicts

| Option | Verdict | Why | Migration | Risk |
|---|---|---|---|---|
| A **wheel** as the core artifact | **ADOPT NOW** | Every route below needs it | Small | Low |
| **nfpm** building .deb, .rpm and Arch packages from one YAML, with a **hash-pinned wheelhouse** (`uv pip compile --generate-hashes`) inside | **ADOPT NOW** | `postinst` builds `/usr/lib/tvgw/venv` with the **distro's** python3, `pip install --no-index --require-hashes`. Units go in `/usr/lib/systemd/system`, `/etc/tvgw/tvgw.conf` is a `config\|noreplace` conffile, state lives in `StateDirectory=tvgw`, sysctls go in `/etc/sysctl.d/60-tvgw.conf`. Architecture-independent, since every dependency is pure Python ([nfpm](https://nfpm.goreleaser.com/docs/configuration/)). | Medium: `install.sh` becomes `postinst` plus `tvgw setup` | Low |
| A **signed apt repository** (reprepro or aptly on static hosting), deb822 `.sources` with `Signed-By: /usr/share/keyrings/tvgw-archive-keyring.pgp`; COPR or a dnf repo for Fedora | **ADOPT NOW** with the .deb | Lets `apt upgrade` update tvgw | Small | Key custody |
| dh-python and pybuild (a "proper Debian" package) | PROTOTYPE later | bscpylgtv is not in Debian; bookworm's zeroconf has open 2026 CVEs ([tracker](https://tracker.debian.org/pkg/python-zeroconf)) | Medium | |
| dh-virtualenv, fpm, pipx, `uv tool install`, Snap, Flatpak | REJECT | Debian-only or per-user; snaps need privileged interfaces; uv-managed Python would bypass distro security updates for a root service | | |
| uv as a **build** tool | **ADOPT NOW** | Locking and hashes. OpenAI announced it is acquiring Astral (2026-03-19; [Willison](https://simonwillison.net/2026/mar/19/openai-acquiring-astral/)): WATCH the governance | | |
| Nix flake / NixOS module | WATCH | The Pi 5 is community-supported only ([NixOS wiki](https://wiki.nixos.org/wiki/NixOS_on_ARM/Raspberry_Pi_5)) | | |
| **A container for the firewall core** (Podman with host network and `NET_ADMIN`) | **REJECT** | Host networking plus `CAP_NET_ADMIN` is the host's firewall, so the container is not a security boundary ([discussion](https://zff.dev/bjorne/podman-seal)). It still needs host sysctls, the dispatcher, dnsmasq and fail-closed boot ordering, and it hides the firewall from `nft list ruleset` users. | High | High |
| AdGuard in its official container | WATCH | Plausible on distros where its script is unwelcome | | |
| **AdGuard as a checked external dependency**: the installer runs AdGuard's script, or detects a Snap or Docker install, then checks the version floor (§2) | **ADOPT NOW** | Do not vendor a security-critical daemon we cannot patch faster than upstream | Small | Low |

### 8.3 Compatibility matrix

| Distro | Init | Firewall front-end | Network config | DHCP for the TV | :53 conflict | Python | nftables |
|---|---|---|---|---|---|---|---|
| Raspberry Pi OS bookworm (today) | systemd 252 | none | NetworkManager | dnsmasq | none | 3.11 | 1.0.6 |
| **Raspberry Pi OS trixie** | systemd 257 | none | **netplan → NetworkManager** (Nov 2025+ images) | dnsmasq | none (unverified) | 3.13 | 1.1.3 |
| Debian 13 | systemd 257 | none | ifupdown or NM | dnsmasq | none | 3.13 | 1.1.3 |
| Ubuntu 24.04 / 26.04 | systemd 255 / 259 | ufw (inactive by default) | netplan (networkd or NM) | dnsmasq or networkd | **resolved stub** on 127.0.0.53 | 3.12 / 3.14 | 1.0.9 / 1.1.6 |
| Fedora 43/44 | systemd | **firewalld (owned table)** | NetworkManager | dnsmasq | resolved stub | 3.14 | 1.1.3 / 1.1.6 |
| Arch | systemd | none | varies | dnsmasq or networkd | none | 3.14 | 1.1.x |
| Alpine 3.24 | **OpenRC** | none | ifupdown-ng | dnsmasq | none | 3.14 | ≥ 1.1.3 |
| DietPi | systemd | none | ifupdown (unverified) | dnsmasq | none | per base | per base |

Versions marked in the sub-research as from memory: bookworm and Ubuntu 24.04 rows. Sources: [Ubuntu 26.04 python](https://launchpad.net/ubuntu/resolute/+source/python3-defaults), [Fedora nftables](https://packages.fedoraproject.org/pkgs/nftables/python3-nftables/fedora-44.html), [Arch python](https://archlinux.org/packages/core/x86_64/python/), [Alpine python](https://pkgs.alpinelinux.org/packages?name=python3&branch=v3.24&arch=aarch64).

**Support policy.**

- **Tier 1, tested on hardware:** Raspberry Pi OS trixie and Debian 13.
- **Tier 2, tested in CI in a network namespace (§11):** Ubuntu 24.04 and 26.04.
- **Tier 3, packages only:** Fedora and Arch.
- **Unsupported:** Alpine (OpenRC) until someone asks.

### 8.4 What must be abstracted

1. **The TV interface, subnet and gateway address.** `eth0` and the subnet are hardcoded across `tvgw-apply`, `tvgw.service`, `tvgw-pcap.service`, `tvgw-flowlog.service`, the dnsmasq template, both nginx files, the NetworkManager files, `config.py`, `conntrack.py` and `queries.py` (observed; deploy/README "Gotchas"). Template every one of them from `TV_IF`, `TV_NET` and `GW_IP` **before** offering a `systemd.link` rename to a stable name such as `tvlan0`.
2. **The network backend.** A `NetBackend` with four implementations: NetworkManager keyfile, netplan YAML, networkd `.network`, ifupdown. Detect the backend at setup; the dispatcher hook differs per backend.
3. **The firewall front-end.** Detect firewalld or ufw and emit a zone and policy, or refuse with a clear message.
4. **DHCP.** dnsmasq (`port=0`) is the default everywhere. networkd's `DHCPServer=` with static leases is an alternative, but it has no lease-script hook, which discovery uses.
5. **The resolver.** Bind AdGuard to the TV-side address and loopback, never `0.0.0.0`, so systemd-resolved's stub can stay.
6. **VPN clients.** `tvgw-apply` hardcodes one VPN client's routing mark (`undo PIA routed-packet tag`). Generalize it: detect fwmark-based policy routing (wg-quick, Tailscale, PIA) and clear the mark on TV packets. The exact marks and tables per client are unverified, so add a hardware test per client.

---

## 9. Installer UX

**Status (observed).** `tvgw discover`, committed 2026-10-27, already does most of what the owner asked for.

- It brings up the TV side with a pool, reads dnsmasq's lease and its DHCP log (webOS announces `LGwebOSTV`), and reads the neighbour table.
- It probes vendor API ports: webOS 3000/3001, Tizen 8001/8002, Roku 8060, SmartCast 7345/9000, Cast 8008/8009.
- It runs an SSDP search behind a temporary output-chain exemption and reads `description.xml` when the TV answers. **This CX does not answer SSDP with its sharing features off** (observed in the commit message).
- It writes `TV_MAC`, `TV_IP`, `TV_NAME` and `PROFILE`. The next commit reads the retail model over the LAN API.

That ordering is better than the SSDP-first approach the owner described, and better than discovering on the Wi-Fi side. On Wi-Fi the neighbour table shows the TV's **Wi-Fi** MAC, which differs from the wired one ([LG](https://www.lg.com/us/support/help-library/how-to-find-the-mac-address-on-your-lg-tv-CT10000018-20155444682287)). On the CX the Wi-Fi module even carries a third-party module maker's vendor prefix (observed), so a MAC vendor lookup would have said "not LG".

**Improvements:**

| Item | Verdict | Detail |
|---|---|---|
| **Pin the SSDP `LOCATION` fetch** | **ADOPT NOW** (security) | `fetch_description` passes the reply's `LOCATION` header to `urllib.request.urlopen` as root, unchecked. urllib accepts `file://` and follows redirects, so a device on the TV segment can make the installer read local files or hit the Pi's loopback services (AdGuard's UI on :3000). Accept only `http://` to the responder's own address, refuse redirects, cap the size (it already reads at most 64 KiB). |
| DHCP fingerprint (options 55, 60, 12) from dnsmasq `log-dhcp` | PROTOTYPE | A second identity signal that needs no open port; also feeds data-architecture's `device` dimension |
| mDNS browse (`_airplay._tcp`, `_googlecast._tcp`, `_androidtvremote2._tcp`, `_viziocast._tcp`) | PROTOTYPE | Service types per Home Assistant's manifests ([androidtv_remote](https://raw.githubusercontent.com/home-assistant/core/dev/homeassistant/components/androidtv_remote/manifest.json), [vizio](https://raw.githubusercontent.com/home-assistant/core/dev/homeassistant/components/vizio/manifest.json)). Use stdlib sockets or python-zeroconf ≥ 0.149.16 (2026 CVEs). Many TVs turn this off with sharing, so it is a bonus signal. |
| OUI vendor lookup | PROTOTYPE, low weight | Wireshark's `manuf` data is GPL-2 ([manuf](https://pypi.org/project/manuf)); module vendors mislead (above) |
| Model → generation → profile, through `tvgw profile --model` and the registry (§6.4) | **ADOPT NOW** | Already half there with getSystemInfo |
| A `tvgw setup` wrapper: discover → pick from a numbered list → pair the LAN API → write the config → apply → verify; `--non-interactive --answers FILE` | **ADOPT NOW** | Plain prompts work over SSH and on every distro |
| whiptail front-end | WATCH | Ships on Raspberry Pi OS; cosmetic |
| Textual TUI | REJECT | A heavy dependency for six prompts |
| debconf | REJECT as the UI | Debian-only; prompts in maintainer scripts break unattended installs. At most one "run setup now?" question. |
| cloud-init answers (`user-data` with `runcmd: tvgw setup --non-interactive --answers /boot/firmware/tvgw.yaml`) | PROTOTYPE | Native on Raspberry Pi OS from Nov 2025; `runcmd` is standard cloud-init but not shown in Raspberry Pi's post |
| **Ready-made image** with rpi-image-gen, published as a Raspberry Pi Imager custom repository | PROTOTYPE after packaging | rpi-image-gen emits an SBOM and CVE list ([Raspberry Pi](https://www.raspberrypi.com/news/introducing-rpi-image-gen-build-highly-customised-raspberry-pi-software-images/)); custom repository JSON ([Raspberry Pi](https://www.raspberrypi.com/news/how-to-add-your-own-images-to-imager/)) |
| DietPi automation | WATCH | `AUTO_SETUP_CUSTOM_SCRIPT_EXEC` ([DietPi](https://dietpi.com/docs/usage/)) |

---

## 10. Security and sandboxing

- **Dissectors are the largest attack surface.** Wireshark published at least 61 advisories in 2026 by July: infinite loops in the HTTP3, SMB2 and OpenFlow dissectors and others ([wnpa-sec-2026-61](https://wireshark.org/security/wnpa-sec-2026-61.html), [-40](https://www.wireshark.org/security/wnpa-sec-2026-40.html), [-11](https://www.wireshark.org/security/wnpa-sec-2026-11.html)). tvgw already runs tshark as `nobody` with no groups, and refuses to run it as root.
  - **ADOPT NOW:** run the extractor (tshark today, our parser later) under `systemd-run --wait --pipe` with `PrivateNetwork=yes`, `ProtectSystem=strict`, `ReadOnlyPaths=` on the one pcap, `NoNewPrivileges=yes`, `SystemCallFilter=@system-service`, `RestrictAddressFamilies=AF_UNIX`, `MemoryMax=512M` and `RuntimeMaxSec=`. This turns a dissector loop into a bounded failure rather than a stuck ingest.
  - **PROTOTYPE:** add a Landlock self-restriction to the pure-Python parser. Linux 6.12 supports filesystem and TCP rules, and Landlock needs no privilege ([kernel docs](https://docs.kernel.org/6.12/userspace-api/landlock.html)).
  - The bigger win is **parsing less**: a ClientHello, HTTP request-line and QUIC Initial parser is a few hundred lines of Python, against Wireshark's thousands of dissectors.
- **Capture privilege.** dumpcap with file capabilities (§1) removes the last root-held parser of TV packets.
- **Supply chain:**
  - **ADOPT NOW:** a hash-pinned wheelhouse; GitHub Actions pinned by commit SHA instead of `@v4`; a signed apt repository; signed tags.
  - If tvgw goes to PyPI, use Trusted Publishing with PEP 740 attestations. These are on by default in the PyPA publish action, with more than 20,000 attestations uploaded ([Sigstore](https://blog.sigstore.dev/pypi-attestations-ga/)).
  - The rpi-image-gen SBOM covers the image.
- **The self-hosted runner is root on the firewall.** The hardware job runs `sudo rsync` and `sudo ./install.sh` on every push to `main`, so whoever can push to `main` controls the TV's firewall.
  - **ADOPT NOW:** require signed commits on `main` and branch protection.
  - **PROTOTYPE:** a GitHub environment with required approval for the deploy job.
- **The Pi's own exposure.** The AdGuard UI is bound to loopback (observed); keep it there (the h2c bypass). From the TV side only DHCP, DNS, nginx on 80 and 443, and rate-limited pings reach the Pi (observed). The SSAP pairing key can control the TV, and in 2026 the TV's pairing port had a root chain, so keep the key `0600` and out of every backup that leaves the box unencrypted.

---

## 11. Testing and quality

| Option | Verdict | Detail |
|---|---|---|
| **Virtual gateway in a network namespace, in CI** | **ADOPT NOW** | GitHub's Ubuntu runners have sudo. Build netns `tv` and `gw` and a fake uplink with veth pairs. Run the rendered `tvgw-apply` inside `gw`. From `tv`, send the probes the hardware suite trusts: DNS to 8.8.8.8 must be redirected, 853 rejected, UDP 443 rejected, the LAN dropped, IPv6 dropped, an unexpected port counted. Assert on the counters, and on **which rule matched** via `meta nftrace set 1` and `nft monitor trace`. This is the rule simulation nftables lacks offline ([namespace pattern](https://oneuptime.com/blog/post/2026-03-20-nftables-network-namespace/view)). It is also what makes the distro matrix (§8.3) testable without hardware. |
| `nft -c -f` on every rendered ruleset variant (direct/vpn × QUIC × strict) | **ADOPT NOW** | Seconds; catches syntax errors before deploy ([NixOS does the same](https://mynixos.com/nixpkgs/option/networking.nftables.checkRuleset)) |
| **Hypothesis property tests** for every parser (conntrack line, query-log record, nginx line, SSDP reply, description XML, ClientHello) | **ADOPT NOW** | Properties: never raises anything but the declared error; output escaped; order-independence and idempotence of ingest (ingest twice equals ingest once; the pcap step before or after flows gives the same rows, data-architecture §2.3). `RuleBasedStateMachine` for log rotation and cursor handling. Hypothesis 6.13x, active in 2025 ([Gentoo changelog](https://packages-cdn.gentoo.org/packages/dev-python/hypothesis/changelog)). |
| **Golden corpora keyed by tool version** | **ADOPT NOW** | Store small pcaps and query-log samples with expected rows, keyed by `(extractor, extractor_version)`: tshark 4.0.17 (bookworm), tshark 4.4.19 (trixie), our parser. CI runs each extractor present and diffs it against the others. This is the differential test that would have caught the 2026-10-27 incident. |
| Hardware-in-the-loop | **ADOPT NOW (keep)** | The self-hosted runner is right; add the signed-commit gate (§10) |
| Mutation testing at scale | Keep mutmut; PROTOTYPE per-PR runs on changed files | mutmut 3.5 (Feb 2026) mutates only inside functions and needs fork ([comparison](https://pytest-gremlins.readthedocs.io/en/latest/guide/comparison/)); cosmic-ray 8.4 is the alternative. Bash glue: shellcheck plus bats (unverified that either is set up). |
| A reachability matrix as a golden file | PROTOTYPE | From the namespace harness, enumerate (source zone, destination, port) → verdict and commit it. A firewall change then shows up as a reviewed diff. This is the "formal-ish" check. |

---

## 12. Moonshots

**A. An opt-in community observatory of TV telemetry.**

- **What it takes:** a local "share pack" of (vendor, model family, firmware, registrable domain, category, day, lookups, connections, blocked) and nothing else. No timestamps finer than a day, no addresses, no URIs. The owner reads it before anything is sent, and sends it by hand.
- **Aggregation:** release a cell only when at least k households report it. Prio-style secret-shared aggregation is being standardized as DAP (draft-ietf-ppm-dap-18, May 2026) with Divvi Up as an operator ([PPM WG](https://datatracker.ietf.org/wg/ppm/documents/), [Divvi Up](https://divviup.org/get-involved)).
- **Who is close:** IoT Inspector (NYU; v3 waitlisted), Northeastern's Mon(IoT)r lab, HaGeZi's issue tracker.
- **First step:** `tvgw share-pack --week` writes the JSON locally. Nothing leaves.

**B. A firmware-diff service.**

- **What it takes:** a behavioural diff per firmware version (new and removed names, JA4 stacks and ports; the brief's Firmware section is the seed). Static diffing with epk2extract needs decryption keys dumped from a rooted TV ([epk2extract](https://github.com/Informatic/epk2extract)), which is legally grey and out of scope.
- **Who is close:** nobody publishes TV behavioural diffs.
- **First step:** `tvgw firmware-diff OLD NEW` over `host_day` once data-architecture Stage 1 lands.

**C. A vendor-neutral profile registry with evidence grades.** See §6.4.

- **Who is close:** HaGeZi (domains only), Home Assistant (LAN APIs), PoPETs 2027 (opt-out effectiveness).
- **First step:** a JSON Schema for the profile TOML plus CI lint, and three DNS-only profiles.

**D. Position-based evidence capture.** On Pi kernels this is NFLOG, not eBPF (§1).

- **First step:** the namespace harness (§11) with a `log group` rule, proving `ct original packets <= 8` captures a two-segment ClientHello.

**E. A privacy-label scorecard per TV, generated from gateway data.**

- **What it measures:** whether the ACR opt-out was effective as observed; telemetry endpoints contacted with settings off; traffic while off or in standby; LAN scanning; hardcoded DNS and DoH attempts; plaintext HTTP, including firmware fetches; estimated upload a day (§5.3); and the breakage cost of each block.
- **Who is close:** Mozilla's *Privacy Not Included was reportedly retired in August 2026 (forum report, [Privacy Guides](https://discuss.privacyguides.net/t/mozillas-privacy-not-included-has-sunsetted/39887)). The Cyber Trust Mark is about security only. PoPETs 2027 measures in a lab.
- **First step:** `tvgw scorecard --week` from the existing tables.

**F. A ready-to-flash appliance image.**

- **First step:** the .deb (§8); then rpi-image-gen and an Imager repository (§9); then the CM5 dual-Ethernet box as reference hardware (§7).

**G. A blocklist other projects consume.**

- **First step:** open HaGeZi issues for observed LG hosts missing from `native.lgwebos`, each with its dated evidence; then the must-allow and breakage ledger (§2).

**H. Academic collaboration.**

- **What we have that labs lack:** a longitudinal, real-home, single-TV record with a firmware timeline, per-rule breakage notes and red-line history. Labs have breadth.
- **Who to approach:** Northeastern (Choffnes, Dubois), IMDEA and Mandalari (IMC 2024), NYU (IoT Inspector).
- **First step:** a one-page data description with the privacy approach of A; the owner decides whether to send it.

---

## Top 10 recommendations

Ranked by impact. Effort: S (days), M (one to two weeks), L (more). Risk is to the running gateway.

1. **Package tvgw properly.** A wheel plus a hash-pinned wheelhouse, built by nfpm into a .deb (then .rpm and Arch); a signed apt repository with deb822 `Signed-By`; units in `/usr/lib/systemd/system`; a conffile config; `StateDirectory`; sysctls in `sysctl.d`; AdGuard as a checked dependency. *L effort, medium risk* (install-path change; keep `install.sh` until parity).
2. **`tvgw setup` around the new `tvgw discover`.** Pick from a list, pair, write, apply, verify; an answers file for unattended installs. Pin the SSDP `LOCATION` fetch now. *S-M effort, low risk.*
3. **A virtual gateway in CI.** Network namespaces, `nft -c`, nftrace rule-match assertions and a reachability matrix golden file. It is the prerequisite for any distro beyond Raspberry Pi OS. *M effort, low risk.*
4. **DNS hardening for 2026.** Strip HTTPS/SVCB answers for the TV (after checking type-65 counts); own `aaaa_disabled` and `handle_ddr`; an AdGuard version floor in `verify`; an ECH canary. *S effort, low risk.*
5. **Capture v2.** dumpcap with wall-clock rotation now; position-based NFLOG capture (`ct original packets <= 8`) as a parallel prototype. It bounds bytes per connection and keeps split ClientHellos. *M effort, medium risk* (firewall change; owner approval).
6. **A small sandboxed extractor.** ClientHello across segments, JA4, ALPN, the ECH extension, QUIC Initial names, HTTP request lines, run under systemd sandboxing. tshark and Zeek become the differential reference over golden corpora keyed by version. *M effort, low-medium risk.*
7. **Storage resilience.** NVMe or eMMC for new builds; an RTC battery; a hardware watchdog; a daily `VACUUM INTO` with `quick_check` and an encrypted pull off the box; 90 days of facts with rollups kept forever. *S-M effort, low risk.*
8. **DNS-gated egress.** Count-only for two weeks, then enforce. Hardcoded addresses and unknown DoH become impossible, not just reported. *M effort, medium-high risk in enforce mode.*
9. **Analysis v2 and a propose-only LLM analyst.** RITA-style beacon scoring with a data-size half and Lomb-Scargle confirmation; the ACR cadence canary; honest upload ranges; a daily Batch call with a schema-constrained, lint-checked, injection-hardened, data-minimized pack, written into the brief and never applied. *M effort, medium risk.*
10. **Profile registry v2 and upstream contributions.** The `peer-reviewed` grade, `[[lan_api]]` and `[[privacy_setting]]` records, DNS-only Samsung, Roku and Vizio profiles, HaGeZi and Perflyst submissions, a must-allow and breakage ledger. *M effort, low risk.*

## Do not do

- **Do not containerize the firewall core.** Host networking with `NET_ADMIN` is no boundary and breaks fail-closed boot ordering.
- **Do not switch the store** to WAL, Litestream, DuckDB, ClickHouse, TimescaleDB or a time-series database. Decision 10 stands, and the WAL-reset bug is one more reason.
- **Do not replace AdGuard Home** with Pi-hole v6, Unbound RPZ, CoreDNS, Blocky or a cloud filter. Revisit only if AdGuard v1.0 breaks config-as-code.
- **Do not deploy eBPF capture on stock Pi kernels**, eCapture, Arkime, ntopng, or a rule-loaded IDS on the Pi.
- **Do not build on JA3**, and do not redistribute JA4+ output in anything sold (FoxIO License).
- **Do not merge** the CC BY-NC-ND ACR list or GPL list text into an MIT or CC0 repository. Cite them; build from our own observations.
- **Do not fork a general blocklist.** Contribute upstream.
- **Do not root the CX** or build features on the Luna write bypass (decision 4). Do not retry SSAP writes on 04.64.
- **Do not let an LLM apply anything.** Do not send it the ZIP code, the device name, LAN probes, minute-level timelines or raw query strings. **Add no push alerts** (the owner's rule).
- **Do not reflash the Pi to OpenWrt or OPNsense.** Do not add a casting reflector by default.
- **Do not use dh-virtualenv, Snap, Flatpak, pipx, uv-managed Python at runtime, or debconf as the installer UI.**
- **Do not rename `eth0`** until every hardcoded interface name and subnet is templated (§8.4).
- **Do not upgrade the Pi in place from bookworm to trixie.** Raspberry Pi recommends a fresh flash. Test netplan's handling of `tv-lan` on a fresh image first.
