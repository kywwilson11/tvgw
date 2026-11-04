# Naming a connection after the TLS name goes dark

*Deep dive, 2026-11-01. Research only: nothing here is implemented. It goes past [state-of-the-art-2026-10.md](../state-of-the-art-2026-10.md) (the October pass) on one question: how tvgw keeps per-connection naming and classification when Encrypted ClientHello (ECH), QUIC or anything else hides the server name. It reads with [architecture.md § Naming a connection](../../how-it-works/architecture.md#naming-a-connection) and design decisions 12, 18, 20 and 21. The work in flight on other branches (capture v2 with NFLOG first-8-packets, the hardened extractor with JA4, QUIC names and the ECH flag, the network-namespace CI gateway, profiles v2) is treated as given and not researched again. Where this page has something for one of those branches, it says so.*

**Method.** Primary sources: RFCs 9460, 9848 and 9849, vendor documentation, source code (AdGuard Home, Chromium, BoringSSL), papers, and FoxIO's license FAQ. Some facts are my own measurements from the workstation on 2026-11-01: public HTTPS-record lookups through Cloudflare's DoH JSON API, `Alt-Svc` headers fetched with curl, PTR lookups, an offline ASN table and PeeringDB. Each such fact is marked **(measured 2026-11-01)**. These measurements did not touch the gateway or the TV. CDN point-of-presence codes and addresses seen from the workstation are left out on purpose. **(unverified)** means I could not confirm the claim from a primary source.

---

## Bottom line

Through 2027, tvgw should name each connection from **the TV's own DNS answers**, with **the TLS name as the cross-check where it is visible**. Today the TLS name is the only source. Every other signal (JA4, the ASN, rDNS, TCP and DHCP fingerprints) labels the client stack or the network operator, and none of them names the service.

ECH is not what will darken the CX in 2027. Its web engine is Chromium 68, which has no ECH code. As far as I could find, only Cloudflare, and Meta without DNS publication, run ECH in production. None of the streaming front doors I checked publishes an ECH key, and they sit on CloudFront, Akamai, Fastly or their own CDNs.

The real losses are different:

- **Flows that never carry a TLS name.** The current join already loses these: UDP, plain HTTP and missed hellos all land in `Unresolved`.
- **Shared CDN addresses.**
- **Later webOS generations and native app stacks.** These have the code to use ECH and would get their keys from configuration they ship with, which DNS stripping cannot remove (RFC 9849 §3.2, and Meta's deployment shows it).

Stripping HTTPS and SVCB records remains effective and safe. AdGuard's `default` blocking mode answers a blocked type-65 query with an empty NOERROR and no SOA. Cloudflare documents that answer as the way to stop Chrome using ECH, and it avoids the "resolution failure" case where RFC 9460 lets a client give up on the service.

Stripping is only a partial defence, though. What tvgw needs is a **DNS-answer naming source with recorded provenance and an ambiguity count**, built on a TTL-carrying address index. Once DNS-gated egress is enforced, every allowed flow has an answer by construction. Then the TV cannot open a connection the gateway cannot name, only one it can name ambiguously, and how often that happens can be measured on the store already there (test T1).

---

## Findings

### F1. ECH in late 2026: a standard, one CDN, and keys that do not need DNS

- **Standard.** ECH is RFC 9849 (March 2026), and RFC 9848 covers publishing its keys in SVCB/HTTPS records ([RFC 9849](https://www.rfc-editor.org/rfc/rfc9849.html), [SANS ISC, 2026-03-09](https://isc.sans.edu/diary.html?date=2026-03-09)). Two of the RFC's rules matter here:
  - **Keys need not come from DNS.** RFC 9849 §3.2 says the ECHConfigList may come from "other delivery mechanisms" and the client "may have the ECH configuration preconfigured". A client whose real ECH offer is rejected receives `retry_configs`, and it SHOULD retry with them (§6.1.6). So an app shipped with an old key gets a fresh one from the server, and DNS is never involved.
  - **GREASE ECH cannot bootstrap real ECH.** A client sending GREASE ECH "MUST NOT save the retry_configs" (§6.2.1). A stack with no key, which is what stripping leaves, stays without one.
- **Servers.** Cloudflare turns ECH on by default for Free zones, and other plans can turn it on, with the shared outer name `cloudflare-ech.com` ([Cloudflare docs](https://developers.cloudflare.com/ssl/edge-certificates/ech/)). A SIGCOMM 2025 poster found that **Meta runs ECH without advertising it in HTTPS DNS records** ([Mücke et al., SIGCOMM 2025 poster](https://dl.acm.org/doi/10.1145/3744969.3748401); [TU Dresden entry](https://netd.cs.tu-dresden.de/pub/mgsw-ptcve-25.html)). Its apps must therefore carry or fetch keys outside DNS. A 2025 passive study saw an ECH extension on 59% of QUIC flows, but only 1.96% of those were real ECH, and every real ECH server was on Cloudflare ([Merlach et al., *Network* 2025](https://www.mdpi.com/2673-8732/5/3/29)). I found no vendor announcement of ECH from Akamai, Fastly or CloudFront; secondary sources disagree, and none cites vendor documentation (unverified either way).
- **Measured 2026-11-01, HTTPS records** (type 65, through Cloudflare DoH):

  | Name | HTTPS record | `ech=` |
  |---|---|---|
  | crypto.cloudflare.com (Cloudflare's test name) | yes, `alpn=h2` | **yes**, public name `cloudflare-ech.com` |
  | google.com | yes, `alpn=h2,h3` | no |
  | www.youtube.com, youtube.com | yes, empty parameters | no |
  | www.facebook.com | yes, `alpn=h2,h3` | no (consistent with Meta's DNS-less ECH) |
  | tv.apple.com | yes, `alpn=h3,h2`, hints on Fastly | no |
  | www.akamai.com | yes, `alpn=h3,h2` | no |
  | play.max.com, aws.amazon.com | yes, `alpn=h2` | no |
  | atv-ps.amazon.com (Prime Video) | yes, `alpn=http/1.1` | no |
  | netflix.com, www.netflix.com, api-global.netflix.com, www.primevideo.com, unagi-na.amazon.com, disneyplus.com, bamgrid.com, www.peacocktv.com, roku.com | none | n/a |
  | us.lgtvsdp.com, lgappstv.com, ngfts.lge.com, us.lgrecommends.lgappstv.com | none | n/a |

  None of the streaming or LG names publishes an ECH key. Several Google, Apple and Akamai names publish `alpn=h3` hints, which the strip also removes (see F4).
- **Client libraries.**
  - **BoringSSL** has had ECH for years, and Chrome shipped it in 117. Chrome fetches the key "over DoH and over our built-in DNS resolver" ([Intent to Ship](https://groups.google.com/a/chromium.org/g/blink-dev/c/CmlXjQeNWDI/m/r-AUe0OqAQAJ)). Both paths ask the resolver the gateway hands out, unless the client has a DoH bypass, which `doh4` and the DNS gate cover.
  - **OpenSSL 4.0.0** (2026-04-14) is the first OpenSSL release with ECH, in shared mode only; 3.5 remains the LTS without it ([Help Net Security](https://www.helpnetsecurity.com/2026/04/14/openssl-4-0-0-released/), [OpenSSL blog](https://mirror.openssl-library.org/post/2026-03-11-ech)).
  - **Go** has had client ECH since 1.23, and only when the application fills `EncryptedClientHelloConfigList` itself ([golang/go#63369](https://github.com/golang/go/issues/63369)). Go does no DNS fetch of its own, so a Go app does ECH only if it brings a key.
  - **Apple:** `sec_protocol_options_set_enable_encrypted_client_hello` is marked "experimental" and is off by default. A 2026 developer-forum report says URLSession and Safari do not attempt ECH ([Apple docs](https://developer.apple.com/tutorials/data/documentation/security/sec_protocol_options_set_enable_encrypted_client_hello.md), [forum FB24334961](https://developer.apple.com/forums/thread/842112)).
- **webOS.** LG's own table gives the web engine per generation: webOS 5 (2020, the CX) Chromium 68; 6 → 79; 22 → 87; 23 → 94; 24 → 108; **25 → 120; 26 → 132** ([LG developer site](https://webostv.developer.lge.com/develop/specifications/web-api-and-web-engine)).
  - **Chromium 68 predates ECH and the HTTPS record type.** The CX's web apps cannot send ECH and have no reason to ask for type 65.
  - **webOS 25 and 26 carry Chromium builds that have ECH code.** Whether LG ships them with the built-in resolver and ECH on is unknown (unverified).
  - **YouTube on TVs runs on Cobalt.** Cobalt 25 LTS tracks Chromium M114 (before Chrome turned ECH on) and "integrated HTTP/3 with IETF standard QUIC" ([Cobalt 25 notes](https://developers.google.com/youtube/cobalt/docs/releases/2025-lts-rc)). Which Cobalt the CX's YouTube app runs is unverified.

**Consequence for the CX in 2027.** Of everything on the TV, only a native app with its own TLS stack and a key it ships with could do real ECH. Its likely target would be a Cloudflare- or Meta-fronted endpoint, such as an SDK, an analytics host or ad tech, not the video. The red line already in place (`Encrypted ClientHello in`) will see it. The gateway will not know the inner name unless DNS supplies it (F3).

### F2. Stripping HTTPS/SVCB: still effective against DNS-keyed ECH, and safe in the form tvgw uses

- **What AdGuard actually answers.** tvgw's rule is `||*^$dnstype=HTTPS|SVCB,client=<TV>` (`profile.py`), and tvgw owns `blocking_mode: default`. In AdGuard Home's `internal/dnsforward/msg.go`, a blocked HTTPS query skips the NODATA shortcut that other types take. The `default` mode then has no address to put in it and returns `replyCompressed`: **NOERROR, empty answer, no SOA** ([msg.go](https://raw.githubusercontent.com/AdguardTeam/AdGuardHome/master/internal/dnsforward/msg.go)). Other modes differ: `nxdomain` returns NXDOMAIN with an SOA, and `refused` returns REFUSED. A blocked SVCB query takes the NODATA path (NOERROR with an SOA).
- **Why the form matters.**
  - **Failures may be fatal.** RFC 9460 §3.1 says that over unprotected DNS a client "MAY treat SVCB resolution failure as fatal" ([RFC 9460](https://www.rfc-editor.org/rfc/rfc9460.html)). REFUSED, SERVFAIL or a timeout are failures; an empty NOERROR is a zone that has no such record. **`blocking_mode` must never become `refused`**, or a strict client could give up on every service at once.
  - **Cloudflare's endorsement.** Cloudflare's own page names an empty NOERROR (or NXDOMAIN) to HTTPS queries as what "will prevent browsers, such as Chrome from using ECH" ([Cloudflare](https://developers.cloudflare.com/ssl/edge-certificates/ech/)).
  - **The rule answers locally.** It acts before any upstream is asked, so a TV's HTTPS query still gets the clean empty answer while the DoH upstreams are down. An A query in the same outage gets SERVFAIL.
  - **No negative caching.** The answer carries no SOA, so the TV cannot cache it as a negative answer and will ask again. This costs nothing on one TV and leaves a count to watch (F4).
- **Strip the whole record, never only the `ech` parameter.** RFC 9848 §5.1: once SVCB resolution succeeds and every endpoint carries `ech`, an ECH-capable client "MUST switch to SVCB-reliant connection establishment", meaning no fallback without ECH ([RFC 9848](https://www.rfc-editor.org/rfc/rfc9848.html)). A partial rewrite, or a strip that applies some of the time, is how a TV ends up refusing to connect. AdGuard 0.107.78's `$dnsrewrite` support for the `ech` parameter (October pass) is therefore a tool tvgw should *not* use for this.
- **Limits of the strip.**
  1. It does nothing against a key the client already has (F1: RFC 9849 §3.2, Meta).
  2. It does nothing against a DoH resolver the TV reaches inside an app. `doh4` covers the known list, and the DNS gate covers the rest.
  3. The October pass's first step (check whether the CX asks for type 65 at all) has no recorded result. Run it now (test T3).
- **Verdict.** Keep the strip. It costs nothing and removes `alpn=h3` hints too. Make its form a tested invariant, and do not count it as the defence against ECH. That role belongs to naming that does not depend on the hello.

### F3. DNS-answer naming: the algorithm, its windows and how it fails

**Prior art.** FlowDNS (CoNEXT 2022) joined NetFlow to DNS at a large ISP:

- **Coverage.** It correlated 81.7% of bytes on average ([paper](https://arxiv.org/pdf/2211.05682)).
- **Storage.** It kept one name per address, so the newer name overwrote the older; its controlled test with two sites on one address scored 50%.
- **Ambiguity.** In a 300-second sample, 88% of addresses mapped to a single name.
- **Other parameters.** It followed CNAME chains to a limit of 6, and fewer than 1% of chains were longer. 99% of A and CNAME TTLs were under 3600 and 7200 seconds respectively.

Its numbers are for a whole ISP's clients mixed together. tvgw's situation is easier on every axis:

1. **One client.** Only the TV's own lookups are candidates, so another household's answers cannot collide with it.
2. **Whole answers, chain included.** AdGuard logs each query with its complete answer section, so the CNAME chain is already inside one row. The store's `answers` column holds `CNAME:x,A:y`, so nothing needs to be chased across separate record streams.
3. **One clock.** The resolver log, conntrack and the pcaps share the Pi's clock.
4. **Blocked names are not candidates.** A blocked lookup was answered `0.0.0.0`, so it can never claim a flow.

**The algorithm (a proposal).** For a flow F to address D, the start time t₀ is the flow's SYN time from the pcap when there is one. Use `flows.t_start` only as a fallback, since conntrack's start runs up to a minute late (architecture.md). A candidate is an A answer *a* to the TV that meets all of these:

- `a.blocked = 0`;
- D is among `a`'s A records;
- `a.t ≤ t₀ + 1 s`, to allow for clock and feeder skew;
- `a.t ≥ t₀ − (a.ttl + GRACE)`.

Then:

- **Name.** The flow's name is the `qname` of the newest candidate: the name the app asked for. The last CNAME target is kept beside it as the CDN label. Policy acts on the qname, and the qname is what `lg-webos.rules` speaks.
- **Ambiguity.** `cands` is the number of distinct qnames among the candidates. With one, the name is `unique`. With several under one registrable domain, the name is `domain`, and a category is still safe. With several under different domains, the name is `ambiguous`: report the set (up to 5) and never use the name for autonomy (F7).
- **Stale fallback.** With no fresh candidate, look back `KNOWN_DAYS = 7` (the constant already in `queries.py`) and call the name `stale`. A TV's cache can outlive the TTL, and it outlives a Pi reboot.
- **No candidate at all** means a hardcoded address or a bypass, which the DNS gate counts.

**Windows.** Start with `GRACE = 300` s. Then set it from evidence: compute Δ = t_SYN − t_answer on flows the TLS hello *does* name and whose qname or CNAME chain matches the hello's name, and take its p99. Δ under 5 s is "just looked up", the strongest DNS evidence, and comparable to `FEEDER_LATE = 2.0` for the gate. A long tail of Δ beyond TTL plus grace measures how far webOS's resolver cache overruns TTLs (unverified until measured).

**What the store lacks.**

- **No TTL.** `dnsmsg.Answer` parses the TTL, but `answers_text` drops it.
- **No index from address to answer.** The join has to `LIKE`-scan `answers`.

Fix both with a derived table `answer_ip(dns_id, ip, t, ttl)` indexed on `(ip, t)`, filled at ingest from rows already parsed. Names stay computed at report time (decision 12), and only the index is new.

**Failure modes, worst first:**

1. **Shared addresses.** Cloudflare anycast, Akamai and CloudFront edges serve many tenants on one address. When the TV looks up two names on one address within the window, the newest wins, and it can be the wrong one; this is FlowDNS's 50% case. Report it (`ambiguous`) and do not guess. The TLS name, where it is visible, settles it per connection.
2. **Connection reuse and coalescing.** HTTP/2 and HTTP/3 carry many requests, and Chromium coalesces origins onto one connection when the certificate covers them. Neither the TLS name nor DNS names the later requests. No naming method fixes this without decryption, and tvgw does not decrypt (decision 3).
3. **Long-lived connections** keep the name from their start. This is correct, but the bytes land hours later (`t_end`, the known limit).
4. **Prefetched lookups** that no connection follows do no harm, except as extra candidates in case 1.
5. **Answers older than the store.** The first day after a Pi rebuild has no history. This is the same overstatement the gate has.
6. **Multi-CDN names.** One qname answers from different CDNs over time (measured 2026-11-01: tv.apple.com's HTTPS-record hints were Fastly while its A answer was an Akamai address). This is harmless for naming, because the qname is the same.
7. **First-party telemetry on content hosts.** When an app sends telemetry to the same name as its video, no network-level name tells the two apart. Only the traffic shape can.

**A free check (T1).** On every flow that has both a TLS name and a DNS name, their agreement measures the DNS method on this very TV before anything depends on it. Until a hello goes dark, the TLS name stays the better per-connection source. The DNS name exists for the flows that have no hello: UDP, plain HTTP, missed hellos, and later ECH and QUIC.

### F4. QUIC: what blocking UDP 443 costs in 2026, and what to measure

- **The firewall today.** `udp dport 443 counter reject` (`tvgw-apply`): in an inet table this replies with an ICMP port-unreachable. Chromium-family stacks then fail fast and mark the alternative service broken for 300 s, doubling on each failure up to a shift of 18 ("approximately 2 days") ([broken_alternative_services.cc](https://chromium.googlesource.com/chromium/src.git/+/HEAD/net/http/broken_alternative_services.cc)). A browser-like client should therefore make fewer and fewer QUIC attempts per origin. A client that tries QUIC on every connection is paying a round trip each time, and the QUIC Initial names (extractor branch) will show which client it is.
- **Who advertises HTTP/3** (measured 2026-11-01, `Alt-Svc` on front doors, US vantage):
  - **Advertise h3:** www.youtube.com and redirector.googlevideo.com (`h3`, `h3-29`, max-age 30 days), tv.apple.com (`h3`).
  - **No `Alt-Svc`:** www.netflix.com, api-global.netflix.com, www.primevideo.com, atv-ps.amazon.com, www.disneyplus.com, disney.api.edge.bamgrid.com, play.max.com, www.peacocktv.com, www.hulu.com, www.paramountplus.com, www.tubitv.com, pluto.tv.
  - **Caveat:** these are front doors, not video edges, and apps can try h3 without any `Alt-Svc`.
  - **h3 hints in DNS.** google.com, tv.apple.com, www.akamai.com and www.facebook.com also publish `alpn=h3` in their HTTPS records (F1), which the strip removes. The TV can then learn h3 only from an `Alt-Svc` header on a TCP connection.
- **The CX's web engine cannot speak today's QUIC.** Chrome got RFC 9000 QUIC in 90 and turned it on by default in 93 ([Chromium QUIC page](https://www.chromium.org/quic)), so Chromium 68 knows only Google QUIC (gQUIC). Google's `Alt-Svc` now offers only `h3` and `h3-29`, with no `quic=` entry (measured), so the web engine has nothing to upgrade to. On the CX, therefore, **any QUIC attempt comes from a native stack**: Cobalt 25 has IETF QUIC, and others are unverified.
- **A capture blind spot (for the capture v2 and extractor branches).** The current BPF keeps UDP/443 only when `udp[8] & 0x80` is set, the IETF long-header bit. gQUIC Q043 and older use a public header whose first byte (0x08, 0x09, 0x0c or 0x0d) lacks that bit, so **such attempts are counted by the firewall and never captured**. Q043's CHLO is also cleartext with an `SNI` tag, so RFC 9001 Initial decryption does not apply and a plain parse does. NFLOG first-8-packets fixes the capture; the extractor should branch on the version field (`0x00000001` v1, `0x6b3343cf` v2, `Q0xx` gQUIC). Whether any gQUIC client is left on the CX is unknown; test T5 settles it.
- **What could break in 2027.** No TV streaming app was found that refuses TCP when UDP 443 is blocked. The October pass agrees, and forum reports say blocking QUIC on TVs falls back cleanly ([Roku community](https://community.roku.com/t5/Discussions/Constant-Buffering-With-4K-Content/m-p/784991)). The one new 2025 development that is UDP-native is **Media over QUIC**. Cloudflare opened a MoQ relay network on 2025-08-21; native apps use raw QUIC, and browsers use WebTransport over HTTP/3 ([moq.dev](https://moq.dev/blog/first-cdn/), [Cloudflare](https://blog.cloudflare.com/moq-relays/)). A live-sports app built on MoQ would be the first plausible h3-only case. Watch for it; it is not a 2027 concern for the CX.
- **The measurable signal (T6).** For each name, take its QUIC Initials and the TCP ClientHellos to the same name within 5 s after them. A pair is a working fallback. An Initial with no TCP hello after it is an app that gave up: the only evidence that the QUIC reject broke something. It belongs in the brief beside the `QUIC` counter.

### F5. JA4 and JA4+: what they can and cannot do for naming

- **Licence.** JA4 (the TLS client fingerprint) is BSD-3-Clause, and FoxIO has "no patent claims" on it. JA4S, JA4H, JA4X, JA4T, JA4TS, JA4D, JA4D6 and "all future additions" are under the FoxIO License 1.1 and are "patent pending" ([License FAQ](https://github.com/FoxIO-LLC/ja4/blob/main/License%20FAQ.md)). Internal and academic use is permitted; monetization needs an OEM licence. An MIT project may include FoxIO-licensed parts if the licence is noted in a NOTICE file, and those parts stay under FoxIO terms. For tvgw (MIT, possibly packaged by others), the clean line is: **compute JA4 only**, and store the raw TCP SYN and DHCP option lists in tvgw's own format rather than the JA4T or JA4D strings. Recording packet fields that p0f and Fingerbank have recorded for decades is not the FoxIO method. That is my reading, not legal advice.
- **JA4 names the client stack, not the destination.** JA4_a holds the transport (`t`/`q`), the version, `d`/`i` for whether a server name is present, the cipher and extension counts (GREASE excluded, server name and ALPN included) and the first and last character of the ALPN. JA4_b hashes the sorted ciphers. JA4_c hashes the sorted extensions without the server name and ALPN, followed by the signature algorithms in wire order ([JA4 spec](https://github.com/FoxIO-LLC/ja4/blob/main/technical_details/JA4.md)). JA4 says *which app or engine* opened a flow, which helps classification, for example "this unnamed flow came from the Netflix stack". It never says which service.
- **Expect several JA4s per app, for known reasons:**
  - **ALPN and server-name presence** change JA4_a.
  - **Resumption** adds `pre_shared_key` (0x0029) only when a session is being resumed (BoringSSL `should_offer_psk`, [extensions.cc](https://boringssl.googlesource.com/boringssl/+/refs/heads/main/ssl/extensions.cc)), which changes the extension count and JA4_c.
  - **Padding** (0x0015) appears in older BoringSSL builds only when the hello is 256 to 511 bytes long. BoringSSL has since removed this F5 workaround ([commit](https://boringssl.googlesource.com/boringssl/+/eae46df1e6c1df0556ee4106bcab75657eb8181e%5E%21/)). JA4 does not exclude it, so on a Chromium 68-era stack the fingerprint can flip with the length of the server name (unverified on the CX).
  - **Proposal:** key the "stack" on JA4_b plus a tvgw-own extension hash that also drops 0x0015, 0x0029 and 0x002a (early data). Show JA4 itself as is.
- **The Pi can already compute it.** The October pass said the Pi's tshark could not produce JA4. That was true on bookworm (4.0). On trixie (4.4.x) the JA4 fields are present, and the JA4_c empty-hash bug was fixed in 4.2.9 and 4.4.2 ([4.2.9 notes](https://wireshark.org/update/relnotes/wireshark-4.2.9.html)). Until the new extractor lands, adding `tls.handshake.ja4` to `tshark.FIELDS` gives JA4 now; test T7 confirms the field name.
- **JA4 databases** do not help a TV. ja4db.com now redirects to ja4db.foxio.io, and its read API did not answer at the documented path on 2026-11-01 (unverified whether moved). Its contents are contributed by browsers, bots and malware, and I found no smart-TV coverage (unverified). tvgw should build its own table: (JA4, app in front from `tvcheck`, first and last seen).
- **The rest of JA4+ adds little.** JA4X fingerprints the server certificate, which TLS 1.3 encrypts, so it sees nothing on most flows. JA4S fingerprints the server's stack, not its tenant. Neither is worth the licence.

### F6. Labelling flows that have no name: ASN, cloud ranges, PeeringDB, rDNS, CT

All of these say **who runs the network or the CDN, never which tenant**. They answer "Amazon CloudFront", never "Prime Video telemetry". They are labels for `Unresolved` and Top upload, and never evidence for a block.

- **Offline ASN, public domain:** [iptoasn.com](https://iptoasn.com/), PDDL v1.0, updated hourly. Measured 2026-11-01: `ip2asn-v4.tsv.gz` is 8.7 MB and holds 540,291 ranges, 80,636 of them unrouted (ASN 0). The columns are start, end, ASN, country and description. It loads into SQLite in seconds, and a lookup is one bisect.
  - **Description strings mislead.** Measured: LG's firmware fallback address in `tvgw-apply` belongs to AS4668 "LGNET-AS-KR - LG CNS", while "LGEENERGY" (AS19273) is Louisville Gas & Electric. Match on ASN numbers, never on description strings.
- **IPinfo Lite**: country and ASN, CC BY-SA 4.0 (attribution), daily, with a free token ([IPinfo](https://ipinfo.io/products/free-ip-data-downloads)). It is a second source, but it needs an account; iptoasn does not.
- **Cloud provider ranges carry a service tag.** AWS `ip-ranges.json` tells `CLOUDFRONT` from `EC2`, `S3`, `GLOBALACCELERATOR` and others. `AMAZON` is the superset, and two codes were added in 2025 ([AWS docs](https://docs.aws.amazon.com/vpc/latest/userguide/aws-ip-syntax.html)). "CloudFront" (a CDN serving many tenants) and "EC2" (some tenant's own server) are different findings. Google, Cloudflare and Fastly publish similar lists. Their URLs are not checked here (unverified).
- **PeeringDB** gives each network's type. Measured 2026-11-01: AS2906 Netflix `Content`, AS13335 Cloudflare `Content`, AS20940 Akamai `Content`, AS54113 Fastly `Content`, AS16509 Amazon `Enterprise`, AS4668 LG CNS `NSP` ([PeeringDB API](https://www.peeringdb.com/api/net?asn__in=2906,16509,13335,20940,54113,4668)). Fetch it at refresh time rather than bundling it; whether its terms allow redistribution is unverified.
- **The embedded-cache trap.** Netflix's embedded appliances are "assigned one publicly routable host IPV4 address" from the ISP's own subnet, and serve only the clients the ISP advertises to them over BGP ([Open Connect deployment guide](https://openconnect.netflix.com/deploymentguide.pdf)). By ASN, Netflix video served from inside the ISP looks like the ISP. Google Global Cache and Akamai's ISP-embedded clusters behave the same way (unverified for those two). So "home ISP ASN" on a big download is not an anomaly.
- **rDNS is a hint, and its owner can spoof it.** Measured 2026-11-01:
  - **What PTR records gave:** CloudFront addresses return `server-…​.r.cloudfront.net` (a POP code, not the tenant); Akamai returns `a…​.deploy.static.akamaitechnologies.com`; the www.netflix.com address returns `prod.ftl4.netflix.com`.
  - **What they did not:** the YouTube and Cloudflare test addresses had no PTR at all.
  - **Trust:** whoever controls a reverse zone can publish any name, so rDNS must never feed allow or block decisions. The Pi's own PTR lookups also leave through its resolver path, which should stay the VPN.
- **Certificate Transparency** logs names, not addresses (IP-address certificates are rare). It cannot map an address to names passively, and with TLS 1.3 the gateway never sees the server's certificate. What CT can do is take a *new name* the TV used and list the other names on its certificate (crt.sh), which groups siblings by operator. That is an online lookup that discloses the name, so it suits the analyst's rare new-host case at most, and nothing per flow.

### F7. Naming feeds autonomy. Guard that before widening it

Decision 20's shapes come from "the flows `FLOW_NAME` names". Widening `FLOW_NAME` with DNS names changes what the payload gate and the canary's streaming baseline see:

- **Wrong attribution fails safe for blocking.** A shared-address video flow wrongly given a telemetry name raises that name's bytes, and the payload gate then *refuses* the block.
- **It does not fail safe for the canary.** Streaming bytes moved to a non-streaming name, or unnamed flows newly named into Streaming, shift the baseline `autoblock.streaming_rate` compares against. The canary's revert then fires on noise, or fails to fire.

Rule: **autonomy and the canary read only names from `sni`, `quic`, `http` and `dns-unique`.** The reports may show `dns-domain`, `dns-ambiguous`, `stale` and `org` labels, marked as such. The analyst pack carries each name's source, so the model is not reasoning from a guess presented as fact.

### F8. DDR, DNR, ODoH and relays: not on any TV found, and checkable at the gateway

- **DDR** (RFC 9462): tvgw owns `handle_ddr`, documented only as "Handle Discovery of Designated Resolvers (DDR) requests" ([AdGuard wiki](https://github.com/AdguardTeam/AdGuardHome/wiki/Configuration)). What it answers when AdGuard has no encryption set up is unverified, and test T8 settles it. The one wrong answer would be a designation of an upstream such as 1.1.1.1 DoH, which `doh4` would then reject. That is safe, but a wasted attempt.
- **DNR** (RFC 9463, DHCP option 162): Kea supports it and ISC DHCP does not ([ISC](https://kb.isc.org/docs/standard-dhcp-options)). The Windows 11 client is behind a registry switch ([guide](https://www.anoopcnair.com/enable-or-disable-dnr-support-for-windows-11/)), and I found no Android or webOS support. dnsmasq sends only the options its template configures, so the TV cannot be offered DNR. The useful signal is the other way round: **if the TV's DHCP parameter request list ever includes 162**, its stack learned DNR. `log-dhcp` is already on in the dnsmasq template, so the request list is already in the journal.
- **ODoH, iCloud Private Relay, Google's relays:** I found no TV platform that uses any of them (unverified as a negative). Private Relay and MASQUE ride QUIC or HTTP/2 CONNECT to listed relay hosts, which the October pass already covers. ODoH relays are not in a DoH list by construction. The DNS gate, not the list, is the backstop.

### F9. Passive fingerprints to spot firmware and stack changes without the LAN API

- **TCP SYN** (the p0f idea, in tvgw's own format): IP TTL, DF, window, MSS, window scale and the option-kind order. It changes only when the kernel or its sysctls change. On the CX, whose firmware updates are minor, it will rarely move. It is worth more to the in-flight Samsung, Roku and Vizio DNS-only profiles, where there is no LAN API.
- **DHCP:** option 55 (the parameter request list), option 60 (vendor class), 57 (maximum message size) and 12 (host name). They are already logged by `log-dhcp`. They change only when the DHCP client changes, and a new option in 55 (162 DNR, 108 IPv6-only preferred, 114 captive portal) is a stack upgrade.
- **JA4 by app** changes when an app updates its TLS stack (Cobalt, Netflix) or when firmware moves the web engine. On the CX this is the likeliest of the three to move.
- **One table** answers both F3 and F9: `syn(t, dst, dport, sport, ttl, df, win, mss, ws, opts)` from the SYNs the capture already keeps. It gives the exact flow start (t₀) the DNS join needs, and the SYN signature. A brief section "New stack signatures", listing any SYN, DHCP or JA4 stack tuple not seen in 30 days, joins the firmware section as a reason for the analyst to look. It is not a red line.

---

## Where this disagrees with the October pass

1. **"The Pi's current OS cannot produce JA4 from tshark."** It can since the trixie upgrade (tshark 4.4.x). JA4 is a field to add now, not something to wait for.
2. **"JA4+ (S, H, X, T, L): WATCH."** Make it REJECT for tvgw. JA4X is blind under TLS 1.3, JA4S does not name tenants, and the useful part of JA4T and JA4D can be had from raw fields without the licence.
3. **"Strip HTTPS/SVCB: clients fall back to A records."** True, but only because of the *form* AdGuard uses: an empty NOERROR in `default` mode, which tvgw must pin as an invariant. A `refused` mode would turn it into an RFC 9460 resolution failure. The strip also does nothing against keys an app ships with, and it should not be read as the ECH defence.
4. **"ECH canary: outer name equal to a known public name means real ECH."** For the CX, any `0xfe0d` is news on its own: Chromium 68 predates even GREASE ECH. A **type-65 query from the TV** is an earlier and cheaper canary than the extension.
5. **"QUIC Initial server-name extraction: ADOPT NOW."** Yes, but the CX's web engine can only speak gQUIC, which today's capture filter drops and RFC 9001 decryption cannot read. The extractor should branch on the version, and capture v2 should keep UDP/443 first packets without the long-header test.
6. **"Unresolved flows" as the end state.** With an address index, most of `Unresolved` becomes DNS-named, and once the gate enforces, a flow with no DNS name is a firewall event rather than a reporting gap.

---

## What to build here

Ranked by value for the risk. Effort: S under a day, M a few days, L more. Risk is to the running gateway.

| # | What | Effort | Risk | Notes |
|---|---|---|---|---|
| 1 | **Run T1 to T3 on the store** before writing code: how much DNS naming agrees with the TLS name, how many addresses are shared, whether type-65 queries happen at all | S | None (read-only SQL) | Decides `GRACE` and whether `dns-ambiguous` is rare or common |
| 2 | **`answer_ip(dns_id, ip, t, ttl)` derived table**, indexed `(ip, t)`, filled at ingest. `answers_text` keeps its format; the TTL comes from `dnsmsg.Answer.ttl` | S-M | Low (additive schema, rebuildable from `dns`) | A schema bump; the backfill can recompute from AdGuard's stored answers only while the query log is retained |
| 3 | **DNS-answer naming as a second source**: `name_source` ∈ {sni, quic, http, dns-unique, dns-domain, dns-ambiguous, stale, org, none}, with `cands` and Δ. The `Unresolved` category splits by source. Agreement with the TLS name goes on the Coverage line | M | Low for reports | Names stay computed, never stored (decision 12); needs a design-decision entry |
| 4 | **Autonomy guard (F7)**: `autoblock.shapes` and `streaming_rate` read only {sni, quic, http, dns-unique}; the analyst pack carries `name_source` | S | Lowers risk | Land it with or before #3, never after |
| 5 | **Pin the strip's form**: `verify` asserts `blocking_mode == default` and the generated rule is present; the netns CI sends an HTTPS and an SVCB query from the TV's address and expects rcode 0 and no answers | S | None | Feeds the netns CI branch |
| 6 | **Type-65 canary**: a brief line, and a novelty reason for the analyst, the first time the TV asks for HTTPS or SVCB in 30 days | S | None | Earlier than the ECH red line |
| 7 | **ECH red line with DNS candidates**: when `0xfe0d` appears under an unlooked-up outer name, list the DNS candidates for the address (the likely inner names) | S | None | Needs #2 |
| 8 | **To the capture v2 and extractor branches**: keep UDP/443 first packets whatever the header form; parse the gQUIC `Q0xx` cleartext CHLO `SNI` tag; record the QUIC version | S | Low (capture change: update the privacy page's numbers) | Gives `quic` names on stacks before RFC 9000 |
| 9 | **QUIC fallback metric (T6)**: per name, the share of QUIC Initials followed by a TCP hello within 5 s; "QUIC without fallback" in the brief | S once QUIC names land | None | The only evidence the reject broke something |
| 10 | **JA4 now through tshark 4.4** (`tls.handshake.ja4`), plus a tvgw "stack key" hash that drops 0x0015, 0x0029 and 0x002a; table (JA4, app in front, first and last seen) | S | Low | The new extractor takes over later |
| 11 | **`syn` table and stack signatures** (TCP SYN fields, DHCP 55/60/57 from the journal, JA4 stack keys); a brief section "New stack signatures" | M | Low | Gives t₀ for #3; most useful for the DNS-only profiles |
| 12 | **Org labels for unnamed flows**: iptoasn (PDDL) and AWS, Google, Cloudflare and Fastly ranges, refreshed weekly by a timer through the Pi's own route; PeeringDB `info_type`; rDNS shown as a hint | M | Low (a fetch job like `tvgw-doh-update`) | Labels only, never block evidence; match on ASN numbers |
| 13 | REJECT: JA4S, JA4X, JA4T and JA4D strings; CT for address-to-name; rDNS or ASN as block or allow evidence; partial `ech` rewriting with `$dnsrewrite` | | | F2, F5, F6 |
| 14 | WATCH: CloudFront, Akamai or Fastly turning on ECH; webOS 25/26 with Chromium ECH on; an `0xfe0d` or a type-65 query from any TV app; MoQ in a streaming app; 162 in the TV's DHCP request list | | | Each trigger has a detector above |

### Tests, exact, to run on the gateway later

- **T1, how much DNS naming agrees with the TLS name.** Run it as an `adm` member with `tvgw sql "<query>"`; the query is below. "agree / unique" is the share DNS gets right per connection. "differ / shared" is the shared-address failure, at its real size on this TV. "no hello" rows with an answer are the flows #3 would newly name. Then repeat with `x.sni` matched against the CNAME chain and against the registrable domain. Validated on a synthetic store (it separates a unique-address agree from a shared-address differ).
  ```sql
  WITH f AS (
    SELECT f.id, f.dst, f.t_start, f.bytes_down,
      (SELECT x.sni FROM tls x WHERE x.dst=f.dst AND x.sport=f.sport AND x.dport=f.dport
         AND x.t BETWEEN f.t_start-300 AND f.t_end ORDER BY x.t DESC LIMIT 1) AS sni
    FROM flows f WHERE f.t_start >= strftime('%s','now','-7 days') AND f.dport=443),
  j AS (
    SELECT f.*,
      (SELECT d.qname FROM dns d WHERE d.blocked=0 AND d.t BETWEEN f.t_start-3600 AND f.t_start+1
         AND ','||d.answers||',' LIKE '%,A:'||f.dst||',%' ORDER BY d.t DESC LIMIT 1) AS dnsname,
      (SELECT COUNT(DISTINCT d.qname) FROM dns d WHERE d.blocked=0 AND d.t BETWEEN f.t_start-3600 AND f.t_start+1
         AND ','||d.answers||',' LIKE '%,A:'||f.dst||',%') AS cands
    FROM f)
  SELECT CASE WHEN sni IS NULL THEN 'no hello' WHEN dnsname IS NULL THEN 'no answer'
              WHEN lower(sni)=lower(dnsname) THEN 'agree' ELSE 'differ' END AS verdict,
         CASE WHEN cands>1 THEN 'shared' ELSE 'unique' END AS addr,
         COUNT(*) AS flows, SUM(bytes_down) AS down
  FROM j GROUP BY 1,2 ORDER BY 1,2;
  ```
- **T2, the lookup-to-connect delay (sets `GRACE`).** Over the T1 "agree" flows, the distribution of `f.t_start - d.t`. Report p50, p90 and p99. A long tail over the record TTLs, once #2 stores them, is webOS caching past the TTL.
- **T3, does the CX ask for HTTPS or SVCB at all?** `tvgw sql "select qtype, count(*), sum(blocked) from dns where t > strftime('%s','now','-30 days') group by 1 order by 2 desc"`. A type-65 row on webOS 5 would mean a native stack, not the web engine. Every such row should show as blocked.
- **T4, the strip's answer on the wire.** In the netns CI, from the TV's address: `dig @<gateway> HTTPS crypto.cloudflare.com +norecurse` should give `status: NOERROR`, `ANSWER: 0`, and no AUTHORITY SOA. Repeat with `SVCB`, which should give NOERROR with an SOA (the NODATA path).
- **T5, gQUIC still present?** On the Pi: `sudo tcpdump -ni eth0 -c 20 -X 'udp dst port 443 and udp[8] & 0x80 = 0'`. Look for the ASCII `Q043` (or `Q03x`) at UDP payload offset 9. Compare the brief's `QUIC` counter with the count of long-header UDP/443 packets in a day's pcaps; a counter well above it means gQUIC the capture drops.
- **T6, QUIC fallback** (once QUIC names exist): per name and day, `quic_initials`, then `tcp_hellos_within_5s`. A ratio below 1 sustained over a day for a name the owner uses is a broken app.
- **T7, JA4 in the Pi's tshark:** `tshark -G fields | grep -i -E 'ja4'` should list `tls.handshake.ja4` (and `ja4_r`). Then `tshark -r <one pcap> -Y tls.handshake.type==1 -T fields -e tls.handshake.extensions_server_name -e tls.handshake.ja4 | sort | uniq -c`, run under the existing sandbox.
- **T8, DDR:** on the Pi, `dig @127.0.0.1 _dns.resolver.arpa SVCB`. The answer should be empty, or designate only the gateway. A designation of an upstream is the case to fix.
- **T9, DHCP request list:** `journalctl -u dnsmasq -g 'requested options' --since -30d | sort | uniq -c`. Record the list as the baseline, and treat a new option as a stack change.

---

## Open questions

1. **How common is a shared address on this TV?** T1 answers it. If `differ/shared` is a large share of bytes, `dns-ambiguous` will be common and the name-source split matters more than the DNS name itself.
2. **Does webOS's resolver honour TTLs?** T2 answers it. If it caches for long past TTLs, `GRACE` grows and ambiguity grows with it.
3. **Is any QUIC on the CX gQUIC?** T5 answers it. And which Cobalt does the CX's YouTube run? Not public (Cobalt's issues sit in the partner portal).
4. **Does webOS 25/26 turn on Chromium's built-in resolver and ECH?** Unverified. It matters for the generations a later profile would cover, not the CX.
5. **Will CloudFront, Akamai or Fastly turn on ECH?** No announcement found as of 2026-11-01. That is the trigger that would put ECH on the streaming apps' own hosts.
6. **What does AdGuard answer to DDR with no encryption configured?** T8 answers it.
7. **Should DNS-named flows enter the DNS gate's enforce-mode logic?** The gate already uses the same answers. Should "named by DNS" and "allowed by the gate" become one function, so that one cannot drift from the other? This is for the DNS-gated egress branch.
8. **May tvgw redistribute PeeringDB data?** Its terms were not checked. Fetching at runtime avoids the question.

---

## Sources

- RFC 9849, TLS Encrypted Client Hello (March 2026): https://www.rfc-editor.org/rfc/rfc9849.html
- RFC 9848, bootstrapping ECH with DNS service bindings: https://www.rfc-editor.org/rfc/rfc9848.html
- RFC 9460, SVCB and HTTPS records (§3, §3.1): https://www.rfc-editor.org/rfc/rfc9460.html
- SANS ISC diary, "Encrypted Client Hello: Ready for Prime Time?", 2026-03-09: https://isc.sans.edu/diary.html?date=2026-03-09
- Cloudflare, Encrypted ClientHello: https://developers.cloudflare.com/ssl/edge-certificates/ech/
- Mücke, Gasser, Schmidt, Wählisch, "Towards a Complete View of Encrypted Client Hello Deployments", SIGCOMM 2025 poster: https://dl.acm.org/doi/10.1145/3744969.3748401 and https://netd.cs.tu-dresden.de/pub/mgsw-ptcve-25.html
- Merlach, Trevisan, Giordano, "Encrypted Client Hello Is Coming: A View from Passive Measurements", *Network* 5(3), 2025: https://www.mdpi.com/2673-8732/5/3/29
- Chromium, Intent to Ship: TLS Encrypted Client Hello: https://groups.google.com/a/chromium.org/g/blink-dev/c/CmlXjQeNWDI/m/r-AUe0OqAQAJ
- OpenSSL 4.0.0 release (2026-04-14): https://www.helpnetsecurity.com/2026/04/14/openssl-4-0-0-released/ ; OpenSSL ECH post: https://mirror.openssl-library.org/post/2026-03-11-ech
- Go ECH tracking issue: https://github.com/golang/go/issues/63369
- Apple, `sec_protocol_options_set_enable_encrypted_client_hello`: https://developer.apple.com/tutorials/data/documentation/security/sec_protocol_options_set_enable_encrypted_client_hello.md ; forum FB24334961: https://developer.apple.com/forums/thread/842112
- LG webOS TV web engine versions: https://webostv.developer.lge.com/develop/specifications/web-api-and-web-engine
- Cobalt 25 LTS release notes: https://developers.google.com/youtube/cobalt/docs/releases/2025-lts-rc
- AdGuard Home `internal/dnsforward/msg.go`: https://raw.githubusercontent.com/AdguardTeam/AdGuardHome/master/internal/dnsforward/msg.go
- AdGuard Home configuration wiki: https://github.com/AdguardTeam/AdGuardHome/wiki/Configuration
- FlowDNS (Maghsoudlou, Gasser, Poese, Feldmann, CoNEXT 2022): https://arxiv.org/pdf/2211.05682
- Chromium QUIC page (RFC 9000 from Chrome 90, default 93): https://www.chromium.org/quic
- Chromium `broken_alternative_services.cc`: https://chromium.googlesource.com/chromium/src.git/+/HEAD/net/http/broken_alternative_services.cc
- Roku community, blocking UDP 443 on a TV: https://community.roku.com/t5/Discussions/Constant-Buffering-With-4K-Content/m-p/784991
- Media over QUIC: https://moq.dev/blog/first-cdn/ ; https://blog.cloudflare.com/moq-relays/
- FoxIO JA4 License FAQ: https://github.com/FoxIO-LLC/ja4/blob/main/License%20FAQ.md ; JA4 technical details: https://github.com/FoxIO-LLC/ja4/blob/main/technical_details/JA4.md
- BoringSSL `extensions.cc`: https://boringssl.googlesource.com/boringssl/+/refs/heads/main/ssl/extensions.cc ; removal of the F5 padding workaround: https://boringssl.googlesource.com/boringssl/+/eae46df1e6c1df0556ee4106bcab75657eb8181e%5E%21/
- Wireshark 4.2.9 release notes (the JA4_c fix): https://wireshark.org/update/relnotes/wireshark-4.2.9.html
- iptoasn: https://iptoasn.com/
- IPinfo free data downloads (Lite): https://ipinfo.io/products/free-ip-data-downloads
- AWS `ip-ranges.json` syntax: https://docs.aws.amazon.com/vpc/latest/userguide/aws-ip-syntax.html
- PeeringDB API: https://www.peeringdb.com/api/net?asn__in=2906,16509,13335,20940,54113,4668
- Netflix Open Connect deployment guide: https://openconnect.netflix.com/deploymentguide.pdf
- ISC, standard DHCP options (option 162 DNR): https://kb.isc.org/docs/standard-dhcp-options
- Windows 11 DNR switch: https://www.anoopcnair.com/enable-or-disable-dnr-support-for-windows-11/
- My own measurements, 2026-11-01, from the workstation: HTTPS records through `https://cloudflare-dns.com/dns-query` (JSON); `Alt-Svc` headers with curl; PTR lookups; `https://iptoasn.com/data/ip2asn-v4.tsv.gz`; PeeringDB API.
