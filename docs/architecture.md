# Architecture

tvgw puts a Raspberry Pi between a smart TV and the home network. The TV has one cable and no other way out, so everything it sends passes through software we control. This page shows how the pieces fit: the path packets take, the control plane that writes policy, the data plane that records what happened, the store, and who is trusted with what.

For day-to-day work see [operations.md](operations.md). For the reasons behind the shape, see [design-decisions.md](design-decisions.md).

## The data path

```
              TV subnet 10.10.10.0/24                          home network
 +-------------+                +------------------------------------+         +--------+
 | LG CX       |  eth0          |               the Pi               |  wlan0  | home   |
 | 10.10.10.17 |--------------->| 10.10.10.1                         |-------->| router |--> internet
 +-------------+  (only path)   |                                    | (WAN_IF)+--------+
                                |  dnsmasq    DHCP only, pins the TV |
                                |  AdGuard    DNS :53 -> DoH upstreams (Pi's own traffic)
                                |  nginx      :80 URL filter, :443 TLS passthrough by SNI
                                |  nftables   inet tvgw + netdev tvgw_l2
                                |  routing    table 100: TV traffic -> WAN_IF, direct
                                |  tcpdump    pcap/ (the TV's ClientHellos, HTTP requests, DNS)
                                |  conntrack  flows.log (one line per finished connection)
                                |  tvgw       ingest -> tvgw.db -> brief, report, verify
                                |  VPN client tun0, for the Pi's own traffic only
                                +------------------------------------+
```

What happens to a packet from the TV:

1. **IPv6** never gets past the wire. The `netdev tvgw_l2` table drops every IPv6 frame on `eth0`, and IPv6 is disabled on the interface.
2. **DNS** to any address is rewritten to `10.10.10.1:53`, where AdGuard Home answers. The TV's hardcoded 8.8.8.8 lands there too. AdGuard forwards what it allows over DNS-over-HTTPS. That lookup is the Pi's own traffic, so it follows the Pi's routes, through the VPN client when one runs.
3. **Traffic to the Pi itself** is limited to DHCP, DNS, ports 80 and 443 (nginx), and pings at up to 5 a second, and only to the gateway address. Everything else is dropped.
4. **Forwarded traffic** must come from the TV subnet (any other source is dropped: it would leave un-NATed and unrecorded) and goes through the `tv_out` chain: no home LAN, no tunnel protocols, no DoT/DoQ, no QUIC, no known DoH resolver, no manual IP blocks. Odd ports are logged and counted. The rest is accepted and masqueraded.
5. **Routing.** Policy rule priority 60 sends the TV subnet to table 100, whose default route is the home router via `WAN_IF`. This is `UPLINK=direct`, the mode in use. The Pi's VPN client marks forwarded packets to send them into the tunnel; `tvgw-apply` clears that mark for packets from the TV. Why direct and not the VPN: [design-decisions.md](design-decisions.md#1-the-tv-uses-the-direct-uplink-not-the-vpn).

`UPLINK=vpn` also exists. It sends TV traffic out `tun0`, clamps the TCP MSS to the tunnel's MTU, and drops TV traffic when the tunnel is down. It is not used.

LG's vendor file service (GFTS) is the one place DNS is not enough. AdGuard answers those names with the gateway's address, so the TV's plain-HTTP requests reach nginx on the Pi. nginx forwards app downloads and returns 403 for the side channels. See [../deploy/nginx/README.md](../deploy/nginx/README.md).

Chain by chain, with the reason for each rule: [../deploy/nftables/README.md](../deploy/nftables/README.md).

## The control plane

Policy lives in the repo. Nothing is configured by hand on the Pi except the site settings.

```
 src/tvgw/profiles/lg-webos.toml  ---+--> tvgw adguard apply --> AdGuardHome.yaml
 src/tvgw/profiles/lg-webos.rules ---+      (lists, rules + generated @@ exceptions and
 /etc/tvgw/tvgw.conf  ---------------+       $dnsrewrite rules, upstreams, the TV as a client)
        |
        +--> deploy/install.sh --> dnsmasq config, nginx config (resolver), units
        |
        +--> tvgw-apply --> nftables tables, sysctls, policy routing
              ^   ^
              |   +-- /etc/tvgw/block4.txt, /var/lib/tvgw/doh4.txt (tvgw-doh-update, daily)
              +------ NetworkManager dispatcher, tvgw.service, tvgw-doh-update
```

- **The profile** (TOML plus a `.rules` file) holds everything vendor-specific: categories, must-allow hosts, clock hosts, blocklists, custom rules, the URL filter. See [../src/tvgw/profiles/README.md](../src/tvgw/profiles/README.md).
- **`tvgw adguard apply`** merges the profile and settings into AdGuard Home's YAML. It changes only the keys it owns, validates the result with `AdGuardHome --check-config`, writes it atomically under a lock (one apply at a time), and rolls back unless, within 30 seconds, the resolver resolves the first must-allow name (NOERROR or NXDOMAIN); SERVFAIL counts as not ready, so a deploy while the DoH upstreams are unreachable rolls back and fails loudly. The rollback is the same atomic write, from a backup taken before the service was stopped. `tvgw adguard diff` reports drift. The hardware suite fails on any drift.
- **The nginx files** are not generated. Their block regex must contain the profile's `block_regex`: `tests/unit/test_profile.py::test_nginx_conf_matches_the_profile` ties the regex, the `server_name` list and the passthrough map to the profile, and a hardware test checks the installed file.
- **`tvgw-apply`** builds the firewall from `/etc/tvgw/tvgw.conf`, `block4.txt` and `doh4.txt`. It is fail-closed: one apply at a time, the ruleset loaded atomically first, forwarding switched on last. See [../deploy/nftables/README.md](../deploy/nftables/README.md).

## The data plane

```
 tcpdump  -> /var/lib/tvgw/pcap/tv-YYYYMMDDTHHMMSSZ.pcap (UTC, hourly) -tshark as nobody-+
 conntrack DESTROY -> /var/log/tvgw/flows.log -------------------------------------------+
 AdGuard -> /opt/AdGuardHome/data/querylog.json ------------------------------------------+--> tvgw ingest
 nginx -> /var/log/tvgw/gfts.log ---------------------------------------------------------+    (hourly, :20)
 tvgw tvcheck (LG LAN API) -> tvcheck.txt, tvcheck-history.log ---------------------------+        |
 kernel log "tvgw-oddport:" (journalctl) -------------------------------------------------+        v
 nginx.conf regex, block4.txt, AdGuard user_rules (rule history) -------------------------+   tvgw.db
                                                                                                 |
 tvgw verify --record (every 10 min) -> verify, fw_counters ------------------------------------>+
                                                                                                 |
                       tvgw brief / report / new-hosts / host / sql ... <------------------------+
                       tvgw-analyze -> reports/latest, daily/<day>, weekly/<week>
```

**Capture.** tcpdump on `eth0` keeps frames the TV sends and nothing it receives: TCP SYN, FIN and RST, the TV's requests to port 80 whole, UDP except QUIC short headers, a TCP segment only when it begins a TLS ClientHello record, and any segment that begins with an HTTP method (LG's firmware fallback on TCP 8080). No response body and no ciphertext. The two filter terms that index into the payload come last: a BPF load past the end of a short segment ends the whole program as "no match", so the flag, port and UDP terms must have had their say first (`tests/unit/test_capture_filter.py` runs the deployed expression through tcpdump on a synthetic hour). tcpdump starts a new file every hour, named in UTC with seconds so no two files can share a name. `tvgw prune-pcaps` (hourly, `tvgw-prune.timer`) deletes files ingest has read once they are older than `PCAP_DAYS`, then the oldest read files while the directory is over `PCAP_MAX_GB` or the filesystem has under 1 GB free. It never deletes the file tcpdump holds open, and it keeps a file ingest has not read, with a warning, until twice `PCAP_DAYS`: evidence goes only after it is in the store, or after a week of saying that it is not. Pcaps are written `640 root:nogroup` so the unprivileged tshark can read them and nobody else can.

**Flows.** `conntrack -E -e DESTROY` prints one line per finished TV connection, with packets and bytes each way. tvgw-apply sets the established-TCP timeout to 2 h 04 min, so an idle connection is reported within hours rather than days. When its netlink socket overflows under load, conntrack drops events, says so on stderr (`We have hit ENOBUFS! We are losing events.`), which reaches the unit's journal and not `flows.log`, and carries on; ingest reads those lines from the journal and warns, since the connections that ended then are missing from a log that reads as whole.

**Ingest** (`tvgw ingest`, `src/tvgw/ingest.py`) is incremental and idempotent:

- Growing logs are read from a stored cursor (inode and byte offset per source in `ingest_state`), in batches of 10 000 lines, each committed together with the cursor that covers it: rows and cursor land as one, a run that dies loses only the batch in flight, and a backlog (the 90-day query log after a lost store) neither fills memory nor holds the write lock for the whole run. Rotation by `copytruncate` or by rename is handled, a copytruncate after a read that found the log empty included; lines written just before a rotation are read from `path.1`, and a log renamed away whose successor does not exist yet (AdGuard creates the new query log only at its next write to disk) is read from `path.1` too, not reported missing. A partial last line waits for the next run. The AdGuard cursor's key is `adguard`, not `dns`, for historical reasons: renaming it would re-read the whole query log.
- The sources are read cheapest first: flows, dns, gfts, tvstate, oddport, rules, then the pcaps, within a budget of 20 minutes of tshark per run (`PCAP_BUDGET`); files past it wait for the next run with a warning, so a backlog of slow files cannot starve the `hosts` refresh, pruning and the run's bookkeeping before the unit's 45-minute timeout. tshark reads request lines and headers only (`http.desegment_body:FALSE`), never holding request bodies for reassembly.
- Each finished pcap is read once, in one tshark pass, and recorded in `pcaps_done`. A file is finished when no tcpdump process holds it open (read from `/proc` by `pcaps.live_files`, after the directory is listed, so a file tcpdump opens in between waits for the next run instead of being read empty); if tcpdump is down every file is finished, and when the answer cannot be had (no `/proc`, not root) the pcaps are skipped with a warning rather than guessed at, and not stamped as read. tshark exits 2 both for a file cut short mid-packet, which is normal, and for a file it cannot open. Only the first counts as success, and only when tshark's error text says "cut short". Otherwise the pcap is retried on every run, its failures counted at most once per clock hour, and after 24 of them, a day however often ingest runs (a deploy runs it two or three times), it is recorded as unreadable with its error (`pcaps_done.error`, `attempts`); one warning per run covers every file that failed in it. A finished file shorter than a pcap header is recorded as "not a capture file" without running tshark. A file with 20 or more connection attempts to :443 and not one ClientHello raises a warning: an extraction fault looks exactly like a quiet hour otherwise (the 2026-10-27 incident).
- Each source is its own transaction. A failing source becomes a warning in the brief, not a lost hour, and does not roll back the others. A source whose input does not exist (a log, the pcap directory) is a warning too, and neither kind is stamped as read, nor are the pcaps in a run that could read none of the pending files (every one failed, or the live file could not be told), so Coverage calls it `NOT ASSESSED` rather than an empty hour; the TV-state history is the exception, since it exists only for profiles with a LAN-API reader. The flow and URL-filter logs are machine-written in one format each, so lines they cannot parse are counted and reported like malformed query-log records.
- Then the `hosts` table is refreshed and rows older than `DB_DAYS` are pruned. Every 30 days the file's free space is checked and the file is vacuumed when at least a quarter of it is free: steady-state churn reuses freed pages, and only a lowered `DB_DAYS` or a hand deletion leaves a file worth rewriting under an exclusive lock. The check is recorded before the `VACUUM` runs, so one that fails on a full card is not retried every hour.

**Reports.** Everything is computed from the store at query time. `tvgw brief DAY` is one calendar day. `tvgw report` takes `--day`, `--week YYYY-Www`, or `--since/--until`, and defaults to the last 24 hours. `tvgw-analyze` writes the text and JSON reports from it. Brief sections and red lines are listed in the [README](../README.md#the-daily-brief).

**Verify.** `tvgw verify` checks the firewall, routing, resolver and services, and with `--record` stores the verdict and a snapshot of every firewall counter. The brief turns those snapshots into "packets stopped per rule". See [operations.md](operations.md#what-tvgw-verify-checks).

## The data model

One SQLite file, `/var/lib/tvgw/tvgw.db`, schema version 7 (`src/tvgw/db.py`). It uses the rollback journal, not WAL, so unprivileged readers need only read access to the one file. The schema is idempotent and applied by every writer on open.

| Table | Purpose | Key columns |
|---|---|---|
| `flows` | One finished TV connection, from conntrack. | `t_start`, `t_end`, `proto`, `dst`, `dport`, `sport`, `pkts_up`, `bytes_up`, `pkts_down`, `bytes_down`, `state`, `timeout_left` (seconds left on the entry's timer when the kernel destroyed it early; NULL when it expired) |
| `dns` | One TV query, from AdGuard's query log. | `t`, `qname`, `qtype`, `answers` (`A:1.2.3.4,CNAME:x`), `blocked`, `reason`, `rule`, `filter_id`, `upstream`, `cached`, `elapsed_ms` |
| `tls` | One TLS ClientHello from the TV, from the pcaps. | `t`, `dst`, `dport`, `sport`, `sni` |
| `http` | One plain-HTTP request. `src` is `pcap` for requests to the internet (from the capture) and `gfts` for requests to the gateway (nginx's log, which also has `status` and `bytes`; `method` is NULL for lines written before the log format carried it, 2026-10-27). The log line also says whether nginx or the real host produced the status, which is how the filter's own 403 is told from LG's. A request to the gateway is never stored from the pcap as well. | `t`, `host`, `method`, `uri` (first 2000 chars), `ua` (first 300), `status`, `bytes`, `src` |
| `lanprobe` | A TCP connection attempt from the TV to a private, multicast or link-local address other than the gateway. A retransmitted SYN (same source port, address and port) is the same attempt. | `t`, `dst`, `proto`, `dport` |
| `oddport` | A kernel log line from the unexpected-port rule. | `t`, `proto`, `dst`, `dport`, `raw` |
| `tvstate` | The hourly power reading and foreground app, from the tab-separated `tvcheck-history.log` line (webOS states such as `Active Standby` contain spaces). `unreachable` when the TV did not answer, `unknown` when it answered but the power read failed; the brief counts anything but `Active` as off. | `t` (key), `power`, `app` |
| `tvsettings` | A TV setting, stored only when its value changes. A read error (`ERR ...` from the LAN API) is not a value and is not stored. | `t`, `key`, `value` |
| `hosts` | One row per public name seen in `dns`, `tls` or `http`. | `name` (key), `first_seen`, `last_seen`, `category`, `dns_n`, `tls_n`, `http_n`, `last_blocked`, `last_rule`, `notes` |
| `rules` | Policy history: AdGuard user rules, the nginx block regex, `block4.txt` entries (read with `tvgw-apply`'s own pattern, so only what the firewall loads). | `kind` (`adguard`, `gfts-block`, `block4`), `text`, `first_seen`, `last_seen`, `removed_at` |
| `verify` | One `tvgw verify --record` run. | `t` (key), `ok`, `failures` (JSON list) |
| `fw_counters` | A snapshot of every commented firewall counter. | `t`, `rule` (the rule's comment), `packets`, `bytes` |
| `pcaps_done` | One row per finished pcap: read (`error` NULL) or failed `attempts` times and why. `syn443_rows` is the TV's connection attempts to :443, the denominator its hellos are judged against. | `name` (key), `done_at`, `tls_rows`, `http_rows`, `syn443_rows`, `error`, `attempts` |
| `ingest_state` | Read cursors: per log its inode, byte offset, first 64 bytes (`head`) and the inode of its `.1` (`rotated`, which is how a copytruncate after a read that found the log empty is seen). `last_t` is the time of the read for the tail sources, the newest event time for `oddport` and `gate`, and for `flowlog` the time the flow log's journal was last checked for lost events. | `source` (key), `inode`, `offset`, `last_t`, `head`, `rotated` |
| `ingest_runs` | One row per ingest run: how long it took, its counters and its warnings. A report's Coverage lists the warnings of the runs that fed its window (the runs inside it and the two hours after), so yesterday's brief does not carry this morning's problems. | `t` (key), `seconds`, `stats` (JSON), `warnings` (JSON list) |
| `meta` | Bookkeeping. | keys `schema`, `hosts_wm`, `hosts_profile`, `sources_read`, `last_run`, `last_warnings` (the last run's, for the hardware suite), `last_vacuum` |

A view, `v_ip_names`, lists which TLS names were seen on which address.

Two details matter when you read or write queries:

- **`hosts` counters advance by row id.** `meta.hosts_wm` holds, per source table, the highest row id already counted and that row's time. Each run counts only rows above it, so a row is counted exactly once however late it arrives. Without a watermark, or when the watermark row is gone or re-stamped (SQLite reuses row ids once a table empties, so the ids below it may be new rows), the table is rebuilt from the base tables and the counters then mean the rows the store still holds; rows with a `notes` value are kept through a rebuild. Categories are recomputed for every name whenever the profile's rules change (`meta.hosts_profile` is a fingerprint of the rules and prefixes the categorizer uses), so a profile change shows up without waiting for the name to be seen again. No command writes `notes`.
- **Pruning** covers `flows`, `dns`, `tls`, `http`, `lanprobe`, `oddport`, `verify`, `fw_counters` (the counters alone would grow by a million rows a year) and `ingest_runs`. `tvstate`, `tvsettings`, `hosts` and `rules` grow slowly and are not pruned. A `pcaps_done` mark older than 7 days goes only once its file is gone, or the file would be ingested twice, and none goes while the pcap directory itself is missing.

Retention and access, from the privacy side: [privacy-and-retention.md](privacy-and-retention.md).

## Naming a connection

A CDN address serves hundreds of names, so the destination address alone says little. tvgw names each flow by its own TLS hello: the `tls` row with the same `dst`, `dport` and TV source port (`sport`), whose time falls inside the flow's lifetime. If several match, the latest wins.

The lifetime has a slack at the start. `t_start` is derived from conntrack's delta-time and can run up to about a minute late, so a hello may precede it; `FLOW_SLACK` in `queries.py` allows 300 seconds. `t_end` is when the entry expired, one idle timeout after the last packet (120 s after a normal close, 7440 s for an established connection that went quiet; see `conntrack.py`), or, for an entry the kernel destroyed before its timer ran out (a reused tuple, a flush), the moment it did, with the seconds it had left in `timeout_left`; so a report that buckets by `t_end` credits a connection to the hour it expired. The join is `queries.FLOW_NAME`, and the `tls(dst, sport, t)` index makes it cheap.

Names are computed when a report runs, not stored. A flow whose pcap has not been ingested yet appears under `Unresolved` in the category table until the next ingest, and a later report names it.

The "Unresolved flows" section of the brief is stricter. It lists TCP destinations with no TLS hello to that address at all and no A answer naming it in the window or the day before: hardcoded addresses or a DNS bypass.

## Cadences

| When | What | Why that often |
|---|---|---|
| Continuously | tcpdump, conntrack, AdGuard's query log, nginx logs, the kernel's `tvgw-oddport` lines (at most 6 a minute) | Evidence is written as it happens. |
| Every 10 minutes (3 min after boot) | `tvgw verify --record` | Firewall counters reset on every apply. The brief sums the positive steps between snapshots, and `tvgw-apply`'s listings either side of each reload are stored as snapshots of their own, so a reset costs nothing unless a second apply follows within the same interval; counters of rules sharing a comment are summed into one series, and snapshots are compared in the order they were taken, not by the clock. A failed check shows within 10 minutes. |
| Hourly at :20 | `tvgw-analyze`: `tvgw tvcheck` (LG only), `tvgw ingest`, reports | tcpdump rotates a pcap 3600 s after the file opened, and only when the next packet arrives, so TLS names and plain HTTP arrive up to about two hours late; conntrack reports an idle connection 2 h 04 min after its last packet. Finished days and weeks are therefore written from 03:20, not 00:20. Counters are fresher; DNS is not: AdGuard Home keeps its query log in memory and writes it to `querylog.json` only when `querylog.size_memory` lookups (1000 by default, every client together) have built up or the service stops, so on a quiet evening the TV's lookups can reach the store hours after they were made, and a daily file or analyst pack written before that write lacks them. A file still open when the TV goes quiet for the night closes with the next morning's first packet, so the archived daily file can list those last flows as Unresolved; `tvgw brief DAY` recomputes from the store. |
| Hourly | `tvgw prune-pcaps` | Keeps the pcap directory under its age and size limits, deleting only what the store has read. |
| Daily, random delay up to 1 h | `tvgw-doh-update`, then `tvgw-apply` | The DoH resolver list changes slowly. |
| On link changes | NetworkManager dispatcher runs `tvgw-apply` | Table 100's route vanishes when the uplink drops. |

## Trust boundaries

| Component | Runs as | Can touch |
|---|---|---|
| `tvgw-apply`, `tvgw.service`, the dispatcher, `tvgw-doh-update` | root | The kernel's firewall, sysctls and routes. |
| tcpdump (`tvgw-pcap`) | `tvgw-pcap:nogroup` holding `CAP_NET_RAW` and `CAP_NET_ADMIN` only, read-only system, its own directory writable | Raw TV packets into the hourly pcaps. Never root. |
| conntrack (`tvgw-flowlog`) | root | Connection events for the TV's address. It writes `flows.log`. |
| tcpdump + nft (`tvgw-dnsgate`) | root, bounded to `CAP_NET_RAW` and `CAP_NET_ADMIN`, read-only system | Reads the resolver's answers to the TV and adds their addresses to `inet tvgw_gate resolved4`. Writes nothing to disk. |
| `tvgw-analyze` (tvcheck, ingest, reports) | root, sandboxed: read-only system, writable only `/var/lib/tvgw`, `/var/log/tvgw`, `/run/lock` | Reads every log; writes the store and reports. |
| tshark | `nobody:nogroup` inside a transient systemd unit (`systemd-run`): no network, a read-only system, no devices, no new privileges or capabilities, the service syscall set, 512 MB and the extract timeout as limits; when started as root | Parses packets from the TV and the internet. It can read the pcaps through the `nogroup` group and nothing else in the state directory. If `setpriv` is missing the pcaps are not read and ingest warns, rather than run tshark as root. |
| `tvgw verify --record` | root | Reads the firewall and resolver; writes `verify` and `fw_counters`. |
| `tvgw adguard apply` | root | Stops and starts AdGuard Home and rewrites its YAML. |
| Read-only CLI (`brief`, `report`, `host`, `sql` ...) | any member of `adm` | Opens the store `mode=ro`; `sql` also sets `query_only`. |
| The TV | untrusted | DHCP, DNS, ports 80 and 443 and pings on `10.10.10.1`. Nothing else on the Pi, nothing on the home LAN. |

Who can read what:

- `/var/lib/tvgw` is `2751 root:adm`. Others may traverse it, which tshark needs, but not list it.
- The store is `640 root:adm`. The reports directory is `2750 root:adm`.
- `/var/lib/tvgw/pcap` is `2750 tvgw-pcap:nogroup` (tcpdump runs as the system user `tvgw-pcap`), and each pcap is `640 tvgw-pcap:nogroup`: readable by the extractor, writable by nothing that parses packets.
- `/var/log/tvgw` is `2750 root:adm`, and the logs are `640 root:adm` (set by `install.sh`).
- The LG pairing key `lgtv-keys.sqlite` is `600`. It can control the TV.

Text that came from the TV or from servers it talks to (names, URIs, user agents, the TV's device name) is escaped before it reaches a terminal: `cli.clean` and `lgwebos.clean`.

Known gaps are listed in [privacy-and-retention.md](privacy-and-retention.md#who-can-read-it).
