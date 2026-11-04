# Capture

This page owns the packet capture: the hourly dumpcap ring, the two capture modes `CAPTURE_MODE` chooses between, how the ingest tells a finished file from the one being written, how to move between the modes, and what has to be measured on the gateway before the headers mode can become the default. It is for the owner running the gateway and for whoever changes the capture. What the full capture keeps, frame class by frame class, is in [what the capture keeps](privacy-and-retention.md#what-the-capture-keeps); the units' sandboxes are in [the units](../../deploy/systemd/README.md#units).

Capture v2 implements two rows of the October 2026 survey ([state of the art, section 1.2](../research/state-of-the-art-2026-10.md#12-verdicts)): dumpcap in place of tcpdump (ADOPT NOW) and position-based capture (PROTOTYPE), which is its top recommendation 5. The choices are [design decision 38](../design-decisions.md#38-dumpcap-writes-the-hourly-ring) and [design decision 39](../design-decisions.md#39-the-first-packets-of-each-connection-behind-a-switch).

## The two modes

`CAPTURE_MODE` in `/etc/tvgw/tvgw.conf` picks one of two capture units. Missing or empty, it is `full`, which is what the gateway did before capture v2, with dumpcap in tcpdump's place.

| | `full` (the default) | `headers` (the prototype) |
|---|---|---|
| Unit | `tvgw-pcap.service` | `tvgw-pcap-headers.service` |
| What picks the packets | A BPF filter on `eth0`, by byte patterns: connection flags, requests to port 80, UDP except QUIC short headers, segments that begin a ClientHello or an HTTP request | The firewall, by position: the first 8 packets the TV sends on each connection, plus every packet it sends to TCP port 80 after them |
| Where | `eth0`, as the frame arrives | `inet tvgw_capture`, prerouting, after conntrack and before the DNAT and the rejects |
| A ClientHello split over segments | Only the segment that starts the record is kept; the server name can be lost | Every segment is kept, so tshark reassembles the hello |
| Bytes kept per connection | Unbounded in principle (every port-80 segment, every UDP datagram) | At most 8 packets of 4096 bytes, plus port 80 |
| TV-sent ciphertext | None, except a chance match | The first few records after the hello (ChangeCipherSpec, Finished, the first application data) when they fall in the first 8 packets |
| File names | `tv_<YYYYmmddHHMMSS>_<nnnnn>.pcap` | `tvhdr_<YYYYmmddHHMMSS>_<nnnnn>.pcap` |
| Link type | Ethernet (1) | NFLOG (239) |

Both units write the same directory, `/var/lib/tvgw/pcap`, as the same user with the same sandbox, and the ingest, retention and `tvgw verify` treat their files alike. Exactly one runs.

## The ring: dumpcap in place of tcpdump

`tvgw-pcap.service` runs:

```
/usr/bin/dumpcap -i ${TV_IF} -q -P -g -s 0 -b interval:3600 -b nametimenum:2 -w /var/lib/tvgw/pcap/tv.pcap -f "<the capture filter>"
```

| Option | Why |
|---|---|
| `-i ${TV_IF}` | The TV's cable: `TV_IF` (`eth0` by default), which systemd fills in from the drop-in `tvgw-pcap.service.d/tv-side.conf` that `install.sh` writes, as it does `${TV_NET}` and `${GW_IP}` in the filter ([the TV side](../reference/settings.md#the-tv-side)). |
| `-q` | No running packet count in the journal. |
| `-P` | pcap, not pcapng: the files are what tcpdump wrote, so the ingest's `.pcap` glob, its 24-byte header check, tshark and the hardware suite read them unchanged. dumpcap's `-n` means pcapng, so it is never passed. |
| `-g` | Group read. Without it dumpcap creates each ring file `0600`, which the extractor, running as `nobody:nogroup`, cannot read: the 2026-10-27 incident again. With the unit's `UMask=0027` the files are `640 tvgw-pcap:nogroup`. |
| `-s 0` | Whole frames, as before: requests to port 80 are kept whole. |
| `-b interval:3600` | A new file whenever the clock reaches an exact multiple of 3600 seconds, so each file covers one clock hour (the first after a start covers the rest of its hour). The check runs in dumpcap's main loop, not on a packet, so a file closes on time with the TV off. tcpdump's `-G 3600` rotated 3600 seconds after its own start, and only when the next packet arrived (data-architecture finding 6). |
| `-b nametimenum:2` | The time before the number in the name. dumpcap numbers files from `00001` at every start, so with the number first a restart would sort its files before the older ones. |
| `-w .../tv.pcap` | The name template: dumpcap splits it at the last dot and writes `tv_20261101120000_00002.pcap`. The stamp is the local time the file was opened, and the unit sets `TZ=UTC`, so it is UTC. |
| `-f "..."` | The capture filter, one argument, unchanged from tcpdump: libpcap compiles it the same way. `tests/unit/test_capture_filter.py` still runs it on a synthetic hour. |

There is no `-b files:`, so dumpcap never deletes a file; retention stays with `tvgw prune-pcaps`, which deletes only what the store has read.

An hour with nothing from the TV is now a 24-byte file, a pcap header and no frames, where tcpdump wrote no file. The ingest reads it like any other: tshark finds no rows and the store marks it read.

### Which file is live

The ingest must never read a file dumpcap still holds open: it would record part of an hour as the whole of it. `pcaps.live_files()` lists the open descriptors of every process named in `pcaps.WRITERS` (`dumpcap`, and `tcpdump` for the deploy that switches and for a gateway rolled back to an older checkout) and returns the `.pcap` files in the directory they hold. A reader such as tshark is not a writer and is not asked. When the descriptors cannot be listed (not root, no `/proc`), the answer is unknown and nothing is read or deleted.

dumpcap closes the hour's file before it opens the next one, so for a moment it holds no file. The ingest lists the directory first and asks `/proc` second. A rotation between the two either leaves the new file unlisted (it opened after the listing) or held (it opened before `/proc` was read); either way the closed file is read and the new one waits for the next run. `tests/unit/test_capture.py` runs both orders.

### What dumpcap needs

dumpcap comes with the Debian package `wireshark-common`, which `tshark` depends on, so a gateway with tshark has it. The unit runs it as `tvgw-pcap` with `CAP_NET_RAW` and `CAP_NET_ADMIN` as ambient capabilities and `NoNewPrivileges=yes`, as tcpdump ran.

The package asks at install time whether non-superusers may capture. Answered No (the default, and what an unattended install gets), dumpcap is `0755 root:root` and the unit's capabilities are all it needs. Answered Yes, the package creates the group `wireshark` and makes dumpcap `0754 root:wireshark` with file capabilities (`4754`, setuid, where `setcap` is missing), and `tvgw-pcap`, not in that group, cannot execute it. Either reconfigure the package and answer No:

```
sudo dpkg-reconfigure wireshark-common
```

or add the capture user to the group (systemd applies a `User=`'s supplementary groups):

```
sudo usermod -aG wireshark tvgw-pcap && sudo systemctl restart tvgw-pcap
```

To answer No before the package is installed, as an unattended install should, preseed the question:

```
echo 'wireshark-common wireshark-common/install-setuid boolean false' | sudo debconf-set-selections
```

To check a gateway before a deploy replaces its capture, run `sudo -u tvgw-pcap test -x /usr/bin/dumpcap && stat -c '%a %U:%G' /usr/bin/dumpcap`: it should print `755 root:root`.

A missing or unusable dumpcap fails the start, before dumpcap runs, with `tvgw-pcap: /usr/bin/dumpcap is missing or not executable by tvgw-pcap: install wireshark-common ...` in `journalctl -u tvgw-pcap`.

## The headers mode

### The firewall rule

With `CAPTURE_MODE=headers`, `tvgw-apply` loads a table of its own after the filter:

```
table inet tvgw_capture {
	chain pre {
		type filter hook prerouting priority mangle - 5; policy accept;
		iifname "eth0" ip saddr 10.10.10.0/24 ip saddr != 10.10.10.1 ct original packets != 0 ct original packets <= 8 counter log group 7 snaplen 4096 queue-threshold 1 comment "capture: the first packets of each TV connection"
		iifname "eth0" ip saddr 10.10.10.0/24 ip saddr != 10.10.10.1 tcp dport 80 ct original packets > 8 counter log group 7 queue-threshold 1 comment "capture: plain HTTP after them"
	}
}
```

- **It cannot change a verdict.** The chain's policy is accept and its two rules only count and log, so the worst a mistake here can do is lose evidence. The table is separate from `inet tvgw`, so `tvgw verify`'s baseline comparison never sees it, and a failure to load it (`nfnetlink_log` missing, an old kernel) prints `tvgw: capture table not loaded; tvgw-pcap-headers records nothing` and leaves the TV forwarded. With `CAPTURE_MODE=full` the script deletes the table.
- **Where it hooks.** Prerouting at `mangle - 5` (-155) runs after conntrack (-200) has counted the packet and before the DNS redirect (`dstnat - 10`) and every reject in `tv_out`. It sees what the TV sent, to the address it sent it to, attempts the filter refuses included: what tcpdump on `eth0` saw.
- **The count.** `ct original packets` is conntrack's count of packets in the direction the connection was opened, the current one included, so the first packet reads 1. It needs `nf_conntrack_acct=1`, which `tvgw-apply` sets before it loads anything. A connection older than that switch has no counter, which reads 0; `!= 0` keeps such a connection from matching every packet.
- **The size bound.** `snaplen 4096` caps the bytes handed over per packet. A packet is a received buffer after the NIC's receive offload (GRO), which merges consecutive segments of a flow, so a ClientHello split over two or three segments can arrive as one packet of about 3 KB. 4096 bytes keeps such a hello whole; 1600 would cut it. The bound per connection is 8 times 4096 bytes, plus NFLOG's own headers.
- **Plain HTTP.** The second rule keeps every packet to TCP port 80 after the first 8, without a size cap, as the full capture keeps port 80 whole: a request on a long keep-alive connection is still seen. The two rules never match the same packet.
- **One packet at a time.** `queue-threshold 1` makes `nfnetlink_log` send each packet as it is logged. By default it batches up to 100 packets or one second, and a reader that stamps a packet when it receives it would then give a SYN or a hello a time up to a second late, which moves it against the flow the ingest joins it to. Step 5 of [the measurements](#measuring-it-on-the-pi) checks the times.
- **One reader.** NFLOG group 7 is read by `tvgw-pcap-headers` alone; a second process cannot subscribe to the same group. `CAPTURE_GROUP` in `tvgw-apply` and the unit's `nflog:7` are checked equal by `tests/unit/test_capture.py`.

`tvgw-pcap-headers.service` runs `dumpcap -i nflog:7 -q -P -g -s 0 -b interval:3600 -b nametimenum:2 -w /var/lib/tvgw/pcap/tvhdr.pcap`, with no BPF filter: the rule already chose the packets, and libpcap would run a filter on an NFLOG source in userspace.

### One switch for two units

`install.sh` enables, starts and restarts `tvgw-pcap` only. `tvgw-pcap` has `Wants=tvgw-pcap-headers.service`, so starting it starts the headers unit too, and the headers unit has `PartOf=tvgw-pcap.service`, so stopping or restarting `tvgw-pcap` stops or restarts it. The headers unit has no `[Install]` section: it is never enabled on its own.

Each unit has an `ExecCondition` that reads `CAPTURE_MODE` from the settings file and lets exactly one of them run:

| `CAPTURE_MODE` | `tvgw-pcap` | `tvgw-pcap-headers` |
|---|---|---|
| missing, empty or `full` | runs | skipped |
| `headers` | skipped | runs |
| anything else, or a settings file the shell cannot source | fails | fails |

A skipped unit is inactive, not failed, and `Restart=always` leaves it alone. A failed one shows in `systemctl --failed` and in `tvgw verify`. The condition runs as root (the `+` prefix) because the settings file is `640 root:adm`; the capture itself never does. `tvgw-apply` and `config.load` refuse the same near misses (`Headers`, `both`).

### What it gains and what it loses

Stated from the code; the sizes and the recall are for the gateway to measure (below).

Gains:

- A ClientHello is kept whole however it is segmented, so a post-quantum hello whose server name lands in the second segment is named ([state of the art, section 1.1](../research/state-of-the-art-2026-10.md#11-findings)). tshark reassembles TCP by default.
- The bytes kept per connection are bounded by the rule rather than by a byte pattern, so the privacy page's bound holds by construction.

Losses, against the full capture:

- Connection flags after the eighth packet: the FIN or RST of a long connection is not kept. The ingest reads only SYNs from the pcaps; when a connection ended comes from the flow log.
- DNS questions after the eighth on one flow. webOS keeps one UDP source port for its resolver all day, which conntrack treats as one connection, so most of the day's questions are not in the pcaps. The store's DNS rows come from AdGuard's query log and do not change; the pcap's copy of where the TV aimed each question is what goes. The DNS redirect's counter still counts them.
- UDP to unexpected ports, and HTTP requests on ports other than 80, after the eighth packet of their flow.
- Some ciphertext: the TV's first records after its hello, when they fall within the first 8 packets. It is encrypted and nothing reads it, but the full capture's "no ciphertext" no longer holds.
- Drop accounting. libpcap counts the packets the netlink socket could not take (ENOBUFS) as drops, and pcap files have nowhere to record them; dumpcap prints the count only when it stops. The rule's counter, which `tvgw verify --record` stores, gives the packets handed over, and the frames in the files give the packets kept.

Unchanged: the files are pcap, and tshark reads link type NFLOG natively. A pure-Python extractor that replaces tshark must unwrap NFLOG's TLVs (type 9 holds the packet) as well as Ethernet.

Not expected: that the headers files are smaller. The full capture keeps a few hundred bytes to two kilobytes per TLS connection (a SYN, the hello's first segment, a FIN); the headers capture keeps the whole hello and several packets after it. The headers mode buys completeness and a bound, and the gateway decides what it costs.

## Measuring it on the Pi

The prototype becomes a candidate for the default only with these five numbers, taken over at least one full viewing day. Every command runs on the gateway as root.

1. **Size per hour.** For each mode, the bytes per file, which `pcaps_done` names by prefix:

   ```
   ls -l /var/lib/tvgw/pcap/tv_*.pcap /var/lib/tvgw/pcap/tvhdr_*.pcap
   ```

2. **Hello recall.** Run a shadow full capture beside the headers mode for a day; an `eth0` capture does not need the firewall, so it can run while `tvgw-pcap-headers` reads NFLOG. It writes to a scratch directory the ingest never reads, and stops by itself after 24 hours:

   ```
   FILTER=$(/opt/tvgw-venv/bin/python -c 'import shlex; t = open("/etc/systemd/system/tvgw-pcap.service", encoding="utf-8").read().replace("\\\n", " "); (line,) = [x for x in t.splitlines() if x.startswith("ExecStart=")]; a = shlex.split(line[len("ExecStart="):]); print(a[a.index("-f") + 1])')
   sudo install -d -o tvgw-pcap -g nogroup -m 750 /var/tmp/tvgw-shadow
   sudo systemd-run --unit=tvgw-shadow -p User=tvgw-pcap -p Group=nogroup \
     -p AmbientCapabilities="CAP_NET_RAW CAP_NET_ADMIN" -p UMask=0027 -p Environment=TZ=UTC \
     /usr/bin/dumpcap -i eth0 -q -P -g -s 0 -a duration:86400 -b interval:3600 -b nametimenum:2 \
     -w /var/tmp/tvgw-shadow/tv.pcap -f "$FILTER"
   ```

   Then compare the server names each capture saw over the same hours:

   ```
   names() { for f in "$@"; do tshark -r "$f" -n -Y 'tls.handshake.type == 1' -T fields -e tls.handshake.extensions_server_name; done | sort -u; }
   names /var/tmp/tvgw-shadow/tv_*.pcap >/tmp/full.txt
   names /var/lib/tvgw/pcap/tvhdr_*.pcap >/tmp/headers.txt   # the same hours
   comm -23 /tmp/full.txt /tmp/headers.txt   # names only the full capture saw: should be empty
   comm -13 /tmp/full.txt /tmp/headers.txt   # names only the headers capture saw: the split hellos it recovered
   ```

   The store's own measure, per file: hellos per connection attempt to port 443.

   ```
   sqlite3 /var/lib/tvgw/tvgw.db "SELECT substr(name,1,instr(name,'_')-1) AS mode, COUNT(*), SUM(tls_rows), SUM(syn443_rows) FROM pcaps_done WHERE error IS NULL GROUP BY mode"
   ```

3. **Drops.** The rule's counter against the frames kept, for the same hours: `tvgw verify --record` stores the counter every 10 minutes as `capture: the first packets of each TV connection`, and `capinfos -c /var/lib/tvgw/pcap/tvhdr_*.pcap` counts the frames. `journalctl -u tvgw-pcap-headers` shows dumpcap's drop count each time it stops.
4. **Offload.** Whether receive offload merges segments on this NIC, and whether 4096 bytes was ever too few: `ethtool -k eth0 | grep receive-offload`, and `tshark -r <file> -Y 'frame.cap_len < frame.len' | wc -l` for packets the snaplen cut.
5. **Timestamps.** The rules send each packet to NFLOG at once (`queue-threshold 1`), so the time dumpcap writes should be the kernel's. Compare the two in one headers file; the difference should stay in the milliseconds, where the ingest's join to flows has `FLOW_SLACK` seconds to spare:

   ```
   tshark -r /var/lib/tvgw/pcap/tvhdr_<hour>_00001.pcap -n -T fields -e frame.time_epoch -e nflog.timestamp | awk 'NF == 2 { d = $1 - $2; if (d < 0) d = -d; if (d > m) m = d } END { print "largest difference:", m + 0, "s" }'
   ```

   If `nflog.timestamp` is empty, the kernel sent none for those packets and the frame time is the reader's: then the difference cannot be measured this way, and a second's lateness is possible.

The shadow capture stops after a day; `sudo systemctl stop tvgw-shadow && sudo rm -rf /var/tmp/tvgw-shadow` ends it early and removes its files.

## Switching modes

The default leaves a running gateway as it was, with one change: the deploy that brings capture v2 replaces tcpdump with dumpcap. `install.sh` restarts `tvgw-pcap` because its unit file changed; tcpdump closes its last file, which the ingest reads and retention prunes like any other, and dumpcap's first file runs to the next full hour. Old and new names sort in time order (`tv-` before `tv_`). No firewall rule changes: with `CAPTURE_MODE` unset, `tvgw-apply` only deletes a capture table that is not there. Before that deploy, check that dumpcap is usable by the capture user:

```
sudo -u tvgw-pcap test -x /usr/bin/dumpcap && echo usable
```

To try the headers mode (a firewall change: the owner's call, per data-architecture open question 3):

1. Set `CAPTURE_MODE=headers` in `/etc/tvgw/tvgw.conf`.
2. `sudo tvgw-apply`, which loads `inet tvgw_capture`.
3. `sudo systemctl restart tvgw-pcap`, which skips `tvgw-pcap` and starts `tvgw-pcap-headers`.
4. `sudo tvgw verify`: `services` and `capture` must be `OK`.

To go back, set `CAPTURE_MODE=full` (or delete the line), then the same three commands. A deploy does the same: `install.sh` runs `tvgw-apply`, then restarts `tvgw-pcap` when the `CAPTURE_MODE` line, either capture unit or the TV side changed since its last restart ([what install.sh does](../../deploy/README.md#what-installsh-does)).

## Checking it

`tvgw verify` reads the mode from the settings file:

- `services` expects the unit the mode names (`verify.CAPTURE_UNITS`) to be active. In headers mode, `tvgw-pcap` being inactive is right.
- `capture` fails when the other unit is active as well, which happens when the setting changed and only one unit was started: two captures write the same directory and every hello is counted twice. In headers mode it also fails when `inet tvgw_capture` has no capture rule, since the unit then writes empty hours. Its detail is `full: tvgw-pcap on eth0` or `headers: tvgw-pcap-headers on nflog:7`.
- `applied_current` fails when `CAPTURE_MODE` was edited and `tvgw-apply` not run.

The hardware suite checks that the capture unit the mode names is active and is dumpcap, that the other is not, that the capture holds at most one file open, and that the capture table is loaded in headers mode only ([the hardware tests](../../tests/hardware/README.md)).

## Files

| File | What it holds |
|---|---|
| `deploy/systemd/tvgw-pcap.service` | The full capture, its condition and its dumpcap check. |
| `deploy/systemd/tvgw-pcap-headers.service` | The headers capture. |
| `deploy/nftables/tvgw-apply` | `CAPTURE_MODE`'s check, and the `inet tvgw_capture` block between `# ---- (capture) begin` and `# ---- (capture) end ----`. |
| `src/tvgw/pcaps.py` | `WRITERS`, `live_files()`, `finished()` and retention. |
| `src/tvgw/ingest.py` | `ingest_pcaps()`: list, ask `/proc`, read what is finished. |
| `src/tvgw/verify.py` | `CAPTURE_UNITS`, `CAPTURE_RULE` and `capture_check()`. |
| `tests/unit/test_capture.py` | The conditions run with `sh` and `dash`, the dumpcap check, the units side by side, the rule's text, verify's checks and a dumpcap ring through the ingest. |
