# Deep dive 6: the platform, one layer deeper

*Proposal, 2026-11-01. Nothing here is built. It reads the research worktree at head `43b3bd9`: `deploy/nftables/tvgw-apply`, `deploy/systemd/*.service`, `src/tvgw/dnsgate.py`, `src/tvgw/ingest.py` and `src/tvgw/adguardcfg.py`. It goes below [the October survey](../state-of-the-art-2026-10.md), which stopped at "nftables as is, keep" and "add a watchdog". Where this section disagrees with that survey, it says so in [Where this disagrees with the October survey](#where-this-disagrees-with-the-october-survey). It does not re-research the work already under way on other branches: packaging, `tvgw setup`, the namespace CI, supply-chain pinning, capture v2, the hardened extractor and profiles v2. It touches them only where a platform fact changes their design.*

## Bottom line

Three platform facts are wrong in the gateway's own model of itself today, and each has a fix of a few lines.

- **The flow log's 32 MB buffer never reached the socket that needed it.** The 2026-10-31 move from 8 MB to 32 MB was a no-op. In conntrack-tools 1.4.7, 1.4.8 and 1.4.9, `-b` sets `SO_RCVBUFFORCE` on the tool's request socket, not on the event socket it reads. So `tvgw-flowlog` has always read through the kernel's default buffer, about 208 KB, while every DESTROY event on the box was queued into it before the userspace `--orig-src` filter threw it away (source read, §F1).
  - The root fix is in the kernel, not the buffer. Kernel 6.18 lets the ruleset choose which connections produce events at all. Set `net.netfilter.nf_conntrack_events=0` and add one rule, `ct event set destroy`, for connections the TV starts. Then only the TV's connections make events: the torrent client's churn never reaches the socket. As a side effect this closes two loss modes nobody has noticed. Connections opened while the logger restarts were never logged, and nor were connections opened at boot before it started.
- **The DNS gate's set never refreshes an address.** Since kernel 6.12 an `add element` updates an existing element's expiry only when the timeout differs or an `expires` is given. The feeder sends neither, so an address resolved every hour still drops out 24 hours after it was first seen. One word fixes it: add `expires 86400s` (§F2).
- **Raspberry Pi OS trixie keeps the journal in RAM.** That is the vendor default since mid-2025, and it reached this Pi with the in-place upgrade. `tvgw ingest` reads three things from the journal: its lost-event warnings, the `tvgw-gate` samples and the `tvgw-oddport` samples. It deliberately avoids `-b` so that it can read lines from before a reboot. Every reboot erases those lines (§F6).

Beyond those three:

- Do not adopt flowtables. Without `counter` they would empty the per-flow byte counts, and the autonomy gate's payload check reads those counts.
- Harden every unit with a shared `tvgw-.service.d/` drop-in, plus per-unit lines, gated in CI by `systemd-analyze security --offline --threshold`.
- Move AdGuard Home's floor to 0.107.79, refuse schema versions above 34, and never let AdGuard update itself. v1.0 is in beta (v1.0.0-b.1, 2026-09-30), and its minor releases may break compatibility.
- The repository is private, so GitHub's artifact attestations are not available on its plan. Keyless cosign would publish the repository's identity to a public log. Sign the apt repository with an OpenPGP key that trixie's `sqv` accepts.
- Nothing in the platform's near future breaks the gateway outright. The risks are AdGuard v1.0 and a conntrack table that the torrent client can fill.

## Contents

- [F1. conntrack events: the buffer bug, in-kernel selection, and lossless delivery](#f1-conntrack-events-the-buffer-bug-in-kernel-selection-and-lossless-delivery) (settled)
- [F2. The DNS gate's set: timeout update semantics on 6.12 and later](#f2-the-dns-gates-set-timeout-update-semantics-on-612-and-later) (settled)
- [F3. Flowtables: rejected, and why they would break the autonomy gate](#f3-flowtables-rejected-and-why-they-would-break-the-autonomy-gate)
- [F4. ct helpers, position-based capture and nftrace: three notes for the branches in flight](#f4-ct-helpers-position-based-capture-and-nftrace-three-notes-for-the-branches-in-flight)
- [F5. AdGuard Home in 2026: schema churn, v1.0 and config as code](#f5-adguard-home-in-2026-schema-churn-v10-and-config-as-code)
- [F6. Raspberry Pi OS trixie as an appliance](#f6-raspberry-pi-os-trixie-as-an-appliance)
- [F7. Unit hardening: the lines to adopt](#f7-unit-hardening-the-lines-to-adopt) (settled)
- [F8. Sysctls and modules to adopt](#f8-sysctls-and-modules-to-adopt) (settled)
- [F9. Supply chain for the .deb when the repository is private](#f9-supply-chain-for-the-deb-when-the-repository-is-private)
- [What will break it next](#what-will-break-it-next)
- [Where this disagrees with the October survey](#where-this-disagrees-with-the-october-survey)
- [What to build here](#what-to-build-here)
- [Open questions](#open-questions)
- [Sources](#sources)

---

## F1. conntrack events: the buffer bug, in-kernel selection, and lossless delivery

### What the unit does today

`tvgw-flowlog.service` runs:

```
conntrack -E -e DESTROY -o timestamp,extended -b 33554432 --orig-src "$TV_IP"
```

and appends its output to `flows.log`. The unit README explains the 32 MB buffer: on 2026-10-31 the torrent client on the Pi overflowed the 8 MB buffer twice in one evening, "since every conntrack event on the box reaches the socket before the TV filter is applied". That premise is right; the remedy did nothing. (The unit table in `deploy/systemd/README.md` still says `-b 8388608`; the prose below it says 32 MB.)

### Finding 1a: `-b` sets the buffer of the wrong socket

Read in the trixie source of conntrack-tools 1.4.8 ([conntrack.c](https://sources.debian.org/src/conntrack-tools/1:1.4.8-2/src/conntrack.c/)), event mode does this:

1. It opens a **new** netlink socket for events: `nfct_mnl_socket_open(event_sock, nl_events)` (line 3436; `event_sock` is `&_event_sock`, line 3229).
2. It applies the buffer size to a **different** socket. It calls `setsockopt(mnl_socket_get_fd(sock->mnl), SOL_SOCKET, SO_RCVBUFFORCE, ...)` (lines 3448-3460). Here `sock` is `&_sock`, the request socket that `main` opened at line 3824.
3. It reads events from the first socket: `mnl_socket_recvfrom(event_sock->mnl, ...)` (line 3477).

The `NOTICE: Netlink socket buffer size has been set to N bytes` line it prints comes from `getsockopt` on that same wrong socket. So the journal says the setting took, and it did not.

- **Versions.** The same code is in 1.4.7 (bookworm) and 1.4.9 (forky and sid), checked against the [Debian sources](https://sources.debian.org/src/conntrack-tools/). No upstream fix was found (search, 2026-11-01).
- **What the TV actually gets.** The event socket keeps `net.core.rmem_default`, which is 212992 bytes on a stock kernel.
- **The filter runs in userspace.** `event_cb` drops non-TV events in userspace (`nfct_filter`, line 1914), after each one has been queued into that buffer and read. The kernel-side filter in this file (`nfct_filter_dump`, CTA_FILTER) is used only for `-L` dumps, never for events.

**Test on the gateway (read-only).** `ss` prints each socket's receive-buffer limit as `rb` and its drop counter as `d`:

```sh
pid=$(systemctl show -p MainPID --value tvgw-flowlog)
sudo ss -f netlink -a -p -m | grep -A1 "pid=$pid,"
```

The bug is confirmed when two netlink sockets show for that pid, one with `rb67108864` (the request socket: the kernel doubles the 32 MB that was asked for) and one with `rb212992`. The second is the event socket; its `d` value counts the events it has lost since it started.

`/proc/net/netlink` shows the same thing. Look for the row with protocol 12 (`NETLINK_NETFILTER`) whose groups are `00000004`, the DESTROY group; its `Drops` column holds the count ([af_netlink.c header line](https://raw.githubusercontent.com/torvalds/linux/v6.18/net/netlink/af_netlink.c)).

### Finding 1b: the kernel can choose which connections make events at all

In 6.18 the per-connection event extension (`ecache`) is allocated by `nf_ct_ecache_ext_add`, which switches on `nf_conntrack_events` ([nf_conntrack_ecache.c, v6.18](https://raw.githubusercontent.com/torvalds/linux/v6.18/net/netfilter/nf_conntrack_ecache.c)):

```c
case 0:
     /* assignment via template / ruleset? ignore sysctl. */
    if (ctmask || expmask)
        break;
    return true;
case 2: /* autodetect: no event listener, don't allocate extension. */
    if (!READ_ONCE(nf_ctnetlink_has_listener))
        return true;
    fallthrough;
case 1:
    /* always allocate an extension. */
```

The nftables `ct event set` statement calls that function, with the mask it is given, on a connection the kernel has not yet confirmed ([nft_ct.c, v6.18](https://raw.githubusercontent.com/torvalds/linux/v6.18/net/netfilter/nft_ct.c)):

```c
if (ctmask && !nf_ct_is_confirmed(ct))
    nf_ct_ecache_ext_add(ct, ctmask, 0, GFP_ATOMIC);
```

The documented syntax is `ct event set new,related,destroy` ([nft(8)](https://www.netfilter.org/projects/nftables/manpage.html)). The kernel puts no limit on the hook or chain the statement may run in. It only has to run before the connection is confirmed, which happens at the end of the first packet's path.

So with `nf_conntrack_events=0`:

- No connection gets an event extension by default.
- The rule `ct event set destroy` gives one to each connection it matches.
- Only those connections ever produce events.

The torrent client's churn, PIA's and AdGuard's own DoH connections, and Samba never touch the netlink socket. The selection happens in the kernel, by source address, which is exactly what the task asked for. The Pi 5 kernel has `CONFIG_NF_CONNTRACK_EVENTS=y` ([bcm2712_defconfig, rpi-6.18.y](https://raw.githubusercontent.com/raspberrypi/linux/rpi-6.18.y/arch/arm64/configs/bcm2712_defconfig)).

**Two loss modes this also closes.** Under the default, `nf_conntrack_events=2`, the extension is allocated only when a listener exists *at the moment the connection is created* (the `case 2` above). That has two consequences:

- **Restart gaps.** A TV connection opened while `tvgw-flowlog` is down never gets an extension, so its DESTROY is never sent, even if it ends hours after the logger is back. `Restart=always` with `RestartSec=5` makes such a window on every crash and every deploy.
- **Boot.** The same happens to every connection the TV opens at boot before `tvgw-flowlog` starts.

With `nf_conntrack_events=0` and the rule, the extension comes from the firewall, whether or not anyone is listening. A connection opened during a gap is logged when it ends, provided the logger is back by then.

**The rule.** It goes in `inet tvgw`, in a chain of its own, so that it exists in both uplink modes. Its priority puts it after conntrack (-200) and before confirmation:

```
chain ct_events {
    type filter hook prerouting priority -150; policy accept;
    iifname "$TV_IF" ip saddr $TV_NET ct state new ct event set destroy comment "flow log: TV connections only"
}
```

The prerouting hook covers both of the TV's paths: the connections it forwards out and the ones it makes to the Pi (DNS, nginx), which `--orig-src` logs today.

**The sysctl.** Put `net.netfilter.nf_conntrack_events = 0` in `/etc/sysctl.d/60-tvgw.conf` (see §F8), and set it in `tvgw-apply` too. Keep `--orig-src` in the unit as a second filter.

**Risks:**

- The sysctl applies to the whole network namespace. Any other program on the Pi that listens for conntrack events would see only the TV's.
  - To list the listeners, run `awk '$2==12 && $4!="00000000"' /proc/net/netlink`. Rows with protocol 12 and non-zero groups are conntrack or nftables subscribers.
  - Then map each `Pid` with `ps -p`. Nothing in the documented stack (PIA, qBittorrent, Samba, AirPlay, xrdp) is known to listen, but that is unverified.
- When `inet tvgw` is removed (`tvgw.service` stopped), new TV connections make no events. The TV is dark then anyway.

**Acceptance test** (a gateway change: run it with the owner, in the same session as a deploy):

1. Before the change, `sudo timeout 600 conntrack -E -e DESTROY | wc -l` counts every DESTROY on the box in 10 minutes, with qBittorrent running.
2. After the change, the same command, with no filter, prints only lines whose original source is in the TV subnet. A second count over 10 minutes shows how far the event rate fell.
3. Restart `tvgw-flowlog` while the TV is playing. A connection the TV opened during the 5 seconds the logger was down must appear in `flows.log` when it ends. Under the old setting it never does.
4. `ss -f netlink -m` (above) shows `d0` on the event socket after an evening of torrenting.

### Finding 1c: lossless DESTROY delivery exists, but `conntrack -E` cannot ask for it

When ctnetlink fails to send a DESTROY event, it returns `-ENOBUFS` ([nf_conntrack_netlink.c, v6.18](https://raw.githubusercontent.com/torvalds/linux/v6.18/net/netfilter/nf_conntrack_netlink.c)). The event cache then records the missed bits, keeps the connection on a dying list, and a worker re-sends the DESTROY until it gets through (`ecache_work_evict_list`, `ECACHE_RETRY_JIFFIES`, in the same ecache file).

Netlink reports such a failure only to a listener that set the socket option `NETLINK_BROADCAST_ERROR`. `do_one_broadcast` sets `delivery_failure` only under `BROADCAST_SEND_ERROR` ([af_netlink.c, v6.18](https://raw.githubusercontent.com/torvalds/linux/v6.18/net/netlink/af_netlink.c)). This is the mechanism behind conntrackd's `NetlinkEventsReliable` option ([conntrackd.conf(5)](https://manpages.debian.org/trixie/conntrackd/conntrackd.conf.5.en.html)). The conntrack command never sets the option.

- **Why it was dangerous before.** Reliable mode holds connections in memory while the listener is slow. On a shared box, with every connection carrying events, a stalled logger could pin the torrent client's connections.
- **Why it is bounded with F1b.** Only the TV's connections carry events, so a stall can pin at most the TV's connections.

**A replacement listener** is about 150 lines of standard-library Python:

- `socket(AF_NETLINK, SOCK_RAW, 12)`, bound to group bit `1<<2`.
- `setsockopt(SOL_SOCKET, SO_RCVBUFFORCE, 8 MiB)` on **this** socket.
- `setsockopt(270 /*SOL_NETLINK*/, 4 /*NETLINK_BROADCAST_ERROR*/, 1)`.
- Parse the attributes: the original tuple, `CTA_COUNTERS_ORIG` and `_REPLY`, `CTA_TIMESTAMP`, and the TCP state.
- The constants are from `linux/netlink.h` and `nfnetlink_conntrack.h`, from memory. Check them against the trixie headers.

It also gives exact kernel start and stop timestamps (`CTA_TIMESTAMP`, which `nf_conntrack_timestamp=1` already turns on). Today's `t_start` is derived from `delta-time`, so the listener may let `FLOW_SLACK` shrink. Whether it can is unverified; measure it against the hello times in the store.

It would also read the socket's drop counter and write it to the store, which ends the dependence on journal lines for Coverage (§F6). Without `NETLINK_BROADCAST_ERROR` the counter can still be non-zero, and with it a non-zero counter means a bug.

**Upstream.** The one-line fix in conntrack-tools is to change `sock->mnl` to `event_sock->mnl` in the `CT_EVENT` case (three places). Send it to netfilter-devel whatever tvgw does; it costs nothing.

**Verdict.**

1. Ship F1b now: the rule and the sysctl. It needs no new code and removes the cause.
2. Meanwhile, read the event socket's `d` counter in `tvgw verify --record` (it is in `ss -m` and `/proc/net/netlink`). The current Coverage warning comes from a journal line that a reboot erases.
3. Build the listener (F1c) after that, as the lossless and better-timed flow log. It needs the owner's approval as a new root service with `CAP_NET_ADMIN`.

---

## F2. The DNS gate's set: timeout update semantics on 6.12 and later

### What the gate does today

- `tvgw-apply` creates `set resolved4 { type ipv4_addr; flags timeout; size 65536; }` with `add` statements, so a re-apply keeps its contents.
- `dnsgate.batch` sends one `nft -f -` per DNS answer: `add element inet tvgw_gate resolved4 { a.b.c.d timeout 86400s, ... }`.
- Its docstring says: "`add` is idempotent, so an address resolved again keeps its first expiry."

### What the kernel does

Kernel 6.12 added "set element timeout update support" ([commit 4201f3938914](https://github.com/torvalds/linux/commit/4201f3938914d8df3c761754b9726770c4225d66), 2024-09-03; the commit code `NFT_TRANS_UPD_EXPIRATION` is present in [v6.12's nf_tables_api.c](https://raw.githubusercontent.com/torvalds/linux/v6.12/net/netfilter/nf_tables_api.c)). When an `add` without `NLM_F_EXCL` meets an existing element that has a timeout ([the patch](https://github.com/torvalds/linux/commit/4201f3938914d8df3c761754b9726770c4225d66.patch)):

```c
if (timeout != nft_set_ext_timeout(ext2)->timeout) {
        nft_trans_elem_timeout(trans) = timeout;
        if (expiration == 0)
                expiration = timeout;
        update_flags |= NFT_TRANS_UPD_TIMEOUT;
}
if (expiration) {
        nft_trans_elem_expiration(trans) = expiration;
        update_flags |= NFT_TRANS_UPD_EXPIRATION;
}
```

The feeder always sends the same timeout and no expiration, so neither branch runs, and the docstring is right about today's code. What it does not say is the cost:

- An address the TV looks up every day expires exactly 24 hours after its *first* lookup, however recently it was looked up again.
- The TV's next connection to it in the minutes after that is counted by the gate as "an address DNS never returned".
- [Design decision 22](../../design-decisions.md#22-a-pass-that-proposes-nothing-is-remembered) names "the gate's day-long memory running out" as one of two causes of the gate's noise. This is that cause, and it is avoidable.

**The fix** is one word in `dnsgate.batch`:

```python
f"{ip} timeout {ttl}s expires {ttl}s"
```

The `expires` element option is documented syntax ([nft(8), ELEMENTS](https://www.netfilter.org/projects/nftables/manpage.html)). On 6.12 and later it moves the expiry of an existing element on every answer. The gate then holds every address the TV was handed in the last 24 hours, not in the 24 hours after it first saw each one.

**Test** (on the gateway with the owner, or in the namespace CI; 192.0.2.1 is a documentation address):

```sh
sudo nft add element inet tvgw_gate resolved4 '{ 192.0.2.1 timeout 1d expires 1h }'
sudo nft list set inet tvgw_gate resolved4 | grep -o '192.0.2.1 timeout 1d expires [^,}]*'   # about 59m
sudo nft add element inet tvgw_gate resolved4 '{ 192.0.2.1 timeout 1d }'
sudo nft list set inet tvgw_gate resolved4 | grep -o '192.0.2.1 timeout 1d expires [^,}]*'   # still about 59m: today's behaviour
sudo nft add element inet tvgw_gate resolved4 '{ 192.0.2.1 timeout 1d expires 1d }'
sudo nft list set inet tvgw_gate resolved4 | grep -o '192.0.2.1 timeout 1d expires [^,}]*'   # about 23h59m: refreshed
sudo nft delete element inet tvgw_gate resolved4 '{ 192.0.2.1 }'
```

**Expected effect.** The brief's gate count should fall on viewing days, and `dns_gate.unexplained` should not change. That is the test that the fix removed noise, not evidence. The baseline is two weeks of counts before the change.

### Two smaller points about the same set

- **Fork per answer.** `dnsgate._nft` forks and executes `nft -f -` for each answer. The race this feeds, between the feeder adding an address and the TV connecting to it, is the other cause of gate noise. Calling libnftables in the same process removes the process start from that race: `libnftables.so.1`, from trixie's `libnftables1` package, through about 20 lines of `ctypes` (`nft_ctx_new`, `nft_run_cmd_from_buffer`). How many milliseconds that saves on the Pi is unmeasured. Measure it on the gateway with `perf stat -r 50 nft add element inet tvgw_gate resolved4 '{ 192.0.2.1 timeout 1d expires 1d }'`, then compare the share of gate samples marked `just looked up` (`queries.FEEDER_LATE`) before and after.
- **A full set.** A 2026 stable fix, "netfilter: nf_tables: unconditionally bump set->nelems before insertion", repairs elements published and then removed without an RCU grace period "in case that the set is full" ([LKML, 6.12.y backport](https://lkml.iu.edu/hypermail/linux/kernel/2605.2/05023.html); upstream `def602e498a4`). Whether 6.18.y has it is unverified. Keep `resolved4` and `seen4` far from their `size 65536`.
  - With refresh on, `resolved4` holds one day of the TV's distinct A answers, likely a few thousand (unverified).
  - Add `tvgw verify` checks: the element count from `nft -j list set inet tvgw_gate resolved4`, warning above 50% of the size.

---

## F3. Flowtables: rejected, and why they would break the autonomy gate

A flowtable (`flowtable ft { hook ingress priority 0; devices = { eth0, wlan0 }; }` plus `flow add @ft` in `forward`) gives established flows a fast path: "packets bypass the classic IP forwarding path" ([nf_flowtable.rst, v6.18](https://raw.githubusercontent.com/torvalds/linux/v6.18/Documentation/networking/nf_flowtable.rst)). The Pi 5 kernel builds it as a module (`CONFIG_NF_FLOW_TABLE_INET=m`). Reasons not to use it here:

1. **No need.** 60 to 70 GB a day is about 6 Mbit/s on average (70e9 × 8 / 86400). The bottleneck is the Wi-Fi uplink, not forwarding.
2. **It would silently disarm the payload gate.** Without the flowtable's `counter` flag, a fast-pathed packet does not update conntrack's counters. The kernel document shows a rule counter that stops counting. `counter` "synchronize[s] packet and byte counters with the existing connection tracking entry" (since 5.7, same document).
   - The autonomy gate's payload check (`MAX_MEDIAN_DOWN`, `MAX_TOTAL_DOWN`), Top upload, the streaming volume used by the hourly judge, and every byte in `flows.log` come from those counters.
   - A flowtable added without `counter`, say as a tuning tip, would make every stream look like 16 KB of telemetry, so the gate would pass content.
3. **The flow entry is a route cache.** "The flowtable behaves like a cache": a stale egress device or MAC address keeps being used (same document). That is a bad fit for policy routing that the dispatcher re-applies when `wlan0` returns, and for the [2026-10-30 incident](../../incidents.md), where route churn destroyed live connections.
4. **What it would not break.** tcpdump on `eth0` still sees every frame, since packet taps run before the ingress hook. The gate and `tv_out` judge only new connections. So it costs no evidence, only safety and simplicity.

**Verdict: REJECT.** Add a `tvgw verify` check that `nft list flowtables` is empty, so a tuning tip copied from a router guide fails loudly.

---

## F4. ct helpers, position-based capture and nftrace: three notes for the branches in flight

- **ct helpers.** None are needed: the TV uses TCP 80 and 443, DNS, and pings. The `nf_conntrack_helper` automatic-assignment sysctl no longer exists in 6.18; it is absent from [nf_conntrack-sysctl.rst](https://raw.githubusercontent.com/torvalds/linux/v6.18/Documentation/networking/nf_conntrack-sysctl.rst). A helper now runs only where a ruleset assigns one with `ct helper set`. Add nothing, and have `tvgw verify` assert that `nft list ct helpers` is empty in the tvgw tables.
- **Position-based capture (capture v2): continuations restart the count.** `ct original packets <= 8` counts packets per conntrack entry, and the count can be read "with or without a direction" ([nft(8)](https://www.netfilter.org/projects/nftables/manpage.html)).
  - With `nf_conntrack_tcp_loose` at its default of 1, the kernel picks up established connections mid-stream ([nf_conntrack-sysctl.rst](https://raw.githubusercontent.com/torvalds/linux/v6.18/Documentation/networking/nf_conntrack-sysctl.rst)).
  - The [decision 21](../../design-decisions.md#21-a-continuation-inherits-its-name) continuations are exactly that: a new entry, starting at packet 1, in the middle of a TLS stream.
  - So a first-8-packets rule would capture 8 mid-stream segments of each continuation, which is TLS ciphertext from the TV. That breaks the privacy page's "never encrypted payload" promise.
  - Do not fix this by setting `tcp_loose=0`: continuations would be dropped as invalid, and the connections would die. Remember a fresh SYN in a 5-tuple set instead, `add @fresh4 { ip saddr . ip daddr . th sport . th dport timeout 2m }` on `tcp flags & (syn|ack) == syn`, and capture only tuples in it.
  - Do not use `ct mark` for this: the VPN client already marks packets (the `undo PIA routed-packet tag` rule), and a collision is unverified but plausible.
- **nftrace in the namespace CI.**
  - Put `meta nftrace set 1` in a table of its own (`table inet tvgw_trace`, a chain at `priority raw`). The baseline `tvgw verify` compares against `inet tvgw` then never changes.
  - Start `nft monitor trace` before sending probes, and wait for it to subscribe; a fixed sleep is a race.
  - Correlate the lines by the `trace id` on each event.
  - Send few probes. Trace events are netlink broadcasts like conntrack's, and the same overrun rules apply (`netlink_overrun`, [af_netlink.c](https://raw.githubusercontent.com/torvalds/linux/v6.18/net/netlink/af_netlink.c)). A burst can lose trace lines and make a test flaky.
  - The nft manual documents `nft monitor trace` with `meta nftrace set 1` ([nft(8)](https://www.netfilter.org/projects/nftables/manpage.html)). Whether nft 1.1.3's JSON monitor (`nft -j monitor trace`) prints the verdict fields the CI wants is unverified. Pin the parser to the text form until a test shows it.

---

## F5. AdGuard Home in 2026: schema churn, v1.0 and config as code

**Where it stands** (GitHub releases, read 2026-11-01, [releases](https://github.com/AdguardTeam/AdGuardHome/releases)):

- **Stable:** v0.107.79, 2026-08-18.
- **Beta:** v0.108.0-b.91 (2026-09-28), then **v1.0.0-b.1 (2026-09-30)**, whose notes say "the `beta` channel has been switched to the new UI and versioning scheme". v0.107.79 says the same of the `edge` channel ([CHANGELOG at v1.0.0-b.1](https://raw.githubusercontent.com/AdguardTeam/AdGuardHome/v1.0.0-b.1/CHANGELOG.md)).
- **A planned v0.107.80** ("2026-09-03 (APPROX.)") is commented out in the changelog and was not released.
- **AdGuard's own warning** for 1.x: "minor releases (like v1.0.0 to v1.1.0) may include backwards-incompatible changes" ([AdGuard blog](https://adguard.com/en/blog/adguard-home-beta-version-1-0.html)).

**What changed in the YAML from v0.107.65 to v0.107.79**, from the [master CHANGELOG](https://raw.githubusercontent.com/AdguardTeam/AdGuardHome/master/CHANGELOG.md). Five schema bumps in eight months:

| Release | Date | Change | What it means for tvgw |
|---|---|---|---|
| 0.107.65 | 2025-08-20 | schema 29→30: `dns.cache_enabled` replaces the implicit `cache_size` logic | not owned; `cache_optimistic` (owned) depends on the cache being on, so own `cache_enabled: true` too |
| 0.107.68 | 2025-10-23 | 30→31: `filtering.rewrites_enabled`, per-rewrite `enabled` | tvgw owns `filtering.rewrites` (empty); own `rewrites_enabled` too, or a UI toggle sits outside the plan |
| 0.107.71 | 2025-12-08 | 31→32: `dns.cache_optimistic_answer_ttl` (30 s), `cache_optimistic_max_age` (12 h) | decision 9 relies on the optimistic cache while the tunnel reconnects; 12 h is now its upper bound |
| 0.107.72 | 2026-02-19 | 32→33: `ignored_enabled` in `querylog` and `statistics` | **own it as `false`**: "ignored" domains drop out of the query log, which is evidence |
| 0.107.74 | 2026-04-16 | 33→34: a new `http.doh` object (`insecure_enabled`, `routes`); `tls.allow_unencrypted_doh` dropped from the example (inferred to be replaced) | not owned; harmless |
| 0.107.75 | 2026-05-19 | `dns.enable_dnssec` now controls the upstream DO bit, default `true` | larger upstream answers; no effect on the TV's |
| 0.107.76 | 2026-05-21 | YAML durations accept `d`; "rolling back below v0.107.76 requires converting values back to hours" | if AdGuard ever rewrites `2160h` as `90d`, `tvgw adguard diff` reports drift forever (unverified; test below) |
| 0.107.78 | 2026-07-13 | h2c upgrade removed; stricter DoH and DNSCrypt upstream validation (GHSA-4qjf-2hgm-92q6); rulelist size cap `filtering.max_http_size` | the DoH validation protects decision 9's upstreams |
| 0.107.79 | 2026-08-18 | DoQ resource-exhaustion fix (GHSA-w6v6-f44j-3rj2); comments allowed in bootstrap config; `strict_sni_check` deprecated | |
| unreleased | | "Incorrect behaviour on the first launch with the `--check-config` flag"; stricter client-ID validation (malformed MACs, leading-zero octets) | tvgw's apply relies on `--check-config`; the client-ID change could refuse a config that loads today |

**What threatens config as code, ranked:**

1. **An upgrade the apply never saw.** `tvgw adguard apply` validates its own candidate with the *installed* binary. It cannot catch the reverse case: a new binary that refuses the *live* YAML because a validation was tightened, as the client-ID change above does. AdGuard then does not start, DNS stops, and the TV goes dark: fail-closed, but down. Fix: a `tvgw adguard upgrade NEWBIN` path that does these steps in order, rolling back on any failure:
   - runs `NEWBIN --check-config -c AdGuardHome.yaml` against a copy of the live file;
   - swaps the binary only when that passes;
   - waits on the same readiness probe as `apply`;
   - runs `tvgw verify`.
2. **AdGuard updating itself.** The web UI offers updates, and the beta channel updates itself ([blog](https://adguard.com/en/blog/adguard-home-beta-version-1-0.html)). `adguardcfg.check` already passes `--no-check-update` to `--check-config`. Add it to the service's own `ExecStart` in tvgw's drop-in, so the binary changes only through the path above.
3. **A schema newer than tvgw has tested.** `plan` checks only that `schema_version` exists. Add a ceiling: refuse to apply when `schema_version` is above the highest version the CI has tested, 34 today. Then a 1.x migration is a deliberate step, not a surprise.
4. **Evidence keys the plan does not own:** `querylog.ignored_enabled` and `statistics.ignored_enabled`, `dns.cache_enabled` and `filtering.rewrites_enabled`. Own each one.
5. **The version floor.** The October survey proposed 0.107.73, for the h2c fix. Raise it to **0.107.79**: 0.107.78 removed h2c entirely and tightened DoH response validation, and 0.107.79 fixed a DoQ resource-exhaustion attack.

**Client-specific rules and upstream behaviour** stay as tvgw uses them:

- The TV is a persistent client with no per-client upstreams.
- The HTTPS/SVCB strip is one rule scoped to the TV's address.
- Nothing in v0.107.65 to v0.107.79 changed `$client` semantics or the order of rules.
- Two adjacent fixes: "Invalid SVCB record from DDR when DoH routes are empty" (unreleased), and "Client ID validation" (unreleased).

  tvgw sets `handle_ddr: true` and serves no DoH of its own. **Test:** from a client on the TV segment, or in the namespace CI, `dig @$GW_IP _dns.resolver.arpa SVCB` must return NOERROR with no answer, on the current version and after each upgrade.

**Running AdGuard as root.** AdGuard Home is the largest parser that reads the TV's bytes, and its install script runs it as root. AdGuard documents running without superuser rights by granting the binary `CAP_NET_BIND_SERVICE` and `CAP_NET_RAW` ([Getting Started](https://github.com/AdguardTeam/AdGuardHome/wiki/Getting-Started)). `setcap` on the binary is lost at each update. Systemd's `AmbientCapabilities=` survives it, and AdGuard's DHCP server, the only user of `CAP_NET_RAW`, is off here. The drop-in is in §F7.

The catch: `tvgw adguard apply` writes `AdGuardHome.yaml` as root through a rename, so it must `chown` the candidate to the service user before the rename. Otherwise AdGuard cannot rewrite its own file, and it does that when migrating a schema at start. **Verdict: PROTOTYPE**, after the upgrade path above.

**Tests for the drift questions:**

- After any save in the web UI, `tvgw adguard diff` must list only the keys that were changed. A `90d` or `2160h` diff it did not cause means AdGuard re-serialized the durations.
- `grep schema_version /opt/AdGuardHome/AdGuardHome.yaml` before and after every upgrade.

---

## F6. Raspberry Pi OS trixie as an appliance

### The journal is volatile by default (settled)

`raspberrypi-sys-mods` on the `pios/trixie` branch ships `/usr/lib/systemd/journald.conf.d/40-rpi-volatile-storage.conf`, which holds `[Journal]` and `Storage=volatile` ([file](https://github.com/RPi-Distro/raspberrypi-sys-mods/blob/pios/trixie/usr/lib/systemd/journald.conf.d/40-rpi-volatile-storage.conf); added 2025-06-10 as `70-…`, renamed to `40-…` on 2025-09-19, per the [commit history](https://github.com/RPi-Distro/raspberrypi-sys-mods/commits/pios/trixie/usr/lib/systemd)). An in-place upgrade from bookworm installs it with the package, and a `/var/log/journal` directory left over from bookworm does not override it ([a 2026-08 write-up](https://homelabpostmortem.com/2026/08/18/trixie-journald-volatile-logs/), secondary).

**Why it matters here.** `ingest.journal_kernel_lines` and `journal_flowlog_lines` read the `tvgw-gate`, `tvgw-oddport` and `tvgw-proto` samples, and conntrack's ENOBUFS warnings, through `journalctl --since`. They avoid `-b` on purpose, "which implies -b and so hides every line between the last run and a reboot" (the docstring). With a volatile journal, a reboot erases everything since the last hourly ingest. After a watchdog reset, it also erases the log of whatever hung.

**Test:**

```sh
systemd-analyze cat-config systemd/journald.conf | grep -n '^Storage'
journalctl --list-boots | head
```

The default is in effect when the last `Storage=` line read is `volatile`, or when `--list-boots` shows only the current boot.

**Fix**, at low risk. Write `/etc/systemd/journald.conf.d/60-tvgw.conf`, then run `systemctl restart systemd-journald; journalctl --flush`:

```
[Journal]
Storage=persistent
SystemMaxUse=256M
SystemKeepFree=1G
MaxRetentionSec=30day
```

- Any name that sorts after `40-` overrides the vendor file.
- The rate-limited log rules (6 a minute) keep tvgw's own share small.
- Card wear: journald's sync interval stays at its default.
- Better still, move the evidence out of the journal: the drop counter of F1, and an NFLOG group for gate samples once capture v2 has its NFLOG reader. The journal would then hold diagnostics only.

### The watchdog is already on

The same package ships `/usr/lib/systemd/system.conf.d/40-rpi-enable-watchdog.conf` with `RuntimeWatchdogSec=1m` and `RebootWatchdogSec=2m` (enabled 2025-06-30, values raised 2025-09-22 in commit `f34bfb2d21`; [file](https://github.com/RPi-Distro/raspberrypi-sys-mods/blob/pios/trixie/usr/lib/systemd/system.conf.d/40-rpi-enable-watchdog.conf)).

On the Pi kernel the bcm2835 watchdog declares `max_hw_heartbeat_ms = WDOG_TICKS_TO_MSECS(PM_WDOG_TIME_SET)`, about 16 s ([bcm2835_wdt.c, rpi-6.18.y](https://raw.githubusercontent.com/raspberrypi/linux/rpi-6.18.y/drivers/watchdog/bcm2835_wdt.c)). The kernel's watchdog core can therefore accept a 1-minute timeout and keep the hardware alive itself between systemd's pings (from the Linux watchdog core's handling of `max_hw_heartbeat_ms`, from memory). The effect:

- If PID 1 hangs, the Pi resets after 1 minute.
- If the kernel hangs hard, it resets after about 16 s.

**Do nothing; check it.** `systemctl show -p RuntimeWatchdogUSec` should print `1min`, and `wdctl` should show the device active. Since a panic stops the kernel's pings, the hardware resets the board even with `kernel.panic=0`. A `kernel.panic=` sysctl adds nothing here.

### No LSM, no Landlock

The Pi 5 kernel config has `CONFIG_SECURITY_APPARMOR=y` but `CONFIG_LSM=""`, and Landlock is not built: no `CONFIG_SECURITY_LANDLOCK` line, and its Kconfig has no default ([bcm2712_defconfig](https://raw.githubusercontent.com/raspberrypi/linux/rpi-6.18.y/arch/arm64/configs/bcm2712_defconfig), [landlock Kconfig](https://raw.githubusercontent.com/raspberrypi/linux/rpi-6.18.y/security/landlock/Kconfig)). The consequences:

- AppArmor profiles do nothing unless the kernel command line enables it (`lsm=` or `apparmor=1 security=apparmor`). Debian's packaged profiles, for instance for tcpdump, are inert here.
- The October survey's Landlock prototype cannot run on this kernel.

**Test:**

```sh
cat /sys/kernel/security/lsm
sudo modprobe configs && zcat /proc/config.gz | grep -E 'LANDLOCK|CONFIG_LSM='
```

Systemd's sandboxing does not depend on any LSM: it uses namespaces, seccomp, capabilities and cgroup BPF (`CONFIG_CGROUP_BPF=y`), all present. So F7 is the hardening that works on this Pi. Enabling AppArmor by command line is possible, but it is a boot change for the whole Pi with no tvgw profile to load: WATCH.

### Secure boot and an encrypted root: no

On a Pi 5, Raspberry Pi's secure-boot provisioner writes key hashes and a device-unique key into OTP. It can set up LUKS2 with a disk secret held in OTP ([provisioner docs](https://www.raspberrypi.com/documentation/security/secure-boot-provisioner.html), [security architecture](https://www.raspberrypi.com/documentation/security/security-architecture.html)). Its options for locking JTAG, EEPROM write protection, the RPIBOOT pin and the provisioning style apply locks that cannot be removed ([v2.3.2 notes](https://github.com/raspberrypi/rpi-sb-provisioner/releases/tag/v2.3.2)).

For a single home gateway with a failing USB disk and an owner who rebuilds by flashing, an irreversible lock-in is the wrong trade. The threat it answers, theft of the box, is not in the threat model. The store's sensitivity belongs in the tabled off-box backup, encrypted. **REJECT**; reconsider only for a commercial appliance image.

### rpi-swap

Trixie's `rpi-swap` defaults to `Mechanism=auto`. Its config documents a `zram+file` mode that writes idle pages back to `/var/swap` every 24 hours (`WritebackPeriodicInterval=24h`; [swap.conf](https://github.com/raspberrypi/rpi-swap/blob/main/etc/rpi/swap.conf), [rpi-zram-writeback.service](https://github.com/raspberrypi/rpi-swap/blob/main/lib/systemd/system/rpi-zram-writeback.service)). What `auto` resolves to on this Pi, and whether the in-place upgrade switched it from `dphys-swapfile` at all, is unverified.

**Test:** `swapon --show; systemctl list-timers 'rpi-zram*'; ls /etc/rpi/swap.conf.d/`

For a gateway on SD: a drop-in `/etc/rpi/swap.conf.d/60-tvgw.conf` with `[Main]` and `Mechanism=zram`, so swap never writes to the card, then a reboot. A drop-in alone takes effect only after a reboot ([write-up](https://homelabpostmortem.com/2026/08/19/trixie-rpi-swap-writeback-file/), secondary). Low value, low risk.

### NetworkManager vs systemd-networkd

Keep NetworkManager:

- The dispatcher hook is how `tvgw-apply` learns that `wlan0` returned.
- The Wi-Fi uplink, and PIA's own integration, assume it.
- Raspberry Pi OS images since November 2025 render through netplan to NM (October survey §8.1).

systemd-networkd would bring nothing a single TV segment needs: its `DHCPServer=` has no lease hook, and discovery reads dnsmasq's leases.

For the gateway, two NetworkManager settings matter, both unverified on this Pi:

- **Wi-Fi power save on the uplink.** Community reports tie Pi 5 overnight unreachability to it ([gist thread](https://gist.github.com/jcberthon/ea8cfe278998968ba7c5a95344bc8b55?permalink_comment_id=5895385), anecdotal). **Test:** `iw dev $WAN_IF get power_save`. If it is on, set `wifi.powersave = 2` in an NM drop-in.
- **Each dispatcher event re-runs `tvgw-apply`.** That is fine, since apply is idempotent, but see §F7: route it through the unit.

### Kernel 6.18 on the Pi

- **The kernel.** Raspberry Pi OS moved from 6.12 LTS to 6.18 LTS in its 2026-06-18 release ([linuxiac](https://linuxiac.com/raspberry-pi-os-june-update-lands-with-linux-kernel-6-18-lts/)). The raspberrypi/linux tree already has `rpi-6.19.y`.
- **16K pages.** The Pi 5 kernel runs `CONFIG_ARM64_16K_PAGES=y`. It matters to anything that assumes 4K pages; nothing in tvgw does.
- **PSI.** It is compiled in but disabled by default (`CONFIG_PSI_DEFAULT_DISABLED=y`), so `systemd-oomd` and memory-pressure triggers do not work without `psi=1` on the command line. That is relevant only if MemoryMax-style limits are extended to jobs (§F7).
- **Netfilter.** No 6.18-specific netfilter regression affecting tvgw's expressions was found (search, 2026-11-01). The one 2026 set-handling fix found is the full-set RCU fix in §F2.

---

## F7. Unit hardening: the lines to adopt

### Principles

1. **One baseline, by prefix.** systemd reads drop-ins from truncated unit names: "for a unit name `foo-bar-baz.service`… both `foo-bar-.service.d/` and `foo-.service.d/`" ([systemd.unit(5)](https://www.freedesktop.org/software/systemd/man/latest/systemd.unit.html)). So `/usr/lib/systemd/system/tvgw-.service.d/10-baseline.conf` applies to every `tvgw-*.service` and not to `tvgw.service`. The package (in flight) owns that one file.
2. **Per-unit additions** live in each unit file, beside the comment that explains why.
3. **A CI gate.** `systemd-analyze security --offline=true --threshold=N deploy/systemd/*.service` scores unit files without PID 1 and fails above the threshold ([systemd-analyze(1)](https://www.freedesktop.org/software/systemd/man/latest/systemd-analyze.html); `--offline` and `--threshold` exist since v250, and GitHub's Ubuntu runners have newer). The scale is 0.0 to 10.0 in output and the default threshold is 100, so the threshold appears to be on a ×10 scale (unverified). Calibrate it on the first run, then lock it per unit so a regression fails CI.
4. **No directive that would break fail-closed.** Notably not on `tvgw.service` or `tvgw-doh-update`, which run `tvgw-apply`.

### The baseline (safe for every `tvgw-*` unit as they stand)

```ini
# /usr/lib/systemd/system/tvgw-.service.d/10-baseline.conf
[Service]
NoNewPrivileges=yes
PrivateTmp=yes
ProtectHome=yes
ProtectControlGroups=yes
ProtectKernelLogs=yes
ProtectClock=yes
ProtectHostname=yes
RestrictRealtime=yes
RestrictSUIDSGID=yes
LockPersonality=yes
SystemCallArchitectures=native
KeyringMode=private
UMask=0027
```

These are left out of the baseline on purpose, with the units they would break:

| Directive | Breaks | Why |
|---|---|---|
| `ProtectKernelTunables=yes` | `tvgw-doh-update` | it runs `tvgw-apply`, which writes sysctls |
| `ProtectKernelModules=yes` | `tvgw-doh-update`, and `tvgw-flowlog` until modules are preloaded | `tvgw-apply` runs `modprobe nf_conntrack`; F8 moves module loading to `modules-load.d` |
| `ProcSubset=pid` | `tvgw-verify` | it reads `/proc/sys/net/...` |
| `PrivateNetwork=yes` | most units | per unit below |
| `MemoryDenyWriteExecute=yes` | uncertain for the Python units | `ctypes` and `cffi` callbacks may need writable executable memory, depending on libffi's trampolines (unverified on trixie's libffi). Use it for the Go and C daemons below, and add it to Python units only after the hardware suite passes with it |
| `SystemCallFilter=@system-service` | `tvgw-doh-update` | `init_module` (modprobe) is outside that set |

### Per unit

| Unit | Add | Notes, and the test |
|---|---|---|
| `tvgw-flowlog` (root, unsandboxed today) | `CapabilityBoundingSet=CAP_NET_ADMIN`, `ProtectSystem=strict`, `ReadWritePaths=/var/log/tvgw`, `PrivateDevices=yes`, `ProtectKernelTunables=yes`, `ProtectKernelModules=yes` (after F8), `RestrictAddressFamilies=AF_NETLINK AF_UNIX`, `RestrictNamespaces=yes`, `MemoryDenyWriteExecute=yes`, `SystemCallFilter=@system-service`, `IPAddressDeny=any` | `CAP_NET_ADMIN` is what binding netlink groups and `SO_RCVBUFFORCE` need. Test: flows keep arriving and `ss -m` shows the socket |
| `tvgw-pcap` | `PrivateDevices=yes`, `ProtectKernelLogs=yes` (baseline), `RestrictNamespaces=yes`, `MemoryDenyWriteExecute=yes`, `SystemCallFilter=@system-service`, `IPAddressDeny=any` | already the best-confined unit; `IPAddressDeny` blocks IP sockets only, not `AF_PACKET`. Test: a new pcap each hour |
| `tvgw-dnsgate` | `User=tvgw-gate` (a new system user), keeping `AmbientCapabilities=CAP_NET_RAW CAP_NET_ADMIN`; drop `-Z root` from the tcpdump arguments (tcpdump drops privileges only when it runs as root); `PrivateDevices=yes`, `RestrictNamespaces=yes`, `SystemCallFilter=@system-service`, `IPAddressDeny=any` | ambient capabilities pass through `execve` to tcpdump and nft. Test: `nft list set inet tvgw_gate resolved4` grows within seconds of a lookup by the TV |
| `tvgw-analyze` | `PrivateDevices=yes`, `ProtectProc=invisible`, `RestrictNamespaces=yes`, `RestrictAddressFamilies=AF_UNIX AF_INET`, `IPAddressDeny=any`, `IPAddressAllow=localhost $TV_NET`, `SystemCallFilter=@system-service`, `CapabilityBoundingSet=CAP_DAC_OVERRIDE CAP_DAC_READ_SEARCH CAP_CHOWN CAP_FOWNER` | it reads the LAN API on the TV subnet and starts tshark through `systemd-run` (D-Bus, AF_UNIX). The capability set is a candidate: root without `CAP_DAC_*` cannot read `tvgw-pcap:nogroup` 0640 files. Test: the hardware suite and one hourly run |
| `tvgw-analyst`, `-weekly` | `IPAddressDeny=any`, `IPAddressAllow=localhost $TV_NET 160.79.104.0/23 2607:6bc0::/48 <the Pi's resolver>`, `PrivateDevices=yes`, `RestrictNamespaces=yes`, `SystemCallFilter=@system-service` | Anthropic publishes `160.79.104.0/23` and `2607:6bc0::/48` as its inbound API ranges and says they "will not change without notice" ([IP addresses](https://platform.claude.com/docs/en/api/ip-addresses)). The model's text is untrusted, and so are the packages it pulls in; this unit then cannot reach anything but the API, the TV, the local resolver and AdGuard. The resolver address is site-specific, from `/etc/resolv.conf`. Test: `systemd-run -p IPAddressDeny=any -p IPAddressAllow=… --pipe curl -sI https://api.anthropic.com`, then a `--dry-run` and a real run |
| `tvgw-autoblock` | `IPAddressDeny=any`, `IPAddressAllow=localhost`, plus the analyst's lines | it talks only to the store, AdGuard on loopback and systemd |
| `tvgw-backup`, `tvgw-prune` | `PrivateNetwork=yes`, `PrivateDevices=yes`, `RestrictAddressFamilies=AF_UNIX`, `SystemCallFilter=@system-service`; `tvgw-prune` also needs `ProtectSystem=strict`, `ReadWritePaths=/var/lib/tvgw` | neither needs a network at all |
| `tvgw-verify` | `ProtectSystem=strict`, `ReadWritePaths=/var/lib/tvgw /run/tvgw`, `PrivateDevices=yes`, `RestrictNamespaces=yes`, `CapabilityBoundingSet=CAP_NET_ADMIN CAP_NET_RAW CAP_DAC_READ_SEARCH` | `nft list` needs `CAP_NET_ADMIN`. No `ProcSubset=pid`. Test: `systemctl start tvgw-verify` passes |
| `tvgw-doh-update` | split it: `ExecStart=` fetches as `DynamicUser=yes` with `StateDirectory=` and `PrivateDevices=yes`, writing a candidate list; `ExecStartPost=+/usr/bin/systemctl reload tvgw.service` (the `+` runs that one line with full privileges) | the fetch is the part that parses internet input; the apply needs root |
| `tvgw.service` | `ExecReload=/usr/local/sbin/tvgw-apply`; `ProtectHome=yes`, `PrivateTmp=yes`, `CapabilityBoundingSet=CAP_NET_ADMIN CAP_NET_RAW` (plus `CAP_SYS_MODULE` until F8). No `ProtectKernelTunables` | see below |

**Route every apply through the unit.** `tvgw-apply` runs today as root from four callers: the boot unit, the NetworkManager dispatcher, `tvgw-doh-update` and `install.sh`. Only the first gets any unit settings. With `ExecReload=`, the other callers can use `systemctl reload tvgw.service`, and then:

- every apply runs under the same sandbox;
- applies are serialized by systemd's job queue as well as the flock;
- every apply is logged under `tvgw.service`.

The dispatcher must use `systemctl --no-block reload tvgw.service`. A blocking call from inside NetworkManager's dispatcher, during a boot that orders `tvgw.service` after NetworkManager, can wait on a job that waits on NetworkManager (a plausible deadlock, unverified). A reload of an inactive unit fails, which is right: the boot start will apply.

Risk: medium, because it changes how the firewall is applied. Test it in the namespace CI first, then with the hardware suite.

### AdGuard Home's drop-in (PROTOTYPE, after F5's upgrade path)

```ini
# /etc/systemd/system/AdGuardHome.service.d/20-tvgw-hardening.conf
[Service]
User=adguardhome
Group=adguardhome
AmbientCapabilities=CAP_NET_BIND_SERVICE
CapabilityBoundingSet=CAP_NET_BIND_SERVICE
NoNewPrivileges=yes
ProtectSystem=strict
ReadWritePaths=/opt/AdGuardHome
ProtectHome=yes
PrivateTmp=yes
PrivateDevices=yes
ProtectKernelTunables=yes
ProtectKernelModules=yes
ProtectKernelLogs=yes
ProtectControlGroups=yes
ProtectClock=yes
RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6 AF_NETLINK
RestrictNamespaces=yes
RestrictRealtime=yes
RestrictSUIDSGID=yes
LockPersonality=yes
MemoryDenyWriteExecute=yes
SystemCallArchitectures=native
SystemCallFilter=@system-service
```

- Go programs work under `MemoryDenyWriteExecute`.
- Do not add `~@resources`: Go's runtime raises its open-file limit at start with `setrlimit` (from memory).
- The `ExecStart=` override that adds `--no-check-update` goes in the same file. Copy the installed unit's own `ExecStart` first: `systemctl cat AdGuardHome`.
- Before enabling: `chown -R adguardhome: /opt/AdGuardHome`, and change `adguardcfg.apply` so the new YAML keeps the old file's owner before the rename.
- **Test:** `dig @127.0.0.1 example.com`, a `tvgw adguard apply` that changes one rule, a restart, then `tvgw verify`.

---

## F8. Sysctls and modules to adopt

**Load the modules before `systemd-sysctl` runs**, so the `net.netfilter.*` keys exist at boot and units can take `ProtectKernelModules=yes`:

```
# /etc/modules-load.d/tvgw.conf
nf_conntrack
nf_conntrack_netlink
nfnetlink_log
```

`nfnetlink_log` is for capture v2's NFLOG reader. trixie's `systemd-sysctl` no longer reads `/etc/sysctl.conf` (October survey §8.1), so the file goes in `sysctl.d`:

```
# /etc/sysctl.d/60-tvgw.conf
# kept (tvgw-apply also sets them at every apply)
net.netfilter.nf_conntrack_acct = 1
net.netfilter.nf_conntrack_timestamp = 1
net.netfilter.nf_conntrack_tcp_timeout_established = 7440
# F1b: only connections the ruleset marks with `ct event set` produce events
net.netfilter.nf_conntrack_events = 0
# headroom against the torrent client (see below); size it from the board's RAM
net.netfilter.nf_conntrack_max = 262144
# the TV interface never takes or sends redirects
net.ipv4.conf.all.send_redirects = 0
net.ipv4.conf.all.accept_redirects = 0
```

- **Leave out `nf_conntrack_tcp_loose = 0`.** It would kill the continuations ([decision 21](../../design-decisions.md#21-a-continuation-inherits-its-name)).
- **Leave out `kernel.panic`.** The watchdog covers it (§F6).
- **Leave out `net.core.rmem_max`.** It has no effect on a socket set with `SO_RCVBUFFORCE`, and the conntrack bug (§F1) means raising it does nothing for the flow log either.

**The conntrack table is shared with the torrent client.**

- **The default limit.** `nf_conntrack_max` defaults to `nf_conntrack_buckets`, which is total memory divided by 16384, between 1024 and 262144 ([nf_conntrack-sysctl.rst](https://raw.githubusercontent.com/torvalds/linux/v6.18/Documentation/networking/nf_conntrack-sysctl.rst)). The kernel also caps it by memory size: from memory, 65536 for boards with up to 4 GiB. So a 4 GB Pi has a much smaller table than the documentation's upper bound suggests (unverified; read it).
- **Why it matters.** A torrent client's DHT and peer churn can fill the table. When it is full, new TV connections are dropped ("table full, dropping packet"), and that would read as a stream breaking. The canary and the hourly judge could then blame the newest block.
- **The fix.** Add a `tvgw verify` check:
  - `nf_conntrack_count` under 75% of `nf_conntrack_max`;
  - `conntrack -S` `drop`, `early_drop` and `insert_failed` not growing between snapshots.

  Store both in `fw_counters`, so the brief and the autonomy judge can tell "the table was full" from "the block broke it".
- **Memory cost.** Each entry is a few hundred bytes. Even a full 262144-entry table is under 100 MB (unverified).

**Test:**

```sh
sysctl net.netfilter.nf_conntrack_max net.netfilter.nf_conntrack_count
sudo conntrack -S | awk '{for(i=1;i<=NF;i++) if($i ~ /^(drop|early_drop|insert_failed)=/) print $i}' | sort | uniq -c
```

Run it during an evening with qBittorrent active.

---

## F9. Supply chain for the .deb when the repository is private

Packaging and SHA pinning are in flight. Four platform facts change how the artifacts should be signed.

1. **Artifact attestations are not available.** GitHub's artifact attestations (SLSA v1.0 Build Level 2, Level 3 with a reusable workflow) "are only available for public repositories" unless the account is on GitHub Enterprise Cloud ([GitHub docs](https://docs.github.com/en/enterprise-cloud@latest/actions/concepts/security/artifact-attestations)). The tvgw repository is private (task #7). Plan without `actions/attest-build-provenance` unless the repository goes public.
2. **Keyless cosign would publish the private repository.** A keyless Sigstore certificate for a GitHub workflow carries the Source Repository URI, the Source Repository Owner URI, the Build Signer URI and the Run Invocation URI ([Fulcio OID extensions](https://github.com/sigstore/fulcio/blob/main/docs/oid-info.md)). With the public Sigstore instance, the certificate goes into the public, append-only Rekor log, and the repository and owner names leak permanently (public Rekor logging is standard Sigstore behaviour, not quoted from the page above).
   - If cosign is wanted, use a key pair (`cosign generate-key-pair`; `cosign sign-blob --key … --tlog-upload=false`).
   - Simpler: let the signed apt repository be the trust root, since that is what apt verifies.
3. **trixie's apt verifies with Sequoia's `sqv`, under a strict policy.** SHA-1 binding signatures have been rejected since 2026-02-01, DSA-1024 keys are refused, and RSA-2048 is accepted until 2030-02-01 ([Tor keyring issue quoting Debian's default policy](https://gitlab.torproject.org/tpo/tpa/debian/deb.torproject.org-keyring/-/issues/1), [Prosody](https://issues.prosody.im/1936)).
   - Generate the archive key as Ed25519, or RSA-3072 or larger, with SHA-512 self-signatures. Test it on trixie before publishing: `sqv --keyring tvgw-archive-keyring.pgp InRelease.sig InRelease`, or simply `apt update` against the repository on a clean trixie container.
   - nfpm's own `.deb` signature (`deb.signature`, `debsign` by default) is optional; apt does not check it ([nfpm configuration](https://nfpm.goreleaser.com/docs/configuration/)).
4. **Reproducible builds are cheap, and give provenance without a log.**
   - nfpm's top-level `mtime` defaults to `$SOURCE_DATE_EPOCH` ([nfpm configuration](https://nfpm.goreleaser.com/docs/configuration/)).
   - The project builds with setuptools. Hatchling, by contrast, builds reproducibly by default and uses `SOURCE_DATE_EPOCH` "for all build timestamps" ([Hatch](https://hatch.pypa.io/latest/config/build/)). setuptools with `wheel` also honours it for zip timestamps (from memory; prove it with the double build).
   - In CI, set `SOURCE_DATE_EPOCH=$(git log -1 --format=%ct)`, build the wheel and the `.deb` twice in separate jobs, and fail when the SHA-256 differ ([SOURCE_DATE_EPOCH spec](https://reproducible-builds.org/specs/source-date-epoch/)).
   - The owner can then rebuild any release on the workstation and compare hashes, which is provenance without a transparency log.
   - **Build on GitHub-hosted runners, never on the Pi's self-hosted runner.** The Pi runner is root on the firewall and has no build isolation, and SLSA Build Level 3 assumes an isolated builder (the GitHub docs above).

---

## What will break it next

Ordered by likelihood within a year:

1. **AdGuard Home 1.x.** A new binary that refuses the live YAML, or a schema above 34. Mitigation: F5's upgrade path, the schema ceiling and `--no-check-update`.
2. **The conntrack table filling** under torrent load, read as a broken stream. Mitigation: F8's check.
3. **A raspberrypi-sys-mods update** that changes the journald or watchdog drop-ins. The files have been renamed once already (`70-` to `40-`, 2025-09). Mitigation: tvgw's own drop-ins at `60-`, and `tvgw verify` reads the effective values (`systemd-analyze cat-config`), not the files.
4. **Kernel minor updates in the 6.18 LTS line.** They are low risk. Pi OS's next kernel jump (the `rpi-6.19.y` branch exists) would need the namespace CI to run on that kernel; GitHub's runners do not. The hardware suite is the gate.
5. **systemd after 257.** Not on trixie: v258 dropped cgroup v1 and raised the kernel baseline ([linuxiac](https://linuxiac.com/systemd-258-drops-cgroup-v1-raises-kernel-baseline-to-5-4/)), and SysV script support is scheduled for removal. Trixie stays on 257 for its life, and tvgw uses native units only. Watch it for forky.

Nothing found in nftables 1.1.x or kernel 6.18 removes an expression tvgw uses.

---

## Where this disagrees with the October survey

- **"Hardware watchdog (`RuntimeWatchdogSec=10s`), ADOPT NOW"** (§7). Raspberry Pi OS trixie already enables it, at `RuntimeWatchdogSec=1m` and `RebootWatchdogSec=2m`. The driver's `max_hw_heartbeat_ms` of about 16 s lets the kernel extend that safely. Keep the vendor default; verify it instead of overriding it.
- **"PROTOTYPE: add a Landlock self-restriction"** (§10). The Pi 5 kernel is built without Landlock, and with `CONFIG_LSM=""`, so neither Landlock nor AppArmor is active. Use systemd sandboxing (F7). Landlock becomes a WATCH for when Raspberry Pi enables it.
- **"Version floor ≥ 0.107.73"** (§2.2). Raise it to 0.107.79, for the h2c removal, the DoH response validation and the DoQ fix.
- **"v1.0 beta (announced 2026-10-02)"** (§2.1). GitHub has `v1.0.0-b.1` published on 2026-09-30, after `v0.108.0-b.91` on 2026-09-28. The blog post may be from 2026-10-02; the release is earlier.
- **DNS-gated egress, mechanism** (§3.2). The survey assumed a set with plain timeouts. On 6.12 and later an element's expiry moves only with an explicit `expires`. That changes what "within the record's TTL plus slack" means in practice, and a future enforce mode must refresh, or it will reject addresses the TV resolved minutes earlier.
- **"Counters need conntrack accounting… position-based capture"** (§1.1). It is right as far as it goes. It misses that continuations restart the packet count, so a first-N rule captures mid-stream ciphertext unless it is keyed to a seen SYN (F4).
- **Implicitly, the 32 MB conntrack buffer**: the survey treated buffer size as the lever. It has no effect on this tool (F1), and the lever is the kernel's event selection.

---

## What to build here

Ranked by value for the risk. Effort: S is days, M is one to two weeks, L is more. Risk is to the running gateway.

1. **TV-only conntrack events.**
   - What: `nf_conntrack_events=0` in `sysctl.d` and `tvgw-apply`; the `ct_events` chain with `ct event set destroy` in `inet tvgw`; record the event socket's drop count (`ss -m` `d`, or `/proc/net/netlink` `Drops`) in `tvgw verify --record`, with an ingest warning when it grows.
   - Fixes: the torrent-driven ENOBUFS at its cause, plus the restart-gap and boot-gap losses.
   - Effort S, risk low to medium (a firewall change; F1b's acceptance test).
2. **Persistent journal.**
   - What: `/etc/systemd/journald.conf.d/60-tvgw.conf` (F6), and a `tvgw verify` line that reads the effective `Storage=`.
   - Effort S, risk low.
3. **Refresh the gate's set.**
   - What: `expires {ttl}s` in `dnsgate.batch`, plus a unit test that the script carries it; then libnftables in-process instead of a fork per answer.
   - Effort S, risk low (a count-only path).
4. **conntrack table headroom.**
   - What: an `nf_conntrack_max` sized to the RAM; `count/max` and `conntrack -S` drops in `verify` and `fw_counters`; a brief line, and a hint the autonomy judge can read.
   - Effort S, risk low.
5. **AdGuard upgrade discipline.**
   - What: floor 0.107.79; schema ceiling 34; own `ignored_enabled: false`, `cache_enabled: true` and `rewrites_enabled`; `--no-check-update` in the service; `tvgw adguard upgrade NEWBIN` running the new binary's `--check-config` on the live YAML first; a CI job running `adguardcfg.plan` output through `--check-config` of v0.107.79 and the newest v1.0 beta.
   - Effort M, risk low.
6. **Unit hardening.**
   - What: the `tvgw-.service.d/10-baseline.conf` drop-in, the per-unit lines in F7 (the analyst's `IPAddressAllow` first), `modules-load.d`, and a CI gate with `systemd-analyze security --offline=true --threshold=` per unit.
   - Effort M, risk medium. Each unit can fail to start; land one unit per deploy, each followed by the hardware suite.
7. **Every apply through `tvgw.service`.**
   - What: `ExecReload=`; the dispatcher, `tvgw-doh-update` and `install.sh` call `systemctl [--no-block] reload`; the DoH fetch split into a `DynamicUser` step.
   - Effort M, risk medium (it changes the firewall's apply path; namespace CI first).
8. **A lossless flow logger.**
   - What: the replacement listener of F1c, with `SO_RCVBUFFORCE` on the right socket, `NETLINK_BROADCAST_ERROR` and kernel timestamps, writing the same `flows.log` format so ingest does not change. Also send the one-line conntrack-tools patch upstream.
   - Effort M, risk medium (a new root parser of kernel messages; run it beside `conntrack -E` for a week and diff the outputs).
9. **Release builds you can re-derive.**
   - What: GitHub-hosted builds with `SOURCE_DATE_EPOCH`, a double-build hash check, an archive key that passes `sqv`, and no keyless cosign while the repository is private.
   - Effort S to M, risk none to the gateway.
10. **AdGuard as a non-root user.**
    - What: the F7 drop-in, plus apply preserving the YAML's owner.
    - Effort M, risk medium (DNS down if wrong; it fails closed). After item 5.

**Do not build:**

- flowtables (F3);
- secure boot or an encrypted root (F6);
- AppArmor turned on by command line, without a profile to load;
- Landlock on this kernel;
- `tcp_loose=0`;
- a bigger `-b` (it does nothing; F1).

---

## Open questions

1. **Are there other conntrack-event listeners on the Pi?** `awk '$2==12 && $4!="00000000"' /proc/net/netlink`, with each `Pid` mapped through `ps`, settles whether `nf_conntrack_events=0` affects anything outside tvgw. Run it on the gateway before item 1.
2. **Does the buffer bug match the Pi?** Two netlink sockets for the flowlog pid, one at `rb212992`. If the event socket instead shows the large buffer, the Debian package carries a patch not seen in the source, and F1a is wrong for this build.
3. **How much RAM does the board have, and what is `nf_conntrack_max` today?** That decides item 4's value and whether the torrent client can realistically fill the table.
4. **Does the VPN client use `ct mark` or `meta mark` only?** This matters for capture v2's choice between a ct mark and a 5-tuple set (F4). `nft list ruleset | grep -n 'ct mark'` answers it.
5. **Does AdGuard re-serialize `h` durations as `d` after a UI save** on 0.107.76 or later? It is the drift test in F5.
6. **Which swap mechanism did the in-place upgrade leave?** `swapon --show`.
7. **How many milliseconds does an in-process libnftables add save** over `nft -f -` on the Pi 5, and how far does that cut `just looked up` gate samples? `perf stat` (F2), then two weeks of briefs.
8. **Does nft 1.1.3's `nft -j monitor trace` carry the verdict** in a form the namespace CI can assert on (F4)?
9. **Does 6.18.y carry the set-full RCU fix** (`def602e498a4`)? Check the stable changelog for the Pi's exact kernel (`uname -r`).

---

## Sources

Kernel and netfilter:

- nf_conntrack_ecache.c, v6.18: https://raw.githubusercontent.com/torvalds/linux/v6.18/net/netfilter/nf_conntrack_ecache.c
- nft_ct.c, v6.18: https://raw.githubusercontent.com/torvalds/linux/v6.18/net/netfilter/nft_ct.c
- nf_conntrack_netlink.c, v6.18: https://raw.githubusercontent.com/torvalds/linux/v6.18/net/netfilter/nf_conntrack_netlink.c
- af_netlink.c, v6.18: https://raw.githubusercontent.com/torvalds/linux/v6.18/net/netlink/af_netlink.c
- nf_conntrack-sysctl.rst, v6.18: https://raw.githubusercontent.com/torvalds/linux/v6.18/Documentation/networking/nf_conntrack-sysctl.rst
- nf_flowtable.rst, v6.18: https://raw.githubusercontent.com/torvalds/linux/v6.18/Documentation/networking/nf_flowtable.rst
- "netfilter: nf_tables: set element timeout update support", commit 4201f3938914: https://github.com/torvalds/linux/commit/4201f3938914d8df3c761754b9726770c4225d66 (patch: https://github.com/torvalds/linux/commit/4201f3938914d8df3c761754b9726770c4225d66.patch)
- nf_tables_api.c, v6.12: https://raw.githubusercontent.com/torvalds/linux/v6.12/net/netfilter/nf_tables_api.c
- "unconditionally bump set->nelems before insertion" (6.12.y backport, 2026-05): https://lkml.iu.edu/hypermail/linux/kernel/2605.2/05023.html
- nft(8): https://www.netfilter.org/projects/nftables/manpage.html

conntrack-tools:

- conntrack.c, 1.4.8 (trixie): https://sources.debian.org/src/conntrack-tools/1:1.4.8-2/src/conntrack.c/
- conntrack.c, 1.4.7 (bookworm): https://sources.debian.org/src/conntrack-tools/1:1.4.7-1/src/conntrack.c/
- conntrack.c, 1.4.9 (forky and sid): https://sources.debian.org/src/conntrack-tools/1:1.4.9-1/src/conntrack.c/
- conntrackd.conf(5): https://manpages.debian.org/trixie/conntrackd/conntrackd.conf.5.en.html

Raspberry Pi:

- raspberrypi-sys-mods, journald drop-in: https://github.com/RPi-Distro/raspberrypi-sys-mods/blob/pios/trixie/usr/lib/systemd/journald.conf.d/40-rpi-volatile-storage.conf
- raspberrypi-sys-mods, watchdog drop-in: https://github.com/RPi-Distro/raspberrypi-sys-mods/blob/pios/trixie/usr/lib/systemd/system.conf.d/40-rpi-enable-watchdog.conf
- raspberrypi-sys-mods, history: https://github.com/RPi-Distro/raspberrypi-sys-mods/commits/pios/trixie/usr/lib/systemd
- bcm2835_wdt.c, rpi-6.18.y: https://raw.githubusercontent.com/raspberrypi/linux/rpi-6.18.y/drivers/watchdog/bcm2835_wdt.c
- bcm2712_defconfig, rpi-6.18.y: https://raw.githubusercontent.com/raspberrypi/linux/rpi-6.18.y/arch/arm64/configs/bcm2712_defconfig
- Landlock Kconfig, rpi-6.18.y: https://raw.githubusercontent.com/raspberrypi/linux/rpi-6.18.y/security/landlock/Kconfig
- rpi-swap, swap.conf: https://github.com/raspberrypi/rpi-swap/blob/main/etc/rpi/swap.conf
- rpi-swap, rpi-zram-writeback.service: https://github.com/raspberrypi/rpi-swap/blob/main/lib/systemd/system/rpi-zram-writeback.service
- Secure Boot Provisioner: https://www.raspberrypi.com/documentation/security/secure-boot-provisioner.html
- Security architecture: https://www.raspberrypi.com/documentation/security/security-architecture.html
- rpi-sb-provisioner v2.3.2: https://github.com/raspberrypi/rpi-sb-provisioner/releases/tag/v2.3.2
- Raspberry Pi OS moves to 6.18 LTS (2026-06): https://linuxiac.com/raspberry-pi-os-june-update-lands-with-linux-kernel-6-18-lts/
- Secondary, on the trixie journald and rpi-swap defaults: https://homelabpostmortem.com/2026/08/18/trixie-journald-volatile-logs/ and https://homelabpostmortem.com/2026/08/19/trixie-rpi-swap-writeback-file/
- Anecdotal, on Wi-Fi power save: https://gist.github.com/jcberthon/ea8cfe278998968ba7c5a95344bc8b55?permalink_comment_id=5895385

AdGuard Home:

- CHANGELOG (master): https://raw.githubusercontent.com/AdguardTeam/AdGuardHome/master/CHANGELOG.md
- CHANGELOG at v1.0.0-b.1: https://raw.githubusercontent.com/AdguardTeam/AdGuardHome/v1.0.0-b.1/CHANGELOG.md
- Releases: https://github.com/AdguardTeam/AdGuardHome/releases
- v1.0 beta announcement: https://adguard.com/en/blog/adguard-home-beta-version-1-0.html
- Getting Started (running without superuser): https://github.com/AdguardTeam/AdGuardHome/wiki/Getting-Started

systemd:

- systemd-analyze(1): https://www.freedesktop.org/software/systemd/man/latest/systemd-analyze.html
- systemd.unit(5): https://www.freedesktop.org/software/systemd/man/latest/systemd.unit.html
- systemd 258 drops cgroup v1: https://linuxiac.com/systemd-258-drops-cgroup-v1-raises-kernel-baseline-to-5-4/

Supply chain:

- Artifact attestations (plans, SLSA levels): https://docs.github.com/en/enterprise-cloud@latest/actions/concepts/security/artifact-attestations
- Fulcio certificate extensions: https://github.com/sigstore/fulcio/blob/main/docs/oid-info.md
- nfpm configuration: https://nfpm.goreleaser.com/docs/configuration/
- Hatch build configuration: https://hatch.pypa.io/latest/config/build/
- SOURCE_DATE_EPOCH specification: https://reproducible-builds.org/specs/source-date-epoch/
- trixie apt and sqv policy (SHA-1 cutoff 2026-02-01): https://gitlab.torproject.org/tpo/tpa/debian/deb.torproject.org-keyring/-/issues/1
- DSA-1024 refused on trixie: https://issues.prosody.im/1936

Anthropic:

- Anthropic API IP addresses: https://platform.claude.com/docs/en/api/ip-addresses
