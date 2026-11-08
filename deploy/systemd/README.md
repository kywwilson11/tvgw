# The systemd units

This folder holds the sixteen services and eight timers that run the gateway; `install.sh` copies every `*.service` and `*.timer` here to `/etc/systemd/system/`, enables them and starts them. This page owns each unit's schedule, user, sandbox and timeout. What each job means for the system as a whole is in [the architecture page](../../docs/how-it-works/architecture.md).

## Units

The units in the order `install.sh` enables them. Every unit runs as root unless the table says otherwise. Every timer has `Persistent=true`, so a run missed while the gateway was off is made up at boot, except `tvgw-verify.timer`, which counts from boot.

| Unit | Type | Schedule | What it runs | User and sandbox | Start timeout |
|---|---|---|---|---|---|
| `tvgw-guard.service` | oneshot, `RemainAfterExit=yes`, `RefuseManualStop=yes`, no `ExecStop` | early boot: `DefaultDependencies=no`, `Before=network-pre.target tvgw.service`, `WantedBy=sysinit.target`, as Debian's `nftables.service` | `nft -f /etc/tvgw/guard.nft`, then its listing to `/run/tvgw/guard.applied`; `ExecReload` the same ([the guard](../nftables/README.md#the-guard)) | root, no sandbox | 1 min |
| `tvgw.service` | oneshot, `RemainAfterExit=yes` | at boot, `After=NetworkManager.service`, `Before=dnsmasq.service` | `/usr/local/sbin/tvgw-apply`; four `ExecStop` lines, the first through `sh -c` so it reads the `TV_IF` of the last apply, or of the settings ([stopping](../nftables/README.md#stopping)) | root, no sandbox | 2 min |
| `tvgw-flowlog.service` | long-running, `Restart=always` after 5 s | always; `After=` and `Wants=tvgw.service` | `sh -c` that sources the settings, then `conntrack -E -e DESTROY -o timestamp,extended --orig-src <TV_IP>` appended to `/var/log/tvgw/flows.log` | root, `UMask=0027` | none |
| `tvgw-pcap.service` | long-running, `Restart=always` after 5 s | always with `CAPTURE_MODE=full` (its `ExecCondition` skips it otherwise); `After=` and `Wants=tvgw.service`; `Wants=tvgw-pcap-headers.service` | `/usr/bin/dumpcap -i ${TV_IF} -q -P -g -s 0 -b interval:3600 -b nametimenum:2 -w /var/lib/tvgw/pcap/tv.pcap -f` with the capture filter on `${TV_NET}` and `${GW_IP}`, `TZ=UTC`; the three come from the drop-in `tvgw-pcap.service.d/tv-side.conf` that `install.sh` writes from the settings | `tvgw-pcap:nogroup`; `CAP_NET_RAW` and `CAP_NET_ADMIN` only; read-only system; only `/var/lib/tvgw/pcap` writable; `UMask=0027` | none |
| `tvgw-pcap-headers.service` | long-running, `Restart=always` after 5 s; static (no `[Install]`) | with `CAPTURE_MODE=headers`, started by `tvgw-pcap`'s `Wants=` and stopped and restarted with it (`PartOf=`) | `/usr/bin/dumpcap -i nflog:7 -q -P -g -s 0 -b interval:3600 -b nametimenum:2 -w /var/lib/tvgw/pcap/tvhdr.pcap`, `TZ=UTC` | as `tvgw-pcap` | none |
| `tvgw-dnsgate.service` | long-running, `Restart=on-failure` | always; `After=` and `Wants=tvgw.service` | `tvgw dnsgate-feed` | root bounded to `CAP_NET_RAW` and `CAP_NET_ADMIN`; read-only system; `MemoryMax=128M` | none |
| `tvgw-dnsgate-inpath.service` | long-running, `Type=notify` with `WatchdogSec=2` and `WatchdogSignal=SIGKILL`, `Restart=on-failure` | only with `DNSGATE=count` and `DNSGATE_FILL=inpath` (enabled by `install.sh` then, and its `ExecCondition` skips it otherwise); `After=` and `Wants=tvgw.service` | `tvgw dnsgate-inpath` | root bounded to `CAP_NET_ADMIN`; netlink and unix sockets only; read-only system but `/run/tvgw-dnsgate-inpath`; `MemoryMax=128M`, `OOMScoreAdjust=300` | 30 s |
| `tvgw-tvlive.service` | long-running, `Restart=on-failure`, `RestartSec=60`, `WatchdogSec=180` | always; `After=` and `Wants=tvgw.service`; exits 0 at once unless `LIVE_READING=on` and `PROFILE=lg-webos` | `tvgw tvlive` | root with no capability; read-only system but `/var/lib/tvgw`; `IPAddressDeny=any` with `IPAddressAllow=<TV_IP>` from the drop-in `install.sh` writes; `MemoryMax=128M`; `UMask=0077` | 15 s to stop |
| `tvgw-prune.service` and `.timer` | oneshot | hourly (`OnCalendar=hourly`) | `tvgw prune-pcaps` | root, no sandbox | 10 min |
| `tvgw-doh-update.service` and `.timer` | oneshot | daily (`OnCalendar=daily`), up to 1 h random delay; after `network-online.target` | `/usr/local/sbin/tvgw-doh-update` | root, no sandbox | 5 min |
| `tvgw-analyze.service` and `.timer` | oneshot | hourly at :20 | `/usr/local/sbin/tvgw-analyze` | root, sandboxed; writable `/var/lib/tvgw`, `/var/log/tvgw`, `/run/lock` | 45 min |
| `tvgw-verify.service` and `.timer` | oneshot | 3 min after boot, then 10 min after each run ends | `tvgw verify --record` | root, no sandbox, `Nice=10` | 5 min |
| `tvgw-backup.service` and `.timer` | oneshot | daily at 03:40 | `tvgw backup` | root, sandboxed; writable `/var/lib/tvgw` | 10 min |
| `tvgw-analyst.service` and `.timer` | oneshot | daily at 03:50, overridden by `ANALYST_SCHEDULE` | `tvgw analyst` | root, sandboxed; writable `/var/lib/tvgw`, `/opt/AdGuardHome`; network | 20 min |
| `tvgw-analyst-weekly.service` and `.timer` | oneshot | Monday at 04:10, overridden by `ANALYST_WEEKLY_SCHEDULE` | `tvgw analyst --weekly` | as `tvgw-analyst` | 20 min |
| `tvgw-autoblock.service` and `.timer` | oneshot | hourly at :25 | `tvgw autoblock check` | root, sandboxed; writable `/var/lib/tvgw`, `/opt/AdGuardHome`; network | 25 min |

What the jobs do:

- `tvgw-guard.service` loads the guard table before the network comes up and never unloads it: a stop is refused, a restart too, and removing the unit leaves the table in the kernel ([design decision 42](../../docs/design-decisions.md#42-the-pi-is-closed-to-the-tv-whatever-nftables-holds)). `systemctl reload tvgw-guard` loads `/etc/tvgw/guard.nft` again in one transaction.
- `tvgw.service` builds the firewall ([the firewall](../nftables/README.md)). It is ordered before dnsmasq, so the filter is in place before the TV gets a lease.
- `tvgw-flowlog` logs every finished TV connection with byte counts. The kernel sends its socket the TV's connections and nothing else: `tvgw-apply`'s `ct_events` chain marks each new TV connection (`ct event set destroy`) and `nf_conntrack_events=0` leaves every other connection on the gateway without events ([design decision 43](../../docs/design-decisions.md#43-the-flow-log-hears-the-tv-alone-and-the-gates-day-starts-at-each-answer), [the kernel switches](../sysctl/README.md)); `--orig-src` is the second filter. A TV connection opened while the unit restarts is still logged when it ends, because its events come from the firewall, not from a listener being there when it opened.
- The unit asks for no buffer size. Until 2026-11-01 it passed `-b 33554432` (8 MB before 2026-10-31, when a torrent client on the gateway overflowed the socket twice in an evening). That did nothing: conntrack-tools 1.4.8 applies `-b` to the request socket it opens first, not to the event socket it reads from, which kept the kernel's default buffer, and its `NOTICE: Netlink socket buffer size has been set to ...` line reads the wrong socket too. Should the socket still overflow, conntrack says `We have hit ENOBUFS!` on stderr, which stays in this unit's journal and which `tvgw ingest` turns into a warning; the kernel counts the same loss in the socket's `Drops`, which `tvgw verify --record` stores and the ingest also warns about.
- `tvgw-flowlog` reads `TV_IP` from the settings each time it starts and falls back to `10.10.10.17`.
- `tvgw-flowlog`, `tvgw-pcap` and `tvgw-dnsgate` start after `tvgw.service` (`After=`, `Wants=`) but are not bound to it. With `Requires=`, a boot apply that failed would fail their start jobs as "dependency failed" and nothing would start them again, and stopping the firewall would stop the capture; with `Wants=`, the capture keeps recording what the TV tries while the firewall is down.
- `tvgw-pcap` captures the frames the TV sends with dumpcap into one file per clock hour, named `tv_<YYYYmmddHHMMSS>_<nnnnn>.pcap` in UTC, the time first so names sort in time order across restarts. What the filter keeps is in [what the capture keeps](../../docs/how-it-works/privacy-and-retention.md#what-the-capture-keeps). `tvgw-pcap-headers` is the `CAPTURE_MODE=headers` variant, which writes what the firewall hands NFLOG group 7. Each unit's `ExecCondition` (run as root, since it reads the settings file) lets exactly one of the two run; `install.sh` enables and restarts `tvgw-pcap` only, and the headers unit follows it. Both start with a check that `/usr/bin/dumpcap` is executable by `tvgw-pcap`, and fail with a message naming `wireshark-common` when it is not ([the capture](../../docs/how-it-works/capture.md)).
- `tvgw-dnsgate` adds every IPv4 address AdGuard hands the TV to the DNS gate set ([the DNS gate table](../nftables/README.md#the-dns-gate-table)). With `DNSGATE=off` it exits 0 and stays down. Its restarts start at 5 seconds and back off to 5 minutes (`RestartSec=5`, `RestartSteps=6`, `RestartMaxDelaySec=5min`), since a feeder that restarted every 5 seconds logged 167 restarts in a quarter hour on 2026-10-28.
- `tvgw-dnsgate-inpath` is the DNS gate's in-path filler ([design decision 64](../../docs/design-decisions.md#64-the-gates-second-set-is-filled-in-the-path-of-the-answer-beside-the-passive-feeder-and-still-only-counts)). It runs only with `DNSGATE=count` and `DNSGATE_FILL=inpath`: `install.sh` enables it then and disables it otherwise, and its `ExecCondition` skips a start the settings do not ask for. It is `Type=notify`: `READY=1` once its queue is bound and configured, then a watchdog ping every 0.4 seconds from its loop. A loop that stops for `WatchdogSec=2` is killed with `WatchdogSignal=SIGKILL`, which a stopped or deadlocked process cannot put off; the queue's socket closes with the process, and the queue rule's `bypass` has the kernel pass the TV's DNS answers itself until the unit is back. A clean stop empties the queue first. Every 2 seconds it puts its port into the set `inpath_live` again, which `tvgw-apply` deletes while it reloads the firewall ([the in-path filler's half](../nftables/README.md#the-in-path-fillers-half)). It restarts on failure with the feeder's back-off, writes its counts to `/run/tvgw-dnsgate-inpath/status.json` (its `RuntimeDirectory`, removed when it stops), and is no part of `verify.SERVICES`: a filler that is down is the `dnsgate_inpath` check's warning, not an outage.
- `tvgw-prune` deletes old pcaps ([how long it is kept](../../docs/how-it-works/privacy-and-retention.md#how-long-it-is-kept)). It shows in `systemctl --failed` whenever it had to keep a file it should have deleted or could not tell which file is live ([commands](../../docs/reference/commands.md)).
- `tvgw-doh-update` refreshes the DoH resolver list and runs `tvgw-apply` ([the shell jobs](../bin/README.md)).
- `tvgw-analyze` reads the TV (LG only), runs the hourly ingest and writes the reports ([the shell jobs](../bin/README.md)).
- `tvgw-verify` runs the checks and stores the verdict and every firewall counter ([what tvgw verify checks](../../docs/reference/verify-checks.md)); it fails, and shows in `systemctl --failed`, when a check fails.
- `tvgw-backup` writes a checked copy of the store ([privacy and retention](../../docs/how-it-works/privacy-and-retention.md)).
- `tvgw-analyst` and `tvgw-analyst-weekly` run the daily and weekly passes of the analyst ([the analyst](../../docs/how-it-works/analyst-and-autonomy.md)). With `ANALYST_APPLY=auto` a pass may apply a block, which rewrites AdGuard's config.
- `tvgw-autoblock` re-judges every rule the gateway added on its own; a revert takes the rule out of the machine's file and re-applies AdGuard ([design decision 20](../../docs/design-decisions.md#20-the-gateway-blocks-on-its-own-under-three-watches)). When a rule's canary is armed and the last TV reading shows the TV on with an app in front, it reads the TV over its LAN API for about 11 minutes, which is why its timeout is 25 minutes. It holds `/var/lib/tvgw/autoblock.lock` while it runs, and so do the analyst's autonomous steps, so two checks, or a check and an apply, never watch the same canary (a check that finds the lock held exits 0) ([design decision 41](../../docs/design-decisions.md#41-the-autonomy-refuses-what-it-cannot-see-and-keeps-what-it-decided)).
- (pause) `tvgw-autoblock` also ends, before it judges anything, a pause of the shared tracker lists past its end that nothing ended. The pause's own way back is no unit file: `sudo tvgw pause` starts a transient timer and service, `tvgw-pause-end`, with `systemd-run --on-active --collect`, which run `tvgw pause --end --timer` once at the pause's end and are gone after it, and after a reboot ([pausing the shared lists](../../docs/how-it-works/adguard.md#pausing-the-shared-lists)).

`install.sh` also writes drop-ins that are not files here: `nginx.service.d/tvgw.conf` (start after `network-online.target`, `Restart=on-failure` after 5 s, and the sandbox of [deploy/nginx](../nginx/README.md#the-sandbox)), `dnsmasq.service.d/20-tvgw-hardening.conf` ([deploy/dnsmasq](../dnsmasq/README.md#the-hardening-drop-in)), `<unit>.service.d/10-tvgw-not-from-tv.conf` with `IPAddressDeny=TV_NET` for each co-tenant `CO_TENANT_UNITS` names (`tvgw guard cotenants`), `AdGuardHome.service.d/workdir.conf` (`WorkingDirectory=/opt/AdGuardHome`), and `tvgw-analyst.timer.d/schedule.conf` and `tvgw-analyst-weekly.timer.d/schedule.conf`, which replace the two timers' `OnCalendar` with the rendered schedule ([what install.sh does](../README.md#what-installsh-does)). It masks `nftables.service`, whose `flush ruleset` would wipe the VPN client's tables and the gateway's.

## Hardening

`tvgw-analyze` parses untrusted input, packets from the TV and the internet and the log lines about them, so it is the most tightly bound of the units:

- `ProtectSystem=strict` with `ReadWritePaths=/var/lib/tvgw /var/log/tvgw /run/lock`: nothing else is writable.
- `NoNewPrivileges=yes`, `PrivateTmp=yes`, `ProtectHome=yes`, `ProtectKernelTunables=yes`, `ProtectKernelModules=yes`, `ProtectControlGroups=yes`, `RestrictRealtime=yes`.
- `Nice=10`, `IOSchedulingClass=best-effort` and `IOSchedulingPriority=7`, so the hourly job yields to the resolver.
- `OOMScoreAdjust=500`, so when memory runs out this job dies before the resolver does.

Inside it, tshark runs in a transient unit of its own as `nobody:nogroup`, with no network and no capabilities (`sandbox()` in src/tvgw/tshark.py).

The other sandboxes, and why each unit has the one it has:

- **`tvgw-pcap`** starts as the system user `tvgw-pcap` with `CAP_NET_RAW` and `CAP_NET_ADMIN` as its whole capability set (`AmbientCapabilities` and `CapabilityBoundingSet`), `NoNewPrivileges=yes`, `ProtectSystem=strict`, only its own directory writable, `RestrictAddressFamilies=AF_PACKET AF_NETLINK AF_UNIX AF_INET` and `SystemCallArchitectures=native`. dumpcap never runs as root, so a bug in the dissector of a frame the TV sent cannot become root; only the `ExecCondition` that reads the settings file runs as root (`+`). `tvgw-pcap-headers` has the same user and sandbox.
- **`tvgw-dnsgate`** runs as root for the two capabilities the capture and the set updates need, with the same bounds as `tvgw-pcap` but nothing writable, and `MemoryMax=128M`. Its tcpdump keeps root (`-Z root` in src/tvgw/dnsgate.py), since Debian's default drop to the `tcpdump` user needs a capability the unit does not grant.
- **`tvgw-backup`** sets `ProtectSystem=strict` with only `/var/lib/tvgw` writable, `NoNewPrivileges=yes`, `PrivateTmp=yes`, `ProtectHome=yes`, `ProtectKernelTunables=yes`, `ProtectKernelModules=yes`, `ProtectControlGroups=yes`, `Nice=10`, `IOSchedulingClass=best-effort` and `IOSchedulingPriority=7`; unlike `tvgw-analyze` it sets no `RestrictRealtime` and no `OOMScoreAdjust`.
- **`tvgw-analyst`, `tvgw-analyst-weekly` and `tvgw-autoblock`** set `ProtectSystem=strict` with `/var/lib/tvgw` and `/opt/AdGuardHome` writable, `NoNewPrivileges=yes`, `PrivateTmp=yes`, `ProtectHome=yes`, `ProtectKernelTunables=yes`, `ProtectKernelModules=yes`, `ProtectControlGroups=yes`, `Nice=10` and `RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6`; no I/O scheduling class, no `RestrictRealtime` and no `OOMScoreAdjust`. A block or a revert re-applies AdGuard's config, so its directory must be writable. The hourly check has its own unit rather than a line in `tvgw-analyze`, whose read-only view of `/opt` would make a revert's re-apply fail.
- **`tvgw`, `tvgw-flowlog`, `tvgw-verify`, `tvgw-prune` and `tvgw-doh-update`** run as root without a sandbox: they need the kernel's firewall, conntrack events or root-only files.

## Timeouts

Every `Type=oneshot` unit sets `TimeoutStartSec`, because a oneshot has no start timeout by default:

- A hung `tvgw-apply` at boot would hold `multi-user.target`, and dnsmasq, which is ordered after it, for ever. With the 2-minute timeout the unit fails instead, and the TV stays unforwarded, which is the fail-closed state ([design decision 5](../../docs/design-decisions.md#5-fail-closed)).
- A hung verify would end the checks and the counter snapshots, because `OnUnitActiveSec=10min` re-arms only when the unit finishes. Each command inside it has a 30-second timeout of its own.
- `tvgw-analyze`'s 45 minutes keep a TV that answers and then stalls, or a tshark that never returns, from blocking the next hour; the timer fires again only after the unit finishes.
- `tvgw-doh-update`'s `curl` gives up after 60 seconds inside the unit's 5 minutes.

`tests/unit/test_deploy_lint.py` fails when a oneshot unit lacks `TimeoutStartSec`, and when the list of oneshot units in this folder changes without the test. The long-running units have no start timeout; their `Restart=` lines bring them back. CI's hardware job allows time for a deploy with a first analyze run ([how a change reaches the gateway](../README.md#how-a-change-reaches-the-gateway)).

## Reading the journals

On the gateway:

```sh
systemctl list-timers 'tvgw-*'                # next and last run of each timer
systemctl --failed                            # a failed tvgw-verify means a FAIL in the last check
journalctl -u tvgw -n 20                      # firewall applies: "tvgw: applied (uplink=direct ...)"
journalctl -u tvgw-analyze -n 50              # the hourly TV reading, ingest and reports
journalctl -u tvgw-verify -n 20               # one line per check, OK, WARN or FAIL
journalctl -u tvgw-doh-update -n 20           # "tvgw: N DoH IPs loaded", or why the old list was kept
journalctl -u tvgw-prune -n 5                 # "tvgw prune-pcaps: deleted N, kept M (X MB)" and its warnings
journalctl -u tvgw-backup -n 7                # one line per daily copy: path, size, quick_check ok
journalctl -u tvgw-dnsgate -n 20              # the feeder's start line, tcpdump's own errors
journalctl -u tvgw-dnsgate-inpath -n 20       # the in-path filler: "holding the TV's DNS answers", late adds, a missing set
journalctl -u tvgw-analyst -u tvgw-autoblock  # analyst runs and the hourly judgements
journalctl -u tvgw-pcap -u tvgw-flowlog       # capture restarts and errors
```

`tvgw-analyze` prints `tvgw-analyze: WARNING: ...` when the TV reports Live Plus on, when ingest reports problems and when a report fails to render, and ends with `tvgw-analyze: latest refreshed; new reports: ...`. `tvgw ingest` writes its own warnings to stderr, and the brief repeats them under Coverage. The dnsgate feeder lets tcpdump's stderr reach the journal, so a feeder that dies at once says why.

## Changing a unit

1. Edit the file in this folder. Write `%%` for a literal `%` and `$$` for a literal `$` in an `Exec` line: systemd expands `%` specifiers and `$VAR` itself, quoted or not, which is why `tvgw-flowlog` writes `$${TV_IP:-10.10.10.17}`.
2. A new oneshot needs a `TimeoutStartSec`, and the oneshot list in `tests/unit/test_deploy_lint.py`.
3. A new unit that must run also goes in the `systemctl enable --now` line in `install.sh`, in `verify.SERVICES` in src/tvgw/verify.py, and in `ENABLED` in tests/hardware/test_gateway.py, with `test_service_active` for a service and `test_timer_scheduled` for a timer.
4. Run `make gate`. `tests/unit/test_deploy_units.py` checks the `Exec` escapes, the UTC pcap names and the analyze unit's OOM score; `tests/unit/test_capture_filter.py` runs the capture filter through tcpdump; `tests/unit/test_capture.py` runs the two capture units' conditions and dumpcap check with `sh` and `dash`.
5. Deploy. `install.sh` copies every unit and timer and reloads systemd, and restarts `tvgw-pcap`, `tvgw-flowlog` or `tvgw-dnsgate` only when what it read at its last start there changed: its unit file, for the capture also `TV_IF`, `TV_NET` and `GW_IP`, `tvgw-pcap-headers.service` and the `CAPTURE_MODE` line, for the flow log also `TV_IP`, for the feeder also the settings and the package it runs, hashed into `/var/lib/tvgw/.unit-stamps/` after each restart ([what install.sh does](../README.md#what-installsh-does)). Every restart is a short hole in the evidence. The hardware suite then checks that each installed file equals the checkout and that each unit is enabled.

Keep `/var/lib/tvgw` and `/var/log/tvgw` in step with the scripts, which hardcode them too. The TV interface comes from the settings (`TV_IF`), in `tvgw-pcap.service` through the drop-in `install.sh` writes. A timer's cadence is a promise the brief makes: two applies within one verify interval lose the counts the first one's listings held, and analyze at :20 sets how late TLS names arrive ([the architecture page](../../docs/how-it-works/architecture.md)).

## Gotchas

- `tvgw-dnsgate` stays down after it exits 0 with `DNSGATE=off`; after switching back to `count`, start it again.
- `tvgw-dnsgate-inpath` is the one unit `install.sh` does not always enable. After changing `DNSGATE_FILL` by hand, run `install.sh`: `tvgw-apply` alone loads or removes the rules but leaves the unit as it was. A filler left running under `passive` rules is idle, and one missing under `inpath` rules costs nothing but the second count.
- The analyst timers' schedules come from the drop-ins `install.sh` writes, so editing `OnCalendar` in the shipped timer files changes nothing while a drop-in exists.
- `tvgw-analyze` exits 0 when ingest reports problems; those show in the brief's Coverage, not in `systemctl --failed`.
