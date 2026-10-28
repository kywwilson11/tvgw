# systemd units

Ten services and six timers run the gateway. `install.sh` copies every `*.service` and `*.timer` here to `/etc/systemd/system/`, enables them and starts them.

## Units

| Unit | Type and cadence | What it runs | Notes |
|---|---|---|---|
| `tvgw.service` | oneshot, stays active; at boot after NetworkManager, before dnsmasq | `tvgw-apply` | Stop turns forwarding off on `eth0` first, then removes `ip rule` 60, `netdev tvgw_l2` and `inet tvgw`. A stopped service leaves the TV dark, not unfiltered. |
| `tvgw-flowlog.service` | long-running, `Restart=always` | `sh -c '. /etc/tvgw/tvgw.conf; exec conntrack -E -e DESTROY -o timestamp,extended -b 8388608 --orig-src ${TV_IP:-10.10.10.17} >> /var/log/tvgw/flows.log'` | Only the TV's connections. The 8 MB netlink buffer keeps a burst of expiring flows from being dropped. The unit writes `$${TV_IP...}`: systemd expands `$VAR` in `ExecStart` itself, quotes or not, so without the `$$` escape the shell would never see the variable and the fallback address would be used whatever the conf says. `UMask=0027` makes a fresh `flows.log` `640`. |
| `tvgw-pcap.service` | long-running, `Restart=always` | `tcpdump -i eth0 -G 3600` as `tvgw-pcap` with ambient `CAP_NET_RAW`/`CAP_NET_ADMIN` (never root) into `/var/lib/tvgw/pcap/tv-%Y%m%dT%H%M%SZ.pcap` with `TZ=UTC` | Keeps only frames the TV sends: SYN/FIN/RST, requests to port 80 whole, UDP except QUIC short headers, a segment that begins a TLS ClientHello, a segment that begins with an HTTP method (the :8080 firmware fallback). Nothing the TV receives. Names are UTC with seconds: local-time names repeat in the DST fall-back hour and tcpdump truncates a file whose name it has used before. `UMask=0027` with the setgid `nogroup` directory makes each file `640 root:nogroup`. |
| `tvgw-dnsgate.service` | long-running, `Restart=on-failure` | `tvgw dnsgate-feed` | Reads the resolver's UDP answers to the TV (tcpdump as a pcap stream) and adds their IPv4 addresses to `inet tvgw_gate resolved4` with a one-day timeout. Root with `CAP_NET_RAW` and `CAP_NET_ADMIN` only, read-only system. Exits 0 and stays down with `DNSGATE=off`. |
| `tvgw-verify.service` / `.timer` | oneshot; 3 min after boot, then every 10 min | `tvgw verify --record` | Fails, and shows in `systemctl --failed`, when any check fails. `Nice=10`. |
| `tvgw-analyze.service` / `.timer` | oneshot; hourly at :20, `Persistent=true` | [`tvgw-analyze`](../bin/README.md) | Reads the TV (LG), ingests, writes reports. Runs missed while the Pi was off are made up at boot. |
| `tvgw-prune.service` / `.timer` | oneshot; hourly, `Persistent=true` | [`tvgw prune-pcaps`](../bin/README.md#tvgw-prune-pcaps) | Pcap retention: files ingest has read past `PCAP_DAYS`, then the oldest read files while over `PCAP_MAX_GB` or under 1 GB free; never the live file, never an un-read file before twice `PCAP_DAYS`. Exits 1, and shows in `systemctl --failed`, when it had to keep or warn. |
| `tvgw-backup.service` / `.timer` | oneshot; daily at 03:40, `Persistent=true` | `tvgw backup` | `VACUUM INTO` a fresh copy of the store in `/var/lib/tvgw/backup/`, `quick_check` before it is named, newest seven kept, `640 root:adm`. Sandboxed like `tvgw-analyze` with only the state directory writable. `make backup` pulls the copies. |
| `tvgw-analyst.service` / `.timer` | oneshot; daily at 03:50, `Persistent=true` | `tvgw analyst` | Yesterday's minimized evidence pack to Claude; proposals (never applied) to `reports/proposals/`. Skips quietly without `/etc/tvgw/claude.key`. Sandboxed like `tvgw-backup`, with the network. |
| `tvgw-doh-update.service` / `.timer` | oneshot; daily with up to 1 h random delay, `Persistent=true`; after the network is online | [`tvgw-doh-update`](../bin/README.md) | Refreshes the DoH set, then runs `tvgw-apply`. |

`tvgw-flowlog` and `tvgw-pcap` have `Requires=tvgw.service`, so stopping the firewall also stops capture, and the store has a gap for that time.

Every `Type=oneshot` unit sets a `TimeoutStartSec` (`tvgw.service` 2 min, `tvgw-verify` 5 min, `tvgw-doh-update` 5 min, `tvgw-prune` 10 min, `tvgw-backup` 10 min, `tvgw-analyst` 20 min, `tvgw-analyze` 45 min), because a oneshot has none by default: a hung `tvgw-apply` at boot would otherwise hold `multi-user.target` and dnsmasq for ever, and a hung verify would end the 10-minute checks and counter snapshots, since `OnUnitActiveSec` re-arms only when the unit finishes. A timed-out apply leaves the TV unforwarded (fail-closed) and the unit in `systemctl --failed`. `tests/unit/test_deploy_lint.py` fails when a oneshot unit lacks one.

`install.sh` also writes two drop-ins that are not files in this directory: `nginx.service.d/tvgw.conf` (start after `network-online.target`, `Restart=on-failure`) and `AdGuardHome.service.d/workdir.conf` (`WorkingDirectory=/opt/AdGuardHome`). It masks `nftables.service`, whose `flush ruleset` would wipe our tables and the VPN client's.

## Hardening

`tvgw-analyze.service` is the unit that parses untrusted input (packets from the TV and the internet, log lines), so it is the one that is sandboxed:

- `ProtectSystem=strict` with `ReadWritePaths=/var/lib/tvgw /var/log/tvgw /run/lock`: nothing else is writable.
- `NoNewPrivileges`, `PrivateTmp`, `ProtectHome`, `ProtectKernelTunables`, `ProtectKernelModules`, `ProtectControlGroups`, `RestrictRealtime`.
- `TimeoutStartSec=45min`: a TV that answers and then stalls, or a tshark that never returns, cannot block the next hour. The timer fires again only after the unit finishes.
- `Nice=10` and low I/O priority; `OOMScoreAdjust=500`, so if memory runs out this job dies before the resolver does.

Inside it, tshark runs in its own transient unit (`systemd-run --wait --pipe`) as `nobody:nogroup` with no network, a read-only system, no devices, no new privileges or capabilities, the service syscall set, a 512 MB memory limit and the extract timeout as its runtime limit. `tvgw-backup.service` carries the same sandbox with only `/var/lib/tvgw` writable. `tvgw-pcap.service` runs as `tvgw-pcap` holding only `CAP_NET_RAW` and `CAP_NET_ADMIN`, read-only system, its own directory writable. `tvgw`, `tvgw-flowlog`, `tvgw-verify`, `tvgw-prune` and `tvgw-doh-update` run as root without a sandbox: they need the kernel's firewall, conntrack events or root-only files.

## Reading their journals

```sh
systemctl list-timers 'tvgw-*'               # next and last run of each timer
systemctl --failed                           # a failed tvgw-verify means a FAIL in the last check
journalctl -u tvgw -n 20                     # firewall applies: "tvgw: applied (uplink=direct ...)"
journalctl -u tvgw-analyze -n 50             # hourly: tvcheck warning, ingest summary, reports written
journalctl -u tvgw-verify -n 20              # one line per check, OK or FAIL
journalctl -u tvgw-doh-update -n 20          # "tvgw: N DoH IPs loaded", or why the old list was kept
journalctl -u tvgw-backup -n 7               # one line per daily copy: path, size, quick_check ok
journalctl -u tvgw-pcap -u tvgw-flowlog      # capture restarts and errors
journalctl -k -g 'tvgw-oddport|tvgw-proto|tvgw-lg8080'   # kernel log lines from the firewall
```

`tvgw-analyze` prints `tvgw-analyze: WARNING: ...` when tvcheck finds Live Plus on, when ingest reports problems, and when a report fails to render. `tvgw ingest` writes its own warnings to stderr as `tvgw ingest: WARNING ...`, and the brief repeats them under Coverage.

## Changing a unit

Edit the file here, deploy, and `install.sh` copies it, runs `systemctl daemon-reload`, and restarts `tvgw-pcap` or `tvgw-flowlog` only when its file changed (every restart is a sub-second hole in the evidence). Keep `eth0`, `/var/lib/tvgw` and `/var/log/tvgw` in step with the scripts, which hardcode them too. Changing a timer's cadence changes what the brief can promise: `verify`'s 10 minutes bound how many counted packets a re-apply can lose, and analyze at :20 sets how late TLS names arrive. See [../../docs/architecture.md](../../docs/architecture.md#cadences).
