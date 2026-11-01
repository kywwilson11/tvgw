# Log rotation

This folder holds the logrotate policy for the gateway's own logs: the three in `/var/log/tvgw/` and the hourly TV-reading log in `/var/lib/tvgw/`; the system's logrotate applies it. How long each kind of data is kept, these logs included, is in [how long it is kept](../../docs/privacy-and-retention.md#how-long-it-is-kept), and why these spans in [design decision 47 (record)](../../docs/design-decisions.md#47-record-the-gateway-keeps-the-least-of-its-own-record-that-the-detectors-need).

## Files

| File | What it is | Installed as |
|---|---|---|
| `tvgw` | The policy, one stanza per span. | `/etc/logrotate.d/tvgw` |

## The logs it rotates

| Log | Writer | Ingested into | Rotated | Old copies |
|---|---|---|---|---|
| `/var/log/tvgw/flows.log` | `tvgw-flowlog` (conntrack) | `flows` | weekly | 2: up to 3 weeks |
| `/var/log/tvgw/gfts.log` | nginx, the URL filter | `http`, with `src='gfts'` | weekly | 2 |
| `/var/log/tvgw/gfts-tls.log` | nginx, the TLS passthrough | not ingested | weekly | 1: up to 2 weeks |
| `/var/lib/tvgw/tvcheck-history.log` | `tvgw-analyze`, a power and app line an hour | `tvstate` | daily | 35 |

The ingest reads only the live file and `.1`, so nothing older than the newest rotated copy is read by anything; the older copies are for an owner troubleshooting by hand.

## The policy, line by line

| Option | Why |
|---|---|
| A path per log, no glob | A glob would name `gfts-tls.log` in two stanzas, and logrotate refuses a log named twice. `tests/unit/test_record_deploy.py` fails when a log the code or the units write is in no stanza. |
| `weekly` or `daily` | One rotation a week for the logs, a day for the TV readings. |
| `rotate 2`, `1` or `35` | The old copies kept. |
| `compress` | Rotated copies are gzipped. |
| `delaycompress` | The newest rotated copy, `<log>.1`, stays plain. The ingest reads the lines written between its last run and a rotation from `<log>.1` (src/tvgw/logtail.py), which only works while that file is uncompressed. |
| `missingok` | A log that does not exist yet is not an error. |
| `notifempty` | An empty log is not rotated. |
| `copytruncate` | Each log is copied and then truncated in place. conntrack's output is a shell redirect that cannot reopen its file, nginx is sent no signal to reopen its logs, and `tvgw-analyze` appends with `>>`, so the writers keep the same file. |

When a count is lowered, logrotate removes only the copy just past the new count at the next rotation and never the ones beyond it. `install.sh` therefore removes, on every run, each `<log>.N` or `<log>.N.gz` whose N is past its log's count (`trim_rotations`, in the `tvgw-journald` block).

## Checking it

On the Pi:

```sh
sudo logrotate -d /etc/logrotate.d/tvgw       # dry run: what would rotate; changes nothing
ls -l /var/log/tvgw/ /var/lib/tvgw/tvcheck-history.log*   # the logs and their rotated copies
sudo tvgw ingest                              # after a rotation: no warnings, no lost lines
```

After a rotation, `flows.log.1` and `gfts.log.1` stay plain until the next one, and then become `.2.gz`. The ingest looks only at the live file and `.1`.

## Changing it

Edit `deploy/logrotate/tvgw`, run `make gate` and deploy; the hardware suite checks that the installed file equals the checkout. A new log needs its own path in a stanza, or the unit test fails. To have it ingested too, it needs a parser and an ingest source ([the package](../../src/tvgw/README.md)), and `tvgw forget` must classify it (`LOG_ENTRIES` in src/tvgw/forget.py covers every `*.log` in `/var/log/tvgw`).

## Gotchas

- `copytruncate` keeps a file's mode. A log created fresh later gets its writer's mode; `install.sh` sets the modes of existing logs on every run ([where it lives and who can read it](../../docs/privacy-and-retention.md#where-it-lives-and-who-can-read-it)).
- Dropping `delaycompress` would lose the lines written shortly before each rotation.
- logrotate refuses a log in a directory writable by a group other than root. `/var/lib/tvgw` is `2751` and `/var/log/tvgw` `2750`, both without group write.
