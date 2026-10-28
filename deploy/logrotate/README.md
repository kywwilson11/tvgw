# Log rotation

This folder holds the logrotate policy for the gateway's own logs in `/var/log/tvgw/`; the system's logrotate applies it. How long each kind of data is kept, these logs included, is in [how long it is kept](../../docs/privacy-and-retention.md#how-long-it-is-kept).

## Files

| File | What it is | Installed as |
|---|---|---|
| `tvgw` | The policy for `/var/log/tvgw/*.log`. | `/etc/logrotate.d/tvgw` |

## The logs it rotates

| Log | Writer | Ingested into |
|---|---|---|
| `flows.log` | `tvgw-flowlog` (conntrack) | `flows` |
| `gfts-tls.log` | nginx, the TLS passthrough | not ingested |
| `gfts.log` | nginx, the URL filter | `http`, with `src='gfts'` |

## The policy, line by line

| Option | Why |
|---|---|
| `weekly` | One rotation a week. |
| `rotate 12` | 12 rotated copies are kept. |
| `compress` | Rotated copies are gzipped. |
| `delaycompress` | The newest rotated copy, `<log>.1`, stays plain. The ingest reads the lines written between its last run and a rotation from `<log>.1` (src/tvgw/logtail.py), which only works while that file is uncompressed. |
| `missingok` | A log that does not exist yet is not an error. |
| `notifempty` | An empty log is not rotated. |
| `copytruncate` | Each log is copied and then truncated in place. conntrack's output is a shell redirect that cannot reopen its file, and nginx is sent no signal to reopen its logs, so the writers keep the same file. |

## Checking it

On the Pi:

```sh
sudo logrotate -d /etc/logrotate.d/tvgw       # dry run: what would rotate; changes nothing
ls -l /var/log/tvgw/                          # the logs and their rotated copies
sudo tvgw ingest                              # after a rotation: no warnings, no lost lines
```

After a rotation, `flows.log.1` and `gfts.log.1` stay plain until the next one, and then become `.2.gz`. The ingest looks only at the live file and `.1`.

## Changing it

Edit `deploy/logrotate/tvgw`, run `make gate` and deploy; the hardware suite checks that the installed file equals the checkout. A new log in `/var/log/tvgw/` is rotated by the same rule through the `*.log` glob. To have it ingested too, it needs a parser and an ingest source ([the package](../../src/tvgw/README.md)).

## Gotchas

- `copytruncate` keeps a file's mode. A log created fresh later gets its writer's mode; `install.sh` sets the modes of existing logs on every run ([where it lives and who can read it](../../docs/privacy-and-retention.md#where-it-lives-and-who-can-read-it)).
- Dropping `delaycompress` would lose the lines written shortly before each rotation.
