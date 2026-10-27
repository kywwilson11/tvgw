# logrotate: the gateway's logs

`/var/log/tvgw/` holds three logs, all written by root:

| Log | Writer | Ingested |
|---|---|---|
| `flows.log` | `tvgw-flowlog` (conntrack) | yes, into `flows` |
| `gfts.log` | nginx, the URL filter | yes, into `http` with `src='gfts'` |
| `gfts-tls.log` | nginx, the TLS passthrough | no |

## Files

| File | Installed as |
|---|---|
| `tvgw` | `/etc/logrotate.d/tvgw` |

The policy for `/var/log/tvgw/*.log`: `weekly`, `rotate 12` (about 12 weeks kept), `compress`, `delaycompress`, `missingok`, `notifempty`, `copytruncate`.

## Why these options

- **`copytruncate`.** conntrack's output is a shell redirect, which cannot reopen a file, and this config sends nginx no signal to reopen its logs. So each file is copied and truncated in place instead of renamed, and the writers keep writing to the same file.
- **`delaycompress`.** The ingest reads lines written between its last run and a rotation from `path.1` (see `src/tvgw/logtail.py`). That only works while `path.1` is still uncompressed. Without `delaycompress`, those lines would be lost at every rotation.

## Checking it

```sh
sudo logrotate -d /etc/logrotate.d/tvgw     # dry run: what would rotate, changes nothing
ls -l /var/log/tvgw/                        # expect root:adm and -rw-r----- on the logs
sudo tvgw ingest                            # after a rotation: no warnings, no lost lines
```

After a rotation, `flows.log.1` and `gfts.log.1` stay uncompressed for a week, then become `.2.gz` and so on. The ingest only ever looks at the live file and `.1`.

## Changing it

Edit `deploy/logrotate/tvgw` and deploy. If you add a log to `/var/log/tvgw/`, it is rotated by the same rule because of the `*.log` glob. If you want it ingested too, it needs a parser and an ingest step; see [../../src/tvgw/README.md](../../src/tvgw/README.md#how-to-change-or-extend-it).

## Gotchas

- `install.sh` sets `/var/log/tvgw` to `2750 root:adm` and existing logs to `640`. A copytruncated file keeps its mode. A log created fresh later gets its writer's default mode, but the directory still keeps other users out.
- Retention here is separate from the store's. The logs keep about 12 weeks; the store keeps `DB_DAYS` (365 by default). See [../../docs/privacy-and-retention.md](../../docs/privacy-and-retention.md).
