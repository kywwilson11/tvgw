# The journal drop-in

This folder holds tvgw's drop-in for systemd-journald, which sets how long the journal keeps its entries on the gateway. The journal holds the firewall's kernel log lines, which ingest reads into `oddport` and `gate`, dnsmasq's DHCP lines with the TV's MAC address and name, and every unit's output. Why this span is in [design decision 47](../../docs/design-decisions.md#47-the-gateway-keeps-the-least-of-its-own-record-that-the-detectors-need), and every other retention in [how long it is kept](../../docs/how-it-works/privacy-and-retention.md#how-long-it-is-kept).

## Files

| File | What it is | Installed as |
|---|---|---|
| `60-tvgw.conf.template` | The drop-in, with `__JOURNAL_DAYS__` for the span. | `/etc/systemd/journald.conf.d/60-tvgw.conf`, with `JOURNAL_DAYS` from `/etc/tvgw/tvgw.conf` filled in |

## What it sets

| Option | Value | Why |
|---|---|---|
| `Storage=` | `persistent` | On disk, so a reboot before the next hourly ingest loses no kernel line. Raspberry Pi OS ships `40-rpi-volatile-storage.conf`, which keeps the journal in memory. |
| `MaxRetentionSec=` | `JOURNAL_DAYS` days, 14 by default | Journal files whose entries are older are deleted. |
| `MaxFileSec=` | `1day` | journald deletes only whole archived files, and its default of a month per file would keep an entry up to a month past `MaxRetentionSec`. |

## How install.sh applies it

The functions are in the `tvgw-journald` block of `install.sh`, and `tests/unit/test_record_deploy.py` runs them on fixtures.

- `journald_dropin` renders the template and writes it only when it differs from the installed file, then runs `systemctl restart systemd-journald`. journald keeps every service's log stream across a restart (systemd-journald.service(8)); on the systemd Debian 13 ships it reads its configuration only at start. A restart that fails prints a note and does not stop the install; the drop-in then applies at the next boot. An unchanged file restarts nothing.
- `JOURNAL_DAYS=off` removes the drop-in, with one restart, and leaves the journal to the other files.
- `journald_note` reads `systemd-analyze cat-config systemd/journald.conf` and prints a note for every other file that sets `MaxRetentionSec=` to another span. Drop-ins are read in the order of their file names, and the last one wins, so `60-tvgw.conf` overrides a `50-persistent.conf` of your own: the note says so, and that the span now holds for every service on the gateway. A file read after it, such as a `70-*.conf`, wins instead, and the note says that.

## Checking it

On the gateway:

```sh
systemd-analyze cat-config systemd/journald.conf     # every file in the order journald reads them
cat /etc/systemd/journald.conf.d/60-tvgw.conf        # the span tvgw set
journalctl --disk-usage
journalctl --list-boots | head -3                     # the oldest boot still in the journal
```

## Gotchas

- The span holds for every service on the gateway, not only tvgw's. To keep a longer journal of your own, set `JOURNAL_DAYS` to it, or `off`.
- A drop-in with a later name, such as `70-site.conf`, overrides this one; the installer names it in its note.
- The package's `postrm` removes the drop-in; journald reads the change at its next start.
