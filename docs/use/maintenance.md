# Keep it running

You can look after a gateway that is already running here: see what it updates by itself, update tvgw, back up and restore its record, upgrade its system and its filter, look at the filter's own page, and remove tvgw. Each task says where its commands run.

## Updates

A gateway set up with this release installs its own updates. Each night, inside the hours set for changes (`DEPLOY_WINDOW`, [the settings](../reference/settings.md)), and only while nobody is watching the TV, it installs:

- the security updates of its own system, and of the Raspberry Pi's own software where it runs on one;
- the newer patch releases of AdGuard Home, the filter, for the version it runs;
- with the setting at `all`, which new installs have, the system's other updates and, when tvgw came from the package, newer tvgw releases.

After each install the gateway runs the checks of `tvgw verify`. When the filter or tvgw fails them, it puts the version from before back; the system's own updates cannot be taken back. When an update needs the gateway restarted, it restarts itself in the same hours, and checks itself again once it is back. It never installs a larger version of the filter on its own, never a test release, and never tells anyone anything: there are no alerts. Which setting does what is in [the settings](../reference/settings.md) under `UPDATE_INSTALL`, and why in [design decision 77](../design-decisions.md#77-the-gateway-installs-its-own-security-updates-in-the-quiet-window-checks-each-install-and-rolls-back-what-it-can).

To see what is waiting, what the gateway installed and when, on the gateway:

```sh
tvgw updates
```

It prints one line for tvgw, one for the filter and one for the system, then the last night's run. Each line that needs you names the command to run. The daily brief also says what was installed, in one line, and its New line names a newer tvgw once a week.

To install now instead of waiting for the night, while nobody is watching the TV (the TV may lose its connection for a minute while services restart):

```sh
sudo tvgw updates --now
```

To change what the gateway installs, edit `UPDATE_INSTALL` in `/etc/tvgw/tvgw.conf` (`all`, `security` or `off`), then run the installer again: `sudo /usr/lib/tvgw/deploy/install.sh`, or from a source checkout `sudo ./install.sh` in its `deploy` folder. With `off` the gateway installs nothing itself, and the sections below are how you update it by hand. A gateway installed before this release has no such line, so it installs nothing itself until you add one.

The gateway asks GitHub once a week for tvgw's newest release (`UPDATE_CHECK=weekly`, which new installs have). What it sends, and to whom, is in [what leaves the gateway](../how-it-works/privacy-and-retention.md#updates).

## Upgrade tvgw

An update re-applies everything the install set up. It keeps your settings and your list of blocked addresses, and it re-applies the firewall without a gap. The web filter reloads and the address server restarts, so the TV may pause for a moment: update when nobody is watching.

From a source install, the way the install guide sets the gateway up, on the gateway:

```sh
cd /opt/tvgw/src
git pull
cd deploy
sudo ./install.sh                 # ends with the checks of tvgw verify
```

From the package, run the newest release's installer without setup, on the gateway:

```sh
curl -fsSL https://github.com/kywwilson11/tvgw/releases/latest/download/get.sh | sudo env TVGW_NO_SETUP=1 sh
```

Or download the new release's files yourself, then on the gateway:

```sh
sha256sum -c SHA256SUMS --ignore-missing
sudo apt install ./tvgw_<new-version>-1_<arch>.deb
```

A gateway installed from source stays a source install: the installer refuses to put the package over it.

Either way, check the gateway afterwards with `sudo tvgw verify`. Every line should start with `OK`. What an update restarts, and what it never does, is in [what is idempotent](../../deploy/README.md#what-is-idempotent).

## Back up and restore

The gateway makes a checked copy of its record every night at 03:40, and keeps one copy a day for 7 days in `/var/lib/tvgw/backup/`. The copies are named by the time they were made, in UTC. How they are made is in [backups](../how-it-works/privacy-and-retention.md#backups).

To restore a copy when the record is damaged or lost, on the gateway:

1. List the copies.
2. Stop the timers of every job that writes the record, and wait until none of those jobs is running: no line of `systemctl is-active` may say `active` or `activating`.
3. Move the damaged record aside, with its journal file if there is one.
4. Put the copy in its place, with the right owner and permissions.
5. Check it: `PRAGMA quick_check` must print `ok`, and `tvgw size` shows the row counts.
6. Start the timers again, and read the logs into the restored record.

```sh
sudo ls -l /var/lib/tvgw/backup/
sudo systemctl stop tvgw-analyze.timer tvgw-verify.timer tvgw-autoblock.timer tvgw-analyst.timer tvgw-analyst-weekly.timer tvgw-backup.timer
systemctl is-active tvgw-analyze tvgw-verify tvgw-autoblock tvgw-analyst tvgw-analyst-weekly tvgw-backup
sudo mv /var/lib/tvgw/tvgw.db /var/lib/tvgw/tvgw.db.old
sudo mv /var/lib/tvgw/tvgw.db-journal /var/lib/tvgw/tvgw.db-journal.old   # only if it exists
sudo install -m 640 -o root -g adm /var/lib/tvgw/backup/<copy> /var/lib/tvgw/tvgw.db
sudo tvgw sql "PRAGMA quick_check"                                         # must print ok
tvgw size
sudo systemctl start tvgw-analyze.timer tvgw-verify.timer tvgw-autoblock.timer tvgw-analyst.timer tvgw-analyst-weekly.timer tvgw-backup.timer
sudo tvgw ingest
```

The copy holds the moment it was made. Lines written to the logs since then may be lost, and the brief's Coverage line then shows the gap. Once the restored record checks out, delete the old one, which holds the same personal data:

```sh
sudo rm /var/lib/tvgw/tvgw.db.old
```

If the analyst may block on its own, compare its record with its rules file afterwards, as [taking a rule out](analyst.md#taking-a-rule-out) describes: `sudo tvgw autoblock list` against `sudo cat /var/lib/tvgw/auto.rules`.

## Upgrade the operating system

The reference gateway went from Raspberry Pi OS 12 (bookworm) to 13 (trixie) in place on 2026-10-27. Nothing in tvgw changed for it, and the project's hardware tests then passed unchanged. These steps are for Raspberry Pi OS, and need someone used to the command line.

On the gateway:

1. Run the upgrade detached from your terminal session, with `systemd-run` or inside `tmux`. The network and the remote login restart during the run, and a dropped session must not take the upgrade with it.
2. If `needrestart` is installed, exclude the upgrade's own runner from it first. For a runner named `os-upgrade`, create `/etc/needrestart/conf.d/90-upgrade.conf` holding `$nrconf{override_rc}{qr(^os-upgrade\.service$)} = 0;`.
3. Bring the current release fully up to date with `apt full-upgrade`.
4. Replace `bookworm` with `trixie` in `/etc/apt/sources.list` and `/etc/apt/sources.list.d/raspi.list`, then run `apt update`.
5. Simulate with `apt-get -s full-upgrade`. Stop if the removal list holds a package the gateway needs: `network-manager`, `openssh-server`, `nftables`, `dnsmasq`, `nginx`, `libnginx-mod-stream`, `python3`, `python3-venv`, `tcpdump`, `tshark`, `wireshark-common` or `conntrack`.
6. Run `apt upgrade --without-new-pkgs`, then `apt full-upgrade`, then `apt autoremove --purge` and `dpkg --audit`. Run them with `DEBIAN_FRONTEND=noninteractive` and `-o Dpkg::Options::=--force-confdef -o Dpkg::Options::=--force-confold`, so the gateway's edited files keep their contents.
7. If `apt full-upgrade` stops on "trying to overwrite", the old desktop packages `lxplug-*` and `pi-greeter` collide with the new ones. Finish with `dpkg --configure -a`, `apt-get -f install` and `apt-get full-upgrade -o Dpkg::Options::=--force-overwrite`. A gateway without the desktop does not meet this.
8. Restart the gateway.
9. Rebuild tvgw's Python environment, which was built for the old Python: delete it and run the installer again. It ends with the checks of `tvgw verify`.
10. Check that `systemctl --failed` lists nothing.

On the gateway, for step 9:

```sh
sudo rm -rf /opt/tvgw-venv
cd /opt/tvgw/src/deploy
sudo ./install.sh
```

## Check the blocklists

The shared blocklists the filter subscribes to update themselves every 24 hours, and nobody reviews those updates ([lists change on their own](../how-it-works/adguard.md#lists-change-on-their-own)). Three things watch them: the brief's List changes, its red line for a name that carried content, and a check in `tvgw verify` that each list still blocks a known test name.

To see which list blocks what, on the gateway:

```sh
tvgw sql "select filter_id, count(*) from dns where blocked=1 group by 1"
tvgw sql "select qname, filter_id, datetime(min(t),'unixepoch','localtime') from dns where blocked=1 and filter_id>0 group by 1,2 order by 3 desc limit 20"
sudo tvgw verify | grep list_sentinels
```

## Upgrade AdGuard Home

The filter's program changes only through tvgw, which tests the live settings with the new program first and puts the old one back if it fails. To take the release this tvgw was tested with, downloaded and checked for you, run on the gateway:

```sh
sudo tvgw adguard upgrade --fetch
```

To use a release you downloaded and checked yourself instead:

```sh
sudo tvgw adguard upgrade <new AdGuardHome binary>
```

The filter's own updater is switched off, so its page offers no update. When the filter's upstream servers are not answering, the command says `deferred: upstream down` and changes nothing, so the TV keeps its answers. Run it again once lookups work. How the upgrade checks itself is in [upgrading AdGuard Home](../how-it-works/adguard.md#upgrading-adguard-home).

## Look at AdGuard Home

The filter has its own web page on the gateway, reachable from the gateway itself only. To see how to reach it and where its password is, run on the gateway:

```sh
sudo tvgw adguard ui
```

To open it, make a tunnel from your own computer:

```sh
ssh -L 3000:127.0.0.1:3000 <username>@tvgw.local
```

Then open <http://127.0.0.1:3000> in a browser on your own computer. When tvgw installed the filter, its user name and password are in a file only the administrator can read. On the gateway:

```sh
sudo cat /etc/tvgw/adguard-admin
```

If the filter was set up through its own first-run page, they are the ones you chose there.

Use it to read the log of lookups and the statistics. Do not change filters, allowed names, custom rules, upstream servers or settings there. tvgw owns those, writes them back at its next apply, and reports the difference until then. Make the change in the profile instead ([block or unblock something](blocking.md)).

## Remove tvgw

For a package install, on the gateway:

```sh
sudo apt remove tvgw      # or: sudo apt purge tvgw
```

| | `remove` | `purge` |
|---|---|---|
| The timers, the capture units, then `tvgw.service` | stopped and disabled; the firewall's stop turns forwarding off first, so the TV is dark, never unfiltered | the same |
| `tvgw-guard.service` and its table `inet tvgw_guard` | the unit is disabled and its file removed; the table stays in the kernel until the next boot (`sudo nft delete table inet tvgw_guard` lifts it now) | the same |
| What `install.sh` wrote: `/usr/local/sbin/tvgw-*`, `/usr/local/bin/tvgw`, the units and their drop-ins, the dnsmasq hardening drop-in and the co-tenants' `10-tvgw-not-from-tv.conf` drop-ins (the daemon-reload lifts their filters), the dnsmasq, nginx, NetworkManager and logrotate files, the `include` line in `nginx.conf`, `/opt/tvgw-venv` | removed | removed |
| `/etc/tvgw` (settings, `block4.txt`, the analyst's key) and `/var/log/tvgw` | kept | removed |
| The `tv-lan` connection | kept | deleted |
| The wired connection the install stopped from connecting on its own, so the TV port was tvgw's | left off, since `tv-lan` stays; a message says so | connects on its own again, so the port works as it did before tvgw |
| dnsmasq, when the one-line installer installed it for tvgw | stopped and switched off, since on its own it would answer DNS for your whole network; a message names `sudo apt purge dnsmasq` | the same |
| The other programs apt installed for tvgw (nginx, the capture tools, and NetworkManager on a computer that lacked it) | left installed; nginx serves nothing once tvgw's files are gone | the same; `sudo apt autoremove` removes what nothing else needs |
| `/var/lib/tvgw`: the store, the pcaps, the reports, the TV pairing key | kept | kept, with a message: `sudo rm -rf /var/lib/tvgw` deletes it |
| AdGuard Home, its configuration, its `workdir.conf` drop-in, the `tvgw-pcap` user, the mask on `nftables.service`, avahi's `deny-interfaces` line (its original is `avahi-daemon.conf.tvgw-backup`) | left as they are | left as they are |

Purge keeps the record on purpose: it is up to a year of evidence, and a habitual purge must not destroy it. AdGuard Home keeps the rules tvgw last applied. The system's own firewall service stays masked; unmask it with `sudo systemctl unmask nftables` if you want it.

To give the computer back to ordinary use, purge rather than remove. Removing keeps the TV port set up for tvgw, so that installing tvgw again picks up where it was. Purging gives the port back to the connection it had before, which then gets its address from your router again.

After either one, the TV has no internet through this computer, because tvgw stops passing its traffic on the moment it stops. Move the TV's cable to your router.

Both keep your record of the TV and the key from pairing the TV under `/var/lib/tvgw`. That key could control the TV, so delete the folder when you no longer want them. On the gateway:

```sh
sudo rm -rf /var/lib/tvgw
```

A source install has no remover of its own yet. An engineer follows [remove the install](../project/reinstall-rehearsal.md#remove-the-install), which lists every file the installer wrote.
