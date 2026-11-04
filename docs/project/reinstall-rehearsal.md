# Rehearsing a cold install

This page owns the rehearsal of a cold install on the owner's own gateway: what to save, how to remove the from-source install completely, how to install again as a stranger would, what to compare, how to put the record back, and how to roll back. It is for the owner, whose gateway is the only machine this can be tried on, so it runs at a time nobody needs the TV. The install itself is the one in [the install guide](../install/README.md) and [tvgw setup](../install/README.md#run-setup); this page adds the steps around it.

## Before you start

Pick a slot of three hours when nobody needs the TV, and expect to read a brief the next day. The TV is off for saving and removal, and on for the install and the checks:

| Phase | TV | About |
|---|---|---|
| [Save](#save-the-gateways-state) | off | 15 min |
| [Remove](#remove-the-install) | off | 20 min, with a reboot |
| [Install](#install-as-a-stranger-would) | on, someone at the remote for pairing | 30 to 60 min |
| [Compare](#compare) | on | 30 min, then the next day's brief |
| [Restore](#restore-the-saved-record) | off or on | 20 min |

- Do not push to `main` and do not run `make deploy` until the rehearsal ends: a push deploys to the gateway through the runner ([how a change reaches the gateway](../../deploy/README.md#how-a-change-reaches-the-gateway)). If the runner is installed as a service, stop it for the rehearsal (`sudo systemctl stop 'actions.runner.*'`) and start it again at the end.
- Choose the path. On 2026-11-01 the repository has no release, so the cold install is the checkout with `tvgw setup`. Once a release carries a .deb, rehearse that path instead, with [installing from the .deb](../install/README.md#install-the-package) in place of [install as a stranger would](#install-as-a-stranger-would).
- AdGuard Home stays installed. A stranger installs it and finishes its wizard before tvgw, and its YAML keeps the configuration tvgw last applied, so this rehearsal does not test the wizard step.

## Save the gateway's state

TV off. Every saved file holds the TV's MAC address, the router's address, the API key or the household's viewing record, so keep the copies root-only on the gateway and in `backups/` on your workstation, which git ignores, and never anywhere else.

1. Record what the gateway says now:
   ```sh
   sudo install -d -m 700 /root/tvgw-rehearsal
   sudo sh -c 'tvgw verify > /root/tvgw-rehearsal/verify-before.txt'
   sudo sh -c 'tvgw report > /root/tvgw-rehearsal/report-before.txt'
   sudo sh -c 'nft list tables > /root/tvgw-rehearsal/tables-before.txt'
   ```
2. Make a checked copy of the store ([backups](../how-it-works/privacy-and-retention.md#backups)) and save it with the files the install cannot make again:
   ```sh
   sudo tvgw backup
   sudo cp -a /var/lib/tvgw/backup /root/tvgw-rehearsal/store
   sudo cp -a /etc/tvgw /root/tvgw-rehearsal/etc-tvgw                    # tvgw.conf, block4.txt, claude.key, guard.nft
   sudo cp -a /var/lib/tvgw/lgtv-keys.sqlite /root/tvgw-rehearsal/       # the TV pairing key store
   sudo cp -a /var/lib/tvgw/auto.rules /root/tvgw-rehearsal/             # only if it exists
   sudo cp -a /opt/AdGuardHome/AdGuardHome.yaml /root/tvgw-rehearsal/
   sudo cp -a /etc/systemd/system/AdGuardHome.service.d /root/tvgw-rehearsal/
   sudo cp -a /etc/avahi/avahi-daemon.conf /root/tvgw-rehearsal/         # only if avahi is installed
   sudo cp -a /etc/nginx/nginx.conf /root/tvgw-rehearsal/
   ```
3. On your workstation, pull a second copy:
   ```sh
   make backup PI=<ssh-host>
   ssh <ssh-host> 'sudo tar -C /root -czf - tvgw-rehearsal' > backups/tvgw-rehearsal.tgz
   ```

The reports, the older store copies and the pcaps stay in `/var/lib/tvgw`, which the removal moves aside whole rather than deletes. That moved directory is the rollback.

## Remove the install

TV off. This removes everything `deploy/install.sh` and `deploy/sync-install.sh` put on the gateway. The file list is the package's `postrm`, which `tests/unit/test_packaging.py` keeps equal to what `install.sh` writes, so the steps run it from the saved checkout ([removing](../use/maintenance.md#remove-tvgw)).

1. Stop the timers, then the capture and the logs, then the firewall. The firewall's stop turns forwarding off before it deletes the table, so the TV is dark, never unfiltered:
   ```sh
   sudo systemctl disable --now tvgw-analyze.timer tvgw-prune.timer tvgw-doh-update.timer tvgw-verify.timer tvgw-backup.timer tvgw-analyst.timer tvgw-analyst-weekly.timer tvgw-autoblock.timer
   sudo systemctl disable --now tvgw-pcap.service tvgw-pcap-headers.service tvgw-flowlog.service tvgw-dnsgate.service
   sudo systemctl disable --now tvgw.service
   ```
2. Disable the guard's unit. Do not mask it: `install.sh` puts the unit file in `/etc/systemd/system`, and `systemctl mask` refuses a unit whose file is there ([removing the guard in an emergency](../use/troubleshooting.md#removing-the-guard-in-an-emergency)). It refuses a stop too, so the table stays loaded until you delete it in step 6:
   ```sh
   sudo systemctl disable tvgw-guard.service
   ```
3. Move the state, the logs, the settings and the checkout aside:
   ```sh
   sudo mv /var/lib/tvgw /var/lib/tvgw.rehearsal
   sudo mv /var/log/tvgw /var/log/tvgw.rehearsal
   sudo mv /etc/tvgw /etc/tvgw.rehearsal
   sudo mv /opt/tvgw/src /opt/tvgw/src.rehearsal
   ```
4. Remove what `install.sh` wrote outside those directories: the scripts in `/usr/local/sbin`, `/usr/local/bin/tvgw`, every `tvgw*` unit with its drop-ins, the timers' schedule drop-ins, the capture's `tv-side.conf`, nginx's `tvgw.conf` drop-in and its URL-filter and passthrough files, the `include` line in `nginx.conf`, the dnsmasq config and its hardening drop-in, the co-tenants' `10-tvgw-not-from-tv.conf` drop-ins, the NetworkManager config and dispatcher, the logrotate file, the journald drop-in, `/etc/sysctl.d/60-tvgw.conf`, `/opt/tvgw-venv` and the `tv-lan` connection. `purge` also removes `/etc/tvgw` and `/var/log/tvgw`, which step 3 already moved:
   ```sh
   sudo sh /opt/tvgw/src.rehearsal/packaging/scripts/postrm purge
   ```
   With the drop-ins gone, dnsmasq, nginx and the co-tenants (`CO_TENANT_UNITS`) run their stock units again: the script reloads systemd, which lifts the co-tenants' `IPAddressDeny`, and restarts dnsmasq without its hardening. nginx only reloads, so its sandbox lifts at the reboot in step 7.
5. Undo what the package's removal leaves on purpose, so the gateway is as a stranger's would be:
   ```sh
   sudo rm -f /etc/systemd/system/AdGuardHome.service.d/workdir.conf /etc/systemd/system/AdGuardHome.service.d/20-tvgw-no-update.conf
   sudo systemctl daemon-reload                                                       # AdGuard keeps running as it is until the install
   sudo cp /etc/avahi/avahi-daemon.conf.tvgw-backup /etc/avahi/avahi-daemon.conf     # only if the backup exists; diff the two first
   sudo systemctl unmask nftables.service
   sudo userdel tvgw-pcap
   ```
6. Delete the firewall tables that are still loaded. The guard needs this by hand, since its unit has no stop; the DNS gate's and the capture's tables outlive `tvgw.service`'s stop:
   ```sh
   sudo nft delete table inet tvgw_guard
   sudo nft list tables                       # delete any other tvgw table it lists: sudo nft delete table inet <name>
   ```
7. Reboot, so the sysctls, the guard and every daemon start from their stock state, then check that nothing of tvgw is left:
   ```sh
   sudo reboot
   sudo nft list tables | grep tvgw           # nothing
   systemctl list-unit-files 'tvgw*'          # 0 unit files listed
   ls /usr/local/bin/tvgw /opt/tvgw-venv      # both missing
   ```

## Install as a stranger would

TV on and cabled to `eth0`, with someone at the remote for the pairing prompt. Follow [the install guide](../install/README.md) from its first step, with these notes:

1. Step 1, the packages: run both commands. apt reports them installed; the point is that the command line works as written.
2. Step 2, AdGuard Home: already installed and past its wizard; skip it.
3. Step 3, the checkout: clone from GitHub into the empty `/opt/tvgw/src`:
   ```sh
   git clone https://github.com/kywwilson11/tvgw.git /opt/tvgw/src
   ```
4. Take the guided way, as the quick start offers:
   ```sh
   cd /opt/tvgw/src
   sudo apt install python3-yaml
   sudo PYTHONPATH=src python3 -m tvgw setup
   ```
   On this first install the TV side has no address yet, so setup offers to run the installer first, and the installer stops with `TV not identified`, as [the guided path](../install/README.md#what-setup-does) says it should. Setup then finds the TV; pick it, accept the offered `WAN_IF` and `WAN_GW`, and answer yes to pairing. Accept the TV's prompt with the remote within a minute ([pairing](../tv/lg-webos.md#pair-the-tv)). Setup ends with `Result: the gateway holds.` or `Result: NOT done.`
5. To rehearse the unattended path instead, give setup the saved settings as its answers file, since a copy of a working `tvgw.conf` is a valid one ([the unattended path](../install/advanced.md#install-with-no-one-at-the-keyboard)). `SETUP_PAIR=yes` still puts the prompt on the TV, so someone must be at the remote:
   ```sh
   sudo install -m 600 /root/tvgw-rehearsal/etc-tvgw/tvgw.conf /root/tvgw-answers.conf
   echo 'SETUP_PAIR=yes' | sudo tee -a /root/tvgw-answers.conf
   sudo PYTHONPATH=src python3 -m tvgw setup --answers /root/tvgw-answers.conf --yes
   sudo rm /root/tvgw-answers.conf
   ```
6. Note every place where the quick start or setup was wrong, unclear or slower than it says. Those notes are the rehearsal's result.

## Compare

TV on. Compare the fresh gateway with what you saved:

1. Every line of `sudo tvgw verify` starts with `OK`, and the checks are the same as before:
   ```sh
   sudo tvgw verify
   sudo awk '{sub(/:$/, "", $2); print $2}' /root/tvgw-rehearsal/verify-before.txt > /tmp/checks-before
   sudo tvgw verify | awk '{sub(/:$/, "", $2); print $2}' | diff /tmp/checks-before -   # no output: the same checks
   ```
2. The firewall tables are the ones before:
   ```sh
   sudo nft list tables | diff <(sudo cat /root/tvgw-rehearsal/tables-before.txt) -
   ```
3. The settings differ only where the guided path set its defaults and where the template sets a new install's own, such as `BRIEF_STYLE=plain`. Every other difference is a setting you chose before and must set again (step 1 of [restore the saved record](#restore-the-saved-record)):
   ```sh
   sudo diff /root/tvgw-rehearsal/etc-tvgw/tvgw.conf /etc/tvgw/tvgw.conf
   ```
4. Use the TV: open each app the household uses and play something in it, and open the Content Store. Each must work as before. Then read the TV's settings, which must say Live Plus is off and the Wi-Fi paths disconnected:
   ```sh
   sudo tvgw tvcheck
   ```
5. After an hour of use, read the last hours' report. The Coverage line has no `NOT ASSESSED` source, "Firewall held" shows `DNS to AdGuard` above 0 and `IPv6 0`, and the clock hosts were looked up and not blocked:
   ```sh
   sudo tvgw verify --record
   tvgw report
   ```
6. The next day, read `tvgw brief --full` (the fresh install has the template's `BRIEF_STYLE=plain`, so `tvgw brief` alone prints the plain brief) and compare it with `report-before.txt`: the same categories blocked, no red line that was not there before.

## Restore the saved record

TV off or on. The fresh install holds an empty store and the template's choices. Put the saved ones back:

1. Settings and lists. Copy back the saved files, then run the installer once so the firewall, AdGuard Home and the units take them:
   ```sh
   sudo install -m 640 -o root -g adm /root/tvgw-rehearsal/etc-tvgw/tvgw.conf /etc/tvgw/tvgw.conf
   sudo install -m 644 /root/tvgw-rehearsal/etc-tvgw/block4.txt /etc/tvgw/block4.txt
   sudo install -m 600 /root/tvgw-rehearsal/etc-tvgw/claude.key /etc/tvgw/claude.key       # only if it was saved
   cd /opt/tvgw/src/deploy
   sudo ./install.sh
   ```
2. The store. Follow [back up and restore](../use/maintenance.md#back-up-and-restore), taking the copy from `/root/tvgw-rehearsal/store/` in its step 5. The rows the fresh install recorded since the install are replaced by the copy.
3. The machine's rules, if `auto.rules` was saved. Then compare the record with the file, as step 9 of restoring a backup says:
   ```sh
   sudo install -m 640 -o root -g adm /root/tvgw-rehearsal/auto.rules /var/lib/tvgw/auto.rules
   sudo tvgw adguard apply
   sudo tvgw autoblock list
   ```
4. The pairing key. When the fresh pairing worked, keep the new key. When it was skipped or failed, put the saved key store back and read the TV with it:
   ```sh
   sudo install -m 600 -o root -g root /root/tvgw-rehearsal/lgtv-keys.sqlite /var/lib/tvgw/lgtv-keys.sqlite
   sudo tvgw tvcheck
   ```
5. The reports and the older store copies, from the moved state directory:
   ```sh
   sudo cp -a /var/lib/tvgw.rehearsal/reports/. /var/lib/tvgw/reports/
   sudo cp -a /var/lib/tvgw.rehearsal/backup/. /var/lib/tvgw/backup/
   ```
6. Check, and start the runner again if you stopped it:
   ```sh
   sudo tvgw ingest
   sudo tvgw verify
   tvgw size
   sudo systemctl start 'actions.runner.*'
   ```
7. After two days of normal briefs, delete the rehearsal's copies, which hold the whole viewing record and both keys:
   ```sh
   sudo rm -rf /var/lib/tvgw.rehearsal /var/log/tvgw.rehearsal /etc/tvgw.rehearsal /opt/tvgw/src.rehearsal /root/tvgw-rehearsal
   ```
   On your workstation, delete `backups/tvgw-rehearsal.tgz` once you no longer need it.

## Roll back

If the install stops, `tvgw verify` keeps a `FAIL` you cannot fix in the slot, or the TV does not stream, put the old gateway back from the moved directories. The TV stays dark meanwhile, never unfiltered ([design decision 5](../design-decisions.md#5-fail-closed)).

1. Stop whatever the fresh install started, as in step 1 of [remove the install](#remove-the-install).
2. Put the moved directories back:
   ```sh
   sudo rm -rf /var/lib/tvgw /var/log/tvgw /etc/tvgw /opt/tvgw/src
   sudo mv /var/lib/tvgw.rehearsal /var/lib/tvgw
   sudo mv /var/log/tvgw.rehearsal /var/log/tvgw
   sudo mv /etc/tvgw.rehearsal /etc/tvgw
   sudo mv /opt/tvgw/src.rehearsal /opt/tvgw/src
   ```
3. If AdGuard Home's configuration changed, put the saved YAML back:
   ```sh
   sudo systemctl stop AdGuardHome
   sudo cp -a /root/tvgw-rehearsal/AdGuardHome.yaml /opt/AdGuardHome/AdGuardHome.yaml
   sudo systemctl start AdGuardHome
   ```
4. Install from the old tree, as a deploy does, and check:
   ```sh
   cd /opt/tvgw/src/deploy
   sudo ./install.sh
   sudo tvgw verify
   ```
5. If `install.sh` itself stops, read its last line and [troubleshooting](../use/troubleshooting.md). From your workstation, `make deploy PI=<ssh-host>` installs your checkout the same way.
6. Write down what failed. A step of the quick start that failed on the owner's own gateway fails for a stranger too, and is fixed in the docs or the code before the next rehearsal.
