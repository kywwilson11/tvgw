# Deploy a change

This page owns how a change in the repository reaches a running gateway from your workstation, and how to take one back: the code, AdGuard Home's configuration alone, or one firewall setting. It is for the owner and for contributors whose change is merged. What the installer does at each step is in [what install.sh does](../../deploy/README.md#what-installsh-does).

## Deploying

On your workstation:

1. Run `make gate` and check that it exits 0. CI runs the same.
2. Run `make window PI=<ssh-host>`. On `tv-off`, a commit since the last deploy changes how the gateway treats the TV: deploy in the quiet window ([the quiet window](../../deploy/README.md#the-quiet-window)).
3. Run `make deploy PI=<ssh-host>`. It copies the working tree, uncommitted changes included, to a staging copy on the gateway, `~/tvgw-deploy/`, leaving out what `deploy/rsync.exclude` lists, then runs `sudo tvgw-deploy/deploy/sync-install.sh` there. That script takes the install lock (`/run/tvgw/install.lock`, waiting up to 10 minutes), copies the staging tree to `/opt/tvgw/src/` with `rsync --delete` and runs `install.sh` with the lock handed down, so neither another deploy nor a hardware suite run can overlap it. The installer's steps are in [what install.sh does](../../deploy/README.md#what-installsh-does).
4. Read the end of the output. The installer ends by running `tvgw verify` and exits with its status, so a FAIL fails the deploy. Treat any FAIL as an outage until it is explained ([incidents](../incidents.md)).
5. Run `make hardware PI=<ssh-host>` for the hardware suite. It runs under the same install lock, so no deploy replaces the tree while it runs.
6. On the gateway, run `sudo tvgw adguard diff`. It must exit 0.

On your workstation:

```sh
make gate
make deploy PI=<ssh-host>
make hardware PI=<ssh-host>
```

A push to `main` deploys nothing: no job of any workflow runs on a gateway ([how a change reaches the gateway](../../deploy/README.md#how-a-change-reaches-the-gateway)). `make deploy` does not wait for the quiet window: before you deploy a change to how the gateway treats the TV, ask the gateway with `sudo tvgw tv quiet --wait 0` and choose the moment ([the quiet window](../../deploy/README.md#the-quiet-window)). During a deploy AdGuard Home restarts only when its config changed, and the firewall is re-applied in place rather than restarted: the counters reset, and the stop path's blackout is avoided.

`tvgw adguard apply` run by itself uses the profile inside the installed package, not the files in `/opt/tvgw/src` ([design decision 6](../design-decisions.md#6-adguard-home-is-configured-as-code)). Change policy by deploying; editing the copy on the gateway changes nothing.

## Rolling back the code

On your workstation:

1. Check out the last good commit, and check with `git status` that nothing uncommitted would go with it.
2. Run `make deploy PI=<ssh-host>`. `sync-install.sh` replaces the tree on the gateway with `rsync --delete`, and the installer reinstalls the package, scripts and units and re-applies AdGuard from the older profile.
3. Finish with steps 3 to 5 of [deploying](#deploying).

Rolling back to a commit from before the `ct_events` chain (2026-11-01) takes two more commands on the gateway, since the older installer and `tvgw-apply` leave the conntrack events switch at `0` with no rule to mark the TV, and the flow log would record nothing ([design decision 43](../design-decisions.md#43-the-flow-log-hears-the-tv-alone-and-the-gates-day-starts-at-each-answer)):

```sh
sudo rm /etc/sysctl.d/60-tvgw.conf
sudo sysctl -w net.netfilter.nf_conntrack_events=2
```

## Rolling back AdGuard alone

Each `tvgw adguard apply` that changes something first copies the live config to `AdGuardHome.yaml.bak-<stamp>-<pid>` beside it, where `<stamp>` is the UTC time such as `20261027151500Z`, and never over an earlier copy (`_backup` in `src/tvgw/adguardcfg.py`). The newest copy is the config from before the newest apply. Nothing prunes them.

On the gateway:

1. List the copies and pick one.
2. Stop AdGuard Home, put the copy back, and start it.
3. Run `sudo tvgw verify`; `resolver_rewrite` and `resolver_must_allow` must pass.

On the gateway:

```sh
sudo ls -l /opt/AdGuardHome/AdGuardHome.yaml.bak-*
sudo systemctl stop AdGuardHome
sudo cp /opt/AdGuardHome/AdGuardHome.yaml.bak-<stamp>-<pid> /opt/AdGuardHome/AdGuardHome.yaml
sudo systemctl start AdGuardHome
sudo tvgw verify
```

To go back to the previous binary as well, with the service stopped, copy the `AdGuardHome.bak-<stamp>-<pid>` an upgrade left over `/opt/AdGuardHome/AdGuardHome` together with the `AdGuardHome.yaml.bak-<stamp>-<pid>` of the same stamp, start it, and run `sudo tvgw adguard diff`. Passing the `.bak` binary to `sudo tvgw adguard upgrade` works too, but only while the live YAML is at schema 34 or below: above it, upgrade refuses the live file like apply does ([the schema ceiling](../how-it-works/adguard.md#the-schema-ceiling)).

This leaves AdGuard out of line with the repository: `tvgw adguard diff` reports drift and the hardware suite fails until they match. The next apply of AdGuard's config puts the profile's back, whoever runs it: a deploy or `tvgw adguard apply`, `tvgw undo`, or, with `ANALYST_APPLY=auto`, the analyst after an autonomous block or the hourly check after a revert. Roll the repository back as well, or apply again. `tvgw adguard apply --dry-run` and `tvgw adguard diff` show the changes without making them, and an apply that fails rolls itself back ([AdGuard apply failures](../use/troubleshooting.md#adguard-apply-failures)).

## Rolling back a firewall setting

On the gateway:

1. Edit `/etc/tvgw/tvgw.conf` and put the old value back. `tvgw-apply` reads `UPLINK`, `WAN_IF`, `WAN_GW`, `BLOCK_QUIC`, `STRICT_PORTS`, `DNSGATE`, `DNSGATE_FILL`, `TV_IF`, `TV_NET`, `GW_IP`, `CAPTURE_MODE`, `VPN_IF`, `ADTECH_PORT_WALL` and `PROFILE`, and `TV_IP` with `TV_MAC` for the forward pin ([the settings file](../reference/settings.md)).
2. Run `sudo tvgw-apply`. Prefer it to `systemctl restart tvgw`, because a restart runs the stop path first and the TV is dark for a moment ([the firewall](../../deploy/nftables/README.md)).
3. Run `sudo tvgw verify`.
