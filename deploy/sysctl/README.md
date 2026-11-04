# Kernel switches

This folder holds the kernel switches the gateway needs from boot, as a `sysctl.d` file. It is for whoever changes what conntrack records or reads why the flow log hears only the TV. `install.sh` installs the file on every run; `tvgw-apply` sets the same keys at every apply, so the file and the script must agree, and `tests/unit/test_events_apply.py` keeps them equal.

## Files

| File | What it is | Installed as |
|---|---|---|
| `60-tvgw.conf` | The three conntrack switches below. | `/etc/sysctl.d/60-tvgw.conf`, by `install.sh` on every run; the .deb's postrm removes it |

## The switches

| Key | Value | Why |
|---|---|---|
| `net.netfilter.nf_conntrack_acct` | `1` | Packet and byte counts on every connection: the flow log's sizes, which the payload gate and the brief read. |
| `net.netfilter.nf_conntrack_timestamp` | `1` | Start and stop times on every connection: the flow log's timestamps. |
| `net.netfilter.nf_conntrack_events` | `0` | No connection makes conntrack events unless the firewall asks for them. The `ct_events` chain in `inet tvgw` asks for the TV's new connections (`ct event set destroy`), so `tvgw-flowlog` hears the TV alone, and the gateway's own connections (the torrent client, the VPN, the resolver's upstreams) never fill its socket ([design decision 43](../../docs/design-decisions.md)). |

`tvgw-apply` writes the first two before it loads the firewall and the third only after `inet tvgw`, which holds `ct_events`, has loaded: set earlier, the TV's connections opened in between would have no events at all. It also sets `nf_conntrack_tcp_timeout_established=7440`, which only matters once conntrack runs and so stays in the script alone.

## At boot

The `net.netfilter` keys exist only once the `nf_conntrack` module is loaded. `systemd-sysctl` runs early in boot, and when the module is not loaded yet it logs `Couldn't write ... ignoring: No such file or directory` for each key and carries on. `tvgw.service` then runs `tvgw-apply`, which loads the module and sets all three. So the file changes nothing at boot unless something loaded conntrack earlier; it is what `sysctl --system` and a reader of `/etc/sysctl.d` find, and it keeps the value the script sets from being a surprise.

## Checking it

On the gateway:

```sh
sysctl net.netfilter.nf_conntrack_acct net.netfilter.nf_conntrack_timestamp net.netfilter.nf_conntrack_events
sudo nft list chain inet tvgw ct_events      # the rule that marks the TV's connections
awk '$2==12 && $4!="00000000"' /proc/net/netlink   # every conntrack and nftables event listener
```

`tvgw verify` checks the switch and the rule together (`flowlog_events`, [what tvgw verify checks](../../docs/reference/verify-checks.md)).

## Changing it

Edit the file and the matching `sysctl` line of `tvgw-apply` together, run `make gate` and deploy.

Going back to the kernel's default for events, where every connection makes events while anyone listens, takes three steps: remove the `nf_conntrack_events` line here and the one in `tvgw-apply`, deploy, then run `sudo sysctl -w net.netfilter.nf_conntrack_events=2` once, since neither file sets the old value back. A rollback to a release older than the `ct_events` chain needs the same command and `sudo rm /etc/sysctl.d/60-tvgw.conf`: the old script and installer leave both in place and have no rule to mark the TV, so the flow log would record nothing.
