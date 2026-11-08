"""(reliability) The gateway's own plain lookups held off the uplink while its VPN's tunnel is down, for a
bounded time, behind `VPN_DNS_SEAL` (design decision 73).

Measured on the reference gateway: a planned reboot on 2026-11-07 stopped the VPN client at shutdown, and
the gateway's own port-53 lookups left by the uplink until it halted (`pi leak: DNS left by the uplink`,
decision 44); every reboot repeats it, and so does the boot before the tunnel comes up. With
`VPN_DNS_SEAL=on` the table `inet tvgw_seal`, apart from tvgw-apply's tables so neither the apply nor
`tvgw.service`'s stop removes it, refuses the gateway's own new connections to port 53 leaving by
`WAN_IF`, but only while its set `held` holds port 53, and every element carries a timeout:

- `tvgw seal hold` puts the port in for `HOLD_SECONDS`: the NetworkManager dispatcher on the uplink's
  `up`, before the tunnel can be up, and `tvgw-vpnseal.service`'s stop, which systemd runs before it stops
  the VPN client (the unit is ordered after it and part of it), at shutdown and at every stop or restart
  of the client.
- `tvgw seal release` takes it out: the dispatcher when the tunnel comes up.
- `tvgw seal sync` loads the table, or with the setting off deletes it, and releases when the tunnel is
  up: the unit's start, so a restart of the unit never leaves a hold behind a working tunnel.

What it never does, by construction: refuse anything of the TV's. The TV's lookups reach AdGuard Home on
the gateway, which asks its upstreams over DoH by address on port 443, which this table does not touch, so
a VPN that never comes up costs the TV nothing; that DoH then leaves by the uplink, encrypted, as decision
44 counts. A hold ends by the kernel's own clock: a tunnel that does not come back within `HOLD_SECONDS`
gets today's behaviour, the lookups leaving by the uplink, and nothing waits on tvgw for it. Two users are
never held: nginx's (www-data), which resolves the vendor's file-service names for the URL filter, so the
TV's app store works through a tunnel outage; and systemd-timesyncd's, so the gateway's clock, on which
every certificate check of the TV's DoH depends, never waits on the VPN. Their lookups still leave by the
uplink while the tunnel is down.
"""

from __future__ import annotations

import os
import pwd
import subprocess
import sys
from collections.abc import Callable

from tvgw import config
from tvgw.config import Settings

TABLE = "tvgw_seal"
SET = "held"
HOLD_SECONDS = 300  # a tunnel that is not back by then gets today's behaviour
PORT = 53
# the users whose lookups are never held, each looked up when the table is written: nginx's (the URL filter,
# so the TV's app store keeps working) and timesyncd's (the gateway's clock)
EXEMPT_USERS = ("www-data", "systemd-timesync")
COMMENT = "seal: the gateway's own plain lookups while the tunnel is down"
ACTIONS = ("hold", "release", "sync")

Runner = Callable[[list[str], str | None], tuple[int, str]]


def exempt_uids(getpwnam: Callable[[str], pwd.struct_passwd] = pwd.getpwnam) -> list[int]:
    """The numeric uids of EXEMPT_USERS this computer has. Numbers, never names, go into the rule: nft
    resolves a name when it loads, and a user that is missing would refuse the whole table."""
    out = []
    for name in EXEMPT_USERS:
        try:
            out.append(getpwnam(name).pw_uid)
        except KeyError:
            continue
    return sorted(set(out))


def ruleset(wan_if: str, uids: list[int]) -> str:
    """The table as one `nft -f` transaction, idempotent: `add` keeps a set and its elements that exist,
    and the chain's one rule is replaced whole, so loading it again never ends a hold."""
    who = f"meta skuid != {{ {', '.join(map(str, uids))} }} " if uids else ""
    return (
        f"add table inet {TABLE}\n"
        f"add set inet {TABLE} {SET} {{ type inet_service; flags timeout; }}\n"
        f"add chain inet {TABLE} output {{ type filter hook output priority filter - 5; policy accept; }}\n"
        f"flush chain inet {TABLE} output\n"
        f'add rule inet {TABLE} output oifname "{wan_if}" {who}meta l4proto {{ tcp, udp }} th dport @{SET}'
        f' counter reject comment "{COMMENT}"\n'
    )


def in_use(s: Settings) -> bool:
    """The setting is on and the gateway names a VPN: VPN_IF=none says it runs none."""
    return s.vpn_dns_seal == "on" and s.vpn_if != "none"


def tunnel_up(s: Settings, exists: Callable[[str], bool]) -> bool:
    dev = config.vpn_interface(s, exists)
    return dev is not None and exists(dev)


def plan(
    s: Settings,
    action: str,
    exists: Callable[[str], bool],
    uids: list[int],
    seconds: int = HOLD_SECONDS,
) -> list[tuple[list[str], str | None, bool]]:
    """The commands for `action`, each (argv, stdin, must succeed). With the setting off (or VPN_IF=none)
    every action deletes the table, so turning it off takes effect at the next event."""
    if action not in ACTIONS:
        raise ValueError(f"unknown action {action!r}")
    if not in_use(s):
        return [(["nft", "delete", "table", "inet", TABLE], None, False)]  # absent already is fine
    text = ruleset(s.wan_if, uids)
    if action == "hold":  # flush, then add: a hold already running gets the full time again
        text += f"flush set inet {TABLE} {SET}\n"
        text += f"add element inet {TABLE} {SET} {{ {PORT} timeout {seconds}s }}\n"
    elif action == "release" or tunnel_up(s, exists):
        text += f"flush set inet {TABLE} {SET}\n"
    return [(["nft", "-f", "-"], text, True)]


def run_nft(argv: list[str], stdin: str | None) -> tuple[int, str]:
    try:
        p = subprocess.run(
            argv, input=stdin, capture_output=True, text=True, encoding="utf-8", errors="replace", timeout=30
        )
    except (OSError, subprocess.TimeoutExpired) as e:
        return 127, str(e)
    return p.returncode, p.stderr.strip()


def main(
    s: Settings,
    action: str,
    run: Runner = run_nft,
    exists: Callable[[str], bool] | None = None,
    uids: list[int] | None = None,
    seconds: int = HOLD_SECONDS,
) -> int:
    """`tvgw seal ACTION`: 0 when done (or nothing to do), 1 with the reason on stderr. It never touches a
    table but its own, so a failure here leaves the TV's path as it was."""
    exists = exists or (lambda dev: os.path.exists(f"/proc/sys/net/ipv4/conf/{dev}"))
    uids = exempt_uids() if uids is None else uids
    for argv, stdin, required in plan(s, action, exists, uids, seconds):
        rc, err = run(argv, stdin)
        if rc != 0 and required:
            print(f"tvgw seal {action}: nft refused the table: {err}", file=sys.stderr)
            return 1
    return 0
