"""The flow logger's event socket, found and read through /proc: how many events the kernel could not
queue to it.

`tvgw-flowlog` is `conntrack -E`, which holds two NETLINK_NETFILTER sockets: the request socket it
opens first, which its `-b` option sizes, and the event socket it opens for `-E` and reads from, which
`-b` never reaches (conntrack-tools 1.4.8). When an event finds the event socket's queue full the
kernel drops it and counts it in that socket's `Drops` column of /proc/net/netlink, and conntrack
learns of it only as an ENOBUFS line in its journal, which a reboot erases. Reading the counter
makes the loss a number in the store (`tvgw verify --record`), whatever the journal kept (design
decision 43).

The two sockets are told apart by the column the kernel prints beside each: a socket subscribed to
multicast groups (conntrack's events are groups) has non-zero `Groups`; the request socket has none.
Each socket is found by its inode: /proc/<pid>/fd/<n> links read `socket:[<inode>]`, and the same
inode is the last column of /proc/net/netlink. The process is the unit's main process and anything it
started, so a wrapper in front of conntrack would not hide the socket.

Everything here reads files under a root that is a parameter, so tests build a fake /proc.
"""

from __future__ import annotations

import os
import re
from dataclasses import dataclass

NETLINK_NETFILTER = 12  # linux/netlink.h: conntrack's and nf_tables' messages
# the fw_counters series `tvgw verify --record` stores the drop count under: packets = drops since the
# event socket was opened. A restart opens a new socket at zero, which queries.fw_activity reads as a
# reset, as it reads a re-applied firewall counter
DROPS_RULE = "flowlog: event socket drops"
_SOCKET = re.compile(r"socket:\[(\d+)\]")


@dataclass(frozen=True)
class NetlinkSocket:
    """One row of /proc/net/netlink: the fields this module uses."""

    inode: int
    protocol: int
    portid: int
    groups: int
    drops: int


def parse_proc_netlink(text: str) -> list[NetlinkSocket]:
    """The rows of /proc/net/netlink, read by the header's column names (`Eth` is the protocol, `Pid`
    the port id, `Groups` hexadecimal), so a kernel that adds a column does not shift the others. A
    row that does not parse is skipped: this is a reading of the kernel's state, not a judgement."""
    lines = text.splitlines()
    if not lines:
        return []
    cols = {name: i for i, name in enumerate(lines[0].split())}
    need = ("Eth", "Pid", "Groups", "Drops", "Inode")
    if any(name not in cols for name in need):
        return []
    out = []
    for line in lines[1:]:
        f = line.split()
        try:
            out.append(
                NetlinkSocket(
                    inode=int(f[cols["Inode"]]),
                    protocol=int(f[cols["Eth"]]),
                    portid=int(f[cols["Pid"]]),
                    groups=int(f[cols["Groups"]], 16),
                    drops=int(f[cols["Drops"]]),
                )
            )
        except (IndexError, ValueError):
            continue
    return out


def _ppid(stat: str) -> int | None:
    """The parent pid from /proc/<pid>/stat. The command name is in parentheses and may itself hold
    spaces and parentheses, so the fields are counted from the last `)`."""
    try:
        return int(stat[stat.rindex(")") + 1 :].split()[1])
    except (ValueError, IndexError):
        return None


def process_tree(pid: int, proc: str = "/proc") -> list[int]:
    """`pid` and every process below it, from each process's parent in /proc/<n>/stat. A process that
    ends while it is read is left out."""
    children: dict[int, list[int]] = {}
    try:
        names = os.listdir(proc)
    except OSError:
        return [pid]
    for name in names:
        if not name.isdigit():
            continue
        try:
            with open(os.path.join(proc, name, "stat"), encoding="utf-8", errors="replace") as fh:
                parent = _ppid(fh.read())
        except OSError:
            continue
        if parent is not None:
            children.setdefault(parent, []).append(int(name))
    tree, todo = [], [pid]
    while todo:
        p = todo.pop()
        if p in tree:
            continue
        tree.append(p)
        todo.extend(children.get(p, ()))
    return tree


def socket_inodes(pid: int, proc: str = "/proc") -> set[int]:
    """The inodes of the sockets process `pid` holds open. PermissionError propagates: another user's
    descriptors need root, and the caller must say so rather than report no socket."""
    fd_dir = os.path.join(proc, str(pid), "fd")
    try:
        fds = os.listdir(fd_dir)
    except FileNotFoundError:
        return set()
    out = set()
    for fd in fds:
        try:
            m = _SOCKET.fullmatch(os.readlink(os.path.join(fd_dir, fd)))
        except OSError:  # closed between the listing and the read
            continue
        if m:
            out.add(int(m.group(1)))
    return out


def event_sockets(pid: int, proc: str = "/proc") -> list[NetlinkSocket]:
    """The NETLINK_NETFILTER sockets subscribed to event groups that `pid` or its children hold. The
    netlink table is the reader's network namespace's, which is the logger's on the gateway."""
    held = set()
    for p in process_tree(pid, proc):
        held |= socket_inodes(p, proc)
    try:
        with open(os.path.join(proc, "net", "netlink"), encoding="utf-8", errors="replace") as fh:
            rows = parse_proc_netlink(fh.read())
    except OSError:
        return []
    return [r for r in rows if r.inode in held and r.protocol == NETLINK_NETFILTER and r.groups]
