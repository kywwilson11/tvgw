"""The flow logger's event socket, found through a fake /proc: the netlink table, the process tree and
the descriptors, laid out as the kernel lays them out (design decision 43)."""

import os

import pytest

from tvgw import flowlog

# /proc/net/netlink as af_netlink.c prints it: the conntrack request socket (groups 0), the event
# socket (group 4, the DESTROY group), another process's event socket, and a route socket
NETLINK = """sk               Eth Pid        Groups   Rmem     Wmem     Dump  Locks    Drops    Inode
0000000000000000 0   1          00000550 0        0        0     2        0        16
0000000000000000 12  4242       00000000 0        0        0     2        0        900
0000000000000000 12  4294963199 00000004 0        0        0     2        31       901
0000000000000000 12  5151       00000004 0        0        0     2        5        902
0000000000000000 0   4242       00000001 0        0        0     2        9        903
"""


def fake_proc(tmp_path, netlink: str = NETLINK, procs: dict | None = None):
    """A /proc with the netlink table and, per pid, its stat line and its descriptors' link targets."""
    root = tmp_path / "proc"
    (root / "net").mkdir(parents=True)
    (root / "net" / "netlink").write_text(netlink, encoding="utf-8")
    procs = procs or {
        4242: (
            "4242 (conntrack) S 1 4242 4242 0",
            ["socket:[900]", "socket:[901]", "socket:[903]", "pipe:[7]"],
        ),
        5151: ("5151 (other) S 1 5151 5151 0", ["socket:[902]"]),
    }
    for pid, (stat, links) in procs.items():
        fd = root / str(pid) / "fd"
        fd.mkdir(parents=True)
        (root / str(pid) / "stat").write_text(stat + "\n", encoding="utf-8")
        for n, target in enumerate(links):
            os.symlink(target, fd / str(n))
    (root / "self").mkdir()  # not a pid: skipped
    return str(root)


def test_the_table_is_read_by_its_column_names():
    rows = flowlog.parse_proc_netlink(NETLINK)
    assert [(r.inode, r.protocol, r.groups, r.drops) for r in rows] == [
        (16, 0, 0x550, 0),
        (900, 12, 0, 0),
        (901, 12, 4, 31),
        (902, 12, 4, 5),
        (903, 0, 1, 9),
    ]
    assert rows[2].portid == 4294963199  # the kernel's own port id for a second socket, unsigned
    # a kernel that adds a column before Drops shifts nothing: the header names the columns
    wider = "sk Eth Pid Groups Rmem Wmem Dump Locks Extra Drops Inode\nffff 12 7 00000004 0 0 0 2 x 3 77\n"
    assert flowlog.parse_proc_netlink(wider) == [flowlog.NetlinkSocket(77, 12, 7, 4, 3)]


def test_a_table_it_cannot_read_gives_nothing_rather_than_a_guess():
    assert flowlog.parse_proc_netlink("") == []
    assert flowlog.parse_proc_netlink("sk Eth Pid\n0 12 1\n") == []  # no Drops or Inode column
    assert flowlog.parse_proc_netlink(NETLINK.splitlines()[0] + "\ngarbage line\n") == []


def test_the_event_socket_is_the_one_with_groups_held_by_the_logger(tmp_path):
    """The request socket (groups 0) is the one -b sized; another process's event socket is not ours;
    a route socket the logger holds is not conntrack's."""
    proc = fake_proc(tmp_path)
    assert flowlog.socket_inodes(4242, proc) == {900, 901, 903}
    assert flowlog.event_sockets(4242, proc) == [flowlog.NetlinkSocket(901, 12, 4294963199, 4, 31)]
    assert flowlog.event_sockets(5151, proc) == [flowlog.NetlinkSocket(902, 12, 5151, 4, 5)]


def test_a_wrapper_in_front_of_conntrack_does_not_hide_the_socket(tmp_path):
    """The unit's main process may be a shell that runs conntrack as a child: its sockets count too.
    A command name with spaces and parentheses must not shift the parent field."""
    procs = {
        100: ("100 (sh) S 1 100 100 0", []),
        4242: ("4242 (con (track) x) S 100 100 100 0", ["socket:[901]"]),
        5151: ("5151 (other) S 1 5151 5151 0", ["socket:[902]"]),
    }
    proc = fake_proc(tmp_path, procs=procs)
    assert flowlog.process_tree(100, proc) == [100, 4242]
    assert [s.inode for s in flowlog.event_sockets(100, proc)] == [901]


def test_a_process_that_is_gone_holds_nothing(tmp_path):
    proc = fake_proc(tmp_path)
    assert flowlog.socket_inodes(7777, proc) == set()
    assert flowlog.event_sockets(7777, proc) == []


def test_no_netlink_table_is_no_socket(tmp_path):
    proc = fake_proc(tmp_path)
    os.unlink(os.path.join(proc, "net", "netlink"))
    assert flowlog.event_sockets(4242, proc) == []


@pytest.mark.skipif(os.geteuid() == 0, reason="root reads any directory")
def test_descriptors_it_may_not_read_are_an_error_not_an_empty_answer(tmp_path):
    """Another user's descriptors need root: verify must say that, not 'no event socket'."""
    proc = fake_proc(tmp_path)
    fd = os.path.join(proc, "4242", "fd")
    os.chmod(fd, 0)
    try:
        with pytest.raises(PermissionError):
            flowlog.event_sockets(4242, proc)
    finally:
        os.chmod(fd, 0o755)
