"""(screentest) The one-second poll (design decision 88): a listing's lines read, the payload taken from
the counters, a tick's difference from the tick before, what a failed listing costs, and the series a run
is scored on."""

import re
import subprocess
from types import SimpleNamespace

import pytest
from tvdouble import TV, listed

from tvgw import connpoll
from tvgw.connpoll import MISSED, PATIENCE, TOTAL, Entry, PollError

WEB = "203.0.113.0/24:443"  # the destination 203.0.113.7 and .8 are counted under
UDP = (
    "ipv4     2 udp      17 29 src=10.10.10.17 dst=203.0.113.9 sport=5353 dport=123 packets=1 bytes=76"
    " [UNREPLIED] src=203.0.113.9 dst=192.0.2.48 sport=123 dport=5353 packets=0 bytes=0 mark=0 use=1 id=22"
)
ICMP = (
    "ipv4     2 icmp     1 29 src=10.10.10.17 dst=203.0.113.9 type=8 code=0 id=77 packets=1 bytes=84"
    " src=203.0.113.9 dst=192.0.2.48 type=0 code=0 id=77 packets=1 bytes=84 mark=0 use=1 id=33"
)
V6 = (
    "ipv6     10 tcp      6 300 ESTABLISHED src=2001:db8::17 dst=2001:db8:1::7 sport=40000 dport=443 packets=3"
    " bytes=300 src=2001:db8:1::7 dst=2001:db8::17 sport=443 dport=40000 packets=2 bytes=200 [ASSURED] use=1"
)
BARE = re.sub(r" packets=\d+ bytes=\d+", "", listed("203.0.113.7", 18, 2259))  # a table that does not count


@pytest.mark.parametrize(
    ("line", "entry"),
    [
        (
            listed("203.0.113.7", 18, 2259, entry=11),
            Entry("tcp", TV, "203.0.113.7", 40000, 443, 18, 2259, 23, 10742, "203.0.113.7", ("11",)),
        ),
        (
            listed("203.0.113.53", 4, 400, by="10.10.10.1"),
            Entry("tcp", TV, "203.0.113.53", 40000, 443, 4, 400, 23, 10742, "10.10.10.1", ("1",)),
        ),
        (UDP, Entry("udp", TV, "203.0.113.9", 5353, 123, 1, 76, 0, 0, "203.0.113.9", ("22",))),
        (ICMP, Entry("icmp", TV, "203.0.113.9", None, None, 1, 84, 1, 84, "203.0.113.9", ("77", "77", "33"))),
        (BARE, Entry("tcp", TV, "203.0.113.7", 40000, 443, 0, 0, 0, 0, "203.0.113.7", ("1",))),
        (V6, None),
        ("conntrack v1.4.8 (conntrack-tools): 3 flow entries have been shown.", None),
        ("ipv4 2 tcp 6 30 SYN_SENT dst=203.0.113.7 sport=1 dport=2", None),
        ("ipv4 2 tcp", None),
        (listed("203.0.113.7", 18, int("9" * 30)), None),
        ("", None),
    ],
    ids=[
        "TCP",
        "answered by the gateway",
        "UDP unreplied",
        "ICMP: a ping's own id and the entry's",
        "no counters",
        "IPv6",
        "the tool's last line",
        "no source",
        "cut short",
        "a counter no 64 bits hold",
        "empty",
    ],
)
def test_a_line_of_the_listing_is_an_ipv4_connection_or_nothing(line, entry):
    assert connpoll.parse_entry(line) == entry


@pytest.mark.parametrize(
    ("dst", "dport", "name"),
    [("203.0.113.7", 443, WEB), ("203.0.113.200", None, "203.0.113.0/24")],
    ids=["a port", "a protocol without ports"],
)
def test_a_destination_is_its_network_and_port(dst, dport, name):
    assert connpoll.cell(dst, dport) == name


@pytest.mark.parametrize(
    ("proto", "packets", "nbytes", "carried"),
    [("tcp", 17, 884, 0), ("tcp", 2, 1004, 900), ("udp", 1, 76, 48), ("tcp", 3, 100, 0), ("icmp", 1, 84, 84)],
    ids=["bare acknowledgements", "TCP", "UDP", "never below nothing", "a protocol with no ports"],
)
def test_the_payload_is_the_bytes_less_52_a_tcp_packet_and_28_a_udp_one(proto, packets, nbytes, carried):
    assert connpoll.payload(proto, packets, nbytes) == carried


def tcp(dst: str, packets: int, carried: int, **how) -> str:
    """A TCP connection of the TV's that has sent `carried` bytes of payload in `packets` packets."""
    return listed(dst, packets, packets * 52 + carried, **how)


def listings(monkeypatch, *tables) -> connpoll.Poll:
    """A poll whose connection table is each of `tables` in turn: its lines, the status the tool ended
    with, or what running it raised."""
    left = iter(tables)

    def conntrack(argv, **kw):
        table = next(left)
        if isinstance(table, BaseException):
            raise table
        if isinstance(table, int):
            return SimpleNamespace(returncode=table, stdout="")
        return SimpleNamespace(returncode=0, stdout="\n".join(table) + "\n")

    monkeypatch.setattr(connpoll.subprocess, "run", conntrack)
    return connpoll.Poll(TV)


def test_a_tick_is_what_each_destination_was_sent_since_the_tick_before(monkeypatch):
    """A connection first seen counts all it has carried. Two to one network and port are one destination.
    One whose bytes went down, or whose entry is another though the ports are the same, is new and counts
    whole. Left out: the home network's, another device's, and one the gateway answered in a public
    address's place. A line that is no connection is counted unread, a blank one is not, and a connection
    that has gone is forgotten."""
    poll = listings(
        monkeypatch,
        [
            tcp("203.0.113.7", 2, 100),
            tcp("10.20.30.40", 5, 9000, entry=7),
            tcp("203.0.113.7", 9, 9000, src="10.10.10.99", entry=8),
            tcp("203.0.113.53", 4, 300, by="10.10.10.1", entry=9),
        ],
        [tcp("203.0.113.7", 5, 700), tcp("203.0.113.8", 1, 50, sport=40001, entry=2), "not a line", ""],
        [tcp("203.0.113.7", 6, 30), tcp("203.0.113.8", 1, 50, sport=40001, entry=3)],
        [],
    )
    assert poll.tick() == {WEB: 100}
    assert (poll.tick(), poll.unread) == ({WEB: 600 + 50}, 1)
    assert (poll.tick(), poll.unread) == ({WEB: 30 + 50}, 1)
    assert (poll.tick(), poll.seen, poll.failed) == ({}, {}, 0)


@pytest.mark.parametrize(
    "failure",
    [1, PermissionError(), subprocess.TimeoutExpired("conntrack", PATIENCE)],
    ids=["the tool fails", "it cannot be run", "it does not answer"],
)
def test_a_listing_that_fails_reads_nothing_and_forgets_nothing(monkeypatch, failure):
    poll = listings(monkeypatch, [tcp("203.0.113.7", 1, 10)], failure, [tcp("203.0.113.7", 3, 40)])
    assert [poll.tick(), poll.tick(), poll.tick()] == [{WEB: 10}, {}, {WEB: 30}]
    assert poll.failed == 1


@pytest.mark.parametrize(
    ("table", "why"),
    [(FileNotFoundError(), "not installed"), ([BARE], "no counters")],
    ids=["no tool", "a table that does not count"],
)
def test_what_no_later_tick_would_mend_stops_the_poll(monkeypatch, table, why):
    with pytest.raises(PollError, match=why):
        listings(monkeypatch, table).tick()


def clocked(monkeypatch, took: float = 0.25) -> list[float]:
    """A clock that moves only when slept on, and then `took` longer than asked: the sleeps asked for."""
    now, slept = [100.0], []
    monkeypatch.setattr(connpoll, "clock", lambda: now[0])
    monkeypatch.setattr(connpoll, "sleep", lambda s: (slept.append(s), now.__setitem__(0, now[0] + s + took)))
    return slept


def test_a_watch_is_one_tick_a_second_after_a_first_that_only_takes_the_counters_as_they_stand(monkeypatch):
    poll = listings(monkeypatch, *[[tcp("203.0.113.7", n, n * 10)] for n in (50, 51, 51, 53)])
    slept = clocked(monkeypatch)
    ticks = connpoll.watch(poll, 3)
    assert ticks == [{WEB: 10}, {}, {WEB: 20}]
    assert slept == [1.0, 0.75, 0.75]  # each second by the clock, a late tick not pushing the next one later
    assert connpoll.series(ticks) == {TOTAL: [10.0, 0.0, 20.0], WEB: [10.0, 0.0, 20.0]}


def test_a_watch_whose_first_listing_fails_has_nothing_to_count_from(monkeypatch):
    clocked(monkeypatch)
    with pytest.raises(PollError, match="could not be listed"):
        connpoll.watch(listings(monkeypatch, 1, []), 1)


def test_a_tick_may_be_patience_behind_its_second_and_no_more(monkeypatch):
    poll = listings(monkeypatch, [], [tcp("203.0.113.7", 1, 10)], [])
    times = iter([0.0, 1 + PATIENCE, 2 + PATIENCE + 0.5])  # the start, then the clock at each second's turn
    monkeypatch.setattr(connpoll, "clock", lambda: next(times))
    with pytest.raises(PollError, match="too busy"):
        connpoll.watch(poll, 2)
    assert len(poll.seen) == 1  # the first second's tick was made


@pytest.mark.parametrize("failures", [2, 3])
def test_a_watch_bears_failed_listings_up_to_a_share_of_its_seconds(monkeypatch, failures):
    seconds = 40
    assert seconds * MISSED == 2
    clocked(monkeypatch)
    poll = listings(monkeypatch, [], *[1] * failures, *[[]] * (seconds - failures))
    if failures <= seconds * MISSED:
        assert connpoll.watch(poll, seconds) == [{}] * seconds
    else:
        with pytest.raises(PollError, match=f"could not be listed {failures} times"):
            connpoll.watch(poll, seconds)
