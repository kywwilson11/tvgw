"""(screentest) The one-second poll (design decision 88): a listing's lines read, the payload taken from
the counters, a tick's difference from the tick before, and the series a run is scored on."""

import pytest

from tvgw import connpoll
from tvgw.connpoll import TCP_HEADERS, TOTAL, UDP_HEADERS, Entry

TV = "10.10.10.17"
TCP = (
    "ipv4     2 tcp      6 431999 ESTABLISHED src=10.10.10.17 dst=203.0.113.7 sport=40000 dport=443 packets=18"
    " bytes=2259 src=203.0.113.7 dst=192.0.2.48 sport=443 dport=40000 packets=23 bytes=10742 [ASSURED] mark=0 use=1"
)
UDP = (
    "ipv4     2 udp      17 29 src=10.10.10.17 dst=203.0.113.9 sport=5353 dport=123 packets=1 bytes=76"
    " [UNREPLIED] src=203.0.113.9 dst=192.0.2.48 sport=123 dport=5353 packets=0 bytes=0 mark=0 use=1"
)
ICMP = (
    "ipv4     2 icmp     1 29 src=10.10.10.17 dst=203.0.113.9 type=8 code=0 id=77 packets=1 bytes=84"
    " src=203.0.113.9 dst=192.0.2.48 type=0 code=0 id=77 packets=1 bytes=84 mark=0 use=1"
)
V6 = (
    "ipv6     10 tcp      6 300 ESTABLISHED src=2001:db8::17 dst=2001:db8:1::7 sport=40000 dport=443 packets=3"
    " bytes=300 src=2001:db8:1::7 dst=2001:db8::17 sport=443 dport=40000 packets=2 bytes=200 [ASSURED] use=1"
)


@pytest.mark.parametrize(
    ("line", "entry"),
    [
        (TCP, Entry("tcp", TV, "203.0.113.7", 40000, 443, 18, 2259, 23, 10742)),
        (UDP, Entry("udp", TV, "203.0.113.9", 5353, 123, 1, 76, 0, 0)),
        (ICMP, Entry("icmp", TV, "203.0.113.9", None, None, 1, 84, 1, 84)),
        (V6, Entry("tcp", "2001:db8::17", "2001:db8:1::7", 40000, 443, 3, 300, 2, 200)),
        ("conntrack v1.4.8 (conntrack-tools): 3 flow entries have been shown.", None),
        ("ipv4 2 tcp 6 30 SYN_SENT dst=203.0.113.7 sport=1 dport=2", None),  # no source
        ("ipv4 2 tcp", None),
        (TCP.replace("bytes=2259", "bytes=" + "9" * 30), None),  # a counter no 64 bits hold
        ("", None),
    ],
    ids=[
        "TCP",
        "UDP unreplied",
        "ICMP",
        "IPv6",
        "the tool's last line",
        "no source",
        "cut short",
        "a huge counter",
        "empty",
    ],
)
def test_a_line_of_the_listing_is_a_connection_or_nothing(line, entry):
    assert connpoll.parse_entry(line) == entry


@pytest.mark.parametrize(
    "junk", ["\x00" * 9, "ipv4 " * 40, "ipv4 2 tcp 6 src= dst= packets=x bytes=²", "ipv6 x y z src=a dst=b"]
)
def test_no_line_makes_the_reader_raise(junk):
    assert connpoll.parse_entry(junk) in (None, connpoll.parse_entry(junk))


@pytest.mark.parametrize(
    ("dst", "dport", "name"),
    [
        ("203.0.113.7", 443, "203.0.113.0/24:443"),
        ("203.0.113.200", None, "203.0.113.0/24"),
        ("2001:db8:1::7", 443, "2001:db8:1::/48:443"),
    ],
)
def test_a_destination_is_its_network_and_port(dst, dport, name):
    assert connpoll.cell(dst, dport) == name


@pytest.mark.parametrize(
    ("proto", "packets", "octets", "carried"),
    [
        ("tcp", 17, 17 * TCP_HEADERS, 0),
        ("tcp", 2, 2 * TCP_HEADERS + 900, 900),
        ("udp", 1, UDP_HEADERS + 48, 48),
        ("tcp", 3, 100, 0),
        ("icmp", 1, 84, 84),
    ],
    ids=["bare acknowledgements", "TCP", "UDP", "never below nothing", "a protocol with no ports"],
)
def test_the_payload_is_the_bytes_less_the_packets_headers(proto, packets, octets, carried):
    assert connpoll.payload(proto, packets, octets) == carried


def tcp(dst: str, packets: int, octets: int, src: str = TV, sport: int = 40000) -> str:
    return (
        TCP.replace("dst=203.0.113.7", f"dst={dst}")
        .replace("src=10.10.10.17", f"src={src}")
        .replace("packets=18 bytes=2259", f"packets={packets} bytes={octets}")
        .replace("sport=40000", f"sport={sport}", 1)
    )


def listings(monkeypatch, *tables: list[str]) -> connpoll.Poll:
    """A poll whose connection table is each of `tables` in turn."""
    left = iter(tables)
    monkeypatch.setattr(
        connpoll.subprocess,
        "run",
        lambda argv, **kw: type("Done", (), {"stdout": "\n".join(next(left)) + "\n"})(),
    )
    return connpoll.Poll(TV)


def test_a_tick_is_what_each_destination_was_sent_since_the_tick_before(monkeypatch):
    """A connection first seen counts all it has carried. One whose counters went down was replaced by
    the kernel and counts what the new one holds. Two connections to one network and port are one
    destination. The gateway's, the home network's and another device's are left out."""
    poll = listings(
        monkeypatch,
        [
            tcp("203.0.113.7", 2, 2 * TCP_HEADERS + 100),
            tcp("192.168.1.9", 5, 9000),
            tcp("203.0.113.7", 9, 9000, src="10.10.10.99"),
        ],
        [
            tcp("203.0.113.7", 5, 5 * TCP_HEADERS + 700),
            tcp("203.0.113.8", 1, TCP_HEADERS + 50, sport=40001),
            "not a line",
        ],
        [tcp("203.0.113.7", 1, TCP_HEADERS + 30), tcp("203.0.113.8", 1, TCP_HEADERS + 50, sport=40001)],
        [],
    )
    assert poll.tick() == {"203.0.113.0/24:443": 100}
    assert (poll.tick(), poll.unread) == ({"203.0.113.0/24:443": 600 + 50}, 1)
    assert (poll.tick(), poll.unread) == ({"203.0.113.0/24:443": 30}, 0)
    assert poll.tick() == {}


def test_a_watch_is_one_tick_a_second_after_a_first_that_only_takes_the_counters_as_they_stand(monkeypatch):
    poll = listings(monkeypatch, *[[tcp("203.0.113.7", n, n * (TCP_HEADERS + 10))] for n in (50, 51, 51, 53)])
    now, slept = [100.0], []
    monkeypatch.setattr(connpoll, "clock", lambda: now[0])
    monkeypatch.setattr(connpoll, "sleep", lambda s: (slept.append(s), now.__setitem__(0, now[0] + s + 0.25)))
    ticks = connpoll.watch(poll, 3)
    assert ticks == [{"203.0.113.0/24:443": 10}, {}, {"203.0.113.0/24:443": 20}]
    assert slept == [1.0, 0.75, 0.75]  # each second by the clock, a late tick not pushing the next one later
    assert connpoll.series(ticks) == {TOTAL: [10.0, 0.0, 20.0], "203.0.113.0/24:443": [10.0, 0.0, 20.0]}
