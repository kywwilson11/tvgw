"""conntrack DESTROY lines, taken verbatim from the gateway's flows.log."""

from tvgw.conntrack import parse_flow

TCP = (
    "[1792977952.120409]\t[DESTROY] ipv4     2 tcp      6 TIME_WAIT src=10.10.10.17 dst=142.251.219.1 "
    "sport=58998 dport=443 packets=18 bytes=2259 src=142.251.219.1 dst=192.0.2.48 sport=443 dport=58998 "
    "packets=23 bytes=10742 [ASSURED] delta-time=360"
)
UDP = (
    "[1792977952.120776]\t[DESTROY] ipv4     2 udp      17 src=10.10.10.17 dst=10.10.10.1 sport=45806 "
    "dport=53 packets=1 bytes=64 src=10.10.10.1 dst=10.10.10.17 sport=53 dport=45806 packets=1 bytes=145 "
    "delta-time=30"
)
ICMP = (
    "[1792977960.5]\t[DESTROY] ipv4     2 icmp     1 src=10.10.10.17 dst=8.8.8.8 type=8 code=0 id=1 "
    "packets=1 bytes=84 src=8.8.8.8 dst=192.0.2.48 type=0 code=0 id=1 packets=1 bytes=84 delta-time=1"
)
UNREPLIED = (
    "[1792977970.0]\t[DESTROY] ipv4     2 tcp      6 SYN_SENT src=10.10.10.17 dst=192.168.8.69 sport=40000 "
    "dport=80 packets=3 bytes=180 [UNREPLIED] src=192.168.8.69 dst=10.10.10.17 sport=80 dport=40000 "
    "packets=0 bytes=0 delta-time=120"
)


def test_tcp_flow_directions_and_duration():
    f = parse_flow(TCP)
    assert f is not None
    assert (f.proto, f.state) == ("tcp", "TIME_WAIT")
    assert (f.src, f.dst, f.sport, f.dport) == ("10.10.10.17", "142.251.219.1", 58998, 443)
    assert (f.pkts_up, f.bytes_up, f.pkts_down, f.bytes_down) == (18, 2259, 23, 10742)
    assert f.t_end == 1792977952.120409
    assert f.t_start == f.t_end - 360


def test_udp_flow_has_no_state():
    f = parse_flow(UDP)
    assert f is not None
    assert f.proto == "udp" and f.state is None
    assert (f.dport, f.bytes_up, f.bytes_down) == (53, 64, 145)


def test_icmp_flow_has_no_ports():
    f = parse_flow(ICMP)
    assert f is not None
    assert f.proto == "icmp" and f.sport is None and f.dport is None
    assert f.bytes_up == 84


def test_unreplied_flow_keeps_zero_reply_counters():
    f = parse_flow(UNREPLIED)
    assert f is not None
    assert (f.pkts_down, f.bytes_down, f.state) == (0, 0, "SYN_SENT")


def test_non_destroy_and_garbage_lines_are_ignored():
    assert parse_flow(TCP.replace("[DESTROY]", "[NEW]")) is None
    assert parse_flow("") is None
    assert parse_flow("not a conntrack line at all") is None
    assert parse_flow("[abc]\t[DESTROY] ipv4 2 tcp 6 src=1.2.3.4") is None  # bad timestamp
    assert parse_flow("[1.0]\t[DESTROY] ipv4 2 tcp 6 sport=1 dport=2") is None  # no addresses
