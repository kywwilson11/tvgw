"""(ports) The probe's port steps (design decision 71): the ports the TV uses pass, the clock port is refused
when the last apply closed it, and an unusual port is refused exactly when STRICT_PORTS=yes.

What a kernel makes of the twin's rules is the namespace tier's (tests/virtual/test_virtual_ports.py). Here:
the plan takes STRICT_PORTS and the clock port from the record of the last apply, every row of the table
`probe._ports` holds, the ICMP error's sender is read from Linux's extended error report, and, on Linux,
the client's own try of the ports against this computer's loopback, where nothing listens."""

from __future__ import annotations

import dataclasses
import socket
import struct
import sys

import pytest
from test_probe import DOWN, GOOD, PORT, UP, S, obs, outcomes

from tvgw import probe
from tvgw.probe import FAIL, PASS, UNKNOWN, Plan

P = Plan("10.10.10.1", "10.10.10.30", ("us.lgtvsdp.com",), "alphonso.tv", True, ("cdn.example.net",))
STRICT = dataclasses.replace(P, strict=True)
CLOSED = dataclasses.replace(P, clock="none")
OPEN = {"tcp/80": "silent", "tcp/443": "silent", "udp/123": "silent", "udp/5000": "silent"}


def ports(**seen: str) -> dict:
    return obs(ports={**OPEN, **{k.replace("_", "/"): v for k, v in seen.items()}})


def stage(p: Plan, seen: dict, uplink=UP) -> probe.Stage:
    v = probe.judge(p, seen, PORT, uplink)
    return next(s for s in v.stages if s.name == "ports")


# ---- the plan ------------------------------------------------------------------------------------------


def test_the_plan_tries_the_web_the_clock_and_one_unusual_port_and_hands_them_to_the_client(lg):
    p = probe.plan(S, lg)
    assert p.ports == (("tcp", 80), ("tcp", 443), ("udp", 123), ("udp", probe.ODD_PORT))
    assert p.spec()["ports"] == [["tcp", 80], ["tcp", 443], ["udp", 123], ["udp", probe.ODD_PORT]]
    # the unusual port is in none of the walls' lists, so only STRICT_PORTS can refuse it
    assert probe.ODD_PORT not in (80, 123, 443, 784, 853, 8853, 4001, 4431, 4445, 4447, 8180, 8883, 8080)
    assert (p.strict, p.clock) == (False, "any")
    assert probe.plan(dataclasses.replace(S, strict_ports="yes"), lg).strict is True
    assert probe.plan(S, lg, "none").clock == "none" and probe.plan(S, lg, "bogus").clock == "any"


def test_what_must_be_refused_follows_strict_ports_and_the_clock_port():
    for p, refused in (
        (P, set()),
        (STRICT, {("udp", probe.ODD_PORT)}),
        (CLOSED, {("udp", 123)}),
        (dataclasses.replace(STRICT, clock="none"), {("udp", 123), ("udp", probe.ODD_PORT)}),
        # resolved lives in the gate's table, which the probe's port does not cross: it cannot be seen
        (dataclasses.replace(P, clock="resolved"), set()),
    ):
        assert {x for x in p.ports if p.expect_refused(*x)} == refused, p
    assert not STRICT.expect_refused("tcp", 80) and not STRICT.expect_refused("tcp", 443)
    # what is usual is per protocol, as the firewall has it: the clock's port on TCP and the web's on UDP are not
    assert STRICT.expect_refused("tcp", 123) and STRICT.expect_refused("udp", 80)
    assert not STRICT.expect_refused("udp", 443) and not P.expect_refused("tcp", 123)


def test_the_plan_reads_strict_ports_and_the_clock_port_from_the_last_apply(lg, tmp_path):
    """The probe judges the gateway as it is: STRICT_PORTS as the last apply used it (a LIVE_KEY), and the
    clock port as it built it (CLOCK_PORT_USED), never what the settings file says next."""
    applied = tmp_path / "settings.applied"
    env = probe.Env(
        read=lambda path: applied.read_text() if path == str(applied) else "", applied=str(applied)
    )
    applied.write_text("STRICT_PORTS=yes\nCLOCK_PORT=none\nCLOCK_PORT_USED=any\n")
    assert probe.live(S, env).strict_ports == "yes" and probe.applied_clock(env) == "any"
    applied.write_text("CLOCK_PORT_USED=none\n")
    assert probe.applied_clock(env) == "none"
    applied.write_text("UPLINK=direct\n")  # an apply from before the key: the port was open then
    assert probe.applied_clock(env) == "any"
    applied.write_text("CLOCK_PORT_USED=sideways\n")
    assert probe.applied_clock(env) == "any"
    applied.write_text("not a settings file\n")
    assert probe.applied_clock(env) == "any"


# ---- the table -------------------------------------------------------------------------------------------

ROWS = [
    # (plan, what the client saw, the uplink, the outcome, what the detail says)
    (P, ports(), UP, PASS, ""),
    (P, ports(tcp_80="unreachable", tcp_443="connected"), UP, PASS, ""),  # not the gateway's refusal
    (P, ports(tcp_80="refused"), UP, FAIL, "the gateway refuses TCP 80"),
    (P, ports(tcp_443="refused"), DOWN, FAIL, "the gateway refuses TCP 443"),  # its own, whatever the uplink
    (P, ports(udp_123="refused"), UP, FAIL, "the gateway refuses UDP 123"),
    (
        P,
        ports(udp_5000="refused"),
        UP,
        FAIL,
        "the gateway refuses UDP 5000",
    ),  # strict, though STRICT_PORTS=no
    (STRICT, ports(udp_5000="refused"), UP, PASS, ""),
    (STRICT, ports(), UP, FAIL, "UDP 5000, an unusual port, was not refused, and STRICT_PORTS=yes"),
    (STRICT, ports(udp_5000="unreachable"), UP, FAIL, "was not refused"),  # someone else's error: let out
    (STRICT, ports(), DOWN, UNKNOWN, "the uplink is down"),
    (CLOSED, ports(udp_123="refused"), UP, PASS, ""),
    (CLOSED, ports(), UP, FAIL, "UDP 123, the clock port, was not refused, and the last apply closed it"),
    (dataclasses.replace(P, clock="resolved"), ports(), UP, PASS, ""),
    # the gateway's own error that refuses nothing: no route out (net unreachable, as when the Wi-Fi or
    # the WAN is gone and the default routes with it). Never a fail, and never a pass
    (P, ports(udp_123="unroutable"), DOWN, UNKNOWN, "the uplink is down"),
    (P, ports(udp_123="unroutable"), UP, UNKNOWN, "the gateway had no route out for UDP 123"),
    (STRICT, ports(udp_5000="unroutable"), UP, UNKNOWN, "no route out for UDP 5000"),
    (CLOSED, ports(udp_123="unroutable"), DOWN, UNKNOWN, "the uplink is down"),
    # an error the probe cannot attribute (a TCP try the raw socket did not see): never a pass
    (P, ports(tcp_80="unattributed"), UP, UNKNOWN, "TCP 80 met an error the probe cannot attribute"),
    (P, ports(tcp_80="error"), UP, UNKNOWN, "cannot attribute"),
    (P, obs(ports=None), UP, UNKNOWN, "tried no port"),
    (P, obs(ports={}), UP, UNKNOWN, "tried no port"),
    (P, obs(ports={"tcp/80": "silent"}), UP, UNKNOWN, "TCP 443 was not tried"),
]


@pytest.mark.parametrize(("p", "seen", "uplink", "outcome", "said"), ROWS)
def test_every_row_of_the_port_steps(p, seen, uplink, outcome, said):
    s = stage(p, seen, uplink)
    assert s.outcome == outcome, s
    assert said in s.detail


def test_a_port_step_that_fails_fails_the_verdict_and_says_which_port():
    v = probe.judge(STRICT, ports(), PORT, UP)
    assert v.verdict == FAIL and v.word == "ports"
    assert v.reason == "ports: UDP 5000, an unusual port, was not refused, and STRICT_PORTS=yes"
    assert outcomes(probe.judge(P, GOOD, PORT, UP))["ports"] == PASS
    # the plain words name the step, and the stored sample keeps only the stage's outcome
    assert "STRICT_PORTS" in probe.STAGE_PLAIN["ports"]
    assert '"ports":"fail"' in v.compact() and "5000" not in v.compact()


def test_with_the_gateways_errors_on_another_address_the_step_cannot_tell(lg):
    """net.ipv4.icmp_errors_use_inbound_ifaddr=1: the gateway's refusal would not come from GW_IP, so a
    refused clock port would read as an error from beyond and pass. The step says it cannot tell."""
    inbound = dataclasses.replace(PORT, icmp_inbound=True)
    v = probe.judge(CLOSED, ports(udp_123="unreachable"), inbound, UP)
    (s,) = [s for s in v.stages if s.name == "ports"]
    assert s.outcome == UNKNOWN and "icmp_errors_use_inbound_ifaddr" in s.detail
    files = {
        "/proc/sys/net/ipv4/icmp_errors_use_inbound_ifaddr": "1\n",
        "/proc/sys/net/ipv4/ip_forward": "1\n",
    }
    env = probe.Env(read=lambda path: files.get(path, ""), run=lambda cmd, timeout=15.0: (1, ""))
    assert probe.read_port(S, probe.plan(S, lg), env).icmp_inbound is True
    files["/proc/sys/net/ipv4/icmp_errors_use_inbound_ifaddr"] = "0\n"
    assert probe.read_port(S, probe.plan(S, lg), env).icmp_inbound is False


def test_a_plan_with_no_ports_has_no_port_step():
    assert "ports" not in outcomes(probe.judge(dataclasses.replace(P, ports=()), GOOD, PORT, UP))


# ---- reading who refused ---------------------------------------------------------------------------------


def errqueue(
    sender: str, origin: int = probe.SO_EE_ORIGIN_ICMP, family: int = socket.AF_INET, code: int = 3
) -> list:
    """The ancillary data of a recvmsg(MSG_ERRQUEUE) on Linux: sock_extended_err, then the sender."""
    err = struct.pack("=IBBBBII", 111, origin, 3, code, 0, 0, 0)
    addr = family.to_bytes(2, sys.byteorder) + b"\x00\x00" + socket.inet_aton(sender) + bytes(8)
    return [(socket.IPPROTO_IP, probe.IP_RECVERR, err + addr)]


def test_the_icmp_errors_sender_is_read_from_the_error_queue():
    assert probe.icmp_sender(errqueue("10.10.10.1")) == (111, "10.10.10.1", 3, 3)
    assert probe.icmp_sender(errqueue("10.10.10.1", code=0)) == (111, "10.10.10.1", 3, 0)
    assert probe.icmp_sender(errqueue("10.10.10.1", origin=1)) is None  # a local error, not ICMP
    assert probe.icmp_sender(errqueue("10.10.10.1", family=socket.AF_INET6)) is None
    assert probe.icmp_sender([(socket.IPPROTO_IP, probe.IP_RECVERR, b"\x00" * 8)]) is None  # cut short
    assert probe.icmp_sender([]) is None


def test_only_the_gateways_own_refusal_reads_as_refused():
    gw = "10.10.10.1"
    for code in (3, 9, 10, 13):  # port unreachable, and the three administratively prohibited
        assert probe._refusal_word(111, gw, gw, (3, code)) == "refused", code
    for code in (0, 1, 4, 6, 7):  # net and host unreachable, and the rest: a route the gateway lacks
        assert probe._refusal_word(101, gw, gw, (3, code)) == "unroutable", code
    assert probe._refusal_word(101, gw, gw, (11, 0)) == "unroutable"  # time exceeded is no refusal either
    assert probe._refusal_word(113, "198.51.100.1", gw, (3, 1)) == "unreachable"  # the home router's error
    assert probe._refusal_word(111, "198.51.100.1", gw, (3, 3)) == "unreachable"  # whatever its code
    assert probe._refusal_word(probe.errno.ECONNREFUSED, None, gw) == "refused"  # TCP: a reset or ICMP
    assert probe._refusal_word(probe.errno.ECONNRESET, None, gw) == "refused"
    assert probe._refusal_word(probe.errno.EHOSTUNREACH, None, gw) == "unattributed"
    assert probe._refusal_word(probe.errno.ENETUNREACH, None, gw) == "unattributed"
    assert probe._refusal_word(0, None, gw) == "connected"
    assert probe._refusal_word(probe.errno.EACCES, None, gw) == "error"


def test_the_reviewers_case_wifi_gone_is_unknown_never_fail():
    """Direct mode with the Wi-Fi down (or vpn mode with the WAN down): the default routes go, and the
    gateway itself answers UDP 123 with ICMP net unreachable, from GW_IP. That is no refusal: the verdict
    is unknown, and nothing could be undone on it."""
    gw = "10.10.10.1"
    word = probe._refusal_word(probe.errno.ENETUNREACH, gw, gw, (3, 0))
    assert word == "unroutable"
    v = probe.judge(P, ports(udp_123=word, udp_5000=word), PORT, DOWN)
    assert v.verdict != FAIL
    (s,) = [s for s in v.stages if s.name == "ports"]
    assert s.outcome == UNKNOWN and s.detail == DOWN.why


def icmp_error(sender: str, icmp_type: int, code: int, proto: int, dst: str, dport: int) -> bytes:
    """An ICMP error as a raw socket reads it: the outer IPv4 header, the ICMP header, the original's
    IPv4 header and its first eight bytes."""
    outer = bytes([0x45, 0]) + (56).to_bytes(2, "big") + bytes(4) + bytes([64, 1]) + bytes(2)
    outer += socket.inet_aton(sender) + socket.inet_aton("10.10.10.30")
    icmp = bytes([icmp_type, code]) + bytes(6)
    inner = bytes([0x45, 0]) + (60).to_bytes(2, "big") + bytes(4) + bytes([63, proto]) + bytes(2)
    inner += socket.inet_aton("10.10.10.30") + socket.inet_aton(dst)
    return outer + icmp + inner + (40000).to_bytes(2, "big") + dport.to_bytes(2, "big") + bytes(4)


def test_a_tcp_trys_icmp_error_is_read_with_its_sender_and_code_from_the_raw_socket():
    wall = probe.WALL_ADDR
    assert probe.icmp_error_of(icmp_error("10.10.10.1", 3, 13, 6, wall, 80)) == (
        "10.10.10.1",
        3,
        13,
        6,
        wall,
        80,
    )
    assert probe.icmp_error_of(icmp_error("198.51.100.1", 3, 1, 17, wall, 123))[1:3] == (3, 1)
    assert probe.icmp_error_of(icmp_error("10.10.10.1", 0, 0, 6, wall, 80)) is None  # an echo reply
    assert probe.icmp_error_of(icmp_error("10.10.10.1", 3, 3, 6, wall, 80)[:40]) is None  # cut short
    assert probe.icmp_error_of(b"\x60" + bytes(60)) is None  # not IPv4

    class Raw:
        def __init__(self, packets):
            self.packets = list(packets)

        def recv(self, _n):
            if not self.packets:
                raise BlockingIOError
            return self.packets.pop(0)

    raw = Raw(
        [
            icmp_error("10.10.10.1", 3, 13, 6, wall, 80),  # the gateway refused TCP 80
            icmp_error("10.10.10.1", 3, 3, 17, wall, 123),  # a UDP try's: its own socket reads that
            icmp_error("198.51.100.1", 3, 1, 6, "203.0.113.9", 443),  # another address's
            b"junk",
        ]
    )
    assert probe._raw_errors(raw, wall) == {80: ("10.10.10.1", 3, 13)}
    assert probe._raw_errors(None, wall) == {}


def test_the_client_tries_the_ports_it_is_handed_after_the_walls(monkeypatch):
    tried = []
    monkeypatch.setattr(probe, "ask", lambda name, server, timeout=2.0: ["0.0.0.0"])
    monkeypatch.setattr(probe, "tcp_try", lambda addr, port, timeout=3.0: "refused")
    monkeypatch.setattr(probe, "udp_try", lambda addr, port, payload, timeout=1.2: "refused")
    monkeypatch.setattr(
        probe,
        "ports_try",
        lambda addr, ports, gw, wait=1.0, refuse=(): (
            tried.append((addr, ports, gw, refuse)) or {"tcp/80": "x"}
        ),
    )
    seen, _ = probe.observe(P.spec(connect=False))
    assert tried == [(probe.WALL_ADDR, list(P.ports), "10.10.10.1", [])] and seen["ports"] == {"tcp/80": "x"}
    tried.clear()
    probe.observe(STRICT.spec(connect=False))  # the ports that must be refused are waited for longer
    assert tried[0][3] == [("udp", probe.ODD_PORT)]
    tried.clear()
    seen, _ = probe.observe({**P.spec(connect=False), "ports": []})
    assert tried == [] and seen["ports"] is None


@pytest.mark.skipif(not sys.platform.startswith("linux"), reason="the extended error report is Linux's")
def test_on_linux_the_client_reads_a_refusal_from_whoever_sent_it():
    """Loopback, where nothing listens on these ports: TCP gets a reset and UDP an ICMP port-unreachable,
    both from 127.0.0.1. With the gateway named as 127.0.0.1 both are its refusal; named as anyone else,
    the UDP one is someone else's error, which the TCP one cannot tell."""
    free = []
    for kind in (socket.SOCK_STREAM, socket.SOCK_DGRAM):
        with socket.socket(socket.AF_INET, kind) as s:
            s.bind(("127.0.0.1", 0))
            free.append(s.getsockname()[1])
    tcp, udp = free
    seen = probe.ports_try("127.0.0.1", [("tcp", tcp), ("udp", udp)], "127.0.0.1", wait=1.0)
    assert seen == {f"tcp/{tcp}": "refused", f"udp/{udp}": "refused"}
    other = probe.ports_try("127.0.0.1", [("udp", udp)], "192.0.2.1", wait=1.0)
    assert other == {f"udp/{udp}": "unreachable"}


@pytest.mark.skipif(not sys.platform.startswith("linux"), reason="the extended error report is Linux's")
def test_on_linux_a_try_no_refusal_is_expected_for_is_decided_without_the_whole_wait():
    """A port nothing answers at is let through once PORT_QUIET has gone by silent, or at once when an ICMP
    error from beyond says so: never the whole PORT_WAIT, which only a port that must be refused waits."""
    import time as clock

    started = clock.monotonic()
    seen = probe.ports_try(probe.WALL_ADDR, [("udp", probe.ODD_PORT)], "192.0.2.1", wait=1.5)
    assert clock.monotonic() - started < 1.0
    assert seen[f"udp/{probe.ODD_PORT}"] in ("silent", "unreachable", "unattributed", "error")
