"""(probe) `tvgw probe`: what it plans, how it judges, what it runs, and that it leaves no trace.

The probe's packets need a kernel, and tests/virtual/test_virtual_probe.py sends them through the
namespace gateway. Everything that decides is pure and is tested here against fixed observations: the
verdict of every combination that matters (`judge`), the "unknown, never fail" rule for an uplink that is
down, the commands that make and remove the namespace, the run that never raises, the verdicts either
side of an apply, and the check, the sample and the exit status built on them. And the record: the
probe's address is in none of the sources the ingest keeps."""

import dataclasses
import errno
import io
import ipaddress
import json
import math
import os
import re
import signal
import socket
import sqlite3
import struct
import subprocess
import sys
import threading
import time

import pytest
from conftest import DNS_ALLOWED, FLOW_TCP, GFTS_TV_ALLOWED, NOW, ROOT

from tvgw import adguard, cli, config, conntrack, db, dnsgate, ledger, probe, verify
from tvgw.config import Settings
from tvgw.probe import FAIL, PASS, SKIPPED, UNKNOWN, Plan, Port, Stage, Uplink

S = Settings(tv_probe="on", wan_if="wlan0", uplink="direct", block_quic="yes")
TARGET = "cdn.example.net"
NAMES = ("us.lgtvsdp.com", "snu.lge.com")
P = Plan("10.10.10.1", "10.10.10.30", NAMES, "alphonso.tv", True, (TARGET,))
WALL = probe.WALL_ADDR
PORT = Port(True, "wlan0", "wlan0", "eth0", "eth0")
UP, DOWN = Uplink(True), Uplink(False, "the uplink is down: wlan0 has no carrier")
ADDR, VENDOR = "203.0.113.7", "198.51.100.77"
GOOD = {
    "allow": [{"name": n, "answers": [VENDOR]} for n in NAMES],
    "path": [{"name": TARGET, "answers": [ADDR], "addr": ADDR, "tls": "ok"}],
    "blocked": ["0.0.0.0"],
    "dot": "refused",
    "quic": "refused",
    "redirect": ["0.0.0.0"],
    # (ports) the web and the clock let through, the unusual port too (STRICT_PORTS=no): none refused
    "ports": {"tcp/80": "silent", "tcp/443": "silent", "udp/123": "silent", "udp/5000": "silent"},
    "adtech": "refused",  # (revert) the wall a plan asks for only where it stands
}


def obs(**changes) -> dict:
    return {**GOOD, **changes}


def outcomes(v: probe.Verdict) -> dict[str, str]:
    return {s.name: s.outcome for s in v.stages}


def whole(profile, base: dict | None = None) -> dict:
    """`base` (GOOD when not given) with an address for every must-allow name of `profile`."""
    return {**(base or GOOD), "allow": [{"name": n, "answers": [VENDOR]} for n in profile.must_allow]}


def never() -> dict:
    raise AssertionError("the control was asked though nothing called for it")


# ---- the plan --------------------------------------------------------------------------------------------


def test_the_plan_takes_every_must_allow_name_and_aims_the_walls_at_an_address_nobody_answers_at(lg):
    p = probe.plan(S, lg)
    assert p.allow == tuple(lg.must_allow) and len(p.allow) >= 3  # every name, looked up and no more
    assert p.block == "alphonso.tv"  # the first name one of the profile's own rules blocks
    assert (p.gw_ip, p.probe_ip, p.quic) == ("10.10.10.1", "10.10.10.30", True)
    assert probe.plan(dataclasses.replace(S, block_quic="no"), lg).quic is False
    # RFC 5737: routed nowhere, so a refusal or an answer is the gateway's and nothing reaches anyone
    assert p.wall == "192.0.2.53" and ipaddress.ip_address(p.wall) in ipaddress.ip_network("192.0.2.0/24")
    assert set(p.spec()) == {"gw", "allow", "block", "wall", "quic", "targets", "ports", "refuse", "adtech"}
    assert p.adtech is True  # (revert) the LG wall stands by default
    # whatever the settings name as a resolver, the walls are never tried against a real one
    assert probe.plan(dataclasses.replace(S, dns_bootstrap="9.9.9.9"), lg).wall == p.wall


def test_the_connection_out_goes_to_a_neutral_server_and_never_to_the_tvs_vendor(lg):
    """The target is where the profile's blocklists are fetched from, hosts the gateway's own software
    asks every day, or the one TV_PROBE_TARGET names. A must-allow host is never one, whoever names it,
    and a run that is told not to connect hands the client no target at all."""
    p = probe.plan(S, lg)
    assert p.targets == ("adguardteam.github.io", "cdn.jsdelivr.net") == tuple(probe.list_hosts(lg)[:2])
    assert not set(p.targets) & set(lg.must_allow)
    named = probe.plan(dataclasses.replace(S, tv_probe_target="static.example.org"), lg)
    assert named.targets == ("static.example.org",)
    vendor = probe.plan(dataclasses.replace(S, tv_probe_target="snu.lge.com"), lg)
    assert vendor.targets == ()  # and the step then says no neutral server is known
    # a name under a must-allow host is the vendor's too (the filter's own suffix match), whatever its case
    assert probe.plan(dataclasses.replace(S, tv_probe_target="Cdn.SNU.lge.com"), lg).targets == ()
    assert probe.plan(dataclasses.replace(S, tv_probe_target="lge.com.example.org"), lg).targets == (
        "lge.com.example.org",
    )
    assert outcomes(probe.judge(vendor, obs(path=[]), PORT, UP, never))["path"] == SKIPPED
    assert p.spec()["targets"] == list(p.targets) and p.spec(connect=False)["targets"] is None
    for bad in ("203.0.113.9", "UPPER.example", "nodot", "a b.example", "https://x.example/"):
        with pytest.raises(ValueError, match="TV_PROBE_TARGET"):
            config.load("/nonexistent", tv_probe_target=bad)
    assert config.load("/nonexistent", tv_probe_target="cdn.example.net").tv_probe_target == "cdn.example.net"


def recorded(monkeypatch, answers):
    """The client's primitives, recorded: (lookups, handshakes, port tries). The port tries are answered
    here too, as a gateway that refuses what must be refused and lets the rest out: left to the real
    `ports_try`, this suite sent them from the machine it runs on, and passed or not by what that
    machine's own router said."""
    asked, shaken, tried = [], [], []

    def gateway(addr, ports, gw, wait=0.0, refuse=()):
        assert addr == probe.WALL_ADDR, "a port is tried at the documentation address and nowhere else"
        tried.append((list(ports), list(refuse)))
        return {
            f"{proto}/{port}": "refused" if (proto, port) in refuse else "silent" for proto, port in ports
        }

    monkeypatch.setattr(probe, "ports_try", gateway)
    monkeypatch.setattr(
        probe, "ask", lambda name, server, timeout=2.0: asked.append((name, server)) or answers(name)
    )
    monkeypatch.setattr(
        probe,
        "handshake",
        lambda addr, name, timeout=3.0, device="": shaken.append((addr, name, device)) or ("ok", None),
    )
    return asked, shaken, tried


DOT, QUIC, ADTECH = probe.WALLS["dot"], probe.WALLS["quic"], probe.WALLS["adtech"]


def test_the_only_packet_of_the_client_that_can_leave_the_home_is_one_handshake_with_the_target(monkeypatch):
    """What the client sends: lookups at the gateway's resolver, one handshake with the target's address,
    and one try of the ports and the walls together at the documentation address (ports_try, whose time to
    live ends at the next hop). A must-allow name's address is never connected to, and no real resolver
    is ever addressed."""
    table = {**{n: [VENDOR] for n in NAMES}, TARGET: [ADDR], "alphonso.tv": ["0.0.0.0"]}
    asked, shaken, tried = recorded(monkeypatch, table.__getitem__)
    seen, held = probe.observe(P.spec())
    assert held is None and shaken == [(ADDR, TARGET, "")]
    assert asked == [
        *((n, "10.10.10.1") for n in NAMES),  # every must-allow name, at the gateway
        (TARGET, "10.10.10.1"),
        ("alphonso.tv", "10.10.10.1"),
        ("alphonso.tv", WALL),  # the redirect: only the gateway can answer a lookup aimed there
    ]
    # the walls with the ports, each of them a port that must be refused (ports_try asserts the address)
    assert tried == [([*P.ports, DOT, QUIC], [DOT, QUIC])]
    assert (seen["dot"], seen["quic"], seen["adtech"]) == ("refused", "refused", None)
    assert set(seen["ports"]) == {f"{proto}/{port}" for proto, port in P.ports}
    assert {a for a, *_ in shaken} | {s for _, s in asked} == {ADDR, WALL, "10.10.10.1"}
    assert probe.judge(P, seen, PORT, UP, never).verdict == PASS
    # a run that makes no connection out: the same without the target, and no handshake at all
    asked.clear(), shaken.clear()
    seen, _ = probe.observe(P.spec(connect=False))
    assert shaken == [] and TARGET not in [n for n, _ in asked] and seen["path"] is None
    v = probe.judge(P, seen, PORT, UP, never)
    assert v.verdict == PASS and outcomes(v)["path"] == SKIPPED


def test_a_resolver_that_is_away_is_asked_twice_and_no_more(monkeypatch):
    asked, _, _ = recorded(monkeypatch, lambda name: None)
    many = dataclasses.replace(P, allow=tuple(f"n{i}.example" for i in range(9)))
    seen, _ = probe.observe(many.spec(connect=False))
    assert [n for n, s in asked if s == "10.10.10.1"] == ["n0.example", "n1.example", "alphonso.tv"]
    assert [a["answers"] for a in seen["allow"]] == [None, None]


def test_a_profile_without_must_allow_names_has_no_lookup_step():
    from tvgw import profile

    generic = profile.load("generic-tv")
    p = probe.plan(S, generic)
    assert p.allow == () and p.block == verify.sentinels(generic)[0] and len(p.targets) == 2
    v = probe.judge(p, obs(allow=[]), PORT, UP, never)
    assert v.verdict == PASS and outcomes(v)["lookup"] == SKIPPED and outcomes(v)["path"] == PASS


# ---- the verdict: every row of judge's table ---------------------------------------------------------------

FAILED_TLS = obs(path=[{"name": TARGET, "answers": [ADDR], "addr": ADDR, "tls": "silent"}])
SILENT = obs(allow=[{"name": n, "answers": None} for n in NAMES], blocked=None, redirect=None, path=None)
ONE_BLOCKED = obs(allow=[{"name": NAMES[0], "answers": ["0.0.0.0"]}, {"name": NAMES[1], "answers": [VENDOR]}])
RULED = obs(path=[{"name": TARGET, "answers": [ADDR], "addr": ADDR, "tls": "refused", "ruled": True}])
TARGET_BLOCKED = obs(path=[{"name": TARGET, "answers": ["0.0.0.0"], "addr": None, "tls": None}])
HOP = {**GOOD["ports"], "tcp/443": "expired"}  # the next hop answered the web's try by time-exceeded
ROWS = [
    # step, what was seen, the port, the uplink, the gateway's own try, the outcome, words of the detail
    ("port", GOOD, PORT, UP, None, PASS, ""),
    (
        "port",
        GOOD,
        Port(False, None, "wlan0", "eth0", "eth0"),
        UP,
        None,
        FAIL,
        "forwarding is off for the TV's port",
    ),
    ("port", GOOD, Port(False, None, "wlan0", "eth0", "eth0"), DOWN, None, FAIL, "forwarding is off"),
    (
        "port",
        GOOD,
        Port(True, "tun0", "wlan0", "eth0", "eth0"),
        UP,
        None,
        FAIL,
        "would leave by tun0, not wlan0",
    ),
    ("port", GOOD, Port(True, "tun0", "wlan0", "eth0", "eth0"), DOWN, None, UNKNOWN, "the uplink is down"),
    (
        "port",
        GOOD,
        Port(True, "wlan0", "wlan0", "wlan0", "eth0"),
        UP,
        None,
        FAIL,
        "answers to the TV would leave by wlan0",
    ),
    ("lookup", GOOD, PORT, UP, None, PASS, ""),
    (
        "lookup",
        SILENT,
        PORT,
        UP,
        {"resolver": True},
        FAIL,
        "answers the gateway itself and nothing at the TV's position",
    ),
    ("lookup", SILENT, PORT, UP, {"resolver": False}, UNKNOWN, "answers nobody"),
    ("lookup", SILENT, PORT, UP, {}, UNKNOWN, "answers nobody"),
    ("lookup", ONE_BLOCKED, PORT, UP, None, UNKNOWN, "1 of 2 must-allow names got no address"),
    (
        "lookup",
        obs(allow=[{"name": NAMES[0], "answers": []}, {"name": NAMES[1], "answers": []}]),
        PORT,
        UP,
        None,
        UNKNOWN,
        "2 of 2",
    ),
    (
        "lookup",
        obs(allow=GOOD["allow"][:1]),
        PORT,
        UP,
        None,
        UNKNOWN,
        "1 of 2",
    ),  # a name that was never asked
    ("path", GOOD, PORT, UP, None, PASS, ""),
    ("path", obs(path=None), PORT, UP, None, SKIPPED, "no connection out was due"),
    ("path", FAILED_TLS, PORT, DOWN, None, UNKNOWN, "the uplink is down"),
    ("path", RULED, PORT, UP, None, UNKNOWN, "name another with TV_PROBE_TARGET"),
    ("path", TARGET_BLOCKED, PORT, UP, None, UNKNOWN, "name another with TV_PROBE_TARGET"),
    ("path", FAILED_TLS, PORT, UP, {"path": True}, FAIL, "completes from the gateway by the same uplink"),
    ("path", FAILED_TLS, PORT, UP, {"path": False}, UNKNOWN, "from the gateway by the same uplink too"),
    (
        "path",
        FAILED_TLS,
        PORT,
        UP,
        {},
        UNKNOWN,
        "from the gateway by the same uplink too",
    ),  # no try could be made
    ("blocked", GOOD, PORT, UP, None, PASS, ""),
    ("blocked", obs(blocked=[ADDR]), PORT, UP, None, UNKNOWN, "did not give its blocked answer"),
    (
        "blocked",
        obs(blocked=[]),
        PORT,
        UP,
        None,
        UNKNOWN,
        "did not give its blocked answer",
    ),  # empty is not blocked
    ("blocked", obs(blocked=None), PORT, UP, None, UNKNOWN, "gave no answer"),
    ("dot", GOOD, PORT, UP, None, PASS, ""),
    ("dot", obs(dot="silent"), PORT, UP, None, FAIL, "DNS over TLS was not refused by the gateway"),
    ("dot", obs(dot="connected"), PORT, UP, None, FAIL, "was not refused"),
    ("dot", obs(dot="unreachable"), PORT, UP, None, FAIL, "was not refused"),
    ("dot", obs(dot="silent"), PORT, DOWN, None, UNKNOWN, "the uplink is down"),
    ("quic", GOOD, PORT, UP, None, PASS, ""),
    ("quic", obs(quic="silent"), PORT, UP, None, FAIL, "QUIC was not refused by the gateway"),
    ("quic", obs(quic="answered"), PORT, UP, None, FAIL, "was not refused"),
    ("quic", obs(quic="silent"), PORT, DOWN, None, UNKNOWN, "the uplink is down"),
    # (walls) only the gateway's own refusal passes: a reset names no sender, and is the gateway's only
    # beside the next hop's time-exceeded for another TCP try (HOP). Until 2026-11-17 any reset passed
    ("dot", obs(dot="expired"), PORT, UP, None, FAIL, "was not refused"),  # it died at the next hop: let out
    ("dot", obs(dot="reset"), PORT, UP, None, UNKNOWN, "reset, by the gateway or by the next hop"),
    ("dot", obs(dot="reset", ports=HOP), PORT, UP, None, PASS, ""),
    ("quic", obs(quic="reset", ports=HOP), PORT, UP, None, UNKNOWN, "cannot be told apart"),  # UDP has none
    ("dot", obs(dot="unroutable"), PORT, UP, None, UNKNOWN, "the gateway had no route out for DNS over TLS"),
    ("dot", obs(dot="unattributed"), PORT, UP, None, UNKNOWN, "an error the probe cannot attribute"),
    ("dot", obs(dot=None), PORT, UP, None, UNKNOWN, "DNS over TLS was not tried"),
    (
        "dot",
        obs(dot="reset", ports=HOP),
        PORT,
        DOWN,
        None,
        PASS,
        "",
    ),  # the gateway's own, whatever the uplink
    ("redirect", GOOD, PORT, UP, None, PASS, ""),
    (
        "redirect",
        obs(redirect=[ADDR]),
        PORT,
        UP,
        None,
        PASS,
        "",
    ),  # whatever it says, only the gateway could answer
    ("redirect", obs(redirect=None), PORT, UP, None, FAIL, "was not answered by the gateway's filter"),
    ("redirect", SILENT, PORT, UP, {"resolver": False}, UNKNOWN, "answers nothing here"),
]


@pytest.mark.parametrize(("step", "seen", "port", "uplink", "gateway", "outcome", "said"), ROWS)
def test_every_row_of_the_verdict_table(step, seen, port, uplink, gateway, outcome, said):
    """`fail` only for what an apply can cause, and for the connection out only beside the gateway's own
    success by the same uplink; what the filter answers for a name is never a `fail` here."""
    control = never if gateway is None else (lambda: gateway)
    v = probe.judge(P, seen, port, uplink, control)
    stage = next(s for s in v.stages if s.name == step)
    assert stage.outcome == outcome, stage
    assert said in stage.detail
    worst = FAIL if FAIL in outcomes(v).values() else UNKNOWN if UNKNOWN in outcomes(v).values() else PASS
    assert v.verdict == worst


def test_everything_as_it_should_be_passes_and_asks_no_control():
    v = probe.judge(P, GOOD, PORT, UP, never)
    assert v.verdict == PASS and v.reason == "" and v.word == ""
    assert outcomes(v) == dict.fromkeys(
        ("port", "lookup", "lists", "path", "blocked", "dot", "quic", "redirect", "ports"), PASS
    )
    assert "quic" not in outcomes(probe.judge(dataclasses.replace(P, quic=False), obs(quic=None), PORT, UP))
    assert probe.judge(P, FAILED_TLS, PORT, UP, None).verdict == UNKNOWN  # no control: no blame


def test_no_fault_the_firewall_cannot_cause_is_a_fail():
    """The filter paused, a list emptied, the resolver stopped, its upstream away, the internet down:
    each is said, and none of them fails the probe or could undo an apply."""
    paused = obs(blocked=[ADDR], redirect=[ADDR])  # the filter answers everything with its real address
    away = obs(
        allow=[{"name": n, "answers": []} for n in NAMES],
        path=[{"name": TARGET, "answers": [], "addr": None, "tls": None}],
    )
    for seen, gateway in (
        (paused, {}),
        (away, {"path": False}),
        (SILENT, {"resolver": False}),
        (ONE_BLOCKED, {}),
    ):
        v = probe.judge(P, seen, PORT, UP, lambda g=gateway: g)
        assert v.verdict == UNKNOWN and FAIL not in outcomes(v).values(), seen


def test_the_second_target_is_enough():
    two = obs(path=[{"name": "a.example", "answers": [ADDR], "addr": ADDR, "tls": "refused"},
                    {"name": TARGET, "answers": [ADDR], "addr": ADDR, "tls": "ok"}])  # fmt: skip
    assert probe.judge(P, two, PORT, UP, never).verdict == PASS


def test_the_gateways_own_try_goes_by_the_uplink_the_tv_uses_and_only_at_what_failed(monkeypatch):
    """The gateway's own traffic may leave by a VPN tunnel while the TV leaves by the uplink: a try by
    the tunnel would say nothing about the TV's way. The socket is bound to the uplink's interface; one
    that cannot be bound, or a target the probe had no address for, proves nothing. And the resolver is
    asked only when it answered the probe nothing at all, the blocked name, which needs no upstream and
    no cache."""
    asked, shaken, _ = recorded(monkeypatch, lambda name: ["0.0.0.0"])
    assert probe.control(P, FAILED_TLS, "wlan0") == {"path": True}
    assert shaken == [(ADDR, TARGET, "wlan0")] and asked == []
    assert probe.control(P, FAILED_TLS, "") == {}  # no uplink named: no try
    assert probe.control(P, TARGET_BLOCKED, "wlan0") == {"path": False}  # no address to try
    monkeypatch.setattr(probe, "handshake", lambda addr, name, timeout=3.0, device="": ("unbound", None))
    assert probe.control(P, FAILED_TLS, "wlan0") == {"path": False}
    asked.clear()
    assert probe.control(P, SILENT, "wlan0") == {"resolver": True} and asked == [
        ("alphonso.tv", "10.10.10.1")
    ]
    assert probe.control(P, ONE_BLOCKED, "wlan0") == {}  # the resolver answered: nothing to ask it again


def test_a_socket_that_cannot_be_bound_to_the_uplink_makes_no_connection(monkeypatch):
    made = []

    class Sock:
        def settimeout(self, _t): ...
        def setsockopt(self, *_a):
            raise PermissionError(1, "not root")

        def connect(self, addr):
            made.append(addr)

        def close(self): ...

    monkeypatch.setattr(probe.socket, "socket", lambda *a: Sock())
    assert probe.handshake(ADDR, TARGET, device="wlan0") == ("unbound", None) and made == []


def test_the_held_connection_names_the_2026_10_30_fault():
    E = probe.Entry
    assert probe.held_stage(E("77"), E("77"), "open") == Stage("held", PASS)
    cut = probe.held_stage(E("77"), E("91"), "open")  # picked up again under a new entry, as in the incident
    assert cut.outcome == FAIL and "the apply cut a live connection" in cut.detail
    assert probe.held_stage(E("77"), None, "open").outcome == FAIL
    # the far end's own goodbye removes the entry too: nothing to judge, and no verdict moved by it
    assert probe.held_stage(E("77"), None, "closed").outcome == SKIPPED
    assert probe.held_stage(None, None, None).outcome == SKIPPED  # no conntrack tool, or nothing held
    # the uplink lost its carrier or took a new address meanwhile: the kernel ended it, not the apply
    assert probe.held_stage(E("77"), None, "open", steady=False).outcome == SKIPPED
    assert probe.judge(P, GOOD, PORT, UP, never, held=cut).verdict == FAIL
    assert (
        probe.judge(P, GOOD, PORT, UP, never, held=probe.held_stage(E("7"), None, "closed")).verdict == PASS
    )


@pytest.mark.parametrize(
    ("peer", "said"),
    [
        ("reset", "the held connection was reset across the apply; who reset it cannot be told"),
        (None, "the test client did not answer"),
        ("garbled", "the test client did not answer"),
    ],
)
def test_a_held_connection_that_was_reset_or_not_reported_is_unknown_never_the_far_ends_goodbye(peer, said):
    """L6-10: a reset is what the client sees when new rules reject the old flow, and a client that sent
    no second line said nothing at all; both were skipped as "the far end closed the held connection
    first", and the stage built to catch a cut connection let a loud cut stay a pass. Unknown undoes
    nothing, so no revert is made possible by it."""
    E = probe.Entry
    for after in (None, E("91")):  # the entry gone, or another in its place
        assert probe.held_stage(E("77"), after, peer) == Stage("held", UNKNOWN, said)
    assert probe.held_stage(E("77"), E("77"), peer).outcome == PASS  # the same entry: nothing was cut
    assert probe.held_stage(E("77"), None, peer, steady=False).outcome == SKIPPED  # the uplink's doing
    assert probe.judge(P, GOOD, PORT, UP, never, held=probe.held_stage(E("7"), None, peer)).verdict == UNKNOWN


def test_a_new_entry_with_the_old_ones_id_is_told_by_its_start_and_its_count(tmp_path):
    """The kernel's id is a hash of the entry's address, which the next entry of a cut connection often
    gets (CI, 2026-11-07: the rule-60 rewrite looked harmless in about half the runs). The same id with
    another start, or with fewer packets than before, is a new entry; the same id and start with the count
    grown is the connection going on."""
    E = probe.Entry
    old = E("77", "Sat Nov  7 10:00:01 2026", 12)
    assert E("77", "Sat Nov  7 10:00:01 2026", 15).same_as(old)
    assert not E("77", "Sat Nov  7 10:00:09 2026", 15).same_as(old)  # same address, made again
    assert not E("77", "Sat Nov  7 10:00:01 2026", 2).same_as(old)  # fewer packets: a count that began again
    assert not E("78", "Sat Nov  7 10:00:01 2026", 15).same_as(old)
    assert E("77", "", 15).same_as(E("77", "", 12)) and not E("77", "", 3).same_as(
        E("77", "", 12)
    )  # no timestamps
    assert E("77").same_as(E("77")) and E("77", "", -1).same_as(E("77", "", 40))  # no counts: the id alone
    assert probe.held_stage(old, E("77", "Sat Nov  7 10:00:09 2026", 2), "open").outcome == FAIL
    # what conntrack prints, read: the TV's side's count is the first, the start is kept whole
    host = Host(
        answers={
            ("conntrack", "-L"): lambda _c: (
                0,
                "tcp      6 431999 ESTABLISHED src=10.10.10.30 dst=203.0.113.44 sport=40000 dport=443 packets=12"
                " bytes=1000 src=203.0.113.44 dst=198.51.100.2 sport=443 dport=40000 packets=11 bytes=900"
                " [ASSURED] mark=0 use=1 id=3141 [start=Sat Nov  7 10:00:01 2026] \n",
            )
        }
    )
    env = host.env(tmp_path)
    entry = probe.conntrack_entry(env, P, {"dst": "203.0.113.44", "sport": 40000})
    assert entry == E("3141", "Sat Nov  7 10:00:01 2026", 12)
    assert host.calls[-1][-2:] == ("-o", "id,timestamp")


# ---- the gateway's own readings ---------------------------------------------------------------------------

FILES = {
    "/proc/sys/net/ipv4/ip_forward": "1\n",
    "/proc/sys/net/ipv4/conf/eth0/forwarding": "1\n",
    "/proc/sys/net/ipv4/conf/wlan0/forwarding": "1\n",
    "/sys/class/net/wlan0/carrier": "1\n",
}
ADDRS = json.dumps([{"addr_info": [{"family": "inet", "local": "192.0.2.48", "scope": "global"}]}])
ROUTE = json.dumps([{"dst": WALL, "dev": "wlan0"}])
BACK = json.dumps([{"dst": "10.10.10.17", "dev": "eth0"}])
LOADED = (
    'table inet tvgw {\n\tchain probe_fwd {\n\t\tiifname "tvgw-probe" ip saddr != 10.10.10.30 drop\n\t}\n}\n'
)


class Host:
    """A gateway as the probe sees it: files, and commands with their exit status and output."""

    def __init__(self, files=None, answers=None, euid=0):
        self.files = {**FILES, **(files or {})}
        # a test's own answers are looked at first, each by the words a command starts with
        self.answers = [
            *(answers or {}).items(),
            (("ip", "-j", "-4", "addr", "show", "dev", "wlan0"), (0, ADDRS)),
            (("ip", "-j", "route", "get", WALL, "from", "10.10.10.17", "iif", "eth0"), (0, ROUTE)),
            (("ip", "-j", "route", "get", "10.10.10.17", "from", "10.10.10.1"), (0, BACK)),
            (("nft", "list", "chain", "inet", "tvgw", "probe_fwd"), (0, LOADED)),
            (("nft", "get", "element"), (1, "")),  # the target's address is in no set the TV's rules refuse
        ]
        self.calls: list[tuple] = []
        self.writes: dict[str, str] = {}
        self.euid = euid

    def run(self, cmd, timeout=15.0):
        self.calls.append(tuple(cmd))
        for key, answer in self.answers:
            if tuple(cmd[: len(key)]) == key and (key != CLIENT or "--client" in cmd):
                return answer(cmd) if callable(answer) else answer
        return 0, ""

    def env(self, tmp_path, **kw) -> probe.Env:
        return probe.Env(
            run=self.run,
            read=lambda path: self.files.get(path, ""),
            write=lambda path, text: self.writes.__setitem__(path, text) or True,
            lock=str(tmp_path / "probe.lock"),
            sleep=lambda _s: None,
            euid=lambda: self.euid,
            exists=lambda path: path in self.files,
            **kw,
        )


def client_says(*lines: dict):
    """An answer for the client's command: each call prints the next of `lines`."""
    left = list(lines)
    return lambda _cmd: (0, json.dumps({"obs": left.pop(0) if len(left) > 1 else left[0]}) + "\n")


CLIENT = ("ip", "netns", "exec", "tvgw-probe")


def test_the_uplink_reading_is_carrier_and_an_address_on_the_way_out(tmp_path):
    assert probe.read_uplink(S, Host().env(tmp_path)) == UP
    gone = Host(files={"/sys/class/net/wlan0/carrier": "0\n"})
    assert probe.read_uplink(S, gone.env(tmp_path)) == DOWN
    absent = Host(files={"/proc/sys/net/ipv4/conf/wlan0/forwarding": ""})
    assert probe.read_uplink(S, absent.env(tmp_path)).why == "the uplink is down: wlan0 does not exist"
    bare = Host(answers={("ip", "-j", "-4", "addr"): (0, "[]")})
    assert probe.read_uplink(S, bare.env(tmp_path)).why == "the uplink is down: wlan0 has no IPv4 address"
    # the tunnel as the uplink: the tunnel, and the home network's interface under it
    vpn = dataclasses.replace(S, uplink="vpn")
    files = {"/proc/sys/net/ipv4/conf/tun0/forwarding": "1\n", "/sys/class/net/tun0/carrier": "1\n"}
    up = Host(files=files, answers={("ip", "-j", "-4", "addr", "show", "dev", "tun0"): (0, ADDRS)})
    assert probe.read_uplink(vpn, up.env(tmp_path)).up
    under = Host(files={**files, "/sys/class/net/wlan0/carrier": "0\n"})
    assert not probe.read_uplink(vpn, under.env(tmp_path)).up
    assert not probe.read_uplink(vpn, Host().env(tmp_path)).up  # no tunnel at all


def test_the_port_is_read_from_the_tvs_own_switches_and_the_kernels_route(tmp_path):
    assert probe.read_port(S, P, Host().env(tmp_path)) == PORT
    off = Host(files={"/proc/sys/net/ipv4/conf/eth0/forwarding": "0\n"})
    assert probe.read_port(S, P, off.env(tmp_path)).forwarding is False
    lost = Host(answers={("ip", "-j", "route", "get"): (2, "")})
    assert probe.read_port(S, P, lost.env(tmp_path)) == Port(True, None, "wlan0", None, "eth0")
    # the gateway's own answers to the TV: table 100's TV-subnet route, which no packet of the probe's
    # crosses (its own way back is a /32 of its own), is asked for as verify's gw_reply_route asks
    wrong = Host(answers={("ip", "-j", "route", "get", "10.10.10.17"): (0, json.dumps([{"dev": "wlan0"}]))})
    port = probe.read_port(S, P, wrong.env(tmp_path))
    assert port.reply_dev == "wlan0" and probe.judge(P, GOOD, port, UP, never).word == "port"


@pytest.mark.parametrize(
    ("s", "host", "said"),
    [
        (dataclasses.replace(S, tv_probe="off"), Host(), "the probe is off"),
        (S, Host(euid=1000), "needs root"),
        # a port of the gateway's that carries the pair's name: said, and the cleanup that would remove it never runs
        (
            dataclasses.replace(S, tv_if="tvgw-probe"),
            Host(files={"/sys/class/net/tvgw-probe/carrier": "1\n"}),
            "named tvgw-probe",
        ),
        (dataclasses.replace(S, tv_probe_ip="10.10.10.15"), Host(), "inside the DHCP pool"),
        (S, Host(answers={("nft", "list", "chain"): (1, "")}), "no rules for the probe at this address yet"),
        (
            dataclasses.replace(S, tv_probe_ip="10.10.10.31"),
            Host(),
            "no rules for the probe at this address yet",
        ),
    ],
)
def test_nothing_is_sent_until_the_loaded_firewall_has_the_probes_rules(tmp_path, lg, s, host, said):
    """Without its chains the probe's packets would meet a rule of the TV's and be counted there. The
    run says unknown, creates nothing and sends nothing."""
    v = probe.run(s, lg, host.env(tmp_path))
    assert v.verdict == UNKNOWN and said in v.reason
    assert not [c for c in host.calls if c[:2] in (("ip", "netns"), ("ip", "link"), ("ip", "route"))]
    assert host.writes == {}


def test_a_run_makes_the_namespace_observes_judges_and_removes_it(tmp_path, lg):
    host = Host(answers={CLIENT: client_says(whole(lg))})
    v = probe.run(S, lg, host.env(tmp_path))
    assert v.verdict == PASS and v.t > 0
    made = [c for c in host.calls if c[0] == "ip" and c[1] not in ("-j",)]
    assert made[:4] == [
        ("ip", "netns", "pids", "tvgw-probe"),  # whatever a killed run left goes first
        ("ip", "netns", "del", "tvgw-probe"),
        ("ip", "link", "del", "tvgw-probe"),
        ("ip", "netns", "add", "tvgw-probe"),
    ]
    link = made[4]
    assert link == (
        "ip", "link", "add", "tvgw-probe", "address", probe.GW_MAC, "type", "veth",
        "peer", "name", "tvgw-probe0", "address", probe.NS_MAC, "netns", "tvgw-probe",
    )  # fmt: skip
    assert ("ip", "route", "replace", "10.10.10.30/32", "dev", "tvgw-probe", "src", "10.10.10.1") in made
    assert (
        "ip",
        "route",
        "replace",
        "10.10.10.30/32",
        "dev",
        "tvgw-probe",
        "src",
        "10.10.10.1",
        "table",
        "100",
    ) in made
    # every route and neighbour it writes names its own address or the pair: none of the TV's is touched
    for c in made:
        if c[1] in ("route", "neigh") or c[3:4] in (("route",), ("neigh",), ("addr",)):
            assert "tvgw-probe" in c or "tvgw-probe0" in c, c
    assert not [c for c in made if "eth0" in c or "wlan0" in c]
    assert made[-3:] == [("ip", "netns", "pids", "tvgw-probe"), ("ip", "netns", "del", "tvgw-probe"), ("ip", "link", "del", "tvgw-probe")]  # fmt: skip
    # the pair's gateway end forwards as the TV's port does, takes no IPv6 and never gets an address
    assert host.writes.pop(probe.PATH_STAMP).endswith(" pass\n")  # when it last connected out
    assert host.writes.pop(probe.LAST).endswith(" pass -\n")  # what tvgw-apply reads before it waits
    assert host.writes == {
        "/proc/sys/net/ipv6/conf/tvgw-probe/disable_ipv6": "1\n",
        "/proc/sys/net/ipv4/conf/tvgw-probe/rp_filter": "1\n",
        "/proc/sys/net/ipv4/conf/tvgw-probe/forwarding": "1\n",
    }
    assert not [c for c in made if c[1] == "addr"]
    # the client is this module, run inside the namespace with the plan and nothing else
    (client,) = [c for c in host.calls if c[:4] == CLIENT and "--client" in c]
    assert (
        client[5:8] == ("-m", "tvgw.probe", "--client") and json.loads(client[8]) == probe.plan(S, lg).spec()
    )


def test_a_port_that_does_not_forward_keeps_the_probes_packets_back_too(tmp_path, lg):
    host = Host(
        files={"/proc/sys/net/ipv4/conf/eth0/forwarding": "0\n"}, answers={CLIENT: client_says(whole(lg))}
    )
    v = probe.run(S, lg, host.env(tmp_path))
    assert host.writes["/proc/sys/net/ipv4/conf/tvgw-probe/forwarding"] == "0\n"
    assert v.verdict == FAIL and v.word == "port"


def test_a_failure_is_taken_again_before_it_stands(tmp_path, lg, monkeypatch):
    monkeypatch.setattr(probe, "control", lambda p, o, dev="", left=None: {"path": True})
    slept: list[float] = []
    once = Host(answers={CLIENT: client_says(whole(lg, FAILED_TLS), whole(lg))})
    env = once.env(tmp_path)
    env.sleep = slept.append
    assert probe.run(S, lg, env).verdict == PASS and slept == [probe.RETRY_PAUSE]
    twice = Host(answers={CLIENT: client_says(whole(lg, FAILED_TLS), whole(lg, FAILED_TLS))})
    v = probe.run(S, lg, twice.env(tmp_path))
    assert v.verdict == FAIL and len([c for c in twice.calls if "--client" in c]) == 2


def test_a_target_in_a_set_the_tvs_rules_refuse_is_found_before_any_blame(tmp_path, lg, monkeypatch):
    monkeypatch.setattr(probe, "control", lambda p, o, dev="", left=None: {"path": True})
    refused = obs(path=[{"name": TARGET, "answers": [ADDR], "addr": ADDR, "tls": "refused"}])
    in_doh4 = {
        ("nft", "get", "element", "inet", "tvgw", "doh4", f"{{ {ADDR} }}"): (0, ""),
        CLIENT: client_says(whole(lg, refused)),
    }
    v = probe.run(S, lg, Host(answers=in_doh4).env(tmp_path))
    assert v.verdict == UNKNOWN and "name another with TV_PROBE_TARGET" in v.reason
    v = probe.run(S, lg, Host(answers={CLIENT: client_says(whole(lg, refused))}).env(tmp_path))
    assert v.verdict == FAIL and v.word == "path"  # in no such set: the refusal is the path's


def test_the_ten_minute_check_connects_out_four_times_a_day_and_the_command_always(tmp_path, lg):
    """A run told `connect=None` makes the connection out only when one is due: none for six hours, or
    the last one did not pass and an hour has gone by. The stamp is written only by a run that made one."""
    host = Host(answers={CLIENT: client_says(whole(lg))})
    env = host.env(tmp_path)
    env.read = lambda path: host.writes.get(path, host.files.get(path, ""))

    def targets() -> list:
        return [json.loads(c[8])["targets"] for c in host.calls if "--client" in c]

    assert probe.run(S, lg, env, connect=None).verdict == PASS and targets()[-1] is not None  # no stamp yet
    stamp = host.writes[probe.PATH_STAMP]
    assert stamp.split()[1] == "pass"
    assert (
        probe.run(S, lg, env, connect=None).verdict == PASS and targets()[-1] is None
    )  # minutes later: none
    assert host.writes[probe.PATH_STAMP] == stamp
    assert probe.run(S, lg, env).verdict == PASS and targets()[-1] is not None  # `sudo tvgw probe`: always
    now = float(stamp.split()[0])
    assert not probe.path_due(env, now + probe.PATH_EVERY - 1) and probe.path_due(env, now + probe.PATH_EVERY)
    host.writes[probe.PATH_STAMP] = f"{now:.0f} unknown\n"
    assert not probe.path_due(env, now + 3599) and probe.path_due(env, now + 3600)
    host.writes[probe.PATH_STAMP] = "garbage\n"
    assert probe.path_due(env, now)
    assert 86400 // probe.PATH_EVERY == 4


@pytest.mark.parametrize(
    "answers",
    [
        {("ip", "netns", "add"): (1, "")},  # no namespaces here
        {("ip", "link", "add"): (2, "")},  # no veth
        {CLIENT: (0, "")},  # the client printed nothing
        {CLIENT: (127, "")},  # it never ran, or hung past its time
        {CLIENT: (0, "not json\n")},
        {CLIENT: lambda _c: (_ for _ in ()).throw(RuntimeError("boom"))},  # the probe's own bug
    ],
)
def test_a_probe_that_breaks_changes_nothing_but_its_own_verdict(tmp_path, lg, answers):
    """Missing, crashed or hung: the verdict is unknown, nothing raises, and what it made is removed."""
    host = Host(answers=answers)
    v = probe.run(S, lg, host.env(tmp_path))
    assert v.verdict == UNKNOWN and v.stages[0].name == "probe"
    assert host.calls[-1] == ("ip", "link", "del", "tvgw-probe")
    assert probe.EXIT[v.verdict] == 4


def test_one_run_at_a_time(tmp_path, lg):
    import fcntl

    host = Host(answers={CLIENT: client_says(whole(lg))})
    env = host.env(tmp_path)
    monkey = pytest.MonkeyPatch()
    monkey.setattr(probe, "LOCK_WAIT", 0.0)
    fd = os.open(env.lock, os.O_RDWR | os.O_CREAT, 0o600)
    try:
        fcntl.flock(fd, fcntl.LOCK_EX)
        v = probe.run(S, lg, env)
    finally:
        os.close(fd)
        monkey.undo()
    assert v.verdict == UNKNOWN and v.reason == "probe: another probe is running"
    assert not [c for c in host.calls if c[:3] == ("ip", "netns", "add")]
    assert probe.run(S, lg, env).verdict == PASS  # and the next one runs


@pytest.mark.parametrize("made", ["a directory", "a link"])
def test_a_lock_that_cannot_be_opened_is_unknown_and_never_a_run_without_one(tmp_path, lg, made):
    """L6-11: the lock lay in the world-writable /run/lock, and one that could not be opened let the run go
    on unlocked: any account could leave a file there that root may not open (fs.protected_regular), and
    two runs at once removed each other's namespace. Here the lock's path is a directory, or a link, which
    is never followed. Nothing is made or removed, before an apply or by the 10-minute check."""
    host = Host(answers={CLIENT: client_says(whole(lg))})
    env = host.env(tmp_path)
    elsewhere = tmp_path / "elsewhere"
    os.mkdir(env.lock) if made == "a directory" else os.symlink(elsewhere, env.lock)
    v = probe.run(S, lg, env)
    assert v.verdict == UNKNOWN and v.reason.startswith("probe: the probe's lock cannot be opened: ")
    (tmp_path / "confirm").mkdir()
    assert probe.across(S, lg, str(tmp_path / "confirm"), env) == 4
    assert (tmp_path / "confirm" / "pre").read_text(encoding="utf-8").startswith("unknown probe\n")
    assert (
        not [c for c in host.calls if c[:2] in (("ip", "netns"), ("ip", "link"))] and not elsewhere.exists()
    )
    host.euid = 1000  # without root nothing is opened, made or removed, and the run says why
    assert probe.run(S, lg, env).reason == "probe: the probe needs root: run it with sudo"


def test_the_lock_lives_in_tvgws_own_directory_which_a_reboot_empties_and_the_run_makes(tmp_path, lg):
    """/run/tvgw is root's alone (tvgw-apply makes it 0755), and /run is emptied at every boot: the
    10-minute check may be the first of tvgw's programs to run after one."""
    assert os.path.dirname(probe.LOCK) == os.path.dirname(probe.LAST) == "/run/tvgw"
    env = Host(answers={CLIENT: client_says(whole(lg))}).env(tmp_path)
    env.lock = str(tmp_path / "tvgw" / "tvgw-probe.lock")
    was = os.umask(0)  # the mode is the run's own, as tvgw-apply's `install -d -m 755`, whatever the umask
    try:
        assert probe.run(S, lg, env).verdict == PASS
    finally:
        os.umask(was)
    assert (tmp_path / "tvgw").is_dir() and (tmp_path / "tvgw").stat().st_mode & 0o777 == 0o755


class Held:
    """The held client of a run on Clock's time: what `across` writes to it, and nothing else."""

    stdin = io.StringIO()

    def kill(self): ...

    def communicate(self, timeout=None):
        return "", ""


SLOW, HUNG = 19.5, 1e9  # the client's longest run with nothing answering; a client that never answers
# the walls gone and the internet beyond the router black-holed: both neutral servers out of reach
DARK = [{"name": n, "answers": [ADDR], "addr": ADDR, "tls": "silent"} for n in ("a.example", TARGET)]
BROKEN = obs(dot="expired", quic="expired", path=DARK)


def on_the_clock(tmp_path, lg, monkeypatch, after, again, gateway, settle_read=0.0) -> list:
    """`across` on a clock that moves only while it waits, each wait taking what its part takes and never
    more than it was given: `after` and `again` are the client's look after the apply and a second one,
    each (seconds, observation or None for no answer); the gateway's own handshake completes at once or,
    black-holed, waits out each timeout it is given, connect and TLS; `settle_read` is the conntrack read
    after the apply. Returns [(the first line, its time)] of what was published, pre then post."""
    now, published = [0.0], []

    def spend(seconds: float, most: float = math.inf) -> bool:
        now[0] += min(seconds, most)
        return seconds <= most

    lines = iter([(1.0, whole(lg)), after])

    def client_line(_proc, timeout):
        cost, seen = next(lines)
        return (
            {"obs": seen and whole(lg, seen), "held": HELD, "held_state": "open"}
            if spend(cost, timeout)
            else None
        )

    host, reads = Host(answers={("conntrack", "-L"): (0, "tcp 6 id=77\n")}), iter([0.0, settle_read])

    def run(cmd, timeout=15.0):
        if "--client" in cmd:  # a second look is a client run of its own
            cost, seen = again
            return (
                (0, json.dumps({"obs": whole(lg, seen)}) + "\n")
                if spend(cost, timeout) and seen
                else (127, "")
            )
        if cmd[0] == "conntrack":
            spend(next(reads))
        return host.run(cmd, timeout)

    def handshake(addr, name, timeout=3.0, device=""):
        assert timeout > 0, "a socket is never given a timeout of no time"
        black = gateway == "black-holed"
        return spend(2 * timeout if black else 0.1) and ("silent" if black else "ok"), None

    env = host.env(tmp_path)
    env.run, env.sleep, env.clock = run, spend, lambda: now[0]
    monkeypatch.setattr(probe, "_client_line", client_line)
    monkeypatch.setattr(probe, "handshake", handshake)
    monkeypatch.setattr(probe.subprocess, "Popen", lambda *a, **k: Held())
    monkeypatch.setattr(
        probe, "_line", lambda v: published.append((f"{v.verdict} {v.word or '-'}", v.reason, now[0])) or ""
    )
    (tmp_path / "confirm").mkdir()
    (tmp_path / "confirm" / "go").touch()  # the apply is done at once
    probe.across(S, lg, str(tmp_path / "confirm"), env)
    return published


NONE_DUE = (HUNG, None)  # a second look nobody expects: one made anyway would read unknown


ONCE = "probe: dot: DNS over TLS was not refused by the gateway, once, and no time was left to take it again"
UNFINISHED = "probe: the test client did not finish"


@pytest.mark.parametrize(
    ("after", "again", "gateway", "settle_read", "want"),
    [
        ((1.0, GOOD), NONE_DUE, "completes", 0.0, ("pass -", "")),
        ((1.0, FAILED_TLS), (1.0, GOOD), "completes", 0.0, ("pass -", "")),  # one lost packet, taken again
        (
            (SLOW, BROKEN),
            (SLOW, BROKEN),
            "black-holed",
            0.0,
            ("fail dot", "dot: DNS over TLS was not refused by the gateway"),
        ),  # 76 s before
        ((HUNG, None), NONE_DUE, "completes", 0.0, ("unknown probe", UNFINISHED)),  # no line after the apply
        ((HUNG, None), NONE_DUE, "completes", 40.0, ("unknown probe", UNFINISHED)),  # nor in what is left
        (
            (SLOW, BROKEN),
            (HUNG, None),
            "black-holed",
            0.0,
            ("unknown probe", UNFINISHED),
        ),  # the second look hangs
        ((SLOW, BROKEN), NONE_DUE, "black-holed", 40.0, ("unknown probe", ONCE)),  # no time left for one
    ],
    ids=[
        "working",
        "taken-again",
        "black-holed",
        "client-silent",
        "client-silent-late",
        "second-look-hangs",
        "no-time-left",
    ],
)
def test_every_path_of_across_publishes_its_verdict_after_within_the_budget(
    tmp_path, lg, monkeypatch, after, again, gateway, settle_read, want
):
    """L6-22: tvgw-apply waits WAIT_AFTER for the verdict after; two slow looks and the gateway's own
    handshakes beside each took 76 s with the internet beyond the router black-holed and the walls broken,
    and a fail that late read as no verdict. Now every wait after `go` gets what is left of BUDGET. A
    failure there is no time to take again is unknown, never a fail: a failure stands only twice."""
    (pre, _, at_go), (post, why, at_post) = on_the_clock(
        tmp_path, lg, monkeypatch, after, again, gateway, settle_read
    )
    assert (pre, (post, why)) == ("pass -", want)
    assert at_post - at_go <= probe.BUDGET + 1e-9


def test_the_gateway_makes_no_try_of_its_own_with_no_time_left():
    """(budget) A socket given no time would raise, and the verdict would be the probe's own error."""
    made = []
    with pytest.MonkeyPatch.context() as mp:
        mp.setattr(probe, "handshake", lambda *a, **k: made.append(a) or ("ok", None))
        mp.setattr(probe, "ask", lambda *a, **k: made.append(a) or [ADDR])
        assert probe.control(P, FAILED_TLS, "wlan0", left=lambda: 0.0) == {"path": False}
        assert probe.control(P, SILENT, "wlan0", left=lambda: 0.0) == {}
        assert made == []
        assert probe.control(P, SILENT, "wlan0", left=lambda: 1.0) == {"resolver": True}


def test_the_budget_is_what_tvgw_apply_waits_for_less_the_time_to_read_it(tmp_path, capsys):
    """`tvgw probe --budget` prints the bound for tvgw-apply to read (its WAIT_AFTER is still its own
    constant: whoever next edits it makes it read this)."""
    text = (ROOT / "deploy" / "nftables" / "tvgw-apply").read_text(encoding="utf-8")
    wait_after = int(re.search(r"^WAIT_AFTER=(\d+)$", text, re.M).group(1))
    assert wait_after - 5 == probe.BUDGET
    conf = tmp_path / "tvgw.conf"
    conf.write_text("TV_PROBE=on\n", encoding="utf-8")
    assert cli.main(["--conf", str(conf), "probe", "--budget"]) == 0 and capsys.readouterr().out == "65\n"


def test_verify_runs_the_probe_so_that_a_sigterm_unwinds_it(tmp_path):
    """L6-21: `tvgw verify --record` runs the probe in its own process, without the handler `tvgw probe`
    installs: a unit stop or its timeout ended Python where it stood, and the pair, its routes and the
    namespace stayed until the next run. A real SIGTERM, in a child that runs a probe stand-in under
    `unwinding`: what it made is removed on the way out, and the exit is the signal's."""
    cleared = tmp_path / "cleared"
    child = (
        "import contextlib, time\nfrom tvgw import probe\n"
        "@contextlib.contextmanager\ndef namespace():\n"
        f"    try: yield\n    finally: open({str(cleared)!r}, 'w').close()\n"
        "def run():\n    with namespace(): print('made', flush=True); time.sleep(30)\n"
        "probe.unwinding(run)\n"
    )
    src = {**os.environ, "PYTHONPATH": str(ROOT / "src")}
    proc = subprocess.Popen([sys.executable, "-c", child], stdout=subprocess.PIPE, env=src, text=True)
    assert proc.stdout.readline() == "made\n"
    proc.terminate()
    assert proc.wait(10) == 143 and cleared.exists()
    proc.stdout.close()

    # in this process: the handler is the probe's while it runs, and the caller's own after it
    def callers(*_):
        return None

    before = signal.signal(signal.SIGTERM, callers)
    try:
        assert probe.unwinding(signal.getsignal, signal.SIGTERM) is probe._ended
        assert signal.getsignal(signal.SIGTERM) is callers
    finally:
        signal.signal(signal.SIGTERM, before)


# ---- the client's own pieces, over loopback ---------------------------------------------------------------


def test_the_words_for_how_an_attempt_ended():
    assert probe._saw(TimeoutError()) == "silent"
    assert probe._saw(ConnectionRefusedError(errno.ECONNREFUSED, "x")) == "refused"
    assert (
        probe._saw(OSError(errno.ENETUNREACH, "x"))
        == probe._saw(OSError(errno.EHOSTUNREACH, "x"))
        == "unreachable"
    )
    assert probe._saw(OSError(errno.ETIMEDOUT, "x")) == "silent"
    assert probe._saw(OSError(errno.EPERM, "x")) == "error"


def test_the_quic_wall_is_tried_with_a_datagram_a_quic_server_must_answer():
    assert probe._payload("udp", "443") == probe.QUIC_PROBE and probe.QUIC_PROBE[0] & 0x80  # a long header
    assert len(probe.QUIC_PROBE) == 1200  # the least a client's first datagram may carry
    assert probe._payload("udp", probe.ODD_PORT) == probe._payload("udp", 123) == probe.PORT_PROBE


def dns_reply(query: bytes, *addrs: str) -> bytes:
    """A resolver's reply to `query`: its question again, then an A record for each of `addrs`."""
    head = query[:2] + b"\x81\x80" + query[4:6] + len(addrs).to_bytes(2, "big") + bytes(4)
    rrs = b"".join(b"\xc0\x0c\x00\x01\x00\x01\x00\x00\x00\x3c\x00\x04" + socket.inet_aton(a) for a in addrs)
    return head + query[12:] + rrs


@pytest.mark.parametrize(
    ("reply", "want"),
    [
        (lambda q: dns_reply(q, ADDR, VENDOR), [ADDR, VENDOR]),
        (dns_reply, []),  # an answer without an address
        (lambda q: q[:2] + b"\x81\x80\x00\x01\x00\x05", []),  # one that cannot be read
        (None, None),  # none at all
    ],
)
def test_a_lookup_takes_the_resolvers_own_reply_and_no_other(reply, want):
    """`ask` over loopback (L6-20: the client's socket half was never run by the suite). Its socket is
    connected: a reply from any other address or port is not taken, however well formed."""
    with (
        socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as resolver,
        socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as stray,
    ):
        resolver.bind(("127.0.0.1", 0))

        def serve():
            query, peer = resolver.recvfrom(512)
            stray.sendto(dns_reply(query, "192.0.2.99"), peer)
            if reply is not None:
                resolver.sendto(reply(query), peer)

        threading.Thread(target=serve, daemon=True).start()
        assert probe.ask("name.example", "127.0.0.1", timeout=0.5, port=resolver.getsockname()[1]) == want


@pytest.mark.parametrize(("far_end", "state"), [("holds", "open"), ("closes", "closed"), ("resets", "reset")])
def test_the_held_connections_state_is_read_from_its_own_socket(far_end, state):
    """`_peer_state` over loopback: what the far end sent after its handshake is read away on the way, and
    an end of the stream or a reset behind it is found."""
    with socket.socket() as listener:
        listener.bind(("127.0.0.1", 0))
        listener.listen(1)
        with socket.create_connection(listener.getsockname(), timeout=2) as held:
            conn, _ = listener.accept()
            conn.sendall(b"session tickets")
            if far_end == "resets":
                conn.setsockopt(socket.SOL_SOCKET, socket.SO_LINGER, struct.pack("ii", 1, 0))
            if far_end != "holds":
                conn.close()
            got, until = probe._peer_state(held), time.monotonic() + 2
            while got == "open" and far_end != "holds" and time.monotonic() < until:  # loopback is fast
                got = probe._peer_state(held)
            conn.close()
    assert got == state


def test_the_client_holds_its_connection_across_the_apply_and_says_how_it_stood(monkeypatch, capsys):
    """`client_main`'s hold over loopback: the first line names the held connection, the plan after the
    apply comes on stdin, and the second line says how the connection stood (here, the far end closed it).
    No plan in time, and it ends after its first line."""
    with socket.socket() as listener:
        listener.bind(("127.0.0.1", 0))
        listener.listen(1)
        held = socket.create_connection(listener.getsockname(), timeout=2)
        conn, _ = listener.accept()
        sport = held.getsockname()[1]
        looks = iter([(GOOD, held), (GOOD, None), (GOOD, held)])
        monkeypatch.setattr(probe, "observe", lambda spec, keep=False: next(looks))
        r, w = os.pipe()
        monkeypatch.setattr(probe.sys, "stdin", os.fdopen(r, encoding="utf-8"))
        with os.fdopen(w, "w", encoding="utf-8") as plan:
            plan.write(json.dumps({"spec": P.spec()}) + "\n")
        conn.close()
        assert probe.client_main([json.dumps(P.spec()), "--hold", "5"]) == 0
        first, second = (json.loads(line) for line in capsys.readouterr().out.splitlines())
        assert first == {"obs": GOOD, "held": {"dst": "127.0.0.1", "sport": sport}}
        assert second == {"obs": GOOD, "held_state": "closed"}
        assert probe.client_main([json.dumps(P.spec()), "--hold", "0.05"]) == 0  # stdin at its end: no plan
        assert len(capsys.readouterr().out.splitlines()) == 1
        held.close()


def test_a_handshake_with_something_that_is_not_tls_is_not_ok():
    with socket.socket() as listener:
        listener.bind(("127.0.0.1", 0))
        listener.listen(1)

        def refuse():
            conn, _ = listener.accept()
            conn.sendall(b"HTTP/1.0 400 no\r\n\r\n")
            conn.close()

        threading.Thread(target=refuse, daemon=True).start()
        port = listener.getsockname()[1]
        state, sock = probe.handshake("127.0.0.1", "name.example", timeout=2, port=port)
    assert state == "tls" and sock is None
    assert probe.tls_context().verify_mode.name == "CERT_NONE"  # the path is judged, not the certificate


# ---- either side of an apply -------------------------------------------------------------------------------


class Client:
    """The held client as `across` drives it: a line before, a line after it is told to go."""

    def __init__(self, first: dict, second: dict | None):
        self.lines = [json.dumps(first) + "\n", *([json.dumps(second) + "\n"] if second else [])]
        r, w = os.pipe()
        self.stdout, self._w = os.fdopen(r, "r", encoding="utf-8"), os.fdopen(w, "w", encoding="utf-8")
        self.stdin = self
        self._w.write(self.lines.pop(0))
        self._w.flush()
        self.told: list[str] = []

    def write(self, text):
        self.told.append(text)
        if self.lines:
            self._w.write(self.lines.pop(0))
            self._w.flush()

    def flush(self):
        pass

    def kill(self):
        pass

    def communicate(self, timeout=None):
        self._w.close()
        self.stdout.close()
        return "", ""


def run_across(tmp_path, lg, monkeypatch, first, second, ids=("77", "77"), go=True, answers=None):
    left = list(ids)
    entry = lambda _c: (0, f"tcp 6 id={left.pop(0)}\n" if left[0] else "")  # noqa: E731
    host = Host(answers={("conntrack", "-L"): entry, **(answers or {})})
    client = Client(first, second)
    monkeypatch.setattr(probe.subprocess, "Popen", lambda *a, **k: client)
    monkeypatch.setattr(probe, "control", lambda p, o, dev="", left=None: {"path": True})
    d = tmp_path / "confirm"
    d.mkdir()
    env = host.env(tmp_path)
    env.sleep = lambda _s: (d / ("go" if go else "abort")).touch()  # the apply finishes while the probe waits
    rc = probe.across(S, lg, str(d), env)
    read = lambda name: (d / name).read_text(encoding="utf-8").splitlines() if (d / name).exists() else None  # noqa: E731
    return rc, read("pre"), read("post"), host, client


HELD = {"dst": ADDR, "sport": 40000}


def told_targets(client) -> list:
    """The targets of each plan the held client was handed after the apply."""
    return [json.loads(line)["spec"]["targets"] for line in client.told]


def test_the_probe_judges_the_gateway_by_the_settings_it_was_applied_with(tmp_path, lg, monkeypatch):
    """The settings file already names the tunnel as the uplink, and no apply has taken that up: the
    gateway still sends the TV out by wlan0, and works. Judged by the file it would read as broken (the
    route does not lead to the tunnel), and an apply about to make that very change could never be
    undone, since only an apply the probe saw working before can be. The record of the last apply is
    what the live gateway is."""
    edited = dataclasses.replace(S, uplink="vpn", block_quic="no", tv_probe_ip="10.10.10.44")
    applied = "UPLINK=direct\nWAN_IF=wlan0\nBLOCK_QUIC=yes\nTV_PROBE_IP=10.10.10.30\nTV_PROBE=on\n"
    host = Host(files={probe.APPLIED: applied}, answers={CLIENT: client_says(whole(lg))})
    env = host.env(tmp_path)
    was = probe.live(edited, env)
    assert (was.uplink, was.block_quic, was.tv_probe_ip) == ("direct", "yes", "10.10.10.30")
    assert probe.run(edited, lg, env).verdict == PASS
    assert probe.live(edited, Host().env(tmp_path)) == edited  # nothing applied since boot: the file stands
    garbled = Host(files={probe.APPLIED: "UPLINK=a b\n"})
    assert probe.live(edited, garbled.env(tmp_path)) == edited
    # across the apply that takes the edit up, the probe's own address changes under it: it cannot judge
    d = tmp_path / "confirm"
    d.mkdir()
    client = Client({"obs": whole(lg), "held": HELD}, {"obs": whole(lg), "held_state": "open"})
    monkeypatch.setattr(probe.subprocess, "Popen", lambda *a, **k: client)
    env = host.env(tmp_path)

    def applies(_seconds):
        host.files[probe.APPLIED] = applied.replace("10.10.10.30", "10.10.10.44")
        (d / "go").touch()

    env.sleep = applies
    assert probe.across(edited, lg, str(d), env) == 4
    assert (d / "pre").read_text(encoding="utf-8").startswith("pass -\n")
    assert (d / "post").read_text(encoding="utf-8").startswith("unknown probe\n") and client.told == []


def test_across_an_apply_one_verdict_each_side_and_the_held_connection_followed(tmp_path, lg, monkeypatch):
    """A verdict before, one after, and the held connection's entry compared. The verdict after is made
    with a connection of its own: the held one was made before the apply, and an established connection
    passes rules that a new one, which is what the TV will open, would meet."""
    rc, pre, post, host, client = run_across(
        tmp_path, lg, monkeypatch, {"obs": whole(lg), "held": HELD}, {"obs": whole(lg), "held_state": "open"}
    )
    assert rc == 0 and pre[0] == "pass -" and post[0] == "pass -"  # the line tvgw-apply reads
    assert json.loads(post[1])["stages"][-1] == {"name": "held", "outcome": "pass", "detail": ""}
    assert told_targets(client) == [list(probe.plan(S, lg).targets)]  # the plan again, target and all
    asked = [c for c in host.calls if c[0] == "conntrack"]
    assert asked[0] == ("conntrack", "-L", "-p", "tcp", "-s", "10.10.10.30", "-d", ADDR, "--sport", "40000", "--dport", "443", "-o", "id,timestamp")  # fmt: skip
    assert len(asked) == 2 and host.calls[-1] == ("ip", "link", "del", "tvgw-probe")
    assert host.writes[probe.PATH_STAMP].split()[1] == "pass"


def test_across_an_apply_that_cut_the_held_connection_fails(tmp_path, lg, monkeypatch):
    rc, pre, post, _, _ = run_across(
        tmp_path, lg, monkeypatch, {"obs": whole(lg), "held": HELD}, {"obs": whole(lg), "held_state": "open"}, ids=("77", "91"),
        answers={CLIENT: client_says(whole(lg))},  # taken again, the path itself is fine: the cut still stands
    )  # fmt: skip
    assert (rc, pre[0], post[0]) == (3, "pass -", "fail held")


def test_across_an_apply_that_broke_the_path_for_new_connections_fails_though_the_held_one_lives(
    tmp_path, lg, monkeypatch
):
    """A rule that drops new connections leaves the held one alone (same entry, still open). The verdict
    after is the new connection's."""
    rc, pre, post, _, _ = run_across(
        tmp_path, lg, monkeypatch, {"obs": whole(lg), "held": HELD}, {"obs": whole(lg, FAILED_TLS), "held_state": "open"},
        answers={CLIENT: client_says(whole(lg, FAILED_TLS))},  # and again when it is taken a second time
    )  # fmt: skip
    assert (rc, pre[0], post[0]) == (3, "pass -", "fail path")
    assert json.loads(post[1])["stages"][-1]["outcome"] == "pass"  # held


def test_across_an_apply_that_never_says_go_ends_without_a_verdict_after(tmp_path, lg, monkeypatch):
    rc, pre, post, host, client = run_across(
        tmp_path, lg, monkeypatch, {"obs": whole(lg), "held": HELD}, None, go=False
    )
    assert rc == 4 and pre[0] == "pass -" and post is None and client.told == []
    assert host.calls[-1] == ("ip", "link", "del", "tvgw-probe")


def test_across_says_unknown_before_when_it_may_not_run(tmp_path, lg):
    d = tmp_path / "confirm"
    d.mkdir()
    rc = probe.across(dataclasses.replace(S, tv_probe="off"), lg, str(d), Host().env(tmp_path))
    assert rc == 4 and (d / "pre").read_text(encoding="utf-8").startswith("unknown probe\n")
    assert not (d / "post").exists()


# ---- the command, the check, the sample --------------------------------------------------------------------


def test_the_verdict_in_plain_words_and_as_json(lg):
    v = probe.judge(P, obs(dot="connected"), PORT, UP, never)
    v.ms = 812
    text = probe.lines(v)
    assert text[0].startswith("OK   the TV's port forwards; the kernel routes the TV out by the uplink")
    assert (
        "FAIL an encrypted lookup (DNS over TLS) is refused: DNS over TLS was not refused by the gateway"
        in text
    )
    assert (
        text[-1] == "tvgw probe: fail: a step failed: the gateway's path for the TV is broken there (812 ms)"
    )
    assert set(v.as_dict()) == {"verdict", "reason", "t", "ms", "stages"}
    assert {s.name for s in v.stages} <= set(probe.STAGE_PLAIN)
    # what the store keeps: outcomes and the deciding stage, no name, no address
    kept = json.loads(v.compact())
    assert kept == {"v": "fail", "why": "dot", "ms": 812, "s": {**outcomes(v)}}
    assert "lgtvsdp" not in v.compact() and ADDR not in v.compact() and TARGET not in v.compact()


def test_the_command_exits_by_verdict_and_takes_no_packet_path_without_root(
    tmp_path, capsys, monkeypatch, lg
):
    conf = tmp_path / "tvgw.conf"
    conf.write_text("TV_PROBE=on\n", encoding="utf-8")
    seen = {}

    def fake(s, profile, env=None, connect=True):
        seen["netns"], seen["connect"] = env.netns, connect
        return probe.judge(P, GOOD, PORT, UP, never)

    monkeypatch.setattr(probe, "run", fake)
    assert cli.main(["--conf", str(conf), "probe"]) == 0
    assert (
        capsys.readouterr()
        .out.splitlines()[-1]
        .startswith("tvgw probe: pass: every step passed for a test client beside the TV's port")
    )
    assert seen == {"netns": "tvgw-probe", "connect": True}  # by hand it always connects out
    monkeypatch.setattr(
        probe, "run", lambda s, p, env=None: probe.unknown("the probe needs root: run it with sudo")
    )
    assert cli.main(["--conf", str(conf), "probe", "--json"]) == 4
    assert json.loads(capsys.readouterr().out)["verdict"] == "unknown"
    monkeypatch.setattr(
        probe, "run", lambda s, p, env=None: probe.judge(P, obs(quic="answered"), PORT, UP, never)
    )
    assert cli.main(["--conf", str(conf), "probe"]) == 3
    assert probe.EXIT == {PASS: 0, FAIL: 3, UNKNOWN: 4}  # tvgw-apply reads 0, 3 and "anything else"


def test_the_check_is_a_warning_at_most_while_it_is_new():
    """Decision 58: a new check starts at WARN, whatever it finds."""
    ok = verify.probe_check(probe.judge(P, GOOD, PORT, UP, never))
    assert ok.line() == (
        "OK   tv_probe: every step passed for a test client beside the TV's port (the TV itself is not tested)"
    )
    assert "would work" not in ok.line()  # a pass says what was tested, and the TV was not
    failed = verify.probe_check(probe.judge(P, obs(dot="connected"), PORT, UP, never))
    assert failed.ok and failed.warn and failed.detail.endswith(verify.HELD)
    assert failed.detail.startswith("fail: dot: DNS over TLS was not refused by the gateway")
    cannot = verify.probe_check(probe.judge(P, FAILED_TLS, PORT, DOWN, never))
    assert cannot.ok and cannot.warn and not cannot.detail.endswith(verify.HELD)
    assert cannot.detail == f"unknown: path: {DOWN.why}"
    assert verify.FAIL_AFTER["tv_probe"] == verify.FAIL and "tv_probe" not in verify.PROMOTED


def test_only_the_recorded_run_of_a_gateway_with_the_probe_on_sends_it(tmp_path, monkeypatch, lg):
    import test_verify
    from test_verify import gateway, patch_gateway

    ran: list[str] = []

    def fake(s, profile, env=None, connect=True):
        # (L6-21) and under the handler that unwinds it on a SIGTERM, as `tvgw probe` has it
        ran.append((s.tv_probe, connect) if signal.getsignal(signal.SIGTERM) is probe._ended else "bare")
        return probe.judge(P, obs(blocked=[ADDR]), PORT, UP, never)

    monkeypatch.setattr(probe, "run", fake)
    monkeypatch.setattr(verify, "STATUS", str(tmp_path / "status.txt"))
    patch_gateway(monkeypatch, gateway())
    monkeypatch.setattr(ledger, "sample", lambda s: ledger.Sample(t=NOW))
    store = str(tmp_path / "tvgw.db")
    on = dataclasses.replace(test_verify.S, tv_probe="on", db_path=store)
    off = dataclasses.replace(on, tv_probe="off")
    assert verify.main(on, lg) == 0 and ran == []  # a plain verify sends nothing
    assert verify.main(off, lg, record_to_store=True) == 0 and ran == []  # nor a recorded one with it off
    # an unknown fails no run; and the check leaves it to the probe whether a connection out is due. The
    # process's own handler first: `tvgw probe`'s, which a test before may have left, would hide a bare run
    before = signal.signal(signal.SIGTERM, signal.SIG_DFL)
    try:
        assert verify.main(on, lg, record_to_store=True) == 0 and ran == [("on", None)]
        assert signal.getsignal(signal.SIGTERM) is signal.SIG_DFL  # and it is the process's own after it
    finally:
        signal.signal(signal.SIGTERM, before)
    conn = db.connect(store, readonly=True)
    rows = conn.execute("SELECT tv_probe FROM gw_samples ORDER BY t").fetchall()
    conn.close()
    kept = json.loads(rows[-1][0])
    assert kept["v"] == "unknown" and kept["why"] == "blocked" and kept["s"]["lookup"] == "pass"
    (sample,) = ledger.samples(sqlite3.connect(store), 0, NOW + 1)
    assert sample.tv_probe == rows[-1][0]


def test_a_store_from_before_the_probe_gains_the_column_and_keeps_its_samples(tmp_path):
    path = str(tmp_path / "s.db")
    c = db.connect(path)
    c.execute("ALTER TABLE gw_samples DROP COLUMN tv_probe")
    c.execute("INSERT INTO gw_samples(t, boot_id) VALUES (?, 'b')", (NOW,))
    c.execute("UPDATE meta SET value = '10' WHERE key = 'schema'")
    c.commit()
    c.close()
    reader = db.connect(path, readonly=True)  # a brief may read before any writer migrated it
    (smp,) = ledger.samples(reader, 0, NOW + 1)
    assert smp.tv_probe is None and smp.boot_id == "b"
    reader.close()
    conn = db.connect(path)
    # 13 brought the column; a store opened today goes all the way (14 reliability, 15 namebound, 16 threats, 17 attention)
    assert db.get_meta(conn, "schema") == str(db.SCHEMA_VERSION) and db.SCHEMA_VERSION >= 13
    assert "tv_probe" in {r[1] for r in conn.execute("PRAGMA table_info(gw_samples)")}
    (smp,) = ledger.samples(conn, 0, NOW + 1)
    assert (smp.boot_id, smp.tv_probe) == ("b", None)
    conn.close()


# ---- the probe is in no record -----------------------------------------------------------------------------

PROBE_IP = Settings().tv_probe_ip


def test_no_source_the_ingest_reads_keeps_a_row_of_the_probes_address():
    """Every source keeps only the rows that carry TV_IP, and the probe's address is never TV_IP
    (config.probe_side refuses that): its lookups in AdGuard's own log, a connection of its own in the
    flow log, a request to the URL filter, would each be another client's row."""
    s = Settings()
    assert s.tv_ip != PROBE_IP and s.gw_ip != PROBE_IP
    mine = DNS_ALLOWED.replace('"IP":"10.10.10.17"', f'"IP":"{PROBE_IP}"')
    assert adguard.parse_querylog_line(DNS_ALLOWED, client=s.tv_ip) is not None
    assert adguard.parse_querylog_line(mine, client=s.tv_ip) is None
    flow = conntrack.parse_flow(FLOW_TCP.replace("src=10.10.10.17 dst=142", f"src={PROBE_IP} dst=142"))
    assert flow is not None and flow.src == PROBE_IP != s.tv_ip  # ingest keeps `f.src == s.tv_ip` alone
    assert f" {PROBE_IP} " in GFTS_TV_ALLOWED.replace(" 10.10.10.17 ", f" {PROBE_IP} ")
    with pytest.raises(ValueError, match="an address of its own"):
        config.probe_side(dataclasses.replace(s, tv_probe="on", tv_probe_ip=s.tv_ip))


def test_the_readers_that_listen_on_the_wire_name_the_tvs_port_and_address():
    """The DNS gate's feeder captures on TV_IF for TV_IP; the flow logger asks for TV_IP's connections;
    the full capture is dumpcap on TV_IF. The probe's packets never cross TV_IF and never carry TV_IP."""
    from conftest import UNITS

    argv = dnsgate.tcpdump_argv(Settings())
    assert argv[argv.index("-i") + 1] == "eth0" and argv[-2:] == ["host", "10.10.10.17"]
    assert '--orig-src "$${TV_IP:-10.10.10.17}"' in (UNITS / "tvgw-flowlog.service").read_text(
        encoding="utf-8"
    )
    assert "dumpcap -i ${TV_IF} " in (UNITS / "tvgw-pcap.service").read_text(encoding="utf-8")
    assert Settings().tv_if != probe.GW_IF


def test_the_probes_rules_add_no_series_to_the_counters_verify_stores():
    """A listing of the table with the probe's chains in it: the rules have no counter and no comment,
    so `counters_from_table` returns what it returned without them."""
    tv = {
        "rule": {
            "chain": "tv_out",
            "comment": "DoT/DoQ",
            "expr": [{"counter": {"packets": 4, "bytes": 240}}, {"reject": None}],
        }
    }
    mine = {"rule": {"chain": "probe_out", "expr": [{"match": {}}, {"reject": None}]}}
    listing = json.dumps({"nftables": [tv, mine]})
    assert verify.counters_from_table(listing) == [("DoT/DoQ", 4, 240)]


def test_no_rule_tvgw_writes_is_scoped_to_the_tvs_address_but_the_record_type_strip():
    """What the probe's `blocked` and `lookup` steps test is the resolver's policy for any client, since
    the probe has its own address. That is the TV's policy for a name as long as tvgw scopes no name
    rule to the TV: the one rule it scopes withholds two record types the probe never asks for, and the
    TV's client entry uses the global settings (adguardcfg). A rule scoped by `client=` or `ctag=`
    would be the TV's alone, and the probe would not see it: this fails when a profile gains one."""
    from tvgw import profile

    for name in profile.bundled_names():
        rules = profile.load(name).adguard_rules("10.10.10.1", "10.10.10.17")
        scoped = [r for r in rules if "client=" in r or "ctag=" in r]
        assert all(r.startswith("||*^$dnstype=") for r in scoped), (name, scoped)
        assert len(scoped) <= 1, (name, scoped)


# ---- a probe that is ended, and what it leaves ---------------------------------------------------------------


def test_a_probe_ended_by_a_signal_removes_what_it_made(tmp_path, lg):
    """SIGTERM is what an apply that gave up waiting, `timeout` and a stopped unit all send. The handler
    raises, as SIGINT does by itself, and the run unwinds through its namespace: nothing is left."""
    with pytest.raises(SystemExit) as ended:
        probe._ended(15, None)
    assert ended.value.code == 143

    def killed(_cmd):
        raise SystemExit(143)

    host = Host(answers={CLIENT: killed})
    with pytest.raises(SystemExit):
        probe.run(S, lg, host.env(tmp_path))
    assert host.calls[-3:] == [
        ("ip", "netns", "pids", "tvgw-probe"),
        ("ip", "netns", "del", "tvgw-probe"),
        ("ip", "link", "del", "tvgw-probe"),
    ]
    import inspect

    assert "signal.signal(signal.SIGTERM, _ended)" in inspect.getsource(probe.main)


def test_what_a_killed_probe_left_is_removed_by_the_next_run_even_one_that_may_not_go_on(tmp_path, lg):
    """SIGKILL leaves the pair and the namespace. The next run removes them first, also when it then
    finds it may not probe (no rules loaded, the probe turned off); tvgw-apply does the same with the
    probe off. Without root nothing can be removed, and nothing is tried."""
    left = {"/proc/sys/net/ipv4/conf/tvgw-probe/forwarding": "1\n"}
    for s, answers in (
        (S, {("nft", "list", "chain"): (1, "")}),
        (dataclasses.replace(S, tv_probe="off"), {}),
    ):
        host = Host(files=left, answers=answers)
        assert probe.run(s, lg, host.env(tmp_path)).verdict == UNKNOWN
        assert host.calls[:3] == [
            ("ip", "netns", "pids", "tvgw-probe"),
            ("ip", "netns", "del", "tvgw-probe"),
            ("ip", "link", "del", "tvgw-probe"),
        ]
    stale = Host(files={"/run/netns/tvgw-probe": ""}, answers={("nft", "list", "chain"): (1, "")})
    probe.run(S, lg, stale.env(tmp_path))
    assert ("ip", "netns", "del", "tvgw-probe") in stale.calls
    unprivileged = Host(files=left, euid=1000)
    probe.run(S, lg, unprivileged.env(tmp_path))
    assert not [c for c in unprivileged.calls if c[:2] in (("ip", "netns"), ("ip", "link"))]
    clean = Host(answers={("nft", "list", "chain"): (1, "")})
    probe.run(S, lg, clean.env(tmp_path))
    assert not [
        c for c in clean.calls if c[:2] in (("ip", "netns"), ("ip", "link"))
    ]  # nothing left: nothing run


# ---- (revert) the steps an armed revert needed: the port walls, the address lists, the gate -------------


def test_the_adtech_wall_is_planned_from_the_settings_as_the_apply_renders_it(lg):
    """The adtech wall is LG's alone (design decision 62): any other profile gets none, whatever the
    setting says, as tvgw-apply renders it."""
    assert probe.plan(dataclasses.replace(S, adtech_port_wall="no"), lg).adtech is False
    assert probe.plan(dataclasses.replace(S, profile="generic-tv"), lg).adtech is False
    text = (ROOT / "deploy" / "nftables" / "tvgw-apply").read_text(encoding="utf-8")
    ports = re.search(r'ADTECH_PORTS="tcp dport \{ ([0-9, ]+) \}"', text).group(1).split(", ")
    assert str(probe.ADTECH_PORT) in ports


def test_the_adtech_port_is_tried_at_the_documentation_address_only_where_its_wall_stands(monkeypatch):
    table = {**{n: [VENDOR] for n in NAMES}, TARGET: [ADDR], "alphonso.tv": ["0.0.0.0"]}
    _asked, _shaken, tried = recorded(monkeypatch, table.__getitem__)
    seen, _ = probe.observe(dataclasses.replace(P, adtech=True, quic=False).spec(connect=False))
    assert tried == [([*P.ports, DOT, ADTECH], [DOT, ADTECH])] and seen["adtech"] == "refused"
    assert seen["quic"] is None  # BLOCK_QUIC=no: not tried
    tried.clear()
    seen, _ = probe.observe(P.spec(connect=False))
    assert tried == [([*P.ports, DOT, QUIC], [DOT, QUIC])] and seen["adtech"] is None


EXPIRED = {**GOOD["ports"], "tcp/80": "expired"}  # the next hop's time-exceeded for the web's try


@pytest.mark.parametrize(
    ("saw", "ports", "dot", "uplink", "outcome"),
    [
        ("reset", EXPIRED, "refused", UP, PASS),  # the wall's reset, the next hop seen to let tries die
        ("reset", GOOD["ports"], "expired", UP, PASS),  # the DoT try that died there says it as well
        ("reset", GOOD["ports"], "refused", UP, UNKNOWN),  # a reset the next hop may have sent
        ("reset", {**EXPIRED, "tcp/80": "reset"}, "refused", UP, UNKNOWN),  # a hop that resets the web too
        ("reset", {**GOOD["ports"], "udp/123": "expired"}, "refused", UP, UNKNOWN),  # a UDP hop proves no TCP
        ("reset", {**GOOD["ports"], "tcp/80": "unreachable"}, "refused", UP, UNKNOWN),  # nor another error
        ("silent", EXPIRED, "refused", UP, FAIL),  # the SYN went out: the wall is missing
        ("expired", GOOD["ports"], "refused", UP, FAIL),  # and died at the next hop, which said so
        ("connected", EXPIRED, "refused", UP, FAIL),
        ("silent", EXPIRED, "refused", DOWN, UNKNOWN),
    ],
)
def test_the_adtech_wall_passes_only_on_the_gateways_own_reset(saw, ports, dot, uplink, outcome):
    """L6-9: the wall answers with a reset, which names no sender. Until 2026-11-17 any reset passed, and
    a router that resets connections to unrouted addresses held the stage up with the wall gone."""
    plan = dataclasses.replace(P, adtech=True)
    v = probe.judge(plan, obs(adtech=saw, ports=ports, dot=dot), PORT, uplink, never)
    assert outcomes(v)["adtech"] == outcome


def test_a_must_allow_address_in_a_refused_list_fails_the_lists_step():
    """A daily DoH refresh, or an edit of the owner's blocked addresses, that took an address the TV needs:
    the TV's connection there would be refused whatever the path. The kernel's sets are asked; nothing
    connects to the address."""
    hit = obs(allow=[{"name": NAMES[0], "answers": [VENDOR], "listed": "doh4"}, *GOOD["allow"][1:]])
    v = probe.judge(P, hit, PORT, UP, never)
    assert v.verdict == FAIL and outcomes(v)["lists"] == FAIL
    assert (
        v.reason
        == "lists: 1 of 2 must-allow names got an address the TV's rules refuse: the DoH resolver list"
    )
    blocked = obs(allow=[{"name": n, "answers": [VENDOR], "listed": "block4"} for n in NAMES])
    assert "block4.txt" in probe.judge(P, blocked, PORT, UP, never).reason
    none = obs(allow=[{"name": n, "answers": []} for n in NAMES])
    assert outcomes(probe.judge(P, none, PORT, UP))["lists"] == SKIPPED
    assert "lists" not in outcomes(probe.judge(dataclasses.replace(P, allow=()), obs(allow=[]), PORT, UP))


SET_DOH = json.dumps(
    {
        "nftables": [
            {"metainfo": {"version": "1.1.1"}},
            {
                "set": {
                    "family": "inet",
                    "name": "doh4",
                    "table": "tvgw",
                    "type": "ipv4_addr",
                    "flags": ["interval"],
                    "elem": [
                        "192.0.2.10",
                        {"prefix": {"addr": "198.51.100.0", "len": 28}},
                        {"range": ["203.0.113.5", "203.0.113.9"]},
                        {"elem": {"val": "192.0.2.99", "timeout": 60}},
                    ],
                }
            },
        ]
    }
)


def test_the_sets_are_read_whole_in_every_form_nft_lists_an_element():
    nets = probe.set_networks(SET_DOH)
    held = lambda a: any(ipaddress.IPv4Address(a) in n for n in nets)  # noqa: E731
    assert [held(a) for a in ("192.0.2.10", "198.51.100.15", "203.0.113.7", "192.0.2.99")] == [True] * 4
    assert [held(a) for a in ("192.0.2.11", "198.51.100.16", "203.0.113.10")] == [False] * 3
    assert probe.set_networks("") == [] and probe.set_networks("{not json") == []


def test_the_lists_are_asked_once_each_and_only_with_an_address_to_look_up(tmp_path, lg):
    host = Host(answers={("nft", "-j", "list", "set", "inet", "tvgw", "doh4"): (0, SET_DOH)})
    env = host.env(tmp_path)
    assert probe.listed_in(env, ["203.0.113.7", "192.0.2.200", "203.0.113.7", "x"]) == {"203.0.113.7": "doh4"}
    asked = [c for c in host.calls if c[:3] == ("nft", "-j", "list")]
    assert asked == [("nft", "-j", "list", "set", "inet", "tvgw", n) for n in ("doh4", "block4")]
    host.calls.clear()
    assert probe.listed_in(env, []) == {} and host.calls == []


def gate_table(*exprs: list) -> str:
    rules = [{"rule": {"family": "inet", "table": "tvgw_gate", "chain": "forward", "expr": e}} for e in exprs]
    return json.dumps({"nftables": [{"metainfo": {}}, {"table": {"name": "tvgw_gate"}}, *rules]})


COUNTS = [{"match": {"op": "==", "left": {"meta": {"key": "iifname"}}, "right": "eth0"}}, {"counter": None}]


@pytest.mark.parametrize(
    ("answer", "state"),
    [
        ((1, ""), "absent"),
        ((0, gate_table(COUNTS, [{"log": {"prefix": "tvgw-gate: "}}])), "counts"),
        ((0, gate_table([{"queue": {"num": 53053, "flags": "bypass"}}])), "counts"),  # the in-path queue
        ((0, gate_table([{"queue": {"num": 53053, "flags": ["bypass"]}}])), "counts"),
        ((0, gate_table(COUNTS, [*COUNTS, {"drop": None}])), "refuses"),
        ((0, gate_table([{"reject": {"type": "icmpx"}}])), "refuses"),
        ((0, gate_table([{"queue": {"num": 53053}}])), "refuses"),  # no bypass: drops with no listener
    ],
)
def test_the_gate_is_read_for_a_rule_that_can_refuse(tmp_path, answer, state):
    host = Host(answers={("nft", "-j", "-t", "list", "table", "inet", "tvgw_gate"): answer})
    assert probe.gate_state(host.env(tmp_path)) == state


def test_a_gate_that_can_refuse_makes_the_verdict_unknown_never_a_pass_it_did_not_earn():
    """The gate matches the TV's port alone, so the probe has no copy of it to cross: while it only counts
    it can take nothing from the TV (pass); once a rule in it can refuse, the probe cannot tell."""
    assert outcomes(probe.judge(P, obs(gate="counts"), PORT, UP, never))["gate"] == PASS
    v = probe.judge(P, obs(gate="refuses"), PORT, UP, never)
    assert v.verdict == UNKNOWN and outcomes(v)["gate"] == UNKNOWN and v.word == "gate"
    assert outcomes(probe.judge(P, obs(gate="absent"), PORT, UP, never))["gate"] == SKIPPED
    assert "gate" not in outcomes(probe.judge(P, GOOD, PORT, UP, never))


def test_the_new_steps_have_plain_words_and_fit_the_spool():
    for name in ("lists", "adtech", "gate"):
        assert name in probe.STAGE_PLAIN and ledger._clean_field(name) == name


def test_the_walls_as_applied_are_what_the_probe_judges(tmp_path, lg):
    """settings.applied says the walls as the last apply rendered them (the adtech wall off for a profile
    not LG's); the settings file may say something the apply has not taken up."""
    applied = "ADTECH_PORT_WALL=no\n"
    s = probe.live(S, probe.Env(read=lambda path: applied if path == probe.APPLIED else ""))
    assert s.adtech_port_wall == "no"


SET_EMPTY = json.dumps(
    {"nftables": [{"set": {"family": "inet", "name": "doh4", "table": "tvgw", "elem": []}}]}
)


def moved_onto(lg, addr: str) -> dict:
    """An observation in which the first must-allow name's answer moved to `addr`, a content network's
    other address, as answers do between two looks."""
    o = whole(lg)
    o["allow"][0] = {"name": o["allow"][0]["name"], "answers": [addr]}
    return o


def test_an_answer_that_moved_onto_an_address_listed_before_the_apply_is_no_finding_about_it(tmp_path, lg):
    """Review of 2026-11-08: across an apply that changed no list, a must-allow name's answer that moved
    onto an address the DoH list held all along turned a harmless apply into pass then fail, a false
    `would have been undone` in report mode. Only an address the apply listed counts after it."""
    host = Host(answers={("nft", "-j", "list", "set", "inet", "tvgw", "doh4"): (0, SET_DOH)})
    env = host.env(tmp_path)
    before = probe.list_networks(env)
    assert probe.listed_in(env, ["203.0.113.7"], before) == {"203.0.113.7": "doh4:before"}
    assert probe.listed_in(env, ["203.0.113.7"], {"doh4": [], "block4": []}) == {"203.0.113.7": "doh4"}
    assert probe.listed_in(env, ["203.0.113.7"]) == {"203.0.113.7": "doh4"}  # a look of its own: no before
    old = obs(allow=[{"name": NAMES[0], "answers": [VENDOR], "listed_before": "doh4"}, *GOOD["allow"][1:]])
    v = probe.judge(P, old, PORT, UP, never)
    assert (v.verdict, outcomes(v)["lists"], v.word) == (UNKNOWN, UNKNOWN, "lists")


@pytest.mark.parametrize(
    ("listings", "want"),
    [
        # the DoH list as read for the verdict before, as kept before the apply, and after it
        ((SET_DOH, SET_DOH, SET_DOH), (4, "unknown lists")),  # unchanged: the answer moved, not the apply
        ((SET_EMPTY, SET_EMPTY, SET_DOH), (3, "fail lists")),  # the apply listed the address: a fail
    ],
    ids=["listed-all-along", "listed-by-the-apply"],
)
def test_across_an_apply_only_an_address_the_apply_listed_fails_the_lists_step(
    tmp_path, lg, monkeypatch, listings, want
):
    seen = list(listings)
    doh = lambda _c: (0, seen.pop(0) if len(seen) > 1 else seen[0])  # noqa: E731
    after = moved_onto(lg, "203.0.113.7")
    rc, pre, post, _, _ = run_across(
        tmp_path, lg, monkeypatch, {"obs": whole(lg), "held": HELD}, {"obs": after, "held_state": "open"},
        answers={("nft", "-j", "list", "set", "inet", "tvgw", "doh4"): doh, CLIENT: client_says(after)},
    )  # fmt: skip
    assert pre[0] == "pass -" and (rc, post[0]) == want
