"""`tvgw probe`: is the gateway's path for the TV whole, and do the walls stand? A test client beside the
TV's port.

The TV is cabled straight to TV_IF and is off for most of every day, so nothing on that wire can say
whether a change the gateway made to itself left the TV's path working (design decision 65). The probe
is a client the gateway makes for a few seconds: a network namespace joined to the gateway by a veth
pair, with an address of its own in TV_NET (TV_PROBE_IP). `tvgw-apply` gives the pair's gateway end
(GW_IF) a twin of every rule the TV's packets cross, made from the text of the TV's own chains at each
apply, without their counters, logs and comments. The client then does this:

- it asks the gateway's resolver for every name the profile says must work, and each must get an
  address. It never connects to one: the probe makes no connection to the TV's vendor, ever;
- when a connection out is due, it completes a TLS handshake with a neutral server (TV_PROBE_TARGET, or
  the host one of the profile's blocklists is fetched from), through the forward path, the address
  translation and the uplink, and back. No request is sent, and the certificate is not judged;
- it asks for a name the profile blocks, and must get the filter's blocked answer;
- it aims a lookup at another resolver at WALL_ADDR, a documentation address (RFC 5737) where nothing on
  the internet answers, so an answer can only be the gateway's; and there, with the ports below and as
  they are, it tries DNS over TLS (TCP 853) and, with BLOCK_QUIC=yes, QUIC (UDP 443): each must be
  refused by the gateway itself, and a try a missing wall let out ends at the next hop;
- (ports) at the same address, all at once, it tries the ports the TV uses (TCP 80 and 443, UDP 123) and
  one unusual port (UDP ODD_PORT): the first must not be refused, the clock port must be refused when the
  last apply closed it (CLOCK_PORT_USED=none), and the unusual one must be refused exactly when
  STRICT_PORTS=yes (design decision 71). The tries the gateway lets through do leave it: a TCP opening to
  80 and 443 and a small datagram to 123 and ODD_PORT, out by the uplink, each with a time to live of two
  (PORT_TTL), so it dies at the next hop (the home router, or the VPN's server), which answers with a
  time-exceeded; none of it goes further. A refusal is only the gateway's own ICMP error of a refusing
  kind (port unreachable or administratively prohibited), told by its sender and its code; any other
  error from the gateway is a missing route, not a refusal.
- (revert) at the same address, LG's adtech port (TCP 4431) where the adtech wall stands: it must be
  reset by the gateway. A reset names no sender, so it counts as the gateway's only when the next hop
  answered the run's other TCP tries with a time-exceeded: a hop that resets would have reset those.

Beside those packets it reads what no packet of its own can cross: the forwarding switch of the TV's own
port, the kernel's route for a packet from the TV's address arriving there, and the route the gateway's
own answers to the TV take ("asked, not crossed"). (revert) It also asks the kernel whether an address a
must-allow name got is one of the TV's refused address lists (the DoH list a daily refresh rewrites, the
owner's blocked addresses), and whether the address gate's table holds a rule that can refuse: the gate
matches the TV's port alone, so the probe has no copy of it to cross, and a gate that can refuse makes
the verdict unknown rather than a pass it did not earn.

A verdict is `fail` only for a step whose failure an apply can cause: the port's switches and routes,
the filter chains, the redirect, the address translation. And for the connection out only when the
gateway itself, by the same uplink the TV uses, completed what the probe could not. What the filter
answers for a name is the filter's lists and its upstream, which no apply of the firewall sets: a
must-allow name without an address, or a blocked name that is not blocked, is `unknown` here (and a
FAIL of `tvgw verify`'s own resolver checks). `unknown` never undoes anything. `judge` holds the table.

What a pass means, and no more: forwarding is on for TV_IF; the kernel routes a packet from TV_IP out by
the uplink and the gateway's answers back by TV_IF; and a client with another address, on another port,
got names from the resolver's policy for any client, was refused at the walls, and (when due) completed
one handshake through copies of the TV's chains. It says nothing about the cable, the TV's lease, the
pin matching the TV's real address, the guard table, the IPv6 guard, other firewalls on the computer,
the URL filter, or any second name or port; and a rule put into the TV's chains by hand after the apply
is not in the copies (`tvgw verify`'s ruleset_unchanged sees that). The capture, the flow log and the
DNS gate have no rule for the probe's port, which is also why the probe is in none of them.

Everything that decides is a pure function of what was observed (`judge`); every command and file is a
parameter (`Env`), so the logic is tested away from a gateway. The client half runs inside the namespace
as `python -m tvgw.probe --client`.
"""

from __future__ import annotations

import contextlib
import errno
import fcntl
import ipaddress
import json
import math
import os
import re
import select
import signal
import socket
import ssl
import struct
import subprocess
import sys
import time
import urllib.parse
from collections.abc import Callable
from dataclasses import dataclass, field, replace

from tvgw import config, dnsmsg, dnsq
from tvgw.config import Settings
from tvgw.profile import Profile, covers

NETNS = "tvgw-probe"  # the namespace, made and removed by each run
GW_IF = "tvgw-probe"  # the pair's gateway end: the name tvgw-apply's probe rules match (PROBE_IF there)
NS_IF = "tvgw-probe0"  # the client's end
# both ends' hardware addresses, locally administered and fixed: given at creation, so udev's
# MACAddressPolicy leaves them alone and the two static neighbour entries below never go stale
GW_MAC, NS_MAC = "02:74:76:67:77:01", "02:74:76:67:77:02"
CHAIN = "probe_fwd"  # the chain whose presence says the loaded firewall has a place for the probe
# in tvgw's own directory under /run, which only root can write: in the world-writable /run/lock any
# account could take the lock first, or leave a file there that root may not open (locked)
LOCK = "/run/tvgw/tvgw-probe.lock"
LOCK_WAIT = 20.0  # seconds a run waits for another run's namespace before it says unknown
PASS, FAIL, UNKNOWN, SKIPPED = "pass", "fail", "unknown", "skipped"
# `tvgw probe`'s exit status. A failure is never 1 or 2: an uncaught error exits 1 and a usage error 2,
# and tvgw-apply reads everything but 0 and 3 as unknown
EXIT = {PASS: 0, FAIL: 3, UNKNOWN: 4}
MAX_TARGETS = 2  # neutral servers tried before the connection out is given up
# The connection out leaves the home, so the 10-minute check makes it four times a day and not 144: what
# it adds to the steps that never leave the gateway (the port, the lookups, the walls, which already cross
# the forward chain and the routing rule) is the address translation, the uplink and the way back, and a
# fault there comes from an apply, which is confirmed with a connection of its own, or from outside the
# gateway. One that did not pass is looked at again within the hour. `sudo tvgw probe` always makes it.
PATH_EVERY, PATH_RETRY = 6 * 3600, 3600
APPLIED = "/run/tvgw/settings.applied"  # the settings the loaded firewall and routes were applied with
# the keys of it that say what the live gateway is: the probe judges that, not what the file says next
LIVE_KEYS = (
    *("UPLINK", "WAN_IF", "VPN_IF", "TV_IF", "TV_NET", "GW_IP", "TV_IP", "BLOCK_QUIC", "TV_PROBE_IP"),
    "STRICT_PORTS",  # (ports) whether the unusual port must be refused
    "ADTECH_PORT_WALL",  # (revert) the wall as applied (off for a profile not LG's)
)
# (ports) what the last apply built of the clock port (tvgw-apply's CLOCK_PORT_USED, design decision 71): a
# record, not a setting; an apply from before the key wrote none, and the port was open then
CLOCK_USED_KEY = "CLOCK_PORT_USED"
PATH_STAMP = "/run/tvgw/probe.path"  # `<epoch> <outcome>` of the last connection out
DNS_TIMEOUT, TCP_TIMEOUT = 2.0, 3.0
# the whole client. Its longest run is every wait above with nothing answering: MAX_ALLOW lookups,
# MAX_TARGETS lookups and handshakes, the blocked name, the walls and the ports together (PORT_WAIT), the
# redirect: 2 x 2 + 2 x (2 + 3) + 2 + 1.5 + 2, under 20 seconds. A wall that stands answers at once, so a
# working gateway pays none of it. tvgw-apply's own waits are sized against it: 8 seconds for the verdict
# before (an apply changes nothing for longer than that; a verdict later is unknown and the apply starts at
# once, so a probe on a slow path gives no verdict before, by design) and (revert) 70 for the one after,
# which `across` publishes within BUDGET; with the apply itself that stays inside tvgw.service's two-minute
# start
CLIENT_TIMEOUT = 30.0
RETRY_PAUSE = 2.0  # a failed verdict is taken again once, this much later, before it stands
HOLD_SETTLE = 2.2  # seconds after a re-apply before the held connection is judged: two keep-alives
HOLD_MAX = 90.0  # the longest the holder waits for the apply it brackets
# (budget) seconds from the apply's `go` within which `across` publishes the verdict after, with what it has
# by then: tvgw-apply stops waiting at its WAIT_AFTER (70), and these 5 fewer leave it time to read the
# file. Two client runs and the gateway's own handshakes beside each can take longer than that on a path
# that answers nothing, so every wait after `go` is cut to what is left. `tvgw probe --budget` prints it
BUDGET = 65.0
# Where the walls are tried: an address of TEST-NET-1 (RFC 5737), which is routed nowhere on the internet
# and is in none of the firewall's sets. Whatever refuses a connection to it, or answers a lookup aimed
# at it, is the gateway; and a packet a missing wall let out reaches nobody.
WALL_ADDR = "192.0.2.53"
# (revert) the port LG's adtech wall is tried on, at WALL_ADDR: ACR fingerprints, the first of tvgw-apply's
# ADTECH_PORTS. The ports the TV uses, and STRICT_PORTS, are the `ports` step's (research pass 5, package D)
ADTECH_PORT = 4431
# (revert) the TV's refused address lists a must-allow name's address is looked up in, and their plain names
LIST_PLAIN = {"doh4": "the DoH resolver list", "block4": "the owner's blocked addresses (block4.txt)"}
LAST = (
    "/run/tvgw/probe.last"  # `<epoch> <verdict> <step>` of the last run: tvgw-apply reads it before it waits
)
QUIC_PROBE = (b"\xc0\x1a\x2a\x3a\x4a\x08tvgwprob\x00" + bytes(1200))[:1200]
# the walls, each a port the gateway must refuse at WALL_ADDR, tried with the ports (observe); `quic` only
# with BLOCK_QUIC=yes and (revert) `adtech` only where its wall stands
WALLS = {"dot": ("tcp", 853), "quic": ("udp", 443), "adtech": ("tcp", ADTECH_PORT)}
# ---- (ports) the port steps (design decision 71) ----
# An unusual port no wall of tvgw's names (not a DoT, QUIC, adtech or LG fallback port): what STRICT_PORTS
# refuses and otherwise lets through. UDP, so that the refusal's sender can be read (ports_try).
ODD_PORT = 5000
# the ports tried, each as (protocol, port): the web, the clock, and the unusual one
PORTS = (("tcp", 80), ("tcp", 443), ("udp", 123), ("udp", ODD_PORT))
# the ports tvgw-apply's odd-port rules leave alone, by protocol (`odd_ports` there)
USUAL_PORTS = {"tcp": (80, 443), "udp": (123, 443)}
# seconds the ports and the walls are given, all at once: the gateway's own refusal comes back in about a
# millisecond, so what has not been refused by then is let through (a UDP datagram is sent again halfway)
PORT_WAIT = 1.5
# a datagram not answered by then is sent again: just past the second the kernel's per-destination ICMP
# limit (net.ipv4.icmp_ratelimit) needs to allow one more error, should the walls' refusals and the ports'
# have spent its burst of six
PORT_RESEND = 1.05
# a port no refusal is expected for is decided by then: the gateway's refusal comes back in about a
# millisecond, and the next hop's time-exceeded about as fast, so a try still silent was let through. Only
# a port that must be refused is waited for the whole PORT_WAIT, with its datagram sent again
PORT_QUIET = 0.4
PORT_PROBE = b"tvgw-probe"  # the datagram's bytes: nothing at WALL_ADDR reads them
# the port tries' time to live: one hop to cross the gateway's filter, and one more, which the next hop (the
# home router, or the VPN's server) spends, answering at once with an ICMP time-exceeded of its own. The
# kernel checks the time to live before the forward hook, so 1 would never reach the filter
PORT_TTL = 2


# ---- what a run plans, sees and concludes ---------------------------------------------------------------


@dataclass(frozen=True)
class Plan:
    """What one run asks: fixed before any packet is sent, from the settings and the profile alone."""

    gw_ip: str
    probe_ip: str
    allow: tuple[
        str, ...
    ]  # every must-allow name of the profile, in its order: looked up, never connected to
    block: str | None  # a name the profile blocks: its first plain rule's, else a list's sentinel
    quic: bool  # BLOCK_QUIC=yes: QUIC must be refused
    # neutral servers for the connection out, at most MAX_TARGETS: TV_PROBE_TARGET, else the hosts the
    # profile's blocklists are fetched from, which the gateway's own software already asks every day
    targets: tuple[str, ...] = ()
    wall: str = WALL_ADDR  # where DNS over TLS, QUIC and the redirected lookup are aimed
    # (ports) STRICT_PORTS=yes as applied: the unusual port must be refused; and the clock port as the last
    # apply built it (any, none or resolved; resolved lives in the gate's table, which the probe's port
    # does not cross, so the probe can only see that the port is not refused)
    strict: bool = False
    clock: str = "any"
    ports: tuple[tuple[str, int], ...] = PORTS
    adtech: bool = False  # (revert) the LG adtech wall stands: its port must be reset

    def spec(self, connect: bool = True) -> dict:
        """What the client is handed. Without `connect` it gets no target and makes no connection out."""
        return {
            "gw": self.gw_ip,
            "allow": list(self.allow),
            "block": self.block,
            "wall": self.wall,
            "quic": self.quic,
            "targets": list(self.targets) if connect else None,
            "ports": [list(x) for x in self.ports],
            "refuse": [list(x) for x in self.ports if self.expect_refused(*x)],
            "adtech": self.adtech,
        }

    def expect_refused(self, proto: str, port: int) -> bool:
        """(ports) Whether the gateway must refuse this port: the clock port when the last apply closed it,
        the unusual port with STRICT_PORTS=yes; never the web. What is usual is per protocol, as the
        firewall's odd-port rules have it: TCP 123 and UDP 80 are unusual."""
        if (proto, port) == ("udp", 123):
            return self.clock == "none"
        return self.strict and port not in USUAL_PORTS.get(proto, ())


@dataclass(frozen=True)
class Stage:
    name: str
    outcome: str  # PASS, FAIL, UNKNOWN or SKIPPED
    detail: str = ""


@dataclass
class Verdict:
    verdict: str  # PASS, FAIL or UNKNOWN
    stages: list[Stage] = field(default_factory=list)
    t: float = 0.0
    ms: int = 0

    @property
    def reason(self) -> str:
        """The first stage that decided the verdict, as `name: detail`; '' for a pass."""
        for s in self.stages:
            if s.outcome == self.verdict and self.verdict != PASS:
                return f"{s.name}: {s.detail}" if s.detail else s.name
        return ""

    @property
    def word(self) -> str:
        """The deciding stage's name alone: a plain word for the change ledger's spool."""
        return next((s.name for s in self.stages if s.outcome == self.verdict and self.verdict != PASS), "")

    def as_dict(self) -> dict:
        return {
            "verdict": self.verdict,
            "reason": self.reason,
            "t": self.t,
            "ms": self.ms,
            "stages": [{"name": s.name, "outcome": s.outcome, "detail": s.detail} for s in self.stages],
        }

    def compact(self) -> str:
        """What the gateway sample stores: the verdict, the stage that decided it and each stage's
        outcome. No name, no address and no time of anything the TV did: nothing here is a viewing record."""
        return json.dumps(
            {
                "v": self.verdict,
                "why": self.word,
                "ms": self.ms,
                "s": {s.name: s.outcome for s in self.stages},
            },
            sort_keys=True,
            separators=(",", ":"),
        )


def unknown(why: str, t: float | None = None) -> Verdict:
    """A run that could not judge: one stage, `probe`, saying why."""
    return Verdict(UNKNOWN, [Stage("probe", UNKNOWN, why)], t=time.time() if t is None else t)


def list_hosts(profile: Profile) -> list[str]:
    """The hosts the profile's blocklists are fetched from, in its order, each once; never an address."""
    out: list[str] = []
    for _name, url in profile.adguard_filters:
        host = (urllib.parse.urlsplit(url).hostname or "").lower()
        with contextlib.suppress(ValueError):
            ipaddress.ip_address(host)
            continue
        if host and host not in out:
            out.append(host)
    return out


def plan(s: Settings, profile: Profile, clock: str = "any") -> Plan:
    """The names a run uses. Raises ValueError when TV_PROBE_IP cannot be used. (ports) `clock` is the clock
    port as the last apply built it (applied_clock)."""
    from tvgw import adguardcfg, verify  # both import heavily; neither is needed by the client half

    filtered = set(profile.url_filter.hosts) if profile.url_filter else set()
    allow = tuple(h for h in profile.must_allow if h not in filtered and "*" not in h)
    block = adguardcfg._locally_blocked(profile.adguard_rules(s.gw_ip, s.tv_ip))
    if block is None:
        block = next(iter(verify.sentinels(profile)), None)
    # never a name of the TV's vendor: a must-allow host, or any name under one, is not a neutral server,
    # whoever names it (`www.lge.com` is the vendor's as `snu.lge.com` is); nor a host the URL filter holds
    named = [s.tv_probe_target.lower()] if s.tv_probe_target else list_hosts(profile)
    vendor = (*profile.must_allow, *filtered)
    targets = tuple(h for h in named if not any(covers(v, h) for v in vendor))[:MAX_TARGETS]
    # (revert) the adtech wall is LG's alone, as tvgw-apply renders it (design decision 62)
    adtech = s.adtech_port_wall == "yes" and (s.profile or "lg-webos") == "lg-webos"
    return Plan(
        s.gw_ip,
        config.probe_side(s),
        allow,
        block,
        s.block_quic == "yes",
        targets,
        strict=s.strict_ports == "yes",
        clock=clock if clock in ("any", "resolved", "none") else "any",
        adtech=adtech,
    )


def _blocked(answers: list[str] | None) -> bool:
    """The filter's own blocked answer and nothing else: 0.0.0.0 (AdGuard's `default` mode, which tvgw
    sets). An empty or failed answer is not it: an upstream that is away answers that way too."""
    return answers == ["0.0.0.0"]


def _address(answers: list[str] | None) -> str | None:
    return next((a for a in answers or [] if a != "0.0.0.0"), None)


@dataclass(frozen=True)
class Port:
    """The TV's own port, read and asked: TV_IF's forwarding switches, the kernel's route for a packet
    from TV_IP arriving on TV_IF, and the interface the gateway's own answers to TV_IP leave by (table
    100's TV-subnet route in direct mode, design decision 49: the probe's own way back is a route of its
    own, so no packet of its tests this one)."""

    forwarding: bool
    route_dev: str | None
    out_if: str
    reply_dev: str | None = None
    tv_if: str = ""
    # (ports) net.ipv4.icmp_errors_use_inbound_ifaddr is not 0: the gateway's ICMP errors then carry another
    # address than GW_IP, and the probe cannot tell its refusals from other errors
    icmp_inbound: bool = False


@dataclass(frozen=True)
class Uplink:
    up: bool
    why: str = ""


def judge(
    p: Plan,
    obs: dict,
    port: Port,
    uplink: Uplink,
    control: Callable[[], dict[str, bool]] | None = None,
    held: Stage | None = None,
) -> Verdict:
    """The verdict of one observation. A step is `fail` only when its failure is one an apply can cause;
    for the connection out, only when `control()` says the gateway itself completed it by the uplink the
    TV uses (`path`); for a resolver that is silent at the TV's position, only when it answers the
    gateway (`resolver`). `control()` is asked only then. The table, a row an outcome:

    port      forwarding off for TV_IF                               fail
              the TV's route leaves by another interface             fail; unknown with the uplink down
              the gateway's answers to the TV leave by another       fail
    lookup    every must-allow name got an address                   pass
              the resolver answers nothing here, and the gateway     fail
              the resolver answers nothing here, nor the gateway     unknown
              a name blocked, or without an address                  unknown (the filter, its upstream)
    lists     no address a must-allow name got is a refused one      pass
              one is in the DoH list or the owner's blocked ones     fail
              no must-allow name got an address to look up           skipped
    path      a handshake completed                                  pass
              not due in this run, or no neutral server known        skipped
              the uplink is down                                     unknown
              the target is blocked or refused by the TV's rules     unknown
              failed, and the gateway by the same uplink completed   fail
              failed, and the gateway by the same uplink did not     unknown
    blocked   the filter's blocked answer                            pass
              anything else                                          unknown (the filter's lists)
    dot,      refused by the gateway: its ICMP error, or a reset     pass
    quic,       while the next hop answered a TCP try by time-exceeded
    adtech    let out: silent, an answer, an error from beyond       fail; unknown with the uplink down
              a reset the next hop may have sent, no route out, an   unknown
                error the probe cannot attribute, not tried
    redirect  any answer                                             pass
              none, and the resolver answers here                    fail
              none, and the resolver answers nothing here            unknown
    ports     each port refused exactly where it must be             pass
              a port the TV uses refused by the gateway              fail
              a port that must be refused let through                fail; unknown with the uplink down
              the gateway had no route for a try (not a refusal)     unknown
              a reset the next hop may have sent (as for the walls)  unknown
              an error the probe cannot attribute                    unknown
              the gateway's errors carry another address than GW_IP  unknown
              the client tried no port                               unknown
    gate      the address gate's table refuses nothing (it counts)   pass
              it holds a rule that can refuse                        unknown (no copy of it to cross)
              it is not loaded                                       skipped
    held      the same conntrack entry                               pass
              gone or new, the far end did not close it              fail; skipped when the uplink changed
              gone or new, the connection reset, or no word of it    unknown
              gone or new, the far end closed it                     skipped
    """
    stages: list[Stage] = []
    did: dict[str, bool] | None = None

    def gateway() -> dict[str, bool]:
        nonlocal did
        if did is None:
            did = dict(control()) if control else {}
        return did

    # 1. the TV's own port: asked, not crossed
    if not port.forwarding:
        stages.append(Stage("port", FAIL, "forwarding is off for the TV's port"))
    elif port.route_dev != port.out_if:
        why = f"the TV's packets would leave by {port.route_dev or 'nothing'}, not {port.out_if}"
        stages.append(Stage("port", FAIL if uplink.up else UNKNOWN, why if uplink.up else uplink.why))
    elif port.tv_if and port.reply_dev != port.tv_if:
        why = (
            f"the gateway's answers to the TV would leave by {port.reply_dev or 'nothing'}, not {port.tv_if}"
        )
        stages.append(Stage("port", FAIL, why))
    else:
        stages.append(Stage("port", PASS))
    # 2. every must-allow name gets an address from the gateway's resolver; no connection is made to one
    asked = obs.get("allow") or []
    tried = obs.get("path")
    answered = obs.get("blocked") is not None or any(
        t.get("answers") is not None for t in [*asked, *(tried or [])]
    )
    without = [t["name"] for t in asked if not _address(t.get("answers"))]
    if not p.allow:
        stages.append(Stage("lookup", SKIPPED, "the profile names no must-allow host"))
    elif asked and not without and len(asked) == len(p.allow):
        stages.append(Stage("lookup", PASS))
    elif not answered and gateway().get("resolver") is True:
        why = "the resolver answers the gateway itself and nothing at the TV's position"
        stages.append(Stage("lookup", FAIL, why))
    elif not answered:
        stages.append(
            Stage("lookup", UNKNOWN, "the resolver answers nobody: its service, not an apply's doing")
        )
    else:
        n = len(p.allow) - len(asked) + len(without)
        why = f"{n} of {len(p.allow)} must-allow names got no address: the filter or its upstream"
        stages.append(Stage("lookup", UNKNOWN, why))
    # 2b. (revert) no address a must-allow name got is one the TV's rules refuse whatever the path: a
    #     refreshed DoH list, or the owner's blocked addresses, that took an address the TV needs. Asked of
    #     the kernel's sets (_judged): nothing connects to the address
    if p.allow:
        got = [t for t in asked if _address(t.get("answers"))]
        listed = [t for t in got if t.get("listed")]
        old = [t for t in got if t.get("listed_before")]
        if listed:
            where = LIST_PLAIN.get(listed[0]["listed"], listed[0]["listed"])
            why = f"{len(listed)} of {len(p.allow)} must-allow names got an address the TV's rules refuse:"
            why += f" {where}"
            stages.append(Stage("lists", FAIL, why))
        elif old:  # across an apply: the answer moved onto an address listed before it, no doing of the apply
            where = LIST_PLAIN.get(old[0]["listed_before"], old[0]["listed_before"])
            why = f"a must-allow name got an address {where} held before this apply too: not its doing"
            stages.append(Stage("lists", UNKNOWN, why))
        elif got:
            stages.append(Stage("lists", PASS))
        else:
            stages.append(Stage("lists", SKIPPED, "no must-allow name got an address to look up"))
    # 3. a connection out and back, to a neutral server
    if tried is None:
        stages.append(Stage("path", SKIPPED, "no connection out was due in this run"))
    elif not p.targets:
        stages.append(Stage("path", SKIPPED, "no neutral server is known: name one with TV_PROBE_TARGET"))
    elif any(t.get("tls") == "ok" for t in tried):
        stages.append(Stage("path", PASS))
    elif not uplink.up:
        stages.append(Stage("path", UNKNOWN, uplink.why))
    elif tried and all(t.get("ruled") or _blocked(t.get("answers")) for t in tried):
        why = "the filter or the firewall refuses the probe's own target: name another with TV_PROBE_TARGET"
        stages.append(Stage("path", UNKNOWN, why))
    elif gateway().get("path"):
        why = "a connection out fails beside the TV's port and completes from the gateway by the same uplink"
        stages.append(Stage("path", FAIL, why))
    else:
        why = "a connection out fails, and from the gateway by the same uplink too: not the TV's path"
        stages.append(Stage("path", UNKNOWN, why))
    # 4. the walls
    if p.block is None:
        stages.append(Stage("blocked", SKIPPED, "the profile names no blocked name"))
    elif _blocked(obs.get("blocked")):
        stages.append(Stage("blocked", PASS))
    elif obs.get("blocked") is None:
        stages.append(Stage("blocked", UNKNOWN, "the resolver gave no answer"))
    else:
        why = "the filter did not give its blocked answer for a blocked name: its lists, not an apply's doing"
        stages.append(Stage("blocked", UNKNOWN, why))
    # every try of the run's at WALL_ADDR, the walls' with the ports': a reset is the gateway's only beside
    # the next hop's time-exceeded for one of them (_owned)
    tries = obs.get("ports") if isinstance(obs.get("ports"), dict) else {}
    hop = _hop_answered({**tries, **{f"{pr}/{n}": obs.get(w) for w, (pr, n) in WALLS.items()}})
    stages.append(_wall("dot", obs.get("dot"), "DNS over TLS", uplink, hop))
    if p.quic:
        stages.append(_wall("quic", obs.get("quic"), "QUIC", uplink, hop, "udp"))
    if p.adtech:  # (revert) a reset, as tvgw-apply's wall sends it
        stages.append(_wall("adtech", obs.get("adtech"), "LG's adtech port", uplink, hop))
    if obs.get("redirect") is not None:
        stages.append(Stage("redirect", PASS))
    elif answered:
        why = "a lookup aimed at another resolver was not answered by the gateway's filter"
        stages.append(Stage("redirect", FAIL, why))
    else:
        stages.append(Stage("redirect", UNKNOWN, "the resolver answers nothing here"))
    if p.ports:
        stages.append(_ports(p, obs.get("ports"), uplink, port, hop))
    gate = obs.get("gate")  # (revert) read from the kernel by _judged
    if gate == "counts":
        stages.append(Stage("gate", PASS))
    elif gate == "refuses":
        why = "the address gate holds a rule that can refuse, and the test has no copy of it to cross"
        stages.append(Stage("gate", UNKNOWN, why))
    elif gate == "absent":
        stages.append(Stage("gate", SKIPPED, "the address gate is not loaded"))
    if held is not None:
        stages.append(held)
    outcomes = {s.outcome for s in stages}
    verdict = FAIL if FAIL in outcomes else UNKNOWN if UNKNOWN in outcomes else PASS
    return Verdict(verdict, stages)


def port_name(proto: str, port: int) -> str:
    """`TCP 80`, `UDP 123`: a port in the words the stages use."""
    return f"{proto.upper()} {port}"


# (ports) the gateway let the try out: nothing answered it, something did, or a host beyond the gateway
# sent an error (the next hop's time-exceeded is `expired`)
LET_OUT = ("silent", "connected", "answered", "unreachable", "expired")


def _hop_answered(words: dict) -> bool:
    """(walls) Whether the next hop answered a TCP try of this run with a time-exceeded of its own: a try
    reaches it with one hop left to live and goes no further, so a hop that answers so is no hop that
    resets, and a reset of another try is the gateway's."""
    return any(w == "expired" for k, w in words.items() if k.startswith("tcp/"))


def _owned(proto: str, got: str | None, hop: bool) -> str | None:
    """(walls) A TCP reset as the gateway's refusal when the next hop answered by time-exceeded (hop);
    without that it may be the next hop's (a router that owns or intercepts the address), and stays
    `reset`. A reset names no sender: an ICMP error does, and is read as such (_refusal_word)."""
    return "refused" if got == "reset" and proto == "tcp" and hop else got


def _unjudged(what: str, got: str | None) -> str:
    """(walls, ports) Why a try's ending is neither a refusal nor a try let out, in the stages' words."""
    if got is None:
        return f"{what} was not tried"
    if got == "unroutable":
        return f"the gateway had no route out for {what}"
    if got == "reset":
        return f"{what} was reset, by the gateway or by the next hop, which cannot be told apart"
    return f"{what} met an error the probe cannot attribute"


def _ports(p: Plan, saw: dict | None, uplink: Uplink, port: Port | None = None, hop: bool = False) -> Stage:
    """(ports) The ports at WALL_ADDR, tried at once (ports_try). Only the gateway's own refusal counts as
    one (_refusal_word; a reset only with `hop`, _owned): a port the TV uses that the gateway refused is a
    fail whatever the uplink; a port that must be refused and was let out (silent, or an error from beyond
    the gateway) is a fail with the uplink up and unknown without it, as for the walls. Neither a missing
    route (an error from the gateway that refuses nothing: the uplink down, say), a reset the next hop may
    have sent, nor an error the probe cannot attribute is ever a pass or a fail. And when the gateway's
    errors do not carry GW_IP, nothing here can be told apart."""
    if port is not None and port.icmp_inbound:
        why = (
            "the gateway's ICMP errors carry the address of the port a packet came in by"
            " (net.ipv4.icmp_errors_use_inbound_ifaddr is not 0), so its refusals cannot be told from"
            " other errors"
        )
        return Stage("ports", UNKNOWN, why)
    if not isinstance(saw, dict) or not saw:
        return Stage("ports", UNKNOWN, "the test client tried no port")
    unknown_why = ""
    for proto, number in p.ports:
        got = _owned(proto, saw.get(f"{proto}/{number}"), hop)
        name = port_name(proto, number)
        if got not in ("refused", *LET_OUT):  # not tried, no route, a reset of no known sender, unattributed
            down = got == "unroutable" and not uplink.up
            unknown_why = unknown_why or (uplink.why if down else _unjudged(name, got))
            continue
        if p.expect_refused(proto, number):
            if got == "refused":
                continue
            if not uplink.up:
                unknown_why = unknown_why or uplink.why
                continue
            why = (
                f"{name}, the clock port, was not refused, and the last apply closed it"
                if (proto, number) == ("udp", 123)
                else f"{name}, an unusual port, was not refused, and STRICT_PORTS=yes"
            )
            return Stage("ports", FAIL, why)
        if got == "refused":
            return Stage("ports", FAIL, f"the gateway refuses {name}, which it must let through")
    if unknown_why:
        return Stage("ports", UNKNOWN, unknown_why)
    return Stage("ports", PASS)


def _wall(
    name: str, saw: str | None, what: str, uplink: Uplink, hop: bool = False, proto: str = "tcp"
) -> Stage:
    """A wall that answers with a refusal, tried at an address where nothing else can answer and with a
    time to live that ends at the next hop (ports_try). Only the gateway's own refusal is a pass: its ICMP
    error, or a reset beside the next hop's time-exceeded (_owned). A try let out is a fail, unless the
    uplink is down: then the packet never came to the rule, which stands behind the choice of the way out.
    Anything else is unknown, never a pass: a reset the next hop may have sent (before 2026-11-17 any reset
    passed, and a router that resets unrouted addresses held up a missing wall), no route out, an error the
    probe cannot attribute, a try not made."""
    got = _owned(proto, saw, hop)
    if got == "refused":
        return Stage(name, PASS)
    if not uplink.up:
        return Stage(name, UNKNOWN, uplink.why)
    if got in LET_OUT:
        return Stage(name, FAIL, f"{what} was not refused by the gateway")
    return Stage(name, UNKNOWN, _unjudged(what, got))


# ---- the client: what runs inside the namespace (and, for the control, in the gateway's own) ------------


def ask(name: str, server: str, timeout: float = DNS_TIMEOUT, port: int = 53) -> list[str] | None:
    """The A records `server` gives for `name` over UDP, [] for an answer without one, None for none at
    all. The socket is connected, so only `server`'s reply is taken."""
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
            sock.settimeout(timeout)
            sock.connect((server, port))
            sock.send(dnsq.question(name, qid=int.from_bytes(os.urandom(2), "big")))
            data = sock.recv(4096)
    except OSError:
        return None
    try:
        return [a.value for a in dnsmsg.decode_answers(data) if a.rtype == "A"]
    except (ValueError, IndexError, struct.error):
        return []


def _saw(exc: BaseException) -> str:
    """One word for how a connection attempt ended."""
    if isinstance(exc, TimeoutError):
        return "silent"
    code = exc.errno if isinstance(exc, OSError) else None
    if code in (errno.ECONNREFUSED, errno.ECONNRESET):
        return "refused"
    if code in (errno.ENETUNREACH, errno.EHOSTUNREACH, errno.ETIMEDOUT):
        return "silent" if code == errno.ETIMEDOUT else "unreachable"
    return "error"


# (ports) Linux's extended error report on a UDP socket (ip(7), IP_RECVERR): `struct sock_extended_err`
# (errno, origin, ICMP type, ICMP code, padding, info, data), then the sender of the error, a sockaddr_in
IP_RECVERR = getattr(socket, "IP_RECVERR", 11)
MSG_ERRQUEUE = getattr(socket, "MSG_ERRQUEUE", 0x2000)
SO_EE_ORIGIN_ICMP = 2
_EXTENDED_ERR = struct.Struct("=IBBBBII")


# the ICMP destination-unreachable codes that are a filter's refusal and not a missing route: port
# unreachable (3, what nft's `reject` sends), network and host administratively prohibited (9, 10) and
# communication administratively prohibited (13, `reject with icmpx admin-prohibited`). Network or host
# unreachable from the gateway (0, 1) is a route it does not have: the uplink down, say
ICMP_UNREACH, ICMP_TIME_EXCEEDED = 3, 11
REFUSAL_CODES = frozenset({3, 9, 10, 13})
ICMP_ERRORS = frozenset({3, 11, 12})  # destination unreachable, time exceeded, parameter problem


def icmp_sender(cmsgs: list) -> tuple[int, str, int, int] | None:
    """(ports) (errno, the address that sent the ICMP error, its type, its code) from the ancillary data of
    a recvmsg of a UDP socket's error queue, or None when it holds no ICMP error with a sender."""
    for level, kind, data in cmsgs:
        if level != socket.IPPROTO_IP or kind != IP_RECVERR or len(data) < _EXTENDED_ERR.size + 8:
            continue
        err, origin, icmp_type, icmp_code, _pad, _info, _data = _EXTENDED_ERR.unpack_from(data)
        if origin != SO_EE_ORIGIN_ICMP:
            continue
        family = int.from_bytes(data[16:18], sys.byteorder)
        if family != socket.AF_INET:
            continue
        return err, socket.inet_ntoa(data[20:24]), icmp_type, icmp_code
    return None


def icmp_error_of(packet: bytes) -> tuple[str, int, int, int, str, int] | None:
    """(ports) (its sender, its type, its code, the original's protocol, destination and destination port)
    of an ICMP error as a raw socket reads it, its IPv4 header first; None for anything else. How the
    client tells who refused a TCP try, which reports only an errno."""
    if len(packet) < 20 or packet[0] >> 4 != 4:
        return None
    ihl = (packet[0] & 0x0F) * 4
    inner = ihl + 8
    if len(packet) < inner + 20 or packet[ihl] not in ICMP_ERRORS or packet[inner] >> 4 != 4:
        return None
    iihl = (packet[inner] & 0x0F) * 4
    if len(packet) < inner + iihl + 4:
        return None
    dport = int.from_bytes(packet[inner + iihl + 2 : inner + iihl + 4], "big")
    return (
        socket.inet_ntoa(packet[12:16]),
        packet[ihl],
        packet[ihl + 1],
        packet[inner + 9],
        socket.inet_ntoa(packet[inner + 16 : inner + 20]),
        dport,
    )


def _refusal_word(err: int, sender: str | None, gw: str, icmp: tuple[int, int] | None = None) -> str:
    """(ports) How a port try ended. With the ICMP error's sender and (type, code) known: `refused` only
    for the gateway's own error of a refusing kind (REFUSAL_CODES); `unroutable` for any other error from
    the gateway, a route it does not have; `expired` for a time-exceeded from another host, the next hop,
    where the try's time to live ran out; `unreachable` for any other error from beyond the gateway. Both
    of those mean the try left it. Without them (a TCP try the raw socket saw no ICMP error for): a reset is
    `reset`, the gateway's or the next hop's, which only the judge can tell (_owned); a host or network
    unreachable is `unattributed`, since the gateway's admin-prohibited refusal, its missing route and an
    error from beyond all read the same. A reset was `refused` until 2026-11-17, whoever sent it."""
    if sender is not None:
        if sender != gw:
            return "expired" if icmp is not None and icmp[0] == ICMP_TIME_EXCEEDED else "unreachable"
        refusing = icmp is not None and icmp[0] == ICMP_UNREACH and icmp[1] in REFUSAL_CODES
        return "refused" if refusing else "unroutable"
    if err in (errno.ECONNREFUSED, errno.ECONNRESET):
        return "reset"
    if err in (errno.EHOSTUNREACH, errno.ENETUNREACH, errno.EHOSTDOWN, errno.ENETDOWN):
        return "unattributed"
    return "connected" if err == 0 else "error"


def _raw_errors(raw: socket.socket | None, addr: str) -> dict[int, tuple[str, int, int]]:
    """(ports) {TCP destination port: (sender, type, code)} of the ICMP errors the raw socket holds for
    TCP tries to `addr`; empty without one (not root)."""
    found: dict[int, tuple[str, int, int]] = {}
    while raw is not None:
        try:
            packet = raw.recv(2048)
        except OSError:
            break
        got = icmp_error_of(packet)
        if got is not None and got[3] == socket.IPPROTO_TCP and got[4] == addr:
            found.setdefault(got[5], (got[0], got[1], got[2]))
    return found


def _payload(proto: str, port) -> bytes:
    """A UDP try's datagram: the QUIC wall's looks like the start of a QUIC connection, the rest are
    PORT_PROBE's few bytes."""
    return QUIC_PROBE if (proto, int(port)) == WALLS["quic"] else PORT_PROBE


def ports_try(addr: str, ports, gw: str, wait: float = PORT_WAIT, refuse=()) -> dict[str, str]:
    """(ports) Every port in `ports` (protocol, port) at `addr`, all at once, for at most `wait` seconds:
    {"tcp/80": refused | reset | unroutable | expired | unreachable | unattributed | silent | connected |
    error, ...} (_refusal_word). Each try leaves with a time to live of PORT_TTL: it crosses the gateway's
    filter, and a try the filter lets through dies at the next hop (the home router, or the VPN's server),
    which says so at once with an ICMP time-exceeded. So nothing of it goes beyond the next hop, and an
    error from beyond never arrives seconds later, when the probe's port is gone. TCP is a connect that
    nobody completes; a raw ICMP socket, open for the client's whole try (it runs as root inside its
    namespace), reads the sender and the code of the ICMP error a TCP try met. UDP sends one small datagram
    (the QUIC wall's a QUIC one), again after PORT_RESEND, and reads the error's sender and code from the
    socket's own error queue. The try ends as soon as every port has its answer, or once only ports no
    refusal is expected for (all but `refuse`) are still silent after PORT_QUIET; while a TCP try that
    must be refused was reset, the TCP tries let through are waited for, up to `wait`, since only the next
    hop's time-exceeded for one of them makes that reset the gateway's (_owned)."""
    must = {f"{proto}/{port}" for proto, port in refuse}
    out: dict[str, str] = {}
    socks: dict[int, tuple[str, str, socket.socket]] = {}
    pending_tcp: dict[int, int] = {}  # TCP destination port -> its socket's descriptor, until it is decided
    seen: dict[int, tuple[str, int, int]] = {}  # TCP destination port -> (sender, type, code), raw socket
    poller = select.poll()
    try:
        raw: socket.socket | None = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
        raw.setblocking(False)
        poller.register(raw.fileno(), select.POLLIN)
    except OSError:
        raw = None
    for proto, port in ports:
        key = f"{proto}/{port}"
        try:
            if proto == "tcp":
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.setsockopt(socket.IPPROTO_IP, socket.IP_TTL, PORT_TTL)
                sock.setblocking(False)
                err = sock.connect_ex((addr, int(port)))
                if err not in (0, errno.EINPROGRESS):
                    sock.close()
                    out[key] = _refusal_word(err, None, gw)
                    continue
                poller.register(sock.fileno(), select.POLLOUT | select.POLLERR | select.POLLHUP)
                pending_tcp[int(port)] = sock.fileno()
            else:
                sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                sock.setsockopt(socket.IPPROTO_IP, IP_RECVERR, 1)
                sock.setsockopt(socket.IPPROTO_IP, socket.IP_TTL, PORT_TTL)
                sock.connect((addr, int(port)))
                sock.setblocking(False)
                sock.send(_payload(proto, port))
                poller.register(sock.fileno(), select.POLLERR | select.POLLIN)
            socks[sock.fileno()] = (proto, key, sock)
        except OSError as e:
            out[key] = _saw(e)

    def done(fd: int, word: str) -> None:
        proto, key, sock = socks.pop(fd)
        out[key] = word
        poller.unregister(fd)
        sock.close()
        if proto == "tcp":
            pending_tcp.pop(int(key.split("/")[1]), None)

    def gather() -> None:
        """The ICMP errors the raw socket holds, each deciding its TCP try: the kernel hands raw sockets
        their copy of an ICMP error before the TCP socket learns of it, so a try's error is here by the time
        its socket says it failed. A time-exceeded is no error to TCP at all, so it decides a try that would
        otherwise wait."""
        for port, found in _raw_errors(raw, addr).items():
            seen.setdefault(port, found)
            if port in pending_tcp:
                done(pending_tcp[port], _refusal_word(0, found[0], gw, (found[1], found[2])))

    def until() -> float:
        """How long the try waits: `wait` while a port that must be refused has no answer, or while a TCP
        one was reset and no TCP try let through has met the next hop's time-exceeded; else PORT_QUIET."""
        pending = {key for _p, key, _s in socks.values()}
        unowned = any(out.get(k) == "reset" for k in must) and not _hop_answered(out)
        tcp = any(k.startswith("tcp/") for k in pending)
        return wait if pending & must or (unowned and tcp) else min(wait, PORT_QUIET)

    start = time.monotonic()
    resend = min(PORT_RESEND, wait / 2)
    resent = False
    try:
        while socks:
            # read what has come before the clock decides anything: a refusal that arrived while this
            # process waited for the CPU (a loaded runner, a busy gateway) is a refusal, not silence. Until
            # 2026-11-17 the clock was looked at first, and a port could be called silent unread
            nxt = until() if resent else min(until(), resend)
            for fd, _event in poller.poll(max(0, math.ceil((nxt - (time.monotonic() - start)) * 1000))):
                if raw is not None and fd == raw.fileno():
                    gather()  # a TCP try's ICMP error, with its sender and code, which its errno cannot say
                    continue
                if fd not in socks:
                    continue
                proto, key, sock = socks[fd]
                if proto == "tcp":
                    gather()  # first: an ICMP error behind this socket's errno says whose it is
                    if fd in socks:
                        done(fd, _refusal_word(sock.getsockopt(socket.SOL_SOCKET, socket.SO_ERROR), None, gw))
                else:
                    udp = None
                    with contextlib.suppress(OSError):
                        _data, cmsgs, _flags, _addr = sock.recvmsg(512, 512, MSG_ERRQUEUE)
                        udp = icmp_sender(cmsgs)
                    err = sock.getsockopt(socket.SOL_SOCKET, socket.SO_ERROR)
                    if udp is not None:
                        done(fd, _refusal_word(udp[0], udp[1], gw, (udp[2], udp[3])))
                    else:  # an error whose report could not be read: whose it is cannot be said
                        done(fd, "unattributed" if err else "connected")
            elapsed = time.monotonic() - start
            if not resent and elapsed >= resend:
                resent = True
                for proto, key, sock in socks.values():
                    if proto == "udp":
                        with contextlib.suppress(OSError):
                            sock.send(_payload(*key.split("/")))
            if elapsed >= until():
                break  # what is left was let through: nothing that must be refused is still waited for
        # an errno the raw socket's error, read after it, can still attribute
        for port, found in _raw_errors(raw, addr).items():
            seen.setdefault(port, found)
        for proto, port in ports:
            key = f"{proto}/{port}"
            if proto == "tcp" and out.get(key) == "unattributed" and int(port) in seen:
                sender, icmp_type, icmp_code = seen[int(port)]
                out[key] = _refusal_word(0, sender, gw, (icmp_type, icmp_code))
    finally:
        for _proto, key, sock in socks.values():
            out.setdefault(key, "silent")
            sock.close()
        if raw is not None:
            raw.close()
    return out


def tls_context() -> ssl.SSLContext:
    """A client that completes a handshake with whatever the far end offers: the probe tests the path,
    and a TV's own servers need not satisfy this computer's trust store or its minimum protocol."""
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    with contextlib.suppress(ValueError, ssl.SSLError):
        ctx.minimum_version = ssl.TLSVersion.MINIMUM_SUPPORTED
    with contextlib.suppress(ssl.SSLError):
        ctx.set_ciphers("DEFAULT:@SECLEVEL=0")
    return ctx


def handshake(
    addr: str, name: str, timeout: float = TCP_TIMEOUT, device: str = "", port: int = 443
) -> tuple[str, ssl.SSLSocket | None]:
    """A TLS handshake with `addr`, naming `name`: ('ok', the open socket) or (how it ended, None).
    Nothing is sent after the handshake. `device` binds the socket to one interface (the gateway's own
    try by the uplink the TV uses); a socket that cannot be bound makes no connection at all."""
    raw = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        raw.settimeout(timeout)
        if device:
            try:
                raw.setsockopt(socket.SOL_SOCKET, getattr(socket, "SO_BINDTODEVICE", 25), device.encode())
            except OSError:
                raw.close()
                return "unbound", None
        raw.connect((addr, port))
    except (OSError, TimeoutError) as e:
        raw.close()
        return _saw(e), None
    try:
        return "ok", tls_context().wrap_socket(raw, server_hostname=name)
    except (OSError, TimeoutError, ValueError) as e:  # ssl.SSLError is an OSError
        raw.close()
        return ("tls" if isinstance(e, ssl.SSLError) else _saw(e)), None


def observe(spec: dict, keep: bool = False) -> tuple[dict, ssl.SSLSocket | None]:
    """Everything one run sends, in order, and what came back. Every must-allow name is looked up and
    none is connected to (two in a row without any answer end the asking: the resolver is away). The
    connection out goes to the spec's `targets`, neutral servers; `targets` None is a run that makes
    none. With `keep` that connection is returned open (for the hold); otherwise it is closed as soon as
    the handshake is done. The walls are tried at `wall`, where nothing but the gateway can answer, with
    the ports and as they are (ports_try)."""
    gw, wall, held, silent = spec["gw"], spec["wall"], None, 0
    obs: dict = {"allow": [], "path": None}
    for name in spec["allow"]:
        answers = ask(name, gw)
        obs["allow"].append({"name": name, "answers": answers})
        silent = silent + 1 if answers is None else 0
        if silent >= 2:
            break
    if spec.get("targets") is not None:
        obs["path"] = []
        for name in spec["targets"]:
            answers = ask(name, gw)
            item: dict = {"name": name, "answers": answers, "addr": _address(answers), "tls": None}
            if item["addr"]:
                item["tls"], sock = handshake(item["addr"], name)
                if sock is not None and keep and held is None:
                    held = sock
                elif sock is not None:
                    sock.close()
            obs["path"].append(item)
            if item["tls"] == "ok":
                break
    block = spec.get("block")
    obs["blocked"] = ask(block, gw) if block else None
    ports = [(str(proto), int(port)) for proto, port in spec.get("ports") or []]  # (ports)
    refuse = [(str(proto), int(port)) for proto, port in spec.get("refuse") or []]
    # the walls, each a port that must be refused, tried once and together with the ports: so with their
    # time to live, which ends a try a missing wall let out at the next hop, and with the sender of each
    # refusal read. (revert) The adtech port only where its wall stands
    walls = {w: WALLS[w] for w in WALLS if w == "dot" or spec.get(w)}
    saw = ports_try(wall, [*ports, *walls.values()], gw, refuse=[*refuse, *walls.values()])
    for w, (proto, port) in WALLS.items():
        obs[w] = saw.get(f"{proto}/{port}") if w in walls else None
    obs["ports"] = {k: saw[k] for k in (f"{proto}/{port}" for proto, port in ports) if k in saw} or None
    obs["redirect"] = ask(block or "redirect.tvgw.invalid", wall)
    return obs, held


def _peer_state(sock: ssl.SSLSocket) -> str:
    """open, closed (the far end ended it) or reset. Whatever the far end sent after its handshake (its
    session tickets) is read away on the way: an end of the stream may sit behind it."""
    try:
        sock.settimeout(0)
        while True:
            if not sock.recv(4096):
                return "closed"
    except (ssl.SSLWantReadError, BlockingIOError):
        return "open"
    except (ssl.SSLEOFError, ssl.SSLZeroReturnError):
        return "closed"
    except OSError:
        return "reset"


def client_main(argv: list[str]) -> int:
    """`python -m tvgw.probe --client SPEC [--hold SECONDS]`: one line of JSON per observation. With
    --hold it keeps the allowed connection open, with a keep-alive each second so that packets of it are
    in flight, waits for a line on stdin (the plan to observe next, as JSON), and observes
    again; no line in time, and it just ends."""
    spec = json.loads(argv[0])
    hold = float(argv[2]) if len(argv) >= 3 and argv[1] == "--hold" else 0.0
    obs, held = observe(spec, keep=hold > 0)
    first: dict = {"obs": obs}
    if held is not None:
        raw = held
        with contextlib.suppress(OSError, AttributeError):
            raw.setsockopt(socket.SOL_SOCKET, socket.SO_KEEPALIVE, 1)
            raw.setsockopt(socket.IPPROTO_TCP, socket.TCP_KEEPIDLE, 1)
            raw.setsockopt(socket.IPPROTO_TCP, socket.TCP_KEEPINTVL, 1)
            raw.setsockopt(socket.IPPROTO_TCP, socket.TCP_KEEPCNT, 30)
        first["held"] = {"dst": held.getpeername()[0], "sport": held.getsockname()[1]}
    print(json.dumps(first), flush=True)
    if hold <= 0:
        return 0
    ready, _, _ = select.select([sys.stdin], [], [], hold)
    line = sys.stdin.readline().strip() if ready else ""
    if not line:
        return 0
    # the line is what to observe now: the plan as the apply left it
    with contextlib.suppress(ValueError, AttributeError):
        spec = json.loads(line).get("spec") or spec
    state = _peer_state(held) if held is not None else None
    obs, _ = observe(spec)
    print(json.dumps({"obs": obs, "held_state": state}), flush=True)
    return 0


# ---- the gateway's side: its own readings, the namespace, the run ---------------------------------------


def _run(cmd: list[str], timeout: float = 15.0) -> tuple[int, str]:
    """(exit status, stdout); 127 for a command that is missing or does not finish."""
    try:
        out = subprocess.run(
            cmd, capture_output=True, text=True, encoding="utf-8", errors="replace", timeout=timeout
        )
        return out.returncode, out.stdout
    except (OSError, subprocess.TimeoutExpired):
        return 127, ""


def _read(path: str) -> str:
    try:
        with open(path, encoding="utf-8", errors="replace") as fh:
            return fh.read()
    except OSError:
        return ""


def _write(path: str, text: str) -> bool:
    try:
        with open(path, "w", encoding="utf-8") as fh:
            fh.write(text)
        return True
    except OSError:
        return False


@dataclass
class Env:
    """Everything a run touches outside itself. `netns` is the namespace's name: a second gateway on the
    same computer (the namespace tier's) names its own."""

    run: Callable[..., tuple[int, str]] = _run
    read: Callable[[str], str] = _read
    write: Callable[[str, str], bool] = _write
    netns: str = NETNS
    python: str = sys.executable
    lock: str = LOCK
    sleep: Callable[[float], None] = time.sleep
    euid: Callable[[], int] = os.geteuid
    stamp: str = PATH_STAMP
    applied: str = APPLIED
    last: str = LAST
    exists: Callable[[str], bool] = os.path.exists
    clock: Callable[[], float] = time.monotonic  # (budget) what `across` measures its waits by


def _json(text: str):
    try:
        return json.loads(text) if text.strip() else None
    except ValueError:
        return None


def live(s: Settings, env: Env) -> Settings:
    """`s` with the firewall's settings as the last apply used them (tvgw-apply's settings.applied). The
    probe judges the gateway as it is. The settings file may already say something else: an edit nobody
    applied yet, or the file of the very apply the probe is asked to stand before, which is about to move
    the TV to another uplink; judged by that file, a working gateway would read as broken. Without the
    record (nothing applied since boot) `s` stands, and the probe finds no rules of its own."""
    try:
        used = config.parse_conf(env.read(env.applied))
    except ValueError:
        return s
    changes = {config.CONF_KEYS[k]: used[k] for k in LIVE_KEYS if used.get(k)}
    return replace(s, **changes) if changes else s


def applied_clock(env: Env) -> str:
    """(ports) The clock port as the last apply built it (CLOCK_USED_KEY in settings.applied): any, none or
    resolved; any without the record, as an apply from before the key had it."""
    try:
        used = config.parse_conf(env.read(env.applied))
    except ValueError:
        return "any"
    value = used.get(CLOCK_USED_KEY, "any")
    return value if value in ("any", "resolved", "none") else "any"


def read_uplink(s: Settings, env: Env) -> Uplink:
    """The gateway's own reading of its uplink: the interface the TV leaves by exists, has carrier and an
    IPv4 address, and in vpn mode the home network's interface under the tunnel has carrier too."""

    def exists(dev: str) -> bool:
        return env.read(f"/proc/sys/net/ipv4/conf/{dev}/forwarding") != ""

    out_if = config.uplink_interface(s, exists)
    for dev in dict.fromkeys((out_if, s.wan_if)):
        if not exists(dev):
            return Uplink(False, f"the uplink is down: {dev} does not exist")
        if env.read(f"/sys/class/net/{dev}/carrier").strip() != "1":
            return Uplink(False, f"the uplink is down: {dev} has no carrier")
    links = _json(env.run(["ip", "-j", "-4", "addr", "show", "dev", out_if])[1]) or []
    for link in links if isinstance(links, list) else []:
        for a in link.get("addr_info", []) if isinstance(link, dict) else []:
            if isinstance(a, dict) and a.get("family") == "inet" and a.get("scope") == "global":
                return Uplink(True)
    return Uplink(False, f"the uplink is down: {out_if} has no IPv4 address")


def _dev(env: Env, *question: str) -> str | None:
    route = _json(env.run(["ip", "-j", "route", "get", *question])[1]) or []
    dev = route[0].get("dev") if isinstance(route, list) and route and isinstance(route[0], dict) else None
    return dev if isinstance(dev, str) and dev else None


def read_port(s: Settings, p: Plan, env: Env) -> Port:
    def exists(dev: str) -> bool:
        return env.read(f"/proc/sys/net/ipv4/conf/{dev}/forwarding") != ""

    on = all(
        env.read(path).strip() == "1"
        for path in ("/proc/sys/net/ipv4/ip_forward", f"/proc/sys/net/ipv4/conf/{s.tv_if}/forwarding")
    )
    out = _dev(env, p.wall, "from", s.tv_ip, "iif", s.tv_if)
    back = _dev(env, s.tv_ip, "from", s.gw_ip)  # as verify's gw_reply_route asks it
    inbound = env.read("/proc/sys/net/ipv4/icmp_errors_use_inbound_ifaddr").strip() not in ("", "0")
    return Port(on, out, config.uplink_interface(s, exists), back, s.tv_if, inbound)


def control(p: Plan, obs: dict, out_if: str = "", left: Callable[[], float] | None = None) -> dict[str, bool]:
    """What the gateway itself can do of what the probe could not. `path`: a target the probe had an
    address for and could not reach is reached from the gateway's own stack with the socket bound to
    `out_if`, the uplink the TV uses, and not by whatever way the gateway's own traffic takes (a VPN
    tunnel, on a gateway that has one); a socket that cannot be bound proves nothing. `resolver`: asked
    only when the resolver answered the probe nothing at all, the blocked name, which it answers from
    its lists with no upstream and no cache involved. Only what the probe failed at is tried. (budget)
    `left`, the seconds `across` has before its verdict is due: no try is given more, and none is made
    once there are none (an untried path proves nothing, as a socket that cannot be bound)."""

    def within(most: float, share: float = 1.0) -> float:
        return most if left is None else min(most, left() * share)

    did: dict[str, bool] = {}
    tried = obs.get("path") or []
    if out_if and tried and not any(t.get("tls") == "ok" for t in tried):
        did["path"] = False
        for item in tried:
            # a connect and a handshake, each up to its timeout: half of what is left each
            timeout = within(TCP_TIMEOUT, 0.5)
            if not item.get("addr") or timeout <= 0:
                continue
            state, sock = handshake(item["addr"], item["name"], timeout=timeout, device=out_if)
            if sock is not None:
                sock.close()
            if state == "ok":
                did["path"] = True
                break
    asked = obs.get("allow") or []
    silent = obs.get("blocked") is None and all(t.get("answers") is None for t in [*asked, *tried])
    name = p.block or (p.allow[0] if p.allow else None)
    if silent and name and within(DNS_TIMEOUT) > 0:
        did["resolver"] = ask(name, p.gw_ip, timeout=within(DNS_TIMEOUT)) is not None
    return did


def set_networks(listing: str) -> list[ipaddress.IPv4Network]:
    """(revert) The networks an nft set holds, from `nft -j list set`: an address, a prefix or a range
    (auto-merge writes ranges) each, plainly or inside an element with a timeout. [] for anything else."""
    doc = _json(listing)
    out: list[ipaddress.IPv4Network] = []

    def add(e) -> None:
        with contextlib.suppress(ValueError, TypeError, KeyError, IndexError):
            if isinstance(e, dict) and "elem" in e:
                add(e["elem"].get("val"))
            elif isinstance(e, str):
                out.append(ipaddress.IPv4Network(e))
            elif isinstance(e, dict) and "prefix" in e:
                out.append(ipaddress.IPv4Network(f"{e['prefix']['addr']}/{e['prefix']['len']}", strict=False))
            elif isinstance(e, dict) and "range" in e:
                low, high = (ipaddress.IPv4Address(a) for a in e["range"])
                out.extend(ipaddress.summarize_address_range(low, high))

    for obj in doc.get("nftables", []) if isinstance(doc, dict) else []:
        st = obj.get("set") if isinstance(obj, dict) else None
        for e in st.get("elem", []) if isinstance(st, dict) else []:
            add(e)
    return out


Lists = dict[str, list[ipaddress.IPv4Network]]  # (revert) each refused list's networks, by its set's name


def list_networks(env: Env) -> Lists:
    """(revert) The TV's refused address lists as the kernel holds them, one listing of each set: the DoH
    resolvers (doh4, which the daily refresh rewrites) and the owner's blocked addresses (block4)."""
    out: Lists = {}
    for name in LIST_PLAIN:
        rc, text = env.run(["nft", "-j", "list", "set", "inet", "tvgw", name])
        out[name] = set_networks(text) if rc == 0 else []
    return out


def listed_in(env: Env, addrs: list[str], before: Lists | None = None) -> dict[str, str]:
    """(revert) Each of `addrs` that is in one of the TV's refused address lists, with the list's name;
    nothing is sent anywhere, and the lists are read only when there is an address to look up. With
    `before`, the lists as they stood before an apply, an address that was in that list already is named
    `<list>:before`: a must-allow name's answer may move between two addresses of a content network, and
    one that moved onto an address listed all along is no doing of the apply."""
    found: dict[str, str] = {}
    wanted = []
    for a in dict.fromkeys(addrs):
        with contextlib.suppress(ValueError):
            wanted.append((a, ipaddress.IPv4Address(a)))
    lists = list_networks(env) if wanted else {}
    for name, nets in lists.items():
        for a, ip in wanted:
            if a not in found and any(ip in n for n in nets):
                was = before is not None and any(ip in n for n in before.get(name, []))
                found[a] = f"{name}:before" if was else name
    return found


REFUSING = ("drop", "reject")  # (revert) the verdicts that can take a packet of the TV's away


def gate_state(env: Env) -> str:
    """(revert) The address gate's table as the kernel holds it: `absent`; `counts` (no rule in it can
    refuse); `refuses` (a rule drops or rejects, or queues without `bypass`, which drops when nothing
    listens). The gate matches the TV's port alone, so no packet of the probe's ever crosses it. Listed
    terse: its sets' elements (the TV's answers and connections) are never read here."""
    rc, text = env.run(["nft", "-j", "-t", "list", "table", "inet", "tvgw_gate"])
    doc = _json(text) if rc == 0 else None
    if not isinstance(doc, dict):
        return "absent"
    for obj in doc.get("nftables", []):
        rule = obj.get("rule") if isinstance(obj, dict) else None
        for e in rule.get("expr", []) if isinstance(rule, dict) else []:
            if not isinstance(e, dict):
                continue
            if any(k in e for k in REFUSING):
                return "refuses"
            q = e.get("queue")
            if q is not None:
                flags = q.get("flags", []) if isinstance(q, dict) else []
                if "bypass" not in ([flags] if isinstance(flags, str) else flags):
                    return "refuses"
    return "counts"


def ruled_out(env: Env, addr: str) -> bool:
    """Is `addr` one the TV's rules refuse whatever the path: a DoH resolver's, a manual block's, the
    home LAN's? A target there says nothing about the path."""
    return any(
        env.run(["nft", "get", "element", "inet", "tvgw", name, f"{{ {addr} }}"])[0] == 0
        for name in ("doh4", "block4", "lan4")
    )


def path_due(env: Env, now: float | None = None) -> bool:
    """Whether the 10-minute check makes its connection out in this run: none for PATH_EVERY, or the
    last one did not pass and PATH_RETRY has gone by."""
    words = env.read(env.stamp).split()
    try:
        last, outcome = float(words[0]), words[1]
    except (IndexError, ValueError):
        return True
    age = (time.time() if now is None else now) - last
    return age < 0 or age >= (PATH_EVERY if outcome == PASS else PATH_RETRY)


def note_path(env: Env, v: Verdict) -> None:
    """Record the run for tvgw-apply (`last`: it asks for a verdict before an apply only when the last
    one passed lately), and a connection out that was made, not one that was skipped, for path_due."""
    env.write(env.last, f"{time.time():.0f} {v.verdict} {v.word or '-'}\n")
    outcome = next((s.outcome for s in v.stages if s.name == "path"), SKIPPED)
    if outcome != SKIPPED:
        env.write(env.stamp, f"{time.time():.0f} {outcome}\n")


def pair_taken(s: Settings) -> str | None:
    """Why nothing of the probe's may be made or removed: a port of the gateway's carries the pair's own
    name, so the cleanup of a leftover would take the gateway's port away. Checked before any cleanup."""
    if GW_IF in (s.tv_if, s.wan_if, s.vpn_if):
        return (
            f"an interface of the gateway is named {GW_IF}, the probe's own pair's name: nothing is touched"
        )
    return None


def not_ready(s: Settings, env: Env) -> str | None:
    """Why no packet may be sent, or None. Without the probe's chains in the loaded firewall its packets
    would be dropped by a rule of the TV's and counted there, so nothing is sent before they are seen."""
    if s.tv_probe != "on":
        return "the probe is off (TV_PROBE=off in the settings)"
    if env.euid() != 0:
        return "the probe needs root: run it with sudo"
    if pair_taken(s):
        return pair_taken(s)
    try:
        probe_ip = config.probe_side(s)
    except ValueError as e:
        return str(e)
    rc, listing = env.run(["nft", "list", "chain", "inet", "tvgw", CHAIN])
    if rc != 0 or f"ip saddr != {probe_ip} " not in listing:
        return "the loaded firewall has no rules for the probe at this address yet: run sudo tvgw-apply"
    return None


def clear(env: Env) -> None:
    """Remove the probe's namespace and pair, whoever left them: this run, or one that was killed. With
    the pair go its routes and its neighbour entry. Never raises."""
    rc, pids = env.run(["ip", "netns", "pids", env.netns])
    for pid in pids.split() if rc == 0 else []:
        with contextlib.suppress(OSError, ValueError):
            os.kill(int(pid), 9)
    env.run(["ip", "netns", "del", env.netns])
    env.run(["ip", "link", "del", GW_IF])


def leftovers(env: Env) -> bool:
    """Did a probe that was killed leave its pair or its namespace?"""
    return env.read(f"/proc/sys/net/ipv4/conf/{GW_IF}/forwarding") != "" or env.exists(
        f"/run/netns/{env.netns}"
    )


class Namespace:
    """The client's namespace and its veth pair, for one run. Nothing outside the pair changes: the
    gateway end has no address, so no service binds to it and no address notifier fires; the two routes
    name only the probe's own address, so no packet of the TV's is routed differently for them."""

    def __init__(self, s: Settings, p: Plan, env: Env):
        self.s, self.p, self.env = s, p, env

    def _do(self, *cmd: str) -> None:
        rc, _ = self.env.run(list(cmd))
        if rc != 0:
            raise RuntimeError(" ".join(cmd[:4]) + " failed")

    def clear(self) -> None:
        clear(self.env)

    def __enter__(self) -> Namespace:
        env, p, ns, proc = self.env, self.p, self.env.netns, "/proc/sys/net"
        self.clear()
        try:
            self._do("ip", "netns", "add", ns)
            self._do(
                "ip", "link", "add", GW_IF, "address", GW_MAC, "type", "veth",
                "peer", "name", NS_IF, "address", NS_MAC, "netns", ns,
            )  # fmt: skip
            env.write(f"{proc}/ipv6/conf/{GW_IF}/disable_ipv6", "1\n")
            env.write(f"{proc}/ipv4/conf/{GW_IF}/rp_filter", "1\n")
            # the pair's gateway end forwards exactly when the TV's port does: a port switched off keeps
            # the probe's packets back as it keeps the TV's
            tv_fwd = env.read(f"{proc}/ipv4/conf/{self.s.tv_if}/forwarding").strip()
            env.write(f"{proc}/ipv4/conf/{GW_IF}/forwarding", "1\n" if tv_fwd == "1" else "0\n")
            self._do("ip", "link", "set", GW_IF, "up")
            # the way back to the client, from GW_IP as the TV sees its answers come; in table 100 too,
            # where rule 60 sends what the gateway itself sends from GW_IP (design decision 49)
            route = ("ip", "route", "replace", f"{p.probe_ip}/32", "dev", GW_IF, "src", p.gw_ip)
            self._do(*route)
            # in table 100 whatever the uplink is now: harmless while rule 60 is absent, and there when an
            # apply this run stands across adds the rule
            self._do(*route, "table", "100")
            self._do("ip", "neigh", "replace", p.probe_ip, "lladdr", NS_MAC, "dev", GW_IF, "nud", "permanent")
            env.run(["ip", "netns", "exec", ns, "sysctl", "-qw", "net.ipv6.conf.all.disable_ipv6=1"])
            self._do("ip", "-n", ns, "link", "set", "lo", "up")
            self._do("ip", "-n", ns, "addr", "add", f"{p.probe_ip}/32", "dev", NS_IF)
            self._do("ip", "-n", ns, "link", "set", NS_IF, "up")
            self._do("ip", "-n", ns, "route", "add", f"{p.gw_ip}/32", "dev", NS_IF)
            self._do("ip", "-n", ns, "route", "add", "default", "via", p.gw_ip, "dev", NS_IF)
            self._do(
                "ip",
                "-n",
                ns,
                "neigh",
                "replace",
                p.gw_ip,
                "lladdr",
                GW_MAC,
                "dev",
                NS_IF,
                "nud",
                "permanent",
            )
        except BaseException:
            self.clear()
            raise
        return self

    def __exit__(self, *exc) -> None:
        self.clear()

    def client_argv(self, hold: float = 0.0, connect: bool = True) -> list[str]:
        argv = ["ip", "netns", "exec", self.env.netns, self.env.python, "-m", "tvgw.probe", "--client"]
        return [*argv, json.dumps(self.p.spec(connect)), *(["--hold", str(hold)] if hold > 0 else [])]

    def observe(self, connect: bool = True, timeout: float = CLIENT_TIMEOUT) -> dict | None:
        rc, out = self.env.run(self.client_argv(connect=connect), timeout=timeout)
        doc = _json(out.splitlines()[0]) if rc == 0 and out.strip() else None
        return doc.get("obs") if isinstance(doc, dict) and isinstance(doc.get("obs"), dict) else None


@contextlib.contextmanager
def locked(env: Env, wait: float | None = None):
    """One run at a time: the namespace and the pair have one name each. Yields None once this run holds
    the lock, else why it may not go on: another run still holds it after `wait` seconds (LOCK_WAIT when
    not given), or, as root, the lock cannot be opened. Its directory is made as tvgw-apply makes it (/run
    is emptied at every boot), and the file is opened without following a link. Until 2026-11-17 it lay in
    the world-writable /run/lock and a lock that could not be opened let the run go on without one: any
    account could hold it for ever (every run unknown) or leave a file root may not open (two runs at
    once, each removing the other's namespace). Without root nothing is opened: such a run sends and
    removes nothing (not_ready), and says so."""
    try:
        with contextlib.suppress(FileExistsError):
            os.mkdir(os.path.dirname(env.lock), 0o755)
        fd = os.open(env.lock, os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600)
    except OSError as e:
        yield f"the probe's lock cannot be opened: {e.strerror or e}" if env.euid() == 0 else None
        return
    try:
        deadline = time.monotonic() + (LOCK_WAIT if wait is None else wait)
        while True:
            try:
                fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
                break
            except OSError:
                if time.monotonic() >= deadline:
                    yield "another probe is running"
                    return
                env.sleep(0.25)
        yield None
    finally:
        os.close(fd)


def _judged(
    s: Settings,
    p: Plan,
    obs: dict | None,
    env: Env,
    held: Stage | None = None,
    before: Lists | None = None,
    left: Callable[[], float] | None = None,
) -> Verdict:
    """One observation judged with what only the gateway can read beside it. (revert) `before`: the refused
    lists as they stood before the apply this verdict follows (across). (budget) `left`: the seconds the
    gateway's own tries may take (control)."""
    if obs is None:
        return unknown("the test client did not finish")
    for item in obs.get("path") or []:  # a target the TV's rules refuse anyway is no finding about the path
        if item.get("addr") and item.get("tls") != "ok":
            item["ruled"] = ruled_out(env, item["addr"])
    # (revert) a must-allow name's address in a refused list, and whether the gate's table can refuse
    allowed = [a for t in obs.get("allow") or [] for a in t.get("answers") or [] if a != "0.0.0.0"]
    found = listed_in(env, allowed, before)
    for item in obs.get("allow") or []:
        hit = next((found[a] for a in item.get("answers") or [] if a in found), None)
        if hit and hit.endswith(":before"):
            item["listed_before"] = hit.removesuffix(":before")
        elif hit:
            item["listed"] = hit
    obs["gate"] = gate_state(env)
    port = read_port(s, p, env)
    return judge(p, obs, port, read_uplink(s, env), lambda: control(p, obs, port.out_if, left), held)


def _settled(
    s: Settings,
    p: Plan,
    ns: Namespace,
    env: Env,
    first: Verdict,
    held: Stage | None = None,
    connect: bool = True,
    before: Lists | None = None,
    left: Callable[[], float] | None = None,
) -> Verdict:
    """A failed verdict is taken once more after RETRY_PAUSE and stands only when it fails again: one
    lost packet, or a resolver's one slow answer, is not the TV's path. (budget) With `left` (across), the
    second look gets no more than the seconds left, and a failure there is no time left to take again is
    unknown, by the same rule: it failed once."""
    if first.verdict != FAIL:
        return first
    if left is not None and left() <= RETRY_PAUSE:
        return unknown(f"{first.reason}, once, and no time was left to take it again")
    env.sleep(RETRY_PAUSE)
    timeout = CLIENT_TIMEOUT if left is None else max(0.0, min(CLIENT_TIMEOUT, left()))
    return _judged(s, p, ns.observe(connect, timeout), env, held, before, left)


def run(s: Settings, profile: Profile, env: Env | None = None, connect: bool | None = True) -> Verdict:
    """One probe: make the namespace, observe, judge (twice for a failure), remove the namespace.
    `connect` says whether this run makes the connection out; None, the 10-minute check's, makes it when
    one is due (path_due). Every run that holds the lock first removes what a killed one left, whether
    or not it may then go on. Never raises an error of its own: whatever stops it is an `unknown`, which
    changes nothing anywhere; a signal that ends it (handled in main) still removes what it made."""
    env = env or Env()
    t0 = time.time()
    try:
        s = live(s, env)
        with locked(env) as busy:
            if busy:
                return unknown(busy, t0)
            why = pair_taken(s)  # first: a gateway port with the pair's name is never cleaned away
            if why is None and env.euid() == 0 and leftovers(env):
                clear(env)  # what a killed run left, even when this one may not go on
            why = why or not_ready(s, env)
            if why:
                return unknown(why, t0)
            p = plan(s, profile, applied_clock(env))
            connect = path_due(env) if connect is None else connect
            with Namespace(s, p, env) as ns:
                v = _settled(s, p, ns, env, _judged(s, p, ns.observe(connect), env), connect=connect)
            note_path(env, v)
    except Exception as e:  # a probe that breaks must change nothing but its own verdict
        v = unknown(f"the probe could not run: {type(e).__name__}: {e}"[:200], t0)
    v.t, v.ms = t0, int((time.time() - t0) * 1000)
    return v


# ---- across an apply: one namespace, one connection held, a verdict on each side ------------------------


@dataclass(frozen=True)
class Entry:
    """A conntrack entry as the held connection is followed: its id, when the kernel made it, and the packets
    it has carried from the TV's side. The id alone cannot say the entry is the same one. It is a hash the
    kernel makes of the entry's address in memory, and the next entry of a cut connection (the held
    connection picked up again at its next keep-alive) often lands in the address the old one gave up and
    so gets the same id; in CI that made the 2026-10-30 rewrite look harmless about half the time. The
    start time (nf_conntrack_timestamp, which tvgw-apply switches on) and the count (nf_conntrack_acct,
    switched on too) tell a new entry from the old one with or without each other."""

    id: str
    start: str = ""  # the `[start=...]` conntrack prints with timestamps on; '' without
    packets: int = -1  # the TV's side's packets, nf_conntrack_acct; -1 when not printed

    def same_as(self, before: Entry) -> bool:
        """Whether this entry, read after an apply, is `before`, read before it."""
        if (self.id, self.start) != (before.id, before.start):
            return False
        return self.packets < 0 or before.packets < 0 or self.packets >= before.packets


def conntrack_entry(env: Env, p: Plan, held: dict) -> Entry | None:
    """The gateway's conntrack entry for the held connection, or None (no entry, two, or no tool)."""
    rc, out = env.run(
        ["conntrack", "-L", "-p", "tcp", "-s", p.probe_ip, "-d", str(held.get("dst")),
         "--sport", str(held.get("sport")), "--dport", "443", "-o", "id,timestamp"]
    )  # fmt: skip
    lines = [ln for ln in out.splitlines() if re.search(r"\bid=\d+", ln)] if rc == 0 else []
    if len(lines) != 1:
        return None
    ident = re.search(r"\bid=(\d+)", lines[0])
    start = re.search(r"\[start=([^\]]*)\]", lines[0])
    packets = re.search(r"\bpackets=(\d+)", lines[0])  # the first count printed is the TV's side's
    assert ident is not None
    return Entry(
        ident.group(1), start.group(1).strip() if start else "", int(packets.group(1)) if packets else -1
    )


def uplink_address(s: Settings, env: Env) -> str | None:
    """The address the TV's connections are translated to, for held_stage: when it changes, the kernel
    itself ends every connection that carried it."""
    out_if = config.uplink_interface(
        s, lambda dev: env.read(f"/proc/sys/net/ipv4/conf/{dev}/forwarding") != ""
    )
    links = _json(env.run(["ip", "-j", "-4", "addr", "show", "dev", out_if])[1]) or []
    for link in links if isinstance(links, list) else []:
        for a in link.get("addr_info", []) if isinstance(link, dict) else []:
            if isinstance(a, dict) and a.get("scope") == "global" and a.get("local"):
                return str(a["local"])
    return None


def held_stage(before: Entry | None, after: Entry | None, peer: str | None, steady: bool = True) -> Stage:
    """The held connection after the re-apply. Its conntrack entry gone or replaced (Entry.same_as), while
    the far end never closed it, is the 2026-10-30 fault: the apply cut a live connection. Not `steady`
    (the uplink lost its carrier or changed its address meanwhile): the kernel ends those connections
    itself, and that is no apply's doing. Only the far end's own goodbye (`closed`) is skipped: a reset is
    what the client sees when new rules reject the old flow as much as when the far end resets it, and a
    client that said nothing (None) said nothing either way, so both are unknown. Until 2026-11-17 both
    were skipped as the far end's goodbye, and a loud cut left the verdict a pass."""
    if before is None:
        return Stage("held", SKIPPED, "no connection could be held and followed")
    if after is not None and after.same_as(before):
        return Stage("held", PASS)
    if not steady:
        return Stage("held", SKIPPED, "the uplink went down or changed its address meanwhile")
    if peer == "closed":  # nothing to judge: the far end's own goodbye removes the entry too
        return Stage("held", SKIPPED, "the far end closed the held connection first")
    if peer == "reset":
        why = "the held connection was reset across the apply; who reset it cannot be told"
        return Stage("held", UNKNOWN, why)
    if peer != "open":
        return Stage("held", UNKNOWN, "the test client did not answer")
    return Stage("held", FAIL, "the apply cut a live connection: its conntrack entry was destroyed")


def _line(v: Verdict) -> str:
    """A verdict as tvgw-apply reads it: `<verdict> <the deciding stage or ->` on the first line, which
    the shell reads with one `read`, then the whole of it as JSON."""
    return f"{v.verdict} {v.word or '-'}\n" + json.dumps(v.as_dict(), sort_keys=True) + "\n"


def across(s: Settings, profile: Profile, directory: str, env: Env | None = None) -> int:
    """`tvgw probe --across DIR`, what tvgw-apply brackets itself with. Writes DIR/pre, the verdict
    before; waits for DIR/go (the apply is done) or DIR/abort; then writes DIR/post, the verdict after,
    with the held connection as one more stage. Each file is written whole (renamed into place). DIR/pid,
    when the apply wrote it, is the apply's own process: once it is gone the wait ends, so an apply that
    was killed does not leave the namespace and its lock held. (budget) DIR/post is out within BUDGET
    seconds of `go`, with what is known by then: before 2026-11-17 two slow observations and the gateway's
    tries beside each could take it past the apply's wait, where it read as no verdict at all."""
    env = env or Env()

    def publish(name: str, v: Verdict) -> None:
        tmp = os.path.join(directory, f".{name}.tmp")
        with open(tmp, "w", encoding="utf-8") as fh:
            fh.write(_line(v))
        os.replace(tmp, os.path.join(directory, name))

    t0 = time.time()
    proc = None
    conf = s  # the settings file's: the apply's own. Each verdict is judged by what is applied at its time
    try:
        s = live(conf, env)
        with locked(env, wait=0.0) as busy:  # an apply never waits for another probe to finish
            if busy:
                publish("pre", unknown(busy, t0))
                return EXIT[UNKNOWN]
            why = pair_taken(s)  # first: a gateway port with the pair's name is never cleaned away
            if why is None and env.euid() == 0 and leftovers(env):
                clear(env)  # what a killed run left, even when this one may not go on
            why = why or not_ready(s, env)
            if why:
                publish("pre", unknown(why, t0))
                return EXIT[UNKNOWN]
            p = plan(s, profile, applied_clock(env))
            with Namespace(s, p, env) as ns:
                proc = subprocess.Popen(
                    ns.client_argv(hold=HOLD_MAX + CLIENT_TIMEOUT),
                    stdin=subprocess.PIPE, stdout=subprocess.PIPE, text=True, encoding="utf-8",
                )  # fmt: skip
                first = _client_line(proc, CLIENT_TIMEOUT) or {}
                obs = first.get("obs") if isinstance(first.get("obs"), dict) else None
                # taken once: a failure before the apply only means there is nothing to go back to
                pre = _judged(s, p, obs, env)
                # (revert) the refused lists before the apply: after it, only an address it listed counts
                lists = list_networks(env)
                held = first.get("held") if isinstance(first.get("held"), dict) else None
                before = conntrack_entry(env, p, held) if held else None
                address = uplink_address(s, env)
                pre.t, pre.ms = t0, int((time.time() - t0) * 1000)
                publish("pre", pre)
                note_path(env, pre)
                deadline = env.clock() + HOLD_MAX
                applying = _pid(env.read(os.path.join(directory, "pid")))
                while not os.path.exists(os.path.join(directory, "go")):
                    gone = applying is not None and not _alive(applying)  # the apply was killed
                    if gone or os.path.exists(os.path.join(directory, "abort")) or env.clock() >= deadline:
                        return EXIT[UNKNOWN]
                    env.sleep(0.1)
                t1 = time.time()
                end = env.clock() + BUDGET  # (budget) every wait from here on gets what is left of it

                def left() -> float:
                    return end - env.clock()

                # the apply is done. The held connection is followed for a cut; it cannot stand for the
                # way out, since a connection made before the apply passes rules a new one would meet
                if before is not None:
                    env.sleep(HOLD_SETTLE)
                after = conntrack_entry(env, p, held) if held and before is not None else None
                was, s = s, live(conf, env)
                was_p, p = p, plan(s, profile, applied_clock(env))
                if (p.probe_ip, p.gw_ip, s.tv_if) != (was_p.probe_ip, was_p.gw_ip, was.tv_if):
                    # the namespace was made for the old ones: nothing made before can judge the new
                    publish("post", unknown("the apply changed the probe's address or the TV's port"))
                    return EXIT[UNKNOWN]
                ns.s, ns.p = s, p
                assert proc.stdin is not None
                proc.stdin.write(json.dumps({"spec": p.spec()}) + "\n")
                proc.stdin.flush()
                second = _client_line(proc, max(0.0, min(CLIENT_TIMEOUT, left()))) or {}
                obs = second.get("obs") if isinstance(second.get("obs"), dict) else None
                steady = read_uplink(s, env).up and uplink_address(s, env) == address
                stage = held_stage(before, after, second.get("held_state"), steady)
                post = _judged(s, p, obs, env, stage, lists, left)
                post = _settled(s, p, ns, env, post, stage, before=lists, left=left)
                note_path(env, post)
                post.t, post.ms = t1, int((time.time() - t1) * 1000)
                publish("post", post)
                return EXIT[post.verdict]
    except Exception as e:  # as in run(): nothing but the verdict
        name = "post" if os.path.exists(os.path.join(directory, "pre")) else "pre"
        with contextlib.suppress(OSError):
            publish(name, unknown(f"the probe could not run: {type(e).__name__}: {e}"[:200]))
        return EXIT[UNKNOWN]
    finally:
        if proc is not None:
            with contextlib.suppress(OSError):
                proc.kill()
            with contextlib.suppress(OSError, subprocess.TimeoutExpired):
                proc.communicate(timeout=5)


def _pid(text: str) -> int | None:
    return int(text) if text.strip().isdigit() and int(text) > 1 else None


def _alive(pid: int) -> bool:
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return False
    except OSError:
        return True
    return True


def _client_line(proc: subprocess.Popen, timeout: float) -> dict | None:
    """The client's next line of JSON, or None when it does not come in time."""
    assert proc.stdout is not None
    ready, _, _ = select.select([proc.stdout], [], [], timeout)
    doc = _json(proc.stdout.readline()) if ready else None
    return doc if isinstance(doc, dict) else None


# ---- what a person reads ------------------------------------------------------------------------------

STAGE_PLAIN = {
    "probe": "the test itself",
    "port": "the TV's port forwards; the kernel routes the TV out by the uplink and back by its port (read)",
    "lookup": "every name the TV needs gets an address from the filter (nothing connects to one)",
    "path": "a secure connection out to a neutral server, and back, completes",
    "blocked": "a blocked name gets the filter's blocked answer",
    "dot": "an encrypted lookup (DNS over TLS) is refused",
    "quic": "QUIC is refused",
    "redirect": "a lookup aimed at another resolver is answered by the gateway's filter",
    "held": "a connection held open across the change is still the same connection",
    # (ports) design decision 71
    "ports": (
        "the ports the TV uses pass (the web on 80 and 443, the clock on 123 unless it is closed), and an"
        " unusual port is refused or let through as STRICT_PORTS says"
    ),
    # (revert)
    "lists": "no name the TV needs got an address the gateway refuses (the DoH list, your blocked addresses)",
    "adtech": "a connection to LG's ad and content-recognition ports is refused",
    "gate": "the address gate only counts: it refuses nothing the test cannot cross",
}
# A pass says what was tested and no more (the module's docstring lists what it does not say): the test
# client is not the TV, and the TV's cable, lease and own address are not in it.
VERDICT_PLAIN = {
    PASS: "every step passed for a test client beside the TV's port (the TV itself is not tested)",
    FAIL: "a step failed: the gateway's path for the TV is broken there",
    UNKNOWN: "could not tell",
}
_MARK = {PASS: "OK  ", FAIL: "FAIL", UNKNOWN: "??  ", SKIPPED: "--  "}


def lines(v: Verdict) -> list[str]:
    """The verdict in plain words: one line a stage, then the verdict."""
    out = []
    for s in v.stages:
        out.append(
            f"{_MARK[s.outcome]} {STAGE_PLAIN.get(s.name, s.name)}" + (f": {s.detail}" if s.detail else "")
        )
    out.append(f"tvgw probe: {v.verdict}: {VERDICT_PLAIN[v.verdict]}" + (f" ({v.ms} ms)" if v.ms else ""))
    return out


def _ended(signum, _frame) -> None:
    """SIGTERM (an apply that gave up waiting, `timeout`, a unit being stopped): leave as an error does,
    through every `with`, so the namespace and the pair are removed on the way out."""
    raise SystemExit(128 + signum)


def unwinding(fn: Callable[..., Verdict], *args, **kwargs) -> Verdict:
    """`fn(*args, **kwargs)` with SIGTERM unwinding it as `tvgw probe` has it (_ended), and the caller's own
    handler back afterwards. `tvgw verify --record` runs the probe in its own process; until 2026-11-17 a
    unit stop or its timeout ended Python where it stood there, and the pair, its routes and the
    namespace stayed until the next run."""
    was = signal.signal(signal.SIGTERM, _ended)
    try:
        return fn(*args, **kwargs)
    finally:
        signal.signal(signal.SIGTERM, signal.SIG_DFL if was is None else was)


def main(
    s: Settings, profile: Profile, as_json: bool = False, directory: str | None = None, netns: str = ""
) -> int:
    signal.signal(signal.SIGTERM, _ended)  # SIGINT already raises, and unwinds the same way
    env = Env(netns=netns or NETNS)
    if directory:
        return across(s, profile, directory, env)
    v = run(s, profile, env)
    if as_json:
        print(json.dumps(v.as_dict(), indent=1))
    else:
        print("\n".join(lines(v)))
    return EXIT[v.verdict]


if __name__ == "__main__":
    if len(sys.argv) >= 3 and sys.argv[1] == "--client":
        signal.signal(signal.SIGTERM, _ended)
        sys.exit(client_main(sys.argv[2:]))
    sys.exit("tvgw.probe: this module is the probe's client half; run `tvgw probe`")
