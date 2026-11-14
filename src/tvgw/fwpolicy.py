"""(fwcheck) What the firewall promises, one promise at a time (design decision 86).

`tvgw.fwcheck` works out where every class of packets ends. This file says where each must end, in
words first and then as two small functions: the packets a promise speaks of, and what must be true of
their end. It is written to be read beside the design decisions, and it restates the policy on purpose:
no value here is taken from the rules it judges. The ports, the private ranges and LG's addresses are
written out again, and the two lists are read from the files the apply was given, so a rule that drifts
from any of them is caught, not followed.

A promise speaks of packets by field: `{"proto": is_("udp"), "dport": is_(443)}`. A class the walk
ended without reading a field stands for every value of it, so the promise speaks of that class too.
Where one promise needs fields to vary together it gives several such descriptions. Every test says
which values it names (`FieldTest`), and the search tries each of them: a port the rules have dropped from a
wall is then a class of its own, which the wall's promise finds forwarded.

`RELATIONS` are the promises between two settings, of every packet that arrives on the TV's port: a value
that only counts changes no packet's end, and a wall switched on lets nothing through that it refused
when off.
"""

from __future__ import annotations

from collections.abc import Callable, Iterable, Iterator, Mapping, Sequence
from dataclasses import dataclass
from functools import cached_property

from tvgw.fwcheck import (
    ACCEPT,
    FORWARD,
    INPUT,
    REFUSALS,
    Need,
    Outcome,
    Ruleset,
    domain,
    merged,
    prefix,
    within,
)
from tvgw.probe import GW_IF as PROBE_IF

# restated here, never read from the rules
PRIVATE = tuple(
    prefix(n) for n in ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "169.254.0.0/16", "100.64.0.0/10")
)
NOWHERE = (*PRIVATE, *(prefix(n) for n in ("0.0.0.0/8", "127.0.0.0/8", "224.0.0.0/3")))  # not the internet
USUAL_PORTS = {
    "tcp": (80, 443),
    "udp": (123, 443),
}  # the web's and the clock's; probe.USUAL_PORTS says the same
ENCRYPTED_DNS = (784, 853, 8853)  # DNS over TLS and over QUIC, and its drafts
SMALL_PING = 128  # bytes: an echo request that carries no tunnel
VPN_PORTS = ("tun0", "wgpia0")  # the tunnel's two names; a third comes from VPN_IF
LG = "lg-webos"
LG_FALLBACK = (prefix("156.147.69.32")[0], 8080)  # the firmware updater's plain-HTTP fallback
LG_ADTECH = (4001, 4431, 4445, 4447, 8180, 8883)  # ACR fingerprints, Alphonso, LG ads (decision 45)


@dataclass(frozen=True)
class FieldTest:
    """A test of one field, and the values it names. The search for classes tries every value a promise
    names beside those the rules name: a rule that has drifted from a value restated here then meets a
    class of its own, where a stand-in for "every other value" would have hidden it."""

    fits: Callable[[object], bool]
    names: tuple = ()

    def __call__(self, value) -> bool:
        return self.fits(value)


def is_(*values) -> FieldTest:
    return FieldTest(lambda v: v in values, values)


def not_(*values) -> FieldTest:
    return FieldTest(lambda v: v not in values, values)


def inside(prefixes) -> FieldTest:
    return FieldTest(lambda v: within(v, prefixes), tuple(prefixes))


def outside(prefixes) -> FieldTest:
    return FieldTest(lambda v: not within(v, prefixes), tuple(prefixes))


def where(fits: Callable[[object], bool], *names) -> FieldTest:
    """A test of its own, with the values it tells apart."""
    return FieldTest(fits, names)


@dataclass(frozen=True)
class Site:
    """Who is who on one gateway: its settings as the apply recorded them, where the TV's traffic leaves,
    the gateway's own addresses, and the two lists the apply loaded."""

    settings: Mapping[str, str]  # settings.applied
    uplink_if: str
    local: tuple[tuple[int, int], ...]
    doh: tuple[tuple[int, int], ...]
    block: tuple[tuple[int, int], ...]

    @classmethod
    def of(cls, settings: Mapping[str, str], uplink_if: str, local: Iterable[str], doh=(), block=()) -> Site:
        """`doh` and `block` are the addresses of doh4.txt and block4.txt, as the apply was given them."""
        nets = lambda addresses: tuple(prefix(a) for a in addresses)  # noqa: E731
        return cls(settings, uplink_if, nets(local), nets(doh), nets(block))

    def on(self, key: str, value: str = "yes") -> bool:
        return self.settings.get(key) == value

    @property
    def tv_if(self) -> str:
        return self.settings["TV_IF"]

    @cached_property
    def tv_net(self) -> tuple[int, int]:
        return prefix(self.settings["TV_NET"])

    @cached_property
    def gw(self) -> int:
        return prefix(self.settings["GW_IP"])[0]

    @cached_property
    def pinned(self) -> int | None:
        """The one address that may forward, once the TV's MAC and address are both known."""
        both = self.settings.get("TV_MAC") and self.settings.get("TV_IP")
        return prefix(self.settings["TV_IP"])[0] if both else None

    @cached_property
    def probe_ip(self) -> int | None:
        return prefix(self.settings["TV_PROBE_IP"])[0] if self.on("TV_PROBE", "on") else None

    @cached_property
    def vpn_ports(self) -> tuple[str, ...]:
        named = self.settings.get("VPN_IF", "auto")
        return (*VPN_PORTS, *(() if named in ("auto", *VPN_PORTS) else (named,)))

    def is_tv(self, address: int) -> bool:
        """An address the TV may send from: its own when it is pinned, else any of its subnet's but the
        gateway's and the probe's."""
        if self.pinned is not None:
            return address == self.pinned
        return within(address, [self.tv_net]) and address not in (self.gw, self.probe_ip)

    def public(self, address: int) -> bool:
        """An internet address the filter has nothing against."""
        return not within(address, (*NOWHERE, *self.local, *self.doh, *self.block))

    @property
    def internet(self) -> FieldTest:
        return where(self.public, *NOWHERE, *self.local, *self.doh, *self.block)

    # ---- the packets most promises speak of ------------------------------------------------------------
    def from_tv(self, **more: FieldTest) -> dict[str, FieldTest]:
        """A packet of the TV's, IPv4, on its own port and from its own address."""
        own = where(self.is_tv, self.tv_net, self.gw, self.pinned, self.probe_ip)
        return {"iif": is_(self.tv_if), "family": is_(4), "saddr": own, **more}

    def leaving(self, **more: FieldTest) -> dict[str, FieldTest]:
        """The first packet of a connection the TV opens to somewhere beyond the gateway, routed to the
        uplink it is meant to use."""
        away = {"ct": is_("new"), "oif": is_(self.uplink_if), "daddr": outside(self.local)}
        return self.from_tv(**{**away, **more})


@dataclass(frozen=True)
class Promise:
    name: str
    decision: int
    says: str
    of: Callable[
        [Site], Sequence[Mapping[str, FieldTest]]
    ]  # the packets it speaks of; none where it does not apply
    holds: Callable[[Outcome, Mapping, Site], bool]


def refused(outcome: Outcome, known: Mapping, site: Site) -> bool:
    return outcome.verdict in REFUSALS


def not_forwarded(outcome: Outcome, known: Mapping, site: Site) -> bool:
    """It did not leave: refused, or taken by the gateway itself, as every lookup is wherever it was aimed."""
    return not forwarded(outcome, known, site)


def forwarded(outcome: Outcome, known: Mapping, site: Site) -> bool:
    return outcome.verdict == ACCEPT and outcome.hook == FORWARD


def forwarded_within_its_rate(outcome: Outcome, known: Mapping, site: Site) -> bool:
    over = any(key[0] == "limit" and not answer for key, answer in known.items() if isinstance(key, tuple))
    return over or forwarded(outcome, known, site)


def delivered_within_its_rate(outcome: Outcome, known: Mapping, site: Site) -> bool:
    over = any(key[0] == "limit" and not answer for key, answer in known.items() if isinstance(key, tuple))
    return over or (outcome.verdict == ACCEPT and outcome.hook == INPUT)


def at_gateway(site: Site) -> dict[str, FieldTest]:
    """A packet from the TV's subnet, on the TV's port, for the gateway's own address there."""
    return {"iif": is_(site.tv_if), "family": is_(4), "saddr": inside([site.tv_net]), "daddr": is_(site.gw)}


def answered_by_the_gateway(outcome: Outcome, known: Mapping, site: Site) -> bool:
    return outcome.verdict == ACCEPT and outcome.hook == INPUT and outcome.daddr == site.gw


def counted(outcome: Outcome, known: Mapping, site: Site) -> bool:
    return outcome.verdict == ACCEPT or (
        outcome.by is not None and outcome.by.counted and bool(outcome.by.comment)
    )


def only_its_own_services(outcome: Outcome, known: Mapping, site: Site) -> bool:
    """What the TV may reach on the gateway itself: DHCP, and at the gateway's TV-side address DNS, the
    block page's two ports and a ping."""
    if outcome.verdict != ACCEPT:
        return True
    proto, dport = known.get("proto"), known.get("dport")
    if proto == "udp" and known.get("sport") == 68 and dport == 67:
        return True
    at_gateway = outcome.daddr == site.gw
    web = proto == "tcp" and dport in (80, 443)
    dns = proto in ("tcp", "udp") and dport == 53
    return at_gateway and (web or dns or (proto == "icmp" and known.get("echo") is True))


def _strict(site: Site) -> Sequence[Mapping[str, FieldTest]]:
    if not site.on("STRICT_PORTS"):
        return ()
    tcp, udp = USUAL_PORTS["tcp"], USUAL_PORTS["udp"]
    if site.settings.get("PROFILE") != LG:
        return (
            site.leaving(proto=is_("tcp"), dport=not_(*tcp)),
            site.leaving(proto=is_("udp"), dport=not_(*udp)),
        )
    address, port = LG_FALLBACK
    return (
        site.leaving(proto=is_("tcp"), dport=not_(*tcp, port)),
        site.leaving(
            proto=is_("tcp"),
            dport=is_(port),
            daddr=where(lambda a: a != address and not within(a, site.local), address, *site.local),
        ),
        site.leaving(proto=is_("udp"), dport=not_(*udp)),
    )


def _open_connections(site: Site) -> Sequence[Mapping[str, FieldTest]]:
    flowing = {"ct": is_("established", "related"), "oif": is_(site.uplink_if), "daddr": site.internet}
    if not site.on("CLOCK_PORT_USED", "resolved"):
        return (site.from_tv(**flowing),)
    return (
        site.from_tv(**flowing, proto=not_("udp")),
        site.from_tv(**flowing, proto=is_("udp"), dport=not_(123)),
    )


def _when(condition: Callable[[Site], bool], of: Callable[[Site], Mapping[str, FieldTest]]):
    return lambda site: (of(site),) if condition(site) else ()


def _always(of: Callable[[Site], Mapping[str, FieldTest]]):
    return lambda site: (of(site),)


PROMISES: tuple[Promise, ...] = (
    Promise(
        "no IPv6",
        2,
        "Nothing the TV sends over IPv6 gets past its port.",
        _always(lambda s: {"iif": is_(s.tv_if), "family": is_(6)}),
        refused,
    ),
    Promise(
        "its own source",
        2,
        "A packet on the TV's port from an address outside the TV's subnet goes nowhere.",
        _always(
            lambda s: {
                "iif": is_(s.tv_if),
                "family": is_(4),
                "saddr": where(lambda a: a != 0 and not within(a, [s.tv_net]), 0, s.tv_net),
            }
        ),
        refused,
    ),
    Promise(
        "the pin",
        42,
        "Once the TV's address is pinned, no new connection from any other address on its port is forwarded.",
        _when(
            lambda s: s.pinned is not None,
            lambda s: {
                "iif": is_(s.tv_if),
                "family": is_(4),
                "saddr": not_(s.pinned),
                "daddr": outside(s.local),
                "ct": not_("established", "related"),
            },
        ),
        not_forwarded,
    ),
    Promise(
        "off its port",
        2,
        "The TV's subnet arriving on any other port is not forwarded, the probe's own port aside.",
        _always(
            lambda s: {
                "iif": not_(s.tv_if, PROBE_IF),
                "oif": not_(PROBE_IF),  # what leaves by the probe's port is the probe's own conversation
                "family": is_(4),
                "saddr": inside([s.tv_net]),
                "daddr": outside(s.local),
            }
        ),
        not_forwarded,
    ),
    Promise(
        "one way out",
        1,
        "A connection the TV opens leaves by the chosen uplink or not at all.",
        _always(lambda s: s.leaving(oif=not_(s.uplink_if))),
        not_forwarded,
    ),
    Promise(
        "the home network",
        2,
        "The TV opens no connection to a private, link-local or shared address.",
        _always(
            lambda s: s.leaving(
                daddr=where(lambda a: within(a, PRIVATE) and not within(a, s.local), *PRIVATE, *s.local)
            )
        ),
        not_forwarded,
    ),
    Promise(
        "nothing in",
        2,
        "Nothing from outside opens a connection to the TV's subnet, the probe's own port aside.",
        _always(
            lambda s: {
                "iif": not_(s.tv_if, PROBE_IF),
                "oif": is_(s.tv_if),
                "family": is_(4),
                "ct": is_("new"),
                "daddr": where(
                    lambda a: within(a, [s.tv_net]) and not within(a, s.local), s.tv_net, *s.local
                ),
            }
        ),
        not_forwarded,
    ),
    Promise(
        "lookups come home",
        2,
        "A lookup the TV aims anywhere, over UDP or TCP, is answered by the gateway's filter.",
        _always(lambda s: s.from_tv(ct=is_("new"), proto=is_("tcp", "udp"), dport=is_(53))),
        answered_by_the_gateway,
    ),
    Promise(
        "no encrypted DNS",
        2,
        "DNS over TLS and DNS over QUIC are refused.",
        _always(lambda s: s.leaving(proto=is_("tcp", "udp"), dport=is_(*ENCRYPTED_DNS))),
        not_forwarded,
    ),
    Promise(
        "no DoH resolver",
        2,
        "Port 443 of every listed DoH resolver is refused.",
        _when(
            lambda s: bool(s.doh), lambda s: s.leaving(proto=is_("tcp"), dport=is_(443), daddr=inside(s.doh))
        ),
        not_forwarded,
    ),
    Promise(
        "manual blocks",
        65,
        "An address in block4.txt is refused on every port.",
        _when(lambda s: bool(s.block), lambda s: s.leaving(daddr=inside(s.block))),
        not_forwarded,
    ),
    Promise(
        "no QUIC",
        3,
        "With BLOCK_QUIC=yes, UDP 443 is refused, so every TLS hello is one the capture can read.",
        _when(lambda s: s.on("BLOCK_QUIC"), lambda s: s.leaving(proto=is_("udp"), dport=is_(443))),
        not_forwarded,
    ),
    Promise(
        "no tunnels",
        2,
        "Only TCP, UDP and ICMP leave.",
        _always(lambda s: s.leaving(proto=not_("tcp", "udp", "icmp"))),
        not_forwarded,
    ),
    Promise(
        "small pings only",
        2,
        "Of ICMP, only an echo request too small to carry a tunnel leaves.",
        lambda s: (
            s.leaving(proto=is_("icmp"), echo=is_(False)),
            s.leaving(proto=is_("icmp"), length=where(lambda n: n > SMALL_PING, SMALL_PING)),
        ),
        not_forwarded,
    ),
    Promise(
        "the ad-tech ports",
        45,
        "With the port wall on, an LG TV reaches none of LG's ad-tech ports.",
        _when(
            lambda s: s.on("ADTECH_PORT_WALL") and s.settings.get("PROFILE") == LG,
            lambda s: s.leaving(proto=is_("tcp"), dport=is_(*LG_ADTECH)),
        ),
        not_forwarded,
    ),
    Promise(
        "strict ports",
        17,
        "With STRICT_PORTS=yes nothing leaves but the web's ports, the clock's and, for an LG TV, the"
        " firmware fallback.",
        _strict,
        not_forwarded,
    ),
    Promise(
        "the clock closed",
        71,
        "With the clock port closed, UDP 123 is refused.",
        _when(
            lambda s: s.on("CLOCK_PORT_USED", "none"), lambda s: s.leaving(proto=is_("udp"), dport=is_(123))
        ),
        not_forwarded,
    ),
    Promise(
        "the web stays open",
        17,
        "TCP 80 and 443 to an internet address the filter has nothing against pass, whatever the settings.",
        _always(lambda s: s.leaving(proto=is_("tcp"), dport=is_(*USUAL_PORTS["tcp"]), daddr=s.internet)),
        forwarded,
    ),
    Promise(
        "the clock stays open",
        71,
        "With the clock port open to any server, UDP 123 passes.",
        _when(
            lambda s: s.on("CLOCK_PORT_USED", "any"),
            lambda s: s.leaving(proto=is_("udp"), dport=is_(123), daddr=s.internet),
        ),
        forwarded,
    ),
    Promise(
        "a ping passes",
        2,
        "A small echo request to the internet passes while its rate has room.",
        _always(
            lambda s: s.leaving(
                proto=is_("icmp"),
                echo=is_(True),
                length=where(lambda n: n <= SMALL_PING, SMALL_PING),
                daddr=s.internet,
            )
        ),
        forwarded_within_its_rate,
    ),
    Promise(
        "the firmware fallback",
        45,
        "An LG TV reaches its updater's fallback address on TCP 8080, whatever the port walls say.",
        _when(
            lambda s: s.settings.get("PROFILE") == LG,
            lambda s: s.leaving(proto=is_("tcp"), dport=is_(LG_FALLBACK[1]), daddr=is_(LG_FALLBACK[0])),
        ),
        forwarded,
    ),
    Promise(
        "a connection keeps flowing",
        86,
        "A packet of a connection already open to the internet passes: no port wall cuts it later. The"
        " clock port narrowed to looked-up servers is the one exception: it judges every packet.",
        _open_connections,
        forwarded,
    ),
    Promise(
        "nothing invalid",
        86,
        "A packet of the TV's that belongs to no connection the gateway knows does not leave.",
        _always(lambda s: s.from_tv(ct=is_("invalid"), daddr=outside(s.local))),
        not_forwarded,
    ),
    Promise(
        "nothing in from the tunnel",
        44,
        "Nothing that arrives by a VPN port opens a connection to the gateway itself.",
        _always(
            lambda s: {"iif": is_(*s.vpn_ports), "family": is_(4), "ct": is_("new"), "daddr": inside(s.local)}
        ),
        refused,
    ),
    Promise(
        "the TV gets its lease",
        42,
        "A DHCP request on the TV's port reaches the gateway, from the TV's subnet or from no address yet.",
        _always(
            lambda s: {
                "iif": is_(s.tv_if),
                "family": is_(4),
                "saddr": where(lambda a: a == 0 or within(a, [s.tv_net]), 0, s.tv_net),
                "daddr": inside(s.local),
                "proto": is_("udp"),
                "sport": is_(68),
                "dport": is_(67),
            }
        ),
        delivered_within_its_rate,
    ),
    Promise(
        "the gateway answers the TV",
        42,
        "From its subnet the TV reaches the block page's two ports and a ping at the gateway's address,"
        " and the answers to what it began there.",
        lambda s: (
            {**at_gateway(s), "ct": is_("new"), "proto": is_("tcp"), "dport": is_(80, 443)},
            {**at_gateway(s), "ct": is_("new"), "proto": is_("icmp"), "echo": is_(True)},
            {**at_gateway(s), "ct": is_("established", "related")},
        ),
        delivered_within_its_rate,
    ),
    Promise(
        "the gateway's other ports",
        44,
        "What reaches the gateway itself by a port that is neither the TV's nor a tunnel's is not this"
        " firewall's to refuse.",
        _always(
            lambda s: {
                "iif": not_(s.tv_if, PROBE_IF, *s.vpn_ports),
                "family": is_(4),
                "saddr": outside([s.tv_net]),
                "daddr": inside(s.local),
            }
        ),
        delivered_within_its_rate,
    ),
    Promise(
        "the gateway's own services",
        42,
        "On the gateway itself the TV reaches DHCP, DNS, the block page and a ping, and nothing else.",
        _always(
            lambda s: {"iif": is_(s.tv_if), "family": is_(4), "ct": is_("new"), "daddr": inside(s.local)}
        ),
        only_its_own_services,
    ),
    Promise(
        "the Pi's other forwarding",
        2,
        "What the gateway forwards between its other ports, from no address of the TV's, passes untouched.",
        _always(
            lambda s: {
                "iif": not_(s.tv_if, PROBE_IF),
                "oif": not_(s.tv_if, PROBE_IF),
                "saddr": outside([s.tv_net]),
                "daddr": outside(s.local),
                "delivered6": is_(False),
            }
        ),
        forwarded,
    ),
    Promise(
        "every refusal is counted",
        13,
        "A packet of the TV's is never refused by a rule without a counter and a name.",
        _always(lambda s: {"iif": is_(s.tv_if)}),
        counted,
    ),
)


def speaks_of(description: Mapping[str, FieldTest], known: Mapping) -> bool:
    """Whether a class may hold a packet a description fits: every field the walk read fits it."""
    return all(test(known[name]) for name, test in description.items() if name in known)


KINDS = {"iif": "if", "oif": "if", "saddr": "net", "daddr": "net"}  # a field -> its kind in `constants`


def named(descriptions: Iterable[Mapping[str, FieldTest]]) -> dict[str, set]:
    """Every value the descriptions name, by kind, as `Ruleset.constants` gives the rules'. A test that
    names nothing must be a `FieldTest` all the same: a bare function would hide what it tells apart."""
    found: dict[str, set] = {kind: set() for kind in ("if", "net", "sport", "dport", "proto", "length")}
    for description in descriptions:
        for name, test in description.items():
            if not isinstance(test, FieldTest):
                raise TypeError(f"the test of {name} does not say which values it names")
            kind = KINDS.get(name, name)
            if kind == "net":
                found[kind] |= {
                    (v, 0xFFFFFFFF) if isinstance(v, int) else v for v in test.names if v is not None
                }
            elif kind in found:
                found[kind] |= {v for v in test.names if v is not None}
    return found


def restated(site: Site) -> dict[str, set]:
    """Every value the promises name at one site: what a search must try beside what the rules name."""
    return named(d for p in PROMISES for d in p.of(site))


def judged(site: Site, rules: Ruleset, fixed: Mapping | None = None, promises=None) -> Iterator[tuple]:
    """(promise, what the walk read, its outcome, whether the promise is kept) for every class of packets
    of `rules` (narrowed to `fixed`) and each promise that speaks of it. The classes are found as
    `fwcheck.explore` finds them, over every value the rules or the promises name, and the descriptions
    that can still fit are narrowed with each field a walk fixes, so a class is never held against a
    promise that one of its fields already ruled out."""
    start = dict(fixed or {})
    live = [(p, d) for p in (PROMISES if promises is None else promises) for d in p.of(site)]
    found, domains = merged(rules.constants(), named(d for _, d in live)), {}
    todo = [(start, [(p, d) for p, d in live if speaks_of(d, start)])]
    while todo:
        known, fitting = todo.pop()
        try:
            outcome = rules.walk(known)
        except Need as need:
            what = need.what
            if what not in domains:
                domains[what] = domain(what, found)
            for value in reversed(domains[what]):
                still = [(p, d) for p, d in fitting if what not in d or d[what](value)]
                todo.append(({**known, what: value}, still))
            continue
        for promise in dict.fromkeys(p for p, _ in fitting):
            yield promise, known, outcome, promise.holds(outcome, known, site)


def broken(site: Site, rules: Ruleset, fixed: Mapping | None = None, promises=None) -> Iterator[tuple]:
    """(promise, what the walk read, its outcome) for each class a promise speaks of that ends otherwise."""
    return ((p, known, end) for p, known, end, kept in judged(site, rules, fixed, promises) if not kept)


@dataclass(frozen=True)
class Relation:
    """A promise between two values of one setting, with the others as they are."""

    name: str
    decision: int
    says: str
    key: str
    off: str
    on: str
    holds: Callable[[Outcome, Outcome], bool]  # (with `off`, with `on`)
    of: Callable[[Site], Mapping[str, FieldTest]] = lambda site: {"iif": is_(site.tv_if)}  # the TV's port


def same_end(off: Outcome, on: Outcome) -> bool:
    return (off.verdict, off.hook) == (on.verdict, on.hook)


def no_new_way_through(off: Outcome, on: Outcome) -> bool:
    return on.verdict != ACCEPT or off.verdict == ACCEPT


RELATIONS: tuple[Relation, ...] = (
    Relation(
        "the gate only counts",
        18,
        "DNSGATE=count changes no packet's end on the TV's port.",
        "DNSGATE",
        "off",
        "count",
        same_end,
    ),
    Relation(
        "the in-path fill only counts",
        64,
        "DNSGATE_FILL=inpath changes no packet's end on the TV's port.",
        "DNSGATE_FILL",
        "passive",
        "inpath",
        same_end,
    ),
    Relation(
        "the name count only counts",
        70,
        "NAME_BINDING=count changes no packet's end on the TV's port.",
        "NAME_BINDING",
        "off",
        "count",
        same_end,
    ),
    Relation(
        "the minted-address shadow only counts",
        96,
        "MINT=shadow changes no packet's end on the TV's port.",
        "MINT",
        "off",
        "shadow",
        same_end,
    ),
    Relation(
        "the attention count only counts",
        69,
        "LIVE_READING=on, which loads the attention count, changes no packet's end on the TV's port.",
        "LIVE_READING",
        "off",
        "on",
        same_end,
    ),
    Relation(
        "the capture mode only records",
        39,
        "CAPTURE_MODE=headers changes no packet's end on the TV's port.",
        "CAPTURE_MODE",
        "full",
        "headers",
        same_end,
    ),
    Relation(
        "the probe leaves the TV alone",
        65,
        "TV_PROBE=on changes the end of no packet on the TV's port, unless it is for the probe's own port"
        " or address.",
        "TV_PROBE",
        "off",
        "on",
        same_end,
        lambda site: {"iif": is_(site.tv_if), "oif": not_(PROBE_IF), "daddr": not_(site.probe_ip)},
    ),
    Relation(
        "strict ports only close",
        17,
        "STRICT_PORTS=yes opens nothing on the TV's port.",
        "STRICT_PORTS",
        "no",
        "yes",
        no_new_way_through,
    ),
    Relation(
        "the QUIC block only closes",
        3,
        "BLOCK_QUIC=yes opens nothing on the TV's port.",
        "BLOCK_QUIC",
        "no",
        "yes",
        no_new_way_through,
    ),
    Relation(
        "the port wall only closes",
        45,
        "ADTECH_PORT_WALL=yes opens nothing on the TV's port.",
        "ADTECH_PORT_WALL",
        "no",
        "yes",
        no_new_way_through,
    ),
)
