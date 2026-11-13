"""(fwcheck) The firewall worked out for every class of packets (design decision 86): the reader and the
walk on rules small enough to check by eye; then `tvgw-apply`'s own rules, rendered by test_apply's stubs
for a spread of settings, against every promise of `tvgw.fwpolicy`, against each row the namespace tier
proves on a kernel (tests/virtual/matrix.txt), and against themselves with one rule taken out."""

import functools
import re
import shutil
import sys
import tempfile
from pathlib import Path

import pytest
from conftest import ROOT
from test_apply import PROC, run_apply

sys.path.append(str(ROOT / "tests" / "virtual"))
import vnet

from tvgw import fwcheck, fwpolicy
from tvgw.fwcheck import ACCEPT, DROP, FORWARD, INPUT, REJECT, Ruleset
from tvgw.fwpolicy import PROBE_IF, is_

pytestmark = pytest.mark.skipif(shutil.which("bash") is None, reason="tvgw-apply is a bash script")


def ip(address: str) -> int:
    return fwcheck.prefix(address)[0]


# ---- the reader ------------------------------------------------------------------------------------------
@pytest.mark.parametrize(
    "text",
    [
        "tcp dport 443 ct mark 7 accept",  # a match it has never seen
        "fib daddr type local drop",
        "accept counter",  # only a comment may follow a verdict
        'tcp dport 443 goto elsewhere comment "x"',
    ],
)
def test_a_clause_the_reader_does_not_know_stops_it_with_the_rule_named(text):
    with pytest.raises(ValueError, match="a clause this model does not know") as stop:
        fwcheck.rule("forward", text)
    assert text in str(stop.value)


@pytest.mark.parametrize(
    "line", ["add map inet tvgw m { type ipv4_addr : verdict; }", "table inet t {\nflowtable f {\n}\n}"]
)
def test_a_line_the_reader_does_not_know_stops_it(line):
    with pytest.raises(ValueError, match="a line this model does not know"):
        Ruleset([line])


@pytest.mark.parametrize(
    ("text", "number"),
    [
        ("filter - 10", -10),
        ("filter", 0),
        ("mangle + 10", -140),
        ("dstnat - 10", -110),
        ("srcnat - 20", 80),
        ("-500", -500),
    ],
)
def test_a_priority_is_its_name_and_its_offset(text, number):
    assert fwcheck.priority(text) == number


def test_one_address_stands_for_each_region_the_prefixes_cut():
    prefixes = [
        fwcheck.prefix(p) for p in ("10.0.0.0/8", "10.10.10.0/24", "10.10.10.1", "10.10.10.255", "192.0.2.7")
    ]
    regions = [{p for p in prefixes if a & p[1] == p[0]} for a in fwcheck.atoms(prefixes)]
    assert len(regions) == len({frozenset(r) for r in regions}) == 6  # none twice: outside all, and five more
    for address in map(
        ip,
        ("9.255.255.255", "10.0.0.1", "10.10.10.0", "10.10.10.1", "10.10.10.2", "10.10.10.255", "192.0.2.7"),
    ):
        assert {p for p in prefixes if address & p[1] == p[0]} in regions


# ---- the walk, on rules small enough to check by eye --------------------------------------------------------
BASE = "type filter hook forward priority filter{}; policy accept;"
TINY = {
    "an accept ends one base chain and the next still runs": (
        f"table inet a {{\nchain f {{\n{BASE.format('')}\ntcp dport 80 accept\ndrop\n}}\n}}\n"
        f'table inet b {{\nchain g {{\n{BASE.format(" + 10")}\nip daddr 192.0.2.7 counter drop comment "later"\n}}\n}}',
        {(ACCEPT, ()), (DROP, ()), (DROP, ("later",))},
    ),
    "a jump comes back when the chain it went to says nothing": (
        f'table inet a {{\nchain f {{\n{BASE.format("")}\njump side\ncounter drop comment "after"\n}}\n'
        'chain side {\nip daddr 192.0.2.7 counter accept comment "side"\nudp dport 9 return\n}\n}',
        {(ACCEPT, ("side",)), (DROP, ("after",))},
    ),
    "a limit on a verdict is followed both ways, and on a log it is not": (
        f"table inet a {{\nchain f {{\n{BASE.format('')}\n"
        'limit rate 6/minute log prefix "seen: "\nlimit rate 2/second counter accept comment "in rate"\n'
        'counter reject comment "over"\n}\n}',
        {(ACCEPT, ("in rate",)), (REJECT, ("over",))},
    ),
    "a set a daemon fills is followed both ways where it decides": (
        "add table inet a\nadd set inet a live { type ipv4_addr; flags timeout; }\n"
        f"add chain inet a f {{ {BASE.format('')} }}\n"
        'add rule inet a f ip daddr != @live counter drop comment "not in the set"',
        {(ACCEPT, ()), (DROP, ("not in the set",))},
    ),
    "a rule inserted goes first, and a policy of drop is the chain's last word": (
        "add table inet a\nadd chain inet a f { type filter hook forward priority filter; policy drop; }\n"
        'add rule inet a f counter accept comment "added"\n'
        'insert rule inet a f ip daddr 192.0.2.7 counter drop comment "inserted"\n'
        "add chain inet a g { type filter hook forward priority filter + 1; policy drop; }\n"
        "add rule inet a g tcp dport 80 accept",
        {(DROP, ("inserted",)), (DROP, ("added",)), (ACCEPT, ("added",))},
    ),
}


@pytest.mark.parametrize("case", TINY)
def test_the_walk_ends_each_class_as_the_kernel_would(case):
    script, ends = TINY[case]
    classes = Ruleset([script]).classes({"family": 4, "iif": "eth0", "delivered6": False})
    assert {(o.verdict, tuple(sorted(o.ticked))) for _known, o in classes} == ends


def test_a_rule_that_only_counts_never_splits_the_walk_and_its_count_is_possible_not_sure():
    rules = Ruleset(
        [
            "add table inet a\nadd set inet a live { type ipv4_addr; flags timeout; }\n"
            f"add chain inet a f {{ {BASE.format('')} }}\n"
            'add rule inet a f ip daddr != @live counter log prefix "new: " comment "unknown address"\n'
            'add rule inet a f counter comment "every packet"'
        ]
    )
    ((known, outcome),) = (c for c in rules.classes({"family": 4, "daddr": ip("192.0.2.7")}))
    assert (outcome.verdict, outcome.ticked, outcome.possible) == (
        ACCEPT,
        {"every packet"},
        {"unknown address", "new: "},
    )
    assert not any(isinstance(key, tuple) for key in known)  # no open question was asked of the walk


def test_a_lookup_sent_elsewhere_is_delivered_to_the_address_dnat_gives_and_only_a_first_packet_is():
    rules = Ruleset(
        [
            "table inet a {\nchain pre {\ntype nat hook prerouting priority dstnat - 10; policy accept;\n"
            "udp dport 53 dnat ip to 10.10.10.1:53\n}\n"
            "chain in {\ntype filter hook input priority filter; policy accept;\nudp dport 53 accept\ndrop\n}\n"
            'chain fwd {\ntype filter hook forward priority filter; policy accept;\ncounter drop comment "left"\n}\n}'
        ],
        local=["10.10.10.1"],
    )
    packet = {"family": 4, "iif": "eth0", "proto": "udp", "dport": 53, "daddr": ip("8.8.8.8")}
    ends = {known["ct"]: (o.verdict, o.hook, o.daddr) for known, o in rules.classes(packet)}
    assert ends["new"] == (ACCEPT, INPUT, ip("10.10.10.1"))
    assert ends["established"] == (DROP, FORWARD, ip("8.8.8.8"))


def test_an_ingress_chain_sees_only_its_own_device():
    script = (
        'table netdev l2 {\nchain in {\ntype filter hook ingress device "eth0" priority -500; policy accept;\n'
        'ether type ip6 counter drop comment "v6"\n}\n}'
    )
    classes = Ruleset([script]).classes({"delivered6": False, "daddr": 0})
    ends = {(known["iif"], known["family"]): outcome.verdict for known, outcome in classes}
    assert ends == {
        ("eth0", 4): ACCEPT,
        ("eth0", 6): DROP,
        (fwcheck.OTHER_IF, 4): ACCEPT,
        (fwcheck.OTHER_IF, 6): ACCEPT,
    }


# ---- tvgw-apply's own rules ----------------------------------------------------------------------------------
LOCAL = (vnet.GW_TV, vnet.GW_WLAN, vnet.GW_TUN, "10.10.10.255", "255.255.255.255", "224.0.0.0/4")
GUARD = (ROOT / "deploy" / "nftables" / "guard.nft.template").read_text(encoding="utf-8")
OUT_IF = {"direct": vnet.WAN_IF, "vpn": vnet.VPN_IF}


@functools.cache
def gateway(*settings: tuple[str, str], guard: bool = True) -> tuple[Ruleset, fwpolicy.Site]:
    """The rules an apply with these settings hands to nft, with the guard's or without, and who is who."""
    with tempfile.TemporaryDirectory() as tmp:
        d = Path(tmp)
        for path, text in (
            (d / "state" / "doh4.txt", vnet.DOH4),
            (d / "etc" / "tvgw" / "block4.txt", vnet.BLOCK4),
        ):
            path.parent.mkdir(parents=True)
            path.write_text(text, encoding="utf-8")
        conf, proc = vnet.render_conf(dict(settings)), (*PROC, f"net/ipv4/conf/{vnet.VPN_IF}/forwarding")
        done = run_apply(d, conf=conf, proc=proc)
        assert done.returncode == 0, done.stderr
        scripts = sorted((d / "stub").glob("nft-script.*"), key=lambda p: int(p.suffix[1:]))
        scripts = [s.read_text(encoding="utf-8") for s in scripts]
        recorded = (d / "run" / "tvgw" / "settings.applied").read_text(encoding="utf-8")
    applied = dict(line.split("=", 1) for line in recorded.splitlines())
    if guard:
        scripts.append(re.sub(r"__(\w+)__", lambda m: applied[m[1]], GUARD))
    rules = Ruleset(scripts, LOCAL)
    return rules, fwpolicy.Site.of(applied, OUT_IF[applied["UPLINK"]], LOCAL, rules)


def pairs(row: dict[str, str]) -> set[frozenset]:
    return {frozenset((a, b)) for a in row.items() for b in row.items() if a < b}


def pairwise(rows: list[dict[str, str]]) -> list[dict[str, str]]:
    """Rows that between them hold every pair of values of every two switches: each time the row that
    covers the most pairs not yet covered."""
    wanted, chosen = set().union(*map(pairs, rows)), []
    while wanted:
        chosen.append(max(rows, key=lambda row: len(pairs(row) & wanted)))
        wanted -= pairs(chosen[-1])
    return chosen


SCENARIOS = {s.name: s for s in vnet.parse_matrix(vnet.MATRIX.read_text(encoding="utf-8"))}
SWITCHED = pairwise(vnet.variants(vnet.script_choices(vnet.APPLY.read_text(encoding="utf-8"))))
SETTINGS = {
    **{f"switches {i}": v for i, v in enumerate(SWITCHED)},
    **{f"the matrix's {name}": s.settings for name, s in SCENARIOS.items()},
    # the clock port closed, and open only to the servers a lookup named; open to any is every row above
    **{
        f"clock {i}": v
        for i, v in enumerate(vnet.CLOCK_VARIANTS)
        if v["CLOCK_PORT"] == "none" or "DNSGATE_FILL" in v
    },
}
# What the checker found on 2026-11-13 and the rules do not yet keep. Each entry names the classes of one
# promise that end otherwise, so that every other class of the promise is still held to it. Closing one
# changes what the firewall does: it has a package and a quiet window of its own.
KNOWN = {
    "manual blocks": ([{"proto": is_("icmp")}], "tv_out accepts a small ping before it reads block4.txt"),
    "every refusal is counted": (
        [{"oif": is_(PROBE_IF)}, {"daddr": is_(ip(vnet.PROBE_IP))}],
        "with TV_PROBE=on, a packet of the TV's for the probe's port or address meets a drop with no counter",
    ),
}


def a_known_hole(promise, known) -> bool:
    holes = KNOWN.get(promise.name, ([], ""))[0]
    return any(all(name in known and test(known[name]) for name, test in hole.items()) for hole in holes)


def shown(known) -> str:
    dotted = lambda n: ".".join(str(n >> s & 255) for s in (24, 16, 8, 0))  # noqa: E731
    fields = {k: v for k, v in known.items() if not isinstance(k, tuple)}
    return " ".join(f"{k}={dotted(v) if k in ('saddr', 'daddr') else v}" for k, v in fields.items())


def unkept(site, rules, fixed=None) -> tuple[list[str], set[str]]:
    """(each class a promise speaks of that ends otherwise and is no known hole, the promises that spoke)"""
    broken, spoke = [], set()
    for promise, known, outcome, kept in fwpolicy.judged(site, rules, fixed):
        spoke.add(promise.name)
        if not kept and not a_known_hole(promise, known):
            by = f" by `{outcome.by.text}`" if outcome.by else ""
            broken.append(f"{promise.name}: {shown(known)} ends {outcome.verdict} at {outcome.hook}{by}")
    return broken, spoke


@pytest.mark.parametrize("name", SETTINGS)
def test_every_class_of_packets_ends_as_the_promises_say(name):
    """Port by port, and not the probe's own: no promise speaks of it, and the test of the probe's twin
    holds it to the TV's."""
    rules, site = gateway(*sorted(SETTINGS[name].items()))
    broken, spoke = [], set()
    for port in fwcheck.domain("iif", rules.constants()):
        if port != PROBE_IF:
            more, said = unkept(site, rules, {"iif": port})
            broken, spoke = broken + more, spoke | said
    assert broken[:10] == []
    assert spoke == {
        p.name for p in fwpolicy.PROMISES if p.of(site)
    }  # one that speaks of no packet proves nothing


def test_the_switches_between_them_show_every_pair_of_values_in_a_fiftieth_of_the_renders():
    every = vnet.variants(vnet.script_choices(vnet.APPLY.read_text(encoding="utf-8")))
    assert set().union(*map(pairs, SWITCHED)) == set().union(*map(pairs, every))
    assert len(SWITCHED) < len(every) / 50


@pytest.mark.parametrize(
    ("promise", "scenario"), [("manual blocks", "direct"), ("every refusal is counted", "probe")]
)
def test_a_known_hole_is_still_a_hole(promise, scenario):
    """When the rules close one, its entry goes: an exception nobody needs is a hole nobody would see."""
    rules, site = gateway(*sorted(SCENARIOS[scenario].settings.items()))
    broken = [(p, known) for p, known, _ in fwpolicy.broken(site, rules) if p.name == promise]
    assert broken and all(a_known_hole(p, known) for p, known in broken)


def test_every_promise_cites_a_design_decision_that_exists_and_no_two_share_a_name():
    page = (ROOT / "docs" / "design-decisions.md").read_text(encoding="utf-8")
    decisions = {int(n) for n in re.findall(r"^## (\d+)\. ", page, re.M)}
    said = [*fwpolicy.PROMISES, *fwpolicy.RELATIONS]
    assert {p.decision for p in said} <= decisions and len({p.name for p in said}) == len(said)
    assert set(KNOWN) <= {p.name for p in fwpolicy.PROMISES}


# ---- the kernel's word: every row of the namespace tier's matrix ----------------------------------------------
SOURCES = {
    "tv": (vnet.TV_IF, vnet.TV_IP),
    "tv-foreign": (vnet.TV_IF, vnet.TV_FOREIGN),
    "tv-alias": (vnet.TV_IF, vnet.TV_ALIAS),
    "probe": (PROBE_IF, vnet.PROBE_IP),
    "probe-alias": (PROBE_IF, vnet.PROBE_ALIAS),
}
PROBES = {
    "tcp": lambda port: {"proto": "tcp", "dport": port},
    "udp": lambda port: {"proto": "udp", "dport": port},
    "dns-tcp": lambda port: {"proto": "tcp", "dport": port},
    "dns-udp": lambda port: {"proto": "udp", "dport": port},
    "ping": lambda payload: {
        "proto": "icmp",
        "echo": True,
        "length": payload + 28,
    },  # the IP and ICMP headers
    "gre": lambda _: {"proto": "gre"},
    "udp6": lambda port: {"family": 6, "proto": "udp", "dport": port, "delivered6": False},
}


def packet(row: vnet.Row, uplink: str) -> dict:
    """The first packet of a row's probe, as it reaches the gateway, routed as the namespaces route it."""
    target = ip(row.target)
    if (
        row.source == "wan"
    ):  # from the internet side: by the tunnel to the tunnel's address, else by the uplink
        arrives = vnet.VPN_IF if row.target == vnet.GW_TUN else vnet.WAN_IF
        leaves = PROBE_IF if row.target == vnet.PROBE_IP else vnet.TV_IF
        source = vnet.WAN_GW
    else:
        (arrives, source), leaves = SOURCES[row.source], uplink
        if fwcheck.within(target, [fwcheck.prefix(f"{vnet.WAN_GW}/24")]):
            leaves = vnet.WAN_IF  # the uplink's own network is reached by the uplink, tunnel or no tunnel
    fields = {"family": 4, "iif": arrives, "oif": leaves, "saddr": ip(source), "daddr": target, "ct": "new"}
    return {**fields, "sport": fwcheck.OTHER_PORT, "echo": False, "length": 60, **PROBES[row.kind](row.port)}


def in_rate(known) -> bool:
    """A class in which every rate limit the walk met still had room."""
    return all(answer for key, answer in known.items() if isinstance(key, tuple) and key[0] == "limit")


def agrees(row: vnet.Row, outcome, site) -> bool:
    kind, _, where = row.verdict.partition(":")
    if kind in (DROP, REJECT):
        ended = outcome.verdict == kind
    elif kind == "answer" and where == "gateway":
        ended = fwpolicy.answered_by_the_gateway(outcome, {}, site)
    else:  # pass, answer:wan, sent
        ended = kind == "sent" or outcome.verdict == ACCEPT
    return ended and (row.counter is None or row.counter in outcome.ticked)


@pytest.mark.parametrize("name", SCENARIOS)
def test_the_model_ends_every_probe_of_the_matrix_as_the_kernel_does(name):
    """CI's namespace tier sends each row's probe through a real kernel. The model must give the same end
    and tick the counter the row names, with every rate limit still having room."""
    rules, site = gateway(*sorted(SCENARIOS[name].settings.items()))
    wrong = []
    for row in SCENARIOS[name].rows:
        ends = [outcome for known, outcome in rules.classes(packet(row, site.uplink_if)) if in_rate(known)]
        assert ends, row.line()
        wrong += [
            f"{row.line()}  model: {o.verdict} at {o.hook}, ticked {sorted(o.ticked)}"
            for o in ends
            if not agrees(row, o, site)
        ]
    assert wrong == []


# ---- between two settings --------------------------------------------------------------------------------------
QUIET = {
    "UPLINK": "direct",
    "BLOCK_QUIC": "no",
    "STRICT_PORTS": "no",
    "DNSGATE": "count",
    "ADTECH_PORT_WALL": "no",
}
COUNTING = {
    "DNSGATE": "count",
    "DNSGATE_FILL": "inpath",
    "NAME_BINDING": "count",
    "LIVE_READING": "on",
    "CAPTURE_MODE": "headers",
}
SILENT = {
    "DNSGATE": "off",
    "DNSGATE_FILL": "passive",
    "NAME_BINDING": "off",
    "LIVE_READING": "off",
    "CAPTURE_MODE": "full",
}
WALLS = {
    "UPLINK": "vpn",
    "BLOCK_QUIC": "yes",
    "STRICT_PORTS": "yes",
    "ADTECH_PORT_WALL": "yes",
    "TV_PROBE": "on",
}


def differing(off: Ruleset, on: Ruleset, site, of, holds) -> list[str]:
    """The classes of the TV's port that a description speaks of and that two rulesets end against `holds`."""
    both = fwcheck.explore(
        [off.walk, on.walk], fwcheck.merged(off.constants(), on.constants()), {"iif": site.tv_if}
    )
    return [
        f"{shown(known)}: {a.verdict} at {a.hook}, then {b.verdict} at {b.hook}"
        for known, (a, b) in both
        if fwpolicy.speaks_of(of, known) and not holds(a, b)
    ]


@pytest.mark.parametrize("relation", fwpolicy.RELATIONS, ids=lambda r: r.name)
def test_a_switch_keeps_its_promise(relation):
    values = (relation.off, relation.on)
    (off, _), (on, site) = (gateway(*sorted({**QUIET, relation.key: value}.items())) for value in values)
    assert differing(off, on, site, relation.of(site), relation.holds)[:10] == []


def test_every_counter_switched_on_at_once_behind_every_wall_still_changes_no_packets_end():
    """The same promise where it is hardest to keep: all five counting values together, on a gateway with
    the tunnel, the walls and the probe."""
    (off, _), (on, site) = (gateway(*sorted({**WALLS, **values}.items())) for values in (SILENT, COUNTING))
    assert differing(off, on, site, {}, fwpolicy.same_end)[:10] == []
    counting = {
        r.key: r.on for r in fwpolicy.RELATIONS if r.holds is fwpolicy.same_end and r.key != "TV_PROBE"
    }
    assert counting == COUNTING  # a counting switch added to the promises is added here


def test_the_probes_port_ends_a_connection_where_the_tvs_port_would():
    """(probe) The test client stands where the TV stands (design decision 65): the first packet of a
    connection from the probe's port and address ends as the same packet from the TV's would, each
    within its own rate."""
    rules, site = gateway(*sorted(SCENARIOS["probe"].settings.items()))
    stand = lambda port, address: lambda known: rules.walk({**known, "iif": port, "saddr": address})  # noqa: E731
    walks = [stand(site.tv_if, site.pinned), stand(PROBE_IF, site.probe_ip)]
    differ = [
        f"{shown(known)}: the TV's {a.verdict} at {a.hook}, the probe's {b.verdict} at {b.hook}"
        for known, (a, b) in fwcheck.explore(
            walks, rules.constants(), {"family": 4, "ct": "new", "oif": site.uplink_if}
        )
        if in_rate(known) and not fwpolicy.same_end(a, b)
    ]
    assert differ[:10] == []


# ---- with one rule taken out -----------------------------------------------------------------------------------
# Two gateways that between them let every rule decide something: under STRICT_PORTS=yes the port wall's
# rule and the DoT wall's never refuse what strict would not, with it off the firmware fallback's accept
# changes no end, and behind the pin the source check never has the last word.
WALLED = {
    "strict and pinned": {
        "UPLINK": "direct",
        "BLOCK_QUIC": "yes",
        "STRICT_PORTS": "yes",
        "ADTECH_PORT_WALL": "no",
        "CLOCK_PORT": "none",
    },
    "the port wall, no pin": {
        "UPLINK": "vpn",
        "BLOCK_QUIC": "yes",
        "STRICT_PORTS": "no",
        "ADTECH_PORT_WALL": "yes",
        "TV_MAC": "",
    },
}
MUTATED = ("pre_nat", "input", "forward", "tv_out")  # the chains of inet tvgw that decide what the TV reaches
# rules whose absence no promise notices on either gateway, each with why
COUNTS = "it changes no packet's end, since the chain's last rule accepts too: it is there for its counter, which the matrix's rows hold to its name"
UNNOTICED = {
    'tcp dport != { 80, 443 } counter accept comment "STRICT_PORTS=no: count only"': COUNTS,
    'udp dport != { 123, 443 } counter accept comment "STRICT_PORTS=no: count only"': COUNTS,
}


@pytest.mark.parametrize("walls", WALLED)
def test_the_main_table_keeps_every_promise_without_the_guard_behind_it(walls):
    rules, site = gateway(*sorted(WALLED[walls].items()), guard=False)
    assert unkept(site, rules)[0][:10] == []


@pytest.mark.parametrize("chain", MUTATED)
def test_a_rule_taken_out_breaks_a_promise(chain):
    """The promises are only as good as what they would notice. On `inet tvgw` alone, each rule that
    decides a packet's end is taken out in turn and the classes that met it are walked again, the TV's
    own first: on a gateway that has the rule, a promise must then be broken."""
    deciding, noticed = set(), set()
    for settings in WALLED.values():
        rules, site = gateway(*sorted(settings.items()), guard=False)
        todo = [
            r
            for r in rules.chains[("inet", "tvgw"), chain].rules
            if r.verdict is not None and r.text not in noticed
        ]
        deciding |= {rule.text for rule in todo}
        classes = sorted(rules.classes(), key=lambda found: found[0].get("iif") != site.tv_if) if todo else []
        for rule in todo:
            met = (known for known, outcome in classes if rule in outcome.met)
            if any(unkept(site, rules.without(rule), known)[0] for known in met):
                noticed.add(rule.text)
    assert sorted(deciding - noticed) == sorted(text for text in UNNOTICED if text in deciding)
