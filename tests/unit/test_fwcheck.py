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
from types import SimpleNamespace

import pytest
import test_apply
from conftest import ROOT
from test_apply import PROC, run_apply
from test_clock_port import supported, tvgw_says

sys.path.append(str(ROOT / "tests" / "virtual"))
import vnet

from tvgw import fwcheck, fwpolicy
from tvgw.fwcheck import ACCEPT, DROP, FORWARD, INPUT, REJECT, Ruleset
from tvgw.fwpolicy import PROBE_IF

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
        'iifname "tun*" drop',  # every name that begins so, which the model would take for one name
        "meta l4proto 17 drop",  # UDP by its number
        "ct state new,untracked accept",  # a state no class of packets is given
        "ct mark set 1 accept",  # a statement that looks like the ones it lets pass
    ],
)
def test_a_clause_the_reader_does_not_know_stops_it_with_the_rule_named(text):
    with pytest.raises(ValueError, match=r"^fwcheck: ") as stop:
        fwcheck.rule("forward", text)
    assert text in str(stop.value)


BLOCK = "table inet t {\nchain c {\ntype filter hook forward priority filter; policy accept;\n}\n}"


@pytest.mark.parametrize(
    "script",
    [
        "add map inet tvgw m { type ipv4_addr : verdict; }",
        "table inet t {\nflowtable f {\n}\n}",
        BLOCK.replace("inet", "ip6"),
        "add table inet t\nadd chain inet t c { type filter hook egress priority filter; policy accept; }",
        f"{BLOCK}\n{BLOCK}",  # nft would add to the chain; the model would have replaced it, hook and all
        "add table inet t\nadd set inet t live { type ipv4_addr; flags interval, timeout; }\n"
        "add element inet t live { 192.0.2.7 }",
        "add table inet t\nadd set inet t live { type ipv4_addr; flags interval, dynamic; }\n"
        "add element inet t live { 192.0.2.7 }",
        "add table inet t\nadd set inet t live { type inet_service; }\nadd element inet t live { 53 }",
    ],
    ids=[
        "a map",
        "a flowtable",
        "another family",
        "a hook nothing walks",
        "a chain twice",
        "a set with a timeout filled",
        "a dynamic set filled",
        "a set with no flags filled",
    ],
)
def test_a_script_the_reader_cannot_follow_stops_it(script):
    with pytest.raises(ValueError, match=r"^fwcheck: "):
        Ruleset([script])


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
    """Nested, side by side and apart. A prefix that begins where the one around it begins leaves the
    outer one's own region to be found just past the inner one's end."""
    prefixes = [
        fwcheck.prefix(p) for p in ("10.0.0.0/8", "10.10.10.0/24", "10.10.10.1", "10.10.10.255", "192.0.2.7")
    ]
    regions = [{p for p in prefixes if a & p[1] == p[0]} for a in fwcheck.atoms(prefixes)]
    assert len(regions) == len({frozenset(r) for r in regions}) == 6  # none twice: outside all, and five more
    for address in (
        "9.255.255.255",
        "10.0.0.1",
        "10.10.10.0",
        "10.10.10.1",
        "10.10.10.2",
        "10.10.10.255",
        "192.0.2.7",
    ):
        assert {p for p in prefixes if ip(address) & p[1] == p[0]} in regions
    inner_first = [
        fwcheck.prefix("10.0.0.0/8"),
        fwcheck.prefix("10.0.0.0/24"),
    ]  # the /8's own region begins past the /24
    assert fwcheck.atoms(inner_first) == [0, ip("10.0.0.0"), ip("10.0.1.0")]


def test_the_values_tried_are_those_named_one_either_side_of_a_length_and_one_nothing_names():
    rules = Ruleset(
        [
            f"table inet a {{\nchain f {{\n{BASE.format('')}\nip length <= 128 tcp dport {{ 80, 40000 }} drop\n}}\n}}"
        ]
    )
    found = rules.constants()
    assert fwcheck.domain("length", found) == (60, 61, 128, 129)
    assert fwcheck.domain("dport", found) == (80, 40000, 40001) and fwcheck.domain("sport", found) == (40000,)
    assert fwcheck.domain("proto", {**found, "proto": {"gre"}}) == ("gre", "icmp", "tcp", "udp", "gre+")


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
        'chain side {\nip daddr 192.0.2.7 counter accept comment "side"\nudp dport 9 return\nudp dport 9 counter drop comment "past the return"\n}\n}',
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


TINY |= {
    "a queue is whoever reads it": (
        f'table inet a {{\nchain f {{\n{BASE.format("")}\ncounter queue flags bypass to 7 comment "held"\n}}\n}}',
        {(ACCEPT, ("held",)), (DROP, ("held",))},
    ),
    "a table deleted is gone with its chains, and made again holds only what it is given": (
        f'table inet a {{\nchain f {{\n{BASE.format("")}\ncounter drop comment "old"\n}}\n}}\n'
        f'delete table inet a\ntable inet a {{\nchain f {{\n{BASE.format("")}\ncounter comment "new"\n}}\n}}',
        {(ACCEPT, ("new",))},
    ),
    "a set the apply fills is known, in it and out of it": (
        "table inet a {\nset known {\ntype ipv4_addr; flags interval\nelements = { 192.0.2.0/24 }\n}\n"
        f'chain f {{\n{BASE.format("")}\nip daddr != @known counter drop comment "out"\n'
        'ip daddr @known counter accept comment "in"\n}\n}',
        {
            (DROP, ("out",)),
            (ACCEPT, ("in",)),
            (ACCEPT, ()),
        },  # the last is IPv6, which no address clause is of
    ),
    "what the forward hook lets through still meets postrouting": (
        f"table inet a {{\nchain f {{\n{BASE.format('')}\naccept\n}}\n"
        "chain p {\ntype filter hook postrouting priority srcnat - 20; policy accept;\n"
        'tcp dport 25 counter drop comment "at the door"\n}\n}',
        {(ACCEPT, ()), (DROP, ("at the door",))},
    ),
}


@pytest.mark.parametrize("case", TINY)
def test_the_walk_ends_each_class_as_the_rules_say(case):
    script, ends = TINY[case]
    classes = Ruleset([script]).classes({"iif": "eth0", "delivered6": False})
    assert {(o.verdict, tuple(sorted(o.ticked))) for _known, o in classes} == ends


def test_a_rule_that_only_counts_never_splits_the_walk_and_its_count_is_possible_not_sure():
    rules = Ruleset(
        [
            "add table inet a\nadd set inet a live { type ipv4_addr; flags timeout; }\n"
            f"add chain inet a f {{ {BASE.format('')} }}\n"
            'add rule inet a f ip daddr != @live counter log prefix "new: " comment "unknown address"\n'
            'add rule inet a f limit rate 1/second counter comment "thinned"\n'
            'add rule inet a f counter comment "every packet"\n'
            'add rule inet a f ip daddr @live counter comment "every packet"'
        ]
    )
    ((known, outcome),) = rules.classes({"family": 4, "daddr": ip("192.0.2.7")})
    assert (outcome.verdict, outcome.ticked) == (ACCEPT, {"every packet"})
    assert outcome.possible == {"unknown address", "new: ", "thinned"}
    assert not any(isinstance(key, tuple) for key in known)  # no open question was asked of the walk


def test_an_address_clause_is_of_ipv4_alone():
    script = f"table inet a {{\nchain f {{\n{BASE.format('')}\nip daddr != 192.0.2.7 drop\nip saddr 192.0.2.8 drop\n}}\n}}"
    ends: dict[int, set[str]] = {}
    for known, outcome in Ruleset([script]).classes({"iif": "eth0", "delivered6": False}):
        ends.setdefault(known["family"], set()).add(outcome.verdict)
    assert ends == {4: {ACCEPT, DROP}, 6: {ACCEPT}}


SMALL = {
    "the value that stands for the rest is one no rule names": (
        'meta l4proto { gre, esp } counter drop comment "tunnels"\ntcp dport 40000 counter drop comment "port"\n'
        'iifname "other0" counter drop comment "port named other0"',
        {(ACCEPT, ()), (DROP, ("tunnels",)), (DROP, ("port",)), (DROP, ("port named other0",))},
    ),
    "th dport is a port only for TCP and UDP, and open for anything else": (
        'meta l4proto { tcp, udp, sctp } th dport 9 counter drop comment "nine"',
        {(ACCEPT, ()), (DROP, ("nine",))},
    ),
    "a daemon's set asked about two fields is two questions": (
        'ip saddr != @live counter drop comment "source"\nip daddr @live counter drop comment "destination"',
        {(ACCEPT, ()), (DROP, ("source",)), (DROP, ("destination",))},
    ),
}


@pytest.mark.parametrize("case", SMALL)
def test_the_classes_leave_no_packet_out(case):
    body, ends = SMALL[case]
    script = f"table inet a {{\nset live {{ type ipv4_addr; flags timeout; }}\nchain f {{\n{BASE.format('')}\n{body}\n}}\n}}"
    classes = list(
        Ruleset([script]).classes({"family": 4, "daddr": ip("192.0.2.7"), "saddr": ip("192.0.2.8")})
    )
    assert {(o.verdict, tuple(sorted(o.ticked))) for _known, o in classes} == ends
    if "stands for the rest" in case:  # each named value has a class of its own, and so has the rest
        for name, named in (("proto", {"gre", "esp"}), ("dport", {40000}), ("iif", {"other0"})):
            assert {known[name] for known, o in classes if o.verdict == ACCEPT and name in known} - named
    if "sctp" in body:  # for SCTP the two bytes are not this model's to read: both ends are followed
        assert {o.verdict for known, o in classes if known["proto"] == "sctp"} == {ACCEPT, DROP}


def test_before_a_packet_is_routed_it_has_no_way_out_to_match():
    script = (
        "table inet a {\nchain in {\ntype filter hook input priority filter; policy accept;\n"
        'oifname "wlan0" drop\n}\n}'
    )
    classes = list(Ruleset([script], local=["10.10.10.1"]).classes({"family": 4, "daddr": ip("10.10.10.1")}))
    assert [(o.verdict, "oif" in known) for known, o in classes] == [(ACCEPT, False)]


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
def gateway(
    *settings: tuple[str, str], guard: bool = True, edit: tuple[str, str] | None = None
) -> tuple[Ruleset, fwpolicy.Site]:
    """The rules an apply with these settings hands to nft, with the guard's or without, and who is who.
    `edit` is a change to those rules, as (the text they have, the text to read in its place)."""
    with tempfile.TemporaryDirectory() as tmp:
        d = Path(tmp)
        for path, text in (
            (d / "state" / "doh4.txt", vnet.DOH4),
            (d / "etc" / "tvgw" / "block4.txt", vnet.BLOCK4),
        ):
            path.parent.mkdir(parents=True)
            path.write_text(text, encoding="utf-8")
        conf, proc = vnet.render_conf(dict(settings)), (*PROC, f"net/ipv4/conf/{vnet.VPN_IF}/forwarding")
        # as the namespace tier runs the clock port's variants: the copy of the script in which
        # ntp=resolved is built, and a tvgw whose record holds no NTP of the TV's, so ntp=none is not held back
        script = supported(test_apply.APPLY).replace("/usr/local/bin/tvgw", f"{d}/bin/tvgw")
        original, test_apply.APPLY = test_apply.APPLY, script
        try:
            done = run_apply(d, conf=conf, proc=proc, stubs={"tvgw": tvgw_says("")})
        finally:
            test_apply.APPLY = original
        assert done.returncode == 0, done.stderr
        scripts = sorted((d / "stub").glob("nft-script.*"), key=lambda p: int(p.suffix[1:]))
        scripts = [s.read_text(encoding="utf-8") for s in scripts]
        recorded = (d / "run" / "tvgw" / "settings.applied").read_text(encoding="utf-8")
    applied = dict(line.split("=", 1) for line in recorded.splitlines())
    if guard:
        scripts.append(re.sub(r"__(\w+)__", lambda m: applied[m[1]], GUARD))
    if edit is not None:
        assert any(edit[0] in s for s in scripts), edit[0]
        scripts = [s.replace(*edit) for s in scripts]
    rules = Ruleset(scripts, LOCAL)
    return rules, fwpolicy.Site.of(
        applied, OUT_IF[applied["UPLINK"]], LOCAL, listed(vnet.DOH4), listed(vnet.BLOCK4)
    )


def listed(text: str) -> list[str]:
    """The addresses of a list file: its lines that are not comments."""
    return [line.strip() for line in text.splitlines() if line.strip() and not line.startswith("#")]


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
GENERIC_STRICT = {**SCENARIOS["generic"].settings, "STRICT_PORTS": "yes"}
SETTINGS = {
    "a TV of no known make behind strict ports": GENERIC_STRICT,
    **{f"switches {i}": v for i, v in enumerate(SWITCHED)},
    **{f"the matrix's {name}": s.settings for name, s in SCENARIOS.items()},
    # the clock port closed, and open only to the servers a lookup named; open to any is every row above
    **{
        f"clock {i}": v
        for i, v in enumerate(vnet.CLOCK_VARIANTS)
        if v["CLOCK_PORT"] == "none" or "DNSGATE_FILL" in v
    },
}


def shown(known) -> str:
    dotted = lambda n: ".".join(str(n >> s & 255) for s in (24, 16, 8, 0))  # noqa: E731
    fields = {k: v for k, v in known.items() if not isinstance(k, tuple)}
    return " ".join(f"{k}={dotted(v) if k in ('saddr', 'daddr') else v}" for k, v in fields.items())


def unkept(site, rules, fixed=None) -> tuple[list[str], set[str]]:
    """(each class a promise speaks of that ends otherwise, the promises that spoke)"""
    broken, spoke = [], set()
    for promise, known, outcome, kept in fwpolicy.judged(site, rules, fixed):
        spoke.add(promise.name)
        if not kept:
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


OPEN = "table inet a {\nchain f {\ntype filter hook forward priority filter; policy accept;\n}\n}"
SHUT = "\n".join(
    f"add chain inet a {hook} {{ type filter hook {hook} priority filter; policy drop; }}"
    for hook in (FORWARD, INPUT)
)


def test_no_promise_is_kept_by_both_a_firewall_that_lets_everything_through_and_one_that_lets_nothing():
    """A promise that neither breaks says nothing. With no rules every packet is forwarded or delivered;
    with two chains that only drop, nothing is, and no refusal has a counter."""
    sites = [
        gateway(*sorted(settings.items()))[1]
        for settings in (WALLED["strict and pinned"], SCENARIOS["probe"].settings)
    ]
    broken = {
        promise.name
        for site in sites
        for script in (OPEN, "add table inet a\n" + SHUT)
        for promise, _known, _outcome in fwpolicy.broken(site, Ruleset([script], LOCAL))
    }
    assert broken == {p.name for p in fwpolicy.PROMISES}


def test_the_two_ways_of_comparing_ends_tell_ends_apart():
    end = lambda verdict, hook: SimpleNamespace(verdict=verdict, hook=hook)  # noqa: E731
    passed, at_gateway, refused = end(ACCEPT, FORWARD), end(ACCEPT, INPUT), end(REJECT, FORWARD)
    assert fwpolicy.same_end(passed, passed) and not fwpolicy.same_end(passed, at_gateway)
    assert not fwpolicy.same_end(passed, refused) and not fwpolicy.same_end(end(DROP, FORWARD), refused)
    assert fwpolicy.no_new_way_through(passed, refused) and fwpolicy.no_new_way_through(refused, refused)
    assert not fwpolicy.no_new_way_through(refused, passed)


def test_the_rules_and_the_promises_name_the_same_ports_and_protocols():
    """A port a wall names and no promise restates is a wall nobody holds to its word; one a promise
    names and no rule does is a promise about nothing. The rules' own extras are the gateway's side of
    DHCP and the two ports of the TV's own API, which the guard keeps for root."""
    rules, site = gateway(*sorted(SCENARIOS["direct"].settings.items()))
    theirs, ours = rules.constants(), fwpolicy.restated(site)
    assert (theirs["dport"] - ours["dport"], ours["dport"] - theirs["dport"]) == ({68, 3000, 3001}, set())
    assert (theirs["sport"], theirs["proto"] | {"tcp", "udp", "icmp"}) == (ours["sport"], ours["proto"])


def test_the_usual_ports_are_restated_and_agree_with_the_probes():
    from tvgw import probe

    assert fwpolicy.USUAL_PORTS == probe.USUAL_PORTS and fwpolicy.PROBE_IF == probe.GW_IF


def test_every_promise_cites_a_design_decision_that_exists_and_no_two_share_a_name():
    page = (ROOT / "docs" / "design-decisions.md").read_text(encoding="utf-8")
    decisions = {int(n) for n in re.findall(r"^## (\d+)\. ", page, re.M)}
    said = [*fwpolicy.PROMISES, *fwpolicy.RELATIONS]
    assert {p.decision for p in said} <= decisions and len({p.name for p in said}) == len(said)


DRIFTS = {
    "a port out of the DoT wall": (
        "th dport { 784, 853, 8853 }",
        "th dport { 784, 853 }",
        True,
        "no encrypted DNS",
    ),
    "a private range out of lan4": (
        ", 172.16.0.0/12, 192.168.0.0/16 }",
        ", 192.168.0.0/16 }",
        False,
        "the home network",
    ),
    "a port out of the ad-tech wall": ("4447, 8180, 8883 }", "4447, 8180 }", True, "the ad-tech ports"),
}


@pytest.mark.parametrize("drift", DRIFTS)
def test_a_rule_that_drifts_from_a_value_the_promises_restate_is_caught(drift):
    """The rules lose one value, and no rule names it any more. The promise that restates it still does:
    the search gives that value a class of its own, and the promise finds it forwarded."""
    was, now, guard, promise = DRIFTS[drift]
    rules, site = gateway(*sorted(SCENARIOS["direct"].settings.items()), guard=guard, edit=(was, now))
    assert promise in {p.name for p, _known, _outcome in fwpolicy.broken(site, rules, {"iif": site.tv_if})}


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
    return {**fields, "sport": 40000, "echo": False, "length": 60, **PROBES[row.kind](row.port)}


def in_rate(known) -> bool:
    """A class in which every rate limit the walk met still had room."""
    return all(answer for key, answer in known.items() if isinstance(key, tuple) and key[0] == "limit")


def agrees(row: vnet.Row, outcome, site) -> bool:
    kind, _, where = row.verdict.partition(":")
    if row.kind == "ping" and kind == DROP:  # a ping that gets no echo back, however it was refused
        ended = outcome.verdict in (DROP, REJECT)
    elif kind in (DROP, REJECT):
        ended = outcome.verdict == kind
    elif kind == "answer" and where == "gateway":
        ended = fwpolicy.answered_by_the_gateway(outcome, {}, site)
    else:  # pass, answer:wan, sent: let through, to the gateway's own address or beyond it
        beyond = not fwcheck.within(ip(row.target), [fwcheck.prefix(a) for a in LOCAL])
        ended = kind == "sent" or (outcome.verdict, outcome.hook) == (ACCEPT, FORWARD if beyond else INPUT)
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
    found = fwcheck.merged(off.constants(), on.constants(), fwpolicy.restated(site))
    return [
        f"{shown(known)}: {a.verdict} at {a.hook}, then {b.verdict} at {b.hook}"
        for known, (a, b) in fwcheck.explore([off.walk, on.walk], found, {"iif": site.tv_if})
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
    found = fwcheck.merged(rules.constants(), fwpolicy.restated(site))
    differ = [
        f"{shown(known)}: the TV's {a.verdict} at {a.hook}, the probe's {b.verdict} at {b.hook}"
        for known, (a, b) in fwcheck.explore(walks, found, {"family": 4, "ct": "new", "oif": site.uplink_if})
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
# the chains that decide what becomes of a packet of the TV's
MUTATED = [(("inet", "tvgw"), name) for name in ("pre_nat", "input", "forward", "tv_out")] + [
    (("netdev", "tvgw_l2"), "in")
]
# rules whose absence no promise notices on either gateway, each with why
COUNTS = "it changes no packet's end, since the chain's last rule accepts too: it is there for its counter, which the matrix's rows hold to its name"
UNNOTICED = {
    'tcp dport != { 80, 443 } counter accept comment "STRICT_PORTS=no: count only"': COUNTS,
    'udp dport != { 123, 443 } counter accept comment "STRICT_PORTS=no: count only"': COUNTS,
}


ALONE = {**WALLED, "the probe on": SCENARIOS["probe"].settings}


@pytest.mark.parametrize("walls", ALONE)
def test_the_main_table_keeps_every_promise_without_the_guard_behind_it(walls):
    rules, site = gateway(*sorted(ALONE[walls].items()), guard=False)
    assert unkept(site, rules)[0][:10] == []


@pytest.mark.parametrize("chain", MUTATED, ids=lambda key: key[1])
def test_a_rule_taken_out_breaks_a_promise(chain):
    """The promises are only as good as what they would notice. On `inet tvgw` alone, each rule that
    decides a packet's end is taken out in turn and the classes that met it are walked again, the TV's
    own first: on a gateway that has the rule, a promise must then be broken."""
    deciding, noticed = set(), set()
    for settings in WALLED.values():
        rules, site = gateway(*sorted(settings.items()), guard=False)
        todo = [r for r in rules.chains[chain].rules if r.verdict is not None and r.text not in noticed]
        deciding |= {rule.text for rule in todo}
        classes = sorted(rules.classes(), key=lambda found: found[0].get("iif") != site.tv_if) if todo else []
        for rule in todo:
            met = (known for known, outcome in classes if rule in outcome.met)
            if any(unkept(site, rules.without(rule), known)[0] for known in met):
                noticed.add(rule.text)
    assert sorted(deciding - noticed) == sorted(text for text in UNNOTICED if text in deciding)
