"""(lint) The five bundled profiles against every rule the lint lets in (L5-6, design decision 86).

The property: no rule that `Profile.lint` admits beside a profile's own rules blocks a must-allow host,
takes a never-block zone whole, blocks a clock host or undoes the URL filter, by the repo's own model of
AdGuard's precedence (`listguard.Engine`). The rules tried are the ones an adversary, or a model steered
by one, would try: every label suffix of every protected name and of every zone, in each rule form the
lint reads, and the rules that match everything. Adopted from the L5 lane's `prop_profiles.py`.
"""

import dataclasses
import re

import pytest

from tvgw import listguard, profile
from tvgw.listguard import BLOCKED, REWRITTEN

GW, TV = "10.10.10.1", "10.10.10.17"
CLIENT = listguard.Client(TV, "tv")
MACHINE = "machine"
# the four profiles where the lint of 0.4.0 lets rules through that take a zone or a clock host (L5-6)
GAPS = {"lg-webos", "roku", "samsung-tizen", "vizio-smartcast"}


def protected(prof: profile.Profile) -> dict[str, list[str]]:
    """The names the profile promises the TV can reach, by kind: each must-allow host and a name under
    it, one concrete name per clock pattern, and the URL filter's hosts (which must stay rewritten)."""
    must = sorted(prof.must_allow) + ["zz." + h for h in prof.must_allow]
    clock = [
        pat.replace("??", prof.country).replace("*.", "api.").replace("*", "0.").replace("?", "a")
        for pat in prof.clock_hosts
    ]
    urlf = list(prof.url_filter.hosts) if prof.url_filter else []
    return {"must-allow": must, "clock": clock, "url-filter": urlf}


def candidates(prof: profile.Profile, prot: dict[str, list[str]]) -> list[str]:
    seeds: set[str] = set()
    for names in prot.values():
        for n in names:
            seeds.update(listguard.suffixes(n))
    for apex in prof.never_block_apex:
        seeds.update(listguard.suffixes(apex))
    out = []
    for s in sorted(seeds):
        esc = re.escape(s)
        out += [
            f"||{s}^",
            f"||*.{s}^",
            f"||{s}^$important",
            f"|{s}^",
            f"0.0.0.0 {s}",
            f"||*{s}^",
            f"||{s}^$dnstype=A",
            f"||{s}^$dnstype=~HTTPS",
            f"||{s}^$client={TV}",
            f"||{s.upper()}^",
            f"/(^|\\.){esc}$/",
            f"/{esc}/",
            f"/^.*{esc}$/",
        ]
    return [*out, "||*^", "||*.*^", "/./", "/^/", "/.*/", "||*.*.*^"]


def parsed(texts) -> list[listguard.Rule]:
    return [r for t in texts for r in listguard.parse(t) or []]


def counterexamples(name: str) -> dict[str, list[tuple[str, str]]]:
    """(kind -> [(rule, name)]) for every admitted rule that breaks a promise of the profile's."""
    prof = profile.load(name)
    prot = protected(prof)
    own = parsed(prof.adguard_rules(GW, TV))
    probes = [(apex, "zz-probe." + apex) for apex in prof.never_block_apex]
    found: dict[str, list[tuple[str, str]]] = {}
    for rule in candidates(prof, prot):
        if dataclasses.replace(prof, custom_rules=(*prof.custom_rules, rule)).lint(strict=True):
            continue  # the lint refuses it: nothing to check
        eng = listguard.Engine([("profile", own), (MACHINE, parsed([rule]))], CLIENT)
        for kind, names in prot.items():
            for n in names:
                v = eng.decide(n)
                if kind == "url-filter":
                    broken = v.state != REWRITTEN
                else:
                    broken = v.state in (BLOCKED, REWRITTEN) and v.hit is not None and v.hit.source == MACHINE
                if broken:
                    found.setdefault(kind, []).append((rule, n))
        for _apex, probe in probes:
            v = eng.decide(probe)
            if v.state == BLOCKED and v.hit is not None and v.hit.source == MACHINE:
                found.setdefault("never-block zone", []).append((rule, probe))
    return found


@pytest.mark.parametrize("name", profile.bundled_names())
def test_no_rule_the_strict_lint_admits_takes_a_zone_a_clock_host_a_must_allow_host_or_the_url_filter(name):
    """Before decision 102 the machine's lint admitted 87 such rules over four profiles (19, 3, 9 and 11
    zone rules, and 45 clock rules on samsung-tizen), which `tvgw block` refuses."""
    found = counterexamples(name)
    summary = {kind: (len(ex), sorted({r for r, _ in ex}, key=len)[:6]) for kind, ex in found.items()}
    assert found == {}, summary


def test_every_bundled_profile_is_clean_under_the_strict_lint_for_every_country():
    """The strict lint must never refuse what ships: each profile as filled for the default country and for
    every country of its [regions]."""
    found = {}
    for name in profile.bundled_names():
        prof = profile.load(name)
        for cc in ("", *(c for ccs in prof.regions.values() for c in ccs)):
            if problems := prof.for_country(cc).lint(strict=True):
                found[name, cc] = problems
    assert found == {}


@pytest.mark.parametrize(
    "rule",
    [
        r"/^[[:alnum:]-]+\.lgtvcommon\.com$/",  # first in its set: Python warns, and reads another set
        r"/(^[a-z[:digit:]-]+\.lgtvcommon\.com|attacker\.example)$/",  # later in the set: no warning
        r"/^[^[:space:]]+\.amagi\.tv$/",
        r"/^[-[:alnum:]]+\.aws-prd\.net$/",
    ],
)
def test_a_regex_that_go_reads_as_a_posix_class_is_refused(lg, rule):
    """In Go's RE2 `[[:alnum:]-]` is a POSIX class and matches every label of the zone; Python reads another
    set, so the lint's probes of the zone do not match and it passed. No DNS name holds `:`, so `[:` is a
    token with no false positive."""
    assert dataclasses.replace(lg, custom_rules=(*lg.custom_rules, rule)).lint() == []
    assert any("POSIX class" in p for p in lg.added_problems(rule))


@pytest.mark.parametrize(
    ("name", "rule", "why"),
    [
        ("lg-webos", "||net^", "takes the whole of 'aws-prd.net'"),  # the parent of a never-block zone
        ("lg-webos", "||*amagi.tv^", "takes the whole of 'amagi.tv'"),  # a leading `*` over LG Channels
        ("lg-webos", "||ngfts.lge.com^", "goes through the URL filter"),
        ("lg-webos", "||gb.lgtvsdp.com^", "reaches the clock host"),
        ("roku", "||*sr.roku.com^", "takes the whole of 'sr.roku.com'"),
        ("samsung-tizen", "||org^", "reaches the clock host"),  # every *pool.ntp.org
        ("samsung-tizen", "||*.ntp.org^", "reaches the clock host"),  # a wildcard host over a wildcard clock
        ("samsung-tizen", "/(^|\\.)org$/", "matches the clock host"),
        ("samsung-tizen", "/^0\\.pool\\.ntp\\.org$/", "matches the clock host"),  # a `*` read as a digit
        ("samsung-tizen", "/^xpool\\.ntp\\.org$/", "matches the clock host"),  # and as a letter
        ("lg-webos", "||x.ngfts.lge.com^", "goes through the URL filter"),  # under a URL-filter host
        ("lg-webos", "||*gfts.lge.com^", "goes through the URL filter"),  # over one, by a wildcard
        ("lg-webos", "||tv^$dnsrewrite=203.0.113.1", "takes the whole of 'amagi.tv'"),  # a rewrite too
        ("lg-webos", "/gb\\.lgtvsdp\\.com/", "matches the clock host"),
        ("vizio-smartcast", "||tv^", "takes the whole of 'amagi.tv'"),
    ],
)
def test_a_machine_rule_the_owner_could_not_write_is_dropped(tmp_path, name, rule, why):
    """`sudo tvgw block` refuses each of these (localrules); the machine's file must not get them through
    either: one lint for every writer (design decision 102)."""
    from tvgw import autoblock

    prof = profile.load(name)
    path = tmp_path / "auto.rules"
    path.write_text(f"{autoblock.HEADER}\n{rule}\n")
    ok, refused = autoblock.admissible(str(path), prof)
    assert ok == [] and len(refused) == 1 and why in refused[0], (ok, refused)


@pytest.mark.parametrize(
    ("host", "pattern", "reached"),
    [
        ("google.com", "time.google.com", True),  # a literal parent: the pattern's tail is itself
        ("*.ntp.org", "*pool.ntp.org", True),  # a wildcard host over a wildcard clock host
        ("*gb.lgtvsdp.com", "??.lgtvsdp.com", True),
        ("de.lgtvsdp.com", "??.lgtvsdp.com", True),  # the TV's own country
        ("time.google.com", "time.google.com", True),
        ("lgtvsdp.com", "??.lgtvsdp.com", True),
        ("fr.lgtvsdp.com", "??.lgtvsdp.com", True),  # any two letters, not only the ones filled
        ("x.fr.lgtvsdp.com", "??.lgtvsdp.com", True),  # under a name the pattern matches
        ("us.lgtvsdp.com", "??.nextlgsdp.com", False),
        ("ads.lgtvsdp.com", "??.lgtvsdp.com", False),  # a name beside the clock hosts
        ("example.org", "*pool.ntp.org", False),
    ],
)
def test_a_block_reaches_a_clock_host_it_covers_by_wildcard_or_by_parent(host, pattern, reached):
    assert profile.reaches(host, pattern) is reached


@pytest.mark.parametrize("rule", [r"/^t-a\.ex\.example$/", r"/^api\.ex2\.example$/", r"/^de\.ex3\.example$/"])
def test_a_regex_matching_a_name_a_clock_pattern_fills_is_refused(lg, rule):
    """`?` is filled with a letter, `*.` with a label, `??` with the country: a profile whose clock host is
    not also a must-allow host (the bundled ones are) has only this check."""
    p = dataclasses.replace(
        lg, must_allow={}, clock_hosts=("t-?.ex.example", "*.ex2.example", "??.ex3.example"), country="de"
    )
    assert any("matches the clock host" in x for x in p.added_problems(rule))


@pytest.mark.parametrize(
    ("name", "rule"),
    [
        ("samsung-tizen", r"/^pool\.ntp\.org$/"),  # the name the capture saw: `*` as nothing
        ("samsung-tizen", r"/^1\.pool\.ntp\.org$/"),
        ("samsung-tizen", "||1.pool.*^"),
    ],
)
def test_a_rule_over_the_real_ntp_pool_names_is_refused(name, rule):
    p = profile.load(name)
    assert any("clock host" in x for x in p.added_problems(rule))


def test_a_rule_repeating_a_problem_its_profile_has_is_still_refused(lg):
    """A sentence names the host, so `||net^$important` beside `||net^` says the same thing again."""
    own = dataclasses.replace(lg, custom_rules=(*lg.custom_rules, "||net^"))
    assert own.added_problems("||net^$important") != []


def test_a_regex_over_the_tvs_own_country_matches_its_clock_host(lg):
    """`??` is filled with gb, us and zz, and with the country the profile is for."""
    rule = r"/^de\.lgtvsdp\.com$/"
    assert lg.added_problems(rule) == []
    assert any("matches the clock host" in p for p in lg.for_country("de").added_problems(rule))


def test_the_strict_lint_adds_nothing_to_the_apex_the_lint_already_refuses(lg):
    """The old sentence stays the only one, so `problems[0]` and the drop's stderr line do not change."""
    p = dataclasses.replace(lg, custom_rules=(*lg.custom_rules, "||amagi.tv^"))
    assert p.lint(strict=True) == p.lint() != []


def test_a_custom_profile_with_a_problem_of_its_own_still_keeps_a_good_machine_rule(tmp_path, lg):
    """A machine rule is refused for what it adds, not for a problem its profile already had: otherwise
    one strict problem in an owner's profile would drop every machine rule and refuse every proposal."""
    from tvgw import analyst, autoblock

    own = dataclasses.replace(lg, custom_rules=(*lg.custom_rules, "||net^"))  # `||net^` is strict-only
    assert own.lint() == [] and own.lint(strict=True)
    path = tmp_path / "auto.rules"
    path.write_text(f"{autoblock.HEADER}\n||tracker.example^\n||tv^\n")
    ok, refused = autoblock.admissible(str(path), own)
    assert ok == ["||tracker.example^"] and len(refused) == 1 and refused[0].startswith("||tv^")
    verdict = analyst._verdict(
        {"kind": "block", "name": "tracker.example", "rule": "||tracker.example^"}, own, own.adguard_rules()
    )
    assert verdict == "ok"
    refused = analyst._verdict({"kind": "block", "name": "x.tv", "rule": "||tv^"}, own, own.adguard_rules())
    assert refused.startswith("refused: block rule 'tv' takes the whole of 'amagi.tv'")
