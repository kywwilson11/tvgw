"""(acr) The rule-set edits of the November research (section 5, from deep-dive 05, 1.8): the Nevo hub as
a regex, rules of our own for three LG hosts that rested on HaGeZi alone, lgchhomeapp as ads, and a FAST
category whose names are allowed and never blocked."""

import dataclasses
import re

import pytest

from tvgw import profile as profile_mod

FAST_NAMES = (
    "amg01874-nhl-channel-lg-us.amagi.tv",  # the slug form (title-bearing)
    "amg00497-c30-amgplt0023.amagi.tv",  # the opaque form
    "wurllg.global.transmit.live",
    "lgcp-xumoent-nbcnn-1.fast.nbcuni.com",
    "lgchannels.ott-channels.stingray.com",
)


def blocked_by(prof, name: str) -> list[str]:
    """The profile's own block rules (plain or regex) that match `name`, as AdGuard would match them."""
    hits = []
    for rule in prof.adguard_rules():
        kind, target = profile_mod.rule_target(rule)
        if (kind == "block" and target and profile_mod.covers(target, name)) or (
            kind == "regex" and re.search(target[1 : target.rfind("/")], name, re.IGNORECASE)
        ):
            hits.append(rule)
    return hits


@pytest.mark.parametrize(
    "name",
    [
        "qs2-nevoai-iothub-12-prod.azure-devices.net",  # the lab set's variant, on no list
        "nevoai-iothub-54-prod.azure-devices.net",  # the host blocked exactly until 2026-11-01
        "nevoai-iothub-7-prod.azure-devices.net",
    ],
)
def test_the_nevo_hub_regex_blocks_every_variant_and_categorizes_it(lg, name):
    # (listguard) a fingerprinting block, so it is loaded with $important (design decision 68)
    assert blocked_by(lg, name) == [
        "/^([a-z0-9]+-)?nevoai-iothub-[0-9]+-prod\\.azure-devices\\.net$/$important"
    ]
    assert lg.categorize(name) == "LG fingerprint"


@pytest.mark.parametrize(
    "name", ["other-iothub-1-prod.azure-devices.net", "nevoai-iothub-54-prod.azure-devices.net.example"]
)
def test_the_nevo_regex_takes_no_other_hub(lg, name):
    assert blocked_by(lg, name) == []


@pytest.mark.parametrize(
    ("name", "rule", "category"),
    [
        # (listguard) each in a red-line category, so loaded with $important (design decision 68)
        ("aic.rdl.lgtvcommon.com", "||rdl.lgtvcommon.com^$important", "LG telemetry"),
        ("aic.wiseconfig.lgtvcommon.com", "||wiseconfig.lgtvcommon.com^$important", "LG telemetry"),
        ("aic.ads.lgtvcommon.com", "||ads.lgtvcommon.com^$important", "LG ads"),
        ("aic.lgchhomeapp.lgtvcommon.com", "||lgchhomeapp.lgtvcommon.com^$important", "LG ads"),
    ],
)
def test_the_lg_hosts_that_rested_on_hagezi_alone_have_rules_of_our_own(lg, name, rule, category):
    assert rule in lg.custom_rules and blocked_by(lg, name) == [rule]
    assert lg.categorize(name) == category and not lg.is_expected(name)


@pytest.mark.parametrize("name", FAST_NAMES)
def test_fast_names_are_expected_and_no_rule_of_ours_blocks_them(lg, name):
    assert lg.categorize(name) == "FAST" and lg.is_expected(name)
    assert blocked_by(lg, name) == []


@pytest.mark.parametrize("rule", ["||amagi.tv^", "||*.amagi.tv^", "/\\.amagi\\.tv$/"])
def test_the_lint_refuses_a_block_over_the_whole_amagi_zone(lg, rule):
    """A block at the apex stops every Amagi FAST channel (report section 17: do not block *.amagi.tv)."""
    p = dataclasses.replace(lg, custom_rules=(*lg.custom_rules, rule))
    assert any("amagi.tv" in x for x in p.lint()), p.lint()


def test_the_edited_profile_lints_clean_and_keeps_its_must_allow_hosts_open(lg):
    assert lg.lint() == []
    for host in lg.must_allow:
        assert not [r for r in blocked_by(lg, host) if not r.startswith("@@")], host
