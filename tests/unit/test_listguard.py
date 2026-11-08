"""(listguard) The pushed-content guard (design decision 68): the profile's red-line blocks held with
`$important`, the model of AdGuard's precedence that proves it, the scan of the subscribed lists for lines
that act on the TV's own rules, and the preview of what a list's update changed.

The lists are GPL-3.0 and their text never enters the repository: every list line here is written for the
test, in the forms the published lists use."""

import dataclasses
from importlib import resources

import pytest

from tvgw import adguardcfg, listguard, profile
from tvgw.listguard import ALLOWED, BLOCKED, NONE, REWRITTEN, Client, Engine, parse

TV = Client("10.10.10.17", "tv")


def rules(*lines: str) -> list:
    return [r for line in lines for r in parse(line) or []]


def engine(*sources: tuple[str, list[str]]) -> Engine:
    return Engine([(name, rules(*lines)) for name, lines in sources], TV)


def as_written(prof: profile.Profile) -> profile.Profile:
    """The profile with its `.rules` file exactly as written, before the load holds its red-line blocks."""
    text = (resources.files("tvgw.profiles") / f"{prof.name}.rules").read_text(encoding="utf-8")
    return dataclasses.replace(prof, custom_rules=tuple(profile.parse_rules(text)))


def plan(prof: profile.Profile, tv_ip: str = TV.ip) -> list[str]:
    return prof.adguard_rules("10.10.10.1", tv_ip)


# ---- the rules the model reads ------------------------------------------------------------------------
@pytest.mark.parametrize(
    ("line", "kind", "exception", "important", "target"),
    [
        ("||alphonso.tv^", listguard.HOST, False, False, "alphonso.tv"),
        ("@@||alphonso.tv^$important", listguard.HOST, True, True, "alphonso.tv"),
        ("||*.example.org^", listguard.PATTERN, False, False, "||*.example.org^"),
        (
            "/^ads[0-9]+\\.example\\.org$/$important",
            listguard.REGEX,
            False,
            True,
            "^ads[0-9]+\\.example\\.org$",
        ),
        ("/^ads\\.example\\.org$/", listguard.REGEX, False, False, "^ads\\.example\\.org$"),
        ("0.0.0.0 ads.example.org", listguard.HOSTS, False, False, "ads.example.org"),
        ("ads.example.org", listguard.HOSTS, False, False, "ads.example.org"),
    ],
)
def test_each_form_of_rule_is_read(line, kind, exception, important, target):
    (r,) = parse(line)
    assert (r.kind, r.exception, r.important, r.target) == (kind, exception, important, target)


@pytest.mark.parametrize(
    "line", ["", "! a comment", "# a hosts comment", "[Adblock Plus 2.0]", "127.0.0.1 localhost"]
)
def test_comments_and_local_names_hold_no_rule(line):
    assert parse(line) == []


@pytest.mark.parametrize(
    "line", ["||ads.example.org^$third-party", "/([/$important", "@@$important", "||ads.example.org^$app=x"]
)
def test_a_line_the_model_cannot_read_is_none_never_a_guess(line):
    """AdGuard drops a rule with a modifier it does not know; the model does too, and the scan counts it."""
    assert parse(line) is None


def test_a_hosts_line_with_an_address_of_its_own_answers_rather_than_blocks():
    (r,) = parse("203.0.113.5 ads.example.org")
    assert r.answer == "203.0.113.5" and r.rewrites
    assert engine(("list", ["203.0.113.5 ads.example.org"])).decide("ads.example.org").state == REWRITTEN


# ---- the model of AdGuard's precedence --------------------------------------------------------------------
@pytest.mark.parametrize(
    ("block", "exception", "state"),
    [
        ("||ads.example.org^", "@@||ads.example.org^", ALLOWED),
        ("||ads.example.org^$important", "@@||ads.example.org^", BLOCKED),
        ("||ads.example.org^$important", "@@||ads.example.org^$important", ALLOWED),
        ("||ads.example.org^", "@@||ads.example.org^$important", ALLOWED),
        ("0.0.0.0 ads.example.org", "@@||ads.example.org^", ALLOWED),
        ("||example.org^$important", "@@||ads.example.org^", BLOCKED),
        ("||example.org^", "@@||ads.example.org^", ALLOWED),
    ],
)
def test_precedence_is_important_exception_then_important_then_exception_then_block(block, exception, state):
    """urlfilter's IsHigherPriority, whichever source each rule sits in and in either order."""
    assert engine(("profile", [block]), ("list", [exception])).decide("ads.example.org").state == state
    assert engine(("list", [exception]), ("profile", [block])).decide("ads.example.org").state == state


def test_a_hosts_line_counts_only_when_no_network_rule_matches_and_only_for_its_own_name():
    e = engine(("list", ["0.0.0.0 ads.example.org"]))
    assert e.decide("ads.example.org").state == BLOCKED
    assert e.decide("sub.ads.example.org").state == NONE


def test_badfilter_deletes_the_rule_it_names_from_any_source_and_nothing_else():
    e = engine(
        ("profile", ["||ads.example.org^$important"]), ("list", ["||ads.example.org^$important,badfilter"])
    )
    assert e.decide("ads.example.org").state == NONE
    other = engine(("profile", ["||ads.example.org^$important"]), ("list", ["||ads.example.org^$badfilter"]))
    assert other.decide("ads.example.org").state == BLOCKED  # the modifiers differ: another rule


def test_a_rewrite_answers_first_unless_an_exception_carrying_dnsrewrite_covers_it():
    e = engine(
        ("profile", ["@@||clock.example.org^$important"]),
        ("list", ["||clock.example.org^$dnsrewrite=NXDOMAIN"]),
    )
    assert e.decide("clock.example.org").state == REWRITTEN
    off = engine(
        ("profile", ["||files.example.org^$dnsrewrite=10.10.10.1"]),
        ("list", ["@@||files.example.org^$dnsrewrite"]),
    )
    assert off.decide("files.example.org").state == NONE


@pytest.mark.parametrize(
    ("line", "state"),
    [
        ("||ads.example.org^$dnstype=HTTPS|SVCB", NONE),
        ("||ads.example.org^$dnstype=~HTTPS", BLOCKED),
        ("||ads.example.org^$client=192.0.2.9", NONE),
        ("||ads.example.org^$client=10.10.10.0/24", BLOCKED),
        ("||ads.example.org^$client=~10.10.10.17", NONE),
        ("||ads.example.org^$client='tv'", BLOCKED),
        ("||ads.example.org^$ctag=device_tv", BLOCKED),
        ("||ads.example.org^$ctag=device_pc", NONE),
        ("||example.org^$denyallow=ads.example.org", NONE),
    ],
)
def test_a_rule_counts_only_for_the_tvs_a_lookup_when_its_modifiers_say_so(line, state):
    assert engine(("list", [line])).decide("ads.example.org").state == state


# ---- item 1: the profile's red-line blocks hold against a list's exception ---------------------------------
def test_a_lists_plain_exception_no_longer_lifts_the_profiles_acr_block(lg):
    """The test the brief asks for: with the profile as written, a subscribed list's `@@||alphonso.tv^`
    unblocked LG's ACR operator (AdGuard's precedence: a plain exception beats a plain block); as loaded,
    the block carries `$important` and holds."""
    listed = ("HaGeZi Pro", ["@@||alphonso.tv^"])
    before = Engine([("profile", rules(*plan(as_written(lg)))), ("HaGeZi Pro", rules(*listed[1]))], TV)
    assert (
        before.decide("alphonso.tv").state == ALLOWED
        and before.decide("alphonso.tv").hit.source == "HaGeZi Pro"
    )
    after = Engine([("profile", rules(*plan(lg))), ("HaGeZi Pro", rules(*listed[1]))], TV)
    verdict = after.decide("alphonso.tv")
    assert verdict.state == BLOCKED and verdict.hit.rule.text == "||alphonso.tv^$important"
    assert after.decide("sdk.alphonso.tv").state == BLOCKED  # and every name under it


def test_the_owners_allow_still_lifts_a_held_block_on_purpose(lg):
    e = Engine(
        [
            ("profile", rules(*plan(lg))),
            ("local", rules("@@||alphonso.tv^$important")),
            ("HaGeZi Pro", rules("||alphonso.tv^$important")),
        ],
        TV,
    )
    verdict = e.decide("alphonso.tv")
    assert verdict.state == ALLOWED and verdict.hit.source == "local"


@pytest.mark.parametrize("name", profile.bundled_names())
def test_every_must_allow_host_is_untouched_and_beats_any_lists_block(name):
    """The must-allow hosts answer as before the change, and no list line short of a `$badfilter` refuses
    them: their exceptions carry `$important`, and so outrank a list's `$important` block too."""
    prof = profile.load(name)
    for host in prof.must_allow:
        parent = host.split(".", 1)[1]
        hostile = [
            f"||{host}^",
            f"||{host}^$important",
            f"||{parent}^$important",
            f"0.0.0.0 {host}",
            f"@@||{host}^",
        ]
        for p in (prof, as_written(prof)):
            e = Engine([("profile", rules(*plan(p))), ("list", rules(*hostile))], TV)
            verdict = e.decide(host)
            assert verdict.state == ALLOWED and verdict.hit.rule.text == f"@@||{host}^$important", host


@pytest.mark.parametrize("name", profile.bundled_names())
def test_every_held_block_of_every_profile_holds_and_no_other_block_changes(name):
    """Each block the load holds is a red-line category's, and holds against a plain exception for its
    name; each block it leaves plain answers exactly as before. What is blocked today does not change."""
    prof = profile.load(name)
    written = as_written(prof)
    for raw, held in zip(written.custom_rules, prof.custom_rules, strict=True):
        kind, target = profile.rule_target(raw)
        if kind != "block" or not target:
            continue
        cat = prof.categorize(target)
        list_rule = f"@@||{target}^"
        lifted = Engine([("profile", rules(*plan(prof))), ("list", rules(list_rule))], TV).decide(target)
        if profile.held_category(cat):
            assert held == raw + "$important" and lifted.state == BLOCKED, (held, cat)
        else:
            assert held == raw and lifted.state == ALLOWED, (held, cat)
        alone_before = Engine([("profile", rules(*plan(written)))], TV).decide(target)
        alone_after = Engine([("profile", rules(*plan(prof)))], TV).decide(target)
        assert alone_before.state == alone_after.state, target


def test_the_red_line_categories_are_acr_and_the_vendors_ads_telemetry_and_fingerprinting():
    held = [
        c
        for c in ("ACR", "ACR suspected (shared AWS)", "LG ads", "LG telemetry", "LG fingerprint", "Roku ads")
    ]
    plain = [
        "3rd-party ads",
        "Voice",
        "LG IoT",
        "LG core",
        "Streaming",
        "FAST",
        "Infra",
        "Other",
        "SmartThings",
    ]
    assert all(profile.held_category(c) for c in held)
    assert not any(profile.held_category(c) for c in plain)


def test_a_regex_block_takes_the_category_of_the_names_it_reaches(lg):
    nevo = "/^([a-z0-9]+-)?nevoai-iothub-[0-9]+-prod\\.azure-devices\\.net$/"
    assert profile.regex_category(lg, nevo) == "LG fingerprint"
    assert profile.regex_category(lg, "/-panelresearch\\.googlevideo\\.com$/") == "3rd-party ads"
    assert profile.regex_category(lg, "/^nothing-the-profile-names\\.example$/") is None
    assert profile.held_rule(lg, nevo) == nevo + "$important"
    assert (
        profile.held_rule(lg, "/^nothing-the-profile-names\\.example$/")
        == "/^nothing-the-profile-names\\.example$/"
    )


def test_a_rule_already_carrying_a_modifier_or_written_as_a_hosts_line_is_left_as_written(lg):
    for raw in (
        "||alphonso.tv^$dnstype=HTTPS",
        "0.0.0.0 alphonso.tv",
        "@@||alphonso.tv^",
        "||*.alphonso.tv^",
    ):
        assert profile.held_rule(lg, raw) == raw


def test_the_lint_reads_important_as_adguard_does(lg):
    """A plain exception over a held block lifts nothing, so it is refused as dead; one carrying
    `$important` lifts it, as before; an `$important` block over a must-allow name is refused like any."""
    dead = dataclasses.replace(lg, custom_rules=(*lg.custom_rules, "@@||alphonso.tv^")).lint()
    assert any("carries $important, so it does nothing" in p for p in dead), dead
    lifts = dataclasses.replace(lg, custom_rules=(*lg.custom_rules, "@@||alphonso.tv^$important")).lint()
    assert any("would unblock it" in p for p in lifts), lifts
    assert (
        dataclasses.replace(lg, custom_rules=(*lg.custom_rules, "@@||alphonso.tv^$important")).lint(
            frozenset({"alphonso.tv"})
        )
        == []
    )  # the owner's allow, which lifts it on purpose
    over = dataclasses.replace(lg, custom_rules=(*lg.custom_rules, "||snu.lge.com^$important")).lint()
    assert any("covers must-allow snu.lge.com" in p for p in over), over
    plain_over = dataclasses.replace(lg, custom_rules=(*lg.custom_rules, "@@||wurl.dev^")).lint()
    assert any("would unblock it" in p for p in plain_over), plain_over


def test_the_restart_guards_probe_name_may_be_a_held_block(lg):
    assert adguardcfg._locally_blocked(plan(lg)) == "alphonso.tv"
    roku = profile.load("roku")
    assert all(r.endswith("$important") for r in roku.custom_rules)
    assert adguardcfg._locally_blocked(plan(roku)) == "scribe.logs.roku.com"


def test_a_plain_proposal_is_already_in_place_over_the_held_block(lg):
    assert profile.held_twin("||alphonso.tv^") == "||alphonso.tv^$important"
    assert profile.held_twin("@@||alphonso.tv^") == "@@||alphonso.tv^"
    assert profile.held_twin("||alphonso.tv^$dnstype=HTTPS") == "||alphonso.tv^$dnstype=HTTPS"
