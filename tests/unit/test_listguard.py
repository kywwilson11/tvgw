"""(listguard) The pushed-content guard (design decision 68): the profile's red-line blocks held with
`$important`, the model of AdGuard's precedence that proves it, the scan of the subscribed lists for lines
that act on the TV's own rules, and the preview of what a list's update changed.

The lists are GPL-3.0 and their text never enters the repository: every list line here is written for the
test, in the forms the published lists use."""

import dataclasses
import gzip
import json
import os
from importlib import resources
from pathlib import Path

import pytest
import yaml

from tvgw import adguardcfg, db, listguard, profile
from tvgw.config import Settings
from tvgw.listguard import ALLOWED, BLOCKED, EXPOSES, HELD, LIFTS, NONE, REWRITTEN, Client, Engine, parse

TV = Client("10.10.10.17", "tv")
NOW = 1793020000.0  # 2026-10-26
DAY = 86400.0


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


# ---- item 2: the scan ---------------------------------------------------------------------------------------
LIST = listguard.ListFile(1792975976, "Test list", "https://lists.example/test.txt", "")


def scan(lg, lines: list[str], local: list[str] = (), tv: Client = TV):
    groups = {"profile": plan(lg), "local": list(local), "machine": []}
    return listguard.scan([(LIST, lines)], groups, lg, tv)


def kinds(found) -> list[tuple[str, str, str]]:
    return [(f.kind, f.line, f.target) for f in found]


def test_a_plain_exception_over_a_held_block_is_held_and_one_carrying_important_lifts_it(lg):
    found, stats = scan(lg, ["@@||alphonso.tv^", "@@||lgads.tv^$important"])
    assert kinds(found) == [
        (LIFTS, "@@||lgads.tv^$important", "||lgads.tv^$important"),
        (HELD, "@@||alphonso.tv^", "||alphonso.tv^$important"),
    ]
    assert stats[LIST.id] == {"exceptions": 2, "unread": 0}


def test_a_plain_exception_over_a_block_outside_the_red_line_categories_lifts_it(lg):
    found, _ = scan(lg, ["@@||wurl.dev^"])
    assert kinds(found) == [(LIFTS, "@@||wurl.dev^", "||wurl.dev^")]


def test_an_exception_under_or_over_a_blocked_name_reaches_it(lg):
    found, _ = scan(lg, ["@@||sdk.alphonso.tv^", "@@||nudge.lgtvcommon.com^"])
    assert (HELD, "@@||sdk.alphonso.tv^", "||alphonso.tv^$important") in kinds(found)
    wide, _ = scan(lg, ["@@||lgtvcommon.com^"])
    targets = {f.target for f in wide}
    assert "||cdpbeacon.lgtvcommon.com^$important" in targets and all(f.kind == HELD for f in wide)


def test_an_exception_over_a_regex_block_is_judged_on_the_names_the_regex_reaches(lg):
    found, _ = scan(lg, ["@@||azure-devices.net^", "@@||googlevideo.com^"])
    got = kinds(found)
    assert (
        HELD,
        "@@||azure-devices.net^",
        "/^([a-z0-9]+-)?nevoai-iothub-[0-9]+-prod\\.azure-devices\\.net$/$important",
    ) in got
    assert (LIFTS, "@@||googlevideo.com^", "/-panelresearch\\.googlevideo\\.com$/") in got
    assert (LIFTS, "@@||googlevideo.com^", "||eligibility-panelresearch.googlevideo.com^") in got


def test_a_regex_or_unanchored_exception_reaches_the_names_it_matches(lg):
    found, _ = scan(lg, ["@@/alphonso/", "@@alphonso.tv^"])
    assert {f.kind for f in found} == {HELD} and len(found) == 2


def test_a_badfilter_naming_a_block_lifts_it_and_one_naming_a_must_allow_exception_exposes_it(lg):
    found, _ = scan(lg, ["||alphonso.tv^$important,badfilter", "@@||us.lgtvsdp.com^$important,badfilter"])
    assert kinds(found) == [
        (EXPOSES, "@@||us.lgtvsdp.com^$important,badfilter", "@@||us.lgtvsdp.com^$important"),
        (LIFTS, "||alphonso.tv^$important,badfilter", "||alphonso.tv^$important"),
    ]
    stale, _ = scan(lg, ["||alphonso.tv^$badfilter"])  # names the rule as written before the load held it
    assert stale == []


def test_a_list_that_rewrites_a_must_allow_name_or_cancels_the_url_filter_exposes_it(lg):
    found, _ = scan(lg, ["||us.lgtvsdp.com^$dnsrewrite=NXDOMAIN", "@@||ngfts.lge.com^$dnsrewrite"])
    got = kinds(found)
    assert (EXPOSES, "||us.lgtvsdp.com^$dnsrewrite=NXDOMAIN", "@@||us.lgtvsdp.com^$important") in got
    assert (EXPOSES, "@@||ngfts.lge.com^$dnsrewrite", "||ngfts.lge.com^$dnsrewrite=10.10.10.1") in got


def test_a_lists_block_of_a_must_allow_name_is_no_finding_the_exception_outranks_it(lg):
    found, _ = scan(lg, ["||us.lgtvsdp.com^$important", "||nextlgsdp.com^", "0.0.0.0 snu.lge.com"])
    assert found == []


def test_an_exception_for_another_client_or_another_record_type_is_no_finding(lg):
    found, _ = scan(lg, ["@@||alphonso.tv^$client=192.0.2.9", "@@||wurl.dev^$dnstype=AAAA"])
    assert found == []


def test_the_owners_block_is_scanned_and_named_as_the_owners(lg):
    found, _ = scan(lg, ["@@||voice.example^"], local=["||voice.example^"])
    assert [(f.kind, f.source) for f in found] == [(LIFTS, "local")]


def test_lines_the_model_cannot_read_are_counted_never_skipped_silently(lg):
    _, stats = scan(lg, ["@@||alphonso.tv^$app=x", "@@||wurl.dev^", "||plain.example^"])
    assert stats[LIST.id] == {"exceptions": 1, "unread": 1}


def test_a_long_line_is_cut_and_the_findings_are_capped(lg, monkeypatch):
    monkeypatch.setattr(listguard, "FINDINGS_CAP", 3)
    long = "@@||alphonso.tv^$client=" + "|".join(["10.10.10.17"] * 40)
    found, _ = scan(lg, [long, "@@||wurl.dev^", "@@||wurl.tv^", "@@||doubleclick.net^", "@@||conviva.com^"])
    assert len(found) == 3 and all(len(f.line) <= listguard.LINE_CAP for f in found)


# ---- item 4: the preview ----------------------------------------------------------------------------------
def test_the_preview_names_what_an_update_newly_blocks_and_newly_allows_for_the_tv(lg):
    groups = {"profile": plan(lg), "local": [], "machine": []}
    before = ["||tracker.example^", "||cdn.example^"]
    after = ["||cdn.example^", "||video.example^", "||alphonso.tv^", "@@||wurl.dev^", "||us.lgtvsdp.com^"]
    names = [
        ("video.example", 40),
        ("tracker.example", 3),
        ("wurl.dev", 2),
        ("alphonso.tv", 9),
        ("us.lgtvsdp.com", 30),
    ]
    got = listguard.preview(
        before, after, [("Other list", ["||cdn.example^"])], groups, names, TV, "Test list"
    )
    assert [(x["name"], x["rule"], x["by"]) for x in got["newly_blocked"]] == [
        ("video.example", "||video.example^", "Test list")
    ]
    assert [(x["name"], x["by"]) for x in got["newly_allowed"]] == [
        ("wurl.dev", "profile"),
        ("tracker.example", "Test list"),
    ] or [(x["name"], x["by"]) for x in got["newly_allowed"]] == [
        ("tracker.example", "Test list"),
        ("wurl.dev", "profile"),
    ]
    assert got["names"] == 5 and got["more_blocked"] == 0


def test_the_preview_caps_each_direction_and_says_how_many_more(lg, monkeypatch):
    monkeypatch.setattr(listguard, "NAMES_CAP", 2)
    groups = {"profile": [], "local": [], "machine": []}
    names = [(f"n{i}.example", i) for i in range(5)]
    got = listguard.preview([], [f"||n{i}.example^" for i in range(5)], [], groups, names, TV)
    assert [x["name"] for x in got["newly_blocked"]] == ["n4.example", "n3.example"] and got[
        "more_blocked"
    ] == 3


# ---- the step: the lists AdGuard holds, the copies, the state ---------------------------------------------
@pytest.fixture
def gw(tmp_path):
    (tmp_path / "data" / "filters").mkdir(parents=True)
    (tmp_path / "state").mkdir()
    s = Settings(
        tv_ip=TV.ip,
        tv_name=TV.name,
        state_dir=str(tmp_path / "state"),
        db_path=str(tmp_path / "state" / "tvgw.db"),
        adguard_yaml=str(tmp_path / "AdGuardHome.yaml"),
        adguard_querylog=str(tmp_path / "data" / "querylog.json"),
        auto_rules=str(tmp_path / "state" / "auto.rules"),
        local_rules=str(tmp_path / "etc" / "local.rules"),
    )
    lists = [
        {"enabled": True, "id": 11, "name": "List A", "url": "https://lists.example/a.txt"},
        {"enabled": True, "id": 12, "name": "List B", "url": "https://lists.example/b.txt"},
        {"enabled": False, "id": 13, "name": "Off", "url": "https://lists.example/off.txt"},
    ]
    Path(s.adguard_yaml).write_text(yaml.safe_dump({"filters": lists, "user_rules": []}), encoding="utf-8")
    return s


def put(s: Settings, list_id: int, *lines: str, at: float | None = None) -> None:
    path = Path(os.path.dirname(s.adguard_querylog)) / "filters" / f"{list_id}.txt"
    path.write_text("! Title: a test list\n" + "".join(f"{x}\n" for x in lines), encoding="utf-8")
    if at is not None:
        os.utime(path, (at, at))


def lookups(conn, *names: tuple[str, float]) -> None:
    conn.executemany("INSERT INTO dns(qname, t, qtype, blocked) VALUES (?, ?, 'A', 0)", names)


def test_the_first_run_scans_keeps_a_copy_of_each_list_and_previews_nothing(gw, lg):
    put(gw, 11, "||cdn.example^", "@@||alphonso.tv^")
    put(gw, 12, "@@||wurl.dev^")
    conn = db.connect(gw.db_path)
    done = listguard.run(conn, gw, lg, now=NOW)
    assert done["scanned"] and done["previews"] == 0
    state = listguard.load_state(conn)
    assert [(e["id"], e["state"]) for e in state["lists"]] == [(11, "ok"), (12, "ok")]
    assert {(f["kind"], f["list"], f["first"]) for f in state["findings"]} == {
        (HELD, "List A", NOW),
        (LIFTS, "List B", NOW),
    }
    with gzip.open(listguard.copy_path(gw, 11), "rt", encoding="utf-8") as fh:
        assert fh.read() == "||cdn.example^\n@@||alphonso.tv^\n"  # the rule lines only
    assert oct(os.stat(listguard.copy_path(gw, 11)).st_mode & 0o777) == "0o640"


def test_nothing_changed_is_no_scan_until_a_day_has_passed(gw, lg):
    put(gw, 11, "||cdn.example^", at=NOW - 60)
    put(gw, 12, "||ads.example^", at=NOW - 60)
    conn = db.connect(gw.db_path)
    listguard.run(conn, gw, lg, now=NOW)
    assert not listguard.run(conn, gw, lg, now=NOW + 3600)["scanned"]
    assert listguard.run(conn, gw, lg, now=NOW + listguard.SCAN_EVERY)["scanned"]
    assert listguard.run(conn, gw, lg, now=NOW + listguard.SCAN_EVERY + 1, force=True)["scanned"]


def test_a_changed_list_is_previewed_against_its_copy_with_the_tvs_lookups(gw, lg):
    put(gw, 11, "||tracker.example^", at=NOW - 60)
    put(gw, 12, "||ads.example^", at=NOW - 60)
    conn = db.connect(gw.db_path)
    lookups(
        conn, ("video.example", NOW - DAY), ("video.example", NOW - 2 * DAY), ("tracker.example", NOW - DAY)
    )
    lookups(conn, ("old.example", NOW - 20 * DAY))  # outside the 14 days
    listguard.run(conn, gw, lg, now=NOW)
    put(gw, 11, "||video.example^", "||old.example^", at=NOW + 3000)
    done = listguard.run(conn, gw, lg, now=NOW + 3600)
    assert done["scanned"] and done["previews"] == 1
    (event,) = listguard.load_previews(conn)
    assert event["list"] == "List A" and event["t"] == NOW + 3600
    assert [(x["name"], x["lookups"]) for x in event["newly_blocked"]] == [("video.example", 2)]
    assert [x["name"] for x in event["newly_allowed"]] == ["tracker.example"]
    with gzip.open(listguard.copy_path(gw, 11), "rt", encoding="utf-8") as fh:
        assert "||video.example^" in fh.read()  # the copy is now the new version


def test_previews_name_what_the_tv_looked_up_and_go_after_14_days(gw, lg):
    put(gw, 11, "||a.example^", at=NOW - 60)
    conn = db.connect(gw.db_path)
    listguard.run(conn, gw, lg, now=NOW)
    put(gw, 11, "||b.example^", at=NOW + 100)
    listguard.run(conn, gw, lg, now=NOW + 200)
    assert len(listguard.load_previews(conn)) == 1
    put(gw, 11, "||c.example^", at=NOW + listguard.PREVIEW_KEEP + 300)
    listguard.run(conn, gw, lg, now=NOW + listguard.PREVIEW_KEEP + 400)
    assert [e["t"] for e in listguard.load_previews(conn)] == [NOW + listguard.PREVIEW_KEEP + 400]


def test_a_finding_keeps_its_first_sight_and_goes_when_no_list_carries_it(gw, lg):
    put(gw, 11, "@@||wurl.dev^", at=NOW - 60)
    conn = db.connect(gw.db_path)
    listguard.run(conn, gw, lg, now=NOW)
    put(gw, 11, "@@||wurl.dev^", "||x.example^", at=NOW + 10)
    listguard.run(conn, gw, lg, now=NOW + 3600)
    (f,) = listguard.load_state(conn)["findings"]
    assert (f["first"], f["last"]) == (NOW, NOW + 3600)
    put(gw, 11, "||x.example^", at=NOW + 20)
    listguard.run(conn, gw, lg, now=NOW + 7200)
    state = listguard.load_state(conn)
    assert state["findings"] == [] and state["gone"][0]["gone"] == NOW + 7200
    view = listguard.brief_view(conn, NOW - 1, NOW + 1)
    assert [f["line"] for f in view["new"]] == ["@@||wurl.dev^"]
    assert listguard.brief_view(conn, NOW + 7300, NOW + 9000)["findings"] == []


def test_a_list_not_downloaded_yet_is_missing_and_one_no_longer_subscribed_loses_its_copy(gw, lg):
    put(gw, 11, "||a.example^")
    conn = db.connect(gw.db_path)
    listguard.run(conn, gw, lg, now=NOW)
    assert [e["state"] for e in listguard.load_state(conn)["lists"]] == ["ok", "missing"]
    cfg = yaml.safe_load(Path(gw.adguard_yaml).read_text(encoding="utf-8"))
    cfg["filters"] = cfg["filters"][1:]
    Path(gw.adguard_yaml).write_text(yaml.safe_dump(cfg), encoding="utf-8")
    listguard.run(conn, gw, lg, now=NOW + 60)
    assert not os.path.exists(listguard.copy_path(gw, 11))


def test_a_broken_copy_previews_nothing_and_is_replaced(gw, lg):
    put(gw, 11, "||a.example^", at=NOW - 60)
    conn = db.connect(gw.db_path)
    listguard.run(conn, gw, lg, now=NOW)
    Path(listguard.copy_path(gw, 11)).write_bytes(b"not gzip")
    put(gw, 11, "||b.example^", at=NOW + 10)
    assert listguard.run(conn, gw, lg, now=NOW + 60)["previews"] == 0
    assert listguard.read_copy(listguard.copy_path(gw, 11)) == ["||b.example^"]


def test_no_adguard_settings_file_is_no_list_and_no_failure(gw, lg):
    os.unlink(gw.adguard_yaml)
    conn = db.connect(gw.db_path)
    assert listguard.run(conn, gw, lg, now=NOW)["lists"] == 0


def test_a_half_written_adguard_file_changes_nothing_until_the_next_run(gw, lg):
    put(gw, 11, "@@||wurl.dev^")
    conn = db.connect(gw.db_path)
    listguard.run(conn, gw, lg, now=NOW)
    before = db.get_meta(conn, listguard.META_KEY)
    Path(gw.adguard_yaml).write_text("filters: [\n", encoding="utf-8")
    assert not listguard.run(conn, gw, lg, now=NOW + listguard.SCAN_EVERY)["scanned"]
    assert db.get_meta(conn, listguard.META_KEY) == before


def test_a_list_file_that_cannot_be_read_fails_the_step(gw, lg):
    put(gw, 11, "||a.example^")
    path = Path(os.path.dirname(gw.adguard_querylog)) / "filters" / "11.txt"
    path.chmod(0)
    conn = db.connect(gw.db_path)
    try:
        if os.geteuid() == 0:
            pytest.skip("root reads a file of mode 0")
        with pytest.raises(PermissionError):
            listguard.run(conn, gw, lg, now=NOW)
    finally:
        path.chmod(0o644)


def test_the_tvs_rules_changing_is_a_scan_of_its_own(gw, lg):
    put(gw, 11, "@@||voice.example^", at=NOW - 60)
    conn = db.connect(gw.db_path)
    listguard.run(conn, gw, lg, now=NOW)
    assert listguard.load_state(conn)["findings"] == []
    os.makedirs(os.path.dirname(gw.local_rules))
    Path(gw.local_rules).write_text("||voice.example^\n", encoding="utf-8")
    assert listguard.run(conn, gw, lg, now=NOW + 60)["scanned"]
    assert [f["source"] for f in listguard.load_state(conn)["findings"]] == ["local"]


def test_the_state_carries_no_name_the_tv_looked_up(gw, lg):
    """meta.list_guard is policy (the lists' lines and the TV's rules) and stays through a forget;
    the names the TV asked for live only in meta.list_preview, which a forget removes."""
    put(gw, 11, "||a.example^", at=NOW - 60)
    conn = db.connect(gw.db_path)
    lookups(conn, ("secret-show.example", NOW - DAY))
    listguard.run(conn, gw, lg, now=NOW)
    put(gw, 11, "||secret-show.example^", at=NOW + 10)
    listguard.run(conn, gw, lg, now=NOW + 60)
    assert "secret-show" not in db.get_meta(conn, listguard.META_KEY)
    assert "secret-show" in db.get_meta(conn, listguard.PREVIEW_KEY)
    from tvgw import forget

    assert listguard.PREVIEW_KEY in forget.META_FORGET and listguard.META_KEY not in forget.META_FORGET
    assert json.loads(db.get_meta(conn, listguard.META_KEY))["lists"][0]["copy"]


# ---- the brief, the red lines, verify and `tvgw lists` ---------------------------------------------------
def finding(kind: str, first: float, source: str = "profile", **extra) -> dict:
    return {
        "kind": kind,
        "list": "Test list",
        "url": "https://lists.example/test.txt",
        "line": "@@||wurl.dev^",
        "target": "||wurl.dev^",
        "source": source,
        "first": first,
        "last": first,
        **extra,
    }


def store_state(conn, findings: list[dict], gone: list[dict] = (), previews: list[dict] = ()) -> None:
    state = {"t": NOW, "rules_sha": "x", "lists": [{"id": 11, "name": "Test list", "state": "ok"}]}
    db.set_meta(conn, listguard.META_KEY, json.dumps({**state, "findings": findings, "gone": list(gone)}))
    db.set_meta(conn, listguard.PREVIEW_KEY, json.dumps(list(previews)))


def test_a_red_line_on_the_day_a_lifting_line_first_appears_and_none_for_a_held_one(tmp_path):
    from tvgw import queries

    conn = db.connect(str(tmp_path / "tvgw.db"))
    store_state(
        conn,
        [
            finding(LIFTS, NOW),
            finding(HELD, NOW, line="@@||alphonso.tv^", target="||alphonso.tv^$important"),
            finding(LIFTS, NOW, source="local", line="@@||voice.example^", target="||voice.example^"),
            finding(
                EXPOSES,
                NOW,
                line="@@||us.lgtvsdp.com^$important,badfilter",
                target="@@||us.lgtvsdp.com^$important",
            ),
        ],
    )
    o: dict = {}
    queries._guard_keys(o, conn, NOW - 10, NOW + DAY)
    lines = queries.red_lines({**o, "coverage": {"sources": {}}, "since": NOW - 10, "until": NOW + DAY})
    assert lines[0].startswith(
        "a list can refuse what the TV needs: Test list carries @@||us.lgtvsdp.com^$important,badfilter, which"
        " overrides @@||us.lgtvsdp.com^$important (first seen "
    )
    assert lines[1].startswith(
        "a list lifts the profile's block ||wurl.dev^: Test list carries @@||wurl.dev^"
    )
    assert lines[2].startswith(
        "a list lifts your block ||voice.example^: Test list carries @@||voice.example^"
    )
    assert len(lines) == 3
    later: dict = {}
    queries._guard_keys(later, conn, NOW + DAY, NOW + 2 * DAY)  # the next day: listed, not a red line
    assert queries.red_lines({**later, "coverage": {"sources": {}}}) == []
    assert len(later["list_guard"]["findings"]) == 4


def test_the_new_red_lines_stay_in_the_engineering_brief_and_never_buy_a_request():
    from tvgw import analyst, plain

    for line in ("a list lifts the profile's block ||x^: ...", "a list can refuse what the TV needs: ..."):
        assert plain.tier(line)[0] == "detail"
        assert line.startswith(analyst.HEALTH_RED_LINES)


def test_a_gateway_that_never_scanned_writes_the_brief_it_wrote_before(tmp_path):
    from tvgw import queries

    conn = db.connect(str(tmp_path / "tvgw.db"))
    o: dict = {}
    queries._guard_keys(o, conn, NOW, NOW + DAY)
    assert "list_guard" not in o and "doh_hold" not in o


def test_the_brief_prints_the_lines_and_the_previews_with_their_content_mark(tmp_path):
    import io

    from tvgw import cli, queries

    conn = db.connect(str(tmp_path / "tvgw.db"))
    event = {
        "t": NOW + 60,
        "id": 11,
        "list": "Test list",
        "url": "https://lists.example/test.txt",
        "names": 812,
        "newly_blocked": [
            {"name": "video.example", "lookups": 40, "rule": "||video.example^", "by": "Test list"}
        ],
        "newly_allowed": [
            {"name": "tracker.example", "lookups": 3, "rule": "||tracker.example^", "by": "Test list"}
        ],
        "more_blocked": 2,
        "more_allowed": 0,
    }
    store_state(
        conn,
        [finding(HELD, NOW, line="@@||alphonso.tv^", target="||alphonso.tv^$important")],
        previews=[event],
    )
    o: dict = {}
    queries._guard_keys(o, conn, NOW - 10, NOW + DAY)
    out = io.StringIO()
    cli.render_list_guard(o["list_guard"], out)
    text = out.getvalue()
    assert "List guard (lines of the subscribed lists that act on the TV's own rules;" in text
    assert "held off  Test list  @@||alphonso.tv^  ||alphonso.tv^$important" in text
    assert "newly blocks  video.example    40" in text and "and 2 more" in text and "newly allows" in text
    assert o["list_guard"]["previews"][0]["newly_blocked"][0]["content"] is False  # no flows: no content
    empty = io.StringIO()
    cli.render_list_guard({"findings": [], "previews": []}, empty)
    assert empty.getvalue() == ""


def test_verify_warns_while_a_doh_refresh_is_held_and_the_brief_says_so_for_the_days_it_covered(tmp_path):
    from tvgw import cli, queries, verify

    record = {"since": NOW, "t": NOW + DAY, "in_force": 1493, "fetched": 600, "dropped": 900, "max": 20}
    check, hold = verify.doh_hold_check("held", lambda path: json.dumps(record))
    assert check.ok and check.warn and hold == record
    assert (
        "would drop 900 of the 1493 entries in force (60%, over 20%); the list in force is kept"
        in check.detail
    )
    assert verify.doh_hold_check("held", lambda path: "") == (verify.Check("doh4_held", True, ""), None)
    broken, _ = verify.doh_hold_check("held", lambda path: "{")
    assert broken.ok and broken.warn and broken.detail == "doh4.held cannot be read"
    conn = db.connect(str(tmp_path / "tvgw.db"))
    verify.record(conn, verify.Result(t=NOW + DAY, doh_hold=record))
    assert queries.doh_hold(conn, NOW, NOW + 2 * DAY)["cleared"] is None
    verify.record(conn, verify.Result(t=NOW + 3 * DAY))  # the next refresh was taken: the file is gone
    assert queries.doh_hold(conn, NOW + 2 * DAY, NOW + 4 * DAY)["cleared"] == NOW + 3 * DAY
    assert queries.doh_hold(conn, NOW + 4 * DAY, NOW + 5 * DAY) is None
    assert queries.doh_hold(conn, NOW - 2 * DAY, NOW - DAY) is None
    line = cli.doh_line(queries.doh_hold(conn, NOW, NOW + 4 * DAY))
    assert (
        line.startswith("DoH list: kept in force since ")
        and "would drop 900 of its 1493 entries (60%, over 20%)" in line
    )
    assert "; a refresh was taken at " in line


def test_tvgw_lists_reads_the_last_scan_and_exits_1_on_a_line_that_lifts_a_block(tmp_path, capsys):
    from tvgw import cli

    conf = tmp_path / "tvgw.conf"
    conf.write_text(f'DB_PATH="{tmp_path / "tvgw.db"}"\nSTATE_DIR="{tmp_path}"\n', encoding="utf-8")
    conn = db.connect(str(tmp_path / "tvgw.db"))
    conn.commit()
    assert cli.main(["--conf", str(conf), "lists"]) == 0
    assert "no scan yet" in capsys.readouterr().out
    store_state(conn, [finding(HELD, NOW, line="@@||alphonso.tv^", target="||alphonso.tv^$important")])
    conn.commit()
    assert cli.main(["--conf", str(conf), "lists"]) == 0
    out = capsys.readouterr().out
    assert "Lists AdGuard Home holds, as scanned" in out and "held off" in out
    store_state(conn, [finding(LIFTS, NOW)])
    conn.commit()
    assert cli.main(["--conf", str(conf), "lists", "--json"]) == 1
    assert json.loads(capsys.readouterr().out)["state"]["findings"][0]["kind"] == LIFTS


def test_tvgw_lists_scan_needs_root(tmp_path, capsys):
    from tvgw import cli

    if os.geteuid() == 0:
        pytest.skip("this account is root")
    conf = tmp_path / "tvgw.conf"
    conf.write_text(f'DB_PATH="{tmp_path / "tvgw.db"}"\n', encoding="utf-8")
    assert cli.main(["--conf", str(conf), "lists", "--scan"]) == 2
    assert "run it with sudo" in capsys.readouterr().out


def test_the_hourly_ingest_runs_the_scan_as_its_lists_step(gateway, lg):
    from conftest import fake_extract, fake_oddport

    from tvgw import ingest

    st = ingest.run(
        gateway, lg, extract=fake_extract, oddport_lines=fake_oddport, gate_lines=lambda s: [], lock=False
    )
    assert not [w for w in st.warnings if w.startswith("lists:")]
    conn = db.connect(gateway.db_path)
    assert listguard.load_state(conn)["lists"] == []  # the fixture's AdGuard holds no list


def test_tvgw_profile_says_how_many_blocks_no_list_can_lift(capsys):
    from tvgw import cli

    assert cli.main(["--conf", "/nonexistent/tvgw.conf", "profile", "--profile", "roku"]) == 0
    out = capsys.readouterr().out
    held = sum(r.endswith("$important") for r in profile.load("roku").custom_rules)
    assert f"held against the lists: {held} blocks in the red-line categories carry $important" in out
