"""Profiles: the bundled LG profile, loading and validation, and the categorizer semantics."""

import os
import re
import tomllib
from importlib import resources

import pytest

from tvgw import cli, profile


@pytest.mark.parametrize(
    ("host", "category"),
    [
        ("alphonso.tv", "ACR"),
        ("prov-lg.alphonso.tv", "ACR"),
        ("us.ibsstat.lgappstv.com", "LG ads"),  # longer pattern beats lgappstv.com (LG core)
        ("us.lgappstv.com", "LG core"),
        ("aic.cdpsvc.lgtvcommon.com", "LG telemetry"),  # regional prefix stripped
        ("eic-ngfts.lge.com", "LG core"),
        ("AIC.recommend.lgtvcommon.com", "LG ads"),
        ("aic.cdpbeacon2.lgtvcommon.com", "LG telemetry"),  # wildcard inside a label
        ("www.ueiwsp.com", "LG fingerprint"),
        ("he-us-ai.lgthinq.com", "LG IoT"),
        ("ingest.webcol.sdp.peacocktv.com", "3rd-party ads"),  # beats peacocktv.com (Streaming)
        ("g006-vod-us-cmaf-prd-cc.cdn.peacocktv.com", "Streaming"),
        ("rr4---sn-bvvbaxivnuxqjvhj5nu-n4v6.googlevideo.com", "Streaming"),
        ("ocsp.digicert.com", "Infra"),
        ("securetime.playready.microsoft.com", "Infra"),
        ("embeddedassistant.googleapis.com", "Voice"),
        ("www.googleapis.com", "Infra"),
        ("example.com.", "Other"),
        ("", "Other"),
    ],
)
def test_lg_categories(lg, host, category):
    assert lg.categorize(host) == category


def test_lg_profile_metadata(lg):
    assert lg.name == "lg-webos" and lg.vendor == "LG"
    assert "us.lgtvsdp.com" in lg.must_allow and "clock" in lg.must_allow["us.lgtvsdp.com"]
    assert lg.category_order[0] == "ACR" and "Streaming" in lg.category_order
    assert lg.url_filter is not None
    assert "ngfts.lge.com" in lg.url_filter.hosts


@pytest.mark.parametrize(
    ("uri", "blocked"),
    [
        ("/fts/gftsDownload.lge?biz_code=PREMIUM&func_code=ACR&file_path=/premium/acr/x", True),
        ("/fts/gftsDownload.lge?biz_code=CDP&func_code=SCHEDULE_FILE", True),
        ("/fts/gftsDownload.lge?biz_code=LGSHOPPING&func_code=DATA", True),
        ("/fts/gftsDownload.lge?biz_code=MAS&func_code=META_THUMBNAIL", True),
        ("/fts/gftsDownload.lge?biz_code=IBS&func_code=ONLINE_EPG_FILE", True),
        ("/fts/gftsDownload.lge?biz_code=mas&func_code=x", True),  # case-insensitive
        ("/fts/gftsDownload.lge?biz_code=APP_STORE&func_code=APP_ICON", False),
        ("/fts/gftsDownload.lge?biz_code=SVCSH&func_code=SVCSH_ASSET", False),
        (
            "/fts/gftsDownload.lge?biz_code=META_IMG&func_code=CPLOGO",
            False,
        ),  # 'MAS' must not match 'META_IMG'
        ("/fts/gftsDownload.lge?biz_code=MASTER&func_code=x", False),  # nor a longer code starting with MAS
        ("/fts/gftsDownload.lge?biz_code=LGSTORE", False),
        ("/fts/gftsDownload.lge?biz_code=IBS", True),  # end of string counts as a boundary
    ],
)
def test_lg_url_filter(lg, uri, blocked):
    assert lg.url_filter.blocks(uri) is blocked


def test_longest_match_and_wildcards_from_dict():
    p = profile.from_dict(
        {
            "profile": {"name": "t"},
            "categories": {
                "strip_prefixes": ["xx."],
                "A": ["example.com"],
                "B": ["tracker.example.com", "cdn*.example.net"],
            },
        }
    )
    assert p.categorize("example.com") == "A"
    assert p.categorize("deep.sub.example.com") == "A"
    assert p.categorize("tracker.example.com") == "B"
    assert p.categorize("x.tracker.example.com") == "B"
    assert p.categorize("cdn17.example.net") == "B"
    assert p.categorize("xx.tracker.example.com") == "B"  # prefix stripped once
    assert p.categorize("example.net") == "Other"
    assert p.url_filter is None and p.must_allow == {}


MINI = '[profile]\nname="mini"\n[categories]\nX=["a.b"]\n[must_allow]\n"A.B"="why"\n'


def test_load_from_toml_path(tmp_path):
    f = tmp_path / "mini.toml"
    f.write_text(MINI)
    (tmp_path / "mini.rules").write_text("")  # present and empty: the capture-phase profile
    p = profile.load(f)
    assert p.name == "mini" and p.categorize("A.B") == "X" and p.must_allow == {"a.b": "why"}
    assert p.custom_rules == () and p.adguard_rules() == ["@@||a.b^"]


def test_a_toml_without_its_rules_file_does_not_load(tmp_path):
    """Reproduced before the fix: the profile loaded as nine generated exceptions and not one block,
    lint() was clean, and apply would have replaced AdGuard's rules with that list."""
    f = tmp_path / "mini.toml"
    f.write_text(MINI)
    with pytest.raises(FileNotFoundError, match=re.escape(str(tmp_path / "mini.rules"))):
        profile.load(f)


@pytest.mark.skipif(os.geteuid() == 0, reason="root reads a mode-0 file")
def test_an_unreadable_rules_file_does_not_load(tmp_path):
    f = tmp_path / "mini.toml"
    f.write_text(MINI)
    rules = tmp_path / "mini.rules"
    rules.write_text("||x.example^\n")
    rules.chmod(0)
    try:
        with pytest.raises(PermissionError):
            profile.load(f)
    finally:
        rules.chmod(0o600)


def test_bundled_rules_come_from_the_name_loaded_not_from_profile_name(lg):
    """A renamed [profile].name must not make the bundled profile load with zero custom rules."""
    assert len(lg.custom_rules) >= 60
    text = (resources.files("tvgw.profiles") / "lg-webos.toml").read_text()
    assert profile.from_dict(tomllib.loads(text)).custom_rules == ()  # from_dict does no IO


def test_cli_reports_an_unloadable_profile_in_one_line(tmp_path):
    f = tmp_path / "mini.toml"
    f.write_text(MINI)
    with pytest.raises(SystemExit) as e:
        cli.main(["--conf", str(tmp_path / "none.conf"), "profile", "--profile", str(f)])
    message = str(e.value)
    assert message.startswith(f"tvgw: profile {f}: ") and "mini.rules" in message and "\n" not in message


def test_unknown_bundled_profile_raises():
    with pytest.raises(FileNotFoundError):
        profile.load("no-such-tv")


@pytest.mark.parametrize(
    ("data", "key"),
    [
        ({"categories": {"Streaming": "netflix.com"}}, "categories.Streaming"),  # eleven 1-char patterns
        ({"must_alow": {"x.example": "why"}}, "must_alow"),  # a typo reads as no must-allow at all
        ({"url_filter": {"hosts": ["h.example"], "block_regex": "("}}, "url_filter.block_regex"),
        ({"url_filter": {"hosts": "h.example", "block_regex": "x"}}, "url_filter.hosts"),
        ({"url_filter": {"hosts": ["h.example"]}}, "url_filter.block_regex"),
        (
            {"profile": {"expected_categories": ["Nope"]}, "categories": {"A": ["a.example"]}},
            "profile.expected_categories",
        ),
        ({"categories": {"Other": ["a.example"]}}, "categories.Other"),
        ({"categories": {"strip_prefixes": 3}}, "categories.strip_prefixes"),
        ({"categories": {"A": ["a.example", ""]}}, "categories.A"),
        ({"profile": {"clock_hosts": "us.lgtvsdp.com"}}, "profile.clock_hosts"),
        ({"profile": {"never_block_apex": [1]}}, "profile.never_block_apex"),
        ({"must_allow": {"h.example": 1}}, "must_allow.h.example"),
        ({"adguard": {"filters": [{"name": "x"}]}}, "adguard.filters"),
    ],
)
def test_mistyped_profile_data_fails_at_load_naming_the_key(data, key):
    with pytest.raises(ValueError, match=re.escape(key)):
        profile.from_dict(data)


def test_strip_prefixes_are_lower_cased_like_the_names_they_strip():
    p = profile.from_dict({"categories": {"strip_prefixes": ["AIC-"], "Core": ["ngfts.lge.com"]}})
    assert p.strip_prefixes == ("aic-",) and p.categorize("aic-ngfts.lge.com") == "Core"


def test_new_measurement_hosts_are_categorized(lg):
    assert lg.categorize("userpaneltv-pa.googleapis.com") == "3rd-party ads"
    assert (
        lg.categorize("73362d5e-c221-46da-a1e4-7bd3abdfcee6-panelresearch.googlevideo.com") == "3rd-party ads"
    )
    assert lg.categorize("d.agkn.com") == "3rd-party ads"
    assert lg.categorize("track.activemetering.com") == "3rd-party ads"
    assert lg.categorize("tools.google.com") == "3rd-party ads"
    assert (
        lg.categorize("rr11---sn-bvvbaxivnuxqjvhj5nu-n4vd.googlevideo.com") == "Streaming"
    )  # video stays video
    assert "||userpaneltv-pa.googleapis.com^" in lg.adguard_rules()


def test_expected_categories_come_from_the_profile(lg):
    assert lg.expected_categories == ("Streaming", "Infra", "LG core")
    assert lg.is_expected("api-global.netflix.com") and lg.is_expected("ocsp.digicert.com")
    assert lg.is_expected("us.lgtvsdp.com") and not lg.is_expected("www.ueiwsp.com")
    assert not lg.is_expected("ingest.webcol.sdp.peacocktv.com")  # telemetry under a streaming domain
    bare = profile.from_dict({"profile": {"name": "x"}, "categories": {"Video": ["v.example"]}})
    assert bare.expected_categories == ("Streaming", "Infra") and not bare.is_expected("v.example")
    custom = profile.from_dict(
        {"profile": {"name": "x", "expected_categories": ["Video"]}, "categories": {"Video": ["v.example"]}}
    )
    assert custom.is_expected("cdn.v.example")


def test_lg_profile_lints_clean_and_generates_allow_rules(lg):
    assert lg.lint() == []
    rules = lg.adguard_rules()
    for host in lg.must_allow:
        assert f"@@||{host}^" in rules
    assert rules.index("@@||us.lgtvsdp.com^") < rules.index("||alphonso.tv^")
    assert "||xlgsmartad.com^" not in rules
    assert lg.clock_hosts == ("??.lgtvsdp.com", "??.nextlgsdp.com")
    assert lg.categorize("telegraph.prd.api.discomax.com") == "3rd-party ads"
    assert lg.categorize("default.any-any.prd.api.discomax.com") == "Streaming"


def test_rule_target_and_covers():
    assert profile.rule_target("||alphonso.tv^") == ("block", "alphonso.tv")
    assert profile.rule_target("@@||us.lgtvsdp.com^") == ("allow", "us.lgtvsdp.com")
    assert profile.rule_target("||ngfts.lge.com^$dnsrewrite=10.10.10.1") == ("rewrite", "ngfts.lge.com")
    assert profile.rule_target("/-panelresearch\\.googlevideo\\.com$/")[0] == "regex"
    assert profile.rule_target("||*-ad-lgsmartad-com.aws-prd.net^") == (
        "block",
        "*-ad-lgsmartad-com.aws-prd.net",
    )
    assert profile.rule_target("||bad host^")[0] == "other"
    assert profile.covers("lge.com", "snu.lge.com") and profile.covers("lge.com", "LGE.com")
    assert not profile.covers("lge.com", "notlge.com")
    assert profile.covers("*-ad-lgsmartad-com.aws-prd.net", "us-ad-lgsmartad-com.aws-prd.net")


def test_lint_catches_the_classic_mistakes(tmp_path):
    toml = tmp_path / "x.toml"
    toml.write_text(
        """[profile]
name = "x"
never_block_apex = ["lgtvsdp.com"]
[categories]
Core = ["lgtvsdp.com"]
[must_allow]
"us.lgtvsdp.com" = "clock"
"ngfts.lge.com" = "store"
[url_filter]
hosts = ["ngfts.lge.com"]
block_regex = "x"
"""
    )
    (tmp_path / "x.rules").write_text(
        "||lgtvsdp.com^\n@@||lgtvcommon.com^\n||rdx2.lgtvcommon.com^\n||ngfts.lge.com^$dnsrewrite=1.2.3.4\n"
    )
    problems = profile.load(toml).lint()
    assert any("covers must-allow us.lgtvsdp.com" in p for p in problems)
    assert any("apex of 'lgtvsdp.com'" in p for p in problems)
    assert any("exception 'lgtvcommon.com' sits above blocked 'rdx2.lgtvcommon.com'" in p for p in problems)
    assert any("both must-allow and rewritten" in p for p in problems)
    assert not any("ngfts.lge.com' covers" in p for p in problems)  # a rewrite is not a block


def test_generations_and_hardware_tables(lg):
    cx = lg.generation_for("5.6.2")
    assert cx and cx.verified and cx.codename == "jhericurl" and "CX" in cx.models
    assert lg.generation_for(firmware="33.31.61").webos == "25"
    assert lg.generation_for("22").years == (2022,) and lg.generation_for("99") is None
    assert lg.generation_for(firmware="04.64.00").webos == "5"
    assert lg.generation_for() is None
    assert lg.hardware_for("OLED55CXPUA").far_field_mic is False
    assert lg.hardware_for("oled65c2pua").far_field_mic is True
    assert lg.hardware_for("65NANO99UNA").far_field_mic is True
    assert lg.hardware_for("OLED77G6").confidence == "low"
    assert lg.hardware_for("UNKNOWN-TV") is None
    assert {g.webos for g in lg.generations} >= {"3", "4", "5", "6", "22", "23", "24", "25", "26"}
    assert all(h.confidence in ("observed", "spec", "community", "low") for h in lg.hardware)
    assert "audio" in lg.checklist and any("Voice Information" in step for step in lg.checklist["audio"])
    # every far-field model line is a 2020 flagship or a 2022+ C/G/Z/M line: the checklist rule from the research
    for h in lg.hardware:
        if h.far_field_mic:
            assert h.year == 2020 or h.year >= 2022, h
