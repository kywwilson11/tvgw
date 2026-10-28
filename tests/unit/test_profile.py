"""Profiles: the bundled LG profile, loading and validation, and the categorizer semantics."""

import dataclasses
import os
import random
import re
import time
import tomllib
from fnmatch import fnmatchcase
from importlib import resources
from pathlib import Path

import pytest

from tvgw import cli, config, profile
from tvgw.config import Settings

NGINX = Path(__file__).resolve().parents[2] / "deploy" / "nginx"


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
    assert p.custom_rules == () and p.adguard_rules() == ["@@||a.b^$important"]


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
        assert f"@@||{host}^$important" in rules  # the modifier is what beats a list's $important block
    assert rules[0].startswith("@@||")
    assert rules.index("@@||us.lgtvsdp.com^$important") < rules.index("||alphonso.tv^")
    assert "||xlgsmartad.com^" not in rules
    assert not any("$dnsrewrite" in r for r in rules)  # the rewrites need the gateway address
    assert lg.clock_hosts == ("??.lgtvsdp.com", "??.nextlgsdp.com")
    assert lg.categorize("telegraph.prd.api.discomax.com") == "3rd-party ads"
    assert lg.categorize("default.any-any.prd.api.discomax.com") == "Streaming"


def test_url_filter_rewrites_are_generated_from_the_profile_and_the_gateway_address(lg):
    n = len(lg.must_allow)
    rules = lg.adguard_rules("192.0.2.1")
    rewrites = [f"||{h}^$dnsrewrite=192.0.2.1" for h in lg.url_filter.hosts]
    assert rules[n : n + len(rewrites)] == rewrites  # after the exceptions, before the .rules file
    assert [r for r in rules if "$dnsrewrite" in r] == rewrites  # and the file carries none of its own
    # with the default settings the generated rules are exactly the lines the .rules file used to hold
    assert [r for r in lg.adguard_rules(Settings().gw_ip) if "$dnsrewrite" in r] == [
        "||ngfts.lge.com^$dnsrewrite=10.10.10.1",
        "||aic-ngfts.lge.com^$dnsrewrite=10.10.10.1",
        "||aic-img-ngfts.lge.com^$dnsrewrite=10.10.10.1",
        "||gfts.lge.com^$dnsrewrite=10.10.10.1",
    ]
    no_filter = profile.from_dict({"must_allow": {"a.example": "why"}})
    assert no_filter.adguard_rules("192.0.2.1") == ["@@||a.example^$important"]


def test_nginx_conf_matches_the_profile(lg):
    """The nginx files are written by hand for LG; this ties them to the profile before a deploy, where
    only a hardware test used to link two of the five places the GFTS host list and regex live."""
    conf = (NGINX / "tvgw-gfts.conf").read_text()
    # the exact shape the rule-history ingest parses (ingest.current_rules)
    assert f'$request_uri ~* "{lg.url_filter.block_regex}"' in conf
    (server_name,) = re.findall(r"^\s*server_name ([^;]+);", conf, re.MULTILINE)
    assert set(server_name.split()) == set(lg.url_filter.hosts)
    (host_check,) = re.findall(r'\$host !~\* "([^"]+)"', conf)
    (passthrough,) = re.findall(
        r"^\s*~(\S+) \$ssl_preread_server_name;", (NGINX / "stream.conf").read_text(), re.M
    )
    for host in lg.url_filter.hosts:
        assert re.match(host_check, host, re.IGNORECASE) and re.match(passthrough, host), host
    assert not re.match(passthrough, "snu.lge.com")  # only the URL-filter names are handed through


def test_rule_target_and_covers():
    assert profile.rule_target("||alphonso.tv^") == ("block", "alphonso.tv")
    assert profile.rule_target("@@||us.lgtvsdp.com^") == ("allow", "us.lgtvsdp.com")
    assert profile.rule_target("@@||us.lgtvsdp.com^$important") == ("allow", "us.lgtvsdp.com")
    assert profile.rule_target("||ngfts.lge.com^$dnsrewrite=10.10.10.1") == ("rewrite", "ngfts.lge.com")
    assert profile.rule_target("/-panelresearch\\.googlevideo\\.com$/")[0] == "regex"
    assert profile.rule_target("||*-ad-lgsmartad-com.aws-prd.net^") == (
        "block",
        "*-ad-lgsmartad-com.aws-prd.net",
    )
    assert profile.rule_target("||bad host^")[0] == "other"
    assert profile.rule_target("0.0.0.0 x.y") == ("block", "x.y")  # hosts syntax
    assert profile.rule_target("::1 Snu.LGE.com") == ("block", "snu.lge.com")
    assert profile.rule_target("0.0.0.0 x.y # c")[0] == "other"
    assert profile.rule_target("||x.y^$dnsrewrite=NXDOMAIN") == ("rewrite", "x.y")
    assert profile.rule_target("@@||x.y^$dnsrewrite") == ("allow", "x.y")  # an exception stays one
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
    assert any("block rule 'lgtvsdp.com' covers must-allow us.lgtvsdp.com" in p for p in problems)
    assert any("apex of 'lgtvsdp.com'" in p for p in problems)
    assert any("exception 'lgtvcommon.com' sits above blocked 'rdx2.lgtvcommon.com'" in p for p in problems)
    assert any("both must-allow and rewritten" in p for p in problems)
    assert any(
        p.startswith("rewrite rule 'ngfts.lge.com' covers") for p in problems
    )  # a rewrite, not a block
    assert not any(p.startswith("block rule") and "ngfts" in p for p in problems)


@pytest.mark.parametrize(
    ("rule", "problem"),
    [
        ("||*.wiselg.com^", "block rule '*.wiselg.com' at the apex of 'wiselg.com'"),
        ("||*.*.aws-prd.net^", "at the apex of 'aws-prd.net'"),
        ("0.0.0.0 us.lgtvsdp.com", "block rule 'us.lgtvsdp.com' covers must-allow us.lgtvsdp.com"),
        ("127.0.0.1 snu.lge.com", "block rule 'snu.lge.com' covers must-allow snu.lge.com"),
        (
            "||us.lgtvsdp.com^$dnsrewrite=NXDOMAIN",
            "rewrite rule 'us.lgtvsdp.com' covers must-allow us.lgtvsdp.com",
        ),
        ("||snu.lge.com^$dnsrewrite=0.0.0.0", "rewrite rule 'snu.lge.com' covers must-allow snu.lge.com"),
        ("||lge.com^$dnsrewrite=0.0.0.0", "rewrite rule 'lge.com' covers must-allow snu.lge.com"),
        ("/^us\\.lgtvsdp\\.com$/", "matches must-allow us.lgtvsdp.com"),
        ("/lgtvsdp/", "regex rule '/lgtvsdp/' matches must-allow us.lgtvsdp.com"),
        ("/lgtvsdp/$important", "regex rule '/lgtvsdp/$important' matches must-allow us.lgtvsdp.com"),
        ("/(/", "regex rule '/(/' does not compile"),
    ],
)
def test_lint_sees_wildcard_apex_hosts_syntax_rewrites_and_regex_rules(lg, rule, problem):
    """Every one of these returned a clean lint before: hosts syntax was 'other', `$dnsrewrite` was
    not a block, regexes were not looked at, and only the bare apex counted as the apex."""
    p = dataclasses.replace(lg, custom_rules=(*lg.custom_rules, rule))
    assert any(problem in x for x in p.lint()), p.lint()


def test_a_dead_block_under_an_equal_exception_is_reported(lg):
    p = dataclasses.replace(lg, custom_rules=(*lg.custom_rules, "||x.example^", "@@||x.example^"))
    assert "exception 'x.example' sits above blocked 'x.example' and would unblock it" in p.lint()


@pytest.mark.parametrize(
    "rule",
    [
        "@@||us.lgtvsdp.com^$dnsrewrite",  # an exception, whatever its modifiers
        "||rdx2.lgtvsdp.com^",  # one telemetry host under the clock zone, not its apex
        "/^[a-z]{2}-rdx2-lgtvsdp-com\\.aws-prd\\.net$/",  # the bundled CNAME-target regex
    ],
)
def test_lint_stays_clean_for_rules_that_only_look_dangerous(lg, rule):
    p = dataclasses.replace(lg, custom_rules=(*lg.custom_rules, rule))
    assert p.lint() == []


def test_a_url_filter_host_above_a_must_allow_host_is_a_conflict():
    p = profile.from_dict(
        {"must_allow": {"snu.lge.com": "firmware"}, "url_filter": {"hosts": ["lge.com"], "block_regex": "x"}}
    )
    assert p.lint() == ["snu.lge.com is both must-allow and rewritten by the URL filter"]


def test_adguard_refuses_a_profile_that_does_not_lint_before_touching_the_yaml(tmp_path, monkeypatch):
    toml = tmp_path / "bad.toml"
    toml.write_text('[profile]\nname = "bad"\n[must_allow]\n"us.lgtvsdp.com" = "clock"\n')
    (tmp_path / "bad.rules").write_text("||lgtvsdp.com^\n")
    yaml = tmp_path / "AdGuardHome.yaml"  # never created: a read would be the 'cannot read' exit instead
    monkeypatch.setattr(
        config, "load", lambda path, **kw: Settings(profile=str(toml), adguard_yaml=str(yaml))
    )
    for action in ("diff", "apply"):
        with pytest.raises(
            SystemExit, match=re.escape("does not lint: block rule 'lgtvsdp.com' covers must-allow")
        ):
            cli.main(["--conf", str(tmp_path / "none.conf"), "adguard", action])
    assert not yaml.exists()


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


# ---- the categorizer against its reference ------------------------------------------------------------
def reference(p: profile.Profile, host: str) -> str:
    """The categorizer as it was, two fnmatch calls per rule per name: the oracle the indexed one must
    agree with, wildcard semantics included (`*` matches dots; a pattern matches the host or a subdomain)."""
    host = host.lower().rstrip(".")
    for pre in p.strip_prefixes:
        if host.startswith(pre):
            host = host[len(pre) :]
            break
    best, cat = -1, "Other"
    for pat, c in p.rules:
        if fnmatchcase(host, pat) or fnmatchcase(host, "*." + pat):
            score = len(pat.replace("*", ""))
            if score > best:
                best, cat = score, c
    return cat


def test_categorizer_agrees_with_the_reference_on_every_pattern_and_on_random_names(lg):
    rng = random.Random(7)

    def label() -> str:
        return "".join(rng.choices("abcdefghijklmnopqrstuvwxyz0123456789-", k=rng.randint(1, 12)))

    zones = sorted({".".join(pat.replace("*", "x").split(".")[-2:]) for pat, _ in lg.rules})
    names = ["", "example.com.", ".lge.com", "lge.com.", "LGE.COM"]
    for pat, _ in lg.rules:
        host = pat.replace("*", "x7").replace("?", "q")
        names += [host, "sub." + host, "aic." + host, "AIC-" + host, host.upper(), "x" + host]
    for _ in range(2000):
        labels = [label() for _ in range(rng.randint(0, 3))] + [rng.choice(zones)]
        names.append(rng.choice(("", "", *lg.strip_prefixes)) + ".".join(labels))
    for name in names:
        assert lg.categorize(name) == reference(lg, name), name


def test_equal_scores_fall_to_the_earlier_pattern_whether_plain_or_wildcard():
    p = profile.from_dict({"categories": {"A": ["?.com"], "B": ["x.com"], "C": ["x.com"], "D": ["*"]}})
    assert p.categorize("x.com") == "A"  # `?.com` scores 5 like `x.com` and came first
    assert p.categorize("deep.x.com") == "A"
    assert p.categorize("xy.com") == "D"  # `?` is exactly one character; the catch-all scores 0
    q = profile.from_dict({"categories": {"B": ["x.com"], "A": ["?.com"]}})
    assert q.categorize("x.com") == "B"


def test_twenty_thousand_names_categorize_in_well_under_a_second(lg):
    """refresh_hosts recategorizes every hosts row whenever the rules change; this took 0.94 s per
    20 000 names with two fnmatch calls per rule and name, several seconds on the Pi."""
    names = [f"h{i}.n{i % 97}.lgtvcommon.com" for i in range(20_000)]
    t0 = time.perf_counter()
    for name in names:
        lg.categorize(name)
    assert time.perf_counter() - t0 < 0.5


def test_strip_rule_is_type_and_client_scoped_and_needs_the_tv_address(lg):
    assert lg.adguard_strip_qtypes == ("HTTPS", "SVCB")
    assert not any("$dnstype" in r for r in lg.adguard_rules())  # the lint's view: no address, no rule
    rules = lg.adguard_rules("10.10.10.1", "10.10.10.17")
    assert rules.count("||*^$dnstype=HTTPS|SVCB,client=10.10.10.17") == 1
    assert lg.lint() == []


def test_typed_rules_are_not_blocks_for_the_lint(lg):
    assert profile.rule_target("||*^$dnstype=HTTPS|SVCB,client=10.10.10.17") == ("typed", "*")
    assert profile.rule_target("||us.lgtvsdp.com^$dnstype=AAAA") == ("typed", "us.lgtvsdp.com")
    assert profile.rule_target("@@||us.lgtvsdp.com^$dnstype=AAAA") == ("allow", "us.lgtvsdp.com")
    assert profile.rule_target("||*^$dnstype=https|Svcb") == ("typed", "*")  # AdGuard reads any case
    typed = dataclasses.replace(lg, custom_rules=(*lg.custom_rules, "||*^$dnstype=HTTPS"))
    assert typed.lint() == []
    blanket = dataclasses.replace(lg, custom_rules=(*lg.custom_rules, "||*^"))
    assert any("covers must-allow" in p for p in blanket.lint())


@pytest.mark.parametrize(
    ("rule", "problem"),
    [
        ("||*^$dnstype=A", "block rule '*' covers must-allow us.lgtvsdp.com"),
        ("||*^$dnstype=a", "block rule '*' covers must-allow us.lgtvsdp.com"),
        ("||*^$dnstype=~HTTPS", "block rule '*' covers must-allow us.lgtvsdp.com"),  # all types but HTTPS
        ("||*^$dnstype=A|AAAA,client=10.10.10.17", "block rule '*' covers must-allow snu.lge.com"),
        ("||lgtvsdp.com^$dnstype=A", "block rule 'lgtvsdp.com' at the apex of 'lgtvsdp.com'"),
    ],
)
def test_a_typed_rule_that_withholds_addresses_is_a_block(lg, rule, problem):
    """Reproduced: each of these linted clean, because any `$dnstype` rule counted as typed whatever
    types it named. Withholding A records takes every name the rule covers; the must-allow exceptions
    keep the readiness probe and verify green while the TV loses everything else."""
    p = dataclasses.replace(lg, custom_rules=(*lg.custom_rules, rule))
    assert any(problem in x for x in p.lint()), p.lint()


def test_strip_qtypes_must_be_record_types_we_know(tmp_path):
    toml = tmp_path / "x.toml"
    toml.write_text('[profile]\nname = "x"\n[categories]\n[must_allow]\n[adguard]\nstrip_qtypes = ["TXT"]\n')
    (tmp_path / "x.rules").write_text("")
    with pytest.raises(ValueError, match="strip_qtypes"):
        profile.load(toml)
    toml.write_text('[profile]\nname = "x"\n[categories]\n[must_allow]\n[adguard]\nstrip_qtypes = "HTTPS"\n')
    with pytest.raises(ValueError, match="strip_qtypes"):
        profile.load(toml)
