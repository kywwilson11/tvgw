"""Profiles: the bundled LG profile and the categorizer semantics."""

import pytest

from tvgw import profile


@pytest.fixture(scope="module")
def lg():
    return profile.load("lg-webos")


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
        ("www.googleapis.com", "Other"),
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


def test_load_from_toml_path(tmp_path):
    f = tmp_path / "mini.toml"
    f.write_text('[profile]\nname="mini"\n[categories]\nX=["a.b"]\n[must_allow]\n"A.B"="why"\n')
    p = profile.load(f)
    assert p.name == "mini" and p.categorize("A.B") == "X" and p.must_allow == {"a.b": "why"}


def test_unknown_bundled_profile_raises():
    with pytest.raises(FileNotFoundError):
        profile.load("no-such-tv")


def test_new_measurement_hosts_are_categorized(lg):
    assert lg.categorize("userpaneltv-pa.googleapis.com") == "3rd-party ads"
    assert (
        lg.categorize("73362d5e-c221-46da-a1e4-7bd3abdfcee6-panelresearch.googlevideo.com") == "3rd-party ads"
    )
    assert lg.categorize("d.agkn.com") == "3rd-party ads"
    assert lg.categorize("track.activemetering.com") == "3rd-party ads"
    assert lg.categorize("tools.google.com") == "Infra"
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
