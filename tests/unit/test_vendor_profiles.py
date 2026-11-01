"""The DNS-only vendor profiles: samsung-tizen, roku and vizio-smartcast (design decision 23 (profiles)).

Nothing in them was seen by this project, so these tests hold them to what an unverified profile must be:
loadable, lint-clean, every rule cited and marked unverified, every must-allow host protected by a
generated `$important` exception and never covered by a rule, and no claim of verification anywhere."""

import re
from fnmatch import fnmatchcase
from importlib import resources

import pytest

from tvgw import adguardcfg, cli, profile
from tvgw.config import Settings

VENDOR = ("samsung-tizen", "roku", "vizio-smartcast")
CATEGORIES = {
    "samsung-tizen": [
        ("acr-us-prd.samsungcloud.tv", "ACR"),
        ("log-ingestion.samsungacr.com", "ACR"),
        ("acr0.samsungcloudsolution.com", "ACR"),  # longer than the zone (Samsung core)
        ("tvp-ads-log.samsungads.com", "Samsung ads"),
        ("devicelog.samsungcloudsolution.net", "Samsung telemetry"),
        ("time.samsungcloudsolution.com", "Samsung core"),
        ("otn2.samsungcloudcdn.com", "Samsung core"),
        ("tvpnlogopus.samsungcloud.tv", "Samsung core"),  # TV Plus logos, the zone's other half
        ("realtime-logger.production-public.tubi.io", "3rd-party ads"),
        ("pvca-samsung-0.api.amazonvideo.com", "Streaming"),
        ("2.pool.ntp.org", "Infra"),
        ("example.com", "Other"),
    ],
    "roku": [
        ("scribe.logs.roku.com", "ACR"),  # beats logs.roku.com (telemetry) and roku.com (core)
        ("liberty.logs.roku.com", "Roku telemetry"),
        ("identity.ads.roku.com", "Roku ads"),
        ("ads-aka-us-east-1.delivery.roku.com", "Roku ads"),  # wildcard inside a label
        ("display.ravm.tv", "Roku ads"),
        ("ads.rokuapi.net", "Roku ads"),
        ("api.rokutime.com", "Roku core"),
        ("sw-update.cs.roku.com", "Roku core"),
        ("vod.delivery.roku.com", "Roku core"),
        ("playtime-tm.everesttech.net", "Other"),
        ("rr3---sn-a5mekn7s.googlevideo.com", "Streaming"),
    ],
    "vizio-smartcast": [
        ("control2.tvinteractive.tv", "ACR"),
        ("kinesis.us-west-2.amazonaws.com", "ACR suspected (shared AWS)"),  # beats amazonaws.com (Infra)
        ("s3.us-west-2.amazonaws.com", "Infra"),
        ("vizio.adsmeasurement.com", "Vizio ads"),
        ("api.vizio.com", "Vizio core"),
        ("watchfreeplus-epg-prod.smartcasttv.com", "Vizio core"),
        ("amg00346-vizioinc-fear-vizious-a15sb.amagi.tv", "Streaming"),
        ("time-a.timefreq.bldrdoc.gov", "Infra"),
        ("example.com", "Other"),
    ],
}


@pytest.fixture(params=VENDOR)
def vendor(request) -> profile.Profile:
    return profile.load(request.param)


def rules_text(name: str) -> str:
    return (resources.files("tvgw.profiles") / f"{name}.rules").read_text(encoding="utf-8")


def toml_text(name: str) -> str:
    return (resources.files("tvgw.profiles") / f"{name}.toml").read_text(encoding="utf-8")


@pytest.mark.parametrize(
    ("name", "host", "category"), [(n, h, c) for n, cases in CATEGORIES.items() for h, c in cases]
)
def test_vendor_categories(name, host, category):
    assert profile.load(name).categorize(host) == category


def test_vendor_profile_loads_lints_clean_and_generates_its_exceptions(vendor):
    assert vendor.lint() == []
    rules = vendor.adguard_rules()
    assert vendor.must_allow, vendor.name
    for host in vendor.must_allow:
        assert f"@@||{host}^$important" in rules
    assert vendor.url_filter is None  # DNS-only: no plain-HTTP file service is split here
    assert vendor.custom_rules, vendor.name  # the pinned blocks
    assert vendor.clock_hosts and vendor.never_block_apex
    assert set(vendor.expected_categories) <= set(vendor.category_order)
    assert vendor.adguard_strip_qtypes == ("HTTPS", "SVCB")


def test_no_vendor_rule_and_no_url_filter_touches_a_must_allow_host(vendor):
    """The lint already refuses this; spelt out per host so a failure names the host and the rule."""
    for rule in vendor.custom_rules:
        kind, target = profile.rule_target(rule)
        for host in vendor.must_allow:
            if kind in ("block", "rewrite"):
                assert not profile.covers(target, host), (rule, host)
            if kind == "regex":
                assert not re.search(target[1 : target.rfind("/")], host, re.IGNORECASE), (rule, host)


def test_every_vendor_rule_is_cited_and_marked_unverified(vendor):
    text = rules_text(vendor.name)
    assert profile.uncited_rules(text) == []
    # each group that holds rules says it is unverified: nothing here was seen on hardware
    for group in re.split(r"\n\s*\n", text):
        lines = [x.strip() for x in group.splitlines() if x.strip()]
        if any(not x.startswith("!") for x in lines):
            assert any("Unverified" in x or "unverified" in x for x in lines if x.startswith("!")), group


def test_every_vendor_must_allow_reason_says_unverified_and_names_its_report(vendor):
    for host, why in vendor.must_allow.items():
        assert "unverified" in why and len(why) > 30, host


def test_vendor_records_are_all_unverified_and_cited(vendor):
    assert vendor.lan_apis and vendor.privacy_settings
    for rec in (*vendor.lan_apis, *vendor.privacy_settings):
        assert not rec.provenance.verified and rec.provenance.sources, rec.name
        assert all(u.startswith("https://") for u in rec.provenance.sources), rec.name
    assert not vendor.generations and not vendor.hardware  # nothing to say about models yet


def test_vendor_blocklists_are_maintained_lists_over_https(vendor):
    assert vendor.adguard_filters
    for name, url in vendor.adguard_filters:
        assert url.startswith("https://") and ("hagezi" in url or "HostlistsRegistry" in url), (name, url)
    # Perflyst's list blocks zones (samsungcloudsolution.com, samsungqbe.com) that carry the clock and firmware
    assert not any("filter_7.txt" in url for _, url in vendor.adguard_filters)


def test_vendor_clock_hosts_cover_a_must_allow_host(vendor):
    """The clock host the red line watches is one the exceptions keep answered."""
    assert any(fnmatchcase(host, pat) for pat in vendor.clock_hosts for host in vendor.must_allow), (
        vendor.clock_hosts
    )


def test_vendor_apex_zones_hold_against_a_careless_block(vendor):
    import dataclasses

    for apex in vendor.never_block_apex:
        careless = dataclasses.replace(vendor, custom_rules=(*vendor.custom_rules, f"||{apex}^"))
        assert any("apex of" in x or "covers must-allow" in x for x in careless.lint()), apex


def test_vendor_categorizer_agrees_with_the_reference(vendor):
    """The indexed categorizer against two fnmatch calls per rule, on every pattern of the profile."""

    def reference(host: str) -> str:
        host = host.lower().rstrip(".")
        best, cat = -1, "Other"
        for pat, c in vendor.rules:
            if fnmatchcase(host, pat) or fnmatchcase(host, "*." + pat):
                score = len(pat.replace("*", ""))
                if score > best:
                    best, cat = score, c
        return cat

    for pat, _ in vendor.rules:
        host = pat.replace("*", "x7").replace("?", "q")
        for name in (host, "sub." + host, host.upper(), "x" + host):
            assert vendor.categorize(name) == reference(name), name


def test_vendor_profile_feeds_adguard_config_as_code(vendor):
    d = adguardcfg.desired(vendor, Settings(profile=vendor.name))
    assert d.filters == vendor.adguard_filters
    assert "||*^$dnstype=HTTPS|SVCB,client=10.10.10.17" in d.user_rules
    assert not any("$dnsrewrite" in r for r in d.user_rules)  # no URL filter, so no rewrites


@pytest.mark.parametrize("name", VENDOR)
def test_cli_profile_prints_a_vendor_profile(name, tmp_path, capsys):
    assert cli.main(["--conf", str(tmp_path / "none.conf"), "profile", "--profile", name]) == 0
    out = capsys.readouterr().out
    assert out.startswith(f"{name}: ") and "rules lint: clean" in out
    assert "LAN APIs:" in out and "Privacy settings:" in out and "verified here" not in out
    assert "Generations:" not in out


@pytest.mark.parametrize("name", VENDOR)
def test_vendor_files_carry_no_site_identifiers(name):
    """Profiles ship to everyone: no private addresses, no MAC addresses, no home names."""
    for text in (rules_text(name), toml_text(name)):
        assert not re.search(r"\b192\.168\.|\b172\.(1[6-9]|2\d|3[01])\.", text)
        assert not re.search(r"\b(?:[0-9a-f]{2}:){5}[0-9a-f]{2}\b", text, re.IGNORECASE)
        assert not re.search(r"\b\d{1,3}(?:\.\d{1,3}){3}\b", text), name  # no address of any kind


def test_hagezi_and_paper_text_is_cited_not_merged():
    """The PoPETs 2027 list is CC BY-NC-ND and HaGeZi's are GPL: the profiles pin a few hosts each, with
    a citation, and subscribe to the lists for the rest, so no list is copied into this MIT repository."""
    for name in VENDOR:
        assert len(profile.load(name).custom_rules) <= 12, name
