"""AdGuard Home config-as-code: planning, diffing and applying against a realistic YAML."""

import yaml

from tvgw import adguardcfg, profile
from tvgw.config import Settings

# trimmed from a real AdGuardHome.yaml (schema 34): the keys we manage plus some we must not touch
STOCK = """
http:
  address: 0.0.0.0:3000
  session_ttl: 30d
users:
  - name: admin
    password: $2a$10$hashhashhash
dns:
  bind_hosts:
    - 0.0.0.0
  port: 53
  anonymize_client_ip: true
  upstream_dns:
    - https://9.9.9.9/dns-query
  bootstrap_dns:
    - 9.9.9.9
  cache_optimistic: false
  enable_dnssec: true
querylog:
  interval: 24h
  enabled: true
  file_enabled: true
statistics:
  interval: 24h
  enabled: true
filters:
  - enabled: false
    url: https://adguardteam.github.io/HostlistsRegistry/assets/filter_1.txt
    name: AdGuard DNS filter
    id: 1
  - enabled: false
    url: https://adguardteam.github.io/HostlistsRegistry/assets/filter_72.txt
    name: old name
    id: 1792975975
user_rules:
  - '||old.example^'
filtering:
  blocked_response_ttl: 300
  rewrites:
    - domain: ngfts.lge.com
      answer: 10.10.10.1
      enabled: false
  filtering_enabled: true
  protection_enabled: true
clients:
  runtime_sources:
    whois: true
  persistent: []
schema_version: 34
"""

SETTINGS = Settings(tv_ip="10.10.10.17", tv_mac="aa:bb:cc:dd:ee:ff", tv_name="lgcx")


def test_desired_from_profile_and_settings():
    lg = profile.load("lg-webos")
    d = adguardcfg.desired(lg, SETTINGS)
    assert [n for n, _ in d.filters] == ["HaGeZi LG webOS", "HaGeZi DoH/VPN bypass (DoH only)", "HaGeZi Pro"]
    assert len(d.user_rules) >= 60 and "||alphonso.tv^" in d.user_rules
    assert "||ngfts.lge.com^$dnsrewrite=10.10.10.1" in d.user_rules  # the default GW_IP
    moved = adguardcfg.desired(lg, Settings(gw_ip="192.0.2.1"))
    assert "||ngfts.lge.com^$dnsrewrite=192.0.2.1" in moved.user_rules  # the rewrites follow the setting
    assert not any(r.endswith("=10.10.10.1") for r in moved.user_rules)
    assert d.upstreams == ("https://1.1.1.1/dns-query", "https://1.0.0.1/dns-query")
    assert d.bootstrap == ("1.1.1.1", "1.0.0.1") and d.tv_name == "lgcx"


def test_plan_sets_only_managed_keys_and_keeps_the_rest():
    current = yaml.safe_load(STOCK)
    d = adguardcfg.desired(profile.load("lg-webos"), SETTINGS)
    new = adguardcfg.plan(current, d)
    assert current["http"]["address"] == "0.0.0.0:3000"  # input untouched
    assert new["http"]["address"] == "127.0.0.1:3000" and new["http"]["session_ttl"] == "30d"
    assert new["users"][0]["password"].startswith("$2a$")  # never touched
    assert new["dns"]["upstream_dns"] == list(d.upstreams) and new["dns"]["enable_dnssec"] is True
    assert new["dns"]["cache_optimistic"] is True and new["dns"]["anonymize_client_ip"] is False
    assert new["querylog"]["interval"] == "90d" and new["statistics"]["interval"] == "90d"
    assert new["filtering"]["blocked_response_ttl"] == 60 and new["filtering"]["rewrites"] == []
    assert new["schema_version"] == 34
    # filters: stock one left disabled, existing LG list re-enabled and renamed, two appended with fresh ids
    f = {x["url"]: x for x in new["filters"]}
    assert f["https://adguardteam.github.io/HostlistsRegistry/assets/filter_1.txt"]["enabled"] is False
    lg_list = f["https://adguardteam.github.io/HostlistsRegistry/assets/filter_72.txt"]
    assert lg_list["enabled"] is True and lg_list["name"] == "HaGeZi LG webOS" and lg_list["id"] == 1792975975
    ids = sorted(x["id"] for x in new["filters"])
    assert ids == [1, 1792975975, 1792975976, 1792975977]
    assert new["user_rules"] == list(d.user_rules)  # replaced wholesale
    tv = new["clients"]["persistent"][0]
    assert (
        tv["name"] == "lgcx"
        and tv["ids"] == ["10.10.10.17", "aa:bb:cc:dd:ee:ff"]
        and tv["tags"] == ["device_tv"]
    )


def test_plan_is_idempotent_and_changes_describe_drift():
    current = yaml.safe_load(STOCK)
    d = adguardcfg.desired(profile.load("lg-webos"), SETTINGS)
    new = adguardcfg.plan(current, d)
    diff = adguardcfg.changes(current, new)
    assert any(c.startswith("http.address: '0.0.0.0:3000' -> '127.0.0.1:3000'") for c in diff)
    assert any(c.startswith("filtering.blocked_response_ttl: 300 -> 60") for c in diff)
    assert not any(c.startswith("users.") or c.startswith("schema_version") for c in diff)
    again = adguardcfg.plan(new, d)
    assert again == new and adguardcfg.changes(new, again) == []


def test_existing_tv_client_keeps_its_name_and_gets_exactly_our_ids():
    current = yaml.safe_load(STOCK)
    current["clients"]["persistent"] = [{"name": "LG CX", "ids": ["10.10.10.17"], "tags": ["device_tv"]}]
    new = adguardcfg.plan(current, adguardcfg.desired(profile.load("lg-webos"), SETTINGS))
    tv = new["clients"]["persistent"][0]
    assert tv["name"] == "LG CX" and tv["ids"] == ["10.10.10.17", "aa:bb:cc:dd:ee:ff"]
    assert tv["ignore_querylog"] is False and len(new["clients"]["persistent"]) == 1


def test_tv_that_changed_address_is_matched_by_mac_or_name_not_duplicated():
    current = yaml.safe_load(STOCK)
    current["clients"]["persistent"] = [{"name": "other", "ids": ["10.10.10.99", "aa:bb:cc:dd:ee:ff"]}]
    new = adguardcfg.plan(current, adguardcfg.desired(profile.load("lg-webos"), SETTINGS))
    assert [c["ids"] for c in new["clients"]["persistent"]] == [["10.10.10.17", "aa:bb:cc:dd:ee:ff"]]
    current["clients"]["persistent"] = [{"name": "lgcx", "ids": ["10.10.10.99"]}]
    new = adguardcfg.plan(current, adguardcfg.desired(profile.load("lg-webos"), SETTINGS))
    assert [c["ids"] for c in new["clients"]["persistent"]] == [["10.10.10.17", "aa:bb:cc:dd:ee:ff"]]


def test_yaml_1_2_scalars_survive_a_round_trip(tmp_path):
    # AdGuard writes YAML 1.2: an all-digit MAC and the word "on" are strings there, not an int / bool
    path = tmp_path / "a.yaml"
    path.write_text(
        "clients:\n  persistent:\n    - name: tv\n      ids:\n        - 10:20:30:40:50:59\n"
        "        - on\nx: 0o17\ny: 1e3\nz: true\n"
    )
    cfg = adguardcfg.load_yaml(str(path))
    assert cfg["clients"]["persistent"][0]["ids"] == ["10:20:30:40:50:59", "on"]
    assert cfg["x"] == 15 and cfg["y"] == 1000.0 and cfg["z"] is True
    assert yaml.safe_load(adguardcfg.dump_yaml(cfg)) == cfg  # PyYAML quotes what 1.1 would misread


def test_plan_from_empty_config():
    new = adguardcfg.plan({}, adguardcfg.desired(profile.load("lg-webos"), SETTINGS))
    assert new["dns"]["upstream_dns"] and new["filters"][0]["id"] == 1792975975 and new["user_rules"]


def test_yaml_round_trip_quotes_rules_safely():
    d = adguardcfg.desired(profile.load("lg-webos"), SETTINGS)
    text = adguardcfg.dump_yaml(adguardcfg.plan(yaml.safe_load(STOCK), d))
    back = yaml.safe_load(text)
    assert back["user_rules"] == list(d.user_rules)
    assert back["user_rules"][0].startswith("@@||")
    assert "@@||us.lgtvsdp.com^$important" in back["user_rules"]
    assert "@@||us.nextlgsdp.com^$important" in back["user_rules"]


def test_apply_stops_backs_up_writes_and_starts(tmp_path):
    path = tmp_path / "AdGuardHome.yaml"
    path.write_text(STOCK)
    calls = []
    d = adguardcfg.desired(profile.load("lg-webos"), SETTINGS)
    checked = []
    diff = adguardcfg.apply(
        str(path),
        d,
        control=lambda *a: calls.append(a),
        ready=lambda: True,
        check=lambda p: checked.append(p) or True,
        now=1793020000,
    )
    assert calls == [("stop", "AdGuardHome"), ("start", "AdGuardHome")]
    assert diff and list(tmp_path.glob("AdGuardHome.yaml.bak-*"))
    assert (
        checked and checked[0] != str(path) and not list(tmp_path.glob(".AdGuardHome.*"))
    )  # tmp validated, gone
    written = yaml.safe_load(path.read_text())
    assert written["user_rules"] == list(d.user_rules)
    # second apply: nothing to do, service not touched
    calls.clear()
    assert adguardcfg.apply(str(path), d, control=lambda *a: calls.append(a), ready=lambda: True) == []
    assert calls == []


def test_apply_refuses_a_config_adguard_rejects_without_touching_the_service(tmp_path):
    import pytest

    path = tmp_path / "AdGuardHome.yaml"
    path.write_text(STOCK)
    d = adguardcfg.desired(profile.load("lg-webos"), SETTINGS)
    calls = []
    with pytest.raises(RuntimeError, match="rejected"):
        adguardcfg.apply(
            str(path), d, control=lambda *a: calls.append(a), ready=lambda: True, check=lambda p: False
        )
    assert calls == [] and path.read_text() == STOCK and not list(tmp_path.glob(".AdGuardHome.*"))


def test_parse_rules_drops_comments_blanks_and_duplicates():
    assert profile.parse_rules("! c\n\n||a^\n  ||b^  \n||a^\n@@||c^\n") == ["||a^", "||b^", "@@||c^"]


def test_apply_waits_for_the_resolver_and_reports_when_it_does_not_come_back(tmp_path):
    import pytest

    path = tmp_path / "AdGuardHome.yaml"
    path.write_text(STOCK)
    d = adguardcfg.desired(profile.load("lg-webos"), SETTINGS)
    calls = []
    with pytest.raises(RuntimeError, match=r"did not answer .* was put back"):
        adguardcfg.apply(
            str(path), d, control=lambda *a: calls.append(a), ready=lambda: False, check=lambda p: True
        )
    # written, started, found dead, rolled back to the backup and restarted
    assert calls == [
        ("stop", "AdGuardHome"),
        ("start", "AdGuardHome"),
        ("stop", "AdGuardHome"),
        ("start", "AdGuardHome"),
    ]
    assert path.read_text() == STOCK


def test_dns_ready_times_out_quickly_on_a_dead_port():
    import time

    t0 = time.monotonic()
    assert adguardcfg.dns_ready(server="127.0.0.1", timeout=1.2) in (True, False)
    assert time.monotonic() - t0 < 10
