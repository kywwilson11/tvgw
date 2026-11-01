"""The places research pass 2's workstreams meet, wired at integration: the change ledger in the
analyst's pack and the hourly check, the TV's consent record in the pack, judge v2's arm A following
the shipped judge's TV hours, and the sampler following VPN_IF (design decisions 41, 44 and 48)."""

import dataclasses
import sqlite3

from test_analyst import DAY, settings  # noqa: F401  (the analyst's seeded store, as a fixture)

from tvgw import analyst, judge2, ledger, queries


def test_the_pack_carries_the_ledgers_counts_and_follows_ledger_off(settings, lg):  # noqa: F811
    conn = sqlite3.connect(f"file:{settings.db_path}?mode=ro", uri=True)
    a, b, label, _ = analyst.window(settings, DAY, None)
    on = analyst.pack(conn, a, b, label, lg, settings)
    assert isinstance(on["changes_in_effect"], dict)
    assert set(on["changes_in_effect"]) <= {
        "changes", "hours", "confounded_by", "firmware_changes", "machine_rules_on_trial",
    }  # fmt: skip
    off = analyst.pack(conn, a, b, label, lg, dataclasses.replace(settings, ledger="off"))
    assert off["changes_in_effect"] == {}


def test_the_consent_record_and_the_ble_switch_reach_the_pack_and_the_home_does_not():
    assert analyst.pack_setting("eula.acrAllowed") and analyst.pack_setting("eula.voiceAllowed")
    assert analyst.pack_setting("network.bleAdvertisingOnOff") and analyst.pack_setting("option.livePlus")
    assert not analyst.pack_setting("option.zipcode") and not analyst.pack_setting("network.deviceName")
    assert not analyst.pack_setting("eulaStatus")  # the prefix is the stored key's, with its dot


def test_judge2s_stalled_trial_line_buys_no_request():
    line = "machine rule ||t.example^ has spent more than half of judge v2's 14-day ceiling with 2 of 6"
    assert line.startswith(analyst.HEALTH_RED_LINES)
    pack = {"red_lines": [line], "tv": {"readings_on": 3}, "totals": {"dns": {"lookups": 5}}}
    assert not any("red line" in r for r in analyst.novelty(pack))


def test_arm_a_counts_the_tv_hours_the_shipped_judge_counts():
    assert judge2.SHIPPED_ON == queries.AWAKE


def test_the_sampler_looks_for_the_tunnel_vpn_if_names_first(settings):  # noqa: F811
    named = dataclasses.replace(settings, vpn_if="wg0")
    seen = {"/sys/class/net/wg0", "/sys/class/net/tun0"}
    smp = ledger.sample(named, run=lambda argv: "", read=lambda p: None, exists=seen.__contains__,
                        which=lambda n: None, listdir=lambda p: [], now=0.0)  # fmt: skip
    assert (smp.vpn_if, smp.vpn_present) == ("wg0", 1)
    auto = ledger.sample(settings, run=lambda argv: "", read=lambda p: None, exists=seen.__contains__,
                         which=lambda n: None, listdir=lambda p: [], now=0.0)  # fmt: skip
    assert (auto.vpn_if, auto.vpn_present) == ("tun0", 1)
