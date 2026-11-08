"""(acr) The LG adtech port wall in tvgw-apply: where it sits in tv_out, the switch that removes it, and
the settings record verify compares, so turning it off is an apply like any other firewall switch and a
gateway upgraded from a conf that never named it reads as applied. (profile) The wall is LG's: another
profile, the general one included, never gets it (design decision 62).

What nft makes of the rules is the virtual suite's question (tests/virtual/test_virtual_rulesets.py,
matrix.txt); what the script hands it is checked here, against the stub commands of test_apply.py."""

import shutil

import pytest
from conftest import ROOT
from test_apply import CONF, chain, ruleset, run_apply
from test_apply_check import checked, run_check

from tvgw import config, verify

pytestmark = pytest.mark.skipif(shutil.which("bash") is None, reason="tvgw-apply is a bash script")

PORTS = "tcp dport { 4001, 4431, 4445, 4447, 8180, 8883 }"
LOG = f'{PORTS} limit rate 6/minute log prefix "tvgw-adport: "'
REJECT = f'{PORTS} counter reject with tcp reset comment "LG adtech port"'


def tv_out(tmp_path, conf: str = CONF) -> list[str]:
    out = run_apply(tmp_path, conf=conf)
    assert out.returncode == 0, out.stderr
    return chain(ruleset(tmp_path), "tv_out")


@pytest.mark.parametrize("extra", ["", "ADTECH_PORT_WALL=yes\n", "STRICT_PORTS=yes\n", "UPLINK=vpn\n"])
def test_the_wall_sits_after_the_manual_blocks_and_before_the_lg_fallback_and_the_port_rules(tmp_path, extra):
    lines = tv_out(tmp_path, CONF + extra)
    at = {key: next(i for i, line in enumerate(lines) if key in line) for key in (
        "manual IP blocks", "tvgw-adport", "LG adtech port", "LG firmware fallback path", "tvgw-oddport",
    )}  # fmt: skip
    assert lines[at["tvgw-adport"]] == LOG and lines[at["LG adtech port"]] == REJECT
    assert at["manual IP blocks"] < at["tvgw-adport"] == at["LG adtech port"] - 1
    assert at["LG adtech port"] < at["LG firmware fallback path"] < at["tvgw-oddport"]
    # the odd-port rule's count (or reject) follows, so "Unexpected ports" counts only unknown ports
    assert any("STRICT_PORTS" in line for line in lines[at["LG adtech port"] + 1 :])


def test_the_switch_off_removes_both_rules_and_the_odd_port_rules_see_the_ports_again(tmp_path):
    lines = tv_out(tmp_path, CONF + "ADTECH_PORT_WALL=no\n")
    assert not any("adport" in line or "adtech" in line or "4431" in line for line in lines)
    assert any("tvgw-oddport" in line for line in lines)


def test_the_check_renders_the_wall_as_the_apply_does(tmp_path):
    assert run_check(tmp_path).returncode == 0
    inet = checked(tmp_path)[0]
    assert LOG in inet and REJECT in inet
    other = tmp_path / "off"
    assert run_check(other, conf=CONF + "ADTECH_PORT_WALL=no\n").returncode == 0
    assert "LG adtech port" not in checked(other)[0]


@pytest.mark.parametrize("value", ["Yes", "on", "1", "off"])
def test_a_near_miss_stops_the_apply_before_anything_is_loaded(tmp_path, value):
    out = run_apply(tmp_path, conf=CONF + f"ADTECH_PORT_WALL={value}\n")
    assert out.returncode == 1 and "tvgw: ADTECH_PORT_WALL must be yes or no" in out.stderr
    assert not (tmp_path / "stub" / "nft-script.0").exists()


def test_config_refuses_the_same_near_misses_and_defaults_the_wall_on(tmp_path):
    conf = tmp_path / "tvgw.conf"
    conf.write_text("ADTECH_PORT_WALL=Yes\n", encoding="utf-8")
    with pytest.raises(ValueError, match="ADTECH_PORT_WALL"):
        config.load(conf)
    conf.write_text("ADTECH_PORT_WALL=no\n", encoding="utf-8")
    assert config.load(conf).adtech_port_wall == "no" and config.Settings().adtech_port_wall == "yes"


def test_the_apply_records_the_switch_and_says_it(tmp_path):
    out = run_apply(tmp_path, conf=CONF + "ADTECH_PORT_WALL=no\n")
    used = config.parse_conf((tmp_path / "run" / "tvgw" / "settings.applied").read_text(encoding="utf-8"))
    assert used["ADTECH_PORT_WALL"] == "no" and "adtech_wall=no" in out.stdout


def test_a_gateway_upgraded_from_a_conf_without_the_key_reads_as_applied():
    """The deploy that brings the wall: the last apply's record has no ADTECH_PORT_WALL, nor has the conf;
    both mean yes. An owner who then writes ADTECH_PORT_WALL=no has an unapplied firewall change."""
    before = "UPLINK=direct\nWAN_IF=wlan0\nWAN_GW=203.0.113.1\nBLOCK_QUIC=yes\nSTRICT_PORTS=no\n"
    assert verify.apply_settings(before) == verify.apply_settings(CONF)
    assert verify.apply_settings(before)["ADTECH_PORT_WALL"] == "yes"
    assert verify.apply_settings(CONF + "ADTECH_PORT_WALL=no\n") != verify.apply_settings(before)


# ---- (profile) the wall stands only in front of an LG TV (design decision 62) -------------------------
def recorded(tmp_path) -> dict[str, str]:
    """The last apply's record of the keys it read; (uplink) WAN_GW_USED, the router the routes use,
    sits beside them and no check compares it, so it is left out here."""
    used = config.parse_conf((tmp_path / "run" / "tvgw" / "settings.applied").read_text(encoding="utf-8"))
    for key in verify.APPLY_RECORDS:  # (ports) and what was built of the clock port, beside the keys
        used.pop(key, None)
    return used


@pytest.mark.parametrize("profile", ["generic-tv", "samsung-tizen", "/etc/tvgw/my-tv.toml"])
@pytest.mark.parametrize("switch", ["", "ADTECH_PORT_WALL=yes\n"])
def test_another_profile_gets_no_wall_whatever_the_switch_says(tmp_path, profile, switch):
    """The ports fall to the odd-port rules, counted like any other; the record says the wall is off and
    names the profile, and verify reads the same from the conf, so applied_current stays quiet."""
    conf = CONF + switch + f"PROFILE={profile}\n"
    out = run_apply(tmp_path, conf=conf)
    assert out.returncode == 0, out.stderr
    lines = chain(ruleset(tmp_path), "tv_out")
    assert not any("adport" in line or "adtech" in line or "4431" in line for line in lines)
    assert any("tvgw-oddport" in line for line in lines)
    used = recorded(tmp_path)
    assert (used["ADTECH_PORT_WALL"], used["PROFILE"]) == ("no", profile)
    assert used == verify.apply_settings(conf) and "adtech_wall=no" in out.stdout


@pytest.mark.parametrize("line", ["", "PROFILE=\n", "PROFILE=lg-webos\n"])
def test_the_lg_profile_named_or_by_default_keeps_the_wall(tmp_path, line):
    """The reference's settings file names PROFILE=lg-webos; a conf from before the key exists has none.
    Both get the wall exactly as before, and the record names lg-webos."""
    conf = CONF + line
    out = run_apply(tmp_path, conf=conf)
    assert out.returncode == 0, out.stderr
    lines = chain(ruleset(tmp_path), "tv_out")
    assert LOG in lines and REJECT in lines
    used = recorded(tmp_path)
    assert (used["ADTECH_PORT_WALL"], used["PROFILE"]) == ("yes", "lg-webos")
    assert used == verify.apply_settings(conf) and "adtech_wall=yes" in out.stdout


def test_the_lg_profile_named_renders_what_no_profile_renders(tmp_path):
    """Writing PROFILE=lg-webos changes nothing the firewall holds: the check renders the same rulesets
    byte for byte as for a conf without the key."""
    assert run_check(tmp_path / "absent").returncode == 0
    assert run_check(tmp_path / "named", conf=CONF + "PROFILE=lg-webos\n").returncode == 0
    assert checked(tmp_path / "named") == checked(tmp_path / "absent")
    assert run_check(tmp_path / "generic", conf=CONF + "PROFILE=generic-tv\n").returncode == 0
    assert "LG adtech port" not in checked(tmp_path / "generic")[0]


def test_a_profile_change_is_a_firewall_change_and_an_old_record_reads_as_lg():
    """PROFILE is one of the keys tvgw-apply reads, so a changed profile nobody applied is stale; the
    record of an apply from before PROFILE was recorded reads as lg-webos, so the reference's next
    verify is quiet until its next apply writes the line."""
    assert "PROFILE" in verify.APPLY_KEYS and verify.WALL_PROFILE == "lg-webos"
    lg = CONF + "PROFILE=lg-webos\n"
    assert verify.apply_settings(lg) == verify.apply_settings(CONF)  # absent means lg-webos
    assert verify.apply_settings(lg + "PROFILE=generic-tv\n") != verify.apply_settings(lg)
    old_record = "".join(f"{k}={v}\n" for k, v in verify.apply_settings(lg).items() if k != "PROFILE")
    assert verify.apply_settings(old_record) == verify.apply_settings(lg)
    generic = verify.apply_settings(CONF + "PROFILE=generic-tv\nADTECH_PORT_WALL=yes\n")
    assert generic["ADTECH_PORT_WALL"] == "no"  # as the script turns it off


def test_the_template_changes_nothing_for_a_settings_file_that_names_lg_webos(tmp_path):
    """The reference's case: a settings file made from the template, its TV and PROFILE=lg-webos written
    in, as the reference's file names them. Its firewall is byte for byte what the same file without a
    PROFILE line renders (what every settings file meant before the template named the general profile),
    the wall included, and verify reads one record from both. The template as shipped, PROFILE=generic-tv,
    renders no wall (design decision 62)."""
    example = (ROOT / "deploy" / "tvgw.conf.example").read_text(encoding="utf-8")
    assert config.parse_conf(example)["PROFILE"] == "generic-tv"
    named = config.update_conf(example, {"TV_MAC": "02:00:00:00:00:01", "PROFILE": "lg-webos"})
    absent = "".join(line for line in named.splitlines(keepends=True) if not line.startswith("PROFILE="))
    assert "PROFILE" not in config.parse_conf(absent) and config.parse_conf(named)["PROFILE"] == "lg-webos"
    for name, conf in (("named", named), ("absent", absent), ("shipped", example)):
        assert run_check(tmp_path / name, conf=conf).returncode == 0, name
    assert checked(tmp_path / "named") == checked(tmp_path / "absent")
    assert LOG in checked(tmp_path / "named")[0] and REJECT in checked(tmp_path / "named")[0]
    assert "LG adtech port" not in checked(tmp_path / "shipped")[0]
    assert verify.apply_settings(named) == verify.apply_settings(absent)
    assert verify.apply_settings(named)["ADTECH_PORT_WALL"] == "yes"
