"""Settings file parsing."""

from tvgw import config


def test_parse_conf_handles_quotes_comments_and_junk():
    text = """# tvgw settings
WAN_IF=wlan0
UPLINK=direct   # streaming-friendly
DB_DAYS="400"
PROFILE='lg-webos'
TV_IP=10.10.10.17
lowercase=ignored
  INDENTED=ok
"""
    c = config.parse_conf(text)
    assert c == {
        "WAN_IF": "wlan0",
        "UPLINK": "direct",
        "DB_DAYS": "400",
        "PROFILE": "lg-webos",
        "TV_IP": "10.10.10.17",
        "INDENTED": "ok",
    }


def test_load_applies_known_keys_types_and_overrides(tmp_path):
    f = tmp_path / "tvgw.conf"
    f.write_text("TV_IP=10.0.0.5\nDB_DAYS=90\nSTATE_DIR=/tmp/x\nUNRELATED=1\nPROFILE=\n")
    s = config.load(f, db_path="/tmp/x/t.db")
    assert s.tv_ip == "10.0.0.5" and s.db_days == 90 and s.state_dir == "/tmp/x"
    assert s.profile == "lg-webos"  # empty value keeps the default
    assert s.db_path == "/tmp/x/t.db"
    assert s.gw_ip == "10.10.10.1"


def test_missing_conf_gives_defaults(tmp_path):
    s = config.load(tmp_path / "nope.conf")
    assert s == config.Settings()


def test_a_conf_that_cannot_be_read_is_an_error_not_the_defaults(tmp_path):
    """The file is 640 root:adm on the gateway; a reader outside adm would otherwise get a Settings
    that looks right and records nothing (the hardware suite's conf-exists assertion was written
    against exactly that)."""
    import os

    import pytest

    if os.geteuid() == 0:
        pytest.skip("root reads a mode-000 file")
    conf = tmp_path / "tvgw.conf"
    conf.write_text("TV_IP=10.10.10.18\n")
    conf.chmod(0)
    try:
        with pytest.raises(PermissionError):
            config.load(conf)
    finally:
        conf.chmod(0o600)
    with pytest.raises(IsADirectoryError):
        config.load(tmp_path)


def test_addresses_must_parse(tmp_path):
    """Every source keeps rows equal to TV_IP: a typo would record nothing while every source read."""
    import pytest

    conf = tmp_path / "tvgw.conf"
    for text in ("TV_IP=10.10.10.17x\n", "GW_IP=gateway\n"):
        conf.write_text(text)
        with pytest.raises(ValueError, match="not an IP address"):
            config.load(conf)
    conf.write_text("TV_IP=10.10.10.18\nGW_IP=10.10.10.1\n")
    assert config.load(conf).tv_ip == "10.10.10.18"


def test_firewall_knobs_are_read_and_bad_integers_rejected(tmp_path):
    import pytest

    from tvgw import config

    conf = tmp_path / "tvgw.conf"
    conf.write_text("UPLINK=vpn\nWAN_IF=eth1\nBLOCK_QUIC=no\nSTRICT_PORTS=yes\nDB_DAYS=30\n")
    s = config.load(conf)
    assert (s.uplink, s.wan_if, s.block_quic, s.strict_ports, s.db_days) == ("vpn", "eth1", "no", "yes", 30)
    conf.write_text("DB_DAYS=0\n")
    with pytest.raises(ValueError, match="at least 1"):
        config.load(conf)
    conf.write_text("DB_DAYS=many\n")
    with pytest.raises(ValueError, match="whole number"):
        config.load(conf)


def test_switches_must_be_exact(tmp_path):
    """tvgw-apply compares them with `case ... yes | no)`: `BLOCK_QUIC=Yes` dropped the QUIC rule
    silently and verify, reading the same value, stopped looking for it."""
    import pytest

    conf = tmp_path / "tvgw.conf"
    for text, key in (
        ("BLOCK_QUIC=Yes\n", "BLOCK_QUIC"),
        ("STRICT_PORTS=on\n", "STRICT_PORTS"),
        ("UPLINK=tunnel\n", "UPLINK"),
    ):
        conf.write_text(text)
        with pytest.raises(ValueError, match=f"{key}=.* expected one of"):
            config.load(conf)
    with pytest.raises(ValueError, match="UPLINK='vpn0'"):
        config.load(conf, uplink="vpn0")  # overrides are judged too
    for text in (
        "UPLINK=vpn\nBLOCK_QUIC=no\nSTRICT_PORTS=yes\n",
        "UPLINK=direct\nBLOCK_QUIC=yes\nSTRICT_PORTS=no\n",
    ):
        conf.write_text(text)
        config.load(conf)


def test_pcap_retention_settings_are_numbers_above_zero(tmp_path):
    import pytest

    conf = tmp_path / "tvgw.conf"
    conf.write_text("PCAP_DAYS=3\nPCAP_MAX_GB=1.5\n")
    s = config.load(conf)
    assert (s.pcap_days, s.pcap_max_gb) == (3, 1.5)
    assert (config.Settings().pcap_days, config.Settings().pcap_max_gb) == (7, 1.5)
    # a typo must never read as "keep nothing", which `awk -v g=abc` made of it in the bash prune
    for text in (
        "PCAP_MAX_GB=abc\n",
        "PCAP_MAX_GB=0\n",
        "PCAP_MAX_GB=-1\n",
        "PCAP_MAX_GB=inf\n",
        "PCAP_MAX_GB=nan\n",
    ):
        conf.write_text(text)
        with pytest.raises(ValueError, match="PCAP_MAX_GB"):
            config.load(conf)
    conf.write_text("PCAP_DAYS=0\n")
    with pytest.raises(ValueError, match="PCAP_DAYS"):
        config.load(conf)


def test_an_unquoted_value_with_a_space_is_refused_as_the_shell_would(tmp_path):
    """The shell scripts source the conf: `KEY=Mon 04:10` sets KEY for a command named `04:10` and
    stops the script under `set -e`. Python must not read a value the shell never sees."""
    import pytest

    conf = tmp_path / "tvgw.conf"
    for text in ("ANALYST_WEEKLY_SCHEDULE=Mon 04:10\n", "ANALYST_SCHEDULE=*-*-* 06,18:00:00   # twice\n"):
        conf.write_text(text)
        with pytest.raises(ValueError, match=r"ANALYST_.*SCHEDULE=.* must be quoted"):
            config.load(conf)
    conf.write_text("ANALYST_WEEKLY_SCHEDULE=\"Mon 04:10\"\nANALYST_SCHEDULE='*-*-* 06,18:00:00'  # twice\n")
    s = config.load(conf)
    assert (s.analyst_weekly_schedule, s.analyst_schedule) == ("Mon 04:10", "*-*-* 06,18:00:00")


# ---- (reserved) the keys nothing reads yet -----------------------------------------------------------
# Each key and the value a settings file without it gets, which is how the gateway behaves today
RESERVED = {
    "UPDATE_CHECK": "off",
    "UPDATE_REPO": "kywwilson11/tvgw",
    "TV_PAIR_MANIFEST": "auto",
    "TV_DHCP": "open",
    "BACKUP_KEEP": "7",
    "TV_PORT_MANAGER": "auto",
    "NETWATCH": "auto",
    "DEPLOY_WINDOW": "03:30-05:30",
}


# (plain) the day-0 keys a release has started to read: still today's behaviour when absent
READ = {
    "BRIEF_STYLE": "full",
    "LOCAL_RULES": "/etc/tvgw/local.rules",
    "WAN_GW_MODE": "literal",
    "ADGUARD_TAKE_OVER": "ask",  # (adguard)
    "LIVE_READING": "off",  # (app in front) no session to the TV is held
    "TV_EVENTS_DAYS": "14",  # (app in front)
    "VPN_DNS_SEAL": "off",  # (reliability) the gateway's own lookups are never held
    "THREAT_LISTS": "off",  # (threats) nothing is downloaded or matched
}


def test_a_file_without_the_reserved_keys_reads_as_today(tmp_path):
    """A settings file from before the keys has none of them: every one must come out at today's
    behaviour, and an empty value must keep the default, as the shell's `${KEY:=default}` does."""
    s = config.load(tmp_path / "missing.conf")
    absent = {**RESERVED, **READ}
    assert {key: str(getattr(s, config.CONF_KEYS[key])) for key in absent} == absent
    conf = tmp_path / "tvgw.conf"
    conf.write_text("".join(f"{key}=\n" for key in absent))
    assert config.load(conf) == config.Settings()


def test_backup_keep_defaults_to_what_tvgw_backup_keeps_today():
    from tvgw import cli

    assert cli.build_parser().parse_args(["backup"]).keep == config.Settings().backup_keep


def test_the_reserved_switches_take_exactly_their_values_default_first(tmp_path):
    """A near miss (`TV_DHCP=Pinned`) fails at the first command instead of waiting, unread, for the
    release that reads the key. None of them is a tvgw-apply `case`, so none is in CHOICES."""
    import pytest

    assert set(config.MODES) <= set(RESERVED) | set(READ) and not set(config.MODES) & set(config.CHOICES)
    conf = tmp_path / "tvgw.conf"
    for key, allowed in config.MODES.items():
        assert allowed[0] == {**RESERVED, **READ}[key], key
        for value in allowed:
            conf.write_text(f"{key}={value}\n")
            assert getattr(config.load(conf), config.CONF_KEYS[key]) == value
        for near in (allowed[-1].capitalize(), "yes", f"{allowed[0]}x"):
            conf.write_text(f"{key}={near}\n")
            with pytest.raises(ValueError, match=f"{key}='{near}' in tvgw.conf: expected one of"):
                config.load(conf)
    with pytest.raises(ValueError, match="NETWATCH='always'"):
        config.load(tmp_path / "missing.conf", netwatch="always")  # overrides are judged too


def test_backup_keep_is_a_whole_number_of_days(tmp_path):
    import pytest

    conf = tmp_path / "tvgw.conf"
    conf.write_text("BACKUP_KEEP=3\n")
    assert config.load(conf).backup_keep == 3
    for value, why in (("0", "at least 1"), ("-2", "at least 1"), ("3d", "whole number")):
        conf.write_text(f"BACKUP_KEEP={value}\n")
        with pytest.raises(ValueError, match=f"BACKUP_KEEP='{value}' in tvgw.conf: .*{why}"):
            config.load(conf)


def test_update_repo_is_a_github_owner_and_name(tmp_path):
    """The update check puts it into an API path: a URL, a query or a further segment must not pass."""
    import pytest

    conf = tmp_path / "tvgw.conf"
    for good in ("kywwilson11/tvgw", "example-org/tvgw.fork", "a/b", "x/.github", f"{'o' * 39}/{'r' * 100}"):
        conf.write_text(f"UPDATE_REPO={good}\n")
        assert config.load(conf).update_repo == good
    for bad in (
        "kywwilson11",
        "kywwilson11/tvgw/releases",
        "https://github.com/kywwilson11/tvgw",
        "-org/tvgw",
        "org/..",
        "org/.",
        "org/tvgw?per_page=1",
        f"{'o' * 40}/tvgw",
        f"org/{'r' * 101}",
        '"org/two words"',
    ):
        conf.write_text(f"UPDATE_REPO={bad}\n")
        with pytest.raises(ValueError, match=r"UPDATE_REPO=.* expected a GitHub repository as owner/name"):
            config.load(conf)


def test_local_rules_is_an_absolute_file_apart_from_the_machines_rules(tmp_path):
    """The machine rewrites AUTO_RULES on its own; the owner's rules in that file would go with it."""
    import pytest

    conf = tmp_path / "tvgw.conf"
    conf.write_text("LOCAL_RULES=/var/lib/tvgw/site.rules\n")
    assert config.load(conf).local_rules == "/var/lib/tvgw/site.rules"
    for bad in (
        "local.rules",
        "etc/tvgw/local.rules",
        "/etc/tvgw/../tvgw/local.rules",
        "/etc/tvgw/./x",
        "/etc//tvgw/local.rules",
        "//etc/tvgw/local.rules",  # normpath keeps a leading pair
        "/etc/tvgw/",
        "/",
    ):
        conf.write_text(f"LOCAL_RULES={bad}\n")
        with pytest.raises(ValueError, match=r"LOCAL_RULES=.* expected an absolute path to a file"):
            config.load(conf)
    for text in (
        "LOCAL_RULES=/var/lib/tvgw/auto.rules\n",
        "AUTO_RULES=/etc/tvgw/local.rules\n",
        "LOCAL_RULES=/etc/tvgw/x.rules\nAUTO_RULES=/etc/tvgw/x.rules\n",
        "LOCAL_RULES=/etc/tvgw/x.rules\nAUTO_RULES=/etc/tvgw//x.rules\n",
        "LOCAL_RULES=/var/lib/tvgw/auto.rules\nAUTO_RULES=//var/lib/tvgw/auto.rules\n",  # Linux reads one /
    ):
        conf.write_text(text)
        with pytest.raises(ValueError, match="the owner's rules cannot be AUTO_RULES"):
            config.load(conf)


def test_deploy_window_is_two_different_times_of_day(tmp_path):
    import pytest

    conf = tmp_path / "tvgw.conf"
    for good in ("03:30-05:30", "23:00-01:30", "00:00-23:59"):
        conf.write_text(f"DEPLOY_WINDOW={good}\n")
        assert config.load(conf).deploy_window == good
    for bad in (
        "3:30-5:30",
        "03:30",
        "03:30-",
        "24:00-01:00",
        "03:60-04:00",
        "03:30-03:30",
        "03.30-05.30",
        '"03:30 - 05:30"',
        "03:30-05:30-07:00",
    ):
        conf.write_text(f"DEPLOY_WINDOW={bad}\n")
        with pytest.raises(ValueError, match=r"DEPLOY_WINDOW=.* expected HH:MM-HH:MM"):
            config.load(conf)


def test_the_writer_takes_the_reserved_keys_and_refuses_what_load_refuses():
    """`tvgw setup` writes the settings file through update_conf: a release that sets one of these on a
    new install needs no change to the writer, and cannot write a value every command would refuse."""
    import pytest

    out = config.update_conf("", {"TV_DHCP": "pinned", "BACKUP_KEEP": "3", "DEPLOY_WINDOW": "02:00-04:00"})
    s = config.check_conf(out)
    assert (s.tv_dhcp, s.backup_keep, s.deploy_window) == ("pinned", 3, "02:00-04:00")
    assert set(RESERVED) | set(READ) <= config.writable_keys()
    with pytest.raises(ValueError, match="UPDATE_CHECK='daily'"):
        config.update_conf("", {"UPDATE_CHECK": "daily"})


def test_the_template_lists_each_reserved_key_commented_out_at_its_default():
    """New installs start from the template: each key shows its default on a commented line, so the
    file a new install gets reads exactly as a file without the keys (nothing reads them yet)."""
    import re

    from conftest import ROOT

    text = (ROOT / "deploy" / "tvgw.conf.example").read_text(encoding="utf-8")
    shown = dict(re.findall(r"^# ([A-Z][A-Z0-9_]*)=(\S+) ", text, re.M))
    assert {key: shown.get(key) for key in RESERVED} == RESERVED
    assert not set(RESERVED) & set(config.parse_conf(text))
    # (site rules) a key a release reads and new installs leave at its default: commented, alone on its line
    alone = dict(re.findall(r"^# ([A-Z][A-Z0-9_]*)=(\S+)$", text, re.M))
    for key in ("LOCAL_RULES", "WAN_GW_MODE", "ADGUARD_TAKE_OVER"):  # (site rules), (uplink), (adguard)
        assert alone.get(key) == READ[key] and key not in config.parse_conf(text), key


def test_adguard_take_over_is_ask_no_or_yes_and_ask_when_absent(tmp_path):
    """(adguard) Whether tvgw may take over an AdGuard Home it did not set up: by the evidence (ask), never
    on any (no), or always (yes); a near miss must stop every command, never read as one of them."""
    import pytest

    conf = tmp_path / "tvgw.conf"
    assert config.load(conf).adguard_take_over == "ask"
    for value in ("ask", "no", "yes"):
        conf.write_text(f"ADGUARD_TAKE_OVER={value}\n")
        assert config.load(conf).adguard_take_over == value
    for bad in ("Yes", "true", "1", "on", "Ask"):
        conf.write_text(f"ADGUARD_TAKE_OVER={bad}\n")
        with pytest.raises(ValueError, match=r"ADGUARD_TAKE_OVER=.* expected ask, no or yes"):
            config.load(conf)
    assert "ADGUARD_TAKE_OVER" in config.writable_keys()
