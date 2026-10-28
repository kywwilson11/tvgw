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
