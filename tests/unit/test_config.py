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
