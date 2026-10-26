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
