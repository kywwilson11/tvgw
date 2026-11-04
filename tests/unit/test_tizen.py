"""The Samsung reader (src/tvgw/tizen.py): one GET to a fake TV on 127.0.0.1, never anything else; what a
reading keeps and what it never keeps; the replies it refuses; and how a reading reaches the brief.

Every reply here is synthetic, shaped like the raw replies published in Home Assistant's and samsungtvws'
issues, with each identifier replaced by a documentation value. No test contacts a TV."""

import ast
import json
import socket
import threading
import time
from datetime import datetime
from pathlib import Path

import pytest

from tvgw import cli, db, ingest, queries, tizen
from tvgw.config import Settings

BSSID = "02:00:5e:10:00:01"  # the shape of the access point's address the reply's `ssid` holds
# a 2020 Q60T on its cable, as the published replies are shaped; every identifier is a stand-in
SAMPLE = {
    "device": {
        "FrameTVSupport": "false", "GamePadSupport": "true", "ImeSyncedSupport": "true", "Language": "en_US",
        "OS": "Tizen", "PowerState": "on", "TokenAuthSupport": "true", "VoiceSupport": "true",
        "countryCode": "US", "description": "Samsung DTV RCR", "developerIP": "0.0.0.0", "developerMode": "0",
        "duid": "uuid:00000000-0000-0000-0000-00000000aaaa", "firmwareVersion": "Unknown",
        "id": "uuid:00000000-0000-0000-0000-00000000aaaa", "ip": "10.10.10.17", "model": "20_NIKEL_UHD",
        "modelName": "QN55Q60TAFXZA", "name": "[TV] Living Room Samsung", "networkType": "wired",
        "resolution": "3840x2160", "smartHubAgreement": "true", "type": "Samsung SmartTV",
        "udn": "uuid:00000000-0000-0000-0000-00000000aaaa", "wifiMac": "02:00:5e:10:00:99",
    },
    "isSupport": "{}", "remote": "1.0", "type": "Samsung SmartTV", "version": "2.0.25",
}  # fmt: skip
SECRETS = ("uuid:", "02:00:5e", "Living Room", "10.10.10.17", "0.0.0.0", BSSID)


def reply(body: bytes, status: str = "200 OK", headers: str = "Content-Type: application/json\r\n") -> bytes:
    return f"HTTP/1.1 {status}\r\n{headers}Content-Length: {len(body)}\r\n\r\n".encode() + body


def device(**changes) -> dict:
    dev = {k: v for k, v in {**SAMPLE["device"], **changes}.items() if v is not None}
    return {**SAMPLE, "device": dev}


class FakeTV:
    """A TCP listener on 127.0.0.1 that records every byte it is sent and answers each connection with
    `answer` (raw bytes), then closes, or holds the connection open when `hold` is set."""

    def __init__(self, answer: bytes = b"", hold: bool = False, delay: float = 0.0):
        self.answer, self.hold, self.delay = answer, hold, delay
        self.received: list[bytes] = []
        self.sock = socket.create_server(("127.0.0.1", 0))
        self.port = self.sock.getsockname()[1]
        self.stop = threading.Event()
        self.thread = threading.Thread(target=self._serve, daemon=True)
        self.thread.start()

    def _serve(self):
        self.sock.settimeout(0.2)
        while not self.stop.is_set():
            try:
                conn, _ = self.sock.accept()
            except OSError:
                continue
            with conn:
                conn.settimeout(2)
                data = b""
                while b"\r\n\r\n" not in data:
                    chunk = conn.recv(4096)
                    if not chunk:
                        break
                    data += chunk
                self.received.append(data)
                time.sleep(self.delay)
                try:
                    if self.answer:
                        conn.sendall(self.answer)
                    if self.hold:
                        self.stop.wait(5)
                except OSError:  # the reader hung up on an answer it refused: that is the point
                    pass

    def close(self):
        self.stop.set()
        self.thread.join(6)
        self.sock.close()


@pytest.fixture()
def tv():
    fake = FakeTV(reply(json.dumps(SAMPLE).encode()))
    yield fake
    fake.close()


def read(fake: FakeTV, deadline: float = tizen.DEADLINE) -> tizen.Reading:
    return tizen.read("127.0.0.1", fake.port, get=lambda ip, port: tizen.fetch(ip, port, deadline=deadline))


# ---- one GET, and nothing else ----------------------------------------------------------------------
def test_a_reading_sends_the_one_get_and_nothing_else(tv):
    r = read(tv)
    assert r.read and r.exit_code() == tizen.OK
    assert tv.received == [f"GET /api/v2/ HTTP/1.1\r\nHost: 127.0.0.1:{tv.port}\r\n".encode() + (
        b"Accept: application/json\r\nUser-Agent: tvgw\r\nConnection: close\r\n\r\n"
    )]  # fmt: skip


def test_the_module_can_send_no_other_request():
    """A POST to /api/v2/applications/<id> launches the app on some sets: the module's only bytes on the
    wire are REQUEST, and no string in its code (docstrings aside) opens the remote-control channel,
    names another method or presses a key."""
    source = Path(tizen.__file__).read_text(encoding="utf-8")
    tree = ast.parse(source)
    docstrings = {
        id(node.body[0].value)
        for node in ast.walk(tree)
        if isinstance(node, ast.Module | ast.FunctionDef | ast.ClassDef)
        and node.body
        and isinstance(node.body[0], ast.Expr)
        and isinstance(node.body[0].value, ast.Constant)
    }
    strings = [
        n.value
        for n in ast.walk(tree)
        if isinstance(n, ast.Constant) and isinstance(n.value, str) and id(n) not in docstrings
    ]
    assert tizen.REQUEST.startswith("GET /api/v2/ HTTP/1.1\r\n") and tizen.REQUEST.count("\r\n\r\n") == 1
    assert source.count("sendall(") == 1 and ".send(" not in source and "urlopen" not in source
    for word in (
        "POST",
        "PUT",
        "DELETE",
        "samsung.remote.control",
        "KEY_",
        "ws://",
        "wss://",
        "/applications",
    ):
        assert not any(word in x for x in strings), word


def test_only_an_address_literal_is_asked_and_a_name_never_looked_up(monkeypatch):
    looked_up = []
    monkeypatch.setattr(socket, "getaddrinfo", lambda *a, **k: looked_up.append(a) or [])
    with pytest.raises(ValueError):
        tizen.fetch("tv.example")
    r = tizen.read("tv.example")
    assert not r.reachable and r.error == "AddressValueError" and r.exit_code() == tizen.UNREACHABLE
    assert looked_up == []


def test_no_answer_is_off_with_the_errors_type_only():
    closed = socket.create_server(("127.0.0.1", 0))
    port = closed.getsockname()[1]
    closed.close()
    r = tizen.read("127.0.0.1", port)
    assert not r.reachable and r.error == "ConnectionRefusedError" and r.exit_code() == tizen.UNREACHABLE
    assert r.lines() == [
        "TV unreachable (ConnectionRefusedError): off, or asleep (a Samsung stops answering about a minute"
        " after it goes to standby)"
    ]


def test_a_tv_that_never_answers_runs_out_of_time_once():
    silent = FakeTV(answer=b"", hold=True)
    try:
        began = time.monotonic()
        r = read(silent, deadline=0.5)
        assert time.monotonic() - began < 3
        assert not r.reachable and r.error == "TimeoutError" and len(silent.received) == 1  # no retry
    finally:
        silent.close()


def test_a_whole_reply_is_taken_without_waiting_for_the_close():
    open_tv = FakeTV(reply(json.dumps(SAMPLE).encode()), hold=True)
    try:
        began = time.monotonic()
        assert read(open_tv).read and time.monotonic() - began < 2
    finally:
        open_tv.close()


# ---- what a reading keeps ---------------------------------------------------------------------------
def test_a_wired_reading_keeps_plain_values_and_no_identifier(tv):
    r = read(tv)
    assert r.values == {
        "rest.reply": "ok",
        "model": "QN55Q60TAFXZA",
        "platform": "20_NIKEL_UHD",
        "firmware": "unknown",
        "model.year": "2020",
        "tizen": "5.5 (model year 2020)",
        "power": "Active",
        "network.wired.state": "connected",
        "network.wifi.state": "disconnected",
        "smarthub.agreement": "true",
        "frame": "false",
        "country": "US",
    }
    text = "\n".join(r.lines())
    for secret in SECRETS:
        assert secret not in text, secret
    assert "WARNING" not in text and r.exit_code() == tizen.OK


def test_wifi_mac_in_the_reply_is_no_wifi_signal():
    """wifiMac is in every reply, wired or not: only networkType and ssid say Wi-Fi."""
    values = tizen.device_values(device())
    assert values["network.wifi.state"] == "disconnected"
    assert all("02:00:5e" not in v for v in values.values())


@pytest.mark.parametrize(
    ("changes", "wired", "wifi"),
    [
        ({"networkType": "wireless", "ssid": BSSID}, "unknown", "connected"),
        ({"networkType": "wireless"}, "unknown", "connected"),
        ({"networkType": "wired", "ssid": BSSID}, "connected", "connected"),  # ssid is there only on Wi-Fi
        ({"networkType": None, "ssid": BSSID}, "unknown", "connected"),
    ],
)
def test_wifi_joined_is_a_second_path_and_the_bssid_is_never_kept(changes, wired, wifi):
    r = tizen.read("127.0.0.1", get=lambda ip, port: device(**changes))
    assert (r.values["network.wired.state"], r.values["network.wifi.state"]) == (wired, wifi)
    assert r.second_paths == ["Wi-Fi"] and r.exit_code() == tizen.SECOND_PATH
    assert r.lines()[-1] == (
        "WARNING: the TV has a second network path (Wi-Fi): traffic can leave around the gateway;"
        " Settings > All Settings > Connection > Network > Expert Settings > Wi-Fi"
    )
    text = json.dumps(r.values) + "\n".join(r.lines())
    assert BSSID not in text and "ssid" not in text


def test_no_network_type_and_no_ssid_leave_both_network_keys_out():
    """One network key without the Wi-Fi state would end the brief's Not checked line with nothing read."""
    values = tizen.device_values(device(networkType=None))
    assert "network.wifi.state" not in values and "network.wired.state" not in values


@pytest.mark.parametrize(
    ("code", "year", "tizen_value"),
    [
        ("19_MUSEL_UHD_BASIC", "2019", "5.0 (model year 2019)"),
        ("20_NIKEL_UHD", "2020", "5.5 (model year 2020)"),
        ("21_KANTSU2E_UHD_VOICE", "2021", "6.0 (model year 2021)"),
        ("22_PONTUSM_FTV", "2022", "6.5 (model year 2022)"),
        ("23_KANTSU2E_UB", "2023", "7.0 (model year 2023)"),  # a 2023 set never upgraded
        ("23_X22U_UHD_T09", "2023", "9 (model code _T09)"),  # upgraded in place to One UI Tizen 9
        ("24_KSUE_UB_T09", "2024", "9 (model code _T09)"),
        ("24_PTM_FTV_T09", "2024", "9 (model code _T09)"),
        ("25_PTM_QTV", "2025", "9.0 (model year 2025)"),
        ("26_PTM_QTV", "2026", "10.0 (model year 2026)"),  # no 2026 reply is published yet
        ("26_PTM_QTV_T10", "2026", "unknown (model code ends _T10)"),  # an ending nobody has seen
        ("14_UHD", None, None),  # no Tizen year in the table
        ("QN55Q60T", None, None),
    ],
)
def test_the_model_code_gives_the_year_and_the_tizen_version(code, year, tizen_value):
    values = tizen.device_values(device(model=code))
    assert values.get("model.year") == year and values.get("tizen") == tizen_value


def test_the_profile_header_carries_the_same_tizen_table():
    """The samsung-tizen profile names the version of each year with its source; the reader's table is
    the same one."""
    from importlib import resources

    header = (resources.files("tvgw.profiles") / "samsung-tizen.toml").read_text(encoding="utf-8")
    rows = {}
    for line in header.splitlines():
        parts = line.lstrip("#").split()
        if len(parts) >= 3 and parts[0].isdigit() and len(parts[0]) == 4 and parts[1] == "Tizen":
            rows[int(parts[0])] = parts[2].rstrip(",;")
    assert rows == tizen.TIZEN_BY_YEAR


@pytest.mark.parametrize(
    ("state", "power"),
    [("on", "Active"), ("standby", "Active Standby"), ("Standby", "Active Standby"), (None, "Active"),
     ("sleeping", "unknown")],
)  # fmt: skip
def test_power_in_the_brief_vocabulary(state, power):
    """A Frame showing art says standby, with its screen lit; a set before 2019 says nothing, and an
    answer at all means its IP server is up."""
    assert tizen.device_values(device(PowerState=state))["power"] == power


def test_firmware_unknown_is_recorded_as_unknown_and_never_warned_on():
    r = tizen.read("127.0.0.1", get=lambda ip, port: device(firmwareVersion="Unknown"))
    assert (
        r.values["firmware"] == "unknown"
        and r.exit_code() == tizen.OK
        and not any("WARNING" in x for x in r.lines())
    )
    assert tizen.device_values(device(firmwareVersion="T-KSU2EFUABC-0090"))["firmware"] == "T-KSU2EFUABC-0090"
    assert "firmware" not in tizen.device_values(device(firmwareVersion=None))


def test_a_value_shaped_like_an_identifier_is_invalid_never_kept():
    """Hostile or odd values: a model name holding the access point's address, or the owner's name, or
    something that is not a plain code, reads `invalid`."""
    assert tizen.device_values(device(modelName=BSSID))["model"] == "invalid"
    assert tizen.device_values(device(modelName="QN55X", name="QN55X"))["model"] == "QN55X"  # under 6
    sneaky = tizen.device_values(device(modelName="ABCDEF1234", ssid="ABCDEF1234"))
    assert sneaky["model"] == "invalid"
    assert tizen.device_values(device(modelName="QN55\nWARNING: x"))["model"] == "invalid"
    assert tizen.device_values(device(model={"x": 1}))["platform"] == "invalid"
    assert "country" not in tizen.device_values(device(countryCode="United States of America"))


# ---- what a reading refuses -------------------------------------------------------------------------
@pytest.mark.parametrize(
    ("answer", "reason"),
    [
        (reply(b"", "302 Found", "Location: http://127.0.0.1:3000/\r\n"), "HTTP 302"),  # never followed
        (reply(b"{}", "404 Not Found"), "HTTP 404"),
        (reply(b"[1, 2, 3]"), "not a JSON object"),
        (reply(b"<html>" + BSSID.encode()), "not JSON"),
        (b"SSH-2.0-OpenSSH_9.6 " + BSSID.encode() + b"\r\n\r\n", "not HTTP"),
        (b"HTTP/1.1 200 " + BSSID.encode() + b"\r\nContent-Length: 4\r\n\r\nnull", "not a JSON object"),
        (reply(b"x" * (tizen.REPLY_MAX + 1)), "reply over 64 KiB"),
        (b"HTTP/1.1 200 OK\r\nContent-Length: 100\r\n\r\n{}", "reply cut short"),
        (reply(b"[" * 100_000 + b"]" * 100_000), "reply over 64 KiB"),
        (reply(b"[" * 40_000 + b"]" * 20_000), "not JSON"),  # nested past the parser's depth
    ],
)
def test_an_answer_the_reader_does_not_take_is_kept_with_its_own_reason(answer, reason):
    fake = FakeTV(answer)
    try:
        r = read(fake)
    finally:
        fake.close()
    assert r.reachable and not r.read and r.values == {"rest.reply": f"refused ({reason})"}
    assert r.exit_code() == tizen.NOT_READ and len(fake.received) == 1
    text = "\n".join(r.lines())
    assert (
        BSSID not in text and "WARNING: the device at the TV's address did not answer as a Samsung TV" in text
    )


def test_a_chunked_reply_is_read():
    body = json.dumps(SAMPLE).encode()
    chunks = b"".join(
        b"%x\r\n" % len(body[i : i + 300]) + body[i : i + 300] + b"\r\n" for i in range(0, len(body), 300)
    )
    raw = b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n" + chunks + b"0\r\n\r\n"
    assert tizen.parse(raw) == SAMPLE
    with pytest.raises(tizen.Refused, match="not HTTP"):
        tizen.parse(b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\nzz\r\n")


@pytest.mark.parametrize(
    "info",
    [
        {"device": {"type": "Samsung Soundbar", "OS": "Tizen"}},  # a Samsung, not a TV
        {"device": {"type": "Samsung SmartTV", "OS": "Android"}},
        {"device": {"OS": "Tizen"}, "type": "Speaker"},
        {"device": "Samsung SmartTV"},
        {},
    ],
)
def test_a_reply_that_is_not_a_samsung_tvs_is_recorded_once_as_such(info):
    r = tizen.read("127.0.0.1", get=lambda ip, port: info)
    assert r.values == {"rest.reply": "not a Samsung TV"} and r.exit_code() == tizen.NOT_READ
    assert tizen.identify("127.0.0.1", get=lambda ip, port: info) == tizen.Identity("not-tv")


def test_the_top_level_type_stands_in_for_a_missing_device_type():
    info = {"type": "Samsung SmartTV", "device": {"modelName": "UN55RU7100", "model": "19_MUSEL_UHD_BASIC"}}
    assert tizen.is_samsung_tv(info)
    assert tizen.identify("127.0.0.1", get=lambda ip, port: info) == tizen.Identity(
        "tv", "UN55RU7100", "2019"
    )


def test_identify_is_none_for_nothing_usable():
    def refused(ip, port):
        raise tizen.Refused("HTTP 404")

    def off(ip, port):
        raise ConnectionRefusedError

    assert tizen.identify("127.0.0.1", get=refused) is None and tizen.identify("127.0.0.1", get=off) is None


# ---- the hourly reading: tvgw tvcheck, the store and the brief --------------------------------------
def conf(tmp_path, profile: str) -> str:
    path = tmp_path / "tvgw.conf"
    path.write_text(f"PROFILE={profile}\nTV_IP=10.10.10.17\nSTATE_DIR={tmp_path}\n", encoding="utf-8")
    return str(path)


def test_tvcheck_reads_a_samsung_with_this_module_and_an_lg_never(tmp_path, monkeypatch, capsys):
    from tvgw import lgwebos

    asked = []
    monkeypatch.setattr(tizen, "read", lambda ip: asked.append(("samsung", ip)) or tizen.Reading(
        True, tizen.device_values(device(networkType="wireless", ssid=BSSID))
    ))  # fmt: skip
    monkeypatch.setattr(lgwebos, "read", lambda ip, key_file: asked.append(("lg", ip)) or lgwebos.TvReading(
        False, error=lgwebos.NOT_PAIRED
    ))  # fmt: skip
    assert cli.main(["--conf", conf(tmp_path, "samsung-tizen"), "tvcheck"]) == tizen.SECOND_PATH
    out = capsys.readouterr().out
    assert "network.wifi.state = connected" in out and BSSID not in out
    for profile in ("lg-webos", "roku", "generic-tv"):
        assert cli.main(["--conf", conf(tmp_path, profile), "tvcheck"]) == 4
    assert asked == [
        ("samsung", "10.10.10.17"),
        ("lg", "10.10.10.17"),
        ("lg", "10.10.10.17"),
        ("lg", "10.10.10.17"),
    ]


def store_reading(s: Settings, conn, stamp: str, reading: tizen.Reading) -> None:
    """What tvgw-analyze does with a reading: tvcheck.txt rewritten, one history line, then the ingest."""
    Path(s.tvcheck_txt).write_text(f"read {stamp}\n" + "\n".join(reading.lines()) + "\n", encoding="utf-8")
    with open(s.tvcheck_history, "a", encoding="utf-8") as fh:
        fh.write(f"{stamp}\t{reading.values.get('power', 'unknown')}\t\n")
    ingest.ingest_tvstate(conn, s)
    conn.commit()


@pytest.fixture()
def gw(tmp_path):
    s = Settings(
        state_dir=str(tmp_path), db_path=str(tmp_path / "tvgw.db"), tvcheck_txt=str(tmp_path / "tvcheck.txt"),
        tvcheck_history=str(tmp_path / "tvcheck-history.log"), profile="samsung-tizen",
    )  # fmt: skip
    return s, db.connect(s.db_path)


def test_a_samsung_on_its_cable_is_a_checked_fact_and_wifi_turning_on_a_red_line(gw):
    s, conn = gw
    until = datetime.fromisoformat("2026-11-05T00:00:00-06:00").timestamp()
    assert queries.not_checked(conn, until, queries.tv_paths(conn, until))  # nothing read yet
    wired = tizen.read("127.0.0.1", get=lambda ip, port: device())
    store_reading(s, conn, "2026-11-04T09:20:00-06:00", wired)
    paths = queries.tv_paths(conn, until)
    assert {k: v["value"] for k, v in paths.items()} == {
        "network.wired.state": "connected",
        "network.wifi.state": "disconnected",
    }
    assert queries.not_checked(conn, until, paths) == [] and queries.red_lines({"tv_paths": paths}) == []
    joined = tizen.read("127.0.0.1", get=lambda ip, port: device(networkType="wireless", ssid=BSSID))
    store_reading(s, conn, "2026-11-04T10:20:00-06:00", joined)
    (line,) = queries.red_lines({"tv_paths": queries.tv_paths(conn, until)})
    assert line.startswith("TV has a second network path: Wi-Fi is connected (since ")
    stored = conn.execute("SELECT key, value FROM tvsettings ORDER BY t, key").fetchall()
    assert all(BSSID not in v and "uuid" not in v for _, v in stored)
    assert ("power", "Active") not in stored  # the power goes to tvstate, as LG's does
    assert conn.execute("SELECT power FROM tvstate ORDER BY t").fetchall() == [("Active",), ("Active",)]


def test_a_device_that_is_not_a_samsung_tv_is_stored_once(gw):
    s, conn = gw
    soundbar = tizen.read("127.0.0.1", get=lambda ip, port: {"device": {"type": "Samsung Soundbar"}})
    for hour in ("09", "10", "11"):
        store_reading(s, conn, f"2026-11-04T{hour}:20:00-06:00", soundbar)
    assert conn.execute("SELECT key, value FROM tvsettings").fetchall() == [
        ("rest.reply", "not a Samsung TV")
    ]
    assert conn.execute("SELECT DISTINCT power FROM tvstate").fetchall() == [("unknown",)]
