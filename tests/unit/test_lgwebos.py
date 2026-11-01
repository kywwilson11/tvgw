import asyncio

from tvgw import lgwebos
from tvgw.lgwebos import TvReading, clean


def test_reading_lines_and_exit_codes():
    off = TvReading(True, {"option.livePlus": "off", "power": "Active"})
    assert off.acr_off is True and off.exit_code() == 0
    assert off.lines() == ["option.livePlus = off", "power = Active"]
    on = TvReading(True, {"option.livePlus": "on"})
    assert on.acr_off is False and on.exit_code() == 2 and any("WARNING" in ln for ln in on.lines())
    unknown = TvReading(True, {"power": "Active"})
    assert unknown.acr_off is None and unknown.exit_code() == 0
    down = TvReading(False, error="OSError")
    assert down.exit_code() == 1 and "unreachable (OSError)" in down.lines()[0]


def test_values_are_one_printable_line():
    assert clean("Living room\nTV\x1b[2J") == "Living room TV [2J"
    assert clean(None) == "None" and len(clean("x" * 500)) == 200


def test_read_never_hangs(monkeypatch):
    async def stuck(ip, key_file, timeout, r):
        await asyncio.sleep(60)

    monkeypatch.setattr(lgwebos, "_read", stuck)
    r = lgwebos.read("10.10.10.17", "/nonexistent", timeout=0.01)
    assert r.reachable is False and r.error == "TimeoutError" and r.exit_code() == 1


def test_a_reading_cut_short_keeps_what_it_read(monkeypatch):
    """A TV that stalls on several keys runs the whole reading out of time; the keys read first, Live
    Plus among them, must not be lost with it, or the hourly job reports unreachable instead of ACR."""
    import sys
    from types import SimpleNamespace

    class StallingTv:
        stall = {"zipcode", "country", "audioGuidance", "storeMode", "deviceName"}

        @classmethod
        async def create(cls, ip, states, key_file_path):
            return cls()

        async def connect(self):
            pass

        async def get_system_settings(self, cat, keys):
            if keys[0] in self.stall:
                await asyncio.sleep(60)
            return {"settings": {keys[0]: "off"}}

        async def disconnect(self):
            pass

    monkeypatch.setitem(sys.modules, "bscpylgtv", SimpleNamespace(WebOsClient=StallingTv))
    r = lgwebos.read("10.10.10.17", "/nonexistent", timeout=0.05)
    assert r.reachable is True and r.values["option.livePlus"] == "off" and r.exit_code() == 0
    unread = [k for k, v in r.values.items() if v.startswith("ERR ")]
    assert "other.simplinkEnable" in unread and "option.zipcode" in unread


STATUS = {  # connectionmanager/getstatus on webOS 5 with the TV wired and its Wi-Fi off, addresses left out
    "returnValue": True,
    "offlineMode": "disabled",
    "wired": {"state": "connected", "interfaceName": "eth0", "method": "dhcp", "onInternet": "yes"},
    "wifi": {"state": "disconnected", "tetheringEnabled": False},
    "wifiDirect": {"state": "disconnected"},
    "bluetooth": {"state": "disconnected", "tetheringEnabled": False},
    "cellular": {"enabled": False},
    "wan": {"connected": False, "connectedContexts": []},
}


def test_paths_turn_the_status_into_settings_and_never_guess():
    assert lgwebos.paths(STATUS) == {
        "network.wired.state": "connected",
        "network.wifi.state": "disconnected",
        "network.wifiDirect.state": "disconnected",
        "network.wifi.tethering": "off",
        "network.bluetooth.tethering": "off",
    }
    # a TV that leaves parts out, or answers something that is not a status at all
    assert lgwebos.paths({"wired": {"state": "connected"}})["network.wifi.state"] == "unknown"
    assert lgwebos.paths({"wifi": {"state": "connected"}})["network.wifi.tethering"] == "unknown"
    assert set(lgwebos.paths(None).values()) == {"unknown"}
    assert lgwebos.paths({"wifi": {"state": "con\nnected\x1b"}})["network.wifi.state"] == "con nected "


def test_a_second_path_is_a_radio_on_or_a_tethering_switch_on_never_an_unknown():
    assert lgwebos.is_second_path("network.wifi.state", "connected")
    assert lgwebos.is_second_path("network.wifiDirect.state", "connecting")
    assert lgwebos.is_second_path("network.wifi.tethering", "on")
    for value in ("disconnected", "unknown", "ERR TimeoutError", None):
        assert not lgwebos.is_second_path("network.wifi.state", value), value
    assert not lgwebos.is_second_path("network.bluetooth.tethering", "off")
    assert not lgwebos.is_second_path("network.bluetooth.tethering", "disconnected")


def test_a_reading_with_a_second_path_warns_and_exits_3():
    wired = TvReading(True, {"option.livePlus": "off", **lgwebos.paths(STATUS)})
    assert wired.second_paths == [] and wired.exit_code() == 0
    assert not any("second network path" in ln for ln in wired.lines())
    on = TvReading(
        True, {"option.livePlus": "off", **lgwebos.paths(STATUS), "network.wifi.state": "connected"}
    )
    assert on.second_paths == ["Wi-Fi"] and on.exit_code() == 3
    assert on.lines()[-1] == (
        "WARNING: the TV has a second network path (Wi-Fi): traffic can leave around the gateway;"
        " Settings > Network"
    )
    both = TvReading(True, {"option.livePlus": "on", "network.wifi.tethering": "on"})
    assert both.second_paths == ["Wi-Fi tethering"] and both.exit_code() == 3  # the bypass outranks ACR
    assert sum("WARNING" in ln for ln in both.lines()) == 2


def test_read_asks_the_tv_for_its_network_paths_and_survives_a_tv_that_cannot_say(monkeypatch):
    import sys
    from types import SimpleNamespace

    class Tv:
        answer = STATUS

        @classmethod
        async def create(cls, ip, states, key_file_path):
            return cls()

        async def connect(self):
            pass

        async def get_system_settings(self, cat, keys):
            return {"settings": {keys[0]: "off"}}

        async def request(self, uri):
            assert uri == lgwebos.PATHS_URI
            if isinstance(self.answer, Exception):
                raise self.answer
            return self.answer

        async def disconnect(self):
            pass

    monkeypatch.setitem(sys.modules, "bscpylgtv", SimpleNamespace(WebOsClient=Tv))
    r = lgwebos.read("10.10.10.17", "/nonexistent", timeout=0.5)
    assert r.reachable and r.values["network.wifi.state"] == "disconnected" and r.exit_code() == 0
    assert "network.paths" not in r.values
    Tv.answer = RuntimeError("404 no such service or method")
    r = lgwebos.read("10.10.10.17", "/nonexistent", timeout=0.5)
    assert r.values["option.livePlus"] == "off" and r.values["network.paths"].startswith("ERR RuntimeError")
    assert "network.wifi.state" not in r.values and r.exit_code() == 0  # unread is not a second path
