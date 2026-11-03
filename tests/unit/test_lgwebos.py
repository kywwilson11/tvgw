import asyncio
import os
import stat
import sys

import pytest
from conftest import ROOT, counting_lgtv, fake_lgtv

from tvgw import cli, lgwebos
from tvgw.lgwebos import TvReading, clean

TV = "10.10.10.17"


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
    unpaired = TvReading(False, error=lgwebos.NOT_PAIRED)
    assert unpaired.exit_code() == 4 and unpaired.lines() == [
        "TV not paired: the gateway holds no key for it, so nothing was asked. Pair once with"
        " `sudo tvgw tv pair` and accept the prompt on the TV"
    ]


def test_values_are_one_printable_line():
    assert clean("Living room\nTV\x1b[2J") == "Living room TV [2J"
    assert clean(None) == "None" and len(clean("x" * 500)) == 200


def test_read_never_hangs(monkeypatch):
    async def stuck(ip, key_file, timeout, r, register=False):
        await asyncio.sleep(60)

    monkeypatch.setattr(lgwebos, "_read", stuck)
    r = lgwebos.read("10.10.10.17", "/nonexistent", timeout=0.01)
    assert r.reachable is False and r.error == "TimeoutError" and r.exit_code() == 1


def test_a_reading_cut_short_keeps_what_it_read(monkeypatch, tmp_path):
    """A TV that stalls on several keys runs the whole reading out of time; the keys read first, Live
    Plus among them, must not be lost with it, or the hourly job reports unreachable instead of ACR."""

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

    keys = tmp_path / "lgtv-keys.sqlite"
    fake_lgtv(monkeypatch, StallingTv, {TV: "key"}, keys)
    r = lgwebos.read(TV, str(keys), timeout=0.05)
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


def test_read_asks_the_tv_for_its_network_paths_and_survives_a_tv_that_cannot_say(monkeypatch, tmp_path):
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

    keys = tmp_path / "lgtv-keys.sqlite"
    fake_lgtv(monkeypatch, Tv, {TV: "key"}, keys)
    r = lgwebos.read(TV, str(keys), timeout=0.5)
    assert r.reachable and r.values["network.wifi.state"] == "disconnected" and r.exit_code() == 0
    assert "network.paths" not in r.values
    Tv.answer = RuntimeError("404 no such service or method")
    r = lgwebos.read(TV, str(keys), timeout=0.5)
    assert r.values["option.livePlus"] == "off" and r.values["network.paths"].startswith("ERR RuntimeError")
    assert "network.wifi.state" not in r.values and r.exit_code() == 0  # unread is not a second path


# ---- (pairing) a reading never pairs: design decision 54 ----------------------------------------------


def calls(counts) -> tuple[int, int, int, int]:
    return counts["create"], counts["connect"], counts["register"], counts["prompts"]


def test_a_reading_without_a_key_asks_the_tv_nothing(monkeypatch, tmp_path):
    """The library registers on every connection, and a registration without a key is the pairing
    prompt on the TV's screen: once an hour, after a pairing the owner declined."""
    tv, counts = counting_lgtv()
    fake_lgtv(monkeypatch, tv)
    keys = tmp_path / "lgtv-keys.sqlite"
    r = lgwebos.read(TV, str(keys))
    assert (r.reachable, r.error, r.exit_code()) == (False, lgwebos.NOT_PAIRED, 4)
    assert calls(counts) == (0, 0, 0, 0)
    assert not keys.exists()  # opening the library's store would have created it
    keys.write_text('{"10.10.10.18": "key"}', encoding="utf-8")  # a key for another address only
    assert lgwebos.read(TV, str(keys)).error == lgwebos.NOT_PAIRED and calls(counts) == (0, 0, 0, 0)


def test_pair_registers_once_and_the_key_is_root_only_from_its_first_byte(monkeypatch, tmp_path):
    tv, counts = counting_lgtv()
    fake_lgtv(monkeypatch, tv)
    keys = tmp_path / "lgtv-keys.sqlite"
    before = os.umask(0o022)
    try:
        r = lgwebos.pair(TV, str(keys), timeout=0.5)
        assert os.umask(0o022) == 0o022  # the caller's umask is back
    finally:
        os.umask(before)
    assert r.reachable and r.values["power"] == "Active" and r.exit_code() == 0
    assert calls(counts) == (1, 1, 1, 1)
    assert counts["born"] == 0o600 and stat.S_IMODE(keys.stat().st_mode) == 0o600
    assert lgwebos.has_key(str(keys), TV)
    # the hourly reading now connects with the stored key, and the TV shows no new prompt
    assert lgwebos.read(TV, str(keys), timeout=0.5).exit_code() == 0
    assert calls(counts) == (2, 2, 2, 1)


def test_pair_closes_up_a_key_an_older_pairing_left_readable(monkeypatch, tmp_path):
    """A key made with the library's own command carries that command's umask, 0644 under sudo's 022."""
    tv, counts = counting_lgtv()
    keys = tmp_path / "lgtv-keys.sqlite"
    fake_lgtv(monkeypatch, tv, {TV: "key"}, keys)
    keys.chmod(0o644)
    assert lgwebos.pair(TV, str(keys), timeout=0.5).reachable
    assert counts["prompts"] == 0 and stat.S_IMODE(keys.stat().st_mode) == 0o600


def test_a_declined_pairing_leaves_no_key_and_the_next_reading_asks_nothing(monkeypatch, tmp_path):
    tv, counts = counting_lgtv(accept=False)
    fake_lgtv(monkeypatch, tv)
    keys = tmp_path / "lgtv-keys.sqlite"
    r = lgwebos.pair(TV, str(keys), timeout=0.5)
    assert not r.reachable and r.error == "RuntimeError" and r.exit_code() == 1
    assert calls(counts) == (1, 1, 1, 1) and not lgwebos.has_key(str(keys), TV)
    assert stat.S_IMODE(keys.stat().st_mode) == 0o600  # the library's empty store, root's alone
    assert lgwebos.read(TV, str(keys)).error == lgwebos.NOT_PAIRED and calls(counts) == (1, 1, 1, 1)


@pytest.mark.parametrize(
    ("content", "paired"),
    [
        (None, False),  # no key file
        ('{"10.10.10.17": "key"}', True),
        ('{"10.10.10.18": "key"}', False),  # another address
        ('{"10.10.10.17": ""}', False),  # an empty key is no key to the TV
        ('{"10.10.10.17": null}', False),
        ("not the library's database", False),
    ],
)
def test_has_key_only_reads_and_finds_a_key_for_this_tv_alone(monkeypatch, tmp_path, content, paired):
    fake_lgtv(monkeypatch, counting_lgtv()[0])
    keys = tmp_path / "lgtv-keys.sqlite"
    if content is not None:
        keys.write_text(content, encoding="utf-8")
    assert lgwebos.has_key(str(keys), TV) is paired
    assert keys.exists() == (content is not None)


def test_has_key_without_the_library_is_no_key(monkeypatch, tmp_path):
    monkeypatch.setitem(sys.modules, "bscpylgtv", None)  # the import fails, as without the extra
    monkeypatch.setitem(sys.modules, "bscpylgtv.storage_sqlitedict", None)
    keys = tmp_path / "lgtv-keys.sqlite"
    keys.write_text('{"10.10.10.17": "key"}', encoding="utf-8")
    assert not lgwebos.has_key(str(keys), TV)


def conf(tmp_path, profile: str = "lg-webos") -> str:
    path = tmp_path / "tvgw.conf"
    path.write_text(f"PROFILE={profile}\nTV_IP={TV}\n", encoding="utf-8")
    return str(path)


def test_tvcheck_exits_4_and_asks_the_tv_nothing_without_a_key(monkeypatch, tmp_path, capsys):
    tv, counts = counting_lgtv()
    fake_lgtv(monkeypatch, tv)
    keys = tmp_path / "lgtv-keys.sqlite"
    assert cli.main(["--conf", conf(tmp_path), "tvcheck", "--key-file", str(keys)]) == 4
    assert capsys.readouterr().out.startswith("TV not paired:")
    assert calls(counts) == (0, 0, 0, 0) and not keys.exists()


def test_tv_pair_says_what_the_prompt_is_then_pairs_and_reads(monkeypatch, tmp_path, capsys):
    from tvgw import setup

    tv, counts = counting_lgtv()
    fake_lgtv(monkeypatch, tv)
    monkeypatch.setattr(os, "geteuid", lambda: 0)
    keys = tmp_path / "lgtv-keys.sqlite"
    argv = ["--conf", conf(tmp_path), "tv", "pair", "--key-file", str(keys)]
    assert cli.main(argv) == 0
    out = capsys.readouterr().out
    assert out.index(setup.NOT_AN_AGREEMENT) < out.index("accept the connection prompt")
    assert out.index("accept the connection prompt") < out.index("paired; the TV reads:")
    assert "power = Active" in out and calls(counts) == (1, 1, 1, 1)
    assert stat.S_IMODE(keys.stat().st_mode) == 0o600
    assert cli.main(argv) == 0  # again: the stored key, no explanation and no prompt
    out = capsys.readouterr().out
    assert out.startswith(f"already paired with the TV at {TV}") and setup.NOT_AN_AGREEMENT not in out
    assert counts["prompts"] == 1


def test_tv_pair_that_the_tv_does_not_accept_exits_1(monkeypatch, tmp_path, capsys):
    tv, counts = counting_lgtv(accept=False)
    fake_lgtv(monkeypatch, tv)
    monkeypatch.setattr(os, "geteuid", lambda: 0)
    keys = tmp_path / "lgtv-keys.sqlite"
    assert cli.main(["--conf", conf(tmp_path), "tv", "pair", "--key-file", str(keys)]) == 1
    assert "did not answer over its LAN API (RuntimeError)" in capsys.readouterr().err
    assert calls(counts) == (1, 1, 1, 1) and not lgwebos.has_key(str(keys), TV)


def test_tv_pair_refuses_without_a_reader_without_root_and_before_the_install(monkeypatch, tmp_path, capsys):
    tv, counts = counting_lgtv()
    fake_lgtv(monkeypatch, tv)
    keys = tmp_path / "lgtv-keys.sqlite"
    monkeypatch.setattr(os, "geteuid", lambda: 0)
    samsung = ["--conf", conf(tmp_path, "samsung-tizen"), "tv", "pair", "--key-file", str(keys)]
    assert cli.main(samsung) == 4
    assert "no LAN-API reader for profile samsung-tizen" in capsys.readouterr().out
    early = ["--conf", conf(tmp_path), "tv", "pair", "--key-file", str(tmp_path / "none" / "k.sqlite")]
    assert cli.main(early) == 1 and "does not exist; run the installer first" in capsys.readouterr().err
    monkeypatch.setattr(os, "geteuid", lambda: 1000)
    assert cli.main(["--conf", conf(tmp_path), "tv", "pair", "--key-file", str(keys)]) == 1
    assert "needs root" in capsys.readouterr().err
    assert calls(counts) == (0, 0, 0, 0) and not keys.exists()


def test_only_setup_and_tv_pair_pair():
    """`register=True` is the one registering path and `pair()` alone takes it; `pair()` is called by
    setup and `tvgw tv pair` only, and every other reader of the TV calls `read()`."""
    package = ROOT / "src" / "tvgw"
    src = (package / "lgwebos.py").read_text(encoding="utf-8")
    assert src.count("register=True") == 1 and "_reading(ip, key_file, timeout, register=True)" in src
    callers = sorted(
        p.name for p in package.rglob("*.py") if "lgwebos.pair(" in p.read_text(encoding="utf-8")
    )
    assert callers == ["cli.py", "setup.py"]
