import asyncio
import io
import os
import sqlite3
import stat
import subprocess
import sys

import pytest
from conftest import CAP_MEMORY, ROOT, counting_lgtv, fake_lgtv, write_lgtv_keys

from tvgw import cli, lgkeys, lgwebos
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
    async def stuck(ip, key_file, timeout, r, register=False, manifest=None):
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
        async def create(cls, ip, states, client_key, storage):
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
        async def create(cls, ip, states, client_key, storage):
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


def locked(path, monkeypatch):
    """A key file another process holds locked past SQLite's 5 s wait: the read raises."""
    write_lgtv_keys(path, {TV: "key"})

    def keys(key_file):
        raise sqlite3.OperationalError("database is locked")

    monkeypatch.setattr(lgkeys, "keys", keys)


NO_KEY = {  # key files that hold no key for TV, or none that can be read (a row that is code: test_lgkeys.py)
    "no file": lambda path, monkeypatch: None,
    "another address": lambda path, monkeypatch: write_lgtv_keys(path, {"10.10.10.18": "key"}),
    "an empty key": lambda path, monkeypatch: write_lgtv_keys(path, {TV: ""}),
    "not a database": lambda path, monkeypatch: path.write_text(
        "not the library's database", encoding="utf-8"
    ),
    "a read that fails": locked,
}


@pytest.mark.parametrize("shape", NO_KEY)
def test_no_unattended_reading_asks_the_tv_anything_without_a_key(monkeypatch, tmp_path, capsys, shape):
    """The library registers on every connection, and a registration without a key is the pairing
    prompt on the TV's screen: once an hour, after a pairing the owner declined. Every path that runs
    with nobody at the keyboard reads through `read()`, or through the key reader the live reading
    checks before every attempt: the hourly reading, the canary's sample, the live reading."""
    from tvgw import analyst, autoblock
    from tvgw.config import Settings

    tv, counts = counting_lgtv()
    fake_lgtv(monkeypatch, tv)
    hellos = []
    monkeypatch.setattr(lgwebos, "handshake", lambda *a, **kw: hellos.append(a))
    monkeypatch.setattr(autoblock, "read_tx_bytes", lambda tv_if: 0)
    keys = tmp_path / "lgtv-keys.sqlite"
    NO_KEY[shape](keys, monkeypatch)
    argv = ["--conf", conf(tmp_path), "tvcheck", "--key-file", str(keys)]
    assert cli.main(argv) == 4 and capsys.readouterr().out.startswith("TV not paired:")  # the hourly reading
    assert analyst.live_sample(Settings(tv_ip=TV, state_dir=str(tmp_path))).power == "unknown"
    assert lgwebos._stored_key(str(keys), TV) is None  # the live reading's key: "not paired", no attempt
    assert calls(counts) == (0, 0, 0, 0) and hellos == [] and keys.exists() == (shape != "no file")


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
    assert counts["keys"] == [None, "key-from-the-tv"]  # the pairing had none to hand over; the reading had


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
    assert not keys.exists()  # the TV sent no key, so there was nothing to store and no file is made
    assert lgwebos.read(TV, str(keys)).error == lgwebos.NOT_PAIRED and calls(counts) == (1, 1, 1, 1)


@pytest.mark.parametrize(
    ("content", "paired"),
    [
        (None, False),  # no key file
        ({"10.10.10.17": "key"}, True),
        ({"10.10.10.18": "key"}, False),  # another address
        ({"10.10.10.17": ""}, False),  # an empty key is no key to the TV
        ({"10.10.10.17": None}, False),
        ("not the library's database", False),
    ],
)
def test_has_key_finds_a_key_for_this_tv_alone_and_needs_no_library(monkeypatch, tmp_path, content, paired):
    monkeypatch.setitem(sys.modules, "bscpylgtv", None)  # tvgw reads the key itself (design decision 106)
    keys = tmp_path / "lgtv-keys.sqlite"
    if isinstance(content, dict):
        write_lgtv_keys(keys, content)
    elif content is not None:
        keys.write_text(content, encoding="utf-8")
    assert lgwebos.has_key(str(keys), TV) is paired
    assert keys.exists() == (content is not None)


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
    assert cli.main(samsung) == 4  # (samsung) read without pairing: nothing to pair, and no prompt
    assert (
        "reads this TV (samsung-tizen) without pairing, every hour; nothing to pair"
        in capsys.readouterr().out
    )
    roku = ["--conf", conf(tmp_path, "roku"), "tv", "pair", "--key-file", str(keys)]
    assert cli.main(roku) == 4
    assert "no LAN-API reader for profile roku" in capsys.readouterr().out
    assert calls(counts) == (0, 0, 0, 0)
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
    assert (
        src.count("register=True") == 1
        and "_reading(ip, key_file, timeout, register=True, manifest=kind)" in src
    )
    callers = sorted(
        p.name for p in package.rglob("*.py") if "lgwebos.pair(" in p.read_text(encoding="utf-8")
    )
    assert callers == ["cli.py", "setup.py"]


# ---- (decision 106) the reading's own bounds -------------------------------------------------------------


@pytest.mark.parametrize("fault", [asyncio.CancelledError, MemoryError])
def test_a_reading_cut_off_by_the_library_or_the_memory_cap_is_unreachable_and_tvcheck_returns(
    monkeypatch, tmp_path, capsys, fault
):
    """A TV's 256 MiB reply took the reading to 820 MiB, and the library's cancelled waits let a
    CancelledError out of read(): `tvgw tvcheck` ended in a traceback. Under the cap on the address
    space, which tvcheck sets before it reads, such a reply is a MemoryError. Either way the TV was not
    read: what was read is kept, the reading is unreachable, and the command returns its exit code."""
    order = []

    async def cut_off(ip, key_file, timeout, r, register=False, manifest=None):
        order.append("read")
        r.reachable, r.values["option.livePlus"] = True, "off"
        raise fault()

    monkeypatch.setattr(lgwebos, "_read", cut_off)
    r = lgwebos.read(TV, str(tmp_path / "lgtv-keys.sqlite"))
    assert (r.reachable, r.error, r.values) == (False, fault.__name__, {"option.livePlus": "off"})
    monkeypatch.setattr(lgwebos, "cap_memory", lambda: order.append("cap"))
    assert cli.main(["--conf", conf(tmp_path), "tvcheck"]) == 1 and order == ["read", "cap", "read"]
    assert capsys.readouterr().out.startswith(f"TV unreachable ({fault.__name__})")


def test_a_tv_that_asks_for_a_pin_gets_no_answer_from_the_terminal(monkeypatch, tmp_path):
    """The library calls input() for a PIN inside the event loop: at a terminal `sudo tvgw tvcheck`
    waited past every timeout for someone to press Enter, and what was typed went to the TV."""

    class PinTv:
        @classmethod
        async def create(cls, ip, states, client_key, storage):
            return cls()

        async def connect(self):
            self.pin = input("Enter PIN: ")  # the library, when the TV answers the registration with PIN

        async def disconnect(self):
            pass

    typed = io.StringIO("1234\n")
    monkeypatch.setattr(sys, "stdin", typed)
    keys = tmp_path / "lgtv-keys.sqlite"
    fake_lgtv(monkeypatch, PinTv, {TV: "key"}, keys)
    r = lgwebos.read(TV, str(keys), timeout=0.5)
    assert (r.reachable, r.error) == (False, "EOFError") and typed.tell() == 0 and sys.stdin is typed


TV_WORDS = "refused\x1b[2J\nWARNING: all clear"  # a library error that carries what the TV sent


def test_an_error_in_the_tvs_words_prints_as_one_clean_line(monkeypatch, tmp_path, capsys):
    """The library's error text was stored and printed as it was: an escape sequence reached the
    terminal, and a newline made a line of its own in tvcheck.txt, which the hourly script reads for
    WARNING lines."""

    class Tv:
        @classmethod
        async def create(cls, ip, states, client_key, storage):
            return cls()

        async def connect(self):
            pass

        async def answer(self, *args):  # Live Plus is off; every other call fails in the TV's words
            if args == ("option", ["livePlus"]):
                return {"settings": {"livePlus": "off"}}
            raise RuntimeError(TV_WORDS)

        get_system_settings = request = get_software_info = answer

        async def disconnect(self):
            pass

    keys = tmp_path / "lgtv-keys.sqlite"
    fake_lgtv(monkeypatch, Tv, {TV: "key"}, keys)
    assert cli.main(["--conf", conf(tmp_path), "tvcheck", "--key-file", str(keys)]) == 0
    out = capsys.readouterr().out
    for key in ("option.zipcode", "network.paths", "info", "eula.status", "agreement.status"):
        assert f"{key} = ERR RuntimeError refused [2J WARNING: all clear\n" in out
    assert not any(line.startswith("WARNING") for line in out.splitlines())
    # and whatever a reading says is printed as one line of printable text
    monkeypatch.setattr(lgwebos, "read", lambda ip, key_file: TvReading(True, {"model": "a\x1b[2J\nb"}))
    assert cli.main(["--conf", conf(tmp_path), "tvcheck"]) == 0
    assert capsys.readouterr().out == "model = a\\x1b[2J\\x0ab\n"


class Limits:
    """The resource module's address-space limit, as Linux reports it (RLIM_INFINITY is -1 there)."""

    RLIMIT_AS, RLIM_INFINITY = 9, -1

    def __init__(self, soft, hard, refuses=None):
        self.now, self.refuses = (soft, hard), refuses

    def getrlimit(self, which):
        assert which == self.RLIMIT_AS
        return self.now

    def setrlimit(self, which, limits):
        assert which == self.RLIMIT_AS
        if self.refuses:
            raise self.refuses("current limit exceeds maximum limit")
        self.now = limits


GIB, INF = 1 << 30, Limits.RLIM_INFINITY


@pytest.mark.parametrize(
    ("soft", "hard", "refuses", "capped", "after"),
    [
        (INF, INF, None, True, (GIB, INF)),  # the gateway's default: no limit, so the reading sets its own
        (INF, GIB // 2, None, True, (GIB // 2, GIB // 2)),  # never above the hard limit
        (GIB // 4, INF, None, True, (GIB // 4, INF)),  # a lower limit already set is kept
        (INF, INF, ValueError, False, (INF, INF)),  # macOS refuses RLIMIT_AS
        (INF, INF, OSError, False, (INF, INF)),
    ],
)
def test_a_reading_caps_its_address_space_at_1_gib_and_never_raises_a_lower_limit(
    monkeypatch, soft, hard, refuses, capped, after
):
    limits = Limits(soft, hard, refuses)
    monkeypatch.setattr(lgwebos, "resource", limits)
    assert CAP_MEMORY() is capped and limits.now == after and lgwebos.READ_AS_LIMIT == GIB


CAPPED_TVCHECK = """
import resource, sys, types
from tvgw import cli, lgwebos


class Tv:  # the library: a TV that answers, or one whose reply it holds without end
    @classmethod
    async def create(cls, ip, states, client_key, storage, manifest_file_path=None):
        return cls()

    async def connect(self):
        held = [bytes(64 << 20) for _ in range(64 if sys.argv[3] == "runaway" else 0)]

    async def get_system_settings(self, cat, keys):
        return {"settings": {keys[0]: "off"}}

    async def disconnect(self):
        pass


async def handshake(ip, key, manifest, timeout=5.0):
    return lgwebos.Handshake(release="5.6.2", registered=True)


sys.modules["bscpylgtv"] = types.SimpleNamespace(WebOsClient=Tv)
sys.modules["bscpylgtv.manifest"] = types.SimpleNamespace(MANIFEST={})
lgwebos.handshake = handshake
rc = cli.main(["--conf", sys.argv[1], "tvcheck", "--key-file", sys.argv[2]])
peak = next(line.split()[1] for line in open("/proc/self/status") if line.startswith("VmPeak:"))
print(f"rc={rc} cap={resource.getrlimit(resource.RLIMIT_AS)[0]} VmPeak={peak} kB")
"""


@pytest.mark.skipif(sys.platform != "linux", reason="Linux enforces RLIMIT_AS; macOS refuses to set it")
@pytest.mark.parametrize(
    ("tv", "rc", "first"),
    [("benign", 0, "option.livePlus = off"), ("runaway", 1, "TV unreachable (MemoryError)")],
)
def test_on_linux_tvcheck_reads_under_its_cap_and_a_reply_held_without_end_ends_inside_it(
    tmp_path, tv, rc, first
):
    """The cap is real only where the kernel enforces it. With a stand-in for the library (CI does not
    install it) and for the handshake, a benign reading runs whole under 1 GiB, and a reply the library
    would hold without end (4 GiB here) ends the reading inside the cap, as unreachable, and the command
    returns: the hourly run goes on to the ingest."""
    keys = tmp_path / "lgtv-keys.sqlite"
    write_lgtv_keys(keys, {TV: "key"})
    env = {**os.environ, "PYTHONPATH": str(ROOT / "src")}
    p = subprocess.run(
        [sys.executable, "-c", CAPPED_TVCHECK, conf(tmp_path), str(keys), tv],
        capture_output=True,
        text=True,
        env=env,
        timeout=120,
        check=False,
    )
    lines = p.stdout.splitlines()
    assert p.returncode == 0 and lines[0].startswith(first), p.stderr[-2000:]
    assert lines[-1].startswith(f"rc={rc} cap={lgwebos.READ_AS_LIMIT} VmPeak="), lines[-1]
