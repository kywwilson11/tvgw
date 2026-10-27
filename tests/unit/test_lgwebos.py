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
    async def stuck(ip, key_file, timeout):
        await asyncio.sleep(60)

    monkeypatch.setattr(lgwebos, "_read", stuck)
    r = lgwebos.read("10.10.10.17", "/nonexistent", timeout=0.01)
    assert r.reachable is False and r.error == "TimeoutError" and r.exit_code() == 1
