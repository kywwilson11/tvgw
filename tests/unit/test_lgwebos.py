from tvgw.lgwebos import TvReading, parse_history_line


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


def test_history_line():
    assert parse_history_line("2026-10-26 09:19 Active youtube.leanback.v4") == (
        "2026-10-26 09:19",
        "Active",
        "youtube.leanback.v4",
    )
    assert parse_history_line("2026-10-26 08:20 unreachable") == ("2026-10-26 08:20", "unreachable", None)
    assert parse_history_line("broken") is None
