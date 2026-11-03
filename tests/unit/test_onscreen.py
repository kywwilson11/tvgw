"""(plain) The on-screen record: the owner's dated answers about TV settings the TV does not report."""

import os
import stat
import time

import pytest
from conftest import NOW

from tvgw import config, forget, onscreen
from tvgw.onscreen import Confirmation

# conftest pins the zone to America/Chicago and time.time() to NOW, 2026-10-26 10:00 CDT
STAMP = "2026-10-26T10:00:00-05:00"


def test_an_answer_is_one_line_read_back_as_given(tmp_path):
    log = str(tmp_path / "onscreen.log")
    c = onscreen.record("wifi-forgotten", "yes", log)
    assert c == Confirmation("wifi-forgotten", "yes", NOW) and c.key == "onscreen.wifi-forgotten"
    assert (tmp_path / "onscreen.log").read_text(
        encoding="utf-8"
    ) == f"{STAMP}\tonscreen.wifi-forgotten\tyes\n"
    assert stat.S_IMODE(os.stat(log).st_mode) == onscreen.MODE == 0o640
    assert onscreen.latest(log) == {"wifi-forgotten": c}


def test_the_newest_answer_for_each_setting_wins_in_the_order_given(tmp_path, monkeypatch):
    log = str(tmp_path / "onscreen.log")
    onscreen.record("wifi-forgotten", "unknown", log)  # setup's "I can't find it"
    onscreen.record("viewing-info", "off", log)
    monkeypatch.setattr(time, "time", lambda: NOW - 7200)  # the clock was set back before the next answer
    onscreen.record("wifi-forgotten", "yes", log)
    got = onscreen.latest(log)
    assert got == {
        "wifi-forgotten": Confirmation("wifi-forgotten", "yes", NOW - 7200),
        "viewing-info": Confirmation("viewing-info", "off", NOW),
    }
    assert len((tmp_path / "onscreen.log").read_text(encoding="utf-8").splitlines()) == 3  # appended


@pytest.mark.parametrize(
    "setting, value, says",
    [
        ("wifi", "off", "unknown on-screen setting 'wifi'"),
        ("wifi-forgotten", "off", "wifi-forgotten takes yes, no, unknown, not 'off'"),
        ("viewing-info", "yes", "viewing-info takes on, off, unknown, not 'yes'"),
        ("voice", "On", "voice takes on, off, unknown, not 'On'"),
        ("mic-switch", "off\tonscreen.voice\ton", "mic-switch takes"),
    ],
)
def test_a_setting_or_an_answer_it_does_not_take_is_refused_and_nothing_is_written(
    tmp_path, setting, value, says
):
    log = tmp_path / "onscreen.log"
    with pytest.raises(ValueError, match=says):
        onscreen.record(setting, value, str(log))
    assert not log.exists()


def test_every_setting_takes_unknown_so_nobody_has_to_answer_falsely():
    assert set(onscreen.SETTINGS) == {"viewing-info", "interest-ads", "voice", "mic-switch", "wifi-forgotten"}
    assert all("unknown" in values for values in onscreen.SETTINGS.values())
    assert {v for values in onscreen.SETTINGS.values() for v in values} == {
        "on",
        "off",
        "yes",
        "no",
        "unknown",
    }


def test_a_wider_mode_is_set_back_and_a_link_in_its_place_is_refused(tmp_path):
    log = tmp_path / "onscreen.log"
    log.write_text("", encoding="utf-8")
    log.chmod(0o644)
    onscreen.record("voice", "off", str(log))
    assert stat.S_IMODE(log.stat().st_mode) == 0o640
    target = tmp_path / "elsewhere"
    target.write_text("", encoding="utf-8")
    link = tmp_path / "linked.log"
    link.symlink_to(target)
    with pytest.raises(OSError):
        onscreen.record("voice", "off", str(link))
    assert target.read_text(encoding="utf-8") == ""


def test_no_file_is_no_answer_and_a_bad_line_hides_no_other(tmp_path):
    log = tmp_path / "onscreen.log"
    assert onscreen.latest(str(log)) == {}
    good = f"{STAMP}\tonscreen.interest-ads\toff"
    log.write_text(
        "\n".join(
            [
                good,
                "2026-10-26T10:00:00\tonscreen.voice\toff",  # no offset: which 10:00?
                "yesterday\tonscreen.voice\toff",
                f"{STAMP}\tonscreen.voice\tyes",  # an answer voice does not take
                f"{STAMP}\tonscreen.bluetooth\toff",  # a setting this version does not know
                f"{STAMP}\tvoice\toff",  # not an onscreen key
                f"{STAMP}\tonscreen.voice\toff\textra",
                f"{STAMP}\tonscreen.vo",  # cut short by a full disk
            ]
        )
        + "\n",
        encoding="utf-8",
    )
    assert onscreen.latest(str(log)) == {"interest-ads": Confirmation("interest-ads", "off", NOW)}
    assert onscreen.parse(good + "\n") == Confirmation("interest-ads", "off", NOW)


def test_an_answer_after_a_line_cut_short_starts_a_line_of_its_own(tmp_path):
    """A write a full disk or a power cut left without its newline would swallow the next answer if that
    were appended straight after it: record() ends the broken line first, so only that line is lost."""
    log = tmp_path / "onscreen.log"
    log.write_text(f"{STAMP}\tonscreen.voice\toff\n{STAMP}\tonscreen.vo", encoding="utf-8")
    c = onscreen.record("wifi-forgotten", "yes", str(log))
    assert log.read_text(encoding="utf-8").splitlines() == [
        f"{STAMP}\tonscreen.voice\toff",
        f"{STAMP}\tonscreen.vo",
        f"{STAMP}\tonscreen.wifi-forgotten\tyes",
    ]
    assert onscreen.latest(str(log)) == {"voice": Confirmation("voice", "off", NOW), "wifi-forgotten": c}
    onscreen.record("voice", "on", str(log))  # after a whole last line, no blank line
    assert log.read_text(encoding="utf-8").endswith(f"\tyes\n{STAMP}\tonscreen.voice\ton\n")


def test_the_time_is_exact_through_the_hour_that_happens_twice(tmp_path, monkeypatch):
    """2026-11-01 01:30 happens twice in America/Chicago; the offset says which, so the epoch comes back."""
    log = str(tmp_path / "onscreen.log")
    first, second = 1793514600.0, 1793518200.0  # 01:30 CDT, then 01:30 CST an hour later
    for t in (first, second):
        monkeypatch.setattr(time, "time", lambda t=t: t)
        onscreen.record("mic-switch", "off", log)
    lines = (tmp_path / "onscreen.log").read_text(encoding="utf-8").splitlines()
    assert [ln.split("\t")[0] for ln in lines] == ["2026-11-01T01:30:00-05:00", "2026-11-01T01:30:00-06:00"]
    assert [onscreen.parse(ln).t for ln in lines] == [first, second]


def test_the_log_lives_in_the_state_directory_and_forget_keeps_it():
    assert onscreen.LOG == onscreen.log_path(config.Settings().state_dir) == "/var/lib/tvgw/onscreen.log"
    assert onscreen.log_path("/srv/tvgw-state") == "/srv/tvgw-state/onscreen.log"
    assert forget.classify("onscreen.log", forget.STATE_ENTRIES)[0] == forget.KEEP
