"""(depth) The on-screen record in the store and the brief: `tvgw tv confirm` appends the owner's answer,
the hourly ingest loads it into `tvsettings` as `onscreen.<setting>`, and the brief says "Not checked: the
TV's Wi-Fi" while no reading reports the TV's network paths and the owner's latest word is not a current
yes (design decision 57). `tvgw forget` keeps the answers, file and rows, as the TV's settings history."""

import os

import pytest
from conftest import NOW

from tvgw import cli, db, forget, ingest, onscreen, queries
from tvgw.config import Settings

DAY = 86400


@pytest.fixture()
def s(tmp_path):
    return Settings(state_dir=str(tmp_path), db_path=str(tmp_path / "tvgw.db"))


def write_log(s, *lines):
    path = onscreen.log_path(s.state_dir)
    with open(path, "a", encoding="utf-8") as fh:
        fh.write("".join(f"{line}\n" for line in lines))
    return path


def rows(conn, prefix="onscreen."):
    return conn.execute(
        "SELECT t, key, value FROM tvsettings WHERE key LIKE ? ORDER BY t, key", (prefix + "%",)
    ).fetchall()


def test_ingest_loads_every_answer_once_with_its_prefix(s):
    conn = db.connect(s.db_path)
    write_log(
        s,
        f"{onscreen.stamp(NOW - 2 * DAY)}\tonscreen.wifi-forgotten\tunknown",
        f"{onscreen.stamp(NOW - DAY)}\tonscreen.voice\toff",
        "cut sh",  # a line a full disk cut short: skipped and counted
        f"{onscreen.stamp(NOW - 3600)}\tonscreen.wifi-forgotten\tyes",
    )
    warnings = []
    assert ingest.ingest_onscreen(conn, s, warnings.append) == 3
    conn.commit()
    assert rows(conn) == [
        (NOW - 2 * DAY, "onscreen.wifi-forgotten", "unknown"),
        (NOW - DAY, "onscreen.voice", "off"),
        (NOW - 3600, "onscreen.wifi-forgotten", "yes"),
    ]
    assert warnings == ["onscreen: 1 line(s) that are not an answer skipped"]
    assert ingest.ingest_onscreen(conn, s, warnings.append) == 0  # tailed: nothing read twice
    # the same answer again, later (after a software download) is stored too: it is what makes it current
    write_log(s, f"{onscreen.stamp(NOW - 60)}\tonscreen.wifi-forgotten\tyes")
    assert ingest.ingest_onscreen(conn, s, warnings.append) == 1
    assert rows(conn)[-1] == (NOW - 60, "onscreen.wifi-forgotten", "yes")


def test_a_gateway_with_no_answers_ingests_without_a_warning(s, monkeypatch, lg):
    monkeypatch.setattr(ingest, "ingest_flows", lambda *a, **k: 0)
    stats = ingest.run(s, lg)
    assert not any(w.startswith("onscreen") for w in stats.warnings)
    write_log(s, f"{onscreen.stamp(NOW - 60)}\tonscreen.mic-switch\toff")
    ingest.run(s, lg)
    conn = db.connect(s.db_path, readonly=True)
    assert rows(conn) == [(NOW - 60, "onscreen.mic-switch", "off")]


def not_checked(conn, until=NOW):
    return queries.not_checked(conn, until, queries.tv_paths(conn, until))


def setting(conn, t, key, value):
    conn.execute("INSERT INTO tvsettings(t,key,value) VALUES (?,?,?)", (t, key, value))
    conn.commit()


def test_the_wifi_line_shows_until_a_current_yes(s):
    conn = db.connect(s.db_path)
    want = [
        "the TV's Wi-Fi. When you have switched it off on the TV, run: sudo tvgw tv confirm wifi-forgotten yes"
    ]
    assert not_checked(conn) == want  # no reading, no answer
    setting(conn, NOW - 3 * DAY, "onscreen.wifi-forgotten", "unknown")
    assert not_checked(conn) == want  # "I can't find it" is an answer, not a yes
    setting(conn, NOW - 2 * DAY, "onscreen.wifi-forgotten", "yes")
    assert not_checked(conn) == []
    assert not_checked(conn, until=NOW - 2.5 * DAY) == want  # a brief for a day before the yes still asks
    setting(conn, NOW - DAY, "onscreen.wifi-forgotten", "no")
    assert not_checked(conn) == want


def test_a_yes_from_before_the_tvs_software_changed_is_asked_again(s):
    conn = db.connect(s.db_path)
    setting(conn, NOW - 10 * DAY, "firmware", "04.40.00")
    setting(conn, NOW - 5 * DAY, "onscreen.wifi-forgotten", "yes")
    setting(conn, NOW - 2 * DAY, "firmware", "04.64.00")
    (line,) = not_checked(conn)
    assert line.startswith("the TV's Wi-Fi. You confirmed it off on ")
    assert "before the TV's software changed on " in line
    assert line.endswith("check it again on the TV, then run: sudo tvgw tv confirm wifi-forgotten yes")
    setting(conn, NOW - DAY, "onscreen.wifi-forgotten", "yes")  # asked again and answered
    assert not_checked(conn) == []


def test_a_tv_that_reports_its_paths_needs_no_answer(s):
    """The reference: the LG CX's hourly reading reports its Wi-Fi, so its brief has no such line."""
    conn = db.connect(s.db_path)
    setting(conn, NOW - 3600, "network.wifi.state", "disconnected")
    assert not_checked(conn) == []


def test_the_brief_prints_the_line_after_its_red_lines(s, lg):
    import io

    conn = db.connect(s.db_path)
    o = queries.brief(conn, "2026-10-25", lg, now=NOW)
    assert o["not_checked"] == [
        "the TV's Wi-Fi. When you have switched it off on the TV, run: sudo tvgw tv confirm wifi-forgotten yes"
    ]
    out = io.StringIO()
    cli.render_brief(o, out)
    text = out.getvalue().splitlines()
    assert (
        "Not checked: the TV's Wi-Fi. When you have switched it off on the TV, run: sudo tvgw tv confirm wifi-forgotten yes"
        in text
    )


def test_tv_confirm_appends_the_answer_and_refuses_one_of_the_wrong_kind(s, tmp_path, capsys):
    conf = tmp_path / "tvgw.conf"
    conf.write_text(f"STATE_DIR={s.state_dir}\nDB_PATH={s.db_path}\n")
    assert cli.main(["--conf", str(conf), "tv", "confirm", "wifi-forgotten", "yes"]) == 0
    out = capsys.readouterr().out
    assert out.startswith("recorded onscreen.wifi-forgotten yes at ") and out.rstrip().endswith(
        "next hourly ingest"
    )
    assert [(c.setting, c.value) for c in onscreen.latest(onscreen.log_path(s.state_dir)).values()] == [
        ("wifi-forgotten", "yes")
    ]
    assert cli.main(["--conf", str(conf), "tv", "confirm", "wifi-forgotten", "off"]) == 2
    assert "wifi-forgotten takes yes, no, unknown, not 'off'" in capsys.readouterr().err
    with pytest.raises(SystemExit):
        cli.main(["--conf", str(conf), "tv", "confirm", "zipcode", "yes"])  # not a setting it records
    assert oct(os.stat(onscreen.log_path(s.state_dir)).st_mode & 0o777) == "0o640"


def test_forget_keeps_the_answers_in_the_store_and_the_file(s):
    """The on-screen answers are the TV's settings history, not viewing: forget keeps both, and lists the
    file as kept."""
    conn = db.connect(s.db_path)
    setting(conn, NOW - DAY, "onscreen.wifi-forgotten", "yes")
    conn.close()
    log = write_log(s, f"{onscreen.stamp(NOW - DAY)}\tonscreen.wifi-forgotten\tyes")
    out = forget.run(
        s,
        live=lambda d: set(),
        backup=lambda db_path, backup_dir: os.makedirs(backup_dir, exist_ok=True),
        lock=False,
        now=lambda: NOW,
    )
    assert any(step.action == "keep" and step.what.endswith("onscreen.log") for step in out.steps)
    assert os.path.exists(log)
    conn = db.connect(s.db_path, readonly=True)
    assert rows(conn) == [(NOW - DAY, "onscreen.wifi-forgotten", "yes")]
