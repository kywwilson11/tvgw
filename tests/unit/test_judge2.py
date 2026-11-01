"""(ledger) Judge v2 in shadow and the placebo calibration (design decision 48), on synthetic stores."""

import json
import os

import pytest
from ledger_store import CDN, H0, HDMI, HOUR, Synth

from tvgw import autoblock, cli, db, judge2

DAY = 86400
ADDED = H0 + 3 * DAY + 3 * HOUR + 50 * 60  # day 3, 03:50: the analyst's hour
EVENING = range(18, 22)
RULE = {"rule": "||t.example^", "name": "t.example", "added_t": ADDED, "trial_until": ADDED + DAY}


@pytest.fixture()
def synth(tmp_path):
    x = Synth(str(tmp_path / "s.db"))
    for d in range(3):  # three evenings of steady streaming before the rule
        for h in EVENING:
            x.stream(H0 + d * DAY + h * HOUR)
    yield x
    x.close()


def day3(h):
    return H0 + 3 * DAY + h * HOUR


def v(synth, lg, now, k=6, row=RULE):
    return judge2.verdict(synth.conn, lg, row, now, k)


def test_inside_the_trial_with_nothing_to_judge_it_watches(synth, lg):
    got = v(synth, lg, ADDED + 5 * HOUR)
    assert (got.verdict, got.clean_hours, got.final) == ("watching", 0, False)


def test_it_passes_only_on_k_clean_demand_hours(synth, lg):
    for h in range(17, 23):
        synth.stream(day3(h))
    got = v(synth, lg, ADDED + DAY + 60)
    assert got.verdict == "passed" and got.final and got.clean_hours == 6
    assert got.reason.startswith("streaming per clean TV hour at 100% of the clean hours before")


def test_too_few_clean_hours_extends_and_the_ceiling_keeps_it_on_probation(synth, lg):
    for h in EVENING[:3]:
        synth.stream(day3(h))
    got = v(synth, lg, ADDED + DAY + 60)
    assert (got.verdict, got.reason, got.final) == ("nodata", "extend: 3 of 6 clean TV hours", False)
    late = v(synth, lg, ADDED + judge2.CEILING + 60)
    assert late.verdict == "nodata" and late.final and late.reason.startswith("ceiling reached with 3 of 6")


def test_two_low_clean_hours_revert_and_one_does_not(synth, lg):
    synth.stream(day3(18), mbytes=1.0)  # low, with demand: the app is up and the CDN is asked
    synth.stream(day3(19))
    synth.stream(day3(20), mbytes=1.0)
    assert v(synth, lg, day3(21) + 60).verdict == "watching"
    synth.stream(day3(21), mbytes=1.0)
    got = v(synth, lg, day3(22) + 60)
    assert got.verdict == "reverted" and got.final
    assert got.reason == "streaming fell to 2% of the clean hours before in 2 clean TV hours from 10-29 20:00"


def test_a_low_run_in_a_confounded_hour_suspends_instead(synth, lg):
    synth.stream(day3(18), mbytes=1.0)
    synth.stream(day3(19), mbytes=1.0)
    synth.change(day3(19) + 600, "pia_down", "Reconnecting", t_end=day3(19) + 1800, t_precision=600)
    got = v(synth, lg, day3(20) + 60)
    assert got.verdict == "suspended" and got.final
    assert "confounded (PIA not connected)" in got.reason and "to be tried again" in got.reason


def test_hours_on_an_input_are_nodata_not_a_collapse(synth, lg):
    for h in range(17, 24):
        synth.reading(day3(h), "Active", HDMI)
    got = v(synth, lg, ADDED + DAY + 60)
    assert got.verdict == "nodata" and got.demand_hours == 0
    # the shipped judge, on the same store, reverts on the first such hour
    shipped = autoblock.judge(synth.conn, lg, RULE, day3(18) + 60)
    assert shipped and shipped[0] == "reverted"


def test_hard_red_lines_revert_in_any_hour(synth, lg):
    synth.conn.execute(
        "INSERT INTO dns(t, qname, qtype, blocked) VALUES (?, 'us.lgtvsdp.com', 'A', 1)", (ADDED + 60,)
    )
    synth.conn.commit()
    got = v(synth, lg, ADDED + HOUR)
    assert (got.verdict, got.reason) == ("reverted", "a must-allow name was blocked after this rule")


def test_the_blocked_name_asked_for_ten_times_as_often_reverts(synth, lg):
    for d in range(3):
        synth.conn.execute(
            "INSERT INTO dns(t, qname, qtype, blocked) VALUES (?, 't.example', 'A', 0)",
            (H0 + d * DAY + 18 * HOUR + 5,),
        )
    for h in (18, 19):
        synth.stream(day3(h))
        synth.conn.executemany(
            "INSERT INTO dns(t, qname, qtype, blocked) VALUES (?, 't.example', 'A', 1)",
            [(day3(h) + i * 60,) for i in range(40)],
        )
    synth.conn.commit()
    got = v(synth, lg, day3(20) + 60)
    assert got.verdict == "reverted" and got.reason.startswith(
        "the blocked name was asked for 40.0 times per TV hour"
    )


def insert_rule(conn, verdict=None, decided=None):
    conn.execute(
        "INSERT OR REPLACE INTO auto_rules(rule, name, added_t, trial_until, verdict, decided_t, reason)"
        " VALUES (?, ?, ?, ?, ?, ?, ?)",
        (RULE["rule"], RULE["name"], ADDED, ADDED + DAY, verdict, decided, "recorded" if verdict else None),
    )
    conn.commit()


def test_shadow_writes_both_verdicts_once_an_hour_and_decides_nothing(synth, lg):
    insert_rule(synth.conn)
    for h in range(17, 23):
        synth.stream(day3(h))
    now = day3(20) + 1500
    first = judge2.shadow(synth.conn, lg, now=now)
    again = judge2.shadow(synth.conn, lg, now=now + 60)
    assert first[0]["v1"] == "watching" and first[0]["v2"] == "watching" and first[0]["hour_class"] == "clean"
    assert again[0]["hour"] == first[0]["hour"] == day3(19)
    assert synth.conn.execute("SELECT COUNT(*) FROM judge_shadow").fetchone()[0] == 1
    judge2.shadow(synth.conn, lg, now=now + HOUR)
    assert synth.conn.execute("SELECT COUNT(*) FROM judge_shadow").fetchone()[0] == 2
    assert autoblock.rows(synth.conn)[0]["verdict"] is None  # nothing was decided


def test_shadow_follows_a_rule_the_shipped_judge_passed_until_v2_is_final(synth, lg):
    insert_rule(synth.conn, "passed", ADDED + DAY)
    now = ADDED + DAY + 3 * HOUR
    out = judge2.shadow(synth.conn, lg, now=now)
    assert [(r["v1"], r["v2"], r["final"]) for r in out] == [("passed", "nodata", 0)]
    for h in range(17, 23):
        synth.stream(H0 + 4 * DAY + h * HOUR)
    out = judge2.shadow(synth.conn, lg, now=H0 + 5 * DAY)
    assert [(r["v2"], r["final"]) for r in out] == [("passed", 1)]
    assert judge2.shadow(synth.conn, lg, now=H0 + 5 * DAY + HOUR) == []


# ---- the calibration ------------------------------------------------------------------------------------
@pytest.fixture()
def history(tmp_path):
    """Eight days: four streaming hours every evening, then an hour on an input with nothing flowing."""
    x = Synth(str(tmp_path / "h.db"))
    for d in range(8):
        for h in EVENING:
            x.stream(H0 + d * DAY + h * HOUR)
        x.reading(H0 + d * DAY + 22 * HOUR, "Active", HDMI)
    yield x
    x.close()


def test_placebo_trials_measure_the_hdmi_hours_the_shipped_judge_reverts_on(history, lg):
    r = judge2.calibrate(history.conn, lg, days=4, now=H0 + 8 * DAY, by_class=True)
    assert r["trials"] == 4 * 24 - 23
    a, b, c = (r["arms"][x] for x in "ABC")
    assert a["alpha"] > 0.5 and a["revert_hour_no_demand"] == a["alpha"]  # every revert is an input hour
    assert b["alpha"] == 0 and c["alpha"] == 0 and c["suspended"] == 0
    assert a["power"] > 0 and c["power"] > 0  # a real 70% collapse is still caught
    assert r["hour_classes"]["no_demand"] == 4 and r["hour_classes"]["clean"] == 16
    assert len(r["hours"]) == 4 * 24 and set(r["reverting_hour_classes"]["A"]) == {"no_demand"}


def test_calibrate_report_table_and_arms(history, lg, tmp_path):
    r = judge2.calibrate(history.conn, lg, days=4, arms=("A",), now=H0 + 8 * DAY)
    path = judge2.write_report(r, str(tmp_path / "reports"))
    assert path.endswith(os.path.join("calibrate", "2026-11-02.json"))  # 23:00: the clocks went back on 11-01
    with open(path, encoding="utf-8") as fh:
        assert json.load(fh)["arms"].keys() == {"A"}
    lines = judge2.summary_lines(r)
    assert lines[0].startswith("placebo trials: 73 over 4 days; K = 6") and lines[3].startswith("A ")
    assert judge2.parse_arms("a, c,A") == ("A", "C")
    with pytest.raises(ValueError):
        judge2.parse_arms("A,D")
    empty = judge2.calibrate(history.conn, lg, days=0, now=H0 + 8 * DAY)
    assert (
        empty["trials"] == 0
        and judge2.summary_lines(empty)[-1] == "(no complete trial window in the store yet)"
    )


# ---- the commands -----------------------------------------------------------------------------------------
@pytest.fixture()
def conf(tmp_path, history):
    path = tmp_path / "tvgw.conf"
    path.write_text(
        f'DB_PATH="{history.path}"\nSTATE_DIR="{tmp_path}"\nREPORTS_DIR="{tmp_path / "reports"}"\n'
        "JUDGE2_CLEAN_HOURS=4\n",
        encoding="utf-8",
    )
    return path


def test_cli_calibrate(conf, capsys, monkeypatch):
    monkeypatch.setattr("time.time", lambda: H0 + 8 * DAY)
    assert cli.main(["--conf", str(conf), "autoblock", "calibrate", "--days", "4", "--arms", "A,C"]) == 0
    out = capsys.readouterr().out
    assert "K = 4 clean hours" in out and "written to" in out and "\nC " in out
    assert cli.main(["--conf", str(conf), "autoblock", "calibrate", "--arms", "Z"]) == 2


def test_cli_check_runs_the_shadow_before_the_shipped_judge(conf, capsys, monkeypatch, history):
    from tvgw import analyst

    insert_rule(history.conn)
    seen = []
    monkeypatch.setattr(analyst, "check", lambda conn, s, prof: seen.append(conn.execute("SELECT COUNT(*) FROM judge_shadow").fetchone()[0]) or [])  # fmt: skip
    monkeypatch.setattr("time.time", lambda: ADDED + 5 * HOUR)
    assert cli.main(["--conf", str(conf), "autoblock", "check"]) == 0
    assert seen == [1]
    k = db.connect(history.path).execute("SELECT k FROM judge_shadow").fetchone()[0]
    assert k == 4


def test_cli_changes_lists_and_notes_a_deploy(conf, capsys, history, tmp_path):
    history.change(H0 + 60, "tv_flap", "eth0", t_precision=600)
    history.conn.commit()
    assert cli.main(["--conf", str(conf), "changes", "2026-10-25"]) == 0
    out = capsys.readouterr().out.splitlines()
    assert out[0].split() == ["time", "until", "source", "kind", "subject", "class", "metric"]
    assert out[1].split()[:6] == ["10-26", "00:01:00", "~10m", "sampler", "tv_flap", "eth0"]
    assert cli.main(["--conf", str(conf), "changes", "--note-deploy", "tvgw 0.1.0"]) == 0
    with open(tmp_path / "changes.spool", encoding="utf-8") as fh:
        assert fh.read().split("\t")[1:3] == ["deploy", "tvgw_0.1.0"]
    assert CDN
