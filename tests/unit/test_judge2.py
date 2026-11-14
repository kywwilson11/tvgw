"""(ledger) Judge v2 in shadow and the placebo calibration (design decision 48), on synthetic stores."""

import json
import os
import re

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
    # the shipped judge, on the same store, no longer reverts either: since decision 41 an
    # hour counts against a rule only with demand, and an input hour has none
    for h in range(18, 25):
        assert autoblock.judge(synth.conn, lg, RULE, day3(h) + 60) is None


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


def test_placebo_trials_on_hdmi_evenings_revert_nothing_under_any_arm(history, lg):
    """(fin-release) Arm A is the shipped judge as it runs: an hour on an input has no demand and
    counts for nothing, so the HDMI hour that used to be its false revert is none now."""
    r = judge2.calibrate(history.conn, lg, days=4, now=H0 + 8 * DAY, by_class=True)
    assert (r["trials"], r["trial_days"]) == (4 * 24 - 23, 3)  # 3 local days: 1 November had 25 hours
    a, b, c = (r["arms"][x] for x in "ABC")
    assert a["alpha"] == 0 and a["revert_hour_no_demand"] == 0 and a["blind_pass"] == 0
    assert b["alpha"] == 0 and c["alpha"] == 0 and c["suspended"] == 0
    assert a["power"] > 0 and c["power"] > 0  # a real 70% collapse is still caught
    assert r["hour_classes"]["no_demand"] == 4 and r["hour_classes"]["clean"] == 16
    assert len(r["hours"]) == 4 * 24 and r["reverting_hour_classes"]["A"] == {}
    d = r["arms"]["D"]  # judge v2 with the shadow's end-time bytes
    assert d["alpha"] == 0 and d["suspended"] == 0 and d["power"] > 0
    assert judge2.summary_lines(r)[-2] == (
        "bytes: A end-time; B end-time; C prorated; D end-time (the shadow judge counts end-time bytes:"
        " D is the judge it records)"
    )


def test_arm_c_counts_prorated_bytes_and_arm_d_the_shadows_end_time_bytes():
    """A trial whose flows all end on time but whose prorated bytes are low: C reverts, D does not."""
    import types

    h = judge2.BASELINE
    hours = range(0, h + judge2.CEILING, HOUR)
    clf = types.SimpleNamespace(
        bytes_end={x: 100.0 for x in hours},
        bytes_pro={x: (100.0 if x < h else 10.0) for x in hours},
    )
    cls = {x: ("clean", []) for x in hours}
    end = h + 3 * DAY
    c = judge2._run_arm("C", h, clf, cls, {}, 6, 1.0, end)
    d = judge2._run_arm("D", h, clf, cls, {}, 6, 1.0, end)
    assert (c.verdict, c.stage) == ("reverted", "hourly")
    assert (d.verdict, d.stage) == ("passed", "final")


def placebo(store, lg, h, end):
    """Arm A's and arm B's outcomes for a placebo trial starting at hour `h`, from the store."""
    from tvgw import ledger

    clf = ledger.Classifier(store.conn, lg, h - judge2.BASELINE, end)
    hs = range(h - judge2.BASELINE, end, HOUR)
    cls = {x: clf.classify(x) for x in hs}
    active = {x: float(sum(1 for r in clf.readings.get(x, []) if r[1] in judge2.SHIPPED_ON)) for x in hs}
    return (
        judge2._run_arm("A", h, clf, cls, active, 6, 1.0, end),
        judge2._run_arm("B", h, clf, cls, active, 6, 1.0, end),
    )


def shipped(store, lg, h, end):
    """`autoblock.judge` run every hour on a rule added at `h`, with the hourly check's NODATA
    extension, mapped to arm A's words: the verdict, and the hour a low run ended in."""
    row = {"rule": "||p.example^", "name": "p.example", "added_t": h, "trial_until": h + autoblock.TRIAL}
    now = h + HOUR + 60
    while now < end + 60:
        got = autoblock.judge(store.conn, lg, row, now)
        if got is not None and got[0] == autoblock.NODATA:
            row["trial_until"] = autoblock.extended_until(row)
        elif got is not None:
            kind = "nodata" if got[0] == autoblock.UNTESTED else got[0]
            return kind, (int(now // HOUR) - 1) * HOUR
        now += HOUR
    return "nodata", None


@pytest.mark.parametrize(
    ("low", "a_verdict", "b_verdict"),
    [
        ((), "passed", "passed"),  # a steady evening
        ((19,), "passed", "reverted"),  # one low hour with demand: the single-hour rule's false revert
        ((19, 20), "reverted", "reverted"),  # two running: the shipped judge reverts too
        ((19, 21), "passed", "reverted"),  # two, not running
    ],
)
def test_arm_a_is_the_shipped_judge_hour_for_hour(tmp_path, lg, low, a_verdict, b_verdict):
    """(fin-release) Placebo data: four evenings of streaming, then the trial's evening with the low
    hours given (demand, 1 MB instead of 40). Arm A gives the verdict `autoblock.judge` gives when it
    runs every hour on the same store, at the same hour; arm B keeps the single-hour rule."""
    x = Synth(str(tmp_path / "p.db"))
    for d in range(5):
        for hh in EVENING:
            x.stream(H0 + d * DAY + hh * HOUR, mbytes=1.0 if d == 4 and hh in low else 40.0)
    h, end = H0 + 4 * DAY, H0 + 6 * DAY
    a, b = placebo(x, lg, h, end)
    verdict, hour = shipped(x, lg, h, end)
    assert (a.verdict, b.verdict) == (a_verdict, b_verdict)
    assert a.verdict == verdict
    if a.stage == "hourly":
        assert a.hour == hour == H0 + 4 * DAY + low[-1] * HOUR
    x.close()


def test_arm_a_extends_a_trial_without_demand_and_never_passes_it_blind(tmp_path, lg):
    """(fin-release) A trial whose TV only shows an input: the shipped judge extends it a day at a time
    and leaves it untested at the ceiling, which arm A reports as nodata, not a blind pass."""
    x = Synth(str(tmp_path / "q.db"))
    for d in range(3):
        for hh in EVENING:
            x.stream(H0 + d * DAY + hh * HOUR)
    for d in range(3, 3 + 15):
        x.reading(H0 + d * DAY + 19 * HOUR, "Active", HDMI)
    h, end = H0 + 3 * DAY, H0 + 19 * DAY
    a, b = placebo(x, lg, h, end)
    assert (a.verdict, a.stage) == ("nodata", "final") and b.verdict == "blind_pass"
    assert shipped(x, lg, h, end)[0] == "nodata"
    x.close()


def test_calibrate_report_table_and_arms(history, lg, tmp_path):
    r = judge2.calibrate(history.conn, lg, days=4, arms=("A",), now=H0 + 8 * DAY)
    path = judge2.write_report(r, str(tmp_path / "reports"))
    assert path.endswith(os.path.join("calibrate", "2026-11-02.json"))  # 23:00: the clocks went back on 11-01
    with open(path, encoding="utf-8") as fh:
        assert json.load(fh)["arms"].keys() == {"A"}
    lines = judge2.summary_lines(r)
    assert lines[0].startswith("placebo trials: 73 over 4 days; K = 6") and lines[3].startswith("A ")
    assert lines[-2].startswith("bytes: A end-time (")
    assert judge2.parse_arms("a, c,A") == ("A", "C") and judge2.parse_arms("D") == ("D",)
    with pytest.raises(ValueError):
        judge2.parse_arms("A,E")
    empty = judge2.calibrate(history.conn, lg, days=0, now=H0 + 8 * DAY)
    assert (
        empty["trials"] == 0
        and judge2.summary_lines(empty)[-1] == "(no complete trial window in the store yet)"
    )


def test_every_share_of_the_placebo_table_carries_its_day_block_interval():
    """L2-3: the table printed each share to a tenth of a point from trials that start every hour, so that
    trials a day apart share 23 of their 24 hours, with no interval; and no false revert on 14 days of
    trials read 0.0%, where it bounds the rate only under about 21%."""
    placebo = [H0 + h * HOUR for h in range(14 * 24)]  # a trial every hour of 14 local days
    cls = {h: ("clean", []) for h in placebo}
    reverted = [
        judge2.Outcome("reverted", "hourly", h) if (h - H0) // DAY % 3 == 0 else None for h in placebo
    ]
    out = [o or judge2.Outcome("passed", "final") for o in reverted]  # every third day reverts, all day
    got = judge2._summary(out, out, placebo, cls)
    assert got["alpha"] == round(5 / 14, 4) and got["intervals"]["alpha"] == got["intervals"]["power"]
    lo, hi = got["intervals"]["alpha"]
    assert 0.07 < lo < got["alpha"] < hi < 0.65  # 5 days of 14: wide, as 14 independent days are
    assert got["intervals"]["suspended"] == [0.0, 0.0] and judge2._summary(out, out, placebo, cls) == got
    result = {
        "trials": len(placebo),
        "days": 14,
        "k": 6,
        "breakage": 0.3,
        "hour_classes": {},
        "trial_days": 14,
    }
    blind = {**got, "blind_pass": got["alpha"], "intervals": {**got["intervals"], "blind_pass": [lo, hi]}}
    lines = judge2.summary_lines({**result, "arms": {"C": got, "B": blind}})
    cells = [re.split(r"\s{2,}", line) for line in lines[2:5]]
    assert cells[0][5] == "blind/nodata" and cells[1][:2] == [
        "C",
        f"35.7% ({100 * lo:.0f} to {100 * hi:.0f})",
    ]
    assert cells[1][5] == "0 of 14 days: under 21%" and cells[2][5] == cells[1][1]  # B's are its blind passes
    assert lines[-1].startswith("each share with its 95% interval in points, from 14 days of trials")


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
    assert cli.main(["--conf", str(conf), "autoblock", "calibrate", "--days", "0"]) == 2
    assert cli.main(["--conf", str(conf), "autoblock", "calibrate", "--breakage", "1.5"]) == 2


def test_cli_check_runs_the_shadow_after_the_shipped_judge_has_decided(conf, capsys, monkeypatch, history):
    from tvgw import analyst

    insert_rule(history.conn)
    seen = []
    monkeypatch.setattr(analyst, "check", lambda conn, s, prof, **kw: seen.append(conn.execute("SELECT COUNT(*) FROM judge_shadow").fetchone()[0]) or [])  # fmt: skip
    monkeypatch.setattr("time.time", lambda: ADDED + 5 * HOUR)
    judged = []
    monkeypatch.setattr(autoblock, "judge", lambda *a: judged.append(a) or None)
    assert cli.main(["--conf", str(conf), "autoblock", "check"]) == 0
    assert seen == [0]  # the shipped judge ran first, with no shadow row yet
    row = db.connect(history.path).execute("SELECT k, v1 FROM judge_shadow").fetchone()
    assert row == (4, "watching") and judged == []  # v1 is the check's: autoblock.judge is not asked again
    assert capsys.readouterr().out.index("nothing to decide") >= 0


def test_a_failing_shadow_never_changes_the_checks_result(conf, capsys, monkeypatch, history):
    from tvgw import analyst

    insert_rule(history.conn)
    monkeypatch.setattr(analyst, "check", lambda conn, s, prof, **kw: [{"verdict": "reverted", "rule": "||t.example^", "reason": "must-allow"}])  # fmt: skip
    monkeypatch.setattr(judge2, "shadow", lambda *a, **kw: 1 / 0)
    assert cli.main(["--conf", str(conf), "autoblock", "check"]) == 0
    io = capsys.readouterr()
    assert "reverted ||t.example^ (must-allow)" in io.out
    assert "judge v2 (shadow) failed: ZeroDivisionError" in io.err


def test_the_shadow_pass_stops_at_its_budget_and_says_so(conf, capsys, history, lg):
    from tvgw import config

    insert_rule(history.conn)
    history.conn.execute(
        "INSERT INTO auto_rules(rule, name, added_t, trial_until) VALUES ('||u.example^', 'u.example', ?, ?)",
        (ADDED + 60, ADDED + DAY),
    )
    history.conn.commit()
    ticks = iter(range(0, 1000, 100))  # each rule takes 100 s of the pass's clock
    s = config.load(conf)
    cli._shadow(history.conn, s, lg, now=ADDED + 5 * HOUR, budget=150, clock=lambda: float(next(ticks)))
    assert "judge v2 (shadow) stopped after 150 s with 1 of 2 rule(s) left" in capsys.readouterr().out
    assert history.conn.execute("SELECT COUNT(*) FROM judge_shadow").fetchone()[0] == 1


def test_shadow_after_the_check_does_not_ask_the_shipped_judge(synth, lg, monkeypatch):
    insert_rule(synth.conn)
    monkeypatch.setattr(autoblock, "judge", lambda *a: 1 / 0)
    out = judge2.shadow(synth.conn, lg, now=ADDED + 5 * HOUR, after_check=True)
    assert [r["v1"] for r in out] == ["watching"]
    clock = iter([0.0, 0.0, 999.0])
    assert judge2.shadow(synth.conn, lg, now=ADDED + 6 * HOUR, after_check=True, budget=10, clock=lambda: next(clock)) != []  # fmt: skip
    late = iter([0.0, 999.0])
    assert judge2.shadow(synth.conn, lg, now=ADDED + 7 * HOUR, after_check=True, budget=10, clock=lambda: next(late)) == []  # fmt: skip


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


def test_arm_a_is_the_shipped_judge_at_the_trials_end(tmp_path, lg):
    """(fin-release) The other path arm A re-implements: no hour low enough to start a run (15 MB an
    hour against 40, above the hourly floor), but the trial's streaming per TV hour under
    STREAMING_COLLAPSE of the days before, so the shipped judge reverts at the trial's end."""
    x = Synth(str(tmp_path / "c.db"))
    for d in range(5):
        for hh in EVENING:
            x.stream(H0 + d * DAY + hh * HOUR, mbytes=15.0 if d == 4 else 40.0)
    h, end = H0 + 4 * DAY, H0 + 6 * DAY
    a, b = placebo(x, lg, h, end)
    assert (a.verdict, a.stage) == ("reverted", "final")
    assert shipped(x, lg, h, end)[0] == a.verdict
    assert (b.verdict, b.stage) == ("reverted", "final")  # B's end-of-trial rule agrees here
    x.close()
