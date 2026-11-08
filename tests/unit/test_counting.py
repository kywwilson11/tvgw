"""(counting) What is counting (design decision 72): each count-only mechanism's run, kept by `tvgw verify
--record` and backfilled from its own record; the judging of two weeks; the brief's Counting section and the
plain brief's line; and the file `tvgw status` reads."""

import io
import json

import pytest

from tvgw import budget, cli, counting, db, inpath, plain, queries, status, tvlive, verify
from tvgw.config import Settings

DAY = 86400.0
T0 = 1794098400.0  # 2026-11-07 18:40 CST: the NTP count's first snapshot on the reference
WEEKS = counting.TWO_WEEKS


@pytest.fixture
def conn(tmp_path):
    c = db.connect(str(tmp_path / "c.db"))
    yield c
    c.close()


def snapshots(conn, rule: str, start: float, end: float, packets: int = 0, size: int = 1024) -> None:
    """One fw_counters row of `rule` every 10 minutes in [start, end)."""
    t = start
    rows = []
    while t < end:
        rows.append((t, rule, packets, size))
        t += 600
    conn.executemany("INSERT INTO fw_counters(t, rule, packets, bytes) VALUES (?,?,?,?)", rows)
    conn.commit()


def obs(s=None, counters=(), probed=False, stood_down=False, budget_row=None):
    return counting.Observation(s or Settings(), set(counters), probed, stood_down, budget_row)


def by_key(rows):
    return {r.key: r for r in rows}


# ---- a run ------------------------------------------------------------------------------------------------------
def test_a_run_is_walked_back_until_a_gap_longer_than_run_gap():
    rows = [(t,) for t in (100_000.0, 99_400.0, 98_800.0, 98_800.0 - counting.RUN_GAP - 1, 1.0)]
    assert counting.run_start(rows) == (98_800.0, 100_000.0)
    assert counting.run_start([]) is None
    assert counting.run_start([(5.0,)]) == (5.0, 5.0)


def test_the_first_look_takes_the_start_from_the_mechanisms_own_record(conn):
    """The NTP count ran since T0 with a break two days in: its run is the part after the break."""
    snapshots(conn, queries.NTP_SET_ROW, T0, T0 + 2 * DAY)
    snapshots(conn, queries.NTP_SET_ROW, T0 + 3 * DAY, T0 + 5 * DAY + 1)
    state = counting.observe(conn, obs(counters={queries.NTP_SET_ROW}), T0 + 5 * DAY)
    assert state == {"ntp": {"since": T0 + 3 * DAY, "last": T0 + 5 * DAY}}
    assert json.loads(db.get_meta(conn, counting.META_KEY)) == state


def test_a_run_is_renewed_broken_after_run_gap_and_begun_again_after_a_clock_set_back(conn):
    ntp = obs(counters={queries.NTP_SET_ROW})
    counting.observe(conn, ntp, T0)  # nothing in the store: from now
    counting.observe(conn, ntp, T0 + 600)
    assert counting.load(conn)["ntp"] == {"since": T0, "last": T0 + 600}
    counting.observe(conn, obs(), T0 + 1200)  # a run that does not show it leaves the row to age
    assert counting.load(conn)["ntp"] == {"since": T0, "last": T0 + 600}
    counting.observe(conn, ntp, T0 + 600 + counting.RUN_GAP)  # just inside the gap: the same run
    later = T0 + 600 + 2 * counting.RUN_GAP + 1
    counting.observe(conn, ntp, later)
    assert counting.load(conn)["ntp"] == {"since": later, "last": later}
    counting.observe(conn, ntp, later - 3600)  # the clock set back before the run began
    assert counting.load(conn)["ntp"] == {"since": later - 3600, "last": later - 3600}


def test_each_mechanism_counts_only_when_its_own_run_shows_it():
    on = Settings(dnsgate_fill="inpath", live_reading="on", upload_ceiling="4M")
    active = {m.key: m.active for m in counting.MECHANISMS}
    assert not active["inpath"](obs(on))  # the setting alone: the rule is not loaded
    assert active["inpath"](obs(on, {inpath.MISS_RULE}))
    assert not active["inpath"](obs(Settings(), {inpath.MISS_RULE}))
    assert active["live"](obs(on)) and not active["live"](obs(on, stood_down=True))
    assert not active["live"](obs(Settings(live_reading="on", profile="samsung-tizen")))
    assert active["probe"](obs(probed=True)) and not active["probe"](obs())
    assert active["budget"](obs(on)) and not active["budget"](obs())
    assert active["budget"](obs(budget_row={"state": budget.FIXED}))
    assert not active["budget"](obs(budget_row={"state": budget.PENDING}))
    assert active["ntp"](obs(counters={queries.NTP_SET_ROW})) and not active["ntp"](obs())


def test_a_row_that_does_not_read_as_a_run_is_dropped(conn):
    db.set_meta(
        conn, counting.META_KEY, json.dumps({"ntp": {"since": "x", "last": 1}, "probe": [1], "live": {}})
    )
    assert counting.load(conn) == {}
    db.set_meta(conn, counting.META_KEY, "not json")
    assert counting.load(conn) == {}


# ---- status ---------------------------------------------------------------------------------------------------
def test_status_says_off_counting_stopped_and_reached(conn, lg):
    db.set_meta(
        conn,
        counting.META_KEY,
        json.dumps(
            {
                "ntp": {"since": T0, "last": T0 + 20 * DAY},
                "probe": {"since": T0 + 10 * DAY, "last": T0 + 20 * DAY},
                "live": {"since": T0, "last": T0 + 5 * DAY},
            }
        ),
    )
    rows = by_key(counting.status(conn, T0 + 20 * DAY, profile=lg, judge=False))
    assert (rows["ntp"].state, rows["ntp"].ends) == ("reached", T0 + WEEKS)
    assert (rows["probe"].state, rows["probe"].ends) == ("counting", T0 + 24 * DAY)
    assert rows["live"].state == "stopped" and rows["inpath"].state == "off"
    assert rows["budget"].state == "waiting" and rows["budget"].note == "it waits for its ceiling"
    # a report of an earlier day: reached only once its two weeks ended inside that day
    early = by_key(counting.status(conn, T0 + 20 * DAY, until=T0 + 13 * DAY, judge=False))
    assert early["ntp"].state == "counting"


def test_before_verify_kept_a_row_the_mechanisms_own_record_says(conn):
    snapshots(conn, queries.NTP_SET_ROW, T0, T0 + DAY)
    assert by_key(counting.status(conn, T0 + DAY))["ntp"].since == T0
    db.set_meta(conn, counting.META_KEY, "{}")  # once verify keeps the row, only the row counts
    assert by_key(counting.status(conn, T0 + DAY))["ntp"].state == "off"


def test_the_budgets_run_is_its_ceilings_unless_the_owner_set_one(conn, lg):
    ident = budget.identity(conn, lg, T0)
    db.set_meta(conn, budget.META_KEY, json.dumps({"state": "pending", "due": T0 + 4 * DAY, **ident}))
    row = by_key(counting.status(conn, T0, profile=lg))["budget"]
    assert (row.state, row.note) == ("waiting", "its ceiling is set after 2026-11-11 18:40")
    fixed = {"state": "fixed", "ceiling": 1, "largest": 0, "since": 0, "until": 0, "days": 14, "set_t": T0}
    db.set_meta(conn, budget.META_KEY, json.dumps({**fixed, **ident}))
    row = by_key(counting.status(conn, T0 + DAY, profile=lg))["budget"]
    assert (row.state, row.since, row.ends) == ("counting", T0, T0 + WEEKS)
    other = {**fixed, **ident, "profile": "samsung-tizen"}  # set for another profile: pending again
    db.set_meta(conn, budget.META_KEY, json.dumps(other))
    assert by_key(counting.status(conn, T0 + DAY, profile=lg))["budget"].state == "waiting"
    db.set_meta(conn, counting.META_KEY, "{}")  # verify has kept rows, and none for the budget yet
    owner = by_key(counting.status(conn, T0 + DAY, profile=lg, upload_ceiling="4M"))["budget"]
    assert owner.state == "off"  # the owner's ceiling: its run is kept by verify's look, as every other is
    counting.observe(conn, obs(Settings(upload_ceiling="4M")), T0 + DAY)
    owner = by_key(counting.status(conn, T0 + DAY, profile=lg, upload_ceiling="4M"))["budget"]
    assert (owner.state, owner.since) == ("counting", T0)  # from the gateway's ceiling, which it had


# ---- what two weeks hold ------------------------------------------------------------------------------------
def reached(conn, key: str, since: float = T0) -> None:
    db.set_meta(conn, counting.META_KEY, json.dumps({key: {"since": since, "last": since + WEEKS + 5 * DAY}}))


def judged(conn, lg, key: str, ceiling: str = "auto") -> counting.Row:
    return by_key(counting.status(conn, T0 + WEEKS + DAY, profile=lg, upload_ceiling=ceiling))[key]


def test_two_weeks_with_no_ntp_request_are_clean_and_one_with_requests_are_not(conn, lg):
    reached(conn, "ntp")
    snapshots(conn, queries.NTP_SET_ROW, T0, T0 + WEEKS + DAY, packets=0)
    snapshots(conn, queries.NTP_RULE, T0, T0 + WEEKS + DAY, packets=0)
    row = judged(conn, lg, "ntp")
    assert (row.state, row.judgement.clean, row.judgement.said) == (
        "reached",
        True,
        "the TV asked no time server",
    )
    conn.execute(
        "INSERT INTO fw_counters(t, rule, packets, bytes) VALUES (?, ?, 5, 0), (?, 'ntp: 203.0.113.5', 5, 800000)",
        (T0 + DAY + 1, queries.NTP_RULE, T0 + DAY + 1),
    )
    conn.execute(
        "INSERT INTO fw_counters(t, rule, packets, bytes) VALUES (?, ?, 1, 1024)",
        (T0 + DAY + 1, queries.NTP_SET_ROW),
    )
    conn.commit()
    row = judged(conn, lg, "ntp")
    assert row.judgement.clean is False and row.judgement.said == "the TV asked 1 time server 5 times"


def test_two_weeks_of_the_probe_are_clean_with_no_failed_test_and_no_apply_undone(conn, lg):
    reached(conn, "probe")
    for k in range(6):
        conn.execute(
            "INSERT INTO gw_samples(t, tv_probe) VALUES (?, ?)",
            (T0 + k * DAY, json.dumps({"v": "unknown" if k == 2 else "pass", "why": "", "ms": 1, "s": {}})),
        )
    conn.commit()
    row = judged(conn, lg, "probe")
    assert row.judgement.clean is True
    assert row.judgement.found == "6 runs: 0 failed, 1 could not judge; 0 applies would have been undone"
    conn.execute("INSERT INTO gw_samples(t, tv_probe) VALUES (?, ?)", (T0 + 7 * DAY, '{"v": "fail"}'))
    conn.execute(
        "INSERT INTO changes(t, t_precision, source, kind, subject, controllable, effect_class)"
        " VALUES (?, 1, 'confirm', 'apply_would_revert', 'would_revert', 1, 'A')",
        (T0 + 8 * DAY,),
    )
    conn.commit()
    row = judged(conn, lg, "probe")
    assert row.judgement.clean is False
    assert row.judgement.said == "1 test failed and 1 change would have been undone"


def test_the_in_path_count_and_the_live_reading_are_the_owners_to_judge(conn, lg):
    reached(conn, "inpath")
    snapshots(conn, inpath.MISS_RULE, T0, T0 + WEEKS + DAY, packets=0)
    conn.execute(
        "INSERT INTO fw_counters(t, rule, packets, bytes) VALUES (?, ?, 3, 0)",
        (T0 + 5 * DAY + 1, inpath.MISS_RULE),
    )
    conn.commit()
    row = judged(conn, lg, "inpath")
    assert row.judgement.clean is None and row.judgement.said.startswith("3 connections went to addresses")
    reached(conn, "live")
    assert judged(conn, lg, "live").judgement.clean is None


def test_two_weeks_of_the_budget_are_clean_with_no_hour_over_its_ceiling(conn, lg, monkeypatch):
    reached(conn, "budget")
    monkeypatch.setattr(budget, "report", lambda *a, **k: {"ceiling": 1_465_000, "events": []})
    row = judged(conn, lg, "budget", ceiling="4M")
    assert (row.judgement.clean, row.judgement.said) == (True, "no hour went over it")
    events = [{"hour": T0 + 3600}, {"hour": T0 + 3600}, {"hour": T0 + 7200}]
    monkeypatch.setattr(budget, "report", lambda *a, **k: {"ceiling": 1_465_000, "events": events})
    row = judged(conn, lg, "budget", ceiling="4M")
    assert (row.judgement.clean, row.judgement.said) == (False, "2 hours went over it")


# ---- the words -------------------------------------------------------------------------------------------------
def test_the_engineering_lines(conn, lg):
    reached(conn, "ntp")
    snapshots(conn, queries.NTP_SET_ROW, T0, T0 + WEEKS + DAY)
    rows = {r.key: r.as_dict() for r in counting.status(conn, T0 + WEEKS + DAY, profile=lg)}
    assert counting.engineering_line(rows["ntp"]) == (
        "NTP count (the clock servers the TV asks, inet tvgw_ntp): counting since 2026-11-07 18:40; two weeks ended"
        " 2026-11-21 18:40: 0 requests (clean)"
    )
    assert (
        counting.engineering_line(rows["inpath"])
        == "Address gate, in-path filler: off (DNSGATE_FILL=inpath starts it)"
    )
    assert counting.engineering_line(rows["budget"]) == "Upload budget: waiting: it waits for its ceiling"
    stopped = {**rows["inpath"], "state": "stopped", "last": T0}
    assert counting.engineering_line(stopped).endswith(
        "stopped, last seen 2026-11-07 18:40; its two weeks start again when it next runs"
    )
    going = {**rows["ntp"], "state": "counting"}
    assert counting.engineering_line(going).endswith("; two weeks end 2026-11-21 18:40")


def test_the_plain_lines_say_what_the_owner_may_decide_and_that_nothing_changes(conn, lg):
    reached(conn, "ntp")
    snapshots(conn, queries.NTP_SET_ROW, T0, T0 + WEEKS + DAY)
    row = by_key(counting.status(conn, T0 + WEEKS + DAY, profile=lg))["ntp"].as_dict()
    assert counting.plain_line(row, T0 + WEEKS + DAY) == (
        "The clock-server count has two clean weeks, since 7 November: the TV asked no time server. So the"
        " clock port could be closed for this TV. Nothing changes unless you decide it."
    )
    live = {"key": "live", "plain": "The reading of which app is in front", "since": T0, "clean": None}
    live["said"] = "it never stopped on its own"
    assert counting.plain_line(live, T0 + WEEKS) == (
        "The reading of which app is in front has counted for two weeks, since 7 November: it never stopped"
        " on its own. Whether an app rule could be tried: sudo tvgw receipt --replay."
    )


def brief_rows(conn, lg, until: float, now: float) -> dict:
    o = queries.window_report(conn, until - DAY, until, lg, now=now)
    return o


def test_the_brief_prints_the_section_once_something_counts_and_the_plain_line_for_three_days(conn, lg):
    end = T0 + WEEKS
    assert "Counting" not in render(brief_rows(conn, lg, T0 + DAY, T0 + DAY))  # nothing ever counted
    reached(conn, "ntp")
    snapshots(conn, queries.NTP_SET_ROW, T0, end + 4 * DAY)
    o = brief_rows(conn, lg, end + 3600, end + 3600)
    text = render(o)
    assert (
        "\nCounting (each refuses nothing; whether a wall refuses after two clean weeks is the owner's"
        in text
    )
    assert (
        "\n  NTP count (the clock servers the TV asks, inet tvgw_ntp): counting since 2026-11-07 18:40; two weeks ended"
        in text
    )
    lines = [x for x in plain.plain_brief(o, profile=lg) if x.startswith("  Counting:")]
    assert lines == [
        "  Counting: The clock-server count has two clean weeks, since 7 November: the TV asked no time server."
        " So the clock port could be closed for this TV. Nothing changes unless you decide it."
    ]
    third = [
        x
        for x in plain.plain_brief(brief_rows(conn, lg, end + 2 * DAY + 60, end + 2 * DAY + 60))
        if "Counting:" in x
    ]
    assert third[0].endswith("(tvgw brief --full keeps it).")
    assert not [
        x
        for x in plain.plain_brief(brief_rows(conn, lg, end + 3 * DAY + 60, end + 3 * DAY + 60))
        if "Counting:" in x
    ]
    early = brief_rows(conn, lg, T0 + 5 * DAY, end + 3600)  # a report of a day before the two weeks ended
    assert not [x for x in plain.plain_brief(early) if "Counting:" in x]


def render(o: dict) -> str:
    out = io.StringIO()
    cli.render_brief(o, out)
    return out.getvalue()


def test_a_failure_to_read_what_is_counting_costs_the_key_not_the_report(conn, lg, monkeypatch):
    monkeypatch.setattr(counting, "status", lambda *a, **k: 1 / 0)
    o = queries.window_report(conn, T0, T0 + DAY, lg, now=T0 + DAY)
    assert o["counting"] is None and "counting: ZeroDivisionError: division by zero" in o["warnings"]
    render(o)
    plain.plain_brief(o)


def test_a_mechanism_a_later_version_adds_is_shown_with_the_rest(conn, lg, monkeypatch):
    """The attention counts (design decision 69) and any later count add one Mechanism to the tuple."""
    extra = counting.Mechanism(
        "attention", "Attention-keyed silence", "The attention count", "connections while nobody watched",
        "ATTENTION_WALL=count", lambda o: True, lambda conn, now: None,
        lambda *a: counting.Judgement(None, "", ""), "", "Your call.",
    )  # fmt: skip
    monkeypatch.setattr(counting, "MECHANISMS", (*counting.MECHANISMS, extra))
    counting.observe(conn, obs(), T0)
    assert by_key(counting.status(conn, T0 + 3600))["attention"].state == "counting"


# ---- the file `tvgw status` reads ----------------------------------------------------------------------------------
def test_the_file_holds_keys_states_and_times_only_and_status_reads_it(conn, lg, status_file):
    reached(conn, "ntp")
    db.set_meta(
        conn,
        counting.META_KEY,
        json.dumps(
            {
                "ntp": {"since": T0, "last": T0 + 15 * DAY},
                "live": {"since": T0 + 10 * DAY, "last": T0 + 15 * DAY},
            }
        ),
    )
    rows = counting.status(conn, T0 + 15 * DAY, profile=lg, judge=False)
    text = counting.file_text(rows)
    assert text.splitlines() == [
        f"ntp reached {int(T0)} {int(T0 + WEEKS)}",
        "budget waiting - -",
        "inpath off - -",
        "probe off - -",
        f"live counting {int(T0 + 10 * DAY)} {int(T0 + 24 * DAY)}",
    ]
    assert counting.status_lines(text, T0 + 15 * DAY) == [
        "Counting, and refusing nothing until you decide:",
        "  the TV's requests to time servers: since 7 November; its two weeks ended on 21 November",
        "  which app is in front, as the TV reports it: since 17 November; its two weeks end on 1 December",
    ]
    status_file.write_text(f"ok {int(T0 + 15 * DAY) - 60} 34\n", encoding="utf-8")
    counting.write_file(rows, counting.file_beside(str(status_file)))
    out = []
    assert status.main(str(status_file), now=T0 + 15 * DAY, out=out.append) == 0
    assert out[3:] == counting.status_lines(text, T0 + 15 * DAY)


def test_lines_the_file_should_not_hold_are_skipped():
    text = "ntp counting 1 2\nunknown counting 1 2\nntp sideways 1 2\nntp counting x 2\nntp counting 1\n"
    assert [(m.key, s) for m, s, _a, _b in counting.parse_file(text)] == [("ntp", "counting")]
    assert counting.status_lines(None, T0) == [] and counting.status_lines("probe off - -\n", T0) == []
    assert counting.status_lines("inpath stopped 1 2\nlive waiting 1 2\n", T0) == []  # only what counts


def test_verify_record_keeps_the_runs_and_writes_the_file(conn, lg, tmp_path, status_file):
    r = verify.Result(checks=[verify.Check("ruleset", True)], t=T0)
    r.counters = [(queries.NTP_SET_ROW, 0, 1024)]
    s = Settings(state_dir=str(tmp_path))
    verify.record(conn, r)
    verify.keep_counting(conn, s, lg, r)
    assert counting.load(conn) == {"ntp": {"since": T0, "last": T0}}
    path = counting.file_beside(verify.STATUS)
    with open(path, encoding="utf-8") as fh:
        assert fh.read().splitlines()[0] == f"ntp counting {int(T0)} {int(T0 + WEEKS)}"
    (tmp_path / tvlive.STOOD_DOWN_FILE).write_text("x", encoding="utf-8")
    live = Settings(state_dir=str(tmp_path), live_reading="on")
    verify.keep_counting(conn, live, lg, r)
    assert "live" not in counting.load(conn)  # stood down: not counting


def test_a_store_that_will_not_take_the_row_is_a_line_on_stderr_not_a_failed_check(
    conn, lg, tmp_path, capsys
):
    conn.close()
    gone = db.connect(str(tmp_path / "ro.db"))
    gone.execute("CREATE TRIGGER no_meta BEFORE INSERT ON meta BEGIN SELECT RAISE(ABORT, 'read-only'); END")
    gone.execute("CREATE TRIGGER no_meta_u BEFORE UPDATE ON meta BEGIN SELECT RAISE(ABORT, 'read-only'); END")
    r = verify.Result(checks=[], t=T0)
    r.counters = [(queries.NTP_SET_ROW, 0, 1024)]
    verify.keep_counting(gone, Settings(state_dir=str(tmp_path)), lg, r)
    assert capsys.readouterr().err.startswith("tvgw verify: could not keep what is counting: ")
    gone.close()


def test_two_weeks_of_the_probe_with_no_run_kept_are_never_clean(conn, lg):
    """A store forgotten since, or samples never kept: nothing to judge the two weeks by."""
    reached(conn, "probe")
    row = judged(conn, lg, "probe")
    assert (row.judgement.clean, row.judgement.said) == (None, "the gateway kept no record of its tests")


def test_forget_takes_the_runs_with_the_rows_they_are_judged_by(conn):
    from tvgw import forget

    assert counting.META_KEY in forget.META_FORGET
