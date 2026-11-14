"""(counting) What is counting (design decision 72): each count-only mechanism's run, kept by `tvgw verify
--record` and backfilled from its own record; the judging of two weeks; the brief's Counting section and the
plain brief's line; and the file `tvgw status` reads."""

import io
import json
import os

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


def test_a_stand_down_of_the_live_reading_ends_its_run_at_once(conn):
    """A stand-down resumed within RUN_GAP still breaks the run, so "it never stopped on its own" holds."""
    on = Settings(live_reading="on")
    counting.observe(conn, obs(on), T0)
    counting.observe(conn, obs(on), T0 + 600)
    counting.observe(conn, obs(on, stood_down=True), T0 + 1200)
    assert counting.load(conn)["live"] == {"since": T0, "last": T0 + 600, "broken": True}
    assert by_key(counting.status(conn, T0 + 1500))["live"].state == "stopped"
    counting.observe(conn, obs(on), T0 + 1800)  # resumed ten minutes later: a new run
    assert counting.load(conn)["live"] == {"since": T0 + 1800, "last": T0 + 1800}


def test_the_live_readings_run_is_never_read_from_the_tvs_own_events(conn):
    """Its events say when the TV was watched: the run starts at the first look that sees the reading on,
    and a store with events and no look says nothing of it."""
    conn.execute("INSERT INTO tv_events(t, kind, value) VALUES (?, 'app', 'netflix')", (T0 - 9 * DAY + 1234,))
    conn.commit()
    assert by_key(counting.status(conn, T0))["live"].state == "off"
    counting.observe(conn, obs(Settings(live_reading="on")), T0)
    assert counting.load(conn)["live"] == {"since": T0, "last": T0}


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
    assert (row.state, row.note) == ("waiting", "its ceiling is set after 2026-11-11")
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


def tv_on(conn, hours: int, start: float = T0 + 3600) -> None:
    """`hours` hourly readings that found the TV awake, one an hour."""
    conn.executemany(
        "INSERT INTO tvstate(t, power, app) VALUES (?, 'Active', 'netflix')",
        [(start + 3600 * h,) for h in range(hours)],
    )
    conn.commit()


def test_two_weeks_with_no_ntp_request_are_clean_and_one_with_requests_are_not(conn, lg):
    reached(conn, "ntp")
    tv_on(conn, counting.MIN_ON_HOURS)
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


def test_two_weeks_with_the_tv_off_are_never_clean(conn, lg, monkeypatch):
    """A TV left off asks no time server and uploads nothing: that is no evidence for closing a port."""
    reached(conn, "ntp")
    tv_on(conn, counting.MIN_ON_HOURS - 1)
    snapshots(conn, queries.NTP_SET_ROW, T0, T0 + WEEKS + DAY, packets=0)
    row = judged(conn, lg, "ntp")
    assert row.judgement.clean is None
    assert (
        row.judgement.said
        == f"the TV was on about {counting.MIN_ON_HOURS - 1} hours in them, too few to tell"
    )
    reached(conn, "budget")
    monkeypatch.setattr(budget, "report", lambda *a, **k: {"ceiling": 1_465_000, "events": []})
    assert judged(conn, lg, "budget", ceiling="4M").judgement.clean is None


def test_where_nothing_reads_the_tv_its_ports_counters_say_how_long_it_was_on(conn, monkeypatch):
    from tvgw import activity

    monkeypatch.setattr(activity, "hours_on", lambda c, a, b: 30.0)
    assert counting.on_hours(conn, T0, T0 + WEEKS) == 30.0
    monkeypatch.setattr(activity, "hours_on", lambda c, a, b: None)
    assert counting.on_hours(conn, T0, T0 + WEEKS) == 0.0
    tv_on(conn, 3)
    conn.execute("INSERT INTO tvstate(t, power, app) VALUES (?, 'Active Standby', '')", (T0 + 10 * 3600,))
    conn.commit()
    assert counting.on_hours(conn, T0, T0 + WEEKS) == 3.0


def probe_runs(conn, verdicts: dict) -> None:
    conn.executemany(
        "INSERT INTO gw_samples(t, tv_probe) VALUES (?, ?)",
        [(t, json.dumps({"v": v, "why": "", "ms": 1, "s": {}})) for t, v in verdicts.items()],
    )
    conn.commit()


def test_two_weeks_of_the_probe_are_clean_with_a_pass_every_day_and_nothing_failed_or_undone(conn, lg):
    reached(conn, "probe")
    passes = {T0 + 600 + k * DAY: "pass" for k in range(15)} | {T0 + 15 * DAY - 600: "pass"}  # every date
    probe_runs(conn, passes | {T0 + 1200 + 2 * DAY: "unknown"})
    row = judged(conn, lg, "probe")
    assert row.judgement.clean is True
    assert row.judgement.found == "17 runs: 0 failed, 1 could not judge; 0 applies would have been undone"
    probe_runs(conn, {T0 + 1800 + 7 * DAY: "fail"})
    conn.execute(
        "INSERT INTO changes(t, t_precision, source, kind, subject, controllable, effect_class)"
        " VALUES (?, 1, 'confirm', 'apply_would_revert', 'would_revert', 1, 'A')",
        (T0 + 8 * DAY,),
    )
    conn.commit()
    row = judged(conn, lg, "probe")
    assert row.judgement.clean is False
    assert row.judgement.said == "1 test failed and 1 change would have been undone"


def test_runs_that_could_not_judge_never_make_the_probes_two_weeks_clean(conn, lg):
    reached(conn, "probe")
    probe_runs(conn, {T0 + 600 * k: "unknown" for k in range(2016)})  # two weeks of them, every 10 minutes
    row = judged(conn, lg, "probe")
    assert row.judgement.clean is None and row.judgement.said == "no test failed, but on 16 days none passed"


def test_the_in_path_count_and_the_live_reading_are_the_owners_to_judge(conn, lg):
    reached(conn, "inpath")
    snapshots(conn, inpath.MISS_RULE, T0, T0 + WEEKS + DAY, packets=0)
    conn.execute(
        "INSERT INTO fw_counters(t, rule, packets, bytes) VALUES (?, ?, 3, 0)",
        (T0 + 5 * DAY + 1, inpath.MISS_RULE),
    )
    conn.commit()
    row = judged(conn, lg, "inpath")
    assert row.judgement.clean is None
    assert (
        row.judgement.said
        == "3 connections went to addresses missing from the gateway's list of looked-up addresses"
    )
    reached(conn, "live")
    assert judged(conn, lg, "live").judgement.said == "the gateway never saw it stop on its own"


def test_two_weeks_of_the_budget_are_clean_with_no_hour_over_its_ceiling(conn, lg, monkeypatch):
    reached(conn, "budget")
    tv_on(conn, counting.MIN_ON_HOURS)
    monkeypatch.setattr(budget, "report", lambda *a, **k: {"ceiling": 1_465_000, "events": []})
    row = judged(conn, lg, "budget", ceiling="4M")
    assert (row.judgement.clean, row.judgement.said) == (True, "no hour went over it")
    events = [{"hour": T0 + 3600}, {"hour": T0 + 3600}, {"hour": T0 + 7200}]
    monkeypatch.setattr(budget, "report", lambda *a, **k: {"ceiling": 1_465_000, "events": events})
    row = judged(conn, lg, "budget", ceiling="4M")
    assert (row.judgement.clean, row.judgement.said) == (False, "2 hours went over it")


def test_two_weeks_of_the_probe_with_no_run_kept_are_never_clean(conn, lg):
    """A store forgotten since, or samples never kept: nothing to judge the two weeks by."""
    reached(conn, "probe")
    row = judged(conn, lg, "probe")
    assert (row.judgement.clean, row.judgement.said) == (None, "the gateway kept no record of its tests")


# ---- the words: dates, never a time of day -----------------------------------------------------------------------
def ntp_reached(conn):
    reached(conn, "ntp")
    tv_on(conn, counting.MIN_ON_HOURS)
    snapshots(conn, queries.NTP_SET_ROW, T0, T0 + WEEKS + DAY)


def test_a_report_carries_the_runs_by_the_day(conn, lg):
    ntp_reached(conn)
    rows = {r.key: r.as_dict() for r in counting.status(conn, T0 + WEEKS + DAY, profile=lg)}
    assert (rows["ntp"]["since"], rows["ntp"]["ends"], rows["ntp"]["last"]) == (
        "2026-11-07",
        "2026-11-21",
        "2026-11-26",
    )
    assert rows["ntp"]["days_past_end"] == 1
    assert counting.engineering_line(rows["ntp"]) == (
        "NTP count (the clock servers the TV asks, inet tvgw_ntp): counting since 2026-11-07; two weeks ended"
        " 2026-11-21: 0 requests (clean)"
    )
    assert (
        counting.engineering_line(rows["inpath"])
        == "Address gate, in-path filler: off (DNSGATE_FILL=inpath starts it)"
    )
    assert counting.engineering_line(rows["budget"]) == "Upload budget: waiting: it waits for its ceiling"
    stopped = {**rows["inpath"], "state": "stopped", "last": "2026-11-07"}
    assert counting.engineering_line(stopped).endswith(
        "stopped, last seen 2026-11-07; its two weeks start again when it next runs"
    )
    going = {**rows["ntp"], "state": "counting"}
    assert counting.engineering_line(going).endswith("; two weeks end 2026-11-21")
    assert not [
        v for r in rows.values() for v in r.values() if isinstance(v, str) and ":" in v and "20" in v[:4]
    ]


def test_the_plain_lines_say_what_the_owner_may_decide_and_that_nothing_changes(conn, lg):
    ntp_reached(conn)
    row = by_key(counting.status(conn, T0 + WEEKS + DAY, profile=lg))["ntp"].as_dict()
    assert counting.plain_line(row, T0 + WEEKS + DAY) == (
        "The clock-server count has two clean weeks, since 7 November: the TV asked no time server. So the"
        " clock port could be closed for this TV. Nothing changes unless you decide it."
    )
    live = {
        "key": "live",
        "plain": "The reading of which app is in front",
        "since": "2026-11-07",
        "clean": None,
    }
    live["said"] = "the gateway never saw it stop on its own"
    assert counting.plain_line(live, T0 + WEEKS) == (
        "The reading of which app is in front has counted for two weeks, since 7 November: the gateway never"
        " saw it stop on its own. Whether an app rule could be tried: sudo tvgw receipt --replay."
    )


def brief_rows(conn, lg, until: float, now: float) -> dict:
    return queries.window_report(conn, until - DAY, until, lg, now=now)


def render(o: dict) -> str:
    out = io.StringIO()
    cli.render_brief(o, out)
    return out.getvalue()


def counting_lines(o) -> list[str]:
    return [x for x in plain.plain_brief(o) if x.startswith("  Counting:")]


def test_the_brief_prints_the_section_once_something_counts_and_the_plain_line_for_three_days(conn, lg):
    end = T0 + WEEKS
    assert "Counting" not in render(brief_rows(conn, lg, T0 + DAY, T0 + DAY))  # nothing ever counted
    reached(conn, "ntp")
    tv_on(conn, counting.MIN_ON_HOURS)
    snapshots(conn, queries.NTP_SET_ROW, T0, end + 4 * DAY)
    o = brief_rows(conn, lg, end + 3600, end + 3600)
    text = render(o)
    assert (
        "\nCounting (each refuses nothing; whether a wall refuses after two clean weeks is the owner's"
        in text
    )
    assert (
        "\n  NTP count (the clock servers the TV asks, inet tvgw_ntp): counting since 2026-11-07; two weeks"
        in text
    )
    assert counting_lines(o) == [
        "  Counting: The clock-server count has two clean weeks, since 7 November: the TV asked no time server."
        " So the clock port could be closed for this TV. Nothing changes unless you decide it."
    ]
    third = counting_lines(brief_rows(conn, lg, end + 2 * DAY + 60, end + 2 * DAY + 60))
    assert third[0].endswith("(tvgw brief --full keeps it).")
    assert counting_lines(brief_rows(conn, lg, end + 3 * DAY + 60, end + 3 * DAY + 60)) == []
    early = brief_rows(conn, lg, T0 + 5 * DAY, end + 3600)  # a report of a day before the two weeks ended
    assert counting_lines(early) == []


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
def test_the_file_holds_keys_states_and_dates_only_and_status_reads_it(conn, lg, status_file):
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
        "ntp reached 2026-11-07 2026-11-21",
        "budget waiting - -",
        "inpath off - -",
        "mint off - -",
        "probe off - -",
        "live counting 2026-11-17 2026-12-01",
    ]
    assert counting.status_lines(text, T0 + 15 * DAY) == [
        "Counting, and refusing nothing until you decide:",
        "  the TV's requests to time servers: since 7 November; its two weeks ended on 21 November",
        "  which app is in front, as the TV reports it: since 17 November; its two weeks end on 1 December",
    ]
    status_file.write_text(f"ok {int(T0 + 15 * DAY) - 60} 34\n", encoding="utf-8")
    counting.write_file(rows, counting.file_beside(str(status_file)))
    out = []
    now = T0 + 15 * DAY
    os.utime(counting.file_beside(str(status_file)), (now - 60, now - 60))
    assert status.main(str(status_file), now=now, out=out.append) == 0
    assert out[3:] == counting.status_lines(text, now)


def test_a_file_the_record_stopped_writing_says_so_and_nothing_else(conn, lg, status_file):
    path = counting.file_beside(str(status_file))
    status_file.write_text(f"ok {int(T0) - 60} 34\n", encoding="utf-8")
    with open(path, "w", encoding="utf-8") as fh:
        fh.write("ntp counting 2026-11-01 2026-11-15\n")
    os.utime(path, (T0 - 3 * 3600, T0 - 3 * 3600))
    out = []
    status.main(str(status_file), now=T0, out=out.append)
    assert out[3:] == ["What is counting is not known: it was last recorded 3 hours ago."]


def test_lines_the_file_should_not_hold_are_skipped():
    text = "ntp counting 2026-11-01 2026-11-15\nunknown counting 1 2\nntp sideways 1 2\nntp counting 179 2\nntp counting 1\n"
    assert [(m.key, s) for m, s, _a, _b in counting.parse_file(text)] == [("ntp", "counting")]
    assert counting.status_lines(None, T0) == [] and counting.status_lines("probe off - -\n", T0) == []
    stopped = "inpath stopped 2026-11-01 2026-11-15\nlive waiting 2026-11-01 2026-11-15\n"
    assert counting.status_lines(stopped, T0) == []  # only what counts


def test_verify_record_keeps_the_runs_and_writes_the_file(conn, lg, tmp_path, status_file):
    r = verify.Result(checks=[verify.Check("ruleset", True)], t=T0)
    r.counters = [(queries.NTP_SET_ROW, 0, 1024)]
    s = Settings(state_dir=str(tmp_path))
    verify.record(conn, r)
    verify.keep_counting(conn, s, lg, r)
    assert counting.load(conn) == {"ntp": {"since": T0, "last": T0}}
    path = counting.file_beside(verify.STATUS)
    with open(path, encoding="utf-8") as fh:
        assert fh.read().splitlines()[0] == "ntp counting 2026-11-07 2026-11-21"
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


def test_forget_takes_the_runs_with_the_rows_they_are_judged_by(conn):
    from tvgw import forget

    assert counting.META_KEY in forget.META_FORGET
