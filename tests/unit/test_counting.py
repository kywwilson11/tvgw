"""(counting) What is counting (design decision 72): each count-only mechanism's run, kept by `tvgw verify
--record` and backfilled from its own record; the judging of two weeks; the brief's Counting section and the
plain brief's line; and the file `tvgw status` reads."""

import dataclasses
import io
import json
import os

import pytest

from tvgw import budget, cli, counting, db, inpath, plain, queries, receipt, status, tvlive, verify
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


def tv_on(conn, hours: int, days: int = 14, start: float = T0 + 3600) -> None:
    """`hours` hourly readings that found the TV awake, one an hour, on each of `days` days."""
    conn.executemany(
        "INSERT INTO tvstate(t, power, app) VALUES (?, 'Active', 'netflix')",
        [(start + d * DAY + 3600 * h,) for d in range(days) for h in range(hours)],
    )
    conn.commit()


def wakes(conn, per_day: int, days: int = 14, start: float = T0 + 3600) -> None:
    """`per_day` wakes from standby on each of `days` days, as the live reading writes them."""
    events = []
    for d in range(days):
        for k in range(per_day):
            t = start + d * DAY + 600 * k
            events += [(t, "Active Standby"), (t + 300, "Active")]
    conn.executemany("INSERT INTO tv_events(t, kind, value) VALUES (?, 'power', ?)", events)
    conn.commit()


def test_two_weeks_with_no_ntp_request_are_clean_and_one_with_requests_are_not(conn, lg):
    reached(conn, "ntp")
    wakes(conn, 5)
    snapshots(conn, queries.NTP_SET_ROW, T0, T0 + WEEKS + DAY, packets=0)
    snapshots(conn, queries.NTP_RULE, T0, T0 + WEEKS + DAY, packets=0)
    row = judged(conn, lg, "ntp")
    assert (row.state, row.judgement.clean, row.judgement.said) == (
        "reached",
        True,
        "the TV asked no time server across 70 starts on 14 days: fewer than 1 start in 23 would have been"
        " cut off",
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
    assert (row.judgement.events, row.judgement.found) == (
        5,
        "5 requests to 1 addresses; 70 starts on 14 days of 15",
    )


def test_fourteen_hours_on_one_day_are_not_two_clean_weeks(conn, lg, monkeypatch):
    """L2-8: fourteen clock hours of one evening, the TV off the other thirteen days, were two clean weeks
    of the upload budget, and zero events in fourteen hours bound the rate only under 1 in 4."""
    reached(conn, "budget")
    tv_on(conn, 14, days=1, start=T0 + 48000)  # 08:00 to 21:00 on 8 November
    monkeypatch.setattr(budget, "report", lambda *a, **k: {"ceiling": 1_465_000, "events": []})
    j = judged(conn, lg, "budget", ceiling="4M").judgement
    assert j.clean is None
    assert (j.clean, j.events, j.exposure, j.unit, j.days, j.bound) == (
        None, 0, 14.0, "on-hour", 1, "fewer than 1 on-hour in 4"
    )  # fmt: skip
    assert j.found == (
        "0 destination-hours over the 1465000-byte ceiling; 14 on-hours on 1 day of 15: fewer than 1 on-hour"
        " in 4, where clean needs 7 days and 1 on-hour in 20"
    )
    assert j.said == "no hour went over it, but across only 14 on-hours on 1 day of 15: too few to tell"


@pytest.mark.parametrize(
    ("per_day", "days", "clean"),
    [(5, 14, True), (9, 6, None), (4, 14, None), (0, 14, None)],
    ids=["70 on 14 days", "54 on 6 days", "56: under 1 in 20", "none"],
)
def test_clean_needs_seven_days_and_a_bound_of_1_in_20(conn, lg, per_day, days, clean):
    reached(conn, "ntp")
    wakes(conn, per_day, days)
    snapshots(conn, queries.NTP_SET_ROW, T0, T0 + WEEKS + DAY, packets=0)
    assert judged(conn, lg, "ntp").judgement.clean is clean


@pytest.mark.parametrize(
    ("amount", "days", "clean"),
    [(60, 7, True), (59, 14, None), (60, 6, None), (0, 0, None)],
    ids=["1 in 20 on 7 days", "1 in 19", "on 6 days", "nothing to count"],
)
def test_clean_is_the_owners_bar_exactly(conn, amount, days, clean):
    quiet = counting.Mechanism(
        "x", "X", "The x", "x", "", lambda o: True, lambda conn, now: None,
        lambda *a: counting.Judgement(True, "0 x", "nothing happened", 0), "", "",
        exposure=lambda conn, a, b: (float(amount), "start", days), cut="would have been cut off",
    )  # fmt: skip
    assert counting.judge(quiet, conn, T0, T0 + WEEKS, None, "auto").clean is clean


def test_a_judgement_with_nothing_to_bound_it_is_never_clean(conn):
    """A later mechanism whose judge says clean with no count, or that has no exposure, fails closed."""
    say = counting.Mechanism(
        "x", "X", "The x", "x", "", lambda o: True, lambda conn, now: None,
        lambda *a: counting.Judgement(True, "x", "x"), "", "",
    )  # fmt: skip
    assert counting.judge(say, conn, T0, T0 + WEEKS, None, "auto").clean is None
    counted = dataclasses.replace(say, exposure=lambda conn, a, b: (100.0, "start", 14))
    assert counting.judge(counted, conn, T0, T0 + WEEKS, None, "auto").clean is None


def test_clean_two_weeks_with_a_request_since_they_ended_are_not_said_to_be_clean(conn, lg):
    """While the plain brief says them, the days since the two weeks ended are read too: a clean two weeks
    followed by requests for the time no longer advise closing the clock port."""
    ntp_reached(conn)
    conn.execute(
        "INSERT INTO fw_counters(t, rule, packets, bytes) VALUES (?, ?, 1, 1024), (?, 'ntp: 203.0.113.5', 5, 800)",
        (T0 + WEEKS + 3600, queries.NTP_SET_ROW, T0 + WEEKS + 3600),
    )
    conn.commit()
    row = by_key(counting.status(conn, T0 + WEEKS + DAY, profile=lg))["ntp"]
    assert (row.judgement.clean, row.judgement.said) == (
        False,
        "the TV asked 1 time server 5 times since they ended",
    )
    assert "has counted for two weeks" in counting.plain_line(row.as_dict(), T0 + WEEKS + DAY)
    gone = by_key(counting.status(conn, T0 + WEEKS + 3 * DAY, profile=lg))["ntp"]  # the line no longer shows
    assert gone.judgement.clean is True


def test_the_clock_ports_exposure_is_the_tvs_starts_not_its_hours_on(conn, lg):
    """A TV asks for the time when it starts: fourteen hours on and one wake are one start."""
    tv_on(conn, 14, days=1)
    wakes(conn, 1, days=1)
    conn.execute("INSERT INTO tv_events(t, kind, value) VALUES (?, 'power', 'Active')", (T0 + 3 * DAY,))
    ntp = by_key(counting.MECHANISMS)["ntp"]
    assert ntp.exposure(conn, T0, T0 + WEEKS) == (1.0, "start", 1)  # a day with no start is no day of it


def power(t: float, state: str, processing: str = "") -> tuple:
    return (t, "power", state, processing)


def carrier(t: float, cc: int | None, boot: str = "b1") -> tuple:
    return (t, boot, cc)


@pytest.mark.parametrize(
    ("events", "samples", "starts"),
    [
        ([power(T0 + 60, "Active Standby"), power(T0 + 120, "Active")], [], 1),
        ([power(T0 + 60, "Active Standby"), power(T0 + 120, "Screen Saver")], [], 1),
        ([power(T0 + 60, "Active"), power(T0 + 120, "Screen Saver"), power(T0 + 180, "Active")], [], 0),
        (
            [
                power(T0 + 60, "Active", "Request Power Off"),
                power(T0 + 90, "Bogus"),
                power(T0 + 120, "Active"),
            ],
            [],
            1,
        ),
        ([power(T0 + 60, "Active Standby"), power(T0 + 90, "Suspend"), power(T0 + 120, "Active")], [], 1),
        ([], [carrier(T0, 3), carrier(T0 + 600, 4), carrier(T0 + 1200, 5)], 1),
        ([], [carrier(T0, 3), carrier(T0 + 600, 4)], 0),
        ([], [carrier(T0, 3), carrier(T0 + 600, 5, "b2")], 0),
        ([], [carrier(T0, None), carrier(T0 + 600, 5), carrier(T0 + 1200, 2)], 0),
        ([power(T0 + 60, "Active")], [carrier(T0, 3), carrier(T0 + 600, 5)], 0),
    ],
    ids=[
        "a wake",
        "a wake to the screen saver",
        "the screen saver is no start",
        "switching off, an unknown word, on",
        "standby, then deeper, then on",
        "a loss and its return",
        "a lone change",
        "across a reboot of the gateway",
        "a missing count and a reset",
        "the live reading's day ignores the carrier",
    ],
)
def test_a_start_is_a_wake_the_live_reading_heard_or_a_loss_and_return_of_the_tvs_link(
    conn, events, samples, starts
):
    conn.executemany("INSERT INTO tv_events(t, kind, value, detail) VALUES (?, ?, ?, ?)", events)
    conn.executemany("INSERT INTO gw_samples(t, boot_id, tv_cc) VALUES (?, ?, ?)", samples)
    assert sum(counting.starts(conn, T0, T0 + DAY).values()) == starts


def test_where_nothing_reads_the_tv_its_ports_counters_say_how_long_it_was_on_each_day(conn, monkeypatch):
    from tvgw import activity

    spans = []
    monkeypatch.setattr(activity, "hours_on", lambda c, a, b: spans.append((a, b)) or 2.0)
    by_day = counting.on_hours(conn, T0, T0 + 2 * DAY)
    assert by_day == {"2026-11-07": 2.0, "2026-11-08": 2.0, "2026-11-09": 2.0}
    assert spans[0][0] == T0 and spans[-1][1] == T0 + 2 * DAY and spans[1][1] - spans[1][0] == DAY
    monkeypatch.setattr(activity, "hours_on", lambda c, a, b: None)
    assert counting.on_hours(conn, T0, T0 + WEEKS) == {}
    tv_on(conn, 3, days=2)
    conn.execute("INSERT INTO tvstate(t, power, app) VALUES (?, 'Active Standby', '')", (T0 + 10 * 3600,))
    conn.execute("INSERT INTO tvstate(t, power, app) VALUES (?, 'Screen Saver', '')", (T0 + 3600 + 900,))
    conn.commit()
    assert counting.on_hours(conn, T0, T0 + WEEKS) == {"2026-11-07": 3.0, "2026-11-08": 3.0}


def probe_runs(conn, verdicts: dict) -> None:
    conn.executemany(
        "INSERT INTO gw_samples(t, tv_probe) VALUES (?, ?)",
        [(t, json.dumps({"v": v, "why": "", "ms": 1, "s": {}})) for t, v in verdicts.items()],
    )
    conn.commit()


def test_two_weeks_of_the_probe_are_clean_with_a_pass_every_day_and_nothing_failed_or_undone(conn, lg):
    reached(conn, "probe")
    passes = {T0 + 600 + k * DAY + h * 3600: "pass" for k in range(14) for h in range(5)}
    probe_runs(conn, passes | {T0 + WEEKS - 600: "pass", T0 + 1200 + 2 * DAY: "unknown"})  # every date
    row = judged(conn, lg, "probe")
    assert row.judgement.clean is True
    assert row.judgement.found == (
        "72 runs: 0 failed, 1 could not judge; 0 applies would have been undone; 72 runs on 15 days of 15:"
        " fewer than 1 run in 24"
    )
    probe_runs(conn, {T0 + 1800 + 7 * DAY: "fail"})
    conn.execute(
        "INSERT INTO changes(t, t_precision, source, kind, subject, controllable, effect_class)"
        " VALUES (?, 1, 'confirm', 'apply_would_revert', 'would_revert', 1, 'A')",
        (T0 + 8 * DAY,),
    )
    conn.commit()
    row = judged(conn, lg, "probe")
    assert (row.judgement.clean, row.judgement.events) == (False, 2)
    assert row.judgement.said == "1 test failed and 1 change would have been undone"


def test_runs_that_could_not_judge_never_make_the_probes_two_weeks_clean(conn, lg):
    reached(conn, "probe")
    probe_runs(conn, {T0 + 600 * k: "unknown" for k in range(2016)})  # two weeks of them, every 10 minutes
    row = judged(conn, lg, "probe")
    assert row.judgement.clean is None and row.judgement.said == "no test failed, but on 15 days none passed"


def test_the_in_path_count_and_the_live_reading_are_the_owners_to_judge(conn, lg):
    reached(conn, "inpath")
    snapshots(conn, inpath.MISS_RULE, T0, T0 + WEEKS + DAY, packets=0)
    conn.execute(
        "INSERT INTO fw_counters(t, rule, packets, bytes) VALUES (?, ?, 3, 0)",
        (T0 + 5 * DAY + 1, inpath.MISS_RULE),
    )
    conn.execute(
        "INSERT INTO flows(t_start, t_end, proto, dst) VALUES (?, ?, 'tcp', '203.0.113.9')",
        (T0 + DAY, T0 + DAY),
    )
    conn.commit()
    row = judged(conn, lg, "inpath")
    assert (row.judgement.clean, row.judgement.events, row.judgement.exposure) == (None, 3, 1.0)
    assert (
        row.judgement.said
        == "3 connections went to addresses missing from the gateway's list of looked-up addresses"
    )
    reached(conn, "live")
    assert judged(conn, lg, "live").judgement.said == "the gateway never saw it stop on its own"


def test_two_weeks_of_the_budget_are_clean_with_no_hour_over_its_ceiling(conn, lg, monkeypatch):
    reached(conn, "budget")
    tv_on(conn, 5)
    monkeypatch.setattr(budget, "report", lambda *a, **k: {"ceiling": 1_465_000, "events": []})
    row = judged(conn, lg, "budget", ceiling="4M")
    assert (row.judgement.clean, row.judgement.said) == (
        True,
        "no hour went over it across 70 on-hours on 14 days: fewer than 1 on-hour in 23 would have been capped",
    )
    events = [{"hour": T0 + 3600}, {"hour": T0 + 3600}, {"hour": T0 + 7200}]
    monkeypatch.setattr(budget, "report", lambda *a, **k: {"ceiling": 1_465_000, "events": events})
    row = judged(conn, lg, "budget", ceiling="4M")
    assert (row.judgement.clean, row.judgement.said) == (False, "2 hours went over it")


def test_two_weeks_of_the_probe_with_no_run_kept_are_never_clean(conn, lg):
    """A store forgotten since, or samples never kept: nothing to judge the two weeks by."""
    reached(conn, "probe")
    row = judged(conn, lg, "probe")
    assert (row.judgement.clean, row.judgement.said) == (None, "the gateway kept no record of its tests")


def quiet_two_weeks(conn, monkeypatch) -> None:
    """Two weeks in which every mechanism counted plenty and nothing happened."""
    db.set_meta(
        conn,
        counting.META_KEY,
        json.dumps({m.key: {"since": T0, "last": T0 + WEEKS + 5 * DAY} for m in counting.MECHANISMS}),
    )
    wakes(conn, 5)
    tv_on(conn, 5)
    snapshots(conn, queries.NTP_SET_ROW, T0, T0 + WEEKS + DAY)
    snapshots(conn, inpath.MISS_RULE, T0, T0 + WEEKS + DAY)
    probe_runs(conn, {T0 + 600 * k: "pass" for k in range(2016)})
    monkeypatch.setattr(budget, "report", lambda *a, **k: {"ceiling": 1_465_000, "events": []})


def test_every_clean_judgement_states_its_exposure_and_the_rate_it_rules_out(conn, lg, monkeypatch):
    quiet_two_weeks(conn, monkeypatch)
    rows = counting.status(conn, T0 + WEEKS + DAY, profile=lg, upload_ceiling="4M")
    clean = {r.key: r.judgement for r in rows if r.judgement.clean}
    assert sorted(clean) == ["budget", "ntp", "probe"]
    for key, j in clean.items():
        assert j.exposure >= 60 and j.days >= 7 and j.bound.startswith(f"fewer than 1 {j.unit} in ")
        assert f": {j.bound} " in j.said, key
    assert all(m.exposure is not None for m in counting.MECHANISMS if m.key in clean)


# ---- judged once ---------------------------------------------------------------------------------------------
def test_a_runs_two_weeks_are_judged_once_kept_after_they_settle_and_read_back(conn, lg, monkeypatch):
    """L6-12: the brief judged the NTP count over its whole run, every time: a run a year old read a year."""
    year = T0 - 365 * DAY
    db.set_meta(conn, counting.META_KEY, json.dumps({"ntp": {"since": year, "last": T0}}))
    spans = []
    real = queries.ntp_servers
    monkeypatch.setattr(queries, "ntp_servers", lambda c, a, b, p: spans.append((a, b)) or real(c, a, b, p))
    counting.status(conn, T0, profile=lg)  # a report judges the two weeks, and keeps nothing
    assert spans == [(year, year + WEEKS)] and "judged" not in counting.load(conn)["ntp"]
    ends = year + WEEKS
    settle = receipt.SETTLE
    db.set_meta(conn, "last_run", repr(ends + settle))  # the hourly ingest has read past them
    counting.status(conn, ends + settle - 1, profile=lg, judge=False, keep=True)  # not settled: not kept
    assert "judged" not in counting.load(conn)["ntp"] and len(spans) == 1
    counting.status(conn, ends + settle - 1, profile=lg, keep=True)  # judged for the report, not kept
    assert "judged" not in counting.load(conn)["ntp"] and len(spans) == 2
    db.set_meta(conn, "last_run", repr(ends + settle - 1))  # an ingest that stopped short: not kept
    counting.status(conn, ends + settle + 600, profile=lg, judge=False, keep=True)
    assert "judged" not in counting.load(conn)["ntp"] and len(spans) == 2
    db.set_meta(conn, "last_run", repr(ends + settle))
    counting.status(conn, ends + settle, profile=lg, judge=False, keep=True)
    kept = counting.load(conn)["ntp"]["judged"]
    assert kept["since"] == year and kept["j"]["found"] == "no snapshot of the count's table"
    rows = by_key(counting.status(conn, T0, profile=lg))
    assert len(spans) == 3 and rows["ntp"].judgement.said == "its record has a hole"
    counting.observe(conn, obs(counters={queries.NTP_SET_ROW}), T0 + 600)  # the run goes on: kept with it
    assert counting.load(conn)["ntp"]["judged"] == kept
    later = T0 + 2 * counting.RUN_GAP
    counting.observe(conn, obs(counters={queries.NTP_SET_ROW}), later)  # a new run: judged again
    assert "judged" not in counting.load(conn)["ntp"]


def test_a_kept_judgement_of_another_run_or_that_this_version_cannot_read_is_judged_again(conn, lg):
    run = {"since": T0, "last": T0 + WEEKS + DAY, "judged": {"since": T0, "j": {"clean": True, "bogus": 1}}}
    stale = {"since": T0 - DAY, "j": {"clean": True, "found": "x", "said": "an earlier run's"}}
    runs = {
        "ntp": run,
        "probe": {**run, "judged": {"since": "x", "j": {"clean": True}}},
        "inpath": {**run, "judged": {"since": T0, "j": 1}},
        "live": {**run, "judged": stale},
    }
    db.set_meta(conn, counting.META_KEY, json.dumps(runs))
    rows = by_key(counting.status(conn, T0 + WEEKS + DAY, profile=lg))
    assert rows["ntp"].judgement.said == "its record has a hole"
    assert rows["live"].judgement.said == "the gateway never saw it stop on its own"
    assert "judged" not in counting.load(conn)["probe"] and "judged" not in counting.load(conn)["inpath"]


def test_a_run_read_from_its_own_record_is_judged_and_keeps_nothing(conn, lg):
    """Before `verify --record` kept a row for it, a run has no row to keep a judgement in."""
    snapshots(conn, queries.NTP_SET_ROW, T0, T0 + WEEKS + DAY)
    db.set_meta(conn, "last_run", repr(T0 + WEEKS + DAY))  # settled and read: it would be kept if it could
    rows = by_key(counting.status(conn, T0 + WEEKS + DAY, profile=lg, keep=True))
    assert (
        rows["ntp"].judgement.found.startswith("0 requests") and db.get_meta(conn, counting.META_KEY) is None
    )


# ---- the words: dates, never a time of day -----------------------------------------------------------------------
def ntp_reached(conn):
    reached(conn, "ntp")
    wakes(conn, 5)
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
    assert (rows["ntp"]["exposure"], rows["ntp"]["unit"], rows["ntp"]["days"], rows["ntp"]["bound"]) == (
        70.0, "start", 14, "fewer than 1 start in 23"
    )  # fmt: skip
    assert counting.engineering_line(rows["ntp"]) == (
        "NTP count (the clock servers the TV asks, inet tvgw_ntp): counting since 2026-11-07; two weeks ended"
        " 2026-11-21: 0 requests; 70 starts on 14 days of 15: fewer than 1 start in 23 (clean)"
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
        "The clock-server count has two clean weeks, since 7 November: the TV asked no time server across 70"
        " starts on 14 days: fewer than 1 start in 23 would have been cut off. So the clock port could be"
        " closed for this TV. Nothing changes unless you decide it."
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
    wakes(conn, 5)
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
        "  Counting: The clock-server count has two clean weeks, since 7 November: the TV asked no time server"
        " across 70 starts on 14 days: fewer than 1 start in 23 would have been cut off. So the clock port could"
        " be closed for this TV. Nothing changes unless you decide it."
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
        "trials off - -",
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


def test_verify_record_keeps_a_settled_runs_judgement_for_good(conn, lg, tmp_path, status_file):
    reached(conn, "ntp", since=T0 - WEEKS - DAY)
    db.set_meta(conn, "last_run", repr(T0 - 600))
    r = verify.Result(checks=[verify.Check("ruleset", True)], t=T0)
    r.counters = [(queries.NTP_SET_ROW, 0, 1024)]
    verify.keep_counting(conn, Settings(state_dir=str(tmp_path)), lg, r)
    other = db.connect(str(tmp_path / "c.db"))  # what a later run reads: the row was committed
    assert counting.load(other)["ntp"]["judged"]["j"]["said"] == "its record has a hole"
    other.close()


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
