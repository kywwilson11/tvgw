"""(trials) The trial record (design decision 98): a keyed coin for each viewing day, committed before the
day begins, and what each app start showed, with nothing refused; the record read alone, judged under
other keys (the A/A), and the forecast."""

import ast
import dataclasses
import json
import os
import random

import pytest
from appfront_store import GW, HDMI, HOME, NF, YT, Store, app, down, power, up

from tvgw import (
    adguardcfg,
    analyst,
    appfront,
    autoblock,
    cli,
    config,
    counting,
    db,
    evidencekit,
    forget,
    minimize,
    trials,
)
from tvgw.config import Settings

DAY = 86400.0
D0 = appfront.viewing_day(1793037600.0)  # the viewing day of 2026-10-26 13:00 CDT
MB = 1024 * 1024
# HMAC-SHA256 under the subkey HMAC-SHA256(bytes 0 to 31, "all"), computed apart from tvgw: the coin of
# days 739910 to 739917 (its first 8 bytes, big-endian, under half of 2^64) and day 739910's commitment
KNOWN_ARMS = [True, True, True, False, False, False, False, False]
KNOWN_COMMIT = "4fc1fff4cb4f78a7"


def evening(day: int, hour: float = 20.0) -> float:
    """`hour` o'clock in the evening of viewing day `day` (hours past midnight are the next date's)."""
    return trials.day_start(day) + (hour - appfront.DAY_START_HOUR) * 3600


@pytest.fixture
def store(tmp_path):
    s = Store(tmp_path / "s.db")
    yield s
    s.conn.close()


@pytest.fixture
def s(tmp_path, store):
    return Settings(state_dir=str(tmp_path), db_path=store.path, gw_ip=GW, trial="record")


OFF = "off"  # a stay the TV ended by switching itself off


def watched(store: Store, t0: float, *stays: tuple, first: str = HOME) -> None:
    """One session to the TV from `t0` with `first` in front, then each stay as (app, seconds, its
    connections as (seconds in, bytes down), what came next: an app, or OFF), one after another; down an
    hour after the last."""
    events, t = [up(t0), power(t0, "Active"), app(t0, first)], t0 + 60
    for app_id, seconds, talks, then in stays:
        events.append(app(t, app_id))
        for offset, got in talks:
            store.talk(t + offset, "www.example.com", down_=got)
        t += seconds
        events.append(power(t, "Active Standby") if then == OFF else app(t, then))
        t += 120
    events.append(down(t + 3600))
    store.conn.executemany(
        "INSERT INTO tv_events(t, kind, value, detail) VALUES (?, ?, ?, ?)",
        [(e.t, e.kind, e.value, e.detail) for e in events],
    )
    store.conn.commit()


def ingested(store: Store, a: float, b: float, warnings: dict[float, list[str]] | None = None) -> None:
    """An hourly ingest run's row for every hour of [a, b), with the warnings given for some."""
    store.conn.executemany(
        "INSERT INTO ingest_runs(t, seconds, stats, warnings) VALUES (?, 1, '{}', ?)",
        [(t, json.dumps((warnings or {}).get(t, []))) for t in range(int(a), int(b), 3600)],
    )
    store.conn.commit()


def hourly(store: Store, s: Settings, a: float, b: float) -> None:
    """The ingest's hourly run of the trial record, every hour of [a, b)."""
    for t in range(int(a), int(b), 3600):
        trials.hourly(store.conn, s, float(t))


def rows(conn, outcome: str | None = None) -> list[dict]:
    got = autoblock.decisions(conn, "stage = ?", (trials.STAGE,))
    return [r for r in got if outcome is None or r["outcome"] == outcome]


# ---- the coin ----------------------------------------------------------------------------------------------------
def test_the_coin_is_fixed_by_its_key_subject_and_day_and_falls_on_each_arm_half_the_time():
    k = bytes(range(32))
    days = range(D0, D0 + 10_000)
    arms = [trials.coin(k, trials.ALL, d) for d in days]
    assert arms == [trials.coin(k, trials.ALL, d) for d in days]
    assert 0.48 <= sum(arms) / len(arms) <= 0.52
    other = [trials.coin(k, "example.org", d) for d in days]
    flipped = [trials.coin(bytes([1]) + k[1:], trials.ALL, d) for d in days]  # one bit of the key
    for arms2 in (other, flipped):
        assert 0.48 <= sum(x == y for x, y in zip(arms, arms2, strict=True)) / len(arms) <= 0.52
    assert trials.coin(k, trials.ALL, D0, share=0.0) is False and trials.coin(k, trials.ALL, D0, share=1.0)


def test_a_commitment_gives_away_no_arm_and_only_its_key_opens_it():
    k = bytes(range(32))
    c = trials.commitment(k, trials.ALL, D0)
    assert len(c) == 16 and int(c, 16) >= 0 and c == trials.commitment(k, trials.ALL, D0)
    assert c != trials.commitment(k, trials.ALL, D0 + 1) and c != trials.commitment(k, "x", D0)
    assert c != trials.commitment(bytes(32), trials.ALL, D0)
    assert trials.fingerprint(k) != trials.fingerprint(bytes(32)) and len(trials.fingerprint(k)) == 4


def test_a_viewing_day_begins_at_five_in_the_morning_through_the_change_of_the_clocks():
    for day in range(D0, D0 + 10):  # the clocks went back on 1 November
        assert appfront.viewing_day(trials.day_start(day)) == day
        assert appfront.viewing_day(trials.day_start(day) - 1) == day - 1


def test_the_key_is_made_once_root_only_and_none_when_it_cannot_be(tmp_path):
    s = Settings(state_dir=str(tmp_path))
    k = trials.key(s)
    path = trials.key_path(s.state_dir)
    assert len(k) == trials.KEY_BYTES and trials.key(s) == k
    assert os.stat(path).st_mode & 0o777 == 0o600 and os.path.dirname(path) == minimize.key_dir(s.state_dir)
    with open(path, "wb") as fh:
        fh.write(b"short")
    assert trials.key(s) is None  # never a short key
    blocked = tmp_path / "file"
    blocked.write_text("x")
    assert trials.key(Settings(state_dir=str(blocked))) is None
    os.remove(path)
    os.mkdir(path)  # a key that cannot be read is not made again
    assert trials.key(s) is None
    locked = tmp_path / "locked"
    os.makedirs(minimize.key_dir(str(locked)), mode=0o500)  # nor one that cannot be written
    assert trials.key(Settings(state_dir=str(locked))) is None


def test_the_coin_and_the_commitment_are_the_published_algorithm():
    """Anyone handed a trial's subkey can redraw its coins and open its commitments: the algorithm is
    fixed, and these are its answers for one key."""
    k = bytes(range(32))
    assert [trials.coin(k, trials.ALL, d) for d in range(739_910, 739_918)] == KNOWN_ARMS
    assert trials.commitment(k, trials.ALL, 739_910) == KNOWN_COMMIT


# ---- drawn before the day, measured after it -----------------------------------------------------------------
def test_each_day_is_drawn_once_before_it_begins_and_never_once_it_has(store, s):
    """A run at any hour draws the next day; a gateway off at 05:00 leaves that day with no coin."""
    rng = random.Random(4)
    t, end = trials.day_start(D0) + 3600, trials.day_start(D0 + 20)
    while t < end:
        trials.hourly(store.conn, s, t)
        t += rng.choice([600, 3600, 3600, 5 * 3600, 30 * 3600])  # a run again soon, hourly, a day off
    drawn = rows(store.conn, "drawn")
    assert len({r["margins"]["day"] for r in drawn}) == len(drawn) > 5
    assert all(r["t"] < trials.day_start(r["margins"]["day"]) for r in drawn)
    assert all(r["t"] >= trials.day_start(r["margins"]["day"] - 1) for r in drawn)  # on the day before
    assert all("arm" not in r["margins"] for r in drawn)


def test_a_run_again_adds_nothing_and_an_outage_draws_nothing_for_the_days_it_missed(store, s):
    trials.hourly(store.conn, s, evening(D0))
    assert trials.hourly(store.conn, s, evening(D0) + 600) == {"drawn": 0, "measured": 0, "unmeasured": 0}
    late = evening(D0 + 3) + trials.receipt.SETTLE
    ingested(store, trials.day_start(D0 + 1), late)
    trials.hourly(store.conn, s, late)  # off from D0's evening to D0 + 3's
    got = {(r["outcome"], r["margins"]["day"]) for r in rows(store.conn)}
    assert ("drawn", D0 + 2) not in got and ("drawn", D0 + 3) not in got and ("drawn", D0 + 4) in got
    assert {r["margins"]["day"]: r["margins"]["why"] for r in rows(store.conn, "unmeasured")} == {
        D0 + 2: "no coin was drawn before it began"
    }  # D0 + 3 has not ended; D0 + 1 was drawn and measured
    assert [r["margins"]["day"] for r in rows(store.conn, "measured")] == [D0 + 1]


def test_without_a_key_nothing_is_drawn_or_measured(store, tmp_path):
    blocked = tmp_path / "file"
    blocked.write_text("x")
    s = Settings(state_dir=str(blocked), gw_ip=GW)
    assert trials.hourly(store.conn, s, evening(D0)) == {"waiting": "the trial key could not be read or made"}
    assert rows(store.conn) == []


def test_a_day_drawn_under_another_key_is_not_measured_under_this_one(store, s):
    """A store restored beside a key made since: its days' commitments open under neither."""
    trials.hourly(store.conn, s, evening(D0))
    os.remove(trials.key_path(s.state_dir))
    ingested(store, evening(D0), evening(D0 + 2))
    trials.hourly(store.conn, s, trials.day_start(D0 + 2) + trials.receipt.SETTLE)
    assert [r["margins"] for r in rows(store.conn, "unmeasured")] == [{"day": D0 + 1, "why": "key changed"}]


def household(store: Store, s: Settings) -> dict[int, dict]:
    """Five viewing days, drawn and run hourly: what each day's starts truly were."""
    hourly(store, s, trials.day_start(D0) + 3600, trials.day_start(D0 + 1))  # draws D0 + 1
    big = [(2, 60 * MB)]
    watched(
        store, evening(D0 + 1), (NF, 1800, big, HOME), (YT, 30, [(2, 10_000)], HOME), (NF, 900, big, HOME)
    )
    watched(store, evening(D0 + 2), (YT, 20, [], HDMI), (NF, 40, [(2, 5_000)], HOME), (YT, 1200, big, HOME))
    watched(
        store,
        evening(D0 + 3),
        ("com.webos.app.settings", 20, [], HOME),  # the TV maker's own: no start
        (NF, 2400, [(2, 80 * MB), (100, 5 * MB)], HOME),  # worked, the first 1 MB 2 s in
        (YT, 600, [(50, 2 * MB)], HOME),  # worked, 50 s in
        (NF, 900, [(2, 10_000)], HOME),  # little down, but too long for a failed start
        (NF, 30, [(2, 5 * MB)], HOME),  # short, but it brought plenty down
        (NF, 30, [], OFF),  # the TV switched off: no start that failed
    )
    watched(store, evening(D0 + 4, 26.5), (NF, 30, [], HOME))  # half past two in the night: D0 + 4's
    watched(store, evening(D0 + 4, 28.5), (NF, 14_400, big, HOME))  # still in front when D0 + 4 ended
    watched(store, evening(D0 + 5), first=NF)  # in front when the session came up: the TV did not report it
    end = trials.day_start(D0 + 6) + trials.receipt.SETTLE + 3600
    ingested(store, trials.day_start(D0 + 1) - 3600, end)
    hourly(store, s, trials.day_start(D0 + 1), end)
    keys = (
        "exposed",
        "analysed",
        "bad",
        "analysed_any",
        "bad_any",
        "bad_all",
        "worked",
        "no_big",
        "delay_med",
    )
    return {
        D0 + 1: dict(zip(keys, (3, 2, 1, 2, 1, 1, 2, 1, 2.0), strict=True)),
        D0 + 2: dict(zip(keys, (3, 2, 1, 1, 1, 1, 1, 2, 2.0), strict=True)),
        D0 + 3: dict(zip(keys, (5, 5, 0, 5, 0, 0, 2, 2, 2.0), strict=True)),  # delays 2, 50, 2: their median
        D0 + 4: dict(zip(keys, (1, 1, 1, 1, 1, 1, 0, 1, None), strict=True)),
        D0 + 5: dict(zip(keys, (0, 0, 0, 0, 0, 0, 0, 0, None), strict=True)),
    }


def test_each_days_starts_are_measured_as_they_were(store, s):
    """A start that left for an input is the wider form only; the TV maker's own apps are no start; each
    form counts the starts up to its first bad one, whatever the arm."""
    truth = household(store, s)
    got = {r["margins"]["day"]: r["margins"] for r in rows(store.conn, "measured")}
    assert sorted(got) == sorted(truth) and len(rows(store.conn, "measured")) == len(truth)  # each once
    for day, want in truth.items():
        assert {k: got[day][k] for k in want} == want, day
        assert got[day]["arm"] == trials.coin(trials.key(s), trials.ALL, day)
    assert (got[D0 + 1]["stay_med"], got[D0 + 3]["stay_med"], got[D0 + 5]["stay_med"]) == (15.0, 10.0, None)
    assert {got[day]["reader"] for day in truth} == {"live"}


def test_a_stay_whose_connections_may_still_be_open_is_not_measured_yet(store):
    watched(store, evening(D0), (NF, 600, [(2, 60 * MB)], HOME))
    a, b, end = trials.day_start(D0), trials.day_start(D0 + 1), evening(D0) + 660
    assert trials.stays(store.conn, GW, a, b, end + trials.receipt.SETTLE - 1) == []
    assert [x.delay for x in trials.stays(store.conn, GW, a, b, end + trials.receipt.SETTLE)] == [2.0]


def test_a_days_reader_is_the_live_reading_else_the_hourly_readings_else_none(store):
    a = trials.day_start(D0)
    store.reading(a + 3600, "Active", NF)
    store.conn.execute("INSERT INTO tv_events(t, kind, value) VALUES (?, 'alive', '')", (a + DAY + 60,))
    readers = [trials._reader(store.conn, a + d * DAY, a + (d + 1) * DAY) for d in range(3)]
    assert readers == ["hourly", "live", "none"]


def test_a_day_waits_until_it_settles_and_a_record_with_a_hole_is_not_measured(store, s):
    trials.hourly(store.conn, s, evening(D0))
    trials.hourly(store.conn, s, evening(D0 + 1))
    lost = trials.day_start(D0 + 2) + 6 * 3600  # in D0 + 2, after D0 + 1 has settled
    ingested(store, evening(D0), evening(D0 + 5), {lost: ["dns: OSError: gone"]})
    end = trials.day_start(D0 + 2)
    assert trials.hourly(store.conn, s, end + trials.receipt.SETTLE - 1)["measured"] == 0
    assert trials.hourly(store.conn, s, end + trials.receipt.SETTLE)["measured"] == 1
    trials.hourly(store.conn, s, end + DAY + trials.receipt.SETTLE)
    assert rows(store.conn, "unmeasured")[-1]["margins"] == {
        "day": D0 + 2, "why": "the record lost lookups or connections"
    }  # fmt: skip
    store.conn.execute(
        "DELETE FROM ingest_runs WHERE t > ? AND t < ?", (end + DAY + 3600, end + DAY + 4 * 3600)
    )
    trials.hourly(store.conn, s, end + 2 * DAY + trials.receipt.SETTLE)
    assert rows(store.conn, "unmeasured")[-1]["margins"] == {
        "day": D0 + 3,
        "why": "the ingest missed part of it",
    }


@pytest.mark.parametrize(
    ("first", "warning", "at", "why"),
    [
        (-3600, "flows: conntrack lost events 2 time(s)", 3600, "the record lost lookups or connections"),
        (-3600, "tvlive: x", 3600, "the record lost lookups or connections"),
        (-3600, "dns: x", 3600, "the record lost lookups or connections"),
        (-3600, "threats: x", 3600, None),
        (-7200, "flows: x", -3600, None),  # the day before's
        (3 * 3600, "", 0, "the ingest missed part of it"),  # it began three hours into the day
    ],
)
def test_a_day_is_whole_only_with_runs_from_its_start_and_no_loss_in_its_sources(
    store, first, warning, at, why
):
    a = trials.day_start(D0)
    ingested(store, a + first, a + 2 * DAY, {a + at: [warning]})
    assert trials._not_whole(store.conn, a, a + DAY, a + DAY + 7200) == why


def test_a_commitment_its_key_does_not_open_is_not_measured(store, s):
    k = trials.key(s)
    margins = {"day": D0 + 1, "unit": "day", "share": 0.5, "commit": "0" * 16, "key": trials.fingerprint(k)}
    autoblock.log_decision(store.conn, trials.STAGE, "drawn", evening(D0), name=trials.ALL, margins=margins)
    ingested(store, evening(D0), evening(D0 + 2))
    trials.hourly(store.conn, s, trials.day_start(D0 + 2) + trials.receipt.SETTLE)
    assert [r["margins"] for r in rows(store.conn, "unmeasured")] == [{"day": D0 + 1, "why": "key changed"}]


# ---- nothing refused, nothing kept that says more -----------------------------------------------------------
def test_the_record_refuses_nothing_and_writes_only_its_rows_and_its_key(store, s, tmp_path, lg):
    tables = [t for (t,) in store.conn.execute("SELECT name FROM sqlite_master WHERE type = 'table'")]
    before = {t: store.conn.execute(f"SELECT COUNT(*) FROM {t}").fetchone()[0] for t in tables}
    files = set(os.listdir(tmp_path))
    household(store, s)
    after = {t: store.conn.execute(f"SELECT COUNT(*) FROM {t}").fetchone()[0] for t in tables}
    changed = {t for t in tables if before[t] != after[t]}
    assert changed - {"tv_events", "tls", "flows", "ingest_runs"} == {"decisions"}
    assert set(os.listdir(tmp_path)) - files == {os.path.basename(minimize.key_dir(s.state_dir))}
    off = Settings(state_dir=s.state_dir, trial="off")
    assert adguardcfg.desired(lg, s, paused=()) == adguardcfg.desired(lg, off, paused=())
    assert "TRIAL" not in config.CHOICES  # tvgw-apply never reads it: no ruleset can differ


def test_the_module_imports_nothing_that_can_change_policy():
    with open(trials.__file__, encoding="utf-8") as fh:
        tree = ast.parse(fh.read())
    names = {a.name for n in ast.walk(tree) if isinstance(n, ast.ImportFrom) for a in n.names}
    names |= {a.name for n in ast.walk(tree) if isinstance(n, ast.Import) for a in n.names}
    assert not names & {"adguardcfg", "analyst", "adguard", "fwpolicy", "guard", "lgwebos", "tvlive", "web"}


def test_a_measured_row_holds_no_time_and_no_app_and_forget_and_the_pack_take_none(store, s, lg):
    household(store, s)
    for r in rows(store.conn, "measured"):
        a, b = trials.day_start(r["margins"]["day"]), trials.day_start(r["margins"]["day"] + 1)
        values = list(r["margins"].values())
        assert not [v for v in values if isinstance(v, int | float) and a - DAY <= v < b + DAY]
        assert not [v for v in values if isinstance(v, str) and v not in ("live", "hourly", "none")]
    assert forget.TABLES["decisions"][0] == forget.FORGET
    assert ("name-keys", forget.FORGET) in {(name, how) for name, how, _why in forget.STATE_ENTRIES}
    a = trials.day_start(D0 + 1)
    text = json.dumps(analyst.pack(store.conn, a, a + 4 * DAY, "x", lg, s))
    assert '"drawn"' not in text and '"measured"' not in text and "commit" not in text


def test_the_record_is_read_from_its_rows_alone(store, s):
    household(store, s)
    days, judged = trials.record(store.conn), trials.aa(trials.record(store.conn), keys=50)
    for table in ("tv_events", "flows", "tls", "dns", "tvstate"):
        store.conn.execute(f"DELETE FROM {table}")
    assert trials.record(store.conn) == days and trials.aa(days, keys=50) == judged
    assert [d.day for d in days] == list(range(D0 + 1, D0 + 6))


# ---- the A/A, the planted break and the forecast -----------------------------------------------------------------
def simulated(
    seed: int, days: int = 120, starts: int = 7, p0: float = 0.03, broken: float = 0.0
) -> list[trials.Day]:
    """A household's record: `starts` app starts a day, each failing with chance p0, and on the days its
    own coin refuses, with chance `broken` as well."""
    rng = random.Random(seed)
    k = rng.randbytes(32)
    out = []
    for d in range(D0, D0 + days):
        arm = trials.coin(k, trials.ALL, d)
        flags = [rng.random() < p0 or (arm and rng.random() < broken) for _ in range(starts)]
        analysed, bad = trials._censored(flags)
        out.append(
            trials.Day(
                trials.ALL,
                d,
                int(arm),
                "live",
                starts,
                analysed,
                bad,
                analysed,
                bad,
                sum(flags),
                0,
                0,
                None,
                None,
            )
        )
    return out


def test_under_other_keys_with_nothing_refused_the_tests_fire_within_their_bounds():
    """The A/A: each key is one more draw of the coins on a record where refusing changed nothing."""
    every = [trials.aa(simulated(seed), keys=100, seed=seed) for seed in range(10)]  # 7 starts a day
    some = [trials.aa(simulated(seed, starts=2), keys=100, seed=seed) for seed in range(10)]
    assert sum(r["harm_rule_fired"] for r in every) / 10 < 0.24  # Wald's bound
    assert sum(r["harm_rule_fired"] for r in some) / 10 < 0.20
    assert sum(r["balance_alarm"] for r in every + some) / 20 < 0.03  # nominal 1%
    got = every
    quiet = trials.aa(simulated(0, p0=0.0), keys=1)["per_start"]  # none failed: bounded by its count alone
    assert (quiet["bad"], quiet["interval"]) == (0, list(evidencekit.wilson(0, quiet["of"])))
    r = got[0]
    lo, hi = r["per_start"]["interval"]
    assert lo < r["per_start"]["share"] < hi and r["per_start"]["of"] == sum(d.analysed for d in simulated(0))


def test_a_planted_break_of_one_start_in_two_fires_the_harm_rule():
    """The positive control, on simulated records only: nothing on a gateway is ever refused."""
    fired = [
        trials.harm(days, [bool(d.arm) for d in days])
        for days in (simulated(s, broken=0.5) for s in range(10))
    ]
    assert sum(fired) >= 8
    assert not any(
        trials.harm(d, [bool(x.arm) for x in d]) for d in (simulated(s, p0=0.0) for s in range(10))
    )


@pytest.mark.parametrize(("bad", "arms", "fired"), [
    ([1, 1, 1], [1, 1, 1], True), ([1, 1, 1, 1], [1, 1, 0, 1], False),
    ([1, 1, 1, 0, 1, 1, 1], [1, 1, 0, 1, 1, 1, 1], True),
    ([0, 0, 0], [1, 1, 1], False),
])  # fmt: skip
def test_the_harm_rule_is_three_refused_bad_days_clear_of_twice_the_others(bad, arms, fired):
    days = [
        trials.Day(trials.ALL, D0 + i, a, "live", 1, 1, b, 1, b, b, 0, 0, None, None)
        for i, (b, a) in enumerate(zip(bad, arms, strict=True))
    ]
    assert trials.harm(days, [bool(a) for a in arms]) is fired


def test_the_balance_alarm_rings_only_when_the_exposed_days_are_lopsided():
    days = [trials.Day(trials.ALL, D0 + i, 1, "live", 1, 1, 0, 1, 0, 0, 0, 0, None, None) for i in range(20)]
    alternate = [i % 2 == 0 for i in range(20)]
    assert trials.unbalanced(days, [True] * 20) and trials.unbalanced(days, [False] * 20)
    assert not trials.unbalanced(days, alternate)
    idle = [trials.Day(trials.ALL, D0 + 20 + i, 1, "none", *[0] * 8, None, None) for i in range(20)]
    assert not trials.unbalanced(days + idle, alternate + [True] * 20)  # a day with no start weighs nothing
    assert not trials.unbalanced(days[:1], [True]) and not trials.unbalanced([], [])


def test_the_aa_says_how_the_failures_cluster_on_their_days():
    """Two failed starts on one day and one on another: one of three fell on a day that had one already."""
    days = [
        trials.Day(trials.ALL, D0, 1, "live", 4, 2, 1, 2, 1, 2, 2, 0, 3.0, 9.0),
        trials.Day(trials.ALL, D0 + 1, 0, "live", 3, 1, 1, 1, 1, 1, 2, 0, 3.0, 9.0),
        trials.Day(trials.ALL, D0 + 2, 1, "live", 5, 5, 0, 5, 0, 0, 5, 0, 3.0, 9.0),
    ]
    r = trials.aa(days, keys=10)
    assert (r["clustered"], r["per_start"]["bad"], r["per_start"]["of"], r["per_day"]["bad"]) == (
        1 / 3,
        2,
        8,
        2,
    )
    assert trials.aa(days[2:], keys=10)["clustered"] is None


def test_the_forecast_needs_59_refused_starts_for_1_in_20_and_77_for_the_first_look():
    f = trials.forecast(simulated(0, days=28, starts=4))
    assert (f["refused_starts"], f["first_look"], f["refused_starts_a_day"]) == (59, 77, 2.0)
    assert (f["days"], f["days_to_first_look"]) == (30, 39)
    assert (
        trials.forecast([])["days"] is None
        and trials.forecast(simulated(0), bar=1 / 10)["refused_starts"] == 29
    )


# ---- the commands, the setting, the ingest and the brief ---------------------------------------------------
def test_the_command_says_what_is_recorded_and_never_an_arm(store, s, capsys, tmp_path):
    household(store, s)
    lines = trials.status_lines(store.conn, "record")
    assert lines[0].endswith("Nothing is refused.") and lines[1] == "Days drawn 7, measured 5."
    assert "arm" not in " ".join(lines).lower().replace("harm", "")
    assert trials.status_lines(db.connect(str(tmp_path / "e.db")), "off")[1] == "Nothing has been recorded."
    conf = tmp_path / "tvgw.conf"
    conf.write_text(f"DB_PATH={store.path}\nSTATE_DIR={tmp_path}\nTRIAL=record\n")
    assert cli.main(["--conf", str(conf), "trial", "aa", "--keys", "20", "--json"]) == 0
    assert json.loads(capsys.readouterr().out)["days"] == 5
    assert cli.main(["--conf", str(conf), "trial"]) == 0
    assert capsys.readouterr().out.splitlines()[0] == lines[0]
    assert cli.main(["--conf", str(conf), "trial", "aa", "--keys", "0"]) == 2


@pytest.mark.parametrize(("value", "error"), [
    ("off", None), ("record", None), ("one", "its stage has not landed"), ("several", "its stage has not landed"),
    ("on", "expected one of off, record"),
])  # fmt: skip
def test_the_setting_is_off_or_record_and_a_later_stage_is_refused(tmp_path, value, error):
    conf = tmp_path / "tvgw.conf"
    conf.write_text(f"TRIAL={value}\n")
    if error is None:
        assert config.load(str(conf)).trial == value
    else:
        with pytest.raises(ValueError, match=error):
            config.load(str(conf))
    assert Settings().trial == "off"


def test_the_brief_counts_the_record_says_nothing_is_refused_and_names_nothing(store, s, lg):
    household(store, s)
    now = trials.day_start(D0 + 6) + trials.receipt.SETTLE
    counting.observe(store.conn, counting.Observation(s), now)
    rows = {r.key: r for r in counting.status(store.conn, now, profile=lg)}
    first = rows["trials"]
    assert (first.state, first.since) == ("counting", rows["trials"].since)
    assert first.since == autoblock.decisions(store.conn, "stage = 'trial'")[0]["t"]  # its own record
    m = next(m for m in counting.MECHANISMS if m.key == "trials")
    j = counting.judge(m, store.conn, trials.day_start(D0), now, lg, "auto")
    assert j.clean is None and j.found == "5 days measured, 12 app starts, 3 days with a failed start"
    later = counting.judge(m, store.conn, trials.day_start(D0 + 3), now, lg, "auto")  # its own two weeks
    assert later.found == "3 days measured, 6 app starts, 1 day with a failed start"
    line = counting.plain_line(
        {"key": "trials", "plain": m.plain, "since": "2026-10-27", "said": j.said}, now
    )
    assert (
        "5 days were recorded and nothing was refused" in line
        and "example" not in line
        and "netflix" not in line.lower()
    )
    assert m.setting == "TRIAL=record" and not m.active(counting.Observation(Settings()))


def test_the_ingest_runs_the_record_only_with_trial_record_and_a_failure_is_one_warning(
    gateway, lg, monkeypatch
):
    from conftest import fake_extract, fake_oddport

    from tvgw import ingest

    called = []
    monkeypatch.setattr(trials, "hourly", lambda conn, s, now: called.append(s.trial) or {})

    def run(trial: str):
        s = dataclasses.replace(gateway, trial=trial)
        return ingest.run(
            s, lg, extract=fake_extract, oddport_lines=fake_oddport, gate_lines=lambda t: [], lock=False
        )

    run("off")
    assert called == []
    assert not [w for w in run("record").warnings if w.startswith("trials")] and called == ["record"]
    monkeypatch.setattr(trials, "hourly", lambda conn, s, now: 1 / 0)
    assert "trials: ZeroDivisionError: division by zero" in run("record").warnings
