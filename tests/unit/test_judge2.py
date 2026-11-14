"""(ledger) Judge v2 in shadow and the placebo calibration (design decision 48), on synthetic stores."""

import json
import os

import pytest
from hypothesis import given, settings
from hypothesis import strategies as st
from ledger_store import APP, CDN, H0, HDMI, HOUR, Synth

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


@pytest.mark.parametrize(
    ("name", "reason"),
    [
        ("us.lgtvsdp.com", "a must-allow name was blocked after this rule"),
        ("kr.lgtvsdp.com", "clock lookups were blocked after this rule"),  # a clock host of another country
    ],
)
def test_hard_red_lines_revert_in_any_hour(synth, lg, name, reason):
    """(exposure) The kernel never disagrees with a red line: it reverts with v2, whatever the rule did."""
    synth.conn.execute("INSERT INTO dns(t, qname, qtype, blocked) VALUES (?, ?, 'A', 1)", (ADDED + 60, name))
    synth.conn.commit()
    got = v(synth, lg, ADDED + HOUR)
    assert (got.verdict, got.reason) == ("reverted", reason)
    k = judge2.kernel_verdict(synth.conn, lg, RULE, ADDED + HOUR)
    assert (k.verdict, k.reason, k.final) == ("reverted", reason, True)


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
    assert json.loads(first[0]["kernel"])["verdict"] == "watching"
    assert again[0]["hour"] == first[0]["hour"] == day3(19)
    assert synth.conn.execute("SELECT COUNT(*) FROM judge_shadow").fetchone()[0] == 1
    judge2.shadow(synth.conn, lg, now=now + HOUR)
    assert synth.conn.execute("SELECT COUNT(*) FROM judge_shadow").fetchone()[0] == 2
    assert autoblock.rows(synth.conn)[0]["verdict"] is None  # nothing was decided


def test_shadow_follows_a_rule_the_shipped_judge_passed_until_v2_and_the_kernel_are_final(synth, lg):
    """(exposure) A rule that never refused a lookup is never final for the kernel short of its ceiling, so
    the shadow follows it after v2 has passed it."""
    insert_rule(synth.conn, "passed", ADDED + DAY)
    now = ADDED + DAY + 3 * HOUR
    out = judge2.shadow(synth.conn, lg, now=now)
    assert [(r["v1"], r["v2"], r["final"]) for r in out] == [("passed", "nodata", 0)]
    for h in range(17, 23):
        synth.stream(H0 + 4 * DAY + h * HOUR)
    out = judge2.shadow(synth.conn, lg, now=H0 + 5 * DAY)
    assert [(r["v2"], r["final"], json.loads(r["kernel"])["verdict"]) for r in out] == [
        ("passed", 1, "nodata")
    ]
    assert [r["v2"] for r in judge2.shadow(synth.conn, lg, now=H0 + 5 * DAY + HOUR)] == ["passed"]
    assert judge2.shadow(synth.conn, lg, now=ADDED + judge2.CEILING + HOUR) == []  # past the ceiling


@pytest.mark.parametrize(
    ("v2_final", "kernel", "followed"),
    [
        (0, None, True),
        (1, None, True),
        (1, '{"final": false}', True),
        (0, '{"final": true}', True),
        (1, '{"final": true}', False),
    ],
)
def test_a_passed_rule_is_followed_while_either_verdict_can_change(synth, v2_final, kernel, followed):
    """A row written before the kernel was (no `kernel`) is a kernel verdict still to come."""
    insert_rule(synth.conn, "passed", ADDED + DAY)
    synth.conn.execute(
        "INSERT INTO judge_shadow(t, rule, added_t, hour, v2, final, kernel) VALUES (0, ?, ?, 0, 'x', ?, ?)",
        (RULE["rule"], ADDED, v2_final, kernel),
    )
    assert bool(judge2.rows_to_shadow(synth.conn, ADDED + 2 * DAY)) is followed


# ---- the exposure-gated verdict (design decision 99) ------------------------------------------------------
YT = "youtube.leanback.v4"
EXTRA_APP = "com.example.tv"  # a third app, for a name's shape


def kernel(store, now, row=RULE, prof=None):
    from tvgw import profile

    return judge2.kernel_verdict(store.conn, prof or profile.load("lg-webos"), row, now)


def refuse(store, *ts, rule=RULE["rule"], name="t.example"):
    """The rule's own refusals of `name` at each time, as AdGuard logs a custom rule's."""
    store.conn.executemany(
        "INSERT INTO dns(t, qname, qtype, blocked, rule, filter_id) VALUES (?, ?, 'A', 1, ?, 0)",
        [(t, name, rule) for t in ts],
    )
    store.conn.commit()


def live(store, *stays):
    """The live reading's record of one evening: each (app, from, to) in front, the home screen between."""
    first, last = stays[0][1] - 300, stays[-1][2] + 300
    rows = [(first, "conn", "up"), (first, "power", "Active"), (first, "app", "com.webos.app.home")]
    for app, a, b in stays:
        rows += [(a, "app", app), (b, "app", "com.webos.app.home")]
    store.conn.executemany(
        "INSERT INTO tv_events(t, kind, value, detail) VALUES (?, ?, ?, '')", [*rows, (last, "conn", "down")]
    )
    store.conn.commit()


def used_before(store, *ats):
    """The rule's name used at each time before the block: a connection with its hello, so its shape
    holds the app the hour's reading had in front."""
    for t in ats:
        store.sport += 1
        store.conn.execute(
            "INSERT INTO tls(t, dst, dport, sport, sni) VALUES (?, '203.0.113.7', 443, ?, 't.example')",
            (t, store.sport),
        )
        store.conn.execute(
            "INSERT INTO flows(t_start, t_end, proto, dst, dport, sport, bytes_up, bytes_down) VALUES"
            " (?, ?, 'tcp', '203.0.113.7', 443, ?, 700, 300)",
            (t, t + 3, store.sport),
        )
    store.conn.commit()


@pytest.fixture()
def watched(synth):
    """The three evenings before the block, each a live session of the app in front: its picture."""
    for d in range(3):
        live(synth, (APP, H0 + d * DAY + 18 * HOUR, H0 + d * DAY + 22 * HOUR))
    return synth


def test_a_rule_that_never_refused_a_lookup_never_passes_however_well_the_tv_streams(synth, lg):
    """(exposure) The shipped judge and v2 pass a rule on six good evening hours whether or not it ever
    refused a lookup; the kernel extends it to the ceiling, then leaves it untested."""
    for h in range(17, 23):
        synth.stream(day3(h))
    end = ADDED + DAY + 60
    assert autoblock.judge(synth.conn, lg, RULE, end)[0] == "passed" and v(synth, lg, end).verdict == "passed"
    got = kernel(synth, end)
    assert (got.verdict, got.final, got.hours, got.exposure) == ("nodata", False, 0, 0)
    assert got.reason == "extend: 0 of 2 hours with demand in which this rule refused a lookup"
    ceiling = ADDED + autoblock.TRIAL_CEILING
    for t in (ceiling + 18 * HOUR, ceiling + 19 * HOUR):  # past the ceiling, nothing counts any more
        synth.stream(t)
        refuse(synth, t + 900)
    late = kernel(synth, ceiling + DAY)
    assert (late.verdict, late.final) == ("untested", True) and late.reason.startswith(
        "ceiling reached with 0"
    )
    blind = kernel(
        synth, H0 + DAY + 60, {**RULE, "added_t": H0, "trial_until": H0 + DAY}
    )  # nothing before it
    assert (blind.verdict, blind.final) == ("untested", False) and blind.reason == (
        "0 TV hour(s) with demand in the 3 days before the block: nothing to compare a trial with"
    )


def test_it_passes_on_hours_it_refused_in_with_every_app_of_its_name_in_front_and_is_final_when_they_worked(
    watched, lg
):
    used_before(watched, *(H0 + d * DAY + h * HOUR + 600 for d, h in ((1, 18), (2, 20), (2, 23))))
    watched.reading(H0 + 2 * DAY + 20 * HOUR, "Active", EXTRA_APP)  # the name was used under two apps...
    watched.reading(H0 + 2 * DAY + 23 * HOUR, "Active", "com.webos.app.home")  # ...and the launcher
    for h in (18, 19):
        watched.stream(day3(h))
    refuse(watched, day3(18) + 900)
    live(watched, (APP, day3(18), day3(20)))
    end = ADDED + DAY + 60
    one = kernel(watched, end)
    assert (one.verdict, one.hours, one.apps_needed, one.apps_seen) == ("nodata", 1, [EXTRA_APP, APP], [APP])
    refuse(watched, day3(19) + 900)
    two = kernel(watched, end)
    assert two.reason == "extend: 1 of 2 apps of its name not yet in front" and two.hours == 2
    watched.reading(day3(20), "Active", EXTRA_APP)  # in front for an hour with demand, nothing downloaded
    got = kernel(watched, end)
    assert (got.verdict, got.final, got.apps_seen, got.events) == ("passed", False, [EXTRA_APP, APP], 0)
    assert got.reason == (
        "refused lookups in 2 TV hours with demand, streaming at 67% of the days before; 1 of 2 apps of its"
        " name worked since"
    )
    assert json.loads(got.as_json())["unit"] == "starts" and got.exposure == 1
    assert kernel(watched, ADDED + autoblock.TRIAL_CEILING + 60).final  # the watch for harm ends there
    watched.stream(day3(21), app=EXTRA_APP)
    live(watched, (EXTRA_APP, day3(21), day3(22)))
    assert kernel(watched, end).final  # every app of its name has worked since: no later hour changes it


@pytest.mark.parametrize(
    ("name", "want"),
    [("t.example", ("reverted", True, 1, 1)), ("pubads.g.doubleclick.net", ("nodata", False, 0, 0))],
)
def test_a_rule_that_breaks_an_app_is_reverted_at_its_first_failed_start_though_streaming_held(
    watched, lg, name, want
):
    """(exposure) The app the rule breaks fails twice at once, the rule's refusals in those seconds, and the
    evening goes on in another app: the shipped judge passes the rule on the volume of that evening. A known
    tracker's refusal is never a likely cause, being refused on purpose, so a rule on one is not blamed."""
    row = {**RULE, "rule": f"||{name}^", "name": name}
    live(
        watched,
        (APP, day3(18), day3(18) + 20),
        (APP, day3(18) + 60, day3(18) + 75),
        (YT, day3(18) + 300, day3(22)),
    )
    refuse(watched, day3(18) + 2, day3(18) + 62, rule=row["rule"], name=name)
    for h in range(18, 22):
        watched.stream(day3(h), app=YT)
    end = ADDED + DAY + 60
    assert autoblock.judge(watched.conn, lg, row, end)[0] == "passed"
    got = kernel(watched, end, row)
    assert (got.verdict, got.final, got.events, got.exposure) == want
    if got.events:
        assert got.reason == "1 app start failed with this rule's refusals in its minutes"
    assert kernel(watched, end, {**RULE, "rule": "||u.example^"}).verdict == "nodata"  # nor another rule


@pytest.mark.parametrize(("mbytes", "want"), [(40.0, ("passed", "100%")), (15.0, ("reverted", "38%"))])
def test_at_the_trials_end_its_hours_are_held_to_the_shipped_judges_volume_test(synth, mbytes, want):
    """No hour is low enough to start a run at 15 MB against 40, but the trial is under half the days before."""
    for h in (18, 19):
        synth.stream(day3(h), mbytes=mbytes)
        refuse(synth, day3(h) + 900)
    got = kernel(synth, ADDED + DAY + 60)
    assert (got.verdict, got.hours, got.final) == (
        want[0],
        2,
        True,
    ) and f" {want[1]} of the days before" in got.reason


def test_volume_reverts_only_once_the_rule_has_refused_a_lookup(synth, lg):
    """Two low hours with demand: the shipped judge reverts whatever the rule did; the kernel only when the
    rule had refused a lookup by the end of the run."""
    synth.stream(day3(18), mbytes=1.0)
    synth.stream(day3(19), mbytes=1.0)
    now = day3(20) + 60
    assert autoblock.judge(synth.conn, lg, RULE, now)[0] == "reverted"
    assert kernel(synth, now).verdict == "watching"  # nothing refused yet
    refuse(synth, day3(20) + 30)  # after the run
    assert kernel(synth, day3(21) + 60).verdict == "watching"
    refuse(synth, day3(19) + 30)
    got = kernel(synth, now)
    assert (got.verdict, got.final) == ("reverted", True)
    assert got.reason == (
        "streaming volume fell to 2% and 2% of the days before in 2 TV hours running with demand, after this"
        " rule had refused a lookup"
    )


def test_on_a_tv_without_readings_a_block_that_stops_every_lookup_is_reverted_within_two_hours(synth):
    """(exposure) generic-tv: no reading ever, so the shipped judge has no hour with demand and keeps a rule
    that stopped everything, untested. The kernel takes the TV's awake hours from its connections, and
    reverts on its allowed lookups collapsing while the rule refuses more."""
    from tvgw import profile

    gen = profile.load("generic-tv")
    synth.conn.execute("DELETE FROM tvstate")
    synth.conn.commit()
    row = {**RULE, "rule": "||*^"}
    refuse(synth, day3(5) + 60, rule="||*^", name="cdn.example")  # once, at dawn: not a run
    assert autoblock.demand_hours(synth.conn, gen, ADDED - 3 * DAY, ADDED) == set()
    assert len(autoblock.demand_hours(synth.conn, gen, ADDED - 3 * DAY, ADDED, unread=True)) == 12
    refuse(synth, *(day3(h) + 60 * i for h in (18, 19) for i in range(5)), rule="||*^", name="cdn.example")
    assert kernel(synth, day3(19) + 60, row, gen).verdict == "watching"
    got = kernel(synth, day3(20) + 60, row, gen)
    assert (got.verdict, got.final) == ("reverted", True)
    assert got.reason == (
        "the TV's allowed lookups fell to 0% and 0% of the days before in 2 hours running while this rule"
        " refused more"
    )
    assert autoblock.judge(synth.conn, gen, row, ADDED + DAY + 60)[0] == "untested"


def test_on_a_tv_without_readings_two_low_hours_after_the_rule_refused_revert(synth):
    """(exposure) The hours the TV opened its streaming connections in are its hours with demand, before the
    block and after: two of them at a fortieth of the days before, the rule refusing meanwhile, revert."""
    from tvgw import profile

    synth.stream(day3(18), mbytes=1.0)
    synth.stream(day3(19), mbytes=1.0)
    synth.conn.execute("DELETE FROM tvstate")
    refuse(synth, day3(18) + 900)
    got = kernel(synth, day3(20) + 60, RULE, profile.load("generic-tv"))
    assert got.verdict == "reverted" and got.reason.startswith(
        "streaming volume fell to 2% and 2% of the days"
    )
    assert kernel(synth, day3(20) + 60).verdict == "watching"  # the same store read as a TV with a reader's


@pytest.mark.parametrize(
    ("allowed", "refused", "others", "cut"),
    [
        ((1, 1), (1, 1), 0, True),  # a twentieth of the days before's mean, the rule refusing: a cut
        ((2, 0), (1, 1), 0, False),  # a tenth is not under a tenth
        ((0, 0), (0, 1), 0, False),  # nothing refused in the first hour either: a TV that is off
        ((0, 5), (1, 1), 0, False),  # one hour is not a run
        ((0, 0), (0, 0), 9, False),  # other rules' refusals are not this rule's
    ],
)
def test_the_lookups_cut_is_two_hours_under_a_tenth_with_the_rules_refusals_up(
    synth, allowed, refused, others, cut
):
    """One of the 3 days before the block holds all their lookups, 60 an hour: their mean is 20 an hour."""
    synth.conn.execute("DELETE FROM dns")
    synth.conn.executemany(
        "INSERT INTO dns(t, qname, qtype, blocked) VALUES (?, 'cdn.example', 'A', 0)",
        [(ADDED - 2 * DAY + i * 60,) for i in range(1440)],
    )
    for h, ok, own in zip((18, 19), allowed, refused, strict=True):
        synth.conn.executemany(
            "INSERT INTO dns(t, qname, qtype, blocked) VALUES (?, 'cdn.example', 'A', 0)",
            [(day3(h) + 1,)] * ok,
        )
        refuse(synth, *[day3(h) + 2] * own)
        refuse(synth, *[day3(h) + 3] * others, rule="||other.example^")
    got = judge2._lookups_cut(synth.conn, RULE["rule"], ADDED, day3(20) + 60)
    assert got == ([(int(day3(18) // HOUR), 0.05), (int(day3(19) // HOUR), 0.05)] if cut else [])
    assert judge2._lookups_cut(synth.conn, RULE["rule"], day3(19) + 1800, day3(21) + 60) == []  # before it


@pytest.mark.parametrize(
    ("name", "read"), [("lg-webos", True), ("samsung-tizen", True), ("generic-tv", False), ("roku", False)]
)
def test_a_tv_is_read_when_the_hourly_reading_has_a_reader_for_its_profile(name, read):
    from tvgw import profile

    assert judge2._read(profile.load(name)) is read


@settings(max_examples=25, deadline=None)
@given(
    evenings=st.lists(st.tuples(st.integers(0, 6), st.integers(17, 23), st.sampled_from([0.5, 5.0, 40.0]))),
    fired=st.booleans(),
    after=st.integers(1, 13),
)
def test_with_no_hour_of_demand_and_refusal_the_kernel_never_passes(tmp_path_factory, evenings, fired, after):
    """Any evenings after the block, and the rule refusing nothing or only at night with the TV off: never
    passed, and with nothing refused never reverted either."""
    x = Synth(str(tmp_path_factory.mktemp("k") / "k.db"))
    for d in range(3):
        for h in EVENING:
            x.stream(H0 + d * DAY + h * HOUR)
    for d, h, mb in evenings:
        x.stream(H0 + (3 + d) * DAY + h * HOUR, mbytes=mb)
    if fired:
        refuse(x, *(H0 + d * DAY + 3 * HOUR for d in range(4, 10)))
    got = kernel(x, ADDED + after * DAY)
    assert got.verdict != "passed" and got.hours == 0
    assert fired or got.verdict != "reverted"
    x.close()


def test_a_kernel_that_fails_costs_v2_nothing(synth, lg, monkeypatch):
    insert_rule(synth.conn)
    monkeypatch.setattr(judge2, "kernel_verdict", lambda *a: 1 / 0)
    (row,) = judge2.shadow(synth.conn, lg, now=ADDED + 5 * HOUR)
    assert row["v2"] == "watching"
    assert json.loads(row["kernel"]) == {"verdict": "error", "reason": "ZeroDivisionError: division by zero", "final": False}  # fmt: skip


def test_a_schema_17_store_gains_the_kernel_column_and_keeps_its_rows(tmp_path):
    path = str(tmp_path / "old.db")
    conn = db.connect(path)
    conn.execute("ALTER TABLE judge_shadow DROP COLUMN kernel")
    conn.execute(
        "INSERT INTO judge_shadow(t, rule, added_t, hour, v2) VALUES (1, '||t.example^', 0, 0, 'nodata')"
    )
    conn.execute("UPDATE meta SET value = '17' WHERE key = 'schema'")
    conn.commit()
    conn.close()
    conn = db.connect(path)
    assert conn.execute("SELECT v2, kernel FROM judge_shadow").fetchall() == [("nodata", None)]
    assert db.get_meta(conn, "schema") == str(db.SCHEMA_VERSION) and db.SCHEMA_VERSION >= 18
    conn.close()


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
    assert r["trials"] == 4 * 24 - 23
    a, b, c = (r["arms"][x] for x in "ABC")
    assert a["alpha"] == 0 and a["revert_hour_no_demand"] == 0 and a["blind_pass"] == 0
    assert b["alpha"] == 0 and c["alpha"] == 0 and c["suspended"] == 0
    assert a["power"] > 0 and c["power"] > 0  # a real 70% collapse is still caught
    assert r["hour_classes"]["no_demand"] == 4 and r["hour_classes"]["clean"] == 16
    assert len(r["hours"]) == 4 * 24 and r["reverting_hour_classes"]["A"] == {}
    d = r["arms"]["D"]  # judge v2 with the shadow's end-time bytes
    assert d["alpha"] == 0 and d["suspended"] == 0 and d["power"] > 0
    assert judge2.summary_lines(r)[-1] == (
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
    assert lines[-1].startswith("bytes: A end-time (")
    assert judge2.parse_arms("a, c,A") == ("A", "C") and judge2.parse_arms("D") == ("D",)
    with pytest.raises(ValueError):
        judge2.parse_arms("A,E")
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
