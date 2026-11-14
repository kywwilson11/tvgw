"""(did it work) Failed app starts from the live record and the hourly readings, joined with what the gateway
refused in the same minutes, and the probation hook `didit.since` (design decision 72). Only an app the
gateway has seen working is judged; every line that names an app, a time or a name is the interactive
run's; what a persisted report may carry is counts."""

import io
import json
import random
import re
import sqlite3
import time

import pytest
from appfront_store import GW, HOME, NF, YT, Store, app, down, evening, power, up

from tvgw import appfront, cli, didit, plain, queries, receipt

T = evening(3, 20.0) + 14 * 60  # 20:14 on the store's fourth evening
LATER = T + 86400  # a day after: every byte has settled
SETTINGS = "com.palm.app.settings"
NEW_APP = "com.peacock.tv"  # never seen working: no picture


def worked_before(store, app_id: str, site: str, hour: float) -> None:
    """Two earlier evenings on which `app_id` was in front between two hourly readings and brought video
    down from `site`: its picture, as the gateway learns it."""
    for d in (1, 2):
        store.reading(evening(d, hour), "Active", app_id)
        store.reading(evening(d, hour + 0.5), "Active", app_id)
        store.talk(evening(d, hour + 0.2), site, down_=50 * 1024 * 1024)


@pytest.fixture
def store(tmp_path):
    s = Store(tmp_path / "s.db")
    worked_before(s, NF, "nflxvideo.net", 21.0)
    worked_before(s, YT, "googlevideo.com", 22.0)
    return s


def opened(t0: float, *stays: tuple[str, float, float]) -> list:
    """A session to the TV from `t0`, the home screen in front, then each (app, at, seconds): the app came to
    the front at `at` and the TV went back to the home screen `seconds` later. Down two hours on."""
    out = [up(t0), power(t0, "Active"), app(t0, HOME)]
    for app_id, at, seconds in stays:
        out += [app(at, app_id), app(at + seconds, HOME)]
    return [*out, down(t0 + 7200)]


def timeline(store, events, a, b):
    back = a - didit.LIVE_LOOKBACK
    return appfront.timeline(events, appfront.readings(store.conn, back, b), back, b)


def found(store, lg, events, a=None, b=None, now=LATER, ev=None, extra=()):
    a = T - 3600 if a is None else a
    b = T + 3600 if b is None else b
    tl = timeline(store, events, a, b)
    conns = appfront.connections(store.conn, a, b, GW)
    return didit.find(store.conn, lg, tl, conns, a, b, now, ev=ev, extra=extra)


# ---- on timing alone -------------------------------------------------------------------------------------------
def test_an_app_that_went_back_home_three_times_in_a_minute_is_a_failed_start(store, lg):
    events = opened(T - 600, (NF, T, 15), (NF, T + 40, 12), (NF, T + 80, 18))
    store.talk(T + 2, "netflix.com", down_=40_000)
    (f,) = found(store, lg, events)
    assert (f.app, f.timed, f.kind, f.times, f.longest, f.down, f.fresh) == (
        NF,
        "live",
        "quick",
        3,
        18,
        40_000,
        True,
    )
    assert (f.start, f.end, f.causes, f.likely, f.reported) == (T, T + 98, [], [], True)
    assert didit.describe(f) == (
        "Netflix opened 3 times from 20:14, and each time the TV went back to the home screen within 18"
        " seconds (39.1 KB down); the gateway refused nothing in those minutes"
    )


def test_one_quick_exit_with_nothing_refused_is_a_person_changing_their_mind(store, lg):
    assert found(store, lg, opened(T - 600, (NF, T, 15))) == []
    store.lookup(T + 3, "pubads.g.doubleclick.net", blocked=1)  # a tracker, refused on purpose
    assert found(store, lg, opened(T - 600, (NF, T, 15))) == []


def test_exits_further_apart_than_the_cluster_are_two_episodes(store, lg):
    gap = didit.CLUSTER + 60
    assert found(store, lg, opened(T - 600, (NF, T, 15), (NF, T + 15 + gap, 15))) == []
    (f,) = found(store, lg, opened(T - 600, (NF, T, 15), (NF, T + 15 + didit.CLUSTER - 1, 15)))
    assert f.times == 2


def test_a_start_that_then_stayed_says_so(store, lg):
    events = opened(T - 600, (NF, T, 10), (NF, T + 30, 10), (NF, T + 60, 1800))
    (f,) = found(store, lg, events)
    assert (f.times, f.then_stayed) == (2, True)
    assert "; the next time it stayed in front;" in didit.describe(f)


def test_only_a_return_to_the_home_screen_counts(store, lg):
    """Another app, standby or a lost session is a choice or the gateway's own blind spot, never a failure."""
    other = [up(T - 600), power(T - 600, "Active"), app(T - 600, HOME)]
    other += [app(T, NF), app(T + 10, YT), app(T + 20, NF), app(T + 30, YT), down(T + 7200)]
    assert found(store, lg, other) == []
    standby = [up(T - 600), power(T - 600, "Active"), app(T - 600, HOME), app(T, NF)]
    standby += [power(T + 10, "Active", "Request Power Off"), down(T + 20)]
    assert found(store, lg, standby) == []
    lost = [up(T - 600), power(T - 600, "Active"), app(T - 600, HOME), app(T, NF), down(T + 10)]
    lost += [up(T + 30), power(T + 30, "Active"), app(T + 30, HOME), app(T + 40, NF), down(T + 50)]
    assert found(store, lg, lost) == []


def test_a_start_the_gateway_did_not_see_begin_is_not_counted(store, lg):
    """The first app a session to the TV reports was already in front: its start is not a start."""
    events = []
    for k in range(3):
        t = T + 100 * k
        events += [up(t), power(t, "Active"), app(t, NF), app(t + 10, HOME), down(t + 20)]
    assert found(store, lg, events) == []


def test_a_tv_that_woke_with_the_app_in_front_did_not_start_it(store, lg):
    """A wake brings back the app that was in front at standby: the TV reports it exactly, and it is no
    start, however soon the TV goes to the home screen."""
    events = [up(T - 600), power(T - 600, "Active"), app(T - 600, NF)]
    for k in range(3):
        t = T + 100 * k
        events += [power(t, "Active Standby"), power(t + 30, "Active"), app(t + 40, HOME), app(t + 50, NF)]
    events.append(down(T + 7200))
    tl = timeline(store, events, T - 3600, T + 3600)
    assert [s.began for s in tl.sessions if s.app == NF and s.timed == "live"][:2] == ["connect", "wake"]
    assert found(store, lg, events) == []


def test_an_input_or_the_home_screen_is_never_a_failed_start(store, lg):
    events = opened(T - 600, ("com.webos.app.hdmi1", T, 10), ("com.webos.app.hdmi1", T + 30, 10))
    assert found(store, lg, events) == []


def test_a_quick_exit_that_brought_much_down_worked(store, lg):
    store.talk(T + 1, "nflxvideo.net", down_=5 * 1024 * 1024)
    events = opened(T - 600, (NF, T, 15), (NF, T + 40, 15))
    tl = timeline(store, events, T - 3600, T + 3600)
    conns = appfront.connections(store.conn, T - 3600, T + 3600, GW)
    (e,), pending = didit.episodes(tl, conns, T - 3600, T + 3600, LATER)
    assert (e.start, e.times, pending) == (T + 40, 1, [])  # the first stay brought 5 MB down
    assert found(store, lg, events) == []  # and one quick exit needs a cause


# ---- the apps the gateway does not judge --------------------------------------------------------------------------
def test_the_tv_makers_own_apps_and_apps_never_seen_working_are_not_judged(store, lg):
    """Settings for three minutes and back home is someone changing a setting; an app with no picture has
    nothing to compare with, whatever was refused meanwhile."""
    store.lookup(T + 2, "api.example.net", blocked=1)  # a first refusal: a likely cause, were it judged
    assert found(store, lg, opened(T - 600, (SETTINGS, T, 180))) == []
    assert found(store, lg, opened(T - 600, (NEW_APP, T, 15), (NEW_APP, T + 40, 15))) == []
    ev = appfront.Evidence()
    ev.seen[SETTINGS] = {("lgtvsdp.com", "Infra"): {appfront.viewing_day(T) - 1}}  # even with a picture
    assert not didit.eligible(SETTINGS, ev, T) and didit.eligible(NF, didit.evidence(store.conn, lg, T, T), T)
    assert found(store, lg, opened(T - 600, (SETTINGS, T, 15), (SETTINGS, T + 40, 15)), ev=ev) == []


def test_a_lone_stall_needs_a_likely_cause_and_settled_bytes(store, lg):
    store.talk(T + 2, "netflix.com", down_=200_000)
    events = opened(T - 600, (NF, T, 180))
    assert found(store, lg, events) == []  # three minutes on a menu reads the same
    store.lookup(T + 5, "api.example.net", blocked=1)
    (f,) = found(store, lg, events)
    assert (f.kind, f.times, f.longest, f.reported) == ("stalled", 1, 180, True)
    assert didit.describe(f).startswith(
        "Netflix opened at 20:14 and stayed 3 min with only 195.3 KB down, then the TV went back to the"
        " home screen; in those minutes the filter refused api.example.net"
    )
    assert found(store, lg, events, now=T + 600) == []  # a start that worked reads the same until then
    assert found(store, lg, opened(T - 600, (NF, T, didit.STALL_MAX + 1))) == []  # too long to be a start


def test_an_app_back_from_memory_needs_a_likely_cause(store, lg):
    """Netflix worked earlier that evening, so its quick returns can come from memory, bringing little."""
    store.talk(T - 3000, "nflxvideo.net", down_=900 * 1024 * 1024)
    events = opened(T - 3600, (NF, T - 3300, 2400), (NF, T, 15), (NF, T + 40, 15))
    assert found(store, lg, events) == []
    store.lookup(T + 2, "api.example.net", blocked=1)
    (f,) = found(store, lg, events)
    assert (f.fresh, f.times) == (False, 2)
    assert "; Netflix had been in front earlier that evening, so it may have come back from memory;" in (
        didit.describe(f)
    )


def test_before_its_bytes_settle_a_start_is_pending_never_failed(store, lg):
    events = opened(T - 600, (NF, T, 15), (NF, T + 40, 15))
    store.lookup(T + 2, "api.example.net", blocked=1)  # even with a first refusal in its minutes
    tl = timeline(store, events, T - 3600, T + 3600)
    candidates, pending = didit.episodes(tl, [], T - 3600, T + 3600, T + 600)
    assert candidates == [] and [p.start for p in pending] == [T, T + 40]
    assert found(store, lg, events, now=T + 600) == []


# ---- with a likely cause ------------------------------------------------------------------------------------------
def test_a_name_refused_for_the_first_time_in_that_minute_is_the_likely_cause(store, lg):
    store.lookup(T + 2, "api.example.net", blocked=1)
    store.lookup(T + 3, "api.example.net", blocked=1)
    (f,) = found(store, lg, opened(T - 600, (NF, T, 15)))
    (c,) = f.causes
    assert (c.name, c.lookups, c.first_sight, c.tracking, c.needed, c.likely, c.strong) == (
        "api.example.net",
        2,
        True,
        False,
        None,
        True,
        False,
    )
    assert didit.describe(f) == (
        "Netflix opened at 20:14, and the TV went back to the home screen after 15 seconds (0 B down); in"
        " that minute the filter refused api.example.net (other services), which it had not refused before:"
        " sudo tvgw check api.example.net"
    )


def test_a_name_refused_every_day_before_is_not_a_likely_cause(store, lg):
    store.lookup(T - 2 * 86400, "api.example.net", blocked=1)
    store.lookup(T + 2, "api.example.net", blocked=1)
    assert found(store, lg, opened(T - 600, (NF, T, 15))) == []
    (f,) = found(store, lg, opened(T - 600, (NF, T, 15), (NF, T + 40, 15)))
    assert not f.causes[0].first_sight
    assert "the gateway refused only 1 name it refuses on purpose or had refused before" in didit.describe(f)


def test_a_name_the_filter_let_through_after_its_last_refusal_is_first_sight_again(store, lg):
    store.lookup(T - 3 * 86400, "api.example.net", blocked=1)
    store.lookup(T - 86400, "api.example.net", blocked=0)  # a list's rule taken out, then put back
    store.lookup(T + 2, "api.example.net", blocked=1)
    (f,) = found(store, lg, opened(T - 600, (NF, T, 15)))
    assert f.causes[0].first_sight


def test_a_name_the_tv_needs_comes_first(store, lg):
    store.lookup(T + 1, "api.example.net", blocked=1)
    store.lookup(T + 2, "pubads.g.doubleclick.net", blocked=1)
    store.lookup(T + 3, "snu.lge.com", blocked=1)
    (f,) = found(store, lg, opened(T - 600, (NF, T, 15)))
    assert [c.name for c in f.causes] == ["snu.lge.com", "api.example.net", "pubads.g.doubleclick.net"]
    assert [c.likely for c in f.causes] == [True, True, False]
    text = didit.describe(f)
    assert "the filter refused snu.lge.com (" in text and "which the profile says the TV needs" in text
    assert text.endswith(", and 1 more like it: sudo tvgw check snu.lge.com")


def test_a_site_the_app_reached_on_earlier_days_is_a_likely_cause_even_when_refused_before(store, lg):
    """Netflix brought its video from nflxvideo.net on two earlier evenings: a name there refused now is
    its own, though the filter had refused it before."""
    store.lookup(T - 2 * 86400, "secure.nflxvideo.net", blocked=1)
    store.lookup(T + 2, "secure.nflxvideo.net", blocked=1)
    (f,) = found(store, lg, opened(T - 600, (NF, T, 15)))
    c = f.causes[0]
    assert (c.app_days, c.first_sight, c.likely, c.strong) == (2, False, True, True)
    assert "whose site Netflix reached on 2 earlier days" in didit.describe(f)


def test_refusals_outside_the_minutes_and_of_record_types_the_tv_goes_without_are_left_out(store, lg):
    store.lookup(T - didit.SLACK - 1, "early.example.net", blocked=1)
    store.lookup(T + 15 + didit.SLACK + 1, "late.example.net", blocked=1)
    store.conn.execute(
        "INSERT INTO dns(t, qname, qtype, blocked) VALUES (?, 'typed.example.net', 'HTTPS', 1)", (T + 2,)
    )
    store.conn.execute(
        "INSERT INTO dns(t, qname, qtype, blocked) VALUES (?, 'printer.local', 'A', 1)", (T + 2,)
    )
    store.conn.commit()
    assert found(store, lg, opened(T - 600, (NF, T, 15))) == []


def test_a_walls_own_refusal_is_judged_by_its_own_record(store, lg):
    """A refusal another reader passes carries whether that reader refused the same before; without that
    it is never first sight. It says the gateway refused a connection, and points at tvgw refused."""
    events = opened(T - 600, (NF, T, 15))
    unknown = didit.Refusal(T + 4, "203.0.113.9", "oddport", "firewall")
    assert found(store, lg, events, extra=[unknown]) == []
    new = didit.Refusal(T + 4, "203.0.113.9", "oddport", "firewall", seen_before=False)
    (f,) = found(store, lg, events, extra=[new])
    (c,) = f.causes
    assert (c.source, c.first_sight, c.likely, c.kind, c.category) == (
        "firewall",
        True,
        True,
        "an address",
        "",
    )
    assert didit.describe(f).endswith(
        "in that minute the gateway refused a connection to 203.0.113.9 (an address), which it had not refused"
        " before: sudo tvgw refused"
    )
    old = didit.Refusal(T + 4, "203.0.113.9", "oddport", "firewall", seen_before=True)
    assert found(store, lg, events, extra=[old]) == []


# ---- from the hourly readings --------------------------------------------------------------------------------------
def readings(store, power_="Active", front=NF, hours=1):
    for h in range(hours + 1):
        store.reading(T + h * 3600, power_, front)


def test_an_hourly_pair_with_little_down_and_the_apps_own_site_refused_is_a_weaker_sign(store, lg):
    readings(store)
    store.talk(T + 600, "netflix.com", down_=2_000_000)
    store.lookup(T + 900, "secure.nflxvideo.net", blocked=1)
    (f,) = found(store, lg, [], a=T - 60, b=T + 7200)
    assert (f.timed, f.kind, f.times, f.down) == ("hourly", "hourly", 1, 2_000_000)
    assert didit.describe(f) == (
        "Netflix was in front at 20:14 and at 21:14 with only 1.9 MB down (times to the hour, a weaker"
        " sign: an app left on its menu reads the same); between those readings the filter refused"
        " secure.nflxvideo.net (Netflix, Inc., streaming), whose site Netflix reached on 2 earlier days: sudo"
        " tvgw check secure.nflxvideo.net"
    )


def test_over_an_hour_a_first_refusal_alone_is_not_enough(store, lg):
    readings(store)
    assert found(store, lg, [], a=T - 60, b=T + 7200) == []
    store.lookup(T + 900, "api.example.net", blocked=1)
    assert found(store, lg, [], a=T - 60, b=T + 7200) == []


def test_an_hourly_session_over_more_than_one_pair_of_readings_is_no_sign(store, lg):
    readings(store, hours=3)
    store.lookup(T + 900, "secure.nflxvideo.net", blocked=1)
    assert found(store, lg, [], a=T - 60, b=T + 4 * 3600) == []


@pytest.mark.parametrize(("power_", "down_"), [("Screen Saver", 0), ("Active", 50 * 1024 * 1024)])
def test_an_hourly_session_behind_the_screen_saver_or_with_video_is_no_sign(store, lg, power_, down_):
    readings(store, power_)
    store.talk(T + 600, "nflxvideo.net", down_=down_)
    store.lookup(T + 900, "secure.nflxvideo.net", blocked=1)
    assert found(store, lg, [], a=T - 60, b=T + 7200) == []


# ---- the record's order does not matter -----------------------------------------------------------------------------
def test_the_same_record_in_any_order_gives_the_same_failed_starts(store, lg):
    events = opened(T - 600, (NF, T, 15), (NF, T + 40, 12), (YT, T + 300, 900), (NF, T + 1300, 9))
    store.lookup(T + 2, "api.example.net", blocked=1)
    want = [f.as_dict() for f in found(store, lg, events)]
    assert want
    rng = random.Random(72)
    for _ in range(20):
        shuffled = events[:]
        rng.shuffle(shuffled)
        assert [f.as_dict() for f in found(store, lg, shuffled)] == want


# ---- the probation hook ----------------------------------------------------------------------------------------------
def stored(store, events):
    store.conn.executemany(
        "INSERT INTO tv_events(t, kind, value, detail) VALUES (?,?,?,?)",
        [(e.t, e.kind, e.value, e.detail) for e in events],
    )
    store.conn.commit()


def test_since_says_broke_with_the_failed_starts_and_their_causes(store, lg):
    stored(store, opened(T - 600, (NF, T, 15), (NF, T + 40, 15)))
    store.lookup(T + 2, "api.example.net", blocked=1)
    v = didit.since(store.conn, lg, T - 60, LATER, gw_ip=GW)
    assert (v.state, len(v.failed), [c.name for c in v.causes]) == ("broke", 1, ["api.example.net"])
    assert v.covered_until == T + 2 and v.why.startswith("1 app start may have failed since ")
    assert v.as_dict()["causes"][0]["likely"] is True


def test_since_says_clean_only_when_settled_bytes_show_an_app_working_and_the_record_reaches_past_it(
    store, lg
):
    events = opened(T - 600, (NF, T, 1800))
    store.talk(T + 5, "nflxvideo.net", down_=300 * 1024 * 1024)
    store.lookup(T + 1, "nflxvideo.net")
    own = [didit.Refusal(T + 900, "api.example.net", "probation", "firewall", seen_before=True)]
    v = didit.since(store.conn, lg, T - 60, LATER, gw_ip=GW, events=events, extra=own)
    assert v.state == "unknown" and "reaches only 20:29, before the last app stay ended" in v.why
    store.lookup(T + 1900, "nflxvideo.net")  # the record of lookups now reaches past the stay
    v = didit.since(store.conn, lg, T - 60, LATER, gw_ip=GW, events=events, extra=own)
    assert (v.state, v.worked, v.failed, v.pending, v.exposed) == ("clean", 1, [], 0, 1)
    assert v.why == "1 of 2 apps opened since 2026-10-29 20:13, and it worked"
    early = didit.since(store.conn, lg, T - 60, T + 2000, gw_ip=GW, events=events, extra=own)
    assert (early.state, early.worked) == ("unknown", 0)  # its bytes not settled: nothing shows it working


def test_an_evening_the_walls_refusals_never_touched_is_never_clean(store, lg):
    """(exposure) A start that worked says nothing of a wall whose refusals came at another time: before,
    one worked start anywhere made the span CLEAN, whatever the other apps would have done (L2-16)."""
    stored(store, opened(T - 600, (NF, T, 1800), (YT, T + 2000, 1800), (NEW_APP, T + 4000, 100)))
    store.talk(T + 5, "nflxvideo.net", down_=300 * 1024 * 1024)
    store.talk(T + 2005, "googlevideo.com", down_=300 * 1024 * 1024)
    store.talk(T + 4005, "peacocktv.com", down_=9_000)  # an app seen today only: not one it knows yet
    store.lookup(T + 4200, "lgtvonline.lge.com")
    v = didit.since(store.conn, lg, T - 60, LATER, gw_ip=GW)
    assert (v.state, v.worked, v.exposed) == ("unknown", 2, 0)
    assert v.why == "2 app starts worked since 2026-10-29 20:13, but none met its refusals"
    after = [didit.Refusal(T + 3800 + didit.SLACK, "api.example.net", "probation", "firewall")]
    assert didit.since(store.conn, lg, T - 60, LATER, gw_ip=GW, extra=after).exposed == 0
    own = [didit.Refusal(T + 3800 + didit.SLACK - 1, "api.example.net", "probation", "firewall")]
    v = didit.since(store.conn, lg, T - 60, LATER, gw_ip=GW, extra=own)
    assert (v.state, v.exposed, v.apps_worked, v.apps_known) == ("clean", 1, [NF, YT], [NF, YT])
    assert v.why == "3 of 3 apps opened since 2026-10-29 20:13; 2 worked, and none failed"
    assert v.as_dict()["exposed"] == 1


def test_an_hourly_start_that_worked_meets_the_refusals_between_its_two_readings(store, lg):
    readings(store)
    store.talk(T + 600, "nflxvideo.net", down_=50 * 1024 * 1024)
    store.lookup(T + 3700, "lgtvonline.lge.com")
    for at, exposed in ((T - 3, 0), (T + 900, 1)):  # the readings' times are its minutes, with no slack
        own = [didit.Refusal(at, "api.example.net", "probation", "firewall")]
        v = didit.since(store.conn, lg, T - 60, LATER, gw_ip=GW, extra=own)
        assert (v.worked, v.exposed, v.state) == (1, exposed, "clean" if exposed else "unknown")


@pytest.mark.parametrize(
    ("opened_", "worked_", "known", "words"),
    [
        ({NF}, [NF], [NF, YT, NEW_APP], "1 of 3 apps opened since 20:13, and it worked"),
        ({NF, YT, NEW_APP}, [NF, YT, NEW_APP], [NF], "3 of 3 apps opened since 20:13, and all 3 worked"),
        ({NF, YT}, [YT], [], "2 of 2 apps opened since 20:13; 1 worked, and none failed"),
        ({NF, YT}, [NF, YT], [NF], "2 of 2 apps opened since 20:13, and both worked"),
        ({NF}, [NF], [], "1 of 1 app opened since 20:13, and it worked"),
    ],
)
def test_the_words_say_how_much_of_what_the_tv_runs_was_seen_working(opened_, worked_, known, words):
    assert didit.apps_words(opened_, worked_, known, "20:13") == words


def test_a_rules_own_refusals_are_its_rows_among_the_custom_rules_alone(store):
    """A downloaded list's line of the same text (filter 3) is not the machine's rule; a custom rule's row
    written before AdGuard logged filter ids (NULL) is."""
    rows = [(T + 1, "||a.example^", 0), (T + 2, "||a.example^", None), (T + 3, "||a.example^", 3)]
    rows.append((T + 4, "||b.example^", 0))
    store.conn.executemany(
        "INSERT INTO dns(t, qname, qtype, blocked, rule, filter_id) VALUES (?, 'a.example', 'A', 1, ?, ?)",
        rows,
    )
    assert [r.t for r in didit.refusals(store.conn, T, T + 60, "||a.example^")] == [T + 1, T + 2]
    assert len(didit.refusals(store.conn, T, T + 60)) == 4


def test_a_refusal_the_store_holds_and_the_caller_passes_again_counts_once(store, lg):
    store.lookup(T + 2, "api.example.net", blocked=1)
    (again,) = didit.refusals(store.conn, T, T + 60)
    (f,) = found(store, lg, opened(T - 600, (NF, T, 15)), extra=[again, again])
    assert [(c.name, c.lookups) for c in f.causes] == [("api.example.net", 1)]


def test_time_in_front_alone_does_not_show_an_app_working(store, lg):
    events = opened(T - 600, (NF, T, 760))
    store.lookup(T + 1, "lgtvonline.lge.com")
    store.lookup(T + 800, "lgtvonline.lge.com")
    v = didit.since(store.conn, lg, T - 60, LATER, gw_ip=GW, events=events)
    assert (v.state, v.worked) == ("unknown", 0) and v.why.startswith("no app start since")


def test_since_with_nothing_started_is_unknown_never_clean(store, lg):
    store.lookup(T + 1, "lgtvonline.lge.com")
    v = didit.since(store.conn, lg, T - 60, LATER, gw_ip=GW)
    assert (v.state, v.worked) == ("unknown", 0) and "no app start since" in v.why
    empty = didit.since(store.conn, lg, T + 60, LATER, gw_ip=GW)
    assert empty.state == "unknown" and empty.why.startswith("the record holds no lookup since")


def test_since_waits_for_a_start_still_settling_and_takes_the_minutes_the_store_has_not_loaded(store, lg):
    """The live reading's own lines and the refusals the store does not hold yet, passed in: a start whose
    bytes have not settled is pending, so a wall's first refusal never turns a working start into a failure."""
    events = opened(T - 600, (NF, T, 15))
    fresh = [didit.Refusal(T + 2, "api.example.net")]
    soon = didit.since(store.conn, lg, T - 60, T + 120, gw_ip=GW, events=events, extra=fresh)
    assert (soon.state, soon.pending, soon.failed) == ("unknown", 1, [])
    assert soon.why.startswith("1 app start is still settling since ")
    later = didit.since(store.conn, lg, T - 60, LATER, gw_ip=GW, events=events, extra=fresh)
    assert (
        later.state == "broke" and later.causes[0].name == "api.example.net" and later.covered_until == T + 2
    )


def test_since_judges_a_walls_own_refusals_with_the_apps_pictures(store, lg):
    events = opened(T - 600, (NF, T, 15))
    wall = [didit.Refusal(T + 3, "secure.nflxvideo.net", "probation", "firewall")]
    v = didit.since(store.conn, lg, T - 60, LATER, gw_ip=GW, events=events, extra=wall)
    (c,) = v.causes
    assert (v.state, c.source, c.app_days, c.strong) == ("broke", "firewall", 2, True)


# ---- what a persisted report may carry -----------------------------------------------------------------------------
def test_the_summary_is_counts_only_and_its_line_names_no_app_time_or_name(store, lg):
    store.lookup(T + 2, "api.example.net", blocked=1)
    got = found(store, lg, opened(T - 600, (NF, T, 15), (YT, T + 1800, 10), (YT, T + 1830, 10)))
    s = didit.summary(got)
    assert s == {"starts": 2, "with_cause": 1, "hourly": 0}
    line = didit.summary_line(s, "2026-10-29")
    assert line == (
        "2 app starts may have failed. In the minutes of 1 of them, the gateway refused a name worth a look:"
        " one the TV needs, one the app used before, or a refusal the gateway had not made before. Which app"
        " and which name: sudo tvgw receipt --since 2026-10-29"
    )
    assert not re.search(r"Netflix|YouTube|example|\d\d:\d\d", line)
    one = didit.summary_line({"starts": 1, "with_cause": 0, "hourly": 0}, "2026-10-29")
    assert one.startswith("One app start may have failed. The gateway refused nothing worth a look in those")


def test_no_line_claims_who_acted_or_why(store, lg):
    """A refusal in the same minutes is a match in time: the receipt's forbidden words hold here too."""
    store.lookup(T + 2, "api.example.net", blocked=1)
    store.lookup(T + 3, "snu.lge.com", blocked=1)
    store.lookup(T + 4, "secure.nflxvideo.net", blocked=1)
    readings(store)
    lines = []
    for f in found(store, lg, opened(T - 600, (NF, T, 15), (NF, T + 40, 120)), a=T - 60, b=T + 7200):
        lines.append(didit.describe(f))
    lines += didit.section(found(store, lg, opened(T - 600, (NF, T, 15))))
    lines.append(didit.summary_line({"starts": 3, "with_cause": 2, "hourly": 1}, "2026-10-29"))
    assert len(lines) > 3 and not [x for x in lines if receipt.FORBIDDEN.search(x)]


# ---- the receipt's section, and the brief's count by the same rule ---------------------------------------------------
def receipt_cli(store, tmp_path, *args):
    conf = tmp_path / "tvgw.conf"
    conf.write_text("", encoding="utf-8")
    return cli.main(["--conf", str(conf), "--db", store.path, "receipt", *args])


def test_the_receipt_opens_with_the_evenings_failed_starts(store, tmp_path, monkeypatch, capsys):
    monkeypatch.setattr(time, "time", lambda: LATER)
    stored(store, opened(T - 600, (NF, T, 15), (NF, T + 40, 12), (YT, T + 300, 1800)))
    store.lookup(T + 2, "api.example.net", blocked=1)
    assert receipt_cli(store, tmp_path) == 0
    out = capsys.readouterr().out.splitlines()
    assert (
        out[1]
        == "Did it work? Apps back at the home screen soon after opening, with almost nothing downloaded:"
    )
    assert out[2].startswith(
        "  Netflix opened 2 times from 20:14, and each time the TV went back to the home"
    )
    assert "sudo tvgw check api.example.net." in " ".join(out[2:5])
    assert receipt_cli(store, tmp_path, "--json") == 0
    (f,) = json.loads(capsys.readouterr().out)["failed_starts"]
    assert (f["app"], f["times"], f["causes"][0]["name"]) == (NF, 2, "api.example.net")
    assert receipt_cli(store, tmp_path, "--since", "2d") == 0
    assert "  Netflix opened 2 times from 20:14" in capsys.readouterr().out


def test_a_receipt_with_no_failed_start_is_as_it_was(store, tmp_path, monkeypatch, capsys):
    monkeypatch.setattr(time, "time", lambda: LATER)
    stored(store, opened(T - 600, (YT, T + 300, 1800)))
    assert receipt_cli(store, tmp_path) == 0
    assert "Did it work?" not in capsys.readouterr().out


def test_the_receipt_and_the_brief_count_by_one_rule(store, lg, tmp_path, monkeypatch, capsys):
    """A name under the app's own site, refused every day: the receipt shows the quick exit, and the brief
    counts it, both by the app's picture."""
    monkeypatch.setattr(time, "time", lambda: LATER)
    for d in (1, 2):
        store.lookup(evening(d, 12.0), "secure.nflxvideo.net", blocked=1)
    store.lookup(T + 2, "secure.nflxvideo.net", blocked=1)
    stored(store, opened(T - 600, (NF, T, 15)))
    assert receipt_cli(store, tmp_path, "--json") == 0
    (f,) = json.loads(capsys.readouterr().out)["failed_starts"]
    assert f["causes"][0]["app_days"] == 2
    o = queries.brief(store.conn, DAY, lg, now=LATER, gw_ip=GW)
    assert o["failed_starts"] == {"starts": 1, "with_cause": 1, "hourly": 0}


# ---- the brief ---------------------------------------------------------------------------------------------------------
DAY = "2026-10-29"  # the day T falls on


def two_failures(store):
    stored(store, opened(T - 600, (NF, T, 15), (NF, T + 40, 12), (YT, T + 1800, 10), (YT, T + 1830, 10)))
    store.lookup(T + 2, "api.example.net", blocked=1)


def test_a_persisted_report_carries_the_counts_and_no_app_time_or_name(store, lg):
    two_failures(store)
    o = queries.brief(store.conn, DAY, lg, now=LATER, gw_ip=GW)
    assert o["failed_starts"] == {"starts": 2, "with_cause": 1, "hourly": 0}
    out = io.StringIO()
    cli.render_brief(o, out)
    line = didit.summary_line(o["failed_starts"], DAY)
    assert (
        f"\nDid it work (app starts that may have failed; a report, nothing changes on its own):\n  {line}\n"
    ) in out.getvalue()
    assert [x for x in plain.plain_brief(o, profile=lg) if x.startswith("  Apps:")] == [f"  Apps: {line}"]


def test_the_interactive_brief_names_the_app_the_time_and_the_name(store, lg):
    two_failures(store)
    o = queries.brief(store.conn, DAY, lg, now=LATER, gw_ip=GW, app_in_front=True)
    first, second = o["failed_starts"]["lines"]
    assert first.startswith("Netflix opened 2 times from 20:14") and "api.example.net" in first
    assert second.startswith("YouTube opened 2 times from 20:44")
    out = io.StringIO()
    cli.render_brief(o, out)
    assert "\n  Netflix opened 2 times from 20:14, and each time the TV went back to the home screen" in (
        out.getvalue()
    )
    (note,) = [x for x in plain.plain_brief(o, profile=lg) if x.startswith("  Apps:")]
    assert note.startswith("  Apps: Netflix opened 2 times from 20:14,")
    assert note.endswith(": sudo tvgw check api.example.net. 1 more: sudo tvgw receipt --since 2026-10-29")


def test_a_day_without_a_failed_start_prints_what_it_printed_before(store, lg):
    stored(store, opened(T - 600, (YT, T + 300, 1800)))
    o = queries.brief(store.conn, DAY, lg, now=LATER, gw_ip=GW)
    assert o["failed_starts"] == {"starts": 0, "with_cause": 0, "hourly": 0}
    out = io.StringIO()
    cli.render_brief(o, out)
    assert "Did it work" not in out.getvalue()
    assert not [x for x in plain.plain_brief(o, profile=lg) if x.startswith("  Apps:")]


def test_a_failure_to_read_failed_starts_costs_the_key_not_the_report(store, lg, monkeypatch):
    def broken(*a, **k):
        raise sqlite3.OperationalError("no such table: tv_events")

    monkeypatch.setattr(didit, "for_window", broken)
    o = queries.brief(store.conn, DAY, lg, now=LATER, gw_ip=GW)
    assert o["failed_starts"] is None
    assert "failed starts: OperationalError: no such table: tv_events" in o["warnings"]
    cli.render_brief(o, io.StringIO())
    plain.plain_brief(o, profile=lg)
