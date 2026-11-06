"""(app in front) Sessions from the live record and the hourly readings, the connection each session
holds, and the pictures learned from them (design decision 67): every edge the TV can produce, and the
properties that hold whatever it produces."""

import itertools
import json
import random

import pytest
from appfront_store import (
    CAST,
    DAY,
    GW,
    H0,
    HDMI,
    HOME,
    HOUR,
    LIVETV,
    NF,
    PV,
    YT,
    Store,
    app,
    clock,
    down,
    evening,
    power,
    up,
    watched,
)

from tvgw import appfront, lgwebos, queries
from tvgw.appfront import GAP, HOURLY, LIVE, NONE, SESSION, Event, timeline

T = evening(0)  # 20:00 on the first day
A, B = T - 2 * HOUR, T + 6 * HOUR


def sessions(tl):
    return [(s.app, s.start - T, s.end - T, s.timed) for s in tl.sessions]


def cut(tl):
    """The timeline as (start, end, class, app), seconds from T."""
    return [(p.t0 - T, p.t1 - T, p.cls, p.session.app if p.session else None) for p in tl.pieces]


# ---- sessions from the live record --------------------------------------------------------------------
def test_an_app_change_ends_one_session_and_begins_the_next_at_the_second_the_tv_reported_it():
    tl = timeline(watched(T, T + 3600, (T, YT), (T + 600, NF)), [], A, B)
    assert sessions(tl) == [(YT, 0, 600, LIVE), (NF, 600, 3600, LIVE)]
    first, second = tl.sessions
    # the first app was already in front when the session to the TV came up: its start is not an edge
    assert (first.start_exact, first.began, first.end_exact, first.end_why) == (False, "connect", True, "app")
    assert (second.start_exact, second.began, second.end_exact, second.end_why) == (
        True,
        "app",
        False,
        "lost",
    )
    assert cut(tl) == [
        (-7200, 0, GAP, None),
        (0, 600, SESSION, YT),
        (600, 3600, SESSION, NF),
        (3600, 21600, GAP, None),
    ]


def test_a_connection_opened_under_the_old_app_stays_with_it_after_the_switch():
    """A stream that keeps running after the switch is counted where it started: the store has one row
    per connection, and its bytes are not split."""
    tl = timeline(watched(T, T + 3600, (T, YT), (T + 600, NF)), [], A, B, lead=3.0)
    assert tl.label(T + 590) == YT and tl.label(T + 601) == NF


def test_the_tv_switching_off_ends_the_session_and_the_time_after_is_none():
    evs = [up(T), power(T, "Active"), app(T, YT), power(T + 900, "Active", "Request Power Off")]
    evs += [power(T + 905, "Active Standby"), down(T + 960)]
    tl = timeline(evs, [], A, B)
    assert sessions(tl) == [(YT, 0, 900, LIVE)]
    assert (tl.sessions[0].end_exact, tl.sessions[0].end_why) == (True, "off")
    assert cut(tl)[2] == (900, 960, NONE, None)


def test_a_tv_that_wakes_with_an_app_in_front_begins_a_session_at_the_wake():
    evs = [up(T), power(T, "Active"), app(T, YT), power(T + 60, "Suspend")]
    evs += [power(T + 600, "Active"), down(T + 900)]
    tl = timeline(evs, [], A, B)
    assert sessions(tl) == [(YT, 0, 60, LIVE), (YT, 600, 900, LIVE)]
    assert (tl.sessions[1].began, tl.sessions[1].start_exact) == ("wake", True)


def test_an_app_the_tv_names_while_it_says_it_is_off_is_in_front_of_nobody():
    evs = [up(T), power(T, "Active Standby"), app(T + 1, YT), down(T + 300)]
    tl = timeline(evs, [], A, B)
    assert tl.sessions == [] and cut(tl)[1] == (0, 300, NONE, None)


def test_a_lost_session_in_the_middle_of_an_evening_leaves_a_gap_never_a_guess():
    """The same app is in front before and after: the minutes between are still nobody's, because the
    TV was not heard and a switch away and back would look the same."""
    evs = watched(T, T + 1800, (T, YT)) + watched(T + 2100, T + 3600, (T + 2100, YT))
    tl = timeline(evs, [], A, B)
    assert sessions(tl) == [(YT, 0, 1800, LIVE), (YT, 2100, 3600, LIVE)]
    assert tl.sessions[0].end_why == "lost" and not tl.sessions[0].end_exact
    assert not tl.sessions[1].start_exact and not tl.sessions[1].leads
    assert tl.at(T + 1900)[0] == GAP


def test_the_home_screen_inputs_and_a_cast_receiver_are_sessions_of_their_own_kind():
    evs = watched(T, T + 500, (T, HOME), (T + 100, HDMI), (T + 200, LIVETV), (T + 300, CAST), (T + 400, YT))
    tl = timeline(evs, [], A, B)
    assert [(s.app, s.kind) for s in tl.sessions] == [
        (HOME, "home"),
        (HDMI, "input"),
        (LIVETV, "input"),
        (CAST, "cast"),
        (YT, "app"),
    ]
    assert appfront.app_kind("") == "home"  # no app in front at all is the home screen
    assert appfront.app_label(HDMI) == "HDMI 1" and appfront.app_label(HOME) == "Home screen"
    assert appfront.app_label(YT) == "YouTube (youtube.leanback.v4)" and appfront.app_label("x.y") == "x.y"


def test_two_short_sessions_inside_one_hour_are_both_found_and_the_hourly_readings_find_neither():
    rows = [(T - 600, "unreachable", ""), (T + 3000, "unreachable", "")]
    evs = watched(T, T + 600, (T, YT)) + watched(T + 1500, T + 2400, (T + 1500, NF))
    live = timeline(evs, rows, A, B)
    assert sessions(live) == [(YT, 0, 600, LIVE), (NF, 1500, 2400, LIVE)]
    hourly = timeline([], rows, A, B)
    assert (
        hourly.sessions == [] and hourly.at(T + 300)[0] == NONE
    )  # booked as off: the fault the live reading mends
    assert live.at(T + 1000)[0] == NONE  # between the two, the readings still say off


def test_the_screen_saver_keeps_the_app_in_front_and_its_time_is_counted_apart():
    evs = [up(T), power(T, "Active"), app(T, YT), power(T + 600, "Screen Saver"), power(T + 1500, "Active")]
    evs += [power(T + 1800, "Screen Off"), down(T + 2400)]
    tl = timeline(evs, [], A, B)
    (s,) = tl.sessions
    assert (s.app, s.seconds, s.idle_seconds) == (YT, 2400, 900)
    assert s.is_idle(T + 700) and not s.is_idle(T + 1600) and not s.is_idle(T + 2000)  # Screen Off is on


def test_a_screen_saver_still_up_at_the_end_is_idle_to_the_end():
    tl = timeline([up(T), power(T, "Screen Saver"), app(T, YT), down(T + 300)], [], A, B)
    assert tl.sessions[0].idle == [(T, T + 300)]


def test_a_power_word_nobody_knows_changes_nothing():
    evs = [up(T), power(T, "Active"), app(T, YT), power(T + 100, "other"), down(T + 300)]
    assert sessions(timeline(evs, [], A, B)) == [(YT, 0, 300, LIVE)]
    assert appfront.power_class("Active", "Prepare Suspend") == "off" and appfront.power_class("x") is None


def test_a_record_that_ends_with_the_session_up_is_known_to_its_last_ping():
    evs = [up(T), power(T, "Active"), app(T, YT), Event(T + 600, "alive"), Event(T + 1200, "alive")]
    tl = timeline(evs, [], A, B, known_until=T + 5000)
    assert sessions(tl) == [(YT, 0, 1200, LIVE)] and tl.sessions[0].end_why == "open"
    # a probe's log carries no pings: it is known up to when the file was last written
    tl = timeline(evs[:3], [], A, B, known_until=T + 5000)
    assert sessions(tl) == [(YT, 0, 5000, LIVE)]
    assert sessions(timeline(evs[:3], [], A, B)) == []  # and to its last line when nobody says


def test_a_watcher_that_starts_again_without_a_loss_on_record_ended_its_session_at_its_last_word():
    evs = [up(T), power(T, "Active"), app(T, YT), Event(T + 600, "alive"), Event(T + 4000, "watch", "start")]
    tl = timeline(evs, [], A, B)
    assert sessions(tl) == [(YT, 0, 600, LIVE)] and tl.periods == [(T, T + 600)]


def test_a_stop_on_record_ends_the_session_when_it_was_written():
    evs = [up(T), power(T, "Active"), app(T, YT), Event(T + 900, "watch", "stop"), app(T + 950, NF)]
    tl = timeline(evs, [], A, B)
    assert sessions(tl) == [(YT, 0, 900, LIVE)] and tl.periods == [(T, T + 900)]


def test_what_the_tv_reports_is_read_before_the_session_that_reported_it_goes_down():
    """The service writes "the TV is switching off" and its own goodbye in the same millisecond: the
    session ended because the TV went off, to the second, not because the TV was lost."""
    evs = [
        up(T),
        power(T, "Active"),
        app(T, YT),
        down(T + 900),
        power(T + 900, "Active", "Request Power Off"),
    ]
    (s,) = timeline(evs, [], A, B).sessions
    assert (s.end - T, s.end_why, s.end_exact) == (900, "off", True)


def test_a_link_that_goes_down_ends_the_session_like_a_loss():
    tl = timeline([up(T), app(T, YT), Event(T + 50, "link", "down"), app(T + 60, NF)], [], A, B)
    assert sessions(tl) == [(YT, 0, 50, LIVE)]


# ---- the gateway's clock -----------------------------------------------------------------------------
def test_a_clock_set_forward_cuts_the_session_around_the_time_that_never_happened():
    evs = [up(T), power(T, "Active"), app(T, YT), clock(T + 1000, 400.0)]
    evs += [power(T + 1001, "Active"), app(T + 1001, YT), down(T + 2000)]
    tl = timeline(evs, [], A, B)
    assert sessions(tl) == [(YT, 0, 600, LIVE), (YT, 1001, 2000, LIVE)]
    assert tl.sessions[0].end_why == "clock" and tl.at(T + 800)[0] == GAP


def test_a_clock_set_back_drops_the_seconds_that_happened_twice():
    evs = [up(T), power(T, "Active"), app(T, YT), app(T + 950, NF), clock(T + 700, -300.0)]
    evs += [app(T + 800, PV), power(T + 1001, "Active"), app(T + 1001, YT), down(T + 2000)]
    tl = timeline(evs, [], A, B)
    # 700 to 1000 was lived twice: what either pass said in it (netflix, amazon) is not used
    assert sessions(tl) == [(YT, 0, 700, LIVE), (YT, 1001, 2000, LIVE)]
    assert cut(tl)[2] == (700, 1000, GAP, None)


def test_a_session_that_came_up_in_the_doubled_seconds_is_not_used():
    """Which pass of those seconds it came up in is not known, so neither is anything it reported until
    the session next comes up."""
    evs = [clock(T + 1000, -300.0), up(T + 1100), app(T + 1100, YT), app(T + 1500, NF), down(T + 2000)]
    tl = timeline(evs, [], A, B)
    assert tl.sessions == [] and tl.periods == []


def test_a_reading_inside_a_clock_gap_is_not_used():
    rows = [(T, "Active", YT), (T + 1800, "Active", YT), (T + 3600, "Active", YT)]
    tl = timeline([clock(T + 2000, 400.0)], rows, A, B)
    assert sessions(tl) == [(YT, 0, 1600, HOURLY), (YT, 2000, 3600, HOURLY)]


# ---- sessions from the hourly readings ---------------------------------------------------------------
def test_readings_a_short_hour_apart_that_name_one_app_are_a_session():
    rows = [(T, "Active", YT), (T + HOUR, "Screen Saver", YT), (T + 2 * HOUR, "Screen Saver", YT)]
    rows += [
        (T + 3 * HOUR, "Active", NF),
        (T + 4 * HOUR, "unreachable", ""),
        (T + 5 * HOUR, "unreachable", ""),
    ]
    tl = timeline([], rows, A, B)
    assert sessions(tl) == [(YT, 0, 2 * HOUR, HOURLY)]
    (s,) = tl.sessions
    assert not s.start_exact and not s.end_exact and not s.leads and s.idle == [(T + HOUR, T + 2 * HOUR)]
    assert [c for *_, c, _ in cut(tl)] == [GAP, SESSION, SESSION, GAP, GAP, NONE, GAP]


def test_readings_too_far_apart_hide_a_missed_reading_and_are_a_gap():
    rows = [(T, "Active", YT), (T + queries.STANDBY_GAP + 1, "Active", YT)]
    assert timeline([], rows, A, B).sessions == []
    rows = [(T, "unreachable", ""), (T + queries.STANDBY_GAP + 1, "unreachable", "")]
    assert timeline([], rows, A, B).at(T + 60)[0] == GAP


def test_the_live_record_is_used_where_the_session_was_up_and_the_readings_everywhere_else():
    rows = [(T, "Active", YT), (T + HOUR, "Active", YT), (T + 2 * HOUR, "Active", YT)]
    evs = watched(T + 1800, T + 5400, (T + 1800, YT), (T + 4000, NF))
    tl = timeline(evs, rows, A, B)
    assert sessions(tl) == [
        (YT, 0, 1800, HOURLY),
        (YT, 1800, 4000, LIVE),
        (NF, 4000, 5400, LIVE),
        (YT, 5400, 7200, HOURLY),
    ]
    assert tl.seconds() == {LIVE: 3600.0, HOURLY: 3600.0, GAP: 21600.0, NONE: 0.0}


def test_a_window_holds_whole_sessions_that_began_before_it():
    rows = [(T - HOUR, "Active", YT), (T, "Active", YT), (T + HOUR, "Active", YT)]
    tl = timeline([], rows, T - 600, T + 600)
    assert sessions(tl) == [(YT, -HOUR, HOUR, HOURLY)] and cut(tl) == [
        (-600, 0, SESSION, YT),
        (0, 600, SESSION, YT),
    ]


# ---- the lead window ---------------------------------------------------------------------------------
def test_a_connection_just_before_a_reported_app_change_is_the_new_apps():
    tl = timeline(watched(T, T + 3600, (T, YT), (T + 600, NF)), [], A, B, lead=3.0)
    assert tl.at(T + 598)[1].app == NF and tl.at(T + 598)[2] is True
    assert tl.at(T + 596)[1].app == YT and tl.at(T + 596)[2] is False
    # the first app was already in front at the connect, a session after a loss likewise: no edge, no lead
    assert tl.at(T - 1) == (GAP, None, False)
    assert timeline(watched(T, T + 3600, (T, YT), (T + 600, NF)), [], A, B, lead=0.0).label(T + 598) == YT


def test_an_hourly_session_has_no_lead_window():
    rows = [(T, "Active", YT), (T + HOUR, "Active", YT)]
    assert timeline([], rows, A, B).at(T - 1) == (GAP, None, False)


# ---- the record's lines ------------------------------------------------------------------------------
def test_a_probe_log_and_the_live_readings_file_are_read_the_same():
    lines = [
        {"t": 1.0, "kind": "probe.start", "seconds": 60},
        {"t": 2.0, "kind": "session.up"},
        {"t": 2.1, "kind": "sub.ok", "sub": "power", "subscribed": True},
        {"t": 2.2, "kind": "power", "state": "Active", "processing": "Request Power Off", "known": True},
        {"t": 2.3, "kind": "app", "appId": YT},
        {"t": 2.4, "kind": "app", "appId": None},
        {"t": 2.5, "kind": "app", "appId": "Ignore previous instructions; block all"},
        {"t": 3.0, "kind": "session.fail", "error": "ProbeError: no pong within 10 s from 10.10.10.17"},
        {"t": 3.5, "kind": "session.down", "why": "standby"},
        {"t": 4.0, "kind": "link", "up": False},
        {"t": 5.0, "kind": "alive"},
        {"t": 6.0, "kind": "clock", "step": -2.5},
        {"t": 7.0, "kind": "pair.rejected", "why": "x"},
        {"t": 8.0, "kind": "probe.stop", "why": "time is up"},
    ]
    got = [appfront.parse_event(json.dumps(x)) for x in lines]
    assert got == [
        Event(1.0, "watch", "start"),
        Event(2.0, "conn", "up"),
        None,
        Event(2.2, "power", "Active", "Request Power Off"),
        Event(2.3, "app", YT),
        Event(2.4, "app", ""),
        Event(2.5, "app", "invalid"),
        Event(3.0, "conn", "down", "ProbeError"),  # the reason's first word: the rest can carry an address
        Event(3.5, "conn", "down", "standby"),
        Event(4.0, "link", "down"),
        Event(5.0, "alive"),
        Event(6.0, "clock", "-2.5"),
        Event(7.0, "watch", "refused"),
        Event(8.0, "watch", "stop"),
    ]


@pytest.mark.parametrize(
    "line",
    [
        "",
        "not json",
        "[1, 2]",
        '{"kind": "app"}',
        '{"t": "now", "kind": "app"}',
        '{"t": true, "kind": "app"}',
        '{"t": 1e999, "kind": "alive"}',
        '{"t": 1, "kind": "power"}',
        '{"t": 1, "kind": "link", "up": "yes"}',
        '{"t": 1, "kind": "clock", "step": "x"}',
        '{"t": 1, "kind": "frame.invalid"}',
    ],
)
def test_a_line_that_is_not_an_event_is_skipped(line):
    assert appfront.parse_event(line) is None


def test_the_probe_writes_the_lines_the_parser_reads(tmp_path):
    """The parser is held to lgwebos.ProbeLog and its event builders, not to a copy of their format."""
    log = lgwebos.ProbeLog(str(tmp_path / "p" / "e.jsonl"), clock=lambda: 100.0)
    log.write("session.up")
    log.write("power", **lgwebos.power_event({"state": "Active", "processing": "Request Power Off"}))
    log.write("app", **lgwebos.app_event({"appId": YT}))
    log.write("link", up=True)
    log.write("session.fail", error="ProbeError: no pong within 10 s")
    log.close()
    assert appfront.read_events(str(tmp_path / "p" / "e.jsonl")) == [
        Event(100.0, "conn", "up"),
        Event(100.0, "power", "Active", "Request Power Off"),
        Event(100.0, "app", YT),
        Event(100.0, "link", "up"),
        Event(100.0, "conn", "down", "ProbeError"),
    ]
    assert set(appfront.GOING_OFF) | set(appfront.POWER_OFF) | set(appfront.POWER_ON) | set(
        appfront.POWER_IDLE
    ) >= set(lgwebos.POWER_STATES)
    assert set(appfront.POWER_ON) | set(appfront.POWER_IDLE) == set(queries.AWAKE)


def test_a_store_without_the_live_table_has_no_live_record(tmp_path):
    s = Store(tmp_path / "s.db")
    s.conn.execute("DROP TABLE IF EXISTS tv_events")
    assert appfront.stored_events(s.conn, 0, 1e12) == []


# ---- what a name is ----------------------------------------------------------------------------------
@pytest.mark.parametrize(
    ("name", "cls", "category", "domain"),
    [
        ("us.lgtvsdp.com", "platform", "LG core", "lgtvsdp.com"),  # must-allow, and the clock
        ("snu.lge.com", "platform", "LG core", "lge.com"),
        ("aic.cdpsvc.lgtvcommon.com", "vendor", "LG telemetry", "lgtvcommon.com"),
        ("us.ad.lgsmartad.com", "vendor", "LG ads", "lgsmartad.com"),
        ("pubads.g.doubleclick.net", "tracking", "3rd-party ads", "doubleclick.net"),
        ("ichnaea.netflix.com", "tracking", "3rd-party ads", "netflix.com"),
        ("api-global.netflix.com", "content", "Streaming", "netflix.com"),
        ("rr3---sn-q4fl6n6r.googlevideo.com", "content", "Streaming", "googlevideo.com"),
        ("ocsp.digicert.com", "shared", "Infra", "digicert.com"),
        ("d1abc.cloudfront.net", "shared", "Infra", "d1abc.cloudfront.net"),
        ("embeddedassistant.googleapis.com", "other", "Voice", "googleapis.com"),
        ("tracker.example.org", "unclassified", "Other", "example.org"),  # no category yet: nobody's
    ],
)
def test_a_name_is_sorted_by_what_the_profile_says_it_is(lg, name, cls, category, domain):
    kind = appfront.classify(lg, name)
    assert (kind.cls, kind.category, kind.domain) == (cls, category, domain)
    assert kind.unit == (domain, category) and kind.why


def test_the_unit_keeps_an_apps_measurement_host_apart_from_its_video(lg):
    """The reason the unit is the domain with its category, not the domain: one registrable domain can
    hold a streaming name and a measurement name."""
    video, beacon = (
        appfront.classify(lg, "api-global.netflix.com"),
        appfront.classify(lg, "ichnaea.netflix.com"),
    )
    assert video.domain == beacon.domain and video.unit != beacon.unit


def test_company_names_come_from_one_place_and_none_is_known_yet():
    assert appfront.company_of("api-global.netflix.com") is None


# ---- connections --------------------------------------------------------------------------------------
def test_a_connection_starts_at_its_hello_and_a_continuation_inherits_its_hello(tmp_path):
    s = Store(tmp_path / "s.db")
    s.talk(T + 10, "api-global.netflix.com", late=40.0)  # conntrack's start runs late
    sport = s.talk(T + 100, "rr1.googlevideo.com", seconds=500.0)
    # conntrack lost the entry mid-stream and opened a new one for the same connection, with no hello
    s.talk(T + 620, None, sport=sport, seconds=900.0, down_=5_000_000)
    s.talk(T + 200, None, dst="203.0.113.99")  # never named
    s.talk(T + 300, "x.example", dst=GW)  # the gateway itself
    s.talk(T + 300, None, dst="192.168.1.5")  # a probe of the home network
    got = appfront.connections(s.conn, A, B, GW)
    assert [(c.t - T, c.name, c.hello, c.down) for c in got] == [
        (10, "api-global.netflix.com", True, 9_000),
        (100, "rr1.googlevideo.com", True, 9_000),
        (100, "rr1.googlevideo.com", True, 5_000_000),
        (200, "", False, 9_000),
    ]
    assert "x.id" in appfront._HELLO_ID and appfront._HELLO_ID != queries.FLOW_NAME


def test_a_continuation_is_counted_under_the_app_its_connection_began_under(tmp_path):
    s = Store(tmp_path / "s.db")
    sport = s.talk(T + 100, "rr1.googlevideo.com", seconds=450.0)
    s.talk(T + 560, None, sport=sport, seconds=900.0)  # after the switch at 600 by conntrack's late clock
    tl = timeline(watched(T, T + 3600, (T, YT), (T + 500, NF)), [], A, B)
    assert [tl.label(c.t) for c in appfront.connections(s.conn, A, B, GW)] == [YT, YT]


# ---- pictures -----------------------------------------------------------------------------------------
def learned(lg, days: dict[int, list[str]], app_id: str = YT, key=appfront.unit_key):
    """Evidence from one evening session of `app_id` per day, each sending hellos to the names given."""
    evs, seen = [], []
    for d, hosts in days.items():
        t = evening(d)
        evs += watched(t, t + 3600, (t, app_id))
        seen += [(t + 60 + i, h, "") for i, h in enumerate(hosts)]
    tl = timeline(evs, [], H0, H0 + 40 * DAY)
    return appfront.learn(tl, sorted(seen), lg, key), tl


def test_a_unit_is_in_the_picture_from_the_day_after_it_was_first_seen_with_its_days_counted(lg):
    ev, _ = learned(
        lg, {d: ["rr1.googlevideo.com"] + (["cdn.example.net"] if d >= 3 else []) for d in range(7)}
    )
    video, late = ("googlevideo.com", "Streaming"), ("example.net", "Other")
    day0 = appfront.viewing_day(evening(0))
    assert ev.picture(YT, before=day0) == set()  # the first evening has nothing behind it
    assert ev.picture(YT, before=day0 + 1) == {video}
    assert ev.picture(YT, before=day0 + 3) == {video}  # the late name is new on the fourth evening
    assert ev.picture(YT, before=day0 + 4) == {video, late}
    # thin on one day, firm on two: every report says which
    assert ev.days_seen(YT, late, before=day0 + 4) == 1 and ev.days_seen(YT, late, before=day0 + 5) == 2
    assert ev.picture(YT, before=day0 + 4, min_days=appfront.PICTURE_FIRM_DAYS) == {video}
    assert ev.picture(YT, before=day0 + 5, min_days=appfront.PICTURE_FIRM_DAYS) == {video, late}
    # nothing is called new until the app has three earlier days
    assert not ev.ready(YT, day0 + 2) and ev.ready(YT, day0 + 3)
    assert ev.picture(YT) == {video, late} and ev.picture(NF) == set()
    assert (appfront.PICTURE_MIN_DAYS, appfront.PICTURE_FIRM_DAYS, appfront.PICTURE_READY_DAYS) == (1, 2, 3)


def test_the_platform_and_the_tv_makers_names_never_enter_a_picture(lg):
    hosts = ["us.lgtvsdp.com", "snu.lge.com", "us.ad.lgsmartad.com", "aic.cdpsvc.lgtvcommon.com"]
    ev, _ = learned(lg, {d: [*hosts, "pubads.g.doubleclick.net", "x.example.org"] for d in range(4)})
    assert ev.picture(YT) == {
        ("doubleclick.net", "3rd-party ads"),
        ("example.org", "Other"),
    }  # an advertiser can be usual; LG cannot
    assert len(ev.days[YT]) == 4  # the days still count as days the app was in front


def test_the_home_screen_an_input_and_a_cast_receiver_learn_no_picture(lg):
    for other in (HOME, HDMI, CAST):
        ev, _ = learned(lg, {d: ["rr1.googlevideo.com"] for d in range(4)}, app_id=other)
        assert ev.days == {} and ev.seen == {}


def test_an_evening_past_midnight_is_one_viewing_day(lg):
    t = evening(0, 23.5)
    tl = timeline(watched(t, t + 4 * HOUR, (t, YT)), [], H0, H0 + 3 * DAY)
    ev = appfront.learn(tl, [(t + 60, "rr1.googlevideo.com", ""), (t + 3 * HOUR, "i.ytimg.com", "")], lg)
    assert len(ev.days[YT]) == 1
    assert appfront.viewing_day(evening(1, 4.9)) == appfront.viewing_day(evening(0, 5.0))
    assert appfront.viewing_day(evening(1, 5.0)) == appfront.viewing_day(evening(0, 5.0)) + 1


def test_a_unit_shared_by_two_apps_is_in_both_pictures(lg):
    """A measurement service or a delivery network several apps use is each app's usual company; which
    apps share it is on record."""
    evs, seen = [], []
    for d in range(4):
        for hour, app_id in ((19, YT), (21, NF)):
            t = evening(d, hour)
            evs += watched(t, t + 3600, (t, app_id))
            seen += [(t + 60, "pubads.g.doubleclick.net", ""), (t + 61, "cdn.fastly.net", "")]
    ev = appfront.learn(timeline(evs, [], H0, H0 + 10 * DAY), sorted(seen), lg)
    assert ev.apps_with(("doubleclick.net", "3rd-party ads")) == [NF, YT]
    assert ev.apps_with(("cdn.fastly.net", "Infra")) == [NF, YT]


# ---- properties ----------------------------------------------------------------------------------------
def random_record(rng: random.Random, n: int = 60) -> tuple[list[Event], list[tuple[float, str, str]]]:
    """A live record and readings no TV would produce in this order: every kind of event at times that
    collide, sessions that come up twice, losses nobody saw, clock steps both ways."""
    apps = [YT, NF, PV, HOME, HDMI, ""]
    powers = [("Active", ""), ("Screen Saver", ""), ("Screen Off", ""), ("Active", "Request Power Off")]
    powers += [("Active Standby", ""), ("Suspend", ""), ("other", "")]
    evs = []
    for _ in range(n):
        t = T + rng.randrange(0, 4 * 3600, 30)  # a 30 s grid: many events share a time
        roll = rng.random()
        if roll < 0.40:
            evs.append(app(t, rng.choice(apps)))
        elif roll < 0.65:
            evs.append(power(t, *rng.choice(powers)))
        elif roll < 0.78:
            evs.append(up(t))
        elif roll < 0.90:
            evs.append(down(t))
        elif roll < 0.94:
            evs.append(Event(t, "alive"))
        elif roll < 0.96:
            evs.append(Event(t, "link", rng.choice(["up", "down"])))
        elif roll < 0.98:
            evs.append(Event(t, "watch", "start"))
        else:
            evs.append(clock(t, rng.choice([-90.0, 45.0, 600.0])))
    rows = [
        (
            T - HOUR + i * HOUR + rng.randrange(-60, 60),
            rng.choice(["Active", "Screen Saver", "unreachable"]),
            rng.choice(apps[:3]),
        )
        for i in range(7)
    ]
    return evs, rows


@pytest.mark.parametrize("seed", range(40))
def test_the_pieces_touch_never_overlap_and_cover_the_window(seed):
    evs, rows = random_record(random.Random(seed))
    tl = timeline(evs, rows, A, B)
    assert tl.pieces[0].t0 == A and tl.pieces[-1].t1 == B
    for p, q in zip(tl.pieces, tl.pieces[1:], strict=False):
        assert p.t1 == q.t0 and p.t0 < p.t1
    for p in tl.pieces:
        assert (p.cls == SESSION) == (p.session is not None)
        if p.session is not None:  # a piece lies inside its session
            assert p.session.start <= p.t0 and p.t1 <= p.session.end
    assert sum(tl.seconds().values()) == pytest.approx(B - A)


@pytest.mark.parametrize("seed", range(40))
def test_sessions_never_overlap_and_a_moment_belongs_to_one_at_most(seed):
    rng = random.Random(seed)
    evs, rows = random_record(rng)
    tl = timeline(evs, rows, A, B)
    ordered = tl.sessions
    for s, nxt in itertools.pairwise(ordered):
        assert s.start < s.end <= nxt.start
    for s in ordered:
        assert all(s.start <= i0 < i1 <= s.end for i0, i1 in s.idle)
    for _ in range(200):
        t = rng.uniform(A, B)
        _cls, s, led = tl.at(t)
        holding = [x for x in ordered if x.start <= t < x.end]
        assert len(holding) <= 1
        if led:  # the lead window hands the moment to the session about to begin, and to no other
            assert s is not None and s.leads and 0 < s.start - t <= tl.lead
        else:
            assert holding == ([s] if s is not None else [])


@pytest.mark.parametrize("seed", range(40))
def test_the_order_events_arrive_in_changes_nothing(seed):
    rng = random.Random(seed)
    evs, rows = random_record(rng)
    want = cut(timeline(evs, rows, A, B))
    for _ in range(5):
        mixed = evs + rng.sample(evs, k=len(evs) // 3)  # and a line read twice is one line
        rng.shuffle(mixed)
        assert cut(timeline(mixed, rows, A, B)) == want


@pytest.mark.parametrize("seed", range(20))
def test_a_picture_learned_from_fewer_days_is_inside_the_picture_learned_from_all(lg, seed):
    rng = random.Random(seed)
    pool = [
        "rr1.googlevideo.com",
        "i.ytimg.com",
        "cdn.example.net",
        "pubads.g.doubleclick.net",
        "a.fastly.net",
    ]
    days = {d: rng.sample(pool, k=rng.randint(1, len(pool))) for d in range(9)}
    everything, tl = learned(lg, days)
    seen = sorted((evening(d) + 60 + i, h, "") for d, hosts in days.items() for i, h in enumerate(hosts))
    all_days = sorted(everything.days[YT])
    for _ in range(10):
        some = set(rng.sample(all_days, k=rng.randint(0, len(all_days))))
        part = appfront.learn(tl, seen, lg, only_days=some)
        for m in (1, 2, 3):
            assert part.picture(YT, min_days=m) <= everything.picture(YT, min_days=m)
        # leaving a day out, or looking only at earlier days, can only take units away
        day = rng.choice(all_days)
        assert everything.picture(YT, without=day) <= everything.picture(YT)
        assert everything.picture(YT, before=day) <= everything.picture(YT, before=day + 1)


# ---- the TLS stack as a second witness ------------------------------------------------------------------
def test_a_stack_names_an_app_only_with_enough_hellos_nearly_all_under_it(monkeypatch):
    monkeypatch.setattr(appfront, "STACK_MIN", 10)
    tl = timeline(watched(T, T + 4000, (T, YT), (T + 1000, NF), (T + 2000, PV), (T + 3000, HOME)), [], A, B)
    seen = [(T + 10 + i, "a.example", "yt-stack") for i in range(19)] + [(T + 1010, "a.example", "yt-stack")]
    seen += [(T + 1100 + i, "b.example", "few") for i in range(9)]
    seen += [(T + 100 + 1000 * k + i, "c.example", "shared") for k in range(3) for i in range(5)]
    seen += [(T + 3100, "d.example", "home-only"), (T + 20, "e.example", "")]
    st = appfront.learn_stacks(tl, sorted(seen))
    assert st.verdict("yt-stack") == ("app", YT, 20, 0.95) and st.names("yt-stack") == YT
    assert st.verdict("few") == ("", NF, 9, 1.0) and st.names("few") is None  # too few to say
    assert st.verdict("shared")[0] == "system" and st.names("shared") is None
    assert st.verdict("home-only") == ("", None, 0, 0.0)  # the home screen's hellos teach nothing
    assert st.names("") is None and st.names("never-seen") is None
    # the day left out takes its hellos away: what is left may no longer be enough
    assert st.names("yt-stack", without=appfront.viewing_day(T)) is None
