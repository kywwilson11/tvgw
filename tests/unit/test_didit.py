"""(did it work) Failed app starts from the live record and the hourly readings, joined with what the filter
refused in the same minutes, and the probation hook `didit.since` (design decision 72). Every line that
names an app, a time or a name is the interactive run's; what a persisted report may carry is counts."""

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


@pytest.fixture
def store(tmp_path):
    return Store(tmp_path / "s.db")


def opened(t0: float, *stays: tuple[str, float, float]) -> list:
    """A session to the TV from `t0`, the home screen in front, then each (app, at, seconds): the app came to
    the front at `at` and the TV went back to the home screen `seconds` later. Down two hours on."""
    out = [up(t0), power(t0, "Active"), app(t0, HOME)]
    for app_id, at, seconds in stays:
        out += [app(at, app_id), app(at + seconds, HOME)]
    return [*out, down(t0 + 7200)]


def found(store, lg, events, a=None, b=None, now=LATER, ev=None):
    a = T - 3600 if a is None else a
    b = T + 3600 if b is None else b
    back = a - didit.LOOKBACK
    tl = appfront.timeline(events, appfront.readings(store.conn, back, b), back, b)
    return didit.find(store.conn, lg, tl, appfront.connections(store.conn, a, b, GW), a, b, now, ev=ev)


# ---- on timing alone -------------------------------------------------------------------------------------------
def test_an_app_that_went_back_home_three_times_in_a_minute_is_a_failed_start(store, lg):
    events = opened(T - 600, (NF, T, 15), (NF, T + 40, 12), (NF, T + 80, 18))
    store.talk(T + 2, "netflix.com", down_=40_000)
    (f,) = found(store, lg, events)
    assert (f.app, f.timed, f.kind, f.times, f.longest, f.down) == (NF, "live", "quick", 3, 18, 40_000)
    assert (f.start, f.end, f.causes, f.likely, f.reported) == (T, T + 98, [], [], True)
    assert didit.describe(f) == (
        "Netflix opened 3 times from 20:14, and each time the TV went back to the home screen within 18"
        " seconds (39.1 KB down); the filter refused no lookup in those minutes"
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


def test_an_input_or_the_home_screen_is_never_a_failed_start(store, lg):
    events = opened(T - 600, ("com.webos.app.hdmi1", T, 10), ("com.webos.app.hdmi1", T + 30, 10))
    assert found(store, lg, events) == []


def test_a_quick_exit_that_brought_much_down_worked(store, lg):
    store.talk(T + 1, "nflxvideo.net", down_=5 * 1024 * 1024)
    events = opened(T - 600, (NF, T, 15), (NF, T + 40, 15))
    back = T - 3600 - didit.LOOKBACK
    tl = appfront.timeline(events, [], back, T + 3600)
    conns = appfront.connections(store.conn, T - 3600, T + 3600, GW)
    (e,) = didit.episodes(tl, conns, T - 3600, T + 3600, LATER)
    assert (e.start, e.times) == (T + 40, 1)  # the first stay brought 5 MB down: only the second is one
    assert found(store, lg, events) == []  # and one quick exit needs a cause


def test_a_stall_counts_once_its_bytes_have_settled_and_not_before(store, lg):
    store.talk(T + 2, "netflix.com", down_=200_000)
    events = opened(T - 600, (NF, T, 180))
    (f,) = found(store, lg, events)
    assert (f.kind, f.times, f.longest, f.reported) == ("stalled", 1, 180, True)
    assert didit.describe(f).startswith(
        "Netflix opened at 20:14 and stayed 3 min with only 195.3 KB down, then the TV went back to the"
        " home screen;"
    )
    assert found(store, lg, events, now=T + 600) == []  # a start that worked reads the same until then
    assert found(store, lg, opened(T - 600, (NF, T, didit.STALL_MAX + 1))) == []  # too long to be a start


def test_before_the_bytes_settle_a_quick_exit_says_they_are_still_being_counted(store, lg):
    (f,) = found(store, lg, opened(T - 600, (NF, T, 15), (NF, T + 40, 15)), now=T + 600)
    assert f.down is None and "(its downloads are still being counted)" in didit.describe(f)


# ---- with a likely cause ------------------------------------------------------------------------------------------
def test_a_name_refused_for_the_first_time_in_that_minute_is_the_likely_cause(store, lg):
    store.lookup(T + 2, "api.example.net", blocked=1)
    store.lookup(T + 3, "api.example.net", blocked=1)
    (f,) = found(store, lg, opened(T - 600, (NF, T, 15)))
    (c,) = f.causes
    assert (c.name, c.lookups, c.first_sight, c.tracking, c.needed, c.likely) == (
        "api.example.net",
        2,
        True,
        False,
        None,
        True,
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
    assert "the filter refused only names it refuses on purpose or refused before (1)" in didit.describe(f)


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
    assert text.endswith(", and 1 more name like it: sudo tvgw check snu.lge.com")


def test_a_site_the_app_reached_on_earlier_days_is_a_likely_cause_even_when_refused_before(store, lg):
    store.lookup(T - 2 * 86400, "api.example.net", blocked=1)
    store.lookup(T + 2, "api.example.net", blocked=1)
    ev = appfront.Evidence()
    unit = appfront.classify(lg, "api.example.net").unit
    ev.seen[NF] = {unit: {appfront.viewing_day(T) - d for d in (1, 2, 4)}}
    (f,) = found(store, lg, opened(T - 600, (NF, T, 15)), ev=ev)
    c = f.causes[0]
    assert (c.app_days, c.first_sight, c.likely) == (3, False, True)
    assert "whose site Netflix reached on 3 earlier days" in didit.describe(f)


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


def test_another_readers_refusal_is_judged_beside_the_filters(store, lg):
    back = T - 3600 - didit.LOOKBACK
    tl = appfront.timeline(opened(T - 600, (NF, T, 15), (NF, T + 40, 15)), [], back, T + 3600)
    kernel = didit.Refusal(T + 4, "203-0-113-9.example.net", None, "firewall")
    (f,) = didit.find(store.conn, lg, tl, [], T - 3600, T + 3600, LATER, extra=[kernel])
    (c,) = f.causes
    assert (c.source, c.first_sight, c.likely) == ("firewall", False, False)  # no history to call it new


# ---- from the hourly readings --------------------------------------------------------------------------------------
def readings(store, power_="Active", front=NF):
    store.reading(T, power_, front)
    store.reading(T + 3600, power_, front)


def test_an_hourly_session_with_little_down_and_a_new_refusal_is_a_weaker_sign(store, lg):
    readings(store)
    store.talk(T + 600, "netflix.com", down_=2_000_000)
    store.lookup(T + 900, "api.example.net", blocked=1)
    (f,) = found(store, lg, [], a=T - 60, b=T + 7200)
    assert (f.timed, f.kind, f.times, f.down) == ("hourly", "hourly", 1, 2_000_000)
    assert didit.describe(f) == (
        "Netflix was in front at 20:14 and at 21:14 with only 1.9 MB down (times to the hour, a weaker"
        " sign: an app left on its menu reads the same); between those readings the filter refused"
        " api.example.net (other services), which it had not refused before: sudo tvgw check api.example.net"
    )


def test_an_hourly_session_is_shown_only_with_a_likely_cause(store, lg):
    readings(store)
    assert found(store, lg, [], a=T - 60, b=T + 7200) == []


@pytest.mark.parametrize(("power_", "down_"), [("Screen Saver", 0), ("Active", 50 * 1024 * 1024)])
def test_an_hourly_session_behind_the_screen_saver_or_with_video_is_no_sign(store, lg, power_, down_):
    readings(store, power_)
    store.talk(T + 600, "nflxvideo.net", down_=down_)
    store.lookup(T + 900, "api.example.net", blocked=1)
    assert found(store, lg, [], a=T - 60, b=T + 7200) == []


# ---- the record's order does not matter -----------------------------------------------------------------------------
def test_the_same_record_in_any_order_gives_the_same_failed_starts(store, lg):
    events = opened(T - 600, (NF, T, 15), (NF, T + 40, 12), (YT, T + 300, 900), (NF, T + 1300, 9))
    store.lookup(T + 2, "api.example.net", blocked=1)
    want = [f.as_dict() for f in found(store, lg, events)]
    rng = random.Random(72)
    for _ in range(20):
        shuffled = events[:]
        rng.shuffle(shuffled)
        assert [f.as_dict() for f in found(store, lg, shuffled)] == want


# ---- the probation hook ----------------------------------------------------------------------------------------------
def test_since_says_broke_with_the_failed_starts_and_their_causes(store, lg):
    for e in opened(T - 600, (NF, T, 15), (NF, T + 40, 15)):
        store.conn.execute(
            "INSERT INTO tv_events(t, kind, value, detail) VALUES (?,?,?,?)", (e.t, e.kind, e.value, e.detail)
        )
    store.lookup(T + 2, "api.example.net", blocked=1)
    v = didit.since(store.conn, lg, T - 60, LATER, gw_ip=GW)
    assert (v.state, len(v.failed), [c.name for c in v.causes]) == ("broke", 1, ["api.example.net"])
    assert v.covered_until == T + 2 and v.why.startswith("1 app start may have failed since ")
    assert v.as_dict()["causes"][0]["likely"] is True


def test_since_says_clean_only_when_an_app_started_and_worked(store, lg):
    events = opened(T - 600, (NF, T, 1800))
    store.talk(T + 5, "nflxvideo.net", down_=300 * 1024 * 1024)
    store.lookup(T + 1, "nflxvideo.net")
    v = didit.since(store.conn, lg, T - 60, LATER, gw_ip=GW, events=events)
    assert (v.state, v.worked, v.failed) == ("clean", 1, [])
    assert v.why.startswith("1 app start worked since ")


def test_since_with_nothing_started_is_unknown_never_clean(store, lg):
    store.lookup(T + 1, "lgtvonline.lge.com")
    v = didit.since(store.conn, lg, T - 60, LATER, gw_ip=GW)
    assert (v.state, v.worked) == ("unknown", 0) and "no app start since" in v.why
    empty = didit.since(store.conn, lg, T + 60, LATER, gw_ip=GW)
    assert empty.state == "unknown" and empty.why.startswith("the record holds no lookup since")


def test_since_takes_the_minutes_the_store_has_not_loaded_yet(store, lg):
    """The live reading's own lines and AdGuard's newest lookups, passed in: a caller need not wait an hour."""
    events = opened(T - 600, (NF, T, 15))
    fresh = [didit.Refusal(T + 2, "api.example.net")]
    v = didit.since(store.conn, lg, T - 60, T + 120, gw_ip=GW, events=events, extra=fresh)
    assert v.state == "broke" and v.causes[0].name == "api.example.net" and v.covered_until == T + 2


# ---- what a persisted report may carry -----------------------------------------------------------------------------
def test_the_summary_is_counts_only_and_its_line_names_no_app_time_or_name(store, lg):
    store.lookup(T + 2, "api.example.net", blocked=1)
    got = found(store, lg, opened(T - 600, (NF, T, 15), (YT, T + 1800, 10), (YT, T + 1830, 10)))
    s = didit.summary(got)
    assert s == {"starts": 2, "with_cause": 1, "hourly": 0}
    line = didit.summary_line(s, "2026-10-29")
    assert line == (
        "2 app starts may have failed, and in the minutes of 1 of them the filter refused a name it does"
        " not usually refuse. Which app and which name: sudo tvgw receipt --since 2026-10-29"
    )
    assert not re.search(r"Netflix|YouTube|example|\d\d:\d\d", line)
    one = didit.summary_line({"starts": 1, "with_cause": 0, "hourly": 0}, "2026-10-29")
    assert one.startswith("One app start may have failed; the filter refused no name it does not usually")


def test_no_line_claims_who_acted_or_why(store, lg):
    """A refusal in the same minutes is a match in time: the receipt's forbidden words hold here too."""
    store.lookup(T + 2, "api.example.net", blocked=1)
    store.lookup(T + 3, "snu.lge.com", blocked=1)
    readings(store)
    lines = []
    for f in found(store, lg, opened(T - 600, (NF, T, 15), (NF, T + 40, 120)), a=T - 60, b=T + 7200):
        lines.append(didit.describe(f))
    lines += didit.section(found(store, lg, opened(T - 600, (NF, T, 15))))
    lines.append(didit.summary_line({"starts": 3, "with_cause": 2, "hourly": 1}, "2026-10-29"))
    assert lines and not [x for x in lines if receipt.FORBIDDEN.search(x)]


# ---- the receipt's section -------------------------------------------------------------------------------------------
def stored(store, events):
    store.conn.executemany(
        "INSERT INTO tv_events(t, kind, value, detail) VALUES (?,?,?,?)",
        [(e.t, e.kind, e.value, e.detail) for e in events],
    )
    store.conn.commit()


def test_the_receipt_opens_with_the_evenings_failed_starts(store, tmp_path, monkeypatch, capsys):
    monkeypatch.setattr(time, "time", lambda: LATER)
    stored(store, opened(T - 600, (NF, T, 15), (NF, T + 40, 12), (YT, T + 300, 1800)))
    store.lookup(T + 2, "api.example.net", blocked=1)
    conf = tmp_path / "tvgw.conf"
    conf.write_text("", encoding="utf-8")
    base = ["--conf", str(conf), "--db", store.path, "receipt"]
    assert cli.main(base) == 0
    out = capsys.readouterr().out.splitlines()
    assert out[1] == (
        "Did it work? Apps that went back to the home screen soon after they opened, with little down:"
    )
    assert out[2].startswith(
        "  Netflix opened 2 times from 20:14, and each time the TV went back to the home"
    )
    assert "sudo tvgw check api.example.net." in " ".join(out[2:5])
    assert cli.main([*base, "--json"]) == 0
    (f,) = json.loads(capsys.readouterr().out)["failed_starts"]
    assert (f["app"], f["times"], f["causes"][0]["name"]) == (NF, 2, "api.example.net")
    assert cli.main([*base, "--since", "2d"]) == 0
    assert "  Netflix opened 2 times from 20:14" in capsys.readouterr().out


def test_a_receipt_with_no_failed_start_is_as_it_was(store, tmp_path, monkeypatch, capsys):
    monkeypatch.setattr(time, "time", lambda: LATER)
    stored(store, opened(T - 600, (YT, T + 300, 1800)))
    conf = tmp_path / "tvgw.conf"
    conf.write_text("", encoding="utf-8")
    assert cli.main(["--conf", str(conf), "--db", store.path, "receipt"]) == 0
    assert "Did it work?" not in capsys.readouterr().out


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
    text = out.getvalue()
    assert (
        "\nDid it work (app starts that may have failed; a report, nothing changes on its own):\n"
        "  2 app starts may have failed, and in the minutes of 1 of them the filter refused a name it does"
        " not usually refuse. Which app and which name: sudo tvgw receipt --since 2026-10-29\n"
    ) in text
    note = [x for x in plain.plain_brief(o, profile=lg) if x.startswith("  Apps:")]
    assert note == [
        "  Apps: 2 app starts may have failed, and in the minutes of 1 of them the filter refused a name it"
        " does not usually refuse. Which app and which name: sudo tvgw receipt --since 2026-10-29"
    ]


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
