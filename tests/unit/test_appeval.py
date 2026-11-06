"""(app in front) `tvgw receipt --evaluate` over a store whose every number is known: five evenings the
hourly readings saw, a sixth held by a `tvgw tvprobe` log, and the connections of each (design decision
67). The expected values are worked out in the comments beside the store, not copied from a run."""

import itertools
import json
import re
import time

import pytest
from appfront_store import GW, H0, HOME, NF, YT, Store, app, down, evening, power, probe_lines, up

from tvgw import appeval, appfront, cli, ledger

A, B = H0, evening(5, 26.0)
YT_STACK, NF_STACK, LG_STACK = (
    "t13d1516h2_aaaaaaaaaaaa_bbbbbbbbbbbb",
    "t13d1715h2_cccccccccccc_dddddddddddd",
    "t12d",
)


def record() -> list:
    """The sixth evening as the probe heard it: three attempts at a TV that was off, then one session.
    The home screen was in front; YouTube came to the front at 19:58:00 and Netflix at 21:30:00; the TV
    said it was switching off at 23:10 and the session was lost a minute later."""
    off = [down(evening(4, 24.5) + 60 * i, "OSError") for i in range(3)]
    t = evening(5, 19.0)
    return [
        *off,
        up(t + 3000),
        power(t + 3000, "Active"),
        app(t + 3000, HOME),
        app(t + 3480, YT),
        app(evening(5, 21.5), NF),
        power(evening(5, 23.0) + 600, "Active", "Request Power Off"),
        down(evening(5, 23.0) + 660),
    ]


@pytest.fixture
def store(tmp_path):
    s = Store(tmp_path / "s.db")
    for d in range(6):
        for hour, pw, front in (
            (19.33, "unreachable", None),
            (20.33, "Active", YT),
            (21.33, "Active", YT),
            (22.33, "Active", NF),
            (23.33, "Active" if d < 5 else "unreachable", NF if d < 5 else None),
            (24.33, "unreachable", None),
            (25.33, "unreachable", None),
        ):
            s.reading(evening(d, hour), pw, front)
        # YouTube's hour: a delivery host numbered by the evening, its images, an advertiser, LG's clock
        s.talk(evening(d, 20.5), f"rr{d}---sn-abc.googlevideo.com", down_=1_000_000, ja4=YT_STACK)
        s.talk(evening(d, 20.5) + 1, "i.ytimg.com", ja4=YT_STACK)
        s.talk(evening(d, 20.67), "pubads.g.doubleclick.net", ja4=YT_STACK)
        s.talk(evening(d, 20.75), "us.lgtvsdp.com", ja4=LG_STACK)
        # Netflix's hour
        s.talk(evening(d, 22.5), "api-global.netflix.com", ja4=NF_STACK)
        s.talk(evening(d, 22.5) + 1, "oca.nflxvideo.net", down_=2_000_000, ja4=NF_STACK)
        if d < 5:
            s.talk(evening(d, 22.67), "ichnaea.netflix.com", ja4=NF_STACK)
    s.talk(evening(3, 20.83), "new.example.org", ja4=YT_STACK)  # once, on the fourth evening
    s.talk(evening(2, 21.67), "between.example.org")  # the readings either side disagree: a gap
    s.talk(evening(1, 24.67), "asleep.example.org")  # the TV said off at both ends: none
    s.talk(evening(1, 24.68), "x.example", dst=GW)  # the gateway itself: not counted anywhere
    # the sixth evening, around the two app changes the probe heard
    yt, nf = evening(5, 19.0) + 3480, evening(5, 21.5)
    s.talk(yt - 1.5, "rr5---sn-abc.googlevideo.com", ja4=YT_STACK)  # before YouTube reached the front
    s.talk(yt + 4, "i.ytimg.com", ja4=YT_STACK)
    s.talk(nf - 1, "oca.nflxvideo.net", ja4=NF_STACK)  # before Netflix reached the front
    s.talk(nf + 10, "api-global.netflix.com", ja4=NF_STACK)
    s.talk(evening(5, 22.0), "d1.aiv-cdn.net", ja4=NF_STACK)  # new under Netflix
    s.talk(evening(5, 22.08), "us.ad.lgsmartad.com", ja4=LG_STACK)  # LG's advertising
    s.talk(evening(5, 22.17), "i.ytimg.com", ja4=YT_STACK)  # YouTube's, while Netflix was in front
    yield s
    s.conn.close()


@pytest.fixture
def result(store, lg):
    return appeval.evaluate(store.conn, lg, record(), A, B, GW, known_until=B, source="a file")


def test_the_record_section_counts_attempts_and_holds_the_readings_against_the_session(result):
    rec = result["record"]
    assert rec["events"] == {"app": 3, "conn": 5, "power": 2}
    assert (rec["live_sessions"], rec["live_hours"]) == (1, round(12060 / 3600, 2))  # 19:50 to 23:11
    assert (rec["attempts"], rec["attempts_failed"], rec["attempts_busiest_hour"]) == (4, 3, 3)
    assert rec["attempts_while_readings_said_off"] == 3  # the three at half past midnight
    assert rec["ended"] == {"OSError": 3, "lost": 1} and rec["lost_near_a_reading"] == 0
    # 20:20 and 21:20 said YouTube, 22:20 said Netflix: all three inside the session, all three agree
    assert (rec["readings_while_up"], rec["readings_judged"], rec["readings_power_agrees"]) == (3, 3, 3)
    assert (rec["readings_both_on"], rec["readings_app_agrees"]) == (3, 3)
    assert rec["readings_off_while_live_said_on"] == 0
    assert rec["off_to_loss_seconds"] == {"n": 1, "median": 60.0, "max": 60.0}
    assert rec["power_words"] == [
        {"state": "Active", "processing": "", "n": 1},
        {"state": "Active", "processing": "Request Power Off", "n": 1},
    ]
    assert rec["apps"] == {HOME: 1, YT: 1, NF: 1}


def test_a_reading_that_found_the_tv_off_while_the_session_was_up_is_counted(store, lg):
    """The sign that two sessions with one key do not get along: the hourly reading fails while the live
    session holds, and the session is lost at the reading."""
    store.reading(evening(5, 20.33), "unreachable", None)
    evs = [*record()[:-1], down(evening(5, 21.33) + 5), up(evening(5, 21.4)), app(evening(5, 21.4), YT)]
    evs.append(down(evening(5, 23.0)))
    rec = appeval.evaluate(store.conn, lg, evs, A, B, GW)["record"]
    assert rec["readings_off_while_live_said_on"] == 1 and rec["readings_power_agrees"] == 2
    assert rec["lost_near_a_reading"] == 1


def test_coverage_says_where_each_connection_started(result):
    cov = result["coverage"]
    # five evenings of 7 connections in hourly sessions, the fourth with one more; the sixth has 13, all
    # inside the live session; one in a gap, one while the TV said off; the gateway's own is left out
    assert cov["connections"] == 51 and cov["named"] == 51 and cov["timed_by_hello"] == 51
    by = cov["by_class"]
    assert [by[k]["conns"] for k in ("live", "hourly", "gap", "none")] == [13, 36, 1, 1]
    assert by["live"]["conns_share"] == round(13 / 51, 4)
    assert cov["in_lead_window"] == 2
    assert cov["sessions"] == {"hourly app": 10, "live app": 2, "live home": 1}
    assert {k: c["conns"] for k, c in cov["by_session_kind"].items()} == {"app": 49}
    assert sum(c["bytes"] for c in by.values()) == cov["bytes"]
    assert sum(cov["hours"].values()) == pytest.approx((B - A) / 3600, abs=0.05)


def test_composition_says_what_talked_under_each_app_by_what_the_profile_calls_it(result):
    comp = result["composition"]
    assert list(comp) == [NF, YT]  # by bytes
    # YouTube: on each of six evenings its video, its images, an advertiser and LG's clock; the stranger
    # on the fourth; two more of its own around the change on the sixth
    assert {k: c["conns"] for k, c in comp[YT]["by_class"].items()} == {
        "content": 14,
        "other": 1,
        "platform": 6,
        "tracking": 6,
    }
    assert {k: c["conns"] for k, c in comp[NF]["by_class"].items()} == {
        "content": 16,
        "tracking": 5,
        "vendor": 1,
    }
    assert comp[YT]["conns"] == 27 and comp[NF]["conns"] == 22
    assert sum(c["bytes_share"] for c in comp[YT]["by_class"].values()) == pytest.approx(1.0, abs=0.001)
    assert comp[YT]["idle_conns"] == 0


def test_composition_counts_what_started_behind_the_screen_saver_and_what_had_no_name(tmp_path, lg):
    s = Store(tmp_path / "s.db")
    t = evening(0)
    evs = [up(t), power(t, "Active"), app(t, YT), power(t + 600, "Screen Saver"), down(t + 3600)]
    evs += [up(t + 4000), power(t + 4000, "Active"), app(t + 4000, HOME), down(t + 5000)]
    s.talk(t + 60, "i.ytimg.com", down_=100)
    s.talk(t + 900, "rr1.googlevideo.com", down_=5_000)
    s.talk(t + 1000, None, down_=700)
    s.talk(t + 4100, "us.ad.lgsmartad.com")
    comp = appeval.evaluate(s.conn, lg, evs, A, B, GW)["composition"]
    assert (comp[YT]["conns"], comp[YT]["idle_conns"], comp[YT]["idle_bytes"]) == (3, 2, 6_000 + 700 + 1_000)
    assert comp[YT]["by_class"]["unnamed"] == {
        "conns": 1,
        "bytes": 1_700,
        "bytes_share": round(1700 / 8800, 4),
    }
    assert comp["(home)"]["by_class"] == {"vendor": {"conns": 1, "bytes": 10_000, "bytes_share": 1.0}}


def test_evidence_holds_the_tv_ports_counter_against_what_the_tv_was_doing(store, lg):
    """What a threshold for "the TV is probably on" has to separate: the bytes from the TV per ten minutes
    in a session, and in time the TV said it was off."""
    rx = 1_000_000
    for i in range(7):  # 20:20 to 21:20 on the first evening: two readings name YouTube
        ledger.record_sample(
            store.conn, ledger.Sample(t=evening(0, 20.34) + 600 * i, boot_id="b1", tv_rx_bytes=rx)
        )
        rx += 40_000 + 1_000 * i
    for i in range(6):  # 00:20 to 01:20: off at both ends
        ledger.record_sample(
            store.conn, ledger.Sample(t=evening(0, 24.34) + 600 * i, boot_id="b1", tv_rx_bytes=rx)
        )
        rx += 120
    # a reboot between two samples, and a counter that went down: neither is an interval
    ledger.record_sample(store.conn, ledger.Sample(t=evening(1, 24.34), boot_id="b1", tv_rx_bytes=rx))
    ledger.record_sample(
        store.conn, ledger.Sample(t=evening(1, 24.34) + 600, boot_id="b2", tv_rx_bytes=rx + 9)
    )
    ledger.record_sample(store.conn, ledger.Sample(t=evening(1, 24.34) + 1200, boot_id="b2", tv_rx_bytes=5))
    store.conn.commit()
    # the TV's first lookup after a quiet evening, 20 s before the session to it came up, and one attempt
    # in between that the TV was not ready for
    store.lookup(evening(5, 18.0), "us.lgtvsdp.com")
    woke = evening(5, 19.0) + 3000 - 20
    store.lookup(woke, "us.lgtvsdp.com")
    store.lookup(woke + 5, "snu.lge.com")
    evs = [*record(), down(woke + 10, "ConnectionRefusedError")]
    e = appeval.evaluate(store.conn, lg, evs, A, B, GW, known_until=B)["evidence"]
    assert (e["intervals_on"], e["intervals_off"]) == (5, 5)  # the interval that ends on the reading is mixed
    assert e["rx_bytes_per_600s_on"] == {"p0": 40_000, "p1": 40_000, "p10": 40_000, "p50": 42_000}
    assert e["rx_bytes_per_600s_off"] == {"p50": 120, "p90": 120, "p99": 120, "p100": 120}
    assert e["on_intervals_above_every_off_interval"] == 1.0
    assert (e["wakes"], e["first_lookup_to_session_seconds"]) == (1, {"n": 1, "median": 20.0, "max": 20.0})
    assert e["attempts_failed_between"] == 1


def test_evidence_on_a_store_without_samples_or_a_wake_says_nothing(result):
    e = result["evidence"]
    assert (e["intervals_on"], e["intervals_off"], e["wakes"]) == (0, 0, 0)
    assert e["rx_bytes_per_600s_on"] is None and e["first_lookup_to_session_seconds"] is None


def gen(result, app_id, unit, m):
    return next(
        g
        for g in result["generalization"]["rows"]
        if (g["app"], g["unit"], g["seen_on_other_days"]) == (app_id, unit, m)
    )


def test_a_picture_learned_from_the_other_days_is_tested_on_the_day_left_out(result):
    # YouTube: 3 connections a picture could hold on each of five evenings, 1 more on the fourth, 5 on
    # the sixth: 21. The one-evening name is outside; LG's clock is never the app's and is not counted
    g = gen(result, YT, "domain+category", 1)
    assert (g["days"], g["days_tested"], g["conns"], g["conns_inside"]) == (6, 6, 21, 20)
    assert g["conns_share"] == round(20 / 21, 4)
    assert gen(result, YT, "domain+category", 3)["conns_inside"] == 20  # every unit is on three other days
    # by full name the delivery host of each evening is new every evening: 7 more outside
    assert gen(result, YT, "name", 1)["conns_inside"] == 13
    assert gen(result, YT, "domain", 1)["conns_inside"] == 20
    # Netflix: 3 on each of five evenings, 6 on the sixth, of which Prime's delivery name and YouTube's
    # images were never seen under it
    g = gen(result, NF, "domain+category", 1)
    assert (g["conns"], g["conns_inside"]) == (21, 19)
    # content bytes: everything but the 10,000 bytes of the one-evening name's kind is content or not;
    # YouTube's content is its video and images, all inside
    assert gen(result, YT, "domain+category", 1)["content_bytes_share"] == 1.0
    cats = {
        (c["app"], c["category"], c["seen_on_other_days"]): c for c in result["generalization"]["by_category"]
    }
    assert (
        cats[(YT, "Other", 1)]["conns_share"] == 0.0 and cats[(YT, "3rd-party ads", 1)]["conns_share"] == 1.0
    )
    # Netflix's streaming names: 2 on each of five evenings and 6 on the sixth, the two strangers among them
    assert cats[(NF, "Streaming", 1)]["conns"] == 16 and cats[(NF, "Streaming", 1)]["conns_inside"] == 14


def test_the_day_left_out_never_feeds_its_own_picture(store, lg):
    """A name seen under the app on one day only is outside that day's picture, however often it was seen
    that day."""
    for i in range(20):
        store.talk(evening(4, 20.9) + i, "only-today.example.net")
    r = appeval.evaluate(store.conn, lg, record(), A, B, GW, known_until=B)
    g = gen(r, YT, "domain+category", 1)
    assert (g["conns"], g["conns_inside"]) == (41, 20)


def test_a_day_is_tested_only_when_the_app_has_enough_other_days(store, lg):
    r = appeval.evaluate(store.conn, lg, [], evening(4, 12.0), B, GW)  # two evenings, readings alone
    assert gen(r, YT, "domain+category", 1)["days_tested"] == 2
    g = gen(r, YT, "domain+category", 3)
    assert (g["days"], g["days_tested"], g["conns"], g["conns_share"]) == (2, 0, 0, None)


def test_lag_says_what_a_worse_signal_would_have_cost(result):
    lag = result["lag"]
    assert lag["conns_while_live"] == 13
    v = {x["variant"]: x for x in lag["variants"]}
    assert v["reports 2 s late"]["conns_moved"] == 0
    assert v["reports 5 s late"]["conns_moved"] == 1  # the images 4 s after YouTube came to the front
    assert v["reports 30 s late"]["conns_moved"] == 2 and v["reports 30 s late"]["to_an_app"] == 2
    assert v["lead window 3 s"]["conns_moved"] == 2  # the two that started just before each change
    # the readings alone keep the four between 20:20 and 21:20, where two readings name YouTube; the
    # hours around each change and the hour before the TV went off are gaps, and nine fall in them
    hourly = v["hourly readings alone"]
    assert (hourly["conns_moved"], hourly["to_an_app"]) == (9, 0)
    assert hourly["conns_share"] == round(9 / 13, 4)


def test_a_late_signal_also_keeps_an_app_in_front_after_the_tv_left_it(tmp_path, lg):
    """What started after the TV said it was switching off is nobody's; with the report 30 s late it would
    have been booked to the app. And what started outside the live session is not part of the comparison."""
    s = Store(tmp_path / "s.db")
    t = evening(0)
    evs = [
        up(t),
        power(t, "Active"),
        app(t, YT),
        power(t + 600, "Active", "Request Power Off"),
        down(t + 700),
    ]
    s.talk(t + 300, "i.ytimg.com")
    s.talk(t + 610, "us.lgtvsdp.com")
    s.talk(t + 5000, "i.ytimg.com")
    lag = appeval.evaluate(s.conn, lg, evs, A, B, GW)["lag"]
    v = {x["variant"]: x for x in lag["variants"]}
    assert lag["conns_while_live"] == 2
    assert (v["reports 5 s late"]["conns_moved"], v["reports 30 s late"]["conns_moved"]) == (0, 1)
    assert v["reports 30 s late"]["to_an_app"] == 1 and v["hourly readings alone"]["conns_moved"] == 2


def test_lead_says_how_long_before_an_app_change_its_names_start(result):
    ld = result["lead"]
    assert ld["app_changes"] == 2
    edges = ld["edges_seconds"]
    new = dict(zip(itertools.pairwise(edges), ld["bins"]["new"], strict=True))
    assert {k: n for k, n in new.items() if n} == {(-2, -1): 1, (-1, 0): 1, (2, 5): 1, (10, 30): 1}
    assert sum(ld["bins"]["all"]) == 4 and sum(ld["bins"]["old"]) == 0
    assert (ld["new_names_before_the_change"], ld["new_names_after_the_change"]) == (2, 2)
    assert ld["new_names_lead_seconds"] == {"median": 1.25, "p90": 1.5, "max": 1.5}


def test_outsiders_are_listed_with_the_reason_only_once_the_picture_is_ready(result):
    o = result["outsiders"]
    # the sixth evening is the first with five earlier days behind each app
    assert (o["app_days_ready"], o["app_days_not_ready"]) == (2, 10)
    assert list(o["by_app"]) == [NF]  # everything under YouTube that evening was its own or LG's clock
    got = {(x["domain"], x["category"]): (x["conns"], x["why"]) for x in o["by_app"][NF]}
    assert got == {
        ("aiv-cdn.net", "Streaming"): (1, "new under this app"),
        ("lgsmartad.com", "LG ads"): (1, "LG ads: the TV maker's, not an app's"),
        ("ytimg.com", "Streaming"): (1, "new under this app; in the picture of youtube.leanback.v4"),
    }


def test_a_name_seen_on_too_few_earlier_days_says_how_many(store, lg):
    for d in (3, 4, 5):
        store.talk(evening(d, 22.6), "late.example.net")
    o = appeval.evaluate(store.conn, lg, record(), A, B, GW, known_until=B)["outsiders"]
    row = next(x for x in o["by_app"][NF] if x["domain"] == "example.net")
    assert row["why"] == "seen on 2 earlier days, 3 needed"


def test_stacks_say_how_pure_each_tls_stack_is_for_its_app(result, monkeypatch):
    st = result["stacks"]
    assert st["available"] and st["stacks"] == 3
    rows = {x["ja4"]: x for x in st["rows"]}
    # YouTube's stack: 3 hellos on each of five evenings, 4 on the fourth, 5 on the sixth under YouTube,
    # and once under Netflix
    assert (rows[YT_STACK]["hellos"], rows[YT_STACK]["apps"], rows[YT_STACK]["top_app"]) == (22, 2, YT)
    assert rows[YT_STACK]["purity"] == round(21 / 22, 3) and rows[YT_STACK]["verdict"] == ""
    assert rows[NF_STACK]["purity"] == 1.0 and rows[LG_STACK]["apps"] == 2
    assert st["agreement"] == 0.0  # no stack has the 200 hellos a verdict needs


def test_a_stack_with_enough_hellos_names_its_app(store, lg, monkeypatch):
    monkeypatch.setattr(appeval, "STACK_MIN", 20)
    st = appeval.evaluate(store.conn, lg, record(), A, B, GW, known_until=B)["stacks"]
    rows = {x["ja4"]: x["verdict"] for x in st["rows"]}
    assert rows == {YT_STACK: f"names {YT}", NF_STACK: f"names {NF}", LG_STACK: ""}
    # 14 content hellos under YouTube, all on its stack; 16 under Netflix, one of them on YouTube's
    assert st["content_hellos"] == 30 and st["agreement"] == round(29 / 30, 4)


def test_a_store_without_ja4_says_so(tmp_path, lg):
    s = Store(tmp_path / "s.db")
    s.reading(evening(0, 20.33), "Active", YT)
    s.reading(evening(0, 21.33), "Active", YT)
    s.talk(evening(0, 20.5), "i.ytimg.com")
    r = appeval.evaluate(s.conn, lg, [], A, B, GW)
    assert r["stacks"] == {"available": False}
    assert "holds no JA4" in "\n".join(appeval.render(r))


def test_an_empty_store_evaluates_to_zeros_and_renders(tmp_path, lg):
    s = Store(tmp_path / "s.db")
    r = appeval.evaluate(s.conn, lg, [], A, B, GW)
    assert r["coverage"]["connections"] == 0 and r["generalization"]["rows"] == []
    assert r["lag"]["conns_while_live"] == 0 and r["lead"]["new_names_lead_seconds"] is None
    text = "\n".join(appeval.render(r))
    assert "no app has connections on a day to test" in text and "outsiders" in text


def test_attempts_are_the_sessions_that_came_up_and_the_failures_that_ended_none():
    evs = [down(10, "OSError"), up(20), down(30), down(40, "OSError"), up(50), up(60), down(70)]
    assert appeval.attempts(evs) == [(10, False), (20, True), (40, False), (50, True), (60, True)]
    assert appeval.busiest_hour([0, 10, 3599, 3600, 3601, 9000]) == 4  # the hour from 10 holds four
    assert appeval.busiest_hour([0, 3600, 7200]) == 1
    assert appeval.busiest_hour([]) == 0


FORBIDDEN = re.compile(r"\b\d{1,3}(?:\.\d{1,3}){3}\b|\b20\d\d-\d\d|\b\d\d:\d\d\b")


def test_what_it_prints_is_safe_to_paste(result, store, lg):
    """Numbers, app ids, registrable domains and categories: no address, no date, no time of day, no full
    host name, and nothing of the reason a session failed but its first word."""
    text = "\n".join(appeval.render(result))
    assert not FORBIDDEN.search(text), FORBIDDEN.search(text)
    for host in ("rr5---sn-abc", "api-global", "pubads", "us.ad.", "i.ytimg.com", "10.10.10"):
        assert host not in text
    for shown in ("ytimg.com", "lgsmartad.com", "LG ads", YT, NF, "Request Power Off"):
        assert shown in text
    assert not FORBIDDEN.search(json.dumps(result))


def test_the_command_reads_a_probe_log_and_a_store_that_has_no_live_table(
    store, tmp_path, monkeypatch, capsys
):
    """What the first evaluation runs: this branch's code, read-only, against a store written by the
    release before it and the events file of a `tvgw tvprobe` run."""
    log = tmp_path / "tvprobe.jsonl"
    log.write_text(probe_lines(record()), encoding="utf-8")
    store.conn.execute("DROP TABLE IF EXISTS tv_events")
    store.conn.commit()
    monkeypatch.setattr(time, "time", lambda: B)
    conf = tmp_path / "tvgw.conf"
    conf.write_text("PROFILE=lg-webos\n", encoding="utf-8")
    argv = [
        "--conf",
        str(conf),
        "--db",
        store.path,
        "receipt",
        "--evaluate",
        "--since",
        "6d",
        "--events",
        str(log),
    ]
    assert cli.main(argv) == 0
    out = capsys.readouterr().out
    assert "live record from a file" in out and "live session" in out
    assert re.search(r"live session\s+\S+\s+13\s", out) and re.search(r"hourly session\s+\S+\s+36\s", out)
    assert not FORBIDDEN.search(out)
    assert cli.main([*argv, "--json"]) == 0
    data = json.loads(capsys.readouterr().out)
    assert data["coverage"]["by_class"]["live"]["conns"] == 13 and data["record"]["attempts"] == 4
    # without a file the live record is the store's, and a store with none evaluates on its readings
    assert cli.main(argv[:-2]) == 0
    out = capsys.readouterr().out
    assert "live record from the store" in out and re.search(r"live session\s+\S+\s+0\s", out)


def test_an_events_file_that_is_not_there_is_an_error_not_a_trace(store, tmp_path, capsys):
    conf = tmp_path / "tvgw.conf"
    conf.write_text("", encoding="utf-8")
    argv = [
        "--conf",
        str(conf),
        "--db",
        store.path,
        "receipt",
        "--evaluate",
        "--events",
        str(tmp_path / "no"),
    ]
    assert cli.main(argv) == 1
    assert "cannot read" in capsys.readouterr().err


def test_the_probe_format_and_the_event_list_evaluate_alike(store, lg, tmp_path):
    log = tmp_path / "p.jsonl"
    log.write_text(probe_lines(record()), encoding="utf-8")
    a = appeval.evaluate(store.conn, lg, appfront.read_events(str(log)), A, B, GW, known_until=B)
    b = appeval.evaluate(store.conn, lg, record(), A, B, GW, known_until=B)
    for part in (
        "evidence",
        "coverage",
        "composition",
        "generalization",
        "lag",
        "lead",
        "outsiders",
        "stacks",
    ):
        assert a[part] == b[part]
