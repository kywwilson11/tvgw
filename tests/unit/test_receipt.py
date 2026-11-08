"""(app in front) `tvgw receipt`: the evening screen, the receipt, the picture, the replay and why, over the
six evenings of test_appeval's store (design decision 67). What each view says, and what none of them may
ever say."""

import io
import json
import re
import time

import pytest
from appfront_store import GW, HDMI, HOME, NF, YT, Store, app, down, evening, power, up
from test_appeval import A, B, record, store  # noqa: F401 - `store` is the fixture

from tvgw import appfront, cli, db, queries, receipt

NOW = B + 86400  # a day after the last evening: everything has settled


@pytest.fixture
def rec(store, lg):  # noqa: F811
    store.lookup(evening(5, 22.0), "pubads.g.doubleclick.net", blocked=1)
    store.lookup(evening(5, 22.0) + 5, "pubads.g.doubleclick.net", blocked=1)
    store.lookup(evening(5, 22.1), "us.info.lgsmartad.com", blocked=1)
    store.lookup(evening(5, 22.2), "api-global.netflix.com", blocked=0)
    store.talk(evening(5, 22.3), None, dst="203.0.113.77", down_=4_000)  # never named
    return receipt.gather(store.conn, lg, GW, A, B, record(), known_until=B, now=NOW)


def text(lines) -> str:
    return "\n".join(lines)


def session(found, app_id, timed="live"):
    return next(r for r in found if r["app"] == app_id and r["timed"] == timed)


# ---- the receipt's data --------------------------------------------------------------------------------------
def test_a_session_sorts_what_started_under_it_by_what_each_name_is(rec):
    found = receipt.receipts(rec, since=evening(5, 12.0))
    assert [(r["app"], r["timed"]) for r in found] == [(HOME, "live"), (YT, "live"), (NF, "live")]
    nf = session(found, NF)
    assert (nf["ready"], nf["days_behind"], nf["conns"], nf["settling"]) == (True, 5, 8, False)
    groups = {g: [(r["name"], r["conns"]) for r in rows] for g, rows in nf["groups"].items() if rows}
    assert groups == {
        "before": [("nflxvideo.net", 2), ("netflix.com", 2)],  # by bytes: the video first; by site
        "tracking": [("us.ad.lgsmartad.com", 1)],  # LG's advertising is advertising; by full name
        "new": [("aiv-cdn.net", 1), ("ytimg.com", 1)],
    }
    assert nf["groups"]["before"][0]["days_seen"] == 5
    assert nf["groups"]["new"][1]["also_with"] == [YT] and nf["groups"]["new"][0]["also_with"] == []
    assert nf["unnamed"] == {"conns": 1, "bytes": 5_000}
    assert nf["refused"] == {
        "lookups": 3,
        "names": [
            {"name": "pubads.g.doubleclick.net", "plain": "advertising or app measurement", "lookups": 2},
            {"name": "us.info.lgsmartad.com", "plain": "LG advertising", "lookups": 1},
        ],
    }
    yt = session(found, YT)
    assert [r["name"] for r in yt["groups"]["tv"]] == ["lgtvsdp.com"]  # the clock: the TV's own
    assert [r["name"] for r in yt["groups"]["tracking"]] == ["pubads.g.doubleclick.net"]


def test_the_tv_makers_other_services_are_listed_with_the_tvs_own_not_as_advertising(store, lg):  # noqa: F811
    """Only the maker's advertising, usage reporting and fingerprinting are advertising and measurement; its
    smart-home links (LG IoT, an AWS IoT endpoint among them) sit with the TV's own services."""
    t = evening(5, 22.0)
    store.talk(t, "lgthinq.com")  # LG IoT
    store.talk(t + 1, "a1b2c3d4-ats.iot.us-east-1.amazonaws.com")  # LG IoT, by its pattern
    store.talk(t + 2, "rdx2.lgtvsdp.com")  # LG telemetry: usage reporting
    rec = receipt.gather(store.conn, lg, GW, A, B, record(), known_until=B, now=NOW)
    nf = session(receipt.receipts(rec, since=evening(5, 12.0)), NF)
    tracking = [r["name"] for r in nf["groups"]["tracking"]]
    assert "rdx2.lgtvsdp.com" in tracking and "us.ad.lgsmartad.com" in tracking
    assert not any("lgthinq" in n or "amazonaws" in n for n in tracking)
    assert {r["name"] for r in nf["groups"]["tv"]} >= {"lgthinq.com", "us-east-1.amazonaws.com"}
    body = text(receipt.render_receipt(nf))
    assert "  The TV's own services (clock, sign-in, updates) and its maker's other services" in body
    assert "lgthinq.com, smart-home links: 1 connection" in body
    advertising = [
        ln
        for ln in text(receipt.render_evening(rec, receipt.evening(rec))).splitlines()
        if "measurement" in ln
    ]
    assert advertising and not any("lgthinq" in ln for ln in advertising)
    assert receipt.why(rec, "lgthinq.com")[0].endswith(
        "It is listed with the TV's own services while an app is in front, never as the app's."
    )
    assert "under advertising and measurement" in receipt.why(rec, "rdx2.lgtvsdp.com")[0]
    yt = session(receipt.receipts(rec, since=evening(5, 12.0)), YT)
    assert yt["groups"]["tv"] and "maker's" not in text(receipt.render_receipt(yt))  # only the clock there


def test_a_session_after_a_loss_says_so_instead_of_claiming_it_was_there_first(tmp_path, lg):
    s = Store(tmp_path / "s.db")
    t = evening(0)
    evs = [up(t), power(t, "Active"), app(t, YT), down(t + 1800), up(t + 2100), power(t + 2100, "Active")]
    evs += [app(t + 2100, YT), down(t + 3600)]
    first, second = receipt.receipts(receipt.gather(s.conn, lg, GW, A, B, evs, now=NOW))
    assert "lost_from" not in first and second["lost_from"] == t + 1800
    out = text(receipt.render_receipt(second))
    assert "The gateway had lost touch with the TV from 20:30" in out and "started listening" not in out
    assert "The gateway started listening while it was in front" in text(receipt.render_receipt(first))


# ---- the receipt in words ------------------------------------------------------------------------------------
def test_the_receipt_reads_in_plain_words(rec):
    nf = session(receipt.receipts(rec, since=evening(5, 12.0)), NF)
    out = receipt.render_receipt(nf)
    assert out[:3] == [
        "Netflix",  # no app identifier in the heading
        "  Sat 31 Oct 21:30 to 23:10 (1 h 40 min)",
        "  8 connections started while it was in front: 2.0 MB down, 7.8 KB up",
    ]
    body = text(out)
    for part in (
        "  New for Netflix (not seen with it on any earlier day)\n    aiv-cdn.net, streaming: 1 connection, 9.8 KB\n",
        "    ytimg.com, streaming: 1 connection, 9.8 KB (usually with YouTube)\n",
        "  Advertising and measurement while Netflix was in front\n    us.ad.lgsmartad.com, LG advertising:",
        "  Seen with Netflix before\n    nflxvideo.net, streaming: 2 connections, 1.9 MB (on 5 of Netflix's 5 earlier days)",
        "  No name was captured for 1 connection (4.9 KB).",
        "  Asked for 2 blocked names 3 times while Netflix was in front, every one refused:\n"
        "      pubads.g.doubleclick.net 2 (advertising or app measurement), us.info.lgsmartad.com 1 (LG\n"
        "      advertising)",
    ):
        assert part in body, part
    assert "The TV's own services" not in body  # Netflix's hour had none
    assert all(len(line) <= receipt.WIDTH + 8 for line in out)


def test_a_session_with_nothing_new_says_so_without_a_clean_bill(rec):
    yt = session(receipt.receipts(rec, since=evening(5, 12.0)), YT)
    assert yt["conns"] == 6 and yt["groups"]["new"] == [] and yt["start_exact"]
    out = text(receipt.render_receipt(yt))
    assert "  No name was new for YouTube." in out
    assert "  Advertising and measurement while YouTube was in front\n    pubads.g.doubleclick.net" in out
    assert "  The TV's own services (clock, sign-in, updates)\n    lgtvsdp.com, LG's own services" in out
    assert "  No lookup was refused while YouTube was in front." in out
    assert "Nothing new" not in out


def test_a_session_from_the_hourly_readings_claims_no_duration(rec):
    first = receipt.receipts(rec, since=A)[0]
    assert (first["app"], first["timed"], first["ready"], first["days_behind"]) == (YT, "hourly", False, 0)
    out = receipt.render_receipt(first)
    body = re.sub(r"\n\s+", " ", text(out))
    assert (
        "Mon 26 Oct, seen in front at 20:19 and at 21:19; it may have started earlier and run longer" in body
    )
    assert "(times to the hour)" in body
    assert (
        "Not judged yet: the gateway has seen YouTube in front on 0 earlier days, and 3 are needed before a"
        " name is called new." in body
    )
    assert "Not seen with YouTube before (too few days to call them new) googlevideo.com" in body
    assert "New for" not in body and "1 h 00 min" not in body


def test_the_home_screen_and_an_input_say_what_they_are_and_judge_nothing(tmp_path, lg):
    s = Store(tmp_path / "s.db")
    t = evening(0)
    evs = [up(t), power(t, "Active"), app(t, HOME), app(t + 600, HDMI), down(t + 1800)]
    s.talk(t + 100, "us.lgtvsdp.com")
    s.talk(t + 700, "aic.cdpsvc.lgtvcommon.com")
    s.talk(t + 800, "rr1.googlevideo.com")
    s.talk(t + 900, "tracker.example.org")
    found = receipt.receipts(receipt.gather(s.conn, lg, GW, A, B, evs, now=NOW))
    home, hdmi = found
    assert (home["kind"], hdmi["kind"], hdmi["label"], hdmi["ready"]) == ("home", "input", "HDMI 1", False)
    assert receipt.render_receipt(home) == [
        "Home screen, Mon 26 Oct 20:00 to 20:10 (10 min): only the TV's own services."
    ]
    out = text(receipt.render_receipt(hdmi))
    assert "An input shows another device's picture and needs no internet." in out
    assert (
        "  Advertising and measurement while HDMI 1 was in front\n    aic.cdpsvc.lgtvcommon.com, LG usage reporting"
        in out
    )
    assert "  Reached while HDMI 1 was in front\n    example.org, no category yet" in out
    assert "Not judged yet" not in out and "New for" not in out


def test_a_session_that_just_ended_is_still_settling(store, lg):  # noqa: F811
    soon = receipt.gather(store.conn, lg, GW, A, B, record(), known_until=B, now=evening(5, 23.5))
    last = receipt.receipts(soon, last=True)[0]
    assert last["app"] == NF and last["settling"]
    assert "  Still settling: the numbers keep filling in for about three hours after a session." in text(
        receipt.render_receipt(last)
    )
    assert receipt.action([last]).startswith("Action: us.ad.lgsmartad.com (LG advertising) got through")
    quiet = {**last, "groups": {**last["groups"], "tracking": []}}  # with nothing that got through, the wait
    assert (
        receipt.action([quiet])
        == (
            "Action: nothing to do; the numbers keep filling in, so run it again after 01:24."  # the clocks go back that night
        )
    )


def test_the_screen_saver_and_the_edges_are_said(tmp_path, lg):
    s = Store(tmp_path / "s.db")
    t = evening(0)
    evs = [up(t), power(t, "Active"), app(t, YT), power(t + 600, "Screen Saver"), down(t + 4200)]
    s.talk(t + 900, "rr1.googlevideo.com", down_=3_000_000)
    (r,) = receipt.receipts(receipt.gather(s.conn, lg, GW, A, B, evs, now=NOW))
    out = text(receipt.render_receipt(r))
    assert "  1 h 00 min of it behind the screen saver: 1 connection started then, 2.9 MB" in out
    assert "  The gateway started listening while it was in front; then lost touch with the TV." in out


def test_no_session_says_so_and_points_at_the_readings(tmp_path, lg):
    s = Store(tmp_path / "s.db")
    rec = receipt.gather(s.conn, lg, GW, A, B, [], now=NOW)
    assert receipt.receipts(rec) == [] and "No viewing session started" in receipt.render(rec, [])[0]
    assert receipt.render_evening(rec, receipt.evening(rec)) == receipt.render(rec, [])


def test_every_view_closes_with_the_footer_the_action_and_the_commands(rec):
    found = receipt.receipts(rec, since=evening(5, 12.0))
    out = receipt.render(rec, found, receipt.gap_summary(rec), "1d")
    assert "a match in time, not proof" in receipt.FOOTER and receipt.FOOTER.startswith(out[-5].strip()[:30])
    assert out[-3].startswith(
        "Action: pubads.g.doubleclick.net (advertising or app measurement) got through the filter;"
    )
    assert (
        "`sudo tvgw" in out[-3]
        and "check pubads.g.doubleclick.net` says why, and how to block it." in out[-2]
    )
    assert out[-1] == "Every name: sudo tvgw receipt --since 1d   One name: sudo tvgw receipt --why NAME"
    # the hourly note, and the pointer at exact times, only where the readings were hourly and the TV is an LG
    hourly = receipt.render(rec, receipt.receipts(rec, since=A), None, "7d")
    assert (
        "Times to the hour: the TV is asked once an hour, so a session can start earlier and run longer"
        in text(hourly)
    )
    assert "see 'Get exact times' in docs/use/receipt.md" not in text(hourly)  # a live record exists
    no_live = receipt.Record(**{**rec.__dict__, "live": False})
    assert "The TV can report exact times: see 'Get exact times' in docs/use/receipt.md." in receipt.render(
        no_live, receipt.receipts(rec, since=A), None, "7d"
    )
    assert receipt.action(found[:2]) == "Action: nothing to do." or "got through" in receipt.action(found[:2])


# ---- the evening: the default screen ------------------------------------------------------------------------
def test_the_default_screen_is_the_evening_one_block_per_app_verdict_first(rec):
    ev = receipt.evening(rec)
    assert [b["app"] for b in ev["blocks"]] == [HOME, YT, NF]
    out = receipt.render_evening(rec, ev)
    assert out[:4] == [
        "Last evening, Sat 31 Oct, 19:50 to 23:10 (exact times, reported by the TV)",
        "Home screen, 8 min in all: only the TV's own services.",
        "YouTube, 19:58 to 21:30 (1 h 32 min), 1.0 MB down",
        "  No name was new for YouTube.",
    ]
    body = text(out)
    assert (
        "Netflix, 21:30 to 23:10 (1 h 40 min), 2.0 MB down\n  New for Netflix: aiv-cdn.net (streaming), ytimg.com (streaming; usually with YouTube)"
        in body
    )
    assert (
        "  Advertising and measurement while it was in front: us.ad.lgsmartad.com, 2 connections, 19.5 KB"
        in body
    )
    assert "  Asked for 2 blocked names 6 times, every one refused: pubads.g.doubleclick.net 4" in body
    assert "  No name was captured for 1 connection." in body
    assert out[-1].startswith("Every name:") and any(line.startswith("Action:") for line in out)
    assert all(len(line) <= receipt.WIDTH + 8 for line in out)
    assert "(youtube.leanback.v4)" not in body  # the app's identifier is for the JSON, not the owner


def test_a_lost_session_in_an_evening_is_one_block_with_the_lost_minutes_named(tmp_path, lg):
    s = Store(tmp_path / "s.db")
    t = evening(0, 21.0)
    for d in range(-4, 0):  # YouTube has its days behind it
        s.reading(evening(d, 20.33), "Active", YT)
        s.reading(evening(d, 21.33), "Active", YT)
        s.talk(evening(d, 20.5), "rr1.googlevideo.com", down_=500_000)
    evs = [up(t), power(t, "Active"), app(t, YT), down(t + 2400), up(t + 2940), power(t + 2940, "Active")]
    evs += [app(t + 2940, YT), power(t + 4200, "Active", "Request Power Off"), down(t + 4260)]
    s.talk(t + 100, "rr2.googlevideo.com", down_=5_000_000)
    s.talk(t + 3000, "rr3.googlevideo.com", down_=5_000_000)
    rec = receipt.gather(s.conn, lg, GW, evening(-5), B, evs, now=NOW)
    ev = receipt.evening(rec)
    (yt,) = [b for b in ev["blocks"] if b["app"] == YT and b["timed"] == "live"]
    assert yt["lost"] == [(t + 2400, t + 2940)] and len(yt["spans"]) == 1
    out = receipt.render_evening(rec, ev)
    assert "YouTube, 21:00 to 22:10 (1 h 10 min; the gateway lost touch 21:40 to 21:49), 9.5 MB down" in out
    assert not any("lost touch with the TV at the end" in line for line in out)


def test_an_evening_from_the_readings_alone_claims_no_duration(store, lg):  # noqa: F811
    rec = receipt.gather(store.conn, lg, GW, A, B, [], now=NOW)
    out = receipt.render_evening(rec, receipt.evening(rec))
    assert (
        out[0]
        == "Last evening, Sat 31 Oct, 20:19 to 21:19 (times to the hour: the TV was asked once an hour)"
    )
    assert (
        out[1]
        == "YouTube, seen in front at 20:19 and 21:19; it may have started earlier and run longer; 1.0 MB down"
    )
    assert "Times to the hour: the TV is asked once an hour" in text(out) and "1 h 00 min" not in text(out)


# ---- the picture -------------------------------------------------------------------------------------------
def test_the_picture_says_what_each_app_was_seen_with_and_on_how_many_days(rec):
    found = {p["app"]: p for p in receipt.pictures(rec)}
    assert set(found) == {YT, NF} and found[YT]["days"] == 6 and found[YT]["ready"]
    units = {(u["domain"], u["category"]): u for u in found[NF]["units"]}
    assert (
        units[("netflix.com", "Streaming")]["days_seen"] == 6 and units[("netflix.com", "Streaming")]["firm"]
    )
    assert units[("netflix.com", "3rd-party ads")]["tracking"]  # the same site, another unit
    assert not units[("aiv-cdn.net", "Streaming")]["firm"]  # one evening
    assert units[("ytimg.com", "Streaming")]["also_with"] == [YT]
    assert ("lgsmartad.com", "LG ads") not in units and ("lgtvsdp.com", "LG core") not in units
    out = receipt.render_pictures(receipt.pictures(rec, NF))
    assert out[0].startswith("What each app has been seen with in the last 28 days, by site")
    assert (
        out[2]
        == "Netflix: in front on 6 viewing days (05:00 to 05:00); enough for a new name to be called new"
    )
    body = text(out)
    assert (
        "    netflix.com, advertising or app measurement: on 5 days; beside Netflix, not part of it" in body
    )
    assert "    aiv-cdn.net, streaming: on 1 day only" in body
    assert "    ytimg.com, streaming: on 1 day only; also with YouTube" in body
    assert "YouTube:" not in body and "JA4" not in body and "t13d" not in body
    assert receipt.render_pictures([])[-1] == "No app has been seen in front yet."


# ---- the replay --------------------------------------------------------------------------------------------
def test_the_replay_says_what_a_rule_would_have_refused_and_one_honest_verdict(store, lg):  # noqa: F811
    store.talk(evening(4, 20.9), "late.example.net")  # new on the fifth evening...
    store.talk(evening(5, 20.9), "late.example.net")  # ...and seen once before on the sixth
    rec = receipt.gather(store.conn, lg, GW, A, B, record(), known_until=B, now=NOW)
    r = receipt.replay(rec)
    apps = {a["app"]: a for a in r["apps"]}
    yt, nf = apps[YT], apps[NF]
    assert (yt["days"], nf["days"]) == (3, 3)  # the rule applies from the fourth evening
    assert [(x["name"], x["conns"]) for x in yt["refused"]] == [("example.net", 1), ("example.org", 1)]
    assert (yt["refused_conns"], yt["thin_conns"], yt["content_outside_share"]) == (2, 1, 0.0)
    assert [(x["name"], x["plain"]) for x in nf["refused"]] == [
        ("aiv-cdn.net", "streaming"),
        ("ytimg.com", "streaming"),
    ]
    assert nf["content_bytes"] == 6_073_000 and nf["content_outside_share"] == round(20_000 / 6_073_000, 4)
    assert nf["filter_conns"] == 1  # LG's advertising: the name filter's business
    assert (yt["must_allow_seen"], yt["must_allow_refused"], yt["must_allow_outside_category"]) == (1, 0, [])
    n = r["numbers"]
    assert (
        n["content_outside_share"] == round(20_000 / (6_073_000 + 3_053_000), 4)
        and n["content_outside_bytes"] == 20_000
    )
    assert (n["must_allow_outside"], n["unnamed_share"], n["app_days"], n["app_days_live"]) == (0, 0.0, 6, 2)
    assert r["meets_the_bar"] is False
    assert r["verdict"] == (
        "Not ready to try: it needs 28 days of app viewing replayed, nine in ten with exact times; it has 6,"
        " 2 with exact times. Keep the live reading on and check again in a few weeks."
    )
    out = text(receipt.render_replay(r))
    assert out.startswith(
        "A replay of the last 6.1 days against an imagined rule. Nothing is refused: this is a report."
    )
    assert (
        "  streaming bytes outside the picture: 0.2% (19.5 KB: aiv-cdn.net, ytimg.com would have been\n      refused) (the bar: at most 1%)"
        in out
    )
    assert "  names the TV must reach outside it: 0 (self-check: 0, as expected)" in out
    assert (
        "  app viewing days replayed: 6, 2 with exact times (the bar: 28, nine in ten with exact times)"
        in out
    )
    assert (
        out.rstrip().endswith("check again in a few weeks.")
        and "design decision" not in out
        and "?" not in out
    )
    assert (
        "of Netflix's streaming bytes, new: 0.3% (19.5 KB: aiv-cdn.net, ytimg.com would have been refused)"
        in out
    )


def test_the_verdict_names_every_failing_condition_and_small_shares_show_their_bytes():
    good = {"content_outside_share": 0.01, "content_outside_bytes": 5_000_000, "must_allow_outside": 0}
    good |= {"unnamed_share": 0.05, "app_days": 28, "app_days_live": 26}
    assert receipt.failing(good) == [] and receipt.meets_the_bar(good)
    assert (
        receipt.verdict(good)
        == "Ready to try, by these numbers alone. No rule exists yet; nothing is refused."
    )
    for key, bad, words in (
        (
            "content_outside_share",
            0.011,
            "1.1% of streaming bytes would have been refused as new; the bar is 1%",
        ),
        ("content_outside_share", None, "no streaming bytes were replayed"),
        ("must_allow_outside", 1, "1 of the names the TV must reach would have been refused"),
        ("unnamed_share", 0.06, "6.0% of bytes had no name to judge; the bar is 5%"),
        (
            "app_days",
            27,
            "it needs 28 days of app viewing replayed, nine in ten with exact times; it has 27, 26 with exact times",
        ),
        ("app_days_live", 25, "it has 28, 25 with exact times"),
    ):
        verdict = receipt.verdict({**good, key: bad})
        assert verdict.startswith("Not ready to try: ") and words in verdict, (key, verdict)
    rows = [{"name": "nflxso.net", "class": "content"}, {"name": "x.example", "class": "unclassified"}]
    assert (
        receipt._share_with_bytes(0.0004, 1_500_000, rows)
        == "under 0.1% (1.4 MB: nflxso.net would have been refused)"
    )
    assert (
        receipt._share_with_bytes(0.0, 0, rows) == "0.0%"
        and receipt._share_with_bytes(None, 0, rows) == "nothing to measure"
    )


def test_a_must_allow_name_only_the_list_protects_is_named(store, lg):  # noqa: F811
    import dataclasses

    odd = dataclasses.replace(lg, must_allow={**lg.must_allow, "login.example.net": "sign-in"})
    store.talk(evening(5, 20.6), "login.example.net")
    rec = receipt.gather(store.conn, odd, GW, A, B, record(), known_until=B, now=NOW)
    yt = next(a for a in receipt.replay(rec)["apps"] if a["app"] == YT)
    assert yt["must_allow_seen"] == 2 and yt["must_allow_outside_category"] == ["login.example.net"]
    assert yt["refused_conns"] == 1  # the stranger of the fourth evening, never the must-allow name
    flat = re.sub(r"\n\s+", " ", text(receipt.render_replay(receipt.replay(rec))))
    assert "protected by the list alone: login.example.net" in flat


# ---- why ---------------------------------------------------------------------------------------------------
def test_why_says_what_a_name_is_and_what_each_apps_days_say_of_it(rec):
    out = receipt.why(rec, "oca.nflxvideo.net")
    assert out[0].startswith(
        "oca.nflxvideo.net: streaming (nflxvideo.net), because the profile files it under Streaming."
    )
    assert "With Netflix it was seen on 6 of 6 viewing days: it is in Netflix's picture." in out
    assert (
        "With YouTube it was never seen in 6 viewing days: a receipt would list it as new while YouTube was in front."
        in out
    )
    assert receipt.why(rec, "d1.aiv-cdn.net", NF)[1] == (
        "With Netflix it was seen on 1 of 6 viewing days: it is in Netflix's picture on one day's evidence."
    )
    clock = receipt.why(rec, "US.lgtvsdp.com.")
    assert len(clock) == 1 and "it is one of the names the TV must reach" in clock[0]
    assert "counted as the TV's own under whichever app is in front" in clock[0]
    ads = receipt.why(rec, "us.ad.lgsmartad.com")
    assert (
        len(ads) == 1
        and "LG's own categories, not an app's. It is listed under advertising and measurement" in ads[0]
    )
    unknown = receipt.why(rec, "tracker.example.com", "amazon")
    assert (
        "no category yet" in unknown[0]
        and unknown[1] == "Prime Video has not been in front in the last 28 days."
    )


def test_why_keeps_advertising_names_out_of_new_and_a_site_apart_from_a_name(rec):
    beacon = receipt.why(rec, "ichnaea.netflix.com", NF)
    assert "listed under advertising and measurement beside the app, not as part of it" in beacon[0]
    assert beacon[1] == "With Netflix it was seen on 5 of 6 viewing days: it is in Netflix's picture."
    never = receipt.why(
        rec, "pubads.g.doubleclick.net", NF
    )  # doubleclick was looked up, never reached, under Netflix
    assert never[1] == (
        "With Netflix it was never seen in 6 viewing days: a receipt would list it under advertising and"
        " measurement while Netflix was in front."
    )
    other = receipt.why(rec, "never-seen.googlevideo.com", YT)
    assert other[1] == (
        "Names of googlevideo.com with streaming were seen with YouTube on 6 of its 6 viewing days; this name"
        " itself: never. Its site is in YouTube's picture, so a receipt would not call this name new."
    )
    assert len(other) == 2


def test_why_before_an_app_has_its_days_says_nothing_is_called_new_yet(store, lg):  # noqa: F811
    rec = receipt.gather(store.conn, lg, GW, A, evening(1, 12.0), [], now=NOW)
    assert receipt.why(rec, "x.example.net", YT)[1] == (
        "With YouTube it was never seen, but YouTube has only 1 viewing day behind it: nothing is called"
        " new before 3."
    )


# ---- what no line may say ------------------------------------------------------------------------------------
@pytest.mark.parametrize(
    "line",
    [
        "YouTube sent 14 KB to doubleclick.net",
        "doubleclick.net tracked you while YouTube was in front",
        "Netflix talked to lgsmartad.com",
        "this proves that Prime Video was running",
        "refused because of YouTube",
        "the TV phoned home",
        "Netflix contacted ytimg.com",
    ],
)
def test_the_words_a_receipt_may_never_use_are_caught(line):
    assert receipt.FORBIDDEN.search(line), line


def test_no_view_claims_who_acted_or_why(rec):
    """Every line the views write over a store with every class of name: advertising, measurement and the
    TV's own names are "while X was in front" or "beside" the app, and a new name is "new for X"."""
    lines = receipt.render_evening(rec, receipt.evening(rec))
    lines += receipt.render(rec, receipt.receipts(rec), receipt.gap_summary(rec), "7d")
    lines += receipt.render_pictures(receipt.pictures(rec))
    lines += receipt.render_replay(receipt.replay(rec))
    for name in (
        "oca.nflxvideo.net",
        "us.lgtvsdp.com",
        "us.ad.lgsmartad.com",
        "pubads.g.doubleclick.net",
        "x.example",
    ):
        lines += receipt.why(rec, name)
    lines += receipt.render_brief_section(receipt.brief_section(rec), "2026-10-31")
    lines += [
        receipt.FOOTER,
        *receipt.KIND_NOTE.values(),
        receipt.verdict({**receipt.replay(rec)["numbers"], "app_days": 28, "app_days_live": 28}),
    ]
    assert len(lines) > 150
    for line in lines:
        assert not receipt.FORBIDDEN.search(line), line
    body = text(lines)
    for title in re.findall(r"^  (Advertising and measurement)(.*)$", body, re.MULTILINE):
        assert title[1].startswith(" while ") and title[1].split(":")[0].endswith("in front"), title
    rest = body.replace("the TV's own", "").replace("The TV's own", "").replace("its own TLS", "")
    assert "Nothing new" not in body and not re.search(r"\bits own\b", rest.replace("picture of its own", ""))
    assert "must-allow" not in body  # the user's words: "the names the TV must reach"


def test_lines_wrap_so_a_terminal_shows_them_whole(rec):
    for lines in (
        receipt.render_evening(rec, receipt.evening(rec)),
        receipt.render(rec, receipt.receipts(rec), receipt.gap_summary(rec), "7d"),
        receipt.render_replay(receipt.replay(rec)),
    ):
        assert all(len(line) <= receipt.WIDTH + 8 for line in lines), max(lines, key=len)


def io_text(o: dict) -> str:
    out = io.StringIO()
    cli.render_brief(o, out)
    return out.getvalue()


# ---- the brief's section, only where a live record exists ---------------------------------------------------
def test_the_brief_gains_its_section_only_when_the_store_holds_a_live_record(store, lg, monkeypatch):  # noqa: F811
    day = time.strftime("%Y-%m-%d", time.localtime(evening(5)))
    monkeypatch.setattr(time, "time", lambda: NOW)
    from tvgw import plain

    before = queries.brief(store.conn, day, lg, now=NOW, app_in_front=True)
    assert "app_sessions" not in before and before["has_live_record"] is False
    plain_text = io.StringIO()
    cli.render_brief(before, plain_text)
    assert "App in front" not in plain_text.getvalue()
    assert "tvgw receipt" not in text(plain.plain_brief(before, None, None, profile=lg, first=False))
    store.conn.executemany(
        "INSERT INTO tv_events(t, kind, value, detail) VALUES (?,?,?,?)",
        [(e.t, e.kind, e.value, e.detail) for e in record()],
    )
    store.conn.commit()
    # the persisted report (tvgw-analyze: app_in_front default False) never carries the finer record,
    # only the cheap flag and, through it, the plain brief's pointer
    persisted = queries.brief(store.conn, day, lg, now=NOW)
    assert "app_sessions" not in persisted and persisted["has_live_record"] is True
    assert "App in front" not in io_text(persisted)
    assert "sudo tvgw receipt" in text(plain.plain_brief(persisted, None, None, profile=lg, first=False))
    after = queries.brief(store.conn, day, lg, now=NOW, app_in_front=True)
    assert {k: v for k, v in after.items() if k != "app_sessions"} == {**before, "has_live_record": True}
    rows = after["app_sessions"]
    assert [(r["app"], r["timed"], r["conns"]) for r in rows] == [
        (HOME, "live", 0),
        (YT, "live", 6),
        (NF, "live", 7),
    ]
    assert rows[2]["new"] == ["aiv-cdn.net", "ytimg.com"] and rows[1]["new"] == [] and rows[1]["ready"]
    assert (rows[1]["tracking"], rows[2]["tracking"]) == (1, 1)
    out = io.StringIO()
    cli.render_brief(after, out)
    section = out.getvalue()[out.getvalue().index("App in front") :].split("\n\n")[0].rstrip().split("\n")
    assert section[0].startswith("App in front (which app was in front when each connection started;")
    assert (
        section[2]
        == "  19:58-21:30 YouTube, 1 h 32 min (exact): 6 connections, 1.0 MB down; no name new for it; 1 advertising or measurement name"
    )
    assert section[3] == (
        "  21:30-23:10 Netflix, 1 h 40 min (exact): 7 connections, 2.0 MB down; new for it: aiv-cdn.net, ytimg.com;"
        " 1 advertising or measurement name"
    )
    assert section[-1] == f"  Each session's receipt: sudo tvgw receipt --since {day}"
    # the plain brief gains one sentence pointing at the receipt
    lines = plain.plain_brief(after, None, None, profile=lg, first=False)
    assert "  Which app was in front, and what the TV reached meanwhile: sudo tvgw receipt" in lines
    assert lines[-1] == plain.FOOTER
    json.dumps(after)  # and the day's JSON still serializes


def test_a_store_from_before_the_live_table_briefs_as_it_did(store, lg):  # noqa: F811
    store.conn.execute("DROP TABLE tv_events")
    store.conn.commit()
    ro = db.connect(store.path, readonly=True)
    day = time.strftime("%Y-%m-%d", time.localtime(evening(5)))
    assert "app_sessions" not in queries.brief(ro, day, lg, now=NOW)


def test_the_brief_section_is_short_however_many_sessions(rec):
    rows = receipt.brief_section(rec)
    out = receipt.render_brief_section(rows, "2026-10-26")
    assert len(rows) == 13 and len(out) == 2 + receipt.BRIEF_MAX + 2 and out[-2] == "  and 5 more sessions"
    assert out[2].startswith(
        "  Mon 20:19 and 21:19 YouTube (to the hour): 4 connections"
    )  # several days: which evening
    assert "too few days to call anything new" in out[2] and "(live)" not in text(out)
    assert receipt.render_brief_section([], "1d")[2] == "  none"


# ---- the command ---------------------------------------------------------------------------------------------
def test_the_command_prints_each_view(store, tmp_path, monkeypatch, capsys):  # noqa: F811
    monkeypatch.setattr(time, "time", lambda: NOW)
    conf = tmp_path / "tvgw.conf"
    conf.write_text("", encoding="utf-8")
    base = ["--conf", str(conf), "--db", store.path, "receipt"]
    assert cli.main(base) == 0  # the newest evening, from the hourly readings (no live record in the store)
    out = capsys.readouterr().out
    assert out.startswith("Last evening, Sat 31 Oct, 20:19 to 21:19 (times to the hour")
    assert "The TV can report exact times: see 'Get exact times' in docs/use/receipt.md." in out
    assert cli.main([*base, "--json"]) == 0
    assert json.loads(capsys.readouterr().out)["blocks"][0]["app"] == YT
    assert cli.main([*base, "--since", "8d", "--json"]) == 0
    data = json.loads(capsys.readouterr().out)
    assert len(data["sessions"]) == 11 and data["gaps"]["conns"] == 10
    assert cli.main([*base, "--since", "8d"]) == 0
    out = capsys.readouterr().out
    assert "in which nothing says which app was in front, 10 connections" in out
    assert "Every name: sudo tvgw receipt --since 8d" in out
    assert cli.main([*base, "--picture", "--app", YT]) == 0
    assert "YouTube: in front on 6 viewing days" in capsys.readouterr().out
    assert cli.main([*base, "--replay"]) == 0
    assert "The numbers that decide" in capsys.readouterr().out
    assert cli.main([*base, "--why", "i.ytimg.com"]) == 0
    assert capsys.readouterr().out.startswith("i.ytimg.com: streaming (ytimg.com), because")
    assert cli.main([*base, "--why", "i.ytimg.com", "--json"]) == 0
    assert json.loads(capsys.readouterr().out)["name"] == "i.ytimg.com"
    assert cli.main([*base, "--last", "--since", "1d"]) == 2
    assert cli.main([*base, "--since", "400d"]) == 2  # past DB_DAYS: the store keeps no older readings
    assert "reaches past DB_DAYS" in capsys.readouterr().err
    with pytest.raises(SystemExit):
        cli.main([*base, "--picture", "--replay"])


def test_a_gap_is_told_by_its_software_fingerprint_alone(store, lg, monkeypatch):  # noqa: F811
    monkeypatch.setattr(appfront, "STACK_MIN", 10)
    rec = receipt.gather(store.conn, lg, GW, A, B, [], now=NOW)  # the hourly readings alone
    g = receipt.gap_summary(rec)
    assert g["conns"] == 10 and g["unnamed"] == 1  # LG's own stack names no app
    assert (g["by_app"][YT]["conns"], g["by_app"][NF]["conns"]) == (4, 5)
    out = text(receipt.render_gap_summary(g))
    assert "in which nothing says which app was in front, 10 connections" in out
    assert "  Opened like the software of: Netflix 5 connections" in out
    assert "suggests which software opened a connection; it does not say which app was in front" in out
    assert "  No fingerprint that is one app's: 1 connection." in out
    assert not receipt.FORBIDDEN.search(out) and receipt.render_gap_summary({**g, "conns": 0}) == []


def test_sizes_spans_and_counts_read_as_the_brief_reads():
    assert [receipt.size(n) for n in (0, 999, 1023, 5_000_000, 3 * 1024**3, 5000 * 1024**3)] == [
        "0 B",
        "999 B",
        "1.0 KB",  # no figure has four digits before its point
        "4.8 MB",
        "3.0 GB",
        "5000.0 GB",
    ]
    assert [receipt.span(s) for s in (0, 59, 60, 3599, 3600, 12900)] == [
        "under a minute",
        "under a minute",
        "1 min",
        "59 min",
        "1 h 00 min",
        "3 h 35 min",
    ]
    assert receipt.count(1, "connection") == "1 connection" and receipt.count(0, "day") == "0 days"
    assert receipt.who("example.net") == "example.net" and appfront.company_of("example.net") is None
    assert (
        receipt.short("YouTube (youtube.leanback.v4)") == "YouTube"
        and receipt.short("Home screen") == "the home screen"
    )


# ---- the finer record stays on the gateway -------------------------------------------------------------------
def test_the_analysts_pack_never_carries_the_sessions_or_the_events(store, lg, tmp_path):  # noqa: F811
    from tvgw import analyst, config

    store.conn.executemany(
        "INSERT INTO tv_events(t, kind, value, detail) VALUES (?,?,?,?)",
        [(e.t, e.kind, e.value, e.detail) for e in record()],
    )
    store.conn.commit()
    s = config.Settings(state_dir=str(tmp_path), db_path=store.path, reports_dir=str(tmp_path / "reports"))
    a, b = queries.day_bounds(time.strftime("%Y-%m-%d", time.localtime(evening(5))))
    assert "app_sessions" in queries.window_report(store.conn, a, b, lg, now=NOW, app_in_front=True)
    pack = json.dumps(analyst.pack(store.conn, a, b, "day", lg, s))
    for word in ("app_sessions", "tv_events", "session.up", "com.webos.app.home", 'aiv-cdn.net", "new'):
        assert word not in pack, word


def test_the_pages_that_name_the_receipt_keep_its_words(tmp_path):
    """The user page's title and every link to it make the gateway the actor, never the app."""
    from conftest import ROOT as root

    page = (root / "docs" / "use" / "receipt.md").read_text(encoding="utf-8")
    title = page.splitlines()[0]
    assert title == "# See what the TV reached while each app was in front" and not receipt.FORBIDDEN.search(
        title
    )
    for path in (
        "docs/README.md",
        "mkdocs.yml",
        "docs/use/privacy.md",
        "docs/how-it-works/app-in-front.md",
        "CHANGELOG.md",
    ):
        text_ = (root / path).read_text(encoding="utf-8")
        for line in text_.splitlines():
            if "receipt.md" in line:
                link = re.sub(r"\(.*?\)", "", line)  # the link text, not the target
                assert not receipt.FORBIDDEN.search(link), (path, line)
    # the example screens on the page are the receipt's own words
    for block in re.findall(r"```text\n(.*?)```", page, re.DOTALL):
        for line in block.splitlines():
            assert not receipt.FORBIDDEN.search(line), line
