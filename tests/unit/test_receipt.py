"""(app in front) `tvgw receipt`: the receipt, the picture, the replay and why, over the six evenings of
test_appeval's store (design decision 67). What each view says, and what none of them may ever say."""

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


# ---- the receipt -------------------------------------------------------------------------------------------
def test_a_session_lists_what_started_under_it_by_what_each_name_is(rec):
    found = receipt.receipts(rec, since=evening(5, 12.0))
    assert [(r["app"], r["timed"]) for r in found] == [(HOME, "live"), (YT, "live"), (NF, "live")]
    nf = session(found, NF)
    assert (nf["ready"], nf["days_behind"], nf["conns"], nf["settling"]) == (True, 5, 8, False)
    groups = {g: [(r["domain"], r["conns"]) for r in rows] for g, rows in nf["groups"].items() if rows}
    assert groups == {
        "before": [("nflxvideo.net", 2), ("netflix.com", 2)],  # by bytes: the video first
        "tv": [("lgsmartad.com", 1)],
        "new": [("aiv-cdn.net", 1), ("ytimg.com", 1)],
    }
    assert nf["groups"]["before"][0]["days_seen"] == 5
    assert nf["groups"]["new"][1]["also_with"] == [YT] and nf["groups"]["new"][0]["also_with"] == []
    assert nf["unnamed"] == {"conns": 1, "bytes": 5_000}
    assert nf["refused"] == {
        "lookups": 3,
        "names": [
            {"domain": "doubleclick.net", "plain": "other advertisers", "lookups": 2},
            {"domain": "lgsmartad.com", "plain": "LG advertising", "lookups": 1},
        ],
    }


def test_the_receipt_reads_in_plain_words(rec):
    nf = session(receipt.receipts(rec, since=evening(5, 12.0)), NF)
    out = receipt.render_receipt(nf)
    assert out[0] == "Netflix (netflix)"
    assert out[1] == "  Sat 31 Oct 21:30 to 23:10: 1 h 40 min, timed by the live reading"
    assert "  8 connections started while it was in front: 2.0 MB down, 7.8 KB up" in out
    body = text(out)
    for title in (
        "  Seen with Netflix before\n",
        "  The TV's own services, while Netflix was in front\n",
        "  Also talked while Netflix was in front: new, not seen with it on any earlier day\n",
        "  No name was captured for 1 connection (4.9 KB).",
        "  The filter refused 3 lookups of 2 names while Netflix was in front:"
        " doubleclick.net 2 (other advertisers), lgsmartad.com 1 (LG advertising)",
    ):
        assert title in body, title
    row = next(ln for ln in out if "nflxvideo.net" in ln)
    assert "streaming" in row and "2 connections" in row and "(on 5 of 5 earlier days)" in row
    assert "(usually seen with YouTube)" in next(ln for ln in out if "ytimg.com" in ln)
    assert "LG advertising" in next(ln for ln in out if "lgsmartad.com" in ln and "connection" in ln)


def test_a_session_with_nothing_new_says_so_and_its_first_connections_are_its_own(rec):
    yt = session(receipt.receipts(rec, since=evening(5, 12.0)), YT)
    # the delivery host that connected 1.5 s before YouTube reached the front is YouTube's
    assert yt["conns"] == 6 and yt["groups"]["new"] == [] and yt["start_exact"]
    out = text(receipt.render_receipt(yt))
    assert "  Nothing new talked while YouTube was in front." in out
    assert "  Advertising and measurement, while YouTube was in front\n" in out
    assert "  The filter refused no lookup while YouTube was in front." in out


def test_a_session_from_the_hourly_readings_says_how_little_is_known_of_its_edges(rec):
    first = receipt.receipts(rec, since=A)[0]
    assert (first["app"], first["timed"], first["ready"], first["days_behind"]) == (YT, "hourly", False, 0)
    out = text(receipt.render_receipt(first))
    assert "timed by the hourly readings: known to the hour, and a short switch to another app" in out
    assert (
        "  Not judged yet: YouTube has been in front on 0 earlier days, and 3 are needed before a name is"
        " called new." in out
    )
    assert "Names with no earlier day behind them" in out and "Also talked" not in out


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
    out = text(receipt.render_receipt(hdmi))
    assert "An input shows another device's picture and needs no internet." in out
    assert "  Also talked while HDMI 1 was in front\n" in out and "Not judged yet" not in out
    assert "while the home screen was in front" in text(receipt.render_receipt(home))
    assert "not classified yet" in next(ln for ln in out.split("\n") if "example.org" in ln)
    assert "LG usage reporting" in out
    assert "The home screen is the TV's own software" in text(receipt.render_receipt(home))


def test_a_session_that_just_ended_is_still_settling(store, lg):  # noqa: F811
    soon = receipt.gather(store.conn, lg, GW, A, B, record(), known_until=B, now=evening(5, 23.5))
    last = receipt.receipts(soon, last=True)[0]
    assert last["app"] == NF and last["settling"]
    assert "Still settling" in text(receipt.render_receipt(last))


def test_the_screen_saver_and_an_unknown_edge_are_said(tmp_path, lg):
    s = Store(tmp_path / "s.db")
    t = evening(0)
    evs = [up(t), power(t, "Active"), app(t, YT), power(t + 600, "Screen Saver"), down(t + 4200)]
    s.talk(t + 900, "rr1.googlevideo.com", down_=3_000_000)
    (r,) = receipt.receipts(receipt.gather(s.conn, lg, GW, A, B, evs, now=NOW))
    out = text(receipt.render_receipt(r))
    assert "  1 h 00 min of it behind the screen saver: 1 connection started then, 2.9 MB" in out
    assert (
        "  it was already in front when the live reading began; the live reading lost the TV before it ended"
        in out
    )


def test_no_session_says_so_and_points_at_the_readings(tmp_path, lg):
    s = Store(tmp_path / "s.db")
    rec = receipt.gather(s.conn, lg, GW, A, B, [], now=NOW)
    assert receipt.receipts(rec) == [] and "No viewing session started" in receipt.render(rec, [])[0]


def test_the_whole_text_ends_with_what_a_receipt_can_claim(rec):
    out = receipt.render(rec, receipt.receipts(rec, last=True))
    assert out[-1] == receipt.FOOTER and "a match in time, not proof" in receipt.FOOTER
    hourly_only = receipt.Record(**{**rec.__dict__, "live": False})
    assert (
        "LIVE_READING=on times them to the second" in receipt.render(hourly_only, receipt.receipts(rec))[-1]
    )


def test_a_gap_is_told_by_its_software_fingerprint_alone(store, lg, monkeypatch):  # noqa: F811
    monkeypatch.setattr(appfront, "STACK_MIN", 10)
    rec = receipt.gather(store.conn, lg, GW, A, B, [], now=NOW)  # the hourly readings alone
    g = receipt.gap_summary(rec)
    # every connection of the sixth evening outside 20:20 to 21:20, and the stray of the third evening
    assert g["conns"] == 10 and g["unnamed"] == 1  # LG's own stack names no app
    assert (g["by_app"][YT]["conns"], g["by_app"][NF]["conns"]) == (4, 5)
    out = text(receipt.render_gap_summary(g))
    assert "in which nothing says which app was in front, 10 connections started" in out
    assert "  By the software fingerprint of their TLS hello: Netflix 5 connections" in out
    assert "names the software that opened a connection, not the app that was in front." in out
    assert "  No fingerprint that is one app's: 1 connection." in out
    assert not receipt.FORBIDDEN.search(out)
    assert receipt.render_gap_summary({**g, "conns": 0}) == []
    assert out.split("\n")[0] in text(receipt.render(rec, receipt.receipts(rec), g))


# ---- the picture -------------------------------------------------------------------------------------------
def test_the_picture_says_what_each_app_was_seen_with_and_on_how_many_days(rec):
    found = {p["app"]: p for p in receipt.pictures(rec)}
    assert set(found) == {YT, NF} and found[YT]["days"] == 6 and found[YT]["ready"]
    units = {(u["domain"], u["category"]): u for u in found[NF]["units"]}
    assert (
        units[("netflix.com", "Streaming")]["days_seen"] == 6 and units[("netflix.com", "Streaming")]["firm"]
    )
    assert units[("netflix.com", "3rd-party ads")]["tracking"]  # the same domain, another unit
    assert not units[("aiv-cdn.net", "Streaming")]["firm"]  # one evening: thin
    assert units[("ytimg.com", "Streaming")]["also_with"] == [YT]
    assert ("lgsmartad.com", "LG ads") not in units and ("lgtvsdp.com", "LG core") not in units
    out = text(receipt.render_pictures(receipt.pictures(rec, NF)))
    assert out.startswith("Netflix (netflix): in front on 6 viewing days of the last 28; enough for")
    assert re.search(r"netflix\.com +other advertisers +on 5 days; present with Netflix, never its own", out)
    assert re.search(r"aiv-cdn\.net +streaming +on 1 day, thin", out)
    assert re.search(r"ytimg\.com +streaming +on 1 day, thin; also with YouTube", out)
    assert "YouTube (" not in out  # one app was asked for
    assert receipt.render_pictures([]) == ["No app has been seen in front yet in the last 28 days."]


# ---- the replay --------------------------------------------------------------------------------------------
def test_the_replay_says_what_a_rule_would_have_refused_and_prints_the_two_numbers(store, lg):  # noqa: F811
    store.talk(evening(4, 20.9), "late.example.net")  # new on the fifth evening...
    store.talk(evening(5, 20.9), "late.example.net")  # ...and seen once before on the sixth
    rec = receipt.gather(store.conn, lg, GW, A, B, record(), known_until=B, now=NOW)
    r = receipt.replay(rec)
    apps = {a["app"]: a for a in r["apps"]}
    yt, nf = apps[YT], apps[NF]
    # the rule applies from the fourth evening, the first with three days behind each app
    assert (yt["days"], nf["days"]) == (3, 3)
    assert [(x["domain"], x["conns"]) for x in yt["refused"]] == [("example.net", 1), ("example.org", 1)]
    assert (yt["refused_conns"], yt["thin_conns"], yt["content_outside_share"]) == (2, 1, 0.0)
    assert [(x["domain"], x["plain"]) for x in nf["refused"]] == [
        ("aiv-cdn.net", "streaming"),
        ("ytimg.com", "streaming"),
    ]
    # Netflix's streaming bytes on those three evenings: 2,011,000 on two and 2,051,000 on the last
    assert nf["content_bytes"] == 6_073_000 and nf["content_outside_share"] == round(20_000 / 6_073_000, 4)
    assert nf["filter_conns"] == 1  # LG's advertising: the name filter's business
    assert (yt["must_allow_seen"], yt["must_allow_refused"], yt["must_allow_outside_category"]) == (1, 0, [])
    n = r["numbers"]
    assert n["content_outside_share"] == round(20_000 / (6_073_000 + 3_053_000), 4)
    assert (n["must_allow_outside"], n["unnamed_share"], n["app_days"], n["app_days_live"]) == (0, 0.0, 6, 2)
    assert r["meets_the_bar"] is False  # six app-days, two of them live: far from 28 and nine in ten
    out = text(receipt.render_replay(r))
    assert "Nothing is refused: this is a report." in out
    assert "  streaming bytes outside the picture: 0.2% (the bar: at most 1%)" in out
    assert "  must-allow names outside it: 0 (the bar: 0)" in out
    assert "These numbers do not meet the bar yet." in out
    assert "of Netflix's streaming bytes, new: 0.3%; new or seen on one day only: 0.3%" in out


def test_the_bar_is_every_one_of_its_numbers():
    good = {"content_outside_share": 0.01, "must_allow_outside": 0, "unnamed_share": 0.05, "app_days": 28}
    good["app_days_live"] = 26
    assert receipt.meets_the_bar(good)
    for key, bad in (
        ("content_outside_share", 0.011),
        ("content_outside_share", None),
        ("must_allow_outside", 1),
        ("unnamed_share", 0.06),
        ("app_days", 27),
        ("app_days_live", 25),
    ):
        assert not receipt.meets_the_bar({**good, key: bad}), key
    r = {"window_days": 14, "apps": [], "numbers": good, "meets_the_bar": True}
    r["bar"] = {
        "content_outside_share": 0.01,
        "must_allow_outside": 0,
        "unnamed_share": 0.05,
        "viewing_days": 28,
    }
    assert "These numbers meet the bar. No rule exists to try" in text(receipt.render_replay(r))


def test_a_must_allow_name_only_the_list_protects_is_named(store, lg):  # noqa: F811
    import dataclasses

    odd = dataclasses.replace(lg, must_allow={**lg.must_allow, "login.example.net": "sign-in"})
    store.talk(evening(5, 20.6), "login.example.net")
    rec = receipt.gather(store.conn, odd, GW, A, B, record(), known_until=B, now=NOW)
    yt = next(a for a in receipt.replay(rec)["apps"] if a["app"] == YT)
    assert yt["must_allow_seen"] == 2 and yt["must_allow_outside_category"] == ["login.example.net"]
    assert yt["refused_conns"] == 1  # the stranger of the fourth evening, never the must-allow name


# ---- why ---------------------------------------------------------------------------------------------------
def test_why_says_what_a_name_is_and_what_each_apps_days_say_of_it(rec):
    out = receipt.why(rec, "oca.nflxvideo.net")
    assert out[0].startswith(
        "oca.nflxvideo.net: streaming (nflxvideo.net), because the profile files it under Streaming."
    )
    assert "With Netflix it was seen on 6 of 6 viewing days: it is in Netflix's picture." in out
    assert (
        "With YouTube it was never seen in 6 viewing days: a receipt would list it as new while YouTube"
        " was in front." in out
    )
    assert receipt.why(rec, "d1.aiv-cdn.net", NF)[1] == (
        "With Netflix it was seen on 1 of 6 viewing days: it is in Netflix's picture on thin evidence."
    )
    clock = receipt.why(rec, "US.lgtvsdp.com.")
    assert len(clock) == 1 and "it is one of the names the TV must reach" in clock[0]
    assert "counted as the TV's own under whichever app is in front" in clock[0]
    ads = receipt.why(rec, "us.ad.lgsmartad.com")
    assert len(ads) == 1 and "It is LG's, so it is never counted as an app's" in ads[0]
    beacon = receipt.why(rec, "ichnaea.netflix.com", NF)
    assert "never as the app's own" in beacon[0] and "seen on 5 of 6 viewing days" in beacon[1]
    unknown = receipt.why(rec, "tracker.example.com", "amazon")
    assert (
        "not classified yet" in unknown[0]
        and unknown[1] == "Prime Video has not been in front in the last 28 days."
    )


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


def test_no_view_claims_who_acted_or_why(rec, tmp_path, lg):
    """Every line the four views write over a store with every class of name: platform, advertising and
    measurement names are "while X was in front", and a new name "also talked"."""
    lines = receipt.render(rec, receipt.receipts(rec))
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
    lines += [receipt.FOOTER, *receipt.KIND_NOTE.values()]
    assert len(lines) > 150
    for line in lines:
        assert not receipt.FORBIDDEN.search(line), line
    body = text(lines)
    # the three kinds of name that are never an app's are always "while X was in front"
    for title in re.findall(
        r"^  (Advertising and measurement|The TV's own services)(.*)$", body, re.MULTILINE
    ):
        assert re.fullmatch(r", while .+ was in front", title[1]), title
    assert "Also talked while" in body and "its own" not in body.replace("never its own", "").replace(
        "the TV's own", ""
    ).replace("The TV's own", "").replace("picture of its own", "")


# ---- the brief's section, only where a live record exists ---------------------------------------------------
def test_the_brief_gains_its_section_only_when_the_store_holds_a_live_record(store, lg, monkeypatch):  # noqa: F811
    day = time.strftime("%Y-%m-%d", time.localtime(evening(5)))
    monkeypatch.setattr(time, "time", lambda: NOW)
    before = queries.brief(store.conn, day, lg, now=NOW)
    assert "app_sessions" not in before
    plain_text = io.StringIO()
    cli.render_brief(before, plain_text)
    assert "App in front" not in plain_text.getvalue()
    store.conn.executemany(
        "INSERT INTO tv_events(t, kind, value, detail) VALUES (?,?,?,?)",
        [(e.t, e.kind, e.value, e.detail) for e in record()],
    )
    store.conn.commit()
    after = queries.brief(store.conn, day, lg, now=NOW)
    assert {k: v for k, v in after.items() if k != "app_sessions"} == before  # nothing else moved
    rows = after["app_sessions"]
    assert [(r["app"], r["timed"], r["conns"]) for r in rows] == [
        (HOME, "live", 0),
        (YT, "live", 6),
        (NF, "live", 7),
    ]
    assert rows[2]["new"] == ["aiv-cdn.net", "ytimg.com"] and rows[1]["new"] == [] and rows[1]["ready"]
    out = io.StringIO()
    cli.render_brief(after, out)
    section = out.getvalue()[out.getvalue().index("App in front") :].split("\n\n")[0].rstrip().split("\n")
    assert (
        section[0]
        == "App in front (sessions that started in this window; a connection counts where it started):"
    )
    assert section[2] == "  19:58-21:30 YouTube, 1 h 32 min (live): 6 connections, 1.0 MB down; nothing new"
    assert section[3] == (
        "  21:30-23:10 Netflix, 1 h 40 min (live): 7 connections, 2.0 MB down; new while it was in front:"
        " aiv-cdn.net, ytimg.com"
    )
    assert section[-1] == f"  Each session's receipt: sudo tvgw receipt --since {day}"
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
    assert out[2].startswith("  Mon 20:19-21:19 YouTube, 1 h 00 min (hourly)")  # several days: which evening
    assert "too few days to call anything new" in out[2]
    assert receipt.render_brief_section([], "1d")[2] == "  none"


# ---- the command ---------------------------------------------------------------------------------------------
def test_the_command_prints_each_view(store, tmp_path, monkeypatch, capsys):  # noqa: F811
    monkeypatch.setattr(time, "time", lambda: NOW)
    conf = tmp_path / "tvgw.conf"
    conf.write_text("", encoding="utf-8")
    base = ["--conf", str(conf), "--db", store.path, "receipt"]
    assert cli.main(base) == 0  # the newest session, from the hourly readings (no live record in the store)
    out = capsys.readouterr().out
    # the last evening's readings end with the TV off, so its last session is YouTube's hour
    assert out.startswith("YouTube (youtube.leanback.v4)\n") and "timed by the hourly readings" in out
    assert out.rstrip().endswith("(docs/how-it-works/app-in-front.md).")
    assert cli.main([*base, "--since", "8d", "--json"]) == 0
    data = json.loads(capsys.readouterr().out)
    assert len(data["sessions"]) == 11 and data["gaps"]["conns"] == 10
    assert cli.main([*base, "--since", "8d"]) == 0
    assert "in which nothing says which app was in front, 10 connections started" in capsys.readouterr().out
    assert cli.main([*base, "--picture", "--app", YT]) == 0
    assert capsys.readouterr().out.startswith("YouTube (youtube.leanback.v4): in front on 6 viewing days")
    assert cli.main([*base, "--replay"]) == 0
    assert "The two numbers that decide" in capsys.readouterr().out
    assert cli.main([*base, "--why", "i.ytimg.com"]) == 0
    assert capsys.readouterr().out.startswith("i.ytimg.com: streaming (ytimg.com), because")
    assert cli.main([*base, "--why", "i.ytimg.com", "--json"]) == 0
    assert json.loads(capsys.readouterr().out)["name"] == "i.ytimg.com"
    assert cli.main([*base, "--last", "--since", "1d"]) == 2
    with pytest.raises(SystemExit):
        cli.main([*base, "--picture", "--replay"])


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


# ---- the finer record stays on the gateway -------------------------------------------------------------------
def test_the_analysts_pack_never_carries_the_sessions_or_the_events(store, lg, tmp_path):  # noqa: F811
    """What goes to the model is the pack, and the pack is built key by key: the live record and what is
    worked out from it are not among them."""
    from tvgw import analyst, config

    store.conn.executemany(
        "INSERT INTO tv_events(t, kind, value, detail) VALUES (?,?,?,?)",
        [(e.t, e.kind, e.value, e.detail) for e in record()],
    )
    store.conn.commit()
    s = config.Settings(state_dir=str(tmp_path), db_path=store.path, reports_dir=str(tmp_path / "reports"))
    a, b = queries.day_bounds(time.strftime("%Y-%m-%d", time.localtime(evening(5))))
    assert "app_sessions" in queries.window_report(store.conn, a, b, lg, now=NOW)
    pack = json.dumps(analyst.pack(store.conn, a, b, "day", lg, s))
    for word in ("app_sessions", "tv_events", "session.up", "com.webos.app.home", 'aiv-cdn.net", "new'):
        assert word not in pack, word
