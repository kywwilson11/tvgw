"""(experiments) `tvgw experiment`, design decision 75: the five report-only experiments over a synthetic
store. New-name probation's weekly count, the platform hosts by the TV's state, fan-out association, the
ACR meter with its positive control, and the firmware before-and-after report with its A/A floor. Each
changes nothing; the tests also hold the failure paths (an empty store, a store still warming up, a
profile without a screen-recognition category, a window with gaps). Addresses are documentation ranges."""

import json
import os
import random
import re
import time

import acr_synth as synth
import pytest
from appfront_store import DAY, H0, HDMI, HOUR, YT, Store, app, down, evening, power, up

from tvgw import appfront, budget, cli, experiments, queries
from tvgw import profile as profile_mod

GW = "10.10.10.1"


@pytest.fixture()
def store(tmp_path):
    s = Store(tmp_path / "tvgw.db")
    yield s
    s.conn.close()


def begin(store: Store, t: float = H0) -> None:
    """The record starts at `t`: the first ingest run."""
    store.conn.execute("INSERT INTO ingest_runs(t, seconds) VALUES (?, 1)", (t,))
    store.conn.commit()


def seen(store: Store, name: str, t: float) -> None:
    """A name's first sighting, as the hourly ingest's `hosts` refresh records it."""
    store.conn.execute(
        "INSERT OR REPLACE INTO hosts(name, first_seen, last_seen) VALUES (?, ?, ?)", (name, t, t)
    )
    store.conn.commit()


def events(store: Store, evs) -> None:
    store.conn.executemany(
        "INSERT INTO tv_events(t, kind, value, detail) VALUES (?, ?, ?, ?)",
        [(e.t, e.kind, e.value, e.detail) for e in evs],
    )
    store.conn.commit()


def setting(store: Store, t: float, key: str, value: str) -> None:
    store.conn.execute("INSERT INTO tvsettings(t, key, value) VALUES (?, ?, ?)", (t, key, value))
    store.conn.commit()


# ---- 1. new-name probation -----------------------------------------------------------------------------
def test_an_empty_store_and_a_store_still_warming_up_count_nothing(store, lg):
    assert experiments.probation(store.conn, lg, H0 + 30 * DAY) == {"state": "empty"}
    begin(store)
    r = experiments.probation(store.conn, lg, H0 + 10 * DAY)
    assert r["state"] == "warming"
    # 14 calendar days from the record's first local midnight: the clocks went back on 2026-11-01, so
    # 14 x 86,400 s would end an hour early
    assert experiments.local_time(r["counted_from"]) == "2026-11-09 00:00"
    assert "only after its first 14 days" in "\n".join(experiments.render_probation(r))


def probation_store(store: Store) -> float:
    """The record from H0; names first seen before and after the warm-up. Returns `now`."""
    begin(store)
    seen(store, "old.example.com", H0 + HOUR)
    seen(store, "cdn2.old.example.com", H0 + 20 * DAY)  # a new name under an old domain: not new
    t1 = H0 + 16 * DAY + 20 * HOUR  # 2026-11-11, ISO week 46
    seen(store, "api.newapp.example", t1)
    store.lookup(t1, "api.newapp.example")
    store.talk(t1 + 1, "api.newapp.example")
    seen(store, "img.newapp.example", t1 + 60)  # the same new domain: counted once, by its first name
    t2 = t1 + DAY
    seen(store, "ads.newtracker.example", t2)
    store.lookup(t2, "ads.newtracker.example", blocked=1)
    store.lookup(t2 + 5, "ads.newtracker.example", blocked=1)
    t3 = t1 + 2 * DAY
    seen(store, "half.example.org", t3)
    store.lookup(t3, "half.example.org", blocked=1)
    store.lookup(t3 + 9, "cdn.half.example.org")
    t4 = H0 + 23 * DAY + 20 * HOUR  # 2026-11-18, ISO week 47
    seen(store, "direct.example.net", t4)  # reached with no lookup in the store
    store.talk(t4, "direct.example.net")
    seen(store, "snu.lge.com", t4 + HOUR)  # a must-allow host first seen after the warm-up
    store.lookup(t4 + HOUR, "snu.lge.com")
    return H0 + 30 * DAY


def test_probation_counts_new_domains_by_week_and_what_a_rule_would_have_held(store, lg):
    now = probation_store(store)
    r = experiments.probation(store.conn, lg, now)
    assert r["state"] == "counted"
    by = {d["domain"]: d for d in r["domains"]}
    assert set(by) == {"newapp.example", "newtracker.example", "example.org", "example.net", "lge.com"}
    assert by["newapp.example"]["name"] == "api.newapp.example" and by["newapp.example"]["hellos"] == 1
    assert by["newapp.example"]["status"] == "answered" and by["newapp.example"]["held"]
    assert by["newtracker.example"]["status"] == "refused" and not by["newtracker.example"]["held"]
    assert by["newtracker.example"]["refused"] == 2
    assert by["example.org"]["status"] == "partly refused" and by["example.org"]["held"]
    assert by["example.net"]["status"] == "no lookup" and not by["example.net"]["held"]
    assert by["lge.com"]["class"] == appfront.PLATFORM and by["lge.com"]["held"]
    assert by["lge.com"]["company"] == "LG Group"
    weeks = {w["week"]: w for w in r["weeks"]}
    assert (
        weeks["2026-W46"]["new"] == 3 and weeks["2026-W46"]["refused"] == 1 and weeks["2026-W46"]["held"] == 2
    )
    assert weeks["2026-W46"]["held_by_class"] == {"unclassified": 2}
    assert (
        weeks["2026-W47"]["new"] == 2
        and weeks["2026-W47"]["held"] == 1
        and weeks["2026-W47"]["no_lookup"] == 1
    )
    assert not weeks["2026-W46"]["partial"] and r["weeks"][-1]["partial"]
    s = r["summary"]
    assert s["full_weeks"] == 2 and s["held_per_week"] == 1.5 and s["held_most"] == 2
    assert s["platform_held"] == 1 and s["no_lookup"] == 1
    text = "\n".join(experiments.render_probation(r))
    assert "would have held 1.5 new domains a week, at most 2" in text
    assert "Of them, 1 domain the TV must reach: a rule would have to let it through" in text
    assert "1 new domain reached with no lookup in the store: a rule at the resolver cannot hold" in text
    assert "newapp.example  unclassified; 1 answered, 0 refused, 1 connection named  would hold" in text


def test_probation_week_counts_add_up_on_random_stores(tmp_path, lg):
    """Property: every new domain falls in exactly one week, and each week's held, refused and unlooked
    domains are its new ones, never more."""
    for seed in range(6):
        rng = random.Random(seed)
        s = Store(tmp_path / f"p{seed}.db")
        begin(s)
        for i in range(40):
            t = H0 + rng.uniform(0, 40) * DAY
            name = f"n{i}.d{rng.randrange(25)}.example"
            seen(s, name, t)
            for _ in range(rng.randrange(3)):
                s.lookup(t + rng.uniform(0, 3600), name, blocked=rng.randrange(2))
        r = experiments.probation(s.conn, lg, H0 + 41 * DAY)
        assert sum(w["new"] for w in r["weeks"]) == len(r["domains"])
        for w in r["weeks"]:
            assert w["held"] + w["refused"] + w["no_lookup"] == w["new"]
            assert sum(w["held_by_class"].values()) == w["held"]
        assert all(d["first"] >= r["counted_from"] for d in r["domains"])
        s.conn.close()


# ---- 2. just-in-time platform access ---------------------------------------------------------------
def platform_store(store: Store) -> tuple[float, float]:
    """One live evening: YouTube, then HDMI, the screen saver, then the TV off. Returns the window."""
    t0 = evening(1, 20)
    events(
        store,
        [up(t0), power(t0, "Active"), app(t0, YT), app(t0 + 1800, HDMI), power(t0 + 3600, "Screen Saver"),
         power(t0 + 5400, "Active Standby"), down(t0 + 5460, "off")],
    )  # fmt: skip
    store.reading(t0 + 5500, "Active Standby", "")
    store.reading(t0 + 8500, "Active Standby", "")
    store.lookup(t0 + 600, "us.lgtvsdp.com")
    store.talk(t0 + 601, "us.lgtvsdp.com")
    store.lookup(t0 + 2400, "us.lgtvsdp.com")
    store.lookup(t0 + 4000, "snu.lge.com")
    store.talk(t0 + 4001, "snu.lge.com")
    store.lookup(t0 + 6000, "ca.lgtvsdp.com")  # a clock host, not this TV's must-allow one
    store.lookup(t0 + 9000, "lgtvonline.lge.com", blocked=1)
    store.lookup(t0 + 700, "www.youtube.com")  # not a platform host
    return evening(1, 19), evening(1, 23)


def test_platform_hosts_are_counted_by_what_the_tv_was_doing(store, lg):
    a, b = platform_store(store)
    r = experiments.platform(store.conn, lg, a, b, GW)
    hosts = {h["host"]: h for h in r["hosts"]}
    clock = hosts["us.lgtvsdp.com"]
    assert (
        clock["lookups"]["app"] == 1 and clock["lookups"]["input"] == 1 and clock["connections"]["app"] == 1
    )
    assert hosts["snu.lge.com"]["lookups"]["idle"] == 1 and hosts["snu.lge.com"]["connections"]["idle"] == 1
    # a name both lists cover is filed once, under its must-allow host; another country's clock host
    # under the clock pattern
    assert hosts["??.lgtvsdp.com"]["lookups"]["off"] == 1
    assert sum(hosts["??.lgtvsdp.com"]["lookups"].values()) == 1
    assert (
        hosts["lgtvonline.lge.com"]["lookups"]["unknown"] == 1 and hosts["lgtvonline.lge.com"]["refused"] == 1
    )
    assert r["live"] is True
    assert r["hours"]["app"] == 0.5 and r["hours"]["input"] == 0.5 and r["hours"]["idle"] == 0.5
    assert sum(r["hours"].values()) == pytest.approx((b - a) / 3600, abs=0.02)
    text = "\n".join(experiments.render_platform(r))
    assert "The filter refused lgtvonline.lge.com 1 time: the TV must reach it." in text
    assert "Not contacted in these days:" in text and "us.lgrecommends.lgappstv.com" in text


def test_state_seconds_cover_the_window_on_random_timelines(tmp_path):
    """Property: the states partition the window, whatever the readings say."""
    states = ("Active", "Screen Saver", "Active Standby", "unreachable", "unknown")
    apps = (YT, HDMI, "com.webos.app.home", "airplay", "netflix")
    for seed in range(8):
        rng = random.Random(seed)
        s = Store(tmp_path / f"t{seed}.db")
        t = H0
        for _ in range(60):
            t += rng.choice((1800, 3600, 3600, 5000, 7200))
            s.reading(t, rng.choice(states), rng.choice(apps))
        a, b = H0, t + HOUR
        tl = experiments.timeline(s.conn, a, b)
        assert sum(experiments.state_seconds(tl).values()) == pytest.approx(b - a)
        for _ in range(50):
            assert experiments.state_at(tl, rng.uniform(a, b)) in experiments.STATES
        s.conn.close()


# ---- 3. fan-out association --------------------------------------------------------------------------
def fanout_store(store: Store) -> tuple[float, float]:
    for day in range(5):
        t = evening(day, 20)
        store.lookup(t, "player.example-cdn.net")  # unclassified
        store.lookup(t + 3, "player.example-cdn.net")  # inside the same episode
        store.lookup(t + 1, "ads.doubleclick.net", blocked=1)
        store.lookup(t - 1.5, "www.youtube.com")
        store.lookup(t + 600, "quiet.example.org")  # unclassified, nothing near it
        store.lookup(t + 900, "edge.example-far.net")
        store.lookup(t + 902.5, "ads.doubleclick.net", blocked=1)  # outside the 2-second window
        store.lookup(t + 3600 * 2, "ads.doubleclick.net", blocked=1)
    store.lookup(evening(0, 21), "once.example.info")  # one day only: never ranked
    return H0, H0 + 6 * DAY


def test_fanout_ranks_the_unclassified_names_with_refused_lookups_beside_them(store, lg):
    a, b = fanout_store(store)
    r = experiments.fanout(store.conn, lg, a, b)
    assert r["unclassified"] == 4 and r["ranked"] == 3
    top = r["top"][0]
    assert top["domain"] == "example-cdn.net" and top["episodes"] == 5 and top["days"] == 5
    assert top["flagged"] == 5 and top["refused_after"] == 5
    near = {n["domain"]: n for n in top["neighbours"]}
    assert near["doubleclick.net"]["label"] == experiments.REFUSED
    assert near["doubleclick.net"]["category"] == "3rd-party ads"
    assert (near["doubleclick.net"]["before"], near["doubleclick.net"]["after"]) == (0, 5)
    assert near["doubleclick.net"]["lift"] > 1
    assert near["youtube.com"]["label"] == appfront.CONTENT and near["youtube.com"]["before"] == 5
    far = next(x for x in r["top"] if x["domain"] == "example-far.net")
    assert far["flagged"] == 0 and not far["neighbours"]  # 2.5 s is outside the window
    assert "example.info" not in {x["domain"] for x in r["top"]}
    text = "\n".join(experiments.render_fanout(r))
    assert text.endswith(experiments.ASSOCIATION) and "Association, not proof" in text


def test_fanout_counts_hold_on_random_lookups(tmp_path, lg):
    """Property: an episode is flagged at most once, a neighbour counted at most once per episode, and
    each counted co-occurrence is before or after, never both."""
    names = ["u1.unknown-a.example", "u2.unknown-b.example", "ads.doubleclick.net", "www.youtube.com",
             "tkacr601.alphonso.tv", "us.lgtvsdp.com"]  # fmt: skip
    for seed in range(6):
        rng = random.Random(seed)
        s = Store(tmp_path / f"f{seed}.db")
        for _ in range(400):
            s.lookup(H0 + rng.uniform(0, 5 * DAY), rng.choice(names), blocked=rng.randrange(2))
        r = experiments.fanout(s.conn, lg, H0, H0 + 5 * DAY)
        for x in r["top"]:
            assert 0 <= x["refused_after"] <= x["flagged"] <= x["episodes"]
            for n in x["neighbours"]:
                assert n["before"] + n["after"] == n["co"] <= x["episodes"]
                assert n["days"] <= x["days"]
        s.conn.close()


# ---- 4. the ACR meter --------------------------------------------------------------------------------
def hdmi_hour(store: Store, hour: float) -> None:
    store.reading(hour, "Active", HDMI)
    store.reading(hour + HOUR, "Active", HDMI)


def test_the_meter_reads_nothing_without_hours_on_and_says_so(store, lg):
    r = experiments.acr_meter(store.conn, lg, H0, H0 + DAY)
    assert r["hours_on"] == 0 and r["net_per_hour"] is None
    assert "the meter has no reading" in "\n".join(experiments.render_acr(r))


def test_the_positive_control_reads_the_hour_the_budget_s_estimate_rests_on(lg):
    ctl = experiments.positive_control(lg)
    assert ctl["hours_on"] == 1 and ctl["shaped_findings"] == 1
    # the corner of budget.ACR_HOUR_NET, counted with conntrack's 40-byte headers: a little above it
    assert budget.ACR_HOUR_NET <= ctl["net_per_hour"] <= budget.ACR_HOUR_NET * 1.05
    assert ctl["net_per_hour"] > budget.BUDGET_CAP
    assert experiments.positive_control(lg) == ctl  # the same on every run


def test_the_control_is_the_test_generator_s_corner_hour(store, lg):
    """The control in the package and acr_synth's corner hour, through the same meter, read the same."""
    hour = H0 + 20 * HOUR
    hdmi_hour(store, hour)
    synth.insert(store.conn, synth.imc_corner_hour(hour, ratio=experiments.CONTROL_RATIO))
    r = experiments.acr_meter(store.conn, lg, hour, hour + HOUR, control=False)
    ctl = experiments.positive_control(lg)
    assert r["net_per_hour"] == pytest.approx(ctl["net_per_hour"], rel=0.002)
    assert r["shaped"]["findings"] == ctl["shaped_findings"] == 1


def test_an_hour_of_fingerprinting_moves_the_meter_and_a_streaming_day_does_not(store, lg):
    rng = random.Random(3)
    hour = H0 + 20 * HOUR
    hdmi_hour(store, hour)
    synth.insert(store.conn, synth.imc_fingerprint_hour(rng, hour))
    r = experiments.acr_meter(store.conn, lg, H0, H0 + DAY)
    assert r["named"]["connections"] == 60 and r["named"]["net_up"] > budget.BUDGET_CAP
    assert r["named"]["by_state"][experiments.INPUT_STATE] == r["named"]["net_up"]
    assert r["net_per_hour"] == round(r["named"]["net_up"] / r["hours_on"])
    assert r["shaped"]["findings"] >= 1 and r["shaped"]["cells"] == ["alphonso.tv"]
    quiet = Store(store.path + ".quiet")
    for h in range(8, 22):
        quiet.reading(H0 + h * HOUR, "Active", YT)
    synth.insert(quiet.conn, synth.streaming_day(rng, H0 + 8 * HOUR))
    q = experiments.acr_meter(quiet.conn, lg, H0, H0 + DAY)
    assert q["hours_on"] == 13 and q["named"]["net_up"] == 0 and q["shaped"]["findings"] == 0
    assert q["net_per_hour"] == 0
    text = "\n".join(experiments.render_acr(q))
    assert "0 B on 0 connections, 0 B per hour on" in text and "Positive control" in text
    quiet.conn.close()


def test_the_meter_reads_the_tv_s_consent_and_counts_attempts_apart(store, lg):
    setting(store, H0 + 10, "option.livePlus", "off")
    setting(store, H0 + 10, "eula.acrAllowed", "false")
    setting(store, H0 + 10, "eula.generalTermsAllowed", "true")
    store.lookup(H0 + 20 * HOUR, "tkacr601.alphonso.tv", blocked=1)
    r = experiments.acr_meter(store.conn, lg, H0, H0 + DAY)
    assert r["consent"] == {
        "live_plus": "off",
        "flags": {"acrAllowed": "false", "generalTermsAllowed": "true"},
    }
    assert r["lookups"] == {"answered": 0, "refused": 1}
    assert "Live Plus off; consent flags no ACR flag true" in "\n".join(experiments.render_acr(r))


def test_a_profile_without_a_screen_recognition_category_has_only_the_shape_test():
    generic = profile_mod.load("generic-tv")
    ctl = experiments.positive_control(generic)
    assert ctl["net_per_hour"] == 0 and ctl["shaped_findings"] == 1
    assert all(f[-1] is None for f in experiments.control_flows(H0, generic))


# ---- 5. firmware before and after --------------------------------------------------------------------
def daily(
    store: Store, day: int, names: list[str], ja4: str = "t13d1516h2_aaaaaaaaaaaa_bbbbbbbbbbbb"
) -> None:
    t = evening(day, 20)
    for i, name in enumerate(names):
        store.lookup(t + i, name)
        store.talk(t + i + 0.5, name, ja4=ja4)


BASE = ["us.lgtvsdp.com", "www.youtube.com", "rr1.googlevideo.com", "api.netflix.com"]


def firmware_store(store: Store) -> float:
    begin(store)
    setting(store, H0 + 60, "firmware", "04.60.00")
    for day in range(60):
        names = BASE + ([f"churn{day // 7}.example"] if day % 7 == 0 else [])
        if day >= 40:
            daily(
                store,
                day,
                [*names, "telemetry.newvendor.example"],
                ja4="t13d1717h2_cccccccccccc_dddddddddddd",
            )
            store.conn.execute(
                "INSERT INTO flows(t_start,t_end,proto,dst,dport,sport,pkts_up,bytes_up,pkts_down,bytes_down)"
                " VALUES (?,?,'tcp','198.51.100.40',8883,50000,5,500,5,500)",
                (evening(day, 21), evening(day, 21) + 60),
            )
        else:
            daily(store, day, names)
    setting(store, H0 + 40 * DAY + 21 * HOUR, "firmware", "04.64.00")
    store.conn.commit()
    return H0 + 60 * DAY


def test_a_software_change_is_compared_with_the_days_around_it_and_read_against_the_a_a_floor(store, lg):
    now = firmware_store(store)
    r = experiments.firmware(store.conn, now)
    assert [c["firmware"] for c in r["changes"]] == ["04.64.00"]
    ch = r["changes"][0]
    assert "newvendor.example" in ch["new"]["domains"] and "tcp/8883" in ch["new"]["ports"]
    assert ch["new"]["stacks"] == ["t13d1717h2_cccccccccccc_dddddddddddd"]
    assert ch["gone"]["stacks"] == ["t13d1516h2_aaaaaaaaaaaa_bbbbbbbbbbbb"]
    aa = r["aa"]
    # the latest 28 days with no change: ending at the change, since one is inside the last 28 days
    assert aa["to"] == r["changes"][0]["t"] - experiments.UPDATE_LEAD and aa["to"] - aa[
        "from"
    ] == pytest.approx(28 * DAY, abs=HOUR)
    assert r["floor"]["ports"] == 0 and r["floor"]["stacks"] == 0 and r["floor"]["domains"] == 2
    # three new domains against a fortnight's two is not above the floor; a new port and a new TLS stack,
    # against none, are
    assert ch["above"] == {"domains": False, "ports": True, "stacks": True, "qtypes": False}
    text = "\n".join(experiments.render_firmware(r))
    assert "A/A floor, the same firmware on both sides" in text and "04.64.00 (firmware)" in text
    assert "read a difference against the A/A floor" in text


def test_no_change_gives_the_floor_alone_and_a_short_record_gives_neither(store, lg):
    begin(store)
    for day in range(30):
        daily(store, day, BASE)
    r = experiments.firmware(store.conn, H0 + 30 * DAY)
    assert r["changes"] == [] and r["aa"] is not None and r["floor"]["domains"] == 0
    assert "No software change of the TV is in the record" in "\n".join(experiments.render_firmware(r))
    short = experiments.firmware(store.conn, H0 + 20 * DAY)
    assert short["aa"] is None and "No A/A floor yet" in "\n".join(experiments.render_firmware(short))


def test_a_window_with_gaps_is_marked_thin(store, lg):
    begin(store)
    for day in list(range(0, 5)) + list(range(14, 28)):
        daily(store, day, BASE)
    r = experiments.firmware(store.conn, H0 + 28 * DAY)
    assert r["aa"]["thin"] and r["aa"]["days"][0] == 5
    assert "the floor counts a gap as change" in "\n".join(experiments.render_firmware(r))


@pytest.mark.parametrize(
    ("n", "floor", "feature", "above"),
    [(5, 0, "domains", True), (2, 0, "domains", False), (3, 0, "domains", True), (10, 5, "domains", False),
     (11, 4, "domains", True), (9, 4, "domains", True), (8, 4, "domains", False), (99, None, "domains", False),
     (1, 0, "ports", True), (1, 0, "stacks", True), (1, 0, "qtypes", True), (2, 1, "stacks", False),
     (3, 1, "stacks", True)],
)  # fmt: skip
def test_above_the_floor_needs_a_margin_and_more_than_twice_it(n, floor, feature, above):
    assert experiments.above_floor(n, floor, feature) is above


# ---- the command -------------------------------------------------------------------------------------
def gateway_conf(tmp_path, db: str) -> str:
    conf = tmp_path / "tvgw.conf"
    conf.write_text(f"STATE_DIR={tmp_path}\nPROFILE=lg-webos\n", encoding="utf-8")
    return str(conf)


def test_the_command_runs_every_experiment_read_only_and_prints_json(store, tmp_path, monkeypatch, capsys):
    now = probation_store(store)
    monkeypatch.setattr(time, "time", lambda: now)
    conf = gateway_conf(tmp_path, store.path)
    before = os.path.getmtime(store.path)
    assert cli.EXPERIMENTS == experiments.NAMES
    for name in experiments.NAMES:
        assert cli.main(["--conf", conf, "--db", store.path, "experiment", name]) == 0
        out = capsys.readouterr().out
        assert out.strip() and not re.search(r"192\.168\.|([0-9a-f]{2}:){5}[0-9a-f]{2}", out)
        assert cli.main(["--conf", conf, "--db", store.path, "experiment", name, "--json"]) == 0
        json.loads(capsys.readouterr().out)
    assert os.path.getmtime(store.path) == before
    assert cli.main(["--conf", conf, "--db", store.path, "experiment", "fanout", "--days", "0"]) == 2
    assert "--days must be 1 to" in capsys.readouterr().err


def test_an_unknown_experiment_is_refused(store, lg):
    with pytest.raises(ValueError, match="no experiment named"):
        experiments.run("lockdown", store.conn, lg, H0, 14, GW)


def test_week_bounds_and_iso_weeks_agree():
    for t in (H0, H0 + 6 * DAY + 23 * HOUR, H0 + 7 * DAY):
        w0, w1 = queries.week_bounds(experiments.iso_week(t))
        assert w0 <= t < w1
