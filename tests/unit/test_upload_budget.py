"""(budget) The upload budget (design decision 66): the net measure and why the gross bound cannot be it,
the positive control shaped like IMC 2024's LG measurement, the shapes that must stay silent, the ceiling
set once from the clean history, bounded by the cap and never computed again, a store shaped like the
reference gateway's evaluation, the first days of a new install, the owner's setting, and the brief's
lines, engineering and plain. Fixtures come from published summary numbers and from the sizes of that
evaluation, with names that are the profile's own or examples, never from a trace."""

import dataclasses
import io
import json
import math
import random
import sqlite3

import acr_synth as synth
import pytest
from conftest import NOW, fake_extract, fake_oddport

from tvgw import analyst, budget, cli, config, db, forget, ingest, plain, queries

SEEDS = range(1, 9)
TELEMETRY = "collector.example.net"  # a name no category covers: Other, outside the expected categories
TELEMETRY_SERVER = "198.51.100.40"
REPLY = 2_000  # bytes of content back on an upload connection


@pytest.fixture()
def conn(tmp_path):
    c = db.connect(str(tmp_path / "budget.db"))
    yield c
    c.close()


def midnight(day: str) -> float:
    """A local midnight, computed under the test time zone (not at import time)."""
    return queries.day_bounds(day)[0]


def clock(day: str, hour: int, minute: int = 0) -> float:
    """A local clock time, so the day the clocks go back, with its 25 hours, reads as the clock does."""
    return queries.datetime.strptime(day, "%Y-%m-%d").replace(hour=hour, minute=minute).timestamp()


def upload(t: float, net: int, sport: int, name: str | None = TELEMETRY, dst: str = TELEMETRY_SERVER):
    """One connection that sends `net` bytes more content than it gets back (REPLY), as conntrack counts
    it, so its net is exactly `net`."""
    return synth.connection(t, 20.0, dst, 443, sport, [net + REPLY], [REPLY], name)


def download(t: float, gross: int, down: int, sport: int, name: str | None, dst: str, acks: int = 1_000_000):
    """One connection whose TV side is `acks` acknowledgements carrying TCP options: conntrack's bytes up
    less HEADER_BYTES a packet leave `gross` bytes of options, the payload bound up, against `down`
    bytes of content down."""
    pkts_down = down // 1448 + 1
    return synth.Flow(
        t_start=t,
        t_end=t + 900 + synth.FIN_LINGER,
        dst=dst,
        dport=443,
        sport=sport,
        bytes_up=synth.HEADER * acks + gross,
        pkts_up=acks,
        bytes_down=down + synth.HEADER * pkts_down,
        pkts_down=pkts_down,
        sni=name,
    )


def record_starts(conn, t: float) -> None:
    """The store's first ingest run, which says how far back its record reaches."""
    conn.execute("INSERT INTO ingest_runs(t, seconds) VALUES (?, 1)", (t,))
    conn.commit()


def background(
    conn, since: float, days: int = budget.BUDGET_DAYS, sport: int = 60_000, per_day: int = 1
) -> None:
    """Named streaming connections from 10:00 every day, an expected category the budget never counts, so
    every day of the history has flows and its TCP 443 connections are named: covered."""
    day = queries.datetime.fromtimestamp(since)
    flows = []
    for d in range(days):
        t = (day + queries.timedelta(days=d)).replace(hour=10).timestamp()
        flows += [
            upload(t + i, 1_000, sport + d * per_day + i, "www.youtube.com", "198.51.100.20")
            for i in range(per_day)
        ]
    synth.insert(conn, flows)


IDENT = {"rule": budget.RULE, "measure": budget.MEASURE, "profile": "lg-webos", "tv": None}


def clean_history(conn, since: float, largest: int, days: int = budget.BUDGET_DAYS) -> None:
    """Two weeks of a modest telemetry upload at 14:00 every day, 60 KB net, and one day of `largest`."""
    flows = [
        upload(since + d * 86400 + 14 * 3600, largest if d == 5 else 60_000, 20_000 + d) for d in range(days)
    ]
    synth.insert(conn, flows)
    record_starts(conn, since - 3600)


def fixed(conn, lg, largest: int) -> dict:
    """A store whose ceiling the ingest set from the 14 days to 2026-10-26, the fixture's NOW."""
    clean_history(conn, midnight("2026-10-12"), largest)
    state = budget.fix(conn, lg, NOW, 365)
    conn.commit()
    assert state["state"] == budget.FIXED
    return state


def report(conn, lg, day: str = "2026-10-26", setting: str = "auto") -> dict:
    a, b = queries.day_bounds(day)
    return budget.report(conn, a, b, lg, setting)


# ---- the measure ---------------------------------------------------------------------------------------


def test_the_net_is_what_one_connection_sent_beyond_what_came_back():
    assert budget.net_up(10_000 + 40 * 10, 10, 2_000 + 40 * 5, 5) == 8_000
    assert budget.net_up(1_000 + 40 * 10, 10, 9_000 + 40 * 5, 5) == 0  # never below zero
    assert budget.net_up(2_000_000, None, None, None) == 2_000_000  # no counts: the bytes whole
    assert budget.net_up(2_000_000, None, 300_000, None) == 1_700_000


def test_one_long_download_with_tens_of_mb_of_bound_up_nets_nothing(conn, lg):
    """The shape that broke the gross bound on the reference gateway's record: a live-video delivery
    host, one connection, tens of GB down, and over a million acknowledgements whose TCP options leave
    56 MB of "payload bound" up. Gross it is the largest destination-hour of 12 days, at 50 times the
    floor; net it is nothing, so it is no event and could never set the ceiling."""
    a, _ = queries.day_bounds("2026-10-26")
    dl = download(
        a + 15 * 3600, 55_899_828, 30_000_000_000, 41_000, "edge.live-video.example", "198.51.100.120"
    )
    synth.insert(conn, [dl])
    (cell,) = budget.destination_hours(conn, *queries.day_bounds("2026-10-26"), lg).values()
    assert (cell["payload_up"], cell["net_up"]) == (55_899_828, 0)
    assert cell["payload_up"] > 50 * budget.BUDGET_FLOOR and report(conn, lg)["events"] == []


@pytest.mark.parametrize("seed", SEEDS)
def test_a_long_streams_acknowledgements_to_a_streaming_host_are_not_upload(conn, lg, seed):
    """YouTube's best lab day: 11.8 MB up on its API at 3 times the bytes down, and 2 GB of video whose
    side from the TV is acknowledgements. Both are Streaming, an expected category."""
    synth.insert(conn, synth.streaming_day(random.Random(seed), midnight("2026-10-26") + 8 * 3600))
    assert report(conn, lg)["events"] == []


def test_a_large_download_from_an_unclassified_host_with_a_small_upload_is_not_upload(conn, lg):
    """A 400 MB download whose TV side is all acknowledgements: conntrack counts megabytes up and the
    net counts nothing, named or not."""
    (dl,) = synth.firmware_download(midnight("2026-10-26") + 3 * 3600)
    assert dl.bytes_up > 10 * budget.BUDGET_FLOOR  # raw bytes would be an event
    named = dataclasses.replace(dl, sport=56_001, dst="198.51.100.91", sni="cdn.example.org")
    synth.insert(conn, [dl, named])
    assert report(conn, lg)["events"] == []
    cells = budget.destination_hours(conn, *queries.day_bounds("2026-10-26"), lg)
    assert {c["key"]: c["net_up"] for c in cells.values()} == {"203.0.113.0/24": 0, "example.org": 0}


def test_a_download_on_one_connection_never_hides_an_upload_on_another(conn, lg):
    """Netting is per connection: a 2 MB upload beside a 9 GB download to the same destination in the
    same hour is still 2 MB net."""
    t = midnight("2026-10-26") + 12 * 3600
    synth.insert(
        conn,
        [
            upload(t, 2_000_000, 42_001, "a.example.net"),
            download(t + 60, 300_000, 9_000_000_000, 42_002, "b.example.net", "198.51.100.41"),
        ],
    )
    (e,) = report(conn, lg)["events"]
    assert (e["key"], e["net_up"], e["payload_up"], e["conns"]) == ("example.net", 2_000_000, 2_302_000, 2)


# ---- the positive control ------------------------------------------------------------------------------


@pytest.mark.parametrize("seed", SEEDS)
def test_the_synthetic_hour_is_imc_2024s_published_lg_hour(seed):
    """IMC 2024's tables are Ethernet frames, both ways, per one-hour run (deep dive 13, 1.3): the
    fixture's hour lands inside the US LG's 4,125 to 4,948 KB, on one destination and one port."""
    flows = synth.imc_fingerprint_hour(random.Random(seed), 0.0)
    low, high = synth.IMC_HOUR_FRAMES
    assert low <= synth.frame_bytes(flows) <= high
    assert {f.dport for f in flows} == {synth.ACR_PORT} and all(f.sni in synth.ACR_NAMES for f in flows)
    assert all(0 <= f.t_start < 3600 for f in flows)


@pytest.mark.parametrize("seed", SEEDS)
@pytest.mark.parametrize("named", [True, False])
@pytest.mark.parametrize("largest", [None, 90_000, 681_064, 1_000_000, 5_000_000])
def test_an_hour_shaped_like_the_published_lg_measurement_would_have_been_capped(
    conn, lg, seed, named, largest
):
    """The positive control: on a new install (the floor) and against every kind of ceiling the rule
    can set (the floor, twice an ordinary hour, the cap, the cap a TV's own hour reached), one hour of
    LG's fingerprinting is an event, at least twice over the ceiling, by its domain when the hellos were
    captured and by its /24 when none was."""
    hour = midnight("2026-10-26") + 20 * 3600
    synth.insert(conn, synth.imc_fingerprint_hour(random.Random(seed), hour, named=named))
    if largest is not None:
        fixed(conn, lg, largest)
    sec = report(conn, lg)
    (e,) = sec["events"]
    key = "alphonso.tv" if named else "203.0.113.0/24"
    assert (e["key"], e["hour"], e["ports"], e["named"], e["conns"]) == (key, hour, [4431], named, 60)
    assert e["net_up"] >= 2 * sec["ceiling"] and e["net_up"] >= budget.ACR_HOUR_NET
    assert json.loads(json.dumps(sec))["events"] == [e]  # the brief's --json carries it as is


def test_the_constants_are_the_ones_the_decision_derives():
    """The net of IMC's quietest fingerprinting hour (4,125 KB of frames, 7 times up to down, the whole
    down side taken off), the cap at half of it, the floor at about twice IMC's busiest hour without
    fingerprinting and under a fifth of the net, and a multiplier that keeps the reference's largest
    ordinary hour (681,064 bytes net) under the cap."""
    net = 4_125_000 * (7 / 8 * 1448 / 1514 - 1 / 8)
    assert budget.ACR_HOUR_NET == math.floor(net / 10_000) * 10_000 == 2_930_000
    assert budget.BUDGET_CAP == budget.ACR_HOUR_NET // 2
    assert budget.BUDGET_FLOOR == 512 * 1024 and 1.9 < budget.BUDGET_FLOOR / 265_000 < 2.1
    assert budget.BUDGET_FLOOR * 5 < budget.ACR_HOUR_NET
    assert budget.BUDGET_TIMES == 2 and budget.BUDGET_TIMES * 681_064 < budget.BUDGET_CAP
    assert budget.ACR_HOUR_NET < 10 * 681_064  # the research pass's ten times could not stand
    assert budget.BUDGET_DAYS == 14


# ---- the ceiling the rule can set ----------------------------------------------------------------------


def test_the_rule_never_sets_a_ceiling_the_published_acr_hour_would_pass_under():
    """A property, over every size from nothing to 10 GB: the rule's ceiling is at least the floor, at
    most the cap, and the quietest published ACR hour is always at least twice over it. Only the owner's
    setting goes higher."""
    rng = random.Random(66)
    sizes = [0, 1, budget.BUDGET_FLOOR // 2, budget.BUDGET_CAP // 2, budget.BUDGET_CAP - 1, budget.BUDGET_CAP]
    sizes += [int(10 ** rng.uniform(0, 10)) for _ in range(5_000)]
    for x in sizes:
        c = budget.ceiling_for(x)
        assert budget.BUDGET_FLOOR <= c <= budget.BUDGET_CAP and 2 * c <= budget.ACR_HOUR_NET, x
        assert c == budget.BUDGET_TIMES * x or c in (budget.BUDGET_FLOOR, budget.BUDGET_CAP), x
    assert config.upload_ceiling_bytes("4M") > budget.ACR_HOUR_NET


@pytest.mark.parametrize("seed", range(20))
def test_no_clean_history_raises_the_ceiling_over_the_cap(conn, lg, seed):
    """The same property through derive(): random histories of uploads to unclassified names, from a few
    bytes to 100 MB net an hour, never fix a ceiling over the cap, and the largest of them is the one
    the derivation names."""
    rng = random.Random(seed)
    since = midnight("2026-10-12")
    nets = [int(10 ** rng.uniform(2, 8)) for _ in range(30)]
    synth.insert(
        conn,
        [
            upload(since + rng.randrange(14 * 24) * 3600 + 60, n, 43_000 + i, f"h{i}.example{i}.net")
            for i, n in enumerate(nets)
        ],
    )
    record_starts(conn, since - 3600)
    background(conn, since)
    state = budget.fix(conn, lg, NOW, 365)
    assert state["ceiling"] <= budget.BUDGET_CAP and state["largest"] == max(nets)
    assert state["at_cap"] == (max(nets) >= budget.BUDGET_CAP)


def test_the_ceiling_is_twice_the_largest_clean_destination_hour(conn, lg):
    state = fixed(conn, lg, largest=681_064)
    assert (state["ceiling"], state["largest"], state["at_cap"]) == (1_362_128, 681_064, False)
    assert (state["key"], state["hour"]) == ("example.net", midnight("2026-10-17") + 14 * 3600)
    assert (state["since"], state["until"]) == (midnight("2026-10-12"), midnight("2026-10-26"))
    assert state["set_t"] == NOW and state["days"] == 14 and state["acr_days"] == 0
    assert (state["times"], state["floor"], state["cap"]) == (2, budget.BUDGET_FLOOR, budget.BUDGET_CAP)


def test_the_floor_holds_when_twice_the_largest_clean_hour_is_less(conn, lg):
    state = fixed(conn, lg, largest=90_000)
    assert state["ceiling"] == budget.BUDGET_FLOOR and state["largest"] == 90_000


def test_the_cap_holds_when_twice_the_largest_clean_hour_is_more(conn, lg):
    state = fixed(conn, lg, largest=900_000)
    assert (state["ceiling"], state["at_cap"]) == (budget.BUDGET_CAP, False)


def test_a_clean_hour_at_the_cap_fixes_the_cap_and_says_so(conn, lg):
    """This TV's own uploads reach the size the budget watches for: the ceiling stays at the cap, never
    raised to fit them, the brief names the destination-hour, and every hour like it is an event."""
    state = fixed(conn, lg, largest=1_600_000)
    assert (state["ceiling"], state["at_cap"], state["key"]) == (budget.BUDGET_CAP, True, "example.net")
    synth.insert(conn, [upload(midnight("2026-10-26") + 14 * 3600, 1_600_000, 39_000)])
    assert [e["key"] for e in report(conn, lg)["events"]] == ["example.net"]
    assert lines(report(conn, lg))[2] == (
        "  set 10-26 10:00 from the 14 days 10-12 .. 10-25: the cap: this TV's own uploads reach the size the"
        " budget watches for, 1.5M net in its largest clean destination-hour (example.net, 10-17 14:00), and"
        " every hour like it is listed; look at it"
    )


def test_a_history_with_no_upload_outside_the_expected_categories_gets_the_floor(conn, lg):
    since = midnight("2026-10-12")
    synth.insert(conn, [upload(since + 3600, 900_000, 34_000, "www.youtube.com")])  # Streaming
    record_starts(conn, since - 3600)
    background(conn, since)
    state = budget.fix(conn, lg, NOW, 365)
    assert (state["ceiling"], state["largest"], state["key"], state["hour"]) == (
        budget.BUDGET_FLOOR,
        0,
        None,
        None,
    )


def test_a_destination_day_the_acr_test_flagged_is_not_clean(conn, lg):
    """An upload-heavy telemetry hour that passes the ACR test's hourly form cannot set the ceiling: the
    gateway's own detector called that destination-day suspect."""
    since = midnight("2026-10-12")
    clean_history(conn, since, largest=300_000)
    synth.insert(conn, synth.telemetry_burst(random.Random(1), since + 3 * 86400 + 9 * 3600))
    state = budget.fix(conn, lg, NOW, 365)
    assert state["acr_days"] == 1 and state["largest"] == 300_000 and state["ceiling"] == 600_000


def test_a_tracking_hour_of_2_4_mb_net_is_an_event_and_never_raises_the_ceiling(conn, lg):
    """A name the profile files under tracking (third-party ads), reached anyway, with the size of the
    telemetry host's hour on the reference's first day: no clean history, so the ceiling comes from the
    ordinary hours; over it, an event like any other."""
    since = midnight("2026-10-12")
    clean_history(conn, since, largest=300_000)
    tracker = "browser-intake-datadoghq.com"
    burst = [
        upload(since + 86400 + 72_000 + i * 300, 350_099, 35_000 + i, tracker, "198.51.100.88")
        for i in range(7)
    ]
    synth.insert(conn, burst)
    state = budget.fix(conn, lg, NOW, 365)
    assert (state["largest"], state["ceiling"], state["key"]) == (300_000, 600_000, "example.net")
    t = midnight("2026-10-26") + 3600
    synth.insert(conn, [upload(t + i * 300, 350_099, 35_100 + i, tracker, "198.51.100.88") for i in range(7)])
    (e,) = report(conn, lg)["events"]
    assert (e["key"], e["net_up"], e["conns"]) == (tracker, 7 * 350_099, 7)


def test_an_ordinary_upload_heavy_hour_passes_under_the_ceiling_it_set(conn, lg):
    """An ordinary upload-heavy hour of 0.68 MB net, the first evaluation's largest: it sets the
    ceiling, and the next such hour, or one twice as large, is no event."""
    fixed(conn, lg, largest=681_064)
    t = midnight("2026-10-26") + 15 * 3600
    synth.insert(conn, [upload(t, 681_064, 39_100), upload(t + 7200, 1_362_128, 39_101)])
    assert report(conn, lg)["events"] == []


def test_the_ceiling_is_never_computed_again(conn, lg):
    """Fixed is fixed: a bigger upload inside the old window, a later run, the record growing; none of it
    moves the ceiling. Only the owner's setting or a forget changes it."""
    first = fixed(conn, lg, largest=300_000)
    synth.insert(conn, [upload(midnight("2026-10-20") + 3600, 1_000_000, 36_000)])
    for later in (NOW + 3600, NOW + 30 * 86400):
        assert budget.fix(conn, lg, later, 365) == first
    assert budget.load(conn) == first


def test_the_largest_hours_name_goes_with_db_days_and_the_ceiling_stays(conn, lg):
    first = fixed(conn, lg, largest=300_000)
    later = budget.fix(conn, lg, first["hour"] + 30 * 86400 + 1, 30)
    assert (later["key"], later["hour"]) == (None, None)
    assert {k: v for k, v in later.items() if k not in ("key", "hour")} == {
        k: v for k, v in first.items() if k not in ("key", "hour")
    }
    assert budget.load(conn) == later


def test_the_window_counts_whole_local_days_across_a_clock_change(conn, lg):
    """The 14 days before 2026-11-08 hold 2026-11-01, which has 25 hours in Chicago."""
    since = midnight("2026-10-25")
    record_starts(conn, since - 86400)
    background(conn, since)
    state = budget.fix(conn, lg, midnight("2026-11-08") + 12 * 3600, 365)
    assert (state["since"], state["until"]) == (since, midnight("2026-11-08"))
    assert state["until"] - state["since"] == 14 * 86400 + 3600


def test_the_last_day_settles_before_the_ceiling_is_set(conn, lg):
    """Before 03:00 the day just ended still lacks its idle connections, so the window ends a day earlier."""
    record_starts(conn, midnight("2026-10-01"))
    background(conn, midnight("2026-10-11"))
    state = budget.fix(conn, lg, midnight("2026-10-26") + 2 * 3600, 365)
    assert (state["state"], state["until"]) == (budget.FIXED, midnight("2026-10-25"))


# ---- a store shaped like the reference gateway's evaluation --------------------------------------------


def reference_shaped(conn) -> float:
    """The sizes of the evaluation run on the reference gateway's 12-day record (2026-11-05 and 06), with
    example names for its hosts, the profile's own for its tracking ones, and invented days and hours:
    nothing here says when that household watched. Returns the run that sets the ceiling; the record
    starts on 2026-10-27, so the window is 2026-10-28 to 2026-11-10."""
    record_starts(conn, midnight("2026-10-27") + 18 * 3600)
    background(conn, midnight("2026-10-28"), per_day=40)  # a day's ordinary named connections
    video, sports, cdn = "edge.live-video.example", "api.sports-app.example", None
    flows = [
        # a live-video delivery host: one long download an hour, its acknowledgements tens of MB "up"
        download(clock("2026-11-04", 19), 55_899_828, 31_000_000_000, 50_001, video, "198.51.100.120"),
        download(clock("2026-11-04", 20), 23_156_504, 12_000_000_000, 50_002, video, "198.51.100.120"),
        download(clock("2026-11-04", 21), 6_000_000, 3_000_000_000, 50_003, video, "198.51.100.121"),
        download(clock("2026-11-04", 21) + 900, 6_139_103, 3_100_000_000, 50_004, video, "198.51.100.121"),
        # a sports app's own host: upload-heavy connections beside downloads, 864,544 net in its busiest hour
        upload(clock("2026-11-04", 19) + 60, 500_000, 50_101, sports, "198.51.100.130"),
        upload(clock("2026-11-04", 19) + 120, 364_544, 50_102, sports, "198.51.100.130"),
        *(
            download(
                clock("2026-11-04", 19) + 200 + i,
                170_278,
                6_795_561,
                50_110 + i,
                sports,
                "198.51.100.131",
                2_000,
            )
            for i in range(6)
        ),
        upload(clock("2026-11-04", 20) + 60, 288_769, 50_121, sports, "198.51.100.130"),
        upload(clock("2026-11-04", 21) + 60, 163_776, 50_122, sports, "198.51.100.130"),
        # an unnamed CDN /24 while a streaming app played: four downloads
        *(
            download(
                clock("2026-11-08", 21) + i * 600, 348_556, 900_000_000, 50_201 + i, cdn, "203.0.113.150"
            )
            for i in range(4)
        ),
        # tracking names reached anyway, small: never clean
        upload(clock("2026-11-06", 20), 76_662, 50_301, "cws.conviva.com", "198.51.100.140"),
        upload(clock("2026-11-06", 21), 71_170, 50_302, "x.omtrdc.net", "198.51.100.141"),
        # before the window: a telemetry host's 2.5 MB hour, a shopping and video company's tracker, a /24
        *(
            upload(
                clock("2026-10-25", 20) + i * 300,
                358_476,
                50_401 + i,
                "browser-intake-datadoghq.com",
                "198.51.100.88",
            )
            for i in range(7)
        ),
        upload(clock("2026-10-25", 20) + 30, 1_009_286, 50_411, "unagi-na.amazon.com", "198.51.100.89"),
        upload(clock("2026-10-26", 10), 585_944, 50_412, None, "203.0.113.160"),
    ]
    synth.insert(conn, flows)
    return midnight("2026-11-11") + 4 * 3600


def test_a_store_shaped_like_the_reference_evaluation_fixes_the_cap(conn, lg):
    """The derivation the reference gateway's record gives under this rule, as the second evaluation
    found on the gateway: the live-video host and the CDN net nothing, the tracking names are not clean,
    the hours before the window do not count, and twice the sports app's busiest hour (864,544 net) is
    over the cap, so the ceiling is the cap, with that hour itself under it (not at_cap)."""
    now = reference_shaped(conn)
    state = budget.fix(conn, lg, now, 365)
    assert state == {
        "state": budget.FIXED,
        "ceiling": budget.BUDGET_CAP,
        "largest": 864_544,
        "key": "sports-app.example",
        "hour": clock("2026-11-04", 19),
        "at_cap": False,
        "since": midnight("2026-10-28"),
        "until": midnight("2026-11-11"),
        "days": 14,
        "times": 2,
        "floor": budget.BUDGET_FLOOR,
        "cap": budget.BUDGET_CAP,
        "acr_days": 0,
        "set_t": now,
        **IDENT,
    }
    cells = budget.destination_hours(conn, state["since"], state["until"], lg)
    gross = max(cells.values(), key=lambda c: c["payload_up"])
    assert (gross["key"], gross["payload_up"], gross["net_up"]) == ("live-video.example", 55_899_828, 0)
    assert 190 < 10 * gross["payload_up"] / budget.ACR_HOUR_NET < 191  # the gross rule's ceiling, 191 times


# ---- what counts, and in which hour --------------------------------------------------------------------


def test_a_must_allow_destination_is_never_flagged(conn, lg):
    """A must-allow host is never counted, by its name or a name under it, nor, unnamed, at an address an
    answer for it returned; the same flows to a host the profile does not keep are events."""
    prof = dataclasses.replace(lg, must_allow={**lg.must_allow, "uploads.example.net": "the test's own"})
    t = midnight("2026-10-26") + 12 * 3600
    synth.insert(
        conn,
        [
            upload(t, 5_000_000, 30_001, "uploads.example.net", "198.51.100.70"),
            upload(t + 60, 5_000_000, 30_002, "eu.uploads.example.net", "198.51.100.71"),
            upload(t + 120, 5_000_000, 30_003, None, "198.51.100.77"),
        ],
        [(t - 600, "uploads.example.net", "A", "CNAME:edge.example.com,A:198.51.100.77", 0)],
    )
    assert report(conn, prof)["events"] == []
    got = {e["key"] for e in report(conn, lg)["events"]}  # lg does not keep the host
    assert got == {"example.net", "198.51.100.0/24"}


def test_a_must_allow_host_of_the_shipped_profile_is_expected_and_kept_anyway(conn, lg):
    """On lg-webos the must-allow hosts are LG core, an expected category: the clock host uploading
    megabytes is the TV's own platform, never an event."""
    t = midnight("2026-10-26") + 9 * 3600
    synth.insert(conn, [upload(t, 8_000_000, 31_000, "us.lgtvsdp.com", "198.51.100.5")])
    assert "us.lgtvsdp.com" in lg.must_allow and report(conn, lg)["events"] == []


def test_a_destination_hour_is_its_registrable_domain_and_the_clock_hour_its_flows_opened_in(conn, lg):
    """Two names under one domain are one destination; a flow at 13:59:59 and one at 14:00:00 fall in two
    hours; a flow that opens at the window's end belongs to the next window."""
    a, b = queries.day_bounds("2026-10-26")
    h = a + 14 * 3600
    synth.insert(
        conn,
        [
            upload(h - 1, 400_000, 32_001, "a.example.net"),
            upload(h, 300_000, 32_002, "a.example.net"),
            upload(h + 60, 250_000, 32_003, "b.example.net"),
            upload(b, 9_000_000, 32_004, "a.example.net"),
        ],
    )
    cells = budget.destination_hours(conn, a, b, lg)
    assert {(k, hr - a): c["net_up"] for (k, hr), c in cells.items()} == {
        ("example.net", 13 * 3600): 400_000,
        ("example.net", 14 * 3600): 550_000,
    }
    (e,) = report(conn, lg)["events"]  # 550 KB > 512 KiB; 400 KB is under it
    assert (e["key"], e["hour"] - a, e["net_up"], e["conns"]) == ("example.net", 14 * 3600, 550_000, 2)


def test_a_destination_hour_at_the_ceiling_is_not_over_it(conn, lg):
    a, _ = queries.day_bounds("2026-10-26")
    synth.insert(
        conn,
        [upload(a + 3600, budget.BUDGET_FLOOR, 32_101), upload(a + 7200, budget.BUDGET_FLOOR + 1, 32_102)],
    )
    assert [e["hour"] - a for e in report(conn, lg)["events"]] == [7200]


def test_a_flow_without_a_packet_count_counts_its_bytes_whole(conn, lg):
    a, _ = queries.day_bounds("2026-10-26")
    conn.execute(
        "INSERT INTO flows(t_start, t_end, proto, dst, dport, sport, bytes_up) VALUES (?, ?, 'tcp', ?, 443, 1, ?)",
        (a + 3600, a + 3700, "203.0.113.200", 2_000_000),
    )
    (e,) = report(conn, lg)["events"]
    assert (e["key"], e["net_up"], e["payload_up"], e["named"]) == (
        "203.0.113.0/24",
        2_000_000,
        2_000_000,
        False,
    )


def test_the_gateway_and_private_addresses_are_never_destinations(conn, lg):
    a, _ = queries.day_bounds("2026-10-26")
    synth.insert(
        conn,
        [
            upload(a + 3600, 5_000_000, 33_001, None, "10.10.10.1"),
            upload(a + 3700, 5_000_000, 33_002, None, "10.10.10.40"),
        ],
    )
    assert report(conn, lg)["events"] == []


# ---- the first days of a new install -------------------------------------------------------------------


def test_a_new_install_judges_against_the_floor_and_says_when_the_ceiling_is_set(conn, lg):
    """The record starts at 10:00 on 2026-10-26: its first whole day is 2026-10-27, so the ceiling is set
    at the first hourly run after 03:00 on 2026-11-10. Until then the floor is the ceiling."""
    record_starts(conn, NOW)
    state = budget.fix(conn, lg, NOW + 3600, 365)
    assert state == {
        "state": budget.PENDING,
        "due": midnight("2026-11-10") + budget.SETTLE,
        "since": midnight("2026-10-27"),
        **IDENT,
    }
    sec = report(conn, lg)
    assert (sec["ceiling"], sec["source"], sec["pending"], sec["fixed"]) == (
        budget.BUDGET_FLOOR,
        budget.FLOOR,
        state,
        None,
    )
    out = io.StringIO()
    cli.render_upload_budget(sec, out)
    assert out.getvalue() == ""  # a quiet first fortnight prints nothing
    background(conn, midnight("2026-10-27"))
    assert budget.fix(conn, lg, midnight("2026-11-10") + 4 * 3600, 365)["state"] == budget.FIXED


def test_the_first_run_of_a_store_has_no_record_yet(conn, lg):
    assert budget.fix(conn, lg, NOW, 365) == {"state": budget.PENDING, "due": None, **IDENT}


def test_a_store_that_keeps_too_few_days_keeps_the_floor(conn, lg):
    record_starts(conn, midnight("2026-09-01"))
    assert budget.fix(conn, lg, NOW, 14) == {"state": budget.PENDING, "due": None, "why": "db_days", **IDENT}
    assert report(conn, lg)["ceiling"] == budget.BUDGET_FLOOR


def test_a_meta_row_that_does_not_read_is_no_ceiling(conn, lg):
    db.set_meta(conn, budget.META_KEY, "{not json")
    assert budget.load(conn) is None and report(conn, lg)["source"] == budget.FLOOR


# ---- the owner's setting --------------------------------------------------------------------------------


def test_the_owners_ceiling_wins_and_is_the_one_way_above_the_cap(conn, lg):
    fixed(conn, lg, largest=681_064)
    synth.insert(conn, [upload(midnight("2026-10-26") + 3600, 3_500_000, 37_000)])
    assert [e["net_up"] for e in report(conn, lg)["events"]] == [3_500_000]
    sec = report(conn, lg, setting="4M")
    assert (sec["ceiling"], sec["source"], sec["events"]) == (4 * 1024**2, budget.OWNER, [])
    assert sec["fixed"]["ceiling"] == 1_362_128 and sec["ceiling"] > budget.BUDGET_CAP


@pytest.mark.parametrize(
    ("value", "expected"),
    [
        ("auto", None),
        ("4M", 4 * 1024**2),
        ("512K", 512 * 1024),
        ("1G", 1024**3),
        ("65536", 65536),
        ("64K", 65536),
    ],
)
def test_upload_ceiling_is_auto_or_a_size(tmp_path, value, expected):
    conf = tmp_path / "tvgw.conf"
    conf.write_text(f"UPLOAD_CEILING={value}\n")
    assert config.load(conf).upload_ceiling == value
    assert config.upload_ceiling_bytes(value) == expected


@pytest.mark.parametrize(
    "value", ["4m", "0", "63K", "2G", "1025M", "-1", "Auto", "4 M", "4MB", "0x10", "1.5M"]
)
def test_a_near_miss_of_upload_ceiling_stops_every_command(tmp_path, value):
    conf = tmp_path / "tvgw.conf"
    conf.write_text(f"UPLOAD_CEILING='{value}'\n")
    with pytest.raises(ValueError, match=r"UPLOAD_CEILING=.* in tvgw.conf: expected auto, or a size"):
        config.load(conf)


def test_a_file_without_upload_ceiling_is_auto_and_the_template_shows_it_commented(tmp_path):
    from conftest import ROOT

    assert config.load(tmp_path / "missing.conf").upload_ceiling == "auto"
    text = (ROOT / "deploy" / "tvgw.conf.example").read_text(encoding="utf-8")
    assert "\n# UPLOAD_CEILING=auto\n" in text and "UPLOAD_CEILING" not in config.parse_conf(text)


# ---- the brief: the engineering section ----------------------------------------------------------------


def lines(sec: dict) -> list[str]:
    out = io.StringIO()
    cli.render_upload_budget(sec, out)
    return [ln.rstrip() for ln in out.getvalue().splitlines()]


HEAD = (
    "Upload budget (count-only; nothing is capped): ceiling {} net per destination-hour outside the"
    " expected categories (net: what each connection sent beyond what came back)"
)
SET = "  set 10-26 10:00 from the 14 days 10-12 .. 10-25: "


def test_a_fixed_ceiling_prints_every_day_with_how_it_was_set(conn, lg):
    fixed(conn, lg, largest=681_064)
    assert lines(report(conn, lg)) == [
        "",
        HEAD.format("1.3M"),
        SET + "2 x 665.1K, the largest clean destination-hour (example.net, 10-17 14:00)",
        "  would have capped: none",
    ]


@pytest.mark.parametrize(
    ("largest", "ceiling", "how"),
    [
        (90_000, "512.0K", "the floor, since 2 x 87.9K, the largest clean destination-hour (example.net, 10-17 14:00), is less"),
        (900_000, "1.4M", "the cap, since 2 x 878.9K, the largest clean destination-hour (example.net, 10-17 14:00), is more"),
    ],
)  # fmt: skip
def test_the_floor_and_the_cap_say_why(conn, lg, largest, ceiling, how):
    fixed(conn, lg, largest)
    assert lines(report(conn, lg))[1:3] == [HEAD.format(ceiling), SET + how]


def test_an_event_prints_its_net_and_its_gross_bound(conn, lg):
    fixed(conn, lg, largest=90_000)
    hour = midnight("2026-10-26") + 20 * 3600
    synth.insert(conn, synth.imc_fingerprint_hour(random.Random(1), hour, named=False))
    (e,) = report(conn, lg)["events"]
    got = lines(report(conn, lg))
    assert got[3] == "  would have capped:"
    assert got[4].split() == ["destination", "hour", "net", "payload<=", "conns", "ports"]
    assert got[5].split() == [
        "203.0.113.0/24", "(no", "TLS", "name)", "10-26", "20:00", cli.hb(e["net_up"]), cli.hb(e["payload_up"]),
        "60", "4431",
    ]  # fmt: skip


def test_the_brief_prints_the_section_after_top_upload(conn, lg):
    fixed(conn, lg, largest=90_000)
    o = queries.brief(conn, "2026-10-26", lg, now=NOW + 86400)
    out = io.StringIO()
    cli.render_brief(o, out)
    text = out.getvalue()
    assert (
        text.index("\nTop upload")
        < text.index("\nUpload budget (count-only")
        < text.index("\nGFTS URL filter")
    )


EVENT = {"key": "x.example", "hour": 0, "net_up": 2 * 1024**2, "payload_up": 2 * 1024**2, "conns": 1, "ports": [443], "named": True}  # fmt: skip


@pytest.mark.parametrize(
    ("sec", "how"),
    [
        (
            {"source": budget.OWNER, "ceiling": 4 * 1024**2, "fixed": {"ceiling": 1_362_128}, "events": []},
            "  set by the owner (UPLOAD_CEILING); the gateway's own is 1.3M",
        ),
        ({"source": budget.OWNER, "ceiling": 512 * 1024, "fixed": None, "events": []}, "  set by the owner (UPLOAD_CEILING)"),
        (
            {"source": budget.FLOOR, "ceiling": budget.BUDGET_FLOOR, "fixed": None, "pending": {"state": "pending", "due": None, "why": "db_days"}, "events": [EVENT]},
            "  the floor: the store keeps too few days (DB_DAYS) to hold 14 days of history",
        ),
        (
            {"source": budget.FLOOR, "ceiling": budget.BUDGET_FLOOR, "fixed": None, "pending": None, "events": [EVENT]},
            "  the floor, until the hourly ingest has a record to set the ceiling from",
        ),
    ],
)  # fmt: skip
def test_how_the_ceiling_was_set_in_each_case(sec, how):
    assert lines(sec)[2] == how


def test_a_pending_ceiling_says_when_and_an_owners_high_one_says_what_it_cannot_catch(conn, lg):
    record_starts(conn, NOW)
    budget.fix(conn, lg, NOW + 3600, 365)
    synth.insert(conn, [upload(midnight("2026-10-26") + 3600, 2_000_000, 38_000)])
    got = lines(report(conn, lg))
    assert (
        got[2]
        == "  the floor, until the hourly ingest sets the ceiling from 14 whole days of the record, after 11-10 03:00"
    )
    assert lines(report(conn, lg, setting="4M"))[3] == (
        "  at or above 2.8M, the estimated net of an hour of LG's screen recognition as IMC 2024 measured it:"
        " an hour like that would not count"
    )
    assert len(lines(report(conn, lg, setting="1M"))) == 6  # under it: no such line


def sqlite3_error():
    return sqlite3.OperationalError("disk I/O error")


def test_a_failing_budget_is_a_report_warning_and_the_brief_stands(conn, lg, monkeypatch):
    """The budget is count-only and never a red line, so its failure may cost the report nothing else:
    a report warning, the key None, every other section as it was."""

    def boom(*a, **k):
        raise sqlite3_error()

    before = queries.brief(conn, "2026-10-26", lg, now=NOW)
    monkeypatch.setattr(budget, "report", boom)
    o = queries.brief(conn, "2026-10-26", lg, now=NOW)
    assert o["upload_budget"] is None and o["warnings"] == ["upload budget: OperationalError: disk I/O error"]
    assert {k: v for k, v in o.items() if k not in ("upload_budget", "warnings", "generated")} == {
        k: v for k, v in before.items() if k not in ("upload_budget", "generated")
    }
    out = io.StringIO()
    cli.render_brief(o, out)
    assert "Upload budget" not in out.getvalue() and "report warning: upload budget" in out.getvalue()


def run_ingest(gateway, lg):
    return ingest.run(
        gateway, lg, extract=fake_extract, oddport_lines=fake_oddport, gate_lines=lambda since: [], lock=False
    )


def test_a_failing_ingest_step_is_a_warning_and_every_other_step_lands(gateway, lg, monkeypatch):
    def boom(*a, **k):
        raise sqlite3_error()

    monkeypatch.setattr(budget, "fix", boom)
    assert run_ingest(gateway, lg).warnings == ["budget: OperationalError: disk I/O error"]
    c = db.connect(gateway.db_path, readonly=True)
    assert c.execute("SELECT COUNT(*) FROM flows").fetchone()[0] == 2 and budget.load(c) is None
    c.close()


def test_the_hourly_ingest_writes_the_pending_state(gateway, lg):
    """The first run has no record yet (its own row lands at its end); the second dates the ceiling."""
    assert run_ingest(gateway, lg).warnings == []
    c = db.connect(gateway.db_path, readonly=True)
    assert budget.load(c) == {"state": budget.PENDING, "due": None, **IDENT}
    c.close()
    run_ingest(gateway, lg)
    c = db.connect(gateway.db_path, readonly=True)
    assert budget.load(c) == {
        "state": budget.PENDING,
        "due": midnight("2026-11-10") + budget.SETTLE,
        "since": midnight("2026-10-27"),
        **IDENT,
    }
    c.close()


# ---- never a red line, never in the pack, forgotten with the record ------------------------------------


def test_an_event_is_no_red_line_and_neither_it_nor_the_off_names_enter_the_analysts_pack(
    conn, lg, tmp_path, monkeypatch
):
    """Count-only in this pass: an event raises no red line and so never reaches the Action line, and
    nothing of it, or of the While off names, leaves the gateway in the analyst's evidence pack (the
    pack picks its keys; marked values show that neither new key is among them)."""
    a, _ = queries.day_bounds("2026-10-26")
    synth.insert(conn, synth.imc_fingerprint_hour(random.Random(2), a + 20 * 3600))
    conn.executemany("INSERT INTO tvstate(t, power) VALUES (?, 'unreachable')", [(a + 3600,), (a + 7200,)])
    conn.execute("INSERT INTO dns(t, qname, blocked) VALUES (?, 'standby.example.org', 0)", (a + 5000,))
    conn.commit()
    o = queries.brief(conn, "2026-10-26", lg, now=NOW + 86400)
    assert o["upload_budget"]["events"] and o["standby_names"]
    assert not any("budget" in r.lower() or "upload" in r.lower() for r in o["red_lines"] if "ACR" not in r)
    assert not any("budget" in sentence for _, sentence, _ in plain.items(o, lg))
    real = budget.report

    def marked_report(*args, **kw):
        sec = real(*args, **kw)
        return {**sec, "events": [{**e, "key": "marked-budget.invalid"} for e in sec["events"]]}

    monkeypatch.setattr(budget, "report", marked_report)
    monkeypatch.setattr(
        queries, "standby_names", lambda *a, **k: [{"name": "marked-off.invalid", "lookups": 1}]
    )
    settings = config.Settings(db_path=str(tmp_path / "budget.db"), state_dir=str(tmp_path))
    pack = analyst.pack(conn, *queries.day_bounds("2026-10-26"), "2026-10-26", lg, settings)
    text = json.dumps(pack, default=str)
    assert "marked-budget.invalid" not in text and "marked-off.invalid" not in text
    assert "upload_budget" not in text and "standby_names" not in text
    assert set(pack["totals"]["standby"]) == {"off_hours", "lookups", "conns", "bytes_up"}


def test_tvgw_forget_removes_the_ceiling_with_the_record():
    assert budget.META_KEY in forget.META_FORGET


# ---- the plain brief -----------------------------------------------------------------------------------


def plain_day(events: list[dict], ceiling: int = 1_362_128) -> dict:
    from test_plain import measured_day

    return {**measured_day(), "upload_budget": {"ceiling": ceiling, "source": budget.FIXED, "events": events}}


def event(key: str, net: int, hour: float = 0.0) -> dict:
    return {
        "key": key,
        "hour": hour,
        "net_up": net,
        "payload_up": net,
        "conns": 9,
        "ports": [443],
        "named": True,
    }


def test_no_event_no_plain_line(lg):
    assert not any("Uploads:" in x for x in plain.plain_brief(plain_day([]), profile=lg))


def test_one_event_is_one_plain_line_after_the_action(lg):
    """(a) One destination-hour: what its connections sent beyond what came back on them, per connection
    as the engineering brief counts it, never "more than it got back" from the destination as a whole."""
    got = plain.plain_brief(plain_day([event("example.net", 4_613_734)]), profile=lg)
    assert got[-2] == PLAIN_ONE
    assert got[5].startswith("  Action: nothing needs your attention.")


PLAIN_ONE = (
    "  Uploads: In one hour the TV sent example.net 4.4 MB more than came back on the same connections, over"
    " the 1.3 MB upload budget for services outside its everyday ones. Nothing was stopped."
)


def test_three_events_in_two_clock_hours_say_two_hours(lg):
    """(b) Hours are clock hours: two destinations in one hour are one hour, never two."""
    evs = [
        event("a.example", 3 * 1024**2, 0.0),
        event("b.example", 2 * 1024**2, 0.0),
        event("a.example", 2 * 1024**2, 3600.0),
    ]
    assert plain.plain_brief(plain_day(evs), profile=lg)[-2] == PLAIN_THREE


PLAIN_THREE = (
    "  Uploads: In 2 hours the TV sent 2 services (a.example, b.example) more than came back on the same"
    " connections, over the 1.3 MB upload budget for services outside its everyday ones. Nothing was stopped."
)


def test_several_services_in_one_hour_are_one_hour_and_name_the_rest(lg):
    evs = [event(k, 2 * 1024**2) for k in ("a.example", "b.example", "c.example", "d.example")]
    assert plain.plain_brief(plain_day(evs), profile=lg)[-2] == (
        "  Uploads: In one hour the TV sent 4 services (a.example, b.example, c.example and 1 more) more than"
        " came back on the same connections, over the 1.3 MB upload budget for services outside its everyday"
        " ones. Nothing was stopped."
    )


def test_at_the_cap_the_plain_line_says_why(lg):
    """(c) The TV's own uploads reached the cap in its history: the line says so, so a daily line is
    explained, not a mystery to learn to ignore."""
    o = plain_day([event("example.net", 1_600_000)], ceiling=budget.BUDGET_CAP)
    o["upload_budget"]["fixed"] = {"at_cap": True}
    assert plain.plain_brief(o, profile=lg)[-2] == PLAIN_CAP


PLAIN_CAP = (
    "  Uploads: In one hour the TV sent example.net 1.5 MB more than came back on the same connections, over"
    " the 1.4 MB upload budget for services outside its everyday ones. Nothing was stopped. The TV's own"
    " uploads reached this size in the two weeks the budget was set from, so such hours are listed."
)


def test_a_late_hour_is_counted_and_said(lg):
    o = plain_day([])
    o["upload_budget"]["late"] = [{**event("example.net", 2 * 1024**2), "late_net": 2 * 1024**2}]
    assert plain.plain_brief(o, profile=lg)[-2].endswith(
        "Nothing was stopped. Part of it is from an earlier day: connections that ended only now."
    )


@pytest.mark.parametrize(
    ("run", "new", "shown"),
    [
        (1, True, True),
        (2, False, True),
        (3, False, True),
        (4, False, False),
        (4, True, True),
        (5, False, False),
    ],
)
def test_a_line_that_comes_daily_says_so_once_then_waits_for_a_change(lg, run, new, shown):
    o = plain_day([event("example.net", 4_613_734)])
    o["upload_budget"].update(days_running=run, new_keys=new)
    got = [x for x in plain.plain_brief(o, profile=lg) if x.startswith("  Uploads:")]
    assert bool(got) == shown
    said = " This has come 3 days running, so the short brief leaves it out until it changes (tvgw brief --full keeps it)."
    assert (got[0].endswith(said) if got else None) == (
        True if shown and run == 3 else (False if shown else None)
    )


def test_the_plain_line_is_never_the_action(lg):
    o = plain_day([event("example.net", 4_613_734)])
    assert plain.action(o, lg) is None


# ---- the corner the ACR estimate comes from -------------------------------------------------------------


@pytest.mark.parametrize(("ratio", "times"), [(7.0, 2.0), (4.5, 1.7)])
def test_the_corner_of_the_acr_estimate_is_over_the_highest_ceiling_the_rule_sets(conn, lg, ratio, times):
    """ACR_HOUR_NET is an estimate on two assumptions: a ratio of 7 up to down, and full-size frames with
    the whole down side taken as payload. At that corner (4,125 KB of frames, every frame full-size) the
    hour is twice over the cap and at least the constant itself, so a constant set 20% too high fails
    here; at the trace's lowest domain-wide ratio, 4.5, it is still 1.7 times over the cap, not twice."""
    hour = midnight("2026-10-26") + 20 * 3600
    flows = synth.imc_corner_hour(hour, ratio)
    assert abs(synth.frame_bytes(flows) - synth.IMC_HOUR_FRAMES[0]) < synth.FULL_FRAME
    synth.insert(conn, flows)
    fixed(conn, lg, largest=5_000_000)  # the highest ceiling the rule can set: the cap
    (e,) = report(conn, lg)["events"]
    assert e["net_up"] >= times * budget.BUDGET_CAP
    assert (e["net_up"] >= budget.ACR_HOUR_NET) == (ratio == 7.0)


# ---- the clean history ---------------------------------------------------------------------------------


def test_a_tracking_names_hour_the_acr_test_does_not_flag_still_cannot_set_the_ceiling(conn, lg):
    """One connection of 1.2 MB net to a name the profile files under tracking: too few connections for
    the ACR test's hourly form, so only the tracking rule keeps it out of the clean history."""
    since = midnight("2026-10-12")
    clean_history(conn, since, largest=300_000)
    tracker = "browser-intake-datadoghq.com"
    synth.insert(conn, [upload(since + 86400 + 72_000, 1_200_000, 35_500, tracker, "198.51.100.88")])
    assert queries.acr_uploader(conn, since, midnight("2026-10-26"), lg) == []
    state = budget.fix(conn, lg, NOW, 365)
    assert (state["largest"], state["ceiling"], state["acr_days"]) == (300_000, 600_000, 0)


def test_the_ceiling_waits_for_fourteen_covered_days(conn, lg):
    since = midnight("2026-10-12")
    clean_history(conn, since, largest=300_000, days=13)  # the fourteenth day has no flow at all
    state = budget.fix(conn, lg, NOW, 365)
    assert (state["state"], state["why"], state["uncovered"]) == (budget.PENDING, "coverage", 1)
    synth.insert(conn, [upload(midnight("2026-10-26") + 3600, 2_000_000, 38_000)])
    assert lines(report(conn, lg))[2] == (
        "  the floor: 1 of the 14 days before the last hourly run have no flows, or under 90% of their TCP 443"
        " connections named, so the ceiling waits for 14 covered days"
    )


def test_a_day_the_capture_left_unnamed_is_not_covered(conn, lg):
    """Twenty TCP 443 connections no hello named beside one that was: the capture missed that day, and its
    unnamed streaming, counted under a /24, could otherwise lift the ceiling for good."""
    since = midnight("2026-10-12")
    clean_history(conn, since, largest=300_000)
    synth.insert(
        conn,
        [upload(since + 3 * 86400 + 43_200 + i, 5_000, 38_300 + i, None, "203.0.113.90") for i in range(20)],
    )
    assert budget.uncovered(conn, since, midnight("2026-10-26")) == [midnight("2026-10-15")]
    assert budget.fix(conn, lg, NOW, 365)["why"] == "coverage"


def test_an_empty_window_is_no_finding(conn, lg):
    record_starts(conn, midnight("2026-10-01"))
    state = budget.fix(conn, lg, NOW, 365)
    assert (state["state"], state["why"], state["uncovered"]) == (budget.PENDING, "coverage", 14)


# ---- late connections ----------------------------------------------------------------------------------


def test_a_connection_still_open_when_its_day_was_briefed_counts_late_on_the_day_it_ends(conn, lg):
    """10-25's daily file is written at 03:00 on 10-26. A connection of 10-25 that ended after it is in no
    daily file of 10-25, so 10-26's brief lists its hour under late; one that ended before it was in 10-25's
    file and is not late. A connection opened days before is found the same way, by its end."""
    d23, d25, d26 = midnight("2026-10-23"), midnight("2026-10-25"), midnight("2026-10-26")
    flows = [
        dataclasses.replace(upload(d25 + 22 * 3600, 2_000_000, 37_100), t_end=d26 + 5 * 3600),
        dataclasses.replace(
            upload(d25 + 23 * 3600, 2_000_000, 37_101, "x.example.org", "198.51.100.42"), t_end=d26 + 2 * 3600
        ),
        dataclasses.replace(
            upload(d23 + 20 * 3600, 1_000_000, 37_102, "y.example.com", "198.51.100.43"), t_end=d26 + 8 * 3600
        ),
    ]
    synth.insert(conn, flows)
    sec = report(conn, lg)
    assert sec["events"] == []
    assert [(e["key"], e["hour"], e["net_up"], e["late_net"]) for e in sec["late"]] == [
        ("example.net", d25 + 22 * 3600, 2_000_000, 2_000_000),
        ("example.com", d23 + 20 * 3600, 1_000_000, 1_000_000),
    ]
    got = lines(sec)
    assert got[3] == "  would have capped: none"
    assert got[4].startswith(
        "  late: hours of earlier days whose connections ended only after that day's brief"
    )
    assert got[5].split()[-1] == "late" and got[6].split()[:3] == ["example.net", "10-25", "22:00"]
    assert report(conn, lg, "2026-10-27")["late"] == []  # late once, on the day it ended


# ---- the row's rule, profile and TV, and the stored ceiling --------------------------------------------


def test_a_row_of_an_earlier_rule_is_not_honoured_and_is_set_again(conn, lg):
    """The first build's row (gross bound, ten times, no rule recorded) would be honoured forever: it
    is pending in the brief, and the next ingest sets the ceiling again under this rule."""
    clean_history(conn, midnight("2026-10-12"), largest=300_000)
    old = {"state": "fixed", "ceiling": 3_000_000, "largest": 300_000, "since": 1.0, "until": 2.0, "days": 14}
    db.set_meta(conn, budget.META_KEY, json.dumps(old))
    sec = report(conn, lg)
    assert (sec["source"], sec["ceiling"], sec["pending"]["why"]) == (
        budget.FLOOR,
        budget.BUDGET_FLOOR,
        "rule",
    )
    state = budget.fix(conn, lg, NOW, 365)
    assert (state["state"], state["ceiling"], state["rule"], state["measure"]) == (
        budget.FIXED,
        600_000,
        2,
        "net",
    )


def test_a_stored_ceiling_is_never_honoured_above_the_cap(conn, lg):
    state = fixed(conn, lg, largest=300_000)
    db.set_meta(conn, budget.META_KEY, json.dumps({**state, "ceiling": 9_000_000}))
    assert report(conn, lg)["ceiling"] == budget.BUDGET_CAP


def test_a_new_profile_waits_for_its_own_fourteen_days(conn, lg):
    fixed(conn, lg, largest=300_000)
    other = dataclasses.replace(lg, name="samsung-tizen")
    sec = budget.report(conn, *queries.day_bounds("2026-10-26"), other)
    assert (sec["source"], sec["pending"]["why"]) == (budget.FLOOR, "profile")
    pending = budget.fix(conn, other, NOW, 365)
    assert pending == {
        "state": budget.PENDING,
        "due": midnight("2026-11-10") + budget.SETTLE,
        "since": midnight("2026-10-27"),
        "why": "profile",
        "after": NOW,
        **IDENT,
        "profile": "samsung-tizen",
    }
    assert budget.fix(conn, other, NOW + 3600, 365) == pending  # still waiting, from the same change


def test_a_new_tv_waits_for_its_own_fourteen_days(conn, lg):
    conn.execute(
        "INSERT INTO tvsettings(t, key, value) VALUES (?, 'model', 'OLED55CXPUA')", (midnight("2026-10-01"),)
    )
    assert fixed(conn, lg, largest=300_000)["tv"] == "OLED55CXPUA"
    conn.execute("INSERT INTO tvsettings(t, key, value) VALUES (?, 'model', 'QN65S95F')", (NOW - 60,))
    pending = budget.fix(conn, lg, NOW, 365)
    assert (pending["state"], pending["why"], pending["tv"], pending["after"]) == (
        budget.PENDING,
        "tv",
        "QN65S95F",
        NOW,
    )


@pytest.mark.parametrize(
    "row",
    [
        {"state": "fixed"},
        {"state": "fixed", "ceiling": "big", "largest": 1, "since": 1, "until": 2, "days": 14},
        {"state": "fixed", "ceiling": True, "largest": 1, "since": 1, "until": 2, "days": 14},
        {"state": "other"},
        [1, 2],
        "fixed",
    ],
)
def test_a_row_that_does_not_hold_is_no_ceiling(conn, lg, row):
    db.set_meta(conn, budget.META_KEY, json.dumps(row))
    assert budget.load(conn) is None and report(conn, lg)["source"] == budget.FLOOR


def test_a_section_that_cannot_be_shown_costs_the_brief_nothing_else(conn, lg):
    o = queries.brief(conn, "2026-10-26", lg, now=NOW)
    o["upload_budget"] = {"source": budget.FIXED, "ceiling": 1, "events": [], "fixed": {}}
    out = io.StringIO()
    cli.render_brief(o, out)
    assert (
        "Upload budget: could not be shown (KeyError" in out.getvalue()
        and "GFTS URL filter" in out.getvalue()
    )


# ---- deriving it again, and the command line -----------------------------------------------------------


def test_the_owner_can_derive_it_again_from_the_latest_fourteen_days_and_the_record_stays(conn, lg):
    first = fixed(conn, lg, largest=300_000)
    later = NOW + 20 * 86400  # 2026-11-15 10:00: its window is 2026-11-01 to 2026-11-14
    clean_history(conn, midnight("2026-11-01"), largest=500_000)
    rows = conn.execute("SELECT COUNT(*) FROM flows").fetchone()[0]
    assert budget.fix(conn, lg, later, 365) == first  # the hourly ingest never computes it again
    again = budget.rederive(conn, lg, later, 365)
    assert (again["state"], again["ceiling"], again["previous"]) == (
        budget.FIXED,
        1_000_000,
        first["ceiling"],
    )
    assert (again["since"], again["set_t"]) == (midnight("2026-11-01"), later)
    assert conn.execute("SELECT COUNT(*) FROM flows").fetchone()[0] == rows


def conf_for(tmp_path, extra: str = "") -> str:
    conf = tmp_path / "tvgw.conf"
    conf.write_text(f'DB_PATH="{tmp_path / "budget.db"}"\nSTATE_DIR="{tmp_path}"\n{extra}', encoding="utf-8")
    return str(conf)


def test_tvgw_budget_says_how_the_ceiling_was_set_and_rederive_needs_root(
    conn, lg, tmp_path, capsys, monkeypatch
):
    import os

    fixed(conn, lg, largest=681_064)
    assert cli.main(["--conf", conf_for(tmp_path), "budget"]) == 0
    out = capsys.readouterr().out.splitlines()
    assert out[0] == "upload budget: ceiling 1.3M net per destination-hour (fixed)"
    assert out[1] == SET + "2 x 665.1K, the largest clean destination-hour (example.net, 10-17 14:00)"
    monkeypatch.setattr(os, "geteuid", lambda: 1000)
    assert cli.main(["--conf", conf_for(tmp_path), "budget", "--rederive"]) == 2
    assert "run it with sudo: sudo tvgw budget --rederive" in capsys.readouterr().out
    monkeypatch.setattr(os, "geteuid", lambda: 0)
    assert cli.main(["--conf", conf_for(tmp_path), "budget", "--rederive", "--json"]) == 0
    got = json.loads(capsys.readouterr().out)
    assert (got["row"]["ceiling"], got["row"]["previous"], got["source"]) == (1_362_128, 1_362_128, "fixed")


def test_upload_ceiling_reaches_the_brief_and_the_report_through_the_command_line(conn, lg, tmp_path, capsys):
    fixed(conn, lg, largest=681_064)
    for argv in (["brief", "2026-10-26", "--json"], ["report", "--day", "2026-10-26", "--json"]):
        assert cli.main(["--conf", conf_for(tmp_path, "UPLOAD_CEILING=4M\n"), *argv]) == 0
        sec = json.loads(capsys.readouterr().out)["upload_budget"]
        assert (sec["source"], sec["ceiling"]) == ("owner", 4 * 1024**2)


def test_tvgw_host_answers_for_what_the_budget_names(conn, lg, tmp_path, capsys):
    """The budget names a registrable domain, or a /24 for unnamed connections: `tvgw host` lists the
    names under the first and the addresses in the second, and still says `not seen` for neither."""
    synth.insert(conn, [upload(NOW - 3600, 900_000, 38_201, None, "203.0.113.77")])
    conn.executemany(
        "INSERT INTO hosts(name, first_seen, last_seen, category, dns_n, tls_n, http_n, last_blocked)"
        " VALUES (?, ?, ?, 'Other', 1, 1, 0, 0)",
        [("a.collector.example.net", NOW - 7200, NOW - 7200), ("b.example.net", NOW - 7000, NOW - 7000)],
    )
    conn.commit()
    assert cli.main(["--conf", conf_for(tmp_path), "host", "example.net"]) == 0
    out = capsys.readouterr().out.splitlines()
    assert out[0] == "example.net: not one name; the names under it:"
    assert [ln.split()[0] for ln in out[2:]] == ["a.collector.example.net", "b.example.net"]
    assert cli.main(["--conf", conf_for(tmp_path), "host", "203.0.113.0/24"]) == 0
    out = capsys.readouterr().out.splitlines()
    assert out[0] == "203.0.113.0/24: the addresses in it the TV connected to" and out[2].split()[:2] == [
        "203.0.113.77",
        "1",
    ]
    assert cli.main(["--conf", conf_for(tmp_path), "host", "nothing.example"]) == 1
    assert capsys.readouterr().out == "not seen\n"


def test_the_hour_the_clocks_go_back_is_marked_with_its_zone():
    first, second = midnight("2026-11-01") + 3600, midnight("2026-11-01") + 7200
    assert (cli.hour_label(first), cli.hour_label(second)) == ("11-01 01:00 CDT", "11-01 01:00 CST")
    assert cli.hour_label(midnight("2026-11-01") + 4 * 3600) == "11-01 03:00"


# ---- a line that comes every day ----------------------------------------------------------------------


def test_days_running_and_a_new_destination(conn, lg):
    for i, day in enumerate(("2026-10-24", "2026-10-25", "2026-10-26", "2026-10-27")):
        synth.insert(conn, [upload(midnight(day) + 14 * 3600, 1_000_000, 38_400 + i)])
    r26 = report(conn, lg, "2026-10-26")
    assert (r26["days_running"], r26["new_keys"]) == (3, False)
    r27 = report(conn, lg, "2026-10-27")
    assert (r27["days_running"], r27["new_keys"]) == (4, False)
    synth.insert(
        conn,
        [upload(midnight("2026-10-27") + 15 * 3600, 1_000_000, 38_410, "n.example.org", "198.51.100.44")],
    )
    assert report(conn, lg, "2026-10-27")["new_keys"] is True
    assert report(conn, lg, "2026-10-24")["days_running"] == 1
    assert "days_running" not in budget.report(conn, NOW - 86400, NOW, lg)  # not a calendar day
