"""(budget) The upload budget (design decision 66): what counts, the positive control shaped like IMC 2024's
LG measurement, the shapes that must stay silent, the ceiling set once from the clean history and never
again, the first days of a new install, the owner's setting, and the brief's lines, engineering and plain.
Fixtures come from published summary numbers only (acr_synth), never from a trace."""

import dataclasses
import io
import json
import random
import sqlite3

import acr_synth as synth
import pytest
from conftest import NOW, fake_extract, fake_oddport

from tvgw import analyst, budget, cli, config, db, forget, ingest, plain, queries

SEEDS = range(1, 9)
TELEMETRY = "collector.example.net"  # a name no category covers: Other, outside the expected categories
TELEMETRY_SERVER = "198.51.100.40"


@pytest.fixture()
def conn(tmp_path):
    c = db.connect(str(tmp_path / "budget.db"))
    yield c
    c.close()


def midnight(day: str) -> float:
    """A local midnight, computed under the test time zone (not at import time)."""
    return queries.day_bounds(day)[0]


def upload(t: float, payload: int, sport: int, name: str | None = TELEMETRY, dst: str = TELEMETRY_SERVER):
    """One connection that sends `payload` bytes of content and gets 2 KB back, as conntrack counts it."""
    return synth.connection(t, 20.0, dst, 443, sport, [payload], [2_000], name)


def record_starts(conn, t: float) -> None:
    """The store's first ingest run, which says how far back its record reaches."""
    conn.execute("INSERT INTO ingest_runs(t, seconds) VALUES (?, 1)", (t,))
    conn.commit()


def clean_history(conn, since: float, largest: int, days: int = budget.BUDGET_DAYS) -> None:
    """Two weeks of a modest telemetry upload at 14:00 every day, 60 KB, and one day of `largest`."""
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
def test_an_hour_shaped_like_the_published_lg_measurement_would_have_been_capped(conn, lg, seed, named):
    """The positive control: against the floor on a new install, and against a ceiling set from a clean
    history, one hour of LG's fingerprinting is a would-have-capped event, by its domain when the hellos
    were captured and by its /24 when none was."""
    hour = midnight("2026-10-26") + 20 * 3600
    synth.insert(conn, synth.imc_fingerprint_hour(random.Random(seed), hour, named=named))
    key = "alphonso.tv" if named else "203.0.113.0/24"
    (e,) = report(conn, lg)["events"]
    assert (e["key"], e["hour"], e["ports"], e["named"], e["conns"]) == (key, hour, [4431], named, 60)
    assert e["payload_up"] > budget.ACR_HOUR_PAYLOAD  # the computed quietest hour is below this one
    fixed(conn, lg, largest=300_000)  # a ceiling of 10 x 300 KB, three times the floor
    (e,) = report(conn, lg)["events"]
    assert e["key"] == key and report(conn, lg)["source"] == budget.FIXED
    assert json.loads(json.dumps(report(conn, lg)))["events"] == [e]  # the brief's --json carries it as is


def test_the_ceiling_constants_are_the_ones_the_decision_derives():
    """The floor is about four times the busiest IMC hour without fingerprinting (265 KB of frames) and
    under a third of the quietest fingerprinting hour's payload; that payload is 4,125 KB at 7 times up
    to down, less 66 bytes of headers in every 1,514."""
    assert budget.BUDGET_FLOOR == 1024**2 and budget.BUDGET_TIMES == 10 and budget.BUDGET_DAYS == 14
    assert 3.5 < budget.BUDGET_FLOOR / 265_000 < 4.5
    assert round(4_125_000 * 7 / 8 * 1448 / 1514, -4) == budget.ACR_HOUR_PAYLOAD
    assert budget.BUDGET_FLOOR * 3 < budget.ACR_HOUR_PAYLOAD


# ---- what must stay silent -----------------------------------------------------------------------------


@pytest.mark.parametrize("seed", SEEDS)
def test_a_long_streams_acknowledgements_to_a_streaming_host_are_not_upload(conn, lg, seed):
    """YouTube's best lab day: 11.8 MB up on its API at 3 times the bytes down, and 2 GB of video whose
    side from the TV is acknowledgements. Both are Streaming, an expected category."""
    synth.insert(conn, synth.streaming_day(random.Random(seed), midnight("2026-10-26") + 8 * 3600))
    assert report(conn, lg)["events"] == []


def test_a_large_download_from_an_unclassified_host_with_a_small_upload_is_not_upload(conn, lg):
    """A 400 MB download whose TV side is all acknowledgements: conntrack counts megabytes up, the payload
    bound counts nothing, so the destination-hour is not an event, named or not."""
    (dl,) = synth.firmware_download(midnight("2026-10-26") + 3 * 3600)
    assert dl.bytes_up > 10 * budget.BUDGET_FLOOR and dl.payload_up == 0  # raw bytes would be an event
    named = dataclasses.replace(dl, sport=56_001, dst="198.51.100.91", sni="cdn.example.org")
    synth.insert(conn, [dl, named])
    sec = report(conn, lg)
    assert sec["events"] == []
    cells = budget.destination_hours(conn, *queries.day_bounds("2026-10-26"), lg)
    assert {c["key"]: c["payload_up"] for c in cells.values()} == {"203.0.113.0/24": 0, "example.org": 0}


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


# ---- what counts, and in which hour --------------------------------------------------------------------


def test_a_destination_hour_is_its_registrable_domain_and_the_clock_hour_its_flows_opened_in(conn, lg):
    """Two names under one domain are one destination; a flow at 13:59:59 and one at 14:00:00 fall in two
    hours; a flow that opens at the window's end belongs to the next window."""
    a, b = queries.day_bounds("2026-10-26")
    h = a + 14 * 3600
    synth.insert(
        conn,
        [
            upload(h - 1, 700_000, 32_001, "a.example.net"),
            upload(h, 600_000, 32_002, "a.example.net"),
            upload(h + 60, 500_000, 32_003, "b.example.net"),
            upload(b, 9_000_000, 32_004, "a.example.net"),
        ],
    )
    cells = budget.destination_hours(conn, a, b, lg)
    assert {(k, hr - a): c["payload_up"] for (k, hr), c in cells.items()} == {
        ("example.net", 13 * 3600): 700_000,
        ("example.net", 14 * 3600): 1_100_000,
    }
    (e,) = report(conn, lg)["events"]  # 1.1 MB > 1 MiB; 700 KB is under it
    assert (e["key"], e["hour"] - a, e["payload_up"], e["conns"]) == ("example.net", 14 * 3600, 1_100_000, 2)


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
    assert (e["key"], e["payload_up"], e["named"]) == ("203.0.113.0/24", 2_000_000, False)


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


# ---- the ceiling: set once, from the clean history -----------------------------------------------------


def test_the_ceiling_is_ten_times_the_largest_clean_destination_hour(conn, lg):
    state = fixed(conn, lg, largest=300_000)
    assert state["ceiling"] == 3_000_000 and state["largest"] == 300_000
    assert (state["key"], state["hour"]) == ("example.net", midnight("2026-10-17") + 14 * 3600)
    assert (state["since"], state["until"]) == (midnight("2026-10-12"), midnight("2026-10-26"))
    assert state["set_t"] == NOW and state["days"] == 14 and state["acr_days"] == 0


def test_the_floor_holds_when_ten_times_the_largest_clean_hour_is_less(conn, lg):
    state = fixed(conn, lg, largest=90_000)
    assert state["ceiling"] == budget.BUDGET_FLOOR and state["largest"] == 90_000


def test_a_history_with_no_upload_outside_the_expected_categories_gets_the_floor(conn, lg):
    since = midnight("2026-10-12")
    synth.insert(conn, [upload(since + 3600, 900_000, 34_000, "www.youtube.com")])  # Streaming
    record_starts(conn, since - 3600)
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
    clean_history(conn, since, largest=120_000)
    synth.insert(conn, synth.telemetry_burst(random.Random(1), since + 3 * 86400 + 9 * 3600))
    state = budget.fix(conn, lg, NOW, 365)
    assert state["acr_days"] == 1 and state["largest"] == 120_000 and state["ceiling"] == 1_200_000


def test_a_tracking_name_never_sets_the_ceiling_but_is_counted_against_it(conn, lg):
    """A name the profile files under tracking (here, third-party ads), reached anyway, is no clean
    history; over the ceiling it is an event like any other."""
    since = midnight("2026-10-12")
    clean_history(conn, since, largest=100_000)
    tracker = "browser-intake-datadoghq.com"
    synth.insert(conn, [upload(since + 86400, 800_000, 35_000, tracker, "198.51.100.88")])
    state = budget.fix(conn, lg, NOW, 365)
    assert state["largest"] == 100_000 and state["ceiling"] == budget.BUDGET_FLOOR
    synth.insert(conn, [upload(midnight("2026-10-26") + 3600, 2_000_000, 35_001, tracker, "198.51.100.88")])
    assert [e["key"] for e in report(conn, lg)["events"]] == [tracker]


def test_the_ceiling_is_never_computed_again(conn, lg):
    """Fixed is fixed: a bigger upload inside the old window, a later run, the record growing; none of it
    moves the ceiling. Only the owner's setting or a forget changes it."""
    first = fixed(conn, lg, largest=300_000)
    synth.insert(conn, [upload(midnight("2026-10-20") + 3600, 5_000_000, 36_000)])
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
    state = budget.fix(conn, lg, midnight("2026-11-08") + 12 * 3600, 365)
    assert (state["since"], state["until"]) == (since, midnight("2026-11-08"))
    assert state["until"] - state["since"] == 14 * 86400 + 3600


def test_the_last_day_settles_before_the_ceiling_is_set(conn, lg):
    """Before 03:00 the day just ended still lacks its idle connections, so the window ends a day earlier."""
    record_starts(conn, midnight("2026-10-01"))
    state = budget.fix(conn, lg, midnight("2026-10-26") + 2 * 3600, 365)
    assert state["until"] == midnight("2026-10-25")


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
    assert budget.fix(conn, lg, midnight("2026-11-10") + 4 * 3600, 365)["state"] == budget.FIXED


def test_the_first_run_of_a_store_has_no_record_yet(conn, lg):
    assert budget.fix(conn, lg, NOW, 365) == {"state": budget.PENDING, "due": None}


def test_a_store_that_keeps_too_few_days_keeps_the_floor(conn, lg):
    record_starts(conn, midnight("2026-09-01"))
    assert budget.fix(conn, lg, NOW, 14) == {"state": budget.PENDING, "due": None, "why": "db_days"}
    assert report(conn, lg)["ceiling"] == budget.BUDGET_FLOOR


def test_a_meta_row_that_does_not_read_is_no_ceiling(conn, lg):
    db.set_meta(conn, budget.META_KEY, "{not json")
    assert budget.load(conn) is None and report(conn, lg)["source"] == budget.FLOOR


# ---- the owner's setting --------------------------------------------------------------------------------


def test_the_owners_ceiling_wins(conn, lg):
    fixed(conn, lg, largest=300_000)
    synth.insert(conn, [upload(midnight("2026-10-26") + 3600, 3_500_000, 37_000)])
    assert [e["payload_up"] for e in report(conn, lg)["events"]] == [3_500_000]
    sec = report(conn, lg, setting="4M")
    assert (sec["ceiling"], sec["source"], sec["events"]) == (4 * 1024**2, budget.OWNER, [])
    assert sec["fixed"]["ceiling"] == 3_000_000


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
    "Upload budget (count-only; nothing is capped): ceiling {} payload<= per destination-hour outside the"
    " expected categories"
)


def test_a_fixed_ceiling_prints_every_day_with_how_it_was_set(conn, lg):
    fixed(conn, lg, largest=300_000)
    assert lines(report(conn, lg)) == [
        "",
        HEAD.format("2.9M"),
        "  set 10-26 10:00 from the 14 days 10-12 .. 10-25: 10 x 293.0K, the largest clean destination-hour"
        " (example.net, 10-17 14:00)",
        "  would have capped: none",
    ]


def test_the_floor_and_an_event_print_with_the_table(conn, lg):
    fixed(conn, lg, largest=90_000)
    hour = midnight("2026-10-26") + 20 * 3600
    synth.insert(conn, synth.imc_fingerprint_hour(random.Random(1), hour, named=False))
    got = lines(report(conn, lg))
    assert got[1:3] == [
        HEAD.format("1.0M"),
        "  set 10-26 10:00 from the 14 days 10-12 .. 10-25: the floor, since 10 x 87.9K, the largest clean"
        " destination-hour (example.net, 10-17 14:00), is less",
    ]
    assert got[3] == "  would have capped:"
    assert got[4].split() == ["destination", "hour", "payload<=", "conns", "ports"]
    assert got[5].split()[:4] == ["203.0.113.0/24", "(no", "TLS", "name)"]
    assert got[5].split()[4:7] == ["10-26", "20:00", cli.hb(report(conn, lg)["events"][0]["payload_up"])]
    assert got[5].split()[7:] == ["60", "4431"]


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


@pytest.mark.parametrize(
    ("sec", "how"),
    [
        (
            {"source": budget.OWNER, "ceiling": 4 * 1024**2, "fixed": {"ceiling": 3_000_000}, "events": []},
            "  set by the owner (UPLOAD_CEILING); the gateway's own is 2.9M",
        ),
        ({"source": budget.OWNER, "ceiling": 512 * 1024, "fixed": None, "events": []}, "  set by the owner (UPLOAD_CEILING)"),
        (
            {"source": budget.FLOOR, "ceiling": budget.BUDGET_FLOOR, "fixed": None, "pending": {"state": "pending", "due": None, "why": "db_days"}, "events": [{"key": "x.example", "hour": 0, "payload_up": 2 * 1024**2, "conns": 1, "ports": [443], "named": True}]},
            "  the floor: the store keeps too few days (DB_DAYS) to hold 14 days of history",
        ),
        (
            {"source": budget.FLOOR, "ceiling": budget.BUDGET_FLOOR, "fixed": None, "pending": None, "events": [{"key": "x.example", "hour": 0, "payload_up": 2 * 1024**2, "conns": 1, "ports": [443], "named": True}]},
            "  the floor, until the hourly ingest has a record to set the ceiling from",
        ),
    ],
)  # fmt: skip
def test_how_the_ceiling_was_set_in_each_case(sec, how):
    assert lines(sec)[2] == how


def test_a_pending_ceiling_says_when_and_a_high_one_says_what_it_cannot_catch(conn, lg):
    record_starts(conn, NOW)
    budget.fix(conn, lg, NOW + 3600, 365)
    synth.insert(conn, [upload(midnight("2026-10-26") + 3600, 2_000_000, 38_000)])
    got = lines(report(conn, lg))
    assert (
        got[2]
        == "  the floor, until the hourly ingest sets the ceiling from 14 whole days of the record, after 11-10 03:00"
    )
    assert lines(report(conn, lg, setting="4M"))[3] == (
        "  at or above 3.3M, an hour of LG's screen recognition as IMC 2024 measured it: an hour like that would"
        " not count"
    )


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
    assert budget.load(c) == {"state": budget.PENDING, "due": None}
    c.close()
    run_ingest(gateway, lg)
    c = db.connect(gateway.db_path, readonly=True)
    assert budget.load(c) == {
        "state": budget.PENDING,
        "due": midnight("2026-11-10") + budget.SETTLE,
        "since": midnight("2026-10-27"),
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


def plain_day(events: list[dict], ceiling: int = budget.BUDGET_FLOOR) -> dict:
    from test_plain import measured_day

    return {**measured_day(), "upload_budget": {"ceiling": ceiling, "source": budget.FIXED, "events": events}}


def event(key: str, payload: int, hour: float = 0.0) -> dict:
    return {"key": key, "hour": hour, "payload_up": payload, "conns": 9, "ports": [443], "named": True}


def test_no_event_no_plain_line(lg):
    assert not any("Uploads:" in x for x in plain.plain_brief(plain_day([]), profile=lg))


def test_one_event_is_one_plain_line_after_the_action(lg):
    got = plain.plain_brief(plain_day([event("example.net", 4_613_734)]), profile=lg)
    assert got[-2] == (
        "  Uploads: The TV sent example.net 4.4 MB in one hour, over the 1.0 MB upload budget for services"
        " outside its everyday ones. Nothing was stopped."
    )
    assert got[5].startswith("  Action: nothing needs your attention.")


def test_several_events_name_the_destinations_once_each(lg):
    evs = [event("a.example", 3 * 1024**2, h) for h in (0.0, 3600.0)] + [
        event(k, 2 * 1024**2) for k in ("b.example", "c.example", "d.example")
    ]
    got = plain.plain_brief(plain_day(evs, ceiling=1024**2), profile=lg)
    assert got[-2] == (
        "  Uploads: In 5 hours the TV sent more than the 1.0 MB upload budget for services outside its everyday"
        " ones (a.example, b.example, c.example and 1 more). Nothing was stopped."
    )


def test_the_plain_line_is_never_the_action(lg):
    o = plain_day([event("example.net", 4_613_734)])
    assert plain.action(o, lg) is None
