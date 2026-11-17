"""(coverage) Design decision 100: each source's gaps over a window, from what the store already keeps, and no
sentence that claims an absence across one. The synthetic evening is 2026-10-26 (America/Chicago): the ingest
runs hourly at :20, the live reading beats every ten minutes, the sampler every ten."""

import ast
import io
import json
import os
import re
import time

import pytest
from appfront_store import GW, HOUR, YT, Store, evening, watched
from conftest import NOW as GATEWAY_NOW
from conftest import fake_extract, fake_oddport

from tvgw import cli, companies, coverage, db, drafts, ingest, plain, queries, receipt, refused, tvlive
from tvgw.coverage import Gap

DAY_A, DAY_B = evening(0, 0), evening(1, 0)  # the evening's day, midnight to midnight
NOW = evening(1, 12)  # long after: every stretch of the day has settled
TRACKER = "stats.g.doubleclick.net"
LOSS = (  # the ingest's words when it found lines of a log lost: the query log's, then conntrack's
    "adguard: log rotated or truncated since the last run and the lines written before it could not be"
    " recovered",
    "flows: conntrack lost events 2 time(s) since the last run (ENOBUFS, first at 2026-10-26 19:10):"
    " connections that ended then are not in the store",
)


def at(hour: float) -> float:
    return evening(0, hour)


def run_at(hour: int) -> float:
    """The ingest's run of an hour of the evening's day, at twenty past: exact, so runs can be named by it."""
    return evening(0, hour) + 1200


def every(start: float, end: float, step: float) -> list[float]:
    return [start + i * step for i in range(int((end - start) // step) + 1)]


LAST_BEAT = every(at(18.1), at(19.2), 600)[-1]  # 19:06


@pytest.fixture()
def conn(tmp_path):
    c = db.connect(str(tmp_path / "c.db"))
    yield c
    c.close()


def runs(conn, times, *warnings: str) -> None:
    conn.executemany(
        "INSERT OR REPLACE INTO ingest_runs(t, seconds, warnings) VALUES (?, 1, ?)",
        [(t, json.dumps(list(warnings))) for t in times],
    )
    conn.commit()


def hourly(skip: tuple[float, float] = (0, 0)) -> list[float]:
    """The ingest's runs at :20 from the noon before to the noon after, but those inside `skip` (hours)."""
    return [run_at(h) for h in range(-12, 37) if not at(skip[0]) <= run_at(h) < at(skip[1])]


def on_all_day(conn) -> None:
    """An hourly reading at ten past saying the TV is on, from midnight to the noon after."""
    rows = [(t, YT) for t in every(at(0.17), at(35.17), HOUR)]  # to the noon after
    conn.executemany("INSERT INTO tvstate(t, power, app) VALUES (?, 'Active', ?)", rows)
    conn.commit()


def beats(conn, start: float, end: float) -> None:
    rows = [(t,) for t in every(start, end, 600)]
    conn.executemany("INSERT INTO tv_events(t, kind, value) VALUES (?, 'alive', '')", rows)
    conn.commit()


def samples(conn, *rows: tuple[float, int]) -> None:
    conn.executemany(
        "INSERT INTO gw_samples(t, boot_id, tv_rx_bytes, tv_tx_bytes) VALUES (?, 'b', 0, ?)", rows
    )
    conn.commit()


def stream(conn, skip: tuple[float, float] = (0, 0), named: bool = False) -> int:
    """The TV's port carries 111 MB to the TV in each ten minutes from 20:00 to 23:00, and the flow record
    holds a connection with 99% of it in each but those of the hours in `skip`, named by a hello when `named`.
    Returns the port's bytes."""
    step = 111_000_000
    times = every(at(20), at(23), 600)
    samples(conn, *[(t, i * step) for i, t in enumerate(times)])
    for i, t in enumerate(times[1:], 1):
        if not at(skip[0]) <= t - 300 < at(skip[1]):
            conn.execute(
                "INSERT INTO flows(t_start, t_end, proto, dst, dport, sport, bytes_up, bytes_down, pkts_up,"
                " pkts_down) VALUES (?, ?, 'tcp', '198.51.100.7', 443, ?, 1000, ?, 10, 10)",
                (t - 300, t - 240, 40000 + i, int(step * 0.99)),
            )
            if named:
                conn.execute(
                    "INSERT INTO tls(t, dst, dport, sport, sni)"
                    " VALUES (?, '198.51.100.7', 443, ?, 'cdn.example')",
                    (t - 300, 40000 + i),
                )
    conn.commit()
    return (len(times) - 1) * step


def spans(found) -> list[tuple[float, float, str]]:
    return [(g.a, g.b, g.why) for g in found]


# ---- the logs the ingest reads -----------------------------------------------------------------------------
@pytest.mark.parametrize("source", ["dns", "flows"])
@pytest.mark.parametrize(
    ("missed", "late", "gap"),
    [
        (0, 0, False),  # read every hour
        (1, 0, False),  # one run missed: the next reads on from the cursor
        (1, 1800, False),  # and that one half an hour late: as long as the ingest allows
        (1, 1801, True),  # a second later
        (2, 0, True),  # two missed
    ],
    ids=["on time", "one run missed", "the next one late", "a second later", "two runs missed"],
)
def test_a_log_no_run_read_for_longer_than_the_ingest_allows_is_not_known_from_run_to_run(
    conn, source, missed, late, gap
):
    back = run_at(18 + missed) + late  # the run that reads the log again after the one at 17:20
    runs(conn, [t for t in hourly() if t <= run_at(17) or t > back + 1800] + [back])
    found = spans(coverage.covered(conn, source, DAY_A, DAY_B, NOW))
    assert found == ([(run_at(17), back, coverage.WHY_UNREAD)] if gap else [])


@pytest.mark.parametrize(
    ("warning", "dns", "flows"),
    [
        (LOSS[0], coverage.WHY_LOST, None),
        (LOSS[1], None, coverage.WHY_LOST),
        (
            "flows: log rotated or truncated since the last run and the lines written before it",
            None,
            coverage.WHY_LOST,
        ),
        (
            "flows: the flow logger's event socket dropped 8 event(s) since the last run",
            None,
            coverage.WHY_LOST,
        ),
        ("dns: 3 malformed query-log record(s) skipped", None, None),  # a line lost, not a stretch
        ("dns: OSError: [Errno 5] Input/output error", coverage.WHY_UNREAD, None),  # failed: nothing read
        ("flows: /var/log/tvgw/flows.log is missing", None, coverage.WHY_UNREAD),
    ],
    ids=[
        "query log lost",
        "conntrack lost",
        "flow log lost",
        "socket dropped",
        "malformed",
        "dns failed",
        "no flow log",
    ],
)
def test_three_runs_that_found_lines_lost_or_read_nothing_leave_their_stretch_not_known(
    conn, warning, dns, flows
):
    runs(conn, hourly())
    runs(conn, [run_at(h) for h in (18, 19, 20)], warning)
    for source, why in (("dns", dns), ("flows", flows)):
        end = run_at(21) if why == coverage.WHY_UNREAD else run_at(20)  # a failed run is not a read
        found = spans(coverage.covered(conn, source, DAY_A, DAY_B, NOW))
        assert found == ([(run_at(17), end, why)] if why else []), source


@pytest.mark.parametrize("late", [0, 1], ids=["within the ingest's schedule", "behind it"])
def test_an_ingest_behind_now_leaves_the_stretch_since_its_last_read_not_known(conn, late):
    runs(conn, [run_at(h) for h in range(11, 16)])
    now = run_at(15) + coverage.RUN_GAP + late
    gaps = [(run_at(15), now, coverage.WHY_UNREAD)] if late else []
    assert spans(coverage.covered(conn, "dns", DAY_A, DAY_B, now)) == gaps


def test_a_log_never_read_is_not_known_up_to_now_and_the_time_before_the_first_run_is_no_gap(conn):
    assert spans(coverage.covered(conn, "dns", DAY_A, DAY_B, at(20))) == [
        (DAY_A, at(20), coverage.WHY_UNREAD)
    ]
    runs(conn, [run_at(h) for h in range(11, 36)])  # the first run read the log from its start
    assert coverage.covered(conn, "dns", DAY_A, DAY_B, NOW) == []


def test_the_ingests_own_words_for_a_lost_query_log_are_read_as_a_lost_stretch(gateway, lg, monkeypatch):
    """The words are the ingest's, not this file's: a query log replaced between two runs an hour apart."""
    clock = [GATEWAY_NOW]
    monkeypatch.setattr(time, "time", lambda: clock[0])

    def run() -> list[str]:
        kw = {"extract": fake_extract, "oddport_lines": fake_oddport, "gate_lines": lambda since: []}
        return ingest.run(gateway, lg, lock=False, **kw).warnings

    assert run() == []
    with open(gateway.adguard_querylog, "w") as fh:
        fh.write("something else entirely\n")  # no .1 to recover from
    clock[0] += HOUR
    assert any(w.startswith("adguard: log rotated") for w in run())
    conn = db.connect(gateway.db_path, readonly=True)
    a, b = GATEWAY_NOW - HOUR, clock[0] + HOUR
    assert spans(coverage.covered(conn, "dns", a, b, clock[0])) == [
        (GATEWAY_NOW, clock[0], coverage.WHY_LOST)
    ]
    assert coverage.covered(conn, "flows", a, b, clock[0]) == []


def test_an_unknown_source_is_refused(conn):
    with pytest.raises(ValueError, match="gfts"):
        coverage.covered(conn, "gfts", DAY_A, DAY_B)


# ---- the live reading --------------------------------------------------------------------------------------
def test_the_constants_kept_here_are_the_ones_their_modules_keep():
    assert (coverage.LIVE_BEAT, coverage.AWAKE) == (tvlive.ALIVE_EVERY, queries.AWAKE)


def quiet_evening(conn) -> None:
    """The TV on all day; the live reading beats from 18:06, is quiet after 19:06, and is back at 20:00."""
    on_all_day(conn)
    beats(conn, at(18.1), at(19.2))
    beats(conn, at(20), NOW)


def test_a_live_reading_quiet_for_more_than_three_heartbeats_with_the_tv_on_is_a_gap(conn):
    quiet_evening(conn)
    assert spans(coverage.covered(conn, "tvlive", DAY_A, DAY_B, NOW)) == [
        (LAST_BEAT, at(20), coverage.WHY_BEAT)
    ]
    conn.execute("DELETE FROM tv_events WHERE t >= ?", (at(20),))  # it never came back: quiet up to now
    assert spans(coverage.covered(conn, "tvlive", DAY_A, DAY_B, at(21))) == [
        (LAST_BEAT, at(21), coverage.WHY_BEAT)
    ]


@pytest.mark.parametrize(
    "explain",
    [
        "UPDATE tvstate SET power='Active Standby'",  # the readings: the TV was off
        f"INSERT INTO tv_events(t, kind, value) VALUES ({at(19.5)}, 'conn', 'down')",  # lost, and said so
        f"INSERT INTO tv_events(t, kind, value) VALUES ({LAST_BEAT + 1800}, 'alive', '')",  # three periods
        "DELETE FROM tv_events",  # never switched on: no heartbeat to miss
        "DROP TABLE tv_events",  # a store from before the live reading
    ],
    ids=["the TV was off", "a disconnect", "three periods", "never switched on", "no table"],
)
def test_a_quiet_live_reading_the_record_explains_is_no_gap(conn, explain):
    quiet_evening(conn)
    conn.execute(explain)
    conn.commit()
    assert coverage.covered(conn, "tvlive", DAY_A, DAY_B, NOW) == []


def test_only_a_heartbeat_ends_a_silence_and_only_a_disconnect_explains_one(conn):
    quiet_evening(conn)
    for kind, value in (("conn", "up"), ("power", "Active"), ("app", YT), ("conn", "lost")):
        conn.execute("INSERT INTO tv_events(t, kind, value) VALUES (?, ?, ?)", (at(19.5), kind, value))
    conn.commit()
    assert spans(coverage.covered(conn, "tvlive", DAY_A, DAY_B, NOW)) == [
        (LAST_BEAT, at(20), coverage.WHY_BEAT)
    ]


# ---- the port's own counters -------------------------------------------------------------------------------
def test_a_flow_record_that_matches_the_port_has_no_hole_and_a_share_within_three_percent(conn):
    runs(conn, hourly())
    port = stream(conn)
    got, flows, share = coverage.reconcile(conn, DAY_A, DAY_B)
    assert (got, flows) == (port, 18 * int(111_000_000 * 0.99)) and abs(share - 1) <= 0.03
    assert coverage.covered(conn, "flows", DAY_A, DAY_B, NOW) == []


def test_the_flows_of_one_hour_missing_while_the_port_streamed_are_one_hole_naming_that_hour(conn):
    runs(conn, hourly())
    stream(conn, skip=(21, 22))
    holes = coverage.covered(conn, "flows", DAY_A, DAY_B, NOW)
    assert (
        spans(holes) == [(at(21), at(22), coverage.WHY_PORT)]
        and coverage.span(holes) == "from 21:00 to 22:00"
    )
    assert coverage.reconcile(conn, DAY_A, DAY_B)[2] == pytest.approx(0.99 * 12 / 18)


@pytest.mark.parametrize(
    ("down", "hole"),
    [(10_000_000, False), (coverage.RECONCILE_FLOOR, False), (coverage.RECONCILE_FLOOR + 1, True)],
    ids=["an app's menus", "the floor", "a stream"],
)
def test_only_an_interval_that_carried_more_than_the_floor_needs_a_connection(conn, down, hole):
    runs(conn, hourly())
    samples(conn, (at(20), 0), (at(20) + 600, down))
    assert bool(coverage.covered(conn, "flows", DAY_A, DAY_B, NOW)) is hole


@pytest.mark.parametrize(
    ("start", "end", "covers"),
    [
        (at(19), at(22), True),  # began before the interval, ran through it
        (None, at(20.05), True),  # no start time: placed by its end, inside
        (at(20.15), at(21), True),  # began inside it
        (at(19), at(20), True),  # ended as it began
        (at(19), at(20) - 1, False),  # ended before it began
        (at(20) + 600, at(21), False),  # began as it ended
    ],
    ids=["through", "end only", "began inside", "ended at its start", "before", "after"],
)
def test_a_connection_covers_an_interval_when_it_began_before_its_end_and_ended_after_its_start(
    conn, start, end, covers
):
    runs(conn, hourly())
    samples(conn, (at(20), 0), (at(20) + 600, 9 * 10**8), (at(20) + 1200, 18 * 10**8))  # two busy intervals
    conn.execute(
        "INSERT INTO flows(t_start, t_end, proto, dst, dport, sport, bytes_up, bytes_down)"
        " VALUES (?, ?, 'tcp', '198.51.100.7', 443, 1, 1, 1)",
        (start, end),
    )
    holes = [g.a for g in coverage.covered(conn, "flows", DAY_A, DAY_B, NOW)]
    assert (at(20) not in holes) is covers  # the first interval, [20:00, 20:10)


def test_an_interval_across_the_windows_edge_counts_by_its_share_of_time_and_a_quiet_port_by_none(conn):
    samples(conn, (at(20), 0), (at(20) + 600, 6000))
    conn.execute(  # a connection is counted where it ended: one with no start time too
        "INSERT INTO flows(t_start, t_end, proto, dst, dport, sport, bytes_down)"
        " VALUES (NULL, ?, 'tcp', '198.51.100.7', 443, 1, 900)",
        (at(20.5),),
    )
    assert coverage.reconcile(conn, at(20) + 150, DAY_B) == (4500, 900, 0.2)
    assert coverage.reconcile(conn, at(21), DAY_B) == (0, 0, None)
    conn.execute("DROP TABLE gw_samples")  # a store from before the sampler: nothing to hold the record to
    assert coverage.reconcile(conn, DAY_A, DAY_B) == (0, 900, None)


# ---- properties --------------------------------------------------------------------------------------------
@pytest.mark.parametrize("source", coverage.SOURCES)
@pytest.mark.parametrize("cut", [at(12.5), at(17.33), at(19.5), at(21), at(23.99)])
def test_the_gaps_over_a_window_are_the_gaps_over_its_two_halves_joined(conn, source, cut):
    runs(conn, hourly((18, 21)))
    runs(conn, [run_at(22)], *LOSS)
    on_all_day(conn)
    beats(conn, at(12.1), at(14.2))
    stream(conn, skip=(21, 22))
    whole = coverage.covered(conn, source, DAY_A, DAY_B, NOW)
    halves = coverage.covered(conn, source, DAY_A, cut, NOW) + coverage.covered(conn, source, cut, DAY_B, NOW)
    assert whole and coverage.join(halves) == whole


def test_gaps_join_only_with_their_own_kind_and_their_words_merge_every_kind():
    gaps = [
        Gap("dns", 10, 50, "x"),
        Gap("dns", 20, 30, "x"),
        Gap("dns", 50, 60, "x"),
        Gap("dns", 40, 70, "y"),
    ]
    assert coverage.join(gaps) == [Gap("dns", 10, 60, "x"), Gap("dns", 40, 70, "y")]
    assert coverage.join([Gap("dns", 10, 20, "x"), Gap("flows", 20, 30, "x")]) == [
        Gap("dns", 10, 20, "x"),
        Gap("flows", 20, 30, "x"),
    ]
    assert coverage.span(gaps) == coverage.span([Gap("dns", 10, 70, "")])
    assert coverage.cut(gaps, 55, 65) == [Gap("dns", 55, 60, "x"), Gap("dns", 55, 65, "y")]
    assert coverage.cut(gaps, 70, 80) == []  # a gap that ends where the window begins is not in it


@pytest.mark.parametrize(
    ("a", "b", "words"),
    [
        (at(19 + 20 / 60), at(20 + 40 / 60), "from 19:20 to 20:40"),
        (at(19.2), DAY_B, "from 19:12 to 24:00"),  # to the end of the day, not "to 00:00" of the next
        (at(23), evening(1, 1), "from Mon 23:00 to 01:00"),  # across midnight: the start's weekday
    ],
)
def test_a_gap_in_words(a, b, words):
    assert coverage.span([Gap("dns", a, b, "")]) == words
    assert plain.absent("No lookup was refused.", [Gap("dns", a, b, "")]) == f"not known {words}"


def test_absent_is_the_sentence_where_the_record_has_no_gap():
    assert plain.absent("No lookup was refused.", []) == "No lookup was refused."


# ---- the brief ---------------------------------------------------------------------------------------------
def test_an_older_days_brief_shows_the_gaps_it_had_then_though_the_source_is_alive_now(conn, lg):
    """A source was judged by when it was last read, as of now: a day the ingest missed five hours of was
    briefed as whole once it ran again."""
    runs(conn, hourly((13.5, 18.4)) + [run_at(h) for h in range(37, 73)])
    o = queries.window_report(conn, DAY_A, DAY_B, lg, now=evening(3, 1), gw_ip=GW)
    lines = cli.coverage_lines(o["coverage"])
    assert "dns: not known from 13:20 to 19:20" in lines and "flows: not known from 13:20 to 19:20" in lines
    later = queries.coverage(conn, evening(2, 0), evening(3, 0), now=evening(3, 1))
    assert later["gaps"] == {"dns": [], "flows": [], "tvlive": []}


def test_the_brief_names_the_share_of_the_ports_bytes_the_flow_record_holds_and_its_holes(conn):
    runs(conn, hourly((15, 17)))  # and no run from 14:20 to 17:20: the holes are the port's alone
    stream(conn, skip=(21, 22))
    cov = queries.coverage(conn, DAY_A, DAY_B, now=NOW)
    assert cli.coverage_lines(cov) == [
        "flow record: 66% of the TV port's bytes; holes: from 21:00 to 22:00",
        "dns: not known from 14:20 to 17:20",
        "flows: not known from 14:20 to 17:20; from 21:00 to 22:00",
    ]
    whole = {"reconcile": {"share": 0.99}, "gaps": {"dns": [], "flows": []}}
    assert cli.coverage_lines(whole) == ["flow record: 99% of the TV port's bytes; holes: none"]
    none_held = {"reconcile": {"share": 0.0}, "gaps": {}}  # the port carried bytes, the record holds none
    assert cli.coverage_lines(none_held) == ["flow record: 0% of the TV port's bytes; holes: none"]
    assert cli.coverage_lines({"gaps": {}, "reconcile": {"share": None}}) == []


@pytest.mark.parametrize("back", [None, at(20)], ids=["quiet still", "quiet, then back"])
def test_a_live_reading_quiet_while_the_tv_was_on_is_a_red_line_while_it_stays_quiet(conn, lg, back):
    """The tabled gap: the heartbeats stop after 19:06 with no disconnect while the readings say the TV is on;
    the brief raised nothing, and the session quietly became "to the hour"."""
    on_all_day(conn)
    beats(conn, at(18.1), at(19.2))
    if back:
        beats(conn, back, NOW)
    o = queries.window_report(conn, DAY_A, DAY_B, lg, now=NOW, gw_ip=GW)
    lines = [x for x in o["red_lines"] if x.startswith("the live reading")]
    assert spans(coverage.Gap(**g) for g in o["coverage"]["gaps"]["tvlive"]) == [
        (LAST_BEAT, back or DAY_B, coverage.WHY_BEAT)
    ]
    assert lines == (
        [] if back else ["the live reading has been silent since 2026-10-26 19:06 while the TV was on"]
    )
    if not back:
        tier, sentence, action = plain.tier(lines[0])
        assert (
            tier == "act" and action.endswith("sudo systemctl restart tvgw-tvlive") and sentence.endswith(".")
        )


@pytest.mark.parametrize(
    ("baseline", "line"),
    [
        (False, "Firewall held from 06:40: adtech ports 50; 6 checks, 0 failed"),
        (True, "Firewall held: adtech ports 60; 6 checks, 0 failed"),
    ],
    ids=["no snapshot before the window", "one in the hour before"],
)
def test_the_firewall_line_says_from_when_its_counts_run_when_that_is_after_the_window_begins(
    conn, lg, baseline, line
):
    """With no snapshot in the hour before, the counts began at the window's first, and nothing said so."""
    snaps = every(at(6 + 40 / 60), at(7.5), 600)
    rows = [(t, 10 * k) for k, t in enumerate(snaps, 1)] + ([(DAY_A - 600, 0)] if baseline else [])
    conn.executemany(
        "INSERT INTO fw_counters(t, rule, packets, bytes) VALUES (?, 'LG adtech port', ?, 0)", rows
    )
    conn.executemany("INSERT INTO verify(t, ok, failures) VALUES (?, 1, '[]')", [(t,) for t in snaps])
    conn.commit()
    out = io.StringIO()
    cli.render_brief(queries.window_report(conn, DAY_A, DAY_B, lg, now=NOW, gw_ip=GW), out)
    assert line in out.getvalue().splitlines()
    assert queries.fw_counted_from(conn, at(8), DAY_B) is None  # no snapshot in the window: nothing to say


# ---- sentences that claim an absence: twenty injected gaps -------------------------------------------------
STRETCHES = {  # five stretches of two runs or more the session from 21:00 to 23:30 overlaps
    "the whole evening": (19, 25),
    "its start": (19, 21.5),
    "its middle": (21.5, 23.5),
    "its end": (22.5, 25),
    "across the session's start": (20, 22),
}


def evening_store(tmp_path, skip=(0, 0), lost=None, name="e") -> Store:
    """The ingest hourly at :20 but for the runs inside `skip`; each run from inside `lost` to the hour after
    it finds lines of both logs lost."""
    s = Store(tmp_path / f"{name}.db")
    runs(s.conn, hourly(skip))
    if lost:
        runs(s.conn, [t for t in hourly() if at(lost[0]) < t < at(lost[1] + 1)], *LOSS)
    return s


def receipt_text(s: Store, lg) -> str:
    """The receipt of a session from 21:00 to 23:30 with one named connection and one answered lookup."""
    s.talk(at(21.5), "cdn.example")
    s.lookup(at(21.4), "cdn.example")
    session = watched(at(21), at(23.5), (at(21), YT))
    rec = receipt.gather(s.conn, lg, GW, at(20), DAY_B, session, known_until=DAY_B, now=NOW)
    (found,) = [r for r in receipt.receipts(rec) if r["app"] == YT]
    return " ".join(" ".join(receipt.render_receipt(found)).split())


def requests(s: Store, lg) -> tuple[dict, str]:
    s.lookup(at(21.5), TRACKER, blocked=1)
    r = drafts.observed(s.conn, lg, DAY_A, DAY_B, now=NOW)
    return r, "\n".join(drafts.render(r)) + drafts.notice(r, [])


@pytest.mark.parametrize("stretch", STRETCHES.values(), ids=STRETCHES)
@pytest.mark.parametrize("how", ["skip", "lost"], ids=["no run read it", "lines lost"])
def test_a_receipt_claims_no_refusal_across_a_stretch_the_query_log_cannot_vouch_for(
    tmp_path, lg, stretch, how
):
    text = receipt_text(evening_store(tmp_path, **{how: stretch}), lg)
    assert "No lookup was refused" not in text
    assert "Whether a lookup was refused while YouTube was in front: not known from" in text


@pytest.mark.parametrize("stretch", STRETCHES.values(), ids=STRETCHES)
@pytest.mark.parametrize("how", ["no run read it", "the port streamed"])
def test_a_company_is_not_called_sent_nothing_across_a_stretch_the_flow_log_cannot_vouch_for(
    tmp_path, lg, stretch, how
):
    s = evening_store(tmp_path, skip=stretch if how == "no run read it" else (0, 0))
    if how == "the port streamed":  # every connection the record holds named: only the holes stand in the way
        stream(s.conn, skip=(max(stretch[0], 20), min(stretch[1], 23)), named=True)
    r, text = requests(s, lg)
    assert not r["sent_nothing_known"] and "nothing through it" not in text
    assert drafts.NO_NAMED in text and drafts.NOTICE_NO_NAMED in text


def test_a_record_read_all_along_still_says_what_did_not_happen(tmp_path, lg):
    # lines lost up to 20:20: inside the window read, before the session began at 21:00
    lost_before = evening_store(tmp_path, lost=(18, 19.5), name="before")
    assert "No lookup was refused while YouTube was in front." in receipt_text(lost_before, lg)
    s = evening_store(tmp_path)
    receipt_text(s, lg)
    r, text = requests(s, lg)  # every connection named: nothing the capture missed
    assert r["sent_nothing_known"] and drafts.SENT_NOTHING in text and drafts.NOTICE_SENT_NOTHING in text


# ---- the receipt's other sentences -------------------------------------------------------------------------
def test_a_session_with_connections_and_no_lookup_of_any_kind_does_not_say_none_was_refused(tmp_path, lg):
    """A session with 29 connections and no lookup of any kind on record said "No lookup was refused"."""
    s = evening_store(tmp_path)
    s.talk(at(21.5), "cdn.example")
    session = watched(at(21), at(23.5), (at(21), YT))
    rec = receipt.gather(s.conn, lg, GW, at(20), DAY_B, session, known_until=DAY_B, now=NOW)
    (found,) = [r for r in receipt.receipts(rec) if r["app"] == YT]
    assert receipt._refused_line(found, "YouTube") == [f"  {receipt.NO_LOOKUPS}"]
    claim = ["  No lookup was refused while YouTube was in front."]
    assert receipt._refused_line({**found, "conns": 0}, "YouTube") == claim  # nothing happened at all


@pytest.mark.parametrize(
    ("answered", "words"),
    [
        (0, "3 times while YouTube was in front, every one refused"),
        (2, "5 times while YouTube was in front, 3 of"),
    ],
)
def test_every_one_refused_is_said_only_when_the_name_was_not_also_answered(tmp_path, lg, answered, words):
    """A name refused three times and answered twice was "asked for 3 times, every one refused"."""
    s = evening_store(tmp_path)
    s.talk(at(21.2), "cdn.example")
    for k, blocked in enumerate([1, 1, 1] + [0] * answered):
        s.lookup(at(22.6) + k * 60, "ads.tracker.example", blocked=blocked)
    s.lookup(at(21.3), "ads.tracker.example", blocked=1)  # the first session's: refused only
    two = watched(at(21), at(22.3), (at(21), YT)) + watched(at(22.5), at(23.5), (at(22.5), YT))
    rec = receipt.gather(s.conn, lg, GW, at(20), DAY_B, two, known_until=DAY_B, now=NOW)
    flat = " ".join(" ".join(receipt.render_receipt(receipt.receipts(rec)[-1])).split())
    assert f"Asked for 1 blocked name {words}" in flat
    evening = " ".join(receipt.render_evening(rec, receipt.evening(rec)))
    assert ("of them refused" in evening) is bool(answered)


# ---- tvgw refused ------------------------------------------------------------------------------------------
OLD = refused.Name(
    "ads.example", 3, 1050.0, 1100.0, "FilteredBlackList", "||ads.example^", 1, first_refused=900.0
)


@pytest.mark.parametrize(
    "fields",
    [{"lookups": 0}, {"lookups": 4}, {"lookups": 4, "hidden": 1}, {"lookups": 4, "names": [OLD]}],
    ids=["looked up nothing", "nothing refused", "no internet name", "nothing new"],
)
@pytest.mark.parametrize("complete", [True, False])
def test_the_first_line_speaks_only_of_the_part_of_the_window_the_query_log_holds(fields, complete):
    """With the log read only part of the way back, the first line still said "Nothing was refused for the TV
    in the last 10 minutes"."""
    rep = refused.Report(since=1000.0, until=1600.0, read_log=True, complete=complete, **fields)
    first = refused.render(rep)[0]
    assert "the last 10 minutes" in first
    assert ("in the part of the last 10 minutes the query log still holds" in first) is not complete


# ---- tvgw requests -----------------------------------------------------------------------------------------
def kept(
    tmp_path, lg, *, dst="203.0.113.50", down=90_000, answers=(TRACKER,), given=-3.0, start=22.0, seconds=60.0
):
    """A company every lookup of which was refused in the window, and one connection no hello named to `dst`,
    an address the `answers` names were given `given` days from the evening (three before)."""
    s = Store(tmp_path / "k.db")
    runs(s.conn, hourly())
    for i, name in enumerate(answers, 1):
        s.lookup(at(20) + given * 86400, name)
        s.conn.execute(
            "INSERT INTO answer_ip(dns_id, t, ip, ttl) VALUES (?, ?, ?, 60)", (i, at(20) + given * 86400, dst)
        )
    s.lookup(at(21), TRACKER, blocked=1)
    s.talk(at(start), None, up_=2_000_000, down_=down, dst=dst, seconds=seconds)
    return drafts.observed(s.conn, lg, DAY_A, DAY_B, now=NOW)


def test_a_company_the_tv_reached_by_an_address_it_kept_is_looked_up_not_only_attempted(tmp_path, lg):
    """Every lookup of the tracker was refused in the window, the TV sent 2 MB to the address it was given
    three days before (the capture missed the hello), and `tvgw requests` said the TV sent it nothing."""
    r = kept(tmp_path, lg)
    google = companies.company(TRACKER)
    assert r[drafts.ATTEMPTED] == [] and [(e["company"], e["kept"]) for e in r[drafts.ANSWERED]] == [
        (google, 1)
    ]
    text = "\n".join(drafts.render(r))
    assert (
        f"{google}: 1 lookup refused; the record holds 1 connection to an address its names were given"
        in text
    )
    assert "Looked up, no named connection (1)" in text and "nothing through it" not in text


@pytest.mark.parametrize(
    "kwargs",
    [
        {"down": 0},  # nothing came back: refused, not made
        {"answers": ("www.example.com",)},  # an address another company's name was given
        {"answers": ()},  # an address no answer gave
        {"given": -7.9},  # given longer ago than the days a name is known by its answers
        {"given": 1.0},  # given after the window
        {"start": -26.0},  # a connection before the window
        {"start": -0.5, "seconds": 7200.0},  # began before it, ended in it
    ],
    ids=[
        "refused connection",
        "another company",
        "no answer",
        "long ago",
        "after",
        "before the window",
        "began before",
    ],
)
def test_a_refused_company_moves_only_for_a_completed_unnamed_connection_in_the_window_to_its_address(
    tmp_path, lg, kwargs
):
    assert [e["company"] for e in kept(tmp_path, lg, **kwargs)[drafts.ATTEMPTED]] == [
        companies.company(TRACKER)
    ]


def test_two_names_of_one_company_given_one_address_count_its_connection_once(tmp_path, lg):
    assert [
        e["kept"] for e in kept(tmp_path, lg, answers=(TRACKER, "ad.doubleclick.net"))[drafts.ANSWERED]
    ] == [1]


@pytest.mark.parametrize(
    ("dst", "known"), [("10.10.10.99", True), ("203.0.113.50", False)], ids=["home", "public"]
)
def test_only_an_unnamed_connection_to_a_public_address_keeps_sent_nothing_from_being_said(
    tmp_path, lg, dst, known
):
    assert kept(tmp_path, lg, dst=dst, answers=("www.example.com",))["sent_nothing_known"] is known


# ---- the guard: no new sentence of absence without the gate ------------------------------------------------
ABSENCE = re.compile(
    r"\bNo (?:[a-z'-]+ ){0,4}(?:was|were)\b|\bNothing (?:new |likely [a-z ]+ )?(?:was|were)\b"
    r"|\bsent (?:these|them|it) nothing\b|\blooked up nothing\b",
    re.IGNORECASE,
)
MODULES = ("queries", "receipt", "refused", "drafts")
BASELINE = os.path.join(os.path.dirname(__file__), "absence_baseline.txt")
GATE = "# gated"


def absence_sentences(src: str, modules: tuple[str, ...] = MODULES) -> dict[tuple[str, str], bool]:
    """Each printed string of the modules that claims an absence, with whether `# gated` stands on its line or
    the one above: the claim is said only where the record was looking. A docstring prints nothing."""
    found: dict[tuple[str, str], bool] = {}
    for module in modules:
        with open(os.path.join(src, f"{module}.py"), encoding="utf-8") as f:
            text = f.read()
        lines = ["", *text.splitlines()]
        tree = ast.parse(text)
        docstrings = {id(n.value) for n in ast.walk(tree) if isinstance(n, ast.Expr)}
        for n in ast.walk(tree):
            printed = isinstance(n, ast.Constant) and isinstance(n.value, str) and id(n) not in docstrings
            if printed and ABSENCE.search(n.value):
                key = (module, " ".join(n.value.split()))
                found[key] = found.get(key, True) and GATE in lines[n.lineno] + lines[n.lineno - 1]
    return found


def baseline() -> set[tuple[str, str]]:
    with open(BASELINE, encoding="utf-8") as f:
        return {tuple(line.rstrip("\n").split("\t", 1)) for line in f if line.strip()}


def test_no_sentence_of_absence_is_new_unless_it_is_gated_and_the_baseline_only_shrinks():
    ungated = {k for k, gated in absence_sentences(os.path.dirname(queries.__file__)).items() if not gated}
    assert ungated <= baseline(), (
        f"gate these, or say them only where the record was looking: {ungated - baseline()}"
    )
    assert baseline() <= ungated, (
        f"take these out of absence_baseline.txt, gated or gone: {baseline() - ungated}"
    )


def test_the_guard_reads_a_sentence_added_without_the_gate_as_new(tmp_path):
    new = tmp_path / "new.py"
    new.write_text(
        '"""No lookup was refused, says a docstring."""\nsay = f"No lookup was refused while {x} ran."\n'
    )
    assert absence_sentences(str(tmp_path), ("new",)) == {("new", "No lookup was refused while"): False}
    new.write_text('say = (  # gated\n    f"No lookup was refused while {x} ran."\n)\n')
    assert absence_sentences(str(tmp_path), ("new",)) == {("new", "No lookup was refused while"): True}
