"""(tripwire) The notice for a TV that speaks while off (design decision 66): the brief's While off/asleep
line names what the TV reached between two readings that both found it off, and the plain brief says so
in one line that is never an action. On the reference CX the line has read 0 lookups and 0 connections
(docs/tv/lg-cx-measured.md); the tests hold the hour boundaries, a missing reading, a screen saver, a
reading that says nothing, a session the readings missed, and the brief's lines."""

import io

import pytest
from conftest import NOW

from tvgw import cli, db, plain, queries


@pytest.fixture()
def conn(tmp_path):
    c = db.connect(str(tmp_path / "off.db"))
    yield c
    c.close()


def at(hour: float) -> float:
    """A local clock time on 2026-10-26, computed under the test time zone."""
    return queries.day_bounds("2026-10-26")[0] + hour * 3600


def readings(conn, *pairs) -> None:
    conn.executemany("INSERT INTO tvstate(t, power) VALUES (?, ?)", [(at(h), p) for h, p in pairs])
    conn.commit()


def lookup(conn, hour: float, name: str) -> None:
    conn.execute("INSERT INTO dns(t, qname, qtype, blocked) VALUES (?, ?, 'A', 0)", (at(hour), name))
    conn.commit()


def connection(conn, hour: float, dst: str, sport: int, name: str | None = None, up: int = 1500) -> None:
    conn.execute(
        "INSERT INTO flows(t_start, t_end, proto, dst, dport, sport, pkts_up, bytes_up, pkts_down, bytes_down)"
        " VALUES (?, ?, 'tcp', ?, 443, ?, 10, ?, 10, 4000)",
        (at(hour), at(hour) + 130, dst, sport, up),
    )
    if name:
        conn.execute(
            "INSERT INTO tls(t, dst, dport, sport, sni) VALUES (?, ?, 443, ?, ?)",
            (at(hour), dst, sport, name),
        )
    conn.commit()


def brief(conn, lg) -> dict:
    return queries.brief(conn, "2026-10-26", lg, now=NOW + 86400)


def while_off(o: dict) -> list[str]:
    out = io.StringIO()
    cli.render_brief(o, out)
    return [ln for ln in out.getvalue().splitlines() if ln.startswith("While off/asleep")]


def note(o: dict, lg) -> list[str]:
    return [ln for ln in plain.plain_brief(o, profile=lg) if ln.startswith("  While off:")]


def test_a_silent_off_tv_reads_as_it_did_before(conn, lg):
    """The reference's shape: off at both ends, nothing in between. The line is the one the brief always
    printed, no names are computed, and the plain brief says nothing."""
    readings(conn, (1, "unreachable"), (2, "unreachable"), (3, "unreachable"))
    o = brief(conn, lg)
    assert o["standby"] == {"off_hours": 2.0, "lookups": 0, "conns": 0, "bytes_up": 0}
    assert o["standby_names"] == []
    assert while_off(o) == ["While off/asleep (2 h): 0 lookups, 0 connections, up 0B"]
    assert note(o, lg) == []


def test_what_the_tv_reached_while_off_is_named_by_lookup_hello_or_address(conn, lg):
    readings(conn, (8, "unreachable"), (9, "unreachable"), (10, "unreachable"))
    lookup(conn, 8.2, "us.lgtvsdp.com")
    lookup(conn, 8.4, "us.lgtvsdp.com")
    lookup(conn, 9.5, "snu.lge.com")
    connection(conn, 9.6, "198.51.100.30", 40_001, "rdx2.lgtvsdp.com")
    connection(conn, 9.7, "203.0.113.9", 40_002)
    o = brief(conn, lg)
    assert (o["standby"]["lookups"], o["standby"]["conns"]) == (3, 2)
    assert o["standby_names"] == [
        {"name": "us.lgtvsdp.com", "lookups": 2, "conns": 0},
        {"name": "203.0.113.9", "lookups": 0, "conns": 1},
        {"name": "rdx2.lgtvsdp.com", "lookups": 0, "conns": 1},
        {"name": "snu.lge.com", "lookups": 1, "conns": 0},
    ]
    assert while_off(o) == [
        "While off/asleep (2 h): 3 lookups, 2 connections, up 2.9K; names: us.lgtvsdp.com x2, 203.0.113.9 x1,"
        " rdx2.lgtvsdp.com x1, snu.lge.com x1"
    ]
    assert note(o, lg) == [
        "  While off: Between two hourly checks that found it switched off, the TV went online: 3 lookups and"
        " 2 connections (lgtvsdp.com, 203.0.113.9, lge.com). Either it was switched on in between, or it goes"
        " online while it is off."
    ]


def test_the_off_hour_runs_from_its_first_reading_to_the_next_and_no_further(conn, lg):
    """Half open: a lookup at the first off reading's own second is in the off hour, one at the next
    reading's second belongs to the hour after, which ends Active and is not off."""
    readings(conn, (5, "unreachable"), (6, "unreachable"), (7, "Active"))
    lookup(conn, 5, "first.example")
    lookup(conn, 6, "next.example")
    o = brief(conn, lg)
    assert [x["name"] for x in o["standby_names"]] == ["first.example"]
    assert o["standby"]["lookups"] == 1


def test_a_screen_saver_is_the_tv_on_and_never_off(conn, lg):
    """On the reference the screen saver hours carry viewing traffic (Peacock paused behind it)."""
    readings(conn, (20, "unreachable"), (21, "Screen Saver"), (22, "Screen Saver"))
    lookup(conn, 20.5, "peacocktv.com")
    lookup(conn, 21.5, "peacocktv.com")
    o = brief(conn, lg)
    assert o["standby"]["off_hours"] == 0 and o["standby_names"] == [] and note(o, lg) == []


def test_a_missing_reading_is_not_an_off_hour(conn, lg):
    """Two off readings three hours apart bracket a reading that never came, not three off hours."""
    readings(conn, (1, "unreachable"), (4, "unreachable"))
    lookup(conn, 2, "ghost.example")
    o = brief(conn, lg)
    assert o["standby"]["off_hours"] == 0 and o["standby_names"] == [] and note(o, lg) == []


@pytest.mark.parametrize(
    "ends", [("unknown", "unknown"), ("unreachable", "unknown"), ("unknown", "unreachable")]
)
def test_a_reading_that_says_nothing_is_neither_on_nor_off(conn, lg, ends):
    """`unknown` is a TV that answered without a power state, or one nothing was asked of (not paired, its
    key refused): it may be on, so an hour with one at either end is not off. Before 2026-11-05 it was,
    and a TV whose key the TV had refused read every hour of its evening as traffic while off."""
    readings(conn, (18, ends[0]), (19, ends[1]))
    lookup(conn, 18.5, "netflix.com")
    o = brief(conn, lg)
    assert o["standby"] == {"off_hours": 0, "lookups": 0, "conns": 0, "bytes_up": 0}
    assert o["standby_names"] == [] and note(o, lg) == []


def test_active_standby_with_traffic_is_the_tv_online_while_off(conn, lg):
    """LG's word for off with the network kept up (Quick Start+): the change the tripwire is for."""
    readings(conn, (2, "Active Standby"), (3, "Active Standby"))
    lookup(conn, 2.5, "snu.lge.com")
    o = brief(conn, lg)
    assert o["standby_names"] == [{"name": "snu.lge.com", "lookups": 1, "conns": 0}]
    assert note(o, lg)[0].startswith(
        "  While off: Between two hourly checks that found it switched off, the TV"
    )


def test_the_names_are_computed_only_when_the_line_has_traffic(conn, lg, monkeypatch):
    def boom(*a, **k):
        raise AssertionError("standby_names ran on a quiet window")

    monkeypatch.setattr(queries, "standby_names", boom)
    readings(conn, (1, "unreachable"), (2, "unreachable"))
    assert brief(conn, lg)["standby_names"] == []


def test_the_notice_is_never_a_red_line_and_never_the_action(conn, lg):
    readings(conn, (2, "unreachable"), (3, "unreachable"))
    lookup(conn, 2.5, "beacon.example")
    o = brief(conn, lg)
    assert note(o, lg) and not any("off" in r.lower() and "beacon" in r for r in o["red_lines"])
    assert all("went online" not in sentence for _, sentence, _ in plain.items(o, lg))


def test_a_name_from_the_tv_is_escaped_in_the_line(conn, lg):
    readings(conn, (2, "unreachable"), (3, "unreachable"))
    lookup(conn, 2.5, "evil\x1b[2J.example")
    assert while_off(brief(conn, lg))[0].endswith("names: evil\\x1b[2J.example x1")


def test_the_plain_brief_and_the_engineering_brief_agree_on_what_says_nothing():
    assert set(plain.NO_READING) - {None} == set(queries.NO_POWER)


def test_a_missed_session_the_counters_calibrate_away_leaves_the_names_too(conn, lg):
    """(activity) Once the TV port's counters are calibrated, a stream between two off readings is a
    session the readings missed: its lookups leave the count and the names, the quiet moment stays."""
    from test_activity import Port, calibration_days, missed_session

    port = Port(conn)
    end = calibration_days(conn, port, queries.day_bounds("2026-10-20")[0])
    t = end + 7200
    port.run(end, 12, 20_000)
    missed_session(conn, port, t)
    assert queries.standby_names(conn, t, t + 3601) == [{"name": "standby.example", "lookups": 1, "conns": 0}]


# ---- the evidence that the TV was really off ----------------------------------------------------------


PLAIN_OFF = (
    "  While off: Between two hourly checks that found it switched off, the TV went online: 1 lookup"
    " (lge.com). Either it was switched on in between, or it goes online while it is off."
)


def test_a_tv_off_at_both_ends_that_made_one_lookup(conn, lg):
    """(d) No samples of the TV port: the readings alone, so the line gives both explanations."""
    readings(conn, (2, "unreachable"), (3, "unreachable"))
    lookup(conn, 2.5, "snu.lge.com")
    assert note(brief(conn, lg), lg) == [PLAIN_OFF]


def port(conn, start_hour: float, per_10_min: int, steps: int = 7) -> None:
    from test_activity import Port

    Port(conn).run(at(start_hour), steps, per_10_min)


def test_a_quiet_port_says_it_goes_online_while_off(conn, lg):
    readings(conn, (2, "unreachable"), (3, "unreachable"))
    lookup(conn, 2.5, "snu.lge.com")
    port(conn, 1.9, 20_000)  # a trickle: under activity.AWAKE_BYTES in every 10 minutes
    o = brief(conn, lg)
    assert o["standby_notice"]["port"] == "quiet"
    assert note(o, lg) == [
        "  While off: Between two hourly checks that found it switched off, the TV went online: 1 lookup"
        " (lge.com). The gateway saw too little traffic for anyone to have been watching, so it goes online"
        " while off."
    ]


def test_a_busy_port_keeps_the_line_out_of_the_plain_brief(conn, lg):
    """The TV port carried 300 KB in a 10 minutes the readings call off: someone was using it, or its
    LAN API answered nothing while it was on. The engineering line says so; the plain brief says nothing."""
    readings(conn, (2, "unreachable"), (3, "unreachable"))
    lookup(conn, 2.5, "snu.lge.com")
    port(conn, 1.9, 300_000)
    o = brief(conn, lg)
    assert o["standby_notice"]["port"] == "active" and note(o, lg) == []
    assert while_off(o)[0].endswith("; names: snu.lge.com x1; the TV port's counters show it in use then")


def test_up_to_three_services_then_how_many_more(conn, lg):
    readings(conn, (2, "unreachable"), (3, "unreachable"))
    for i, name in enumerate(
        ("a.one.example", "b.two.example", "c.three.example", "d.four.example", "e.five.example")
    ):
        lookup(conn, 2.1 + i / 10, name)
    assert "(one.example, two.example, three.example and 2 more)" in note(brief(conn, lg), lg)[0]


# ---- a line that comes every day ----------------------------------------------------------------------


def day_at(day: str, hour: float) -> float:
    return queries.day_bounds(day)[0] + hour * 3600


def test_a_line_that_comes_daily_says_so_once_then_waits_for_a_new_name(conn, lg):
    days = ("2026-10-23", "2026-10-24", "2026-10-25", "2026-10-26")
    for day in days:
        conn.executemany(
            "INSERT INTO tvstate(t, power) VALUES (?, 'unreachable')", [(day_at(day, 3),), (day_at(day, 4),)]
        )
        conn.execute(
            "INSERT INTO dns(t, qname, qtype, blocked) VALUES (?, 'snu.lge.com', 'A', 0)", (day_at(day, 3.5),)
        )
    conn.commit()

    def day_brief(day):
        return queries.brief(conn, day, lg, now=NOW + 86400)

    third, fourth = day_brief("2026-10-25"), day_brief("2026-10-26")
    assert third["standby_notice"]["days_running"] == 3 and note(third, lg)[0].endswith(
        " This has come 3 days running, so the short brief leaves it out until it changes (tvgw brief --full"
        " keeps it)."
    )
    assert fourth["standby_notice"]["days_running"] == 4 and note(fourth, lg) == []
    assert while_off(fourth)[0].endswith(
        "; names: snu.lge.com x1; 4 days running"
    )  # the engineering brief keeps it
    lookup(conn, 3.6, "new.vendor.example")  # 2026-10-26: a name the earlier days did not have
    assert note(day_brief("2026-10-26"), lg)


# ---- what the tripwire could not judge -----------------------------------------------------------------


def test_hours_whose_check_could_not_read_the_power_state_are_listed_as_not_checked(conn, lg):
    """Since `unknown` is no reading, a TV whose power read fails would make the tripwire silently blind;
    the brief says what it could not check instead."""
    readings(conn, (18, "unknown"), (19, "unknown"), (20, "unreachable"))
    o = brief(conn, lg)
    said = "whether the TV went online while it was off, in 2 hours when the hourly check could not tell whether it was on"
    assert said in o["not_checked"]
    assert f"  Not checked: {said}." in plain.plain_brief(o, profile=lg)
    out = io.StringIO()
    cli.render_brief(o, out)
    assert f"Not checked: {said}" in out.getvalue()
