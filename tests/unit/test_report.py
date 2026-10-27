"""The report path tvgw-analyze actually runs: window bounds, the weekly shape, `tvgw report` through the
CLI, and the renderer branches a week reaches that a day does not. Hand-seeded stores throughout."""

import io
import json
from datetime import datetime

import pytest
from conftest import NOW, fake_extract, fake_oddport

from tvgw import cli, db, ingest, queries
from tvgw.adguard import parse_time

D1_NOON = parse_time("2026-10-26T12:00:00-05:00")  # a Monday, in ISO week 2026-W44
D2_NOON = D1_NOON + 86400
BEFORE_WEEK = D1_NOON - 86400
AFTER_WEEK = D1_NOON + 7 * 86400


@pytest.fixture()
def conn(tmp_path):
    c = db.connect(str(tmp_path / "r.db"))
    yield c
    c.close()


@pytest.fixture()
def conf(gateway, lg, tmp_path):
    """The fake gateway ingested, and a conf file that points the CLI at its store."""
    ingest.run(gateway, lg, extract=fake_extract, oddport_lines=fake_oddport, lock=False)
    path = tmp_path / "tvgw.conf"
    path.write_text(f'TV_IP={gateway.tv_ip}\nDB_PATH="{gateway.db_path}"\n')
    return path


def local(t: float) -> str:
    return datetime.fromtimestamp(t).strftime("%Y-%m-%d %H:%M")


def readings(conn, rows):
    conn.executemany("INSERT INTO tvstate(t, power) VALUES (?, ?)", rows)
    conn.commit()


def render(o: dict) -> str:
    buf = io.StringIO()
    cli.render_brief(o, buf)
    return buf.getvalue()


# ---- the TV line ---------------------------------------------------------------------------------------
def test_tv_readings_collapse_into_power_runs(conn, lg):
    noon = parse_time("2026-10-26T12:00:00-05:00")
    readings(conn, [(noon, "Active"), (noon + 3600, "Active"), (noon + 7200, "unreachable")])
    o = queries.brief(conn, "2026-10-26", lg, now=NOW)
    assert "\nTV: 12:00-13:00=Active, 14:00=unreachable\n" in render(o) + "\n"


def test_a_week_of_readings_is_one_dated_run(conn, lg):
    """168 undated 'HH:MM=state' entries were about 2,700 characters in the weekly report."""
    a, b = queries.week_bounds("2026-W44")
    readings(conn, [(t, "Active") for t in range(int(a) + 1200, int(b), 3600)])
    o = queries.weekly(conn, "2026-W44", lg, now=b + 86400)
    assert len(o["tvstate"]) == 169 and o["tvstate"][0]["time"] == "10-26 00:20"  # the JSON keeps the list
    assert "\nTV: 10-26 00:20-11-01 23:20=Active" in render(o)


# ---- window bounds -----------------------------------------------------------------------------------------
def test_week_bounds_are_monday_to_monday_in_local_time():
    a, b = queries.week_bounds("2026-W01")
    assert (local(a), local(b)) == ("2025-12-29 00:00", "2026-01-05 00:00")  # ISO week 1 starts in 2025
    assert (
        local(queries.week_bounds("2026-W53")[0]) == "2026-12-28 00:00"
    )  # 2026 has 52 weeks: next year's W01
    a, b = queries.week_bounds("2026-W44")
    assert (b - a) / 3600 == 169  # the fall-back night


@pytest.mark.parametrize("week", ["2026-W54", "2026-W99", "2026-44", "W44"])
def test_week_bounds_reject_what_is_not_an_iso_week(week):
    with pytest.raises(ValueError):
        queries.week_bounds(week)


def test_latest_is_the_hours_up_to_now(conn, lg):
    o = queries.latest(conn, 24, lg, now=NOW)
    assert (o["since"], o["until"], o["generated"]) == (NOW - 86400, NOW, NOW)
    assert o["label"] == "last 24 h to 2026-10-26 10:00"


# ---- the weekly shape ----------------------------------------------------------------------------------------
def seed_week(conn):
    conn.executemany(
        "INSERT INTO dns(t, qname, blocked) VALUES (?, ?, ?)",
        [(D1_NOON, "a.example", 0), (D1_NOON, "a.example", 1), (D1_NOON, "b.example", 0)]
        + [(BEFORE_WEEK, "out.example", 1)] * 5
        + [(AFTER_WEEK, "out.example", 1)] * 5,
    )
    conn.executemany(
        "INSERT INTO flows(t_end, dst, dport, bytes_up, bytes_down) VALUES (?, ?, 443, ?, ?)",
        [
            (D1_NOON, "9.9.9.9", 100, 10),
            (D1_NOON, "8.8.8.8", 200, 20),
            (D2_NOON, "7.7.7.7", 300, 30),
            (BEFORE_WEEK, "6.6.6.6", 5000, 5000),
            (AFTER_WEEK, "6.6.6.6", 5000, 5000),
        ],
    )
    conn.commit()


def test_by_day_rows_sum_to_the_header_and_stay_inside_the_week(conn, lg):
    seed_week(conn)
    o = queries.weekly(conn, "2026-W44", lg, now=AFTER_WEEK)
    assert o["week"] == "2026-W44" and o["label"] == "week 2026-W44 (2026-10-26 .. 2026-11-01)"
    assert o["by_day"] == [
        {"day": "2026-10-26", "lookups": 3, "blocked": 1, "conns": 2, "bytes_up": 300, "bytes_down": 30},
        {"day": "2026-10-27", "lookups": 0, "blocked": 0, "conns": 1, "bytes_up": 300, "bytes_down": 30},
    ]  # a day with flows but no lookups is still a row; the days outside the week are not
    assert o["dns"] == {"lookups": 3, "blocked": 1, "names": 2}
    assert o["flows"] == {"conns": 3, "bytes_up": 600, "bytes_down": 60}
    text = render(o)
    assert "\nBy day:\n" in text
    assert (
        "2026-10-26  3        1        2      300B  30B" in text and "2026-10-27  0        0        1" in text
    )


# ---- plain HTTP and DNS bypass -------------------------------------------------------------------------------
def test_plain_http_groups_by_path_without_query_and_skips_the_file_service_and_ssdp(conn, lg):
    agent = "Mozilla/5.0 (Web0S; Linux/SmartTV) " + "x" * 35  # 70 characters
    rows = [("cfg.example", "GET", uri, agent) for uri in ("/a?x=1", "/a?x=1", "/a?x=2")]
    rows += [("other.example", "POST", "/b", "ua")]
    rows += [
        ("ngfts.lge.com", "GET", "/fts/x?biz_code=MAS", "ua"),
        ("239.255.255.250:1900", "M-SEARCH", "*", "ua"),
    ]
    conn.executemany(
        "INSERT INTO http(t, host, method, uri, ua, src) VALUES (?, ?, ?, ?, ?, 'pcap')",
        [(D1_NOON, *r) for r in rows],
    )
    conn.execute(
        "INSERT INTO http(t, host, method, uri, ua, src) VALUES (?, 'g.example', 'GET', '/', 'ua', 'gfts')",
        (D1_NOON,),
    )
    conn.commit()
    assert queries.plain_http(conn, D1_NOON - 1, D1_NOON + 1, lg) == [
        ("cfg.example", "GET", "/a", 3, agent[:60]),
        ("other.example", "POST", "/b", 1, "ua"),
    ]
    assert queries.plain_http(conn, D1_NOON - 1, D1_NOON + 1, lg, limit=1) == [
        ("cfg.example", "GET", "/a", 3, agent[:60])
    ]


def test_dns_bypass_groups_other_resolvers_by_flows_and_excludes_the_gateway(conn):
    conn.executemany(
        "INSERT INTO flows(t_end, dst, dport, pkts_up) VALUES (?, ?, ?, ?)",
        [
            (D1_NOON, "8.8.8.8", 53, 2),
            (D1_NOON, "8.8.8.8", 53, 3),
            (D1_NOON, "1.1.1.1", 53, 1),
            *[(D1_NOON, "10.10.10.1", 53, 1)] * 5,  # the gateway: where DNS is meant to go
            (D1_NOON, "8.8.8.8", 443, 9),  # not DNS
        ],
    )
    conn.commit()
    assert queries.dns_bypass(conn, D1_NOON - 1, D1_NOON + 1, "10.10.10.1") == [
        ("8.8.8.8", 2, 5),
        ("1.1.1.1", 1, 1),
    ]


# ---- `tvgw report` through the CLI ------------------------------------------------------------------------
def report_json(capsys, conf, *argv) -> dict:
    assert cli.main(["--conf", str(conf), "report", *argv, "--json"]) == 0
    return json.loads(capsys.readouterr().out)


def test_report_week_day_window_and_default(capsys, conf):
    week = report_json(capsys, conf, "--week", "2026-W44")
    assert {"week", "by_day"} <= set(week) and "day" not in week
    assert week["label"].startswith("week 2026-W44 (2026-10-26 .. 2026-11-01)")
    assert week["by_day"] == [
        {
            "day": "2026-10-26",
            "lookups": 2,
            "blocked": 1,
            "conns": 2,
            "bytes_up": 2259 + 64,
            "bytes_down": 10742 + 145,
        }
    ]
    day = report_json(capsys, conf, "--day", "2026-10-26")
    assert day["day"] == "2026-10-26" and "by_day" not in day
    window = report_json(capsys, conf, "--since", "2026-10-26", "--until", "2026-10-27")
    assert "day" not in window and window["label"] == "2026-10-26 00:00 .. 2026-10-27 00:00"
    assert window["dns"] == day["dns"] and window["flows"] == day["flows"]
    latest = report_json(capsys, conf)
    assert latest["label"].startswith("last 24 h to 2026-10-26 10:00") and latest["dns"] == day["dns"]


def test_report_week_text_has_the_by_day_table(capsys, conf):
    assert cli.main(["--conf", str(conf), "report", "--week", "2026-W44"]) == 0
    lines = [ln.rstrip() for ln in capsys.readouterr().out.splitlines()]
    assert lines[0].startswith("=== week 2026-W44 (2026-10-26 .. 2026-11-01): 2 lookups")
    at = lines.index("By day:")
    assert lines[at + 1 : at + 3] == [
        "day         lookups  blocked  conns  up    down",
        "2026-10-26  2        1        2      2.3K  10.6K",
    ]
    assert "TV: 10-26 08:20=unreachable, 10-26 09:19=Active" in lines  # dated: longer than a day
