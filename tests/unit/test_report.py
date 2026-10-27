"""The report path tvgw-analyze actually runs: window bounds, the weekly shape, `tvgw report` through the
CLI, and the renderer branches a week reaches that a day does not. Hand-seeded stores throughout."""

import io

import pytest
from conftest import NOW

from tvgw import cli, db, queries
from tvgw.adguard import parse_time


@pytest.fixture()
def conn(tmp_path):
    c = db.connect(str(tmp_path / "r.db"))
    yield c
    c.close()


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
