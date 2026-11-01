"""The VPN boundary in the brief (design decision 44 (vpn)): the Pi's own lookups that left by the uplink,
counted by tvgw-apply's post_leaks chain, as a red line of their own; PIA's state on the Coverage line;
and the flow logger's dropped events kept out of the firewall's evidence (43 (events))."""

import io
import json

import pytest
from conftest import NOW, fake_extract, fake_oddport

from tvgw import analyst, cli, db, flowlog, ingest, queries

DOH = "pi leak: DoH left by the uplink"
DNS = "pi leak: DNS left by the uplink"
A, B = 1793020000, 1793023600  # two snapshots inside 2026-10-26


@pytest.fixture()
def conn(gateway, lg):
    ingest.run(
        gateway, lg, extract=fake_extract, oddport_lines=fake_oddport, gate_lines=lambda since: [], lock=False
    )
    c = db.connect(gateway.db_path)
    yield c
    c.close()


def counters(conn, rows) -> None:
    conn.executemany("INSERT INTO fw_counters(t, rule, packets, bytes) VALUES (?,?,?,0)", rows)
    conn.commit()


def boundary(conn, **vpn) -> None:
    db.set_meta(
        conn, "vpn_boundary", json.dumps({"vpn_if": "auto", "device": None, "pia": None, "t": B, **vpn})
    )
    conn.commit()


def brief(conn, lg):
    return queries.brief(conn, "2026-10-26", lg, now=NOW + 3600)


def test_leaks_and_drops_are_not_the_tvs_firewall_evidence(conn, lg, gateway):
    counters(
        conn,
        [
            (A, "DoT/DoQ", 0),
            (B, "DoT/DoQ", 4),
            (A, DOH, 2),
            (B, DOH, 5),
            (A, DNS, 0),
            (B, DNS, 0),
            (A, flowlog.DROPS_RULE, 10),
            (B, flowlog.DROPS_RULE, 3),  # a new socket: the logger restarted, 3 since
        ],
    )
    o = brief(conn, lg)
    assert o["firewall"]["activity"] == [{"rule": "DoT/DoQ", "packets": 4}]
    assert o["vpn_leaks"] == {"DoH left by the uplink": 3, "DNS left by the uplink": 0}
    assert o["flowlog_drops"] == 3
    buf = io.StringIO()
    cli.render_brief(o, buf)
    assert "pi leak" not in buf.getvalue() and flowlog.DROPS_RULE not in buf.getvalue()
    a, b = queries.day_bounds("2026-10-26")
    p = analyst.pack(conn, a, b, "2026-10-26", lg, gateway)
    assert "pi leak" not in str(p["firewall"])


def test_a_leak_is_a_red_line_on_a_gateway_with_a_vpn(conn, lg):
    counters(conn, [(A, DOH, 0), (B, DOH, 2), (A, DNS, 1), (B, DNS, 4)])
    boundary(conn, device="tun0", pia="Disconnected")
    lines = [r for r in brief(conn, lg)["red_lines"] if r.startswith("the Pi's own lookups")]
    assert lines == [
        "the Pi's own lookups left outside the VPN: DNS left by the uplink 3 time(s), DoH left by the uplink"
        " 2 time(s) (was the tunnel down? see Coverage)"
    ]
    # the VPN client's name and state stay on the Coverage line, out of the analyst's pack
    assert "PIA" not in lines[0]


@pytest.mark.parametrize(
    ("vpn", "red"),
    [
        (None, False),  # no verify run recorded the boundary
        ({}, False),  # auto found no tunnel and there is no piactl, in a store that never saw a VPN
        ({"device": "wgpia0"}, True),
        ({"pia": "Connecting"}, True),  # the tunnel is gone, PIA is not: the very window leaks happen in
        ({"vpn_if": "wg0"}, True),  # a tunnel named in the settings
        ({"vpn_if": "none", "device": None}, False),  # the owner says the Pi runs no VPN client
    ],
)
def test_the_leak_red_line_needs_a_vpn_to_leak_from(conn, lg, vpn, red):
    counters(conn, [(A, DOH, 0), (B, DOH, 1)])
    if vpn is not None:
        boundary(conn, **vpn)
    o = brief(conn, lg)
    assert any(r.startswith("the Pi's own lookups") for r in o["red_lines"]) == red


def test_no_rise_is_no_red_line(conn, lg):
    counters(conn, [(A, DOH, 5), (B, DOH, 5)])
    boundary(conn, device="tun0", pia="Connected")
    assert not any(r.startswith("the Pi's own lookups") for r in brief(conn, lg)["red_lines"])


def test_the_leak_line_is_the_gateways_health_and_buys_no_analyst_request():
    assert "the Pi's own lookups left outside the VPN: x".startswith(analyst.HEALTH_RED_LINES)


def test_pia_state_is_on_the_coverage_line_only_when_the_tool_answered(conn, lg):
    boundary(conn, device="tun0", pia="Connected")
    o = brief(conn, lg)
    assert o["coverage"]["vpn"]["pia"] == "Connected"
    buf = io.StringIO()
    cli.render_brief(o, buf)
    coverage = next(line for line in buf.getvalue().splitlines() if line.startswith("Coverage:"))
    assert ", PIA Connected;" in coverage
    boundary(conn, device="tun0", pia=None)
    buf = io.StringIO()
    cli.render_brief(brief(conn, lg), buf)
    assert "PIA" not in buf.getvalue().splitlines()[1]


def test_a_boundary_record_that_is_not_json_is_no_boundary(conn):
    db.set_meta(conn, "vpn_boundary", "{not json")
    assert queries.vpn_boundary(conn) is None
    db.set_meta(conn, "vpn_boundary", "[1, 2]")
    assert queries.vpn_boundary(conn) is None


@pytest.mark.parametrize(
    ("seen_days_before", "red"),
    [
        (1, True),  # the daemon is down at the last run: no tunnel, no answer from piactl
        (29, True),
        (31, False),  # a VPN last seen over a month ago is no longer this gateway's
    ],
)
def test_a_vpn_seen_lately_keeps_the_leak_red_line_while_the_daemon_is_down(conn, lg, seen_days_before, red):
    """Decision 44's leak cases include the daemon not being active: then the tunnel is gone and
    piactl prints nothing, so the last run's boundary alone would read as a gateway without a VPN,
    exactly while AdGuard's DoH leaves by the uplink."""
    counters(conn, [(A, DOH, 0), (B, DOH, 6)])
    boundary(conn)  # device None, pia None, VPN_IF auto
    _, until = queries.day_bounds("2026-10-26")
    db.set_meta(conn, "vpn_seen_t", repr(float(until - seen_days_before * 86400)))
    conn.commit()
    o = brief(conn, lg)
    assert any(r.startswith("the Pi's own lookups") for r in o["red_lines"]) == red
    assert o["coverage"]["vpn"]["seen_t"] == until - seen_days_before * 86400


def test_a_vpn_seen_without_a_boundary_record_still_counts(conn, lg):
    counters(conn, [(A, DOH, 0), (B, DOH, 1)])
    db.set_meta(conn, "vpn_seen_t", repr(float(B)))
    conn.commit()
    assert queries.vpn_boundary(conn) == {"seen_t": B}
    assert any(r.startswith("the Pi's own lookups") for r in brief(conn, lg)["red_lines"])
    db.set_meta(conn, "vpn_seen_t", "not a time")
    assert queries.vpn_boundary(conn) is None


def test_the_windows_drops_come_from_the_drop_series_alone(conn, lg):
    """tvgw-apply's reload listings carry no drop row: taken as the baseline (fw_activity's shared one),
    they made the window's first drop snapshot count in full."""
    a, b = queries.day_bounds("2026-10-26")
    counters(
        conn,
        [
            (a - 1200, flowlog.DROPS_RULE, 40),  # the drop series' own last snapshot before the window
            (a - 600, "DoT/DoQ", 0),  # an apply's listing, later, with no drop row
            (a + 600, flowlog.DROPS_RULE, 42),
            (a + 1200, flowlog.DROPS_RULE, 45),
        ],
    )
    assert dict(queries.fw_activity(conn, a, b))[flowlog.DROPS_RULE] == 45  # the overcount, shared baseline
    assert queries.flowlog_drops(conn, a, b) == 5
    assert brief(conn, lg)["flowlog_drops"] == 5


def test_without_a_drop_snapshot_before_the_window_its_first_one_is_the_baseline(conn):
    a, b = queries.day_bounds("2026-10-26")
    rows = [
        (a + 600, flowlog.DROPS_RULE, 40),
        (a + 1200, flowlog.DROPS_RULE, 2),
        (a + 1800, flowlog.DROPS_RULE, 7),
    ]
    counters(conn, rows)
    assert queries.flowlog_drops(conn, a, b) == 7  # a restart: 2 new, then 5 more
    assert queries.flowlog_drops(conn, a + 3600, b) == 0  # the last snapshot, an hour before, is the baseline
