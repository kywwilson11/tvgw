"""The brief's red lines and evidence sections, on a store seeded with the fake gateway."""

import pytest
from conftest import NOW, fake_extract, fake_oddport

from tvgw import cli, db, ingest, queries


@pytest.fixture()
def conn(gateway, lg):
    ingest.run(gateway, lg, extract=fake_extract, oddport_lines=fake_oddport, lock=False)
    c = db.connect(gateway.db_path)
    yield c
    c.close()


def day():
    return queries.day_bounds("2026-10-26")


def test_quiet_day_has_no_red_lines(conn, lg):
    o = queries.brief(conn, "2026-10-26", lg, now=NOW + 3600)
    assert o["red_lines"] == [] and o["must_allow_blocked"] == []
    assert o["clock"]["lookups"] == 1 and o["clock"]["blocked"] == 0  # us.lgtvsdp.com, allowed
    assert o["firewall"]["runs"] == 0 and o["firewall"]["activity"] == []
    assert [u["dst"] for u in o["unresolved"]] == ["142.251.219.1"]  # the fixture flow has no name anywhere
    assert o["ptr"] == {"lookups": 0, "names": 0}
    assert o["standby"] == {
        "off_hours": 0,
        "lookups": 0,
        "conns": 0,
        "bytes_up": 0,
    }  # off at 08:20, on at 09:19


def test_must_allow_blocked_and_blocked_clock_are_red_lines(conn, lg):
    conn.execute("INSERT INTO dns(t,qname,blocked,rule) VALUES (1793030000, 'snu.lge.com', 1, '||lge.com^')")
    conn.execute(
        "INSERT INTO dns(t,qname,blocked,rule) VALUES (1793030001, 'us.lgtvsdp.com', 1, '||lgtvsdp.com^')"
    )
    conn.commit()
    o = queries.brief(conn, "2026-10-26", lg)
    assert any("snu.lge.com x1 by ||lge.com^" in r for r in o["red_lines"])
    assert any("clock host lookups blocked: 1" in r for r in o["red_lines"])


def test_telemetry_under_the_clock_zone_is_not_a_clock_host(conn, lg):
    conn.execute(
        "INSERT INTO dns(t,qname,blocked,rule) VALUES (1793030000, 'us.rdx2.lgtvsdp.com', 1, '||rdx2.lgtvsdp.com^')"
    )
    conn.execute("INSERT INTO dns(t,qname,blocked) VALUES (1793030001, 'gb.nextlgsdp.com', 0)")
    conn.commit()
    a, b = day()
    clock = queries.clock_sync(conn, a, b, lg)
    assert clock["lookups"] == 2 and clock["blocked"] == 0  # us.lgtvsdp.com + gb.nextlgsdp.com; rdx2 ignored
    assert queries._like("??.lgtvsdp.com") == "__.lgtvsdp.com" and queries._like("a_b*") == "a\\_b%"


def test_tv_on_without_a_clock_lookup_is_a_red_line(conn, lg):
    conn.execute("DELETE FROM dns WHERE qname='us.lgtvsdp.com'")
    conn.commit()
    o = queries.brief(conn, "2026-10-26", lg)
    assert any("never looked up its clock host" in r for r in o["red_lines"])
    conn.execute("UPDATE tvstate SET power='unreachable'")
    conn.commit()
    assert queries.red_lines(queries.brief(conn, "2026-10-26", lg)) == []  # TV off all day: nothing expected


def test_unresolved_flows_need_no_name_from_any_source(conn, lg):
    a, b = day()
    # the fixture flow to 142.251.219.1 has no TLS hello and no DNS answer: unresolved
    assert [u[0] for u in queries.unresolved_flows(conn, a, b, "10.10.10.1")] == ["142.251.219.1"]
    conn.execute(
        "INSERT INTO dns(t,qname,blocked,answers) VALUES (1793019000, 'x.example', 0, 'A 142.251.219.1')"
    )
    conn.commit()
    assert queries.unresolved_flows(conn, a, b, "10.10.10.1") == []
    conn.execute(
        "INSERT INTO flows(t_start,t_end,proto,dst,dport,sport,bytes_up,bytes_down) VALUES (1793020000,1793020010,'tcp','192.168.8.69',80,1,60,0)"
    )
    conn.execute(
        "INSERT INTO flows(t_start,t_end,proto,dst,dport,sport,bytes_up,bytes_down) VALUES (1793020000,1793020010,'tcp','10.10.10.1',80,2,60,0)"
    )
    conn.commit()
    assert (
        queries.unresolved_flows(conn, a, b, "10.10.10.1") == []
    )  # LAN probe and the gateway itself do not count


def test_ptr_sweeps_count_private_reverse_lookups_only(conn, lg):
    a, b = day()
    conn.executemany(
        "INSERT INTO dns(t,qname,qtype,blocked) VALUES (1793020000, ?, 'PTR', 0)",
        [(f"{i}.8.168.192.in-addr.arpa",) for i in range(1, 6)]
        + [("1.0.0.1.in-addr.arpa",), ("1.1.10.10.in-addr.arpa",)],
    )
    conn.commit()
    assert queries.ptr_sweeps(conn, a, b) == (6, 6)  # five 192.168.8.x plus one 10.x; 1.0.0.1 is public


def test_firmware_change_lists_the_hosts_that_followed(conn, lg):
    a, b = day()
    conn.execute("INSERT INTO tvsettings(t,key,value) VALUES (1793020000, 'firmware', '04.65.10')")
    conn.commit()
    fc = queries.firmware_changes(conn, a, b)
    assert len(fc) == 1 and fc[0]["firmware"] == "04.65.10" and "gfts.lge.com" in fc[0]["new_hosts"]


def test_standby_activity_counts_traffic_while_the_tv_said_it_was_off(conn, lg):
    a, b = day()
    conn.execute("UPDATE tvstate SET power='unreachable'")  # off at 08:20 and still off at 09:19
    conn.execute("INSERT INTO dns(t,qname,blocked) VALUES (1793021000, 'ghost.example', 0)")  # 08:23 CDT
    conn.commit()
    # the window is 08:20-09:19: the ghost plus the two 09:14 fixture lookups; the flows ended 08:07, before it
    assert queries.standby_activity(conn, a, b) == {"off_hours": 1, "lookups": 3, "conns": 0, "bytes_up": 0}


def test_standby_hours_are_those_the_tv_called_anything_but_active(conn, lg):
    """webOS reports 'Active Standby' and 'Screen Off' for its sleeping states: both are off hours,
    and a day with no Active reading expects no clock lookup."""
    a, b = day()
    conn.execute("DELETE FROM tvstate")
    conn.executemany(
        "INSERT INTO tvstate(t, power) VALUES (?, 'Active Standby')", [(1793016000,), (1793019600,)]
    )  # 07:00 and 08:00 CDT
    conn.execute("INSERT INTO dns(t,qname,blocked) VALUES (1793017000, 'ghost.example', 0)")  # 07:16
    conn.execute("DELETE FROM dns WHERE qname='us.lgtvsdp.com'")
    conn.commit()
    assert queries.standby_activity(conn, a, b) == {"off_hours": 1, "lookups": 1, "conns": 0, "bytes_up": 0}
    assert not any("clock host" in r for r in queries.brief(conn, "2026-10-26", lg)["red_lines"])


def test_render_shows_firewall_and_red_lines(conn, lg):
    import io

    conn.execute(
        "INSERT INTO verify(t, ok, failures) VALUES (1793030000, 0, '[\"FAIL forwarding: ip_forward=0\"]')"
    )
    conn.executemany(
        "INSERT INTO fw_counters(t, rule, packets, bytes) VALUES (?,?,?,?)",
        [
            (1793020000, "DoT/DoQ", 0, 0),
            (1793023600, "DoT/DoQ", 4, 1),
            (1793020000, "TV DNS aimed elsewhere -> AdGuard", 100, 0),
            (1793023600, "TV DNS aimed elsewhere -> AdGuard", 130, 0),
        ],
    )
    conn.commit()
    o = queries.brief(conn, "2026-10-26", lg, now=NOW + 3600)
    buf = io.StringIO()
    cli.render_brief(o, buf)
    text = buf.getvalue()
    assert "Firewall held: DNS forced to AdGuard 30, DoT/DoQ 4; 1 checks, 1 failed" in text
    assert "RED LINE: firewall checks failed 1 of 1 times; last: FAIL forwarding: ip_forward=0" in text
    assert "Clock hosts: 1 lookups (0 blocked)" in text
    assert "Unresolved flows" in text and "142.251.219.1" in text
