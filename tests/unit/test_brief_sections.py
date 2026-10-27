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
        "INSERT INTO dns(t,qname,blocked,answers) VALUES (1793019000, 'x.example', 0, 'A:142.251.219.1')"
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


FLOW_SQL = "INSERT INTO flows(t_start,t_end,proto,dst,dport,sport,bytes_up,bytes_down) VALUES (?,?,'tcp',?,443,?,?,0)"


@pytest.mark.parametrize(
    ("answers", "resolved"),
    [
        ("A:203.0.113.45", False),  # a substring match took this for the address
        ("A:1203.0.113.4", False),
        ("CNAME:203.0.113.4x.example", False),
        ("A:203.0.113.4", True),
        ("A:198.51.100.1,A:203.0.113.4", True),
        ("CNAME:x,A:203.0.113.4", True),
    ],
)
def test_an_address_is_resolved_only_by_an_a_record_that_names_it(conn, answers, resolved):
    a, b = day()
    conn.execute(FLOW_SQL, (a + 3600, a + 3660, "203.0.113.4", 40100, 500))
    conn.execute(
        "INSERT INTO dns(t,qname,blocked,answers) VALUES (?, 'x.example', 0, ?)", (a + 3000, answers)
    )
    conn.commit()
    unresolved = [u[0] for u in queries.unresolved_flows(conn, a, b, "10.10.10.1")]
    assert ("203.0.113.4" in unresolved) is not resolved


def test_an_answer_counts_from_the_day_before_the_window(conn):
    a, b = day()
    conn.execute(FLOW_SQL, (a + 3600, a + 3660, "203.0.113.4", 40100, 500))
    conn.execute(
        "INSERT INTO dns(t,qname,blocked,answers) VALUES (?, 'x.example', 0, 'A:203.0.113.4')",
        (a - 36 * 3600,),
    )
    conn.commit()
    assert "203.0.113.4" in [u[0] for u in queries.unresolved_flows(conn, a, b, "10.10.10.1")]
    conn.execute(
        "INSERT INTO dns(t,qname,blocked,answers) VALUES (?, 'x.example', 0, 'A:203.0.113.4')",
        (a - 12 * 3600,),
    )
    conn.commit()
    assert "203.0.113.4" not in [u[0] for u in queries.unresolved_flows(conn, a, b, "10.10.10.1")]


def test_unresolved_limit_applies_after_filtering(conn):
    a, b = day()
    conn.executemany(
        FLOW_SQL, [(a + 3600, a + 3660, f"203.0.113.{i}", 40000 + i, 1000 - i) for i in range(1, 31)]
    )
    # the five biggest uploads are answered: they must not use up the limit
    conn.executemany(
        "INSERT INTO dns(t,qname,blocked,answers) VALUES (?, 'x.example', 0, ?)",
        [(a + 3000, f"A:203.0.113.{i}") for i in range(1, 6)],
    )
    conn.commit()
    rows = queries.unresolved_flows(conn, a, b, "10.10.10.1")
    assert len(rows) == 20 and not {r[0] for r in rows} & {f"203.0.113.{i}" for i in range(1, 6)}


def test_ptr_sweeps_count_private_reverse_lookups_only(conn, lg):
    a, b = day()
    conn.executemany(
        "INSERT INTO dns(t,qname,qtype,blocked) VALUES (1793020000, ?, 'PTR', 0)",
        [(f"{i}.8.168.192.in-addr.arpa",) for i in range(1, 6)]
        + [("1.0.0.1.in-addr.arpa",), ("1.1.10.10.in-addr.arpa",)],
    )
    conn.commit()
    assert queries.ptr_sweeps(conn, a, b) == (6, 6)  # five 192.168.8.x plus one 10.x; 1.0.0.1 is public


def test_ptr_sweeps_cover_the_whole_lan4_set_and_nothing_beyond_it(conn, lg):
    """Reproduced: LIKE patterns on the second octet missed 172.18 and 172.19 and counted 172.32-39."""
    a, b = day()
    names = [f"1.1.{n}.172.in-addr.arpa" for n in range(16, 40)] + [
        "1.1.0.10.in-addr.arpa",
        "1.1.168.192.in-addr.arpa",
        "1.1.254.169.in-addr.arpa",
        "1.1.64.100.in-addr.arpa",
        "1.0.0.1.in-addr.arpa",
        "not-a-reverse-name.in-addr.arpa",
    ]
    conn.executemany(
        "INSERT INTO dns(t,qname,qtype,blocked) VALUES (1793020000, ?, 'PTR', 0)", [(n,) for n in names]
    )
    conn.commit()
    assert queries.ptr_sweeps(conn, a, b) == (20, 20)  # 172.16-31 plus the four other LAN ranges


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


def test_standby_attributes_a_connection_to_the_hour_it_was_opened_in(conn, lg):
    """Reproduced: a flow opened while Active and destroyed by the idle timeout during off hours was
    counted as standby traffic, 5 MB of it. conntrack's t_start is the one instant in the row that the
    timeout does not inflate."""
    a, b = day()

    def at(hour: int, minute: int = 0) -> float:
        return a + hour * 3600 + minute * 60  # local clock time on the fixture day

    conn.execute("DELETE FROM tvstate")
    conn.executemany(
        "INSERT INTO tvstate(t, power) VALUES (?, ?)",
        [(at(20, 20), "Active"), (at(21, 20), "Off"), (at(22, 20), "Off"), (at(23, 20), "Off")],
    )
    conn.execute(
        "INSERT INTO flows(t_start,t_end,proto,dst,dport,sport,bytes_up) VALUES (?,?,'tcp','203.0.113.4',443,1,5000000)",
        (at(20, 30), at(21) + 7440),  # last packet about 21:00, reported 2 h 04 min later at 23:04
    )
    conn.commit()
    assert queries.standby_activity(conn, a, b) == {"off_hours": 2, "lookups": 0, "conns": 0, "bytes_up": 0}
    conn.execute(
        "INSERT INTO flows(t_start,t_end,proto,dst,dport,sport,bytes_up) VALUES (?,?,'tcp','203.0.113.5',443,2,700)",
        (at(21, 30), at(21, 31)),  # opened while the TV said it was off: the evidence
    )
    conn.commit()
    assert queries.standby_activity(conn, a, b) == {"off_hours": 2, "lookups": 0, "conns": 1, "bytes_up": 700}


def test_standby_skips_the_gap_between_readings_that_are_not_an_hour_apart(conn, lg):
    """Two off readings 20 h apart bracket a missed day of readings, not an off day; 60 minutes is an hour."""
    a, b = day()
    conn.execute("DELETE FROM tvstate")
    conn.executemany("INSERT INTO tvstate(t, power) VALUES (?, 'Off')", [(a + 3600,), (a + 21 * 3600,)])
    conn.execute("INSERT INTO dns(t,qname,blocked) VALUES (?, 'ghost.example', 0)", (a + 5400,))
    conn.commit()
    assert queries.standby_activity(conn, a, b) == {"off_hours": 0, "lookups": 0, "conns": 0, "bytes_up": 0}
    conn.execute("DELETE FROM tvstate")
    conn.executemany("INSERT INTO tvstate(t, power) VALUES (?, 'Off')", [(a + 3600,), (a + 7200,)])
    conn.commit()
    assert queries.standby_activity(conn, a, b) == {"off_hours": 1, "lookups": 1, "conns": 0, "bytes_up": 0}


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


# ---- the brief's alarms: a silent source must not look like a clean day (design decision 14) ---------
def verify_runs(conn, start: float, n: int) -> None:
    conn.executemany("INSERT INTO verify(t, ok) VALUES (?, 1)", [(start + i * 600,) for i in range(n)])
    conn.commit()


def closed_day(conn, lg):
    """The fixture day as a finished day: `now` is past its end."""
    return queries.brief(conn, "2026-10-26", lg, now=day()[1] + 3600)


def test_a_store_that_never_ran_verify_is_not_assessed_not_alarmed(conn, lg):
    o = closed_day(conn, lg)
    assert "verify" in o["coverage"]["not_assessed"] and o["firewall"]["expected"] == 0
    assert not any("firewall checks ran" in r for r in o["red_lines"])


def test_a_watchdog_that_stopped_mid_day_is_a_red_line(conn, lg):
    verify_runs(conn, day()[0], 36)  # every 10 minutes for the first 6 h, then nothing
    o = closed_day(conn, lg)
    assert (o["firewall"]["runs"], o["firewall"]["expected"]) == (36, 144)
    assert "firewall checks ran 36 of ~144 times (is tvgw-verify.timer alive?)" in o["red_lines"]
    assert "verify" in o["coverage"]["not_assessed"]  # its last run was 18 h before the day closed


def test_a_full_day_of_runs_raises_nothing(conn, lg):
    verify_runs(conn, day()[0], 144)
    o = closed_day(conn, lg)
    assert o["firewall"]["runs"] == 144 and not any("firewall checks ran" in r for r in o["red_lines"])
    assert "verify" not in o["coverage"]["not_assessed"]


def test_expected_runs_count_from_the_first_recorded_run(conn, lg):
    """A store created at 20:00 owes nothing for the hours before it existed."""
    verify_runs(conn, day()[0] + 20 * 3600, 24)
    o = closed_day(conn, lg)
    assert (o["firewall"]["runs"], o["firewall"]["expected"]) == (24, 24)
    assert not any("firewall checks ran" in r for r in o["red_lines"])


def test_the_clock_rule_needs_a_whole_day(conn, lg):
    """The TV reads its clock once after a boot; a two-hour window cannot say it never did."""
    a, b = day()
    conn.execute("DELETE FROM dns WHERE qname='us.lgtvsdp.com'")
    conn.commit()
    two_hours = queries.window_report(conn, a + 9 * 3600, a + 11 * 3600, lg, now=b)  # holds the 09:19 Active
    assert not any("clock host" in r for r in two_hours["red_lines"])
    assert any("never looked up its clock host" in r for r in closed_day(conn, lg)["red_lines"])


def test_an_active_tv_with_no_flows_recorded_names_the_dead_producer(conn, lg):
    conn.execute("DELETE FROM flows")
    conn.commit()
    o = closed_day(conn, lg)
    assert "TV was on but no connections were recorded (is the flow log being read?)" in o["red_lines"]
    assert not any("no lookups" in r for r in o["red_lines"])  # the fixture has DNS rows
    conn.execute("UPDATE tvstate SET power='unreachable'")
    conn.commit()
    assert not any("were recorded" in r for r in closed_day(conn, lg)["red_lines"])


def test_ingest_warnings_belong_to_the_runs_that_fed_the_window(conn, lg):
    _, b = day()
    conn.execute(
        "INSERT INTO ingest_runs(t, seconds, stats, warnings) VALUES (?, 0, '{}', '[\"pcaps: boom\"]')",
        (NOW + 600,),
    )
    conn.commit()
    o = closed_day(conn, lg)
    assert o["coverage"]["warnings"] == ["pcaps: boom"] and "ingest warnings: 1" in o["red_lines"]
    conn.execute("UPDATE ingest_runs SET t=? WHERE t=?", (b + 3 * 3600, NOW + 600))  # after the settle lag
    conn.commit()
    o = closed_day(conn, lg)
    assert o["coverage"]["warnings"] == [] and not any("ingest warnings" in r for r in o["red_lines"])


def test_the_report_carries_when_it_was_generated(conn, lg):
    assert queries.brief(conn, "2026-10-26", lg, now=NOW + 42)["generated"] == NOW + 42


def test_blocked_names_still_reached_over_tls_join_the_two_tables_that_prove_a_bypass(conn, lg):
    """The brief showed DNS retries and unnamed addresses but never joined them; the fixture's blocked
    name (aic.recommend.lgtvcommon.com) has no hello, so the fixture brief stays as it was."""
    import io

    a, b = day()
    assert queries.brief(conn, "2026-10-26", lg)["blocked_reached"] == []
    conn.execute(
        "INSERT INTO tls(t,dst,dport,sport,sni) VALUES (?, '203.0.113.9', 443, 40100, 'aic.recommend.lgtvcommon.com')",
        (a - 3600,),  # the day before: not this window's evidence
    )
    conn.commit()
    assert queries.blocked_reached(conn, a, b) == []
    conn.execute(
        "INSERT INTO tls(t,dst,dport,sport,sni) VALUES (?, '203.0.113.9', 443, 40101, 'aic.recommend.lgtvcommon.com')",
        (a + 10 * 3600,),
    )
    conn.execute("INSERT INTO dns(t,qname,blocked) VALUES (?, 'mixed.example', 1)", (a + 3600,))
    conn.execute("INSERT INTO dns(t,qname,blocked) VALUES (?, 'mixed.example', 0)", (a + 7200,))
    conn.executemany(
        "INSERT INTO tls(t,dst,dport,sport,sni) VALUES (?, '203.0.113.10', 443, ?, 'mixed.example')",
        [(a + 7300, 40102), (a + 7400, 40103)],
    )
    conn.commit()
    o = queries.brief(conn, "2026-10-26", lg)
    assert o["blocked_reached"] == [
        {"name": "mixed.example", "hellos": 2, "blocked": 1, "allowed": 1},  # a rule changed mid-day
        {"name": "aic.recommend.lgtvcommon.com", "hellos": 1, "blocked": 1, "allowed": 0},
    ]
    buf = io.StringIO()
    cli.render_brief(o, buf)
    text = buf.getvalue()
    assert (
        "Blocked names still reached over TLS (cached answer, hardcoded address, or a rule that changed):"
        in text
    )
    assert "aic.recommend.lgtvcommon.com  1       1                0" in text
    assert o["red_lines"] == []  # no alarm yet: AdGuard's 60 s blocked TTL would raise false ones


def acr_line(o: dict) -> str | None:
    return next((r for r in o["red_lines"] if "Live Plus (ACR)" in r), None)


def test_live_plus_coming_back_on_is_a_red_line_until_a_reading_says_off(conn, lg):
    """The README promised a warning when Live Plus comes back on; the only one was an echo in the
    tvgw-analyze journal. The fixture read it off at 09:19."""
    import io

    assert acr_line(queries.brief(conn, "2026-10-26", lg)) is None
    a, b = day()
    conn.execute("INSERT INTO tvsettings(t,key,value) VALUES (?, 'option.livePlus', 'on')", (a + 15 * 3600,))
    conn.commit()
    o = queries.brief(conn, "2026-10-26", lg)
    assert (
        acr_line(o)
        == "Live Plus (ACR) is on on the TV (since 2026-10-26 15:00): General > Additional Settings"
    )
    assert [(r["key"], r["value"]) for r in o["settings_changes"]] == [
        ("option.livePlus", "off"),
        ("option.zipcode", "10001"),
        ("option.livePlus", "on"),
    ]
    buf = io.StringIO()
    cli.render_brief(o, buf)
    text = buf.getvalue()
    assert "TV settings (first reading or change):" in text
    assert "10-26 09:19  option.livePlus  off" in text and "10-26 15:00  option.livePlus  on" in text
    # the next day has no reading of its own; the last known state still stands
    assert acr_line(queries.brief(conn, "2026-10-27", lg)) is not None
    conn.execute("INSERT INTO tvsettings(t,key,value) VALUES (?, 'option.livePlus', 'off')", (b + 3600,))
    conn.commit()
    assert acr_line(queries.brief(conn, "2026-10-27", lg)) is None


def test_a_failed_read_of_live_plus_is_unknown_not_on(conn, lg):
    """Older stores hold 'ERR <type> <msg>' values from before ingest stopped storing read errors."""
    conn.execute(
        "INSERT INTO tvsettings(t,key,value) VALUES (?, 'option.livePlus', 'ERR TimeoutError x')",
        (day()[0] + 15 * 3600,),
    )
    conn.commit()
    assert acr_line(queries.brief(conn, "2026-10-26", lg)) is None


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
