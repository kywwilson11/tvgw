"""The ingest's warning when the flow logger's event socket dropped events: from the counter `tvgw verify
--record` stores (flowlog.DROPS_RULE), which a reboot cannot erase (design decision 43 (events))."""

from conftest import NOW, fake_extract, fake_oddport

from tvgw import db, flowlog, ingest, queries


def snap(conn, t: float, drops: int) -> None:
    """One `verify --record` snapshot of the drop counter, as record() stores it."""
    conn.execute(
        "INSERT INTO fw_counters(t, rule, packets, bytes) VALUES (?,?,?,0)", (t, flowlog.DROPS_RULE, drops)
    )


def check(conn) -> list[str]:
    said: list[str] = []
    ingest._event_drops(conn, said.append)
    conn.commit()
    return said


def test_the_first_check_only_starts_the_cursor(gateway):
    conn = db.connect(gateway.db_path)
    assert check(conn) == []  # nothing stored yet: no cursor either
    assert conn.execute("SELECT 1 FROM ingest_state WHERE source='flowlog_drops'").fetchone() is None
    snap(conn, NOW - 1200, 40)
    snap(conn, NOW - 600, 45)
    assert check(conn) == []  # what came before the first check is not this run's to report
    row = conn.execute("SELECT offset, last_t FROM ingest_state WHERE source='flowlog_drops'").fetchone()
    assert row == (conn.execute("SELECT MAX(rowid) FROM fw_counters").fetchone()[0], NOW - 600)


def test_growth_since_the_last_check_is_one_warning_with_the_count_and_when(gateway):
    conn = db.connect(gateway.db_path)
    snap(conn, NOW - 3600, 7)
    check(conn)
    snap(conn, NOW - 3000, 7)
    snap(conn, NOW - 2400, 12)  # 2026-10-26 09:20 CDT
    snap(conn, NOW - 1800, 15)
    assert check(conn) == [
        "flows: the flow logger's event socket dropped 8 event(s) since the last run (first seen by tvgw"
        " verify at 2026-10-26 09:20): connections that ended then are not in the store"
    ]
    assert check(conn) == []  # said once
    snap(conn, NOW - 1200, 15)
    assert check(conn) == []  # no growth, no warning


def test_a_lower_count_is_a_new_socket_and_all_of_it_is_new(gateway):
    """tvgw-flowlog restarted (a deploy, a crash): its new event socket counts from zero."""
    conn = db.connect(gateway.db_path)
    snap(conn, NOW - 3600, 15)
    check(conn)
    snap(conn, NOW - 3000, 2)
    snap(conn, NOW - 2400, 4)
    assert "dropped 4 event(s)" in check(conn)[0]


def test_a_pruned_cursor_starts_again_from_the_next_snapshot(gateway):
    conn = db.connect(gateway.db_path)
    snap(conn, NOW - 7300, 1)
    snap(conn, NOW - 7200, 3)
    check(conn)
    conn.execute("DELETE FROM fw_counters WHERE t = ?", (NOW - 7200,))  # the cursor's own snapshot
    snap(conn, NOW - 600, 20)
    snap(conn, NOW - 300, 25)
    assert "dropped 5 event(s)" in check(conn)[0]  # 20 is a baseline: it cannot be split


def test_a_store_pruned_bare_does_not_leave_the_cursor_ahead_of_every_snapshot(gateway):
    """SQLite reuses the rowids of deleted rows at the top of a table: with every snapshot gone, new ones
    would sit below the cursor and never be read."""
    conn = db.connect(gateway.db_path)
    for i in range(5):
        snap(conn, NOW - 7200 + i, i)
    check(conn)
    conn.execute("DELETE FROM fw_counters")
    snap(conn, NOW - 600, 9)  # rowid 1, below the cursor
    assert check(conn) == []  # re-anchored on it
    snap(conn, NOW - 300, 11)
    assert "dropped 2 event(s)" in check(conn)[0]


def test_the_warning_reaches_the_runs_record_and_the_brief(gateway, lg):
    def run():
        return ingest.run(
            gateway,
            lg,
            extract=fake_extract,
            oddport_lines=fake_oddport,
            gate_lines=lambda since: [],
            lock=False,
        )

    conn = db.connect(gateway.db_path)
    snap(conn, NOW - 3600, 1)
    conn.commit()
    assert run().warnings == []
    snap(conn, NOW - 600, 4)
    conn.commit()
    warnings = run().warnings
    assert len(warnings) == 1 and "event socket dropped 3 event(s)" in warnings[0]
    cov = queries.coverage(conn, NOW - 86400, NOW + 1, now=NOW)
    assert any("event socket dropped 3" in w for w in cov["warnings"])
