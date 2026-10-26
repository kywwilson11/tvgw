"""End-to-end ingest on the fake gateway: counts, idempotency, rotation, hosts, rules, pruning."""

import os
import sqlite3

from conftest import FLOW_TCP, fake_extract, fake_oddport

from tvgw import db, ingest


def run(gateway, lg):
    return ingest.run(gateway, lg, extract=fake_extract, oddport_lines=fake_oddport, lock=False)


def test_first_run_loads_everything_once(gateway, lg):
    st = run(gateway, lg)
    assert (st.flows, st.dns, st.pcaps, st.tls, st.http, st.gfts) == (2, 2, 1, 1, 1, 2)
    assert (st.tvstate, st.oddport) == (2, 1)
    assert (st.rules_added, st.rules_removed) == (5, 0)  # 3 adguard + 1 gfts regex + 1 block4
    assert st.warnings == []
    assert os.path.exists(gateway.db_path)
    conn = db.connect(gateway.db_path, readonly=True)
    c = db.counts(conn)
    assert c["flows"] == 2 and c["dns"] == 2 and c["tls"] == 1 and c["http"] == 3  # 1 pcap + 2 gfts
    assert c["tvstate"] == 2 and c["tvsettings"] == 2 and c["oddport"] == 1 and c["rules"] == 5
    # the foreign client, the other-source flow and the test request from the Pi were skipped
    assert conn.execute("SELECT COUNT(*) FROM dns WHERE qname='us.lgtvsdp.com'").fetchone()[0] == 1
    assert conn.execute("SELECT COUNT(*) FROM http WHERE host='example.com'").fetchone()[0] == 0
    # rule and reason came through from AdGuard
    assert conn.execute("SELECT rule, reason FROM dns WHERE blocked=1").fetchone() == (
        "||recommend.lgtvcommon.com^",
        "FilteredBlockList",
    )
    # unexpected-port event parsed
    assert conn.execute("SELECT proto, dst, dport FROM oddport").fetchone() == ("TCP", "156.147.69.32", 8080)


def test_second_run_is_a_no_op(gateway, lg):
    run(gateway, lg)
    st = run(gateway, lg)
    assert (st.flows, st.dns, st.pcaps, st.gfts, st.tvstate, st.oddport, st.rules_added) == (
        0,
        0,
        0,
        0,
        0,
        0,
        0,
    )
    conn = db.connect(gateway.db_path, readonly=True)
    assert db.counts(conn)["dns"] == 2


def test_partial_trailing_line_is_read_once_completed(gateway, lg):
    run(gateway, lg)
    with open(gateway.adguard_querylog, "a") as fh:  # complete the half record left by the fixture
        fh.write('4:40Z","QH":"late.example","QT":"A","IP":"10.10.10.17","Result":{}}\n')
    st = run(gateway, lg)
    assert st.dns == 1
    conn = db.connect(gateway.db_path, readonly=True)
    assert conn.execute("SELECT COUNT(*) FROM dns").fetchone()[0] == 3


def test_copytruncate_rotation_loses_nothing(gateway, lg):
    run(gateway, lg)
    with open(gateway.flows_log, "a") as fh:
        fh.write(FLOW_TCP.replace("sport=58998", "sport=1111"))
    os.rename(gateway.flows_log, gateway.flows_log + ".1")
    with open(gateway.flows_log + ".1", "rb") as src, open(gateway.flows_log, "wb") as dst:
        dst.write(src.read())  # copytruncate: same content copied back... then truncated and reused
    with open(gateway.flows_log, "wb") as fh:
        fh.write(FLOW_TCP.replace("sport=58998", "sport=2222").encode())
    st = run(gateway, lg)
    assert st.flows == 2
    conn = db.connect(gateway.db_path, readonly=True)
    assert sorted(r[0] for r in conn.execute("SELECT sport FROM flows WHERE proto='tcp'")) == [
        1111,
        2222,
        58998,
    ]


def test_hosts_dimension_is_categorized_and_marks_blocked_state(gateway, lg):
    run(gateway, lg)
    conn = db.connect(gateway.db_path, readonly=True)
    rows = {
        r[0]: r for r in conn.execute("SELECT name, category, dns_n, tls_n, http_n, last_blocked FROM hosts")
    }
    assert rows["aic.recommend.lgtvcommon.com"][1:] == ("LG ads", 1, 0, 0, 1)
    assert rows["us.lgtvsdp.com"][1:] == ("LG core", 1, 0, 0, 0)
    assert rows["gfts.lge.com"][1:] == ("LG core", 0, 1, 0, None)  # TLS only: no DNS verdict known
    assert rows["ngfts.lge.com"][1:4] == ("LG core", 0, 0) and rows["ngfts.lge.com"][4] == 3


def test_rules_history_tracks_removals(gateway, lg):
    run(gateway, lg)
    with open(gateway.adguard_yaml) as fh:
        yaml = fh.read()
    with open(gateway.adguard_yaml, "w") as fh:
        fh.write(yaml.replace("  - '||alphonso.tv^'\n", "  - '||example.org^'\n"))
    st = run(gateway, lg)
    assert (st.rules_added, st.rules_removed) == (1, 1)
    conn = db.connect(gateway.db_path, readonly=True)
    removed = conn.execute("SELECT text FROM rules WHERE removed_at IS NOT NULL").fetchall()
    assert removed == [("||alphonso.tv^",)]
    assert conn.execute("SELECT COUNT(*) FROM rules WHERE removed_at IS NULL").fetchone()[0] == 5


def test_tv_settings_recorded_only_on_change(gateway, lg):
    run(gateway, lg)
    with open(gateway.tvcheck_txt, "w") as fh:
        fh.write("read 2026-10-26 10:19\noption.livePlus = on\noption.zipcode = 10001\npower = Active\n")
    run(gateway, lg)
    conn = db.connect(gateway.db_path, readonly=True)
    rows = conn.execute("SELECT key, value FROM tvsettings ORDER BY t, key").fetchall()
    assert rows == [("option.livePlus", "off"), ("option.zipcode", "10001"), ("option.livePlus", "on")]


def test_prune_removes_old_rows_and_vacuums_once(gateway, lg):
    run(gateway, lg)
    conn = db.connect(gateway.db_path)
    conn.execute("INSERT INTO dns(t,qname,blocked) VALUES (1000, 'ancient.example', 0)")
    conn.commit()
    n = ingest.prune(conn, days=365, now=1792990000.0)
    assert n == 1
    assert conn.execute("SELECT COUNT(*) FROM dns WHERE qname='ancient.example'").fetchone()[0] == 0
    assert db.get_meta(conn, "last_vacuum") is not None
    conn.close()


def test_extract_failure_is_retried_next_run(gateway, lg):
    calls = []

    def flaky(pcap):
        calls.append(pcap)
        if len(calls) == 1:
            raise RuntimeError("tshark rc=1")
        return fake_extract(pcap)

    st1 = ingest.run(gateway, lg, extract=flaky, oddport_lines=fake_oddport, lock=False)
    assert st1.pcaps == 0 and st1.warnings and "will retry" in st1.warnings[0]
    st2 = ingest.run(gateway, lg, extract=flaky, oddport_lines=fake_oddport, lock=False)
    assert st2.pcaps == 1 and st2.tls == 1


def test_readonly_connection_works_on_rollback_journal(gateway, lg):
    run(gateway, lg)
    ro = db.connect(gateway.db_path, readonly=True)
    assert ro.execute("SELECT COUNT(*) FROM flows").fetchone()[0] == 2
    try:
        ro.execute("DELETE FROM flows")
        raise AssertionError("read-only connection must not write")
    except sqlite3.OperationalError:
        pass
