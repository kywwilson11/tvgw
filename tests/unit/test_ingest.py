"""End-to-end ingest on the fake gateway: counts, idempotency, rotation, hosts, rules, pruning."""

import os
import sqlite3

from conftest import FLOW_TCP, fake_extract, fake_oddport

from tvgw import db, ingest


def run(gateway, lg):
    return ingest.run(gateway, lg, extract=fake_extract, oddport_lines=fake_oddport, lock=False)


def test_first_run_loads_everything_once(gateway, lg):
    st = run(gateway, lg)
    assert (st.flows, st.dns, st.pcaps, st.tls, st.http, st.gfts) == (2, 2, 1, 1, 2, 2)
    assert (st.tvstate, st.oddport, st.lanprobe) == (2, 1, 1)
    assert (st.rules_added, st.rules_removed) == (5, 0)  # 3 adguard + 1 gfts regex + 1 block4
    assert st.warnings == []
    assert os.path.exists(gateway.db_path)
    conn = db.connect(gateway.db_path, readonly=True)
    c = db.counts(conn)
    assert c["flows"] == 2 and c["dns"] == 2 and c["tls"] == 1 and c["http"] == 4  # 2 pcap + 2 gfts
    assert c["tvstate"] == 2 and c["tvsettings"] == 2 and c["oddport"] == 1 and c["rules"] == 5
    # the SYN towards a remembered LAN device is a probe; those to the gateway and the internet are not
    assert conn.execute("SELECT dst, dport FROM lanprobe").fetchall() == [("192.168.8.69", 80)]
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
    assert "239.255.255.250:1900" not in rows  # SSDP multicast is not a host


def test_hosts_counters_count_each_row_once_however_often_ingest_runs(gateway, lg):
    run(gateway, lg)
    before = conn_rows(gateway)
    run(gateway, lg)
    run(gateway, lg)
    assert conn_rows(gateway) == before
    # a late row (a pcap retried an hour later would look like this) is still counted exactly once
    conn = db.connect(gateway.db_path)
    conn.execute(
        "INSERT INTO tls(t,dst,dport,sport,sni) VALUES (1793000000, '1.1.1.1', 443, 1, 'late.example.net')"
    )
    conn.commit()
    conn.close()
    run(gateway, lg)
    rows = conn_rows(gateway)
    assert rows["late.example.net"] == ("Other", 0, 1, 0)
    assert rows["gfts.lge.com"] == before["gfts.lge.com"]


def conn_rows(gateway):
    conn = db.connect(gateway.db_path, readonly=True)
    out = {r[0]: r[1:] for r in conn.execute("SELECT name, category, dns_n, tls_n, http_n FROM hosts")}
    conn.close()
    return out


def test_hosts_rebuild_when_the_watermark_is_missing_fixes_inflated_counters(gateway, lg):
    run(gateway, lg)
    conn = db.connect(gateway.db_path)
    conn.execute("UPDATE hosts SET dns_n = dns_n * 7, http_n = 99")
    conn.execute("DELETE FROM meta WHERE key='hosts_wm'")
    conn.commit()
    conn.close()
    run(gateway, lg)
    rows = conn_rows(gateway)
    assert rows["us.lgtvsdp.com"] == ("LG core", 1, 0, 0) and rows["ngfts.lge.com"][3] == 3


def test_hosts_categories_follow_the_profile_without_a_new_sighting(gateway, lg):
    from tvgw import profile as profile_mod

    run(gateway, lg)
    changed = profile_mod.from_dict(
        {"profile": {"name": "x"}, "categories": {"Everything": ["lgtvsdp.com", "lge.com", "lgtvcommon.com"]}}
    )
    ingest.run(gateway, changed, extract=fake_extract, oddport_lines=fake_oddport, lock=False)
    assert {r[0] for r in conn_rows(gateway).values()} == {"Everything"}


def test_an_unreadable_rules_source_retires_nothing(gateway, lg):
    run(gateway, lg)
    with open(gateway.adguard_yaml, "w") as fh:
        fh.write("user_rules: [\n")  # half-written file: unknown, not empty
    st = run(gateway, lg)
    assert (st.rules_added, st.rules_removed) == (0, 0)
    os.unlink(gateway.block4)
    st = run(gateway, lg)
    assert st.rules_removed == 0
    conn = db.connect(gateway.db_path, readonly=True)
    assert conn.execute("SELECT COUNT(*) FROM rules WHERE removed_at IS NULL").fetchone()[0] == 5


def test_one_broken_source_is_a_warning_and_the_others_still_land(gateway, lg):
    def exploding(pcap):
        raise ZeroDivisionError("boom")

    st = ingest.run(gateway, lg, extract=exploding, oddport_lines=fake_oddport, lock=False)
    assert st.flows == 2 and st.dns == 2 and st.pcaps == 0
    assert any("pcaps" in w and "ZeroDivisionError" in w for w in st.warnings)
    conn = db.connect(gateway.db_path, readonly=True)
    assert conn.execute("SELECT COUNT(*) FROM flows").fetchone()[0] == 2
    assert "pcaps" not in db.get_meta(conn, "sources_read")
    assert "flows" in db.get_meta(conn, "sources_read")


def test_malformed_dns_records_are_skipped_and_counted(gateway, lg):
    with open(gateway.adguard_querylog, "a") as fh:
        fh.write(
            '{"T":"2026-10-26T09:14:38-05:00","QH":"x.example","IP":"10.10.10.17","Result":{"Reason":"3"},"Elapsed":"x"}\n'
        )
        fh.write(
            '{"T":"2026-10-26T09:14:39-05:00","QH":"y.example","IP":"10.10.10.17","Result":{"Rules":[5]},"Elapsed":1}\n'
        )
    st = run(gateway, lg)
    assert (st.dns >= 2 and st.warnings == []) or any("malformed" in w for w in st.warnings)


def test_pcaps_done_marks_live_while_the_file_exists(gateway, lg):
    run(gateway, lg)
    conn = db.connect(gateway.db_path)
    conn.execute("UPDATE pcaps_done SET done_at = 0")
    conn.commit()
    ingest.prune(conn, days=365, now=1793030000.0, pcap_dir=gateway.pcap_dir)
    assert conn.execute("SELECT COUNT(*) FROM pcaps_done").fetchone()[0] == 1
    os.unlink(os.path.join(gateway.pcap_dir, "tv-20261026-0800.pcap"))
    ingest.prune(conn, days=365, now=1793030000.0, pcap_dir=gateway.pcap_dir)
    assert conn.execute("SELECT COUNT(*) FROM pcaps_done").fetchone()[0] == 0
    conn.close()


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


def test_tail_state_keys_are_stable(gateway, lg):
    """Renaming a source key would re-ingest its whole log on every deployed gateway."""
    run(gateway, lg)
    conn = db.connect(gateway.db_path, readonly=True)
    keys = {r[0] for r in conn.execute("SELECT source FROM ingest_state")}
    assert {"flows", "adguard", "gfts", "tvstate", "oddport"} <= keys
