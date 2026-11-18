"""End-to-end ingest on the fake gateway: counts, idempotency, rotation, hosts, rules, pruning."""

import base64
import dataclasses
import json
import os
import sqlite3
import struct
from pathlib import Path

import pytest
from conftest import DNS_ALLOWED, DNS_BLOCKED, FLOW_TCP, GFTS_TV_ALLOWED, NOW, TV, fake_extract, fake_oddport

from tvgw import adguard, db, ingest


def no_kernel_lines(since):
    return []  # the DNS gate's kernel log: nothing, unless a test says otherwise


def run(gateway, lg):
    return ingest.run(
        gateway, lg, extract=fake_extract, oddport_lines=fake_oddport, gate_lines=no_kernel_lines, lock=False
    )


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
    assert conn.execute("SELECT dst, dport FROM lanprobe").fetchall() == [("192.168.77.69", 80)]
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
    # the pcap's mark: read without error, one connection attempt to :443 to set against its one hello
    assert conn.execute("SELECT error, attempts, syn443_rows FROM pcaps_done").fetchone() == (None, 0, 1)


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


def test_a_copytruncate_after_a_quiet_spell_loses_nothing(gateway, lg):
    """The cursor of a log found empty must carry what it needs to see the next rotation: `.1`'s inode."""
    with open(gateway.gfts_log, "w") as fh:
        fh.truncate(0)
    assert run(gateway, lg).gfts == 0
    with open(gateway.gfts_log, "a") as fh:
        fh.write(GFTS_TV_ALLOWED)
    with open(gateway.gfts_log, "rb") as src, open(gateway.gfts_log + ".1", "wb") as dst:
        dst.write(src.read())  # copytruncate: copied to .1, then truncated in place
    os.truncate(gateway.gfts_log, 0)
    st = run(gateway, lg)
    assert (st.gfts, st.warnings) == (1, [])


def test_a_log_replaced_by_another_file_is_one_warning_and_the_other_sources_still_land(gateway, lg):
    run(gateway, lg)
    with open(gateway.flows_log, "w") as fh:
        fh.write("something else entirely\n")  # same inode, different beginning, no .1 to recover from
    with open(gateway.gfts_log, "a") as fh:
        fh.write(GFTS_TV_ALLOWED.replace("09:15:30", "09:16:30"))
    st = run(gateway, lg)
    assert st.warnings == [
        "flows: log rotated or truncated since the last run and the lines written before it could not be recovered",
        "flows: 1 malformed line(s) skipped",  # the replacement's one line is not a flow either
    ]
    assert (st.flows, st.gfts) == (0, 1)
    assert run(gateway, lg).warnings == []  # said once


def test_a_poison_flow_line_is_skipped_counted_and_left_behind(gateway, lg):
    """The cursor commits with the rows, so a line the parser rejects would otherwise roll the flows
    step back every hour forever: the good lines land, the cursor moves past it, the brief hears once."""
    poison = FLOW_TCP.replace("packets=18", "packets=18446744073709551615")  # a counter SQLite cannot store
    with open(gateway.flows_log, "w") as fh:
        fh.write(FLOW_TCP + poison + FLOW_TCP.replace("sport=58998", "sport=1111"))
    st = run(gateway, lg)
    assert st.flows == 2 and st.warnings == ["flows: 1 malformed line(s) skipped"]
    again = run(gateway, lg)
    assert again.flows == 0 and again.warnings == []


def test_a_flow_destroyed_early_is_stored_with_its_state_and_the_time_it_had_left(gateway, lg):
    early = FLOW_TCP.replace(" 6 TIME_WAIT ", " 6 7417 ESTABLISHED ")
    huge = early.replace(" 7417 ", " 99999999999999999999 ").replace("sport=58998", "sport=1111")
    with open(gateway.flows_log, "w") as fh:
        fh.write(FLOW_TCP + early + huge)
    st = run(gateway, lg)
    assert st.flows == 2 and st.warnings == ["flows: 1 malformed line(s) skipped"]
    conn = db.connect(gateway.db_path, readonly=True)
    assert conn.execute("SELECT state, timeout_left FROM flows ORDER BY id").fetchall() == [
        ("TIME_WAIT", None),
        ("ESTABLISHED", 7417),
    ]


def test_flows_gains_the_timeout_column_on_an_old_store(tmp_path):
    path = str(tmp_path / "old.db")
    c = sqlite3.connect(path)
    c.execute(
        "CREATE TABLE flows(id INTEGER PRIMARY KEY, t_start REAL, t_end REAL NOT NULL, proto TEXT,"
        " dst TEXT NOT NULL, dport INTEGER, sport INTEGER, pkts_up INTEGER, bytes_up INTEGER,"
        " pkts_down INTEGER, bytes_down INTEGER, state TEXT)"
    )
    c.execute("INSERT INTO flows(t_end, dst, state) VALUES (1, '1.2.3.4', 'TIME_WAIT')")
    c.commit()
    c.close()
    conn = db.connect(path)
    assert conn.execute("SELECT state, timeout_left FROM flows").fetchall() == [("TIME_WAIT", None)]


@pytest.mark.parametrize(("source", "log"), [("flows", "flows_log"), ("gfts", "gfts_log")])
def test_lines_in_neither_log_format_are_counted(gateway, lg, source, log):
    """Both logs are machine-written in one format each, so a line the parser cannot read is a fault
    worth a line in the brief, not silence."""
    with open(getattr(gateway, log), "a") as fh:
        fh.write("garbage\n\n[1793020052.1] not a destroy event\n")
    st = run(gateway, lg)
    assert (st.flows, st.gfts) == (2, 2) and st.warnings == [f"{source}: 3 malformed line(s) skipped"]


def test_fifty_unparsable_gfts_lines_are_one_warning_with_the_count(gateway, lg):
    with open(gateway.gfts_log, "a") as fh:
        fh.writelines(f"==> rotated by hand, line {i} <==\n" for i in range(50))
    st = run(gateway, lg)
    assert st.gfts == 2 and st.warnings == ["gfts: 50 malformed line(s) skipped"]


def test_gfts_rows_carry_the_method_once_the_log_format_does(gateway, lg):
    """Rows from the older format keep NULL; nothing is invented for them."""
    with open(gateway.gfts_log, "a") as fh:
        fh.write(
            '2026-10-26T09:16:30-05:00 10.10.10.17 403 153 0.000 "ngfts.lge.com" '
            '"/fts/gftsDownload.lge?biz_code=CDP&func_code=SCHEDULE_FILE" "Mozila/4.0" POST 412 "-"\n'
        )
    run(gateway, lg)
    conn = db.connect(gateway.db_path, readonly=True)
    rows = conn.execute("SELECT method, status FROM http WHERE src='gfts' ORDER BY t").fetchall()
    assert rows == [(None, 403), (None, 200), ("POST", 403)]


@pytest.mark.parametrize(
    ("field", "warned"),
    [("flows_log", True), ("gfts_log", True), ("adguard_querylog", True), ("tvcheck_history", False)],
)
def test_a_log_that_does_not_exist_is_not_read_and_said_unless_optional(gateway, lg, tmp_path, field, warned):
    """Design decision 14: a silent source must not look like a clean day. The TV-state history is the
    one input that exists only for profiles with a LAN-API reader, so its absence is not a warning;
    it is still not stamped as read."""
    missing = str(tmp_path / "nope.log")
    st = run(dataclasses.replace(gateway, **{field: missing}), lg)
    source = {
        "flows_log": "flows",
        "gfts_log": "gfts",
        "adguard_querylog": "dns",
        "tvcheck_history": "tvstate",
    }[field]
    assert st.warnings == ([f"{source}: {missing} is missing"] if warned else [])
    conn = db.connect(gateway.db_path, readonly=True)
    read = json.loads(db.get_meta(conn, "sources_read"))
    assert source not in read and len(read) == len(ingest.SOURCES) - 1


def test_a_query_log_renamed_away_is_read_from_dot1_until_adguard_writes_the_next(gateway, lg):
    """AdGuard rotates by renaming and creates the new file at its next flush, hours later on a quiet
    night: until then the source was 'missing', NOT ASSESSED and an ingest warning."""
    log = gateway.adguard_querylog
    with open(log, "w") as fh:
        fh.write(DNS_BLOCKED)
    assert run(gateway, lg).dns == 1
    with open(log, "a") as fh:
        fh.write(DNS_ALLOWED)
    os.rename(log, log + ".1")
    st = run(gateway, lg)
    assert (st.dns, st.warnings) == (1, [])
    conn = db.connect(gateway.db_path, readonly=True)
    assert "dns" in json.loads(db.get_meta(conn, "sources_read"))
    with open(log, "w") as fh:
        fh.write(DNS_ALLOWED)
    assert (run(gateway, lg).dns, conn.execute("SELECT COUNT(*) FROM dns").fetchone()) == (1, (3,))


def test_a_missing_pcap_directory_is_a_warning_and_an_empty_one_is_not(gateway, lg, tmp_path):
    st = run(dataclasses.replace(gateway, pcap_dir=str(tmp_path / "nowhere")), lg)
    assert st.warnings == [f"pcaps: {tmp_path / 'nowhere'} is missing"]
    conn = db.connect(gateway.db_path, readonly=True)
    assert "pcaps" not in json.loads(db.get_meta(conn, "sources_read"))
    (tmp_path / "empty").mkdir()
    st = run(dataclasses.replace(gateway, pcap_dir=str(tmp_path / "empty")), lg)
    assert st.warnings == [] and st.pcaps == 0
    assert "pcaps" in json.loads(db.get_meta(conn, "sources_read"))


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
    ingest.run(
        gateway,
        changed,
        extract=fake_extract,
        oddport_lines=fake_oddport,
        gate_lines=no_kernel_lines,
        lock=False,
    )
    assert {r[0] for r in conn_rows(gateway).values()} == {"Everything"}


def test_an_unreadable_rules_source_retires_nothing_and_is_a_warning(gateway, lg):
    run(gateway, lg)
    with open(gateway.adguard_yaml, "w") as fh:
        fh.write("user_rules: [\n")  # half-written file: unknown, not empty
    st = run(gateway, lg)
    assert (st.rules_added, st.rules_removed) == (0, 0)
    assert [w for w in st.warnings if w.startswith("rules: adguard:")] == st.warnings and len(
        st.warnings
    ) == 1
    os.unlink(gateway.block4)
    st = run(gateway, lg)
    assert st.rules_removed == 0
    assert sorted(w.split(":")[1].strip() for w in st.warnings) == ["adguard", "block4"]
    assert any(w.startswith("rules: block4:") and gateway.block4 in w for w in st.warnings)
    conn = db.connect(gateway.db_path, readonly=True)
    assert conn.execute("SELECT COUNT(*) FROM rules WHERE removed_at IS NULL").fetchone()[0] == 5


def test_one_broken_source_is_a_warning_and_the_others_still_land(gateway, lg):
    def exploding(pcap):
        raise ZeroDivisionError("boom")

    st = ingest.run(
        gateway, lg, extract=exploding, oddport_lines=fake_oddport, gate_lines=no_kernel_lines, lock=False
    )
    assert st.flows == 2 and st.dns == 2 and st.pcaps == 0
    assert any("pcaps" in w and "ZeroDivisionError" in w for w in st.warnings)
    conn = db.connect(gateway.db_path, readonly=True)
    assert conn.execute("SELECT COUNT(*) FROM flows").fetchone()[0] == 2
    assert "pcaps" not in db.get_meta(conn, "sources_read")
    assert "flows" in db.get_meta(conn, "sources_read")


def test_a_failing_step_rolls_its_rows_back_and_leaves_no_cursor(gateway, lg, monkeypatch):
    """The rollback in step() had no test: without it the half-done rows rode into the next step's
    commit (the mutant that removed it survived the suite)."""

    def half_done(conn, s, warn):
        conn.execute("INSERT INTO http(t, host, src) VALUES (1, 'half.example', 'gfts')")
        raise ZeroDivisionError("boom")

    monkeypatch.setattr(ingest, "ingest_gfts", half_done)
    st = run(gateway, lg)
    assert st.warnings == ["gfts: ZeroDivisionError: boom"]
    conn = db.connect(gateway.db_path, readonly=True)
    assert conn.execute("SELECT COUNT(*) FROM http WHERE host='half.example'").fetchone() == (0,)
    assert "gfts" not in json.loads(db.get_meta(conn, "sources_read"))
    assert conn.execute("SELECT COUNT(*) FROM ingest_state WHERE source='gfts'").fetchone() == (0,)


def test_malformed_dns_records_are_skipped_and_counted(gateway, lg):
    """Lines that are not records (a NUL run after a power loss, a torn record, an unreadable time)
    are counted and left behind; the good lines land and the cursor moves past them."""
    with open(gateway.adguard_querylog, "w") as fh:
        fh.write(DNS_BLOCKED + "\x00" * 32 + "\n")
        fh.write('{"T":"2026-10-26T09:14:38-05:00","QH":"torn.exa\n')
        fh.write('{"T":"0001-99-99","QH":"y.example","IP":"10.10.10.17","Result":{}}\n' + DNS_ALLOWED)
    st = run(gateway, lg)
    assert st.dns == 2 and st.warnings == ["dns: 3 malformed query-log record(s) skipped"]
    assert run(gateway, lg).warnings == []  # counted once, never retried


def test_an_oddly_typed_record_does_not_hold_the_query_log_back(gateway, lg):
    """A list where AdGuard writes an int could not be bound; executemany raised outside the
    per-record try, so the rows and the cursor rolled back and every later record waited forever."""
    poison = DNS_ALLOWED.replace(
        '"Text":"@@||us.lgtvsdp.com^"}', '"Text":"@@||us.lgtvsdp.com^","FilterListID":[0]}'
    )
    assert poison != DNS_ALLOWED
    with open(gateway.adguard_querylog, "w") as fh:
        fh.write(DNS_BLOCKED + poison + DNS_ALLOWED)
    st = run(gateway, lg)
    assert st.dns == 3 and st.warnings == []
    conn = db.connect(gateway.db_path, readonly=True)
    offset = conn.execute("SELECT offset FROM ingest_state WHERE source='adguard'").fetchone()[0]
    assert offset == os.path.getsize(gateway.adguard_querylog)


# ---- (bounds) the query log's lines, bounded where they enter (design decision 107) ------------------------
def lookup(i: int, **fields) -> str:
    """One query-log line of the TV's: an A lookup of n<i>.example, `fields` over it."""
    line = {
        "T": f"2026-10-26T09:10:{i:02d}-05:00",
        "QH": f"n{i}.example",
        "QT": "A",
        "IP": TV,
        "Elapsed": 1000,
    }
    return json.dumps({**line, **fields}) + "\n"


def answer(addresses: int = 0, cnames: int = 0) -> str:
    """AdGuard's base64 of an answer: `cnames` CNAMEs, each naming the question's 251-character name through
    one pointer, then A records of `addresses` addresses. A 64 KB answer to a name an app controls (over
    TCP) holds thousands; the reference's largest held 14."""
    question = b"".join(b"\x01a" for _ in range(126)) + b"\x00" + struct.pack(">HH", 1, 1)
    rdata = [(5, b"\xc0\x0c")] * cnames + [(1, struct.pack(">I", 0xC6336401 + i)) for i in range(addresses)]
    records = b"".join(b"\xc0\x0c" + struct.pack(">HHIH", t, 1, 60, len(rd)) + rd for t, rd in rdata)
    head = struct.pack(">HHHHHH", 1, 0x8180, 1, len(rdata), 0, 0)
    return base64.b64encode(head + question + records).decode()


def read_log(gateway, *lines: str) -> tuple[sqlite3.Connection, int, list[str]]:
    """The query log made of `lines`, read once by the dns step: the store, the rows and the warnings."""
    Path(gateway.adguard_querylog).write_text("".join(lines), encoding="utf-8")
    conn, warnings = db.connect(gateway.db_path), []
    n = ingest.ingest_dns(conn, gateway, warnings.append)
    conn.commit()
    return conn, n, warnings


ODD = {
    "a list id past 64 bits": (lookup(1, Result={"Rules": [{"Text": "||x^", "FilterListID": 2**70}]}), 2),
    "a time past a float's range": (lookup(1).replace('"Elapsed": 1000', '"Elapsed": 1' + "0" * 400), 3),
    "a lone surrogate in the name": (lookup(1).replace("n1.example", "n\\ud800.example"), 2),
    "a lone surrogate in the upstream": (lookup(1, Upstream="https://\ud800.example"), 2),
    "100,000 brackets": ("[" * 100_000 + "\n", 2),
}


@pytest.mark.parametrize(("odd", "stored"), ODD.values(), ids=ODD)
def test_one_odd_line_neither_stops_the_query_log_nor_holds_its_cursor(gateway, odd, stored):
    """Each line raised out of the dns step (OverflowError, UnicodeEncodeError at the bind, RecursionError),
    so the hour rolled back with its cursor, and every hour after it did too: one odd line stopped the DNS
    record for good. A number past a float's range now reads as no time; the others are malformed."""
    conn, n, warnings = read_log(gateway, lookup(0), odd, lookup(2))
    assert n == stored and conn.execute("SELECT COUNT(*) FROM dns").fetchone() == (stored,)
    assert warnings == ([] if stored == 3 else ["dns: 1 malformed query-log record(s) skipped"])
    offset = conn.execute("SELECT offset FROM ingest_state WHERE source='adguard'").fetchone()[0]
    assert offset == os.path.getsize(gateway.adguard_querylog)


@pytest.mark.parametrize(
    ("addresses", "cnames", "kept", "named"),
    [(4000, 0, 64, 64), (0, 4661, 64, 0), (65, 0, 64, 64), (64, 0, 64, 64), (12, 2, 14, 12)],
    ids=["4,000 addresses", "4,661 CNAMEs", "one past the cut", "the cut", "the reference's largest"],
)
def test_an_answer_is_stored_to_its_first_64_records_and_the_cut_is_one_warning_a_run(
    gateway, addresses, cnames, kept, named
):
    """Answers were stored whole: 4,000 A records were 4,000 answer_ip rows, and 4,661 CNAMEs 1.2 MB of
    store and 400 ms of ingest, for one lookup an app can make several times a second."""
    looked_up = [lookup(i, Answer=answer(addresses, cnames)) for i in range(2)]
    conn, n, warnings = read_log(gateway, *looked_up)
    stored = [a.split(",") for (a,) in conn.execute("SELECT answers FROM dns")]
    assert n == 2 and [len(a) for a in stored] == [kept, kept]
    assert conn.execute("SELECT COUNT(*) FROM answer_ip").fetchone() == (2 * named,)
    cut = addresses + cnames > adguard.ANSWER_RECORDS
    assert warnings == (["dns: 2 answer(s) held more than 64 records; cut"] if cut else [])


@pytest.mark.parametrize(
    ("others", "seen"),
    [({"10.10.10.99": 40, "10.10.10.98": 1}, {"lookups": 41, "addresses": 2}), ({}, None)],
    ids=["a second device", "the reference's own"],
)
def test_lookups_from_another_address_on_the_tv_side_are_counted_and_never_stored(gateway, others, seen):
    """40 lookups from 10.10.10.99 were answered by AdGuard and dropped by the ingest without a word: the
    TV under a second address could look names up outside the record. The gateway's own address on the
    TV's side and the probe's look names up by design, and an address outside TV_NET is no device on the
    TV's side: none of them is ever counted. The count is kept as counts, never an address."""
    ours = {gateway.gw_ip: 5, gateway.tv_probe_ip: 5, "192.0.2.33": 2, "no address": 1}
    elsewhere = [lookup(9, IP=ip) for ip, times in {**ours, **others}.items() for _ in range(times)]
    conn, n, warnings = read_log(gateway, lookup(0), *elsewhere, lookup(1), lookup(2))
    assert n == 3 and conn.execute("SELECT COUNT(*) FROM dns").fetchone() == (3,)
    kept = db.get_meta(conn, ingest.OTHERS_KEY)
    if seen is None:
        assert warnings == [] and kept is None
    else:
        assert warnings == [
            "dns: 41 lookup(s) came from 2 other address(es) on the TV's side; they are not in the record"
        ]
        assert json.loads(kept) == {"t": NOW, **seen} and "10.10" not in kept


def stored(gateway, lg) -> list[str]:
    """Every row a run stores from the fake gateway, as SQL text; the store is removed after it."""
    assert run(gateway, lg).warnings == []
    conn = sqlite3.connect(gateway.db_path)
    try:
        return list(conn.iterdump())
    finally:
        conn.close()
        os.unlink(gateway.db_path)


def test_a_normal_day_is_stored_row_for_row_the_same_with_and_without_the_bounds(gateway, lg, monkeypatch):
    """Design decision 107's promise: no bound may lose what a normal day on the reference stores. A day
    shaped like the reference's (the fixture's hour, the largest answer it has seen, of 14 records with
    their CNAMEs, and the gateway's own and the probe's lookups on the TV's side) stores the same rows in
    every table with the bounds as shipped and with each of them lifted."""
    day = [
        lookup(1, Answer=answer(12, cnames=2)),
        lookup(2, IP=gateway.gw_ip),
        lookup(3, IP=gateway.tv_probe_ip),
    ]
    Path(gateway.adguard_querylog).write_text(DNS_BLOCKED + DNS_ALLOWED + "".join(day), encoding="utf-8")
    shipped = stored(gateway, lg)
    assert any("CNAME:" in row and "A:198.51.100.12" in row for row in shipped)
    monkeypatch.setattr(adguard, "ANSWER_RECORDS", 2**16)  # more than any answer holds
    monkeypatch.setattr(ingest, "_tv_side_other", lambda s: lambda client: False)
    monkeypatch.setattr(ingest._Clock, "install", lambda clock: None)  # no step on a clock
    assert stored(gateway, lg) == shipped


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

    st1 = ingest.run(
        gateway, lg, extract=flaky, oddport_lines=fake_oddport, gate_lines=no_kernel_lines, lock=False
    )
    assert st1.pcaps == 0 and st1.warnings and "will retry" in st1.warnings[0]
    st2 = ingest.run(
        gateway, lg, extract=flaky, oddport_lines=fake_oddport, gate_lines=no_kernel_lines, lock=False
    )
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


def test_tv_state_lines_in_iso_form_with_offset_and_the_old_naive_form(gateway, lg):
    with open(gateway.tvcheck_history, "a") as fh:
        fh.write("2026-10-26T10:20:00-05:00 Active com.peacock.tv\n2026-10-26T11:20:00-05:00 unreachable\n")
    with open(gateway.tvcheck_txt, "w") as fh:
        fh.write(
            "read 2026-10-26T11:20:00-05:00\noption.livePlus = off\noption.zipcode = 10001\npower = Active\n"
        )
    run(gateway, lg)
    conn = db.connect(gateway.db_path, readonly=True)
    rows = conn.execute(
        "SELECT datetime(t,'unixepoch','localtime'), power, app FROM tvstate ORDER BY t"
    ).fetchall()
    assert rows == [
        ("2026-10-26 08:20:00", "unreachable", None),
        ("2026-10-26 09:19:00", "Active", "youtube.leanback.v4"),
        ("2026-10-26 10:20:00", "Active", "com.peacock.tv"),
        ("2026-10-26 11:20:00", "unreachable", None),
    ]
    assert conn.execute("SELECT COUNT(*) FROM tvsettings").fetchone()[0] == 2  # same values: no new rows


def test_pcaps_done_gains_its_newer_columns_on_an_old_store(tmp_path):
    """Old marks have no error and no attempts: they read as done, which is what they were."""
    path = tmp_path / "old.db"
    c = sqlite3.connect(path)
    c.execute(
        "CREATE TABLE pcaps_done(name TEXT PRIMARY KEY, done_at REAL, tls_rows INTEGER, http_rows INTEGER)"
    )
    c.execute("INSERT INTO pcaps_done VALUES ('tv-1.pcap', 1, 2, 3)")
    c.commit()
    c.close()
    conn = db.connect(str(path))
    assert conn.execute("SELECT syn443_rows, error, attempts FROM pcaps_done").fetchone() == (
        None,
        None,
        None,
    )
    conn.close()


def test_ingest_state_gains_the_head_column_on_an_old_store(tmp_path):
    import sqlite3

    path = tmp_path / "old.db"
    c = sqlite3.connect(path)
    c.execute(
        "CREATE TABLE ingest_state(source TEXT PRIMARY KEY, inode INTEGER, offset INTEGER, last_t REAL)"
    )
    c.execute("INSERT INTO ingest_state VALUES ('flows', 1, 2, 3)")
    c.commit()
    c.close()
    conn = db.connect(str(path))
    assert conn.execute("SELECT head FROM ingest_state WHERE source='flows'").fetchone() == (None,)
    conn.close()


def test_connect_commits_its_own_bookkeeping_so_other_writers_do_not_wait(tmp_path):
    """db.connect used to leave the schema-version INSERT in an open transaction: a RESERVED lock every
    other writer (the analyst, the ingest) waited on until the first commit or close."""
    import sqlite3

    from tvgw import db

    first = db.connect(str(tmp_path / "x.db"))
    assert not first.in_transaction
    other = sqlite3.connect(str(tmp_path / "x.db"), timeout=0.2)
    other.execute("INSERT INTO judgments(name, kind, t) VALUES ('a', 'watch', 1)")
    other.commit()
    assert first.execute("SELECT COUNT(*) FROM judgments").fetchone()[0] == 1
    first.close()
    other.close()
