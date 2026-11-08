"""(namebound) Name-bound egress, stage 1 (design decision 70): the answer record, the five classes of a TLS
connection, the naming of flows a hello did not name and its guard, the DoH-shaped meter, the brief's
section and plain lines, and `tvgw host` explaining one connection."""

import json
import random
import re

from conftest import NOW, fake_extract, fake_oddport, plan, statements

from tvgw import adguard, db, forget, ingest, namebound, queries

DAY = 86400
BASE = 1793020000.0  # 2026-10-26 08:06 CDT, the fixtures' day
A, B = queries.day_bounds("2026-10-26")


def store(tmp_path, since: float = BASE - 30 * DAY):
    conn = db.connect(str(tmp_path / "n.db"))
    db.set_meta(conn, namebound.FROM_KEY, "0")
    db.set_meta(conn, namebound.DONE_KEY, "1")
    db.set_meta(conn, namebound.SINCE_KEY, str(since))
    conn.commit()
    return conn


def answer(conn, t, qname, answers, ttl=60, blocked=0):
    cur = conn.execute(
        "INSERT INTO dns(t, qname, qtype, answers, blocked) VALUES (?, ?, 'A', ?, ?)",
        (t, qname, answers, blocked),
    )
    namebound.record(conn, cur.lastrowid, t, answers, ttl)
    return cur.lastrowid


def hello(conn, t, dst, sni, sport=40000, ech=0, transport=None, dport=443):
    conn.execute(
        "INSERT INTO tls(t, dst, dport, sport, sni, ech, transport) VALUES (?,?,?,?,?,?,?)",
        (t, dst, dport, sport, sni, ech, transport),
    )


def flow(conn, start, dst, up, down, sport=40000, dport=443, proto="tcp", pkts_up=10, pkts_down=10, end=None):
    conn.execute(
        "INSERT INTO flows(t_start, t_end, proto, dst, dport, sport, pkts_up, bytes_up, pkts_down, bytes_down)"
        " VALUES (?,?,?,?,?,?,?,?,?,?)",
        (
            start,
            end if end is not None else start + 60,
            proto,
            dst,
            dport,
            sport,
            pkts_up,
            up,
            pkts_down,
            down,
        ),
    )


def classes(conn, a=A, b=B):
    return [(h.sni, h.dst, h.cls) for h in namebound.classify(conn, a, b, "10.10.10.1")]


# ---- the record ------------------------------------------------------------------------------------------
def test_the_parser_keeps_the_smallest_a_lifetime_and_the_stored_answer_as_it_was():
    from conftest import DNS_ALLOWED, DNS_BLOCKED

    r = adguard.parse_querylog_line(DNS_ALLOWED)
    assert r.answers == "CNAME:us-lgtvsdp-com.aws-prd.net,A:35.166.189.68" and r.a_ttl == 12
    assert adguard.parse_querylog_line(DNS_BLOCKED).a_ttl is None  # an AAAA answer has no A lifetime
    broken = json.loads(DNS_ALLOWED)
    broken["Answer"] = "AAAA"  # three bytes: no header
    r = adguard.parse_querylog_line(json.dumps(broken))
    assert (r.answers, r.a_ttl) == (None, None)  # what answers_text has always stored for it


def test_only_public_addresses_enter_once_each_and_the_chain_is_every_name():
    answers = "CNAME:Edge.Example.NET.,A:203.0.113.7,A:203.0.113.7,A:0.0.0.0,A:10.10.10.1,A:192.168.1.4,A:198.51.100.2"
    assert namebound.addresses(answers) == ["203.0.113.7", "198.51.100.2"]
    assert namebound.addresses(None) == [] and namebound.addresses("AAAA:::1") == []
    assert namebound.chain("cdn.example", answers) == ["cdn.example", "edge.example.net"]


def test_the_hourly_ingest_records_each_allowed_answers_addresses_with_its_lifetime(gateway, lg):
    ingest.run(
        gateway, lg, extract=fake_extract, oddport_lines=fake_oddport, gate_lines=lambda s: [], lock=False
    )
    conn = db.connect(gateway.db_path)
    rows = conn.execute(
        "SELECT d.qname, a.ip, a.ttl, a.t = d.t FROM answer_ip a JOIN dns d ON d.id = a.dns_id"
    ).fetchall()
    assert rows == [("us.lgtvsdp.com", "35.166.189.68", 12, 1)]  # the blocked AAAA answer named nothing
    assert db.get_meta(conn, namebound.FROM_KEY) == "0" and db.get_meta(conn, namebound.DONE_KEY) == "1"
    assert float(db.get_meta(conn, namebound.SINCE_KEY)) == NOW  # a new store covers nothing before it
    assert db.get_meta(conn, "schema") == str(db.SCHEMA_VERSION)


def test_the_backfill_turns_older_lookups_into_rows_newest_first_and_moves_the_coverage_back(tmp_path):
    conn = db.connect(str(tmp_path / "n.db"))
    old = [
        (NOW - d * DAY, f"n{d}.example", f"A:203.0.113.{d}") for d in range(40, 0, -1)
    ]  # 40 days, in order
    conn.executemany("INSERT INTO dns(t, qname, qtype, answers, blocked) VALUES (?, ?, 'A', ?, 0)", old)
    namebound.mark_start(conn, NOW)
    namebound.mark_start(conn, NOW + 5)  # once only
    assert (
        float(db.get_meta(conn, namebound.SINCE_KEY)) == NOW and db.get_meta(conn, namebound.FROM_KEY) == "40"
    )
    answer(conn, NOW + 1, "live.example", "A:198.51.100.9")  # the live ingest's row, after the boundary
    assert namebound.backfill(conn, NOW, rows=10) == 10
    got = [r[0] for r in conn.execute("SELECT ip FROM answer_ip WHERE ttl IS NULL ORDER BY t DESC")]
    assert got == [f"203.0.113.{d}" for d in range(1, 11)]  # the newest ten, with no lifetime
    assert float(db.get_meta(conn, namebound.SINCE_KEY)) == NOW - 10 * DAY
    while namebound.backfill(conn, NOW, rows=10):
        pass
    days = sorted(
        int(ip.rsplit(".", 1)[1]) for (ip,) in conn.execute("SELECT ip FROM answer_ip WHERE ttl IS NULL")
    )
    assert days == list(range(1, namebound.ANSWER_IP_DAYS + 1))  # nothing older than the table keeps
    assert float(db.get_meta(conn, namebound.SINCE_KEY)) == NOW - namebound.ANSWER_IP_DAYS * DAY
    assert conn.execute("SELECT COUNT(*) FROM answer_ip WHERE ip = '198.51.100.9'").fetchone() == (1,)
    assert namebound.backfill(conn, NOW) == 0  # done


def test_a_store_younger_than_the_table_span_is_covered_from_its_first_lookup(tmp_path):
    conn = db.connect(str(tmp_path / "n.db"))
    conn.execute(
        "INSERT INTO dns(t, qname, qtype, answers, blocked) VALUES (?, 'a.example', 'A', 'A:203.0.113.1', 0)",
        (NOW - 3 * DAY,),
    )
    namebound.mark_start(conn, NOW)
    namebound.backfill(conn, NOW)
    assert float(db.get_meta(conn, namebound.SINCE_KEY)) == NOW - 3 * DAY
    empty = db.connect(str(tmp_path / "e.db"))
    namebound.mark_start(empty, NOW)
    assert namebound.backfill(empty, NOW) == 0 and float(db.get_meta(empty, namebound.SINCE_KEY)) == NOW


def test_prune_keeps_the_span_and_moves_the_coverage_up(tmp_path):
    conn = store(tmp_path, since=NOW - 60 * DAY)
    answer(conn, NOW - 40 * DAY, "old.example", "A:203.0.113.1")
    answer(conn, NOW - 2 * DAY, "new.example", "A:203.0.113.2")
    assert namebound.prune(conn, NOW) == 1
    assert float(db.get_meta(conn, namebound.SINCE_KEY)) == NOW - namebound.ANSWER_IP_DAYS * DAY
    assert namebound.prune(conn, NOW, db_days=1) == 1  # DB_DAYS shorter than the span wins
    assert ingest.prune(conn, 365, now=NOW) >= 0 and conn.execute(
        "SELECT COUNT(*) FROM answer_ip"
    ).fetchone() == (0,)


def test_forget_takes_the_rows_and_the_coverage_with_it(tmp_path):
    assert forget.TABLES["answer_ip"][0] == forget.FORGET and forget.TIME_COLUMNS["answer_ip"] == "t"
    assert set(namebound.META_KEYS) <= set(forget.META_FORGET)


# ---- the five classes ------------------------------------------------------------------------------------
def test_each_connection_gets_its_class(tmp_path):
    conn = store(tmp_path)
    answer(conn, BASE - 3600, "app.example", "CNAME:app.example.edge.net,A:203.0.113.10,A:203.0.113.11")
    answer(conn, BASE - 60, "video.example", "A:198.51.100.20")
    hello(conn, BASE, "203.0.113.10", "app.example")  # the question
    hello(conn, BASE + 1, "203.0.113.11", "APP.example.Edge.NET.")  # a CNAME target, any case, trailing dot
    hello(conn, BASE + 2, "198.51.100.20", "tracker.example")  # the address was given, for another name
    hello(conn, BASE + 3, "192.0.2.30", "app.example")  # this address was never given
    hello(conn, BASE + 4, "192.0.2.31", "cloudflare-ech.com", ech=1)  # real ECH, by its outer name
    hello(conn, BASE + 5, "203.0.113.10", "app.example", transport="quic")  # refused by the wall: left out
    hello(conn, BASE + 6, "10.10.10.1", "gfts.lge.com")  # the gateway's own server: left out
    hello(conn, BASE + 7, "192.168.1.9", "nas.example")  # a LAN address: left out
    conn.execute(
        "INSERT INTO tls_noname(t, dst, dport, sport) VALUES (?, '203.0.113.10', 443, 40009)", (BASE + 8,)
    )
    conn.commit()
    assert classes(conn) == [
        ("app.example", "203.0.113.10", "bound"),
        ("app.example.edge.net", "203.0.113.11", "bound"),
        ("tracker.example", "198.51.100.20", "shared"),
        ("app.example", "192.0.2.30", "never"),
        ("cloudflare-ech.com", "192.0.2.31", "ech"),
    ]
    sec = namebound.section(conn, A, B, None)
    assert sec["counts"] == {"bound": 2, "shared": 1, "never": 1, "noname": 1, "ech": 1, "unassessed": 0}


def test_an_answer_binds_for_the_day_after_it_and_never_before_it(tmp_path):
    conn = store(tmp_path)
    answer(conn, BASE - DAY + 30, "day.example", "A:203.0.113.40")
    answer(conn, BASE + 10, "late.example", "A:203.0.113.41")  # logged after the connection
    hello(conn, BASE, "203.0.113.40", "day.example")
    hello(conn, BASE + 60, "203.0.113.40", "day.example")  # the answer is over a day old by now
    hello(conn, BASE, "203.0.113.41", "late.example")
    conn.commit()
    assert classes(conn) == [
        ("day.example", "203.0.113.40", "bound"),
        ("late.example", "203.0.113.41", "never"),
        ("day.example", "203.0.113.40", "never"),
    ]


def test_a_connection_the_answers_cannot_reach_back_for_is_not_assessed_never_never(tmp_path):
    conn = store(tmp_path, since=BASE - 3600)  # the table began an hour before
    hello(conn, BASE, "192.0.2.50", "cached.example")
    conn.commit()
    assert classes(conn) == [("cached.example", "192.0.2.50", "unassessed")]
    assert namebound.section(conn, A, B, None)["counts"]["never"] == 0
    assert (
        namebound.section(db.connect(str(tmp_path / "fresh.db")), A, B, None) is None
    )  # no table record yet


def test_grease_ech_on_a_looked_up_name_is_an_ordinary_hello(tmp_path):
    conn = store(tmp_path)
    answer(conn, BASE - 5, "site.example", "A:203.0.113.60")
    hello(conn, BASE, "203.0.113.60", "site.example", ech=1)  # Chromium's GREASE extension, a real name
    hello(conn, BASE + 1, "203.0.113.61", "outer.example", ech=1)  # never looked up: real ECH
    conn.commit()
    assert classes(conn) == [
        ("site.example", "203.0.113.60", "bound"),
        ("outer.example", "203.0.113.61", "ech"),
    ]


def test_the_samples_say_what_explains_each_one(tmp_path, lg):
    conn = store(tmp_path)
    answer(
        conn, BASE - 3 * DAY, "tracker.example", "A:198.51.100.70"
    )  # given this address, three days before
    answer(conn, BASE - 600, "tracker.example", "A:0.0.0.0", blocked=1)  # blocked since
    answer(conn, BASE - 300, "www.shop.example", "A:198.51.100.70")
    answer(conn, BASE - 200, "img.shop.example", "A:198.51.100.71")
    answer(conn, BASE - 100, "us.lgtvsdp.com", "A:198.51.100.72")
    hello(conn, BASE, "198.51.100.70", "tracker.example")
    hello(conn, BASE + 5, "198.51.100.70", "tracker.example", sport=40001)
    hello(conn, BASE + 1, "198.51.100.71", "api.shop.example")
    hello(conn, BASE + 2, "198.51.100.72", "snu.lge.com")
    hello(conn, BASE + 3, "192.0.2.80", "us.lgtvsdp.com")  # looked up, answered with another address
    conn.commit()
    sec = namebound.section(conn, A, B, lg)
    shared = {e["name"]: e for e in sec["shared"]}
    t = shared["tracker.example"]
    assert (t["n"], t["answered_for"], t["same_site"], t["blocked"], t["last_bound"]) == (
        2,
        ["www.shop.example"],
        False,
        True,
        BASE - 3 * DAY,
    )
    assert shared["api.shop.example"]["same_site"] and not shared["api.shop.example"]["blocked"]
    assert shared["snu.lge.com"]["must_allow"] and not shared["tracker.example"]["must_allow"]
    (never,) = sec["never"]
    assert (never["name"], never["looked_up"], never["blocked"], never["must_allow"]) == (
        "us.lgtvsdp.com",
        True,
        False,
        True,
    )
    assert sec["shared"][0]["name"] == "tracker.example"  # most connections first


def test_classify_reads_by_index_never_a_pass_over_the_answers(tmp_path):
    conn = store(tmp_path)
    for i in range(50):
        answer(conn, BASE - i * 600, f"n{i}.example", f"A:203.0.113.{i}")
        hello(conn, BASE + i, f"203.0.113.{i}", f"n{i}.example")
    conn.commit()
    ran = statements(conn, lambda: namebound.section(conn, A, B, None))
    assert len(ran) > 50
    scans = [
        sql
        for sql in ran
        if re.search(r"\bSCAN (a|answer_ip|d|dns|tls|tls_noname|flows|f)\b", plan(conn, sql))
    ]
    assert not scans, [plan(conn, sql) for sql in scans]


def test_the_classes_partition_the_connections(tmp_path):
    """Property: whatever the answers and hellos, every TLS connection over TCP to a public address gets
    exactly one class; a hello whose own name and address were answered in the day before is bound; one
    whose address no answer gave is never; and adding an answer can only move a connection toward bound."""
    rng = random.Random(7)
    for trial in range(25):
        (tmp_path / str(trial)).mkdir()
        conn = store(tmp_path / str(trial))
        names = [f"s{i}.example" for i in range(5)]
        addrs = [f"203.0.113.{i}" for i in range(1, 6)]
        given = set()
        for _ in range(rng.randint(0, 8)):
            t = BASE - rng.uniform(0, 2 * DAY)
            n, ip = rng.choice(names), rng.choice(addrs)
            answer(conn, t, n, f"A:{ip}")
            given.add((n, ip, t))
        hellos = [(BASE + i, rng.choice(addrs), rng.choice(names)) for i in range(10)]
        for t, ip, n in hellos:
            hello(conn, t, ip, n, sport=40000 + int(t - BASE))
        conn.commit()
        got = namebound.classify(conn, A, B, "10.10.10.1")
        assert len(got) == len(hellos)
        for h in got:
            in_day = [(n, ip) for n, ip, t in given if h.t - DAY <= t <= h.t + namebound.SLACK]
            if (h.sni, h.dst) in in_day:
                assert h.cls == "bound"
            elif any(ip == h.dst for _, ip in in_day):
                assert h.cls == "shared"
            else:
                assert h.cls == "never"
        before = {(h.t, h.dst): h.cls for h in got}
        answer(conn, BASE - 1, names[0], f"A:{addrs[0]}")
        rank = {"never": 0, "shared": 1, "bound": 2}
        for h in namebound.classify(conn, A, B, "10.10.10.1"):
            assert rank[h.cls] >= rank[before[(h.t, h.dst)]]
        conn.close()


# ---- naming the flows no hello named --------------------------------------------------------------------
def test_a_flow_without_a_hello_is_named_only_by_a_single_service(tmp_path):
    conn = store(tmp_path)
    answer(conn, BASE - 600, "a.example", "CNAME:a.example.cdn.net,A:203.0.113.90")
    answer(conn, BASE - 500, "b.example", "A:203.0.113.91")
    answer(conn, BASE - 400, "c.other", "A:203.0.113.91")  # a second service on the same address
    flow(conn, BASE, "203.0.113.90", 1000, 5000, dport=123, proto="udp")  # one service: named by its answers
    flow(conn, BASE + 1, "203.0.113.91", 2000, 1000)  # two services: shared, named nothing
    flow(conn, BASE + 2, "192.0.2.92", 3000, 1000)  # no answer at all
    flow(conn, BASE + 3, "198.51.100.93", 4000, 9000, sport=40100)  # its own hello
    hello(conn, BASE + 3.5, "198.51.100.93", "own.example", sport=40100)
    flow(conn, BASE + 4, "10.10.10.1", 99999, 99999, dport=53, proto="udp")  # the gateway: left out
    conn.commit()
    named = namebound.name_flows(conn, A, B, "10.10.10.1")
    assert named["bytes_up"] == {"hello": 4000, "dns": 1000, "shared": 2000, "unnamed": 3000, "unassessed": 0}
    assert named["conns"] == {"hello": 1, "dns": 1, "shared": 1, "unnamed": 1, "unassessed": 0}
    assert named["dns_names"] == [{"name": "a.example", "bytes": 6000}]
    assert namebound.named_share(named) == (4000 + 1000) / 10000


def test_a_flow_before_the_coverage_is_not_assessed_and_the_share_is_withheld(tmp_path):
    conn = store(tmp_path, since=BASE - 3600)
    flow(conn, BASE, "192.0.2.92", 3000, 1000)
    conn.commit()
    named = namebound.name_flows(conn, A, B, "10.10.10.1")
    assert named["bytes_up"]["unassessed"] == 3000 and namebound.named_share(named) is None
    assert namebound.named_share(None) is None
    assert namebound.named_share({"bytes_up": {"hello": 0}}) is None


# ---- DoH-shaped ------------------------------------------------------------------------------------------
def test_a_long_connection_of_small_packets_both_ways_is_doh_shaped(tmp_path):
    conn = store(tmp_path)
    answer(conn, BASE - 60, "resolver.example", "A:203.0.113.99")
    answer(conn, BASE - 30, "resolver.example", "A:0.0.0.0", blocked=1)
    # 20 minutes, 900 packets each way of about 150 bytes: the shape
    flow(conn, BASE, "203.0.113.99", 135000, 140000, pkts_up=900, pkts_down=900, end=BASE + 1200)
    flow(conn, BASE, "203.0.113.98", 135000, 140000, pkts_up=900, pkts_down=900, end=BASE + 1200, sport=40200)
    hello(conn, BASE + 0.5, "203.0.113.98", "push.example", sport=40200)
    flow(
        conn, BASE, "203.0.113.97", 9000000, 140000, pkts_up=900, pkts_down=900, end=BASE + 1200, sport=40300
    )
    flow(conn, BASE, "203.0.113.96", 135000, 140000, pkts_up=900, pkts_down=900, end=BASE + 500, sport=40400)
    flow(conn, BASE, "203.0.113.95", 13500, 14000, pkts_up=90, pkts_down=90, end=BASE + 1200, sport=40500)
    conn.commit()
    got = namebound.doh_shaped(conn, A, B, "10.10.10.1")
    assert [(e["name"], e["by_dns"], e["dst"], e["minutes"], e["blocked"]) for e in got] == [
        ("push.example", False, "203.0.113.98", 20, False),
        ("resolver.example", True, "203.0.113.99", 20, True),
    ]
    assert got[0]["per_packet_up"] == 150
