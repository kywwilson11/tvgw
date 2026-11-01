"""Schema 8 (extractor): the migration of an older store, what ingest writes for named, nameless,
partial and QUIC hellos, and the queries that read them. The naming of flows must not change."""

import sqlite3

import pytest
from conftest import TV

from tvgw import db, ingest, queries
from tvgw.tshark import Syn, TlsHello

T = 1793020100.0
JA4_A = "t13d1516h2_8daaf6152771_02713d6af862"
JA4_B = "t12i050500_80e8f3f87ec2_aa6c610322f9"


def test_a_schema_7_store_gains_the_new_columns_table_and_index(tmp_path):
    path = tmp_path / "old.db"
    c = sqlite3.connect(path)
    c.execute(
        "CREATE TABLE tls(id INTEGER PRIMARY KEY, t REAL NOT NULL, dst TEXT, dport INTEGER, sport INTEGER,"
        " sni TEXT NOT NULL, ech INTEGER)"
    )
    c.execute(
        "INSERT INTO tls(t,dst,dport,sport,sni,ech) VALUES (1, '203.0.113.1', 443, 4, 'old.example', 0)"
    )
    c.execute("CREATE TABLE meta(key TEXT PRIMARY KEY, value TEXT)")
    c.execute("INSERT INTO meta VALUES ('schema', '7')")
    c.commit()
    c.close()
    conn = db.connect(str(path))
    cols = [r[1] for r in conn.execute("PRAGMA table_info(tls)")]
    assert cols[-3:] == ["ja4", "transport", "partial"]
    assert conn.execute("SELECT sni, ja4, transport, partial FROM tls").fetchall() == [
        ("old.example", None, None, None)
    ]
    assert {r[1] for r in conn.execute("PRAGMA table_info(tls_noname)")} == {
        "id",
        "t",
        "dst",
        "dport",
        "sport",
        "ja4",
        "transport",
        "partial",
    }
    indexes = {r[0] for r in conn.execute("SELECT name FROM sqlite_master WHERE type='index'")}
    assert {"tls_ja4", "tls_noname_t"} <= indexes
    assert db.get_meta(conn, "schema") == "8" == str(db.SCHEMA_VERSION)
    conn.close()
    db.connect(str(path)).close()  # a second open of a migrated store is a no-op


def test_the_ja4_index_serves_the_stack_lookup(tmp_path):
    from conftest import plan

    conn = db.connect(str(tmp_path / "s.db"))
    assert "tls_ja4" in plan(conn, "SELECT sni FROM tls WHERE ja4 = 'x' AND t >= 0 AND t < 1")


def hellos():
    return [
        TlsHello(T, TV, 40001, "203.0.113.1", 443, "www.example.com", True, JA4_A, "tcp", False),
        TlsHello(T + 1, TV, 40002, "203.0.113.2", 443, "early.example.com", False, "", "tcp", True),
        TlsHello(T + 2, TV, 50003, "203.0.113.3", 443, "video.example.com", False, "q13d0311h3_x_y", "quic"),
        TlsHello(T + 3, TV, 40004, "198.51.100.4", 443, "", False, JA4_B, "tcp", False),
        TlsHello(T + 4, TV, 40005, "198.51.100.5", 443, "", False, "", "tcp", True),
        TlsHello(T + 5, "10.10.10.1", 40006, "198.51.100.6", 443, "", False, JA4_B),  # not the TV
    ]


def test_ingest_writes_named_hellos_to_tls_and_nameless_ones_to_tls_noname(gateway, lg):
    conn = db.connect(gateway.db_path)
    warnings: list[str] = []
    assert ingest.ingest_pcaps(conn, gateway, lambda p: hellos(), warnings.append) == (1, 3, 0, 0)
    assert conn.execute("SELECT sni, ech, ja4, transport, partial FROM tls ORDER BY t").fetchall() == [
        ("www.example.com", 1, JA4_A, "tcp", 0),
        ("early.example.com", 0, "", "tcp", 1),
        ("video.example.com", 0, "q13d0311h3_x_y", "quic", 0),
    ]
    assert conn.execute("SELECT dst, ja4, transport, partial FROM tls_noname ORDER BY t").fetchall() == [
        ("198.51.100.4", JA4_B, "tcp", 0),
        ("198.51.100.5", "", "tcp", 1),
    ]
    # the per-file count is the named hellos, as before schema 8: before/after comparisons hold
    assert conn.execute("SELECT tls_rows FROM pcaps_done").fetchone() == (3,)
    assert ingest.refresh_hosts(conn, lg) == 3  # a hello without a name names no host
    assert warnings == []


@pytest.mark.parametrize(("nameless", "warned"), [(2, False), (0, True)])
def test_attempts_to_443_with_only_nameless_hellos_are_not_an_extraction_fault(gateway, lg, nameless, warned):
    """The SYN check asks whether tshark found any hello at all: hellos without a name were found,
    so twenty attempts to :443 with only those is no fault; with no hello at all it still warns."""
    conn = db.connect(gateway.db_path)
    rows = [Syn(T + i, TV, 40000 + i, "203.0.113.10", 443) for i in range(ingest.SYN_CHECK)]
    rows += [
        TlsHello(T + 30 + i, TV, 40000 + i, "203.0.113.10", 443, "", False, JA4_B) for i in range(nameless)
    ]
    warnings: list[str] = []
    ingest.ingest_pcaps(conn, gateway, lambda p: rows, warnings.append)
    assert conn.execute("SELECT tls_rows, syn443_rows FROM pcaps_done").fetchone() == (0, ingest.SYN_CHECK)
    assert conn.execute("SELECT COUNT(*) FROM tls_noname").fetchone() == (nameless,)
    assert [w for w in warnings if "no TLS hello" in w] == (
        [
            f"tv-20261026-0800.pcap: {ingest.SYN_CHECK} connection attempts to :443 but no TLS hello:"
            " check the capture filter and tshark"
        ]
        if warned
        else []
    )


def test_prune_removes_old_nameless_hellos(tmp_path):
    conn = db.connect(str(tmp_path / "p.db"))
    conn.executemany("INSERT INTO tls_noname(t, dst) VALUES (?, '198.51.100.4')", [(T - 40 * 86400,), (T,)])
    ingest.prune(conn, 30, now=T + 60)
    assert conn.execute("SELECT t FROM tls_noname").fetchall() == [(T,)]


def test_tls_noname_groups_by_address_and_fingerprint_and_names_the_stack(tmp_path):
    conn = db.connect(str(tmp_path / "q.db"))
    conn.executemany(
        "INSERT INTO tls(t,dst,dport,sport,sni,ech,ja4,transport,partial) VALUES (?,?,443,?,?,0,?,'tcp',0)",
        [
            (T - 3 * 86400, "203.0.113.1", 1, "a.example", JA4_B),  # the week before counts
            (T, "203.0.113.1", 2, "a.example", JA4_B),
            (T, "203.0.113.2", 3, "b.example", JA4_B),
            (T, "203.0.113.3", 4, "c.example", JA4_A),
            (T - 9 * 86400, "203.0.113.4", 5, "too-old.example", JA4_B),
        ],
    )
    conn.executemany(
        "INSERT INTO tls_noname(t,dst,dport,sport,ja4,transport,partial) VALUES (?,?,443,?,?,?,?)",
        [
            (T + 10, "198.51.100.4", 1, JA4_B, "tcp", 0),
            (T + 20, "198.51.100.4", 2, JA4_B, "tcp", 0),
            (T + 30, "198.51.100.5", 3, "", "tcp", 1),
            (T + 40, "198.51.100.6", 4, None, None, None),  # every column a later extractor may leave out
        ],
    )
    out = queries.tls_noname(conn, T - 60, T + 3600)
    assert out == [
        {
            "dst": "198.51.100.4",
            "dport": 443,
            "transport": "tcp",
            "ja4": JA4_B,
            "n": 2,
            "partial": 0,
            "first": T + 10,
            "last": T + 20,
            "stack_names": ["a.example", "b.example"],
        },
        {
            "dst": "198.51.100.5",
            "dport": 443,
            "transport": "tcp",
            "ja4": "",
            "n": 1,
            "partial": 1,
            "first": T + 30,
            "last": T + 30,
            "stack_names": [],
        },
        {
            "dst": "198.51.100.6",
            "dport": 443,
            "transport": "tcp",
            "ja4": "",
            "n": 1,
            "partial": 0,
            "first": T + 40,
            "last": T + 40,
            "stack_names": [],
        },
    ]
    assert queries.tls_noname(conn, T + 3600, T + 7200) == []


def test_a_nameless_hello_on_a_named_connection_does_not_change_its_name(tmp_path):
    """FLOW_NAME reads `tls` alone; a hello without SNI lives in tls_noname and cannot shadow it."""
    conn = db.connect(str(tmp_path / "f.db"))
    conn.execute(
        "INSERT INTO tls(t,dst,dport,sport,sni) VALUES (?, '203.0.113.1', 443, 4000, 'named.example')", (T,)
    )
    conn.execute("INSERT INTO tls_noname(t,dst,dport,sport) VALUES (?, '203.0.113.1', 443, 4000)", (T + 1,))
    conn.execute(
        "INSERT INTO flows(t_start,t_end,proto,dst,dport,sport) VALUES (?, ?, 'tcp', '203.0.113.1', 443, 4000)",
        (T, T + 60),
    )
    (name,) = conn.execute(f"SELECT {queries.FLOW_NAME} FROM flows f").fetchone()
    assert name == "named.example"


def test_a_known_ech_public_name_is_real_ech_even_when_the_tv_looked_it_up(tmp_path):
    """The lookup test alone would count it as GREASE: a stack that fetches ECH configs may well
    resolve the provider's public name too."""
    conn = db.connect(str(tmp_path / "e.db"))
    conn.execute("INSERT INTO dns(t,qname,blocked) VALUES (?, 'cloudflare-ech.com', 0)", (T - 60,))
    conn.execute(
        "INSERT INTO tls(t,dst,dport,sport,sni,ech) VALUES (?, '203.0.113.9', 443, 1, 'cloudflare-ech.com', 1)",
        (T,),
    )
    seen = queries.ech_seen(conn, T - 3600, T + 3600)
    assert (seen["count"], seen["first"], seen["grease"], seen["outer_names"]) == (
        1,
        T,
        0,
        ["cloudflare-ech.com"],
    )
    assert "cloudflare-ech.com" in queries.ECH_PUBLIC_NAMES
