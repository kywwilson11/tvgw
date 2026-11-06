"""(ntp) The count of the clock servers the TV sends NTP to (design decision 17, its note of 2026-11-05).

tvgw-apply keeps `inet tvgw_ntp`: one rule that counts the TV's UDP 123 and updates a dynamic set with a
counter per address (tests/unit/test_apply.py holds the script; tests/virtual/test_virtual_ntp.py the
kernel). `tvgw verify --record` stores the rule's total and one series per address; the brief reads the
series into one line. Everything here runs on listings and rows written by hand: no nft, no kernel."""

import io
import json

import pytest
from conftest import NOW
from test_verify import S, gateway, resolver

from tvgw import analyst, cli, db, queries, verify

T0 = 1792990800.0  # 2026-10-26 00:00 CDT, the start of the fixtures' day (conftest.NOW is 10:00)
DAY = ("2026-10-26", T0, T0 + 86400)


def listing(elements: list[dict], rule_packets: int = 0) -> str:
    """`nft -j list table inet tvgw_ntp` as nft 1.1 prints it: the table, the set with its elements,
    the chain, and the rule with its total."""
    rule_expr = [
        {"match": {"op": "==", "left": {"meta": {"key": "iifname"}}, "right": "eth0"}},
        {"counter": {"packets": rule_packets, "bytes": 76 * rule_packets}},
        {
            "set": {
                "op": "update",
                "elem": {"payload": {"protocol": "ip", "field": "daddr"}},
                "set": "@ntp4",
                "stmt": [{"counter": {"packets": 0, "bytes": 0}}],
            }
        },
    ]
    return json.dumps(
        {
            "nftables": [
                {"metainfo": {"version": "1.1.3", "json_schema_version": 1}},
                {"table": {"family": "inet", "name": "tvgw_ntp", "handle": 9}},
                {
                    "set": {
                        "family": "inet",
                        "name": "ntp4",
                        "table": "tvgw_ntp",
                        "type": "ipv4_addr",
                        "handle": 1,
                        "size": 1024,
                        "flags": ["timeout", "dynamic"],
                        "timeout": 86400,
                        **({"elem": elements} if elements else {}),
                    }
                },
                {"chain": {"family": "inet", "table": "tvgw_ntp", "name": "forward", "handle": 2}},
                {
                    "rule": {
                        "family": "inet",
                        "table": "tvgw_ntp",
                        "chain": "forward",
                        "handle": 3,
                        "comment": queries.NTP_RULE,
                        "expr": rule_expr,
                    }
                },
            ]
        }
    )


def elem(addr: str, packets: int) -> dict:
    return {
        "elem": {
            "val": addr,
            "timeout": 86400,
            "expires": 86000,
            "counter": {"packets": packets, "bytes": 76 * packets},
        }
    }


# ---- verify reads the listing ----------------------------------------------------------------------


def test_each_element_of_the_set_is_a_series_of_its_own_in_address_order():
    text = listing([elem("203.0.113.40", 3), elem("198.51.100.9", 12), elem("203.0.113.5", 1)], 16)
    assert verify.ntp_counters(text) == [
        ("ntp: 198.51.100.9", 12, 912),
        ("ntp: 203.0.113.5", 1, 76),
        ("ntp: 203.0.113.40", 3, 228),
    ]
    # the rule's own total is an ordinary counted rule, read by the same parser as every table's
    assert verify.counters_from_table(text) == [(queries.NTP_RULE, 16, 1216)]


@pytest.mark.parametrize(
    "bad",
    [
        {"elem": {"val": "203.0.113.5"}},  # no counter: nothing to store
        "203.0.113.5",  # a bare value, as nft prints an element with no statements
        {"elem": {"val": "not-an-address", "counter": {"packets": 1, "bytes": 1}}},
        {"elem": {"val": "2001:db8::1", "counter": {"packets": 1, "bytes": 1}}},  # the set is IPv4
        {"elem": {"val": {"prefix": {"addr": "203.0.113.0", "len": 24}}, "counter": {"packets": 1}}},
        {"elem": {"val": "203.0.113.6", "counter": {"packets": "many", "bytes": 1}}},
    ],
)
def test_an_element_that_is_not_an_address_with_a_counter_gives_nothing(bad):
    assert verify.ntp_counters(listing([bad, elem("203.0.113.7", 2)], 2)) == [("ntp: 203.0.113.7", 2, 152)]


@pytest.mark.parametrize("text", ["", "not json", json.dumps({"nftables": []}), listing([], 0)])
def test_a_missing_or_empty_table_gives_no_series(text):
    assert verify.ntp_counters(text) == []


def test_verify_stores_the_total_and_each_server_beside_the_other_counters(lg, tmp_path):
    ntp = listing([elem("203.0.113.5", 4), elem("198.51.100.9", 1)], 5)
    r = verify.check(
        S, lg, **gateway({("nft", "-j", "list", "table", "inet", "tvgw_ntp"): ntp}), resolve=resolver()
    )
    assert r.ok, r.failures  # the count is no check: nothing about it can fail a run
    tail = r.counters[-3:]
    assert tail == [(queries.NTP_RULE, 5, 380), ("ntp: 198.51.100.9", 1, 76), ("ntp: 203.0.113.5", 4, 304)]
    conn = db.connect(str(tmp_path / "v.db"))
    verify.record(conn, r)
    rows = conn.execute(
        "SELECT rule, packets FROM fw_counters WHERE rule=? OR rule LIKE 'ntp: %' ORDER BY rule",
        (queries.NTP_RULE,),
    ).fetchall()
    assert rows == [(queries.NTP_RULE, 5), ("ntp: 198.51.100.9", 1), ("ntp: 203.0.113.5", 4)]
    # a gateway without the table (an older apply, a kernel that refused it) stores neither
    bare = verify.check(S, lg, **gateway(), resolve=resolver())
    assert not [c for c in bare.counters if c[0] == queries.NTP_RULE or c[0].startswith("ntp: ")]


# ---- the brief reads the series ---------------------------------------------------------------------


def snapshot(conn, t: float, servers: dict[str, int], rule: int | None = 0) -> None:
    """One `verify --record` snapshot of the NTP count at `t`: the rule's row (None: the table was not
    listed) and a row per address."""
    rows = [] if rule is None else [(t, queries.NTP_RULE, rule, 0)]
    rows += [(t, f"ntp: {dst}", n, 0) for dst, n in servers.items()]
    conn.executemany("INSERT INTO fw_counters(t, rule, packets, bytes) VALUES (?,?,?,?)", rows)


@pytest.fixture()
def store(tmp_path):
    c = db.connect(str(tmp_path / "n.db"))
    yield c
    c.close()


def test_steps_are_each_servers_increase_and_a_new_server_counts_whole(store):
    snapshot(store, T0 - 600, {"203.0.113.5": 10})  # the baseline, before the window
    snapshot(store, T0 + 600, {"203.0.113.5": 14})
    snapshot(store, T0 + 1200, {"203.0.113.5": 15, "198.51.100.9": 2})  # new since: both count
    out = queries.ntp_servers(store, T0, T0 + 86400)
    assert out["addresses"] == 2 and out["requests"] == 7
    assert [(x["dst"], x["requests"]) for x in out["servers"]] == [("203.0.113.5", 5), ("198.51.100.9", 2)]


def test_a_server_that_left_the_set_and_came_back_counts_from_zero(store):
    """An address leaves the set a day after its last request; back, its counter starts again. A
    snapshot of the table without it is how the reader knows, even when the new count is the higher."""
    snapshot(store, T0 - 600, {"203.0.113.5": 3})
    snapshot(store, T0 + 600, {})  # listed, and the address had expired
    snapshot(store, T0 + 1200, {"203.0.113.5": 5})  # back: five new requests, not two
    snapshot(store, T0 + 1800, {"203.0.113.5": 1})  # and a lower count is a return too
    out = queries.ntp_servers(store, T0, T0 + 86400)
    assert out["servers"][0]["requests"] == 6 and out["requests"] == 6


def test_a_reapply_keeps_the_counts_and_its_listings_are_no_reset(store):
    """tvgw-apply flushes the chain, which zeroes the rule's total, and keeps the set; its reload
    listings hold neither the rule nor the servers, so they are no snapshot of the count."""
    snapshot(store, T0 - 600, {"203.0.113.5": 8}, rule=8)
    store.execute("INSERT INTO fw_counters(t, rule, packets, bytes) VALUES (?, 'DoT/DoQ', 3, 0)", (T0 + 300,))
    snapshot(store, T0 + 600, {"203.0.113.5": 9}, rule=1)  # the total restarted; the server did not
    out = queries.ntp_servers(store, T0, T0 + 86400)
    assert out["requests"] == 1


def test_without_a_snapshot_before_the_window_its_first_one_is_the_baseline(store):
    """Days nobody recorded are not credited to the window after them, as fw_activity does it."""
    snapshot(store, T0 - 7200, {"203.0.113.5": 1})  # older than FW_BASELINE before the window
    snapshot(store, T0 + 600, {"203.0.113.5": 40})
    snapshot(store, T0 + 1200, {"203.0.113.5": 42, "198.51.100.9": 1})
    out = queries.ntp_servers(store, T0, T0 + 86400)
    assert [(x["dst"], x["requests"]) for x in out["servers"]] == [("203.0.113.5", 2), ("198.51.100.9", 1)]


def test_a_snapshot_without_the_rule_is_not_the_table_listed(store):
    """A row of the series alone (no rule row at its time) says nothing about which addresses expired,
    so it is not read; the next real snapshot steps from the last real one."""
    snapshot(store, T0 - 600, {"203.0.113.5": 2})
    snapshot(store, T0 + 600, {"203.0.113.5": 7}, rule=None)
    snapshot(store, T0 + 1200, {"203.0.113.5": 9})
    assert queries.ntp_servers(store, T0, T0 + 86400)["requests"] == 7


def test_no_ntp_in_the_window_is_no_servers(store):
    snapshot(store, T0 - 600, {"203.0.113.5": 2})
    snapshot(store, T0 + 600, {"203.0.113.5": 2})
    assert queries.ntp_servers(store, T0, T0 + 86400) == {"addresses": 0, "requests": 0, "servers": []}
    assert queries.ntp_servers(store, T0 + 86400, T0 + 2 * 86400)["servers"] == []  # nothing recorded


def test_each_server_is_named_by_the_answers_of_the_week_before(store):
    store.executemany(
        "INSERT INTO dns(t, qname, blocked, answers) VALUES (?, ?, 0, ?)",
        [
            (T0 - 3 * 86400, "time.example.com", "A:203.0.113.5,A:203.0.113.6"),
            (T0 + 100, "pool.example.net", "CNAME:x.example.net,A:203.0.113.5"),
            (T0 - 8 * 86400, "old.example.org", "A:198.51.100.9"),  # older than KNOWN_DAYS
            (T0 + 200, "near.example.org", "A:198.51.100.90"),  # a longer address, not this one
        ],
    )
    snapshot(store, T0 - 600, {})
    snapshot(store, T0 + 600, {"203.0.113.5": 3, "198.51.100.9": 1})
    servers = queries.ntp_servers(store, T0, T0 + 86400)["servers"]
    assert servers == [
        {"dst": "203.0.113.5", "requests": 3, "names": ["pool.example.net", "time.example.com"]},
        {"dst": "198.51.100.9", "requests": 1, "names": []},
    ]


def test_the_brief_line_names_the_top_servers_and_how_many_more():
    ntp = {
        "addresses": 4,
        "requests": 103,
        "servers": [
            {"dst": "203.0.113.5", "requests": 90, "names": ["pool.example.net", "time.example.com"]},
            {"dst": "198.51.100.9", "requests": 10, "names": []},
            {"dst": "192.0.2.7", "requests": 2, "names": ["ntp.example.org"]},
            {"dst": "192.0.2.8", "requests": 1, "names": []},
        ],
    }
    assert cli.ntp_line(ntp) == (
        "Clock servers (NTP): 103 requests to 4 addresses: 203.0.113.5 (pool.example.net +1) 90,"
        " 198.51.100.9 (no lookup) 10, 192.0.2.7 (ntp.example.org) 2, 1 more"
    )
    one = {"addresses": 1, "requests": 3, "servers": [ntp["servers"][2] | {"requests": 3}]}
    assert (
        cli.ntp_line(one) == "Clock servers (NTP): 3 requests to 1 addresses: 192.0.2.7 (ntp.example.org) 3"
    )
    for nothing in (None, {}, {"addresses": 0, "requests": 0, "servers": []}):
        assert cli.ntp_line(nothing) is None


def test_with_no_ntp_the_brief_prints_what_it_printed_before(conn, lg):
    """The count adds a line only when the TV sent NTP: without it, the text is what it was before the
    count existed, line for line."""
    o = queries.brief(conn, DAY[0], lg, now=NOW + 3600)
    assert o["ntp"] == {"addresses": 0, "requests": 0, "servers": []}
    with_key, without = io.StringIO(), io.StringIO()
    cli.render_brief(o, with_key)
    cli.render_brief({k: v for k, v in o.items() if k != "ntp"}, without)
    assert with_key.getvalue() == without.getvalue()
    assert "Clock servers" not in with_key.getvalue()


def test_the_count_reaches_the_brief_and_stays_out_of_the_firewall_evidence(conn, lg, gateway):
    """The filter accepts NTP by design, so the count is no part of Firewall held, the firewall's
    activity or the analyst's pack: it has its line and its key."""
    for t, n in ((T0 + 600, 0), (T0 + 1200, 4)):
        snapshot(conn, t, {"203.0.113.5": n}, rule=n)
    conn.executemany(
        "INSERT INTO fw_counters(t, rule, packets, bytes) VALUES (?,?,?,0)",
        [(T0 + 600, "DoT/DoQ", 0), (T0 + 1200, "DoT/DoQ", 4)],
    )
    conn.commit()
    o = queries.brief(conn, DAY[0], lg, now=NOW + 3600)
    assert o["ntp"]["requests"] == 4 and o["ntp"]["servers"][0]["dst"] == "203.0.113.5"
    assert o["firewall"]["activity"] == [{"rule": "DoT/DoQ", "packets": 4}]
    buf = io.StringIO()
    cli.render_brief(o, buf)
    text = buf.getvalue()
    assert "Clock servers (NTP): 4 requests to 1 addresses: 203.0.113.5 (no lookup) 4" in text
    assert "Firewall held: DoT/DoQ 4;" in text and "NTP from the TV" not in text
    p = analyst.pack(conn, DAY[1], DAY[2], DAY[0], lg, gateway)
    assert p["firewall"]["activity"] == [{"rule": "DoT/DoQ", "packets": 4}]
    assert "ntp: " not in str(p) and queries.NTP_RULE not in str(p)


@pytest.fixture()
def conn(gateway, lg):
    from conftest import fake_extract, fake_oddport

    from tvgw import ingest

    ingest.run(
        gateway, lg, extract=fake_extract, oddport_lines=fake_oddport, gate_lines=lambda since: [], lock=False
    )
    c = db.connect(gateway.db_path)
    yield c
    c.close()
