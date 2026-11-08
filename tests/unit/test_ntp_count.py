"""(ntp) The count of the clock servers the TV sends NTP to (design decision 17, its note of 2026-11-05).

tvgw-apply keeps `inet tvgw_ntp`: one rule that counts the TV's UDP 123 and updates a dynamic set with a
counter per address (tests/unit/test_apply.py holds the script; tests/virtual/test_virtual_ntp.py the
kernel). `tvgw verify --record` stores the rule's total, a row saying how many addresses the set holds,
and the most requested addresses with their counts and expiries; the brief reads them into one line.
Everything here runs on listings and rows written by hand: no nft, no kernel."""

import io
import json

import pytest
from conftest import NOW
from test_verify import S, gateway, resolver

from tvgw import analyst, cli, db, queries, verify

T0 = 1792990800.0  # 2026-10-26 00:00 CDT, the start of the fixtures' day (conftest.NOW is 10:00)
DAY = ("2026-10-26", T0, T0 + 86400)
TIMEOUT = 864000  # the set's timeout, 10 days, as tvgw-apply writes it


def listing(elements: list, rule_packets: int = 0, size: int = 1024) -> str:
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
                        "size": size,
                        "flags": ["timeout", "dynamic"],
                        "timeout": TIMEOUT,
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


def elem(addr: str, packets: int, expires: int | None = 800000) -> dict:
    e = {"val": addr, "counter": {"packets": packets, "bytes": 76 * packets}}
    if expires is not None:
        e["expires"] = expires
    return {"elem": e}


# ---- verify reads the listing ----------------------------------------------------------------------


def test_the_set_row_first_then_the_most_recently_requested_addresses_with_their_expiry():
    text = listing([elem("203.0.113.40", 3), elem("198.51.100.9", 12, 700), elem("203.0.113.5", 4)], 19)
    assert verify.ntp_counters(text) == [
        (queries.NTP_SET_ROW, 3, 1024),  # three addresses held, in a set of 1024
        ("ntp: 203.0.113.5", 4, 800000),  # the latest expiry first (the latest request), then by count
        ("ntp: 203.0.113.40", 3, 800000),
        ("ntp: 198.51.100.9", 12, 700),  # most requests of all, and the oldest last request
    ]
    # the rule's own total is an ordinary counted rule, read by the same parser as every table's
    assert verify.counters_from_table(text) == [(queries.NTP_RULE, 19, 1444)]


def test_todays_servers_are_stored_before_a_pools_old_addresses_with_more_requests():
    """The review's D: kept 10 days, a rotating pool's old addresses have the most lifetime requests;
    stored by count they would crowd out the addresses the TV uses today. The stored ones are those
    requested most recently, which `update`'s fresh timeout at each request makes the latest expiries."""
    old = [elem(f"198.51.100.{i}", 1000 + i, 100000 + i) for i in range(1, 41)]  # days old, much used
    today = [elem(f"203.0.113.{i}", 1, 863000 + i) for i in range(1, 4)]  # asked once each, minutes ago
    rows = verify.ntp_counters(listing(old + today))
    assert rows[0] == (queries.NTP_SET_ROW, 43, 1024)
    assert [r[0] for r in rows[1:4]] == ["ntp: 203.0.113.3", "ntp: 203.0.113.2", "ntp: 203.0.113.1"]
    assert len(rows) == 1 + queries.NTP_STORED


def test_a_snapshot_stores_the_most_requested_addresses_only_and_says_how_many_the_set_holds():
    """A TV spraying NTP at new addresses, broken or hostile, fills the set (1024); stored whole that is
    about 148,000 rows a day. A snapshot keeps NTP_STORED rows of addresses and the set row."""
    many = [elem(f"198.51.100.{i}", i) for i in range(1, 101)]
    rows = verify.ntp_counters(listing(many, sum(range(1, 101))))
    assert rows[0] == (queries.NTP_SET_ROW, 100, 1024)
    assert len(rows) == 1 + queries.NTP_STORED
    assert [r[1] for r in rows[1:]] == list(range(100, 100 - queries.NTP_STORED, -1))
    assert verify.ntp_counters(listing(many), stored=2)[1:] == [
        ("ntp: 198.51.100.100", 100, 800000),
        ("ntp: 198.51.100.99", 99, 800000),
    ]


@pytest.mark.parametrize(
    "bad",
    [
        {"elem": {"val": "203.0.113.5"}},  # no counter: held, not stored
        "203.0.113.5",  # a bare value, as nft prints an element with no statements
        {"elem": {"val": "not-an-address", "counter": {"packets": 1, "bytes": 1}}},
        {"elem": {"val": "2001:db8::1", "counter": {"packets": 1, "bytes": 1}}},  # the set is IPv4
        {"elem": {"val": {"prefix": {"addr": "203.0.113.0", "len": 24}}, "counter": {"packets": 1}}},
        {"elem": {"val": "203.0.113.6", "counter": {"packets": "many", "bytes": 1}}},
    ],
)
def test_an_element_that_is_not_an_address_with_a_counter_is_not_stored(bad):
    assert verify.ntp_counters(listing([bad, elem("203.0.113.7", 2)], 2)) == [
        (queries.NTP_SET_ROW, 2, 1024),
        ("ntp: 203.0.113.7", 2, 800000),
    ]


def test_an_element_without_an_expiry_is_stored_with_minus_one():
    assert verify.ntp_counters(listing([elem("203.0.113.7", 2, None)]))[1] == ("ntp: 203.0.113.7", 2, -1)


@pytest.mark.parametrize("text", ["", "not json", json.dumps({"nftables": []})])
def test_a_missing_table_gives_no_rows(text):
    assert verify.ntp_counters(text) == []


def test_an_empty_set_is_still_a_snapshot():
    assert verify.ntp_counters(listing([], 0)) == [(queries.NTP_SET_ROW, 0, 1024)]


def test_verify_stores_the_total_the_set_and_each_server_beside_the_other_counters(lg, tmp_path):
    ntp = listing([elem("203.0.113.5", 4), elem("198.51.100.9", 1)], 5)
    r = verify.check(
        S, lg, **gateway({("nft", "-j", "list", "table", "inet", "tvgw_ntp"): ntp}), resolve=resolver()
    )
    assert r.ok, r.failures  # the count is no check: nothing about it can fail a run
    assert r.counters[-4:] == [
        (queries.NTP_RULE, 5, 380),
        (queries.NTP_SET_ROW, 2, 1024),
        ("ntp: 203.0.113.5", 4, 800000),
        ("ntp: 198.51.100.9", 1, 800000),
    ]
    conn = db.connect(str(tmp_path / "v.db"))
    verify.record(conn, r)
    rows = conn.execute(
        "SELECT rule, packets, bytes FROM fw_counters WHERE rule=? OR rule LIKE 'ntp: %' ORDER BY rowid",
        (queries.NTP_RULE,),
    ).fetchall()
    assert rows == [
        (queries.NTP_RULE, 5, 380),
        (queries.NTP_SET_ROW, 2, 1024),
        ("ntp: 203.0.113.5", 4, 800000),
        ("ntp: 198.51.100.9", 1, 800000),
    ]
    # a gateway without the table (an older apply, a kernel that refused it) stores none of them
    bare = verify.check(S, lg, **gateway(), resolve=resolver())
    assert not [c for c in bare.counters if c[0] == queries.NTP_RULE or c[0].startswith("ntp: ")]


# ---- the brief reads the rows -----------------------------------------------------------------------


def snapshot(
    conn,
    t: float,
    servers: dict,
    held: int | None = None,
    size: int = 1024,
    rule: int | None = None,
) -> None:
    """One `verify --record` snapshot of the NTP count at `t`: the set row (how many it holds, `held`,
    by default the addresses given), each address's requests and seconds to expiry (an int alone has
    800000 left), and the rule's total when `rule` is given."""
    rows = [] if rule is None else [(t, queries.NTP_RULE, rule, 0)]
    rows.append((t, queries.NTP_SET_ROW, len(servers) if held is None else held, size))
    for dst, value in servers.items():
        count, expires = value if isinstance(value, tuple) else (value, 800000)
        rows.append((t, f"ntp: {dst}", count, expires))
    conn.executemany("INSERT INTO fw_counters(t, rule, packets, bytes) VALUES (?,?,?,?)", rows)


def total_row(conn, t: float, packets: int) -> None:
    conn.execute(
        "INSERT INTO fw_counters(t, rule, packets, bytes) VALUES (?, ?, ?, 0)", (t, queries.NTP_RULE, packets)
    )


@pytest.fixture()
def store(tmp_path):
    c = db.connect(str(tmp_path / "n.db"))
    yield c
    c.close()


def requests(out: dict) -> list[tuple[str, int]]:
    return [(x["dst"], x["requests"]) for x in out["servers"]]


def test_steps_are_each_servers_increase_and_a_new_server_counts_whole(store):
    snapshot(store, T0 - 600, {"203.0.113.5": 10})  # the baseline, before the window
    snapshot(store, T0 + 600, {"203.0.113.5": 14})
    snapshot(store, T0 + 1200, {"203.0.113.5": 15, "198.51.100.9": 2})  # new since: both count
    out = queries.ntp_servers(store, T0, T0 + 86400)
    assert out["counted"] and out["addresses"] == 2 and out["requests"] == 7
    assert requests(out) == [("203.0.113.5", 5), ("198.51.100.9", 2)]


def test_a_tv_that_syncs_once_a_day_is_counted_every_day(store):
    """The review's case: an element that expires between two snapshots and comes back at the count it
    had (1, then 1) reads as no step from the counts alone. The expiry the snapshot before gave it says
    the element was gone by then, so the same count is a new element, and its request counts. (With
    the set's timeout of 10 days a daily sync never expires; this is the case the timeout cannot rule
    out, a request just past an expiry.)"""
    snapshot(store, T0 - 600, {"203.0.113.5": (1, 300)})  # due to expire at T0 - 300
    snapshot(store, T0 + 1200, {"203.0.113.5": (1, 86000)})  # back, made again by the day's one request
    snapshot(store, T0 + 43200, {"203.0.113.5": (1, 44000)})  # nothing since: its expiry is still ahead
    assert requests(queries.ntp_servers(store, T0, T0 + 86400)) == [("203.0.113.5", 1)]
    snapshot(store, T0 + 86400 - 600, {"203.0.113.5": (1, 1400)})  # the last snapshot of the day
    snapshot(store, T0 + 86400 + 1200, {"203.0.113.5": (1, 86000)})  # the next day, the same
    assert requests(queries.ntp_servers(store, T0 + 86400, T0 + 2 * 86400)) == [("203.0.113.5", 1)]
    assert queries.ntp_servers(store, T0, T0 + 2 * 86400)["requests"] == 2


def test_an_unused_address_near_its_expiry_is_no_request(store):
    """The review's A, as its probe made it: a snapshot's time is when verify began, the table is listed
    seconds later and nft rounds down, so the stored expiry is a few seconds early. The snapshot just
    before an abandoned address leaves then comes after that early expiry, with the address still there
    and its count unchanged. Its expiry has not moved, so no request reached it, and nothing counts."""
    snapshot(store, T0 - 600, {"203.0.113.5": (500, 900)}, rule=500)  # expires, by the store, at T0 + 300
    snapshot(store, T0 + 305, {"203.0.113.5": (500, 0)}, rule=500)  # still there 5 s past it: nft is later
    snapshot(store, T0 + 905, {}, rule=500)  # gone
    out = queries.ntp_servers(store, T0, T0 + 86400)
    assert (out["requests"], out["servers"]) == (0, [])
    assert cli.ntp_line(out) is None
    # and with no rule's row to check against, the expiry alone keeps it from counting
    store.execute("DELETE FROM fw_counters WHERE rule=?", (queries.NTP_RULE,))
    assert queries.ntp_servers(store, T0, T0 + 86400)["servers"] == []


def test_the_rules_total_bounds_what_the_addresses_add_up_to(store):
    """A step read wrong can never put more requests in the brief than the rule counted between the same
    snapshots: the addresses are scaled down to its total, each its share."""
    snapshot(store, T0 - 600, {"203.0.113.5": (10, -1), "198.51.100.9": (3, -1)}, rule=0)
    snapshot(store, T0 + 600, {"203.0.113.5": (2, -1), "198.51.100.9": (1, -1)}, rule=3)  # read as made again
    out = queries.ntp_servers(store, T0, T0 + 86400)
    assert out["requests"] == 3 and out["placed"] == 3 and out["unplaced"] == 0
    assert requests(out) == [("203.0.113.5", 2), ("198.51.100.9", 1)]


def test_a_reload_after_the_days_last_snapshot_is_the_next_days(store):
    """The review's C: tvgw-apply's listings either side of a reload are stored by the next verify run
    under the reload's own time; one in the day's last minutes falls after its last snapshot. The total is
    read between the snapshots the addresses are, so those requests count once, on the next day, and the
    first day says nothing of addresses the count did not keep."""
    day2 = T0 + 86400
    snapshot(store, T0 + 600, {"203.0.113.5": 0}, rule=0)
    snapshot(store, day2 - 600, {"203.0.113.5": 10}, rule=10)  # the day's last snapshot
    total_row(store, day2 - 120, 18)  # the apply's listing before its reload: 8 more since
    total_row(store, day2 - 119, 0)  # and after it
    snapshot(store, day2 + 600, {"203.0.113.5": 20}, rule=2)
    first = queries.ntp_servers(store, T0, day2)
    assert (first["requests"], first["placed"], first["unplaced"]) == (10, 10, 0)
    assert "did not keep" not in cli.ntp_line(first)
    second = queries.ntp_servers(store, day2, day2 + 86400)
    assert (second["requests"], second["placed"], second["unplaced"]) == (10, 10, 0)


def test_the_same_count_before_its_expiry_is_no_request(store):
    snapshot(store, T0 - 600, {"203.0.113.5": (3, 500000)})
    snapshot(store, T0 + 600, {"203.0.113.5": (3, 498800)})
    assert queries.ntp_servers(store, T0, T0 + 86400)["servers"] == []


def test_an_expiry_nft_did_not_give_falls_back_to_the_counts(store):
    snapshot(store, T0 - 600, {"203.0.113.5": (3, -1)})
    snapshot(store, T0 + 600, {"203.0.113.5": (3, -1)})
    snapshot(store, T0 + 1200, {"203.0.113.5": (4, -1)})
    assert requests(queries.ntp_servers(store, T0, T0 + 86400)) == [("203.0.113.5", 1)]


def test_a_server_that_left_the_set_and_came_back_counts_from_zero(store):
    """An address leaves the set ten days after its last request; back, its counter starts again. A
    whole snapshot of the set without it is how the reader knows, even when the new count is higher."""
    snapshot(store, T0 - 600, {"203.0.113.5": 3})
    snapshot(store, T0 + 600, {})  # listed whole, and the address had left
    snapshot(store, T0 + 1200, {"203.0.113.5": 5})  # back: five new requests, not two
    snapshot(store, T0 + 1800, {"203.0.113.5": 1})  # and a lower count is a return too
    out = queries.ntp_servers(store, T0, T0 + 86400)
    assert out["servers"][0]["requests"] == 6 and out["requests"] == 6


def test_an_address_a_truncated_snapshot_left_out_keeps_its_count(store):
    """With more addresses than a snapshot stores, one that drops out of the stored top and comes back
    steps from its last stored count, not from zero."""
    snapshot(store, T0 - 600, {"203.0.113.5": 10, "198.51.100.9": 3})
    snapshot(store, T0 + 600, {"203.0.113.5": 12}, held=40)  # 198.51.100.9 not stored, still held
    snapshot(store, T0 + 1200, {"203.0.113.5": 12, "198.51.100.9": 4}, held=40)
    assert requests(queries.ntp_servers(store, T0, T0 + 86400)) == [
        ("203.0.113.5", 2),
        ("198.51.100.9", 1),
    ]


def test_a_reapply_keeps_the_counts_and_the_rules_total_survives_through_its_listings(store):
    """tvgw-apply flushes the chain, which zeroes the rule's total, and keeps the set; its listings
    either side of the reload hold the rule's total and none of the set's rows, so they are no snapshot
    of the set, and the total's reset costs nothing."""
    snapshot(store, T0 - 600, {"203.0.113.5": 8}, rule=8)
    total_row(store, T0 + 300, 9)  # the apply's listing before its reload
    total_row(store, T0 + 301, 0)  # and after it
    snapshot(store, T0 + 600, {"203.0.113.5": 10}, rule=1)
    out = queries.ntp_servers(store, T0, T0 + 86400)
    assert (out["requests"], out["placed"], out["unplaced"]) == (2, 2, 0)


def test_without_a_snapshot_before_the_window_its_first_one_is_the_baseline(store):
    """Days nobody recorded are not credited to the window after them, as fw_activity does it."""
    snapshot(store, T0 - 7200, {"203.0.113.5": 1})  # older than FW_BASELINE before the window
    snapshot(store, T0 + 600, {"203.0.113.5": 40})
    snapshot(store, T0 + 1200, {"203.0.113.5": 42, "198.51.100.9": 1})
    out = queries.ntp_servers(store, T0, T0 + 86400)
    assert requests(out) == [("203.0.113.5", 2), ("198.51.100.9", 1)]


def test_rows_without_the_set_row_are_not_a_snapshot(store):
    """Address rows alone (no set row at their time) say nothing about which addresses left, so they are
    not read; the next real snapshot steps from the last real one."""
    snapshot(store, T0 - 600, {"203.0.113.5": 2})
    store.execute(
        "INSERT INTO fw_counters(t, rule, packets, bytes) VALUES (?, 'ntp: 203.0.113.5', 7, 0)", (T0 + 600,)
    )
    snapshot(store, T0 + 1200, {"203.0.113.5": 9})
    assert queries.ntp_servers(store, T0, T0 + 86400)["requests"] == 7


def test_requests_no_stored_address_accounts_for_are_said_and_a_full_set_is_named(store):
    snapshot(store, T0 - 600, {"203.0.113.5": 2}, rule=2, held=1024)
    snapshot(store, T0 + 600, {"203.0.113.5": 6}, rule=12, held=1024)  # 10 requests, 4 placed
    out = queries.ntp_servers(store, T0, T0 + 86400)
    assert (out["requests"], out["placed"], out["unplaced"], out["full"]) == (10, 4, 6, True)
    assert cli.ntp_line(out) == (
        "Clock servers (NTP): 10 requests to 1 address: 203.0.113.5 (no lookup) 4;"
        " 6 of them to addresses the count did not keep (its set is full)"
    )
    # and when no stored address took any request, the line says only that
    snapshot(store, T0 + 1200, {"203.0.113.5": 6}, rule=15, held=1024)
    later = queries.ntp_servers(store, T0 + 1000, T0 + 86400)
    assert cli.ntp_line(later) == (
        "Clock servers (NTP): 3 requests, 3 of them to addresses the count did not keep (its set is full)"
    )


def test_no_ntp_in_the_window_is_no_servers(store):
    snapshot(store, T0 - 600, {"203.0.113.5": 2})
    snapshot(store, T0 + 600, {"203.0.113.5": 2})
    out = queries.ntp_servers(store, T0, T0 + 86400)
    assert (out["counted"], out["requests"], out["servers"]) == (True, 0, [])
    assert cli.ntp_line(out) is None


def test_a_window_the_gateway_checked_without_the_count_says_not_counted(store):
    """A table nft refused, or one that is missing, is not a TV without NTP: verify ran in the window
    and no snapshot listed the set, so the line says so. A window nothing was checked in says nothing."""
    store.execute("INSERT INTO verify(t, ok, failures) VALUES (?, 1, '[]')", (T0 + 600,))
    out = queries.ntp_servers(store, T0, T0 + 86400)
    assert (out["counted"], out["checked"]) == (False, True)
    assert cli.ntp_line(out) == cli.NTP_NOT_COUNTED
    nothing = queries.ntp_servers(store, T0 + 86400, T0 + 2 * 86400)
    assert (nothing["counted"], nothing["checked"]) == (False, False)
    assert cli.ntp_line(nothing) is None


def test_names_put_the_profiles_clock_and_platform_hosts_first_then_the_newest(store, lg):
    """An address's answers can name unrelated hosts on a shared address: the profile's clock hosts come
    first, then its platform's (the must-allow hosts and names under them), then the most recently
    answered; the count of names is the true one, and the line's `+K` is it less one."""
    rows = [
        (T0 - 3 * 86400, "old.example.org", "A:203.0.113.5"),
        (T0 - 2 * 86400, "snu.lge.com", "A:203.0.113.5"),
        (T0 - 1 * 86400, "us.lgtvsdp.com", "A:203.0.113.5,A:203.0.113.6"),
        (T0 + 100, "pool.example.net", "CNAME:x.example.net,A:203.0.113.5"),
        (T0 - 8 * 86400, "too.old.example.org", "A:203.0.113.5"),  # older than KNOWN_DAYS
        (T0 + 200, "near.example.org", "A:198.51.100.90"),  # a longer address, not this one
    ] + [(T0 + 300 + i, f"n{i}.example.com", "A:203.0.113.5") for i in range(4)]
    store.executemany("INSERT INTO dns(t, qname, blocked, answers) VALUES (?, ?, 0, ?)", rows)
    snapshot(store, T0 - 600, {})
    snapshot(store, T0 + 600, {"203.0.113.5": 3, "198.51.100.9": 1})
    out = queries.ntp_servers(store, T0, T0 + 86400, lg)
    first, second = out["servers"]
    assert first["names"] == [
        "us.lgtvsdp.com",
        "snu.lge.com",
        "n3.example.com",
        "n2.example.com",
        "n1.example.com",
    ]
    assert first["names_n"] == 8
    assert second == {"dst": "198.51.100.9", "requests": 1, "names": [], "names_n": 0}
    assert "203.0.113.5 (us.lgtvsdp.com +7) 3, 198.51.100.9 (no lookup) 1" in cli.ntp_line(out)


def test_every_server_is_named_from_one_scan_of_the_answers(store):
    snapshot(store, T0 - 600, {})
    snapshot(store, T0 + 600, {f"198.51.100.{i}": i for i in range(1, 11)})
    scans = []
    store.set_trace_callback(lambda sql: scans.append(sql) if "FROM dns" in sql else None)
    assert queries.ntp_servers(store, T0, T0 + 86400)["addresses"] == 10
    store.set_trace_callback(None)
    assert len(scans) == 1


def test_six_hundred_addresses_in_a_window_are_named_in_chunks_and_never_crash_the_brief(store):
    """The review's B: one scan of 2N LIKE terms passes SQLite's limit of 1,000 at 500 addresses and
    raised "Expression tree is too large", which no caller catches: the brief and the analyst's pack
    failed. A window can hold that many, the stored top changing between snapshots; they are named
    NTP_NAMED_CHUNK at a time."""
    addrs = [f"10.{i // 250}.{i % 250}.1" for i in range(600)]
    store.executemany(
        "INSERT INTO dns(t, qname, blocked, answers) VALUES (?, ?, 0, ?)",
        [(T0 + 100, "a.example.com", f"A:{addrs[0]}"), (T0 + 100, "z.example.com", f"A:{addrs[-1]}")],
    )
    snapshot(store, T0 - 600, {})
    snapshot(store, T0 + 600, {a: 1 for a in addrs})
    scans = []
    store.set_trace_callback(lambda sql: scans.append(sql) if "FROM dns" in sql else None)
    out = queries.ntp_servers(store, T0, T0 + 86400)
    store.set_trace_callback(None)
    assert out["addresses"] == 600 and len(scans) == 3
    named = {x["dst"]: x["names"] for x in out["servers"]}
    assert named[addrs[0]] == ["a.example.com"] and named[addrs[-1]] == ["z.example.com"]


def test_the_brief_line_names_the_top_servers_and_how_many_more():
    servers = [
        {
            "dst": "203.0.113.5",
            "requests": 90,
            "names": ["pool.example.net", "time.example.com"],
            "names_n": 2,
        },
        {"dst": "198.51.100.9", "requests": 10, "names": [], "names_n": 0},
        {"dst": "192.0.2.7", "requests": 2, "names": ["ntp.example.org"], "names_n": 1},
        {"dst": "192.0.2.8", "requests": 1, "names": [], "names_n": 0},
    ]
    ntp = {"counted": True, "addresses": 4, "requests": 103, "unplaced": 0, "servers": servers}
    assert cli.ntp_line(ntp) == (
        "Clock servers (NTP): 103 requests to 4 addresses: 203.0.113.5 (pool.example.net +1) 90,"
        " 198.51.100.9 (no lookup) 10, 192.0.2.7 (ntp.example.org) 2, 1 more"
    )
    one = {**ntp, "addresses": 1, "requests": 1, "servers": [servers[2] | {"requests": 1}]}
    assert cli.ntp_line(one) == "Clock servers (NTP): 1 request to 1 address: 192.0.2.7 (ntp.example.org) 1"
    for nothing in (None, {}, {"counted": True, "addresses": 0, "requests": 0, "servers": []}):
        assert cli.ntp_line(nothing) is None


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


def test_with_no_ntp_the_brief_prints_what_it_printed_before(conn, lg):
    """The count adds a line only when the TV sent NTP, or when the gateway checked itself and the count
    was not there: a day whose snapshots held the set and saw no NTP reads as before, line for line."""
    snapshot(conn, T0 + 600, {})
    snapshot(conn, T0 + 1200, {})
    conn.commit()
    o = queries.brief(conn, DAY[0], lg, now=NOW + 3600)
    assert o["ntp"]["counted"] and o["ntp"]["requests"] == 0
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
    assert "Clock servers (NTP): 4 requests to 1 address: 203.0.113.5 (no lookup) 4" in text
    assert "Firewall held: DoT/DoQ 4;" in text and "NTP from the TV" not in text and "ntp: " not in text
    p = analyst.pack(conn, DAY[1], DAY[2], DAY[0], lg, gateway)
    assert p["firewall"]["activity"] == [{"rule": "DoT/DoQ", "packets": 4}]
    assert "ntp: " not in str(p) and queries.NTP_RULE not in str(p)
