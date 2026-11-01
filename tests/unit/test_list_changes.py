"""(lists) "List changes": the names a blocklist's own update began or stopped blocking that the TV had
been using, from the dns table alone, on hand-seeded stores. Names are documentation ones."""

from __future__ import annotations

import pytest
from conftest import NOW

from tvgw import autoblock, cli, db, queries

LIST = 1792975976  # a list's id as AdGuard numbers user-added lists
OTHER_LIST = 1792975977
A, B = NOW - 86400, NOW  # the window: the day before the frozen now
DAY = 86400


@pytest.fixture()
def conn(tmp_path):
    c = db.connect(str(tmp_path / "tvgw.db"))
    yield c
    c.close()


def lookup(conn, t, name, *, blocked=0, filter_id=None, rule=None, answers="A:203.0.113.5", qtype="A"):
    conn.execute(
        "INSERT INTO dns(t, qname, qtype, answers, blocked, rule, filter_id) VALUES (?,?,?,?,?,?,?)",
        (t, name, qtype, answers, blocked, rule, filter_id),
    )


def connection(conn, t, name, down, dst="203.0.113.5", sport=40000):
    """One TLS connection the TV made to `name`: its hello, then conntrack's record of it."""
    conn.execute("INSERT INTO tls(t, dst, dport, sport, sni) VALUES (?,?,?,?,?)", (t, dst, 443, sport, name))
    conn.execute(
        "INSERT INTO flows(t_start, t_end, proto, dst, dport, sport, bytes_up, bytes_down)"
        " VALUES (?,?,?,?,?,?,?,?)",
        (t, t + 60, "tcp", dst, 443, sport, 1000, down),
    )


def seed(conn):
    # carried content: answered for a week, 3 MB down in two connections, then a list blocks it
    for d in range(2, 9):
        lookup(conn, A - d * DAY, "cdn.example.net")
    connection(conn, A - 3 * DAY, "cdn.example.net", 2 * 1024 * 1024, sport=40001)
    connection(conn, A - 2 * DAY, "cdn.example.net", 1024 * 1024, sport=40002)
    lookup(conn, A + 3600, "cdn.example.net", blocked=1, filter_id=LIST, rule="||example.net^")
    lookup(conn, A + 7200, "cdn.example.net", blocked=1, filter_id=LIST, rule="||example.net^")
    # telemetry-shaped: answered, 4 KB per connection, then blocked by a list
    lookup(conn, A - DAY, "beacon.example.com")
    connection(conn, A - DAY, "beacon.example.com", 4096, dst="198.51.100.20", sport=40010)
    lookup(conn, A + 100, "beacon.example.com", blocked=1, filter_id=OTHER_LIST, rule="||beacon.example.com^")
    # never resolved before: a list block of a name the TV did not use is not a change for the TV
    lookup(conn, A + 200, "never.example.org", blocked=1, filter_id=LIST, rule="||never.example.org^")
    # blocked by the list before the window too: not new
    lookup(conn, A - 5 * DAY, "old.example.com")
    lookup(conn, A - 4 * DAY, "old.example.com", blocked=1, filter_id=LIST, rule="||old.example.com^")
    lookup(conn, A + 300, "old.example.com", blocked=1, filter_id=LIST, rule="||old.example.com^")
    # the custom rules (filter 0) are the profile's and the machine's, reviewed elsewhere
    lookup(conn, A - DAY, "custom.example.com")
    lookup(conn, A + 400, "custom.example.com", blocked=1, filter_id=0, rule="||custom.example.com^")
    # only empty AAAA answers before (aaaa_disabled): the TV never had an address for it
    lookup(conn, A - DAY, "v6only.example.com", qtype="AAAA", answers="")
    lookup(conn, A + 500, "v6only.example.com", blocked=1, filter_id=LIST, rule="||v6only.example.com^")
    # newly allowed: list-blocked three days ago, answered with no rule today
    lookup(conn, A - 3 * DAY, "metrics.example.com", blocked=1, filter_id=LIST, rule="||metrics.example.com^")
    lookup(conn, A + 600, "metrics.example.com")
    lookup(conn, A + 700, "metrics.example.com")
    # answered today through a profile exception: the profile let it through, not a list change
    lookup(conn, A - 2 * DAY, "excepted.example.com", blocked=1, filter_id=LIST, rule="||example.com^")
    lookup(conn, A + 800, "excepted.example.com", rule="@@||excepted.example.com^$important")
    conn.commit()


def test_a_list_s_first_block_of_a_name_the_tv_used_is_a_change(conn):
    seed(conn)
    got = queries.list_newly_blocked(conn, A, B)
    assert [x["name"] for x in got] == ["cdn.example.net", "beacon.example.com"]  # content first
    cdn, beacon = got
    assert cdn == {
        "name": "cdn.example.net",
        "filter_id": LIST,
        "rule": "||example.net^",
        "first_blocked": A + 3600,
        "answered_before": 7,
        "blocked_lookups": 2,
        "conns": 2,
        "down": 3 * 1024 * 1024,
        "median_down": int(1.5 * 1024 * 1024),
        "content": True,
    }
    assert beacon["filter_id"] == OTHER_LIST and beacon["content"] is False and beacon["down"] == 4096


def test_a_median_over_16k_is_content_even_under_2mb(conn):
    lookup(conn, A - DAY, "tiles.example.net")
    for i in range(5):
        connection(conn, A - DAY + i, "tiles.example.net", 20 * 1024, sport=41000 + i)
    lookup(conn, A + 10, "tiles.example.net", blocked=1, filter_id=LIST, rule="||tiles.example.net^")
    (x,) = queries.list_newly_blocked(conn, A, B)
    assert x["down"] < queries.LIST_CONTENT_TOTAL and x["median_down"] == 20 * 1024 and x["content"]


def test_the_shape_is_the_14_days_before_the_block(conn):
    """A big download a month before the block is not this name's shape now; and the lookups that make
    the name "used" reach back 30 days, no further."""
    lookup(conn, A - 20 * DAY, "late.example.net")
    connection(conn, A - 20 * DAY, "late.example.net", 50 * 1024 * 1024, sport=42000)
    lookup(conn, A + 10, "late.example.net", blocked=1, filter_id=LIST, rule="||late.example.net^")
    lookup(conn, A - 40 * DAY, "ancient.example.net")
    lookup(conn, A + 20, "ancient.example.net", blocked=1, filter_id=LIST, rule="||ancient.example.net^")
    (x,) = queries.list_newly_blocked(conn, A, B)
    assert x["name"] == "late.example.net" and x["conns"] == 0 and not x["content"]


def test_a_name_a_list_stopped_blocking_is_the_mirror(conn):
    seed(conn)
    assert queries.list_newly_allowed(conn, A, B) == [
        {
            "name": "metrics.example.com",
            "filter_id": LIST,
            "last_blocked": A - 3 * DAY,
            "first_answered": A + 600,
            "answered_lookups": 2,
        }
    ]


def test_the_brief_carries_both_and_a_red_line_for_content_only(conn, lg):
    seed(conn)
    o = queries.window_report(conn, A, B, lg, now=NOW)
    assert [x["name"] for x in o["list_changes"]["newly_blocked"]] == [
        "cdn.example.net",
        "beacon.example.com",
    ]
    reds = [line for line in o["red_lines"] if "list update" in line]
    assert reds == [
        f"a list update newly blocks cdn.example.net, which carried content (list {LIST}, 3.0M down over 2"
        " connections in the 14 days before, median 1.5M): if the TV needs it, add it to must_allow"
    ]


def test_the_red_line_comes_right_after_the_must_allow_one():
    o = {
        "must_allow_blocked": [{"name": "us.example.com", "lookups": 2, "rule": ""}],
        "list_changes": {
            "newly_blocked": [
                {"name": "c.example", "filter_id": 7, "down": 3 << 20, "conns": 1, "median_down": 3 << 20}
                | {"content": True}
            ]
        },
        "acr": {"value": "on", "t": NOW},
    }
    out = queries.red_lines(o | {"since": A, "until": B})
    assert out[0].startswith("must-allow name blocked") and out[1].startswith("a list update newly blocks")
    assert out[2].startswith("Live Plus")


def test_a_quiet_store_has_no_list_changes(conn, lg):
    o = queries.window_report(conn, A, B, lg, now=NOW)
    assert o["list_changes"] == {"newly_blocked": [], "newly_allowed": []}


def test_the_content_limits_are_decision_20_s():
    assert queries.LIST_CONTENT_TOTAL == autoblock.MAX_TOTAL_DOWN
    assert queries.LIST_CONTENT_MEDIAN == autoblock.MAX_MEDIAN_DOWN


def test_the_queries_use_the_indexes(conn):
    """The brief runs these every day over a year of lookups: the window's rows by time, each name's
    history by name, never a scan of the table."""
    from conftest import plan, statements

    seed(conn)
    sql = statements(conn, lambda: queries.list_changes(conn, A, B))
    plans = " | ".join(plan(conn, s) for s in sql)
    assert "SCAN dns" not in plans.replace("SCAN dns USING", "") and "dns_t" in plans and "dns_q_t" in plans


def test_the_section_renders_only_when_there_is_a_change(conn, capsys):
    seed(conn)
    cli.render_list_changes(queries.list_changes(conn, A, B))
    out = capsys.readouterr().out.splitlines()
    assert out[1] == "List changes (a list's own update; 14-day shape before the first block):"
    assert out[2].split() == ["change", "name", "by", "since", "lookups", "shape"]
    assert "newly blocks  cdn.example.net" in out[3] and out[3].rstrip().endswith("CARRIED CONTENT")
    assert "3.0M down, 2 conns, median 1.5M" in out[3]
    assert "newly allows  metrics.example.com" in out[5] and "2 answered now" in out[5]
    cli.render_list_changes({"newly_blocked": [], "newly_allowed": []})
    assert capsys.readouterr().out == ""


def test_text_from_the_store_is_cleaned_in_the_section(capsys):
    row = {
        "name": "evil\x1b[2J.example",
        "filter_id": LIST,
        "first_blocked": A,
        "answered_before": 1,
        "down": 0,
        "conns": 0,
        "median_down": 0,
        "content": False,
    }
    cli.render_list_changes({"newly_blocked": [row]})
    assert "\x1b" not in capsys.readouterr().out
