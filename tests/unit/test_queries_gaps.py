"""Read-side queries on hand-seeded data: column mapping, day windows, limits, ordering."""

from datetime import datetime

import pytest

from tvgw import db, queries
from tvgw.adguard import parse_time


def at(stamp: str) -> float:
    return parse_time(stamp)  # explicit offsets: the expected value never depends on the host TZ


D1_NOON = at("2026-10-26T12:00:00-05:00")
D2_NOON = D1_NOON + 86400
D0_NOON = D1_NOON - 86400


@pytest.fixture()
def conn(tmp_path):
    c = db.connect(str(tmp_path / "q.db"))
    yield c
    c.close()


def dns(conn, rows):
    conn.executemany("INSERT INTO dns(t, qname, blocked, rule) VALUES (?,?,?,?)", rows)


# ---- time arguments -------------------------------------------------------------------------------
@pytest.mark.parametrize(
    ("text", "seconds"),
    [("30s", 30), ("5m", 300), ("2h", 7200), ("3d", 259200), ("1w", 604800), (" 2H ", 7200), ("1.5h", 5400)],
)
def test_since_epoch_units(text, seconds):
    assert queries.since_epoch(text, 1_000_000.0) == 1_000_000.0 - seconds


def test_since_epoch_accepts_iso_dates_in_local_time():
    assert queries.since_epoch("2026-10-26") == at("2026-10-26T00:00:00-05:00")
    assert queries.since_epoch("2026-10-26T09:30") == at("2026-10-26T09:30:00-05:00")


def test_day_bounds_follow_the_local_calendar_across_dst():
    a, b = queries.day_bounds("2026-11-01")  # US clocks go back that night: a 25 hour day
    assert b - a == 25 * 3600
    assert datetime.fromtimestamp(a).hour == 0 and datetime.fromtimestamp(b).hour == 0


# ---- host_detail -------------------------------------------------------------------------------------
def test_host_detail_maps_every_column(conn):
    conn.execute(
        "INSERT INTO hosts(name, first_seen, last_seen, category, dns_n, tls_n, http_n, last_blocked, last_rule) "
        "VALUES ('h.example', 100, 200, 'Cat', 3, 2, 5, 1, 'rule-x')"
    )
    dns(
        conn,
        [
            (D0_NOON, "h.example", 0, "r1"),
            (D1_NOON, "h.example", 1, "r1"),
            (D1_NOON + 1, "h.example", 1, "r2"),
            (D1_NOON + 2, "h.example", 0, None),
            (D1_NOON, "other.example", 1, "r9"),
        ],
    )
    conn.executemany(
        "INSERT INTO tls(t, dst, dport, sport, sni) VALUES (1, ?, 443, 1, ?)",
        [
            ("9.9.9.9", "h.example"),
            ("9.9.9.9", "h.example"),
            ("8.8.8.8", "h.example"),
            ("7.7.7.7", "other.example"),
        ],
    )
    conn.executemany(
        "INSERT INTO flows(t_end, dst, bytes_up, bytes_down) VALUES (1, ?, ?, ?)",
        [("9.9.9.9", 10, 100), ("9.9.9.9", 20, 200), ("8.8.8.8", 1, 2), ("7.7.7.7", 1000, 1000)],
    )
    conn.executemany(
        "INSERT INTO http(t, host, status, src) VALUES (1, ?, ?, 'gfts')",
        [("h.example", 200), ("h.example", 403), ("other.example", 500)],
    )
    d = queries.host_detail(conn, "H.Example")
    assert sorted(d.pop("rules")) == ["r1", "r2"]
    assert d == {
        "name": "h.example",
        "category": "Cat",
        "first_seen": 100,
        "last_seen": 200,
        "dns_n": 3,
        "tls_n": 2,
        "http_n": 5,
        "last_blocked": 1,
        "ips": [("9.9.9.9", 2), ("8.8.8.8", 1)],
        "bytes_up": 31,
        "bytes_down": 302,
        "http": (2, 200, 403),
        "by_day": [("2026-10-25", 1, 0), ("2026-10-26", 3, 2)],
    }


def test_host_detail_without_tls_has_zero_bytes(conn):
    conn.execute(
        "INSERT INTO hosts(name, first_seen, last_seen, category) VALUES ('quiet.example', 1, 2, 'Other')"
    )
    d = queries.host_detail(conn, "quiet.example")
    assert (d["ips"], d["bytes_up"], d["bytes_down"], d["http"], d["by_day"]) == (
        [],
        0,
        0,
        (0, None, None),
        [],
    )


# ---- gfts_summary -----------------------------------------------------------------------------------
def test_gfts_summary_groups_sorts_and_windows(conn):
    def row(t, status, uri, nbytes, src="gfts"):
        return (t, "ngfts.lge.com", "GET", uri, "ua", status, nbytes, src)

    rows = (
        [row(10, 403, "/x?biz_code=PREMIUM&a=1", 10)] * 3
        + [row(11, 403, "/x?biz_code=CDP", 250)] * 2
        + [row(12, 200, "/x?no_code=1", None), row(13, 200, None, 5)]
        + [row(14, 200, "/x?biz_code=APP_STORE", 7, src="pcap"), row(20, 403, "/x?biz_code=MAS", 1)]
    )
    conn.executemany("INSERT INTO http(t,host,method,uri,ua,status,bytes,src) VALUES (?,?,?,?,?,?,?,?)", rows)
    assert queries.gfts_summary(conn, 10, 20) == [
        (200, "(other)", 2, 5),  # no biz_code, NULL uri and NULL bytes still count
        (403, "PREMIUM", 3, 30),  # status first, then most requests (not alphabetical, not by bytes)
        (403, "CDP", 2, 500),
    ]
    assert (403, "MAS", 1, 1) in queries.gfts_summary(conn, 10)  # `until` is optional and exclusive


# ---- small selectors ---------------------------------------------------------------------------------
def test_tvstate_orders_filters_and_blanks_missing_app(conn):
    conn.executemany(
        "INSERT INTO tvstate(t, power, app) VALUES (?,?,?)", [(30, "Active", "yt"), (10, "Off", None)]
    )
    assert queries.tvstate(conn, 0) == [(10, "Off", ""), (30, "Active", "yt")]
    assert queries.tvstate(conn, 10, 30) == [(10, "Off", "")]


def test_settings_rules_and_oddport_selectors(conn):
    conn.executemany("INSERT INTO tvsettings(t, key, value) VALUES (?,?,?)", [(30, "b", "2"), (10, "a", "1")])
    assert queries.settings_changes(conn, 20) == [(30, "b", "2")]
    conn.executemany(
        "INSERT INTO rules(kind, text, first_seen, last_seen, removed_at) VALUES (?,?,?,?,?)",
        [("k", "b", 5, 5, None), ("k", "a", 5, 5, 9), ("j", "z", 1, 1, None)],
    )
    assert queries.rules_history(conn) == [("j", "z", 1, None), ("k", "a", 5, 9), ("k", "b", 5, None)]
    conn.executemany(
        "INSERT INTO oddport(t, proto, dst, dport) VALUES (?,?,?,?)",
        [
            (10, "TCP", "1.1.1.1", 80),
            (11, "TCP", "1.1.1.1", 80),
            (12, "UDP", "2.2.2.2", 9),
            (30, "TCP", "3.3.3.3", 1),
        ],
    )
    assert sorted(queries.oddports(conn, 10, 30)) == [("TCP", "1.1.1.1", 80, 2), ("UDP", "2.2.2.2", 9, 1)]
    assert len(queries.oddports(conn, 10)) == 3


def test_default_limits(conn):
    names = [f"n{i:03d}.example" for i in range(70)]
    dns(conn, [(D1_NOON + i, n, 1, "r") for i, n in enumerate(names) for _ in range(i + 1)])
    assert len(queries.blocked_retries(conn, 0)) == 40
    conn.execute("UPDATE dns SET blocked=0")
    assert len(queries.allowed_non_streaming(conn, 0)) == 60
    conn.executemany(
        "INSERT INTO flows(t_end, dst, dport, bytes_up, bytes_down) VALUES (?,?,?,?,?)",
        [(D1_NOON, f"10.0.0.{i}", 443, i + 1, 0) for i in range(40)],
    )
    top = queries.top_upload(conn, 0)
    assert len(top) == 30 and top[0][4] == 40


def test_top_upload_names_a_destination_from_its_busiest_sni(conn):
    conn.executemany(
        "INSERT INTO tls(t, dst, dport, sport, sni) VALUES (1,'9.9.9.9',443,1,?)",
        [("rare.example",), ("busy.example",), ("busy.example",)],
    )
    conn.executemany(
        "INSERT INTO flows(t_end, dst, dport, bytes_up, bytes_down) VALUES (5,?,443,?,1)",
        [("9.9.9.9", 100), ("1.2.3.4", 300)],
    )
    assert queries.top_upload(conn, 0, 6) == [
        (None, "1.2.3.4", 443, 1, 300, 1),
        ("busy.example", "9.9.9.9", 443, 1, 100, 1),
    ]


# ---- the daily brief --------------------------------------------------------------------------------------
def seed_brief(conn):
    """Three days of data around 2026-10-26 so every window edge is exercised."""
    dns(
        conn,
        [(D1_NOON, "ads.example", 1, "||ads^")] * 3
        + [(D2_NOON, "ads.example", 1, "||ads^")] * 4
        + [(D1_NOON, f"b{i:02d}.example", 1, "||b^") for i in range(16)]
        + [(D1_NOON, f"ok{i:02d}.example", 0, None) for i in range(30) for _ in range(i + 1)]
        + [(D1_NOON, "video.googlevideo.com", 0, None)],
    )
    conn.executemany(
        "INSERT INTO flows(t_end, dst, dport, bytes_up, bytes_down) VALUES (?,?,?,?,?)",
        [(D1_NOON, f"10.1.1.{i}", 443, 100 + i, 1) for i in range(14)] + [(D2_NOON, "10.2.2.2", 443, 999, 1)],
    )
    conn.executemany(
        "INSERT INTO http(t, host, method, uri, ua, status, bytes, src) VALUES (?,?,?,?,?,?,?,?)",
        [
            (D1_NOON, "ngfts.lge.com", "GET", "/x?biz_code=MAS", "u", 403, 5, "gfts"),
            (D2_NOON, "ngfts.lge.com", "GET", "/x?biz_code=MAS", "u", 403, 5, "gfts"),
        ],
    )
    conn.executemany(
        "INSERT INTO oddport(t, proto, dst, dport) VALUES (?,?,?,?)",
        [(D1_NOON, "TCP", "1.1.1.1", 8080), (D2_NOON, "TCP", "1.1.1.1", 8080)],
    )
    conn.executemany(
        "INSERT INTO tvstate(t, power, app) VALUES (?,?,?)",
        [(D1_NOON, "Active", "youtube"), (D1_NOON + 3600, "Active", None), (D2_NOON, "Off", None)],
    )
    conn.executemany(
        "INSERT INTO rules(kind, text, first_seen, last_seen, removed_at) VALUES (?,?,?,?,?)",
        [
            ("adguard", "added-d1", D1_NOON, D1_NOON, None),
            ("adguard", "added-d0-removed-d1", D0_NOON, D1_NOON, D1_NOON + 60),
            ("adguard", "added-d0-removed-d2", D0_NOON, D2_NOON, D2_NOON),
            ("adguard", "added-d2", D2_NOON, D2_NOON, None),
        ],
    )
    conn.executemany(
        "INSERT INTO hosts(name, first_seen, last_seen, category, dns_n, tls_n, http_n, last_blocked) VALUES (?,?,?,?,?,?,?,?)",
        [
            ("new-d1.example", D1_NOON, D1_NOON, "LG ads", 4, 3, 2, 1),
            ("old.example", D0_NOON, D1_NOON, "Other", 1, 1, 1, 0),
        ],
    )


def test_brief_is_bounded_to_its_day_and_caps_each_section(conn):
    seed_brief(conn)
    o = queries.brief(conn, "2026-10-26")
    assert o["dns"] == {"lookups": 3 + 16 + sum(range(1, 31)) + 1, "blocked": 19, "names": 1 + 16 + 30 + 1}
    assert o["flows"] == {"conns": 14, "bytes_up": sum(100 + i for i in range(14)), "bytes_down": 14}
    assert o["new_hosts"] == [
        {"name": "new-d1.example", "category": "LG ads", "dns": 4, "tls": 3, "http": 2, "blocked": 1}
    ]
    assert len(o["blocked_retries"]) == 15  # capped; the most retried name leads
    top = o["blocked_retries"][0]  # the exact count is pinned by the xfail test below
    assert (top["name"], top["rule"], top["lookups"] >= 3) == ("ads.example", "||ads^", True)
    names = [r["name"] for r in o["allowed_non_streaming"]]
    assert len(names) == 25 and names[0] == "ok29.example" and "video.googlevideo.com" not in names
    assert [r["lookups"] for r in o["allowed_non_streaming"]] == list(range(30, 5, -1))
    assert len(o["top_upload"]) == 12 and o["top_upload"][0]["bytes_up"] == 113
    assert o["gfts"] == [{"status": 403, "biz_code": "MAS", "requests": 1, "bytes": 5}]
    assert o["oddports"] == [{"proto": "TCP", "dst": "1.1.1.1", "dport": 8080, "n": 1}]
    assert o["tvstate"] == [
        {"time": "12:00", "power": "Active", "app": "youtube"},
        {"time": "13:00", "power": "Active", "app": ""},
    ]
    assert {(c["text"], c["added"], c["removed"]) for c in o["rule_changes"]} == {
        ("added-d1", D1_NOON, None),
        ("added-d0-removed-d1", D0_NOON, D1_NOON + 60),
    }
    assert all(set(c) == {"kind", "text", "added", "removed"} for c in o["rule_changes"])


def test_brief_ignores_names_first_blocked_at_or_after_midnight(conn):
    midnight = queries.day_bounds("2026-10-26")[1]  # computed under the TZ fixture, not at import time
    dns(conn, [(D1_NOON, "today.example", 1, "||t^"), (midnight, "midnight.example", 1, "||m^")] * 3)
    names = [r["name"] for r in queries.brief(conn, "2026-10-26")["blocked_retries"]]
    assert names == ["today.example"]  # the day is [00:00, next 00:00)


@pytest.mark.xfail(
    strict=True, reason="brief() counts a blocked name's lookups from the day start to now, not to day end"
)
def test_brief_blocked_retry_counts_stop_at_day_end(conn):
    seed_brief(conn)
    ads = next(r for r in queries.brief(conn, "2026-10-26")["blocked_retries"] if r["name"] == "ads.example")
    assert ads["lookups"] == 3  # four more lookups happened the next day
