"""(reliability) The QUIC fallback watch (design decision 73; research pass 5, external note B6): each
refused QUIC attempt the capture stored, and whether the TV followed it with TCP within 10 seconds to the
same address or the same registrable domain; the names that never fall back; verify's `quic_fallback`,
which names none of them in its detail; and the brief's line."""

import pytest
from conftest import NOW
from test_verify import S

from tvgw import cli, db, queries, verify
from tvgw.config import Settings

T0 = NOW - 86400


@pytest.fixture
def conn(tmp_path):
    c = db.connect(str(tmp_path / "tvgw.db"))
    yield c
    c.close()


def hello(conn, t, sni, dst="203.0.113.10", sport=50000, transport="tcp"):
    conn.execute(
        "INSERT INTO tls(t, dst, dport, sport, sni, transport) VALUES (?, ?, 443, ?, ?, ?)",
        (t, dst, sport, sni, transport),
    )


def flow(conn, t, dst, proto="tcp", dport=443):
    conn.execute(
        "INSERT INTO flows(t_start, t_end, proto, dst, dport, sport) VALUES (?, ?, ?, ?, ?, 40000)",
        (t, t + 60, proto, dst, dport),
    )


def seed(conn):
    # a video app: QUIC (two retransmissions of one Initial), then TCP to another host of its domain
    for k in range(3):
        hello(conn, T0 + k * 0.3, "v1.video.example", sport=50001, transport="quic")
    hello(conn, T0 + 2, "v2.video.example", dst="198.51.100.20")
    # an app whose TCP connection has no hello in the store: the flow to the same address counts
    hello(conn, T0 + 100, "api.store.example", dst="203.0.113.30", sport=50002, transport="quic")
    flow(conn, T0 + 103, "203.0.113.30")
    # a live-video name that never falls back, three attempts
    for k in range(3):
        hello(
            conn, T0 + 200 + k * 60, "edge.moq.example", dst="203.0.113.40", sport=50010 + k, transport="quic"
        )
    # two attempts to a rare name, under the bar, and a TCP hello 11 seconds later, outside the window
    for k in range(2):
        hello(conn, T0 + 400 + k * 60, "rare.example", dst="203.0.113.50", sport=50020 + k, transport="quic")
    hello(conn, T0 + 471, "rare.example", dst="203.0.113.50")
    # an old row without a transport counts as TCP; a UDP flow to the address does not
    hello(conn, T0 + 600, "cdn.old.example", dst="203.0.113.60", sport=50030, transport="quic")
    hello(conn, T0 + 601, "img.old.example", dst="203.0.113.61", transport=None)
    hello(conn, T0 + 700, "udp.example", dst="203.0.113.70", sport=50040, transport="quic")
    flow(conn, T0 + 701, "203.0.113.70", proto="udp")
    conn.commit()


def test_each_attempt_is_judged_by_tcp_to_its_address_or_its_domain_within_10_seconds(conn):
    seed(conn)
    q = queries.quic_fallback(conn, T0 - 1, T0 + 3600)
    by = {x["name"]: (x["attempts"], x["fell_back"]) for x in q["names"]}
    assert by == {
        "moq.example": (3, 0),
        "rare.example": (2, 0),
        "video.example": (1, 1),  # three retransmitted Initials are one attempt
        "store.example": (1, 1),
        "old.example": (1, 1),
        "udp.example": (1, 0),
    }
    assert q["attempts"] == 9 and q["fell_back"] == 3
    assert q["never"] == [{"name": "moq.example", "attempts": 3, "fell_back": 0}]
    assert [x["name"] for x in q["names"]][:2] == ["moq.example", "rare.example"]  # most attempts first


def test_a_window_without_attempts_is_empty(conn):
    q = queries.quic_fallback(conn, T0, T0 + 3600)
    assert q == {"attempts": 0, "fell_back": 0, "names": [], "never": [], "window": queries.FALLBACK_WINDOW}


def test_the_week_verify_reads_leaves_the_newest_two_hours_out(tmp_path):
    path = tmp_path / "tvgw.db"
    c = db.connect(str(path))
    for k in range(3):  # three unanswered attempts in the last hour: their TCP may be in a pcap not yet read
        hello(c, NOW - 1800 + k, "fresh.example", sport=51000 + k, transport="quic")
    c.commit()
    c.close()
    assert verify.store_quic(str(path), NOW)["attempts"] == 0
    assert verify.store_quic(str(path), NOW + 3 * 3600)["never"][0]["name"] == "fresh.example"
    assert verify.store_quic(str(tmp_path / "none.db"), NOW)["attempts"] == 0


@pytest.mark.parametrize(
    ("s", "view", "level", "detail"),
    [
        (Settings(block_quic="no"), None, verify.OK, "not in use (BLOCK_QUIC=no)"),
        (S, None, verify.OK, "the store could not be read"),
        (S, {"attempts": 0, "never": []}, verify.OK, "no refused QUIC attempt recorded in 7 days"),
        (S, {"attempts": 9, "never": []}, verify.OK,
         "no name the TV tried QUIC with 3 times or more in 7 days stayed without TCP"),
        (S, {"attempts": 9, "never": [{"name": "moq.example"}]}, verify.WARN,
         "1 name never fell back to TCP after a refused QUIC attempt in 7 days; tvgw report --since 7d names it"),
        (S, {"attempts": 9, "never": [{"name": "a.example"}, {"name": "b.example"}]}, verify.WARN,
         "2 names never fell back to TCP after a refused QUIC attempt in 7 days; tvgw report --since 7d names them"),
    ],
)  # fmt: skip
def test_the_check_says_how_many_names_never_fall_back_and_names_none(s, view, level, detail):
    assert verify.quic_level(s, view) == (level, detail)
    assert "example" not in detail  # the names are a viewing record; the public hardware log never has them


def test_the_brief_names_them_and_says_nothing_without_an_attempt(conn):
    seed(conn)
    q = queries.quic_fallback(conn, T0 - 1, T0 + 3600)
    assert cli.quic_line(q) == (
        "QUIC refused: 9 attempts to 6 names, 3 followed by TCP within 10 s; never fell back: moq.example (3)"
    )
    every = {"attempts": 2, "fell_back": 2, "names": [{"name": "x.example"}], "never": [], "window": 10.0}
    assert cli.quic_line(every) == "QUIC refused: 2 attempts to 1 name, all followed by TCP within 10 s"
    assert cli.quic_line({"attempts": 0}) is None and cli.quic_line(None) is None
    assert cli.quic_line({**q, "refused": 0}) is None  # the rule refused nothing: QUIC was let through
    assert cli.quic_line({**q, "refused": 12}) is not None


def test_the_report_carries_it(conn, lg):
    seed(conn)
    o = queries.window_report(conn, T0 - 1, T0 + 3600, lg, now=NOW)
    assert o["quic_fallback"]["never"][0]["name"] == "moq.example"
    assert o["quic_fallback"]["refused"] == 0  # no counter snapshot in this store
    assert not any(line.startswith("QUIC") for line in o["red_lines"])  # an engineering line, never red
