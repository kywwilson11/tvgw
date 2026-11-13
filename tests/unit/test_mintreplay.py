"""(mint) `tvgw mint replay` (design decision 85): the stored answers and connections run through the
minting table, each connection in one class for each ticket lifetime, with counts only in the result.
The record is test_namebound's: an `answer` writes its `dns` row and its `answer_ip` rows."""

import json
from types import SimpleNamespace

import pytest
from conftest import NOW
from test_namebound import DAY, answer, flow, store

from tvgw import cli, mint, mintreplay
from tvgw.mintreplay import LAPSED, LISTED, LOCAL, NEVER, TICKET, TICKETS, UNASSESSED

T = NOW - 5 * DAY  # when the record's answers were given
ONE, TWO, OLD, NOBODY = "203.0.113.10", "203.0.113.20", "203.0.113.30", "198.51.100.99"
FALLBACK = ("156.147.69.32", 8080)  # the LG profile's hardcoded update server
GATEWAY = "198.51.100.1"  # on a TV side numbered from a range that reads as public
MINUTE, HOUR, SIX_HOURS, DAY_LONG = range(4)  # the rows of mintreplay.LIFETIMES


def record(tmp_path, **kw):
    """One address answered for one name, one for two names, and one answered three days before."""
    conn = store(tmp_path, **kw)
    answer(conn, T, "one.example", f"A:{ONE}")
    answer(conn, T, "left.example", f"A:{TWO}")
    answer(conn, T, "right.example", f"CNAME:edge.example,A:{TWO}")
    answer(conn, T - 3 * DAY, "old.example", f"A:{OLD}")
    return conn


def replay(conn, profile=None):
    conn.commit()
    return mintreplay.replay(conn, T - DAY, T + DAY, GATEWAY, profile)


def classes(r) -> list[str]:
    """The class of the record's one connection under each lifetime, shortest first."""
    return (
        [LOCAL] * 4
        if r["local"]
        else [cls for row in r["lifetimes"] for cls, n in row["connections"].items() if n]
    )


@pytest.mark.parametrize(
    ("dst", "dport", "after", "expected"),
    [
        pytest.param(ONE, 443, 30, TICKET, id="an address one name was answered with"),
        pytest.param(TWO, 443, 30, TICKETS, id="an address two names were answered with"),
        pytest.param(OLD, 443, 30, LAPSED, id="an address answered three days before"),
        pytest.param(NOBODY, 443, 30, NEVER, id="an address no answer named"),
        pytest.param(*FALLBACK, 30, LISTED, id="the profile's hardcoded server"),
        pytest.param(FALLBACK[0], 443, 30, NEVER, id="that server on a port the profile does not list"),
        pytest.param(ONE, 443, 2 * 3600, [LAPSED, LAPSED, TICKET, TICKET], id="two hours after the answer"),
        pytest.param(ONE, 443, 58.5, TICKET, id="half a second inside the shortest ticket"),
        pytest.param(ONE, 443, 59, [LAPSED, TICKET, TICKET, TICKET], id="at the shortest ticket's end"),
        pytest.param(ONE, 443, -1, TICKET, id="an answer stamped a second after the connection began"),
        pytest.param(ONE, 443, -1.5, NEVER, id="an answer stamped later than that"),
        pytest.param(ONE, 443, None, UNASSESSED, id="a connection whose beginning was not seen"),
        pytest.param(GATEWAY, 443, 30, LOCAL, id="the gateway"),
        pytest.param("192.168.1.50", 8009, 30, LOCAL, id="a device at home"),
        pytest.param("8.8.8.8", 53, 30, LOCAL, id="DNS aimed at a public resolver"),
    ],
)
def test_each_connection_gets_one_class_for_each_lifetime(tmp_path, lg, dst, dport, after, expected):
    conn = record(tmp_path)
    flow(conn, None if after is None else T + after, dst, 100, 100, dport=dport, end=T + 2 * 3600 + 60)
    r = replay(conn, lg)
    assert classes(r) == (expected if isinstance(expected, list) else [expected] * 4)
    assert r["judged"] + r["local"] == 1


@pytest.mark.parametrize(
    ("name", "address", "dport"),
    [
        pytest.param("One.Example.", ONE, 443, id="a name spelt another way is the same name"),
        pytest.param(
            "update.example", *FALLBACK, id="a listed server an answer also named is held by its ticket"
        ),
    ],
)
def test_one_more_answer_and_the_address_still_has_one_names_ticket(tmp_path, lg, name, address, dport):
    conn = record(tmp_path)
    answer(conn, T + 1, name, f"A:{address}")
    flow(conn, T + 30, address, 100, 100, dport=dport)
    assert classes(replay(conn, lg)) == [TICKET] * 4


def test_a_connection_the_record_cannot_reach_back_for_is_not_assessed(tmp_path, lg):
    """The record starts an hour, to the second, before the connections: it can say `never` of a ticket
    that lives an hour, and cannot of one that lives six. A ticket the table holds, and the profile's
    list, need no reach."""
    conn = record(tmp_path, since=T + 30 - 3600)
    flow(conn, T + 30, NOBODY, 100, 100)
    assert classes(replay(conn, lg)) == [NEVER, NEVER, UNASSESSED, UNASSESSED]
    flow(conn, T + 30, ONE, 100, 100)
    flow(conn, T + 30, FALLBACK[0], 100, 100, dport=FALLBACK[1])
    rows = replay(conn, lg)["lifetimes"]
    assert [(row["connections"][TICKET], row["connections"][LISTED]) for row in rows] == [(1, 1)] * 4


def test_the_window_takes_the_connections_that_began_in_it(tmp_path):
    conn = record(tmp_path)
    for start, end in (
        (T - DAY - 1, None),
        (T - DAY, None),
        (T + DAY - 1, None),
        (T + DAY, None),
        (None, T + DAY),
    ):
        flow(conn, start, ONE, 100, 100, end=end)
    assert replay(conn)["judged"] == 2


def test_a_row_that_names_no_public_address_is_passed_over(tmp_path):
    conn = record(tmp_path)
    conn.execute("INSERT INTO answer_ip(dns_id, t, ip, ttl) VALUES (1, ?, 'not-an-address', 60)", (T,))
    flow(conn, T + 30, ONE, 100, 100)
    r = replay(conn)
    assert (r["answers"], classes(r)) == (4, [TICKET] * 4)


def test_what_strict_would_refuse_is_listed_most_first_with_the_age_of_the_newest_answer(tmp_path):
    conn = record(tmp_path)
    for after in (30, 90):
        flow(conn, T + after, OLD, 100, 100)
    for _ in range(3):
        flow(conn, T + 30, NOBODY, 100, 100, dport=123, proto="udp")
        flow(conn, T + 30, NOBODY, 100, 100, dport=80)
    flow(conn, T + 30, ONE, 100, 100)
    r = replay(conn)
    assert r["lifetimes"][DAY_LONG]["refused"] == [
        {"class": NEVER, "proto": "tcp", "dport": 80, "n": 3, "newest": None, "oldest": None},
        {"class": NEVER, "proto": "udp", "dport": 123, "n": 3, "newest": None, "oldest": None},
        {
            "class": LAPSED,
            "proto": "tcp",
            "dport": 443,
            "n": 2,
            "newest": 3 * DAY + 30,
            "oldest": 3 * DAY + 90,
        },
    ]
    assert [row["connections"][TICKET] for row in r["lifetimes"]] == [1, 1, 1, 1]
    assert (r["judged"], r["local"], r["answers"], r["pool"]) == (9, 0, 4, 130_048)


def test_the_tables_own_counts_come_with_each_lifetime(tmp_path):
    conn = record(tmp_path)
    answer(
        conn, T + 2 * 3600, "one.example", f"A:{ONE}"
    )  # again: a new ticket for an hour, the same for a day
    flow(conn, T + 3 * 3600, ONE, 100, 100)
    rows = replay(conn)["lifetimes"]
    assert [row["lifetime"] for row in rows] == list(mintreplay.LIFETIMES) and rows[-1][
        "lifetime"
    ] == mint.LIFETIME
    assert [(row["tickets"]["minted"], row["tickets"]["renewed"]) for row in rows] == [
        (5, 0),
        (5, 0),
        (4, 1),
        (4, 1),
    ]
    assert rows[DAY_LONG]["tickets"] == {
        "minted": 4, "renewed": 1, "expired": 1, "revoked": 0, "evicted": 0, "refused": 0, "peak": 3, "widest": 1
    }  # fmt: skip


def test_a_connection_made_after_its_answers_own_lifetime_is_counted_where_that_lifetime_is_known(tmp_path):
    """The helper's answers live 60 seconds. PAST_TTL more is from the TV's own cache; an answer whose
    lifetime the record never held, and a connection whose beginning was not seen, are not counted."""
    conn = record(tmp_path)
    answer(conn, T, "unknown.example", "A:203.0.113.40", ttl=None)
    for after in (30, 120, 120.5):
        flow(conn, T + after, ONE, 100, 100)
    flow(conn, T + 500, "203.0.113.40", 100, 100)
    flow(conn, None, ONE, 100, 100, end=T + 500)
    assert replay(conn)["ttl"] == {"known": 3, "past": 1}


def test_the_result_holds_no_name_and_no_address(tmp_path, lg):
    conn = record(tmp_path)
    for dst in (ONE, TWO, OLD, NOBODY, FALLBACK[0], "192.168.1.50"):
        flow(conn, T + 30, dst, 100, 100)
    text = json.dumps(replay(conn, lg))
    assert not [
        word for word in (ONE, TWO, OLD, NOBODY, FALLBACK[0], "192.168.1.50", "example") if word in text
    ]


@pytest.mark.parametrize(
    ("entry", "pair"),
    [
        ("156.147.69.32:8080 CheckSWAutoUpdate.laf (OTA fallback)", ("156.147.69.32", 8080)),
        ("54.186.247.229:443", ("54.186.247.229", 443)),
        ("203.0.113.5 with no port", None),
        ("203.0.113.5:https", None),
        ("10.0.0.7:80 a private address", None),
        ("update.example:443 a name", None),
        ("", None),
    ],
)
def test_a_hardcoded_entry_lists_the_public_address_and_port_it_begins_with(entry, pair):
    profile = SimpleNamespace(generations=[SimpleNamespace(hardcoded=(entry,))])
    assert mintreplay.listed(profile) == ({pair} if pair else set())


def test_the_lg_profile_lists_its_update_fallback_and_no_profile_lists_nothing(lg):
    assert FALLBACK in mintreplay.listed(lg) and mintreplay.listed(None) == frozenset()


# ---- the command -----------------------------------------------------------------------------------------
def run(tmp_path, capsys, *args) -> tuple[int, str, str]:
    """`tvgw mint replay` on the test's store: its exit status, what it printed and what it complained of."""
    conf = tmp_path / "tvgw.conf"
    conf.write_text(f'DB_PATH="{tmp_path / "n.db"}"\n', encoding="utf-8")
    code = cli.main(["--conf", str(conf), "mint", "replay", *args])
    return code, *capsys.readouterr()


def test_the_command_prints_the_table_and_what_strict_would_refuse(tmp_path, capsys):
    conn = record(tmp_path)
    for dst, after in ((ONE, 30), (ONE, 2 * 3600), (TWO, 30), (OLD, 30), (OLD, 3630), ("192.168.1.50", 30)):
        flow(conn, T + after, dst, 100, 100)
    conn.commit()
    code, out, _err = run(tmp_path, capsys)
    assert code == 0
    lines = [" ".join(line.split()) for line in out.splitlines()]
    assert (
        "5 connections judged against 4 answered addresses; 1 more went to the gateway or the home network."
        in lines
    )
    assert lines[lines.index("") + 1 :][:5] == [
        "a ticket lives one name several names listed lapsed never not assessed most tickets most for one name",
        "1 minute 1 1 0 3 0 0 3 1",
        "1 hour 1 1 0 3 0 0 3 1",
        "6 hours 2 1 0 2 0 0 3 1",
        "24 hours 2 1 0 2 0 0 3 1",
    ]
    assert lines[-4:] == [
        "With a ticket that lives 24 hours, a strict stage would have refused 2 of 5 connections:",
        "lapsed tcp/443 2 last answered 72 to 73 hours before",
        "In 3 of 5 connections whose answer's own lifetime is known, the TV used the address more than a minute"
        " after that lifetime had passed.",
        "The pool holds 130048 addresses; every answer got a ticket.",
    ]
    for word in (ONE, TWO, OLD, "example"):
        assert word not in out


def test_the_summary_has_words_for_nothing_refused_a_full_pool_and_a_protocol_without_ports(
    tmp_path, capsys, monkeypatch
):
    conn = record(tmp_path)
    flow(conn, T + 30, ONE, 100, 100)
    conn.commit()
    assert run(tmp_path, capsys)[1].splitlines()[-3:-2] == [
        "With a ticket that lives 24 hours, a strict stage would have refused 0 of 1 connections."
    ]
    flow(conn, T + 30, NOBODY, 100, 100, proto="icmp", dport=None)
    r = replay(conn)
    r["lifetimes"][-1]["tickets"]["refused"] = 7
    monkeypatch.setattr(mintreplay, "replay", lambda *a, **kw: r)
    lines = run(tmp_path, capsys)[1].splitlines()
    assert lines[-3] == "  never  icmp  1"
    assert lines[-1] == "The pool holds 130048 addresses; 7 answers got no ticket because it was full."


def test_the_command_as_json_is_the_replay_itself(tmp_path, capsys):
    conn = record(tmp_path)
    flow(conn, T + 30, ONE, 100, 100)
    conn.commit()
    code, out, _err = run(tmp_path, capsys, "--days", "7", "--json")
    assert code == 0 and json.loads(out) == mintreplay.replay(conn, NOW - 7 * DAY, NOW, "10.10.10.1")
    assert json.loads(out)["lifetimes"][DAY_LONG]["connections"][TICKET] == 1


def test_a_store_whose_answer_record_has_not_started_says_so(tmp_path, capsys):
    from tvgw import db

    db.connect(str(tmp_path / "n.db")).close()
    code, out, _err = run(tmp_path, capsys)
    assert (
        code == 1
        and out.strip() == "The record of answered addresses has not started: the hourly ingest starts it."
    )


@pytest.mark.parametrize("days", ["0", "-3", "100000"])
def test_days_outside_what_the_store_keeps_is_a_usage_error(tmp_path, capsys, days):
    code, out, err = run(tmp_path, capsys, "--days", days)
    assert (code, out) == (2, "") and "--days must be 1 to" in err


@pytest.mark.parametrize(
    ("seconds", "words"),
    [(60, "1 minute"), (3600, "1 hour"), (21600, "6 hours"), (90, "90 seconds"), (mint.LIFETIME, "24 hours")],
)
def test_a_lifetime_is_spelt_in_its_largest_whole_unit(seconds, words):
    assert cli._lifetime(seconds) == words
