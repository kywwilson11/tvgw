"""(mint) `tvgw mint replay` (design decision 85): the stored answers and connections run through the
minting table, each connection in one class for each ticket lifetime, with counts only in the result.
The record is test_namebound's: an `answer` writes its `dns` row and its `answer_ip` rows."""

import ipaddress
import json
from types import SimpleNamespace

import pytest
from conftest import NOW
from test_namebound import BASE, DAY, answer, flow, store

from tvgw import cli, db, mint, mintreplay
from tvgw.mintreplay import CROWDED, LAPSED, LISTED, NEVER, TICKET, TICKETS, UNASSESSED

T = NOW - 5 * DAY  # when the record's answers were given
ONE, TWO, OLD, NOBODY = "203.0.113.10", "203.0.113.20", "203.0.113.30", "198.51.100.99"
FALLBACK = ("156.147.69.32", 8080)  # the LG profile's hardcoded update server
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
    return mintreplay.replay(conn, T - DAY, T + DAY, profile)


def classes(r) -> list[str]:
    """The class of the record's one judged connection under each lifetime, shortest first."""
    return [cls for row in r["lifetimes"] for cls, n in row["connections"].items() if n]


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
        pytest.param(ONE, 443, 59.5, TICKET, id="half a second inside the shortest ticket"),
        pytest.param(ONE, 443, 60, [LAPSED, TICKET, TICKET, TICKET], id="at the shortest ticket's end"),
        pytest.param(ONE, 443, -1, TICKET, id="an answer stamped a second after the connection began"),
        pytest.param(ONE, 443, -1.5, NEVER, id="an answer stamped later than that"),
        pytest.param(ONE, 443, None, UNASSESSED, id="a connection whose beginning was not seen"),
    ],
)
def test_each_connection_gets_one_class_for_each_lifetime(tmp_path, lg, dst, dport, after, expected):
    conn = record(tmp_path)
    flow(conn, None if after is None else T + after, dst, 100, 100, dport=dport, end=T + 2 * 3600 + 60)
    r = replay(conn, lg)
    assert classes(r) == (expected if isinstance(expected, list) else [expected] * 4)
    assert (r["judged"], r["local"]) == (1, 0)


@pytest.mark.parametrize(
    ("dst", "dport"),
    [
        pytest.param("10.10.10.1", 443, id="the gateway"),
        pytest.param("192.168.1.50", 8009, id="a device at home"),
        pytest.param("8.8.8.8", 53, id="DNS aimed at a public resolver"),
        pytest.param("2001:db8::7", 443, id="an IPv6 address"),
    ],
)
@pytest.mark.parametrize("seen", [True, False], ids=["its beginning seen", "its beginning not seen"])
def test_a_local_connection_is_left_out_and_not_judged(tmp_path, dst, dport, seen):
    conn = record(tmp_path)
    flow(conn, T + 30 if seen else None, dst, 100, 100, dport=dport, end=T + 90)
    r = replay(conn)
    assert (r["judged"], r["local"], classes(r)) == (0, 1, [])


def test_an_answer_stamped_within_the_slack_after_the_windows_end_still_counts(tmp_path):
    conn = record(tmp_path)
    answer(conn, T + DAY + 0.4, "late.example", "A:203.0.113.50")
    flow(conn, T + DAY - 0.5, "203.0.113.50", 100, 100)
    assert classes(replay(conn)) == [TICKET] * 4


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
    that lives an hour, and cannot of one that lives six, which is then no refusal either. A ticket the
    table holds, and the profile's list, need no reach."""
    conn = record(tmp_path, since=T + 30 - 3600)
    flow(conn, T + 30, NOBODY, 100, 100)
    r = replay(conn, lg)
    assert classes(r) == [NEVER, NEVER, UNASSESSED, UNASSESSED]
    assert [len(row["refused"]) for row in r["lifetimes"]] == [1, 1, 0, 0]
    flow(conn, T + 30, ONE, 100, 100)
    flow(conn, T + 30, FALLBACK[0], 100, 100, dport=FALLBACK[1])
    rows = replay(conn, lg)["lifetimes"]
    assert [(row["connections"][TICKET], row["connections"][LISTED]) for row in rows] == [(1, 1)] * 4


def test_an_address_answered_in_time_and_left_without_a_ticket_is_crowded_out_not_lapsed(tmp_path):
    """One name answered with one address more than its share within a minute: its first address has lost
    its ticket to the last. That is the table's cost, and is not read as the ticket's lifetime running out."""
    conn = record(tmp_path)
    first, *_ = wide = [f"203.0.{113 + i // 250}.{1 + i % 250}" for i in range(mint.PER_NAME + 1)]
    for i, address in enumerate(wide):
        answer(conn, T + i / 100, "wide.example", f"A:{address}")
    flow(conn, T + 30, first, 100, 100)
    r = replay(conn)
    assert classes(r) == [CROWDED] * 4
    assert [(row["tickets"]["evicted"], row["tickets"]["widest"]) for row in r["lifetimes"]] == [
        (1, mint.PER_NAME)
    ] * 4
    assert r["lifetimes"][DAY_LONG]["refused"] == [
        {"class": CROWDED, "proto": "tcp", "dport": 443, "n": 1, "newest": 30.0, "oldest": 30.0}
    ]


def test_the_window_takes_the_connections_that_began_in_it_and_the_unseen_that_ended_in_it(tmp_path, lg):
    conn = record(tmp_path)
    for start in (T - DAY - 1, T - DAY, T + DAY - 1, T + DAY):
        flow(conn, start, ONE, 100, 100)
    unseen = (
        (T - DAY - 1, ONE, 443),
        (T - DAY, ONE, 443),
        (T, *FALLBACK),
        (T, "10.10.10.1", 443),
        (T + DAY, *FALLBACK),
    )
    for end, dst, dport in unseen:
        flow(conn, None, dst, 100, 100, dport=dport, end=end)
    r = replay(conn, lg)
    assert (r["judged"], r["local"]) == (4, 1)
    assert [(row["connections"][UNASSESSED], row["connections"][LISTED]) for row in r["lifetimes"]] == [
        (1, 1)
    ] * 4


def test_a_row_that_names_no_public_address_is_passed_over(tmp_path):
    conn = record(tmp_path)
    conn.execute("INSERT INTO answer_ip(dns_id, t, ip, ttl) VALUES (1, ?, 'not-an-address', 60)", (T,))
    flow(conn, T + 30, ONE, 100, 100)
    r = replay(conn)
    assert (r["answers"], classes(r)) == (4, [TICKET] * 4)


def test_what_strict_would_refuse_is_listed_most_first_with_the_age_of_the_newest_answer(tmp_path):
    """Most first, then by class, protocol and port. An address answered twice is as old as its newest
    answer."""
    conn = record(tmp_path)
    answer(conn, T - 2 * DAY, "old.example", f"A:{OLD}")
    for after in (30, 90):
        flow(conn, T + after, OLD, 100, 100)
        flow(conn, T + after, NOBODY, 100, 100, dport=8080)
        flow(conn, T + after, NOBODY, 100, 100, dport=80)
    for _ in range(3):
        flow(conn, T + 30, NOBODY, 100, 100, dport=123, proto="udp")
    flow(conn, T + 30, ONE, 100, 100)
    r = replay(conn)
    assert r["lifetimes"][DAY_LONG]["refused"] == [
        {"class": NEVER, "proto": "udp", "dport": 123, "n": 3, "newest": None, "oldest": None},
        {
            "class": LAPSED,
            "proto": "tcp",
            "dport": 443,
            "n": 2,
            "newest": 2 * DAY + 30,
            "oldest": 2 * DAY + 90,
        },
        {"class": NEVER, "proto": "tcp", "dport": 80, "n": 2, "newest": None, "oldest": None},
        {"class": NEVER, "proto": "tcp", "dport": 8080, "n": 2, "newest": None, "oldest": None},
    ]
    assert [row["connections"][TICKET] for row in r["lifetimes"]] == [1, 1, 1, 1]
    assert (r["judged"], r["local"], r["answers"], r["pool"]) == (10, 0, 5, 130_048)


def test_the_tables_own_counts_come_with_each_lifetime(tmp_path):
    conn = record(tmp_path)
    answer(
        conn, T + 2 * 3600, "one.example", f"A:{ONE}"
    )  # again: a new ticket for an hour, the same for a day
    flow(conn, T + 3 * 3600, ONE, 100, 100)
    rows = replay(conn)["lifetimes"]
    assert [row["lifetime"] for row in rows] == list(mintreplay.LIFETIMES)
    assert rows[-1]["lifetime"] == mint.LIFETIME  # the command's summary is of the last row
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
def run(tmp_path, capsys, *args, conf: str = "") -> tuple[int, str, str]:
    """`tvgw mint replay` on the test's store: its exit status, what it printed and what it complained of."""
    path = tmp_path / "tvgw.conf"
    path.write_text(f'DB_PATH="{tmp_path / "n.db"}"\n{conf}', encoding="utf-8")
    code = cli.main(["--conf", str(path), "mint", "replay", *args])
    return code, *capsys.readouterr()


def test_the_command_prints_the_table_its_legend_and_what_strict_would_refuse(tmp_path, capsys):
    conn = record(tmp_path)
    for dst, after in (
        (ONE, 30),
        (ONE, 7200),
        (TWO, 30),
        (OLD, 30),
        (OLD, 3630),
        (NOBODY, 30),
        ("192.168.1.50", 30),
    ):
        flow(conn, T + after, dst, 100, 100)
    conn.commit()
    code, out, _err = run(tmp_path, capsys)
    assert code == 0 and cli.MINT_LEGEND in out
    lines = [" ".join(line.split()) for line in out.replace(cli.MINT_LEGEND, "").splitlines() if line.strip()]
    assert lines == [
        "One address per name, replayed over the record. Nothing is changed.",
        "Judged: 6 connections the TV began in the last 14 days. Left out: 1 (to the gateway, the home network"
        " or port 53).",
        "The tables were given every address the record's answers gave the TV: 4 in all, an address answered"
        f" again counted again. The record is complete since {cli.ts(BASE - 30 * DAY, '%Y-%m-%d %H:%M')}.",
        "a ticket lives one name several names listed crowded out lapsed never not assessed most tickets"
        " most for one name",
        "1 minute 1 1 0 0 3 1 0 3 1",
        "1 hour 1 1 0 0 3 1 0 3 1",
        "6 hours 2 1 0 0 2 1 0 3 1",
        "24 hours 2 1 0 0 2 1 0 3 1",
        "With a ticket that lives 24 hours, a strict stage would have refused 3 of the 6 judged:",
        "lapsed tcp/443 2 last answered 72 to 73 hours before",
        "never tcp/443 1",
        "Of the 5 whose answer's own lifetime the record holds, 3 began more than a minute after that"
        " lifetime had passed.",
        "The pool holds 130,048 addresses; every answer got a ticket.",
    ]
    for word in (ONE, TWO, OLD, NOBODY, "example"):
        assert word not in out


def test_one_connection_is_one_connection_and_a_port_is_printed_only_where_there_is_one(tmp_path, capsys):
    conn = record(tmp_path)
    flow(conn, T + 30, ONE, 100, 100)
    conn.commit()
    lines = run(tmp_path, capsys, "--days", "6")[1].splitlines()
    assert lines[1].startswith("Judged: 1 connection the TV began in the last 6 days. Left out: 0 ")
    assert (
        lines[-3] == "With a ticket that lives 24 hours, a strict stage would have refused 0 of the 1 judged."
    )
    for proto, dport in (("icmp", None), (None, None), ("udp", 0)):
        flow(conn, T + 30, NOBODY, 100, 100, proto=proto, dport=dport)
    conn.commit()
    lines = run(tmp_path, capsys)[1].splitlines()
    assert lines[-5:-2] == ["  never  ?  1", "  never  icmp  1", "  never  udp/0  1"]


def test_a_full_pool_is_said_for_each_lifetime_it_cost_an_answer(tmp_path, capsys, monkeypatch):
    """Two addresses in the pool: the oldest answer's ticket ran out days ago and its address still rests,
    so of the three pairs answered together one gets a ticket and two get none, whatever a ticket lives."""
    monkeypatch.setattr(mint, "POOL", ipaddress.ip_network("198.18.0.8/31"))
    conn = record(tmp_path)
    flow(conn, T + 30, TWO, 100, 100)
    conn.commit()
    lines = run(tmp_path, capsys)[1].splitlines()
    assert [" ".join(line.split()) for line in lines[5:9]] == [
        f"{lived} 0 0 0 1 0 0 0 1 1" for lived in ("1 minute", "1 hour", "6 hours", "24 hours")
    ]
    assert lines[-1] == (
        "The pool holds 2 addresses; answers that got no ticket because it was full:"
        " 2 with 1 minute, 2 with 1 hour, 2 with 6 hours, 2 with 24 hours."
    )


def test_the_default_window_is_no_longer_than_the_store_keeps_and_an_empty_one_prints_no_table(
    tmp_path, capsys
):
    record(tmp_path).commit()
    code, out, _err = run(tmp_path, capsys, conf="DB_DAYS=7\n")
    assert code == 0 and out.splitlines()[1].startswith(
        "Judged: 0 connections the TV began in the last 7 days."
    )
    assert (
        out.splitlines()[-1] == "There is no connection to judge in that window."
        and "a ticket lives" not in out
    )


def test_the_command_as_json_is_the_replay_itself(tmp_path, capsys):
    conn = record(tmp_path)
    flow(conn, T + 30, ONE, 100, 100)
    conn.commit()
    code, out, _err = run(tmp_path, capsys, "--days", "7", "--json")
    assert code == 0 and json.loads(out) == mintreplay.replay(conn, NOW - 7 * DAY, NOW)


def test_a_store_whose_answer_record_has_not_started_says_so(tmp_path, capsys):
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
    "args", [["mint"], ["mint", "replay", "--days", "1.5"], ["mint", "replay", "--days", "week"]]
)
def test_no_action_and_days_that_are_no_whole_number_are_refused_by_the_parser(args, capsys):
    with pytest.raises(SystemExit) as stop:
        cli.main(args)
    assert stop.value.code == 2 and "usage: tvgw mint" in capsys.readouterr().err


@pytest.mark.parametrize(
    ("seconds", "words"),
    [
        (60, "1 minute"),
        (3600, "1 hour"),
        (21600, "6 hours"),
        (5400, "90 minutes"),
        (90, "90 seconds"),
        (mint.LIFETIME, "24 hours"),
    ],
)
def test_a_lifetime_is_spelt_in_its_largest_whole_unit(seconds, words):
    assert cli._lifetime(seconds) == words
