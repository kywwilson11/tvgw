"""(screentest) The screen test (design decision 88): the exact rank test against counting by hand, the
level it keeps whatever the traffic, a stand-in TV in six modes (tvdouble.py), what a "no" is worth, the
words of a result, and the dry run that plays nothing."""

import itertools
import json
import random

import pytest
import tvdouble

from tvgw import cli, connpoll, screentest
from tvgw.screentest import ALPHA, TOTAL


def labels(seed: int, n: int = 20) -> list[bool]:
    return screentest.draw_slots(random.Random(seed), n)


# ---- the exact test ----------------------------------------------------------------------------------------
def by_hand(values: list[float], on: list[bool]) -> float:
    """Every way to call half the slots on, one at a time."""
    ranks = screentest._doubled_midranks(values)
    seen = sum(rank for rank, lit in zip(ranks, on, strict=True) if lit)
    halves = list(itertools.combinations(range(len(on)), sum(on)))
    return sum(sum(ranks[i] for i in half) >= seen for half in halves) / len(halves)


@pytest.mark.parametrize("n", [4, 6, 8, 10, 12])
def test_the_rank_test_is_the_count_of_every_way_to_choose_the_half_ties_and_all(n):
    rng = random.Random(n)
    for _ in range(60):
        values = [float(rng.choice([0, 0, 1, 2, 3, 5, 8])) for _ in range(n)]
        on = screentest.draw_slots(rng, n)
        assert screentest.rank_test(values, on) == pytest.approx(by_hand(values, on), abs=1e-12)


def test_a_perfect_follower_in_twenty_slots_is_one_chance_in_184_756_and_a_tie_is_no_evidence():
    on = [True, False] * 10
    assert (
        screentest.rank_test([float(lit) + k for k, lit in enumerate(on)], on) > ALPHA
    )  # a trend, not the order
    assert 1 / screentest.rank_test([10.0 if lit else 1.0 for lit in on], on) == pytest.approx(184_756)
    assert screentest.rank_test([7.0] * 20, on) == 1.0


@pytest.mark.parametrize("n", [0, 1, 7, 66])
def test_the_slots_are_an_even_number_the_counting_can_hold(n):
    with pytest.raises(ValueError, match="even, from 2 to 64"):
        screentest.draw_slots(random.Random(0), n)


def test_half_the_slots_are_on_and_sixty_four_can_be_counted():
    on = labels(1, 64)
    assert sum(on) == 32 and len(on) == 64
    assert 0 < screentest.rank_test([float(k) for k in range(64)], on) <= 1
    with pytest.raises(ValueError, match="at most 64"):
        screentest.rank_test([0.0] * 66, [True, False] * 33)


def test_a_slots_value_is_what_was_sent_in_its_seconds_a_lag_later_and_a_short_series_is_refused():
    series = [float(t) for t in range(10)]
    assert screentest.slot_values(series, width=3, n=2, lag=0) == [0 + 1 + 2, 3 + 4 + 5]
    assert screentest.slot_values(series, width=3, n=2, lag=4) == [4 + 5 + 6, 7 + 8 + 9]
    with pytest.raises(ValueError, match="10 seconds; 11 are needed"):
        screentest.slot_values(series, width=3, n=2, lag=5)
    assert screentest.seconds_needed(20, 45) == 20 * 45 + 22 and screentest.default_lags(45) == (11, 22)


def test_the_two_readings_are_the_bytes_and_the_seconds_with_an_upload_in_them():
    series = [0.0, 199.0, 200.0, 5000.0]
    assert screentest.reading(series, screentest.BYTES) is series
    assert screentest.reading(series, screentest.UPLOADS) == [0.0, 0.0, 1.0, 1.0]
    with pytest.raises(ValueError, match="no such reading"):
        screentest.reading(series, "packets")


# ---- the level: a property of the design, whatever the traffic --------------------------------------------------
def test_one_awkward_series_under_fresh_orders_is_reported_no_more_often_than_the_level_allows():
    """A trend, a timer at twice the slot's width, a burst, a sparse destination and a dense one. The
    order is drawn again 3,000 times over the same numbers: nothing can follow an order drawn afterwards."""
    seconds = screentest.seconds_needed(20, 45)
    rng = random.Random(5)
    series = {
        "a trend": [1000.0 + 3 * t for t in range(seconds)],
        "a timer": [5000.0 if t % 90 == 0 else 0.0 for t in range(seconds)],
        "a burst": [80_000.0 if 300 <= t < 330 else 0.0 for t in range(seconds)],
        "sparse": [900.0 if rng.random() < 0.01 else 0.0 for _ in range(seconds)],
        "dense": [rng.lognormvariate(8, 1) for _ in range(seconds)],
    }
    series[TOTAL] = [sum(xs[t] for xs in series.values()) for t in range(seconds)]
    reported = sum(bool(screentest.score(series, labels(seed), 45).followed()) for seed in range(3000))
    assert reported <= 3000 * ALPHA


# ---- the stand-in TV ---------------------------------------------------------------------------------------------
def flagged(mode: str, n: int, width: int, runs: int) -> int:
    """In how many of `runs` runs, each with its own order and its own TV, something followed the pattern."""
    hits = 0
    for seed in range(runs):
        rng = random.Random(f"{mode} {seed}")
        on = screentest.draw_slots(rng, n)
        hits += bool(screentest.score(tvdouble.run(mode, on, width, rng), on, width).followed())
    return hits


@pytest.mark.parametrize(
    ("mode", "slots", "runs", "at_least", "at_most"),
    [
        pytest.param(
            "lg", screentest.SLOTS_FAST, 100, 97, 100, id="LG's client, a server of its own, 15 minutes"
        ),
        pytest.param("samsung", screentest.SLOTS_GENERAL, 100, 95, 100, id="Samsung's, 40 minutes"),
        pytest.param("lg-hidden", (48, 45), 40, 36, 40, id="LG's, inside the busiest connection, 36 minutes"),
        pytest.param(
            "sluggish", screentest.SLOTS_FAST, 100, 97, 100, id="a client slow to start and to stop"
        ),
        pytest.param("sluggish", (20, 30), 100, 0, 75, id="the same with slots too short for it"),
        pytest.param("none", screentest.SLOTS_FAST, 400, 0, 4, id="no recognition"),
        pytest.param("timer", screentest.SLOTS_FAST, 400, 0, 4, id="uploads on a timer, whatever is on"),
    ],
)
def test_a_client_that_reports_the_screen_is_found_and_one_that_does_not_is_left_alone(
    mode, slots, runs, at_least, at_most
):
    assert at_least <= flagged(mode, *slots, runs) <= at_most


def test_the_destination_that_follows_is_named_first_with_what_it_sent_on_and_off():
    rng = random.Random(4)
    on = screentest.draw_slots(rng, 20)
    result = screentest.score(tvdouble.run("lg", on, 45, rng), on, 45)
    top = result.findings[0]
    assert (top.key, top.reading) == (connpoll.cell(f"198.18.{tvdouble.OWN}.1", 443), screentest.BYTES)
    assert top.p <= ALPHA < top.raw * result.tests + 1 and top.off_median == 0 < top.on_median
    assert result.tests == len(result.findings) * 4 and result.destinations() == len(result.findings) - 1
    assert [f.p for f in result.findings] == sorted(f.p for f in result.findings)


# ---- what a "no" is worth --------------------------------------------------------------------------------------------
def test_a_run_says_where_it_would_have_caught_a_hidden_upload_of_each_known_shape():
    """LG's shape is caught everywhere in fifteen minutes. Samsung's, about once a minute, is caught
    nowhere in slots of 45 seconds, and in slots of two minutes only where little else is sent: the count
    is of the run that was made, and never a promise."""
    rng = random.Random(3)
    fast, slow = tvdouble.run("none", labels(3), 45, rng), tvdouble.run("none", labels(3), 120, rng)
    assert screentest.sensitivity(fast, labels(3), 45, rng) == {"LG": len(fast) - 1, "Samsung": 0}
    assert 0 < screentest.sensitivity(slow, labels(3), 120, rng)["Samsung"] < len(slow) - 1


def test_a_catch_is_the_planted_destination_following_not_something_else_that_does():
    """In a run where LG's client is already found on its own server, an upload of Samsung's size planted
    elsewhere is caught in few destinations in slots of 45 seconds, though something follows in every
    one of those scorings: a catch is the planted destination's own."""
    rng = random.Random(4)
    on = screentest.draw_slots(rng, 20)
    series = tvdouble.run("lg", on, 45, rng)
    caught = screentest.sensitivity(series, on, 45, rng)
    assert 1 <= caught["Samsung"] <= 3 < caught["LG"] == len(series) - 1


def test_a_planted_upload_goes_where_the_pattern_was_mostly_on_before_it():
    on = [True, False]
    out = screentest.planted([0.0] * 200, on, width=100, period=10.0, size=5.0, rng=random.Random(1))
    assert sum(out[:110]) >= 9 * 5.0 and sum(out[120:]) == 0


# ---- the words -------------------------------------------------------------------------------------------------------
def result_of(mode: str, seed: int = 4):
    rng = random.Random(seed)
    on = screentest.draw_slots(rng, 20)
    series = tvdouble.run(mode, on, 45, rng)
    return screentest.score(series, on, 45), screentest.sensitivity(series, on, 45, rng)


def test_a_no_says_how_much_was_watched_what_would_have_been_caught_and_what_it_cannot_rule_out():
    lines = screentest.render(*result_of("none"))
    assert (
        lines[0]
        == "Nothing the TV sent followed the picture or the sound: 7 destinations watched for 15 minutes."
    )
    assert lines[1] == (
        "Of those 7, this run would have caught an upload hidden there: one the size of LG's in 7 and one the"
        " size of Samsung's in 0."
    )
    assert lines[2].startswith("A TV that reports on a timer whatever is on the screen") and len(lines) == 3


@pytest.mark.parametrize(
    ("played", "last"), [(True, "Run the test again to confirm."), (False, "false alarm.")]
)
def test_a_yes_names_the_destination_what_it_sent_and_the_odds_and_a_dry_run_calls_it_a_false_alarm(
    played, last
):
    result, caught = result_of("lg")
    lines = screentest.render(result, caught, played=played)
    assert lines[0] == f"What the TV sent to {result.findings[0].key} followed the order of the pattern."
    assert "KB in each 45 seconds the pattern was on, and 0 bytes in each that it was off." in lines[1]
    assert lines[2].startswith("Chance would do that less than once in ") and lines[3].endswith(last)


# ---- the dry run -----------------------------------------------------------------------------------------------------
LINE = (
    "ipv4     2 tcp      6 431999 ESTABLISHED src=10.10.10.17 dst={dst} sport=40000 dport=443 packets={packets}"
    " bytes={octets} src={dst} dst=192.0.2.48 sport=443 dport=40000 packets=1 bytes=52 [ASSURED] mark=0 use=1\n"
)


class Gateway:
    """A gateway whose connection table is a stand-in TV's, and whose clock moves when it is slept on and
    while a listing takes `busy` seconds."""

    def __init__(self, monkeypatch, tmp_path, mode: str = "none", root: bool = True, busy: float = 0.0):
        self.tv, self.now, self.busy, self.calls = tvdouble.Double(mode, random.Random(11)), 0.0, busy, []
        self.sent = [0.0] * tvdouble.SERVERS
        self.conf = tmp_path / "tvgw.conf"
        self.conf.write_text("TV_IP=10.10.10.17\n", encoding="utf-8")
        monkeypatch.setattr(cli.os, "geteuid", lambda: 0 if root else 1000)
        monkeypatch.setattr(connpoll.subprocess, "run", self.conntrack)
        monkeypatch.setattr(connpoll, "clock", lambda: self.now)
        monkeypatch.setattr(connpoll, "sleep", self.sleep)

    def on_screen(self) -> bool:
        return False  # nothing is on the screen in a dry run

    def sleep(self, seconds: float) -> None:
        self.now += seconds

    def conntrack(self, argv, **kw):
        """The table as it stands, a second on: the TV has sent what it sends."""
        self.calls.append(argv)
        self.now += self.busy  # how long the listing took
        for server, size in self.tv.step(self.on_screen()).items():
            self.sent[server] += size
        listing = "".join(
            LINE.format(dst=f"198.18.{server}.1", packets=1, octets=int(sent) + 52)
            for server, sent in enumerate(self.sent)
            if sent
        )
        return type("Done", (), {"stdout": listing + "conntrack v1.4.8: flow entries have been shown.\n"})()

    def run(self, *args: str) -> int:
        return cli.main(["--conf", str(self.conf), "screen-test", *args])


def test_a_dry_run_watches_a_runs_length_plays_nothing_and_says_what_it_would_have_caught(
    monkeypatch, tmp_path, capsys
):
    gateway = Gateway(monkeypatch, tmp_path)
    assert gateway.run("--dry-run") == 0
    out = capsys.readouterr().out.splitlines()
    assert out[0] == "Nothing is played: this is a dry run. It watches what the TV sends for 15 minutes."
    assert out[1].startswith("Nothing the TV sent followed the picture or the sound: ") and len(out) == 4
    assert len(gateway.calls) == screentest.seconds_needed(*screentest.SLOTS_FAST) + 1  # and the first look
    assert set(map(tuple, gateway.calls)) == {
        (*connpoll.LISTING, "10.10.10.17")
    }  # the table, and nothing else


def test_a_dry_run_in_which_something_follows_says_it_is_the_tests_own_false_alarm(
    monkeypatch, tmp_path, capsys
):
    """Nothing is played, so nothing can follow. Here the stand-in TV is shown the order all the same, as
    if it could see what was drawn: the run reports it, exits 1, and calls it what it would be."""
    gateway = Gateway(monkeypatch, tmp_path, mode="lg")
    order = screentest.draw_slots(random.Random(5), 20)
    monkeypatch.setattr(cli.random, "SystemRandom", lambda: random.Random(5))
    monkeypatch.setattr(
        gateway,
        "on_screen",
        lambda: (len(gateway.calls) - 2) // 45 < 20 and order[(len(gateway.calls) - 2) // 45],
    )
    assert gateway.run("--dry-run") == 1
    out = capsys.readouterr().out.splitlines()
    assert out[1].endswith("followed the order of the pattern.") and out[-1].endswith(
        "the test's own false alarm."
    )


def test_the_json_form_names_no_more_than_the_text_does(monkeypatch, tmp_path, capsys):
    assert Gateway(monkeypatch, tmp_path).run("--dry-run", "--general", "--json") == 0
    doc = json.loads(capsys.readouterr().out)
    assert (doc["dry_run"], doc["slots"], doc["width"], doc["followed"]) == (True, 20, 120, [])
    assert set(doc) == {"dry_run", "slots", "width", "destinations", "p", "followed", "caught", "unread"}
    assert doc["unread"] == 1 and set(doc["caught"]) == set(screentest.SHAPES)


@pytest.mark.parametrize(
    ("kw", "args", "said"),
    [
        ({}, (), "Playing is not built yet. --dry-run watches without playing."),
        ({"root": False}, ("--dry-run",), "reading the connection table needs root"),
        (
            {"busy": 1.5},
            ("--dry-run",),
            "The gateway was too busy to look once a second. Nothing is concluded.",
        ),
    ],
    ids=["without --dry-run", "without root", "on a gateway that cannot keep up"],
)
def test_what_the_command_will_not_do_it_says_and_concludes_nothing(
    monkeypatch, tmp_path, capsys, kw, args, said
):
    assert Gateway(monkeypatch, tmp_path, **kw).run(*args) == 2
    got = capsys.readouterr()
    assert said in got.err and "followed" not in got.out
