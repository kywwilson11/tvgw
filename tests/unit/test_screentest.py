"""(screentest) The screen test (design decision 88): the exact rank test against counting by hand, the
level it keeps whatever the traffic, a stand-in TV in six modes (tvdouble.py), what a "no" is worth, the
words of a result, and the dry run that plays nothing."""

import itertools
import json
import random
from types import SimpleNamespace

import pytest
import tvdouble

from tvgw import cli, connpoll, screentest
from tvgw.screentest import ALPHA, BYTES, TOTAL, UPLOADS, Finding, Result


def labels(seed: int, n: int = 20) -> list[bool]:
    return screentest.draw_slots(random.Random(seed), n)


# ---- the exact test ----------------------------------------------------------------------------------------
def by_hand(values: list[float], on: list[bool]) -> float:
    """Every way to call half the slots on, one at a time, with ranks counted the long way: twice a
    value's rank is twice the values below it, and the values equal to it, and one."""
    ranks = [2 * sum(w < v for w in values) + sum(w == v for w in values) + 1 for v in values]
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


@pytest.mark.parametrize(
    ("on", "p"),
    [
        ([False, False, True, True], 1 / 6),
        ([True, False, True, False], 5 / 6),
        ([True, True, False, False], 1),
    ],
    ids=["the upper pair", "one of each", "the lower pair"],
)
def test_equal_values_share_the_mean_of_their_ranks(on, p):
    """Two pairs of equals rank 1.5, 1.5, 3.5, 3.5. Of the six halves one sums to 7, four to 5, one to 3."""
    assert screentest.rank_test([1.0, 1.0, 2.0, 2.0], on) == pytest.approx(p)


def test_a_perfect_follower_in_twenty_slots_is_one_chance_in_184_756_and_a_tie_is_no_evidence():
    on = [True, False] * 10
    trend = [float(lit) + k for k, lit in enumerate(on)]  # a trend, not the order
    assert screentest.rank_test(trend, on) > ALPHA
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
    for values, order in (([0.0] * 66, [True, False] * 33), ([1.0], [True, False])):
        with pytest.raises(ValueError, match="one value for each slot, and at most 64"):
            screentest.rank_test(values, order)


def test_a_slots_value_is_what_was_sent_in_its_seconds_a_lag_later_and_a_short_series_is_refused():
    series = [float(t) for t in range(10)]
    assert screentest.slot_values(series, width=3, n=2, lag=0) == [0 + 1 + 2, 3 + 4 + 5]
    assert screentest.slot_values(series, width=3, n=2, lag=4) == [4 + 5 + 6, 7 + 8 + 9]
    with pytest.raises(ValueError, match="10 seconds; 11 are needed"):
        screentest.slot_values(series, width=3, n=2, lag=5)
    assert screentest.seconds_needed(20, 45) == 20 * 45 + 22 and screentest.default_lags(45) == (11, 22)


def test_the_two_readings_are_the_bytes_and_the_seconds_with_an_upload_in_them():
    series = [0.0, 199.0, 200.0, 5000.0]
    assert screentest.read_as(series, BYTES) is series
    assert screentest.read_as(series, UPLOADS) == [0.0, 0.0, 1.0, 1.0]
    with pytest.raises(ValueError, match="no such reading"):
        screentest.read_as(series, "packets")


def test_the_correction_gives_each_test_its_place_and_none_a_smaller_p_than_the_one_before():
    """Three destinations, one test each, in four slots: p of 1/6, 1/6 and 1/3. Holm multiplies them by
    3, 2 and 1 and lets none fall below the one before, so all three end at 1/2."""
    series = {"a": [3.0, 4.0, 1.0, 2.0], "b": [3.0, 4.0, 1.0, 2.0], "c": [2.0, 4.0, 1.0, 3.0]}
    result = screentest.score(series, [True, True, False, False], 1, lags=(0,), readings=(BYTES,))
    assert [(f.key, f.raw, f.p) for f in result.findings] == [
        ("a", pytest.approx(1 / 6), 0.5),
        ("b", pytest.approx(1 / 6), 0.5),
        ("c", pytest.approx(1 / 3), 0.5),
    ]
    assert (result.p, result.tests, result.seconds) == (0.5, 3, 4)
    assert (result.findings[0].on_median, result.findings[0].off_median) == (3.5, 1.5)


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
    assert screentest.sensitivity(fast, labels(3), 45, rng) == (7, {"LG": 7, "Samsung": 0})
    weighed, caught = screentest.sensitivity(slow, labels(3), 120, rng)
    assert 0 < caught["Samsung"] < weighed == 7


def test_a_catch_is_the_planted_destination_following_not_something_else_that_does():
    """In a run where LG's client is already found on its own server, an upload of Samsung's size planted
    elsewhere is caught in few destinations in slots of 45 seconds, though something follows in every
    one of those scorings: a catch is the planted destination's own."""
    rng = random.Random(4)
    on = screentest.draw_slots(rng, 20)
    series = tvdouble.run("lg", on, 45, rng)
    weighed, caught = screentest.sensitivity(series, on, 45, rng)
    assert 1 <= caught["Samsung"] <= 3 < caught["LG"] == weighed == len(series) - 1


def test_an_upload_is_hidden_only_where_the_tv_kept_sending_and_the_total_rises_by_what_was_planted(
    monkeypatch,
):
    """A destination sent to in three slots is weighed; one sent to in two, or once, is not. Each scoring
    is of the run with one destination's upload added, to it and to the total alike."""
    on, width = [True, False] * 4, 10
    seconds = screentest.seconds_needed(len(on), width)
    series = {
        "kept": [300.0 if t % width == 0 and t < 3 * width else 0.0 for t in range(seconds)],
        "twice": [300.0 if t in (0, width) else 0.0 for t in range(seconds)],
        "once": [9000.0 if t == 5 else 0.0 for t in range(seconds)],
    }
    series[TOTAL] = [sum(sent) for sent in zip(*series.values(), strict=True)]
    assert screentest.active(series, width, len(on)) == ["kept"]
    scored = []
    monkeypatch.setattr(
        screentest, "score", lambda again, *a: scored.append(again) or screentest.Result(1, (), 0, 0, 0, 0)
    )
    assert screentest.sensitivity(series, on, width, random.Random(1)) == (1, {"LG": 0, "Samsung": 0})
    for again in scored:
        added = [a - b for a, b in zip(again["kept"], series["kept"], strict=True)]
        assert sum(added) > 0 and again["twice"] is series["twice"]
        assert [a - b for a, b in zip(again[TOTAL], series[TOTAL], strict=True)] == added
    del series[TOTAL]
    scored.clear()
    screentest.sensitivity(series, on, width, random.Random(1))
    assert len(scored) == 2 and not any(TOTAL in again for again in scored)  # no total is made up


class At:
    """A random source whose every draw is one number."""

    def __init__(self, value: float):
        self.value = value

    def uniform(self, low: float, high: float) -> float:
        return self.value


def test_a_planted_upload_goes_where_the_pattern_was_on_for_half_or_more_of_the_period_before_it():
    out = screentest.planted(
        [0.0] * 200, [True, False], width=100, period=10.0, size=5.0, rng=random.Random(1)
    )
    assert sum(out[:110]) >= 9 * 5.0 and sum(out[120:]) == 0
    halves = screentest.planted([0.0] * 41, [True, False] * 2, width=10, period=20.0, size=5.0, rng=At(20.0))
    assert [t for t, sent in enumerate(halves) if sent] == [20, 40]  # each after ten seconds on and ten off


# ---- the words -------------------------------------------------------------------------------------------------------
def result_of(mode: str, seed: int = 4):
    rng = random.Random(seed)
    on = screentest.draw_slots(rng, 20)
    series = tvdouble.run(mode, on, 45, rng)
    return screentest.score(series, on, 45), *screentest.sensitivity(series, on, 45, rng)


def found(*findings: Finding) -> Result:
    """A fast run's result with these findings, as `score` would hand it over."""
    return Result(findings[0].p, findings, 4 * len(findings), 20, 45, 922)


def quiet(key: str) -> Finding:
    return Finding(key, 1.0, 0.5, BYTES, 11, 0.0, 0.0)


TIMER = "A TV that reports on a timer whatever is on the screen, or that sends later, would look the same."


@pytest.mark.parametrize(
    ("result", "weighed", "caught", "lines"),
    [
        (
            found(*map(quiet, "abc"), quiet(TOTAL)),
            2,
            {"LG": 2, "Samsung": 1},
            [
                "Nothing the TV sent followed the picture or the sound: 3 destinations watched for 15 minutes.",
                "The TV kept sending to 2 of them. Had a known upload been hidden in what one of them was"
                " sent, this run would have caught it: LG's in 2 of 2, Samsung's in 1 of 2.",
                TIMER,
            ],
        ),
        (
            found(quiet("a"), quiet(TOTAL)),
            0,
            {"LG": 0, "Samsung": 0},
            [
                "Nothing the TV sent followed the picture or the sound: 1 destination watched for 15 minutes.",
                "The TV kept sending to none of them, so this run cannot say what it would have caught.",
                TIMER,
            ],
        ),
    ],
    ids=["some kept sending", "none did"],
)
def test_a_no_says_how_much_was_watched_what_would_have_been_caught_and_what_it_cannot_rule_out(
    result, weighed, caught, lines
):
    assert screentest.render(result, weighed, caught) == lines


def test_a_no_from_a_whole_run_counts_the_destinations_the_run_saw():
    lines = screentest.render(*result_of("none"))
    assert lines[0].endswith(": 7 destinations watched for 15 minutes.")
    assert lines[1].endswith("this run would have caught it: LG's in 7 of 7, Samsung's in 0 of 7.")


@pytest.mark.parametrize(
    ("findings", "said"),
    [
        (
            (
                Finding(TOTAL, 0.001, 1e-5, BYTES, 11, 4096.0, 100.0),
                Finding("a", 0.004, 1e-4, BYTES, 11, 2048.0, 0.0),
            ),
            [
                "What the TV sent to a followed the order of the pattern.",
                "It sent about 2 KB in a typical 45 seconds with the pattern on, and 0 bytes in a typical 45"
                " seconds with it off.",
                "Chance would do that no more than once in 250 runs.",
            ],
        ),
        (
            (Finding(TOTAL, 0.002, 1e-5, UPLOADS, 22, 3.0, 1.0), quiet("a")),
            [
                "Everything the TV sent followed the order of the pattern.",
                "It sent something in 3 of a typical 45 seconds with the pattern on, and in 1 with it off.",
                "Chance would do that no more than once in 500 runs.",
            ],
        ),
    ],
    ids=["a destination is named before the total", "the total alone, by its uploads"],
)
@pytest.mark.parametrize(
    ("played", "last"),
    [
        (True, "This is what screen recognition looks like. Run the test again to confirm."),
        (False, "Nothing was played, so nothing could follow it: this is the test's own false alarm."),
    ],
    ids=["played", "a dry run"],
)
def test_a_yes_names_what_followed_what_it_sent_and_the_odds_after_correction(findings, said, played, last):
    assert screentest.render(found(*findings), 1, {}, played=played) == [*said, last]


@pytest.mark.parametrize(
    ("nbytes", "size"), [(0, "0 bytes"), (1023, "1023 bytes"), (1024, "1 KB"), (22_600, "22 KB")]
)
def test_a_size_is_in_bytes_below_a_kb_of_1024(nbytes, size):
    assert screentest._size(nbytes) == size


# ---- the dry run -----------------------------------------------------------------------------------------------------
class Gateway:
    """A gateway whose connection table is a stand-in TV's, and whose clock moves when it is slept on and
    while a listing takes `busy` seconds. `faults` says what the tool does at a listing in place of
    answering: the status it ends with, or what it raises."""

    def __init__(
        self, monkeypatch, tmp_path, mode: str = "none", root: bool = True, busy: float = 0.0, faults=None
    ):
        self.tv, self.now, self.busy, self.calls = tvdouble.Double(mode, random.Random(11)), 0.0, busy, []
        self.faults = faults or {}
        self.sent = [0.0] * tvdouble.SERVERS
        self.conf = tmp_path / "tvgw.conf"
        self.conf.write_text(f"TV_IP={tvdouble.TV}\n", encoding="utf-8")
        monkeypatch.setattr(cli.os, "geteuid", lambda: 0 if root else 1000)
        monkeypatch.setattr(cli.random, "SystemRandom", lambda: random.Random(5))
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
        fault = self.faults.get(len(self.calls) - 1)
        if isinstance(fault, BaseException):
            raise fault
        listing = "".join(
            tvdouble.listed(f"198.18.{server}.1", 1, int(sent) + 52, entry=server + 1) + "\n"
            for server, sent in enumerate(self.sent)
            if sent
        )
        return SimpleNamespace(returncode=fault or 0, stdout="" if fault else listing)

    def run(self, *args: str) -> int:
        return cli.main(["--conf", str(self.conf), "screen-test", *args])


@pytest.mark.parametrize(
    ("args", "slots", "minutes"),
    [((), screentest.SLOTS_FAST, 15), (("--general",), screentest.SLOTS_GENERAL, 41)],
    ids=["fast", "general"],
)
def test_a_dry_run_watches_a_runs_length_plays_nothing_and_says_what_it_would_have_caught(
    monkeypatch, tmp_path, capsys, args, slots, minutes
):
    gateway = Gateway(monkeypatch, tmp_path)
    assert gateway.run("--dry-run", *args) == 0
    out = capsys.readouterr().out.splitlines()
    assert (
        out[0] == f"Nothing is played: this is a dry run. It watches what the TV sends for {minutes} minutes."
    )
    assert out[1] == (
        f"Nothing the TV sent followed the picture or the sound: 7 destinations watched for {minutes} minutes."
    )
    assert out[2].startswith("The TV kept sending to 7 of them.") and len(out) == 4
    assert len(gateway.calls) == screentest.seconds_needed(*slots) + 1  # and the first look
    assert set(map(tuple, gateway.calls)) == {(*connpoll.LISTING, tvdouble.TV)}  # the table, and nothing else


def test_a_dry_run_in_which_something_follows_says_it_is_the_tests_own_false_alarm(
    monkeypatch, tmp_path, capsys
):
    """Nothing is played, so nothing can follow. Here the stand-in TV is shown the order all the same, as
    if it could see what was drawn: the run reports it, exits 1, and calls it what it would be."""
    gateway = Gateway(monkeypatch, tmp_path, mode="lg")
    order = screentest.draw_slots(random.Random(5), 20)
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


def test_the_json_form_says_what_the_text_does_in_numbers(monkeypatch, tmp_path, capsys):
    assert Gateway(monkeypatch, tmp_path, faults={3: 1, 4: 1}).run("--dry-run", "--json") == 0
    doc = json.loads(capsys.readouterr().out)
    assert doc.pop("p") > ALPHA
    assert doc == {
        "dry_run": True,
        "slots": 20,
        "width": 45,
        "seconds": 922,
        "destinations": 7,
        "followed": [],
        "active": 7,
        "caught": {"LG": 7, "Samsung": 0},
        "failed": 2,
        "unread": 0,
    }


def test_a_run_that_lost_a_few_listings_says_so_after_its_result(monkeypatch, tmp_path, capsys):
    assert Gateway(monkeypatch, tmp_path, faults={3: 1, 4: 1}).run("--dry-run") == 0
    assert capsys.readouterr().out.splitlines()[-1] == (
        "Along the way 2 listings of the connection table failed and 0 of its lines could not be read; what"
        " was sent then is counted late or not at all."
    )


def test_a_tv_that_sends_nothing_is_no_run(monkeypatch, tmp_path, capsys):
    gateway = Gateway(monkeypatch, tmp_path)
    monkeypatch.setattr(gateway.tv, "step", lambda seen: {})
    assert gateway.run("--dry-run") == 2
    got = capsys.readouterr()
    assert (
        got.err
        == (
            "The TV sent nothing to the internet in 15 minutes, so there was nothing to test. Nothing is"
            " concluded.\n"
        )
        and "followed" not in got.out
    )


@pytest.mark.parametrize(
    ("kw", "args", "said"),
    [
        ({}, (), "Playing is not built yet. --dry-run watches without playing."),
        ({"root": False}, ("--dry-run",), "reading the connection table needs root"),
        (
            {"busy": 1.5},
            ("--dry-run",),
            "The test stopped: the gateway was too busy to look once a second. Nothing is concluded.",
        ),
        (
            {"faults": {0: FileNotFoundError()}},
            ("--dry-run",),
            "The test stopped: the conntrack tool is not installed. Nothing is concluded.",
        ),
        (
            {"faults": {0: 1}},
            ("--dry-run",),
            "The test stopped: the connection table could not be listed. Nothing is concluded.",
        ),
        (
            {"faults": dict.fromkeys(range(100, 200), 1)},
            ("--dry-run",),
            "The test stopped: the connection table could not be listed 47 times. Nothing is concluded.",
        ),
        (
            {"faults": {30: KeyboardInterrupt()}},
            ("--dry-run",),
            "The test was stopped. Nothing is concluded.",
        ),
    ],
    ids=[
        "without --dry-run",
        "without root",
        "on a gateway that cannot keep up",
        "without the tool",
        "when the first listing fails",
        "when too many listings fail",
        "when it is interrupted",
    ],
)
def test_what_the_command_will_not_do_it_says_and_concludes_nothing(
    monkeypatch, tmp_path, capsys, kw, args, said
):
    assert Gateway(monkeypatch, tmp_path, **kw).run(*args) == 2
    got = capsys.readouterr()
    assert said in got.err and "followed" not in got.out
