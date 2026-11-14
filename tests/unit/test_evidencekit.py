"""(evidencekit) The arithmetic every judgement needs (design decision 97): the Wilson interval, the exact
Poisson bound and its words, the spread of the exposure over days, the day-block bootstrap, and the
binomial tail."""

import math
import random

import pytest

from tvgw import evidencekit as ek


@pytest.mark.parametrize(
    ("exposure", "one_in", "words"),
    [
        (14, 4, "fewer than 1 start in 4"),  # 4.67
        (31, 10, "fewer than 1 start in 10"),
        (60, 20, "fewer than 1 start in 20"),  # 20.03: Q7's bar is met at 60
        (59, 19, "fewer than 1 start in 19"),
        (300, 100, "fewer than 1 start in 100"),
        (5, 1, "no bound"),  # 1.67: it rules out nothing smaller than every other start
        (0, 0, "no bound"),
    ],
)
def test_no_event_in_an_exposure_rules_out_one_in_n_rounded_down(exposure, one_in, words):
    b = ek.bound(0, exposure, "start")
    assert (b.one_in(), b.words()) == (one_in, words)


def test_the_bound_with_no_event_is_minus_ln_of_one_less_the_confidence_over_the_exposure():
    assert ek.poisson_upper(0, 14) == pytest.approx(-math.log(0.05) / 14)
    assert ek.poisson_upper(0, 14, conf=0.99) == pytest.approx(-math.log(0.01) / 14)
    assert ek.bound(0, 0, "run").upper == math.inf and ek.poisson_upper(3, 0) == math.inf


@pytest.mark.parametrize(("k", "upper"), [(1, 4.7439), (3, 7.7537), (10, 16.9622), (2000, 2075.0)])
def test_the_exact_upper_limit_with_events_matches_the_chi_square_tables(k, upper):
    """The mean whose CDF at k is 5%: chi-square(0.95, 2k + 2) / 2."""
    assert ek.poisson_upper(k, 1) == pytest.approx(upper, rel=2e-3 if k == 2000 else 1e-4)
    assert ek.poisson_upper(k, 10) == pytest.approx(upper / 10, rel=2e-3)


def test_the_upper_limit_holds_at_a_confidence_beyond_the_first_guess():
    """At 99.999% one event's limit is past the search's first upper end: the search widens first."""
    mean = ek.poisson_upper(1, 1, conf=0.99999)
    assert mean > 12 and math.exp(-mean) * (1 + mean) == pytest.approx(1e-5)


@pytest.mark.parametrize("k", [0, 1, 4, 30])
def test_poisson_upper_falls_as_the_exposure_grows(k):
    found = [ek.poisson_upper(k, e) for e in (1, 2, 10, 100, 1000)]
    assert found == sorted(found, reverse=True) and len(set(found)) == len(found)


@pytest.mark.parametrize(("k", "n"), [(0, 1), (0, 40), (1, 3), (23, 24), (40, 40), (17, 1000), (500, 1000)])
def test_the_wilson_interval_holds_the_share_and_stays_in_zero_to_one(k, n):
    lo, hi = ek.wilson(k, n)
    assert 0 <= lo <= k / n <= hi <= 1 and lo < hi
    lo99, hi99 = ek.wilson(k, n, conf=0.99)
    assert lo99 <= lo and hi99 >= hi and hi99 - lo99 > hi - lo  # a surer interval is wider


def test_the_wilson_interval_of_known_shares():
    assert ek.wilson(23, 24)[0] == pytest.approx(0.7976, abs=1e-4)  # L2-15's 95.8%
    assert ek.wilson(35, 35)[0] >= 0.90 > ek.wilson(34, 34)[0]  # no miss in 35 asserts 90%
    assert ek.wilson(0, 0) == (0.0, 1.0)


@pytest.mark.parametrize(("days", "ok"), [(6, False), (7, True), (14, True), (0, False)])
def test_the_exposure_must_fall_on_seven_days(days, ok):
    assert ek.spread_ok(days) is ok


def by_day(seed: int = 1, days: int = 30) -> dict[str, list[float]]:
    rng = random.Random(seed)
    return {f"d{d}": [float(rng.random() < 0.2) for _ in range(rng.randint(1, 24))] for d in range(days)}


def test_the_day_block_bootstrap_is_reproducible_for_a_seed_and_holds_the_share():
    data = by_day()
    share = sum(map(sum, data.values())) / sum(map(len, data.values()))
    lo, hi = ek.day_block_bootstrap(data)
    assert lo < share < hi and ek.day_block_bootstrap(data) == (lo, hi)
    assert ek.day_block_bootstrap(data, seed=1) != (lo, hi)
    assert ek.day_block_bootstrap(data, draws=4000, conf=0.99) != (lo, hi)


def test_a_stat_of_the_resampled_values_draws_the_same_days_as_the_mean():
    data = by_day()
    mean = ek.day_block_bootstrap(data, lambda xs: sum(xs) / len(xs), draws=500)
    assert mean == pytest.approx(ek.day_block_bootstrap(data, draws=500))
    assert ek.day_block_bootstrap(data, max, draws=50) == (1.0, 1.0)
    assert ek.day_block_bootstrap({"d": []}, draws=10) == (0.0, 0.0)


def test_the_day_block_bootstrap_needs_a_day():
    with pytest.raises(ValueError, match="no day"):
        ek.day_block_bootstrap({})


def test_resampling_whole_days_widens_the_interval_of_values_that_cluster_by_day():
    """Trials an hour apart share a day: 30 days that are all bad or all good are 30 units, not 720."""
    clustered = {f"d{d}": [float(d % 5 == 0)] * 24 for d in range(30)}
    lo, hi = ek.day_block_bootstrap(clustered)
    flat_lo, flat_hi = ek.wilson(6 * 24, 30 * 24)
    assert hi - lo > 2 * (flat_hi - flat_lo)


@pytest.mark.parametrize(
    ("k", "n", "p", "tail"),
    [
        (0, 5, 0.5, 1.0),
        (6, 5, 0.5, 0.0),
        (3, 3, 0.5, 0.125),
        (2, 3, 0.5, 0.5),
        (1, 10, 0.0, 0.0),
        (1, 10, 1.0, 1.0),
        (3, 10, 0.1, 0.0702),
        (60, 100, 0.5, 0.0284),
    ],
)
def test_the_binomial_tail_is_the_chance_of_k_or_more(k, n, p, tail):
    assert ek.binom_tail(k, n, p) == pytest.approx(tail, abs=1e-4)


def test_the_binomial_tail_of_a_large_n_does_not_underflow():
    assert ek.binom_tail(520, 1000, 0.5) == pytest.approx(0.1087, abs=1e-3)
    assert 0 < ek.binom_tail(900, 1000, 0.5) < 1e-100
