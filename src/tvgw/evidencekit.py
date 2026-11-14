"""(evidencekit) The arithmetic every judgement needs: how much a count rules out (design decision 97).

A count of nothing says something only beside how much there was to count. Two weeks with no request to a
time server are no evidence for closing the clock port if the TV started four times in them, and a false
revert rate read from placebo trials that share 23 of their 24 hours is one number from about one trial a
day. So each judgement states its events, its exposure in a named unit, the days that exposure fell on,
and the rate the evidence rules out (`Bound`); a share states its Wilson interval (`wilson`); and a rate
read from trials that overlap in time states an interval that resamples whole days (`day_block_bootstrap`).

Pure functions, the standard library only, and no import from tvgw, so any module may use them.
"""

from __future__ import annotations

import math
import random
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass
from statistics import NormalDist

CONF = 0.95  # the confidence every bound and interval is stated at
MIN_DAYS = 7  # local days the exposure must fall on before "nothing happened" may be called clean (Q7)


def wilson(k: int, n: int, conf: float = CONF) -> tuple[float, float]:
    """The Wilson score interval of the share k of n, two-sided at `conf`. Nothing seen (n = 0) rules
    nothing out: (0, 1)."""
    if n <= 0:
        return 0.0, 1.0
    z = NormalDist().inv_cdf(0.5 + conf / 2)
    p = k / n
    d = 1 + z * z / n
    c = p + z * z / (2 * n)
    h = z * math.sqrt(p * (1 - p) / n + z * z / (4 * n * n))
    # min and max with p: rounding at a share of 0 or 1 must not leave the share outside its interval
    return max(0.0, min(p, (c - h) / d)), min(1.0, max(p, (c + h) / d))


def _poisson_cdf(k: int, mean: float) -> float:
    """P(X <= k) for X ~ Poisson(mean), summed in logs so that a large mean does not underflow."""
    logs = [-mean + i * math.log(mean) - math.lgamma(i + 1) for i in range(k + 1)]
    top = max(logs)
    return min(1.0, math.exp(top) * sum(math.exp(x - top) for x in logs))


def poisson_upper(k: int, exposure: float, conf: float = CONF) -> float:
    """The exact one-sided upper limit, at `conf`, of a rate per unit of exposure that gave `k` events:
    the mean at which `k` or fewer would happen only 1 - conf of the time, over the exposure. For k = 0
    it is -ln(1 - conf) / exposure, about 3 / exposure. No exposure bounds nothing: infinity."""
    if exposure <= 0:
        return math.inf
    if k <= 0:
        return -math.log(1 - conf) / exposure
    lo, hi = float(k), 2.0 * k + 10.0
    while _poisson_cdf(k, hi) > 1 - conf:
        lo, hi = hi, 2 * hi
    for _ in range(60):  # bisection: the CDF falls as the mean rises
        mid = (lo + hi) / 2
        if _poisson_cdf(k, mid) > 1 - conf:
            lo = mid
        else:
            hi = mid
    return hi / exposure


@dataclass(frozen=True)
class Bound:
    """What a count rules out: `events` in `exposure` units of `unit` (singular, "start"), and `upper`,
    the most events per unit the count leaves possible at CONF (infinity with no exposure)."""

    events: int
    exposure: float
    unit: str
    upper: float

    def one_in(self) -> int:
        """The rate ruled out as 1 in N units, N rounded down so that it never claims more than the
        count shows; 0 when there is no bound."""
        return 0 if not math.isfinite(self.upper) else math.floor(1 / self.upper)

    def words(self) -> str:
        """`fewer than 1 start in 10`, or `no bound` when the exposure rules out nothing smaller than
        every other unit."""
        n = self.one_in()
        return f"fewer than 1 {self.unit} in {n}" if n >= 2 else "no bound"


def bound(events: int, exposure: float, unit: str, conf: float = CONF) -> Bound:
    """`events` in `exposure` units of `unit`, with the exact upper limit of their rate."""
    return Bound(events, exposure, unit, poisson_upper(events, exposure, conf))


def spread_ok(days_with_exposure: int, min_days: int = MIN_DAYS) -> bool:
    """Whether the exposure fell on enough local days: fourteen hours of one evening are one evening."""
    return days_with_exposure >= min_days


def day_block_bootstrap(
    by_day: Mapping[str, Sequence[float]],
    stat: Callable[[list[float]], float] | None = None,
    draws: int = 2000,
    seed: int = 0,
    conf: float = CONF,
) -> tuple[float, float]:
    """The percentile interval, at `conf`, of `stat` over the values of `by_day`, resampled a whole day at a
    time: values that share a day share its viewer, its outages and its hours, so the day is the unit that
    is independent. `stat` takes the resampled values; None is their mean, read from each day's sum and
    count so that a draw costs a step a day. The same seed gives the same interval. `by_day` must hold at
    least one day."""
    if not by_day:
        raise ValueError("day_block_bootstrap: no day to resample")
    rng = random.Random(seed)
    days = list(by_day.values())
    if stat is None:
        sums = [(sum(day), len(day)) for day in days]

        def draw() -> float:
            picked = rng.choices(sums, k=len(sums))
            n = sum(k for _, k in picked)
            return sum(x for x, _ in picked) / n if n else 0.0
    else:

        def draw() -> float:
            return stat([x for day in rng.choices(days, k=len(days)) for x in day])

    found = sorted(draw() for _ in range(draws))
    tail = (1 - conf) / 2
    return found[round(draws * tail)], found[round(draws * (1 - tail)) - 1]


def binom_tail(k: int, n: int, p: float) -> float:
    """P(X >= k) for X ~ Binomial(n, p), summed in logs: how often chance alone gives k or more of n."""
    if k <= 0:
        return 1.0
    if k > n or p <= 0:
        return 0.0
    if p >= 1:
        return 1.0
    lp, lq = math.log(p), math.log1p(-p)
    logs = [
        math.lgamma(n + 1) - math.lgamma(i + 1) - math.lgamma(n - i + 1) + i * lp + (n - i) * lq
        for i in range(k, n + 1)
    ]
    top = max(logs)
    return min(1.0, math.exp(top) * sum(math.exp(x - top) for x in logs))
