"""(screentest) The screen test's kernel (design decision 88): does anything the TV sends follow what is
on its screen? Pure arithmetic over series of numbers; it reads no clock, no socket and no store.

Screen recognition is looked for today by name, by port, and by how much goes up against how much comes
down. A client under another name, on an ordinary port, inside a connection that returns as much as it
sends, passes all three. What it cannot hide is that it reports what is on the screen.

So the test decides what is on the screen. A run is `n` slots of `width` seconds. Half of them, chosen
uniformly at random when the run starts, show a moving picture with sound ("on"); the rest are black and
silent. For one destination, each slot's value is what the TV sent there in the slot's seconds, moved a
`lag` later, since an upload reports what was on the screen before it. The statistic is the rank sum of
the on slots' values, one-sided: more is sent while the pattern plays.

**Why the answer can be trusted whatever the traffic.** If the TV would have sent the same whatever was
played, the slot values are fixed numbers and the on label fell on a random half of them. How often a
random half ranks as high as the half that was on is then a matter of counting, and `rank_test` counts
it: every choice of half, ties included, no simulation and no assumption that traffic is steady or that
one second is independent of the next. The p-values of every destination, reading and lag are corrected
together (Holm), so a run in which nothing follows the picture reports something at level ALPHA in at
most ALPHA of runs.

**Two readings** of each series: the bytes sent, where a large upload shows through heavy traffic, and
the number of seconds with an upload in them, where a small regular one shows among a few irregular
ones. **Two lags:** a quarter of a slot for a prompt client and a half for a slow one.

**What a "no" is worth** is measured in the run itself: `sensitivity` plants an upload of a known shape
in each destination the TV kept sending to, on the run's own slots, and counts where the test would have
caught it.
"""

from __future__ import annotations

import random
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, replace
from functools import lru_cache

ALPHA = 0.01  # the chance a run with nothing to find reports something
MAX_SLOTS = 64  # the counting below keeps each count in 64 bits, and C(64, 32) is the largest that fits
SLOTS_FAST = (20, 45)  # slots, and seconds each: for a client that reports about every 14 seconds
SLOTS_GENERAL = (20, 120)  # for one that reports about once a minute
EVENT_BYTES = 200  # a second counts as an upload from this much payload
ACTIVE_SLOTS = 3  # slots the TV must have sent to a destination in for an upload to be hidden there
BYTES, UPLOADS = "bytes", "uploads"
READINGS = (BYTES, UPLOADS)
TOTAL = "total"  # the series of everything the TV sent: watched, and no destination
# seconds between uploads, and bytes in each, of the two clients published measurements describe: what
# `sensitivity` plants. LG's are the medians measured; Samsung's is its 2.5 KB a minute as one upload.
# docs/research/screen-test.md cites the numbers
SHAPES = {"LG": (13.9, 22_600.0), "Samsung": (60.0, 2_600.0)}


def draw_slots(rng: random.Random, n: int) -> list[bool]:
    """`n` slots, exactly half of them on, every such choice equally likely. In use `rng` is
    random.SystemRandom: the order must be one nothing could have known."""
    if n < 2 or n % 2 or n > MAX_SLOTS:
        raise ValueError(f"the number of slots must be even, from 2 to {MAX_SLOTS}")
    slots = [True] * (n // 2) + [False] * (n // 2)
    rng.shuffle(slots)
    return slots


def default_lags(width: int) -> tuple[int, ...]:
    return (width // 4, width // 2)


def seconds_needed(n: int, width: int) -> int:
    """How long a run's series must be: its slots, and the longest lag after the last."""
    return n * width + max(default_lags(width))


def slot_values(series: Sequence[float], width: int, n: int, lag: int) -> list[float]:
    """What was sent in each slot's seconds, `lag` seconds later."""
    if len(series) < n * width + lag:
        raise ValueError(f"the series has {len(series)} seconds; {n * width + lag} are needed")
    return [sum(series[k * width + lag : (k + 1) * width + lag]) for k in range(n)]


def _doubled_midranks(values: Sequence[float]) -> list[int]:
    """Twice each value's rank, equal values sharing the mean of theirs: twice, so that ties stay whole."""
    order = sorted(range(len(values)), key=values.__getitem__)
    ranks = [0] * len(values)
    first = 0
    while first < len(order):
        last = first
        while last + 1 < len(order) and values[order[last + 1]] == values[order[first]]:
            last += 1
        for k in range(first, last + 1):
            ranks[order[k]] = first + last + 2  # twice the mean of the ranks first + 1 to last + 1
        first = last + 1
    return ranks


@lru_cache(maxsize=4096)
def _rank_sum_counts(ranks: tuple[int, ...], m: int) -> tuple[int, ...]:
    """counts[s]: how many choices of `m` of the slots have ranks that sum to s. One integer for each
    number of slots chosen holds its counts side by side in 64-bit fields, so taking one more slot into
    account is a shift and an add."""
    chosen = [1] + [0] * m  # chosen[c]: the counts for c slots taken, among the slots read so far
    for rank in ranks:
        for c in range(m, 0, -1):
            chosen[c] += chosen[c - 1] << (rank * 64)
    top = sum(sorted(ranks)[-m:]) if m else 0
    return tuple((chosen[m] >> (s * 64)) & (2**64 - 1) for s in range(top + 1))


def rank_test(values: Sequence[float], on: Sequence[bool]) -> float:
    """The exact one-sided p: of every way to call half the slots on, the share whose rank sum is at
    least the one observed."""
    if len(values) != len(on) or len(on) > MAX_SLOTS:
        raise ValueError(f"one value for each slot, and at most {MAX_SLOTS} slots")
    ranks = _doubled_midranks(values)
    observed = sum(rank for rank, lit in zip(ranks, on, strict=True) if lit)
    counts = _rank_sum_counts(tuple(sorted(ranks)), sum(on))
    return sum(counts[observed:]) / sum(counts)


def read_as(series: Sequence[float], name: str) -> Sequence[float]:
    """A series in one of READINGS."""
    if name == BYTES:
        return series
    if name == UPLOADS:
        return [1.0 if sent >= EVENT_BYTES else 0.0 for sent in series]
    raise ValueError(f"no such reading: {name}")


@dataclass(frozen=True)
class Finding:
    """The test that speaks loudest for one destination."""

    key: str
    p: float  # corrected over every destination, reading and lag of the run
    raw: float  # the test's own p
    reading: str
    lag: int
    on_median: float  # the reading in a slot that was on, and in one that was off, at that lag
    off_median: float


@dataclass(frozen=True)
class Result:
    p: float  # the smallest corrected p: whether anything, anywhere, followed the pattern
    findings: tuple[Finding, ...]  # one for each series, the most followed first
    tests: int
    slots: int
    width: int
    seconds: int  # how long the series had to be: the slots, and the longest lag after the last

    def followed(self) -> tuple[Finding, ...]:
        """The series that followed the pattern at level ALPHA."""
        return tuple(f for f in self.findings if f.p <= ALPHA)

    def destinations(self) -> int:
        return sum(1 for f in self.findings if f.key != TOTAL)


def _median(values: Sequence[float]) -> float:
    ordered = sorted(values)
    return (ordered[(len(ordered) - 1) // 2] + ordered[len(ordered) // 2]) / 2 if ordered else 0.0


def score(
    series: Mapping[str, Sequence[float]],
    on: Sequence[bool],
    width: int,
    lags: Sequence[int] | None = None,
    readings: Sequence[str] = READINGS,
) -> Result:
    """Every series against the slots. `series[key][t]` is what the TV sent `key` in second t, from the
    first slot's first second to the longest lag after the last slot's end."""
    lags = default_lags(width) if lags is None else lags
    n = len(on)
    tests: list[Finding] = []  # each with its own p in both places, until the correction below
    for key in sorted(series):
        for name in readings:
            read = read_as(series[key], name)
            for lag in lags:
                values = slot_values(read, width, n, lag)
                on_values = [v for v, is_on in zip(values, on, strict=True) if is_on]
                off_values = [v for v, is_on in zip(values, on, strict=True) if not is_on]
                p = 1.0 if max(values) == min(values) else rank_test(values, on)  # nothing varies
                tests.append(Finding(key, p, p, name, lag, _median(on_values), _median(off_values)))
    # Holm: the smallest p is multiplied by the number of tests, the next by one less, and no corrected
    # value is below the one before it
    best: dict[str, Finding] = {}
    floor = 0.0
    for place, test in enumerate(sorted(tests, key=lambda test: test.raw)):
        floor = max(floor, min(1.0, test.raw * (len(tests) - place)))
        if test.key not in best:  # a key's first is its smallest
            best[test.key] = replace(test, p=floor)
    findings = tuple(sorted(best.values(), key=lambda f: (f.p, f.raw, f.key)))
    return Result(findings[0].p if findings else 1.0, findings, len(tests), n, width, n * width + max(lags))


def planted(
    series: Sequence[float], on: Sequence[bool], width: int, period: float, size: float, rng: random.Random
) -> list[float]:
    """`series` with an upload of `size` bytes every `period` seconds wherever the `period` before it was
    mostly on: what a client that reports the screen would have added to this destination in this run."""
    out = list(series)
    t = rng.uniform(0, period)
    while t < len(out):
        start, end = max(0, int(t - period)), max(1, int(t))
        lit = sum(1 for second in range(start, end) if second // width < len(on) and on[second // width])
        if lit * 2 >= end - start:
            out[int(t)] += size
        t += period
    return out


def active(series: Mapping[str, Sequence[float]], width: int, n: int) -> list[str]:
    """The destinations the TV sent something to in ACTIVE_SLOTS slots or more. One that got a single
    packet once is no place to hide an upload, and finding one planted there says nothing of the run."""
    busy = []
    for key, sent in series.items():
        if key != TOTAL and sum(1 for value in slot_values(sent, width, n, 0) if value) >= ACTIVE_SLOTS:
            busy.append(key)
    return busy


def sensitivity(
    series: Mapping[str, Sequence[float]], on: Sequence[bool], width: int, rng: random.Random
) -> tuple[int, dict[str, int]]:
    """(the active destinations, and for each of SHAPES in how many of them the run would have caught an
    upload of that shape). The upload is planted in one destination at a time, and in the total with it
    where the run has one, and the whole run is scored again."""
    busy = active(series, width, len(on))
    caught = dict.fromkeys(SHAPES, 0)
    for shape, (period, size) in SHAPES.items():
        for key in busy:
            with_it = planted(series[key], on, width, period, size, rng)
            again = {**series, key: with_it}
            if TOTAL in series:
                again[TOTAL] = [
                    t + a - b for t, a, b in zip(series[TOTAL], with_it, series[key], strict=True)
                ]
            caught[shape] += any(f.key == key for f in score(again, on, width).followed())
    return len(busy), caught


def minutes(seconds: float) -> int:
    """A run's length as its banner and its result both give it."""
    return round(seconds / 60)


def _size(nbytes: float) -> str:
    """A size as a reader takes it: KB are 1,024 bytes."""
    return f"{nbytes / 1024:.0f} KB" if nbytes >= 1024 else f"{nbytes:.0f} bytes"


def _count(n: int, word: str) -> str:
    return f"{n} {word}" + ("" if n == 1 else "s")


def render(result: Result, weighed: int, caught: Mapping[str, int], played: bool = True) -> list[str]:
    """The result in the words of a user page. `weighed` and `caught` are `sensitivity`'s. A run in which
    nothing followed always carries its last line: a "no" is not "this TV has no screen recognition"."""
    followed = result.followed()
    hits = [f for f in followed if f.key != TOTAL] or list(followed)  # a destination before the total
    if not hits:
        watched = _count(result.destinations(), "destination")
        would = ", ".join(f"{shape}'s in {count} of {weighed}" for shape, count in caught.items())
        return [
            f"Nothing the TV sent followed the picture or the sound: {watched} watched for"
            f" {minutes(result.seconds)} minutes.",
            f"The TV kept sending to {weighed} of them. Had a known upload been hidden in what one of them"
            f" was sent, this run would have caught it: {would}."
            if weighed
            else "The TV kept sending to none of them, so this run cannot say what it would have caught.",
            "A TV that reports on a timer whatever is on the screen, or that sends later, would look the"
            " same.",
        ]
    top = hits[0]
    where = "everything the TV sent" if top.key == TOTAL else f"what the TV sent to {top.key}"
    if top.reading == BYTES:
        sent = f"about {_size(top.on_median)} in a typical {result.width} seconds with the pattern on"
        dark = f"{_size(top.off_median)} in a typical {result.width} seconds with it off"
    else:
        sent = f"something in {top.on_median:.0f} of a typical {result.width} seconds with the pattern on"
        dark = f"in {top.off_median:.0f} with it off"
    lines = [
        f"{where[0].upper()}{where[1:]} followed the order of the pattern.",
        f"It sent {sent}, and {dark}.",
        f"Chance would do that no more than once in {int(1 / max(top.p, 1e-12)):,} runs.",
    ]
    if played:
        return [*lines, "This is what screen recognition looks like. Run the test again to confirm."]
    return [*lines, "Nothing was played, so nothing could follow it: this is the test's own false alarm."]
