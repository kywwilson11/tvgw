"""(adbreaks) Ad breaks read from the lookups an ad makes (design decision 89): the rule on cases worked
by hand, on a stand-in evening (adbreak_synth.py) and on anything at all; the timers; how long a TV
holds a refusal; the shipped list of advertising firms; and the report's numbers and words."""

import itertools
import random
import statistics

import adbreak_synth as synth
import pytest
from appfront_store import DAY, H0, HDMI, HOUR, NF, PV, YT, Store, power, watched
from hypothesis import given, settings
from hypothesis import strategies as st

from tvgw import adbreaks, appfront, companies, experiments
from tvgw.adbreaks import CHAIN, NEED, TAIL, WINDOW, Break

# four firms; the first has a second domain
FIRMS = {"a.test": "A", "a-cdn.test": "A", "b.test": "B", "c.test": "C", "d.test": "D"}


def refusals(*at: tuple[float, str]) -> list[tuple[float, str]]:
    return sorted(at)


def breaks_of(*at: tuple[float, str], regular: frozenset[str] = frozenset()) -> list[Break]:
    return adbreaks.breaks(adbreaks.labels(refusals(*at), FIRMS, regular))


# ---- the rule ---------------------------------------------------------------------------------------
def test_the_rule_is_the_one_set_before_any_break_was_marked():
    """Three firms in ten seconds open a break, a label within 65 seconds extends it (longer than the
    minute a refusal is held), and it ends 20 seconds after its last. A timer keeps a steady beat (seven
    tenths of its time in gaps up to three times the usual one of their run, a run ending at 45 minutes'
    absence) and comes alone (under half its lookups with two other firms within two seconds), judged
    from 20 gaps and half an hour of them. These were fixed before any break was marked by hand. Change
    one and the report's figures are no longer of the rule design decision 89 records: number a new
    decision first."""
    assert (WINDOW, NEED, CHAIN, TAIL, adbreaks.MERGE) == (10.0, 3, 65.0, 20.0, 5.0)
    assert (adbreaks.TIMER_GAPS, adbreaks.TIMER_SPAN, adbreaks.TIMER_PAUSE) == (20, 1800.0, 2700.0)
    assert (adbreaks.STEADY, adbreaks.STEADY_SHARE, adbreaks.ALONE, adbreaks.COMPANY) == (3.0, 0.70, 0.5, 2.0)


@pytest.mark.parametrize(
    ("at", "breaks"),
    [
        ([(0, "x.a.test"), (4, "b.test"), (WINDOW, "c.test")], [Break(0, WINDOW, 3, 3)]),
        ([(0, "a.test"), (4, "b.test"), (WINDOW + 0.01, "c.test")], []),
        ([(0, "a.test"), (1, "b.test"), (2, "c.test"), (2 + CHAIN, "a.test")], [Break(0, 2 + CHAIN, 3, 4)]),
        ([(0, "a.test"), (1, "b.test"), (2, "c.test"), (2.01 + CHAIN, "d.test")], [Break(0, 2, 3, 3)]),
        ([(0, "x.a.test"), (6, "y.a.test"), (8, "z.a.test"), (9, "b.test")], []),
        ([(0, "a.test"), (6, "a-cdn.test"), (8, "b.test")], []),
        ([(0, "a.test"), (3, "a-cdn.test"), (6, "b.test"), (7, "c.test")], [Break(0, 7, 3, 3)]),
        ([(0, "a.test"), (1, "a.test"), (2, "b.test"), (3, "c.test"), (9, "a.test")], [Break(0, 9, 3, 4)]),
        (
            [(0, "a.test"), (4, "a.test"), (8, "a.test"), (9, "b.test"), (9.5, "c.test")],
            [Break(0, 9.5, 3, 3)],
        ),
        ([(0, "a.test"), (adbreaks.MERGE, "a.test"), (6, "b.test"), (7, "c.test")], [Break(0, 7, 3, 3)]),
        ([(60 * k + d, name) for k in range(6) for d, name in ((0, "a.test"), (0.5, "b.test"))], []),
        ([(0, "a.test"), (1, "b.test"), (2, "other.test"), (3, "sub.c.test")], [Break(0, 3, 3, 3)]),
        (
            [(t0 + d, name) for t0 in (0, 500) for d, name in ((0, "a.test"), (1, "b.test"), (2, "c.test"))],
            [Break(0, 2, 3, 3), Break(500, 502, 3, 3)],
        ),
    ],
    ids=[
        "three firms within the window",
        "the third a moment late",
        "a label at the chain's end extends it",
        "a label a moment later does not, and cannot open one alone",
        "three hosts of one firm are one firm",
        "and so are two domains of one firm",
        "which are one label while the firm is not quiet for five seconds",
        "a firm asked again within five seconds is one label",
        "and stays one while it is asked every four",
        "and at five seconds exactly",
        "two firms asked again every minute, six times",
        "a name no firm owns counts for nothing",
        "two breaks",
    ],
)
def test_a_break_opens_on_three_firms_and_lasts_while_more_follow(at, breaks):
    assert breaks_of(*at) == breaks


def test_a_break_runs_on_for_the_tail_and_a_timer_is_no_label():
    (only,) = breaks_of((0, "a.test"), (1, "b.test"), (2, "c.test"), (30, "d.test"))
    assert only == Break(0, 30, 4, 4) and only.seconds == 30 + TAIL  # a firm that joins later is counted
    assert breaks_of((0, "a.test"), (1, "b.test"), (2, "c.test"), regular=frozenset({"c.test"})) == []


steps = st.lists(
    st.tuples(st.floats(0, 120), st.sampled_from([*FIRMS, "x.a.test", "other.test"])), max_size=60
)


@given(steps)
@settings(max_examples=300, deadline=None, derandomize=True)
def test_whatever_is_refused_the_breaks_are_in_order_apart_and_each_of_three_firms_or_more(gaps):
    at, t = [], 0.0
    for gap, name in gaps:
        t += gap
        at.append((t, name))
    breaks = breaks_of(*at)
    assert all(b.firms >= NEED and b.labels >= b.firms and b.last >= b.start for b in breaks)
    assert all(later.start - earlier.last > CHAIN for earlier, later in itertools.pairwise(breaks))
    # a quiet stretch longer than the chain cuts the record in two that are judged alone
    cut = next((i for i in range(1, len(at)) if at[i][0] - at[i - 1][0] > CHAIN + adbreaks.MERGE), None)
    if cut is not None:
        assert breaks == breaks_of(*at[:cut]) + breaks_of(*at[cut:])


# ---- the stand-in evening ---------------------------------------------------------------------------
def overlap(a: tuple[float, float], b: tuple[float, float]) -> float:
    return max(0.0, min(a[1], b[1]) - max(a[0], b[0]))


def hits(a: tuple[float, float], b: tuple[float, float]) -> bool:
    """Two spans are one break when they share half of the longer: one long "all of it is ads" hits
    nothing."""
    return overlap(a, b) >= 0.5 * max(a[1] - a[0], b[1] - b[0])


def evenings_of(rng: random.Random, n: int, hold: float, called: float = 1.0):
    """`n` stand-in evenings, each beginning at some minute of its eight o'clock hour: (its refused
    lookups, what was shown)."""
    for k in range(n):
        yield synth.evening(rng, H0 + k * DAY + 20 * HOUR + rng.uniform(0, HOUR), hold, called)


def judged(
    hold: float, called: float = 1.0, evenings: int = 100, firms=synth.FIRMS, more=()
) -> dict[str, float]:
    """The rule over stand-in evenings against what was shown, the timers judged over all of them at
    once, as the report judges a window. `more` is refused beside what the evenings hold."""
    nights = list(evenings_of(random.Random(6), evenings, hold, called))
    if more:  # each evening takes the lookups of its own day
        by_day: dict[int, list[tuple[float, str]]] = {}
        for t, name in more:
            by_day.setdefault(int((t - H0) // DAY), []).append((t, name))
        nights = [
            (sorted([*refused, *by_day.get(int((refused[0][0] - H0) // DAY), [])]), shown)
            for refused, shown in nights
        ]
    regular = adbreaks.timers(sorted(lookup for refused, _shown in nights for lookup in refused), firms)
    shown_n = called_n = found_n = shown_hit = called_hit = found_hit = 0
    found_s = shown_s = 0.0
    late = []
    for refused, shown in nights:
        got = adbreaks.breaks(adbreaks.labels(refused, firms, regular))
        spans = [(b.start, b.start + b.seconds) for b in got]
        truth = [(s.start, s.end) for s in shown]
        caught = [any(hits(span, t) for span in spans) for t in truth]
        right = [[t for t in truth if hits(span, t)] for span in spans]
        shown_n, shown_hit = shown_n + len(shown), shown_hit + sum(caught)
        called_n += sum(s.called for s in shown)
        called_hit += sum(c for c, s in zip(caught, shown, strict=True) if s.called)
        found_n, found_hit = found_n + len(got), found_hit + sum(map(bool, right))
        late += [min(abs(span[0] - t[0]) for t in ts) for span, ts in zip(spans, right, strict=True) if ts]
        found_s, shown_s = found_s + sum(e - s for s, e in spans), shown_s + sum(e - s for s, e in truth)
    return {
        "of all": shown_hit / shown_n,
        "of called": called_hit / called_n,
        "are breaks": found_hit / found_n,
        "start": statistics.median(late),
        "minutes": found_s / shown_s,
        "timers": len(regular),
    }


AD_TIMERS = synth.FAST_TIMERS // 2  # the stand-in's timers that are advertising firms' names


@pytest.mark.parametrize(
    ("evenings", "at_least"), [(100, 0.95), (1, 0.85)], ids=["a hundred evenings", "one evening alone"]
)
def test_on_a_tv_that_holds_a_refusal_a_minute_the_rule_finds_the_breaks_the_tv_itself_reports(
    evenings, at_least
):
    """Measured over the hundred evenings, which begin at any minute of an hour: 97% of breaks found, 98%
    of found breaks are breaks, the start 0.07 seconds off at the median, found minutes over shown 1.03.
    One evening alone is enough to know the timers: 10 of its 11 breaks found, and 10 of 11 found are
    breaks."""
    got = judged(hold=60.0, evenings=evenings)
    assert got["of all"] >= at_least and got["are breaks"] >= at_least and got["timers"] == AD_TIMERS
    assert got["start"] < 1.0 and 0.94 <= got["minutes"] <= 1.09


def test_a_break_the_services_own_servers_report_is_not_seen_so_there_may_be_more():
    got = judged(hold=60.0, called=0.5)
    assert got["of called"] >= 0.95 and 0.40 <= got["of all"] <= 0.60 and got["minutes"] < 0.6


@pytest.mark.parametrize(
    ("hold", "found", "minutes"),
    [
        (0.0, 0.96, (1.10, 1.22)),
        (10.0, 0.92, (1.16, 1.29)),
        (120.0, 0.93, (0.91, 1.01)),
        (300.0, 0.89, (0.86, 0.97)),
    ],
    ids=["no hold", "ten seconds", "two minutes", "five minutes"],
)
def test_on_a_tv_that_holds_a_refusal_for_another_time_the_breaks_are_found_and_the_minutes_drift(
    hold, found, minutes
):
    """Measured: with no hold 98% found and minutes 1.16 of shown; at ten seconds 94% and 1.22; at two
    minutes 95% and 0.96; at five minutes 92% and 0.91. Under HOLD_SHORT the report says the minutes may
    run about a quarter long."""
    got = judged(hold=hold)
    assert (
        got["of all"] >= found and minutes[0] <= got["minutes"] <= minutes[1] and got["timers"] == AD_TIMERS
    )


def test_a_service_that_breaks_every_few_minutes_is_read_as_well(monkeypatch):
    """A break every four to seven minutes puts an ad's firms in most five-minute bins, which a count of
    bins would take for timers. Their gaps are a minute inside a break and minutes between, and they come
    together: no timer. Measured: 98% found."""
    monkeypatch.setattr(synth, "BREAK_EVERY", (120.0, 300.0))
    got = judged(hold=60.0)
    assert got["of all"] >= 0.96 and got["are breaks"] >= 0.96 and got["timers"] == AD_TIMERS


def crowded(timers: int, together: int = 1) -> tuple[dict[str, str], list[tuple[float, str]]]:
    """(the stand-in's firms and `timers` more, each a beat of 60 to 75 seconds kept by `together` firms
    at once; their refusals through the hundred evenings `judged` reads)."""
    names = {f"beat.crowd{i}x{j}.test": f"Crowd {i}.{j}" for i in range(timers) for j in range(together)}
    firms = synth.FIRMS | {name.partition(".")[2]: firm for name, firm in names.items()}
    rng = random.Random("the crowd")
    refused = []
    for k in range(100):
        t0 = H0 + k * DAY + 20 * HOUR
        for i in range(timers):
            period = random.Random(f"crowd {i}").uniform(60.0, 75.0)
            for n in range(int((synth.SESSION + HOUR) / period)):
                beat = t0 + rng.uniform(0, 0.3) + n * period
                refused += [(beat + 0.3 * j, f"beat.crowd{i}x{j}.test") for j in range(together)]
    return firms, refused


@pytest.mark.parametrize(
    ("timers", "together", "known", "are_breaks"),
    [(16, 1, 16, 0.94), (1, 2, 2, 0.94), (1, 3, 0, 0.0)],
    ids=["sixteen more timers", "two firms on one beat", "three firms on one beat: the limit"],
)
def test_many_timers_do_not_keep_one_another_company_but_three_firms_on_one_beat_do(
    timers, together, known, are_breaks
):
    """Timers fall within ten seconds of one another by chance, and seldom within two: sixteen more of
    them are each known for one (with company counted within ten seconds, four are enough to turn every
    timer into a label and every evening into one break). Two firms on one beat are alone too. Three
    are one another's company at every turn, and each turn reads as a break: the limit the report's
    pages state. Measured: 97% found and 98% of found are breaks, as without them; 4% with three on one
    beat."""
    firms, more = crowded(timers, together)
    got = judged(hold=60.0, firms=firms, more=more)
    assert got["timers"] == AD_TIMERS + known
    assert got["are breaks"] >= are_breaks and (known or got["are breaks"] < 0.3)


def test_what_is_found_rests_on_the_apps_own_ad_server_being_a_refused_firm():
    """Where it is not, an ad that calls only two measurement firms opens nothing. Measured: 79% found."""
    others = {domain: firm for domain, firm in synth.FIRMS.items() if "appads" not in domain}
    got = judged(hold=60.0, firms=others)
    assert 0.70 <= got["of all"] <= 0.86 and got["are breaks"] >= 0.80


# ---- timers -----------------------------------------------------------------------------------------
def by_rate(refused: list[tuple[float, str]], hours: float) -> frozenset[str]:
    """The test this module does not use: a timer is a name refused ten times an hour or more."""
    return frozenset(
        n for n in {n for _t, n in refused} if sum(1 for _t, m in refused if m == n) >= 10 * hours
    )


@pytest.mark.parametrize("hold", [0.0, 10.0, 60.0])
def test_the_stand_ins_timers_are_told_from_the_apps_own_ad_hosts_which_a_rate_would_drop(hold):
    """The timers are the advertising firms' names on a beat, all of them and no other. Counting lookups
    an hour instead also drops the app's own ad hosts on a TV that holds a refusal for less than a
    minute, and with them most of the label."""
    nights = [refused for refused, _shown in evenings_of(random.Random(8), 5, hold)]
    regular = adbreaks.timers(sorted(lookup for refused in nights for lookup in refused), synth.FIRMS)
    assert regular == {synth.timer(i) for i in range(0, synth.FAST_TIMERS, 2)}
    dropped = sum(
        host in by_rate(refused, synth.SESSION / HOUR) for refused in nights for host in synth.APP_AD_HOSTS
    )
    assert (dropped == 10) == (hold < 60)  # every host of every evening, unless the TV holds a minute


TICK = "tick.a.test"  # a name of firm A


def at(gaps: list[float], name: str = TICK) -> list[tuple[float, str]]:
    """A name refused at H0 and then after each of `gaps`."""
    times = list(itertools.accumulate(gaps, initial=H0))
    return [(t, name) for t in times]


def beside(lookups: list[tuple[float, str]], *names: str, after: float = 1.0) -> list[tuple[float, str]]:
    """`lookups`, and each of `names` refused `after` seconds after each of them."""
    return sorted([*lookups, *((t + after, name) for t, _n in lookups for name in names)])


BURSTS = [60.0, 60.0, 480.0] * 24  # three lookups a minute apart, every ten minutes, for four hours


@pytest.mark.parametrize(
    ("refused", "is_timer"),
    [
        (at([60.0] * 30), True),
        (at([60.0] * 29), False),
        (at([200.0] * 20), True),
        (at([200.0] * 19), False),
        (at(BURSTS), False),
        (at([60.0] * 70 + [600.0] * 3), True),
        (at([60.0] * 69 + [600.0] * 3), False),
        (at([60.0] * 30 + [180.0] * 29), True),
        (at([60.0] * 30 + [181.0] * 29), False),
        (at([60.0] * 40 + [3000.0] + [240.0] * 10), True),
        (at([60.0] * 40 + [2700.0] + [240.0] * 10), False),
        (at([2700.0] * 20), True),
        (at([2701.0] * 40), False),
        (at([60.0] * 30, "tick.other.test"), False),
        (sorted([*at([60.0] * 30), *((t + 0.01, n) for t, n in at([60.0] * 30))]), True),
        (at([4.0, 4.0, 52.0] * 30), True),
        (at([4.0] * 900), False),
    ],
    ids=[
        "every minute for half an hour",
        "for a minute under half an hour",
        "twenty gaps",
        "nineteen",
        "a minute apart in bursts, ten minutes between: not steady",
        "seven tenths of its time in its usual gap",
        "a little under",
        "gaps of three times the usual one are steady",
        "a second more are not",
        "two runs on two beats, an absence between: each steady by its own",
        "the same with a gap of 45 minutes between: one run, and not steady",
        "every 45 minutes",
        "longer absences are no gaps at all",
        "no advertising firm's name",
        "asked for A and AAAA at once",
        "asked three times in eight seconds each minute: one lookup, as a label is one",
        "asked every four seconds for an hour: one lookup with no gap, as it is one label",
    ],
)
def test_a_timer_keeps_a_steady_beat(refused, is_timer):
    assert adbreaks.timers(refused, FIRMS) == (frozenset({refused[0][1]}) if is_timer else frozenset())


@pytest.mark.parametrize(
    ("refused", "is_timer"),
    [
        (beside(at([60.0] * 119), "b.test", "c.test"), False),
        (beside(at([60.0] * 119), "b.test", "c.test", after=adbreaks.COMPANY), False),
        (beside(at([60.0] * 119), "b.test", "c.test", after=-adbreaks.COMPANY), False),
        (beside(at([60.0] * 119), "b.test", "c.test", after=adbreaks.COMPANY + 0.01), True),
        (beside(at([60.0] * 119), "b.test", "c.test", after=-adbreaks.COMPANY - 0.01), True),
        (beside(at([60.0] * 119), "b.test"), True),
        (beside(at([60.0] * 119), "b.test", "a-cdn.test"), True),
        (sorted([*at([60.0] * 119), *beside(at([60.0] * 59), "b.test", "c.test")]), False),
        (sorted([*at([60.0] * 119), *beside(at([60.0] * 58), "b.test", "c.test")]), True),
    ],
    ids=[
        "two other firms beside it every time",
        "two seconds after it",
        "two seconds before it",
        "a moment more than two seconds after is no company",
        "nor a moment more before",
        "one other firm",
        "one other firm and its own second domain",
        "two others beside half of its lookups",
        "beside one fewer than half",
    ],
)
def test_and_a_timer_comes_alone(refused, is_timer):
    """A steady name refused together with two other firms is an ad's name at breaks that come evenly."""
    assert (TICK in adbreaks.timers(refused, FIRMS)) == is_timer


# ---- the hold ---------------------------------------------------------------------------------------
@pytest.mark.parametrize(
    ("gaps", "names", "seconds"),
    [
        ([60.0] * 20, 1, 60.0),
        ([60.0] * 19, 0, None),
        ([0.3, 60.0] * 20, 1, 60.0),
        ([4.0, 60.0] * 20, 1, 60.0),
        ([adbreaks.HOLD_OVER, 60.0] * 20, 1, 60.0),
        ([60.0] * 10 + [4000.0] + [60.0] * 10, 1, 60.0),
        ([adbreaks.HOLD_UNDER] * 20, 0, None),
        ([30.0] + [61.0] * 30, 1, 61.0),
        ([30.0] * 3 + [61.0] * 37, 1, 30.0),
    ],
    ids=[
        "asked again every minute",
        "too few repeats to say",
        "a lookup's own repeat is no gap",
        "nor is one four seconds on",
        "nor one five seconds on exactly",
        "another evening is no gap",
        "a name refused once an hour has none",
        "one early repeat in thirty is not the usual",
        "three in forty are",
    ],
)
def test_the_hold_is_the_shortest_usual_gap_between_a_names_refusals(gaps, names, seconds):
    at, t = [(0.0, "n.test")], 0.0
    for gap in gaps:
        t += gap
        at.append((t, "n.test"))
    assert adbreaks.hold(at) == (names, pytest.approx(seconds))


def test_the_hold_is_the_median_over_names():
    at = [(k * period, name) for name, period in (("a", 50.0), ("b", 60.0), ("c", 300.0)) for k in range(30)]
    assert adbreaks.hold(sorted(at)) == (3, 60.0)


# ---- the shipped list -------------------------------------------------------------------------------
def test_the_shipped_list_is_the_advertising_rows_of_the_shipped_companies():
    header, firms = companies.snapshot(companies.ADFIRMS)
    assert companies.trouble(companies.ADFIRMS) is None and len(firms) > 2000
    assert firms.items() <= companies.snapshot()[1].items()
    assert header["Source"] == companies.snapshot()[0]["Source"]
    # firms an ad on a TV calls are in it; so is a search engine, which is why only refusals are labels
    assert {"doubleclick.net", "adnxs.com", "innovid.com", "google.com"} <= set(firms)
    # a firm that measures audiences is in the first file and not in this one
    assert companies.company("b.scorecardresearch.com") and not companies.company(
        "b.scorecardresearch.com", firms
    )
    assert len(firms) < len(companies.snapshot()[1])
    assert companies.company("s.innovid.com", firms) == firms["innovid.com"]
    assert companies.company("peacocktv.com", firms) is None


# ---- the report -------------------------------------------------------------------------------------
PEACOCK = "com.peacock.tv"
AD = ("s.innovid.com", "ad.doubleclick.net", "ib.adnxs.com")  # three firms of the shipped list


TIMER_BEATS = 48  # four hours of one lookup every five minutes
LONG, SHORT = 2 * 30 + 0.6 + TAIL, 0.6 + TAIL  # a break of three ads, and of one: seconds, at least


def ad_break(store: Store, t: float, ads: int = 1) -> None:
    """`ads` ads from `t`, 30 seconds apart, each calling the three firms within a second."""
    for k in range(ads):
        for i, name in enumerate(AD):
            store.lookup(t + 30 * k + 0.3 * i, name, blocked=1)


@pytest.fixture()
def fortnight(tmp_path):
    """Evenings of four hours: three on Peacock with two breaks each, three on YouTube and one on Netflix
    with none the lookups hold, and one on an input, with a break. Netflix sits behind the screen saver
    for an hour, Prime Video is opened for half an hour, and through two of YouTube's evenings an
    advertising firm's name is refused every five minutes, on a timer."""
    store = Store(tmp_path / "tvgw.db")
    events = []
    for day, app in enumerate([PEACOCK, NF, YT, PEACOCK, YT, PEACOCK, YT, HDMI]):
        t0 = H0 + day * DAY + 20 * HOUR
        events += watched(t0, t0 + 4 * HOUR, (t0, app))
        if app == NF:
            events += [power(t0 + HOUR, "Screen Saver"), power(t0 + 2 * HOUR, "Active")]
        if app == HDMI:
            events += watched(t0 - HOUR, t0 - HOUR / 2, (t0 - HOUR, PV))
        if app in (PEACOCK, HDMI):
            ad_break(store, t0 + 600, ads=3)
        if app == PEACOCK:
            ad_break(store, t0 + 2 * HOUR)
        if app == YT and day < 5:
            for beat in range(TIMER_BEATS):
                store.lookup(t0 + 300 * beat, "beat.criteo.com", blocked=1)
        store.lookup(t0 + 700, "www.google.com", blocked=0)  # a listed name, answered: no label
        store.lookup(t0 + 900, "telemetry.example.test", blocked=1)  # refused, and no firm's
    store.conn.executemany(
        "INSERT INTO tv_events(t, kind, value, detail) VALUES (?, ?, ?, ?)",
        [(e.t, e.kind, e.value, e.detail) for e in events],
    )
    store.conn.commit()
    yield store
    store.conn.close()


def first_day(store: Store) -> dict:
    """The report of the store's first day and the hour after it, in which the evening's session ends."""
    a, b = H0 + HOUR, H0 + DAY + HOUR
    return adbreaks.report(store.conn, experiments.timeline(store.conn, a, b), a, b)


def test_the_report_counts_breaks_by_the_app_in_front_and_says_what_it_cannot_see(fortnight):
    r = experiments.run("adbreaks", fortnight.conn, None, H0 + 9 * DAY, 9, "10.10.10.1")
    assert r["apps"] == [
        {"app": PEACOCK, "hours": 12.0, "breaks": 6, "minutes": pytest.approx(3 * (LONG + SHORT) / 60)},
        {"app": appfront.app_label(YT), "hours": 12.0, "breaks": 0, "minutes": 0.0},
        {"app": appfront.app_label(NF), "hours": 3.0, "breaks": 0, "minutes": 0.0},  # less its idle hour
    ]  # most breaks first, then most hours; and no row for the half hour of Prime Video
    assert r["unknown"] == {"breaks": 1, "minutes": pytest.approx(LONG / 60)}
    ads = 3 * (3 + 1) + 3  # Peacock's three evenings, and the input's one break
    assert (r["breaks"], r["firms"], r["labels"], r["timers"]) == (7, 3, 3 * ads, 1)  # three firms an ad
    assert r["refused"] == r["labels"] + 8 + 2 * TIMER_BEATS  # a telemetry name an evening, and the timer
    assert r["hold"] == {"names": 1, "seconds": 300.0}
    assert r["list"] == {"domains": len(companies.snapshot(companies.ADFIRMS)[1]), "trouble": None}
    assert experiments.RENDER["adbreaks"](r) == [
        "Ad breaks, read from the lookups an ad makes: the last 9 days.",
        "A break is 3 or more advertising firms refused within 10 seconds; it lasts while more follow.",
        "",
        "  com.peacock.tv: 12.0 hours in front, 6 breaks, 0.5 an hour, about 5 minutes of ads",
        "  YouTube (youtube.leanback.v4): 12.0 hours in front, no break seen: if it shows ads, they cannot be"
        " seen this way",
        "  Netflix (netflix): 3.0 hours in front, no break seen (under 10 hours is too few to say)",
        "  With no app known in front: 1 break, about 1 minute of ads",
        "",
        "There may be more: an ad that calls fewer than 3 refused firms is not counted, nor one the service"
        " reports from its own servers.",
        "The minutes are an estimate: a break's start is known to the second, its end to within one ad.",
        "It has not been checked against breaks marked by hand.",
        "This TV asks a refused name again after about 300 seconds (1 name).",
    ]


def test_no_name_the_tv_looked_up_leaves_the_report(fortnight):
    r = experiments.run("adbreaks", fortnight.conn, None, H0 + 9 * DAY, 9, "10.10.10.1")
    said = "\n".join(adbreaks.render(r)) + repr(r)
    assert not any(name in said for name in (*AD, "innovid", "criteo", "telemetry.example.test"))


def test_a_break_is_the_apps_that_was_in_front_when_it_began_and_an_hour_in_front_lists_an_app(tmp_path):
    """A break of three ads begins a minute before the TV changes app: it is the first app's. Each app
    was in front for one hour exactly, which is enough to be listed."""
    store = Store(tmp_path / "tvgw.db")
    t0 = H0 + 20 * HOUR
    store.conn.executemany(
        "INSERT INTO tv_events(t, kind, value, detail) VALUES (?, ?, ?, ?)",
        [
            (e.t, e.kind, e.value, e.detail)
            for e in watched(t0, t0 + 2 * HOUR, (t0, PEACOCK), (t0 + HOUR, YT))
        ],
    )
    ad_break(store, t0 + HOUR - 60, ads=3)
    a, b = H0, H0 + 2 * DAY
    r = adbreaks.report(store.conn, experiments.timeline(store.conn, a, b), a, b)
    store.conn.close()
    assert [(row["app"], row["hours"], row["breaks"]) for row in r["apps"]] == [
        (PEACOCK, 1.0, 1),
        (appfront.app_label(YT), 1.0, 0),
    ]


def test_the_window_takes_a_refusal_at_its_first_second_and_none_at_its_last(tmp_path):
    store = Store(tmp_path / "tvgw.db")
    a, b = H0, H0 + DAY
    for at in (a, b - 2):  # a break in the window's first seconds, and one its end cuts to two labels
        for i, name in enumerate(AD):
            store.lookup(at + i, name, blocked=1)
    r = adbreaks.report(store.conn, experiments.timeline(store.conn, a, b), a, b)
    store.conn.close()
    assert (r["labels"], r["breaks"]) == (3 + 2, 1)


def test_an_apps_hours_leave_out_the_screen_saver_only_where_the_window_holds_it():
    """A session's idle spans are the whole session's. An hour behind the screen saver before the window
    began takes nothing from the hours inside it, and the home screen is no app."""
    session = appfront.Session(
        YT, H0, H0 + 6 * HOUR, appfront.LIVE, idle=[(H0, H0 + HOUR), (H0 + 3 * HOUR, H0 + 3.5 * HOUR)]
    )
    home = appfront.Session("com.webos.app.home", H0 + 6 * HOUR, H0 + 7 * HOUR, appfront.LIVE)
    pieces = [
        appfront.Piece(H0 + 2 * HOUR, H0 + 6 * HOUR, appfront.SESSION, session),
        appfront.Piece(H0 + 6 * HOUR, H0 + 7 * HOUR, appfront.SESSION, home),
    ]
    assert adbreaks.app_seconds(appfront.Timeline(H0 + 2 * HOUR, H0 + 7 * HOUR, pieces)) == {YT: 3.5 * HOUR}


def a_report(**changed) -> dict:
    """A report as `adbreaks.report` hands it over, for the words alone."""
    return {
        "window": [H0, H0 + 14 * DAY],
        "refused": 10,
        "apps": [],
        "unknown": {"breaks": 0, "minutes": 0.0},
        "hold": {"names": 31, "seconds": 60.2},
        "list": {"domains": 2416, "trouble": None},
        "long": 0,
    } | changed


@pytest.mark.parametrize(
    ("row", "line"),
    [
        ((1.0, 2, 3.4), "  A: 1.0 hours in front, 2 breaks, 2.0 an hour, about 3 minutes of ads"),
        ((0.5, 1, 1.2), "  A: 0.5 hours in front, 1 break, about 1 minute of ads"),
        ((2.0, 1, 0.99), "  A: 2.0 hours in front, 1 break, 0.5 an hour, under a minute of ads"),
        (
            (10.0, 0, 0.0),
            "  A: 10.0 hours in front, no break seen: if it shows ads, they cannot be seen this way",
        ),
        ((9.9, 0, 0.0), "  A: 9.9 hours in front, no break seen (under 10 hours is too few to say)"),
    ],
    ids=[
        "a rate from one hour in front",
        "no rate under an hour",
        "never about no minutes",
        "blind at ten hours",
        "too few under ten",
    ],
)
def test_an_apps_line_says_its_hours_its_breaks_and_what_they_allow(row, line):
    hours, breaks, minutes = row
    lines = adbreaks.render(
        a_report(apps=[{"app": "A", "hours": hours, "breaks": breaks, "minutes": minutes}])
    )
    assert lines[3:5] == [line, ""]  # and no line of breaks with no app known, when there was none
    assert lines[-1] == "This TV asks a refused name again after about 60 seconds (31 names)."


@pytest.mark.parametrize(("long", "said"), [(0, False), (1, True), (2, True)], ids=["none", "one", "two"])
def test_a_break_past_ten_minutes_is_said_to_be_one_a_timer_may_have_carried_on(long, said):
    """No break lasts ten minutes. One that long had a name on a beat among its labels, one not yet
    known for a timer."""
    row = {"app": "A", "hours": 2.0, "breaks": 3, "minutes": 40.0}
    lines = adbreaks.render(a_report(apps=[row], long=long))
    breaks = "1 break" if long == 1 else "2 breaks"
    expected = f"  {breaks} above ran past 10 minutes: a name asked on a timer may have carried them on"
    assert (lines[4] == expected) == said and len(lines) == (10 if said else 9)


def test_a_fast_beat_under_half_an_hour_carries_a_break_on_and_the_report_counts_it_long(tmp_path):
    """Three firms open a break, and a fourth firm's name beats every minute for 25 minutes after: too
    short a time to know it for a timer. The break runs as long as the beat, and `long` counts it."""
    store = Store(tmp_path / "tvgw.db")
    for i, name in enumerate(AD):
        store.lookup(H0 + i, name, blocked=1)
    for beat in range(25):
        store.lookup(H0 + 60 * (beat + 1), "beat.criteo.com", blocked=1)
    a, b = H0, H0 + DAY
    r = adbreaks.report(store.conn, experiments.timeline(store.conn, a, b), a, b)
    store.conn.close()
    assert (r["timers"], r["breaks"], r["long"]) == (0, 1, 1) and r["unknown"]["minutes"] > 25


@pytest.mark.parametrize(
    ("seconds", "warned"), [(44.9, True), (adbreaks.HOLD_SHORT, False)], ids=["sooner", "from 45 seconds"]
)
def test_a_tv_that_asks_again_sooner_than_the_rule_is_set_for_is_told_its_minutes_run_long(seconds, warned):
    last = adbreaks.render(a_report(hold={"names": 4, "seconds": seconds}))[-1]
    assert last.startswith(f"This TV asks a refused name again after about {seconds:.0f} seconds (4 names).")
    assert last.endswith("on this TV the minutes may run about a quarter long.") == warned


def test_a_tv_that_asks_again_every_minute_is_said_to_and_a_short_window_is_one_day(fortnight):
    for k in range(30):
        fortnight.lookup(H0 + 20 * HOUR + 60 * k, "beat.example.test", blocked=1)
    r = first_day(fortnight)
    lines = adbreaks.render(r)
    assert lines[0].endswith("the last 1 day.") and r["hold"] == {"names": 1, "seconds": 60.0}
    assert (r["breaks"], r["unknown"]["breaks"]) == (2, 0)  # the later evenings' are outside the window
    assert lines[-1] == "This TV asks a refused name again after about 60 seconds (1 name)."
    assert lines[3] == "  com.peacock.tv: 4.0 hours in front, 2 breaks, 0.5 an hour, about 2 minutes of ads"


@pytest.mark.parametrize(
    ("spoiled", "last"),
    [
        ({"list"}, "The list of advertising firms could not be read: adfirms.txt: gone"),
        ({"refusals"}, "The filter refused nothing in this window, so there is nothing to read."),
        ({"list", "refusals"}, "The list of advertising firms could not be read: adfirms.txt: gone"),
    ],
    ids=["no list", "nothing refused", "neither: the list first"],
)
def test_a_report_with_nothing_to_read_says_which_nothing(fortnight, monkeypatch, spoiled, last):
    if "list" in spoiled:
        monkeypatch.setattr(companies, "_load", lambda data: ({}, {}, f"{data}: gone"))
    if "refusals" in spoiled:
        fortnight.conn.execute("UPDATE dns SET blocked = 0")
    r = first_day(fortnight)
    assert r["breaks"] == 0 and adbreaks.render(r)[-1] == last and len(adbreaks.render(r)) == 3


def test_with_no_app_in_front_for_an_hour_the_report_says_so(tmp_path):
    store = Store(tmp_path / "tvgw.db")
    store.lookup(H0 + 5, "x.example.test", blocked=1)
    r = adbreaks.report(store.conn, experiments.timeline(store.conn, H0, H0 + DAY), H0, H0 + DAY)
    assert adbreaks.render(r)[3] == "  No app was in front for 1 hour or more."
    store.conn.close()
