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

FIRMS = {"a.test": "A", "b.test": "B", "c.test": "C", "d.test": "D"}


def refusals(*at: tuple[float, str]) -> list[tuple[float, str]]:
    return sorted(at)


def found(*at: tuple[float, str], regular: frozenset[str] = frozenset()) -> list[Break]:
    return adbreaks.breaks(adbreaks.labels(refusals(*at), FIRMS, regular))


# ---- the rule ---------------------------------------------------------------------------------------
def test_the_rule_is_the_one_set_before_any_break_was_marked():
    """Three firms in ten seconds open a break, a label within 45 seconds extends it, and it ends 20
    seconds after its last. These were fixed on 2026-11-12 from the design's simulation alone. Change
    one and the report's figures are no longer of the rule the design decision records: number a new
    decision first."""
    assert (WINDOW, NEED, CHAIN, TAIL, adbreaks.MERGE) == (10.0, 3, 45.0, 20.0, 5.0)
    assert (adbreaks.TIMER_BIN, adbreaks.TIMER_SHARE, adbreaks.TIMER_HOURS) == (300.0, 0.70, 2)


@pytest.mark.parametrize(
    ("at", "breaks"),
    [
        ([(0, "x.a.test"), (4, "b.test"), (WINDOW, "c.test")], [Break(0, WINDOW, 3, 3)]),
        ([(0, "a.test"), (4, "b.test"), (WINDOW + 0.01, "c.test")], []),
        ([(0, "a.test"), (1, "b.test"), (2, "c.test"), (2 + CHAIN, "a.test")], [Break(0, 2 + CHAIN, 3, 4)]),
        ([(0, "a.test"), (1, "b.test"), (2, "c.test"), (2.01 + CHAIN, "d.test")], [Break(0, 2, 3, 3)]),
        ([(0, "x.a.test"), (6, "y.a.test"), (8, "z.a.test"), (9, "b.test")], []),
        ([(0, "a.test"), (1, "a.test"), (2, "b.test"), (3, "c.test"), (9, "a.test")], [Break(0, 9, 3, 4)]),
        (
            [(0, "a.test"), (4, "a.test"), (8, "a.test"), (9, "b.test"), (9.5, "c.test")],
            [Break(0, 9.5, 3, 3)],
        ),
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
        "a firm asked again within five seconds is one label",
        "and stays one while it is asked every four",
        "two firms asked again every minute, six times",
        "a name no firm owns counts for nothing",
        "two breaks",
    ],
)
def test_a_break_opens_on_three_firms_and_lasts_while_more_follow(at, breaks):
    assert found(*at) == breaks


def test_a_break_runs_on_for_the_tail_and_a_timer_is_no_label():
    (only,) = found((0, "a.test"), (1, "b.test"), (2, "c.test"), (30, "d.test"))
    assert only == Break(0, 30, 4, 4) and only.seconds == 30 + TAIL  # a firm that joins later is counted
    assert found((0, "a.test"), (1, "b.test"), (2, "c.test"), regular=frozenset({"c.test"})) == []


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
    breaks = found(*at)
    assert all(b.firms >= NEED and b.labels >= b.firms and b.last >= b.start for b in breaks)
    assert all(later.start - earlier.last > CHAIN for earlier, later in itertools.pairwise(breaks))
    # a quiet stretch longer than the chain cuts the record in two that are judged alone
    cut = next((i for i in range(1, len(at)) if at[i][0] - at[i - 1][0] > CHAIN + adbreaks.MERGE), None)
    if cut is not None:
        assert breaks == found(*at[:cut]) + found(*at[cut:])


# ---- the stand-in evening ---------------------------------------------------------------------------
def overlap(a: tuple[float, float], b: tuple[float, float]) -> float:
    return max(0.0, min(a[1], b[1]) - max(a[0], b[0]))


def hits(a: tuple[float, float], b: tuple[float, float]) -> bool:
    """Two spans are one break when they share half of the longer: one long "all of it is ads" hits
    nothing."""
    return overlap(a, b) >= 0.5 * max(a[1] - a[0], b[1] - b[0])


def judged(hold: float, called: float, evenings: int = 100) -> dict[str, float]:
    """The rule over `evenings` stand-in evenings against what was shown."""
    rng = random.Random(6)
    shown_n = called_n = found_n = shown_hit = called_hit = found_hit = 0
    found_s = shown_s = 0.0
    late = []
    for k in range(evenings):
        refused, shown = synth.evening(rng, H0 + k * DAY, hold, called)
        got = adbreaks.breaks(adbreaks.labels(refused, synth.FIRMS, adbreaks.timers(refused)))
        spans = [(b.start, b.start + b.seconds) for b in got]
        truth = [(s.start, s.end) for s in shown]
        caught = [any(hits(span, t) for span in spans) for t in truth]
        shown_n, shown_hit = shown_n + len(shown), shown_hit + sum(caught)
        called_n += sum(s.called for s in shown)
        called_hit += sum(c for c, s in zip(caught, shown, strict=True) if s.called)
        found_n, found_hit = (
            found_n + len(got),
            found_hit + sum(any(hits(span, t) for t in truth) for span in spans),
        )
        late += [
            min(abs(span[0] - t[0]) for t in truth if hits(span, t))
            for span in spans
            if any(hits(span, t) for t in truth)
        ]
        found_s, shown_s = found_s + sum(e - s for s, e in spans), shown_s + sum(e - s for s, e in truth)
    return {
        "of all": shown_hit / shown_n,
        "of called": called_hit / called_n,
        "are breaks": found_hit / found_n,
        "start": statistics.median(late),
        "minutes": found_s / shown_s,
    }


def test_on_a_tv_that_holds_a_refusal_a_minute_the_rule_finds_the_breaks_the_tv_itself_reports():
    """Measured at the first build over 200 evenings: 94% of breaks found, 88% of found breaks are
    breaks, the start 0.06 seconds off at the median, found minutes over shown 1.00."""
    got = judged(hold=60.0, called=1.0)
    assert got["of all"] >= 0.90 and got["are breaks"] >= 0.85
    assert got["start"] < 1.0 and 0.9 <= got["minutes"] <= 1.1


def test_a_break_the_services_own_servers_report_is_not_seen_which_is_why_the_figure_is_a_floor():
    got = judged(hold=60.0, called=0.5)
    assert got["of called"] >= 0.90 and 0.40 <= got["of all"] <= 0.60 and got["minutes"] < 0.7


# ---- timers -----------------------------------------------------------------------------------------
def by_rate(refused: list[tuple[float, str]], hours: float) -> frozenset[str]:
    """The test this module does not use: a timer is a name refused ten times an hour or more."""
    return frozenset(
        n for n in {n for _t, n in refused} if sum(1 for _t, m in refused if m == n) >= 10 * hours
    )


@pytest.mark.parametrize("hold", [0.0, 10.0, 60.0])
def test_a_timer_is_told_by_being_there_whatever_is_on_and_an_apps_ad_host_is_kept(hold):
    """A name asked on a timer is in nearly every five minutes; an ad host is only in those with a
    break. Counting lookups an hour instead also drops the app's own ad hosts on a TV that holds a
    refusal for less than a minute, and with them most of the label."""
    rng = random.Random(8)
    kept = timers_seen = hosts_kept = hosts_by_rate = 0
    for k in range(40):
        refused, _shown = synth.evening(rng, H0 + k * DAY, hold)
        regular = adbreaks.timers(refused)
        fast = {synth.timer(i) for i in range(synth.FAST_TIMERS)}
        timers_seen, kept = timers_seen + len(fast), kept + len(fast - regular)
        hosts_kept += sum(host not in regular for host in synth.APP_AD_HOSTS)
        hosts_by_rate += sum(
            host not in by_rate(refused, synth.SESSION / HOUR) for host in synth.APP_AD_HOSTS
        )
    assert kept <= 0.02 * timers_seen and hosts_kept >= 0.9 * 80  # measured: 3 of 640, and 76 to 80 of 80
    assert hosts_by_rate == 0 if hold < 60 else hosts_by_rate > 0


@pytest.mark.parametrize(
    ("hours", "share", "is_timer"),
    [(2, 0.75, True), (2, 0.5, False), (1, 1.0, False), (6, 0.75, True)],
    ids=["most bins of two hours", "half of them", "every bin of one hour", "most bins of six hours"],
)
def test_a_timer_is_in_seven_tenths_of_the_five_minute_bins_of_two_clock_hours_or_more(
    hours, share, is_timer
):
    refused = [
        (H0 + h * HOUR + b * 300 + 1, "tick.test") for h in range(hours) for b in range(round(12 * share))
    ]
    assert adbreaks.timers(refused) == (frozenset({"tick.test"}) if is_timer else frozenset())


# ---- the hold ---------------------------------------------------------------------------------------
@pytest.mark.parametrize(
    ("gaps", "names", "seconds"),
    [
        ([60.0] * 20, 1, 60.0),
        ([60.0] * 19, 0, None),
        ([0.3, 60.0] * 20, 1, 60.0),
        ([60.0] * 10 + [4000.0] + [60.0] * 10, 1, 60.0),
        ([4000.0] * 20, 0, None),
        ([30.0] + [61.0] * 30, 1, 61.0),
    ],
    ids=[
        "asked again every minute",
        "too few repeats to say",
        "a lookup's own repeat is no gap",
        "another evening is no gap",
        "a name refused once an evening has none",
        "one early repeat is not the usual",
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


def ad_break(store: Store, t: float, ads: int = 1) -> None:
    """`ads` ads from `t`, 30 seconds apart, each calling the three firms within a second."""
    for k in range(ads):
        for i, name in enumerate(AD):
            store.lookup(t + 30 * k + 0.3 * i, name, blocked=1)


@pytest.fixture()
def fortnight(tmp_path):
    """Evenings of four hours: three on Peacock with two breaks each, three on YouTube and one on Netflix
    with none the lookups hold, and one on an input, with a break. Netflix sits behind the screen saver
    for an hour, and Prime Video is opened for half an hour."""
    store = Store(tmp_path / "tvgw.db")
    events = []
    for day, app in enumerate([PEACOCK, YT, PEACOCK, YT, PEACOCK, YT, NF, HDMI]):
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
    now = H0 + 9 * DAY
    r = experiments.run("adbreaks", fortnight.conn, None, now, 9, "10.10.10.1")
    assert r["apps"] == [
        {"app": PEACOCK, "hours": 12.0, "breaks": 6, "minutes": pytest.approx(3 * (80.6 + 20.6) / 60)},
        {"app": appfront.app_label(YT), "hours": 12.0, "breaks": 0, "minutes": 0.0},
        {"app": appfront.app_label(NF), "hours": 3.0, "breaks": 0, "minutes": 0.0},  # less its idle hour
    ]  # and no row for the half hour of Prime Video
    assert r["unknown"] == {"breaks": 1, "minutes": pytest.approx(80.6 / 60)}
    assert (r["breaks"], r["firms"], r["labels"], r["timers"]) == (
        7,
        3,
        15 * 3,
        0,
    )  # fifteen ads, three firms each
    assert r["refused"] == r["labels"] + 8 and r["hold"] == {"names": 0, "seconds": None}
    assert r["list"] == {"domains": len(companies.snapshot(companies.ADFIRMS)[1]), "trouble": None}
    assert experiments.RENDER["adbreaks"](r) == [
        "Ad breaks, read from the lookups an ad makes: the last 9 days.",
        "A break is 3 or more advertising firms' names refused within 10 seconds; it lasts while more follow.",
        "",
        "  com.peacock.tv: 12.0 hours in front, 6 breaks, 0.5 an hour, at least 5 minutes of ads",
        "  YouTube (youtube.leanback.v4): 12.0 hours in front, no break seen: if it shows ads, they cannot be"
        " seen this way",
        "  Netflix (netflix): 3.0 hours in front, no break seen (under 10 hours is too few to say)",
        "  With no app known in front: 1 break, at least 1 minute of ads",
        "",
        "This is a floor. An ad that calls fewer than 3 refused firms is not counted, and a break's end is"
        " known only to within one ad.",
        "It has not been checked against breaks marked by hand.",
        "Too few names were refused often enough to say how long this TV waits before it asks again.",
    ]
    said = "\n".join(experiments.RENDER["adbreaks"](r)) + repr(r)
    assert not any(name in said for name in (*AD, "innovid", "telemetry.example.test"))  # no name leaves it


def test_a_tv_that_asks_again_every_minute_is_said_to_and_a_short_window_is_one_day(fortnight):
    for k in range(30):
        fortnight.lookup(H0 + 20 * HOUR + 60 * k, "beat.example.test", blocked=1)
    r = first_day(fortnight)
    lines = adbreaks.render(r)
    assert lines[0].endswith("the last 1 day.") and r["hold"] == {"names": 1, "seconds": 60.0}
    assert (r["breaks"], r["unknown"]["breaks"]) == (2, 0)  # the later evenings' are outside the window
    assert lines[-1] == "This TV asks a refused name again after about 60 seconds (1 name)."
    assert (
        lines[3] == "  com.peacock.tv: 4.0 hours in front, 2 breaks, 0.5 an hour, at least 2 minutes of ads"
    )


@pytest.mark.parametrize(
    ("spoil", "last"),
    [
        ("list", "The list of advertising firms could not be read: adfirms.txt: gone"),
        ("refusals", "The filter refused nothing in this window, so there is nothing to read."),
    ],
)
def test_a_report_with_nothing_to_read_says_which_nothing(fortnight, monkeypatch, spoil, last):
    if spoil == "list":
        monkeypatch.setattr(companies, "_load", lambda data: ({}, {}, f"{data}: gone"))
    else:
        fortnight.conn.execute("UPDATE dns SET blocked = 0")
    r = first_day(fortnight)
    assert r["breaks"] == 0 and adbreaks.render(r)[-1] == last and len(adbreaks.render(r)) == 3


def test_with_no_app_in_front_for_an_hour_the_report_says_so(tmp_path):
    store = Store(tmp_path / "tvgw.db")
    store.lookup(H0 + 5, "x.example.test", blocked=1)
    r = adbreaks.report(store.conn, experiments.timeline(store.conn, H0, H0 + DAY), H0, H0 + DAY)
    assert adbreaks.render(r)[3] == "  No app was in front for 1 hour or more."
    store.conn.close()
