"""(adbreaks) Ad breaks read from the lookups an ad makes (design decision 89). A report: it reads the
store and changes nothing.

On most services an ad comes down the same connection as the show, so no connection says "this is an
ad". But an ad is measured. When one starts, the player calls the firms that count it: who served it,
who checks that it was seen, who bills for it. Several are called within a second or two, and each call
begins with a lookup of the firm's name. The filter refuses those names, and a TV asks a refused name
again about a minute later (`hold` measures it), so the lookups keep coming for as long as ads play.

**The rule** is set before any break has been marked by hand, and a test pins it:

- a **label** is a refused lookup of a name of an advertising firm (`companies.ADFIRMS`: the advertising
  category of the pinned companies database gives each domain its company), with the names that are
  asked on a timer left out (`timers`). A firm asked again and again is one label until it has been
  quiet for MERGE seconds, whichever of its names and domains were asked;
- NEED labels of different firms within WINDOW seconds open a break. Firms, not domains: one company's
  software asks several of its own domains at once, and that is no ad;
- a label within CHAIN seconds of the break's last one extends it. CHAIN is longer than the minute a
  refusal is held: the ads of one break call many of the same firms, and the TV does not ask a name
  again sooner;
- the break ends TAIL seconds after its last label: a lookup marks an ad's start, not its end.

Refused names only: a name the filter answers is kept by the TV for as long as the answer says, so its
lookups are no clock, and general names the database also files under advertising (a search engine's, a
social network's) are answered and so never count.

**No break lasts ten minutes,** and two things follow from it.

A name asked without a pause for longer than that is asked on a timer, whatever is on the screen, by an
app's own measurement or by the TV. It is known when over UNBROKEN_SHARE of its lookups come in such
stretches: no gap over UNBROKEN for more than LONG_BREAK. Most of its lookups, because one freak of a
break that long must not make timers of an ad's firms for the whole window. Such a name is no label,
and it is no other name's company either. This is the test that knows the fast timers, the ones that
beat every minute or two for longer than a break lasts, however many there are and whoever else is
refused beside them.

And a stretch of labels that runs past LONG_BREAK is not counted as a break. The report sets it aside
and says so.

**A slower timer keeps a steady beat and comes alone.** A name asked every few minutes pauses as long
as an ad's name does between two breaks, so it is told by two other things together. Its gaps are
alike: within each of its runs, STEADY_SHARE of the time lies in gaps no longer than STEADY times the
run's usual one, where an ad's name has a minute's gaps inside a break and many minutes between breaks.
And it comes alone: under ALONE of its lookups have NEED - 1 other firms refused within WINDOW seconds,
where an ad's name is refused with the other firms of the ad. Neither alone will do: breaks that come
at an even spacing make a name asked once a break look steady, and a firm that few ads call is often
alone. Counting the five-minute bins a name is in, the first rule tried, cannot tell a timer from the
firms of a service that breaks every few minutes.

**What it cannot see, and what it estimates.** An ad whose player calls fewer than NEED refused firms
opens nothing, and neither does an ad the service reports from its own servers: there may be more
breaks than it counts. A service with many hours and no break is one this rule cannot see, and the
report says so. The slower timers have an edge: about a dozen of them fall within WINDOW of one another
by chance so often that none is alone, and NEED firms that keep one slow beat are one another's
company at every turn. What those open is set aside when it runs past LONG_BREAK and counted when it
does not; none was seen on the reference. Three more cases are known for neither kind of timer, and
nothing in the report marks them. A fast name that beats only in spells shorter than LONG_BREAK, as an
app's own beacon does when the app is opened for a few minutes at a time: one carries breaks on, and
four in step read as breaks of their own. A refused ad call that the player goes on retrying for some
minutes after a break, which carries the break on for as long. And an ad server asked at the start of
every short video, which the slower test takes for a timer. In a window of a day or two, one evening
of breaks longer than LONG_BREAK is most of what its firms were asked, and makes timers of them. A
break's start is known to the second and its end to within one ad, so the minutes are an estimate; on a
TV that asks a refused name again much sooner than a minute they run long, and the report says that
when `hold` finds it. Nothing here has yet been checked against breaks marked by hand, and the report
says that too.
"""

from __future__ import annotations

import bisect
import itertools
import sqlite3
import statistics
from collections.abc import Mapping, Sequence
from dataclasses import dataclass

from tvgw import appfront, companies

# the rule: seconds in which NEED firms open a break, seconds a later label may follow the last, and
# seconds a break runs on after its last label
WINDOW, NEED, CHAIN, TAIL = 10.0, 3, 65.0, 20.0
MERGE = 5.0  # seconds a firm must be quiet before its next lookup is a new label
LONG_BREAK = 600.0  # seconds no break lasts: a longer stretch of labels is set aside
# a fast timer (`timers`): over UNBROKEN_SHARE of the name's lookups come in stretches longer than
# LONG_BREAK with no gap over UNBROKEN. That is over the beats of two minutes and a little more, run late;
# measured on the tests' stand-in, 150 misses the timers that beat every two and a half minutes, and 200
# joins the breaks of a service that breaks every few minutes on a TV that holds a refusal ten seconds
UNBROKEN, UNBROKEN_SHARE = 160.0, 0.7
# a slower timer (`timers`). A name's lookups fall into runs, a gap longer than TIMER_PAUSE being an
# absence that ends one. It is judged once it has TIMER_GAPS gaps that come to TIMER_SPAN seconds. It is
# steady when STEADY_SHARE of that time lies in gaps of at most STEADY times the usual (median) gap of
# their run, and alone when under ALONE of its lookups have company: other firms refused within WINDOW
TIMER_GAPS, TIMER_SPAN, TIMER_PAUSE = 20, 1800.0, 2700.0
STEADY, STEADY_SHARE, ALONE = 3.0, 0.70, 0.5
# the hold: gaps between a name's refusals, from HOLD_OVER seconds (under it, one lookup's repeats) to
# HOLD_UNDER (over it, another evening); a name counts with HOLD_GAPS of them
HOLD_OVER, HOLD_UNDER, HOLD_GAPS = 5.0, 3600.0, 20
HOLD_SHORT = 45.0  # a TV that asks again sooner than this is not the TV the rule's minutes are set for
LISTED_HOURS = 1.0  # an app is listed with this many hours in front, or with a break
BLIND_HOURS = 10.0  # hours in front without one break after which an app's ads "cannot be seen this way"

Lookup = tuple[float, str]  # when a name was refused, and the name
Label = tuple[float, str]  # when a firm was refused, and the firm (its company's name)


@dataclass(frozen=True)
class Break:
    start: float  # its first label
    last: float  # its last
    firms: int  # the different firms among its labels
    labels: int

    @property
    def seconds(self) -> float:
        """Its length, as near as the lookups say: to TAIL after its last label."""
        return self.last + TAIL - self.start


def _unbroken(times: Sequence[float]) -> int:
    """How many of a name's lookups, refused at `times`, came in stretches that went on for longer than
    any break lasts without a pause: more than LONG_BREAK with no gap over UNBROKEN."""
    inside = first = 0
    for i in range(1, len(times) + 1):
        if i == len(times) or times[i] - times[i - 1] > UNBROKEN:  # the stretch times[first:i] ends
            if times[i - 1] - times[first] > LONG_BREAK:
                inside += i - first
            first = i
    return inside


def _steady(times: Sequence[float]) -> bool:
    """Whether a name refused at `times` keeps a beat. Its lookups fall into runs, a gap over TIMER_PAUSE
    being an absence that ends one and no gap. It is judged once it has TIMER_GAPS gaps that come to
    TIMER_SPAN seconds, and is steady when STEADY_SHARE of that time lies in gaps of at most STEADY
    times the usual (median) gap of their run."""
    runs: list[list[float]] = [[]]  # the gaps of each run
    for earlier, later in itertools.pairwise(times):
        if later - earlier > TIMER_PAUSE:
            runs.append([])
        else:
            runs[-1].append(later - earlier)
    span = sum(map(sum, runs))
    if sum(map(len, runs)) < TIMER_GAPS or span < TIMER_SPAN:
        return False
    on_the_beat = 0.0
    for run in filter(None, runs):
        usual = statistics.median(run)
        on_the_beat += sum(gap for gap in run if gap <= STEADY * usual)
    return on_the_beat >= STEADY_SHARE * span  # under it: a minute's gaps in a break, many minutes between


def timers(refused: Sequence[Lookup], adfirms: Mapping[str, str]) -> frozenset[str]:
    """The advertising firms' names among `refused` (in time order) that are refused on a timer, whatever
    is on the screen: those asked mostly in stretches longer than any break lasts, and of the rest
    those that keep a steady beat and come alone, the first kind being no one's company. (Only the
    first kind: leaving out every timer found, round after round, makes timers of the firms of an ad
    that calls three, one after another.) A name with under TIMER_GAPS gaps, or under TIMER_SPAN
    seconds of them, is not judged steady: unless it is of the first kind, it is no timer yet."""
    firm_of: dict[str, str | None] = {}
    asked: dict[str, list[float]] = {}  # a firm's name -> when it was refused, as `labels` merges a firm
    last: dict[str, float] = {}
    of_firms: list[Lookup] = []
    for t, name in refused:
        if name not in firm_of:
            firm_of[name] = companies.company(name, adfirms)
        if firm_of[name] is None:
            continue
        of_firms.append((t, name))
        if name not in last or t - last[name] > MERGE:
            asked.setdefault(name, []).append(t)
        last[name] = t
    regular = {name for name, times in asked.items() if _unbroken(times) > UNBROKEN_SHARE * len(times)}
    # the company the others may keep: every refusal of a firm's name that is not such a timer's
    marks: list[Label] = [(t, firm_of[name]) for t, name in of_firms if name not in regular]
    when = [t for t, _firm in marks]
    for name, times in asked.items():
        if name in regular or not _steady(times):
            continue
        in_company = 0
        for t in times:
            near = marks[bisect.bisect_left(when, t - WINDOW) : bisect.bisect_right(when, t + WINDOW)]
            in_company += len({firm for _t, firm in near} - {firm_of[name]}) >= NEED - 1
        if in_company < ALONE * len(times):
            regular.add(name)
    return frozenset(regular)


def labels(refused: Sequence[Lookup], adfirms: Mapping[str, str], regular: frozenset[str]) -> list[Label]:
    """The labels among `refused`, which is in time order: the refusals of advertising firms' names
    (`adfirms` is the table of companies.ADFIRMS) that are not `regular`, a firm's run of lookups
    counted once until it has been quiet for MERGE seconds."""
    out: list[Label] = []
    firm_of: dict[str, str | None] = {}
    last: dict[str, float] = {}
    for t, name in refused:
        if name not in firm_of:
            firm_of[name] = None if name in regular else companies.company(name, adfirms)
        firm = firm_of[name]
        if firm is None:
            continue
        if firm not in last or t - last[firm] > MERGE:
            out.append((t, firm))
        last[firm] = t
    return out


def breaks(marks: Sequence[Label]) -> list[Break]:
    """The breaks among the labels `marks` (`labels` makes them), in time order. No two overlap."""
    out: list[Break] = []
    i = 0
    while i < len(marks):
        j, firms = i, set()
        while j < len(marks) and marks[j][0] - marks[i][0] <= WINDOW:
            firms.add(marks[j][1])
            j += 1
        if len(firms) < NEED:
            i += 1
            continue
        last = marks[j - 1][0]
        while j < len(marks) and marks[j][0] - last <= CHAIN:
            firms.add(marks[j][1])
            last = marks[j][0]
            j += 1
        out.append(Break(marks[i][0], last, len(firms), j - i))
        i = j
    return out


def hold(refused: Sequence[Lookup]) -> tuple[int, float | None]:
    """How long this TV waits before it asks a refused name again: (the names with HOLD_GAPS gaps or
    more, the median over them of each name's shortest usual gap, about its 5th percentile). None with
    no such name."""
    gaps: dict[str, list[float]] = {}
    last: dict[str, float] = {}
    for t, name in refused:
        if name in last and HOLD_OVER < t - last[name] < HOLD_UNDER:
            gaps.setdefault(name, []).append(t - last[name])
        last[name] = t
    floors = [sorted(g)[len(g) // 20] for g in gaps.values() if len(g) >= HOLD_GAPS]
    return len(floors), statistics.median(floors) if floors else None


def app_seconds(tl: appfront.Timeline) -> dict[str, float]:
    """Seconds each app was in front and the TV not behind its screen saver. The home screen, the inputs
    and a cast receiver are no app."""
    out: dict[str, float] = {}
    for piece in tl.pieces:
        session = piece.session
        if session is None or session.kind != appfront.APP:
            continue
        idle = sum(max(0.0, min(e, piece.t1) - max(s, piece.t0)) for s, e in session.idle)
        out[session.app] = out.get(session.app, 0.0) + piece.t1 - piece.t0 - idle
    return out


def report(conn: sqlite3.Connection, tl: appfront.Timeline, a: float, b: float) -> dict:
    """The breaks of [a, b) by the app the TV said was in front when each began (`tl` is the window's
    timeline). Counts, hours and minutes only: no name and no time of day. `apps` lists an app with
    LISTED_HOURS in front or a break, most breaks first and then most hours; `unknown` is the breaks that
    began with no app known in front, and `long` the stretches past LONG_BREAK, which are no breaks and
    are counted nowhere else. A break that began
    behind the screen saver is its app's all the same, though the app's hours leave that time out."""
    refused = conn.execute(
        "SELECT t, qname FROM dns WHERE blocked AND t >= ? AND t < ? ORDER BY t", (a, b)
    ).fetchall()
    adfirms = companies.snapshot(companies.ADFIRMS)[1]
    regular = timers(refused, adfirms)
    marks = labels(refused, adfirms, regular)
    found = breaks(marks)
    in_front = app_seconds(tl)
    tally = {app: [0, 0.0] for app, seconds in in_front.items() if seconds >= LISTED_HOURS * 3600}
    unknown = [0, 0.0]
    long = [0, 0.0]  # stretches past LONG_BREAK: no breaks, and counted nowhere else
    for brk in found:
        session = tl.at(brk.start)[1]
        known = session is not None and session.kind == appfront.APP
        if brk.seconds > LONG_BREAK:
            row = long
        else:
            row = tally.setdefault(session.app, [0, 0.0]) if known else unknown
        row[0] += 1
        row[1] += brk.seconds
    names, floor = hold(refused)
    return {
        "window": [a, b],
        "refused": len(refused),
        "timers": len(regular),
        "labels": len(marks),
        "firms": len({firm for _t, firm in marks}),
        "breaks": len(found) - long[0],
        "long": {"stretches": long[0], "minutes": long[1] / 60},
        "apps": [
            {
                "app": appfront.app_label(app),
                "hours": in_front.get(app, 0.0) / 3600,
                "breaks": n,
                "minutes": seconds / 60,
            }
            for app, (n, seconds) in sorted(
                tally.items(), key=lambda row: (-row[1][0], -in_front.get(row[0], 0.0))
            )
        ],
        "unknown": {"breaks": unknown[0], "minutes": unknown[1] / 60},
        "hold": {"names": names, "seconds": floor},
        "list": {"domains": len(adfirms), "trouble": companies.trouble(companies.ADFIRMS)},
    }


def _count(n: float, word: str) -> str:
    """`1 break`, `2 breaks`, and a number of days to the nearest one."""
    return f"{n:.0f} {word}{'' if round(n) == 1 else 's'}"


def _ads(minutes: float) -> str:
    """A break's or an app's minutes of ads: an estimate, so `about`, and never `about 0`."""
    return "under a minute of ads" if minutes < 1 else f"about {_count(minutes, 'minute')} of ads"


def _app_line(row: dict) -> str:
    front = f"  {row['app']}: {row['hours']:.1f} hours in front, "
    if row["breaks"]:
        rate = f", {row['breaks'] / row['hours']:.1f} an hour" if row["hours"] >= LISTED_HOURS else ""
        return f"{front}{_count(row['breaks'], 'break')}{rate}, {_ads(row['minutes'])}"
    if row["hours"] >= BLIND_HOURS:
        return f"{front}no break seen: if it shows ads, they cannot be seen this way"
    return f"{front}no break seen (under {BLIND_HOURS:g} hours is too few to say)"


def _hold_line(names: int, seconds: float | None) -> str:
    if seconds is None:
        return "Too few names were refused often enough to say how long this TV waits before it asks again."
    line = f"This TV asks a refused name again after about {seconds:.0f} seconds ({_count(names, 'name')})."
    if seconds < HOLD_SHORT:
        line += " The rule is set for about a minute: on this TV the minutes may run about a quarter long."
    return line


def render(r: dict) -> list[str]:
    """The report in the words of a user page. Whenever it gives a figure it says what the figure
    leaves out, that the minutes are an estimate, and that nothing is checked against marked breaks."""
    lines = [
        f"Ad breaks, read from the lookups an ad makes: the last {_count(_days(r), 'day')}.",
        f"A break is {NEED} or more advertising firms refused within {WINDOW:g} seconds; it lasts while"
        " more follow.",
    ]
    if r["list"]["trouble"]:
        return [*lines, f"The list of advertising firms could not be read: {r['list']['trouble']}"]
    if not r["refused"]:
        return [*lines, "The filter refused nothing in this window, so there is nothing to read."]
    lines += ["", *map(_app_line, r["apps"])]
    if not r["apps"]:
        lines.append(f"  No app was in front for {LISTED_HOURS:g} hour or more.")
    if r["unknown"]["breaks"]:
        lines.append(
            f"  With no app known in front: {_count(r['unknown']['breaks'], 'break')},"
            f" {_ads(r['unknown']['minutes'])}"
        )
    if r["long"]["stretches"]:
        lines.append(
            f"  Not counted: {r['long']['stretches']} stretch{'' if r['long']['stretches'] == 1 else 'es'} of"
            f" such lookups that ran past {LONG_BREAK / 60:g} minutes, {r['long']['minutes']:.0f} minutes in"
            " all. A break is not that long as a rule: most likely these are names asked on timers."
        )
    return [
        *lines,
        "",
        f"There may be more: an ad that calls fewer than {NEED} refused firms is not counted, nor one the"
        " service reports from its own servers.",
        "The minutes are an estimate: a break's start is known to the second, its end to within one ad.",
        "It has not been checked against breaks marked by hand.",
        _hold_line(r["hold"]["names"], r["hold"]["seconds"]),
    ]


def _days(r: dict) -> float:
    return (r["window"][1] - r["window"][0]) / 86400
