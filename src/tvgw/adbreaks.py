"""(adbreaks) Ad breaks read from the lookups an ad makes (design decision 89). A report: it reads the
store and changes nothing.

On most services an ad comes down the same connection as the show, so no connection says "this is an
ad". But an ad is measured. When one starts, the player calls the firms that count it: who served it,
who checks that it was seen, who bills for it. Several are called within a second or two, and each call
begins with a lookup of the firm's name. The filter refuses those names, and a TV asks a refused name
again about a minute later (`hold` measures it), so the lookups keep coming for as long as ads play.

**The rule** was set on 2026-11-12, before any break had been marked by hand, and a test pins it:

- a **label** is a refused lookup of a name under an advertising firm's domain (`companies.ADFIRMS`, the
  advertising category of the pinned companies database), one for each registrable domain in MERGE
  seconds, with the names that are asked on a timer left out (`timers`);
- NEED labels of different domains within WINDOW seconds open a break;
- a label within CHAIN seconds of the break's last one extends it;
- the break ends TAIL seconds after its last label: a lookup marks an ad's start, not its end.

Refused names only: a name the filter answers is kept by the TV for as long as the answer says, so its
lookups are no clock, and general names the database also files under advertising (a search engine's, a
social network's) are answered and so never count.

**It is a floor.** An ad whose player calls fewer than NEED refused firms opens nothing, and so does an
ad measured from the service's own servers. A service with many hours and no break is one this rule
cannot see, and the report says so. A break's start is known to the second and its end to within one
ad. Nothing here has yet been checked against breaks marked by hand, and the report says that too.
"""

from __future__ import annotations

import sqlite3
import statistics
from collections.abc import Mapping, Sequence
from dataclasses import dataclass

from tvgw import appfront, companies
from tvgw.names import registrable_domain

# the rule: seconds in which NEED firms open a break, seconds a later label may follow the last, and
# seconds a break runs on after its last label
WINDOW, NEED, CHAIN, TAIL = 10.0, 3, 45.0, 20.0
MERGE = 5.0  # seconds in which a domain's lookups are one label (a name is asked for A and AAAA at once)
# a timer: a name present in TIMER_SHARE of the TIMER_BIN-second bins of the clock hours it appears in,
# over TIMER_HOURS hours or more. A name asked whatever is on the screen is in nearly every bin; a firm
# called by ads is only in the bins that hold a break
TIMER_BIN, TIMER_SHARE, TIMER_HOURS = 300.0, 0.70, 2
# the hold: gaps between a name's refusals, from HOLD_OVER seconds (under it, one lookup's repeats) to
# HOLD_UNDER (over it, another evening); a name counts with HOLD_GAPS of them
HOLD_OVER, HOLD_UNDER, HOLD_GAPS = 5.0, 3600.0, 20
LISTED_HOURS = 1.0  # an app is listed with this many hours in front, or with a break
BLIND_HOURS = 10.0  # hours in front without one break after which an app's ads "cannot be seen this way"

Lookup = tuple[float, str]  # when a name was refused, and the name


@dataclass(frozen=True)
class Break:
    start: float  # its first label
    last: float  # its last
    firms: int  # the different domains among its labels
    labels: int

    @property
    def seconds(self) -> float:
        """Its length, at least: to TAIL after its last label."""
        return self.last + TAIL - self.start


def timers(refused: Sequence[Lookup]) -> frozenset[str]:
    """The names refused on a timer, whatever is on the screen."""
    bins: dict[str, set[int]] = {}
    for t, name in refused:
        bins.setdefault(name, set()).add(int(t // TIMER_BIN))
    in_an_hour = int(3600 // TIMER_BIN)
    regular = set()
    for name, present in bins.items():
        hours = len({b // in_an_hour for b in present})
        if hours >= TIMER_HOURS and len(present) >= TIMER_SHARE * in_an_hour * hours:
            regular.add(name)
    return frozenset(regular)


def labels(refused: Sequence[Lookup], firms: Mapping[str, str], regular: frozenset[str]) -> list[Lookup]:
    """(when, registrable domain) of each label among `refused`, which is in time order: the refusals of
    advertising firms' names (`firms` is the table of companies.ADFIRMS) that are not `regular`, one for
    each domain in MERGE seconds."""
    out: list[Lookup] = []
    is_firm: dict[str, bool] = {}
    last: dict[str, float] = {}
    for t, name in refused:
        if name not in is_firm:
            is_firm[name] = name not in regular and companies.company(name, firms) is not None
        if not is_firm[name]:
            continue
        domain = registrable_domain(name)
        if domain not in last or t - last[domain] > MERGE:
            out.append((t, domain))
        last[domain] = t
    return out


def breaks(found: Sequence[Lookup]) -> list[Break]:
    """The breaks among the labels `found` (`labels` makes them), in time order. No two overlap."""
    out: list[Break] = []
    i = 0
    while i < len(found):
        j, domains = i, set()
        while j < len(found) and found[j][0] - found[i][0] <= WINDOW:
            domains.add(found[j][1])
            j += 1
        if len(domains) < NEED:
            i += 1
            continue
        last = found[j - 1][0]
        while j < len(found) and found[j][0] - last <= CHAIN:
            domains.add(found[j][1])
            last = found[j][0]
            j += 1
        out.append(Break(found[i][0], last, len(domains), j - i))
        i = j
    return out


def hold(refused: Sequence[Lookup]) -> tuple[int, float | None]:
    """How long this TV waits before it asks a refused name again: (the names with HOLD_GAPS gaps or
    more, the median over them of each name's shortest usual gap, its 5th percentile). None with no
    such name."""
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
    began with no app known in front."""
    refused = conn.execute(
        "SELECT t, qname FROM dns WHERE blocked AND t >= ? AND t < ? ORDER BY t", (a, b)
    ).fetchall()
    firms = companies.snapshot(companies.ADFIRMS)[1]
    regular = timers(refused)
    found = labels(refused, firms, regular)
    in_front = app_seconds(tl)
    tally = {app: [0, 0.0] for app, seconds in in_front.items() if seconds >= LISTED_HOURS * 3600}
    unknown = [0, 0.0]
    count = 0
    for brk in breaks(found):
        session = tl.at(brk.start)[1]
        known = session is not None and session.kind == appfront.APP
        row = tally.setdefault(session.app, [0, 0.0]) if known else unknown
        row[0] += 1
        row[1] += brk.seconds
        count += 1
    names, floor = hold(refused)
    return {
        "window": [a, b],
        "refused": len(refused),
        "timers": len(regular),
        "labels": len(found),
        "firms": len({domain for _t, domain in found}),
        "breaks": count,
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
        "list": {"domains": len(firms), "trouble": companies.trouble(companies.ADFIRMS)},
    }


def _count(n: float, word: str) -> str:
    """`1 break`, `2 breaks`, and a number of minutes to the nearest one."""
    return f"{n:.0f} {word}{'' if round(n) == 1 else 's'}"


def _app_line(row: dict) -> str:
    front = f"  {row['app']}: {row['hours']:.1f} hours in front, "
    if row["breaks"]:
        rate = f", {row['breaks'] / row['hours']:.1f} an hour" if row["hours"] >= LISTED_HOURS else ""
        ads = _count(row["minutes"], "minute")
        return f"{front}{_count(row['breaks'], 'break')}{rate}, at least {ads} of ads"
    if row["hours"] >= BLIND_HOURS:
        return f"{front}no break seen: if it shows ads, they cannot be seen this way"
    return f"{front}no break seen (under {BLIND_HOURS:g} hours is too few to say)"


def render(r: dict) -> list[str]:
    """The report in the words of a user page. It always says that it is a floor and that it is
    unchecked."""
    days = round((r["window"][1] - r["window"][0]) / 86400)
    lines = [
        f"Ad breaks, read from the lookups an ad makes: the last {_count(days, 'day')}.",
        f"A break is {NEED} or more advertising firms' names refused within {WINDOW:g} seconds; it lasts"
        " while more follow.",
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
            f"  With no app known in front: {_count(r['unknown']['breaks'], 'break')}, at least"
            f" {_count(r['unknown']['minutes'], 'minute')} of ads"
        )
    held = r["hold"]["seconds"]
    lines += [
        "",
        f"This is a floor. An ad that calls fewer than {NEED} refused firms is not counted, and a break's"
        " end is known only to within one ad.",
        "It has not been checked against breaks marked by hand.",
        "Too few names were refused often enough to say how long this TV waits before it asks again."
        if held is None
        else f"This TV asks a refused name again after about {held:.0f} seconds"
        f" ({_count(r['hold']['names'], 'name')}).",
    ]
    return lines
