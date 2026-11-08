"""(did it work) Failed app starts, read from the TV's own account of itself and joined with what the gateway
refused in the same minutes; and the one question a wall on probation asks: did anything break since then?
(design decision 72)

A failed start is read from the sessions `appfront.timeline()` cuts (design decision 67), and only for an
app the gateway has seen working: one with a picture, a site of its own reached on an earlier viewing day.
Settings, launchers, input pickers and the media player bring nothing down when they work, so the TV
maker's own apps are left out by name as well (SYSTEM_APPS), and so are the home screen, inputs and cast
receivers by kind. Only a start the TV itself reported counts: an app that came to the front by a change
the live reading heard, to the second, and that ended with a change to the home screen.

- **Quick**: the TV went back to the home screen within SHORT seconds, with under LITTLE_DOWN down on the
  connections that started while the app was in front.
- **Stalled**: the app stayed in front longer, up to STALL_MAX, still with under LITTLE_DOWN down.
- **Hourly**: with no live record, one pair of hourly readings a short hour apart named the same app,
  awake and not behind the screen saver, and the connections between them brought under
  HOURLY_LITTLE_DOWN down. The line says its times are to the hour: an app left on its menu reads the same.

Every one waits for its bytes to settle (`receipt.SETTLE`): conntrack logs a connection when it lets it go,
so before that a start that worked reads as one that failed, and it is only pending (`pending()`). A start
that ended at another app, an input, a cast receiver or standby is a choice; one the gateway did not see
begin (the session to the TV came up with the app already in front, or the TV woke with it) or lost touch
during is its own blind spot; neither is ever counted.

What is shown. REPEAT quick exits of one app, each within CLUSTER of the one before, are a failed start on
their timing alone, but only when the app had not been in front earlier that viewing day: an app the TV
brings back from memory brings little down, and its quick exits look the same. Everything else (one quick
exit, a stall, a return of an app that ran earlier that evening) is shown only with a likely cause in its
minutes; an hourly one only with a strong one (below), since its window spans up to an hour.

What was refused in the same minutes (SLACK seconds either side of the stays, or the time between the two
readings) is the store's record of the TV's refused lookups, judged as `tvgw refused` judges them
(`refused.needed`, `refused.store_history`, `refused.domain_history`), and any other reader's refusals a
caller passes as `Refusal` rows, each with its own `seen_before`. A likely cause is a name the profile says
the TV needs or a name whose site the app reached on earlier viewing days (the strong two), or a refusal
the record has not seen before, or one after the filter had let the name through; never a known tracker
(`plain.is_tracking`), which the gateway refuses on purpose. A refusal in the same minutes is a coincidence
in time, never proof, so no line says one caused anything: each says what was refused then and points at
the command that says why.

`since()` is the probation hook. A wall that has begun to refuse asks it "did anything break since T?" and
gets BROKE (failed starts and their likely causes), CLEAN (apps started, their bytes are in and show them
working, the record of lookups reaches past them, and none failed) or UNKNOWN (anything less, starts still
settling among it). UNKNOWN is never CLEAN.

What is minute-level stays out of persisted reports: `summary()` is counts only, and every line that names
an app, a time or a refused name is for an interactive run (design decision 67).

Everything here reads the store and writes nothing.
"""

from __future__ import annotations

import sqlite3
import time
from collections.abc import Iterable
from dataclasses import dataclass, field
from datetime import datetime

from tvgw import appfront, companies, names, plain, queries, receipt, refused
from tvgw.appfront import APP, HOME, HOURLY, LIVE, Conn, Event, Session, Timeline
from tvgw.profile import HARMLESS_QTYPES, Profile

SHORT = 60.0  # seconds: back to the home screen sooner than this after coming to the front is a quick exit
CLUSTER = 600.0  # seconds: quick exits of one app this close one after another are one episode
REPEAT = 2  # quick exits in one episode of a fresh start that make it a failed start on their timing alone
# bytes down on the connections that started while the app was in front: less says almost nothing loaded.
# A guess, like appfront.LEAD_SECONDS, until the live record has measured app starts that worked and ones
# that did not; an app's own menu brings its artwork down, which is more than this in the starts seen
LITTLE_DOWN = 1024 * 1024
STALL_MAX = 600.0  # seconds: in front longer than this is not a start that stalled, whatever came down
# bytes down between two hourly readings that both named the app: an hour of video is hundreds of MB
HOURLY_LITTLE_DOWN = 10 * 1024 * 1024
SLACK = appfront.LEAD_SECONDS + 2.0  # seconds either side of the stays: a lookup an app makes on its way in
LIVE_LOOKBACK = (
    2 * 86400.0
)  # how far before a window the live record is read, to find the session it began in
PICTURE_LOOKBACK = appfront.PICTURE_DAYS * 86400.0  # how far back an app's picture is learned from
# the TV maker's own apps, which bring nothing down when they work: settings, the input picker, the media
# player for a USB stick, notices and setup screens. REPORTED identifiers of LG integrations, none seen on
# the reference TV yet; an app without a picture is left out whatever its name, so the list is a second guard
SYSTEM_APPS = (
    "com.palm.app.settings",
    "com.webos.app.settings",
    "com.webos.app.inputpicker",
    "com.webos.app.inputcommon",
    "com.webos.app.mediadiscovery",
    "com.webos.app.photovideo",
    "com.webos.app.music",
    "com.webos.app.notificationcenter",
    "com.webos.app.softwareupdate",
    "com.webos.app.connectionwizard",
    "com.webos.app.membership",
    "com.webos.app.customersupport",
    "com.webos.app.channeledit",
    "com.webos.app.voice",
    "com.webos.app.screensaver",
)
QUICK, STALLED = "quick", "stalled"
BROKE, CLEAN, UNKNOWN = "broke", "clean", "unknown"
FILTER = "filter"  # a refusal's source: the filter's refused lookup, as the store holds it
_HARMLESS = tuple(sorted(HARMLESS_QTYPES))


@dataclass(frozen=True)
class Refusal:
    """One refused attempt of the TV's: a lookup the filter refused (`source` FILTER, judged against the
    store's history), or one another reader gives (a kernel refusal, say: its own `source`), with the rule
    that decided when known and, for another reader, whether its own record had refused the same before
    (`seen_before`; None: it cannot say, and the refusal is then never first sight)."""

    t: float
    name: str
    rule: str | None = None
    source: str = FILTER
    seen_before: bool | None = None


@dataclass
class Cause:
    """A name, or an address, refused in a failed start's minutes, with what the record says of it."""

    name: str
    lookups: int
    first: float
    last: float
    rule: str | None
    source: str = FILTER
    category: str = ""
    kind: str = ""  # the category in plain words
    company: str | None = None
    needed: str | None = None  # why the profile says the TV needs it, in a clause (refused.needed)
    first_sight: bool = False  # not refused before by its rule under its site, or let through since
    tracking: bool = False  # a known tracking category: refused on purpose
    app_days: int = 0  # earlier viewing days the app reached the name's site on (0: none, or not known)

    @property
    def strong(self) -> bool:
        """A name the TV needs, or one whose site the app used on earlier days, that is no known tracker."""
        return self.needed is not None or (not self.tracking and self.app_days > 0)

    @property
    def likely(self) -> bool:
        """A strong cause, or a refusal the record has not seen before that is no known tracker."""
        return self.strong or (not self.tracking and self.first_sight)

    def why(self, app_name: str) -> str:
        """What makes it likely, in a clause."""
        if self.needed is not None:
            return "which the profile says the TV needs"
        if self.app_days and not self.tracking:
            days = "1 earlier day" if self.app_days == 1 else f"{self.app_days} earlier days"
            return f"whose site {app_name} reached on {days}"
        if self.first_sight and not self.tracking:
            return "which it had not refused before"
        return "which it refuses on purpose" if self.tracking else "which it had refused before"

    def as_dict(self) -> dict:
        return {
            "name": self.name,
            "lookups": self.lookups,
            "first": self.first,
            "last": self.last,
            "rule": self.rule,
            "source": self.source,
            "category": self.category,
            "kind": self.kind,
            "company": self.company,
            "needed": self.needed,
            "first_sight": self.first_sight,
            "tracking": self.tracking,
            "app_days": self.app_days,
            "likely": self.likely,
        }


def rank_key(c: Cause) -> tuple:
    """Needed first; known trackers last; then the app's own sites, then first sight, then the most
    retried, the earliest and by name, so the same minutes always read the same."""
    return (c.needed is None, c.tracking, c.app_days == 0, not c.first_sight, -c.lookups, c.first, c.name)


@dataclass
class FailedStart:
    """An app that may not have started: one quick or stalled episode, or one hourly pair of readings."""

    app: str
    timed: str  # LIVE or HOURLY
    start: float  # when it first came to the front; an hourly one: the first reading that saw it
    end: float  # when the TV last went back to the home screen; an hourly one: the second reading
    times: int  # how many times it came to the front and went back in this episode (1 for an hourly one)
    longest: float  # the longest of those stays, in seconds
    down: int  # bytes down on the connections that started meanwhile
    fresh: bool = True  # the app had not been in front earlier that viewing day
    then_stayed: bool = False  # it came to the front again within CLUSTER and stayed
    causes: list[Cause] = field(default_factory=list)  # every name refused in its minutes, ranked

    @property
    def label(self) -> str:
        return appfront.app_label(self.app)

    @property
    def kind(self) -> str:
        if self.timed == HOURLY:
            return HOURLY
        return STALLED if self.longest >= SHORT else QUICK

    @property
    def likely(self) -> list[Cause]:
        """The causes that count for it: strong ones for an hourly one, likely ones otherwise."""
        if self.timed == HOURLY:
            return [c for c in self.causes if c.strong]
        return [c for c in self.causes if c.likely]

    @property
    def window(self) -> tuple[float, float]:
        """Where a refusal counts as in its minutes."""
        if self.timed == HOURLY:
            return self.start, self.end
        return self.start - SLACK, self.end + SLACK

    @property
    def reported(self) -> bool:
        """Whether it is shown at all: REPEAT quick exits of a fresh start on their timing, anything else
        only with a cause that counts for it."""
        if self.likely:
            return True
        return self.timed == LIVE and self.times >= REPEAT and self.fresh  # a stall is an episode of one

    def as_dict(self) -> dict:
        return {
            "app": self.app,
            "label": self.label,
            "kind": self.kind,
            "timed": self.timed,
            "start": self.start,
            "end": self.end,
            "times": self.times,
            "longest": self.longest,
            "down": self.down,
            "fresh": self.fresh,
            "then_stayed": self.then_stayed,
            "causes": [c.as_dict() for c in self.causes],
        }


# ---- reading the record -----------------------------------------------------------------------------------
def refusals(conn: sqlite3.Connection, a: float, b: float) -> list[Refusal]:
    """The TV's refused lookups of internet names in [a, b), from the store: record types the TV goes
    without (`profile.HARMLESS_QTYPES`) left out, as `tvgw refused` leaves them out."""
    rows = conn.execute(
        "SELECT t, qname, rule FROM dns WHERE t >= ? AND t < ? AND blocked = 1"
        f" AND COALESCE(qtype, '') NOT IN ({', '.join('?' * len(_HARMLESS))}) ORDER BY t",
        (a, b, *_HARMLESS),
    ).fetchall()
    return [Refusal(t, names.normalize(q), rule) for t, q, rule in rows if names.is_public_name(q)]


def evidence(conn: sqlite3.Connection, profile: Profile, a: float, b: float) -> appfront.Evidence:
    """Each app's picture as of [a, b): learned from the PICTURE_LOOKBACK before `a`, as the receipt
    learns it, so the receipt and the brief judge a start by the same rule."""
    back = a - PICTURE_LOOKBACK
    tl = appfront.timeline(appfront.stored_events(conn, back, b), appfront.readings(conn, back, b), back, b)
    return appfront.learn(tl, appfront.hellos(conn, back, b), profile)


def judge(
    conn: sqlite3.Connection | None,
    profile: Profile,
    rows: Iterable[Refusal],
    before: float,
    app: str = "",
    ev: appfront.Evidence | None = None,
) -> list[Cause]:
    """The refusals as causes, ranked. `before` is where the window starts: "refused before" is the store's
    record older than it, for the filter's refusals, and each other reader's own `seen_before`. `ev`, the
    apps' pictures, says whether the name's site was the app's on earlier viewing days. Without a store, no
    refusal of the filter counts as first sight. sqlite3.Error is the caller's."""
    by: dict[tuple[str, str], Cause] = {}
    seen_before: dict[tuple[str, str], bool | None] = {}
    for r in rows:
        key = (r.source, r.name)
        c = by.get(key)
        if c is None:
            by[key] = Cause(r.name, 1, r.t, r.t, r.rule, r.source)
            seen_before[key] = r.seen_before
            continue
        c.lookups += 1
        c.first = min(c.first, r.t)
        if r.t >= c.last:  # the newest refusal's rule is the one that decides now
            c.last, c.rule = r.t, r.rule
        if r.seen_before is not None:
            seen_before[key] = bool(seen_before[key]) or r.seen_before
    day = appfront.viewing_day(before)
    for key, c in by.items():
        named = names.is_public_name(c.name)
        c.category = profile.categorize(c.name) if named else ""
        c.kind = plain.category_label(c.category, profile) if named else "an address"
        c.company = companies.company(c.name) if named else None
        c.needed = refused.needed(c.name, profile)[0] if named else None
        c.tracking = plain.is_tracking(c.category)
        if c.source != FILTER:
            c.first_sight = seen_before[key] is False
        elif conn is not None:
            own = refused.store_history(conn, c.name, c.rule, before)
            domain = names.registrable_domain(c.name)
            siblings = refused.domain_history(conn, domain, c.rule, before, c.name)
            c.first_sight = own.let_through_since or (own.first_by_rule is None and siblings is None)
        if ev is not None and app and named:
            c.app_days = ev.days_seen(app, appfront.classify(profile, c.name).unit, before=day)
    return sorted(by.values(), key=rank_key)


def eligible(app: str, ev: appfront.Evidence, at: float) -> bool:
    """Whether a start of `app` can be judged: an app of the kind `app`, not one of the TV maker's own
    (SYSTEM_APPS), with a picture as of the viewing day of `at` (a site of its own on an earlier day)."""
    if appfront.app_kind(app) != APP or app in SYSTEM_APPS:
        return False
    return bool(ev.picture(app, before=appfront.viewing_day(at)))


def _downs(tl: Timeline, conns: Iterable[Conn]) -> dict[int, int]:
    """Bytes down by session, each connection where it started (lead seconds included)."""
    out: dict[int, int] = {}
    for c in conns:
        s = tl.at(c.t)[1]
        if s is not None:
            out[id(s)] = out.get(id(s), 0) + c.down
    return out


def _back_home(s: Session, starting: dict[float, Session]) -> bool:
    """The TV reported the app coming to the front itself, by a change of app, to the second; it reported
    its end the same way; and what came next was the home screen."""
    if not (s.timed == LIVE and s.began == "app" and s.start_exact and s.end_exact and s.end_why == "app"):
        return False
    nxt = starting.get(s.end)
    return nxt is not None and nxt.kind == HOME


def episodes(
    tl: Timeline, conns: Iterable[Conn], a: float, b: float, now: float
) -> tuple[list[FailedStart], list[FailedStart]]:
    """(candidates, pending) that began in [a, b), before any refusal is read or any picture consulted.
    Candidates: live episodes of quick exits (one app's each within CLUSTER of the one before) or one
    stall each, with their bytes settled; hourly pairs of readings that brought little down. Pending: live
    stays that would be candidates but whose bytes have not settled. Whether a candidate is shown is
    FailedStart.reported, once its causes are in."""
    sessions = tl.sessions
    starting = {s.start: s for s in sessions if s.timed == LIVE}
    down = _downs(tl, conns)
    out: list[FailedStart] = []
    waiting: list[FailedStart] = []
    open_: dict[str, FailedStart] = {}  # the live episode of quick exits still open, by app
    last_day: dict[str, int] = {}  # the viewing day each app was last in front on
    for s in sessions:
        if s.kind != APP:
            continue
        day = appfront.viewing_day(s.start)
        fresh = last_day.get(s.app) != day
        last_day[s.app] = day
        settled = now - s.end >= receipt.SETTLE
        got = down.get(id(s), 0)
        inside = a <= s.start < b
        if s.timed == HOURLY:
            one_pair = s.seconds <= queries.STANDBY_GAP
            if inside and settled and one_pair and not s.idle and got < HOURLY_LITTLE_DOWN:
                out.append(FailedStart(s.app, HOURLY, s.start, s.end, 1, s.seconds, got, fresh))
            continue
        ep = open_.get(s.app)
        if ep is not None and s.start - ep.end > CLUSTER:
            del open_[s.app]
            ep = None
        shape = _back_home(s, starting) and s.seconds < STALL_MAX
        if shape and not settled:
            if inside:
                waiting.append(FailedStart(s.app, LIVE, s.start, s.end, 1, s.seconds, got, fresh))
            continue
        if not (shape and got < LITTLE_DOWN):
            if ep is not None and s.began == "app" and (s.seconds >= SHORT or s.end_why == "open"):
                ep.then_stayed = True  # it came back within CLUSTER and stayed
                del open_[s.app]
            continue
        if not inside:
            continue
        if s.seconds >= SHORT:  # a stall is an episode of its own
            out.append(FailedStart(s.app, LIVE, s.start, s.end, 1, s.seconds, got, fresh))
            continue
        if ep is None:
            ep = FailedStart(s.app, LIVE, s.start, s.end, 0, 0.0, 0, fresh)
            open_[s.app] = ep
            out.append(ep)
        ep.times += 1
        ep.end = s.end
        ep.longest = max(ep.longest, s.seconds)
        ep.down += got
    return sorted(out, key=lambda e: (e.start, e.app)), waiting


def worked(tl: Timeline, conns: Iterable[Conn], a: float, b: float, now: float) -> int:
    """App starts in [a, b) whose settled bytes show them working: a start the TV reported that stayed in
    front SHORT or longer and brought at least LITTLE_DOWN down; an hourly session awake and not idle that
    brought at least HOURLY_LITTLE_DOWN down. Time in front alone proves nothing."""
    down = _downs(tl, conns)
    n = 0
    for s in tl.sessions:
        if s.kind != APP or not a <= s.start < b or now - s.end < receipt.SETTLE:
            continue
        got = down.get(id(s), 0)
        if s.timed == LIVE and s.began == "app" and s.start_exact:
            n += s.seconds >= SHORT and got >= LITTLE_DOWN
        elif s.timed == HOURLY and not s.idle:
            n += got >= HOURLY_LITTLE_DOWN
    return n


def find(
    conn: sqlite3.Connection,
    profile: Profile,
    tl: Timeline,
    conns: Iterable[Conn],
    a: float,
    b: float,
    now: float,
    ev: appfront.Evidence | None = None,
    extra: Iterable[Refusal] = (),
) -> list[FailedStart]:
    """The failed starts that began in [a, b), each with the names refused in its minutes, ranked; only
    those of an `eligible` app that FailedStart.reported keeps. `ev` is the apps' pictures (`evidence()`
    when not given); `extra` adds refusals the store does not hold (the minutes the hourly ingest has not
    loaded yet, another reader's refusals)."""
    conns = list(conns)
    candidates, _pending = episodes(tl, conns, a, b, now)
    if not candidates:
        return []
    ev = evidence(conn, profile, a, b) if ev is None else ev
    extra = list(extra)
    out = []
    for e in candidates:
        if not eligible(e.app, ev, e.start):
            continue
        lo, hi = e.window
        rows = refusals(conn, lo, hi) + [r for r in extra if lo <= r.t < hi]
        e.causes = judge(conn, profile, rows, lo, e.app, ev)
        if e.reported:
            out.append(e)
    return out


def for_window(
    conn: sqlite3.Connection, profile: Profile, gw_ip: str, a: float, b: float, now: float
) -> list[FailedStart]:
    """The failed starts of [a, b) from the store alone, for the brief: the live record and the readings
    from LIVE_LOOKBACK before; the pictures, as the receipt has them, only when a candidate needs them."""
    back = a - LIVE_LOOKBACK
    tl = appfront.timeline(appfront.stored_events(conn, back, b), appfront.readings(conn, back, b), back, b)
    return find(conn, profile, tl, appfront.connections(conn, a, b, gw_ip), a, b, now)


# ---- the probation hook ---------------------------------------------------------------------------------
@dataclass
class Verdict:
    """The answer to "did anything break since `since`?"."""

    state: str  # BROKE, CLEAN or UNKNOWN
    since: float
    until: float
    failed: list[FailedStart]
    worked: int  # app starts since then whose settled bytes show them working
    pending: int  # app starts since then whose bytes have not settled: judged at a later ask
    covered_until: float | None  # the newest lookup the record holds: a refusal after it is not seen
    why: str  # one plain sentence

    @property
    def causes(self) -> list[Cause]:
        """The likely causes over every failed start, each name once per source, ranked."""
        seen: dict[tuple[str, str], Cause] = {}
        for f in self.failed:
            for c in f.likely:
                seen.setdefault((c.source, c.name), c)
        return sorted(seen.values(), key=rank_key)

    def as_dict(self) -> dict:
        return {
            "state": self.state,
            "since": self.since,
            "until": self.until,
            "failed": [f.as_dict() for f in self.failed],
            "worked": self.worked,
            "pending": self.pending,
            "covered_until": self.covered_until,
            "why": self.why,
            "causes": [c.as_dict() for c in self.causes],
        }


def since(
    conn: sqlite3.Connection,
    profile: Profile,
    t: float,
    now: float | None = None,
    *,
    gw_ip: str = "10.10.10.1",
    events: Iterable[Event] = (),
    extra: Iterable[Refusal] = (),
    known_until: float | None = None,
) -> Verdict:
    """Did anything break since `t`? The probation hook a wall's automatic undo calls (design decision 72).

    It reads the store: the live record, the hourly readings, the connections, the refused lookups since
    `t`, and the apps' pictures. The hourly ingest loads them up to an hour late, so a caller that must
    answer sooner passes the live reading's own lines (`events`, `appfront.read_events()` of
    `tvlive-events.log`, with `known_until` the time that file was last written) and the refusals the store
    does not hold yet (`extra`: AdGuard's query log through `adguard.records_since()`, or a wall's own
    refusals as Refusal rows with their own `source` and `seen_before`).

    BROKE: at least one failed start since `t` (FailedStart.reported); `causes` ranks their likely causes,
    and a caller undoes only what it can tie to its own refusals. CLEAN only when none failed, none is
    still settling (conntrack logs a connection when it lets it go, up to `receipt.SETTLE` later), at
    least one app start's settled bytes show it working (`worked()`), and the record of lookups reaches
    past the end of the last app stay since `t`. UNKNOWN otherwise, which says nothing either way.
    sqlite3.Error is the caller's."""
    now = time.time() if now is None else now
    back = t - LIVE_LOOKBACK
    evs = appfront.stored_events(conn, back, now) + list(events)
    tl = appfront.timeline(evs, appfront.readings(conn, back, now), back, now, known_until=known_until)
    conns = appfront.connections(conn, t, now, gw_ip)
    extra = list(extra)
    ev = evidence(conn, profile, t, now)
    candidates, waiting = episodes(tl, conns, t, now, now)
    failed = find(conn, profile, tl, conns, t, now, now, ev=ev, extra=extra) if candidates else []
    pending = sum(1 for p in waiting if eligible(p.app, ev, p.start))
    good = worked(tl, conns, t, now, now)
    newest = conn.execute("SELECT MAX(t) FROM dns WHERE t < ?", (now,)).fetchone()[0]
    covered = max([x for x in (newest, *(r.t for r in extra if r.t < now)) if x is not None], default=None)
    stays = [s.end for s in tl.sessions if s.kind == APP and t <= s.start < now]
    at = datetime.fromtimestamp(t).strftime("%Y-%m-%d %H:%M")
    if failed:
        n = len(failed)
        state, why = BROKE, f"{n} app start{'s' if n > 1 else ''} may have failed since {at}"
    elif pending:
        state, why = (
            UNKNOWN,
            f"{pending} app start{'s are' if pending > 1 else ' is'} still settling since {at}",
        )
    elif covered is None or covered < t:
        state, why = UNKNOWN, f"the record holds no lookup since {at}"
    elif stays and covered < max(stays):
        when = datetime.fromtimestamp(covered).strftime("%H:%M")
        state, why = UNKNOWN, f"the record of lookups reaches only {when}, before the last app stay ended"
    elif good:
        state, why = CLEAN, f"{good} app start{'s' if good > 1 else ''} worked since {at}, and none failed"
    else:
        state, why = UNKNOWN, f"no app start since {at} shows apps working"
    return Verdict(state, t, now, failed, good, pending, covered, why)


# ---- the words ------------------------------------------------------------------------------------------
def stay(seconds: float) -> str:
    """`20 seconds`, `1 minute`, `4 min`: how long an app stayed in front."""
    if seconds < 60:
        n = max(1, round(seconds))
        return f"{n} second{'s' if n > 1 else ''}"
    return "1 minute" if seconds < 120 else receipt.span(seconds)


def refused_words(c: Cause) -> tuple[str, str]:
    """(what refused it, as a clause's start; the command that says why) by the refusal's source."""
    who = f"{c.name} ({c.company}, {c.kind})" if c.company else f"{c.name} ({c.kind})"
    if c.source == FILTER:
        return f"the filter refused {who}", f"sudo tvgw check {c.name}"
    return f"the gateway refused a connection to {who}", "sudo tvgw refused"


def describe(f: FailedStart) -> str:
    """One failed start in plain words: the app, when, what was seen, and the first likely cause with the
    command that explains it. Interactive runs only: it carries an app, a time and a name."""
    name = receipt.short(f.label)
    at = datetime.fromtimestamp(f.start).strftime("%H:%M")
    got = f"{receipt.size(f.down)} down"
    if f.timed == HOURLY:
        head = (
            f"{name} was in front at {at} and at {datetime.fromtimestamp(f.end):%H:%M} with only {got}"
            " (times to the hour, a weaker sign: an app left on its menu reads the same)"
        )
        where = "between those readings"
    elif f.times > 1:
        head = (
            f"{name} opened {f.times} times from {at}, and each time the TV went back to the home screen"
            f" within {stay(f.longest)} ({got})"
        )
        where = "in those minutes"
    elif f.kind == STALLED:
        head = (
            f"{name} opened at {at} and stayed {stay(f.longest)} with only {got}, then the TV went back to"
            " the home screen"
        )
        where = "in those minutes"
    else:
        back = f"the TV went back to the home screen after {stay(f.longest)}"
        head = f"{name} opened at {at}, and {back} ({got})"
        where = "in that minute"
    if not f.fresh:
        head += f"; {name} had been in front earlier that evening, so it may have come back from memory"
    if f.then_stayed:
        head += "; the next time it stayed in front"
    likely = f.likely
    if likely:
        top = likely[0]
        refusal, command = refused_words(top)
        more = len(likely) - 1
        tail = f", and {more} more like it" if more else ""
        return f"{head}; {where} {refusal}, {top.why(name)}{tail}: {command}"
    if f.causes:
        n = len(f.causes)
        what = "1 name" if n == 1 else f"{n} names"
        return f"{head}; {where} the gateway refused only {what} it refuses on purpose or had refused before"
    return f"{head}; the gateway refused nothing {where}"


def summary(found: list[FailedStart]) -> dict:
    """What a persisted report may carry: counts, never an app, a time or a name (design decision 67)."""
    return {
        "starts": len(found),
        "with_cause": sum(1 for f in found if f.likely),
        "hourly": sum(1 for f in found if f.timed == HOURLY),
    }


def day_arg(o: dict) -> str:
    """The `--since` a report's line points the receipt at: its day, or the date its window starts."""
    if o.get("day"):
        return str(o["day"])
    return datetime.fromtimestamp(o.get("since") or time.time()).strftime("%Y-%m-%d")


WORTH_A_LOOK = "one the TV needs, one the app used before, or a refusal the gateway had not made before"


def summary_line(s: dict, day: str) -> str:
    """The persisted reports' words for `summary()`: how many, and where the rest is."""
    n, k = s["starts"], s["with_cause"]
    head = "One app start may have failed." if n == 1 else f"{n} app starts may have failed."
    if k and n == 1:
        what = f" In its minutes, the gateway refused a name worth a look: {WORTH_A_LOOK}."
    elif k:
        whose = "each" if k == n else f"{k} of them"
        what = f" In the minutes of {whose}, the gateway refused a name worth a look: {WORTH_A_LOOK}."
    else:
        what = " The gateway refused nothing worth a look in those minutes."
    return f"{head}{what} Which app and which name: sudo tvgw receipt --since {day}"


def section(found: list[FailedStart]) -> list[str]:
    """The receipt's section, at the top of the screen: one wrapped line each, or nothing."""
    if not found:
        return []
    out = ["Did it work? Apps back at the home screen soon after opening, with almost nothing downloaded:"]
    for f in found:
        out += receipt.wrap(describe(f) + ".", "  ")
    out += receipt.wrap(
        "Something refused in the same minutes is a match in time, not proof: the command at the end of each"
        " line says why it was refused and what to do.",
        "  ",
    )
    return out
