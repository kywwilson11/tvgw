"""The app in front: viewing sessions from the TV's own account of itself, every connection held against
the session it started in, and each app's picture learned over days (design decision 67).

Two sources say which app is in front. The hourly reading (`tvstate`) says it once an hour. The live
reading (tvlive.py, off by default) and a `tvgw tvprobe` run say it at the moment it changes, as events:
`app`, `power`, the session to the TV going up and down, and the gateway's clock being set. `timeline()`
turns both into one partition of a window:

- a **session**: one app in front from start to end, timed `live` (from events, edges to the second) or
  `hourly` (between two readings a short hour apart that name the same app; a switch away and back
  between them is not seen);
- a **gap**: the TV may have been on, and nothing says which app was in front (the live session was
  lost, the readings either side disagree, the gateway's clock was set);
- **none**: the TV said it was off, or was not reachable, at both ends.

Inside the time the live session was up, only events count; outside it, only readings. A connection
belongs to the session that holds the moment it started: the time of its own TLS hello where the capture
has one (a continuation inherits its hello, and so its session, under design decision 21), else
conntrack's start, which can run a minute late. A connection opened in the `lead` seconds before the TV
reported an app change belongs to the new app: apps open connections before they reach the front.

That is a correlation in time, never proof of who opened a connection. The TV's own software talks under
every app, so a name is first sorted by what the profile says it is (`classify`), and only names that
are neither the platform's nor the TV maker's can belong to an app's picture:

- `platform`: the profile's must-allow hosts, its clock hosts and the vendor's expected category;
- `vendor`: the TV maker's other categories (its advertising, usage reporting, fingerprinting);
- `tracking`: anybody else's advertising and measurement;
- `content`: the profile's other expected categories (streaming, free channels);
- `shared`: internet plumbing several apps use (certificate checks, shared delivery networks);
- `other`: a category the profile names that is none of these;
- `unclassified`: the profile has no category for the name yet. It is never counted as somebody else's:
  on the reference gateway one app's whole video came from a delivery host the profile did not know.

A picture's unit is a registrable domain with its category: `nflxvideo.net / Streaming`. A full host name
does not carry over from one evening to the next (delivery hosts are numbered per session), and a
registrable domain alone would file an app's measurement host with its video (`ichnaea.netflix.com` beside
`netflix.com`); `tvgw receipt --evaluate` measures all three. On the reference gateway's first 28 days
the full name kept 19% of one app's bytes inside its picture from the other days and 0.1% of another's;
the domain kept 100% of both.

A picture is what was seen under the app on earlier viewing days, each unit with the number of days it
was seen on. One earlier day is enough to be in it (PICTURE_MIN_DAYS): on the same 28 days a three-day
rule put half of one app's connections outside its own picture, because an app's less common names show
up on few days and the hourly readings miss the hour an app starts in. A unit seen on one day only is
`thin`, on PICTURE_FIRM_DAYS or more `firm`, and every report says which. A name is `new` under an app
when no earlier day has it, and nothing is called new until the app itself has PICTURE_READY_DAYS earlier
days. A viewing day runs from DAY_START_HOUR to the same hour of the next morning, so an evening that runs
past midnight is one day.

A second witness needs no clock at all: the TLS stack. Each app that brings its own TLS library sends
hellos with its own fingerprint (JA4), and the TV's shared software sends others. `Stacks` learns, from
the hellos sent in sessions, which fingerprint is one app's (STACK_PURE of at least STACK_MIN hellos under
that app) and which is the system's (under SYSTEM_APPS apps or more, none above SYSTEM_PURITY). It names
the software that opened a connection, whichever app was in front: in a gap it says whose connection it
probably was, and in a session it says when another app's software talked.

Nothing here writes, connects or refuses anything.
"""

from __future__ import annotations

import bisect
import itertools
import json
import math
import sqlite3
from collections.abc import Callable, Iterable
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from fnmatch import fnmatchcase

from tvgw import names, queries
from tvgw.profile import OTHER as NO_CATEGORY  # the category of a name no pattern of the profile matches
from tvgw.profile import Profile, covers

# ---- the vocabulary ---------------------------------------------------------------------------------
LEAD_SECONDS = (
    3.0  # a connection this long before an app change is the new app's (a guess; evaluate measures it)
)
PICTURE_MIN_DAYS = 1  # earlier viewing days a unit must be seen on under an app to be in its picture
PICTURE_FIRM_DAYS = 2  # seen on this many: firm; on fewer: thin, and every report says so
PICTURE_READY_DAYS = 3  # earlier viewing days an app needs before any name is called new under it
# deep dive 14, F6, with its 200 hellos halved: `--evaluate` holds the rule to a leave-one-day-out test
STACK_PURE, STACK_MIN, SYSTEM_APPS, SYSTEM_PURITY = 0.9, 100, 3, 0.5
PICTURE_DAYS = 28  # how far back a picture is learned from
DAY_START_HOUR = 5  # a viewing day runs 05:00 to 05:00 local: an evening past midnight is one day
CONT_TAIL = 6 * 3600.0  # a continuation's row can start this long after the window its hello fell in
ON, IDLE, OFF = "on", "idle", "off"
POWER_ON = ("Active", "Screen Off")  # Screen Off: the panel is dark, the app and its sound still run
POWER_IDLE = ("Screen Saver",)  # on and idle, the app still in front behind the screen saver
POWER_OFF = ("Active Standby", "Suspend", "Power Off")
GOING_OFF = (
    "Request Power Off",
    "Request Active Standby",
    "Prepare Active Standby",
    "Request Suspend",
    "Prepare Suspend",
)
SESSION, GAP, NONE = "session", "gap", "none"
LIVE, HOURLY = "live", "hourly"
# kinds of app: what a session of each can claim
APP, HOME, INPUT, CAST = "app", "home", "input", "cast"
HOME_APPS = ("", "com.webos.app.home", "com.webos.app.launcher")  # as autoblock.HOME_APPS
# an input shows another device's picture and needs no internet; the identifiers are the ones LG
# integrations use (autoblock.INPUT_APP_PREFIXES), none seen on the reference TV yet
INPUT_APP_PREFIXES = ("com.webos.app.hdmi", "com.webos.app.livetv", "com.webos.app.externalinput")
# a cast receiver shows what a phone sends it: the session is the receiver's, what was cast is not
# visible here (REPORTED identifiers, not seen on the reference TV)
CAST_APPS = ("com.webos.app.miracast", "com.webos.app.screenshare", "airplay")
# what the TV calls the apps people know by another name; an id not here is shown as the TV names it
APP_NAMES = {
    "youtube.leanback.v4": "YouTube",
    "netflix": "Netflix",
    "amazon": "Prime Video",
    "com.disney.disneyplus-prod": "Disney+",
    "com.webos.app.home": "Home screen",
    "com.webos.app.launcher": "Home screen",
    "com.webos.app.livetv": "Live TV",
    "com.webos.app.browser": "Web browser",
    "com.webos.app.discovery": "LG Content Store",
    "com.webos.app.miracast": "Screen Share",
    "airplay": "AirPlay",
}
PLATFORM, VENDOR, TRACKING, CONTENT, SHARED, OTHER, UNCLASSIFIED = (
    "platform",
    "vendor",
    "tracking",
    "content",
    "shared",
    "other",
    "unclassified",
)
SHARED_CATEGORIES = ("Infra",)
TRACKING_CATEGORIES = ("ACR", "3rd-party ads")
PICTURE_CLASSES = (CONTENT, SHARED, TRACKING, OTHER, UNCLASSIFIED)  # what can be in an app's picture
_APP_ID = "abcdefghijklmnopqrstuvwxyz0123456789._+-"


def company_of(name: str) -> str | None:
    """The company behind a host name, or None when nothing here knows it. The one place the receipt
    asks: a source of company names is plugged in here, and until one is the receipt shows the
    registrable domain alone."""
    return None


def app_kind(app: str) -> str:
    """What a session of `app` is: the home screen, an input (HDMI, live TV), a cast receiver, or an app
    that could have a picture of its own."""
    if app in HOME_APPS:
        return HOME
    if app.startswith(INPUT_APP_PREFIXES):
        return INPUT
    return CAST if app in CAST_APPS else APP


def app_label(app: str) -> str:
    """`YouTube (youtube.leanback.v4)` for an id this table knows, the id alone otherwise; the home screen
    and an input by their plain names."""
    if app in HOME_APPS:
        return "Home screen"
    if app.startswith("com.webos.app.hdmi"):
        return f"HDMI {app[len('com.webos.app.hdmi') :] or 'input'}".strip()
    name = APP_NAMES.get(app)
    return f"{name} ({app})" if name else app


def clean_app(app) -> str:
    """An app id as it may be kept: the TV chooses the string, so anything but a plain id is `invalid`."""
    if app is None or app == "":
        return ""
    ok = isinstance(app, str) and 0 < len(app) <= 128 and app[0].isalnum() and set(app) <= set(_APP_ID)
    return app if ok else "invalid"


def power_class(state: str, processing: str = "") -> str | None:
    """ON, IDLE or OFF for a power reading or event; None for a word this vocabulary does not know, which
    changes nothing. A TV that says it is switching off is off from that message on."""
    if processing in GOING_OFF or state in POWER_OFF:
        return OFF
    if state in POWER_IDLE:
        return IDLE
    return ON if state in POWER_ON else None


def viewing_day(t: float) -> int:
    """The viewing day a moment falls in, as a day number: 05:00 local to 05:00."""
    return (datetime.fromtimestamp(t) - timedelta(hours=DAY_START_HOUR)).toordinal()


# ---- events ------------------------------------------------------------------------------------------
@dataclass(frozen=True, order=True)
class Event:
    """One line of the live record. `kind` is `app` (value: the id), `power` (value: the state, detail:
    its `processing`), `conn` (value: up or down; detail: why), `link` (up or down), `alive` (the session
    answered a ping), `clock` (value: the seconds the gateway's clock jumped by, at the new time) or
    `watch` (value: start, stop, refused)."""

    t: float
    kind: str
    value: str = ""
    detail: str = ""


# events that share a time are taken in one fixed order, whatever order they arrived in: a session to the
# TV comes up before what it reports, and what it reports is read before the session goes down (the
# service writes "the TV is switching off" and its own goodbye in the same millisecond)
_RANK = {"watch": 0, "cut": 1, "resume": 2, "up": 3, "clock": 4, "power": 5, "app": 6, "alive": 7, "down": 8}


def _order(e: Event) -> tuple:
    kind = e.value if e.kind in ("conn", "link") else e.kind
    return (e.t, _RANK.get(kind, 9), e.kind, e.value, e.detail)


def parse_event(line: str) -> Event | None:
    """One JSON line of the live reading's file or of a `tvgw tvprobe` log, as an Event; None for a line
    that is neither (a subscription's acknowledgement, a line cut short, a kind nothing here uses)."""
    try:
        rec = json.loads(line)
    except ValueError:
        return None
    if not isinstance(rec, dict):
        return None
    t, kind = rec.get("t"), rec.get("kind")
    if (
        isinstance(t, bool)
        or not isinstance(t, int | float)
        or not isinstance(kind, str)
        or not math.isfinite(t)
    ):
        return None
    t = float(t)
    if kind == "app":
        return Event(t, "app", clean_app(rec.get("appId")))
    if kind == "power":
        state = rec.get("state")
        if not isinstance(state, str):
            return None
        proc = rec.get("processing")
        return Event(t, "power", state[:40], proc[:40] if isinstance(proc, str) else "")
    if kind == "link":
        up = rec.get("up")
        return Event(t, "link", "up" if up is True else "down") if isinstance(up, bool) else None
    if kind == "session.up":
        return Event(t, "conn", "up")
    if kind in ("session.down", "session.fail", "session.end"):
        why = rec.get("why") or rec.get("error") or kind
        return Event(t, "conn", "down", _word(str(why)))
    if kind == "alive":
        return Event(t, "alive")
    if kind == "clock":
        step = rec.get("step")
        if isinstance(step, bool) or not isinstance(step, int | float) or not math.isfinite(step):
            return None
        return Event(t, "clock", repr(float(step)))
    if kind in ("watch.start", "probe.start"):
        return Event(t, "watch", "start")
    if kind in ("watch.stop", "probe.stop"):
        return Event(t, "watch", "stop")
    if kind in ("watch.refused", "pair.rejected"):
        return Event(t, "watch", "refused")
    return None


def _word(text: str) -> str:
    """The first word of a reason (`TimeoutError: ...` -> `TimeoutError`): the rest can carry an address."""
    head = text.split(":", 1)[0].strip()[:40]
    return head if head and all(ch.isalnum() or ch in " ._-" for ch in head) else "error"


def read_events(path: str) -> list[Event]:
    """The events of a file of JSON lines (the live reading's, or a probe's)."""
    out = []
    with open(path, encoding="utf-8", errors="replace") as fh:
        for line in fh:
            e = parse_event(line)
            if e is not None:
                out.append(e)
    return out


def stored_events(conn: sqlite3.Connection, a: float, b: float) -> list[Event]:
    """The live record of [a, b) from the store; none from a store that has no such table yet."""
    try:
        rows = conn.execute(
            "SELECT t, kind, COALESCE(value,''), COALESCE(detail,'') FROM tv_events WHERE t >= ? AND t < ?"
            " ORDER BY t, id",
            (a, b),
        ).fetchall()
    except sqlite3.OperationalError:
        return []
    return [Event(*r) for r in rows]


def readings(conn: sqlite3.Connection, a: float, b: float) -> list[tuple[float, str, str]]:
    """The hourly readings of [a, b), with one reading's reach either side so the window's edges are
    judged like its middle: (t, power, app)."""
    reach = queries.STANDBY_GAP
    return [
        (t, power or "", clean_app(app))
        for t, power, app in conn.execute(
            "SELECT t, power, app FROM tvstate WHERE t >= ? AND t < ? ORDER BY t", (a - reach, b + reach)
        )
    ]


# ---- sessions ----------------------------------------------------------------------------------------
@dataclass
class Session:
    app: str
    start: float
    end: float
    timed: str  # LIVE | HOURLY
    start_exact: bool = False  # the TV reported the change that began it
    end_exact: bool = False
    began: str = ""  # app (an app change), wake (the TV came on with it in front), connect, reading
    end_why: str = ""  # app, off, lost, clock, reading, open (still in front at the end of the record)
    idle: list[tuple[float, float]] = field(default_factory=list)  # behind the screen saver

    @property
    def kind(self) -> str:
        return app_kind(self.app)

    @property
    def seconds(self) -> float:
        return self.end - self.start

    @property
    def idle_seconds(self) -> float:
        return sum(e - s for s, e in self.idle)

    @property
    def leads(self) -> bool:
        """Whether connections just before its start are its own: only where the TV reported the app
        change itself, to the second."""
        return self.timed == LIVE and self.start_exact and self.began == "app"

    def is_idle(self, t: float) -> bool:
        return any(s <= t < e for s, e in self.idle)


@dataclass(frozen=True)
class Piece:
    t0: float
    t1: float
    cls: str  # SESSION | GAP | NONE
    session: Session | None = None


@dataclass
class Timeline:
    """A window cut into pieces that touch and never overlap, each a session, a gap or none."""

    a: float
    b: float
    pieces: list[Piece]
    lead: float = LEAD_SECONDS
    periods: list[tuple[float, float]] = field(default_factory=list)  # the live session to the TV was up
    _starts: list[float] = field(default_factory=list, repr=False)

    def __post_init__(self) -> None:
        self._starts = [p.t0 for p in self.pieces]

    @property
    def sessions(self) -> list[Session]:
        seen: dict[int, Session] = {}
        for p in self.pieces:
            if p.session is not None:
                seen.setdefault(id(p.session), p.session)
        return sorted(seen.values(), key=lambda s: (s.start, s.app))

    def at(self, t: float) -> tuple[str, Session | None, bool]:
        """(class, session, lead) for a moment: the piece that holds it, or, in the `lead` seconds before
        an app change the TV reported, the session that change began. Outside the window: a gap."""
        if not self.a <= t < self.b:
            return GAP, None, False
        i = bisect.bisect_right(self._starts, t) - 1
        if i + 1 < len(self.pieces):
            nxt = self.pieces[i + 1]
            s = nxt.session
            if s is not None and s.leads and nxt.t0 == s.start and 0 < nxt.t0 - t <= self.lead:
                return SESSION, s, True
        p = self.pieces[i]
        return p.cls, p.session, False

    def label(self, t: float) -> str:
        """The app in front at `t`, or `(gap)` or `(none)`."""
        cls, s, _ = self.at(t)
        return s.app or "(home)" if s is not None else f"({cls})"

    def seconds(self) -> dict[str, float]:
        """Seconds of the window in live sessions, hourly sessions, gaps and none."""
        out = {LIVE: 0.0, HOURLY: 0.0, GAP: 0.0, NONE: 0.0}
        for p in self.pieces:
            out[p.session.timed if p.session is not None else p.cls] += p.t1 - p.t0
        return out


def _clock_gaps(events: list[Event]) -> list[tuple[float, float]]:
    """The stretches a clock step makes unusable: a step forward by s at the new time T never happened
    between T-s and T; a step back makes T to T+s happen twice. Merged where they touch."""
    spans = []
    for e in events:
        if e.kind == "clock":
            try:
                step = float(e.value)
            except ValueError:
                continue
            if step:
                spans.append((min(e.t, e.t - step), max(e.t, e.t - step)))
    out: list[tuple[float, float]] = []
    for g0, g1 in sorted(spans):
        if out and g0 <= out[-1][1]:
            out[-1] = (out[-1][0], max(out[-1][1], g1))
        else:
            out.append((g0, g1))
    return out


def _in(spans: list[tuple[float, float]], t: float) -> bool:
    return any(s <= t < e for s, e in spans)


class _Live:
    """The events of the live record walked once, in their fixed order: the stretches the session to the
    TV was up (`periods`), and inside them the pieces."""

    def __init__(self, known_until: float | None):
        self.known_until = known_until
        self.periods: list[tuple[float, float]] = []
        self.pieces: list[Piece] = []
        self.up = False
        self.was_up = False  # across a clock gap
        self.since = 0.0
        self.mark = 0.0  # where the piece being written began
        self.last = 0.0
        self.power: str | None = None
        self.app: str | None = None
        self.fresh = True  # no app event yet on this session: the first one says what was already in front
        self.cur: Session | None = None
        self.alive = False

    def _cls(self) -> str:
        return SESSION if self.cur is not None else NONE if self.power == OFF else GAP

    def _cut(self, t: float) -> None:
        """End the piece being written at `t`; the next begins there."""
        if t > self.mark:
            self.pieces.append(Piece(self.mark, t, self._cls(), self.cur))
        self.mark = max(self.mark, t)

    def _open(self, t: float, exact: bool, began: str) -> None:
        self._cut(t)
        self.cur = Session(self.app or "", t, t, LIVE, start_exact=exact, began=began)
        if self.power == IDLE:
            self.cur.idle.append((t, t))

    def _close(self, t: float, why: str, exact: bool) -> None:
        if self.cur is None:
            return
        self._cut(t)
        s = self.cur
        s.end, s.end_why, s.end_exact = t, why, exact
        if s.idle and s.idle[-1][1] <= s.idle[-1][0]:  # the screen saver was still up
            s.idle[-1] = (s.idle[-1][0], t)
        s.idle = [(i0, i1) for i0, i1 in s.idle if i1 > i0]
        self.cur = None

    def _down(self, t: float, why: str) -> None:
        if not self.up:
            return
        self._close(t, why, False)
        self._cut(t)
        if t > self.since:
            self.periods.append((self.since, t))
        self.up = False

    def _up(self, t: float) -> None:
        self.up, self.since, self.mark, self.last = True, t, t, t
        self.power, self.app, self.fresh, self.cur = None, None, True, None

    def feed(self, e: Event) -> None:
        if e.kind == "cut":
            self.was_up = self.up
            self._down(e.t, "clock")
            return
        if e.kind == "resume":
            if self.was_up:
                self._up(e.t)
            return
        if e.kind == "watch":
            # a new start with the session still up: it ended unseen, some time after its last word. A
            # stop or a refusal on record is the process saying when
            self._down(self.last if e.value == "start" else e.t, "lost")
            return
        if e.kind == "conn":
            if e.value == "up":
                self._down(self.last, "lost")
                self._up(e.t)
            else:
                self._down(e.t, "lost")
            return
        if e.kind == "link":
            if e.value == "down":
                self._down(e.t, "lost")
            return
        if not self.up:
            return
        self.last = e.t
        if e.kind == "alive":
            self.alive = True
        elif e.kind == "power":
            self._power(e)
        elif e.kind == "app":
            self._app(e)

    def _power(self, e: Event) -> None:
        cls = power_class(e.value, e.detail)
        if cls is None or cls == self.power:
            return
        if cls == OFF:
            self._close(e.t, "off", True)
        self._cut(e.t)  # what came before keeps the class it had
        before, self.power = self.power, cls
        if cls == OFF:
            return
        if self.cur is None:
            if before == OFF and self.app is not None:
                self._open(e.t, True, "wake")
            return
        if cls == IDLE:
            self.cur.idle.append((e.t, e.t))
        elif self.cur.idle and self.cur.idle[-1][1] <= self.cur.idle[-1][0]:
            self.cur.idle[-1] = (self.cur.idle[-1][0], e.t)

    def _app(self, e: Event) -> None:
        first, self.fresh = self.fresh, False
        self.app = e.value
        if self.power == OFF:
            return  # the TV says it is off: the app it names is in front of nobody
        if self.cur is not None and self.cur.app == e.value:
            return
        self._close(e.t, "app", True)
        self._open(e.t, not first, "connect" if first else "app")

    def finish(self) -> None:
        if not self.up:
            return
        # the record ends with the session up: it is known up to its last ping, or, for a record that
        # carries no pings (a probe's), up to when the record was last written
        end = self.last if self.alive or self.known_until is None else max(self.last, self.known_until)
        self._close(end, "open", False)
        self._cut(end)
        if end > self.since:
            self.periods.append((self.since, end))
        self.up = False


def _hourly(rows: list[tuple[float, str, str]]) -> list[tuple[float, float, str, str, bool]]:
    """Each pair of consecutive readings as (t0, t1, class, app, idle): a session where both are awake a
    short hour apart and name the same app, none where neither is awake, a gap otherwise."""
    out = []
    for (t0, p0, a0), (t1, p1, a1) in itertools.pairwise(rows):
        if t1 <= t0:
            continue
        near = t1 - t0 <= queries.STANDBY_GAP
        on0, on1 = p0 in queries.AWAKE, p1 in queries.AWAKE
        if near and on0 and on1 and a0 == a1:
            out.append((t0, t1, SESSION, a0, p0 in POWER_IDLE and p1 in POWER_IDLE))
        elif near and not on0 and not on1:
            out.append((t0, t1, NONE, "", False))
        else:
            out.append((t0, t1, GAP, "", False))
    return out


def _outside(a: float, b: float, spans: list[tuple[float, float]]) -> list[tuple[float, float]]:
    """[a, b) less the spans, as the pieces that remain, in order."""
    out, at = [], a
    for s, e in sorted(spans):
        if e <= at or s >= b:
            continue
        if s > at:
            out.append((at, s))
        at = max(at, e)
    if at < b:
        out.append((at, b))
    return out


def timeline(
    events: Iterable[Event],
    rows: list[tuple[float, str, str]],
    a: float,
    b: float,
    lead: float = LEAD_SECONDS,
    known_until: float | None = None,
) -> Timeline:
    """The window [a, b) as sessions, gaps and none, from the live record and the hourly readings.
    `known_until` is when the live record was last written, for a record that ends with its session up.
    The result does not depend on the order the events are given in."""
    evs = sorted(set(events), key=_order)
    gaps = _clock_gaps(evs)
    if gaps:
        evs = [e for e in evs if e.kind == "clock" or not _in(gaps, e.t)]
        evs += [Event(g0, "cut") for g0, _ in gaps] + [Event(g1, "resume") for _, g1 in gaps]
        evs.sort(key=_order)
    live = _Live(known_until)
    for e in evs:
        live.feed(e)
    live.finish()
    pieces = [
        Piece(max(p.t0, a), min(p.t1, b), p.cls, p.session) for p in live.pieces if p.t1 > a and p.t0 < b
    ]
    pieces += [Piece(max(g0, a), min(g1, b), GAP) for g0, g1 in gaps if g1 > a and g0 < b]
    # outside the live record, the readings; a run of pieces that touch and name one app is one session
    taken = live.periods + gaps
    run: Session | None = None
    for t0, t1, cls, app, idle in _hourly([r for r in rows if not _in(gaps, r[0])]):
        for s0, s1 in _outside(t0, t1, taken):
            if cls == SESSION:
                if run is None or run.app != app or run.end != s0:
                    run = Session(app, s0, s1, HOURLY, began="reading", end_why="reading")
                run.end = s1
                if idle:
                    run.idle.append((s0, s1))
            if s1 > a and s0 < b:
                pieces.append(Piece(max(s0, a), min(s1, b), cls, run if cls == SESSION else None))
    pieces.sort(key=lambda p: (p.t0, p.t1))
    out: list[Piece] = []
    at = a
    for p in pieces:
        t0 = max(p.t0, at)  # the live record wins where two sources meet at an edge
        if p.t1 <= t0:
            continue
        if t0 > at:
            out.append(Piece(at, t0, GAP))
        out.append(Piece(t0, p.t1, p.cls, p.session))
        at = p.t1
    if at < b:
        out.append(Piece(at, b, GAP))
    periods = [(max(p0, a), min(p1, b)) for p0, p1 in live.periods if p1 > a and p0 < b]
    return Timeline(a, b, out, lead, periods)


def shifted(events: Iterable[Event], seconds: float) -> list[Event]:
    """The record as it would read with the TV's own reports (app, power) arriving `seconds` late."""
    return [
        Event(e.t + seconds, e.kind, e.value, e.detail) if e.kind in ("app", "power") else e for e in events
    ]


# ---- what a name is ----------------------------------------------------------------------------------
@dataclass(frozen=True)
class Kind:
    cls: str  # PLATFORM | VENDOR | TRACKING | CONTENT | SHARED | OTHER | UNCLASSIFIED
    category: str
    domain: str
    why: str  # one plain sentence: what made it this class

    @property
    def unit(self) -> tuple[str, str]:
        return (self.domain, self.category)


def classify(profile: Profile, name: str) -> Kind:
    """What the profile says a name is, before any app is considered."""
    host = names.normalize(name)
    cat = profile.categorize(host)
    dom = names.registrable_domain(host)
    reason = next((why for pat, why in profile.must_allow.items() if covers(pat, host)), None)
    if reason is not None:
        return Kind(PLATFORM, cat, dom, f"it is one of the names the TV must reach ({reason})")
    if any(fnmatchcase(host, pat) for pat in profile.clock_hosts):
        return Kind(PLATFORM, cat, dom, "it is where the TV sets its clock")
    vendor = bool(profile.vendor) and cat.startswith(profile.vendor + " ")
    if vendor and cat in profile.expected_categories:
        return Kind(PLATFORM, cat, dom, f"the profile files it under {cat}, the TV's own services")
    if vendor:
        return Kind(
            VENDOR, cat, dom, f"the profile files it under {cat}, which is {profile.vendor}'s, not an app's"
        )
    if cat in TRACKING_CATEGORIES:
        return Kind(TRACKING, cat, dom, f"the profile files it under {cat}")
    if cat in SHARED_CATEGORIES:
        return Kind(SHARED, cat, dom, f"the profile files it under {cat}, plumbing several apps use")
    if cat in profile.expected_categories:
        return Kind(CONTENT, cat, dom, f"the profile files it under {cat}")
    if cat == NO_CATEGORY:
        return Kind(UNCLASSIFIED, cat, dom, "the profile has no category for it yet")
    return Kind(OTHER, cat, dom, f"the profile files it under {cat}")


# ---- connections, lookups and hellos -----------------------------------------------------------------
@dataclass(frozen=True)
class Conn:
    t: float  # when it started: its hello's time where the capture has one, else conntrack's start
    name: str  # its TLS name, "" when no hello named it
    up: int
    down: int
    hello: bool  # timed by a hello
    ja4: str = ""
    t_end: float = 0.0

    @property
    def bytes(self) -> int:
        return self.up + self.down


# the hello FLOW_NAME picks, by its row: the same choice, so a connection's name and its time agree
_HELLO_ID = queries.FLOW_NAME.replace("SELECT x.sni", "SELECT x.id", 1)


def connections(conn: sqlite3.Connection, a: float, b: float, gw_ip: str) -> list[Conn]:
    """The TV's connections to the internet that started in [a, b), each with the name and the time of
    its hello. Connections to the gateway itself (its resolver, its file-service filter) and to addresses
    no internet host answers from are left out: they are not somebody the TV talked to."""
    rows = conn.execute(
        f"""SELECT g.t_start, g.t_end, g.dst, COALESCE(g.bytes_up,0), COALESCE(g.bytes_down,0),
                   h.t, h.sni, h.ja4
            FROM (SELECT f.t_start, f.t_end, f.dst, f.bytes_up, f.bytes_down, {_HELLO_ID} AS hid
                  FROM flows f WHERE f.t_start >= ? AND f.t_start < ?) g
            LEFT JOIN tls h ON h.id = g.hid""",
        (a - queries.FLOW_SLACK, b + CONT_TAIL),
    ).fetchall()
    out = []
    for t_start, t_end, dst, up, down, ht, sni, ja4 in rows:
        if dst == gw_ip or not names.is_public_address(dst):
            continue
        t = ht if ht is not None else t_start
        if a <= t < b:
            out.append(Conn(t, sni or "", up, down, ht is not None, ja4 or "", t_end))
    out.sort(key=lambda c: c.t)
    return out


def hellos(conn: sqlite3.Connection, a: float, b: float) -> list[tuple[float, str, str]]:
    """(t, name, ja4) of every TLS hello the TV sent in [a, b): what pictures are learned from."""
    try:
        rows = conn.execute(
            "SELECT t, sni, COALESCE(ja4,'') FROM tls WHERE t >= ? AND t < ? ORDER BY t", (a, b)
        ).fetchall()
    except sqlite3.OperationalError:  # a store from before schema 8 has no ja4 column
        rows = [
            (t, sni, "")
            for t, sni in conn.execute("SELECT t, sni FROM tls WHERE t >= ? AND t < ? ORDER BY t", (a, b))
        ]
    return [(t, sni, ja4) for t, sni, ja4 in rows if sni]


def lookups(conn: sqlite3.Connection, a: float, b: float) -> list[tuple[float, str, int]]:
    """(t, name, blocked) of the TV's lookups in [a, b)."""
    return conn.execute(
        "SELECT t, qname, blocked FROM dns WHERE t >= ? AND t < ? ORDER BY t", (a, b)
    ).fetchall()


# ---- pictures ----------------------------------------------------------------------------------------
Key = Callable[[Kind, str], object]


def unit_key(kind: Kind, name: str) -> object:
    """A picture's unit: the registrable domain with its category."""
    return kind.unit


@dataclass
class Evidence:
    """What was seen under each app, by viewing day: `days[app]` the days it was in front, `seen[app][unit]`
    the days that unit was contacted while it was."""

    days: dict[str, set[int]] = field(default_factory=dict)
    seen: dict[str, dict[object, set[int]]] = field(default_factory=dict)
    names: dict[str, dict[str, set[int]]] = field(default_factory=dict)  # by full host name, for `--why`

    def picture(
        self,
        app: str,
        before: int | None = None,
        without: int | None = None,
        min_days: int = PICTURE_MIN_DAYS,
    ) -> set:
        """The units seen under `app` on at least `min_days` viewing days: days before `before` (what a
        rule would have known that day), or every day but `without` (leave one day out)."""
        return {
            u
            for u, days in self.seen.get(app, {}).items()
            if len(self._kept(days, before, without)) >= min_days
        }

    def days_known(self, app: str, before: int | None = None, without: int | None = None) -> int:
        return len(self._kept(self.days.get(app, set()), before, without))

    def ready(self, app: str, before: int) -> bool:
        """Whether `app` had enough earlier viewing days on `before` for anything to be called an outsider."""
        return self.days_known(app, before) >= PICTURE_READY_DAYS

    def days_seen(self, app: str, unit: object, before: int | None = None, without: int | None = None) -> int:
        return len(self._kept(self.seen.get(app, {}).get(unit, set()), before, without))

    def days_named(self, app: str, host: str, before: int | None = None) -> int:
        """The viewing days this exact host name was seen on under `app`: a unit is seen through any of
        its names, and `--why` tells the two apart."""
        return len(self._kept(self.names.get(app, {}).get(host, set()), before, None))

    def apps_with(
        self, unit: object, before: int | None = None, min_days: int = PICTURE_MIN_DAYS
    ) -> list[str]:
        """The apps whose picture holds `unit`."""
        return sorted(app for app in self.seen if unit in self.picture(app, before, None, min_days))

    @staticmethod
    def _kept(days: set[int], before: int | None, without: int | None) -> set[int]:
        return {d for d in days if (before is None or d < before) and d != without}


def learn(
    tl: Timeline,
    seen: Iterable[tuple[float, str, str]],
    profile: Profile,
    key: Key = unit_key,
    only_days: set[int] | None = None,
) -> Evidence:
    """What each app's sessions show: every hello sent while an app (not the home screen, an input or a
    cast receiver) was in front, kept by unit and viewing day, unless the profile says the name is the
    platform's or the TV maker's. `only_days` keeps those viewing days alone."""
    ev = Evidence()
    for t, name, _ in seen:
        cls, s, _lead = tl.at(t)
        if cls != SESSION or s is None or s.kind != APP:
            continue
        day = viewing_day(t)
        if only_days is not None and day not in only_days:
            continue
        ev.days.setdefault(s.app, set()).add(day)
        kind = classify(profile, name)
        if kind.cls in PICTURE_CLASSES:
            host = names.normalize(name)
            ev.seen.setdefault(s.app, {}).setdefault(key(kind, host), set()).add(day)
            ev.names.setdefault(s.app, {}).setdefault(host, set()).add(day)
    return ev


# ---- the TLS stack as a second witness ---------------------------------------------------------------
@dataclass
class Stacks:
    """Hellos by fingerprint, app in front and viewing day: `seen[ja4][(app, day)]`."""

    seen: dict[str, dict[tuple[str, int], int]] = field(default_factory=dict)

    def apps(self, ja4: str, without: int | None = None) -> dict[str, int]:
        """Hellos with this fingerprint under each app, on every day but `without`."""
        out: dict[str, int] = {}
        for (app, day), n in self.seen.get(ja4, {}).items():
            if day != without:
                out[app] = out.get(app, 0) + n
        return out

    def verdict(self, ja4: str, without: int | None = None) -> tuple[str, str | None, int, float]:
        """(`app`, the app, hellos, purity) for a fingerprint that is one app's; (`system`, None, ...) for
        one several apps share; (``, the most common app, ...) for one nothing can be said of yet."""
        apps = self.apps(ja4, without)
        n = sum(apps.values())
        if not n:
            return "", None, 0, 0.0
        top, top_n = sorted(apps.items(), key=lambda kv: (-kv[1], kv[0]))[0]
        purity = top_n / n
        if purity >= STACK_PURE and n >= STACK_MIN:
            return "app", top, n, purity
        if len(apps) >= SYSTEM_APPS and purity < SYSTEM_PURITY:
            return "system", None, n, purity
        return "", top, n, purity

    def names(self, ja4: str, without: int | None = None) -> str | None:
        """The app whose software sends this fingerprint, or None when it is not one app's."""
        kind, app, _, _ = self.verdict(ja4, without) if ja4 else ("", None, 0, 0.0)
        return app if kind == "app" else None


def learn_stacks(tl: Timeline, seen: Iterable[tuple[float, str, str]]) -> Stacks:
    """The fingerprints of the hellos sent while an app was in front, by app and viewing day."""
    st = Stacks()
    for t, _, ja4 in seen:
        if not ja4:
            continue
        cls, s, _lead = tl.at(t)
        if cls == SESSION and s is not None and s.kind == APP:
            cell = st.seen.setdefault(ja4, {})
            key = (s.app, viewing_day(t))
            cell[key] = cell.get(key, 0) + 1
    return st
