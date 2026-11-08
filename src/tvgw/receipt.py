"""`tvgw receipt`: what the TV talked to, by the app that was in front (design decision 67).

Four views of the same record, each in plain words:

- the **receipt**: for each viewing session, the app, when and how long, and every connection that started
  while it was in front, sorted by what the name is: seen with the app before, advertising and
  measurement, the TV's own services, and what also talked and was new; then what the filter refused
  meanwhile;
- the **picture** (`--picture`): what each app has been seen with, on how many of its days;
- the **replay** (`--replay`): what an imagined rule "while an app is in front, allow its picture and the
  TV's essentials" would have refused over the store. A report: nothing enforces;
- **why** (`--why NAME`): why a name counts as an app's company, the TV's own or new.

What it may say is bounded by what the record is. A connection is listed under the app that was in front
when it started: a match in time, never proof of which software opened it. So no line says an app "sent"
anything; platform, advertising and measurement names are "while X was in front"; a name not seen with
the app before "also talked"; a name the profile has no category for is "not classified yet", never
somebody else's; and nothing is called new until the app has enough days behind it. `FORBIDDEN` lists the
words a line may never use, and a test holds every line this module can write to it.

Everything here reads the store and writes nothing.
"""

from __future__ import annotations

import re
import sqlite3
import textwrap
import time
from collections.abc import Callable
from dataclasses import dataclass
from datetime import datetime, timedelta

from tvgw import appfront, names, plain
from tvgw.appfront import APP, CAST, HOME, INPUT, SESSION, Conn, Event, Kind, Session, Timeline
from tvgw.profile import Profile, covers

LOOKBACK = appfront.PICTURE_DAYS * 86400.0
SETTLE = 7440 + 3600 + 600  # a connection is logged when conntrack lets it go, up to 2 h 04 min after its
# last packet, and loaded by the next hourly ingest: a session younger than this is still filling in
TOP_ROWS = 8  # rows a group shows before "and N more"
TOP_REFUSED = 5
REPLAY_DAYS = 14
# the bar an app-in-front rule would have to clear in a replay before it is ever tried (decision 67)
BAR_CONTENT_OUTSIDE = 0.01
BAR_MUST_ALLOW_OUTSIDE = 0
BAR_UNNAMED = 0.05
BAR_DAYS = 28
BAR_LIVE_SHARE = 0.9
# words no line of a receipt may use: they claim who acted, or why, which a match in time cannot show
FORBIDDEN = re.compile(
    r"\b(sent|sends|sending|tracked|tracks you|tracking you|spied|spies|spying|stole|leaked|leaks|"
    r"caused|because of|responsible|guilty|proves|proof that|talked to|contacted|phoned home)\b",
    re.IGNORECASE,
)
FOOTER = (
    "A connection is listed under the app that was in front when it started. That is a match in time,"
    " not proof of which software opened it: the TV's own software talks under every app."
)
KIND_NOTE = {
    HOME: "The home screen is the TV's own software; it has no picture of its own.",
    INPUT: "An input shows another device's picture and needs no internet. What is listed here belongs to"
    " the TV's own software, or to an app still running behind it.",
    CAST: "A cast receiver shows what a phone hands it; what was cast is not visible to the gateway.",
}


def size(n: float) -> str:
    """Bytes in the brief's units (powers of 1024), moving to the next unit at 1000 so that no figure has
    four digits before its point."""
    for unit in ("B", "KB", "MB"):
        if abs(n) < 1000:
            return f"{n:.0f} {unit}" if unit == "B" else f"{n:.1f} {unit}"
        n /= 1024
    return f"{n:.1f} GB"


def short(label: str) -> str:
    """An app's name as a sentence takes it: `YouTube` for `YouTube (youtube.leanback.v4)`, and `the home
    screen` in the middle of a sentence."""
    name = label.split(" (")[0]
    return "the home screen" if name == "Home screen" else name


def span(seconds: float) -> str:
    """`3 h 35 min`, `12 min`, `under a minute`."""
    minutes = int(seconds // 60)
    if minutes < 1:
        return "under a minute"
    hours, minutes = divmod(minutes, 60)
    return f"{hours} h {minutes:02d} min" if hours else f"{minutes} min"


def count(n: int, word: str) -> str:
    return f"{n} {word}" if n == 1 else f"{n} {word}s"


def when(t: float) -> str:
    return datetime.fromtimestamp(t).strftime("%a %-d %b %H:%M")


def who(domain: str) -> str:
    """A domain with its company, when one is known."""
    company = appfront.company_of(domain)
    return f"{domain} ({company})" if company else domain


# ---- the record, gathered once ---------------------------------------------------------------------------
@dataclass
class Record:
    """Everything the four views read: the timeline from `a - LOOKBACK`, the connections and lookups of
    the window, and what the lookback taught (pictures, TLS stacks)."""

    a: float
    b: float
    now: float
    profile: Profile
    tl: Timeline
    conns: list[Conn]
    looked: list[tuple[float, str, int]]
    ev: appfront.Evidence
    stacks: appfront.Stacks
    live: bool  # the store, or the file, holds a live record at all


def gather(
    conn: sqlite3.Connection,
    profile: Profile,
    gw_ip: str,
    a: float,
    b: float,
    events: list[Event] | None = None,
    known_until: float | None = None,
    now: float | None = None,
) -> Record:
    """Read the store for the window [a, b) and the PICTURE_DAYS before it."""
    now = time.time() if now is None else now
    back = a - LOOKBACK
    events = appfront.stored_events(conn, back, b) if events is None else events
    tl = appfront.timeline(events, appfront.readings(conn, back, b), back, b, known_until=known_until)
    seen = appfront.hellos(conn, back, b)
    return Record(
        a,
        b,
        now,
        profile,
        tl,
        appfront.connections(conn, a, b, gw_ip),
        appfront.lookups(conn, a, b),
        appfront.learn(tl, seen, profile),
        appfront.learn_stacks(tl, seen),
        bool(events),
    )


# ---- one session's receipt --------------------------------------------------------------------------------
GROUPS = ("before", "tracking", "tv", "new", "unjudged", "meanwhile")
# the plain label of the third-party category: it holds the apps' own analytics as well as advertisers
TRACKING_PLAIN = {"3rd-party ads": "advertising or app measurement"}
WIDTH = 100  # columns a line of the receipt wraps at


def label(kind: Kind, profile: Profile) -> str:
    if kind.cls == appfront.UNCLASSIFIED:
        return "no category yet"
    return TRACKING_PLAIN.get(kind.category) or plain.category_label(kind.category, profile)


def wrap(text: str, indent: str) -> list[str]:
    return textwrap.wrap(text, WIDTH, initial_indent=indent, subsequent_indent=indent + "    ") or [indent]


def _row(kind: Kind, profile: Profile, name: str) -> dict:
    return {
        "name": name,
        "domain": kind.domain,
        "category": kind.category,
        "plain": label(kind, profile),
        "class": kind.cls,
        "company": appfront.company_of(kind.domain),
        "conns": 0,
        "up": 0,
        "down": 0,
    }


def receipts(rec: Record, since: float | None = None, last: bool = False) -> list[dict]:
    """The receipt of every session that started in the window (from `since` on), oldest first; with
    `last`, only the newest."""
    chosen = [s for s in rec.tl.sessions if (since if since is not None else rec.a) <= s.start < rec.b]
    if last:
        chosen = chosen[-1:]
    by_session: dict[int, list[Conn]] = {id(s): [] for s in chosen}
    for c in rec.conns:
        s = rec.tl.at(c.t)[1]
        if s is not None and id(s) in by_session:
            by_session[id(s)].append(c)
    refused: dict[int, dict[str, dict]] = {id(s): {} for s in chosen}
    for t, name, blocked in rec.looked:
        s = rec.tl.at(t)[1]
        if blocked and s is not None and id(s) in refused:
            kind = appfront.classify(rec.profile, name)
            host = names.normalize(name)
            row = refused[id(s)].setdefault(
                host, {"name": host, "plain": label(kind, rec.profile), "lookups": 0}
            )
            row["lookups"] += 1
    out = []
    before: Session | None = None
    for s in rec.tl.sessions:
        if id(s) in by_session:
            r = _receipt(rec, s, by_session[id(s)], refused[id(s)])
            # a session that began at a connect right after a loss: the gateway lost touch, that is all
            if s.began == "connect" and before is not None and before.end_why == "lost":
                r["lost_from"] = before.end
            out.append(r)
        before = s
    return out


def _receipt(rec: Record, s: Session, conns: list[Conn], refused: dict[str, dict]) -> dict:
    day = appfront.viewing_day(s.start)
    is_app = s.kind == APP
    behind = rec.ev.days_known(s.app, before=day) if is_app else 0
    ready = is_app and rec.ev.ready(s.app, day)
    picture = rec.ev.picture(s.app, before=day) if is_app else set()
    groups: dict[str, dict[object, dict]] = {g: {} for g in GROUPS}
    unnamed = {"conns": 0, "bytes": 0}
    idle = {"conns": 0, "bytes": 0}
    for c in conns:
        if s.is_idle(c.t):
            idle["conns"] += 1
            idle["bytes"] += c.bytes
        if not c.name:
            unnamed["conns"] += 1
            unnamed["bytes"] += c.bytes
            continue
        kind = appfront.classify(rec.profile, c.name)
        host = names.normalize(c.name)
        if kind.cls == appfront.PLATFORM:
            group, key = "tv", kind.unit
        elif kind.cls in (appfront.VENDOR, appfront.TRACKING):
            group, key = "tracking", host  # the full name: one site holds an app's video and its beacon
        elif not is_app:
            group, key = "meanwhile", kind.unit
        elif kind.unit in picture:
            group, key = "before", kind.unit
        else:
            group, key = ("new" if ready else "unjudged"), kind.unit
        row = groups[group].setdefault(
            key, _row(kind, rec.profile, host if group == "tracking" else kind.domain)
        )
        row["conns"] += 1
        row["up"] += c.up
        row["down"] += c.down
        if is_app and kind.cls in appfront.PICTURE_CLASSES:
            row["days_seen"] = rec.ev.days_seen(s.app, kind.unit, before=day)
            if group == "new":
                row["also_with"] = [o for o in rec.ev.apps_with(kind.unit, before=day) if o != s.app]
        software = rec.stacks.names(c.ja4)
        if software is not None and software != s.app and group in ("new", "unjudged", "meanwhile"):
            row["stack_of"] = software
    ranked = {
        g: sorted(rows.values(), key=lambda r: (-(r["up"] + r["down"]), r["name"], r["category"]))
        for g, rows in groups.items()
    }
    return {
        "app": s.app,
        "label": appfront.app_label(s.app),
        "kind": s.kind,
        "start": s.start,
        "end": s.end,
        "seconds": s.seconds,
        "timed": s.timed,
        "start_exact": s.start_exact,
        "end_exact": s.end_exact,
        "end_why": s.end_why,
        "idle_seconds": s.idle_seconds,
        "idle": idle,
        "settling": rec.now - s.end < SETTLE,
        "days_behind": behind,
        "ready": ready,
        "conns": len(conns),
        "up": sum(c.up for c in conns),
        "down": sum(c.down for c in conns),
        "groups": ranked,
        "unnamed": unnamed,
        "refused": {
            "lookups": sum(r["lookups"] for r in refused.values()),
            "names": sorted(refused.values(), key=lambda r: (-r["lookups"], r["name"])),
        },
    }


# ---- the words -------------------------------------------------------------------------------------------
def _notes(r: dict, name: str, behind: int) -> list[str]:
    notes = []
    if r.get("days_seen") == 1 and behind > 1:
        notes.append("seen on 1 day only")
    elif r.get("days_seen"):
        notes.append(f"on {r['days_seen']} of {name}'s {count(behind, 'earlier day')}")
    if r.get("also_with"):
        notes.append("usually with " + ", ".join(short(appfront.app_label(o)) for o in r["also_with"]))
    if r.get("stack_of"):
        notes.append(f"opened like {short(appfront.app_label(r['stack_of']))}'s software")
    return notes


def _line(r: dict, name: str, behind: int) -> list[str]:
    """One row of a group: the name, what it is, how much, and what is known of it; wrapped."""
    notes = _notes(r, name, behind)
    tail = f" ({'; '.join(notes)})" if notes else ""
    return wrap(
        f"{who(r['name'])}, {r['plain']}: {count(r['conns'], 'connection')},"
        f" {size(r['up'] + r['down'])}{tail}",
        "    ",
    )


def _group(out: list[str], title: str, rows: list[dict], name: str, behind: int) -> None:
    if not rows:
        return
    out.append(f"  {title}")
    for r in rows[:TOP_ROWS]:
        out += _line(r, name, behind)
    if len(rows) > TOP_ROWS:
        rest = rows[TOP_ROWS:]
        out.append(
            f"    and {count(len(rest), 'more name')}: {count(sum(r['conns'] for r in rest), 'connection')},"
            f" {size(sum(r['up'] + r['down'] for r in rest))}"
        )


def _refused_line(r: dict, name: str) -> list[str]:
    ref = r["refused"]
    if not ref["lookups"]:
        return [f"  No lookup was refused while {name} was in front."]
    shown = ref["names"][:TOP_REFUSED]
    top = ", ".join(f"{who(n['name'])} {n['lookups']} ({n['plain']})" for n in shown)
    rest = len(ref["names"]) - len(shown)
    more = f", and {count(rest, 'more name')}" if rest else ""
    return wrap(
        f"Asked for {count(len(ref['names']), 'blocked name')} {count(ref['lookups'], 'time')} while {name}"
        f" was in front, every one refused: {top}{more}",
        "  ",
    )


def _hourly_span(r: dict) -> str:
    """What two readings an hour apart can say: when the app was seen, not how long it ran."""
    a, b = datetime.fromtimestamp(r["start"]), datetime.fromtimestamp(r["end"])
    return f"seen in front at {a:%H:%M} and at {b:%H:%M}; it may have started earlier and run longer"


def _edges(r: dict) -> str:
    """What is not known of a live session's edges, in one clause."""
    parts = []
    if not r["start_exact"]:
        parts.append(
            f"the gateway had lost touch with the TV from {datetime.fromtimestamp(r['lost_from']):%H:%M}"
            if r.get("lost_from")
            else "the gateway started listening while it was in front"
        )
    if not r["end_exact"]:
        parts.append(
            {
                "lost": "then lost touch with the TV",
                "open": "it was still in front when this was written",
                "clock": "the gateway's clock was set while it ran",
            }.get(r["end_why"], "")
        )
    return "; ".join(p for p in parts if p)


def render_receipt(r: dict) -> list[str]:
    """One session's receipt as lines."""
    name, behind = short(r["label"]), r["days_behind"]
    g = r["groups"]
    start = datetime.fromtimestamp(r["start"])
    if r["kind"] != APP and not any(g[k] for k in ("tracking", "meanwhile")) and not r["unnamed"]["conns"]:
        when_ = (
            f"{start:%a %-d %b %H:%M} to {datetime.fromtimestamp(r['end']):%H:%M} ({span(r['seconds'])})"
            if r["timed"] == appfront.LIVE
            else f"{start:%a %-d %b}, {_hourly_span(r)}"
        )
        return [
            f"{r['label'] if r['kind'] == HOME else short(r['label'])}, {when_}: only the TV's own services."
        ]
    out = [name if r["kind"] == APP else r["label"]]
    if r["timed"] == appfront.LIVE:
        out.append(f"  {when(r['start'])} to {datetime.fromtimestamp(r['end']):%H:%M} ({span(r['seconds'])})")
        edges = _edges(r)
        if edges:
            out.append(f"  {edges[0].upper()}{edges[1:]}.")
    else:
        out += wrap(f"{start:%a %-d %b}, {_hourly_span(r)} (times to the hour)", "  ")
    if r["idle_seconds"] >= 60:
        out.append(
            f"  {span(r['idle_seconds'])} of it behind the screen saver:"
            f" {count(r['idle']['conns'], 'connection')} started then, {size(r['idle']['bytes'])}"
        )
    if r["settling"]:
        out.append("  Still settling: the numbers keep filling in for about three hours after a session.")
    out.append(
        f"  {count(r['conns'], 'connection')} started while it was in front:"
        f" {size(r['down'])} down, {size(r['up'])} up"
    )
    if r["kind"] in KIND_NOTE:
        out += wrap(KIND_NOTE[r["kind"]], "  ")
    if r["kind"] == APP:
        if r["ready"] and g["new"]:
            _group(out, f"New for {name} (not seen with it on any earlier day)", g["new"], name, behind)
        elif r["ready"]:
            out.append(f"  No name was new for {name}.")
        else:
            out += wrap(
                f"Not judged yet: the gateway has seen {name} in front on {count(behind, 'earlier day')},"
                f" and {appfront.PICTURE_READY_DAYS} are needed before a name is called new.",
                "  ",
            )
            _group(
                out,
                f"Not seen with {name} before (too few days to call them new)",
                g["unjudged"],
                name,
                behind,
            )
    _group(out, f"Advertising and measurement while {name} was in front", g["tracking"], name, behind)
    _group(out, f"Seen with {name} before", g["before"], name, behind)
    _group(out, f"Reached while {name} was in front", g["meanwhile"], name, behind)
    _group(out, "The TV's own services (clock, sign-in, updates)", g["tv"], name, behind)
    if r["unnamed"]["conns"]:
        out.append(
            f"  No name was captured for {count(r['unnamed']['conns'], 'connection')}"
            f" ({size(r['unnamed']['bytes'])})."
        )
    out += _refused_line(r, name)
    return out


def action(found: list[dict]) -> str:
    """One line in the plain brief's voice: what to do, or nothing."""
    through = [
        (r, row)
        for r in found
        for row in r["groups"]["tracking"]
        if row["class"] in (appfront.TRACKING, appfront.VENDOR)
    ]
    if through:
        row = max(through, key=lambda x: x[1]["conns"])[1]
        return (
            f"Action: {who(row['name'])} ({row['plain']}) got through the filter; `sudo tvgw check"
            f" {row['name']}` says why, and how to block it."
        )
    settling = [r for r in found if r["settling"]]
    if settling:
        again = datetime.fromtimestamp(max(r["end"] for r in settling) + SETTLE)
        return f"Action: nothing to do; the numbers keep filling in, so run it again after {again:%H:%M}."
    return "Action: nothing to do."


def closing(rec: Record, found: list[dict], since_arg: str = "1d") -> list[str]:
    """What every view of the record ends with: the footer, what the times mean, the action, the commands."""
    out = wrap(FOOTER, "")
    if any(r["timed"] == appfront.HOURLY for r in found):
        out += wrap(
            "Times to the hour: the TV is asked once an hour, so a session can start earlier and run longer"
            " than shown, and one under about two hours can be missing.",
            "",
        )
        if rec.profile.name == tvlive_profile() and not rec.live:
            out.append("The TV can report exact times: see 'Get exact times' in docs/use/receipt.md.")
    out += wrap(action(found), "")
    out.append(f"Every name: sudo tvgw receipt --since {since_arg}   One name: sudo tvgw receipt --why NAME")
    return out


def tvlive_profile() -> str:
    from tvgw import tvlive  # here: tvlive imports lgwebos and more

    return tvlive.PROFILE


def render(rec: Record, found: list[dict], gaps: dict | None = None, since_arg: str = "1d") -> list[str]:
    """Every session's receipt as one text; with `gaps`, what started in the time no session covers."""
    if not found:
        return [
            "No viewing session started in this time: the TV was off, or nothing says which app was in"
            " front (sudo tvgw tvstate shows the readings)."
        ]
    out: list[str] = []
    for r in found:
        out += [*render_receipt(r), ""]
    if gaps is not None and gaps["conns"]:
        out += [*render_gap_summary(gaps), ""]
    return out + closing(rec, found, since_arg)


# ---- the evening: the default screen --------------------------------------------------------------------
def evening(rec: Record) -> dict:
    """The newest viewing day's sessions, one block per app in the order the apps first came to the
    front, with the stretches the gateway lost touch inside a block: the screen `tvgw receipt` opens with."""
    found = receipts(rec)
    if not found:
        return {"day": None, "blocks": [], "receipts": []}
    day = appfront.viewing_day(found[-1]["start"])
    mine = [r for r in found if appfront.viewing_day(r["start"]) == day]
    blocks: dict[str, dict] = {}
    previous: dict | None = None
    for r in mine:
        b = blocks.setdefault(
            r["app"],
            {
                "app": r["app"],
                "label": r["label"],
                "kind": r["kind"],
                "timed": r["timed"],
                "spans": [],
                "lost": [],
                "seconds": 0.0,
                "conns": 0,
                "down": 0,
                "up": 0,
                "ready": r["ready"],
                "days_behind": r["days_behind"],
                "new": {},
                "unjudged": {},
                "tracking": {},
                "meanwhile": {},
                "refused": {},
                "unnamed": 0,
                "settling": False,
                "edges": "",
            },
        )
        if previous is not None and previous["app"] == r["app"] and previous["end_why"] == "lost":
            b["lost"].append((previous["end"], r["start"]))
            b["spans"][-1] = (b["spans"][-1][0], r["end"])
        else:
            b["spans"].append((r["start"], r["end"]))
        b["seconds"] += r["seconds"]
        b["conns"] += r["conns"]
        b["down"] += r["down"]
        b["up"] += r["up"]
        b["unnamed"] += r["unnamed"]["conns"]
        b["settling"] = b["settling"] or r["settling"]
        b["ready"] = b["ready"] and r["ready"]
        b["edges"] = _block_edges(b, r)
        for g in ("new", "unjudged", "tracking", "meanwhile"):
            for row in r["groups"][g]:
                cell = b[g].setdefault(row["name"], dict(row))
                if cell is not row:
                    for k in ("conns", "up", "down"):
                        cell[k] += row[k]
        for n in r["refused"]["names"]:
            cell = b["refused"].setdefault(n["name"], dict(n))
            if cell is not n:
                cell["lookups"] += n["lookups"]
        previous = r
    return {"day": day, "blocks": list(blocks.values()), "receipts": mine}


def _block_edges(b: dict, last: dict) -> str:
    """What is not known of a block's edges: its first span's start and its last span's end. A loss the
    same app came back from is in the head line already."""
    parts = []
    first = b.get("first")
    if first is None:
        b["first"] = first = last
    if last["timed"] == appfront.LIVE and not first["start_exact"] and not first.get("lost_from"):
        parts.append("the gateway started listening while it was in front")
    if last["timed"] == appfront.LIVE and not last["end_exact"]:
        parts.append(
            {
                "lost": "the gateway lost touch with the TV at the end",
                "open": "it was still in front when this was written",
                "clock": "the gateway's clock was set while it ran",
            }.get(last["end_why"], "")
        )
    return "; ".join(p for p in parts if p)


def _day_name(day: int, now: float) -> str:
    today = appfront.viewing_day(now)
    date = datetime.fromtimestamp(
        (datetime.fromordinal(day) + timedelta(hours=appfront.DAY_START_HOUR)).timestamp()
    )
    word = "This evening" if day == today else "Last evening" if day == today - 1 else "The evening of"
    return f"{word}, {date:%a %-d %b}" if word != "The evening of" else f"{word} {date:%a %-d %b}"


def render_evening(rec: Record, ev: dict) -> list[str]:
    """The default screen: the evening, one block per app, verdict first, then the closing lines."""
    if not ev["blocks"]:
        return render(rec, [])
    rs = ev["receipts"]
    first, last = min(r["start"] for r in rs), max(r["end"] for r in rs)
    live = all(r["timed"] == appfront.LIVE for r in rs)
    times = "exact times, reported by the TV" if live else "times to the hour: the TV was asked once an hour"
    out = [
        f"{_day_name(ev['day'], rec.now)}, {datetime.fromtimestamp(first):%H:%M} to"
        f" {datetime.fromtimestamp(last):%H:%M} ({times})"
    ]
    for b in ev["blocks"]:
        name = short(b["label"])
        spans = [
            f"{datetime.fromtimestamp(s):%H:%M} to {datetime.fromtimestamp(e):%H:%M}" for s, e in b["spans"]
        ]
        elapsed = sum(e - s for s, e in b["spans"])
        if b["kind"] != APP and not b["tracking"] and not b["meanwhile"] and not b["unnamed"]:
            out.append(f"{b['label']}, {span(elapsed)} in all: only the TV's own services.")
            continue
        if b["timed"] == appfront.LIVE:
            head = f"{name}, {' and '.join(spans)} ({span(elapsed)}"
            if b["lost"]:
                lost = " and ".join(
                    f"{datetime.fromtimestamp(s):%H:%M} to {datetime.fromtimestamp(e):%H:%M}"
                    for s, e in b["lost"]
                )
                head += f"; the gateway lost touch {lost}"
            head += f"), {size(b['down'])} down"
        else:
            seen = " and ".join(
                f"at {datetime.fromtimestamp(s):%H:%M} and {datetime.fromtimestamp(e):%H:%M}"
                for s, e in b["spans"]
            )
            head = (
                f"{name}, seen in front {seen}; it may have started earlier and run longer;"
                f" {size(b['down'])} down"
            )
        out += wrap(head, "")
        if b["edges"]:
            out.append(f"  {b['edges'][0].upper()}{b['edges'][1:]}.")
        behind = b["days_behind"]
        if b["kind"] == APP:
            if b["ready"] and b["new"]:
                rows = sorted(b["new"].values(), key=lambda r: (-(r["up"] + r["down"]), r["name"]))
                items = [
                    f"{who(r['name'])} ({'; '.join([r['plain'], *_notes(r, name, behind)])})" for r in rows
                ]
                out += wrap(f"New for {name}: " + ", ".join(items), "  ")
            elif b["ready"]:
                out.append(f"  No name was new for {name}.")
            else:
                out += wrap(
                    f"Not judged yet: the gateway has seen {name} in front on"
                    f" {count(behind, 'earlier day')}, and {appfront.PICTURE_READY_DAYS} are needed before a"
                    " name is called new.",
                    "  ",
                )
                if b["unjudged"]:
                    rows = sorted(b["unjudged"].values(), key=lambda r: (-(r["up"] + r["down"]), r["name"]))
                    out += wrap(
                        f"Not seen with {name} before (too few days to call them new): "
                        + ", ".join(f"{who(r['name'])} ({r['plain']})" for r in rows),
                        "  ",
                    )
        if b["tracking"]:
            rows = sorted(b["tracking"].values(), key=lambda r: (-(r["up"] + r["down"]), r["name"]))
            items = [
                f"{who(r['name'])}, {count(r['conns'], 'connection')}, {size(r['up'] + r['down'])}"
                for r in rows
            ]
            out += wrap("Advertising and measurement while it was in front: " + "; ".join(items), "  ")
        if b["meanwhile"]:
            rows = sorted(b["meanwhile"].values(), key=lambda r: (-(r["up"] + r["down"]), r["name"]))
            out += wrap(
                "Reached while it was in front: "
                + ", ".join(f"{who(r['name'])} ({r['plain']})" for r in rows),
                "  ",
            )
        if b["refused"]:
            rows = sorted(b["refused"].values(), key=lambda r: (-r["lookups"], r["name"]))
            lookups = sum(r["lookups"] for r in rows)
            out += wrap(
                f"Asked for {count(len(rows), 'blocked name')} {count(lookups, 'time')}, every one refused: "
                + ", ".join(f"{who(r['name'])} {r['lookups']} ({r['plain']})" for r in rows[:TOP_REFUSED])
                + (f", and {count(len(rows) - TOP_REFUSED, 'more name')}" if len(rows) > TOP_REFUSED else ""),
                "  ",
            )
        if b["unnamed"]:
            out.append(f"  No name was captured for {count(b['unnamed'], 'connection')}.")
        if b["settling"]:
            out.append("  Still settling: the numbers keep filling in for about three hours after a session.")
    return [*out, "", *closing(rec, rs, "1d")]


# ---- what started in gaps -------------------------------------------------------------------------------
def gap_summary(rec: Record, since: float | None = None) -> dict:
    """The time of the window in which nothing says which app was in front, the connections that started
    in it, and how many of them carry a TLS fingerprint that is one app's."""
    a = rec.a if since is None else since
    seconds = sum(
        min(p.t1, rec.b) - max(p.t0, a) for p in rec.tl.pieces if p.cls == appfront.GAP and p.t1 > a
    )
    out = {"seconds": max(0.0, seconds), "conns": 0, "bytes": 0, "by_app": {}, "unnamed": 0}
    for c in rec.conns:
        if c.t < a or rec.tl.at(c.t)[0] != appfront.GAP:
            continue
        out["conns"] += 1
        out["bytes"] += c.bytes
        software = rec.stacks.names(c.ja4)
        if software is None:
            out["unnamed"] += 1
            continue
        cell = out["by_app"].setdefault(
            software, {"label": appfront.app_label(software), "conns": 0, "bytes": 0}
        )
        cell["conns"] += 1
        cell["bytes"] += c.bytes
    out["by_app"] = dict(sorted(out["by_app"].items(), key=lambda kv: (-kv[1]["bytes"], kv[0])))
    return out


def render_gap_summary(g: dict) -> list[str]:
    if not g["conns"]:
        return []
    out = wrap(
        f"In the {span(g['seconds'])} of this time in which nothing says which app was in front,"
        f" {count(g['conns'], 'connection')} started ({size(g['bytes'])}).",
        "",
    )
    if g["by_app"]:
        named = "; ".join(
            f"{short(c['label'])} {count(c['conns'], 'connection')}, {size(c['bytes'])}"
            for c in g["by_app"].values()
        )
        out += wrap(f"Opened like the software of: {named}.", "  ")
        out.append(
            "  A TLS fingerprint suggests which software opened a connection; it does not say which app was"
            " in front."
        )
    out.append(f"  No fingerprint that is one app's: {count(g['unnamed'], 'connection')}.")
    return out


# ---- the brief's section --------------------------------------------------------------------------------
def brief_section(rec: Record) -> list[dict]:
    """The sessions that started in the window, as the brief's short section shows them."""
    out = []
    for r in receipts(rec):
        out.append(
            {
                "app": r["app"],
                "label": r["label"],
                "kind": r["kind"],
                "start": r["start"],
                "end": r["end"],
                "seconds": r["seconds"],
                "timed": r["timed"],
                "conns": r["conns"],
                "down": r["down"],
                "up": r["up"],
                "ready": r["ready"],
                "new": [n["name"] for n in r["groups"]["new"]],
                "tracking": len(r["groups"]["tracking"]),
                "refused_lookups": r["refused"]["lookups"],
                "settling": r["settling"],
            }
        )
    return out


BRIEF_MAX = 8


def render_brief_section(rows: list[dict], day_arg: str) -> list[str]:
    """The brief's section: one line a session, and where the whole receipt is."""
    out = [
        "",
        "App in front (which app was in front when each connection started; exact times where the TV"
        " reported them, else the readings an hour apart that saw it):",
    ]
    days = {datetime.fromtimestamp(r["start"]).date() for r in rows}
    clock = "%H:%M" if len(days) <= 1 else "%a %H:%M"  # a week's report says which evening
    for r in rows[:BRIEF_MAX]:
        name = short(r["label"])
        tail = ""
        if r["kind"] == APP and r["ready"]:
            tail = (
                f"; new for it: {', '.join(r['new'][:3])}"
                + (f" +{len(r['new']) - 3}" if len(r["new"]) > 3 else "")
                if r["new"]
                else "; no name new for it"
            )
        elif r["kind"] == APP:
            tail = "; too few days to call anything new"
        if r["tracking"]:
            tail += f"; {count(r['tracking'], 'advertising or measurement name')}"
        start, end = datetime.fromtimestamp(r["start"]), datetime.fromtimestamp(r["end"])
        head = (
            f"{start.strftime(clock)}-{end:%H:%M} {name}, {span(r['seconds'])} (exact)"
            if r["timed"] == appfront.LIVE
            else f"{start.strftime(clock)} and {end:%H:%M} {name} (to the hour)"
        )
        out.append(
            f"  {head}: {count(r['conns'], 'connection')}, {size(r['down'])} down{tail}"
            + ("; still settling" if r["settling"] else "")
        )
    if len(rows) > BRIEF_MAX:
        out.append(f"  and {count(len(rows) - BRIEF_MAX, 'more session')}")
    if not rows:
        out.append("  none")
    out.append(f"  Each session's receipt: sudo tvgw receipt --since {day_arg}")
    return out


# ---- the picture -------------------------------------------------------------------------------------------
def pictures(rec: Record, app: str | None = None) -> list[dict]:
    """Each app's picture as of the end of the window: its days, and every unit with the days it was seen
    on and the other apps it is seen with."""
    day = appfront.viewing_day(rec.b) + 1
    out = []
    for a in sorted(rec.ev.days, key=lambda x: (-len(rec.ev.days[x]), x)):
        if app is not None and a != app:
            continue
        days = rec.ev.days_known(a, before=day)
        rows = []
        for unit in rec.ev.picture(a, before=day):
            domain, category = unit
            seen = rec.ev.days_seen(a, unit, before=day)
            kind = Kind(
                appfront.TRACKING if category in appfront.TRACKING_CATEGORIES else "",
                category,
                domain,
                "",
            )
            rows.append(
                {
                    "domain": domain,
                    "category": category,
                    "plain": "no category yet"
                    if category == appfront.NO_CATEGORY
                    else label(kind, rec.profile),
                    "tracking": category in appfront.TRACKING_CATEGORIES,
                    "company": appfront.company_of(domain),
                    "days_seen": seen,
                    "firm": seen >= appfront.PICTURE_FIRM_DAYS,
                    "also_with": [o for o in rec.ev.apps_with(unit, before=day) if o != a],
                }
            )
        rows.sort(key=lambda r: (-r["days_seen"], r["domain"], r["category"]))
        own = sorted(ja4 for ja4 in rec.stacks.seen if rec.stacks.names(ja4) == a)
        out.append(
            {
                "app": a,
                "label": appfront.app_label(a),
                "days": days,
                "ready": days >= appfront.PICTURE_READY_DAYS,
                "units": rows,
                "stacks": own,
            }
        )
    return out


def render_pictures(found: list[dict]) -> list[str]:
    out = [
        "What each app has been seen with in the last 28 days, by site (the part of a name its owner"
        " registered) and kind:",
        "",
    ]
    if not found:
        return [*out, "No app has been seen in front yet."]
    for p in found:
        name = short(p["label"])
        need = appfront.PICTURE_READY_DAYS
        state = (
            "enough for a new name to be called new"
            if p["ready"]
            else f"{need} are needed before a name is called new"
        )
        out.append(f"{name}: in front on {count(p['days'], 'viewing day')} (05:00 to 05:00); {state}")
        for r in p["units"]:
            notes = [f"on {count(r['days_seen'], 'day')}" + ("" if r["firm"] else " only")]
            if r["tracking"]:
                notes.append(f"beside {name}, not part of it")
            if r["also_with"]:
                others = ", ".join(short(appfront.app_label(o)) for o in r["also_with"])
                notes.append(f"also with {others}")
            out += wrap(f"{who(r['domain'])}, {r['plain']}: {'; '.join(notes)}", "    ")
        if not p["units"]:
            out.append("    nothing yet but the TV's own services")
        if p["stacks"]:
            out.append(
                f"    its own TLS fingerprints (the way its software opens a connection): {len(p['stacks'])}"
            )
        out.append("")
    out.append(
        "The TV's own services and its maker's are never in a picture. A name is in an app's picture from"
        " the day after it was first seen with that app."
    )
    return out


# ---- the replay ------------------------------------------------------------------------------------------
def replay(rec: Record) -> dict:
    """The imagined rule over the window: while an app with enough days behind it is in front, allow its
    picture as of that day and the platform's essentials, refuse what is new. Per app and in all: what it
    would have refused, what it would have allowed on one earlier day's evidence alone (`thin`), how much
    of the app's content either is, and the names the TV must reach. The rule carries that list, so none of
    them can be refused (`must_allow_refused` is a self-check); `must_allow_outside_category` names any
    that only the list protects, because the profile files it outside the TV maker's own category."""
    apps: dict[str, dict] = {}
    days_all: set[tuple[str, int]] = set()
    days_live: set[tuple[str, int]] = set()
    for c in rec.conns:
        cls, s, _ = rec.tl.at(c.t)
        if cls != SESSION or s is None or s.kind != APP:
            continue
        day = appfront.viewing_day(c.t)
        if not rec.ev.ready(s.app, day):
            continue
        days_all.add((s.app, day))
        if s.timed == appfront.LIVE:
            days_live.add((s.app, day))
        a = apps.setdefault(
            s.app,
            {
                "app": s.app,
                "label": appfront.app_label(s.app),
                "days": set(),
                "conns": 0,
                "bytes": 0,
                "content_bytes": 0,
                "content_refused_bytes": 0,
                "content_thin_bytes": 0,
                "refused_conns": 0,
                "refused_bytes": 0,
                "thin_conns": 0,
                "thin_bytes": 0,
                "unnamed_conns": 0,
                "unnamed_bytes": 0,
                "filter_conns": 0,
                "must_allow_seen": set(),
                "must_allow_refused": set(),
                "must_allow_outside_category": set(),
                "refused": {},
            },
        )
        a["days"].add(day)
        a["conns"] += 1
        a["bytes"] += c.bytes
        if not c.name:
            a["unnamed_conns"] += 1
            a["unnamed_bytes"] += c.bytes
            continue
        kind = appfront.classify(rec.profile, c.name)
        host = names.normalize(c.name)
        if any(covers(pat, host) for pat in rec.profile.must_allow):
            a["must_allow_seen"].add(host)
            vendor = bool(rec.profile.vendor) and kind.category.startswith(rec.profile.vendor + " ")
            if not (vendor and kind.category in rec.profile.expected_categories):
                a["must_allow_outside_category"].add(host)
        if kind.cls == appfront.PLATFORM:
            continue  # the essentials: allowed whatever is in front
        if kind.cls == appfront.VENDOR:
            a["filter_conns"] += 1  # the TV maker's other names: the name filter's business, as today
            continue
        seen = rec.ev.days_seen(s.app, kind.unit, before=day)
        content = kind.cls == appfront.CONTENT
        a["content_bytes"] += c.bytes * content
        if seen >= appfront.PICTURE_FIRM_DAYS:
            continue
        if seen:
            a["thin_conns"] += 1
            a["thin_bytes"] += c.bytes
            a["content_thin_bytes"] += c.bytes * content
            continue
        a["refused_conns"] += 1
        a["refused_bytes"] += c.bytes
        a["content_refused_bytes"] += c.bytes * content
        row = a["refused"].setdefault(kind.unit, _row(kind, rec.profile, kind.domain))
        row["conns"] += 1
        row["down"] += c.down
        row["up"] += c.up
    out = []
    for a in sorted(apps.values(), key=lambda x: (-x["bytes"], x["app"])):
        ranked = sorted(a["refused"].values(), key=lambda r: (-(r["up"] + r["down"]), r["name"]))
        out.append(
            a
            | {
                "days": len(a["days"]),
                "content_outside_share": _share(a["content_refused_bytes"], a["content_bytes"]),
                "content_outside_or_thin_share": _share(
                    a["content_refused_bytes"] + a["content_thin_bytes"], a["content_bytes"]
                ),
                "unnamed_share": _share(a["unnamed_bytes"], a["bytes"]),
                "must_allow_seen": len(a["must_allow_seen"]),
                "must_allow_refused": len(a["must_allow_refused"]),
                "must_allow_outside_category": sorted(a["must_allow_outside_category"]),
                "refused": ranked,
            }
        )
    content = sum(a["content_bytes"] for a in out)
    total = sum(a["bytes"] for a in out)
    numbers = {
        "content_outside_share": _share(sum(a["content_refused_bytes"] for a in out), content),
        "content_outside_bytes": sum(a["content_refused_bytes"] for a in out),
        "must_allow_outside": sum(a["must_allow_refused"] for a in out),
        "unnamed_share": _share(sum(a["unnamed_bytes"] for a in out), total),
        "app_days": len(days_all),
        "app_days_live": len(days_live),
    }
    return {
        "window_days": round((rec.b - rec.a) / 86400, 1),
        "apps": out,
        "numbers": numbers,
        "bar": {
            "content_outside_share": BAR_CONTENT_OUTSIDE,
            "must_allow_outside": BAR_MUST_ALLOW_OUTSIDE,
            "unnamed_share": BAR_UNNAMED,
            "viewing_days": BAR_DAYS,
            "live_share": BAR_LIVE_SHARE,
        },
        "meets_the_bar": meets_the_bar(numbers),
        "verdict": verdict(numbers),
    }


def _share(n: float, of: float) -> float | None:
    return round(n / of, 4) if of else None


def meets_the_bar(n: dict) -> bool:
    """Whether a replay's numbers are the ones decision 67 asks for before a rule is ever tried on
    probation. True changes nothing: no rule exists to try."""
    return not failing(n)


def failing(n: dict) -> list[str]:
    """The conditions a replay does not meet, in plain words; [] when it meets them all."""
    out = []
    if n["app_days"] < BAR_DAYS or n["app_days_live"] < BAR_LIVE_SHARE * n["app_days"]:
        out.append(
            f"it needs {BAR_DAYS} days of app viewing replayed, nine in ten with exact times; it has"
            f" {n['app_days']}, {n['app_days_live']} with exact times"
        )
    if n["content_outside_share"] is None:
        out.append("no streaming bytes were replayed")
    elif n["content_outside_share"] > BAR_CONTENT_OUTSIDE:
        out.append(
            f"{_pct(n['content_outside_share'])} of streaming bytes would have been refused as new; the bar"
            f" is {BAR_CONTENT_OUTSIDE:.0%}"
        )
    if n["must_allow_outside"] > BAR_MUST_ALLOW_OUTSIDE:
        out.append(f"{n['must_allow_outside']} of the names the TV must reach would have been refused")
    if n["unnamed_share"] is None or n["unnamed_share"] > BAR_UNNAMED:
        out.append(f"{_pct(n['unnamed_share'])} of bytes had no name to judge; the bar is {BAR_UNNAMED:.0%}")
    return out


def verdict(n: dict) -> str:
    bad = failing(n)
    if not bad:
        return "Ready to try, by these numbers alone. No rule exists yet; nothing is refused."
    return (
        "Not ready to try: " + "; ".join(bad) + ". Keep the live reading on and check again in a few weeks."
    )


def _pct(x: float | None) -> str:
    if x is None:
        return "nothing to measure"
    return "under 0.1%" if 0 < x < 0.001 else f"{x:.1%}"


def _share_with_bytes(share: float | None, n_bytes: int, rows: list[dict]) -> str:
    """A small share with what it hides: `under 0.1% (1.5 MB: nflxso.net would have been refused)`."""
    text = _pct(share)
    if share and n_bytes:
        content = [r["name"] for r in rows if r["class"] == appfront.CONTENT][:3]
        tail = f": {', '.join(content)} would have been refused" if content else ""
        text += f" ({size(n_bytes)}{tail})"
    return text


def render_replay(r: dict) -> list[str]:
    out = [
        *wrap(
            f"A replay of the last {r['window_days']:g} days against an imagined rule. Nothing is refused:"
            " this is a report.",
            "",
        ),
        *wrap(
            "The rule: while an app is in front, allow what was seen with it before and the TV's own"
            " services (clock, sign-in, store, updates); refuse what is new.",
            "",
        ),
        "",
    ]
    for a in r["apps"]:
        name = short(a["label"])
        out.append(
            f"{name}: {count(a['days'], 'day')} replayed, {count(a['conns'], 'connection')},"
            f" {size(a['bytes'])}"
        )
        out += wrap(
            f"would have been refused as new: {count(a['refused_conns'], 'connection')},"
            f" {size(a['refused_bytes'])}; allowed on one earlier day only:"
            f" {count(a['thin_conns'], 'connection')}, {size(a['thin_bytes'])}",
            "  ",
        )
        out += wrap(
            f"of {name}'s streaming bytes, new: "
            + _share_with_bytes(a["content_outside_share"], a["content_refused_bytes"], a["refused"])
            + f"; new or seen on one day only: {_pct(a['content_outside_or_thin_share'])}",
            "  ",
        )
        out += wrap(
            f"names the TV must reach, seen: {a['must_allow_seen']}; refused: {a['must_allow_refused']}"
            " (self-check: the rule carries that list)"
            + (
                f"; protected by the list alone: {', '.join(a['must_allow_outside_category'])}"
                if a["must_allow_outside_category"]
                else ""
            ),
            "  ",
        )
        out += wrap(
            f"no name to judge: {count(a['unnamed_conns'], 'connection')}, {_pct(a['unnamed_share'])}"
            f" of bytes; the TV maker's other names, left to the name filter: {a['filter_conns']}",
            "  ",
        )
        for row in a["refused"][:TOP_ROWS]:
            out += wrap(
                f"{who(row['name'])}, {row['plain']}: {count(row['conns'], 'connection')},"
                f" {size(row['up'] + row['down'])}",
                "    ",
            )
        if len(a["refused"]) > TOP_ROWS:
            out.append(f"    and {count(len(a['refused']) - TOP_ROWS, 'more name')}")
        out.append("")
    if not r["apps"]:
        out += ["No app had enough days behind it in this time for the rule to apply on any day.", ""]
    n, bar = r["numbers"], r["bar"]
    out.append("The numbers that decide whether such a rule can ever be tried:")
    out += wrap(
        "streaming bytes outside the picture: "
        + _share_with_bytes(
            n["content_outside_share"],
            n["content_outside_bytes"],
            [row for a in r["apps"] for row in a["refused"]],
        )
        + f" (the bar: at most {bar['content_outside_share']:.0%})",
        "  ",
    )
    out.append(
        f"  names the TV must reach outside it: {n['must_allow_outside']}"
        f" (self-check: {n['must_allow_outside']}, as expected)"
    )
    out.append(
        f"  bytes with no name to judge: {_pct(n['unnamed_share'])} (the bar: at most"
        f" {bar['unnamed_share']:.0%})"
    )
    out.append(
        f"  app viewing days replayed: {n['app_days']}, {n['app_days_live']} with exact times (the bar:"
        f" {bar['viewing_days']}, nine in ten with exact times)"
    )
    return [*out, *wrap(r["verdict"], "")]


# ---- why -------------------------------------------------------------------------------------------------
CLASS_MEANS: dict[str, Callable[[str], str]] = {
    appfront.PLATFORM: lambda v: (
        "It is counted as the TV's own under whichever app is in front, and no rule"
        " keyed to an app would touch it."
    ),
    appfront.VENDOR: lambda v: (
        f"The profile files it under {v}'s own categories, so it is listed under advertising and"
        " measurement while an app is in front, never as the app's."
    ),
    appfront.TRACKING: lambda v: (
        "It is listed under advertising and measurement beside the app, not as part of it."
    ),
    appfront.CONTENT: lambda v: "It belongs to an app's picture once it has been seen with that app.",
    appfront.SHARED: lambda v: "Several apps use such names, so it can be in more than one app's picture.",
    appfront.OTHER: lambda v: "It belongs to an app's picture once it has been seen with that app.",
    appfront.UNCLASSIFIED: lambda v: (
        "Until the profile names it, it is listed as having no category yet, never as somebody else's."
    ),
}


def why(rec: Record, name: str, app: str | None = None) -> list[str]:
    """Why `name` counts as it does: what the profile says it is, and what each app's days say of it."""
    kind = appfront.classify(rec.profile, name)
    host = names.normalize(name)
    out = [
        f"{host}: {label(kind, rec.profile)} ({who(kind.domain)}), because {kind.why}."
        f" {CLASS_MEANS[kind.cls](rec.profile.vendor or 'the TV maker')}"
    ]
    if kind.cls not in appfront.PICTURE_CLASSES:
        return out
    day = appfront.viewing_day(rec.b) + 1
    apps = [app] if app else sorted(rec.ev.days, key=lambda x: (-len(rec.ev.days[x]), x))
    for a in apps:
        known = rec.ev.days_known(a, before=day)
        seen = rec.ev.days_seen(a, kind.unit, before=day)
        named = rec.ev.days_named(a, host, before=day)
        short_name = short(appfront.app_label(a))
        days = count(known, "viewing day")
        if not known:
            out.append(f"{short_name} has not been in front in the last 28 days.")
            continue
        if seen and named < seen:
            unit = f"Names of {kind.domain} with {label(kind, rec.profile)}"
            itself = f"on {count(named, 'day')}" if named else "never"
            out.append(
                f"{unit} were seen with {short_name} on {seen} of its {days}; this name itself: {itself}."
                f" Its site is in {short_name}'s picture, so a receipt would not call this name new."
            )
            continue
        where = "under advertising and measurement while" if kind.cls == appfront.TRACKING else "as new while"
        if seen >= appfront.PICTURE_FIRM_DAYS:
            out.append(f"With {short_name} it was seen on {seen} of {days}: it is in {short_name}'s picture.")
        elif seen:
            out.append(
                f"With {short_name} it was seen on 1 of {days}: it is in {short_name}'s picture on one day's"
                " evidence."
            )
        elif kind.cls == appfront.TRACKING or known >= appfront.PICTURE_READY_DAYS:
            out.append(
                f"With {short_name} it was never seen in {days}: a receipt would list it {where} {short_name}"
                " was in front."
            )
        else:
            out.append(
                f"With {short_name} it was never seen, but {short_name} has only {days} behind it:"
                f" nothing is called new before {appfront.PICTURE_READY_DAYS}."
            )
    return out
