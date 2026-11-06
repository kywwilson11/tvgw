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
import time
from collections.abc import Callable
from dataclasses import dataclass
from datetime import datetime

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
    INPUT: "An input shows another device's picture and needs no internet. What is listed here is the"
    " TV's own software, or an app still running behind it.",
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


def _row(kind: Kind, profile: Profile) -> dict:
    return {
        "domain": kind.domain,
        "category": kind.category,
        "plain": "not classified yet"
        if kind.cls == appfront.UNCLASSIFIED
        else plain.category_label(kind.category, profile),
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
    refused: dict[int, dict[tuple[str, str], int]] = {id(s): {} for s in chosen}
    for t, name, blocked in rec.looked:
        s = rec.tl.at(t)[1]
        if blocked and s is not None and id(s) in refused:
            kind = appfront.classify(rec.profile, name)
            key = (kind.domain, plain.category_label(kind.category, rec.profile))
            refused[id(s)][key] = refused[id(s)].get(key, 0) + 1
    return [_receipt(rec, s, by_session[id(s)], refused[id(s)]) for s in chosen]


def _receipt(rec: Record, s: Session, conns: list[Conn], refused: dict[tuple[str, str], int]) -> dict:
    day = appfront.viewing_day(s.start)
    is_app = s.kind == APP
    behind = rec.ev.days_known(s.app, before=day) if is_app else 0
    ready = is_app and rec.ev.ready(s.app, day)
    picture = rec.ev.picture(s.app, before=day) if is_app else set()
    groups: dict[str, dict[tuple[str, str], dict]] = {g: {} for g in GROUPS}
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
        if kind.cls in (appfront.PLATFORM, appfront.VENDOR):
            group = "tv"
        elif kind.cls == appfront.TRACKING:
            group = "tracking"
        elif not is_app:
            group = "meanwhile"
        elif kind.unit in picture:
            group = "before"
        else:
            group = "new" if ready else "unjudged"
        row = groups[group].setdefault(kind.unit, _row(kind, rec.profile))
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
        g: sorted(rows.values(), key=lambda r: (-(r["up"] + r["down"]), r["domain"], r["category"]))
        for g, rows in groups.items()
    }
    names = sorted(refused.items(), key=lambda kv: (-kv[1], kv[0]))
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
            "lookups": sum(refused.values()),
            "names": [{"domain": d, "plain": p, "lookups": n} for (d, p), n in names],
        },
    }


def _line(r: dict, behind: int) -> str:
    """One row of a group: the domain, what it is in plain words, how much, and what is known of it."""
    notes = []
    if r.get("days_seen"):
        notes.append(f"on {r['days_seen']} of {count(behind, 'earlier day')}")
    if r.get("also_with"):
        notes.append("usually seen with " + ", ".join(short(appfront.app_label(o)) for o in r["also_with"]))
    if r.get("stack_of"):
        notes.append(f"its TLS fingerprint is the one {short(appfront.app_label(r['stack_of']))} uses")
    tail = f"  ({'; '.join(notes)})" if notes else ""
    return (
        f"    {who(r['domain']):<34} {r['plain']:<24} {count(r['conns'], 'connection'):>15}"
        f"  {size(r['up'] + r['down']):>9}{tail}"
    )


def _group(out: list[str], title: str, rows: list[dict], behind: int) -> None:
    if not rows:
        return
    out.append(f"  {title}")
    out += [_line(r, behind) for r in rows[:TOP_ROWS]]
    if len(rows) > TOP_ROWS:
        rest = rows[TOP_ROWS:]
        out.append(
            f"    and {count(len(rest), 'more name')}: {count(sum(r['conns'] for r in rest), 'connection')},"
            f" {size(sum(r['up'] + r['down'] for r in rest))}"
        )


def render_receipt(r: dict) -> list[str]:
    """One session's receipt as lines."""
    name, behind = short(r["label"]), r["days_behind"]
    out = [r["label"]]
    timed = (
        "timed by the live reading"
        if r["timed"] == appfront.LIVE
        else "timed by the hourly readings: known to the hour, and a short switch to another app"
        " between two readings is not seen"
    )
    end = datetime.fromtimestamp(r["end"]).strftime("%H:%M")
    out.append(f"  {when(r['start'])} to {end}: {span(r['seconds'])}, {timed}")
    if r["timed"] == appfront.LIVE and not (r["start_exact"] and r["end_exact"]):
        edges = [
            "it was already in front when the live reading began" if not r["start_exact"] else "",
            {
                "lost": "the live reading lost the TV before it ended",
                "open": "it was still in front when this was written",
                "clock": "the gateway's clock was set while it ran",
            }.get(r["end_why"], "")
            if not r["end_exact"]
            else "",
        ]
        if any(edges):
            out.append("  " + "; ".join(e for e in edges if e))
    if r["idle_seconds"] >= 60:
        out.append(
            f"  {span(r['idle_seconds'])} of it behind the screen saver:"
            f" {count(r['idle']['conns'], 'connection')} started then, {size(r['idle']['bytes'])}"
        )
    if r["settling"]:
        out.append(
            "  Still settling: connections that were open in the last three hours are not all counted yet."
        )
    out.append(
        f"  {count(r['conns'], 'connection')} started while it was in front:"
        f" {size(r['down'])} down, {size(r['up'])} up"
    )
    if r["kind"] in KIND_NOTE:
        out.append("  " + KIND_NOTE[r["kind"]])
    g = r["groups"]
    _group(out, f"Seen with {name} before", g["before"], behind)
    _group(out, f"Advertising and measurement, while {name} was in front", g["tracking"], behind)
    _group(out, f"The TV's own services, while {name} was in front", g["tv"], behind)
    _group(out, f"Also talked while {name} was in front", g["meanwhile"], behind)
    new_title = f"Also talked while {name} was in front: new, not seen with it on any earlier day"
    _group(out, new_title, g["new"], behind)
    if r["kind"] == APP and not r["ready"]:
        need = appfront.PICTURE_READY_DAYS
        out.append(
            f"  Not judged yet: {name} has been in front on {count(r['days_behind'], 'earlier day')}, and"
            f" {need} are needed before a name is called new."
        )
        _group(out, "Names with no earlier day behind them", g["unjudged"], behind)
    elif r["kind"] == APP and not g["new"]:
        out.append(f"  Nothing new talked while {name} was in front.")
    if r["unnamed"]["conns"]:
        out.append(
            f"  No name was captured for {count(r['unnamed']['conns'], 'connection')}"
            f" ({size(r['unnamed']['bytes'])})."
        )
    ref = r["refused"]
    if ref["lookups"]:
        shown = ref["names"][:TOP_REFUSED]
        top = ", ".join(f"{who(n['domain'])} {n['lookups']} ({n['plain']})" for n in shown)
        rest = len(ref["names"]) - len(shown)
        more = f", and {count(rest, 'more name')}" if rest else ""
        out.append(
            f"  The filter refused {count(ref['lookups'], 'lookup')} of {count(len(ref['names']), 'name')}"
            f" while {name} was in front: {top}{more}"
        )
    else:
        out.append(f"  The filter refused no lookup while {name} was in front.")
    return out


def gap_summary(rec: Record, since: float | None = None) -> dict:
    """The time of the window in which nothing says which app was in front, the connections that started
    in it, and how many of them carry a TLS fingerprint that is one app's: the second witness, for the
    hours the first one missed. It names the software that opened a connection, not the app in front."""
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
    out = [
        f"In the {span(g['seconds'])} of this time in which nothing says which app was in front,"
        f" {count(g['conns'], 'connection')} started ({size(g['bytes'])})."
    ]
    if g["by_app"]:
        named = "; ".join(
            f"{short(c['label'])} {count(c['conns'], 'connection')}, {size(c['bytes'])}"
            for c in g["by_app"].values()
        )
        out.append(f"  By the software fingerprint of their TLS hello: {named}.")
        out.append(
            "  A fingerprint names the software that opened a connection, not the app that was in front."
        )
    out.append(f"  No fingerprint that is one app's: {count(g['unnamed'], 'connection')}.")
    return out


def render(rec: Record, found: list[dict], gaps: dict | None = None) -> list[str]:
    """The receipts as one text; with `gaps`, what started in the time no session covers."""
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
    out.append(FOOTER)
    if not rec.live:
        out.append(
            "These sessions come from the hourly readings. LIVE_READING=on times them to the second"
            " (docs/how-it-works/app-in-front.md)."
        )
    return out


def brief_section(rec: Record) -> list[dict]:
    """The sessions that started in the window, as the brief's short section shows them."""
    out = []
    for r in receipts(rec):
        new = r["groups"]["new"]
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
                "new": [n["domain"] for n in new],
                "refused_lookups": r["refused"]["lookups"],
                "settling": r["settling"],
            }
        )
    return out


BRIEF_MAX = 8


def render_brief_section(rows: list[dict], day_arg: str) -> list[str]:
    """The brief's section: one line a session, and where the whole receipt is."""
    out = ["", "App in front (sessions that started in this window; a connection counts where it started):"]
    days = {datetime.fromtimestamp(r["start"]).date() for r in rows}
    clock = "%H:%M" if len(days) <= 1 else "%a %H:%M"  # a week's report says which evening
    for r in rows[:BRIEF_MAX]:
        name = r["label"].split(" (")[0]
        tail = ""
        if r["kind"] == APP and r["ready"]:
            tail = (
                f"; new while it was in front: {', '.join(r['new'][:3])}"
                + (f" +{len(r['new']) - 3}" if len(r["new"]) > 3 else "")
                if r["new"]
                else "; nothing new"
            )
        elif r["kind"] == APP:
            tail = "; too few days to call anything new"
        start, end = datetime.fromtimestamp(r["start"]), datetime.fromtimestamp(r["end"])
        out.append(
            f"  {start.strftime(clock)}-{end:%H:%M} {name}, {span(r['seconds'])} ({r['timed']}):"
            f" {count(r['conns'], 'connection')}, {size(r['down'])} down{tail}"
            + ("; settling" if r["settling"] else "")
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
            rows.append(
                {
                    "domain": domain,
                    "category": category,
                    "plain": "not classified yet"
                    if category == appfront.NO_CATEGORY
                    else plain.category_label(category, rec.profile),
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
    if not found:
        return ["No app has been seen in front yet in the last 28 days."]
    out: list[str] = []
    for p in found:
        name = short(p["label"])
        need = appfront.PICTURE_READY_DAYS
        state = (
            "enough for a new name to be called new"
            if p["ready"]
            else f"{need} are needed before a name is called new"
        )
        out.append(f"{p['label']}: in front on {count(p['days'], 'viewing day')} of the last 28; {state}")
        for r in p["units"]:
            notes = [f"on {count(r['days_seen'], 'day')}" + ("" if r["firm"] else ", thin")]
            if r["tracking"]:
                notes.append(f"present with {name}, never its own")
            if r["also_with"]:
                others = ", ".join(short(appfront.app_label(o)) for o in r["also_with"])
                notes.append(f"also with {others}")
            out.append(f"    {who(r['domain']):<34} {r['plain']:<24} {'; '.join(notes)}")
        if not p["units"]:
            out.append("    nothing yet but the TV's own services")
        if p["stacks"]:
            out.append(f"    its own TLS fingerprints: {', '.join(p['stacks'])}")
        out.append("")
    out.append(
        "A picture is what was seen while the app was in front, by registrable domain and category."
        " The TV's own services and its maker's are never in one."
    )
    return out


# ---- the replay ------------------------------------------------------------------------------------------
def replay(rec: Record) -> dict:
    """The imagined rule over the window: while an app with enough days behind it is in front, allow its
    picture as of that day and the platform's essentials, refuse what is new. Per app and in all: what it
    would have refused, what it would have allowed on one earlier day's evidence alone (`thin`), how much
    of the app's content either is, and whether a must-allow name is among the refused. The rule carries
    the must-allow list, so none can be; `must_allow_outside_category` names any that only the list
    protects, because the profile files it outside the TV maker's own category."""
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
        row = a["refused"].setdefault(kind.unit, _row(kind, rec.profile))
        row["conns"] += 1
        row["down"] += c.down
        row["up"] += c.up
    out = []
    for a in sorted(apps.values(), key=lambda x: (-x["bytes"], x["app"])):
        ranked = sorted(a["refused"].values(), key=lambda r: (-(r["up"] + r["down"]), r["domain"]))
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
    }


def _share(n: float, of: float) -> float | None:
    return round(n / of, 4) if of else None


def meets_the_bar(n: dict) -> bool:
    """Whether a replay's numbers are the ones decision 67 asks for before a rule is ever tried on
    probation. True changes nothing: no rule exists to try."""
    return (
        n["content_outside_share"] is not None
        and n["content_outside_share"] <= BAR_CONTENT_OUTSIDE
        and n["must_allow_outside"] <= BAR_MUST_ALLOW_OUTSIDE
        and n["unnamed_share"] is not None
        and n["unnamed_share"] <= BAR_UNNAMED
        and n["app_days"] >= BAR_DAYS
        and n["app_days_live"] >= BAR_LIVE_SHARE * n["app_days"]
    )


def _pct(x: float | None) -> str:
    return "nothing to measure" if x is None else f"{x:.1%}"


def render_replay(r: dict) -> list[str]:
    out = [
        f"Would an app-in-front rule have worked? A replay of the last {r['window_days']:g} days."
        " Nothing is refused: this is a report.",
        "The imagined rule: while an app is in front, allow what was seen with it before and the TV's"
        " essentials (clock, sign-in, store, updates); refuse what is new.",
        "",
    ]
    for a in r["apps"]:
        name = short(a["label"])
        out.append(
            f"{a['label']}: {count(a['days'], 'day')} replayed, {count(a['conns'], 'connection')},"
            f" {size(a['bytes'])}"
        )
        out.append(
            f"  would have been refused as new: {count(a['refused_conns'], 'connection')},"
            f" {size(a['refused_bytes'])}; allowed on one earlier day only:"
            f" {count(a['thin_conns'], 'connection')}, {size(a['thin_bytes'])}"
        )
        out.append(
            f"  of {name}'s streaming bytes, new: {_pct(a['content_outside_share'])};"
            f" new or seen on one day only: {_pct(a['content_outside_or_thin_share'])}"
        )
        out.append(
            f"  must-allow names seen: {a['must_allow_seen']}, refused: {a['must_allow_refused']}"
            " (the rule carries the list)"
            + (
                f"; outside the TV maker's own category: {', '.join(a['must_allow_outside_category'])}"
                if a["must_allow_outside_category"]
                else ""
            )
        )
        out.append(
            f"  no name to judge: {count(a['unnamed_conns'], 'connection')}, {_pct(a['unnamed_share'])}"
            f" of bytes; the TV maker's other names, left to the name filter: {a['filter_conns']}"
        )
        for row in a["refused"][:TOP_ROWS]:
            out.append(
                f"    {who(row['domain']):<34} {row['plain']:<24} {count(row['conns'], 'connection'):>15}"
                f"  {size(row['up'] + row['down']):>9}"
            )
        if len(a["refused"]) > TOP_ROWS:
            out.append(f"    and {count(len(a['refused']) - TOP_ROWS, 'more name')}")
        out.append("")
    if not r["apps"]:
        out += ["No app had enough days behind it in this time for the rule to apply on any day.", ""]
    n, bar = r["numbers"], r["bar"]
    out.append("The two numbers that decide whether such a rule can ever be tried:")
    out.append(
        f"  streaming bytes outside the picture: {_pct(n['content_outside_share'])}"
        f" (the bar: at most {bar['content_outside_share']:.0%})"
    )
    out.append(
        f"  must-allow names outside it: {n['must_allow_outside']} (the bar: {bar['must_allow_outside']})"
    )
    out.append(
        f"Also asked: at most {bar['unnamed_share']:.0%} of bytes with no name to judge (here"
        f" {_pct(n['unnamed_share'])}), and at least {bar['viewing_days']} app-days replayed, nine in ten"
        f" timed by the live reading (here {n['app_days']}, {n['app_days_live']} of them live)."
    )
    out.append(
        "These numbers meet the bar. No rule exists to try: design decision 67 says what else it needs."
        if r["meets_the_bar"]
        else "These numbers do not meet the bar yet."
    )
    return out


# ---- why -------------------------------------------------------------------------------------------------
CLASS_MEANS: dict[str, Callable[[str], str]] = {
    appfront.PLATFORM: lambda v: (
        "It is counted as the TV's own under whichever app is in front, and no rule"
        " keyed to an app would touch it."
    ),
    appfront.VENDOR: lambda v: f"It is {v}'s, so it is never counted as an app's, whichever app is in front.",
    appfront.TRACKING: lambda v: (
        "It can be usual company for an app, and is listed as present with the app, never as the app's own."
    ),
    appfront.CONTENT: lambda v: "It belongs to an app's picture once it has been seen with that app.",
    appfront.SHARED: lambda v: "Several apps use such names, so it can be in more than one app's picture.",
    appfront.OTHER: lambda v: "It belongs to an app's picture once it has been seen with that app.",
    appfront.UNCLASSIFIED: lambda v: (
        "Until the profile names it, it is listed as not classified yet, never as somebody else's."
    ),
}


def why(rec: Record, name: str, app: str | None = None) -> list[str]:
    """Why `name` counts as it does: what the profile says it is, and what each app's days say of it."""
    kind = appfront.classify(rec.profile, name)
    label = (
        "not classified yet"
        if kind.cls == appfront.UNCLASSIFIED
        else plain.category_label(kind.category, rec.profile)
    )
    host = names.normalize(name)
    out = [
        f"{host}: {label} ({who(kind.domain)}), because {kind.why}."
        f" {CLASS_MEANS[kind.cls](rec.profile.vendor or 'the TV maker')}"
    ]
    if kind.cls not in appfront.PICTURE_CLASSES:
        return out
    day = appfront.viewing_day(rec.b) + 1
    apps = [app] if app else sorted(rec.ev.days, key=lambda x: (-len(rec.ev.days[x]), x))
    for a in apps:
        known = rec.ev.days_known(a, before=day)
        seen = rec.ev.days_seen(a, kind.unit, before=day)
        short_name = short(appfront.app_label(a))
        days = count(known, "viewing day")
        if not known:
            out.append(f"{short_name} has not been in front in the last 28 days.")
        elif seen >= appfront.PICTURE_FIRM_DAYS:
            out.append(f"With {short_name} it was seen on {seen} of {days}: it is in {short_name}'s picture.")
        elif seen:
            out.append(
                f"With {short_name} it was seen on 1 of {days}: it is in {short_name}'s picture on thin"
                " evidence."
            )
        elif known >= appfront.PICTURE_READY_DAYS:
            out.append(
                f"With {short_name} it was never seen in {days}: a receipt would list it as new while"
                f" {short_name} was in front."
            )
        else:
            out.append(
                f"With {short_name} it was never seen, but {short_name} has only {days} behind it:"
                f" nothing is called new before {appfront.PICTURE_READY_DAYS}."
            )
    return out
