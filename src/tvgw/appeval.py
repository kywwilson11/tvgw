"""`tvgw receipt --evaluate`: how well the app in front explains the TV's traffic, in numbers.

The sessions, the attribution and the pictures of appfront.py rest on choices that only a real store can
judge: how early an app's connections start before the TV reports it in front, what a late signal costs,
whether a picture learned on some days holds on another. This module measures each one over the store and
a live record (the store's, or a file of JSON lines from the live reading or from `tvgw tvprobe`):

- `record`: what the live record holds, and how the session to the TV behaved (attempts in the busiest
  hour, losses, the readings taken while it was up and whether they agreed);
- `evidence`: what the TV port's own counter read while the TV was on and while it was off, and how long
  after a TV's first lookup the session to it came up: what "the TV is probably on" can be taken from;
- `coverage`: the share of connections and bytes that started in a live session, an hourly session, a gap
  or none;
- `composition`: under each app, the connections and bytes by what the profile says each name is, and how
  much of it started behind the screen saver;
- `generalization`: leave one viewing day out. For each app and each of its days, the share of that day's
  connections and bytes inside the picture learned from the app's other days, the day itself never used:
  for three units (the full name, the registrable domain, the domain with its category), for a unit seen
  on at least one, two and three other days, and by category; then `outside`, every unit that falls
  outside on the day it is tested, which is the list a person reads before any rule is tried;
- `unclassified`: the domains the profile has no category for, by bytes, so the profile can be completed;
- `lag`: the attribution again with the TV's reports 2, 5 and 30 seconds late, with the lead window, and
  from the hourly readings alone: how many connections and bytes change hands;
- `lead`: when connections start around an app change the TV reported, all of them and those of the
  names only the new app uses;
- `outsiders`: per app, the names outside its picture on days the picture was ready, with the reason;
- `stacks`: per TLS stack (the hello's JA4), the share of its hellos under its most common app; how often
  a stack learned on the other days names the right app on the day left out; how much of the traffic that
  started in a gap a stack would attribute; and where one app's stack talked while another was in front.

It prints app ids, registrable domains, categories and counts: nothing dated, no address, no full host
name. It reads and never writes.
"""

from __future__ import annotations

import bisect
import itertools
import sqlite3
import statistics
from collections import Counter

from tvgw import appfront, names, queries
from tvgw.appfront import APP, GAP, HOURLY, LIVE, NONE, SESSION, Conn, Event, Timeline
from tvgw.profile import Profile

LAGS = (2.0, 5.0, 30.0)  # seconds the TV's reports are delayed by
LEAD_REACH = 60.0  # seconds either side of an app change the lead table looks at
LEAD_EDGES = (-60, -30, -10, -5, -3, -2, -1, 0, 1, 2, 5, 10, 30, 60)
NEAR_READING = (-90.0, 30.0)  # a session lost this close to an hourly reading may have been lost to it
TOP = 10
UNITS = ("name", "domain", "domain+category")
THRESHOLDS = (1, 2, 3)  # a unit seen on at least this many other days


def _key(unit: str) -> appfront.Key:
    if unit == "name":
        return lambda kind, name: name
    if unit == "domain":
        return lambda kind, name: kind.domain
    return appfront.unit_key


def _share(n: float, of: float) -> float | None:
    return round(n / of, 4) if of else None


def evaluate(
    conn: sqlite3.Connection,
    profile: Profile,
    events: list[Event],
    a: float,
    b: float,
    gw_ip: str,
    known_until: float | None = None,
    source: str = "store",
) -> dict:
    """Every measure over [a, b), as plain data."""
    rows = appfront.readings(conn, a, b)
    tl = appfront.timeline(events, rows, a, b, known_until=known_until)
    conns = appfront.connections(conn, a, b, gw_ip)
    seen = appfront.hellos(conn, a, b)
    ev = appfront.learn(tl, seen, profile)
    return {
        "window_days": round((b - a) / 86400, 2),
        "source": source,
        "constants": {
            "lead_seconds": appfront.LEAD_SECONDS,
            "picture_min_days": appfront.PICTURE_MIN_DAYS,
            "picture_ready_days": appfront.PICTURE_READY_DAYS,
        },
        "record": record(events, rows, tl, a, b),
        "evidence": evidence(conn, events, tl, a, b),
        "coverage": coverage(tl, conns),
        "composition": composition(tl, conns, profile),
        "generalization": generalization(tl, conns, seen, profile),
        "unclassified": unclassified(tl, conns, profile),
        "lag": lag(events, rows, a, b, conns, known_until),
        "lead": lead(events, rows, a, b, seen, profile, known_until),
        "outsiders": outsiders(tl, conns, profile, ev, appfront.learn_stacks(tl, seen)),
        "stacks": stacks(tl, seen, conns, profile),
    }


# ---- the record --------------------------------------------------------------------------------------
def attempts(events: list[Event]) -> list[tuple[float, bool]]:
    """(t, came up) for every connection attempt the record shows: a session that came up, or a failure
    that was not the end of one."""
    out, up = [], False
    for e in sorted(set(events), key=lambda e: (e.t, e.kind != "conn", e.value != "down")):
        if e.kind == "conn" and e.value == "up":
            out.append((e.t, True))
            up = True
        elif e.kind == "conn":
            if not up:
                out.append((e.t, False))
            up = False
        elif e.kind == "watch":
            up = False
    return out


def busiest_hour(times: list[float]) -> int:
    """The most of `times` inside any stretch of 3600 seconds."""
    times = sorted(times)
    return max((bisect.bisect_left(times, t + 3600) - i for i, t in enumerate(times)), default=0)


def record(events: list[Event], rows: list[tuple[float, str, str]], tl: Timeline, a: float, b: float) -> dict:
    evs = [e for e in events if a <= e.t < b]
    tried = [x for x in attempts(evs)]
    hourly = appfront.timeline([], rows, a, b, lead=0.0)
    while_off = sum(1 for t, _ in tried if hourly.at(t)[0] == NONE)
    downs = Counter(e.detail or "down" for e in evs if e.kind == "conn" and e.value == "down")
    # the hourly readings taken while the live session was up, against what the session said then
    exact = appfront.Timeline(tl.a, tl.b, tl.pieces, 0.0, tl.periods)
    inside = [r for r in rows if any(p0 <= r[0] < p1 for p0, p1 in tl.periods)]
    judged = power_ok = app_ok = both_on = unreachable = 0
    for t, power, app in inside:
        cls, s, _ = exact.at(t)
        if cls == GAP:
            continue
        judged += 1
        on = power in queries.AWAKE
        power_ok += on == (cls == SESSION)
        if cls == SESSION and not on:
            unreachable += 1
        if cls == SESSION and on and s is not None:
            both_on += 1
            app_ok += s.app == app
    reading_times = [r[0] for r in rows]
    lost = [
        e.t for e in evs if e.kind == "conn" and e.value == "down" and any(p1 == e.t for _, p1 in tl.periods)
    ]
    near = sum(
        1 for t in lost if any(NEAR_READING[0] <= t - r <= NEAR_READING[1] for r in _around(reading_times, t))
    )
    off_delays = []
    for p0, p1 in tl.periods:
        first_off = next(
            (
                e.t
                for e in sorted(evs, key=lambda e: e.t)
                if e.kind == "power"
                and p0 <= e.t < p1
                and appfront.power_class(e.value, e.detail) == appfront.OFF
            ),
            None,
        )
        if first_off is not None:
            off_delays.append(p1 - first_off)
    words = Counter((e.value, e.detail) for e in evs if e.kind == "power")
    return {
        "events": dict(sorted(Counter(e.kind for e in evs).items())),
        "readings": sum(1 for r in rows if a <= r[0] < b),
        "live_hours": round(sum(p1 - p0 for p0, p1 in tl.periods) / 3600, 2),
        "live_sessions": len(tl.periods),
        "attempts": len(tried),
        "attempts_failed": sum(1 for _, ok in tried if not ok),
        "attempts_busiest_hour": busiest_hour([t for t, _ in tried]),
        "attempts_while_readings_said_off": while_off,
        "ended": dict(sorted(downs.items())),
        "lost_near_a_reading": near,
        "readings_while_up": len(inside),
        "readings_judged": judged,
        "readings_power_agrees": power_ok,
        "readings_off_while_live_said_on": unreachable,
        "readings_both_on": both_on,
        "readings_app_agrees": app_ok,
        "off_to_loss_seconds": _spread(off_delays),
        "power_words": [
            {"state": s, "processing": p, "n": n}
            for (s, p), n in sorted(words.items(), key=lambda kv: (-kv[1], kv[0]))
        ],
        "apps": dict(Counter(e.value or "(home)" for e in evs if e.kind == "app").most_common()),
    }


def _around(times: list[float], t: float) -> list[float]:
    i = bisect.bisect_left(times, t)
    return times[max(0, i - 2) : i + 2]


def _spread(values: list[float]) -> dict | None:
    if not values:
        return None
    return {"n": len(values), "median": round(statistics.median(values), 1), "max": round(max(values), 1)}


# ---- evidence that the TV is on ------------------------------------------------------------------------
QUIET_BEFORE = 1800.0  # seconds without a lookup before one counts as the TV's first after a quiet stretch
WAKE_REACH = 600.0  # how long before a session came up its first lookup is looked for
SAMPLE_GAP = 1800.0  # as activity.MAX_GAP: two samples further apart are not an interval


def evidence(conn: sqlite3.Connection, events: list[Event], tl: Timeline, a: float, b: float) -> dict:
    """The bytes the gateway received from the TV between two of the sampler's readings (`gw_samples`,
    every 10 minutes), per 600 s, by what the TV was doing: intervals that lie whole in a session, whole in
    time the TV said it was off, and whole in a gap. Off is what a threshold for "the TV is probably on"
    has to clear. `pairs` says how many intervals there were and why the rest did not count, and
    `off_hours_sampled` how much of the off time the samples cover at all: an off spread that is missing
    explains itself. Then, for each time the
    session to the TV came up, how long after the TV's first lookup that was, and how many attempts failed
    in between: how long a TV takes to answer after its traffic starts."""
    try:
        samples = conn.execute(
            "SELECT t, boot_id, tv_rx_bytes FROM gw_samples WHERE t >= ? AND t < ? ORDER BY t", (a, b)
        ).fetchall()
    except sqlite3.OperationalError:  # a store from before the sampler
        samples = []
    rates: dict[str, list[float]] = {SESSION: [], NONE: [], GAP: []}
    pairs = Counter()
    for (t0, boot0, rx0), (t1, boot1, rx1) in itertools.pairwise(samples):
        if rx0 is None or rx1 is None:
            pairs["no counter"] += 1
        elif not 0 < t1 - t0 <= SAMPLE_GAP:
            pairs["samples too far apart"] += 1
        elif boot0 and boot1 and boot0 != boot1:
            pairs["a reboot between"] += 1
        elif rx1 < rx0:
            pairs["the counter went down"] += 1
        else:
            rate = (rx1 - rx0) * 600 / (t1 - t0)
            classes = {tl.at(t)[0] for t in (t0, (t0 + t1) / 2, t1 - 0.001)}
            cls = classes.pop() if len(classes) == 1 else "mixed"
            pairs[cls] += 1
            if cls in rates:
                rates[cls].append(rate)
    span = (samples[0][0], samples[-1][0]) if samples else None
    off_hours = sum(p.t1 - p.t0 for p in tl.pieces if p.cls == NONE) / 3600
    off_sampled = (
        sum(max(0.0, min(p.t1, span[1]) - max(p.t0, span[0])) for p in tl.pieces if p.cls == NONE) / 3600
        if span
        else 0.0
    )
    tried = attempts([e for e in events if a <= e.t < b])
    delays, failed_before = [], 0
    for p0, _ in tl.periods:
        times = [
            t
            for (t,) in conn.execute(
                "SELECT t FROM dns WHERE t >= ? AND t <= ? ORDER BY t", (p0 - WAKE_REACH - QUIET_BEFORE, p0)
            )
        ]
        first = next(
            (
                t
                for i, t in enumerate(times)
                if t >= p0 - WAKE_REACH and (i == 0 or t - times[i - 1] >= QUIET_BEFORE)
            ),
            None,
        )
        if first is not None:
            delays.append(p0 - first)
            failed_before += sum(1 for t, ok in tried if not ok and first <= t < p0)
    on, off = rates[SESSION], rates[NONE]
    floor = max(off, default=None)
    return {
        "samples": len(samples),
        "sampled_hours": round((span[1] - span[0]) / 3600, 1) if span else 0.0,
        "pairs": dict(sorted(pairs.items())),
        "off_hours": round(off_hours, 1),
        "off_hours_sampled": round(off_sampled, 1),
        "intervals_on": len(on),
        "intervals_off": len(off),
        "intervals_gap": len(rates[GAP]),
        "rx_bytes_per_600s_on": _quantiles(on, (0.0, 0.01, 0.1, 0.5)),
        "rx_bytes_per_600s_off": _quantiles(off, (0.5, 0.9, 0.99, 1.0)),
        "rx_bytes_per_600s_gap": _quantiles(rates[GAP], (0.0, 0.1, 0.5, 1.0)),
        "on_intervals_above_every_off_interval": (
            None if floor is None else _share(sum(1 for x in on if x > floor), len(on))
        ),
        "wakes": len(delays),
        "first_lookup_to_session_seconds": _spread(delays),
        "attempts_failed_between": failed_before,
    }


def _quantiles(values: list[float], points: tuple[float, ...]) -> dict | None:
    if not values:
        return None
    ordered = sorted(values)
    return {
        f"p{round(q * 100)}": round(ordered[min(len(ordered) - 1, int(q * len(ordered)))]) for q in points
    }


# ---- composition -------------------------------------------------------------------------------------
UNNAMED = "unnamed"


def composition(tl: Timeline, conns: list[Conn], profile: Profile) -> dict:
    """Under each app (and under the home screen, inputs and cast receivers as three groups): connections
    and bytes by what the profile says each name is, and how much started behind the screen saver. How
    much of an evening's traffic can be the app's own at all."""
    out: dict[str, dict] = {}
    for c in conns:
        cls, s, _ = tl.at(c.t)
        if cls != SESSION or s is None:
            continue
        who = s.app if s.kind == APP else f"({s.kind})"
        row = out.setdefault(who, {"conns": 0, "bytes": 0, "idle_conns": 0, "idle_bytes": 0, "by_class": {}})
        kind = appfront.classify(profile, c.name).cls if c.name else UNNAMED
        cell = row["by_class"].setdefault(kind, {"conns": 0, "bytes": 0})
        for target in (row, cell):
            target["conns"] += 1
            target["bytes"] += c.bytes
        if s.is_idle(c.t):
            row["idle_conns"] += 1
            row["idle_bytes"] += c.bytes
    for row in out.values():
        for cell in row["by_class"].values():
            cell["bytes_share"] = _share(cell["bytes"], row["bytes"])
        row["by_class"] = dict(sorted(row["by_class"].items()))
    return dict(sorted(out.items(), key=lambda kv: (-kv[1]["bytes"], kv[0])))


# ---- coverage ----------------------------------------------------------------------------------------
def coverage(tl: Timeline, conns: list[Conn]) -> dict:
    cells = {k: {"conns": 0, "bytes": 0} for k in (LIVE, HOURLY, GAP, NONE)}
    kinds: dict[str, dict] = {}
    led = named = timed = 0
    for c in conns:
        cls, s, was_lead = tl.at(c.t)
        cell = cells[s.timed if s is not None else cls]
        cell["conns"] += 1
        cell["bytes"] += c.bytes
        if s is not None:
            k = kinds.setdefault(s.kind, {"conns": 0, "bytes": 0})
            k["conns"] += 1
            k["bytes"] += c.bytes
        led += was_lead
        named += bool(c.name)
        timed += c.hello
    n, total = len(conns), sum(c.bytes for c in conns)
    for cell in cells.values():
        cell["conns_share"] = _share(cell["conns"], n)
        cell["bytes_share"] = _share(cell["bytes"], total)
    secs = tl.seconds()
    return {
        "connections": n,
        "bytes": total,
        "named": named,
        "timed_by_hello": timed,
        "in_lead_window": led,
        "hours": {k: round(v / 3600, 2) for k, v in secs.items()},
        "by_class": cells,
        "by_session_kind": dict(sorted(kinds.items())),
        "sessions": Counter(f"{s.timed} {s.kind}" for s in tl.sessions),
    }


# ---- leave one viewing day out -----------------------------------------------------------------------
def generalization(
    tl: Timeline, conns: list[Conn], seen: list[tuple[float, str, str]], profile: Profile
) -> dict:
    """Per app, unit and threshold: of each day's connections and bytes under the app, the share inside
    the picture learned from the app's other days. A day is tested only when the app has at least as many
    other days as the threshold asks; the day itself never feeds its own picture."""
    items = []  # (app, day, kind, name, bytes) for every named connection an app's picture could hold
    for c in conns:
        cls, s, _ = tl.at(c.t)
        if cls != SESSION or s is None or s.kind != APP or not c.name:
            continue
        kind = appfront.classify(profile, c.name)
        if kind.cls in appfront.PICTURE_CLASSES:
            items.append((s.app, appfront.viewing_day(c.t), kind, names.normalize(c.name), c.bytes))
    thresholds = THRESHOLDS
    rows, by_category = [], []
    outside: dict[tuple[str, str, str], dict] = {}  # (app, domain, category) -> what fell outside
    for unit in UNITS:
        key = _key(unit)
        ev = appfront.learn(tl, seen, profile, key)
        for app in sorted(ev.days, key=lambda x: (-len(ev.days[x]), x)):
            mine = [it for it in items if it[0] == app]
            for m in thresholds:
                pictures = {
                    d: ev.picture(app, without=d, min_days=m)
                    for d in ev.days[app]
                    if ev.days_known(app, without=d) >= m
                }
                tot = _Tally()
                cats: dict[str, _Tally] = {}
                for _, day, kind, name, size in mine:
                    if day not in pictures:
                        continue
                    hit = key(kind, name) in pictures[day]
                    tot.add(hit, size, kind.cls == appfront.CONTENT)
                    cats.setdefault(kind.category, _Tally()).add(hit, size, kind.cls == appfront.CONTENT)
                    if not hit and unit == UNITS[-1] and m == appfront.PICTURE_MIN_DAYS:
                        o = outside.setdefault(
                            (app, kind.domain, kind.category),
                            {"app": app, "domain": kind.domain, "category": kind.category, "cls": kind.cls}
                            | {"conns": 0, "bytes": 0, "days": set()},
                        )
                        o["conns"] += 1
                        o["bytes"] += size
                        o["days"].add(day)
                rows.append(
                    {"app": app, "days": len(ev.days[app]), "days_tested": len(pictures), "unit": unit}
                    | {"seen_on_other_days": m}
                    | tot.as_dict()
                )
                if unit == UNITS[-1]:
                    by_category += [
                        {"app": app, "seen_on_other_days": m, "category": cat} | t.as_dict()
                        for cat, t in sorted(cats.items())
                    ]
    listed = sorted(outside.values(), key=lambda o: (o["app"], -o["bytes"], o["domain"], o["category"]))
    return {
        "rows": rows,
        "by_category": by_category,
        "outside": [o | {"days": len(o["days"])} for o in listed],
    }


def unclassified(tl: Timeline, conns: list[Conn], profile: Profile) -> dict:
    """The registrable domains the profile has no category for, by bytes, with the apps they were seen
    under: what to classify first. Their bytes are nobody's until then, never "somebody else's"."""
    found: dict[str, dict] = {}
    total = sum(c.bytes for c in conns)
    for c in conns:
        if not c.name:
            continue
        kind = appfront.classify(profile, c.name)
        if kind.cls != appfront.UNCLASSIFIED:
            continue
        row = found.setdefault(kind.domain, {"domain": kind.domain, "conns": 0, "bytes": 0, "apps": set()})
        row["conns"] += 1
        row["bytes"] += c.bytes
        s = tl.at(c.t)[1]
        if s is not None and s.kind == APP:
            row["apps"].add(s.app)
    ranked = sorted(found.values(), key=lambda r: (-r["bytes"], r["domain"]))
    return {
        "domains": len(ranked),
        "conns": sum(r["conns"] for r in ranked),
        "bytes": sum(r["bytes"] for r in ranked),
        "bytes_share": _share(sum(r["bytes"] for r in ranked), total),
        "rows": [r | {"apps": sorted(r["apps"])} for r in ranked[: 2 * TOP]],
    }


class _Tally:
    def __init__(self) -> None:
        self.conns = self.inside = self.bytes = self.bytes_in = self.content = self.content_in = 0

    def add(self, hit: bool, size: int, content: bool) -> None:
        self.conns += 1
        self.inside += hit
        self.bytes += size
        self.bytes_in += size * hit
        if content:
            self.content += size
            self.content_in += size * hit

    def as_dict(self) -> dict:
        return {
            "conns": self.conns,
            "conns_inside": self.inside,
            "conns_share": _share(self.inside, self.conns),
            "bytes": self.bytes,
            "bytes_share": _share(self.bytes_in, self.bytes),
            "content_bytes": self.content,
            "content_bytes_share": _share(self.content_in, self.content),
        }


# ---- lag ---------------------------------------------------------------------------------------------
def lag(
    events: list[Event],
    rows: list[tuple[float, str, str]],
    a: float,
    b: float,
    conns: list[Conn],
    known_until: float | None,
) -> dict:
    """How many connections and bytes change hands when the signal is worse than the record: the base is
    the record as it is, with no lead window, and what is compared is every connection that started while
    the live session was up, whether the record puts it under an app or under nobody (a late signal keeps
    an app in front after the TV has left it)."""
    base = appfront.timeline(events, rows, a, b, lead=0.0, known_until=known_until)
    starts = [p0 for p0, _ in base.periods]

    def heard(t: float) -> bool:
        i = bisect.bisect_right(starts, t) - 1
        return i >= 0 and t < base.periods[i][1]

    live = [c for c in conns if heard(c.t)]
    labels = [base.label(c.t) for c in live]
    variants = [(f"reports {d:g} s late", appfront.shifted(events, d), 0.0) for d in LAGS]
    variants.append((f"lead window {appfront.LEAD_SECONDS:g} s", events, appfront.LEAD_SECONDS))
    variants.append(("hourly readings alone", [], 0.0))
    total = sum(c.bytes for c in live)
    out = []
    for name, evs, lead_s in variants:
        tl = appfront.timeline(evs, rows, a, b, lead=lead_s, known_until=known_until)
        moved = moved_bytes = to_other_app = 0
        for c, was in zip(live, labels, strict=True):
            now = tl.label(c.t)
            if now != was:
                moved += 1
                moved_bytes += c.bytes
                to_other_app += not now.startswith("(")
        out.append(
            {
                "variant": name,
                "conns_moved": moved,
                "conns_share": _share(moved, len(live)),
                "bytes_moved": moved_bytes,
                "bytes_share": _share(moved_bytes, total),
                "to_an_app": to_other_app,
            }
        )
    return {"conns_while_live": len(live), "bytes_while_live": total, "variants": out}


# ---- lead --------------------------------------------------------------------------------------------
def lead(
    events: list[Event],
    rows: list[tuple[float, str, str]],
    a: float,
    b: float,
    seen: list[tuple[float, str, str]],
    profile: Profile,
    known_until: float | None,
) -> dict:
    """Hellos by their distance from the nearest app change the TV reported. `new` are names in the
    picture of the app that came to the front and not of the one that left (seen under it on two days or
    more); `old` the reverse: how early an app starts talking, and how long the old one keeps on."""
    tl = appfront.timeline(events, rows, a, b, lead=0.0, known_until=known_until)
    ev = appfront.learn(tl, seen, profile)
    changes = []  # (t, app before, app after)
    for s in tl.sessions:
        if s.leads and tl.a < s.start < tl.b:
            before = tl.at(s.start - 0.001)[1]
            changes.append((s.start, before.app if before is not None else None, s.app))
    times = [c[0] for c in changes]
    pictures = {app: ev.picture(app, min_days=2) for app in ev.seen}
    bins = {k: [0] * (len(LEAD_EDGES) - 1) for k in ("all", "new", "old")}
    offsets_new = []
    for t, name, _ in seen:
        i = bisect.bisect_left(times, t)
        near = [c for c in changes[max(0, i - 1) : i + 1] if abs(t - c[0]) < LEAD_REACH]
        if not near:
            continue
        at, before, after = min(near, key=lambda c: abs(t - c[0]))
        slot = bisect.bisect_right(LEAD_EDGES, t - at) - 1
        if not 0 <= slot < len(LEAD_EDGES) - 1:
            continue
        bins["all"][slot] += 1
        unit = appfront.classify(profile, name).unit
        in_new = unit in pictures.get(after, ())
        in_old = before is not None and unit in pictures.get(before, ())
        if in_new and not in_old:
            bins["new"][slot] += 1
            offsets_new.append(t - at)
        elif in_old and not in_new:
            bins["old"][slot] += 1
    early = sorted(-o for o in offsets_new if o < 0)
    return {
        "app_changes": len(changes),
        "edges_seconds": list(LEAD_EDGES),
        "bins": bins,
        "new_names_before_the_change": len(early),
        "new_names_after_the_change": len(offsets_new) - len(early),
        "new_names_lead_seconds": {
            "median": round(statistics.median(early), 2),
            "p90": round(early[min(len(early) - 1, int(0.9 * len(early)))], 2),
            "max": round(early[-1], 2),
        }
        if early
        else None,
    }


# ---- outsiders ---------------------------------------------------------------------------------------
def outsiders(
    tl: Timeline, conns: list[Conn], profile: Profile, ev: appfront.Evidence, st: appfront.Stacks
) -> dict:
    """Per app, what talked while it was in front and was new under it, on days the app had enough earlier
    days for that to mean something, each with why: the names a receipt would list, so a person can check
    them."""
    pictures: dict[tuple[str, int], set] = {}
    found: dict[str, dict[tuple[str, str], dict]] = {}
    days = {"ready": set(), "not_ready": set()}
    for c in conns:
        cls, s, _ = tl.at(c.t)
        if cls != SESSION or s is None or s.kind != APP or not c.name:
            continue
        day = appfront.viewing_day(c.t)
        if not ev.ready(s.app, day):
            days["not_ready"].add((s.app, day))
            continue
        days["ready"].add((s.app, day))
        kind = appfront.classify(profile, c.name)
        why = outsider_reason(ev, s.app, kind, day, pictures, st.names(c.ja4))
        if why is None:
            continue
        row = found.setdefault(s.app, {}).setdefault(
            kind.unit,
            {"domain": kind.domain, "category": kind.category, "conns": 0, "bytes": 0, "days": set()},
        )
        row["conns"] += 1
        row["bytes"] += c.bytes
        row["days"].add(day)
        row["why"] = why
    out = {}
    for app, units in sorted(found.items()):
        ranked = sorted(units.values(), key=lambda r: (-r["conns"], r["domain"], r["category"]))
        out[app] = [r | {"days": len(r["days"])} for r in ranked[:TOP]]
        if len(ranked) > TOP:
            out[app].append({"more": len(ranked) - TOP})
    return {
        "app_days_ready": len(days["ready"]),
        "app_days_not_ready": len(days["not_ready"] - days["ready"]),
        "by_app": out,
    }


def outsider_reason(
    ev: appfront.Evidence,
    app: str,
    kind: appfront.Kind,
    day: int,
    cache: dict[tuple[str, int], set],
    software: str | None = None,
) -> str | None:
    """Why a name is outside `app`'s picture on `day`, or None when it is inside it or is the platform's.
    `cache` holds the pictures already worked out, by app and day; `software` is the app the connection's
    TLS stack names, when it names one."""

    def picture(of: str) -> set:
        if (of, day) not in cache:
            cache[(of, day)] = ev.picture(of, before=day)
        return cache[(of, day)]

    if kind.cls == appfront.PLATFORM:
        return None
    if kind.cls == appfront.VENDOR:
        return f"{kind.category}: the TV maker's, not an app's"
    if kind.unit in picture(app):
        return None
    why = "new under this app"
    if kind.cls == appfront.UNCLASSIFIED:
        why += "; not classified yet"
    others = [o for o in sorted(ev.seen) if o != app and kind.unit in picture(o)]
    if others:
        why += "; in the picture of " + ", ".join(others)
    if software is not None and software != app:
        why += f"; its TLS stack is the one {software} uses"
    return why


# ---- stacks ------------------------------------------------------------------------------------------
def stacks(tl: Timeline, seen: list[tuple[float, str, str]], conns: list[Conn], profile: Profile) -> dict:
    """Per TLS stack (a hello's JA4): how many hellos, under how many apps, and the share under its most
    common app (appfront.Stacks holds the rule). Then four measures of the stack as a witness:
    `agreement`, the share of content hellos whose stack names the app in front; `left_out`, how often a
    stack learned on the other viewing days names an app for a hello of the day left out, and how often
    that is the app in front; `gap`, how many of the connections that started in a gap a stack names an
    app for; and `other_software`, connections under one app whose stack is another app's."""
    st = appfront.learn_stacks(tl, seen)
    if not st.seen:
        return {"available": False}
    rows = []
    for ja4 in st.seen:
        kind, app, n, purity = st.verdict(ja4)
        verdict = f"names {app}" if kind == "app" else kind
        top = app if app is not None else sorted(st.apps(ja4).items(), key=lambda kv: (-kv[1], kv[0]))[0][0]
        rows.append(
            {"ja4": ja4, "hellos": n, "apps": len(st.apps(ja4)), "top_app": top, "purity": round(purity, 3)}
            | {"verdict": verdict}
        )
    rows.sort(key=lambda r: (-r["hellos"], r["ja4"]))
    content = named = agree = tested = said = right = 0
    for t, name, ja4 in seen:
        cls, s, _ = tl.at(t)
        if cls != SESSION or s is None or s.kind != APP or not ja4:
            continue
        tested += 1
        guess = st.names(ja4, without=appfront.viewing_day(t))
        said += guess is not None
        right += guess == s.app
        if appfront.classify(profile, name).cls == appfront.CONTENT:
            content += 1
            named += st.names(ja4) is not None
            agree += st.names(ja4) == s.app
    gap = {"conns": 0, "bytes": 0, "with_a_stack": 0, "named": 0, "named_bytes": 0, "by_app": {}}
    other: dict[tuple[str, str], dict] = {}
    for c in conns:
        cls, s, _ = tl.at(c.t)
        whose = st.names(c.ja4)
        if cls == GAP:
            gap["conns"] += 1
            gap["bytes"] += c.bytes
            gap["with_a_stack"] += bool(c.ja4)
            if whose is not None:
                gap["named"] += 1
                gap["named_bytes"] += c.bytes
                cell = gap["by_app"].setdefault(whose, {"conns": 0, "bytes": 0})
                cell["conns"] += 1
                cell["bytes"] += c.bytes
        elif s is not None and s.kind == APP and whose is not None and whose != s.app:
            cell = other.setdefault(
                (s.app, whose), {"in_front": s.app, "software_of": whose, "conns": 0, "bytes": 0}
            )
            cell["conns"] += 1
            cell["bytes"] += c.bytes
    gap["conns_share"] = _share(gap["named"], gap["conns"])
    gap["bytes_share"] = _share(gap["named_bytes"], gap["bytes"])
    gap["by_app"] = dict(sorted(gap["by_app"].items(), key=lambda kv: (-kv[1]["bytes"], kv[0])))
    return {
        "available": True,
        "rule": {"purity": appfront.STACK_PURE, "hellos": appfront.STACK_MIN},
        "stacks": len(rows),
        "rows": rows[: 2 * TOP],
        "content_hellos": content,
        "content_hellos_named": named,
        "agreement": _share(agree, content),
        "left_out": {
            "hellos": tested,
            "named": said,
            "right": right,
            "named_share": _share(said, tested),
            "right_of_named": _share(right, said),
        },
        "gap": gap,
        "other_software": sorted(
            other.values(), key=lambda r: (-r["conns"], r["in_front"], r["software_of"])
        ),
    }


# ---- as text -----------------------------------------------------------------------------------------
def _pct(x: float | None) -> str:
    return "-" if x is None else f"{x:.1%}"


def _table(rows: list[list], headers: list[str]) -> list[str]:
    cells = [headers, *[[str(c) for c in r] for r in rows]]
    widths = [max(len(r[i]) for r in cells) for i in range(len(headers))]
    return ["  " + "  ".join(c.ljust(w) for c, w in zip(r, widths, strict=True)).rstrip() for r in cells]


def render(r: dict) -> list[str]:
    """The evaluation as lines: numbers and names the brief already shows."""
    k = r["constants"]
    out = [
        f"tvgw receipt --evaluate: {r['window_days']} days, live record from {r['source']}; lead"
        f" {k['lead_seconds']:g} s, in a picture after {k['picture_min_days']} days, ready after"
        f" {k['picture_ready_days']}"
    ]
    rec = r["record"]
    out += ["", "record"]
    out.append("  events: " + (", ".join(f"{kind} {n}" for kind, n in rec["events"].items()) or "none"))
    out.append(f"  hourly readings: {rec['readings']}")
    out.append(f"  live: {rec['live_hours']} h in {rec['live_sessions']} sessions to the TV")
    out.append(
        f"  attempts: {rec['attempts']} ({rec['attempts_failed']} failed), busiest hour"
        f" {rec['attempts_busiest_hour']}, while the readings said off"
        f" {rec['attempts_while_readings_said_off']}"
    )
    out.append("  ended: " + (", ".join(f"{why} {n}" for why, n in rec["ended"].items()) or "none"))
    out.append(f"  lost within 90 s before or 30 s after an hourly reading: {rec['lost_near_a_reading']}")
    out.append(
        f"  readings while up: {rec['readings_while_up']}; judged {rec['readings_judged']}, power agrees"
        f" {rec['readings_power_agrees']}, said off while live said on"
        f" {rec['readings_off_while_live_said_on']};"
        f" both on {rec['readings_both_on']}, app agrees {rec['readings_app_agrees']}"
    )
    d = rec["off_to_loss_seconds"]
    out.append(
        "  from the TV saying it switches off to the session's loss: "
        + (f"median {d['median']} s, max {d['max']} s (n={d['n']})" if d else "not seen")
    )
    out.append(
        "  power words: "
        + (
            ", ".join(
                f"{w['state']}{' / ' + w['processing'] if w['processing'] else ''} {w['n']}"
                for w in rec["power_words"]
            )
            or "none"
        )
    )
    out.append("  app events: " + (", ".join(f"{app} {n}" for app, n in rec["apps"].items()) or "none"))
    evd = r["evidence"]
    out += ["", "evidence that the TV is on (bytes the gateway received from the TV, per 600 s)"]
    out.append(
        f"  samples: {evd['samples']} over {evd['sampled_hours']} h; pairs: "
        + (", ".join(f"{why} {n}" for why, n in evd["pairs"].items()) or "none")
    )
    out.append(
        f"  hours the readings call off: {evd['off_hours']}, of them inside the samples:"
        f" {evd['off_hours_sampled']}"
    )
    for label, key, n in (
        ("in a session", "rx_bytes_per_600s_on", evd["intervals_on"]),
        ("TV off", "rx_bytes_per_600s_off", evd["intervals_off"]),
        ("in a gap", "rx_bytes_per_600s_gap", evd["intervals_gap"]),
    ):
        q = evd[key]
        out.append(
            f"  {label}: {n} intervals" + ("; " + ", ".join(f"{k} {v}" for k, v in q.items()) if q else "")
        )
    out.append(
        "  session intervals above every off interval: " + _pct(evd["on_intervals_above_every_off_interval"])
    )
    d = evd["first_lookup_to_session_seconds"]
    out.append(
        "  from the TV's first lookup after a quiet half hour to the session coming up: "
        + (f"median {d['median']} s, max {d['max']} s (n={d['n']})" if d else "not seen")
        + f"; attempts that failed in between: {evd['attempts_failed_between']}"
    )
    cov = r["coverage"]
    out += ["", "coverage"]
    out.append(
        f"  connections {cov['connections']} ({cov['named']} named, {cov['timed_by_hello']} timed by their"
        f" hello, {cov['in_lead_window']} in the lead window), bytes {cov['bytes']}"
    )
    out += _table(
        [
            [name, cov["hours"][key], c["conns"], _pct(c["conns_share"]), c["bytes"], _pct(c["bytes_share"])]
            for name, key in (
                ("live session", LIVE),
                ("hourly session", HOURLY),
                ("gap", GAP),
                ("none", NONE),
            )
            for c in [cov["by_class"][key]]
        ],
        ["started in", "hours", "conns", "share", "bytes", "share"],
    )
    out.append(
        "  sessions: " + (", ".join(f"{name} {n}" for name, n in sorted(cov["sessions"].items())) or "none")
    )
    out.append(
        "  by kind of session: "
        + (
            ", ".join(
                f"{kd} {c['conns']} conns {c['bytes']} bytes" for kd, c in cov["by_session_kind"].items()
            )
            or "none"
        )
    )
    out += ["", "composition (connections that started under each app, by what the profile says the name is)"]
    comp_rows = []
    for who, row in r["composition"].items():
        for kind, cell in row["by_class"].items():
            comp_rows.append([who, kind, cell["conns"], cell["bytes"], _pct(cell["bytes_share"])])
        comp_rows.append([who, "(behind the screen saver)", row["idle_conns"], row["idle_bytes"], ""])
    out += _table(comp_rows, ["app", "class", "conns", "bytes", "share"]) if comp_rows else ["  none"]
    gen = r["generalization"]
    out += ["", "generalization (leave one viewing day out: share inside the picture from the other days)"]
    if gen["rows"]:
        out += _table(
            [
                [
                    g["app"],
                    f"{g['days_tested']}/{g['days']}",
                    g["unit"],
                    g["seen_on_other_days"],
                    g["conns"],
                    _pct(g["conns_share"]),
                    _pct(g["bytes_share"]),
                    _pct(g["content_bytes_share"]),
                ]
                for g in gen["rows"]
            ],
            ["app", "days", "unit", "on>=", "conns", "inside", "bytes in", "content in"],
        )
        out.append("  by category (unit: domain+category)")
        out += _table(
            [
                [
                    g["app"],
                    g["seen_on_other_days"],
                    g["category"],
                    g["conns"],
                    _pct(g["conns_share"]),
                    g["bytes"],
                    _pct(g["bytes_share"]),
                ]
                for g in gen["by_category"]
            ],
            ["app", "on>=", "category", "conns", "inside", "bytes", "bytes in"],
        )
        out.append("  outside (domain+category, seen on no other day): what a rule would have refused")
        if gen["outside"]:
            out += _table(
                [
                    [o["app"], o["domain"], o["category"], o["cls"], o["conns"], o["bytes"], o["days"]]
                    for o in gen["outside"]
                ],
                ["app", "domain", "category", "class", "conns", "bytes", "days"],
            )
        else:
            out.append("  nothing")
    else:
        out.append("  no app has connections on a day to test")
    unc = r["unclassified"]
    out += [
        "",
        f"unclassified (no category in the profile: {unc['domains']} domains, {unc['conns']} connections,"
        f" {_pct(unc['bytes_share'])} of all bytes)",
    ]
    out += (
        _table(
            [[u["domain"], u["conns"], u["bytes"], ", ".join(u["apps"]) or "-"] for u in unc["rows"]],
            ["domain", "conns", "bytes", "seen under"],
        )
        if unc["rows"]
        else ["  none"]
    )
    lg = r["lag"]
    out += ["", f"lag (of {lg['conns_while_live']} connections that started while the live session was up)"]
    out += _table(
        [
            [
                v["variant"],
                v["conns_moved"],
                _pct(v["conns_share"]),
                v["bytes_moved"],
                _pct(v["bytes_share"]),
                v["to_an_app"],
            ]
            for v in lg["variants"]
        ],
        ["variant", "conns moved", "share", "bytes moved", "share", "to an app"],
    )
    ld = r["lead"]
    out += [
        "",
        f"lead (hellos around {ld['app_changes']} app changes the TV reported; seconds from the change)",
    ]
    edges = ld["edges_seconds"]
    out += _table(
        [
            [
                f"{edges[i]:+d}..{edges[i + 1]:+d}",
                ld["bins"]["all"][i],
                ld["bins"]["new"][i],
                ld["bins"]["old"][i],
            ]
            for i in range(len(edges) - 1)
        ],
        ["seconds", "all", "new app's", "old app's"],
    )
    s = ld["new_names_lead_seconds"]
    out.append(
        f"  the new app's names: {ld['new_names_before_the_change']} before the change,"
        f" {ld['new_names_after_the_change']} after"
        + (
            f"; before it by median {s['median']} s, 90th percentile {s['p90']} s, most {s['max']} s"
            if s
            else ""
        )
    )
    o = r["outsiders"]
    out += [
        "",
        f"outsiders (app-days with a ready picture: {o['app_days_ready']};"
        f" not ready: {o['app_days_not_ready']})",
    ]
    for app, rows in o["by_app"].items():
        out.append(f"  {app}")
        out += [
            "  " + line
            for line in _table(
                [
                    [x["domain"], x["category"], x["conns"], x["bytes"], x["days"], x["why"]]
                    for x in rows
                    if "more" not in x
                ],
                ["domain", "category", "conns", "bytes", "days", "why"],
            )
        ]
        out += [f"    +{x['more']} more" for x in rows if "more" in x]
    if not o["by_app"]:
        out.append("  none")
    st = r["stacks"]
    out += ["", "stacks (a hello's JA4; purity: the share under its most common app)"]
    if st["available"]:
        out += _table(
            [[x["ja4"], x["hellos"], x["apps"], x["top_app"], x["purity"], x["verdict"]] for x in st["rows"]],
            ["ja4", "hellos", "apps", "top app", "purity", "verdict"],
        )
        rule, lo, gap = st["rule"], st["left_out"], st["gap"]
        out.append(
            f"  {st['stacks']} stacks; a stack names an app at purity {rule['purity']} over {rule['hellos']}"
            f" hellos; content hellos whose stack names the app in front: {_pct(st['agreement'])} of"
            f" {st['content_hellos']} ({st['content_hellos_named']} have a stack that names any app)"
        )
        out.append(
            f"  a viewing day left out: of {lo['hellos']} hellos the other days' stacks name an app for"
            f" {lo['named']} ({_pct(lo['named_share'])}), the app in front for {lo['right']}"
            f" ({_pct(lo['right_of_named'])} of those named)"
        )
        out.append(
            f"  in gaps: {gap['conns']} connections, {gap['with_a_stack']} with a stack; a stack names an app"
            f" for {gap['named']} ({_pct(gap['conns_share'])} of connections,"
            f" {_pct(gap['bytes_share'])} of bytes)"
        )
        out += [
            f"    {app}: {c['conns']} connections, {c['bytes']} bytes" for app, c in gap["by_app"].items()
        ]
        out.append("  another app's stack while an app was in front:")
        out += (
            _table(
                [[x["in_front"], x["software_of"], x["conns"], x["bytes"]] for x in st["other_software"]],
                ["in front", "stack of", "conns", "bytes"],
            )
            if st["other_software"]
            else ["    none"]
        )
    else:
        out.append("  the store's tls table holds no JA4 for hellos sent under an app in this window")
    return out
