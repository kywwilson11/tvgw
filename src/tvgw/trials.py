"""(trials) The trial record: a keyed coin for each viewing day, committed before the day begins, and what
each app start showed, with nothing refused (design decision 98).

A wall on trial would be on for some viewing days and off for the others by a coin, so that what it costs
is measured against the same household's other days, not argued from a before and an after (the owner's
Q7). This is the first stage of that design: with `TRIAL=record` the hourly ingest draws the coins and
measures the days, and nothing reads a coin to refuse anything. The record says whether a trial can work
on this TV: how often an ordinary app start fails with nothing refused, how many starts a day there are to
judge, and whether the trial's own tests stay quiet when nothing was refused (`aa`).

**The coin.** For each subject and viewing day (05:00 to 05:00 local, `appfront.viewing_day`), the arm is
an HMAC-SHA256 of the day's number under the subject's own subkey, read as a share of 2^64. Today the one
subject is `ALL`, every app start, the subject a wall on trial would have. The key is 32 random bytes in
`trial.key` in the name-key directory, root-only and made once as the uplink tag's key is: `tvgw backup`
never copies it and `tvgw forget` deletes it. Nothing the TV or an app does enters the hash, and the day
is the clock's, so an app that starts itself again cannot draw again.

**Committed before the day.** Each hourly run draws the next viewing day once, before it begins: a `drawn`
row in `decisions` holds the day, a commitment (an HMAC of the day under the subkey, 16 hex characters)
and the key's fingerprint, and no arm. A day that has begun is never drawn, so a gateway that was off at
05:00 leaves that day unmeasured. `decisions` is append-only: a row cannot be changed once the day is seen.

**Measured once it settles.** When a day's end is `receipt.SETTLE` behind, so that its last connection is
in the record, the next run writes one `measured` row: the arm, and what the day's app starts showed. A
start is an app stay the TV itself reported beginning, to the second (the live reading); the TV maker's
own apps are left out (`didit.SYSTEM_APPS`). Two forms of a bad start are kept side by side: `didit`'s,
back at the home screen within `didit.STALL_MAX` with under `didit.LITTLE_DOWN` down (`bad`), and a wider
one, left within LEFT_WITHIN for anything but standby with under BIG down (`bad_any`). Each form counts
the day's starts up to and including its first bad one (`analysed`), since a trial would act on that one,
and the rule is the same whatever the arm. A day the ingest did not cover whole, or warned of lost
lookups or connections, or drawn under another key, is `unmeasured`, with why.

**Kept.** One row a subject and day: a day number, the arm, counts and two medians; no time of day, no
app, no name. The rows are kept as `DECISIONS_DAYS` says and deleted by `tvgw forget`, and the analyst's
pack reads none of them.

Nothing here can refuse: the module reads the store, writes `decisions` rows and its key, and calls
nothing that writes AdGuard, the firewall or the TV.
"""

from __future__ import annotations

import hashlib
import hmac
import itertools
import json
import math
import os
import random
import sqlite3
import statistics
from dataclasses import dataclass
from datetime import datetime, timedelta

from tvgw import appfront, autoblock, didit, evidencekit, minimize, receipt
from tvgw.config import Settings

STAGE = "trial"  # the decisions rows' stage
ALL = "all"  # the subject whose exposure is every app start: the one a wall on trial would have
SUBJECTS = (ALL,)  # what is drawn for; a name of its own is a later stage's
UNIT = "day"  # the unit a coin is drawn for: the viewing day
SHARE = 0.5  # the share of days the coin puts in the arm a trial would refuse on
KEY_FILE = "trial.key"
KEY_BYTES = 32
COIN = b"tvgw-trial-coin-v1"
BIG = 1024 * 1024  # bytes: a connection that brings this much down is the app working
LEFT_WITHIN = 600.0  # seconds: the wider bad start left the app this soon, with under BIG down
STRIKES, CONTROL_WEIGHT = 3, 2  # the harm rule: bad days refused, less twice those not, reach STRIKES
BALANCE_P = 0.005  # each tail of the balance alarm: exposed days this lopsided between the arms
BAR = 1 / 20  # the rate a wall's trial must rule out (Q7)
FIRST_LOOK = 0.02  # the error a trial's first planned look may spend
INGEST_GAP = 2 * 3600.0 + 600  # seconds between two ingest runs that leave part of a day unread
# warnings that the record lost lookups, connections or the live record; a capture's (pcaps:) names only
# which name a connection had, which the subject `all` does not read, and its deferrals lose nothing
LOSSES = ("flows:", "dns:", "tvlive:")


# ---- the key and the coin ---------------------------------------------------------------------------------
def key_path(state_dir: str) -> str:
    return os.path.join(minimize.key_dir(state_dir), KEY_FILE)


def key(s: Settings) -> bytes | None:
    """The trial key: read, or made once, KEY_BYTES random bytes root-only in the name-key directory
    (0700), as `ledger.wan_salt` makes its own. None when it cannot be read or made (not root): no coin is
    then drawn, and never an unkeyed one. A short file is one whose making was cut off before it was
    ever used (a key is used only once written whole), so it is made again."""
    path = key_path(s.state_dir)
    try:
        with open(path, "rb") as fh:
            k = fh.read()
        if len(k) == KEY_BYTES:
            return k
        os.remove(path)
    except FileNotFoundError:
        pass
    except OSError:
        return None
    try:
        os.makedirs(os.path.dirname(path), mode=0o700, exist_ok=True)
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    except FileExistsError:
        return key(s)  # another run made it first
    except OSError:
        return None
    k = os.urandom(KEY_BYTES)
    try:
        os.write(fd, k)
        os.fsync(fd)
    finally:
        os.close(fd)
    return k


def _subkey(k: bytes, subject: str) -> bytes:
    """Each subject's own key: showing it after a trial lets anyone redraw that trial's coins and check
    its commitments, and opens no other subject's."""
    return hmac.digest(k, subject.encode(), "sha256")


def _arm(subkey: bytes, day: int, share: float) -> bool:
    return (
        int.from_bytes(hmac.digest(subkey, COIN + b"\0" + str(day).encode(), "sha256")[:8], "big")
        < share * 2**64
    )


def coin(k: bytes, subject: str, day: int, share: float = SHARE) -> bool:
    """True: the arm a trial would refuse on, for `subject` on viewing day `day`. The same key, subject and
    day always give the same arm, so a run again cannot draw again."""
    return _arm(_subkey(k, subject), day, share)


def commitment(k: bytes, subject: str, day: int) -> str:
    """What may be written before the day without giving its arm away: only the key opens it."""
    return hmac.digest(_subkey(k, subject), b"commit\0" + str(day).encode(), "sha256").hex()[:16]


def fingerprint(k: bytes) -> str:
    """Four hex characters that tell one key from another: a day drawn under a key since replaced (a
    store restored beside a new key) is never measured under the new one."""
    return hashlib.sha256(b"tvgw-trial-key\0" + k).hexdigest()[:4]


def day_start(day: int) -> float:
    """When viewing day `day` begins: 05:00 local on its date (`appfront.viewing_day`'s inverse)."""
    return (datetime.fromordinal(day) + timedelta(hours=appfront.DAY_START_HOUR)).timestamp()


# ---- what a day's app starts showed ------------------------------------------------------------------------
@dataclass(frozen=True)
class Stay:
    """One app stay the TV reported beginning, to the second: the unit measured. Memory only."""

    start: float
    seconds: float
    down: int  # bytes down on the connections that began while it was in front
    delay: float | None  # seconds to the first connection that brought BIG down; None: none did
    bad: bool  # didit's failed start
    bad_any: bool  # the wider form
    worked: bool  # in front didit.SHORT or longer, with didit.LITTLE_DOWN down


def stays(conn: sqlite3.Connection, gw_ip: str, a: float, b: float, now: float) -> list[Stay]:
    """The settled app stays that began in [a, b) and that the TV reported beginning, in time order."""
    back = a - didit.LIVE_LOOKBACK
    tl = appfront.timeline(appfront.stored_events(conn, back, b), appfront.readings(conn, back, b), back, b)
    starting = {x.start: x for x in tl.sessions if x.timed == appfront.LIVE}
    down: dict[int, int] = {}
    first: dict[int, float] = {}
    for c in appfront.connections(conn, a, b, gw_ip):
        x = tl.at(c.t)[1]
        if x is None:
            continue
        down[id(x)] = down.get(id(x), 0) + c.down
        if c.down >= BIG and id(x) not in first:
            first[id(x)] = max(0.0, c.t - x.start)
    out = []
    for x in tl.sessions:
        reported = x.timed == appfront.LIVE and x.began == "app" and x.start_exact
        if not reported or x.kind != appfront.APP or x.app in didit.SYSTEM_APPS or not a <= x.start < b:
            continue
        if now - x.end < receipt.SETTLE:
            continue
        got = down.get(id(x), 0)
        left = x.end_exact and x.end_why == "app"  # to another app, an input or the home screen
        nxt = starting.get(x.end)
        home = left and nxt is not None and nxt.kind == appfront.HOME
        out.append(
            Stay(
                x.start,
                x.seconds,
                got,
                first.get(id(x)),
                bad=home and x.seconds < didit.STALL_MAX and got < didit.LITTLE_DOWN,
                bad_any=left and x.seconds < LEFT_WITHIN and got < BIG,
                worked=x.seconds >= didit.SHORT and got >= didit.LITTLE_DOWN,
            )
        )
    return out


def _censored(flags: list[bool]) -> tuple[int, int]:
    """(analysed, bad): the starts up to and including the first bad one, and whether there was one."""
    first = next((i for i, f in enumerate(flags) if f), None)
    return (len(flags), 0) if first is None else (first + 1, 1)


def measure(day: list[Stay]) -> dict:
    """A day's counts from its stays, in time order: no time of day, no app."""
    analysed, bad = _censored([x.bad for x in day])
    analysed_any, bad_any = _censored([x.bad_any for x in day])
    delays = [x.delay for x in day if x.delay is not None]
    return {
        "exposed": len(day),
        "analysed": analysed,
        "bad": bad,
        "analysed_any": analysed_any,
        "bad_any": bad_any,
        "bad_all": sum(x.bad for x in day),
        "worked": sum(x.worked for x in day),
        "no_big": len(day) - len(delays),
        "delay_med": round(statistics.median(delays), 1) if delays else None,
        "stay_med": round(statistics.median(x.seconds for x in day) / 60, 1) if day else None,
    }


def _reader(conn: sqlite3.Connection, a: float, b: float) -> str:
    """Which record the day had: the live reading, only the hourly readings, or none."""
    if conn.execute("SELECT 1 FROM tv_events WHERE t >= ? AND t < ? LIMIT 1", (a, b)).fetchone():
        return "live"
    if conn.execute("SELECT 1 FROM tvstate WHERE t >= ? AND t < ? LIMIT 1", (a, b)).fetchone():
        return "hourly"
    return "none"


def _not_whole(conn: sqlite3.Connection, a: float, b: float, now: float) -> str | None:
    """Why the record of [a, b) cannot be measured, or None: an hourly ingest missed for INGEST_GAP, or a
    run that fed it warned that lookups or connections were lost."""
    runs = conn.execute(
        "SELECT t, warnings FROM ingest_runs WHERE t >= ? AND t < ? ORDER BY t", (a - INGEST_GAP, now)
    ).fetchall()
    times = [t for t, _ in runs] + [now]
    if times[0] > a or any(t1 - t0 > INGEST_GAP for t0, t1 in itertools.pairwise(times) if t0 < b):
        return "the ingest missed part of it"
    for t, raw in runs:
        try:
            warnings = json.loads(raw or "[]")
        except ValueError:
            warnings = []
        if t >= a and t < b + receipt.SETTLE and any(str(w).startswith(LOSSES) for w in warnings):
            return "the record lost lookups or connections"
    return None


# ---- the hourly run ----------------------------------------------------------------------------------------
def hourly(conn: sqlite3.Connection, s: Settings, now: float) -> dict:
    """With `TRIAL=record`, at the end of each hourly ingest: draw the next viewing day for each subject
    that has none, and measure each drawn day that has settled; a day with no coin drawn before it began
    is unmeasured. A second run adds nothing. Returns what it wrote."""
    k = key(s)
    if k is None:
        return {"waiting": "the trial key could not be read or made"}
    today = appfront.viewing_day(now)
    rows = autoblock.decisions(conn, "stage = ?", (STAGE,))
    drawn = {(r["name"], r["margins"]["day"]): r["margins"] for r in rows if r["outcome"] == "drawn"}
    done = {(r["name"], r["margins"]["day"]) for r in rows if r["outcome"] in ("measured", "unmeasured")}
    out = {"drawn": 0, "measured": 0, "unmeasured": 0}
    for subject in SUBJECTS:
        days = sorted(d for sub, d in drawn if sub == subject)
        for day in range(days[0], today) if days else ():
            a, b = day_start(day), day_start(day + 1)
            if (subject, day) in done or now < b + receipt.SETTLE:
                continue
            margins = drawn.get((subject, day))
            if margins is None:
                why = "no coin was drawn before it began"
            elif margins.get("key") != fingerprint(k) or margins.get("commit") != commitment(k, subject, day):
                why = "key changed"
            else:
                why = _not_whole(conn, a, b, now)
            if why:
                autoblock.log_decision(
                    conn, STAGE, "unmeasured", now, name=subject, margins={"day": day, "why": why}
                )
                out["unmeasured"] += 1
                continue
            got = {"day": day, "arm": int(coin(k, subject, day)), "reader": _reader(conn, a, b)}
            got |= measure(stays(conn, s.gw_ip, a, b, now))
            autoblock.log_decision(conn, STAGE, "measured", now, name=subject, margins=got)
            out["measured"] += 1
        if (subject, today + 1) not in drawn:
            margins = {
                "day": today + 1, "unit": UNIT, "share": SHARE,
                "commit": commitment(k, subject, today + 1), "key": fingerprint(k),
            }  # fmt: skip
            autoblock.log_decision(conn, STAGE, "drawn", now, name=subject, margins=margins)
            out["drawn"] += 1
    return out


# ---- the record, read alone -------------------------------------------------------------------------------
@dataclass(frozen=True)
class Day:
    subject: str
    day: int
    arm: int
    reader: str
    exposed: int
    analysed: int
    bad: int
    analysed_any: int
    bad_any: int
    bad_all: int
    worked: int
    no_big: int
    delay_med: float | None
    stay_med: float | None


def record(conn: sqlite3.Connection, subject: str = ALL) -> list[Day]:
    """The measured days of `subject`, in day order, from the `decisions` rows alone."""
    fields = Day.__dataclass_fields__
    days = {
        r["margins"]["day"]: Day(subject, **{f: r["margins"].get(f) for f in fields if f != "subject"})
        for r in autoblock.decisions(
            conn, "stage = ? AND outcome = 'measured' AND name = ?", (STAGE, subject)
        )
    }
    return [days[d] for d in sorted(days)]


def counts(conn: sqlite3.Connection, subject: str = ALL) -> dict[str, int]:
    """How many days `subject` has drawn, measured and left unmeasured, and why each was."""
    out: dict[str, int] = {}
    for r in autoblock.decisions(conn, "stage = ? AND name = ?", (STAGE, subject)):
        key_ = r["outcome"] if r["outcome"] != "unmeasured" else f"unmeasured: {r['margins'].get('why')}"
        out[key_] = out.get(key_, 0) + 1
    return out


def harm(days: list[Day], arms: list[bool]) -> bool:
    """The trial's sequential harm rule, read day by day: bad days on the refused arm, less CONTROL_WEIGHT
    times those on the other, reach STRIKES. Under "refusing changes nothing" each bad day's arm is a fair
    coin, whatever the baseline, so the rule has a stated error (Wald's bound: under 24%)."""
    k1 = k0 = 0
    for d, refused in zip(days, arms, strict=True):
        k1 += refused and d.bad
        k0 += not refused and d.bad
        if k1 - CONTROL_WEIGHT * k0 >= STRIKES:
            return True
    return False


def unbalanced(days: list[Day], arms: list[bool]) -> bool:
    """The balance alarm: the days with a start fell on one arm far more than a fair coin gives."""
    n1 = sum(1 for d, refused in zip(days, arms, strict=True) if d.exposed and refused)
    n = sum(1 for d in days if d.exposed)
    tails = (evidencekit.binom_tail(n1, n, SHARE), evidencekit.binom_tail(n - n1, n, 1 - SHARE))
    return bool(n) and min(tails) <= BALANCE_P


def aa(days: list[Day], keys: int = 1000, seed: int = 0) -> dict:
    """The record judged as a trial would judge it, under `keys` other keys: nothing was refused, so each
    key is one more draw from "refusing changes nothing", and the rule's firing rate under them is its real
    false-alarm rate on this TV. With the baseline rates a trial's length rests on."""
    rng = random.Random(seed)
    fired = alarms = 0
    for _ in range(keys):
        k = rng.randbytes(KEY_BYTES)
        subkeys = {subject: _subkey(k, subject) for subject in {d.subject for d in days}}
        arms = [_arm(subkeys[d.subject], d.day, SHARE) for d in days]
        fired += harm(days, arms)
        alarms += unbalanced(days, arms)
    exposed = [d for d in days if d.exposed]

    def per_start(bad: str, analysed: str) -> dict:
        k = sum(getattr(d, bad) for d in exposed)
        n = sum(getattr(d, analysed) for d in exposed)
        by_day = {
            str(d.day): [1.0] * getattr(d, bad) + [0.0] * (getattr(d, analysed) - getattr(d, bad))
            for d in exposed
        }
        # resampled a day at a time, as the failures of one evening share it; none bounds only by its count
        lo, hi = evidencekit.day_block_bootstrap(by_day, seed=seed) if k else evidencekit.wilson(0, n)
        return {"bad": k, "of": n, "share": k / n if n else None, "interval": [lo, hi]}

    bad_all = sum(d.bad_all for d in exposed)
    return {
        "days": len(days),
        "exposed_days": len(exposed),
        "starts": sum(d.exposed for d in days),
        "per_start": per_start("bad", "analysed"),
        "per_start_any": per_start("bad_any", "analysed_any"),
        "per_day": {
            "bad": sum(d.bad for d in exposed),
            "of": len(exposed),
            "interval": list(evidencekit.wilson(sum(d.bad for d in exposed), len(exposed))),
        },
        "clustered": (bad_all - sum(d.bad for d in exposed)) / bad_all if bad_all else None,
        "keys": keys,
        "harm_rule_fired": fired / keys if keys else None,
        "balance_alarm": alarms / keys if keys else None,
    }


def forecast(days: list[Day], bar: float = BAR) -> dict:
    """How long a wall's trial would take at this record's rate: refused starts with no bad one that rule
    out `bar` at evidencekit.CONF, and at the trial's first planned look, and the days each takes when half
    the days are refused."""
    need = math.ceil(math.log(1 - evidencekit.CONF) / math.log(1 - bar))
    first = math.ceil(math.log(FIRST_LOOK) / math.log(1 - bar))
    rate = sum(d.exposed for d in days) / len(days) * SHARE if days else 0.0
    return {
        "bar": bar,
        "refused_starts": need,
        "first_look": first,
        "refused_starts_a_day": rate,
        "days": math.ceil(need / rate) if rate else None,
        "days_to_first_look": math.ceil(first / rate) if rate else None,
    }


# ---- the words ---------------------------------------------------------------------------------------------
def _pct(x: float | None) -> str:
    return "none to tell" if x is None else f"{x:.1%}"


def status_lines(conn: sqlite3.Connection, setting: str, subject: str = ALL) -> list[str]:
    """`tvgw trial`: what is drawn and measured, what the record says so far, and how long a wall's trial
    would take at its rate. Never the arm of a day: a measured day's arm is in the record, and only `tvgw
    trial aa` reads it, as one of a thousand draws."""
    recording = setting == "record"
    head = (
        "The trial record (TRIAL=record): a coin for each viewing day, drawn before it begins. Nothing is"
        " refused."
        if recording
        else "The trial record is off (TRIAL=record starts it). Nothing is refused."
    )
    n = counts(conn, subject)
    if not n:
        return [head, "No day has been drawn yet." if recording else "Nothing has been recorded."]
    days = record(conn, subject)
    unmeasured = {k.split(": ", 1)[1]: v for k, v in n.items() if k.startswith("unmeasured: ")}
    gaps = "; ".join(f"{why}: {v}" for why, v in sorted(unmeasured.items()))
    missed = f", not measured {sum(unmeasured.values())} ({gaps})" if gaps else ""
    lines = [head, f"Days drawn {n.get('drawn', 0)}, measured {len(days)}{missed}."]
    if days:
        starts, on = sum(d.exposed for d in days), sum(1 for d in days if d.exposed)
        failed, failed_on, wider = (sum(getattr(d, f) for d in days) for f in ("bad_all", "bad", "bad_any"))
        lines.append(
            f"App starts the TV reported: {starts} on {on} of {len(days)} days. Failed, back at the home"
            f" screen: {failed}, on {failed_on} days; left within {LEFT_WITHIN / 60:.0f} minutes with little"
            f" down: on {wider} days."
        )
        f = forecast(days)
        took = (
            f"about {f['days']} days ({f['days_to_first_look']}) at this rate"
            if f["days"]
            else "no start yet"
        )
        lines.append(
            f"A wall's trial at 1 in {round(1 / f['bar'])} needs {f['refused_starts']} refused starts, none"
            f" failed ({f['first_look']} at its first planned look): {took}."
        )
    lines.append("sudo tvgw trial aa: the record judged as a trial would judge it, under 1,000 other keys.")
    return lines


def aa_lines(r: dict) -> list[str]:
    """`tvgw trial aa`: the baseline and the false alarms of the trial's tests, nothing refused."""

    def rate(x: dict) -> str:
        lo, hi = x["interval"]
        return f"{x['bad']} of {x['of']} ({_pct(x['share'])}, {100 * lo:.1f} to {100 * hi:.1f})"

    wider = f"left within {LEFT_WITHIN / 60:.0f} minutes"
    return [
        f"tvgw trial aa: {r['days']} days measured, {r['exposed_days']} with an app start;"
        f" {r['starts']} starts",
        f"failed starts (back at the home screen), per start analysed: {rate(r['per_start'])}",
        f"the wider form ({wider}), per start analysed: {rate(r['per_start_any'])}",
        f"days with a failed start: {r['per_day']['bad']} of {r['per_day']['of']}"
        f" ({100 * r['per_day']['interval'][0]:.1f} to {100 * r['per_day']['interval'][1]:.1f})",
        f"failed starts on a day that already had one: {_pct(r['clustered'])}",
        f"under {r['keys']:,} other keys, nothing refused: the harm rule fired {_pct(r['harm_rule_fired'])}"
        f" (its bound: under 24%), the balance alarm {_pct(r['balance_alarm'])} (nominal 1%)",
    ]
