"""(pause) `tvgw pause`: the shared tracker lists off for a few minutes, back on their own, then the names
they were stopping (design decision 79).

When an app breaks behind a Pi-hole or an AdGuard Home, its owner switches blocking off for five minutes
to learn whether the filter is the cause at all. `tvgw refused` names the likely cause from the refusals
of the last minutes, but it cannot say whether the app works without the lists. A pause can, and this one
lifts as little as possible: the profile's tracker lists (`Profile.tracking_filters()`: HaGeZi Pro and a
vendor's native list) go off for at most `MAX_MINUTES`; the profile's own blocks, the owner's and the
machine's rules, the must-allow exceptions, the URL filter's rewrites, the withheld record types, the list
of encrypted-DNS servers (`role = "bypass"`), every firewall wall and the TV's isolation stay as they are.

The pause is a row in the store's `meta` (`META_KEY`: start, planned end, minutes, the lists, and once it
is over when and how it ended). AdGuard changes only through the plan: `adguardcfg.desired()` reads the row
(`paused_urls()`) and renders the lists `enabled: false` while it is in force and on after its end, so any
apply after the end, a reboot's included, takes the pause away. It ends on its own two independent ways: a
transient systemd timer (`systemd-run --on-active`, unit `UNIT`) runs `tvgw pause --end --timer` at the end,
and the hourly check (`tvgw autoblock check`, which may change AdGuard already) ends a pause it finds past
its end (`fallback()`). A start that cannot set the timer pauses nothing. Every restart goes through
AdGuard's restart guard: with the upstreams down a start pauses nothing and exits 3, and an end is tried
again. Each start and end is an `owner_pause` line in the change ledger.

At the end it reads AdGuard's query log for the pause's window as `tvgw refused` reads it, asks AdGuard's
check_host, with the lists back, about the names the TV resolved (at most `ASKED`), keeps the ones a
paused list blocks again, and ranks them as `tvgw refused` ranks its refusals (`refused.judge()`), with the
fix for the first: the `tvgw allow` the owner runs himself, never one made for him.
"""

from __future__ import annotations

import contextlib
import dataclasses
import json
import math
import os
import shutil
import sqlite3
import subprocess
import time
from collections.abc import Callable
from dataclasses import dataclass, field

from tvgw import db
from tvgw.config import Settings
from tvgw.profile import BYPASS, HARMLESS_QTYPES, Profile, rule_target

META_KEY = "pause"  # the row in the store's meta table
DEFAULT_MINUTES = 10
MAX_MINUTES = 60  # a pause is a test, not a way to live without the lists
ASKED = 200  # distinct names the end asks AdGuard about, the likeliest first (`candidates()`)
UNIT = "tvgw-pause-end"  # the transient timer and service systemd-run makes for one pause
TVGW = "/usr/local/bin/tvgw"  # where the units find tvgw when PATH does not
LOCK_WAIT = 30.0  # seconds a start, and the owner's --end, wait for the hourly check or the analyst
# seconds the timer's end waits for the autonomy's lock before it ends the pause without it: an armed canary
# holds it for 11 minutes at most, and protection does not wait on a judgement for longer
END_WAIT = 900.0
# seconds the hourly check's end waits: its unit has 25 minutes in all, and an armed canary of its own may
# follow; it runs every hour, so a short wait loses little
FALLBACK_WAIT = 120.0
RETRY_EVERY = 300.0  # seconds between the timer's tries while AdGuard holds its restart back
RETRY_FOR = 7200.0  # how long the timer keeps trying; the hourly check tries every hour after that
EARLY_TIMER = 60.0  # a timer that fires this long before the end is not this pause's: it ends nothing
BUSY_TRIES = 6  # tries of an apply that finds AdGuard's own lock held, BUSY_PAUSE seconds apart
BUSY_PAUSE = 5.0
# exit statuses: done, refused or failed with nothing changed, AdGuard held its restart back (the
# upstreams are down, cli.DEFERRED_EXIT); (report) could not read the log or ask AdGuard
OK, REFUSED, DEFERRED = 0, 1, 3
NOTHING, NAMED, UNREAD = 0, 1, 2
# how a pause ended: its timer, the owner's --end, the hourly check, or at once for want of a timer
TIMER, EARLY, FALLBACK, UNTIMED = "timer", "early", "fallback", "untimed"
ENDED_BY = {
    TIMER: "by its timer",
    EARLY: "by sudo tvgw pause --end",
    FALLBACK: "by the hourly check, after its timer did not end it",
    UNTIMED: "at once, because the timer that would end it could not be set",
}
NOT_THE_CAUSE = (
    "The TV reached nothing the shared lists block during the pause, so they were not the cause:"
    " run sudo tvgw refused right after the app fails."
)


@dataclass(frozen=True)
class Pause:
    """One pause: when it began, when it ends, the lists it switched off as (name, url), and once it is
    over when and how it ended."""

    start: float
    end: float
    minutes: int
    lists: tuple[tuple[str, str], ...]
    ended: float | None = None
    how: str | None = None

    @property
    def urls(self) -> tuple[str, ...]:
        return tuple(url for _, url in self.lists)

    @property
    def names(self) -> tuple[str, ...]:
        return tuple(name for name, _ in self.lists)

    def in_force(self, now: float) -> bool:
        """Planned and not yet over: between its start and its end, and not ended early."""
        return self.ended is None and self.start <= now < self.end

    def overdue(self, now: float) -> bool:
        """Past its end and not yet recorded as over: its lists may still be off."""
        return self.ended is None and now >= self.end

    def as_json(self) -> str:
        return json.dumps(
            {
                "start": self.start,
                "end": self.end,
                "minutes": self.minutes,
                "lists": [list(x) for x in self.lists],
                "ended": self.ended,
                "how": self.how,
            },
            sort_keys=True,
        )

    @classmethod
    def from_json(cls, raw: str | None) -> Pause | None:
        """The row, or None for no row or one this version cannot read whole."""
        try:
            d = json.loads(raw or "null")
            if not isinstance(d, dict):
                return None
            lists = tuple((str(n), str(u)) for n, u in d["lists"])
            ended = None if d.get("ended") is None else float(d["ended"])
            how = d.get("how")
            p = cls(float(d["start"]), float(d["end"]), int(d["minutes"]), lists, ended, how)
        except (ValueError, TypeError, KeyError):
            return None
        stamps = [p.start, p.end, *([p.ended] if p.ended is not None else [])]
        if not all(math.isfinite(t) for t in stamps) or p.end < p.start:
            return None
        return p


@dataclass
class Outcome:
    """What a step did: the exit status, the lines it prints, and the pause it left, where there is one."""

    code: int
    lines: list[str] = field(default_factory=list)
    pause: Pause | None = None


# ---- the row -------------------------------------------------------------------------------------------
def read(db_path: str, timeout: float = 10.0) -> Pause | None:
    """The row, from a read-only connection; None with no store, no row or a row it cannot read. Every
    other failure to read (a store it may not open, one locked past `timeout`) raises sqlite3.Error."""
    if not os.path.exists(db_path):
        return None
    conn = db.connect(db_path, readonly=True, timeout=timeout)
    try:
        return Pause.from_json(db.get_meta(conn, META_KEY))
    except sqlite3.OperationalError as e:
        if "no such table" in str(e):  # a store no writer has given its schema yet
            return None
        raise
    finally:
        conn.close()


def _row(conn: sqlite3.Connection) -> Pause | None:
    return Pause.from_json(db.get_meta(conn, META_KEY))


def _put(conn: sqlite3.Connection, p: Pause | None) -> None:
    """The row as `p`, or no row; committed at once, so no write lock is held across an apply."""
    if p is None:
        conn.execute("DELETE FROM meta WHERE key = ?", (META_KEY,))
    else:
        db.set_meta(conn, META_KEY, p.as_json())
    conn.commit()


def paused_urls(prof: Profile, s: Settings, now: float | None = None) -> tuple[str, ...]:
    """The URLs of the profile's tracker lists a pause in force switches off, for `adguardcfg.desired()`;
    none when no pause is in force. A row that cannot be read is no pause: the lists stay on, the safe
    side, and `tvgw verify` then says a list is not in force."""
    try:
        p = read(s.db_path)
    except sqlite3.Error:
        return ()
    if p is None or not p.in_force(time.time() if now is None else now):
        return ()
    tracking = {url for _, url in prof.tracking_filters()}
    return tuple(u for u in p.urls if u in tracking)


# ---- what a pause lifts --------------------------------------------------------------------------------
def own_blocks(prof: Profile) -> bool:
    """Whether the profile's own rules block any name: on the general profile they do not, so its only
    name blocks are the shared lists, and a pause lifts every one of them."""
    return any(rule_target(r)[0] in ("block", "regex") for r in prof.custom_rules)


def _join(items: list[str] | tuple[str, ...]) -> str:
    items = list(items)
    return items[0] if len(items) == 1 else ", ".join(items[:-1]) + " and " + items[-1]


def describe(prof: Profile, s: Settings, minutes: int, now: float) -> list[str]:
    """What a pause of `minutes` lifts and what it keeps, in plain words, for the question before it."""
    from tvgw.refused import _times, clock

    off = [name for name, _ in prof.tracking_filters()]
    bypass = [name for name, url in prof.adguard_filters if prof.filter_role(url) == BYPASS]
    keep = ["the blocks of this TV's profile"] if own_blocks(prof) else []
    keep += [
        "your own rules, and the ones the gateway added on its own",
        "the names the TV must always reach",
    ]
    if prof.url_filter is not None:
        keep.append("the filter on the TV maker's file service")
    if prof.adguard_strip_qtypes:
        keep.append(f"the {_join(prof.adguard_strip_qtypes)} records the gateway withholds from the TV")
    if bypass:
        keep.append(f"the shared list of encrypted lookup services: {_join(bypass)}")
    walls = ["the TV's own encrypted lookups"]
    walls += ["QUIC"] if s.block_quic == "yes" else []
    walls += ["LG's ad ports"] if s.adtech_port_wall == "yes" and prof.name == "lg-webos" else []
    keep.append(f"every firewall wall: {_join(walls)} stay refused")
    keep.append("the TV's separation from your home network")
    out = [
        f"For {_times(minutes, 'minute')}, the gateway stops using these shared blocklists for the TV:"
        f" {_join(off)}.",
        "These stay in force:",
        *(f"  {line}" for line in keep),
    ]
    if own_blocks(prof):
        out.append("While the lists are off, the TV can reach the trackers that only they block.")
    else:
        out.append(
            "This TV's profile blocks no names of its own, so while the lists are off the TV can reach"
            " every tracker they know, its maker's included."
        )
    out.append(
        f"At {clock(now + minutes * 60, now)} the lists come back on their own, and the gateway then names"
        " what they would have stopped."
    )
    return out


# ---- the timer -----------------------------------------------------------------------------------------
def _systemctl(*args: str) -> subprocess.CompletedProcess:
    return subprocess.run(
        ["systemctl", *args], capture_output=True, text=True, encoding="utf-8", errors="replace", timeout=30
    )


def end_argv(conf: str | None = None, db_path: str | None = None) -> list[str]:
    """The command the timer runs: this tvgw, with the settings file and store it was started with."""
    exe = shutil.which("tvgw") or TVGW
    return [
        exe,
        *(["--conf", conf] if conf else []),
        *(["--db", db_path] if db_path else []),
        "pause",
        "--end",
        "--timer",
    ]


def arm(seconds: int, argv: list[str]) -> str | None:
    """A transient timer that runs `argv` once, `seconds` from now: None when systemd took it, else why
    not. A unit of the same name left from an earlier pause is stopped and cleared first; the pair is
    collected once it has run, failed or not, and lives in /run, so a reboot forgets it (the next apply
    and the hourly check end the pause then)."""
    with contextlib.suppress(OSError, subprocess.TimeoutExpired):
        _systemctl("stop", f"{UNIT}.timer")
        _systemctl("reset-failed", f"{UNIT}.timer", f"{UNIT}.service")
    cmd = [
        "systemd-run",
        f"--unit={UNIT}",
        "--description=tvgw: bring back the shared blocklists a pause switched off",
        f"--on-active={int(seconds)}",
        "--timer-property=AccuracySec=1s",
        "--collect",
        "--setenv=PYTHONUTF8=1",
        *argv,
    ]
    try:
        r = subprocess.run(
            cmd, capture_output=True, text=True, encoding="utf-8", errors="replace", timeout=30
        )
    except (OSError, subprocess.TimeoutExpired) as e:
        return str(e)
    return None if r.returncode == 0 else (r.stderr or r.stdout).strip()[-300:] or f"exit {r.returncode}"


def disarm() -> None:
    """Stop the pause's timer; one that is not there is not an error."""
    with contextlib.suppress(OSError, subprocess.TimeoutExpired):
        _systemctl("stop", f"{UNIT}.timer")


def armed() -> bool | None:
    """Whether the pause's timer is waiting: True, False, or None when systemd could not be asked."""
    try:
        r = _systemctl("show", "-P", "ActiveState", f"{UNIT}.timer")
    except (OSError, subprocess.TimeoutExpired):
        return None
    state = r.stdout.strip()
    return None if r.returncode != 0 or not state else state == "active"


# ---- the lock and the apply ----------------------------------------------------------------------------
def _locked(
    s: Settings,
    verb: str,
    wait: float,
    sleep: Callable[[float], None],
    body: Callable[[], Outcome],
    proceed: bool,
) -> Outcome:
    """`body` under the autonomy's lock (`autoblock.exclusive`), as `tvgw allow` takes it, waiting up to
    `wait` seconds for the hourly check or the analyst. Past the wait a start is refused; an end, which
    puts protection back, goes ahead without the lock and says so (`proceed`)."""
    from tvgw import autoblock

    deadline = time.monotonic() + wait
    while True:
        with autoblock.exclusive(s.state_dir) as free:
            if free:
                return body()
        if time.monotonic() >= deadline:
            break
        sleep(1.0)
    if not proceed:
        return Outcome(
            REFUSED,
            [
                f"tvgw pause{verb}: the gateway's hourly check or the analyst is changing rules right now;"
                " nothing changed; run it again in a few minutes"
            ],
        )
    done = body()
    note = (
        f"tvgw pause{verb}: the hourly check or the analyst was still at work, so the lists came back"
        " without waiting for it"
    )
    return dataclasses.replace(done, lines=[note, *done.lines]) if done.code == OK else done


def _apply(apply_fn: Callable[[tuple[str, ...]], object], paused: tuple[str, ...], sleep) -> None:
    """One apply, tried again while another apply holds AdGuard's own lock (adguardcfg.Busy)."""
    from tvgw import adguardcfg

    for n in range(BUSY_TRIES):
        try:
            apply_fn(paused)
            return
        except adguardcfg.Busy:
            if n == BUSY_TRIES - 1:
                raise
            sleep(BUSY_PAUSE)


def _default_apply(s: Settings, prof: Profile) -> Callable[[tuple[str, ...]], object]:
    def apply(paused: tuple[str, ...]) -> object:
        from tvgw import analyst  # the apply every rule change goes through: lint, guard, readiness

        return analyst.adguardcfg_apply(s, prof, paused)

    return apply


def _spool(s: Settings, fields: list[str], t: float) -> None:
    from tvgw import ledger

    with contextlib.suppress(OSError):  # (ledger) one spool line; a failed write never undoes the change
        ledger.append_spool(ledger.spool_path(s), ["owner", "pause", *fields], t)


# ---- starting -------------------------------------------------------------------------------------------
def refusal(prof: Profile, p: Pause | None, now: float) -> Outcome | None:
    """Why a pause cannot start now, or None: the profile has no tracker list to switch off, a pause is
    in force (with its end), or one is past its end and not yet over."""
    from tvgw.refused import clock

    if not prof.tracking_filters():
        return Outcome(
            REFUSED, ["tvgw pause: this TV's profile subscribes to no shared tracker list; nothing to pause"]
        )
    if p is not None and p.in_force(now):
        return Outcome(
            REFUSED,
            [
                f"tvgw pause: the shared blocklists are already paused until {clock(p.end, now)}; nothing"
                " changed. sudo tvgw pause --end brings them back now."
            ],
        )
    if p is not None and p.overdue(now):
        return Outcome(
            REFUSED,
            [
                f"tvgw pause: the pause that should have ended at {clock(p.end, now)} is still in force;"
                " nothing changed. Run sudo tvgw pause --end first."
            ],
        )
    return None


def start(
    s: Settings,
    prof: Profile,
    minutes: int,
    argv: list[str] | None = None,
    apply_fn: Callable[[tuple[str, ...]], object] | None = None,
    arm_fn: Callable[[int, list[str]], str | None] = arm,
    disarm_fn: Callable[[], None] = disarm,
    clock: Callable[[], float] = time.time,
    sleep: Callable[[float], None] = time.sleep,
    wait: float = LOCK_WAIT,
) -> Outcome:
    """`sudo tvgw pause [MINUTES]` once the owner said yes: under the autonomy's lock, set the timer that
    ends it, write the row, apply. A refused or deferred apply puts the row back and stops the timer, so
    nothing is paused; a timer that cannot be set pauses nothing at all."""
    from tvgw import adguardcfg
    from tvgw.refused import clock as hhmm

    if not 1 <= minutes <= MAX_MINUTES:
        raise ValueError(f"a pause is 1 to {MAX_MINUTES} minutes")
    apply_fn = apply_fn or _default_apply(s, prof)

    def body() -> Outcome:
        conn = db.connect(s.db_path)
        try:
            before = _row(conn)
            now = clock()
            refused = refusal(prof, before, now)
            if refused is not None:
                return refused
            p = Pause(now, now + minutes * 60, minutes, prof.tracking_filters())
            why = arm_fn(minutes * 60, argv or end_argv())
            if why is not None:
                return Outcome(
                    REFUSED,
                    [
                        "tvgw pause: the gateway could not set the timer that ends a pause, so it paused"
                        f" nothing ({why})"
                    ],
                )
            _put(conn, p)
            try:
                _apply(apply_fn, p.urls, sleep)
            except adguardcfg.Deferred as e:
                _put(conn, before)
                disarm_fn()
                return Outcome(DEFERRED, [f"tvgw pause: {e}; nothing was paused"])
            except (RuntimeError, OSError, ValueError) as e:
                _put(conn, before)
                disarm_fn()
                return Outcome(
                    REFUSED, [f"tvgw pause: AdGuard Home did not take the change ({e}); nothing was paused"]
                )
        finally:
            conn.close()
        _spool(s, ["start", str(minutes), f"{p.end:.0f}"], p.start)
        until = hhmm(p.end, p.start)
        return Outcome(
            OK,
            [
                f"tvgw pause: the shared blocklists are off until {until} ({_join(p.names)}). Try the app"
                " now.",
                f"tvgw pause: they come back on their own at {until}; sudo tvgw pause --end brings them back"
                " sooner. Then the gateway names what they would have stopped (sudo tvgw pause --report).",
            ],
            p,
        )

    return _locked(s, "", wait, sleep, body, proceed=False)


# ---- ending ---------------------------------------------------------------------------------------------
def _minutes(p: Pause, ended: float) -> int:
    return max(1, round((ended - p.start) / 60))


def end(
    s: Settings,
    prof: Profile,
    how: str,
    apply_fn: Callable[[tuple[str, ...]], object] | None = None,
    disarm_fn: Callable[[], None] = disarm,
    clock: Callable[[], float] = time.time,
    sleep: Callable[[float], None] = time.sleep,
    wait: float = LOCK_WAIT,
) -> Outcome:
    """Bring the lists back: under the autonomy's lock (or past `wait` without it), mark the row ended,
    apply with no list paused, and record the end. A refused or deferred apply leaves the pause in force,
    to be tried again by the timer or the hourly check. With no pause in force there is nothing to do."""
    from tvgw import adguardcfg
    from tvgw.refused import clock as hhmm

    apply_fn = apply_fn or _default_apply(s, prof)
    verb = " --end"

    def body() -> Outcome:
        conn = db.connect(s.db_path)
        try:
            p = _row(conn)
            now = clock()
            if p is None or p.ended is not None:
                return Outcome(OK, [f"tvgw pause{verb}: no pause is in force; nothing changed"], p)
            if how == TIMER and now < p.end - EARLY_TIMER:
                return Outcome(
                    OK,
                    [f"tvgw pause{verb}: this pause ends at {hhmm(p.end, now)}, not now; nothing changed"],
                    p,
                )
            _put(conn, dataclasses.replace(p, ended=now, how=how))  # every other apply renders no pause now
            try:
                _apply(apply_fn, (), sleep)
            except adguardcfg.Deferred as e:
                _put(conn, p)
                return Outcome(
                    DEFERRED, [f"tvgw pause{verb}: {e}; the shared blocklists stay off for now"], p
                )
            except (RuntimeError, OSError, ValueError) as e:
                _put(conn, p)
                return Outcome(
                    REFUSED,
                    [
                        f"tvgw pause{verb}: AdGuard Home did not take the change ({e}); the shared blocklists"
                        " stay off for now"
                    ],
                    p,
                )
            done = dataclasses.replace(p, ended=clock(), how=how)  # the lists are back from here on
            _put(conn, done)
        finally:
            conn.close()
        if how != TIMER:  # the timer that fired needs no stopping
            disarm_fn()
        minutes = _minutes(done, done.ended)
        _spool(s, ["end", str(minutes), how], done.ended)
        start_at, end_at = hhmm(done.start, done.ended), hhmm(done.ended, done.ended)
        return Outcome(
            OK,
            [
                f"tvgw pause{verb}: the shared blocklists are back on: paused {minutes} minute"
                f"{'s' if minutes != 1 else ''}, from {start_at} to {end_at}, ended {ENDED_BY[how]}"
            ],
            done,
        )

    return _locked(s, verb, wait, sleep, body, proceed=True)


def end_by_timer(
    s: Settings,
    prof: Profile,
    say: Callable[[str], None],
    clock: Callable[[], float] = time.time,
    sleep: Callable[[float], None] = time.sleep,
    **kw,
) -> Outcome:
    """The timer's end: `end()` with TIMER, waiting END_WAIT for the lock, tried again every RETRY_EVERY
    seconds for RETRY_FOR while AdGuard holds its restart back or does not take the change. Each failed
    try is said as it happens (the unit's journal)."""
    deadline = clock() + RETRY_FOR
    wait = kw.pop("wait", END_WAIT)
    while True:
        done = end(s, prof, TIMER, clock=clock, sleep=sleep, wait=wait, **kw)
        if done.code == OK or clock() + RETRY_EVERY > deadline:
            return done
        for line in done.lines:
            say(line)
        say(f"tvgw pause --end: trying again in {RETRY_EVERY / 60:.0f} minutes")
        sleep(RETRY_EVERY)


def fallback(s: Settings, prof: Profile, clock: Callable[[], float] = time.time, **kw) -> Outcome | None:
    """The second way back, run by the hourly check: end a pause past its end that nothing has ended (its
    timer lost to a reboot, failed, or still waiting on an upstream outage). None when there is none,
    which is every run but those."""
    try:
        p = read(s.db_path)
    except sqlite3.Error:
        return None  # the end's own read would fail the same way; the timer and the next hour remain
    if p is None or not p.overdue(clock()):
        return None
    kw.setdefault("wait", FALLBACK_WAIT)
    return end(s, prof, FALLBACK, clock=clock, **kw)


# ---- status ---------------------------------------------------------------------------------------------
def status(s: Settings, now: float | None = None, timer: Callable[[], bool | None] | None = None) -> Outcome:
    """`tvgw pause --status`: whether a pause is in force and until when, the last one otherwise. Needs
    read access to the store only (adm). Exit 1 for a pause past its end whose lists may still be off,
    or a store it cannot read."""
    from tvgw.refused import _times, clock

    now = time.time() if now is None else now
    try:
        p = read(s.db_path)
    except sqlite3.Error as e:
        return Outcome(REFUSED, [f"tvgw pause: cannot read the gateway's record ({e}); run it with sudo"])
    if p is not None and p.in_force(now):
        left = max(1, math.ceil((p.end - now) / 60))
        lines = [
            f"The shared blocklists are paused until {clock(p.end, now)}, {_times(left, 'minute')} from now:"
            f" {_join(p.names)}.",
            "They come back on their own then; sudo tvgw pause --end brings them back now.",
        ]
        state = (timer or armed)()
        if state is True:
            lines.append("The timer that ends the pause is set.")
        elif state is False:
            lines.append("The timer that ends the pause is not set: the hourly check ends it after its end.")
        return Outcome(OK, lines, p)
    if p is not None and p.overdue(now):
        return Outcome(
            REFUSED,
            [
                f"The pause of the shared blocklists should have ended at {clock(p.end, now)}, and it is not"
                " over yet: sudo tvgw pause --end ends it now; otherwise the hourly check does."
            ],
            p,
        )
    lines = ["No pause is in force: the shared blocklists are on."]
    if p is not None and p.ended is not None:
        minutes = _minutes(p, p.ended)
        lines.append(
            f"The last pause: {minutes} minute{'s' if minutes != 1 else ''}, from {clock(p.start, now)} to"
            f" {clock(p.ended, now)}, ended {ENDED_BY.get(p.how or '', 'early')}. sudo tvgw pause --report"
            " names what the lists would have stopped."
        )
    return Outcome(OK, lines, p)


def diff_note(prof: Profile, s: Settings, now: float | None = None) -> str | None:
    """(adguard) The line `tvgw adguard diff` prints about a pause: one in force, which the plan renders,
    so its lists are no drift; or one past its end and not over, whose lists show as drift."""
    from tvgw.refused import clock

    now = time.time() if now is None else now
    try:
        p = read(s.db_path)
    except sqlite3.Error:
        return None
    if p is not None and p.in_force(now):
        return (
            f"A pause is in force until {clock(p.end, now)}: the shared blocklists {_join(p.names)} are off"
            " until then, as planned (sudo tvgw pause --status)."
        )
    if p is not None and p.overdue(now):
        return (
            f"The pause of the shared blocklists should have ended at {clock(p.end, now)} and is not over:"
            " sudo tvgw pause --end ends it now."
        )
    return None


# ---- the answer at the end ------------------------------------------------------------------------------
def candidates(window: list, before: list, limit: int = ASKED) -> tuple[list[str], int]:
    """(the names to ask AdGuard about, how many more were left out) from the TV's lookups during the
    pause: public names answered with no rule at all, the way a name only a list blocks is answered while
    the list is off (an exception's or a rewrite's answer carries its rule). Names the log does not show
    answered before the pause come first, then the most looked up, then the earliest, then by name."""
    from tvgw.names import is_public_name

    looked: dict[str, list[float]] = {}
    for r in window:
        if r.blocked or r.rule is not None or r.reason != "NotFilteredNotFound":
            continue
        if r.qtype.upper() in HARMLESS_QTYPES or not is_public_name(r.qname):
            continue
        looked.setdefault(r.qname, []).append(r.t)
    answered = {b.qname for b in before if not b.blocked and b.rule is None}
    order = sorted(looked, key=lambda n: (n in answered, -len(looked[n]), min(looked[n]), n))
    return order[:limit], max(0, len(order) - limit)


def report(
    s: Settings,
    prof: Profile,
    p: Pause,
    now: float | None = None,
    ask: Callable[[str, bool], str] | None = None,
    check: Callable[..., dict] | None = None,
    page: Callable[..., dict] | None = None,
    admin: str | None = None,
) -> Outcome:
    """The names the TV resolved during `p` that a list it paused blocks again now, ranked as `tvgw
    refused` ranks its refusals, with the fix for the first; or that there were none. `ask` prompts for
    AdGuard's password when tvgw keeps none; `check` stands in for `aghinstall.check_host()`, `page` for
    `aghinstall.querylog()`, `admin` for the credentials file. Nothing is written."""
    import yaml

    from tvgw import adguardcfg, aghinstall, refused

    now = time.time() if now is None else now
    until = p.ended if p.ended is not None else now
    try:
        cfg = adguardcfg.load_yaml(s.adguard_yaml)
    except (OSError, yaml.YAMLError) as e:
        return Outcome(UNREAD, [f"tvgw pause: cannot read {s.adguard_yaml}: {e}"], p)
    try:
        groups = adguardcfg.rule_groups(prof, s)
    except OSError as e:
        return Outcome(UNREAD, [f"tvgw pause: cannot read the rules tvgw plans: {e}"], p)
    conn, newest, _oldest, _why = refused._store(s.db_path)
    try:
        return _report(s, prof, p, now, until, cfg, groups, conn, newest, ask, check, page, admin)
    except aghinstall.AskError as e:  # check_host stopped answering part way: no half a ranking
        return Outcome(
            UNREAD,
            [
                f"tvgw pause: AdGuard Home stopped answering about the names ({e}); run sudo tvgw pause"
                " --report in a minute"
            ],
            p,
        )
    finally:
        if conn is not None:
            conn.close()


def _report(s, prof, p, now, until, cfg, groups, conn, newest, ask, check, page, admin) -> Outcome:
    from tvgw import adguard, aghinstall, namecheck, refused
    from tvgw.refused import _times, clock

    span = f"from {clock(p.start, now)} to {clock(until, now)}"
    notes: list[str] = []
    path = aghinstall.querylog_path(cfg, s)
    # back to the store's newest lookup, so "before" has no gap, as `tvgw refused` reads it
    read_from = min(p.start, newest) if newest is not None else 0.0
    records: list = []
    try:
        records, reached = adguard.records_since(path, read_from, s.tv_ip)
        if not reached and not (records and records[0].t <= p.start):
            notes.append(
                "The query log could not be read back to the start of the pause: its oldest part is missing."
            )
    except OSError as e:
        notes.append(f"AdGuard Home's query log file could not be read ({e.strerror or e}).")
    try:
        user, password = aghinstall.credentials(cfg, admin=admin or aghinstall.ADMIN_FILE, ask=ask)
    except aghinstall.AskError as e:
        window = [r for r in records if p.start <= r.t < until]
        names, _ = candidates(window, [])
        if not names:
            return _words(p, now, until, window, [], notes)
        return Outcome(
            UNREAD,
            [
                f"tvgw pause: the TV looked up {_times(len(names), 'name')} during the pause, {span}, but"
                f" AdGuard Home could not be asked which of them the lists block ({e}).",
                "To see them, run this at a terminal, which asks for AdGuard Home's password and keeps it"
                " nowhere: sudo tvgw pause --report",
            ],
            p,
        )
    base = aghinstall.page_base(cfg)
    api: list = []
    with contextlib.suppress(aghinstall.AskError):  # the file holds what the page would add, but its newest

        def ask_page(older: str) -> dict:
            return (page or aghinstall.querylog)(
                base, user, password, client=s.tv_ip, older_than=older, limit=refused.API_LIMIT
            )

        api, _ = refused.api_records(ask_page, p.start, s.tv_ip)
    merged = {refused._key(r): r for r in records if r.t >= p.start}
    merged.update({refused._key(r): r for r in api})
    window = sorted((r for r in merged.values() if r.t < until), key=lambda r: r.t)
    before = [r for r in records if r.t < p.start]
    names, left_out = candidates(window, before)
    lists = namecheck.list_names(cfg, prof)
    paused_ids = {
        f.get("id")
        for f in cfg.get("filters") or []
        if isinstance(f, dict) and f.get("url") in set(p.urls) and isinstance(f.get("id"), int)
    }
    blocks: dict[str, tuple[str | None, int | None]] = {}
    one = check or aghinstall.check_host
    for name in names:
        answer = one(base, name, s.tv_ip, user, password)  # an AskError ends the report (report())
        rule, fid = namecheck.first_rule(answer)
        if str(answer.get("reason") or "") in namecheck.BLOCK_REASONS and fid in paused_ids:
            blocks[name] = (rule, fid)
    if left_out:
        notes.append(
            f"{left_out:,} more name{'s' if left_out != 1 else ''} the TV looked up during the pause"
            f" {'was' if left_out == 1 else 'were'} not asked about: at most {ASKED} are."
        )
    synth = [
        dataclasses.replace(
            r, blocked=True, reason="FilteredBlockList", rule=blocks[r.qname][0], filter_id=blocks[r.qname][1]
        )
        for r in window
        if r.qname in blocks and not r.blocked and r.rule is None and r.qtype.upper() not in HARMLESS_QTYPES
    ]
    try:
        ranked, _hidden, _masked = refused.judge(synth, before, prof, s, groups, lists, conn, p.start)
    except sqlite3.Error:
        ranked, _hidden, _masked = refused.judge(synth, before, prof, s, groups, lists, None, p.start)
    return _words(p, now, until, window, ranked, notes, lists)


def _words(p, now, until, window, ranked, notes, lists=None) -> Outcome:
    """The report's lines from the ranked names."""
    from tvgw.refused import _times, clock

    span = f"from {clock(p.start, now)} to {clock(until, now)}"
    out: list[str] = []
    if not ranked:
        if not window:
            out.append(
                f"The TV looked up nothing during the pause, {span}: it may have been off, so the pause"
                " cannot say whether the shared lists were the cause."
            )
        else:
            out.append(NOT_THE_CAUSE)
        out += [f"Note: {n}" for n in notes]
        return Outcome(NOTHING, out, p)
    many = len(ranked) != 1
    out.append(
        f"During the pause, {span}, the TV reached {len(ranked):,} name{'s' if many else ''} the shared"
        f" blocklists block again now{', the likeliest cause first' if many else ''}:"
    )
    for n in ranked:
        where = (lists or {}).get(n.filter_id, "a shared list")
        tracker = ", a known tracker" if n.tracking else ""
        company = f" Company: {n.company}." if n.company else ""
        out.append(f"  {n.name}, looked up {_times(n.lookups)}: {where}{tracker}. Kind: {n.kind}.{company}")
    top = ranked[0]
    where = (lists or {}).get(top.filter_id, "a shared list")
    out.append(f"If the app worked during the pause, the likely cause is {top.name} ({where}): {top.fix}")
    if top.tracking:
        out.append(
            "  It is a known tracker, and an app rarely stops for want of one: check before you allow it."
        )
    out.append(
        "If the app failed during the pause too, the shared lists were not the cause: run sudo tvgw refused"
        " right after it fails."
    )
    out += [f"Note: {n}" for n in notes]
    return Outcome(NAMED, out, p)


def last_report(s: Settings, prof: Profile, now: float | None = None, **kw) -> Outcome:
    """`tvgw pause --report`: the report of the last pause that is over, computed again from the query log
    and AdGuard's answers now; a pause in force has none yet."""
    from tvgw.refused import clock

    now = time.time() if now is None else now
    try:
        p = read(s.db_path)
    except sqlite3.Error as e:
        return Outcome(UNREAD, [f"tvgw pause: cannot read the gateway's record ({e})"])
    if p is None:
        return Outcome(NOTHING, ["tvgw pause: there has been no pause yet; nothing to report"])
    if p.ended is None:
        when = f"until {clock(p.end, now)}" if p.in_force(now) else "past its end"
        return Outcome(NOTHING, [f"tvgw pause: a pause is in force {when}; its report comes when it ends"], p)
    return report(s, prof, p, now, **kw)
