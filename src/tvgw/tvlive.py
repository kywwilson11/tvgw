"""The live reading: one read-only session to an LG TV, held only while the TV is on (design decision 67).

The hourly reading says which app is in front once an hour. This service hears it at the moment it
changes: it registers with the stored key, subscribes to the power state and the foreground app, and
writes each change as one JSON line with the gateway's time (`<STATE_DIR>/tvlive-events.log`, which the
hourly ingest loads into `tv_events`). It is off unless `LIVE_READING=on`, and exists for the LG profile.

It only reads. It never pairs, never opens the input socket, never subscribes to channels or programmes,
never sends a setting or Wake-on-LAN, and never holds a second connection. The WebSocket client is
`tvgw tvprobe`'s own (lgwebos._WebSocket: a frame over 1 MiB closes the session; a close frame goes out
before the socket is dropped).

LG locks a TV out after too many pairing requests, and the lock clears only by unplugging the TV. The
service's whole design is the list of things that must be true before it opens one connection
(`Discipline.why_not`), each of which sends nothing when it does not hold:

- **A key the TV takes.** The key file holds a key for the TV and the key store records no refusal, read
  again before every attempt. A refusal seen here is written to the record the hourly reading obeys, so
  one refusal stops both, and only `tvgw tv pair` starts either again.
- **Evidence that the TV is on**, newer than the last attempt: the TV port received at least
  `EVIDENCE_BYTES` from the TV inside `EVIDENCE_SECONDS` (the kernel's counter, read every `TICK`
  seconds; the bytes are counted from after the last attempt ended, so an attempt's own replies are
  never evidence), or an hourly reading newer than the last attempt found the TV awake. The carrier is
  not evidence: on the reference CX the link stays up while the TV is off. A carrier that reads down
  forbids an attempt, and that is its only use. With neither source there is no attempt: no timer ever
  tries blind.
  After `TRAFFIC_TRUSTED` failures in a row the port's traffic no longer counts, only a reading does:
  a TV whose traffic says on while its API does not answer is tried once an hour at most. A port that
  has been silent for `QUIET_RESET` seconds ends that count (the TV went off, and its next evening is
  tried on the first traffic again); the count that makes the service give up is not ended by silence.
- **The back-off has run.** `BACKOFF` after each failure in a row, `MIN_GAP` after anything, and
  `STANDBY_HOLD` after the TV said it was switching off. The count of failures goes back to zero only
  after a session that stayed up `STABLE` seconds, so a TV that accepts and then hangs keeps climbing.
- **The hour has room.** Every attempt by anything in tvgw is appended to one small file before the
  connect (`Ledger`: this service, and the hourly reading's two connections). The service attempts only
  while the last `HOUR` holds fewer than `SERVICE_LIMIT` attempts by anyone. The file survives a restart,
  so a crash loop cannot escape the count; the process also counts its own attempts by the steady clock,
  so setting the gateway's clock forward cannot empty the hour; and when the file cannot be read or
  written the service attempts nothing. The hourly reading is counted and never refused: it carries the
  Live Plus and Wi-Fi red lines.
- **The hourly reading is not at work.** No attempt within `YIELD` seconds of one of its attempts.
- **It has not stood down.** When an hourly reading fails to reach a TV this service is holding a
  session to, two sessions on one key do not get along on this TV: the service drops its session, leaves
  a marker and attempts nothing until the owner runs `tvgw tvlive --resume`. It stands down the same way
  when the TV refuses a subscription, and after `GIVE_UP` failures in a row.

A session ends when the TV says it is switching off (the service closes it itself: nobody has measured
whether a held session delays this TV's standby), when the TV stops answering pings, or when the service
is stopped. A lost session is written as lost, never as "the TV went off".

If this service dies, hangs or is not there, nothing the TV needs notices: the receipt uses the hourly
readings for the time it did not cover, and says so. Every wait has a limit, the loop tells systemd's
watchdog that it turns (`heartbeat`), and a loop that stops is killed and started again after a minute.
"""

from __future__ import annotations

import asyncio
import contextlib
import fcntl
import json
import math
import os
import signal
import socket
import tempfile
import time
from collections import deque
from collections.abc import Awaitable, Callable
from dataclasses import dataclass, field
from datetime import datetime

from tvgw import appfront, lgkeys, lgwebos, queries

PROFILE = "lg-webos"  # the one profile whose TV this service reads
EVENTS_FILE = "tvlive-events.log"
ATTEMPTS_FILE = "tvlive-attempts"
STOOD_DOWN_FILE = "tvlive-stood-down"
PROGRESS_FILE = "tvlive-progress"  # the give-up counts, so a crash loop or a restart buys no fresh knocks
HOUR = 3600.0
CEILING = 8  # attempts an hour by this service and the hourly reading together, at most
RESERVED = 2  # of them kept for the hourly reading, which opens two connections a reading
SERVICE_LIMIT = (
    CEILING - RESERVED
)  # the service attempts only while the hour holds fewer than this, by anyone
BACKOFF = (15.0, 30.0, 60.0, 120.0, 300.0, 600.0, 900.0)  # seconds after the n-th failure in a row
MIN_GAP = 15.0  # seconds between two attempts, whatever happened
STABLE = 600.0  # a session up this long clears the failures before it
STANDBY_HOLD = 120.0  # seconds without an attempt after the TV said it was switching off
YIELD = 120.0  # seconds without an attempt after an attempt by the hourly reading
EVIDENCE_BYTES = 8_000  # bytes from the TV ...
EVIDENCE_SECONDS = 30.0  # ... inside this long: the TV is probably on
READING_FRESH = 4200.0  # an hourly reading older than this says nothing about now
TRAFFIC_TRUSTED = 3  # after this many failures in a row, traffic alone is no longer evidence
PROMPT_LIMIT = 3  # a prompt may have shown this many times: stand down and leave the :20 reading to settle it
CONFLICT_LIMIT = 2  # an hourly reading failed during a held session this many times: stand down
FLOOD_PER_MINUTE = 120  # the TV may change power or app at most this often before a session is a flood
BOOT_GUARD = 75.0  # seconds to wait after the first traffic from a TV that had been off: webOS is slow then
QUEUE_MAX = 256  # frames the reader may buffer before it waits: a TV cannot make the Pi hold more
GIVE_UP = (
    12  # after this many failures with no session that held, the service stands down until the owner says
)
QUIET_RESET = 600.0  # the port silent this long: the TV went off, and its next evening starts from zero
TICK = 2.0  # seconds between two looks at the counter while there is no session
KEY_RECHECK = 60.0  # seconds between two looks at the key store while there is nothing to do
CONNECT_TIMEOUT = 5.0
IO_TIMEOUT = 15.0  # the registration's answer, and each subscription's
PING = 30.0
PONG_TIMEOUT = 10.0
ALIVE_EVERY = 600.0  # one `alive` line this often while the session answers its pings
CLOCK_STEP = 2.0  # the wall clock and the monotonic clock apart by this much: the clock was set
CONFLICT_AFTER = 60.0  # a reading this long into a session that found no TV: the two do not get along
SERVICE, HOURLY = "live", "hourly"
# how a session ended
FAILED, LOST, STANDBY, REFUSED, STOPPED, CONFLICT, UNSUPPORTED, PROMPTED, FLOOD = (
    "failed",
    "lost",
    "standby",
    "refused",
    "stopped",
    "conflict",
    "unsupported",
    "prompted",
    "flood",
)
FAILURE_OUTCOMES = frozenset(
    {FAILED, LOST, STANDBY, PROMPTED, CONFLICT, FLOOD}
)  # count toward back-off and give-up


def state_path(key_file: str, name: str) -> str:
    """A file of this service's, beside the key file (the state directory)."""
    return os.path.join(os.path.dirname(os.path.abspath(key_file)), name)


# ---- the attempts of the last hour -------------------------------------------------------------------
class Ledger:
    """Every connection attempt at the TV, one line each (`<epoch> <who>`), appended before the connect.
    A line is one `write` of a few bytes under an exclusive lock, so two writers never mix, and reads
    take a shared lock, so none reads the file mid-rewrite. The file is cut back to the last hour on
    every write, so it never grows into a record of when the TV was on; a line nobody can read counts
    as an attempt made now (so a damaged file can only make the service more careful) and is dropped at
    the next write."""

    def __init__(self, path: str, hour: float = HOUR):
        self.path, self.hour = path, hour

    @staticmethod
    def _parse(data: bytes, now: float) -> list[tuple[float, str, bool]]:
        out = []
        for line in data.decode("utf-8", "replace").splitlines():
            if not line.strip():
                continue
            stamp, _, who = line.strip().partition(" ")
            try:
                t, ok = float(stamp), True
            except ValueError:
                t, ok = now, False
            if not math.isfinite(t):  # float() accepts nan and inf; they are not a time
                t, ok = now, False
            # a line ahead of the clock (it was set back) or unparseable counts as made now, so a stale
            # clock never lets an attempt slip; a line far in the past is simply old. Either is an
            # artifact (ok False) and is dropped at the next write; a recent line is kept
            if not ok or t > now + HOUR:
                t, ok = now, False
            elif t < now - HOUR:
                ok = False
            out.append((t, who or "?", ok))
        return out

    def _read(self, now: float) -> list[tuple[float, str, bool]]:
        fd = os.open(self.path, os.O_RDONLY)
        try:
            fcntl.flock(fd, fcntl.LOCK_SH)  # not while a write is rewriting the file
            data = os.read(fd, 1 << 20)
        finally:
            os.close(fd)
        return self._parse(data, now)

    def recent(self, now: float) -> list[tuple[float, str]]:
        """(t, who) of the attempts inside the last hour. Raises OSError when the file cannot be read:
        the caller then attempts nothing."""
        return [(t, who) for t, who, _ in self._read(now) if now - t < self.hour]

    def note(self, who: str, now: float) -> None:
        """Record an attempt about to be made, then cut the file to the last hour so it never becomes a
        record of when the TV was on. Raises OSError when it cannot be written."""
        fd = os.open(self.path, os.O_RDWR | os.O_CREAT, 0o600)
        try:
            fcntl.flock(fd, fcntl.LOCK_EX)
            kept = [
                (t, w) for t, w, ok in self._parse(os.read(fd, 1 << 20), now) if ok and now - t < self.hour
            ]
            kept.append((now, who))
            body = "".join(f"{t:.3f} {w}\n" for t, w in kept).encode()
            os.ftruncate(fd, 0)
            os.pwrite(fd, body, 0)
            os.fsync(fd)
        finally:
            os.close(fd)  # and with it the lock

    def create(self) -> None:
        """Make the file, 0600: from then on the hourly reading counts its attempts in it too."""
        os.close(os.open(self.path, os.O_WRONLY | os.O_APPEND | os.O_CREAT, 0o600))


def note_attempt(key_file: str, who: str = HOURLY, now: float | None = None) -> None:
    """Count one connection attempt by another part of tvgw (the hourly reading) in the service's ledger,
    when the service has ever run here: the file is made by the service alone, so a gateway that never
    turned the live reading on writes nothing. Never raises: the reading must not fail on its bookkeeping."""
    path = state_path(key_file, ATTEMPTS_FILE)
    if not os.path.isfile(path):
        return
    with contextlib.suppress(OSError):
        Ledger(path).note(who, time.time() if now is None else now)


# ---- evidence from the TV port -----------------------------------------------------------------------
class Traffic:
    """The bytes the gateway received from the TV, as the kernel counts them, kept for the last
    `seconds`. `seen()` is true once the counter has moved by `need` inside that long since `reset()`."""

    def __init__(self, need: int = EVIDENCE_BYTES, seconds: float = EVIDENCE_SECONDS):
        self.need, self.seconds = need, seconds
        self.samples: deque[tuple[float, int]] = deque()
        self.readable = False

    def sample(self, now: float, rx: int | None) -> None:
        self.readable = rx is not None
        if rx is None or (
            self.samples and rx < self.samples[-1][1]
        ):  # unreadable, or the counter began again
            self.samples.clear()
            if rx is None:
                return
        self.samples.append((now, rx))
        while len(self.samples) > 1 and now - self.samples[1][0] >= self.seconds:
            self.samples.popleft()  # keep one sample at or before the window's start

    def reset(self, now: float, rx: int | None) -> None:
        """Start counting again from here: what the port carried up to now is not evidence."""
        self.samples.clear()
        self.sample(now, rx)

    def seen(self, now: float) -> bool:
        if len(self.samples) < 2:
            return False
        (t0, rx0), (t1, rx1) = self.samples[0], self.samples[-1]
        # the newest sample is recent, the oldest kept is the window's start (not a sample from before a
        # long pause in the sampling), and the counter moved enough between them
        return now - t1 <= self.seconds and t1 - t0 <= 2 * self.seconds and rx1 - rx0 >= self.need


# ---- the rules ---------------------------------------------------------------------------------------
@dataclass
class Rules:
    """The constants as one value, so a test can run an hour in a second."""

    hour: float = HOUR
    limit: int = SERVICE_LIMIT
    backoff: tuple[float, ...] = BACKOFF
    min_gap: float = MIN_GAP
    stable: float = STABLE
    standby_hold: float = STANDBY_HOLD
    yield_s: float = YIELD
    reading_fresh: float = READING_FRESH
    traffic_trusted: int = TRAFFIC_TRUSTED
    give_up: int = GIVE_UP
    quiet_reset: float = QUIET_RESET
    tick: float = TICK
    key_recheck: float = KEY_RECHECK
    connect_timeout: float = CONNECT_TIMEOUT
    io_timeout: float = IO_TIMEOUT
    register_grace: float = lgwebos.PROBE_REGISTER_GRACE
    ping: float = PING
    pong_timeout: float = PONG_TIMEOUT
    alive_every: float = ALIVE_EVERY
    clock_step: float = CLOCK_STEP
    conflict_after: float = CONFLICT_AFTER
    prompt_limit: int = PROMPT_LIMIT
    conflict_limit: int = CONFLICT_LIMIT
    flood_per_minute: int = FLOOD_PER_MINUTE
    boot_guard: float = BOOT_GUARD


@dataclass
class Seen:
    """What the service knows at one moment, before it decides whether to try."""

    now: float
    key: bool  # the key file holds a key for the TV
    refused: bool  # the key store records a refusal
    stood_down: str | None  # the marker's reason
    carrier: bool | None
    traffic: bool  # the port's counter moved enough since the last attempt
    reading: tuple[float, str] | None  # the newest hourly reading: (t, power)
    mono: float = 0.0  # the steady clock, which no one can set
    quiet: float = 0.0  # seconds since the port's traffic last was evidence


class Discipline:
    """Whether the service may open a connection now, and what each attempt's end does to the next."""

    def __init__(self, ledger: Ledger, rules: Rules | None = None):
        self.ledger, self.rules = ledger, rules or Rules()
        self.failures = (
            0  # in a row, in this stretch of traffic: what the back-off and the trust in traffic count
        )
        self.unanswered = 0  # since the last session that held, whatever lay between: what giving up counts
        self.prompted = 0  # prompts whose outcome was unknown: a few of these and the daemon stands down
        self.conflicts = (
            0  # hourly readings that failed during a held session: two and the daemon stands down
        )
        self.last_end: float | None = None  # when the last attempt, or the session it became, ended
        self.hold_until = 0.0
        self.attempts = 0
        self.own: deque[float] = deque()  # this process's attempts by the steady clock
        self.asleep = False  # the port has been quiet long enough that the TV went off
        self.woke_at: float | None = None  # when its traffic first came back: the boot guard counts from here

    def snapshot(self) -> dict:
        """The counts that must outlive a restart (a crash loop must not buy fresh knocks)."""
        return {"unanswered": self.unanswered, "prompted": self.prompted, "conflicts": self.conflicts}

    def restore(self, saved: dict) -> None:
        for key in ("unanswered", "prompted", "conflicts"):
            value = saved.get(key)
            if isinstance(value, int) and 0 <= value < 10_000:
                setattr(self, key, value)

    def why_not(self, s: Seen) -> str | None:
        """None when every condition holds; otherwise the first one that does not, in a few words."""
        r = self.rules
        if s.quiet >= r.quiet_reset:
            # the TV has been silent long enough to have gone off: what failed before it did says
            # nothing about its next evening, which is tried on the first sign of traffic again. The
            # give-up count (unanswered, prompted, conflicts) is not forgiven by silence
            self.failures = 0
            self.asleep, self.woke_at = True, None
        elif self.asleep and s.traffic:
            self.asleep, self.woke_at = False, s.now  # its traffic came back: the boot guard starts now
        if s.stood_down is not None:
            return f"stood down: {s.stood_down}"
        if not s.key:
            return "not paired"
        if s.refused:
            return "the TV refused the key"
        if s.carrier is False:
            return "no link on the TV port"
        fresh = (
            s.reading is not None
            and s.reading[1] in queries.AWAKE
            and 0 <= s.now - s.reading[0] <= r.reading_fresh
            and (self.last_end is None or s.reading[0] > self.last_end)
        )
        if not fresh and not (s.traffic and self.failures < r.traffic_trusted):
            # after a few failures in a row the port's traffic has been wrong about the TV's API that
            # often: only a reading that reached the TV counts then, which is one attempt an hour at most
            return "no sign that the TV is on"
        if self.woke_at is not None and s.now - self.woke_at < r.boot_guard:
            # the TV's traffic just came back after it was off: webOS answers its API slowly while it
            # boots, and a registration then is the one most likely to leave a prompt on the screen
            return "waiting for the TV to finish waking"
        if self.last_end is not None:
            wait = max(r.min_gap, r.backoff[min(self.failures, len(r.backoff)) - 1] if self.failures else 0.0)
            if s.now - self.last_end < wait:
                return "backing off"
        if s.now < self.hold_until:
            return "holding off after the TV switched off"
        try:
            recent = self.ledger.recent(s.now)
        except OSError:
            return "the attempts file cannot be read"
        while self.own and s.mono - self.own[0] >= r.hour:
            self.own.popleft()
        # by the file, which survives a restart, and by the steady clock, which survives the clock being
        # set: whichever counts more
        if max(len(recent), len(self.own)) >= r.limit:
            return "the hour's attempts are used"
        if any(who != SERVICE and s.now - t < r.yield_s for t, who in recent):
            return "the hourly reading is at work"
        return None

    def begin(self, now: float, mono: float = 0.0) -> bool:
        """Count the attempt about to be made. False, and no attempt, when it cannot be written down."""
        try:
            self.ledger.note(SERVICE, now)
        except OSError:
            return False
        self.own.append(mono)
        self.attempts += 1
        return True

    def end(self, now: float, outcome: str, up_seconds: float) -> None:
        self.last_end = now
        if outcome == STANDBY:
            self.hold_until = now + self.rules.standby_hold
        if up_seconds >= self.rules.stable:
            # a session that genuinely held is the one thing that forgives the counts: not a TV that
            # takes the connection and says off, nor one that holds a minute and drops
            self.failures = self.unanswered = self.prompted = self.conflicts = 0
        elif outcome in FAILURE_OUTCOMES:
            self.failures += 1
            self.unanswered += 1
            self.prompted += outcome == PROMPTED
            self.conflicts += outcome == CONFLICT


# ---- the events file ---------------------------------------------------------------------------------
class EventLog:
    """The service's JSON lines: root-only, one line per event with the gateway's time, written at once."""

    def __init__(self, path: str, clock: Callable[[], float] = time.time):
        self.clock = clock
        fd = os.open(path, os.O_WRONLY | os.O_APPEND | os.O_CREAT, 0o600)
        self.fh = open(fd, "a", encoding="utf-8", buffering=1)  # noqa: SIM115 - closed by close()

    def write(self, kind: str, **fields) -> None:
        line = json.dumps({"t": round(self.clock(), 3), "kind": kind, **fields}, sort_keys=True, default=str)
        self.fh.write(line[:2000] + "\n")

    def close(self) -> None:
        self.fh.close()


# ---- one session -------------------------------------------------------------------------------------
@dataclass
class Env:
    """Everything outside the process, one callable each, so the tests pass a fake TV and a fake clock."""

    connect: Callable[[], Awaitable[object]]  # the socket, TLS and upgrade done, or an exception
    key: Callable[[], Awaitable[str | None]]  # the stored key for the TV, None when there is none
    record: Callable[[], lgkeys.Pairing | None]  # tvgw's row for the key: its manifest, a refusal
    manifest: Callable[[str], dict]
    refuse: Callable[[str], None]  # write a refusal where the hourly reading obeys it
    rx_bytes: Callable[[], int | None]
    carrier: Callable[[], bool | None]
    reading: Callable[[], tuple[float, str] | None]
    stood_down: Callable[[], str | None]
    stand_down: Callable[[str], None]
    clock: Callable[[], float] = time.time
    mono: Callable[[], float] = time.monotonic
    sleep: Callable[[float], Awaitable[None]] = asyncio.sleep
    stopping: Callable[[], bool] = lambda: False
    beat: Callable[[], None] = lambda: None  # tell the service manager the loop still turns
    load_progress: Callable[[], dict] = dict  # the give-up counts from before a restart
    save_progress: Callable[[dict], None] = lambda d: None  # persist them, so a crash loop buys no knocks
    session: Callable[..., Awaitable[tuple[str, float]]] | None = None  # held(); a test's stand-in


@dataclass
class _State:
    power: tuple[str, str] | None = None
    app: str | None = None
    off: bool = False
    acked: set = field(default_factory=set)


def _safe(fn: Callable, *args) -> bool:
    """Call `fn`, swallowing an error: a write to the key store or a marker that fails (a locked or
    read-only disk) must never crash the daemon. True when it ran, False when it raised."""
    try:
        fn(*args)
    except Exception:
        return False
    return True


def rules_queue_max(rules: Rules) -> int:
    return QUEUE_MAX


async def held(env: Env, rules: Rules, log: EventLog, key: str, manifest: dict) -> tuple[str, float]:
    """One attempt and, when the TV takes it, one session: (how it ended, seconds it was up). Every wait
    has a limit. The events go to `log` as they come; a failed attempt is one `session.fail` line."""
    try:
        ws = await asyncio.wait_for(env.connect(), 2 * rules.connect_timeout + 1)  # the connect, the upgrade
    except Exception as e:  # refused, unreachable, timed out, not a WebSocket: the TV is not there
        log.write("session.fail", error=type(e).__name__)
        return FAILED, 0.0
    reader: asyncio.Task | None = None
    up_at: float | None = None
    outcome = LOST
    try:
        register = {"forcePairing": False, "pairingType": "PROMPT", "client-key": key, "manifest": manifest}
        await ws.send_text(json.dumps({"type": "register", "id": "register_0", "payload": register}))
        pc = lgwebos.ProbeConfig(host="", register_grace=rules.register_grace)
        await asyncio.wait_for(lgwebos._registered(ws, pc), rules.io_timeout)
        up_at = env.mono()
        log.write("session.up")
        subs = {"power": lgwebos.POWER_URI, "app": lgwebos.APP_URI}
        for sid, uri in subs.items():
            await ws.send_text(json.dumps({"id": sid, "type": "subscribe", "uri": uri}))
        queue: asyncio.Queue = asyncio.Queue(maxsize=rules_queue_max(rules))

        async def read_all() -> None:
            try:
                while True:
                    await queue.put(await ws.recv())
            except Exception as e:  # handed to the loop below, which raises it there
                await queue.put(e)

        reader = asyncio.create_task(read_all())
        outcome = await _listen(env, rules, log, ws, queue, subs, up_at)
        if outcome != LOST:
            log.write("session.down", why=outcome)
    except lgwebos.PairingRejected as e:
        if not e.explicit:
            # a prompt may have shown, but the TV did not deny the key: never touch the shared key store,
            # which would stop the hourly reading; the daemon stands itself down after a few of these
            log.write("session.fail", error="prompted")
            return PROMPTED, 0.0
        why = lgwebos.clean(str(e))[:120]
        if not _safe(env.refuse, why):  # the key store could not be written: do not knock again blind
            log.write("session.fail", error="refusal-unwritten")
            return PROMPTED, 0.0
        log.write("watch.refused", why=why)
        return REFUSED, 0.0
    except Exception as e:  # a socket error, a timeout, a frame too big, a close from the TV
        if up_at is None:
            log.write("session.fail", error=type(e).__name__)
            return FAILED, 0.0
        log.write("session.down", why=type(e).__name__)
        outcome = LOST
    finally:
        if reader is not None:
            reader.cancel()
            with contextlib.suppress(BaseException):
                await reader
        await ws.close(1000)
    return outcome, env.mono() - up_at


async def _listen(env: Env, rules: Rules, log: EventLog, ws, queue, subs: dict, up_at: float) -> str:
    """The session's loop: messages, pings, the gateway's clock, the hourly reading's word. Returns how
    it ended when it ended by this side's choice; raises when the TV or the socket ended it."""
    st = _State()
    up_wall = env.clock()
    sent, pongs, waiting = env.mono(), ws.pongs, None
    last_alive = env.mono()
    events, minute_at = 0, env.mono()  # the TV's power and app changes, capped per minute
    offset = env.clock() - env.mono()  # how far the wall clock is ahead of the steady one
    restate_at: float | None = None
    while True:
        if env.stopping():
            return STOPPED
        env.beat()
        now = env.mono()
        due = (waiting + rules.pong_timeout) if waiting is not None else (sent + rules.ping)
        try:
            item = await asyncio.wait_for(queue.get(), max(0.02, min(1.0, due - now)))
        except TimeoutError:
            item = None
        if isinstance(item, BaseException):
            raise item
        if item is not None:
            events += 1
            verdict = _message(item, subs, st, log)
            if verdict is not None:
                return verdict
        now = env.mono()
        if now - minute_at >= 60:
            events, minute_at = 0, now
        elif events > rules.flood_per_minute:  # a TV cannot flood the Pi's disk through this session
            return FLOOD
        # the gateway's clock was set: say so, and say the TV's state again once the doubled seconds pass
        drift = (env.clock() - now) - offset
        if abs(drift) >= rules.clock_step:
            offset += drift
            log.write("clock", step=round(drift, 3))
            restate_at = env.clock() + max(0.0, -drift)
        if restate_at is not None and env.clock() >= restate_at:
            restate_at = None
            if st.power is not None:
                log.write("power", state=st.power[0], **({"processing": st.power[1]} if st.power[1] else {}))
            if st.app is not None:
                log.write("app", appId=st.app or None)
        if ws.pongs != pongs:
            pongs, waiting = ws.pongs, None
            if now - last_alive >= rules.alive_every:
                last_alive = now
                log.write("alive")
            # the hourly reading found no TV while this session held one: end the session and back off; the
            # daemon stands down only on a second such reading (one unreachable can be a transient read)
            found = env.reading()
            if (
                found is not None
                and found[1] == "unreachable"
                and found[0] >= up_wall + rules.conflict_after
                and env.clock() - found[0] <= rules.reading_fresh
            ):
                return CONFLICT
        if waiting is not None and now - waiting > rules.pong_timeout:
            raise lgwebos.ProbeError(f"no pong within {rules.pong_timeout:.0f} s")
        if waiting is None and now - sent >= rules.ping:
            await ws.ping()
            sent = waiting = env.mono()


def _message(raw: str, subs: dict, st: _State, log: EventLog) -> str | None:
    """One message from the TV: an event line when it says something new. Returns STANDBY when the TV
    says it is switching off, UNSUPPORTED when it refuses a subscription, else None."""
    try:
        msg = json.loads(raw)
    except ValueError:
        return None
    sid = msg.get("id") if isinstance(msg, dict) else None
    if sid not in subs:
        return None  # nothing else was asked
    payload = msg.get("payload") if isinstance(msg.get("payload"), dict) else {}
    if msg.get("type") == "error" or payload.get("returnValue") is False:
        log.write("sub.err", sub=sid)
        return UNSUPPORTED
    st.acked.add(sid)
    if sid == "power":
        ev = lgwebos.power_event(payload)
        state = ev.get("state")
        if state is None:
            return None
        word = (state, ev.get("processing") or "")
        if word != st.power:
            st.power = word
            log.write("power", state=word[0], **({"processing": word[1]} if word[1] else {}))
        if appfront.power_class(*word) == appfront.OFF:
            return STANDBY
        return None
    app = appfront.clean_app(lgwebos.app_event(payload)["appId"])
    if app != st.app:
        st.app = app
        log.write("app", appId=app or None)
    return None


# ---- the service -------------------------------------------------------------------------------------
async def run(env: Env, ledger: Ledger, log: EventLog, rules: Rules | None = None) -> int:
    """Hold sessions while the rules allow one, until told to stop. Always 0: a service that has nothing
    it may do waits; it never exits to be started again."""
    rules = rules or Rules()
    rule = Discipline(ledger, rules)
    with contextlib.suppress(Exception):
        rule.restore(env.load_progress())  # a restart does not forgive the give-up counts
    exhausted = _stand_down_reason(rule, rules, "")
    if exhausted is not None:  # a crash loop or a forward clock step must not buy a fresh first knock
        _safe(env.stand_down, exhausted)
    traffic = Traffic()
    session = env.session or held
    log.write("watch.start")
    said = None
    key_at, key, rec = -1e18, None, None
    traffic.reset(env.clock(), env.rx_bytes())

    evidence_at = env.clock()

    def look(now: float) -> Seen:
        nonlocal evidence_at
        moving = traffic.seen(now)
        if moving:
            evidence_at = now
        return Seen(
            now,
            key is not None,
            rec is not None and rec.refused,
            env.stood_down(),
            env.carrier(),
            moving,
            env.reading(),
            env.mono(),
            now - evidence_at,
        )

    while not env.stopping():
        env.beat()
        now = env.clock()
        traffic.sample(now, env.rx_bytes())
        if now - key_at >= rules.key_recheck:
            key_at, key, rec = now, await env.key(), env.record()
        why = rule.why_not(look(now))
        if why is None and key_at != now:
            # everything holds by what was read a while ago: read the key store again, now, and decide
            # on that. A refusal the hourly reading recorded a second ago stops this attempt
            key_at, key, rec = now, await env.key(), env.record()
            why = rule.why_not(look(now))
        if why is not None:
            head = why.split(":")[0]
            if head != said and head in ("stood down", "not paired", "the TV refused the key"):
                log.write("watch.idle", why=head)  # the reasons a person has to act on
            said = head
            await env.sleep(rules.tick)
            continue
        said = None
        if not rule.begin(now, env.mono()):
            await env.sleep(rules.tick)
            continue
        try:
            manifest = env.manifest(rec.manifest if rec else "signed")
        except Exception:  # the library is not installed: nothing to send
            rule.end(env.clock(), FAILED, 0.0)
            continue
        try:
            outcome, up_seconds = await session(env, rules, log, key, manifest)
        except Exception:  # whatever a session did not catch: end it, stand the daemon down, do not crash
            _safe(env.stand_down, "the live reading hit an error it did not expect")
            break
        rule.end(env.clock(), outcome, up_seconds)
        _safe(env.save_progress, rule.snapshot())  # before anything else: a crash now must not lose it
        traffic.reset(env.clock(), env.rx_bytes())  # the attempt's own packets are not evidence
        key_at = -1e18  # look at the key store again before anything else
        reason = _stand_down_reason(rule, rules, outcome)
        if reason is not None:
            _safe(env.stand_down, reason)
    log.write("watch.stop")
    return 0


def _stand_down_reason(rule: Discipline, rules: Rules, outcome: str) -> str | None:
    """Why the daemon should stop knocking until a person runs `tvgw tvlive --resume`, or None to go on."""
    if outcome == UNSUPPORTED:
        return "the TV refused the power or the app subscription"
    if rule.prompted >= rules.prompt_limit:
        return f"a pairing prompt may have shown {rule.prompted} times"
    if rule.conflicts >= rules.conflict_limit:
        return "the hourly reading could not reach the TV while the live reading held it, twice"
    if rule.unanswered >= rules.give_up:
        return f"{rule.unanswered} attempts in a row failed"
    return None


# ---- the gateway's side ------------------------------------------------------------------------------
def heartbeat(notify_socket: str | None = None) -> Callable[[], None]:
    """A function that tells systemd's watchdog the loop still turns (`WATCHDOG=1` on $NOTIFY_SOCKET),
    and does nothing where no service manager listens. It never raises: a heartbeat that cannot be sent
    costs a restart at worst, which the attempts file outlives."""
    path = os.environ.get("NOTIFY_SOCKET", "") if notify_socket is None else notify_socket
    if not path:
        return lambda: None
    address = "\0" + path[1:] if path.startswith("@") else path

    def beat() -> None:
        with contextlib.suppress(OSError), socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM) as sock:
            sock.sendto(b"WATCHDOG=1", address)

    return beat


def read_progress(path: str) -> dict:
    """The give-up counts a previous run left, or {} when there are none to read."""
    try:
        with open(path, encoding="utf-8") as fh:
            data = json.load(fh)
        return data if isinstance(data, dict) else {}
    except (OSError, ValueError):
        return {}


def write_progress(path: str, data: dict) -> None:
    """Persist the give-up counts, 0600, atomically. Never raises: the caller runs it through `_safe`."""
    tmp = f"{path}.{os.getpid()}"
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with open(fd, "w", encoding="utf-8") as fh:
        json.dump(data, fh)
    os.replace(tmp, path)


def last_reading(history_path: str) -> tuple[float, str] | None:
    """(t, power) of the newest line of tvcheck-history.log, or None when there is none to read."""
    try:
        with open(history_path, "rb") as fh:
            fh.seek(0, os.SEEK_END)
            fh.seek(max(0, fh.tell() - 512))
            lines = [ln for ln in fh.read().decode("utf-8", "replace").splitlines() if ln.strip()]
    except OSError:
        return None
    if not lines or "\t" not in lines[-1]:
        return None
    stamp, power = lines[-1].split("\t")[:2]
    try:
        return datetime.fromisoformat(stamp.strip()).timestamp(), power.strip()
    except ValueError:
        return None


def rx_reader(tv_if: str) -> Callable[[], int | None]:
    """A reader of the bytes the gateway received on the TV port, None when the kernel does not say."""

    def read() -> int | None:
        try:
            with open(f"/sys/class/net/{tv_if}/statistics/rx_bytes", encoding="utf-8") as fh:
                return int(fh.read().strip())
        except (OSError, ValueError):
            return None

    return read


def stood_down(key_file: str) -> str | None:
    """The reason the service stood down, or None when it has not."""
    try:
        with open(state_path(key_file, STOOD_DOWN_FILE), encoding="utf-8") as fh:
            return fh.read().strip()[:200] or "no reason given"
    except OSError:
        return None


def stand_down(key_file: str, why: str) -> None:
    with open(state_path(key_file, STOOD_DOWN_FILE), "w", encoding="utf-8") as fh:
        fh.write(f"{time.strftime('%Y-%m-%d %H:%M')} {why}\n")


def resume(key_file: str) -> bool:
    """Take the marker away: the owner's word that the service may try again. False when there was none."""
    try:
        os.unlink(state_path(key_file, STOOD_DOWN_FILE))
    except FileNotFoundError:
        return False
    return True


def status_lines(s, key_file: str, now: float | None = None) -> list[str]:
    """`tvgw tvlive --status`: what the service would do and why, read from its files. Connects to
    nothing."""
    now = time.time() if now is None else now
    out = [f"LIVE_READING={s.live_reading}, PROFILE={s.profile}"]
    if s.live_reading != "on" or s.profile != PROFILE:
        out.append("the live reading is off: the service does not run")
    rec = lgkeys.record(key_file, s.tv_ip)
    if not lgwebos.has_key(key_file, s.tv_ip):
        out.append("not paired: the service connects to nothing (sudo tvgw tv pair)")
    elif rec is not None and rec.refused:
        out.append("the TV refused the key: the service connects to nothing until sudo tvgw tv pair")
    why = stood_down(key_file)
    if why is not None:
        out.append(f"stood down ({why}): sudo tvgw tvlive --resume lets it try again")
    path = state_path(key_file, ATTEMPTS_FILE)
    try:
        recent = Ledger(path).recent(now)
        by = {who: sum(1 for _, w in recent if w == who) for who in sorted({w for _, w in recent})}
        said = ", ".join(f"{who} {n}" for who, n in by.items()) or "none"
        out.append(f"connection attempts in the last hour: {said} (at most {SERVICE_LIMIT} an hour)")
    except OSError:
        out.append("connection attempts in the last hour: no record (the service has not run here)")
    heard = last_heard(os.path.join(s.state_dir, EVENTS_FILE))
    if heard is not None:
        out.append(f"last heard the TV at {time.strftime('%Y-%m-%d %H:%M', time.localtime(heard))}")
    return out


def last_heard(events_path: str) -> float | None:
    """When the service last heard the TV: the time of the newest line of its events file that came from
    the TV or the session (a power or app event, a ping answered, the session coming up); None without one."""
    try:
        with open(events_path, "rb") as fh:
            fh.seek(0, os.SEEK_END)
            fh.seek(max(0, fh.tell() - 65536))
            lines = fh.read().decode("utf-8", "replace").splitlines()
    except OSError:
        return None
    for line in reversed(lines):
        try:
            rec = json.loads(line)
        except ValueError:
            continue
        if isinstance(rec, dict) and rec.get("kind") in ("power", "app", "alive", "session.up"):
            t = rec.get("t")
            if isinstance(t, int | float):
                return float(t)
    return None


def hear(s, key_file: str, seconds: float = 5.0) -> tuple[str, list[dict]]:
    """One short session by the service's own rules, for the hardware suite and for a person who wants to
    see what the TV says before switching the service on: (`skipped: <why>` or how the session ended, the
    event lines it wrote). It needs what the service needs, except that only an hourly reading that found
    the TV awake counts as evidence (it does not wait for traffic): the key, no refusal, no marker, room
    in the hour, the hourly reading not at work. It counts its attempt where the service counts, and a
    refusal is recorded where the hourly reading obeys it."""
    if s.profile != PROFILE:
        return f"skipped: PROFILE={s.profile} has no live reading", []
    key = asyncio.run(lgwebos._stored_key(key_file, s.tv_ip))
    rec = lgkeys.record(key_file, s.tv_ip) if key else None
    now = time.time()
    with tempfile.TemporaryDirectory() as tmp:
        path = state_path(key_file, ATTEMPTS_FILE)
        counted = os.path.isfile(path)  # where the service never ran, nothing of its is made here
        ledger = Ledger(path if counted else os.path.join(tmp, ATTEMPTS_FILE))
        ledger.create()
        seen = Seen(
            now,
            key is not None,
            rec is not None and rec.refused,
            stood_down(key_file),
            lgwebos.carrier(s.tv_if)(),
            False,
            last_reading(s.tvcheck_history),
        )
        why = Discipline(ledger).why_not(seen)
        if why is not None:
            return f"skipped: {why}", []
        try:
            manifest = lgwebos.manifest_for(rec.manifest if rec else "signed")
        except ImportError:
            return "skipped: the LAN-API library is not installed", []
        ledger.note("listen", now)
        out = os.path.join(tmp, "events.log")
        log = EventLog(out)

        async def connect():
            return await lgwebos._connect_ws(s.tv_ip, CONNECT_TIMEOUT)

        async def listen() -> tuple[str, float]:
            until = time.monotonic() + seconds
            env = Env(
                connect=connect,
                key=lambda: None,
                record=lambda: rec,
                manifest=lgwebos.manifest_for,
                refuse=lambda why: lgkeys.refused(key_file, s.tv_ip, f"a live reading's registration: {why}"),
                rx_bytes=lambda: None,
                carrier=lambda: None,
                reading=lambda: None,
                stood_down=lambda: None,
                stand_down=lambda why: None,
                stopping=lambda: time.monotonic() >= until,
            )
            return await held(env, Rules(), log, key, manifest)

        try:
            outcome, _ = asyncio.run(listen())
        finally:
            log.close()
        with open(out, encoding="utf-8") as fh:
            lines = [json.loads(line) for line in fh]
    return outcome, lines


def main(s, key_file: str) -> int:
    """`tvgw tvlive`: the service. 0 at once when the live reading is off or the profile has no reader."""
    if s.live_reading != "on" or s.profile != PROFILE:
        print(f"tvgw tvlive: LIVE_READING={s.live_reading}, PROFILE={s.profile}: nothing to do")
        return 0
    ledger = Ledger(state_path(key_file, ATTEMPTS_FILE))
    ledger.create()
    log = EventLog(os.path.join(s.state_dir, EVENTS_FILE))
    stop = asyncio.Event()

    async def connect():
        return await lgwebos._connect_ws(s.tv_ip, CONNECT_TIMEOUT)

    async def key():
        return await lgwebos._stored_key(key_file, s.tv_ip)

    def record():
        try:
            return lgkeys.record(key_file, s.tv_ip)
        except Exception:  # a locked or unreadable key file: as if refused, nothing is tried
            return lgkeys.Pairing(s.tv_ip, refused_at=time.time(), refused_why="the key file cannot be read")

    env = Env(
        connect=connect,
        key=key,
        record=record,
        manifest=lgwebos.manifest_for,
        refuse=lambda why: lgkeys.refused(key_file, s.tv_ip, f"the live reading's registration: {why}"),
        rx_bytes=rx_reader(s.tv_if),
        carrier=lgwebos.carrier(s.tv_if),
        reading=lambda: last_reading(s.tvcheck_history),
        stood_down=lambda: stood_down(key_file),
        stand_down=lambda why: stand_down(key_file, why),
        load_progress=lambda: read_progress(state_path(key_file, PROGRESS_FILE)),
        save_progress=lambda d: write_progress(state_path(key_file, PROGRESS_FILE), d),
        stopping=stop.is_set,
        beat=heartbeat(),
    )

    async def serve() -> int:
        loop = asyncio.get_running_loop()
        for sig in (signal.SIGTERM, signal.SIGINT):
            loop.add_signal_handler(sig, stop.set)
        return await run(env, ledger, log)

    try:
        return asyncio.run(serve())
    finally:
        log.close()
