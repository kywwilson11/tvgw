"""Attention-keyed silence, its first stage: the kernel holds the TV's own account of where its viewer's
attention is, and counts what a wall keyed to it would refuse (design decision 69). Nothing here refuses
anything on a live gateway.

On the reference CX the screen saver, not standby, is where the idle traffic is: over 28 days about 595
connections and 85 MB went out while the TV said its screen saver was on, against 7 connections with an
HDMI input or live TV in front, and none while it was off. Nobody is using the TV's internet side in those
moments, so a wall that let only the TV's essentials through then would have real traffic to stop and
almost nothing to break. This module builds the instrument that wall would need, and counts.

**Four states, one kernel entry each.** The live reading (tvlive.py) knows the TV's power state and the app
in front. `state_of` turns them into one of IDLE (the screen saver is on), INPUT (an HDMI or other external
input is in front), LIVETV (the live-TV input) and APP (anything else with the TV on: an app, the home
screen, a cast receiver), or None when it does not know. Each state is a one-element set in tvgw-apply's
table `inet tvgw_attn` (`idle4`, `input4`, `livetv4`, `app4`) that holds the TV's address while the TV is
in that state.

**Dead-man entries: the gateway can fail to protect, never fail closed.** Each element carries a short
lifetime (HOLD seconds) that must be renewed (every RENEW_EVERY seconds) or the kernel itself lets it go.
Two processes stand between the TV's word and the kernel, and either one dying opens the wall:

- tvgw-tvlive, which faces the TV and holds no capability at all, writes the state it reads to a small
  file in its runtime directory (`STATE_FILE`, on a memory file system, never the SD card) whenever the
  state changes and at least every WRITE_EVERY seconds while its session answers. It writes the class of
  state only: never the app, never a time but its own steady clock. A session that ends writes None.
- tvgw-attention (`Holder`, `main`), which holds CAP_NET_ADMIN and no network socket, reads that file
  every POLL seconds. A word older than FRESH seconds is no word. It moves the TV's address from one
  state's set to the next in one netlink transaction, at once when the state changes (by event, under a
  second, never by waiting for a timeout), and renews the element while the word stays fresh.

So: the live reading dies, hangs, stands down or loses the TV, and its word goes stale within FRESH
seconds, when the holder empties every set; the holder dies or hangs, and the element expires within HOLD
seconds by the kernel's own clock; the table is reloaded, and the next renewal puts the element back. The
holder reads only a state from a fixed vocabulary and computes the address from the settings, so even a
live reading the TV had subverted could only pick one of four states for the TV's own address.

**The platform set: the TV's essentials.** `platform4` holds the addresses the TV needs in every state:
the profile's must-allow hosts, its clock hosts and the vendor's own expected category (`appfront.classify`
calls them `platform`). It is filled from the TV's own DNS answers, by the in-path filler where
DNSGATE_FILL=inpath (in the answer's path, before the TV has it: exact) and by the passive feeder otherwise
(a few milliseconds after the answer: the race is marked in the report). The probe's lookups were the
other candidate and are not used: they see the resolver's answer to the probe, not to the TV, every ten
minutes, for the listed names only, while the TV may be handed a new address between two probes and
asks for names under the listed ones.

**The count.** In each counted state (COUNTED: IDLE, INPUT, LIVETV) a rule counts the TV's new TCP and UDP
connections to addresses outside `platform4` (NTP's port 123 and LG's firmware fallback are essentials
by port), once per connection, and keeps each in a sample set of its own for SAMPLE_TIMEOUT seconds. The
hourly ingest copies the samples into the store's `attention` table (`ingest_samples`), the brief names
the services behind them per state (`report`), and the plain brief says it in one line (plain.py).

**The switch for later.** ATTENTION_WALL=refuse would refuse, in WALLED (IDLE and INPUT, never live TV,
where LG Channels plays), what the count counts. tvgw-apply renders those rules only where its line
ATTENTION_REFUSE_SUPPORTED says yes, which the shipped script does not: on a live gateway `refuse` says so
and counts. The namespace tier runs a copy with the line set to yes.

**Privacy.** The live reading's rules hold: the kernel's sets are in memory, the state file is overwritten
in place, and the store keeps the samples (each a time, a state and a connection) only as long as it keeps
`tv_events`, the live record (TV_EVENTS_DAYS), with `tvgw forget` removing them. The counters
`tvgw verify --record` stores under RULE_PREFIX are pruned on the same span. The brief carries counts per
state and service for its window, never a time.
"""

from __future__ import annotations

import contextlib
import errno
import ipaddress
import json
import math
import os
import signal
import sqlite3
import stat
import sys
import threading
import time
from collections.abc import Callable, Iterable
from dataclasses import asdict, dataclass, field
from datetime import datetime, timedelta

from tvgw import appfront, companies, names, nfnl, queries
from tvgw.config import Settings
from tvgw.profile import Profile

# ---- the vocabulary -----------------------------------------------------------------------------------
TABLE = "tvgw_attn"  # in the inet family, as tvgw-apply creates it
PLATFORM_SET = "platform4"
IDLE, INPUT, LIVETV, APP = "idle", "input", "livetv", "app"
STATES = (IDLE, INPUT, LIVETV, APP)
STATE_SETS = {s: f"{s}4" for s in STATES}  # the dead-man entries: each holds the TV's address, or nothing
COUNTED = (IDLE, INPUT, LIVETV)  # the states whose connections outside the essentials are counted
WALLED = (IDLE, INPUT)  # the states ATTENTION_WALL=refuse would refuse in: never live TV (LG Channels)
SAMPLE_SETS = {s: f"{s}_seen4" for s in COUNTED}  # each counted connection, kept SAMPLE_TIMEOUT seconds
# the comments of the counting rules: an interface (design decision 13). tvgw-apply writes them, verify
# stores them as fw_counters series, the brief reads them
RULE_PREFIX = "attention:"
RULES = {
    IDLE: "attention: outside the essentials, screen saver on",
    INPUT: "attention: outside the essentials, an input in front",
    LIVETV: "attention: outside the essentials, live TV in front",
}
# the input apps: HDMI and other external inputs, and live TV apart (appfront.INPUT_APP_PREFIXES holds all)
INPUT_PREFIXES = ("com.webos.app.hdmi", "com.webos.app.externalinput")
LIVETV_PREFIXES = ("com.webos.app.livetv",)
PROFILE = "lg-webos"  # the one profile with a live reading (tvlive.PROFILE)

# ---- the timing ---------------------------------------------------------------------------------------
HOLD = 8  # seconds an element lives without a renewal: the most the kernel holds a state nobody renews
RENEW_EVERY = 2.0  # seconds between two renewals of the element of an unchanged state
FRESH = 5.0  # seconds the live reading's word holds: older, and it is no word at all
WRITE_EVERY = 1.0  # seconds between two writes of an unchanged word by the live reading
POLL = 0.25  # seconds between two looks at the word: a change reaches the kernel within this
RETRY_EVERY = 2.0  # seconds after a transaction the kernel refused before the holder tries again
STATUS_EVERY = 10.0  # seconds between two writes of the holder's status
STATUS_STALE = 60.0  # seconds after which a status says nothing about the holder now
LOG_EVERY = 60.0  # seconds between two log lines of the same kind
SAMPLE_TIMEOUT = 3 * 3600  # seconds the kernel keeps a sample: the hourly ingest reads it within this
SAMPLE_SLACK = 30.0  # seconds two readings of one sample's first time may differ by and still be one
STATE_MAX = 256  # bytes of the word read: it is a few dozen
STATE_FILE = "/run/tvgw-tvlive/attention"  # tvgw-tvlive's RuntimeDirectory; tvgw-attention reads it
STATUS = "/run/tvgw-attention/status.json"  # tvgw-attention's RuntimeDirectory; verify reads it
# the report: services named per state, and how close before a change of state a connection is the next
# state's (an app that starts before the TV says so: appfront.LEAD_SECONDS, deep dive 14's guess)
SHOWN = 10
LEAD = appfront.LEAD_SECONDS
LOOKBACK = 86400.0  # seconds of the live record before a window read to know the state at its start


def not_in_use(s: Settings) -> str | None:
    """Why nothing of this runs on this gateway, in the settings' own words, or None when it does: the
    live reading on, for the profile that has one, and ATTENTION_WALL not off."""
    if s.live_reading != "on":
        return f"LIVE_READING={s.live_reading}"
    if s.profile != PROFILE:
        return f"PROFILE={s.profile} has no live reading"
    if s.attention_wall == "off":
        return "ATTENTION_WALL=off"
    return None


def wanted(s: Settings) -> bool:
    return not_in_use(s) is None


def state_of(power: tuple[str, str] | None, app: str | None) -> str | None:
    """The attention state of a TV that reports `power` (state, processing) and has `app` in front, or None
    when the words do not say: no power state yet, a power word this vocabulary does not know, the TV
    switching off, or the TV on with no app reported yet. The screen saver wins over the app behind it."""
    if power is None:
        return None
    cls = appfront.power_class(*power)
    if cls == appfront.IDLE:
        return IDLE
    if cls != appfront.ON or app is None:
        return None
    if app.startswith(INPUT_PREFIXES):
        return INPUT
    if app.startswith(LIVETV_PREFIXES):
        return LIVETV
    return APP


# ---- the word: what the live reading tells the holder -------------------------------------------------
def encode_word(state: str | None, mono: float) -> bytes:
    return json.dumps({"v": 1, "state": state, "mono": round(mono, 3)}, sort_keys=True).encode() + b"\n"


def decode_word(data: bytes) -> tuple[str | None, float] | None:
    """(state, the writer's steady clock) of a word, or None for anything that is not one exactly: too
    long, not JSON, another version, a state outside the vocabulary, a clock that is not a finite number."""
    if len(data) > STATE_MAX:
        return None
    try:
        rec = json.loads(data.decode("ascii"))
    except (UnicodeDecodeError, ValueError):
        return None
    if not isinstance(rec, dict) or rec.get("v") != 1:
        return None
    state, mono = rec.get("state"), rec.get("mono")
    if state is not None and state not in STATES:
        return None
    if isinstance(mono, bool) or not isinstance(mono, int | float) or not math.isfinite(mono):
        return None
    return state, float(mono)


def write_word(path: str, state: str | None, mono: float) -> None:
    """Replace the word, whole and root's alone (0600). Raises OSError, which the live reading's Word
    swallows."""
    tmp = f"{path}.tmp"
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    try:
        os.write(fd, encode_word(state, mono))
    finally:
        os.close(fd)
    os.replace(tmp, path)


def read_word(path: str = STATE_FILE) -> tuple[str | None, float] | None:
    """The word, or None: a regular file only, never through a symbolic link and never a FIFO that could
    hold the holder's loop (O_NOFOLLOW, O_NONBLOCK), read no further than STATE_MAX + 1 bytes."""
    try:
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    except OSError:
        return None
    try:
        if not stat.S_ISREG(os.fstat(fd).st_mode):
            return None
        return decode_word(os.read(fd, STATE_MAX + 1))
    except OSError:
        return None
    finally:
        os.close(fd)


class Word:
    """The live reading's side: `say(state)` on every turn of its session's loop writes the word when the
    state changed or WRITE_EVERY seconds have passed, `clear()` when the session ends. A write that fails
    (no runtime directory: the service runs outside its unit) is never the session's problem."""

    def __init__(
        self,
        path: str = STATE_FILE,
        clock: Callable[[], float] = time.monotonic,
        write: Callable[[str, str | None, float], None] = write_word,
    ):
        self.path, self.clock, self._write = path, clock, write
        self.last: str | None = None
        self.at = -math.inf

    def say(self, state: str | None) -> None:
        now = self.clock()
        if state == self.last and now - self.at < WRITE_EVERY:
            return
        with contextlib.suppress(OSError):
            self._write(self.path, state, now)
            self.last, self.at = state, now

    def clear(self) -> None:
        self.at = -math.inf
        self.say(None)


# ---- the holder: the word into the kernel -------------------------------------------------------------
@dataclass
class HolderStats:
    """Counts since the holder started, for its status file: none of it is a state or a time."""

    changes: int = 0  # transactions that moved the TV's address to another state's set, or out of all
    renewals: int = 0  # renewals of an unchanged state's element
    failures: int = 0  # transactions the kernel refused (the table missing during an apply, mostly)
    stale: int = 0  # times the live reading's word went stale while a state was held


class Holder:
    """Holds the TV's address in the set of the state the live reading's word names, and in no other.
    `transact(build, parts) -> errno` runs one nf_tables transaction (inpath.NftSocket.transact); `read()`
    returns the word or None; `clock` is the steady clock the live reading writes its word with."""

    def __init__(
        self,
        transact: Callable[..., int],
        addr: bytes,
        read: Callable[[], tuple[str | None, float] | None] = read_word,
        clock: Callable[[], float] = time.monotonic,
        log: Callable[[str], None] = lambda line: print(line, file=sys.stderr, flush=True),
        hold: int = HOLD,
        renew: float = RENEW_EVERY,
        fresh: float = FRESH,
    ):
        if len(addr) != 4:
            raise ValueError("the TV's address is four bytes")
        self.transact, self.addr, self.read, self.clock, self._log = transact, addr, read, clock, log
        self.hold, self.renew, self.fresh = hold, renew, fresh
        self.held: str | None = None  # the state whose set the last committed transaction left holding it
        self.renewed = -math.inf
        self.next_try = -math.inf  # after a refused transaction, not before this
        self.dirty = True  # the kernel's sets may not be what `held` says: the first tick writes them whole
        self.word_fresh = False
        self.last_error = 0
        self.stats = HolderStats()
        self._logged: dict[str, float] = {}

    def say(self, kind: str, line: str) -> None:
        now = self.clock()
        if now - self._logged.get(kind, -math.inf) >= LOG_EVERY:
            self._logged[kind] = now
            self._log(f"tvgw attention-hold: {line}")

    def wanted(self, now: float) -> str | None:
        """The state the word names, when it is fresh; None otherwise."""
        word = self.read()
        if word is None:
            self.word_fresh = False
            return None
        state, mono = word
        # the same steady clock on both sides; a word a second ahead is rounding, more is no word
        self.word_fresh = -1.0 <= now - mono <= self.fresh
        return state if self.word_fresh else None

    def _move(self, want: str | None) -> int:
        """One transaction: every state's set emptied, and the TV's address put in `want`'s with a whole
        lifetime. The kernel commits all of it or none, so the TV is never in two states at once, and the
        element is always a new one: a kernel before 6.12 keeps an element's first expiry when an add meets
        it (design decision 43), and a new element has a whole lifetime on every kernel."""
        parts = [nfnl.set_flush_part(TABLE, STATE_SETS[s]) for s in STATES]
        if want is not None:
            parts.append(nfnl.setelem_add_part(TABLE, STATE_SETS[want], [self.addr], self.hold))
        return self.transact(lambda seq: nfnl.transaction(seq, parts), len(parts))

    def tick(self) -> None:
        now = self.clock()
        before = self.word_fresh
        want = self.wanted(now)
        if before and not self.word_fresh and self.held is not None:
            self.stats.stale += 1
            self.say("stale", "the live reading's word went stale; the TV is in no state until it speaks")
        if now < self.next_try:
            return
        changed = want != self.held
        due = want is not None and now - self.renewed >= self.renew
        if not (changed or due or self.dirty):
            return
        err = self._move(want)
        if err:
            self._refused(err, now)
            return
        if changed:
            self.stats.changes += 1
        elif due:
            self.stats.renewals += 1
        self.held, self.renewed, self.dirty = want, now, False

    def _refused(self, err: int, now: float) -> None:
        """A refused transaction changed nothing. What the kernel holds is what it held, with an element
        that expires within HOLD; the next try, RETRY_EVERY later, writes every set again."""
        self.stats.failures += 1
        self.last_error = err
        self.dirty = True
        self.next_try = now + RETRY_EVERY
        if err == errno.ENOENT:
            self.say("missing", f"inet {TABLE} is not loaded; nothing is held until tvgw-apply loads it")
        else:
            self.say("refused", f"the kernel refused a change ({errno.errorcode.get(err, err)})")

    def clear(self) -> int:
        """Every state's set emptied: the TV in no state. The start and the stop of the service."""
        err = self._move(None)
        if err == 0:
            self.held, self.dirty = None, False
        return err

    def status(self, started: float, wall: float) -> dict:
        """What `tvgw verify` and `tvgw attention` read. The state held is there for the gateway's root
        alone (the file is 0640 root's in a 0750 directory of root's); verify's check never prints it."""
        return {
            "v": 1,
            "pid": os.getpid(),
            "started": started,
            "t": wall,
            "held": self.held,
            "word_fresh": self.word_fresh,
            "last_error": self.last_error,
            "stats": asdict(self.stats),
        }


def write_status(path: str, doc: dict) -> bool:
    """Replace the status, whole, mode 0640; False when it cannot be written (no runtime directory)."""
    tmp = f"{path}.tmp"
    try:
        with open(tmp, "w", encoding="utf-8") as fh:
            json.dump(doc, fh, sort_keys=True)
            fh.write("\n")
        os.chmod(tmp, 0o640)
        os.replace(tmp, path)
    except OSError:
        return False
    return True


def read_status(path: str = STATUS, now: float | None = None) -> dict | None:
    """The holder's status when it is fresh (written in the last STATUS_STALE seconds), else None."""
    try:
        with open(path, encoding="utf-8") as fh:
            doc = json.load(fh)
    except (OSError, ValueError):
        return None
    now = time.time() if now is None else now
    t = doc.get("t") if isinstance(doc, dict) else None
    if isinstance(t, bool) or not isinstance(t, int | float) or not 0 <= now - t <= STATUS_STALE:
        return None
    return doc


def _notify(state: str) -> None:
    from tvgw import inpath  # its sd_notify; imported here so the store side never loads the filler

    inpath.notify(state)


def main(s: Settings, status_path: str = STATUS, state_path: str = STATE_FILE) -> int:
    """`tvgw attention-hold`: the holder, as tvgw-attention.service runs it. 0 at once where nothing of
    this is in use (the unit's ExecCondition keeps it from getting here)."""
    why = not_in_use(s)
    if why is not None:
        print(f"tvgw attention-hold: {why}: nothing to hold", flush=True)
        _notify("READY=1")
        return 0
    from tvgw import inpath

    addr = ipaddress.IPv4Address(s.tv_ip).packed
    stopping = threading.Event()
    for sig in (signal.SIGTERM, signal.SIGINT):
        signal.signal(sig, lambda *_: stopping.set())
    nft = inpath.NftSocket()
    holder = Holder(nft.transact, addr, read=lambda: read_word(state_path))
    holder.clear()  # whatever an earlier holder left: the TV in no state until the live reading speaks
    started, next_status = time.time(), 0.0
    _notify("READY=1")
    print(f"tvgw attention-hold: holding the live reading's word for {s.tv_ip} in inet {TABLE}", flush=True)
    try:
        while not stopping.is_set():
            holder.tick()
            _notify("WATCHDOG=1")
            if (now := time.monotonic()) >= next_status:
                next_status = now + STATUS_EVERY
                write_status(status_path, holder.status(started, time.time()))
            stopping.wait(POLL)
    finally:
        _notify("STOPPING=1")
        holder.clear()
        nft.close()
    print(f"tvgw attention-hold: stopped ({holder.stats.changes} changes, {holder.stats.failures} refused)")
    return 0


STATE_WORDS = {
    IDLE: "the screen saver is on",
    INPUT: "an input (HDMI or another external one) is in front",
    LIVETV: "live TV is in front",
    APP: "an app or the home screen is in front",
}


def set_sizes(listing: str) -> dict[str, int]:
    """name -> elements, for each set of an `nft -j list table inet tvgw_attn` listing; {} without one."""
    try:
        data = json.loads(listing) if listing.strip() else {}
    except ValueError:
        return {}
    out = {}
    for obj in data.get("nftables", []) if isinstance(data, dict) else []:
        st = obj.get("set") if isinstance(obj, dict) else None
        if isinstance(st, dict) and isinstance(st.get("name"), str):
            out[st["name"]] = len(st.get("elem") or [])
    return out


def status_lines(s: Settings, status: dict | None, listing: str, now: float | None = None) -> list[str]:
    """`tvgw attention`: whether the count runs here, what the holder holds now, and what the kernel's
    table holds, read from the holder's status and one listing. Connects to nothing and changes nothing."""
    now = time.time() if now is None else now
    out = [f"LIVE_READING={s.live_reading}, PROFILE={s.profile}, ATTENTION_WALL={s.attention_wall}"]
    why = not_in_use(s)
    if why is not None:
        return [*out, f"the attention count is not in use ({why}): nothing is held or counted"]
    if s.attention_wall == "refuse":
        out.append(
            "ATTENTION_WALL=refuse is not supported on a live gateway yet (design decision 69 says what it"
            " lacks): the gateway counts, as with count, and refuses nothing"
        )
    if status is None:
        out.append("the holder is not running: the TV is in no state, and nothing is counted")
    else:
        held = status.get("held")
        since = status.get("started")
        when = f" since {time.strftime('%Y-%m-%d %H:%M', time.localtime(since))}" if since else ""
        out.append(f"the holder is running{when}")
        if held in STATE_WORDS:
            out.append(f"the firewall holds the live reading's word now: {STATE_WORDS[held]}")
        elif status.get("word_fresh"):
            out.append("the live reading speaks, but has not said the TV's state yet: the TV is in no state")
        else:
            out.append("the live reading is silent (no session to the TV): the TV is in no state")
        stats = status.get("stats") or {}
        if stats.get("failures"):
            out.append(f"changes the kernel refused since it started: {stats['failures']}")
    sizes = set_sizes(listing)
    if not sizes:
        out.append(f"inet {TABLE} is not loaded (sudo tvgw-apply loads it)")
        return out
    out.append(f"essential addresses the gateway knows: {sizes.get(PLATFORM_SET, 0)}")
    short = {IDLE: "screen saver", INPUT: "input", LIVETV: "live TV"}
    waiting = ", ".join(f"{short[st]} {sizes.get(SAMPLE_SETS[st], 0)}" for st in COUNTED)
    out.append(f"connections counted in the last {SAMPLE_TIMEOUT // 3600} hours, by state: {waiting}")
    out.append("what they were, by service: tvgw brief --full (the Attention section)")
    return out


# ---- the essentials -----------------------------------------------------------------------------------
def platform_check(profile: Profile, limit: int = 4096) -> Callable[[str], bool]:
    """A test of whether a looked-up name is one of the TV's essentials (`appfront.classify`'s platform
    class), remembering up to `limit` names: the fillers ask it for every answer the TV gets."""
    seen: dict[str, bool] = {}

    def check(name: str) -> bool:
        key = names.normalize(name or "")
        if not key:
            return False
        hit = seen.get(key)
        if hit is None:
            try:
                hit = appfront.classify(profile, key).cls == appfront.PLATFORM
            except Exception:  # a name the profile cannot read is no essential
                hit = False
            if len(seen) >= limit:
                seen.clear()
            seen[key] = hit
        return hit

    return check


def platform_batch(ips: list[str], ttl: int) -> str:
    """The passive feeder's nft script for the platform set: each address with a lifetime and an expiry of
    the same length, as dnsgate.batch writes the gate's own set."""
    elements = ", ".join(f"{ip} timeout {ttl}s expires {ttl}s" for ip in ips)
    return f"add element inet {TABLE} {PLATFORM_SET} {{ {elements} }}\n"


# ---- the samples: the kernel's sets into the store ----------------------------------------------------
@dataclass(frozen=True)
class Sample:
    t: float  # when the kernel first counted the connection, to the second
    state: str
    proto: str
    dst: str
    sport: int
    dport: int


_PROTOS = {6: "tcp", 17: "udp", "tcp": "tcp", "udp": "udp", "6": "tcp", "17": "udp"}


def _port(value) -> int | None:
    if isinstance(value, bool):
        return None
    try:
        port = int(value)
    except (TypeError, ValueError):
        return None
    return port if 0 <= port <= 65535 else None


def _seconds(value) -> float | None:
    if isinstance(value, bool) or not isinstance(value, int | float) or not math.isfinite(value):
        return None
    return float(value)


def samples_from_listing(text: str, now: float) -> list[Sample]:
    """The samples in an `nft -j list table inet tvgw_attn` listing taken at `now`: each element of a
    sample set (address . protocol . source port . destination port) with the time the kernel added it,
    which is `now` less what of its lifetime has passed. Anything that is not exactly such an element is
    skipped: nothing but an address, a protocol and two ports reaches a row."""
    try:
        data = json.loads(text) if text.strip() else {}
    except ValueError:
        return []
    by_set = {v: k for k, v in SAMPLE_SETS.items()}
    out: list[Sample] = []
    for obj in data.get("nftables", []) if isinstance(data, dict) else []:
        s = obj.get("set") if isinstance(obj, dict) else None
        if not isinstance(s, dict) or s.get("table") not in (None, TABLE) or s.get("name") not in by_set:
            continue
        state = by_set[s["name"]]
        default = _seconds(s.get("timeout"))
        for item in s.get("elem") or []:
            e = item.get("elem") if isinstance(item, dict) else None
            if not isinstance(e, dict):
                continue
            val = e.get("val")
            parts = val.get("concat") if isinstance(val, dict) else None
            if not isinstance(parts, list) or len(parts) != 4:
                continue
            dst, proto, sport, dport = parts
            proto = _PROTOS.get(proto) if isinstance(proto, int | str) else None
            sport, dport = _port(sport), _port(dport)
            timeout = _seconds(e.get("timeout")) or default
            expires = _seconds(e.get("expires"))
            try:
                dst = str(ipaddress.IPv4Address(dst))
            except (TypeError, ValueError):
                continue
            if proto is None or sport is None or dport is None or timeout is None or expires is None:
                continue
            age = min(max(timeout - expires, 0.0), timeout)
            out.append(Sample(round(now - age, 3), state, proto, dst, sport, dport))
    return out


def store_samples(conn: sqlite3.Connection, found: Iterable[Sample]) -> int:
    """Insert the samples the store does not hold yet; the count inserted. The kernel keeps a sample for
    SAMPLE_TIMEOUT seconds and the ingest reads it every hour, so each one is read up to three times,
    with a first time that may differ by the rounding of its expiry: one already stored within
    SAMPLE_SLACK seconds, for the same connection in the same state, is that one."""
    n = 0
    for x in found:
        known = conn.execute(
            "SELECT 1 FROM attention WHERE state=? AND dst=? AND sport=? AND dport=? AND proto=?"
            " AND t >= ? AND t <= ? LIMIT 1",
            (x.state, x.dst, x.sport, x.dport, x.proto, x.t - SAMPLE_SLACK, x.t + SAMPLE_SLACK),
        ).fetchone()
        if known:
            continue
        conn.execute(
            "INSERT INTO attention(t, state, proto, dst, sport, dport) VALUES (?,?,?,?,?,?)",
            (x.t, x.state, x.proto, x.dst, x.sport, x.dport),
        )
        n += 1
    return n


def list_table(run: Callable[..., object] | None = None) -> str:
    """`nft -j list table inet tvgw_attn`, or "" when it is not loaded or nft cannot be run."""
    import subprocess

    runner = run or subprocess.run
    try:
        argv = ["nft", "-j", "list", "table", "inet", TABLE]
        out = runner(argv, capture_output=True, text=True, timeout=30)
    except (OSError, subprocess.TimeoutExpired):
        return ""
    return out.stdout if getattr(out, "returncode", 1) == 0 else ""


def ingest_samples(
    conn: sqlite3.Connection, listing: Callable[[], str] = list_table, now: Callable[[], float] = time.time
) -> int:
    """The hourly ingest's step: the kernel's samples into `attention`. A gateway without the table (the
    live reading off, or ATTENTION_WALL=off) reads nothing and stores nothing."""
    text = listing()
    if not text:
        return 0
    return store_samples(conn, samples_from_listing(text, now()))


# ---- the report ---------------------------------------------------------------------------------------
def intervals(events: list[appfront.Event], a: float, b: float) -> list[tuple[float, float, str]]:
    """The window [a, b) cut into (start, end, state) pieces by the live record's events, None-state time
    left out. A session to the TV that goes down or up, or the service starting or stopping, forgets the
    power state and the app: the state is None until the TV says again, as the holder's would be."""
    out: list[tuple[float, float, str]] = []
    power: tuple[str, str] | None = None
    app: str | None = None
    cur: str | None = None
    since = a

    def close(t: float) -> None:
        lo, hi = max(since, a), min(t, b)
        if cur is not None and hi > lo:
            out.append((lo, hi, cur))

    for e in sorted(events, key=appfront._order):
        if e.t >= b:
            break
        if e.kind == "power":
            power = (e.value, e.detail)
        elif e.kind == "app":
            app = e.value
        elif e.kind in ("conn", "watch"):
            power, app = None, None
        else:
            continue
        new = state_of(power, app)
        if new != cur:
            close(e.t)
            cur, since = new, e.t
    close(b)
    return out


def _state_at(pieces: list[tuple[float, float, str]], t: float) -> str | None:
    for lo, hi, state in pieces:
        if lo <= t < hi:
            return state
    return None


def _named(conn: sqlite3.Connection, t: float, dst: str, sport: int, dport: int) -> tuple[str, int]:
    """(name, bytes both ways) of a sampled connection: the flow conntrack logged for it (same server and
    ports, a start within a minute of the sample) with the name its own hello gave, else the name the
    newest A answer gave its server in the KNOWN_DAYS before; "" when neither says. A connection still open
    has no flow yet, and no bytes."""
    row = conn.execute(
        f"""SELECT {queries.FLOW_NAME}, COALESCE(f.bytes_up, 0) + COALESCE(f.bytes_down, 0) FROM flows f
            WHERE f.dst=? AND f.sport=? AND f.dport=? AND f.t_end >= ? AND COALESCE(f.t_start, f.t_end) <= ?
            ORDER BY ABS(COALESCE(f.t_start, f.t_end) - ?) LIMIT 1""",
        (dst, sport, dport, t - 60, t + 60, t),
    ).fetchone()
    name, size = (row[0] or "", row[1] or 0) if row else ("", 0)
    return name or _answered(conn, dst, t - queries.KNOWN_DAYS * 86400, t) or "", size


def _answered(conn: sqlite3.Connection, dst: str, since: float, until: float) -> str | None:
    """The name of the newest A answer in [since, until] that handed out `dst` exactly (`A:203.0.113.45`
    is not 203.0.113.4)."""
    row = conn.execute(
        "SELECT qname FROM dns WHERE t <= ? AND t >= ? AND (',' || answers || ',') LIKE ?"
        " ORDER BY t DESC LIMIT 1",
        (until, since, f"%,A:{dst},%"),
    ).fetchone()
    return row[0] if row else None


@dataclass
class Service:
    """One service a state's connections outside the essentials went to: a registrable domain, or a /24
    where no name was seen."""

    key: str
    company: str | None
    cls: str
    category: str
    conns: int = 0
    bytes: int = 0
    essential: bool = False  # an address of one of the TV's essentials the platform set did not hold
    late: int = 0  # of them, connections within FEEDER_LATE of the answer that named the address
    lead: int = 0  # of them, connections within LEAD seconds before the TV said the state ended


@dataclass
class StateReport:
    seconds: float = 0.0  # time the live record has the TV in this state in the window
    counted: int = 0  # the kernel's count of connections outside the essentials (fw_counters)
    samples: int = 0  # connections the store holds a sample of
    bytes: int = 0
    other_state: int = 0  # samples the live record puts in another state, or in none (the holder's lag)
    services: list[Service] = field(default_factory=list)


def _has_data(conn: sqlite3.Connection, a: float, b: float) -> bool:
    """Whether the window holds a count of this kind: a sample, or a counter verify stored."""
    try:
        if conn.execute("SELECT 1 FROM attention WHERE t >= ? AND t < ? LIMIT 1", (a, b)).fetchone():
            return True
    except sqlite3.OperationalError:  # a store from before schema 17
        return False
    return (
        conn.execute(
            "SELECT 1 FROM fw_counters WHERE rule LIKE ? AND t >= ? AND t < ? LIMIT 1",
            (f"{RULE_PREFIX}%", a, b),
        ).fetchone()
        is not None
    )


def _states(conn: sqlite3.Connection, a: float, b: float, profile: Profile) -> dict[str, StateReport]:
    """Per counted state: its time, the kernel's count and the services behind the samples of [a, b)."""
    pieces = intervals(appfront.stored_events(conn, a - LOOKBACK, b), a, b)
    states = {s: StateReport() for s in COUNTED}
    ends: dict[str, list[float]] = {}  # where the live record has each state end inside the window
    for (lo, hi, state), nxt in zip(pieces, [*pieces[1:], None], strict=True):
        if state in states:
            states[state].seconds += hi - lo
        if hi < b and (nxt is None or nxt[0] != hi or nxt[2] != state):
            ends.setdefault(state, []).append(hi)
    for state in COUNTED:
        states[state].counted = queries.series_gain(conn, RULES[state], a, b)
    by: dict[tuple[str, str], Service] = {}
    rows = conn.execute(
        "SELECT t, state, dst, sport, dport FROM attention WHERE t >= ? AND t < ? ORDER BY t", (a, b)
    ).fetchall()
    for t, state, dst, sport, dport in rows:
        rep = states.get(state)
        if rep is None:
            continue
        rep.samples += 1
        if _state_at(pieces, t) != state:
            rep.other_state += 1
        name, size = _named(conn, t, dst, sport, dport)
        kind = appfront.classify(profile, name) if name else None
        key = kind.domain if kind else queries.acr_cell(None, dst)
        svc = by.get((state, key))
        if svc is None:
            svc = by[(state, key)] = Service(
                key,
                companies.company(name) if name else None,
                kind.cls if kind else appfront.UNCLASSIFIED,
                kind.category if kind else "",
            )
            rep.services.append(svc)
        svc.conns += 1
        svc.bytes += size
        rep.bytes += size
        svc.essential = svc.essential or (kind is not None and kind.cls == appfront.PLATFORM)
        if _answered(conn, dst, t - queries.FEEDER_LATE, t + 0.5) is not None:
            svc.late += 1
        if any(0 <= end - t <= LEAD for end in ends.get(state, [])):
            svc.lead += 1
    for rep in states.values():
        rep.services.sort(key=lambda x: (not x.essential, -x.conns, -x.bytes, x.key))
    return states


def outside(states: dict[str, StateReport]) -> list[str]:
    """The services a wall would have refused in the walled states, most connections first: what the plain
    line names. An essential the platform set missed is not one (it is a fault to fix, not a service to
    refuse), nor a service whose every connection came just before the TV said the state ended."""
    seen: dict[str, int] = {}
    for s in WALLED:
        for x in states[s].services:
            if not x.essential and x.lead < x.conns:
                seen[x.key] = seen.get(x.key, 0) + x.conns
    return sorted(seen, key=lambda k: (-seen[k], k))


def report(
    conn: sqlite3.Connection, a: float, b: float, profile: Profile, times: bool = False
) -> dict | None:
    """The brief's "Attention" section for [a, b): per counted state, how long the live record has the TV
    in it, the kernel's count, and the services behind the samples, each with its company, class,
    connections and bytes, and three marks: `essential` (an address of one of the TV's essentials the
    platform set did not hold: a wall would have refused something the TV needs), `late` (within
    FEEDER_LATE of the answer that named it: the passive feeder's race) and `lead` (within LEAD seconds
    before the TV said the state ended: the next app starting before the TV reported it). `outside` lists
    what the plain line names. On a calendar day also `days_running` and `new_services`, for the plain
    line's repeat rule. None when the window holds no count of this kind at all, so every other gateway's
    brief and JSON are what they were. The time in each state (`seconds`) only with `times`, for an
    interactive run: a persisted report would keep the live record's time past TV_EVENTS_DAYS."""
    if not _has_data(conn, a, b):
        return None
    states = _states(conn, a, b, profile)
    found = outside(states)
    run, new = _run(conn, a, b, profile, set(found))
    shown = {s: asdict(r) for s, r in states.items()}
    if not times:
        for rep in shown.values():
            del rep["seconds"]
    return {
        "states": shown,
        "outside": found,
        "days_running": run,
        "new_services": new,
    }


def _run(
    conn: sqlite3.Connection, a: float, b: float, profile: Profile, keys: set[str]
) -> tuple[int | None, bool]:
    """(days running, a new service) for a calendar day whose walled states reached a service outside the
    essentials: the days in a row (this one included, up to REPEAT_DAYS + 1) that did, and whether this
    day has a service none of those earlier days had (queries.standby_notice's rule)."""
    day_long = b - a <= 90000 and datetime.fromtimestamp(a).time() == datetime.min.time()
    if not day_long or not keys:
        return None, True
    run, seen, day = 1, set(), a
    while run <= queries.REPEAT_DAYS:
        start = (datetime.fromtimestamp(day) - timedelta(days=1)).timestamp()
        found = set(outside(_states(conn, start, day, profile))) if _has_data(conn, start, day) else set()
        if not found:
            break
        seen |= found
        run, day = run + 1, start
    return run, bool(keys - seen)
