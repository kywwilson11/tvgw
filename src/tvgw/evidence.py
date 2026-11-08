"""(evidence) `tvgw evidence`: a local file of the facts the gateway can show, one line a day, each line
chained to the one before it by SHA-256 (design decision 75).

The file is JSON lines, `<STATE_DIR>/evidence/evidence.jsonl`, root's alone (0600 in a 0700 directory).
Its first line is a header that says, for a reader who has never seen the gateway, what the lines are,
what was observed and what was estimated, and what the file cannot show. Every later line is one local
day: the TV's model and firmware, its consent readings, the tracking domains the filter refused and any
the TV reached, the uploads the ACR test flagged, the uploads over the budget, and how much record the
day has, so a quiet day can be told from a missed one. Names are registrable domains; there is no
address of the home, no time of day and no app.

Each line is written once, in a canonical form (`canonical()`: sorted keys, no spaces, ASCII), and holds
in `prev` the SHA-256 of the line before it (the header's is GENESIS). Changing, removing or inserting a
line breaks every `prev` after it, which `verify()` finds. Nothing is ever rewritten: a run appends the
settled days the file does not have yet, up to `--days` back, and refuses a file whose chain is broken.
The chain is not anchored anywhere: a timestamp from a public service would show that this home runs
the gateway at that moment, so that step is left to the owner, by hand, with the head hash the command
prints.

Nothing here sends anything or opens a connection. `tvgw forget` deletes the directory with the record.
"""

from __future__ import annotations

import contextlib
import fcntl
import hashlib
import json
import os
import sqlite3
from dataclasses import dataclass, field
from datetime import datetime, timedelta

from tvgw import budget, companies, plain, queries
from tvgw.names import is_public_address, is_public_name, registrable_domain
from tvgw.profile import Profile

DIR = "evidence"  # under STATE_DIR; forget.STATE_ENTRIES deletes it
NAME = "evidence.jsonl"
FORMAT, VERSION = "tvgw-evidence", 1
GENESIS = "0" * 64  # the `prev` of the header
DEFAULT_DAYS = 30
# a day is written once it has settled: an idle connection reaches the store up to 2 h 04 min after its
# last packet, and the daily files wait the same 3 h (budget.SETTLE)
SETTLE = budget.SETTLE
HEADER, DAY_KIND = "header", "day"
ABOUT = (
    "Each line after this one is one local day of facts that a home privacy gateway, tvgw, recorded about"
    " one television's network traffic, from its own record of that day.",
    "Each line holds in prev the SHA-256 of the exact text of the line before it. A line changed, removed"
    " or put in later breaks the chain from there on; tvgw evidence --verify checks it. The chain shows"
    " that no line was changed after the next one was written. It does not show when a line was written:"
    " nothing was sent to a timestamp service, since that would reveal the home.",
    "Observed: lookups the gateway's filter answered or refused; connections whose encrypted opening named"
    " a server; the TV's own readings of its settings and agreements.",
    "Estimated: net_up and payload_up, bytes sent beyond what came back, computed from packet and byte"
    " counts. They bound what was sent; they are not a reading of the content, which stays encrypted.",
    "A refused lookup is an attempt the gateway stopped: nothing went to that name through this gateway."
    " Because the gateway refuses trackers, a zero upload to them does not show what the TV would have done"
    " without it.",
    "Names are registrable domains (example.com), never full host names. There is no address of the home,"
    " no time of day and no app the household used.",
)


def canonical(obj: dict) -> str:
    """The one text a line may have: sorted keys, no spaces, ASCII only."""
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=True)


def digest(line: str) -> str:
    return hashlib.sha256(line.encode("ascii")).hexdigest()


def path_for(state_dir: str) -> str:
    return os.path.join(state_dir, DIR, NAME)


# ---- one day's facts ---------------------------------------------------------------------------------
def _latest(conn: sqlite3.Connection, key: str, until: float) -> str | None:
    row = conn.execute(
        "SELECT value FROM tvsettings WHERE key = ? AND t < ? ORDER BY t DESC LIMIT 1", (key, until)
    ).fetchone()
    return row[0] if row else None


def _consent(conn: sqlite3.Connection, a: float, b: float) -> dict:
    flags = {
        key.removeprefix("eula."): _latest(conn, key, b)
        for (key,) in conn.execute(
            "SELECT DISTINCT key FROM tvsettings WHERE key LIKE 'eula.%' AND t < ? ORDER BY key", (b,)
        )
    }
    return {
        "live_plus": _latest(conn, "option.livePlus", b),
        "flags": flags,
        "accepted_this_day": sorted({f["flag"] for f in queries.consent_flips(conn, a, b)}),
    }


def _trackers(conn: sqlite3.Connection, profile: Profile, a: float, b: float) -> list[dict]:
    """Per tracking domain (a category `plain.is_tracking()` names): lookups refused and answered, and
    the connections a hello named, with their net upload. Ordered by refused lookups."""
    found: dict[tuple[str, str], dict] = {}
    cat_cache: dict[str, str] = {}

    def entry(name: str) -> dict | None:
        if not name or not is_public_name(name):
            return None
        cat = cat_cache.get(name)
        if cat is None:
            cat = cat_cache[name] = profile.categorize(name)
        if not plain.is_tracking(cat):
            return None
        d = registrable_domain(name)
        return found.setdefault(
            (d, cat),
            {"domain": d, "category": cat, "company": companies.company(name), "refused_lookups": 0,
             "answered_lookups": 0, "connections": 0, "net_up": 0},
        )  # fmt: skip

    for qname, blocked, n in conn.execute(
        "SELECT qname, blocked, COUNT(*) FROM dns WHERE t >= ? AND t < ? GROUP BY qname, blocked", (a, b)
    ):
        e = entry(qname)
        if e is not None:
            e["refused_lookups" if blocked else "answered_lookups"] += n
    for name, dst, bu, pu, bd, pd in conn.execute(
        f"""SELECT {queries.FLOW_NAME}, f.dst, f.bytes_up, f.pkts_up, f.bytes_down, f.pkts_down FROM flows f
            WHERE f.t_start >= ? AND f.t_start < ?""",
        (a, b),
    ):
        e = entry(name) if is_public_address(dst) else None
        if e is not None:
            e["connections"] += 1
            e["net_up"] += budget.net_up(bu, pu, bd, pd)
    return sorted(found.values(), key=lambda e: (-e["refused_lookups"], -e["connections"], e["domain"]))


def _record(conn: sqlite3.Connection, a: float, b: float) -> dict:
    """How much record the day has: a day with none was not seen, not quiet."""

    def count(sql: str) -> int:
        return conn.execute(sql, (a, b)).fetchone()[0]

    tls443 = conn.execute(
        f"""SELECT COUNT(*), SUM({queries.FLOW_NAME} IS NOT NULL) FROM flows f
            WHERE f.t_start >= ? AND f.t_start < ? AND f.proto = 'tcp' AND f.dport = 443""",
        (a, b),
    ).fetchone()
    return {
        "lookups": count("SELECT COUNT(*) FROM dns WHERE t >= ? AND t < ?"),
        "connections": count("SELECT COUNT(*) FROM flows WHERE t_start >= ? AND t_start < ?"),
        "named_share": round((tls443[1] or 0) / tls443[0], 3) if tls443[0] else None,
        "tv_readings": count("SELECT COUNT(*) FROM tvstate WHERE t >= ? AND t < ?"),
    }


def day_facts(conn: sqlite3.Connection, profile: Profile, day: str, setting: str = "auto") -> dict:
    """The facts of one local calendar day, as a day line holds them."""
    a, b = queries.day_bounds(day)
    card = queries.tv_card(conn, b)
    acr = queries.acr_uploader(conn, a, b, profile)
    over = budget.report(conn, a, b, profile, setting)
    trackers = _trackers(conn, profile, a, b)
    facts = {
        "tv": {k: card[k] for k in ("model", "firmware") if k in card},
        "consent": _consent(conn, a, b),
        "trackers": trackers,
        "acr_test": [
            {
                "destination": f["key"],
                "port": f["dport"],
                "connections": f["conns"],
                "payload_up": f["payload_up"],
                "payload_down": f["payload_down"],
            }
            for f in acr
        ],
        "uploads_over_budget": {
            "ceiling": over["ceiling"],
            "source": over["source"],
            "over": [
                {"destination": e["key"], "connections": e["conns"], "net_up": e["net_up"]}
                for e in over["events"] + over["late"]
            ],
        },
        "record": _record(conn, a, b),
    }
    facts["summary"] = summary(facts)
    return facts


def _n(n: int, word: str) -> str:
    return f"{n} {word}{'' if n == 1 else 's'}"


def summary(facts: dict) -> str:
    """One plain sentence of what the day's facts say, for a reader of the file."""
    rec = facts["record"]
    if not rec["lookups"] and not rec["connections"]:
        return "The gateway recorded no lookup and no connection of the TV this day."
    t = facts["trackers"]
    refused = sum(e["refused_lookups"] for e in t)
    reached = [e for e in t if e["connections"]]
    domains = sum(1 for e in t if e["refused_lookups"])
    over = len(facts["uploads_over_budget"]["over"])
    parts = [
        f"The filter refused {_n(refused, 'lookup')} of {_n(domains, 'tracking domain')}",
        f"the TV reached {_n(len(reached), 'tracking domain')} on"
        f" {_n(sum(e['connections'] for e in reached), 'connection')}",
        f"the ACR test flagged {_n(len(facts['acr_test']), 'upload')}",
        f"{_n(over, 'destination')} {'was' if over == 1 else 'were'} sent more than the upload budget",
    ]
    flags = facts["consent"]["flags"]
    acr_true = sorted(k for k, v in flags.items() if v == "true" and k.lower().startswith("acr"))
    consent = (
        "no consent reading"
        if not flags and facts["consent"]["live_plus"] is None
        else ("ACR consent flags true: " + ", ".join(acr_true))
        if acr_true
        else "no ACR consent flag read as true"
    )
    return "; ".join(parts) + f"; {consent}."


# ---- the chain ---------------------------------------------------------------------------------------
@dataclass
class Verdict:
    ok: bool
    path: str
    lines: int = 0
    days: list[str] = field(default_factory=list)
    head: str | None = None  # the SHA-256 of the last line: what the owner may write down or anchor
    problem: str | None = None
    line: int | None = None  # the 1-based line the problem is on

    def as_json(self) -> dict:
        return {
            "ok": self.ok,
            "path": self.path,
            "lines": self.lines,
            "first_day": self.days[0] if self.days else None,
            "last_day": self.days[-1] if self.days else None,
            "days": len(self.days),
            "head": self.head,
            "problem": self.problem,
            "line": self.line,
        }


def check(text: str, path: str = "") -> Verdict:
    """The chain of a file's text: every line a JSON object in canonical form, the first a header with
    GENESIS, every later one a day after the one before it, each `prev` the SHA-256 of the line above."""
    if not text:
        return Verdict(False, path, problem="the file is empty")
    lines = text.split("\n")
    if lines[-1] != "":
        return Verdict(False, path, len(lines), problem="its last line is cut off (a write that did not end)",
                       line=len(lines))  # fmt: skip
    lines = lines[:-1]
    prev, days = GENESIS, []
    for i, line in enumerate(lines, 1):
        try:
            obj = json.loads(line)
        except ValueError:
            return Verdict(False, path, len(lines), days, problem="not a JSON line", line=i)
        if not isinstance(obj, dict) or line != canonical(obj):
            return Verdict(False, path, len(lines), days, problem="not in the canonical form", line=i)
        if obj.get("prev") != prev:
            return Verdict(
                False, path, len(lines), days, problem="its prev is not the SHA-256 of the line above", line=i
            )
        if i == 1 and (obj.get("kind") != HEADER or obj.get("format") != FORMAT):
            return Verdict(False, path, len(lines), days, problem="the first line is not the header", line=i)
        if i == 1 and obj.get("version") != VERSION:
            return Verdict(False, path, len(lines), days, problem="a version this tvgw does not know", line=i)
        if i > 1:
            day = obj.get("day")
            if obj.get("kind") != DAY_KIND or not isinstance(day, str) or not _is_day(day):
                return Verdict(False, path, len(lines), days, problem="not a day line", line=i)
            if days and day <= days[-1]:
                return Verdict(False, path, len(lines), days, problem="a day not after the one above", line=i)
            days.append(day)
        prev = digest(line)
    return Verdict(True, path, len(lines), days, head=prev)


def _is_day(day: str) -> bool:
    try:
        return datetime.strptime(day, "%Y-%m-%d").strftime("%Y-%m-%d") == day
    except ValueError:
        return False


def verify(path: str) -> Verdict:
    """The chain of the file at `path`; a missing or unreadable file is a problem, not an exception."""
    try:
        with open(path, encoding="ascii", newline="") as f:
            text = f.read()
    except FileNotFoundError:
        return Verdict(False, path, problem="there is no evidence file yet")
    except (OSError, UnicodeDecodeError) as e:
        return Verdict(False, path, problem=f"it cannot be read: {getattr(e, 'strerror', None) or e}")
    return check(text, path)


def due_days(last: str | None, now: float, days: int, record_from: float | None) -> list[str]:
    """The settled local days the file should gain: the `days` days before today whose end is SETTLE or
    more ago, after `last` (the file's newest day) and not before the day the store's record starts."""
    if record_from is None:
        return []
    today = datetime.fromtimestamp(now)
    out = []
    for back in range(days, 0, -1):
        d = (datetime(today.year, today.month, today.day) - timedelta(days=back)).strftime("%Y-%m-%d")
        _a, b = queries.day_bounds(d)
        if b + SETTLE > now or b <= record_from or (last is not None and d <= last):
            continue
        out.append(d)
    return out


def header(profile: Profile, now: float, version: str) -> dict:
    return {
        "kind": HEADER,
        "format": FORMAT,
        "version": VERSION,
        "prev": GENESIS,
        "made": datetime.fromtimestamp(now).strftime("%Y-%m-%d"),
        "tvgw": version,
        "profile": profile.name,
        "about": list(ABOUT),
    }


class BrokenChain(Exception):
    """The file's chain does not hold: nothing is appended to it."""

    def __init__(self, verdict: Verdict):
        super().__init__(verdict.problem)
        self.verdict = verdict


@dataclass
class Written:
    path: str
    days: list[str]
    head: str
    total: int  # day lines in the file after the run
    created: bool


def append(
    path: str,
    conn: sqlite3.Connection,
    profile: Profile,
    now: float,
    days: int,
    version: str,
    setting: str = "auto",
    record_from: float | None = None,
) -> Written:
    """Append the due days to the file at `path`, making it (with its header) when it is absent. Under an
    exclusive lock on the file; the chain is checked first and a broken one raises BrokenChain. Each line
    is flushed to disk before the run returns. `record_from` is when the store's record starts."""
    os.makedirs(os.path.dirname(path), mode=0o700, exist_ok=True)
    fd = os.open(path, os.O_RDWR | os.O_CREAT | os.O_APPEND, 0o600)
    with os.fdopen(fd, "r+", encoding="ascii", newline="") as f:
        fcntl.flock(f, fcntl.LOCK_EX)
        f.seek(0)
        text = f.read()
        created = text == ""
        lines: list[str] = []
        if created:
            lines.append(canonical(header(profile, now, version)))
            prev, last = digest(lines[0]), None
            verdict = Verdict(True, path, 1, [], head=prev)
        else:
            verdict = check(text, path)
            if not verdict.ok:
                raise BrokenChain(verdict)
            prev, last = verdict.head, (verdict.days[-1] if verdict.days else None)
        new_days = due_days(last, now, days, record_from)
        for d in new_days:
            line = canonical(
                {"kind": DAY_KIND, "prev": prev, "day": d, "profile": profile.name,
                 "facts": day_facts(conn, profile, d, setting)}
            )  # fmt: skip
            lines.append(line)
            prev = digest(line)
        if lines:
            f.write("".join(line + "\n" for line in lines))
            f.flush()
            os.fsync(f.fileno())
        if created:
            with contextlib.suppress(OSError):  # the new name must outlive a power cut too
                dfd = os.open(os.path.dirname(path), os.O_RDONLY)
                try:
                    os.fsync(dfd)
                finally:
                    os.close(dfd)
    return Written(path, new_days, prev, len(verdict.days) + len(new_days), created)
