"""(refused) `tvgw refused`: what the filter refused the TV in the last minutes, the likeliest cause first.

When an app stops working, the question is which name it was refused, now. The store cannot answer
it: the hourly ingest copies AdGuard Home's query log into it up to an hour late. So this reads the
log itself, two ways, either of which is enough: the file AdGuard appends to, read backwards from its
end (`adguard.records_since()`), and the newest pages of AdGuard's API (`aghinstall.querylog()`),
which also hold the lookups AdGuard keeps in memory before it writes them (`querylog.size_memory`).
While AdGuard restarts, the file still says what it says, and the report says AdGuard was not asked.

Each name refused in the window is ranked so the likeliest cause of a broken app comes first: a name
the profile says the TV needs (a must-allow host, a name the URL filter answers, a clock host), then a
name refused for the first time (first sight; one the filter let through before ahead of one the TV
never asked for), then by retries, the lookups refused in the window. "Before" is the store, opened
read-only, and the log between the store's newest lookup and the window. Each name comes with its
count, when it started, its kind, the rule that decided and where it comes from (`namecheck.source()`),
the company behind it where the snapshot knows it (`companies`) and the fix `tvgw check` would give
(`namecheck.fix()`). Lookups of the record types the TV goes without (`profile.HARMLESS_QTYPES`) break
nothing when refused, and are left out.

Nothing is written anywhere: the store is opened `mode=ro`, AdGuard is only asked, and no key, cache
or file is made. A name that is not an internet name (the home network's own names, an address, a
malformed name) is counted, never shown; with `NAME_HMAC=on` a name that carries a title is shown by
its zone alone, as the store keeps it.
"""

from __future__ import annotations

import fnmatch
import os
import sqlite3
from collections import defaultdict
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import datetime

import yaml

from tvgw import adguard, adguardcfg, aghinstall, companies, db, minimize, namecheck, plain
from tvgw.config import Settings
from tvgw.names import is_public_name
from tvgw.profile import HARMLESS_QTYPES, Profile, covers

# exit statuses, as `tvgw check` uses them: nothing likely to have broken an app (nothing refused, or
# only names refused before too); a name refused that the TV needs or that was never refused before;
# no log could be read and AdGuard could not be asked
NOTHING_NEW, LIKELY, UNREAD = 0, 1, 2
WINDOW = 600.0  # seconds: the window when `--since` gives none (10 minutes)
MAX_WINDOW = 86400.0  # a longer window is a question for the store: `tvgw retries`
# pages of the API's query log asked for, newest first, aghinstall.QUERYLOG_LIMIT entries each: the file
# holds everything older, so a busy window loses nothing when the pages run out first
API_PAGES = 4
SHOWN_LIKELY = 10  # names ranked likely, in full, before "and N more"
SHOWN_OTHERS = 5  # names refused before too, two lines each, before "and N more" (`--all` shows all)
TITLE = "<title>"  # what stands for the labels of a title-bearing name under NAME_HMAC=on
DOCTOR_NEXT = "If an app stopped working, run sudo tvgw doctor, which checks the rest of the gateway."
# the TV keeps a refusal for the answer's TTL (adguardcfg's blocked_response_ttl, 60 seconds), so a fix
# takes a minute to reach an app
AFTER_FIX = "After the fix, wait a minute, then try the app again."
SAID = "it blocked nothing and changed nothing."
_HARMLESS = tuple(sorted(HARMLESS_QTYPES))
_NOT_HARMLESS = f"qtype NOT IN ({', '.join('?' * len(_HARMLESS))})"


@dataclass
class Name:
    """One refused name, with what the report says of it."""

    name: str  # as shown: the lookup's name, or TITLE.<zone> under NAME_HMAC=on
    lookups: int  # refused in the window: the retries
    first: float  # the window's first refused lookup
    last: float
    reason: str  # AdGuard's reason, as its API names it
    rule: str | None
    filter_id: int | None
    first_refused: float | None = None  # before the window; None is first sight
    last_allowed: float | None = None  # before the window, the newest lookup the filter let through
    seen_before: bool = False
    needed: str | None = None  # why the profile says the TV needs it, in a clause
    needed_for: str | None = None  # (a must-allow host) what for, in the profile's words
    category: str = ""
    kind: str = ""
    source: namecheck.Source | None = None
    company: str | None = None
    fix: str = ""

    @property
    def first_sight(self) -> bool:
        return self.first_refused is None

    @property
    def likely(self) -> bool:
        return self.needed is not None or self.first_sight


@dataclass
class Report:
    since: float
    until: float
    names: list[Name] = field(default_factory=list)  # ranked
    lookups: int = 0  # every lookup the TV made in the window, refused or not
    hidden: int = 0  # refused lookups of names that are not internet names
    asked: bool = False  # AdGuard's API answered
    read_log: bool = False  # the log file, or its rotated copy, was there and read
    complete: bool = False  # the window was read back to its start, by the file or by the API
    history_from: float | None = None  # how far back "before" reaches
    used_store: bool = False
    notes: list[str] = field(default_factory=list)
    masked: bool = False  # a title-bearing name is shown by its zone

    @property
    def code(self) -> int:
        return LIKELY if any(n.likely for n in self.names) else NOTHING_NEW


@dataclass
class Outcome:
    """The exit status, with the report, or the one line that says why there is none."""

    code: int
    lines: list[str] = field(default_factory=list)
    report: Report | None = None


# ---- reading -----------------------------------------------------------------------------------------


def _key(r: adguard.DnsRecord) -> tuple[int, str, str]:
    """One lookup, whichever reader gave it: the file's `T` and the API's `time` are the same text."""
    return round(r.t * 1e6), r.qname, r.qtype


def api_records(
    ask: Callable[[str], dict], since: float, client: str, pages: int = API_PAGES
) -> tuple[list[adguard.DnsRecord], bool]:
    """The client's lookups from `since` on in the API's newest pages, and whether the pages reached
    `since`. `ask(older_than)` returns one page (`aghinstall.querylog()`); its AskError is the caller's.
    A page with nothing in it ends the log; a page whose `oldest` cannot be read cannot be followed."""
    found: list[adguard.DnsRecord] = []
    older = ""
    for _ in range(pages):
        page = ask(older)
        entries = page.get("data") or []
        for e in entries:
            r = adguard.parse_api_entry(e, client=client)
            if r is not None and r.t >= since:
                found.append(r)
        if not entries:
            return found, True
        oldest = adguard.parse_time(str(page.get("oldest") or ""))
        if oldest is None:
            return found, False
        if oldest < since:
            return found, True
        older = str(page["oldest"])
    return found, False


def store_history(
    conn: sqlite3.Connection, name: str, before: float
) -> tuple[float | None, float | None, bool]:
    """(first refused, last let through, seen at all) of `name` in the store before `before`. The first
    refusal is the oldest blocked row of a record type that matters, found from the oldest end of the
    name's rows by the (qname, t) index; only a name never refused is asked for its newest allowed row."""
    row = conn.execute(
        f"SELECT t FROM dns WHERE qname = ? AND t < ? AND blocked = 1 AND {_NOT_HARMLESS} ORDER BY t LIMIT 1",
        (name, before, *_HARMLESS),
    ).fetchone()
    if row is not None:
        return row[0], None, True
    last = conn.execute(
        "SELECT MAX(t) FROM dns WHERE qname = ? AND t < ? AND blocked = 0", (name, before)
    ).fetchone()[0]
    if last is not None:
        return None, last, True
    seen = conn.execute("SELECT 1 FROM dns WHERE qname = ? AND t < ? LIMIT 1", (name, before)).fetchone()
    return None, None, seen is not None


def _store(path: str) -> tuple[sqlite3.Connection | None, float | None, float | None, str | None]:
    """(the store read-only, its newest and oldest lookup, why it could not be read). No store yet is
    no store and no reason: a gateway's first hour."""
    if not os.path.exists(path):
        return None, None, None, None
    conn = None
    try:
        conn = db.connect(path, readonly=True, timeout=5)
        newest, oldest = conn.execute("SELECT MAX(t), MIN(t) FROM dns").fetchone()
        return conn, newest, oldest, None
    except sqlite3.Error as e:
        if conn is not None:
            conn.close()
        return None, None, None, str(e)


# ---- judging -----------------------------------------------------------------------------------------


def needed(name: str, prof: Profile) -> tuple[str | None, str | None, bool]:
    """(why the TV needs `name`, in a clause; what for, in the must-allow list's words; whether the URL
    filter answers it). The first is None when the profile says nothing of it; the second is None but
    for a must-allow host."""
    must = next((why for host, why in prof.must_allow.items() if covers(host, name)), None)
    served = prof.url_filter is not None and any(covers(h, name) for h in prof.url_filter.hosts)
    if must is not None:
        return "the profile says the TV needs it", must, served
    if served:
        return "the gateway's URL filter answers it, so it should never be refused", None, True
    if any(fnmatch.fnmatchcase(name, pat) for pat in prof.clock_hosts):
        return "the TV sets its clock from names like it", None, False
    return None, None, False


def rank_key(n: Name) -> tuple:
    """Needed first, then first sight (let through before, then never asked for), then the most
    retried, then the most recent, then by name, so the same window always reads the same."""
    return (n.needed is None, not n.first_sight, n.last_allowed is None, -n.lookups, -n.last, n.name)


def _zone_of(name: str, zones: tuple[str, ...], protected: Callable[[str], bool]) -> str | None:
    """The title zone `name` sits under, as minimize.NameHasher finds it, or None."""
    for zone in zones:
        if name.endswith("." + zone) and not protected(name):
            return zone
    return None


def _refusal(r: adguard.DnsRecord) -> bool:
    return r.blocked and r.qtype.upper() not in HARMLESS_QTYPES


def judge(
    window: list[adguard.DnsRecord],
    before: list[adguard.DnsRecord],
    prof: Profile,
    s: Settings,
    groups: dict[str, list[str]],
    lists: dict[int, str],
    conn: sqlite3.Connection | None = None,
    since: float = 0.0,
) -> tuple[list[Name], int, bool]:
    """(the ranked names, the hidden lookups, whether a title-bearing name was shown by its zone) of the
    window's refusals. `before` is the log's records older than the window, and the store, when given,
    answers for its rows older than `since`, the window's start. sqlite3.Error is the caller's."""
    zones = minimize.title_zones(prof) if s.name_hmac == "on" else ()
    protected = minimize.protected_names(prof)
    hidden, masked = 0, False
    by: dict[str, Name] = {}
    zone_of: dict[str, str] = {}
    for r in window:
        if not _refusal(r):
            continue
        if not is_public_name(r.qname):
            hidden += 1
            continue
        zone = _zone_of(r.qname, zones, protected)
        shown = f"{TITLE}.{zone}" if zone else r.qname
        if zone:
            masked = True
            zone_of[shown] = zone
        reason = adguard.API_REASONS.get(r.reason, r.reason)
        n = by.get(shown)
        if n is None:
            by[shown] = Name(shown, 1, r.t, r.t, reason, r.rule, r.filter_id)
            continue
        n.lookups += 1
        n.first = min(n.first, r.t)
        if r.t >= n.last:  # the newest lookup's rule is the one that decides now
            n.last, n.reason, n.rule, n.filter_id = r.t, reason, r.rule, r.filter_id
    earlier: dict[str, list[adguard.DnsRecord]] = defaultdict(list)
    for b in before:
        zone = _zone_of(b.qname, zones, protected)
        earlier[f"{TITLE}.{zone}" if zone else b.qname].append(b)
    for shown, n in by.items():
        mine = earlier.get(shown, [])
        refused = [b.t for b in mine if _refusal(b)]
        allowed = [b.t for b in mine if not b.blocked]
        n.first_refused = min(refused, default=None)
        n.last_allowed = max(allowed, default=None) if n.first_refused is None else None
        n.seen_before = bool(mine)
        zone = zone_of.get(shown)
        if conn is not None and zone is None:  # the store keeps a title-bearing name tagged, not by name
            first, last, seen = store_history(conn, shown, since)
            if first is not None:
                n.first_refused = min(first, n.first_refused if n.first_refused is not None else first)
                n.last_allowed = None
            elif n.first_refused is None and last is not None:
                n.last_allowed = max(last, n.last_allowed if n.last_allowed is not None else last)
            n.seen_before = n.seen_before or seen
        target = zone or shown
        n.needed, n.needed_for, served = needed(target, prof)
        n.category = prof.categorize(target)
        n.kind = plain.category_label(n.category, prof)
        answer = {"reason": n.reason, "rules": [{"text": n.rule, "filter_list_id": n.filter_id}]}
        n.source = namecheck.source(answer, groups, lists, s)
        n.company = companies.company(target)
        n.fix = namecheck.fix(target, n.source, n.needed_for is not None, served, n.reason, prof)
    return sorted(by.values(), key=rank_key), hidden, masked


# ---- the report ----------------------------------------------------------------------------------------


def run(
    s: Settings,
    prof: Profile,
    since: float,
    now: float,
    ask: Callable[[str, bool], str] | None = None,
    page: Callable[..., dict] | None = None,
    admin: str | None = None,
) -> Outcome:
    """The report of the TV's refused lookups in [since, now). `ask` prompts for AdGuard's password when
    tvgw keeps none (None: nothing is asked); `page` stands in for `aghinstall.querylog()` and `admin`
    for its credentials file. Nothing is written."""
    try:
        cfg = adguardcfg.load_yaml(s.adguard_yaml)
    except FileNotFoundError:
        return Outcome(
            UNREAD,
            ["tvgw refused: AdGuard Home is not set up on this computer yet: sudo tvgw adguard install"],
        )
    except (OSError, yaml.YAMLError) as e:
        return Outcome(UNREAD, [f"tvgw refused: cannot read {s.adguard_yaml}: {e}"])
    log = cfg.get("querylog") if isinstance(cfg.get("querylog"), dict) else {}
    if log.get("enabled") is False:
        return Outcome(
            UNREAD,
            [
                "tvgw refused: AdGuard Home keeps no query log (querylog.enabled is false), so nothing says"
                " what it refused: sudo tvgw adguard apply turns it back on"
            ],
        )
    try:
        groups = adguardcfg.rule_groups(prof, s)
    except OSError as e:
        return Outcome(UNREAD, [f"tvgw refused: cannot read the rules tvgw plans: {e}"])
    rep = Report(since=since, until=now)
    conn, newest, oldest, store_error = _store(s.db_path)
    try:
        return _report(s, prof, cfg, log, groups, rep, conn, newest, oldest, store_error, ask, page, admin)
    finally:
        if conn is not None:
            conn.close()


def _report(s, prof, cfg, log, groups, rep, conn, newest, oldest, store_error, ask, page, admin) -> Outcome:
    since, now = rep.since, rep.until
    path = aghinstall.querylog_path(cfg, s)
    # the log is read back to the store's newest lookup, so "before" has no gap; with no store, as far
    # back as adguard.CLIENTS_MAX_BYTES of each file reaches
    read_from = min(since, newest) if newest is not None else 0.0
    records: list[adguard.DnsRecord] = []
    file_error = None
    try:
        records, reached = adguard.records_since(path, read_from, s.tv_ip)
        rep.read_log = os.path.exists(path) or os.path.exists(path + ".1")
        rep.complete = rep.read_log and (reached or bool(records and records[0].t <= since))
    except OSError as e:
        file_error = e.strerror or str(e)
    api: list[adguard.DnsRecord] = []
    api_error = None
    try:
        user, password = aghinstall.credentials(cfg, admin=admin or aghinstall.ADMIN_FILE, ask=ask)
        base, one = aghinstall.page_base(cfg), page or aghinstall.querylog

        def ask_page(older: str) -> dict:
            return one(base, user, password, client=s.tv_ip, older_than=older)

        api, reached = api_records(ask_page, since, s.tv_ip)
        rep.asked = True
        rep.complete = rep.complete or reached
    except aghinstall.AskError as e:
        api_error = str(e)
    if api_error is not None and not rep.read_log:
        why = f"cannot read it ({file_error})" if file_error else "it is not there"
        return Outcome(
            UNREAD,
            [
                f"tvgw refused: AdGuard Home's query log {path}: {why}, and AdGuard Home could not be"
                f" asked: {api_error}"
            ],
        )
    if file_error is not None:
        rep.notes.append(
            f"AdGuard Home's query log file could not be read ({file_error}): this is what its page holds."
        )
    elif log.get("file_enabled") is False:
        rep.notes.append(
            "AdGuard Home writes no query log file (querylog.file_enabled is false), so only its newest"
            " lookups are here: sudo tvgw adguard apply turns the file back on."
        )
    if api_error is not None:
        rep.notes.append(
            "AdGuard Home could not be asked for the lookups it has not written down yet, so the last few"
            f" may be missing: run this again in a minute. ({api_error})"
        )
    if not rep.complete:
        rep.notes.append(
            "The query log could not be read back to the start of this window: its oldest part is missing."
        )
    merged = {_key(r): r for r in records if r.t >= since}
    merged.update({_key(r): r for r in api})
    window = sorted((r for r in merged.values() if r.t < now), key=lambda r: r.t)
    before = [r for r in records if r.t < since]
    rep.lookups = len(window)
    names = namecheck.list_names(cfg, prof)
    try:
        rep.names, rep.hidden, rep.masked = judge(window, before, prof, s, groups, names, conn, since)
        rep.used_store = conn is not None
    except sqlite3.Error as e:  # a store that went away or locked up between reads: the log alone
        store_error = str(e)
        rep.names, rep.hidden, rep.masked = judge(window, before, prof, s, groups, names, None, since)
    starts = [before[0].t] if before else []
    starts += [oldest] if rep.used_store and oldest is not None else []
    rep.history_from = min(starts, default=None)
    if not rep.used_store:
        cause = (
            f"the gateway's record could not be read ({store_error})"
            if store_error
            else "the gateway has no record yet"
        )
        if rep.history_from is None:
            rep.notes.append(
                f"Nothing before this window could be read, since {cause}: every name counts as refused"
                " for the first time."
            )
        else:
            rep.notes.append(
                f'"Refused before" looks back only to {clock(rep.history_from, now)}, the oldest lookup'
                f" in the query log, since {cause}."
            )
    if rep.hidden:
        rep.notes.append(
            f"{_times(rep.hidden, 'lookup')} of names that are not internet names (the home network's own"
            f" names, addresses or malformed names) {'was' if rep.hidden == 1 else 'were'} refused too;"
            " such names are never shown."
        )
    if companies.trouble():
        rep.notes.append(f"The company names could not be read, so none is shown ({companies.trouble()}).")
    if rep.masked:
        rep.notes.append(
            "A name that carries what was on screen is shown by its zone alone, as NAME_HMAC=on asks."
        )
    return Outcome(rep.code, report=rep)


# ---- words -------------------------------------------------------------------------------------------


def _times(n: int, word: str = "time") -> str:
    return f"{n:,} {word if n == 1 else word + 's'}"


def _date(d: datetime, now: datetime) -> str:
    text = f"{d.day} {plain.MONTHS[d.month - 1]}"
    return text if d.year == now.year else f"{text} {d.year}"


def clock(t: float, now: float) -> str:
    """A moment: `20:33` today, `4 November 23:50` another day."""
    d, n = datetime.fromtimestamp(t), datetime.fromtimestamp(now)
    return d.strftime("%H:%M") if d.date() == n.date() else f"{_date(d, n)} {d:%H:%M}"


def day(t: float, now: float) -> str:
    """When something long-running began: `14:05` today, else the day alone, `2 October`."""
    d, n = datetime.fromtimestamp(t), datetime.fromtimestamp(now)
    return d.strftime("%H:%M") if d.date() == n.date() else _date(d, n)


def span(since: float, until: float) -> str:
    """The window's length in words: `10 minutes`, `2 hours`."""
    minutes = round((until - since) / 60)
    return _times(max(minutes, 1), "minute") if minutes < 120 else _times(round(minutes / 60), "hour")


def why(n: Name, now: float) -> str:
    """Why a likely name is ranked where it is, in a clause or two."""
    parts = [n.needed] if n.needed else []
    if n.first_sight and n.last_allowed is not None:
        until = clock(n.last_allowed, now)
        parts.append(f"the filter let it through until {until} and never refused it before")
    elif n.first_sight and not n.seen_before:
        parts.append("the TV never asked for it before")
    elif n.first_sight:
        parts.append("it was never refused before")
    return "; ".join(parts)


def _rule(n: Name) -> str:
    return n.source.line if n.source else "unknown"


def _detail(n: Name, indent: str) -> list[str]:
    """The lines `tvgw check` prints for a blocked name, in the order the reader acts on them, with what
    the TV needs it for when the profile says."""
    lines = [f"{indent}Needed for: {n.needed_for}"] if n.needed_for else []
    lines += [f"{indent}Fix: {n.fix}", f"{indent}Rule: {_rule(n)}", f"{indent}Kind: {n.kind}"]
    return lines + ([f"{indent}Company: {n.company}"] if n.company else [])


def render(rep: Report, show_all: bool = False) -> list[str]:
    """The report in plain words: the likeliest cause, or that there is none, on the first line."""
    now = rep.until
    window = f"the last {span(rep.since, now)}"
    likely = [n for n in rep.names if n.likely]
    others = [n for n in rep.names if not n.likely]
    out: list[str] = []
    if likely:
        top = likely[0]
        started = clock(top.first, now)
        out.append(f"Most likely cause: {top.name}, refused {_times(top.lookups)} since {started}.")
        out.append(f"  Why it is first: {why(top, now)}.")
        out += _detail(top, "  ")
        if top.fix.startswith(("sudo tvgw allow", "sudo tvgw unblock")):
            out.append(f"  {AFTER_FIX}")
        rest = likely[1:] if show_all else likely[1:SHOWN_LIKELY]
        if rest:
            out += ["", f"Also new, or needed by the TV, in {window}:"]
            for n in rest:
                started = clock(n.first, now)
                out.append(f"  {n.name}, refused {_times(n.lookups)} since {started}: {why(n, now)}.")
                out += _detail(n, "    ")
        if len(likely) - 1 > len(rest):
            out.append(f"  and {len(likely) - 1 - len(rest)} more: sudo tvgw refused --all lists every one.")
    elif others:
        those = "name below was" if len(others) == 1 else f"{len(others):,} names below were"
        out.append(
            f"Nothing new was refused for the TV in {window}: the {those} refused before too, so"
            f" {'it is' if len(others) == 1 else 'they are'} probably not why an app stopped."
        )
        out.append(DOCTOR_NEXT)
    elif not rep.lookups:
        out.append(
            f"The TV looked up nothing in {window}, so nothing was refused: it may be off, or its traffic may"
            " not be reaching the gateway."
        )
        out.append(DOCTOR_NEXT)
    else:
        out.append(f"Nothing was refused for the TV in {window}.")
        out.append(DOCTOR_NEXT)
    if others:
        shown = others if show_all else others[:SHOWN_OTHERS]
        out += ["", "Refused before too, so probably not the cause:" if likely else "Refused before too:"]
        for n in shown:
            company = f" Company: {n.company}." if n.company else ""
            began = day(n.first_refused, now) if n.first_refused is not None else clock(n.first, now)
            out.append(
                f"  {n.name}, refused {_times(n.lookups)}; first refused {began}. Kind: {n.kind}.{company}"
            )
            out.append(f"    Rule: {_rule(n)}. Fix: {n.fix}")
        if len(others) > len(shown):
            out.append(f"  and {len(others) - len(shown)} more: sudo tvgw refused --all lists every one.")
    if rep.notes:
        out.append("")
        out += [f"Note: {note}" for note in rep.notes]
    read = "AdGuard Home's query log" if rep.read_log else "AdGuard Home's page"
    out += ["", f"tvgw refused read {read} from {clock(rep.since, now)} to {clock(now, now)}; {SAID}"]
    return out


def as_json(rep: Report) -> dict:
    """The report for tools: every name, ranked, with every field; no client, answer or address."""
    return {
        "since": rep.since,
        "until": rep.until,
        "lookups": rep.lookups,
        "asked_adguard": rep.asked,
        "read_log": rep.read_log,
        "complete": rep.complete,
        "history_from": rep.history_from,
        "hidden_lookups": rep.hidden,
        "notes": rep.notes,
        "names": [
            {
                "name": n.name,
                "lookups": n.lookups,
                "first": n.first,
                "last": n.last,
                "likely": n.likely,
                "first_sight": n.first_sight,
                "first_refused": n.first_refused,
                "last_allowed": n.last_allowed,
                "seen_before": n.seen_before,
                "needed": n.needed,
                "needed_for": n.needed_for,
                "category": n.category,
                "kind": n.kind,
                "reason": n.reason,
                "rule": n.rule,
                "decided_by": n.source.kind if n.source else None,
                "decided": _rule(n),
                "company": n.company,
                "fix": n.fix,
            }
            for n in rep.names
        ],
    }
