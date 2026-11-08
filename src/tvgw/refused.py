"""(refused) `tvgw refused`: what the filter refused the TV in the last minutes, the likeliest cause first.

When an app stops working, the question is which name it was refused, now. The store cannot answer
it: the hourly ingest copies AdGuard Home's query log into it up to an hour late. So this reads the
log itself, two ways, either of which is enough: the file AdGuard appends to, read backwards from its
end (`adguard.records_since()`), and the newest pages of AdGuard's API (`aghinstall.querylog()`),
which also hold the lookups AdGuard keeps in memory before it writes them (`querylog.size_memory`).
While AdGuard restarts, the file still says what it says, and the report says AdGuard was not asked.

Each name refused in the window is ranked so the likeliest cause of a broken app comes first: a name
the profile says the TV needs (a must-allow host, a name the URL filter answers, a clock host), then a
refusal the record has not seen before (first sight: its rule had refused no name under the same
registrable domain, or title zone, before; one the filter let through before ahead of one the TV
never asked for), then by retries, the lookups refused in the window. A known tracker
(`plain.is_tracking`) ranks below everything else and is never on its own the likely cause: an app
rarely stops for want of an ad host. "Before" is the store, opened read-only, and the log between the
store's newest lookup and the window. A likely cause comes with its count, when it started, its kind,
the rule that decided and where it comes from (`namecheck.source()`), the company behind it where the
snapshot knows it (`companies`) and the fix `tvgw check` would give (`namecheck.fix()`); every other
name gets one line without a fix, since a privacy gateway does not hand out an unblock for what it
refuses on purpose. Lookups of the record types the TV goes without (`profile.HARMLESS_QTYPES`) break
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
from tvgw.names import is_public_name, registrable_domain
from tvgw.profile import HARMLESS_QTYPES, Profile, covers

# exit statuses, as `tvgw check` uses them: nothing likely to have broken an app (nothing refused, only
# names refused before too, or known trackers); a name the TV needs, or a refusal the record has not
# seen before that is no known tracker; no log could be read and AdGuard could not be asked
NOTHING_NEW, LIKELY, UNREAD = 0, 1, 2
WINDOW = 600.0  # seconds: the window when `--since` gives none (10 minutes)
MAX_WINDOW = 86400.0  # a longer window is a question for the store: `tvgw retries`
# pages of the API's query log asked for, newest first, API_LIMIT entries each: the file holds everything
# older, so a busy window loses nothing when the pages run out first
API_PAGES = 4
API_LIMIT = aghinstall.QUERYLOG_LIMIT
# names under one domain the store is asked about for a domain's history, the most recently seen first:
# a tracker's domain has a handful, and a video domain's thousands are cut here
DOMAIN_NAMES = 200
SHOWN_LIKELY = 10  # names ranked likely, in full, before "and N more"
SHOWN_OTHERS = 5  # the other names, one line each, before "and N more" (`--all` shows all)
TITLE = "<title>"  # what stands for the labels of a title-bearing name under NAME_HMAC=on
DOCTOR_NEXT = "If an app stopped working, run sudo tvgw doctor, which checks the rest of the gateway."
# the TV keeps a refusal for the answer's TTL (adguardcfg's blocked_response_ttl, 60 seconds), so a fix
# takes a minute to reach an app
AFTER_FIX = "After the fix, wait a minute, then try the app again."
# the last line under the names that are not a likely cause, which carry no fix line unless --all asks:
# whoever means to let one through finds the command there, beside why the name is refused
WHY_CHECK = (
    "To see why one of these is refused, and how to let it through if you mean to: sudo tvgw check <name>"
)
# the rule sources that make a refusal one the gateway makes on purpose: the profile and the lists it
# subscribes to (`namecheck.Source.kind`); a tracking category is on purpose whatever refused it
ON_PURPOSE = ("profile", "list")
ON_PURPOSE_WORDS = "Refused on purpose"
UNLIKELY = "unlikely to break an app"
# what refused a name, in plain words, by `namecheck.Source.kind`, for a refusal that is not on purpose
REFUSED_BY = {
    "local": "Refused by your own rule",
    "machine": "Refused by a rule the gateway added on its own",
    "feature": "Refused by one of AdGuard Home's own features",
    "unplanned": "Refused by a rule in none of tvgw's files",
}
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
    domain: str = ""  # its registrable domain, or its title zone: what first sight is judged on
    first_refused: float | None = None  # before the window, by its rule under its domain; None: first sight
    by_domain: bool = False  # first_refused is another name's under the domain, by the same rule
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
    def tracking(self) -> bool:
        """A known tracking category: ACR, ads, telemetry, fingerprinting (`plain.is_tracking`)."""
        return plain.is_tracking(self.category)

    @property
    def likely(self) -> bool:
        """A likely cause of a broken app: a name the TV needs, or a first sight that is no tracker."""
        return self.needed is not None or (self.first_sight and not self.tracking)

    @property
    def on_purpose(self) -> bool:
        """Refused as the gateway means to refuse it: a tracking category, or a rule of the profile or of
        a list it subscribes to."""
        return self.tracking or (self.source is not None and self.source.kind in ON_PURPOSE)


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
    history_complete: bool = True  # the log was read back to the store's newest lookup, or to its start
    history_from: float | None = None  # how far back "before" reaches
    used_store: bool = False
    top_notes: list[str] = field(default_factory=list)  # what weakens the ranking: under the first line
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
    The page's `oldest` decides (internal/querylog/search.go at the pinned tag): it is the oldest entry
    the page holds, or, on a page with none, where AdGuard's scan of its file stopped, which it caps at
    50,000 lines a request; it is empty once AdGuard has nothing older. So an empty `oldest` is the end
    of the log, an `oldest` before `since` reaches the window, and any other is followed with
    `older_than`, an empty page included. An `oldest` that cannot be read cannot be followed."""
    found: list[adguard.DnsRecord] = []
    older = ""
    for _ in range(pages):
        page = ask(older)
        for e in page.get("data") or []:
            r = adguard.parse_api_entry(e, client=client)
            if r is not None and r.t >= since:
                found.append(r)
        raw = str(page.get("oldest") or "")
        if not raw:
            return found, True
        oldest = adguard.parse_time(raw)
        if oldest is None:
            return found, False
        if oldest < since:
            return found, True
        older = raw
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


def _like(domain: str) -> str:
    """`%.<domain>` for LIKE ... ESCAPE '\\': a name under the domain, its `_` and `%` taken literally."""
    return "%." + domain.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")


def domain_history(
    conn: sqlite3.Connection, domain: str, rule: str | None, before: float, exclude: str
) -> float | None:
    """When `rule` first refused another name under `domain` in the store before `before`, or None. The
    names come from `hosts` (one row per name the ingest has seen, title tags included), those its last
    lookup was refused, the DOMAIN_NAMES most recently seen; each is then asked by the (qname, t) index,
    so no query reads the whole of `dns`."""
    names = [
        r[0]
        for r in conn.execute(
            "SELECT name FROM hosts WHERE (name = ? OR name LIKE ? ESCAPE '\\') AND last_blocked = 1"
            " AND name != ? ORDER BY last_seen DESC LIMIT ?",
            (domain, _like(domain), exclude, DOMAIN_NAMES),
        )
    ]
    firsts = []
    for name in names:
        row = conn.execute(
            f"SELECT t FROM dns WHERE qname = ? AND t < ? AND blocked = 1 AND rule IS ? AND {_NOT_HARMLESS}"
            " ORDER BY t LIMIT 1",
            (name, before, rule, *_HARMLESS),
        ).fetchone()
        if row is not None:
            firsts.append(row[0])
    return min(firsts, default=None)


def _store(path: str) -> tuple[sqlite3.Connection | None, float | None, float | None, str | None]:
    """(the store read-only, its newest and oldest lookup, why it could not be read). No store yet is
    no store and no reason: a gateway's first hour. MAX and MIN apart, each one step of the t index."""
    if not os.path.exists(path):
        return None, None, None, None
    conn = None
    try:
        conn = db.connect(path, readonly=True, timeout=5)
        newest = conn.execute("SELECT MAX(t) FROM dns").fetchone()[0]
        oldest = conn.execute("SELECT MIN(t) FROM dns").fetchone()[0]
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
    """Needed first; known trackers last of all; then first sight (let through before, then never asked
    for), then the most retried, then the most recent, then by name, so the same window always reads
    the same."""
    return (
        n.needed is None,
        n.tracking,
        not n.first_sight,
        n.last_allowed is None,
        -n.lookups,
        -n.last,
        n.name,
    )


def _zone_of(name: str, zones: tuple[str, ...], protected: Callable[[str], bool]) -> str | None:
    """The title zone `name` sits under, as minimize.NameHasher finds it, or None."""
    for zone in zones:
        if name.endswith("." + zone) and not protected(name):
            return zone
    return None


def _refusal(r: adguard.DnsRecord) -> bool:
    return r.blocked and r.qtype.upper() not in HARMLESS_QTYPES


def _under(name: str, domain: str) -> bool:
    return name == domain or name.endswith("." + domain)


def _min(*ts: float | None) -> float | None:
    return min((t for t in ts if t is not None), default=None)


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
    answers for its rows older than `since`, the window's start. A refusal is first seen when neither
    the name nor, by the same rule, another name under its registrable domain or title zone was refused
    before: a rotating name under a rule that has refused its domain for a month is no news.
    sqlite3.Error is the caller's."""
    zones = minimize.title_zones(prof) if s.name_hmac == "on" else ()
    protected = minimize.protected_names(prof)
    hidden, masked = 0, False
    by: dict[str, Name] = {}
    for r in window:
        if not _refusal(r):
            continue
        if not is_public_name(r.qname):
            hidden += 1
            continue
        zone = _zone_of(r.qname, zones, protected)
        shown = f"{TITLE}.{zone}" if zone else r.qname
        masked = masked or zone is not None
        reason = adguard.API_REASONS.get(r.reason, r.reason)
        n = by.get(shown)
        if n is None:
            domain = zone or registrable_domain(r.qname)
            by[shown] = Name(shown, 1, r.t, r.t, reason, r.rule, r.filter_id, domain=domain)
            continue
        n.lookups += 1
        n.first = min(n.first, r.t)
        if r.t >= n.last:  # the newest lookup's rule is the one that decides now
            n.last, n.reason, n.rule, n.filter_id = r.t, reason, r.rule, r.filter_id
    earlier: dict[str, list[adguard.DnsRecord]] = defaultdict(list)
    by_rule: dict[str | None, list[adguard.DnsRecord]] = defaultdict(list)  # the earlier refusals
    for b in before:
        zone = _zone_of(b.qname, zones, protected)
        earlier[f"{TITLE}.{zone}" if zone else b.qname].append(b)
        if _refusal(b):
            by_rule[b.rule].append(b)
    for shown, n in by.items():
        title = shown.startswith(TITLE + ".")
        mine = earlier.get(shown, [])
        exact = _min(*(b.t for b in mine if _refusal(b)))
        allowed = max((b.t for b in mine if not b.blocked), default=None)
        seen = bool(mine)
        siblings = _min(*(b.t for b in by_rule[n.rule] if b.qname != shown and _under(b.qname, n.domain)))
        if conn is not None:
            if not title:  # the store keeps a title-bearing name tagged, never by its name
                first, last, in_store = store_history(conn, shown, since)
                exact = _min(exact, first)
                allowed = allowed if last is None else max(last, allowed or last)
                seen = seen or in_store
            siblings = _min(siblings, domain_history(conn, n.domain, n.rule, since, shown))
        n.first_refused = _min(exact, siblings)
        n.by_domain = exact is None and siblings is not None
        n.last_allowed = allowed if n.first_refused is None else None
        n.seen_before = seen
        target = n.domain if title else shown
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
        rep.history_complete = reached
    except OSError as e:
        file_error = e.strerror or str(e)
    api: list[adguard.DnsRecord] = []
    api_error, no_password = None, False
    try:
        user, password = aghinstall.credentials(cfg, admin=admin or aghinstall.ADMIN_FILE, ask=ask)
        base, one = aghinstall.page_base(cfg), page or aghinstall.querylog

        def ask_page(older: str) -> dict:
            return one(base, user, password, client=s.tv_ip, older_than=older, limit=API_LIMIT)

        api, reached = api_records(ask_page, since, s.tv_ip)
        rep.asked = True
        rep.complete = rep.complete or reached
    except aghinstall.AskError as e:
        api_error, no_password = str(e), isinstance(e, aghinstall.NoPassword)
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
    if no_password:
        rep.notes.append(
            "To let tvgw ask AdGuard Home for its newest lookups, run this at a terminal, which asks for"
            " AdGuard Home's password and keeps it nowhere, or keep the password in"
            f" {aghinstall.ADMIN_FILE}"
            " (two lines, user=<name> and password=<password>; edit the file with sudoedit). This time it"
            " read the query log file alone, so the last few lookups AdGuard Home has not written down yet"
            " may be missing."
        )
    elif api_error is not None:
        rep.notes.append(
            "Run this again in a minute to see the newest lookups too: AdGuard Home did not answer, so the"
            f" last few it has not written down yet may be missing ({api_error})."
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
    _history_notes(rep, store_error, records)
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


def _history_notes(rep: Report, store_error: str | None, records: list[adguard.DnsRecord]) -> None:
    """What makes "first time" weaker than it reads, said under the first line: no store to compare
    with, or a log read that stopped short of the store's newest lookup."""
    now = rep.until
    if not rep.used_store:
        cause = (
            f"the gateway's record could not be read ({store_error})"
            if store_error
            else "the gateway has no record yet"
        )
        if rep.history_from is None:
            rep.top_notes.append(
                f"Nothing before this window could be read, since {cause}: every name counts as refused"
                " for the first time."
            )
        else:
            rep.top_notes.append(
                f'"Before" goes back only to {clock(rep.history_from, now)}, the oldest lookup in the query'
                f" log, since {cause}."
            )
    elif not rep.history_complete and records:
        rep.top_notes.append(
            f"The query log could be read back only to {clock(records[0].t, now)}, short of the gateway's"
            ' record: lookups between the two are not part of "before".'
        )


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


def why(n: Name, now: float, start: float | None) -> str:
    """Why a likely name is ranked where it is, in a clause or two, never claiming more than the record
    holds: `start` is where "before" begins (Report.history_from), None when nothing before the window
    could be read."""
    parts = [n.needed] if n.needed else []
    if n.first_sight:
        if start is None:
            parts.append("nothing before this window could be read to compare it with")
        elif n.last_allowed is not None:
            parts.append(
                f"the filter let it through until {clock(n.last_allowed, now)}, and its rule refused no name"
                f" under {n.domain} in the record since {day(start, now)}"
            )
        elif not n.seen_before:
            parts.append(f"it is not in the record since {day(start, now)}")
        else:
            parts.append(f"its rule refused no name under {n.domain} in the record since {day(start, now)}")
    return "; ".join(parts)


def _rule(n: Name) -> str:
    return n.source.line if n.source else "unknown"


def refused_by(n: Name) -> str:
    """Why a name that is no likely cause is refused, in plain words: on purpose, and so unlikely to
    break an app, or by whose rule."""
    if n.on_purpose:
        return f"{ON_PURPOSE_WORDS}, {UNLIKELY}"
    return REFUSED_BY.get(n.source.kind if n.source else "", "Refused")


def _history(n: Name, now: float) -> str:
    """How long a name that is no likely cause has been refused, after its count."""
    if n.first_refused is None:
        return f" since {clock(n.first, now)}, new"
    if n.by_domain:
        return f"; its rule has refused names under {n.domain} since {day(n.first_refused, now)}"
    return f"; first refused {day(n.first_refused, now)}"


def _detail(n: Name, indent: str) -> list[str]:
    """The lines `tvgw check` prints for a blocked name, in the order the reader acts on them, with what
    the TV needs it for when the profile says."""
    lines = [f"{indent}Needed for: {n.needed_for}"] if n.needed_for else []
    lines += [f"{indent}Fix: {n.fix}", f"{indent}Rule: {_rule(n)}", f"{indent}Kind: {n.kind}"]
    return lines + ([f"{indent}Company: {n.company}"] if n.company else [])


def render(rep: Report, show_all: bool = False) -> list[str]:
    """The report in plain words: the likeliest cause, or that there is none, on the first line, and
    under it whatever weakens the ranking (Report.top_notes)."""
    now, start = rep.until, rep.history_from
    window = f"the last {span(rep.since, now)}"
    likely = [n for n in rep.names if n.likely]
    others = [n for n in rep.names if not n.likely]
    top_notes = [f"  Note: {note}" for note in rep.top_notes]
    out: list[str] = []
    if likely:
        top = likely[0]
        started = clock(top.first, now)
        out.append(f"Most likely cause: {top.name}, refused {_times(top.lookups)} since {started}.")
        out += top_notes
        out.append(f"  Why it is first: {why(top, now, start)}.")
        out += _detail(top, "  ")
        if top.fix.startswith(("sudo tvgw allow", "sudo tvgw unblock")):
            out.append(f"  {AFTER_FIX}")
        rest = likely[1:] if show_all else likely[1:SHOWN_LIKELY]
        if rest:
            out += ["", f"Also new, or needed by the TV, in {window}:"]
            for n in rest:
                started = clock(n.first, now)
                out.append(f"  {n.name}, refused {_times(n.lookups)} since {started}: {why(n, now, start)}.")
                out += _detail(n, "    ")
        if len(likely) - 1 > len(rest):
            out.append(f"  and {len(likely) - 1 - len(rest)} more: sudo tvgw refused --all lists every one.")
    elif others:
        names = "name below" if len(others) == 1 else f"{len(others):,} names below"
        if any(n.first_sight for n in others):  # a new tracker, refused on purpose
            out.append(
                f"Nothing likely to break an app was refused for the TV in {window}: the {names}"
                f" {'is a tracker' if len(others) == 1 else 'are trackers'} refused on purpose, or"
                f" {'was' if len(others) == 1 else 'were'} refused before too."
            )
        else:
            out.append(
                f"Nothing new was refused for the TV in {window}: the {names}"
                f" {'was' if len(others) == 1 else 'were'} refused before too, so"
                f" {'it is' if len(others) == 1 else 'they are'} probably not why an app stopped."
            )
        out += top_notes
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
        out += ["", "Also refused, and probably not the cause:" if likely else "What was refused:"]
        for n in shown:
            company = f" Company: {n.company}." if n.company else ""
            out.append(
                f"  {n.name}, refused {_times(n.lookups)}{_history(n, now)}. {refused_by(n)}: {n.kind}."
                f"{company}"
            )
            if show_all:  # a fix for a name refused on purpose only for whoever asks for every one
                out.append(f"    Rule: {_rule(n)}. Fix: {n.fix}")
        if len(others) > len(shown):
            out.append(f"  and {len(others) - len(shown)} more: sudo tvgw refused --all lists every one.")
        if not show_all:
            out.append(WHY_CHECK)
    if rep.notes:
        out.append("")
        out += [f"Note: {note}" for note in rep.notes]
    read = "AdGuard Home's query log" if rep.read_log else "AdGuard Home's page"
    out += ["", f"tvgw refused read {read} from {clock(rep.since, now)} to {clock(now, now)}; {SAID}"]
    return out


def as_json(rep: Report) -> dict:
    """The report for tools: every name, ranked, with every field, its fix included; no client, answer
    or address."""
    return {
        "since": rep.since,
        "until": rep.until,
        "lookups": rep.lookups,
        "asked_adguard": rep.asked,
        "read_log": rep.read_log,
        "complete": rep.complete,
        "history_complete": rep.history_complete,
        "history_from": rep.history_from,
        "hidden_lookups": rep.hidden,
        "notes": [*rep.top_notes, *rep.notes],
        "names": [
            {
                "name": n.name,
                "lookups": n.lookups,
                "first": n.first,
                "last": n.last,
                "likely": n.likely,
                "tracking": n.tracking,
                "on_purpose": n.on_purpose,
                "first_sight": n.first_sight,
                "first_refused": n.first_refused,
                "domain": n.domain,
                "by_domain": n.by_domain,
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
