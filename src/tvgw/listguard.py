"""(listguard) What a subscribed blocklist can do to the TV's own rules, and what each update of one changed
(design decision 68).

AdGuard Home downloads each subscribed list again every 24 hours and applies whatever it gets (design
decision 46). A list can do more than block. An exception (`@@`) in it lifts every block of the same name
that carries no `$important`, whichever list or custom rule the block sits in, and a `$badfilter` line
deletes the rule it names. The profile loads its red-line blocks with `$important` (`profile.held_rule`);
this module reads what the lists say, from the files AdGuard has already downloaded, and fetches nothing:

- `scan()` names every line of a subscribed list that acts on one of the TV's own rules: an exception that
  lifts a block of the profile or of the owner (`lifts`, as does a `$badfilter` line that deletes one), an
  exception the block's `$important` holds against (`held`), and a line that cancels a must-allow
  exception, an owner's allow or the URL filter's rewrite, or rewrites a must-allow name (`exposes`);
- `preview()` judges every name the TV asked for in the `PREVIEW_DAYS` before a list's update against the
  list as it was and as it is, with every other rule as it stands, and names each verdict that changed.
  AdGuard swaps a list in as soon as it has it, so the preview comes at the first hourly ingest after the
  change, from the copy of the list this module kept at the scan before;
- `Engine` is the model of AdGuard's precedence both rest on, for the rules tvgw and the lists use.

All of it is a report: nothing here changes what AdGuard does or what the TV may reach.
"""

from __future__ import annotations

import contextlib
import fcntl
import gzip
import hashlib
import ipaddress
import json
import os
import re
import sqlite3
import tempfile
import time
from collections import defaultdict
from collections.abc import Iterable
from dataclasses import dataclass, field

from tvgw import db
from tvgw.config import Settings
from tvgw.names import is_public_name, normalize
from tvgw.profile import Profile, covers, filled_names

# a finding's kind, most serious first: a line that opens a must-allow name or the URL filter's rewrite to
# a list's say, one that lifts a block of the TV's, and an exception the block's `$important` outranks
EXPOSES, LIFTS, HELD = "exposes", "lifts", "held"
KINDS = (EXPOSES, LIFTS, HELD)
# a rule's form: `||name^`, any other adblock pattern, a `/regex/`, and a hosts-file line (`0.0.0.0 name`,
# or a bare name), which AdGuard matches against the name alone and ranks below every other rule
HOST, PATTERN, REGEX, HOSTS = "host", "pattern", "regex", "hosts"
BLOCKED, ALLOWED, REWRITTEN, NONE = "blocked", "allowed", "rewritten", "none"
# the modifiers the model reads; AdGuard drops a rule with any other, and so does the model
KNOWN_MODS = frozenset({"important", "badfilter", "dnsrewrite", "dnstype", "client", "ctag", "denyallow"})
KNOWN_MODS |= {"match-case"}
# the answers a hosts-file line blocks with; any other address is an answer of its own (a rewrite)
BLOCKING_ADDRESSES = frozenset({"0.0.0.0", "127.0.0.1", "::", "::1"})
TV_TAGS = ("device_tv",)  # the tag adguardcfg.plan gives the TV's client
PREVIEW_DAYS = 14  # days of the TV's lookups a list's update is judged on
# a preview names what the TV looked up, a viewing record: kept this long in meta, and `tvgw forget`
# removes it (forget.META_FORGET)
PREVIEW_KEEP = 14 * 86400
SCAN_EVERY = 23 * 3600  # with nothing changed, the hourly ingest still scans once a day
GONE_KEEP = 90 * 86400  # a finding no list carries any more stays this long, for the briefs of its days
LINE_CAP = 200  # characters of a list's line a finding keeps
FINDINGS_CAP = 200  # findings kept from one scan, the most serious first
NAMES_CAP = 50  # names per direction in one preview
COPY_DIR = "lists"  # under STATE_DIR: the copy of each list the next preview compares with
META_KEY, PREVIEW_KEY = "list_guard", "list_preview"
_HOST_RULE = re.compile(r"\|\|([a-z0-9_-]+(?:\.[a-z0-9_-]+)*)\^")
_NAME = re.compile(r"[a-z0-9_-]+(?:\.[a-z0-9_-]+)+")


# ---- rules ----------------------------------------------------------------------------------------------
@dataclass(frozen=True)
class Rule:
    """One rule as AdGuard reads it, for a lookup of a name."""

    text: str  # the line as written
    exception: bool
    kind: str  # HOST | PATTERN | REGEX | HOSTS
    target: str  # HOST and HOSTS: the name; PATTERN: the pattern; REGEX: the expression
    mods: tuple[tuple[str, str], ...] = ()
    rx: re.Pattern[str] | None = field(default=None, compare=False)
    literal: str = ""  # PATTERN: a piece of text every name it matches contains, to skip the regex
    answer: str = ""  # HOSTS: the address a line that answers instead of blocking gives

    def mod(self, name: str) -> str | None:
        return next((v for k, v in self.mods if k == name), None)

    @property
    def important(self) -> bool:
        return self.mod("important") is not None

    @property
    def badfilter(self) -> bool:
        return self.mod("badfilter") is not None

    @property
    def rewrites(self) -> bool:
        """It answers with something of its own: `$dnsrewrite`, or a hosts-file line with an address."""
        return (self.mod("dnsrewrite") is not None and not self.exception) or bool(self.answer)

    def key(self) -> tuple:
        """What a `$badfilter` twin names: the same rule but for that modifier (urlfilter's
        `negatesBadfilter`: the pattern, the exception mark and every other modifier equal)."""
        return (
            self.exception,
            self.kind,
            self.target,
            frozenset(m for m in self.mods if m[0] != "badfilter"),
        )

    def matches(self, name: str) -> bool:
        if self.kind == HOST:
            return name == self.target or name.endswith("." + self.target)
        if self.kind == HOSTS:
            return name == self.target
        if self.literal and self.literal not in name:
            return False
        return bool(self.rx and self.rx.search(name))


def _translate(pattern: str) -> tuple[re.Pattern[str], str]:
    """An adblock pattern as a regex over a name, and its longest literal piece. `||` is the start of the
    name or of a label, `|` the start or the end, `*` anything, and `^` a separator, which inside a name
    can only be its end."""
    p = pattern.lower()
    head = tail = ""
    if p.startswith("||"):
        head, p = r"(?:^|\.)", p[2:]
    elif p.startswith("|"):
        head, p = "^", p[1:]
    if p.endswith("|"):
        tail, p = "$", p[:-1]
    out = []
    for ch in p:
        out.append(".*" if ch == "*" else "$" if ch == "^" else re.escape(ch))
    pieces = re.split(r"[*^]", p)
    return re.compile(head + "".join(out) + tail), max(pieces, key=len) if pieces else ""


def _options_at(body: str) -> int | None:
    """Where a regex rule's modifiers start: the last `$` that is not escaped, as urlfilter scans for it."""
    for i in range(len(body) - 2, -1, -1):
        if body[i] == "$" and (i == 0 or body[i - 1] != "\\"):
            return i
    return None


def _mods(text: str) -> tuple[tuple[str, str], ...] | None:
    out = []
    for item in filter(None, (x.strip() for x in text.split(","))):
        name, _, value = item.partition("=")
        name = name.strip().lower()
        if name.lstrip("~") not in KNOWN_MODS:
            return None
        out.append((name, value.strip()))
    return tuple(out)


def _is_address(text: str) -> bool:
    try:
        ipaddress.ip_address(text)
    except ValueError:
        return False
    return True


def parse(line: str) -> list[Rule] | None:
    """The rules one line holds: none for a blank line or a comment, several for a hosts-file line that
    names several hosts, None for a rule line the model cannot read (an unknown modifier, a regex that
    does not compile, an empty pattern). AdGuard drops a rule with an unknown modifier too."""
    s = line.strip()
    if not s or s[0] in "!#[":
        return []
    words = s.split("#", 1)[0].split()
    if len(words) >= 2 and _is_address(words[0]):
        answer = "" if str(ipaddress.ip_address(words[0])) in BLOCKING_ADDRESSES else words[0]
        names = [normalize(w) for w in words[1:]]
        return [Rule(s, False, HOSTS, n, answer=answer) for n in names if _NAME.fullmatch(n)]
    if len(words) == 1 and _NAME.fullmatch(s.lower()):  # a bare name: a hosts-file block of it alone
        return [Rule(s, False, HOSTS, normalize(s))]
    exception = s.startswith("@@")
    body = s[2:] if exception else s
    if body.startswith("/"):
        if body.endswith("/") and len(body) > 2:
            pattern, options = body, ""
        else:
            at = _options_at(body)
            if at is None:
                return None
            pattern, options = body[:at], body[at + 1 :]
            if not (len(pattern) > 2 and pattern.endswith("/")):
                return None
        mods = _mods(options)
        try:
            rx = re.compile(pattern[1:-1], re.IGNORECASE)
        except re.error:
            return None
        return None if mods is None else [Rule(s, exception, REGEX, pattern[1:-1], mods, rx)]
    pattern, _, options = body.partition("$")
    mods = _mods(options)
    if not pattern or mods is None:
        return None
    m = _HOST_RULE.fullmatch(pattern.lower())
    if m:
        return [Rule(s, exception, HOST, m.group(1), mods)]
    rx, literal = _translate(pattern)
    return [Rule(s, exception, PATTERN, pattern.lower(), mods, rx, literal)]


def suffixes(name: str) -> list[str]:
    """The name and each name above it: `a.b.c`, `b.c`, `c`."""
    parts = name.split(".")
    return [".".join(parts[i:]) for i in range(len(parts))]


def interest_of(names: Iterable[str]) -> set[str]:
    """Every name a `||name^` or hosts-file rule must carry to match one of `names`."""
    return {x for n in names for x in suffixes(n)}


def read_rules(lines: Iterable[str], interest: set[str] | None = None) -> tuple[list[Rule], int]:
    """The rules of a list's lines and the count of rule lines the model could not read. With `interest`,
    a `||name^` or hosts-file rule whose name is not in it is left out at once: a list has hundreds of
    thousands of them, and a preview needs the few that can match a name the TV asked for."""
    out: list[Rule] = []
    unread = 0
    for raw in lines:
        s = raw.strip()
        if not s or s[0] in "!#[":
            continue
        if s.startswith("||") and s.endswith("^") and "*" not in s and "$" not in s:  # the usual block
            host = s[2:-1].lower()
            if interest is not None and host not in interest:
                continue
        got = parse(s)
        if got is None:
            unread += 1
            continue
        if interest is not None:
            got = [r for r in got if r.kind not in (HOST, HOSTS) or r.target in interest]
        out += got
    return out, unread


# ---- the model of AdGuard's precedence --------------------------------------------------------------------
@dataclass(frozen=True)
class Client:
    """Whom a lookup comes from, as `$client` and `$ctag` read it: the TV, by its address and name."""

    ip: str
    name: str = ""
    tags: tuple[str, ...] = TV_TAGS


def _client_match(item: str, client: Client) -> bool:
    if item in (client.ip, client.name.lower()):
        return True
    with contextlib.suppress(ValueError):
        if "/" in item:
            return ipaddress.ip_address(client.ip) in ipaddress.ip_network(item, strict=False)
    return False


def applies(rule: Rule, client: Client, qtype: str = "A") -> bool:
    """Whether a rule is for this lookup at all: its `$dnstype` takes the type, its `$client` the TV's
    address or name, its `$ctag` one of the TV's tags. A `~` before a value excludes it."""
    types = rule.mod("dnstype")
    if types is not None:
        values = [x.strip().upper() for x in types.split("|") if x.strip()]
        neg = {x[1:] for x in values if x.startswith("~")}
        pos = {x for x in values if not x.startswith("~")}
        if qtype in neg or (pos and qtype not in pos):
            return False
    for key, match in (
        ("client", lambda x: _client_match(x, client)),
        ("ctag", lambda x: x in client.tags),
    ):
        value = rule.mod(key)
        if value is None:
            continue
        items = [x.strip().strip("'\"").lower() for x in value.split("|") if x.strip()]
        neg = [x[1:] for x in items if x.startswith("~")]
        pos = [x for x in items if not x.startswith("~")]
        if any(match(x) for x in neg) or (pos and not any(match(x) for x in pos)):
            return False
    return True


def _rank(rule: Rule) -> int:
    """urlfilter's `IsHigherPriority` for one name: `@@` with `$important`, then `$important`, then `@@`,
    then a plain block. The list a rule sits in, and the order of the lines, decide nothing."""
    return (2 if rule.important else 0) + (1 if rule.exception else 0)


@dataclass(frozen=True)
class Hit:
    source: str  # where the rule came from: profile, local, machine, or a list's name
    rule: Rule


@dataclass(frozen=True)
class Verdict:
    state: str  # BLOCKED | ALLOWED | REWRITTEN | NONE
    hit: Hit | None = None

    @property
    def blocked(self) -> bool:
        return self.state == BLOCKED


class Engine:
    """Every rule AdGuard holds for the TV, from every source, and the verdict on a name's A lookup.

    The order AdGuard applies, as far as the gateway's rules and the lists use it: a `$badfilter` line
    deletes the rule it names, from any source; a `$dnsrewrite` rule answers first unless an `@@` rule
    with `$dnsrewrite` covers the name; then the highest of the network rules (`_rank`); a hosts-file line
    only when no network rule matches."""

    def __init__(self, sources: Iterable[tuple[str, Iterable[Rule]]], client: Client):
        rules = [Hit(src, r) for src, rs in sources for r in rs]
        cancelled = {h.rule.key() for h in rules if h.rule.badfilter}
        self.by_host: dict[str, list[Hit]] = defaultdict(list)
        self.hosts: dict[str, list[Hit]] = defaultdict(list)
        self.other: list[Hit] = []
        for h in rules:
            r = h.rule
            if r.badfilter or r.key() in cancelled or not applies(r, client):
                continue
            if r.kind == HOST:
                self.by_host[r.target].append(h)
            elif r.kind == HOSTS:
                self.hosts[r.target].append(h)
            else:
                self.other.append(h)

    def matching(self, name: str) -> list[Hit]:
        n = normalize(name)
        out = [h for s in suffixes(n) for h in self.by_host.get(s, ())]
        out += [h for h in self.other if h.rule.matches(n)]
        return [h for h in out if not _denied(h.rule, n)]

    def decide(self, name: str) -> Verdict:
        hits = self.matching(name)
        rewrites = [h for h in hits if h.rule.rewrites]
        if rewrites and not any(h.rule.exception and h.rule.mod("dnsrewrite") is not None for h in hits):
            return Verdict(REWRITTEN, max(rewrites, key=lambda h: _rank(h.rule)))
        basic = [h for h in hits if h.rule.mod("dnsrewrite") is None]
        if basic:
            top = max(basic, key=lambda h: _rank(h.rule))
            return Verdict(ALLOWED if top.rule.exception else BLOCKED, top)
        listed = self.hosts.get(normalize(name), [])
        if listed:
            blocking = [h for h in listed if not h.rule.answer]
            return Verdict(BLOCKED, blocking[0]) if blocking else Verdict(REWRITTEN, listed[0])
        return Verdict(NONE)


def _denied(rule: Rule, name: str) -> bool:
    """`$denyallow=a.example|b.example`: the rule is not for those names or any under them."""
    value = rule.mod("denyallow")
    return value is not None and any(covers(d.strip().lower(), name) for d in value.split("|") if d.strip())


# ---- the scan ---------------------------------------------------------------------------------------------
@dataclass(frozen=True)
class Finding:
    kind: str  # EXPOSES | LIFTS | HELD
    list: str  # the list's name in AdGuard
    url: str
    line: str  # the list's line, cut to LINE_CAP
    target: str  # the TV's rule it acts on, as AdGuard holds it
    source: str  # profile | local (the owner's site rules)

    def as_dict(self) -> dict:
        return dict(self.__dict__)

    @property
    def ident(self) -> tuple[str, str, str]:
        return (self.url, self.line, self.target)


@dataclass(frozen=True)
class ListFile:
    """A subscribed list as AdGuard holds it: its id, name and URL in the YAML, and its file."""

    id: int
    name: str
    url: str
    path: str


def _names_of(rule: Rule, samples: tuple[str, ...]) -> list[str]:
    """Names a block of the TV's reaches: its own name and one under it, or, for a regex or a pattern, the
    names filled from the profile's categories that it matches (`profile.filled_names`)."""
    if rule.kind == HOST:
        return [rule.target, "zz." + rule.target]
    if rule.kind == HOSTS:
        return [rule.target]
    return [n for n in samples if rule.matches(n)]


def overlap(exception: Rule, block: Rule, names: list[str]) -> list[str]:
    """The names both a list's exception and a block of the TV's reach. Two `||name^` rules overlap on the
    narrower one's name: an exception under a blocked name lifts that part of it. Any other form is judged
    on `names`, the block's `_names_of`, and a regex block also on the exception's own name."""
    if exception.kind == HOST and block.kind in (HOST, HOSTS):
        if covers(exception.target, block.target):
            return [block.target]
        return [exception.target] if block.kind == HOST and covers(block.target, exception.target) else []
    if exception.kind == HOST:
        out = [n for n in names if covers(exception.target, n)]
        return out + ([exception.target] if block.matches(exception.target) else [])
    return [n for n in names if exception.matches(n)]


def reaches(exception: Rule, block: Rule, samples: tuple[str, ...] = ()) -> bool:
    """Does a list's exception reach at least one name the block blocks (`overlap`)?"""
    return bool(overlap(exception, block, _names_of(block, samples)))


def tv_rules(groups: dict[str, list[str]], prof: Profile) -> list[tuple[str, Rule]]:
    """The TV's own rules as the plan gives them to AdGuard (`adguardcfg.rule_groups`), with their source:
    `must-allow` for a generated exception, `profile` and `local` for the rest. The machine's rules are left
    out of the scan: they come and go every hour, and the hourly check judges each one."""
    must = {f"@@||{h}^$important" for h in prof.must_allow}
    out = []
    for source in ("profile", "local"):
        for text in groups.get(source, []):
            for r in parse(text) or []:
                out.append(("must-allow" if text in must else source, r))
    return out


def scan(
    lists: Iterable[tuple[ListFile, Iterable[str]]],
    groups: dict[str, list[str]],
    prof: Profile,
    client: Client,
) -> tuple[list[Finding], dict[int, dict]]:
    """Every line of the lists that acts on one of the TV's rules (`Finding`), the most serious first, and
    per list the count of exceptions it holds and of the lines the model could not read."""
    own = tv_rules(groups, prof)
    blocks = [
        (src, r)
        for src, r in own
        if not r.exception and not r.rewrites and r.mod("dnsrewrite") is None and applies(r, client)
    ]
    keys = {r.key(): (src, r) for src, r in own}
    must = [r.target for src, r in own if src == "must-allow"]
    rewritten = [r for _, r in own if r.mod("dnsrewrite") is not None and not r.exception]
    samples = filled_names(prof)
    reach = [_names_of(b, samples) for _, b in blocks]  # once per block, not once per list line
    # what holds each name today: the strongest of the TV's own blocks on it, so an exception that a
    # wider `$important` block still outranks on the same name is held off, not lifted
    own_engine = Engine([("tv", [r for _, r in blocks])], client)

    def strongest(name: str) -> int:
        return max((_rank(h.rule) for h in own_engine.matching(name)), default=-1)

    found: list[Finding] = []
    stats: dict[int, dict] = {}
    for lf, lines in lists:
        n_exc = unread = 0
        for raw in lines:
            s = raw.strip()
            if not s or s[0] in "!#[" or (not s.startswith("@@") and "$" not in s):
                continue
            got = parse(s)
            if got is None:
                unread += 1
                continue
            for r in got:
                n_exc += r.exception
                line = s[:LINE_CAP]
                if r.badfilter:
                    named = keys.get(r.key())
                    if named:
                        src, target = named
                        kind = LIFTS if not (target.exception or target.rewrites) else EXPOSES
                        found.append(Finding(kind, lf.name, lf.url, line, target.text, _src(src)))
                    continue
                if not applies(r, client):
                    continue
                if r.exception and r.mod("dnsrewrite") is not None:  # it cancels the rewrites it covers
                    for w in rewritten:
                        if r.matches(w.target) or (r.kind == HOST and covers(w.target, r.target)):
                            found.append(Finding(EXPOSES, lf.name, lf.url, line, w.text, "profile"))
                    continue
                if r.exception:
                    for (src, b), names in zip(blocks, reach, strict=True):
                        both = overlap(r, b, names)
                        if both:
                            kind = LIFTS if any(_rank(r) > strongest(n) for n in both) else HELD
                            found.append(Finding(kind, lf.name, lf.url, line, b.text, _src(src)))
                    continue
                if r.rewrites:
                    for host in must:
                        if r.matches(host):
                            found.append(
                                Finding(
                                    EXPOSES, lf.name, lf.url, line, f"@@||{host}^$important", "must-allow"
                                )
                            )
        stats[lf.id] = {"exceptions": n_exc, "unread": unread}
    found = list({f.ident: f for f in found}.values())
    found.sort(key=lambda f: (KINDS.index(f.kind), f.list, f.line, f.target))
    return found[:FINDINGS_CAP], stats


def _src(source: str) -> str:
    return "profile" if source == "must-allow" else source


# ---- the preview ------------------------------------------------------------------------------------------
def preview(
    before: Iterable[str],
    after: Iterable[str],
    others: Iterable[tuple[str, Iterable[str]]],
    groups: dict[str, list[str]],
    names: list[tuple[str, int]],
    client: Client,
    label: str = "list",
) -> dict:
    """Each name of `names` (name, lookups) whose verdict for the TV changes between the list `before` and
    `after`, every other rule (`others`, the other lists; `groups`, the TV's own rules, the machine's
    included) as it stands: `newly_blocked` with the rule that blocks it now, `newly_allowed` with the rule
    that blocked it before, each with its lookups, the most looked up first."""
    interest = interest_of(n for n, _ in names)
    own = [(src, [r for t in rules for r in parse(t) or []]) for src, rules in groups.items()]
    rest = [(name, read_rules(lines, interest)[0]) for name, lines in others]
    old = Engine([*own, *rest, (label, read_rules(before, interest)[0])], client)
    new = Engine([*own, *rest, (label, read_rules(after, interest)[0])], client)
    blocked, allowed = [], []
    for name, lookups in names:
        was, now = old.decide(name), new.decide(name)
        if was.blocked == now.blocked:
            continue
        hit = now.hit if now.blocked else was.hit
        row = {
            "name": name,
            "lookups": lookups,
            "rule": hit.rule.text[:LINE_CAP] if hit else "",
            "by": hit.source if hit else "",
        }
        (blocked if now.blocked else allowed).append(row)
    blocked.sort(key=_most_looked_up)
    allowed.sort(key=_most_looked_up)
    return {
        "names": len(names),
        "newly_blocked": blocked[:NAMES_CAP],
        "newly_allowed": allowed[:NAMES_CAP],
        "more_blocked": max(0, len(blocked) - NAMES_CAP),
        "more_allowed": max(0, len(allowed) - NAMES_CAP),
    }


def _most_looked_up(row: dict) -> tuple[int, str]:
    return (-row["lookups"], row["name"])


def tv_names(conn: sqlite3.Connection, now: float, days: int = PREVIEW_DAYS) -> list[tuple[str, int]]:
    """The public names the TV looked up in the `days` before `now`, with their lookups, the most first.
    A name kept as a keyed tag (`NAME_HMAC=on`) never matches a list's rule and is left out."""
    from tvgw import minimize

    rows = conn.execute(
        "SELECT qname, COUNT(*) FROM dns WHERE t >= ? AND t < ? GROUP BY qname ORDER BY 2 DESC, 1",
        (now - days * 86400, now),
    ).fetchall()
    return [(normalize(q), n) for q, n in rows if is_public_name(normalize(q)) and not minimize.is_tagged(q)]


# ---- the lists AdGuard holds, and the state between runs ----------------------------------------------
def subscribed(s: Settings) -> list[ListFile] | None:
    """The enabled lists of AdGuard's YAML, each with the file AdGuard keeps it in (`data/filters/<id>.txt`
    beside the query log). No YAML, or one without lists, is none; a YAML that does not parse (AdGuard in
    the middle of writing it) is None, which the ingest's rules step already warns about; one that cannot
    be opened raises."""
    import yaml

    try:
        with open(s.adguard_yaml, encoding="utf-8") as fh:
            cfg = yaml.safe_load(fh)
    except FileNotFoundError:
        return []
    except yaml.YAMLError:
        return None
    filters = cfg.get("filters") if isinstance(cfg, dict) else None
    folder = os.path.join(os.path.dirname(s.adguard_querylog), "filters")
    out = []
    for f in filters if isinstance(filters, list) else []:
        if not isinstance(f, dict) or not f.get("enabled"):
            continue
        try:
            fid = int(f.get("id"))
        except (TypeError, ValueError):
            continue
        out.append(ListFile(fid, str(f.get("name") or fid), str(f.get("url") or ""), f"{folder}/{fid}.txt"))
    return out


def _lines(path: str) -> list[str]:
    with open(path, encoding="utf-8", errors="replace") as fh:
        return fh.read().splitlines()


def _digest(path: str) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def load_state(conn: sqlite3.Connection) -> dict:
    try:
        state = json.loads(db.get_meta(conn, META_KEY) or "{}")
    except ValueError:
        return {}
    return state if isinstance(state, dict) else {}


def load_previews(conn: sqlite3.Connection) -> list[dict]:
    try:
        events = json.loads(db.get_meta(conn, PREVIEW_KEY) or "[]")
    except ValueError:
        return []
    return [e for e in events if isinstance(e, dict)] if isinstance(events, list) else []


def copy_path(s: Settings, list_id: int) -> str:
    return os.path.join(s.state_dir, COPY_DIR, f"{list_id}.txt.gz")


def write_copy(path: str, lines: list[str]) -> None:
    """The list's rule lines, gzipped, beside the old copy and renamed over it (0640, as the job writes)."""
    folder = os.path.dirname(path)
    os.makedirs(folder, mode=0o750, exist_ok=True)
    fd, tmp = tempfile.mkstemp(prefix=".list.", dir=folder)
    try:
        with os.fdopen(fd, "wb") as raw, gzip.GzipFile(fileobj=raw, mode="wb", mtime=0) as gz:
            for line in lines:
                s = line.strip()
                if s and s[0] not in "!#[":
                    gz.write((s + "\n").encode("utf-8"))
        os.chmod(tmp, 0o640)
        os.replace(tmp, path)
    except BaseException:
        with contextlib.suppress(FileNotFoundError):
            os.unlink(tmp)
        raise


def read_copy(path: str) -> list[str] | None:
    try:
        with gzip.open(path, "rt", encoding="utf-8", errors="replace") as fh:
            return fh.read().splitlines()
    except (FileNotFoundError, OSError, EOFError):
        return None


def _merge(old: dict, found: list[Finding], now: float) -> tuple[list[dict], list[dict]]:
    """The findings with the time each was first seen and last seen, and those no list carries any more,
    with when they went (kept GONE_KEEP)."""
    seen = {tuple(f.get(k) for k in ("url", "line", "target")): f for f in old.get("findings") or []}
    current = []
    for f in found:
        prev = seen.pop(f.ident, None)
        current.append({**f.as_dict(), "first": prev["first"] if prev else now, "last": now})
    gone = [g for g in old.get("gone") or [] if now - g.get("gone", 0) < GONE_KEEP]
    gone += [{**g, "gone": now} for g in seen.values()]
    return current, gone[-FINDINGS_CAP:]


def run(
    conn: sqlite3.Connection, s: Settings, prof: Profile, now: float | None = None, force: bool = False
) -> dict:
    """The hourly ingest's `lists` step, and `tvgw lists --scan`: scan when a list or the TV's rules changed,
    when the last scan is SCAN_EVERY old, or when `force`; preview each list whose file changed since a copy
    was kept; keep a copy of each list as it is now. Writes `meta.list_guard` and `meta.list_preview`; the
    caller commits. Returns what it did, for the caller to print."""
    from tvgw import adguardcfg

    now = time.time() if now is None else now
    state = load_state(conn)
    before = {e.get("id"): e for e in state.get("lists") or [] if isinstance(e, dict)}
    groups = adguardcfg.rule_groups(prof, s)
    rules_sha = hashlib.sha256(json.dumps(groups, sort_keys=True).encode("utf-8")).hexdigest()
    entries: list[dict] = []
    present: list[tuple[ListFile, dict]] = []
    lists = subscribed(s)
    if lists is None:  # half-written: the next run reads it, and the state stays as it was
        return {"scanned": False, "lists": len(before), "previews": 0}
    for lf in lists:
        prev = before.get(lf.id) or {}
        entry = {"id": lf.id, "name": lf.name, "url": lf.url, "state": "missing"}
        try:
            st = os.stat(lf.path)
        except FileNotFoundError:
            entries.append(entry)
            continue
        same = prev.get("size") == st.st_size and prev.get("mtime") == st.st_mtime and prev.get("sha256")
        sha = prev["sha256"] if same else _digest(lf.path)
        entry.update(state="ok", size=st.st_size, mtime=st.st_mtime, sha256=sha)
        entry["since"] = prev.get("since", now) if prev.get("sha256") == sha else now
        entry["copy"] = prev.get("copy", "")
        entries.append(entry)
        present.append((lf, entry))
    changed = [lf.id for lf, e in present if (before.get(lf.id) or {}).get("sha256") != e["sha256"]]
    due = (
        force
        or changed
        or rules_sha != state.get("rules_sha")
        or now - float(state.get("t") or 0) >= SCAN_EVERY
        or sorted(before) != sorted(e["id"] for e in entries)
    )
    if not due:
        return {"scanned": False, "lists": len(entries), "previews": 0}
    texts = {lf.id: _lines(lf.path) for lf, _ in present}
    client = Client(s.tv_ip, s.tv_name)
    found, stats = scan(((lf, texts[lf.id]) for lf, _ in present), groups, prof, client)
    for _, e in present:
        e.update(stats.get(e["id"], {}))
    current, gone = _merge(state, found, now)
    previews = [e for e in load_previews(conn) if now - float(e.get("t") or 0) < PREVIEW_KEEP]
    made = 0
    names: list[tuple[str, int]] | None = None
    for lf, e in present:
        path = copy_path(s, lf.id)
        old = read_copy(path) if e["copy"] and e["copy"] != e["sha256"] else None
        if old is not None:
            names = tv_names(conn, now) if names is None else names
            others = [(o.name, texts[o.id]) for o, _ in present if o.id != lf.id]
            change = preview(old, texts[lf.id], others, groups, names, client, lf.name)
            previews.append({"t": now, "id": lf.id, "list": lf.name, "url": lf.url, **change})
            made += 1
        if e["copy"] != e["sha256"]:
            write_copy(path, texts[lf.id])
            e["copy"] = e["sha256"]
    keep = {copy_path(s, lf.id) for lf, _ in present}
    with contextlib.suppress(OSError):
        folder = os.path.join(s.state_dir, COPY_DIR)
        for name in os.listdir(folder):
            path = os.path.join(folder, name)
            if path not in keep and name.endswith(".txt.gz"):
                os.unlink(path)  # a list no longer subscribed
    db.set_meta(
        conn,
        META_KEY,
        json.dumps({"t": now, "rules_sha": rules_sha, "lists": entries, "findings": current, "gone": gone}),
    )
    db.set_meta(conn, PREVIEW_KEY, json.dumps(previews))
    return {"scanned": True, "lists": len(entries), "previews": made, "findings": current}


def scan_now(s: Settings, prof: Profile) -> dict:
    """`tvgw lists --scan`: one forced run under the ingest's lock, committed."""
    os.makedirs(s.state_dir, exist_ok=True)
    lock = os.path.join(s.state_dir, ".ingest.lock")
    with open(lock, "w", encoding="utf-8") as fh:
        fcntl.flock(fh, fcntl.LOCK_EX)
        conn = db.connect(s.db_path)
        try:
            done = run(conn, s, prof, force=True)
            conn.commit()
            return done
        finally:
            conn.close()


# ---- what a window's brief says ---------------------------------------------------------------------------
def brief_view(conn: sqlite3.Connection, since: float, until: float) -> dict | None:
    """The brief's "List guard": the findings any list carried in [since, until), those first seen in it
    (which the red lines read), and the previews made in it. None before the first scan, so a gateway that
    never scanned prints what it printed before."""
    state = load_state(conn)
    if not state:
        return None
    findings = [f for f in state.get("findings") or [] if f.get("first", 0) < until]
    findings += [
        g for g in state.get("gone") or [] if g.get("first", 0) < until and g.get("gone", 0) >= since
    ]
    return {
        "scanned": state.get("t"),
        "lists": [
            {k: e.get(k) for k in ("id", "name", "state", "exceptions", "unread", "since")}
            for e in state.get("lists") or []
        ],
        "findings": findings,
        "new": [f for f in findings if since <= f.get("first", 0) < until],
        "previews": [e for e in load_previews(conn) if since <= float(e.get("t") or 0) < until],
    }
