"""(listguard) A model of AdGuard Home's precedence, for the rules tvgw and the subscribed lists use (design
decision 68).

AdGuard Home downloads each subscribed list again every 24 hours and applies whatever it gets (design
decision 46). A list can do more than block. An exception (`@@`) in it lifts every block of the same name
that carries no `$important`, whichever list or custom rule the block sits in, and a `$badfilter` line
deletes the rule it names. The profile loads its red-line blocks with `$important` (`profile.held_rule`);
`Engine` says what AdGuard answers the TV for a name, given every rule from every source, so the tests
can prove that a list's exception no longer lifts them and that the must-allow hosts are untouched.
"""

from __future__ import annotations

import contextlib
import ipaddress
import re
from collections import defaultdict
from collections.abc import Iterable
from dataclasses import dataclass, field

from tvgw.names import normalize
from tvgw.profile import covers

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
