"""TV profiles: everything vendor-specific, loaded from a TOML file and its companion `.rules` file.

A profile names the categories a hostname falls into (longest matching pattern wins, `*` is a
wildcard, a pattern matches the host itself or any subdomain, regional prefixes are stripped
first), the hosts that must never be blocked, and the plain-HTTP URL filter for the vendor's
file service. The bundled `lg-webos` profile is what the LG CX work produced.
"""

from __future__ import annotations

import ipaddress
import re
import tomllib
from dataclasses import dataclass, field
from fnmatch import fnmatchcase, translate
from importlib import resources
from pathlib import Path

OTHER = "Other"
# the tables a profile may have: a misspelt one would otherwise read as absent, and an absent
# [must_allow] is a profile with no must-allow hosts and a clean lint
TABLES = frozenset(
    {"profile", "categories", "must_allow", "adguard", "url_filter", "generations", "hardware", "checklist"}
)


@dataclass(frozen=True)
class UrlFilter:
    hosts: tuple[str, ...]
    block_regex: str

    def blocks(self, uri: str) -> bool:
        return re.search(self.block_regex, uri, re.IGNORECASE) is not None


@dataclass(frozen=True)
class Generation:
    """One webOS release line: what a gateway operator should know before trusting this profile on it."""

    webos: str
    years: tuple[int, ...] = ()
    codename: str = ""
    models: tuple[str, ...] = ()
    firmware_major: str = ""
    verified: bool = False
    clock_hosts: tuple[str, ...] = ()
    lan_api: str = ""
    dns_bypass: tuple[str, ...] = ()
    hardcoded: tuple[str, ...] = ()
    notes: tuple[str, ...] = ()
    confidence: str = "low"


@dataclass(frozen=True)
class Hardware:
    """The audio-privacy facts for a model line (fnmatch patterns on the model number)."""

    models: tuple[str, ...]
    year: int = 0
    far_field_mic: bool = False
    assistants: tuple[str, ...] = ()
    notes: str = ""
    confidence: str = "low"

    def matches(self, model: str) -> bool:
        m = model.upper().replace(" ", "")
        return any(fnmatchcase(m, pat.upper()) for pat in self.models)


@dataclass(frozen=True)
class Profile:
    name: str
    vendor: str
    description: str
    rules: tuple[tuple[str, str], ...]  # (pattern, category), in file order
    strip_prefixes: tuple[str, ...]
    must_allow: dict[str, str]  # host -> reason
    url_filter: UrlFilter | None
    category_order: tuple[str, ...] = field(default_factory=tuple)
    # categories that are the TV doing its job (video, app APIs, CDNs, the vendor's core services);
    # an allowed name outside them is what the daily brief surfaces
    expected_categories: tuple[str, ...] = ("Streaming", "Infra")
    # lookups the TV must make to set its clock (patterns); a day on without one is a red line
    clock_hosts: tuple[str, ...] = field(default_factory=tuple)
    # zones that mix delivery with telemetry: a block at the apex breaks the TV (lint refuses it)
    never_block_apex: tuple[str, ...] = field(default_factory=tuple)
    adguard_filters: tuple[tuple[str, str], ...] = field(default_factory=tuple)  # (name, url)
    adguard_strip_qtypes: tuple[str, ...] = ()  # record types withheld from the TV (HTTPS, SVCB)
    generations: tuple[Generation, ...] = field(default_factory=tuple)
    hardware: tuple[Hardware, ...] = field(default_factory=tuple)
    checklist: dict[str, tuple[str, ...]] = field(default_factory=dict)  # topic -> steps
    custom_rules: tuple[str, ...] = ()  # the companion .rules file, comments and blanks dropped
    _cache: dict[str, str] = field(default_factory=dict, compare=False, repr=False)
    # the categorizer's two indexes over `rules`, built in __post_init__: a plain pattern is a
    # dictionary key, so a name costs one lookup per label suffix; a wildcard pattern is compiled once
    _exact: dict[str, tuple[int, int, str]] = field(
        init=False, default_factory=dict, compare=False, repr=False
    )
    _wild: tuple[tuple[re.Pattern[str], int, int, str], ...] = field(
        init=False, default=(), compare=False, repr=False
    )

    def __post_init__(self) -> None:
        exact: dict[str, tuple[int, int, str]] = {}
        wild: list[tuple[re.Pattern[str], int, int, str]] = []
        for index, (pat, cat) in enumerate(self.rules):
            rank = (len(pat.replace("*", "")), -index)  # the longest wins, the earlier on a tie
            if any(ch in pat for ch in "*?["):
                # `(?:.*\.)?` + the shell pattern is fnmatchcase(host, pat) or fnmatchcase(host, "*." + pat)
                wild.append((re.compile(r"(?:.*\.)?" + translate(pat)), *rank, cat))
            else:
                exact.setdefault(pat, (*rank, cat))
        object.__setattr__(self, "_exact", exact)
        object.__setattr__(self, "_wild", tuple(wild))

    def categorize(self, host: str) -> str:
        """Category of a hostname; longest matching pattern wins, Other if none."""
        key = host.lower().rstrip(".")
        hit = self._cache.get(key)
        if hit is None:
            hit = self._cache[key] = _categorize(self, key)
        return hit

    def hardware_for(self, model: str) -> Hardware | None:
        """The hardware row for a model number such as OLED65C2PUA, or None when unknown."""
        return next((h for h in self.hardware if h.matches(model)), None)

    def generation_for(self, webos: str | None = None, firmware: str | None = None) -> Generation | None:
        """By webOS version ('5', '5.6.2', '22') or firmware ('33.31.61' -> the line whose major is 33)."""
        if webos:
            major = webos.split(".")[0]
            hit = next((g for g in self.generations if g.webos == major), None)
            if hit:
                return hit
        if firmware:
            major = firmware.split(".")[0]
            return next((g for g in self.generations if g.firmware_major and g.firmware_major == major), None)
        return None

    def is_expected(self, host: str) -> bool:
        """Does this name fall in a category the TV needs (as opposed to one worth a look)?"""
        return self.categorize(host) in self.expected_categories

    def adguard_rules(self, gw_ip: str | None = None, tv_ip: str | None = None) -> list[str]:
        """AdGuard's custom rules: an `$important` exception per must-allow host, the URL filter's
        `$dnsrewrite` rules when the gateway address is given, one type-scoped rule withholding
        `strip_qtypes` records from the TV when its address is given, then the companion `.rules` file.

        Order has no effect on AdGuard's precedence. What makes "whatever a list says" true is the
        modifier: a plain `@@` exception loses to a `$important` block in any list, and only an
        exception carrying `$important` itself outranks both. The TOML stays the one place to edit.
        """
        generated = [f"@@||{host}^$important" for host in self.must_allow]
        if gw_ip and self.url_filter:
            generated += [f"||{host}^$dnsrewrite={gw_ip}" for host in self.url_filter.hosts]
        if tv_ip and self.adguard_strip_qtypes:
            # scoped to the record types and to the TV's address: its A lookups and every other
            # client are untouched, and a must-allow `$important` exception still wins for its hosts
            generated.append(f"||*^$dnstype={'|'.join(self.adguard_strip_qtypes)},client={tv_ip}")
        return generated + [r for r in self.custom_rules if r not in generated]

    def lint(self) -> list[str]:
        """Rules that would break the TV or defeat themselves, as sentences; empty when clean.

        Lore from every LG blocklist project: a block (hosts syntax included), a rewrite or a regex
        that covers a must-allow name, a block at the apex of a mixed zone (lgtvsdp.com, or
        `*.lgtvsdp.com`, which takes the zone the same way), or an exception sitting over a blocked
        name (it unblocks it; equal to it, the block is dead) each broke clocks, stores or apps for
        someone. `tvgw adguard` refuses a profile with problems, so nothing here is advisory.
        """
        problems: list[str] = []
        targets = [rule_target(r) for r in self.adguard_rules()]
        blocks = [h for k, h in targets if k == "block" and h]
        allows = [h for k, h in targets if k == "allow" and h]
        rewrites = [h for k, h in targets if k == "rewrite" and h]
        regexes = [r for k, r in targets if k == "regex"]
        for host in self.must_allow:
            problems += [f"block rule {b!r} covers must-allow {host}" for b in blocks if covers(b, host)]
            problems += [f"rewrite rule {b!r} covers must-allow {host}" for b in rewrites if covers(b, host)]
            if self.url_filter and any(covers(u, host) for u in self.url_filter.hosts):
                problems.append(f"{host} is both must-allow and rewritten by the URL filter")
        for r in regexes:
            body = r[1 : r.rfind("/")]  # between the first and the last slash: `$modifiers` excluded
            try:
                rx = re.compile(body)
            except re.error as err:
                problems.append(f"regex rule {r!r} does not compile: {err}")
                continue
            problems += [
                f"regex rule {r!r} matches must-allow {host}" for host in self.must_allow if rx.search(host)
            ]
        for apex in self.never_block_apex:
            problems += [
                f"block rule {b!r} at the apex of {apex!r} mixes delivery with telemetry"
                for b in blocks
                if _at_apex(b, apex)
            ]
        for a in allows:
            problems += [
                f"exception {a!r} sits above blocked {b!r} and would unblock it"
                for b in blocks
                if covers(a, b)
            ]
        return problems


STRIPPABLE_QTYPES = ("HTTPS", "SVCB")  # the record types a profile may withhold from the TV
# the types a `$dnstype` rule may withhold and still hide no name: HTTPS/SVCB, which clients do
# without (RFC 9460), and AAAA, answered empty anyway on a segment that drops IPv6 at the wire
HARMLESS_QTYPES = frozenset({*STRIPPABLE_QTYPES, "AAAA"})


def rule_target(rule: str) -> tuple[str, str]:
    """('block' | 'allow' | 'rewrite' | 'typed' | 'regex' | 'other', host) for one AdGuard DNS rule.

    `0.0.0.0 host` (hosts syntax) is a block. `$dnsrewrite` turns a block into a rewrite and a
    `$dnstype` naming only HARMLESS_QTYPES into a typed rule (it withholds record types, never a
    name, so the lint's host checks do not apply); any other type list, a negated one (`~HTTPS`, every
    type but HTTPS) included, withholds the addresses and stays a block. Neither changes an `@@`
    exception. A `/regex/` rule comes back whole, for the lint to compile."""
    r = rule.strip()
    if r.startswith("/"):
        return "regex", r
    words = r.split()
    if len(words) == 2 and _is_address(words[0]):
        return "block", words[1].lower()
    kind = "block"
    if r.startswith("@@"):
        kind, r = "allow", r[2:]
    body, _, mods = r.partition("$")
    types = set(_modifiers(mods).get("dnstype", "").upper().split("|"))  # absent is {''}; `~X` is no type
    if kind == "block" and "dnsrewrite" in mods:
        kind = "rewrite"
    elif kind == "block" and types <= HARMLESS_QTYPES:
        kind = "typed"
    if body.startswith("||"):
        body = body[2:]
    elif body.startswith("|"):
        body = body[1:]
    host = body.strip("|^").lower()
    if not host or "/" in host or " " in host:
        return "other", host
    return kind, host


def _modifiers(mods: str) -> dict[str, str]:
    """`important,dnstype=A|AAAA` as {'important': '', 'dnstype': 'A|AAAA'}, names lower-cased."""
    out = {}
    for mod in mods.split(","):
        name, _, value = mod.partition("=")
        if name.strip():
            out[name.strip().lower()] = value.strip()
    return out


def _is_address(text: str) -> bool:
    try:
        ipaddress.ip_address(text)
    except ValueError:
        return False
    return True


def _at_apex(block: str, apex: str) -> bool:
    """The apex itself, or a wildcard-only chain above it (`*.apex`, `*.*.apex`) that takes the whole
    zone the way the apex rule would; `rdx2.apex` is one host and is not."""
    return block == apex or (block.endswith("." + apex) and set(block[: -len(apex) - 1]) <= {"*", "."})


def covers(pattern: str, name: str) -> bool:
    """Does an AdGuard host pattern (`||pattern^` semantics, `*` allowed) match `name` or a subdomain?"""
    pattern, name = pattern.lower(), name.lower()
    if "*" in pattern:
        return fnmatchcase(name, pattern) or fnmatchcase(name, "*." + pattern)
    return name == pattern or name.endswith("." + pattern)


def parse_rules(text: str) -> list[str]:
    """AdGuard rule lines: drop `!` comments and blank lines, keep order, no duplicates."""
    out: list[str] = []
    for line in text.splitlines():
        s = line.strip()
        if s and not s.startswith("!") and s not in out:
            out.append(s)
    return out


def _categorize(profile: Profile, host: str) -> str:
    for p in profile.strip_prefixes:
        if host.startswith(p):
            host = host[len(p) :]
            break
    best = (-1, 0, OTHER)  # (score, -index, category), compared as a tuple
    suffix = host
    while True:  # the host and each label suffix of it: `a.b.c`, `b.c`, `c`
        best = max(best, profile._exact.get(suffix, best))
        _, dot, suffix = suffix.partition(".")
        if not dot:
            break
    for rx, score, order, cat in profile._wild:
        if (score, order) > best[:2] and rx.match(host):
            best = (score, order, cat)
    return best[2]


def load(source: str | Path) -> Profile:
    """A profile by bundled name (`lg-webos`) or by the path of its TOML. The companion `.rules` file
    (same name, `.rules` suffix, resolved by the name asked for and never by `[profile].name`) must
    exist beside it; an empty one is the capture-phase profile that blocks nothing. A file that is
    missing or unreadable raises (OSError), as does bad data (ValueError): a profile loaded with fewer
    rules than written would quietly unblock what it was meant to block."""
    path = Path(source)
    if path.suffix == ".toml" and path.exists():
        toml, rules = path, path.with_suffix(".rules")
    else:
        bundled = resources.files("tvgw.profiles")
        toml, rules = bundled / f"{source}.toml", bundled / f"{source}.rules"
    data = tomllib.loads(toml.read_text())
    return from_dict(data, tuple(parse_rules(rules.read_text())))


def _strs(value: object, where: str) -> tuple[str, ...]:
    """`value` as a tuple of non-empty strings, or ValueError naming `where`: TOML lets a bare string
    stand where a list was meant, and iterating it would make one-character patterns."""
    if not isinstance(value, list | tuple) or not all(isinstance(x, str) and x for x in value):
        raise ValueError(f"{where}: expected a list of non-empty strings")
    return tuple(value)


def from_dict(data: dict, custom_rules: tuple[str, ...] = ()) -> Profile:
    """A Profile from parsed TOML. Pure: `custom_rules` is what `load` read from the companion file.
    Raises ValueError, naming the key, for data TOML accepts but the profile would misread."""
    unknown = set(data) - TABLES
    if unknown:
        raise ValueError(f"{min(unknown)}: unknown table")
    meta = data.get("profile", {})
    cats = data.get("categories", {})
    rules: list[tuple[str, str]] = []
    order: list[str] = []
    for cat, patterns in cats.items():
        if cat == "strip_prefixes":
            continue
        if cat == OTHER:
            raise ValueError(f"categories.{OTHER}: reserved for names no pattern matches")
        order.append(cat)
        rules += [(pat.lower(), cat) for pat in _strs(patterns, f"categories.{cat}")]
    if "expected_categories" in meta:
        expected = _strs(meta["expected_categories"], "profile.expected_categories")
        for cat in expected:
            if cat not in order:
                raise ValueError(f"profile.expected_categories: {cat!r} is not a category")
    else:
        expected = ("Streaming", "Infra")
    must_allow = data.get("must_allow", {})
    for host, why in must_allow.items():
        if not isinstance(why, str):
            raise ValueError(f"must_allow.{host}: expected a string, the reason")
    uf = data.get("url_filter")
    if uf is not None:
        hosts = _strs(uf.get("hosts"), "url_filter.hosts")
        try:
            re.compile(uf.get("block_regex"))
        except (re.error, TypeError) as e:
            raise ValueError(f"url_filter.block_regex: {e}") from None
    adg = data.get("adguard", {})
    strip = _strs(adg.get("strip_qtypes", []), "adguard.strip_qtypes") if adg.get("strip_qtypes") else ()
    if bad := [q for q in strip if q not in STRIPPABLE_QTYPES]:
        raise ValueError(f"adguard.strip_qtypes: {bad} not among {list(STRIPPABLE_QTYPES)}")
    filters: list[tuple[str, str]] = []
    for f in adg.get("filters", []):
        if not isinstance(f, dict) or not isinstance(f.get("name"), str) or not isinstance(f.get("url"), str):
            raise ValueError("adguard.filters: every entry needs a name and a url")
        filters.append((f["name"], f["url"]))
    return Profile(
        name=meta.get("name", "unnamed"),
        vendor=meta.get("vendor", ""),
        description=meta.get("description", ""),
        rules=tuple(rules),
        # lower-cased like the names they are stripped from, or an upper-case prefix is inert
        strip_prefixes=tuple(
            p.lower() for p in _strs(cats.get("strip_prefixes", ()), "categories.strip_prefixes")
        ),
        must_allow={k.lower(): v for k, v in must_allow.items()},
        url_filter=UrlFilter(tuple(h.lower() for h in hosts), uf["block_regex"]) if uf is not None else None,
        category_order=tuple(order),
        expected_categories=expected,
        clock_hosts=tuple(h.lower() for h in _strs(meta.get("clock_hosts", ()), "profile.clock_hosts")),
        never_block_apex=tuple(
            h.lower() for h in _strs(meta.get("never_block_apex", ()), "profile.never_block_apex")
        ),
        generations=tuple(
            Generation(
                webos=str(g["webos"]),
                years=tuple(int(y) for y in g.get("years", ())),
                codename=g.get("codename", ""),
                models=tuple(g.get("models", ())),
                firmware_major=str(g.get("firmware_major", "")),
                verified=bool(g.get("verified", False)),
                clock_hosts=tuple(g.get("clock_hosts", ())),
                lan_api=g.get("lan_api", ""),
                dns_bypass=tuple(g.get("dns_bypass", ())),
                hardcoded=tuple(g.get("hardcoded", ())),
                notes=tuple(g.get("notes", ())),
                confidence=g.get("confidence", "low"),
            )
            for g in data.get("generations", [])
        ),
        hardware=tuple(
            Hardware(
                models=tuple(h["models"]),
                year=int(h.get("year", 0)),
                far_field_mic=bool(h.get("far_field_mic", False)),
                assistants=tuple(h.get("assistants", ())),
                notes=h.get("notes", ""),
                confidence=h.get("confidence", "low"),
            )
            for h in data.get("hardware", [])
        ),
        checklist={k: tuple(v) for k, v in data.get("checklist", {}).items()},
        adguard_filters=tuple(filters),
        adguard_strip_qtypes=strip,
        custom_rules=custom_rules,
    )
