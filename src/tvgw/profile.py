"""TV profiles: everything vendor-specific, loaded from a TOML file and its companion `.rules` file.

A profile names the categories a hostname falls into (longest matching pattern wins, `*` is a
wildcard, a pattern matches the host itself or any subdomain, regional prefixes are stripped
first), the hosts that must never be blocked, and the plain-HTTP URL filter for the vendor's
file service. The bundled `lg-webos` profile is what the LG CX work produced.
"""

from __future__ import annotations

import re
import tomllib
from dataclasses import dataclass, field
from fnmatch import fnmatchcase
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
    generations: tuple[Generation, ...] = field(default_factory=tuple)
    hardware: tuple[Hardware, ...] = field(default_factory=tuple)
    checklist: dict[str, tuple[str, ...]] = field(default_factory=dict)  # topic -> steps
    custom_rules: tuple[str, ...] = ()  # the companion .rules file, comments and blanks dropped
    _cache: dict[str, str] = field(default_factory=dict, compare=False, repr=False)

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

    def adguard_rules(self) -> list[str]:
        """AdGuard custom rules: an exact allow rule for every must-allow host (so the TOML is the
        one source of truth and no upstream list can take them), then the companion `.rules` file."""
        allow = [f"@@||{host}^" for host in self.must_allow]
        return allow + [r for r in self.custom_rules if r not in allow]

    def lint(self) -> list[str]:
        """Rules that would break the TV or defeat themselves, as sentences; empty when clean.

        Lore from every LG blocklist project: a block covering a must-allow name, a block at the
        apex of a mixed zone (lgtvsdp.com, nextlgsdp.com ...), or an exception above a blocked
        name (AdGuard exceptions outrank blocks) each broke clocks, stores or apps for someone.
        """
        problems = []
        targets = [rule_target(r) for r in self.adguard_rules()]
        blocks = [h for k, h in targets if k == "block" and h]
        allows = [h for k, h in targets if k == "allow" and h]
        for host in self.must_allow:
            problems += [f"block rule {b!r} covers must-allow {host}" for b in blocks if covers(b, host)]
            if self.url_filter and host in self.url_filter.hosts:
                problems.append(f"{host} is both must-allow and rewritten by the URL filter")
        for apex in self.never_block_apex:
            problems += [
                f"block rule at the apex of {apex!r} mixes delivery with telemetry"
                for b in blocks
                if b == apex
            ]
        for a in allows:
            problems += [
                f"exception {a!r} sits above blocked {b!r} and would unblock it"
                for b in blocks
                if b != a and covers(a, b)
            ]
        return problems


def rule_target(rule: str) -> tuple[str, str]:
    """('block' | 'allow' | 'rewrite' | 'regex' | 'other', host) for one AdGuard DNS rule."""
    r = rule.strip()
    if r.startswith("/"):
        return "regex", r
    kind = "block"
    if r.startswith("@@"):
        kind, r = "allow", r[2:]
    body, _, mods = r.partition("$")
    if "dnsrewrite" in mods:
        kind = "rewrite"
    if body.startswith("||"):
        body = body[2:]
    elif body.startswith("|"):
        body = body[1:]
    host = body.strip("|^").lower()
    if not host or "/" in host or " " in host:
        return "other", host
    return kind, host


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
    best, cat = -1, OTHER
    for pat, c in profile.rules:
        if fnmatchcase(host, pat) or fnmatchcase(host, "*." + pat):
            score = len(pat.replace("*", ""))
            if score > best:
                best, cat = score, c
    return cat


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
    filters: list[tuple[str, str]] = []
    for f in data.get("adguard", {}).get("filters", []):
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
        custom_rules=custom_rules,
    )
