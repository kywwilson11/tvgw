"""TV profiles: everything vendor-specific, loaded from a TOML file.

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


@dataclass(frozen=True)
class UrlFilter:
    hosts: tuple[str, ...]
    block_regex: str

    def blocks(self, uri: str) -> bool:
        return re.search(self.block_regex, uri, re.IGNORECASE) is not None


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
    adguard_filters: tuple[tuple[str, str], ...] = field(default_factory=tuple)  # (name, url)
    rules_path: Path | None = None  # the companion .rules file (AdGuard custom rules)
    _cache: dict[str, str] = field(default_factory=dict, compare=False, repr=False)

    def categorize(self, host: str) -> str:
        """Category of a hostname; longest matching pattern wins, Other if none."""
        key = host.lower().rstrip(".")
        hit = self._cache.get(key)
        if hit is None:
            hit = self._cache[key] = _categorize(self, key)
        return hit

    def is_expected(self, host: str) -> bool:
        """Does this name fall in a category the TV needs (as opposed to one worth a look)?"""
        return self.categorize(host) in self.expected_categories

    def adguard_rules(self) -> list[str]:
        """AdGuard custom rules from the companion `.rules` file (comments and blanks dropped)."""
        if self.rules_path is not None:
            try:
                return parse_rules(self.rules_path.read_text())
            except OSError:
                return []
        try:  # bundled profile: the .rules file ships inside the package
            return parse_rules(resources.files("tvgw.profiles").joinpath(f"{self.name}.rules").read_text())
        except (OSError, FileNotFoundError):
            return []


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
    """Load a profile by bundled name (`lg-webos`) or from a TOML path."""
    path = Path(source)
    if path.suffix == ".toml" and path.exists():
        data = tomllib.loads(path.read_text())
        rules_path = path.with_suffix(".rules")
    else:
        data = tomllib.loads(resources.files("tvgw.profiles").joinpath(f"{source}.toml").read_text())
        rules_path = None  # resolved from the package at call time
    return from_dict(data, rules_path)


def from_dict(data: dict, rules_path: Path | None = None) -> Profile:
    meta = data.get("profile", {})
    cats = data.get("categories", {})
    rules = []
    order = []
    for cat, patterns in cats.items():
        if cat == "strip_prefixes":
            continue
        order.append(cat)
        for pat in patterns:
            rules.append((pat.lower(), cat))
    uf = data.get("url_filter")
    return Profile(
        name=meta.get("name", "unnamed"),
        vendor=meta.get("vendor", ""),
        description=meta.get("description", ""),
        rules=tuple(rules),
        strip_prefixes=tuple(cats.get("strip_prefixes", ())),
        must_allow={k.lower(): v for k, v in data.get("must_allow", {}).items()},
        url_filter=UrlFilter(tuple(h.lower() for h in uf["hosts"]), uf["block_regex"]) if uf else None,
        category_order=tuple(order),
        expected_categories=tuple(meta.get("expected_categories", ("Streaming", "Infra"))),
        adguard_filters=tuple((f["name"], f["url"]) for f in data.get("adguard", {}).get("filters", [])),
        rules_path=rules_path,
    )
