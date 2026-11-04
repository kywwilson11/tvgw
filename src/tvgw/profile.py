"""TV profiles: everything vendor-specific, loaded from a TOML file and its companion `.rules` file.

A profile names the categories a hostname falls into (longest matching pattern wins, `*` is a
wildcard, a pattern matches the host itself or any subdomain, regional prefixes are stripped
first), the hosts that must never be blocked, and the plain-HTTP URL filter for the vendor's
file service. The bundled `lg-webos` profile is what the LG CX work produced; `samsung-tizen`, `roku`
and `vizio-smartcast` are DNS-only profiles built from maintained lists and measurement papers, and
`generic-tv` is the general profile, for a TV no vendor profile is assigned to (design decision 62).

Reference records (`[[generations]]`, `[[hardware]]`, `[[lan_api]]`, `[[privacy_setting]]`) block
nothing; `tvgw profile` prints them. The last two carry a provenance block that the loader checks.
"""

from __future__ import annotations

import ipaddress
import re
import tomllib
from dataclasses import dataclass, field, replace
from fnmatch import fnmatchcase, translate
from importlib import resources
from pathlib import Path

OTHER = "Other"
# the tables a profile may have: a misspelt one would otherwise read as absent, and an absent
# [must_allow] is a profile with no must-allow hosts and a clean lint
TABLES = frozenset(
    {
        "profile",
        "categories",
        "must_allow",
        "adguard",
        "url_filter",
        "generations",
        "hardware",
        "checklist",
        "lan_api",
        "privacy_setting",
        "category_labels",  # (plain) the plain brief's names for the profile's categories
        "clock",  # (profile) how the TV sets its clock
        "support",  # (profile) how far the profile is tested
        "regions",  # (W12) the vendor's regional host prefix ({rg} in must_allow) per country
    }
)
# (W12) the placeholders a must_allow host may carry: the TV's country (two lower-case letters, LG's
# `us.nextlgsdp.com`) and the vendor's region prefix for it (`aic`, `eic`, `kic`, `ruc`); filled at load
# with [profile] default_country (`us` unless the profile says) and again by `for_country()`
COUNTRY_PLACEHOLDER, REGION_PLACEHOLDER = "{cc}", "{rg}"
DEFAULT_COUNTRY, DEFAULT_REGION = "us", "aic"
_COUNTRY = re.compile(r"[a-z]{2}")
# (W12) the menu topics a [[generations]] row may give a path for, in the order the docs show them
MENU_TOPICS = ("wifi", "agreements", "live_plus", "advertising", "standby")
GENERATION_MANIFESTS = ("", "signed", "unsigned")
# (profile) the general profile: any TV no vendor profile was assigned to (design decision 62)
GENERIC = "generic-tv"
# (profile) how the TV sets its clock: from the vendor's own HTTPS reply (webOS: LG's SDP), from NTP,
# from both, or not known. `none` turns the clock red line off; a profile without [clock] keeps the
# red line its clock_hosts give, as before the table existed
CLOCK_MODELS = ("vendor-https", "ntp", "mixed", "none")
# (profile) how far a profile is tested, strongest first, with the words `tvgw profile` prints
SUPPORT = {"tested": "Tested", "reported": "Reported", "not-yet-tested": "Not yet tested"}
# (profile) a sentinel, the name a list answers with 0.0.0.0 once it is in force: a DNS name that
# `tvgw verify` resolves, lower case, at least two labels
_LABEL = r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?"
_DNS_NAME = re.compile(rf"(?=.{{1,253}}$)(?:{_LABEL}\.)+[a-z](?:[a-z0-9-]{{0,61}}[a-z0-9])?")

# ---- provenance of the reference records (design decision 31) -----------------------------
# A record is 'verified' only when it was seen on a set this project ran, and then it names the kind of
# evidence; anything else is 'unverified' and must cite where it came from, so no fact enters a profile
# without either a capture behind it or a URL a reviewer can open.
PROVENANCE = ("verified", "unverified")
# the evidence grades, strongest first: what a verified record is (observed) and what an unverified one
# rests on (a peer-reviewed measurement study, independent community reports, the vendor's own pages,
# or one report or a guess)
GRADES = ("observed", "peer-reviewed", "community", "spec", "low")
# how a verified record was seen: packets through the gateway, a reading over the TV's LAN API, the
# TV's own menu or screen, or a block that broke a named feature and its lifting that restored it
EVIDENCE_KINDS = ("capture", "lan-api", "on-screen", "breakage")
LAN_PROTOCOLS = ("ws", "wss", "http", "https", "mqtt", "mqtts", "adb", "tls")
WRITE_MODES = ("ok", "refused", "root", "unknown")


@dataclass(frozen=True)
class UrlFilter:
    hosts: tuple[str, ...]
    block_regex: str

    def blocks(self, uri: str) -> bool:
        return re.search(self.block_regex, uri, re.IGNORECASE) is not None


@dataclass(frozen=True)
class Generation:
    """One webOS release line: what a gateway operator should know before trusting this profile on it.
    (W12) A generation is the OS the TV runs, keyed by `os_major` (what the TV reports in its `hello`
    reply as `deviceOSReleaseVersion`: 7.x is webOS 22, 11.x webOS 26), since LG's updates move a 2022
    set through four releases; the model years are what shipped with it."""

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
    # (W12) the release the TV reports (`deviceOSReleaseVersion` major), and the range in words (`7.x`)
    os_major: str = ""
    release_range: str = ""
    firmware_majors: tuple[str, ...] = ()  # every firmware major seen on this line; shared ones are ambiguous
    menu: tuple[tuple[str, str], ...] = ()  # (topic of MENU_TOPICS, the path on the TV), in file order
    manifest: str = ""  # the pairing manifest that works: signed, unsigned, or "" for not known
    readable: tuple[str, ...] = ()  # the getSystemSettings keys in the public read list (bscpylgtv dumps)
    consent_flags: tuple[str, ...] = ()  # the eulaStatus flags the dumps show
    support: str = ""  # tested | reported | not-yet-tested, or "" for the profile's own status
    sources: tuple[str, ...] = ()

    def menu_path(self, topic: str) -> str:
        """The TV's menu path for a MENU_TOPICS topic, "" when the row gives none."""
        return dict(self.menu).get(topic, "")


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
class Provenance:
    """Where one reference record's facts come from. A verified record was seen on hardware this
    project ran (grade 'observed', with the kind of evidence); an unverified one carries the URLs it
    was taken from and the grade of the best of them. `from_dict` refuses any other combination."""

    status: str = "unverified"
    grade: str = "low"
    evidence: str = ""
    sources: tuple[str, ...] = ()

    @property
    def verified(self) -> bool:
        return self.status == "verified"

    def label(self) -> str:
        """`verified here (lan-api)` or `unverified, community`: what `tvgw profile` prints."""
        return f"verified here ({self.evidence})" if self.verified else f"unverified, {self.grade}"


@dataclass(frozen=True)
class LanApi:
    """One vendor LAN API endpoint (R&D survey 6.1 and 6.4): how a gateway on the TV's segment could
    read the TV's state, and what it cannot change. Reference only: nothing is blocked or opened by it."""

    name: str
    port: int
    protocol: str
    tls: str = ""  # "", "self-signed", "ca": what the client must accept
    pairing: str = ""
    discovery: str = ""  # an SSDP search target or an mDNS service type
    generations: tuple[str, ...] = ()  # the OS releases the record describes; empty is "all known"
    reads: tuple[str, ...] = ()  # readable fields, a setting key path where one is known
    write: str = "unknown"  # ok | refused | root | unknown
    read_only: str = ""  # what can be read and not changed, and why
    gate: str = ""  # the TV setting that switches the API on or off
    notes: tuple[str, ...] = ()
    provenance: Provenance = field(default_factory=Provenance)


@dataclass(frozen=True)
class PrivacySetting:
    """One privacy setting on the TV (R&D survey 6.4): what it controls, the value this project
    recommends, and where it sits in the menus, per generation since vendors move it between releases."""

    name: str  # as the TV labels it: Live Plus, Viewing Information Services, Viewing Data
    controls: str
    recommended: str
    menu: tuple[tuple[str, str], ...]  # (generation or menu-family label, menu path), in file order
    key: str = ""  # the key the LAN API reads it by, where one is known
    opt_out_effective: str = ""  # what measurement says the opt-out achieves, with its source in `sources`
    notes: tuple[str, ...] = ()
    provenance: Provenance = field(default_factory=Provenance)


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
    lan_apis: tuple[LanApi, ...] = ()  # [[lan_api]]: reference, printed by `tvgw profile`
    privacy_settings: tuple[PrivacySetting, ...] = ()  # [[privacy_setting]]: likewise
    # (plain) [category_labels]: a category in plain words for the plain brief, where plain.CATEGORY_PLAIN
    # and its vendor suffixes would name it wrongly
    category_labels: dict[str, str] = field(default_factory=dict)
    # (profile) [clock] model, one of CLOCK_MODELS; "" when the profile has no [clock] table
    clock_model: str = ""
    # (profile) [support]: a key of SUPPORT, "" when the profile declares none; the sets it was tested
    # on; and what the TV's owner checks in the TV's own menus, in plain words
    support: str = ""
    tested_on: tuple[str, ...] = ()
    you_check: str = ""
    # (W11) [support] does, can_check and cannot_check: in plain words, what tvgw does for this TV, what
    # its hourly reading reads and what it cannot, for the generated support tables and "what tvgw can
    # check" blocks of the vendor pages; empty where the profile does not say
    does: str = ""
    can_check: tuple[str, ...] = ()
    cannot_check: tuple[str, ...] = ()
    # (profile) [checklist] wifi_off: the plain-words steps that make the cable the TV's only path, and
    # whether they were checked on a set of this profile
    wifi_off: str = ""
    wifi_off_confirmed: bool = False
    # (profile) url -> the sentinel an [adguard] filters entry names; verify prefers it to its own table
    filter_sentinels: dict[str, str] = field(default_factory=dict)
    # (W12) [must_allow] as written, placeholders and all; `must_allow` is it filled for `country`
    must_allow_templates: tuple[tuple[str, str], ...] = ()
    country: str = DEFAULT_COUNTRY
    regions: dict[str, tuple[str, ...]] = field(default_factory=dict)  # (W12) [regions]: prefix -> countries
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

    def generation_for(
        self, webos: str | None = None, firmware: str | None = None, release: str | None = None
    ) -> Generation | None:
        """By the release the TV reports (`release`: '11.2.0' -> the row whose os_major is 11; what the
        hourly reading uses), by LG's name ('5', '5.6.2', '22') or by firmware ('33.31.61' -> the line
        whose `firmware_major` is 33). The release is tried first, then the name, then the firmware."""
        if release:
            major = release.split(".")[0]
            hit = next((g for g in self.generations if g.os_major and g.os_major == major), None)
            if hit:
                return hit
        if webos:
            major = webos.split(".")[0]
            hit = next((g for g in self.generations if g.webos == major), None)
            if hit:
                return hit
        if firmware:
            major = firmware.split(".")[0]
            return next((g for g in self.generations if g.firmware_major and g.firmware_major == major), None)
        return None

    def region_for(self, country: str) -> str:
        """(W12) The vendor's regional prefix for a two-letter country, from [regions]; DEFAULT_REGION when
        no region lists it."""
        return next((rg for rg, ccs in self.regions.items() if country in ccs), DEFAULT_REGION)

    def for_country(self, country: str) -> Profile:
        """(W12) This profile with its must-allow hosts filled for the TV's country: `{cc}` becomes the
        two-letter code and `{rg}` the region it falls in. "" or the default country gives the profile as
        loaded, byte for byte in its rules; anything but two lower-case letters raises ValueError."""
        cc = country.strip().lower() if country else ""
        if not cc:
            return self
        if not _COUNTRY.fullmatch(cc):
            raise ValueError(f"country {country!r}: expected two letters, as in us or de")
        if cc == self.country:
            return self
        filled = fill_country(self.must_allow_templates, cc, self.region_for(cc))
        return replace(self, must_allow=filled, country=cc)

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

    def lint(self, lifts: frozenset[str] = frozenset()) -> list[str]:
        """Rules that would break the TV or defeat themselves, as sentences; empty when clean.

        Lore from every LG blocklist project: a block (hosts syntax included), a rewrite or a regex
        that covers a must-allow name, one at the apex of a mixed zone (lgtvsdp.com, or
        `*.lgtvsdp.com`, which takes the zone the same way), or an exception sitting over a blocked
        name (it unblocks it; equal to it, the block is dead) each broke clocks, stores or apps for
        someone. So does a rule that switches others off (`$badfilter`, an `@@...$dnsrewrite` over a
        rewrite) and one whose reach the lint cannot read (a regex exception, an unanchored pattern).
        `tvgw adguard` refuses a profile with problems, so nothing here is advisory.

        (site rules) `lifts` names the hosts of the owner's own allows (`localrules`, design decision
        59): an exception at or under a blocked name is what such an allow is for, so for those hosts
        alone the exception-over-block refusal does not apply. Every other check does.
        """
        problems: list[str] = []
        rules = self.adguard_rules()
        targets = [rule_target(r) for r in rules]
        blocks = [h for k, h in targets if k == "block" and h]
        allows = [h for k, h in targets if k == "allow" and h]
        rewrites = [h for k, h in targets if k == "rewrite" and h]
        regexes = [r for k, r in targets if k == "regex"]
        for host in self.must_allow:
            problems += [f"block rule {b!r} covers must-allow {host}" for b in blocks if covers(b, host)]
            problems += [f"rewrite rule {b!r} covers must-allow {host}" for b in rewrites if covers(b, host)]
            if self.url_filter and any(covers(u, host) for u in self.url_filter.hosts):
                problems.append(f"{host} is both must-allow and rewritten by the URL filter")
        compiled: list[tuple[str, re.Pattern[str]]] = []
        for r in regexes:
            body = r[1 : r.rfind("/")]  # between the first and the last slash: `$modifiers` excluded
            try:
                rx = re.compile(body, re.IGNORECASE)  # as AdGuard compiles it, short of $match-case
            except re.error as err:
                problems.append(f"regex rule {r!r} does not compile: {err}")
                continue
            compiled.append((r, rx))
            problems += [
                f"regex rule {r!r} matches must-allow {host}" for host in self.must_allow if rx.search(host)
            ]
        for apex in self.never_block_apex:
            problems += [
                f"{kind} rule {b!r} at the apex of {apex!r} mixes delivery with telemetry"
                for kind, hosts in (("block", blocks), ("rewrite", rewrites))
                for b in hosts
                if _at_apex(b, apex)
            ]
            problems += [
                f"regex rule {r!r} matches across {apex!r}, a zone that mixes delivery with telemetry"
                for r, rx in compiled
                if any(rx.search(probe + apex) for probe in APEX_PROBES)
            ]
        for a in allows:
            if a in lifts:  # (site rules) the owner's allow lifts a block on purpose
                continue
            problems += [
                f"exception {a!r} sits above blocked {b!r} and would unblock it"
                for b in blocks
                if covers(a, b)
            ]
        # rules that switch others off: AdGuard drops every rule a `$badfilter` twin names before it
        # matches anything (the generated exceptions and strip included), and an exception carrying
        # `$dnsrewrite` cancels the rewrites of its host, the URL filter's among them
        rewritten = (*(self.url_filter.hosts if self.url_filter else ()), *rewrites)
        for r, (k, host) in zip(rules, targets, strict=True):
            mods = _rule_modifiers(r)
            if "badfilter" in mods:
                problems.append(f"rule {r!r} carries $badfilter, which deletes the rule it names")
            if k == "allow" and "dnsrewrite" in mods:
                problems += [
                    f"exception {r!r} cancels the rewrite of {b!r}"
                    for b in rewritten
                    if covers(host, b) or covers(b, host)
                ]
        problems += [
            f"regex exception {r!r} may lift any block and cannot be checked: write @@||host^"
            for r, (k, _) in zip(rules, targets, strict=True)
            if k == "allow-regex"
        ]
        problems += [
            f"rule {r!r} is not one the lint can read: write ||host^, a one-name hosts line or a /regex/"
            for r, (k, _) in zip(rules, targets, strict=True)
            if k == "other"
        ]
        return problems


STRIPPABLE_QTYPES = ("HTTPS", "SVCB")  # the record types a profile may withhold from the TV
# the types a `$dnstype` rule may withhold and still hide no name: HTTPS/SVCB, which clients do
# without (RFC 9460), and AAAA, answered empty anyway on a segment that drops IPv6 at the wire
HARMLESS_QTYPES = frozenset({*STRIPPABLE_QTYPES, "AAAA"})
_HOST = re.compile(r"[a-z0-9*._-]+")  # a host pattern between `||` and `^`
# prefixes making names in a protected zone that a regex aimed at particular hosts does not match
# and one over the whole zone does: the apex, a label, LG's hyphenated CNAME-target shape, two labels
APEX_PROBES = ("", "zz.", "zz-zz-zz.", "zz.zz.")


def rule_target(rule: str) -> tuple[str, str]:
    """('block' | 'allow' | 'rewrite' | 'typed' | 'regex' | 'allow-regex' | 'other', host) for one rule.

    `0.0.0.0 host` (hosts syntax, one name) is a block. `$dnsrewrite` turns a block into a rewrite and a
    `$dnstype` naming only HARMLESS_QTYPES into a typed rule (it withholds record types, never a
    name, so the lint's host checks do not apply); any other type list, a negated one (`~HTTPS`, every
    type but HTTPS) included, withholds the addresses and stays a block. Neither changes an `@@`
    exception. A `/regex/` rule comes back whole, for the lint to compile; so does an `@@/regex/`
    exception, which the lint refuses, since which blocked names it lifts cannot be checked."""
    r = rule.strip()
    if r.startswith("/"):
        return "regex", r
    if r.startswith("@@/"):
        return "allow-regex", r[2:]
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
    # `||host^` is the host and its subdomains, and `|host^`, the host alone, is read the same (it
    # over-reports, never under). AdGuard matches a pattern without the anchor inside any name
    # (`tvsdp.com^` is us.lgtvsdp.com) and one without the `^` as a prefix (`||us.lgtv`): `covers`
    # cannot model either, so both are 'other', which the lint refuses
    if body.startswith("||"):
        body = body[2:]
    elif body.startswith("|"):
        body = body[1:]
    else:
        body = ""
    host = body[:-1].lower() if body.endswith("^") else ""
    if not _HOST.fullmatch(host):
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


def _rule_modifiers(rule: str) -> dict[str, str]:
    """One rule's modifiers as _modifiers reads them; a regex rule's follow its closing slash."""
    r = rule.strip()
    if r.removeprefix("@@").startswith("/"):
        r = r[r.rfind("/") + 1 :]
    return _modifiers(r.partition("$")[2])


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


_URL = re.compile(r"https?://\S+")


def uncited_rules(text: str) -> list[str]:
    """The rules of a `.rules` file that no source URL stands over, in file order.

    A rule's citation is the comment block that opens its group: the comment lines after the last
    blank line before it (a group may hold several rules under one block). A blank line closes the
    group, so a citation never reaches past it. A profile built from lists and papers rather than
    from its own captures holds itself to this (design decision 32): a rule nobody can
    trace back is one nobody can review or lift with confidence."""
    out: list[str] = []
    cited = False
    in_comments = False
    for line in text.splitlines():
        s = line.strip()
        if not s:
            cited, in_comments = False, False
        elif s.startswith("!"):
            if not in_comments:  # a comment after rules opens a new block within the group
                cited, in_comments = False, True
            cited = cited or bool(_URL.search(s))
        else:
            in_comments = False
            if not cited and s not in out:
                out.append(s)
    return out


def fill_country(templates: tuple[tuple[str, str], ...], country: str, region: str) -> dict[str, str]:
    """(W12) The must-allow hosts for one country: `{cc}` and `{rg}` replaced, lower-cased, in file
    order. A host without a placeholder is kept as it is."""
    out: dict[str, str] = {}
    for host, why in templates:
        filled = host.replace(COUNTRY_PLACEHOLDER, country).replace(REGION_PLACEHOLDER, region).lower()
        out[filled] = why
    return out


def bundled_names() -> tuple[str, ...]:
    """The names of the profiles shipped in the package (`lg-webos`, `roku` ...), sorted: each is a
    TOML file in tvgw.profiles with its `.rules` companion beside it."""
    bundled = resources.files("tvgw.profiles")
    names = {p.name[: -len(".toml")] for p in bundled.iterdir() if p.name.endswith(".toml")}
    return tuple(sorted(n for n in names if (bundled / f"{n}.rules").is_file()))


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
    data = tomllib.loads(toml.read_text(encoding="utf-8"))
    return from_dict(data, tuple(parse_rules(rules.read_text(encoding="utf-8"))))


def _strs(value: object, where: str) -> tuple[str, ...]:
    """`value` as a tuple of non-empty strings, or ValueError naming `where`: TOML lets a bare string
    stand where a list was meant, and iterating it would make one-character patterns."""
    if not isinstance(value, list | tuple) or not all(isinstance(x, str) and x for x in value):
        raise ValueError(f"{where}: expected a list of non-empty strings")
    return tuple(value)


def _text(rec: dict, key: str, where: str, required: bool = False) -> str:
    """A string field of a record: ValueError naming `where.key` for a non-string, or for an empty or
    missing one that is required."""
    value = rec.get(key, "")
    if not isinstance(value, str) or (required and not value.strip()):
        raise ValueError(f"{where}.{key}: expected a{' non-empty' if required else ''} string")
    return value


def _choice(rec: dict, key: str, where: str, allowed: tuple[str, ...], default: str) -> str:
    value = rec.get(key, default)
    if value not in allowed:
        raise ValueError(f"{where}.{key}: {value!r} not among {list(allowed)}")
    return value


def _records(data: dict, table: str) -> list[tuple[str, dict]]:
    """`[[table]]` as (where, record) pairs; ValueError when it is not an array of tables."""
    recs = data.get(table, [])
    if not isinstance(recs, list) or not all(isinstance(r, dict) for r in recs):
        raise ValueError(f"{table}: expected [[{table}]] records")
    return [(f"{table}[{i}]", r) for i, r in enumerate(recs)]


_PROVENANCE_KEYS = frozenset({"provenance", "grade", "evidence", "sources"})


def _provenance(rec: dict, where: str) -> Provenance:
    """The provenance block every reference record carries, checked as R&D survey 6.4 asks: verified
    means observed here and names the evidence; unverified means a source URL and a grade below
    observed. A record with neither is refused at load, so CI fails it before it can mislead."""
    status = _choice(rec, "provenance", where, PROVENANCE, "unverified")
    sources = _strs(rec.get("sources", []), f"{where}.sources") if rec.get("sources") else ()
    if bad := [u for u in sources if not _URL.fullmatch(u)]:
        raise ValueError(f"{where}.sources: {bad[0]!r} is not an http(s) URL")
    if status == "verified":
        grade = _choice(rec, "grade", where, ("observed",), "observed")
        evidence = _choice(rec, "evidence", where, EVIDENCE_KINDS, "")
        return Provenance(status, grade, evidence, sources)
    if "evidence" in rec:
        raise ValueError(f"{where}.evidence: only a verified record names evidence; cite sources instead")
    if not sources:
        raise ValueError(f"{where}.sources: an unverified record needs at least one source URL")
    grade = _choice(rec, "grade", where, GRADES[1:], "low")
    return Provenance(status, grade, "", sources)


def _table(data: dict, name: str, keys: frozenset[str]) -> dict:
    """(profile) An optional table whose keys are all known: {} when it is absent. A misspelt key is
    refused, since `[clock] modle = "none"` would otherwise read as no table and keep the red line."""
    table = data.get(name, {})
    if not isinstance(table, dict):
        raise ValueError(f"{name}: expected a [{name}] table")
    if unknown := set(table) - keys:
        raise ValueError(f"{name}.{min(unknown)}: unknown key")
    return table


_SUPPORT_KEYS = frozenset({"status", "tested_on", "you_check", "does", "can_check", "cannot_check"})


def _support(data: dict) -> tuple[str, tuple[str, ...], str]:
    """(profile) [support] as (status, tested_on, you_check). A status is required with the table, and
    a tested profile names the sets it was tested on: "Tested" with nothing behind it is a claim."""
    sup = _table(data, "support", _SUPPORT_KEYS)
    if "support" not in data:
        return "", (), ""
    status = _choice(sup, "status", "support", tuple(SUPPORT), "")
    tested_on = _strs(sup["tested_on"], "support.tested_on") if "tested_on" in sup else ()
    if status == "tested" and not tested_on:
        raise ValueError("support.tested_on: a tested profile names the sets it was tested on")
    return status, tested_on, _text(sup, "you_check", "support")


def _reading(data: dict) -> tuple[str, tuple[str, ...], tuple[str, ...]]:
    """(W11) [support] does, can_check and cannot_check; ("", (), ()) where the profile does not say."""
    sup = data.get("support", {}) if isinstance(data.get("support", {}), dict) else {}
    lists = tuple(
        _strs(sup[key], f"support.{key}") if key in sup else () for key in ("can_check", "cannot_check")
    )
    return _text(sup, "does", "support"), lists[0], lists[1]


def _checklist(data: dict) -> tuple[dict[str, tuple[str, ...]], str, bool]:
    """(profile) [checklist] as (topics, wifi_off, wifi_off_confirmed). A topic is a list of steps;
    `wifi_off` is one plain-words text and `wifi_off_confirmed` a boolean, so they are kept apart."""
    raw = data.get("checklist", {})
    if not isinstance(raw, dict):
        raise ValueError("checklist: expected a [checklist] table")
    wifi_off = _text(raw, "wifi_off", "checklist")
    confirmed = raw.get("wifi_off_confirmed", False)
    if not isinstance(confirmed, bool):
        raise ValueError("checklist.wifi_off_confirmed: expected true or false")
    if confirmed and not wifi_off.strip():
        raise ValueError("checklist.wifi_off_confirmed: there are no wifi_off steps to have checked")
    topics = {
        k: _strs(v, f"checklist.{k}") for k, v in raw.items() if k not in ("wifi_off", "wifi_off_confirmed")
    }
    return topics, wifi_off, confirmed


def _check_keys(rec: dict, where: str, keys: frozenset[str]) -> None:
    """A new record format refuses keys it does not know: a misspelt `source` or `evidance` would
    otherwise read as a record with no citation."""
    if unknown := set(rec) - keys - _PROVENANCE_KEYS:
        raise ValueError(f"{where}.{min(unknown)}: unknown key")


_LAN_API_KEYS = frozenset(
    {"name", "port", "protocol", "tls", "pairing", "discovery", "generations", "reads", "write"}
    | {"read_only", "gate", "notes"}
)


def _lan_api(rec: dict, where: str) -> LanApi:
    _check_keys(rec, where, _LAN_API_KEYS)
    port = rec.get("port")
    if isinstance(port, bool) or not isinstance(port, int) or not 0 < port < 65536:
        raise ValueError(f"{where}.port: expected a TCP/UDP port number")
    return LanApi(
        name=_text(rec, "name", where, required=True),
        port=port,
        protocol=_choice(rec, "protocol", where, LAN_PROTOCOLS, ""),
        tls=_text(rec, "tls", where),
        pairing=_text(rec, "pairing", where),
        discovery=_text(rec, "discovery", where),
        generations=_strs(rec.get("generations", []), f"{where}.generations"),
        reads=_strs(rec.get("reads", []), f"{where}.reads"),
        write=_choice(rec, "write", where, WRITE_MODES, "unknown"),
        read_only=_text(rec, "read_only", where),
        gate=_text(rec, "gate", where),
        notes=_strs(rec.get("notes", []), f"{where}.notes"),
        provenance=_provenance(rec, where),
    )


_PRIVACY_KEYS = frozenset({"name", "controls", "recommended", "menu", "key", "opt_out_effective", "notes"})


def _privacy_setting(rec: dict, where: str) -> PrivacySetting:
    _check_keys(rec, where, _PRIVACY_KEYS)
    menu = rec.get("menu")
    if (
        not isinstance(menu, dict)
        or not menu
        or not all(isinstance(k, str) and k and isinstance(v, str) and v for k, v in menu.items())
    ):
        raise ValueError(f'{where}.menu: expected a table of "generation" = "menu path"')
    return PrivacySetting(
        name=_text(rec, "name", where, required=True),
        controls=_text(rec, "controls", where, required=True),
        recommended=_text(rec, "recommended", where, required=True),
        menu=tuple(menu.items()),
        key=_text(rec, "key", where),
        opt_out_effective=_text(rec, "opt_out_effective", where),
        notes=_strs(rec.get("notes", []), f"{where}.notes"),
        provenance=_provenance(rec, where),
    )


_GENERATION_KEYS = frozenset(
    {"webos", "years", "codename", "models", "firmware_major", "verified", "clock_hosts", "lan_api"}
    | {"dns_bypass", "hardcoded", "notes", "confidence", "os_major", "release_range", "firmware_majors"}
    | {"menu", "manifest", "readable", "consent_flags", "support", "sources"}
)


def _generations(data: dict) -> tuple[Generation, ...]:
    """(W12) [[generations]] rows, each key checked: a misspelt `readble` would otherwise read as a
    generation that reads nothing. No two rows may claim one `os_major` (the hourly reading picks the row
    by it), a `menu` names MENU_TOPICS topics only, `manifest` is signed, unsigned or absent, and
    `support` is a SUPPORT level or absent."""
    out: list[Generation] = []
    majors: dict[str, str] = {}
    for where, g in _records(data, "generations"):
        if unknown := set(g) - _GENERATION_KEYS:
            raise ValueError(f"{where}.{min(unknown)}: unknown key")
        if "webos" not in g:
            raise ValueError(f"{where}.webos: a generation names its release")
        os_major = str(g.get("os_major", ""))
        if os_major:
            if not os_major.isdigit():
                raise ValueError(f"{where}.os_major: {os_major!r} is not the major of a release version")
            if os_major in majors:
                raise ValueError(f"{where}.os_major: {os_major} is also webOS {majors[os_major]}'s")
            majors[os_major] = str(g["webos"])
        menu = g.get("menu", {})
        if not isinstance(menu, dict) or not all(
            k in MENU_TOPICS and isinstance(v, str) and v for k, v in menu.items()
        ):
            raise ValueError(f'{where}.menu: expected a table of topic = "path", topics {list(MENU_TOPICS)}')
        manifest = _choice(g, "manifest", where, GENERATION_MANIFESTS, "")
        support = _choice(g, "support", where, ("", *SUPPORT), "")
        sources = _strs(g.get("sources", []), f"{where}.sources") if g.get("sources") else ()
        if bad := [u for u in sources if not _URL.fullmatch(u)]:
            raise ValueError(f"{where}.sources: {bad[0]!r} is not an http(s) URL")
        out.append(
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
                os_major=os_major,
                release_range=_text(g, "release_range", where),
                firmware_majors=tuple(str(m) for m in g.get("firmware_majors", ())),
                menu=tuple(menu.items()),
                manifest=manifest,
                readable=_strs(g.get("readable", []), f"{where}.readable") if g.get("readable") else (),
                consent_flags=(
                    _strs(g.get("consent_flags", []), f"{where}.consent_flags")
                    if g.get("consent_flags")
                    else ()
                ),
                support=support,
                sources=sources,
            )
        )
    return tuple(out)


def _regions(data: dict) -> dict[str, tuple[str, ...]]:
    """(W12) [regions]: `prefix = ["de", "fr", ...]`, each country two lower-case letters named once."""
    raw = data.get("regions", {})
    if not isinstance(raw, dict):
        raise ValueError("regions: expected a [regions] table of prefix = [countries]")
    out: dict[str, tuple[str, ...]] = {}
    seen: dict[str, str] = {}
    for rg, ccs in raw.items():
        if not re.fullmatch(r"[a-z]{2,8}", rg):
            raise ValueError(f"regions.{rg}: a region prefix is 2 to 8 lower-case letters")
        countries = _strs(ccs, f"regions.{rg}")
        for cc in countries:
            if not _COUNTRY.fullmatch(cc):
                raise ValueError(f"regions.{rg}: {cc!r} is not two lower-case letters")
            if cc in seen:
                raise ValueError(f"regions.{rg}: {cc} is also in {seen[cc]}")
            seen[cc] = rg
        out[rg] = countries
    return out


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
    # (W12) the hosts as written, and the same filled for the default country: `{cc}.nextlgsdp.com` is
    # `us.nextlgsdp.com` on a file that says nothing, so a gateway that predates the placeholders plans
    # the rules it always did
    templates = tuple((str(h).lower(), why) for h, why in must_allow.items())
    country = _text(meta, "default_country", "profile") or DEFAULT_COUNTRY
    if not _COUNTRY.fullmatch(country):
        raise ValueError(f"profile.default_country: {country!r} is not two lower-case letters")
    regions = _regions(data)
    must_allow = fill_country(
        templates, country, next((rg for rg, ccs in regions.items() if country in ccs), DEFAULT_REGION)
    )
    uf = data.get("url_filter")
    if uf is not None:
        hosts = _strs(uf.get("hosts"), "url_filter.hosts")
        try:
            re.compile(uf.get("block_regex"))
        except (re.error, TypeError) as e:
            raise ValueError(f"url_filter.block_regex: {e}") from None
    labels = data.get("category_labels", {})
    if not isinstance(labels, dict):
        raise ValueError('category_labels: expected a table of category = "plain words"')
    for cat, label in labels.items():
        if cat not in order and cat != OTHER:
            raise ValueError(f"category_labels.{cat}: not a category of this profile")
        if not isinstance(label, str) or not label.strip():
            raise ValueError(f"category_labels.{cat}: expected a non-empty string")
    adg = data.get("adguard", {})
    strip = _strs(adg.get("strip_qtypes", []), "adguard.strip_qtypes") if adg.get("strip_qtypes") else ()
    if bad := [q for q in strip if q not in STRIPPABLE_QTYPES]:
        raise ValueError(f"adguard.strip_qtypes: {bad} not among {list(STRIPPABLE_QTYPES)}")
    filters: list[tuple[str, str]] = []
    sentinels: dict[str, str] = {}
    for f in adg.get("filters", []):
        if not isinstance(f, dict) or not isinstance(f.get("name"), str) or not isinstance(f.get("url"), str):
            raise ValueError("adguard.filters: every entry needs a name and a url")
        filters.append((f["name"], f["url"]))
        if "sentinel" in f:  # (profile)
            sentinel = f["sentinel"]
            if not isinstance(sentinel, str) or not _DNS_NAME.fullmatch(sentinel):
                raise ValueError(f"adguard.filters: the sentinel of {f['name']!r} is not a lower-case name")
            sentinels[f["url"]] = sentinel
    clock = _table(data, "clock", frozenset({"model"}))  # (profile)
    support, tested_on, you_check = _support(data)
    does, can_check, cannot_check = _reading(data)  # (W11)
    checklist, wifi_off, wifi_off_confirmed = _checklist(data)
    return Profile(
        name=meta.get("name", "unnamed"),
        vendor=meta.get("vendor", ""),
        description=meta.get("description", ""),
        rules=tuple(rules),
        # lower-cased like the names they are stripped from, or an upper-case prefix is inert
        strip_prefixes=tuple(
            p.lower() for p in _strs(cats.get("strip_prefixes", ()), "categories.strip_prefixes")
        ),
        must_allow=dict(must_allow),
        url_filter=UrlFilter(tuple(h.lower() for h in hosts), uf["block_regex"]) if uf is not None else None,
        category_order=tuple(order),
        expected_categories=expected,
        clock_hosts=tuple(h.lower() for h in _strs(meta.get("clock_hosts", ()), "profile.clock_hosts")),
        never_block_apex=tuple(
            h.lower() for h in _strs(meta.get("never_block_apex", ()), "profile.never_block_apex")
        ),
        generations=_generations(data),
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
        checklist=checklist,
        adguard_filters=tuple(filters),
        adguard_strip_qtypes=strip,
        custom_rules=custom_rules,
        lan_apis=tuple(_lan_api(r, w) for w, r in _records(data, "lan_api")),
        privacy_settings=tuple(_privacy_setting(r, w) for w, r in _records(data, "privacy_setting")),
        category_labels=dict(labels),
        clock_model=_choice(clock, "model", "clock", CLOCK_MODELS, "") if "clock" in data else "",
        support=support,
        tested_on=tested_on,
        you_check=you_check,
        does=does,
        can_check=can_check,
        cannot_check=cannot_check,
        wifi_off=wifi_off,
        wifi_off_confirmed=wifi_off_confirmed,
        filter_sentinels=sentinels,
        must_allow_templates=templates,
        country=country,
        regions=regions,
    )
