#!/usr/bin/env python3
"""Write the documentation's tables that copy the code, or check that they still match it.

A table copied from the code by hand drifts from it. These are written from the code instead, each
between two markers that stand alone on their lines:

    <!-- generated:NAME -->                       or  <!-- generated:NAME profile=PROFILE -->
    ...the block, written by this script...
    <!-- /generated:NAME -->

Everything outside the markers is left as it is, byte for byte. A marker inside a fenced code block or
a code span is an example and is not read. The blocks (BLOCKS), and where each takes its facts:

- `support-table`: which TVs work, one row per profile and support level, from each bundled profile's
  `[support]` table and `[[generations]]` rows, and from which profiles the gateway can pair with
  (`setup.PAIRABLE_PROFILES`) or reads without pairing (`setup.READ_WITHOUT_PAIRING`). What tvgw does
  for a TV it pairs with is READERS'; for one it reads without pairing, the profile's `[support] does`.
  The front page and docs/tv/README.md carry it; `profile-support` is the same rows with each one's
  profile, for src/tvgw/profiles/README.md.
- `generations profile=...`: the profile's `[[generations]]` rows: the release the TV reports, the
  pairing that works and the support level of each, how each is known, and where each row's menus are.
- `can-check profile=...`: what the gateway reads on that brand's TVs: READS for a TV it pairs with,
  the profile's `[support] can_check` and `cannot_check` for one it reads without pairing.
- `verify-checks`: `verify.GROUPS`, `verify.SETTLING` and `verify.PLAIN`; `verify-new-checks`:
  `verify.FAIL_AFTER` and `verify.PROMOTED`.
- `red-lines`: `plain.RED_LINE_PLAIN`, with each profile's action for the screen-recognition lines.

    python3 tools/docgen.py [--check] [--root DIR]
        Rewrites every generated region that differs from the code and names each page it wrote.
        With --check it writes nothing: one line per region that differs, `page:line: NAME: ...`, and
        exit 1. Exit 2, with nothing written, when a marker is malformed or a block cannot be written.

Standard library only. It imports the tvgw package of the checkout it sits in (that checkout's src/
goes first on the path), so it reads the code beside it, also under `python3 -I`. The pages are the
Markdown files under DIR, this checkout by default, leaving out folders whose name starts with a dot
and the build, virtualenv and cache folders (`SKIP_DIRS`).
"""

from __future__ import annotations

import argparse
import os
import re
import sys
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT / "src") not in sys.path:  # this checkout's code, whatever tvgw is installed
    sys.path.insert(0, str(ROOT / "src"))

from tvgw import plain, profile, setup, verify  # noqa: E402

# the folders the page walk leaves out, besides every folder whose name starts with a dot (.git, and
# .claude with its worktrees): what a checkout's .gitignore leaves out, the site's copy of the pages
# under build/ among them
SKIP_DIRS = frozenset({"venv", "node_modules", "mutants", "build", "dist", "backups", "__pycache__"})

# ---- markers -------------------------------------------------------------------------------------------
_NAME = r"[a-z][a-z0-9-]*"
OPEN = re.compile(rf"<!--[ \t]*generated:(?P<name>{_NAME})(?P<params>(?:[ \t]+{_NAME}=[\w.-]+)*)[ \t]*-->")
CLOSE = re.compile(rf"<!--[ \t]*/generated:(?P<name>{_NAME})[ \t]*-->")
# what a reader would take for a marker: a comment that starts with `generated:`, with or without the
# slash, whatever its spaces or its case. Such a line must be a marker exactly, or docgen stops
LOOKS_LIKE = re.compile(r"<!--\s*/?\s*generated\s*:", re.IGNORECASE)
FENCE = re.compile(r"^[ \t]*(`{3,}|~{3,})(.*)$")
CODE_SPAN = re.compile(r"(`+)(?!`)(.+?)(?<!`)\1(?!`)")
SYNTAX = (
    "a marker stands alone on its line, as <!-- generated:NAME --> or <!-- generated:NAME profile=PROFILE -->"
)

# a command in verify's plain texts, which docs/reference/verify-checks.md shows in a code span: `sudo`
# and a program, then words of letters, digits and - < > / _, with a dot only inside a word (so
# `install.sh` is one, and the full stop after a command is not part of it). tests/unit/test_verify_plain.py
# checks that each one exists in this version
TOKEN = r"[-\w<>/]+(?:\.[-\w<>/]+)*"
COMMAND = re.compile(
    rf"(?:sudo (?:tvgw-apply|tvgw-doh-update|tvgw|systemctl"
    rf"|/usr/lib/tvgw/deploy/install\.sh|deploy/install\.sh)|journalctl)"
    rf"(?: {TOKEN})*"
)
# a command in the brief's plain words: a tvgw command and its options, nothing after them
TVGW_COMMAND = re.compile(r"(?:sudo )?tvgw [a-z][a-z-]*(?: --?[a-z][a-z-]*)*")

# ---- what the code does not say in plain words yet ----------------------------------------------------
# The support table's name for each bundled profile's TVs, in the table's order: the tested TV first, the
# general profile last. A bundled profile without a name here stops docgen, so a new profile gets its row.
TV_NAMES = {
    "lg-webos": "LG",
    "samsung-tizen": "Samsung (Tizen)",
    "roku": "Roku TV",
    "vizio-smartcast": "Vizio (SmartCast)",
    profile.GENERIC: "Other TVs (Google TV, Fire TV, Sony, TCL, Hisense and more)",
}
OS_NAME = "webOS"  # a [[generations]] row is a webOS release (profile.Generation.webos)


@dataclass(frozen=True)
class Reader:
    """What the gateway does for a TV it can pair with and read, at one support level, and what the TV's
    owner still checks on the TV ("" for the profile's [support] you_check)."""

    does: str
    you_check: str = ""


# The TVs the gateway can pair with and read (setup.PAIRABLE_PROFILES), in plain words, until a profile
# says what its reader reads: per support level for the support table, and the hourly reading for
# can-check. A profile the gateway learns to read stops docgen until it has its words here.
READERS: dict[str, dict[str, Reader]] = {
    "lg-webos": {
        "tested": Reader(
            "Blocks, reports every day, and once paired reads the TV's privacy settings and Wi-Fi state"
            " every hour",
            "Nothing after setup",
        ),
        "not-yet-tested": Reader(
            "Blocks and reports every day; once paired, reads the privacy settings, and the Wi-Fi state"
            " where the TV reports it"
        ),
    },
}
READS: dict[str, tuple[str, ...]] = {
    "lg-webos": (
        "whether the TV is on, and which app is in front",
        "Live Plus, LG's screen recognition (ACR)",
        "the TV's data agreements, such as Viewing Information and Voice Information",
        "the state of its wired port, Wi-Fi and Wi-Fi Direct, and whether tethering is on",
        "the model and the software version",
    ),
}
# what tvgw does for a TV it cannot read: with blocks of the profile's own, and with shared lists alone
BLOCKS_ONLY = "Blocks and reports every day"
SHARED_LISTS_ONLY = (
    "Keeps the TV away from your other devices, reports every day, and blocks known trackers from"
    " shared lists"
)
READS_NOTHING = (
    "Nothing yet. The gateway does not read this TV's settings, its Wi-Fi state or whether it is on."
)
# (samsung) a TV the gateway reads without pairing (setup.READ_WITHOUT_PAIRING): the lists are the
# profile's [support] can_check and cannot_check
READS_UNPAIRED = "Every hour, with no pairing and nothing on the TV's screen, the gateway reads:"
CANNOT_READ = "It cannot read:"
# (W12) the generations block: the pairing each row's manifest names, how a row is known (its evidence
# grade, profile.GRADES), and the menus' topics (profile.MENU_TOPICS) as the TV's menus name them
MANIFESTS = {
    "signed": "The signed list of LG's remote app",
    "unsigned": "tvgw's own read-only list",
    "": "Not known yet",
}
KNOWN_BY = {
    "observed": "Seen on the project's own TV",
    "peer-reviewed": "A published study",
    "community": "Reports from owners and developers",
    "spec": "LG's own documentation",
    "low": "One report, not confirmed",
}
MENU_NAMES = {
    "wifi": "Wi-Fi",
    "agreements": "User agreements",
    "live_plus": "Live Plus",
    "advertising": "Advertising",
    "standby": "Standby",
}
DETAIL_ONLY = "Nothing: the line stays in the engineering brief."
MENU_ACR_HERE = "The menu path of the TV's screen-recognition setting, from its profile (below)."


class DocgenError(Exception):
    """A marker docgen cannot read, or a block it cannot write. Nothing is written."""


@dataclass(frozen=True)
class Region:
    """One generated region of a page: its opening marker's line (from 1), the block it names with its
    parameters, and the text between the two markers."""

    page: str
    line: int
    name: str
    params: tuple[tuple[str, str], ...]
    body: str
    start: int  # the index of the opening marker's line in the page's lines
    end: int  # the index of the closing marker's line

    @property
    def label(self) -> str:
        return " ".join([self.name, *(f"{k}={v}" for k, v in self.params)])


# ---- reading the pages ---------------------------------------------------------------------------------


def pages(root: Path) -> list[str]:
    """The Markdown files under `root`, relative, with `/`, sorted."""
    found = []
    for folder, dirs, files in os.walk(root):
        dirs[:] = sorted(d for d in dirs if not d.startswith(".") and d not in SKIP_DIRS)
        rel = Path(folder).relative_to(root).as_posix()
        found += [f if rel == "." else f"{rel}/{f}" for f in files if f.endswith(".md")]
    return sorted(found)


def _marker_like(line: str) -> bool:
    return bool(LOOKS_LIKE.search(CODE_SPAN.sub("", line)))


def regions(page: str, text: str) -> list[Region]:
    """The generated regions of one page, in page order. A marker docgen cannot read stops it with a
    DocgenError that names the page, the line and the fix."""
    lines = text.split("\n")
    found: list[Region] = []
    fence: tuple[str, int] | None = None
    i = 0
    while i < len(lines):
        line = lines[i]
        m = FENCE.match(line)
        if fence:
            if m and m.group(1)[0] == fence[0] and len(m.group(1)) >= fence[1] and not m.group(2).strip():
                fence = None
            i += 1
            continue
        if m and not (m.group(1)[0] == "`" and "`" in m.group(2)):
            fence = (m.group(1)[0], len(m.group(1)))
            i += 1
            continue
        if not _marker_like(line):
            i += 1
            continue
        where, marker = f"{page}:{i + 1}", line.strip()
        close = CLOSE.fullmatch(marker)
        if close:
            raise DocgenError(f"{where}: {marker} closes no region: nothing above it opens {close['name']}")
        opening = OPEN.fullmatch(marker)
        if not opening:
            raise DocgenError(f"{where}: {marker} is not a marker docgen can read: {SYNTAX}")
        name, params = opening["name"], _params(opening["params"], where)
        _validate(name, params, where)
        for j in range(i + 1, len(lines)):
            if not _marker_like(lines[j]):
                continue
            inner = CLOSE.fullmatch(lines[j].strip())
            if inner and inner["name"] == name:
                break
            raise DocgenError(
                f"{page}:{j + 1}: {lines[j].strip()} is inside the region {name} opened on line {i + 1}:"
                f" close that region with <!-- /generated:{name} --> first"
            )
        else:
            raise DocgenError(
                f"{where}: {marker} is never closed: put <!-- /generated:{name} --> on a line of its own"
                " after the block"
            )
        found.append(Region(page, i + 1, name, params, "\n".join(lines[i + 1 : j]), i, j))
        i = j + 1
    return found


def _params(raw: str, where: str) -> tuple[tuple[str, str], ...]:
    out: dict[str, str] = {}
    for pair in raw.split():
        key, _, value = pair.partition("=")
        if key in out:
            raise DocgenError(f"{where}: {key}= is given twice")
        out[key] = value
    return tuple(out.items())


def _validate(name: str, params: tuple[tuple[str, str], ...], where: str) -> None:
    block = BLOCKS.get(name)
    if block is None:
        raise DocgenError(f"{where}: docgen writes no block named {name}; it writes {', '.join(BLOCKS)}")
    given = {k for k, _ in params}
    extra = sorted(given - set(block.params))
    if extra:
        raise DocgenError(f"{where}: {name} takes no {extra[0]}=")
    missing = [key for key in block.params if key not in given]
    if missing:
        raise DocgenError(
            f"{where}: {name} needs {missing[0]}=, as <!-- generated:{name} {missing[0]}=lg-webos -->"
        )
    for key, value in params:
        if key == "profile" and value not in profile.bundled_names():
            names = ", ".join(profile.bundled_names())
            raise DocgenError(f"{where}: there is no bundled profile {value}; the profiles are {names}")


# ---- the blocks ----------------------------------------------------------------------------------------


def _cell(text: str) -> str:
    return text.replace("|", "\\|")


def table(header: list[str], rows: list[list[str]]) -> str:
    """A Markdown table; an empty cell is one space, as the hand-written tables had it."""

    def line(cells: list[str]) -> str:
        return "|" + "|".join(f" {_cell(c)} " if c else " " for c in cells) + "|"

    return "\n".join([line(header), "|" + "|".join("---" for _ in header) + "|", *map(line, rows)])


def _code(text: str, command: re.Pattern[str]) -> str:
    """Each command of a plain text in a code span."""
    return command.sub(lambda m: f"`{m[0]}`", text)


def _profiles() -> list[profile.Profile]:
    """The bundled profiles in the support table's order; a profile without a name stops docgen."""
    bundled = set(profile.bundled_names())
    unnamed, gone = sorted(bundled - set(TV_NAMES)), sorted(set(TV_NAMES) - bundled)
    if unnamed:
        raise DocgenError(
            f"the bundled profile {unnamed[0]} has no name in the support table: add it to TV_NAMES"
        )
    if gone:
        raise DocgenError(f"TV_NAMES names {gone[0]}, which is not a bundled profile: take it out")
    return [profile.load(name) for name in TV_NAMES]


def _unpaired() -> list[profile.Profile]:
    """(samsung) The profiles the gateway reads without pairing, each with the words its [support] gives
    for what tvgw does and what the reading reads; a profile without them stops docgen."""
    found = []
    for name in setup.READ_WITHOUT_PAIRING:
        p = profile.load(name)
        if not (p.does and p.can_check and p.cannot_check):
            raise DocgenError(
                f"the gateway reads {name} TVs without pairing (setup.READ_WITHOUT_PAIRING) and its profile's"
                " [support] does not say it: give it does, can_check and cannot_check"
            )
        found.append(p)
    return found


def _readers() -> None:
    """READERS and READS describe exactly the profiles the gateway can pair with."""
    pairable = set(setup.PAIRABLE_PROFILES)
    undescribed = sorted(pairable - set(READERS) | pairable - set(READS))
    unread = sorted(set(READERS) - pairable | set(READS) - pairable)
    if undescribed:
        raise DocgenError(
            f"the gateway can read {undescribed[0]} TVs (setup.PAIRABLE_PROFILES) and docgen has no plain"
            " words for it: add it to READERS and READS"
        )
    if unread:
        raise DocgenError(
            f"READERS or READS describes {unread[0]}, which the gateway cannot pair with: take it out"
        )


def generation_support(p: profile.Profile, g: profile.Generation) -> str:
    """A generation's support level: (W12) the row's own `support` where it gives one; else the
    profile's where the row is verified, else not yet tested, since a tested profile was tested on its
    verified generation alone."""
    if g.support:
        return g.support
    return p.support if g.verified else "not-yet-tested"


def _runs(p: profile.Profile) -> list[tuple[tuple[profile.Generation, ...], str]]:
    """The profile's generations in runs of one support level: the strongest level first, and within a
    level the newest run first."""
    runs: list[tuple[list[profile.Generation], str]] = []
    for g in p.generations:
        level = generation_support(p, g)
        if runs and runs[-1][1] == level:
            runs[-1][0].append(g)
        else:
            runs.append(([g], level))
    rank = list(profile.SUPPORT)
    order = sorted(range(len(runs)), key=lambda i: (rank.index(runs[i][1]), -i))
    return [(tuple(runs[i][0]), runs[i][1]) for i in order]


def _span(p: profile.Profile, run: tuple[profile.Generation, ...]) -> str:
    """`webOS 5 (2020 sets)`, `webOS 3 and 4 (2016 to 2019 sets)`, `webOS 6 and later (2021 on)`."""
    to_the_end = run[-1] is p.generations[-1] and len(run) > 1
    first, last = run[0].webos, run[-1].webos
    if len(run) == 1:
        os_part = f"{OS_NAME} {first}"
    elif to_the_end:
        os_part = f"{OS_NAME} {first} and later"
    elif len(run) == 2:
        os_part = f"{OS_NAME} {first} and {last}"
    else:
        os_part = f"{OS_NAME} {first} to {last}"
    years = sorted({y for g in run for y in g.years})
    if not years:
        return os_part
    if len(years) == 1:
        return f"{os_part} ({years[0]} sets)"
    if to_the_end:
        return f"{os_part} ({years[0]} on)"
    return f"{os_part} ({years[0]} to {years[-1]} sets)"


def _seen(p: profile.Profile) -> bool:
    """Whether anything in the profile was seen on a set: a verified record or generation."""
    records = (*p.lan_apis, *p.privacy_settings)
    return any(r.provenance.verified for r in records) or any(g.verified for g in p.generations)


@dataclass(frozen=True)
class SupportRow:
    profile: str
    tv: str
    level: str
    status: str
    does: str
    you_check: str


def _support_row(p: profile.Profile, tv: str, level: str) -> SupportRow:
    word = profile.SUPPORT[level]
    if level == "tested":
        status = f"**{word}** on {'; '.join(p.tested_on)}"
    elif p.generations and level != p.support:
        status = f"**{word}** on these versions"
    elif p.name == profile.GENERIC:
        status = f"**{word}**, with the general profile"
    elif not _seen(p):
        status = f"**{word}**, built from published research"
    else:
        status = f"**{word}**"
    you_check = ""
    if p.name in READERS:
        reader = READERS[p.name].get(level)
        if reader is None:
            raise DocgenError(
                f"READERS has no words for what the gateway does on {p.name} TVs that are {word}"
            )
        does, you_check = reader.does, reader.you_check
    elif p.name in setup.READ_WITHOUT_PAIRING:  # (samsung) read without pairing: the profile says what
        does = p.does
    elif not p.custom_rules and not p.must_allow:
        does = SHARED_LISTS_ONLY
    else:
        does = BLOCKS_ONLY
    you_check = you_check or p.you_check
    if not you_check:
        raise DocgenError(
            f"profile {p.name} has no [support] you_check: the support table says what its owner checks"
        )
    return SupportRow(p.name, tv, level, status, does, you_check)


def support_rows() -> list[SupportRow]:
    """One row per bundled profile and support level, in TV_NAMES' order; a profile with generations has
    one row per run of generations at one level."""
    _readers()
    _unpaired()
    rows = []
    for p in _profiles():
        if not p.support:
            raise DocgenError(
                f"profile {p.name} has no [support] table: the support table needs its status and what its"
                " owner checks"
            )
        if p.generations:
            rows += [_support_row(p, f"{TV_NAMES[p.name]}, {_span(p, run)}", lv) for run, lv in _runs(p)]
        else:
            rows.append(_support_row(p, TV_NAMES[p.name], p.support))
    return rows


def support_table(with_profile: bool = False) -> str:
    header = ["TV", "Status", "What tvgw does", "What you check on the TV yourself"]
    found = support_rows()
    if not with_profile:
        return table(header, [[r.tv, r.status, r.does, r.you_check] for r in found])
    rows = [[r.tv, f"`{r.profile}`", r.status, r.does, r.you_check] for r in found]
    return table([header[0], "Profile", *header[1:]], rows)


def generations(profile_name: str) -> str:
    """(W12) The profile's generations: what each row's TV reports and which pairing works there, its
    support level and how it is known; then where each row's menus are, for the rows that give them."""
    p = profile.load(profile_name)
    if not p.generations:
        raise DocgenError(f"profile {profile_name} has no [[generations]] rows for a generations block")
    unknown = sorted({g.manifest for g in p.generations} - set(MANIFESTS))
    if unknown:
        raise DocgenError(f"a [[generations]] row names the manifest {unknown[0]!r}: add it to MANIFESTS")
    rows = []
    for g in p.generations:
        level = generation_support(p, g)
        word = profile.SUPPORT[level]
        status = f"**{word}** on {'; '.join(p.tested_on)}" if level == "tested" else word
        rows.append(
            [
                g.webos,
                ", ".join(map(str, g.years)),
                ", ".join(g.models),
                g.release_range,
                MANIFESTS[g.manifest],
                status,
                KNOWN_BY[g.confidence],
            ]
        )
    out = table(
        [OS_NAME, "Years", "Models", "The TV reports", "The pairing that works", "Status", "How it is known"],
        rows,
    )
    topics = [t for t in profile.MENU_TOPICS if any(g.menu_path(t) for g in p.generations)]
    menus = [[g.webos, *(g.menu_path(t) for t in topics)] for g in p.generations if g.menu]
    if menus:
        out += "\n\nWhere the settings are, by version:\n\n" + table(
            [OS_NAME, *(MENU_NAMES[t] for t in topics)], menus
        )
    return out


def can_check(profile_name: str) -> str:
    _readers()
    unpaired = {p.name: p for p in _unpaired()}
    if profile_name in unpaired:  # (samsung) read without pairing: the profile's own lists
        p = unpaired[profile_name]

        def listed(items: tuple[str, ...]) -> str:
            *rest, final = items
            return "\n".join([f"- {x};" for x in rest] + [f"- {final}."])

        return f"{READS_UNPAIRED}\n\n{listed(p.can_check)}\n\n{CANNOT_READ}\n\n{listed(p.cannot_check)}"
    if profile_name not in setup.PAIRABLE_PROFILES:
        return READS_NOTHING
    *items, final = READS[profile_name]
    lines = [f"- {x};" for x in items] + [f"- {final}."]
    return "Once the TV is paired, the gateway reads it every hour:\n\n" + "\n".join(lines)


def verify_checks() -> str:
    """verify's groups, its settling checks and its plain words, as docs/reference/verify-checks.md shows
    them under "In plain words"."""
    lines = [
        f"- {sentence}: " + ", ".join(f"`{n}`" for n in names) for sentence, names in verify.GROUPS.items()
    ]
    settling = ", ".join(f"`{n}`" for n in verify.PLAIN if n in verify.SETTLING)
    lines += [
        "",
        f"The settling checks, which may fail for a few minutes after an install or a restart: {settling}.",
        "",
    ]
    rows = [[f"`{name}`", *(_code(part, COMMAND) for part in parts)] for name, parts in verify.PLAIN.items()]
    return "\n".join(lines) + "\n" + table(["Check", "What it means", "What you notice", "The fix"], rows)


def verify_new_checks() -> str:
    """The checks still held at a warning, and the level each one takes once promoted."""
    unknown = sorted(set(verify.FAIL_AFTER) - set(verify.PLAIN))
    if unknown:
        raise DocgenError(f"verify.FAIL_AFTER names {unknown[0]}, which is not a check in verify.PLAIN")
    rows = []
    for name in verify.PLAIN:
        if name not in verify.FAIL_AFTER:
            continue
        later = "FAIL" if verify.FAIL_AFTER[name] == verify.FAIL else "WARN at most"
        rows.append([f"`{name}`", later if name in verify.PROMOTED else "WARN at most", later])
    return table(["Check", "Worst level now", "Once promoted"], rows)


def red_lines() -> str:
    """Each red line's tier and plain words in the brief's order, then each profile's action for the
    lines whose action is the TV's screen-recognition setting."""
    rows = []
    for prefix, tier, sentence, action in plain.RED_LINE_PLAIN:
        if tier == "detail":
            says, asks = DETAIL_ONLY, ""
        elif action == plain.MENU_ACR:
            says, asks = sentence, MENU_ACR_HERE
        else:
            says, asks = sentence, plain.action_text(action, None)
        rows.append([f"`{prefix.rstrip()}`", tier, _code(says, TVGW_COMMAND), _code(asks, TVGW_COMMAND)])
    acr = [[f"`{p.name}`", _code(plain.action_text(plain.MENU_ACR, p), TVGW_COMMAND)] for p in _profiles()]
    return (
        table(["The line begins", "Plain brief", "What the plain brief says", "What it asks"], rows)
        + "\n\n"
        + table(["Profile", "What the Live Plus and ACR lines ask"], acr)
    )


@dataclass(frozen=True)
class Block:
    render: Callable[..., str]
    params: tuple[str, ...] = ()  # the parameters a marker must give, as `profile=lg-webos`


BLOCKS: dict[str, Block] = {
    "support-table": Block(support_table),
    "profile-support": Block(lambda: support_table(with_profile=True)),
    "generations": Block(lambda **given: generations(given["profile"]), ("profile",)),
    "can-check": Block(lambda **given: can_check(given["profile"]), ("profile",)),
    "verify-checks": Block(verify_checks),
    "verify-new-checks": Block(verify_new_checks),
    "red-lines": Block(red_lines),
}


def render(name: str, params: tuple[tuple[str, str], ...] = ()) -> str:
    """The text of one block, without its markers."""
    return BLOCKS[name].render(**dict(params))


# ---- checking and writing ------------------------------------------------------------------------------


def stale(root: Path) -> tuple[list[Region], list[tuple[Region, str]]]:
    """Every generated region under `root`, and those whose text differs from the code, with the text."""
    found = [r for page in pages(root) for r in regions(page, (root / page).read_text(encoding="utf-8"))]
    written: dict[tuple[str, tuple[tuple[str, str], ...]], str] = {}
    out = []
    for r in found:
        key = (r.name, r.params)
        if key not in written:
            written[key] = render(r.name, r.params)
        if r.body != written[key]:
            out.append((r, written[key]))
    return found, out


def rewrite(text: str, changes: list[tuple[Region, str]]) -> str:
    """The page with each region's text replaced; nothing outside the markers changes."""
    lines = text.split("\n")
    for r, body in sorted(changes, key=lambda change: change[0].start, reverse=True):
        lines[r.start + 1 : r.end] = body.split("\n")
    return "\n".join(lines)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="docgen", description="Write the documentation's generated tables from the code, or check them."
    )
    parser.add_argument("--check", action="store_true", help="write nothing; exit 1 if a region differs")
    parser.add_argument(
        "--root", type=Path, default=ROOT, help="the tree whose pages to read (default: this one)"
    )
    args = parser.parse_args(argv)
    root = args.root.resolve()
    try:
        found, changes = stale(root)
    except DocgenError as exc:
        print(f"docgen: {exc}; nothing was written", file=sys.stderr)
        return 2
    count = f"{len(found)} generated region{'' if len(found) == 1 else 's'}"
    on = len({r.page for r in found})
    if args.check:
        for r, _ in changes:
            print(f"{r.page}:{r.line}: {r.label}: differs from the code; run `make docgen`, then commit it")
        sys.stdout.flush()
        if changes:
            print(f"docgen: {len(changes)} of {count} differ from the code", file=sys.stderr)
            return 1
        print(f"docgen: {count} on {on} page{'' if on == 1 else 's'}, all as the code has them")
        return 0
    by_page: dict[str, list[tuple[Region, str]]] = {}
    for r, body in changes:
        by_page.setdefault(r.page, []).append((r, body))
    for page, page_changes in sorted(by_page.items()):
        path = root / page
        path.write_text(rewrite(path.read_text(encoding="utf-8"), page_changes), encoding="utf-8")
        print(f"docgen: wrote {page}: {', '.join(r.label for r, _ in page_changes)}")
    print(f"docgen: {count} on {on} page{'' if on == 1 else 's'}, all as the code has them")
    return 0


if __name__ == "__main__":
    sys.exit(main())
