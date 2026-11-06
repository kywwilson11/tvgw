#!/usr/bin/env python3
"""Move the documentation's pages the way tools/page-map.csv says, and take every pointer to them along.

The page map has one row per moved, merged, split, cut or new section of the documentation. This
script makes the part of a move that needs no judgement, and it may run again at any time: after a
rebase, which can bring links written against the old paths, or after a section was moved by hand.

- A page moves whole, with `git mv`: to the new path of its row without an anchor, or, when the map
  only splits it, to the new path of its first row. The sections other rows send elsewhere stay in the
  moved page until someone moves them by hand; nothing here cuts a page apart.
- Every relative link of every Markdown file follows it: a link to a page that moved, and each link of
  a page that moved, recomputed from the linking file's new folder (inline links, reference
  definitions, and the `href`, `src` and `srcset` of HTML such as a figure's `<picture>`); a link
  that now leads to a section of its own page is written as the anchor alone. The records (RECORDS)
  get these link edits and nothing else; their text never changes.
- On every other Markdown page, a repository path written as text, such as `docs/<page>.md` in a list
  or a code span, follows too, and so does a link label that repeats its link's path.
- Every docs path a file that is not Markdown names follows: a message in src/, a comment in deploy/,
  nfpm's `./docs/...`, a workflow, an issue form, a test, and `"docs" / "<page>.md"` in Python.
- An anchor follows its section. A pointer to a section the map sends elsewhere points where the
  section is now: at the page it moved with, until its anchor is gone from there and present at the
  map's new home. A subsection's anchor follows when exactly one of the pages the map sends that page's
  sections to holds it.
- A page that released code prints (STUBS) keeps a stub at its old path, its H1 and one sentence
  linking the new home, which nothing links to.
- A new page of the map that no move creates (PLACEHOLDERS) gets its H1 and a short lead when
  it is missing; a page that exists is never touched.

Fenced code blocks are examples and are left as they are, and so are links to other sites.

    python3 tools/rewrite_doc_paths.py [--root DIR] [--map CSV] [--check] [--no-stubs]
        Make the moves and the rewrites, and print what was moved, created and rewritten.
        --check changes nothing: one line per change it would make, and exit 1 when there is one.
        --no-stubs leaves the stubs out, so that a first commit holds the moves alone and git
        records each as a rename; a second run writes them.
        Exit 1, with nothing changed, when the tree and the map disagree (a page at both its old and
        its new path, or at neither); exit 2 when the map cannot be read or git cannot list or move
        the files.

Standard library only, with git's `ls-files` and `mv` in a git checkout (any other folder is walked,
and files are renamed). It reads Markdown with tools/check_docs_links.py, so the two agree on what a
link and an anchor are.
"""

from __future__ import annotations

import argparse
import csv
import importlib.util
import os
import posixpath
import re
import subprocess
import sys
from collections.abc import Iterable, Mapping
from dataclasses import dataclass, field
from pathlib import Path
from urllib.parse import quote, unquote

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent


def _load_checker():
    """tools/check_docs_links.py as a module, by its path, so `python3 -I` finds it too."""
    name = "check_docs_links"
    if name in sys.modules:
        return sys.modules[name]
    spec = importlib.util.spec_from_file_location(name, HERE / "check_docs_links.py")
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module  # a dataclass looks its module up by name
    spec.loader.exec_module(module)
    return module


cdl = _load_checker()

MAP = "tools/page-map.csv"
FIELDS = ["old_path", "old_anchor", "new_path", "new_anchor", "action", "note"]
ACTIONS = frozenset({"move", "merge", "split", "cut", "new", "keep", "rewrite"})
# the actions that take a section, or a whole page, somewhere else
MOVING = frozenset({"move", "merge", "split"})

# the records: a move edits their links and never their text (design decision D9 of the restructure)
RECORDS = ("CHANGELOG.md", "docs/design-decisions.md", "docs/incidents.md")
RECORD_FOLDERS = ("docs/research/",)

# the old paths that released code prints (v0.2.0's messages and comments, its workflows, its release
# notes and issue forms, and the settings template copied once into /etc/tvgw/tvgw.conf), each kept as a
# stub for one release; a path leaves this list, and its stub the tree, once no supported release
# prints it
STUBS = (
    "docs/adding-a-profile.md",
    "docs/adguard.md",
    "docs/capture.md",
    "docs/operations.md",
    "docs/packaging.md",
    "docs/privacy-and-retention.md",
    "docs/setup.md",
    "docs/troubleshooting.md",
)

# the new pages of the map that no move creates, and the README of each new folder the map gives one:
# the H1 and the short lead each starts with, written only when the page is missing
PLACEHOLDERS: dict[str, tuple[str, str]] = {
    # a user page's lead keeps each sentence to 18 words at most, the target for the pages a reader
    # who is not an engineer reads (what it stops, install, use, your TV)
    "docs/what-it-stops.md": (
        "What it stops, and what it cannot",
        "tvgw controls only the traffic that passes through the gateway. It may not stop everything: "
        "how much it stops depends on the TV.",
    ),
    "docs/install/choosing-a-gateway.md": (
        "Choose a gateway computer",
        "The gateway is a small computer with a port for the TV, such as a Raspberry Pi 5.",
    ),
    "docs/tv/README.md": (
        "Which TVs work",
        "tvgw is tested on an LG CX; its Samsung, Roku and Vizio support is not yet tested.",
    ),
    "docs/tv/lg-webos.md": (
        "LG TVs",
        "tvgw is tested on an LG CX with webOS 5; see [what an LG CX does, measured](lg-cx-measured.md).",
    ),
    "docs/tv/samsung-tizen.md": (
        "Samsung TVs",
        "tvgw's Samsung profile is built from published blocklists and research, and is not yet tested.",
    ),
    "docs/tv/roku.md": (
        "Roku TVs",
        "tvgw's profile for Roku TVs and players is built from blocklists and research, and is not yet "
        "tested.",
    ),
    "docs/tv/vizio-smartcast.md": (
        "Vizio TVs",
        "tvgw's Vizio profile is built from a published blocklist and research, and is not yet tested.",
    ),
    "docs/how-it-works/README.md": (
        "How tvgw works, in pictures",
        "tvgw puts the TV on a network of its own behind the gateway, filters the names it looks up and "
        "records what it does, and [the architecture](architecture.md) explains each part.",
    ),
    "docs/project/README.md": (
        "Working on tvgw",
        "This part is for contributors and the maintainer: where each part of tvgw lives, its folder "
        "READMEs and its records, and [writing these pages](writing-docs.md) sets the rules for every "
        "page.",
    ),
}

# files never rewritten: the map and this script name the old paths on purpose
# (uplink) and the released tvgw-apply the WAN_GW_MODE tests run as an older release would, which is a
# verbatim copy of v0.2.0's file: its comments name the pages v0.2.0 shipped with, whose stubs stand
KEEP_AS_WRITTEN = (
    MAP,
    "tools/rewrite_doc_paths.py",
    "tests/unit/tvgw-apply-v0.2.0",
    "tests/unit/tvgw-apply-v0.3.2",
)

# `"docs" / "<page>.md"`, a path the tests build with pathlib
PATHLIB = re.compile(r'"docs"((?:[ \t]*/[ \t]*"[A-Za-z0-9_.-]+")+)')
PATHLIB_PART = re.compile(r'"([A-Za-z0-9_.-]+)"')
# each URL of a `srcset`: the first word of each comma-separated part
SRCSET_URL = re.compile(r"(?:^|,)\s*([^\s,]+)")
# a link with a plain label, the label first: `[label](destination)`
LABELLED = re.compile(r"\[([^\[\]\n]*)\]\(\s*(<[^>\n]*>|[^\s()<>]+)")
ANCHOR = re.compile(r"[\w-]+")


class MapError(Exception):
    """The page map cannot be read, or says two things at once."""


class TreeError(Exception):
    """git could not list or move the files."""


@dataclass(frozen=True)
class Row:
    """One row of the page map, with the line it is on."""

    line: int
    old_path: str
    old_anchor: str
    new_path: str
    new_anchor: str
    action: str


def read_map(path: Path) -> list[Row]:
    """The rows of a page map, checked one by one."""
    try:
        handle = path.open(encoding="utf-8", newline="")
    except OSError as exc:
        raise MapError(f"{path}: {exc.strerror or exc}") from exc
    with handle:
        reader = csv.DictReader(handle)
        if reader.fieldnames != FIELDS:
            raise MapError(f"{path}: the header must be {','.join(FIELDS)}")
        rows = []
        for record in reader:
            if None in record or any(record.get(k) is None for k in FIELDS):
                raise MapError(f"{path}:{reader.line_num}: a row has {len(FIELDS)} fields")
            row = Row(reader.line_num, *(record[k].strip() for k in FIELDS[:5]))
            _check_row(path, row)
            rows.append(row)
    return rows


def _check_row(path: Path, row: Row) -> None:
    where = f"{path}:{row.line}"
    if row.action not in ACTIONS:
        raise MapError(f"{where}: unknown action {row.action!r}")
    for name in ("old_path", "new_path"):
        value = getattr(row, name)
        if value.startswith("/") or ".." in value.split("/") or "#" in value:
            raise MapError(f"{where}: {name} {value!r} is not a path from the repository root")
    for name in ("old_anchor", "new_anchor"):
        value = getattr(row, name)
        if value and not ANCHOR.fullmatch(value):
            raise MapError(f"{where}: {name} {value!r} is not an anchor")
    if row.action == "new" and (row.old_path or not row.new_path):
        raise MapError(f"{where}: a new page has a new path and no old one")
    if row.action != "new" and not row.old_path:
        raise MapError(f"{where}: only a new page has no old path")
    if row.action in MOVING and not row.new_path:
        raise MapError(f"{where}: {row.action} needs a new path")


@dataclass(frozen=True)
class PageMap:
    """What the map says about each page: where it moves whole, and where each of its sections goes."""

    moves: Mapping[str, str]  # an old page -> the page it moves to whole
    sections: Mapping[tuple[str, str], tuple[str, str]]  # (old page, anchor) -> (new page, anchor or "")
    whole_anchors: Mapping[str, str]  # an old page merged as one section -> that section's anchor
    homes: Mapping[str, str]  # the inverse of moves
    spread: Mapping[str, frozenset[str]]  # an old page -> every page its rows send it or its sections to
    named: frozenset[str]  # every new path the map names

    @classmethod
    def from_rows(cls, rows: Iterable[Row]) -> PageMap:
        rows = list(rows)
        pages: dict[str, list[Row]] = {}
        for row in rows:
            if row.old_path.endswith(".md"):
                pages.setdefault(row.old_path, []).append(row)
        moves: dict[str, str] = {}
        whole_anchors: dict[str, str] = {}
        for page, own in pages.items():
            whole = [r for r in own if not r.old_anchor]
            if len(whole) > 1:
                raise MapError(f"line {whole[1].line}: a second row for the whole of {page}")
            if whole:
                row = whole[0]
                if row.action in ("move", "merge") and row.new_path != page:
                    moves[page] = row.new_path
                    if row.new_anchor:
                        whole_anchors[page] = row.new_anchor
                continue
            first = next((r for r in own if r.action in MOVING), None)
            if first and first.new_path != page:
                moves[page] = first.new_path
        homes: dict[str, str] = {}
        for old, new in moves.items():
            if not new.endswith(".md"):
                raise MapError(f"{old} moves to {new}, which is not a Markdown page")
            if new in homes:
                raise MapError(f"{homes[new]} and {old} both move whole to {new}")
            if new in pages:
                raise MapError(f"{old} moves to {new}, a page the map also lists as an old one")
            homes[new] = old
        sections: dict[tuple[str, str], tuple[str, str]] = {}
        for row in rows:
            if row.old_anchor and row.action in MOVING and row.old_path.endswith(".md"):
                key = (row.old_path, row.old_anchor)
                if key in sections:
                    raise MapError(f"line {row.line}: a second row for {row.old_path}#{row.old_anchor}")
                sections[key] = (row.new_path, row.new_anchor)
        spread = {
            page: frozenset({r.new_path for r in own if r.new_path} | {moves.get(page, page)})
            for page, own in pages.items()
        }
        named = frozenset(r.new_path for r in rows if r.new_path)
        return cls(moves, sections, whole_anchors, homes, spread, named)

    def page(self, path: str) -> str:
        """Where a page is after the moves."""
        return self.moves.get(path, path)

    def origin(self, page: str) -> str:
        """The old page whose rows say where the sections of `page` go."""
        return self.homes.get(page, page)


def is_record(path: str) -> bool:
    return path in RECORDS or path.startswith(RECORD_FOLDERS)


def is_stub(text: str) -> bool:
    """A stub is an H1 and one line that links somewhere, and nothing else."""
    lines = [line for line in text.splitlines() if line.strip()]
    return len(lines) == 2 and lines[0].startswith("# ") and "](" in lines[1]


def _read(root: Path, rel: str) -> str | None:
    """A file as UTF-8 text, or None for a binary file or one that is not UTF-8."""
    data = (root / rel).read_bytes()
    if b"\0" in data[:8192]:
        return None
    try:
        return data.decode("utf-8")
    except UnicodeDecodeError:
        return None


def h1(text: str) -> str | None:
    for _, line in cdl.prose_lines(text):
        if line.startswith("# "):
            return line[2:].strip()
    return None


@dataclass
class View:
    """The tree as it is once the planned moves are made: which files it holds, read from where they
    are now, and the pages this run creates."""

    root: Path
    files: set[str]
    source: dict[str, str] = field(default_factory=dict)  # a path after the moves -> where it is now
    created: dict[str, str] = field(default_factory=dict)  # a path -> the text this run writes there
    _anchors: dict[str, set[str]] = field(default_factory=dict)

    def text(self, path: str) -> str | None:
        if path in self.created:
            return self.created[path]
        if path not in self.files:
            return None
        return _read(self.root, self.source.get(path, path))

    def anchors(self, path: str) -> set[str]:
        if path not in self._anchors:
            text = self.text(path) if path.endswith(".md") else None
            self._anchors[path] = cdl.anchors(text) if text is not None else set()
        return self._anchors[path]

    def create(self, path: str, text: str) -> None:
        self.created[path] = text
        self.files.add(path)
        self._anchors.pop(path, None)


def follow(pages: PageMap, view: View, path: str, anchor: str) -> tuple[str, str]:
    """Where a pointer to `path` and its `anchor` (without the `#`, or empty) points after the moves."""
    page = pages.page(path)
    if not page.endswith(".md"):
        return page, anchor
    if not anchor:
        merged = pages.whole_anchors.get(path) if path in pages.moves else None
        if merged and merged in view.anchors(page):
            return page, merged
        return page, ""
    origin = pages.origin(page)
    here = anchor in view.anchors(page)
    target = pages.sections.get((origin, anchor))
    if target:
        new_page, new_anchor = target
        if here or target == (page, anchor):
            return page, anchor  # the section is still in the page it moved with
        if new_page in view.files and (not new_anchor or new_anchor in view.anchors(new_page)):
            return new_page, new_anchor
        return page, anchor  # it is nowhere yet: the link check names the pointer
    if here:
        return page, anchor
    holders = sorted(p for p in pages.spread.get(origin, ()) if p != page and anchor in view.anchors(p))
    return (holders[0], anchor) if len(holders) == 1 else (page, anchor)


@dataclass(frozen=True)
class Edit:
    """One pointer rewritten: the file (where it is after the moves), the line, and the text before and
    after."""

    path: str
    line: int
    old: str
    new: str

    def __str__(self) -> str:
        return f"{self.path}:{self.line}: {self.old} -> {self.new}"


@dataclass
class Rewriter:
    """Rewrites the pointers of one file, read at `src` and written at `dst`."""

    pages: PageMap
    view: View
    src: str
    dst: str

    def link(self, written: str) -> str:
        """A Markdown link destination as it must be written from `dst`."""
        if cdl.external(written):
            return written
        wrapped = written.startswith("<") and written.endswith(">")
        dest = written[1:-1].strip() if wrapped else written.strip()
        own = cdl.SELF_URL.match(dest)
        prefix = ""
        if own:
            prefix, dest = dest[: own.start(1)], own.group(1)
        path_part, _, fragment = dest.partition("#")
        path_part, asked, query = path_part.partition("?")
        if path_part:
            start = "" if path_part.startswith("/") else posixpath.dirname(self.src)
            target = posixpath.normpath(posixpath.join(start, unquote(path_part).lstrip("/")))
            target = "" if target == "." else target
            if target == ".." or target.startswith("../"):
                return written  # it leaves the repository
        else:
            target = self.src
        anchor = unquote(fragment)
        if target.endswith(".md") and "plain=1" not in query:
            new_target, new_anchor = follow(self.pages, self.view, target, anchor)
        else:
            new_target, new_anchor = self.pages.page(target), anchor
        if (new_target, new_anchor) == (target, anchor) and self.dst == self.src:
            return written
        if own or path_part.startswith("/"):
            new_path = "/" + new_target
        elif new_target == self.dst and not asked and (new_anchor or not path_part):
            new_path = ""  # a section of the linking page itself: its anchor alone, as the pages write it
        else:
            new_path = posixpath.relpath(new_target or ".", posixpath.dirname(self.dst) or ".")
            if path_part.startswith("./") and not new_path.startswith("."):
                new_path = "./" + new_path
            if path_part.endswith("/") and not new_path.endswith("/"):
                new_path += "/"
        if "%" in path_part:
            new_path = quote(new_path, safe="/.-_~")
        # an anchor that did not change keeps the spelling it was written with
        new_fragment = (fragment if new_anchor == anchor else new_anchor) if new_anchor else ""
        out = prefix + new_path + (f"?{query}" if asked else "")
        out += f"#{new_fragment}" if new_fragment else ""
        if not out:
            return written
        return f"<{out}>" if wrapped else out

    def target_moved(self, written: str) -> bool:
        """Whether a destination's page or anchor changes, not only the folder it is written from."""
        return Rewriter(self.pages, self.view, self.src, self.src).link(written) != written

    def printed(self, written: str) -> str:
        """A repository path written from the root (`./` and an anchor allowed), as it must read now."""
        dot = "./" if written.startswith("./") else ""
        path, _, anchor = written.removeprefix("./").partition("#")
        new_path, new_anchor = follow(self.pages, self.view, path, anchor)
        if (new_path, new_anchor) == (path, anchor):
            return written
        return dot + new_path + (f"#{new_anchor}" if new_anchor else "")

    def self_url(self, written: str) -> str:
        """A link to this repository's main branch, as it must read now."""
        m = cdl.SELF_URL.match(written)
        path = m.group(1).lstrip("/")
        new = self.printed(path)
        return written if new == path else written[: m.start(1)] + "/" + new

    def pathlib(self, m: re.Match) -> str:
        """`"docs" / "<page>.md"` with the parts of the page's path now."""
        written = "/".join(["docs", *PATHLIB_PART.findall(m.group(1))])
        new, _ = follow(self.pages, self.view, written, "") if written.endswith(".md") else (written, "")
        if new == written:
            return m.group(0)
        sep = re.match(r"[ \t]*/[ \t]*", m.group(1)).group(0)
        return '"' + f'"{sep}"'.join(new.split("/")) + '"'


def rewrite_markdown(text: str, rewriter: Rewriter, record: bool) -> tuple[str, list[Edit]]:
    """A Markdown file with its pointers rewritten: in a record, the link destinations alone."""
    lines = text.splitlines(keepends=True)
    prose = {number for number, _ in cdl.prose_lines(text)}
    edits: list[Edit] = []
    for number, line in enumerate(lines, 1):
        if number not in prose:
            continue
        masked = cdl.CODE_SPAN.sub(lambda m: " " * len(m.group(0)), line)
        destinations = _destinations(line, masked)
        changes: list[tuple[int, int, str]] = []  # (start, end, new text) within the line
        moved: set[tuple[int, int]] = set()  # the destinations whose page or anchor changes
        for start, end in destinations:
            written = line[start:end]
            new = rewriter.link(written)
            if new != written:
                changes.append((start, end, new))
                if rewriter.target_moved(written):
                    moved.add((start, end))
        if not record:
            changes += _labels(line, masked, rewriter, moved)
            changes += _text_paths(line, destinations + [(s, e) for s, e, _ in changes], rewriter)
        if changes:
            new_line = line
            for start, end, replacement in sorted(changes, reverse=True):
                new_line = new_line[:start] + replacement + new_line[end:]
            edits += [Edit(rewriter.dst, number, line[s:e], r) for s, e, r in sorted(changes)]
            lines[number - 1] = new_line
    return "".join(lines), edits


def _destinations(line: str, masked: str) -> list[tuple[int, int]]:
    """The spans of a line's link destinations, as tools/check_docs_links.py reads them: inline links
    and images, a reference definition, and each URL of an HTML `href`, `src` or `srcset`. `masked` is
    the line with its code spans blanked, so it has the line's length."""
    spans = [m.span(1) for m in cdl.INLINE.finditer(masked)]
    m = cdl.REF_DEF.match(masked)
    if m:
        spans.append(m.span(1))
    for m in cdl.HTML_ATTR.finditer(masked):
        group = 2 if m.group(2) is not None else 3
        start, end = m.span(group)
        if m.group(1).lower() == "srcset":  # `a.png 2x, b.png 1x`: the first word of each part
            spans += [(start + u.start(1), start + u.end(1)) for u in SRCSET_URL.finditer(line[start:end])]
        else:
            spans.append((start, end))
    return spans


def _labels(
    line: str, masked: str, rewriter: Rewriter, moved: set[tuple[int, int]]
) -> list[tuple[int, int, str]]:
    """A label that repeats its destination's path (`[x.md](x.md)`) follows a destination whose page
    moved."""
    out = []
    for m in LABELLED.finditer(masked):
        if m.span(2) not in moved:
            continue
        label = line[m.start(1) : m.end(1)]
        written = line[m.start(2) : m.end(2)]
        bare = label.strip("`")
        path = _path_part(written)
        new_path = _path_part(rewriter.link(written))
        if bare and bare == path and new_path and new_path != path:
            out.append((m.start(1), m.end(1), label.replace(bare, new_path, 1)))
    return out


def _path_part(destination: str) -> str:
    inner = destination[1:-1].strip() if destination.startswith("<") else destination
    return inner.partition("#")[0].partition("?")[0]


def _text_paths(line: str, covered: list[tuple[int, int]], rewriter: Rewriter) -> list[tuple[int, int, str]]:
    """Repository paths written as text in the line (in a list, a table or a code span), outside its
    link destinations and the spans already rewritten."""

    def free(start: int, end: int) -> bool:
        return not any(s < end and start < e for s, e in covered)

    out = []
    for m in cdl.PRINTED.finditer(line):
        new = rewriter.printed(m.group(0))
        if new != m.group(0) and free(*m.span()):
            out.append((m.start(), m.end(), new))
    for m in cdl.SELF_URL.finditer(line):
        written = m.group(0).rstrip(".,;:")
        new = rewriter.self_url(written)
        if new != written and free(m.start(), m.start() + len(written)):
            out.append((m.start(), m.start() + len(written), new))
    return out


def rewrite_other(text: str, rewriter: Rewriter, python: bool) -> tuple[str, list[Edit]]:
    """A file that is not Markdown with the repository paths it names rewritten: the paths from the root
    that tools/check_docs_links.py reads, the links to this repository's main branch, and in Python the
    paths built with pathlib."""
    edits: list[Edit] = []

    def sub(source: str, pattern: re.Pattern, fix) -> str:
        pieces, last = [], 0
        for m in pattern.finditer(source):
            written = m.group(0).rstrip(".,;:") if pattern is cdl.SELF_URL else m.group(0)
            new = fix(m) if pattern is PATHLIB else fix(written)
            if new != written:
                edits.append(Edit(rewriter.dst, source.count("\n", 0, m.start()) + 1, written, new))
                pieces += [source[last : m.start()], new]
                last = m.start() + len(written)
        return "".join(pieces) + source[last:]

    out = sub(text, cdl.PRINTED, rewriter.printed)
    out = sub(out, cdl.SELF_URL, rewriter.self_url)
    if python:
        out = sub(out, PATHLIB, rewriter.pathlib)
    return out, edits


@dataclass
class Plan:
    """What a run does: the moves, the files it writes (by their path after the moves, created ones
    included) and the pointers it rewrites; what stops it, and what it could not do but need not stop
    for."""

    moves: list[tuple[str, str]] = field(default_factory=list)
    writes: dict[str, str] = field(default_factory=dict)
    created: list[str] = field(default_factory=list)
    edits: list[Edit] = field(default_factory=list)
    problems: list[str] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)

    def empty(self) -> bool:
        return not (self.moves or self.writes or self.problems)


def stub_text(old: str, home: str, view: View) -> str:
    title = h1(view.text(home) or "") or posixpath.basename(old)
    link = posixpath.relpath(home, posixpath.dirname(old) or ".")
    return f"# {title}\n\nThis page moved to [{home}]({link}).\n"


def plan(
    root: Path,
    pages: PageMap,
    *,
    stubs: Iterable[str] = STUBS,
    placeholders: Mapping[str, tuple[str, str]] = PLACEHOLDERS,
    keep: Iterable[str] = KEEP_AS_WRITTEN,
    write_stubs: bool = True,
) -> Plan:
    """Everything a run would do to the tree at `root`, without doing any of it."""
    try:
        now = set(cdl.listed(root))
    except cdl.ListingError as exc:
        raise TreeError(str(exc)) from exc
    result = Plan()
    for old, new in sorted(pages.moves.items()):
        old_here, new_here = old in now, new in now
        old_stub = old_here and is_stub(_read(root, old) or "")
        if old_here and not new_here and not old_stub:
            result.moves.append((old, new))
        elif old_here and not new_here:
            result.problems.append(f"{old} is a stub, but {new}, where the page moved, is missing")
        elif old_here and not old_stub:
            result.problems.append(f"{old} and {new} both hold the page: merge one into the other first")
        elif not old_here and not new_here:
            result.notes.append(f"neither {old} nor {new} is in the tree")
    source = {new: old for old, new in result.moves}
    view = View(root, (now - {old for old, _ in result.moves}) | set(source), source)
    if write_stubs:
        for old in stubs:
            home = pages.moves.get(old)
            if home is None:
                result.problems.append(f"{old} has a stub, but the map does not move it")
            elif old not in view.files and home in view.files:
                view.create(old, stub_text(old, home, view))
    for path, (title, lead) in placeholders.items():
        if path not in view.files:
            view.create(path, f"# {title}\n\n{lead}\n")
    if result.problems:
        return result
    after = {old: new for old, new in result.moves}
    keep = set(keep)
    for cur in sorted(now):
        if cur in keep:
            continue
        text = _read(root, cur)
        if text is None:
            continue
        dst = after.get(cur, cur)
        rewriter = Rewriter(pages, view, cur, dst)
        if cur.endswith(".md"):
            out, edits = rewrite_markdown(text, rewriter, is_record(dst))
        else:
            out, edits = rewrite_other(text, rewriter, cur.endswith(".py"))
        if out != text:
            result.writes[dst] = out
            result.edits += edits
    for path, text in view.created.items():
        result.writes[path] = text
        result.created.append(path)
    result.created.sort()
    return result


def apply(root: Path, result: Plan) -> None:
    """Make the moves, then write every file the plan rewrites or creates."""
    git = (root / ".git").exists()
    tracked: set[str] = set()
    if git:
        tracked = set(_git(root, "ls-files", "-z", "--cached").split("\0"))
    for old, new in result.moves:
        (root / new).parent.mkdir(parents=True, exist_ok=True)
        if old in tracked:
            _git(root, "mv", "--", old, new)
        else:
            os.replace(root / old, root / new)
    for path, text in result.writes.items():
        target = root / path
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(text.encode("utf-8"))


def _git(root: Path, *args: str) -> str:
    try:
        out = subprocess.run(["git", "-C", str(root), *args], capture_output=True, check=True)
    except (OSError, subprocess.CalledProcessError) as exc:
        detail = (getattr(exc, "stderr", b"") or b"").decode("utf-8", "replace").strip()
        raise TreeError(f"git {' '.join(args)} failed in {root}: {detail or exc}") from exc
    return out.stdout.decode("utf-8", "surrogateescape")


def report(result: Plan) -> list[str]:
    """The lines a run prints: each move, each page created, each pointer rewritten."""
    created = set(result.created)
    lines = [f"move {old} -> {new}" for old, new in result.moves]
    lines += [f"create {path}" for path in result.created]
    lines += [str(edit) for edit in result.edits if edit.path not in created]
    return lines


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="rewrite_doc_paths",
        description="Move the documentation's pages as the page map says, and every pointer to them.",
    )
    parser.add_argument("--root", type=Path, default=ROOT, help="the checkout to change (default: this one)")
    parser.add_argument("--map", type=Path, help=f"the page map (default: {MAP} in the checkout)")
    parser.add_argument("--check", action="store_true", help="change nothing; exit 1 when there is a change")
    parser.add_argument("--no-stubs", action="store_true", help="leave the stubs out of this run")
    args = parser.parse_args(argv)
    root = args.root.resolve()
    map_path = (args.map or root / MAP).resolve()
    keep = list(KEEP_AS_WRITTEN)
    if map_path.is_relative_to(root):  # a map kept in the tree is never rewritten
        keep.append(map_path.relative_to(root).as_posix())
    try:
        pages = PageMap.from_rows(read_map(map_path))
        # the stubs and placeholders of this repository's map; another map (a test's) names none of them
        result = plan(
            root,
            pages,
            stubs=[old for old in STUBS if old in pages.moves],
            placeholders={path: words for path, words in PLACEHOLDERS.items() if path in pages.named},
            keep=keep,
            write_stubs=not args.no_stubs,
        )
    except (MapError, TreeError) as exc:
        print(f"rewrite_doc_paths: {exc}", file=sys.stderr)
        return 2
    for note in result.notes:
        print(f"rewrite_doc_paths: note: {note}", file=sys.stderr)
    for problem in result.problems:
        print(f"rewrite_doc_paths: {problem}", file=sys.stderr)
    if result.problems:
        print("rewrite_doc_paths: nothing was changed", file=sys.stderr)
        return 1
    lines = report(result)
    for line in lines:
        print(line)
    sys.stdout.flush()
    if args.check:
        if not result.empty():
            print(f"rewrite_doc_paths: {_count(len(lines), 'change')} to make; run it without --check")
            return 1
        print("rewrite_doc_paths: the tree follows the page map")
        return 0
    try:
        apply(root, result)
    except (OSError, TreeError) as exc:
        print(f"rewrite_doc_paths: {exc}", file=sys.stderr)
        return 2
    rewritten = len(result.writes) - len(result.created)
    print(
        f"rewrite_doc_paths: moved {_count(len(result.moves), 'page')}, "
        f"created {_count(len(result.created), 'page')}, "
        f"rewrote {_count(len(result.edits), 'pointer')} in {_count(rewritten, 'file')}"
    )
    return 0


def _count(n: int, noun: str) -> str:
    return f"{n:,} {noun}{'' if n == 1 else 's'}"


if __name__ == "__main__":
    sys.exit(main())
