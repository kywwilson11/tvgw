#!/usr/bin/env python3
"""Does every link in the repository's Markdown resolve, and every Markdown path its other files name?

A page that moves must take every pointer to it along: a link on another page, an anchor, a docs path
the code prints on a running gateway or copies into /etc/tvgw/tvgw.conf, a file nfpm copies into the
package. This finds the ones left behind, in the working tree:

- every relative link, image, reference definition and HTML `href`, `src` or `srcset` in each Markdown
  file git lists (tracked, or new and not ignored) names a file or folder git lists, written from the
  linking file's folder; a leading `/` is the repository root, as on GitHub;
- every fragment names a heading of its target as GitHub slugs it (lowercase, punctuation other than
  `-` and `_` removed, each space a hyphen, a repeated heading numbered -1, -2 ...), or an `id` or
  `name` attribute in it; a folder's fragment is its README's;
- every repository Markdown path written in any other file git lists (code, deployed files, workflows,
  issue forms, tests, the Makefile), such as `docs/<page>.md#<anchor>` in a message or nfpm's
  `./docs/<page>.md`, resolves the same way from the repository root; the page map and the script
  that applies it, whose paths are the two ends of each move, are not read;
- a link to a file on this repository's main branch on GitHub is checked as that path.

Fenced code blocks and code spans are examples, not links, and are skipped.

    python3 tools/check_docs_links.py [--root DIR]
        One line per problem, `file:line: target: what is wrong`, and exit 1; otherwise one summary
        line and exit 0. Exit 2 when git cannot list the files of a checkout.

Standard library only, and git's `ls-files` where DIR is a git checkout (any other folder is walked),
so it runs under `python3 -I` before anything is installed.
"""

from __future__ import annotations

import argparse
import html
import os
import posixpath
import re
import subprocess
import sys
from collections.abc import Iterator
from dataclasses import dataclass, field
from pathlib import Path
from urllib.parse import unquote

ROOT = Path(__file__).resolve().parents[1]

# a folder walk (DIR is not a git checkout) leaves out what a checkout's .gitignore would
SKIP_DIRS = frozenset(
    {
        ".git",
        ".claude",
        ".venv",
        "venv",
        "node_modules",
        "mutants",
        "build",
        "dist",
        "backups",
        "__pycache__",
        ".pytest_cache",
        ".ruff_cache",
        ".mutmut-cache",
    }
)

# --- Markdown, as GitHub reads it ---------------------------------------------------------------------
# a fence opens with three or more backticks or tildes at any indent (a list item's block is indented)
FENCE = re.compile(r"^[ \t]*(`{3,}|~{3,})(.*)$")
CODE_SPAN = re.compile(r"(`+)(?!`)(.+?)(?<!`)\1(?!`)")
ATX = re.compile(r"^ {0,3}#{1,6}(?:[ \t]+(.*?))?[ \t]*$")
CLOSING = re.compile(r"(?:^|[ \t]+)#+$")  # `## Title ##`; the `#` of `## C#` is text
ESCAPE = re.compile(r"\\([!-/:-@\[-`{-~])")
IMAGE = re.compile(r"!\[[^\]]*\]\([^)]*\)")
LINKED = re.compile(r"\[([^\]]*)\](?:\([^)]*\)|\[[^\]]*\])")
TAG = re.compile(r"</?[A-Za-z][^>]*>")
# `_x_` and `__x__` around text, not inside a word: `snake_case` keeps its underscore, as GitHub does
UNDERSCORES = re.compile(r"(?<![^\W_])(_{1,3})(?=[^\s_])(.+?)(?<=[^\s_])\1(?![^\W_])")
INLINE = re.compile(r"\]\(\s*(<[^>\n]*>|[^\s()<>]+)")
REF_DEF = re.compile(r"^ {0,3}\[(?!\^)[^\]]+\]:[ \t]*(<[^>\n]*>|\S+)")  # `[^1]:` is a footnote
HTML_ATTR = re.compile(r"""(?<![\w-])(href|src|srcset)\s*=\s*(?:"([^"]*)"|'([^']*)')""", re.I)
ID_ATTR = re.compile(r"""<[A-Za-z][\w-]*\s[^>]*?(?<![\w-])(?:id|name)\s*=\s*["']([^"']+)["']""")
SCHEME = re.compile(r"^(?:[A-Za-z][A-Za-z0-9+.-]*:|//)")

# --- paths named outside Markdown -----------------------------------------------------------------------
# the files whose paths are not pointers: the page map and the script that applies it name the old and
# the new path of every move, so some of them are gone and others are still to come
UNREAD = frozenset({"tools/page-map.csv", "tools/rewrite_doc_paths.py"})
# a Markdown path from the repository root, as code prints it or a config names it (nfpm's `./docs/...`);
# `../docs/x.md` and `/usr/share/doc/tvgw/x.md` are relative to something else and are not read, and
# `x.md.in` or `x.md.bak` is another kind of file, while the full stop that ends a sentence is not
PRINTED = re.compile(
    r"(?<![\w/.-])(?:\./)?((?:docs|deploy|src|tests|packaging|tools|\.github)/[A-Za-z0-9_./-]*\.md)"
    r"(?![A-Za-z0-9_-]|\.[A-Za-z0-9_])(#[A-Za-z0-9_-]+)?"
)
# this repository's own files on GitHub; only the main branch is checked, since a tag or a commit pins a
# tree in which a file may rightly be somewhere else
SELF_URL = re.compile(
    r"https://(?:github\.com/kywwilson11/tvgw/(?:blob|tree|raw)/main"
    r"|raw\.githubusercontent\.com/kywwilson11/tvgw/(?:refs/heads/)?main)(/[^\s\"'<>()\[\]`]*)"
)


class ListingError(Exception):
    """git could not list the files of a checkout."""


@dataclass(frozen=True)
class Problem:
    """One pointer that leads nowhere: the file and line that hold it, what it says, and why."""

    path: str
    line: int
    target: str
    reason: str

    def __str__(self) -> str:
        return f"{self.path}:{self.line}: {self.target}: {self.reason}"


def listed(root: Path) -> list[str]:
    """The files of the tree, relative and with `/`: in a git checkout what `git ls-files` lists,
    tracked or new and not ignored (a page counts before it is added); elsewhere a walk of the folder."""
    if (root / ".git").exists():  # a worktree's .git is a file
        try:
            out = subprocess.run(
                ["git", "-C", str(root), "ls-files", "-z", "--cached", "--others", "--exclude-standard"],
                capture_output=True,
                check=True,
            ).stdout
        except (OSError, subprocess.CalledProcessError) as exc:
            detail = getattr(exc, "stderr", b"") or b""
            raise ListingError(
                f"git ls-files failed in {root}: {detail.decode('utf-8', 'replace').strip() or exc}"
            ) from exc
        names = out.decode("utf-8", "surrogateescape").split("\0")
    else:
        names = []
        for folder, dirs, files in os.walk(root):
            dirs[:] = sorted(d for d in dirs if d not in SKIP_DIRS)
            rel = Path(folder).relative_to(root).as_posix()
            names.extend(f if rel == "." else f"{rel}/{f}" for f in files)
    # a tracked file deleted from the working tree is still listed by git until the deletion is staged
    return sorted({n for n in names if n and (root / n).is_file()})


def prose_lines(text: str) -> Iterator[tuple[int, str]]:
    """The lines of a Markdown text outside fenced code blocks, numbered from 1. A fence closes with a
    line of its own character at least as long, with nothing after it; an unclosed fence runs to the
    end. A backtick line whose info string holds a backtick is a code span, not a fence."""
    fence: tuple[str, int] | None = None
    for number, line in enumerate(text.splitlines(), 1):
        m = FENCE.match(line)
        if fence:
            if m and m.group(1)[0] == fence[0] and len(m.group(1)) >= fence[1] and not m.group(2).strip():
                fence = None
            continue
        if m and not (m.group(1)[0] == "`" and "`" in m.group(2)):
            fence = (m.group(1)[0], len(m.group(1)))
            continue
        yield number, line


def _text(markdown: str) -> str:
    """Inline Markdown outside code spans as text: a link keeps its label, an image and an HTML tag
    drop out, underscore emphasis goes, a backslash escape and an entity become the character. (An
    asterisk is punctuation, which the slug drops anyway.)"""
    held: list[str] = []

    def hold(m: re.Match) -> str:
        held.append(m.group(1))
        return f"\0{len(held) - 1}\0"

    text = TAG.sub("", LINKED.sub(r"\1", IMAGE.sub("", ESCAPE.sub(hold, markdown))))
    while (inner := UNDERSCORES.sub(r"\2", text)) != text:  # `__a _b_ c__` takes two passes
        text = inner
    return re.sub(r"\0(\d+)\0", lambda m: held[int(m.group(1))], html.unescape(text))


def heading_text(raw: str) -> str:
    """A heading's text as GitHub renders it. A code span keeps its content as written, and the rest is
    read with each code span held in place, so a code span inside a link's label or inside emphasis
    stays part of it."""
    spans: list[str] = []

    def hold(m: re.Match) -> str:
        code = m.group(2)
        if len(code) > 2 and code[0] == code[-1] == " " and code.strip():
            code = code[1:-1]
        spans.append(code)
        return f"\x01{len(spans) - 1}\x01"

    text = _text(CODE_SPAN.sub(hold, raw))
    return re.sub(r"\x01(\d+)\x01", lambda m: spans[int(m.group(1))], text)


def slug(text: str) -> str:
    """GitHub's anchor for a heading's text: lowercase, every character but a letter, digit, `_`, `-`
    or space removed, each space a hyphen."""
    return re.sub(r"[^\w\- ]", "", text.strip().lower()).replace(" ", "-")


def anchors(text: str) -> set[str]:
    """Every fragment a Markdown text answers to: its headings' slugs, a repeat numbered as GitHub
    numbers it (`a`, `a-1`, ..., and a heading that slugs to a taken `a-1` becomes `a-1-1`), and every
    `id` or `name` attribute outside code."""
    found: set[str] = set()
    taken: dict[str, int] = {}
    for _, line in prose_lines(text):
        m = ATX.match(line)
        if m:
            base = slug(heading_text(CLOSING.sub("", m.group(1) or "")))
            if base:
                anchor = base
                while anchor in taken:
                    taken[base] += 1
                    anchor = f"{base}-{taken[base]}"
                taken[anchor] = 0
                found.add(anchor)
        found.update(ID_ATTR.findall(CODE_SPAN.sub(" ", line)))
    return found


def link_targets(text: str) -> Iterator[tuple[int, str]]:
    """Every link destination of a Markdown text outside code, with its line: inline links and images,
    reference definitions, and the `href`, `src` and `srcset` of HTML such as a `<picture>`."""
    for number, raw in prose_lines(text):
        line = CODE_SPAN.sub(" ", raw)
        for m in INLINE.finditer(line):
            yield number, m.group(1)
        m = REF_DEF.match(line)
        if m:
            yield number, m.group(1)
        for m in HTML_ATTR.finditer(line):
            value = m.group(2) if m.group(2) is not None else m.group(3)
            if m.group(1).lower() == "srcset":
                yield from ((number, part.split()[0]) for part in value.split(",") if part.strip())
            else:
                yield number, value


@dataclass
class Tree:
    """The files of a checkout, read once."""

    root: Path
    files: frozenset[str]
    dirs: frozenset[str] = field(init=False)
    _anchors: dict[str, set[str]] = field(default_factory=dict, init=False, repr=False)

    def __post_init__(self) -> None:
        self.dirs = frozenset({""} | {folder for f in self.files for folder in _parents(f)})

    @classmethod
    def load(cls, root: Path) -> Tree:
        """The tree as `listed` sees it."""
        return cls(root, frozenset(listed(root)))

    @property
    def markdown(self) -> list[str]:
        return sorted(f for f in self.files if f.endswith(".md"))

    @property
    def others(self) -> list[str]:
        """The files that are not Markdown and may name a docs path: all of them but UNREAD."""
        return sorted(f for f in self.files if not f.endswith(".md") and f not in UNREAD)

    def read(self, rel: str) -> str | None:
        """A file as UTF-8 text, or None for a binary file."""
        data = (self.root / rel).read_bytes()
        if b"\0" in data[:8192]:
            return None
        try:
            return data.decode("utf-8")
        except UnicodeDecodeError:
            return None

    def anchors(self, rel: str) -> set[str]:
        """The fragments a Markdown file answers to, read once."""
        if rel not in self._anchors:
            self._anchors[rel] = anchors(self.read(rel) or "")
        return self._anchors[rel]


def _parents(rel: str) -> Iterator[str]:
    """The folders that hold a file, innermost first, the root left out."""
    while (rel := posixpath.dirname(rel)) != "":
        yield rel


def _unwrap(target: str) -> str:
    """A destination without the angle brackets CommonMark allows around it."""
    dest = target.strip()
    return dest[1:-1].strip() if dest.startswith("<") and dest.endswith(">") else dest


def external(target: str) -> bool:
    """Whether a link goes to another site or a mail address, which is not ours to check."""
    dest = _unwrap(target)
    return bool(SCHEME.match(dest)) and not SELF_URL.match(dest)


def resolve(tree: Tree, source: str, target: str) -> str | None:
    """Why a link written in `source` leads nowhere, or None when it resolves or is external."""
    if external(target):
        return None
    dest = _unwrap(target)
    own = SELF_URL.match(dest)
    if own:
        dest = own.group(1)
    dest, _, frag = dest.partition("#")
    dest, _, query = dest.partition("?")
    dest, frag = unquote(dest), unquote(frag)
    if not dest:
        rel = source
    else:
        start = "" if dest.startswith("/") else posixpath.dirname(source)
        rel = posixpath.normpath(posixpath.join(start, dest.lstrip("/")))
        if rel == ".":
            rel = ""
        if rel == ".." or rel.startswith("../"):
            return "leaves the repository"
    if rel not in tree.files and rel not in tree.dirs:
        if not (tree.root / rel).exists():
            return "no such file"
        if _case_differs(tree.root, rel):  # this filesystem ignores case (macOS); GitHub's does not
            return "no such file: one exists whose name differs in case"
        return "exists here, but git ignores it"
    if not frag or "plain=1" in query:  # `?plain=1#L12` is a line of the source view
        return None
    page = rel
    if rel in tree.dirs:
        page = posixpath.join(rel, "README.md") if rel else "README.md"
        if page not in tree.files:
            return f"no README.md in {rel or 'the root'} to hold #{frag}"
    if not page.endswith(".md"):
        return None  # a fragment of another kind of file (`#L12`, `#gh-dark-mode-only`) is not a heading
    if frag not in tree.anchors(page):
        return f"no heading #{frag} in {page}"
    return None


def _case_differs(root: Path, rel: str) -> bool:
    """Whether an existing `rel` is spelled in another case than the names on disk."""
    here = root
    for part in rel.split("/"):
        try:
            names = os.listdir(here)
        except OSError:
            return False
        if part not in names:
            return True
        here = here / part
    return False


def check_markdown(tree: Tree, rel: str) -> tuple[list[Problem], int]:
    """The links of one Markdown file that lead nowhere, and how many it holds that are not external."""
    problems, count = [], 0
    for number, target in link_targets(tree.read(rel) or ""):
        if external(target):
            continue
        count += 1
        reason = resolve(tree, rel, target)
        if reason:
            problems.append(Problem(rel, number, target, reason))
    return problems, count


def printed_paths(text: str) -> Iterator[tuple[int, str]]:
    """The repository Markdown paths a file that is not Markdown names, with their line, as written
    (with `./` and the anchor), and the links to this repository's main branch it holds."""
    for number, line in enumerate(text.splitlines(), 1):
        for m in PRINTED.finditer(line):
            yield number, m.group(0)
        for m in SELF_URL.finditer(line):
            yield number, m.group(0).rstrip(".,;:")


def check_printed(tree: Tree, rel: str) -> tuple[list[Problem], int]:
    """The paths one file that is not Markdown names that lead nowhere, and how many it names. Each is
    read from the repository root, whatever folder the file is in."""
    text = tree.read(rel)
    if text is None:
        return [], 0
    problems, count = [], 0
    for number, written in printed_paths(text):
        count += 1
        target = written if SELF_URL.match(written) else "/" + written.removeprefix("./")
        reason = resolve(tree, "README.md", target)
        if reason:
            problems.append(Problem(rel, number, written, reason))
    return problems, count


@dataclass
class Report:
    """What a check of the whole tree found, and how much it read."""

    problems: list[Problem]
    pages: int
    links: int
    printed: int


def check(root: Path) -> Report:
    """Every Markdown file's links and every other file's named paths, in path order."""
    tree = Tree.load(root)
    problems: list[Problem] = []
    links = printed = 0
    for rel in tree.markdown:
        found, count = check_markdown(tree, rel)
        problems += found
        links += count
    for rel in tree.others:
        found, count = check_printed(tree, rel)
        problems += found
        printed += count
    return Report(problems, len(tree.markdown), links, printed)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="check_docs_links",
        description="Check every Markdown link and anchor, and every Markdown path other files name.",
    )
    parser.add_argument("--root", type=Path, default=ROOT, help="the checkout to read (default: this one)")
    args = parser.parse_args(argv)
    try:
        report = check(args.root.resolve())
    except ListingError as exc:
        print(f"check_docs_links: {exc}", file=sys.stderr)
        return 2
    for problem in report.problems:
        print(problem)
    sys.stdout.flush()  # the problems, then the count, in that order in a CI log
    if report.problems:
        n = len(report.problems)
        print(
            f"check_docs_links: {_count(n, 'pointer')} {'leads' if n == 1 else 'lead'} nowhere",
            file=sys.stderr,
        )
        return 1
    print(
        f"check_docs_links: {_count(report.pages, 'Markdown file')} with {_count(report.links, 'link')}, "
        f"and {_count(report.printed, 'path')} named in other files: all resolve"
    )
    return 0


def _count(n: int, noun: str) -> str:
    """`1 link`, `1,521 links`."""
    return f"{n:,} {noun}{'' if n == 1 else 's'}"


if __name__ == "__main__":
    sys.exit(main())
