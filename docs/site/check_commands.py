#!/usr/bin/env python3
"""Do the user pages name only commands and options that a released tvgw has?

The documentation site must never show a reader a command their installed version lacks, so it is
published from `main` only while this passes against the latest release (docs/site/README.md). It
checks out the release's tag into a temporary git worktree, imports that tree's
`tvgw.cli.build_parser()` with nothing but the tree's own `src/` on the path (`python3 -I`), and
reads the command tree argparse holds: each command, each subcommand (a nested parser such as
`tv quiet`, or the choices of a command's first argument such as `adguard diff`), and each option.

Then, on every user page (A13 of docs/project/writing-docs.md: README.md, docs/README.md,
docs/what-it-stops.md and the pages under docs/install/, docs/use/ and docs/tv/), every tvgw command
line is checked against that tree: the command, its subcommand and every option it passes, in fenced
blocks and code spans alike, and `sudo tvgw <command>` in prose. A command line is `tvgw` (or
`.../bin/tvgw`, or `python3 -m tvgw`) at the start of a line or span, after a prompt, `sudo`, `env`
or a variable, or after `|`, `;`, `&&` or `$(`; in a `text` block, which holds output, only after
`sudo` or a `$ ` prompt. A placeholder (`<command>`, `DAY`, `{diff,apply}`) is not checked. An option
written on its own in a code span (`--dry-run`) is an unreleased option when the checkout's own tree
has it and the tag's does not. HTML comments are not read; engineering pages are not checked.

    python3 docs/site/check_commands.py --against v0.2.0 [--root DIR]
        One line per problem, `page:line: what: why`, and exit 1; otherwise one summary line and exit
        0. Exit 2 when the check cannot run: no such tag in the checkout (CI must fetch tags), git
        failed, or the tag's parser would not import.

Standard library and git only.
"""

from __future__ import annotations

import argparse
import json
import re
import shutil
import subprocess
import sys
import tempfile
from dataclasses import dataclass
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]

# A13: the user pages; tests/unit/test_user_pages.py holds the same list
USER_PAGE_FILES = ("README.md", "docs/README.md", "docs/what-it-stops.md")
USER_PAGE_GLOBS = ("docs/install/*.md", "docs/use/*.md", "docs/tv/*.md")

# run in a child `python3 -I` with the tree's src/ as its only addition to the path: the command tree
# argparse builds, as JSON. Each node is {"options": {flag: takes a value}, "subcommands": {name: node}}
DUMP = r"""
import argparse, json, sys
sys.path.insert(0, sys.argv[1])
from tvgw import cli

def node(parser):
    out = {"options": {}, "subcommands": {}}
    positionals = 0
    for action in parser._actions:
        if action.option_strings:
            for flag in action.option_strings:
                out["options"][flag] = action.nargs != 0
            continue
        positionals += 1
        if isinstance(action, argparse._SubParsersAction):
            for name, sub in action.choices.items():
                out["subcommands"][name] = node(sub)
        elif positionals == 1 and action.choices:
            for name in action.choices:
                out["subcommands"][str(name)] = {"options": {}, "subcommands": {}}
    return out

print(json.dumps(node(cli.build_parser()), sort_keys=True))
"""

FENCE = re.compile(r"^[ \t]*(`{3,}|~{3,})(.*)$")
CODE_SPAN = re.compile(r"(`+)(?!`)(.+?)(?<!`)\1(?!`)")
COMMENT = re.compile(r"<!--.*?-->", re.S)
OUTPUT_LANGS = frozenset({"text", "txt", "output", "log"})
# what may stand before the program: a prompt, sudo and its options, env, a variable assignment
_PREFIX = (
    r"(?:(?:sudo(?:\s+-[ugCDhpRrT]\s+\S+|\s+-\S+)*|env|time|nice|exec|command)\s+"
    r"|[A-Za-z_][A-Za-z0-9_]*=\S*\s+)*"
)
_PROGRAM = r"(?:\S*/bin/)?(?:tvgw|python3?(?:\.\d+)?(?:\s+-[A-Za-z]+)*\s+-m\s+tvgw)(?=\s|$|[;&|)`])"
START = re.compile(r"(?:^|(?<=[;&|(`]))\s*(?P<prompt>\$\s+)?(?P<prefix>" + _PREFIX + r")" + _PROGRAM)
PROSE = re.compile(r"(?<![\w/.-])sudo\s+tvgw\s+([a-z][a-z0-9-]*)\b")
# where a command line ends: a pipe, a list, a redirection (not the `>` of a placeholder), a subshell's
# close, a comment
END = re.compile(r"\s#|[|;&`)]|(?<![<\w-])>|\s<\s")
TOKEN = re.compile(r"\"(?:[^\"\\]|\\.)*\"|'[^']*'|\S+")
COMMAND = re.compile(r"^[a-z][a-z0-9-]*$")
OPTION = re.compile(r"^--?[A-Za-z][\w-]*")
LONE_OPTION = re.compile(r"^(--[a-z][a-z0-9-]*)(?:[ =]\S+)?$")


class CannotCheck(Exception):
    """The tag's command tree could not be read."""


@dataclass(frozen=True)
class Line:
    """A command line a page names: where, the words after the program, and whether it is only a
    standalone option (`words` is then that one option)."""

    path: str
    line: int
    words: tuple[str, ...]
    lone_option: bool = False
    prose: bool = False


# ---- the command trees ---------------------------------------------------------------------------------


def command_tree(src: Path) -> dict:
    """The command tree of the tvgw package under `src`, read in a child interpreter."""
    try:
        out = subprocess.run(
            [sys.executable, "-I", "-c", DUMP, str(src)],
            capture_output=True,
            text=True,
            timeout=120,
            cwd=src,
        )
    except (OSError, subprocess.TimeoutExpired) as e:
        raise CannotCheck(f"cannot run {sys.executable}: {e}") from None
    if out.returncode != 0:
        tail = "\n".join(out.stderr.strip().splitlines()[-5:])
        raise CannotCheck(f"tvgw.cli.build_parser() under {src} failed:\n{tail}")
    return json.loads(out.stdout)


def git(root: Path, *args: str) -> str:
    out = subprocess.run(["git", "-C", str(root), *args], capture_output=True, text=True, timeout=120)
    if out.returncode != 0:
        raise CannotCheck(f"git {' '.join(args)}: {out.stderr.strip() or 'failed'}")
    return out.stdout.strip()


def tree_at(root: Path, ref: str) -> dict:
    """The command tree at `ref`, from a temporary worktree that is removed afterwards."""
    if not ref or ref.startswith("-"):
        raise CannotCheck(f"{ref!r} is not a tag")
    try:
        commit = git(root, "rev-parse", "--verify", "--quiet", f"{ref}^{{commit}}")
    except CannotCheck:
        raise CannotCheck(f"{ref}: no such tag or commit in {root} (fetch the tags first)") from None
    tmp = Path(tempfile.mkdtemp(prefix="tvgw-commands-"))
    tree = tmp / "tree"
    try:
        git(root, "worktree", "add", "--detach", "--quiet", str(tree), commit)
        return command_tree(tree / "src")
    finally:
        if tree.exists():
            subprocess.run(
                ["git", "-C", str(root), "worktree", "remove", "--force", str(tree)],
                capture_output=True,
                timeout=120,
            )
        shutil.rmtree(tmp, ignore_errors=True)


def all_options(tree: dict) -> set[str]:
    found = set(tree["options"])
    for sub in tree["subcommands"].values():
        found |= all_options(sub)
    return found


# ---- the pages -----------------------------------------------------------------------------------------


def user_pages(root: Path) -> list[str]:
    pages = {name for name in USER_PAGE_FILES if (root / name).is_file()}
    for pattern in USER_PAGE_GLOBS:
        pages |= {p.relative_to(root).as_posix() for p in root.glob(pattern) if p.is_file()}
    return sorted(pages)


def _blank_comments(text: str) -> str:
    """HTML comments replaced by their line breaks, so line numbers stay true."""
    return COMMENT.sub(lambda m: "\n" * m.group(0).count("\n"), text)


def _command_lines(text: str, path: str, line: int, output: bool) -> list[Line]:
    found = []
    for m in START.finditer(text):
        if output and not (m.group("prompt") or "sudo" in m.group("prefix")):
            continue
        rest = text[m.end() :]
        end = END.search(rest)
        words = tuple(TOKEN.findall(rest[: end.start()] if end else rest))
        found.append(Line(path, line, words))
    return found


def lines_of(text: str, path: str) -> list[Line]:
    """Every command line, and every option written alone in a code span, on one page."""
    found: list[Line] = []
    fence, lang, pending, pending_at = "", "", "", 0
    for n, raw in enumerate(_blank_comments(text).splitlines(), 1):
        m = FENCE.match(raw)
        if not fence and m:
            fence, lang = m.group(1), (m.group(2).split() or [""])[0].lower()
            continue
        if fence:
            if m and m.group(1)[0] == fence[0] and len(m.group(1)) >= len(fence) and not m.group(2).strip():
                fence = pending = ""
                continue
            if not pending:
                pending_at = n
            if raw.rstrip().endswith("\\"):
                pending += raw.rstrip()[:-1] + " "
                continue
            found += _command_lines(pending + raw, path, pending_at, lang in OUTPUT_LANGS)
            pending = ""
            continue
        prose = raw
        for span in CODE_SPAN.finditer(raw):
            body = span.group(2).strip()
            lone = LONE_OPTION.match(body)
            if lone:
                found.append(Line(path, n, (lone.group(1),), lone_option=True))
            else:
                found += _command_lines(body, path, n, output=False)
            prose = prose.replace(span.group(0), " ")
        found += [Line(path, n, (m.group(1),), prose=True) for m in PROSE.finditer(prose)]
    return found


# ---- the check -----------------------------------------------------------------------------------------


def _placeholder(word: str) -> bool:
    return bool(re.search(r"[<>{}$]|\.\.\.|…", word)) or bool(re.fullmatch(r"[A-Z][A-Z0-9_-]*", word))


def _clean(word: str) -> str:
    """A word as the parser would see it: quotes, synopsis brackets and a sentence's last mark off."""
    word = word.strip("\"'")
    word = word.strip("[]()")
    return word.rstrip(".,:;!?")


def line_problems(entry: Line, tree: dict, head_options: set[str], against: str) -> list[str]:
    where = f"{entry.path}:{entry.line}"
    if entry.lone_option:
        (flag,) = entry.words
        if flag in head_options and flag not in all_options(tree):
            return [f"{where}: {flag}: an option {against} does not have (it is not released yet)"]
        return []
    pairs = [(w, _clean(w)) for w in entry.words]
    raw = [w for w, clean in pairs if clean]
    words = [clean for _, clean in pairs if clean]
    options = dict(tree["options"])
    i = 0
    found = []
    while i < len(words) and OPTION.match(words[i]):  # options before the command: the global ones
        flag = words[i].split("=", 1)[0]
        if flag not in options:
            found.append(f"{where}: tvgw {flag}: no such option in {against}")
        elif options[flag] and "=" not in words[i]:
            i += 1
        i += 1
    if i == len(words) or not COMMAND.match(words[i]) or _placeholder(words[i]) or raw[i].endswith(":"):
        # `tvgw`, `tvgw --version`, `tvgw <command> --help`, a message (`tvgw adguard: ...`), or not a
        # command line at all
        return found
    command = words[i]
    if command not in tree["subcommands"]:
        return [*found, f"{where}: tvgw {command}: no such command in {against}"]
    if entry.prose:
        return found
    node, path = tree["subcommands"][command], [command]
    options.update(node["options"])
    chose = not node["subcommands"]
    i += 1
    while i < len(words):
        word = words[i]
        if OPTION.match(word):
            flag = word.split("=", 1)[0]
            if flag not in options:
                found.append(f"{where}: tvgw {' '.join(path)} {flag}: no such option in {against}")
            elif options[flag] and "=" not in word and i + 1 < len(words) and not OPTION.match(words[i + 1]):
                i += 1
        elif not chose:
            chose = True
            if _placeholder(word):
                pass
            elif word in node["subcommands"]:
                node = node["subcommands"][word]
                path.append(word)
                options.update(node["options"])
                chose = not node["subcommands"]
            else:
                found.append(f"{where}: tvgw {' '.join(path)} {word}: no such subcommand in {against}")
        i += 1
    return found


def check(root: Path, against: str, tree: dict, head: dict) -> tuple[list[str], int, int]:
    """(problems, pages read, command lines and options checked)."""
    head_options = all_options(head)
    pages = user_pages(root)
    problems, checked = [], 0
    for page in pages:
        for entry in lines_of((root / page).read_text(encoding="utf-8"), page):
            checked += 1
            problems += line_problems(entry, tree, head_options, against)
    return problems, len(pages), checked


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--against", required=True, metavar="TAG", help="the release whose commands to allow")
    ap.add_argument("--root", type=Path, default=ROOT, help="the checkout (default: this script's)")
    args = ap.parse_args(argv)
    root = args.root.resolve()
    try:
        tree = tree_at(root, args.against)
        head = command_tree(root / "src")
    except CannotCheck as e:
        print(f"check_commands: {e}", file=sys.stderr)
        return 2
    problems, pages, checked = check(root, args.against, tree, head)
    for line in problems:
        print(line)
    print(
        f"check_commands: {pages} user pages, {checked} command lines and options, "
        f"{len(problems)} not in {args.against}",
        file=sys.stderr,
    )
    return 1 if problems else 0


if __name__ == "__main__":
    raise SystemExit(main())
