#!/usr/bin/env python3
"""Which commits change how the live gateway treats the TV, and do they say so?

A commit that touches the firewall, the TV port's network setup, DHCP, the URL filter, a TV's LAN-API
modules, a profile's `[firewall]` or `[url_filter]` table, or the routing and dnsmasq parts of
`deploy/install.sh` must carry the trailer `Deploy-window: tv-off`, and whoever deploys it does so only
in the gateway's quiet window (design decisions 63 and 83, docs: deploy/README.md, "How a change reaches
the gateway").

    python3 tools/check_deploy_window.py [--base REF]
        The gate (`make gate`): exit 1, naming each commit in REF..HEAD (default origin/main, from
        their merge base; merges skipped) that changes such a path without the trailer. With no REF
        to compare with (a shallow checkout) it says so and checks nothing.

    python3 -I tools/check_deploy_window.py --deploy BEFORE
        Before a deploy: print `tv-off` when any commit in BEFORE..HEAD carries the trailer or the
        range changes such a path, else `plain`. A BEFORE that is not a commit here prints `tv-off`.

Standard library only, and nothing outside git's read commands: it runs under a system Python before
anything is installed.
"""

from __future__ import annotations

import argparse
import re
import subprocess
import sys
import tomllib
from collections.abc import Callable, Iterable
from pathlib import Path

TRAILER, VALUE = "Deploy-window", "tv-off"
# whole folders whose every file changes what the TV may reach or how it gets an address
PREFIXES = (
    "deploy/nftables/",
    "deploy/networkmanager/",
    "deploy/dnsmasq/",
    "deploy/nginx/",
    "src/tvgw/tvapi/",
)
PROFILES = re.compile(r"src/tvgw/profiles/[^/]+\.toml")
PROFILE_TABLES = ("firewall", "url_filter")
INSTALL_SH = "deploy/install.sh"
# the routing and dnsmasq parts of install.sh: a changed line, or the line git names as its hunk's
# context (the function a changed line sits in), that names one of these
INSTALL_PARTS = re.compile(
    r"dnsmasq|nmcli|NetworkManager|networkmanager|tv-lan|tv_lan|stand_aside|tv_side|tvgw-net"
    r"|\bip\s+(?:-\S+\s+)*(?:route|rule)\b|tvgw-apply|sysctl|ip_forward"
)
ZERO = re.compile(r"0{40}|0{64}")  # the "before" of a push that created the branch
Git = Callable[..., str]


def git_in(repo: Path) -> Git:
    """git's stdout in `repo`; a failing command raises CalledProcessError."""

    def run(*args: str) -> str:
        return subprocess.run(
            ["git", "-C", str(repo), *args],
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            check=True,
        ).stdout

    return run


def show(git: Git, rev: str, path: str) -> str | None:
    """A file at a revision, or None where it does not exist there."""
    try:
        return git("show", f"{rev}:{path}")
    except subprocess.CalledProcessError:
        return None


def profile_tables(text: str | None) -> dict | None:
    """The tables of a profile that change the gateway's rules (a profile that is not there has none),
    or None for text that is not TOML."""
    try:
        data = tomllib.loads(text) if text is not None else {}
    except tomllib.TOMLDecodeError:
        return None
    return {name: data.get(name) for name in PROFILE_TABLES}


def install_parts(diff: str) -> bool:
    """Whether a `git diff -U0` of install.sh changes a line of its routing or dnsmasq parts."""
    for line in diff.splitlines():
        if line.startswith(("+++", "---")):
            continue
        if line.startswith("@@"):
            text = line.split("@@", 2)[-1]
        elif line.startswith(("+", "-")):
            text = line[1:]
        else:
            continue
        if INSTALL_PARTS.search(text):
            return True
    return False


def reasons(git: Git, old: str | None, new: str, paths: Iterable[str]) -> list[str]:
    """What makes the change from `old` to `new` behavior-changing, one phrase each; [] for none.
    `old` None is a root commit."""
    found: list[str] = []
    for path in sorted(set(paths)):
        if path.endswith(".md"):  # a folder's README is read by people, never installed
            continue
        if path.startswith(PREFIXES):
            found.append(path)
        elif PROFILES.fullmatch(path):
            before = profile_tables(show(git, old, path) if old else None)
            after = profile_tables(show(git, new, path))
            if before is None or after is None or before != after:
                found.append(f"{path} [{'] or ['.join(PROFILE_TABLES)}]")
        elif path == INSTALL_SH:
            if old:
                diff = git("diff", "-U0", old, new, "--", path)
            else:  # a root commit: its patch against nothing
                diff = git("diff-tree", "-p", "-U0", "--root", new, "--", path)
            if install_parts(diff):
                found.append(f"{path} (routing or dnsmasq)")
    return found


def carries_trailer(git: Git, rev: str) -> bool:
    values = git("log", "-1", f"--format=%(trailers:key={TRAILER},valueonly)", rev)
    return any(v.strip().lower() == VALUE for v in values.splitlines())


def commit_reasons(git: Git, rev: str) -> list[str]:
    parents = git("rev-list", "--parents", "-n", "1", rev).split()[1:]
    old = parents[0] if parents else None
    # --no-renames: a file moved out of a folder that waits names both paths, never only the new one
    paths = git("diff-tree", "--no-commit-id", "-r", "--name-only", "--no-renames", "--root", rev).split("\n")
    return reasons(git, old, rev, [p for p in paths if p])


def gate(git: Git, base: str) -> tuple[list[str], str | None]:
    """(problems, note): one problem per commit in base..HEAD that changes a behavior-changing path
    without the trailer; the note says why nothing was checked."""
    try:
        start = git("merge-base", base, "HEAD").strip()
    except subprocess.CalledProcessError:
        return [], f"no {base} to compare with (a shallow or detached checkout): nothing checked"
    problems = []
    for rev in git("rev-list", "--no-merges", "--reverse", f"{start}..HEAD").split():
        why = commit_reasons(git, rev)
        if why and not carries_trailer(git, rev):
            subject = git("log", "-1", "--format=%s", rev).strip()
            problems.append(f"{rev[:12]} {subject}: changes {', '.join(why)}")
    return problems, None


def deploy(git: Git, before: str) -> tuple[str, str]:
    """(`tv-off` or `plain`, why) for the deploy of HEAD after BEFORE."""
    if not before or ZERO.fullmatch(before):
        return VALUE, "no previous commit for this push"
    try:
        git("cat-file", "-e", f"{before}^{{commit}}")
    except subprocess.CalledProcessError:
        return VALUE, "the pushed range cannot be read here"
    revs = git("rev-list", f"{before}..HEAD").split()
    if any(carries_trailer(git, rev) for rev in revs):
        return VALUE, f"a commit carries {TRAILER}: {VALUE}"
    # --no-renames: `git diff` detects renames by default and would name only where a file went, so
    # a file moved out of deploy/nginx/ would read as no change there
    paths = git("diff", "--name-only", "--no-renames", before, "HEAD").split("\n")
    why = reasons(git, before, "HEAD", [p for p in paths if p])
    if why:
        return VALUE, f"changed without the trailer: {', '.join(why)}"
    return "plain", "nothing that needs the window"


def main(argv: list[str] | None = None, repo: Path | None = None) -> int:
    p = argparse.ArgumentParser(prog="tools/check_deploy_window.py", description=__doc__.split("\n\n")[0])
    p.add_argument("--base", default="origin/main", help="the branch to compare with (default origin/main)")
    p.add_argument("--deploy", metavar="BEFORE", help="print tv-off or plain for the deploy of BEFORE..HEAD")
    a = p.parse_args(argv)
    git = git_in(repo or Path(__file__).resolve().parents[1])
    if a.deploy is not None:
        word, why = deploy(git, a.deploy)
        print(f"check_deploy_window: {why}", file=sys.stderr)
        print(word)
        return 0
    problems, note = gate(git, a.base)
    if note:
        print(f"check_deploy_window: {note}")
        return 0
    for line in problems:
        print(f"check_deploy_window: {line}")
    if problems:
        print(
            f"check_deploy_window: whoever deploys one of these cannot know to wait for the quiet window"
            f" unless its message ends with the trailer line '{TRAILER}: {VALUE}'"
        )
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
