#!/usr/bin/env python3
"""A deferred deploy waits here, on the gateway, for its quiet window.

CI's hardware job defers a deploy that `tvgw tv quiet` does not let through (design decision 63 and
its note of 2026-11-05; docs: deploy/README.md, "The quiet window"). GitHub's schedule starts too few
runs, too late, to bring a deploy into a two-hour window, and the gateway's own clock is reliable, so
the run that deferred stays on the gateway's runner and waits there.

    python3 -I tools/wait_deploy_window.py --wait VOUCHED
        Wait for the window, at most 22 hours 15 minutes (LIMIT), with the deploy VOUCHED vouches
        for: the commit whose tests passed. When the wait ends, print one line, then append
        `deploy=WORD` to the file $GITHUB_OUTPUT names, and exit 0:
          `deploy: now`, WORD `now`: a half hour answered `deploy: now`, and the checkout is main's
            head, which is VOUCHED or ahead of it only by paths `ci.yml` ignores;
          `deploy: deferred`, WORD `deferred`: the limit came first;
          the hand-over line, WORD `handed-over`: main's head differs from VOUCHED in a path
            `ci.yml` does not ignore, so a newer push has a CI run of its own, or it does not descend
            from VOUCHED; that push's run takes the wait. The two commits are compared, not the pushes
            between them: a change and its revert between two reads of main count as no change.
        Exit 1 with an `::error::` line when `tvgw tv quiet` exits without its one line, when
        VOUCHED is not a commit of the checkout, or when the checkout cannot be made main's head.

    python3 -I tools/wait_deploy_window.py --vouches VOUCHED
        Exit 0 when the checkout's HEAD is VOUCHED or ahead of it only by paths `ci.yml` ignores, else
        1 with the reason on standard error. Nothing but git's read commands.

A VOUCHED that is not a whole commit id, 40 or 64 hexadecimal digits, is a usage error (exit 2) and
never reaches git: the job reads it from a file.

The wait asks `tvgw tv quiet` on the local half hours only (:00 and :30), the same times every day,
never between them, and prints no answer but its last line: the job's log is public, and a job whose
timing followed the TV would publish when the household watches it. What the log still shows is which
half hour let the deploy through, and so that the ones before it in this wait did not, as the
30-minute retry showed before (design decision 63 accepts that). An ask that would run more than
5 minutes after its half hour, because the clock jumped, is left out. Every 5 minutes the wait reads
main's head from the remote, without credentials (the repository is public); a read that fails
changes nothing.

Standard library only: the hardware job runs it with the gateway's system Python, as the runner's
user. The one command it runs as root is the checkout's own `tvgw tv quiet` (ASK).
"""

from __future__ import annotations

import argparse
import contextlib
import math
import os
import re
import signal
import subprocess
import sys
import time
from collections.abc import Callable
from datetime import datetime
from pathlib import Path

NOW, DEFERRED = "deploy: now", "deploy: deferred"  # tvgw tv quiet's two lines (src/tvgw/quiet.py)
HANDED_OVER = "main moved on: the newer push's run takes the wait"
# the checkout's own tvgw, as root, the way the job's window step asks: -B writes no bytecode into the
# runner's workspace, -P keeps the working directory off the path and -s the user's site
ROOT_PYTHON = ("sudo", "env", "PYTHONPATH=src", "python3", "-B", "-P", "-s")
ASK = (*ROOT_PYTHON, "-m", "tvgw", "tv", "quiet", "--wait", "0")
ASK_EVERY = 30 * 60  # seconds: the local half hours
LATE = 5 * 60  # seconds after a half hour an ask may still run: a read of main can be in its way that long
POLL_EVERY = 5 * 60  # seconds between reads of main's head
LIMIT = (22 * 60 + 15) * 60  # seconds: with the deploy after it, the job ends inside 24 hours
GIT_TIMEOUT = 120  # seconds for one git command: a read of main that hangs must not cost a half hour
# ci.yml's `paths-ignore`: a push that changes only these has no CI run. The standard library reads no
# YAML, so the list is written here, and tests/unit/test_wait_deploy_window.py holds it to the workflow's
PATHS_IGNORE = ("**/*.md", "docs/**", "mkdocs.yml")
MAIN = "refs/heads/main"
TRACKING = "refs/remotes/origin/main"
COMMIT = re.compile(r"[0-9a-f]{40}|[0-9a-f]{64}")  # a SHA-1 or a SHA-256 commit id, whole
GIT_FAILED = (subprocess.CalledProcessError, subprocess.TimeoutExpired, OSError)
Git = Callable[..., str]


class Stop(Exception):
    """The wait cannot go on. Its message is the step's `::error::` line; `detail` is what the command
    that failed wrote to standard error."""

    def __init__(self, message: str, detail: str = "") -> None:
        super().__init__(message)
        self.detail = detail


def git_in(repo: Path, timeout: float = GIT_TIMEOUT) -> Git:
    """git's stdout in `repo`. A failing command raises CalledProcessError. One still running after
    `timeout` seconds is killed with the helpers it started (its own process group: a transport
    helper left holding the pipes would block the read of them) and raises TimeoutExpired. git never
    asks for a name or a password: there is nobody to answer."""
    env = {**os.environ, "GIT_TERMINAL_PROMPT": "0"}

    def run(*args: str) -> str:
        cmd = ["git", "-C", str(repo), *args]
        proc = subprocess.Popen(
            cmd,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            encoding="utf-8",
            errors="replace",
            env=env,
            start_new_session=True,
        )
        try:
            out, err = proc.communicate(timeout=timeout)
        except subprocess.TimeoutExpired:
            with contextlib.suppress(OSError):
                os.killpg(proc.pid, signal.SIGKILL)
            proc.communicate()
            raise
        if proc.returncode:
            raise subprocess.CalledProcessError(proc.returncode, cmd, out, err)
        return out

    return run


def ask_in(repo: Path) -> Callable[[], bool]:
    """The ask: `tvgw tv quiet --wait 0` from the checkout, as root. True for `deploy: now`, False for
    `deploy: deferred`, and Stop when its exit status and its line do not agree, as the job's window
    step fails on the same."""

    def ask() -> bool:
        try:
            out = subprocess.run(
                ASK,
                cwd=repo,
                stdin=subprocess.DEVNULL,
                capture_output=True,
                text=True,
                encoding="utf-8",
                errors="replace",
                check=False,
            )
        except OSError as e:
            raise Stop("tvgw tv quiet could not be run", str(e)) from e
        answer = (out.returncode, out.stdout.rstrip("\n"))
        if answer == (0, NOW):
            return True
        if answer == (1, DEFERRED):
            return False
        raise Stop(f"tvgw tv quiet exited {out.returncode} without its one line", out.stderr)

    return ask


def pattern(glob: str) -> re.Pattern[str]:
    """A `paths-ignore` pattern as GitHub reads the forms the workflow uses: `**/` is any folders or
    none, `**` is anything, `*` is anything but a `/`, and every other character is itself. ValueError
    for a character GitHub gives a meaning this does not know."""
    out, i = [], 0
    while i < len(glob):
        if glob.startswith("**/", i):
            out.append("(?:.*/)?")
            i += 3
        elif glob.startswith("**", i):
            out.append(".*")
            i += 2
        elif glob[i] == "*":
            out.append("[^/]*")
            i += 1
        elif glob[i] in "?+[]!{}\\":
            raise ValueError(f"{glob!r}: {glob[i]!r} is a pattern character this does not read")
        else:
            out.append(re.escape(glob[i]))
            i += 1
    return re.compile("".join(out))


IGNORED = tuple(pattern(glob) for glob in PATHS_IGNORE)


def ignored(path: str) -> bool:
    """Whether CI ignores a change of this path: it matches one of `paths-ignore`'s patterns, whole."""
    return any(p.fullmatch(path) for p in IGNORED)


def changed(git: Git, old: str, new: str) -> list[str]:
    """The paths that differ between two commits. --no-renames names a moved file under its old path
    and its new one, so a file moved out of `src/` into `docs/` is still a change of `src/`; -z gives
    every name as it is, unquoted; the `--` keeps a path named like a commit id from being read as one."""
    names = git("diff", "--name-only", "--no-renames", "-z", old, new, "--")
    return [p for p in names.split("\0") if p]


def vouches(git: Git, vouched: str, head: str) -> bool:
    """Whether the tests that passed for `vouched` stand for `head` too: `head` is that commit, or
    descends from it and differs only in paths CI ignores, for which no run exists. A git command that
    fails for another reason than "not an ancestor" raises."""
    if head == vouched:
        return True
    try:
        git("merge-base", "--is-ancestor", vouched, head)
    except subprocess.CalledProcessError as e:
        if e.returncode == 1:
            return False
        raise
    return all(ignored(path) for path in changed(git, vouched, head))


def have(git: Git, rev: str) -> bool:
    """Whether the checkout holds this commit."""
    try:
        git("cat-file", "-e", f"{rev}^{{commit}}")
    except GIT_FAILED:
        return False
    return True


def remote_head(git: Git) -> str | None:
    """main's head as the remote has it now, or None when it cannot be read: no network, no such
    branch, or an answer that is not one line with one commit id."""
    try:
        lines = git("ls-remote", "origin", MAIN).splitlines()
    except GIT_FAILED:
        return None
    if len(lines) != 1:
        return None
    rev, _, ref = lines[0].partition("\t")
    return rev if ref == MAIN and COMMIT.fullmatch(rev) else None


def judge(git: Git, vouched: str, head: str) -> bool | None:
    """How main's head stands to the vouched commit: True when `vouched` vouches for it (the wait goes
    on, and the deploy takes it), False when it does not (its own push's run takes the wait), None when
    it cannot be told now: the fetch failed, or main moved again before it."""
    if head == vouched:
        return True
    if not have(git, head):
        try:
            git("fetch", "--quiet", "--no-tags", "origin", f"+{MAIN}:{TRACKING}")
        except GIT_FAILED:
            return None
        if not have(git, head):
            return None
    try:
        return vouches(git, vouched, head)
    except GIT_FAILED:
        return None


def take(git: Git, head: str) -> None:
    """Make the checkout main's head: the deploy step that follows installs the checkout."""
    try:
        if git("rev-parse", "--verify", "HEAD^{commit}").strip() != head:
            git("checkout", "--quiet", "--detach", head, "--")  # the commit, never a path of that name
    except GIT_FAILED as e:
        said = getattr(e, "stderr", None)  # git's own words; a command killed at its timeout has none
        raise Stop("the checkout cannot be made main's head", said if isinstance(said, str) else "") from e


def half_hour_after(t: float) -> float:
    """The first :00 or :30 of the local wall clock after `t`, whatever the zone's offset. Whole
    seconds, so a clock that reads exactly a half hour gets the next one, never the same one twice."""
    base = math.floor(t)
    local = datetime.fromtimestamp(base)
    return float(base + ASK_EVERY - ((local.minute % 30) * 60 + local.second))


def wait(
    vouched: str,
    *,
    git: Git,
    ask: Callable[[], bool],
    clock: Callable[[], float] = time.time,
    sleep: Callable[[float], None] = time.sleep,
) -> tuple[str, str]:
    """Wait for the window (the module docstring has the rules): (the output word, the line to print).
    Stop when the ask does not answer or the checkout cannot be made main's head."""
    if not have(git, vouched):
        raise Stop("the commit that vouches for the deploy is not in this checkout")
    start = clock()
    give_up = start + LIMIT
    next_ask = half_hour_after(start)
    next_poll = start
    seen = vouched  # the last head of main that was judged, and vouched for
    while True:
        now = clock()
        if now >= give_up:
            return "deferred", DEFERRED
        if now < next_ask:
            next_ask = min(next_ask, half_hour_after(now))  # a clock set back: its half hours as it is now
        else:
            on_time = now - next_ask < LATE  # else the clock jumped, or the wait was stopped: no ask
            next_ask = half_hour_after(now)
            if on_time and ask():
                # main as it is now, read once more: the deploy takes its head, never an older commit
                head = remote_head(git)
                verdict = judge(git, vouched, head) if head else None
                if verdict is False:
                    return "handed-over", HANDED_OVER
                if verdict:
                    take(git, head)
                    return "now", NOW
                # main cannot be read: no deploy at this half hour; the next one asks again
        next_poll = min(next_poll, now + POLL_EVERY)  # a clock set back holds no read of main up
        if now >= next_poll:
            while next_poll <= now:
                next_poll += POLL_EVERY
            head = remote_head(git)
            if head and head != seen:
                verdict = judge(git, vouched, head)
                if verdict is False:
                    return "handed-over", HANDED_OVER
                if verdict:
                    seen = head
        # never asleep longer than a read of main is apart: the clock is read again here, and one set
        # back since `now` was read would otherwise make this one sleep as long as the step back
        sleep(min(POLL_EVERY, max(0.0, min(next_ask, next_poll, give_up) - clock())))


def commit_id(text: str) -> str:
    """argparse's check of VOUCHED. The text may come from a file, so the error never repeats it."""
    if not COMMIT.fullmatch(text):
        raise argparse.ArgumentTypeError("not a commit id (40 or 64 hexadecimal digits, lower case)")
    return text


def main(
    argv: list[str] | None = None,
    repo: Path | None = None,
    *,
    git: Git | None = None,
    ask: Callable[[], bool] | None = None,
    clock: Callable[[], float] = time.time,
    sleep: Callable[[float], None] = time.sleep,
    output: str | None = None,
) -> int:
    p = argparse.ArgumentParser(prog="tools/wait_deploy_window.py", description=__doc__.split("\n\n")[0])
    mode = p.add_mutually_exclusive_group(required=True)
    mode.add_argument("--wait", metavar="VOUCHED", type=commit_id, help="wait for the quiet window")
    mode.add_argument("--vouches", metavar="VOUCHED", type=commit_id, help="does VOUCHED vouch for HEAD?")
    a = p.parse_args(argv)
    repo = repo or Path(__file__).resolve().parents[1]
    git = git or git_in(repo)
    if a.vouches is not None:
        try:
            ok = vouches(git, a.vouches, git("rev-parse", "--verify", "HEAD^{commit}").strip())
            why = "HEAD is not that commit, nor ahead of it only by paths CI ignores"
        except GIT_FAILED:
            ok, why = False, "that commit and HEAD cannot be compared in this checkout"
        if not ok:
            print(f"wait_deploy_window: {why}", file=sys.stderr)
        return 0 if ok else 1
    try:
        word, line = wait(a.wait, git=git, ask=ask or ask_in(repo), clock=clock, sleep=sleep)
    except Stop as stop:
        if stop.detail.strip():
            print(stop.detail.rstrip("\n"), file=sys.stderr)
        print(f"::error::{stop}", file=sys.stderr)
        return 1
    # the line first: with nobody left to read it (the step's scrubber gone in these hours) the write
    # fails here, and the step ends failed with no `deploy=` output written
    print(line, flush=True)
    output = output if output is not None else os.environ.get("GITHUB_OUTPUT")
    if output:
        with open(output, "a", encoding="utf-8") as fh:
            fh.write(f"deploy={word}\n")
    return 0


if __name__ == "__main__":
    sys.exit(main())
