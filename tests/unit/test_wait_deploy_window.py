"""tools/wait_deploy_window.py (design decision 63, its note of 2026-11-05): a deferred deploy waits on
the gateway for the quiet window. The clock is a fake that only `sleep` moves, `tvgw tv quiet` is a
stand-in that records when it was asked, and git is real: `origin` is a throwaway repository whose
commits on main are the pushes, and `work` is a clone of it, the runner's checkout. git's own
configuration is kept out, and the zone is conftest's America/Chicago."""

import os
import shutil
import subprocess
import sys
import time
from datetime import datetime

import pytest
import yaml
from conftest import ROOT, load_tool

wdw = load_tool("wait_deploy_window")
TOOL = ROOT / "tools" / "wait_deploy_window.py"
WINDOW = (3 * 60 + 30, 5 * 60 + 30)  # 03:30-05:30, DEPLOY_WINDOW's default


def at(hh: int, mm: int, ss: int = 0, day: int = 3) -> float:
    return datetime(2026, 11, day, hh, mm, ss).timestamp()


def hhmm(t: float) -> str:
    return datetime.fromtimestamp(t).strftime("%d %H:%M:%S")


class Repo:
    def __init__(self, path):
        self.path = path
        self.git = wdw.git_in(path)

    def write(self, rel, text):
        target = self.path / rel
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(text, encoding="utf-8")

    def commit(self, message, **files):
        for rel, text in files.items():
            self.write(rel, text)
        self.git("add", "-A")
        self.git("-c", "commit.gpgsign=false", "commit", "-q", "--no-verify", "--allow-empty", "-m", message)
        return self.head()

    def head(self):
        return self.git("rev-parse", "HEAD").strip()


class Clock:
    """A wall clock that only `sleep` moves. What happens meanwhile (a push, the network going down) is
    set for a time and happens as the clock passes it."""

    def __init__(self, start: float):
        self.now = float(start)
        self.slept: list[float] = []
        self.events: list[tuple[float, object]] = []

    def __call__(self) -> float:
        return self.now

    def at(self, when: float, what) -> None:
        self.events.append((when, what))

    def sleep(self, seconds: float) -> None:
        assert 0 <= seconds <= wdw.POLL_EVERY, seconds  # never asleep past a read of main
        self.slept.append(seconds)
        assert len(self.slept) < 5000, "the wait does not end"
        self.now += seconds
        due = sorted((e for e in self.events if e[0] <= self.now), key=lambda e: e[0])
        self.events = [e for e in self.events if e[0] > self.now]
        for _, what in due:
            what()


class Quiet:
    """`tvgw tv quiet` stood in for: `deploy: now` inside the window from `quiet_from` on. Every ask is
    kept with its time."""

    def __init__(self, clock: Clock, quiet_from: float | None = 0.0):
        self.clock, self.quiet_from, self.asked = clock, quiet_from, []

    def __call__(self) -> bool:
        now = self.clock.now
        self.asked.append(now)
        local = datetime.fromtimestamp(now)
        in_window = WINDOW[0] <= local.hour * 60 + local.minute < WINDOW[1]
        return in_window and self.quiet_from is not None and now >= self.quiet_from


class Git:
    """The checkout's git, every call kept with its time. `down` fails what needs the network, or the
    one command it names; `remote` answers `ls-remote` from memory, for a wait too long to ask the real
    one each time."""

    def __init__(self, run, clock: Clock):
        self.run, self.clock, self.calls = run, clock, []
        self.down: bool | str = False
        self.remote: str | None = None

    def __call__(self, *args: str) -> str:
        self.calls.append((self.clock.now, args))
        if args[0] in ("ls-remote", "fetch"):
            if self.down in (True, args[0]):
                raise subprocess.CalledProcessError(128, ["git", *args], "", "fatal: unable to access")
            if args[0] == "ls-remote" and self.remote:
                return f"{self.remote}\t{wdw.MAIN}\n"
        return self.run(*args)

    def times(self, command: str) -> list[float]:
        return [t for t, args in self.calls if args[0] == command]

    def set_down(self, down: bool | str):
        return lambda: setattr(self, "down", down)


class Gateway:
    """The runner's checkout (`work`, detached at main's head as actions/checkout leaves it), its
    remote (`origin`), and one run of the tool's `--wait`."""

    def __init__(self, tmp_path):
        self.tmp = tmp_path
        self.origin = Repo(tmp_path / "origin")
        self.origin.path.mkdir()
        self.origin.git("init", "-q", "-b", "main")
        self.vouched = self.origin.commit(
            "base",
            **{"src/tvgw/cli.py": "print('cli')\n", "README.md": "# tvgw\n", "docs/README.md": "docs\n"},
        )
        wdw.git_in(tmp_path)("clone", "-q", str(self.origin.path), "work")
        self.work = Repo(tmp_path / "work")
        self.work.git("checkout", "-q", "--detach")
        self.output = tmp_path / "github_output"

    def push(self, message, **files):
        """A commit on origin's main: a push, as the remote has it."""
        return lambda: self.origin.commit(message, **files)

    def wait(self, start: float, quiet_from: float | None = 0.0, vouched: str | None = None, **where):
        self.clock = getattr(self, "clock", None) or Clock(start)
        self.quiet = Quiet(self.clock, quiet_from)
        self.git = getattr(self, "git", None) or Git(self.work.git, self.clock)
        return wdw.main(
            ["--wait", vouched or self.vouched],
            repo=self.work.path,
            git=self.git,
            ask=self.quiet,
            clock=self.clock,
            sleep=self.clock.sleep,
            **{"output": str(self.output), **where},
        )

    def prepared(self, start: float):
        """The clock and git of the wait to come, to set events on."""
        self.clock = Clock(start)
        self.git = Git(self.work.git, self.clock)
        return self.clock, self.git

    def outputs(self) -> str:
        return self.output.read_text(encoding="utf-8") if self.output.exists() else ""


@pytest.fixture()
def gw(tmp_path, monkeypatch):
    for key, value in {
        "GIT_CONFIG_GLOBAL": "/dev/null",
        "GIT_CONFIG_NOSYSTEM": "1",
        "GIT_AUTHOR_NAME": "test",
        "GIT_AUTHOR_EMAIL": "test@example.com",
        "GIT_COMMITTER_NAME": "test",
        "GIT_COMMITTER_EMAIL": "test@example.com",
    }.items():
        monkeypatch.setenv(key, value)
    return Gateway(tmp_path)


def on_a_half_hour(t: float) -> bool:
    local = datetime.fromtimestamp(t)
    return local.minute in (0, 30) and local.second == 0 and t == int(t)


# ---- the asks: the local half hours, and nothing printed but the last line ----------------------------


def test_it_asks_on_the_local_half_hours_only_and_deploys_at_the_first_that_answers_now(gw, capsys):
    clock, git = gw.prepared(at(14, 7, 13))
    git.remote = gw.vouched  # main does not move in these 13 hours
    assert gw.wait(at(14, 7, 13)) == 0
    out = capsys.readouterr()
    assert out.out == "deploy: now\n" and out.err == ""  # no verdict but the last line
    assert gw.outputs() == "deploy=now\n"
    asked = gw.quiet.asked
    assert all(on_a_half_hour(t) for t in asked)
    # every half hour from the first after the start to the window's first, none twice, none skipped
    assert asked == [at(14, 30) + 1800 * n for n in range(27)] and asked[-1] == at(3, 30, day=4)
    assert clock.now == at(3, 30, day=4)
    assert gw.work.head() == gw.vouched  # main did not move: the checkout is left as it is


def test_a_tv_in_use_at_one_half_hour_moves_the_deploy_to_the_next(gw, capsys):
    assert gw.wait(at(3, 7, 13), quiet_from=at(4, 10)) == 0
    assert capsys.readouterr().out == "deploy: now\n"
    assert gw.quiet.asked == [at(3, 30), at(4, 0), at(4, 30)] and gw.clock.now == at(4, 30)


def test_a_wait_that_starts_on_a_half_hour_asks_at_the_next_one(gw):
    """The window step asked a moment ago; the same half hour is not asked twice."""
    assert gw.wait(at(3, 30)) == 0
    assert gw.quiet.asked == [at(4, 0)]


def test_the_output_goes_to_the_file_the_runner_names_and_nowhere_without_one(gw, capsys, monkeypatch):
    monkeypatch.setenv("GITHUB_OUTPUT", str(gw.output))
    gw.output.write_text("vouched=x\n", encoding="utf-8")
    assert gw.wait(at(3, 20), output=None) == 0
    assert gw.outputs() == "vouched=x\ndeploy=now\n"  # appended, as every step writes its outputs
    monkeypatch.delenv("GITHUB_OUTPUT")
    del gw.clock, gw.git
    assert gw.wait(at(3, 20), output=None) == 0  # by hand: the line alone
    assert gw.outputs() == "vouched=x\ndeploy=now\n" and capsys.readouterr().out == "deploy: now\n" * 2


def test_with_nobody_to_read_its_last_line_the_wait_writes_no_output(gw, monkeypatch):
    """The step pipes the tool into the scrubber, which has to live as long as the wait. With the
    scrubber gone the line cannot be written: the tool fails before it writes `deploy=now`, so the job
    neither deploys behind a failed step nor takes the marker away."""

    class Gone:
        def write(self, text):
            raise BrokenPipeError(32, "Broken pipe")

        def flush(self):
            pass

    monkeypatch.setattr(sys, "stdout", Gone())
    with pytest.raises(BrokenPipeError):
        gw.wait(at(3, 20))
    assert gw.outputs() == "" and gw.quiet.asked == [at(3, 30)]


def test_it_gives_up_after_22_hours_15_minutes_and_says_deferred(gw, capsys):
    clock, git = gw.prepared(at(5, 20))
    git.remote = gw.vouched
    assert gw.wait(at(5, 20), quiet_from=None) == 0  # the TV is never quiet
    assert capsys.readouterr().out == "deploy: deferred\n"
    assert gw.outputs() == "deploy=deferred\n"
    assert clock.now - at(5, 20) == wdw.LIMIT == (22 * 60 + 15) * 60
    asked = gw.quiet.asked
    assert all(on_a_half_hour(t) for t in asked)
    assert asked[0] == at(5, 30) and asked[-1] == at(3, 30, day=4)  # it reached the window's first half hour


def test_a_wait_that_starts_in_the_quarter_hour_after_the_windows_last_half_hour_reaches_no_other(gw):
    """05:00 is the default window's last half hour and 03:30 its next, 22 hours 30 minutes on: more
    than LIMIT, which the 24 hours of the job's token and the deploy's 90 minutes hold under that.
    Such a wait gives up before 03:30 and the schedule takes it up."""
    clock, git = gw.prepared(at(5, 0, 1))
    git.remote = gw.vouched
    assert gw.wait(at(5, 0, 1)) == 0  # quiet whenever it is asked inside the window
    assert gw.outputs() == "deploy=deferred\n"
    assert gw.quiet.asked[-1] == at(3, 0, day=4) and clock.now == at(3, 15, 1, day=4)


@pytest.mark.parametrize("zone", ["Asia/Kathmandu", "UTC", "Australia/Lord_Howe"])
def test_the_half_hours_are_the_local_clocks_whatever_the_zones_offset(monkeypatch, zone):
    """Kathmandu is 5 hours 45 minutes from UTC: its half hours are not UTC's."""
    monkeypatch.setenv("TZ", zone)
    time.tzset()
    t = 1793878033.25
    for _ in range(4):
        nxt = wdw.half_hour_after(t)
        assert t < nxt <= t + 1800 and on_a_half_hour(nxt)
        assert wdw.half_hour_after(nxt) == nxt + 1800  # exactly on one: the next, never the same again
        t = nxt + 0.5


def test_a_clock_set_back_or_forward_keeps_the_asks_on_its_half_hours(gw):
    clock, git = gw.prepared(at(22, 7, 13))
    git.remote = gw.vouched

    def set_clock(seconds):
        return lambda: setattr(clock, "now", clock.now + seconds)

    clock.at(at(23, 10), set_clock(-3600))  # back an hour: 22:10 again, and no hour of silence
    clock.at(at(0, 40, day=4), set_clock(47 * 60))  # forward 47 minutes, past 01:00: it is not asked late
    assert gw.wait(at(22, 7, 13)) == 0
    asked = [hhmm(t) for t in gw.quiet.asked]
    assert all(on_a_half_hour(t) for t in gw.quiet.asked)
    assert asked[:6] == [
        "03 22:30:00",
        "03 23:00:00",
        "03 22:30:00",
        "03 23:00:00",
        "03 23:30:00",
        "04 00:00:00",
    ]
    assert asked[6:] == [
        "04 00:30:00",
        "04 01:30:00",
        "04 02:00:00",
        "04 02:30:00",
        "04 03:00:00",
        "04 03:30:00",
    ]


# ---- main's head: read every 5 minutes; docs ride along, a push with its own run takes the wait --------


def test_it_reads_main_every_five_minutes_from_the_start(gw):
    start = at(2, 52, 13)
    assert gw.wait(start) == 0
    reads = gw.git.times("ls-remote")
    assert reads[:8] == [start + 300 * n for n in range(8)]  # 02:52:13 ... 03:27:13
    assert reads[8:] == [at(3, 30)]  # and once more at the half hour that answered now
    assert gw.git.times("fetch") == [] and gw.git.times("checkout") == []


def test_a_docs_only_push_rides_along_and_the_deploy_takes_mains_head(gw, capsys):
    clock, _ = gw.prepared(at(3, 2))
    clock.at(
        at(3, 8),
        gw.push("docs", **{"docs/README.md": "more\n", "CHANGELOG.md": "x\n", "mkdocs.yml": "a: 1\n"}),
    )
    clock.at(
        at(3, 19), gw.push("more docs", **{"docs/site/prebuild.py": "print()\n", "deploy/README.md": "y\n"})
    )
    assert gw.wait(at(3, 2)) == 0
    assert capsys.readouterr().out == "deploy: now\n" and gw.outputs() == "deploy=now\n"
    assert clock.now == at(3, 30)
    assert gw.work.head() == gw.origin.head() != gw.vouched  # the checkout is main's head
    assert (gw.work.path / "deploy" / "README.md").read_text(encoding="utf-8") == "y\n"
    assert gw.work.git("status", "--porcelain") == ""


def test_a_push_with_a_run_of_its_own_takes_the_wait_within_five_minutes(gw, capsys):
    clock, _ = gw.prepared(at(14, 7, 13))
    clock.at(at(14, 9), gw.push("cli", **{"src/tvgw/cli.py": "print('new')\n"}))
    assert gw.wait(at(14, 7, 13)) == 0
    out = capsys.readouterr()
    assert out.out == "main moved on: the newer push's run takes the wait\n" and out.err == ""
    assert gw.outputs() == "deploy=handed-over\n"
    assert 0 < clock.now - at(14, 9) <= wdw.POLL_EVERY
    assert gw.quiet.asked == [] and gw.work.head() == gw.vouched  # nothing asked, nothing checked out


@pytest.mark.parametrize(
    "pushes",
    [
        [{"docs/README.md": "more\n"}, {"docs/README.md": "more\n", "pyproject.toml": "[project]\n"}],
        [{"docs/README.md": "more\n", "tests/unit/test_x.py": "x = 1\n"}],
        [{"mkdocs.yaml": "a: 1\n"}],  # not mkdocs.yml
        [{"sub/mkdocs.yml": "a: 1\n"}],  # the pattern names the root's
        [{"README.md.in": "x\n"}],
    ],
)
def test_any_path_ci_does_not_ignore_since_the_vouched_commit_hands_over(gw, pushes):
    clock, _ = gw.prepared(at(3, 2))
    for n, files in enumerate(pushes):
        clock.at(at(3, 4 + 6 * n), gw.push(f"push {n}", **files))
    assert gw.wait(at(3, 2)) == 0
    assert gw.outputs() == "deploy=handed-over\n" and clock.now < at(3, 30)


def test_a_file_moved_out_of_the_code_into_docs_hands_over(gw):
    """`git diff` would name only docs/cli.py, the new path; the push changed src/ all the same."""
    clock, _ = gw.prepared(at(3, 2))

    def move():
        gw.origin.git("mv", "src/tvgw/cli.py", "docs/cli.py")
        gw.origin.commit("cli: becomes a page")

    clock.at(at(3, 4), move)
    assert gw.wait(at(3, 2)) == 0
    assert gw.outputs() == "deploy=handed-over\n"
    assert gw.work.git("diff", "--name-only", gw.vouched, gw.origin.head()).split() == ["docs/cli.py"]


def test_a_head_that_does_not_descend_from_the_vouched_commit_hands_over(gw):
    """main set back and continued with docs alone: nothing vouches for a head the tested commit is
    not in."""
    base = gw.vouched
    vouched = gw.origin.commit("cli", **{"src/tvgw/cli.py": "print('tested')\n"})
    gw.work.git("fetch", "-q", "origin")
    gw.work.git("checkout", "-q", "--detach", vouched)
    clock, _ = gw.prepared(at(3, 2))

    def rewrite():
        gw.origin.git("reset", "-q", "--hard", base)
        gw.origin.commit("docs", **{"docs/README.md": "other\n"})

    clock.at(at(3, 4), rewrite)
    assert gw.wait(at(3, 2), vouched=vouched) == 0
    assert gw.outputs() == "deploy=handed-over\n" and gw.work.head() == vouched


def test_a_head_beside_the_vouched_commit_hands_over_though_only_docs_differ(gw):
    """Two docs commits on one parent: the trees differ in docs/ alone, and still the head is not the
    vouched commit's descendant, so main was rewritten and the wait is another run's."""
    base = gw.vouched
    vouched = gw.origin.commit("docs", **{"docs/README.md": "one\n"})
    gw.work.git("fetch", "-q", "origin")
    gw.work.git("checkout", "-q", "--detach", vouched)
    gw.origin.git("reset", "-q", "--hard", base)
    gw.origin.commit("other docs", **{"docs/README.md": "two\n"})
    assert gw.wait(at(3, 2), vouched=vouched) == 0
    assert gw.outputs() == "deploy=handed-over\n"
    assert wdw.main(["--vouches", vouched], repo=gw.work.path) == 0
    gw.work.git("checkout", "-q", "--detach", gw.origin.head())
    assert wdw.main(["--vouches", vouched], repo=gw.work.path) == 1


def test_a_fetch_that_fails_changes_nothing_either(gw):
    """main's new head can be read and not fetched: the wait neither hands over nor deploys what it
    cannot judge, and judges it once the fetch works."""
    clock, git = gw.prepared(at(3, 2))
    git.down = "fetch"
    clock.at(at(3, 4), gw.push("docs", **{"docs/README.md": "more\n"}))
    clock.at(at(3, 41), git.set_down(False))
    assert gw.wait(at(3, 2)) == 0
    assert gw.outputs() == "deploy=now\n" and clock.now == at(4, 0)
    assert gw.quiet.asked == [at(3, 30), at(4, 0)]  # quiet at 03:30, and main's head not judged yet
    assert len(git.times("fetch")) > 5 and gw.work.head() == gw.origin.head()


def test_a_read_of_main_that_fails_changes_nothing(gw, capsys):
    """The network is down from 03:03 to 03:21, and a docs push lands meanwhile: the wait goes on, reads
    again every 5 minutes, and the deploy takes the head it could read in the end."""
    clock, git = gw.prepared(at(3, 2))
    clock.at(at(3, 3), git.set_down(True))
    clock.at(at(3, 10), gw.push("docs", **{"docs/README.md": "more\n"}))
    clock.at(at(3, 21), git.set_down(False))
    assert gw.wait(at(3, 2)) == 0
    out = capsys.readouterr()
    assert out.out == "deploy: now\n" and out.err == ""
    assert git.times("ls-remote")[:6] == [at(3, 2) + 300 * n for n in range(6)]
    assert gw.work.head() == gw.origin.head() != gw.vouched


def test_an_answer_that_is_not_one_commit_id_is_a_read_that_failed(gw):
    for answer in (
        "",
        "not-a-commit\trefs/heads/main\n",
        f"{'a' * 40}\trefs/heads/other\n",
        f"{'A' * 40}\t{wdw.MAIN}\n",
    ):
        assert wdw.remote_head(lambda *args, answer=answer: answer) is None
    two = f"{'a' * 40}\t{wdw.MAIN}\n{'b' * 40}\t{wdw.MAIN}\n"
    assert wdw.remote_head(lambda *args: two) is None
    assert wdw.remote_head(lambda *args: f"{'a' * 64}\t{wdw.MAIN}\n") == "a" * 64
    assert wdw.remote_head(gw.work.git) == gw.vouched


# ---- the half hour that answers now: main is read once more ---------------------------------------------


def test_with_main_unreadable_at_a_quiet_half_hour_the_deploy_waits_for_the_next(gw, capsys):
    clock, git = gw.prepared(at(3, 2))
    clock.at(at(3, 28), git.set_down(True))
    clock.at(at(3, 41), git.set_down(False))
    assert gw.wait(at(3, 2)) == 0
    assert capsys.readouterr().out == "deploy: now\n"
    assert gw.quiet.asked == [at(3, 30), at(4, 0)] and clock.now == at(4, 0)


def test_a_push_just_before_a_quiet_half_hour_is_seen_before_anything_deploys(gw):
    """The last read of main was at 03:27; the push lands at 03:29. The half hour reads main again."""
    clock, _ = gw.prepared(at(3, 2))
    clock.at(at(3, 29), gw.push("cli", **{"src/tvgw/cli.py": "print('new')\n"}))
    assert gw.wait(at(3, 2)) == 0
    assert gw.outputs() == "deploy=handed-over\n"
    assert gw.quiet.asked == [at(3, 30)] and clock.now == at(3, 30) and gw.work.head() == gw.vouched


def test_a_docs_push_just_before_a_quiet_half_hour_is_what_deploys(gw):
    clock, _ = gw.prepared(at(3, 2))
    clock.at(at(3, 29), gw.push("docs", **{"docs/README.md": "late\n"}))
    assert gw.wait(at(3, 2)) == 0
    assert gw.outputs() == "deploy=now\n" and clock.now == at(3, 30)
    assert gw.work.head() == gw.origin.head() != gw.vouched


def test_a_scheduled_run_waits_with_the_markers_commit_and_a_checkout_ahead_of_it_by_docs(gw):
    """The schedule's checkout is main's head, and the marker's commit vouches for it."""
    vouched = gw.vouched
    gw.origin.commit("docs", **{"docs/README.md": "more\n"})
    gw.work.git("fetch", "-q", "origin")
    gw.work.git("checkout", "-q", "--detach", gw.origin.head())
    assert gw.wait(at(3, 2), vouched=vouched) == 0
    assert gw.outputs() == "deploy=now\n" and gw.work.head() == gw.origin.head()


def test_a_checkout_that_cannot_be_made_mains_head_fails_the_step(gw, capsys):
    """A file in the way of the docs push's checkout: git refuses, and nothing deploys an older tree."""
    clock, _ = gw.prepared(at(3, 2))
    clock.at(at(3, 8), gw.push("docs", **{"docs/new.txt": "new\n"}))
    gw.work.write("docs/new.txt", "in the way\n")
    assert gw.wait(at(3, 2)) == 1
    out = capsys.readouterr()
    assert out.out == "" and gw.outputs() == ""
    assert out.err.rstrip().endswith("::error::the checkout cannot be made main's head")


def test_a_vouched_commit_the_checkout_does_not_hold_fails_at_once(gw, capsys):
    assert gw.wait(at(3, 2), vouched="1234567" * 5 + "12345") == 1
    assert (
        "::error::the commit that vouches for the deploy is not in this checkout" in capsys.readouterr().err
    )
    assert gw.clock.slept == [] and gw.quiet.asked == []


# ---- the ask itself: the checkout's tvgw tv quiet, as root, held to its one line ------------------------

FAKE_SUDO = """#!/bin/sh
[ "$*" = "env PYTHONPATH=src python3 -B -P -s -m tvgw tv quiet --wait 0" ] || { echo "unexpected: sudo $*" >&2; exit 97; }
[ -z "$QUIET_ERR" ] || echo "$QUIET_ERR" >&2
[ -z "$QUIET_LINE" ] || printf '%s\\n' "$QUIET_LINE"
exit "$QUIET_RC"
"""


@pytest.fixture()
def sudo(tmp_path, monkeypatch):
    """`sudo` stood in for on PATH: it checks the command and answers as $QUIET_RC and $QUIET_LINE say."""
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    (bin_dir / "sudo").write_text(FAKE_SUDO, encoding="utf-8")
    (bin_dir / "sudo").chmod(0o755)
    monkeypatch.setenv("PATH", f"{bin_dir}:{os.environ['PATH']}")

    def answer(rc: int, line: str, err: str = ""):
        monkeypatch.setenv("QUIET_RC", str(rc))
        monkeypatch.setenv("QUIET_LINE", line)
        monkeypatch.setenv("QUIET_ERR", err)

    return answer


def test_the_ask_runs_the_checkouts_quiet_check_as_root_and_reads_its_two_answers(tmp_path, sudo):
    ask = wdw.ask_in(tmp_path)
    sudo(0, "deploy: now")
    assert ask() is True
    sudo(1, "deploy: deferred", err="a warning nobody prints")
    assert ask() is False


@pytest.mark.parametrize(
    "quiet",
    [
        (1, ""),
        (0, "deploy: deferred"),
        (1, "deploy: now"),
        (2, "usage"),
        (1, "Traceback"),
        (0, " deploy: now"),
        (0, "deploy: now "),
        (0, "Deploy: now"),
        (0, "deploy: now\nand more"),
    ],
)
def test_an_ask_whose_status_and_line_do_not_agree_fails_the_step_as_the_window_step_does(
    gw, sudo, capsys, quiet
):
    sudo(*quiet, err="why it failed")
    clock = Clock(at(3, 2))
    rc = wdw.main(
        ["--wait", gw.vouched],
        repo=gw.work.path,
        clock=clock,
        sleep=clock.sleep,
        output=str(gw.output),
    )
    out = capsys.readouterr()
    assert rc == 1 and out.out == "" and gw.outputs() == ""
    assert out.err == f"why it failed\n::error::tvgw tv quiet exited {quiet[0]} without its one line\n"
    assert clock.now == at(3, 30)  # at the first half hour


def test_an_ask_that_cannot_be_run_fails_the_step_too(tmp_path, monkeypatch):
    monkeypatch.setenv("PATH", str(tmp_path))  # no sudo here
    with pytest.raises(wdw.Stop, match="tvgw tv quiet could not be run"):
        wdw.ask_in(tmp_path)()


def test_the_ask_is_the_window_steps_command():
    """Root's Python from the runner's workspace: -B, or its bytecode fails the next checkout's clean
    (test_supply_chain.py holds the workflow's own commands to the same)."""
    assert " ".join(wdw.ASK) == "sudo env PYTHONPATH=src python3 -B -P -s -m tvgw tv quiet --wait 0"
    assert (wdw.NOW, wdw.DEFERRED) == ("deploy: now", "deploy: deferred")
    quiet = (ROOT / "src" / "tvgw" / "quiet.py").read_text(encoding="utf-8")
    assert 'NOW, DEFERRED = "deploy: now", "deploy: deferred"' in quiet


# ---- --vouches, and the paths CI ignores -------------------------------------------------------------------


def test_vouches_says_whether_the_checkout_is_the_commit_or_ahead_of_it_by_ignored_paths(gw, capsys):
    def vouches(commit):
        return wdw.main(["--vouches", commit], repo=gw.work.path)

    base = gw.vouched
    assert vouches(base) == 0  # HEAD is the commit
    docs = gw.origin.commit("docs", **{"docs/README.md": "more\n", "tools/README.md": "t\n"})
    gw.work.git("fetch", "-q", "origin")
    gw.work.git("checkout", "-q", "--detach", docs)
    assert vouches(base) == 0  # ahead by documentation alone
    assert capsys.readouterr().err == ""
    code = gw.origin.commit("cli", **{"src/tvgw/cli.py": "print('new')\n"})
    gw.work.git("fetch", "-q", "origin")
    gw.work.git("checkout", "-q", "--detach", code)
    assert vouches(base) == 1 and vouches(docs) == 1  # a change with a CI run of its own
    assert "HEAD is not that commit, nor ahead of it only by paths CI ignores" in capsys.readouterr().err
    assert vouches(code) == 0
    gw.work.git("checkout", "-q", "--detach", base)
    assert vouches(code) == 1  # HEAD is behind it
    assert vouches("1234567" * 5 + "12345") == 1  # not a commit here
    assert "cannot be compared" in capsys.readouterr().err


@pytest.mark.parametrize(
    "text", ["", "main", "HEAD~1", "a" * 39, "a" * 41, "A" * 40, "a" * 40 + "\n", "--upload-pack=x"]
)
@pytest.mark.parametrize("mode", ["--vouches", "--wait"])
def test_a_vouched_that_is_not_a_whole_commit_id_never_reaches_git(gw, capsys, mode, text):
    def no_git(*args):
        raise AssertionError(f"git {args}")

    with pytest.raises(SystemExit) as stop:
        wdw.main([f"{mode}={text}"], repo=gw.work.path, git=no_git)
    assert stop.value.code == 2
    said = capsys.readouterr().err.rsplit("error:", 1)[1]
    assert "not a commit id" in said
    assert not text.strip() or text.strip() not in said  # a file's text is never repeated in the log


def test_the_ignored_paths_are_the_workflows():
    """The tool cannot read YAML, so it carries ci.yml's `paths-ignore`; a pattern added to one and not
    the other fails here."""
    wf = yaml.safe_load((ROOT / ".github" / "workflows" / "ci.yml").read_text(encoding="utf-8"))
    assert tuple(wf[True]["push"]["paths-ignore"]) == wdw.PATHS_IGNORE  # PyYAML reads `on` as True


@pytest.mark.parametrize(
    ("path", "is_ignored"),
    [
        ("README.md", True),  # **/ is any folders, or none
        ("deploy/nftables/README.md", True),
        (".github/PULL_REQUEST_TEMPLATE.md", True),
        ("docs/design-decisions.md", True),
        ("docs/site/prebuild.py", True),
        ("docs/diagrams/fig-01.light.png", True),
        ("mkdocs.yml", True),
        ("sub/mkdocs.yml", False),
        ("mkdocs.yml.bak", False),
        ("docs", False),  # a file of that name is not under docs/
        ("docs.py", False),
        ("src/docs/x.py", False),
        ("src/tvgw/cli.py", False),
        ("notes.md.txt", False),
        ("notes.MD", False),
        ("md", False),
        (".github/workflows/ci.yml", False),
    ],
)
def test_a_path_is_ignored_as_github_reads_the_workflows_three_patterns(path, is_ignored):
    assert wdw.ignored(path) is is_ignored


def test_a_single_star_stays_inside_one_folder():
    """None of the workflow's three patterns shows it, and the next one added may."""
    assert wdw.pattern("*.md").fullmatch("README.md") and not wdw.pattern("*.md").fullmatch("docs/README.md")
    assert wdw.pattern("docs/*/x").fullmatch("docs/a/x") and not wdw.pattern("docs/*/x").fullmatch(
        "docs/a/b/x"
    )
    assert wdw.pattern("a.b").fullmatch("a.b") and not wdw.pattern("a.b").fullmatch("axb")


@pytest.mark.parametrize("glob", ["docs/[a-z]*", "!docs/**", "*.md?", "src/+"])
def test_a_pattern_form_the_tool_does_not_read_is_refused_not_guessed(glob):
    with pytest.raises(ValueError, match="does not read"):
        wdw.pattern(glob)


# ---- the tool as the job runs it ------------------------------------------------------------------------------


def test_it_runs_under_an_isolated_interpreter_from_its_own_checkout(gw):
    """The hardware job runs it as `python3 -I tools/wait_deploy_window.py`: the standard library only,
    and the repository is the one the script sits in."""
    (gw.work.path / "tools").mkdir()
    shutil.copy(TOOL, gw.work.path / "tools" / "wait_deploy_window.py")

    def run(*args):
        return subprocess.run(
            [sys.executable, "-I", "tools/wait_deploy_window.py", *args],
            cwd=gw.work.path,
            capture_output=True,
            text=True,
            timeout=60,
        )

    out = run("--vouches", gw.vouched)
    assert out.returncode == 0 and out.stdout == "" and out.stderr == ""
    gw.origin.commit("cli", **{"src/tvgw/cli.py": "print('new')\n"})
    gw.work.git("fetch", "-q", "origin")
    gw.work.git("checkout", "-q", "--detach", gw.origin.head())
    out = run("--vouches", gw.vouched)
    assert out.returncode == 1 and out.stdout == "" and out.stderr.startswith("wait_deploy_window: ")
    assert run().returncode == 2 and run("--wait", "main").returncode == 2


def test_the_wait_as_the_job_runs_it_with_the_real_clock_and_a_main_that_already_moved(gw, monkeypatch):
    """The whole script under `python3 -I`, nothing stood in for: main has a newer push with a run of
    its own before the wait begins, so its first read of main, made at once, hands the wait over."""
    (gw.work.path / "tools").mkdir()
    shutil.copy(TOOL, gw.work.path / "tools" / "wait_deploy_window.py")
    gw.origin.commit("cli", **{"src/tvgw/cli.py": "print('new')\n"})
    monkeypatch.setenv("GITHUB_OUTPUT", str(gw.output))
    out = subprocess.run(
        [sys.executable, "-I", "tools/wait_deploy_window.py", "--wait", gw.vouched],
        cwd=gw.work.path,
        capture_output=True,
        text=True,
        timeout=120,
    )
    assert (out.returncode, out.stdout, out.stderr) == (0, wdw.HANDED_OVER + "\n", "")
    assert gw.outputs() == "deploy=handed-over\n" and gw.work.head() == gw.vouched


def test_a_git_command_that_hangs_is_killed_with_what_it_started(tmp_path, monkeypatch):
    """A read of main on a network that stalls: git and the transport helper holding its pipes are
    killed together, or the wait would sit in that read past its half hour."""
    if not shutil.which("sh"):
        pytest.skip("no sh")
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    (bin_dir / "git").write_text("#!/bin/sh\nsleep 60 &\nwait\n", encoding="utf-8")
    (bin_dir / "git").chmod(0o755)
    monkeypatch.setenv("PATH", f"{bin_dir}:{os.environ['PATH']}")
    git = wdw.git_in(tmp_path, timeout=0.5)
    began = time.monotonic()
    with pytest.raises(subprocess.TimeoutExpired):
        git("ls-remote", "origin", wdw.MAIN)
    assert time.monotonic() - began < 20
    assert wdw.remote_head(git) is None  # and to the wait it is a read that failed


def test_the_limits_are_the_designs():
    assert (wdw.ASK_EVERY, wdw.POLL_EVERY, wdw.LIMIT) == (1800, 300, 80100)
    assert wdw.LATE <= wdw.POLL_EVERY < wdw.ASK_EVERY
    # one read of main and one fetch, both stalled, still leave the half hour its ask
    assert 2 * wdw.GIT_TIMEOUT < wdw.LATE
