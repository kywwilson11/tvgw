"""`make deploy` records what it deployed, `make deployed` reads it back and `make window` asks the
deploy-window check about the commits since (design decision 83). The Makefile's own recipes run here,
in a throwaway repository, against stand-ins for `ssh` and `rsync`: nothing leaves the machine."""

import os
import shutil
import subprocess

import pytest
from conftest import ROOT

pytestmark = pytest.mark.skipif(
    not (shutil.which("make") and shutil.which("git")), reason="needs make and git"
)

# ssh's stand-in. The remote command is its last argument: the install ends as INSTALL_EXIT says, and
# the record is one file under GATEWAY, written from stdin and read back
SSH = """#!/bin/sh
for remote; do :; done
case "$remote" in
*sync-install.sh*) exit "${INSTALL_EXIT:-0}" ;;
"cat >"*) cat >"$GATEWAY/deployed" ;;
"cat "*) cat "$GATEWAY/deployed" ;;
esac
"""


class Workstation:
    """A checkout with one commit, a gateway that is a directory, and `make <target> PI=gw` between them."""

    def __init__(self, tmp_path):
        self.gateway = tmp_path / "gateway"
        self.repo = tmp_path / "repo"
        bindir = tmp_path / "bin"
        for directory in (self.gateway, self.repo / "tools", bindir):
            directory.mkdir(parents=True)
        for name, body in (("ssh", SSH), ("rsync", "#!/bin/sh\n")):
            (bindir / name).write_text(body, encoding="utf-8")
            (bindir / name).chmod(0o755)
        shutil.copy(ROOT / "tools" / "check_deploy_window.py", self.repo / "tools")
        self.env = {
            **{k: v for k, v in os.environ.items() if not k.startswith("GIT_")},
            "PATH": f"{bindir}:{os.environ['PATH']}",
            "GATEWAY": str(self.gateway),
            "GIT_CONFIG_GLOBAL": os.devnull,
            "GIT_CONFIG_SYSTEM": os.devnull,
        }
        self.git("init", "-q", "-b", "main")
        self.commit("README.md")

    def git(self, *args):
        ident = ("-c", "user.name=t", "-c", "user.email=t@example.invalid")
        done = subprocess.run(
            ["git", *ident, *args], cwd=self.repo, env=self.env, capture_output=True, text=True, check=True
        )
        return done.stdout.strip()

    def commit(self, path):
        """A commit that changes `path`, and its id."""
        target = self.repo / path
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(
            f"{path} at {len(self.git('log', '--oneline', '--all').splitlines())}\n", encoding="utf-8"
        )
        self.git("add", "-A")
        self.git("commit", "-q", "-m", f"change {path}")
        return self.git("rev-parse", "HEAD")

    def make(self, target, **env):
        return subprocess.run(
            ["make", "-s", "-f", str(ROOT / "Makefile"), target, "PI=gw"],
            cwd=self.repo, env={**self.env, **env}, capture_output=True, text=True, timeout=60,
        )  # fmt: skip

    @property
    def recorded(self):
        record = self.gateway / "deployed"
        return record.read_text(encoding="utf-8").strip() if record.exists() else None


@pytest.fixture
def ws(tmp_path):
    return Workstation(tmp_path)


@pytest.mark.parametrize("uncommitted", [None, "notes.txt"], ids=["clean", "dirty"])
def test_a_deploy_that_ends_well_records_its_commit_and_says_when_the_tree_held_more(ws, uncommitted):
    head = ws.git("rev-parse", "HEAD")
    if uncommitted:
        (ws.repo / uncommitted).write_text("rsync copies this too\n", encoding="utf-8")
    assert ws.make("deploy").returncode == 0
    assert ws.recorded == head + ("-dirty" if uncommitted else "")
    assert ws.make("deployed").stdout.strip() == ws.recorded


def test_a_deploy_whose_install_fails_records_nothing(ws):
    assert ws.make("deploy", INSTALL_EXIT="1").returncode != 0
    assert ws.recorded is None


def test_a_deploy_from_a_tree_that_is_no_repository_records_unknown(ws):
    shutil.rmtree(ws.repo / ".git")
    assert ws.make("deploy").returncode == 0
    assert ws.recorded == "unknown"


@pytest.mark.parametrize(
    ("changed", "answer"),
    [
        (None, "plain"),  # nothing since the deploy
        ("README.md", "plain"),
        ("deploy/nftables/tvgw-apply", "tv-off"),  # a path that changes how the gateway treats the TV
    ],
)
def test_the_window_target_asks_about_the_commits_since_the_last_deploy(ws, changed, answer):
    assert ws.make("deploy").returncode == 0
    if changed:
        ws.commit(changed)
    asked = ws.make("window")
    assert (asked.returncode, asked.stdout.strip()) == (0, answer), asked.stderr


@pytest.mark.parametrize(
    "record", [None, "unknown", "0" * 40], ids=["no record", "unknown", "a commit git lacks"]
)
def test_a_range_the_window_target_cannot_read_must_wait(ws, record):
    """No record, a deploy from outside a repository and a commit this checkout lacks all answer
    `tv-off`: what cannot be read is not called safe."""
    if record:
        (ws.gateway / "deployed").write_text(record + "\n", encoding="utf-8")
    assert ws.make("window").stdout.strip() == "tv-off"
