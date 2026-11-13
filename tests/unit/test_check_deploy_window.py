"""tools/check_deploy_window.py (design decision 63): which commits change how the live gateway
treats the TV, and whether each says so with `Deploy-window: tv-off`. Each test builds a throwaway
git repository under tmp_path with a stand-in of the repository's layout; git's own configuration
is kept out, so no hook, signing key or template of the machine's applies."""

import importlib.util
import shutil
import subprocess
import sys

import pytest
from conftest import ROOT

TOOL = ROOT / "tools" / "check_deploy_window.py"
spec = importlib.util.spec_from_file_location("check_deploy_window", TOOL)
cdw = importlib.util.module_from_spec(spec)
spec.loader.exec_module(cdw)

TRAILER = "\n\nDeploy-window: tv-off\n"
PROFILE = """[profile]
name = "x"

[categories]
ADS = ["ads.example"]

[url_filter]
hosts = ["files.example"]
block_regex = 'biz_code=(ACR)'
"""
INSTALL = """#!/bin/bash
set -euo pipefail
echo "lock"

tv_lan() { # tv-lan made or moved
\tlocal want=$1
\techo "$want"
}

render_dnsmasq() { # the pin line only once the TV is known
\tsed "s/X/$1/" dnsmasq/tvgw.conf.template
}

analyst_schedule() {
\techo "03:50"
}
"""


@pytest.fixture()
def repo(tmp_path, monkeypatch):
    for key, value in {
        "GIT_CONFIG_GLOBAL": "/dev/null",
        "GIT_CONFIG_NOSYSTEM": "1",
        "GIT_AUTHOR_NAME": "test",
        "GIT_AUTHOR_EMAIL": "test@example.com",
        "GIT_COMMITTER_NAME": "test",
        "GIT_COMMITTER_EMAIL": "test@example.com",
    }.items():
        monkeypatch.setenv(key, value)
    r = Repo(tmp_path / "repo")
    r.git("init", "-q", "-b", "main")
    r.write("deploy/install.sh", INSTALL)
    r.write("deploy/nftables/tvgw-apply", "nft add table inet tvgw\n")
    r.write("deploy/nftables/README.md", "# The firewall\n")
    r.write("src/tvgw/profiles/lg.toml", PROFILE)
    r.write("src/tvgw/cli.py", "print('cli')\n")
    r.commit("base")
    r.git("update-ref", "refs/remotes/origin/main", "HEAD")
    r.git("checkout", "-q", "-b", "work")
    return r


class Repo:
    def __init__(self, path):
        self.path = path
        path.mkdir()
        self.run = cdw.git_in(path)

    def git(self, *args):
        return self.run(*args)

    def write(self, rel, text):
        target = self.path / rel
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(text, encoding="utf-8")

    def edit(self, rel, old, new):
        text = (self.path / rel).read_text(encoding="utf-8")
        assert old in text
        self.write(rel, text.replace(old, new, 1))

    def commit(self, message):
        self.git("add", "-A")
        self.git("-c", "commit.gpgsign=false", "commit", "-q", "--no-verify", "-m", message)
        return self.git("rev-parse", "HEAD").strip()

    def gate(self, base="origin/main"):
        return cdw.gate(self.run, base)


def test_a_firewall_commit_without_the_trailer_fails_the_gate_and_with_it_passes(repo):
    repo.edit("deploy/nftables/tvgw-apply", "tvgw", "tvgw\nnft add rule inet tvgw x")
    bare = repo.commit("tvgw-apply: a rule")
    problems, note = repo.gate()
    assert note is None
    assert problems == [f"{bare[:12]} tvgw-apply: a rule: changes deploy/nftables/tvgw-apply"]
    repo.git("commit", "-q", "--amend", "--no-verify", "-m", "tvgw-apply: a rule" + TRAILER)
    assert repo.gate() == ([], None)


def test_each_commit_answers_for_itself(repo):
    """A trailer on one commit does not cover another's firewall change."""
    repo.write("src/tvgw/tvapi/samsung.py", "x = 1\n")
    repo.commit("tvapi: samsung")
    repo.write("deploy/nginx/tvgw-gfts.conf", "server {}\n")
    repo.commit("nginx: the filter" + TRAILER)
    problems, _ = repo.gate()
    assert len(problems) == 1 and "src/tvgw/tvapi/samsung.py" in problems[0]


@pytest.mark.parametrize(
    "path",
    ["deploy/networkmanager/90-tvgw-dispatcher", "deploy/dnsmasq/tvgw.conf.template", "deploy/nginx/x.conf"],
)
def test_every_folder_that_reaches_the_tv_needs_it(repo, path):
    repo.write(path, "changed\n")
    repo.commit("change")
    assert len(repo.gate()[0]) == 1


def test_documentation_and_other_code_need_nothing(repo):
    repo.write("deploy/nftables/README.md", "# The firewall, rule by rule\n")
    repo.write("src/tvgw/cli.py", "print('cli, changed')\n")
    repo.write("docs/README.md", "words\n")
    repo.commit("docs and the cli")
    assert repo.gate() == ([], None)


def test_a_profile_needs_it_only_for_its_firewall_or_url_filter_table(repo):
    repo.edit("src/tvgw/profiles/lg.toml", '"ads.example"', '"ads.example", "more-ads.example"')
    repo.commit("profile: a category")
    repo.write("src/tvgw/profiles/new.toml", '[profile]\nname = "new"\n')
    repo.commit("profile: a new one without the tables")
    assert repo.gate() == ([], None)
    repo.edit("src/tvgw/profiles/lg.toml", "(ACR)", "(ACR|CDP)")
    repo.commit("profile: the URL filter")
    repo.write("src/tvgw/profiles/new.toml", '[profile]\nname = "new"\n[firewall]\nports = [4001]\n')
    repo.commit("profile: a firewall table")
    repo.write("src/tvgw/profiles/lg.toml", "not = [valid")
    repo.commit("profile: broken")
    problems, _ = repo.gate()
    subjects = [p.split(" ", 1)[1].split(": changes ")[0] for p in problems]
    assert subjects == ["profile: the URL filter", "profile: a firewall table", "profile: broken"]
    assert all("[firewall] or [url_filter]" in p for p in problems)


def test_install_sh_needs_it_for_its_routing_and_dnsmasq_parts_only(repo):
    repo.edit("deploy/install.sh", '\techo "03:50"', '\techo "04:10"')
    repo.commit("install.sh: the analyst's time")
    assert repo.gate() == ([], None)
    repo.edit("deploy/install.sh", '\techo "$want"', '\techo "moving to $want"')
    repo.commit("install.sh: say where tv-lan goes")  # inside tv_lan(): git names it as the context
    repo.edit("deploy/install.sh", 'echo "lock"', 'echo "lock"\nsystemctl restart dnsmasq')
    repo.commit("install.sh: restart dnsmasq")
    problems, _ = repo.gate()
    assert len(problems) == 2 and all("deploy/install.sh (routing or dnsmasq)" in p for p in problems)


def test_merge_commits_are_skipped_and_their_branches_judged(repo):
    repo.git("checkout", "-q", "-b", "side")
    repo.write("deploy/dnsmasq/x", "x\n")
    repo.commit("dnsmasq: x" + TRAILER)
    repo.git("checkout", "-q", "work")
    repo.write("src/tvgw/cli.py", "print(2)\n")
    repo.commit("cli")
    repo.git("-c", "commit.gpgsign=false", "merge", "-q", "--no-ff", "--no-edit", "side")
    assert repo.gate() == ([], None)


def test_with_nothing_to_compare_it_checks_nothing(repo):
    problems, note = repo.gate("origin/nowhere")
    assert problems == [] and "nothing checked" in note


def test_the_deploy_reading_of_a_push(repo):
    before = repo.git("rev-parse", "HEAD").strip()
    repo.write("src/tvgw/cli.py", "print(3)\n")
    repo.commit("cli")
    assert cdw.deploy(repo.run, before)[0] == "plain"
    repo.write("docs/README.md", "y\n")
    repo.commit("docs" + TRAILER)  # a trailer anywhere in the push: the push waits for the window
    assert cdw.deploy(repo.run, before) == ("tv-off", "a commit carries Deploy-window: tv-off")
    later = repo.git("rev-parse", "HEAD").strip()
    repo.edit("deploy/nftables/tvgw-apply", "tvgw", "tvgw2")
    repo.commit("tvgw-apply without the trailer")  # the safety net: the path alone
    word, why = cdw.deploy(repo.run, later)
    assert word == "tv-off" and "deploy/nftables/tvgw-apply" in why
    assert cdw.deploy(repo.run, "0" * 40)[0] == "tv-off"  # no previous commit
    assert cdw.deploy(repo.run, "1234567" * 5 + "12345")[0] == "tv-off"  # not here: cannot read the range
    assert cdw.deploy(repo.run, "")[0] == "tv-off"


def test_a_file_moved_out_of_a_folder_that_waits_still_waits(repo):
    """`git diff` detects renames by default and names only the new path; a firewall file moved
    elsewhere is still a change of the firewall, in the gate and in the deploy reading."""
    before = repo.git("rev-parse", "HEAD").strip()
    (repo.path / "src" / "tvgw" / "templates").mkdir(parents=True)
    repo.git("mv", "deploy/nftables/tvgw-apply", "src/tvgw/templates/tvgw-apply")
    moved = repo.commit("tvgw-apply: becomes a template")
    assert repo.git("diff", "--name-only", before, "HEAD").split() == ["src/tvgw/templates/tvgw-apply"]
    word, why = cdw.deploy(repo.run, before)
    assert word == "tv-off" and "deploy/nftables/tvgw-apply" in why
    problems, _ = repo.gate()
    assert problems == [f"{moved[:12]} tvgw-apply: becomes a template: changes deploy/nftables/tvgw-apply"]


def test_main_prints_one_word_for_the_deploy_and_names_the_commits_for_the_gate(repo, capsys):
    before = repo.git("rev-parse", "HEAD").strip()
    assert cdw.main(["--deploy", before], repo=repo.path) == 0
    out = capsys.readouterr()
    assert out.out == "plain\n" and out.err.startswith("check_deploy_window: ")
    repo.write("deploy/nftables/x", "x\n")
    repo.commit("firewall")
    assert cdw.main([], repo=repo.path) == 1
    out = capsys.readouterr().out
    assert "firewall: changes deploy/nftables/x" in out and "Deploy-window: tv-off" in out
    assert cdw.main(["--base", "origin/nowhere"], repo=repo.path) == 0


def test_it_runs_under_an_isolated_interpreter_from_its_own_checkout(repo):
    """It runs as `python3 -I tools/check_deploy_window.py` from a checkout: the standard library only, and the repository is the one the script sits in."""
    (repo.path / "tools").mkdir()
    shutil.copy(TOOL, repo.path / "tools" / "check_deploy_window.py")
    before = repo.git("rev-parse", "HEAD").strip()
    repo.write("deploy/nftables/x", "x\n")
    repo.commit("firewall" + TRAILER)
    out = subprocess.run(
        [sys.executable, "-I", "tools/check_deploy_window.py", "--deploy", before],
        cwd=repo.path,
        capture_output=True,
        text=True,
        timeout=60,
    )
    assert out.returncode == 0 and out.stdout == "tv-off\n", out.stderr


def test_the_paths_are_the_ones_the_design_names():
    assert cdw.PREFIXES == (
        "deploy/nftables/",
        "deploy/networkmanager/",
        "deploy/dnsmasq/",
        "deploy/nginx/",
        "src/tvgw/tvapi/",
    )
    assert cdw.PROFILE_TABLES == ("firewall", "url_filter")
    for folder in cdw.PREFIXES[:4]:
        assert (ROOT / folder).is_dir(), folder  # a renamed folder must not leave the check blind
    assert (ROOT / cdw.INSTALL_SH).is_file()
    install = (ROOT / cdw.INSTALL_SH).read_text(encoding="utf-8")
    for needle in ("tv_lan()", "render_dnsmasq()", "restart_dnsmasq()", "stand_aside()", "nmcli"):
        assert needle in install and cdw.INSTALL_PARTS.search(needle), needle
