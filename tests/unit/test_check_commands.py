"""docs/site/check_commands.py: the documentation site publishes `main` only while every command and
option the user pages name is in the latest release (docs/site/README.md#when-it-publishes).

First the whole check on throwaway git repositories with tagged releases, then how a page is read, on
small texts against a small command tree. The link check (tools/check_docs_links.py) reads this file
too, so a page path a fixture writes is spelled through DOCS in an f-string."""

import importlib.util
import shutil
import subprocess
import sys

import pytest
from conftest import ROOT

spec = importlib.util.spec_from_file_location(
    "site_check_commands", ROOT / "docs" / "site" / "check_commands.py"
)
cc = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = cc  # a dataclass looks its module up by name
spec.loader.exec_module(cc)

DOCS = "docs"
CLI = """import argparse


def build_parser():
    p = argparse.ArgumentParser(prog="tvgw")
    p.add_argument("--conf")
    sub = p.add_subparsers(dest="cmd", required=True)
    v = sub.add_parser("verify")
    v.add_argument("--json", action="store_true")
    g = sub.add_parser("adguard")
    g.add_argument("action", choices=["diff", "apply"])
    g.add_argument("--dry-run", action="store_true")
{more}    return p
"""
DOCTOR = '    d = sub.add_parser("doctor")\n    d.add_argument("--fix", action="store_true")\n'


def git(repo, *args):
    subprocess.run(
        ["git", "-C", str(repo), "-c", "commit.gpgsign=false", "-c", "tag.gpgsign=false", *args],
        check=True,
        capture_output=True,
        env={
            "GIT_AUTHOR_NAME": "t",
            "GIT_AUTHOR_EMAIL": "t@example.org",
            "GIT_COMMITTER_NAME": "t",
            "GIT_COMMITTER_EMAIL": "t@example.org",
            "GIT_CONFIG_GLOBAL": "/dev/null",
            "PATH": "/usr/bin:/bin:/usr/local/bin:/opt/homebrew/bin",
        },
    )


@pytest.fixture
def repo(tmp_path):
    """v1.0 has verify and adguard; v1.1 adds doctor; the working tree is v1.1 with a user page."""
    if not shutil.which("git"):
        pytest.skip("no git")
    root = tmp_path / "repo"
    (root / "src" / "tvgw").mkdir(parents=True)
    (root / DOCS / "use").mkdir(parents=True)
    (root / "src" / "tvgw" / "__init__.py").write_text("", encoding="utf-8")
    (root / "src" / "tvgw" / "cli.py").write_text(CLI.format(more=""), encoding="utf-8")
    (root / "README.md").write_text("# tvgw\n\nRun `sudo tvgw verify`.\n", encoding="utf-8")
    git(root, "init", "-q")
    git(root, "add", "-A")
    git(root, "commit", "-q", "-m", "one")
    git(root, "tag", "v1.0")
    (root / "src" / "tvgw" / "cli.py").write_text(CLI.format(more=DOCTOR), encoding="utf-8")
    git(root, "commit", "-q", "-am", "two")
    git(root, "tag", "v1.1")
    return root


def write_page(repo, text):
    (repo / DOCS / "use" / "fix.md").write_text(text, encoding="utf-8")


def worktrees(repo):
    out = subprocess.run(["git", "-C", str(repo), "worktree", "list"], capture_output=True, text=True)
    return out.stdout.strip().splitlines()


# ---- the whole check, on throwaway repositories --------------------------------------------------------


def test_a_page_naming_a_command_fails_against_a_release_without_it_and_passes_with_it(repo, capsys):
    write_page(repo, "# Fix\n\n```sh\nsudo tvgw doctor --fix\n```\n")
    assert cc.main(["--against", "v1.0", "--root", str(repo)]) == 1
    assert f"{DOCS}/use/fix.md:4: tvgw doctor: no such command in v1.0" in capsys.readouterr().out
    assert cc.main(["--against", "v1.1", "--root", str(repo)]) == 0
    assert len(worktrees(repo)) == 1  # the temporary worktree is gone


def test_an_option_the_release_lacks_fails_and_one_it_has_passes(repo, capsys):
    write_page(repo, "# Fix\n\nRun `sudo tvgw adguard apply --dry-run`, never `tvgw verify --record`.\n")
    assert cc.main(["--against", "v1.0", "--root", str(repo)]) == 1
    out = capsys.readouterr().out
    assert "tvgw verify --record: no such option in v1.0" in out
    assert "--dry-run" not in out


def test_an_option_written_alone_fails_only_when_it_is_not_released_yet(repo, capsys):
    write_page(repo, "# Fix\n\nAdd `--fix` to repair it. Pip takes `--require-hashes`.\n")
    assert cc.main(["--against", "v1.0", "--root", str(repo)]) == 1
    out = capsys.readouterr().out
    assert "--fix: an option v1.0 does not have" in out
    assert "require-hashes" not in out  # no tvgw has it: another program's option
    assert cc.main(["--against", "v1.1", "--root", str(repo)]) == 0


def test_engineering_pages_are_not_checked(repo):
    (repo / DOCS / "reference").mkdir()
    (repo / DOCS / "reference" / "commands.md").write_text("`sudo tvgw doctor`\n", encoding="utf-8")
    assert cc.main(["--against", "v1.0", "--root", str(repo)]) == 0


@pytest.mark.parametrize("ref", ["v9.9", "--upload-pack=x", ""])
def test_a_tag_that_is_not_there_cannot_be_checked(repo, ref, capsys):
    assert cc.main([f"--against={ref}", "--root", str(repo)]) == 2  # a git option is never handed to git
    assert "check_commands:" in capsys.readouterr().err


def test_a_release_whose_parser_does_not_import_cannot_be_checked(repo, capsys):
    (repo / "src" / "tvgw" / "cli.py").write_text("import not_a_module_tvgw_has\n", encoding="utf-8")
    git(repo, "commit", "-q", "-am", "broken")
    git(repo, "tag", "v1.2")
    assert cc.main(["--against", "v1.2", "--root", str(repo)]) == 2
    assert "not_a_module_tvgw_has" in capsys.readouterr().err
    assert len(worktrees(repo)) == 1


def test_the_tag_is_read_with_only_its_own_source_on_the_path(repo, monkeypatch):
    """`python3 -I`: neither PYTHONPATH nor the working directory can put another tvgw in its place."""
    monkeypatch.setenv("PYTHONPATH", str(ROOT / "src"))
    monkeypatch.chdir(ROOT / "src")
    tree = cc.tree_at(repo, "v1.0")
    assert set(tree["subcommands"]) == {"verify", "adguard"}


def test_the_real_parser_is_read_as_a_tree():
    tree = cc.command_tree(ROOT / "src")
    assert {"verify", "setup", "brief", "adguard"} <= set(tree["subcommands"])
    assert {"diff", "apply"} <= set(tree["subcommands"]["adguard"]["subcommands"])  # a choice
    assert tree["subcommands"]["setup"]["options"]["--answers"] is True  # takes a value
    assert tree["subcommands"]["setup"]["options"]["--dry-run"] is False
    assert tree["options"]["--conf"] is True


def test_the_user_pages_are_the_ones_the_plain_words_test_holds():
    import test_user_pages as tup

    assert cc.USER_PAGE_FILES == tup.USER_PAGE_FILES
    assert cc.USER_PAGE_GLOBS == tup.USER_PAGE_GLOBS


# ---- reading a page -----------------------------------------------------------------------------------

LEAF = {"options": {}, "subcommands": {}}
TREE = {
    "options": {"--conf": True, "--version": False, "-h": False, "--help": False},
    "subcommands": {
        "verify": {"options": {"--json": False, "--record": False}, "subcommands": {}},
        "brief": {"options": {"--json": False}, "subcommands": {}},
        "setup": {"options": {"--answers": True, "--yes": False, "--dry-run": False}, "subcommands": {}},
        "adguard": {"options": {"--dry-run": False}, "subcommands": {"diff": LEAF, "apply": LEAF}},
        "autoblock": {"options": {"--days": True}, "subcommands": {"check": LEAF, "list": LEAF}},
        "tv": {
            "options": {},
            "subcommands": {"quiet": {"options": {"--wait": True}, "subcommands": {}}},
        },
    },
}
HEAD_OPTIONS = cc.all_options(TREE) | {"--fix", "--wait-more"}


def problems(text):
    found = []
    for line in cc.lines_of(text, "p.md"):
        found += cc.line_problems(line, TREE, HEAD_OPTIONS, "v1")
    return found


@pytest.mark.parametrize(
    "text",
    [
        "`tvgw verify`",
        "`sudo tvgw verify --record --json`",
        "`tvgw --conf /etc/tvgw/tvgw.conf verify`",
        "`tvgw --version`",
        "`sudo tvgw adguard apply --dry-run`",
        "`sudo tvgw autoblock --days 30 check`",
        "`tvgw tv quiet --wait 0`",
        "`sudo tvgw setup --answers=/root/a.conf --yes`",
        "`tvgw brief [DAY] [--json]`",
        "`tvgw brief <day>`",
        "`tvgw <command> --help`",
        "`tvgw adguard {diff,apply}`",
        "`sudo -u tvgw tvgw brief | less`",
        "`sudo env PYTHONPATH=src python3 -m tvgw verify`",
        "`/opt/tvgw-venv/bin/tvgw verify`",
        "`systemctl status tvgw-guard` and `tvgw-apply`, `/etc/tvgw/tvgw.conf`, `tvgw.db`",
        "`tvgw adguard: the profile does not lint: <problems>`",  # a message, not a command
        "```sh\n# tvgw doctor is coming\necho tvgw doctor\nsudo tvgw verify\n```\n",
        "```text\ntvgw 0.2.0\ntvgw is ready\nRun sudo tvgw verify\n```\n",
        "<!-- `tvgw doctor` once it ships -->\n",
        "tvgw makes a computer the only way out, and tvgw blocks things.",
        "`--dry-run` and `--require-hashes`",
    ],
)
def test_a_line_in_the_release_or_not_a_command_line_passes(text):
    assert problems(text) == []


@pytest.mark.parametrize(
    ("text", "problem"),
    [
        ("`sudo tvgw doctor`", "p.md:1: tvgw doctor: no such command in v1"),
        ("`tvgw verify --fix`", "p.md:1: tvgw verify --fix: no such option in v1"),
        ("`tvgw --debug verify`", "p.md:1: tvgw --debug: no such option in v1"),
        ("`sudo tvgw adguard upgrade`", "p.md:1: tvgw adguard upgrade: no such subcommand in v1"),
        ("`tvgw tv loud`", "p.md:1: tvgw tv loud: no such subcommand in v1"),
        ("`tvgw tv quiet --idle 5`", "p.md:1: tvgw tv quiet --idle: no such option in v1"),
        ("`tvgw verify && tvgw doctor`", "p.md:1: tvgw doctor: no such command in v1"),
        ("`echo $(tvgw doctor)`", "p.md:1: tvgw doctor: no such command in v1"),
        ("```sh\nsudo tvgw setup \\\n  --answers a.conf \\\n  --fix\n```\n", "p.md:2: tvgw setup --fix"),
        ("```console\n$ tvgw doctor\n```\n", "p.md:2: tvgw doctor: no such command"),
        ("```text\n$ tvgw doctor\n```\n", "p.md:2: tvgw doctor: no such command"),
        ("    ```sh\n    sudo tvgw doctor\n    ```\n", "p.md:2: tvgw doctor"),
        ("Then run sudo tvgw doctor again.", "p.md:1: tvgw doctor: no such command in v1"),
        ("Add `--wait-more` to wait.", "p.md:1: --wait-more: an option v1 does not have"),
        ("| `sudo tvgw doctor` | fixes it |", "p.md:1: tvgw doctor"),
    ],
)
def test_a_command_subcommand_or_option_outside_the_release_fails(text, problem):
    found = problems(text)
    assert len(found) == 1 and found[0].startswith(problem), found


def test_line_numbers_count_the_lines_a_comment_spans():
    text = "# Page\n<!-- one\ntwo\nthree -->\n`tvgw doctor`\n"
    assert problems(text) == ["p.md:5: tvgw doctor: no such command in v1"]
