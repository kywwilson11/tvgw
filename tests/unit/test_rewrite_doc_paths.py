"""tools/rewrite_doc_paths.py: first the repository, which must already be as the page map says (each
page at its new path, every pointer at it, the stubs and the placeholders written), then each rule on
a throwaway tree with a page map of its own.

tools/check_docs_links.py reads this file too, so fixture text writes `@/` for `docs/` and `"@"` for
`"docs"`: a fixture's page is then never taken for a path of the repository, and the rewrite this file
tests never rewrites the file itself."""

import importlib.util
import os
import posixpath
import re
import subprocess
import sys

import pytest
from conftest import ROOT

TOOL = ROOT / "tools" / "rewrite_doc_paths.py"
spec = importlib.util.spec_from_file_location("rewrite_doc_paths", TOOL)
rdp = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = rdp  # a dataclass looks its module up by name
spec.loader.exec_module(rdp)

REPO_PAGES = rdp.PageMap.from_rows(rdp.read_map(ROOT / rdp.MAP))


# ---- the repository ------------------------------------------------------------------------------


def test_the_repository_follows_the_page_map():
    """Every page the map moves is at its new path, nothing points at an old one, and the stubs and
    the placeholders are written. A branch that adds a link to an old path fails here until the
    script has run."""
    result = rdp.plan(ROOT, REPO_PAGES)
    assert not result.problems and not result.notes, result.problems + result.notes
    assert result.empty(), "run python3 tools/rewrite_doc_paths.py:\n" + "\n".join(rdp.report(result))


def test_each_stub_is_an_h1_and_a_link_to_its_page_new_home():
    for old in rdp.STUBS:
        home = REPO_PAGES.moves[old]
        text = (ROOT / old).read_text(encoding="utf-8")
        assert rdp.is_stub(text), old
        assert f"]({posixpath.relpath(home, posixpath.dirname(old))})" in text, old


def test_every_page_the_map_moves_to_and_every_placeholder_exists():
    for path in [*REPO_PAGES.moves.values(), *rdp.PLACEHOLDERS]:
        assert (ROOT / path).is_file(), path


def test_the_stubs_and_the_placeholders_are_pages_of_the_map():
    """The command line writes only those the map names, so one the map lost would go unwritten."""
    assert set(rdp.STUBS) <= set(REPO_PAGES.moves)
    placeholders = set(rdp.PLACEHOLDERS)
    assert placeholders <= REPO_PAGES.named
    assert not placeholders & set(REPO_PAGES.moves.values())
    assert not placeholders & set(REPO_PAGES.moves)


def test_a_user_page_placeholder_keeps_each_sentence_to_18_words():
    """The pages a reader who is not an engineer reads keep each sentence to 18 words at most; a link
    counts by its label."""
    user = ("docs/what-it-stops.md", "docs/install/", "docs/use/", "docs/tv/")
    checked = 0
    for path, (_, lead) in rdp.PLACEHOLDERS.items():
        if not path.startswith(user):
            continue
        checked += 1
        text = re.sub(r"\[([^\]]*)\]\([^)]*\)", r"\1", lead)
        for sentence in re.split(r"(?<=[.!?])\s+", text):
            assert len(sentence.split()) <= 18, (path, sentence)
    assert checked


def test_the_map_and_the_script_are_left_as_written():
    """They name the old paths on purpose."""
    assert {rdp.MAP, "tools/rewrite_doc_paths.py"} <= set(rdp.KEEP_AS_WRITTEN)


# ---- the rules, on throwaway trees ---------------------------------------------------------------

MAP = """old_path,old_anchor,new_path,new_anchor,action,note
README.md,,README.md,,rewrite,
README.md,start,@/use/start.md,,move,a section of a page that stays
@/whole.md,,@/how/whole.md,,move,a page that moves whole
@/split.md,first,@/use/home.md,first,move,"the first row, so the page moves here whole"
@/split.md,second,@/use/other.md,renamed,move,
@/split.md,third,@/ref/third.md,,split,
@/notice.md,,@/use/privacy.md,the-notice,merge,
,,@/new/page.md,,new,
"""
STUBS = ("@/whole.md",)
PLACEHOLDERS = {"@/new/page.md": ("A new page", "It holds one sentence.")}


def d(text):
    """Fixture text as it is written to disk."""
    return text.replace("@/", "docs/").replace('"@"', '"docs"')


def write(root, files):
    for rel, text in files.items():
        path = root / d(rel)
        path.parent.mkdir(parents=True, exist_ok=True)
        if isinstance(text, bytes):
            path.write_bytes(text)
        else:
            path.write_text(d(text), encoding="utf-8")


def read(root, rel):
    return (root / d(rel)).read_text(encoding="utf-8")


def make(root, files, page_map=MAP):
    write(root, {"tools/page-map.csv": page_map, **files})
    return root


def pages(root):
    return rdp.PageMap.from_rows(rdp.read_map(root / rdp.MAP))


def plan(root, **kw):
    return rdp.plan(
        root,
        pages(root),
        stubs=[d(s) for s in STUBS],
        placeholders={d(k): v for k, v in PLACEHOLDERS.items()},
        **kw,
    )


def run(root, **kw):
    result = plan(root, **kw)
    assert not result.problems, result.problems
    rdp.apply(root, result)
    return result


WHOLE = """# Whole page

The lead.

## Part

Back to [the front page](../README.md), on to [the second part](split.md#second), [this part](#part).

<picture>
  <source media="(prefers-color-scheme: dark)" srcset="diagrams/fig.dark.png">
  <img alt="A figure" src="diagrams/fig.light.png">
</picture>
"""
SPLIT = """# Split page

## First

[The second](#second).

## Second

### Sub

## Third
"""
FIGURES = {"@/diagrams/fig.dark.png": b"\x89PNG\r\n\0dark", "@/diagrams/fig.light.png": b"\x89PNG\r\n\0light"}


def test_a_page_that_moves_whole_takes_every_link_along(tmp_path):
    make(
        tmp_path,
        {
            "README.md": "# Front\n\n## Start\n\nSee [the page](@/whole.md#part) and [it](/@/whole.md).\n",
            "@/README.md": "# Index\n\n- [whole.md](whole.md): one page\n- [split](split.md)\n",
            "@/whole.md": WHOLE,
            "@/split.md": SPLIT,
            **FIGURES,
        },
    )
    result = run(tmp_path)
    assert result.moves == [(d("@/split.md"), d("@/use/home.md")), (d("@/whole.md"), d("@/how/whole.md"))]
    assert read(tmp_path, "README.md") == d(
        "# Front\n\n## Start\n\nSee [the page](@/how/whole.md#part) and [it](/@/how/whole.md).\n"
    )
    # a label that repeats its link's path follows it
    assert (
        read(tmp_path, "@/README.md")
        == "# Index\n\n- [how/whole.md](how/whole.md): one page\n- [split](use/home.md)\n"
    )
    # the moved page's own links are written from its new folder; its own anchor stays as it was
    moved = read(tmp_path, "@/how/whole.md")
    assert "[the front page](../../README.md)" in moved
    assert "[the second part](../use/home.md#second)" in moved
    assert "[this part](#part)" in moved
    assert 'srcset="../diagrams/fig.dark.png"' in moved and 'src="../diagrams/fig.light.png"' in moved
    assert not (tmp_path / d("@/split.md")).exists()  # no stub: it is not a printed path
    assert read(tmp_path, "@/use/home.md") == SPLIT  # moved as it was: nothing cuts it apart


def test_a_section_the_map_sends_elsewhere_follows_once_it_is_there(tmp_path):
    """The anchor stays with the page the section moved with until the section is moved by hand: its
    anchor gone from there, and the map's new anchor present at the new home."""
    make(
        tmp_path,
        {
            "README.md": "# Front\n\n[2](@/split.md#second) [sub](@/split.md#sub) [3](@/split.md#third)\n",
            "@/split.md": SPLIT,
        },
    )
    run(tmp_path)
    assert read(tmp_path, "README.md") == d(
        "# Front\n\n[2](@/use/home.md#second) [sub](@/use/home.md#sub) [3](@/use/home.md#third)\n"
    )
    write(
        tmp_path,
        {
            "@/use/home.md": "# Split page\n\n## First\n\n[The second](other.md#renamed).\n",
            "@/use/other.md": "# Other\n\n## Renamed\n\n### Sub\n",
            "@/ref/third.md": "# Third\n",
        },
    )
    run(tmp_path)
    # the subsection follows to the one page of the map that holds its anchor; a row without a new
    # anchor takes a pointer to the page itself
    assert read(tmp_path, "README.md") == d(
        "# Front\n\n[2](@/use/other.md#renamed) [sub](@/use/other.md#sub) [3](@/ref/third.md)\n"
    )


def test_a_pointer_to_a_section_moved_nowhere_yet_stays_for_the_link_check_to_name(tmp_path):
    make(tmp_path, {"README.md": "# Front\n\n[2](@/split.md#second)\n", "@/split.md": SPLIT})
    run(tmp_path)
    write(tmp_path, {"@/use/home.md": "# Split page\n\n## First\n"})  # Second cut, and pasted nowhere
    assert plan(tmp_path).empty()
    assert read(tmp_path, "README.md") == d("# Front\n\n[2](@/use/home.md#second)\n")


def test_a_section_of_a_page_that_stays_follows_once_it_is_moved(tmp_path):
    make(
        tmp_path,
        {
            "README.md": "# Front\n\n## Start\n",
            "@/README.md": "# Index\n\n[s](../README.md#start)\n",
            "@/new/page.md": "# A new page\n",
        },
    )
    assert plan(tmp_path).empty()
    write(tmp_path, {"README.md": "# Front\n", "@/use/start.md": "# Start\n"})
    run(tmp_path)
    assert read(tmp_path, "@/README.md") == "# Index\n\n[s](use/start.md)\n"


def test_a_section_moved_into_the_page_that_links_it_is_linked_by_its_anchor(tmp_path):
    """The pages link a section of their own as `#anchor`, never by their own file name."""
    make(tmp_path, {"@/split.md": SPLIT, "@/use/other.md": "# Other\n\nSee [it](../split.md#second).\n"})
    run(tmp_path)
    assert read(tmp_path, "@/use/other.md") == "# Other\n\nSee [it](home.md#second).\n"
    write(
        tmp_path,
        {
            "@/use/home.md": "# Split page\n\n## First\n",
            "@/use/other.md": "# Other\n\nSee [it](home.md#second) and [the page](home.md).\n\n## Renamed\n",
        },
    )
    run(tmp_path)
    assert read(tmp_path, "@/use/other.md") == (
        "# Other\n\nSee [it](#renamed) and [the page](home.md).\n\n## Renamed\n"
    )


def test_a_page_merged_as_one_section_is_linked_at_it_once_it_exists(tmp_path):
    make(tmp_path, {"@/notice.md": "# Notice\n", "@/a.md": "# A\n\n[n](notice.md)\n"})
    run(tmp_path)
    assert read(tmp_path, "@/a.md") == "# A\n\n[n](use/privacy.md)\n"
    write(
        tmp_path,
        {"@/use/privacy.md": "# Privacy\n\n## The notice\n", "@/b.md": "# B\n\n[n](notice.md)\n"},
    )
    run(tmp_path)
    assert read(tmp_path, "@/b.md") == "# B\n\n[n](use/privacy.md#the-notice)\n"
    assert read(tmp_path, "@/a.md") == "# A\n\n[n](use/privacy.md)\n"  # a link to the page stays one


def test_a_record_gets_its_links_rewritten_and_nothing_else(tmp_path):
    record = "- [@/whole.md](@/whole.md#part): @/whole.md moved, `@/whole.md` in a code span\n"
    make(
        tmp_path,
        {
            "CHANGELOG.md": "# Changelog\n\n" + record,
            "@/research/r.md": "# R\n\n[whole.md](../whole.md), @/whole.md\n",
            "@/whole.md": WHOLE,
        },
    )
    run(tmp_path)
    assert read(tmp_path, "CHANGELOG.md") == d(
        "# Changelog\n\n- [@/whole.md](@/how/whole.md#part): @/whole.md moved, `@/whole.md` in a code span\n"
    )
    assert read(tmp_path, "@/research/r.md") == d("# R\n\n[whole.md](../how/whole.md), @/whole.md\n")


def test_any_other_page_gets_its_paths_written_as_text_rewritten_too(tmp_path):
    make(
        tmp_path,
        {
            "@/rules.md": (
                "# Rules\n\n"
                "- owner: @/whole.md#part, and `@/whole.md` in a code span\n"
                "- [@/whole.md](whole.md) and [`whole.md`](whole.md) and [another name](whole.md)\n"
                "- elsewhere: https://example.com/@/whole.md and ../@/whole.md and x/@/whole.md\n"
                "\n```text\n@/whole.md in an example\n```\n"
            ),
            "@/whole.md": WHOLE,
        },
    )
    run(tmp_path)
    assert read(tmp_path, "@/rules.md") == d(
        "# Rules\n\n"
        "- owner: @/how/whole.md#part, and `@/how/whole.md` in a code span\n"
        "- [@/how/whole.md](how/whole.md) and [`how/whole.md`](how/whole.md) and [another name](how/whole.md)\n"
        "- elsewhere: https://example.com/@/whole.md and ../@/whole.md and x/@/whole.md\n"
        "\n```text\n@/whole.md in an example\n```\n"
    )


def test_a_link_to_this_repositorys_main_branch_follows(tmp_path):
    url = "https://github.com/kywwilson11/tvgw/blob/main"
    make(
        tmp_path,
        {
            "README.md": f"# F\n\n[w]({url}/@/whole.md#part)\n",
            "@/whole.md": WHOLE,
            "x.yml": f"# {url}/@/whole.md\n",
        },
    )
    run(tmp_path)
    assert read(tmp_path, "README.md") == d(f"# F\n\n[w]({url}/@/how/whole.md#part)\n")
    assert read(tmp_path, "x.yml") == d(f"# {url}/@/how/whole.md\n")


def test_the_paths_other_files_name_follow(tmp_path):
    make(
        tmp_path,
        {
            "@/whole.md": WHOLE,
            "@/split.md": SPLIT,
            "src/x.py": (
                'print("see @/whole.md#part.")  # @/split.md#second\n'
                'PAGE = ROOT / "@" / "whole.md"\n'
                'PICS = ROOT / "@" / "diagrams"\n'
            ),
            "packaging/nfpm.yaml": "contents:\n  - src: ./@/whole.md\n    dst: /usr/share/doc/x/whole.md\n",
            "deploy/x.service": "# @/split.md (a split page goes whole to its first row's home)\n",
            "tools/blob.bin": b"\0@/whole.md",
        },
    )
    before_map = read(tmp_path, "tools/page-map.csv")
    run(tmp_path)
    assert read(tmp_path, "src/x.py") == d(
        'print("see @/how/whole.md#part.")  # @/use/home.md#second\n'
        'PAGE = ROOT / "@" / "how" / "whole.md"\n'
        'PICS = ROOT / "@" / "diagrams"\n'
    )
    assert read(tmp_path, "packaging/nfpm.yaml") == d(
        "contents:\n  - src: ./@/how/whole.md\n    dst: /usr/share/doc/x/whole.md\n"
    )
    assert read(tmp_path, "deploy/x.service") == d(
        "# @/use/home.md (a split page goes whole to its first row's home)\n"
    )
    assert (tmp_path / "tools/blob.bin").read_bytes() == b"\0@/whole.md"
    assert read(tmp_path, "tools/page-map.csv") == before_map


def test_a_printed_page_keeps_a_stub_and_nothing_links_to_it(tmp_path):
    make(tmp_path, {"@/whole.md": WHOLE, "src/x.py": 'print("@/whole.md")\n'})
    run(tmp_path, write_stubs=False)
    assert not (tmp_path / d("@/whole.md")).exists()
    result = run(tmp_path)
    assert result.created == [d("@/whole.md")] and result.moves == [] and result.edits == []
    assert read(tmp_path, "@/whole.md") == d(
        "# Whole page\n\nThis page moved to [@/how/whole.md](how/whole.md).\n"
    )
    assert rdp.is_stub(read(tmp_path, "@/whole.md"))
    # a pointer written later at the old path goes to the new home, not to the stub
    write(tmp_path, {"src/y.py": 'print("@/whole.md#part")\n', "README.md": "# F\n\n[w](@/whole.md)\n"})
    run(tmp_path)
    assert read(tmp_path, "src/y.py") == d('print("@/how/whole.md#part")\n')
    assert read(tmp_path, "README.md") == d("# F\n\n[w](@/how/whole.md)\n")


def test_a_placeholder_is_written_once_and_never_over_a_page(tmp_path):
    make(tmp_path, {})
    result = run(tmp_path)
    assert result.created == [d("@/new/page.md")]
    assert read(tmp_path, "@/new/page.md") == "# A new page\n\nIt holds one sentence.\n"
    write(tmp_path, {"@/new/page.md": "# A new page\n\nIts real content.\n"})
    assert plan(tmp_path).empty()


def test_a_second_run_finds_nothing_to_do(tmp_path):
    make(
        tmp_path,
        {"README.md": "# F\n\n[w](@/whole.md)\n", "@/whole.md": WHOLE, "@/split.md": SPLIT, **FIGURES},
    )
    run(tmp_path)
    again = plan(tmp_path)
    assert again.empty(), rdp.report(again)


def test_a_page_at_both_paths_stops_the_run_with_nothing_changed(tmp_path, capsys):
    make(tmp_path, {"@/whole.md": WHOLE, "@/how/whole.md": WHOLE, "README.md": "# F\n\n[w](@/whole.md)\n"})
    assert rdp.main(["--root", str(tmp_path)]) == 1
    err = capsys.readouterr().err
    assert d("@/whole.md and @/how/whole.md both hold the page") in err
    assert "nothing was changed" in err
    assert read(tmp_path, "README.md") == d("# F\n\n[w](@/whole.md)\n")


def test_a_page_at_neither_path_is_named(tmp_path):
    make(tmp_path, {})
    result = rdp.plan(tmp_path, pages(tmp_path), stubs=(), placeholders={})
    assert d("neither @/whole.md nor @/how/whole.md is in the tree") in result.notes
    assert not result.problems  # the run goes on with the pages that are there


def test_check_changes_nothing_and_lists_each_change(tmp_path, capsys):
    make(
        tmp_path,
        {
            "README.md": "# F\n\n[w](@/whole.md)\n",
            "@/whole.md": WHOLE,
            "@/split.md": SPLIT,
            "@/notice.md": "# N\n",
        },
    )
    before = {p: p.read_bytes() for p in tmp_path.rglob("*") if p.is_file()}
    assert rdp.main(["--root", str(tmp_path), "--check"]) == 1
    out = capsys.readouterr().out.splitlines()
    assert d("move @/whole.md -> @/how/whole.md") in out
    assert d("README.md:3: @/whole.md -> @/how/whole.md") in out
    assert out[-1].startswith("rewrite_doc_paths: ") and out[-1].endswith("run it without --check")
    assert {p: p.read_bytes() for p in tmp_path.rglob("*") if p.is_file()} == before


def git(root, *args):
    return subprocess.run(["git", "-C", str(root), *args], check=True, capture_output=True, text=True).stdout


@pytest.fixture()
def git_env(monkeypatch):
    for key, value in {
        "GIT_CONFIG_GLOBAL": "/dev/null",
        "GIT_CONFIG_NOSYSTEM": "1",
        "GIT_AUTHOR_NAME": "test",
        "GIT_AUTHOR_EMAIL": "test@example.com",
        "GIT_COMMITTER_NAME": "test",
        "GIT_COMMITTER_EMAIL": "test@example.com",
    }.items():
        monkeypatch.setenv(key, value)


def test_in_a_checkout_git_records_each_move_as_a_rename(tmp_path, git_env, capsys):
    make(tmp_path, {"README.md": "# F\n\n[w](@/whole.md)\n", "@/whole.md": WHOLE, "@/notice.md": "# N\n"})
    git(tmp_path, "init", "-q", "-b", "main")
    git(tmp_path, "add", "-A", ":!" + d("@/notice.md"))  # one page is new and not yet added
    git(tmp_path, "commit", "-q", "-m", "base")
    assert rdp.main(["--root", str(tmp_path), "--no-stubs"]) == 0
    status = git(tmp_path, "status", "--porcelain").splitlines()
    # renamed in the index (R), its links then rewritten in the working tree (M)
    assert d("RM @/whole.md -> @/how/whole.md") in status
    assert (tmp_path / d("@/use/privacy.md")).is_file() and not (tmp_path / d("@/notice.md")).exists()
    assert capsys.readouterr().out.splitlines()[-1].startswith("rewrite_doc_paths: moved 2 pages")
    git(tmp_path, "add", "-A")
    assert rdp.main(["--root", str(tmp_path)]) == 0  # the stub
    assert rdp.main(["--root", str(tmp_path), "--check"]) == 0
    assert capsys.readouterr().out.splitlines()[-1] == "rewrite_doc_paths: the tree follows the page map"


@pytest.mark.parametrize(
    ("page_map", "message"),
    [
        ("old,new\n", "the header must be"),
        (MAP + "@/x.md,,@/y.md,,shuffle,\n", "unknown action 'shuffle'"),
        (MAP + "@/x.md,,@/how/whole.md,,move,\n", "both move whole to"),
        (MAP + "@/split.md,second,@/z.md,,move,\n", "a second row for"),
        (MAP + "@/x.md,,../y.md,,move,\n", "is not a path from the repository root"),
        (MAP + "@/x.md,Not An Anchor,@/y.md,,move,\n", "is not an anchor"),
        (MAP + "@/x.md,,,,move,\n", "move needs a new path"),
        (MAP + "@/x.md,,@/whole.md,,move,\n", "a page the map also lists as an old one"),
    ],
)
def test_a_map_that_cannot_be_read_or_says_two_things_is_refused(tmp_path, capsys, page_map, message):
    make(tmp_path, {}, page_map=page_map)
    assert rdp.main(["--root", str(tmp_path)]) == 2
    assert message in capsys.readouterr().err


def test_a_map_given_by_path_inside_the_tree_is_left_as_written(tmp_path):
    make(tmp_path, {"@/whole.md": WHOLE, "@/maps/m.csv": MAP})
    assert rdp.main(["--root", str(tmp_path), "--map", str(tmp_path / d("@/maps/m.csv"))]) == 0
    assert read(tmp_path, "@/maps/m.csv") == d(MAP)
    assert (tmp_path / d("@/how/whole.md")).is_file()


def test_the_command_line_runs_isolated(tmp_path):
    """`python3 -I` puts no folder of its own on the path: the checker is loaded by its file."""
    make(tmp_path, {"@/whole.md": WHOLE})
    out = subprocess.run(
        [sys.executable, "-I", str(TOOL), "--root", str(tmp_path), "--check"],
        capture_output=True,
        text=True,
        encoding="utf-8",
        env={**os.environ, "PYTHONUTF8": "1"},
        timeout=60,
    )
    assert out.returncode == 1, out.stderr
    assert d("move @/whole.md -> @/how/whole.md") in out.stdout.splitlines()
