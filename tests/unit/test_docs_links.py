"""tools/check_docs_links.py: first the repository itself, where every Markdown link and anchor and
every docs path the other files name must resolve (the guard every page move needs), then the
checker's rules on throwaway trees under tmp_path, so a rule that drifts from GitHub's is caught here
rather than by a reader.

The checker reads this file too. A path that must not exist in the repository is therefore written
with DOCS, REPO or RAW in an f-string, never literally."""

import importlib.util
import os
import re
import subprocess
import sys

import pytest
from conftest import ROOT

TOOL = ROOT / "tools" / "check_docs_links.py"
spec = importlib.util.spec_from_file_location("check_docs_links", TOOL)
cdl = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = cdl  # a dataclass looks its module up by name
spec.loader.exec_module(cdl)

DOCS = "docs"
REPO = "https://github.com/kywwilson11/tvgw"
RAW = "https://raw.githubusercontent.com/kywwilson11/tvgw"
TREE = cdl.Tree.load(ROOT)


# ---- the repository ------------------------------------------------------------------------------


@pytest.mark.parametrize("page", TREE.markdown)
def test_every_link_and_anchor_on_the_page_resolves(page):
    problems, _ = cdl.check_markdown(TREE, page)
    assert not problems, "\n".join(map(str, problems))


def test_every_docs_path_the_other_files_name_resolves():
    """A message a user reads on a running gateway, a comment copied into /etc/tvgw/tvgw.conf, a file
    nfpm copies into the package, a workflow's note, an issue form, a test's docstring."""
    problems = [p for rel in TREE.others for p in cdl.check_printed(TREE, rel)[0]]
    assert not problems, "\n".join(map(str, problems))


@pytest.mark.parametrize(
    "path",
    [
        "packaging/nfpm.yaml",  # the page the package carries, as `./docs/...`
        "deploy/install.sh",
        "deploy/tvgw.conf.example",  # its comments are copied into /etc/tvgw/tvgw.conf
        "deploy/systemd/tvgw-guard.service",
        "src/tvgw/setup.py",
        "src/tvgw/adguardcfg.py",
        "src/tvgw/config.py",
        "src/tvgw/cli.py",
        ".github/workflows/release.yml",
        ".github/ISSUE_TEMPLATE/tv_report.yml",
        ".github/ISSUE_TEMPLATE/config.yml",  # a link to a file on main
        "tests/unit/test_fw_lines.py",
        "Makefile",
    ],
)
def test_the_checker_reads_the_paths_these_files_name(path):
    """The files that print or copy docs paths: a pattern that drifted would check them for nothing."""
    assert path in TREE.files
    assert cdl.check_printed(TREE, path)[1] > 0


def test_nfpms_dot_slash_path_is_read():
    """The draft checker's look-behind skipped `./docs/...`, the one path a page move breaks the
    package build with."""
    written = [w for _, w in cdl.printed_paths(TREE.read("packaging/nfpm.yaml"))]
    assert any(w.startswith("./") for w in written), written


TABLE_RULE = re.compile(r"\|?(\s*:?-{3,}:?\s*\|)*\s*:?-{3,}:?\s*\|?")


def cells(row: str) -> int:
    """A table row's cells: its pipes outside code spans, an escaped pipe and the outer two aside."""
    text = re.sub(r"`[^`]*`", "", row.strip().replace("\\|", ""))
    return text.removeprefix("|").removesuffix("|").count("|") + 1


def table_problems(text: str) -> list[str]:
    """The rows that do not fit their table. A table is a header line with its rule line under it and
    every line after them up to a blank line, an HTML comment or a fenced block."""
    problems, width, last = [], 0, 0
    lines = dict(cdl.prose_lines(text))
    for number, line in sorted(lines.items()):
        if width and (number != last + 1 or not line.strip() or line.lstrip().startswith("<!--")):
            width = 0
        elif width and (not line.lstrip().startswith("|") or cells(line) != width):
            problems.append(f"{number}: {cells(line)} cells in a table of {width}")
        elif not width and "|" in line:
            rule = lines.get(number + 1, "").strip()
            if "-" in rule and TABLE_RULE.fullmatch(rule) and cells(rule) == cells(line):
                width = cells(line)
        last = number
    return problems


def test_every_table_row_has_its_headers_cells():
    """A row cut in pieces passes every link check and renders as broken rows: a row put into the
    middle of the commands page's `tv quiet` row on 2026-11-04 left it in three, and nothing said so."""
    problems = [f"{page}:{p}" for page in TREE.markdown for p in table_problems(TREE.read(page) or "")]
    assert not problems, "\n".join(problems)
    cut = "| a | b | c |\n|---|---|---|\n| `x \\| y` | 1 \n| 2 | 3 | 4 |\nthe rest | of it |\n\n| not | a table |\n"
    assert table_problems(cut) == ["3: 2 cells in a table of 3", "5: 2 cells in a table of 3"]


def test_the_tree_is_what_git_lists():
    assert {"README.md", "docs/README.md", "tools/check_docs_links.py"} <= TREE.files
    assert not any(f.startswith((".git/", ".claude/")) or "__pycache__" in f for f in TREE.files)


# ---- the rules, on throwaway trees ---------------------------------------------------------------


def tree(tmp_path, files):
    for rel, text in files.items():
        path = tmp_path / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        if isinstance(text, bytes):
            path.write_bytes(text)
        else:
            path.write_text(text, encoding="utf-8")
    return cdl.Tree.load(tmp_path)


def problems(t, page):
    return [str(p) for p in cdl.check_markdown(t, page)[0]]


def printed_problems(t, rel):
    return [str(p) for p in cdl.check_printed(t, rel)[0]]


@pytest.mark.parametrize(
    ("heading", "anchor"),
    [
        ("What install.sh does", "what-installsh-does"),
        ("The machine's rules file", "the-machines-rules-file"),
        ("The service runs with `--no-check-update`", "the-service-runs-with---no-check-update"),
        ("`ingest_state`", "ingest_state"),
        ("STRICT_PORTS", "strict_ports"),
        ("13. Counters, not logs, prove the firewall held", "13-counters-not-logs-prove-the-firewall-held"),
        ("**Bold** and _italic_ words", "bold-and-italic-words"),
        ("__init__ and snake_case", "init-and-snake_case"),
        ("__Outer _inner_ text__", "outer-inner-text"),
        ("Escaped \\_underscores\\_", "escaped-_underscores_"),
        ("A [linked](other.md) word", "a-linked-word"),
        ("A <em>tagged</em> word", "a-tagged-word"),
        ("Tom &amp; Jerry", "tom--jerry"),
        ("Café au lait", "café-au-lait"),
        ("Done ✅", "done-"),
        ("`` a `tick` ``", "a-tick"),
        ("A [`linked` code](x.md) word", "a-linked-code-word"),  # a code span inside a link's label
        ("_Emphasis around `code`_", "emphasis-around-code"),
        ("`&amp;` and &amp;", "amp-and-"),  # an entity in a code span is text as written
    ],
)
def test_a_heading_slugs_as_github_slugs_it(heading, anchor):
    assert cdl.slug(cdl.heading_text(heading)) == anchor


def test_a_repeated_heading_is_numbered_as_github_numbers_it():
    """github-slugger counts per slug and registers the numbered one too, so a later heading whose own
    slug is a taken `a-1` becomes `a-1-1`."""
    assert cdl.anchors("# A\n## A\n## A\n## A-1\n") == {"a", "a-1", "a-2", "a-1-1"}


def test_only_real_headings_make_anchors():
    text = (
        "```\n# in a fence\n```\n"
        "~~~~\n```\n# in a tilde fence holding a backtick line\n~~~~\n"
        "   ```sh\n   # in a list item's fence\n   ```\n"
        "## Closing hashes ##\n"
        "## C#\n"
        "#hashtag\n"
        "####### seven\n"
        "#\n"
    )
    assert cdl.anchors(text) == {"closing-hashes", "c"}


def test_an_id_or_name_outside_code_is_an_anchor():
    text = '<a id="old-name"></a>\n## New name\n<a name=\'kept\'></a>\nSee `<a id="in-code">`.\n'
    assert cdl.anchors(text) == {"old-name", "new-name", "kept"}


def test_links_resolve_from_the_linking_files_folder(tmp_path):
    t = tree(
        tmp_path,
        {
            "README.md": "# Root\n",
            "pages/README.md": "# Pages\n## Section one\n",
            "pages/my page.md": "# Page\n",
            "pages/pic.png": b"\x89PNG",
            "folder/README.md": "# Folder\n## Files\n",
            "pages/guide.md": (
                "# Guide\n"
                "[up](../README.md) [same](README.md#section-one) [root](/folder/README.md#files)\n"
                "[folder](../folder/) [its anchor](../folder/#files) [here](#local) [repo](/)\n"
                "[source view](README.md?plain=1#L2) [encoded](my%20page.md) [angle](<my page.md>)\n"
                '[titled](README.md "A title") ![image](pic.png) [image anchor](pic.png#gh-dark-mode-only)\n'
                "[ref]: README.md#section-one\n"
                "## Local\n"
            ),
        },
    )
    assert problems(t, "pages/guide.md") == []
    assert cdl.check_markdown(t, "pages/guide.md")[1] == 14


def test_a_broken_link_names_its_file_line_target_and_why(tmp_path):
    """The acceptance case: an anchor broken on a branch fails the gate with the file and the line."""
    t = tree(
        tmp_path,
        {
            "pages/README.md": "# Pages\n## Section one\n",
            "pages/guide.md": (
                "# Guide\n\nSee [gone](gone.md).\nAnd [the section](README.md#section-two).\n"
                "[out](../../x.md) and [self](#nowhere)\n"
            ),
        },
    )
    assert problems(t, "pages/guide.md") == [
        "pages/guide.md:3: gone.md: no such file",
        "pages/guide.md:4: README.md#section-two: no heading #section-two in pages/README.md",
        "pages/guide.md:5: ../../x.md: leaves the repository",
        "pages/guide.md:5: #nowhere: no heading #nowhere in pages/guide.md",
    ]


def test_code_is_an_example_not_a_link(tmp_path):
    t = tree(
        tmp_path,
        {
            "a.md": (
                "```\n[x](gone.md)\n```\n"
                "   ```sh\n   [y](gone.md)\n   ```\n"
                "`[z](gone.md)` and ``[w](gone.md) `x` ``\n"
                "````\n```\n[v](gone.md)\n```\n````\n"
                '`<img src="gone.png">`\n'
            )
        },
    )
    assert problems(t, "a.md") == []


def test_an_unclosed_fence_runs_to_the_end_and_a_backtick_run_with_backticks_after_it_is_code(tmp_path):
    t = tree(tmp_path, {"a.md": "```not`a fence```\n[x](gone.md)\n```\n[y](gone.md)\n"})
    assert problems(t, "a.md") == ["a.md:2: gone.md: no such file"]


def test_html_sources_and_reference_definitions_are_links_and_a_footnote_is_not(tmp_path):
    t = tree(
        tmp_path,
        {
            "fig.dark.png": b"\x89PNG",
            "fig.light.png": b"\x89PNG",
            "a.md": (
                "<picture>\n"
                '  <source media="(prefers-color-scheme: dark)" srcset="fig.dark.png 2x, fig.small.png 1x">\n'
                '  <img alt="A figure." src="fig.light.png" data-src="ignored.png" width="960">\n'
                "</picture>\n"
                "[ref]: <missing ref.md>\n"
                "[^1]: A footnote, not a path.\n"
                "<a href='gone.html'>x</a>\n"
            ),
        },
    )
    assert problems(t, "a.md") == [
        "a.md:2: fig.small.png: no such file",
        "a.md:5: <missing ref.md>: no such file",
        "a.md:7: gone.html: no such file",
    ]


def test_a_folders_fragment_is_its_readmes(tmp_path):
    t = tree(
        tmp_path,
        {
            "folder/README.md": "# Folder\n## Part\n",
            "empty/data.txt": "x\n",
            "a.md": "[a](folder/#part) [b](folder/#nope) [c](empty/#x)\n",
        },
    )
    assert problems(t, "a.md") == [
        "a.md:1: folder/#nope: no heading #nope in folder/README.md",
        "a.md:1: empty/#x: no README.md in empty to hold #x",
    ]


def test_a_name_that_differs_in_case_is_not_found(tmp_path):
    """GitHub's paths are case-sensitive even where this filesystem is not (macOS)."""
    t = tree(tmp_path, {"Guide.md": "# Guide\n", "a.md": "[a](guide.md)\n"})
    (problem,) = cdl.check_markdown(t, "a.md")[0]
    assert problem.reason in {"no such file", "no such file: one exists whose name differs in case"}


def test_external_links_are_left_alone_and_this_repositorys_main_branch_is_checked(tmp_path):
    t = tree(
        tmp_path,
        {
            "pages/b.md": "# B\n",
            "a.md": (
                "[site](https://example.com/x.md) [mail](mailto:owner@example.com) [any](//example.com/x)\n"
                f"[main]({REPO}/blob/main/pages/b.md#b) [folder]({REPO}/tree/main/pages)\n"
                f"[tag]({REPO}/blob/v0.2.0/gone.md) [issues]({REPO}/issues)\n"
                f"[moved]({REPO}/blob/main/gone.md) [script]({RAW}/main/get.sh)\n"
                f"[raw ref]({RAW}/refs/heads/main/pages/b.md) [raw tag]({RAW}/v0.2.0/gone.sh)\n"
            ),
        },
    )
    assert problems(t, "a.md") == [
        f"a.md:4: {REPO}/blob/main/gone.md: no such file",
        f"a.md:4: {RAW}/main/get.sh: no such file",
    ]
    assert cdl.check_markdown(t, "a.md")[1] == 5


def test_a_path_the_code_names_resolves_from_the_root_with_its_anchor(tmp_path):
    """The two fixes the design asks of the draft (E-F20): nfpm's `./docs/...`, and paths in
    `.github/` and `tests/`, are read like any other."""
    t = tree(
        tmp_path,
        {
            f"{DOCS}/packaging.md": "# Packaging\n## Building the .deb\n",
            "packaging/nfpm.yaml": f"contents:\n  - src: ./{DOCS}/packaging.md\n",
            "src/tvgw/x.py": f'print("see {DOCS}/packaging.md#building-the-deb.")\n',
            ".github/workflows/w.yml": f"# {DOCS}/packaging.md\n",
            "tests/unit/t.py": f'"""{DOCS}/packaging.md#building-the-deb"""\n',
        },
    )
    for rel in ("packaging/nfpm.yaml", "src/tvgw/x.py", ".github/workflows/w.yml", "tests/unit/t.py"):
        assert cdl.check_printed(t, rel) == ([], 1), rel


def test_the_page_map_and_its_script_are_not_read_for_pointers(tmp_path):
    """tools/page-map.csv and tools/rewrite_doc_paths.py name each move's old path and its new one, and
    one of the two is always missing; every other file that is not Markdown is still read."""
    t = tree(
        tmp_path,
        {
            "tools/page-map.csv": f"old_path,new_path\n{DOCS}/gone.md,{DOCS}/later.md\n",
            "tools/rewrite_doc_paths.py": f'STUBS = ("{DOCS}/gone.md",)\n',
            "tools/other.csv": f"{DOCS}/gone.md\n",
        },
    )
    assert t.others == ["tools/other.csv"]
    assert [p.path for p in cdl.check(tmp_path).problems] == ["tools/other.csv"]


def test_a_page_moved_without_the_paths_that_name_it_fails_at_each(tmp_path):
    """The acceptance case: the packaging page moved, and `nfpm.yaml` and a workflow left alone."""
    t = tree(
        tmp_path,
        {
            f"{DOCS}/project/packaging.md": "# Packaging\n",
            "packaging/nfpm.yaml": f"contents:\n  - src: ./{DOCS}/packaging.md\n",
            ".github/workflows/release.yml": f"# Builds the .deb ({DOCS}/packaging.md).\n",
        },
    )
    assert printed_problems(t, "packaging/nfpm.yaml") == [
        f"packaging/nfpm.yaml:2: ./{DOCS}/packaging.md: no such file"
    ]
    assert printed_problems(t, ".github/workflows/release.yml") == [
        f".github/workflows/release.yml:1: {DOCS}/packaging.md: no such file"
    ]


def test_an_anchor_the_code_names_must_be_a_heading(tmp_path):
    t = tree(
        tmp_path,
        {
            f"{DOCS}/a.md": "# A\n## The levers\n",
            "deploy/x.conf": f"# {DOCS}/a.md#the-levers {DOCS}/a.md#The-Levers {DOCS}/a.md#gone\n",
        },
    )
    assert printed_problems(t, "deploy/x.conf") == [
        f"deploy/x.conf:1: {DOCS}/a.md#The-Levers: no heading #The-Levers in {DOCS}/a.md",
        f"deploy/x.conf:1: {DOCS}/a.md#gone: no heading #gone in {DOCS}/a.md",
    ]


def test_paths_relative_to_something_else_are_not_read():
    text = (
        f"../{DOCS}/x.md /usr/share/doc/tvgw/x.md https://example.com/{DOCS}/x.md\n"
        f"{DOCS}/x.mdx {DOCS}/x.md5 notes/{DOCS}/x.md\n"
    )
    assert list(cdl.printed_paths(text)) == []


def test_a_markdown_name_with_another_extension_after_it_is_another_file():
    """A template such as `.github/release-notes.md.in` is not the page `release-notes.md`; the full
    stop that ends a sentence, or a colon and a line number, still ends the path."""
    text = (
        f"--template .github/release-notes.md.in {DOCS}/x.md.bak {DOCS}/x.md.j2\n"
        f"See {DOCS}/a.md. Then {DOCS}/b.md#part, then {DOCS}/c.md:12.\n"
    )
    assert list(cdl.printed_paths(text)) == [
        (2, f"{DOCS}/a.md"),
        (2, f"{DOCS}/b.md#part"),
        (2, f"{DOCS}/c.md"),
    ]


def test_a_link_to_main_in_a_file_that_is_not_markdown_is_checked(tmp_path):
    t = tree(
        tmp_path,
        {
            "SECURITY.md": "# Security\n",
            ".github/ISSUE_TEMPLATE/config.yml": (
                f"url: {REPO}/blob/main/SECURITY.md\nurl: {REPO}/blob/main/CONDUCT.md.\n"
            ),
        },
    )
    assert printed_problems(t, ".github/ISSUE_TEMPLATE/config.yml") == [
        f".github/ISSUE_TEMPLATE/config.yml:2: {REPO}/blob/main/CONDUCT.md: no such file"
    ]


def test_markdown_and_binary_files_are_not_read_for_named_paths(tmp_path):
    t = tree(
        tmp_path,
        {
            "a.md": f"A path in prose is not a link: `{DOCS}/gone.md`.\n",
            "pic.png": b"\x89PNG\x00" + f"{DOCS}/gone.md".encode(),
            "latin.txt": f"caf\xe9 {DOCS}/gone.md".encode("latin-1"),
        },
    )
    assert t.others == ["latin.txt", "pic.png"]
    assert [cdl.check_printed(t, rel) for rel in t.others] == [([], 0), ([], 0)]
    assert problems(t, "a.md") == []


# ---- what the tree is ----------------------------------------------------------------------------


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


def git(root, *args):
    subprocess.run(["git", "-C", str(root), *args], check=True, capture_output=True)


def test_git_lists_a_new_page_and_leaves_out_what_it_ignores(tmp_path, git_env):
    """A page counts before `git add`; a file git ignores is not on GitHub, so a link to it is broken;
    a tracked page deleted from the working tree is gone."""
    tree(
        tmp_path,
        {
            ".gitignore": "ignored/\n",
            "README.md": "[new](new.md) [ignored](ignored/x.md) [deleted](old.md)\n",
            "old.md": "# Old\n",
        },
    )
    git(tmp_path, "init", "-q", "-b", "main")
    git(tmp_path, "add", "-A")
    git(tmp_path, "commit", "-q", "-m", "base")
    tree(tmp_path, {"new.md": "# New\n", "ignored/x.md": "# X\n"})
    (tmp_path / "old.md").unlink()
    t = cdl.Tree.load(tmp_path)
    assert t.files == {".gitignore", "README.md", "new.md"}
    assert problems(t, "README.md") == [
        "README.md:1: ignored/x.md: exists here, but git ignores it",
        "README.md:1: old.md: no such file",
    ]


def test_a_folder_that_is_not_a_checkout_is_walked_without_what_gitignore_holds(tmp_path):
    t = tree(
        tmp_path,
        {
            "a.md": "# A\n",
            "build/b.md": "[x](gone.md)\n",
            ".venv/c.md": "[x](gone.md)\n",
            "src/__pycache__/d.pyc": b"\x00",
            "pages/e.md": "# E\n",
        },
    )
    assert t.files == {"a.md", "pages/e.md"}


def test_a_checkout_git_cannot_read_stops_the_check(tmp_path, git_env):
    (tmp_path / ".git").write_text(f"gitdir: {tmp_path / 'nowhere'}\n", encoding="utf-8")
    with pytest.raises(cdl.ListingError, match="git ls-files failed"):
        cdl.Tree.load(tmp_path)
    assert cdl.main(["--root", str(tmp_path)]) == 2


def run_tool(root):
    return subprocess.run(
        [sys.executable, "-I", str(TOOL), "--root", str(root)],
        capture_output=True,
        text=True,
        encoding="utf-8",
        env={**os.environ, "PYTHONUTF8": "1"},
        timeout=60,
    )


def test_the_command_line_passes_a_sound_tree_and_names_each_broken_pointer(tmp_path):
    """Run as CI and the docs workflow run it: `python3 -I`, standard library only."""
    sound = tmp_path / "sound"
    tree(sound, {"README.md": "# Root\n## Part\n[part](#part)\n", "Makefile": f"# {DOCS}/README.md\n"})
    tree(sound, {f"{DOCS}/README.md": "# Docs\n"})
    out = run_tool(sound)
    assert out.returncode == 0, out.stdout + out.stderr
    assert out.stdout == (
        "check_docs_links: 2 Markdown files with 1 link, and 1 path named in other files: all resolve\n"
    )
    broken = tmp_path / "broken"
    tree(broken, {"README.md": "# Root\n\n[gone](gone.md)\n"})
    out = run_tool(broken)
    assert out.returncode == 1
    assert out.stdout == "README.md:3: gone.md: no such file\n"
    assert out.stderr == "check_docs_links: 1 pointer leads nowhere\n"


def test_the_gate_runs_the_checker():
    """`make gate` runs it before the unit suite, so a broken pointer is listed by file and line first."""
    make = (ROOT / "Makefile").read_text(encoding="utf-8")
    gate = make.split("\ngate:", 1)[1].split("\n\n", 1)[0].splitlines()
    assert "\t$(PY) tools/check_docs_links.py" in gate
    assert gate.index("\t$(PY) tools/check_docs_links.py") < gate.index("\t$(PY) -m pytest -q")
