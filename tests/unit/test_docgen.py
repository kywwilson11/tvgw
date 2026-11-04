"""tools/docgen.py: first the repository, whose generated regions must be what the code writes (so a hand
edit inside a region, or a profile, a check or a red line changed without `make docgen`, fails the gate),
and the facts the hand-written vendor tables must keep; then the generator's rules on throwaway trees
under tmp_path."""

import os
import subprocess
import sys

import pytest
from conftest import ROOT, load_tool

from tvgw import profile, setup, verify

docgen = load_tool("docgen")
TOOL = ROOT / "tools" / "docgen.py"
VENDOR = ("lg-webos", "samsung-tizen", "roku", "vizio-smartcast")

# where each generated region of the repository is, by page and block: a marker taken out by mistake,
# or a block added to a page, shows here
EXPECTED = {
    ("README.md", "support-table"),
    ("docs/tv/README.md", "support-table"),
    ("src/tvgw/profiles/README.md", "profile-support"),
    ("docs/tv/lg-webos.md", "can-check profile=lg-webos"),
    ("docs/tv/lg-webos.md", "generations profile=lg-webos"),
    ("docs/tv/samsung-tizen.md", "can-check profile=samsung-tizen"),
    ("docs/tv/roku.md", "can-check profile=roku"),
    ("docs/tv/vizio-smartcast.md", "can-check profile=vizio-smartcast"),
    ("docs/reference/verify-checks.md", "verify-new-checks"),
    ("docs/reference/verify-checks.md", "verify-checks"),
    ("docs/reference/brief-sections.md", "red-lines"),
}


def page(name: str) -> str:
    return (ROOT / "docs" / "tv" / f"{name}.md").read_text(encoding="utf-8")


# ---- the repository ------------------------------------------------------------------------------


def test_every_generated_region_is_what_the_code_writes():
    found, changes = docgen.stale(ROOT)
    assert found
    assert not changes, "run `make docgen`: " + ", ".join(f"{r.page}:{r.line} {r.label}" for r, _ in changes)


def test_the_regions_are_on_the_pages_that_need_them():
    found, _ = docgen.stale(ROOT)
    assert {(r.page, r.label) for r in found} == EXPECTED
    for r in found:  # a brand's block sits on that brand's page
        for key, value in r.params:
            assert key == "profile" and r.page == f"docs/tv/{value}.md", (r.page, r.label)


def test_the_check_runs_under_python3_I_from_the_checkouts_own_code():
    """No PYTHONPATH and no installed package needed: the tool puts its checkout's src/ first."""
    env = {k: v for k, v in os.environ.items() if k != "PYTHONPATH"}
    run = subprocess.run(
        [sys.executable, "-I", str(TOOL), "--check"], capture_output=True, text=True, env=env, cwd="/"
    )
    assert run.returncode == 0, run.stdout + run.stderr
    assert run.stdout == f"docgen: {len(EXPECTED)} generated regions on 9 pages, all as the code has them\n"


@pytest.mark.parametrize("name", VENDOR)
def test_every_must_allow_host_is_on_its_vendor_page(name):
    """The must-allow tables keep their plain reasons by hand until the profiles hold plain ones; the
    names in them are the profile's, every one of them."""
    text = page(name)
    for host in profile.load(name).must_allow:
        assert f"| `{host}` |" in text, f"{host} is in {name}'s [must_allow] and not on its page"


@pytest.mark.parametrize("name", VENDOR)
def test_every_privacy_setting_and_menu_path_is_on_its_vendor_page(name):
    """A menu path changed in the profile and not on its page fails here: the privacy tables are written
    by hand until the profiles say what each setting controls in plain words."""
    text = page(name)
    for setting in profile.load(name).privacy_settings:
        assert f"| {setting.name} |" in text, f"{setting.name} is not in {name}'s privacy table"
        for _, path in setting.menu:
            assert path in text, f"{name}'s page lacks the menu path {path!r}"


@pytest.mark.parametrize("name", profile.bundled_names())
def test_no_privacy_record_recommends_accepting_an_agreement(name):
    for setting in profile.load(name).privacy_settings:
        if any(word in setting.name for word in ("agreement", "Voice", "Viewing")):
            assert setting.recommended.lower().startswith(("decline", "off", "untick")), setting.name


def test_tested_only_where_the_profile_and_the_generation_say_so():
    for row in docgen.support_rows():
        assert ("**Tested**" in row.status) == (row.level == "tested"), row
        assert row.status.startswith(f"**{profile.SUPPORT[row.level]}**"), row
    lg = profile.load("lg-webos")
    lines = [line for line in docgen.render("generations", (("profile", "lg-webos"),)).split("\n")[2:]]
    for line, g in zip(lines, lg.generations, strict=True):
        assert line.startswith(f"| {g.webos} |")
        assert ("Tested" in line) == (g.verified and lg.support == "tested"), line


def test_the_profile_readme_and_the_front_page_tables_hold_the_same_facts():
    front = docgen.render("support-table").split("\n")
    readme = docgen.render("profile-support").split("\n")
    assert len(front) == len(readme) == 2 + len(docgen.support_rows())
    for f, r in zip(front[2:], readme[2:], strict=True):
        cells = r.split(" | ")
        assert " | ".join(cells[:1] + cells[2:]) == f


def test_support_rows_follow_the_names_order_and_split_lg_by_generation():
    rows = docgen.support_rows()
    assert [r.profile for r in rows] == ["lg-webos"] * 3 + list(docgen.TV_NAMES)[1:]
    assert [r.tv for r in rows][:3] == [
        "LG, webOS 5 (2020 sets)",
        "LG, webOS 6 and later (2021 on)",
        "LG, webOS 3 and 4 (2016 to 2019 sets)",
    ]
    assert rows[0].you_check == "Nothing after setup"
    assert rows[-1].does == docgen.SHARED_LISTS_ONLY and "general profile" in rows[-1].status


def test_a_bundled_profile_without_a_name_stops_it(monkeypatch):
    monkeypatch.setattr(profile, "bundled_names", lambda: (*docgen.TV_NAMES, "acme-tv"))
    with pytest.raises(
        docgen.DocgenError, match="acme-tv has no name in the support table: add it to TV_NAMES"
    ):
        docgen.render("support-table")
    monkeypatch.setattr(profile, "bundled_names", lambda: tuple(docgen.TV_NAMES)[1:])
    with pytest.raises(docgen.DocgenError, match="TV_NAMES names lg-webos, which is not a bundled profile"):
        docgen.render("support-table")


def test_a_tv_the_gateway_learns_to_read_needs_its_plain_words(monkeypatch):
    assert docgen.render("can-check", (("profile", "roku"),)) == docgen.READS_NOTHING
    assert docgen.render("can-check", (("profile", "lg-webos"),)).startswith("Once the TV is paired")
    monkeypatch.setattr(setup, "PAIRABLE_PROFILES", ("lg-webos", "roku"))
    with pytest.raises(docgen.DocgenError, match=r"can read roku TVs .* add it to READERS and READS"):
        docgen.render("can-check", (("profile", "roku"),))
    monkeypatch.setattr(setup, "PAIRABLE_PROFILES", ())
    with pytest.raises(docgen.DocgenError, match="describes lg-webos, which the gateway cannot pair with"):
        docgen.render("support-table")


def test_a_new_check_held_at_a_warning_must_be_a_check(monkeypatch):
    monkeypatch.setitem(verify.FAIL_AFTER, "no_such_check", verify.FAIL)
    with pytest.raises(docgen.DocgenError, match="FAIL_AFTER names no_such_check"):
        docgen.render("verify-new-checks")


def test_every_block_renders_the_same_twice():
    """No time, no set order: the same code writes the same text."""
    for name, block in docgen.BLOCKS.items():
        params = (("profile", "lg-webos"),) if block.params else ()
        assert docgen.render(name, params) == docgen.render(name, params), name


# ---- the rules, on throwaway trees ---------------------------------------------------------------

BLOCK = "verify-new-checks"
OPEN, CLOSE = f"<!-- generated:{BLOCK} -->", f"<!-- /generated:{BLOCK} -->"


def tree(root, files):
    for rel, text in files.items():
        path = root / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text, encoding="utf-8")
    return root


def run(root, *args):
    return docgen.main(["--root", str(root), *args])


def test_a_region_is_written_and_everything_around_it_kept_byte_for_byte(tmp_path, capsys):
    before = "# T\n\nA line with two trailing spaces  \n\n| a | b |\n|---|---|\n\n"
    after = "\n\nAfter it, no newline at the end."
    tree(tmp_path, {"pages/p.md": f"{before}{OPEN}\nold text\n\nmore old text\n{CLOSE}{after}"})
    assert run(tmp_path) == 0
    assert capsys.readouterr().out.startswith(f"docgen: wrote pages/p.md: {BLOCK}\n")
    text = (tmp_path / "pages" / "p.md").read_text(encoding="utf-8")
    assert text == f"{before}{OPEN}\n{docgen.render(BLOCK)}\n{CLOSE}{after}"


def test_an_empty_region_is_filled(tmp_path):
    tree(tmp_path, {"p.md": f"{OPEN}\n{CLOSE}\n"})
    assert run(tmp_path) == 0
    assert (tmp_path / "p.md").read_text(encoding="utf-8") == f"{OPEN}\n{docgen.render(BLOCK)}\n{CLOSE}\n"


def test_check_names_each_stale_region_and_writes_nothing(tmp_path, capsys):
    stale = f"# T\n\n{OPEN}\nedited by hand\n{CLOSE}\n"
    tree(
        tmp_path,
        {"a.md": stale, "pages/b.md": f"x\n{OPEN}\n{docgen.render(BLOCK)}\n{CLOSE}\n{OPEN}\n{CLOSE}\n"},
    )
    assert run(tmp_path, "--check") == 1
    out, err = capsys.readouterr()
    assert out.splitlines() == [
        f"a.md:3: {BLOCK}: differs from the code; run `make docgen`, then commit it",
        f"pages/b.md:{docgen.render(BLOCK).count(chr(10)) + 5}: {BLOCK}: differs from the code; run `make docgen`, then"
        " commit it",
    ]
    assert err == "docgen: 2 of 3 generated regions differ from the code\n"
    assert (tmp_path / "a.md").read_text(encoding="utf-8") == stale


def test_a_current_tree_passes_and_a_second_write_changes_nothing(tmp_path, capsys):
    tree(
        tmp_path,
        {"p.md": f"{OPEN}\n{CLOSE}\n<!-- generated:support-table -->\n<!-- /generated:support-table -->\n"},
    )
    assert run(tmp_path) == 0
    written = (tmp_path / "p.md").read_text(encoding="utf-8")
    capsys.readouterr()
    assert run(tmp_path) == 0
    assert capsys.readouterr().out == "docgen: 2 generated regions on 1 page, all as the code has them\n"
    assert (tmp_path / "p.md").read_text(encoding="utf-8") == written
    assert run(tmp_path, "--check") == 0


def test_a_page_without_markers_is_left_alone(tmp_path, capsys):
    text = "# T\n\n<!-- a note: this table is generated by hand, no marker -->\n\n| a |\n|---|\n"
    tree(tmp_path, {"p.md": text, "q.md": f"{OPEN}\nold\n{CLOSE}\n"})
    mtime = os.stat(tmp_path / "p.md").st_mtime_ns
    assert run(tmp_path) == 0
    assert "p.md" not in capsys.readouterr().out.replace("q.md", "")
    assert (tmp_path / "p.md").read_text(encoding="utf-8") == text
    assert os.stat(tmp_path / "p.md").st_mtime_ns == mtime


def test_markers_in_code_are_examples(tmp_path):
    text = (
        f"Write `{OPEN}` above the block and `{CLOSE}` below it.\n\n"
        f"```markdown\n{OPEN}\nanything\n{CLOSE}\n```\n\n~~~\n<!-- generated: not even well formed -->\n~~~\n"
    )
    tree(tmp_path, {"p.md": text})
    assert run(tmp_path, "--check") == 0
    assert docgen.regions("p.md", text) == []


def test_the_folders_a_checkout_ignores_are_not_read(tmp_path):
    stale = f"{OPEN}\nold\n{CLOSE}\n"
    tree(tmp_path, {"build/site-pages/p.md": stale, ".claude/worktrees/x/p.md": stale, "venv/p.md": stale})
    assert docgen.pages(tmp_path) == []
    assert run(tmp_path, "--check") == 0


@pytest.mark.parametrize(
    ("text", "line", "message"),
    [
        (
            f"x\n<!-- generated: {BLOCK} -->\n{CLOSE}\n",
            2,
            "is not a marker docgen can read: a marker stands alone",
        ),
        (f"<!-- Generated:{BLOCK} -->\n{CLOSE}\n", 1, "is not a marker docgen can read"),
        (f"See {OPEN} here.\n{CLOSE}\n", 1, "is not a marker docgen can read"),
        (f"{OPEN}\nthe block\n", 1, f"is never closed: put {CLOSE} on a line of its own"),
        (f"text\n{CLOSE}\n", 2, f"closes no region: nothing above it opens {BLOCK}"),
        (f"{OPEN}\n<!-- /generated:red-lines -->\n", 2, f"is inside the region {BLOCK} opened on line 1"),
        (f"{OPEN}\n{OPEN}\n{CLOSE}\n", 2, f"is inside the region {BLOCK} opened on line 1"),
        (
            "<!-- generated:radios profile=lg-webos -->\n<!-- /generated:radios -->\n",
            1,
            "writes no block named radios",
        ),
        ("<!-- generated:can-check -->\n<!-- /generated:can-check -->\n", 1, "can-check needs profile="),
        (f"<!-- generated:{BLOCK} profile=roku -->\n{CLOSE}\n", 1, f"{BLOCK} takes no profile="),
        (
            "<!-- generated:can-check profile=acme -->\n<!-- /generated:can-check -->\n",
            1,
            "no bundled profile acme",
        ),
        (
            "<!-- generated:can-check profile=roku profile=roku -->\n<!-- /generated:can-check -->\n",
            1,
            "profile= is given twice",
        ),
    ],
)
def test_a_malformed_marker_is_refused_in_plain_words_and_nothing_is_written(
    tmp_path, capsys, text, line, message
):
    stale = f"{OPEN}\nold\n{CLOSE}\n"
    tree(tmp_path, {"a.md": stale, "pages/bad.md": text})
    assert run(tmp_path) == 2
    out, err = capsys.readouterr()
    assert out == ""
    assert err.startswith(f"docgen: pages/bad.md:{line}: ") and message in err, err
    assert err.endswith("; nothing was written\n")
    assert (tmp_path / "a.md").read_text(encoding="utf-8") == stale  # all or nothing
    assert run(tmp_path, "--check") == 2


def test_a_block_that_cannot_be_written_stops_it_with_nothing_written(tmp_path, capsys, monkeypatch):
    monkeypatch.setattr(setup, "PAIRABLE_PROFILES", ("lg-webos", "roku"))
    stale = f"{OPEN}\nold\n{CLOSE}\n"
    tree(
        tmp_path,
        {"a.md": stale, "b.md": "<!-- generated:can-check profile=roku -->\n<!-- /generated:can-check -->\n"},
    )
    assert run(tmp_path) == 2
    assert "add it to READERS and READS; nothing was written" in capsys.readouterr().err
    assert (tmp_path / "a.md").read_text(encoding="utf-8") == stale


def test_the_command_line_writes_a_throwaway_tree_under_python3_I(tmp_path):
    tree(tmp_path, {"p.md": f"{OPEN}\nold\n{CLOSE}\n"})
    env = {k: v for k, v in os.environ.items() if k != "PYTHONPATH"}
    check = [sys.executable, "-I", str(TOOL), "--check", "--root", str(tmp_path)]
    first = subprocess.run(check, capture_output=True, text=True, env=env)
    assert first.returncode == 1 and first.stdout.startswith(f"p.md:1: {BLOCK}: differs from the code")
    write = subprocess.run(check[:3] + check[4:], capture_output=True, text=True, env=env)
    assert write.returncode == 0, write.stderr
    assert subprocess.run(check, capture_output=True, text=True, env=env).returncode == 0
