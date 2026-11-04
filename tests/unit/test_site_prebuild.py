"""The documentation site's build (docs/site/README.md): docs/site/prebuild.py on throwaway trees, the
built-HTML check docs/site/check_site.py on throwaway sites, and mkdocs.yml against the landing page.

The link check (tools/check_docs_links.py) reads this file too, so a repository path a fixture writes
is spelled through DOCS or DEPLOY in an f-string, never literally."""

import importlib.util
import re
import sys

import pytest
import yaml
from conftest import ROOT


def load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


sp = load("site_prebuild", ROOT / "docs" / "site" / "prebuild.py")
cs = load("site_check", ROOT / "docs" / "site" / "check_site.py")

DOCS, DEPLOY = "docs", "deploy"
REPO = "https://github.com/kywwilson11/tvgw"
PICTURE = (
    '<picture>\n  <source media="(prefers-color-scheme: dark)" srcset="diagrams/fig-1.dark.png">\n'
    '  <img alt="A figure." src="diagrams/fig-1.light.png" width="960">\n</picture>\n'
)
BADGES = (
    "<!-- badges:start -->\n"
    "[![latest release](https://img.shields.io/github/v/release/kywwilson11/tvgw)](https://example.org/r)\n"
    "<!-- badges:end -->\n"
)


@pytest.fixture
def repo(tmp_path):
    root = tmp_path / "repo"
    (root / DOCS / "diagrams").mkdir(parents=True)
    (root / DOCS / "site").mkdir()
    (root / DOCS / "use").mkdir()
    (root / DEPLOY).mkdir()
    (root / "README.md").write_text(
        f"# tvgw\n\n{BADGES}\n[setup]({DOCS}/setup.md#before-you-start) [map]({DOCS}/README.md) "
        f"[settings]({DEPLOY}/README.md#the-settings-file) [license](LICENSE) "
        f'<img src="{DOCS}/diagrams/fig-1.light.png">\n',
        encoding="utf-8",
    )
    (root / "LICENSE").write_text("MIT\n", encoding="utf-8")
    (root / DEPLOY / "README.md").write_text("# deploy\n", encoding="utf-8")
    (root / DOCS / "README.md").write_text("# Documentation index\n\n[setup](setup.md)\n", encoding="utf-8")
    (root / DOCS / "setup.md").write_text(
        f"# Setup\n\n[the index](README.md) [front page](../README.md#quick-start) "
        f"[installer](../{DEPLOY}/README.md#what-installsh-does) [style](diagrams/STYLE.md) "
        "[the CSS](diagrams/diagram.css)\n\n"
        + PICTURE
        + f"\n```sh\n[not a link](../{DEPLOY}/README.md)\n```\n",
        encoding="utf-8",
    )
    (root / DOCS / "use" / "README.md").write_text("# Use\n", encoding="utf-8")
    (root / DOCS / "diagrams" / "STYLE.md").write_text("# Style\n", encoding="utf-8")
    (root / DOCS / "diagrams" / "diagram.css").write_text("body{}\n", encoding="utf-8")
    (root / DOCS / "diagrams" / "fig-1.light.png").write_bytes(b"png")
    (root / DOCS / "diagrams" / "fig-1.dark.png").write_bytes(b"png")
    (root / DOCS / "site" / "prebuild.py").write_text("# the script\n", encoding="utf-8")
    return root


def build(repo, *extra):
    out = repo.parent / "out"
    assert sp.main(["--root", str(repo), "--out", str(out), "--repo", REPO, "--ref", "abc123", *extra]) == 0
    return out


def page(repo, name, text):
    (repo / DOCS / name).write_text(text, encoding="utf-8")
    return (build(repo) / name).read_text(encoding="utf-8")


# ---- prebuild.py ---------------------------------------------------------------------------------


def test_the_front_page_is_the_home_page_and_its_links_are_rewritten(repo):
    home = (build(repo) / "index.md").read_text(encoding="utf-8")
    assert "[setup](setup.md#before-you-start)" in home
    assert "[map](map.md)" in home
    assert f"[settings]({REPO}/blob/abc123/{DEPLOY}/README.md#the-settings-file)" in home
    assert f"[license]({REPO}/blob/abc123/LICENSE)" in home
    assert 'src="diagrams/fig-1.light.png"' in home


def test_the_badge_row_is_dropped_from_the_site_and_nothing_else(repo):
    home = (build(repo) / "index.md").read_text(encoding="utf-8")
    assert "badges:" not in home and "shields.io" not in home
    assert home.startswith("# tvgw\n\n\n[setup]")
    # on GitHub the front page keeps its badges
    assert BADGES in (repo / "README.md").read_text(encoding="utf-8")


def test_with_a_release_one_line_naming_it_takes_the_badge_rows_place(repo):
    (repo / "CHANGELOG.md").write_text(
        "# Changelog\n\n## Unreleased\n\n## 0.3.0 (2026-11-04)\n\n### Highlights\n", encoding="utf-8"
    )
    home = (build(repo, "--release", "v0.3.0") / "index.md").read_text(encoding="utf-8")
    line = (
        f"**Latest release:** [tvgw 0.3.0]({REPO}/releases/tag/v0.3.0), 2026-11-04. "
        "Every command on these pages is in it.\n"
    )
    assert home.startswith(f"# tvgw\n\n{line}\n[setup]")
    assert "badges:" not in home and "shields.io" not in home
    # only the page with a badge row carries it
    assert "Latest release" not in (repo.parent / "out" / "setup.md").read_text(encoding="utf-8")


@pytest.mark.parametrize("changelog", ["## 0.3.0 (2026-11-04)\n", None])
def test_a_release_the_checkouts_changelog_does_not_date_is_named_without_a_date(repo, changelog):
    """A release cut from another branch has no section on main yet; the site still names it."""
    if changelog is not None:
        (repo / "CHANGELOG.md").write_text(f"# Changelog\n\n{changelog}", encoding="utf-8")
    home = (build(repo, "--release", "v0.3.1") / "index.md").read_text(encoding="utf-8")
    assert f"**Latest release:** [tvgw 0.3.1]({REPO}/releases/tag/v0.3.1). Every command" in home


@pytest.mark.parametrize(
    "tag", ["main", "v0.3", "v0.3.0)[x](https://example.org", "v0.3.0\n", "v0.3.0\n# Title"]
)
def test_a_release_that_is_not_a_tag_stops_the_build(repo, tag):
    with pytest.raises(SystemExit, match="is not a release tag"):
        build(repo, "--release", tag)


def test_markers_named_in_prose_or_code_are_text_not_a_badge_row(repo):
    text = (
        "# Conventions\n\nWrap the row in `<!-- badges:start -->` and `<!-- badges:end -->`.\n\n"
        "```text\n<!-- badges:start -->\nkept\n<!-- badges:end -->\n```\n"
    )
    assert page(repo, "conventions.md", text) == text


def test_a_badge_row_that_is_never_closed_stops_the_build(repo):
    (repo / "README.md").write_text("# tvgw\n\n<!-- badges:start -->\n[![x](y.svg)](z)\n", encoding="utf-8")
    with pytest.raises(SystemExit, match="badges:end"):
        build(repo)


def test_the_docs_index_becomes_map_and_links_to_it_follow(repo):
    out = build(repo)
    assert (out / "map.md").exists() and not (out / "README.md").exists()
    text = (out / "setup.md").read_text(encoding="utf-8")
    assert "[the index](map.md)" in text
    assert "[front page](index.md#quick-start)" in text


def test_links_that_leave_docs_go_to_github_at_the_ref(repo):
    text = (build(repo) / "setup.md").read_text(encoding="utf-8")
    assert f"[installer]({REPO}/blob/abc123/{DEPLOY}/README.md#what-installsh-does)" in text
    # a file the site does not serve (a figure's CSS) is linked on GitHub, not copied
    assert f"[the CSS]({REPO}/blob/abc123/{DOCS}/diagrams/diagram.css)" in text
    assert "[style](diagrams/STYLE.md)" in text


def test_a_folder_link_goes_to_its_readme_on_the_site_or_to_the_tree_on_github(repo):
    text = page(repo, "folders.md", f"[use](use/) [use too](use) [deploy](../{DEPLOY}/)\n")
    assert "[use](use/README.md) [use too](use/README.md)" in text
    assert f"[deploy]({REPO}/tree/abc123/{DEPLOY})" in text


def test_reference_definitions_and_root_links_are_rewritten(repo):
    text = page(repo, "refs.md", f"[a][inst] [b](/{DEPLOY}/README.md)\n\n[inst]: ../{DEPLOY}/README.md#x\n")
    assert f"[inst]: {REPO}/blob/abc123/{DEPLOY}/README.md#x" in text
    assert f"[b]({REPO}/blob/abc123/{DEPLOY}/README.md)" in text


def test_a_link_to_nothing_is_left_for_the_strict_build_to_name(repo):
    text = f"[gone](gone.md) [gone too](../{DEPLOY}/gone.md)\n"
    assert page(repo, "broken.md", text) == text


def test_fenced_code_is_never_rewritten(repo):
    text = (build(repo) / "setup.md").read_text(encoding="utf-8")
    assert f"[not a link](../{DEPLOY}/README.md)" in text


def test_code_spans_and_indented_fences_are_never_rewritten(repo):
    text = (
        f"# Code\n\nWrite `[x](../{DEPLOY}/README.md)` like this.\n\n"
        f"1. A step:\n\n   ```sh\n   [y](../{DEPLOY}/README.md)\n   ```\n\n"
        f"~~~~\n[z](../{DEPLOY}/README.md)\n~~~\nstill code\n~~~~\n"
        f"[after](../{DEPLOY}/README.md)\n"
    )
    out = page(repo, "code.md", text)
    assert out.count(f"(../{DEPLOY}/README.md)") == 3
    assert f"[after]({REPO}/blob/abc123/{DEPLOY}/README.md)" in out


def test_every_srcset_candidate_is_rewritten(repo):
    text = page(repo, "set.md", f'<img srcset="../{DEPLOY}/a.png 1x, diagrams/fig-1.dark.png 2x">\n')
    assert f'srcset="../{DEPLOY}/a.png 1x, diagrams/fig-1.dark.png 2x"' in text  # a.png does not exist
    (repo / DEPLOY / "a.png").write_bytes(b"png")
    text = page(repo, "set.md", f'<img srcset="../{DEPLOY}/a.png 1x, diagrams/fig-1.dark.png 2x">\n')
    assert f'srcset="{REPO}/blob/abc123/{DEPLOY}/a.png 1x, diagrams/fig-1.dark.png 2x"' in text


def test_the_site_folder_and_unserved_files_stay_out(repo):
    out = build(repo)
    assert not (out / "site").exists()
    assert not (out / "diagrams" / "diagram.css").exists()
    assert (out / "diagrams" / "fig-1.dark.png").exists()


def test_pictures_stay_pictures_without_the_toggle(repo):
    text = (build(repo) / "setup.md").read_text(encoding="utf-8")
    assert "<picture>" in text and "#only-light" not in text


def test_the_toggle_rewrites_each_picture_into_the_theme_pair(repo):
    text = (build(repo, "--picture-toggle") / "setup.md").read_text(encoding="utf-8")
    assert "<picture>" not in text
    assert 'src="diagrams/fig-1.light.png#only-light"' in text
    assert 'src="diagrams/fig-1.dark.png#only-dark"' in text


def test_a_link_out_of_the_repository_is_refused(repo):
    (repo / DOCS / "bad.md").write_text("[x](../../outside.md)\n", encoding="utf-8")
    with pytest.raises(SystemExit, match="leaves the repository"):
        build(repo)


@pytest.mark.parametrize("where", ["repo", "docs", "parent"])
def test_an_output_folder_that_would_overwrite_the_pages_is_refused(repo, where):
    out = {"repo": repo, "docs": repo / DOCS / "x", "parent": repo.parent}[where]
    with pytest.raises(SystemExit, match="would overwrite"):
        sp.main(["--root", str(repo), "--out", str(out), "--repo", REPO])
    assert (repo / "README.md").exists()


def test_the_real_tree_prebuilds_with_every_user_page_and_no_badge_marker(tmp_path):
    out = tmp_path / "site-docs"
    changelog = (ROOT / "CHANGELOG.md").read_text(encoding="utf-8")
    newest = re.search(r"^## (\d+\.\d+\.\d+) \(", changelog, re.M).group(1)
    assert sp.main(["--out", str(out), "--repo", REPO, "--ref", "abc123", "--release", f"v{newest}"]) == 0
    assert (out / "index.md").exists() and (out / "map.md").exists()
    home = (out / "index.md").read_text(encoding="utf-8")
    assert f"**Latest release:** [tvgw {newest}]({REPO}/releases/tag/v{newest})" in home
    for md in out.rglob("*.md"):
        assert "badges:start" not in md.read_text(encoding="utf-8"), md
    assert not (out / "site").exists()


# ---- check_site.py -----------------------------------------------------------------------------------


@pytest.fixture
def site(tmp_path):
    root = tmp_path / "site"
    (root / "how-it-works").mkdir(parents=True)
    (root / "diagrams").mkdir()
    (root / "assets").mkdir()
    (root / "diagrams" / "fig-1.light.png").write_bytes(b"png")
    (root / "diagrams" / "fig-1.dark.png").write_bytes(b"png")
    (root / "assets" / "main.css").write_text("body{font-family:system-ui}\n", encoding="utf-8")
    (root / "index.html").write_text(
        '<link rel="stylesheet" href="assets/main.css"><link rel="canonical" href="https://x.example/tvgw/">'
        '<a href="how-it-works/index.html">how</a><a href="https://github.com/kywwilson11/tvgw">gh</a>',
        encoding="utf-8",
    )
    (root / "how-it-works" / "index.html").write_text(
        '<picture><source media="(prefers-color-scheme: dark)" srcset="../diagrams/fig-1.dark.png">'
        '<img alt="x" src="../diagrams/fig-1.light.png"></picture><a href="/tvgw/index.html#top">home</a>'
        "<p><code>src='tvcheck'</code> and <code>fonts.googleapis.com</code> are text</p>",
        encoding="utf-8",
    )
    return root


def test_a_clean_site_passes(site):
    pages, checked, found = cs.problems(site, "/tvgw/")
    assert (pages, found) == (2, []) and checked == 5
    assert cs.main([str(site)]) == 0


@pytest.mark.parametrize(
    ("html", "problem"),
    [
        ('<img src="../diagrams/fig-9.light.png">', "fig-9.light.png does not resolve"),
        (
            '<source srcset="../diagrams/fig-1.dark.png 1x, ../diagrams/gone.png 2x">',
            "gone.png does not resolve",
        ),
        ('<a href="/elsewhere/x.html">x</a>', "outside the site's prefix"),
        ('<img src="https://img.shields.io/badge/x">', "loads from another site"),
        ('<script src="//cdn.example/x.js"></script>', "loads from another site"),
        ('<link rel="stylesheet" href="https://fonts.googleapis.com/css?family=Inter">', "from another site"),
        ('<link rel="preconnect" href="https://fonts.gstatic.com">', "from another site"),
    ],
)
def test_a_broken_reference_or_a_request_to_another_site_fails(site, html, problem):
    (site / "how-it-works" / "bad.html").write_text(html, encoding="utf-8")
    _, _, found = cs.problems(site, "/tvgw/")
    assert any(problem in line and "how-it-works/bad.html" in line for line in found), found
    assert cs.main([str(site)]) == 1


def test_a_stylesheet_that_fetches_from_another_site_fails(site):
    (site / "assets" / "main.css").write_text(
        '@import url("https://fonts.googleapis.com/x");\n', encoding="utf-8"
    )
    assert any("assets/main.css" in line for line in cs.problems(site, "/tvgw/")[2])


def test_an_empty_site_fails(tmp_path):
    (tmp_path / "empty").mkdir()
    assert cs.main([str(tmp_path / "empty")]) == 1


# ---- mkdocs.yml and the landing page ------------------------------------------------------------------


class _Loader(yaml.SafeLoader):
    """mkdocs.yml names a Python function for the slugs; read the tag as data, call nothing."""


_Loader.add_multi_constructor(
    "tag:yaml.org,2002:python/",
    lambda loader, suffix, node: {suffix: loader.construct_mapping(node, deep=True)},
)
MKDOCS = yaml.load((ROOT / "mkdocs.yml").read_text(encoding="utf-8"), Loader=_Loader)
LANDING = (ROOT / DOCS / "README.md").read_text(encoding="utf-8")


def nav_pages(entries):
    for entry in entries:
        for value in entry.values():
            if isinstance(value, list):
                yield from nav_pages(value)
            else:
                yield value


def test_the_tabs_are_the_landing_pages_seven_sections_in_its_order():
    sections = re.findall(r"^## (.+)$", LANDING, re.M)
    tabs = [next(iter(entry)) for entry in MKDOCS["nav"]]
    assert tabs == [
        "Start here",
        "Install",
        "Everyday use",
        "Your TV",
        "How it works",
        "Reference",
        "Project",
    ]
    assert sections[: len(tabs)] == tabs


def test_every_page_the_landing_page_links_is_in_the_nav():
    """A page added to the landing page goes into the nav in the same change. A link that leaves docs/ is
    a link to the file on main on GitHub."""
    nav = set(nav_pages(MKDOCS["nav"]))
    body = LANDING.split("## Reading paths", 1)[0]
    for target in re.findall(r"\]\(([^)#]+)(?:#[^)]*)?\)", body):
        if target.startswith("../"):
            assert f"{REPO}/blob/main/{target[3:]}" in nav, target
        else:
            assert target in nav, target


def test_every_user_page_and_every_nav_entry_is_a_page_the_prebuild_writes():
    nav = set(nav_pages(MKDOCS["nav"]))
    user = {"README.md", f"{DOCS}/README.md", f"{DOCS}/what-it-stops.md"}
    for folder in ("install", "use", "tv"):
        user |= {p.relative_to(ROOT).as_posix() for p in (ROOT / DOCS / folder).glob("*.md")}
    site_names = {"README.md": "index.md", f"{DOCS}/README.md": "map.md"}
    for rel in user:
        assert site_names.get(rel, rel.removeprefix(f"{DOCS}/")) in nav, rel
    for entry in nav:
        if entry.startswith("https://"):
            assert entry.startswith(f"{REPO}/blob/main/") and (ROOT / entry.split("/blob/main/")[1]).exists()
        elif entry not in ("index.md", "map.md"):
            assert (ROOT / DOCS / entry).is_file(), entry


def test_the_keys_the_site_depends_on_stay():
    assert MKDOCS["docs_dir"] == "build/site-docs" and MKDOCS["site_dir"] == "build/site"
    assert MKDOCS["use_directory_urls"] is False  # the figures' paths are relative to the page
    assert MKDOCS["strict"] is True
    assert MKDOCS["theme"]["font"] is False  # no Google Fonts
    assert MKDOCS["site_url"] == "https://kywwilson11.github.io/tvgw/"
    assert "analytics" not in MKDOCS.get("extra", {})
    assert "content.code.copy" in MKDOCS["theme"]["features"]
    toc = next(e["toc"] for e in MKDOCS["markdown_extensions"] if isinstance(e, dict) and "toc" in e)
    assert toc["slugify"] == {"object/apply:pymdownx.slugs.slugify": {"kwds": {"case": "lower"}}}  # GitHub's
    assert MKDOCS["plugins"] == ["search"]


def test_the_generator_is_pinned_and_locked_with_hashes():
    pin = (ROOT / DOCS / "site" / "requirements.in").read_text(encoding="utf-8")
    lock = (ROOT / DOCS / "site" / "requirements.lock").read_text(encoding="utf-8")
    (version,) = re.findall(r"^zensical==(\S+)$", pin, re.M)
    assert f"\nzensical=={version} \\\n" in lock
    blocks = re.findall(
        r"^([a-z0-9._-]+)==(\S+) \\\n((?:\s+--hash=sha256:[0-9a-f]{64}(?: \\)?\n)+)", lock, re.M
    )
    assert blocks and len(blocks) == len(re.findall(r"^[a-z0-9._-]+==", lock, re.M))
    make = (ROOT / "Makefile").read_text(encoding="utf-8")
    assert "-o docs/site/requirements.lock" in make
    assert "--require-hashes --no-deps -r docs/site/requirements.lock" in make
