"""A release's notes (packaging/release_notes.py, .github/release-notes.md.in) and the changelog convention
they read: a version's section starts with `### Highlights` and `### Status` (docs/packaging.md#the-changelogs-highlights-and-status).

release.yml runs the script before anything is built and again before the release is created, so every
refusal here is a release that never exists half-made. The last tests hold the real CHANGELOG.md and the
real template to the convention."""

import importlib.util
import re
import subprocess
import sys

import pytest
from conftest import ROOT

PKG = ROOT / "packaging"
TEMPLATE_PATH = ROOT / ".github" / "release-notes.md.in"
TEMPLATE = TEMPLATE_PATH.read_text(encoding="utf-8")
CHANGELOG = (ROOT / "CHANGELOG.md").read_text(encoding="utf-8")


def load():
    spec = importlib.util.spec_from_file_location("release_notes", PKG / "release_notes.py")
    mod = importlib.util.module_from_spec(spec)
    sys.modules["release_notes"] = mod
    spec.loader.exec_module(mod)
    return mod


rn = load()

SUMS = (
    "1111111111111111111111111111111111111111111111111111111111111111  tvgw_0.3.0-1_arm64.deb\n"
    "2222222222222222222222222222222222222222222222222222222222222222  tvgw_0.3.0-1_amd64.deb\n"
    "3333333333333333333333333333333333333333333333333333333333333333  get.sh\n"
)
HIGHLIGHTS = (
    "- Install with one command on a Raspberry Pi or a mini PC; setup tells you when to plug in the TV.\n"
    "- The daily brief opens with five plain lines and one thing to do, if anything.\n"
    "- Samsung TVs: blocking from published lists, with a page that says what to switch off on the TV.\n"
)
STATUS = (
    "Tested on one LG CX (webOS 5) behind a Raspberry Pi 5. Not yet tested on hardware: Samsung, Roku\n"
    "and Vizio TVs, mini PCs.\n"
)
GOOD = f"""# Changelog

## Unreleased

## 0.3.0 (2026-11-20)

### Highlights

{HIGHLIGHTS}
### Status

{STATUS}
### Packaging: an amd64 package (2026-11-15)

- `release.yml` builds `TVGW_ARCH=amd64` too.

## 0.2.0 (2026-11-01)

**Highlights.** Written before the convention, as a paragraph.

### Figures (2026-11-01)

- old entry
"""


def render(changelog=GOOD, version="0.3.0", template=TEMPLATE, sums=SUMS):
    return rn.render(template, version, changelog, sums)


def test_the_notes_carry_the_highlights_status_install_command_and_sums():
    out = render()
    assert out.startswith("**tvgw 0.3.0**, released 2026-11-20.")
    assert "- Install with one command" in out and "- Samsung TVs" in out
    # the status reads as one paragraph, whatever its line breaks in the changelog
    assert "Not yet tested on hardware: Samsung, Roku and Vizio TVs, mini PCs." in out
    assert "releases/download/v0.3.0/get.sh | sudo sh" in out
    assert "tvgw_0.3.0-1_amd64.deb" in out and "tvgw_0.3.0-1_arm64.deb" in out
    assert "```text\n" + SUMS.strip() + "\n```" in out
    assert "CHANGELOG.md#030-2026-11-20" in out  # GitHub's anchor for "## 0.3.0 (2026-11-20)"
    assert "gh attestation verify tvgw_0.3.0-1_arm64.deb -R kywwilson11/tvgw" in out
    assert "gh release verify-asset v0.3.0 tvgw_0.3.0-1_arm64.deb -R kywwilson11/tvgw" in out
    assert not re.search(r"@[A-Z]+@", out)
    assert "release.yml builds" not in out  # the engineering detail stays in the changelog
    assert "\n\n\n" not in out and out.endswith("\n") and not out.endswith("\n\n")


def test_the_status_comes_before_the_install_command():
    out = render()
    assert out.index("## Status") < out.index("## Install")


def test_the_early_check_needs_no_sums():
    out = render(sums="")
    assert "```text" not in out
    assert "## Check a download yourself" in out


def test_with_six_highlights_and_the_sums_the_notes_fit_on_one_screen():
    six = "".join(
        f"- Plain change number {i}, said in a short sentence a reader can act on.\n" for i in range(6)
    )
    out = render(GOOD.replace(HIGHLIGHTS, six))
    assert len(out.splitlines()) <= rn.MAX_LINES


def test_notes_longer_than_one_screen_are_refused():
    with pytest.raises(rn.NotesError, match=r"run to \d+ lines"):
        render(template=TEMPLATE + "\nmore\n" * rn.MAX_LINES)


def test_a_version_without_a_section_is_refused():
    with pytest.raises(rn.NotesError, match=r"no '## 9\.9\.9 \(YYYY-MM-DD\)' section"):
        render(version="9.9.9")


def test_a_section_written_before_the_convention_is_refused():
    with pytest.raises(rn.NotesError, match="text before '### Highlights'"):
        render(version="0.2.0")


def test_highlights_and_status_must_open_the_section_in_that_order():
    swapped = GOOD.replace(
        f"### Highlights\n\n{HIGHLIGHTS}\n### Status\n\n{STATUS}",
        f"### Status\n\n{STATUS}\n### Highlights\n\n{HIGHLIGHTS}",
    )
    with pytest.raises(
        rn.NotesError, match="starts with '### Highlights', then '### Status'; found Status, Highlights"
    ):
        render(swapped)
    no_status = GOOD.replace(f"### Status\n\n{STATUS}", "")
    with pytest.raises(rn.NotesError, match="found Highlights, Packaging"):
        render(no_status)


@pytest.mark.parametrize("n", [2, 7])
def test_too_few_or_too_many_highlights_are_refused(n):
    bullets = "".join(f"- Plain change number {i}.\n" for i in range(n))
    with pytest.raises(rn.NotesError, match=f"Highlights has {n} bullets; write 3 to 6"):
        render(GOOD.replace(HIGHLIGHTS, bullets))


def test_a_long_highlight_is_refused():
    long = HIGHLIGHTS.replace("if anything.", "if anything" + ", and more" * 30 + ".")
    with pytest.raises(rn.NotesError, match="over 220 characters"):
        render(GOOD.replace(HIGHLIGHTS, long))


def test_a_highlight_wrapped_onto_a_second_line_is_refused():
    wrapped = HIGHLIGHTS.replace("five plain lines and", "five plain lines and\n  ")
    with pytest.raises(rn.NotesError, match="bullets only, one line each"):
        render(GOOD.replace(HIGHLIGHTS, wrapped))


@pytest.mark.parametrize(
    ("words", "named"),
    [
        ("conntrack events now feed the brief", "conntrack"),
        ("the nftables guard is reloaded", "nftables"),
        ("set TV_IF to your port", "TV_IF"),
        ("ANALYST_APPLY=auto blocks on its own", "ANALYST_APPLY"),
        ("design decision 20 is amended", "design decision 20"),
        ("nginx filters LG's file service", "nginx"),
        ("works behind WireGuard", "WireGuard"),
        ("the store keeps a year", "the store"),
        ("a new canary watches each rule", "canary"),
        ("the must-allow hosts stay open", "must-allow"),
    ],
)
def test_a_highlight_in_an_engineers_words_is_refused(words, named):
    text = GOOD.replace("The daily brief opens with five plain lines", f"Now {words}, and the brief opens")
    with pytest.raises(rn.NotesError, match=f"uses {named!r}"):
        render(text)


@pytest.mark.parametrize("words", ["A Raspberry Pi 5 or a mini PC", "Samsung, Roku and Vizio", "Wi-Fi off"])
def test_plain_words_pass(words):
    assert rn.plain_word(words) is None


def test_a_status_that_is_missing_empty_two_paragraphs_or_a_list_is_refused():
    with pytest.raises(rn.NotesError, match="Status' block is empty"):
        render(GOOD.replace(STATUS, ""))
    with pytest.raises(rn.NotesError, match="Status is one paragraph"):
        render(GOOD.replace(STATUS, "Tested on one LG CX.\n\nNot on Samsung.\n"))
    with pytest.raises(rn.NotesError, match="Status is one paragraph"):
        render(GOOD.replace(STATUS, "Tested on:\n- one LG CX\n"))


def test_the_template_fills_every_field_and_refuses_one_it_does_not_know():
    assert set(rn.FIELD.findall(TEMPLATE)) == {"VERSION", "DATE", "ANCHOR", "HIGHLIGHTS", "STATUS", "SUMS"}
    with pytest.raises(rn.NotesError, match=r"fields this script does not fill: \['MIRROR'\]"):
        render(template=TEMPLATE + "@MIRROR@\n")


def test_text_from_the_changelog_is_never_read_as_a_field():
    text = GOOD.replace("Not yet tested on hardware", "Not yet tested on @DATE@ hardware")
    assert "Not yet tested on @DATE@ hardware" in render(text)


def test_github_anchors_drop_punctuation_and_keep_hyphens():
    assert rn.anchor("## 0.3.0 (2026-11-20)") == "030-2026-11-20"
    assert rn.anchor("## The changelog's Highlights and Status") == "the-changelogs-highlights-and-status"


def run_cli(tmp_path, *args):
    (tmp_path / "CHANGELOG.md").write_text(GOOD, encoding="utf-8")
    (tmp_path / "SHA256SUMS").write_text(SUMS, encoding="utf-8")
    return subprocess.run(
        [
            sys.executable,
            "-I",
            str(PKG / "release_notes.py"),
            "--changelog",
            str(tmp_path / "CHANGELOG.md"),
            "--template",
            str(TEMPLATE_PATH),
            *args,
        ],
        capture_output=True,
        text=True,
        encoding="utf-8",
    )


def test_the_command_line_writes_the_notes(tmp_path):
    out_file = tmp_path / "RELEASE_NOTES.md"
    out = run_cli(
        tmp_path, "--version", "0.3.0", "--sums", str(tmp_path / "SHA256SUMS"), "--out", str(out_file)
    )
    assert out.returncode == 0, out.stderr
    assert out_file.read_text(encoding="utf-8").startswith("**tvgw 0.3.0**")
    assert re.search(r"release notes: .*RELEASE_NOTES\.md \(\d+ lines\)", out.stderr)


def test_the_command_line_checks_without_writing_and_refuses_with_the_reason(tmp_path):
    out = run_cli(tmp_path, "--version", "0.3.0")
    assert out.returncode == 0 and "release notes: checked" in out.stderr
    assert not (tmp_path / "RELEASE_NOTES.md").exists()
    out = run_cli(tmp_path, "--version", "0.2.0")
    assert out.returncode == 1
    assert out.stderr.startswith("release notes: the version's section has text before '### Highlights'")
    assert "Traceback" not in out.stderr


# ---- the real changelog and template -------------------------------------------------------------


def versions(changelog: str) -> list[str]:
    return re.findall(r"^## (\d+(?:\.\d+)*) \(\d{4}-\d{2}-\d{2}\)", changelog, re.M)


BEFORE_THE_CONVENTION = {"0.1.0", "0.2.0"}  # released before release.yml read Highlights and Status


def test_every_version_released_since_the_convention_has_its_notes():
    """Vacuous until the first release after 0.2.0; from then on, a section the release job would refuse
    fails here first."""
    for version in versions(CHANGELOG):
        if version not in BEFORE_THE_CONVENTION:
            render(CHANGELOG, version, sums="")


def test_the_versions_before_the_convention_are_left_as_they_were_written():
    assert {"0.2.0"} <= set(versions(CHANGELOG))
    with pytest.raises(rn.NotesError, match="Highlights"):
        render(CHANGELOG, "0.2.0", sums="")


def unreleased_problem(changelog: str) -> str | None:
    """Why the changelog's Unreleased section breaks the convention, or None. Its two blocks are kept
    current as changes land, so cutting a release is trimming them: their place, each bullet's length
    and words, and the status's shape are checked now; the count of three to six and a status that is
    not empty, at the release. Both are empty right after a cut, as docs/packaging.md#cutting-a-release
    leaves them."""
    body = re.search(r"^## Unreleased\n(.*?)(?=^## )", changelog, re.M | re.S).group(1)
    where = (
        "a change's own bullets go in a dated '### <topic> (<YYYY-MM-DD>)' subsection after Status, "
        "never directly under '## Unreleased' or under Status"
    )
    try:
        subs = rn.subsections(body)
        if [title for title, _ in subs[:2]] != ["Highlights", "Status"]:
            return f"Unreleased opens with {[title for title, _ in subs[:2]]}, not Highlights then Status; {where}"
        rn.bullets(subs[0][1])
        if subs[1][1]:
            rn.status(subs[1][1])
    except rn.NotesError as e:
        return f"{e}; {where}"
    return None


def test_unreleased_opens_with_highlights_then_status_in_plain_words():
    assert unreleased_problem(CHANGELOG) is None


@pytest.mark.parametrize(
    ("unreleased", "problem"),
    [
        ("### Highlights\n\n### Status\n\n", None),  # right after a release is cut
        (
            f"### Highlights\n\n{HIGHLIGHTS}\n### Status\n\n{STATUS}\n### Docs (2026-11-21)\n\n- a page\n",
            None,
        ),
        (f"- a change\n\n### Highlights\n\n{HIGHLIGHTS}\n### Status\n\n{STATUS}", "text before"),
        (f"### Highlights\n\n{HIGHLIGHTS}\n### Status\n\n{STATUS}\n- a change\n", "one paragraph"),
        (f"### Docs (2026-11-21)\n\n- a page\n\n### Highlights\n\n{HIGHLIGHTS}", "not Highlights then"),
        ("### Highlights\n\n- set TV_IF first\n\n### Status\n\n", "uses 'TV_IF'"),
    ],
)
def test_the_unreleased_check_takes_an_empty_cut_and_refuses_a_misplaced_bullet(unreleased, problem):
    found = unreleased_problem(f"# Changelog\n\n## Unreleased\n\n{unreleased}\n## 0.2.0 (2026-11-01)\n")
    if problem is None:
        assert found is None
    else:
        assert problem in found and "dated '### <topic> (<YYYY-MM-DD>)' subsection after Status" in found


def test_every_page_the_template_links_at_the_tag_exists_with_its_heading():
    """The template is not Markdown the link check reads, so its links into the repository are checked
    here, against the tree the tag is cut from."""
    links = re.findall(
        r"https://github\.com/kywwilson11/tvgw/blob/v@VERSION@/([^)#\s]+)(?:#([^)\s]+))?", TEMPLATE
    )
    assert links
    for path, frag in links:
        target = ROOT / path
        assert target.is_file(), path
        if frag and not rn.FIELD.fullmatch(frag):
            headings = re.findall(r"^#{1,6} +(.+?) *$", target.read_text(encoding="utf-8"), re.M)
            assert frag in {rn.anchor(h) for h in headings}, f"{path}#{frag}"


def test_the_template_and_the_installer_name_the_same_supported_systems():
    systems = "Raspberry Pi OS (64-bit), Debian 12 or 13, and Ubuntu 24.04 or 26.04"
    assert systems in TEMPLATE
    assert systems in (PKG / "get.sh.in").read_text(encoding="utf-8")
