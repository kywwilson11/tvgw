"""(fin-figures) The documentation figures stay consistent with their shared files, the code and their embeds.

Each docs/diagrams/fig-*.html carries copies of diagram.css, wires.js and the sprites, which build.py
refreshes; a figure edited without a rebuild ships a stale copy. A block between <!-- data:NAME -->
markers is what build.py generates from the code, so a figure cannot drift from the timers it draws.
Every figure has both renders, and every <picture> embed in the Markdown points at renders that exist
and says in its alt text what the figure shows (docs/README.md, A9). A figure for the typical user
names no hardware of the owner's, says Tested only where a generator does, and shows in a terminal
only lines the code prints. Where TVGW_CHROME names a browser, no figure overlaps in either theme.
"""

from __future__ import annotations

import functools
import html
import importlib.util
import os
import re
import shutil
import tempfile
from html.parser import HTMLParser

import pytest
from conftest import ROOT

DIAGRAMS = ROOT / "docs" / "diagrams"
FIGURES = sorted(DIAGRAMS.glob("fig-*.html"), key=lambda p: int(p.name.split("-")[1]))
# the checkout's pages, not the copies .gitignore leaves out: mutmut's mutants/ (which it fills inside the
# checkout, its src/ READMEs linking figures it has no docs/ for) and `make site`'s build/
MARKDOWN = [
    p
    for p in ROOT.rglob("*.md")
    if not any(
        part in {".git", ".claude", "node_modules", ".venv", "mutants", "build"}
        for part in p.relative_to(ROOT).parts
    )
]
PICTURE = re.compile(r"<picture>(.*?)</picture>", re.S)
FENCE = re.compile(r"^```.*?^```", re.S | re.M)  # an example in a code block is not an embed
DATA = re.compile(r"<!-- data:([\w-]+) -->\n(.*?)\n<!-- /data:\1 -->", re.S)
# what names the owner's own hardware; a user figure may name it only inside [data-names-hardware]
OWNER_HARDWARE = re.compile(r"LG CX|OLED|Raspberry Pi|\bPi 5\b")
STYLE = DIAGRAMS / "STYLE.md"
FONT_URL = re.compile(r'url\("fonts/([^"]+)"\)')
# what would make a render or a published page fetch from another site: a CSS import, a remote url(),
# or a <link> or <script> with a remote address
REMOTE = re.compile(
    r"@import|url\(\s*[\"']?(?:https?:)?//|<(?:link|script)\b[^>]*\b(?:href|src)=\"(?:https?:)?//", re.I
)


@functools.cache
def _build():
    spec = importlib.util.spec_from_file_location("diagrams_build", DIAGRAMS / "build.py")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def _markup(fig):
    return re.search(r"<!-- figure -->(.*?)<!-- /figure -->", fig.read_text(encoding="utf-8"), re.S).group(1)


class _Visible(HTMLParser):
    """The text a figure's PNG shows: no caption, and nothing inside an element marked
    data-names-hardware (the source label of a measured set, a figure about one board)."""

    VOID = {"br", "img", "hr", "input", "meta", "link", "use", "path", "rect", "circle", "i"}

    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.depth, self.skip_at, self.text = 0, None, []

    def handle_starttag(self, tag, attrs):
        if tag in self.VOID:
            return
        self.depth += 1
        keys = dict(attrs)
        if self.skip_at is None and (tag == "figcaption" or "data-names-hardware" in keys):
            self.skip_at = self.depth

    def handle_endtag(self, tag):
        if tag in self.VOID:
            return
        if self.skip_at == self.depth:
            self.skip_at = None
        self.depth -= 1

    def handle_data(self, data):
        if self.skip_at is None:
            self.text.append(data)


def visible_text(markup):
    parser = _Visible()
    parser.feed(DATA.sub(" ", markup))
    return re.sub(r"\s+", " ", " ".join(parser.text)).strip()


def audience(fig):
    m = re.search(r'<figure class="fig"[^>]*\sdata-audience="(user|engineer)"', _markup(fig))
    assert m, f"{fig.name}: the <figure> names no data-audience (user or engineer)"
    return m.group(1)


def _div_body(markup, start):
    """The inside of the <div> whose start tag ends at start, up to its own </div>."""
    depth, pos = 1, start
    for tag in re.finditer(r"<(/?)div\b[^>]*>", markup[start:]):
        depth += -1 if tag.group(1) else 1
        if depth == 0:
            return markup[start : start + tag.start()]
        pos = start + tag.end()
    raise ValueError(f"a <div> opened before {pos} is never closed")


def term_asks(markup):
    """(source file, text) for each terminal with data-source: its .ln.ask lines joined by spaces."""
    out = []
    for m in re.finditer(r'<div class="term"[^>]*\sdata-source="([^"]+)"[^>]*>', markup):
        lines = re.findall(r'<div class="ln ask">(.*?)</div>', _div_body(markup, m.end()), re.S)
        out.append((m.group(1), " ".join(html.unescape(re.sub(r"<[^>]+>", "", ln)).strip() for ln in lines)))
    return out


def test_the_figures_are_numbered_without_gaps():
    numbers = [int(p.name.split("-")[1]) for p in FIGURES]
    assert numbers == list(range(1, len(numbers) + 1))


@pytest.mark.parametrize("fig", FIGURES, ids=lambda p: p.stem)
def test_each_figure_carries_the_current_shared_files(fig):
    build = _build()
    html = fig.read_text(encoding="utf-8")
    for name in build.SHARED:
        m = re.search(
            rf"<!-- inline:{re.escape(name)} -->\n(.*?)\n<!-- /inline:{re.escape(name)} -->", html, re.S
        )
        assert m, f"{fig.name}: no inline block for {name}"
        assert m.group(1) == build.shared(name), f"{fig.name}: stale copy of {name}; run build.py"


def test_the_fonts_are_vendored_with_their_licence():
    fonts = FONT_URL.findall((DIAGRAMS / "diagram.css").read_text(encoding="utf-8"))
    assert {"Geist-Variable.woff2", "GeistMono-Variable.woff2"} <= set(fonts)
    for name in fonts:
        assert (DIAGRAMS / "fonts" / name).is_file(), (
            f"diagram.css loads fonts/{name}, which is not committed"
        )
    assert "SIL OPEN FONT LICENSE Version 1.1" in (DIAGRAMS / "fonts" / "OFL.txt").read_text(encoding="utf-8")


SOURCES = [
    *FIGURES,
    *(DIAGRAMS / n for n in ("diagram.css", "wires.js", "icons.svg", "art.svg", "preview.template.html")),
]


@pytest.mark.parametrize("path", SOURCES, ids=lambda p: p.name)
def test_a_figure_loads_nothing_from_another_site(path):
    """A render needs no network, and a published page showing a figure asks no font service for anything."""
    assert not REMOTE.search(path.read_text(encoding="utf-8")), (
        f"{path.name} loads something from another site"
    )


def test_the_remote_load_check_sees_an_import_a_remote_url_and_a_remote_script():
    for text in (
        '@import url("https://fonts.googleapis.com/css2?family=Geist");',
        "src: url(https://fonts.gstatic.com/s/geist.woff2)",
        '<script src="//cdn.example.org/x.js"></script>',
    ):
        assert REMOTE.search(text), text
    assert not REMOTE.search(
        'src: url("fonts/Geist-Variable.woff2"); <svg xmlns="http://www.w3.org/2000/svg">'
    )


@pytest.mark.parametrize("fig", FIGURES, ids=lambda p: p.stem)
def test_each_figure_has_both_renders_and_one_caption(fig):
    for theme in ("light", "dark"):
        assert fig.with_name(f"{fig.stem}.{theme}.png").is_file(), f"{fig.stem}.{theme}.png missing"
    markup = re.search(r"<!-- figure -->(.*?)<!-- /figure -->", fig.read_text(encoding="utf-8"), re.S)
    assert markup and markup.group(1).count("<figcaption") == 1
    assert re.search(r'data-size="960x\d+"', markup.group(1)), "the canvas is 960 px wide"


@pytest.mark.parametrize("fig", FIGURES, ids=lambda p: p.stem)
def test_no_figure_names_a_home_network_address(fig):
    markup = re.search(r"<!-- figure -->(.*?)<!-- /figure -->", fig.read_text(encoding="utf-8"), re.S).group(
        1
    )
    assert not re.search(r"\b192\.168\.\d+\.\d+\b", markup)
    macs = set(re.findall(r"\b(?:[0-9a-f]{2}:){5}[0-9a-f]{2}\b", markup, re.I))
    assert macs <= {"b4:b2:91:aa:bb:cc", "00:00:00:00:00:00"}


def test_every_embed_points_at_renders_that_exist_and_has_alt_text():
    embeds = 0
    for md in MARKDOWN:
        for block in PICTURE.findall(FENCE.sub("", md.read_text(encoding="utf-8"))):
            dark = re.search(r'srcset="([^"]+)"', block).group(1)
            img = re.search(r'<img alt="([^"]*)" src="([^"]+)"', block)
            assert img, f"{md}: an embed without alt text"
            alt, light = img.groups()
            assert len(alt.split()) >= 12, f"{md}: alt text for {light} does not say what the figure shows"
            for src in (dark, light):
                assert (md.parent / src).resolve().is_file(), f"{md}: {src} does not exist"
            assert dark.replace(".dark.png", "") == light.replace(".light.png", "")
            embeds += 1
    assert embeds


@pytest.mark.parametrize("fig", FIGURES, ids=lambda p: p.stem)
def test_every_figure_is_embedded_somewhere(fig):
    used = any(f"{fig.stem}.light.png" in FENCE.sub("", md.read_text(encoding="utf-8")) for md in MARKDOWN)
    assert used, f"{fig.stem} is drawn but no page shows it"


GENERATED = [f for f in FIGURES if DATA.search(f.read_text(encoding="utf-8"))]


@pytest.mark.parametrize("fig", GENERATED, ids=lambda p: p.stem)
def test_generated_blocks_are_current(fig):
    build = _build()
    for name, block in DATA.findall(fig.read_text(encoding="utf-8")):
        assert block == build.generated(name), f"{fig.name}: data:{name} differs from the code; run build.py"


@pytest.mark.parametrize(
    ("keys", "want"),
    [
        ({"OnBootSec": "3min", "OnUnitActiveSec": "10min"}, ("every", 10, "every 10 min")),
        ({"OnCalendar": "*-*-* *:20:00", "Persistent": "true"}, ("hourly", 20, "every hour at :20")),
        ({"OnCalendar": "hourly"}, ("hourly", 0, "every hour")),
        ({"OnCalendar": "*-*-* 03:40:00"}, ("daily", 220, "daily at 03:40")),
        ({"OnCalendar": "Mon *-*-* 04:10:00"}, ("weekly", 250, "Mondays at 04:10")),
        (
            {"OnCalendar": "daily", "RandomizedDelaySec": "1h"},
            ("daily", 0, "daily, at a random time in its first hour"),
        ),
    ],
)
def test_the_timer_generator_reads_the_forms_the_gateway_uses(keys, want):
    assert _build().schedule(keys) == want


@pytest.mark.parametrize(
    "keys",
    [
        {"OnCalendar": "weekly"},
        {"OnCalendar": "*-*-* 03:40:00", "RandomizedDelaySec": "5min"},
        {"OnCalendar": "daily", "RandomizedDelaySec": "2h"},
        {"OnCalendar": "Mon,Thu *-*-* 04:10:00"},
        {"OnUnitActiveSec": "1h 30min"},
    ],
)
def test_the_timer_generator_refuses_a_form_it_cannot_draw(keys):
    with pytest.raises(ValueError):
        _build().schedule(keys)


@pytest.mark.parametrize(("settle", "minute", "want"), [(10800, 20, 200), (10800, 0, 180), (3600, 20, 80)])
def test_the_days_report_is_the_first_hourly_run_after_it_settles(tmp_path, settle, minute, want):
    (tmp_path / "deploy" / "bin").mkdir(parents=True)
    (tmp_path / "deploy" / "bin" / "tvgw-analyze").write_text(
        f"#!/bin/bash\nSETTLE={settle}\n", encoding="utf-8"
    )
    assert _build().day_report_minute(tmp_path, minute) == want


def test_a_timer_the_day_figure_does_not_place_stops_the_build(tmp_path):
    shutil.copytree(ROOT / "deploy" / "systemd", tmp_path / "deploy" / "systemd")
    shutil.copytree(ROOT / "deploy" / "bin", tmp_path / "deploy" / "bin")
    build = _build()
    assert "Writes yesterday's report" in build.gen_timers(tmp_path)
    (tmp_path / "deploy" / "systemd" / "tvgw-new.timer").write_text(
        "[Timer]\nOnCalendar=hourly\n", encoding="utf-8"
    )
    with pytest.raises(ValueError, match=r"tvgw-new\.timer"):
        build.gen_timers(tmp_path)


def test_a_timer_the_day_figure_has_no_room_for_stops_the_build(tmp_path, monkeypatch):
    shutil.copytree(ROOT / "deploy" / "systemd", tmp_path / "deploy" / "systemd")
    shutil.copytree(ROOT / "deploy" / "bin", tmp_path / "deploy" / "bin")
    build = _build()
    (tmp_path / "deploy" / "systemd" / "tvgw-new.timer").write_text(
        "[Timer]\nOnCalendar=*-*-* 05:00:00\n", encoding="utf-8"
    )
    monkeypatch.setitem(build.TIMER_LANES, "tvgw-new", ("Does something new", ""))
    with pytest.raises(ValueError, match="has room for 8 lanes"):
        build.gen_timers(tmp_path)


def test_a_block_without_a_generator_stops_the_build():
    with pytest.raises(ValueError, match="no generator"):
        _build().inline_text("<!-- data:nothing -->\nold\n<!-- /data:nothing -->")


def test_the_overlap_count_is_read_from_the_html_tag_not_from_the_script():
    build = _build()
    script = "<script>/* writes the count to <html data-overlaps> */</script>"
    dom = '<html lang="en" data-overlaps="2" data-overlap-list="card x wire">' + script
    assert build.overlaps_in(dom) == (2, "card x wire")
    assert build.overlaps_in('<html lang="en"><script>/* <html data-overlaps="0"> */</script>') is None


@pytest.mark.parametrize("fig", FIGURES, ids=lambda p: p.stem)
def test_user_figures_name_no_owner_hardware(fig):
    if audience(fig) != "user":
        return
    named = OWNER_HARDWARE.findall(visible_text(_markup(fig)))
    assert not named, f"{fig.name} names {named} outside an element marked data-names-hardware"


def test_hardware_inside_a_marked_element_and_in_the_caption_is_not_visible_text():
    markup = (
        '<figure class="fig" data-audience="user"><div class="stage"><div class="title">The gateway</div>'
        "<span data-names-hardware>LG CX, 24 h<br><b>Raspberry Pi 5</b></span><span>the TV</span></div>"
        "<figcaption>measured on the LG CX</figcaption></figure>"
    )
    assert visible_text(markup) == "The gateway the TV"
    assert OWNER_HARDWARE.search(visible_text(markup.replace(" data-names-hardware", "")))


def test_style_md_gives_each_figure_its_audience():
    rows = {}
    for line in STYLE.read_text(encoding="utf-8").splitlines():
        cells = [c.strip() for c in line.strip().strip("|").split("|")]
        if len(cells) == 4 and cells[0].startswith("`fig-"):
            for stem in re.findall(r"`(fig-[\w-]+)`", cells[0]):
                rows[stem] = cells[2]
    assert sorted(rows) == sorted(f.stem for f in FIGURES), "STYLE.md's figure table lists every figure once"
    for fig in FIGURES:
        assert rows[fig.stem] == audience(fig), (
            f"{fig.name}: STYLE.md and the <figure> differ on the audience"
        )


@pytest.mark.parametrize("fig", FIGURES, ids=lambda p: p.stem)
def test_no_figure_says_tested_unless_a_generator_does(fig):
    """Tested is a status word (a hardware run on a gateway installed as the front page says); only a
    generated block, built from what the code records, may print it."""
    assert not re.search(r"\bTested\b", visible_text(_markup(fig))), f"{fig.name} says Tested by hand"


@pytest.mark.parametrize("fig", FIGURES, ids=lambda p: p.stem)
def test_terminal_lines_come_from_the_code(fig):
    for source, text in term_asks(_markup(fig)):
        assert text in (ROOT / source).read_text(encoding="utf-8"), f"{fig.name}: {text!r} is not in {source}"


def test_a_terminal_line_is_read_whole_across_its_wrapped_lines():
    markup = (
        '<div class="term" style="left:0" data-source="src/tvgw/setup.py"><div class="bar"><i></i></div>'
        '<div class="body"><div class="ln"><span class="p">$</span> <b>sudo tvgw setup</b></div>'
        '<div class="ln ask">Is the TV cabled to the</div><div class="ln ask">gateway&#x27;s TV port?</div>'
        "</div></div>"
    )
    assert term_asks(markup) == [("src/tvgw/setup.py", "Is the TV cabled to the gateway's TV port?")]


@pytest.mark.skipif(not os.environ.get("TVGW_CHROME"), reason="needs a browser: set TVGW_CHROME")
@pytest.mark.parametrize("fig", FIGURES, ids=lambda p: p.stem)
def test_no_figure_overlaps(fig):
    with tempfile.TemporaryDirectory(prefix="tvgw-figures-") as profile:
        assert _build().check(fig, profile) == []


@pytest.mark.skipif(not os.environ.get("TVGW_CHROME"), reason="needs a browser: set TVGW_CHROME")
def test_the_overlap_check_finds_a_card_drawn_over_another(tmp_path):
    """The check above is only worth its green if it can go red: a card placed on the phones card of
    fig-1, and a wire run through it, are both reported."""
    fig = DIAGRAMS / "fig-1-gateway.html"
    planted = fig.read_text(encoding="utf-8").replace(
        "    <!-- Wires -->",
        '    <div class="card" data-id="planted" style="left:96px;top:352px;width:160px">'
        '<div class="body"><div class="title">Planted</div></div></div>\n'
        '    <div class="wire" data-from="@40,376" data-to="@320,376">through it</div>\n'
        "    <!-- Wires -->",
        1,
    )
    path = tmp_path / fig.name
    path.write_text(planted, encoding="utf-8")
    with tempfile.TemporaryDirectory(prefix="tvgw-figures-") as profile:
        problems = _build().check(path, profile)
    assert len(problems) == 2, problems  # once per theme
    for problem in problems:
        assert "card 'Phones and laptops" in problem and "card 'Planted'" in problem
        assert "wire @40,376|@320,376 x card 'Planted'" in problem
