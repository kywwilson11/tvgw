"""(fin-figures) The documentation figures stay consistent with their shared files and their embeds.

Each docs/diagrams/fig-*.html carries copies of diagram.css, wires.js and the sprites, which build.py
refreshes; a figure edited without a rebuild ships a stale copy. Every figure has both renders, and
every <picture> embed in the Markdown points at renders that exist and says in its alt text what the
figure shows (docs/README.md, A9).
"""

from __future__ import annotations

import importlib.util
import pathlib
import re

import pytest

ROOT = pathlib.Path(__file__).resolve().parents[2]
DIAGRAMS = ROOT / "docs" / "diagrams"
FIGURES = sorted(DIAGRAMS.glob("fig-*.html"), key=lambda p: int(p.name.split("-")[1]))
MARKDOWN = [
    p
    for p in ROOT.rglob("*.md")
    if not any(part in {".git", ".claude", "node_modules", ".venv"} for part in p.relative_to(ROOT).parts)
]
PICTURE = re.compile(r"<picture>(.*?)</picture>", re.S)
FENCE = re.compile(r"^```.*?^```", re.S | re.M)  # an example in a code block is not an embed


def _build():
    spec = importlib.util.spec_from_file_location("diagrams_build", DIAGRAMS / "build.py")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


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
