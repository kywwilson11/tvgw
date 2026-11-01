#!/usr/bin/env python3
"""Build the tvgw figures.

    python3 docs/diagrams/build.py            inline the shared files, then render every figure
    python3 docs/diagrams/build.py --inline   only refresh the inlined copies
    python3 docs/diagrams/build.py fig-1-gateway   one figure
    python3 docs/diagrams/build.py --preview OUT.html   also write a page with every figure inline

Each fig-*.html is self-contained: between <!-- inline:NAME --> and <!-- /inline:NAME --> it carries a
copy of diagram.css, wires.js, icons.svg or art.svg. Edit those shared files, never the copies.
The stage's data-size="WxH" sets the render window; PNGs are written at 2x beside the HTML as
NAME.light.png and NAME.dark.png. Embed them in Markdown with <picture> (see STYLE.md).
"""

import pathlib
import re
import subprocess
import sys

HERE = pathlib.Path(__file__).resolve().parent
CHROME = "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome"
SHARED = {"diagram.css": "style", "wires.js": "script", "icons.svg": None, "art.svg": None}


def shared(name):
    text = (HERE / name).read_text(encoding="utf-8")
    tag = SHARED[name]
    return f"<{tag}>\n{text}</{tag}>" if tag else text


def inline(path):
    html = path.read_text(encoding="utf-8")
    for name in SHARED:
        pat = re.compile(rf"(<!-- inline:{re.escape(name)} -->).*?(<!-- /inline:{re.escape(name)} -->)", re.S)
        body = shared(name)
        html = pat.sub(lambda m, body=body: f"{m.group(1)}\n{body}\n{m.group(2)}", html)
    path.write_text(html, encoding="utf-8")
    return html


def render(path):
    html = path.read_text(encoding="utf-8")
    m = re.search(r'data-size="(\d+)x(\d+)"', html)
    w, h = m.groups()
    for theme in ("light", "dark"):
        out = path.with_name(f"{path.stem}.{theme}.png")
        args = [
            CHROME,
            "--headless=new",
            "--disable-gpu",
            "--hide-scrollbars",
            "--force-device-scale-factor=2",
            f"--window-size={w},{h}",
            "--virtual-time-budget=6000",
            f"--screenshot={out}",
        ]
        if theme == "dark":
            args.append("--force-dark-mode")
        args.append(f"file://{path}#render-{theme}")
        subprocess.run(args, check=True, capture_output=True)
        print("wrote", out.relative_to(HERE))


def figure_markup(path):
    html = path.read_text(encoding="utf-8")
    m = re.search(r"<!-- figure -->(.*?)<!-- /figure -->", html, re.S)
    return m.group(1).strip()


def preview(out):
    figs = figures()
    tpl = (HERE / "preview.template.html").read_text(encoding="utf-8")
    parts = []
    for n, f in enumerate(figs, 1):
        fig = figure_markup(f)
        cap = re.search(r"<figcaption[^>]*>(.*?)</figcaption>", fig, re.S).group(1)
        fig = re.sub(r"\s*<figcaption.*?</figcaption>", "", fig, flags=re.S)
        parts.append(
            f'<section class="pv-fig"><p class="pv-eyebrow">Figure {n}</p>'
            f'<div class="pv-scroll">{fig}</div>'
            f'<p class="pv-hint">Scroll the figure sideways to see all of it.</p>'
            f'<p class="fig-caption">{cap}</p></section>'
        )
    body = "\n".join(parts)
    page = tpl.replace("<!-- FIGURES -->", body)
    for name in SHARED:
        page = page.replace(f"<!-- inline:{name} -->", shared(name))
    pathlib.Path(out).write_text(page, encoding="utf-8")
    print("wrote", out)


def figures():
    """Every fig-N-*.html, in figure-number order (fig-10 after fig-9)."""
    return sorted(HERE.glob("fig-*.html"), key=lambda p: int(p.name.split("-")[1]))


def main(argv):
    pv = None
    if "--preview" in argv:
        i = argv.index("--preview")
        pv = argv[i + 1]
        del argv[i : i + 2]
    only_inline = "--inline" in argv
    names = [a for a in argv if not a.startswith("--")]
    figs = [HERE / f"{n}.html" for n in names] if names else figures()
    for f in figs:
        inline(f)
        if not only_inline:
            render(f)
    if pv:
        preview(pv)


if __name__ == "__main__":
    main(sys.argv[1:])
