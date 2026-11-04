#!/usr/bin/env python3
"""Copy the front page and docs/ into the documentation site's source tree, without changing a page.

The Markdown in the repository is the one source, read on GitHub as it is. The site is built from a
copy (docs/site/README.md), which this script writes:

- README.md at the root becomes the home page, index.md, so GitHub and the site open on one page;
- docs/README.md, the landing page, becomes map.md, since a folder cannot hold both README.md and
  index.md as its landing page, and every link to it follows;
- a link that leaves docs/ (deploy/, src/, tests/, the root's community files), or names a file the site
  does not serve (a figure's HTML source, its CSS), goes to the file on GitHub at the commit built,
  `<repo>/blob/<ref>/<path>` (`tree` for a folder), keeping the fragment;
- the badge row between `<!-- badges:start -->` and `<!-- badges:end -->`, each on a line of its own,
  is dropped, so the site makes no request to the badge service;
- with --picture-toggle, each figure's <picture> becomes the #only-light / #only-dark image pair the
  theme switches with its palette toggle; without it the site follows the reader's system setting, as
  GitHub does.

Fenced code and code spans are examples, never rewritten. A link that leaves the repository stops the
build; a link to a file that does not exist is left as it is, for the strict build to name. docs/site/
holds this script and its lock, not pages, and is not copied.

    python3 docs/site/prebuild.py --out build/site-docs --repo https://github.com/kywwilson11/tvgw \
        --ref "$(git rev-parse HEAD)" [--root DIR] [--picture-toggle]

Standard library only.
"""

from __future__ import annotations

import argparse
import os
import pathlib
import re
import shutil
import sys
from urllib.parse import unquote

KEEP_SUFFIXES = frozenset({".md", ".png", ".gif", ".svg", ".jpg", ".jpeg", ".webp", ".cast"})
SKIP_DIRS = frozenset({"site"})

FENCE = re.compile(r"^[ \t]*(`{3,}|~{3,})")
CODE_SPAN = re.compile(r"(`+)(?!`).+?(?<!`)\1(?!`)")
MD_LINK = re.compile(r"(\]\()([^)\s]+)((?:\s+\"[^\"]*\")?\))")
REF_DEF = re.compile(r"^( {0,3}\[(?!\^)[^\]]+\]:[ \t]*)(\S+)", re.M)
HTML_ATTR = re.compile(r"""((?<![\w-])(?:src|srcset|href)\s*=\s*)(["'])(.*?)\2""", re.I)
SCHEME = re.compile(r"^(?:[A-Za-z][A-Za-z0-9+.-]*:|//)")
BADGES = re.compile(
    r"^[ \t]*<!-- badges:start -->[ \t]*\n.*?^[ \t]*<!-- badges:end -->[ \t]*(?:\n|\Z)", re.S | re.M
)
BADGES_START = re.compile(r"^[ \t]*<!-- badges:start -->[ \t]*$", re.M)
PICTURE = re.compile(
    r"<picture>\s*<source media=\"\(prefers-color-scheme: dark\)\" srcset=\"([^\"]+)\">\s*"
    r"<img alt=\"([^\"]*)\" src=\"([^\"]+)\"([^>]*)>\s*</picture>",
    re.S,
)


def chunks(text: str) -> list[tuple[str, bool]]:
    """The text cut into (piece, is_prose): fenced blocks are not prose, at any indent, closed by a
    run of the same character at least as long; an unclosed fence runs to the end, as on GitHub."""
    out: list[tuple[str, bool]] = []
    buf: list[str] = []
    fence = ""
    for line in text.splitlines(keepends=True):
        m = FENCE.match(line)
        if not fence and m:
            out.append(("".join(buf), True))
            buf, fence = [line], m.group(1)
        elif fence and m and m.group(1).startswith(fence) and not line.strip().strip(fence[0]):
            buf.append(line)
            out.append(("".join(buf), False))
            buf, fence = [], ""
        else:
            buf.append(line)
    out.append(("".join(buf), not fence))
    return [(piece, prose) for piece, prose in out if piece]


class Site:
    def __init__(self, root: pathlib.Path, out: pathlib.Path, repo: str, ref: str):
        self.root, self.docs, self.out = root, root / "docs", out
        self.repo, self.ref = repo.rstrip("/"), ref

    def out_path(self, src: pathlib.Path) -> pathlib.Path | None:
        """Where a repository file lands in the site tree, or None when it stays on GitHub."""
        if src.is_dir():
            readme = src / "README.md"
            return self.out_path(readme) if readme.is_file() and self.out_path(readme) else None
        if src.suffix not in KEEP_SUFFIXES:
            return None  # a figure's HTML source, its CSS, build.py: linked on GitHub, not served
        if src == self.root / "README.md":
            return self.out / "index.md"
        if src == self.docs / "README.md":
            return self.out / "map.md"
        try:
            rel = src.relative_to(self.docs)
        except ValueError:
            return None
        if rel.parts[0] in SKIP_DIRS or any(part.startswith(".") for part in rel.parts):
            return None
        return self.out / rel

    def target(self, page_src: pathlib.Path, page_out: pathlib.Path, link: str) -> str:
        """The link as the site needs it: unchanged when absolute, a fragment alone or broken."""
        if SCHEME.match(link) or link.startswith("#"):
            return link
        path, mark, frag = link.partition("#")
        if not path:
            return link
        base = self.root if path.startswith("/") else page_src.parent
        resolved = (base / unquote(path).lstrip("/")).resolve()
        try:
            rel = resolved.relative_to(self.root)
        except ValueError:
            raise SystemExit(f"{page_src}: {link} leaves the repository") from None
        if not resolved.exists():
            return link  # the strict build names it, by page
        dest = self.out_path(resolved)
        if dest is not None:
            new = os.path.relpath(dest, page_out.parent).replace(os.sep, "/")
        else:
            kind = "tree" if resolved.is_dir() else "blob"
            new = f"{self.repo}/{kind}/{self.ref}/{rel.as_posix()}" if rel.parts else f"{self.repo}"
        return new + (mark + frag if mark else "")

    def rewrite(self, page_src: pathlib.Path, page_out: pathlib.Path, text: str, toggle: bool) -> str:
        def link(m: re.Match) -> str:
            return m.group(1) + self.target(page_src, page_out, m.group(2)) + m.group(3)

        def ref_def(m: re.Match) -> str:
            return m.group(1) + self.target(page_src, page_out, m.group(2))

        def attr(m: re.Match) -> str:
            name, quote, value = m.groups()
            if name.split("=")[0].strip().lower() == "srcset":
                parts = []
                for candidate in value.split(","):
                    url, _, descriptor = candidate.strip().partition(" ")
                    new = self.target(page_src, page_out, url)
                    parts.append(new + (" " + descriptor if descriptor else ""))
                value = ", ".join(parts)
            else:
                value = self.target(page_src, page_out, value)
            return f"{name}{quote}{value}{quote}"

        def picture(m: re.Match) -> str:
            dark, alt, light, rest = m.groups()
            return (
                f'<img alt="{alt}" src="{light}#only-light"{rest}>'
                f'<img alt="{alt}" src="{dark}#only-dark"{rest}>'
            )

        out = []
        for piece, prose in chunks(text):
            if prose:
                piece = BADGES.sub("", piece)
                if BADGES_START.search(piece):
                    raise SystemExit(f"{page_src}: <!-- badges:start --> without <!-- badges:end -->")
                spans, last, kept = [], 0, []
                for m in CODE_SPAN.finditer(piece):
                    spans.append(piece[last : m.start()])
                    kept.append(m.group(0))
                    last = m.end()
                spans.append(piece[last:])
                spans = [HTML_ATTR.sub(attr, REF_DEF.sub(ref_def, MD_LINK.sub(link, s))) for s in spans]
                if toggle:
                    spans = [PICTURE.sub(picture, s) for s in spans]
                piece = "".join(s + (kept[i] if i < len(kept) else "") for i, s in enumerate(spans))
            out.append(piece)
        return "".join(out)


def sources(site: Site) -> list[pathlib.Path]:
    """The front page and every file under docs/, in a fixed order."""
    found = [p for p in site.docs.rglob("*") if p.is_file()]
    return [site.root / "README.md", *sorted(found)]


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--root", type=pathlib.Path, default=pathlib.Path(__file__).resolve().parents[2])
    ap.add_argument("--out", required=True, type=pathlib.Path)
    ap.add_argument("--repo", required=True, help="https://github.com/<owner>/<name>")
    ap.add_argument("--ref", default="main", help="the commit built, so links on GitHub match the site")
    ap.add_argument("--picture-toggle", action="store_true", help="rewrite <picture> for a palette toggle")
    args = ap.parse_args(argv)
    site = Site(args.root.resolve(), args.out.resolve(), args.repo, args.ref)
    if site.out == site.root or site.root.is_relative_to(site.out) or site.out.is_relative_to(site.docs):
        raise SystemExit(f"prebuild: --out {site.out} would overwrite the pages it copies")
    if site.out.exists():
        shutil.rmtree(site.out)
    pages = files = 0
    for src in sources(site):
        dst = site.out_path(src)
        if dst is None:
            continue
        dst.parent.mkdir(parents=True, exist_ok=True)
        if src.suffix == ".md":
            text = site.rewrite(src, dst, src.read_text(encoding="utf-8"), args.picture_toggle)
            dst.write_text(text, encoding="utf-8")
            pages += 1
        else:
            shutil.copy2(src, dst)
            files += 1
    print(f"prebuild: {pages} pages and {files} files into {site.out}", file=sys.stderr)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
