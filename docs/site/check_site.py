#!/usr/bin/env python3
"""Check a built documentation site: every local href, src and srcset resolves, and nothing loads from
another party.

The generator's strict build checks Markdown links and anchors; it does not look inside raw HTML, and
every figure is a raw <picture> element (docs/diagrams/STYLE.md), so a figure path that breaks on the
site passes the strict build. This catches it, in every page the build wrote. It also refuses what
would make the reader's browser fetch something from another site: an image, a script or a frame with
an absolute address, a <link> that loads a stylesheet, a font or an icon from one, and a stylesheet
that imports or loads from one, Google Fonts among them. Attributes are read from the tags alone, so
an example in a code block is text. Links to other sites are not requests and are not checked. The
theme's repository widget asks api.github.com for the star count from its script; that one is known
(docs/site/README.md#gotchas).

    python3 docs/site/check_site.py build/site [--prefix /tvgw/]

One line per problem and exit 1 (also when no page was built); otherwise one summary line and exit 0.
Standard library only.
"""

from __future__ import annotations

import argparse
import pathlib
import re
import sys
from html.parser import HTMLParser
from urllib.parse import unquote, urlsplit

# a <link> of these kinds is fetched by the browser; canonical, next and prev are not
FETCHED_RELS = frozenset(
    {"stylesheet", "icon", "preload", "preconnect", "dns-prefetch", "prefetch", "modulepreload"}
)
GOOGLE_FONTS = re.compile(r"fonts\.(?:googleapis|gstatic)\.com")
CSS_REMOTE = re.compile(r"""(?:@import\s+|url\(\s*)["']?(?:https?:)?//""", re.I)
ABSOLUTE = re.compile(r"^(?:[A-Za-z][A-Za-z0-9+.-]*:)?//")


class Refs(HTMLParser):
    """The href, src and srcset of every tag in a page, and the <link> tags; text is not read, so an
    attribute written in a code example is not taken for one."""

    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.refs: list[tuple[str, str, str]] = []  # (tag, attribute, value)
        self.links: list[tuple[set[str], str]] = []  # (rel words, href)

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        values = {name.lower(): value or "" for name, value in attrs}
        for name in ("href", "src", "srcset"):
            if values.get(name):
                self.refs.append((tag, name, values[name]))
        if tag == "link":
            self.links.append((set(values.get("rel", "").lower().split()), values.get("href", "")))

    handle_startendtag = handle_starttag


def urls_of(kind: str, raw: str) -> list[str]:
    """The addresses an attribute names; a srcset lists candidates, each an address and a size."""
    if kind == "srcset":
        return [c.strip().split(" ")[0] for c in raw.split(",") if c.strip()]
    return [raw]


def page_problems(site: pathlib.Path, page: pathlib.Path, prefix: str) -> tuple[int, list[str]]:
    rel = page.relative_to(site).as_posix()
    html = page.read_text(encoding="utf-8", errors="replace")
    found, checked = [], 0
    parser = Refs()
    parser.feed(html)
    parser.close()
    for rels, href in parser.links:
        if rels & FETCHED_RELS and ABSOLUTE.match(href):
            hint = " (theme.font: false keeps Google Fonts out)" if GOOGLE_FONTS.search(href) else ""
            found.append(f"{rel}: <link rel={' '.join(sorted(rels))}> fetches {href} from another site{hint}")
    for _tag, kind, raw in parser.refs:
        for url in urls_of(kind, raw):
            if kind != "href" and ABSOLUTE.match(url):
                found.append(f"{rel}: {kind}={url} loads from another site")
                continue
            u = urlsplit(url)
            if u.scheme or url.startswith(("#", "//")) or not u.path:
                continue
            path = unquote(u.path)
            if path.startswith(prefix):
                target = site / path[len(prefix) :]
            elif path.startswith("/"):
                found.append(f"{rel}: {url} is outside the site's prefix {prefix}")
                continue
            else:
                target = page.parent / path
            target = target.resolve()
            if target.is_dir():
                target = target / "index.html"
            checked += 1
            if not target.exists():
                found.append(f"{rel}: {url} does not resolve")
    return checked, found


def problems(site: pathlib.Path, prefix: str) -> tuple[int, int, list[str]]:
    found, pages, checked = [], 0, 0
    for page in sorted(site.rglob("*.html")):
        pages += 1
        n, more = page_problems(site, page, prefix)
        checked += n
        found += more
    for sheet in sorted(site.rglob("*.css")):
        css = sheet.read_text(encoding="utf-8", errors="replace")
        if GOOGLE_FONTS.search(css) or CSS_REMOTE.search(css):
            found.append(f"{sheet.relative_to(site).as_posix()}: the stylesheet fetches from another site")
    return pages, checked, found


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("site", type=pathlib.Path)
    ap.add_argument("--prefix", default="/tvgw/", help="the path the site is served under")
    a = ap.parse_args(argv)
    pages, checked, found = problems(a.site, a.prefix)
    for line in found:
        print(f"check_site: {line}", file=sys.stderr)
    print(f"check_site: {pages} pages, {checked} local references, {len(found)} problems", file=sys.stderr)
    return 1 if found or pages == 0 else 0


if __name__ == "__main__":
    raise SystemExit(main())
