"""The user pages read as plain words: the front page, the landing page, what it stops, and the pages
under docs/install/, docs/use/ and docs/tv/ (A13 of docs/project/writing-docs.md).

Outside code, tables, HTML comments, alt text and generated blocks, each page keeps the targets of A4
(a mean sentence of at most 18 words, none over 35, no paragraph over 80 words) and the link limits
of A7 (one relative link in a paragraph or step, four in 100 words), cites no design decision (A8),
names no src/ path in its prose (A1), and avoids the engineering terms of A14.

W3A_REWRITES named the pages whose plain rewrite was still to come, and skipped them; it is empty now
that every user page is rewritten, and it may hold only pages that still break a rule. The rules
themselves are pinned on small texts at the end of this file.
"""

import math
import re

import pytest
from conftest import ROOT

from tvgw import config

# A13: the user pages. Every other Markdown page is an engineering page.
USER_PAGE_GLOBS = ("docs/install/*.md", "docs/use/*.md", "docs/tv/*.md")
USER_PAGE_FILES = ("README.md", "docs/README.md", "docs/what-it-stops.md")

# The pages whose prose the user-page rewrite (W3a of the November design: the front page, what it
# stops, the install guide and the moved user pages in plain words) was still to replace. Each left
# this list in the commit that rewrote it, and the list is empty now: every user page keeps the rules.
# A page added here must still break a rule, or test_each_exempt_page_still_breaks_a_rule fails.
W3A_REWRITES: frozenset[str] = frozenset()

MEAN_SENTENCE_WORDS = 18
MAX_SENTENCE_WORDS = 35
MAX_PARAGRAPH_WORDS = 80
LINKS_PER_100_WORDS = 4
LINKS_PER_PARAGRAPH = 1

# A14, matched in prose outside code spans; a term written in capitals is matched in capitals only, so
# "dot" and "doh" are not DoT and DoH
TERMS = (
    r"design decisions?",
    r"guards?",
    r"nftables",
    r"inet tvgw\w*",
    r"netdev tvgw\w*",
    r"conntrack",
    r"dumpcap",
    r"the store",
    r"SQLite",
    r"evidence packs?",
    r"canary",
    r"probation",
    r"judges?",
    r"shadow",
    r"sudoedit",
    r"debconf",
    r"PYTHONPATH",
    r"venv",
    r"make deploy",
    r"nginx",
    r"dnsmasq",
    r"NetworkManager",
    r"Private Internet Access",
    r"piactl",
    r"Mullvad",
    r"NordVPN",
    r"ProtonVPN",
    r"ExpressVPN",
    r"Surfshark",
    r"LAN APIs?",
    r"must-allow",
)
CAPITAL_TERMS = ("DoH", "DoT", "DoQ", "QUIC", "SDP", "GFTS", "MQTT", "PIA")
TERM = re.compile(r"(?<![\w-])(" + "|".join(TERMS) + r")(?![\w-])", re.IGNORECASE)
CAPITAL_TERM = re.compile(r"(?<![\w-])(" + "|".join(CAPITAL_TERMS) + r")(?![\w-])")
# A14's "any settings key", in prose and in code spans alike: a key shown to a user belongs in a code
# block, where a command sets it
SETTINGS_KEYS = frozenset(config.CONF_KEYS) | {"WAN_GW", "URL_FILTER_RESOLVER", "DOH_LIST_URL"}
KEYS = "|".join(sorted(SETTINGS_KEYS, key=len, reverse=True))
SETTING = re.compile(r"(?<![\w-])(" + KEYS + r"|SETUP_[A-Z]+)(?![\w-])")
SRC_PATH = re.compile(r"(?<![\w./-])src/[\w./-]+")

FENCE = re.compile(r"^\s*(```|~~~)")
GENERATED = re.compile(r"<!--\s*generated:([\w-]+)[^>]*-->.*?<!--\s*/generated:\1\s*-->", re.DOTALL)
BADGES = re.compile(r"<!--\s*badges:start\s*-->.*?<!--\s*badges:end\s*-->", re.DOTALL)
COMMENT = re.compile(r"<!--.*?-->", re.DOTALL)
PICTURE = re.compile(r"<picture>.*?</picture>", re.DOTALL | re.IGNORECASE)
TAG = re.compile(r"<[^>\n]+>")
IMAGE = re.compile(r"!\[[^\]]*\]\([^)]*\)")
LINK = re.compile(r"\[([^\]\n]*)\]\(\s*<?([^\s)>]*)>?(?:\s+\"[^\"]*\")?\s*\)")
CODE_SPAN = re.compile(r"(`+)(.+?)\1")
LIST_ITEM = re.compile(r"^\s*(?:[-*+]|\d+[.)])\s+")
HEADING = re.compile(r"^#{1,6}\s")
SENTENCE_END = re.compile(r"(?<=[.!?])[\"')\]]*\s+")


def user_pages():
    pages = {p for p in USER_PAGE_FILES if (ROOT / p).is_file()}
    for pattern in USER_PAGE_GLOBS:
        pages |= {str(p.relative_to(ROOT)) for p in ROOT.glob(pattern)}
    return sorted(pages)


def blocks(text):
    """The page's prose: one entry per paragraph, list item or heading, as (kind, text), with code
    blocks, tables, HTML comments, generated blocks, figures, images and other HTML taken out."""
    text = GENERATED.sub("\n", text)
    text = BADGES.sub("\n", text)
    text = COMMENT.sub("", text)
    text = PICTURE.sub("\n", text)
    out = []
    current = []

    def flush():
        if current:
            out.append(("paragraph", " ".join(current)))
            current.clear()

    fenced = False
    for line in text.split("\n"):
        if FENCE.match(line):
            flush()
            fenced = not fenced
            continue
        if fenced:
            continue
        stripped = line.strip()
        if not stripped or stripped.startswith("|") or re.fullmatch(r"[-*_]{3,}", stripped):
            flush()
            continue
        if HEADING.match(stripped):
            flush()
            out.append(("heading", stripped.lstrip("#").strip()))
            continue
        if LIST_ITEM.match(line):
            flush()
            stripped = LIST_ITEM.sub("", line).strip()
        stripped = IMAGE.sub("", stripped)
        stripped = TAG.sub("", stripped).strip()
        if stripped.startswith(">"):
            stripped = stripped.lstrip("> ").strip()
        if stripped:
            current.append(stripped)
    flush()
    return out


def links(text):
    """The relative links of a block: (label, target)."""
    found = [(m.group(1), m.group(2)) for m in LINK.finditer(text)]
    return [(label, target) for label, target in found if not re.match(r"^[a-z][a-z0-9+.-]*:", target)]


def visible(text):
    """What a reader sees of a block: link labels for links, code spans kept as they are."""
    return LINK.sub(lambda m: m.group(1), text)


def prose(text):
    """What a reader sees, without the code spans."""
    return CODE_SPAN.sub(" ", visible(text))


def words(text):
    """A code span counts as one word."""
    return len(CODE_SPAN.sub(" code ", visible(text)).split())


def sentences(text):
    return [s for s in SENTENCE_END.split(CODE_SPAN.sub(" code ", visible(text)).strip()) if s.strip()]


def problems(text):
    """Every rule the page's prose breaks, one line each."""
    found = []
    paragraphs = [b for kind, b in blocks(text) if kind == "paragraph"]
    everything = [b for _, b in blocks(text)]
    lengths = [len(s.split()) for p in paragraphs for s in sentences(p)]
    if lengths and sum(lengths) / len(lengths) > MEAN_SENTENCE_WORDS:
        found.append(f"mean sentence of {sum(lengths) / len(lengths):.1f} words, over {MEAN_SENTENCE_WORDS}")
    for p in paragraphs:
        for s in sentences(p):
            if len(s.split()) > MAX_SENTENCE_WORDS:
                found.append(f"a sentence of {len(s.split())} words: {s[:60]}...")
        if words(p) > MAX_PARAGRAPH_WORDS:
            found.append(f"a paragraph of {words(p)} words: {visible(p)[:60]}...")
        if len(links(p)) > LINKS_PER_PARAGRAPH:
            found.append(f"{len(links(p))} links in one paragraph: {visible(p)[:60]}...")
    total_words = sum(words(p) for p in paragraphs)
    total_links = sum(len(links(p)) for p in paragraphs)
    if total_links > LINKS_PER_100_WORDS * max(1, math.ceil(total_words / 100)):
        found.append(f"{total_links} links in {total_words} words, over {LINKS_PER_100_WORDS} in 100")
    for b in everything:
        for _, target in links(b):
            if re.search(r"(^|/)design-decisions\.md", target):
                found.append(f"a link to the design decisions: {target}")
        for m in [*TERM.finditer(prose(b)), *CAPITAL_TERM.finditer(prose(b))]:
            found.append(f"the term {m.group(1)!r}: {prose(b)[:60]}...")
        for m in SETTING.finditer(visible(b)):
            found.append(f"the settings key {m.group(1)}: {visible(b)[:60]}...")
        for m in SRC_PATH.finditer(visible(b)):
            found.append(f"the path {m.group(0)}: {visible(b)[:60]}...")
    return found


# ---- the repository ------------------------------------------------------------------------------


def test_the_user_pages_are_the_pages_a13_names():
    pages = user_pages()
    assert {"README.md", "docs/README.md", "docs/what-it-stops.md"} <= set(pages)
    assert {"docs/install/README.md", "docs/use/daily-brief.md", "docs/tv/README.md"} <= set(pages)
    assert set(pages) >= W3A_REWRITES, sorted(W3A_REWRITES - set(pages))


@pytest.mark.parametrize("page", [p for p in user_pages() if p not in W3A_REWRITES])
def test_a_user_page_reads_as_plain_words(page):
    found = problems((ROOT / page).read_text(encoding="utf-8"))
    assert not found, f"{page}:\n" + "\n".join(found)


@pytest.mark.parametrize("page", sorted(W3A_REWRITES))
def test_each_exempt_page_still_breaks_a_rule(page):
    """An exemption ends with its rewrite: a page that passes leaves W3A_REWRITES."""
    assert problems((ROOT / page).read_text(encoding="utf-8")), f"{page} passes: remove it from W3A_REWRITES"


# ---- the rules -----------------------------------------------------------------------------------


def test_a_short_plain_page_passes():
    text = (
        "# Read your daily brief\n\n"
        "You can check the gateway in a few minutes a day.\n\n"
        "1. Run the brief on the gateway.\n"
        "2. Read the first line. It says whether the rest can be trusted.\n\n"
        "Next: [fix a problem](troubleshooting.md).\n"
    )
    assert problems(text) == []


def test_code_tables_comments_figures_and_generated_blocks_are_not_prose():
    long = " ".join(["word"] * 50) + "."
    text = (
        f"# Title\n\nA short lead.\n\n```sh\n{long}\nsudo nft list ruleset   # nftables\n```\n\n"
        f"| Column | Value |\n|---|---|\n| {long} | dnsmasq |\n\n"
        f"<!-- {long} conntrack -->\n\n"
        f'<picture>\n  <img alt="{long} the guard" src="x.png">\n</picture>\n\n'
        f"<!-- generated:support -->\n{long} nginx\n<!-- /generated:support -->\n\n"
        f"![{long} dumpcap](x.png)\n"
    )
    assert problems(text) == []


def test_sentences_paragraphs_and_their_means():
    eighteen = " ".join(["word"] * 18) + "."
    nineteen = " ".join(["word"] * 19) + "."
    assert problems(f"# T\n\n{eighteen} {eighteen}\n") == []
    assert problems(f"# T\n\n{nineteen} {nineteen}\n")[0].startswith("mean sentence of 19.0 words")
    thirty_six = " ".join(["word"] * 36) + "."
    short = "A short one."
    found = problems(f"# T\n\n{thirty_six}\n\n{short}\n\n{short}\n\n{short}\n\n{short}\n\n{short}\n")
    assert found == ["a sentence of 36 words: " + ("word " * 12)[:60] + "..."]
    paragraph = " ".join(["Five words in a sentence."] * 17)  # 85 words in sentences of five
    assert problems(f"# T\n\n{paragraph}\n")[0].startswith("a paragraph of 85 words")


def test_a_list_item_is_its_own_paragraph_and_a_code_span_one_word():
    items = "\n".join(f"- Run `sudo tvgw verify --record` on the gateway, step {n}." for n in range(20))
    assert problems(f"# T\n\n{items}\n") == []


def test_links_one_per_paragraph_and_four_per_100_words():
    two = "Read [the brief](a.md) and [the fix](b.md)."
    assert problems(f"# T\n\n{two}\n") == [f"2 links in one paragraph: {'Read the brief and the fix.'}..."]
    five = "\n\n".join(f"See [page {n}](p{n}.md)." for n in range(5))
    assert problems(f"# T\n\n{five}\n") == ["5 links in 15 words, over 4 in 100"]
    outside = "See [the release](https://example.org/releases/latest) and [the site](https://example.org/)."
    assert problems(f"# T\n\n{outside}\n") == []


def test_a_design_decision_is_not_cited():
    text = "# T\n\nIt stays off for a reason ([why](../design-decisions.md#4-no-rooting-of-the-tv)).\n"
    assert problems(text) == ["a link to the design decisions: ../design-decisions.md#4-no-rooting-of-the-tv"]
    assert problems("# T\n\nAs design decision 4 says, nothing is installed.\n") == [
        "the term 'design decision': As design decision 4 says, nothing is installed...."
    ]


def test_engineering_terms_settings_keys_and_src_paths():
    assert problems("# T\n\nThe guard stays loaded.\n") == ["the term 'guard': The guard stays loaded...."]
    assert problems("# T\n\nThe TV has no Wi-Fi Direct; the dot is gone.\n") == []
    assert problems("# T\n\nIt blocks DoH servers.\n") == ["the term 'DoH': It blocks DoH servers...."]
    assert problems("# T\n\nRun `sudo nft list ruleset` to see it.\n") == []  # a code span is code
    assert problems("# T\n\nSet `ANALYST_APPLY=auto` to let it block.\n") == [
        "the settings key ANALYST_APPLY: Set `ANALYST_APPLY=auto` to let it block...."
    ]
    assert problems("# T\n\nThe list is in `src/tvgw/profiles/lg-webos.toml`.\n") == [
        "the path src/tvgw/profiles/lg-webos.toml: The list is in `src/tvgw/profiles/lg-webos.toml`...."
    ]
    assert problems("# T\n\nRead [the profiles](../src/tvgw/profiles/README.md).\n") == []  # a link's target
