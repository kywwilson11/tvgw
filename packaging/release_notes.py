"""Write a release's notes from CHANGELOG.md, the release's SHA256SUMS and .github/release-notes.md.in.

release.yml runs it twice on a tag: before anything is built, to refuse a release whose changelog is not
ready, and after the packages are built, to write the notes the release is created with:

    python3 packaging/release_notes.py --version 0.3.0 --changelog CHANGELOG.md \\
        --template .github/release-notes.md.in --sums dist/SHA256SUMS --out dist/RELEASE_NOTES.md

What a typical user reads comes from one place, the version's section of CHANGELOG.md, which starts with two
blocks the owner writes when cutting the release
(docs/project/packaging.md#the-changelogs-highlights-and-status): "### Highlights", three to six plain
bullets, and "### Status", one paragraph on what was tested on hardware for this version and what was not. The
engineering detail below them is linked, not pasted. The script refuses, and the release job stops before any
release exists, when the section or either block is missing or out of place, a highlight is too long or uses a
word the user pages avoid, or the notes would run past MAX_LINES. Standard library only.
"""

from __future__ import annotations

import argparse
import pathlib
import re
import sys

MIN_BULLETS, MAX_BULLETS, MAX_CHARS = 3, 6, 220
MAX_LINES = 60  # the notes are read on one screen; the changelog holds the rest
FIELD = re.compile(r"@([A-Z]+)@")
# the engineering terms the user pages avoid: a highlight that needs one belongs in the changelog's detail,
# where an engineer reads it
PLAIN_WORDS = re.compile(
    r"\b(?:design decisions?(?: \d+)?|decision \d+|guard|tvgw_guard|inet tvgw|nftables|nft|conntrack|dumpcap"
    r"|DoH|DoT|DoQ|QUIC|SDP|GFTS|MQTT|SQLite|the store|evidence packs?|canary|probation|judge|shadow"
    r"|sudoedit|debconf|PYTHONPATH|venv|virtualenv|make deploy|nginx|dnsmasq|NetworkManager|LAN API"
    r"|must-allow|WireGuard|OpenVPN|PIA|Private Internet Access|Mullvad|NordVPN|Proton ?VPN|ExpressVPN"
    r"|Surfshark|Tailscale)\b",
    re.I,
)
# a settings key, or any other name from the code written in capitals with an underscore
SETTING = re.compile(r"\b[A-Z][A-Z0-9]*_[A-Z0-9_]+\b")


class NotesError(ValueError):
    """A refusal: the message says what to fix in CHANGELOG.md or the template."""


def section(changelog: str, version: str) -> tuple[str, str]:
    """The heading `## <version> (<YYYY-MM-DD>)` and the section's body, up to the next `## ` heading."""
    m = re.search(rf"^## {re.escape(version)} \((\d{{4}}-\d{{2}}-\d{{2}})\)[ \t]*$", changelog, re.M)
    if not m:
        raise NotesError(f"CHANGELOG.md has no '## {version} (YYYY-MM-DD)' section")
    rest = changelog[m.end() :]
    nxt = re.search(r"^## ", rest, re.M)
    return m.group(0).strip(), rest[: nxt.start()] if nxt else rest


def subsections(body: str) -> list[tuple[str, str]]:
    """The `### ` subsections of a section's body, in order, as (title, text) pairs."""
    parts = re.split(r"^### +(.+?)[ \t]*$", body, flags=re.M)
    if parts[0].strip():
        raise NotesError(
            "the version's section has text before '### Highlights'; it starts with Highlights, then Status"
        )
    return [(parts[i].strip(), parts[i + 1].strip()) for i in range(1, len(parts), 2)]


def plain_word(text: str) -> str | None:
    """The first word of `text` the user pages avoid, or None."""
    found = [m for m in (PLAIN_WORDS.search(text), SETTING.search(text)) if m]
    return min(found, key=lambda m: m.start()).group(0) if found else None


def bullets(text: str) -> list[str]:
    """The bullets of a Highlights block, each short and in plain words; the count is not checked."""
    lines = [line for line in text.splitlines() if line.strip()]
    if stray := [line for line in lines if not line.startswith("- ")]:
        raise NotesError(f"Highlights holds bullets only, one line each: {stray[0][:60]!r}")
    found = [line[2:].strip() for line in lines]
    for b in found:
        if not b or len(b) > MAX_CHARS:
            raise NotesError(f"a highlight is empty or over {MAX_CHARS} characters: {b[:60]!r}")
        if word := plain_word(b):
            raise NotesError(f"a highlight uses {word!r}; say it in plain words: {b[:60]!r}")
    return found


def highlights(text: str) -> list[str]:
    """Three to six bullets, each one line, short and in plain words."""
    found = bullets(text)
    if not MIN_BULLETS <= len(found) <= MAX_BULLETS:
        raise NotesError(f"Highlights has {len(found)} bullets; write {MIN_BULLETS} to {MAX_BULLETS}")
    return found


def status(text: str) -> str:
    """One paragraph, not a list."""
    if not text:
        raise NotesError("the version's '### Status' block is empty; say what was tested and what was not")
    if re.search(r"\n[ \t]*\n", text) or re.search(r"^[ \t]*(?:[-*+]|\d+\.) ", text, re.M):
        raise NotesError(
            "Status is one paragraph: what was tested on hardware for this version and what was not"
        )
    return " ".join(line.strip() for line in text.splitlines())


def blocks(body: str) -> tuple[list[str], str]:
    """The Highlights bullets and the Status paragraph, which must be the section's first two blocks."""
    subs = subsections(body)
    titles = [title for title, _ in subs[:2]]
    if titles != ["Highlights", "Status"]:
        found = ", ".join(titles) or "no subsection"
        raise NotesError(
            f"the version's section starts with '### Highlights', then '### Status'; found {found}"
        )
    return highlights(subs[0][1]), status(subs[1][1])


def anchor(heading: str) -> str:
    """GitHub's anchor for a heading: lowercase, punctuation other than - and _ dropped, spaces to -."""
    text = heading.lstrip("#").strip().lower()
    return re.sub(r"[^\w\- ]", "", text).replace(" ", "-")


def render(template: str, version: str, changelog: str, sums: str = "") -> str:
    """The notes for `version`, or NotesError saying what to fix."""
    heading, body = section(changelog, version)
    bullets, para = blocks(body)
    fields = {
        "VERSION": version,
        "DATE": re.search(r"\((\d{4}-\d{2}-\d{2})\)", heading).group(1),
        "ANCHOR": anchor(heading),
        "HIGHLIGHTS": "\n".join(f"- {b}" for b in bullets),
        "STATUS": para,
        "SUMS": f"```text\n{sums.strip()}\n```" if sums.strip() else "",
    }
    if unknown := sorted(set(FIELD.findall(template)) - set(fields)):
        raise NotesError(f"the template has fields this script does not fill: {unknown}")
    # one pass, so text from the changelog is never read as a field
    notes = FIELD.sub(lambda m: fields[m.group(1)], template)
    notes = re.sub(r"\n{3,}", "\n\n", notes).strip() + "\n"
    if (n := len(notes.splitlines())) > MAX_LINES:
        raise NotesError(f"the notes run to {n} lines; keep them to {MAX_LINES}")
    return notes


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--version", required=True, help="the version, without the tag's v")
    ap.add_argument("--changelog", type=pathlib.Path, required=True)
    ap.add_argument("--template", type=pathlib.Path, required=True)
    ap.add_argument("--sums", type=pathlib.Path, help="the release's SHA256SUMS; left out, the check only")
    ap.add_argument("--out", type=pathlib.Path, help="where to write the notes; left out, nothing is written")
    a = ap.parse_args(argv)
    try:
        notes = render(
            a.template.read_text(encoding="utf-8"),
            a.version,
            a.changelog.read_text(encoding="utf-8"),
            a.sums.read_text(encoding="utf-8") if a.sums else "",
        )
    except NotesError as e:
        print(f"release notes: {e}", file=sys.stderr)
        return 1
    if a.out:
        a.out.write_text(notes, encoding="utf-8")
    print(f"release notes: {a.out or 'checked'} ({len(notes.splitlines())} lines)", file=sys.stderr)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
