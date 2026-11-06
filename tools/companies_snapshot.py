#!/usr/bin/env python3
"""Write src/tvgw/data/companies.txt, tvgw's trimmed snapshot of AdGuard's companies database.

The database (https://github.com/AdguardTeam/companiesdb) maps a tracker's domains to the tracker and
the tracker to the company behind it. tvgw keeps only a domain and its company's name, so `tvgw check`,
`tvgw refused` and the plain brief can say whose a name is without asking anyone at run time. The
snapshot is pinned to one commit of the database, and its header records that commit, the hash of
each file it was read from, the licence (CC BY-SA 4.0, which the file stays under) and the attribution
the licence asks for (src/tvgw/data/README.md).

    python3 tools/companies_snapshot.py --commit <sha>             # fetch the two files at that commit
    python3 tools/companies_snapshot.py --commit <sha> --from DIR  # DIR/trackers.json, DIR/companies.json
    python3 tools/companies_snapshot.py --commit <sha> --check     # compare with the file, write nothing

Standard library only; it imports the tvgw package of the checkout it sits in for the name rules.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT / "src") not in sys.path:  # this checkout's code, whatever tvgw is installed
    sys.path.insert(0, str(ROOT / "src"))

from tvgw.names import is_public_name, normalize  # noqa: E402

OUT = ROOT / "src" / "tvgw" / "data" / "companies.txt"
REPO = "https://github.com/AdguardTeam/companiesdb"
RAW = "https://raw.githubusercontent.com/AdguardTeam/companiesdb/{commit}/dist/{name}"
FILES = ("trackers.json", "companies.json")
MAX_BYTES = 16 * 1024 * 1024  # each file is under 1 MB; a larger answer is not it
COMMIT = re.compile(r"[0-9a-f]{40}")
# the categories whose entries name the carrier of a name, never whom it serves: a CDN or a cloud
# host's domain is every tenant's, so its company would be a guess about any one name under it
CARRIERS = frozenset({"cdn", "hosting"})
NAME_CAP = 80  # characters of a company's name kept; the longest real one is about 50
BODY_HASH = "# Body sha256: "


def clean_name(text: object) -> str:
    """A company's name on one line: no control or format characters (one entry ends in \\x03), no
    tab, single spaces, at most NAME_CAP characters; "" when nothing is left."""
    if not isinstance(text, str):
        return ""
    kept = "".join(ch if ch.isprintable() else " " for ch in text)
    return " ".join(kept.split())[:NAME_CAP].strip()


def rows(trackers: dict, companies: dict) -> list[tuple[str, str]]:
    """(domain, company name) for every domain of a tracker that names a company with a name, outside
    the CARRIERS categories, for a domain that is an internet name, sorted by domain. ValueError when
    either file is not the shape the database's README describes."""
    if not isinstance(trackers, dict) or not isinstance(companies, dict):
        trackers, companies = {}, {}
    domains = trackers.get("trackerDomains")
    entries = trackers.get("trackers")
    cats = trackers.get("categories")
    found = companies.get("companies")
    if not all(isinstance(x, dict) for x in (domains, entries, cats, found)):
        raise ValueError(
            "expected trackers.json with trackers, trackerDomains and categories, and companies.json"
            " with companies"
        )
    out: dict[str, str] = {}
    for domain, tracker_id in domains.items():
        tracker = entries.get(tracker_id)
        if not isinstance(tracker, dict) or not isinstance(domain, str):
            continue
        if cats.get(str(tracker.get("categoryId"))) in CARRIERS:
            continue
        company = found.get(tracker.get("companyId")) if isinstance(tracker.get("companyId"), str) else None
        name = clean_name(company.get("name")) if isinstance(company, dict) else ""
        host = normalize(domain)
        if name and is_public_name(host):
            out[host] = name
    return sorted(out.items())


def body(found: list[tuple[str, str]]) -> str:
    return "".join(f"{domain}\t{name}\n" for domain, name in found)


def render(commit: str, raw: dict[str, bytes]) -> str:
    """The whole file: the header, with the commit, each source file's hash, the database's own
    timeUpdated, the licence and the attribution, then one line per domain."""
    trackers, companies = (json.loads(raw[name].decode("utf-8")) for name in FILES)
    text = body(rows(trackers, companies))
    hashes = ", ".join(f"dist/{name} sha256 {hashlib.sha256(raw[name]).hexdigest()}" for name in FILES)
    updated = clean_name(trackers.get("timeUpdated")) or "not given"
    header = [
        "# tvgw's trimmed snapshot of AdGuard's companies database: one line per domain, the domain,",
        "# a tab and the name of the company behind it. Written by tools/companies_snapshot.py; never",
        "# edit it by hand.",
        f"# Source: AdGuard Companies DB, {REPO}, commit {commit}",
        f"# Read from: {hashes}; timeUpdated {updated}",
        "# Licence: Creative Commons Attribution-ShareAlike 4.0 International (CC BY-SA 4.0),",
        "#   https://creativecommons.org/licenses/by-sa/4.0/ . This file stays under that licence, not under",
        "#   tvgw's MIT licence, and is shared on the same terms.",
        "# Attribution: AdGuard Companies DB by AdGuard; it builds on WhoTracks.Me by Ghostery",
        "#   (https://github.com/whotracksme/whotracks.me), CC BY 4.0.",
        "# Changes: tvgw kept only each domain and the name of its tracker's company, dropped the",
        "#   domains whose tracker names no company and those of the cdn and hosting categories, cleaned",
        "#   each name to one line and sorted the lines. No endorsement by AdGuard or Ghostery is implied.",
        "#   Provided as-is, without warranties, as the licence says.",
        f"{BODY_HASH}{hashlib.sha256(text.encode('utf-8')).hexdigest()}",
    ]
    return "\n".join(header) + "\n" + text


def fetch(commit: str) -> dict[str, bytes]:
    out = {}
    for name in FILES:
        with urllib.request.urlopen(RAW.format(commit=commit, name=name), timeout=60) as r:
            data = r.read(MAX_BYTES + 1)
        if len(data) > MAX_BYTES:
            raise ValueError(f"{name}: larger than {MAX_BYTES} bytes")
        out[name] = data
    return out


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    p.add_argument("--commit", required=True, help="the database's commit, 40 hexadecimal digits")
    p.add_argument("--from", dest="source", help="a folder holding trackers.json and companies.json")
    p.add_argument("--out", default=str(OUT), help=f"the file to write (default {OUT.relative_to(ROOT)})")
    p.add_argument("--check", action="store_true", help="compare with --out and write nothing")
    a = p.parse_args(argv)
    if not COMMIT.fullmatch(a.commit):
        p.error("--commit takes the full 40-digit commit id")
    try:
        raw = {n: (Path(a.source) / n).read_bytes() for n in FILES} if a.source else fetch(a.commit)
        text = render(a.commit, raw)
    except (OSError, ValueError) as e:
        print(f"companies_snapshot: {e}", file=sys.stderr)
        return 2
    out = Path(a.out)
    if a.check:
        same = out.is_file() and out.read_text(encoding="utf-8") == text
        print(f"companies_snapshot: {out} {'matches' if same else 'differs from'} commit {a.commit}")
        return 0 if same else 1
    out.write_text(text, encoding="utf-8")
    domains = sum(1 for line in text.splitlines() if line and not line.startswith("#"))
    print(f"companies_snapshot: wrote {out}, {domains} domains")
    return 0


if __name__ == "__main__":
    sys.exit(main())
