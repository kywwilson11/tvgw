#!/usr/bin/env python3
"""Write src/tvgw/data/companies.txt, tvgw's trimmed snapshot of AdGuard's companies database.

The database (https://github.com/AdguardTeam/companiesdb) maps a tracker's domains to the tracker and
the tracker to the company behind it. tvgw keeps only a domain and its company's name, so `tvgw check`,
`tvgw refused` and the plain brief can say whose a name is without asking anyone at run time. The
snapshot is pinned to one commit of the database, and its header records that commit, each input's
SHA-256 and git blob id, the licence (CC BY-SA 4.0, which the file stays under), the attribution the
licence asks for and every change tvgw made (src/tvgw/data/README.md).

Rows that are a hosting provider's customers' suffix, or sit above one, would credit every customer's
name to the provider, so they are left out by the private section of the Public Suffix List
(https://github.com/publicsuffix/list, MPL 2.0) at a pinned commit; the list is read here and none of
it goes into the file.

    python3 tools/companies_snapshot.py --commit <sha> --psl-commit <sha>          # fetch and check
    python3 tools/companies_snapshot.py --commit <sha> --psl-commit <sha> --from DIR
    python3 tools/companies_snapshot.py --commit <sha> --psl-commit <sha> --check  # compare, write nothing

Fetched files are checked against the git blob ids GitHub's contents API gives for them at the commit.
`--from DIR` reads trackers.json, companies.json and public_suffix_list.dat from a folder; their blob ids
go in the header, unchecked, for anyone to compare with the commit. It fails on an input whose shape the
database no longer has, and refuses a row count more than SWING away from the file's without
`--accept-swing`. Standard library only; it imports the tvgw package of the checkout it sits in.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
import urllib.request
from collections import Counter
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT / "src") not in sys.path:  # this checkout's code, whatever tvgw is installed
    sys.path.insert(0, str(ROOT / "src"))

from tvgw.companies import BODY_HASH  # noqa: E402
from tvgw.names import is_public_name, normalize  # noqa: E402

OUT = ROOT / "src" / "tvgw" / "data" / "companies.txt"
REPO = "AdguardTeam/companiesdb"
PSL_REPO = "publicsuffix/list"
RAW = "https://raw.githubusercontent.com/{repo}/{commit}/{path}"
API = "https://api.github.com/repos/{repo}/contents/{path}?ref={commit}"
FILES = {"trackers.json": "dist/trackers.json", "companies.json": "dist/companies.json"}
PSL = ("public_suffix_list.dat", "public_suffix_list.dat")
MAX_BYTES = 16 * 1024 * 1024  # each file is under 1 MB; a larger answer is not it
COMMIT = re.compile(r"[0-9a-f]{40}")
# the categories whose entries name the carrier of a name, never whom it serves: a CDN or a cloud
# host's domain is every tenant's, so its company would be a guess about any one name under it
CARRIERS = frozenset({"cdn", "hosting"})
# carriers' domains the database files under another category and the Public Suffix List does not
# list, under which every name is a customer's: left out by name (a removal, never an addition)
CARRIERS_BY_HAND = frozenset({"firebaseio.com", "msecnd.net", "wordpress.com", "wpengine.com"})
NAME_CAP = 80  # characters of a company's name kept; the longest real one is about 50
MIN_ROWS = 1000  # fewer is a database that changed shape, not one that shrank
MIN_SUFFIXES = 1000  # the private section holds thousands; fewer is a list that changed shape
SWING = 0.2  # a row count this much above or below the file's is refused without --accept-swing
PRIVATE = ("// ===BEGIN PRIVATE DOMAINS===", "// ===END PRIVATE DOMAINS===")


class DriftError(ValueError):
    """An input is not the shape this tool reads, or the result is not believable."""


def clean_name(text: object) -> str:
    """A company's name on one line: no control or format characters (one entry ends in \\x03), no
    tab, single spaces, at most NAME_CAP characters; "" when nothing is left."""
    if not isinstance(text, str):
        return ""
    kept = "".join(ch if ch.isprintable() else " " for ch in text)
    return " ".join(kept.split())[:NAME_CAP].strip()


def private_suffixes(text: str) -> frozenset[str]:
    """The private section's suffixes of the Public Suffix List: `*.x` as `x`, exceptions (`!x`) left
    out, an internationalized one in its ASCII form."""
    if PRIVATE[0] not in text or PRIVATE[1] not in text:
        raise DriftError("public_suffix_list.dat has no private section between its markers")
    section = text.split(PRIVATE[0], 1)[1].split(PRIVATE[1], 1)[0]
    out = set()
    for line in section.splitlines():
        rule = line.strip().split()[0] if line.strip() else ""
        if not rule or rule.startswith(("//", "!")):
            continue
        rule = rule.removeprefix("*.").lower()
        out.add(rule if rule.isascii() else rule.encode("idna").decode("ascii"))
    if len(out) < MIN_SUFFIXES:
        raise DriftError(f"public_suffix_list.dat's private section holds {len(out)} suffixes, not thousands")
    return frozenset(out)


def _check_shape(trackers: object, companies: object) -> tuple[dict, dict, dict, dict]:
    if not isinstance(trackers, dict) or not isinstance(companies, dict):
        raise DriftError("expected trackers.json and companies.json to be JSON objects")
    domains, entries = trackers.get("trackerDomains"), trackers.get("trackers")
    cats, found = trackers.get("categories"), companies.get("companies")
    if not all(isinstance(x, dict) for x in (domains, entries, cats, found)):
        raise DriftError(
            "expected trackers.json with trackers, trackerDomains and categories, and companies.json"
            " with companies"
        )
    if not set(cats.values()) >= CARRIERS:
        raise DriftError(
            f"trackers.json's categories no longer name {sorted(CARRIERS)}: {sorted(cats.values())}"
        )
    with_company = sum(
        1 for e in entries.values() if isinstance(e, dict) and isinstance(e.get("companyId"), str)
    )
    if with_company * 2 < len(entries):
        raise DriftError(f"only {with_company} of {len(entries)} trackers name a companyId")
    return domains, entries, cats, found


def rows(trackers: dict, companies: dict, suffixes: frozenset[str] = frozenset()) -> tuple[list, Counter]:
    """((domain, company name) sorted by domain, the domains left out by reason). Kept: every domain of
    a tracker that names a company with a name, outside the CARRIERS categories and CARRIERS_BY_HAND,
    that is an internet name and is neither one of `suffixes` nor above one. DriftError when an input
    is not the shape the database's README describes."""
    domains, entries, cats, found = _check_shape(trackers, companies)
    above = {s.split(".", i)[-1] for s in suffixes for i in range(1, s.count(".") + 1)}  # their parents
    out: dict[str, str] = {}
    dropped: Counter = Counter()
    for domain, tracker_id in domains.items():
        tracker = entries.get(tracker_id)
        if not isinstance(tracker, dict) or not isinstance(domain, str):
            dropped["no tracker"] += 1
            continue
        if cats.get(str(tracker.get("categoryId"))) in CARRIERS:
            dropped["cdn or hosting category"] += 1
            continue
        company = found.get(tracker.get("companyId")) if isinstance(tracker.get("companyId"), str) else None
        name = clean_name(company.get("name")) if isinstance(company, dict) else ""
        host = normalize(domain)
        if not name:
            dropped["no company"] += 1
        elif not is_public_name(host):
            dropped["not an internet name"] += 1
        elif host in CARRIERS_BY_HAND:
            dropped["a carrier's domain, by hand"] += 1
        elif host in suffixes or host in above:
            dropped["a public suffix, or above one"] += 1
        else:
            if isinstance(company, dict) and name != company.get("name"):
                dropped["(kept, name cleaned)"] += 1
            out[host] = name
    return sorted(out.items()), dropped


def body(found: list[tuple[str, str]]) -> str:
    return "".join(f"{domain}\t{name}\n" for domain, name in found)


def blob(data: bytes) -> str:
    """git's blob id of a file's bytes, which GitHub's contents API reports for it at a commit."""
    return hashlib.sha1(b"blob %d\0" % len(data) + data).hexdigest()


def render(commit: str, psl_commit: str, raw: dict[str, bytes], fetched: bool) -> tuple[str, Counter]:
    """(the whole file, the drops by reason): the header, with each input's commit, SHA-256 and blob
    id, the database's own timeUpdated, the licence, copyright and attribution and every change, then
    one line per domain."""
    trackers, companies = (json.loads(raw[name].decode("utf-8")) for name in FILES)
    suffixes = private_suffixes(raw[PSL[0]].decode("utf-8"))
    found, dropped = rows(trackers, companies, suffixes)
    if len(found) < MIN_ROWS:
        raise DriftError(f"{len(found)} domains kept, fewer than {MIN_ROWS}: the database changed shape")
    text = body(found)
    digests = ", ".join(
        f"{path} sha256 {hashlib.sha256(raw[name]).hexdigest()} git blob {blob(raw[name])}"
        for name, path in FILES.items()
    )
    how = "fetched at the commit, blobs checked" if fetched else "read from a folder, blobs not checked"
    updated = clean_name(trackers.get("timeUpdated")) or "not given"
    psl = raw[PSL[0]]
    header = [
        "# tvgw's trimmed snapshot of AdGuard's companies database: one line per domain, the domain,",
        "# a tab and the name of the company behind it. Written by tools/companies_snapshot.py; never",
        "# edit it by hand.",
        f"# Source: AdGuard Companies DB, https://github.com/{REPO}, commit {commit}",
        f"# Read from: {digests}; timeUpdated {updated}; {how}",
        f"# Suffixes: the Public Suffix List, https://github.com/{PSL_REPO}, commit {psl_commit},"
        f" public_suffix_list.dat sha256 {hashlib.sha256(psl).hexdigest()} git blob {blob(psl)}; MPL 2.0;"
        " used only to leave rows out, and no part of it is in this file",
        "# Licence: Creative Commons Attribution-ShareAlike 4.0 International (CC BY-SA 4.0),",
        "#   https://creativecommons.org/licenses/by-sa/4.0/ . This file stays under that licence, not under",
        "#   tvgw's MIT licence, and is shared on the same terms.",
        "# Copyright: the source gives no copyright notice; the database is AdGuard's, and the",
        "#   WhoTracks.Me data it builds on is Ghostery's.",
        "# Attribution: AdGuard Companies DB by AdGuard; it builds on WhoTracks.Me by Ghostery",
        "#   (https://github.com/whotracksme/whotracks.me), CC BY 4.0.",
        "# Changes: tvgw kept only each domain and the name of its tracker's company. It left out the",
        "#   domains whose tracker names no company, those of the cdn and hosting categories, four",
        "#   carriers' domains by name (firebaseio.com, msecnd.net, wordpress.com, wpengine.com), those",
        "#   that are, or sit above, a private-section public suffix, and those that are not internet",
        "#   names. It cleaned each company's name to one printable line of at most 80 characters, and",
        "#   sorted the lines. No endorsement by AdGuard or Ghostery is implied. Provided as-is, without",
        "#   warranties, as the licence says.",
        f"{BODY_HASH}{hashlib.sha256(text.encode('utf-8')).hexdigest()}",
    ]
    return "\n".join(header) + "\n" + text, dropped


def _get(url: str) -> bytes:
    with urllib.request.urlopen(url, timeout=60) as r:
        data = r.read(MAX_BYTES + 1)
    if len(data) > MAX_BYTES:
        raise DriftError(f"{url}: larger than {MAX_BYTES} bytes")
    return data


def fetch(commit: str, psl_commit: str, get=_get) -> dict[str, bytes]:
    """Each input at its commit, checked against the blob id GitHub's contents API gives for it there.
    `get(url)` stands in for the network."""
    out = {}
    wanted = {n: (REPO, p, commit) for n, p in FILES.items()}
    wanted[PSL[0]] = (PSL_REPO, PSL[1], psl_commit)
    for name, (repo, path, at) in wanted.items():
        data = get(RAW.format(repo=repo, commit=at, path=path))
        meta = json.loads(get(API.format(repo=repo, commit=at, path=path)).decode("utf-8"))
        if not isinstance(meta, dict) or meta.get("sha") != blob(data):
            raise DriftError(f"{path} at {at[:12]} is not the blob GitHub names for it")
        out[name] = data
    return out


def _rows_of(path: Path) -> int | None:
    if not path.is_file():
        return None
    return sum(
        1 for line in path.read_text(encoding="utf-8").splitlines() if line and not line.startswith("#")
    )


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    p.add_argument("--commit", required=True, help="the database's commit, 40 hexadecimal digits")
    p.add_argument(
        "--psl-commit", required=True, help="the Public Suffix List's commit, 40 hexadecimal digits"
    )
    p.add_argument(
        "--from", dest="source", help="a folder holding trackers.json, companies.json, public_suffix_list.dat"
    )
    p.add_argument("--out", default=str(OUT), help=f"the file to write (default {OUT.relative_to(ROOT)})")
    p.add_argument("--check", action="store_true", help="compare with --out and write nothing")
    p.add_argument(
        "--accept-swing", action="store_true", help=f"write a row count over {SWING:.0%} from the file's"
    )
    a = p.parse_args(argv)
    if not COMMIT.fullmatch(a.commit) or not COMMIT.fullmatch(a.psl_commit):
        p.error("--commit and --psl-commit take the full 40-digit commit id")
    out = Path(a.out)
    try:
        if a.source:
            raw = {n: (Path(a.source) / n).read_bytes() for n in (*FILES, PSL[0])}
        else:
            raw = fetch(a.commit, a.psl_commit)
        text, dropped = render(a.commit, a.psl_commit, raw, fetched=not a.source)
    except (OSError, ValueError) as e:  # DriftError and JSON errors are ValueErrors
        print(f"companies_snapshot: {e}", file=sys.stderr)
        return 2
    kept = sum(1 for line in text.splitlines() if line and not line.startswith("#"))
    for reason, n in sorted(dropped.items()):
        print(f"companies_snapshot: {n} {reason}")
    if a.check:
        same = out.is_file() and out.read_text(encoding="utf-8") == text
        print(f"companies_snapshot: {out} {'matches' if same else 'differs from'} commit {a.commit}")
        return 0 if same else 1
    before = _rows_of(out)
    if before and abs(kept - before) > SWING * before and not a.accept_swing:
        print(
            f"companies_snapshot: {kept} domains against {before} in {out}: more than {SWING:.0%} apart;"
            " check the source, then run again with --accept-swing",
            file=sys.stderr,
        )
        return 2
    out.write_text(text, encoding="utf-8")
    print(f"companies_snapshot: wrote {out}, {kept} domains")
    return 0


if __name__ == "__main__":
    sys.exit(main())
