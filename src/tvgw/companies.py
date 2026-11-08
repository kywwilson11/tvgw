"""The company behind a name, from tvgw's snapshot of AdGuard's companies database.

`src/tvgw/data/companies.txt` is a pinned, trimmed copy of the database (a domain and its company's
name, nothing else), written by `tools/companies_snapshot.py` with its source commit, the hashes of the
files it came from, its licence (CC BY-SA 4.0, which that file stays under) and the attribution the
licence asks for in its header (src/tvgw/data/README.md). Nothing is fetched at run time.

`company(name)` gives the company of the most specific domain the snapshot lists at or above `name`,
and None for a name it does not list: a name with no known company says nothing, and nothing is ever
guessed from the name's own words. The walk up never reaches or crosses a domain in
`names.PUBLIC_SUFFIXES`, under which each name is a different customer's (`myapp.azurewebsites.net` is
nobody's that tvgw knows, whoever runs azurewebsites.net), as `names.registrable_domain()` treats it.
"""

from __future__ import annotations

import functools
import hashlib
import re
from importlib import resources

from tvgw.names import PUBLIC_SUFFIXES, normalize

DATA = "companies.txt"  # in tvgw/data, shipped as package data (pyproject.toml)
BODY_HASH = "# Body sha256: "  # the header line tools/companies_snapshot.py writes the lines' hash on
_KEY = re.compile(r"[A-Z][A-Za-z0-9 ]{0,20}")  # a header line's `Key:` (Source, Read from, Licence ...)


class SnapshotError(ValueError):
    """The snapshot is not the file its header describes: a hand edit, or a cut copy."""


def parse(text: str) -> tuple[dict[str, str], dict[str, str]]:
    """(the header's `Key: value` lines, domain -> company) of a snapshot's text. SnapshotError when a
    line is neither a comment nor `domain<TAB>company`, or when the lines' sha256 is not the one the
    header records."""
    header: dict[str, str] = {}
    table: dict[str, str] = {}
    lines = text.splitlines(keepends=True)
    body = [line for line in lines if not line.startswith("#")]
    for line in lines:
        if line.startswith("#"):
            key, sep, value = line[1:].strip().partition(": ")
            if sep and _KEY.fullmatch(key):
                header[key] = value.strip()
            continue
        domain, tab, name = line.rstrip("\n").partition("\t")
        if not tab or not domain or not name or "\t" in name:
            raise SnapshotError(f"{DATA}: not a domain and a company: {line[:80]!r}")
        table[domain] = name
    found = hashlib.sha256("".join(body).encode("utf-8")).hexdigest()
    if header.get(BODY_HASH[2:-2]) != found:
        raise SnapshotError(f"{DATA}: its lines do not match the hash its header records")
    return header, table


@functools.lru_cache(maxsize=1)
def _load() -> tuple[dict[str, str], dict[str, str], str | None]:
    try:
        text = (resources.files("tvgw") / "data" / DATA).read_text(encoding="utf-8")
        return (*parse(text), None)
    except (OSError, UnicodeDecodeError, SnapshotError) as e:
        return {}, {}, str(e)


def snapshot() -> tuple[dict[str, str], dict[str, str]]:
    """The shipped snapshot, read and checked once per process. One that is missing or does not match
    its hash is an empty table, so every name says nothing and nothing that names companies fails:
    the brief, `tvgw check` and `tvgw refused` print what they printed before the snapshot existed.
    `trouble()` says why."""
    header, table, _ = _load()
    return header, table


def trouble() -> str | None:
    """Why the shipped snapshot could not be read, or None when it was."""
    return _load()[2]


def company(name: str, table: dict[str, str] | None = None) -> str | None:
    """The company behind `name`: the snapshot's entry for the name itself, else for the nearest domain
    above it (`us.lgtvsdp.com` takes `lgtvsdp.com`'s), down to two labels and never to or past a public
    suffix (`names.PUBLIC_SUFFIXES`). None when no entry covers it. `table` stands in for the shipped
    snapshot."""
    entries = snapshot()[1] if table is None else table
    n = normalize(name or "")
    while "." in n:
        if n in PUBLIC_SUFFIXES:  # the names below are customers', each its own registrable domain
            return None
        hit = entries.get(n)
        if hit is not None:
            return hit
        n = n.partition(".")[2]
    return None
