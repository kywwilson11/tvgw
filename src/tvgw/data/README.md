# Data shipped with the package

This folder holds data files that ship inside the package, read when a command runs and never fetched at run time: today, tvgw's snapshot of AdGuard's companies database, which names the company behind a host in `tvgw check`, `tvgw refused` and the plain brief. The snapshot is third-party data under its own licence, not tvgw's code; what it is for is in [the commands](../../../docs/reference/commands.md) and [the plain brief](../../../docs/reference/brief-sections.md#the-plain-brief).

## Files

| File | What it is | Used by |
|---|---|---|
| `__init__.py` | Makes the folder a package, so `importlib.resources` finds the file inside the installed package. | `companies.snapshot()` |
| `companies.txt` | One line per domain: the domain, a tab and the name of the company behind it, from AdGuard's companies database at one commit. Its header names that commit, the SHA-256 of each file it was read from, the database's own `timeUpdated`, the licence, the attribution and what tvgw changed, and ends with the SHA-256 of the lines below it. Licensed CC BY-SA 4.0, not MIT. | `companies.company()`, through `namecheck`, `refused` and `plain`; written by `tools/companies_snapshot.py` |

`[tool.setuptools.package-data]` in pyproject.toml ships `data/*.txt`.

## The licence

The source is the [AdGuard Companies DB](https://github.com/AdguardTeam/companiesdb), licensed [Creative Commons Attribution-ShareAlike 4.0 International](https://creativecommons.org/licenses/by-sa/4.0/) (read on 2026-11-05). It builds on [WhoTracks.Me](https://github.com/whotracksme/whotracks.me) by Ghostery, whose data is CC BY 4.0. The licence allows the snapshot here on four conditions, which the file's header meets and which hold for anyone who copies it:

- **Attribution.** The header credits AdGuard and WhoTracks.Me, links the source and the licence, and implies no endorsement.
- **Changes said.** The header says what tvgw changed: only each domain and its company's name are kept, the domains of the `cdn` and `hosting` categories are left out, each name is cleaned to one line, and the lines are sorted.
- **ShareAlike.** The file stays under CC BY-SA 4.0. tvgw's MIT licence covers its code, which reads the file; it does not cover the file, and the file is never merged into code.
- **No warranty.** The header says the data comes as-is.

## How a name is looked up

`companies.company(name)` takes the entry for the name itself, else for the nearest domain above it, down to two labels: `us.lgtvsdp.com` takes `lgtvsdp.com`'s. A name no entry covers gets None, and every caller then says nothing about its company. Nothing is guessed from the words of a name. The `cdn` and `hosting` rows are left out because a carrier's domain is every tenant's: `cloudfront.net` would name Amazon for a host Amazon only carries. A tenant's own row under a carrier, such as one `cloudfront.net` host a tracker uses, is kept.

`companies.snapshot()` reads the file once per process and checks it with `companies.parse()`, which raises `SnapshotError` when a line is not a domain and a company, or when the lines' SHA-256 is not the one the header records, so a hand edit or a cut copy is refused rather than read.

## Changing it

Never edit `companies.txt` by hand. On your workstation, write it again from a newer commit of the database, then run the gate:

```sh
python3 tools/companies_snapshot.py --commit <commit>
make gate
```

`--from <folder>` reads `trackers.json` and `companies.json` from a folder instead of fetching the commit's `dist/` files, and `--check` compares instead of writing. `tests/unit/test_companies.py` holds the shipped file to its header, the lookup to its rules and the tool to its output; the brief's tests in `tests/unit/test_plain.py` and the check and refused tests name companies the shipped file holds, so a newer snapshot that renames one fails them until they are updated with it.
