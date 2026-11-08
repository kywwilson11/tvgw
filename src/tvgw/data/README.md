# Data shipped with the package

This folder holds data files that ship inside the package, read when a command runs and never fetched at run time: today, tvgw's snapshot of AdGuard's companies database, which names the company behind a host in `tvgw check`, `tvgw refused` and the plain brief. The snapshot is third-party data under its own licence, not tvgw's code; what it is for is in [the commands](../../../docs/reference/commands.md) and [the plain brief](../../../docs/reference/brief-sections.md#the-plain-brief).

## Files

| File | What it is | Used by |
|---|---|---|
| `__init__.py` | Makes the folder a package, so `importlib.resources` finds the file inside the installed package. | `companies.snapshot()` |
| `companies.txt` | One line per domain: the domain, a tab and the name of the company behind it, from AdGuard's companies database at one commit. Its header names that commit, the SHA-256 and git blob id of each file it was read from and whether those were checked against the commit, the database's own `timeUpdated`, the Public Suffix List's commit it was filtered with, the licence, the copyright holders, the attribution and every change tvgw made, and ends with the SHA-256 of the lines below it. Licensed CC BY-SA 4.0, not MIT. | `companies.company()`, through `namecheck`, `refused` and `plain`; written by `tools/companies_snapshot.py` |

`[tool.setuptools.package-data]` in pyproject.toml ships `data/*.txt`. The package says the file's licence beside tvgw's own: pyproject.toml's `license = "MIT AND CC-BY-SA-4.0"` and its `license-files`, which put `NOTICE` in the wheel; the .deb's `copyright` (packaging/copyright), whose `Files:` entry names this file, and its `NOTICE`; and the front page.

## The licence

The source is the [AdGuard Companies DB](https://github.com/AdguardTeam/companiesdb), licensed [Creative Commons Attribution-ShareAlike 4.0 International](https://creativecommons.org/licenses/by-sa/4.0/) (read on 2026-11-05). It builds on [WhoTracks.Me](https://github.com/whotracksme/whotracks.me) by Ghostery, whose data is CC BY 4.0. The source gives no copyright notice line; the header names AdGuard and Ghostery as the holders. The licence allows the snapshot here on four conditions, which the file's header meets and which hold for anyone who copies it:

- **Attribution.** The header credits AdGuard and WhoTracks.Me, links the source and the licence, and implies no endorsement.
- **Changes said.** The header says what tvgw changed: only each domain and its company's name are kept; the domains whose tracker names no company, those of the `cdn` and `hosting` categories, six carriers' domains by name, those that are, or sit above, a private-section public suffix, and those that are not internet names are left out; each company's name is cleaned to one printable line of at most 80 characters; and the lines are sorted.
- **ShareAlike.** The file stays under CC BY-SA 4.0. tvgw's MIT licence covers its code, which reads the file; it does not cover the file, and the file is never merged into code.
- **No warranty.** The header says the data comes as-is.

## How a name is looked up

`companies.company(name)` takes the entry for the name itself, else for the nearest domain above it, down to two labels: `us.lgtvsdp.com` takes `lgtvsdp.com`'s. The walk stops at a domain in `names.PUBLIC_SUFFIXES`, tvgw's own short list of suffixes under which every name is a different customer's (`azurewebsites.net`, `herokuapp.com`, `github.io` and others), as `names.registrable_domain()` treats them. A name no entry covers gets None, and every caller then says nothing about its company. Nothing is guessed from the words of a name. Most names a TV looks up have no entry, a well-known operator's too: the database lists trackers and their companies, not every service, and tvgw adds no entry by hand, so the file stays the database's at its commit. Three kinds of rows are left out because a carrier's domain is every tenant's, and its company would be credited with each customer's name: the `cdn` and `hosting` categories (`cloudfront.net` would name Amazon for a host Amazon only carries); a row that is, or sits above, a suffix in the private section of the [Public Suffix List](https://github.com/publicsuffix/list) (`azurewebsites.net`, `windows.net` above `blob.core.windows.net`, `githubusercontent.com`, `myshopify.com`), which the tool reads at a pinned commit, MPL 2.0, and of which no part is in the file; and six carriers' domains the list does not name, by hand (`CARRIERS_BY_HAND` in the tool: `firebaseio.com`, `footprint.net`, `hwcdn.net`, `msecnd.net`, `wordpress.com`, `wpengine.com`). A tenant's own row under a carrier, such as one `cloudfront.net` host a tracker uses, is kept.

`companies.snapshot()` reads the file once per process and checks it with `companies.parse()`, which raises `SnapshotError` when a line is not a domain and a company, or when the lines' SHA-256 is not the one the header records, so a hand edit or a cut copy is refused rather than read.

## Changing it

Never edit `companies.txt` by hand. On your workstation, write it again from a newer commit of the database, then run the gate:

```sh
python3 tools/companies_snapshot.py --commit <commit> --psl-commit <commit>
make gate
```

The tool fetches the database's `dist/trackers.json` and `dist/companies.json` at `--commit` and `public_suffix_list.dat` at `--psl-commit`, and checks each against the git blob id GitHub's contents API gives for it at that commit. `--from <folder>` reads the three files from a folder instead, and records their blob ids unchecked. It prints how many domains it left out, by reason. It fails when an input is not the database's shape (the `cdn` and `hosting` categories gone, most trackers without a `companyId`, fewer than 1,000 rows kept, no private section in the suffix list), and refuses a row count more than 20% from the file's (`SWING`) without `--accept-swing`. `--check` compares instead of writing. `tests/unit/test_companies.py` holds the shipped file to its header, the lookup to its rules and the tool to its output; the brief's tests in `tests/unit/test_plain.py` and the check and refused tests name companies the shipped file holds, so a newer snapshot that renames one fails them until they are updated with it.
