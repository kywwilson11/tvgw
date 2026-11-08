# Working on tvgw

This page is the map of the repository for contributors and the maintainer: what each folder holds and the README that describes it, and the records and how to add to them. How to set up a working copy and get a change merged is in [CONTRIBUTING.md](../../CONTRIBUTING.md), and the rules every page follows are in [writing these pages](writing-docs.md).

## Repository map

| Folder | What it holds | README |
|---|---|---|
| repository root | The front page, `CHANGELOG.md`, `LICENSE`, (companies) `NOTICE` (the companies snapshot's own licence, CC BY-SA 4.0), the `Makefile`, `pyproject.toml`, `mkdocs.yml` (the documentation site's configuration), and the community files: `CONTRIBUTING.md` (setting up, the gate, the house rules, how a change lands), `SECURITY.md` (what to report privately and how), `CODE_OF_CONDUCT.md` and `CITATION.cff`. | [README.md](../../README.md) |
| `.github/` | `dependabot.yml`, which proposes weekly bumps of the GitHub Actions and Python dependencies, `actionlint.yaml`, the runner label `actionlint` should accept, `PULL_REQUEST_TEMPLATE.md`, the checklist every pull request fills in, and `release-notes.md.in`, the template of a release's notes ([the changelog's Highlights and Status](packaging.md#the-changelogs-highlights-and-status)). | [docs/project/supply-chain.md](supply-chain.md) |
| `.github/ISSUE_TEMPLATE/` | The issue forms (a bug, a feature, a report from another TV) and `config.yml`, which turns blank issues off and sends questions to Discussions and security reports to `SECURITY.md`. | none; how to report is in [CONTRIBUTING.md](../../CONTRIBUTING.md) and [SECURITY.md](../../SECURITY.md) |
| `.github/workflows/` | `ci.yml`, the CI workflow; `virtual.yml`, the virtual gateway on both architectures and with other interface names ([the virtual gateway](../../tests/virtual/README.md)); `distro.yml`, the platform check in four distributions on both architectures ([packaging](packaging.md#the-platform-check)); `release.yml`, which builds the .deb for both architectures and, on a tag, publishes the release with `get.sh` ([packaging](packaging.md#releases)); `pages.yml`, which builds and publishes the documentation site ([the documentation site](../site/README.md)). | none; the wiring is in [how a change reaches the gateway](../../deploy/README.md#how-a-change-reaches-the-gateway), the rules every workflow follows are in [project/supply-chain.md](supply-chain.md#adding-or-changing-a-workflow) |
| `deploy/` | `install.sh`, `sync-install.sh` (takes the install lock, replaces `/opt/tvgw/src` and runs `install.sh`), the settings template `tvgw.conf.example` and `rsync.exclude`. | [deploy/README.md](../../deploy/README.md) |
| `deploy/bin/` | `tvgw-analyze` and `tvgw-doh-update`. | [deploy/bin/README.md](../../deploy/bin/README.md) |
| `deploy/dnsmasq/` | The DHCP template and dnsmasq's hardening drop-in. | [deploy/dnsmasq/README.md](../../deploy/dnsmasq/README.md) |
| `deploy/journald/` | The journal drop-in template. | [deploy/journald/README.md](../../deploy/journald/README.md) |
| `deploy/logrotate/` | The rotation config for the gateway's logs. | [deploy/logrotate/README.md](../../deploy/logrotate/README.md) |
| `deploy/networkmanager/` | The NetworkManager config and dispatcher script. | [deploy/networkmanager/README.md](../../deploy/networkmanager/README.md) |
| `deploy/nftables/` | `tvgw-apply`, `block4.txt`, `doh-exclude.txt` and the guard's template `guard.nft.template`. | [deploy/nftables/README.md](../../deploy/nftables/README.md) |
| `deploy/nginx/` | The URL filter and the TLS passthrough config, and nginx's sandbox lines. | [deploy/nginx/README.md](../../deploy/nginx/README.md) |
| `deploy/sysctl/` | `60-tvgw.conf`, the conntrack switches. | [deploy/sysctl/README.md](../../deploy/sysctl/README.md) |
| `deploy/systemd/` | Fourteen services and eight timers. | [deploy/systemd/README.md](../../deploy/systemd/README.md) |
| `docs/` | The documentation: the landing page, the user sections (`install/`, `use/`, `tv/`), `how-it-works/`, `reference/`, `project/`, and the records. | [docs/README.md](../README.md) |
| `docs/diagrams/` | The figures: one HTML file each with its light and dark PNG, the shared `diagram.css`, `wires.js`, icon and illustration sprites, the vendored fonts, and `build.py`, which renders them. | [docs/diagrams/STYLE.md](../diagrams/STYLE.md) |
| `docs/research/` | The dated proposals. | [docs/research/README.md](../research/README.md) |
| `docs/site/` | What builds the documentation site from these pages: the prebuild, the HTML and command checks, and the generator's pin and hash lock. | [docs/site/README.md](../site/README.md) |
| `packaging/` | The .deb's nfpm config, maintainer scripts, hash-pinned lock, wheelhouse builder and build script; the installer template `get.sh.in`, the release scripts, `release_notes.py`, and the platform check `check-platform.sh`. | [packaging/README.md](../../packaging/README.md) |
| `src/tvgw/` | The Python package. | [src/tvgw/README.md](../../src/tvgw/README.md) |
| `src/tvgw/profiles/` | The bundled profiles, each a `.toml` and a `.rules` file. | [src/tvgw/profiles/README.md](../../src/tvgw/profiles/README.md) |
| `tests/` | The test suites. | [tests/README.md](../../tests/README.md) |
| `tests/corpora/` | The extractor's golden corpus and its builder. | [tests/corpora/README.md](../../tests/corpora/README.md) |
| `tests/hardware/` | `test_gateway.py`, run on the gateway. | [tests/hardware/README.md](../../tests/hardware/README.md) |
| `tests/unit/` | The unit tests and `conftest.py`. | [tests/unit/README.md](../../tests/unit/README.md) |
| `tests/virtual/` | The virtual gateway suite and its reachability matrix. | [tests/virtual/README.md](../../tests/virtual/README.md) |
| `tools/` | `check_deploy_window.py`, which `make gate` and CI's hardware job run, `wait_deploy_window.py`, in which that job waits for the quiet window, `check_docs_links.py` and `docgen.py`, whose checks `make gate` runs, and `rewrite_doc_paths.py` with the page map it applies, `page-map.csv`. | [tools/README.md](../../tools/README.md) |

## Folder READMEs

| README | What it owns |
|---|---|
| [README.md](../../README.md) | The front page: what tvgw is, and where its pages are. |
| [deploy/README.md](../../deploy/README.md) | The installer, the files it installs, and how a change reaches the gateway. |
| [deploy/bin/README.md](../../deploy/bin/README.md) | The shell jobs the timers run. |
| [deploy/dnsmasq/README.md](../../deploy/dnsmasq/README.md) | DHCP for the TV. |
| [deploy/journald/README.md](../../deploy/journald/README.md) | The journal drop-in and how long the journal keeps its entries. |
| [deploy/logrotate/README.md](../../deploy/logrotate/README.md) | Rotation of the gateway's logs. |
| [deploy/networkmanager/README.md](../../deploy/networkmanager/README.md) | The TV interface and the dispatcher that re-applies the firewall when a link changes. |
| [deploy/nftables/README.md](../../deploy/nftables/README.md) | The firewall, rule by rule. |
| [deploy/nginx/README.md](../../deploy/nginx/README.md) | The URL filter, the TLS passthrough and nginx's sandbox. |
| [deploy/sysctl/README.md](../../deploy/sysctl/README.md) | The conntrack switches the flow log needs from boot. |
| [deploy/systemd/README.md](../../deploy/systemd/README.md) | Every unit with its schedule, user and timeout. |
| [docs/demo/README.md](../demo/README.md) | The terminal recording of `tvgw verify` and the daily brief, as an asciicast and a GIF, and how to play it. |
| [docs/diagrams/STYLE.md](../diagrams/STYLE.md) | The figure system: how a figure is drawn in HTML, rendered to light and dark PNGs and embedded in a page; [diagrams/RESEARCH.md](../diagrams/RESEARCH.md) says why the figures are HTML. |
| [docs/research/README.md](../research/README.md) | The folder of dated proposals, none of which is a decision. |
| [docs/site/README.md](../site/README.md) | The documentation site: how it is built from these pages, when it publishes, and how the owner turns it on. |
| [packaging/README.md](../../packaging/README.md) | The files that build the .deb and a release: the nfpm config, the maintainer scripts, the lock, the wheelhouse builder, the installer template, the release scripts and the notes writer. |
| [src/tvgw/README.md](../../src/tvgw/README.md) | The Python package, module by module, the rules of its code, and how to extend it. |
| [src/tvgw/profiles/README.md](../../src/tvgw/profiles/README.md) | The bundled profiles, `lg-webos` and the DNS-only Samsung, Roku and Vizio ones, and where their evidence came from. |
| [tests/README.md](../../tests/README.md) | The kinds of tests and when each runs. |
| [tests/corpora/README.md](../../tests/corpora/README.md) | The extractor's golden corpus: synthesised ClientHello pcaps, their tshark rows and the expected hellos. |
| [tests/hardware/README.md](../../tests/hardware/README.md) | The hardware suite that runs on the gateway. |
| [tests/unit/README.md](../../tests/unit/README.md) | The unit tests and their fixtures. |
| [tests/virtual/README.md](../../tests/virtual/README.md) | The virtual gateway: the namespace topology, the reachability matrix and how to run it in a VM. |
| [tools/README.md](../../tools/README.md) | The repository's own checks: which commits wait for the gateway's quiet window, and the trailer they carry; every link, anchor and docs path the code names; the tables the docs copy from the code, and how they are written. |

## Records

Four kinds of text are records rather than pages. Pages describe the code now; records keep what was decided, what broke, what changed and what was proposed. A record's text never changes: when a page moves, its links are rewritten to the page's new home and nothing else ([moving a page](../../tools/README.md#moving-a-page)).

- [design-decisions.md](../design-decisions.md) is append-only. To record a choice that someone would otherwise undo by accident, add a numbered entry with its context, decision and consequences. To reverse a decision, keep the old entry and add a new one that says so.
- [incidents.md](../incidents.md) lists what broke on a running gateway, newest first. Add an entry for any outage and for any near miss, using the template at its top: date and title, impact, detection, root cause, fix, lesson.
- [CHANGELOG.md](../../CHANGELOG.md) lists the changes since each release. A version's section, and "Unreleased", starts with `### Highlights` (three to six plain bullets) and `### Status` (one paragraph on what was tested), which are the release page's text ([the changelog's Highlights and Status](packaging.md#the-changelogs-highlights-and-status)). Add a line under the matching dated section of "Unreleased", after those two.
- [research/](../research/README.md) holds dated proposals, which are not decisions. Add one as a new file named for its topic and month, with its date and status at the top, and list it in [the research folder's README](../research/README.md).
