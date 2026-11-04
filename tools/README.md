# Repository tools

This folder holds the scripts that check or change the repository itself rather than the gateway. The checks run on your workstation from `make gate`, in CI's `test` job, and, for the deploy window, in CI's `hardware` job before a deploy; the page mover runs only when someone runs it. None of them is installed on the gateway. The deploy window they serve is explained in [the quiet window](../deploy/README.md#the-quiet-window).

## Files

| File | What it is | Used by |
|---|---|---|
| `check_deploy_window.py` | Finds the commits that change how the gateway treats the TV and checks that each carries the trailer `Deploy-window: tv-off`; for a push, says whether its deploy waits for the quiet window. Standard library and git's read commands only. | `make gate` (`--base`, default `origin/main`); CI's `hardware` job (`--deploy <before>`) |
| `check_docs_links.py` | Checks that every link and anchor in the repository's Markdown resolves, and every Markdown path the other files name, so a page cannot move and leave a pointer behind. Standard library and `git ls-files` only. | `make gate` and `make links`; `tests/unit/test_docs_links.py` |
| `page-map.csv` | The documentation's page map: one row per moved, merged, split, cut or new section, with its old path and anchor, its new path and anchor, the action and a note. | `rewrite_doc_paths.py` |
| `rewrite_doc_paths.py` | Moves the pages the page map moves with `git mv`, and rewrites every link, anchor and named docs path that pointed at them; writes the stubs and the placeholder pages. Standard library, `git ls-files` and `git mv` only. | By hand, after a rebase or after a section was moved; `tests/unit/test_rewrite_doc_paths.py`, which also fails while the tree does not follow the map |

## What counts as a change that waits

A commit waits for the window, and must say so, when it changes any of these ([design decision 63](../docs/design-decisions.md#63-behavior-changing-deploys-to-the-reference-wait-for-a-quiet-window-decided-on-the-gateway-nothing-the-gateway-prints-where-others-can-read-it-carries-a-home-identifier-acceptance-that-needs-systemd-runs-in-a-container-tier)):

| What | How the script tells | Why |
|---|---|---|
| A file under `deploy/nftables/`, `deploy/networkmanager/`, `deploy/dnsmasq/`, `deploy/nginx/` or `src/tvgw/tvapi/` | The path, by its prefix (`PREFIXES`); a `.md` file is never one | The firewall, the TV port, DHCP, the URL filter and the TV's LAN APIs |
| The `[firewall]` or `[url_filter]` table of a profile in `src/tvgw/profiles/` | Both versions of the file read as TOML and the two tables compared (`PROFILE_TABLES`); a file that is not TOML counts as changed | The rules the gateway renders from them |
| The routing and dnsmasq parts of `deploy/install.sh` | A changed line of `git diff -U0`, or the context line git names for its hunk (the function it sits in), that matches `INSTALL_PARTS`: dnsmasq, NetworkManager, `nmcli`, `tv-lan`, `tv_side`, `tvgw-net`, `ip route`, `ip rule`, `sysctl`, `ip_forward` or `tvgw-apply` | The steps that bring the TV port up, hand out its address and load its routes |

The gate reads each commit since its merge base with `--base` on its own, merges aside, so a trailer on one commit never covers another. The deploy reading takes the whole push: any commit with the trailer, or a change of the kinds above in the push's combined diff, makes it `tv-off`. A `before` that is all zeros or not a commit in the checkout is `tv-off` too, since the push cannot be read. Both readings list a moved file under its old path and its new one (`--no-renames`), so a file moved out of a folder that waits still waits.

## What the link check reads

The files are what `git ls-files --cached --others --exclude-standard` lists: tracked, or new and not ignored. A page counts before `git add`, and a file git ignores counts as missing, as it is on GitHub. A folder that is not a git checkout is walked instead, leaving out version-control, virtualenv, cache and build folders (`SKIP_DIRS`).

| What | Where | The rule |
|---|---|---|
| Inline links and images, reference definitions, and the `href`, `src` and `srcset` of HTML such as a figure's `<picture>` | Every Markdown file | The target is a listed file or folder, written from the linking file's folder; a leading `/` is the repository root, as on GitHub. Names are compared with their case, as GitHub compares them, even on a filesystem that ignores case. |
| A fragment (`#...`) | The same links | It is a heading of the target as GitHub slugs it: the rendered text (a code span's content, a link's label, no emphasis marks), lowercase, every character but a letter, digit, `_`, `-` or space removed, each space a hyphen, and a repeated slug numbered `-1`, `-2` in page order. An `id` or `name` attribute counts too. A folder's fragment is its README's; a fragment of a file that is not Markdown (`#L12`) is not checked. |
| A repository Markdown path such as `docs/<page>.md#<anchor>`, or `./docs/<page>.md` as `nfpm.yaml` writes it | Every other listed file: code, deployed files, the settings template, workflows, issue forms, tests, the Makefile. Not `page-map.csv` and `rewrite_doc_paths.py`, which name both ends of each move (`UNREAD`). | It resolves from the repository root, with its fragment. A path after `/`, `.`, `-` or a word character (`../docs/...`, `/usr/share/doc/tvgw/...`, a URL) is relative to something else and is not read, and a name with another extension after `.md` (`.github/release-notes.md.in`) is another kind of file. |
| A link to this repository's `main` branch on GitHub (`blob`, `tree` or `raw`, or `raw.githubusercontent.com`) | Markdown and every other file | It is checked as the path it names. A tag or a commit pins a tree in which a file may rightly be elsewhere, so those are not. |

Fenced code blocks (backticks or tildes, at any indent) and code spans are examples, not links, and are skipped; so are links to other sites and mail addresses.

## Moving a page

The page map says where each section of the documentation goes. `rewrite_doc_paths.py` does what needs no judgement and may run again at any time:

| What | The rule |
|---|---|
| A page | It moves whole with `git mv`: to the new path of its row without an anchor, or, when the map only splits it, to the new path of its first row. The sections other rows send elsewhere stay in the moved page until someone moves them by hand; nothing here cuts a page apart. |
| A relative link in a Markdown file | It follows the page it points at, and a moved page's own links are written again from its new folder: inline links, reference definitions, and the `href`, `src` and `srcset` of a figure's `<picture>`. A link that now leads to a section of its own page is written as the anchor alone (`#<anchor>`). |
| A record (`CHANGELOG.md`, the design decisions, the incident log, `docs/research/`) | Its links follow and nothing else changes: the label of a link and every path written as text stay as written. |
| Any other Markdown page | A repository path written as text (in a list, a table or a code span) follows too, and so does a link label that repeats its link's path. Fenced code blocks are examples and stay as they are. |
| A docs path in a file that is not Markdown | It follows, with its `./` and its anchor: messages and comments in `src/` and `deploy/`, nfpm's `./docs/...`, workflows, issue forms, tests, and `"docs" / "<page>.md"` in Python. |
| An anchor | It follows its section. A pointer to a section the map sends elsewhere points where the section is now: at the page it moved with, until its anchor is gone from there and present at the map's new home. A subsection's anchor follows when exactly one of the pages the map sends that page's sections to holds it. A pointer to a section that is nowhere yet is left for the link check to name. |
| A page that a release prints (`STUBS`) | Its old path keeps a stub: its H1 and one sentence linking the new home, written when the page moves. Once the page is split, the sentence is edited by hand to name where each section went, the ones a release prints first. Nothing links to a stub; a pointer written at the old path later goes to the new home. A path leaves `STUBS`, and its stub the tree, once no supported release prints it. |
| A new page of the map (`PLACEHOLDERS`) | When it is missing it gets its H1 and a short lead, each sentence of a user page's lead at most 18 words; a page that exists is never touched. |

The tree and the map must agree: a page at both its old and its new path stops the run with nothing changed (merge the two by hand, then run it again), and a page at neither is reported and skipped.

On your workstation:

```sh
python3 tools/rewrite_doc_paths.py --check      # what it would move, create and rewrite; exit 1 if anything
python3 tools/rewrite_doc_paths.py --no-stubs   # the moves and rewrites alone: commit them, so git records renames
python3 tools/rewrite_doc_paths.py              # then the stubs, in a commit of their own
make links                                      # every pointer resolves
```

After a rebase onto a branch that moved pages, run it once: links and paths your branch wrote against the old paths follow. A page your branch edited that now holds a stub conflicts at the stub, since git sees a changed file there rather than a rename; carry the edit to the new path by hand. A rewrite can make a line in `src/` longer than the 110 columns ruff allows; wrap it by hand.

## Checking it

On your workstation:

```sh
python3 tools/check_deploy_window.py                     # the gate's check against origin/main
python3 tools/check_deploy_window.py --base <branch>     # against another base
python3 -I tools/check_deploy_window.py --deploy <sha>   # what CI would decide for a push after <sha>
make links                                               # every link, anchor and named docs path
```

A gate that finds a commit prints one line for it:

```text
check_deploy_window: 0123456789ab tvgw-apply: a rule: changes deploy/nftables/tvgw-apply
```

The link check prints one line for each pointer that leads nowhere, with its file and line, then a count on standard error, and exits 1:

```text
deploy/tvgw.conf.example:150: docs/privacy-and-retention.md#the-levers: no heading #the-levers in docs/privacy-and-retention.md
packaging/nfpm.yaml:66: ./docs/packaging.md: no such file
check_docs_links: 2 pointers lead nowhere
```

With nothing broken it prints one line, with how many Markdown files, links and named paths it read, and exits 0. It exits 2 when git cannot list a checkout's files.

## Changing it

For the deploy window, add a path or a pattern in `check_deploy_window.py` and a case in `tests/unit/test_check_deploy_window.py`, which builds throwaway repositories and checks each kind of change, the trailer, merges and the deploy reading. The test also fails when a folder in `PREFIXES` or a function `INSTALL_PARTS` names is gone from the tree, so a rename cannot leave the check blind. Change the deploy window's own description in [the quiet window](../deploy/README.md#the-quiet-window) in the same commit.

For the page map, edit `page-map.csv`, then run `rewrite_doc_paths.py` and commit what it changed with the map. For the page mover itself, add a case to `tests/unit/test_rewrite_doc_paths.py`, whose fixtures write `@/` for `docs/` so that the link check and the mover never take a fixture's page for the repository's.

For the link check, change the patterns in `check_docs_links.py` and add a case to `tests/unit/test_docs_links.py`. That file checks the repository itself, page by page, and then each rule on a throwaway tree. Since the check reads the tests too, a test that writes a path that must not exist puts it in an f-string through a variable (`f"{DOCS}/gone.md"`).

## Gotchas

- A checkout without `origin/main` (a shallow clone, a tarball) checks nothing for the deploy window and says so; `make gate WINDOW_BASE=<branch>` compares with another branch.
- A commit already on `main` cannot gain a trailer. Until a commit that changed such a path without it is on `origin/main`, `make gate` names it on every branch that carries it.
- A squash merge must keep `Deploy-window: tv-off` as the last line of the squashed message: git reads trailers only from the message's final paragraph.
- The link check reads ATX headings (`## Title`), the only kind these pages use. GitHub also anchors a setext heading (a title underlined with `===` or `---`), but the check does not, so a link to one fails here.
- A fenced block that is never closed runs to the end of the page, so every link after it goes unchecked. GitHub renders the rest of the page as code too, which shows it.
- On a page that is not a record, a repository path written as text is a pointer, and the page mover rewrites it, so `tests/unit/test_rewrite_doc_paths.py` fails on an old path written in a sentence. An old path meant as history belongs in a record or a fenced block.
- A page the map only splits moves whole to its first row's page and keeps its old H1 there until its sections are moved by hand. Move a section by giving it the heading of its row's new anchor at its new home; the next run then points every link at it there.
- A section that the map sends elsewhere but that is better kept where it is (an engineering reference left on its page) gets its row changed to `keep`, or to `split` with a note when part of it goes; a pointer follows a section only once its anchor is gone from where it was.
