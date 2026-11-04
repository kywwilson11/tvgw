# Repository tools

This folder holds the scripts that check or change the repository itself rather than the gateway. The checks run on your workstation from `make gate`, in CI's `test` job, and, for the deploy window, in CI's `hardware` job before a deploy; the page mover runs only when someone runs it, and the table generator when a change needs its tables written again. None of them is installed on the gateway. The deploy window they serve is explained in [the quiet window](../deploy/README.md#the-quiet-window).

## Files

| File | What it is | Used by |
|---|---|---|
| `check_deploy_window.py` | Finds the commits that change how the gateway treats the TV and checks that each carries the trailer `Deploy-window: tv-off`; for a push, says whether its deploy waits for the quiet window. Standard library and git's read commands only. | `make gate` (`--base`, default `origin/main`); CI's `hardware` job (`--deploy <before>`) |
| `check_docs_links.py` | Checks that every link and anchor in the repository's Markdown resolves, and every Markdown path the other files name, so a page cannot move and leave a pointer behind. Standard library and `git ls-files` only. | `make gate` and `make links`; `tests/unit/test_docs_links.py` |
| `docgen.py` | Writes the documentation's tables that copy the code, between markers, from the profiles, `tvgw verify`'s checks and the brief's red lines; `--check` says which differ and writes nothing. Standard library and the checkout's own `src/` only. | `make docgen`; `make gate`, `make site` and the site workflow (`--check`); `tests/unit/test_docgen.py` and `tests/unit/test_verify_plain.py` |
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

## Generated tables

A table that copies the code by hand drifts from it, so `docgen.py` writes these from the code, between two markers, each alone on its line. Everything outside the markers stays as it is.

| Block | Page | Written from |
|---|---|---|
| `support-table` | README.md, docs/tv/README.md | Each bundled profile's `[support]` table (`status`, `tested_on`, `you_check`, and `does` for a TV read without pairing) and `[[generations]]` rows, in the order of `TV_NAMES`, and which profiles the gateway can pair with (`setup.PAIRABLE_PROFILES`) or reads without pairing (`setup.READ_WITHOUT_PAIRING`) |
| `profile-support` | src/tvgw/profiles/README.md | The same rows, with each one's profile |
| `generations profile=lg-webos` | docs/tv/lg-webos.md | The profile's `[[generations]]` rows: the years and models, the release the TV reports (`release_range`), the pairing that works (`manifest`, in `MANIFESTS`' words), the support level (the row's `support`, else as below) and how the row is known (`confidence`, in `KNOWN_BY`'s words); then a table of the rows' `menu` paths, one column per topic of `profile.MENU_TOPICS` that a row gives |
| `can-check profile=<name>` | docs/tv/<name>.md | "Nothing yet" for a TV the gateway cannot read; `READS`' list for one it pairs with (`setup.PAIRABLE_PROFILES`); for one it reads without pairing (`setup.READ_WITHOUT_PAIRING`), the profile's `[support] can_check` and `cannot_check` |
| `verify-checks` | docs/reference/verify-checks.md | `verify.GROUPS`, `verify.SETTLING` and `verify.PLAIN`, in run order, each command in a code span |
| `verify-new-checks` | docs/reference/verify-checks.md | `verify.FAIL_AFTER` and `verify.PROMOTED` |
| `red-lines` | docs/reference/brief-sections.md | `plain.RED_LINE_PLAIN`, and `plain.action_text()` for each profile's screen-recognition action |

The rules the tables follow:

| What | The rule |
|---|---|
| A marker | `<!-- generated:NAME -->`, or `<!-- generated:NAME profile=PROFILE -->` for a brand's block, alone on its line, then the block, then `<!-- /generated:NAME -->` alone on its line. A marker in a fenced block or a code span is an example and is not read. A comment that starts `generated:` in any other form, a marker inside another region, one never closed, a block docgen does not write, a missing or unknown parameter and a profile that is not bundled each stop the run with the page, the line and what to write instead, and nothing is written. |
| The pages | Every Markdown file of the tree, leaving out folders whose name starts with a dot (`.git`, `.claude` and its worktrees) and `SKIP_DIRS`: `build`, where the site copies the pages, `dist`, `venv`, `node_modules`, `mutants`, `backups` and `__pycache__`. A page without markers is never written. |
| A support level | The profile's `[support] status`. A profile with `[[generations]]` has one row per run of generations at one level, the strongest level first and within a level the newest run first: a generation is at its row's `support` where the row gives one, else at the profile's level where its row is `verified`, and not yet tested otherwise. The words are `profile.SUPPORT`'s; "Tested" names the sets in `tested_on`. |
| What tvgw does | For a TV the gateway can pair with, `READERS` holds the plain words per level, and `READS` the hourly reading's list, until a profile says what its reader reads. For a TV it reads without pairing, the profile's `[support] does`. A profile with no blocks of its own and no must-allow names blocks from shared lists only; any other blocks and reports. |
| What you check | `READERS`' words where it gives them, else the profile's `you_check`. |
| Order | No time, no set's order: the same code writes the same text. |

What it does not write, and why: a brand's radio steps, its privacy settings and its must-allow names stay hand-written on its page, because the profiles hold them in an engineer's words (`[checklist]`, `controls` and the must-allow reasons, with their sources) and the pages carry the plain ones. `tests/unit/test_docgen.py` holds those tables to the profiles instead: every must-allow name and every privacy setting's name and menu path must be on its brand's page. The daily brief's red lines on docs/use/daily-brief.md are sections of prose, not a table, and stay hand-written.

After a change to a profile, a check, its plain words or a red line, on your workstation:

```sh
make docgen          # writes every region that differs, and names each page it wrote
git diff             # read what changed; then commit it with the change
```

A new bundled profile needs its name in `TV_NAMES` in `docgen.py`; a profile the gateway learns to pair with needs its words in `READERS` and `READS`, and one it learns to read without pairing needs `does`, `can_check` and `cannot_check` in its `[support]`; until then the run stops and says so.

## Checking it

On your workstation:

```sh
python3 tools/check_deploy_window.py                     # the gate's check against origin/main
python3 tools/check_deploy_window.py --base <branch>     # against another base
python3 -I tools/check_deploy_window.py --deploy <sha>   # what CI would decide for a push after <sha>
make links                                               # every link, anchor and named docs path
python3 tools/docgen.py --check                          # every generated table is what the code writes
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

The table check prints one line for each region that differs from the code, then a count on standard error, and exits 1:

```text
README.md:52: support-table: differs from the code; run `make docgen`, then commit it
docgen: 1 of 11 generated regions differ from the code
```

With every region as the code writes it, it prints `docgen: 11 generated regions on 9 pages, all as the code has them` and exits 0. A marker it cannot read, or a block it cannot write, gives one line on standard error and exit 2, and nothing is written:

```text
docgen: docs/tv/roku.md:31: <!-- generated: can-check profile=roku --> is not a marker docgen can read: a marker stands alone on its line, as <!-- generated:NAME --> or <!-- generated:NAME profile=PROFILE -->; nothing was written
```

## Changing it

For the deploy window, add a path or a pattern in `check_deploy_window.py` and a case in `tests/unit/test_check_deploy_window.py`, which builds throwaway repositories and checks each kind of change, the trailer, merges and the deploy reading. The test also fails when a folder in `PREFIXES` or a function `INSTALL_PARTS` names is gone from the tree, so a rename cannot leave the check blind. Change the deploy window's own description in [the quiet window](../deploy/README.md#the-quiet-window) in the same commit.

For the page map, edit `page-map.csv`, then run `rewrite_doc_paths.py` and commit what it changed with the map. For the page mover itself, add a case to `tests/unit/test_rewrite_doc_paths.py`, whose fixtures write `@/` for `docs/` so that the link check and the mover never take a fixture's page for the repository's.

For a generated table, add its renderer to `BLOCKS` in `docgen.py`, its markers on the page and its row in `EXPECTED` and in the table above, and a case to `tests/unit/test_docgen.py`, which checks the repository's regions and then each rule on a throwaway tree. Write its words in the voice of the page it lands on: on a user page, the conventions' plain words ([writing the docs](../docs/project/writing-docs.md)).

For the link check, change the patterns in `check_docs_links.py` and add a case to `tests/unit/test_docs_links.py`. That file checks the repository itself, page by page, and then each rule on a throwaway tree. Since the check reads the tests too, a test that writes a path that must not exist puts it in an f-string through a variable (`f"{DOCS}/gone.md"`).

## Gotchas

- A generated region is written over whole: an edit inside one is lost at the next `make docgen`, and `make gate` fails on it until then. Change the code it comes from, or the words in `docgen.py`.
- `docgen.py` imports tvgw from its own checkout's `src/`, never an installed copy, so a worktree's run reads that worktree's profiles even when the editable install points at another checkout.
- A checkout without `origin/main` (a shallow clone, a tarball) checks nothing for the deploy window and says so; `make gate WINDOW_BASE=<branch>` compares with another branch.
- A commit already on `main` cannot gain a trailer. Until a commit that changed such a path without it is on `origin/main`, `make gate` names it on every branch that carries it.
- A squash merge must keep `Deploy-window: tv-off` as the last line of the squashed message: git reads trailers only from the message's final paragraph.
- The link check reads ATX headings (`## Title`), the only kind these pages use. GitHub also anchors a setext heading (a title underlined with `===` or `---`), but the check does not, so a link to one fails here.
- A fenced block that is never closed runs to the end of the page, so every link after it goes unchecked. GitHub renders the rest of the page as code too, which shows it.
- On a page that is not a record, a repository path written as text is a pointer, and the page mover rewrites it, so `tests/unit/test_rewrite_doc_paths.py` fails on an old path written in a sentence. An old path meant as history belongs in a record or a fenced block.
- A page the map only splits moves whole to its first row's page and keeps its old H1 there until its sections are moved by hand. Move a section by giving it the heading of its row's new anchor at its new home; the next run then points every link at it there.
- A section that the map sends elsewhere but that is better kept where it is (an engineering reference left on its page) gets its row changed to `keep`, or to `split` with a note when part of it goes; a pointer follows a section only once its anchor is gone from where it was.
