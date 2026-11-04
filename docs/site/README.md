# The documentation site

This folder holds what builds the documentation site at `https://kywwilson11.github.io/tvgw/` from the front page and `docs/`: the script that copies the pages into the site's source tree, the two checks that run on the result, and the generator's pin and hash lock. `.github/workflows/pages.yml` runs them on GitHub's runners for a pull request, a push to `main` and each release; `make site` runs them on your workstation. The site is a view of the same Markdown GitHub shows, never a second copy to edit, and it never shows a command the latest release lacks ([design decision 60](../design-decisions.md#60-the-documentation-is-organized-by-what-the-reader-wants-to-do-user-pages-are-written-for-a-non-engineer-the-site-is-a-view-of-docs-built-by-a-pinned-generator-never-showing-a-command-the-latest-release-lacks-and-github-stays-complete)). Nothing here is installed on the gateway or runs on it.

## Files

| File | What it is | Used by |
|---|---|---|
| `prebuild.py` | Copies `README.md` and `docs/` into `build/site-docs`: the front page becomes `index.md`, the landing page `map.md`, a link that leaves `docs/` (or names a file the site does not serve) goes to the file on GitHub at the commit built, and the badge row between `<!-- badges:start -->` and `<!-- badges:end -->` is dropped; with `--release`, one line takes its place, naming that release, linked, with the date of its `CHANGELOG.md` section. Fenced code and code spans are never rewritten. Standard library only. | `pages.yml`, `make site`; `tests/unit/test_site_prebuild.py` |
| `check_site.py` | Reads every built page: each local `href`, `src` and `srcset` must name a file of the site, and no page or stylesheet may fetch anything from another site (an image, a script, a stylesheet, a font, Google Fonts). Standard library only. | `pages.yml`, `make site`; `tests/unit/test_site_prebuild.py` |
| `check_commands.py` | Checks out a release's tag into a temporary git worktree, reads the command tree of its `tvgw.cli.build_parser()` in a child `python3 -I`, and fails when a user page names a command, a subcommand or an option that tree lacks, or an option alone (`--dry-run`) that only the checkout's own tree has. Exit 2 when it cannot check. Standard library and git only. | `pages.yml`, which publishes `main` only while it passes; `make site`, which reports it; `tests/unit/test_check_commands.py` |
| `requirements.in` | The generator, Zensical, pinned exactly. | `make lock` |
| `requirements.lock` | Zensical and its eleven dependencies, each with every file's hash PyPI publishes, for Python 3.11 and later on any platform. | `pages.yml` and `make site`, with `--require-hashes` |

The site's configuration is `mkdocs.yml` at the repository root, because Zensical refuses a `site_dir` outside the folder that holds it, and the workflow is `.github/workflows/pages.yml`.

## How the site is built

`pages.yml`'s `build` job, on `ubuntu-latest` with Python 3.13, runs these in order; `make site` runs the same steps in a venv of its own, `build/site-venv`.

1. `tools/check_docs_links.py`, the link check of `make gate`: every link, anchor and docs path the repository names resolves on GitHub ([the link check](../../tools/README.md#what-the-link-check-reads)).
2. `tools/docgen.py --check`, the table check of `make gate`: every table the pages copy from the code is what the code writes ([generated tables](../../tools/README.md#generated-tables)). A push to `main` that touches only the docs runs no `ci.yml`, so this is where a hand edit inside a generated region stops.
3. `pip install --require-hashes --no-deps -r docs/site/requirements.lock`.
4. `gh release view` names the latest release, and `prebuild.py --out build/site-docs --repo <repository URL> --ref <commit> --release <its tag>` copies the pages; the home page's line names that release. `make site` names the newest tag instead (`git describe --tags --abbrev=0`).
5. `zensical build --strict --clean`, from `mkdocs.yml`: any warning fails it, so a link, an anchor or a nav entry that leads nowhere on the site stops the build.
6. `check_site.py build/site --prefix /tvgw/`, since the strict build does not read raw HTML and every figure is a raw `<picture>`.
7. The publish gate (below), then the Pages artifact when the gate says yes.

The `deploy` job then publishes the artifact with `actions/deploy-pages`, with `pages: write` and `id-token: write` on that job alone, in the `github-pages` environment.

## When it publishes

| Event | The build | The deploy |
|---|---|---|
| A pull request that touches `docs/**`, `README.md`, `mkdocs.yml` or `pages.yml` | runs; the gate reports whether merging it would hold the site | never |
| A push to `main` that touches the same paths, or a manual run on `main` | runs | only while `check_commands.py --against <the latest release>` passes; otherwise the run ends with the notice "user pages name commands not yet released; the site updates with the next release", and the site stays at its last publish |
| A release `release.yml` published (a pushed tag) | `release.yml`'s `site` job starts a manual run on `main` once the release is published, because GitHub starts no workflow from a release a workflow's own token published | as for a manual run on `main`: while `main`'s head is the release's tag, every command the pages name is in the release and the site publishes; once `main` has moved past the tag, the command check decides. If the job cannot start the run, it ends with a warning that names `gh workflow run pages.yml --ref main --repo kywwilson11/tvgw`, and the release stands |
| A release a person published (on GitHub's release page, or with their own token) | runs from the release's tag | when the release is the latest one; a pre-release, or a patch to an older line, leaves the site as it is |

Every deploy also needs the repository variable `TVGW_PAGES` set to `on`, and runs only in `kywwilson11/tvgw`. Until the variable is set, the `deploy` job is skipped and the build still checks every change. The latest release is what `gh release view` names, so the pages a reader sees describe a version they can install.

## Turning it on

Owner-run, once, in the repository's settings on GitHub (the menu names as of 2026-11-03; no agent or workflow changes them):

1. **Settings, Pages, Build and deployment, Source:** "GitHub Actions". GitHub then creates the `github-pages` environment.
2. **Settings, Secrets and variables, Actions, Variables:** a repository variable `TVGW_PAGES` with the value `on`, or from a terminal:

   ```sh
   gh variable set TVGW_PAGES --body on --repo kywwilson11/tvgw
   ```

3. **Settings, Environments, `github-pages`, Deployment branches and tags:** if the rules name `main` alone, add the tag rule `v*`. Only a release a person publishes needs it: that release's run deploys from its tag, which a rule for branches refuses. A release `release.yml` publishes deploys from `main`.
4. Optionally, the site as the repository's homepage:

   ```sh
   gh repo edit kywwilson11/tvgw --homepage https://kywwilson11.github.io/tvgw/
   ```

The next push to `main` that touches the docs, or a manual run of `docs-site` on `main`, publishes the site, and from then on every release `release.yml` publishes starts that manual run itself. Setting `TVGW_PAGES` to anything else stops publishing and leaves the last publish in place.

## Checking it

On your computer, from a checkout:

```sh
make site                                                    # build/site: strict build, HTML check, command check
python3 -m http.server -d build/site 8000                    # then open http://localhost:8000/
python3 docs/site/check_commands.py --against v0.2.0         # the user pages against one release
```

`make site` makes `build/site-venv` from the lock the first time and again whenever the lock changes. Its last step reports the command check against the newest tag and does not fail the target: on `main`, a failing check holds the site rather than failing a build. Served from `build/site` the pages sit at the root rather than under `/tvgw/`, which changes nothing a reader sees: every link the build writes is relative, and only each page's canonical address names the published site.

## Changing it

- **The nav** is in `mkdocs.yml`: the seven sections of the landing page, docs/README.md, in its order and with its page names. A page added to the landing page goes into the nav in the same change; `tests/unit/test_site_prebuild.py` fails when the two disagree, or when a user page is not in the nav.
- **A user page that names a command from the next release** can merge: the site holds at its last publish until that release is out, then publishes with it. The pull request's gate says so.
- **Bumping the generator:** raise the pin in `requirements.in`, run `make lock` with the Makefile's uv, then `make site`; the pull request's strict build is the check. Zensical is alpha software ("Development Status :: 3 - Alpha"), so a bump is a deliberate change of its own, not a dependabot one: dependabot does not watch this lock.
- **The fallback generator:** `mkdocs.yml` uses only keys that Material for MkDocs 9.8.0 also reads, so `pip install mkdocs-material==9.8.0` and `mkdocs build --strict` build the same site, until Material's maintenance ends on 2027-05-05. Pin it by hash in this folder before a workflow uses it.
- **A box on a page** (GitHub's `> [!NOTE]` alert) needs the `github-callouts` extension: uncomment it in `mkdocs.yml` and add `markdown-callouts` to `requirements.in` in the same change.
- The tests: `tests/unit/test_site_prebuild.py` (the prebuild, the HTML check, the nav), `tests/unit/test_check_commands.py` (the command check, with throwaway git repositories), `tests/unit/test_supply_chain.py` (the workflow: pins, permissions, which jobs each event runs, the gate step run with stand-ins, and `release.yml` starting it on `main`) and `tests/unit/test_packaging.py` (the `site` job of `release.yml`, its step run with a stand-in `gh`).

## Gotchas

- **A release a workflow published starts no workflow.** GitHub creates no run for an event a job's `GITHUB_TOKEN` caused, `workflow_dispatch` and `repository_dispatch` excepted ([triggering a workflow from a workflow](https://docs.github.com/en/actions/how-tos/write-workflows/choose-when-workflows-run/trigger-a-workflow#triggering-a-workflow-from-a-workflow), read 2026-11-04). So 0.3.0's publish never fired `pages.yml`'s `release` trigger, and the site was published by hand. `release.yml`'s `site` job now sends the dispatch, with `actions: write` on that job alone; the `release` trigger stays for a release a person publishes, which does fire it.
- **Strict mode does not read raw HTML.** A figure's `<picture>` path that breaks on the site passes `zensical build --strict`; `check_site.py` is what catches it.
- **`use_directory_urls: false`.** Pages are `name.html`, not `name/index.html`: the figures' paths are relative to the page and no generator rewrites raw HTML, so a page one folder deeper would lose them.
- **The anchors are GitHub's.** `toc.slugify` is `pymdownx.slugs.slugify(case="lower")`, which keeps every hyphen as GitHub does (`--no-check-update` gives `---no-check-update`), so one link works on both. A heading the two would slug differently fails the strict build on the pull request, never on the live site.
- **`theme.font: false`.** Without it both generators make every reader's browser fetch fonts from Google; `check_site.py` refuses the result.
- **No light and dark toggle.** The site follows the reader's system setting, as GitHub shows the figures. `prebuild.py --picture-toggle` rewrites each `<picture>` into the image pair the theme's toggle switches; it stays off until it is checked on a published page.
- **The theme keeps the scheme of a reader's first visit** in the browser's storage, while each figure follows the system setting as it is now. A reader who switches their system between light and dark later sees light figures on a dark page, or the reverse, until the browser's data for the site is cleared (seen in headless Chrome, 2026-11-03).
- **One request to another site remains:** the header's repository widget asks `api.github.com` for the star count. Removing `repo_url` from `mkdocs.yml` removes it, and the header's link to GitHub with it.
- **The edit pencil on the home page and on `map.html` leads nowhere:** those pages are copies of `README.md` and `docs/README.md` under other names, and `edit_uri` maps a site page to `docs/` by its name.
- **The command check imports the tag's own `cli.py`,** with only the tag's `src/` on the path. A release whose `cli.py` imports a third-party module at load time makes the check exit 2 and the `main` build fail, visibly, rather than publish.
- **The checkout needs the tags:** `pages.yml` checks out with `fetch-depth: 0`, and `check_commands.py` exits 2 when the tag is not in the checkout.
- **Zensical keeps a build cache in `.cache/` at the repository root,** wherever it is run from. `.gitignore` and `deploy/rsync.exclude` leave it out of commits and of `make deploy`'s copy to the gateway, and `make clean` removes it.
- **Zensical's strict abort ends in a Python traceback.** The warnings printed above it name each page and line; the traceback says only that `--strict` stopped the build.
- **A push that changes only `docs/site/`** runs no unit tests on `main`, since `ci.yml` ignores `docs/**`; the pull request runs them, and `pages.yml` runs the scripts for real on every push that changes them.
