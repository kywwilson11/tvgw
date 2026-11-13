# Supply chain

This page says what the repository's automation is allowed to do, what stops it from doing more, and the settings that keep it that way. It is for the owner, who applies and changes the GitHub settings, and for anyone adding a workflow or a dependency. The research behind it is [section 10 of the state-of-the-art report](../research/state-of-the-art-2026-10.md#10-security-and-sandboxing); the decisions are [design decision 26](../design-decisions.md#26-the-workflows-are-the-most-privileged-code-in-the-repository), for the gateway [design decision 83](../design-decisions.md#83-no-job-of-any-workflow-runs-on-a-gateway-a-change-reaches-one-only-when-its-owner-deploys-it), and, for releases, [design decision 53](../design-decisions.md#53-releases-carry-a-hash-checked-bootstrap-for-two-architectures-with-provenance-under-immutable-releases-updates-are-checked-weekly-installed-only-by-the-user-judged-by-verify-and-rolled-back-a-new-settings-key-never-changes-the-meaning-of-an-old-keys-value).

## The threat in one paragraph

Until 2026-11-11 a push to `main` ran the `hardware` job on the reference gateway, through a self-hosted runner whose login had unrestricted password-free `sudo`, for a public repository: one approved pull request that edited a workflow, or one push made with a stolen token, would have run as root on the machine that holds the TV's firewall, the DNS filter and the store of what the TV did, inside the home network. That route is closed: no job of any workflow runs on a gateway, and a change reaches one only when its owner runs `make deploy` ([design decision 83](../design-decisions.md#83-no-job-of-any-workflow-runs-on-a-gateway-a-change-reaches-one-only-when-its-owner-deploys-it)). What the automation can still reach is the repository and its releases, which every gateway installs from. Three routes lead there: a third-party action that changed under a tag the workflow trusted, a pull request (a fork's, or a branch's) that runs its own code in a workflow, and a stolen or careless push to `main`. The rest of this page closes each, and says plainly what stays open.

## What is in place

| Control | Where | What it stops |
|---|---|---|
| Every action pinned by its full commit hash, with the tag in a trailing comment | every file in `.github/workflows/` | An action's maintainer, or whoever steals their keys, moving a tag to new code. A commit hash cannot be repointed. |
| `permissions: contents: read` at the top of the workflow | every file in `.github/workflows/` | A job's token being able to write to the repository, releases or packages. A job that needs more says so on the job, with the reason. |
| Every container image named by its digest, with the date it was read in a comment | `release.yml`, jobs `install-check-arm64` and `install-check-amd64`; `distro.yml`, jobs `distro-amd64` and `distro-arm64`; `tests/container/Dockerfile`'s `FROM`, which `tests/unit/test_container_harness.py` keeps equal to `release.yml`'s `debian:13` | Whoever publishes an image moving its tag (`debian:13`) to new contents, which the job then runs as root. A digest names one image. `.github/dependabot.yml` has no entry for them, so they are refreshed by hand ([adding or changing a workflow](#adding-or-changing-a-workflow)). |
| A release token only on a tag, and a signing token only in the job that signs | `release.yml`: `publish` holds `contents: write` and runs on a tag only; `assets` holds `id-token: write` and `attestations: write` and runs none of the build's third-party code | A build step, a dependency's setup code among them, writing a release or signing an attestation in the repository's name. |
| A token that can start workflows only in the job that starts the documentation site, on a tag, after the release is published | `release.yml`: `site` holds `actions: write` alone, checks nothing out, runs no action and sends one `gh workflow run pages.yml --ref main`; GitHub starts no workflow from a release a job's token published, so this dispatch is how a release reaches the site ([the documentation site](../site/README.md#when-it-publishes)) | A build step starting, re-running or cancelling workflows in the repository's name. The run it starts uses `main`'s copy of `pages.yml`. |
| Releases made as drafts, given every file, then published, with build provenance for the packages and `get.sh` | `release.yml`, `packaging/publish-release.sh` | A release public with a file missing, which immutable releases would then keep missing; a file nobody can trace to this workflow ([checking a release](packaging.md#checking-a-release)). |
| `persist-credentials: false` on every checkout | `ci.yml`, `release.yml`, `virtual.yml`, `distro.yml`, `container.yml`, `pages.yml` | The job's token staying in `.git/config`. |
| No job runs on a runner GitHub does not host: every `runs-on` names GitHub-hosted labels alone, whatever the job's `if:` says, and no workflow names `self-hosted` | every file in `.github/workflows/` | A pull request that edits a workflow, or a push with a stolen token, running its code on a gateway. A job's condition is read from the file the pull request or the push supplies, so it guards nothing ([the reference gateway's runner](#the-reference-gateways-runner-what-it-can-and-cannot-be-trusted-with)). |
| The documentation site's deploy job alone holds `pages: write` and `id-token: write`, runs only in `kywwilson11/tvgw`, never for a pull request, only from `main` or a release, and only while the repository variable `TVGW_PAGES` is `on` | `pages.yml`, job `deploy` | A pull request, a fork or another branch publishing the site, and the site publishing before the owner turns it on ([the documentation site](../site/README.md#when-it-publishes)). Its build runs the hash-pinned generator on GitHub's runners and never on the gateway. |
| Weekly dependabot pull requests for the actions and the Python dependencies, minor and patch grouped, with a seven-day cooldown | `.github/dependabot.yml` | Pins going stale (a pin that is never bumped is a pin that stops getting security fixes), and a release pulled within days of being published being proposed at all. |
| `tests/unit/test_supply_chain.py` | `make gate` | Any of the above going away, in any workflow including the ones added later. |

The unit test checks, for every workflow in `.github/workflows/`: each remote action is pinned by 40 hexadecimal characters and has a comment after it; there is a top-level `permissions` map with no write access; the triggers do not include `pull_request_target` or `workflow_run`; no `run:` step expands a pull-request title, branch name, comment or commit message; no job can reach a runner GitHub does not host, whatever its condition: every label it asks for is GitHub-hosted, never a `group`, an expression or a reusable-workflow call, and no workflow names `self-hosted`; the one schedule, `ci.yml`'s weekly one, starts the `mutation` job alone; no `run:` line or `with:` input (such as a github-script `script:`) expands outsider-written text; every `container:` and service image names a `@sha256:` digest, the matrix's values checked one by one, and an image's tag names one digest and an action's version one commit across all the workflows; a job with `contents: write` runs on a tag only; a job with `id-token: write` has an action that uses it (an attest step, or the docs site's `deploy-pages`), a job with `attestations: write` has an attest step, and neither runs `pip`, `make`, `npm`, `curl` or a build script; a job with `actions: write` runs on a tag only, starts a workflow with `gh workflow run`, and runs no action, no checkout and none of those; `release.yml` starts the site only once `publish` has succeeded, and on `main`, where `pages.yml`'s deploy takes the run; and `pages.yml` deploys only with `TVGW_PAGES` on, from `main` or a release, after its gate, with write access on the deploy job alone and the same pins as `ci.yml`. It also checks the `ci.yml` checkouts and the dependabot file, and that the branch-protection JSON below stays the shape this page describes.

### Adding or changing a workflow

A new workflow follows the same rules, and the test fails until it does.

- Pin each `uses:` to a commit: `uses: owner/repo@<40 hex> # v1.2.3`. Dependabot reads the comment and updates both.
- Put `permissions:` at the top. Start from `contents: read`. A release job that must write gets its permissions on the job (`contents: write` to attach files to a release, `id-token: write` and `attestations: write` for build provenance, `actions: write` to start another workflow, which a job's token can do only with a dispatch), never at the top. The job that signs runs no third-party code: it takes the build's output as an artifact and runs only the repository's scripts and the pinned attest action.
- Name a container image by its digest, `debian:13@sha256:<64 hex>`, with the date read in a comment. The digest of a multi-architecture image's index serves every architecture; read it with `docker buildx imagetools inspect debian:13` (the `Digest:` line).
- Never use `pull_request_target` or `workflow_run`.
- Never put `${{ github.event.pull_request.title }}`, `github.head_ref` or a similar value in a `run:` line or a `with:` input (a github-script `script:` is code). Pass it through `env:` and read the variable in the script.
- Never name a runner GitHub does not host. Any `runs-on` that is not purely GitHub-hosted (`ubuntu-*`, `windows-*`, `macos-*`) can reach a machine of someone's own, whether or not it says `self-hosted`, since such a runner's other labels reach it too, and no `if:` makes it safe: the condition is read from the file the push or the pull request supplies ([the reference gateway's runner](#the-reference-gateways-runner-what-it-can-and-cannot-be-trusted-with)).

### Pinning an action, and checking a pin

To pin a new action to a tag, ask GitHub which commit the tag names. An annotated tag names a tag object first, so check the commit it points at:

```sh
gh api repos/actions/checkout/git/ref/tags/v7.0.1 --jq '.object'
# {"sha":"3d3c42e5...","type":"commit",...}   a commit: use this sha
# {"sha":"...","type":"tag",...}              a tag object: follow it
gh api repos/actions/checkout/git/tags/<that sha> --jq '.object.sha'
```

To check a pin that is already in a workflow, ask GitHub how the tag and the pinned commit relate; `identical` means the tag names exactly that commit:

```sh
gh api repos/actions/checkout/compare/v7.0.1...3d3c42e5aac5ba805825da76410c181273ba90b1 --jq '.status'
gh api repos/actions/setup-python/compare/v7.1.0...6d4fd22b20465ccc0f7354476588e8df7c9ca0e0 --jq '.status'
```

Both return `identical` for the pins in `ci.yml` and `release.yml` (read 2026-11-03). The dependabot pull requests move the pins, one reviewed diff at a time.

To lint every workflow:

```sh
brew install actionlint   # or the release binary from the actionlint repository
actionlint                # no output means clean
```

## Branch protection on `main`

**Status (2026-11-01): documented, not applied.** `main` is unprotected today. Apply the settings below with the commands shown, only after every branch is integrated by fast-forward, rebase or squash (a `git merge --no-ff` push is refused once linear history is required), and read them back. Until then the controls in the repository (the pins, the permissions, the GitHub-hosted runners and the test) are the only ones in force.

The owner pushes to `main` directly. A rule that put a pull request or a green check in front of that push would stop the owner's own work, so the protection is deliberately narrow: it makes history permanent and keeps `main` from being deleted or rewritten, and it asks for nothing else.

| Setting | Value | Why |
|---|---|---|
| Force pushes | blocked | A rewritten `main` hides what was deployed: the tree a gateway runs and the commit now on `main` would no longer be the same history. |
| Deletion | blocked | A deleted and recreated `main` is a force push by another name. |
| Linear history | required | Every commit on `main` has one parent: no merge commit can hide a second line of work in a diff nobody read. Merge with `git merge --ff-only` or `git rebase`, not `git merge --no-ff`. Merge a dependabot pull request with **Rebase and merge** or **Squash and merge**: the default **Create a merge commit** button is refused, and `gh api -X PATCH repos/kywwilson11/tvgw -F allow_merge_commit=false` stops GitHub offering it. |
| Required status checks | none | A required check would make the owner's push itself wait for a run that cannot start until the push exists. |
| Required pull requests | none | The owner works on `main`. |
| Required signed commits | none | See [signed commits and tags](#signed-commits-and-tags). |
| Include administrators | yes | The owner is the only account with access, so with administrators exempt the rules would bind nobody. With them included, a force push or a merge commit needs the protection lifted first (below): a deliberate act, not a slip. |

The body GitHub takes, which `test_supply_chain.py` reads:

```json
{
  "required_status_checks": null,
  "enforce_admins": true,
  "required_pull_request_reviews": null,
  "restrictions": null,
  "required_linear_history": true,
  "allow_force_pushes": false,
  "allow_deletions": false,
  "block_creations": false,
  "required_conversation_resolution": false,
  "lock_branch": false,
  "allow_fork_syncing": false
}
```

Save it as `protect.json` and apply it with the GitHub CLI, logged in as the repository's owner:

```sh
gh api -X PUT repos/kywwilson11/tvgw/branches/main/protection --input protect.json
```

To read back what is set, and to see that nothing stands in front of the owner's push:

```sh
gh api repos/kywwilson11/tvgw/branches/main/protection \
  --jq '{enforce_admins:.enforce_admins.enabled, linear:.required_linear_history.enabled, force:.allow_force_pushes.enabled, delete:.allow_deletions.enabled, checks:.required_status_checks, reviews:.required_pull_request_reviews}'
```

The expected answer is `enforce_admins: true`, `linear: true`, `force: false`, `delete: false`, and `null` for checks and reviews. `gh api repos/kywwilson11/tvgw/branches/main/protection` answering `Branch not protected` means the settings are not applied.

To push something the protection refuses (an amended commit that was already pushed, a merge commit), lift it, push, and put it back:

```sh
gh api -X DELETE repos/kywwilson11/tvgw/branches/main/protection
git push --force-with-lease origin main
gh api -X PUT repos/kywwilson11/tvgw/branches/main/protection --input protect.json
```

A force push to `main` rewrites the history a gateway's tree was deployed from; do it knowing that.

## Repository settings that matter for the reference gateway

These are settings of the repository, not files in it, so they are applied once with the CLI and recorded here.

**Status (2026-11-11): fork pull requests need approval for every outside contributor (applied 2026-11-10, `all_external_contributors`), and the reference gateway's runner is removed (2026-11-11).** Secret scanning, push protection and dependabot security updates were off when read on 2026-11-01; apply them with the commands shown and read each back. Immutable releases were off when read on 2026-11-03.

**Fork pull requests need approval for everyone.** The repository is public. GitHub's default asks approval only from people who have never contributed; one merged change later, a contributor's pull request runs workflows with no one looking. Set it to every outside contributor:

```sh
gh api -X PUT repos/kywwilson11/tvgw/actions/permissions/fork-pr-contributor-approval -f approval_policy=all_external_contributors
```

Check with `gh api repos/kywwilson11/tvgw/actions/permissions/fork-pr-contributor-approval`. The default token for workflows is already read-only (`default_workflow_permissions: read`, and workflows cannot approve pull requests); keep it so:

```sh
gh api repos/kywwilson11/tvgw/actions/permissions/workflow
```

**Secret scanning, push protection and dependabot security updates** cost nothing on a public repository and are off by default:

Vulnerability alerts go first: GitHub refuses dependabot security updates while they are off.

```sh
gh api -X PUT repos/kywwilson11/tvgw/vulnerability-alerts
gh api -X PATCH repos/kywwilson11/tvgw --input - <<'JSON'
{"security_and_analysis":{"secret_scanning":{"status":"enabled"},"secret_scanning_push_protection":{"status":"enabled"},"dependabot_security_updates":{"status":"enabled"}}}
JSON
gh api repos/kywwilson11/tvgw --jq .security_and_analysis   # read back: each status is "enabled"
```

Push protection refuses a push that contains a recognised token or key. If a fixture trips it, GitHub's message links the one-time bypass; do not rewrite the fixture to dodge the pattern.

**Immutable releases** keep a published release's files and tag from changing, and make GitHub attest the release itself, which `gh release verify-asset` checks ([checking a release](packaging.md#checking-a-release)). `get.sh` carries the packages' hashes, so without them a replaced `get.sh` could carry the hash of a replaced package. They cover only releases published after the setting is on, and `release.yml` uploads to a draft first, which they allow. Turn them on before the first release that carries `get.sh`:

```sh
gh api -X PUT repos/kywwilson11/tvgw/immutable-releases
gh api repos/kywwilson11/tvgw/immutable-releases      # read back: {"enabled":true,...}
```

**Optional: refuse unpinned actions repository-wide.** `gh api -X PUT repos/kywwilson11/tvgw/actions/permissions -F enabled=true -f allowed_actions=all -F sha_pinning_required=true` makes GitHub fail any workflow run that uses an action by tag. The unit test already catches that before a push, so the setting is a second lock, not a first. Turn it on only after every workflow in the repository is pinned, because a workflow that is not pinned then fails at run time.

## The reference gateway's runner: what it can and cannot be trusted with

There is no runner. Until 2026-11-11 the reference gateway ran a self-hosted GitHub Actions runner as the owner's login, which had unrestricted password-free `sudo`, for this public repository, and `ci.yml`'s `hardware` job deployed every push to `main` through it. One approved pull request that edited a workflow, or one push made with a stolen token, would have run as root on the gateway, inside the home network: the job's condition was read from the workflow file the pull request or the push supplied, so it could not hold that back. On 2026-11-10 the repository's fork pull-request approval was set to every outside contributor (`all_external_contributors`); on 2026-11-11 the runner was stopped and disabled. What holds is that no runner is registered for the repository: a unit test can be replaced by the same push it would have caught, a registration cannot. Remove it under Settings > Actions > Runners, and read the count back with `gh api repos/<owner>/<repo>/actions/runners --jq .total_count`, which prints 0 ([design decision 83](../design-decisions.md#83-no-job-of-any-workflow-runs-on-a-gateway-a-change-reaches-one-only-when-its-owner-deploys-it)).

No job of any workflow runs on a gateway now. `tests/unit/test_supply_chain.py` refuses any job whose `runs-on` is not purely GitHub-hosted labels, whatever its `if:` says, and a change reaches a gateway only when its owner runs `make deploy` ([how a change reaches the gateway](../../deploy/README.md#how-a-change-reaches-the-gateway)).

A fork that registers a runner on its own gateway takes that risk back. The runner executes whatever the workflow file of the pushed commit or the pull request tells it to, as its user, with no sandbox between the job and a machine that sits on the TV's network and the home network; anything in the job's environment, a secret included, is readable by that code. The unit test fails on such a job, so a fork that wants one changes the test knowingly.

**Guardrails, in place or recommended.**

| Guardrail | State |
|---|---|
| No job of any workflow runs on a gateway | In place since 2026-11-11: no runner is registered (read the count back as above), and no `runs-on` but GitHub-hosted labels, checked by the unit test. |
| A fork's pull request runs no workflow without the owner | In place since 2026-11-10: every outside contributor's run waits for the owner's approval. |
| The workflow cannot use `pull_request_target` or `workflow_run` | In place, checked by the unit test. |
| The checkout holds no token after the job | In place (`persist-credentials: false`). |
| Branch protection on `main` | Documented, not applied as of 2026-11-01; apply with the commands above, then read back. |
| The owner's GitHub account is the real key to the repository and its releases | Use a passkey or hardware key and two-factor sign-in. Keep CLI tokens narrow: a token with the `workflow` scope can edit a workflow, and a workflow edited on `main` can give its job write access to the repository and its releases. Prefer a fine-grained token limited to this repository, with a short life, for anything automated. |
| Optional: a gateway that fetches `main` and deploys it itself | Not built. It would be safe only if it deployed commits the owner signed, and only ones that descend from the commit deployed; 461 of the 465 commits on `main` were unsigned on 2026-11-11, so it waits for a later decision ([signed commits and tags](#signed-commits-and-tags)). |

The honest summary: the boundary is the owner's GitHub account for the repository and its releases, and the owner's own `make deploy` for a gateway. Everything above makes sure that no route to `main` exists other than that account, and that nothing on `main` reaches a gateway until its owner deploys it.

## Signed commits and tags

Signing proves a commit or a tag came from the holder of a key, not just from a logged-in account. It needs a key only the owner can make, so this page gives the steps and nothing here creates one. Nothing is required to be signed yet, for two reasons: nothing checks a signature before a deploy, since a gateway runs what its owner's `make deploy` copies, so requiring them today would add friction without closing a route; and a commit made in GitHub's web editor is signed by GitHub, not by the owner, which would be rejected or silently accepted depending on a setting.

SSH signing is the smaller setup, using a key the owner already has or makes for the purpose:

```sh
# one time, on the workstation (the key may be an existing ed25519 key, ideally on a hardware token)
git config --global gpg.format ssh
git config --global user.signingkey ~/.ssh/id_ed25519.pub
git config --global commit.gpgsign true      # sign every commit
git config --global tag.gpgsign true         # sign every tag
# a file of who may sign, so that git can verify too
echo "$(git config user.email) $(cat ~/.ssh/id_ed25519.pub)" >> ~/.config/git/allowed_signers
git config --global gpg.ssh.allowedSignersFile ~/.config/git/allowed_signers
```

Then, once in the GitHub web interface: Settings, SSH and GPG keys, New SSH key, and choose the key type **Signing Key** for the same public key (an authentication key and a signing key are separate entries). Commits then show as Verified. Turn on **Vigilant mode** on the same page if you want every commit that claims your name and is not signed shown as Unverified.

To sign and check a release:

```sh
git tag -s v0.2.0 -m "tvgw 0.2.0"
git tag -v v0.2.0              # verifies against allowed_signers
git log --show-signature -3    # the same for commits
git push origin v0.2.0
```

When the owner has a key in use and wants the protection to carry it, add `required_signatures` to `main` (`gh api -X POST repos/kywwilson11/tvgw/branches/main/protection/required_signatures`). Do that only after every way the owner commits is signed, including the editor on the phone, or the next push will be refused. Dependabot's commits are signed by GitHub and verify.

<!-- (fin-release) --> The release workflow signs no tag and no `SHA256SUMS`; it attests where the packages and `get.sh` were built ([checking a release](packaging.md#checking-a-release)). A release's integrity rests on the GitHub account, immutable releases and those attestations, and what the owner's key adds later is in [packaging](packaging.md#releases).

## What this page does not cover

- A signed apt repository, the hash-pinned wheelhouse and PyPI trusted publishing belong to the packaging work (section 10 of the report lists them). Their workflows follow the rules in [adding or changing a workflow](#adding-or-changing-a-workflow) like any other.
- Dependencies of the gateway itself (Debian packages, AdGuard Home, the VPN client) are updated by the operating system and by `tvgw verify`'s version floor ([operations](../use/daily-brief.md)).
- If dependabot later watches a second place that holds Python requirements (a hash-pinned wheelhouse under `packaging/`), add an `updates:` entry for its directory in `.github/dependabot.yml` when that file is created.

## Dependabot and the hash-pinned build backend

Dependabot's first pass (2026-11-01) opened a bump of `setuptools` in `packaging/build-requirements.in` without regenerating the hashed lock beside it, and `test_the_build_backend_is_pinned_by_hash_and_installed_with_them` refused it. The build backend's pins are `make lock`'s to move, so `.github/dependabot.yml` ignores `setuptools` and `wheel`; a security advisory against either still arrives through GitHub's advisory alerts, and the owner bumps the `.in` and runs `make lock` by hand.
