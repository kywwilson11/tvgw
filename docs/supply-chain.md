# Supply chain

This page says what the repository's automation is allowed to do, what stops it from doing more, and the settings that keep it that way. It is for the owner, who applies and changes the GitHub settings, and for anyone adding a workflow or a dependency. The research behind it is [section 10 of the state-of-the-art report](research/state-of-the-art-2026-10.md#10-security-and-sandboxing); the decision is [design decision 23](design-decisions.md#23-supplychain-the-workflows-are-the-most-privileged-code-in-the-repository).

## The threat in one paragraph

A push to `main` runs the `hardware` job on the Raspberry Pi. That job executes `sudo deploy/sync-install.sh`, so whoever can get a commit onto `main`, or get code into any step of that job, runs as root on the machine that holds the TV's firewall, the DNS filter and the store of what the TV did. Three routes lead there: a third-party action that changed under a tag the workflow trusted, a pull request (a fork's, or a branch's) that makes the self-hosted runner run its own code, and a stolen or careless push to `main`. The rest of this page closes each, and says plainly what stays open.

## What is in place

| Control | Where | What it stops |
|---|---|---|
| Every action pinned by its full commit hash, with the tag in a trailing comment | every file in `.github/workflows/` | An action's maintainer, or whoever steals their keys, moving a tag to new code. A commit hash cannot be repointed. |
| `permissions: contents: read` at the top of the workflow | `ci.yml` | A job's token being able to write to the repository, releases or packages. A job that needs more says so on the job, with the reason. |
| `persist-credentials: false` on every checkout | `ci.yml` | The job's token staying in `.git/config`. On the Pi the checkout stays on disk between runs. |
| The hardware job runs only for `push` events, in `kywwilson11/tvgw`, on `refs/heads/main` | `ci.yml`, job `hardware` | A pull request, a fork, a manual dispatch or another branch reaching the Pi. |
| Weekly dependabot pull requests for the actions and the Python dependencies, minor and patch grouped, with a seven-day cooldown | `.github/dependabot.yml` | Pins going stale (a pin that is never bumped is a pin that stops getting security fixes), and a release pulled within days of being published being proposed at all. |
| `tests/unit/test_supply_chain.py` | `make gate` | Any of the above going away, in any workflow including the ones added later. |
| `actionlint` configuration naming the `tvgw` runner label | `.github/actionlint.yaml` | Nothing by itself: it lets `actionlint` run clean on `ci.yml` so a real finding is not lost among a known one. |

The unit test checks, for every workflow in `.github/workflows/`: each remote action is pinned by 40 hexadecimal characters and has a comment after it; there is a top-level `permissions` map with no write access; the triggers do not include `pull_request_target` or `workflow_run`; no `run:` step expands a pull-request title, branch name, comment or commit message; and a job that runs on a self-hosted runner carries the push, repository and `main` condition. It also checks the `ci.yml` checkouts and the dependabot file, and that the branch-protection JSON below stays the shape this page describes.

### Adding or changing a workflow

A new workflow follows the same rules, and the test fails until it does.

- Pin each `uses:` to a commit: `uses: owner/repo@<40 hex> # v1.2.3`. Dependabot reads the comment and updates both.
- Put `permissions:` at the top. Start from `contents: read`. A release job that must write gets its permissions on the job (`contents: write` to attach files to a release, `id-token: write` and `attestations: write` for build provenance), never at the top.
- Never use `pull_request_target` or `workflow_run`.
- Never put `${{ github.event.pull_request.title }}`, `github.head_ref` or a similar value in a `run:` line. Pass it through `env:` and read the variable in the script.
- A job on the Pi is a deploy. It needs the same `if:` as `hardware` and a reason to exist.

### Pinning an action, and checking a pin

To pin a new action to a tag, ask GitHub which commit the tag names. An annotated tag names a tag object first, so check the commit it points at:

```sh
gh api repos/actions/checkout/git/ref/tags/v4.4.0 --jq '.object'
# {"sha":"11d5960a...","type":"commit",...}   a commit: use this sha
# {"sha":"...","type":"tag",...}              a tag object: follow it
gh api repos/actions/checkout/git/tags/<that sha> --jq '.object.sha'
```

To check a pin that is already in a workflow, ask GitHub how the tag and the pinned commit relate; `identical` means the tag names exactly that commit:

```sh
gh api repos/actions/checkout/compare/v4.4.0...11d5960a326750d5838078e36cf38b85af677262 --jq '.status'
gh api repos/actions/setup-python/compare/v5.6.0...a26af69be951a213d495a4c3e4e4022e16d87065 --jq '.status'
```

Both return `identical` for the pins in `ci.yml` today. The pins are not the newest releases of those actions; the dependabot pull requests move them, one reviewed diff at a time. A major bump of `actions/checkout` or `actions/setup-python` can raise the minimum runner version, so read the release notes against the runner version GitHub shows for the Pi (Settings, Actions, Runners) before merging one.

To lint every workflow:

```sh
brew install actionlint   # or the release binary from the actionlint repository
actionlint                # reads .github/actionlint.yaml; no output means clean
```

## Branch protection on `main`

The owner pushes to `main` directly, and the Pi's runner deploys what lands there. A rule that put a pull request or a green check between those two would stop the deploy the owner wants, so the protection is deliberately narrow: it makes history permanent and keeps `main` from being deleted or rewritten, and it asks for nothing else.

| Setting | Value | Why |
|---|---|---|
| Force pushes | blocked | A rewritten `main` hides what was deployed. The hardware job's checkout of an old commit and the commit now on `main` would no longer be the same history. |
| Deletion | blocked | A deleted and recreated `main` is a force push by another name. |
| Linear history | required | Every commit on `main` has one parent: no merge commit can hide a second line of work in a diff nobody read. Merge with `git merge --ff-only` or `git rebase`, not `git merge --no-ff`. |
| Required status checks | none | The Pi deploys from `main` after the push. A required check would make the push itself wait for a run that cannot start until the push exists. |
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

To read back what is set, and to see that nothing stands between a push and the deploy:

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

A force push to `main` is a deploy of rewritten history to the live gateway; do it knowing that.

## Repository settings that matter for the Pi

These are settings of the repository, not files in it, so they are applied once with the CLI and recorded here.

**Fork pull requests need approval for everyone.** The repository is public. GitHub's default asks approval only from people who have never contributed; one merged change later, a contributor's pull request runs workflows with no one looking. Set it to every outside contributor:

```sh
gh api -X PUT repos/kywwilson11/tvgw/actions/permissions/fork-pr-contributor-approval -f approval_policy=all_external_contributors
```

Check with `gh api repos/kywwilson11/tvgw/actions/permissions/fork-pr-contributor-approval`. The default token for workflows is already read-only (`default_workflow_permissions: read`, and workflows cannot approve pull requests); keep it so:

```sh
gh api repos/kywwilson11/tvgw/actions/permissions/workflow
```

**Secret scanning, push protection and dependabot security updates** cost nothing on a public repository and are off by default:

```sh
gh api -X PATCH repos/kywwilson11/tvgw --input - <<'JSON'
{"security_and_analysis":{"secret_scanning":{"status":"enabled"},"secret_scanning_push_protection":{"status":"enabled"},"dependabot_security_updates":{"status":"enabled"}}}
JSON
gh api -X PUT repos/kywwilson11/tvgw/vulnerability-alerts
```

Push protection refuses a push that contains a recognised token or key. If a fixture trips it, GitHub's message links the one-time bypass; do not rewrite the fixture to dodge the pattern.

**Optional: refuse unpinned actions repository-wide.** `gh api -X PUT repos/kywwilson11/tvgw/actions/permissions -F enabled=true -f allowed_actions=all -F sha_pinning_required=true` makes GitHub fail any workflow run that uses an action by tag. The unit test already catches that before a push, so the setting is a second lock, not a first. Turn it on only after every workflow in the repository is pinned, because a workflow that is not pinned then fails at run time, and `ci.yml` is the one that deploys.

## The Pi's runner: what it can and cannot be trusted with

The `hardware` job runs on a self-hosted runner on the gateway (labels `self-hosted` and `tvgw`), as the Pi's user, which has `sudo`. The job's one step runs `sudo deploy/sync-install.sh`, which replaces `/opt/tvgw/src`, runs `install.sh` and runs the hardware suite as root.

**What it can be trusted with.** Deploying this repository's `main` branch, on a push by the owner, and running the hardware suite against the live firewall, resolver and store. The code it runs is the code of the commit that was pushed.

**What it cannot be trusted with, because it is root on the gateway.**

- Any code the owner has not read. A pull request, a fork, another branch, a dependency bumped without reading the diff, an action pinned to a tag. The runner executes whatever the workflow tells it to; there is no sandbox between the job and the machine.
- Secrets. Do not store a repository secret that the Pi's job can read. Anything in the job's environment is readable by the code the job runs, which is root. The analyst's API key is a root-only file on the Pi (`/etc/tvgw/claude.key`) and not a repository secret for the same reason.
- A second purpose. The runner is registered for this repository only. Do not register it for another repository, an organisation, or reuse the Pi's user for anything the gateway does not need.
- Being reached from the network the TV is on. The runner dials out to GitHub; nothing listens for it. Keep it that way. Only DHCP, DNS and the web ports on the Pi are reachable from the TV's side ([architecture](architecture.md)).

**Guardrails, in place or recommended.**

| Guardrail | State |
|---|---|
| Run the `hardware` job only for a push to `main` of `kywwilson11/tvgw` | In place (`if:` on the job, checked by the unit test). |
| No fork pull requests on the Pi | In place for the job (a pull request never matches the condition); the approval policy above stops a fork's edited workflow from running at all without the owner's click. |
| The workflow cannot use `pull_request_target` or `workflow_run` | In place, checked by the unit test. |
| The checkout holds no token after the job | In place (`persist-credentials: false`). |
| Branch protection on `main` | Settings above; apply once. |
| The owner's GitHub account is the real key to the Pi | Use a passkey or hardware key and two-factor sign-in. Keep CLI tokens narrow: a token with the `workflow` scope can edit `ci.yml`, and an edit to `ci.yml` on `main` is root on the Pi. Prefer a fine-grained token limited to this repository, with a short life, for anything automated. |
| Keep the runner current | The runner updates itself; check `Settings > Actions > Runners` shows it online and on a recent version. An old runner misses fixes. |
| Optional: an environment with a required reviewer for the deploy job | Not applied. It would make every push wait for a click before the Pi deploys, which is the opposite of what the owner wants today. It is the right control the day anyone besides the owner can push. |
| Optional: verify the signature of the commit on the Pi before `install.sh` | Not applied; needs the owner's signing key first ([below](#signed-commits-and-tags)). |

The honest summary: the boundary is the owner's GitHub account. Everything above makes sure that no route to `main` or to the runner exists other than that account.

## Signed commits and tags

Signing proves a commit or a tag came from the holder of a key, not just from a logged-in account. It needs a key only the owner can make, so this page gives the steps and nothing here creates one. Nothing is required to be signed yet, for two reasons: the Pi's runner would not check a signature even if one were required, so requiring them today would add friction without closing a route; and a commit made in GitHub's web editor is signed by GitHub, not by the owner, which would be rejected or silently accepted depending on a setting.

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

Release artifacts (the wheel, the packages) are signed by the release workflow of the packaging work, with their own keys and attestations; `docs/packaging.md` covers that once the packaging work lands; this page does not.

## What this page does not cover

- A signed apt repository, the hash-pinned wheelhouse and PyPI trusted publishing belong to the packaging work (section 10 of the report lists them). Their workflows follow the rules in [adding or changing a workflow](#adding-or-changing-a-workflow) like any other.
- Dependencies of the Pi itself (Debian packages, AdGuard Home, the VPN client) are updated by the operating system and by `tvgw verify`'s version floor ([operations](operations.md)).
- If dependabot later watches a second place that holds Python requirements (a hash-pinned wheelhouse under `packaging/`), add an `updates:` entry for its directory in `.github/dependabot.yml` when that file is created.
