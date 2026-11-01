"""The repository's automation as a system: what no job can be trusted to check about itself.

The hardware job runs `sudo` on the live gateway on every push to main, so the workflows are the
most privileged code in the repository. These read every workflow under .github/workflows as YAML and
text and fail `make gate` when one drifts from docs/supply-chain.md: an action not pinned by commit, a
workflow with no token permissions, a trigger that hands a fork's code the secrets or the Pi, a
`run:` line that splices attacker-controlled text into a shell, a self-hosted job without its guard,
a dependabot file that stops watching an ecosystem. Nothing here touches the network or GitHub."""

import json
import re

import pytest
import yaml
from conftest import ROOT

WORKFLOWS = sorted((ROOT / ".github" / "workflows").glob("*.y*ml"))
DEPENDABOT = ROOT / ".github" / "dependabot.yml"
DOC = ROOT / "docs" / "supply-chain.md"

# what a `run:` line must never contain: text an outsider writes (a pull request title, a branch name,
# a commit message) expanded into the script before the shell parses it
UNTRUSTED = re.compile(
    r"\$\{\{\s*github\.(?:event\.(?:issue|pull_request|comment|review|head_commit|commits|pages|discussion"
    r"|release|workflow_run|merge_group|check_run|check_suite)|head_ref)",
)
FULL_SHA = re.compile(r"[0-9a-f]{40}")
# a label only GitHub's own runners carry; every other label can name a self-hosted runner, and a job
# goes to any runner that has all the labels it asks for, `self-hosted` or not
GITHUB_HOSTED = re.compile(r"(?:ubuntu|windows|macos)-[\w.-]+")
SELF_HOSTED_GUARD = (
    "github.event_name == 'push'",
    "github.repository == 'kywwilson11/tvgw'",
    "refs/heads/main",
)


def load(path):
    """Parse a workflow; PyYAML reads the `on` key as the boolean True, so normalise it."""
    data = yaml.safe_load(path.read_text(encoding="utf-8"))
    if True in data:
        data["on"] = data.pop(True)
    return data


def triggers(wf):
    on = wf["on"]
    return {on} if isinstance(on, str) else set(on)


def uses_lines(path):
    return [
        (n, line.strip())
        for n, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1)
        if re.match(r"\s*(-\s+)?uses:", line)
    ]


def all_jobs(path):
    return [(name, job) for name, job in load(path)["jobs"].items()]


def test_there_are_workflows_to_check():
    assert [p.name for p in WORKFLOWS if p.name == "ci.yml"], "the CI workflow is gone"


@pytest.mark.parametrize("path", WORKFLOWS, ids=lambda p: p.name)
def test_every_remote_action_is_pinned_by_full_commit_with_its_tag_named(path):
    """A tag such as `v4` moves: whoever controls the action's repository (or steals its keys) can point
    it at new code that then runs with this job's token, or as root on the gateway. A 40-hex commit
    cannot be repointed; the trailing comment is what dependabot reads to keep the pin current.
    (test_deploy_lint.py checks the same for ci.yml with a stricter pattern; this covers every workflow.)"""
    for n, line in uses_lines(path):
        target = line.split("uses:", 1)[1].split("#")[0].strip()
        if target.startswith("./"):  # a local action is this checkout's own code
            continue
        assert not target.startswith("docker://") or "@sha256:" in target, f"{path.name}:{n} {line}"
        if target.startswith("docker://"):
            continue
        ref = target.rpartition("@")[2]
        assert FULL_SHA.fullmatch(ref), f"{path.name}:{n} not pinned by commit: {line}"
        assert re.search(r"#\s*\S+", line.split(target, 1)[1]), f"{path.name}:{n} no version comment: {line}"


@pytest.mark.parametrize("path", WORKFLOWS, ids=lambda p: p.name)
def test_every_workflow_sets_its_token_permissions_at_the_top(path):
    """Without a `permissions` key the token takes the repository default, which an owner can change
    to read-write in one click. Stated at the top it is fixed in the file under review."""
    perms = load(path).get("permissions")
    assert isinstance(perms, dict), f"{path.name}: no top-level permissions"
    assert perms.get("contents", "none") in ("read", "none"), (
        f"{path.name}: contents is not read-only at the top"
    )
    assert not any(value == "write" for value in perms.values()), (
        f"{path.name}: write access at the top level"
    )


@pytest.mark.parametrize("path", WORKFLOWS, ids=lambda p: p.name)
def test_no_workflow_runs_a_forks_code_with_secrets_or_the_pi(path):
    """`pull_request_target` and `workflow_run` run in the base repository's context with its secrets
    and write token while the head's code is one `actions/checkout` away; both are the classic route
    from a fork's pull request to the repository. Neither is needed here."""
    wf = load(path)
    assert not triggers(wf) & {"pull_request_target", "workflow_run"}, path.name


def strings(value):
    """Every string inside a YAML value, however deeply it is nested."""
    if isinstance(value, str):
        yield value
    elif isinstance(value, dict):
        for item in value.values():
            yield from strings(item)
    elif isinstance(value, list):
        for item in value:
            yield from strings(item)


def injection_problems(path):
    """A `run:` line is shell and a `with:` input such as actions/github-script's `script:` is code: text an
    outsider writes, expanded into either before it is parsed, is theirs to execute."""
    found = []
    for name, job in all_jobs(path):
        for step in job.get("steps", []):
            for where, value in (("run", step.get("run", "")), ("with", step.get("with", {}))):
                if any(UNTRUSTED.search(text) for text in strings(value)):
                    found.append(f"{path.name}: {name}: untrusted expression in a {where} of a step")
    return found


@pytest.mark.parametrize("path", WORKFLOWS, ids=lambda p: p.name)
def test_no_step_expands_text_an_outsider_writes(path):
    assert injection_problems(path) == []


def tmp_workflow(tmp_path, text):
    path = tmp_path / "w.yml"
    path.write_text(text, encoding="utf-8")
    return path


@pytest.mark.parametrize(
    "step",
    [
        "run: echo '${{ github.event.pull_request.title }}'",
        "uses: actions/github-script@" + "a" * 40 + " # v7.0.0\n        with:\n"
        "          script: core.info('${{ github.event.pull_request.title }}')",
        "uses: actions/github-script@" + "a" * 40 + " # v7.0.0\n        with:\n"
        "          script: |\n            const body = `${{ github.event.release.body }}`",
        "run: echo ${{ github.event.workflow_run.head_branch }}",
        "run: echo ${{ github.event.merge_group.head_commit.message }}",
    ],
)
def test_the_injection_check_sees_run_lines_and_with_inputs(tmp_path, step):
    path = tmp_workflow(
        tmp_path,
        f"on: push\npermissions:\n  contents: read\njobs:\n  j:\n    runs-on: ubuntu-latest\n"
        f"    steps:\n      - {step}\n",
    )
    assert injection_problems(path)


def test_the_injection_check_lets_an_env_hand_over_pass(tmp_path):
    path = tmp_workflow(
        tmp_path,
        "on: push\njobs:\n  j:\n    runs-on: ubuntu-latest\n    steps:\n"
        '      - run: echo "$TITLE"\n        env:\n          TITLE: ${{ github.event.pull_request.title }}\n',
    )
    assert injection_problems(path) == []


def runner_labels(runs_on):
    """The labels a job asks for, whatever shape `runs-on` takes: a string, a list, or a mapping."""
    if isinstance(runs_on, str):
        return [runs_on]
    if isinstance(runs_on, list):
        return [str(label) for label in runs_on]
    if isinstance(runs_on, dict):
        group = runs_on.get("group")
        return ([f"group:{group}"] if group else []) + runner_labels(runs_on.get("labels", []))
    return [str(runs_on)]


def self_hosted_problems(path):
    """A job reaches the Pi unless every label it asks for is one only GitHub's own runners carry. A job
    with no `runs-on` (a call to a reusable workflow) is held to the same guard, and an expression in
    `runs-on` is refused since it cannot be read here."""
    found = []
    for name, job in all_jobs(path):
        runs_on = job.get("runs-on")
        labels = runner_labels(runs_on) if runs_on is not None else []
        if any("${{" in label for label in labels):
            found.append(f"{path.name}: {name}: runs-on is an expression; name the runner")
            continue
        if labels and all(GITHUB_HOSTED.fullmatch(label) for label in labels):
            continue
        guard = str(job.get("if", ""))
        found.extend(
            f"{path.name}: {name}: the job can reach the self-hosted runner and its condition lacks {part!r}"
            for part in SELF_HOSTED_GUARD
            if part not in guard
        )
    return found


@pytest.mark.parametrize("path", WORKFLOWS, ids=lambda p: p.name)
def test_a_job_that_can_reach_the_self_hosted_runner_runs_only_for_a_push_to_main_of_this_repository(path):
    """The runner is the owner's gateway: its user has sudo. A pull request (a fork's or a branch's)
    that edits a workflow could otherwise name the runner's labels and run its own code as that user.
    `self-hosted` is only one of the runner's labels (`tvgw`, `Linux` and `ARM64` reach it too), so a job
    is taken to be bound for the Pi unless it asks only for GitHub-hosted labels."""
    assert self_hosted_problems(path) == []


@pytest.mark.parametrize(
    "runs_on",
    [
        "tvgw",
        "[Linux, ARM64]",
        "[self-hosted]",
        "[ubuntu-latest, tvgw]",
        "{ group: pi, labels: [tvgw] }",
        "{ labels: [Linux, ARM64] }",
        "{ group: pi }",
    ],
)
def test_the_self_hosted_check_flags_any_label_that_can_name_the_pi(tmp_path, runs_on):
    path = tmp_workflow(
        tmp_path,
        f"on: pull_request\njobs:\n  j:\n    if: github.event_name == 'pull_request'\n"
        f"    runs-on: {runs_on}\n    steps:\n      - run: id\n",
    )
    assert self_hosted_problems(path)


@pytest.mark.parametrize("runs_on", ["${{ matrix.runner }}", "[self-hosted, '${{ inputs.label }}']"])
def test_the_self_hosted_check_refuses_a_runner_chosen_by_an_expression(tmp_path, runs_on):
    path = tmp_workflow(
        tmp_path,
        f"on: push\njobs:\n  j:\n    runs-on: {runs_on}\n    steps:\n      - run: id\n",
    )
    assert any("expression" in problem for problem in self_hosted_problems(path))


def test_the_self_hosted_check_holds_a_reusable_workflow_call_to_the_guard(tmp_path):
    path = tmp_workflow(
        tmp_path,
        "on: push\njobs:\n  j:\n    uses: ./.github/workflows/other.yml\n",
    )
    assert self_hosted_problems(path)  # no KeyError, and no way round the guard


@pytest.mark.parametrize("runs_on", ["ubuntu-latest", "[ubuntu-24.04-arm]", "{ labels: [macos-14] }"])
def test_the_self_hosted_check_leaves_github_hosted_jobs_alone(tmp_path, runs_on):
    path = tmp_workflow(
        tmp_path,
        f"on: pull_request\njobs:\n  j:\n    runs-on: {runs_on}\n    steps:\n      - run: id\n",
    )
    assert self_hosted_problems(path) == []


def test_a_guarded_job_on_the_pi_passes(tmp_path):
    path = tmp_workflow(
        tmp_path,
        "on: push\njobs:\n  j:\n    if: >-\n      github.event_name == 'push'\n"
        "      && github.repository == 'kywwilson11/tvgw'\n      && github.ref == 'refs/heads/main'\n"
        "    runs-on: [self-hosted, tvgw]\n    steps:\n      - run: id\n",
    )
    assert self_hosted_problems(path) == []


def test_the_checkouts_of_ci_leave_no_token_behind():
    """Nothing in ci.yml pushes. The default leaves the job's token in `.git/config`, and on the
    self-hosted runner that checkout stays on disk between runs."""
    path = ROOT / ".github" / "workflows" / "ci.yml"
    seen = 0
    for name, job in all_jobs(path):
        for step in job["steps"]:
            if step.get("uses", "").startswith("actions/checkout@"):
                seen += 1
                assert step.get("with", {}).get("persist-credentials") is False, name
    assert seen >= 1, "ci.yml has no checkout to check"


@pytest.mark.parametrize("path", WORKFLOWS, ids=lambda p: p.name)
def test_no_checkout_in_any_workflow_leaves_its_token_behind(path):
    """No workflow pushes: release.yml and virtual.yml check out without keeping the token either."""
    for name, job in all_jobs(path):
        for step in job["steps"]:
            if step.get("uses", "").startswith("actions/checkout@"):
                assert step.get("with", {}).get("persist-credentials") is False, name


def test_dependabot_watches_actions_and_python_weekly_with_minor_and_patch_grouped():
    cfg = yaml.safe_load(DEPENDABOT.read_text(encoding="utf-8"))
    assert cfg["version"] == 2
    by_eco = {entry["package-ecosystem"]: entry for entry in cfg["updates"]}
    assert {"github-actions", "pip"} <= set(by_eco)
    for eco in ("github-actions", "pip"):
        entry = by_eco[eco]
        assert entry["directory"] == "/"
        assert entry["schedule"]["interval"] == "weekly"
        assert entry["cooldown"]["default-days"] >= 7  # a release is a week old before it is proposed
        types = [t for group in entry["groups"].values() for t in group["update-types"]]
        assert sorted(types) == ["minor", "patch"], f"{eco}: a major bump must stay its own pull request"


def test_the_documented_branch_protection_cannot_block_the_owners_push_or_the_pis_deploy():
    """The settings the page tells the owner to apply: no force pushes, no deletion, a linear history,
    and nothing that stands between a push to main and the hardware job (no required checks, no pull
    request, no signed-commit requirement)."""
    text = DOC.read_text(encoding="utf-8")
    block = re.search(r"```json\n(\{.*?\})\n```", text, re.S)
    assert block, "docs/supply-chain.md has no branch-protection JSON block"
    body = json.loads(block.group(1))
    assert body["allow_force_pushes"] is False and body["allow_deletions"] is False
    assert body["required_linear_history"] is True
    assert body["required_status_checks"] is None
    assert body["required_pull_request_reviews"] is None
    assert body["restrictions"] is None
    assert body["lock_branch"] is False
