"""The repository's automation as a system: what no job can be trusted to check about itself.

The hardware job runs `sudo` on the live gateway on every push to main, so the workflows are the
most privileged code in the repository. These read every workflow under .github/workflows as YAML and
text and fail `make gate` when one drifts from docs/supply-chain.md: an action not pinned by commit, a
container image not pinned by digest, a workflow with no token permissions, a token that can write a
release or sign held by a job that does not need it, a trigger that hands a fork's code the secrets or
the Pi, a `run:` line that splices attacker-controlled text into a shell, a self-hosted job without its
guard, a dependabot file that stops watching an ecosystem. Nothing here touches the network or GitHub."""

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


# ---- container images, and the jobs that write or sign ---------------------------------------------

DIGEST = re.compile(r"@sha256:[0-9a-f]{64}$")
MATRIX_REF = re.compile(r"^\$\{\{\s*matrix\.([\w-]+)\s*\}\}$")


def matrix_values(job, key):
    """Every value a job's matrix gives `key`, its `include` entries counted."""
    matrix = job.get("strategy", {}).get("matrix", {})
    values = matrix.get(key, [])
    values = list(values) if isinstance(values, list) else [values]
    return values + [entry[key] for entry in matrix.get("include", []) if key in entry]


def image_problems(path):
    """A tag such as `debian:13` is moved by whoever publishes the image, and the job then runs what they
    pushed, as root inside the container. A digest names one image and cannot be moved. An image taken
    from the matrix is checked value by value; any other expression cannot be read here and is refused."""
    found = []
    for name, job in all_jobs(path):
        container = job.get("container")
        images = [("container", container.get("image") if isinstance(container, dict) else container)]
        images += [(f"service {svc}", spec.get("image")) for svc, spec in (job.get("services") or {}).items()]
        for where, image in images:
            if image is None:
                continue
            ref = MATRIX_REF.match(str(image))
            values = matrix_values(job, ref.group(1)) if ref else [image]
            if not values:
                found.append(f"{path.name}: {name}: {where} names a matrix key with no values")
            for value in values:
                if "${{" in str(value) or not DIGEST.search(str(value)):
                    found.append(f"{path.name}: {name}: {where} {value} is not pinned by digest")
    return found


@pytest.mark.parametrize("path", WORKFLOWS, ids=lambda p: p.name)
def test_every_container_image_is_pinned_by_digest(path):
    assert image_problems(path) == []


def test_some_workflow_runs_in_containers_so_the_digest_rule_has_work():
    assert any("container" in job for path in WORKFLOWS for _, job in all_jobs(path))


@pytest.mark.parametrize(
    "spec",
    [
        "container: debian:13",
        "container:\n      image: ubuntu:24.04",
        "services:\n      db:\n        image: postgres:17",
        "strategy:\n      matrix:\n        image: [debian:13]\n    container: ${{ matrix.image }}",
        "strategy:\n      matrix:\n        include: [{image: 'debian:13'}]\n    container: ${{ matrix.image }}",
        "container: ${{ matrix.missing }}",
        "container: ${{ inputs.image }}",
    ],
)
def test_the_digest_check_flags_an_image_named_by_a_tag_or_an_unreadable_expression(tmp_path, spec):
    path = tmp_path_workflow(tmp_path, spec)
    assert image_problems(path)


@pytest.mark.parametrize(
    "spec",
    [
        f"container: debian:13@sha256:{'a' * 64}",
        f"strategy:\n      matrix:\n        image: ['debian:13@sha256:{'b' * 64}']\n    container: ${{{{ matrix.image }}}}",
        f"services:\n      db:\n        image: postgres@sha256:{'c' * 64}",
    ],
)
def test_the_digest_check_passes_an_image_named_by_digest(tmp_path, spec):
    assert image_problems(tmp_path_workflow(tmp_path, spec)) == []


def tmp_path_workflow(tmp_path, job_spec):
    return tmp_workflow(
        tmp_path,
        f"on: push\npermissions:\n  contents: read\njobs:\n  j:\n    runs-on: ubuntu-latest\n"
        f"    {job_spec}\n    steps:\n      - run: id\n",
    )


SIGNING_ACTIONS = ("actions/attest@", "actions/attest-build-provenance@")
# the actions that use the job's OIDC token: the attest actions sign with it, deploy-pages proves to Pages
# which run is publishing
OIDC_ACTIONS = (*SIGNING_ACTIONS, "actions/deploy-pages@")
# what runs code fetched from outside the repository's pinned actions: a package install, a build
THIRD_PARTY = re.compile(r"\bpip\b|\bmake\b|build-deb\.sh|\bnpm\b|\bcurl\b")


def privilege_problems(path):
    """A token that can write releases is used on a tag only. An OIDC token (`id-token: write`) is held only
    by a job with an action that uses it, `attestations: write` only by a job that attests, and neither job
    runs the build's third-party code, so nothing but a pinned action can sign or publish in the
    repository's name."""
    found = []
    for name, job in all_jobs(path):
        perms = job.get("permissions", {})
        if not isinstance(perms, dict):
            found.append(f"{path.name}: {name}: permissions must be a map")
            continue
        if perms.get("contents") == "write" and "github.ref_type == 'tag'" not in str(job.get("if", "")):
            found.append(f"{path.name}: {name}: contents: write on a job that does not run on a tag only")
        if perms.get("id-token") == "write" or perms.get("attestations") == "write":
            steps = job.get("steps", [])
            used = [step.get("uses", "") for step in steps]
            if perms.get("id-token") == "write" and not any(u.startswith(OIDC_ACTIONS) for u in used):
                found.append(f"{path.name}: {name}: id-token: write with no action that uses it")
            if perms.get("attestations") == "write" and not any(u.startswith(SIGNING_ACTIONS) for u in used):
                found.append(f"{path.name}: {name}: attestations: write with no attest step")
            for step in steps:
                if THIRD_PARTY.search(step.get("run", "")):
                    found.append(
                        f"{path.name}: {name}: a job that can sign runs: {step['run'].splitlines()[0]}"
                    )
    return found


@pytest.mark.parametrize("path", WORKFLOWS, ids=lambda p: p.name)
def test_writing_and_signing_tokens_are_held_only_where_they_are_used(path):
    assert privilege_problems(path) == []


@pytest.mark.parametrize(
    "job",
    [
        "permissions:\n      contents: write\n    steps:\n      - run: gh release create v1",
        "permissions:\n      id-token: write\n    steps:\n      - run: echo sign",
        "permissions:\n      id-token: write\n      attestations: write\n    steps:\n"
        "      - run: python -m pip install -e .\n      - uses: actions/attest@" + "a" * 40 + " # v4.2.2",
    ],
)
def test_the_privilege_check_flags_a_token_held_where_it_is_not_used(tmp_path, job):
    path = tmp_workflow(
        tmp_path,
        f"on: push\npermissions:\n  contents: read\njobs:\n  j:\n    runs-on: ubuntu-latest\n    {job}\n",
    )
    assert privilege_problems(path)


def test_the_privilege_check_passes_a_tag_only_publisher_a_clean_signer_and_a_pages_deploy(tmp_path):
    path = tmp_workflow(
        tmp_path,
        "on: push\npermissions:\n  contents: read\njobs:\n"
        "  sign:\n    runs-on: ubuntu-latest\n    permissions:\n      id-token: write\n      attestations: write\n"
        "    steps:\n      - run: packaging/release-assets.sh 1.0.0 dist\n"
        "      - uses: actions/attest@" + "a" * 40 + " # v4.2.2\n"
        "  publish:\n    if: github.ref_type == 'tag'\n    runs-on: ubuntu-latest\n"
        "    permissions:\n      contents: write\n    steps:\n      - run: packaging/publish-release.sh\n"
        "  pages:\n    runs-on: ubuntu-latest\n    permissions:\n      pages: write\n      id-token: write\n"
        "    steps:\n      - uses: actions/deploy-pages@" + "b" * 40 + " # v5.0.1\n",
    )
    assert privilege_problems(path) == []


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
