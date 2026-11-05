"""The repository's automation as a system: what no job can be trusted to check about itself.

The hardware job runs `sudo` on the live gateway on every push to main, so the workflows are the
most privileged code in the repository. These read every workflow under .github/workflows as YAML and
text and fail `make gate` when one drifts from docs/project/supply-chain.md: an action not pinned by
commit, a container image not pinned by digest, a workflow with no token permissions, a token that can
write a release or sign held by a job that does not need it, a trigger that hands a fork's code the
secrets or the Pi, a `run:` line that splices attacker-controlled text into a shell, a self-hosted job
without its guard, a dependabot file that stops watching an ecosystem. Nothing here touches the network
or GitHub."""

import json
import os
import re
import shutil
import subprocess

import pytest
import yaml
from conftest import ROOT, load_tool

from tvgw import forget

WORKFLOWS = sorted((ROOT / ".github" / "workflows").glob("*.y*ml"))
DEPENDABOT = ROOT / ".github" / "dependabot.yml"
DOC = ROOT / "docs" / "project" / "supply-chain.md"

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


# ---- the platform workflows: distro.yml, and virtual.yml's two architectures and two sets of names ----

DISTRO = ROOT / ".github" / "workflows" / "distro.yml"
VIRTUAL = ROOT / ".github" / "workflows" / "virtual.yml"
DISTROS = ["debian-12", "debian-13", "ubuntu-24.04", "ubuntu-26.04"]
RUNNERS = {"amd64": "ubuntu-latest", "arm64": "ubuntu-24.04-arm"}


def without_arch(job: dict, arch: str) -> str:
    """A job's steps as text, with its architecture's name taken out, so two jobs that differ only in it
    compare equal."""
    return yaml.safe_dump(job["steps"], sort_keys=True).replace(arch, "<arch>")


def test_the_platform_check_runs_in_four_distributions_on_both_architectures():
    wf = load(DISTRO)
    assert wf["permissions"] == {"contents": "read"}
    docs = ["**/*.md", "docs/**"]
    assert wf["on"]["push"] == {"branches": ["main"], "paths-ignore": docs}
    assert wf["on"]["pull_request"] == {"paths-ignore": docs}
    assert set(wf["jobs"]) == {f"distro-{arch}" for arch in RUNNERS}
    cells = {}
    for arch, runner in RUNNERS.items():
        job = wf["jobs"][f"distro-{arch}"]
        assert job["runs-on"] == runner
        assert "permissions" not in job, "the check runs the distributions' code and gets only the top's read"
        include = job["strategy"]["matrix"]["include"]
        assert [cell["name"] for cell in include] == DISTROS
        for cell in include:
            tag, _, digest = cell["image"].partition("@")
            # the name is the tag, so the artifact says which image it came from
            assert tag == cell["name"].replace("-", ":", 1), cell
            assert re.fullmatch(r"sha256:[0-9a-f]{64}", digest), cell
        cells[arch] = include
        assert job["container"] == {
            "image": "${{ matrix.image }}",
            "options": "--cap-add=NET_ADMIN --cap-add=NET_RAW",
        }
        runs = [step["run"] for step in job["steps"] if "run" in step]
        assert runs == ["sh packaging/check-platform.sh --source"]
        upload = next(s for s in job["steps"] if s.get("uses", "").startswith("actions/upload-artifact@"))
        assert upload["with"]["name"] == f"platform-${{{{ matrix.name }}}}-{arch}"
        assert upload["if"] == "always()" and upload["with"]["path"] == "/tmp/tvgw-platform"
    # the same images, digest for digest, and the same steps on both architectures
    assert cells["amd64"] == cells["arm64"]
    assert without_arch(wf["jobs"]["distro-amd64"], "amd64") == without_arch(
        wf["jobs"]["distro-arm64"], "arm64"
    )


def test_an_image_tag_is_pinned_to_one_digest_in_every_workflow():
    """release.yml installs the packages in two of the images distro.yml checks: a tag moved in one file
    and not the other would check one image and ship to another."""
    pins: dict[str, set[str]] = {}
    for path in WORKFLOWS:
        for _, job in all_jobs(path):
            container = job.get("container")
            image = container.get("image") if isinstance(container, dict) else container
            ref = MATRIX_REF.match(str(image)) if image else None
            for value in matrix_values(job, ref.group(1)) if ref else [image] if image else []:
                tag, _, digest = str(value).partition("@")
                pins.setdefault(tag, set()).add(digest)
    assert {"debian:12", "debian:13", "ubuntu:24.04", "ubuntu:26.04"} <= set(pins)
    assert {tag: digests for tag, digests in pins.items() if len(digests) > 1} == {}


def test_an_action_at_one_version_is_pinned_to_one_commit_in_every_workflow():
    """The version comment is what dependabot and a reviewer read; one commit behind each, everywhere."""
    pins: dict[str, set[str]] = {}
    for path in WORKFLOWS:
        for _, line in uses_lines(path):
            target, _, comment = line.split("uses:", 1)[1].partition("#")
            name, _, sha = target.strip().rpartition("@")
            if name and not name.startswith(("./", "docker://")):
                pins.setdefault(f"{name} {comment.strip()}", set()).add(sha)
    assert pins and {key: shas for key, shas in pins.items() if len(shas) > 1} == {}


def test_the_virtual_gateway_runs_with_other_interface_names_and_on_arm64():
    wf = load(VIRTUAL)
    assert set(wf["jobs"]) == {"virtual", "virtual-arm64"}
    amd, arm = wf["jobs"]["virtual"], wf["jobs"]["virtual-arm64"]
    assert amd["runs-on"] == "ubuntu-latest" and arm["runs-on"] == "ubuntu-24.04-arm"
    assert amd["strategy"]["matrix"] == {"ifnames": ["default", "alt"]}
    assert amd["env"] == {"TVGW_VIRTUAL_IFNAMES": "${{ matrix.ifnames }}", "ARCH": "amd64"}
    assert arm["env"] == {"TVGW_VIRTUAL_IFNAMES": "default", "ARCH": "arm64"}
    suite = next(s for s in amd["steps"] if "pytest -m virtual" in s.get("run", ""))
    assert 'TVGW_VIRTUAL_IFNAMES="$TVGW_VIRTUAL_IFNAMES"' in suite["run"], (
        "sudo env passes the choice to root"
    )
    fetch = next(s for s in amd["steps"] if "aghinstall.fetch_release" in s.get("run", ""))
    assert 'aghinstall.fetch_release(dest, os.environ["ARCH"])' in fetch["run"]
    assert 'aghinstall.PIN["assets"][os.environ["ARCH"]]' in fetch["run"]
    names = [
        next(s for s in job["steps"] if "upload-artifact" in s.get("uses", ""))["with"]["name"]
        for job in (amd, arm)
    ]
    assert names == ["virtual-gateway${{ matrix.ifnames == 'alt' && '-alt' || '' }}", "virtual-gateway-arm64"]

    # the same steps but for the artifact's name
    def steps(job):
        return [
            {**s, "with": {**s["with"], "name": "<name>"}} if "upload-artifact" in s.get("uses", "") else s
            for s in job["steps"]
        ]

    assert steps(amd) == steps(arm)


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
    repository's name. A token that can start, re-run and cancel workflows (`actions: write`) is held only
    by a job that runs on a tag only and starts one with `gh workflow run`, and that runs no action, no
    checkout and none of the build's code."""
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
        if perms.get("actions") == "write":
            steps = job.get("steps", [])
            if "github.ref_type == 'tag'" not in str(job.get("if", "")):
                found.append(f"{path.name}: {name}: actions: write on a job that does not run on a tag only")
            if not any("gh workflow run " in step.get("run", "") for step in steps):
                found.append(f"{path.name}: {name}: actions: write with no step that starts a workflow")
            for step in steps:
                if "uses" in step or THIRD_PARTY.search(step.get("run", "")):
                    what = step.get("uses") or step["run"].splitlines()[0]
                    found.append(f"{path.name}: {name}: a job that can start workflows runs: {what}")
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
        # a workflow started from a job that is not a tag's, from one that starts nothing, and from one
        # that checks out code first
        "permissions:\n      actions: write\n    steps:\n      - run: gh workflow run pages.yml --ref main",
        "if: github.ref_type == 'tag'\n    permissions:\n      actions: write\n    steps:\n"
        "      - run: gh run cancel 1",
        "if: github.ref_type == 'tag'\n    permissions:\n      actions: write\n    steps:\n"
        "      - uses: actions/checkout@" + "a" * 40 + " # v7.0.1\n"
        "      - run: gh workflow run pages.yml --ref main",
    ],
)
def test_the_privilege_check_flags_a_token_held_where_it_is_not_used(tmp_path, job):
    path = tmp_workflow(
        tmp_path,
        f"on: push\npermissions:\n  contents: read\njobs:\n  j:\n    runs-on: ubuntu-latest\n    {job}\n",
    )
    assert privilege_problems(path)


def test_the_privilege_check_passes_a_tag_only_publisher_a_clean_signer_a_dispatch_and_a_pages_deploy(
    tmp_path,
):
    path = tmp_workflow(
        tmp_path,
        "on: push\npermissions:\n  contents: read\njobs:\n"
        "  sign:\n    runs-on: ubuntu-latest\n    permissions:\n      id-token: write\n      attestations: write\n"
        "    steps:\n      - run: packaging/release-assets.sh 1.0.0 dist\n"
        "      - uses: actions/attest@" + "a" * 40 + " # v4.2.2\n"
        "  publish:\n    if: github.ref_type == 'tag'\n    runs-on: ubuntu-latest\n"
        "    permissions:\n      contents: write\n    steps:\n      - run: packaging/publish-release.sh\n"
        "  site:\n    if: github.ref_type == 'tag'\n    runs-on: ubuntu-latest\n"
        "    permissions:\n      actions: write\n    steps:\n      - run: gh workflow run pages.yml --ref main\n"
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
    assert block, "docs/project/supply-chain.md has no branch-protection JSON block"
    body = json.loads(block.group(1))
    assert body["allow_force_pushes"] is False and body["allow_deletions"] is False
    assert body["required_linear_history"] is True
    assert body["required_status_checks"] is None
    assert body["required_pull_request_reviews"] is None
    assert body["restrictions"] is None
    assert body["lock_branch"] is False


# ---- (deploy window) which jobs each event runs, read from the `if:` expressions themselves --------
CI = ROOT / ".github" / "workflows" / "ci.yml"
SCRUB = "| sudo env PYTHONPATH=src python3 -B -P -s -m tvgw.scrub --stdin"
QUIET = "sudo env PYTHONPATH=src python3 -B -P -s -m tvgw tv quiet --wait 0"
RETRY = "13,43 * * * *"  # off the hour and half hour, which GitHub delays and drops
WAIT_TOOL = load_tool("wait_deploy_window")  # the tool a deferred run waits in, for its own root command
MUTATION = "17 6 * * 1"
_TOKEN = re.compile(r"\s*(?:(==|!=|&&|\|\||[()!])|'((?:[^']|'')*)'|([A-Za-z_][\w.-]*(?:\(\))?))")


def evaluate(expression, context, success=True):
    """A GitHub Actions expression as the runner reads the subset the workflows use: `==` and `!=`
    (strings compared without case), `&&` and `||` returning an operand, `!`, parentheses, string
    literals, context names (a missing one is null) and the status functions. `success` is whether
    every job the job needs succeeded; nothing is ever cancelled here."""
    text = expression.strip()
    if text.startswith("${{") and text.endswith("}}"):
        text = text[3:-2]
    tokens, pos = [], 0
    while text[pos:].strip():
        m = _TOKEN.match(text, pos)
        assert m, f"cannot read {text[pos:]!r}"
        op, literal, name = m.groups()
        tokens.append(
            ("op", op)
            if op
            else ("str", literal.replace("''", "'"))
            if literal is not None
            else ("name", name)
        )
        pos = m.end()
    funcs = {"always()": True, "cancelled()": False, "success()": success, "failure()": not success}

    def truthy(v):
        return v not in (None, False, "", 0)

    def same(a, b):
        return (a or "").lower() == (b or "").lower() if isinstance(a, str) or isinstance(b, str) else a == b

    def primary(i):
        kind, value = tokens[i]
        if (kind, value) == ("op", "("):
            v, i = either(i + 1)
            assert tokens[i] == ("op", ")"), expression
            return v, i + 1
        if kind == "str":
            return value, i + 1
        assert kind == "name", expression
        return (funcs[value] if value.endswith("()") else context.get(value)), i + 1

    def unary(i):
        if tokens[i] == ("op", "!"):
            v, i = unary(i + 1)
            return not truthy(v), i
        left, i = primary(i)
        if i < len(tokens) and tokens[i] in (("op", "=="), ("op", "!=")):
            right, j = primary(i + 1)
            return same(left, right) == (tokens[i][1] == "=="), j
        return left, i

    def both(i):
        left, i = unary(i)
        while i < len(tokens) and tokens[i] == ("op", "&&"):
            right, i = unary(i + 1)
            left = right if truthy(left) else left
        return left, i

    def either(i):
        left, i = both(i)
        while i < len(tokens) and tokens[i] == ("op", "||"):
            right, i = both(i + 1)
            left = left if truthy(left) else right
        return left, i

    value, end = either(0)
    assert end == len(tokens), f"left over in {expression!r}"
    return value


def jobs_that_run(
    path, event, schedule=None, repository="kywwilson11/tvgw", ref="refs/heads/main", failing=(), context=None
):
    """The jobs of a workflow an event runs, in file order: a job runs when its `if:` holds, and,
    unless the `if:` calls a status function, when every job it needs succeeded. `context` adds names
    the conditions read beyond the event's own, such as a repository variable (`vars.NAME`) or a job's
    output (`needs.build.outputs.NAME`)."""
    wf = load(path)
    if event not in triggers(wf) or (event == "schedule" and schedule not in schedules(wf)):
        return set()
    results = {}
    for name, job in wf["jobs"].items():
        needs = job.get("needs", [])
        needs = [needs] if isinstance(needs, str) else needs
        context = {
            "github.event_name": event,
            "github.event.schedule": schedule,
            "github.repository": repository,
            "github.ref": ref,
            **{f"needs.{n}.result": results[n] for n in needs},
            **(context or {}),
        }
        success = all(results[n] == "success" for n in needs)
        cond = str(job.get("if", "")).strip()
        if not cond:
            runs = success
        elif re.search(r"\b(?:always|cancelled|success|failure)\(\)", cond):
            runs = bool(evaluate(cond, context, success))
        else:
            runs = success and bool(evaluate(cond, context, success))
        results[name] = ("failure" if name in failing else "success") if runs else "skipped"
    return {name for name, result in results.items() if result != "skipped"}


def schedules(wf):
    on = wf["on"]
    return [entry["cron"] for entry in (on.get("schedule") or [])] if isinstance(on, dict) else []


def test_the_expression_reader_reads_what_the_workflows_write():
    ctx = {"github.event_name": "Push", "github.ref": "refs/heads/main"}
    assert evaluate("github.event_name == 'push' && github.ref == 'refs/heads/main'", ctx) is True
    assert evaluate("!(github.event_name == 'push') || github.missing == 'x'", ctx) is False
    assert evaluate("${{ github.event_name == 'schedule' && 'a' || 'b' }}", ctx) == "b"
    assert evaluate("!cancelled() && failure()", ctx, success=False) is True
    assert evaluate("github.event.schedule == '13,43 * * * *'", {"github.event.schedule": RETRY}) is True


@pytest.mark.parametrize(
    ("event", "schedule", "jobs"),
    [
        ("push", None, {"test", "hardware"}),
        ("pull_request", None, {"test", "deb-build"}),  # (packaging) the build checks what it touches
        ("workflow_dispatch", None, {"test", "mutation"}),
        ("schedule", MUTATION, {"mutation"}),
        ("schedule", RETRY, {"hardware"}),  # the retry: the hardware job alone, never the tests
    ],
)
def test_each_event_runs_the_jobs_the_wiring_names(event, schedule, jobs):
    assert jobs_that_run(CI, event, schedule) == jobs


RELEASE = ROOT / ".github" / "workflows" / "release.yml"
RELEASE_BUILD = {"gate", "deb", "install-check-arm64", "install-check-amd64", "assets"}


@pytest.mark.parametrize(
    ("event", "where", "jobs"),
    [
        ("push", {}, RELEASE_BUILD | {"publish", "site"}),
        ("push", {"failing": ("publish",)}, RELEASE_BUILD | {"publish"}),  # no release, no site
        ("push", {"failing": ("install-check-arm64",)}, RELEASE_BUILD),
        ("workflow_dispatch", {"ref_type": "branch", "ref": "refs/heads/main"}, RELEASE_BUILD),
    ],
)
def test_a_release_starts_the_site_only_once_it_is_published(event, where, jobs):
    """A tag's run publishes the release and then starts the site; a manual run publishes nothing and
    starts nothing."""
    where = {"ref": "refs/tags/v0.3.1", **where}
    ref_type = where.pop("ref_type", "tag")
    assert jobs_that_run(RELEASE, event, context={"github.ref_type": ref_type}, **where) == jobs


def test_the_retry_runs_no_other_workflow():
    """virtual.yml and release.yml have no schedule, so the 30-minute trigger starts none of them."""
    for path in WORKFLOWS:
        if path.name != "ci.yml":
            assert "schedule" not in triggers(load(path)), path.name
    assert schedules(load(CI)) == [MUTATION, RETRY]


@pytest.mark.parametrize(
    ("event", "schedule", "where"),
    [
        ("push", None, {"repository": "someone/tvgw"}),
        ("push", None, {"ref": "refs/heads/other"}),
        ("push", None, {"failing": ("test",)}),
        ("schedule", RETRY, {"repository": "someone/tvgw"}),
        ("schedule", MUTATION, {}),
        ("pull_request", None, {}),
        ("workflow_dispatch", None, {}),
    ],
)
def test_the_hardware_job_runs_for_nothing_else(event, schedule, where):
    assert "hardware" not in jobs_that_run(CI, event, schedule, **where)


def test_the_hardware_job_names_only_the_push_and_the_retry():
    """The guard's three parts are there (test_a_job_that_can_reach...), and the only events the job's
    condition lets through are a push and the retry's schedule, which GitHub runs on the default branch
    alone, from that branch's copy of this file."""
    cond = load(CI)["jobs"]["hardware"]["if"]
    assert set(re.findall(r"github\.event_name == '(\w+)'", cond)) == {"push", "schedule"}
    assert re.findall(r"github\.event\.schedule == '([^']+)'", cond) == [RETRY]


def hardware():
    return load(CI)["jobs"]["hardware"]


def step(name_part):
    (found,) = [s for s in hardware()["steps"] if name_part in s.get("name", "")]
    return found


def test_every_hardware_step_runs_under_pipefail_and_through_the_scrubber():
    """Everything the job prints reaches a public log: each `run` ends in the checkout's scrubber, and
    the job's shell fails a step when anything in its pipe fails, not only the scrubber at its end."""
    shell = hardware()["defaults"]["run"]["shell"].split()
    assert shell[0] == "bash" and "-e" in shell and shell[shell.index("-o") + 1] == "pipefail"
    runs = [s for s in hardware()["steps"] if "run" in s]
    assert len(runs) >= 6
    for s in runs:
        assert "shell" not in s, s["name"]
        assert s["run"].rstrip().endswith(SCRUB), s["name"]


def test_no_python_the_job_runs_as_root_from_its_checkout_writes_bytecode_there():
    """The scrubber and `tvgw tv quiet` run as root from the runner's workspace. Bytecode they wrote
    would leave a root-owned __pycache__ there, which the next job's checkout, cleaning the workspace as
    the runner's user, cannot remove, and every later deploy would stop at its checkout. Each passes -B;
    the two window tools run as the runner's user and import the standard library alone, and the suite
    runs from /opt/tvgw/src with PYTHONDONTWRITEBYTECODE=1. The tool that waits asks `tvgw tv quiet`
    itself, as root, with the window step's own command."""
    runs = "\n".join(s["run"] for s in hardware()["steps"] if "run" in s)
    rooted = re.findall(r"sudo env PYTHONPATH=src python3((?:\s+-\w+)*)\s+-m\s+tvgw\b", runs)
    tools = [line for line in runs.splitlines() if re.search(r"python3 -I tools/\w+\.py", line)]
    assert len(rooted) == runs.count("python3 ") - len(tools)  # every python3 but the tools'
    assert len(rooted) >= 7 and all("-B" in flags.split() for flags in rooted)
    assert sorted(re.findall(r"tools/(\w+\.py --\w+)", runs)) == [
        "check_deploy_window.py --deploy",
        "wait_deploy_window.py --vouches",
        "wait_deploy_window.py --wait",
    ]
    for tool in tools:  # as the runner's user: any sudo on the line is the scrubber's, after the pipe
        assert "sudo" not in tool.split("|")[0], tool
    assert " ".join(WAIT_TOOL.ASK) == QUIET


def test_the_window_is_decided_from_the_checkout_before_anything_deploys():
    steps = hardware()["steps"]
    names = [s.get("name", "") for s in steps]
    window, deploy = step("the deploy window"), step("deploy this checkout")
    assert names.index(window["name"]) < names.index(deploy["name"])
    assert QUIET in window["run"]  # the checkout's own tvgw, before the gateway's has the command
    assert (
        "tools/check_deploy_window.py --deploy" in window["run"]
        and "/var/lib/tvgw/deploy-deferred" in window["run"]
    )
    assert '"0:deploy: now"' in window["run"] and '"1:deploy: deferred"' in window["run"]
    # at once (plain), in the window as the window step found it, or in the window the wait reached
    assert " ".join(deploy["if"].split()) == (
        "steps.window.outputs.deploy == 'now' || steps.window.outputs.deploy == 'plain'"
        " || steps.wait.outputs.deploy == 'now'"
    )
    assert "sync-install.sh" in deploy["run"]
    assert deploy["id"] == "deploy"  # the step that clears the marker asks whether this one ran


def test_a_deferred_run_waits_on_the_gateway_between_the_marker_and_the_deploy():
    """GitHub's schedule cannot be relied on to start a run inside the window, so the run that deferred
    waits for it: one more step that ends in the scrubber, after the marker and before the deploy, as
    the runner's user, with the commit the window step vouched for handed over in the environment."""
    names = [s.get("name", "") for s in hardware()["steps"]]
    order = [
        "the deploy window",
        "deferred to the quiet window",
        "wait for the quiet window",
        "deploy this checkout",
    ]
    assert [names.index(step(part)["name"]) for part in order] == sorted(
        names.index(step(p)["name"]) for p in order
    )
    wait = step("wait for the quiet window")
    assert wait["id"] == "wait" and wait["if"] == "steps.window.outputs.deploy == 'deferred'"
    assert wait["env"] == {"VOUCHED": "${{ steps.window.outputs.vouched }}"}
    assert wait["run"] == f'python3 -I tools/wait_deploy_window.py --wait "$VOUCHED" 2>&1 {SCRUB}'
    # the step outlives the tool's own limit, so the tool ends the wait and never the runner
    assert wait["timeout-minutes"] * 60 > WAIT_TOOL.LIMIT
    window = step("the deploy window")["run"]
    assert 'echo "vouched=$vouched" >>"$GITHUB_OUTPUT"' in window and "vouched=$GITHUB_SHA" in window


def test_a_deferred_run_leaves_the_marker_and_only_a_windowed_deploy_clears_it():
    deferred, cleared = step("deferred to the quiet window"), step("the deferred deploy has run")
    assert deferred["if"] == "steps.window.outputs.deploy == 'deferred'"
    assert "sudo tee /var/lib/tvgw/deploy-deferred" in deferred["run"] and "$GITHUB_SHA" in deferred["run"]
    assert "sync-install" not in deferred["run"]
    assert 'if [ "$EVENT" = push ]; then' in deferred["run"]  # the marker is a tested push's alone
    assert deferred["env"] == {"EVENT": "${{ github.event_name }}"}
    # only after a deploy step that ran, passed or failed: a window or wait step that wrote `now` and
    # then failed deploys nothing, and the marker of a deploy that never ran must stay
    assert " ".join(cleared["if"].split()) == (
        "!cancelled()"
        " && (steps.deploy.outcome == 'success' || steps.deploy.outcome == 'failure')"
        " && (steps.window.outputs.deploy == 'now' || steps.wait.outputs.deploy == 'now')"
    )
    assert "sudo rm -f /var/lib/tvgw/deploy-deferred" in cleared["run"]
    # the marker lives in the state directory, so tvgw forget knows it, and keeps it: a commit id
    for name in set(re.findall(r"/var/lib/tvgw/([\w.-]+)", CI.read_text(encoding="utf-8"))):
        assert forget.classify(name, forget.STATE_ENTRIES)[0] == forget.KEEP, name


def test_the_retry_stops_at_its_first_step_unless_a_deploy_waits():
    first = next(s for s in hardware()["steps"] if "run" in s)
    assert first["if"] == "github.event_name == 'schedule'"
    assert "sudo test -e /var/lib/tvgw/deploy-deferred" in first["run"]
    window = step("the deploy window")
    assert window["if"] == "github.event_name == 'push' || steps.waiting.outputs.waiting == 'yes'"
    # a scheduled run goes on only when the marker's commit vouches for its checkout, the marker's text
    # held to a commit id before it reaches the tool, and then leaves this step before the ask: the wait
    # asks, on the half hours, and deploys main's head as it reads it from the remote
    run = window["run"]
    assert "id='^([0123456789abcdef]{40}|[0123456789abcdef]{64})$'" in run
    assert (
        run.index('if [ "$EVENT" = schedule ]; then')
        < run.index("vouched=$(sudo cat /var/lib/tvgw/deploy-deferred)")
        < run.index('[[ "$vouched" =~ $id ]]')
        < run.index('python3 -I tools/wait_deploy_window.py --vouches "$vouched"')
        < run.index("this scheduled run takes the wait up")
        < run.index("vouched=$GITHUB_SHA")  # the push's part starts here
        < run.index("tv quiet --wait 0")
    )
    # actions/checkout makes refs/remotes/origin/main the run's own commit, also after main moved on,
    # so comparing the two can never find a stale run: the comparison that was here is not to come back
    # (the step's own run asks git nothing at all: the tests of its shell hold that)
    assert "refs/remotes/origin/main" not in run and "rev-parse" not in run


def test_the_retry_cannot_take_a_waiting_push_deploys_place():
    group = hardware()["concurrency"]["group"]
    assert evaluate(group, {"github.event_name": "push"}) == "deploy-tvgw"
    assert evaluate(group, {"github.event_name": "schedule"}) == "deploy-tvgw-retry"


# ---- (deploy window) the hardware job's steps, run under its own shell with stand-ins ------------------
FAKE_SUDO = """#!/bin/bash
# runs the command as given, with the gateway's state directory moved under the test's tmp_path
args=("${@//\\/var\\/lib\\/tvgw/$FAKE_STATE}")
exec "${args[@]}"
"""
FAKE_PYTHON = """#!/bin/bash
# every call but the scrubber's is kept, one line each, for the test to read
case "$*" in *"-m tvgw.scrub --stdin"*) ;; *) printf 'python3 %s\\n' "${*//$'\\n'/<newline>}" >>"$FAKE_CALLS" ;; esac
case "$*" in
  *"-m tvgw.scrub --stdin"*) exec sed 's/192\\.0\\.2\\.1/<router>/g' ;;
  *"-m tvgw tv quiet --wait 0"*) [ -z "$QUIET_LINE" ] || printf '%s\\n' "$QUIET_LINE"; exit "$QUIET_RC" ;;
  *"tools/check_deploy_window.py --deploy"*) echo "check_deploy_window: why, via 192.0.2.1" >&2; echo "$WINDOW_WORD" ;;
  *"tools/wait_deploy_window.py --vouches "*) echo "wait_deploy_window: why, via 192.0.2.1" >&2; exit "$VOUCHES_RC" ;;
  *"tools/wait_deploy_window.py --wait "*)
    [ -z "$WAIT_WORD" ] || echo "deploy=$WAIT_WORD" >>"$GITHUB_OUTPUT"
    echo "the wait's last line, via 192.0.2.1"
    exit "$WAIT_RC" ;;
  *) echo "unexpected: python3 $*" >&2; exit 99 ;;
esac
"""
FAKE_GIT = """#!/bin/bash
# the marker step's one question, kept for the test to read: is this run's commit an ancestor of the
# marker's? $ANCESTOR_RC answers as git does: 0 yes, 1 no, 128 with a line when it cannot tell
printf 'git %s\\n' "$*" >>"$FAKE_CALLS"
case "$*" in
  "merge-base --is-ancestor $GITHUB_SHA "*)
    [ "$ANCESTOR_RC" != 128 ] || echo "fatal: Not a valid commit name, says 192.0.2.1" >&2
    exit "$ANCESTOR_RC" ;;
  *) echo "unexpected: git $*" >&2; exit 98 ;;
esac
"""
SHA = "a" * 40
MARKED = "b" * 40  # the commit in the marker: the one a tested push deferred


def run_step(
    tmp_path,
    name_part,
    *,
    event="push",
    marker=False,
    word="plain",
    quiet=(0, "deploy: now"),
    vouches=0,
    wait=(0, "now"),
    vouched=SHA,
    ancestor=1,
):
    """One `run` of the hardware job under the job's shell, with sudo, python3 and git stood in for:
    (exit status, what it printed, what it wrote to $GITHUB_OUTPUT, whether the marker exists after).
    `marker` is True for a marker holding MARKED, or the marker's text. The step runs in tmp_path, and
    the python3 and git calls it made, the scrubber's aside, are in tmp_path/calls."""
    bash = shutil.which("bash")
    if not bash:
        pytest.skip("no bash")
    bin_dir, state = tmp_path / "bin", tmp_path / "state"
    bin_dir.mkdir(exist_ok=True)
    state.mkdir(exist_ok=True)
    for tool, text in (("sudo", FAKE_SUDO), ("python3", FAKE_PYTHON), ("git", FAKE_GIT)):
        (bin_dir / tool).write_text(text, encoding="utf-8")
        (bin_dir / tool).chmod(0o755)
    if marker is not False:
        text = MARKED + "\n" if marker is True else marker
        (state / "deploy-deferred").write_text(text, encoding="utf-8")
    output = tmp_path / "github_output"
    output.write_text("", encoding="utf-8")
    (tmp_path / "calls").write_text("", encoding="utf-8")
    shell = hardware()["defaults"]["run"]["shell"].replace("{0}", "").split()
    env = {
        "PATH": f"{bin_dir}:{os.environ['PATH']}",
        "FAKE_STATE": str(state),
        "GITHUB_OUTPUT": str(output),
        "GITHUB_SHA": SHA,
        "EVENT": event,
        "BEFORE": "c" * 40,
        "WINDOW_WORD": word,
        "QUIET_RC": str(quiet[0]),
        "QUIET_LINE": quiet[1],
        "ANCESTOR_RC": str(ancestor),
        "FAKE_CALLS": str(tmp_path / "calls"),
        "VOUCHES_RC": str(vouches),
        "WAIT_RC": str(wait[0]),
        "WAIT_WORD": wait[1],
        "VOUCHED": vouched,
    }
    script = step(name_part)["run"]
    out = subprocess.run(
        [bash, *shell[1:], "-c", script], env=env, cwd=tmp_path, capture_output=True, text=True, timeout=60
    )
    outputs = dict(line.split("=", 1) for line in output.read_text(encoding="utf-8").splitlines())
    return out.returncode, out.stdout + out.stderr, outputs, (state / "deploy-deferred").exists()


def calls(tmp_path, tool="python3"):
    """The python3 commands the step ran, the scrubber's aside, or the git ones."""
    lines = (tmp_path / "calls").read_text(encoding="utf-8").splitlines()
    return [line for line in lines if line.startswith(f"{tool} ")]


@pytest.mark.parametrize(
    ("marker", "word", "quiet", "outputs"),
    [
        (False, "plain", (0, "deploy: now"), {"deploy": "plain"}),  # as before the window existed
        (False, "tv-off", (0, "deploy: now"), {"deploy": "now"}),
        # a push that defers waits with its own commit: its tests passed
        (False, "tv-off", (1, "deploy: deferred"), {"deploy": "deferred", "vouched": SHA}),
        # one waits: the next waits too, and vouches for itself, never with the older commit
        (True, "plain", (1, "deploy: deferred"), {"deploy": "deferred", "vouched": SHA}),
        (True, "plain", (0, "deploy: now"), {"deploy": "now"}),
    ],
)
def test_the_window_step_decides_for_a_push_as_its_inputs_say(tmp_path, marker, word, quiet, outputs):
    rc, printed, wrote, _ = run_step(tmp_path, "the deploy window", marker=marker, word=word, quiet=quiet)
    assert rc == 0, printed
    assert wrote == outputs
    assert "192.0.2.1" not in printed  # stderr went through the scrubber too
    if outputs["deploy"] in ("now", "deferred"):
        assert quiet[1] in printed
    assert not any("wait_deploy_window.py" in c for c in calls(tmp_path))  # a push vouches for itself
    assert calls(tmp_path, "git") == []


@pytest.mark.parametrize("quiet", [(0, "deploy: now"), (1, "deploy: deferred"), (2, "Traceback")])
def test_a_scheduled_run_never_asks_in_the_window_step_and_takes_the_wait_up(tmp_path, quiet):
    """A scheduled run can start hours after it was created, behind a run that waited, with a commit
    main has left behind, at any minute. It neither asks `tvgw tv quiet` here nor deploys from this
    step, whatever the TV would answer: with a marker whose commit vouches for its checkout it takes
    the wait up, and the wait reads main from the remote, asks on the half hours and deploys main's
    head. Nothing asks git whether main moved: the checkout's tracking ref is the run's own commit."""
    rc, printed, wrote, exists = run_step(
        tmp_path, "the deploy window", event="schedule", marker=True, quiet=quiet
    )
    assert rc == 0 and exists, printed
    assert wrote == {"deploy": "deferred", "vouched": MARKED}
    assert "this scheduled run takes the wait up" in printed and "deploy: now" not in printed
    assert calls(tmp_path) == [f"python3 -I tools/wait_deploy_window.py --vouches {MARKED}"]
    assert calls(tmp_path, "git") == []


def test_the_schedule_skips_a_checkout_the_markers_commit_does_not_vouch_for(tmp_path):
    """The run's commit is a push whose tests failed, or have not passed yet, or one older than the
    commit that waits: the schedule must not take the wait with it, nor deploy it, as it did before
    the marker's commit had to vouch. Nothing asks the TV either."""
    rc, printed, wrote, exists = run_step(
        tmp_path, "the deploy window", event="schedule", marker=True, vouches=1
    )
    assert rc == 0 and wrote == {"deploy": "skip"} and exists
    assert "does not vouch for this run's commit" in printed and "192.0.2.1" not in printed
    assert calls(tmp_path) == [f"python3 -I tools/wait_deploy_window.py --vouches {MARKED}"]


@pytest.mark.parametrize(
    "text",
    [
        False,  # no file at all: it went between the first step and this one
        "",
        "\n",
        "main\n",
        "b" * 39 + "\n",
        "b" * 41 + "\n",
        "B" * 40 + "\n",
        "b" * 39 + "g\n",
        " " + "b" * 40 + "\n",
        "b" * 40 + " x\n",
        "b" * 40 + "\ndeploy=now\n",  # a second line would be a second output
        "b" * 40 + "\n" + "c" * 40 + "\n",
        "--upload-pack=touch x\n",
        "$(touch x)\n",
    ],
)
def test_a_marker_that_is_not_one_commit_id_reaches_neither_git_nor_the_outputs(tmp_path, text):
    rc, printed, wrote, _ = run_step(tmp_path, "the deploy window", event="schedule", marker=text)
    assert rc == 0 and wrote == {"deploy": "skip"}, printed
    assert "the marker does not hold a commit id" in printed
    assert calls(tmp_path) == [] and not (tmp_path / "x").exists()


@pytest.mark.parametrize("marker", [MARKED + "\n", "c" * 64 + "\n", MARKED])
def test_a_marker_that_is_a_commit_id_goes_to_the_tool_whole(tmp_path, marker):
    _, _, wrote, _ = run_step(tmp_path, "the deploy window", event="schedule", marker=marker)
    assert wrote == {"deploy": "deferred", "vouched": marker.strip()}
    assert calls(tmp_path)[0] == f"python3 -I tools/wait_deploy_window.py --vouches {marker.strip()}"


def test_a_vouching_check_that_does_not_answer_fails_the_step(tmp_path):
    rc, printed, wrote, _ = run_step(tmp_path, "the deploy window", event="schedule", marker=True, vouches=2)
    assert rc != 0 and wrote == {} and "::error::wait_deploy_window.py --vouches exited 2" in printed


@pytest.mark.parametrize("quiet", [(1, ""), (0, "deploy: deferred"), (2, "usage"), (1, "Traceback")])
def test_a_quiet_check_that_does_not_answer_fails_the_step(tmp_path, quiet):
    rc, printed, outputs, _ = run_step(tmp_path, "the deploy window", word="tv-off", quiet=quiet)
    assert rc != 0 and "deploy" not in outputs and "without its one line" in printed


def test_the_retry_stops_without_a_marker_and_goes_on_with_one(tmp_path):
    assert run_step(tmp_path, "goes on only while", event="schedule")[2] == {}
    assert run_step(tmp_path, "goes on only while", event="schedule", marker=True)[2] == {"waiting": "yes"}


def test_the_marker_is_written_deferred_and_cleared_after_the_windowed_deploy(tmp_path):
    rc, printed, _, exists = run_step(tmp_path, "deferred to the quiet window")
    assert rc == 0 and exists and (tmp_path / "state" / "deploy-deferred").read_text() == SHA + "\n"
    assert "::notice::deploy: deferred" in printed
    assert "this run waits" in printed and "skipped" not in printed  # the run goes on: it waits
    rc, _, _, exists = run_step(tmp_path, "the deferred deploy has run", marker=True)
    assert rc == 0 and not exists


@pytest.mark.parametrize(
    ("marker", "ancestor", "kept", "asked"),
    [
        (False, 1, False, False),  # no marker: written, and git is not asked
        (SHA + "\n", 0, False, False),  # this run's own commit (a re-run): written again
        (True, 1, False, True),  # an older commit's, or a branch main left: replaced
        (True, 0, True, True),  # a newer commit's, which descends from this run's: it stays
        (True, 128, False, True),  # git cannot tell (the checkout lacks that commit): replaced
        ("not a commit\n", 0, False, False),  # no commit id: replaced, and it never reaches git
        ("", 0, False, False),
        ("b" * 40 + "\n--upload-pack=x\n", 0, False, False),
    ],
)
def test_a_push_writes_the_marker_unless_it_names_a_newer_commit(tmp_path, marker, ancestor, kept, asked):
    """A re-run of an older push's job must not take the marker from the newer commit that waits, or
    no scheduled run of main's head could take the wait up. Every other case writes the run's commit, a
    git error included: the step fails open to writing, so a tested push always gets its marker."""
    rc, printed, _, exists = run_step(
        tmp_path, "deferred to the quiet window", marker=marker, ancestor=ancestor
    )
    text = (tmp_path / "state" / "deploy-deferred").read_text(encoding="utf-8")
    assert rc == 0 and exists, printed
    assert text == (MARKED if kept else SHA) + "\n"
    assert ("the marker names a newer commit than this run's" in printed) is kept
    assert "::notice::deploy: deferred" in printed and "192.0.2.1" not in printed
    wanted = [f"git merge-base --is-ancestor {SHA} {MARKED}"] if asked else []
    assert calls(tmp_path, "git") == wanted


def test_only_a_push_writes_the_marker(tmp_path):
    """The marker names the newest commit a tested push deferred. A push replaces an older one; a
    scheduled run, which has no tests of its own, leaves it as it is, and writes none."""
    marker = tmp_path / "state" / "deploy-deferred"
    rc, _, _, exists = run_step(tmp_path, "deferred to the quiet window", marker=True)
    assert rc == 0 and exists and marker.read_text(encoding="utf-8") == SHA + "\n"
    marker.unlink()
    rc, printed, _, exists = run_step(tmp_path, "deferred to the quiet window", event="schedule", marker=True)
    assert rc == 0 and exists and marker.read_text(encoding="utf-8") == MARKED + "\n"
    assert "::notice::deploy: deferred" in printed
    marker.unlink()
    rc, _, _, exists = run_step(tmp_path, "deferred to the quiet window", event="schedule")
    assert rc == 0 and not exists


def test_the_wait_step_runs_the_tool_with_the_vouched_commit_through_the_scrubber(tmp_path):
    rc, printed, wrote, _ = run_step(tmp_path, "wait for the quiet window", vouched=MARKED)
    assert rc == 0 and wrote == {"deploy": "now"}
    assert calls(tmp_path) == [f"python3 -I tools/wait_deploy_window.py --wait {MARKED}"]
    assert "the wait's last line, via <router>" in printed and "192.0.2.1" not in printed


def test_a_wait_that_fails_fails_the_step(tmp_path):
    """pipefail: the tool's failure is the step's, though the scrubber after it ended well, so nothing
    deploys after an ask that did not answer."""
    rc, _, wrote, _ = run_step(tmp_path, "wait for the quiet window", wait=(1, ""))
    assert rc != 0 and wrote == {}


# ---- (site) the documentation site's workflow ----------------------------------------------------------
PAGES = ROOT / ".github" / "workflows" / "pages.yml"
VIRTUAL = ROOT / ".github" / "workflows" / "virtual.yml"
SITE_PATHS = {"docs/**", "README.md", "mkdocs.yml", ".github/workflows/pages.yml"}
# what the deploy needs besides the event: the owner's switch, and the build's gate saying yes
TURNED_ON = {"vars.TVGW_PAGES": "on", "needs.build.outputs.publish": "yes"}


def test_the_expression_reader_reads_a_repository_variable():
    assert evaluate("vars.TVGW_PAGES == 'on'", {"vars.TVGW_PAGES": "on"}) is True
    assert evaluate("vars.TVGW_PAGES == 'on'", {}) is False  # an unset variable reads as empty
    assert evaluate("needs.build.outputs.publish == 'yes'", {"needs.build.outputs.publish": "no"}) is False


@pytest.mark.parametrize(
    ("event", "where", "jobs"),
    [
        ("pull_request", {}, {"build"}),  # a pull request only builds, whatever the gate says
        ("push", {}, {"build", "deploy"}),
        ("push", {"context": {**TURNED_ON, "vars.TVGW_PAGES": ""}}, {"build"}),  # not turned on yet
        ("push", {"context": {**TURNED_ON, "vars.TVGW_PAGES": "off"}}, {"build"}),
        ("push", {"context": {**TURNED_ON, "needs.build.outputs.publish": "no"}}, {"build"}),  # unreleased
        ("push", {"repository": "someone/tvgw"}, {"build"}),  # a fork never publishes
        ("push", {"failing": ("build",)}, {"build"}),
        ("workflow_dispatch", {}, {"build", "deploy"}),
        ("workflow_dispatch", {"ref": "refs/heads/other"}, {"build"}),
        ("release", {"ref": "refs/tags/v0.3.0"}, {"build", "deploy"}),
        ("release", {"ref": "refs/tags/v0.3.0", "context": {**TURNED_ON, "vars.TVGW_PAGES": ""}}, {"build"}),
        ("schedule", {"schedule": RETRY}, set()),  # the deferred deploy's retry starts nothing here
    ],
)
def test_the_site_deploys_only_once_turned_on_and_only_what_the_gate_let_through(event, where, jobs):
    where = {"context": TURNED_ON, **where}
    assert jobs_that_run(PAGES, event, **where) == jobs


def test_the_site_workflow_triggers_on_the_docs_and_releases_alone():
    on = load(PAGES)["on"]
    assert set(on) == {"push", "pull_request", "release", "workflow_dispatch"}
    assert on["push"]["branches"] == ["main"]
    assert set(on["push"]["paths"]) == set(on["pull_request"]["paths"]) == SITE_PATHS
    assert on["release"] == {"types": ["published"]}


def test_the_release_starts_the_site_where_its_deploy_runs():
    """A dispatch is the one way release.yml's token can start pages.yml. It must name a workflow that takes
    one, on the branch the deploy accepts, or the site waits for the next push to main."""
    (step,) = load(RELEASE)["jobs"]["site"]["steps"]
    workflow, branch = re.search(r"\bgh workflow run (\S+) --ref (\S+);", step["run"]).groups()
    assert ROOT / ".github" / "workflows" / workflow == PAGES
    assert "workflow_dispatch" in triggers(load(PAGES))
    assert jobs_that_run(PAGES, "workflow_dispatch", ref=f"refs/heads/{branch}", context=TURNED_ON) == {
        "build",
        "deploy",
    }


def test_a_site_change_never_deploys_the_gateway():
    """ci.yml's hardware job and virtual.yml run on a push to main unless every changed file is ignored:
    the pages, the Markdown and the site's config are, so publishing the site deploys nothing."""
    for path in (CI, VIRTUAL):
        ignored = load(path)["on"]["push"]["paths-ignore"]
        assert {"**/*.md", "docs/**", "mkdocs.yml"} <= set(ignored), path.name


def test_only_the_deploy_job_may_write_and_only_to_pages():
    wf = load(PAGES)
    assert wf["permissions"] == {"contents": "read"}
    assert "permissions" not in wf["jobs"]["build"]
    deploy = wf["jobs"]["deploy"]
    assert deploy["permissions"] == {"pages": "write", "id-token": "write"}
    assert deploy["environment"]["name"] == "github-pages"
    assert deploy["concurrency"] == {"group": "docs-site-deploy", "cancel-in-progress": False}


def pins(path):
    return dict(line.split("uses:", 1)[1].split("#")[0].strip().split("@") for _, line in uses_lines(path))


def test_the_site_uses_the_four_actions_it_names_at_the_pins_ci_uses():
    site = pins(PAGES)
    assert set(site) == {
        "actions/checkout",
        "actions/setup-python",
        "actions/upload-pages-artifact",
        "actions/deploy-pages",
    }
    ci = pins(CI)
    assert {name: site[name] for name in site.keys() & ci.keys()} == {
        name: ci[name] for name in site.keys() & ci.keys()
    }


def build_steps():
    return load(PAGES)["jobs"]["build"]["steps"]


def site_step(name_part):
    (found,) = [s for s in build_steps() if name_part in s.get("name", "")]
    return found


def test_the_build_checks_links_before_it_builds_and_publishes_only_through_the_gate():
    steps = build_steps()
    runs = [s.get("run", "") for s in steps]

    def at(text):
        (index,) = [i for i, run in enumerate(runs) if text in run]
        return index

    assert (
        at("tools/check_docs_links.py")
        < at("--require-hashes --no-deps -r docs/site/requirements.lock")
        < at("docs/site/prebuild.py")
        < at("zensical build --strict")
        < at("docs/site/check_site.py")
        < at("docs/site/check_commands.py --against")
    )
    checkout = steps[0]
    assert checkout["uses"].startswith("actions/checkout@") and checkout["with"]["fetch-depth"] == 0  # tags
    upload = next(s for s in steps if s.get("uses", "").startswith("actions/upload-pages-artifact@"))
    assert upload["if"] == "github.event_name != 'pull_request' && steps.gate.outputs.publish == 'yes'"
    assert load(PAGES)["jobs"]["build"]["outputs"] == {"publish": "${{ steps.gate.outputs.publish }}"}


FAKE_GH = """#!/bin/bash
[ "$*" = "release view --repo kywwilson11/tvgw --json tagName -q .tagName" ] || exit 98
[ -n "$LATEST" ] || exit 1
printf '%s\\n' "$LATEST"
"""
FAKE_SITE_PYTHON = """#!/bin/bash
[ "$*" = "-I docs/site/check_commands.py --against $LATEST" ] || { echo "unexpected: $*" >&2; exit 99; }
exit "$CHECK_RC"
"""


def run_gate(tmp_path, *, event="push", latest="v0.2.0", check_rc=0, ref_name="main"):
    """The gate step under the runner's shell, with gh and python3 stood in for: (exit status, what it
    printed, what it wrote to $GITHUB_OUTPUT)."""
    bash = shutil.which("bash")
    if not bash:
        pytest.skip("no bash")
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir(exist_ok=True)
    for tool, text in (("gh", FAKE_GH), ("python3", FAKE_SITE_PYTHON)):
        (bin_dir / tool).write_text(text, encoding="utf-8")
        (bin_dir / tool).chmod(0o755)
    output = tmp_path / "github_output"
    output.write_text("", encoding="utf-8")
    env = {
        "PATH": f"{bin_dir}:{os.environ['PATH']}",
        "GITHUB_OUTPUT": str(output),
        "GITHUB_REPOSITORY": "kywwilson11/tvgw",
        "GITHUB_REF_NAME": ref_name,
        "EVENT": event,
        "LATEST": latest,
        "CHECK_RC": str(check_rc),
    }
    out = subprocess.run(
        [
            bash,
            "--noprofile",
            "--norc",
            "-eo",
            "pipefail",
            "-c",
            site_step("may this build be published")["run"],
        ],
        env=env,
        capture_output=True,
        text=True,
        timeout=60,
    )
    outputs = dict(line.split("=", 1) for line in output.read_text(encoding="utf-8").splitlines())
    return out.returncode, out.stdout + out.stderr, outputs


@pytest.mark.parametrize(
    ("where", "publish", "notice"),
    [
        ({}, "yes", None),
        (
            {"check_rc": 1},
            "no",
            "user pages name commands not yet released; the site updates with the next release",
        ),
        ({"event": "pull_request", "check_rc": 1}, "no", "not yet released"),
        # release.yml's dispatch on main right after a release: main's head is the tag, so the check
        # passes; once main has moved past it, the check decides
        ({"event": "workflow_dispatch"}, "yes", None),
        ({"event": "workflow_dispatch", "check_rc": 1}, "no", "not yet released"),
        ({"event": "release", "ref_name": "v0.2.0", "check_rc": 99}, "yes", None),  # its own tag: no check
        ({"event": "release", "ref_name": "v0.1.9"}, "no", "v0.1.9 is not the latest release (v0.2.0)"),
    ],
)
def test_the_gate_publishes_what_the_latest_release_can_run(tmp_path, where, publish, notice):
    rc, printed, outputs = run_gate(tmp_path, **where)
    assert rc == 0, printed
    assert outputs == {"publish": publish}
    if notice:
        assert "::notice::" in printed and notice in printed


@pytest.mark.parametrize(("where", "said"), [({"latest": ""}, "::error::"), ({"check_rc": 2}, "")])
def test_a_gate_that_cannot_decide_fails_the_build_rather_than_publish(tmp_path, where, said):
    rc, printed, outputs = run_gate(tmp_path, **where)
    assert rc != 0 and outputs == {}
    assert said in printed
