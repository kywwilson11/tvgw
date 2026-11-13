"""The repository's automation as a system: what no job can be trusted to check about itself.

The workflows build what every gateway installs and hold the tokens that publish it, so they are
the most privileged code in the repository. These read every workflow under .github/workflows as YAML
and text and fail `make gate` when one drifts from docs/project/supply-chain.md: an action not pinned
by commit, a container image not pinned by digest, a workflow with no token permissions, a token that
can write a release or sign held by a job that does not need it, a trigger that hands a fork's code
the secrets, a `run:` line that splices attacker-controlled text into a shell, a job that could run on
a machine GitHub does not host, a dependabot file that stops watching an ecosystem. Nothing here
touches the network or GitHub."""

import json
import os
import re
import shutil
import subprocess

import pytest
import yaml
from conftest import ROOT

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
def test_no_workflow_runs_a_forks_code_with_secrets(path):
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


def refusal(job):
    """Why a job could run on a machine GitHub does not host, or None when it cannot."""
    if "runs-on" not in job:
        return "no runs-on: a called workflow chooses its own runner"
    labels = runner_labels(job["runs-on"])
    if any("${{" in label for label in labels):
        return "runs-on is an expression: name the runner"
    if not labels or not all(GITHUB_HOSTED.fullmatch(label) for label in labels):
        return f"{labels} can name a runner GitHub does not host"
    return None


def self_hosted_problems(path):
    """The jobs of a workflow that could reach a self-hosted runner, each with the reason. A job is
    safe only when every label it asks for is one GitHub's own runners alone carry. No condition
    excuses it: a job's `if:` is read from the file a push or a pull request supplies, so it guards
    nothing."""
    return [f"{path.name}: {name}: {why}" for name, job in all_jobs(path) if (why := refusal(job))]


@pytest.mark.parametrize("path", WORKFLOWS, ids=lambda p: p.name)
def test_no_job_of_any_workflow_can_reach_a_runner_github_does_not_host(path):
    """Until 2026-11-11 the reference gateway was a self-hosted runner whose user had unrestricted
    sudo, for a public repository: one approved pull request that edits a workflow, or one push with
    a stolen token, was root on the machine that holds the TV's firewall, inside the home network.
    A change now reaches a gateway only when its owner runs `make deploy` (design decision 83)."""
    assert "self-hosted" not in path.read_text(encoding="utf-8"), path.name
    assert self_hosted_problems(path) == []


# the condition the hardware job carried; it lived in the workflow file, which a pull request replaces
GUARD = "github.event_name == 'push' && github.repository == 'kywwilson11/tvgw' && github.ref == 'refs/heads/main'"


def one_job_workflow(tmp_path, job, condition=None):
    """A workflow of one job: `job` is its `runs-on:` or `uses:` line, `condition` its `if:`."""
    guard = f"    if: {condition}\n" if condition else ""
    return tmp_workflow(tmp_path, f"on: push\njobs:\n  j:\n{guard}    {job}\n")


@pytest.mark.parametrize("condition", [None, GUARD], ids=["bare", "guarded"])
@pytest.mark.parametrize(
    ("job", "why"),
    [
        # `self-hosted` is only one of the labels such a runner carries: its own and the machine's reach it too
        ("runs-on: tvgw", "can name a runner"),
        ("runs-on: [self-hosted]", "can name a runner"),
        ("runs-on: [Linux, ARM64]", "can name a runner"),
        ("runs-on: [ubuntu-latest, tvgw]", "can name a runner"),
        ("runs-on: pi-ubuntu-24.04", "can name a runner"),  # a hosted label inside another name is not one
        ("runs-on: { labels: [Linux, ARM64] }", "can name a runner"),
        ("runs-on: { group: pi }", "can name a runner"),
        ("runs-on: { group: pi, labels: [ubuntu-latest] }", "can name a runner"),
        ("runs-on: []", "can name a runner"),
        ("runs-on: ${{ matrix.runner }}", "expression"),
        ("runs-on: [self-hosted, '${{ inputs.label }}']", "expression"),
        ("uses: ./.github/workflows/other.yml", "no runs-on"),
    ],
)
def test_a_job_that_could_leave_githubs_runners_is_refused_whatever_its_condition(
    tmp_path, job, why, condition
):
    (problem,) = self_hosted_problems(one_job_workflow(tmp_path, job, condition))
    assert why in problem


@pytest.mark.parametrize(
    "job", ["runs-on: ubuntu-latest", "runs-on: [ubuntu-24.04-arm]", "runs-on: { labels: [macos-14] }"]
)
def test_a_job_on_githubs_own_runners_passes(tmp_path, job):
    assert self_hosted_problems(one_job_workflow(tmp_path, job)) == []


def test_the_checkouts_of_ci_leave_no_token_behind():
    """Nothing in ci.yml pushes, and the default leaves the job's token in `.git/config`."""
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


def test_the_documented_branch_protection_cannot_block_the_owners_push():
    """The settings the page tells the owner to apply: no force pushes, no deletion, a linear history,
    and nothing that stands in the way of the owner's own push to main (no required checks, no pull
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


# ---- which jobs each event runs, read from the `if:` expressions themselves -------------------------
CI = ROOT / ".github" / "workflows" / "ci.yml"
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
    assert evaluate("github.event.schedule == '17 6 * * 1'", {"github.event.schedule": MUTATION}) is True


@pytest.mark.parametrize(
    ("event", "schedule", "jobs"),
    [
        ("push", None, {"test"}),  # nothing deploys: no job runs on a gateway (design decision 83)
        ("pull_request", None, {"test", "deb-build"}),  # (packaging) the build checks what it touches
        ("workflow_dispatch", None, {"test", "mutation"}),
        ("schedule", MUTATION, {"mutation"}),
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


def test_the_one_schedule_is_the_weekly_mutation_run():
    """No other workflow has a schedule, and ci.yml's starts the mutation job alone."""
    for path in WORKFLOWS:
        if path.name != "ci.yml":
            assert "schedule" not in triggers(load(path)), path.name
    assert schedules(load(CI)) == [MUTATION]


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
        ("schedule", {"schedule": MUTATION}, set()),  # ci.yml's weekly schedule starts nothing here
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


def test_a_site_change_runs_neither_the_unit_tests_nor_the_namespace_tier():
    """ci.yml and virtual.yml run on a push to main unless every changed file is ignored: the pages,
    the Markdown and the site's config are, and the site's own workflow checks what it publishes."""
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
