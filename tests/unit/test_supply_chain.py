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
from conftest import ROOT

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
RETRY = "*/30 * * * *"
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
    assert evaluate("github.event.schedule == '*/30 * * * *'", {"github.event.schedule": RETRY}) is True


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
    assert len(runs) >= 5
    for s in runs:
        assert "shell" not in s, s["name"]
        assert s["run"].rstrip().endswith(SCRUB), s["name"]


def test_no_python_the_job_runs_as_root_from_its_checkout_writes_bytecode_there():
    """The scrubber and `tvgw tv quiet` run as root from the runner's workspace. Bytecode they wrote
    would leave a root-owned __pycache__ there, which the next job's checkout, cleaning the workspace as
    the runner's user, cannot remove, and every later deploy would stop at its checkout. Each passes -B;
    the window tool runs as the runner's user and imports the standard library alone, and the suite runs
    from /opt/tvgw/src with PYTHONDONTWRITEBYTECODE=1."""
    runs = "\n".join(s["run"] for s in hardware()["steps"] if "run" in s)
    rooted = re.findall(r"sudo env PYTHONPATH=src python3((?:\s+-\w+)*)\s+-m\s+tvgw\b", runs)
    assert len(rooted) == runs.count("python3 ") - 1  # every python3 but the window tool's
    assert len(rooted) >= 6 and all("-B" in flags.split() for flags in rooted)
    (tool,) = [line for line in runs.splitlines() if "tools/check_deploy_window.py" in line]
    assert "sudo" not in tool


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
    assert set(re.findall(r"deploy == '(\w+)'", deploy["if"])) == {"now", "plain"}
    assert "sync-install.sh" in deploy["run"]


def test_a_deferred_run_leaves_the_marker_and_only_a_windowed_deploy_clears_it():
    deferred, cleared = step("deferred to the quiet window"), step("the deferred deploy has run")
    assert deferred["if"] == "steps.window.outputs.deploy == 'deferred'"
    assert "sudo tee /var/lib/tvgw/deploy-deferred" in deferred["run"] and "$GITHUB_SHA" in deferred["run"]
    assert "sync-install" not in deferred["run"]
    assert "steps.window.outputs.deploy == 'now'" in cleared["if"]
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
    # the retry deploys main's head, never an older commit
    assert "git rev-parse --verify -q refs/remotes/origin/main" in window["run"]
    assert '"$GITHUB_SHA"' in window["run"]


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
case "$*" in
  *"-m tvgw.scrub --stdin"*) exec sed 's/192\\.0\\.2\\.1/<router>/g' ;;
  *"-m tvgw tv quiet --wait 0"*) [ -z "$QUIET_LINE" ] || printf '%s\\n' "$QUIET_LINE"; exit "$QUIET_RC" ;;
  *"tools/check_deploy_window.py --deploy"*) echo "check_deploy_window: why, via 192.0.2.1" >&2; echo "$WINDOW_WORD" ;;
  *) echo "unexpected: python3 $*" >&2; exit 99 ;;
esac
"""
FAKE_GIT = """#!/bin/bash
[ "$*" = "rev-parse --verify -q refs/remotes/origin/main" ] || exit 98
[ -n "$REMOTE_HEAD" ] || exit 1
printf '%s\\n' "$REMOTE_HEAD"
"""
SHA = "a" * 40


def run_step(
    tmp_path, name_part, *, event="push", marker=False, word="plain", quiet=(0, "deploy: now"), head=SHA
):
    """One `run` of the hardware job under the job's shell, with sudo, python3 and git stood in for:
    (exit status, what it printed, what it wrote to $GITHUB_OUTPUT, whether the marker exists after)."""
    bash = shutil.which("bash")
    if not bash:
        pytest.skip("no bash")
    bin_dir, state = tmp_path / "bin", tmp_path / "state"
    bin_dir.mkdir(exist_ok=True)
    state.mkdir(exist_ok=True)
    for tool, text in (("sudo", FAKE_SUDO), ("python3", FAKE_PYTHON), ("git", FAKE_GIT)):
        (bin_dir / tool).write_text(text, encoding="utf-8")
        (bin_dir / tool).chmod(0o755)
    if marker:
        (state / "deploy-deferred").write_text("b" * 40 + "\n", encoding="utf-8")
    output = tmp_path / "github_output"
    output.write_text("", encoding="utf-8")
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
        "REMOTE_HEAD": head,
    }
    script = step(name_part)["run"]
    out = subprocess.run(
        [bash, *shell[1:], "-c", script], env=env, capture_output=True, text=True, timeout=60
    )
    outputs = dict(line.split("=", 1) for line in output.read_text(encoding="utf-8").splitlines())
    return out.returncode, out.stdout + out.stderr, outputs, (state / "deploy-deferred").exists()


@pytest.mark.parametrize(
    ("event", "marker", "word", "quiet", "head", "deploy"),
    [
        ("push", False, "plain", (0, "deploy: now"), SHA, "plain"),  # as before the window existed
        ("push", False, "tv-off", (0, "deploy: now"), SHA, "now"),
        ("push", False, "tv-off", (1, "deploy: deferred"), SHA, "deferred"),
        ("push", True, "plain", (1, "deploy: deferred"), SHA, "deferred"),  # one waits: the next waits too
        ("schedule", True, "", (0, "deploy: now"), SHA, "now"),
        ("schedule", True, "", (0, "deploy: now"), "d" * 40, "skip"),  # main moved on: its own run deploys
        ("schedule", True, "", (0, "deploy: now"), "", "skip"),  # main unreadable: wait for the next retry
    ],
)
def test_the_window_step_decides_as_its_inputs_say(tmp_path, event, marker, word, quiet, head, deploy):
    rc, printed, outputs, _ = run_step(
        tmp_path, "the deploy window", event=event, marker=marker, word=word, quiet=quiet, head=head
    )
    assert rc == 0, printed
    assert outputs == {"deploy": deploy}
    assert "192.0.2.1" not in printed  # stderr went through the scrubber too
    if deploy in ("now", "deferred"):
        assert quiet[1] in printed


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
    rc, _, _, exists = run_step(tmp_path, "the deferred deploy has run", marker=True)
    assert rc == 0 and not exists


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
