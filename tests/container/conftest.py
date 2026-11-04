"""The container tier's fixtures: the image, one booted gateway per test module, and the stages.

Every test module here sets `pytestmark = pytest.mark.container`, and its tests are skipped unless a Docker
daemon answers. CI sets TVGW_CONTAINER_REQUIRED=1, which turns that skip into a failure: a tier that
skipped itself in CI would pass every installer change unexamined.

A module's tests are the stages of one install, in file order, on one container: a stage needs the ones
before it, so after a failure the later stages of that module are skipped and name the stage that
failed, instead of failing for its reason."""

from __future__ import annotations

import hashlib
import os
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent))

import ctr  # the directory is not a package; its helpers are imported by path

_FAILED: dict[str, str] = {}  # module -> the first stage that failed in it


def pytest_configure(config):
    config.addinivalue_line(
        "markers", "container: needs Docker; boots a systemd gateway in a container (tests/container)"
    )


def pytest_collection_modifyitems(config, items):
    here = Path(__file__).resolve().parent
    mine = [item for item in items if Path(item.path).resolve().parent == here]
    if not mine:
        return
    why = ctr.Docker().available()
    if not why:
        return
    reason = f"the container tier needs a Docker daemon ({why})"
    if os.environ.get("TVGW_CONTAINER_REQUIRED") == "1":
        raise pytest.UsageError(f"TVGW_CONTAINER_REQUIRED=1 but {reason}")
    for item in mine:
        item.add_marker(pytest.mark.skip(reason=reason))


@pytest.hookimpl(hookwrapper=True)
def pytest_runtest_makereport(item, call):
    outcome = yield
    report = outcome.get_result()
    if report.when == "call" and report.failed and not hasattr(report, "wasxfail"):
        _FAILED.setdefault(item.module.__name__, item.name)


def pytest_runtest_setup(item):
    failed = _FAILED.get(item.module.__name__)
    if failed is not None:
        pytest.skip(f"an earlier stage failed: {failed}")


@pytest.fixture(scope="session")
def artifacts(tmp_path_factory) -> Path:
    """Where each container's journal, installer output and captures go; CI uploads it."""
    path = Path(os.environ.get("TVGW_CONTAINER_ARTIFACTS") or tmp_path_factory.mktemp("container"))
    path.mkdir(parents=True, exist_ok=True)
    return path


@pytest.fixture(scope="session")
def docker() -> ctr.Docker:
    d = ctr.Docker()
    # a killed run's containers, recognised by the name's process id
    listing = d("ps", "--all", "--filter", f"label={ctr.LABEL}", "--format", "{{.Names}}", check=False)
    for name in ctr.stale(listing.stdout.split()):
        d("rm", "--force", "--volumes", name, check=False)
    return d


@pytest.fixture(scope="session")
def image(docker) -> str:
    """TVGW_CONTAINER_IMAGE when CI built it already; otherwise built here and tagged by what goes into
    it (the Dockerfile and image/, the whole build context), so an unchanged image is built once."""
    named = os.environ.get("TVGW_CONTAINER_IMAGE")
    if named:
        return named
    h = hashlib.sha256()
    for path in ctr.image_files():
        h.update(str(path.relative_to(ctr.HERE)).encode() + b"\0" + path.read_bytes())
    tag = f"tvgw-container:{h.hexdigest()[:12]}"
    if docker("image", "inspect", tag, check=False).returncode != 0:
        docker("build", "--tag", tag, str(ctr.HERE), timeout=1800)
    return tag


@pytest.fixture(scope="module")
def gateway(request, docker, image, artifacts) -> ctr.Gateway:
    """A booted gateway for one module: the checkout copied in and tvgw in its virtualenv (Gateway.prepare),
    and nothing else of tvgw. The container is saved to the artifacts and removed when the module ends,
    however it ends."""
    name = ctr.container_name(request.module.__name__.rpartition(".")[2])
    docker(*ctr.run_argv(image, name, ctr.ROOT), timeout=300)
    gw = ctr.Gateway(docker, name, artifacts)
    try:
        state = gw.wait_booted()
        gw.keep(
            "boot.txt", f"systemd: {state}\n" + gw.sh("systemctl --failed --no-pager", check=False).stdout
        )
        gw.prepare()
        yield gw
    finally:
        gw.save()
        gw.remove()
