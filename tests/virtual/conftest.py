"""The virtual gateway's fixtures: one topology for the whole run, torn down however the run ends.

Every test module here sets `pytestmark = pytest.mark.virtual`, and its tests are skipped unless the
machine is Linux, the user is root and nft, ip, unshare, mount and bash exist. CI sets
TVGW_VIRTUAL_REQUIRED=1, which turns that skip into a failure: a suite that skipped itself in CI would
pass every firewall change unexamined."""

from __future__ import annotations

import os
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent))

import vnet  # the directory is not a package; its helpers are imported by path


def pytest_configure(config):
    config.addinivalue_line(
        "markers", "virtual: needs root, nft and ip; builds the namespace gateway (tests/virtual)"
    )


def pytest_collection_modifyitems(config, items):
    here = Path(__file__).resolve().parent
    mine = [item for item in items if Path(item.path).resolve().parent == here]
    missing = vnet.prerequisites()
    if not missing or not mine:
        return
    reason = "the virtual gateway needs " + ", ".join(missing)
    if os.environ.get("TVGW_VIRTUAL_REQUIRED") == "1":
        raise pytest.UsageError(f"TVGW_VIRTUAL_REQUIRED=1 but {reason}")
    for item in mine:
        item.add_marker(pytest.mark.skip(reason=reason))


@pytest.fixture(scope="session")
def artifacts(tmp_path_factory) -> Path:
    """Where the rendered rulesets, the applied baselines and the observed matrix go; CI uploads it."""
    path = Path(os.environ.get("TVGW_VIRTUAL_ARTIFACTS") or tmp_path_factory.mktemp("virtual"))
    path.mkdir(parents=True, exist_ok=True)
    return path


@pytest.fixture(scope="session")
def net(artifacts):
    """The topology, built once. The finalizer runs on a failure or an interrupt, and atexit (registered
    by vnet.Net) covers a run that dies before pytest can finalize; a later run deletes whatever a killed
    one left (vnet.stale_namespaces)."""
    n = vnet.Net(artifacts)
    try:
        n.build()
        yield n
    finally:
        n.destroy()
