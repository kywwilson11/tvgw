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


@pytest.hookimpl(trylast=True)  # after pytest's own reorder, which in_scenario_order overrides
def pytest_collection_modifyitems(config, items):
    in_scenario_order(items)
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


def in_scenario_order(items: list) -> None:
    """test_virtual_gateway.py's tests that take a scenario, put scenario by scenario in the matrix's
    order, each scenario's in the file's order and its rows in the matrix's, so each scenario is applied
    once, as the dispatcher would. The other tests keep their places. pytest reorders the tests of a
    module-scoped parameter to share its setups, and from 9.2 on it groups them by the parameter's value:
    the `row` parameter, the same Row in two scenarios (the QUIC row is in three), pulled the scenarios
    apart, and the gateway was applied again for nearly every row (46 applies for four scenarios)."""
    order = {s.name: s for s in vnet.parse_matrix(vnet.MATRIX.read_text(encoding="utf-8"))}
    names = list(order)

    def scenario_of(item) -> str | None:
        params = getattr(getattr(item, "callspec", None), "params", {})
        name = params.get("scenario")
        return name if Path(item.path).name == "test_virtual_gateway.py" and name in order else None

    def key(item) -> tuple[int, int, int]:
        name = scenario_of(item)
        row = item.callspec.params.get("row")
        return names.index(name), item.location[1], order[name].rows.index(row) if row else 0

    slots = [n for n, item in enumerate(items) if scenario_of(item)]
    for n, item in zip(slots, sorted((items[n] for n in slots), key=key), strict=True):
        items[n] = item


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
