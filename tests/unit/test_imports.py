"""Every module of the package imports first, in an interpreter that has read nothing of tvgw. A cycle
between modules shows only for the module that happens to be read first, and the unit suite reads them
in one order: design decision 90's change met one (walls, ingest, forget, ports and walls again) that
only the namespace tier's order showed."""

import pkgutil
import subprocess
import sys

import pytest

import tvgw

# `tvgw.__main__` is the command itself: reading it runs it
MODULES = sorted(
    m.name for m in pkgutil.walk_packages(tvgw.__path__, "tvgw.") if not m.name.endswith(".__main__")
)


@pytest.mark.parametrize("module", MODULES)
def test_a_module_imports_first(module):
    done = subprocess.run(
        [sys.executable, "-c", f"import {module}"], capture_output=True, text=True, check=False
    )
    assert done.returncode == 0, done.stderr[-600:]
