"""conftest's ROOT is the checkout wherever the suite runs from: tests/unit in a checkout, and the copy
mutmut runs it from, mutants/, which holds tests/ and pyproject.toml beside the mutated src/ and no
deploy/. CI's weekly mutation run of 2026-11-02 failed at collection because ROOT was the folder two
above the test file, mutants/ there, which has no deploy/nftables/tvgw-apply."""

import os
import re
import shutil
import subprocess
import sys
from pathlib import Path

from conftest import ROOT, find_root

CONFTEST = ROOT / "tests" / "unit" / "conftest.py"


def plant_checkout(folder: Path) -> Path:
    """The two files that make a folder the checkout."""
    (folder / "deploy" / "nftables").mkdir(parents=True)
    (folder / "deploy" / "nftables" / "tvgw-apply").write_text("#!/bin/sh\n", encoding="utf-8")
    (folder / "pyproject.toml").write_text('[project]\nname = "tvgw"\n', encoding="utf-8")
    return folder


def copy_tests(into: Path) -> Path:
    """tests/unit's conftest.py copied to <into>/tests/unit, as mutmut copies tests/: the copy's path."""
    (into / "tests" / "unit").mkdir(parents=True)
    return Path(shutil.copy(CONFTEST, into / "tests" / "unit" / "conftest.py"))


def root_of(conftest_copy: Path) -> Path:
    """The ROOT a copied conftest.py works out, imported in a child python from where it sits, on the
    checkout's own src/: under mutmut the tvgw this process imported is the mutated copy, which needs
    mutmut's settings from the folder the child runs in."""
    out = subprocess.run(
        [
            sys.executable,
            "-c",
            "import runpy, sys; print(runpy.run_path(sys.argv[1])['ROOT'])",
            conftest_copy,
        ],
        env={**os.environ, "PYTHONPATH": str(ROOT / "src")},
        cwd=conftest_copy.parent,
        capture_output=True,
        text=True,
        timeout=60,
    )
    assert out.returncode == 0, out.stderr
    return Path(out.stdout.strip())


def test_the_root_is_this_checkout():
    assert (ROOT / "deploy" / "nftables" / "tvgw-apply").is_file() and (ROOT / "pyproject.toml").is_file()
    assert find_root(CONFTEST) == ROOT


def test_a_copied_tests_dir_two_levels_down_finds_the_planted_checkout(tmp_path):
    checkout = plant_checkout(tmp_path / "checkout")
    copy = copy_tests(checkout / "a" / "b")
    assert root_of(copy) == checkout.resolve()


def test_mutmuts_copy_finds_the_checkout_above_it(tmp_path):
    """mutants/ has a pyproject.toml of its own and no deploy/: the walk goes on past it."""
    checkout = plant_checkout(tmp_path / "checkout")
    (checkout / "mutants").mkdir()
    shutil.copy(checkout / "pyproject.toml", checkout / "mutants" / "pyproject.toml")
    copy = copy_tests(checkout / "mutants")
    assert root_of(copy) == checkout.resolve()


def test_the_nearest_checkout_wins_and_none_leaves_the_folder_two_above(tmp_path):
    outer = plant_checkout(tmp_path / "outer")
    inner = plant_checkout(outer / "inner")
    assert find_root(inner / "tests" / "unit" / "conftest.py") == inner.resolve()
    # with no checkout above it, the folder two above the file, as ROOT was before the walk
    lone = tmp_path / "lone" / "tests" / "unit" / "conftest.py"
    assert find_root(lone) == (tmp_path / "lone").resolve()


def test_every_test_file_reads_the_checkout_through_conftest():
    """A module that works out the checkout from its own path finds mutants/ under mutmut, so the walk
    lives in conftest.py alone. A folder inside tests/ (tests/corpora, tests/virtual) is copied with the
    tests, so a path one level up stays fine."""
    two_up = re.compile(r"__file__\)(?:\.resolve\(\))?\.parents\[[2-9]\]|parent\.parent\.parent")
    found = [
        p.name
        for p in sorted((ROOT / "tests" / "unit").glob("*.py"))
        if p.name != "conftest.py" and two_up.search(p.read_text(encoding="utf-8"))
    ]
    assert found == []
