"""The golden corpus's builder (tests/corpora/build.py), importable from the unit tests.

Loaded by path under a name of its own: a bare `import build` could find PyPA's `build` package."""

import importlib.util
import sys
from pathlib import Path

CORPORA = Path(__file__).resolve().parents[1] / "corpora"


def _load():
    spec = importlib.util.spec_from_file_location("tvgw_corpus_build", CORPORA / "build.py")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module  # dataclasses look their module up while the file runs
    spec.loader.exec_module(module)
    return module


build = sys.modules.get("tvgw_corpus_build") or _load()
