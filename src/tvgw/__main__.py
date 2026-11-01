"""`python3 -m tvgw`: the CLI before it is installed, so `tvgw setup` can run from a fresh checkout
(`sudo PYTHONPATH=src python3 -m tvgw setup`) on a Pi that has no `tvgw` command yet. Setup needs only
the standard library; a command that needs a package the system Python lacks says which to install."""

import sys

from tvgw.cli import main

APT = {"yaml": "python3-yaml"}  # what a checkout run on the system Python may lack, by module

try:
    sys.exit(main())
except ModuleNotFoundError as e:
    if e.name not in APT:
        raise
    pkg = APT[e.name]
    sys.exit(f"tvgw: this command needs {e.name}: install {pkg} (sudo apt install {pkg}) first")
