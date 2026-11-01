"""`python3 -m tvgw`: the CLI before it is installed, so `tvgw setup` can run from a fresh checkout
(`sudo PYTHONPATH=src python3 -m tvgw setup`) on a Pi that has no `tvgw` command yet."""

import sys

from tvgw.cli import main

sys.exit(main())
