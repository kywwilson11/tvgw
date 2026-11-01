"""Record what the installed tshark prints for each corpus pcap, as tests/corpora/tsv/tshark-<version>/.

Run on a machine with tshark (the Pi), as an ordinary user, from the checkout:

    PYTHONPATH=src python3 tests/corpora/record.py

It runs exactly the command ingest runs (`tvgw.tshark.command`, without the sandbox: the corpus is
synthetic and needs no privilege) and writes tshark's stdout per case. Commit the new directory:
tests/unit/test_corpora.py then checks those rows on every machine, tshark or not, so a field that
prints differently in a new tshark version shows up as a test failure, keyed by that version.
"""

from __future__ import annotations

import re
import subprocess
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent


def tshark_version() -> str:
    out = subprocess.run(["tshark", "--version"], capture_output=True, encoding="utf-8", check=True).stdout
    m = re.search(r"TShark \(Wireshark\) (\d+\.\d+\.\d+)", out)
    if not m:
        sys.exit(f"cannot read the tshark version from: {out[:100]!r}")
    return m.group(1)


def main() -> None:
    from tvgw import tshark

    out_dir = HERE / "tsv" / f"tshark-{tshark_version()}"
    out_dir.mkdir(parents=True, exist_ok=True)
    for pcap in sorted((HERE / "pcap").glob("*.pcap")):
        run = subprocess.run(
            tshark.command(str(pcap)), capture_output=True, encoding="utf-8", errors="replace"
        )
        cut_short = run.returncode == tshark.CUT_SHORT_RC and tshark.CUT_SHORT_TEXT in run.stderr
        if run.returncode != 0 and not cut_short:
            sys.exit(f"{pcap.name}: tshark rc={run.returncode}: {run.stderr.strip()[:200]}")
        (out_dir / f"{pcap.stem}.tsv").write_text(run.stdout, encoding="utf-8")
        print(out_dir.name, pcap.stem, len([x for x in run.stdout.split("\n") if x]), "rows")


if __name__ == "__main__":
    main()
