#!/usr/bin/env python3
"""(reliability) What each `synchronous` setting costs a store commit on this machine's disk (design
decision 73).

The store uses a rollback journal (`journal_mode=DELETE`, decision 10), so the choice is among NORMAL,
FULL and EXTRA; WAL with NORMAL is measured beside them for the record, since it is what an SD card is
usually given and decision 10 rules out. Each mode commits the same small transaction COMMITS times, one
row like a gateway sample with an index, into a fresh scratch store in DIR, and the median and the 95th
percentile of a commit's wall time are printed. With `--device NAME` (Linux) the block device's own
counters are read before and after each mode from /sys/block/NAME/stat: the 512-byte sectors written and
the cache flushes the kernel sent the device, per commit. Those counters are the whole device's, so other
writers add to them; run it on a quiet machine, and read them as an upper bound.

The scratch stores are removed afterwards. Standard library only, so it runs from a checkout on the
gateway: `sudo python3 tools/sync_bench.py --dir /var/tmp --device mmcblk0` (a directory on the card,
not /tmp, which is memory on Debian 13). It writes about COMMITS x 3 small files' worth to that disk.
"""

from __future__ import annotations

import argparse
import os
import shutil
import sqlite3
import statistics
import sys
import tempfile
import time
from collections.abc import Callable

MODES = (("DELETE", "NORMAL"), ("DELETE", "FULL"), ("DELETE", "EXTRA"), ("WAL", "NORMAL"))
ROW = b"x" * 300  # about one gw_samples row


def device_counters(device: str, read: Callable[[str], str] | None = None) -> tuple[int, int] | None:
    """(sectors written, flush requests completed) of /sys/block/DEVICE/stat, or None where the file is
    missing or older than the flush fields (Linux 5.5)."""
    read = read or (lambda p: open(p, encoding="utf-8").read())  # noqa: SIM115 - a one-line read
    try:
        fields = read(f"/sys/block/{device}/stat").split()
    except OSError:
        return None
    if len(fields) < 15:
        return None
    return int(fields[6]), int(fields[14])


def bench(
    directory: str,
    journal: str,
    sync: str,
    commits: int,
    clock: Callable[[], float] = time.perf_counter,
) -> list[float]:
    """Seconds per commit, for `commits` commits of one row each into a fresh store in `directory`."""
    path = os.path.join(directory, f"bench-{journal}-{sync}.db".lower())
    conn = sqlite3.connect(path, isolation_level=None)
    try:
        conn.execute(f"PRAGMA journal_mode={journal}")
        conn.execute(f"PRAGMA synchronous={sync}")
        conn.execute("CREATE TABLE s(t REAL PRIMARY KEY, v BLOB)")
        conn.execute("CREATE INDEX s_v ON s(v)")
        times = []
        for n in range(commits):
            t0 = clock()
            conn.execute("BEGIN")
            conn.execute("INSERT INTO s VALUES (?, ?)", (float(n), ROW))
            conn.execute("COMMIT")
            times.append(clock() - t0)
        return times
    finally:
        conn.close()


def run(
    directory: str,
    commits: int,
    device: str | None = None,
    out=None,
    keep: bool = False,
    read: Callable[[str], str] | None = None,
) -> list[dict]:
    """Every mode in MODES, one after the other, in a scratch directory inside `directory`; one dict per
    mode, printed as a table on `out`. `read` reads the device's counter file (the tests' seam)."""
    out = out or sys.stdout
    scratch = tempfile.mkdtemp(prefix="tvgw-sync-bench-", dir=directory)
    rows = []
    try:
        for journal, sync in MODES:
            before = device_counters(device, read) if device else None
            times = bench(scratch, journal, sync, commits)
            after = device_counters(device, read) if device else None
            row = {
                "mode": f"{journal}/{sync}",
                "commits": commits,
                "median_ms": statistics.median(times) * 1000,
                "p95_ms": sorted(times)[max(0, int(len(times) * 0.95) - 1)] * 1000,
            }
            if before and after:
                row["sectors_per_commit"] = (after[0] - before[0]) / commits
                row["flushes_per_commit"] = (after[1] - before[1]) / commits
            rows.append(row)
    finally:
        if not keep:
            shutil.rmtree(scratch, ignore_errors=True)
    head = f"{'mode':<14}{'median ms':>11}{'p95 ms':>9}"
    if any("sectors_per_commit" in r for r in rows):
        head += f"{'sectors/commit':>16}{'flushes/commit':>16}"
    print(f"{commits} commits per mode in {directory}; SQLite {sqlite3.sqlite_version}", file=out)
    print(head, file=out)
    for r in rows:
        line = f"{r['mode']:<14}{r['median_ms']:>11.3f}{r['p95_ms']:>9.3f}"
        if "sectors_per_commit" in r:
            line += f"{r['sectors_per_commit']:>16.1f}{r['flushes_per_commit']:>16.2f}"
        print(line, file=out)
    return rows


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    p.add_argument("--dir", required=True, help="a directory on the disk to measure (not a memory one)")
    p.add_argument("--commits", type=int, default=200, help="commits per mode (default 200)")
    p.add_argument("--device", help="the block device under DIR, as /sys/block names it (Linux)")
    a = p.parse_args(argv)
    if a.commits < 1:
        p.error("--commits must be at least 1")
    run(a.dir, a.commits, a.device)
    return 0


if __name__ == "__main__":
    sys.exit(main())
