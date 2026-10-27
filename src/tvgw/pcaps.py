"""The pcap directory as a store: which files tcpdump has finished with.

A file is finished when no tcpdump process holds it open, read from /proc. That answer is exact
without a naming convention or a rename hook, and it stays right when tcpdump is down (every file
is finished) or a clock step reorders names. Listing another process's descriptors needs root,
which ingest has on the gateway; where the answer cannot be had, callers get None and must not
guess, because reading a file tcpdump is still writing would record half an hour as a whole one.
"""

from __future__ import annotations

import glob
import os


def live_files(pcap_dir: str, proc: str = "/proc") -> set[str] | None:
    """Realpaths of the `.pcap` files in `pcap_dir` that a tcpdump process holds open, or None when
    that cannot be told (no /proc, or a tcpdump whose descriptors we may not list)."""
    here = os.path.realpath(pcap_dir)
    try:
        pids = [p for p in os.listdir(proc) if p.isdigit()]
    except OSError:
        return None
    live: set[str] = set()
    for pid in pids:
        try:
            with open(os.path.join(proc, pid, "comm")) as fh:
                if fh.read().strip() != "tcpdump":
                    continue
            fds = os.listdir(os.path.join(proc, pid, "fd"))
        except PermissionError:
            return None
        except OSError:  # the process ended between the listing and the read
            continue
        for fd in fds:
            try:
                target = os.readlink(os.path.join(proc, pid, "fd", fd))
            except OSError:
                continue
            path = os.path.realpath(target.removesuffix(" (deleted)"))
            if os.path.dirname(path) == here and path.endswith(".pcap"):
                live.add(path)
    return live


def finished(pcap_dir: str, live: set[str]) -> list[str]:
    """The `.pcap` paths in `pcap_dir` that tcpdump is not writing, sorted by name."""
    return sorted(p for p in glob.glob(os.path.join(pcap_dir, "*.pcap")) if os.path.realpath(p) not in live)
