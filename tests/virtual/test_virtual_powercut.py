"""(reliability) Power cut under the store and the gateway's file writers, at the block device (design
decision 73).

A scratch ext4 filesystem on a loop device behind device-mapper. The cut is dm-flakey's `drop_writes`,
the way the kernel's own filesystem tests (xfstests' dmflakey) cut power: from the instant the table is
swapped every write the device receives is acknowledged and thrown away, the writer is killed, the
filesystem is unmounted (its last writes dropped too), and the plain table comes back and the filesystem is
mounted again, replaying its journal. What reached the device before the cut is all that is left: the
page cache, a commit the kernel had not yet written, a rename it had not yet journaled, are gone, as in a
cut. It models no lying card: a device that acknowledges a flush it did not do defeats every software
order, and no test here can see that.

Each writer is the code the gateway runs, in its own process, and acknowledges each write on a pipe
after the call returned; for the durability cases it then waits, so the cut lands between two writes:

- the store with `synchronous=EXTRA` keeps every acknowledged commit, whole;
- the store with FULL, the old setting, is the control: its last acknowledged commit comes back rolled
  back, because the unlink of its journal, which is the commit, was not yet on the device;
- the store cut while it runs free is never torn, and keeps what it acknowledged before the cut;
- the settings file, the machine's rules file and the live reading's give-up counts each come back as
  the acknowledged version, whole;
- a file renamed into place with no fsync, the machine's rules file's old order, is the second control:
  the cut loses the acknowledged version.

The gate's reboot list that research pass 5 names does not exist yet; when it is built it is written with
durable.replace, which the cases here cut under. The bench of tools/sync_bench.py also runs on the
device here, and its counts go to the artifacts.

Run as root on a Linux machine or VM with dmsetup, losetup, mkfs.ext4 and the dm_flakey module
(tests/virtual/README.md):

    sudo env PYTHONPATH=src python3 -m pytest -m virtual tests/virtual/test_virtual_powercut.py -q -p no:cacheprovider
"""

from __future__ import annotations

import hashlib
import json
import os
import random
import shutil
import sqlite3
import subprocess
import sys
from pathlib import Path

import pytest
import vnet

pytestmark = pytest.mark.virtual

SRC = vnet.ROOT / "src"
TOOLS = ("losetup", "dmsetup", "mkfs.ext4", "blockdev", "mount", "umount", "modprobe")
SIZE = 256 * 2**20
ROWS = 7
ROUNDS = random.Random(73).sample(range(2, 20), 3)  # acknowledged writes before each cut: fixed, repeatable

WRITER = r"""
import hashlib, os, sys
kind, path, mode, sync = sys.argv[1:5]
if kind == "store":
    from tvgw import db
    if sync:
        db.SYNCHRONOUS = sync
    conn = db.connect(path)
    conn.execute("CREATE TABLE IF NOT EXISTS t(n INTEGER, k INTEGER, v BLOB)")
    conn.commit()
for n in range(1, 1_000_000):
    if kind == "store":
        conn.execute("BEGIN")
        conn.executemany("INSERT INTO t VALUES (?, ?, ?)", [(n, k, b"v" * 400) for k in range(ROWS)])
        db.set_meta(conn, "n", str(n))
        conn.commit()
    elif kind == "settings":
        from tvgw import discover
        body = f"VERSION={n}\nPAD={'p' * (4096 + n % 997)}\n"
        discover.write_conf(path, body + f"CHECK={hashlib.sha256(body.encode()).hexdigest()}\n")
    elif kind == "rules":
        from tvgw import autoblock
        autoblock.add_rule(path, f"||n{n}.example^", f"rule {n}")
    elif kind == "progress":
        from tvgw import tvlive
        tvlive.write_progress(path, {"n": n, "pad": "p" * (2048 + n % 499)})
    elif kind == "no-fsync":  # the machine's rules file's order before this change
        with open(path + ".tmp", "w", encoding="utf-8") as fh:
            fh.write(f"version {n}\n" + "x" * 8192)
        os.replace(path + ".tmp", path)
    print(n, flush=True)
    if mode == "wait" and not sys.stdin.readline():
        break
""".replace("ROWS", str(ROWS))


def run(*argv: str, check: bool = True) -> subprocess.CompletedProcess:
    return vnet.run(list(argv), check=check, timeout=120)


class Disk:
    """A loop device behind a device-mapper target, ext4 on it, mounted under a scratch directory."""

    def __init__(self, root: Path):
        self.root, self.image, self.mnt = root, root / "disk.img", root / "mnt"
        self.name = f"tvgwv-flakey-{os.getpid()}"
        self.dev = f"/dev/mapper/{self.name}"
        self.loop = ""
        self.sectors = 0

    def table(self, drop: bool) -> str:
        if drop:  # up for 0 s, down for 180, writes dropped while down: from now on, every write is lost
            return f"0 {self.sectors} flakey {self.loop} 0 0 180 1 drop_writes"
        return f"0 {self.sectors} linear {self.loop} 0"

    def load(self, drop: bool) -> None:
        run("dmsetup", "suspend", "--nolockfs", self.name)
        run("dmsetup", "load", self.name, "--table", self.table(drop))
        run("dmsetup", "resume", self.name)

    def build(self) -> None:
        with open(self.image, "wb") as fh:
            fh.truncate(SIZE)
        self.loop = run("losetup", "--find", "--show", str(self.image)).stdout.strip()
        self.sectors = int(run("blockdev", "--getsz", self.loop).stdout.strip())
        run("dmsetup", "create", self.name, "--table", self.table(False))
        run("mkfs.ext4", "-q", "-F", self.dev)
        self.mnt.mkdir()
        run("mount", "-t", "ext4", self.dev, str(self.mnt))

    def cut(self, writer: subprocess.Popen | None = None) -> None:
        """The power goes: writes dropped, the writer killed, the filesystem gone; then it comes back."""
        self.load(drop=True)
        if writer is not None:
            writer.kill()
            writer.communicate(timeout=60)
        run("umount", str(self.mnt))
        self.load(drop=False)
        run("mount", "-t", "ext4", self.dev, str(self.mnt))

    def kernel_name(self) -> str:
        return os.path.basename(os.path.realpath(self.dev))  # dm-<n>, as /sys/block names it

    def destroy(self) -> None:
        run("umount", "-l", str(self.mnt), check=False)
        run("dmsetup", "remove", "--force", self.name, check=False)
        if self.loop:
            run("losetup", "-d", self.loop, check=False)


@pytest.fixture(scope="module")
def disk(tmp_path_factory):
    missing = [t for t in TOOLS if shutil.which(t) is None]
    if not missing and run("modprobe", "dm_flakey", check=False).returncode != 0:
        missing.append("the dm_flakey module")
    if not missing and "flakey" not in run("dmsetup", "targets").stdout:
        missing.append("device-mapper's flakey target")
    if missing:
        reason = "the power-cut test needs " + ", ".join(missing)
        if os.environ.get("TVGW_VIRTUAL_REQUIRED") == "1":
            pytest.fail(f"TVGW_VIRTUAL_REQUIRED=1 but {reason}")
        pytest.skip(reason)
    d = Disk(tmp_path_factory.mktemp("powercut"))
    try:
        d.build()
        yield d
    finally:
        d.destroy()


def start(kind: str, path: Path, mode: str, sync: str = "") -> subprocess.Popen:
    env = {**os.environ, "PYTHONPATH": str(SRC), "PYTHONDONTWRITEBYTECODE": "1"}
    return subprocess.Popen(
        [sys.executable, "-c", WRITER, kind, str(path), mode, sync],
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        text=True,
        env=env,
    )


def ack_then_cut(disk: Disk, kind: str, path: Path, acks: int, sync: str = "") -> int:
    """`acks` writes acknowledged one by one, the writer waiting after the last; then the cut."""
    p = start(kind, path, "wait", sync)
    for n in range(1, acks + 1):
        assert int(p.stdout.readline()) == n, f"the {kind} writer stopped before write {n}"
        if n < acks:
            p.stdin.write("\n")
            p.stdin.flush()
    disk.cut(p)
    return acks


def store_state(path: Path) -> tuple[str, int, int, int]:
    conn = sqlite3.connect(path)  # a writer's connection: it rolls back the journal a cut left
    try:
        ok = conn.execute("PRAGMA integrity_check").fetchone()[0]
        n = int(conn.execute("SELECT value FROM meta WHERE key = 'n'").fetchone()[0])
        rows, top = conn.execute("SELECT COUNT(*), COALESCE(MAX(n), 0) FROM t").fetchone()
    finally:
        conn.close()
    return ok, n, rows, top


def note(artifacts: Path, line: dict) -> None:
    with open(artifacts / "powercut.jsonl", "a", encoding="utf-8") as fh:
        fh.write(json.dumps(line) + "\n")


@pytest.mark.parametrize("acks", ROUNDS)
def test_the_store_keeps_every_acknowledged_commit_through_a_cut(disk, artifacts, acks):
    path = disk.mnt / f"extra-{acks}.db"
    ack_then_cut(disk, "store", path, acks)
    ok, n, rows, top = store_state(path)
    note(artifacts, {"case": "store EXTRA", "acked": acks, "after": n})
    assert ok == "ok"
    assert n == acks and top == acks and rows == acks * ROWS


def test_with_full_the_last_acknowledged_commit_rolls_back(disk, artifacts):
    """The control, and the reason for EXTRA: FULL syncs the journal and the store, not the directory
    after the journal's unlink, so the cut brings the journal back and the next open rolls the
    acknowledged commit back. Atomic still, never torn; not durable."""
    lost = 0
    for acks in ROUNDS:
        path = disk.mnt / f"full-{acks}.db"
        ack_then_cut(disk, "store", path, acks, sync="FULL")
        ok, n, rows, top = store_state(path)
        note(artifacts, {"case": "store FULL", "acked": acks, "after": n})
        assert ok == "ok" and top == n and rows == n * ROWS
        lost += n < acks
    assert lost >= 1, "FULL kept every acknowledged commit: this cut no longer reaches what EXTRA closes"


@pytest.mark.parametrize("acks", ROUNDS)
def test_a_store_cut_while_it_writes_is_never_torn(disk, artifacts, acks):
    path = disk.mnt / f"free-{acks}.db"
    p = start("store", path, "run")
    last = 0
    while last < acks:
        last = int(p.stdout.readline())
    disk.cut(p)
    ok, n, rows, top = store_state(path)
    note(artifacts, {"case": "store EXTRA, cut mid-write", "acked_before_cut": last, "after": n})
    assert ok == "ok" and top == n and rows == n * ROWS
    assert n >= last


def settings_version(path: Path) -> int:
    from tvgw import config

    text = path.read_text(encoding="utf-8")
    body = text[: text.index("CHECK=")]
    conf = config.parse_conf(text)
    assert conf["CHECK"] == hashlib.sha256(body.encode()).hexdigest(), "a torn settings file"
    return int(conf["VERSION"])


@pytest.mark.parametrize("acks", ROUNDS)
def test_the_settings_file_comes_back_as_the_acknowledged_version(disk, artifacts, acks):
    path = disk.mnt / f"tvgw-{acks}.conf"
    ack_then_cut(disk, "settings", path, acks)
    n = settings_version(path)
    note(artifacts, {"case": "settings", "acked": acks, "after": n})
    assert n == acks


@pytest.mark.parametrize("acks", ROUNDS)
def test_the_machines_rules_file_comes_back_with_every_acknowledged_rule(disk, artifacts, acks):
    from tvgw import autoblock

    path = disk.mnt / f"auto-{acks}.rules"
    ack_then_cut(disk, "rules", path, acks)
    lines = path.read_text(encoding="utf-8").splitlines()
    rules = [ln for ln in lines[1:] if not ln.startswith("! ")]
    note(artifacts, {"case": "auto.rules", "acked": acks, "after": len(rules)})
    assert lines[0] == autoblock.HEADER
    assert rules == [f"||n{k}.example^" for k in range(1, acks + 1)]


@pytest.mark.parametrize("acks", ROUNDS)
def test_the_live_readings_give_up_counts_come_back(disk, artifacts, acks):
    from tvgw import tvlive

    path = disk.mnt / f"progress-{acks}"
    ack_then_cut(disk, "progress", path, acks)
    data = tvlive.read_progress(str(path))
    note(artifacts, {"case": "tvlive progress", "acked": acks, "after": data.get("n")})
    assert data.get("n") == acks


def test_a_rename_without_an_fsync_loses_the_acknowledged_version(disk, artifacts):
    """The second control: the order autoblock wrote its rules file in before this change. The rename is
    not yet journaled when the power goes, so the file comes back older, or not at all."""
    lost = 0
    for acks in ROUNDS:
        path = disk.mnt / f"nofsync-{acks}.rules"
        ack_then_cut(disk, "no-fsync", path, acks)
        text = path.read_text(encoding="utf-8") if path.exists() else ""
        note(artifacts, {"case": "rename without fsync", "acked": acks, "after": text[:12]})
        lost += not text.startswith(f"version {acks}\n")
    assert lost >= 1, "no acknowledged version was lost: this cut no longer reaches a missing fsync"


def test_the_bench_counts_what_each_mode_costs_the_device(disk, artifacts):
    """tools/sync_bench.py on the device: the flushes and sectors per commit of each mode, to the
    artifacts. EXTRA costs at least what FULL does; the counts are the virtual disk's, not the card's."""
    sys.path.insert(0, str(vnet.ROOT / "tools"))
    import sync_bench

    rows = sync_bench.run(str(disk.mnt), 100, device=disk.kernel_name(), out=sys.stderr)
    (artifacts / "sync-bench.json").write_text(json.dumps(rows, indent=1), encoding="utf-8")
    by = {r["mode"]: r for r in rows}
    if "flushes_per_commit" in by["DELETE/FULL"] and by["DELETE/FULL"]["flushes_per_commit"] > 0:
        assert by["DELETE/EXTRA"]["flushes_per_commit"] >= by["DELETE/FULL"]["flushes_per_commit"]
