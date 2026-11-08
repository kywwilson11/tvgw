"""(reliability) Writers killed at a random instant: the store, the settings file, the machine's rules file
and the live reading's give-up counts, each by the code the gateway runs, in a process killed with SIGKILL
while it writes (design decision 73).

What this proves and what it does not. A killed process loses nothing it handed the kernel, so every
commit and every replace it acknowledged must be there afterwards, whole: a torn row, a short file or a
missing acknowledged write is a bug in the writer's order or its transactions. It is not a power cut: the
kernel's page cache survives a SIGKILL, and a cut throws it away. tests/virtual/test_virtual_powercut.py
cuts the power at the block device, as root on CI's runners. The in-place writer below is the control:
the same kill tears it, so a pass here is not the harness failing to look."""

import hashlib
import os
import random
import signal
import sqlite3
import subprocess
import sys
from pathlib import Path

import pytest

import tvgw
from tvgw import autoblock, config, db

SRC = str(Path(tvgw.__file__).resolve().parents[1])
ROWS = 7  # rows per store transaction, so a torn transaction shows as a count that is not a multiple

WRITER = r"""
import hashlib, json, os, sys, time
kind, path = sys.argv[1], sys.argv[2]
if kind == "store":
    from tvgw import db
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
    elif kind == "in-place":
        with open(path, "w", encoding="utf-8") as fh:
            for k in range(64):
                fh.write("x" * 1024)
                fh.flush()
                if k == 0:
                    print(f"start {n}", flush=True)  # truncated, and one chunk written
                time.sleep(0.005)
    print(n, flush=True)
""".replace("ROWS", str(ROWS))


def kill_while_writing(kind: str, path: Path, acks: int) -> int:
    """Start the writer, let it acknowledge `acks` writes, SIGKILL it at once, and return the last write it
    acknowledged, counting the acknowledgements still in the pipe."""
    env = {**os.environ, "PYTHONPATH": SRC, "PYTHONDONTWRITEBYTECODE": "1"}
    p = subprocess.Popen(
        [sys.executable, "-c", WRITER, kind, str(path)], stdout=subprocess.PIPE, text=True, env=env
    )
    last = 0
    try:
        while last < acks:
            line = p.stdout.readline()
            assert line, f"the {kind} writer stopped before its {acks}th write"
            if line.startswith("start "):
                if kind == "in-place" and int(line.split()[1]) == acks:
                    break  # the control: killed inside a write
                continue
            last = int(line)
    finally:
        p.send_signal(signal.SIGKILL)
        rest, _ = p.communicate(timeout=30)
    for line in rest.splitlines():
        if line.strip().isdigit():
            last = max(last, int(line))
    return last


ROUNDS = random.Random(73).sample(range(2, 26), 3)  # fixed, so a failure repeats


@pytest.mark.parametrize("acks", ROUNDS)
def test_a_killed_store_writer_leaves_every_acknowledged_commit_whole(tmp_path, acks):
    path = tmp_path / "tvgw.db"
    last = kill_while_writing("store", path, acks)
    conn = sqlite3.connect(path)  # a writer's connection: it rolls back a journal the kill left
    try:
        assert conn.execute("PRAGMA integrity_check").fetchone()[0] == "ok"
        n = int(db.get_meta(conn, "n"))
        rows, top = conn.execute("SELECT COUNT(*), MAX(n) FROM t").fetchone()
    finally:
        conn.close()
    assert last <= n <= last + 1  # acknowledged is there; at most one finished without its line
    assert top == n and rows == n * ROWS  # the rows and the meta row are one transaction, never torn
    assert db.connect(str(path)).execute("PRAGMA synchronous").fetchone()[0] == 3  # opens again, as EXTRA


def settings_version(path: Path) -> int:
    text = path.read_text(encoding="utf-8")
    conf = config.parse_conf(text)
    body = text[: text.index("CHECK=")]
    assert conf["CHECK"] == hashlib.sha256(body.encode()).hexdigest(), "a torn settings file"
    return int(conf["VERSION"])


@pytest.mark.parametrize("acks", ROUNDS)
def test_a_killed_settings_writer_leaves_one_whole_version(tmp_path, acks):
    path = tmp_path / "tvgw.conf"
    last = kill_while_writing("settings", path, acks)
    n = settings_version(path)
    assert last <= n <= last + 1
    # a temporary file the kill left beside it never stands in for the file, and the next write works
    from tvgw import discover

    discover.write_conf(str(path), "VERSION=0\nCHECK=x\n")
    assert config.parse_conf(path.read_text(encoding="utf-8"))["VERSION"] == "0"


@pytest.mark.parametrize("acks", ROUNDS)
def test_a_killed_rules_writer_leaves_every_acknowledged_rule(tmp_path, acks):
    path = tmp_path / "auto.rules"
    last = kill_while_writing("rules", path, acks)
    lines = path.read_text(encoding="utf-8").splitlines()
    assert lines[0] == autoblock.HEADER
    rules = [ln for ln in lines[1:] if not ln.startswith("! ")]
    assert last <= len(rules) <= last + 1
    assert rules == [f"||n{k}.example^" for k in range(1, len(rules) + 1)]  # in order, none cut short


@pytest.mark.parametrize("acks", ROUNDS)
def test_a_killed_live_reading_keeps_its_give_up_counts(tmp_path, acks):
    from tvgw import tvlive

    path = tmp_path / "tvlive-progress"
    last = kill_while_writing("progress", path, acks)
    data = tvlive.read_progress(str(path))
    assert data, "the counts came back empty: a torn file reads as no counts, and buys the TV fresh knocks"
    assert last <= data["n"] <= last + 1


def test_the_same_kill_tears_a_file_written_in_place(tmp_path):
    """The control: a writer that truncates and writes in place, killed inside a write, leaves a short
    file. The durable writers above take the same kill and never do."""
    path = tmp_path / "in-place"
    kill_while_writing("in-place", path, 3)
    assert 1024 <= path.stat().st_size < 64 * 1024
