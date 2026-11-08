"""(reliability) tools/sync_bench.py, the measure behind the store's synchronous=EXTRA (design decision 73):
every mode runs, its scratch stores go, the device counters are read from the kernel's own file, and a
bad count is a usage error. The numbers are the gateway's to give; here only the shape is held."""

import io
import os

import pytest
from conftest import load_tool

bench = load_tool("sync_bench")

# /sys/block/<dev>/stat on Linux 5.5 and later: 17 fields; sectors written is the 7th, flushes the 15th
STAT = "  1000  20  8000  300  500  40  {written}  900  0  1200  1500  0  0  0  {flushes}  77  0\n"


def test_every_mode_is_measured_in_a_scratch_directory_that_goes(tmp_path):
    out = io.StringIO()
    rows = bench.run(str(tmp_path), 5, out=out)
    assert [r["mode"] for r in rows] == ["DELETE/NORMAL", "DELETE/FULL", "DELETE/EXTRA", "WAL/NORMAL"]
    assert all(r["commits"] == 5 and r["median_ms"] >= 0 and r["p95_ms"] >= 0 for r in rows)
    assert os.listdir(tmp_path) == []  # the scratch stores are removed
    text = out.getvalue()
    assert text.startswith(f"5 commits per mode in {tmp_path}; SQLite ") and "DELETE/EXTRA" in text
    assert "sectors/commit" not in text  # no device named, no device columns


def test_the_device_counters_come_from_the_kernels_file_per_commit(tmp_path):
    texts = iter([STAT.format(written=100, flushes=10), STAT.format(written=160, flushes=14)] * 4)
    paths = []

    def read(path):
        paths.append(path)
        return next(texts)

    out = io.StringIO()
    rows = bench.run(str(tmp_path), 4, device="mmcblk0", out=out, read=read)
    assert set(paths) == {"/sys/block/mmcblk0/stat"} and len(paths) == 8  # before and after each mode
    assert all(r["sectors_per_commit"] == 15.0 and r["flushes_per_commit"] == 1.0 for r in rows)
    assert "sectors/commit" in out.getvalue()


def test_a_counter_file_that_is_missing_or_old_gives_none():
    def missing(path):
        raise FileNotFoundError(path)

    assert bench.device_counters("sda", read=missing) is None
    assert bench.device_counters("sda", read=lambda p: "1 2 3 4 5 6 7 8 9 10 11\n") is None  # before 5.5
    assert bench.device_counters("sda", read=lambda p: STAT.format(written=8, flushes=3)) == (8, 3)


def test_a_count_under_one_is_a_usage_error(tmp_path):
    with pytest.raises(SystemExit) as e:
        bench.main(["--dir", str(tmp_path), "--commits", "0"])
    assert e.value.code == 2
