"""The systemd units as text: what systemd makes of an Exec line before any process runs."""

import os
import time
from datetime import datetime

import pytest
from conftest import UNITS, capture_argv, exec_lines

SERVICES = sorted(p.name for p in UNITS.glob("*.service"))


def test_pcaps_are_named_in_utc_with_seconds():
    """Local-time names repeat in the DST fall-back hour (both 01:37 files of 2026-11-01 would be
    tv-20261101-0137.pcap) and tcpdump truncates a file whose name it has used before."""
    argv = capture_argv()
    assert argv[argv.index("-w") + 1].endswith("tv-%Y%m%dT%H%M%SZ.pcap")
    assert "Environment=TZ=UTC" in (UNITS / "tvgw-pcap.service").read_text().splitlines()


def test_the_fall_back_hour_would_repeat_a_local_time_name():
    """Why the unit sets TZ=UTC: tcpdump formats -w names with strftime in its local time and
    truncates a file whose name it has used before, so the second 01:20 of 2026-11-01 (CST, an hour
    after the first, CDT) would overwrite the first hour's capture. In UTC the names are unique and
    sort in time order."""
    argv = capture_argv()
    pattern = os.path.basename(argv[argv.index("-w") + 1])
    first = datetime.fromisoformat("2026-11-01T01:20:00-05:00").timestamp()
    local = [time.strftime(pattern, time.localtime(t)) for t in (first, first + 3600)]
    utc = [time.strftime(pattern, time.gmtime(t)) for t in (first, first + 3600)]
    assert local[0] == local[1] and utc == ["tv-20261101T062000Z.pcap", "tv-20261101T072000Z.pcap"]


def test_the_analyze_job_is_the_first_to_go_when_memory_runs_out():
    """It parses the backlog and runs tshark; the resolver must outlive it."""
    assert "OOMScoreAdjust=500" in (UNITS / "tvgw-analyze.service").read_text().splitlines()


@pytest.mark.parametrize("unit", SERVICES)
def test_exec_lines_escape_every_specifier_and_variable(unit):
    """A lone `%` is a systemd specifier and a lone `$` is expanded by systemd before the command runs,
    quotes or not: `%%` and `$$` are the escapes, and nothing else may remain."""
    for directive, value in exec_lines(unit):
        assert "%" not in value.replace("%%", ""), f"{unit} {directive}: stray % (strftime needs %%)"
        assert "$" not in value.replace("$$", ""), f"{unit} {directive}: stray $ (the shell needs $$)"


@pytest.mark.parametrize("unit", ["tvgw-pcap.service", "tvgw-flowlog.service", "tvgw-dnsgate.service"])
def test_capture_starts_whether_or_not_the_boot_apply_succeeded(unit):
    """Reproduced: with Requires=tvgw.service a failed boot apply failed these start jobs ("dependency
    failed"), Restart= never fires for a unit that never started, and the dispatcher's later apply that
    put the TV online left all three down for the whole boot. They still start after it."""
    lines = (UNITS / unit).read_text().splitlines()
    assert "After=tvgw.service" in lines and "Wants=tvgw.service" in lines
    assert not [line for line in lines if line.startswith(("Requires=", "BindsTo=", "Requisite="))]
