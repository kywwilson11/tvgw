"""The systemd units as text: what systemd makes of an Exec line before any process runs."""

import pytest
from conftest import UNITS, capture_argv, exec_lines

SERVICES = sorted(p.name for p in UNITS.glob("*.service"))


def test_pcaps_are_named_in_utc_with_seconds():
    """Local-time names repeat in the DST fall-back hour (both 01:37 files of 2026-11-01 would be
    tv-20261101-0137.pcap) and tcpdump truncates a file whose name it has used before."""
    argv = capture_argv()
    assert argv[argv.index("-w") + 1].endswith("tv-%Y%m%dT%H%M%SZ.pcap")
    assert "Environment=TZ=UTC" in (UNITS / "tvgw-pcap.service").read_text().splitlines()


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
