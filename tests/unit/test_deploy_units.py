"""The systemd units as text: what systemd makes of an Exec line before any process runs."""

import os
import time
from datetime import datetime

import pytest
from conftest import UNITS, capture_argv, exec_lines

SERVICES = sorted(p.name for p in UNITS.glob("*.service"))


def ring_name(template: str, opened: float, number: int, nametimenum: bool) -> str:
    """The name dumpcap gives a ring file (ringbuffer.c, Wireshark 4.0 to 4.6): the -w name split at
    its last dot, the local time the file was opened as %Y%m%d%H%M%S, and the file's number as %05u,
    the time first with -b nametimenum:2."""
    prefix, dot, suffix = os.path.basename(template).rpartition(".")
    stamp, num = time.strftime("%Y%m%d%H%M%S", time.localtime(opened)), f"{number:05d}"
    middle = f"{stamp}_{num}" if nametimenum else f"{num}_{stamp}"
    return f"{prefix}_{middle}{dot}{suffix}"


def ring_options(argv: list[str]) -> dict[str, str]:
    """dumpcap's -b key:value options, by key."""
    return dict(argv[i + 1].split(":", 1) for i, a in enumerate(argv) if a == "-b")


@pytest.mark.parametrize(
    ("unit", "prefix"), [("tvgw-pcap.service", "tv"), ("tvgw-pcap-headers.service", "tvhdr")]
)
def test_pcaps_are_named_in_utc_with_the_time_first(unit, prefix):
    """dumpcap names ring files <prefix>_<local time>_<number>.pcap and truncates a file whose name it
    has used before; TZ=UTC keeps the stamp unambiguous, and the time first keeps names in time order
    across restarts. `.pcap` and -P keep the ingest's glob and tshark's input what tcpdump wrote."""
    argv = capture_argv(unit)
    assert argv[0] == "/usr/bin/dumpcap"
    assert argv[argv.index("-w") + 1] == f"/var/lib/tvgw/pcap/{prefix}.pcap"
    assert ring_options(argv) == {"interval": "3600", "nametimenum": "2"}  # no files: no self-deletion
    assert "-P" in argv and "-n" not in argv  # pcap, not pcapng (dumpcap's -n means pcapng)
    assert "Environment=TZ=UTC" in (UNITS / unit).read_text().splitlines()


def test_utc_names_sort_in_time_order_through_the_fall_back_hour_and_a_restart(monkeypatch):
    """Why TZ=UTC and nametimenum:2: in local time the two 01:20 files of 2026-11-01 (CDT, then CST an
    hour later) carry the same stamp, and with the number first a restart (which numbers from 00001
    again) sorts the new files before the old ones. In UTC with the time first, names sort as they
    were written, which is the order the ingest reads them in."""
    template = capture_argv()[capture_argv().index("-w") + 1]
    first = datetime.fromisoformat("2026-11-01T01:20:00-05:00").timestamp()
    local = [ring_name(template, t, n, True) for t, n in ((first, 1), (first + 3600, 2))]
    assert local[0][:17] == local[1][:17] == "tv_20261101012000"
    monkeypatch.setenv("TZ", "UTC")  # the unit's Environment=TZ=UTC; the autouse fixture restores it
    time.tzset()
    written = [(first, 7), (first + 3600, 8), (first + 3700, 1)]  # the third after a restart
    utc = [ring_name(template, t, n, True) for t, n in written]
    assert (
        utc
        == sorted(utc)
        == [
            "tv_20261101062000_00007.pcap",
            "tv_20261101072000_00008.pcap",
            "tv_20261101072140_00001.pcap",
        ]
    )
    assert sorted(ring_name(template, t, n, False) for t, n in written)[0].startswith("tv_00001_")


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
