"""The shell jobs as text: what tvgw-analyze promises, checked before it runs anywhere (shell syntax
and the contracts between deploy files are in test_deploy_lint.py)."""

import os
import shutil
import subprocess

import pytest
from conftest import ROOT

DEPLOY = ROOT / "deploy"
ANALYZE = (DEPLOY / "bin" / "tvgw-analyze").read_text()
INSTALL = (DEPLOY / "install.sh").read_text()


def test_finished_days_and_weeks_are_written_once_their_evidence_has_settled():
    """A finished day is written once, so the run waits SETTLE seconds after it ends for the last idle
    connections (reported 2 h 04 min after their last packet) and the last pcap to be ingested."""
    assert "SETTLE=10800" in ANALYZE.splitlines()
    assert "settled=$(($(date +%s) - SETTLE))" in ANALYZE
    assert ANALYZE.count('[ "$end" -le "$settled" ]') == 2  # the daily loop and the weekly condition
    assert "hour=" not in ANALYZE  # the clock-face rule it replaces


def test_tv_power_history_lines_are_tab_separated_and_name_both_absent_states():
    """webOS power states contain spaces ('Active Standby', 'Screen Off'), so the fields are tabs. No
    power line means unreachable when the TV did not answer (tvcheck exit 1) and unknown when it
    answered but the power read failed."""
    assert (
        'printf \'%s\\t%s\\t%s\\n\' "$(date -Is)" "$power" "$app" >>"$STATE/tvcheck-history.log"' in ANALYZE
    )
    assert '[ -n "$power" ] || { power=unknown; [ "$rc" -ne 1 ] || power=unreachable; }' in ANALYZE
    assert 'echo "$(date -Is)' not in ANALYZE


def test_install_takes_only_the_first_backup(tmp_path):
    """The timer makes the daily copies; a copy on every deploy rotated the daily restore points out
    within one morning of deploys, and hid a dead timer from the hardware suite's freshness check. The
    line runs here with a fake systemctl and the state directory moved under tmp_path."""
    bash = shutil.which("bash")
    if bash is None:
        pytest.skip("bash is not installed here")
    (line,) = [x for x in INSTALL.splitlines() if "start tvgw-backup.service" in x]
    (tmp_path / "bin").mkdir()
    fake = tmp_path / "bin" / "systemctl"
    fake.write_text(f'#!/bin/sh\necho "$*" >>{tmp_path}/calls\n')
    fake.chmod(0o755)
    env = {"PATH": f"{tmp_path / 'bin'}:/usr/bin:/bin"}
    script = line.replace("/var/lib/tvgw", str(tmp_path))
    (tmp_path / "backup").mkdir()
    for _ in range(2):
        subprocess.run([bash, "-euo", "pipefail", "-c", script], env=env, check=True)
        (tmp_path / "backup" / "tvgw-20261028T084004Z.db").write_bytes(b"")
    assert (tmp_path / "calls").read_text() == "start tvgw-backup.service\n"


LONG_RUNNING = ("tvgw-pcap", "tvgw-flowlog", "tvgw-dnsgate")


def restart_changed(tmp_path, tv_ip="10.10.10.17", fail=""):
    """Run install.sh's restart_changed for the three long-running units against copies of their unit
    files, a settings file and a package tree under tmp_path, with a fake systemctl (which fails to
    restart `fail`); returns the units it restarted."""
    bash = shutil.which("bash")
    if bash is None or shutil.which("sha256sum") is None:
        pytest.skip("bash and sha256sum are needed here")
    start = INSTALL.index("\nSTAMPS=")
    block = INSTALL[start : INSTALL.index("\n}\n", INSTALL.index("restart_changed() {", start)) + 3]
    units = tmp_path / "deploy" / "systemd"
    if not units.exists():
        units.mkdir(parents=True)
        for u in LONG_RUNNING:
            (units / f"{u}.service").write_text((DEPLOY / "systemd" / f"{u}.service").read_text())
        (tmp_path / "src" / "tvgw").mkdir(parents=True)
        (tmp_path / "src" / "tvgw" / "dnsgate.py").write_text("feed = 1\n")
        (tmp_path / "etc").mkdir()
        (tmp_path / "etc" / "tvgw.conf").write_text(f"TV_IP={tv_ip}\n")
        (tmp_path / "bin").mkdir()
    fake = tmp_path / "bin" / "systemctl"
    fake.write_text(f'#!/bin/sh\necho "$2" >>{tmp_path}/calls\n[ "$2" != "{fail}.service" ]\n')
    fake.chmod(0o755)
    calls = tmp_path / "calls"
    calls.write_text("")
    script = "\n".join(
        (
            f"REPO={tmp_path}",
            f"TV_IP={tv_ip}",
            block.replace("/var/lib/tvgw", str(tmp_path / "state")).replace(
                "/etc/tvgw", str(tmp_path / "etc")
            ),
            "restart_changed " + " ".join(LONG_RUNNING),
        )
    )
    env = {**os.environ, "PATH": f"{tmp_path / 'bin'}:{os.environ['PATH']}"}
    out = subprocess.run([bash, "-euo", "pipefail", "-c", script], cwd=tmp_path / "deploy", env=env)
    assert (out.returncode == 0) == (not fail), out
    return [line.removesuffix(".service") for line in calls.read_text().split()]


def test_a_long_running_unit_restarts_when_what_it_read_at_start_changed(tmp_path):
    """Restarting only on a changed unit file left the flow log filtering on the old TV_IP and the
    DNS-gate feeder waiting for answers to the old address, running the code it loaded at start, until
    a reboot. The record of what each one started with is written only after its restart."""
    assert restart_changed(tmp_path) == list(LONG_RUNNING)  # no record yet: what they run is unknown
    assert restart_changed(tmp_path) == []
    (tmp_path / "etc" / "tvgw.conf").write_text("TV_IP=10.10.10.18\n")
    assert restart_changed(tmp_path, tv_ip="10.10.10.18") == ["tvgw-flowlog", "tvgw-dnsgate"]
    (tmp_path / "src" / "tvgw" / "dnsgate.py").write_text("feed = 2\n")
    assert restart_changed(tmp_path, tv_ip="10.10.10.18") == ["tvgw-dnsgate"]
    with (tmp_path / "deploy" / "systemd" / "tvgw-pcap.service").open("a") as fh:
        fh.write("# a changed filter\n")
    assert restart_changed(tmp_path, tv_ip="10.10.10.18") == ["tvgw-pcap"]
    assert restart_changed(tmp_path, tv_ip="10.10.10.18") == []


def test_a_restart_an_install_did_not_reach_is_made_by_the_next_one(tmp_path):
    """The restart list used to come from comparing the shipped units with the installed copies just
    before the copy, and was acted on at the end: an install that stopped in between (a failed
    `tvgw adguard apply`, a schedule systemd rejects, `nginx -t`) left the new file installed and the old
    process running, and the next install found equal files and restarted nothing until a reboot."""
    assert restart_changed(tmp_path) == list(LONG_RUNNING)
    with (tmp_path / "deploy" / "systemd" / "tvgw-pcap.service").open("a") as fh:
        fh.write("# a changed filter\n")
    assert restart_changed(tmp_path, fail="tvgw-pcap") == ["tvgw-pcap"]  # the restart fails: install stops
    assert restart_changed(tmp_path) == ["tvgw-pcap"]  # the next install makes it
    assert restart_changed(tmp_path) == []
