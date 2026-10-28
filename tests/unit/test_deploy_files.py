"""The shell jobs as text: what tvgw-analyze promises, checked before it runs anywhere (shell syntax
and the contracts between deploy files are in test_deploy_lint.py)."""

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
