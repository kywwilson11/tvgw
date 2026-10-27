"""The shell jobs as text: what tvgw-analyze promises, checked before it runs anywhere (shell syntax
and the contracts between deploy files are in test_deploy_lint.py)."""

from pathlib import Path

DEPLOY = Path(__file__).resolve().parents[2] / "deploy"
ANALYZE = (DEPLOY / "bin" / "tvgw-analyze").read_text()


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
