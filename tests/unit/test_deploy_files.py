"""The shell jobs as text: what tvgw-analyze and install.sh promise, checked before they run anywhere."""

import shutil
import subprocess
from pathlib import Path

import pytest

DEPLOY = Path(__file__).resolve().parents[2] / "deploy"
ANALYZE = (DEPLOY / "bin" / "tvgw-analyze").read_text()
INSTALL = (DEPLOY / "install.sh").read_text()


@pytest.mark.parametrize(
    "script", ["bin/tvgw-analyze", "bin/tvgw-doh-update", "install.sh", "nftables/tvgw-apply"]
)
def test_bash_scripts_parse(script):
    bash = shutil.which("bash")
    if bash is None:
        pytest.skip("bash is not installed here")
    out = subprocess.run([bash, "-n", str(DEPLOY / script)], capture_output=True, text=True)
    assert out.returncode == 0, out.stderr


def test_tv_power_history_lines_are_tab_separated_and_name_both_absent_states():
    """webOS power states contain spaces ('Active Standby', 'Screen Off'), so the fields are tabs. No
    power line means unreachable when the TV did not answer (tvcheck exit 1) and unknown when it
    answered but the power read failed."""
    assert (
        'printf \'%s\\t%s\\t%s\\n\' "$(date -Is)" "$power" "$app" >>"$STATE/tvcheck-history.log"' in ANALYZE
    )
    assert '[ -n "$power" ] || { power=unknown; [ "$rc" -ne 1 ] || power=unreachable; }' in ANALYZE
    assert 'echo "$(date -Is)' not in ANALYZE
