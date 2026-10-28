"""The deploy tree as a system: contracts between files that only the live gateway used to check.

Nothing under deploy/ runs in CI, so the first run of a changed heredoc, unit or workflow was on
the production gateway. These read the files as text: shell syntax, the rule text three consumers
match on (`queries.FW_LINES` has its own test in test_fw_lines.py), the start timeout every oneshot
needs, the workflow's shape, the one rsync list, and the defaults `tvgw-apply` and `config.Settings`
must share."""

import ast
import re
import shutil
import subprocess
from pathlib import Path

import pytest
import yaml
from conftest import ROOT, UNITS

from tvgw import config, verify

APPLY = (ROOT / "deploy" / "nftables" / "tvgw-apply").read_text()
SCRIPTS = (
    "deploy/install.sh",
    "deploy/nftables/tvgw-apply",
    "deploy/bin/tvgw-analyze",
    "deploy/bin/tvgw-doh-update",
    "deploy/networkmanager/90-tvgw-dispatcher",
)
ONESHOT = sorted(p.name for p in UNITS.glob("*.service") if "Type=oneshot" in p.read_text().splitlines())


def hardware_literal(name: str):
    """A module-level literal of tests/hardware/test_gateway.py, which cannot be imported here: it
    skips itself off the gateway."""
    tree = ast.parse((ROOT / "tests" / "hardware" / "test_gateway.py").read_text())
    for node in tree.body:
        if isinstance(node, ast.Assign) and any(
            isinstance(t, ast.Name) and t.id == name for t in node.targets
        ):
            return ast.literal_eval(node.value)
    raise AssertionError(f"{name} is not a module-level literal of the hardware suite")


@pytest.mark.parametrize("script", SCRIPTS)
def test_shell_syntax(script):
    """`-n` with the shell the shebang names; on ubuntu-latest `sh` is dash, which parses the
    dispatcher as the POSIX script it must be."""
    path = ROOT / script
    shell = Path(path.read_text().splitlines()[0].removeprefix("#!").split()[0]).name
    exe = shutil.which(shell)
    if exe is None:
        pytest.skip(f"{shell} is not installed here")
    out = subprocess.run([exe, "-n", str(path)], capture_output=True, text=True)
    assert out.returncode == 0, out.stderr


def test_the_key_rules_verify_looks_for_are_in_the_script():
    """verify.KEY_RULES are substrings of the live listing; the script spells the gateway address
    $TV_ADDR. A reworded rule fails here, not on the gateway ten minutes after the deploy."""
    for needle in (*verify.KEY_RULES, *verify.QUIC_RULE):
        assert needle.replace("GW_IP", "$TV_ADDR") in APPLY, needle


def test_the_ipv6_guard_verify_looks_for_is_the_scripts_wire_drop():
    assert f'ether type ip6 counter drop comment "{verify.IPV6_GUARD}"' in APPLY


def test_the_key_rules_the_hardware_suite_looks_for_are_in_the_script():
    for needle in hardware_literal("KEY_RULES"):
        assert needle.replace("10.10.10.1", "$TV_ADDR") in APPLY, needle


def test_the_hardware_suite_compares_files_that_exist():
    """A renamed deploy file would otherwise fail its byte comparison only after the deploy."""
    for source, installed in hardware_literal("INSTALLED").items():
        assert (ROOT / source).is_file(), source
        assert installed.startswith("/"), installed
    for template in ("dnsmasq/tvgw.conf.template", "nginx/tvgw-gfts.conf", "nginx/stream.conf"):
        assert (ROOT / "deploy" / template).is_file(), template


@pytest.mark.parametrize("unit", ONESHOT)
def test_every_oneshot_unit_has_a_start_timeout(unit):
    """A oneshot has no start timeout by default: a hung tvgw-apply at boot would hold
    multi-user.target and dnsmasq for ever, and a hung verify would end the 10-minute snapshots."""
    assert any(line.startswith("TimeoutStartSec=") for line in (UNITS / unit).read_text().splitlines()), unit


def test_the_oneshot_list_is_what_the_tree_holds():
    assert ONESHOT == [
        "tvgw-analyst-weekly.service",
        "tvgw-analyst.service",
        "tvgw-analyze.service",
        "tvgw-autoblock.service",
        "tvgw-backup.service",
        "tvgw-doh-update.service",
        "tvgw-prune.service",
        "tvgw-verify.service",
        "tvgw.service",
    ]


def test_ci_never_cancels_or_cuts_off_a_deploy_and_skips_docs_only_pushes():
    """install.sh is a linear `set -e` script with no rollback, run on the production gateway by the
    hardware job: nothing may cancel it mid-way, and a Markdown-only push must not run it."""
    wf = yaml.safe_load((ROOT / ".github" / "workflows" / "ci.yml").read_text())
    jobs = wf["jobs"]
    assert "concurrency" not in wf  # a workflow-level cancel reaches every job, the deploy included
    unit = jobs["test"]["concurrency"]
    assert unit["cancel-in-progress"] is True and "matrix.python" in unit["group"]
    assert jobs["hardware"]["concurrency"] == {"group": "deploy-tvgw", "cancel-in-progress": False}
    assert jobs["hardware"]["timeout-minutes"] >= 90  # a first analyze run (45 min) plus two ingests
    assert "**/*.md" in wf[True]["push"]["paths-ignore"]  # PyYAML reads the `on` key as the boolean True
    runs = [step.get("run", "") for job in jobs.values() for step in job["steps"]]
    assert not any("sudo -E" in run for run in runs), "the runner's whole environment handed to root"


def test_both_deploy_paths_use_the_one_rsync_exclude_list():
    needle = "--exclude-from=deploy/rsync.exclude"
    assert needle in (ROOT / "Makefile").read_text()
    assert needle in (ROOT / ".github" / "workflows" / "ci.yml").read_text()
    assert {".git", "*.db"} <= set((ROOT / "deploy" / "rsync.exclude").read_text().split())


def test_apply_defaults_and_choices_are_those_of_settings():
    """tvgw-apply defaults a missing switch (`${KEY:=value}`) and checks it with an exact `case`;
    config.load must accept exactly the same values, or apply and verify disagree about the gateway."""
    defaults = dict(re.findall(r"\$\{([A-Z_]+):=([^}]*)\}", APPLY))
    assert {"UPLINK", "WAN_IF", "BLOCK_QUIC", "STRICT_PORTS"} <= set(defaults)
    s = config.Settings()
    for key, value in defaults.items():
        if key in config.CONF_KEYS:
            assert value == str(getattr(s, config.CONF_KEYS[key])), key
    arms = re.findall(r"^\s*([a-z]+(?: \| [a-z]+)*)\)", APPLY, re.M)  # "yes | no", "direct", "vpn"
    named = {value for arm in arms for value in arm.split(" | ")}
    for key, allowed in config.CHOICES.items():
        assert set(allowed) <= named, f"{key}: {allowed} vs the script's case arms {sorted(named)}"


def test_every_action_is_pinned_by_commit_with_its_version_named():
    import re
    from pathlib import Path

    text = (Path(__file__).resolve().parents[2] / ".github" / "workflows" / "ci.yml").read_text()
    uses = [line.strip() for line in text.splitlines() if "uses:" in line]
    assert uses, "no actions in the workflow?"
    for line in uses:
        assert re.fullmatch(r"- uses: [\w.-]+/[\w.-]+@[0-9a-f]{40} # v\d+\.\d+\.\d+", line), line
    assert (Path(__file__).resolve().parents[2] / ".github" / "dependabot.yml").exists()
