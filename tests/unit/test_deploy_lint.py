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
    "deploy/sync-install.sh",
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


def make_list(name: str) -> list[str]:
    """A Makefile variable's words, with its continued lines joined."""
    text = (ROOT / "Makefile").read_text().replace("\\\n", " ")
    (value,) = re.findall(rf"^{name} :?= (.*)$", text, re.M)
    return value.split()


def test_every_posix_script_is_shellchecked_by_the_gate():
    """`make gate` runs `shellcheck -s sh` over SH_PATHS when shellcheck is installed (it is on CI's
    runners). The maintainer scripts, the dispatcher and the installer run under dash on a gateway, where
    a bashism is a failure at install time, and so does the container tier's DHCP hook, inside the TV's
    namespace; a new one is listed or this fails."""
    listed = make_list("SH_PATHS")
    found = sorted(
        str(path.relative_to(ROOT))
        for top in ("deploy", "packaging", "tests/container")
        for path in (ROOT / top).rglob("*")
        if path.is_file() and path.read_bytes()[:10] == b"#!/bin/sh\n"
    )
    assert found and sorted(listed) == found
    assert "shellcheck -s sh -S warning $(SH_PATHS)" in (ROOT / "Makefile").read_text()


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
    for template in (
        "dnsmasq/tvgw.conf.template",
        "nginx/tvgw-gfts.conf",
        "nginx/stream.conf",
        "networkmanager/90-tvgw.conf",
    ):
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
        "tvgw-guard.service",  # (guard)
        "tvgw-prune.service",
        "tvgw-threat-update.service",  # (threats)
        "tvgw-update-boot.service",  # (updates)
        "tvgw-update.service",
        "tvgw-verify.service",
        "tvgw-vpnseal.service",  # (reliability)
        "tvgw.service",
    ]


def test_a_newer_push_replaces_only_the_older_run_of_the_same_job_and_pages_alone_run_none():
    """Each cell of the unit matrix is a group of its own: without the time zone in the group the two
    3.13 cells would cancel each other. The package build is one group per ref. A push of pages alone
    runs no unit tests, and no step hands the runner's environment to root. Nothing in CI deploys
    (design decision 83): test_supply_chain.py holds every job to GitHub's own runners."""
    wf = yaml.safe_load((ROOT / ".github" / "workflows" / "ci.yml").read_text())
    jobs = wf["jobs"]
    assert {name: job.get("concurrency") for name, job in jobs.items()} == {
        "test": {
            "group": "test-${{ github.ref }}-${{ matrix.python }}-${{ matrix.tz }}",
            "cancel-in-progress": True,
        },
        "deb-build": {"group": "deb-build-${{ github.ref }}", "cancel-in-progress": True},
        "mutation": None,
    }
    assert "**/*.md" in wf[True]["push"]["paths-ignore"]  # PyYAML reads the `on` key as the boolean True
    runs = [step.get("run", "") for job in jobs.values() for step in job["steps"]]
    assert not any("sudo -E" in run for run in runs), "the runner's whole environment handed to root"


def test_both_deploy_paths_use_the_one_rsync_exclude_list():
    assert "--exclude-from=deploy/rsync.exclude" in (ROOT / "Makefile").read_text()  # to the staging copy
    assert '--exclude-from="$SRC/deploy/rsync.exclude"' in (ROOT / "deploy" / "sync-install.sh").read_text()
    assert {".git", "*.db"} <= set((ROOT / "deploy" / "rsync.exclude").read_text().split())


def test_the_rsync_list_leaves_out_everything_git_ignores():
    """`make deploy` copies the working tree, so what git ignores is local: a virtualenv, pcaps and logs,
    the site settings in deploy/local/ (the TV's MAC and LAN addresses), .pi, the store copies in
    backups/. Left off this list, each went to /opt/tvgw/src with the workstation's modes."""
    rsync = {line.rstrip("/") for line in (ROOT / "deploy" / "rsync.exclude").read_text().split()}
    for line in (ROOT / ".gitignore").read_text().splitlines():
        if line.strip() and not line.startswith("#"):
            assert line.strip().rstrip("/") in rsync, line


def test_every_deploy_and_suite_run_holds_the_install_lock():
    """The lock lived inside install.sh, after the tree had already been rsynced into /opt/tvgw/src, and
    was released before a suite ran from that tree: two deploys could mix two trees, and one during the
    suite left a pass certifying a commit that was not what was tested. Only sync-install.sh writes
    /opt/tvgw/src, and it holds the lock through install.sh and whatever command follows it; `make
    hardware` takes the same lock. No workflow deploys (design decision 83), so the Makefile's two
    targets are every route."""
    make = (ROOT / "Makefile").read_text()
    assert "ssh $(PI) 'sudo tvgw-deploy/deploy/sync-install.sh'" in make
    assert "sudo flock -w 600 /run/tvgw/install.lock /opt/tvgw-venv/bin/python -m pytest -m hardware" in make
    assert "/opt/tvgw/src/\n" not in make and ":/opt/tvgw/src" not in make, "an rsync outside the lock"
    for path in sorted((ROOT / ".github" / "workflows").glob("*.y*ml")):
        text = path.read_text(encoding="utf-8")
        assert "/opt/tvgw/src" not in text and "tvgw-deploy" not in text, (
            f"{path.name} reaches a gateway's tree"
        )


def test_the_example_conf_reads_the_same_in_the_shell_and_in_python():
    """install.sh, tvgw-apply and tvgw-doh-update source the conf under `set -eu`. An unquoted
    `ANALYST_WEEKLY_SCHEDULE=Mon 04:10` ran `04:10` as a command, so a fresh install stopped at the
    line that reads the settings while config.load, which took the value whole, passed."""
    bash = shutil.which("bash")
    if bash is None:
        pytest.skip("bash is not installed here")
    example = ROOT / "deploy" / "tvgw.conf.example"
    conf = config.parse_conf(example.read_text())
    script = '. "$1"; shift; for k; do printf "%s=%s\\n" "$k" "${!k}"; done'
    out = subprocess.run([bash, "-euc", script, "_", str(example), *conf], capture_output=True, text=True)
    assert out.returncode == 0, out.stderr
    assert dict(line.split("=", 1) for line in out.stdout.splitlines()) == conf


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


DEFAULT = re.compile(r"\$\{([A-Z][A-Z0-9_]*):=([^}]*)\}")  # `${KEY:=value}`, the shell's default
# (reserved) the keys nothing reads yet, and the scripts that are to read them: each defaults them now,
# so the change that starts reading one adds no default line of its own
RESERVED_IN = {
    "deploy/install.sh": {
        "TV_DHCP",
        "TV_PORT_MANAGER",
        "NETWATCH",
    },
}


@pytest.mark.parametrize("script", SCRIPTS)
def test_every_script_defaults_a_setting_as_settings_does(script):
    """A script that defaults a key `config.Settings` reads must default it to the same value, or the
    shell and Python disagree about a file without it (install.sh's own defaults were checked only for
    the TV side)."""
    s = config.Settings()
    for key, value in DEFAULT.findall((ROOT / script).read_text()):
        if key in config.CONF_KEYS:
            assert value == str(getattr(s, config.CONF_KEYS[key])), f"{script}: {key}"


@pytest.mark.parametrize("script", sorted(RESERVED_IN))
def test_the_reserved_keys_are_defaulted_after_the_settings_are_read(script):
    """`${KEY:=value}` before the file is sourced would let an empty `KEY=` in it win; after, an absent
    or empty key reads as the default, which is today's behaviour. Each is a switch `config.load`
    holds to exact values, so the script that starts reading one can `case` on them."""
    text = (ROOT / script).read_text()
    sourced = text.index("\n. /etc/tvgw/tvgw.conf\n")
    found = {m.group(1): m.start() for m in DEFAULT.finditer(text) if m.group(1) in RESERVED_IN[script]}
    assert set(found) == RESERVED_IN[script]
    assert all(at > sourced for at in found.values()), found
    assert RESERVED_IN[script] <= set(config.MODES)


@pytest.mark.parametrize("script", sorted(RESERVED_IN))
def test_a_script_only_defaults_its_reserved_keys_so_nothing_changes(script):
    """Nothing reads them yet: each key appears once, in its default, so tvgw-apply cannot record it in
    settings.applied either, and verify does not compare it with the file (a key there would read as an
    unapplied change). The change that starts reading a key takes it out of RESERVED_IN."""
    text = (ROOT / script).read_text()
    for key in RESERVED_IN[script]:
        assert len(re.findall(rf"\$\{{?{key}\b", text)) == 1, f"{script} reads {key}"
        assert key not in verify.APPLY_KEYS, key


@pytest.mark.parametrize("script", sorted(RESERVED_IN))
def test_the_reserved_defaults_hold_under_set_u_for_a_file_that_leaves_them_empty(script, tmp_path):
    """The script's own default lines, run as it runs them (`set -eu`, the file sourced first): a file
    with each key empty, as `tvgw setup` may leave one, reads as one without them."""
    bash = shutil.which("bash")
    if bash is None:
        pytest.skip("bash is not installed here")
    keys = sorted(RESERVED_IN[script])
    lines = [
        line
        for line in (ROOT / script).read_text().splitlines()
        if line.startswith(": ") and any(f"${{{key}:=" in line for key in keys)
    ]
    conf = tmp_path / "tvgw.conf"
    conf.write_text("".join(f"{key}=\n" for key in keys))
    body = '. "$1"; shift\n' + "\n".join(lines) + '\nfor k; do printf "%s=%s\\n" "$k" "${!k}"; done'
    out = subprocess.run([bash, "-euc", body, "_", str(conf), *keys], capture_output=True, text=True)
    assert out.returncode == 0, out.stderr
    s = config.Settings()
    assert dict(line.split("=", 1) for line in out.stdout.splitlines()) == {
        key: str(getattr(s, config.CONF_KEYS[key])) for key in keys
    }


def test_every_action_is_pinned_by_commit_with_its_version_named():
    import re

    text = (ROOT / ".github" / "workflows" / "ci.yml").read_text()
    uses = [line.strip() for line in text.splitlines() if "uses:" in line]
    assert uses, "no actions in the workflow?"
    for line in uses:
        assert re.fullmatch(r"- uses: [\w.-]+/[\w.-]+@[0-9a-f]{40} # v\d+\.\d+\.\d+", line), line
    assert (ROOT / ".github" / "dependabot.yml").exists()


def test_the_apply_never_churns_a_policy_route_that_is_already_right():
    """Deleting and re-adding rule 60, or replacing an unchanged table-100 route, destroyed the conntrack
    entry of a connection with data in flight at every DHCP renewal and DoH refresh (2026-10-30,
    reproduced with a client namespace). The script compares before it touches either."""
    text = (ROOT / "deploy" / "nftables" / "tvgw-apply").read_text()
    # every delete of the rule sits inside the mismatch branch of the comparison, never ahead of it
    assert (
        text.index("want_rule=") < text.index('case "$have_rule" in') < text.index("ip rule del priority 60")
    )
    assert 'want_rule="from $TV_NET lookup $RT_TABLE"' in text
    # (uplink) the router WAN_GW_MODE resolved (wan_router): WAN_GW itself unless the mode is auto
    assert 'want_route="default via $WAN_GW_USED dev $WAN_IF"' in text
    assert text.index("want_rule=") < text.index("ip rule add priority 60")
    routing = text[text.index("# Policy routing: in direct mode") :]
    assert routing.index("want_route=") < routing.index("ip route replace default")
    # (revert) a held apply writes no route of its own: it hands restore_state, which compares each route
    # before it writes one, last-good's table 100 with the router auto reads now (held_table100)
    held = text[text.index("held_table100() {") : text.index("\nHOLD=no ")]
    assert "ip route" not in held
    assert 'restore_state "$LAST_GOOD" "$LAST_GOOD/table100.now"' in held
    # the TV subnet in table 100 (design decision 49), compared the same way before it is written
    assert 'want_net="$TV_NET dev $TV_IF scope link src $GW_IP"' in text
    assert '"$want_net" | "$want_net "*) ;;' in text
    assert (
        text.index("want_net=")
        < text.index('case "$have_net" in')
        < text.index('ip route replace "$TV_NET" dev "$TV_IF" scope link src "$GW_IP" table "$RT_TABLE" ||')
    )
