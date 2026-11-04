"""The shell jobs as text: what tvgw-analyze promises, checked before it runs anywhere (shell syntax
and the contracts between deploy files are in test_deploy_lint.py)."""

import os
import shutil
import subprocess
import sys

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


def tv_reading_block() -> str:
    """tvgw-analyze's TV reading, from its comment to its closing `fi`."""
    start = ANALYZE.index("# TV settings drift check")
    return ANALYZE[start : ANALYZE.index("\nfi\n", start) + 4]


@pytest.mark.parametrize(
    ("rc", "said", "kept", "line"),
    [
        (0, "option.livePlus = off\npower = Active\napp = netflix\n", True, "Active\tnetflix"),
        (3, "power = Screen Off\nWARNING: the TV has a second network path (Wi-Fi)\n", True, "Screen Off\t"),
        (1, "TV unreachable (OSError): off, or in standby with Quick Start+ off\n", False, "unreachable\t"),
        (4, "TV not paired: the gateway holds no key for it, so nothing was asked.\n", False, "unknown\t"),
    ],
)
def test_only_a_reading_replaces_tvcheck_txt_and_every_run_adds_one_history_line(
    tmp_path, rc, said, kept, line
):
    """(pairing) tvcheck exits 4 when the gateway is not paired with the TV, having asked it nothing.
    Like a TV that did not answer (1), that writes no tvcheck.txt, so the last reading stays; its power is
    `unknown`, since nobody asked, not `unreachable`. The block runs with a stub tvgw and a fixed date."""
    bash = shutil.which("bash")
    if bash is None:
        pytest.skip("bash is not installed here")
    stub = tmp_path / "bin"
    stub.mkdir()
    (tmp_path / "said").write_text(said)
    (stub / "tvgw").write_text(f'#!/bin/sh\n[ "$1" = tvcheck ] || exit 9\ncat {tmp_path}/said\nexit {rc}\n')
    (stub / "date").write_text("#!/bin/sh\necho 2026-11-03T10:20:00-06:00\n")  # date -Is is GNU's
    for f in stub.iterdir():
        f.chmod(0o755)
    (tmp_path / "tvcheck.txt").write_text("read 2026-11-02T22:20:00-06:00\noption.livePlus = off\n")
    script = tv_reading_block().replace("/usr/local/bin/tvgw", str(stub / "tvgw"))
    env = {"PATH": f"{stub}:/usr/bin:/bin", "STATE": str(tmp_path)}
    out = subprocess.run([bash, "-euo", "pipefail", "-c", script], env=env, capture_output=True, text=True)
    assert out.returncode == 0, out.stderr
    reading = (tmp_path / "tvcheck.txt").read_text()
    assert reading == (
        "read 2026-11-03T10:20:00-06:00\n" + said
        if kept
        else "read 2026-11-02T22:20:00-06:00\noption.livePlus = off\n"
    )
    assert (tmp_path / "tvcheck-history.log").read_text() == f"2026-11-03T10:20:00-06:00\t{line}\n"
    assert not (tmp_path / ".tvcheck.tmp").exists()
    assert ("WARNING" in out.stdout) == (rc == 3)


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


def restart_changed(tmp_path, tv_ip="10.10.10.17", fail="", tv_if="eth0", mode="source"):
    """Run install.sh's restart_changed for the three long-running units against copies of their unit
    files, a settings file and a package tree under tmp_path, with a fake systemctl (which fails to
    restart `fail`); returns the units it restarted. `mode` is install.sh's MODE, source or package."""
    bash = shutil.which("bash")
    if bash is None or shutil.which("sha256sum") is None:
        pytest.skip("bash and sha256sum are needed here")
    start = INSTALL.index("\nSTAMPS=")
    block = INSTALL[start : INSTALL.index("\n}\n", INSTALL.index("restart_changed() {", start)) + 3]
    units = tmp_path / "deploy" / "systemd"
    if not units.exists():
        units.mkdir(parents=True)
        for u in (*LONG_RUNNING, "tvgw-pcap-headers"):  # (capture) the headers unit restarts with tvgw-pcap
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
            f"MODE={mode}",
            f"TV_IP={tv_ip}",
            f"TV_IF={tv_if} TV_NET=10.10.10.0/24 GW_IP=10.10.10.1",
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
    (tmp_path / "src" / "tvgw" / "dnsgate.py").write_text("feed = 2\n", encoding="utf-8")
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


def test_the_tree_is_replaced_installed_and_tested_under_one_lock(tmp_path):
    """sync-install.sh takes the lock first, then replaces the tree, then runs install.sh with the lock
    on the descriptor it inherits, then the command given (the CI suite) from the installed tree. Here
    flock is a fake that logs and the paths are moved under tmp_path; rsync is the real one, logged
    (openrsync re-runs itself as `rsync --server` for a local copy)."""
    bash, rsync = shutil.which("bash"), shutil.which("rsync")
    if bash is None or rsync is None:
        pytest.skip("bash and rsync are needed here")
    log, src, dest = tmp_path / "log", tmp_path / "checkout", tmp_path / "opt" / "src"
    (src / "deploy").mkdir(parents=True)
    (dest / "build").mkdir(parents=True)
    (dest / "build" / "kept").write_text("")  # excluded, so --delete leaves it
    (dest / "gone.py").write_text("")
    script = (DEPLOY / "sync-install.sh").read_text()
    (src / "deploy" / "sync-install.sh").write_text(
        script.replace("/opt/tvgw/src", str(dest)).replace("/run/tvgw", str(tmp_path / "run"))
    )
    (src / "deploy" / "rsync.exclude").write_text((DEPLOY / "rsync.exclude").read_text())
    (src / "deploy" / "install.sh").write_text(
        f'#!/bin/bash\n{{ true >&8; }} 2>/dev/null && echo "install fd8 locked=$TVGW_INSTALL_LOCKED" >>{log}\n'
    )
    (src / "deploy" / "install.sh").chmod(0o755)
    (tmp_path / "bin").mkdir()
    for name, body in (
        ("flock", f'echo "flock $*" >>{log}'),
        ("rsync", f'[ "$1" = --server ] || echo rsync >>{log}; exec {rsync} "$@"'),
    ):
        (tmp_path / "bin" / name).write_text(f"#!/bin/sh\n{body}\n")
        (tmp_path / "bin" / name).chmod(0o755)
    env = {**os.environ, "PATH": f"{tmp_path / 'bin'}:{os.environ['PATH']}"}
    suite = f'echo "suite $(pwd)" >>{log}'
    subprocess.run([bash, str(src / "deploy" / "sync-install.sh"), "sh", "-c", suite], env=env, check=True)
    assert log.read_text().splitlines() == [
        "flock -w 600 8",
        "rsync",
        "install fd8 locked=1",
        f"suite {os.path.realpath(dest)}",
    ]
    assert (dest / "deploy" / "install.sh").exists() and (dest / "build" / "kept").exists()
    assert not (dest / "gone.py").exists()


FLOCK = f"""#!{sys.executable}
# flock(1) where util-linux is not installed: flock(2) on a descriptor or a file, then the command.
# A held lock is refused at once, -w or not: nothing in these tests waits for one.
import fcntl, os, sys
args = [a for a in sys.argv[1:] if a != "-n"]
args = args[2:] if args[0] == "-w" else args
fd = int(args[0]) if args[0].isdigit() else os.open(args[0], os.O_RDWR | os.O_CREAT, 0o644)
try:
    fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
except OSError:
    sys.exit(1)
if args[1:]:
    os.execvp(args[1], args[1:])
"""


def test_install_takes_the_held_lock_through_the_descriptor_it_inherits(tmp_path):
    """What install.sh relies on under sync-install.sh: flock on the open file that already holds the
    lock returns at once, while any other open of the lock file is refused until the holder is done.
    flock(1) is util-linux's where installed, else a stand-in making the same flock(2) call."""
    bash = shutil.which("bash")
    if bash is None:
        pytest.skip("bash is not installed here")
    env = dict(os.environ)
    if shutil.which("flock") is None:
        (tmp_path / "bin").mkdir()
        (tmp_path / "bin" / "flock").write_text(FLOCK)
        (tmp_path / "bin" / "flock").chmod(0o755)
        env["PATH"] = f"{tmp_path / 'bin'}:{env['PATH']}"
    start = INSTALL.index("install -d -m 755 /run/tvgw\n")
    block = INSTALL[start : INSTALL.index("\n", INSTALL.index("flock -w 600 8", start))]
    child = tmp_path / "child.sh"
    child.write_text(
        'die() { echo "died: $*"; exit 1; }\n'
        + block.replace("/run/tvgw", str(tmp_path))
        + "\necho inherited\n"
    )
    lock = tmp_path / "install.lock"
    parent = (
        f"exec 8>{lock}; flock -w 1 8; TVGW_INSTALL_LOCKED=1 bash {child}; flock -n {lock} true || echo held"
    )
    out = subprocess.run([bash, "-c", parent], capture_output=True, text=True, env=env, timeout=60)
    assert out.stdout.split() == ["inherited", "held"], out


def test_the_package_is_built_from_a_fresh_build_directory():
    """pip builds the checkout in place and setuptools never prunes build/lib, which rsync --delete
    leaves alone (it is on the exclude list): report.py, retired from src/, kept shipping in every
    wheel. The build directory goes before every pip install of the checkout."""
    lines = [line.strip() for line in INSTALL.splitlines()]  # (packaging) inside the source-mode branch
    pip = next(i for i, line in enumerate(lines) if line.startswith('$VENV/bin/pip install -q "$REPO['))
    assert 'rm -rf "$REPO/build"' in lines[:pip]


def test_what_the_next_boot_runs_is_on_disk_before_the_install_goes_on():
    """GNU install unlinks the destination and writes a new file, which ext4 may hold in memory for half
    a minute; a power cut soon after a deploy could leave tvgw-apply or a unit empty and the TV dark
    at boot. One sync follows the last file the boot reads, before the long first analyze run."""
    lines = INSTALL.splitlines()
    synced = lines.index("sync")
    last_write = max(i for i, line in enumerate(lines) if ">/etc/systemd/system/" in line)
    analyze = next(
        i for i, line in enumerate(lines) if line.startswith("systemctl start tvgw-analyze.service")
    )
    assert last_write < synced < analyze


def test_the_capture_restarts_when_its_tv_side_changed(tmp_path):
    """(packaging) dumpcap's interface and filter come from the drop-in install.sh writes from TV_IF,
    TV_NET and GW_IP: a changed TV port must reach the running capture."""
    assert restart_changed(tmp_path) == list(LONG_RUNNING)
    assert restart_changed(tmp_path, tv_if="eth1") == ["tvgw-pcap"]
    assert restart_changed(tmp_path, tv_if="eth1") == []


def test_a_stray_wheels_directory_in_a_checkout_does_not_change_what_the_feeder_is_stamped_with(tmp_path):
    """(packaging) the stamp follows install.sh's MODE: a wheels/ left in a checkout used to make a source
    install stamp a wheel, and a change to src/ then never restarted tvgw-dnsgate."""
    (tmp_path / "wheels").mkdir()
    (tmp_path / "wheels" / "tvgw-0.1.0-py3-none-any.whl").write_bytes(b"old")
    assert restart_changed(tmp_path) == list(LONG_RUNNING)
    (tmp_path / "src" / "tvgw" / "dnsgate.py").write_text("feed = 2\n", encoding="utf-8")
    assert restart_changed(tmp_path) == ["tvgw-dnsgate"]
    assert restart_changed(tmp_path, mode="package") == ["tvgw-dnsgate"]  # now the wheel
    (tmp_path / "src" / "tvgw" / "dnsgate.py").write_text("feed = 3\n", encoding="utf-8")
    assert restart_changed(tmp_path, mode="package") == []  # the package runs the wheel, not src/


def test_the_capture_restarts_when_its_mode_or_the_headers_unit_changed(tmp_path):
    """(integration, capture) Each capture unit's ExecCondition reads CAPTURE_MODE when it starts, and
    tvgw-pcap-headers stops and starts with tvgw-pcap (PartOf=): a deploy restarts tvgw-pcap when either
    changed, and an edit to another key of the settings leaves the capture alone."""
    assert restart_changed(tmp_path) == list(LONG_RUNNING)
    conf = tmp_path / "etc" / "tvgw.conf"
    conf.write_text("TV_IP=10.10.10.17\nCAPTURE_MODE=headers\n", encoding="utf-8")
    assert restart_changed(tmp_path) == ["tvgw-pcap", "tvgw-dnsgate"]  # the feeder hashes the whole conf
    conf.write_text("TV_IP=10.10.10.17\nCAPTURE_MODE=headers\nDB_DAYS=200\n", encoding="utf-8")
    assert restart_changed(tmp_path) == ["tvgw-dnsgate"]
    with (tmp_path / "deploy" / "systemd" / "tvgw-pcap-headers.service").open("a") as fh:
        fh.write("# a changed headers unit\n")
    assert restart_changed(tmp_path) == ["tvgw-pcap"]
    assert restart_changed(tmp_path) == []


def dumpcap_preflight(tmp_path, mode: int | None, usable: bool) -> subprocess.CompletedProcess:
    """install.sh's dumpcap check, with dumpcap at `mode` (None: missing) under tmp_path and a fake
    runuser that answers for tvgw-pcap as `usable` says."""
    bash = shutil.which("bash")
    if bash is None:
        pytest.skip("install.sh is bash")
    start = INSTALL.index("DUMPCAP=/usr/bin/dumpcap\n")
    end = INSTALL.index("\n", INSTALL.index("\tdie ", start)) + 1
    dumpcap = tmp_path / "dumpcap"
    if mode is not None:
        dumpcap.write_text("#!/bin/sh\n", encoding="utf-8")
        dumpcap.chmod(mode)
    (tmp_path / "bin").mkdir()
    runuser = tmp_path / "bin" / "runuser"
    runuser.write_text(
        f'#!/bin/sh\necho "$*" >>{tmp_path}/calls\nexit {0 if usable else 1}\n', encoding="utf-8"
    )
    runuser.chmod(0o755)
    step = INSTALL[start:end].replace("/usr/bin/dumpcap", str(dumpcap))
    script = 'die() { echo "tvgw: $*" >&2; exit 1; }\n' + step + "echo passed\n"
    env = {**os.environ, "PATH": f"{tmp_path / 'bin'}:{os.environ['PATH']}"}
    return subprocess.run([bash, "-euo", "pipefail", "-c", script], env=env, capture_output=True, text=True)


@pytest.mark.parametrize(("mode", "usable"), [(None, True), (0o644, True), (0o754, False)])
def test_install_stops_before_the_units_when_tvgw_pcap_cannot_run_dumpcap(tmp_path, mode, usable):
    """(integration, capture) A missing dumpcap, or one wireshark-common made 0754 root:wireshark, would
    leave the new tvgw-pcap failing in a loop: install.sh stops first, with what to do."""
    out = dumpcap_preflight(tmp_path, mode, usable)
    assert out.returncode == 1 and "passed" not in out.stdout
    assert "is missing or not executable by tvgw-pcap" in out.stderr
    assert "docs/how-it-works/capture.md#what-dumpcap-needs" in out.stderr


def test_install_goes_on_when_tvgw_pcap_can_run_dumpcap(tmp_path):
    out = dumpcap_preflight(tmp_path, 0o755, True)
    assert out.returncode == 0 and out.stdout == "passed\n", out.stderr
    assert (tmp_path / "calls").read_text().split()[:3] == ["-u", "tvgw-pcap", "--"]


def test_the_dumpcap_check_comes_after_the_user_and_before_any_unit_is_installed():
    check = INSTALL.index('runuser -u tvgw-pcap -- test -x "$DUMPCAP"')
    assert INSTALL.index("useradd --system") < check < INSTALL.index("install -m 644 systemd/*.service")
