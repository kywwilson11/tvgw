"""The .deb (packaging, R&D §8.2): its layout, its maintainer scripts, the lock and the release job.

Nothing here builds a package or touches the network. The maintainer scripts run for real with their
absolute paths moved under tmp_path and systemctl, nmcli and nginx replaced by stubs; the build tool's
lock handling runs on the committed lock and on fakes of pip and PyPI."""

import importlib.util
import os
import re
import shutil
import stat
import subprocess
import sys
import tomllib
from pathlib import Path

import pytest
import yaml
from conftest import ROOT

from tvgw import verify

PKG = ROOT / "packaging"
SCRIPTS = PKG / "scripts"
NFPM = yaml.safe_load((PKG / "nfpm.yaml").read_text(encoding="utf-8"))
INSTALL = (ROOT / "deploy" / "install.sh").read_text(encoding="utf-8")
LOCK = (PKG / "requirements.lock").read_text(encoding="utf-8")
RELEASE = ROOT / ".github" / "workflows" / "release.yml"


def load_wheelhouse():
    spec = importlib.util.spec_from_file_location("wheelhouse", PKG / "wheelhouse.py")
    mod = importlib.util.module_from_spec(spec)
    sys.modules["wheelhouse"] = mod
    spec.loader.exec_module(mod)
    return mod


wheelhouse = load_wheelhouse()


def block(text: str, name: str) -> str:
    start = text.index(f"# ---- {name}:")
    end = text.index(f"# ---- end {name} ----\n", start) + len(f"# ---- end {name} ----\n")
    return text[start:end]


def moved(text: str, root: Path) -> str:
    """A script with every absolute path it touches moved under `root`, in one pass: root itself
    may live under /var (macOS's temporary directories do)."""
    prefixes = r"/(?:etc|usr/local|usr/lib/tvgw|opt|var|run)/"
    return re.sub(rf"(?<=[\s\"'=>(|:])(?={prefixes})", str(root), text)


def stub(bin_dir: Path, name: str, body: str = "") -> None:
    bin_dir.mkdir(parents=True, exist_ok=True)
    log = bin_dir.parent / "calls"
    (bin_dir / name).write_text(f'#!/bin/sh\necho "{name} $*" >>{log}\n{body}\n', encoding="utf-8")
    (bin_dir / name).chmod(0o755)


def run_script(name: str, root: Path, *args: str, stubs=(), env=None) -> subprocess.CompletedProcess:
    text = moved((SCRIPTS / name).read_text(encoding="utf-8"), root)
    path = root / name
    path.write_text(text, encoding="utf-8")
    for s in stubs:
        stub(root / "bin", *(s if isinstance(s, tuple) else (s,)))
    full = {"PATH": f"{root / 'bin'}{os.pathsep}{os.environ['PATH']}", **(env or {})}
    return subprocess.run(
        ["sh", str(path), *args], env=full, capture_output=True, text=True, encoding="utf-8"
    )


def calls(root: Path) -> list[str]:
    log = root / "calls"
    return log.read_text(encoding="utf-8").splitlines() if log.exists() else []


# ---- the layout ---------------------------------------------------------------------------------


def test_the_package_carries_what_install_sh_looks_for_in_package_mode():
    """install.sh switches to the offline wheelhouse when it finds the lock and the wheels beside its
    tree: the package must put them exactly there, and the scripts must run that install.sh."""
    dst = {c["dst"]: c for c in NFPM["contents"]}
    assert dst["/usr/lib/tvgw/deploy"]["type"] == "tree"
    assert dst["/usr/lib/tvgw/wheels"]["type"] == "tree"
    assert "/usr/lib/tvgw/requirements.lock" in dst and "/usr/lib/tvgw/SHA256SUMS" in dst
    assert 'if [ -f "$REPO/requirements.lock" ] && [ -d "$REPO/wheels" ]; then' in INSTALL
    assert "INSTALL=/usr/lib/tvgw/deploy/install.sh" in (SCRIPTS / "postinst").read_text(encoding="utf-8")


def test_every_staged_source_is_one_the_build_script_makes_or_the_repo_has():
    build = (PKG / "build-deb.sh").read_text(encoding="utf-8")
    assert "STAGE=build/deb" in build
    for c in NFPM["contents"]:
        src = c["src"].removeprefix("./")
        assert src.startswith("build/deb/") or (ROOT / src).is_file(), src
    for staged in ("deploy", "wheels", "requirements.lock", "SHA256SUMS"):
        assert any(c["src"] == f"./build/deb/{staged}" for c in NFPM["contents"]), staged


def test_the_package_depends_on_every_apt_package_install_sh_names():
    header = next(line for line in INSTALL.splitlines() if line.startswith("# Prerequisites (apt):"))
    named = header.split(":", 1)[1].split("plus")[0].split()
    depends = {d.split()[0] for d in NFPM["depends"]}
    assert set(named) <= depends, set(named) - depends
    assert {"nftables", "network-manager", "python3", "curl", "util-linux"} <= depends
    assert not [d for d in depends if "adguard" in d.lower()], "AdGuard Home is never bundled or depended on"


def test_the_maintainer_scripts_exist_are_executable_and_parse():
    for key, path in NFPM["scripts"].items():
        script = ROOT / path.removeprefix("./")
        assert script.is_file(), key
        assert script.stat().st_mode & stat.S_IXUSR, f"{script.name} is not executable"
        out = subprocess.run(["sh", "-n", str(script)], capture_output=True, text=True, encoding="utf-8")
        assert out.returncode == 0, out.stderr


def test_the_version_and_architecture_come_from_the_build():
    assert NFPM["version"] == "${TVGW_VERSION}" and NFPM["arch"] == "${TVGW_ARCH}"
    build = (PKG / "build-deb.sh").read_text(encoding="utf-8")
    assert "TVGW_VERSION=$VERSION TVGW_ARCH=$ARCH nfpm package --config packaging/nfpm.yaml" in build


def test_only_tracked_deploy_files_are_packaged():
    """deploy/local/ holds a site's real settings (gitignored); the build copies what git tracks."""
    build = (PKG / "build-deb.sh").read_text(encoding="utf-8")
    assert "git ls-files -z deploy | tar --null -T - -cf -" in build
    assert "git ls-files --others --exclude-standard deploy src packaging" in build


@pytest.mark.skipif(shutil.which("bash") is None, reason="the build script is bash")
def test_a_release_tag_must_name_the_version_it_packages(tmp_path):
    out = subprocess.run(
        ["bash", str(PKG / "build-deb.sh"), str(tmp_path)],
        env={**os.environ, "TVGW_TAG": "v0.0.0-not-this"},
        capture_output=True,
        text=True,
        encoding="utf-8",
    )
    version = tomllib.loads((ROOT / "pyproject.toml").read_text(encoding="utf-8"))["project"]["version"]
    assert out.returncode == 1
    assert f"does not match the version in pyproject.toml ({version})" in out.stderr
    assert not list(tmp_path.iterdir()), "nothing is built for a mismatched tag"


# ---- AdGuard Home, a checked dependency ---------------------------------------------------------

AGH = block(INSTALL, "tvgw-adguard")


def test_the_adguard_check_is_the_same_in_install_and_preinst():
    assert block((SCRIPTS / "preinst").read_text(encoding="utf-8"), "tvgw-adguard") == AGH


def test_the_shell_floor_is_verify_s():
    (floor,) = re.findall(r"^AGH_MIN=(\S+)$", AGH, re.M)
    assert tuple(int(x) for x in floor.split(".")) == verify.ADGUARD_MIN
    assert "https://raw.githubusercontent.com/AdguardTeam/AdGuardHome/master/scripts/install.sh" in AGH
    assert "https://raw.githubusercontent.com/AdguardTeam/AdGuardHome/master/scripts/install.sh" in (
        verify.ADGUARD_INSTALL
    )


@pytest.mark.parametrize(
    ("have", "want", "ok"),
    [
        ("0.107.73", "0.107.73", True),
        ("v0.107.74", "0.107.73", True),
        ("0.108.0", "0.107.73", True),
        ("1.0", "0.107.73", True),
        ("0.107.72", "0.107.73", False),
        ("0.107", "0.107.73", False),
        ("0.99.200", "0.107.73", False),
        ("x.107.73", "0.107.73", False),
        ("0..73", "0.107.73", False),
    ],
)
def test_version_at_least(have, want, ok):
    out = subprocess.run(["sh", "-c", AGH + 'version_at_least "$1" "$2"', "_", have, want])
    assert (out.returncode == 0) == ok


def fake_adguard(root: Path, version_line: str | None) -> None:
    """An AdGuardHome binary under root/opt that prints `version_line` (None: no binary at all)."""
    exe = root / "opt" / "AdGuardHome" / "AdGuardHome"
    exe.parent.mkdir(parents=True, exist_ok=True)
    if version_line is not None:
        exe.write_text(f"#!/bin/sh\necho '{version_line}'\n", encoding="utf-8")
        exe.chmod(0o755)


@pytest.mark.parametrize(
    ("version_line", "ok", "says"),
    [
        ("AdGuard Home, version v0.107.79", True, ""),  # (lists) the floor since 2026-11-01
        ("AdGuard Home, version v0.108.0-b.2", True, ""),
        ("AdGuard Home, version v0.107.78", False, "is below v0.107.79"),
        ("AdGuard Home, version v0.107.73", False, "is below v0.107.79"),
        ("something else", False, "could not read AdGuard Home's version"),
        (None, False, "AdGuard Home is not installed"),
    ],
)
@pytest.mark.parametrize("arg", ["install", "upgrade"])
def test_preinst_refuses_without_adguard_at_the_floor(tmp_path, version_line, ok, says, arg):
    fake_adguard(tmp_path, version_line)
    out = run_script("preinst", tmp_path, arg)
    assert (out.returncode == 0) == ok, out.stderr
    if not ok:
        assert says in out.stderr and "nothing was changed" in out.stderr
    if version_line is None:
        assert "scripts/install.sh | sh -s -- -v" in out.stderr


@pytest.mark.parametrize("installed", [True, False])
def test_a_floor_failure_names_tvgws_upgrade_once_tvgw_is_installed(tmp_path, installed):
    """(lists) With tvgw there the binary changes only through `tvgw adguard upgrade`, which checks the
    live config with the new binary first; before tvgw, AdGuard's own updater is the only way."""
    fake_adguard(tmp_path, "AdGuard Home, version v0.107.78")
    if installed:
        stub(tmp_path / "bin", "tvgw")
    (tmp_path / "bin").mkdir(exist_ok=True)
    out = run_script("preinst", tmp_path, "upgrade", env={"PATH": f"{tmp_path / 'bin'}:/usr/bin:/bin"})
    assert out.returncode != 0
    assert ("sudo tvgw adguard upgrade <its AdGuardHome binary>" in out.stderr) == installed, out.stderr
    assert ("--update" in out.stderr) == (not installed) and "web UI" not in out.stderr


def test_preinst_checks_only_before_unpacking(tmp_path):
    """abort-upgrade and friends run with dpkg already unwinding: refusing there helps nobody."""
    fake_adguard(tmp_path, None)
    assert run_script("preinst", tmp_path, "abort-upgrade", "0.1.0").returncode == 0


def test_install_sh_runs_the_same_check_before_it_writes_anything():
    """Before the first file it writes: only the install lock (under /run) comes earlier."""
    lines = INSTALL.splitlines()
    check = lines.index('adguard_ok || die "$AGH_ERR"')
    writes = [
        i
        for i, line in enumerate(lines)
        if re.match(r"\s*(install |ln |rm |sed |printf |cp |mv |nmcli |systemctl |useradd )", line)
        or re.search(r"[^2&]>\s*/", line)
    ]
    early = [lines[i] for i in writes if i < check]
    assert all("/run/tvgw" in line for line in early) and len(early) == 2, early  # the lock, nothing else
    assert check < lines.index("install -d -m 755 /etc/tvgw")


# ---- postinst -----------------------------------------------------------------------------------


def run_postinst(
    tmp_path, status: int, systemd: bool = True, body: str | None = None, stubs=()
) -> subprocess.CompletedProcess:
    """postinst with a stand-in install.sh that exits `status`, or runs `body` (a bash script)."""
    install = tmp_path / "usr" / "lib" / "tvgw" / "deploy" / "install.sh"
    install.parent.mkdir(parents=True)
    # records how it was called: the variable, and whether stdin is a terminal or /dev/null
    install.write_text(
        body
        or f'#!/bin/sh\nif [ -t 0 ]; then s=tty; else s=closed; fi\necho "install TVGW_POSTINST=$TVGW_POSTINST stdin=$s" >>{tmp_path}/calls\n'
        f"exit {status}\n",
        encoding="utf-8",
    )
    install.chmod(0o755)
    if systemd:
        (tmp_path / "run" / "systemd" / "system").mkdir(parents=True)
    return run_script("postinst", tmp_path, "configure", "", stubs=stubs)


@pytest.mark.parametrize(
    ("status", "exit_", "says"), [(0, 0, ""), (75, 0, "not identified"), (76, 0, "FAIL")]
)
def test_postinst_reports_a_missing_tv_or_a_failed_verify_and_keeps_the_package(
    tmp_path, status, exit_, says
):
    out = run_postinst(tmp_path, status)
    assert out.returncode == exit_, out.stderr
    assert says in out.stderr
    assert calls(tmp_path) == ["install TVGW_POSTINST=1 stdin=closed"]  # never prompts


@pytest.mark.parametrize("status", [1, 3, 4])
def test_postinst_fails_the_configuration_when_the_install_stopped(tmp_path, status):
    """dpkg then marks the package half-configured and `dpkg --configure -a` runs install.sh again.
    3 and 4 are nmcli's timeout and failed activation: never one of the two deliberate exits."""
    out = run_postinst(tmp_path, status)
    assert out.returncode == status
    assert "dpkg --configure -a" in out.stderr


def test_the_two_deliberate_exits_are_the_ones_postinst_reads():
    """install.sh exits 75 and 76 on purpose, and otherwise only 0 or 1 (its ERR trap); postinst keeps
    the package for exactly those two."""
    assert set(re.findall(r"\bexit (\d+)", INSTALL)) == {"0", "1", "75", "76"}
    assert "exit 75" in INSTALL and "tvgw verify || exit 76" in INSTALL
    postinst = (SCRIPTS / "postinst").read_text(encoding="utf-8")
    assert re.findall(r"^\t(\d+)\)$", postinst, re.M) == ["75", "76"]


def strict_preamble() -> str:
    """install.sh's shell options and its ERR trap, as they open the script."""
    start = INSTALL.index("set -euo pipefail\n")
    end = INSTALL.index("trap 'exit 1' ERR\n") + len("trap 'exit 1' ERR\n")
    return INSTALL[start:end]


def tv_lan_functions() -> str:
    start = INSTALL.index("stand_aside() {")
    return INSTALL[start : INSTALL.index("\ntv_lan\n", start) + 1]


# nmcli as the create path sees it: no tv-lan yet, and an activation that fails with nmcli's status 4
NMCLI_UP_FAILS = """case "$*" in
"con up tv-lan") exit 4 ;;
"-g GENERAL.STATE con show tv-lan") echo activating ;;
esac
exit 0"""


@pytest.mark.skipif(shutil.which("bash") is None, reason="install.sh is bash")
def test_a_failed_nmcli_activation_fails_the_configuration_and_is_not_read_as_a_deliberate_exit(tmp_path):
    """install.sh's own tv-lan step under its own shell options, with `nmcli con up` exiting 4 as nmcli
    does when an activation fails: under set -e alone the script exited 4, which postinst read as
    "installed, verify reported a FAIL", and dpkg called the half-done install configured."""
    body = "#!/bin/bash\n" + strict_preamble()
    body += "TV_IF=eth0 GW_IP=10.10.10.1 TV_PREFIX=24\n" + tv_lan_functions() + "tv_lan\nexit 0\n"
    out = run_postinst(tmp_path, 0, body=body, stubs=[("nmcli", NMCLI_UP_FAILS)])
    assert "nmcli con up tv-lan" in calls(tmp_path)
    assert out.returncode == 1, out.stderr
    assert "install.sh stopped (status 1)" in out.stderr and "dpkg --configure -a" in out.stderr
    # the same step without the trap: the command's own status escapes, the collision this prevents
    untrapped = body.replace("trap 'exit 1' ERR\n", "")
    (tmp_path / "untrapped.sh").write_text(untrapped, encoding="utf-8")
    env = {"PATH": f"{tmp_path / 'bin'}{os.pathsep}{os.environ['PATH']}"}
    assert subprocess.run(["bash", str(tmp_path / "untrapped.sh")], env=env).returncode == 4


def test_postinst_without_a_running_systemd_leaves_the_install_for_the_first_boot(tmp_path):
    out = run_postinst(tmp_path, 1, systemd=False)
    assert out.returncode == 0 and "first boot" in out.stderr
    assert calls(tmp_path) == []


# ---- prerm --------------------------------------------------------------------------------------


def prerm(tmp_path, *args):
    units = tmp_path / "usr" / "lib" / "tvgw" / "deploy" / "systemd"
    units.mkdir(parents=True)
    for unit in (ROOT / "deploy" / "systemd").iterdir():
        (units / unit.name).write_text("", encoding="utf-8")
    (tmp_path / "run" / "systemd" / "system").mkdir(parents=True)
    return run_script("prerm", tmp_path, *args, stubs=["systemctl"])


def test_removal_stops_the_timers_then_the_capture_then_the_firewall(tmp_path):
    """The firewall goes last, through its own stop path: forwarding off first, so the TV is dark,
    never unfiltered, from the moment the filter goes."""
    assert prerm(tmp_path, "remove").returncode == 0
    seen = calls(tmp_path)
    timers = [c for c in seen if c.endswith(".timer")]
    assert len(timers) == len(list((ROOT / "deploy" / "systemd").glob("*.timer")))
    assert seen[-1] == "systemctl disable --now tvgw.service"
    assert seen.index(
        "systemctl disable --now tvgw-pcap.service tvgw-flowlog.service tvgw-dnsgate.service"
    ) > max(seen.index(t) for t in timers)


def test_removal_disables_the_guard_and_never_stops_it(tmp_path):
    """(guard) The guard refuses a manual stop and has no ExecStop: it is disabled, and its table keeps
    the Pi closed to the TV until the next boot."""
    assert prerm(tmp_path, "remove").returncode == 0
    seen = calls(tmp_path)
    assert "systemctl disable tvgw-guard.service" in seen
    assert seen.index("systemctl disable tvgw-guard.service") < seen.index(
        "systemctl disable --now tvgw.service"
    )
    assert not [c for c in seen if "tvgw-guard" in c and ("--now" in c or " stop" in c)]


def test_an_upgrade_stops_nothing(tmp_path):
    """The new postinst re-applies the firewall in place; a stop would black the TV out for the upgrade."""
    assert prerm(tmp_path, "upgrade", "0.2.0").returncode == 0
    assert calls(tmp_path) == []


# ---- postrm -------------------------------------------------------------------------------------

# what install.sh leaves on the system (outside the package's own files), and what postrm does to it
WRITTEN = [
    "usr/local/sbin/tvgw-apply",
    "usr/local/sbin/tvgw-doh-update",
    "usr/local/sbin/tvgw-analyze",
    "usr/local/bin/tvgw",
    "etc/systemd/system/tvgw.service",
    "etc/systemd/system/tvgw-pcap.service",
    "etc/systemd/system/tvgw-verify.timer",
    "etc/systemd/system/tvgw-analyst.timer.d/schedule.conf",
    "etc/systemd/system/tvgw-analyst-weekly.timer.d/schedule.conf",
    "etc/systemd/system/tvgw-pcap.service.d/tv-side.conf",
    "etc/systemd/system/multi-user.target.wants/tvgw.service",
    "etc/systemd/system/timers.target.wants/tvgw-verify.timer",
    "etc/systemd/system/nginx.service.d/tvgw.conf",
    "etc/dnsmasq.d/tvgw.conf",
    "etc/logrotate.d/tvgw",
    "etc/sysctl.d/60-tvgw.conf",  # (events)
    "etc/systemd/journald.conf.d/60-tvgw.conf",  # (record)
    "etc/NetworkManager/conf.d/90-tvgw.conf",
    "etc/NetworkManager/dispatcher.d/90-tvgw",
    "etc/nginx/conf.d/tvgw-gfts.conf",
    "etc/nginx/tvgw/stream.conf",
    "opt/tvgw-venv/bin/python",
    "var/lib/tvgw/.unit-stamps/tvgw-pcap",
    # (guard) the hardening and co-tenant drop-ins (design decision 42)
    "etc/systemd/system/tvgw-guard.service",
    "etc/systemd/system/dnsmasq.service.d/20-tvgw-hardening.conf",
    "etc/systemd/system/smbd.service.d/10-tvgw-not-from-tv.conf",
    "etc/systemd/system/ssh.socket.d/10-tvgw-not-from-tv.conf",
]
KEPT_ON_REMOVE = ["etc/tvgw/tvgw.conf", "var/log/tvgw/flows.log", "var/lib/tvgw/tvgw.db"]
NOT_OURS = [
    "etc/systemd/system/AdGuardHome.service.d/workdir.conf",
    "etc/systemd/system/nginx.service.d/other.conf",
    "etc/dnsmasq.d/other.conf",
    "opt/AdGuardHome/AdGuardHome.yaml",
]


def system(tmp_path) -> None:
    for rel in (*WRITTEN, *KEPT_ON_REMOVE, *NOT_OURS):
        (tmp_path / rel).parent.mkdir(parents=True, exist_ok=True)
        (tmp_path / rel).write_text("x\n", encoding="utf-8")
    (tmp_path / "etc" / "nginx" / "nginx.conf").write_text(
        f"events {{}}\nhttp {{}}\ninclude {tmp_path}/etc/nginx/tvgw/stream.conf;\n", encoding="utf-8"
    )
    (tmp_path / "run" / "systemd" / "system").mkdir(parents=True)


@pytest.mark.parametrize("arg", ["remove", "purge"])
def test_removal_takes_away_what_install_wrote_and_nothing_of_anyone_else(tmp_path, arg):
    system(tmp_path)
    out = run_script("postrm", tmp_path, arg, stubs=["systemctl", "nmcli", ("nginx", "exit 0"), "sysctl"])
    assert out.returncode == 0, out.stderr
    left = [rel for rel in WRITTEN if (tmp_path / rel).exists()]
    assert not left
    # (events) the kernel's own default back, or a later conntrack listener hears nothing until a reboot
    assert "sysctl -q -w net.netfilter.nf_conntrack_events=2" in calls(tmp_path)
    assert all((tmp_path / rel).exists() for rel in NOT_OURS)
    assert (tmp_path / "etc" / "nginx" / "nginx.conf").read_text(encoding="utf-8") == "events {}\nhttp {}\n"
    assert (tmp_path / "var" / "lib" / "tvgw" / "tvgw.db").exists(), "the store outlives even a purge"
    for rel in ("etc/tvgw/tvgw.conf", "var/log/tvgw/flows.log"):
        assert (tmp_path / rel).exists() == (arg == "remove"), rel
    assert "systemctl daemon-reload" in calls(tmp_path)
    if arg == "purge":
        assert "nmcli con delete tv-lan" in calls(tmp_path)
        assert "kept in" in out.stderr and "rm -rf" in out.stderr


def test_an_upgrade_removes_nothing(tmp_path):
    system(tmp_path)
    assert (
        run_script("postrm", tmp_path, "upgrade", "0.2.0", stubs=["systemctl", "nmcli", "sysctl"]).returncode
        == 0
    )
    assert all((tmp_path / rel).exists() for rel in WRITTEN)
    assert calls(tmp_path) == []


def test_every_path_install_writes_is_one_postrm_knows():
    """A file install.sh starts writing must be removed with the package, or listed here as kept."""
    kept = ("/etc/tvgw/", "/var/log/tvgw", "/var/lib/tvgw", "/run/tvgw", "/etc/systemd/system/AdGuardHome")
    kept += ("/etc/nginx/nginx.conf",)  # not removed: postrm takes out the one line install added
    postrm = (SCRIPTS / "postrm").read_text(encoding="utf-8")
    removed = [w for line in postrm.splitlines() if line.strip().startswith("rm ") for w in line.split()[2:]]
    targets = set(re.findall(r">\s*(/(?:etc|usr|opt)/[^\s;\"')]+)", INSTALL))
    targets |= set(re.findall(r"^\s*install -m \d+ (?:\S+ )+(/\S+)$", INSTALL, re.M))
    targets |= set(re.findall(r"^ln -sf \S+ (/\S+)$", INSTALL, re.M))
    assert "/etc/dnsmasq.d/tvgw.conf" in targets and "/usr/local/bin/tvgw" in targets
    for target in sorted(targets):
        if target.startswith(kept):
            continue
        if target.endswith("/"):  # a directory install copies units into: the units go by pattern
            assert any(r.startswith(target) for r in removed), target
            continue
        covered = any(
            target == r
            or target.startswith(r.rstrip("/") + "/")
            or (r.endswith("/") and target.startswith(r))
            for r in removed
        ) or any(re.fullmatch(r.replace(".", r"\.").replace("*", "[^/]*"), target) for r in removed)
        assert covered, target


# ---- the lock and the wheelhouse ----------------------------------------------------------------


def test_the_lock_pins_every_runtime_dependency_with_hashes():
    reqs = {wheelhouse.normalize(r.name): r for r in wheelhouse.parse_lock(LOCK)}
    project = tomllib.loads((ROOT / "pyproject.toml").read_text(encoding="utf-8"))["project"]
    direct = [*project["dependencies"], *project["optional-dependencies"]["lgwebos"]]
    direct += project["optional-dependencies"]["analyst"]
    for spec in direct:
        name = wheelhouse.normalize(re.split(r"[<>=!~\[ ;]", spec)[0])
        assert name in reqs, f"{name} is a runtime dependency the lock does not pin"
    assert all(r.hashes for r in reqs.values())
    assert LOCK.startswith("# This file was autogenerated by uv via the following command:\n#    make lock\n")


def test_the_lock_is_made_for_what_install_sh_installs():
    """The extras the lock resolves are the ones the source install asks for, so both paths run the
    same set of modules."""
    make = (ROOT / "Makefile").read_text(encoding="utf-8")
    assert "--extra lgwebos --extra analyst --universal --python-version 3.11" in make
    assert '"$REPO[lgwebos,analyst]"' in INSTALL
    assert "--generate-hashes" in make


@pytest.mark.parametrize(
    "bad",
    ["pyyaml>=6 \\\n    --hash=sha256:" + "a" * 64, "pyyaml==6.0.3", "    --hash=sha256:" + "b" * 64],
)
def test_parse_lock_refuses_what_would_let_pip_choose(bad):
    with pytest.raises(ValueError):
        wheelhouse.parse_lock(bad + "\n")


SAMPLE = """# header
sqlitedict==2.1.0 \\
    --hash=sha256:{a}
    # via bscpylgtv
truststore==0.10.5 ; sys_platform != 'emscripten' \\
    --hash=sha256:{b} \\
    --hash=sha256:{c}
    # via httpx2
""".format(a="a" * 64, b="b" * 64, c="c" * 64)


def test_a_built_wheel_s_hash_joins_its_requirement_and_nothing_else_changes():
    out = wheelhouse.with_built_hashes(SAMPLE, {"sqlitedict": ["d" * 64]})
    reqs = {r.name: r for r in wheelhouse.parse_lock(out)}
    assert reqs["sqlitedict"].hashes == ("a" * 64, "d" * 64)
    assert reqs["truststore"].hashes == ("b" * 64, "c" * 64)
    assert reqs["truststore"].marker == "sys_platform != 'emscripten'"
    assert out.replace(" \\\n    --hash=sha256:" + "d" * 64, "") == SAMPLE
    assert wheelhouse.with_built_hashes(SAMPLE, {}) == SAMPLE


def test_the_committed_lock_survives_the_rewrite_unchanged():
    assert wheelhouse.with_built_hashes(LOCK, {}) == LOCK


def test_the_build_fetches_wheels_against_the_lock_and_builds_only_what_has_none(tmp_path, monkeypatch):
    """pip is a fake here: downloads write a file per target, builds write a pure-Python wheel."""
    lock = tmp_path / "requirements.lock"
    lock.write_text(SAMPLE, encoding="utf-8")
    seen: list[list[str]] = []

    def fake_pip(*args: str) -> None:
        seen.append(list(args))
        dest = Path(args[args.index("--dest") + 1]) if "--dest" in args else None
        if args[0] == "download" and "--no-binary=:all:" in args:
            dest.mkdir(parents=True, exist_ok=True)
            (dest / "sqlitedict-2.1.0.tar.gz").write_bytes(b"sdist")
        elif args[0] == "download":
            py = args[args.index("--python-version") + 1]
            (dest / f"truststore-0.10.5-py3-none-any.{py}.whl").write_bytes(b"wheel")
        elif args[0] == "wheel":
            out = Path(args[args.index("--wheel-dir") + 1])
            (out / "sqlitedict-2.1.0-py3-none-any.whl").write_bytes(b"built")

    monkeypatch.setattr(wheelhouse, "pip", fake_pip)
    releases = {
        "sqlitedict": {"urls": [{"packagetype": "sdist"}]},
        "truststore": {"urls": [{"packagetype": "bdist_wheel"}]},
    }
    built = wheelhouse.build(
        lock, tmp_path / "stage", "aarch64", ["3.11", "3.13"], release=lambda n, v: releases[n]
    )
    downloads = [a for a in seen if a[0] == "download" and "--only-binary=:all:" in a]
    assert [a[a.index("--python-version") + 1] for a in downloads] == ["3.11", "3.13"]
    for a in downloads:
        assert (
            "--require-hashes" in a
            and "manylinux_2_17_aarch64" in a
            and "cp" + a[a.index("--python-version") + 1].replace(".", "") in a
        )
    sdist = next(a for a in seen if "--no-binary=:all:" in a)
    assert "--require-hashes" in sdist and "--no-build-isolation" in sdist
    assert "--no-build-isolation" in next(
        a for a in seen if a[0] == "wheel"
    )  # (packaging) the pinned backend
    assert set(built) == {"sqlitedict"}
    carried = {
        r.name: r.hashes
        for r in wheelhouse.parse_lock((tmp_path / "stage" / "requirements.lock").read_text(encoding="utf-8"))
    }
    assert carried["sqlitedict"] == (
        "a" * 64,
        wheelhouse.sha256(tmp_path / "stage" / "wheels" / "sqlitedict-2.1.0-py3-none-any.whl"),
    )


BUILD_LOCK = (PKG / "build-requirements.lock").read_text(encoding="utf-8")


def test_the_build_backend_is_pinned_by_hash_and_installed_with_them():
    """(packaging) setuptools and wheel build both wheels; pip's build isolation used to fetch them
    unpinned, so a changed backend reached the release unhashed."""
    reqs = {wheelhouse.normalize(r.name): r for r in wheelhouse.parse_lock(BUILD_LOCK)}
    assert {"setuptools", "wheel"} <= set(reqs)
    assert all(r.hashes for r in reqs.values())
    wanted = re.findall(
        r"^([A-Za-z0-9._-]+)==(\S+)$", (PKG / "build-requirements.in").read_text(encoding="utf-8"), re.M
    )
    assert wanted and all(reqs[wheelhouse.normalize(n)].version == v for n, v in wanted)
    build = (PKG / "build-deb.sh").read_text(encoding="utf-8")
    assert (
        '"$PY" -m pip install -q --disable-pip-version-check --require-hashes -r packaging/build-requirements.lock'
        in build
    )
    assert '--no-build-isolation --no-deps --wheel-dir "$STAGE/wheels" .' in build
    assert '"$PY" packaging/wheelhouse.py' in build
    assert "python3 -m pip" not in build, "every pip call runs in the pinned build venv"
    assert '"--no-build-isolation"' in (PKG / "wheelhouse.py").read_text(encoding="utf-8")


def test_make_lock_runs_only_with_the_pinned_uv():
    make = (ROOT / "Makefile").read_text(encoding="utf-8")
    (version,) = re.findall(r"^UV_VERSION := (\d+\.\d+\.\d+)$", make, re.M)
    assert "$(UV) --version | grep -qE '^uv $(subst .,\\.,$(UV_VERSION))( |$$)'" in make, version
    assert "-o packaging/build-requirements.lock" in make


def test_install_checks_the_wheelhouse_and_installs_it_offline_and_hash_checked():
    assert "sha256sum --quiet --strict -c ../SHA256SUMS" in INSTALL
    assert '--no-index --find-links "$REPO/wheels" --require-hashes -r "$REPO/requirements.lock"' in INSTALL
    assert '--no-index --no-deps --force-reinstall "$REPO"/wheels/tvgw-*.whl' in INSTALL


# ---- the release job ----------------------------------------------------------------------------


def test_the_release_job_builds_on_a_tag_or_by_hand_with_the_least_it_needs():
    wf = yaml.safe_load(RELEASE.read_text(encoding="utf-8"))
    assert wf[True] == {"push": {"tags": ["v*"]}, "workflow_dispatch": None}  # PyYAML reads `on` as True
    assert wf["permissions"] == {"contents": "read"}
    job = wf["jobs"]["deb"]
    assert job["permissions"] == {"contents": "write"}
    assert job["concurrency"]["cancel-in-progress"] is False
    runs = "\n".join(step.get("run", "") for step in job["steps"])
    assert "packaging/build-deb.sh dist" in runs and "make gate" in runs
    assert "sha256sum -c -" in runs, "nfpm is checked against its pinned hash"
    assert re.fullmatch(r"[0-9a-f]{64}", job["env"]["NFPM_SHA256"])
    upload = next(step for step in job["steps"] if "gh release" in step.get("run", ""))
    assert upload["if"] == "github.ref_type == 'tag'"
    assert "TVGW_TAG" in next(step for step in job["steps"] if "build-deb.sh" in step.get("run", ""))["env"]


def test_every_release_action_is_pinned_by_commit_with_its_version_named():
    uses = [line.strip() for line in RELEASE.read_text(encoding="utf-8").splitlines() if "uses:" in line]
    assert uses
    for line in uses:
        assert re.fullmatch(r"- uses: [\w.-]+/[\w.-]+@[0-9a-f]{40} # v\d+\.\d+\.\d+", line), line
    assert "persist-credentials: false" in RELEASE.read_text(encoding="utf-8")
