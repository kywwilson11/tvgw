"""The .deb (packaging, R&D §8.2): its layout, its maintainer scripts, the lock, the release job, and
the build a pull request runs.

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

from tvgw import aghinstall, verify

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
    assert "sudo tvgw adguard install" in verify.ADGUARD_INSTALL


# every place that tells someone how to install AdGuard Home before tvgw can: the release tvgw pins
PINNED_HINTS = (
    "deploy/install.sh",
    "packaging/scripts/preinst",
    "packaging/get.sh.in",
    "packaging/install-check.sh",
    "docs/install/README.md",
)


@pytest.mark.parametrize("rel", PINNED_HINTS)
def test_adguard_home_is_installed_from_the_pinned_release_never_its_unpinned_script(rel):
    """Informational review item: the hints said `curl ... master/scripts/install.sh | sh`, which runs
    whatever AdGuard's master branch holds that day as root. Each now names aghinstall.PIN's version, and
    every SHA-256 it names is the pin's for that architecture."""
    text = (ROOT / rel).read_text(encoding="utf-8")
    assert "scripts/install.sh" not in text and "AdguardTeam/AdGuardHome/master" not in text
    assert aghinstall.PIN["version"] in text
    pinned = {digest for _, digest in aghinstall.PIN["assets"].values()}
    named = set(re.findall(r"\b[0-9a-f]{64}\b", text))
    assert named and named <= pinned, named - pinned
    if rel != "docs/install/README.md":  # the guide is the Raspberry Pi's: arm64 alone
        assert named == pinned


@pytest.mark.parametrize(("arch", "asset"), [("arm64", "arm64"), ("amd64", "amd64"), ("riscv64", None)])
def test_the_preinst_names_the_commands_for_this_computer(tmp_path, arch, asset):
    fake_adguard(tmp_path, None)
    out = run_script("preinst", tmp_path, "install", stubs=[("dpkg", f"echo {arch}")])
    assert out.returncode == 1 and "AdGuard Home is not installed" in out.stderr
    if asset:
        name, digest = aghinstall.PIN["assets"][asset]
        assert f"echo '{digest}  {name}' | sha256sum -c" in out.stderr
        assert f"sudo tar -xzf {name} -C /opt" in out.stderr
    else:
        assert f"releases/tag/v{aghinstall.PIN['version']}" in out.stderr


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
        assert "install the release tvgw pins" in out.stderr and "scripts/install.sh" not in out.stderr


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


AGH_OK = "AdGuard Home, version v0.107.79"


def stock_services(root: Path) -> None:
    """dnsmasq and nginx as their packages leave them once dpkg has configured both, on a computer that
    had them before tvgw: Debian's dnsmasq.conf of comments with its conf-dir line, /etc/dnsmasq.d/README,
    nginx's default site and an empty conf.d."""
    (root / "etc" / "dnsmasq.d").mkdir(parents=True)
    (root / "etc" / "dnsmasq.d" / "README").write_text("# drop files here\n", encoding="utf-8")
    (root / "etc" / "dnsmasq.conf").write_text(
        "# Configuration file for dnsmasq.\n\n#port=5353\n   # indented comment\nconf-dir=/etc/dnsmasq.d/,*.conf\n",
        encoding="utf-8",
    )
    (root / "etc" / "nginx" / "sites-enabled").mkdir(parents=True)
    (root / "etc" / "nginx" / "sites-enabled" / "default").symlink_to("../sites-available/default")
    (root / "etc" / "nginx" / "conf.d").mkdir()


def test_preinst_installs_beside_debians_own_dnsmasq_and_nginx_files(tmp_path):
    fake_adguard(tmp_path, AGH_OK)
    stock_services(tmp_path)
    out = run_script("preinst", tmp_path, "install")
    assert out.returncode == 0, out.stderr
    assert out.stderr == ""


def unpacked_services(root: Path) -> None:
    """dnsmasq and nginx as apt leaves them a moment before tvgw's preinst runs on a computer that had
    neither: the one apt run that installs tvgw has unpacked both and configured none, so every packaged
    file under /etc still carries dpkg's .dpkg-new, and nginx's postinst has enabled no site yet. The
    dnsmasq.d name is the one release.yml's install check printed for v0.3.1 on 2026-11-05."""
    (root / "etc" / "dnsmasq.d").mkdir(parents=True)
    (root / "etc" / "dnsmasq.d" / "README.dpkg-new").write_text("# drop files here\n", encoding="utf-8")
    (root / "etc" / "dnsmasq.conf.dpkg-new").write_text("#port=5353\n", encoding="utf-8")
    (root / "etc" / "nginx" / "sites-available").mkdir(parents=True)
    (root / "etc" / "nginx" / "sites-available" / "default.dpkg-new").write_text(
        "server {}\n", encoding="utf-8"
    )
    (root / "etc" / "nginx" / "sites-enabled").mkdir()
    (root / "etc" / "nginx" / "conf.d").mkdir()


def test_preinst_installs_in_the_apt_run_that_brings_dnsmasq_and_nginx(tmp_path):
    """0.3.1 refused every computer without dnsmasq: it named /etc/dnsmasq.d/README.dpkg-new, dpkg's copy
    of Debian's README until the package is configured, as somebody's setting, and the release's install
    check stopped the release on all four systems. A fresh install with nothing of anyone's passes."""
    fake_adguard(tmp_path, AGH_OK)
    unpacked_services(tmp_path)
    out = run_script("preinst", tmp_path, "install")
    assert out.returncode == 0, out.stderr
    assert out.stderr == ""


@pytest.mark.parametrize("suffix", [".dpkg-new", ".dpkg-dist", ".dpkg-old"])
def test_preinst_passes_the_copies_dpkg_keeps_which_debians_dnsmasq_skips(tmp_path, suffix):
    """CONFIG_DIR=/etc/dnsmasq.d,.dpkg-dist,.dpkg-old,.dpkg-new in Debian's /etc/default/dnsmasq: dnsmasq
    reads no file with such an ending, so one is no job of anybody's, whatever it holds. The same file
    under its own name is refused, and so is a name that only looks like dpkg's."""
    fake_adguard(tmp_path, AGH_OK)
    stock_services(tmp_path)
    kept = tmp_path / "etc" / "dnsmasq.d" / f"pihole.conf{suffix}"
    kept.write_text("port=5353\n", encoding="utf-8")
    out = run_script("preinst", tmp_path, "install")
    assert out.returncode == 0, out.stderr
    assert out.stderr == ""
    for name in ("pihole.conf", f"pihole{suffix}.conf", "README.dpkg-tmp", "README.bak"):
        other = tmp_path / "etc" / "dnsmasq.d" / name
        other.write_text("port=5353\n", encoding="utf-8")
        out = run_script("preinst", tmp_path, "install")
        assert out.returncode == 1, (name, out.stderr)
        # the files the message names, one to a line: this one alone, never dpkg's copy beside it
        named = [line for line in out.stderr.splitlines() if "/etc/dnsmasq.d/" in line]
        assert len(named) == 1 and named[0].endswith(f"/etc/dnsmasq.d/{name}"), (name, out.stderr)
        other.unlink()


@pytest.mark.parametrize(
    ("rel", "text"),
    [
        ("etc/dnsmasq.conf", "# mine\ninterface=eth1\n"),
        ("etc/dnsmasq.d/libvirt-daemon", "bind-interfaces\n"),
        ("etc/dnsmasq.d/pihole.conf", "port=5353\n"),
        ("etc/nginx/sites-enabled/photos", "server {}\n"),
        ("etc/nginx/conf.d/blog.conf", "server {}\n"),
    ],
)
def test_preinst_refuses_a_dnsmasq_or_nginx_that_already_does_a_job_of_its_own(tmp_path, rel, text):
    """install.sh would turn that dnsmasq's DNS off, give it the TV port alone, remove nginx's default site
    and sandbox both (no /home, no home network): a stranger's resolver or web site would break silently.
    Refused before dpkg unpacks anything, naming the file."""
    fake_adguard(tmp_path, AGH_OK)
    stock_services(tmp_path)
    (tmp_path / rel).write_text(text, encoding="utf-8")
    out = run_script("preinst", tmp_path, "install")
    assert out.returncode == 1
    named = "/etc/dnsmasq.conf holds settings" if rel == "etc/dnsmasq.conf" else f"/{rel}"
    assert named in out.stderr and "nothing was changed" in out.stderr, out.stderr
    assert "TVGW_TAKE_OVER=1" in out.stderr
    # the override, as the one-line installer hands its environment through apt
    out = run_script("preinst", tmp_path, "install", env={"TVGW_TAKE_OVER": "1"})
    assert out.returncode == 0, out.stderr
    # an upgrade changes nothing about either service: the files found are tvgw's own install's
    out = run_script("preinst", tmp_path, "upgrade", "0.2.0")
    assert out.returncode == 0, out.stderr


def test_preinst_knows_its_own_dnsmasq_and_nginx_files(tmp_path):
    """A reinstall after a remove that left them, or a half-done install: tvgw's own files are no one else's."""
    fake_adguard(tmp_path, AGH_OK)
    stock_services(tmp_path)
    (tmp_path / "etc" / "dnsmasq.d" / "tvgw.conf").write_text("port=0\n", encoding="utf-8")
    (tmp_path / "etc" / "nginx" / "conf.d" / "tvgw-gfts.conf").write_text("server {}\n", encoding="utf-8")
    out = run_script("preinst", tmp_path, "install")
    assert out.returncode == 0, out.stderr


def test_preinst_checks_only_before_unpacking(tmp_path):
    """abort-upgrade and friends run with dpkg already unwinding: refusing there helps nobody."""
    fake_adguard(tmp_path, None)
    assert run_script("preinst", tmp_path, "abort-upgrade", "0.1.0").returncode == 0


def test_install_sh_runs_the_same_check_before_it_writes_anything():
    """Before the first file it writes: only the install lock (under /run) comes earlier. (setup) The
    bring-up pass alone skips it: it stops before the steps that need AdGuard Home."""
    lines = INSTALL.splitlines()
    check = lines.index('[ "$TVGW_SETUP_PASS" = bringup ] || adguard_ok || die "$AGH_ERR"')
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


# (uninstall) nmcli as $NM/conns describes the connections, one `<uuid>:<yes|no>` a line (connects on its
# own or not); a connection gives its name as "Wired connection 1", and `con modify` fails for one named in
# $NM/stuck
NMCLI_CONNS = """case "$*" in
"-t -f UUID,AUTOCONNECT con show") cat "$NM/conns" 2>/dev/null ;;
"-t -f UUID con show") cut -d: -f1 "$NM/conns" 2>/dev/null ;;
"-g connection.autoconnect con show "*) sed -n "s/^$5:\\(.*\\)$/\\1/p" "$NM/conns" ;;
"-g connection.id con show "*) echo "Wired connection 1" ;;
"con modify "*) ! grep -qx "$3" "$NM/stuck" 2>/dev/null ;;
esac"""
# systemctl as the postinst and postrm see it: dnsmasq's unit is $DNSMASQ_STATE (enabled by default)
SYSTEMCTL_DNSMASQ = 'case "$1" in is-enabled) echo "${DNSMASQ_STATE:-enabled}" ;; esac\nexit 0'


def run_postinst(
    tmp_path, status: int, systemd: bool = True, body: str | None = None, stubs=(), env=None
) -> subprocess.CompletedProcess:
    """postinst with a stand-in install.sh that exits `status`, or runs `body` (a bash script); systemctl
    and nmcli are stubs whose answers `env` sets (DNSMASQ_STATE, NM)."""
    install = tmp_path / "usr" / "lib" / "tvgw" / "deploy" / "install.sh"
    install.parent.mkdir(parents=True, exist_ok=True)
    # records how it was called: the variable, and whether stdin is a terminal or /dev/null
    install.write_text(
        body
        or f'#!/bin/sh\nif [ -t 0 ]; then s=tty; else s=closed; fi\necho "install TVGW_POSTINST=$TVGW_POSTINST stdin=$s" >>{tmp_path}/calls\n'
        f"exit {status}\n",
        encoding="utf-8",
    )
    install.chmod(0o755)
    if systemd:
        (tmp_path / "run" / "systemd" / "system").mkdir(parents=True, exist_ok=True)
    stubs = [("systemctl", SYSTEMCTL_DNSMASQ), ("nmcli", NMCLI_CONNS), *stubs]
    return run_script("postinst", tmp_path, "configure", "", stubs=stubs, env=env)


def installs(root) -> list[str]:
    """The stand-in install.sh's own lines of the call log."""
    return [c for c in calls(root) if c.startswith("install ")]


@pytest.mark.parametrize(
    ("status", "exit_", "says"), [(0, 0, ""), (75, 0, "not identified"), (76, 0, "FAIL")]
)
def test_postinst_reports_a_missing_tv_or_a_failed_verify_and_keeps_the_package(
    tmp_path, status, exit_, says
):
    out = run_postinst(tmp_path, status)
    assert out.returncode == exit_, out.stderr
    assert says in out.stderr
    assert installs(tmp_path) == ["install TVGW_POSTINST=1 stdin=closed"]  # never prompts


@pytest.mark.parametrize("left", ["bringup", "apply", "nonsense"])
def test_postinst_never_hands_install_sh_a_setup_pass_from_dpkgs_environment(tmp_path, left):
    """(setup) TVGW_SETUP_PASS belongs to `tvgw setup`; one exported where apt runs would make the
    package's configure stop after the TV side, refuse an unknown TV, or run nothing at all."""
    body = (
        f'#!/bin/sh\necho "install pass=[${{TVGW_SETUP_PASS-unset}}] TVGW_POSTINST=$TVGW_POSTINST" >>{tmp_path}/calls\n'
        "exit 0\n"
    )
    out = run_postinst(tmp_path, 0, body=body, env={"TVGW_SETUP_PASS": left})
    assert out.returncode == 0, out.stderr
    assert installs(tmp_path) == ["install pass=[unset] TVGW_POSTINST=1"]


def test_postinst_fails_the_configuration_when_adguard_home_is_not_tvgws_to_take(tmp_path):
    """(adguard) 77: install.sh stopped at AdGuard Home, which serves other devices, and said how to go on
    (ADGUARD_TAKE_OVER=yes, then `dpkg --configure -a`); the postinst adds its own short line, not the
    one of a step that broke, and dpkg marks the configuration failed so that command runs it again."""
    out = run_postinst(tmp_path, 77)
    assert out.returncode == 1, out.stderr
    assert "AdGuard Home was left as it is" in out.stderr and "install.sh stopped" not in out.stderr
    assert installs(tmp_path) == ["install TVGW_POSTINST=1 stdin=closed"]


@pytest.mark.parametrize("status", [1, 3, 4])
def test_postinst_fails_the_configuration_when_the_install_stopped(tmp_path, status):
    """dpkg then marks the package half-configured and `dpkg --configure -a` runs install.sh again.
    3 and 4 are nmcli's timeout and failed activation: never one of the two deliberate exits."""
    out = run_postinst(tmp_path, status)
    assert out.returncode == status
    assert "dpkg --configure -a" in out.stderr


def test_the_deliberate_exits_are_the_ones_postinst_reads():
    """install.sh exits 75, 76 and 77 on purpose, and otherwise only 0 or 1 (its ERR trap); postinst keeps
    the package for the first two, and (adguard) fails the configuration on 77, without the line of a
    step that stopped: install.sh's own line says how to go on. (setup) The two passes add no exit of
    their own: `bringup` ends with 0 once the TV side is up, and `apply` ends as the postinst's run does,
    76 on a FAIL."""
    assert set(re.findall(r"\bexit (\d+)", INSTALL)) == {"0", "1", "75", "76", "77"}
    assert "exit 75" in INSTALL and "tvgw verify || exit 76" in INSTALL
    assert INSTALL.count("exit 77") == 1
    postinst = (SCRIPTS / "postinst").read_text(encoding="utf-8")
    assert re.findall(r"^\t(\d+)\)$", postinst, re.M) == ["75", "76", "77"]
    assert '\t"" | bringup | apply) ;;\n' in INSTALL
    # the postinst never runs a pass: it names the variable only to clear one left in dpkg's environment
    code = [line for line in postinst.splitlines() if not line.lstrip().startswith("#")]
    assert [line for line in code if "TVGW_SETUP_PASS" in line] == ["unset TVGW_SETUP_PASS"]
    bringup = INSTALL.index('if [ "$TVGW_SETUP_PASS" = bringup ]; then\n')
    assert INSTALL.index("\ntv_lan\n") < bringup < INSTALL.index("exit 75")
    block = INSTALL[bringup : INSTALL.index("\nfi\n", bringup) + 4]
    code = [line.strip() for line in block.splitlines() if not line.strip().startswith("#")]
    assert code == [
        'if [ "$TVGW_SETUP_PASS" = bringup ]; then',
        'sysctl -q -w "net.ipv4.conf.$TV_IF.forwarding=0"',  # nothing the TV sends is passed on
        "restart_dnsmasq # (guard) with the health check",
        'echo "tvgw: TV side up on $TV_IF ($GW_IP)"',
        "exit 0",
        "fi",
    ]
    # (revert) an apply the gateway undid ends the postinst's run and setup's apply pass as a FAIL does (76),
    # and a plain run with 1, after the same verify
    ending = (
        'if [ -n "${TVGW_POSTINST:-}" ] || [ "$TVGW_SETUP_PASS" = apply ]; then\n'
        "\ttvgw verify || exit 76\n"
        '\t[ "$UNDONE" = no ] || exit 76 # (revert) completed on the rules from before: a verify FAIL\'s exit\n'
        "\texit 0\nfi\n"
    )
    assert INSTALL.count(ending) == 1 and INSTALL.index(ending) < INSTALL.index("exec tvgw verify")
    assert INSTALL.index(
        'if [ "$UNDONE" = yes ]; then\n\ttvgw verify || true\n\texit 1\nfi\n'
    ) < INSTALL.index("exec tvgw verify")


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


# ---- (uninstall) the record of what the install changed ---------------------------------------------------

RECORD = "var/lib/tvgw/.installed-by-tvgw"


def stand_aside_body(root: Path, status: int = 75) -> str:
    """A stand-in install.sh that makes the state directory and does what stand_aside does to the
    connections: aaaa (the stock DHCP one on the TV port) stops connecting on its own; dddd, which connected
    on its own too, is deleted; bbbb was already off, the owner's choice; cccc is another port's."""
    nm = root / "nm"
    return (
        f"#!/bin/sh\nmkdir -p {root}/var/lib/tvgw\n"
        f"sed -e 's/^aaaa:yes$/aaaa:no/' -e '/^dddd:/d' {nm}/conns >{nm}/conns.new\n"
        f"mv {nm}/conns.new {nm}/conns\nexit {status}\n"
    )


def connections(root: Path, text: str) -> dict[str, str]:
    (root / "nm").mkdir(exist_ok=True)
    (root / "nm" / "conns").write_text(text, encoding="utf-8")
    return {"NM": str(root / "nm")}


@pytest.mark.parametrize("status", [75, 0, 1])
def test_postinst_records_the_connection_install_sh_stood_aside_and_the_services_apt_brought(
    tmp_path, status
):
    """L5: install.sh's stand_aside turns off the stock wired connection so tv-lan has the port, and the
    one-line installer lists in /run what apt installs new; neither survives anywhere a removal can read.
    The postinst keeps both in the state directory, whatever install.sh ended with: a later stop does not
    undo what stood aside before it."""
    env = connections(tmp_path, "aaaa:yes\nbbbb:no\ncccc:yes\ndddd:yes\n")
    (tmp_path / "run" / "tvgw").mkdir(parents=True)
    (tmp_path / "run" / "tvgw" / "fresh-deps").write_text("nginx\ndnsmasq\n", encoding="utf-8")
    run_postinst(tmp_path, 0, body=stand_aside_body(tmp_path, status), env=env)
    record = tmp_path / RECORD
    assert record.read_text(encoding="utf-8") == "autoconnect aaaa\npackage dnsmasq\npackage nginx\n"
    assert stat.S_IMODE(record.stat().st_mode) == 0o640
    # an upgrade's run stands nothing aside and adds nothing; what was recorded stays
    (tmp_path / "run" / "tvgw" / "fresh-deps").write_text("", encoding="utf-8")
    run_postinst(tmp_path, 0, body=stand_aside_body(tmp_path, 0), env=env)
    assert record.read_text(encoding="utf-8") == "autoconnect aaaa\npackage dnsmasq\npackage nginx\n"


def test_postinst_writes_no_record_when_nothing_changed_or_there_is_no_state_directory(tmp_path):
    env = connections(tmp_path, "cccc:yes\n")
    out = run_postinst(tmp_path, 75, env=env)  # a stand-in that changes nothing and makes no directory
    assert out.returncode == 0, out.stderr
    assert not (tmp_path / "var").exists()
    (tmp_path / "var" / "lib" / "tvgw").mkdir(parents=True)
    run_postinst(tmp_path, 75, env=env)
    assert list((tmp_path / "var" / "lib" / "tvgw").iterdir()) == []


@pytest.mark.parametrize(("state", "enabled"), [("disabled", True), ("enabled", False), ("masked", False)])
def test_postinst_switches_a_disabled_dnsmasq_on_before_the_install(tmp_path, state, enabled):
    """A purge switches off the dnsmasq apt brought for tvgw; an install after it needs the TV's DHCP at
    every boot again. A masked one is the administrator's and stays as it is."""
    run_postinst(tmp_path, 0, env={"DNSMASQ_STATE": state})
    seen = calls(tmp_path)
    assert ("systemctl enable dnsmasq.service" in seen) == enabled
    if enabled:
        assert seen.index("systemctl enable dnsmasq.service") < seen.index(
            "install TVGW_POSTINST=1 stdin=closed"
        )


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
        " tvgw-tvlive.service"
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


def postrm(tmp_path, arg: str, record: str | None, conns: str = "aaaa:no\n", **env: str):
    system(tmp_path)
    if record is not None:
        (tmp_path / RECORD).write_text(record, encoding="utf-8")
    nm = connections(tmp_path, conns)
    stubs = [("systemctl", SYSTEMCTL_DNSMASQ), ("nmcli", NMCLI_CONNS), ("nginx", "exit 0"), "sysctl"]
    return run_script("postrm", tmp_path, arg, stubs=stubs, env={**nm, **env})


def test_purge_gives_the_port_back_and_switches_off_the_dnsmasq_tvgw_brought(tmp_path):
    """L5: after a purge the stock wired connection connects on its own again, once tv-lan is gone, so a
    computer back in ordinary use has DHCP on its port; the dnsmasq apt installed for tvgw, which would
    now answer DNS on every network, is stopped and switched off, with the command that removes it."""
    out = postrm(tmp_path, "purge", "autoconnect aaaa\npackage dnsmasq\npackage nginx\n")
    assert out.returncode == 0, out.stderr
    seen = calls(tmp_path)
    assert seen.index("nmcli con delete tv-lan") < seen.index(
        "nmcli con modify aaaa connection.autoconnect yes"
    )
    assert (
        "systemctl disable --now dnsmasq.service" in seen
        and "systemctl try-restart dnsmasq.service" not in seen
    )
    assert "the connection Wired connection 1 connects on its own again" in out.stderr
    assert "remove it with: sudo apt purge dnsmasq" in out.stderr
    # given back: its line goes; the packages stay recorded for a later purge
    assert (tmp_path / RECORD).read_text(encoding="utf-8") == "package dnsmasq\npackage nginx\n"


def test_remove_keeps_tv_lan_and_the_stood_aside_connection_and_says_how_purge_gives_the_port_back(tmp_path):
    """`remove` keeps the settings and tv-lan, so a reinstall picks up where it was; the stock connection
    connecting on its own beside tv-lan would fight it for the port. The dnsmasq tvgw brought goes off."""
    out = postrm(tmp_path, "remove", "autoconnect aaaa\npackage dnsmasq\n")
    assert out.returncode == 0, out.stderr
    seen = calls(tmp_path)
    assert not [c for c in seen if c.startswith(("nmcli con modify", "nmcli con delete"))]
    assert "systemctl disable --now dnsmasq.service" in seen
    assert "sudo apt purge tvgw deletes it and gives the port back" in out.stderr
    assert (tmp_path / RECORD).read_text(encoding="utf-8") == "autoconnect aaaa\npackage dnsmasq\n"


@pytest.mark.parametrize("arg", ["remove", "purge"])
def test_without_a_record_the_dnsmasq_and_the_connections_are_left_as_they_were(tmp_path, arg):
    """A dnsmasq that was there before tvgw is the administrator's: restarted on its own file, never
    switched off; and no connection is touched but tv-lan."""
    out = postrm(tmp_path, arg, None)
    assert out.returncode == 0, out.stderr
    seen = calls(tmp_path)
    assert (
        "systemctl try-restart dnsmasq.service" in seen
        and "systemctl disable --now dnsmasq.service" not in seen
    )
    assert not [c for c in seen if c.startswith("nmcli con modify")]
    assert "dnsmasq came with tvgw" not in out.stderr and "gives the port back" not in out.stderr


def test_purge_skips_a_connection_deleted_since_and_names_the_command_for_one_it_cannot_change(tmp_path):
    out = postrm(tmp_path, "purge", "autoconnect aaaa\nautoconnect gone\n")  # gone: not among the conns
    assert out.returncode == 0, out.stderr
    assert not [c for c in calls(tmp_path) if "con modify gone" in c]
    assert not (tmp_path / RECORD).exists(), "nothing left to give back"
    root = tmp_path / "stuck"
    (root / "nm").mkdir(parents=True)
    (root / "nm" / "stuck").write_text("aaaa\n", encoding="utf-8")
    out = postrm(root, "purge", "autoconnect aaaa\n")
    assert "sudo nmcli con modify aaaa connection.autoconnect yes" in out.stderr
    assert (root / RECORD).read_text(encoding="utf-8") == "autoconnect aaaa\n", "kept for another try"


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
    assert '"${REPO}[lgwebos,analyst]"' in INSTALL  # braced: shellcheck reads "$REPO[" as an array (SC1087)
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

WF = yaml.safe_load(RELEASE.read_text(encoding="utf-8"))
JOBS = WF["jobs"]
TAG_ONLY = "github.ref_type == 'tag'"


def runs(job: dict) -> str:
    return "\n".join(step.get("run", "") for step in job["steps"])


def step_running(job: dict, text: str) -> dict:
    return next(step for step in job["steps"] if text in step.get("run", ""))


def step_using(job: dict, action: str) -> dict:
    return next(step for step in job["steps"] if step.get("uses", "").startswith(f"{action}@"))


def test_the_release_runs_on_a_tag_or_by_hand_and_reads_only_at_the_top():
    assert WF[True] == {"push": {"tags": ["v*"]}, "workflow_dispatch": None}  # PyYAML reads `on` as True
    assert WF["permissions"] == {"contents": "read"}
    assert set(JOBS) == {
        "gate",
        "deb",
        "install-check-arm64",
        "install-check-amd64",
        "assets",
        "publish",
        "site",
    }


def test_the_changelog_and_the_gate_are_checked_before_anything_is_built():
    """A tag whose changelog section lacks its Highlights or Status fails here, minutes before a build
    and long before any release exists."""
    gate = JOBS["gate"]
    notes = step_running(gate, "packaging/release_notes.py")
    assert notes["if"] == TAG_ONLY
    assert "--out" not in notes["run"] and '--version "${GITHUB_REF_NAME#v}"' in notes["run"]
    assert gate["steps"].index(notes) < gate["steps"].index(step_running(gate, "make gate"))
    assert JOBS["deb"]["needs"] == "gate"


def test_both_architectures_are_built_by_the_same_steps_with_the_tag_checked():
    deb = JOBS["deb"]
    assert deb["strategy"]["matrix"]["arch"] == ["arm64", "amd64"]
    assert "permissions" not in deb, "the build runs third-party code and gets only the top's read"
    build = step_running(deb, "packaging/build-deb.sh dist")
    assert build["env"]["TVGW_ARCH"] == "${{ matrix.arch }}"
    assert build["env"]["TVGW_TAG"] == "${{ github.ref_type == 'tag' && github.ref_name || '' }}"
    assert "sha256sum -c -" in runs(deb), "nfpm is checked against its pinned hash"
    assert re.fullmatch(r"[0-9a-f]{64}", deb["env"]["NFPM_SHA256"])
    upload = step_using(deb, "actions/upload-artifact")
    assert upload["with"]["name"] == "tvgw-deb-${{ matrix.arch }}"
    assert upload["with"]["if-no-files-found"] == "error"


@pytest.mark.parametrize(("arch", "runner"), [("arm64", "ubuntu-24.04-arm"), ("amd64", "ubuntu-latest")])
def test_each_package_is_installed_in_clean_debian_and_ubuntu_on_its_own_architecture(arch, runner):
    job = JOBS[f"install-check-{arch}"]
    assert job["runs-on"] == runner and job["needs"] == "deb"
    images = job["strategy"]["matrix"]["image"]
    assert [image.split("@")[0] for image in images] == ["debian:13", "ubuntu:24.04"]
    # the platform check's dummy ports and nft need NET_ADMIN, its dumpcap run NET_RAW
    assert job["container"] == {
        "image": "${{ matrix.image }}",
        "options": "--cap-add=NET_ADMIN --cap-add=NET_RAW",
    }
    assert step_using(job, "actions/download-artifact")["with"]["name"] == f"tvgw-deb-{arch}"
    # install-check.sh installs the package (check-platform.sh runs it first), then the platform check
    # reads the package's own files
    assert runs(job).strip() == f"sh packaging/check-platform.sh --package dist/tvgw_*-1_{arch}.deb"
    assert "permissions" not in job


def test_the_assets_are_written_and_attested_by_a_job_that_runs_no_build_code():
    job = JOBS["assets"]
    assert job["needs"] == "deb"
    assert job["permissions"] == {"contents": "read", "id-token": "write", "attestations": "write"}
    assert 'packaging/release-assets.sh "$V" dist' in runs(job)
    notes = step_running(job, "packaging/release_notes.py")
    assert notes["if"] == TAG_ONLY
    assert "--sums dist/SHA256SUMS --out dist/RELEASE_NOTES.md" in notes["run"]
    attest = step_using(job, "actions/attest")
    assert attest["if"] == TAG_ONLY
    assert attest["with"]["subject-path"].split() == ["dist/tvgw_*.deb", "dist/get.sh"]
    assert not re.search(r"\bpip\b|make |build-deb", runs(job)), "no third-party code where tokens are minted"
    assert step_using(job, "actions/upload-artifact")["with"]["name"] == "tvgw-release"


def test_the_release_is_published_from_a_tag_after_every_check_with_contents_write_alone():
    job = JOBS["publish"]
    assert job["if"] == TAG_ONLY
    assert set(job["needs"]) == {"assets", "install-check-arm64", "install-check-amd64"}
    assert job["permissions"] == {"contents": "write"}
    assert job["concurrency"] == {"group": "release-${{ github.ref }}", "cancel-in-progress": False}
    publish = step_running(job, "packaging/publish-release.sh")
    assert publish["run"] == 'packaging/publish-release.sh "$GITHUB_REF_NAME" dist'
    assert publish["env"] == {"GH_TOKEN": "${{ github.token }}", "GH_REPO": "${{ github.repository }}"}
    assert step_using(job, "actions/download-artifact")["with"]["name"] == "tvgw-release"


# what the site job's step is given as gh: it records its arguments, and exits as told with the reason a
# token without `actions: write` gets
FAKE_DISPATCH_GH = """#!/bin/sh
printf '%s\\n' "$*" >>"$GH_CALLS"
if [ "$GH_RC" != 0 ]; then
    echo 'could not create workflow dispatch event: HTTP 403: Resource not accessible by integration' >&2
fi
exit "$GH_RC"
"""


def run_site_step(tmp_path, gh_rc):
    """The site job's step under the runner's shell (`bash -e`), with gh stood in for: (exit status,
    what it printed, gh's arguments, one call a line)."""
    bash = shutil.which("bash")
    if not bash:
        pytest.skip("no bash")
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    (bin_dir / "gh").write_text(FAKE_DISPATCH_GH, encoding="utf-8")
    (bin_dir / "gh").chmod(0o755)
    calls = tmp_path / "calls"
    calls.write_text("", encoding="utf-8")
    (step,) = JOBS["site"]["steps"]
    env = {
        "PATH": f"{bin_dir}:{os.environ['PATH']}",
        "GH_CALLS": str(calls),
        "GH_RC": str(gh_rc),
        "GITHUB_REPOSITORY": "kywwilson11/tvgw",
        "GITHUB_REF_NAME": "v0.3.1",
    }
    out = subprocess.run(
        [bash, "--noprofile", "--norc", "-e", "-c", step["run"]],
        env=env,
        capture_output=True,
        text=True,
        timeout=60,
    )
    return out.returncode, out.stdout + out.stderr, calls.read_text(encoding="utf-8").splitlines()


def test_once_published_the_release_starts_the_site_with_actions_write_alone():
    """A release a job's token published starts no workflow, so pages.yml's `release` trigger never fires
    for one; a workflow_dispatch is the exception GitHub makes. The job that sends it runs on a tag only,
    after the publish, holds only what a dispatch needs, and runs no action and no checkout."""
    job = JOBS["site"]
    assert job["needs"] == "publish" and job["if"] == TAG_ONLY
    assert job["permissions"] == {"actions": "write"}
    (step,) = job["steps"]
    assert "uses" not in step
    assert step["env"] == {"GH_TOKEN": "${{ github.token }}", "GH_REPO": "${{ github.repository }}"}


@pytest.mark.parametrize(
    ("gh_rc", "said", "not_said"),
    [
        (0, "started docs-site (pages.yml) on main for v0.3.1", "::warning::"),
        (1, "::warning::the documentation site was not started for v0.3.1", "started docs-site"),
    ],
)
def test_the_site_step_never_fails_the_release_and_names_the_command_when_it_cannot_start(
    tmp_path, gh_rc, said, not_said
):
    rc, printed, calls = run_site_step(tmp_path, gh_rc)
    assert rc == 0, printed  # the release is published either way, so the run stays green
    assert calls == ["workflow run pages.yml --ref main"]
    assert said in printed and not_said not in printed
    if gh_rc:
        assert "Resource not accessible by integration" in printed  # gh's own reason stays in the log
        assert "Start it by hand: gh workflow run pages.yml --ref main --repo kywwilson11/tvgw" in printed


def test_every_job_that_writes_or_signs_says_so_on_the_job():
    granted = {name: job.get("permissions", {}) for name, job in JOBS.items()}
    writers = {name for name, perms in granted.items() if "write" in perms.values()}
    assert writers == {"assets", "publish", "site"}


def test_every_release_action_is_pinned_by_commit_with_its_version_named():
    uses = [line.strip() for line in RELEASE.read_text(encoding="utf-8").splitlines() if "uses:" in line]
    assert uses
    for line in uses:
        assert re.fullmatch(r"(?:- )?uses: [\w.-]+/[\w.-]+@[0-9a-f]{40} # v\d+\.\d+\.\d+", line), line
    checkouts = [
        s for job in JOBS.values() for s in job["steps"] if s.get("uses", "").startswith("actions/checkout@")
    ]
    assert checkouts and all(s["with"]["persist-credentials"] is False for s in checkouts)


def test_the_package_says_what_it_does_in_debians_shape():
    """Debian's control file: a synopsis under 80 characters with no full stop, then the long description,
    whose blank line nfpm writes as the paragraph separator."""
    lines = NFPM["description"].splitlines()
    synopsis, body = lines[0], lines[1:]
    assert len(synopsis) < 80 and not synopsis.endswith(".") and not synopsis.lower().startswith("tvgw")
    assert all(len(line) < 80 for line in body)
    assert "" in body, "two paragraphs"
    text = " ".join(line for line in body if line)
    assert (
        "Privacy gateway for a smart TV: blocks its tracking, keeps it off your home network, reports daily."
        in text
    )
    assert "AdGuard Home is not part of this package." in text
    assert "a Raspberry Pi and other 64-bit Debian-based computers" in text


# ---- the pull request's build (ci.yml's deb-build) -------------------------------------------------
CI = ROOT / ".github" / "workflows" / "ci.yml"
# the files of the checkout nfpm.yaml copies by name: the docs page, the copyright file and the notice
COPIED = [c["src"].removeprefix("./") for c in NFPM["contents"] if not c["src"].startswith("./build/")]


def deb_build():
    return yaml.safe_load(CI.read_text(encoding="utf-8"))["jobs"]["deb-build"]


def test_a_pull_request_builds_the_amd64_package_and_keeps_nothing():
    """The release job builds only for a tag, so a path nfpm.yaml copies that a change broke showed up
    at the next release. The pull request's build runs the same script for amd64 and uploads nothing."""
    job = deb_build()
    assert job["if"] == "github.event_name == 'pull_request'"
    assert job["runs-on"] == "ubuntu-latest"
    assert "permissions" not in job  # the workflow's contents: read, and nothing more
    assert "needs" not in job
    assert job["defaults"]["run"]["shell"] == "bash"  # -eo pipefail: a failing build fails the job
    steps = job["steps"]
    for step in steps:
        assert "upload" not in step.get("uses", ""), step
        assert not re.search(
            r"\bgh\s|github\.token|GITHUB_TOKEN", step.get("run", "") + str(step.get("env"))
        ), step
    (build,) = [s for s in steps if "packaging/build-deb.sh dist" in s.get("run", "")]
    assert build["env"] == {"TVGW_ARCH": "amd64"}  # no TVGW_TAG: there is no tag to check
    assert build["run"].startswith("packaging/build-deb.sh dist\n")
    after = steps[[s.get("id") for s in steps].index("touched") + 1 :]
    assert after and all(s["if"] == "steps.touched.outputs.build == 'yes'" for s in after)


def test_the_pull_request_build_takes_the_release_jobs_nfpm():
    release = yaml.safe_load(RELEASE.read_text(encoding="utf-8"))["jobs"]["deb"]
    job = deb_build()
    assert {k: job["env"][k] for k in ("NFPM_VERSION", "NFPM_SHA256")} == {
        k: release["env"][k] for k in ("NFPM_VERSION", "NFPM_SHA256")
    }

    def install(j):
        (step,) = [s for s in j["steps"] if "nfpm.tar.gz" in s.get("run", "")]
        return step["run"]

    assert install(job) == install(release)


def test_nfpm_copies_a_docs_page_from_the_checkout():
    """What the pull request's build watches beside the folders: if nfpm.yaml stopped copying any file
    of the checkout, the cases below would test nothing."""
    assert {"packaging/copyright", "NOTICE"} <= set(COPIED) and any(
        path.endswith(".md") for path in COPIED
    ), COPIED


@pytest.fixture()
def pr_repo(tmp_path, monkeypatch):
    """A throwaway repository with the paths the step tells apart, committed as the pull request's base;
    git's own configuration is kept out."""
    for key, value in {
        "GIT_CONFIG_GLOBAL": "/dev/null",
        "GIT_CONFIG_NOSYSTEM": "1",
        "GIT_AUTHOR_NAME": "test",
        "GIT_AUTHOR_EMAIL": "test@example.com",
        "GIT_COMMITTER_NAME": "test",
        "GIT_COMMITTER_EMAIL": "test@example.com",
    }.items():
        monkeypatch.setenv(key, value)
    repo = tmp_path / "repo"
    files = {
        "packaging/nfpm.yaml": (PKG / "nfpm.yaml").read_text(encoding="utf-8"),
        "pyproject.toml": '[project]\nname = "tvgw"\n',
        ".github/workflows/ci.yml": "name: ci\n",
        ".github/workflows/virtual.yml": "name: virtual\n",
        "src/tvgw/cli.py": "print('cli')\n",
        "deploy/install.sh": "#!/bin/bash\n",
        "README.md": "# tvgw\n",
        "docs/README.md": "# Documentation\n",
        **{path: f"{path}\n" for path in COPIED},
    }
    for rel, text in files.items():
        (repo / rel).parent.mkdir(parents=True, exist_ok=True)
        (repo / rel).write_text(text, encoding="utf-8")
    pr_git(repo, "init", "-q", "-b", "main")
    pr_git(repo, "add", "-A")
    pr_git(repo, "commit", "-q", "-m", "base")
    return repo


def pr_git(repo, *args):
    return subprocess.run(
        ["git", "-C", str(repo), *args], check=True, capture_output=True, text=True
    ).stdout.strip()


def run_touched(repo, base):
    """The step as the runner runs it, `bash --noprofile --norc -eo pipefail`, in the checkout:
    (exit status, what it printed, what it wrote to $GITHUB_OUTPUT)."""
    bash = shutil.which("bash")
    if not bash:
        pytest.skip("no bash")
    (step,) = [s for s in deb_build()["steps"] if s.get("id") == "touched"]
    output = repo.parent / "github_output"
    output.write_text("", encoding="utf-8")
    out = subprocess.run(
        [bash, "--noprofile", "--norc", "-eo", "pipefail", "-c", step["run"]],
        cwd=repo,
        env={**os.environ, "BASE": base, "GITHUB_OUTPUT": str(output)},
        capture_output=True,
        text=True,
        timeout=60,
    )
    return out.returncode, out.stdout + out.stderr, output.read_text(encoding="utf-8")


@pytest.mark.parametrize(
    ("change", "path", "build"),
    [
        ("edit", "src/tvgw/cli.py", "yes"),
        ("edit", "deploy/install.sh", "yes"),
        ("edit", "packaging/nfpm.yaml", "yes"),
        ("edit", "pyproject.toml", "yes"),
        ("edit", ".github/workflows/ci.yml", "yes"),  # the job checks a change to itself
        *[("edit", path, "yes") for path in COPIED],
        *[("move", path, "yes") for path in COPIED],  # moved away from the path nfpm.yaml names
        ("edit", "docs/README.md", "no"),  # a page the package does not carry
        ("edit", "README.md", "no"),
        ("edit", ".github/workflows/virtual.yml", "no"),
        ("none", None, "no"),
    ],
)
def test_the_package_is_built_when_the_pull_request_changes_what_it_is_built_from(
    pr_repo, change, path, build
):
    base = pr_git(pr_repo, "rev-parse", "HEAD")
    if change == "edit":
        with (pr_repo / path).open("a", encoding="utf-8") as f:
            f.write("changed\n")
        pr_git(pr_repo, "commit", "-q", "-am", "edit")
    elif change == "move":
        moved = Path(path).parent / "moved" / Path(path).name
        (pr_repo / moved).parent.mkdir(parents=True, exist_ok=True)
        pr_git(pr_repo, "mv", path, moved.as_posix())
        pr_git(pr_repo, "commit", "-q", "-m", "move")
    else:
        pr_git(pr_repo, "commit", "-q", "--allow-empty", "-m", "nothing")
    rc, printed, outputs = run_touched(pr_repo, base)
    assert rc == 0, printed
    assert outputs == f"build={build}\n"
    assert f"the package is built: {build}" in printed


def test_a_name_git_would_quote_still_builds_the_package(pr_repo):
    """git writes a name with a byte outside ASCII in quotes and octal escapes unless core.quotePath is
    off, and a quoted `"src/...` would match none of the step's patterns."""
    base = pr_git(pr_repo, "rev-parse", "HEAD")
    (pr_repo / "src" / "tvgw" / "caf\u00e9.py").write_text("print('x')\n", encoding="utf-8")
    pr_git(pr_repo, "add", "-A")
    pr_git(pr_repo, "commit", "-q", "-m", "a name outside ASCII")
    rc, printed, outputs = run_touched(pr_repo, base)
    assert rc == 0, printed
    assert outputs == "build=yes\n"


def test_a_base_commit_that_cannot_be_read_builds_the_package(pr_repo):
    rc, printed, outputs = run_touched(pr_repo, "0" * 40)
    assert rc == 0, printed
    assert outputs == "build=yes\n"
    assert "cannot be read here" in printed


# ---- (companies) the companies snapshot's own licence, beside tvgw's -----------------------------------
DATA_FILES = ("src/tvgw/data/companies.txt", "src/tvgw/data/adfirms.txt")


def test_the_package_names_both_licences_wherever_it_names_one():
    """src/tvgw/data/companies.txt is CC BY-SA 4.0 data in an MIT package: the wheel's metadata (a PEP 639
    expression, which the pinned setuptools reads) and the .deb name both licences, and the notice
    ships in both, so neither can lose the data's licence without this test failing."""
    pyproject = tomllib.loads((ROOT / "pyproject.toml").read_text(encoding="utf-8"))
    assert pyproject["project"]["license"] == "MIT AND CC-BY-SA-4.0"
    assert pyproject["project"]["license-files"] == [
        "LICENSE",
        "NOTICE",
    ]  # into the wheel's .dist-info/licenses
    assert "setuptools>=77" in pyproject["build-system"]["requires"][0]  # 77: PEP 639's two fields
    pinned = re.search(
        r"^setuptools==(\d+)\.", (PKG / "build-requirements.in").read_text(encoding="utf-8"), re.M
    )
    assert pinned and int(pinned.group(1)) >= 77  # the .deb's wheel is built with this one
    assert NFPM["license"] == "MIT AND CC-BY-SA-4.0"
    dst = {c["dst"]: c["src"] for c in NFPM["contents"]}
    assert dst["/usr/share/doc/tvgw/copyright"] == "./packaging/copyright"
    assert dst["/usr/share/doc/tvgw/NOTICE"] == "./NOTICE"
    citation = yaml.safe_load((ROOT / "CITATION.cff").read_text(encoding="utf-8"))
    # CFF reads a list of licences as a choice: tvgw is MIT, and the data is a reference under its own
    assert citation["license"] == "MIT" and citation["version"] == pyproject["project"]["version"]
    (data,) = [r for r in citation["references"] if r["title"] == "AdGuard Companies DB"]
    assert data["license"] == "CC-BY-SA-4.0" and all(path in data["notes"] for path in DATA_FILES)
    assert "CC BY-SA 4.0 ([notice](NOTICE))" in (ROOT / "README.md").read_text(encoding="utf-8")


def test_the_notice_names_the_data_file_its_licence_and_whose_it_is():
    notice = (ROOT / "NOTICE").read_text(encoding="utf-8")
    for needed in (
        *DATA_FILES,
        *(path.removeprefix("src/") + "\n" for path in DATA_FILES),  # each as the package installs it
        "MIT License",
        "Creative Commons",
        "CC BY-SA 4.0",
        "https://creativecommons.org/licenses/by-sa/4.0/",
        "AdGuard Companies DB by AdGuard",
        "https://github.com/AdguardTeam/companiesdb",
        "WhoTracks.Me by Ghostery",
        "No endorsement",
    ):
        assert needed in notice, needed


def test_the_debs_copyright_is_machine_readable_with_the_mit_text_and_a_files_entry_for_the_data():
    """Debian's copyright format: a stanza per set of files, and each licence's text after its name,
    each line indented one space and an empty line as " .". The MIT text is LICENSE's, word for word,
    and the companies snapshot has its own `Files:` stanza under CC-BY-SA-4.0."""
    text = (PKG / "copyright").read_text(encoding="utf-8")
    assert text.startswith("Format: https://www.debian.org/doc/packaging-manuals/copyright-format/1.0/\n")
    stanzas = [s for s in text.split("\n\n") if s.strip()]
    fields = [dict(re.findall(r"^([A-Z][\w-]*): ?(.*)$", s, re.M)) for s in stanzas]
    files = {f["Files"]: f["License"] for f in fields if "Files" in f}
    assert files == {"*": "MIT", " ".join(DATA_FILES): "CC-BY-SA-4.0"}
    (mit,) = [
        s for s, f in zip(stanzas, fields, strict=True) if "Files" not in f and f.get("License") == "MIT"
    ]
    body = [line[1:] for line in mit.splitlines()[1:]]
    assert "\n".join("" if line == "." else line for line in body) == (ROOT / "LICENSE").read_text(
        encoding="utf-8"
    ).rstrip("\n")
    (cc,) = [
        s
        for s, f in zip(stanzas, fields, strict=True)
        if "Files" not in f and f.get("License") == "CC-BY-SA-4.0"
    ]
    # the licence's own text, as Debian's format asks, not a link to it
    assert (
        "Attribution-ShareAlike 4.0 International Public License" in cc and "Section 1 -- Definitions." in cc
    )
    assert all((ROOT / path).is_file() for path in DATA_FILES)
