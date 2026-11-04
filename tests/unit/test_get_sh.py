"""The one-line installer, get.sh (docs/project/packaging.md#the-installer-getsh), run for real under sh.

`packaging/release-assets.sh` renders it from `packaging/get.sh.in` as the release job does, with the hashes
of two stand-in packages. Each test then runs it with `TVGW_ROOT` pointing at a fake system under tmp_path
and stubs first on PATH for every program it calls: curl copies files from a fake release folder, dpkg and
dpkg-query answer from the test's environment, and apt-get, debconf-set-selections, id, sha256sum and tvgw
record their calls. Nothing touches the network, the package database or the real /etc."""

import hashlib
import os
import re
import shutil
import stat
import subprocess
from pathlib import Path

import pytest
from conftest import ROOT

PKG = ROOT / "packaging"
TEMPLATE = PKG / "get.sh.in"
V = "9.8.7"
SHELLS = sorted({s for s in ("sh", "dash") if shutil.which(s)})
PRESEED = "wireshark-common wireshark-common/install-setuid boolean false"
OUR_POLICY_MARK = "# tvgw installer: no service starts while apt runs; removed when the installer ends"

OS_RELEASE = {
    "debian13": 'PRETTY_NAME="Debian GNU/Linux 13 (trixie)"\nID=debian\nVERSION_ID="13"\nVERSION="13 (trixie)"\n',
    "debian12": 'PRETTY_NAME="Debian GNU/Linux 12 (bookworm)"\nID=debian\nVERSION_ID="12"\n',
    "ubuntu2404": 'PRETTY_NAME="Ubuntu 24.04.3 LTS"\nID=ubuntu\nID_LIKE=debian\nVERSION_ID="24.04"\n',
    "ubuntu2604": 'PRETTY_NAME="Ubuntu 26.04 LTS"\nID=ubuntu\nID_LIKE=debian\nVERSION_ID="26.04"\n',
    "debian11": 'PRETTY_NAME="Debian GNU/Linux 11 (bullseye)"\nID=debian\nVERSION_ID="11"\n',
    "ubuntu2204": 'PRETTY_NAME="Ubuntu 22.04.5 LTS"\nID=ubuntu\nVERSION_ID="22.04"\n',
    "fedora": 'PRETTY_NAME="Fedora Linux 43 (Server Edition)"\nID=fedora\nVERSION_ID=43\n',
    # a hostile os-release cannot replace the installer's own names: it is read in a subshell
    "clobber": 'PRETTY_NAME="Debian GNU/Linux 13 (trixie)"\nID=debian\nVERSION_ID="13"\nWANT=0\nBASE=x\nTMP=/\n',
}

# Every program get.sh runs that would touch the system or the network. Each appends "name args" to
# $CALLS; the rest of the body is what it answers.
STUBS = {
    "id": '[ "$1" = -u ] && echo "${FAKE_UID:-0}"',
    "dpkg": '[ "$1" = --print-architecture ] && echo "${FAKE_ARCH:-arm64}"',
    # dpkg-query -W -f <format> <package>: the status from FAKE_STATUS_<package>, or no such package
    "dpkg-query": 'eval "s=\\${FAKE_STATUS_$4:-}"\n[ -n "$s" ] || exit 1\necho "$s"',
    "curl": (
        "out= url=\nwhile [ $# -gt 0 ]; do\n  case $1 in -o) out=$2; shift ;; *) url=$1 ;; esac\n  shift\ndone\n"
        'case " ${CURL_FAIL:-} " in *" ${url##*/} "*) exit 22 ;; esac\n'
        'cp "$CURL_FROM/${url##*/}" "$out" || exit 22'
    ),
    "debconf-set-selections": 'echo "debconf got: $(cat)" >>"$CALLS"',
    "apt-get": (
        'echo "apt says: $*"\n'
        'p="$TVGW_ROOT/usr/sbin/policy-rc.d"\n'
        'if [ -f "$p" ]; then echo "apt policy: $(stat_mode "$p") $(tr "\\n" "|" <"$p")" >>"$CALLS"; '
        'else echo "apt policy: none" >>"$CALLS"; fi\n'
        'case " $* " in *" install "*)\n'
        '  [ -z "${FAKE_APT_SIGNAL:-}" ] || kill -s "$FAKE_APT_SIGNAL" "$PPID"\n'
        '  echo "E: fake apt failure"; exit "${FAKE_APT_RC:-0}" ;;\nesac'
    ),
    "tvgw": (
        "case $1 in\n"
        '--version) echo "tvgw $FAKE_VERSION" ;;\n'
        "setup)\n"
        '  deb=$(sed -n "s/^apt-get .*install -y //p" "$CALLS" | tail -n 1)\n'
        '  [ -e "${deb%/*}" ] && echo "setup sees: the download folder" >>"$CALLS"\n'
        '  [ -e "$TVGW_ROOT/usr/sbin/policy-rc.d" ] && echo "setup sees: policy-rc.d" >>"$CALLS"\n'
        '  echo "setup stdin: $(cat)" >>"$CALLS" ;;\n'
        "esac"
    ),
    "sha256sum": 'exec python3 -I -c "$SHA256SUM_PY" "$@"',
}
SHA256SUM_PY = (
    "import hashlib, sys\n"
    "for name in sys.argv[1:]:\n"
    "    print(hashlib.sha256(open(name, 'rb').read()).hexdigest() + '  ' + name)\n"
)
# stat's flags differ between GNU and BSD; the stub reads the mode with Python instead
STAT_MODE = "stat_mode() { python3 -I -c 'import os, sys; print(oct(os.stat(sys.argv[1]).st_mode & 0o7777))' \"$1\"; }"


@pytest.fixture(scope="module")
def stub_bin(tmp_path_factory) -> Path:
    """The stubs, made once: each test's environment says where they log and what they answer."""
    bin_dir = tmp_path_factory.mktemp("bin")
    for name, body in STUBS.items():
        path = bin_dir / name
        path.write_text(f'#!/bin/sh\n{STAT_MODE}\necho "{name} $*" >>"$CALLS"\n{body}\n', encoding="utf-8")
        path.chmod(0o755)
    return bin_dir


class Box:
    """A fake computer and a fake release, with get.sh rendered for them."""

    def __init__(self, tmp_path: Path, stub_bin: Path):
        self.tmp = tmp_path
        self.root = tmp_path / "root"
        self.release = tmp_path / "release"
        self.bin = stub_bin
        self.calls = tmp_path / "calls"
        self.tmpdir = tmp_path / "tmp"
        for d in (self.root / "run/systemd/system", self.root / "usr/sbin", self.root / "etc", self.release):
            d.mkdir(parents=True)
        self.tmpdir.mkdir()
        self.os("debian13")
        self.adguard(True)
        (self.root / "dev").mkdir()
        (self.root / "dev/tty").write_text("the terminal\n", encoding="utf-8")
        for arch in ("arm64", "amd64"):
            (self.release / f"tvgw_{V}-1_{arch}.deb").write_bytes(
                f"a stand-in {arch} package\n".encode() * 64
            )
        out = subprocess.run(
            ["sh", str(PKG / "release-assets.sh"), V, str(self.release)],
            env=self.env(),
            capture_output=True,
            text=True,
            encoding="utf-8",
        )
        assert out.returncode == 0, out.stderr
        self.getsh = self.release / "get.sh"
        self.calls.unlink(missing_ok=True)  # the render's own sha256sum calls are not the installer's

    def os(self, name: str) -> None:
        (self.root / "etc/os-release").write_text(OS_RELEASE[name], encoding="utf-8")

    def adguard(self, installed: bool) -> None:
        """AdGuard Home's binary where the package's preinst looks for it, or nothing there."""
        exe = self.root / "opt/AdGuardHome/AdGuardHome"
        exe.parent.mkdir(parents=True, exist_ok=True)
        if installed:
            exe.write_text("#!/bin/sh\necho 'AdGuard Home, version v0.107.79'\n", encoding="utf-8")
            exe.chmod(0o755)
        else:
            exe.unlink(missing_ok=True)

    def env(self, **extra: str) -> dict[str, str]:
        env = {
            "PATH": f"{self.bin}{os.pathsep}{os.environ['PATH']}",
            "CALLS": str(self.calls),
            "CURL_FROM": str(self.release),
            "TVGW_ROOT": str(self.root),
            "TVGW_BASE": "https://example.invalid/release",
            "TMPDIR": str(self.tmpdir),
            "SHA256SUM_PY": SHA256SUM_PY,
            "FAKE_VERSION": V,
        }
        env.update(extra)
        return {k: v for k, v in env.items() if v is not None}

    def run(self, shell: str = "sh", script: str | None = None, **extra: str) -> subprocess.CompletedProcess:
        """Run get.sh as `curl ... | sudo sh` does: the script on the shell's standard input."""
        return subprocess.run(
            [shell],
            input=self.getsh.read_text(encoding="utf-8") if script is None else script,
            env=self.env(**extra),
            capture_output=True,
            text=True,
            encoding="utf-8",
        )

    def log(self) -> list[str]:
        return self.calls.read_text(encoding="utf-8").splitlines() if self.calls.exists() else []

    def ran(self, name: str) -> list[str]:
        return [line for line in self.log() if line.split(" ", 1)[0] == name]


@pytest.fixture
def box(tmp_path, stub_bin):
    return Box(tmp_path, stub_bin)


def sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


# ---- the happy path ------------------------------------------------------------------------------


@pytest.mark.parametrize("shell", SHELLS)
def test_debian_13_on_arm64_installs_the_checked_package_and_hands_over_to_setup(box, shell):
    out = box.run(shell)
    assert out.returncode == 0, out.stderr
    assert f"tvgw installer {V}" in out.stdout
    assert "Debian 13, arm64" in out.stdout
    assert f"SHA-256:       {sha256(box.release / f'tvgw_{V}-1_arm64.deb')}" in out.stdout
    assert "matches this installer and the release's SHA256SUMS" in out.stdout
    log = box.log()
    names = [line.split(" ", 1)[0] for line in log]
    # checked before anything is written, preseeded before apt, the lists read before the install
    assert names.index("curl") < names.index("debconf-set-selections") < names.index("apt-get")
    assert f"debconf got: {PRESEED}" in log
    lock = "apt-get -o DPkg::Lock::Timeout=300"
    confs = "-o Dpkg::Options::=--force-confdef -o Dpkg::Options::=--force-confold"
    update, install = box.ran("apt-get")
    assert update == f"{lock} update"
    assert re.fullmatch(
        rf"{re.escape(f'{lock} {confs} install -y {box.tmpdir}')}/tvgw-get\.\w+/tvgw_{V}-1_arm64\.deb",
        install,
    )
    assert "tvgw --version" in log
    assert "tvgw setup" in log
    assert "setup stdin: the terminal" in log  # setup reads the terminal, not the pipe the script came on
    assert "Starting setup." in out.stdout


@pytest.mark.parametrize(
    ("os_name", "arch", "says"),
    [
        ("debian12", "amd64", "Debian 12, amd64"),
        ("ubuntu2404", "amd64", "Ubuntu 24.04, amd64"),
        ("ubuntu2604", "arm64", "Ubuntu 26.04, arm64"),
        ("clobber", "amd64", "Debian 13, amd64"),
    ],
)
def test_each_supported_system_gets_the_package_for_its_architecture(box, os_name, arch, says):
    box.os(os_name)
    out = box.run(FAKE_ARCH=arch)
    assert out.returncode == 0, out.stderr
    assert says in out.stdout
    urls = [line.split()[-1] for line in box.ran("curl")]
    assert urls == [
        f"https://example.invalid/release/tvgw_{V}-1_{arch}.deb",
        "https://example.invalid/release/SHA256SUMS",
    ]
    assert box.ran("apt-get")[-1].endswith(f"/tvgw_{V}-1_{arch}.deb")


def test_raspberry_pi_os_is_named_and_the_board_is_read(box):
    (box.root / "etc/rpi-issue").write_text("Raspberry Pi reference 2026-10-01\n", encoding="utf-8")
    (box.root / "proc/device-tree").mkdir(parents=True)
    (box.root / "proc/device-tree/model").write_bytes(b"Raspberry Pi 5 Model B Rev 1.0\x00")
    out = box.run()
    assert out.returncode == 0, out.stderr
    assert "This computer: Raspberry Pi 5 Model B Rev 1.0, Raspberry Pi OS (Debian 13), arm64" in out.stdout


def test_a_pc_is_named_from_its_firmware_or_not_at_all(box):
    out = box.run(FAKE_ARCH="amd64")
    assert "This computer: this computer, Debian 13, amd64" in out.stdout
    (box.root / "sys/class/dmi/id").mkdir(parents=True)
    (box.root / "sys/class/dmi/id/product_name").write_text("Mini PC N100\n", encoding="utf-8")
    assert "This computer: Mini PC N100, Debian 13, amd64" in box.run(FAKE_ARCH="amd64").stdout


def test_without_a_test_base_it_downloads_from_this_versions_github_release_over_https_only(box):
    box.run(TVGW_BASE=None)
    curls = box.ran("curl")
    base = f"https://github.com/kywwilson11/tvgw/releases/download/v{V}"
    assert [c.split()[-1] for c in curls] == [f"{base}/tvgw_{V}-1_arm64.deb", f"{base}/SHA256SUMS"]
    for c in curls:
        assert "--proto =https,file --proto-redir =https --tlsv1.2 -fsSL --retry 3" in c


def test_the_installer_asks_nothing_and_ends_on_one_line_that_calls_main():
    text = TEMPLATE.read_text(encoding="utf-8")
    code = [line.split("#", 1)[0] for line in text.splitlines() if not line.lstrip().startswith("#")]
    assert not [line for line in code if " read " in f" {line} "], "get.sh asks nothing"
    assert text.endswith('\nmain "$@"\n')
    assert text.count('main "$@"') == 1


# ---- what stops it, before anything is written ---------------------------------------------------


def assert_stopped_before_anything(box, out, says):
    assert out.returncode == 1
    assert says in out.stderr, out.stderr
    assert not box.ran("apt-get") and not box.ran("debconf-set-selections") and not box.ran("tvgw")
    assert not (box.root / "run/tvgw/fresh-deps").exists()
    assert not (box.root / "usr/sbin/policy-rc.d").exists()
    assert list(box.tmpdir.iterdir()) == []


@pytest.mark.parametrize("arch", ["armhf", "armel", "i386"])
def test_a_32_bit_system_is_told_to_reflash_with_the_64_bit_one(box, arch):
    out = box.run(FAKE_ARCH=arch)
    assert_stopped_before_anything(box, out, "reflash with Raspberry Pi OS Lite (64-bit)")
    assert not box.ran("curl")


def test_an_architecture_without_a_package_stops(box):
    out = box.run(FAKE_ARCH="riscv64")
    assert_stopped_before_anything(box, out, "tvgw has no package for riscv64; it has arm64 and amd64")


@pytest.mark.parametrize(
    ("os_name", "pretty"),
    [
        ("debian11", "Debian GNU/Linux 11 (bullseye)"),
        ("ubuntu2204", "Ubuntu 22.04.5 LTS"),
        ("fedora", "Fedora Linux 43 (Server Edition)"),
    ],
)
def test_an_unsupported_system_stops_and_names_the_supported_ones(box, os_name, pretty):
    box.os(os_name)
    out = box.run()
    assert_stopped_before_anything(
        box,
        out,
        f"{pretty} is not supported: tvgw installs on Raspberry Pi OS (64-bit), Debian 12 or 13, "
        "and Ubuntu 24.04 or 26.04",
    )
    assert not box.ran("curl")


def test_a_system_with_no_os_release_stops(box):
    (box.root / "etc/os-release").unlink()
    assert_stopped_before_anything(box, box.run(), "cannot tell which system this is")


@pytest.mark.parametrize(
    "text",
    [
        'ID=debian\nVERSION_ID="13"\nif\n',  # not shell: the subshell that reads it fails
        'ID=debian\nVERSION_ID="13"\nNAME=$UNSET_BY_ANYONE\n',  # an unset name, under set -u
    ],
)
def test_an_os_release_that_cannot_be_read_stops_with_a_reason(box, text):
    (box.root / "etc/os-release").write_text(text, encoding="utf-8")
    out = box.run()
    assert_stopped_before_anything(
        box, out, "cannot tell which system this is: /etc/os-release could not be read"
    )
    assert not box.ran("curl")


def test_without_root_it_stops_and_says_to_use_sudo(box):
    out = box.run(FAKE_UID="1000")
    assert_stopped_before_anything(box, out, "run it as root: put sudo before sh")
    assert [line.split(" ", 1)[0] for line in box.log()] == ["id"]


def test_without_systemd_it_stops(box):
    (box.root / "run/systemd/system").rmdir()
    out = box.run()
    assert_stopped_before_anything(box, out, "does not run systemd")


def test_without_adguard_home_it_stops_before_downloading_and_says_what_to_install(box):
    """The package's preinst refuses a computer without AdGuard Home (design decision 25). apt would say so
    last, after the download, under its own output; the installer says it first, with the way forward."""
    box.adguard(False)
    out = box.run()
    assert_stopped_before_anything(box, out, "AdGuard Home is not installed")
    assert "finish its first-run page" in out.stderr and "scripts/install.sh | sh -s -- -v" in out.stderr
    assert not box.ran("curl")


def test_a_source_install_is_left_to_its_checkout(box):
    (box.root / "usr/local/bin").mkdir(parents=True)
    (box.root / "usr/local/bin/tvgw").symlink_to("/opt/tvgw-venv/bin/tvgw")
    out = box.run()
    assert_stopped_before_anything(box, out, "tvgw is installed here from a source checkout")
    assert "git pull, then sudo ./install.sh" in out.stderr
    assert not box.ran("curl")


@pytest.mark.parametrize("status", ["installed", "half-configured"])
def test_a_package_install_is_upgraded(box, status):
    (box.root / "usr/local/bin").mkdir(parents=True)
    (box.root / "usr/local/bin/tvgw").symlink_to("/opt/tvgw-venv/bin/tvgw")
    out = box.run(FAKE_STATUS_tvgw=status, TVGW_NO_SETUP="1")
    assert out.returncode == 0, out.stderr
    assert box.ran("apt-get")


def test_a_tampered_package_stops_with_nothing_installed(box):
    deb = box.release / f"tvgw_{V}-1_arm64.deb"
    data = bytearray(deb.read_bytes())
    data[100] ^= 0x01  # one bit of one byte
    deb.write_bytes(bytes(data))
    out = box.run()
    assert_stopped_before_anything(
        box, out, "the downloaded package does not match this installer's hash; nothing was installed"
    )


def test_a_package_whose_hash_is_missing_from_sha256sums_stops(box):
    sums = box.release / "SHA256SUMS"
    sums.write_text(
        "".join(line for line in sums.read_text(encoding="utf-8").splitlines(True) if "arm64" not in line),
        encoding="utf-8",
    )
    out = box.run()
    assert_stopped_before_anything(box, out, "the package's hash is not in the release's SHA256SUMS")


@pytest.mark.parametrize("missing", [f"tvgw_{V}-1_arm64.deb", "SHA256SUMS"])
def test_a_download_that_fails_stops(box, missing):
    out = box.run(CURL_FAIL=missing)
    assert_stopped_before_anything(box, out, f"could not download https://example.invalid/release/{missing}")


@pytest.mark.parametrize("shell", SHELLS)
def test_a_download_cut_short_anywhere_before_its_last_line_runs_nothing(box, shell):
    """`curl | sh` runs what has arrived. Every line but the last only defines: a script cut at a line
    or in the middle of one either ends before `main "$@"` or is a syntax error. (Cut after `main` itself,
    every definition has arrived, and it runs as the whole script would.)"""
    lines = box.getsh.read_text(encoding="utf-8").splitlines(True)
    assert lines[-1] == 'main "$@"\n'
    cuts = ["".join(lines[:n]) for n in range(len(lines))]
    cuts += ["".join(lines[:n]) + lines[n][: len(lines[n]) // 2] for n in range(len(lines) - 1)]
    cuts += ["".join(lines[:-1]) + "main"[:n] for n in range(1, 4)]
    for cut in cuts:
        box.run(shell, script=cut)
        assert box.log() == [], f"ran with the script cut after {len(cut)} bytes"


# ---- the install itself --------------------------------------------------------------------------


def test_both_apt_calls_wait_five_minutes_for_the_lock(box):
    """A first boot's unattended-upgrades or PackageKit can hold the lock for minutes; and an install
    over an existing system keeps the administrator's version of a changed config file, without asking."""
    box.run()
    apt = box.ran("apt-get")
    assert len(apt) == 2
    for call in apt:
        assert call.startswith("apt-get -o DPkg::Lock::Timeout=300 ")
    assert "-o Dpkg::Options::=--force-confdef -o Dpkg::Options::=--force-confold install" in apt[1]


def test_policy_rc_d_holds_the_services_while_apt_installs_and_is_gone_after(box):
    out = box.run(TVGW_NO_SETUP="1")
    assert out.returncode == 0, out.stderr
    log = box.log()
    during_update, during_install = (line for line in log if line.startswith("apt policy:"))
    assert during_update == "apt policy: none"  # the lists are read before it exists
    assert during_install == f"apt policy: 0o755 #!/bin/sh|{OUR_POLICY_MARK}|exit 101|"
    assert not (box.root / "usr/sbin/policy-rc.d").exists()


def test_policy_rc_d_is_gone_when_apt_fails_too_and_apt_says_why(box):
    out = box.run(FAKE_APT_RC="100")
    assert out.returncode == 1
    assert "E: fake apt failure" in out.stderr
    assert "apt could not install the package; the lines above say why" in out.stderr
    assert "apt policy: 0o755" in "\n".join(box.log())
    assert not (box.root / "usr/sbin/policy-rc.d").exists()
    assert list(box.tmpdir.iterdir()) == []
    assert not box.ran("tvgw")


def test_an_existing_policy_rc_d_is_the_administrators_and_is_kept(box):
    theirs = box.root / "usr/sbin/policy-rc.d"
    theirs.write_text("#!/bin/sh\n# the image builder's\nexit 101\n", encoding="utf-8")
    theirs.chmod(0o755)
    box.run(TVGW_NO_SETUP="1")
    assert theirs.read_text(encoding="utf-8") == "#!/bin/sh\n# the image builder's\nexit 101\n"
    assert "apt policy: 0o755 #!/bin/sh|# the image builder's|exit 101|" in box.log()


def test_a_policy_rc_d_that_links_to_nothing_is_kept_and_not_written_through(box):
    link = box.root / "usr/sbin/policy-rc.d"
    target = box.tmp / "nowhere" / "policy"
    link.symlink_to(target)
    out = box.run(TVGW_NO_SETUP="1")
    assert out.returncode == 0, out.stderr
    assert link.is_symlink() and os.readlink(link) == str(target)
    assert not target.exists() and not target.parent.exists()


@pytest.mark.parametrize("shell", SHELLS)
@pytest.mark.parametrize(("signal", "status"), [("TERM", 143), ("INT", 130), ("HUP", 129)])
def test_an_install_interrupted_by_a_signal_leaves_no_policy_rc_d_and_no_download(box, shell, signal, status):
    """The trap the design asks for: a Ctrl-C, a closed terminal or a kill while apt runs ends the
    script, and the exit trap still removes its policy-rc.d and its download folder."""
    out = box.run(shell, FAKE_APT_SIGNAL=signal)
    assert out.returncode == status, out.stderr
    assert "apt policy: 0o755" in "\n".join(box.log())  # it was there while apt ran
    assert not (box.root / "usr/sbin/policy-rc.d").exists()
    assert list(box.tmpdir.iterdir()) == []
    assert not box.ran("tvgw")


def test_a_policy_rc_d_a_killed_run_left_behind_is_removed(box):
    left = box.root / "usr/sbin/policy-rc.d"
    left.write_text(f"#!/bin/sh\n{OUR_POLICY_MARK}\nexit 101\n", encoding="utf-8")
    box.run(TVGW_NO_SETUP="1")
    assert not left.exists()


@pytest.mark.parametrize(
    ("statuses", "fresh"),
    [
        ({}, "nginx\ndnsmasq\n"),
        ({"FAKE_STATUS_nginx": "installed"}, "dnsmasq\n"),
        ({"FAKE_STATUS_dnsmasq": "installed", "FAKE_STATUS_nginx": "config-files"}, "nginx\n"),
        ({"FAKE_STATUS_nginx": "installed", "FAKE_STATUS_dnsmasq": "installed"}, ""),
    ],
)
def test_fresh_deps_lists_the_services_apt_installs_new(box, statuses, fresh):
    box.run(TVGW_NO_SETUP="1", **statuses)
    path = box.root / "run/tvgw/fresh-deps"
    assert path.read_text(encoding="utf-8") == fresh
    assert stat.S_IMODE(path.parent.stat().st_mode) == 0o755
    assert not (box.root / "run/tvgw/fresh-deps.new").exists()


def test_the_download_folder_and_policy_rc_d_are_gone_before_setup_starts(box):
    out = box.run()
    assert out.returncode == 0, out.stderr
    assert "tvgw setup" in box.log()
    assert not [line for line in box.log() if line.startswith("setup sees:")]
    assert list(box.tmpdir.iterdir()) == []


def test_with_tvgw_no_setup_it_installs_and_prints_the_next_step(box):
    out = box.run(TVGW_NO_SETUP="1")
    assert out.returncode == 0, out.stderr
    assert "Next, with the TV nearby, run: sudo tvgw setup" in out.stdout
    assert "tvgw setup" not in box.log()
    assert list(box.tmpdir.iterdir()) == []


def test_without_a_terminal_it_installs_and_prints_the_next_step(box):
    (box.root / "dev/tty").unlink()
    out = box.run()
    assert out.returncode == 0, out.stderr
    assert (
        "There is no terminal to run setup on. Next, with the TV nearby, run: sudo tvgw setup" in out.stdout
    )
    assert "tvgw setup" not in box.log()


def test_without_curl_it_stops_and_says_to_install_it_not_to_check_the_network(box):
    no_curl = box.tmp / "bin-no-curl"
    no_curl.mkdir()
    for stub in box.bin.iterdir():
        if stub.name != "curl":
            (no_curl / stub.name).symlink_to(stub)
    for tool in (
        "sh",
        "cat",
        "cut",
        "grep",
        "tr",
        "mktemp",
        "rm",
        "mv",
        "chmod",
        "install",
        "head",
        "python3",
    ):
        if (found := shutil.which(tool)) and not (no_curl / tool).exists():
            (no_curl / tool).symlink_to(found)
    out = box.run(PATH=str(no_curl))
    assert_stopped_before_anything(
        box, out, "downloads with curl, which is missing: sudo apt-get install curl"
    )
    assert "internet connection" not in out.stderr


def test_a_package_that_left_no_tvgw_command_says_how_to_finish(box):
    no_tvgw = box.tmp / "bin-no-tvgw"
    no_tvgw.mkdir()
    for stub in box.bin.iterdir():
        if stub.name != "tvgw":
            (no_tvgw / stub.name).symlink_to(stub)
    out = box.run(PATH=f"{no_tvgw}{os.pathsep}/usr/bin{os.pathsep}/bin")
    assert out.returncode == 1
    assert "the tvgw command is missing; run: sudo dpkg --configure -a" in out.stderr


@pytest.mark.skipif(shutil.which("shellcheck") is None, reason="shellcheck is not installed")
def test_the_rendered_installer_passes_shellcheck(box):
    out = subprocess.run(
        ["shellcheck", "-s", "sh", str(box.getsh)], capture_output=True, text=True, encoding="utf-8"
    )
    assert out.returncode == 0, out.stdout
