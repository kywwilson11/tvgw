"""The platform check, packaging/check-platform.sh (docs/project/packaging.md#the-platform-check), run for real under sh.

The check installs packages and writes system files, so here it runs with TVGW_ROOT pointing at a fake
system under tmp_path, from a copy of the checkout's packaging/ and deploy/ trees, with a PATH that holds
stubs for every program that would touch the system and links to the few ordinary tools it needs (sed,
awk, cp and the like), so no real apt, nft or nginx is ever reached. The stubs record their calls and
answer from the test's environment. What runs for real is the check's own logic: which Depends go to
apt, the conf of each `tvgw-apply --check`, the ring file's name, both forms of nginx's stream include,
the three DHCP files, which of systemd-analyze's findings fail on which distribution, and that every
check runs before the verdict. distro.yml and release.yml run the script in containers."""

import hashlib
import os
import re
import shutil
import subprocess
import sys
from pathlib import Path

import pytest
import yaml
from conftest import ROOT

sys.path.insert(0, str(ROOT / "tests" / "virtual"))
import vnet  # the switches' values, read from tvgw-apply's own case arms

PKG = ROOT / "packaging"
SCRIPT = PKG / "check-platform.sh"
TEXT = SCRIPT.read_text(encoding="utf-8")
INSTALL_SH = (ROOT / "deploy" / "install.sh").read_text(encoding="utf-8")
SHELLS = sorted({s for s in ("sh", "dash") if shutil.which(s)})
PRESEED = "wireshark-common wireshark-common/install-setuid boolean false"
# the ordinary tools the script and the stubs run, linked into the test's PATH from where they are
TOOLS = (
    "sh", "dash", "awk", "cat", "chmod", "cmp", "cp", "cut", "dirname", "grep", "head", "install", "ln", "ls",
    "mkdir", "mktemp", "paste", "python3", "rm", "sed", "sort", "tail", "tr", "uname", "wc",
)  # fmt: skip
OS_RELEASE = {
    "debian-12": 'PRETTY_NAME="Debian GNU/Linux 12 (bookworm)"\nID=debian\nVERSION_ID="12"\n',
    "debian-13": 'PRETTY_NAME="Debian GNU/Linux 13 (trixie)"\nID=debian\nVERSION_ID="13"\n',
    "ubuntu-26.04": 'PRETTY_NAME="Ubuntu 26.04 LTS"\nID=ubuntu\nID_LIKE=debian\nVERSION_ID="26.04"\n',
}
RESTART_STEPS = (
    "/etc/systemd/system/tvgw-dnsgate.service:31: Unknown key 'RestartSteps' in section [Service], ignoring.\n"
    "/etc/systemd/system/tvgw-dnsgate.service:32: Unknown key 'RestartMaxDelaySec' in section [Service], "
    "ignoring."
)

# Every program the check runs that would touch the system. Each appends "name args" to $CALLS; the rest
# of the body is what it answers.
STUBS = {
    "id": 'if [ "$1" = -u ] && [ $# -eq 1 ]; then echo "${FAKE_UID:-0}"; else exit "${FAKE_ID_USER_RC:-1}"; fi',
    "dpkg": '[ "$1" = --print-architecture ] && echo "${FAKE_ARCH:-amd64}"',
    "apt-get": (
        'p="$TVGW_ROOT/usr/sbin/policy-rc.d"\n'
        'if [ -f "$p" ]; then echo "apt policy: $(tr "\\n" "|" <"$p")" >>"$CALLS"; '
        'else echo "apt policy: none" >>"$CALLS"; fi\n'
        'case " $* " in *" ${FAKE_APT_FAIL:-no-such-word} "*) echo "E: Unable to satisfy dependencies" >&2; exit 100 ;; esac'
    ),
    "debconf-set-selections": 'echo "debconf got: $(cat)" >>"$CALLS"',
    "useradd": 'exit "${FAKE_USERADD_RC:-0}"',
    "chown": ":",
    "getent": 'exit "${FAKE_GETENT_RC:-2}"',
    "runuser": (
        'case "$*" in\n*"test -x /usr/bin/dumpcap"*) exit "${FAKE_DUMPCAP_X_RC:-0}" ;;\n'
        '*) exit "${FAKE_SUITE_RC:-0}" ;;\nesac'
    ),
    "ip": 'case "$1 $2" in "link show") exit 1 ;; "link add") exit "${FAKE_IP_RC:-0}" ;;'
    ' "addr replace") exit "${FAKE_IP_ADDR_RC:-0}" ;; esac',
    # `list tables`: the container's own tables, and tvgw's once an apply has left it loaded
    "nft": (
        'case $1 in --version) echo "nftables v1.1.3" ;;\n'
        'list) printf "%s" "${FAKE_TABLES:-}"; [ ! -e "$TVGW_ROOT/left-loaded" ] || echo "table inet tvgw" ;; esac'
    ),
    # tvgw-apply --check: the conf it would read is the one the check wrote under the fake root
    "bash": (
        'conf="$TVGW_ROOT/etc/tvgw/tvgw.conf"\n'
        '[ -z "${FAKE_APPLY_LEAVES:-}" ] || : >"$TVGW_ROOT/left-loaded"\n'
        'if [ -n "${FAKE_APPLY_REFUSE:-}" ] && grep -qx "$FAKE_APPLY_REFUSE" "$conf"; then\n'
        '  echo "Error: syntax error, unexpected junk" >&2; exit 1\nfi\n'
        'printf "table inet tvgw\\nadd chain inet tvgw input\\n"'
    ),
    "dumpcap": (
        'case $1 in --version) echo "Dumpcap (Wireshark) 4.4.19."; exit 0 ;; esac\n'
        'w=\nwhile [ $# -gt 0 ]; do [ "$1" = -w ] && w=$2; shift; done\n'
        '[ -z "${FAKE_DUMPCAP_RC:-}" ] || exit "$FAKE_DUMPCAP_RC"\n'
        'for n in ${FAKE_PCAP_NAMES-tv_20261103120000_00001.pcap}; do : >"${w%/*}/$n"; done'
    ),
    "nginx": (
        'case $1 in -v) echo "nginx version: nginx/1.26.3" >&2; exit 0 ;; esac\n'
        'etc="$TVGW_ROOT/etc/nginx"\n'
        'grep -qx "include /etc/nginx/tvgw/stream.conf;" "$etc/nginx.conf" && echo "nginx form: appended" >>"$CALLS"\n'
        'm="$etc/modules-enabled/99-tvgw-stream.conf"\n'
        '[ ! -f "$m" ] || echo "nginx form: modules-enabled $(cat "$m")" >>"$CALLS"\n'
        'exit "${FAKE_NGINX_RC:-0}"'
    ),
    "dnsmasq": (
        'case $1 in --version) echo "Dnsmasq version 2.91  Copyright (c) 2000-2025 Simon Kelley"; exit 0 ;; esac\n'
        "f=${2#--conf-file=}\n"
        'if [ -n "${FAKE_DNSMASQ_REFUSE:-}" ] && grep -q "$FAKE_DNSMASQ_REFUSE" "$f"; then\n'
        '  echo "dnsmasq: bad option at line 3 of $f" >&2; exit 1\nfi\n'
        'echo "dnsmasq: syntax check OK."'
    ),
    "systemd-analyze": '[ -z "${FAKE_VERIFY_OUT:-}" ] || printf "%s\\n" "$FAKE_VERIFY_OUT" >&2\nexit "${FAKE_VERIFY_RC:-0}"',
    "systemctl": 'echo "systemd 257 (257.13-1~deb13u1)"',
    "conntrack": 'echo "conntrack v1.4.8 (conntrack-tools)"',
    # as root tshark warns on stderr first; the version is its first line on stdout
    "tshark": 'echo "Running as user \\"root\\" and group \\"root\\". This could be dangerous." >&2\n'
    'echo "TShark (Wireshark) 4.4.19."',
    "NetworkManager": 'echo "1.52.1"',
    "curl": (
        "out= url=\nwhile [ $# -gt 0 ]; do\n  case $1 in -o) out=$2; shift ;; *) url=$1 ;; esac\n  shift\ndone\n"
        'cp "$CURL_FROM/${url##*/}" "$out" || exit 22'
    ),
    "sha256sum": 'exec python3 -I -c "$SHA256SUM_PY" "$@"',
}
SHA256SUM_PY = (
    "import hashlib, sys\n"
    "for name in sys.argv[1:]:\n"
    "    print(hashlib.sha256(open(name, 'rb').read()).hexdigest() + '  ' + name)\n"
)
# packaging/install-check.sh, which installs the package; here it says what it was given and leaves the
# virtualenv's tvgw where the real one would
INSTALL_CHECK = (
    '#!/bin/sh\necho "install-check $* venv=$TVGW_CHECK_VENV" >>"$CALLS"\n'
    'mkdir -p "$TVGW_CHECK_VENV/bin" && : >"$TVGW_CHECK_VENV/bin/tvgw"\nexit "${FAKE_INSTALL_CHECK_RC:-0}"\n'
)


def make_bin(path: Path, names) -> Path:
    """The stubs `names` and, beside them, links to the ordinary tools. Made once per module: macOS checks a
    program the first time it runs, about half a second each, which a fresh set per test would pay again."""
    path.mkdir()
    for name in names:
        script = path / name
        script.write_text(f'#!/bin/sh\necho "{name} $*" >>"$CALLS"\n{STUBS[name]}\n', encoding="utf-8")
        script.chmod(0o755)
    return path


@pytest.fixture(scope="module")
def stub_bin(tmp_path_factory) -> Path:
    """Every stub but NetworkManager's, which nm_bin holds, so a test can leave a program out of PATH; and
    links to the ordinary tools, so no other program on this computer is found."""
    path = make_bin(tmp_path_factory.mktemp("stubs") / "bin", [n for n in STUBS if n != "NetworkManager"])
    for tool in TOOLS:
        found = shutil.which(tool)
        if found is None and tool != "dash":
            pytest.skip(f"{tool} is not installed here")
        if found is not None:
            (path / tool).symlink_to(found)
    return path


@pytest.fixture(scope="module")
def nm_bin(tmp_path_factory) -> Path:
    return make_bin(tmp_path_factory.mktemp("nm") / "bin", ["NetworkManager"])


class Box:
    """A fake container, and a copy of the checkout's trees the check reads."""

    def __init__(self, tmp_path: Path, bins: tuple[Path, ...]):
        self.tmp = tmp_path
        self.root = tmp_path / "root"
        self.src = tmp_path / "src"
        self.bins = bins
        self.bin = bins[0]
        self.calls = tmp_path / "calls"
        self.release = tmp_path / "release"
        self.out = self.root / "tmp" / "tvgw-platform"
        for d in (self.root / "etc", self.release, self.tmp / "tmpdir"):
            d.mkdir(parents=True)
        (self.root / ".dockerenv").write_text("", encoding="utf-8")
        self.os("debian-13")
        nginx = self.root / "etc/nginx"
        for d in ("conf.d", "sites-enabled", "modules-enabled"):
            (nginx / d).mkdir(parents=True)
        self.shipped = "user www-data;\ninclude /etc/nginx/modules-enabled/*.conf;\nevents {}\nhttp {}\n"
        (nginx / "nginx.conf").write_text(self.shipped, encoding="utf-8")
        (nginx / "modules-enabled/50-mod-stream.conf").write_text("load_module stream;\n", encoding="utf-8")
        (nginx / "sites-enabled/default").write_text("server {}\n", encoding="utf-8")
        # the checkout: the trees the check reads, and a stand-in for the script that installs a package
        (self.src / "packaging").mkdir(parents=True)
        shutil.copy2(SCRIPT, self.src / "packaging" / "check-platform.sh")
        shutil.copy2(PKG / "nfpm.yaml", self.src / "packaging" / "nfpm.yaml")
        (self.src / "packaging" / "install-check.sh").write_text(INSTALL_CHECK, encoding="utf-8")
        shutil.copytree(ROOT / "deploy", self.src / "deploy")

    def os(self, name: str) -> None:
        (self.root / "etc/os-release").write_text(OS_RELEASE[name], encoding="utf-8")

    def env(self, **extra: str) -> dict[str, str]:
        env = {
            "PATH": os.pathsep.join(str(b) for b in self.bins),
            "CALLS": str(self.calls),
            "CURL_FROM": str(self.release),
            "TVGW_ROOT": str(self.root),
            "TVGW_RELEASE_BASE": "https://example.invalid/releases/download",
            "TMPDIR": str(self.tmp / "tmpdir"),
            "SHA256SUM_PY": SHA256SUM_PY,
        }
        env.update(extra)
        return {k: v for k, v in env.items() if v is not None}

    def run(self, *args: str, shell: str = "sh", **extra: str) -> subprocess.CompletedProcess:
        return subprocess.run(
            [str(self.bin / shell), str(self.src / "packaging" / "check-platform.sh"), *args],
            env=self.env(**extra),
            capture_output=True,
            text=True,
            encoding="utf-8",
        )

    def log(self) -> list[str]:
        return self.calls.read_text(encoding="utf-8").splitlines() if self.calls.exists() else []

    def ran(self, name: str) -> list[str]:
        return [line for line in self.log() if line.split(" ", 1)[0] == name]

    def deb(self, version: str = "9.8.7", arch: str = "amd64") -> Path:
        path = self.release / f"tvgw_{version}-1_{arch}.deb"
        path.write_bytes(b"a stand-in package\n" * 64)
        digest = hashlib.sha256(path.read_bytes()).hexdigest()
        (self.release / "SHA256SUMS").write_text(f"{digest}  {path.name}\n", encoding="utf-8")
        return path


@pytest.fixture
def box(tmp_path, stub_bin, nm_bin):
    return Box(tmp_path, (stub_bin, nm_bin))


def depends() -> list[str]:
    return yaml.safe_load((PKG / "nfpm.yaml").read_text(encoding="utf-8"))["depends"]


def effective(conf: str) -> dict[str, str]:
    """The settings a sourced conf ends with: the last assignment of each key wins, as in the shell."""
    values = {}
    for line in conf.splitlines():
        m = re.match(r"([A-Z_][A-Z0-9_]*)=(\S*)", line.split("#", 1)[0].strip())
        if m:
            values[m.group(1)] = m.group(2).strip('"')
    return values


# ---- what it installs and reads ----------------------------------------------------------------------


def test_the_depends_it_installs_are_the_packages_own():
    out = subprocess.run(
        ["sh", str(SCRIPT), "--list-depends"], capture_output=True, text=True, encoding="utf-8"
    )
    assert out.returncode == 0, out.stderr
    assert out.stdout.splitlines() == depends()
    assert "python3 (>= 3.11)" in out.stdout and "wireshark-common" in out.stdout.splitlines()


@pytest.mark.parametrize("shell", SHELLS)
def test_a_source_run_installs_the_depends_with_no_service_started_then_runs_every_check(box, shell):
    out = box.run("--source", shell=shell)
    assert out.returncode == 0, out.stderr
    assert "Debian GNU/Linux 13 (trixie), amd64: every check passed" in out.stdout
    assert (box.out / "result.txt").read_text(encoding="utf-8") == "ok\n"
    log = box.log()
    names = [line.split(" ", 1)[0] for line in log]
    assert names.index("debconf-set-selections") < names.index("apt-get")
    assert f"debconf got: {PRESEED}" in log
    lock = "apt-get -o DPkg::Lock::Timeout=300 -q"
    assert box.ran("apt-get") == [f"{lock} update", f"{lock} satisfy -y {', '.join(depends())}"]
    # every apt call ran with the check's own policy-rc.d in place, and it is gone afterwards
    policies = [line for line in log if line.startswith("apt policy:")]
    assert len(policies) == 2 and all("exit 101" in p and "tvgw platform check" in p for p in policies)
    assert not (box.root / "usr/sbin/policy-rc.d").exists()
    # the unit suite, as the unprivileged user, on a copy of the checkout
    tail = box.calls.read_text(encoding="utf-8").split("runuser -u tvgwci -- ", 1)[1]
    suite = tail[
        : tail.index(f" sh {box.root}/home/tvgwci/src\n")
    ]  # the call spans lines: its script has some
    assert suite.startswith(f"env HOME={box.root}/home/tvgwci sh -c ")
    assert 'python -m pip install -q --no-warn-script-location -e ".[dev]"' in suite
    assert suite.endswith("python -m pytest -p no:cacheprovider")
    assert (box.root / "home/tvgwci/src/packaging/check-platform.sh").exists()
    for check in (
        "tvgw-apply --check, default settings",
        "dumpcap",
        "nginx -t",
        "dnsmasq --test",
        "systemd-analyze",
    ):
        assert f"check-platform: ok: {check}" in out.stdout, check


@pytest.mark.parametrize("mode", ["--source", "--package"])
def test_when_the_programs_cannot_be_installed_nothing_is_checked(box, mode):
    if mode == "--source":
        out = box.run(mode, FAKE_APT_FAIL="satisfy")
        says = "apt could not install the package's Depends on Debian GNU/Linux 13 (trixie) (above)"
    else:
        shutil.copytree(ROOT / "deploy", box.root / "usr/lib/tvgw/deploy")
        out = box.run(mode, str(box.deb()), FAKE_INSTALL_CHECK_RC="1")
        says = "packaging/install-check.sh could not install"
    assert out.returncode == 1 and says in out.stderr, out.stderr
    assert (box.out / "result.txt").read_text(encoding="utf-8") == "fail: install\n"
    assert not box.ran("bash") and not box.ran("nginx") and not box.ran("systemd-analyze")
    assert not (box.root / "usr/sbin/policy-rc.d").exists()  # removed on the way out


def test_a_release_whose_downloader_cannot_be_installed_is_never_fetched(box):
    package_tree(box)
    box.deb("9.8.7", "amd64")
    out = box.run("--package", "v9.8.7", FAKE_APT_FAIL="curl")
    assert out.returncode == 1
    assert "apt could not install curl, which downloads the release (above)" in out.stderr
    assert (box.out / "result.txt").read_text(encoding="utf-8") == "fail: install\n"
    assert not box.ran("curl") and not box.ran("install-check") and not box.ran("bash")


def test_package_lists_apt_cannot_read_stop_the_check(box):
    out = box.run("--source", FAKE_APT_FAIL="update")
    assert out.returncode == 1 and "apt could not read its package lists (above)" in out.stderr
    assert (box.out / "result.txt").read_text(encoding="utf-8") == "fail: install\n"
    assert len(box.ran("apt-get")) == 1


def test_an_existing_policy_rc_d_is_left_as_it_was(box):
    policy = box.root / "usr/sbin/policy-rc.d"
    policy.parent.mkdir(parents=True)
    policy.write_text("#!/bin/sh\n# the image's own\nexit 101\n", encoding="utf-8")
    assert box.run("--source").returncode == 0
    assert policy.read_text(encoding="utf-8") == "#!/bin/sh\n# the image's own\nexit 101\n"


def test_the_versions_are_recorded_and_a_missing_program_fails(box, tmp_path, stub_bin):
    out = box.run("--source")
    assert out.returncode == 0, out.stderr
    versions = (box.out / "versions.txt").read_text(encoding="utf-8")
    assert versions.startswith("system: Debian GNU/Linux 13 (trixie) (debian-13, amd64)\nkernel: ")
    for line in (
        "nft: nftables v1.1.3",
        "systemctl: systemd 257 (257.13-1~deb13u1)",
        "dnsmasq: Dnsmasq version 2.91  Copyright (c) 2000-2025 Simon Kelley",
        "nginx: nginx version: nginx/1.26.3",  # on stderr, where nginx -v prints it
        "dumpcap: Dumpcap (Wireshark) 4.4.19.",
        "conntrack: conntrack v1.4.8 (conntrack-tools)",
        "tshark: TShark (Wireshark) 4.4.19.",  # not the warning tshark prints first on stderr
        "NetworkManager: 1.52.1",
    ):
        assert line in versions.splitlines(), line
    assert re.search(r"^python3: Python 3\.\d+", versions, re.M)
    other = Box(tmp_path / "missing", (stub_bin,))  # no NetworkManager on PATH
    out = other.run("--source")
    assert out.returncode == 1
    assert "NetworkManager: missing" in (other.out / "versions.txt").read_text(encoding="utf-8")
    assert "FAIL: versions: a program the package needs is missing" in out.stderr


# ---- refused before anything is changed --------------------------------------------------------------


@pytest.mark.parametrize(
    "args",
    [(), ("--frobnicate",), ("--source", "extra"), ("--package",), ("--list-depends", "x"), ("-h",)],
)
def test_a_wrong_command_line_is_refused_with_the_usage(box, args):
    out = box.run(*args)
    assert out.returncode == 1 and "usage: check-platform.sh --source | --package" in out.stderr
    assert box.log() == []


def assert_changed_nothing(box, out, says):
    assert out.returncode == 1 and says in out.stderr, out.stderr
    assert not box.ran("apt-get") and not box.ran("debconf-set-selections") and not box.ran("ip")
    assert not (box.root / "usr/sbin/policy-rc.d").exists()


def test_it_runs_only_as_root(box):
    assert_changed_nothing(
        box, box.run("--source", FAKE_UID="1000"), "run it as root, in a throwaway container"
    )


def test_it_runs_only_in_a_container(box):
    (box.root / ".dockerenv").unlink()
    assert_changed_nothing(box, box.run("--source"), "this is not a container")
    (box.root / "run").mkdir()
    (box.root / "run/.containerenv").write_text("", encoding="utf-8")  # podman's mark
    assert box.run("--source").returncode == 0


def test_it_never_overwrites_a_gateways_settings(box):
    """A gateway has /etc/tvgw: the check would replace its tvgw.conf, so it stops. A second run in the
    same container finds the mark the first one left and carries on."""
    conf = box.root / "etc/tvgw/tvgw.conf"
    conf.parent.mkdir(parents=True)
    conf.write_text("TV_IF=eth0\n", encoding="utf-8")
    assert_changed_nothing(box, box.run("--source"), "this computer has /etc/tvgw, a gateway's settings")
    assert conf.read_text(encoding="utf-8") == "TV_IF=eth0\n"
    conf.parent.joinpath(".made-by-check-platform").write_text("", encoding="utf-8")
    assert box.run("--source").returncode == 0


# ---- the checks --------------------------------------------------------------------------------------


def test_tvgw_apply_is_checked_with_every_switch_at_each_of_its_values_on_the_dummy_ports(box):
    out = box.run("--source")
    assert out.returncode == 0, out.stderr
    assert [line for line in box.ran("ip") if " add " in line][:2] == [
        "ip link add dummy0 type dummy",
        "ip link add dummy1 type dummy",
    ]
    assert "ip addr replace 10.10.10.1/24 dev dummy0" in box.ran("ip")
    applies = box.ran("bash")
    assert applies == [f"bash {box.src}/deploy/nftables/tvgw-apply --check"] * 4
    template = (ROOT / "deploy/tvgw.conf.example").read_text(encoding="utf-8")
    confs = {}
    for name in ("default", "vpn", "headers", "open"):
        text = (box.out / "apply" / f"{name}.conf").read_text(encoding="utf-8")
        assert text.startswith(template), name  # the template first, then the check's own lines
        confs[name] = effective(text)
        assert {k: confs[name][k] for k in ("TV_IF", "WAN_IF", "TV_MAC")} == {
            "TV_IF": "dummy0",
            "WAN_IF": "dummy1",
            "TV_MAC": "02:00:00:00:00:17",
        }
        assert confs[name]["WAN_GW"] == "198.51.100.1"  # a documentation address, not the template's
    choices = vnet.script_choices(vnet.APPLY.read_text(encoding="utf-8"))
    for switch, values in choices.items():
        assert {c[switch] for c in confs.values()} == set(values), switch
    assert (box.root / "etc/tvgw/block4.txt").read_text(encoding="utf-8") == (
        ROOT / "deploy/nftables/block4.txt"
    ).read_text(encoding="utf-8")


def test_a_refused_variant_fails_the_run_but_every_other_check_still_runs(box):
    out = box.run("--source", FAKE_APPLY_REFUSE="UPLINK=vpn")
    assert out.returncode == 1
    assert "FAIL: apply: tvgw-apply --check failed: vpn" in out.stderr
    assert "Error: syntax error, unexpected junk" in out.stderr
    assert "check-platform: ok: tvgw-apply --check, headers settings" in out.stdout
    assert box.ran("nginx") and box.ran("dnsmasq") and box.ran("systemd-analyze")
    assert (box.out / "result.txt").read_text(encoding="utf-8") == "fail: apply\n"
    assert "failed: apply (the lines above say why" in out.stderr


def test_a_table_left_loaded_by_the_check_fails_it(box):
    out = box.run("--source", FAKE_APPLY_LEAVES="1")
    assert out.returncode == 1 and "(a table was left loaded)" in out.stderr
    assert (box.out / "apply/tables.after").read_text(encoding="utf-8") == "table inet tvgw\n"


def test_a_table_the_container_held_before_the_check_is_not_one_it_left(box):
    """A container on a user-defined network, as GitHub's container jobs are, holds Docker's NAT table for
    its embedded DNS before anything runs; the check compares the tables with those, not with none."""
    docker = "table ip nat\n"
    out = box.run("--source", FAKE_TABLES=docker)
    assert out.returncode == 0, out.stderr
    assert "every check passed" in out.stdout
    for when in ("before", "after"):
        assert (box.out / f"apply/tables.{when}").read_text(encoding="utf-8") == docker
    # the tables are read before the first apply and after the last
    log = box.log()
    lists = [i for i, line in enumerate(log) if line == "nft list tables"]
    applies = [i for i, line in enumerate(log) if line.startswith("bash ")]
    assert len(lists) == 2 and lists[0] < applies[0] and applies[-1] < lists[1]


def test_a_port_that_cannot_be_made_fails_the_apply_check_only(box):
    out = box.run("--source", FAKE_IP_RC="2")
    assert out.returncode == 1
    assert "could not make the dummy port dummy0 (a container needs --cap-add=NET_ADMIN)" in out.stderr
    assert not box.ran("bash") and box.ran("nginx")


def test_an_address_the_tv_port_cannot_take_fails_the_apply_check_only(box):
    out = box.run("--source", FAKE_IP_ADDR_RC="2")
    assert out.returncode == 1
    assert "could not give the dummy port dummy0 the gateway's address 10.10.10.1" in out.stderr
    assert not box.ran("bash") and box.ran("nginx") and box.ran("systemd-analyze")
    assert (box.out / "result.txt").read_text(encoding="utf-8") == "fail: apply\n"


def test_dumpcap_runs_with_the_capture_units_own_ring_options(box):
    assert box.run("--source").returncode == 0
    unit = (ROOT / "deploy/systemd/tvgw-pcap.service").read_text(encoding="utf-8")
    (opts,) = re.findall(r"^ExecStart=/usr/bin/dumpcap -i \$\{TV_IF\} (.*?) -w ", unit, re.M)
    assert "-b nametimenum:2" in opts and "-b interval:3600" in opts
    (capture,) = [line for line in box.ran("dumpcap") if "--version" not in line]
    assert re.fullmatch(rf"dumpcap -i lo {re.escape(opts)} -a duration:1 -w \S+/pcap/tv\.pcap", capture)
    assert "runuser -u tvgw-pcap -- test -x /usr/bin/dumpcap" in box.log()  # install.sh's own check


@pytest.mark.parametrize(
    ("env", "says"),
    [
        (
            {"FAKE_PCAP_NAMES": "tv_00001.pcap"},
            "the ring file is not tv_<14 digits>_00001.pcap: tv_00001.pcap",
        ),
        (
            {"FAKE_PCAP_NAMES": "tv_20261103120000_00001.pcap tv_20261103130000_00002.pcap"},
            "the ring file is not tv_<14 digits>_00001.pcap",
        ),
        ({"FAKE_PCAP_NAMES": "tv_2026110312000_00001.pcap"}, "the ring file is not"),  # 13 digits
        ({"FAKE_DUMPCAP_RC": "1"}, "dumpcap refused tvgw-pcap.service's options: -q -P -g -s 0"),
        ({"FAKE_DUMPCAP_X_RC": "1"}, "not executable by tvgw-pcap: the wireshark-common answer did not take"),
    ],
)
def test_a_ring_file_named_otherwise_or_a_refused_option_fails_the_dumpcap_check(box, env, says):
    out = box.run("--source", **env)
    assert out.returncode == 1 and "FAIL: dumpcap: " in out.stderr and says in out.stderr, out.stderr


def test_users_that_cannot_be_made_fail_their_own_checks_and_every_other_check_still_runs(box):
    """The suite's user and the capture user are made by the check; when useradd refuses, the unit suite and
    the dumpcap check fail with the reason, and the run carries on to its verdict."""
    out = box.run("--source", FAKE_USERADD_RC="1")
    assert out.returncode == 1
    assert "FAIL: unit-suite: could not give the user tvgwci its own copy of the checkout" in out.stderr
    assert "FAIL: dumpcap: could not create the capture user tvgw-pcap" in out.stderr
    assert not [line for line in box.ran("runuser") if "-u tvgwci" in line]
    assert box.ran("nginx") and box.ran("dnsmasq") and box.ran("systemd-analyze")
    assert (box.out / "result.txt").read_text(encoding="utf-8") == "fail: unit-suite dumpcap\n"


def test_nginx_is_tested_with_the_include_appended_then_among_the_modules(box):
    out = box.run("--source")
    assert out.returncode == 0, out.stderr
    forms = [line for line in box.log() if line.startswith("nginx form:")]
    assert forms == [
        "nginx form: appended",
        "nginx form: modules-enabled include /etc/nginx/tvgw/stream.conf;",
    ]
    etc = box.root / "etc/nginx"
    assert (etc / "nginx.conf").read_text(encoding="utf-8") == box.shipped  # left as shipped
    assert not (etc / "modules-enabled/99-tvgw-stream.conf").exists()
    assert not (etc / "sites-enabled/default").exists()  # removed, as install.sh removes it
    for path in (etc / "conf.d/tvgw-gfts.conf", etc / "tvgw/stream.conf"):
        text = path.read_text(encoding="utf-8")
        assert "__" not in text and "10.10.10.1:" in text and "resolver 1.1.1.1 " in text, path


def test_without_the_stream_module_or_with_a_refusal_the_nginx_check_fails(box, tmp_path):
    (box.root / "etc/nginx/modules-enabled/50-mod-stream.conf").unlink()
    out = box.run("--source")
    assert out.returncode == 1 and "no stream module in" in out.stderr
    other = Box(tmp_path / "refused", box.bins)
    out = other.run("--source", FAKE_NGINX_RC="1")
    assert "nginx -t refused the files with the include appended to nginx.conf" in out.stderr
    assert "nginx -t refused the files with the include as modules-enabled/99-tvgw-stream.conf" in out.stderr


def test_the_three_dhcp_files_are_tested_and_say_what_each_case_means(box):
    assert box.run("--source").returncode == 0
    tested = [line.split("--conf-file=")[1] for line in box.ran("dnsmasq") if "--test" in line]
    assert [Path(p).name for p in tested] == [
        f"tvgw.conf.{f}" for f in ("open-unknown", "open-pinned", "pinned")
    ]
    files = {Path(p).name.split(".")[-1]: Path(p).read_text(encoding="utf-8") for p in tested}
    pool = "dhcp-range=10.10.10.10,10.10.10.20,255.255.255.0,12h"
    pin = "dhcp-host=02:00:00:00:00:17,10.10.10.17,tv"
    lines = {name: text.splitlines() for name, text in files.items()}
    assert pool in lines["open-unknown"] and not any(
        x.startswith("dhcp-host=") for x in lines["open-unknown"]
    )
    assert pool in lines["open-pinned"] and pin in lines["open-pinned"]
    assert pool not in lines["pinned"] and pin in lines["pinned"]
    assert "dhcp-range=10.10.10.17,static,255.255.255.0,12h" in lines["pinned"]
    assert "dhcp-ignore=tag:!known" in lines["pinned"]
    assert all("interface=dummy0" in x and "__" not in x for x in files.values())


def test_a_dhcp_file_dnsmasq_refuses_fails_the_check(box):
    out = box.run("--source", FAKE_DNSMASQ_REFUSE="dhcp-ignore")
    assert out.returncode == 1 and "FAIL: dnsmasq: dnsmasq --test refused: pinned" in out.stderr


def test_systemd_verifies_the_units_and_drop_ins_install_sh_writes(box):
    assert box.run("--source").returncode == 0
    (verify,) = box.ran("systemd-analyze")
    sd = box.root / "etc/systemd/system"
    units = sorted(p.name for p in (ROOT / "deploy/systemd").iterdir() if p.suffix in (".service", ".timer"))
    args = verify.split()
    assert args[:3] == ["systemd-analyze", "verify", "--man=no"] and args[-2:] == [
        "dnsmasq.service",
        "nginx.service",
    ]
    assert sorted(Path(a).name for a in args[3:-2]) == units
    assert (sd / "tvgw-pcap.service.d/tv-side.conf").read_text(encoding="utf-8") == (
        "[Service]\nEnvironment=TV_IF=dummy0 TV_NET=10.10.10.0/24 GW_IP=10.10.10.1\n"
    )
    hardening = (sd / "dnsmasq.service.d/20-tvgw-hardening.conf").read_text(encoding="utf-8")
    assert "IPAddressAllow=localhost 0.0.0.0/32 255.255.255.255/32 10.10.10.0/24" in hardening
    nginx = (sd / "nginx.service.d/tvgw.conf").read_text(encoding="utf-8")
    assert nginx.startswith("[Unit]\nAfter=network-online.target\n") and "ProtectSystem=strict" in nginx
    assert os.readlink(box.root / "usr/local/bin/tvgw") == f"{box.root}/home/tvgwci/venv/bin/tvgw"
    for script in ("tvgw-apply", "tvgw-doh-update", "tvgw-analyze"):
        assert os.access(box.root / "usr/local/sbin" / script, os.X_OK), script


@pytest.mark.parametrize(
    ("distro", "output", "rc", "verdict"),
    [
        # systemd 252 knows neither restart key: allowed on Debian 12, with the reason printed
        ("debian-12", RESTART_STEPS, 0, "allowed on debian-12: systemd 252 predates RestartSteps (254)"),
        # the same finding anywhere else is a unit this systemd misreads
        ("debian-13", RESTART_STEPS, 0, "FAIL: systemd: systemd-analyze verify found a tvgw file"),
        # a finding on the distribution's own unit is shown and passes
        (
            "ubuntu-26.04",
            "/usr/lib/systemd/system/dnsmasq.service:12: PIDFile= is in /var/run",
            0,
            "note: a file",
        ),
        # any finding on a tvgw file the list does not name fails, on Debian 12 too
        (
            "debian-12",
            "/etc/systemd/system/tvgw.service:9: Unknown key 'ProtectNothing' in section [Service], ignoring.",
            0,
            "FAIL: systemd",
        ),
        ("debian-12", "/etc/systemd/system/nginx.service.d/tvgw.conf:3: Unknown section 'Servce'", 0, "FAIL"),
        ("debian-13", "", 1, "FAIL: systemd: systemd-analyze verify exited 1"),
    ],
)
def test_systemds_findings_fail_unless_this_distribution_allows_them(box, distro, output, rc, verdict):
    box.os(distro)
    out = box.run("--source", FAKE_VERIFY_OUT=output, FAKE_VERIFY_RC=str(rc))
    assert verdict in out.stdout + out.stderr, out.stdout + out.stderr
    assert out.returncode == (1 if "FAIL" in verdict else 0)


def test_the_allow_list_names_debian_12s_two_restart_keys_and_nothing_else():
    (block,) = re.findall(r'^ALLOWED="(.*?)"$', TEXT, re.M | re.S)
    entries = [line.split("|") for line in block.splitlines()]
    assert [(e[0], e[1]) for e in entries] == [
        ("debian-12", "Unknown key 'RestartSteps' in section [Service], ignoring."),
        ("debian-12", "Unknown key 'RestartMaxDelaySec' in section [Service], ignoring."),
    ]
    assert all(len(e) == 3 and e[2] for e in entries), "every allowed finding says why"
    unit = (ROOT / "deploy/systemd/tvgw-dnsgate.service").read_text(encoding="utf-8")
    assert "RestartSteps=6\nRestartMaxDelaySec=5min\n" in unit  # what the entries are about


# ---- the same renders as install.sh ------------------------------------------------------------------


@pytest.mark.parametrize(
    "line",
    [
        'ngx="s/__RESOLVER__/$URL_FILTER_RESOLVER/; s/__GW_IP__/$GW_IP/"',
        'printf \'[Service]\\nEnvironment=TV_IF=%s TV_NET=%s GW_IP=%s\\n\' "$TV_IF" "$TV_NET" "$GW_IP"',
        "printf '[Unit]\\nAfter=network-online.target\\nWants=network-online.target\\n[Service]\\nRestart=on-failure\\nRestartSec=5\\n'",
        "grep -v '^#' nginx/tvgw-hardening.conf",
        'sed -e "$side; /__TV_MAC__/d"',
        'sed -e "$side; s/__TV_MAC__/$TV_MAC/; s/__TV_IP__/$TV_IP/g; s/__TV_NAME__/$TV_NAME/"',
        "useradd --system --no-create-home --shell /usr/sbin/nologin -g nogroup tvgw-pcap",
        "install -m 755 nftables/tvgw-apply bin/tvgw-doh-update bin/tvgw-analyze",
    ],
)
def test_each_file_is_rendered_with_install_shs_own_expression(line):
    """The check renders what install.sh renders, with the same words, so a change to one shows here."""
    assert line in INSTALL_SH, f"install.sh no longer has: {line}"
    ours = line.replace("nginx/tvgw-hardening.conf", '"$DEPLOY/nginx/tvgw-hardening.conf"')
    ours = re.sub(r"(nftables|bin)/(tvgw-[a-z-]+)", r'"$DEPLOY/\1/\2"', ours)
    assert ours in TEXT, f"check-platform.sh does not have: {ours}"


def test_the_dhcp_sides_substitutions_are_install_shs():
    side = re.search(r'local side="(.*?)"\n\tside\+="; (.*?)"\n', INSTALL_SH)
    assert side, "install.sh's render_dnsmasq changed shape"
    assert f'side="{side.group(1)}; {side.group(2)}"' in TEXT


def test_the_settings_of_the_check_are_the_templates_tv_side_and_documentation_values():
    template = effective((ROOT / "deploy/tvgw.conf.example").read_text(encoding="utf-8"))
    ours = dict(re.findall(r"\b([A-Z_]+)=(\S+)", TEXT.split("# what `tvgw-apply --check` is run with")[0]))
    for key in ("TV_NET", "GW_IP", "TV_IP", "TV_NAME", "URL_FILTER_RESOLVER"):
        assert ours[key] == template[key], key
    assert ours["WAN_GW"].startswith(("192.0.2.", "198.51.100.", "203.0.113."))  # RFC 5737
    assert int(ours["TV_MAC"].split(":")[0], 16) & 0b10, "a locally administered MAC"


# ---- the package mode ----------------------------------------------------------------------------------


def package_tree(box: Box) -> Path:
    """The package's copy of deploy/, where --package reads the files it checks."""
    tree = box.root / "usr/lib/tvgw/deploy"
    shutil.copytree(ROOT / "deploy", tree)
    return tree


def test_a_package_is_installed_by_install_check_and_its_own_files_are_checked(box):
    tree = package_tree(box)
    deb = box.deb()
    out = box.run("--package", str(deb))
    assert out.returncode == 0, out.stderr
    venv = box.root / "opt/tvgw-platform-venv"
    assert box.ran("install-check") == [f"install-check {deb} venv={venv}"]
    assert "-m pytest" not in box.calls.read_text(encoding="utf-8"), "no unit suite from a package"
    assert box.ran("apt-get") == [
        "apt-get -o DPkg::Lock::Timeout=300 -q update"
    ]  # the package brings its own
    assert box.ran("bash") == [f"bash {tree}/nftables/tvgw-apply --check"] * 4
    assert os.readlink(box.root / "usr/local/bin/tvgw") == f"{venv}/bin/tvgw"


def test_a_release_is_downloaded_and_checked_against_its_sha256sums(box):
    package_tree(box)
    box.deb("9.8.7", "arm64")
    out = box.run("--package", "v9.8.7", FAKE_ARCH="arm64")
    assert out.returncode == 0, out.stderr
    urls = [line.split()[-1] for line in box.ran("curl")]
    base = "https://example.invalid/releases/download/v9.8.7"
    assert urls == [f"{base}/tvgw_9.8.7-1_arm64.deb", f"{base}/SHA256SUMS"]
    assert all("--proto =https --tlsv1.2 -fsSL --retry 3" in line for line in box.ran("curl"))
    (installed,) = box.ran("install-check")
    assert installed.split()[1].endswith("/tvgw_9.8.7-1_arm64.deb")


def test_a_downloaded_package_that_does_not_match_is_never_installed(box):
    package_tree(box)
    box.deb("9.8.7", "amd64")
    (box.release / "SHA256SUMS").write_text(f"{'0' * 64}  tvgw_9.8.7-1_amd64.deb\n", encoding="utf-8")
    out = box.run("--package", "v9.8.7")
    assert out.returncode == 1
    assert "tvgw_9.8.7-1_amd64.deb does not match its line in the release's SHA256SUMS" in out.stderr
    assert not box.ran("install-check")


@pytest.mark.parametrize(
    ("arg", "says"),
    [
        ("v1..2", "a release is v and its version, such as v0.3.0, not v1..2"),
        ("v", "not v"),
        ("9.8.7", "no package at 9.8.7"),
    ],
)
def test_a_release_or_a_file_that_is_not_one_is_refused(box, arg, says):
    out = box.run("--package", arg)
    assert out.returncode == 1 and says in out.stderr
    assert not box.ran("install-check") and not box.ran("curl")


def test_install_check_takes_the_virtualenv_it_is_given():
    text = (PKG / "install-check.sh").read_text(encoding="utf-8")
    assert "VENV=${TVGW_CHECK_VENV:-$(mktemp -d)/venv}" in text
    assert 'TVGW_CHECK_VENV=$VENV sh "$HERE/install-check.sh" "$DEB"' in TEXT
