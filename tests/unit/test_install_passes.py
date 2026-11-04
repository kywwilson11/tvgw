"""(setup) install.sh's two setup passes, run whole against stub commands with every path it touches
moved under tmp_path (the stub pattern of test_packaging.py). `bringup` brings the TV side up and exits
0 whether the TV is known or not, and never reaches AdGuard Home, nginx, the firewall's unit or the
others; `apply` runs everything and ends as the postinst's run does, 76 on a FAIL; with no pass the
installer is the deploy path it was, ending in `exec tvgw verify`; any other value runs nothing."""

import re
import shutil
import subprocess
from pathlib import Path

import pytest
from conftest import ROOT

from tvgw import verify

BASH = shutil.which("bash")
pytestmark = pytest.mark.skipif(
    BASH is None or shutil.which("sha256sum") is None, reason="install.sh needs bash and sha256sum"
)

DEPLOY = ROOT / "deploy"
MAC = "00:00:5e:00:53:17"  # RFC 7042's documentation range
# every absolute path install.sh touches starts with one of these; dumpcap is moved by name
TOUCHED = r"/(?:etc|usr/local|usr/lib/tvgw|opt|var|run)/"
AGH_VERSION = ".".join(str(n) for n in verify.ADGUARD_MIN)

# One log line per call, "<command> <args>". systemctl: dnsmasq and nginx are active, every tvgw unit
# is not (a first install: so the firewall unit is restarted, never re-applied by the real tvgw-apply)
SYSTEMCTL = """[ "$1" = -q ] && shift
case "$1" in
is-active) [ "$2" = -q ] && shift; case "$2" in dnsmasq.service | nginx.service) exit 0 ;; esac; exit 3 ;;
is-enabled) echo disabled ;;
esac
exit 0"""
SS = """case "$*" in
*-ulnp*) echo 'UNCONN 0 0 0.0.0.0%eth0:67 0.0.0.0:* users:(("dnsmasq",pid=7,fd=4))' ;;
*:80*) echo 'LISTEN 0 511 10.10.10.1:80 0.0.0.0:*' ;;
*:443*) echo 'LISTEN 0 511 10.10.10.1:443 0.0.0.0:*' ;;
esac"""
NFT = '[ "$1" = -c ] || exit 1'  # the rendered guard passes `nft -c`; no table is loaded yet
NGINX = '[ "$1" = -T ] && printf "http {\\n}\\n"\nexit 0'
# nmcli as $NM describes the connections: `names` lists them; tv-lan sits on eth0 with GW_IP, up
NMCLI = """case "$*" in
"-t -f NAME con show") cat "$NM/names" ;;
"-t -f NAME,DEVICE con show --active") cat "$NM/active" ;;
"-g connection.interface-name con show tv-lan") echo eth0 ;;
"-g ipv4.addresses con show tv-lan") echo 10.10.10.1/24 ;;
"-g GENERAL.STATE con show tv-lan") echo activated ;;
esac
exit 0"""
TVGW = """case "$1" in
--version) echo "tvgw 0.2.0" ;;
verify) exit "$VERIFY_RC" ;;
adguard) [ "$2" != apply ] || exit "${ADGUARD_RC:-0}" ;;
esac
exit 0"""
SYSTEMD_ANALYZE = '[ "$1" = calendar ]'  # every schedule parses; cat-config shows no other journald file
# install(1) for an unprivileged run: -o and -g are dropped, -D makes the target's directory
INSTALL_CMD = """dir=no parents=no mode=
while [ $# -gt 0 ]; do
	case $1 in
	-d) dir=yes; shift ;;
	-D) parents=yes; shift ;;
	-m) mode=$2; shift 2 ;;
	-o | -g) shift 2 ;;
	*) break ;;
	esac
done
if [ $dir = yes ]; then
	mkdir -p "$@" && { [ -z "$mode" ] || chmod "$mode" "$@"; }
	exit
fi
for last in "$@"; do :; done
[ $parents = no ] || mkdir -p "$(dirname "$last")"
while [ $# -gt 1 ]; do
	if [ -d "$last" ]; then to=$last/$(basename "$1"); else to=$last; fi
	cat "$1" >"$to" && { [ -z "$mode" ] || chmod "$mode" "$to"; } || exit 1
	shift
done"""
STUBS = {
    "systemctl": SYSTEMCTL,
    "ss": SS,
    "nft": NFT,
    "nginx": NGINX,
    "nmcli": NMCLI,
    "tvgw": TVGW,
    "systemd-analyze": SYSTEMD_ANALYZE,
    "install": INSTALL_CMD,
    "ip": "exit 0",  # the uplink has no address yet: nothing overlaps TV_NET
    "udevadm": "exit 0",
    "flock": "exit 0",
    "getent": "exit 0",  # tvgw-pcap exists
    "useradd": "exit 0",
    "runuser": "exit 0",
    "chgrp": "exit 0",
    "chown": "exit 0",
    "sync": "exit 0",
}
# a command these stubs leave to the system must not be able to change it
SYSTEM_CHANGING = {"systemctl", "nmcli", "nft", "ip", "nginx", "tvgw", "useradd", "runuser", "install"}


def moved(text: str, root: Path) -> str:
    """install.sh with every absolute path it touches moved under `root`, the `${1:-/var/...}` defaults
    included, and dumpcap's path too; refuses a script that would still touch the real system."""
    text = re.sub(rf"(?<=[\s\"'=>(|:-])(?={TOUCHED})", str(root), text)
    text = text.replace("DUMPCAP=/usr/bin/dumpcap", f"DUMPCAP={root}/usr/bin/dumpcap")
    left = re.findall(rf"(?<![\w./-]){TOUCHED}\S*", text.replace(str(root), "ROOT"))
    assert not left, f"install.sh would still touch {left}"
    return text


def executable(path: Path, body: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(body, encoding="utf-8")
    path.chmod(0o755)


def gateway(tmp_path: Path, *, tv_mac: str = MAC, tv_lan: bool = True, adguard: bool = True) -> Path:
    """A computer as install.sh finds it: the repository's deploy tree, a settings file, the system
    directories that exist on Debian, a virtualenv, dumpcap and, with `adguard`, AdGuard Home after its
    wizard; with `tv_lan`, the tv-lan connection already made."""
    root = tmp_path / "root"
    shutil.copytree(DEPLOY, root / "deploy")
    executable(
        root / "deploy" / "nftables" / "tvgw-apply", f'#!/bin/sh\necho "tvgw-apply $*" >>{root}/calls\n'
    )
    (root / "deploy" / "install.sh").write_text(
        moved((DEPLOY / "install.sh").read_text(encoding="utf-8"), root), encoding="utf-8"
    )
    for d in (
        "etc/tvgw",
        "etc/nginx/conf.d",
        "etc/nginx/sites-enabled",
        "etc/NetworkManager/conf.d",
        "etc/NetworkManager/dispatcher.d",
        "etc/logrotate.d",
        "etc/systemd/system",
        "etc/dnsmasq.d",
        "usr/local/bin",
        "usr/local/sbin",
        "src/tvgw",
    ):
        (root / d).mkdir(parents=True, exist_ok=True)
    (root / "etc/nginx/nginx.conf").write_text("events {}\n", encoding="utf-8")
    (root / "src/tvgw/__init__.py").write_text("", encoding="utf-8")
    (root / "etc/tvgw/tvgw.conf").write_text(
        f"TV_MAC={tv_mac}\nTV_IP=10.10.10.17\nTV_NAME=tv\nPROFILE=lg-webos\nTV_IF=eth0\n"
        "TV_NET=10.10.10.0/24\nGW_IP=10.10.10.1\nWAN_IF=wlan0\nWAN_GW=192.0.2.1\n",
        encoding="utf-8",
    )
    executable(root / "usr/bin/dumpcap", "#!/bin/sh\n")
    executable(root / "opt/tvgw-venv/bin/python", "#!/bin/sh\n")
    executable(root / "opt/tvgw-venv/bin/pip", f'#!/bin/sh\necho "pip $*" >>{root}/calls\n')
    if adguard:
        executable(
            root / "opt/AdGuardHome/AdGuardHome", f"#!/bin/sh\necho 'AdGuard Home, version v{AGH_VERSION}'\n"
        )
        (root / "opt/AdGuardHome/AdGuardHome.yaml").write_text("schema_version: 30\n", encoding="utf-8")
    for name, body in STUBS.items():
        executable(root / "bin" / name, f'#!/bin/sh\necho "{name} $*" >>{root}/calls\n{body}\n')
    (root / "nm").mkdir()
    (root / "nm" / "names").write_text("tv-lan\nhome-wifi\n" if tv_lan else "home-wifi\n", encoding="utf-8")
    (root / "nm" / "active").write_text("home-wifi:wlan0\n", encoding="utf-8")
    return root


def run(root: Path, setup_pass: str | None, verify_rc: int = 0, **extra: str):
    """install.sh as setup runs it: no terminal on stdin, the pass in TVGW_SETUP_PASS (None: unset), and
    `extra` in its environment. Returns the process and the calls it made, in order."""
    assert set(STUBS) >= SYSTEM_CHANGING
    env = {"PATH": f"{root / 'bin'}:/usr/bin:/bin:/usr/sbin:/sbin", "NM": str(root / "nm"), **extra}
    env["VERIFY_RC"] = str(verify_rc)
    if setup_pass is not None:
        env["TVGW_SETUP_PASS"] = setup_pass
    out = subprocess.run(
        [BASH, str(root / "deploy" / "install.sh")],
        env=env,
        stdin=subprocess.DEVNULL,
        capture_output=True,
        text=True,
        encoding="utf-8",
    )
    log = root / "calls"
    return out, log.read_text(encoding="utf-8").splitlines() if log.exists() else []


def never(seen: list[str], *prefixes: str) -> list[str]:
    return [c for c in seen if c.startswith(prefixes)]


def scrubbed(lines: list[str], root: Path) -> list[str]:
    return [line.replace(str(root), "<root>") for line in lines]


# what only the full install does, after the TV side: nginx, AdGuard Home, the firewall, the units
FULL_ONLY = (
    "nginx -t",
    "tvgw adguard",
    "systemctl restart tvgw.service",
    "systemctl enable --now",
    "systemctl start tvgw-analyze.service",
    "tvgw verify",
)


@pytest.mark.parametrize(
    ("tv_mac", "tv_lan"),
    [
        (MAC, True),  # a re-run with the TV known: tv-lan exists and is left as it is
        ("00:00:00:00:00:00", False),  # a first install: the template's MAC, no tv-lan yet
    ],
)
def test_bringup_exits_0_with_the_tv_side_up_whatever_the_tv_is(tmp_path, tv_mac, tv_lan):
    """No AdGuard Home on this computer either: the bring-up pass comes before it is set up."""
    root = gateway(tmp_path, tv_mac=tv_mac, tv_lan=tv_lan, adguard=False)
    out, seen = run(root, "bringup")
    assert out.returncode == 0, out.stderr
    assert out.stdout.splitlines()[-1] == "tvgw: TV side up on eth0 (10.10.10.1)"
    assert "AdGuard Home is not installed" not in out.stderr and "not identified" not in out.stderr
    assert ("nmcli con add type ethernet ifname eth0 con-name tv-lan" in " ".join(seen)) == (not tv_lan)
    assert seen[-4:] == [
        "systemctl daemon-reload",
        "systemctl restart dnsmasq.service",
        "systemctl is-active -q dnsmasq.service",
        "ss -H -ulnp sport = :67",
    ], "the pass ends on dnsmasq's restart and its health check"
    assert seen.index("nmcli general reload conf") > seen.index("tvgw guard cotenants")
    assert not never(seen, *FULL_ONLY, "tvgw discover", "tvgw-apply", "udevadm"), seen
    pinned = (root / "etc/dnsmasq.d/tvgw.conf").read_text(encoding="utf-8")
    assert (MAC in pinned) == (tv_mac == MAC)  # the pin only for a known TV; the pool either way


def test_networkmanager_is_started_before_the_tv_side_only_when_it_is_not_running(tmp_path):
    """(packaging) apt installed network-manager with the package and the installer's policy-rc.d held its
    start (systemctl does not ask it): every nmcli call would fail. install.sh starts it before the TV
    side; one that is running is left alone."""
    root = gateway(tmp_path / "stopped", tv_lan=False, adguard=False)
    out, seen = run(root, "bringup")
    assert out.returncode == 0, out.stderr
    assert seen.index("systemctl start NetworkManager.service") < seen.index("nmcli general reload conf")
    root = gateway(tmp_path / "running", tv_lan=False, adguard=False)
    executable(
        root / "bin" / "systemctl",
        f'#!/bin/sh\necho "systemctl $*" >>{root}/calls\n'
        + SYSTEMCTL.replace(
            "dnsmasq.service | nginx.service", "dnsmasq.service | nginx.service | NetworkManager.service"
        ),
    )
    out, seen = run(root, "bringup")
    assert out.returncode == 0, out.stderr
    assert "systemctl start NetworkManager.service" not in seen


def test_apply_ends_as_the_postinst_does_and_no_pass_is_the_same_install_ending_in_exec(tmp_path):
    """A FAIL right after a first install is often AdGuard Home still loading its lists: the apply pass
    exits 76 for it, which setup tells from a stop (1) and waits out. With no pass the installer runs
    the same steps in the same order, then execs `tvgw verify`, whose 1 is the deploy's verdict."""
    apply_root = gateway(tmp_path / "apply")
    applied, apply_seen = run(apply_root, "apply", verify_rc=1)
    assert applied.returncode == 76, applied.stderr
    assert apply_seen[-1] == "tvgw verify" and "TV side up" not in applied.stdout
    reload_conf, nginx_t = apply_seen.index("nmcli general reload conf"), apply_seen.index("nginx -t")
    assert reload_conf < nginx_t < apply_seen.index("tvgw adguard apply") < apply_seen.index("tvgw verify")
    deploy_root = gateway(tmp_path / "deploy")
    deployed, deploy_seen = run(deploy_root, None, verify_rc=1)
    assert deployed.returncode == 1, deployed.stderr
    assert scrubbed(deploy_seen, deploy_root) == scrubbed(apply_seen, apply_root)
    assert scrubbed([deployed.stdout], deploy_root) == scrubbed([applied.stdout], apply_root)


def test_apply_without_the_tv_stops_before_the_tv_side(tmp_path):
    root = gateway(tmp_path, tv_mac="00:00:00:00:00:00")
    out, seen = run(root, "apply")
    assert out.returncode == 1 and out.stderr.endswith("tvgw: setup's apply pass needs TV_MAC\n")
    assert not never(seen, "pip", "nmcli", "nft", "systemctl", "tvgw"), seen


def test_with_no_pass_an_unknown_tv_and_no_terminal_is_still_75(tmp_path):
    root = gateway(tmp_path, tv_mac="00:00:00:00:00:00", tv_lan=False)
    out, seen = run(root, None)
    assert out.returncode == 75, out.stderr
    assert "TV not identified and no terminal to ask on" in out.stderr and "tvgw adguard apply" not in seen


@pytest.mark.parametrize("setup_pass", ["Bringup", "apply ", "prepare", "bringup,apply"])
def test_any_other_pass_runs_nothing(tmp_path, setup_pass):
    root = gateway(tmp_path)
    out, seen = run(root, setup_pass)
    assert out.returncode == 1
    assert out.stderr == f"tvgw: TVGW_SETUP_PASS={setup_pass}: the passes are bringup and apply\n"
    assert seen == [] and not (root / "run").exists()


@pytest.mark.parametrize(
    ("setup_pass", "extra", "again"),
    [
        (None, {}, "sudo ./install.sh"),  # from a checkout, by hand
        (None, {"TVGW_POSTINST": "1"}, "sudo dpkg --configure -a"),  # the package's postinst
        ("apply", {}, "sudo tvgw setup"),  # setup's apply pass
    ],
)
def test_an_adguard_home_that_is_not_tvgws_to_take_stops_the_install_with_the_way_on(
    tmp_path, setup_pass, extra, again
):
    """(adguard) H1: `tvgw adguard apply` exits 4 when AdGuard Home was not set up by tvgw and serves
    other devices. The install stops right there with 77, never with a failure's 1 or a FAIL's 76, and
    says in one line what tvgw would do to it and the two ways on, with the command for where it ran."""
    root = gateway(tmp_path)
    (root / "etc/tvgw/tvgw.conf").write_text(
        (root / "etc/tvgw/tvgw.conf").read_text(encoding="utf-8") + "ADGUARD_LISTEN=gateway\n",
        encoding="utf-8",
    )
    out, seen = run(root, setup_pass, ADGUARD_RC="4", **extra)
    assert out.returncode == 77, out.stderr
    last = out.stderr.splitlines()[-1].replace(str(root), "")  # the harness moved /etc under root
    assert last == (
        "tvgw: this AdGuard Home serves other devices, and tvgw would move its DNS and its page to this"
        " computer and the TV alone. If nothing else depends on it, set ADGUARD_TAKE_OVER=yes in"
        f" /etc/tvgw/tvgw.conf and run {again}; otherwise put tvgw on a computer of its own, with an"
        " AdGuard Home for the TV alone (docs/install/choosing-a-gateway.md)"
    )
    assert seen[-1] == "tvgw adguard apply", "nothing runs after the refused apply"
    assert not never(seen, "systemctl restart tvgw.service", "systemctl enable --now", "tvgw verify")


def test_with_keep_the_stop_says_only_the_page_moves(tmp_path):
    """With ADGUARD_LISTEN=keep the apply leaves AdGuard's DNS addresses alone: only its page moves."""
    root = gateway(tmp_path)
    out, _ = run(root, None, ADGUARD_RC="4")
    assert out.returncode == 77
    assert "tvgw would move its page to this computer alone." in out.stderr.splitlines()[-1]
