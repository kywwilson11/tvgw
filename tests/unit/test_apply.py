"""tvgw-apply run for real against stub commands: the shell logic and the rules it hands nft.

Nothing under deploy/ runs in CI, so the script runs here with its paths moved into tmp_path and nft,
sysctl, ip, modprobe and flock replaced by stubs on PATH. The nft stub keeps every script it is fed
and lists a fixed table; the sysctl stub writes into a fake /proc/sys and, like procps, fails on a key
whose file does not exist. What nft would make of a rule is the gateway's to say (the hardware suite);
what the script asks of it is checked here."""

import json
import os
import re
import shutil
import subprocess

import pytest
from conftest import ROOT

from tvgw import config, verify

APPLY = (ROOT / "deploy" / "nftables" / "tvgw-apply").read_text()
pytestmark = pytest.mark.skipif(shutil.which("bash") is None, reason="tvgw-apply is a bash script")

STUBS = {
    # every call on one line; a script read from stdin into its own numbered file
    "nft": """#!/bin/sh
printf '%s\\n' "$*" >>"$STUB_DIR/nft.calls"
case "$*" in
"-f -") n=$(ls "$STUB_DIR" | grep -c '^nft-script\\.'); cat >"$STUB_DIR/nft-script.$n" ;;
"-s list table inet tvgw") printf 'table inet tvgw {\\n}\\n' ;;
"-j -t list table "*)  # one counter: how many scripts nft had been fed when it was listed
	n=$(ls "$STUB_DIR" | grep -c '^nft-script\\.')
	printf '{"nftables": [{"rule": {"table": "%s", "comment": "loads", "expr": [{"counter": {"packets": %s, "bytes": 0}}]}}]}\\n' "$6" "$n" ;;
esac
exit 0
""",
    "sysctl": """#!/bin/sh
rc=0
for a in "$@"; do
	case "$a" in
	-*) ;;
	*=*)
		f="$FAKE_PROC/sys/$(printf %s "${a%%=*}" | tr . /)"
		if [ -e "$f" ]; then printf '%s\\n' "${a#*=}" >"$f"; else echo "sysctl: cannot stat $f" >&2; rc=1; fi
		;;
	esac
done
exit $rc
""",
    "ip": """#!/bin/sh
printf '%s\\n' "$*" >>"$STUB_DIR/ip.calls"
exit 0
""",
    "modprobe": "#!/bin/sh\nexit 0\n",
    "flock": "#!/bin/sh\nexit 0\n",
}
PROC = (
    "net/netfilter/nf_conntrack_acct",
    "net/netfilter/nf_conntrack_timestamp",
    "net/netfilter/nf_conntrack_tcp_timeout_established",
    "net/ipv6/conf/eth0/disable_ipv6",
    "net/ipv4/ip_forward",
    "net/ipv4/conf/eth0/forwarding",
    "net/ipv4/conf/wlan0/forwarding",
)
CONF = "UPLINK=direct\nWAN_IF=wlan0\nWAN_GW=203.0.113.1\n"


def run_apply(
    tmp_path, conf: str = CONF, proc: tuple[str, ...] = PROC, stubs: dict[str, str] | None = None
) -> subprocess.CompletedProcess:
    """tvgw-apply with every absolute path it touches moved under tmp_path; `stubs` replaces some."""
    for d in ("bin", "stub", "etc/tvgw", "state", "run/lock"):
        (tmp_path / d).mkdir(parents=True, exist_ok=True)
    for name, body in {**STUBS, **(stubs or {})}.items():
        (tmp_path / "bin" / name).write_text(body)
        (tmp_path / "bin" / name).chmod(0o755)
    for key in proc:
        (tmp_path / "proc" / "sys" / key).parent.mkdir(parents=True, exist_ok=True)
        (tmp_path / "proc" / "sys" / key).write_text("0\n")
    (tmp_path / "etc" / "tvgw" / "tvgw.conf").write_text(conf)
    script = (
        APPLY.replace("/etc/tvgw/", f"{tmp_path}/etc/tvgw/")
        .replace("/var/lib/tvgw", f"{tmp_path}/state")
        .replace("/run/", f"{tmp_path}/run/")
        .replace("/proc/sys/", f"{tmp_path}/proc/sys/")
    )
    (tmp_path / "tvgw-apply").write_text(script)
    env = {
        "PATH": f"{tmp_path / 'bin'}{os.pathsep}{os.environ['PATH']}",
        "STUB_DIR": str(tmp_path / "stub"),
        "FAKE_PROC": str(tmp_path / "proc"),
    }
    return subprocess.run(["bash", str(tmp_path / "tvgw-apply")], env=env, capture_output=True, text=True)


def ruleset(tmp_path) -> str:
    """The first script nft was fed: the inet tvgw table, variables expanded."""
    return (tmp_path / "stub" / "nft-script.0").read_text()


def chain(text: str, name: str) -> list[str]:
    body = re.search(r"chain " + name + r" \{\n(.*?)\n\t\}", text, re.S)
    assert body, name
    return [line.strip() for line in body.group(1).splitlines() if line.strip()]


def test_the_harness_runs_the_script_the_way_the_gateway_does(tmp_path):
    out = run_apply(tmp_path)
    assert out.returncode == 0, out.stderr
    assert "tvgw: applied (uplink=direct via wlan0" in out.stdout
    assert ruleset(tmp_path).startswith("table inet tvgw\ndelete table inet tvgw\n")
    assert (tmp_path / "proc" / "sys" / "net" / "ipv4" / "conf" / "eth0" / "forwarding").read_text() == "1\n"
    assert (tmp_path / "run" / "tvgw" / "ruleset.applied").read_text() == "table inet tvgw {\n}\n"


def test_a_tv_packet_with_a_source_outside_the_subnet_is_dropped_before_anything_accepts_it(tmp_path):
    """Reproduced in a lab container (nft 1.1.3, kernel 6.12): nothing in forward or tv_out looked at
    the source and masquerade covers only 10.10.10.0/24, so with the uplink the main table's default
    (no VPN, or the VPN down) UDP from 198.51.100.33 left by the uplink with that source, unseen by the
    capture, the flow log and the gate, which all key on the TV's addresses."""
    assert run_apply(tmp_path).returncode == 0
    forward = chain(ruleset(tmp_path), "forward")
    guard = next(i for i, line in enumerate(forward) if 'iifname "eth0" ip saddr != 10.10.10.0/24' in line)
    assert forward[guard].split(" comment ")[0].endswith("counter drop")
    assert guard < next(i for i, line in enumerate(forward) if line.startswith("ct state established"))
    assert guard < next(i for i, line in enumerate(forward) if "jump tv_out" in line)


def test_the_counters_are_saved_on_both_sides_of_the_reload(tmp_path):
    """Reproduced on the live store: ten applies a day each zeroed every counter, and what a counter
    gained since the last 10-minute snapshot was lost (the gate read 3 where 11 samples were logged).
    The listings either side of the reload let `tvgw verify --record` store the reset itself."""
    assert run_apply(tmp_path).returncode == 0
    run = tmp_path / "run" / "tvgw"
    tables = ["tvgw", "tvgw_l2", "tvgw_gate"]
    for name, loads in (("counters.before-apply", 0), ("counters.after-apply", 3)):
        lines = (run / name).read_text().splitlines()
        assert [json.loads(line)["nftables"][0]["rule"]["table"] for line in lines] == tables, name
        assert {
            json.loads(line)["nftables"][0]["rule"]["expr"][0]["counter"]["packets"] for line in lines
        } == {loads}, name


def test_a_failed_reload_publishes_no_counter_listings(tmp_path):
    """Nothing was reset, so a before-and-after pair would make verify count a reset that never was."""
    refuses = STUBS["nft"].replace('"-f -") n=', '"-f -") [ -e "$STUB_DIR/nft-script.0" ] || exit 1; n=', 1)
    assert run_apply(tmp_path, stubs={"nft": refuses}).returncode == 1  # the inet table did not load
    assert not list((tmp_path / "run" / "tvgw").glob("counters.*-apply"))


def test_the_settings_an_apply_used_are_what_verify_reads_from_the_same_conf(tmp_path):
    """applied_current compares the conf's firewall keys with what the last apply used; the script's
    defaults and verify's must agree, or every conf edit would read as unapplied."""
    conf = CONF + "ANALYST_EFFORT=medium\nSTRICT_PORTS=no # count only\n"
    assert run_apply(tmp_path, conf=conf).returncode == 0
    used = config.parse_conf((tmp_path / "run" / "tvgw" / "settings.applied").read_text())
    assert (
        used
        == verify.apply_settings(conf)
        == {
            "UPLINK": "direct",
            "WAN_IF": "wlan0",
            "WAN_GW": "203.0.113.1",
            "BLOCK_QUIC": "yes",
            "STRICT_PORTS": "no",
            "DNSGATE": "count",
        }
    )


def test_a_vpn_mode_boot_apply_succeeds_before_the_tunnel_exists(tmp_path):
    """Reproduced: at boot tun0 appears only once the VPN connects, procps' sysctl exits 1 on a key it
    cannot stat, and set -e stopped the script after ip_forward was on: no baseline, no policy routing,
    tvgw.service failed, and the capture units that follow it never started that boot."""
    out = run_apply(tmp_path, conf="UPLINK=vpn\n")
    assert out.returncode == 0, out.stderr
    assert "tun0 not there yet" in out.stderr
    proc = tmp_path / "proc" / "sys" / "net" / "ipv4"
    assert (proc / "ip_forward").read_text() == (proc / "conf" / "eth0" / "forwarding").read_text() == "1\n"
    assert (tmp_path / "run" / "tvgw" / "ruleset.applied").exists()
    # once the tunnel is up the dispatcher's apply switches it on like any uplink
    assert (
        run_apply(tmp_path, conf="UPLINK=vpn\n", proc=(*PROC, "net/ipv4/conf/tun0/forwarding")).returncode
        == 0
    )
    assert (proc / "conf" / "tun0" / "forwarding").read_text() == "1\n"
