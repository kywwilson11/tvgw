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

APPLY = (ROOT / "deploy" / "nftables" / "tvgw-apply").read_text(encoding="utf-8")
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
    return (tmp_path / "stub" / "nft-script.0").read_text(encoding="utf-8")


def chain(text: str, name: str) -> list[str]:
    body = re.search(r"chain " + name + r" \{\n(.*?)\n\t\}", text, re.S)
    assert body, name
    return [line.strip() for line in body.group(1).splitlines() if line.strip()]


def test_the_harness_runs_the_script_the_way_the_gateway_does(tmp_path):
    out = run_apply(tmp_path)
    assert out.returncode == 0, out.stderr
    assert "tvgw: applied (uplink=direct via wlan0" in out.stdout
    assert ruleset(tmp_path).startswith("table inet tvgw\ndelete table inet tvgw\n")
    assert (tmp_path / "proc" / "sys" / "net" / "ipv4" / "conf" / "eth0" / "forwarding").read_text(
        encoding="utf-8"
    ) == "1\n"
    assert (tmp_path / "run" / "tvgw" / "ruleset.applied").read_text(
        encoding="utf-8"
    ) == "table inet tvgw {\n}\n"


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
    tables = ["tvgw", "tvgw_l2", "tvgw_gate", "tvgw_capture", "tvgw_guard"]  # (guard) the last
    for name, loads in (("counters.before-apply", 0), ("counters.after-apply", 3)):
        lines = (run / name).read_text(encoding="utf-8").splitlines()
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
    used = config.parse_conf((tmp_path / "run" / "tvgw" / "settings.applied").read_text(encoding="utf-8"))
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
            # (packaging) the TV side, defaulted as Settings defaults it
            "TV_IF": "eth0",
            "TV_NET": "10.10.10.0/24",
            "GW_IP": "10.10.10.1",
            "CAPTURE_MODE": "full",  # (capture)
            "TV_IP": "10.10.10.17",  # (guard) the pin's inputs, defaulted as Settings defaults them
            "TV_MAC": "",
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
    assert (
        (proc / "ip_forward").read_text(encoding="utf-8")
        == (proc / "conf" / "eth0" / "forwarding").read_text(encoding="utf-8")
        == "1\n"
    )
    assert (tmp_path / "run" / "tvgw" / "ruleset.applied").exists()
    # once the tunnel is up the dispatcher's apply switches it on like any uplink
    assert (
        run_apply(tmp_path, conf="UPLINK=vpn\n", proc=(*PROC, "net/ipv4/conf/tun0/forwarding")).returncode
        == 0
    )
    assert (proc / "conf" / "tun0" / "forwarding").read_text(encoding="utf-8") == "1\n"


def test_the_gate_counts_a_connection_once_however_often_its_first_packet_is_sent(tmp_path):
    """Reproduced in a lab container (nft 1.1.3, kernel 6.12): one connect to an address that never
    answers and one unanswered three-datagram UDP flow counted 10, since conntrack calls every packet
    new until a reply. The rule now counts a flow's tuple only when it is not yet in seen4."""
    assert run_apply(tmp_path).returncode == 0
    gate = (tmp_path / "stub" / "nft-script.2").read_text(encoding="utf-8")
    assert "add set inet tvgw_gate seen4 {" in gate and "flags dynamic, timeout; timeout 2m;" in gate
    (rule,) = [line for line in gate.splitlines() if line.startswith("add rule inet tvgw_gate forward")]
    tuple_ = "ip saddr . ip daddr . meta l4proto . th sport . th dport"
    assert f"{tuple_} != @seen4 add @seen4 {{ {tuple_} }} counter limit rate 6/minute log" in rule


def test_the_tunnel_protocol_drop_logs_a_sample_and_still_drops_every_packet(tmp_path):
    """Reproduced: the drop logged every GRE/ESP/SCTP packet with no limit (a dropped packet never
    confirms its conntrack entry, so each one reached the rule) and journald does not rate-limit the
    kernel, so the TV could rotate the oddport and gate samples out of the journal before ingest read
    them. The log is a rule of its own with a limit, like the odd-port one: a limit on the drop itself
    would let the packets over the rate fall through to tv_out's final accept."""
    assert run_apply(tmp_path).returncode == 0
    tv_out = chain(ruleset(tmp_path), "tv_out")
    proto = [i for i, line in enumerate(tv_out) if line.startswith("meta l4proto != { tcp, udp, icmp }")]
    log, drop = (tv_out[i] for i in proto)
    assert log == 'meta l4proto != { tcp, udp, icmp } limit rate 6/minute log prefix "tvgw-proto: "'
    assert drop.split(" comment ")[0] == "meta l4proto != { tcp, udp, icmp } counter drop"
    ruleset_lines = ruleset(tmp_path).splitlines()
    assert not [
        line for line in ruleset_lines if "limit rate" in line and re.search(r"\b(drop|reject)\b", line)
    ]


# ---- (capture) CAPTURE_MODE=headers: the table the headers capture reads from (docs/capture.md) ----


def scripts(tmp_path) -> list[str]:
    """Every script nft was fed, in order."""
    files = sorted((tmp_path / "stub").glob("nft-script.*"), key=lambda p: int(p.suffix[1:]))
    return [p.read_text(encoding="utf-8") for p in files]


def test_full_mode_loads_no_capture_table_and_removes_a_left_over_one(tmp_path):
    assert run_apply(tmp_path).returncode == 0
    assert not [s for s in scripts(tmp_path) if "tvgw_capture" in s]
    calls = (tmp_path / "stub" / "nft.calls").read_text(encoding="utf-8").splitlines()
    assert "delete table inet tvgw_capture" in calls


def test_headers_mode_loads_the_capture_table_after_the_filter_and_changes_nothing_in_it(tmp_path):
    """The filter a headers gateway loads is byte for byte the full one's: the capture is a table of
    its own, loaded after inet tvgw, with one base chain that only counts and logs."""
    assert run_apply(tmp_path).returncode == 0
    full = scripts(tmp_path)[0]
    other = tmp_path / "headers"
    out = run_apply(other, conf=CONF + "CAPTURE_MODE=headers\n")
    assert out.returncode == 0, out.stderr
    loaded = scripts(other)
    assert loaded[0] == full
    (capture,) = [s for s in loaded if "tvgw_capture" in s]
    assert loaded.index(capture) > 0
    assert capture.startswith("table inet tvgw_capture\ndelete table inet tvgw_capture\n")
    pre = chain(capture, "pre")
    assert pre[0] == "type filter hook prerouting priority mangle - 5; policy accept;"
    assert pre[1] == (
        'iifname "eth0" ip saddr 10.10.10.0/24 ip saddr != 10.10.10.1 ct original packets != 0 '
        "ct original packets <= 8 counter log group 7 snaplen 4096 queue-threshold 1 "
        'comment "capture: the first packets of each TV connection"'
    )
    assert pre[2] == (
        'iifname "eth0" ip saddr 10.10.10.0/24 ip saddr != 10.10.10.1 tcp dport 80 ct original packets > 8 '
        'counter log group 7 queue-threshold 1 comment "capture: plain HTTP after them"'
    )
    assert len(pre) == 3
    used = config.parse_conf((other / "run" / "tvgw" / "settings.applied").read_text(encoding="utf-8"))
    assert used["CAPTURE_MODE"] == "headers"
    assert (
        "delete table inet tvgw_capture"
        not in (other / "stub" / "nft.calls").read_text(encoding="utf-8").splitlines()
    )


def test_a_capture_table_nft_refuses_only_warns_and_the_tv_stays_online(tmp_path):
    """nfnetlink_log missing, a kernel without the ct expression: the headers capture records nothing,
    and verify says so; the TV is forwarded through the filter as before."""
    keep = 'cat >"$STUB_DIR/nft-script.$n" ;;'
    assert keep in STUBS["nft"]
    refuses = STUBS["nft"].replace(  # kept like every script, then refused when it is the capture's
        keep, 'cat >"$STUB_DIR/nft-script.$n"; ! grep -q tvgw_capture "$STUB_DIR/nft-script.$n" || exit 1 ;;'
    )
    out = run_apply(tmp_path, conf=CONF + "CAPTURE_MODE=headers\n", stubs={"nft": refuses})
    assert out.returncode == 0, out.stderr
    assert "tvgw: capture table not loaded" in out.stderr
    assert (tmp_path / "proc" / "sys" / "net" / "ipv4" / "conf" / "eth0" / "forwarding").read_text(
        encoding="utf-8"
    ) == "1\n"
    assert (tmp_path / "run" / "tvgw" / "ruleset.applied").exists()
    assert "tvgw_capture" in scripts(tmp_path)[-1]  # it was tried, after the filter loaded


@pytest.mark.parametrize("mode", ["Headers", "both", "on"])
def test_a_capture_mode_near_miss_stops_the_apply_before_anything_is_loaded(tmp_path, mode):
    """Exact, like every switch the script reads: config.load refuses the same values."""
    out = run_apply(tmp_path, conf=CONF + f"CAPTURE_MODE={mode}\n")
    assert out.returncode == 1 and "CAPTURE_MODE must be full or headers" in out.stderr
    assert scripts(tmp_path) == []
    assert (tmp_path / "proc" / "sys" / "net" / "ipv4" / "ip_forward").read_text(encoding="utf-8") == "0\n"
