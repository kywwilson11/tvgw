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
        .replace("/var/lib/misc/", f"{tmp_path}/misc/")  # (guard) dnsmasq's leases, read for the pin
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
    # (guard) the guard last; (ntp) the NTP count's table too, whose rule's total a reload zeroes, while
    # its set keeps every address's count
    tables = ["tvgw", "tvgw_l2", "tvgw_gate", "tvgw_ntp", "tvgw_capture", "tvgw_guard"]
    # after: inet tvgw, the IPv6 guard, the gate and the NTP count, four loads
    for name, loads in (("counters.before-apply", 0), ("counters.after-apply", 4)):
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
    assert used.pop("WAN_GW_USED") == "203.0.113.1"  # (uplink) the address the routes use, beside the keys
    # (ports) what the profile said and what was built, beside the key: here no tvgw to read the profile
    # with, so it is unread and the port stays open, as before the key existed
    assert (used.pop("CLOCK_PORT_PROFILE"), used.pop("CLOCK_PORT_USED")) == ("unread", "any")
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
            "DNSGATE_FILL": "passive",  # (inpath) absent from the conf: the default
            "NAME_BINDING": "off",  # (namebound) absent from the conf: the default
            # (packaging) the TV side, defaulted as Settings defaults it
            "TV_IF": "eth0",
            "TV_NET": "10.10.10.0/24",
            "GW_IP": "10.10.10.1",
            "CAPTURE_MODE": "full",  # (capture)
            "TV_IP": "10.10.10.17",  # (guard) the pin's inputs, defaulted as Settings defaults them
            "TV_MAC": "",
            "VPN_IF": "auto",  # (events)
            "ADTECH_PORT_WALL": "yes",  # (acr) on unless the conf says no
            "PROFILE": "lg-webos",  # (profile) the default for a conf without the key
            "WAN_GW_MODE": "literal",  # (uplink) what a conf without the key means
            "TV_PROBE": "off",  # (probe) off unless the conf turns it on, at the default address
            "TV_PROBE_IP": "10.10.10.30",
            "CLOCK_PORT": "profile",  # (ports) the profile's [firewall] ntp, unless the conf says otherwise
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


# ---- (capture) CAPTURE_MODE=headers: the table the headers capture reads from (docs/how-it-works/capture.md) ----


def scripts(tmp_path) -> list[str]:
    """Every script nft was fed, in order."""
    files = sorted((tmp_path / "stub").glob("nft-script.*"), key=lambda p: int(p.suffix[1:]))
    return [p.read_text(encoding="utf-8") for p in files]


# ---- (ntp) the clock servers the TV uses, counted by address (design decision 17, its note of 2026-11-05) ----

NTP_SCRIPT = (
    "add table inet tvgw_ntp\n"
    "add set inet tvgw_ntp ntp4 { type ipv4_addr; flags dynamic, timeout; timeout 10d; size 1024; }\n"
    "add chain inet tvgw_ntp forward { type filter hook forward priority filter + 20; policy accept; }\n"
    "flush chain inet tvgw_ntp forward\n"
    'add rule inet tvgw_ntp forward iifname "eth0" ip saddr 10.10.10.0/24 udp dport 123 counter'
    ' update @ntp4 { ip daddr counter } comment "NTP from the TV, by server"\n'
)


@pytest.mark.parametrize("conf", ["", "DNSGATE=off\n", "UPLINK=vpn\n", "CAPTURE_MODE=headers\n"])
def test_the_ntp_count_is_its_own_table_that_a_reapply_keeps_and_that_refuses_nothing(tmp_path, conf):
    """A table of its own written with `add` (so a re-apply keeps the set's addresses and their counts)
    after every forward chain that can refuse, one rule with no verdict, and a bounded set whose
    elements expire 10 days after their last request, far from any poll period (a day made a daily sync
    a new element every day). The same in every mode: no switch turns it off."""
    out = run_apply(tmp_path, conf=CONF + conf)
    assert out.returncode == 0, out.stderr
    loaded = scripts(tmp_path)
    (ntp,) = [s for s in loaded if "tvgw_ntp" in s]
    assert ntp == NTP_SCRIPT
    assert "delete" not in ntp and "tvgw_ntp" not in loaded[0]  # never deleted, never in inet tvgw
    (rule,) = [line for line in ntp.splitlines() if line.startswith("add rule")]
    assert not re.search(r"\b(accept|drop|reject|queue|jump|goto|return)\b", rule.split(" comment ")[0])
    calls = (tmp_path / "stub" / "nft.calls").read_text(encoding="utf-8").splitlines()
    # the set's terse listing before the load, found empty here, and the counters either side of the
    # reload; no delete
    assert [c for c in calls if "tvgw_ntp" in c] == [
        "-j -t list table inet tvgw_ntp",
        "-t list set inet tvgw_ntp ntp4",
        "-j -t list table inet tvgw_ntp",
    ]
    # the guard forwards at filter + 10 and inet tvgw at filter - 10: the count comes after both
    assert "priority filter + 20;" in ntp


# the set as nft 1.1 lists it with -t, as this script writes it, and as the first build of the count did
NTP_SET_NOW = (
    "table inet tvgw_ntp {\n\tset ntp4 {\n\t\ttype ipv4_addr\n\t\tsize 1024\n"
    "\t\tflags dynamic,timeout\n\t\ttimeout 10d\n\t}\n}\n"
)
NTP_SET_OLD = NTP_SET_NOW.replace("timeout 10d", "timeout 1d")


@pytest.mark.parametrize(
    ("listed", "remade"),
    [
        (NTP_SET_NOW, False),
        (NTP_SET_NOW.replace("flags dynamic,timeout", "flags timeout,dynamic"), False),
        (NTP_SET_OLD, True),  # the first build's day: the kernel would refuse the batch at every apply
        (NTP_SET_NOW.replace("size 1024", "size 65536"), True),
        (NTP_SET_NOW.replace("\t\tflags dynamic,timeout\n", ""), True),
        (NTP_SET_NOW.replace("ipv4_addr", "ipv4_addr . inet_service"), True),
    ],
)
def test_a_set_of_other_properties_is_deleted_and_made_again_before_the_load(tmp_path, listed, remade):
    """The kernel never changes an existing set's size or timeout, and nft refuses an `add set` that
    differs from the set there, failing the whole batch: the table would stay as it was at every apply.
    So the script reads the set's terse listing first and, when it is not the set it writes, deletes
    the table and says so; the load then makes it again, its counts from zero."""
    case = '"-t list set inet tvgw_ntp ntp4") printf \'%s\' "$LISTED" ;;\n'
    stub = STUBS["nft"].replace('case "$*" in\n', 'case "$*" in\n' + case, 1)
    env_stub = stub.replace("#!/bin/sh\n", '#!/bin/sh\nLISTED=$(cat "$STUB_DIR/listed")\n', 1)
    (tmp_path / "stub").mkdir(parents=True, exist_ok=True)
    (tmp_path / "stub" / "listed").write_text(listed, encoding="utf-8")
    out = run_apply(tmp_path, stubs={"nft": env_stub})
    assert out.returncode == 0, out.stderr
    calls = (tmp_path / "stub" / "nft.calls").read_text(encoding="utf-8").splitlines()
    assert ("delete table inet tvgw_ntp" in calls) == remade
    assert ("held a set of other properties" in out.stderr) == remade
    if remade:  # deleted before the load that makes it again
        loads = [i for i, c in enumerate(calls) if c == "-f -"]
        assert calls.index("delete table inet tvgw_ntp") < loads[3]
    (ntp,) = [s for s in scripts(tmp_path) if "tvgw_ntp" in s]
    assert ntp == NTP_SCRIPT


def test_an_ntp_table_nft_refuses_only_warns_and_the_tv_stays_online(tmp_path):
    """A kernel without dynamic sets' per-element counters, say: the count is missing and nothing
    else is. The NTP the TV sends goes through the filter's own accept as it always has."""
    keep = 'cat >"$STUB_DIR/nft-script.$n" ;;'
    refuses = STUBS["nft"].replace(
        keep, 'cat >"$STUB_DIR/nft-script.$n"; ! grep -q tvgw_ntp "$STUB_DIR/nft-script.$n" || exit 1 ;;'
    )
    out = run_apply(tmp_path, stubs={"nft": refuses})
    assert out.returncode == 0, out.stderr
    assert "tvgw: NTP count table not loaded" in out.stderr
    assert (tmp_path / "proc" / "sys" / "net" / "ipv4" / "conf" / "eth0" / "forwarding").read_text(
        encoding="utf-8"
    ) == "1\n"
    assert (tmp_path / "run" / "tvgw" / "ruleset.applied").exists()
    assert "tvgw: applied (uplink=direct" in out.stdout


def test_ntp_stays_open_to_any_address_in_the_filter(tmp_path):
    """Design decision 17 keeps UDP 123 open: the count changes nothing in inet tvgw, where 123 is still
    one of the three ports the odd-port rules leave alone."""
    assert run_apply(tmp_path, conf=CONF + "STRICT_PORTS=yes\n").returncode == 0
    tv_out = chain(ruleset(tmp_path), "tv_out")
    assert [line for line in tv_out if "123" in line] == [
        'meta l4proto { tcp, udp } th dport != { 80, 123, 443 } limit rate 6/minute log prefix "tvgw-oddport: "'
        ' comment "unexpected port"',
        "meta l4proto { tcp, udp } th dport != { 80, 123, 443 } counter reject with icmpx admin-prohibited"
        ' comment "STRICT_PORTS: only web, NTP and DNS"',
    ]


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


# ---- (guard) the source pinning of design decision 42 -------------------------------------------------

MAC = "aa:bb:cc:00:11:22"  # a placeholder, not any device's


def test_the_input_chain_drops_a_forged_source_before_anything_answers(tmp_path):
    """A home-LAN host's address as the source of a query to the resolver makes the Pi answer that
    host (11 F4): the source rule comes before the DNS counter and the established shortcut."""
    assert run_apply(tmp_path).returncode == 0
    inp = [ln for ln in chain(ruleset(tmp_path), "input") if not ln.startswith("#")]
    at = next(i for i, ln in enumerate(inp) if ln.startswith("ip saddr != { 0.0.0.0, 10.10.10.0/24 }"))
    assert inp[at].endswith('counter drop comment "TV source outside its subnet (input)"')
    assert inp[at - 1] == 'iifname != "eth0" accept'
    assert at < next(i for i, ln in enumerate(inp) if "TV DNS to the gateway" in ln)
    assert at < next(i for i, ln in enumerate(inp) if ln.startswith("ct state established"))


def test_strict_reverse_path_filtering_is_set_on_the_tv_port_when_it_exists(tmp_path):
    proc = (*PROC, "net/ipv4/conf/eth0/rp_filter")
    assert run_apply(tmp_path, proc=proc).returncode == 0
    assert (tmp_path / "proc" / "sys" / "net" / "ipv4" / "conf" / "eth0" / "rp_filter").read_text(
        encoding="utf-8"
    ) == "1\n"
    assert run_apply(tmp_path / "noport").returncode == 0  # no key (the port not there yet): no stop


@pytest.mark.parametrize(
    ("conf", "pinned"),
    [
        ("", None),  # a fresh install: no TV identity yet
        ("TV_MAC=00:00:00:00:00:00\nTV_IP=10.10.10.17\n", None),  # the template's placeholder
        (f"TV_MAC={MAC}\nTV_IP=10.10.10.300\n", None),  # an address tv_ip_ok refuses
        (f"TV_MAC={MAC}\nTV_IP=10.10.10.17\n", "10.10.10.17"),
    ],
)
def test_forward_pins_the_tv_once_its_mac_is_known(tmp_path, conf, pinned):
    """A second address in the TV subnet escapes the flow log and the HTTPS strip (11 F5): once the
    TV is pinned only TV_IP forwards, checked right after the subnet rule, before anything accepts."""
    out = run_apply(tmp_path, conf=CONF + conf)
    assert out.returncode == 0, out.stderr
    forward = [ln for ln in chain(ruleset(tmp_path), "forward") if not ln.startswith("#")]
    pins = [ln for ln in forward if "TV source is not the TV" in ln]
    if pinned is None:
        assert pins == [] and "tv_pin=none" in out.stdout
        return
    assert pins == [
        f'iifname "eth0" ip saddr != {{ {pinned} }} counter drop comment "TV source is not the TV"'
    ]
    sub = next(i for i, ln in enumerate(forward) if "TV source outside its subnet" in ln)
    assert forward.index(pins[0]) == sub + 1
    assert forward.index(pins[0]) < next(
        i for i, ln in enumerate(forward) if ln.startswith("ct state established")
    )


def test_the_old_lease_keeps_forwarding_until_the_tv_takes_its_new_address(tmp_path):
    """TV_IP edited while the TV holds its old lease: dnsmasq moves it at the renewal, up to six hours
    away. That lease's address forwards until then, or the TV would be dark; an expired lease, another
    device's lease, and a lease outside TV_NET do not."""
    (tmp_path / "misc").mkdir()
    far = 4102444800  # 2100-01-01
    (tmp_path / "misc" / "dnsmasq.leases").write_text(
        f"{far} {MAC.upper()} 10.10.10.15 tv *\n"
        f"1000 {MAC} 10.10.10.16 tv *\n"  # expired
        f"{far} 02:00:00:00:00:99 10.10.10.18 laptop *\n"  # someone else
        f"0 {MAC} 192.0.2.7 tv *\n"  # an infinite lease outside TV_NET
        "garbage\n",
        encoding="utf-8",
    )
    out = run_apply(tmp_path, conf=CONF + f"TV_MAC={MAC}\nTV_IP=10.10.10.17\n")
    assert out.returncode == 0, out.stderr
    assert "ip saddr != { 10.10.10.17, 10.10.10.15 }" in ruleset(tmp_path)
    assert "still holds 10.10.10.15" in out.stderr and "tv_pin=10.10.10.17, 10.10.10.15" in out.stdout


# ---- the TV subnet in table 100: the gateway's own answers to the TV (design decision 49) ------------

# the route as `ip route show table 100 10.10.10.0/24` prints it, and the call that writes it
TV_SUBNET = "10.10.10.0/24 dev eth0 scope link src 10.10.10.1"
SUBNET_REPLACE = "route replace 10.10.10.0/24 dev eth0 scope link src 10.10.10.1 table 100"
ROUTING_WRITES = ("route replace", "route add", "route del", "rule add", "rule del")


def routed_ip(subnet: str | None = TV_SUBNET, replace_fails: bool = False) -> str:
    """ip, answering the apply's routing questions as a gateway whose rule 60 and table-100 default
    are already right; table 100's TV-subnet route prints as `subnet` (None: absent). With
    `replace_fails` a replace of that route fails, as it does at boot while GW_IP is not on the port."""
    answers = [
        "\"rule show priority 60\") printf '60:\\tfrom 10.10.10.0/24 lookup 100 \\n' ;;",
        '"route show table 100 default") echo "default via 203.0.113.1 dev wlan0 " ;;',
    ]
    if subnet is not None:
        answers.append(f'"route show table 100 10.10.10.0/24") echo "{subnet} " ;;')
    if replace_fails:
        answers.append(
            '"route replace 10.10.10.0/24 "*) echo "Error: Invalid prefsrc address." >&2; exit 2 ;;'
        )
    return STUBS["ip"].replace("exit 0\n", 'case "$*" in\n' + "\n".join(answers) + "\nesac\nexit 0\n")


def ip_writes(tmp_path) -> list[str]:
    """Every call that changed a route or a rule, in order."""
    path = tmp_path / "stub" / "ip.calls"
    calls = path.read_text(encoding="utf-8").splitlines() if path.exists() else []
    return [c for c in calls if c.startswith(ROUTING_WRITES)]


def routing_class(tmp_path) -> str:
    """The change ledger's class for the apply: whether it touched the policy routing."""
    (line,) = (tmp_path / "state" / "changes.spool").read_text(encoding="utf-8").splitlines()
    return line.split("\t")[3]


def test_a_missing_tv_subnet_is_added_to_table_100_once(tmp_path):
    """Rule 60 also sends what the gateway itself sends to the TV from 10.10.10.1 into table 100, which
    held only the default route: on a gateway with no VPN client the TV's DNS answers left by the
    uplink. The route is the one write, and the ledger says the apply changed routing."""
    out = run_apply(tmp_path, stubs={"ip": routed_ip(subnet=None)})
    assert out.returncode == 0, out.stderr
    assert ip_writes(tmp_path) == [SUBNET_REPLACE]
    assert routing_class(tmp_path) == "changed"


@pytest.mark.parametrize("printed", [TV_SUBNET, f"{TV_SUBNET} linkdown"], ids=["up", "no-carrier"])
def test_a_tv_subnet_route_that_is_already_right_is_left_alone(tmp_path, printed):
    """A replace of an unchanged route destroyed the conntrack entry of a live connection (the
    2026-10-30 incident), so the apply compares first. With the TV off the port has no carrier and
    ip prints the same route with a trailing linkdown: still the route the apply wants."""
    out = run_apply(tmp_path, stubs={"ip": routed_ip(subnet=printed)})
    assert out.returncode == 0, out.stderr
    assert ip_writes(tmp_path) == []
    assert routing_class(tmp_path) == "unchanged"


@pytest.mark.parametrize(
    "printed",
    [
        "10.10.10.0/24 dev eth1 scope link src 10.10.10.1",  # another port
        "10.10.10.0/24 dev eth0 scope link",  # no source address
        "10.10.10.0/24 via 203.0.113.1 dev wlan0",  # by the uplink
        "10.10.10.0/24 dev eth0 scope link src 10.10.10.10",  # another source, GW_IP as its prefix
    ],
)
def test_a_tv_subnet_route_that_differs_is_replaced(tmp_path, printed):
    out = run_apply(tmp_path, stubs={"ip": routed_ip(subnet=printed)})
    assert out.returncode == 0, out.stderr
    assert ip_writes(tmp_path) == [SUBNET_REPLACE]
    assert routing_class(tmp_path) == "changed"


def test_a_tv_port_without_its_address_yet_only_says_so_and_the_apply_finishes(tmp_path):
    """At boot tvgw.service can apply before tv-lan has put GW_IP on the port, and `src GW_IP` makes the
    replace fail. Under set -e that would stop the apply after forwarding was on, with no ledger line;
    the dispatcher's apply when the port comes up adds the route."""
    out = run_apply(tmp_path, stubs={"ip": routed_ip(subnet=None, replace_fails=True)})
    assert out.returncode == 0, out.stderr
    assert "tvgw: eth0 not up yet; the dispatcher adds the TV subnet to table 100" in out.stderr
    assert "tvgw: applied (uplink=direct via wlan0" in out.stdout
    assert ip_writes(tmp_path) == [SUBNET_REPLACE]
    assert routing_class(tmp_path) == "changed"


def test_vpn_mode_removes_rule_60_and_asks_nothing_of_table_100(tmp_path):
    """Without rule 60 the gateway's answers to the TV follow the main table's route on the TV port, so
    vpn mode needs no route of its own; the stop path is unchanged too."""
    out = run_apply(tmp_path, conf="UPLINK=vpn\n", stubs={"ip": routed_ip(subnet=None)})
    assert out.returncode == 0, out.stderr
    assert ip_writes(tmp_path) == ["rule del priority 60"]
    calls = (tmp_path / "stub" / "ip.calls").read_text(encoding="utf-8").splitlines()
    assert not [c for c in calls if "table 100" in c]
