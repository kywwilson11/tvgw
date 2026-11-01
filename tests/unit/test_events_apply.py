"""(events) What the events workstream changed in the deploy tree, run for real against stubs: the
ct_events chain and the conntrack events switch, VPN_IF in tvgw-apply, the dispatcher and Python,
the count-only leak rules, the sysctl.d file and the flow logger's unit (design decisions 43 and 44).

tvgw-apply runs as in test_apply.py, its paths moved under tmp_path; the dispatcher runs with its
tvgw-apply replaced by a stub that says it ran. Whether nft accepts the rendered text is the virtual
suite's question (tests/virtual/test_virtual_rulesets.py)."""

import os
import re
import shutil
import subprocess

import pytest
from conftest import ROOT, UNITS, exec_lines
from test_apply import CONF, PROC, STUBS, chain, ruleset, run_apply

from tvgw import config

pytestmark = pytest.mark.skipif(shutil.which("bash") is None, reason="tvgw-apply is a bash script")
EVENTS = "net/netfilter/nf_conntrack_events"
APPLY = (ROOT / "deploy" / "nftables" / "tvgw-apply").read_text(encoding="utf-8")
SYSCTL_D = ROOT / "deploy" / "sysctl" / "60-tvgw.conf"


def ordered_stubs() -> dict[str, str]:
    """nft and sysctl stubs that also write one shared log, so a test can see which came first."""
    log = 'printf "%s %s\\n" "$(basename "$0")" "$*" >>"$STUB_DIR/order"\n'
    return {name: STUBS[name].replace("#!/bin/sh\n", "#!/bin/sh\n" + log, 1) for name in ("nft", "sysctl")}


def read_proc(tmp_path, key: str) -> str:
    return (tmp_path / "proc" / "sys" / key).read_text(encoding="utf-8")


# ---- conntrack events from the ruleset ---------------------------------------------------------------


def test_the_tvs_new_connections_are_marked_and_events_go_off_after_the_table_loads(tmp_path):
    out = run_apply(tmp_path, proc=(*PROC, EVENTS), stubs=ordered_stubs())
    assert out.returncode == 0, out.stderr
    rules = chain(ruleset(tmp_path), "ct_events")
    assert rules == [
        "type filter hook prerouting priority -150; policy accept;",
        'iifname "eth0" ip saddr 10.10.10.0/24 ct state new ct event set destroy comment'
        ' "flow log: TV connections only"',
    ]
    assert read_proc(tmp_path, EVENTS) == "0\n"
    order = (tmp_path / "stub" / "order").read_text(encoding="utf-8").splitlines()
    loaded = order.index("nft -f -")  # the first load is inet tvgw
    switched = order.index("sysctl -q -w net.netfilter.nf_conntrack_events=0")
    assert loaded < switched, order  # set first, the connections in between would have no events


def test_the_rule_follows_the_tv_side(tmp_path):
    conf = CONF + "TV_IF=enp1s0\nTV_NET=10.20.30.0/24\nGW_IP=10.20.30.1\nTV_IP=10.20.30.17\n"
    proc = (*(p.replace("/eth0/", "/enp1s0/") for p in PROC), EVENTS)
    assert run_apply(tmp_path, conf=conf, proc=proc).returncode == 0
    (rule,) = chain(ruleset(tmp_path), "ct_events")[1:]
    assert rule.startswith('iifname "enp1s0" ip saddr 10.20.30.0/24 ct state new ct event set destroy')


def test_a_kernel_without_conntrack_events_keeps_the_tv_online_without_the_rule(tmp_path):
    """No sysctl key means no CONFIG_NF_CONNTRACK_EVENTS, and nft would refuse `ct event set` and with
    it the whole table: the TV would stay dark for a flow log that cannot work there anyway."""
    out = run_apply(tmp_path, proc=PROC, stubs=ordered_stubs())  # no events key
    assert out.returncode == 0, out.stderr
    assert "no conntrack events" in out.stderr
    assert chain(ruleset(tmp_path), "ct_events") == [
        "type filter hook prerouting priority -150; policy accept;"
    ]
    order = (tmp_path / "stub" / "order").read_text(encoding="utf-8")
    assert "nf_conntrack_events" not in order
    assert read_proc(tmp_path, "net/ipv4/conf/eth0/forwarding") == "1\n"


def test_a_switch_that_will_not_take_does_not_keep_the_tv_dark(tmp_path):
    refusing = STUBS["sysctl"].replace("*=*)\n", "*nf_conntrack_events*) exit 1 ;;\n\t*=*)\n", 1)
    out = run_apply(tmp_path, proc=(*PROC, EVENTS), stubs={"sysctl": refusing})
    assert out.returncode == 0, out.stderr
    assert "nf_conntrack_events not set" in out.stderr
    assert read_proc(tmp_path, "net/ipv4/conf/eth0/forwarding") == "1\n"


# ---- the sysctl.d file ---------------------------------------------------------------------------------


def sysctl_d() -> dict[str, str]:
    pairs = {}
    for line in SYSCTL_D.read_text(encoding="utf-8").splitlines():
        if line.strip() and not line.lstrip().startswith(("#", ";")):
            key, eq, value = line.partition("=")
            assert eq, line
            pairs[key.strip()] = value.strip()
    return pairs


def apply_sysctls() -> dict[str, str]:
    """Every `key=value` tvgw-apply writes with a literal value (net.netfilter only)."""
    return dict(re.findall(r"\b(net\.netfilter\.[a-z_]+)=(\d+)\b", APPLY))


def test_the_sysctl_file_says_what_the_apply_sets():
    """One truth in two places: the file holds at boot what every apply writes."""
    file = sysctl_d()
    assert file == {
        "net.netfilter.nf_conntrack_acct": "1",
        "net.netfilter.nf_conntrack_timestamp": "1",
        "net.netfilter.nf_conntrack_events": "0",
    }
    script = apply_sysctls()
    assert {k: script[k] for k in file} == file


def test_the_sysctl_values_the_file_names_are_the_ones_an_apply_writes(tmp_path):
    keys = [k.replace(".", "/") for k in sysctl_d()]
    for key in keys:  # start each from the opposite of what is wanted
        assert key in (*PROC, EVENTS)
    assert run_apply(tmp_path, proc=(*PROC, EVENTS)).returncode == 0
    assert {k: read_proc(tmp_path, k.replace(".", "/")).strip() for k in sysctl_d()} == sysctl_d()


def test_install_ships_the_file_and_the_package_removes_it():
    install = (ROOT / "deploy" / "install.sh").read_text(encoding="utf-8")
    assert "install -D -m 644 sysctl/60-tvgw.conf /etc/sysctl.d/60-tvgw.conf" in install
    postrm = (ROOT / "packaging" / "scripts" / "postrm").read_text(encoding="utf-8")
    assert "rm -f /etc/sysctl.d/60-tvgw.conf" in postrm


def test_the_flow_logger_asks_for_no_buffer_it_never_gets():
    """conntrack-tools 1.4.8 applies -b to its request socket, not to the event socket it reads: the
    32 MB of 2026-10-31 did nothing. The TV filter stays as the second one."""
    ((_, value),) = [(k, v) for k, v in exec_lines("tvgw-flowlog.service") if k == "ExecStart"]
    assert " -b " not in value and "--orig-src" in value and "-e DESTROY" in value
    assert (
        "-b"
        not in (UNITS / "tvgw-flowlog.service").read_text(encoding="utf-8").split("ExecStart=")[1].split()
    )


# ---- VPN_IF in tvgw-apply ----------------------------------------------------------------------------


def input_drop(tmp_path) -> str:
    (rule,) = [r for r in chain(ruleset(tmp_path), "input") if "nothing unsolicited from the VPN side" in r]
    return rule


def test_auto_drops_both_pia_tunnels_and_counts_the_pis_leaks(tmp_path):
    assert run_apply(tmp_path).returncode == 0
    assert input_drop(tmp_path).startswith('iifname { "tun0", "wgpia0" } ct state new counter drop')
    leaks = chain(ruleset(tmp_path), "post_leaks")
    assert leaks == [
        "type filter hook postrouting priority srcnat - 20; policy accept;",
        'oifname "wlan0" ip saddr != 10.10.10.0/24 ct state new tcp dport 443 ip daddr @doh4 counter'
        ' comment "pi leak: DoH left by the uplink"',
        'oifname "wlan0" ip saddr != 10.10.10.0/24 ct state new meta l4proto { tcp, udp } th dport 53'
        ' counter comment "pi leak: DNS left by the uplink"',
    ]
    assert not [r for r in leaks[1:] if re.search(r"\b(drop|reject|accept)\b", r.split("comment")[0])]


@pytest.mark.parametrize(
    ("present", "expected"),
    [((), "tun0"), (("tun0",), "tun0"), (("wgpia0",), "wgpia0"), (("tun0", "wgpia0"), "tun0")],
)
def test_vpn_mode_follows_the_tunnel_auto_finds(tmp_path, present, expected):
    """PIA 3.8.0 makes WireGuard (wgpia0) the default: hardcoded tun0 left vpn mode dark after a
    reinstall. Before either exists (the boot apply) tun0, as before; the dispatcher applies again."""
    proc = (*PROC, *(f"net/ipv4/conf/{dev}/forwarding" for dev in present))
    out = run_apply(tmp_path, conf="UPLINK=vpn\n", proc=proc)
    assert out.returncode == 0, out.stderr
    tv_out = chain(ruleset(tmp_path), "tv_out")
    assert tv_out[0] == f'oifname != "{expected}" counter drop comment "only via the chosen uplink"'
    assert f"uplink=vpn via {expected}" in out.stdout
    assert (expected in present) == (f"{expected} not there yet" not in out.stderr)


def test_a_named_tunnel_is_used_and_dropped_beside_pias(tmp_path):
    out = run_apply(tmp_path, conf="UPLINK=vpn\nVPN_IF=wg0\n", proc=(*PROC, "net/ipv4/conf/wg0/forwarding"))
    assert out.returncode == 0, out.stderr
    assert input_drop(tmp_path).startswith('iifname { "tun0", "wgpia0", "wg0" } ct state new')
    assert chain(ruleset(tmp_path), "tv_out")[0].startswith('oifname != "wg0"')
    assert "VPN_IF=wg0" in (tmp_path / "run" / "tvgw" / "settings.applied").read_text(encoding="utf-8")


def test_none_keeps_the_tunnel_drop_and_counts_no_leaks(tmp_path):
    """A gateway without a VPN client has nothing to leak from; the input drop never weakens."""
    assert run_apply(tmp_path, conf=CONF + "VPN_IF=none\n").returncode == 0
    assert input_drop(tmp_path).startswith('iifname { "tun0", "wgpia0" } ct state new')
    assert chain(ruleset(tmp_path), "post_leaks") == [
        "type filter hook postrouting priority srcnat - 20; policy accept;"
    ]


@pytest.mark.parametrize(
    ("conf", "says"),
    [
        ("UPLINK=vpn\nVPN_IF=none\n", "UPLINK=vpn needs a tunnel"),
        (CONF + "VPN_IF=eth0\n", "VPN_IF=eth0 must be auto, none or"),
        (CONF + "VPN_IF=wlan0\n", "VPN_IF=wlan0 must be auto, none or"),
        (CONF + "VPN_IF=lo\n", "VPN_IF=lo must be"),
        (CONF + "VPN_IF=wg/0\n", "VPN_IF=wg/0 must be"),
        # the input chain drops new connections from both PIA names whatever VPN_IF says: a TV port or
        # an uplink under either name would lose DHCP, DNS and SSH to the Pi
        (CONF + "TV_IF=wgpia0\n", "TV_IF=wgpia0 is not an interface name for the TV"),
        (CONF + "WAN_IF=wgpia0\n", "WAN_IF=wgpia0 is a VPN tunnel's name"),
        (CONF + "WAN_IF=tun0\nVPN_IF=none\n", "WAN_IF=tun0 is a VPN tunnel's name"),
    ],
)
def test_a_vpn_if_the_apply_refuses_stops_it_before_anything_loads(tmp_path, conf, says):
    out = run_apply(tmp_path, conf=conf)
    assert out.returncode == 1 and says in out.stderr
    assert not (tmp_path / "stub" / "nft-script.0").exists()


# ---- VPN_IF in Python ----------------------------------------------------------------------------------


def write(tmp_path, text: str) -> str:
    p = tmp_path / "tvgw.conf"
    p.write_text(text, encoding="utf-8")
    return str(p)


def test_vpn_if_defaults_to_auto_and_takes_a_name(tmp_path):
    assert config.load(write(tmp_path, "")).vpn_if == "auto"
    assert config.load(write(tmp_path, "VPN_IF=wgpia0\n")).vpn_if == "wgpia0"
    for bad in ("lo", "wg/0", "a-very-long-interface-name"):
        with pytest.raises(ValueError, match="VPN_IF"):
            config.load(write(tmp_path, f"VPN_IF={bad}\n"))


def test_the_writer_refuses_what_the_apply_would_refuse(tmp_path):
    with pytest.raises(ValueError, match="cannot be TV_IF or WAN_IF"):
        config.check_conf("VPN_IF=eth0\n")
    with pytest.raises(ValueError, match=r"UPLINK=vpn in tvgw\.conf needs a tunnel"):
        config.check_conf("UPLINK=vpn\nVPN_IF=none\n")
    assert config.check_conf("VPN_IF=wg0\n").vpn_if == "wg0"
    # a reader still works on a conf the apply would refuse
    assert config.load(write(tmp_path, "VPN_IF=eth0\n")).vpn_if == "eth0"


@pytest.mark.parametrize(
    ("vpn_if", "present", "tunnel"),
    [
        ("auto", set(), None),
        ("auto", {"wgpia0"}, "wgpia0"),
        ("auto", {"tun0", "wgpia0"}, "tun0"),
        ("none", {"tun0"}, None),
        ("wg0", set(), "wg0"),
    ],
)
def test_python_resolves_the_tunnel_as_the_apply_does(vpn_if, present, tunnel):
    s = config.Settings(vpn_if=vpn_if)
    assert config.vpn_interface(s, present.__contains__) == tunnel
    assert config.uplink_interface(s, present.__contains__) == "wlan0"
    vpn = config.Settings(vpn_if=vpn_if, uplink="vpn")
    assert config.uplink_interface(vpn, present.__contains__) == (tunnel or "tun0")


# ---- the dispatcher ------------------------------------------------------------------------------------


def dispatch(tmp_path, conf: str, iface: str, action: str = "up") -> bool:
    """Run the dispatcher for one event; True when it ran tvgw-apply."""
    text = (ROOT / "deploy" / "networkmanager" / "90-tvgw-dispatcher").read_text(encoding="utf-8")
    (tmp_path / "tvgw.conf").write_text(conf, encoding="utf-8")
    stub = tmp_path / "tvgw-apply"
    stub.write_text("#!/bin/sh\necho applied\n", encoding="utf-8")
    stub.chmod(0o755)
    script = text.replace("/etc/tvgw/tvgw.conf", str(tmp_path / "tvgw.conf")).replace(
        "/usr/local/sbin/tvgw-apply", str(stub)
    )
    (tmp_path / "dispatcher").write_text(script, encoding="utf-8")
    out = subprocess.run(
        ["sh", str(tmp_path / "dispatcher"), iface, action],
        capture_output=True,
        text=True,
        encoding="utf-8",
        env={"PATH": os.environ["PATH"]},
    )
    assert out.returncode == 0, out.stderr
    return out.stdout == "applied\n"


@pytest.mark.parametrize(
    ("conf", "iface", "applies"),
    [
        ("", "tun0", True),
        ("", "wgpia0", True),
        ("VPN_IF=auto\n", "wgpia0", True),
        ("", "wg0", False),
        ("VPN_IF=wg0\n", "wg0", True),
        ("VPN_IF=wg0\n", "tun0", False),
        ("VPN_IF=none\n", "tun0", False),
        ("VPN_IF=none\n", "wlan0", True),  # the uplink and the TV port re-apply whatever VPN_IF says
        ("VPN_IF=none\n", "eth0", True),
        ("", "docker0", False),
    ],
)
def test_the_dispatcher_reapplies_when_the_tunnel_vpn_if_names_comes_up(tmp_path, conf, iface, applies):
    assert dispatch(tmp_path, conf, iface) == applies
    assert not dispatch(tmp_path, conf, iface, "down")


def test_the_check_renders_the_rule_on_a_machine_that_never_loaded_conntrack(tmp_path):
    """--check is the virtual suite's renderer, and the CI runner may have no conntrack loaded when it
    runs: the rule is always rendered there, nft -c judges it, and no switch is written."""
    from test_apply_check import checked, run_check

    out = run_check(tmp_path)  # PROC holds no nf_conntrack_events key
    assert out.returncode == 0, out.stderr
    inet = checked(tmp_path)[0]
    assert "ct state new ct event set destroy" in inet and "pi leak: DoH left by the uplink" in inet
    assert "no conntrack events" not in out.stderr
    assert not (tmp_path / "proc" / "sys" / EVENTS).exists()
