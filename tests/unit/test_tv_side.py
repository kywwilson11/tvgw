"""The TV side templated (packaging, R&D §8.4.1): TV_IF, TV_NET and GW_IP come from the settings file
everywhere, with the shipped values as defaults.

The shell side (install.sh and tvgw-apply share one `tvgw-net` block) and config.tv_side must agree on
every value they accept and on what they derive from it, or the dnsmasq pool, the nmcli address and
the firewall would describe three different subnets. Each case runs through both."""

import os
import re
import shutil
import subprocess

import pytest
from conftest import ROOT, exec_lines
from test_apply import PROC, STUBS, chain, ruleset, run_apply

from tvgw import config

DEPLOY = ROOT / "deploy"
INSTALL = (DEPLOY / "install.sh").read_text(encoding="utf-8")
APPLY = (DEPLOY / "nftables" / "tvgw-apply").read_text(encoding="utf-8")
BASH = shutil.which("bash")
needs_bash = pytest.mark.skipif(BASH is None, reason="the shell side is bash")


def block(text: str, name: str) -> str:
    """A shared block, from its opening marker line to its closing one, both included."""
    start = text.index(f"# ---- {name}:")
    end = text.index(f"# ---- end {name} ----\n", start) + len(f"# ---- end {name} ----\n")
    return text[start:end]


NET = block(INSTALL, "tvgw-net")

# (TV_IF, WAN_IF, TV_NET, GW_IP, TV_IP): the shipped defaults, a second site, and one case per rule
CASES = [
    ("eth0", "wlan0", "10.10.10.0/24", "10.10.10.1", "10.10.10.17"),
    ("enp1s0", "wlan1", "10.20.30.0/24", "10.20.30.1", "10.20.30.17"),
    ("eth1", "eth0", "172.20.0.0/16", "172.20.0.1", "172.20.3.4"),
    ("eth0", "wlan0", "10.10.10.0/27", "10.10.10.1", "10.10.10.30"),
    ("eth0", "wlan0", "10.10.10.0/28", "10.10.10.1", "10.10.10.5"),  # too small for the pool
    ("eth0", "wlan0", "10.10.0.0/15", "10.10.0.1", "10.10.0.17"),  # too large
    ("eth0", "wlan0", "10.10.10.1/24", "10.10.10.1", "10.10.10.17"),  # host bits set
    ("eth0", "wlan0", "10.10.10.0/08", "10.10.10.1", "10.10.10.17"),
    ("eth0", "wlan0", "10.10.10.0", "10.10.10.1", "10.10.10.17"),  # no prefix
    ("eth0", "wlan0", "203.0.113.0/24", "203.0.113.1", "203.0.113.17"),  # not private
    ("eth0", "wlan0", "172.32.0.0/16", "172.32.0.1", "172.32.0.17"),  # just outside 172.16/12
    ("eth0", "wlan0", "300.10.10.0/24", "10.10.10.1", "10.10.10.17"),
    ("eth0", "wlan0", "10.10.10.0/24", "10.10.11.1", "10.10.10.17"),  # gateway outside the subnet
    ("eth0", "wlan0", "10.10.10.0/24", "10.10.10.0", "10.10.10.17"),  # the network address
    ("eth0", "wlan0", "10.10.10.0/24", "10.10.10.255", "10.10.10.17"),  # the broadcast address
    ("eth0", "wlan0", "10.10.10.0/24", "10.10.10.15", "10.10.10.17"),  # inside the DHCP pool
    ("eth0", "wlan0", "10.10.10.0/24", "010.10.10.1", "10.10.10.17"),  # a leading zero
    ("eth0", "wlan0", "10.10.10.0/24", "10.10.10.1", "10.10.11.17"),  # the TV outside the subnet
    ("eth0", "wlan0", "10.10.10.0/24", "10.10.10.1", "10.10.10.1"),  # the TV on the gateway address
    ("eth0", "wlan0", "10.10.10.0/24", "10.10.10.1", "10.10.10.255"),
    ("eth0", "eth0", "10.10.10.0/24", "10.10.10.1", "10.10.10.17"),  # the TV port is the uplink
    ("tun0", "wlan0", "10.10.10.0/24", "10.10.10.1", "10.10.10.17"),
    ("wgpia0", "wlan0", "10.10.10.0/24", "10.10.10.1", "10.10.10.17"),  # (events) PIA's WireGuard
    ("eth0", "tun0", "10.10.10.0/24", "10.10.10.1", "10.10.10.17"),  # (events) the uplink is no tunnel
    ("eth0", "wgpia0", "10.10.10.0/24", "10.10.10.1", "10.10.10.17"),
    ("lo", "wlan0", "10.10.10.0/24", "10.10.10.1", "10.10.10.17"),
    ("eth0/1", "wlan0", "10.10.10.0/24", "10.10.10.1", "10.10.10.17"),  # sed and nft would choke
    ("an-interface-name-too-long", "wlan0", "10.10.10.0/24", "10.10.10.1", "10.10.10.17"),
    ("eth0 ", "wlan0", "10.10.10.0/24", "10.10.10.1", "10.10.10.17"),
]


def shell_side(tv_if: str, wan_if: str, tv_net: str, gw_ip: str, tv_ip: str) -> str:
    """What the shell block derives, `prefix netmask broadcast first last`, or `FAIL <reason>`."""
    script = NET + 'tv_side && tv_ip_ok && echo "$TV_PREFIX $TV_NETMASK $TV_BCAST $DHCP_FIRST $DHCP_LAST" ||'
    script += ' echo "FAIL $TV_SIDE_ERR"'
    env = {"PATH": os.environ["PATH"], "TV_IF": tv_if, "WAN_IF": wan_if, "TV_NET": tv_net}
    env |= {"GW_IP": gw_ip, "TV_IP": tv_ip}
    out = subprocess.run(
        [BASH, "-euo", "pipefail", "-c", script], env=env, capture_output=True, text=True, encoding="utf-8"
    )
    assert out.returncode == 0, out.stderr
    return out.stdout.strip()


def python_side(tv_if: str, wan_if: str, tv_net: str, gw_ip: str, tv_ip: str) -> str:
    s = config.Settings(tv_if=tv_if, wan_if=wan_if, tv_net=tv_net, gw_ip=gw_ip, tv_ip=tv_ip)
    try:
        side = config.tv_side(s)
    except ValueError as e:
        return f"FAIL {e}"
    return f"{side.prefix} {side.netmask} {side.broadcast} {side.dhcp_first} {side.dhcp_last}"


@needs_bash
@pytest.mark.parametrize("case", CASES, ids=lambda c: "-".join(c))
def test_the_shell_and_python_accept_and_derive_the_same(case):
    shell, python = shell_side(*case), python_side(*case)
    assert shell.startswith("FAIL") == python.startswith("FAIL"), (shell, python)
    if not shell.startswith("FAIL"):
        assert shell == python
    else:  # both name the same key first
        assert shell.split("=")[0] == python.split("=")[0], (shell, python)


@needs_bash
def test_the_defaults_derive_what_the_files_used_to_hard_code():
    """The live gateway's behaviour is unchanged: the pool, mask and broadcast the dnsmasq file and
    tvgw-apply wrote before the TV side was templated."""
    assert shell_side(*CASES[0]) == "24 255.255.255.0 10.10.10.255 10.10.10.10 10.10.10.20"


def test_the_shell_block_is_the_same_in_install_and_apply():
    assert block(APPLY, "tvgw-net") == NET


def test_install_and_apply_default_the_tv_side_as_settings_does():
    s = config.Settings()
    for text in (INSTALL, APPLY):
        defaults = dict(re.findall(r"\$\{([A-Z_]+):=([^}]*)\}", text))
        for key in ("TV_IF", "TV_NET", "GW_IP", "WAN_IF"):
            assert defaults[key] == getattr(s, config.CONF_KEYS[key]), key
    assert dict(re.findall(r"\$\{([A-Z_]+):=([^}]*)\}", INSTALL))["TV_IP"] == s.tv_ip


def test_the_settings_file_reads_the_tv_side(tmp_path):
    conf = tmp_path / "tvgw.conf"
    conf.write_text(
        "TV_IF=enp1s0\nTV_NET=10.20.30.0/24\nGW_IP=10.20.30.1\nTV_IP=10.20.30.17\n", encoding="utf-8"
    )
    s = config.load(conf)
    assert (s.tv_if, s.tv_net, s.gw_ip) == ("enp1s0", "10.20.30.0/24", "10.20.30.1")
    assert config.tv_side(s).dhcp_first == "10.20.30.10"
    assert config.load(tmp_path / "missing.conf").tv_net == "10.10.10.0/24"


@pytest.mark.parametrize("line", ["TV_IF=eth0/1", "TV_IF=tun0", "TV_NET=10.10.10.0/28", "TV_NET=8.8.8.0/24"])
def test_every_command_refuses_a_malformed_tv_side(tmp_path, line):
    """The shape of the two new keys is checked on load, so a typo shows on the next command rather
    than at the next boot's apply. Membership (GW_IP and TV_IP inside TV_NET) is the writers' check."""
    conf = tmp_path / "tvgw.conf"
    conf.write_text(line + "\n", encoding="utf-8")
    with pytest.raises(ValueError, match=line.split("=")[0]):
        config.load(conf)


def test_a_reader_still_loads_a_conf_the_installer_would_refuse(tmp_path):
    """TV_IP outside TV_NET stops install.sh, but `tvgw brief` on a copied store must still run."""
    conf = tmp_path / "tvgw.conf"
    conf.write_text("TV_IP=10.0.0.5\n", encoding="utf-8")
    s = config.load(conf)
    with pytest.raises(ValueError, match="TV_IP"):
        config.tv_side(s)


SITE = (
    "UPLINK=direct\nWAN_IF=wlan1\nWAN_GW=203.0.113.1\nTV_IF=enp1s0\nTV_NET=10.20.30.0/24\nGW_IP=10.20.30.1\n"
)
SITE_PROC = tuple(p.replace("eth0", "enp1s0").replace("wlan0", "wlan1") for p in PROC)


@needs_bash
def test_a_second_site_gets_its_own_interfaces_and_subnet_in_every_rule(tmp_path):
    out = run_apply(tmp_path, conf=SITE, proc=SITE_PROC)
    assert out.returncode == 0, out.stderr
    rules = ruleset(tmp_path)
    assert "eth0" not in rules and "10.10.10." not in rules
    assert 'iifname "enp1s0" ip daddr != 10.20.30.1 udp dport 53 counter dnat ip to 10.20.30.1:53' in rules
    forward = chain(rules, "forward")
    assert any('iifname "enp1s0" ip saddr != 10.20.30.0/24 counter drop' in line for line in forward)
    assert any("10.20.30.255, 255.255.255.255" in line for line in chain(rules, "output"))
    assert any(
        'iifname "enp1s0" oifname "wlan1" ip saddr 10.20.30.0/24 masquerade' in line
        for line in chain(rules, "post_nat")
    )
    l2 = (tmp_path / "stub" / "nft-script.1").read_text(encoding="utf-8")
    assert 'hook ingress device "enp1s0"' in l2
    proc = tmp_path / "proc" / "sys" / "net"
    assert (proc / "ipv4" / "conf" / "enp1s0" / "forwarding").read_text(encoding="utf-8") == "1\n"
    assert (proc / "ipv6" / "conf" / "enp1s0" / "disable_ipv6").read_text(encoding="utf-8") == "1\n"
    calls = (tmp_path / "stub" / "ip.calls").read_text(encoding="utf-8")
    assert "rule add priority 60 from 10.20.30.0/24 lookup 100" in calls
    applied = config.parse_conf((tmp_path / "run" / "tvgw" / "settings.applied").read_text(encoding="utf-8"))
    assert (applied["TV_IF"], applied["TV_NET"], applied["GW_IP"]) == (
        "enp1s0",
        "10.20.30.0/24",
        "10.20.30.1",
    )


@needs_bash
@pytest.mark.parametrize(
    "bad", ["TV_NET=0.0.0.0/0", "TV_NET=10.10.10.0/28", "GW_IP=10.10.11.1", "TV_IF=wlan0"]
)
def test_apply_refuses_a_tv_side_that_would_cover_more_than_the_tv_before_loading_anything(tmp_path, bad):
    """A subnet of 0.0.0.0/0 would masquerade, and send through table 100, everything the Pi forwards:
    the apply stops before nft, sysctl or ip is asked anything, so the old ruleset stays."""
    out = run_apply(tmp_path, conf="UPLINK=direct\nWAN_IF=wlan0\nWAN_GW=203.0.113.1\n" + bad + "\n")
    assert out.returncode == 1 and out.stderr.startswith("tvgw: "), out.stderr
    assert not (tmp_path / "stub" / "nft.calls").exists() and not (tmp_path / "stub" / "ip.calls").exists()
    assert (tmp_path / "proc" / "sys" / "net" / "ipv4" / "ip_forward").read_text(encoding="utf-8") == "0\n"


def test_every_placeholder_in_a_template_is_one_install_fills_in():
    """A placeholder install.sh does not replace would reach dnsmasq or nginx as text."""
    templates = (
        "dnsmasq/tvgw.conf.template",
        "nginx/tvgw-gfts.conf",
        "nginx/stream.conf",
        "networkmanager/90-tvgw.conf",
    )
    for template in templates:
        for placeholder in set(re.findall(r"__[A-Z_]+__", (DEPLOY / template).read_text(encoding="utf-8"))):
            assert f"s/{placeholder}/" in INSTALL, (template, placeholder)


@needs_bash
@pytest.mark.parametrize("have_tv", ["yes", "no"])
def test_the_dnsmasq_file_for_the_defaults_is_the_one_the_gateway_runs(tmp_path, have_tv):
    start = INSTALL.index("render_dnsmasq() {")
    fn = INSTALL[start : INSTALL.index("\n}\n", start) + 3].replace("/etc/dnsmasq.d/", f"{tmp_path}/")
    pins = "TV_MAC=aa:bb:cc:dd:ee:ff TV_IP=10.10.10.17 TV_NAME=tv"
    script = (
        f"{NET}\nTV_IF=eth0 WAN_IF=wlan0 TV_NET=10.10.10.0/24 GW_IP=10.10.10.1 {pins} have_tv={have_tv}\n"
    )
    script += f"tv_side\n{fn}\nrender_dnsmasq\n"
    subprocess.run([BASH, "-euo", "pipefail", "-c", script], cwd=DEPLOY, check=True)
    lines = [
        x for x in (tmp_path / "tvgw.conf").read_text(encoding="utf-8").splitlines() if not x.startswith("#")
    ]
    expected = [
        "port=0",
        "interface=eth0",
        "bind-dynamic",
        "dhcp-authoritative",
        "dhcp-range=10.10.10.10,10.10.10.20,255.255.255.0,12h",
        "dhcp-option=option:router,10.10.10.1",
        "dhcp-option=option:dns-server,10.10.10.1",
        *(["dhcp-host=aa:bb:cc:dd:ee:ff,10.10.10.17,tv"] if have_tv == "yes" else []),
        "log-dhcp",
        "dhcp-broadcast",  # (guard) with no-ping: no CAP_NET_ADMIN, no CAP_NET_RAW (design decision 42)
        "no-ping",
    ]
    assert lines == expected


@needs_bash
@pytest.mark.parametrize(
    ("applied", "conf", "expected"),
    [
        (None, "", "eth0"),
        (None, "TV_IF=enp1s0\n", "enp1s0"),
        (None, None, "eth0"),
        # (packaging) after a TV_IF edit, before install.sh moved tv-lan: the port the filter was built for
        ("UPLINK=direct\nTV_IF=eth0\nTV_NET=10.10.10.0/24\n", "TV_IF=enp1s0\n", "eth0"),
        ("UPLINK=direct\nTV_IF=enp1s0\n", None, "enp1s0"),
        ("UPLINK=direct\n", "TV_IF=enp1s0\n", "enp1s0"),  # written before applies recorded TV_IF
    ],
)
def test_stopping_the_firewall_turns_off_forwarding_on_the_tv_interface_the_filter_was_built_for(
    tmp_path, applied, conf, expected
):
    """tvgw.service's stop path: forwarding off on the TV port before the filter goes (fail closed). The
    port is the one the last apply recorded in settings.applied, then the conf's TV_IF, then eth0, so
    a stop between a TV_IF edit and the install that moves tv-lan darkens the port the TV is on."""
    (stop,) = [v for k, v in exec_lines("tvgw.service") if k == "ExecStop" and "sysctl" in v]
    (tmp_path / "bin").mkdir()
    (tmp_path / "bin" / "sysctl").write_text(f'#!/bin/sh\necho "$*" >{tmp_path}/called\n', encoding="utf-8")
    (tmp_path / "bin" / "sysctl").chmod(0o755)
    if conf is not None:
        (tmp_path / "tvgw.conf").write_text(conf, encoding="utf-8")
    if applied is not None:
        (tmp_path / "settings.applied").write_text(applied, encoding="utf-8")
    argv = stop.replace("$$", "$").replace("/etc/tvgw/tvgw.conf", str(tmp_path / "tvgw.conf"))
    argv = argv.replace("/run/tvgw/settings.applied", str(tmp_path / "settings.applied"))
    argv = argv.replace("/usr/sbin/sysctl", str(tmp_path / "bin" / "sysctl"))
    script = argv.removeprefix("/bin/sh -c '").removesuffix("'")
    subprocess.run(["sh", "-c", script], check=True)
    assert (tmp_path / "called").read_text(
        encoding="utf-8"
    ) == f"-q -w net.ipv4.conf.{expected}.forwarding=0\n"


@pytest.mark.parametrize(
    ("iface", "applies"), [("enp1s0", True), ("wlan1", True), ("tun0", True), ("eth0", False)]
)
def test_the_dispatcher_reapplies_for_the_tv_port_the_conf_names(tmp_path, iface, applies):
    text = (DEPLOY / "networkmanager" / "90-tvgw-dispatcher").read_text(encoding="utf-8")
    (tmp_path / "tvgw.conf").write_text("TV_IF=enp1s0\nWAN_IF=wlan1\n", encoding="utf-8")
    (tmp_path / "apply").write_text(f"#!/bin/sh\ntouch {tmp_path}/applied\n", encoding="utf-8")
    (tmp_path / "apply").chmod(0o755)
    script = text.replace("/etc/tvgw/tvgw.conf", str(tmp_path / "tvgw.conf"))
    script = script.replace("/usr/local/sbin/tvgw-apply", str(tmp_path / "apply"))
    (tmp_path / "dispatcher").write_text(script, encoding="utf-8")
    subprocess.run(["sh", str(tmp_path / "dispatcher"), iface, "up"], check=True)
    assert (tmp_path / "applied").exists() == applies


# Files allowed to spell the shipped TV side, and why. Everything else reads it from the conf.
LITERAL_OK = {
    "deploy/tvgw.conf.example": "the template states the defaults",
}
# single lines that must name the shipped value, marked in the file with the same words
LITERAL_LINES = ("the stock profile of a Pi's built-in port",)
LITERAL = re.compile(r"\beth0\b|\bwlan0\b|\b10\.10\.10\.\d")


def test_no_deploy_file_hard_codes_the_tv_side():
    """Every eth0, wlan0 and 10.10.10.x left under deploy/ is a default (`${KEY:=...}` or
    `${KEY:-...}`), a comment, an example in a message, a line marked as literal on purpose, or in a
    file listed above with its reason."""
    found = []
    for path in sorted(DEPLOY.rglob("*")):
        rel = str(path.relative_to(ROOT))
        if not path.is_file() or path.suffix == ".md" or rel in LITERAL_OK:
            continue
        for n, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
            if line.endswith(tuple(f"# literal on purpose: {why}" for why in LITERAL_LINES)):
                continue
            code = line.split("#", 1)[0] if not line.lstrip().startswith("#") else ""
            code = re.sub(r"\$\{[A-Z_]+:[-=][^}]*\}", "", code)  # a default
            code = re.sub(r"such as 10\.10\.10\.0/24", "", code)  # an example in a message
            if LITERAL.search(code):
                found.append(f"{rel}:{n}: {line.strip()}")
    assert not found, "\n".join(found)


# ---- (packaging) a TV_IF change before install.sh moved tv-lan: the TV is never forwarded unfiltered

MOVED = "UPLINK=direct\nWAN_IF=wlan0\nWAN_GW=203.0.113.1\nTV_IF=eth1\n"
MOVED_PROC = (*PROC, "net/ipv6/conf/eth1/disable_ipv6", "net/ipv4/conf/eth1/forwarding")
# sysctl as test_apply has it, with every call logged
LOGGED_SYSCTL = STUBS["sysctl"].replace("rc=0\n", 'printf "%s\\n" "$*" >>"$STUB_DIR/sysctl.calls"\nrc=0\n', 1)


def ip_with_gw_on(dev: str) -> str:
    """The ip stub, answering `ip -4 -o addr show to GW_IP` with GW_IP on `dev`."""
    line = f"2: {dev}    inet 10.10.10.1/24 brd 10.10.10.255 scope global noprefixroute {dev}\\\\       valid_lft forever"
    return STUBS["ip"].replace(
        "exit 0\n", f'case "$*" in "-4 -o addr show to "*) echo \'{line}\' ;; esac\nexit 0\n'
    )


@needs_bash
def test_the_tv_subnet_arriving_off_the_tv_port_is_dropped_and_never_masqueraded(tmp_path):
    """TV_IF edited to eth1 while the TV, tv-lan and dnsmasq are still on eth0: the boot's ip_forward
    0 to 1 switches forwarding on everywhere, and the forward chain's accept of everything not on the
    TV port passed the TV's eth0 traffic, which post_nat then masqueraded. The drop comes first, and
    masquerade covers only what came in on the TV port."""
    out = run_apply(tmp_path, conf=MOVED, proc=MOVED_PROC)
    assert out.returncode == 0, out.stderr
    forward = chain(ruleset(tmp_path), "forward")
    drop = forward.index(
        'ip saddr 10.10.10.0/24 iifname != "eth1" counter drop comment "TV subnet off the TV port"'
    )
    assert drop < forward.index('iifname != "eth1" oifname != "eth1" accept')
    assert chain(ruleset(tmp_path), "post_nat") == [
        "type nat hook postrouting priority srcnat - 10; policy accept;",
        'iifname "eth1" oifname "wlan0" ip saddr 10.10.10.0/24 masquerade',
    ]


@needs_bash
@pytest.mark.parametrize(("applied", "dark"), [(None, True), ("TV_IF=eth0\n", False)])
def test_apply_stops_when_gw_ip_is_on_another_port_than_tv_if(tmp_path, applied, dark):
    """GW_IP still on eth0 (tv-lan not moved) with TV_IF=eth1: nothing is loaded and the message says to
    run install.sh. eth0's forwarding goes off unless the filter loaded now was built for eth0 (a
    boot has none, so the TV goes dark rather than unfiltered)."""
    (tmp_path / "run" / "tvgw").mkdir(parents=True)
    if applied is not None:
        (tmp_path / "run" / "tvgw" / "settings.applied").write_text(applied, encoding="utf-8")
    out = run_apply(
        tmp_path, conf=MOVED, proc=MOVED_PROC, stubs={"ip": ip_with_gw_on("eth0"), "sysctl": LOGGED_SYSCTL}
    )
    assert out.returncode == 1
    assert "GW_IP 10.10.10.1 is on eth0, not TV_IF=eth1; run install.sh" in out.stderr
    assert not (tmp_path / "stub" / "nft.calls").exists()
    sysctl = tmp_path / "stub" / "sysctl.calls"
    logged = sysctl.read_text(encoding="utf-8").splitlines() if sysctl.exists() else []
    assert logged == (["-q -w net.ipv4.conf.eth0.forwarding=0"] if dark else [])
    assert (tmp_path / "proc" / "sys" / "net" / "ipv4" / "ip_forward").read_text(encoding="utf-8") == "0\n"


@needs_bash
def test_apply_goes_ahead_when_gw_ip_is_on_tv_if(tmp_path):
    out = run_apply(tmp_path, stubs={"ip": ip_with_gw_on("eth0")})
    assert out.returncode == 0, out.stderr


@needs_bash
@pytest.mark.parametrize(
    ("conf", "off"),
    [
        (MOVED, ["-q -w net.ipv4.conf.eth0.forwarding=0"]),  # the old TV port
        (MOVED.replace("WAN_IF=wlan0", "WAN_IF=eth0"), []),  # the old TV port is now the uplink
        ("UPLINK=direct\nWAN_IF=wlan0\nWAN_GW=203.0.113.1\nTV_IF=eth0\n", []),  # unchanged
    ],
)
def test_the_previous_tv_port_stops_forwarding_once_the_new_one_is_filtered(tmp_path, conf, off):
    """After the forwarding switch-on, which turns every port on when ip_forward goes from 0 to 1, the
    TV_IF the previous apply filtered is switched off again, unless it is the uplink now."""
    (tmp_path / "run" / "tvgw").mkdir(parents=True)
    (tmp_path / "run" / "tvgw" / "settings.applied").write_text(
        "UPLINK=direct\nTV_IF=eth0\n", encoding="utf-8"
    )
    proc = (*MOVED_PROC, "net/ipv4/conf/eth0/forwarding")
    out = run_apply(tmp_path, conf=conf, proc=tuple(dict.fromkeys(proc)), stubs={"sysctl": LOGGED_SYSCTL})
    assert out.returncode == 0, out.stderr
    logged = (tmp_path / "stub" / "sysctl.calls").read_text(encoding="utf-8").splitlines()
    on = next(i for i, c in enumerate(logged) if "net.ipv4.ip_forward=1" in c)
    assert [c for c in logged[on + 1 :] if c.endswith("forwarding=0")] == off
    applied = config.parse_conf((tmp_path / "run" / "tvgw" / "settings.applied").read_text(encoding="utf-8"))
    assert applied["TV_IF"] == config.parse_conf(conf)["TV_IF"]


# ---- (packaging) install.sh's TV-side steps against stub commands


def install_fn(name: str) -> str:
    """One function of install.sh, from its first line to its closing brace."""
    start = INSTALL.index(f"\n{name}() {{") + 1
    return INSTALL[start : INSTALL.index("\n}\n", start) + 3]


def overlap_step() -> str:
    """install.sh's WAN overlap check: the function and the stop that uses it."""
    start = INSTALL.index("\nwan_overlap() {") + 1
    end = INSTALL.index("\nfi\n", INSTALL.index("if lan=$(wan_overlap); then", start)) + 4
    return INSTALL[start:end]


@needs_bash
@pytest.mark.parametrize(
    ("tv_net", "wan", "stops"),
    [
        ("10.10.10.0/24", "192.168.1.50/24", False),
        ("10.10.10.0/24", "10.10.11.7/24", False),
        ("10.10.10.0/24", "10.10.0.5/16", True),  # the home /16 holds the TV /24
        ("10.10.10.0/24", "10.0.0.2/8", True),
        ("10.10.10.0/24", "10.10.10.200/30", True),  # a small uplink network inside the TV /24
        ("172.20.0.0/16", "172.20.9.1/24", True),
        ("172.20.0.0/16", "172.21.0.1/16", False),
        ("10.10.10.0/24", "", False),  # the uplink has no address yet
    ],
)
def test_install_stops_on_a_tv_subnet_the_home_network_overlaps(tmp_path, tv_net, wan, stops):
    gw = tv_net.split("/")[0].rsplit(".", 1)[0] + ".1"
    (tmp_path / "bin").mkdir()
    line = (
        f"3: wlan0    inet {wan} brd 0.0.0.0 scope global dynamic wlan0\\\\       valid_lft 86000sec"
        if wan
        else ""
    )
    (tmp_path / "bin" / "ip").write_text(
        f'#!/bin/sh\ncase "$*" in "-4 -o addr show dev wlan0") [ -z "{line}" ] || echo \'{line}\' ;; esac\n',
        encoding="utf-8",
    )
    (tmp_path / "bin" / "ip").chmod(0o755)
    script = 'die() { echo "tvgw: $*" >&2; exit 1; }\n' + NET + "tv_side\n" + overlap_step() + "echo passed\n"
    env = {"PATH": f"{tmp_path / 'bin'}{os.pathsep}{os.environ['PATH']}", "TV_IF": "eth0", "WAN_IF": "wlan0"}
    env |= {"TV_NET": tv_net, "GW_IP": gw}
    out = subprocess.run(
        [BASH, "-euo", "pipefail", "-c", script], env=env, capture_output=True, text=True, encoding="utf-8"
    )
    assert (out.returncode == 1) == stops, out.stderr
    if stops:
        assert f"TV_NET={tv_net} overlaps the network of wlan0 ({wan})" in out.stderr
    else:
        assert out.stdout == "passed\n"


NMCLI = """#!/bin/sh
echo "nmcli $*" >>"$NM/calls"
case "$*" in
"-t -f NAME con show") cat "$NM/names" ;;
"-t -f NAME,DEVICE con show --active") cat "$NM/active" ;;
"-g connection.interface-name con show tv-lan") cat "$NM/ifname" ;;
"-g ipv4.addresses con show tv-lan") cat "$NM/addr" ;;
"-g GENERAL.STATE con show tv-lan") echo activated ;;
esac
exit 0
"""


def run_tv_lan(
    tmp_path, tv_if: str, gw: str, names: str, active: str, ifname="", addr=""
) -> tuple[list[str], str]:
    """install.sh's tv_lan with a fake nmcli: `names` and `active` are what `con show` lists, `ifname`
    and `addr` what tv-lan holds. Returns the nmcli calls and the step's output."""
    nm = tmp_path / "nm"
    (nm / "bin").mkdir(parents=True)
    for name, text in (("names", names), ("active", active), ("ifname", ifname), ("addr", addr)):
        (nm / name).write_text(text, encoding="utf-8")
    (nm / "bin" / "nmcli").write_text(NMCLI, encoding="utf-8")
    (nm / "bin" / "nmcli").chmod(0o755)
    script = install_fn("stand_aside") + install_fn("tv_lan") + "tv_lan\n"
    env = {"PATH": f"{nm / 'bin'}{os.pathsep}{os.environ['PATH']}", "NM": str(nm)}
    env |= {"TV_IF": tv_if, "GW_IP": gw, "TV_PREFIX": "24"}
    out = subprocess.run(
        [BASH, "-euo", "pipefail", "-c", script], env=env, capture_output=True, text=True, encoding="utf-8"
    )
    assert out.returncode == 0, out.stderr
    return (nm / "calls").read_text(encoding="utf-8").splitlines(), out.stdout


@needs_bash
def test_tv_lan_where_the_settings_put_it_is_left_alone(tmp_path):
    """The live gateway's case on every deploy: no modify and no `con up`, so GW_IP never drops."""
    seen, said = run_tv_lan(
        tmp_path,
        "eth0",
        "10.10.10.1",
        "tv-lan\nhome-wifi\n",
        "tv-lan:eth0\nhome-wifi:wlan0\n",
        "eth0\n",
        "10.10.10.1/24\n",
    )
    assert not [c for c in seen if " con modify " in c or " con up " in c or " con add " in c]
    assert "moves to" not in said


@needs_bash
@pytest.mark.parametrize(
    ("tv_if", "gw", "active"),
    [
        ("eth1", "10.10.10.1", "tv-lan:eth0\nWired connection 2:eth1\nhome-wifi:wlan0\n"),  # another port
        ("eth0", "10.20.30.1", "tv-lan:eth0\nhome-wifi:wlan0\n"),  # another subnet, same port
    ],
)
def test_tv_lan_moves_when_the_settings_moved_and_the_new_port_s_profile_stands_aside(
    tmp_path, tv_if, gw, active
):
    seen, said = run_tv_lan(
        tmp_path, tv_if, gw, "tv-lan\nWired connection 2\nhome-wifi\n", active, "eth0\n", "10.10.10.1/24\n"
    )
    assert said == f"tvgw: tv-lan moves to {tv_if} with {gw}/24\n"
    move = f"nmcli con modify tv-lan connection.interface-name {tv_if} ipv4.addresses {gw}/24"
    assert (
        move in seen
        and "nmcli con up tv-lan" in seen
        and seen.index(move) < seen.index("nmcli con up tv-lan")
    )
    stood = [c for c in seen if c.endswith("connection.autoconnect no")]
    assert stood == (
        ["nmcli con modify Wired connection 2 connection.autoconnect no"] if tv_if == "eth1" else []
    )
    assert seen.index(move) > max((seen.index(c) for c in stood), default=-1)


@needs_bash
@pytest.mark.parametrize(
    ("tv_if", "names", "active", "stood"),
    [
        (
            "eth1",
            "Wired connection 1\nWired connection 2\n",
            "Wired connection 1:eth0\nWired connection 2:eth1\n",
            ["Wired connection 2"],
        ),
        (
            "eth0",
            "Wired connection 1\nhome-wifi\n",
            "home-wifi:wlan0\n",
            ["Wired connection 1"],
        ),  # the stock one, active or not
        (
            "eth0",
            "Wired connection 1\n",
            "Wired connection 1:eth0\n",
            ["Wired connection 1", "Wired connection 1"],
        ),
        ("enp1s0", "home-wifi\n", "home-wifi:wlan0\n", []),
    ],
)
def test_a_first_install_makes_tv_lan_after_the_port_s_profile_stands_aside(
    tmp_path, tv_if, names, active, stood
):
    seen, said = run_tv_lan(tmp_path, tv_if, "10.10.10.1", names, active)
    assert [
        c.removeprefix("nmcli con modify ").removesuffix(" connection.autoconnect no")
        for c in seen
        if c.endswith("autoconnect no")
    ] == stood
    add = next(i for i, c in enumerate(seen) if c.startswith("nmcli con add type ethernet"))
    assert f"ifname {tv_if} con-name tv-lan ipv4.method manual ipv4.addresses 10.10.10.1/24" in seen[add]
    assert all(seen.index(f"nmcli con modify {n} connection.autoconnect no") < add for n in stood)
    assert "moves to" not in said


# ---- (packaging) the capture's TV side


def test_the_capture_reads_its_tv_side_from_the_drop_in_install_writes():
    """dumpcap runs as tvgw-pcap, which cannot read the settings file: systemd fills ${TV_IF}, ${TV_NET}
    and ${GW_IP} from the drop-in install.sh writes from the checked settings, before the units are
    reloaded and the capture is restarted."""
    (value,) = [v for k, v in exec_lines("tvgw-pcap.service") if k == "ExecStart"]
    assert set(re.findall(r"\$\{([A-Z_]+)\}", value)) == {"TV_IF", "TV_NET", "GW_IP"}
    assert value.startswith("/usr/bin/dumpcap -i ${TV_IF} ")  # (capture) dumpcap in place of tcpdump
    assert "ip src net ${TV_NET} and not ip src host ${GW_IP} and (" in value
    write = INSTALL.index(">/etc/systemd/system/tvgw-pcap.service.d/tv-side.conf")
    assert INSTALL.index("tv_side || die") < write < INSTALL.index("restart_changed tvgw-pcap")
    assert write < INSTALL.index("systemctl daemon-reload", write)


@needs_bash
def test_the_drop_in_holds_the_settings_tv_side(tmp_path):
    start = INSTALL.index("install -d /etc/systemd/system/tvgw-pcap.service.d\n")
    end = INSTALL.index("tv-side.conf\n", start) + len("tv-side.conf\n")
    step = INSTALL[start:end].replace("/etc/systemd/system/", f"{tmp_path}/")
    env = {"PATH": os.environ["PATH"], "TV_IF": "enp1s0", "TV_NET": "10.20.30.0/24", "GW_IP": "10.20.30.1"}
    subprocess.run([BASH, "-euo", "pipefail", "-c", step], env=env, check=True)
    text = (tmp_path / "tvgw-pcap.service.d" / "tv-side.conf").read_text(encoding="utf-8")
    assert text == "[Service]\nEnvironment=TV_IF=enp1s0 TV_NET=10.20.30.0/24 GW_IP=10.20.30.1\n"
