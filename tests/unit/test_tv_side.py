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
from test_apply import PROC, chain, ruleset, run_apply

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
    assert any("ip saddr 10.20.30.0/24 masquerade" in line for line in chain(rules, "post_nat"))
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
    ]
    assert lines == expected


@needs_bash
@pytest.mark.parametrize(("conf", "expected"), [("", "eth0"), ("TV_IF=enp1s0\n", "enp1s0"), (None, "eth0")])
def test_stopping_the_firewall_turns_off_forwarding_on_the_tv_interface_the_conf_names(
    tmp_path, conf, expected
):
    """tvgw.service's stop path: forwarding off on TV_IF before the filter goes (fail closed), also with
    no settings file at all."""
    (stop,) = [v for k, v in exec_lines("tvgw.service") if k == "ExecStop" and "sysctl" in v]
    (tmp_path / "bin").mkdir()
    (tmp_path / "bin" / "sysctl").write_text(f'#!/bin/sh\necho "$*" >{tmp_path}/called\n', encoding="utf-8")
    (tmp_path / "bin" / "sysctl").chmod(0o755)
    if conf is not None:
        (tmp_path / "tvgw.conf").write_text(conf, encoding="utf-8")
    argv = stop.replace("$$", "$").replace("/etc/tvgw/tvgw.conf", str(tmp_path / "tvgw.conf"))
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
    "deploy/systemd/tvgw-pcap.service": "owned by the capture workstream; templating it is its follow-up",
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
