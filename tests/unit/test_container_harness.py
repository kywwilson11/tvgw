"""The container tier's own parts that need no Docker: the `docker run` line, the settings it writes, the
parsers, the settle loop, the stale-container rule, the image and the workflow (tests/container).

The Docker half of tests/container runs only in its own CI job, so a settings file tvgw would refuse, a
sampler that misreads /proc, or an image that drifted from the package's dependencies would otherwise
surface there first, as an installer failure that is not one."""

import itertools
import json
import re
import shutil
import subprocess
import sys

import pytest
import yaml
from conftest import ROOT

from tvgw import config

sys.path.insert(0, str(ROOT / "tests" / "container"))
sys.path.insert(0, str(ROOT / "tests" / "container" / "guest"))
import ctr
import listeners

HERE = ROOT / "tests" / "container"
WORKFLOW = ROOT / ".github" / "workflows" / "container.yml"
TEMPLATE = (ROOT / "deploy" / "tvgw.conf.example").read_text(encoding="utf-8")


# ---- the container -----------------------------------------------------------------------------------


def test_the_run_line_boots_systemd_with_what_it_needs_and_the_checkout_read_only():
    argv = ctr.run_argv("img:1", "tvgwc-1-x", "/some/checkout")
    assert argv[0] == "run" and argv[-1] == "img:1"
    pairs = list(itertools.pairwise(argv))
    for flag in ("--detach", "--privileged", "--cgroupns=private"):
        assert flag in argv
    assert ("--tmpfs", "/run") in pairs and ("--tmpfs", "/run/lock") in pairs
    assert ("--volume", "/lib/modules:/lib/modules:ro") in pairs
    assert ("--volume", f"/some/checkout:{ctr.CHECKOUT}:ro") in pairs
    assert ("--label", f"{ctr.LABEL}=1") in pairs and ("--name", "tvgwc-1-x") in pairs
    # the host name is the container's own, never a real machine's
    assert ("--hostname", "tvgw-container") in pairs


def test_a_container_is_named_for_its_run_and_module_and_a_dead_runs_are_stale():
    assert ctr.container_name("test_container_first_run", pid=42) == "tvgwc-42-test-container-first-run"
    names = ["tvgwc-1-a", "tvgwc-2-b-c", "tvgwc-x-a", "other", "tvgwc-3-"]
    assert ctr.stale(names, alive=lambda pid: pid == 2) == ["tvgwc-1-a"]


class Recorder:
    """subprocess.run for Docker: records each argv and answers from a script of results."""

    def __init__(self, *results):
        self.calls = []
        self.results = list(results)

    def __call__(self, argv, **kw):
        self.calls.append((argv, kw))
        rc, out, err = self.results.pop(0) if self.results else (0, "", "")
        return subprocess.CompletedProcess(argv, rc, out, err)


def test_docker_calls_carry_the_arguments_and_a_failure_names_the_command():
    rec = Recorder((0, "ok\n", ""), (1, "", "no such container\n"))
    d = ctr.Docker(run=rec)
    assert d("ps").stdout == "ok\n"
    assert rec.calls[0][0] == ["docker", "ps"] and rec.calls[0][1]["timeout"] == 600
    with pytest.raises(RuntimeError, match=r"docker rm x exited 1: no such container"):
        d("rm", "x")
    assert d("rm", "x", check=False).returncode == 0  # the recorder ran out: a plain 0


def test_docker_is_unavailable_with_the_reason_when_its_daemon_does_not_answer():
    assert ctr.Docker(run=Recorder((0, "29.4.3\n", ""))).available() == ""
    why = ctr.Docker(run=Recorder((1, "", "Cannot connect to the Docker daemon\n"))).available()
    assert "Cannot connect" in why

    def missing(argv, **kw):
        raise FileNotFoundError("docker")

    assert ctr.Docker(run=missing).available().startswith("docker:")


def test_every_gateway_call_is_bash_under_pipefail_in_the_container():
    rec = Recorder()
    gw = ctr.Gateway(ctr.Docker(run=rec), "tvgwc-1-x")
    gw.sh("echo hi")
    gw.write("/etc/tvgw/tvgw.conf", "A=1\n", mode="0640")
    argv, kw = rec.calls[0]
    assert argv == ["docker", "exec", "tvgwc-1-x", "bash", "-o", "pipefail", "-c", "echo hi"]
    argv, kw = rec.calls[1]
    assert argv[:4] == ["docker", "exec", "--interactive", "tvgwc-1-x"] and kw["input"] == "A=1\n"
    assert "chmod 0640 /etc/tvgw/tvgw.conf" in argv[-1]


def test_the_installer_runs_from_the_gateways_tree_with_the_pass_and_no_terminal(tmp_path):
    rec = Recorder((0, "tvgw: TV side up on eth1 (10.10.10.1)\n", ""), (76, "", ""))
    gw = ctr.Gateway(ctr.Docker(run=rec), "tvgwc-1-x", artifacts=tmp_path)
    assert gw.installer("bringup").returncode == 0
    assert gw.installer(None).returncode == 76
    assert rec.calls[0][0][-1] == f"TVGW_SETUP_PASS=bringup {ctr.INSTALL} </dev/null"
    assert rec.calls[1][0][-1] == f"{ctr.INSTALL} </dev/null"  # no pass: the deploy path
    kept = (tmp_path / "tvgwc-1-x" / "install-bringup.txt").read_text(encoding="utf-8")
    assert kept.startswith("exit 0\n") and "TV side up" in kept
    assert (tmp_path / "tvgwc-1-x" / "install-deploy.txt").read_text(encoding="utf-8").startswith("exit 76\n")


def test_the_tv_port_and_the_tv_carry_documentation_macs_so_a_replug_is_the_same_port():
    rec = Recorder()
    gw = ctr.Gateway(ctr.Docker(run=rec), "tvgwc-1-x")
    gw.add_tv()
    link = rec.calls[0][0][-1]
    assert f"ip link add {ctr.TV_IF} address {ctr.PORT_MAC} type veth peer name {ctr.TV_NIC}" in link
    assert f"link set {ctr.TV_NIC} address {ctr.TV_MAC}" in link
    for mac in (ctr.PORT_MAC, ctr.TV_MAC):
        assert re.fullmatch(r"00:00:5e:00:53:[0-9a-f]{2}", mac)  # RFC 7042's documentation range
    assert ctr.PORT_MAC != ctr.TV_MAC
    assert f"NetworkNamespacePath=/run/netns/{ctr.TV_NS}" in rec.calls[1][0][-1]  # the TV's DHCP client


def test_a_reboot_restarts_the_container_and_waits_for_systemd(tmp_path):
    rec = Recorder(
        (0, "tvgwc-1-x\n", ""), (0, "starting\n", ""), (0, "degraded\n", ""), (0, "x.service\n", "")
    )
    gw = ctr.Gateway(ctr.Docker(run=rec), "tvgwc-1-x", artifacts=tmp_path)
    slept = []
    gw.wait_booted = lambda timeout: ctr.Gateway.wait_booted(gw, timeout, sleep=slept.append)
    assert gw.reboot() == "degraded"
    assert rec.calls[0][0] == ["docker", "restart", "-t", "60", "tvgwc-1-x"]
    assert rec.calls[1][0][-1] == rec.calls[2][0][-1] == "systemctl is-system-running" and slept == [1]
    kept = (tmp_path / "tvgwc-1-x" / "reboot.txt").read_text(encoding="utf-8")
    assert kept == "systemd: degraded\nx.service\n"


# ---- the settings file -------------------------------------------------------------------------------


def rendered(wan_gw="192.0.2.1"):
    return ctr.render_settings(TEMPLATE, {**ctr.SETTINGS, "WAN_GW": wan_gw})


def test_the_settings_are_the_template_with_the_tv_named_by_a_documentation_mac(tmp_path):
    text = rendered()
    lines = text.splitlines()
    assert f"TV_MAC={ctr.TV_MAC}" in lines and "WAN_GW=192.0.2.1" in lines and "VPN_IF=none" in lines
    assert re.fullmatch(r"00:00:5e:00:53:[0-9a-f]{2}", ctr.TV_MAC)  # RFC 7042's documentation range
    # every other line is the template's own: its comments, its other keys, its commented reserved keys
    set_here = set(ctr.SETTINGS) | {"WAN_GW"}
    assert len(lines) == len(TEMPLATE.splitlines())
    for mine, theirs in zip(lines, TEMPLATE.splitlines(), strict=True):
        if mine.partition("=")[0] not in set_here:
            assert mine == theirs
    assert [line for line in lines if line.startswith("WAN_GW=")] == ["WAN_GW=192.0.2.1"]  # not the sample
    path = tmp_path / "tvgw.conf"
    path.write_text(text, encoding="utf-8")
    s = config.load(path)  # tvgw itself accepts it
    assert (s.tv_mac, s.tv_if, s.wan_if, s.vpn_if, s.adguard_listen) == (
        ctr.TV_MAC,
        ctr.TV_IF,
        ctr.WAN_IF,
        "none",
        "gateway",
    )
    assert (s.tv_ip, s.gw_ip, s.tv_net, s.profile) == (ctr.TV_IP, ctr.GW_IP, ctr.TV_NET, "lg-webos")


@pytest.mark.skipif(shutil.which("bash") is None, reason="needs bash")
def test_the_shell_scripts_read_the_same_settings(tmp_path):
    path = tmp_path / "tvgw.conf"
    path.write_text(rendered(), encoding="utf-8")
    out = subprocess.run(
        ["bash", "-c", f'. {path}; echo "$TV_MAC $TV_IF $WAN_IF $WAN_GW $UPLINK $VPN_IF $ADGUARD_LISTEN"'],
        capture_output=True,
        text=True,
        check=True,
    )
    assert out.stdout.split() == [ctr.TV_MAC, "eth1", "eth0", "192.0.2.1", "direct", "none", "gateway"]


def test_a_key_the_template_lacks_is_appended_and_a_commented_one_is_left_alone():
    text = ctr.render_settings("A=1 # one\n# B=2\nC=3\n", {"A": "9", "B": "8", "D": "7"})
    assert text == "A=9\n# B=2\nC=3\nB=8\nD=7\n"


def test_every_key_the_tier_sets_is_a_setting_tvgw_knows():
    assert set(ctr.SETTINGS) | {"WAN_GW"} <= config.writable_keys()


@pytest.mark.parametrize(
    ("text", "want"),
    [
        ("default via 198.51.100.1 dev eth0 \n", "198.51.100.1"),
        ("default via 198.51.100.1 dev eth0 proto static metric 100\n", "198.51.100.1"),
        ("default via 192.0.2.9 dev wlan0\ndefault via 198.51.100.1 dev eth0\n", "198.51.100.1"),
    ],
)
def test_the_uplinks_next_hop_comes_from_the_default_route(text, want):
    assert ctr.default_gateway(text) == want


@pytest.mark.parametrize("text", ["", "default dev eth0 scope link\n", "default via 192.0.2.9 dev wlan0\n"])
def test_no_default_route_on_the_uplink_is_an_error(text):
    with pytest.raises(ValueError, match="no default route via eth0"):
        ctr.default_gateway(text)


def test_the_reply_route_is_recognised_in_tvgw_apply_only_where_table_100_carries_the_tv_subnet():
    with_route = (
        'ip route replace "$TV_NET" dev "$TV_IF" scope link src "$GW_IP" table "$RT_TABLE" ||\n'
        '\techo "tvgw: $TV_IF not up yet" >&2\n'
    )
    assert ctr.reply_route_in_apply(with_route)
    assert not ctr.reply_route_in_apply(
        'ip route replace default via "$WAN_GW" dev "$WAN_IF" table "$RT_TABLE"\n'
    )
    assert not ctr.reply_route_in_apply('ip route replace "$TV_NET" dev "$TV_IF" scope link\n')  # main table
    # the real script answers one way or the other without raising
    assert ctr.reply_route_in_apply(ctr.APPLY.read_text(encoding="utf-8")) in (True, False)


# ---- the parsers ---------------------------------------------------------------------------------------


def test_the_tvs_lease_is_read_from_its_dhcp_hook():
    lease = ctr.parse_lease("ip=10.10.10.17\nmask=24\nrouter=10.10.10.1\ndns=10.10.10.1\nnoise\n")
    assert lease == {"ip": "10.10.10.17", "mask": "24", "router": "10.10.10.1", "dns": "10.10.10.1"}


HEADER = "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode\n"
TCP = HEADER + (
    "   0: 0100007F:0BB8 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 1\n"
    "   1: 010A0A0A:0035 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 2\n"
    "   2: 026433C6:9C40 0A7100CB:01BB 01 00000000:00000000 00:00000000 00000000     0        0 3\n"
    "   3: 00000000:0050 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 4\n"
)
UDP = HEADER + (
    "   0: 0100007F:0035 00000000:0000 07 00000000:00000000 00:00000000 00000000     0        0 5\n"
    "   1: 026433C6:D431 350200C0:0035 01 00000000:00000000 00:00000000 00000000     0        0 6\n"
    "   2: 00000000:0043 00000000:0000 07 00000000:00000000 00:00000000 00000000     0        0 7\n"
)
TCP6 = HEADER + (
    "   0: 00000000000000000000000000000000:0BB8 00000000000000000000000000000000:0000 0A 0 0 0 0 0 8\n"
    "   1: 00000000000000000000000001000000:0035 00000000000000000000000000000000:0000 0A 0 0 0 0 0 9\n"
)


def test_the_sampler_reads_listening_tcp_and_unconnected_udp_sockets_from_proc():
    assert listeners.parse(TCP, "tcp", False) == {
        ("tcp", "127.0.0.1", 3000),
        ("tcp", "10.10.10.1", 53),
        ("tcp", "0.0.0.0", 80),
    }  # the established connection is not a listener
    assert listeners.parse(UDP, "udp", False) == {("udp", "127.0.0.1", 53), ("udp", "0.0.0.0", 67)}
    assert listeners.parse(TCP6, "tcp", True) == {("tcp", "::", 3000), ("tcp", "::1", 53)}


def test_the_sampler_reads_every_table_and_skips_one_the_kernel_lacks():
    tables = {"/proc/net/tcp": TCP, "/proc/net/udp": UDP}

    def read(path):
        if path not in tables:
            raise FileNotFoundError(path)
        return tables[path]

    seen = listeners.sample(read)
    assert ("udp", "0.0.0.0", 67) in seen and ("tcp", "127.0.0.1", 3000) in seen
    text = listeners.lines(seen)
    # ordered by port, then protocol, then address
    assert text.splitlines()[:3] == ["tcp 10.10.10.1 53", "udp 127.0.0.1 53", "udp 0.0.0.0 67"]
    assert ctr.parse_listeners(text) == {ctr.Listener(*x) for x in seen}


def test_the_sampler_writes_its_file_and_runs_until_stopped(tmp_path):
    out = tmp_path / "listeners"
    proc = subprocess.Popen([sys.executable, "-I", str(HERE / "guest" / "listeners.py"), str(out)])
    try:
        for _ in range(50):
            if out.exists():
                break
            subprocess.run([sys.executable, "-c", "import time; time.sleep(0.1)"], check=True)
        assert out.exists() and proc.poll() is None
    finally:
        proc.kill()
        proc.wait()
    assert subprocess.run([sys.executable, "-I", str(HERE / "guest" / "listeners.py")]).returncode == 2


def test_a_wildcard_listener_on_a_watched_port_is_exposed_and_a_bound_one_is_not():
    seen = ctr.parse_listeners(
        "tcp 127.0.0.1 3000\nudp 10.10.10.1 53\ntcp 0.0.0.0 80\nudp :: 53\ntcp 0.0.0.0 24567\nbad line\n"
    )
    assert ctr.exposed(seen, [53, 3000]) == [ctr.Listener("udp", "::", 53)]
    assert ctr.exposed(seen, range(20000, 30000)) == [ctr.Listener("tcp", "0.0.0.0", 24567)]
    assert ctr.exposed(seen, [443]) == []


# ---- verify and the settle loop ------------------------------------------------------------------------


def checks(*failed):
    names = ["ruleset", "list_sentinels", "doh4_loaded", "services"]
    names += [n for n in failed if n not in names]
    return [{"name": n, "ok": n not in failed, "detail": "x" if n in failed else ""} for n in names]


def test_verifys_json_is_read_and_anything_else_is_a_failed_run():
    v = ctr.parse_verify(1, json.dumps({"ok": False, "checks": checks("list_sentinels")}))
    assert v.failed == ["list_sentinels"] and "list_sentinels: x" in v.summary()
    bad = ctr.parse_verify(1, "Traceback (most recent call last):\n  ...\nPermissionError\n")
    assert bad.failed == ["verify-output"] and "PermissionError" in bad.summary()


class Clock:
    def __init__(self):
        self.t = 0.0
        self.slept = []

    def __call__(self):
        return self.t

    def sleep(self, s):
        self.slept.append(s)
        self.t += s


SETTLING = frozenset({"list_sentinels", "doh4_loaded", "services"})


def scripted(*verdicts):
    it = iter(verdicts)
    return lambda: next(it)


def test_settle_waits_out_the_checks_that_settle_and_returns_the_pass():
    clock = Clock()
    verify = scripted(
        ctr.Verdict(1, checks("list_sentinels", "doh4_loaded")),
        ctr.Verdict(1, checks("list_sentinels")),
        ctr.Verdict(0, checks()),
    )
    v = ctr.settle(verify, SETTLING, timeout=600, interval=10, clock=clock, sleep=clock.sleep)
    assert v.rc == 0 and v.runs == 3 and clock.slept == [10, 10]


def test_settle_returns_a_real_failure_after_its_patience_without_waiting_the_timeout():
    clock = Clock()
    verify = scripted(*(ctr.Verdict(1, checks("ruleset", "list_sentinels")) for _ in range(10)))
    v = ctr.settle(verify, SETTLING, timeout=600, interval=10, patience=3, clock=clock, sleep=clock.sleep)
    assert v.rc == 1 and v.runs == 3 and v.failed == ["ruleset", "list_sentinels"]


def test_a_real_failure_that_clears_resets_the_patience():
    clock = Clock()
    verify = scripted(
        ctr.Verdict(1, checks("ruleset")),
        ctr.Verdict(1, checks("ruleset")),
        ctr.Verdict(1, checks("services")),
        ctr.Verdict(1, checks("ruleset")),
        ctr.Verdict(0, checks()),
    )
    v = ctr.settle(verify, SETTLING, timeout=600, interval=10, patience=3, clock=clock, sleep=clock.sleep)
    assert v.rc == 0 and v.runs == 5


def test_settle_gives_up_at_the_timeout_with_the_last_verdict():
    clock = Clock()
    verify = scripted(*(ctr.Verdict(1, checks("list_sentinels")) for _ in range(100)))
    v = ctr.settle(verify, SETTLING, timeout=60, interval=10, clock=clock, sleep=clock.sleep)
    assert v.rc == 1 and v.failed == ["list_sentinels"] and clock.t == 60 and v.runs == 7


def test_poll_returns_the_seconds_until_the_probe_held():
    clock = Clock()
    answers = iter([False, False, True])
    assert ctr.poll(lambda: next(answers), timeout=30, interval=1, clock=clock, sleep=clock.sleep) == 2
    assert clock.slept == [1, 1]


def test_poll_gives_up_after_its_timeout_and_a_late_success_does_not_count():
    clock = Clock()
    assert ctr.poll(lambda: False, timeout=30, interval=1, clock=clock, sleep=clock.sleep) is None
    assert clock.t == 31  # the probe at 31 s, past the deadline, ended the wait

    clock = Clock()

    def slow():  # a probe that holds, but only once its own timeout has carried it past the deadline
        clock.t += 31
        return True

    assert ctr.poll(slow, timeout=30, clock=clock, sleep=clock.sleep) is None


# ---- the image and the guest scripts -----------------------------------------------------------------


DOCKERFILE = (HERE / "Dockerfile").read_text(encoding="utf-8")


def debian_13_pins(text):
    return set(re.findall(r"debian:13@(sha256:[0-9a-f]{64})", text))


def test_the_image_is_debian_13_by_digest_the_same_one_the_release_checks_install_into():
    (pin,) = debian_13_pins(DOCKERFILE)
    assert re.search(rf"^FROM debian:13@{pin}$", DOCKERFILE, re.M)
    assert debian_13_pins((ROOT / ".github" / "workflows" / "release.yml").read_text(encoding="utf-8")) == {
        pin
    }
    assert re.search(r"read from Docker Hub on \d{4}-\d{2}-\d{2}", DOCKERFILE)


def packages(spec_lines):
    return {re.split(r"[\s(#]", line.strip().lstrip("- "), maxsplit=1)[0] for line in spec_lines}


def test_the_image_holds_every_package_the_deb_depends_on_or_recommends():
    nfpm = yaml.safe_load((ROOT / "packaging" / "nfpm.yaml").read_text(encoding="utf-8"))
    wanted = packages(nfpm["depends"]) | packages(nfpm.get("recommends", []))
    m = re.search(r"apt-get install -y --no-install-recommends(.*?)&& rm -rf", DOCKERFILE, re.S)
    assert m, "the Dockerfile's apt-get install line moved"
    installed = set(m.group(1).replace("\\", " ").split())
    assert wanted <= installed, sorted(wanted - installed)
    # and what a computer has that the slim image lacks, which NetworkManager and the TV need
    assert {"systemd-sysv", "udev", "dbus", "busybox", "rsync"} <= installed
    assert "wireshark-common/install-setuid boolean false" in DOCKERFILE  # dumpcap stays 0755 root:root


def test_the_image_boots_systemd_and_carries_only_its_own_files():
    assert re.search(r"^CMD \[\"/sbin/init\"\]$", DOCKERFILE, re.M)
    assert re.search(r"^STOPSIGNAL SIGRTMIN\+3$", DOCKERFILE, re.M)
    assert re.search(r"^COPY image/ /$", DOCKERFILE, re.M)
    assert (HERE / ".dockerignore").read_text(encoding="utf-8").split("\n", 1)[1].split() == ["*", "!image"]
    assert ctr.image_files()[0] == HERE / "Dockerfile"
    assert {p.relative_to(HERE / "image").as_posix() for p in ctr.image_files()[1:]} == {
        "etc/NetworkManager/conf.d/10-tvgw-container.conf",
        "etc/dnsmasq.d/tvgw.conf",
        "etc/sysctl.d/10-tvgw-container.conf",
    }


def settings_lines(path):
    return [
        line.strip()
        for line in path.read_text(encoding="utf-8").splitlines()
        if line.strip()[:1] not in ("#", "")
    ]


def test_the_image_serves_nothing_on_53_leaves_resolv_conf_alone_and_does_not_forward():
    etc = HERE / "image" / "etc"
    # install.sh writes /etc/dnsmasq.d/tvgw.conf; until then dnsmasq answers neither DNS nor DHCP
    assert settings_lines(etc / "dnsmasq.d" / "tvgw.conf") == ["port=0"]
    assert settings_lines(etc / "NetworkManager" / "conf.d" / "10-tvgw-container.conf") == [
        "[main]",
        "dns=none",
    ]
    assert settings_lines(etc / "sysctl.d" / "10-tvgw-container.conf") == ["net.ipv4.ip_forward = 0"]


def test_the_tvs_dhcp_hook_is_an_executable_posix_script_the_gate_shellchecks():
    hook = HERE / "guest" / "tv-dhcp.sh"
    assert hook.read_bytes()[:10] == b"#!/bin/sh\n" and hook.stat().st_mode & 0o111
    text = (ROOT / "Makefile").read_text(encoding="utf-8").replace("\\\n", " ")
    assert "tests/container/guest/tv-dhcp.sh" in re.search(r"^SH_PATHS := (.*)$", text, re.M).group(1).split()
    assert "-s {GUEST}/tv-dhcp.sh" in (HERE / "ctr.py").read_text(encoding="utf-8")  # what udhcpc runs


@pytest.mark.skipif(shutil.which("sh") is None, reason="needs sh")
@pytest.mark.parametrize("event", ["bound", "renew"])
def test_the_dhcp_hook_writes_the_lease_it_was_given(tmp_path, event):
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    (bin_dir / "ip").write_text(f'#!/bin/sh\necho "ip $*" >>{tmp_path}/calls\n', encoding="utf-8")
    (bin_dir / "ip").chmod(0o755)
    lease = tmp_path / "lease"
    env = {
        "PATH": f"{bin_dir}:/usr/bin:/bin",
        "TV_LEASE": str(lease),
        "interface": "tvnic",
        "ip": "10.10.10.17",
        "mask": "24",
        "router": "10.10.10.1",
        "dns": "10.10.10.1",
    }
    out = subprocess.run(
        ["sh", str(HERE / "guest" / "tv-dhcp.sh"), event], env=env, capture_output=True, text=True
    )
    assert out.returncode == 0, out.stderr
    assert ctr.parse_lease(lease.read_text(encoding="utf-8"))["ip"] == "10.10.10.17"
    calls = (tmp_path / "calls").read_text(encoding="utf-8").splitlines()
    assert calls == [
        "ip -4 addr flush dev tvnic",
        "ip -4 addr add 10.10.10.17/24 dev tvnic",
        "ip -4 route replace default via 10.10.10.1 dev tvnic",
    ]
    out = subprocess.run(["sh", str(HERE / "guest" / "tv-dhcp.sh"), "deconfig"], env=env, capture_output=True)
    assert out.returncode == 0 and not lease.exists()


# ---- the workflow --------------------------------------------------------------------------------------


def load_workflow():
    wf = yaml.safe_load(WORKFLOW.read_text(encoding="utf-8"))
    wf["on"] = wf.pop(True)
    return wf


def test_the_workflow_runs_on_pull_requests_and_pushes_to_main_but_not_for_docs():
    wf = load_workflow()
    assert wf["permissions"] == {"contents": "read"}
    on = wf["on"]
    assert on["push"]["branches"] == ["main"] and "workflow_dispatch" in on
    for trigger in ("push", "pull_request"):
        assert on[trigger]["paths-ignore"] == ["**/*.md", "docs/**"], trigger


def test_the_workflow_runs_the_tier_on_a_hosted_runner_and_cannot_skip_it():
    """A container tier that skipped itself (no Docker) would pass every installer change unexamined."""
    (job,) = load_workflow()["jobs"].values()
    assert job["runs-on"] == "ubuntu-latest" and job["timeout-minutes"] <= 60
    runs = [step.get("run", "") for step in job["steps"]]
    assert any(r.startswith("docker build --tag tvgw-container tests/container") for r in runs)
    suite = next(r for r in runs if "-m container tests/container" in r)
    for part in (
        "TVGW_CONTAINER_REQUIRED=1",
        "TVGW_CONTAINER_IMAGE=tvgw-container",
        "TVGW_CONTAINER_ARTIFACTS=",
    ):
        assert part in suite
    cleanup = next(s for s in job["steps"] if "docker rm" in s.get("run", ""))
    assert cleanup["if"] == "always()" and f"label={ctr.LABEL}" in cleanup["run"]
    upload = next(s for s in job["steps"] if s.get("uses", "").startswith("actions/upload-artifact@"))
    assert upload["if"] == "always()"


def test_every_action_of_the_workflow_is_pinned_by_commit_with_its_version_named():
    uses = [line.strip() for line in WORKFLOW.read_text(encoding="utf-8").splitlines() if "uses:" in line]
    assert len(uses) == 3
    for line in uses:
        assert re.fullmatch(r"- uses: [\w.-]+/[\w.-]+@[0-9a-f]{40} # v\d+\.\d+\.\d+", line), line


def test_every_module_of_the_tier_is_marked_so_the_unit_suite_never_collects_it():
    modules = sorted(HERE.glob("test_*.py"))
    assert modules
    for path in modules:
        assert "pytestmark = pytest.mark.container" in path.read_text(encoding="utf-8"), path.name
