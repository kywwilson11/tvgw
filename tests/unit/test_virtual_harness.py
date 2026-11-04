"""The virtual gateway's own parts that need no root: the matrix file, the conf, the variants, the counter
parser, and the probes and services of tests/virtual/agent.py over loopback.

The root half of tests/virtual runs only in its own CI job, so a broken matrix row or a probe that
misreads a reply would otherwise surface there first, as a firewall failure that is not one."""

import ast
import errno
import json
import os
import shutil
import socket
import subprocess
import sys

import pytest
from conftest import ROOT

sys.path.insert(0, str(ROOT / "tests" / "virtual"))
import agent
import vnet

from tvgw import profile

SCRIPT = vnet.APPLY.read_text(encoding="utf-8")
SCENARIOS = vnet.parse_matrix(vnet.MATRIX.read_text(encoding="utf-8"))
PROBES = {"dns-udp", "dns-tcp", "tcp", "udp", "ping", "gre", "udp6"}


# --- the matrix --------------------------------------------------------------------------------------


def test_the_matrix_names_four_scenarios_with_settings_the_script_accepts():
    assert [s.name for s in SCENARIOS] == ["direct", "strict", "vpn", "generic"]
    choices = vnet.script_choices(SCRIPT)
    for s in SCENARIOS:
        assert set(s.settings) - {"PROFILE"} == set(vnet.CONF_SWITCHES), s.name
        for key, value in s.settings.items():
            if key == "PROFILE":  # (profile) a bundled profile, not a switch with case arms
                assert value in profile.bundled_names(), (s.name, value)
            else:
                assert value in choices[key], (s.name, key, value)
    # (profile) the general profile's scenario has no wall to count, so the port goes to the odd-port rule
    generic = next(s for s in SCENARIOS if s.name == "generic")
    assert generic.settings["PROFILE"] == "generic-tv"
    assert not any(r.counter == "LG adtech port" for r in generic.rows)
    assert any(r.port == 4431 and r.counter == "STRICT_PORTS=no: count only" for r in generic.rows)
    # the first scenario is the shipped default, so the main matrix is what a new gateway runs
    assert SCENARIOS[0].settings == {
        "UPLINK": "direct",
        "BLOCK_QUIC": "yes",
        "STRICT_PORTS": "no",
        "DNSGATE": "count",
    }


def test_every_counter_a_row_names_is_a_counted_rule_of_the_script():
    """A misspelt comment would make its row fail on the namespace gateway as if the rule had not matched."""
    counted = vnet.counted_comments(SCRIPT)
    named = {r.counter for s in SCENARIOS for r in s.rows if r.counter}
    assert named - counted == set()


def test_every_row_is_well_formed_and_said_once():
    for s in SCENARIOS:
        ids = [r.id for r in s.rows]
        assert len(ids) == len(set(ids)), s.name
        for r in s.rows:
            assert r.source in {"tv", "tv-foreign", "tv-alias", "wan"}, r  # (guard) tv-alias
            assert r.kind in PROBES, r
            head, _, name = r.verdict.partition(":")
            assert head in {"pass", "answer", "reject", "drop", "sent"}, r
            assert not name or name in vnet.NAMES, r
            # every refusal is pinned to the rule that made it
            assert r.counter or head not in {"reject", "drop", "sent"}, r


def test_the_matrix_holds_the_guarantees_the_task_names():
    """The rows that must exist whatever else changes: DNS redirected, DoT/DoQ/DoH/QUIC refused, the
    gateway's other ports and a foreign source dropped, the web reached by the chosen uplink."""
    direct = {(r.kind, r.target, r.port): r for r in SCENARIOS[0].rows if r.source == "tv"}
    assert direct[("dns-udp", vnet.RESOLVER, 53)].verdict == "answer:gateway"
    assert direct[("dns-tcp", vnet.RESOLVER, 53)].verdict == "answer:gateway"
    for port in (853, 784, 8853):
        assert direct[("udp", vnet.RESOLVER, port)].verdict == "reject"
    assert direct[("tcp", vnet.DOH, 443)].verdict == "reject"
    assert direct[("udp", vnet.WEB, 443)].verdict == "reject"
    assert direct[("tcp", vnet.GW_TV, 8000)].verdict == "drop"
    assert direct[("tcp", vnet.WEB, 443)].verdict == "pass:wlan0"
    vpn = {(r.kind, r.target, r.port): r for r in SCENARIOS[2].rows if r.source == "tv"}
    assert vpn[("tcp", vnet.WEB, 443)].verdict == "pass:tun0"
    assert all(any(r.source == "tv-foreign" and r.verdict == "drop" for r in s.rows) for s in SCENARIOS)


def test_a_row_written_back_reads_the_same():
    row = SCENARIOS[0].rows[0]
    again = vnet.parse_matrix(f"[x] UPLINK=direct\n{row.line()}\n")[0].rows[0]
    assert again == row
    assert vnet.Row("tv", "tcp", vnet.WEB, 443, "pass:wlan0", None).expected() == f"pass:{vnet.GW_WLAN}"
    assert (
        vnet.Row("tv", "dns-udp", vnet.RESOLVER, 53, "answer:gateway", None).expected()
        == f"answer:{vnet.GW_ANSWER}"
    )
    assert vnet.Row("tv", "gre", vnet.WEB, None, "drop", "x").expected() == "drop"


@pytest.mark.parametrize(
    "text",
    [
        "tv tcp 203.0.113.10 443 drop -\n",  # a row before any scenario
        "[x] UPLINK=direct\ntv tcp 203.0.113.10 443 drop\n",  # five fields
        "[x] WAN_GW=198.51.100.1\n",  # not a switch the scenario may set
        "[x] UPLINK=direct\n[x] UPLINK=vpn\n",  # the same name twice
    ],
)
def test_a_malformed_matrix_is_refused(text):
    with pytest.raises(ValueError):
        vnet.parse_matrix(text)


def test_comments_and_blank_lines_are_ignored():
    text = "# a note\n\n[x] UPLINK=vpn  # trailing\ntv udp 203.0.113.10 443 reject QUIC: force TCP+TLS so SNI is visible\n"
    (s,) = vnet.parse_matrix(text)
    assert s.settings == {"UPLINK": "vpn"}
    assert s.rows[0].counter == "QUIC: force TCP+TLS so SNI is visible"


# --- the conf and the variants -----------------------------------------------------------------------


def test_the_conf_reads_back_in_bash_as_written():
    bash = shutil.which("bash")
    if bash is None:
        pytest.skip("bash is not installed here")
    conf = vnet.render_conf(SCENARIOS[2].settings)
    script = '. /dev/stdin; printf "%s %s %s\\n" "$UPLINK" "$WAN_IF" "$WAN_GW"'
    out = subprocess.run([bash, "-euc", script], input=conf, capture_output=True, text=True, encoding="utf-8")
    assert out.stdout == f"vpn wlan0 {vnet.WAN_GW}\n"


# --- the interface names (TVGW_VIRTUAL_IFNAMES) --------------------------------------------------------


def test_the_interface_names_are_one_of_two_sets_and_a_misspelt_choice_is_refused():
    default = {"TV_IF": "eth0", "WAN_IF": "wlan0", "VPN_IF": "tun0"}
    assert vnet.ifnames(None) == vnet.ifnames("") == vnet.ifnames("default") == default
    assert vnet.ifnames("alt") == {"TV_IF": "tvport0", "WAN_IF": "uplink0", "VPN_IF": "wg0"}
    with pytest.raises(ValueError, match="TVGW_VIRTUAL_IFNAMES='alternative'"):
        vnet.ifnames("alternative")
    # none of the other names is one tvgw-apply falls back to, so a setting the script ignored would show
    assert not set(vnet.IFNAMES["alt"].values()) & {*default.values(), "wgpia0"}


def test_the_default_names_leave_the_conf_as_it_was():
    """Unset, the suite runs the script's own defaults: TV_IF and VPN_IF are not written."""
    if vnet.IFNAMES_CHOICE != "default":
        pytest.skip("this run chose other interface names")
    assert vnet.render_conf({}) == (
        f"WAN_IF=wlan0\nWAN_GW={vnet.WAN_GW}\nTV_IP={vnet.TV_IP}\nTV_MAC={vnet.TV_MAC}\n"
    )
    assert vnet.VPN_DROP == 'iifname { "tun0", "wgpia0" }'


def test_a_module_on_the_shared_gateway_names_its_ports_through_vnet():
    """A test that takes the shared `net` fixture reaches the gateway's ports as vnet.TV_IF, vnet.WAN_IF
    and vnet.VPN_IF, never by a default name written out, or the `alt` run sends it to a port that does
    not exist. Modules that build a topology of their own (AdGuard's) name its ports as they like."""
    defaults = set(vnet.IFNAMES["default"].values())
    found = []
    for path in sorted((ROOT / "tests" / "virtual").glob("test_*.py")):
        tree = ast.parse(path.read_text(encoding="utf-8"))
        shared = any(
            isinstance(node, ast.FunctionDef) and any(a.arg == "net" for a in node.args.args)
            for node in ast.walk(tree)
        )
        if shared:
            found += [
                f"{path.name}:{node.lineno} {node.value!r}"
                for node in ast.walk(tree)
                if isinstance(node, ast.Constant) and node.value in defaults
            ]
    assert not found, found


def alt_vnet(expr: str) -> str:
    """`expr` evaluated in a fresh interpreter that imported vnet with TVGW_VIRTUAL_IFNAMES=alt; a reload
    here would hand the rest of this module's tests new dataclasses that compare unequal to the old."""
    code = f"import sys; sys.path.insert(0, {str(ROOT / 'tests' / 'virtual')!r}); import vnet; print({expr})"
    out = subprocess.run(
        [sys.executable, "-c", code],
        env={"PATH": os.environ.get("PATH", ""), "TVGW_VIRTUAL_IFNAMES": "alt"},
        capture_output=True,
        text=True,
        encoding="utf-8",
    )
    assert out.returncode == 0, out.stderr
    return out.stdout.rstrip("\n")


def test_the_alternative_names_are_written_where_the_script_reads_them():
    bash = shutil.which("bash")
    if bash is None:
        pytest.skip("bash is not installed here")
    conf = alt_vnet("vnet.render_conf({'UPLINK': 'vpn'}), end=''")
    script = '. /dev/stdin; printf "%s %s %s %s\\n" "$TV_IF" "$WAN_IF" "$VPN_IF" "$UPLINK"'
    out = subprocess.run([bash, "-euc", script], input=conf, capture_output=True, text=True, encoding="utf-8")
    assert out.stdout == "tvport0 uplink0 wg0 vpn\n", out.stderr
    # the input chain's drop names the third tunnel beside PIA's two, as the script renders it
    assert alt_vnet("vnet.VPN_DROP") == 'iifname { "tun0", "wgpia0", "wg0" }'
    assert 'VPN_DROP+=", \\"$VPN_IF\\""' in SCRIPT
    assert alt_vnet("vnet.TV_IF, vnet.WAN_IF, vnet.VPN_IF") == "tvport0 uplink0 wg0"


def test_a_misspelt_choice_stops_the_import():
    code = f"import sys; sys.path.insert(0, {str(ROOT / 'tests' / 'virtual')!r}); import vnet"
    out = subprocess.run(
        [sys.executable, "-c", code],
        env={"PATH": os.environ.get("PATH", ""), "TVGW_VIRTUAL_IFNAMES": "Alt"},
        capture_output=True,
        text=True,
        encoding="utf-8",
    )
    assert out.returncode != 0 and "TVGW_VIRTUAL_IFNAMES='Alt'" in out.stderr


def test_the_switch_values_come_from_the_scripts_own_case_arms():
    choices = vnet.script_choices(SCRIPT)
    assert set(choices["UPLINK"]) >= {"direct", "vpn"}
    assert set(choices["BLOCK_QUIC"]) == set(choices["STRICT_PORTS"]) == {"yes", "no"}
    assert set(choices["DNSGATE"]) >= {"off", "count"}
    assert set(choices["CAPTURE_MODE"]) == {"full", "headers"}  # (capture) checked, not probed
    assert set(choices["ADTECH_PORT_WALL"]) == {"yes", "no"}  # (acr) checked both ways, probed at yes
    # a value added to an arm is a variant at once
    grown = SCRIPT.replace("\toff | count) ;;", "\toff | count | enforce) ;;", 1)
    assert "enforce" in vnet.script_choices(grown)["DNSGATE"]


def test_every_combination_is_a_variant():
    v = vnet.variants(
        {"UPLINK": ["direct", "vpn"], "BLOCK_QUIC": ["yes", "no"], "DNSGATE": ["off", "count", "x"]}
    )
    assert len(v) == 12 and len({vnet.variant_name(x) for x in v}) == 12
    assert v[0] == {"UPLINK": "direct", "BLOCK_QUIC": "yes", "DNSGATE": "off"}
    assert vnet.variant_name(v[0]) == "uplink=direct-block_quic=yes-dnsgate=off"


# --- the counters ------------------------------------------------------------------------------------

LISTING = json.dumps(
    {
        "nftables": [
            {"metainfo": {"version": "1.1.3"}},
            {
                "rule": {
                    "comment": "DoT/DoQ",
                    "expr": [{"counter": {"packets": 2, "bytes": 120}}, {"reject": None}],
                }
            },
            {
                "rule": {
                    "comment": "a dns redirect",
                    "expr": [{"counter": {"packets": 1, "bytes": 60}}, {"dnat": {}}],
                }
            },
            {
                "rule": {
                    "comment": "a dns redirect",
                    "expr": [{"counter": {"packets": 3, "bytes": 180}}, {"dnat": {}}],
                }
            },
            {"rule": {"comment": "LAN", "expr": [{"counter": {"packets": 0, "bytes": 0}}, {"drop": None}]}},
            {"rule": {"comment": "a log only", "expr": [{"log": {}}]}},
            {"rule": {"expr": [{"counter": {"packets": 9, "bytes": 9}}, {"accept": None}]}},
        ]
    }
)


def test_counters_are_summed_by_comment_with_the_verdict_of_the_rule():
    assert vnet.counters(LISTING) == {
        "DoT/DoQ": (2, "reject"),
        "a dns redirect": (4, "other"),
        "LAN": (0, "drop"),
    }
    assert vnet.counters("") == {}


def test_ticked_is_what_each_counter_gained():
    before = vnet.counters(LISTING)
    after = {**before, "LAN": (3, "drop"), "new": (1, "other")}
    assert vnet.ticked(before, after) == {"LAN": 3, "new": 1}


def test_a_crashed_runs_namespaces_are_found_and_nobody_elses():
    listing = "tvgwv-111-gw (id: 0)\ntvgwv-222-tv\nsomeone-else\ntvgwv-x-gw\ntvgwv-333-wan (id: 4)\n"
    alive = {222}
    assert vnet.stale_namespaces(listing, alive=lambda pid: pid in alive) == ["tvgwv-111-gw", "tvgwv-333-wan"]


def test_the_root_half_says_what_it_lacks():
    missing = vnet.prerequisites()
    assert isinstance(missing, list)
    if not sys.platform.startswith("linux"):
        assert "Linux" in missing


# --- the agent: DNS bytes ----------------------------------------------------------------------------


def test_a_dns_answer_is_read_back_by_the_probe():
    q = agent.dns_query(0x1234, "probe.tvgw.example")
    assert q[:2] == b"\x12\x34" and q.endswith(b"\x00\x01\x00\x01")
    reply = agent.dns_answer(q, "198.51.100.153")
    assert agent.dns_parse(reply, 0x1234) == "198.51.100.153"
    assert agent.dns_parse(reply, 0x4321) is None  # someone else's reply
    assert agent.dns_parse(q, 0x1234) is None  # a query, not a reply
    assert agent.dns_parse(reply[:-2], 0x1234) is None  # cut short
    assert agent.dns_parse(b"\x00", 1) is None


def test_failures_are_classed_as_the_matrix_spells_them():
    assert agent._failure(TimeoutError()) == "drop"
    for code in (errno.ECONNREFUSED, errno.ECONNRESET, errno.EHOSTUNREACH, errno.ENETUNREACH):
        assert agent._failure(OSError(code, "x")) == "reject"
    assert agent._failure(OSError(errno.EACCES, "x")) == "error:EACCES"
    assert agent._failure(ValueError("x")) == "error:ValueError"


def test_an_unknown_probe_is_a_usage_error(capsys):
    assert agent.main(["probe", "smoke", "192.0.2.1"]) == 2
    assert "unknown probe" in capsys.readouterr().err


# --- the agent over loopback -------------------------------------------------------------------------


def free_port(kind: int) -> int:
    with socket.socket(socket.AF_INET, kind) as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def free_port_tcp_and_udp() -> int:
    """A port free on TCP and on UDP at once: the agent's DNS listener binds both. A port free on UDP alone
    met a TCP connection of the CI runner's on the same number (2026-11-04, "Address already in use")."""
    for _ in range(64):
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as t:
            t.bind(("127.0.0.1", 0))
            port = t.getsockname()[1]
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as u:
                try:
                    u.bind(("127.0.0.1", port))
                except OSError:
                    continue
                return port
    raise RuntimeError("no loopback port free on both TCP and UDP")


def _serve_on_free_ports() -> tuple[subprocess.Popen, dict[str, int]]:
    """The agent started on freshly chosen ports; a port taken between the choice and the agent's bind
    (the usual race of choosing a port by binding and closing) is tried again with new ports."""
    last = ""
    for _ in range(3):
        tcp, udp, dns = free_port(socket.SOCK_STREAM), free_port(socket.SOCK_DGRAM), free_port_tcp_and_udp()
        argv = [sys.executable, "-I", str(vnet.AGENT), "serve", "--bind", "127.0.0.1", "--tcp", str(tcp)]
        argv += ["--udp", str(udp), "--dns", "203.0.113.153", "--dns-port", str(dns)]
        p = subprocess.Popen(
            argv, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, encoding="utf-8"
        )
        if p.stdout.readline().strip() == "ready":
            return p, {"tcp": tcp, "udp": udp, "dns": dns}
        p.kill()
        p.wait(timeout=5)
        last = p.stderr.read()
        if "Address already in use" not in last:
            break
    raise AssertionError(last)


@pytest.fixture
def served():
    """agent.py serve on loopback, as the namespaces run it: a child interpreter, isolated (-I)."""
    p, ports = _serve_on_free_ports()
    try:
        yield ports
    finally:
        p.kill()
        p.wait(timeout=5)


def test_tcp_and_udp_probes_report_the_address_the_far_end_saw(served):
    assert agent.probe("tcp", "127.0.0.1", served["tcp"], None, None, 2.0) == "pass:127.0.0.1"
    assert agent.probe("udp", "127.0.0.1", served["udp"], None, None, 2.0) == "pass:127.0.0.1"


def test_a_udp_probe_can_send_from_a_fixed_source_port(served):
    """(guard) DHCP is allowed from source port 68 only; the probe must be able to send from it."""
    import socket

    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
        s.bind(("127.0.0.1", 0))
        free = s.getsockname()[1]
    assert agent.probe("udp", "127.0.0.1", served["udp"], None, None, 2.0, free) == "pass:127.0.0.1"
    assert agent.probe_udp("127.0.0.1", served["udp"], "127.0.0.1", 2.0, 0) == "pass:127.0.0.1"


def test_dns_probes_get_the_resolvers_answer_over_udp_and_tcp(served):
    for kind in ("dns-udp", "dns-tcp"):
        assert agent.probe(kind, "127.0.0.1", served["dns"], None, None, 2.0) == "answer:203.0.113.153"


def test_a_closed_port_is_a_reject_not_a_drop(served):
    closed = free_port(socket.SOCK_STREAM)
    assert agent.probe("tcp", "127.0.0.1", closed, None, None, 2.0) == "reject"


def test_the_probe_command_prints_one_verdict_line(served):
    out = subprocess.run(
        [sys.executable, "-I", str(vnet.AGENT), "probe", "tcp", "127.0.0.1", str(served["tcp"])],
        capture_output=True,
        text=True,
        encoding="utf-8",
        timeout=30,
    )
    assert (out.returncode, out.stdout) == (0, "pass:127.0.0.1\n")


def test_a_held_connection_echoes_each_line(served):
    p = subprocess.Popen(
        [sys.executable, "-I", str(vnet.AGENT), "probe", "hold", "127.0.0.1", str(served["tcp"])],
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        text=True,
        encoding="utf-8",
    )
    try:
        assert p.stdout.readline().strip() == "connected:127.0.0.1"
        p.stdin.write("one\n")
        p.stdin.flush()
        assert p.stdout.readline().strip() == "echo:one"
        p.stdin.close()
        assert p.wait(timeout=10) == 0
    finally:
        p.kill()


# --- the workflow ------------------------------------------------------------------------------------


def test_the_workflow_runs_the_suite_as_root_and_cannot_skip_it():
    """A virtual job that skipped itself (no root, no nft) would pass every firewall change unexamined."""
    yaml = pytest.importorskip("yaml")
    text = (ROOT / ".github" / "workflows" / "virtual.yml").read_text(encoding="utf-8")
    wf = yaml.safe_load(text)
    assert wf["permissions"] == {"contents": "read"}
    jobs = wf["jobs"]
    assert {name: job["runs-on"] for name, job in jobs.items()} == {
        "virtual": "ubuntu-latest",
        "virtual-arm64": "ubuntu-24.04-arm",
    }
    for job in jobs.values():
        runs = [step.get("run", "") for step in job["steps"]]
        suite = next(r for r in runs if "-m virtual tests/virtual" in r)
        assert (
            suite.startswith("sudo ")
            and "TVGW_VIRTUAL_REQUIRED=1" in suite
            and "TVGW_VIRTUAL_ARTIFACTS=" in suite
        )
        assert any("nftables" in r and "iproute2" in r for r in runs)
        upload = next(s for s in job["steps"] if s.get("uses", "").startswith("actions/upload-artifact@"))
        assert upload["if"] == "always()"
        cleanup = next(s for s in job["steps"] if "ip netns del" in s.get("run", ""))
        assert cleanup["if"] == "always()" and "tvgwv-" in cleanup["run"] and vnet.PREFIX == "tvgwv-"


def test_the_workflow_takes_adguard_from_the_pin_in_aghinstall():
    """(adguard) One pin: the workflow names no version and no hash of its own, fetches through the
    module tvgw adguard install uses, and checks the hash again with sha256sum."""
    import re

    yaml = pytest.importorskip("yaml")
    from tvgw import aghinstall

    text = (ROOT / ".github" / "workflows" / "virtual.yml").read_text(encoding="utf-8")
    assert not re.search(r"\b[0-9a-f]{64}\b", text) and "0.107." not in text
    jobs = yaml.safe_load(text)["jobs"]
    # each job's architecture picks its asset from the pin: amd64 on ubuntu-latest, arm64 on the arm runner
    assert (
        {job["env"]["ARCH"] for job in jobs.values()} == set(aghinstall.PIN["assets"]) == {"amd64", "arm64"}
    )
    for job in jobs.values():
        fetch = next(s["run"] for s in job["steps"] if "aghinstall" in s.get("run", ""))
        assert 'aghinstall.fetch_release(dest, os.environ["ARCH"])' in fetch
        assert 'aghinstall.PIN["assets"][os.environ["ARCH"]]' in fetch
        assert "sha256sum -c" in fetch and "TVGW_VIRTUAL_ADGUARD=" in fetch
        suite = next(s["run"] for s in job["steps"] if "-m virtual tests/virtual" in s.get("run", ""))
        assert "TVGW_VIRTUAL_HOST_NET=1" in suite


def test_every_action_of_the_workflow_is_pinned_by_commit_with_its_version_named():
    import re

    text = (ROOT / ".github" / "workflows" / "virtual.yml").read_text(encoding="utf-8")
    uses = [line.strip() for line in text.splitlines() if "uses:" in line]
    assert len(uses) == 6  # checkout, setup-python and the upload, in each of the two jobs
    for line in uses:
        assert re.fullmatch(r"- uses: [\w.-]+/[\w.-]+@[0-9a-f]{40} # v\d+\.\d+\.\d+", line), line
