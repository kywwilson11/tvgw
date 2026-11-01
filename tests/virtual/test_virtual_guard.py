"""The guard in the namespace gateway: 11 F6's acceptance test, run on a kernel (design decision 42).

The guard table is rendered from deploy/nftables/guard.nft.template as install.sh renders it and
loaded in the `gw` namespace beside the `direct` scenario's tables. Canary services stand in for the
Pi's co-tenants (RDP, SMB, JupyterHub's proxy, an AirPlay port, SSH, mDNS), each bound to the
wildcard and to a second address standing for the Pi's home-LAN address. From the TV, with inet tvgw
loaded, only DNS, DHCP from source port 68, and nginx's 80 and 443 answer. After `nft delete table inet
tvgw` (the stop, a failed boot apply, the half-apply case) the same holds, and the guard's last input
counter is what grows. The weak-host case, a route to the LAN address by the gateway, reaches nothing.
Re-applying tvgw leaves the guard's counter where it was. And a canary under systemd's IPAddressDeny
does not answer the TV even with both tables gone.

Run as root on a Linux machine or VM (tests/virtual/README.md):

    sudo env PYTHONPATH=src python3 -m pytest -m virtual tests/virtual -q -p no:cacheprovider
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import time
from pathlib import Path

import pytest
import vnet

pytestmark = pytest.mark.virtual

TEMPLATE = vnet.ROOT / "deploy" / "nftables" / "guard.nft.template"
LAN_ADDR = "198.51.100.200"  # the Pi's second address: a dummy interface in gw, standing for its Wi-Fi one
CANARY_TCP = (3389, 445, 22, 5353, 67)  # 8000/tcp is the gw namespace's own "other Pi service"
CANARY_UDP = (3389, 445, 22, 5353, 67)  # and 5000/udp; 67 answers only DHCP's source port
FINAL = "guard: TV may not reach other Pi services"
WEAK_HOST = "guard: the gateway address only (weak host)"
# what answers from the TV side, with or without inet tvgw: DNS, DHCP from port 68, nginx
ALLOWED = (
    ("dns-udp", vnet.GW_TV, 53, {}, f"answer:{vnet.GW_ANSWER}"),
    ("udp", vnet.GW_TV, 67, {"sport": "68"}, f"pass:{vnet.TV_IP}"),
    ("tcp", vnet.GW_TV, 80, {}, f"pass:{vnet.TV_IP}"),
    ("tcp", vnet.GW_TV, 443, {}, f"pass:{vnet.TV_IP}"),
)


def render(text: str) -> str:
    """The template as install.sh's render_guard fills it, for the virtual topology's TV side."""
    return (
        text.replace("__TV_IF__", "eth0")
        .replace("__TV_NET__", "10.10.10.0/24")
        .replace("__GW_IP__", vnet.GW_TV)
    )


def guard_counters(net) -> dict[str, int]:
    out = net.ns(net.gw, "nft", "-j", "list", "table", "inet", "tvgw_guard").stdout
    return {comment: n for comment, (n, _) in vnet.counters(out).items()}


def closed_probes() -> list[tuple[str, str, int, dict[str, str]]]:
    """Every canary, on the gateway address and on the LAN address; and DHCP's port from any other."""
    probes = [("tcp", addr, port, {}) for addr in (vnet.GW_TV, LAN_ADDR) for port in (*CANARY_TCP, 8000)]
    probes += [("udp", addr, port, {}) for addr in (vnet.GW_TV, LAN_ADDR) for port in (*CANARY_UDP, 5000)]
    return probes


@pytest.fixture(scope="module")
def guarded(net):
    """The direct scenario applied, the guard loaded on top, the canaries serving, the TV routing the
    LAN address by the gateway. Undone afterwards: the next module finds the gateway as it was."""
    s = {"UPLINK": "direct", "BLOCK_QUIC": "yes", "STRICT_PORTS": "no", "DNSGATE": "count"}
    conf = vnet.render_conf(s)
    out = net.apply(net.gw, conf)
    assert out.returncode == 0, out.stderr
    if net.reply_dev() != "eth0":  # vnet.HELPER_ROUTE says why
        net.ns(net.gw, "ip", *vnet.HELPER_ROUTE)
    rendered = net.save("guard/guard.nft", render(TEMPLATE.read_text(encoding="utf-8")))
    loaded = net.ns(net.gw, "nft", "-f", str(rendered), check=False)
    assert loaded.returncode == 0, loaded.stderr
    net.ns(net.gw, "ip", "link", "add", "lan0", "type", "dummy")
    net.ns(net.gw, "ip", "addr", "add", f"{LAN_ADDR}/32", "dev", "lan0")
    net.ns(net.gw, "ip", "link", "set", "lan0", "up")
    net.ns(net.tv, "ip", "route", "add", f"{LAN_ADDR}/32", "via", vnet.GW_TV)
    ports = ",".join(map(str, CANARY_TCP))
    net.serve(
        net.gw, ["--bind", f"0.0.0.0,{LAN_ADDR}", "--tcp", ports, "--udp", ",".join(map(str, CANARY_UDP))]
    )
    yield conf
    net.ns(net.tv, "ip", "route", "del", f"{LAN_ADDR}/32", check=False)
    net.ns(net.gw, "ip", "link", "del", "lan0", check=False)
    net.ns(net.gw, "nft", "delete", "table", "inet", "tvgw_guard", check=False)
    again = net.apply(net.gw, conf)  # inet tvgw back, whatever a test left
    assert again.returncode == 0, again.stderr


def test_the_rendered_guard_is_one_nft_transaction_that_reloads_in_place(guarded, net):
    """`add` plus `flush chain`: loading it again replaces the rules without a moment of no chain, and
    the three chains sit at filter + 10, after inet tvgw."""
    listing = net.ns(net.gw, "nft", "-s", "list", "table", "inet", "tvgw_guard").stdout
    again = net.ns(net.gw, "nft", "-f", str(net.artifacts / "guard" / "guard.nft"), check=False)
    assert again.returncode == 0, again.stderr
    assert net.ns(net.gw, "nft", "-s", "list", "table", "inet", "tvgw_guard").stdout == listing
    for chain in ("input", "forward", "output"):
        assert f"type filter hook {chain} priority filter + 10;" in listing
    verify = pytest.importorskip("tvgw.verify")
    guard = pytest.importorskip("tvgw.guard")
    assert guard.chains_hooked(listing) == ["input", "forward", "output"]
    check = verify.guard_present_check(
        lambda cmd: listing if cmd[:3] == ["nft", "-s", "list"] else "", lambda p: ""
    )
    assert check.ok, check.detail


def _probe_all(net, probes) -> dict[tuple, str]:
    return {
        (kind, addr, port): net.probe("tv", kind, addr, port, **opts) for kind, addr, port, opts in probes
    }


def test_with_tvgw_loaded_only_dns_dhcp_and_nginx_answer_and_the_guard_stays_still(guarded, net):
    before = guard_counters(net)
    for kind, addr, port, opts, want in ALLOWED:
        assert net.probe("tv", kind, addr, port, **opts) == want, (kind, addr, port)
    seen = _probe_all(net, closed_probes())
    assert {k: v for k, v in seen.items() if v != "drop"} == {}
    assert guard_counters(net) == before, "the guard dropped something inet tvgw had accepted"


def test_without_tvgw_the_guard_holds_the_same_line_and_counts_it(guarded, net):
    """The stop, a failed boot apply, the half-apply case: inet tvgw gone, forwarding still on."""
    net.ns(net.gw, "nft", "delete", "table", "inet", "tvgw")
    try:
        before = guard_counters(net)
        for kind, addr, port, opts, want in ALLOWED:
            assert net.probe("tv", kind, addr, port, **opts) == want, (kind, addr, port)
        seen = _probe_all(net, closed_probes())
        assert {k: v for k, v in seen.items() if v != "drop"} == {}
        after = guard_counters(net)
        assert after[FINAL] > before[FINAL], (
            "the gateway address's canaries must end at the guard's last rule"
        )
        assert after[WEAK_HOST] > before[WEAK_HOST], "the LAN address must end at the weak-host rule"
    finally:
        out = net.apply(net.gw, guarded)
        assert out.returncode == 0, out.stderr
        if net.reply_dev() != "eth0":
            net.ns(net.gw, "ip", *vnet.HELPER_ROUTE)


def test_restoring_tvgw_leaves_the_guard_counter_unchanged(guarded, net):
    before = guard_counters(net)
    seen = _probe_all(net, closed_probes())
    assert set(seen.values()) == {"drop"}
    assert guard_counters(net)[FINAL] == before[FINAL]


def test_a_spoofed_source_and_ipv6_end_at_the_guard_without_tvgw(guarded, net):
    net.ns(net.gw, "nft", "delete", "table", "inet", "tvgw")
    try:
        before = guard_counters(net)
        assert net.probe("tv-foreign", "udp", vnet.GW_TV, 53) == "drop"
        assert guard_counters(net)["guard: spoofed source"] > before["guard: spoofed source"]
    finally:
        out = net.apply(net.gw, guarded)
        assert out.returncode == 0, out.stderr
        if net.reply_dev() != "eth0":
            net.ns(net.gw, "ip", *vnet.HELPER_ROUTE)


def test_verify_reads_the_guard_quiet_while_tvgw_is_loaded(guarded, net):
    """guard_quiet against the listing tvgw-apply wrote after its last load, which now names the guard."""
    verify = pytest.importorskip("tvgw.verify")
    run_dir = Path(net.sandbox) / "run-guard-quiet"
    run_dir.mkdir(exist_ok=True)
    out = net.apply(net.gw, guarded, run_dir=run_dir)
    assert out.returncode == 0, out.stderr
    if net.reply_dev() != "eth0":
        net.ns(net.gw, "ip", *vnet.HELPER_ROUTE)
    after_apply = (run_dir / "counters.after-apply").read_text(encoding="utf-8")
    tables = {
        o["table"]["name"]
        for line in after_apply.splitlines()
        for o in json.loads(line)["nftables"]
        if "table" in o
    }
    assert "tvgw_guard" in tables, "tvgw-apply's listing after its load must name the guard"
    _probe_all(net, closed_probes())
    listing = net.ns(net.gw, "nft", "-j", "list", "table", "inet", "tvgw_guard").stdout
    check = verify.guard_quiet_check(True, listing, after_apply)
    assert check.ok and not check.warn, check.detail


@pytest.mark.skipif(
    shutil.which("systemd-run") is None or not os.path.isdir("/run/systemd/system"),
    reason="needs a running systemd for a transient scope",
)
def test_a_canary_under_ip_address_deny_answers_the_lan_and_never_the_tv(guarded, net):
    """The co-tenants' second wall: with every nftables table gone, a service in a scope with
    IPAddressDeny=TV_NET still never answers the TV, and still answers the LAN side."""
    argv = ["systemd-run", "--scope", "--quiet", "-p", "IPAddressDeny=10.10.10.0/24", "--"]
    argv += net.agent_argv(net.gw, "serve", "--bind", LAN_ADDR, "--tcp", "2222")
    p = subprocess.Popen(argv, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, encoding="utf-8")
    if p.stdout.readline().strip() != "ready":  # the machine, not the filter: no scope to be had
        p.kill()
        pytest.skip(f"systemd-run could not start a scope: {p.communicate(timeout=5)[1].strip()}")
    try:
        for table in (("inet", "tvgw"), ("inet", "tvgw_guard")):
            net.ns(net.gw, "nft", "delete", "table", *table)
        # the internet side stands for the home LAN: it reaches the dummy address by the uplink
        net.ns(net.wan, "ip", "route", "add", f"{LAN_ADDR}/32", "via", vnet.GW_WLAN, check=False)
        time.sleep(0.2)
        assert net.probe("tv", "tcp", LAN_ADDR, 2222) == "drop"
        assert net.probe("wan", "tcp", LAN_ADDR, 2222) == f"pass:{vnet.WAN_GW}"
    finally:
        p.kill()
        p.communicate(timeout=5)
        net.ns(net.wan, "ip", "route", "del", f"{LAN_ADDR}/32", check=False)
        net.ns(net.gw, "nft", "-f", str(net.artifacts / "guard" / "guard.nft"))
        out = net.apply(net.gw, guarded)
        assert out.returncode == 0, out.stderr
        if net.reply_dev() != "eth0":
            net.ns(net.gw, "ip", *vnet.HELPER_ROUTE)
