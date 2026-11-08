"""(ports) The clock port narrowed, on a kernel (design decision 71).

Over the `direct` scenario this module applies CLOCK_PORT=none and probes UDP 123 from the TV: it is
refused, the closing rule counts it and `walls.read_live` (what `tvgw refused` reads) counts it from the
kernel's own listing, while the web and every other row still pass. With the NTP count holding a server
the TV asked, the same setting keeps the port open and says so. `resolved` is held back on a live
gateway, so it runs with a copy of the script whose CLOCK_RESOLVED_SUPPORTED line says yes: an address
the gate's sets hold passes, any other is refused, and an address admitted once stays admitted after the
gate forgets it. Leaving `resolved` takes its chain and its set away. The module applies the scenario
again when it ends, so the next module finds the gateway as the apply leaves it.

Run as root on a Linux machine or VM (tests/virtual/README.md):

    sudo env PYTHONPATH=src python3 -m pytest -m virtual tests/virtual -q -p no:cacheprovider
"""

from __future__ import annotations

import sys
from dataclasses import dataclass
from pathlib import Path

import pytest
import vnet

pytestmark = pytest.mark.virtual

DIRECT = {"UPLINK": "direct", "BLOCK_QUIC": "yes", "STRICT_PORTS": "no", "DNSGATE": "count"}
PASS = f"pass:{vnet.GW_WLAN}"
CLOSED = "clock port: closed, NTP to no server"
RESOLVED = "clock port: only to an address a lookup returned"


def conf(**more: str) -> str:
    return vnet.render_conf({**DIRECT, **more})


def ntp(net, target: str) -> str:
    return net.probe("tv", "udp", target, 123)


def flush_count(net) -> None:
    net.ns(net.gw, "nft", "flush", "set", "inet", "tvgw_ntp", "ntp4", check=False)


@dataclass
class Scripts:
    shipped: Path  # the script as it ships, finding `tvgw` at a shim
    supported: Path  # the same, with ntp=resolved supported


@pytest.fixture(scope="module")
def clock(net):
    """Copies of the script whose `tvgw` is a shim running this checkout's, as the gateway's runs: the apply
    asks it for the profile's rule and for the record of the TV's NTP (none here: the sandbox's state
    directory holds no store, so the record says nothing and the live count decides). One copy as it
    ships, one with resolved supported. The scenario is applied again at the end."""
    shim = net.sandbox / "tvgw-clock-shim"
    shim.write_text(
        f'#!/bin/bash\nexec "{sys.executable}" -m tvgw --conf /etc/tvgw/tvgw.conf "$@"\n', encoding="utf-8"
    )
    shim.chmod(0o755)
    text = vnet.APPLY.read_text(encoding="utf-8")
    assert text.count("\nTVGW=/usr/local/bin/tvgw\n") == 1
    text = text.replace("\nTVGW=/usr/local/bin/tvgw\n", f"\nTVGW={shim}\n")
    shipped, supported = net.sandbox / "tvgw-apply-clock", net.sandbox / "tvgw-apply-clock-resolved"
    shipped.write_text(text, encoding="utf-8")
    supported.write_text(vnet.clock_script(text), encoding="utf-8")
    yield Scripts(shipped, supported)
    flush_count(net)
    out = net.apply(net.gw, conf())
    assert out.returncode == 0, out.stderr


def test_none_refuses_the_tvs_ntp_and_counts_it_and_nothing_else_changes(net, clock):
    flush_count(net)
    out = net.apply(net.gw, conf(CLOCK_PORT="none"), script=clock.shipped)
    assert out.returncode == 0, out.stderr
    assert "the clock port stays open" not in out.stderr
    before = net.counters()
    assert ntp(net, vnet.WEB) == "reject"
    assert net.probe("tv", "tcp", vnet.WEB, 443) == PASS
    assert net.probe("tv", "tcp", vnet.WEB, 80) == PASS
    ticked = vnet.ticked(before, net.counters())
    assert ticked.get(CLOSED, 0) >= 1, ticked
    # what `tvgw refused` reads: the kernel's own listing, through the same parser verify uses
    walls = pytest.importorskip("tvgw.walls")

    def run(cmd: list[str]) -> tuple[int, str]:
        done = net.ns(net.gw, *cmd, check=False)
        return done.returncode, done.stdout

    reading = walls.read_live(0, 1, run=run, read=lambda p: "", mtime=lambda p: None, journal=lambda s: [])
    assert reading.counters_read and reading.live.get(CLOSED, 0) >= 1
    # nothing reached the NTP count: the closed port is refused before it
    listed = net.ns(net.gw, "nft", "list", "set", "inet", "tvgw_ntp", "ntp4").stdout
    assert vnet.WEB not in listed


def test_none_stays_open_while_the_count_holds_a_server_the_tv_asked(net, clock):
    flush_count(net)
    assert net.apply(net.gw, conf(CLOCK_PORT="any"), script=clock.shipped).returncode == 0
    assert ntp(net, vnet.WEB) == PASS  # the count now holds it
    out = net.apply(net.gw, conf(CLOCK_PORT="none"), script=clock.shipped)
    assert out.returncode == 0, out.stderr
    assert "the clock port stays open" in out.stderr
    assert ntp(net, vnet.WEB) == PASS
    assert CLOSED not in net.ns(net.gw, "nft", "list", "table", "inet", "tvgw").stdout


def test_resolved_admits_what_the_gates_sets_hold_and_keeps_it_while_it_is_asked(net, clock):
    flush_count(net)
    out = net.apply(net.gw, conf(CLOCK_PORT="resolved", DNSGATE_FILL="inpath"), script=clock.supported)
    assert out.returncode == 0, out.stderr
    gate = net.ns(net.gw, "nft", "list", "table", "inet", "tvgw_gate").stdout
    assert RESOLVED in gate and "set ntp_ok4" in gate
    # the gate's sets outlive an apply: neither may hold the two servers from an earlier module
    for name in ("resolved4", "resolved4_inpath", "ntp_ok4"):
        for addr in (vnet.WEB, vnet.RESOLVER):
            net.ns(
                net.gw, "nft", "delete", "element", "inet", "tvgw_gate", name, f"{{ {addr} }}", check=False
            )
    # nothing told the gate about the web server: refused, and counted
    before = net.counters()
    assert ntp(net, vnet.WEB) == "reject"
    assert vnet.ticked(before, net.counters()).get(RESOLVED, 0) >= 1
    # the in-path set holds it (as the filler adds an answer's addresses): admitted, and kept in ntp_ok4
    net.ns(
        net.gw,
        "nft",
        "add",
        "element",
        "inet",
        "tvgw_gate",
        "resolved4_inpath",
        f"{{ {vnet.WEB} timeout 1h }}",
    )
    assert ntp(net, vnet.WEB) == PASS
    net.ns(net.gw, "nft", "delete", "element", "inet", "tvgw_gate", "resolved4_inpath", f"{{ {vnet.WEB} }}")
    assert ntp(net, vnet.WEB) == PASS  # the gate forgot it; the clock port did not
    assert vnet.WEB in net.ns(net.gw, "nft", "list", "set", "inet", "tvgw_gate", "ntp_ok4").stdout
    # the passive feeder's set admits too, so a filler that died costs no clock
    net.ns(
        net.gw, "nft", "add", "element", "inet", "tvgw_gate", "resolved4", f"{{ {vnet.RESOLVER} timeout 1h }}"
    )
    assert ntp(net, vnet.RESOLVER) == PASS
    assert net.probe("tv", "tcp", vnet.WEB, 443) == PASS


def test_the_shipped_script_holds_resolved_back(net, clock):
    out = net.apply(net.gw, conf(CLOCK_PORT="resolved", DNSGATE_FILL="inpath"), script=clock.shipped)
    assert out.returncode == 0, out.stderr
    assert "not supported on a live gateway yet" in out.stderr
    gate = net.ns(net.gw, "nft", "list", "table", "inet", "tvgw_gate").stdout
    assert RESOLVED not in gate and "ntp_ok4" not in gate  # and the copy's chain and set went with it
    assert ntp(net, vnet.WEB) == PASS


def test_without_a_tvgw_to_read_the_record_the_port_stays_open(net, clock):
    """The script as it ships, with no /usr/local/bin/tvgw on this machine: nothing can say the TV does
    without NTP, so none is held back and said."""
    flush_count(net)
    out = net.apply(net.gw, conf(CLOCK_PORT="none"))
    assert out.returncode == 0, out.stderr
    assert "could not be read" in out.stderr and ntp(net, vnet.WEB) == PASS


def test_any_after_a_narrowing_opens_the_port_again(net, clock):
    flush_count(net)
    assert net.apply(net.gw, conf(CLOCK_PORT="none"), script=clock.shipped).returncode == 0
    assert ntp(net, vnet.WEB) == "reject"
    assert net.apply(net.gw, conf()).returncode == 0
    assert ntp(net, vnet.WEB) == PASS
