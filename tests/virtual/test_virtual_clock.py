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


@pytest.fixture(scope="module")
def clock(net):
    """The script copy with resolved supported, and the scenario applied again at the end."""
    path = net.sandbox / "tvgw-apply-clock"
    path.write_text(vnet.clock_script(vnet.APPLY.read_text(encoding="utf-8")), encoding="utf-8")
    yield path
    flush_count(net)
    out = net.apply(net.gw, conf())
    assert out.returncode == 0, out.stderr


def test_none_refuses_the_tvs_ntp_and_counts_it_and_nothing_else_changes(net, clock):
    flush_count(net)
    out = net.apply(net.gw, conf(CLOCK_PORT="none"))
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
    assert net.apply(net.gw, conf(CLOCK_PORT="any")).returncode == 0
    assert ntp(net, vnet.WEB) == PASS  # the count now holds it
    out = net.apply(net.gw, conf(CLOCK_PORT="none"))
    assert out.returncode == 0, out.stderr
    assert "the clock port stays open" in out.stderr
    assert ntp(net, vnet.WEB) == PASS
    assert CLOSED not in net.ns(net.gw, "nft", "list", "table", "inet", "tvgw").stdout


def test_resolved_admits_what_the_gates_sets_hold_and_keeps_it_while_it_is_asked(net, clock):
    flush_count(net)
    out = net.apply(net.gw, conf(CLOCK_PORT="resolved", DNSGATE_FILL="inpath"), script=clock)
    assert out.returncode == 0, out.stderr
    gate = net.ns(net.gw, "nft", "list", "table", "inet", "tvgw_gate").stdout
    assert RESOLVED in gate and "set ntp_ok4" in gate
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
    out = net.apply(net.gw, conf(CLOCK_PORT="resolved", DNSGATE_FILL="inpath"))
    assert out.returncode == 0, out.stderr
    assert "not supported on a live gateway yet" in out.stderr
    gate = net.ns(net.gw, "nft", "list", "table", "inet", "tvgw_gate").stdout
    assert RESOLVED not in gate and "ntp_ok4" not in gate  # and the copy's chain and set went with it
    assert ntp(net, vnet.WEB) == PASS


def test_any_after_a_narrowing_opens_the_port_again(net, clock):
    flush_count(net)
    assert net.apply(net.gw, conf(CLOCK_PORT="none")).returncode == 0
    assert ntp(net, vnet.WEB) == "reject"
    assert net.apply(net.gw, conf()).returncode == 0
    assert ntp(net, vnet.WEB) == PASS
