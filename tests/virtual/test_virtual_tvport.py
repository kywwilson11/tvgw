"""(tv port) A boot with the TV's port missing: the cable out of the gateway at boot, or the USB adapter the
TV's port is on absent. Found by the container tier and still true on 2026-11-08: `tvgw-apply` wrote the
port's IPv6 switch before it loaded any table, the write failed for a port that does not exist, and the
script stopped there, so tvgw.service failed until the port came back, and the Pi's own walls, which live
in those tables (the input chain's drop of the VPN side, the count of its lookups that leave by the
uplink), stood nowhere meanwhile.

Here the gateway is put back to its boot state (no table, no rule 60, forwarding off), the TV's port is
taken away (no address, down, under another name: nothing of it under its own name in /proc), and the real
script runs. The tables must load and nothing be switched on; then the port comes back as a port that was
never set up does, the TV stays dark until its own apply (the dispatcher's, on the port's up), and after
that apply the TV reaches the internet with every switch of the port set. The topology is put back as vnet
built it whatever happens."""

from __future__ import annotations

import pytest
import vnet

pytestmark = pytest.mark.virtual

AWAY = "tvgone0"  # the port's name while it is gone: none the script or the topology uses
SETTINGS = {"UPLINK": "direct", "BLOCK_QUIC": "yes", "STRICT_PORTS": "no", "DNSGATE": "count"}
PASS = vnet.Row("tv", "tcp", vnet.WEB, 443, "pass:wlan0", None).expected()


def conf() -> str:
    return vnet.render_conf(SETTINGS)


def sysctl(net, key: str) -> str:
    return net.ns(net.gw, "sysctl", "-n", key, check=False).stdout.strip()


def port_back(net) -> None:
    """The port under its own name again, with the gateway's address, up: as a port comes back that was
    never set up, forwarding off and IPv6 on (what a new interface takes after a boot with forwarding off)."""
    gw = net.gw
    if net.ns(gw, "ip", "link", "show", AWAY, check=False).returncode == 0:
        net.ns(gw, "ip", "link", "set", AWAY, "name", vnet.TV_IF)
    net.ns(gw, "ip", "addr", "add", f"{vnet.GW_TV}/24", "dev", vnet.TV_IF, check=False)
    net.ns(gw, "sysctl", "-qw", f"net.ipv4.conf.{vnet.TV_IF}.forwarding=0")
    net.ns(gw, "sysctl", "-qw", f"net.ipv6.conf.{vnet.TV_IF}.disable_ipv6=0")
    net.ns(gw, "ip", "link", "set", vnet.TV_IF, "up")


@pytest.fixture
def boot_without_the_port(net):
    gw = net.gw
    for table in (("inet", "tvgw"), ("netdev", "tvgw_l2")):
        net.ns(gw, "nft", "delete", "table", *table, check=False)
    net.ns(gw, "ip", "rule", "del", "priority", "60", check=False)
    net.ns(gw, "sysctl", "-qw", "net.ipv4.ip_forward=0")
    net.ns(gw, "ip", "addr", "flush", "dev", vnet.TV_IF)
    net.ns(gw, "ip", "link", "set", vnet.TV_IF, "down")
    net.ns(gw, "ip", "link", "set", vnet.TV_IF, "name", AWAY)
    try:
        yield
    finally:
        port_back(net)
        out = net.apply(gw, conf())  # the module's scenario, every switch set again
        assert out.returncode == 0, out.stderr


def test_a_boot_without_the_tv_port_loads_the_firewall_and_the_ports_own_apply_finishes_it(
    net, boot_without_the_port
):
    gw = net.gw
    out = net.apply(gw, conf())
    net.save("tvport/apply-without-the-port.log", out.stdout + out.stderr)
    assert out.returncode == 0, out.stderr
    assert f"the TV's port {vnet.TV_IF} is not there: the firewall is loaded" in out.stderr
    listing = net.ns(gw, "nft", "list", "table", "inet", "tvgw").stdout
    assert "nothing unsolicited from the VPN side" in listing  # the Pi's own walls stand
    assert "pi leak: DNS left by the uplink" in listing
    assert sysctl(net, "net.ipv4.ip_forward") == "0"  # nothing switched on for a port that is not there
    # the port comes back: dark until its own apply, the fail-closed state
    port_back(net)
    assert net.probe("tv", "tcp", vnet.WEB, 443) != PASS
    out = net.apply(gw, conf())  # what the dispatcher runs when the port comes up
    net.save("tvport/apply-with-the-port.log", out.stdout + out.stderr)
    assert out.returncode == 0 and "is not there" not in out.stderr, out.stderr
    assert sysctl(net, "net.ipv4.ip_forward") == "1"
    assert sysctl(net, f"net.ipv4.conf.{vnet.TV_IF}.forwarding") == "1"
    assert sysctl(net, f"net.ipv6.conf.{vnet.TV_IF}.disable_ipv6") == "1"
    assert "no IPv6 from the TV" in net.ns(gw, "nft", "list", "table", "netdev", "tvgw_l2").stdout
    assert net.probe("tv", "tcp", vnet.WEB, 443) == PASS
