"""(uplink) A router swap on the virtual gateway: the home router comes back on another address, as a
replaced or reset router does, and the dispatcher's apply runs as it does on `dhcp4-change`.

With WAN_GW_MODE=auto the apply takes the router from WAN_IF's own default route in the main table, so
table 100 follows it and the TV keeps reaching the internet. With the literal WAN_GW (the mode absent,
as on the reference gateway) table 100 keeps the old router, and the TV's traffic goes nowhere: what
verify's wan_gateway check warns about. The topology is put back as it was whatever happens, so the
modules after this one see the router where vnet built it."""

from __future__ import annotations

import pytest
import vnet

from tvgw import config

pytestmark = pytest.mark.virtual

NEW_ROUTER = "198.51.100.254"  # the router's new address, in the uplink's own documentation subnet
# below the tunnel's default in preference, as NetworkManager's uplink default sits under PIA's
METRIC = "600"
# out by the uplink, as the matrix says (`pass:wlan0` is the uplink's address whatever it is called)
PASS = vnet.Row("tv", "tcp", vnet.WEB, 443, "pass:wlan0", None).expected()


def conf(mode: str | None) -> str:
    settings = {"UPLINK": "direct", "BLOCK_QUIC": "yes", "STRICT_PORTS": "no", "DNSGATE": "count"}
    return vnet.render_conf(settings) + (f"WAN_GW_MODE={mode}\n" if mode else "")


def table_100(net) -> str:
    return net.ns(net.gw, "ip", "route", "show", "table", "100", "default").stdout.strip()


@pytest.fixture
def swapped(net):
    """The uplink's main-table default via the router (as DHCP installs it), then the router on its new
    address: the old one gone from the internet side, the main-table default via the new one."""
    gw, wan = net.gw, net.wan
    net.ns(gw, "ip", "route", "add", "default", "via", vnet.WAN_GW, "dev", vnet.WAN_IF, "metric", METRIC)
    try:
        yield
    finally:
        # the old address back first: up0 then holds it as its primary, as vnet built it
        net.ns(wan, "ip", "addr", "del", f"{NEW_ROUTER}/24", "dev", "up0", check=False)
        net.ns(wan, "ip", "addr", "add", f"{vnet.WAN_GW}/24", "dev", "up0", check=False)
        for via in (vnet.WAN_GW, NEW_ROUTER):
            net.ns(
                gw,
                "ip",
                "route",
                "del",
                "default",
                "via",
                via,
                "dev",
                vnet.WAN_IF,
                "metric",
                METRIC,
                check=False,
            )
        net.ns(gw, "ip", "neigh", "flush", "dev", vnet.WAN_IF, check=False)
        out = net.apply(gw, conf(None))  # the module's own scenario: the literal router, as built
        assert out.returncode == 0, out.stderr
        assert table_100(net).startswith(f"default via {vnet.WAN_GW} dev {vnet.WAN_IF}")


def swap(net) -> None:
    """The router on its new address. The old one goes first: deleting a primary address takes the
    secondaries of its subnet with it, and the gateway's cached neighbour entry goes too, or the frames
    would still reach the router's old hardware address."""
    net.ns(net.wan, "ip", "addr", "del", f"{vnet.WAN_GW}/24", "dev", "up0")
    net.ns(net.wan, "ip", "addr", "add", f"{NEW_ROUTER}/24", "dev", "up0")
    net.ns(
        net.gw, "ip", "route", "replace", "default", "via", NEW_ROUTER, "dev", vnet.WAN_IF, "metric", METRIC
    )
    net.ns(net.gw, "ip", "neigh", "flush", "dev", vnet.WAN_IF, check=False)


def test_with_auto_the_tv_follows_a_router_that_moved(net, swapped):
    run_dir = net.sandbox / "run-uplink-auto"
    run_dir.mkdir(exist_ok=True)
    out = net.apply(net.gw, conf("auto"), run_dir=run_dir)
    assert out.returncode == 0, out.stderr
    assert table_100(net).startswith(f"default via {vnet.WAN_GW} dev {vnet.WAN_IF}")
    assert net.probe("tv", "tcp", vnet.WEB, 443) == PASS
    swap(net)
    out = net.apply(net.gw, conf("auto"), run_dir=run_dir)  # what the dispatcher runs on dhcp4-change
    assert out.returncode == 0, out.stderr
    assert table_100(net).startswith(f"default via {NEW_ROUTER} dev {vnet.WAN_IF}")
    assert (run_dir / "wan_gw.last").read_text(encoding="utf-8").strip() == NEW_ROUTER
    used = config.parse_conf((run_dir / "settings.applied").read_text(encoding="utf-8"))
    assert (used["WAN_GW"], used["WAN_GW_MODE"], used["WAN_GW_USED"]) == (vnet.WAN_GW, "auto", NEW_ROUTER)
    assert net.probe("tv", "tcp", vnet.WEB, 443) == PASS


def test_with_the_literal_the_tv_loses_a_router_that_moved(net, swapped):
    swap(net)
    out = net.apply(net.gw, conf(None))
    assert out.returncode == 0, out.stderr
    assert table_100(net).startswith(
        f"default via {vnet.WAN_GW} dev {vnet.WAN_IF}"
    )  # the router that is gone
    assert net.probe("tv", "tcp", vnet.WEB, 443) != PASS
