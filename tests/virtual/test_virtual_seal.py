"""(reliability) VPN_DNS_SEAL on a kernel: the gateway's own plain lookups held off the uplink while the
tunnel is down, and nothing of the TV's ever held (design decision 73).

Over the `direct` scenario, the gateway namespace's own lookups to the internet's public resolver are sent
by the uplink with a host route, as the gateway's are while its tunnel is down (its main default points
at the tunnel, as the VPN client's routes do). Without the table they are answered, and the `pi leak: DNS
left by the uplink` counter of decision 44 counts them. Held, they are refused at once, with nothing
counted as a leak, while the TV's own lookups and its web traffic out of the uplink pass, and the
gateway's lookups by the tunnel are answered. A release, a sync with the tunnel up, and the kernel's own
timeout each end the hold; with the setting off the table goes.

Run as root on a Linux machine or VM (tests/virtual/README.md):

    sudo env PYTHONPATH=src python3 -m pytest -m virtual tests/virtual -q -p no:cacheprovider
"""

from __future__ import annotations

import json
import sys
import time

import pytest
import vnet

pytestmark = pytest.mark.virtual

SRC = vnet.ROOT / "src"
CONF = vnet.render_conf({"UPLINK": "direct", "BLOCK_QUIC": "yes", "STRICT_PORTS": "no", "DNSGATE": "count"})
LEAK = "pi leak: DNS left by the uplink"
# the gateway's own lookup, as the C library's resolver makes one: a connected UDP socket, so a refusal
# comes back at once as an error, where an unconnected one would wait out its timeout. Prints the answer's
# addresses, "refused", or "silence" when nothing came back in 2 s
ASK = """
import json, socket, sys
sys.path.insert(0, sys.argv[1])
from tvgw import dnsmsg, dnsq
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.settimeout(2.0)
try:
    s.connect((sys.argv[2], 53))
    s.send(dnsq.question("example.com"))
    data = s.recv(4096)
    print(json.dumps([a.value for a in dnsmsg.decode_answers(data) if a.rtype == "A"]))
except ConnectionRefusedError:
    print(json.dumps("refused"))
except TimeoutError:
    print(json.dumps("silence"))
"""


def settings(on: bool = True):
    from tvgw.config import Settings

    return Settings(vpn_dns_seal="on" if on else "off", wan_if=vnet.WAN_IF, vpn_if=vnet.VPN_IF)


def seal(net, action: str, on: bool = True, seconds: int | None = None, tunnel_up: bool = False) -> None:
    """`tvgw seal ACTION`'s commands, run in the gateway namespace."""
    from tvgw import seal as mod

    plan = mod.plan(settings(on), action, lambda dev: tunnel_up, [], seconds or mod.HOLD_SECONDS)
    for argv, stdin, required in plan:
        net.ns(net.gw, *argv, input=stdin, check=required)


def ask(net, server: str):
    return json.loads(net.ns(net.gw, sys.executable, "-c", ASK, str(SRC), server, timeout=30).stdout)


def counted(net, comment: str) -> int:
    return net.counters().get(comment, (0, ""))[0]


@pytest.fixture(scope="module")
def uplink(net):
    """The direct scenario, the gateway's lookups to the public resolver sent by the uplink, no seal."""
    out = net.apply(net.gw, CONF)
    assert out.returncode == 0, out.stderr
    net.ns(net.gw, "nft", "delete", "table", "inet", "tvgw_seal", check=False)
    net.ns(net.gw, "ip", "route", "replace", f"{vnet.RESOLVER}/32", "via", vnet.WAN_GW, "dev", vnet.WAN_IF)
    yield net
    net.ns(net.gw, "nft", "delete", "table", "inet", "tvgw_seal", check=False)
    net.ns(net.gw, "ip", "route", "del", f"{vnet.RESOLVER}/32", check=False)


def test_without_the_table_the_gateways_lookups_leave_by_the_uplink_and_are_counted(uplink):
    net = uplink
    before = counted(net, LEAK)
    assert ask(net, vnet.RESOLVER) == [vnet.WAN_ANSWER]
    assert counted(net, LEAK) == before + 1


def test_held_they_are_refused_at_once_and_nothing_of_the_tvs_is(uplink):
    net = uplink
    seal(net, "hold")
    try:
        leak = counted(net, LEAK)
        assert ask(net, vnet.RESOLVER) == "refused"  # at once, so the resolver moves on, not waited out
        assert counted(net, LEAK) == leak  # it never left
        assert counted(net, "seal: the gateway's own plain lookups while the tunnel is down") >= 1
        # the TV's lookups, its traffic out of the uplink, and the gateway's own lookups by the tunnel
        assert net.probe("tv", "dns-udp", vnet.GW_TV, 53) == "answer:gateway"
        assert net.probe("tv", "dns-udp", vnet.RESOLVER, 53) == "answer:gateway"
        assert net.probe("tv", "tcp", vnet.WEB, 443) == f"pass:{vnet.GW_WLAN}"
        assert ask(net, vnet.WAN_TUN) == [vnet.WAN_ANSWER]
    finally:
        seal(net, "release")
    assert ask(net, vnet.RESOLVER) == [vnet.WAN_ANSWER]  # released


def test_a_hold_ends_by_the_kernels_clock(uplink):
    net = uplink
    seal(net, "hold", seconds=2)
    assert ask(net, vnet.RESOLVER) == "refused"
    time.sleep(3)
    assert ask(net, vnet.RESOLVER) == [vnet.WAN_ANSWER]


def test_a_sync_with_the_tunnel_up_ends_a_hold_and_one_without_keeps_it(uplink):
    net = uplink
    seal(net, "hold")
    seal(net, "sync", tunnel_up=False)
    assert ask(net, vnet.RESOLVER) == "refused"  # loading the table again never ends a hold
    seal(net, "sync", tunnel_up=True)
    assert ask(net, vnet.RESOLVER) == [vnet.WAN_ANSWER]


def test_with_the_setting_off_the_table_goes(uplink):
    net = uplink
    seal(net, "hold")
    seal(net, "hold", on=False)
    assert net.ns(net.gw, "nft", "list", "table", "inet", "tvgw_seal", check=False).returncode != 0
    assert ask(net, vnet.RESOLVER) == [vnet.WAN_ANSWER]
