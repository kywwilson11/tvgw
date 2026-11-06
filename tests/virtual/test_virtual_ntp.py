"""(ntp) The count of the clock servers the TV sends NTP to, on a kernel (design decision 17, its note of
2026-11-05).

tvgw-apply keeps the table `inet tvgw_ntp`: one forward rule after every chain that can refuse, which
counts the TV's UDP 123 and updates the dynamic set `ntp4` with a counter per address. Over the
`direct` scenario this module probes UDP 123 from the TV to two of the internet side's addresses and
one the manual blocks refuse, and reads the kernel's own listing with `verify.ntp_counters`, the parser
`tvgw verify --record` uses: each address the TV reached is an element with exactly its requests, the
refused one is none, the rule's total is their sum, and no probe's verdict changed. A re-apply keeps
every element and its count and zeroes only the rule's total. With the table gone, and with a set too
small for the addresses the TV uses, NTP still leaves: the count can lose evidence, never the TV's
clock. The module deletes what it built and applies the scenario again, so the next module finds the
gateway as the apply leaves it.

Run as root on a Linux machine or VM (tests/virtual/README.md):

    sudo env PYTHONPATH=src python3 -m pytest -m virtual tests/virtual -q -p no:cacheprovider
"""

from __future__ import annotations

import json

import pytest
import vnet

pytestmark = pytest.mark.virtual

SCRIPT = vnet.APPLY.read_text(encoding="utf-8")
PASS = f"pass:{vnet.GW_WLAN}"  # the far end saw the request come from the uplink, masqueraded
CONF = vnet.render_conf({"UPLINK": "direct", "BLOCK_QUIC": "yes", "STRICT_PORTS": "no", "DNSGATE": "count"})
RULE = "NTP from the TV, by server"


def ntp_definition(size: int) -> str:
    """The table, the set, the chain and the rule exactly as tvgw-apply writes them, with the set's size
    given here and the TV side the topology's."""
    lines = [
        line.strip()
        for line in SCRIPT.splitlines()
        if line.strip().startswith(
            ("add table inet tvgw_ntp", "add set inet tvgw_ntp ", "add chain inet tvgw_ntp ")
        )
        or line.strip().startswith(("flush chain inet tvgw_ntp ", "add rule inet tvgw_ntp "))
    ]
    assert len(lines) == 5, lines
    text = "\n".join(lines) + "\n"
    return (
        text.replace("$NTP_SIZE", str(size))
        .replace('"$TV_IF"', f'"{vnet.TV_IF}"')
        .replace("$TV_NET", "10.10.10.0/24")
    )


def listing(net) -> str:
    return net.ns(net.gw, "nft", "-j", "list", "table", "inet", "tvgw_ntp", check=False).stdout


def servers(net) -> dict[str, int]:
    verify = pytest.importorskip("tvgw.verify")
    return {rule.split(": ", 1)[1]: packets for rule, packets, _ in verify.ntp_counters(listing(net))}


def total(net) -> int | None:
    verify = pytest.importorskip("tvgw.verify")
    return dict((rule, p) for rule, p, _ in verify.counters_from_table(listing(net))).get(RULE)


def ntp(net, target: str) -> str:
    return net.probe("tv", "udp", target, 123)


@pytest.fixture(scope="module")
def fresh(net):
    """The direct scenario applied over a gateway with no NTP table, so the counts are this module's
    alone; afterwards the table goes again and the scenario is applied once more."""
    net.ns(net.gw, "nft", "delete", "table", "inet", "tvgw_ntp", check=False)
    out = net.apply(net.gw, CONF)
    assert out.returncode == 0, out.stderr
    assert "NTP count table not loaded" not in out.stderr
    yield net
    net.ns(net.gw, "nft", "delete", "table", "inet", "tvgw_ntp", check=False)
    again = net.apply(net.gw, CONF)
    assert again.returncode == 0, again.stderr


def test_each_address_the_tv_reaches_is_counted_and_nothing_is_refused(fresh):
    net = fresh
    assert servers(net) == {} and total(net) == 0
    assert [ntp(net, vnet.WEB) for _ in range(2)] == [PASS, PASS]
    assert ntp(net, vnet.RESOLVER) == PASS
    # a manual block refuses it before the count, which counts only what the filter let out
    assert ntp(net, vnet.BLOCKED) == "reject"
    assert servers(net) == {vnet.WEB: 2, vnet.RESOLVER: 1}
    assert total(net) == 3
    # the set is bounded, and each element leaves a day after its last request
    (ntp4,) = [
        o["set"] for o in json.loads(listing(net))["nftables"] if (o.get("set") or {}).get("name") == "ntp4"
    ]
    assert ntp4["size"] == 1024 and ntp4["timeout"] == 86400
    # a kernel may list an element's timeout only where it differs from the set's; its expiry it lists
    assert {e["elem"].get("timeout", 86400) for e in ntp4["elem"]} == {86400}
    assert all(0 < e["elem"]["expires"] <= 86400 for e in ntp4["elem"])


def test_a_reapply_keeps_every_address_and_its_count(fresh):
    net = fresh
    before = servers(net)
    assert before  # the module's first test sent its requests
    out = net.apply(net.gw, CONF)
    assert out.returncode == 0, out.stderr
    assert servers(net) == before
    assert total(net) == 0  # the chain was flushed and its rule written again; the set was kept
    assert ntp(net, vnet.WEB) == PASS
    assert servers(net) == {**before, vnet.WEB: before[vnet.WEB] + 1}


def test_without_the_table_the_tvs_ntp_still_leaves(fresh):
    net = fresh
    net.ns(net.gw, "nft", "delete", "table", "inet", "tvgw_ntp")
    assert listing(net).strip() == ""
    assert ntp(net, vnet.WEB) == PASS
    out = net.apply(net.gw, CONF)  # the next apply brings it back, empty
    assert out.returncode == 0, out.stderr
    assert servers(net) == {}


def test_a_full_set_counts_what_it_holds_and_lets_every_request_through(fresh):
    """The set is bounded; when it is full, `update` adds nothing and the rule ends there, and the
    packet goes on by the chain's accept policy, as when the table is missing."""
    net = fresh
    net.ns(net.gw, "nft", "delete", "table", "inet", "tvgw_ntp")
    net.ns(net.gw, "nft", "-f", "-", input=ntp_definition(1))
    try:
        assert ntp(net, vnet.WEB) == PASS
        assert ntp(net, vnet.RESOLVER) == PASS  # no room for it in the set, and it still left
        assert servers(net) == {vnet.WEB: 1}
        assert total(net) == 2  # the rule counts before it updates the set
    finally:
        net.ns(net.gw, "nft", "delete", "table", "inet", "tvgw_ntp", check=False)
