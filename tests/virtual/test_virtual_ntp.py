"""(ntp) The count of the clock servers the TV sends NTP to, on a kernel (design decision 17, its note of
2026-11-05).

tvgw-apply keeps the table `inet tvgw_ntp`: one forward rule after every chain that can refuse, which
counts the TV's UDP 123 and updates the dynamic set `ntp4` with a counter per address. Over the
`direct` scenario this module probes UDP 123 from the TV to two of the internet side's addresses and
one the manual blocks refuse, and reads the kernel's own listing with `verify.ntp_counters`, the parser
`tvgw verify --record` uses: each address the TV reached is an element with exactly its requests, the
refused one is none, the rule's total is their sum, and no probe's verdict changed. A re-apply keeps
every element and its count and zeroes only the rule's total. Each request starts its element's
timeout again, which `update` does and `add` would not. A set an older build left with other
properties is deleted and made again by the next apply, where nft would otherwise refuse the batch at
every apply. With the table gone, and with a set too small for the addresses the TV uses, NTP still
leaves: the count can lose evidence, never the TV's clock. The module deletes what it built and applies
the scenario again, so the next module finds the gateway as the apply leaves it.

Run as root on a Linux machine or VM (tests/virtual/README.md):

    sudo env PYTHONPATH=src python3 -m pytest -m virtual tests/virtual -q -p no:cacheprovider
"""

from __future__ import annotations

import json
import time

import pytest
import vnet

pytestmark = pytest.mark.virtual

SCRIPT = vnet.APPLY.read_text(encoding="utf-8")
PASS = f"pass:{vnet.GW_WLAN}"  # the far end saw the request come from the uplink, masqueraded
CONF = vnet.render_conf({"UPLINK": "direct", "BLOCK_QUIC": "yes", "STRICT_PORTS": "no", "DNSGATE": "count"})
RULE = "NTP from the TV, by server"
TIMEOUT = 864000  # NTP_TIMEOUT, 10 days, in the seconds nft's JSON gives
REMADE = "held a set of other properties"


def ntp_definition(size: int = 1024, timeout: str = "10d") -> str:
    """The table, the set, the chain and the rule exactly as tvgw-apply writes them, with the set's size
    and timeout given here and the TV side the topology's."""
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
        .replace("$NTP_TIMEOUT", timeout)
        .replace('"$TV_IF"', f'"{vnet.TV_IF}"')
        .replace("$TV_NET", "10.10.10.0/24")
    )


def listing(net) -> str:
    return net.ns(net.gw, "nft", "-j", "list", "table", "inet", "tvgw_ntp", check=False).stdout


def ntp4(net) -> dict:
    (found,) = [
        o["set"] for o in json.loads(listing(net))["nftables"] if (o.get("set") or {}).get("name") == "ntp4"
    ]
    return found


def rows(net) -> list[tuple[str, int, int]]:
    verify = pytest.importorskip("tvgw.verify")
    out = verify.ntp_counters(listing(net))
    assert out and out[0][0] == "ntp: ~set", out  # the set was listed
    return out


def servers(net) -> dict[str, int]:
    """Each address's requests, as `tvgw verify --record` stores them; the set's own row left out."""
    return {rule.split(": ", 1)[1]: packets for rule, packets, _ in rows(net)[1:]}


def expiry(net, addr: str) -> int:
    """The seconds the kernel says `addr` has left in the set, as verify stores them."""
    (left,) = [e for rule, _, e in rows(net)[1:] if rule == f"ntp: {addr}"]
    return left


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
    assert "NTP count table not loaded" not in out.stderr and REMADE not in out.stderr
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
    assert rows(net)[0] == ("ntp: ~set", 2, 1024)
    # the set is bounded, and each element leaves 10 days after its last request
    s = ntp4(net)
    assert s["size"] == 1024 and s["timeout"] == TIMEOUT
    # a kernel may list an element's timeout only where it differs from the set's; its expiry it lists
    assert {e["elem"].get("timeout", TIMEOUT) for e in s["elem"]} == {TIMEOUT}
    assert all(0 < e["elem"]["expires"] <= TIMEOUT for e in s["elem"])


def test_a_reapply_keeps_every_address_and_its_count(fresh):
    net = fresh
    before = servers(net)
    assert before  # the module's first test sent its requests
    out = net.apply(net.gw, CONF)
    assert out.returncode == 0, out.stderr
    assert REMADE not in out.stderr  # the set tvgw-apply finds is the one it writes, as nft lists it
    assert servers(net) == before
    assert total(net) == 0  # the chain was flushed and its rule written again; the set was kept
    assert ntp(net, vnet.WEB) == PASS
    assert servers(net) == {**before, vnet.WEB: before[vnet.WEB] + 1}


def test_each_request_starts_its_addresss_timeout_again(fresh):
    """`update` restarts an element's timeout at each request, so an address leaves 10 days after its
    last one; `add` would leave the expiry of its first, and this would fail with it."""
    net = fresh
    assert ntp(net, vnet.WEB) == PASS
    time.sleep(3)
    before = expiry(net, vnet.WEB)  # three seconds or so short of the full timeout
    assert ntp(net, vnet.WEB) == PASS
    assert expiry(net, vnet.WEB) > before


def test_a_set_an_older_build_left_with_other_properties_is_made_again(fresh):
    """The kernel never changes an existing set's timeout or size, and an `add set` that differs fails
    the whole batch: the first build's day-long set would have kept the table as it was at every apply.
    The apply deletes it, says so, and writes the set it writes now, its counts from zero."""
    net = fresh
    net.ns(net.gw, "nft", "delete", "table", "inet", "tvgw_ntp")
    net.ns(net.gw, "nft", "-f", "-", input=ntp_definition(timeout="1d"))
    assert ntp(net, vnet.WEB) == PASS
    assert ntp4(net)["timeout"] == 86400 and servers(net) == {vnet.WEB: 1}
    out = net.apply(net.gw, CONF)
    assert out.returncode == 0, out.stderr
    assert REMADE in out.stderr and "NTP count table not loaded" not in out.stderr
    assert ntp4(net)["timeout"] == TIMEOUT and servers(net) == {}
    assert ntp(net, vnet.WEB) == PASS
    assert servers(net) == {vnet.WEB: 1}


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
    packet goes on by the chain's accept policy, as when the table is missing. The set's row says it is
    full, and the rule's total holds the request no address does."""
    net = fresh
    net.ns(net.gw, "nft", "delete", "table", "inet", "tvgw_ntp")
    net.ns(net.gw, "nft", "-f", "-", input=ntp_definition(size=1))
    try:
        assert ntp(net, vnet.WEB) == PASS
        assert ntp(net, vnet.RESOLVER) == PASS  # no room for it in the set, and it still left
        assert servers(net) == {vnet.WEB: 1}
        assert rows(net)[0] == ("ntp: ~set", 1, 1)
        assert total(net) == 2  # the rule counts before it updates the set
    finally:
        net.ns(net.gw, "nft", "delete", "table", "inet", "tvgw_ntp", check=False)
