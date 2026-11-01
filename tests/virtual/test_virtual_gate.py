"""(events) The DNS gate's set on a real kernel: an address answered again starts its day again
(design decision 43 (events), deep dive 06 F2).

From kernel 6.12 an `add element` that meets an element already in a timeout set moves its expiry
only when the add carries `expires`; without it the address keeps its first expiry and drops out a
day after it was first answered, however often the TV asked since. The test builds resolved4 as
tvgw-apply builds it, in the scratch namespace, feeds it what dnsgate.batch sends, reads the expiry
back, and leaves the namespace empty, as test_virtual_rulesets.py requires."""

from __future__ import annotations

import json
import os
import re

import pytest
import vnet

from tvgw import dnsgate

pytestmark = pytest.mark.virtual

ADDRESS = "192.0.2.1"  # a documentation address
SCRIPT = vnet.APPLY.read_text(encoding="utf-8")


def gate_definition() -> str:
    """The table and the set exactly as tvgw-apply creates them."""
    lines = [
        line.strip()
        for line in SCRIPT.splitlines()
        if line.strip().startswith(("add table inet tvgw_gate", "add set inet tvgw_gate resolved4 "))
    ]
    assert len(lines) == 2, lines
    return "\n".join(lines) + "\n"


def kernel_at_least(major: int, minor: int) -> bool:
    m = re.match(r"(\d+)\.(\d+)", os.uname().release)
    return bool(m) and (int(m.group(1)), int(m.group(2))) >= (major, minor)


def expires(net) -> int:
    """Seconds left on ADDRESS in resolved4, from the kernel's own listing."""
    out = net.ns(net.chk, "nft", "-j", "list", "set", "inet", "tvgw_gate", "resolved4").stdout
    for obj in json.loads(out)["nftables"]:
        for elem in (obj.get("set") or {}).get("elem") or []:
            e = elem.get("elem") if isinstance(elem, dict) else None
            if isinstance(e, dict) and e.get("val") == ADDRESS:
                return int(e["expires"])
    raise AssertionError(f"{ADDRESS} is not in the set: {out}")


def nft(net, script: str) -> None:
    net.ns(net.chk, "nft", "-f", "-", input=script)


def test_an_address_answered_again_gets_a_fresh_day(net):
    try:
        nft(net, gate_definition())
        nft(net, f"add element inet tvgw_gate resolved4 {{ {ADDRESS} timeout 1d expires 1h }}\n")
        assert 3500 <= expires(net) <= 3600  # about 59 minutes left
        # today's feeder before the fix: a timeout alone keeps the first expiry, on every kernel
        nft(net, f"add element inet tvgw_gate resolved4 {{ {ADDRESS} timeout 1d }}\n")
        assert 3500 <= expires(net) <= 3600
        # what dnsgate.batch sends now
        nft(net, dnsgate.batch([ADDRESS]))
        if not kernel_at_least(6, 12):
            pytest.skip(f"kernel {os.uname().release} keeps the first expiry; the refresh needs 6.12")
        assert expires(net) > dnsgate.TTL - 120  # about 23 h 59 min: refreshed
    finally:
        net.ns(net.chk, "nft", "delete", "table", "inet", "tvgw_gate", check=False)
    assert net.ns(net.chk, "nft", "list", "ruleset").stdout.strip() == ""
