"""(depth) Two of verify's new checks on a kernel: `disk` on a filesystem that really fills, and
`forward_policy` and `input_policy` against another firewall's drop policy in the namespace gateway.

`disk` reads a small tmpfs, mounted in a mount namespace of its own with `unshare --mount` so nothing on
the host is mounted: empty, it reports its WARN level (under 2 GiB free), and filled past the last 512
MiB, its FAIL level (held at WARN while the check is new); remounted read-only, its FAIL level again.

The firewall checks run over the `direct` scenario with a ufw-like table added beside tvgw's: a forward
chain with policy drop stops the TV's web traffic (the probe proves it) and `forward_policy` reports its
FAIL level; an accept for the TV's port lets it through again and the check reports its WARN level; the
table removed, OK. The same for the input hook, where the TV's lookup to the gateway is the probe.

Run as root on a Linux machine or VM (tests/virtual/README.md):

    sudo env PYTHONPATH=src python3 -m pytest -m virtual tests/virtual -q -p no:cacheprovider
"""

from __future__ import annotations

import json
import subprocess
import sys

import pytest
import vnet

pytestmark = pytest.mark.virtual

SRC = vnet.ROOT / "src"
WEB_PASS = f"pass:{vnet.GW_WLAN}"  # the web service saw the TV's connection come from the uplink
TABLE = "tvgwv_ufw"  # family ip, not inet tvgw*: another firewall's, as far as the checks can tell
# what the disk check says of a path, run inside the mount namespace: one JSON line per state
DISK_PROBE = """
import json, os, sys
sys.path.insert(0, sys.argv[1])
from tvgw import verify
level, detail = verify.disk_level(sys.argv[2], os.statvfs)
print(json.dumps([level, detail]))
"""


def test_disk_reports_each_level_on_a_filesystem_that_fills(tmp_path):
    mount = tmp_path / "state"
    mount.mkdir()
    probe = [sys.executable, "-I", "-c", DISK_PROBE, str(SRC), str(mount)]
    script = (
        'set -e; mount -t tmpfs -o size=600m tvgwv-disk "$1"; shift; '
        '"$@"; dd if=/dev/zero of="$MNT/fill" bs=1M count=200 status=none; "$@"; '
        'mount -o remount,ro "$MNT"; "$@"'
    )
    out = subprocess.run(
        ["unshare", "--mount", "--propagation", "private", "bash", "-c", script, "_", str(mount), *probe],
        capture_output=True,
        text=True,
        timeout=60,
        env={"MNT": str(mount), "PATH": "/usr/sbin:/usr/bin:/sbin:/bin"},
        check=False,
    )
    assert out.returncode == 0, out.stderr
    empty, full, read_only = (json.loads(line) for line in out.stdout.splitlines())
    assert empty[0] == "warn" and empty[1].endswith("under 2.0 GiB"), empty
    assert full[0] == "fail" and full[1].endswith("under 512 MiB"), full
    assert read_only == ["fail", "the filesystem where the record is kept is read-only"]
    assert not any(mount.iterdir())  # the tmpfs lived in the namespace only


@pytest.fixture(scope="module")
def applied(net):
    """The direct scenario applied in the gateway namespace, the gap's helper route in place, and every
    table this module adds removed at the end."""
    conf = vnet.render_conf(
        {"UPLINK": "direct", "BLOCK_QUIC": "yes", "STRICT_PORTS": "no", "DNSGATE": "count"}
    )
    out = net.apply(net.gw, conf)
    assert out.returncode == 0, out.stderr
    if net.reply_dev() != vnet.TV_IF:  # vnet.HELPER_ROUTE says why
        net.ns(net.gw, "ip", *vnet.HELPER_ROUTE)
    yield net
    net.ns(net.gw, "nft", "delete", "table", "ip", TABLE, check=False)


def levels(net) -> tuple[str, str]:
    verify = pytest.importorskip("tvgw.verify")
    doc = json.loads(net.ns(net.gw, "nft", "-j", "list", "ruleset").stdout)
    return verify.forward_policy_level(doc, vnet.TV_IF)[0], verify.input_policy_level(doc, vnet.TV_IF)[0]


def drop_table(hook: str) -> str:
    """Another firewall's table as nft reads it from a file: one base chain on `hook`, dropping by default."""
    return f"table ip {TABLE} {{\n\tchain {hook} {{\n\t\ttype filter hook {hook} priority 0; policy drop;\n\t}}\n}}\n"


def load(net, text: str) -> None:
    path = net.save(f"depth/{TABLE}.nft", text)
    loaded = net.ns(net.gw, "nft", "-f", str(path), check=False)
    assert loaded.returncode == 0, loaded.stderr


def test_another_firewalls_forward_drop_is_reported_at_its_level(applied):
    net = applied
    assert levels(net) == ("ok", "ok")  # tvgw's own tables drop by default and are not counted
    assert net.probe("tv", "tcp", vnet.WEB, 80) == WEB_PASS
    load(net, drop_table("forward"))
    try:
        assert net.probe("tv", "tcp", vnet.WEB, 80, timeout="1") == "drop"  # the premise: the TV is cut off
        assert levels(net)[0] == "fail"
        net.ns(net.gw, "nft", "add", "rule", "ip", TABLE, "forward", "iifname", vnet.TV_IF, "accept")
        net.ns(
            net.gw,
            "nft",
            "add",
            "rule",
            "ip",
            TABLE,
            "forward",
            "ct",
            "state",
            "established,related",
            "accept",
        )
        assert net.probe("tv", "tcp", vnet.WEB, 80) == WEB_PASS
        assert levels(net)[0] == "warn"
    finally:
        net.ns(net.gw, "nft", "delete", "table", "ip", TABLE, check=False)
    assert levels(net)[0] == "ok"


def test_another_firewalls_input_drop_is_reported_at_its_level(applied):
    net = applied
    dns = ("dns-udp", vnet.GW_TV, 53)
    want = f"answer:{vnet.GW_ANSWER}"
    assert net.probe("tv", *dns) == want
    load(net, drop_table("input"))
    try:
        assert net.probe("tv", *dns, timeout="1") != want  # the TV's lookups no longer reach the filter
        assert levels(net)[1] == "fail"
        for proto, port in (("udp", "67"), ("udp", "53"), ("tcp", "53")):
            net.ns(
                net.gw,
                "nft",
                "add",
                "rule",
                "ip",
                TABLE,
                "input",
                "iifname",
                vnet.TV_IF,
                proto,
                "dport",
                port,
                "accept",
            )
        assert net.probe("tv", *dns) == want
        assert levels(net)[1] == "warn"
    finally:
        net.ns(net.gw, "nft", "delete", "table", "ip", TABLE, check=False)
    assert levels(net)[1] == "ok"
