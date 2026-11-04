"""The virtual gateway at work: tvgw-apply runs in the `gw` namespace and the TV's probes go through it.

Each scenario of matrix.txt is applied in turn, once, the way the dispatcher re-applies on the Pi
(conftest.in_scenario_order keeps them in turn, whatever order pytest would choose), and each row is one
probe from the TV (or from the internet) with two checks: what the probe saw, and which rule's counter
moved. The second is what the hardware suite can only infer on the Pi: a probe that was rejected by the
wrong rule, or let through by a rule meant to count only, fails here. A refusal the kernel's ICMP rate
limit held back would look like a drop; the gateway namespace has that limit off (vnet.Net.build), and a
row's observed line names any the kernel held back all the same.

Run as root on a Linux machine or VM (tests/virtual/README.md):

    sudo env PYTHONPATH=src python3 -m pytest -m virtual tests/virtual -q -p no:cacheprovider
"""

from __future__ import annotations

import dataclasses
import json
import select
import shutil
import subprocess
import time
from pathlib import Path

import pytest
import vnet

pytestmark = pytest.mark.virtual

SCENARIOS = vnet.parse_matrix(vnet.MATRIX.read_text(encoding="utf-8"))
BY_NAME = {s.name: s for s in SCENARIOS}
OUT_IF = {"direct": vnet.WAN_IF, "vpn": vnet.VPN_IF}


@dataclasses.dataclass(frozen=True)
class Applied:
    """A scenario as the gateway now runs it, and the directory its apply wrote /run/tvgw into."""

    name: str
    settings: dict[str, str]
    run_dir: Path
    reply_dev: str | None  # where the gateway's own packets to the TV leave after this apply


class Observed:
    """The matrix as this run saw it, written next to the rulesets: the file to diff when a row fails."""

    def __init__(self, path: Path):
        self.path = path
        self.lines: dict[str, list[str]] = {}

    def record(
        self, scenario: Applied, row: vnet.Row, got: str, gained: dict[str, int], held: dict[str, int]
    ) -> None:
        mark = "" if got == row.expected() else "   # expected " + row.verdict
        moved = ", ".join(f"{c} +{n}" for c, n in sorted(gained.items()))
        kernel = "".join(f", kernel {k} +{n}" for k, n in sorted(held.items()))  # vnet.ICMP_HELD
        self.lines.setdefault(scenario.name, []).append(
            f"{row.line(got)}{mark}\n#   moved: {moved or 'nothing'}{kernel}"
        )

    def write(self) -> None:
        body = []
        for s in SCENARIOS:
            if s.name in self.lines:
                settings = " ".join(f"{k}={v}" for k, v in s.settings.items())
                body += [f"[{s.name}] {settings}", *self.lines[s.name], ""]
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.path.write_text("\n".join(body), encoding="utf-8")


@pytest.fixture(scope="module")
def observed(artifacts):
    o = Observed(artifacts / "matrix.observed.txt")
    yield o
    o.write()


@pytest.fixture(scope="module")
def scenario(request, net) -> Applied:
    """The scenario's settings applied to the gateway, and what the apply wrote kept as artifacts."""
    s = BY_NAME[request.param]
    run_dir = net.sandbox / f"run-{s.name}"
    run_dir.mkdir(exist_ok=True)
    # an earlier scenario's apply left the TV subnet in table 100; without it here, the route the
    # gateway's own answers take after this apply is this apply's doing (design decision 49)
    net.ns(net.gw, "ip", "route", "del", "10.10.10.0/24", "table", "100", check=False)
    out = net.apply(net.gw, vnet.render_conf(s.settings), run_dir=run_dir)
    net.save(f"scenarios/{s.name}/apply.log", out.stdout + out.stderr)
    assert out.returncode == 0, out.stderr
    for f in sorted(run_dir.iterdir()):
        net.save(f"scenarios/{s.name}/{f.name}", f.read_text(encoding="utf-8"))
    net.save(f"scenarios/{s.name}/ruleset.nft", net.ns(net.gw, "nft", "list", "ruleset").stdout)
    return Applied(s.name, s.settings, run_dir, net.reply_dev())


def pytest_generate_tests(metafunc):
    if "row" in metafunc.fixturenames:
        pairs = list(vnet.iter_rows(SCENARIOS))
        metafunc.parametrize(
            ["scenario", "row"],
            [(s.name, r) for s, r in pairs],
            ids=[f"{s.name}:{r.id}" for s, r in pairs],
            indirect=["scenario"],
            scope="module",
        )
    elif "scenario" in metafunc.fixturenames and not any(
        "scenario" in str(m.args[0]) for m in metafunc.definition.iter_markers("parametrize")
    ):
        metafunc.parametrize("scenario", list(BY_NAME), indirect=True, scope="module")


def test_reachability(scenario, row, net, observed):
    held_before = net.icmp_held()
    before = net.counters()
    got = net.probe(row.source, row.kind, row.target, row.port)
    after = net.counters()
    gained = vnet.ticked(before, after)
    held = {k: n - held_before.get(k, 0) for k, n in net.icmp_held().items() if n > held_before.get(k, 0)}
    observed.record(scenario, row, got, gained, held)
    why = f"; the kernel's ICMP rate limit held back {held}" if held else ""
    assert got == row.expected(), f"{row.line()}: the probe saw {got}{why}"
    if row.counter:
        assert row.counter in after, f"no rule with a counter is commented {row.counter!r}"
        assert gained.get(row.counter, 0) >= 1, f"{row.counter!r} did not move; moved: {gained}"
    stray = sorted(
        c for c in gained if after[c][1] in ("drop", "reject") and c != row.counter and c not in vnet.NOISY
    )
    assert not stray, f"{row.line()}: other drop or reject rules moved: {stray}"


def test_the_counters_the_script_names_are_the_ones_loaded(scenario, net):
    """Every counted rule the apply renders for these settings is in the kernel with its counter, and
    nothing else is: the brief and verify read the counters by comment (design decision 13)."""
    rendered = net.apply(net.gw, vnet.render_conf(scenario.settings), ("--check",))
    assert rendered.returncode == 0, rendered.stderr
    assert set(net.counters()) == vnet.counted_comments(rendered.stdout)


def test_the_policy_route_sends_the_tv_out_by_the_chosen_uplink(scenario, net):
    uplink = scenario.settings["UPLINK"]
    route = json.loads(
        net.ns(net.gw, "ip", "-j", "route", "get", vnet.WEB, "from", vnet.TV_IP, "iif", vnet.TV_IF).stdout
    )
    assert route[0]["dev"] == OUT_IF[uplink]
    rule = net.ns(net.gw, "ip", "rule", "show", "priority", "60").stdout
    if uplink == "direct":
        assert "from 10.10.10.0/24 lookup 100" in rule
        table = net.ns(net.gw, "ip", "route", "show", "table", "100").stdout
        assert f"default via {vnet.WAN_GW} dev {vnet.WAN_IF}" in table
        assert f"10.10.10.0/24 dev {vnet.TV_IF} scope link src {vnet.GW_TV}" in table  # design decision 49
    else:
        assert rule.strip() == ""
    # the gateway's own default (PIA's, on the Pi) is left alone
    main = net.ns(net.gw, "ip", "route", "show", "default").stdout
    assert f"default via {vnet.WAN_TUN} dev {vnet.VPN_IF}" in main


def test_verify_finds_its_rules_in_the_kernels_own_listing(scenario, net):
    """verify.KEY_RULES are matched against `nft -s list table inet tvgw`, which nft prints in its own
    spelling; test_deploy_lint.py only checks them against the script's text. And the baseline the apply
    wrote is the listing verify will compare it with."""
    verify = pytest.importorskip("tvgw.verify")
    config = pytest.importorskip("tvgw.config")
    listing = net.ns(net.gw, "nft", "-s", "list", "table", "inet", "tvgw").stdout
    needles = {**verify.KEY_RULES, **(verify.QUIC_RULE if scenario.settings["BLOCK_QUIC"] == "yes" else {})}
    missing = [why for needle, why in needles.items() if needle.replace("GW_IP", vnet.GW_TV) not in listing]
    assert missing == []
    l2 = json.loads(net.ns(net.gw, "nft", "-j", "list", "table", "netdev", "tvgw_l2").stdout)
    assert any(
        o.get("rule", {}).get("comment") == verify.IPV6_GUARD
        and any(isinstance(e, dict) and "drop" in e for e in o["rule"]["expr"])
        for o in l2["nftables"]
    )
    applied = (scenario.run_dir / "ruleset.applied").read_text(encoding="utf-8")
    assert applied.strip() == listing.strip()
    used = config.parse_conf((scenario.run_dir / "settings.applied").read_text(encoding="utf-8"))
    # (uplink) the router the routes use, beside the keys verify compares: WAN_GW, the mode being literal
    assert used.pop("WAN_GW_USED") == (vnet.WAN_GW if scenario.settings["UPLINK"] == "direct" else "")
    assert used == verify.apply_settings(vnet.render_conf(scenario.settings))


@pytest.mark.parametrize("scenario", ["direct"], indirect=True)
def test_a_reapply_with_nothing_changed_keeps_a_live_connection(scenario, net):
    """The 2026-10-30 incident: re-adding rule 60 or replacing an unchanged route destroyed the conntrack
    entry of the connection with data in flight. A re-apply must emit no rule or route change at all,
    and the connection must carry on with the same conntrack entry."""
    held = subprocess.Popen(
        net.agent_argv(net.tv, "probe", "hold", vnet.WEB, "443"),
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        text=True,
        encoding="utf-8",
    )
    monitor = None
    try:
        assert held.stdout.readline().strip() == f"connected:{vnet.GW_WLAN}"
        before = conntrack_ids(net)
        monitor = subprocess.Popen(
            ["ip", "-4", "-n", net.gw, "monitor", "rule", "route"],  # v6 addrconf routes are noise
            stdout=subprocess.PIPE,
            text=True,
            encoding="utf-8",
        )
        time.sleep(0.5)  # subscribed before the apply starts
        out = net.apply(net.gw, vnet.render_conf(scenario.settings))
        assert out.returncode == 0, out.stderr
        time.sleep(0.5)
        monitor.terminate()
        events, _ = monitor.communicate(timeout=5)
        assert events.strip() == "", f"the re-apply changed routing:\n{events}"
        held.stdin.write("after the re-apply\n")
        held.stdin.flush()
        ready, _, _ = select.select([held.stdout], [], [], 5)
        assert ready and held.stdout.readline().strip() == "echo:after the re-apply"
        if before is not None:
            assert conntrack_ids(net) == before
    finally:
        for p in (monitor, held):
            if p is None:
                continue
            p.kill()
            p.communicate(timeout=5)  # reaps it and closes its pipes


def test_the_gateway_reaches_the_tv_by_the_apply_alone(scenario, net):
    """Rule 60 also matches what the gateway itself sends to the TV from 10.10.10.1 (a DNS answer,
    nginx's half of a handshake). The apply puts the TV subnet in table 100, so those leave by the TV
    port with no route from outside tvgw, which no gateway without a VPN client has (design decision
    49). In vpn mode rule 60 is gone and the main table's route answers. And `tvgw verify`'s check
    reads the kernel's own answer the same way."""
    assert scenario.reply_dev == vnet.TV_IF
    assert net.reply_dev("10.10.10.17") == vnet.TV_IF  # any address of the TV subnet
    verify = pytest.importorskip("tvgw.verify")
    config = pytest.importorskip("tvgw.config")
    s = config.Settings(tv_ip=vnet.TV_IP, gw_ip=vnet.GW_TV, tv_if=vnet.TV_IF)  # the same in both modes
    check = verify.gw_reply_route_check(s, lambda cmd: net.ns(net.gw, *cmd, check=False).stdout)
    assert check.ok, check.detail


@pytest.mark.parametrize("scenario", ["direct"], indirect=True)
def test_a_rejects_refusal_never_needed_the_tv_subnet_in_table_100(scenario, net):
    """The refusal of a forwarded packet, the ICMP of a `reject`, is routed before it has a source
    address: with net.ipv4.icmp_errors_use_inbound_ifaddr at its default the kernel picks one after the
    route, so rule 60 (`from 10.10.10.0/24`) never matches it and the main table's route to the TV
    subnet takes it. With the TV subnet out of table 100 the QUIC row is still refused at once, while
    nginx's half of a handshake, from 10.10.10.1, leaves by the uplink and is lost, and `gw_reply_route`
    fails: the check reads the stricter of the two paths (design decision 49, its note of 2026-11-04).
    The apply then puts the route back."""
    verify = pytest.importorskip("tvgw.verify")
    config = pytest.importorskip("tvgw.config")
    s = config.Settings(tv_ip=vnet.TV_IP, gw_ip=vnet.GW_TV, tv_if=vnet.TV_IF)
    net.ns(net.gw, "ip", "route", "del", "10.10.10.0/24", "table", "100")
    try:
        assert net.reply_dev() == vnet.WAN_IF
        assert net.probe("tv", "udp", vnet.WEB, 443) == "reject"
        assert net.probe("tv", "tcp", vnet.GW_TV, 80) == "drop"
        check = verify.gw_reply_route_check(s, lambda cmd: net.ns(net.gw, *cmd, check=False).stdout)
        assert not check.ok, check.detail
    finally:
        out = net.apply(net.gw, vnet.render_conf(scenario.settings))
        assert out.returncode == 0, out.stderr
    assert net.reply_dev() == vnet.TV_IF


def conntrack_ids(net) -> set[str] | None:
    """The ids of the gateway's conntrack entries for TCP to the web server, or None without conntrack."""
    if shutil.which("conntrack") is None:
        return None
    out = net.ns(
        net.gw, "conntrack", "-L", "-p", "tcp", "-d", vnet.WEB, "--dport", "443", "-o", "id", check=False
    )
    ids = {word.removeprefix("id=") for word in out.stdout.split() if word.startswith("id=")}
    assert ids, f"no conntrack entry for the held connection: {out.stdout} {out.stderr}"
    return ids


@pytest.mark.parametrize(
    ("kind", "target", "port", "expected"),
    [
        ("dns-udp", vnet.RESOLVER, 53, "answer:wan"),
        ("dns-tcp", vnet.RESOLVER, 53, "answer:wan"),
        ("tcp", vnet.RESOLVER, 853, "pass:tun0"),
        ("udp", vnet.RESOLVER, 853, "pass:tun0"),
        ("udp", vnet.RESOLVER, 784, "pass:tun0"),
        ("udp", vnet.RESOLVER, 8853, "pass:tun0"),
        ("tcp", vnet.DOH, 443, "pass:tun0"),
        ("udp", vnet.WEB, 443, "pass:tun0"),
        ("tcp", vnet.WEB, 8000, "pass:tun0"),
        ("udp", vnet.WEB, 5000, "pass:tun0"),
        ("tcp", vnet.WEB, 8080, "pass:tun0"),
        ("tcp", vnet.WEB, 4431, "pass:tun0"),  # (acr) the adtech port wall's rows
        ("tcp", vnet.BLOCKED, 443, "pass:tun0"),
        ("tcp", vnet.LAN_HOST, 443, "pass:tun0"),
        ("tcp", vnet.LG_FALLBACK, 8080, "pass:tun0"),
        ("ping", vnet.WEB, 200, "pass"),
        ("gre", vnet.WEB, None, "pass"),
        ("tcp", vnet.TV_IP, 8000, "pass:gw"),
    ],
    ids=lambda v: str(v),
)
def test_every_service_a_row_expects_blocked_answers_the_gateway_itself(net, kind, target, port, expected):
    """The negative rows mean something only if the far end would have answered: from the gateway, which
    tvgw does not filter, every service is reached (by the tunnel, the main table's default; `pass:tun0`
    is the tunnel's address whatever the interface is called)."""
    want = vnet.Row("gw", kind, target, port, expected, None).expected()
    assert net.probe("gw", kind, target, port) == want
