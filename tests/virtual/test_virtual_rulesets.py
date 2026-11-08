"""`nft -c` on every ruleset tvgw-apply can produce, before any of them reaches the Pi (R&D section 11).

The switches' values are read from the script's own `case` arms (vnet.script_choices), so a value added
there is checked without anyone remembering to list it here. Each variant is rendered by
`tvgw-apply --check` in a scratch namespace that holds only the interfaces the netdev table names, and
the check must leave that namespace exactly as it found it. The rendered rulesets are the CI artifact."""

from __future__ import annotations

import re

import pytest
import vnet

pytestmark = pytest.mark.virtual

SCRIPT = vnet.APPLY.read_text(encoding="utf-8")
VARIANTS = vnet.variants(vnet.script_choices(SCRIPT))


@pytest.fixture(scope="module")
def renders(net) -> dict[str, tuple]:
    """name -> (settings, the --check run, its /run/tvgw): every variant rendered once, kept as an artifact."""
    out = {}
    for settings in VARIANTS:
        name = vnet.variant_name(settings)
        run_dir = net.sandbox / f"check-{name}"
        run_dir.mkdir()
        done = net.apply(net.chk, vnet.render_conf(settings), ("--check",), run_dir=run_dir)
        net.save(f"rulesets/{name}.nft", done.stdout)
        if done.stderr:
            net.save(f"rulesets/{name}.stderr", done.stderr)
        out[name] = (settings, done, run_dir)
    return out


def test_the_variants_cover_every_switch():
    assert {
        "UPLINK",
        "BLOCK_QUIC",
        "STRICT_PORTS",
        "DNSGATE",
        "CAPTURE_MODE",
        "ADTECH_PORT_WALL",
        "DNSGATE_FILL",
        "NAME_BINDING",
    } <= set(VARIANTS[0])
    assert len(VARIANTS) >= 128  # (acr) ADTECH_PORT_WALL doubled the 32; (inpath) DNSGATE_FILL the 64


@pytest.mark.parametrize("name", [vnet.variant_name(v) for v in VARIANTS])
def test_every_variant_passes_nft_check_and_changes_nothing(renders, net, name):
    _settings, done, run_dir = renders[name]
    assert done.returncode == 0, done.stderr
    assert done.stdout.startswith("table inet tvgw\n")
    assert list(run_dir.iterdir()) == [], "--check wrote under /run/tvgw"
    # the scratch namespace is as the check found it: no table, forwarding off, no policy rule
    assert net.ns(net.chk, "nft", "list", "ruleset").stdout.strip() == ""
    assert net.ns(net.chk, "sysctl", "-n", "net.ipv4.ip_forward").stdout.strip() == "0"
    assert net.ns(net.chk, "ip", "rule", "show", "priority", "60").stdout.strip() == ""
    # the artifact is itself a ruleset nft accepts, so a reviewer can load what CI checked
    again = net.ns(net.chk, "nft", "-c", "-f", str(net.artifacts / f"rulesets/{name}.nft"), check=False)
    assert again.returncode == 0, again.stderr


@pytest.mark.parametrize("name", [vnet.variant_name(v) for v in VARIANTS])
def test_each_switch_renders_what_it_says(renders, name):
    settings, done, _ = renders[name]
    text = done.stdout
    assert ("QUIC: force TCP+TLS so SNI is visible" in text) == (settings["BLOCK_QUIC"] == "yes")
    # (probe) the probe's port has its twin exactly when TV_PROBE=on, and the twin records nothing
    twin = ("add chain inet tvgw probe_", "add rule inet tvgw probe_", "insert rule inet tvgw ")
    mine = [ln for ln in text.splitlines() if ln.startswith(twin)]
    assert bool(mine) == (settings["TV_PROBE"] == "on") == (f'iifname "{vnet.PROBE_IF}"' in text)
    assert not [ln for ln in mine if " counter" in ln or " comment " in ln or " log " in ln]
    if mine:
        assert (
            f'add rule inet tvgw probe_fwd iifname "{vnet.PROBE_IF}" ip saddr != {vnet.PROBE_IP} drop' in mine
        )
        assert (
            mine[-1].startswith("insert rule inet tvgw post_nat ")
            and "add rule inet tvgw probe_out accept" in mine
        )
    assert ("STRICT_PORTS: only web, NTP and DNS" in text) == (settings["STRICT_PORTS"] == "yes")
    assert ("STRICT_PORTS=no: count only" in text) == (settings["STRICT_PORTS"] == "no")
    assert ("add table inet tvgw_gate" in text) == (settings["DNSGATE"] != "off")
    assert ("table inet tvgw_capture {" in text) == (settings["CAPTURE_MODE"] == "headers")  # (capture)
    # (inpath) the in-path block, whole, only with the gate counting and DNSGATE_FILL=inpath (design
    # decision 64): its sets, its two queue rules with bypass, its own count; no trace of it otherwise
    fill = settings["DNSGATE"] != "off" and settings["DNSGATE_FILL"] == "inpath"
    assert ("add set inet tvgw_gate resolved4_inpath" in text) == fill
    assert ("add set inet tvgw_gate inpath_live { type inet_service; }" in text) == fill
    # the word alone would not do: the headers capture's `queue-threshold 1` is in every headers variant
    assert (text.count(" queue flags bypass to ") == 2) == fill
    for proto in (
        "udp sport @inpath_live",
        "tcp sport @inpath_live tcp flags & (syn | rst) == 0",
    ):
        assert (f"{proto} counter queue flags bypass to 53053 comment" in text) == fill
    assert ("resolved4_inpath" in text) == fill and ("forward_inpath" in text) == fill
    assert ('log prefix "tvgw-inpath: "' in text) == fill
    assert ("inpath" in text or "in-path" in text) == fill
    # (namebound) the names table, whole, only with NAME_BINDING=count (design decision 70): two base chains
    # of copies and nothing that decides; no trace of it otherwise
    names = settings["NAME_BINDING"] == "count"
    assert ("table inet tvgw_names {" in text) == names and ("names:" in text) == names
    if names:
        table = text[text.index("table inet tvgw_names {") :]
        table = table[: table.index("\n}\n")]
        verdicts = table.replace("policy accept;", "").replace("queue-threshold", "")
        assert not re.search(
            r"\b(drop|reject|accept|queue|dnat|snat|masquerade|redirect|jump|goto)\b", verdicts
        )
        assert table.count("log group 8 snaplen 4096 queue-threshold 1") == 3
    # (acr) the wall, its log sample and its counter, in every variant with the switch on and none without
    wall = settings["ADTECH_PORT_WALL"] == "yes"
    ports = "tcp dport { 4001, 4431, 4445, 4447, 8180, 8883 }"
    assert (f'{ports} counter reject with tcp reset comment "LG adtech port"' in text) == wall
    assert (f'{ports} limit rate 6/minute log prefix "tvgw-adport: "' in text) == wall
    assert ("tvgw-adport" in text or "LG adtech port" in text) == wall
    vpn = settings["UPLINK"] == "vpn"
    assert (f'oifname != "{vnet.VPN_IF}"' in text) == vpn and ('comment "tunnel MTU"' in text) == vpn
    assert ("undo PIA routed-packet tag" in text) == (not vpn)
    # (events) every variant marks the TV's connections for the flow log and counts the Pi's leaks, in
    # both uplink modes (design decisions 43 and 44)
    assert "chain ct_events {\n\t\ttype filter hook prerouting priority -150; policy accept;" in text
    assert 'ct state new ct event set destroy comment "flow log: TV connections only"' in text
    assert (
        'comment "pi leak: DoH left by the uplink"' in text
        and 'comment "pi leak: DNS left by the uplink"' in text
    )
    assert f"{vnet.VPN_DROP} ct state new counter drop" in text


@pytest.mark.parametrize("name", [vnet.variant_name(v) for v in VARIANTS if v["DNSGATE_FILL"] == "passive"])
def test_a_passive_variant_renders_what_a_conf_without_the_key_renders(renders, net, name):
    """(inpath) DNSGATE_FILL=passive is the default and changes nothing: byte for byte the rulesets of
    the same settings with the key left out, as an existing gateway's settings file leaves it out."""
    settings, done, _ = renders[name]
    without = {k: v for k, v in settings.items() if k != "DNSGATE_FILL"}
    again = net.apply(net.chk, vnet.render_conf(without), ("--check",))
    assert again.returncode == 0, again.stderr
    assert again.stdout == done.stdout


@pytest.fixture(scope="module")
def clock_renders(net) -> dict[str, tuple]:
    """(ports) The clock port's variants (vnet.CLOCK_VARIANTS), rendered by the copy of the script in which
    ntp=resolved is supported, as test_virtual_clock.py runs it; kept as artifacts beside the others."""
    script = net.sandbox / "tvgw-apply-clock-check"
    script.write_text(vnet.clock_script(SCRIPT), encoding="utf-8")
    out = {}
    for settings in vnet.CLOCK_VARIANTS:
        name = "clock-" + vnet.variant_name(settings)
        run_dir = net.sandbox / f"check-{name}"
        run_dir.mkdir()
        done = net.apply(net.chk, vnet.render_conf(settings), ("--check",), run_dir=run_dir, script=script)
        net.save(f"rulesets/{name}.nft", done.stdout)
        out[name] = (settings, done, run_dir)
    return out


@pytest.mark.parametrize("name", ["clock-" + vnet.variant_name(v) for v in vnet.CLOCK_VARIANTS])
def test_each_clock_variant_passes_nft_check_and_renders_its_rule_where_it_belongs(clock_renders, net, name):
    settings, done, run_dir = clock_renders[name]
    assert done.returncode == 0, done.stderr
    assert list(run_dir.iterdir()) == [], "--check wrote under /run/tvgw"
    assert net.ns(net.chk, "nft", "list", "ruleset").stdout.strip() == ""
    text = done.stdout
    closed = settings["CLOCK_PORT"] == "none"
    resolved = (
        settings["CLOCK_PORT"] == "resolved"
        and settings["DNSGATE"] == "count"
        and settings.get("DNSGATE_FILL") == "inpath"
    )
    assert ('udp dport 123 counter reject comment "clock port: closed, NTP to no server"' in text) == closed
    # the sample: in tv_out when closed, in the gate's clock chain (after its set lookups) when resolved
    assert ('udp dport 123 limit rate 6/minute log prefix "tvgw-ntp: "' in text) == closed
    assert ('log prefix "tvgw-ntp: "' in text) == (closed or resolved)
    assert ("add chain inet tvgw_gate clock {" in text) == resolved
    assert ('comment "clock port: only to an address a lookup returned"' in text) == resolved
    if closed and settings.get("TV_PROBE") == "on":  # the probe's twin carries the closed port
        assert "add rule inet tvgw probe_out udp dport 123 reject\n" in text
    if settings["CLOCK_PORT"] == "resolved" and not resolved:
        assert "needs DNSGATE=count and DNSGATE_FILL=inpath" in done.stderr


def test_every_counted_rule_of_the_script_is_rendered_by_some_variant(renders, clock_renders):
    """A rule no variant renders is a rule no check and no matrix row has ever seen. (ports) The clock
    port's rules are rendered only by a narrowing, so its variants count here too."""
    every = [*renders.values(), *clock_renders.values()]
    rendered = set().union(*(vnet.counted_comments(done.stdout) for _, done, _ in every))
    assert vnet.counted_comments(SCRIPT) == rendered
