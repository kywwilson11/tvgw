"""`nft -c` on every ruleset tvgw-apply can produce, before any of them reaches the Pi (R&D section 11).

The switches' values are read from the script's own `case` arms (vnet.script_choices), so a value added
there is checked without anyone remembering to list it here. Each variant is rendered by
`tvgw-apply --check` in a scratch namespace that holds only the interfaces the netdev table names, and
the check must leave that namespace exactly as it found it. The rendered rulesets are the CI artifact."""

from __future__ import annotations

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
        "tcp sport @inpath_live tcp flags & (fin | syn | rst | psh) == psh",
    ):
        assert (f"{proto} counter queue flags bypass to 53053 comment" in text) == fill
    assert ("resolved4_inpath" in text) == fill and ("forward_inpath" in text) == fill
    assert ('log prefix "tvgw-inpath: "' in text) == fill
    assert ("inpath" in text or "in-path" in text) == fill
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


def test_every_counted_rule_of_the_script_is_rendered_by_some_variant(renders):
    """A rule no variant renders is a rule no check and no matrix row has ever seen."""
    rendered = set().union(*(vnet.counted_comments(done.stdout) for _, done, _ in renders.values()))
    assert vnet.counted_comments(SCRIPT) == rendered
