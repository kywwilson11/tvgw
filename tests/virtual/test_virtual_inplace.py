"""(inplace) The tables changed in place on a kernel (design decision 110): an apply after another ends
with the ruleset a fresh load of its settings makes, keeps the tables that stand where nothing they
define changed, and keeps a connection of the TV's open through three applies.

For each pair of settings below, `nft -s list ruleset` after "the first applied on a gateway that holds
none of tvgw's tables, then the second" is compared with the same after "the second alone". `normalised`
strips what two such rulesets may differ by while every packet meets the same rules: the counters'
values (`-s`), how many elements a set holds (`# count`, from nftables 1.1.6), the elements of the sets
the daemons and the kernel fill as the gateway runs (`RUNTIME`; nothing fills them here, so they are
empty either way), and the order of the tables and of the objects in a table, which is the order they
were made in. That order decides nothing: no two base chains share a hook and a priority (checked here),
so a packet meets them in one order whichever table was made first. Rules keep their order, and the sets
the apply fills keep their elements. Whether a table stood through the second apply is told by its
handle, which the kernel numbers anew for a table made again. Each apply keeps /run/tvgw from the one
before, as on a gateway."""

from __future__ import annotations

import re
import select
import shutil
import subprocess
import tempfile
import time
from pathlib import Path

import pytest
import vnet

pytestmark = pytest.mark.virtual

SCENARIOS = {s.name: s.settings for s in vnet.parse_matrix(vnet.MATRIX.read_text(encoding="utf-8"))}
DIRECT = SCENARIOS["direct"]
COUNTING = {  # every table of a counting switch: the in-path half, the capture, the names, mint, attention
    **DIRECT,
    "DNSGATE_FILL": "inpath",
    "CAPTURE_MODE": "headers",
    "NAME_BINDING": "count",
    "MINT": "shadow",
    "LIVE_READING": "on",
}
# (old, new, whether the second apply changes every table that stands in place: only a table whose chains
# it defines otherwise, inet tvgw with the probe's, is made again)
PAIRS = {
    "nothing changed": (DIRECT, DIRECT, True),
    "rules only, and the gate taken away": (DIRECT, SCENARIOS["strict"], True),
    "the uplink: the tunnel, then direct": (SCENARIOS["vpn"], DIRECT, True),
    "the probe's chains made": (DIRECT, SCENARIOS["probe"], False),
    "the probe's chains taken away": (SCENARIOS["probe"], DIRECT, False),
    "every counting table, again": (COUNTING, COUNTING, True),
    "every counting table taken away": (COUNTING, DIRECT, True),
    "every counting table made": (DIRECT, COUNTING, True),
}
OURS = ("tvgw", "tvgw_l2", "tvgw_gate", "tvgw_ntp", "tvgw_attn", "tvgw_capture", "tvgw_names", "tvgw_mint")
LOADED = ("tvgw", "tvgw_l2", "tvgw_capture", "tvgw_names", "tvgw_mint")  # the tables load_table loads
RUNTIME = {  # (table, set): what fills it as the gateway runs
    ("tvgw_gate", "resolved4"): "tvgw-dnsgate, from the answers it captures",
    ("tvgw_gate", "seen4"): "the gate's own rule, each counted tuple",
    ("tvgw_gate", "resolved4_inpath"): "tvgw-dnsgate-inpath, before each answer leaves",
    ("tvgw_gate", "seen4_inpath"): "the second count's own rule",
    ("tvgw_gate", "inpath_live"): "tvgw-dnsgate-inpath, its port once its queue is bound",
    ("tvgw_gate", "ntp_ok4"): "the clock port's rule, each server it admitted",
    ("tvgw_ntp", "ntp4"): "the NTP count's rule, each server",
    ("tvgw_attn", "platform4"): "the in-path filler or the passive feeder, the TV's essentials",
    ("tvgw_attn", "idle4"): "tvgw-attention",
    ("tvgw_attn", "input4"): "tvgw-attention",
    ("tvgw_attn", "livetv4"): "tvgw-attention",
    ("tvgw_attn", "app4"): "tvgw-attention",
    ("tvgw_attn", "conn4"): "the attention rules, each counted tuple",
    ("tvgw_attn", "idle_seen4"): "the attention rules' samples",
    ("tvgw_attn", "input_seen4"): "the attention rules' samples",
    ("tvgw_attn", "livetv_seen4"): "the attention rules' samples",
}


def normalised(listing: str) -> dict:
    """table -> {(kind, name): its lines}, a set's elements sorted after its properties, and none for a
    RUNTIME set's."""
    out: dict = {}
    depth, table, obj = 0, None, None
    for line in vnet.uncounted(listing).splitlines():
        text = line.strip()
        if depth == 0 and (m := re.fullmatch(r"table (\w+) (\w+) \{", text)):
            table = (m[1], m[2])
            out[table] = {}
        elif depth == 1 and (m := re.fullmatch(r"(\w+) (\w+) \{", text)):
            obj = (m[1], m[2])
            out[table][obj] = []
        elif depth >= 2 and text and text != "}":  # an object's lines, not its closing brace
            out[table][obj].append(text)
        depth += text.count("{") - text.count("}")
    for (_, table_name), objects in out.items():
        for (kind, name), lines in objects.items():
            head, braced, elements = " ".join(lines).partition("elements = {")
            if kind == "set" and braced:
                kept = elements.rsplit("}", 1)[0].split(",") if (table_name, name) not in RUNTIME else []
                lines[:] = [head.strip(), *sorted(e.strip() for e in kept)]
    return out


BASE = re.compile(r'type \w+ hook (\w+)(?: device "([^"]+)")? priority ([^;]+);')


def hooks(ruleset: dict) -> list[tuple]:
    """Every base chain's hook, device and priority."""
    return [
        m.groups()
        for objects in ruleset.values()
        for (kind, _), lines in objects.items()
        if kind == "chain" and lines and (m := BASE.match(lines[0]))
    ]


def handles(net) -> dict[str, str]:
    """Each table by its handle, which the kernel numbers anew for a table made again."""
    listing = net.ns(net.gw, "nft", "-a", "list", "ruleset").stdout
    return dict(re.findall(r"^table \w+ (\w+) \{ # handle (\d+)$", listing, re.M))


@pytest.fixture(scope="module")
def gw(net):
    """The gateway namespace, holding none of tvgw's tables between the tests; the `direct` scenario put
    back when the module is done, as the other modules expect it."""
    yield net
    clear(net)
    out = net.apply(net.gw, vnet.render_conf(DIRECT))
    assert out.returncode == 0, out.stderr


def clear(net) -> None:
    tables = net.ns(net.gw, "nft", "list", "tables").stdout
    for family, name in re.findall(r"^table (\w+) (\w+)$", tables, re.M):
        if name in OURS:
            net.ns(net.gw, "nft", "delete", "table", family, name)


def apply(net, settings: dict, run_dir: Path, tag: str) -> subprocess.CompletedProcess:
    out = net.apply(net.gw, vnet.render_conf(settings), run_dir=run_dir)
    net.save(f"inplace/{tag}.log", out.stdout + out.stderr)
    assert out.returncode == 0, out.stderr
    return out


def ruleset(net) -> dict:
    return normalised(net.ns(net.gw, "nft", "-s", "list", "ruleset").stdout)


@pytest.fixture(scope="module")
def fresh(gw):
    """The ruleset of one apply of some settings on a gateway that held none of tvgw's tables, by its
    settings, each made once."""
    made: dict = {}

    def of(settings: dict) -> dict:
        key = tuple(sorted(settings.items()))
        if key not in made:
            clear(gw)
            apply(gw, settings, Path(tempfile.mkdtemp(dir=gw.sandbox)), f"fresh-{len(made)}")
            made[key] = ruleset(gw)
        return made[key]

    return of


@pytest.mark.parametrize("pair", PAIRS)
def test_one_apply_after_another_ends_as_a_fresh_load_ends(gw, fresh, pair):
    net = gw
    old, new, in_place = PAIRS[pair]
    tag = re.sub(r"\W+", "-", pair)
    want = fresh(new)
    clear(net)
    run_dir = Path(tempfile.mkdtemp(dir=net.sandbox))
    apply(net, old, run_dir, f"{tag}-old")
    before = handles(net)
    second = apply(net, new, run_dir, f"{tag}-new")
    got = ruleset(net)
    net.save(f"inplace/{tag}.nft", net.ns(net.gw, "nft", "-s", "list", "ruleset").stdout)
    assert got == want
    every = hooks(got)
    assert len(every) == len(set(every)), every
    after = handles(net)
    made_again = {t for t in LOADED if t in before and t in after and before[t] != after[t]}
    assert made_again == (set() if in_place else {"tvgw"})
    assert ("tvgw: load: in place" in second.stdout) == in_place


def test_a_connection_held_open_lives_through_three_applies_in_place(gw):
    """The probe's held stage, from the TV's side: one connection with data in flight before the applies
    and after them, with the same conntrack entry, while each apply keeps every table it loads."""
    net = gw
    clear(net)
    run_dir = Path(tempfile.mkdtemp(dir=net.sandbox))
    apply(net, DIRECT, run_dir, "held-first")
    held = subprocess.Popen(
        net.agent_argv(net.tv, "probe", "hold", vnet.WEB, "443"),
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        text=True,
        encoding="utf-8",
    )
    try:
        assert held.stdout.readline().strip() == f"connected:{vnet.GW_WLAN}"
        before, tables = entries(net), handles(net)
        for n in range(3):
            assert "tvgw: load: in place" in apply(net, DIRECT, run_dir, f"held-{n}").stdout
            time.sleep(0.3)
        assert handles(net) == tables
        held.stdin.write("after three applies\n")
        held.stdin.flush()
        ready, _, _ = select.select([held.stdout], [], [], 5)
        assert ready and held.stdout.readline().strip() == "echo:after three applies"
        assert entries(net) == before
    finally:
        held.kill()
        held.communicate(timeout=5)


def entries(net) -> set[str] | None:
    """The ids of the gateway's conntrack entries for TCP to the web server, or None without conntrack."""
    if shutil.which("conntrack") is None:
        return None
    out = net.ns(
        net.gw, "conntrack", "-L", "-p", "tcp", "-d", vnet.WEB, "--dport", "443", "-o", "id", check=False
    )
    return {word.removeprefix("id=") for word in out.stdout.split() if word.startswith("id=")}
