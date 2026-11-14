"""(drills) The fail-closed drills' parts that need no root, and the written safe-state table held to them
(design decision 75). The drills themselves kill each part on a kernel in tests/virtual/
test_virtual_drills.py, which runs only in CI's virtual job; here the table in
docs/how-it-works/architecture.md must name a drill for every part and every drill must have its row,
the restart settings it quotes must be the unit files' own, and the harness helpers the drills lean on
must do what they say."""

import ast
import re
import subprocess
import sys

import pytest
from conftest import ROOT

sys.path.insert(0, str(ROOT / "tests" / "virtual"))
import vnet

from tvgw import adguardcfg, conntrack

DRILLS = ROOT / "tests" / "virtual" / "test_virtual_drills.py"
PAGE = ROOT / "docs" / "how-it-works" / "architecture.md"
UNITS = ROOT / "deploy" / "systemd"


def drill_names() -> list[str]:
    tree = ast.parse(DRILLS.read_text(encoding="utf-8"))
    return [
        n.name for n in tree.body if isinstance(n, ast.FunctionDef) and n.name.startswith("test_a_killed")
    ]


def table_rows() -> list[list[str]]:
    text = PAGE.read_text(encoding="utf-8")
    section = text.split("\n## When a part fails\n", 1)[1].split("\n## ", 1)[0]
    rows = [line for line in section.splitlines() if line.startswith("| ")]
    return [[c.strip() for c in row.strip("|").split("|")] for row in rows[1:] if not row.startswith("|---")]


def test_every_drill_has_its_row_and_every_row_its_drill():
    drills = drill_names()
    rows = table_rows()
    named = [re.search(r"`(test_[a-z_]+)`", row[-1]).group(1) for row in rows]
    assert named == drills, "the table's rows and the drills, in the order the drills run"
    assert len(drills) == 5


def unit_value(unit: str, key: str) -> str:
    for line in (UNITS / unit).read_text(encoding="utf-8").splitlines():
        if line.startswith(f"{key}="):
            return line.split("=", 1)[1].strip()
    raise AssertionError(f"{unit} has no {key}")


@pytest.mark.parametrize(
    ("part", "facts"),
    [
        ("tvgw-dnsgate-inpath", {"Restart": "on-failure", "RestartSec": "5"}),
        ("tvgw-dnsgate", {"Restart": "on-failure", "RestartSec": "5"}),
        ("tvgw-tvlive", {"Restart": "on-failure", "RestartSec": "60"}),
    ],
)
def test_the_restart_settings_the_table_quotes_are_the_units_own(part, facts):
    row = next(r for r in table_rows() if f"`{part}`" in r[0])
    for key, value in facts.items():
        assert unit_value(f"{part}.service", key) == value
        assert f"`{key}={value}`" in row[3]


def test_the_filter_s_restart_and_the_hourly_timer_are_what_the_table_says():
    filt = next(r for r in table_rows() if "AdGuard Home" in r[0])
    assert "Restart=always\nRestartSec=5\n" in adguardcfg.WORKDIR_GATEWAY
    assert "`Restart=always`, `RestartSec=5`" in filt[3]
    hourly = next(r for r in table_rows() if "`tvgw-analyze`" in r[0])
    assert (
        unit_value("tvgw-analyze.timer", "OnCalendar") == "*-*-* *:20:00" and "20 minutes past" in hourly[3]
    )


# ---- the harness's pure parts --------------------------------------------------------------------------
def test_the_drill_s_flow_log_is_one_conntrack_reads_as_the_tv_s():
    text = vnet.conntrack_lines(500, vnet.TV_IP, vnet.GW_WLAN, 1_793_000_000.0)
    flows = [conntrack.parse_flow(line) for line in text.splitlines(keepends=True)]
    assert len(flows) == 500 and all(f is not None and f.src == vnet.TV_IP for f in flows)
    assert all(f.dst.startswith("203.0.113.") and f.dport == 443 for f in flows)
    assert max(f.t_end for f in flows) <= 1_793_000_000.0


LISTING = (  # as `nft list ruleset` prints it, tabs and all
    "table inet tvgw_gate {\n"
    "\tset resolved4 {\n"
    "\t\ttype ipv4_addr\n"
    "\t\tsize 65535\n"
    "\t\tflags timeout\n"
    "\t\telements = { 198.51.100.153 expires 23h59m58s,\n"
    "\t\t\t     203.0.113.9 expires 23h00m01s }\n"
    "\t}\n"
    "\tchain gate {\n"
    '\t\tip daddr != @resolved4 counter packets 3 bytes 180 comment "TV to an address DNS never returned"\n'
    "\t}\n"
    "}\n"
)


def test_rules_only_ignores_elements_and_counters_and_sees_a_changed_rule():
    moved = LISTING.replace("packets 3 bytes 180", "packets 9 bytes 540").replace(
        "elements = { 198.51.100.153 expires 23h59m58s,\n\t\t\t     203.0.113.9 expires 23h00m01s }",
        "elements = { 198.51.100.7 expires 1h }",
    )
    assert "198.51.100.7" in moved and "203.0.113.9" not in moved and "packets 9" in moved
    assert vnet.rules_only(moved) == vnet.rules_only(LISTING)
    assert vnet.rules_only(LISTING.replace("!= @resolved4", "== @resolved4")) != vnet.rules_only(LISTING)
    port = LISTING.replace("ip daddr != @resolved4", "udp dport 53 ip daddr != @resolved4")
    assert vnet.rules_only(port.replace("dport 53", "dport 5353")) != vnet.rules_only(port)
    assert vnet.rules_only(LISTING.replace("size 65535", "size 1024")) != vnet.rules_only(LISTING)
    # how many a set holds, which nft 1.1.6 prints after the size, is no rule; the size before it is
    assert vnet.rules_only(LISTING.replace("size 65535", "size 65535\t# count 2")) == vnet.rules_only(LISTING)
    assert vnet.rules_only(LISTING.replace("size 65535", "size 1024\t# count 2")) != vnet.rules_only(LISTING)
    assert not any("198.51.100" in line for line in vnet.rules_only(LISTING))


def test_the_wrapped_analyze_script_calls_this_checkout_s_tvgw(tmp_path):
    copy = vnet.wrapped_script(
        vnet.ROOT / "deploy" / "bin" / "tvgw-analyze", tmp_path, ROOT / "src", sys.executable
    )
    text = copy.read_text(encoding="utf-8")
    assert "/usr/local/bin/tvgw " not in text and text.count(f"{tmp_path / 'tvgw'} ") >= 4
    out = subprocess.run([str(tmp_path / "tvgw"), "--version"], capture_output=True, text=True, check=True)
    assert out.stdout.startswith("tvgw ")
    plain = tmp_path / "other.sh"
    plain.write_text("#!/bin/sh\necho hi\n", encoding="utf-8")
    with pytest.raises(ValueError, match="no longer calls"):
        vnet.wrapped_script(plain, tmp_path, ROOT / "src", sys.executable)
