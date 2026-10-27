"""Rule comments are an interface (design decision 13): every counted comment in tvgw-apply must have a
line in the brief, and every line must still match a rule, or a rename silently drops its evidence."""

import re
from pathlib import Path

from tvgw import queries

APPLY = (Path(__file__).resolve().parents[2] / "deploy" / "nftables" / "tvgw-apply").read_text()
# comments appear bare in the heredoc and as \"...\" inside shell variables
COUNTED = re.compile(r'counter\b[^\n]*?comment \\?"([^"\\]+)\\?"')
# counted accepts that are not firewall evidence: the brief does not list them
ACCEPT_COUNTERS = {"TV DNS to the gateway", "small pings only", "undo PIA routed-packet tag"}


def counted_comments() -> set[str]:
    return {m.group(1) for line in APPLY.splitlines() if "counter" in line for m in COUNTED.finditer(line)}


def test_every_counted_drop_or_reject_has_a_line_in_the_brief():
    unlabelled = {
        c
        for c in counted_comments() - ACCEPT_COUNTERS
        if not any(c.startswith(p) for p, _ in queries.FW_LINES)
    }
    assert unlabelled == set()


def test_every_brief_line_still_matches_a_counted_rule():
    comments = counted_comments()
    dead = [p for p, _ in queries.FW_LINES if not any(c.startswith(p) for c in comments)]
    assert dead == []  # "unexpected port" was one: that rule only logs and has no counter


def test_the_fixture_knows_the_shape_of_the_script():
    """The regex reads both spellings; if the script's quoting changes, this says so before the two
    contract tests pass vacuously."""
    comments = counted_comments()
    assert {"TV DNS aimed elsewhere -> AdGuard", "no IPv6 from the TV", "DoT/DoQ"} <= comments  # bare
    assert {"QUIC: force TCP+TLS so SNI is visible", "undo PIA routed-packet tag"} <= comments  # escaped
    assert len(comments) >= 20
