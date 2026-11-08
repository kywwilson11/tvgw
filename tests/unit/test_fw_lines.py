"""Rule comments are an interface (design decision 13): every counted comment in tvgw-apply must have a
line in the brief, and every line must still match a rule, or a rename silently drops its evidence."""

import re

from conftest import ROOT

from tvgw import queries

APPLY = (ROOT / "deploy" / "nftables" / "tvgw-apply").read_text(encoding="utf-8")
# (fin-release) the guard's table: verify stores its counters by comment beside inet tvgw's
GUARD = (ROOT / "deploy" / "nftables" / "guard.nft.template").read_text(encoding="utf-8")
# comments appear bare in the heredoc and as \"...\" inside shell variables
COUNTED = re.compile(r'counter\b[^\n]*?comment \\?"([^"\\]+)\\?"')
# counted accepts that are not firewall evidence: the brief does not list them
ACCEPT_COUNTERS = {
    "TV DNS to the gateway",
    "small pings only",
    "undo PIA routed-packet tag",
    # (capture) packets handed to the headers capture: a measure of the capture, not of the filter
    "capture: the first packets of each TV connection",
    "capture: plain HTTP after them",
    # (events) the Pi's own lookups leaving by the uplink: count-only, about the Pi, not the TV; the brief
    # carries them as a red line of their own (queries.LEAK_RULE), not as a Firewall held line
    "pi leak: DoH left by the uplink",
    "pi leak: DNS left by the uplink",
    # (ntp) the TV's NTP, which the filter accepts by design: where its clock goes, not something the
    # filter held; the brief gives it a line of its own (queries.NTP_RULE), from its servers' counts
    "NTP from the TV, by server",
    # (inpath) the DNS gate's in-path filler under comparison (design decision 64): what its queue was
    # offered and its own count of misses, shown in the gate's section (queries.INPATH_RULE)
    "in-path: UDP answers offered to the filler",
    "in-path: TCP answers offered to the filler",
    "in-path: TV to an address the filler never added",
    # (attention) the attention count (design decision 69): what a wall keyed to the TV's state would have
    # refused, counted and refused by nothing, shown in the brief's Attention section (attention.RULE_PREFIX)
    "attention: outside the essentials, screen saver on",
    "attention: outside the essentials, an input in front",
    "attention: outside the essentials, live TV in front",
}


def counted_comments(text: str = APPLY) -> set[str]:
    return {m.group(1) for line in text.splitlines() if "counter" in line for m in COUNTED.finditer(line)}


def test_every_counted_drop_or_reject_has_a_line_in_the_brief():
    unlabelled = {
        c
        for c in counted_comments() - ACCEPT_COUNTERS
        if not any(c.startswith(p) for p, _ in queries.FW_LINES)
    }
    assert unlabelled == set()


def test_every_brief_line_still_matches_a_counted_rule():
    comments = counted_comments() | counted_comments(GUARD)
    dead = [p for p, _ in queries.FW_LINES if not any(c.startswith(p) for c in comments)]
    assert dead == []  # "unexpected port" was one: that rule only logs and has no counter


def test_the_fixture_knows_the_shape_of_the_script():
    """The regex reads both spellings; if the script's quoting changes, this says so before the two
    contract tests pass vacuously."""
    comments = counted_comments()
    assert {"TV DNS aimed elsewhere -> AdGuard", "no IPv6 from the TV", "DoT/DoQ"} <= comments  # bare
    assert {"QUIC: force TCP+TLS so SNI is visible", "undo PIA routed-packet tag"} <= comments  # escaped
    assert len(comments) >= 20


def test_the_guards_final_drop_has_the_brief_line_guard():
    """(fin-release) The guard's last input counter is the only one of its counters the brief shows:
    it stays still while inet tvgw drops first, so a count is what inet tvgw let through. The prefix is
    the guard's own comment, counted in its template, and no earlier line's prefix takes it."""
    from tvgw import guard

    assert guard.FINAL_DROP in counted_comments(GUARD)
    first = next(label for prefix, label in queries.FW_LINES if guard.FINAL_DROP.startswith(prefix))
    assert first == "guard"
    # the guard's other counters stay out of Firewall held, as before
    others = counted_comments(GUARD) - {guard.FINAL_DROP}
    assert others and not any(c.startswith(p) for c in others for p, _ in queries.FW_LINES)


def test_the_guards_stored_counter_reaches_firewall_held(tmp_path, lg):
    """(fin-release) From the guard's `nft -j` listing, as verify parses it, through fw_counters to the
    brief's Firewall held line."""
    import io
    import json

    from tvgw import cli, db, guard, verify

    def listing(n: int) -> str:
        rule = {
            "comment": guard.FINAL_DROP,
            "expr": [{"counter": {"packets": n, "bytes": 60 * n}}, {"drop": None}],
        }
        return json.dumps({"nftables": [{"table": {"name": "tvgw_guard"}}, {"rule": rule}]})

    conn = db.connect(str(tmp_path / "s.db"))
    t0 = 1793020000
    for t, n in ((t0, 2), (t0 + 3600, 9)):
        rows = verify.counters_from_table(listing(n))
        assert rows == [(guard.FINAL_DROP, n, 60 * n)]
        conn.executemany(
            "INSERT INTO fw_counters(t, rule, packets, bytes) VALUES (?,?,?,?)", [(t, *r) for r in rows]
        )
    conn.commit()
    o = queries.window_report(conn, t0 - 60, t0 + 7200, lg)
    buf = io.StringIO()
    cli.render_brief(o, buf)
    assert "Firewall held: guard 7;" in buf.getvalue()
    conn.close()


def test_reading_the_brief_lists_every_label_and_no_other():
    """(fin-release) docs/reference/brief-sections.md's Label table is FW_LINES as prose: the two drifted once
    (`guard` and `second TV address` were missing), so they are compared row for row."""
    page = (ROOT / "docs" / "reference" / "brief-sections.md").read_text(encoding="utf-8")
    section = page.split("| Label | Counter comment begins |", 1)[1].split("\n\n", 1)[0]
    row = re.compile(r"^\| `([^`]+)`(?: <!-- \([a-z-]+\) -->)? \| `([^`]+)` \|$")
    rows = [m.groups() for line in section.splitlines() if (m := row.match(line))]
    assert len(rows) == len(section.strip().splitlines()) - 1  # every row but the |---|---| one parsed
    assert sorted(rows) == sorted((label, prefix) for prefix, label in queries.FW_LINES)
