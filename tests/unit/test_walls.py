"""(ports) What the firewall refused, in `tvgw refused` (design decision 71).

The firewall's half of the report reads the counters of its refusing rules (stepped from the store's
newest snapshot before the window to the live count now) and the samples its rules log to the kernel
journal. Everything that decides is pure (`walls.judge` over a `walls.Reading`), so it is tested here with
readings written by hand; the stand-ins for AdGuard Home are test_refused.py's. What the kernel's counters
and log lines really look like is the namespace tier's (tests/virtual/test_virtual_clock.py reads them back
through `walls.read_live`)."""

from __future__ import annotations

import json

import pytest
from conftest import NOW, READ_LIVE
from test_refused import WINDOW_START, Lookup, report, site  # noqa: F401  (site is a fixture)

from tvgw import db, refused, walls

QUIC = "QUIC: force TCP+TLS so SNI is visible"
STRICT_ON = "STRICT_PORTS: only web, NTP and DNS"
STRICT_OFF = "STRICT_PORTS=no: count only"
CLOSED = "clock port: closed, NTP to no server"
BLOCKS = "manual IP blocks"
LAN = "TV may not reach the home LAN"
HOST = "gw kernel"


def line(t: float, prefix: str, dst: str, proto: str = "TCP", dpt: int | None = 5222) -> str:
    """A kernel log sample as `journalctl -o short-unix` prints it."""
    port = f" SPT=40000 DPT={dpt}" if dpt is not None else ""
    return (
        f"{t:.6f} {HOST}: {prefix}: IN=eth0 OUT=wlan0 MAC=00 SRC=10.10.10.17 DST={dst} LEN=60 TOS=0x00 TTL=63"
        f" ID=1 DF PROTO={proto}{port} WINDOW=64240 SYN"
    )


APPLIED_AT = WINDOW_START - 99  # 09:48: the last apply, whose listing pair starts the counts in the report
PAIR = [(APPLIED_AT - 1, {}), (APPLIED_AT, {})]


def reading(live: dict, samples: list[str] = (), reloads=(), gate: bool = False) -> walls.Reading:
    return walls.Reading(
        live=dict(live),
        reloads=list(reloads),
        samples=walls.parse_samples(list(samples), WINDOW_START, NOW),
        gate_refuses=gate,
        counters_read=True,
        samples_read=True,
    )


@pytest.fixture
def store(tmp_path):
    conn = db.connect(str(tmp_path / "tvgw.db"))
    yield conn
    conn.close()


def snap(conn, t: float, **counts: int) -> None:
    """One counter snapshot at `t`, each keyword a rule (its comment from NAMES) and its packets."""
    names = {"quic": QUIC, "on": STRICT_ON, "off": STRICT_OFF, "closed": CLOSED, "blocks": BLOCKS, "lan": LAN}
    conn.executemany(
        "INSERT INTO fw_counters(t, rule, packets, bytes) VALUES (?,?,?,0)",
        [(t, names[k], n) for k, n in counts.items()],
    )


# ---- reading ---------------------------------------------------------------------------------------------


def test_the_journals_samples_are_read_with_their_destination_and_port_in_the_window():
    lines = [
        line(WINDOW_START + 60, "tvgw-oddport", "203.0.113.5"),
        line(WINDOW_START + 30, "tvgw-ntp", "203.0.113.9", proto="UDP", dpt=123),
        line(WINDOW_START - 60, "tvgw-oddport", "203.0.113.6"),  # before the window
        line(WINDOW_START + 90, "tvgw-lg8080", "156.147.69.32"),  # accepted, not a refusal's sample
        line(WINDOW_START + 95, "tvgw-adport", "203.0.113.7", dpt=4431),
        "not a line of the journal's",
    ]
    got = walls.parse_samples(lines, WINDOW_START, NOW)
    assert [(x.prefix, x.proto, x.dst, x.dport) for x in got] == [
        ("tvgw-ntp", "udp", "203.0.113.9", 123),
        ("tvgw-oddport", "tcp", "203.0.113.5", 5222),
        ("tvgw-adport", "tcp", "203.0.113.7", 4431),
    ]


def test_the_live_reading_asks_nft_the_apply_s_pair_and_the_journal(tmp_path):
    asked = []
    listing = json.dumps(
        {"nftables": [{"rule": {"comment": QUIC, "expr": [{"counter": {"packets": 7, "bytes": 0}}]}}]}
    )

    def run(cmd):
        asked.append(cmd)
        return (0, listing) if cmd[-1] == "tvgw" else (1, "")

    files = {walls.verify.SETTINGS_APPLIED: "DNSGATE=count\n"}
    r = READ_LIVE(
        WINDOW_START,
        NOW,
        run=run,
        read=lambda p: files.get(p, ""),
        mtime=lambda p: None,
        journal=lambda since: (
            [line(WINDOW_START + 5, "tvgw-oddport", "203.0.113.5")]
            if since == f"@{int(WINDOW_START)}"
            else []
        ),
    )
    assert asked == [
        ["nft", "-j", "-t", "list", "table", "inet", "tvgw"],
        ["nft", "-j", "-t", "list", "table", "inet", "tvgw_gate"],
    ]
    assert r.live == {QUIC: 7} and r.counters_read and r.samples_read and not r.gate_refuses
    assert [x.dst for x in r.samples] == ["203.0.113.5"] and r.reloads == []

    def broken(since):
        raise RuntimeError("journalctl rc=1: no access")

    r = READ_LIVE(
        WINDOW_START, NOW, run=lambda cmd: (1, ""), read=lambda p: "", mtime=lambda p: None, journal=broken
    )
    assert not r.counters_read and not r.samples_read
    assert walls.note(r) == [
        "The firewall's own counters could not be read (nft could not list table inet tvgw), so what it"
        " refused is not shown.",
        "The kernel journal could not be read, so the firewall's refusals are counted but their"
        " destinations are not named.",
    ]


# ---- counting the window ---------------------------------------------------------------------------------


def test_the_count_runs_from_the_newest_snapshot_before_the_window_through_a_reload_to_now(store):
    snap(store, WINDOW_START - 400, quic=100)  # the starting point: the newest at or before the window
    snap(store, WINDOW_START - 4000, quic=1)  # older: not the start
    snap(store, WINDOW_START + 200, quic=104)
    pair = [(WINDOW_START + 300, {QUIC: 106}), (WINDOW_START + 301, {QUIC: 0})]  # the apply zeroed it
    counts, start = walls.window_counts(store, WINDOW_START, NOW, reading({QUIC: 3}, reloads=pair))
    assert start == WINDOW_START - 400 and counts == {QUIC: 4 + 2 + 3}


def test_without_a_snapshot_the_count_starts_at_the_last_apply_and_without_either_there_is_none(store):
    pair = [(WINDOW_START + 100, {QUIC: 50}), (WINDOW_START + 101, {QUIC: 0})]
    counts, start = walls.window_counts(store, WINDOW_START, NOW, reading({QUIC: 5}, reloads=pair))
    assert (counts, start) == ({QUIC: 5}, WINDOW_START + 101)
    assert walls.window_counts(None, WINDOW_START, NOW, reading({QUIC: 5})) == ({}, None)
    snap(store, WINDOW_START - 7200, quic=1)  # older than an hour before the window: no starting point
    assert walls.window_counts(store, WINDOW_START, NOW, reading({QUIC: 5})) == ({}, None)


# ---- judging ---------------------------------------------------------------------------------------------


def test_a_wall_kept_on_purpose_is_counted_and_never_a_likely_cause(store):
    snap(store, WINDOW_START - 60, quic=10, lan=0)
    found, _ = walls.judge(reading({QUIC: 50, LAN: 4}), store, WINDOW_START, NOW)
    assert [(w.key, w.count, w.likely, w.on_purpose) for w in found] == [
        ("quic", 40, False, True),
        ("lan", 4, False, True),
    ]


def test_an_unusual_port_is_a_refusal_only_while_the_strict_reject_is_loaded(store):
    samples = [line(WINDOW_START + 300, "tvgw-oddport", "203.0.113.5")]
    off, _ = walls.judge(reading({STRICT_OFF: 9}, samples), store, WINDOW_START, NOW)
    assert off == []  # let through and counted: no refusal
    store.execute(
        "INSERT INTO dns(t, qname, qtype, answers, blocked) VALUES (?, 'chat.example.net', 'A', 'A:203.0.113.5', 0)",
        (WINDOW_START,),
    )
    on, _ = walls.judge(reading({STRICT_ON: 2}, samples * 2), store, WINDOW_START, NOW)
    (w,) = on
    assert w.name == "TCP port 5222 at 203.0.113.5 (chat.example.net)" and w.count == 2 and w.likely
    assert w.first_sight and w.let_through is None and not w.at_least


def test_an_unusual_port_refused_before_is_no_news_and_one_let_through_before_is_a_change(store):
    samples = [line(WINDOW_START + 300, "tvgw-oddport", "203.0.113.5")]
    snap(store, NOW - 5 * 86400, off=3)
    snap(store, NOW - 3 * 86400, on=0)  # STRICT_PORTS=yes from here
    store.execute(
        "INSERT INTO oddport(t, proto, dst, dport) VALUES (?, 'TCP', '203.0.113.5', 5222)", (NOW - 4 * 86400,)
    )
    (w,) = walls.judge(reading({STRICT_ON: 1}, samples), store, WINDOW_START, NOW)[0]
    assert w.first_sight and w.let_through == NOW - 4 * 86400 and w.likely  # it used to pass
    store.execute(
        "INSERT INTO oddport(t, proto, dst, dport) VALUES (?, 'TCP', '203.0.113.5', 5222)", (NOW - 86400,)
    )
    (w,) = walls.judge(reading({STRICT_ON: 1}, samples), store, WINDOW_START, NOW)[0]
    assert not w.first_sight and w.prior == NOW - 86400 and not w.likely


def test_the_clock_port_refused_is_always_a_likely_cause_and_names_its_server(store):
    samples = [
        line(WINDOW_START + 100 + i, "tvgw-ntp", "203.0.113.9", proto="UDP", dpt=123) for i in range(3)
    ]
    snap(store, WINDOW_START - 60, closed=0)
    found, _ = walls.judge(reading({CLOSED: 9}, samples), store, WINDOW_START, NOW)
    (w,) = found
    assert w.name == "the clock port (NTP) at 203.0.113.9" and w.needed and w.likely
    assert w.count == 3 and w.at_least  # the counter counted more than the samples: a lower bound
    found, _ = walls.judge(reading({CLOSED: 0}, samples), store, WINDOW_START, NOW)
    assert len(found) == 1  # samples, though the count was zeroed meanwhile
    # without the rule loaded, a stray sample is no refusal
    assert walls.judge(reading({QUIC: 0}, samples), store, WINDOW_START, NOW)[0] == []


def test_your_own_address_blocks_are_likely_the_first_time_only(store):
    snap(store, WINDOW_START - 60, blocks=0)
    (w,) = walls.judge(reading({BLOCKS: 2}), store, WINDOW_START, NOW)[0]
    assert w.likely and w.first_sight and w.before == 0
    snap(store, NOW - 3 * 86400, blocks=0)
    snap(store, NOW - 2 * 86400, blocks=5)
    snap(store, WINDOW_START - 30, blocks=5)
    (w,) = walls.judge(reading({BLOCKS: 7}), store, WINDOW_START, NOW)[0]
    assert not w.likely and w.before == 5


def test_the_gate_is_read_only_once_its_settings_refuse(store):
    samples = [line(WINDOW_START + 10, "tvgw-gate", "198.51.100.40", dpt=443)]
    assert walls.judge(reading({}, samples), store, WINDOW_START, NOW)[0] == []  # it only counts today
    (w,) = walls.judge(reading({}, samples, gate=True), store, WINDOW_START, NOW)[0]
    assert w.key == "gate" and w.likely and w.name == "198.51.100.40, an address no lookup returned"


# ---- in the report ---------------------------------------------------------------------------------------


def test_an_unusual_port_is_the_most_likely_cause_when_the_filter_refused_nothing(site, lg):  # noqa: F811
    site.lookups = [Lookup(WINDOW_START + 30, "api.netflix.com")]
    site.write()
    samples = [line(WINDOW_START + 300 + i, "tvgw-oddport", "203.0.113.5") for i in range(2)]
    done = report(site, lg, firewall=lambda since, until: reading({STRICT_ON: 2}, samples, reloads=PAIR))
    assert done.code == refused.LIKELY
    lines = refused.render(done.report)
    assert lines[0] == "Most likely cause: TCP port 5222 at 203.0.113.5, refused 2 times since 09:55."
    at = lines.index(
        "  Why it is first: the record holds no earlier use of TCP port 5222, and STRICT_PORTS=yes refuses it."
    )
    assert lines[at + 1 : at + 3] == [
        "  Refused by: STRICT_PORTS=yes, which refuses every port but the web, the clock and DNS",
        "  Fix: if the app needs that port, set STRICT_PORTS=no in /etc/tvgw/tvgw.conf, then run sudo tvgw-apply",
    ]
    assert lines[-1] == (
        "tvgw refused read AdGuard Home's query log and the firewall's counters from 09:50 to 10:00;"
        f" {refused.SAID}"
    )
    doc = refused.as_json(done.report)
    assert doc["firewall_read"] and doc["firewall"][0]["wall"] == "oddport" and doc["firewall"][0]["likely"]


def test_the_clock_port_ranks_with_the_names_the_tv_needs_and_walls_on_purpose_below_trackers(site, lg):  # noqa: F811
    site.lookups = [
        *(Lookup(WINDOW_START + 30 + i, "lgsmartad.com", reason=3, rule="||lgsmartad.com^") for i in range(3))
    ]
    site.write()
    samples = [line(WINDOW_START + 60, "tvgw-ntp", "203.0.113.9", proto="UDP", dpt=123)]
    done = report(
        site, lg, firewall=lambda since, until: reading({CLOSED: 1, QUIC: 40}, samples, reloads=PAIR)
    )
    lines = refused.render(done.report)
    assert lines[0] == "Most likely cause: the clock port (NTP) at 203.0.113.9, refused 1 time since 09:51."
    assert (
        "  Why it is first: the TV asked a clock server for the time, and a wrong clock breaks its secure"
        " connections."
    ) in lines
    assert "  Fix: set CLOCK_PORT=any in /etc/tvgw/tvgw.conf, then run sudo tvgw-apply" in lines
    others = lines[lines.index("Also refused, and probably not the cause:") + 1 :]
    assert others[0].startswith("  lgsmartad.com, refused 3 times")  # a tracker, before the walls on purpose
    assert others[1] == (
        "  QUIC (UDP port 443), refused 40 times since 09:48, new. Refused on purpose, unlikely to break an app:"
        " apps fall back to an ordinary secure connection, whose name the gateway can see."
    )


def test_walls_on_purpose_alone_say_nothing_likely_was_refused(site, lg):  # noqa: F811
    site.lookups = [Lookup(WINDOW_START + 30, "api.netflix.com")]
    site.write()
    done = report(site, lg, firewall=lambda since, until: reading({QUIC: 40, LAN: 3}, reloads=PAIR))
    assert done.code == refused.NOTHING_NEW
    lines = refused.render(done.report)
    assert lines[0].startswith(
        "Nothing likely to break an app was refused for the TV in the last 10 minutes: the 2"
    )
    assert "refusals below" in lines[0]
    assert (
        "  connections to your home network, dropped 3 packets since 09:48, new. Refused on purpose"
        in "\n".join(lines)
    )
    shown = refused.render(done.report, show_all=True)
    assert (
        "    Rule: the firewall's QUIC (UDP port 443). Fix: BLOCK_QUIC=no in /etc/tvgw/tvgw.conf, then sudo tvgw-apply"
        in shown
    )


def test_counts_with_no_starting_point_are_left_out_and_said(site, lg):  # noqa: F811
    site.lookups = [Lookup(WINDOW_START + 30, "api.netflix.com")]
    site.write()
    done = report(site, lg, firewall=lambda since, until: reading({QUIC: 40}))
    assert done.report.walls == [] and done.report.firewall_read
    assert any(n.startswith("The firewall's counts have no starting point here") for n in done.report.notes)


def test_with_no_firewall_on_the_computer_the_report_is_what_it_was(site, lg):  # noqa: F811
    site.lookups = [Lookup(WINDOW_START + 30, "api.netflix.com")]
    site.write()
    done = report(site, lg)  # conftest's quiet_firewall: no nft here
    assert done.report.walls == [] and not done.report.firewall_read
    assert refused.render(done.report)[-1] == (
        f"tvgw refused read AdGuard Home's query log from 09:50 to 10:00; {refused.SAID}"
    )


def test_a_clock_port_opened_again_in_the_window_keeps_what_it_refused_before(store):
    """(review) The owner opened the port a minute ago: the rule is gone from the live listing, but the
    snapshots in the window counted its refusals, which may be why an app stopped."""
    samples = [line(WINDOW_START + 100, "tvgw-ntp", "203.0.113.9", proto="UDP", dpt=123)]
    snap(store, WINDOW_START - 60, closed=0, quic=0)
    snap(store, WINDOW_START + 200, closed=2, quic=0)
    found, _ = walls.judge(reading({QUIC: 0}, samples), store, WINDOW_START, NOW)
    assert [(w.key, w.likely) for w in found] == [("clock", True)]


def test_with_adguards_log_unreadable_the_firewalls_refusals_are_shown_all_the_same(
    site,  # noqa: F811
    lg,
    tmp_path,
):
    """(review) The firewall's refusals do not depend on AdGuard Home's log, and may be the very cause:
    when the log cannot be read, the report still says what the firewall refused, and exits 2 as before."""
    from dataclasses import replace

    samples = [line(WINDOW_START + 300, "tvgw-oddport", "203.0.113.5")]
    fw = lambda since, until: reading({STRICT_ON: 1, QUIC: 9}, samples, reloads=PAIR)  # noqa: E731
    gone = replace(site.s, adguard_yaml=str(tmp_path / "missing.yaml"))
    done = refused.run(gone, lg, WINDOW_START, NOW, firewall=fw)
    assert done.code == refused.UNREAD and done.report is None
    assert done.lines[0].startswith("tvgw refused: AdGuard Home is not set up on this computer yet")
    assert done.lines[2] == "What the firewall itself refused the TV in the last 10 minutes:"
    assert done.lines[3].startswith("  TCP port 5222 at 203.0.113.5, refused 1 time since 09:55: the record")
    assert any(ln.startswith("  QUIC (UDP port 443), refused 9 times") for ln in done.lines)
    assert [w.key for w in done.walls] == ["oddport", "quic"]
    # and with no firewall on the computer, the one line as before
    assert refused.run(gone, lg, WINDOW_START, NOW, firewall=lambda s, u: None).lines == done.lines[:1]
