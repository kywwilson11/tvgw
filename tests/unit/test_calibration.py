"""(plain) The ledger's calibration of 2026-11-03 (design decision 48, its dated note): "Wi-Fi degraded"
only where the link fell short of what the TV pulled, "connections cut early" with their cause, and the
sampler's salted tag of the uplink's address (schema 10)."""

import dataclasses
import json
import os
import random
import sqlite3
import stat
from datetime import datetime

import pytest
from ledger_store import H0, HOUR, Synth

from tvgw import db, ingest, ledger
from tvgw.config import Settings

DAY = 86400
SALT = b"k" * 32
STREAM = 6e6 / 8 * 600  # bytes the TV takes in 10 minutes at 6 Mbit/s


@pytest.fixture()
def s(tmp_path):
    return Settings(state_dir=str(tmp_path), db_path=str(tmp_path / "s.db"), reports_dir=str(tmp_path / "r"))


@pytest.fixture()
def synth(s):
    x = Synth(s.db_path)
    yield x
    x.close()


# ---- Wi-Fi degraded, made relevant --------------------------------------------------------------------------
def wifi_week(synth, days=8, seed=7, rx=None):
    """`days` of 10-minute samples from H0 - DAY: a steady signal, a link rate that renegotiates between
    180 and 433 Mbit/s, the TV streaming at 6 Mbit/s all along, and `tx failed` creeping up."""
    rnd = random.Random(seed)
    tv = failed = 0
    for i in range(days * 144):
        t = H0 - DAY + i * 600
        tv += STREAM
        failed += rnd.randint(0, 5)
        rate = rx(t) if rx else rnd.uniform(180.0, 433.0)
        synth.sample(
            t, wlan_signal=-31.0, wlan_rx_mbps=rate, wlan_tx_failed=failed, tv_tx_bytes=int(tv),
            tv_rx_bytes=int(tv / 20), wan_tx_bytes=int(tv / 20),
        )  # fmt: skip


def degraded_share(conn, lg, first, last) -> float:
    clf = ledger.Classifier(conn, lg, first, last)
    hours = ledger.hours(first, last)
    return sum("Wi-Fi degraded" in clf.confounders(h) for h in hours) / len(hours)


def old_rule_share(conn, first, last) -> float:
    """The rule before 2026-11-03, on the same samples: two samples of the window under the 14-day 10th
    percentile of the link rate."""
    import statistics

    flagged = total = 0
    for h in ledger.hours(first, last):
        day = int(h // DAY) * DAY
        history = ledger.samples(conn, day - 14 * DAY, day)
        floor = statistics.quantiles([x.wlan_rx_mbps for x in history], n=10)[0]
        window = ledger.samples(conn, h - ledger.LEAD, h + HOUR)
        flagged += sum(1 for x in window if x.wlan_rx_mbps < floor) >= 2
        total += 1
    return flagged / total


def test_a_steady_week_with_a_noisy_link_rate_flags_almost_no_hour(synth, lg):
    """The synthetic week of design section 7.2: the old rule flags hours by construction, the new one
    under 1%, because 180 Mbit/s is thirty times what a 6 Mbit/s stream needs."""
    wifi_week(synth)
    first, last = H0 + DAY, H0 + 7 * DAY  # days with a whole day of history before them
    assert degraded_share(synth.conn, lg, first, last) < 0.01
    assert old_rule_share(synth.conn, first, last) > 0.05


def test_a_real_drop_during_a_stream_flags_and_the_same_drop_with_nothing_pulled_does_not(synth, lg):
    drop = (H0 + 3 * DAY + 20 * HOUR, H0 + 3 * DAY + 20 * HOUR + 1800)

    def rx(t):
        return 20.0 if drop[0] <= t < drop[1] else 300.0

    wifi_week(synth, days=5, rx=rx)
    h = H0 + 3 * DAY + 20 * HOUR
    clf = ledger.Classifier(synth.conn, lg, h, h + HOUR)
    assert "Wi-Fi degraded" in clf.confounders(h)  # 20 Mbit/s against 4 x 6 Mbit/s, in 3 samples
    synth.conn.execute("UPDATE gw_samples SET tv_tx_bytes = 0")  # the TV pulled nothing in that hour
    synth.conn.commit()
    clf = ledger.Classifier(synth.conn, lg, h, h + HOUR)
    assert "Wi-Fi degraded" not in clf.confounders(h)


def test_tx_failed_jumps_count_as_low_samples(synth, lg):
    wifi_week(synth, days=3, rx=lambda t: 300.0)
    h = H0 + DAY + 12 * HOUR
    rows = synth.conn.execute(
        "SELECT t, wlan_tx_failed FROM gw_samples WHERE t >= ? AND t < ? ORDER BY t", (h, h + HOUR)
    ).fetchall()
    for t, _ in rows[1:4]:  # three intervals of 60 more failures each
        synth.conn.execute("UPDATE gw_samples SET wlan_tx_failed = wlan_tx_failed + 60 WHERE t >= ?", (t,))
    synth.conn.commit()
    clf = ledger.Classifier(synth.conn, lg, h, h + HOUR)
    assert "Wi-Fi degraded" in clf.confounders(h)
    assert ledger.WIFI_LOW_SAMPLES == 3 and ledger.WIFI_TX_FAILED == 50


def test_a_sample_low_in_rate_and_in_tx_failed_counts_once(synth, lg):
    """Two samples whose rate fell short during a stream and whose intervals also ended in a `tx failed`
    jump are two low samples, not four: the hour is not degraded until a third sample is low."""
    h = H0 + DAY + 20 * HOUR

    def rx(t):
        return 20.0 if h <= t < h + 1200 else 300.0

    wifi_week(synth, days=3, rx=rx)
    for t in (h, h + 600):  # the two samples low in rate, each 60 failures over the one before
        synth.conn.execute("UPDATE gw_samples SET wlan_tx_failed = wlan_tx_failed + 60 WHERE t >= ?", (t,))
    synth.conn.commit()
    assert "Wi-Fi degraded" not in ledger.Classifier(synth.conn, lg, h, h + HOUR).confounders(h)
    # a third sample, low in tx failed alone, makes three
    synth.conn.execute("UPDATE gw_samples SET wlan_tx_failed = wlan_tx_failed + 60 WHERE t >= ?", (h + 1800,))
    synth.conn.commit()
    assert "Wi-Fi degraded" in ledger.Classifier(synth.conn, lg, h, h + HOUR).confounders(h)


def test_the_constants_are_the_designs():
    assert (ledger.WIFI_LOW_SAMPLES, ledger.WIFI_RX_PCTL, ledger.WIFI_HEADROOM, ledger.WIFI_TX_FAILED) == (
        3,
        0.02,
        4,
        50,
    )


# ---- the uplink's salted tag ----------------------------------------------------------------------------
IP_ADDR = (
    "3: wlan0    inet 192.0.2.48/24 brd 192.0.2.255 scope global dynamic noprefixroute wlan0\\"
    "       valid_lft 86077sec preferred_lft 86077sec\n"
)
IP_ROUTE = "default via 192.0.2.1 proto dhcp src 192.0.2.48 metric 600\n"


def fake_ip(addr=IP_ADDR, route=IP_ROUTE):
    calls = []

    def run(cmd):
        calls.append(cmd[1:])
        return addr if "addr" in cmd else route

    return {
        "run": run,
        "read": lambda p: None,
        "exists": lambda p: False,
        "which": lambda t: "/usr/sbin/ip" if t == "ip" else None,
        "listdir": lambda d: [],
        "now": H0,
    }, calls


def test_the_sampler_keeps_a_keyed_tag_of_the_uplink_and_never_the_address(s):
    kw, calls = fake_ip()
    smp = ledger.sample(s, salt=lambda: SALT, **kw)
    sid, addr, router = smp.wan_addr_tag.split(".")
    assert len(sid) == 4 and len(addr) == len(router) == 8
    assert "192.0.2" not in json.dumps(dataclasses.asdict(smp))
    assert calls == [
        ["-4", "-o", "addr", "show", "dev", "wlan0", "scope", "global"],
        ["-4", "route", "show", "default", "dev", "wlan0"],
    ]  # read-only, on WAN_IF alone
    again = ledger.sample(s, salt=lambda: SALT, **kw)
    assert again.wan_addr_tag == smp.wan_addr_tag
    moved = ledger.sample(
        s, salt=lambda: SALT, **fake_ip(addr=IP_ADDR.replace("192.0.2.48", "192.0.2.53"))[0]
    )
    assert moved.wan_addr_tag.split(".")[::2] == [sid, router] and moved.wan_addr_tag.split(".")[1] != addr


def test_no_address_no_key_or_no_route_is_said_as_none_or_a_dash(s):
    kw, calls = fake_ip(addr="")
    assert ledger.sample(s, salt=lambda: SALT, **kw).wan_addr_tag is None and len(calls) == 1
    kw, calls = fake_ip()
    assert ledger.sample(s, salt=lambda: None, **kw).wan_addr_tag is None  # never an unkeyed tag
    kw, _ = fake_ip(route="")
    assert ledger.sample(s, salt=lambda: SALT, **kw).wan_addr_tag.endswith(".-")


def test_the_salt_is_made_once_root_only_beside_the_name_keys(s):
    path = ledger.wan_salt_path(s)
    assert path == os.path.join(s.state_dir, "name-keys", "wan.salt")
    key = ledger.wan_salt(s)
    assert len(key) == 32 and ledger.wan_salt(s) == key
    assert stat.S_IMODE(os.stat(path).st_mode) == 0o600
    assert stat.S_IMODE(os.stat(os.path.dirname(path)).st_mode) == 0o700
    with open(path, "wb") as fh:
        fh.write(b"short")
    assert ledger.wan_salt(s) is None  # a damaged key is no key, not a new one


def tagged(t, addr="192.0.2.48", router="192.0.2.1", salt=SALT, **kw):
    return ledger.Sample(t, boot_id="b", wan_addr_tag=ledger.wan_addr_tag(salt, addr, router), **kw)


def test_derive_names_the_part_of_the_uplink_that_moved(s):
    a = tagged(H0)
    assert ledger.derive(a, tagged(H0 + 600), s) == []
    (c,) = ledger.derive(a, tagged(H0 + 600, addr="192.0.2.53"), s)
    assert (c.kind, c.subject, c.detail, c.t_precision) == (
        "wan_addr_change",
        "wlan0",
        {"router": "same"},
        600,
    )
    (c,) = ledger.derive(a, tagged(H0 + 600, addr="192.0.2.53", router="192.0.2.254"), s)
    assert c.detail == {"router": "changed"}
    (c,) = ledger.derive(a, tagged(H0 + 600, router="192.0.2.254"), s)
    assert c.kind == "wan_gw_change"
    assert ledger.derive(a, tagged(H0 + 600, addr="192.0.2.53", salt=b"j" * 32), s) == []  # another key
    assert ledger.derive(a, ledger.Sample(H0 + 600, boot_id="b"), s) == []  # no tag: nothing known
    assert ledger.derive(a, tagged(H0 + 600, router=None), s) == []  # the router went unread
    assert ledger.KINDS["wan_addr_change"] == ("A", 0, "uplink address changed")
    assert {"wan_addr_change", "wan_gw_change"} <= set(ledger.GROUPS["Uplink"])


def test_a_change_a_precise_writer_recorded_is_not_derived_again(s, synth):
    synth.sample(H0, wan_addr_tag=ledger.wan_addr_tag(SALT, "192.0.2.48", "192.0.2.1"))
    synth.change(H0 + 200, "wan_addr_change", "wlan0", source="dispatcher", t_precision=1.0)
    synth.sample(H0 + 600, wan_addr_tag=ledger.wan_addr_tag(SALT, "192.0.2.53", "192.0.2.1"))
    ledger.derive_all(synth.conn, s)
    rows = synth.conn.execute("SELECT source FROM changes WHERE kind = 'wan_addr_change'").fetchall()
    assert rows == [("dispatcher",)]
    synth.sample(H0 + 1200, wan_addr_tag=ledger.wan_addr_tag(SALT, "192.0.2.60", "192.0.2.1"))
    ledger.derive_all(synth.conn, s)  # nothing explains this one
    assert synth.conn.execute("SELECT COUNT(*) FROM changes WHERE source = 'sampler'").fetchone() == (1,)


# ---- connections cut early, with their cause --------------------------------------------------------------
def at(hms: str) -> float:
    """2026-11-02 at HH:MM:SS in the tests' zone (CST since 2026-11-01), read when the zone is set."""
    h, m, sec = (int(x) for x in hms.split(":"))
    return datetime(2026, 11, 2, h, m, sec).timestamp()


def evening(s, synth, tags=True):
    """The rows of 2026-11-02 from 19:40 to 20:10 on the reference, with documentation addresses: the
    uplink re-associated at 19:46:25 and took a new address, the dispatcher's DHCP line and an apply that
    changed routing followed at 19:46:31 and 19:46:36, the five TV connections the address carried were
    destroyed at 19:46:36, PIA bounced its tunnel at 19:47:35, and the sample at 19:52:10 saw two carrier
    changes (and, with the tag, the new address)."""
    lines = [
        f"{at('19:46:31')}\tdispatcher\twlan0\tdhcp4-change",
        f"{at('19:46:36')}\tapply\tnm-dispatcher\tchanged",
        f"{at('19:47:35')}\tdispatcher\ttun0\tdown",
        f"{at('19:47:36')}\tdispatcher\ttun0\tup",
        f"{at('19:47:40')}\tapply\tnm-dispatcher\tunchanged",
    ]
    with open(ledger.spool_path(s), "a", encoding="utf-8") as fh:
        fh.write("".join(line + "\n" for line in lines))
    ledger.load_spool(synth.conn, s, ingest._tail, lambda w: None)
    for t, addr, cc in (
        ("19:32:10", "192.0.2.48", 2),
        ("19:42:10", "192.0.2.48", 2),
        ("19:52:10", "192.0.2.53", 4),
    ):
        tag = ledger.wan_addr_tag(SALT, addr, "192.0.2.1") if tags else None
        synth.sample(at(t), wan_cc=cc, wan_addr_tag=tag)
    ledger.derive_all(synth.conn, s)
    for i in range(5):
        synth.conn.execute(
            "INSERT INTO flows(t_start, t_end, proto, dst, dport, sport, bytes_down, state, timeout_left)"
            " VALUES (?, ?, 'tcp', '203.0.113.9', 443, ?, 1000, 'ESTABLISHED', 431000)",
            (at("19:30:00"), at("19:46:36"), 41000 + i),
        )
    synth.conn.execute(  # a connection that ran its course: not cut
        "INSERT INTO flows(t_start, t_end, proto, dst, dport, sport, bytes_down, state)"
        " VALUES (?, ?, 'tcp', '203.0.113.9', 443, 42000, 1000, 'TIME_WAIT')",
        (at("19:41:00"), at("19:43:00")),
    )
    synth.conn.commit()


def evidence_line(synth, lg) -> str:
    sec = ledger.section(synth.conn, lg, at("19:40:00"), at("20:10:00"), at("21:00:00"))
    return next(line for line in ledger.render(sec) if line.startswith("  Evidence"))


def test_replaying_the_2026_11_02_evening_names_the_uplink_address(s, synth, lg):
    """The nearest class-A change to the cut is the apply at 19:46:36, the reaction; the cause is the
    address change the sampler's tag shows."""
    evening(s, synth)
    assert evidence_line(synth, lg).endswith("connections cut early: 5 (uplink address changed 19:46)")
    sec = ledger.section(synth.conn, lg, at("19:40:00"), at("20:10:00"), at("21:00:00"))
    assert sec["evidence"]["cut_early"] == 5 and sec["evidence"]["by_cause"] == {"uplink address changed": 5}
    uplink = next(line for line in ledger.render(sec) if line.startswith("  Uplink"))
    assert "~19:52 uplink address changed" in uplink
    clf = ledger.Classifier(synth.conn, lg, at("19:00:00"), at("20:00:00"))
    assert clf.cause(at("19:46:36")) == ("uplink address changed", at("19:52:10"))


def test_without_the_tag_the_cut_is_the_uplinks_flap_and_without_that_the_apply(s, synth, lg):
    evening(s, synth, tags=False)
    assert evidence_line(synth, lg).endswith("connections cut early: 5 (uplink flap 19:46)")
    synth.conn.execute("DELETE FROM changes WHERE kind = 'wan_flap'")
    synth.conn.commit()
    assert evidence_line(synth, lg).endswith("connections cut early: 5 (apply that changed routing 19:46)")


def test_a_cut_with_no_change_near_is_cause_unknown_and_causes_are_counted_apart(s, synth, lg):
    evening(s, synth)
    synth.conn.execute(
        "INSERT INTO flows(t_start, t_end, proto, dst, dport, sport, state, timeout_left)"
        " VALUES (?, ?, 'tcp', '203.0.113.9', 443, 43000, 'ESTABLISHED', 300)",
        (at("19:55:00"), at("20:05:00")),
    )
    synth.conn.commit()
    assert evidence_line(synth, lg).endswith(
        "connections cut early: 6 (uplink address changed 19:46 x5; cause unknown 20:05 x1)"
    )


def test_a_change_explains_a_cut_only_inside_its_reach(synth, lg):
    synth.change(H0 + 1000, "reboot", "gateway", t_precision=600.0)
    synth.change(H0 + 2000, "apply", "tvgw-doh-update", source="apply", t_precision=1.0, effect_class="A")
    clf = ledger.Classifier(synth.conn, lg, H0, H0 + HOUR)
    assert clf.cause(H0 + 400)[0] == "gateway reboot"  # inside the 10 minutes it may have happened in
    assert clf.cause(H0 + 1030)[0] == "gateway reboot"  # 30 s after it was seen
    assert clf.cause(H0 + 1031) == (ledger.UNKNOWN_CAUSE, None)  # after that, not its doing
    assert clf.cause(H0 + 1971)[0] == "apply that changed routing"  # within 30 s before a precise change
    assert clf.cause(H0 + 1969) == (ledger.UNKNOWN_CAUSE, None)


def test_among_the_changes_that_end_connections_the_nearest_wins_and_the_order_settles_a_tie(synth, lg):
    """A TV link that went down 10 s before the cut explains it before a reboot seen 20 s after it,
    though a reboot comes first in CUT_CAUSES, and before an apply at the cut itself, which ends no
    connection by itself; at the same distance CUT_CAUSES' order decides."""
    cut = H0 + 1800
    synth.change(cut - 10, "tv_link_down", "eth0", source="dispatcher", t_precision=1.0)
    synth.change(cut + 20, "reboot", "gateway", t_precision=1.0)
    synth.change(cut, "apply", "nm-dispatcher", source="apply", t_precision=1.0, effect_class="A")
    clf = ledger.Classifier(synth.conn, lg, H0, H0 + HOUR)
    assert clf.cause(cut) == ("TV link down", cut - 10)
    assert clf.cause(cut + 20) == ("gateway reboot", cut + 20)
    synth.change(cut - 10, "ct_pressure", "conntrack", t_precision=1.0)
    synth.change(cut - 10, "wan_link_down", "wlan0", source="dispatcher", t_precision=1.0)
    clf = ledger.Classifier(synth.conn, lg, H0, H0 + HOUR)
    assert ledger.CUT_CAUSES.index("wan_link_down") < ledger.CUT_CAUSES.index("tv_link_down")
    assert clf.cause(cut) == ("uplink down", cut - 10)  # three 10 s away: the order decides


def test_the_hour_is_confounded_by_the_cut_and_the_pack_keeps_the_closed_label(s, synth, lg):
    evening(s, synth)
    synth.stream(int(at("19:00:00")))
    clf = ledger.Classifier(synth.conn, lg, at("19:00:00"), at("20:00:00"))
    cls, why = clf.classify(int(at("19:00:00")))
    assert cls == "confounded" and {"uplink address changed", "connections cut early"} <= set(why)
    sec = ledger.section(synth.conn, lg, at("19:00:00"), at("20:00:00"), at("21:00:00"))
    assert ledger.pack_entry(sec)["confounded_by"]["connections cut early"] == 1


# ---- the store: schema 10 -------------------------------------------------------------------------------
def schema9_store(path: str) -> None:
    """A store as schema 9 left it: gw_samples without wan_addr_tag, one sample in it."""
    c = db.connect(path)
    c.execute("ALTER TABLE gw_samples DROP COLUMN wan_addr_tag")
    c.execute("INSERT INTO gw_samples(t, boot_id, wan_cc) VALUES (?, 'b', 2)", (H0,))
    c.execute("UPDATE meta SET value = '9' WHERE key = 'schema'")
    c.commit()
    c.close()


def test_a_schema_9_store_gains_the_tag_column_and_keeps_its_samples(tmp_path):
    path = str(tmp_path / "s.db")
    schema9_store(path)
    conn = db.connect(path)
    assert db.get_meta(conn, "schema") == "10" == str(db.SCHEMA_VERSION)
    (smp,) = ledger.samples(conn, 0, H0 + 1)
    assert (smp.boot_id, smp.wan_cc, smp.wan_addr_tag) == ("b", 2, None)
    conn.close()


def test_a_reader_of_a_schema_9_store_reads_its_samples(tmp_path, lg):
    """The brief opens the store read-only and may come before any writer migrated it."""
    path = str(tmp_path / "s.db")
    schema9_store(path)
    conn = db.connect(path, readonly=True)
    with pytest.raises(sqlite3.OperationalError):
        conn.execute("SELECT wan_addr_tag FROM gw_samples").fetchall()
    (smp,) = ledger.samples(conn, 0, H0 + 1)
    assert smp.wan_addr_tag is None
    assert ledger.section(conn, lg, H0, H0 + DAY, H0 + DAY)["samples"] == 1
    conn.close()


def test_the_plain_brief_names_the_address_change_and_the_reservation(s, synth, lg):
    """(uplink) The design's acceptance on the 2026-11-02 evening: the plain brief's Action is the
    address the router moved and the reservation that stops it, in the act tier, with no time or address."""
    from tvgw import plain

    evening(s, synth)
    sec = ledger.section(synth.conn, lg, at("19:40:00"), at("20:10:00"), at("21:00:00"))
    assert plain.action({"changes_in_effect": sec}, lg) == (
        "act",
        "Your router gave the gateway a new address, and 5 of the TV's connections were cut. To stop this,"
        " reserve this computer's address in your router's settings.",
    )
    quiet = {**sec, "groups": {g: v for g, v in sec["groups"].items() if g != "Uplink"}}
    assert plain.uplink_moved({"changes_in_effect": quiet}) is None and plain.uplink_moved({}) is None
