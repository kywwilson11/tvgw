"""(uplink quality) Is the gateway why the TV buffered? The verdict on the uplink samples (design decision 78):
the figures and the findings on fixture days, the thresholds at their edges, the plain lines, `tvgw uplink`,
verify's `uplink_quality` and the brief's section and JSON."""

import json
import re
import sqlite3

import pytest
from conftest import NOW
from ledger_store import H0, Synth
from test_verify import S, gateway, resolver

from tvgw import cli, plain, queries, uplink, verify
from tvgw.config import Settings
from tvgw.ledger import Sample

DAY = 86400
STEP = 600
BOOT = "0" * 8 + "-0000-0000-0000-" + "0" * 12
EVENING = range(19 * 6 + 1, 23 * 6 + 1)  # the intervals that end at 19:10 .. 23:00: the TV on 19:00-23:00
NIGHT = range(2 * 6 + 1, 4 * 6 + 1)  # 02:00-04:00


def per_10min(mbit: float) -> int:
    """Bytes in 10 minutes at `mbit` Mbit/s."""
    return round(mbit * 1e6 / 8 * STEP)


def tv_bytes(on=EVENING, mbit: float = 6.0):
    """The TV port's cumulative download: the interval that ends at sample i carries `mbit` while i is in
    `on`, a trickle the TV makes while off (under activity's awake floor) otherwise."""
    return lambda i: sum(per_10min(mbit) if j in on else 1000 for j in range(1, i + 1))


def stepped(base: int, at: dict[int, int]):
    """A carrier-change counter that rises by at[i] at sample i."""
    return lambda i: base + sum(n for j, n in at.items() if j <= i)


def series(synth: Synth, n: int = 145, start: float = H0, **cols) -> None:
    """`n` samples ten minutes apart from `start`; each keyword is a column, as a function of the sample's
    index or a constant. The sample at index 144 closes the day's last interval."""
    defaults = {"wan_cc": 2, "tv_cc": 1, "wlan_tx_failed": lambda i: 3 * i}
    for i in range(n):
        values = {k: (v(i) if callable(v) else v) for k, v in {**defaults, **cols}.items()}
        synth.sample(start + i * STEP, **values)


def wifi_day(synth: Synth, signal=-45.0, rx=300.0, on=EVENING, mbit=6.0, **cols) -> None:
    series(synth, wlan_signal=signal, wlan_rx_mbps=rx, tv_tx_bytes=tv_bytes(on, mbit), **cols)


@pytest.fixture()
def synth(tmp_path):
    x = Synth(str(tmp_path / "s.db"))
    yield x
    x.close()


def nothing(path: str) -> bool:
    return False


def judge(synth: Synth, **kw) -> dict:
    kw.setdefault("exists", nothing)
    return uplink.judge(synth.conn, H0, H0 + DAY, **kw)


def note(sec: dict | None) -> str | None:
    """The plain brief's `Uplink:` line for a day's section, or None."""
    found = plain._uplink_note({"uplink": sec})
    assert len(found) <= 1
    return found[0].removeprefix("  Uplink: ") if found else None


MOVE_CLOSER = (
    "If the TV buffered, move the gateway closer to the router or connect it to the router by cable."
)


# ---- the fixture days -------------------------------------------------------------------------------------
def test_a_good_wireless_evening_is_good_and_the_plain_brief_says_nothing(synth):
    wifi_day(synth)
    sec = judge(synth, uplink_if="wlan0")
    assert sec["verdict"] == uplink.GOOD and sec["findings"] == []
    assert (sec["kind"], sec["use_known"], sec["in_use_minutes"], sec["samples"]) == (
        "wireless",
        True,
        240,
        144,
    )
    assert (sec["signal_min"], sec["signal_median"], sec["weak_minutes"], sec["rx_min_mbps"]) == (
        -45,
        -45,
        0,
        300,
    )
    assert (sec["wan_drops"], sec["tv_drops"], sec["tx_failed"]) == (0, 0, 72)  # 24 intervals of +3
    assert (sec["tv_busiest_mbps"], sec["peak_mbps"], sec["peak_link_mbps"], sec["peak_share"]) == (
        6.0,
        6.0,
        300.0,
        0.02,
    )
    assert note(sec) is None and plain.action({"uplink": sec}) is None


def test_a_weak_evening_is_weak_and_the_plain_line_says_how_long_and_how_low(synth):
    weak = range(20 * 6, 22 * 6 + 1)  # 20:00 .. 22:00 read -79: twelve intervals with both readings weak
    wifi_day(synth, signal=lambda i: -79.0 if i in weak else -45.0)
    sec = judge(synth)
    assert sec["verdict"] == uplink.WEAK and sec["weak_minutes"] == 120 and sec["signal_min"] == -79
    assert note(sec) == (
        "The gateway's Wi-Fi to your router was weak for about 2 hours while the TV was on (as low as"
        f" -79 dBm). {MOVE_CLOSER}"
    )
    assert plain.action({"uplink": sec}) is None  # a note, never the Action: nothing in action.txt


def test_the_same_weak_signal_while_the_tv_is_off_is_no_finding(synth):
    wifi_day(synth, signal=lambda i: -85.0 if i in range(2 * 6, 4 * 6 + 1) else -45.0)
    sec = judge(synth)
    assert sec["verdict"] == uplink.GOOD and sec["weak_minutes"] == 0 and sec["signal_min"] == -45


def test_a_busy_evening_near_the_link_rate_is_near_its_limit(synth):
    wifi_day(synth, rx=20.0, mbit=12.0)
    sec = judge(synth)
    assert sec["verdict"] == uplink.NEAR and (sec["peak_mbps"], sec["peak_link_mbps"], sec["peak_share"]) == (
        12.0,
        20.0,
        0.6,
    )
    assert note(sec) == (
        "Over 10 minutes the TV downloaded 12 Mbit/s on average, more than half the rate the gateway's"
        " Wi-Fi to your router last reported (20 Mbit/s), so that link may have been near its limit. The"
        " signal itself was fine, so if the TV stopped or buffered then, look at the router first."
    )


def test_a_link_rate_read_once_low_beside_a_fast_one_makes_no_claim(synth):
    """The faster of an interval's readings is its link rate: a reading taken between frames at a basic
    rate must not make the claim, and is no slowest link rate either."""
    wifi_day(synth, rx=lambda i: 6.0 if i == 21 * 6 else 300.0, mbit=6.0)
    sec = judge(synth)
    assert sec["rx_min_mbps"] == 300 and sec["verdict"] == uplink.GOOD and sec["peak_share"] == 0.02


@pytest.mark.parametrize("basic", [6.0, 6.5, 12.0])
def test_rates_at_a_basic_rate_on_both_ends_make_no_claim(synth, basic):
    """The review's probe: a 3.6 Mbit/s stream between two readings of 6.5 Mbit/s, the rate of a
    management frame heard between its bursts, read as more than half the link. Rates of 12 Mbit/s or
    less are no link rate, so nothing is claimed and the plain brief says nothing."""
    wifi_day(synth, rx=basic, mbit=3.6, wlan_tx_mbps=basic)
    sec = judge(synth)
    assert sec["verdict"] == uplink.GOOD and sec["peak_share"] is None and sec["rx_min_mbps"] is None
    assert note(sec) is None


def test_the_send_rate_counts_as_the_link_when_the_receive_rate_reads_basic(synth):
    wifi_day(synth, rx=6.5, mbit=3.6, wlan_tx_mbps=144.4)
    sec = judge(synth)
    assert (sec["verdict"], sec["peak_link_mbps"], sec["peak_share"]) == (uplink.GOOD, 144.4, 0.025)


def test_a_link_that_really_runs_slowly_is_still_near_its_limit(synth):
    wifi_day(synth, rx=13.0, mbit=7.0, wlan_tx_mbps=13.0)
    assert judge(synth)["verdict"] == uplink.NEAR


def test_a_day_of_drops_counts_each_loss_once_and_only_while_the_tv_was_on(synth):
    """Two drops in the evening (two carrier changes each), one at 03:00 with the TV off, and one that
    ends the TV's traffic for half an hour, which the interval in use before it counts."""
    outage_at = 22 * 6
    on = [i for i in EVENING if not outage_at < i <= outage_at + 3]
    wifi_day(synth, on=on, wan_cc=stepped(2, {125: 2, 130: 2, 3 * 6: 2, outage_at + 1: 1, outage_at + 3: 1}))
    sec = judge(synth)
    assert sec["wan_drops"] == 3 and sec["verdict"] == uplink.DROPPED
    # the signal was fine all day, so the line points at the router, not at where the gateway stands
    assert note(sec) == (
        "The gateway's Wi-Fi to your router lost its connection 3 times while the TV was on or just after."
        " The signal itself was fine, so if the TV stopped or buffered then, look at the router first."
    )


def test_drops_with_a_weak_signal_point_at_where_the_gateway_stands(synth):
    wifi_day(synth, signal=lambda i: -75.0 if i == 125 else -45.0, wan_cc=stepped(2, {125: 2}))
    sec = judge(synth)
    assert sec["findings"] == [uplink.DROPPED] and note(sec).endswith(MOVE_CLOSER)


def test_a_flap_at_midnight_with_the_tv_off_is_no_drop_while_it_was_on(synth):
    """The review's probe: the TV off from 22:00 to 01:00, the uplink lost at 00:00. The interval before
    midnight belongs to the day before, and its label must still be read, or it counts as in use."""
    on = [*range(0, 22 * 6 + 1), *range(25 * 6 + 1, 27 * 6 + 1)]  # until 22:00, and 01:00 to 03:00 next day
    series(
        synth,
        n=28 * 6 + 1,
        wlan_signal=-45.0,
        wlan_rx_mbps=300.0,
        tv_tx_bytes=tv_bytes(on=on),
        wan_cc=stepped(2, {144: 1, 145: 1}),
    )
    nextday = uplink.judge(synth.conn, H0 + DAY, H0 + 2 * DAY, exists=nothing)
    assert (
        nextday["in_use_minutes"] == 120 and nextday["wan_drops"] == 0 and nextday["verdict"] == uplink.GOOD
    )
    assert judge(synth)["wan_drops"] == 0


def test_an_odd_count_of_changes_is_a_loss_not_yet_seen_to_return():
    assert [uplink.drops(n) for n in (0, 1, 2, 3, 4)] == [0, 1, 1, 2, 2]


def test_a_reboot_between_two_samples_is_no_drop(synth):
    """The counters start again at a reboot: the pair across it is no interval, and the next boot's
    first carrier changes are its own link coming up."""
    wifi_day(
        synth, boot_id=lambda i: BOOT if i < 125 else "1" + BOOT[1:], wan_cc=lambda i: 0 if i < 125 else 2
    )
    sec = judge(synth)
    assert sec["wan_drops"] == 0 and sec["verdict"] == uplink.GOOD


def test_a_wired_day_reads_the_cables_speed_and_names_the_cable(synth):
    series(synth, tv_tx_bytes=tv_bytes(mbit=85.0), wan_cc=stepped(1, {125: 2}), wlan_tx_failed=None)
    files = {"/sys/class/net/eth1/speed": "100\n"}
    sec = judge(
        synth,
        uplink_if="eth1",
        read=files.get,
        exists=lambda path: path == "/sys/class/net/eth1",
    )
    assert (sec["kind"], sec["wired_mbps"], sec["signal_min"], sec["rx_min_mbps"], sec["tx_failed"]) == (
        "wired",
        100,
        None,
        None,
        None,
    )
    assert sec["findings"] == [uplink.DROPPED, uplink.NEAR] and sec["peak_share"] == 0.85
    assert note(sec) == (
        "The gateway's cable to your router lost its connection once while the TV was on or just after."
        " Over 10 minutes the TV downloaded 85 Mbit/s on average, close to the speed the gateway's cable to"
        " your router runs at now (100 Mbit/s), so that link may have been near its limit. Check the"
        " gateway's cable to the router at both ends, or try another. If the TV buffered then, try another"
        " cable or another port on your router."
    )
    text = uplink.render(sec)
    assert text[0].startswith("Uplink (cable, eth1, 100 Mbit/s now; 144 samples;")
    assert not any(line.startswith(("  Signal", "  Receive")) for line in text)


def test_a_cables_speed_read_now_judges_no_older_day(synth):
    """The speed is read now: a day that ended over CABLE_FRESH ago is judged by its drops alone."""
    series(synth, tv_tx_bytes=tv_bytes(mbit=85.0))
    kw = {"uplink_if": "eth1", "read": lambda p: "100", "exists": lambda p: p == "/sys/class/net/eth1"}
    fresh = judge(synth, now=H0 + DAY + uplink.CABLE_FRESH, **kw)
    old = judge(synth, now=H0 + DAY + uplink.CABLE_FRESH + 1, **kw)
    assert (fresh["wired_mbps"], fresh["verdict"]) == (100, uplink.NEAR)
    assert (old["wired_mbps"], old["peak_share"], old["verdict"]) == (None, None, uplink.GOOD)
    assert uplink.render(old)[0].startswith("Uplink (cable, eth1; 144 samples;")


@pytest.mark.parametrize("speed", ["-1\n", "", "fast\n"])
def test_a_cable_whose_speed_cannot_be_read_is_judged_by_its_drops_alone(synth, speed):
    series(synth, tv_tx_bytes=tv_bytes(mbit=85.0))
    sec = judge(synth, uplink_if="eth1", read=lambda path: speed, exists=lambda p: p == "/sys/class/net/eth1")
    assert sec["kind"] == "wired" and sec["wired_mbps"] is None and sec["peak_share"] is None
    assert sec["verdict"] == uplink.GOOD and sec["tv_busiest_mbps"] == 85.0


def test_a_day_with_no_samples_and_a_gateway_that_keeps_none(synth):
    sec = judge(synth)
    assert sec["verdict"] == uplink.NO_SAMPLES and sec["samples"] == 0 and uplink.render(sec) == []
    off = judge(synth, ledger_on=False)
    assert off["ledger"] is False and off["verdict"] == uplink.NO_SAMPLES
    assert uplink.render(off) == ["Uplink: no samples (LEDGER=off: the gateway keeps no 10-minute samples)"]
    assert note(sec) is note(off) is None and plain._uplink_note({}) == []
    synth.sample(H0 + 3600, wlan_signal=-90.0)  # one sample is no interval
    assert judge(synth)["verdict"] == uplink.NO_SAMPLES


def test_a_store_from_before_the_sampler_has_no_samples(tmp_path):
    conn = sqlite3.connect(tmp_path / "old.db")
    assert uplink.judge(conn, H0, H0 + DAY)["verdict"] == uplink.NO_SAMPLES


def test_a_store_with_missing_columns_judges_what_it_has(tmp_path):
    """A store the reader opens before any writer added the newer columns (`ledger._columns`): no TV port
    counter, so nothing says when the TV was in use and every interval counts, and the plain line says
    'during the day', never 'while the TV was on'."""
    conn = sqlite3.connect(tmp_path / "old.db")
    conn.execute("CREATE TABLE gw_samples(t REAL PRIMARY KEY, boot_id TEXT, tv_cc INTEGER, wan_cc INTEGER)")
    conn.executemany(
        "INSERT INTO gw_samples VALUES (?, ?, 1, ?)",
        [(H0 + i * STEP, BOOT, 2 if i < 50 else 4) for i in range(145)],
    )
    sec = uplink.judge(conn, H0, H0 + DAY, uplink_if="wlan0", exists=nothing)
    assert (sec["use_known"], sec["in_use_minutes"], sec["wan_drops"], sec["kind"]) == (False, 1440, 1, None)
    assert sec["signal_min"] is None and sec["tv_busiest_mbps"] is None and sec["verdict"] == uplink.DROPPED
    assert note(sec) == (
        "The gateway's connection to your router lost its connection once during the day. If the TV stopped"
        " then, check how the gateway connects to the router."
    )
    assert "TV use not known: every interval counts" in uplink.render(sec)[0]


def test_samples_whose_sources_were_missing_are_judged_without_them(synth):
    series(synth, wlan_tx_failed=None)  # no Wi-Fi reading, no TV port counter
    sec = judge(synth)
    assert (sec["verdict"], sec["use_known"], sec["kind"], sec["tx_failed"]) == (
        uplink.GOOD,
        False,
        None,
        None,
    )
    assert uplink.render(sec) == [
        "Uplink (link not known; 144 samples; TV use not known: every interval counts): good",
        "  Link drops: uplink 0, TV port 0",
    ]


def test_the_tv_off_all_day_is_not_judged(synth):
    wifi_day(synth, signal=-85.0, rx=2.0, on=(), wan_cc=stepped(2, {50: 2}), tv_cc=stepped(1, {60: 2, 70: 2}))
    sec = judge(synth)
    assert sec["verdict"] == uplink.IDLE and sec["findings"] == [] and sec["in_use_minutes"] == 0
    assert note(sec) is None
    assert uplink.render(sec) == [
        "Uplink (Wi-Fi; 144 samples; TV in use 0.0 h by its port's traffic): TV not in use"
    ]


# ---- the thresholds at their edges ------------------------------------------------------------------------
@pytest.mark.parametrize(("signal", "weak"), [(-72.0, False), (-72.5, True)])
def test_the_weak_line_is_strictly_under_it(synth, signal, weak):
    wifi_day(synth, signal=signal)
    assert (judge(synth)["verdict"] == uplink.WEAK) is weak


@pytest.mark.parametrize(("readings", "minutes", "weak"), [(3, 20, False), (4, 30, True)])
def test_thirty_minutes_is_four_weak_readings_in_a_row(synth, readings, minutes, weak):
    """Both readings of an interval must be weak: four in a row are three intervals, 30 minutes."""
    first = 20 * 6
    wifi_day(synth, signal=lambda i: -80.0 if first <= i < first + readings else -45.0)
    sec = judge(synth)
    assert sec["weak_minutes"] == minutes and (uplink.WEAK in sec["findings"]) is weak


def test_weak_readings_apart_never_add_up(synth):
    wifi_day(synth, signal=lambda i: -80.0 if i in EVENING and i % 2 else -45.0)
    sec = judge(synth)
    assert sec["signal_min"] == -80 and sec["weak_minutes"] == 0 and sec["verdict"] == uplink.GOOD


@pytest.mark.parametrize(("mbit", "near"), [(10.0, False), (10.2, True)])
def test_near_its_limit_is_over_half_the_wifi_link_rate(synth, mbit, near):
    wifi_day(synth, rx=20.0, mbit=mbit)
    assert (judge(synth)["verdict"] == uplink.NEAR) is near


@pytest.mark.parametrize(("mbit", "near"), [(80.0, False), (80.5, True)])
def test_near_its_limit_is_over_four_fifths_of_a_cables_speed(synth, mbit, near):
    series(synth, tv_tx_bytes=tv_bytes(mbit=mbit))
    sec = judge(synth, uplink_if="eth1", read=lambda p: "100", exists=lambda p: p == "/sys/class/net/eth1")
    assert (sec["verdict"] == uplink.NEAR) is near


@pytest.mark.parametrize(("at", "findings"), [({125: 2}, []), ({125: 2, 130: 2}, [uplink.TV_CABLE])])
def test_the_tvs_cable_counts_from_two_drops_mid_use(synth, at, findings):
    wifi_day(synth, tv_cc=stepped(1, at))
    sec = judge(synth)
    assert sec["findings"] == findings and sec["tv_drops"] == len(at)
    if findings:
        assert note(sec) == (
            "The TV's cable to the gateway lost its connection 2 times while the TV was on. If nobody"
            " switched the TV off or restarted it then, check the TV's cable at both ends, or try another."
        )


def test_a_tv_that_drops_its_link_when_switched_off_and_on_is_no_finding(synth):
    """Many TVs drop the link in standby: the change at the end of use and the one at its start each sit
    beside an interval the TV was not in use, so neither counts."""
    last, first = EVENING[-1], EVENING[0]
    wifi_day(synth, tv_cc=stepped(1, {first: 1, last: 1, last + 6: 1}))
    sec = judge(synth)
    assert sec["tv_drops"] == 0 and sec["verdict"] == uplink.GOOD


def test_one_uplink_drop_is_enough():
    assert uplink.WAN_DROPS == 1


def test_the_constants_are_the_designs():
    """The starting lines of design decision 78, which its calibration on the reference may move."""
    assert (uplink.WEAK_DBM, uplink.WEAK_MINUTES, uplink.NEAR_SHARE, uplink.WIRED_SHARE) == (
        -72.0,
        30,
        0.5,
        0.8,
    )
    assert (uplink.WAN_DROPS, uplink.TV_DROPS, uplink.RECENT, uplink.RECENT_WEAK) == (1, 2, 3600, 3)
    assert (uplink.BASIC_RATE, uplink.CABLE_FRESH) == (12.0, 86400)
    assert uplink.FINDINGS == ("dropped", "weak", "near its limit", "TV cable dropped")


# ---- the plain brief ------------------------------------------------------------------------------------------
def test_every_finding_at_once_is_one_note_and_never_the_action(synth, lg):
    """Four findings make one `Uplink:` line, each piece of advice once, after the notes; the Action line
    and action.txt are what they were without them (design decisions 58 and 66)."""
    wifi_day(
        synth,
        signal=lambda i: -80.0 if i in EVENING else -45.0,
        rx=20.0,
        mbit=12.0,
        wan_cc=stepped(2, {125: 2}),
        tv_cc=stepped(1, {126: 2, 132: 2}),
    )
    sec = judge(synth)
    assert sec["findings"] == [uplink.DROPPED, uplink.WEAK, uplink.NEAR, uplink.TV_CABLE]
    assert sec["verdict"] == "dropped, weak, near its limit, TV cable dropped"
    assert note(sec) == (
        "The gateway's Wi-Fi to your router lost its connection once while the TV was on or just after."
        " The gateway's Wi-Fi to your router was weak for about 4 hours while the TV was on (as low as"
        " -80 dBm). Over 10 minutes the TV downloaded 12 Mbit/s on average, more than half the rate the"
        " gateway's Wi-Fi to your router last reported (20 Mbit/s), so that link may have been near its"
        f" limit. The TV's cable to the gateway lost its connection 2 times while the TV was on. {MOVE_CLOSER}"
        " If nobody switched the TV off or restarted it then, check the TV's cable at both ends, or try"
        " another."
    )
    o = {"uplink": sec, "red_lines": ["firewall checks failed 1 of 144", "Live Plus (ACR) is on (value on)"]}
    without = {**o, "uplink": None}
    assert plain.items(o, lg) == plain.items(without, lg) and plain.action(o, lg) == plain.action(without, lg)
    assert plain.action({"uplink": sec}, lg) is None


def test_an_interval_longer_than_ten_minutes_is_said_as_it_was(synth):
    """Two samples up to 30 minutes apart are one interval: the line gives its length."""
    for i in range(0, 145, 3):  # one sample each 30 minutes
        synth.sample(
            H0 + i * STEP, wlan_signal=-45.0, wlan_rx_mbps=20.0, tv_tx_bytes=tv_bytes(mbit=12.0)(i), wan_cc=2
        )
    sec = judge(synth)
    assert sec["peak_minutes"] == 30 and note(sec).startswith("Over 30 minutes the TV downloaded 12 Mbit/s")


def test_no_plain_line_carries_a_time_of_day_or_an_address(synth):
    wifi_day(
        synth,
        signal=-80.0,
        rx=20.0,
        mbit=12.0,
        wan_cc=stepped(2, {125: 2}),
        tv_cc=stepped(1, {126: 2, 132: 2}),
    )
    line = note(judge(synth))
    assert not re.search(r"\b\d{1,2}:\d{2}\b|\b\d{1,3}(\.\d{1,3}){3}\b", line), line
    assert line.endswith(".")


def test_the_plain_brief_carries_the_uplink_line_after_the_notes(synth, lg):
    """On the fixture store the record's other sources were never read, a doctor item: it stays the
    Action alone, and the uplink's line comes after the notes, before the footer."""
    wifi_day(synth, signal=lambda i: -79.0 if 120 <= i <= 132 else -45.0)
    o = queries.brief(synth.conn, "2026-10-26", lg, now=H0 + DAY + 3600)
    assert [t for t, _, _ in plain.items(o, lg)] == ["doctor"]
    brief = plain.plain_brief(o, profile=lg)
    assert not brief[5].endswith("need a look: tvgw brief --full.")
    assert brief[-2] == "  Uplink: " + note(o["uplink"]) and brief[-1] == plain.FOOTER


# ---- the brief's section and its JSON ------------------------------------------------------------------------
KEYS = {
    "ledger", "interface", "kind", "samples", "use_known", "in_use_minutes", "signal_min", "signal_median",
    "weak_minutes", "rx_min_mbps", "tx_failed", "wan_drops", "tv_drops", "tv_busiest_mbps", "peak_mbps",
    "peak_link_mbps", "peak_share", "peak_minutes", "wired_mbps", "findings", "verdict",
}  # fmt: skip


def test_the_brief_json_carries_the_uplink_key(synth, lg):
    wifi_day(synth)
    o = queries.brief(synth.conn, "2026-10-26", lg, now=H0 + DAY + 3600, uplink_if="wlan0")
    assert set(o["uplink"]) == KEYS and o["uplink"]["verdict"] == uplink.GOOD
    assert o["uplink"]["interface"] == "wlan0"
    json.dumps(o)  # what --json prints
    off = queries.brief(synth.conn, "2026-10-26", lg, now=H0 + DAY + 3600, ledger_on=False)
    assert off["uplink"]["ledger"] is False and off["uplink"]["verdict"] == uplink.NO_SAMPLES


def test_a_verdict_that_fails_is_a_warning_and_never_the_report(synth, lg, monkeypatch):
    def boom(*a, **kw):
        raise RuntimeError("boom")

    monkeypatch.setattr(uplink, "judge", boom)
    o = queries.brief(synth.conn, "2026-10-26", lg, now=H0 + DAY + 3600)
    assert o["uplink"] is None and "uplink: RuntimeError: boom" in o["warnings"]
    assert plain._uplink_note(o) == [] and uplink.render(o["uplink"]) == []


def test_the_full_brief_prints_the_section(capsys, synth, lg):
    wifi_day(synth, signal=lambda i: -79.0 if 120 <= i <= 132 else -45.0)
    cli.render_brief(queries.brief(synth.conn, "2026-10-26", lg, now=H0 + DAY + 3600, uplink_if="wlan0"))
    out = capsys.readouterr().out
    assert (
        "\nUplink (Wi-Fi, wlan0; 144 samples; TV in use 4.0 h by its port's traffic): weak\n"
        "  Signal: weakest -79 dBm, median -79 dBm; under -72 dBm for 120 min\n"
        "  Receive link rate: slowest 300 Mbit/s of the readings over 12; failed sends +72\n"
        "  Link drops: uplink 0, TV port 0\n"
        "  TV download: busiest interval 6.0 Mbit/s on average; most of the link used 6.0 of 300 Mbit/s (2%)\n"
    ) in out


# ---- tvgw uplink -----------------------------------------------------------------------------------------------
@pytest.fixture()
def conf(tmp_path, synth):
    """Yesterday (2026-10-25) a weak evening; today (2026-10-26, NOW is 10:00) a good morning so far."""
    series(
        synth,
        n=144 + 61,
        start=H0 - DAY,
        wlan_signal=lambda i: -79.0 if 120 <= i <= 132 else -45.0,
        wlan_rx_mbps=300.0,
        tv_tx_bytes=tv_bytes(on=[*EVENING, *range(144 + 7 * 6, 144 + 9 * 6)]),
    )
    path = tmp_path / "tvgw.conf"
    path.write_text(f'DB_PATH="{synth.path}"\n')
    return path


TABLE = """\
tvgw uplink: the gateway's link to your router (Wi-Fi, wlan0), while the TV was in use, from its 10-minute samples
day                  TV in use  signal       weak     slowest link  drops  most of link       verdict
2026-10-26 (so far)  2.0 h      -45/-45 dBm  0 min    300 Mbit/s    0/0    6.0 of 300 Mbit/s  good
2026-10-25           4.0 h      -79/-79 dBm  120 min  300 Mbit/s    0/0    6.0 of 300 Mbit/s  weak
2026-10-24           -          -            -        -             -      -                  no samples
signal: weakest/median; weak: under -72 dBm; slowest link: of the rates over 12 Mbit/s; drops: the uplink/the TV's cable; most of link: the TV's download against the link where it used the most of it
"""


def test_tvgw_uplink_prints_a_row_per_day_today_first(conf, capsys):
    assert cli.main(["--conf", str(conf), "uplink", "--days", "3"]) == 0
    assert [line.rstrip() for line in capsys.readouterr().out.splitlines()] == TABLE.splitlines()


def test_tvgw_uplink_json_is_the_same_figures(conf, capsys):
    assert cli.main(["--conf", str(conf), "uplink", "--days", "2", "--json"]) == 0
    doc = json.loads(capsys.readouterr().out)
    assert doc["ledger"] is True and [d["day"] for d in doc["days"]] == ["2026-10-26", "2026-10-25"]
    assert [d["verdict"] for d in doc["days"]] == ["good", "weak"] and set(doc["days"][0]) == KEYS | {"day"}


def test_tvgw_uplink_without_samples_says_so_plainly(tmp_path, capsys):
    path = tmp_path / "tvgw.conf"
    path.write_text(f'DB_PATH="{tmp_path / "none.db"}"\nLEDGER=off\n')
    assert cli.main(["--conf", str(path), "uplink"]) == 0
    assert (
        capsys.readouterr().out
        == "tvgw uplink: no samples (LEDGER=off: the gateway keeps no 10-minute samples)\n"
    )
    assert cli.main(["--conf", str(path), "uplink", "--json"]) == 0
    assert json.loads(capsys.readouterr().out) == {"ledger": False, "days": []}


@pytest.mark.parametrize("days", ["0", "401"])
def test_tvgw_uplink_refuses_a_days_out_of_range(conf, capsys, days):
    assert cli.main(["--conf", str(conf), "uplink", "--days", days]) == 2
    assert capsys.readouterr().err == "tvgw uplink: error: --days must be 1 to 400\n"


# ---- verify's uplink_quality ------------------------------------------------------------------------------------
def hour(signal=-45.0, wan_cc=lambda i: 2, n=7, boot=lambda i: BOOT, end=NOW):
    """`n` samples ten minutes apart, the last a second before `end`: the first lies just before the
    last hour."""
    return [
        Sample(end - (n - 1 - i) * STEP - 1, boot_id=boot(i), wan_cc=wan_cc(i),
               wlan_signal=signal(i) if callable(signal) else signal)
        for i in range(n)
    ]  # fmt: skip


@pytest.mark.parametrize(
    ("samples", "level", "detail"),
    [
        (hour(), verify.OK, "no drop and no weak signal in the last hour's 6 samples"),
        (hour(signal=None), verify.OK, "no drop in the last hour's 6 samples"),
        (hour(signal=lambda i: -80.0 if i in (4, 5) else -45.0), verify.OK, "no drop and no weak signal in the last hour's 6 samples"),
        (
            hour(signal=lambda i: -80.0 if i in (4, 5, 6) else -45.0),
            verify.WARN,
            "the Wi-Fi signal to the router read under -72 dBm in 3 of the last hour's 6 samples",
        ),
        # the weak reading before the hour does not count
        (hour(signal=lambda i: -80.0 if i in (0, 5, 6) else -45.0), verify.OK, "no drop and no weak signal in the last hour's 6 samples"),
        (hour(wan_cc=lambda i: 2 if i < 4 else 4), verify.WARN, "the uplink lost its connection once in the last hour"),
        # a drop between the sample before the hour and the hour's first counts
        (hour(wan_cc=lambda i: 2 if i < 1 else 4), verify.WARN, "the uplink lost its connection once in the last hour"),
        # a reboot is no drop
        (hour(wan_cc=lambda i: 0 if i < 3 else 2, boot=lambda i: BOOT if i < 3 else "1" + BOOT[1:]), verify.OK, "no drop and no weak signal in the last hour's 6 samples"),
        (
            hour(signal=-80.0, wan_cc=lambda i: 2 + 2 * i),
            verify.WARN,
            "the uplink lost its connection 6 times in the last hour; the Wi-Fi signal to the router read under"
            " -72 dBm in 6 of the last hour's 6 samples",
        ),
        ([], verify.OK, "no samples in the last hour"),
        (hour()[:1], verify.OK, "no samples in the last hour"),
        (None, verify.OK, "not checked: the store could not be read"),
    ],
)  # fmt: skip
def test_uplink_quality_warns_on_a_weak_or_dropping_last_hour(samples, level, detail):
    assert verify.uplink_quality_level(S, samples, NOW) == (level, detail)


def test_uplink_quality_is_not_checked_without_samples_kept():
    off = Settings(**{**S.__dict__, "ledger": "off"})
    assert verify.uplink_quality_level(off, hour(signal=-90.0), NOW) == (
        verify.OK,
        "not checked: the gateway keeps no samples (LEDGER=off)",
    )


def test_uplink_quality_is_a_warning_and_never_more_in_a_run(lg):
    weak = hour(signal=-90.0, wan_cc=lambda i: 2 + i)
    r = verify.check(S, lg, **{**gateway(), "samples": lambda: weak}, resolve=resolver())
    (c,) = [c for c in r.checks if c.name == "uplink_quality"]
    assert c.ok and c.warn and r.ok and "-90" not in c.detail  # a warning; no reading in the detail
    assert verify.FAIL_AFTER["uplink_quality"] == verify.WARN
    assert verify.held("uplink_quality", verify.FAIL, "x") == (True, "x", True)


def test_the_recent_samples_come_from_the_store_read_only(synth, tmp_path):
    for x in hour(signal=-80.0):
        synth.sample(x.t, wlan_signal=x.wlan_signal)
    synth.sample(NOW - 3 * 3600, wlan_signal=-90.0)  # long before the hour
    got = verify.recent_samples(synth.path, NOW)
    assert [x.t for x in got] == [x.t for x in hour()] and all(x.wlan_signal == -80.0 for x in got)
    assert verify.recent_samples(str(tmp_path / "none.db"), NOW) == []
    assert not (tmp_path / "none.db").exists()  # none is created
    junk = tmp_path / "junk.db"
    junk.write_bytes(b"not a database, " * 100)
    assert verify.recent_samples(str(junk), NOW) is None


def test_the_doctor_explains_the_warning_and_changes_nothing(lg):
    from test_doctor import Fake, doc, result

    fake = Fake(
        [
            result(
                verify.Check(
                    "uplink_quality", True, "the uplink lost its connection once in the last hour", warn=True
                )
            )
        ]
    )
    assert doc(fake, lg, yes=True) == 0
    assert fake.ran == [] and fake.lock_taken == 0
    assert any("changes neither its own Wi-Fi nor your router's settings" in line for line in fake.said)
    assert "  The fix: " + verify.PLAIN["uplink_quality"][2] in fake.said
