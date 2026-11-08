"""(uplink quality) Is the gateway why the TV buffered? A verdict on the uplink samples (design decision 78).

Every 10 minutes `tvgw verify --record` stores a sample of the gateway's own counters in `gw_samples`
(`ledger.sample`, with LEDGER=on): for the uplink (WAN_IF) its Wi-Fi signal, its receive and send link
rates and failed sends from `iw dev <WAN_IF> station dump`, its carrier changes and its byte counters, and
the carrier changes and byte counters of the TV's port (TV_IF). This module judges them, passively: it
sends nothing, so there is no speed test and no ping, which would contact a third party and load the line
while the TV plays.

Two consecutive samples of one boot, at most `MAX_GAP` apart, make an interval. An interval counts as the
TV in use when the TV port's counters label it streaming or awake (`activity.buckets`, read up to MAX_GAP
either side of the window, so an interval at its edge has its label), and when no label is known for it
(no TV port counter), so a gateway that cannot tell judges every interval. Over the intervals in use:

- **weak**: both readings of an interval under `WEAK_DBM`, for `WEAK_MINUTES` or more in the window;
- **near its limit**: in one interval the TV's average download (the bytes the gateway sent out of
  TV_IF) over `NEAR_SHARE` of the Wi-Fi link rate, since Wi-Fi delivers roughly half of it. The link
  rate is the fastest of the interval's two receive and two send readings over `BASIC_RATE`: a rate at
  or under it is likely that of a broadcast or management frame, the last one heard between a stream's
  bursts, and says nothing of what the link can carry. On a cable, over `WIRED_SHARE` of its speed, read
  from `/sys/class/net/<WAN_IF>/speed` and used only for a window that ended up to `CABLE_FRESH` ago;
- **dropped**: the uplink lost its link at least `WAN_DROPS` times in an interval in use or right after
  one (a long outage stops the TV's traffic, which would otherwise hide it);
- **TV cable dropped**: the TV port lost its link at least `TV_DROPS` times in an interval in use whose
  neighbours on both sides were in use too, since many TVs drop their link when switched off, and a
  restart or a software update drops it once.

A carrier change is a loss or a return of the link, so one drop is two changes; an odd count ends on a
loss not yet seen to return and is one more drop. The failed sends are reported and not judged.

The thresholds are starting values (design decision 78 says how they are calibrated). Nothing here
touches the system but `read` and `exists`, which the tests replace.
"""

from __future__ import annotations

import itertools
import os
import sqlite3
import statistics
import time
from collections.abc import Callable, Iterable
from dataclasses import dataclass

from tvgw import activity, ledger
from tvgw.ledger import Sample

WEAK_DBM = -72.0  # dBm: a signal under this is weak
WEAK_MINUTES = 30  # minutes of weak signal in use that make the window weak
NEAR_SHARE = 0.5  # of the Wi-Fi receive link rate: Wi-Fi delivers roughly half of it
WIRED_SHARE = 0.8  # of a cable's speed, which delivers close to all of it
# Mbit/s: a Wi-Fi rate reading at or under this is no link rate. 6 Mbit/s is the 5 GHz basic rate and 6.5
# HT MCS0, the rates of the broadcast and management frames that can be the last heard between bursts
BASIC_RATE = 12.0
CABLE_FRESH = 86400  # seconds: a cable's speed read now judges only a window that ended this recently
WAN_DROPS = 1  # uplink drops in use that make the window "dropped"
TV_DROPS = 2  # TV port drops in use that make it "TV cable dropped": a restart drops the link once
MAX_GAP = activity.MAX_GAP  # seconds: two samples further apart are a gap, not an interval
RECENT = 3600  # seconds: what verify's uplink_quality reads
RECENT_WEAK = 3  # samples of the last hour under WEAK_DBM that make uplink_quality warn

DROPPED, WEAK, NEAR, TV_CABLE = "dropped", "weak", "near its limit", "TV cable dropped"
FINDINGS = (DROPPED, WEAK, NEAR, TV_CABLE)  # the order the verdict and the plain lines take
GOOD, IDLE, NO_SAMPLES = "good", "TV not in use", "no samples"
WIRELESS, WIRED = "wireless", "wired"
NO_LEDGER = "no samples (LEDGER=off: the gateway keeps no 10-minute samples)"
# (hook) pass 5 H samples the SoC's temperature and throttling into gw_samples. When those columns exist,
# a throttled interval in use belongs beside the findings above, as its own word, read from the same spans


@dataclass(frozen=True)
class Span:
    """Two consecutive samples of one boot: `use` True when the TV port's counters say the TV was in use,
    False when they say it was not, None when nothing says (counted as in use)."""

    p: Sample
    c: Sample
    use: bool | None

    @property
    def counts(self) -> bool:
        return self.use is not False

    def overlap(self, a: float, b: float) -> float:
        return max(0.0, min(self.c.t, b) - max(self.p.t, a))


def rise(a: float | None, b: float | None) -> float:
    """A counter's rise between two samples; 0 when either is missing or it went down (a reset)."""
    return b - a if a is not None and b is not None and b > a else 0


def drops(changes: float) -> int:
    """Carrier changes as drops of the link: a loss and its return are two changes."""
    return int(changes + 1) // 2


def spans(samples: Iterable[Sample], labels: dict[tuple[float, float], str]) -> list[Span]:
    """The intervals between consecutive samples of one boot, at most MAX_GAP apart, each with what the
    TV port's label for it (`activity.buckets`, keyed by its two times) says of the TV's use."""
    out = []
    for p, c in itertools.pairwise(samples):
        if not 0 < c.t - p.t <= MAX_GAP or (p.boot_id and c.boot_id and p.boot_id != c.boot_id):
            continue
        label = labels.get((p.t, c.t))
        out.append(Span(p, c, None if label is None else label in activity.ON))
    return out


def link_speed(iface: str, read: Callable[[str], str | None]) -> int | None:
    """A cable's speed in Mbit/s from `/sys/class/net/<iface>/speed`, or None: a wireless or a down link
    reads as an error or -1."""
    raw = (read(f"/sys/class/net/{iface}/speed") or "").strip()
    try:
        speed = int(raw)
    except ValueError:
        return None
    return speed if speed > 0 else None


def _kind(window: list[Sample], iface: str | None, exists: Callable[[str], bool]) -> str | None:
    """wireless when a sample of the window has a Wi-Fi reading or the interface is wireless now; wired
    when the interface exists and is not; None when neither can be told (no interface given)."""
    if any(x.wlan_signal is not None or x.wlan_rx_mbps is not None for x in window):
        return WIRELESS
    if iface and exists(f"/sys/class/net/{iface}/wireless"):
        return WIRELESS
    if iface and exists(f"/sys/class/net/{iface}"):
        return WIRED
    return None


def _r(x: float | None, digits: int = 1) -> float | None:
    return None if x is None else round(x, digits)


def empty(ledger_on: bool, iface: str | None) -> dict:
    """The section of a window with nothing to judge."""
    return {
        "ledger": ledger_on,
        "interface": iface,
        "kind": None,
        "samples": 0,
        "use_known": False,
        "in_use_minutes": 0,
        "signal_min": None,
        "signal_median": None,
        "weak_minutes": 0,
        "rx_min_mbps": None,
        "tx_failed": None,
        "wan_drops": 0,
        "tv_drops": 0,
        "tv_busiest_mbps": None,
        "peak_mbps": None,
        "peak_link_mbps": None,
        "peak_share": None,
        "peak_minutes": None,
        "wired_mbps": None,
        "findings": [],
        "verdict": NO_SAMPLES,
    }


def judge(
    conn: sqlite3.Connection,
    a: float,
    b: float,
    *,
    ledger_on: bool = True,
    uplink_if: str | None = None,
    read: Callable[[str], str | None] = ledger.read_text,
    exists: Callable[[str], bool] = os.path.exists,
    now: float | None = None,
) -> dict:
    """The uplink over [a, b) while the TV was in use, as plain data: the figures, the findings in
    FINDINGS' order, and the verdict (the findings joined, GOOD, IDLE or NO_SAMPLES). `uplink_if` is
    WAN_IF, for a cable's speed and whether the link is wireless now; None judges the samples alone.
    A cable's speed is read only when the window ended at most CABLE_FRESH before `now`."""
    out = empty(ledger_on, uplink_if)
    if not ledger_on:
        return out
    try:
        rows = ledger.samples(conn, a - MAX_GAP, b + MAX_GAP)
    except sqlite3.OperationalError:  # a store from before the sampler (schema 9)
        rows = []
    window = [x for x in rows if a <= x.t < b]
    out["samples"] = len(window)
    # the labels reach past the window, so the intervals beside its edges are judged by their own label
    labels = {(iv.start, iv.end): iv.label for iv in activity.buckets(conn, a - MAX_GAP, b + MAX_GAP)}
    found = spans(rows, labels)
    if not window or not any(sp.overlap(a, b) for sp in found):
        return out
    kind = _kind(window, uplink_if, exists)
    fresh = (time.time() if now is None else now) - b <= CABLE_FRESH
    wired = link_speed(uplink_if, read) if kind == WIRED and uplink_if and fresh else None
    out.update(kind=kind, use_known=bool(labels), wired_mbps=wired)
    used = [sp for sp in found if sp.counts and sp.overlap(a, b)]
    out["in_use_minutes"] = round(sum(sp.overlap(a, b) for sp in used) / 60)
    if not used:
        out["verdict"] = IDLE
        return out
    # the readings taken while the TV was in use: the ends of the intervals in use, inside the window
    readings = list({x.t: x for sp in used for x in (sp.p, sp.c) if a <= x.t < b}.values())
    signal = [x.wlan_signal for x in readings if x.wlan_signal is not None]
    rx = [x.wlan_rx_mbps for x in readings if x.wlan_rx_mbps is not None and x.wlan_rx_mbps > BASIC_RATE]
    out["signal_min"] = _r(min(signal)) if signal else None
    out["signal_median"] = _r(statistics.median(signal)) if signal else None
    out["rx_min_mbps"] = _r(min(rx)) if rx else None

    def weak(sp: Span) -> bool:
        return all(x.wlan_signal is not None and x.wlan_signal < WEAK_DBM for x in (sp.p, sp.c))

    out["weak_minutes"] = round(sum(sp.overlap(a, b) for sp in used if weak(sp)) / 60)
    ending = [i for i, sp in enumerate(found) if a <= sp.c.t < b]  # each counter's rise counted once

    def counts(i: int) -> bool:
        return 0 <= i < len(found) and found[i].counts

    def joined(i: int, j: int) -> bool:
        return 0 <= i < len(found) and 0 <= j < len(found) and found[i].c.t == found[j].p.t

    failed = [
        rise(found[i].p.wlan_tx_failed, found[i].c.wlan_tx_failed)
        for i in ending
        if counts(i) and found[i].p.wlan_tx_failed is not None and found[i].c.wlan_tx_failed is not None
    ]
    out["tx_failed"] = int(sum(failed)) if failed else None
    wan = sum(
        rise(found[i].p.wan_cc, found[i].c.wan_cc)
        for i in ending
        if counts(i) or (joined(i - 1, i) and counts(i - 1))
    )
    tv = sum(
        rise(found[i].p.tv_cc, found[i].c.tv_cc)
        for i in ending
        if counts(i) and joined(i - 1, i) and counts(i - 1) and joined(i, i + 1) and counts(i + 1)
    )
    out["wan_drops"], out["tv_drops"] = drops(wan), drops(tv)
    busiest: float | None = None
    # (share of the link, the TV's rate, the link's rate, the interval's minutes)
    peak: tuple[float, float, float, float] | None = None
    for i in ending:
        sp = found[i]
        if not sp.counts or sp.p.tv_tx_bytes is None or sp.c.tv_tx_bytes is None:
            continue
        rate = rise(sp.p.tv_tx_bytes, sp.c.tv_tx_bytes) * 8 / (sp.c.t - sp.p.t) / 1e6  # Mbit/s
        busiest = rate if busiest is None else max(busiest, rate)
        rates = [r for x in (sp.p, sp.c) for r in (x.wlan_rx_mbps, x.wlan_tx_mbps) if r and r > BASIC_RATE]
        link = wired if kind == WIRED else max(rates) if kind == WIRELESS and rates else None
        if link and (peak is None or rate / link > peak[0]):
            peak = (rate / link, rate, float(link), (sp.c.t - sp.p.t) / 60)
    out["tv_busiest_mbps"] = _r(busiest)
    if peak is not None:
        out["peak_share"], out["peak_mbps"], out["peak_link_mbps"] = (
            round(peak[0], 3),
            _r(peak[1]),
            _r(peak[2]),
        )
        out["peak_minutes"] = round(peak[3])
    findings = []
    if out["wan_drops"] >= WAN_DROPS:
        findings.append(DROPPED)
    if out["weak_minutes"] >= WEAK_MINUTES:
        findings.append(WEAK)
    if peak is not None and peak[0] > (WIRED_SHARE if kind == WIRED else NEAR_SHARE):
        findings.append(NEAR)
    if out["tv_drops"] >= TV_DROPS:
        findings.append(TV_CABLE)
    out["findings"] = findings
    out["verdict"] = ", ".join(findings) or GOOD
    return out


def recent(samples: Iterable[Sample], now: float) -> dict:
    """What verify's uplink_quality reads of the last RECENT seconds: the samples in it, how many read
    a signal under WEAK_DBM, the uplink's drops between consecutive samples of one boot that end in it,
    and whether any is a Wi-Fi reading."""
    rows = sorted(samples, key=lambda x: x.t)
    inside = [x for x in rows if now - RECENT < x.t <= now]
    changes = sum(rise(sp.p.wan_cc, sp.c.wan_cc) for sp in spans(rows, {}) if now - RECENT < sp.c.t <= now)
    return {
        "samples": len(inside),
        "weak": sum(1 for x in inside if x.wlan_signal is not None and x.wlan_signal < WEAK_DBM),
        "drops": drops(changes),
        "wireless": any(x.wlan_signal is not None or x.wlan_rx_mbps is not None for x in inside),
    }


# ---- the engineering brief's section and `tvgw uplink` --------------------------------------------------
def mbps(x: float) -> str:
    """A rate in Mbit/s: one decimal under 10, whole above."""
    return f"{x:.1f}" if x < 10 else f"{x:.0f}"


def _kind_text(sec: dict) -> str:
    iface = sec.get("interface")
    named = f", {iface}" if iface else ""
    if sec.get("kind") == WIRELESS:
        return f"Wi-Fi{named}"
    if sec.get("kind") == WIRED:
        speed = f", {sec['wired_mbps']} Mbit/s now" if sec.get("wired_mbps") else ""
        return f"cable{named}{speed}"
    return iface or "link not known"


def _use_text(sec: dict) -> str:
    if not sec.get("use_known"):
        return "TV use not known: every interval counts"
    return f"TV in use {sec['in_use_minutes'] / 60:.1f} h by its port's traffic"


def render(sec: dict | None) -> list[str]:
    """The brief's "Uplink" section: nothing on a window without samples, one line with LEDGER=off."""
    if not sec:
        return []
    if not sec.get("ledger"):
        return [f"Uplink: {NO_LEDGER}"]
    if sec["verdict"] == NO_SAMPLES:
        return []
    out = [f"Uplink ({_kind_text(sec)}; {sec['samples']} samples; {_use_text(sec)}): {sec['verdict']}"]
    if sec["verdict"] == IDLE:
        return out
    if sec["signal_min"] is not None:
        out.append(
            f"  Signal: weakest {sec['signal_min']:g} dBm, median {sec['signal_median']:g} dBm;"
            f" under {WEAK_DBM:g} dBm for {sec['weak_minutes']} min"
        )
    if sec["rx_min_mbps"] is not None or sec["tx_failed"] is not None:
        parts = []
        if sec["rx_min_mbps"] is not None:
            parts.append(f"slowest {mbps(sec['rx_min_mbps'])} Mbit/s of the readings over {BASIC_RATE:g}")
        if sec["tx_failed"] is not None:
            parts.append(f"failed sends +{sec['tx_failed']}")
        out.append("  Receive link rate: " + "; ".join(parts))
    out.append(f"  Link drops: uplink {sec['wan_drops']}, TV port {sec['tv_drops']}")
    if sec["tv_busiest_mbps"] is not None:
        line = f"  TV download: busiest interval {mbps(sec['tv_busiest_mbps'])} Mbit/s on average"
        if sec["peak_share"] is not None:
            line += (
                f"; most of the link used {mbps(sec['peak_mbps'])} of {mbps(sec['peak_link_mbps'])} Mbit/s"
                f" ({sec['peak_share']:.0%})"
            )
        out.append(line)
    return out


TABLE_HEADERS = ("day", "TV in use", "signal", "weak", "slowest link", "drops", "most of link", "verdict")
LEGEND = (
    f"signal: weakest/median; weak: under {WEAK_DBM:g} dBm; slowest link: of the rates over {BASIC_RATE:g}"
    " Mbit/s; drops: the uplink/the TV's cable; most of link: the TV's download against the link where it"
    " used the most of it"
)


def table_row(day: str, sec: dict, today: bool = False) -> tuple[str, ...]:
    """One day of `tvgw uplink`."""
    label = day + (" (so far)" if today else "")
    if sec["verdict"] == NO_SAMPLES:
        return (label, "-", "-", "-", "-", "-", "-", NO_SAMPLES)
    used = f"{sec['in_use_minutes'] / 60:.1f} h" if sec["use_known"] else "?"
    signal = (
        f"{sec['signal_min']:.0f}/{sec['signal_median']:.0f} dBm" if sec["signal_min"] is not None else "-"
    )
    weak = f"{sec['weak_minutes']} min" if sec["signal_min"] is not None else "-"
    slowest = f"{mbps(sec['rx_min_mbps'])} Mbit/s" if sec["rx_min_mbps"] is not None else "-"
    if sec["peak_share"] is not None:
        busiest = f"{mbps(sec['peak_mbps'])} of {mbps(sec['peak_link_mbps'])} Mbit/s"
    else:
        busiest = "-"
    if sec["verdict"] == IDLE:
        signal = weak = slowest = busiest = "-"
    drops_ = "-" if sec["verdict"] == IDLE else f"{sec['wan_drops']}/{sec['tv_drops']}"
    return (label, used, signal, weak, slowest, drops_, busiest, sec["verdict"])


def title(sec: dict | None) -> str:
    """`tvgw uplink`'s first line."""
    link = f" ({_kind_text(sec)})" if sec and (sec.get("kind") or sec.get("interface")) else ""
    return (
        f"tvgw uplink: the gateway's link to your router{link}, while the TV was in use, from its"
        " 10-minute samples"
    )
