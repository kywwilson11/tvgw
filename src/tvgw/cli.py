"""`tvgw` command line: ingest the sources, then ask the store questions."""

from __future__ import annotations

import argparse
import contextlib
import glob
import json
import os
import random
import re
import sqlite3
import sys
import time
from collections.abc import Iterable, Sequence
from datetime import datetime, timedelta
from typing import NoReturn

from tvgw import (
    __version__,
    attention,
    budget,
    config,
    db,
    ingest,
    ledger,
    namebound,
    pcaps,
    profile,
    queries,
    uplink,
)


def hb(n: float | None) -> str:
    n = float(n or 0)
    for unit in ("B", "K", "M"):
        if n < 1024:
            return f"{n:.0f}B" if unit == "B" else f"{n:.1f}{unit}"
        n /= 1024
    return f"{n:.1f}G"


def ts(t: float | None, fmt: str = "%m-%d %H:%M") -> str:
    return datetime.fromtimestamp(t).strftime(fmt) if t else "-"


def _esc(ch: str) -> str:
    o = ord(ch)
    return f"\\x{o:02x}" if o < 0x100 else f"\\u{o:04x}" if o < 0x10000 else f"\\U{o:08x}"


def clean(v) -> str:
    """Text for the terminal. Names, URIs, user agents and the TV's device name come from the TV and
    from servers it talks to. str.isprintable() is False for controls, format characters (bidi
    overrides, zero-width spaces), surrogates, private-use and unassigned code points and every
    whitespace but the space: none of those may steer the terminal or reorder a table row."""
    return "".join(ch if ch.isprintable() else _esc(ch) for ch in str(v))


def table(rows: Iterable[Sequence], headers: Sequence[str], out=None) -> None:
    out = out or sys.stdout  # resolved at call time so pytest's capture (and redirects) see it
    rows = [[clean(c) for c in r] for r in rows]
    widths = [max([len(h), *(len(r[i]) for r in rows)]) for i, h in enumerate(headers)]
    print("  ".join(h.ljust(w) for h, w in zip(headers, widths, strict=True)), file=out)
    for r in rows:
        print("  ".join(c.ljust(w) for c, w in zip(r, widths, strict=True)), file=out)
    if not rows:
        print("(none)", file=out)


def state_word(blocked: int | None) -> str:
    return "BLOCKED" if blocked == 1 else "allowed" if blocked == 0 else "?"


def render_list_changes(lc: dict, out=None) -> None:
    """(lists) "List changes": names a blocklist's own update began or stopped blocking that the TV
    had been using. Printed only when there is one; the red line covers a name that carried content."""
    out = out or sys.stdout
    blocked, allowed = lc.get("newly_blocked") or [], lc.get("newly_allowed") or []
    if not blocked and not allowed:
        return
    print("\nList changes (a list's own update; 14-day shape before the first block):", file=out)
    rows = [
        (
            "newly blocks",
            x["name"],
            f"list {x['filter_id']}",
            ts(x["first_blocked"]),
            f"{x['answered_before']} answered before",
            f"{hb(x['down'])} down, {x['conns']} conns, median {hb(x['median_down'])}",
            "CARRIED CONTENT" if x["content"] else "",
        )
        for x in blocked
    ] + [
        (
            "newly allows",
            x["name"],
            f"list {x['filter_id']}",
            ts(x["first_answered"]),
            f"{x['answered_lookups']} answered now",
            f"last blocked {ts(x['last_blocked'])}",
            "",
        )
        for x in allowed
    ]
    table(rows, ["change", "name", "by", "since", "lookups", "shape", ""], out)


# (listguard) what a list's line does to the TV's rule, in the brief's and `tvgw lists`'s words
GUARD_EFFECT = {"exposes": "can refuse", "lifts": "lifts it", "held": "held off"}


def render_list_guard(view: dict | None, out=None) -> None:
    """(listguard) "List guard" (design decision 68): every line of a subscribed list that acts on one of the
    TV's own rules in the window, then each list update's preview, the names the TV looked up in the 14
    days before it that the update newly blocks or newly allows. Printed only when there is one."""
    out = out or sys.stdout
    findings, previews = (view or {}).get("findings") or [], (view or {}).get("previews") or []
    if findings:
        print(
            f"\nList guard (lines of the subscribed lists that act on the TV's own rules; scanned"
            f" {ts(view.get('scanned'))}):",
            file=out,
        )
        rows = [
            (
                GUARD_EFFECT.get(f["kind"], f["kind"]),
                clean(f["list"]),
                clean(f["line"]),
                clean(f["target"]) + (" (yours)" if f.get("source") == "local" else ""),
                ts(f.get("first")),
                f"gone {ts(f['gone'])}" if f.get("gone") else "",
            )
            for f in findings
        ]
        table(rows, ["effect", "list", "line", "the TV's rule", "first seen", ""], out)
    if previews:
        print(
            "\nList update preview (the names the TV looked up in the 14 days before each update,"
            " judged against the list before and after it):",
            file=out,
        )
        rows = []
        for e in previews:
            head = f"{ts(e['t'])} {clean(e['list'])} ({e['names']} names)"
            for change, key in (("newly blocks", "newly_blocked"), ("newly allows", "newly_allowed")):
                for x in e.get(key) or []:
                    mark = "CARRIED CONTENT" if x.get("content") else ""
                    rows.append((head, change, clean(x["name"]), x["lookups"], clean(x["rule"]), mark))
                more = e.get("more_" + key.split("_")[1]) or 0
                if more:
                    rows.append((head, change, f"and {more} more", "", "", ""))
            if not (e.get("newly_blocked") or e.get("newly_allowed")):
                rows.append((head, "no change", "", "", "", ""))
        table(rows, ["update", "change", "name", "lookups", "rule", ""], out)


def doh_line(hold: dict | None) -> str:
    """(listguard) The DoH list's line: refreshes `tvgw-doh-update` held back because one would drop more
    than DOH_DROP_MAX percent of the last refresh taken, or "" when none was held in the window."""
    if not hold:
        return ""
    share = 100 * hold.get("dropped", 0) / max(1, hold.get("in_force", 0))
    line = (
        f"DoH list: refreshes held back since {ts(hold.get('since'))}: the one of {ts(hold.get('t'))} would"
        f" drop {hold.get('dropped')} of the {hold.get('in_force')} entries of the last refresh taken"
        f" ({share:.0f}%, over {hold.get('max')}%); they stay blocked and its new entries are added"
    )
    if hold.get("cleared"):
        line += f"; a refresh was taken at {ts(hold['cleared'])}"
    return line


def hour_label(t: float, fmt: str = "%m-%d %H:%M") -> str:
    """(budget) A clock hour as the brief prints it. The hour the clocks go back comes twice, so each of
    the two carries its zone (`01:00 CDT`, `01:00 CST`)."""
    text = ts(t, fmt)
    if text in (ts(t - 3600, fmt), ts(t + 3600, fmt)):
        text += " " + datetime.fromtimestamp(t).astimezone().strftime("%Z")
    return text


def render_upload_budget(sec: dict | None, out=None) -> None:
    """(budget) "Upload budget": the ceiling, how it was set, and every destination-hour over it (design
    decision 66), by the net each connection sent beyond what came back, with the gross bound beside
    it, then the late hours of earlier days. Printed once the ceiling is set or the owner's; before
    that, only on a window with an hour over the floor, so a store with neither prints what it printed
    before."""
    out = out or sys.stdout
    if not sec or (sec["source"] == budget.FLOOR and not sec["events"] and not sec.get("late")):
        return
    print(
        f"\nUpload budget (count-only; nothing is capped): ceiling {hb(sec['ceiling'])} net per"
        " destination-hour outside the expected categories (net: what each connection sent beyond what"
        " came back)",
        file=out,
    )
    print(f"  {clean(_budget_how(sec))}", file=out)
    if sec["ceiling"] >= budget.ACR_HOUR_NET:
        print(
            f"  at or above {hb(budget.ACR_HOUR_NET)}, the estimated net of an hour of LG's screen"
            " recognition as IMC 2024 measured it: an hour like that would not count",
            file=out,
        )
    head = ["destination", "hour", "net", "payload<=", "conns", "ports"]

    def row(e: dict) -> tuple:
        return (
            e["key"] + ("" if e["named"] else " (no TLS name)"),
            hour_label(e["hour"]),
            hb(e["net_up"]),
            hb(e["payload_up"]),
            e["conns"],
            ",".join(map(str, e["ports"])) or "-",
        )

    if sec["events"]:
        print("  would have capped:", file=out)
        table([row(e) for e in sec["events"]], head, out)
    else:
        print("  would have capped: none", file=out)
    if sec.get("late"):
        print(
            "  late: hours of earlier days whose connections ended only after that day's brief was written,"
            " now over the ceiling (late: the net that came late):",
            file=out,
        )
        table([(*row(e), hb(e["late_net"])) for e in sec["late"]], [*head, "late"], out)


# (attention) the brief's words for each counted state and each class of name (design decision 69)
ATTENTION_STATES = (
    ("idle", "screen saver on"),
    ("input", "an input in front (HDMI or another)"),
    ("livetv", "live TV in front"),
)


def render_attention(sec: dict | None, out=None) -> None:
    """(attention) "Attention": per state the TV said it was in (screen saver, an input, live TV), how long,
    the kernel's count of new connections outside the TV's essentials, what the samples add up to, and the
    services behind them, each with its company and class (design decision 69). Nothing was refused. The
    marks say what the two weeks of this count are for: `ESSENTIAL` is an address of one of the TV's
    essentials the gateway did not know (a wall would have cut the TV off from it), `just looked up` the
    passive feeder's race, `before a change` an app starting before the TV reported it. Printed only where
    the window holds the count."""
    out = out or sys.stdout
    if not sec:
        return
    print(
        "\nAttention (count-only; nothing is refused): new connections outside the TV's essentials by the"
        " state the TV said it was in",
        file=out,
    )
    for key, words in ATTENTION_STATES:
        st = (sec.get("states") or {}).get(key) or {}
        if not st.get("seconds") and not st.get("counted") and not st.get("samples"):
            continue
        extra = f", {st['other_state']} in another state by the live record" if st.get("other_state") else ""
        counted, sampled = st.get("counted", 0), st.get("samples", 0)
        # the time in the state only where the report carries it: an interactive brief, never a saved one
        span = f"{_span(st['seconds'])}; " if "seconds" in st else ""
        print(
            f"  {words}: {span}{counted} counted, {sampled} sampled, {hb(st.get('bytes', 0))}{extra}",
            file=out,
        )
        rows = [
            (
                clean(x["key"]),
                clean(x.get("company") or ""),
                x["cls"] + (" ESSENTIAL" if x.get("essential") else ""),
                x["conns"],
                hb(x["bytes"]),
                x.get("late", 0),
                x.get("lead", 0),
            )
            for x in (st.get("services") or [])[: attention.SHOWN]
        ]
        if rows:
            head = ["service", "company", "class", "conns", "bytes", "just looked up", "before a change"]
            table(rows, head, out)
        more = len(st.get("services") or []) - attention.SHOWN
        if more > 0:
            print(f"    and {more} more (tvgw report --json lists them)", file=out)


def _span(seconds: float) -> str:
    """(attention) A stretch of time in hours and minutes."""
    minutes = round(seconds / 60)
    return f"{minutes // 60} h {minutes % 60:02d} min" if minutes >= 60 else f"{minutes} min"


def _budget_how(sec: dict) -> str:
    """(budget) Where the ceiling came from, in one line: the owner's setting; the clean history it was
    set from (twice its largest destination-hour, the floor, or the cap, and plainly so when that hour
    itself reached the cap); or the floor while it waits, and why."""
    fixed = sec.get("fixed")
    if sec["source"] == budget.OWNER:
        return "set by the owner (UPLOAD_CEILING)" + (
            f"; the gateway's own is {hb(fixed['ceiling'])}" if fixed else ""
        )
    if sec["source"] == budget.FIXED:
        span = f"{ts(fixed['since'], '%m-%d')} .. {ts(fixed['until'] - 1, '%m-%d')}"
        largest, times = fixed.get("largest") or 0, fixed.get("times", budget.BUDGET_TIMES)
        floor, cap = fixed.get("floor", budget.BUDGET_FLOOR), fixed.get("cap", budget.BUDGET_CAP)
        where = (
            f" ({fixed['key']}, {hour_label(fixed['hour'])})"
            if fixed.get("key") and fixed.get("hour")
            else ""
        )
        largest_hour = f"{times} x {hb(largest)}, the largest clean destination-hour{where}"
        if not largest:
            why = "the floor: no clean destination-hour outside the expected categories"
            why += " sent more than came back"
        elif largest >= cap:
            why = (
                f"the cap: this TV's own uploads reach the size the budget watches for, {hb(largest)} net in"
                f" its largest clean destination-hour{where}, and every hour like it is listed; look at it"
            )
        elif times * largest >= cap:
            why = f"the cap, since {largest_hour}, is more"
        elif times * largest <= floor:
            why = f"the floor, since {largest_hour}, is less"
        else:
            why = largest_hour
        flagged = fixed.get("acr_days") or 0
        left = f"; {flagged} destination-day(s) the ACR test flagged are not clean" if flagged else ""
        return f"set {ts(fixed.get('set_t'))} from the {fixed['days']} days {span}: {why}{left}"
    pending = sec.get("pending") or {}
    why = pending.get("why")
    if why == "db_days":
        return (
            f"the floor: the store keeps too few days (DB_DAYS) to hold {budget.BUDGET_DAYS} days of history"
        )
    if why == "coverage":
        return (
            f"the floor: {pending.get('uncovered', 'some')} of the {budget.BUDGET_DAYS} days before the last"
            f" hourly run have no flows, or under {budget.CAPTURE_NAMED:.0%} of their TCP 443 connections"
            f" named, so the ceiling waits for {budget.BUDGET_DAYS} covered days"
        )
    if why == "rule":
        return "the floor: the stored ceiling was set by another rule, and the hourly ingest sets it again"
    reason = {"profile": " for the new profile", "tv": " for the new TV", "owner": " again, as asked"}.get(
        why, ""
    )
    if pending.get("due"):
        return (
            f"the floor, until the hourly ingest sets the ceiling{reason} from {budget.BUDGET_DAYS} whole"
            f" days of the record, after {ts(pending['due'])}"
        )
    if reason:
        return f"the floor, until the hourly ingest sets the ceiling{reason}"
    return "the floor, until the hourly ingest has a record to set the ceiling from"


def _off_evidence(notice: dict | None) -> str:
    """(tripwire) What the While off/asleep line adds about its traffic: the TV port's counters saying the
    TV was in use then, and how many days running it has come."""
    notice = notice or {}
    said = "; the TV port's counters show it in use then" if notice.get("port") == "active" else ""
    run = notice.get("days_running") or 0
    return said + (f"; {run} days running" if run > 1 else "")


def tv_card_text(card: dict) -> str:
    """(W12) `OLED55CXPUA, webOS 5 (5.6.2), firmware 04.64.00`: the parts the readings gave, or ""."""
    parts = []
    if card.get("model"):
        parts.append(card["model"])
    if card.get("generation"):
        parts.append(f"webOS {card['generation']}" + (f" ({card['release']})" if card.get("release") else ""))
    elif card.get("release"):
        parts.append(f"webOS release {card['release']}")
    if card.get("firmware"):
        parts.append(f"firmware {card['firmware']}")
    return ", ".join(parts)


def tv_notes(o: dict) -> list[str]:
    """(W12) The plain lines about the TV that are neither red lines nor "Not checked": the gateway can no
    longer read it (the TV refused the key: `tvgw tv pair`), the standby switches that keep its network up
    while the screen is off, the agreements it asks for again, and a country its must-allow hosts miss."""
    lines = []
    pairing = o.get("pairing") or {}
    if pairing.get("state") == "refused":
        when = ts(pairing["t"], "%Y-%m-%d")
        lines.append(f"Pairing: the gateway can no longer read the TV since {when}: run {queries.PAIR_AGAIN}")
    if on := o.get("standby_features"):
        names = ", ".join(f"{x['label']} {x['value']}" for x in on)
        lines.append(f"Standby: {names}: the TV keeps its network up while the screen is off")
    for x in o.get("agreements_pending") or []:
        lines.append(f"Agreements: the TV asks you to accept {x['name']} again; it is not accepted")
    country = o.get("tv_country")
    if country:
        lines.append(
            f"TV country: the TV reports {country['reported']} ({country['code']});"
            f" {country['missing'][0]} is not on the must-allow list: run {country['allow']}, or set"
            f" TV_COUNTRY={country['code']} in /etc/tvgw/tvgw.conf and run sudo tvgw adguard apply"
        )
    return lines


def _count(n: int, word: str, plural: str | None = None) -> str:
    return f"{n} {word if n == 1 else plural or word + 's'}"


# (ports) the engineering brief's line when the clock port refused the TV's NTP (design decision 71)
CLOCK_REFUSED = (
    "Clock port closed: it refused the TV's NTP {n}; the TV's clock may drift, and sign-in and paid video"
    " can then fail (sudo tvgw refused names the servers; CLOCK_PORT=any, then sudo tvgw-apply, opens it)"
)
NTP_NOT_COUNTED = (
    "Clock servers (NTP): not counted: no snapshot of the count's table in the window"
    " (sudo tvgw-apply loads it, and says why when it cannot)"
)


def ntp_line(ntp: dict | None) -> str | None:
    """(ntp) `Clock servers (NTP): R requests to N addresses: <address> (<name>) <requests>, ...`: the
    NTP_TOP most used, each with its first name (`+K` for the K further names its answers gave, `no
    lookup` for none), `, M more` for the rest, and the requests no stored address accounts for, with
    `(its set is full)` when that is why. NTP_NOT_COUNTED when the gateway checked itself in the window
    and no snapshot listed the count's set, so a missing or refused table is not read as a TV without
    NTP. None when the count saw no NTP, and when nothing was checked at all."""
    if not ntp:
        return None
    if not ntp.get("counted", True):
        return NTP_NOT_COUNTED if ntp.get("checked") else None
    if not ntp.get("requests"):
        return None
    shown = []
    for x in ntp["servers"][: queries.NTP_TOP]:
        names, more = x.get("names") or [], x.get("names_n", len(x.get("names") or [])) - 1
        name = (names[0] + (f" +{more}" if more > 0 else "")) if names else "no lookup"
        shown.append(f"{x['dst']} ({name}) {x['requests']}")
    rest = ntp["addresses"] - len(shown)
    line = f"Clock servers (NTP): {_count(ntp['requests'], 'request')}"
    if shown:
        line += f" to {_count(ntp['addresses'], 'address', 'addresses')}: " + ", ".join(shown)
        line += f", {rest} more" if rest > 0 else ""
    unplaced = ntp.get("unplaced", 0)
    if unplaced:
        line += "; " if shown else ", "
        line += f"{unplaced} of them to addresses the count did not keep"
        line += " (its set is full)" if ntp.get("full") else ""
    return line


def health_line(h: dict | None) -> str | None:
    """(reliability) `Gateway health: SoC 61 °C at most, not slowed; mmcblk0 took 312.0M of writes; at least
    48% of memory free; no disk errors, no USB resets`, from the window's samples. None when no sample of the
    window carries a health field (samples from before schema 14, or LEDGER=off)."""
    if not h or not h.get("samples"):
        return None
    parts = []
    if h.get("temp_max") is not None:
        parts.append(f"SoC {h['temp_max']:.0f} °C at most")
    if h.get("throttle_known"):
        parts.append("slowed: " + ", ".join(h["slowed"]) if h.get("slowed") else "not slowed")
    first = ", ".join(parts)
    rest = []
    if h.get("written") is not None:
        rest.append(f"{h.get('disk') or 'the record'} took {hb(h['written'])} of writes")
    if h.get("mem_avail_min") is not None:
        rest.append(f"at least {h['mem_avail_min']:.0f}% of memory free")
    if not (first or rest):
        return None
    io, usb = h.get("io_errors") or 0, h.get("usb_resets") or 0
    rest.append(
        (f"{_count(io, 'disk error')}" if io else "no disk errors")
        + ", "
        + (f"{_count(usb, 'USB reset')}" if usb else "no USB resets")
    )
    return "Gateway health: " + "; ".join(([first] if first else []) + rest)


def quic_line(q: dict | None) -> str | None:
    """(reliability) `QUIC refused: 14 attempts to 3 names, 11 followed by TCP within 10 s; never fell back:
    moq.example (3)`: the window's refused QUIC attempts, how many the TV followed with TCP to the same
    address or registrable domain, and the names with queries.NEVER_MIN attempts or more and none followed
    (queries.quic_fallback). None when the window has no attempt, or when the QUIC rule refused nothing in
    it (`refused` 0, as with BLOCK_QUIC=no): those attempts were let through, and none needed a fallback."""
    if not q or not q.get("attempts") or q.get("refused") == 0:
        return None
    names, fell = len(q.get("names") or []), q.get("fell_back", 0)
    followed = "all" if fell == q["attempts"] else str(fell)
    line = (
        f"QUIC refused: {_count(q['attempts'], 'attempt')} to {_count(names, 'name')},"
        f" {followed} followed by TCP within {q.get('window', queries.FALLBACK_WINDOW):g} s"
    )
    never = q.get("never") or []
    if never:
        shown = ", ".join(f"{x['name']} ({x['attempts']})" for x in never[: queries.QUIC_SHOWN])
        more = len(never) - queries.QUIC_SHOWN
        line += f"; never fell back: {shown}" + (f", {more} more" if more > 0 else "")
    return line


def render_counting(rows: list[dict], out=None) -> None:
    """(counting) "Counting": every count-only mechanism, since when and when its two weeks end (design
    decision 72). Printed once one counts or has counted, so a store where nothing ever did prints what
    it printed before."""
    from tvgw import counting

    out = out or sys.stdout
    if not any(r["state"] in (counting.COUNTING, counting.REACHED, counting.STOPPED) for r in rows):
        return
    print(
        "\nCounting (each refuses nothing; whether a wall refuses after two clean weeks is the owner's"
        " decision):",
        file=out,
    )
    for r in rows:
        print(f"  {clean(counting.engineering_line(r))}", file=out)


NAMES_CLASSES = (  # (namebound) the classes as the brief's headline names them, in its order
    ("bound", "name-bound"),
    ("shared", "to an address answered for another name"),
    ("never", "to an address never answered"),
    ("noname", "without a name"),
    ("ech", "ECH"),
    ("unassessed", "not assessed (the answers do not reach back a day)"),
)
LIVE_UNASSESSED = (  # (namebound) why the live count could not assess a connection, each with its count
    ("unassessed_start", "its memory short of a day"),
    ("unassessed_loss", "after a copy lost or an answer not read"),
    ("unassessed_crowded", "an address of too many names"),
)
NAMED_LABELS = (  # (namebound) how the window's bytes up were named
    ("hello", "by their hello"),
    ("dns", "by the answers of one service"),
    ("shared", "at addresses shared by services"),
    ("unnamed", "unnamed"),
    ("unassessed", "not assessed"),
)


def _names_note(e: dict) -> str:
    """(namebound) What a sample row's flags say, for the owner explaining it by hand."""
    notes = []
    if e.get("same_site"):
        notes.append("same site")
    if e.get("blocked"):
        notes.append("name blocked")
    elif e.get("looked_up"):
        notes.append("name answered elsewhere")
    if e.get("last_bound") and e.get("first"):  # the interactive brief: when, too
        hours = max(1, round((e["first"] - e["last_bound"]) / 3600))
        notes.append(f"given this address {hours} h before")
    elif e.get("given_before") or e.get("last_bound"):  # a persisted report keeps no time
        notes.append("given this address before")
    if e.get("must_allow"):
        notes.append("must-allow")
    return ", ".join(notes)


def render_names(sec: dict | None, out=None) -> None:
    """(namebound) The brief's "Server names against the filter's answers" (design decision 70): each TLS
    connection the TV made, by whether its hello named something the filter answered with that address in
    the day before; the samples of the two classes that matter; how the window's bytes up were named; the
    DoH-shaped connections; and, from stage 2, the live count. Nothing at all for a window with none of
    them."""
    out = out or sys.stdout
    if not sec:
        return
    c = sec.get("counts") or {}
    named = sec.get("named") or {}
    up = named.get("bytes_up") or {}
    live = sec.get("live")
    # a window the answers cannot assess at all (a gateway's first day) has nothing to say yet
    assessed = sum(n for k, n in c.items() if k != "unassessed") + sum(
        n for k, n in up.items() if k != "unassessed"
    )
    if not (assessed or sec.get("doh_shaped") or live):
        return
    hours = round(sec.get("window", 86400) / 3600)
    total = sum(c.values())
    parts = [f"{c.get(k, 0)} {label}" for k, label in NAMES_CLASSES if c.get(k) or k == "bound"]
    print(
        f"\nServer names against the filter's answers (count-only; each connection against the {hours} h"
        f" before it): {total} TLS connections: " + ", ".join(parts),
        file=out,
    )
    if sec.get("shared"):
        print(
            "  to an address answered for another name (a server shared by many names, or a name the filter"
            " never answered with it):",
            file=out,
        )
        table(
            [
                (
                    e["name"],
                    e["dst"],
                    e["dport"],
                    e["n"],
                    ", ".join(e.get("answered_for") or [])
                    + (f" +{e['answered_n'] - 3}" if e.get("answered_n", 0) > 3 else ""),
                    ts(e.get("first")),
                    _names_note(e),
                )
                for e in sec["shared"]
            ],
            ["name", "address", "port", "conns", "answered for", "first", "note"],
            out,
        )
    if sec.get("never"):
        print("  to an address never answered (what the DNS gate counts):", file=out)
        table(
            [
                (e["name"], e["dst"], e["dport"], e["n"], ts(e.get("first")), _names_note(e))
                for e in sec["never"]
            ],
            ["name", "address", "port", "conns", "first", "note"],
            out,
        )
    total_up = sum(up.values())
    if total_up:
        shares = ", ".join(f"{label} {100 * up.get(k, 0) / total_up:.1f}%" for k, label in NAMED_LABELS)
        print(f"  bytes up {hb(total_up)}, named {shares}", file=out)
    if sec.get("doh_shaped"):
        print(
            f"  DoH-shaped (TCP 443, over {namebound.DOH_SECONDS // 60} min, over {namebound.DOH_PACKETS}"
            f" packets each way of under {namebound.DOH_BYTES} B; the DoH wall's list does not hold these"
            " addresses):",
            file=out,
        )
        table(
            [
                (
                    (e["name"] or "(no name)") + (" (by its answers)" if e.get("by_dns") else ""),
                    e["dst"],
                    e["minutes"],
                    f"{e['pkts_up']}/{e['pkts_down']}",
                    f"{e['per_packet_up']}/{e['per_packet_down']} B",
                    "name blocked" if e.get("blocked") else "",
                )
                for e in sec["doh_shaped"]
            ],
            ["name", "address", "min", "packets up/down", "per packet", "note"],
            out,
        )
    if live:
        render_names_live(live, out)


def render_names_live(live: dict, out=None) -> None:
    """(namebound) Stage 2's line (design decision 70): the same classes, counted as the connections
    happened from the copies the firewall made, with the answers read and the copies lost or unread."""
    out = out or sys.stdout
    total = sum(live.get(k, 0) for k, _label in NAMES_CLASSES)
    parts = [
        f"{live.get(k, 0)} {label}" for k, label in NAMES_CLASSES[:-1] if live.get(k) or k == "bound"
    ]  # not assessed: the store's reason is not the live count's, so each of its own is given
    if live.get("unassessed"):
        why = ", ".join(f"{live.get(k, 0)} {label}" for k, label in LIVE_UNASSESSED if live.get(k))
        parts.append(f"{live['unassessed']} not assessed" + (f" ({why})" if why else ""))
    print(
        f"  live count (stage 2, from the firewall's copies as they happened): {total} TLS connections: "
        + ", ".join(parts)
        + f"; {live.get('answers', 0)} DNS answers read, {live.get('answers_unread', 0)} not read,"
        f" copies lost {live.get('lost', 0)} times, {live.get('unparsed', 0)} other copies not read",
        file=out,
    )


def render_brief(o: dict, out=None) -> None:
    out = out or sys.stdout
    d, f = o["dns"], o["flows"]
    title = clean(o.get("label") or o["day"])
    print(
        f"=== {title}: {d['lookups']} lookups ({d['blocked']} blocked, {d['names']} names), "
        f"{f['conns']} connections, up {hb(f['bytes_up'])} down {hb(f['bytes_down'])}",
        file=out,
    )
    cov = o.get("coverage")
    if cov:
        parts = [f"{src} {v['rows']}" for src, v in cov["sources"].items()]
        if cov.get("adguard_version"):
            parts.append(f"AdGuard {cov['adguard_version']}")
        if (cov.get("vpn") or {}).get("pia"):  # (events) PIA's own state at the last verify run
            parts.append(f"PIA {clean(cov['vpn']['pia'])}")
        if cov.get("resolver"):  # (resolver) who answers the TV's lookups, by the settings
            parts.append(f"lookups answered by {clean(cov['resolver'])}")
        print(f"Coverage: {', '.join(parts)}; last ingest {ts(cov['last_run'], '%m-%d %H:%M')}", file=out)
        if cov["not_assessed"]:
            print(f"NOT ASSESSED (source not read recently): {', '.join(cov['not_assessed'])}", file=out)
        for w in cov["warnings"]:
            print(f"ingest warning: {clean(w)}", file=out)
    for w in o.get("warnings") or []:  # (ledger) a part of the report that could not be computed
        print(f"report warning: {clean(w)}", file=out)
    for line in o.get("red_lines", []):
        print(f"RED LINE: {clean(line)}", file=out)
    for line in o.get("not_checked") or []:  # (depth) what no reading vouches for, and how to answer it
        print(f"Not checked: {clean(line)}", file=out)
    for line in tv_notes(
        o
    ):  # (W12) the pairing, the standby switches, the agreements asked again, the country
        print(clean(line), file=out)
    fw = o.get("firewall")
    if fw is not None:
        hits = {}
        for item in fw.get("activity", []):
            for prefix, label in queries.FW_LINES:
                if item["rule"].startswith(prefix):
                    hits[label] = hits.get(label, 0) + item["packets"]
                    break
        labels = list(dict.fromkeys(label for _, label in queries.FW_LINES if label in hits))
        shown = ", ".join(f"{label} {hits[label]}" for label in labels)
        checks = f"{fw['runs']} checks, {fw['failed']} failed" if fw["runs"] else "no checks recorded"
        print(f"Firewall held: {shown or 'no counter snapshots yet'}; {checks}", file=out)
    line = doh_line(o.get("doh_hold"))  # (listguard) a DoH list refresh held back
    if line:
        print(clean(line), file=out)
    clock = o.get("clock")
    if clock and clock.get("hosts"):
        first = ts(clock["first"], "%H:%M") if clock["first"] else "-"
        print(
            f"Clock hosts: {clock['lookups']} lookups ({clock['blocked']} blocked), first at {first}",
            file=out,
        )
    line = ntp_line(o.get("ntp"))  # (ntp) the clock servers the TV sent NTP to; nothing when none
    if line:
        print(clean(line), file=out)
    line = health_line(o.get("gateway_health"))  # (reliability) the gateway's own hardware
    if line:
        print(clean(line), file=out)
    line = quic_line(o.get("quic_fallback"))  # (reliability) whether refused QUIC attempts fall back
    if line:
        print(clean(line), file=out)
    refused = queries.clock_port_refusals(o)  # (ports) a closed clock port is no success: say so
    if refused:
        print(CLOCK_REFUSED.format(n=_count(refused, "time")), file=out)
    sb = o.get("standby")
    if sb and sb["off_hours"]:
        # (activity) a session the hourly readings missed, left out once the TV port's counters are calibrated
        missed = sb.get("streaming_left_out_hours")
        # (tripwire) the names behind the counts, when the TV went online while it said it was off
        names = ", ".join(
            f"{clean(x['name'])} x{x['lookups'] + x['conns']}" for x in o.get("standby_names") or []
        )
        print(
            f"While off/asleep ({sb['off_hours']:g} h): {sb['lookups']} lookups, {sb['conns']} connections, "
            f"up {hb(sb['bytes_up'])}"
            + (f"; names: {names}" if names else "")
            + _off_evidence(o.get("standby_notice"))
            + (f"; {missed:g} h of streaming between readings left out" if missed else ""),
            file=out,
        )
    ptr = o.get("ptr")
    if ptr and ptr["lookups"]:
        print(
            f"Private reverse lookups (LAN inventory): {ptr['lookups']} for {ptr['names']} names",
            file=out,
        )
    render_counting(o.get("counting") or [], out)  # (counting) what counts and refuses nothing
    if o.get("changes_in_effect"):  # (ledger) what changed, read before what the machine concluded
        try:
            lines = ledger.render(o["changes_in_effect"])
        except Exception as e:  # the rest of the brief is still worth printing
            lines = [f"Changes in effect: could not be shown ({type(e).__name__}: {e})"]
        print("", file=out)
        for line in lines:
            print(clean(line), file=out)
    try:  # (uplink quality) the gateway's link to the router while the TV was in use
        lines = uplink.render(o.get("uplink"))
    except Exception as e:  # the rest of the brief is still worth printing
        lines = [f"Uplink: could not be shown ({type(e).__name__}: {e})"]
    if lines:
        print("", file=out)
        for line in lines:
            print(clean(line), file=out)
    if o.get("by_day"):
        print("\nBy day:", file=out)
        table(
            [
                (r["day"], r["lookups"], r["blocked"], r["conns"], hb(r["bytes_up"]), hb(r["bytes_down"]))
                for r in o["by_day"]
            ],
            ["day", "lookups", "blocked", "conns", "up", "down"],
            out,
        )
    if o.get("categories"):
        print("\nBy category:", file=out)
        table(
            [
                (
                    c["category"],
                    c["lookups"],
                    c["blocked"],
                    c["names"],
                    c["conns"],
                    hb(c["bytes_up"]),
                    hb(c["bytes_down"]),
                )
                for c in o["categories"]
            ],
            ["category", "lookups", "blocked", "names", "conns", "up", "down"],
            out,
        )
    if o.get("dns_bypass"):
        print(
            "DNS sent to other resolvers (redirected to AdGuard): "
            + ", ".join(f"{r['dst']} x{r['flows']}" for r in o["dns_bypass"]),
            file=out,
        )
    print(f"\nNew hosts ({len(o['new_hosts'])}):", file=out)
    table(
        [
            (
                h["name"],
                h["category"],
                h["dns"],
                h["tls"],
                h["http"],
                state_word(h["blocked"]),
                "new domain" if h.get("new_domain", True) else "",
            )
            for h in o["new_hosts"]
        ],
        ["name", "category", "dns", "tls", "http", "state", ""],
        out,
    )
    try:  # (threats) a row nothing here wrote must not cost the rest of the brief
        render_threats(o.get("threats"), out)
    except Exception as e:
        print(f"\nKnown-bad names: could not be shown ({type(e).__name__}: {e})", file=out)
    print("\nBlocked and still retried:", file=out)
    table(
        [(r["name"], r["lookups"], r["rule"]) for r in o["blocked_retries"]], ["name", "lookups", "rule"], out
    )
    if o.get("blocked_reached"):
        why = "cached answer, hardcoded address, or a rule that changed"
        print(f"\nBlocked names still reached over TLS ({why}):", file=out)
        table(
            [(r["name"], r["hellos"], r["blocked"], r["allowed"]) for r in o["blocked_reached"]],
            ["name", "hellos", "blocked lookups", "allowed lookups"],
            out,
        )
    print("\nAllowed, outside the expected categories:", file=out)
    table(
        [(r["name"], r["category"], r["lookups"]) for r in o["allowed_unexpected"]],
        ["name", "category", "lookups"],
        out,
    )
    print(
        "\nTop upload (per TLS name; IP when no hello was captured;"
        " payload<= strips 40 B of headers per packet):",
        file=out,
    )
    table(
        [
            (
                r["name"] or "(no TLS name)",
                r["dst"] if r["ips"] == 1 else f"{r['dst']} +{r['ips'] - 1}",
                r["dport"],
                r["conns"],
                hb(r["bytes_up"]),
                hb(p) if (p := queries.payload_bound(r["bytes_up"], r.get("pkts_up"))) is not None else "?",
                hb(r["bytes_down"]),
            )
            for r in o["top_upload"]
        ],
        ["name", "dst", "port", "conns", "up", "payload<=", "down"],
        out,
    )
    try:  # (budget) a row nothing here wrote must not cost the rest of the brief
        render_upload_budget(o.get("upload_budget"), out)
    except Exception as e:
        print(f"\nUpload budget: could not be shown ({type(e).__name__}: {e})", file=out)
    try:  # (attention) the same: a count, never the reason a brief is lost
        render_attention(o.get("attention"), out)
    except Exception as e:
        print(f"\nAttention: could not be shown ({type(e).__name__}: {e})", file=out)
    gate = o.get("gate") or {}
    if gate.get("new_connections") or gate.get("examples") or gate.get("inpath"):
        print(
            f"\nDNS-gated egress (count-only): {gate.get('new_connections', 0)} new connections to addresses"
            " no lookup had returned; logged samples (`just looked up`: within seconds of an answer naming"
            " the address, so the TV beat the feeder; otherwise a TLS name means a lookup the gate forgot):",
            file=out,
        )
        table(
            [
                (
                    g["dst"],
                    g["dport"],
                    g["n"],
                    g.get("late", 0),
                    ts(g["first"], "%m-%d %H:%M"),
                    clean(g["name"] or "(none)"),
                )
                for g in gate.get("examples", [])
            ],
            ["address", "port", "samples", "just looked up", "first", "TLS name seen"],
            out,
        )
        if gate.get("unexplained"):
            print(
                "  unexplained: neither just looked up nor in any answer of the week before (a hardcoded"
                " server or a resolver bypass; what the gate is for):",
                file=out,
            )
            table(
                [
                    (
                        g["dst"],
                        g["dport"],
                        g["n"],
                        ts(g["first"], "%m-%d %H:%M"),
                        clean(g["name"] or "(none)"),
                    )
                    for g in gate["unexplained"]
                ],
                ["address", "port", "samples", "first", "TLS name seen"],
                out,
            )
        fill = gate.get("inpath")
        if fill:
            # (inpath) the two fillers side by side (design decision 64); nothing is refused by either
            did = fill.get("filler") or {}
            print(
                f"  in-path filler (count-only, beside the passive feeder): passive feeder"
                f" {gate.get('new_connections', 0)} misses, in-path {fill.get('new_connections', 0)} misses;"
                f" answers offered {fill.get('offered', 0)}: held {did.get('held', 0)},"
                f" released at once {did.get('known', 0)}, late {did.get('late', 0)},"
                f" unadded {did.get('failed', 0)}, not parsed {did.get('unparsed', 0)},"
                f" passed by the kernel {max(fill.get('offered', 0) - did.get('received', 0), 0)}",
                file=out,
            )
            if fill.get("examples"):
                print(
                    "  in-path misses, logged samples (`just looked up`: an answer the filler did not hold;"
                    " otherwise an address the TV kept from before the list knew it):",
                    file=out,
                )
                table(
                    [
                        (
                            g["dst"],
                            g["dport"],
                            g["n"],
                            g.get("late", 0),
                            ts(g["first"], "%m-%d %H:%M"),
                            clean(g["name"] or "(none)"),
                        )
                        for g in fill["examples"]
                    ],
                    ["address", "port", "samples", "just looked up", "first", "TLS name seen"],
                    out,
                )
    try:  # (namebound) a row nothing here wrote must not cost the rest of the brief
        render_names(o.get("names"), out)
    except Exception as e:
        print(f"\nServer names: could not be shown ({type(e).__name__}: {e})", file=out)
    auto = o.get("autonomous") or {}
    # (autonomy) a rule on probation untested is listed every day until the owner decides, and the
    # blocks waiting their turn are named
    if auto.get("blocked") or auto.get("decided") or auto.get("untested") or auto.get("queued"):
        from tvgw import autoblock

        print(
            "\nRules the gateway added on its own (design decision 20; `tvgw undo` takes the newest out):",
            file=out,
        )
        seen: set[str] = set()
        rows = []
        for r in auto.get("blocked", []) + auto.get("decided", []) + auto.get("untested", []):
            if r["rule"] in seen:
                continue
            seen.add(r["rule"])
            why = clean(r["reason"] or r["verifier_reason"] or "")[:70]
            rows.append((r["rule"], ts(r["added_t"], "%m-%d %H:%M"), autoblock.state_label(r), why))
        rows += [
            (q["rule"], ts(q["queued_t"], "%m-%d %H:%M"), "queued", "waits for the trial in progress")
            for q in auto.get("queued", [])
        ]
        table(rows, ["machine rule", "added", "verdict", "why"], out)
    render_list_changes(o.get("list_changes") or {}, out)  # (lists)
    render_list_guard(o.get("list_guard"), out)  # (listguard)
    if o.get("beacons"):
        print(
            "\nPeriodic connections (start-to-start interval; jitter = MAD/median; payload per connection):",
            file=out,
        )
        table(
            [
                (
                    clean(x["name"]) + ("" if x["named"] else " (no TLS name)"),
                    x["category"] or "?",
                    x["conns"],
                    f"{x['period']:.0f} s",
                    f"{x['jitter']:.2f}",
                    hb(x["payload"]),
                    "ACR-like" if x["acr_like"] else "",
                )
                for x in o["beacons"]
            ],
            ["name", "category", "conns", "every", "jitter", "payload<=", ""],
            out,
        )
    print("\nGFTS URL filter (status biz_code: requests):", file=out)
    print(
        "  " + ", ".join(f"{g['status']} {g['biz_code']}: {g['requests']}" for g in o["gfts"])
        if o["gfts"]
        else "  (none)",
        file=out,
    )
    if o.get("plain_http"):
        print("\nPlain HTTP (unencrypted; vendor file service excluded):", file=out)
        table(
            [(r["host"], r["method"], r["path"], r["requests"], r["agents"]) for r in o["plain_http"]],
            ["host", "method", "path", "requests", "user agents"],
            out,
        )
    odd = o["oddports"]
    print(
        "\nUnexpected ports: "
        + (", ".join(f"{p['proto']}/{p['dport']} -> {p['dst']} x{p['n']}" for p in odd) if odd else "none"),
        file=out,
    )
    lan = o.get("lan_probes", [])
    more = f" +{len(lan) - 12} more" if len(lan) > 12 else ""
    print(
        "LAN probes (dropped): "
        + (", ".join(f"{p['dst']}:{p['dport']} x{p['n']}" for p in lan[:12]) + more if lan else "none"),
        file=out,
    )
    if o.get("unresolved"):
        print("\nUnresolved flows (no DNS answer or TLS name explains the address):", file=out)
        table(
            [
                (u["dst"], u["dport"], u["conns"], hb(u["bytes_up"]), hb(u["bytes_down"]))
                for u in o["unresolved"]
            ],
            ["dst", "port", "conns", "up", "down"],
            out,
        )
    for fc in o.get("firmware_changes", []):
        seen = ts(fc["t"], "%m-%d %H:%M")
        print(
            f"\nFirmware {clean(fc['firmware'])} seen {seen}; new names from the hour before to 72 h after:",
            file=out,
        )
        print("  " + (", ".join(clean(n) for n in fc["new_hosts"]) or "(none yet)"), file=out)
    if o.get("dns_anomalies"):
        print("\nDNS oddities:", file=out)
        table(
            [
                (x["kind"], x["name"], x["lookups"], state_word(x["blocked"]), x["detail"])
                for x in o["dns_anomalies"]
            ],
            ["kind", "name", "lookups", "state", "detail"],
            out,
        )
    runs: list[list] = []  # [first time, last time, power] of consecutive readings with one power
    for s in o["tvstate"]:
        power = s["power"] or "?"
        if runs and runs[-1][2] == power:
            runs[-1][1] = s["time"]
        else:
            runs.append([s["time"], s["time"], power])
    shown = ", ".join(f"{a}={p}" if a == b else f"{a}-{b}={p}" for a, b, p in runs)
    card = tv_card_text(o.get("tv_card") or {})  # (W12) which TV, as its readings name it
    print(
        "\nTV" + (f" ({clean(card)})" if card else "") + ": " + (clean(shown) if runs else "no readings"),
        file=out,
    )
    if o.get("settings_changes"):
        print("\nTV settings (first reading or change):", file=out)
        table(
            [(ts(r["t"], "%m-%d %H:%M"), r["key"], r["value"]) for r in o["settings_changes"]],
            ["time", "key", "value"],
            out,
        )
    if "app_sessions" in o:  # (app in front) only where the store holds a live record (decision 67)
        from tvgw import receipt

        for line in receipt.render_brief_section(o["app_sessions"], o.get("day") or "1d"):
            print(clean(line), file=out)
    starts = o.get("failed_starts") or {}  # (did it work) only on a window with one (design decision 72)
    if starts.get("starts"):
        from tvgw import didit, receipt

        print(
            "\nDid it work (app starts that may have failed; a report, nothing changes on its own):", file=out
        )
        if "lines" in starts:  # the interactive brief: the app, the time and the name
            for line in starts["lines"]:
                for part in receipt.wrap(line + ".", "  "):
                    print(clean(part), file=out)
        else:  # a persisted report carries the counts only (design decision 67)
            print(f"  {clean(didit.summary_line(starts, didit.day_arg(o)))}", file=out)
    if o["rule_changes"]:
        print("\nRule changes:", file=out)
        table(
            [
                (
                    r["kind"],
                    r["text"],
                    ts(r["added"], "%m-%d %H:%M"),
                    ts(r["removed"], "%m-%d %H:%M") if r["removed"] else "",
                )
                for r in o["rule_changes"]
            ],
            ["kind", "rule", "added", "removed"],
            out,
        )
    if o.get("rule_use"):  # (rule use) weekly reports only (design decision 82)
        from tvgw import rulestats

        print(
            "\nRule use (what each list and rule refused this week; tvgw lists and tvgw rules --local say"
            " more; nothing is removed on its own):",
            file=out,
        )
        for line in rulestats.weekly_lines(o["rule_use"]):
            print(clean(line), file=out)


THREAT_KINDS = {"tif": "threat", "nrd": "newly registered"}  # (threats) a list's kind as the tables print it


def _threat_note(h: dict) -> str:
    """(threats) A hit's note: the list's entry when it is a domain above the name, why the list is more
    likely wrong than the TV (`threats.why()`), and a newly-registered band by the day of its copy."""
    from tvgw import threats

    notes = [f"under {clean(h['entry'])}"] if h.get("entry") and h["entry"] != h["name"] else []
    if h.get("doubt"):
        notes.append(threats.why(h))
    if h.get("list") == threats.NRD and h.get("copy"):
        notes.append(threats.band_words(h.get("band"), h["copy"]))
    return ", ".join(notes)


def _threat_lists(copies: list[dict]) -> str:
    """(threats) The copies a match read, by label, day and size."""
    return "; ".join(f"{clean(c['source'])} (copy of {c['copy']}, {c['names']:,} names)" for c in copies)


def render_threats(sec: dict | None, out=None) -> None:
    """(threats) Known-bad names, then Newly registered names (design decision 80): each name of the window
    a threat list, then a newly-registered list, covers, with its lookups and how many the filter answered
    with a public address. Nothing on a gateway that never matched the lists, so a brief there is what it
    was; the second section only where a newly-registered list is matched or has a hit."""
    if not sec:
        return
    out = out or sys.stdout
    hits = sec.get("hits") or []
    tif = [h for h in hits if h["list"] == "tif"]
    nrd = [h for h in hits if h["list"] == "nrd"]
    copies = sec.get("copies") or []
    head = "\nKnown-bad names (count-only; matched on the gateway against downloaded lists):"
    if not sec.get("matched") and not hits:
        print(f"{head} not matched yet; each day is matched once, 3 h after it ends", file=out)
        return
    print(head + (f" {len(tif)} on a threat list" if tif else " none on a threat list"), file=out)
    if copies:
        print(f"  lists: {_threat_lists(copies)}", file=out)
    unmatched = [d for d in sec.get("days") or [] if d not in (sec.get("matched") or [])]
    if unmatched and sec.get("matched"):
        print(
            f"  not matched yet: {', '.join(unmatched)} (each day is matched once, 3 h after it ends)",
            file=out,
        )
    if sec.get("stale"):
        oldest = min(c["copy"] for c in copies)
        print(
            f"  the oldest copy is from {oldest}, over a week old: sudo tvgw threats --update fetches them",
            file=out,
        )
    _threat_table(tif, out)
    if nrd or any(c["list"] == "nrd" for c in copies):
        print(
            "\nNewly registered names (count-only; a new domain is not a known-bad one):"
            + (f" {len(nrd)} on a list of newly registered domains" if nrd else " none"),
            file=out,
        )
        _threat_table(nrd, out)


def _threat_table(hits: list[dict], out) -> None:
    if not hits:
        return
    table(
        [
            (h["name"], h["lookups"], h["answered"], ts(h["first"]), ts(h["last"]), _threat_note(h))
            for h in hits[:SHOWN_THREATS]
        ],
        ["name", "lookups", "answered", "first", "last", "note"],
        out,
    )
    if len(hits) > SHOWN_THREATS:
        print(f"  and {len(hits) - SHOWN_THREATS} more: tvgw threats", file=out)


SHOWN_THREATS = 20  # (threats) rows the brief's Known-bad names lists before "and N more"


def cmd_ingest(a, s, prof) -> int:
    stats = ingest.run(s, prof)
    for w in stats.warnings:
        print(f"tvgw ingest: WARNING {clean(w)}", file=sys.stderr)
    size = os.path.getsize(s.db_path) / 1e6 if os.path.exists(s.db_path) else 0
    print(f"tvgw ingest: {stats.summary()}; db {size:.1f} MB")
    return 1 if stats.warnings else 0


def cmd_prune_pcaps(a, s, prof) -> int:
    """Retention for the raw captures: only files ingest has read, never the one the capture is writing."""
    from tvgw import forget

    deletable: set[str] = set()
    doomed: frozenset[str] = frozenset()
    if os.path.exists(s.db_path):  # no store yet means nothing has been read
        conn = _ro(s)
        deletable = ingest.deletable_pcaps(conn)
        doomed = forget.doomed_pcaps(conn)  # captures a forget could not delete while they were open
        conn.close()
    budget = int(s.pcap_max_gb * 2**30)
    deleted, warnings = pcaps.prune(
        s.pcap_dir, deletable, s.pcap_days, budget, pcaps.live_files(s.pcap_dir), doomed=doomed
    )
    sizes = [os.path.getsize(p) for p in glob.glob(os.path.join(s.pcap_dir, "*.pcap"))]
    print(f"tvgw prune-pcaps: deleted {len(deleted)}, kept {len(sizes)} ({sum(sizes) / 2**20:.0f} MB)")
    for w in warnings:
        print(f"tvgw prune-pcaps: WARNING {clean(w)}", file=sys.stderr)
    return 1 if warnings else 0  # a failed oneshot shows in `systemctl --failed`


def _ro(s):
    # (depth) a store that is there and not readable: the account is not in adm, which sqlite reports
    # only as "unable to open database file"
    if os.path.exists(s.db_path) and not os.access(s.db_path, os.R_OK):
        sys.exit(NEEDS_SETTINGS)
    try:
        return db.connect(s.db_path, readonly=True)
    except Exception as e:  # any open failure means the same thing to the operator
        sys.exit(f"cannot open {s.db_path}: {e} (run `sudo tvgw ingest` first?)")


def plain_lines(conn, o: dict, prof, now: float | None = None) -> list[str]:
    """(plain) The plain brief of the day `o` holds, as `plain.plain_brief` writes it: the TV's hours from
    its own readings, and the first-day line on a store younger than a day."""
    from tvgw import plain

    first = plain.first_day(queries.first_ingest(conn), time.time() if now is None else now)
    return plain.plain_brief(o, _activity(conn, o), None, profile=prof, first=first)


def _activity(conn, o: dict):
    """(plain) The TV's hours on: from its own readings, else (activity) estimated from the TV port's
    counters over the day, else unknown."""
    from tvgw import activity, plain

    found = plain.activity_from_readings(o)
    if found is not None or "since" not in o or "until" not in o:
        return found
    hours = activity.hours_on(conn, o["since"], o["until"])
    return None if hours is None else plain.Activity(hours=hours, estimated=True)


def print_plain(lines: list[str], out=None) -> None:
    out = out or sys.stdout
    for line in lines:
        print(clean(line), file=out)


def cmd_brief(a, s, prof) -> int:
    conn = _ro(s)
    kw = {"ledger_on": s.ledger == "on", "clean_hours": s.judge2_clean_hours}  # (ledger)
    kw["upload_ceiling"] = s.upload_ceiling  # (budget)
    kw["uplink_if"] = s.wan_if  # (uplink quality) a cable's speed is read at report time
    # (app in front) the interactive brief shows the viewing sessions; the persisted report (tvgw-analyze)
    # never does, so the finer record stays root-only in the store (design decision 67)
    o = queries.brief(conn, a.day or queries.yesterday(), prof, gw_ip=s.gw_ip, app_in_front=True, **kw)
    _with_resolver(o, s)
    if a.json:
        print(json.dumps(o, indent=1))
    elif a.action:
        # (plain) reports/action.txt for the login message: `<tier>\t<text>`, or nothing when nothing needs
        # a person (or on a store younger than a day, which has no whole day to tell about)
        from tvgw import plain

        found = None if plain.first_day(queries.first_ingest(conn), time.time()) else plain.action(o, prof)
        if found:
            print(f"{found[0]}\t{clean(found[1])}")
    elif a.plain or (s.brief_style == "plain" and not a.full):  # (plain) BRIEF_STYLE, absent is full
        print_plain(plain_lines(conn, o, prof))
    else:
        render_brief(o)
    return 0


def _with_resolver(o: dict, s) -> None:
    """(resolver) The Coverage line names who answers the TV's lookups: a preset's name, or "your own
    resolver", never an address, since the report's JSON may reach the analyst's pack."""
    from tvgw import resolver

    if isinstance(o.get("coverage"), dict):
        o["coverage"]["resolver"] = resolver.label_for(s)


def cmd_new_hosts(a, s, prof) -> int:
    conn = _ro(s)
    rows = queries.new_hosts(conn, a.since)
    table(
        [(r[0], r[1], ts(r[2], "%Y-%m-%d %H:%M"), r[3], r[4], r[5], state_word(r[6]), r[7]) for r in rows],
        ["name", "category", "first seen", "dns", "tls", "http", "state", "rule"],
    )
    return 0


def cmd_retries(a, s, prof) -> int:
    conn = _ro(s)
    rows = queries.blocked_retries(conn, a.since)
    table(
        [(r[0], r[1], ts(r[2]), ts(r[3]), r[4]) for r in rows],
        ["blocked name", "lookups", "first", "last", "rule"],
    )
    return 0


def cmd_allowed(a, s, prof) -> int:
    conn = _ro(s)
    rows = queries.allowed_unexpected(conn, a.since, None, prof)
    table(
        [(r[0], r[1], r[2], ts(r[3]), r[4]) for r in rows],
        ["allowed name (unexpected category)", "category", "lookups", "last", "allow rule"],
    )
    return 0


def cmd_top_upload(a, s, prof) -> int:
    conn = _ro(s)
    rows = queries.top_upload(conn, a.since)
    table(
        [
            (
                r[0] or "(no TLS name)",
                r[1] if r[2] == 1 else f"{r[1]} +{r[2] - 1}",
                r[3],
                r[4],
                hb(r[5]),
                hb(r[6]),
            )
            for r in rows
        ],
        ["name", "dst", "port", "conns", "up", "down"],
    )
    return 0


HOST_DAYS = 7  # (namebound) days `tvgw host` checks a name's connections, or an address's answers, over


def cmd_host(a, s, prof) -> int:
    conn = _ro(s)
    h = queries.host_detail(conn, a.name)
    if not h:
        # (namebound) an address: what the filter answered with it, and the names the TV used there
        if re.fullmatch(r"(?:\d{1,3}\.){3}\d{1,3}", a.name) and _host_address(conn, a.name, s):
            return 0
        # (budget) the upload budget names a registrable domain, or a /24 for unnamed connections
        if _host_group(conn, a.name.lower().rstrip(".")):
            return 0
        print("not seen")
        return 1
    print(
        f"{clean(h['name'])}  category={h['category']}  first={ts(h['first_seen'], '%Y-%m-%d %H:%M')}  "
        f"last={ts(h['last_seen'], '%Y-%m-%d %H:%M')}  dns={h['dns_n']} tls={h['tls_n']} http={h['http_n']}  "
        f"state={state_word(h['last_blocked'])}"
    )
    print("rules seen in answers:", clean(", ".join(h["rules"])) or "(none)")
    if h["ips"]:
        print("TLS to:", ", ".join(f"{clean(ip)} x{n}" for ip, n in h["ips"]))
        print(f"its connections: {h['conns']}, up {hb(h['bytes_up'])} down {hb(h['bytes_down'])}")
    if h["http"][0]:
        print(f"plain HTTP requests: {h['http'][0]} (status {h['http'][1]}..{h['http'][2]})")
    table(h["by_day"], ["day", "lookups", "blocked"])
    _host_binding(conn, h["name"], s)
    return 0


def _host_binding(conn, name: str, s) -> None:
    """(namebound) `tvgw host NAME`: the name's TLS connections of the last HOST_DAYS days against the
    filter's answers (design decision 70), and each one that was not name-bound with what its address had
    been answered for."""
    now = time.time()
    try:
        e = namebound.explain_name(conn, name, now - HOST_DAYS * 86400, now, s.gw_ip)
    except sqlite3.OperationalError:  # a store no writer has taken to the schema with answer_ip
        return
    c = e["counts"]
    if not sum(n for k, n in c.items() if k != "unassessed"):  # nothing the answers could assess yet
        return
    parts = [f"{c[k]} {label}" for k, label in NAMES_CLASSES if c.get(k)]
    print(f"its TLS connections against the filter's answers, last {HOST_DAYS} days: " + ", ".join(parts))
    if e["other"]:
        table(
            [
                (
                    ts(x["t"]),
                    x["dst"],
                    x["dport"],
                    dict(NAMES_CLASSES)[x["cls"]],
                    ", ".join(x["answered_for"]) or "-",
                    ts(x["last_bound"]) if x["last_bound"] else "-",
                )
                for x in e["other"]
            ],
            ["time", "address", "port", "class", "address answered for", "given it before"],
        )


def _host_address(conn, ip: str, s) -> bool:
    """(namebound) `tvgw host ADDRESS`: the questions the filter answered with the address in the last
    HOST_DAYS days, the services behind them (an address of SHARED_FROM or more names no connection), and
    the TLS names the TV used there with their classes. False when the store holds none of it."""
    now = time.time()
    try:
        e = namebound.explain_address(conn, ip, now - HOST_DAYS * 86400, now, s.gw_ip)
    except sqlite3.OperationalError:
        return False
    if not e["answers"] and not e["hellos"]:
        return False
    print(f"{ip}: the answers that gave it, last {HOST_DAYS} days")
    table(
        [
            (" > ".join(x["names"]), x["n"], ts(x["last"]), "-" if x["ttl"] is None else f"{x['ttl']} s")
            for x in e["answers"]
        ],
        ["question > CNAME chain", "answers", "last", "lifetime"],
    )
    many = "a shared address: it names no connection by its answers" if e["shared"] else "one service"
    print(f"services behind it: {', '.join(clean(d) for d in e['domains']) or '(none)'} ({many})")
    if e["hellos"]:
        print("TLS names the TV used there, by class:")
        table(
            [
                (n, ", ".join(f"{dict(NAMES_CLASSES)[k]} {v}" for k, v in c.items()))
                for n, c in e["hellos"].items()
            ],
            ["name", "connections"],
        )
    if e["since"]:
        print(f"the answers are on record from {ts(e['since'], '%Y-%m-%d %H:%M')}")
    return True


def _host_group(conn, name: str) -> bool:
    """(budget) `tvgw host` for what the upload budget prints as a destination that is no single name: a
    /24 lists the addresses in it the TV connected to and the TLS names seen there; a registrable domain
    lists the names under it. False when the store has neither."""
    from tvgw.names import registrable_domain

    if re.fullmatch(r"(?:\d{1,3}\.){3}0/24", name):
        prefix = name[: -len("0/24")]
        rows = conn.execute(
            "SELECT dst, COUNT(*), COALESCE(SUM(bytes_up),0), COALESCE(SUM(bytes_down),0) FROM flows"
            " WHERE dst LIKE ? GROUP BY dst ORDER BY 2 DESC, dst LIMIT 20",
            (prefix + "%",),
        ).fetchall()
        if not rows:
            return False
        print(f"{name}: the addresses in it the TV connected to")
        table([(d, n, hb(u), hb(dn)) for d, n, u, dn in rows], ["address", "conns", "up", "down"])
        snis = conn.execute(
            "SELECT sni, COUNT(*) FROM tls WHERE dst LIKE ? GROUP BY sni ORDER BY 2 DESC, sni LIMIT 10",
            (prefix + "%",),
        ).fetchall()
        print("TLS names seen there:", ", ".join(f"{clean(n)} x{c}" for n, c in snis) or "(none)")
        return True
    names = [
        r
        for r in conn.execute(
            "SELECT name, category, first_seen, last_seen, dns_n, tls_n, last_blocked FROM hosts"
            " ORDER BY name"
        )
        if registrable_domain(r[0]) == name and r[0] != name
    ]
    if not names:
        return False
    print(f"{clean(name)}: not one name; the names under it:")
    table(
        [(n, c, ts(f), ts(la), d, t, state_word(b)) for n, c, f, la, d, t, b in names],
        ["name", "category", "first", "last", "dns", "tls", "state"],
    )
    return True


def cmd_budget(a, s, prof) -> int:
    """(budget) The upload budget's ceiling and how it was set; with --rederive (root), set it again
    from the 14 whole days before today, under the ingest's lock, keeping the record."""
    import fcntl

    if a.rederive:
        if os.geteuid() != 0:
            print("tvgw budget: --rederive writes the store; run it with sudo: sudo tvgw budget --rederive")
            return 2
        with open(os.path.join(s.state_dir, ".ingest.lock"), "w", encoding="utf-8") as lock:
            fcntl.flock(lock, fcntl.LOCK_EX)
            conn = db.connect(s.db_path)
            budget.rederive(conn, prof, time.time(), s.db_days)
            conn.commit()
            conn.close()
    conn = _ro(s)
    a_, b_ = queries.day_bounds(queries.yesterday())
    sec = budget.report(conn, a_, b_, prof, s.upload_ceiling)
    if a.json:
        print(
            json.dumps(
                {"row": budget.load(conn), "ceiling": sec["ceiling"], "source": sec["source"]}, indent=1
            )
        )
        return 0
    print(f"upload budget: ceiling {hb(sec['ceiling'])} net per destination-hour ({sec['source']})")
    print(f"  {clean(_budget_how(sec))}")
    return 0


def cmd_lists(a, s, prof) -> int:
    """(listguard) What the subscribed lists say about the TV's own rules, from the last scan, and the
    previews of their updates in the last 14 days; with --scan (root), scan now under the ingest's lock
    (design decision 68). (rule use) Then what each list, and the profile's, the owner's and the
    machine's rules, refused the TV since --since, 7 days by default (design decision 82). Exit 1 when a
    list's line lifts one of the TV's blocks or can refuse what it needs."""
    from tvgw import listguard, rulestats

    now = time.time()
    if a.since >= now:  # (rule use) before --scan does any work
        return _usage("--since must be in the past", "lists")
    if a.scan:
        if os.geteuid() != 0:
            print("tvgw lists: --scan reads AdGuard Home's files and writes the store; run it with sudo")
            return 2
        listguard.scan_now(s, prof)
    conn = _ro(s)
    state = listguard.load_state(conn)
    previews = listguard.load_previews(conn)
    use = rulestats.lists(s, prof, conn, a.since, now)  # (rule use)
    if a.json:
        print(json.dumps({"state": state, "previews": previews, "use": use}, indent=1))
    elif not state:
        print(
            "tvgw lists: no scan yet; the hourly job scans the lists AdGuard Home holds,"
            " and sudo tvgw lists --scan scans them now"
        )
        _print_list_use(use)
        return 0
    else:
        print(f"Lists AdGuard Home holds, as scanned {ts(state.get('t'), '%Y-%m-%d %H:%M')}:")
        table(
            [
                (
                    e.get("id"),
                    clean(e.get("name")),
                    e.get("state"),
                    e.get("exceptions", "-"),
                    e.get("unread", "-"),
                    ts(e.get("since")) if e.get("since") else "-",
                )
                for e in state.get("lists") or []
            ],
            ["id", "list", "file", "exceptions", "unread", "this version since"],
        )
        view = {"scanned": state.get("t"), "findings": state.get("findings") or [], "previews": previews}
        render_list_guard(view)
        if not view["findings"]:
            print("\nNo line of these lists acts on the TV's own rules.")
        _print_list_use(use)
    worst = [f for f in state.get("findings") or [] if f.get("kind") in ("lifts", "exposes")]
    return 1 if worst else 0


def cmd_threats(a, s, prof) -> int:
    """(threats) The names the TV looked up that a downloaded list covers, since SINCE (adm). As root,
    --update downloads the lists and --match DAY matches one day now (design decision 80)."""
    from tvgw import threats

    if (a.update or a.match) and os.geteuid() != 0:
        what = "--update writes the list copies" if a.update else "--match writes the store"
        print(f"tvgw threats: {what}; run it with sudo")
        return 2
    if a.update:
        done = threats.update(s.state_dir, s.threat_lists, s.threat_list_urls)
        for line in done.lines:
            print(clean(line))
        return done.code
    if a.match:
        return _threat_match(a.match, s, prof)
    conn = _ro(s)
    found = threats.rows(conn, a.since, float("inf"))
    meta = threats.load_meta(conn)
    newest = meta[max(meta)] if meta else {}
    if a.json:
        print(
            json.dumps(
                {"rows": found, "matched": sorted(meta), "copies": newest.get("copies") or []}, indent=1
            )
        )
        return 0
    if not found and not meta:
        if s.threat_lists != "count":
            print("tvgw threats: THREAT_LISTS is off, so no name is matched (docs/reference/settings.md)")
        else:
            print("tvgw threats: no day has been matched yet; each day is matched once, 3 h after it ends")
        return 0
    if found:
        table(
            [
                (
                    r["day"],
                    r["name"],
                    THREAT_KINDS.get(r["list"], r["list"]),
                    r["lookups"],
                    r["answered"],
                    ts(r["first"]),
                    ts(r["last"]),
                    _threat_note(r),
                )
                for r in found
            ],
            ["day", "name", "list", "lookups", "answered", "first", "last", "note"],
        )
    else:
        print(f"tvgw threats: no name the TV looked up since {ts(a.since, '%Y-%m-%d %H:%M')} is on the lists")
    copies = [
        dict(zip(("list", "file", "copy", "names", "source"), c[:5], strict=True))
        for c in newest.get("copies") or []
        if isinstance(c, list) and len(c) >= 5
    ]
    if copies:
        print(f"lists: {_threat_lists(copies)}; matched up to {max(meta)}")
    return 0


def _threat_match(day: str, s, prof) -> int:
    """(threats) `sudo tvgw threats --match DAY`: match one day now, under the ingest's lock. A day not
    yet settled is matched but not marked, so the hourly ingest still matches it once it is."""
    import fcntl

    from tvgw import threats

    if s.threat_lists != "count":
        print("tvgw threats: THREAT_LISTS is off, so nothing is matched (docs/reference/settings.md)")
        return 2
    sources = threats.parse_urls(s.threat_list_urls)
    found_in = threats.copies(s.state_dir, sources)
    if not found_in:
        print("tvgw threats: no list copy yet: sudo tvgw threats --update downloads them")
        return 1
    now = time.time()
    settled = queries.day_bounds(day)[1] <= now - threats.SETTLE
    with open(os.path.join(s.state_dir, ".ingest.lock"), "w", encoding="utf-8") as lock:
        fcntl.flock(lock, fcntl.LOCK_EX)
        conn = db.connect(s.db_path)
        n = threats.match_day(conn, day, prof, found_in, now, record=settled)
        conn.commit()
        conn.close()
    later = "" if settled else "; the day is not over, so the hourly ingest matches it again once it is"
    print(f"tvgw threats: {day}: {n} name{'' if n == 1 else 's'} on the lists{later}")
    return 0


APPLIED = "/run/tvgw/settings.applied"  # (ports) what the last apply used and built


def cmd_ports(a, s, prof) -> int:
    """(ports) The two port walls' readiness from the store, read-only: STRICT_PORTS's odd-port count and
    the clock port's NTP count over the last two weeks, each with its one-line verdict (ports.py)."""
    from tvgw import ports

    if a.ntp_seen:  # what tvgw-apply reads before it closes the clock port (design decision 71)
        if not os.path.exists(s.db_path):  # no record yet: nothing says the TV uses NTP
            print("ntp_requests=0\nntp_record=none")
            return 0
        now = time.time()
        try:
            conn = _ro(s)
            ntp = queries.ntp_servers(conn, now - ports.READY_DAYS * 86400, now, prof)
            kept = ports.ntp_seen_kept(conn, now)  # what a forget kept of the count it deleted
        except sqlite3.Error as e:  # a store that cannot be read says nothing: the port stays open
            sys.exit(f"tvgw ports: cannot read {s.db_path}: {e}")
        record = "counted" if ntp["counted"] or kept else "none"
        print(f"ntp_requests={ntp['requests'] + kept}\nntp_record={record}")
        return 0
    try:
        with open(APPLIED, encoding="utf-8") as fh:
            applied = config.parse_conf(fh.read())
    except (OSError, ValueError):
        applied = {}
    conn = _ro(s)
    now = time.time()
    readings = ports.report(conn, now, prof, s, applied)
    if a.json:
        print(json.dumps({"now": now, "walls": [r.as_dict() for r in readings]}, indent=1))
        return 0
    for line in ports.render(readings, now, s, applied):
        print(clean(line))
    return 0


def _print_list_use(use: dict) -> None:
    """(rule use) `tvgw lists`' second section: the refusals by list (design decision 82)."""
    from tvgw import rulestats

    print(f"\nRefusals by list over the last {rulestats.span(use['until'] - use['since'])}:")
    for line in rulestats.list_lines(use):
        print(clean(line))


def cmd_gfts(a, s, prof) -> int:
    conn = _ro(s)
    rows = queries.gfts_summary(conn, a.since)
    table([(r[0], r[1], r[2], hb(r[3])) for r in rows], ["status", "biz_code", "requests", "bytes"])
    return 0


def cmd_tvstate(a, s, prof) -> int:
    conn = _ro(s)
    table(
        [(ts(t, "%Y-%m-%d %H:%M"), p, app) for t, p, app in queries.tvstate(conn, a.since)],
        ["time", "power", "app"],
    )
    ch = queries.settings_changes(conn, a.since)
    if ch:
        print("settings changes:")
        table([(ts(t, "%Y-%m-%d %H:%M"), k, v) for t, k, v in ch], ["time", "key", "value"])
    return 0


def cmd_rules(a, s, prof) -> int:
    if a.local:  # (site rules) the owner's own rules file, not the store's history
        return _rules_local(a, s, prof)
    if a.since is not None or a.json:
        return _usage("--since and --json go with --local", "rules")
    conn = _ro(s)
    table(
        [
            (k, t, ts(f, "%Y-%m-%d %H:%M"), ts(r, "%Y-%m-%d %H:%M") if r else "")
            for k, t, f, r in queries.rules_history(conn)
        ],
        ["kind", "rule", "since", "removed"],
    )
    return 0


def _rules_local(a, s, prof) -> int:
    """(site rules) `tvgw rules --local`: the owner's rules, with (rule use) what each decided in the
    store's record and the allows that let nothing through in 30 days (design decision 82)."""
    from tvgw import rulestats

    now = time.time()
    if a.since is not None and a.since >= now:
        return _usage("--since must be in the past", "rules")
    conn = _ro(s) if os.path.exists(s.db_path) else None  # no store yet: the rules without counts
    try:
        rep = rulestats.owner(s, prof, conn, now, a.since)
    except PermissionError:
        line = f"tvgw rules: cannot read {s.local_rules}; run it with sudo"
        print(json.dumps({"error": line}, indent=1) if a.json else line)
        return 1
    if a.json:
        print(json.dumps(rep, indent=1))
        return 0
    for line in rulestats.owner_lines(rep):
        print(clean(line))
    return 0


def cmd_size(a, s, prof) -> int:
    conn = _ro(s)
    for t, n in db.counts(conn).items():
        print(f"{t:11s} {n:>9}")
    oldest = conn.execute("SELECT MIN(t) FROM dns").fetchone()[0]
    print(f"oldest dns row: {ts(oldest, '%Y-%m-%d %H:%M')}")
    print(f"file: {os.path.getsize(s.db_path) / 1e6:.1f} MB")
    return 0


def cmd_analyst(a, s, prof) -> int:
    from tvgw import analyst

    if a.show:
        path = analyst.latest(s)
        if not path:
            print("tvgw analyst: no proposals yet")
            return 1
        with open(path, encoding="utf-8") as fh:
            print(fh.read(), end="")
        return 0
    if sum(bool(x) for x in (a.day, a.since, a.week, a.weekly)) > 1:
        return _usage("--day, --since, --week and --weekly exclude each other")
    if a.week and not re.fullmatch(r"\d{4}-W\d{2}", a.week):
        return _usage("--week takes an ISO week like 2026-W43")
    hours = None
    if a.since:
        m = re.fullmatch(r"(\d+(?:\.\d+)?)h", a.since)
        if not m or not 0 < float(m.group(1)) <= 168:
            return _usage("--since takes hours like 6h (up to 168h)")
        hours = float(m.group(1))
    return analyst.run(
        s,
        prof,
        a.day,
        hours,
        a.model,
        a.effort,
        dry_run=a.dry_run,
        week=a.week,
        weekly=a.weekly,
        force=a.force,
    )


def cmd_undo(a, s, prof) -> int:
    from tvgw import analyst, autoblock

    conn = db.connect(s.db_path)
    try:
        gone = analyst.undo(conn, s, prof, everything=a.all)
    except Exception as e:  # the file is already changed; AdGuard is not
        print(
            f"tvgw undo: the rules file was changed but AdGuard was not re-applied ({type(e).__name__}: {e})"
        )
        print("tvgw undo: the next hourly check applies it again; to do it now, run `tvgw adguard apply`")
        return 1
    else:
        # how this undo's push ended is its own last `apply` row, the last row this connection wrote; the
        # store's debt is no guide, since a revert the hourly check made meanwhile owes a push as well
        (ended,) = autoblock.decisions(conn, "id = last_insert_rowid()") if gone else ({},)
    finally:
        conn.close()
    if ended.get("outcome") == autoblock.DEFERRED:
        # (fin-release) AdGuard held its restart back because the upstreams are down: the revert stands
        # in the file and the record, and the next hourly check pushes it
        print(
            f"tvgw undo: {', '.join(gone)} removed from the rules file; AdGuard held its restart back"
            " (deferred: upstream down) and the next hourly check re-applies it"
        )
        return DEFERRED_EXIT
    if (ended.get("outcome"), ended.get("reason")) == (autoblock.REAPPLY_FAILED, autoblock.STALE_PUSH):
        # (decision 91) the push took, but its plan was made before another revert and may still hold
        # that revert's rule: the push is owed again
        print(
            f"tvgw undo: {', '.join(gone)} removed from the rules file; another change to the rules"
            " came while AdGuard was being re-applied, so the next hourly check applies it again"
            " (to do it now: sudo tvgw adguard apply)"
        )
        return DEFERRED_EXIT
    print(
        "tvgw undo: "
        + (", ".join(gone) + " removed and AdGuard re-applied" if gone else "no machine rule to remove")
    )
    return 0


def cmd_autoblock(a, s, prof) -> int:
    from tvgw import analyst, autoblock

    conn = db.connect(s.db_path)
    try:
        if a.action == "calibrate":  # (ledger) placebo trials over the store's history, read-only
            return _calibrate(a, s, prof, conn)
        if a.action == "check":
            # (pause) the second way back: a pause past its end that nothing ended, before anything else;
            # it takes the lock below itself, and a failure here never stops the judging
            pause_failed = _pause_fallback(s, prof)
            # (autonomy) one check at a time, and never beside the analyst's apply: both watch canaries
            with autoblock.exclusive(s.state_dir) as free:
                if not free:
                    print(
                        "tvgw autoblock: another check or the analyst's trial is running; the next run judges"
                    )
                    return 0
                decisions = analyst.check(conn, s, prof, watch=not a.no_watch)
            for d in decisions:  # (fin-release) rule None: an owed push alone, which names no rule
                rule = "" if d["rule"] is None else f" {d['rule']}"
                print(f"tvgw autoblock: {d['verdict']}{rule} ({d['reason']})")
            if not decisions:
                print(
                    f"tvgw autoblock: {len(autoblock.pending(conn))} rule(s) on probation, nothing to decide"
                )
            sys.stdout.flush()
            # (ledger) judge v2 beside the shipped judge, after it has decided: a slow or failing shadow
            # pass can never keep a revert from running
            _shadow(conn, s, prof)
            if any(d.get("reapply_failed") for d in decisions):
                print(
                    "tvgw autoblock: WARNING: a reverted rule is still in AdGuard; run `tvgw adguard apply`"
                )
                return 1
            return 1 if pause_failed else 0
        table(
            [
                (
                    r["rule"],
                    ts(r["added_t"]),
                    autoblock.state_label(r),  # (autonomy) untested and an armed canary are named
                    clean(r["reason"] or r["verifier_reason"] or "")[:60],
                )
                for r in autoblock.rows(conn)
            ]
            + [  # (autonomy) the blocks waiting their turn
                (q["rule"], ts(q["queued_t"]), "queued", "waits for the trial in progress")
                for q in autoblock.queued(conn)
            ],
            ["machine rule", "added", "verdict", "why"],
        )
        return 0
    finally:
        conn.close()


def _pause_fallback(s, prof) -> bool:
    """(pause) End a pause past its end that its timer did not end (`listpause.fallback`), print what it did
    and the report, and say whether it failed for any reason but the upstreams being down, which the
    next hour tries again. Nothing it raises reaches the hourly check."""
    from tvgw import listpause

    try:
        done = listpause.fallback(s, prof)
        if done is None:
            return False
        for line in done.lines:
            print(clean(line))
        if done.code == listpause.OK and done.pause is not None and done.pause.ended is not None:
            for line in listpause.report(s, prof, done.pause).lines:
                print(clean(line))
        sys.stdout.flush()
        return done.code == listpause.REFUSED
    except Exception as e:  # the judge that reverts a bad block must run whatever this did
        print(f"tvgw autoblock: WARNING: the end of a pause past its end failed: {type(e).__name__}: {e}")
        return True


SHADOW_BUDGET = 120.0  # seconds: the shadow pass's share of tvgw-autoblock's 10-minute TimeoutStartSec


def _shadow(conn, s, prof, now: float | None = None, budget: float = SHADOW_BUDGET, clock=None) -> None:
    """(ledger) Judge v2's verdicts beside the shipped judge's, in judge_shadow. It runs after the
    shipped judge has decided and within a time budget; it decides nothing, so a failure here is
    reported and the hourly check's result stands."""
    if s.ledger != "on":
        return
    from tvgw import judge2

    now = now if now is not None else time.time()
    try:
        todo = len(judge2.rows_to_shadow(conn, now))
        k = s.judge2_clean_hours
        done = judge2.shadow(conn, prof, now=now, k=k, after_check=True, budget=budget, clock=clock)
        if len(done) < todo:
            print(
                f"tvgw autoblock: judge v2 (shadow) stopped after {budget:g} s with"
                f" {todo - len(done)} of {todo} rule(s) left for the next hour"
            )
    except Exception as e:
        conn.rollback()
        print(f"tvgw autoblock: judge v2 (shadow) failed: {type(e).__name__}: {e}", file=sys.stderr)


def _calibrate(a, s, prof, conn) -> int:
    """(ledger) `tvgw autoblock calibrate`: the false-revert rate of each judge design, measured."""
    from tvgw import judge2

    try:
        arms = judge2.parse_arms(a.arms)
        if not 1 <= a.days <= 400 or not 0 <= a.breakage < 1:
            raise ValueError("--days must be 1 to 400 and --breakage at least 0 and under 1")
    except ValueError as e:
        print(f"tvgw autoblock: error: {e}", file=sys.stderr)
        return 2
    result = judge2.calibrate(
        conn, prof, days=a.days, arms=arms, k=s.judge2_clean_hours, breakage=a.breakage, by_class=a.by_class
    )
    for line in judge2.summary_lines(result):
        print(line)
    try:
        print(f"tvgw autoblock calibrate: written to {judge2.write_report(result, s.reports_dir)}")
    except OSError as e:
        print(f"tvgw autoblock calibrate: could not write the report: {e}", file=sys.stderr)
        return 1
    return 0


def cmd_changes(a, s, prof) -> int:
    """(ledger) `tvgw changes`: the change ledger since SINCE; `--note-deploy` appends install.sh's line."""
    if a.note_deploy:
        try:
            print("tvgw changes: noted " + ledger.note_deploy(s, a.note_deploy))
        except OSError as e:
            print(f"tvgw changes: could not write the spool: {e}", file=sys.stderr)
            return 1
        return 0
    conn = _ro(s)
    try:
        rows = conn.execute(
            "SELECT t, t_end, t_precision, source, kind, subject, effect_class, metric_affecting FROM changes"
            " WHERE t >= ? ORDER BY t",
            (a.since,),
        ).fetchall()
    except sqlite3.Error as e:
        sys.exit(f"tvgw changes: {e} (has the ingest run since the deploy?)")
    table(
        [
            (
                ts(t, "%m-%d %H:%M:%S") + (f" ~{p / 60:.0f}m" if p and p >= 60 else ""),
                ts(t_end, "%m-%d %H:%M") if t_end else "",
                source,
                kind,
                subject,
                cls,
                metric or "",
            )
            for t, t_end, p, source, kind, subject, cls, metric in rows
        ],
        ["time", "until", "source", "kind", "subject", "class", "metric"],
    )
    return 0


def cmd_tvprobe(a, s, prof) -> int:
    """(ledger) `tvgw tvprobe`: one read-only session for --hours, events logged to --out."""
    from tvgw import lgwebos

    if not 0 < a.hours <= 48:
        print("tvgw tvprobe: error: --hours must be more than 0 and at most 48", file=sys.stderr)
        return 2
    out = a.out or os.path.join(s.state_dir, "probe", "tvprobe.jsonl")
    return lgwebos.probe_main(s.tv_ip, a.key_file, out, a.hours, s.tv_if)


def cmd_probe(a, s, prof) -> int:
    """(probe) `tvgw probe`: exit 0 pass, 3 fail, 4 unknown (probe.EXIT)."""
    from tvgw import probe

    return probe.main(s, prof, as_json=a.json, directory=a.across, netns=a.netns)


def cmd_dnsgate_feed(a, s, prof) -> int:
    from tvgw import dnsgate

    return dnsgate.main(s, prof)


def cmd_dnsgate_inpath(a, s, prof) -> int:
    """(inpath) The in-path filler of design decision 64; exits 0 at once unless DNSGATE_FILL=inpath."""
    from tvgw import inpath

    return inpath.main(s, profile=prof)


def cmd_attention_hold(a, s, prof) -> int:
    """(attention) The holder of design decision 69; exits 0 at once unless the count is in use here."""
    return attention.main(s)


def cmd_attention(a, s, prof) -> int:
    """(attention) `tvgw attention`: whether the attention count runs, what it holds and what it counted.
    The holder's status and the firewall's table are root's: without root it says so, and reads nothing."""
    if os.geteuid() != 0:
        print(f"LIVE_READING={s.live_reading}, PROFILE={s.profile}, ATTENTION_WALL={s.attention_wall}")
        print("the holder's status and the firewall's table are root's: run sudo tvgw attention")
        return 0
    for line in attention.status_lines(s, attention.read_status(), attention.list_table()):
        print(clean(line))
    return 0


def cmd_names_tap(a, s, prof) -> int:
    """(namebound) The live name count of design decision 70; exits 0 at once unless NAME_BINDING=count."""
    from tvgw import nametap

    return nametap.main(s, prof)


def cmd_backup(a, s, prof) -> int:
    """A checked copy of the store; (depth) its outcome is recorded in the store for verify's store_backup.
    (reliability) `--export`: the newest checked copy, encrypted to BACKUP_RECIPIENT, on standard output."""
    from tvgw import backup

    if a.export:
        if sys.stdout.isatty():
            print(
                "tvgw backup --export: the copy is binary; send it to a file on your computer:"
                " ssh <ssh-host> sudo tvgw backup --export > tvgw.db.age (make backup does that)",
                file=sys.stderr,
            )
            return 2
        sys.stdout.flush()
        code, said = backup.export(backup.directory(s.state_dir), s.backup_recipient, sys.stdout.fileno())
        print(f"tvgw backup --export: {said}", file=sys.stderr)
        return code
    if a.keep < 1:
        print("tvgw backup: error: --keep must be at least 1", file=sys.stderr)
        return 2
    try:
        b = backup.run(s.db_path, backup.directory(s.state_dir), keep=a.keep)
    except (sqlite3.Error, OSError, RuntimeError) as e:
        print(f"tvgw backup: FAILED: {e}", file=sys.stderr)
        _record_backup(s.db_path, backup.failure(e))
        return 1
    _record_backup(s.db_path, None)
    removed = f"; removed {', '.join(b.removed)}" if b.removed else ""
    print(f"tvgw backup: {b.path} ({b.size / 1e6:.1f} MB, quick_check ok); {len(b.kept)} kept{removed}")
    return 0


def cmd_restore(a, s, prof) -> int:
    """(reliability) `tvgw restore --check FILE`: backup.restore_check. Needs no settings, so it runs on the
    owner's computer, where the key that opens an encrypted copy is."""
    from tvgw import backup

    drill = backup.restore_check(a.check, a.identity)
    for line in drill.lines:
        print(f"tvgw restore --check: {line}", file=sys.stdout if drill.ok else sys.stderr)
    if not drill.ok and drill.lines and "give --identity" in drill.lines[0]:
        return 2
    return 0 if drill.ok else 1


def cmd_seal(a, s, prof) -> int:
    """(reliability) `tvgw seal hold|release|sync`: src/tvgw/seal.py."""
    from tvgw import seal

    return seal.main(s, a.action)


def _record_backup(db_path: str, why: str | None) -> None:
    """(depth) A result that cannot be recorded is said on stderr and changes nothing else: the copy is made
    or not made either way, and verify then reports the last result it can read."""
    from tvgw import backup

    try:
        backup.record(db_path, why)
    except sqlite3.Error as e:
        print(f"tvgw backup: could not record the result in the store: {e}", file=sys.stderr)


def cmd_sql(a, s, prof) -> int:
    sql = " ".join(a.query)
    if not re.match(r"\s*(select|with|explain|pragma|values)\b", sql, re.I):
        sys.exit("read-only: SELECT, WITH, EXPLAIN, PRAGMA or VALUES only")
    conn = _ro(s)
    conn.execute("PRAGMA query_only=1")
    try:
        cur = conn.execute(sql)
        rows = cur.fetchall()
    except sqlite3.Error as e:
        sys.exit(f"sql: {e}")
    table(rows, [d[0] for d in cur.description or []])
    return 0


def cmd_forget(a, s, prof) -> int:
    """(record) Delete the viewing record, keep the gateway: src/tvgw/forget.py."""
    from tvgw import forget

    if not a.dry_run and not a.yes:
        if not sys.stdin.isatty():
            print(
                "tvgw forget: error: it deletes the viewing record; pass --yes, or run it at a terminal",
                file=sys.stderr,
            )
            return 2
        print(
            "tvgw forget deletes every viewing-derived row and file (tvgw forget --dry-run lists what"
            " goes). Of the firewall's counters it keeps one total each, and no timeline."
        )
        if input("Type forget to go on: ").strip() != "forget":
            print("tvgw forget: nothing done")
            return 1
    r = forget.run(s, dry_run=a.dry_run, querylog=a.querylog)
    verb = {"delete-rows": "rows", "empty": "empty", "delete": "delete", "backup": "backup"}
    head = "would go" if a.dry_run else "gone"
    rows = [
        (verb[st.action], st.what, st.count, hb(st.size) if st.size else "")
        for st in r.steps
        if st.action in verb and (st.count or st.action == "empty")
    ]
    print(f"tvgw forget: {head}:")
    table(rows, ["what", "table or path", "rows or files", "size"])
    kept = [(st.what, st.why) for st in r.steps if st.action == "keep"]
    if kept:
        print("\nkept:")
        table(kept, ["table or path", "why"])
    odd = [st.what for st in r.steps if st.action == "unclassified"]
    for what in odd:
        print(f"tvgw forget: WARNING {clean(what)}: not classified, kept", file=sys.stderr)
    print("\nnot reached by tvgw:")
    for line in r.residue:
        print(f"  - {line}")
    for w in r.warnings:
        print(f"tvgw forget: WARNING {clean(w)}", file=sys.stderr)
    return 1 if r.warnings or odd else 0


def _day(text: str) -> str:
    try:
        queries.day_bounds(text)
    except ValueError:
        raise argparse.ArgumentTypeError(f"{text!r}: use YYYY-MM-DD") from None
    return text


def _week(text: str) -> str:
    try:
        queries.week_bounds(text)
    except ValueError:
        raise argparse.ArgumentTypeError(f"{text!r}: use YYYY-Www") from None
    return text


def _when(text: str) -> float:
    try:
        return queries.since_epoch(text)
    except ValueError:
        raise argparse.ArgumentTypeError(f"{text!r}: use 2h, 1d, 7d or an ISO date/time") from None


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="tvgw", description=__doc__)
    p.add_argument("--version", action="version", version=f"tvgw {__version__}")
    p.add_argument(
        "--conf", default="/etc/tvgw/tvgw.conf", help="settings file (default /etc/tvgw/tvgw.conf)"
    )
    p.add_argument("--db", help="override the database path")
    sub = p.add_subparsers(dest="cmd", required=True)
    sub.add_parser("ingest", help="load new log/pcap data into the store").set_defaults(fn=cmd_ingest)
    sub.add_parser(
        "prune-pcaps",
        help="delete raw pcaps past PCAP_DAYS or PCAP_MAX_GB: ingested files only, never the live one",
    ).set_defaults(fn=cmd_prune_pcaps)
    b = sub.add_parser("brief", help="one-screen daily brief (default: yesterday)")
    b.add_argument("day", nargs="?", type=_day)
    form = b.add_mutually_exclusive_group()  # (plain) the brief's form; without one, BRIEF_STYLE decides
    form.add_argument("--json", action="store_true")
    form.add_argument("--plain", action="store_true", help="the day in plain words (BRIEF_STYLE=plain)")
    form.add_argument("--full", action="store_true", help="the engineering brief (BRIEF_STYLE=full, default)")
    form.add_argument(
        "--action",
        action="store_true",
        help="only the plain brief's action as TIER<tab>TEXT, or nothing (tvgw-analyze: reports/action.txt)",
    )
    b.set_defaults(fn=cmd_brief)
    for name, fn, help_ in (
        ("new-hosts", cmd_new_hosts, "names first seen since SINCE"),
        ("retries", cmd_retries, "blocked names the TV keeps asking for"),
        ("allowed", cmd_allowed, "allowed names outside the profile's expected categories"),
        ("top-upload", cmd_top_upload, "destinations by bytes the TV sent"),
        ("gfts", cmd_gfts, "URL-filter requests by status and biz_code"),
        ("tvstate", cmd_tvstate, "hourly power state and settings changes"),
    ):
        sp = sub.add_parser(name, help=help_)
        sp.add_argument(
            "since", nargs="?", default="1d", type=_when, help="2h, 1d, 7d or an ISO time (default 1d)"
        )
        sp.set_defaults(fn=fn)
    h = sub.add_parser("host", help="everything about one name")
    h.add_argument("name")
    h.set_defaults(fn=cmd_host)
    rl = sub.add_parser("rules", help="our policy as history; --local: your own site rules")
    rl.add_argument(
        "--local", action="store_true", help="the rules tvgw allow and tvgw block wrote (LOCAL_RULES)"
    )
    # (rule use) the window of --local's counts, and its form for scripts (design decision 82)
    rl.add_argument(
        "--since",
        type=_when,
        help="with --local: count since 2h, 1d, 7d or an ISO time (default 7 and 30 days)",
    )
    rl.add_argument("--json", action="store_true", help="with --local: every rule and count as JSON")
    rl.set_defaults(fn=cmd_rules)
    sub.add_parser("size", help="row counts and file size").set_defaults(fn=cmd_size)
    an = sub.add_parser(
        "analyst", help="one day's evidence read by Claude as proposals (never applied); needs the key file"
    )
    an.add_argument("--day", help="YYYY-MM-DD (default: ANALYST_WINDOW, normally yesterday)")
    an.add_argument("--since", help="the last N hours instead of a day, e.g. 6h")
    an.add_argument("--week", help="one ISO week, e.g. 2026-W43 (Monday to Sunday)")
    an.add_argument(
        "--weekly",
        action="store_true",
        help="the week that ended most recently, with the weekly model and effort",
    )
    an.add_argument("--model", help="model id for this run (default: ANALYST_MODEL)")
    an.add_argument(
        "--effort", choices=config.EFFORTS, help="reasoning depth for this run (default: ANALYST_EFFORT)"
    )
    an.add_argument("--dry-run", action="store_true", help="write the pack and prompt, send nothing")
    an.add_argument("--show", action="store_true", help="print the newest proposals")
    an.add_argument("--force", action="store_true", help="ask even when nothing new happened")
    un = sub.add_parser(
        "undo", help="revert the newest rule the gateway added on its own (design decision 20)"
    )
    un.add_argument("--all", action="store_true", help="revert every machine rule")
    un.set_defaults(fn=cmd_undo)
    ab = sub.add_parser(
        "autoblock", help="the rules the gateway added on its own: check (hourly re-judgement) or list"
    )
    ab.add_argument("action", choices=["check", "list", "calibrate"])
    ab.add_argument(
        "--no-watch",
        action="store_true",
        help="check: judge only, never run an armed canary (the TV is not watched; the hardware suite)",
    )
    # (ledger) calibrate: placebo trials of each judge design over the store's history (read-only)
    ab.add_argument("--days", type=int, default=60, help="with calibrate: days of history (default 60)")
    ab.add_argument(
        "--arms",
        default="A,B,C,D",
        help="with calibrate: A shipped, B clean hours, C judge v2 prorated, D judge v2 end-time (shadow)",
    )
    ab.add_argument("--by-class", action="store_true", help="with calibrate: add the per-hour classes")
    ab.add_argument(
        "--breakage", type=float, default=0.3, help="with calibrate: the byte scale power is measured at"
    )
    ab.set_defaults(fn=cmd_autoblock)
    # (ledger) the change ledger (design decision 48)
    ch = sub.add_parser("changes", help="the change ledger: what changed on the gateway, and when")
    ch.add_argument(
        "since", nargs="?", default="1d", type=_when, help="2h, 1d, 7d or an ISO time (default 1d)"
    )
    ch.add_argument("--note-deploy", metavar="VERSION", help="append a deploy line to the spool (install.sh)")
    ch.set_defaults(fn=cmd_changes)
    tp = sub.add_parser("tvprobe", help="hold one read-only LAN-API session and log power and app changes")
    tp.add_argument("--hours", type=float, default=26.0, help="stop after this many hours (default 26)")
    tp.add_argument("--out", help="the events file (default <STATE_DIR>/probe/tvprobe.jsonl)")
    tp.add_argument("--key-file", default="/var/lib/tvgw/lgtv-keys.sqlite")
    tp.set_defaults(fn=cmd_tvprobe)
    # (probe) the test client beside the TV's port (design decision 65); --across and --netns are tvgw-apply's
    # and the namespace tier's, not a person's
    pb = sub.add_parser(
        "probe", help="is the gateway's path for the TV whole? a test client beside the TV's port (root)"
    )
    pb.add_argument("--json", action="store_true")
    pb.add_argument("--across", metavar="DIR", help=argparse.SUPPRESS)
    pb.add_argument("--netns", default="", help=argparse.SUPPRESS)
    pb.set_defaults(fn=cmd_probe)
    an.set_defaults(fn=cmd_analyst)
    sub.add_parser(
        "dnsgate-feed", help="feed the DNS-gate set from the resolver's answers to the TV (runs as a service)"
    ).set_defaults(fn=cmd_dnsgate_feed)
    sub.add_parser(
        "dnsgate-inpath",
        help="hold each DNS answer to the TV until its addresses are in the gate's in-path set"
        " (runs as a service, with DNSGATE_FILL=inpath)",
    ).set_defaults(fn=cmd_dnsgate_inpath)
    sub.add_parser(
        "names-tap",
        help="count each TLS connection of the TV against the names its answers gave the address"
        " (runs as a service, with NAME_BINDING=count)",
    ).set_defaults(fn=cmd_names_tap)
    sub.add_parser(
        "attention-hold",
        help="hold the live reading's word of the TV's state in the firewall's dead-man entries"
        " (runs as a service, with LIVE_READING=on)",
    ).set_defaults(fn=cmd_attention_hold)
    sub.add_parser(
        "attention",
        help="whether the attention count runs, the state the firewall holds and what it counted (root)",
    ).set_defaults(fn=cmd_attention)
    bk = sub.add_parser(
        "backup", help="a checked copy of the store in <STATE_DIR>/backup (VACUUM INTO + quick_check)"
    )
    bk.add_argument(
        "--keep",
        type=int,
        default=7,
        help="days to keep a copy of, newest first, plus the newest copy (default 7)",
    )
    bk.add_argument(
        "--export",
        action="store_true",
        help="(reliability) write the newest checked copy, encrypted with age to BACKUP_RECIPIENT, to"
        " standard output, for make backup to pull to another computer",
    )
    bk.set_defaults(fn=cmd_backup)
    # (reliability) the restore drill: needs no settings, so it runs where the age key is
    rs = sub.add_parser("restore", help="prove a copy of the store restores, into a scratch store")
    rs.add_argument("--check", required=True, metavar="FILE", help="a copy: a .db, or an encrypted .db.age")
    rs.add_argument("--identity", metavar="KEY", help="the age key file an encrypted copy was made for")
    rs.set_defaults(fn=cmd_restore, needs_conf=False)
    # (reliability) the gateway's own plain lookups held off the uplink while the tunnel is down
    se = sub.add_parser(
        "seal",
        help="with VPN_DNS_SEAL=on, hold this computer's own plain lookups off the uplink while the VPN's"
        " tunnel is down (the dispatcher and tvgw-vpnseal run it)",
    )
    se.add_argument("action", choices=("hold", "release", "sync"))
    se.set_defaults(fn=cmd_seal)
    # (record) docs/use/privacy.md#forget-the-viewing-record
    fg = sub.add_parser(
        "forget", help="delete the viewing record (store rows, pcaps, reports, logs); keep the gateway"
    )
    fg.add_argument(
        "--dry-run", action="store_true", help="list what would go, with counts only; change nothing"
    )
    fg.add_argument("--yes", action="store_true", help="do not ask")
    fg.add_argument("--querylog", action="store_true", help="also empty AdGuard Home's query log")
    fg.set_defaults(fn=cmd_forget)
    q = sub.add_parser("sql", help="read-only SQL")
    q.add_argument("query", nargs="+")
    q.set_defaults(fn=cmd_sql)
    r = sub.add_parser(
        "report", help="the brief over a window: a day, an ISO week, or --since/--until (default: last 24 h)"
    )
    window = r.add_mutually_exclusive_group()
    window.add_argument("--day", type=_day, help="YYYY-MM-DD")
    window.add_argument("--week", type=_week, help="ISO week, e.g. 2026-W44 (Monday to Sunday)")
    window.add_argument("--since", type=_when, help="2h, 1d, 7d or an ISO time")
    r.add_argument("--until", type=_when, help="same forms; default now (with --since only)")
    r.add_argument("--json", action="store_true")
    r.add_argument(
        "--with-plain",
        action="store_true",
        help="with --day: the plain brief first, then the full one (tvgw-analyze with BRIEF_STYLE=plain)",
    )
    r.set_defaults(fn=cmd_report)
    d = sub.add_parser("discover", help="find the TV on the TV-side network; --write records its identity")
    d.add_argument("--iface", help="TV-side interface (default: the configured one)")
    d.add_argument(
        "--write", action="store_true", help="write TV_MAC/TV_IP/TV_NAME/PROFILE into the settings file"
    )
    d.add_argument("--yes", action="store_true", help="with --write: take the first candidate without asking")
    d.add_argument("--name", help="with --write: the TV_NAME to use (default: from the announced hostname)")
    d.add_argument("--no-ssdp", action="store_true", help="skip the SSDP search")
    d.add_argument("--json", action="store_true")
    d.set_defaults(fn=cmd_discover)
    pr = sub.add_parser("profile", help="what the TV profile knows: must-allow, lint, generations, hardware")
    pr.add_argument("--profile", help="bundled name or TOML path (default: the configured one)")
    pr.add_argument("--model", help="model number, e.g. OLED65C2PUA: print the hardware facts and checklist")
    pr.add_argument("--webos", help="webOS version, e.g. 5.6.2 or 25")
    pr.add_argument("--firmware", help="firmware version, e.g. 33.31.61")
    pr.add_argument("--release", help="the webOS release the TV reports in its hello reply, e.g. 11.2.0")
    pr.add_argument(  # (ports) design decision 71
        "--firewall",
        action="store_true",
        help="print only the profile's firewall keys, one KEY=value a line, as tvgw-apply reads them",
    )
    pr.set_defaults(fn=cmd_profile)
    v = sub.add_parser("verify", help="check that firewall, routing, resolver and services still hold")
    v.add_argument("--record", action="store_true", help="also store the verdict and firewall counters")
    v.add_argument("--json", action="store_true")
    v.set_defaults(fn=cmd_verify)
    t = sub.add_parser(
        "tvcheck", help="read the TV over its LAN API (LG webOS once paired; Samsung Tizen without pairing)"
    )
    t.add_argument("--key-file", default="/var/lib/tvgw/lgtv-keys.sqlite")
    t.set_defaults(fn=cmd_tvcheck)
    _add_tv_parser(sub)
    _add_adguard_parser(sub)
    _add_doctor_parser(sub)
    _add_status_parser(sub)
    _add_localrules_parser(sub)
    _add_resolver_parser(sub)  # (resolver) design decision 81
    _add_check_parser(sub)
    _add_refused_parser(sub)
    _add_pause_parser(sub)  # (pause) design decision 79
    _add_activity_parser(sub)
    _add_uplink_parser(sub)  # (uplink quality) design decision 78
    bu = sub.add_parser("budget", help="the upload budget's ceiling and how it was set")  # (budget)
    bu.add_argument("--json", action="store_true")
    bu.add_argument(
        "--rederive", action="store_true", help="set the ceiling again from the 14 days before today (root)"
    )
    bu.set_defaults(fn=cmd_budget)
    # (listguard) the subscribed lists against the TV's own rules (design decision 68)
    li = sub.add_parser(
        "lists", help="what the subscribed blocklists say about the TV's own rules, and what each refused"
    )
    li.add_argument("--json", action="store_true")
    li.add_argument("--scan", action="store_true", help="scan AdGuard Home's lists now (root)")
    # (rule use) the window of the refusals by list (design decision 82)
    li.add_argument(
        "--since", default="7d", type=_when, help="refusals since 2h, 1d, 7d or an ISO time (default 7d)"
    )
    li.set_defaults(fn=cmd_lists)
    _add_threats_parser(sub)  # (threats) design decision 80
    po = sub.add_parser(  # (ports) design decision 71
        "ports", help="whether STRICT_PORTS and the clock port's narrowing have two clean weeks to refuse on"
    )
    po.add_argument("--json", action="store_true")
    po.add_argument(
        "--ntp-seen",
        action="store_true",
        help="print only the TV's NTP requests the record holds for 14 days, as tvgw-apply reads them",
    )
    po.set_defaults(fn=cmd_ports)
    _add_receipt_parser(sub)  # (app in front) design decision 67
    _add_tvlive_parser(sub)
    _add_experiment_parser(sub)  # (experiments) design decision 75
    _add_evidence_parser(sub)
    _add_requests_parser(sub)
    _add_mint_parser(sub)  # (mint) design decision 85
    _add_screen_parser(sub)  # (screentest) design decision 88
    _add_web_parser(sub)  # (web) design decision 76
    _add_updates_parser(sub)  # (updates) design decision 77
    # (setup) the guided installer: docs/install/README.md
    su = sub.add_parser("setup", help="guided install: find the TV, pair, write the settings, apply, verify")
    su.add_argument("--answers", metavar="FILE", help="answers for an unattended run (tvgw.conf format)")
    su.add_argument("--yes", action="store_true", help="ask nothing: take the answers file or each default")
    su.add_argument("--dry-run", action="store_true", help="print every change, change nothing")
    su.add_argument("--installer", metavar="PATH", help="install.sh to apply with (default: found)")
    su.add_argument("--no-ssdp", action="store_true", help="skip the SSDP search")
    su.set_defaults(fn=cmd_setup)
    # (guard) install.sh's co-tenant step: design decision 42
    gd = sub.add_parser("guard", help="co-tenant filters against the TV subnet (install.sh runs this)")
    gd.add_argument(
        "action",
        choices=["cotenants", "avahi"],
        help="cotenants: write or remove the IPAddressDeny drop-ins; avahi: deny the TV port in its conf",
    )
    gd.add_argument("--dry-run", action="store_true", help="print what would change, change nothing")
    gd.add_argument("--unit-dir", default="/etc/systemd/system", help=argparse.SUPPRESS)
    gd.add_argument("--avahi-conf", default="/etc/avahi/avahi-daemon.conf", help=argparse.SUPPRESS)
    gd.set_defaults(fn=cmd_guard)
    return p


def _add_threats_parser(sub) -> None:
    """(threats) `tvgw threats [SINCE]`: the TV's names on the downloaded lists (design decision 80)."""
    th = sub.add_parser("threats", help="names the TV looked up that a threat or new-domain list covers")
    th.add_argument(
        "since", nargs="?", default="7d", type=_when, help="2h, 1d, 7d or an ISO time (default 7d)"
    )
    act = th.add_mutually_exclusive_group()
    act.add_argument("--json", action="store_true")
    act.add_argument("--update", action="store_true", help="download the lists now (root)")
    act.add_argument("--match", metavar="DAY", type=_day, help="match one day's names now (root)")
    th.set_defaults(fn=cmd_threats)


def _add_tv_parser(sub) -> None:
    """(pairing) `tvgw tv`, the commands about the TV itself. `tv pair` is the explicit pairing: besides
    setup, the one command that may put the pairing prompt on the TV (design decision 54). `tv quiet` is
    the deploy window's check (design decision 63). `tv confirm` records what the owner saw on the TV's
    screen (design decision 57)."""
    tv = sub.add_parser(
        "tv", help="the TV: pair with its LAN API; record what its screen shows; whether a deploy may run now"
    )
    actions = tv.add_subparsers(dest="tv_action", required=True)
    pr = actions.add_parser("pair", help="pair with the TV's LAN API, read-only: accept the prompt on the TV")
    pr.add_argument("--key-file", default="/var/lib/tvgw/lgtv-keys.sqlite")
    # (W12) the manifest the pairing sends: tvgw's unsigned read-only one for a new pairing, the manifest
    # the stored key was made with otherwise; `signed` is the library's, which LG's newer firmware refuses
    pr.add_argument(
        "--manifest",
        choices=["signed", "unsigned"],
        help="the permissions list to pair with: unsigned (tvgw's read-only list, the default for a new"
        " pairing) or signed (the library's LG Remote App list, which the reference CX was paired with)",
    )
    pr.set_defaults(fn=cmd_tv_pair)
    _add_tv_quiet_parser(actions)
    # (depth) the owner's dated word on a setting the TV does not report (onscreen.py, design decision 57)
    from tvgw import onscreen

    cf = actions.add_parser(
        "confirm", help="record what you saw on the TV's screen, for a setting the gateway cannot read"
    )
    cf.add_argument("setting", choices=list(onscreen.SETTINGS))
    cf.add_argument("value", choices=sorted({v for vals in onscreen.SETTINGS.values() for v in vals}))
    cf.set_defaults(fn=cmd_tv_confirm)


def _window(text: str) -> str:
    from tvgw import quiet

    try:
        quiet.parse_window(text)
    except ValueError as e:
        raise argparse.ArgumentTypeError(str(e)) from None
    return text


def _bounded(low: int, high: int):
    def parse(text: str) -> int:
        try:
            n = int(text)
        except ValueError:
            n = low - 1
        if not low <= n <= high:
            raise argparse.ArgumentTypeError(f"{text!r}: a whole number from {low} to {high}")
        return n

    return parse


def _add_tv_quiet_parser(actions) -> None:
    """(deploy window) `tvgw tv quiet`: the check before a deploy that changes the network (design
    decision 63), asked by whoever deploys and by `tvgw updates`. Read-only; one line out, never the
    reason."""
    from tvgw import quiet

    q = actions.add_parser(
        "quiet",
        help="exit 0 and print 'deploy: now' when a deploy may run (in the window, the TV quiet), else 1",
    )
    q.add_argument("--window", type=_window, metavar="HH:MM-HH:MM", help="the hours (default DEPLOY_WINDOW)")
    q.add_argument(
        "--idle",
        type=_bounded(1, 1440),
        default=quiet.IDLE_MINUTES,
        metavar="MIN",
        help=f"minutes the TV port must have moved under 1 MB (default {quiet.IDLE_MINUTES})",
    )
    q.add_argument(
        "--wait",
        type=_bounded(0, quiet.MAX_WAIT),
        default=0,
        metavar="SEC",
        help="also watch the TV port for this many seconds (default 0)",
    )
    q.set_defaults(fn=cmd_tv_quiet)


def cmd_tv_quiet(a, s, prof) -> int:
    from tvgw import quiet

    return quiet.main(s, a.window, a.idle, a.wait)


def _add_doctor_parser(sub) -> None:
    """(depth) `tvgw doctor`: every check that did not pass, in plain words, with its fix (root)."""
    d = sub.add_parser(
        "doctor", help="what is wrong with the gateway, in plain words, and the fix for each (root)"
    )
    d.add_argument("--fix", action="store_true", help="do every fix it offers, after one question")
    d.add_argument("--yes", action="store_true", help="ask nothing: do every fix it offers")
    d.set_defaults(fn=cmd_doctor)


def _add_status_parser(sub) -> None:
    """(depth) `tvgw status`: three lines about now, from the last check's status file alone. It reads no
    settings file, so cli.main skips loading one (`needs_conf`)."""
    st = sub.add_parser("status", help="is it working now? three lines from the last check (no root needed)")
    st.set_defaults(fn=cmd_status, needs_conf=False)


def cmd_doctor(a, s, prof) -> int:
    from tvgw import doctor

    return doctor.main(s, prof, doctor.live_env(s, prof, a.conf), fix=a.fix, yes=a.yes)


def cmd_status(a, s, prof) -> int:
    from tvgw import status

    return status.main()


def cmd_tv_confirm(a, s, prof) -> int:
    """(depth) Append the owner's answer to the on-screen record; the hourly ingest stores it."""
    from tvgw import onscreen

    try:
        c = onscreen.record(a.setting, a.value, onscreen.log_path(s.state_dir))
    except ValueError as e:
        print(f"tvgw tv confirm: error: {e}", file=sys.stderr)
        return 2
    when = onscreen.stamp(c.t)
    print(f"recorded {c.key} {c.value} at {when}; the brief reads it after the next hourly ingest")
    return 0


def _add_localrules_parser(sub) -> None:
    """(site rules) `tvgw allow`, `block`, `unallow` and `unblock`: the owner's own rules (decision 59)."""
    for name, help_ in (
        ("allow", "let a name the lists block through for the TV (writes LOCAL_RULES, re-applies AdGuard)"),
        ("block", "block a name for the TV (writes LOCAL_RULES, re-applies AdGuard)"),
        ("unallow", "take your own allow of a name out again"),
        ("unblock", "take your own block of a name out again"),
    ):
        sp = sub.add_parser(name, help=help_)
        sp.add_argument("name", help="the name, such as ads.example; every name under it is included")
        if name in ("allow", "block"):
            sp.add_argument("--reason", default="", help="why, kept in the comment line above the rule")
        if name == "allow":
            sp.add_argument(
                "--force",
                action="store_true",
                help="allow a whole domain the profile files under tracking (ads, telemetry, ACR)",
            )
        sp.set_defaults(fn=cmd_localrules, verb=name)


def _add_check_parser(sub) -> None:
    """(adguard) `tvgw check NAME`: what the filter does with one name for the TV, and why."""
    ck = sub.add_parser("check", help="is a name blocked for the TV, by which list or rule, and the fix")
    ck.add_argument("name", help="the name, such as ads.example")
    ck.set_defaults(fn=cmd_check)


def _ask_terminal(prompt: str, secret: bool) -> str:
    """(adguard) One answer typed at the terminal; a secret one is not echoed."""
    import getpass

    return getpass.getpass(prompt) if secret else input(prompt)


def cmd_check(a, s, prof) -> int:
    """(adguard) Root only: it reads AdGuard Home's YAML and the password tvgw keeps for its page. Exit 0
    allowed, 1 blocked, 2 could not ask. With no password kept, it asks for one at a terminal only.
    Every line goes through clean(): a rule's text comes from a list someone else writes."""
    from tvgw import namecheck

    if os.geteuid() != 0:
        print(
            "tvgw check: it asks AdGuard Home with its password; run it with sudo:"
            f" sudo tvgw check {clean(a.name)}"
        )
        return namecheck.UNASKED
    ask = _ask_terminal if sys.stdin.isatty() else None
    done = namecheck.run(s, prof, a.name, ask=ask)
    for line in done.lines:
        print(clean(line))
    return done.code


def _add_refused_parser(sub) -> None:
    """(refused) `tvgw refused`: the names the filter refused the TV in the last minutes, likeliest first."""
    rf = sub.add_parser(
        "refused",
        help="what the filter refused the TV in the last minutes, the likely cause of a broken app first",
    )
    rf.add_argument(
        "--since", default="10m", type=_when, help="10m, 2h or an ISO time, at most a day back (default 10m)"
    )
    rf.add_argument("--json", action="store_true", help="every name with every field, for tools")
    rf.add_argument("--all", action="store_true", help="list every name, not the first few of each kind")
    rf.set_defaults(fn=cmd_refused)


def cmd_refused(a, s, prof) -> int:
    """(refused) Root only, as `check` is: it reads AdGuard Home's YAML, its query log and the password tvgw
    keeps for its page. Exit 0 nothing likely to have broken an app was refused, 1 a name that likely
    was, 2 when it could not read the log or ask AdGuard; with --json even that is a JSON object. Every
    line goes through clean(): names come from the TV and rules from lists someone else writes."""
    from tvgw import refused

    def failed(lines: list[str], found=()) -> int:
        if a.json:  # (ports) with what the firewall refused all the same
            doc = {"error": " ".join(lines), "code": refused.UNREAD}
            if found:
                doc["firewall"] = [refused.wall_json(w) for w in found]
            print(json.dumps(doc, indent=1))
        else:
            for line in lines:
                print(clean(line))
        return refused.UNREAD

    if os.geteuid() != 0:
        return failed(
            [
                "tvgw refused: it reads AdGuard Home's query log and asks it with its password; run it with"
                " sudo:",
                "  sudo tvgw refused",
            ]
        )
    now = time.time()
    # argparse read --since a moment ago: 1d is the whole day, not a day and the parse's milliseconds
    if not now - refused.MAX_WINDOW - 60 <= a.since < now:
        return _usage("--since must be in the last day: 10m, 2h or a time today", "refused")
    ask = _ask_terminal if sys.stdin.isatty() and not a.json else None
    done = refused.run(s, prof, a.since, now, ask=ask)
    if done.report is None:
        return failed(done.lines if not a.json else done.lines[:1], done.walls)
    if a.json:
        print(json.dumps(refused.as_json(done.report), indent=1))
    else:
        for line in refused.render(done.report, show_all=a.all):
            print(clean(line))
    return done.code


def _add_pause_parser(sub) -> None:
    """(pause) `tvgw pause`: the shared tracker lists off for a few minutes, then what they were stopping."""
    from tvgw import listpause

    pa = sub.add_parser(
        "pause",
        help="switch the shared tracker lists off for a few minutes to see whether they broke an app; they"
        " come back on their own",
    )
    pa.add_argument(
        "minutes",
        nargs="?",
        type=int,
        metavar="MINUTES",
        help=f"how long, 1 to {listpause.MAX_MINUTES} (default {listpause.DEFAULT_MINUTES})",
    )
    mode = pa.add_mutually_exclusive_group()
    mode.add_argument("--end", action="store_true", help="bring the lists back now")
    mode.add_argument(
        "--status", action="store_true", help="whether a pause is in force, and until when (adm is enough)"
    )
    mode.add_argument(
        "--report",
        action="store_true",
        help="what the TV reached during the last pause that the lists block again, the likely cause first",
    )
    pa.add_argument("--yes", action="store_true", help="pause without the question")
    pa.add_argument("--timer", action="store_true", help=argparse.SUPPRESS)  # the end the timer runs
    pa.set_defaults(fn=cmd_pause)


def cmd_pause(a, s, prof) -> int:
    """(pause) `--status` reads the store alone; everything else is root's, since it changes AdGuard Home or
    asks it with its password. Every line goes through clean(): a name comes from the TV, a rule from a
    list someone else writes."""
    from tvgw import listpause

    def show(done) -> int:
        for line in done.lines:
            print(clean(line))
        return done.code

    extra = (a.end or a.status or a.report) and (a.minutes is not None or a.yes)
    if extra or (a.timer and not a.end):
        return _usage("MINUTES and --yes go with a start alone, --timer with --end", "pause")
    if a.status:
        return show(listpause.status(s))
    if os.geteuid() != 0:
        what = "--end" if a.end else "--report" if a.report else str(a.minutes or listpause.DEFAULT_MINUTES)
        print("tvgw pause: it changes AdGuard Home's lists or asks it with its password; run it with sudo:")
        print(f"  sudo tvgw pause {what}")
        return listpause.REFUSED
    ask = _ask_terminal if sys.stdin.isatty() else None
    if a.report:
        return show(listpause.last_report(s, prof, ask=ask))
    if a.end:
        if a.timer:  # the transient unit's journal: no terminal, no password asked
            done = listpause.end_by_timer(s, prof, say=lambda line: print(clean(line), flush=True))
        else:
            done = listpause.end(s, prof, listpause.EARLY)
        code = show(done)
        if done.code == listpause.OK and done.pause is not None and done.pause.how is not None:
            sys.stdout.flush()
            show(listpause.report(s, prof, done.pause, ask=None if a.timer else ask))
        return code
    minutes = listpause.DEFAULT_MINUTES if a.minutes is None else a.minutes
    if not 1 <= minutes <= listpause.MAX_MINUTES:
        return _usage(f"MINUTES is 1 to {listpause.MAX_MINUTES}", "pause")
    now = time.time()
    try:
        refused = listpause.refusal(prof, listpause.read(s.db_path), now)
    except sqlite3.Error as e:
        print(f"tvgw pause: cannot read the gateway's record ({e}); nothing changed")
        return listpause.REFUSED
    if refused is not None:
        return show(refused)
    for line in listpause.describe(prof, s, minutes, now):
        print(clean(line))
    if not a.yes:
        if not sys.stdin.isatty():
            print("tvgw pause: nothing changed; add --yes to pause without the question")
            return listpause.REFUSED
        try:
            answer = input(f"Pause the shared blocklists for {minutes} minutes? [y/N] ")
        except EOFError:
            answer = ""
        if answer.strip().lower() not in ("y", "yes"):
            print("tvgw pause: nothing changed")
            return listpause.REFUSED
    # the timer's end reads the same settings file and store this start did
    return show(listpause.start(s, prof, minutes, argv=listpause.end_argv(a.conf, a.db)))


def _add_activity_parser(sub) -> None:
    """(activity) `tvgw activity calibrate`: the TV port's counters held against the TV's own readings."""
    ac = sub.add_parser("activity", help="when the TV was on, from its port's traffic, held against readings")
    ac.add_argument("action", choices=["calibrate"])
    ac.add_argument("--days", type=int, default=14, help="days of readings to compare (default 14)")
    ac.add_argument("--json", action="store_true")
    ac.set_defaults(fn=cmd_activity)


def cmd_activity(a, s, prof) -> int:
    from tvgw import activity

    if not 1 <= a.days <= 400:
        return _usage("--days must be 1 to 400", "activity")
    conn = _ro(s)
    result = activity.calibrate(conn, time.time(), days=a.days)
    if a.json:
        print(json.dumps(result, indent=1))
    else:
        for line in activity.summary_lines(result):
            print(line)
    return 0


def _add_uplink_parser(sub) -> None:
    """(uplink quality) `tvgw uplink`: the gateway's link to the router, day by day (design decision 78)."""
    up = sub.add_parser("uplink", help="the gateway's link to your router while the TV was in use, by day")
    up.add_argument("--days", type=int, default=7, help="days to show, today first (default 7)")
    up.add_argument("--json", action="store_true")
    up.set_defaults(fn=cmd_uplink)


def cmd_uplink(a, s, prof) -> int:
    """(uplink quality) One row per local calendar day, today (so far) first, from the stored samples."""
    if not 1 <= a.days <= 400:
        return _usage("--days must be 1 to 400", "uplink")
    on = s.ledger == "on"
    if not on:
        if a.json:
            print(json.dumps({"ledger": False, "days": []}, indent=1))
        else:
            print(f"tvgw uplink: {uplink.NO_LEDGER}")
        return 0
    conn = _ro(s)
    now = time.time()
    today = datetime.fromtimestamp(now).date()
    days = []
    for i in range(a.days):
        day = (today - timedelta(days=i)).isoformat()
        since, until = queries.day_bounds(day)
        days.append({"day": day, **uplink.judge(conn, since, until, uplink_if=s.wan_if, now=now)})
    if a.json:
        print(json.dumps({"ledger": True, "days": days}, indent=1))
        return 0
    print(clean(uplink.title(days[0])))
    table([uplink.table_row(d["day"], d, today=i == 0) for i, d in enumerate(days)], uplink.TABLE_HEADERS)
    print(uplink.LEGEND)
    return 0


def _add_updates_parser(sub) -> None:
    """(updates) `tvgw updates`: what is waiting and what the gateway installed (design decision 77)."""
    u = sub.add_parser(
        "updates", help="tvgw, AdGuard Home and the system: what is waiting and what was installed, when"
    )
    u.add_argument("--json", action="store_true")
    what = u.add_mutually_exclusive_group()
    what.add_argument(
        "--now",
        action="store_true",
        help="install what UPDATE_INSTALL allows now, without the night window (root)",
    )
    what.add_argument(
        "--check-now", action="store_true", help="ask GitHub for tvgw's latest release now (root)"
    )
    what.add_argument(
        "--scheduled",
        action="store_true",
        help="tvgw-update.service's run: the weekly check, then the installs",
    )
    what.add_argument(
        "--after-reboot", action="store_true", help="tvgw-update-boot.service's check after a restart it made"
    )
    what.add_argument(
        "--configure",
        action="store_true",
        help="install.sh's step: apt's configuration and the timer's window",
    )
    u.set_defaults(fn=cmd_updates)


def cmd_updates(a, s, prof) -> int:
    """(updates) `tvgw updates` and its modes: the report needs no root; every mode that writes does."""
    from tvgw import updates

    writes = a.now or a.check_now or a.scheduled or a.after_reboot or a.configure
    if writes and os.geteuid() != 0:
        print("tvgw updates: this writes the gateway's record; run it with sudo")
        return 2
    if a.configure:
        for line in updates.configure(s, updates._write, updates._remove):
            print(f"tvgw updates: {line}")
        return 0
    if a.check_now:
        if s.update_check == "off" and s.update_install == "off":
            print(
                "tvgw updates: the gateway asks GitHub nothing while UPDATE_CHECK and UPDATE_INSTALL are off."
                f" The releases are at https://github.com/{s.update_repo}/releases"
            )
            return 1
        conn = db.connect(s.db_path)
        try:
            row = updates.weekly_check(s, conn, time.time(), updates.open_url, force=True)
        finally:
            conn.close()
        said = f"the latest release is {row.get('latest')}" if row.get("ok") else f"failed: {row.get('why')}"
        print(f"tvgw updates: checked GitHub; {said}")
        return 0 if row.get("ok") else 1
    if a.now:
        if s.update_install == "off":
            print(
                "tvgw updates: automatic installs are off (UPDATE_INSTALL=off), so the gateway installs"
                f" nothing itself. Install by hand: {updates.INSTALL_BY_HAND}; and sudo tvgw adguard upgrade"
                " --fetch"
            )
            return 1
        print(
            "tvgw updates: installing now; the TV may lose its connection for a minute while services restart"
        )
        run = updates.install(s, updates.live_env(s, prof, a.conf), "owner")
        print("tvgw updates: " + updates.run_sentence(run, ""))
        return 1 if run.get("result") in (updates.FAILED, updates.ROLLED_BACK) else 0
    if a.scheduled:
        return updates.scheduled(s, updates.live_env(s, prof, a.conf))
    if a.after_reboot:
        run = updates.after_reboot(s, updates.live_env(s, prof, a.conf))
        print("tvgw updates: " + (updates.run_sentence(run, "") if run else "no restart to check"))
        return 0
    return _updates_report(a, s)


def _updates_report(a, s) -> int:
    """(updates) The report: the store read-only (no store yet reads as nothing recorded), the system's
    reading stored by verify or read now, AdGuard's version from its binary, and the restart flag."""
    from tvgw import adguardcfg, updates

    conn = None
    if os.path.exists(s.db_path) and os.access(s.db_path, os.R_OK):
        with contextlib.suppress(sqlite3.Error):
            conn = db.connect(s.db_path, readonly=True, timeout=10)
    try:
        now = time.time()
        stored = updates.load_system(conn)
        system, _ = updates.system_state(stored, lambda argv: updates._run(argv, timeout=60)[1], now)
        check = updates.load_check(conn) if conn is not None else None
        runs = updates.load_runs(conn)
    finally:
        if conn is not None:
            conn.close()
    kind, deb = updates.installed_kind()
    exe = os.path.join(os.path.dirname(s.adguard_yaml), "AdGuardHome")
    flag = updates.REBOOT_FLAG
    reboot = None
    if os.path.exists(flag):
        try:
            with open(flag + ".pkgs", encoding="utf-8", errors="replace") as fh:
                reboot = len(set(fh.read().split()))
        except OSError:
            reboot = 0
    rep = updates.report(
        s, now, check, system, runs, kind, updates.upstream(deb) if deb else __version__,
        adguardcfg.binary_version(exe), reboot,
    )  # fmt: skip
    if a.json:
        print(json.dumps(rep.data, indent=1))
    else:
        for line in rep.lines:
            print(clean(line))
    return 0


def _add_tvlive_parser(sub) -> None:
    """(app in front) `tvgw tvlive`: the live reading's service, and what it would do (decision 67)."""
    tl = sub.add_parser(
        "tvlive", help="hold the live reading of an LG TV's power state and app in front (LIVE_READING=on)"
    )
    tl.add_argument("--key-file", help="the pairing key file (default <STATE_DIR>/lgtv-keys.sqlite)")
    mode = tl.add_mutually_exclusive_group()
    mode.add_argument(
        "--status", action="store_true", help="what the service would do and why; connects to nothing"
    )
    mode.add_argument(
        "--resume", action="store_true", help="let a service that stood down try again (removes its marker)"
    )
    mode.add_argument(
        "--listen",
        metavar="SECONDS",
        type=float,
        help="one session of SECONDS (1 to 60) by the service's own rules, printed; needs a reading that"
        " found the TV on",
    )
    tl.set_defaults(fn=cmd_tvlive)


def cmd_tvlive(a, s, prof) -> int:
    from tvgw import tvlive

    key_file = a.key_file or os.path.join(s.state_dir, "lgtv-keys.sqlite")
    if a.status:
        for line in tvlive.status_lines(s, key_file):
            print(clean(line))
        return 0
    if a.resume:
        was = tvlive.stood_down(key_file)
        if tvlive.resume(key_file):
            print(f"tvgw tvlive: it had stood down ({clean(was)}); it may try again now")
        else:
            print("tvgw tvlive: it had not stood down; nothing changed")
        return 0
    if a.listen is not None:
        if not 1 <= a.listen <= 60:
            return _usage("--listen takes 1 to 60 seconds", "tvlive")
        outcome, lines = tvlive.hear(s, key_file, a.listen)
        for rec in lines:
            fields = ", ".join(f"{k}={clean(v)}" for k, v in rec.items() if k not in ("t", "kind"))
            print(f"{ts(rec['t'], '%H:%M:%S')} {rec['kind']}{' ' + fields if fields else ''}")
        print(f"tvgw tvlive: {outcome}")
        return 1 if outcome in (tvlive.REFUSED, tvlive.FAILED, tvlive.UNSUPPORTED) else 0
    return tvlive.main(s, key_file)


def _add_web_parser(sub) -> None:
    """(web) `tvgw web`: the read-only page on the home network, behind a password (design decision 76)."""
    w = sub.add_parser(
        "web", help="the brief on your phone: a read-only page on the home network, off unless WEB=on"
    )
    w.add_argument(
        "web_action",
        metavar="ACTION",
        choices=["serve", "cert", "password", "status", "dropin"],
        help="status: how the page stands; cert: make its certificate; password: set its password;"
        " serve: run it (its unit does); dropin: print its unit's address filter (install.sh runs this)",
    )
    w.set_defaults(fn=cmd_web)


def cmd_web(a, s, prof) -> int:
    from tvgw import web

    return web.main(a.web_action, s, prof)


def _add_receipt_parser(sub) -> None:
    """(app in front) `tvgw receipt`: the TV's traffic by the app that was in front (design decision 67)."""
    rc = sub.add_parser("receipt", help="what the TV talked to, by the app that was in front")
    rc.add_argument(
        "--since",
        help="every session that started since: 2h, 1d, 7d or an ISO time (default: the newest session;"
        " 14d with --replay, 28d with --evaluate)",
    )
    rc.add_argument("--last", action="store_true", help="the newest evening only (the default)")
    view = rc.add_mutually_exclusive_group()
    view.add_argument(
        "--picture", action="store_true", help="what each app has been seen with, and on how many days"
    )
    view.add_argument(
        "--replay",
        action="store_true",
        help="what a rule keyed to the app in front would have refused; a report, nothing enforces",
    )
    view.add_argument(
        "--why", metavar="NAME", help="why a name counts as an app's company, the TV's own or new"
    )
    view.add_argument(
        "--evaluate",
        action="store_true",
        help="a developers' view, numbers only: how well the app in front explains the traffic (coverage,"
        " pictures, lag, lead)",
    )
    rc.add_argument(
        "--app", metavar="APP", help="with --picture or --why: one app, by the id the TV gives it"
    )
    rc.add_argument(
        "--events",
        metavar="FILE",
        nargs="+",
        help="take the live record from these files of JSON lines (tvgw tvprobe logs) instead of the store",
    )
    rc.add_argument(
        "--live-until",
        metavar="WHEN",
        help="with --events: the record is still being written, so a session that is up at its end is known"
        " up to WHEN (`now`, or an ISO time) rather than to the file's last line",
    )
    rc.add_argument("--json", action="store_true")
    rc.set_defaults(fn=cmd_receipt)


def cmd_receipt(a, s, prof) -> int:
    from tvgw import appeval, appfront, receipt

    now = time.time()
    since_arg = a.since
    try:
        a.since = None if a.since is None else queries.since_epoch(a.since)
    except ValueError:
        return _usage(f"--since {since_arg!r}: use 2h, 1d, 7d or an ISO date/time", "receipt")
    if a.since is not None and a.since >= now:
        return _usage("--since must be in the past", "receipt")
    if a.since is not None and a.since < now - s.db_days * 86400:
        return _usage(
            f"--since reaches past DB_DAYS ({s.db_days}): the store keeps no older readings", "receipt"
        )
    if a.since is not None and a.last:
        return _usage("--last and --since do not go together", "receipt")
    events, known_until = None, None
    if a.live_until and not a.events:
        return _usage("--live-until goes with --events", "receipt")
    if a.live_until:
        try:
            known_until = now if a.live_until == "now" else datetime.fromisoformat(a.live_until).timestamp()
        except ValueError:
            return _usage("--live-until takes now or an ISO time", "receipt")
        if known_until > now + 60:
            return _usage("--live-until must not be in the future", "receipt")
    if a.events:
        events = []
        for path in a.events:  # one run of a probe per file, or several runs appended to one
            try:
                events += appfront.read_events(path)
                if not a.live_until:  # a finished record: a session up at its end is known to its last line
                    known_until = max(known_until or 0.0, os.path.getmtime(path))
            except OSError as e:
                print(f"tvgw receipt: cannot read {path}: {e.strerror or e}", file=sys.stderr)
                return 1
    conn = _ro(s)

    def show(data, lines) -> int:
        if a.json:
            print(json.dumps(data, indent=1, default=sorted))
        else:
            for line in lines:
                print(clean(line))
        return 0

    if a.evaluate:
        since = a.since if a.since is not None else now - 28 * 86400
        if events is None:
            events = appfront.stored_events(conn, since - 86400, now)
        source = "a file" if a.events else "the store"
        result = appeval.evaluate(conn, prof, events, since, now, s.gw_ip, known_until, source)
        return show(result, appeval.render(result))
    if a.replay:
        since = a.since if a.since is not None else now - receipt.REPLAY_DAYS * 86400
        result = receipt.replay(receipt.gather(conn, prof, s.gw_ip, since, now, events, known_until, now))
        return show(result, receipt.render_replay(result))
    if a.picture or a.why:
        rec = receipt.gather(conn, prof, s.gw_ip, now - 3600, now, events, known_until, now)
        if a.why:
            lines = receipt.why(rec, a.why, a.app)
            return show({"name": a.why, "lines": lines}, lines)
        found = receipt.pictures(rec, a.app)
        return show(found, receipt.render_pictures(found))
    if a.since is None:  # the default screen: the newest evening, one block per app
        rec = receipt.gather(conn, prof, s.gw_ip, now - 2 * 86400, now, events, known_until, now)
        ev = receipt.evening(rec)
        # (did it work) the evening's failed starts, under its first line (design decision 72)
        starts = receipt.failed_starts(conn, rec, *receipt.evening_bounds(ev["day"])) if ev["day"] else []
        data = {"day": ev["day"], "blocks": ev["blocks"], "failed_starts": [f.as_dict() for f in starts]}
        return show(data, receipt.render_evening(rec, ev, starts))
    rec = receipt.gather(conn, prof, s.gw_ip, a.since, now, events, known_until, now)
    found = receipt.receipts(rec)
    gaps = receipt.gap_summary(rec)
    starts = receipt.failed_starts(conn, rec)  # (did it work)
    data = {"sessions": found, "gaps": gaps, "failed_starts": [f.as_dict() for f in starts]}
    return show(data, receipt.render(rec, found, gaps, since_arg, starts))


# ---- (experiments) design decision 75: report-only experiments, the evidence file, request drafts ----
# experiments.NAMES, without its import
EXPERIMENTS = ("probation", "platform", "fanout", "acr", "firmware", "adbreaks")


def _add_experiment_parser(sub) -> None:
    ex = sub.add_parser(
        "experiment", help="what a rule not built would have done, from the store; a report, nothing changes"
    )
    ex.add_argument("name", choices=EXPERIMENTS)
    ex.add_argument(
        "--days",
        type=int,
        default=14,
        help="days of record for platform, fanout, acr and adbreaks (default 14)",
    )
    ex.add_argument("--json", action="store_true")
    ex.set_defaults(fn=cmd_experiment)


def cmd_experiment(a, s, prof) -> int:
    from tvgw import experiments

    if not 1 <= a.days <= min(experiments.MAX_DAYS, s.db_days):
        return _usage(f"--days must be 1 to {min(experiments.MAX_DAYS, s.db_days)} (DB_DAYS)", "experiment")
    conn = _ro(s)
    result = experiments.run(a.name, conn, prof, time.time(), a.days, s.gw_ip)
    if a.json:
        print(json.dumps(experiments.json_ready(result), indent=1))
    else:
        for line in experiments.RENDER[a.name](result):
            print(clean(line))
    return 0


def _add_evidence_parser(sub) -> None:
    ev = sub.add_parser(
        "evidence", help="add the settled days' facts to a local hash-chained file; --verify checks the chain"
    )
    ev.add_argument("--days", type=int, default=30, help="how many days back to fill in (default 30)")
    ev.add_argument("--verify", action="store_true", help="check the file's chain; writes nothing")
    ev.add_argument(
        "--head",
        metavar="HASH",
        help="with --verify: a last line's SHA-256 you wrote down; a line must have it",
    )
    ev.add_argument("--file", metavar="PATH", help="the file (default <STATE_DIR>/evidence/evidence.jsonl)")
    ev.add_argument("--json", action="store_true")
    ev.set_defaults(fn=cmd_evidence)


def cmd_evidence(a, s, prof) -> int:
    from tvgw import evidence, experiments

    path = a.file or evidence.path_for(s.state_dir)
    if a.head is not None and not a.verify:
        return _usage("--head goes with --verify", "evidence")
    if a.head is not None and not evidence.HEAD.fullmatch(a.head):
        return _usage("--head takes a SHA-256 as the command printed it: 64 hexadecimal digits", "evidence")
    if a.verify:
        v = evidence.verify(path, a.head)
        if a.json:
            print(json.dumps(v.as_json(), indent=1))
        elif v.ok:
            span = f", {v.days[0]} to {v.days[-1]}" if v.days else ""
            print(f"tvgw evidence: the chain holds: {len(v.days)} days{span}, in {clean(path)}.")
            if v.head_line is not None:
                print(
                    f"Line {v.head_line} has the head hash you gave; every line up to it is as it was then."
                )
            else:
                print(
                    "The chain has no key, so this shows no line was changed by hand; against the chain being"
                    " computed again or the last lines cut off, check it with --head and a hash written down"
                    " earlier."
                )
            print(f"The last line's SHA-256 is {v.head}.")
        else:
            where = f" at line {v.line}" if v.line else ""
            print(f"tvgw evidence: {clean(path)}: the chain does not hold{where}: {v.problem}.")
        return 0 if v.ok else 1
    if not 1 <= a.days <= min(400, s.db_days):
        return _usage(f"--days must be 1 to {min(400, s.db_days)} (DB_DAYS)", "evidence")
    conn = _ro(s)
    try:
        done = evidence.append(
            path,
            conn,
            prof,
            time.time(),
            a.days,
            __version__,
            s.upload_ceiling,
            experiments.record_start(conn),
        )
    except evidence.BrokenChain as e:
        v = e.verdict
        print(
            f"tvgw evidence: {clean(path)}: the chain does not hold at line {v.line}: {v.problem}. Nothing"
            " was added. Keep that file, since it is the old record, and move it aside to start a new one.",
            file=sys.stderr,
        )
        return 1
    except PermissionError:
        print(
            f"tvgw evidence: it writes {clean(path)}; run it with sudo: sudo tvgw evidence", file=sys.stderr
        )
        return 1
    if a.json:
        out = {"path": path, "added": done.days, "days": done.total, "head": done.head,
               "left_out": [{"day": d, "why": w} for d, w in done.left_out]}  # fmt: skip
        print(json.dumps(out, indent=1))
        return 0
    if done.days:
        span = done.days[0] if len(done.days) == 1 else f"{done.days[0]} to {done.days[-1]}"
        print(f"tvgw evidence: added {len(done.days)} days ({span}) to {clean(path)}.")
    else:
        print(f"tvgw evidence: nothing was added to {clean(path)}.")
    for day, why in done.left_out:
        print(f"Left out {day}: {clean(why)}.")
    print(f"The file holds {done.total} days. The last line's SHA-256 is {done.head}.")
    print(
        "Nothing was sent anywhere. Write that hash down somewhere off the gateway: the chain has no key,"
        " so only a hash kept elsewhere shows later that no line was changed or cut off. To check the file:"
        " sudo tvgw evidence --verify --head <that hash>"
    )
    return 0


def _add_requests_parser(sub) -> None:
    rq = sub.add_parser(
        "requests",
        help="companies the TV reached or only tried to reach; --draft writes request drafts it never sends",
    )
    rq.add_argument("--days", type=int, default=30, help="days of record (default 30)")
    rq.add_argument(
        "--draft", action="store_true", help="write a data-access request draft per company reached"
    )
    rq.add_argument("--out", metavar="DIR", help="with --draft: a new or empty directory for the drafts")
    rq.add_argument("--json", action="store_true")
    rq.set_defaults(fn=cmd_requests)


def cmd_requests(a, s, prof) -> int:
    from tvgw import drafts

    if a.out and not a.draft:
        return _usage("--out goes with --draft", "requests")
    if not 1 <= a.days <= min(400, s.db_days):
        return _usage(f"--days must be 1 to {min(400, s.db_days)} (DB_DAYS)", "requests")
    now = time.time()
    conn = _ro(s)
    found = drafts.observed(conn, prof, now - a.days * 86400, now)
    if a.json:
        print(json.dumps(found, indent=1))
    else:
        for line in drafts.render(found):
            print(clean(line))
    if not a.draft:
        return 0
    out = a.out or drafts.default_dir(s.state_dir, now)
    try:
        paths = drafts.write(found, out)
    except drafts.NotEmpty:
        print(f"tvgw requests: {clean(out)} is not empty; give a new or empty directory", file=sys.stderr)
        return 1
    except PermissionError:
        print(f"tvgw requests: it writes {clean(out)}; run it with sudo, or give --out DIR", file=sys.stderr)
        return 1
    stream = sys.stderr if a.json else sys.stdout
    print(
        f"tvgw requests: wrote {len(paths)} drafts to {clean(out)} ({drafts.NOTICE} explains them)."
        " Nothing was sent.",
        file=stream,
    )
    if paths:
        print(
            "Each draft identifies your household to its company once you add your details and send it:"
            " read its first lines before you do.",
            file=stream,
        )
    return 0


def _print_outcome(done) -> int:
    for line in done.lines:
        print(line)
    return done.code


def cmd_localrules(a, s, prof) -> int:
    """(site rules) The four commands: root only, since they write /etc/tvgw and restart AdGuard."""
    from tvgw import localrules

    if os.geteuid() != 0:
        print(
            f"tvgw {a.verb}: it changes AdGuard Home's rules; run it with sudo: sudo tvgw {a.verb} {a.name}"
        )
        return 1
    if a.verb == "allow":
        done = localrules.allow(s, prof, a.name, a.reason, a.force)
    elif a.verb == "block":
        done = localrules.block(s, prof, a.name, a.reason)
    else:
        kind = localrules.ALLOW if a.verb == "unallow" else localrules.BLOCK
        done = localrules.remove(s, prof, a.name, kind)
    return _print_outcome(done)


MINT_DAYS = 14  # (mint) the days of connections `tvgw mint replay` judges unless told
# (mint) what the columns of `tvgw mint replay` mean, printed under its table
MINT_LEGEND = """\
one name, several names: the table held a ticket for the connection's address, for one name or for more.
listed: no ticket, and the profile lists the address and port as one the TV reaches without a lookup.
crowded out, lapsed, never: what a strict stage would refuse. An answer named the address in time and
  the table had no room for it; the newest answer was older than a ticket lives; no answer named it.
not assessed: the record does not reach back far enough, or the connection's beginning was not seen.
most tickets, most for one name: the table's own counts, over every answer it was given."""


def _add_screen_parser(sub) -> None:
    """(screentest) `tvgw screen-test`: the screen test (design decision 88). So far only its dry run."""
    sc = sub.add_parser(
        "screen-test",
        help="does anything the TV sends follow its screen? --dry-run watches and plays nothing",
    )
    sc.add_argument("--dry-run", action="store_true", help="draw the order and watch, playing nothing")
    sc.add_argument(
        "--general", action="store_true", help="two-minute slots, for a TV that reports about once a minute"
    )
    sc.add_argument("--json", action="store_true")
    sc.set_defaults(fn=cmd_screen_test)


def cmd_screen_test(a, s, prof) -> int:
    """(screentest) `tvgw screen-test --dry-run`: the order of a run is drawn and played to nobody, the
    TV's connections are polled once a second for as long as a run takes, and the result is scored as a
    real run's would be. Nothing was on the screen, so nothing should follow: it shows what the TV sends
    while it sits there, and whether a hidden upload would have been caught. It plays nothing, keeps
    nothing, loads no rule and asks the TV nothing.

    It exits 0 when nothing followed, 1 when something did, and 2 when nothing is concluded: the table
    could not be read, the TV sent nothing, the run was stopped. `--json` prints `slots` and `width` (of
    each, in seconds), `seconds` watched, `destinations` seen, the run's `p`, what `followed` (which may
    name `total`, everything the TV sent), in how many of the `active` destinations each known upload
    would have been `caught`, and the listings that `failed` and the lines `unread` along the way."""
    from tvgw import connpoll, screentest

    if not a.dry_run:
        print("Playing is not built yet. --dry-run watches without playing.", file=sys.stderr)
        return 2
    if os.geteuid() != 0:
        print(
            "tvgw screen-test: reading the connection table needs root: sudo tvgw screen-test --dry-run",
            file=sys.stderr,
        )
        return 2
    n, width = screentest.SLOTS_GENERAL if a.general else screentest.SLOTS_FAST
    seconds = screentest.seconds_needed(n, width)
    rng = random.SystemRandom()
    on = screentest.draw_slots(rng, n)
    if not a.json:
        print(
            "Nothing is played: this is a dry run."
            f" It watches what the TV sends for {screentest.minutes(seconds)} minutes."
        )
    poll = connpoll.Poll(s.tv_ip)
    try:
        series = connpoll.series(connpoll.watch(poll, seconds))
        result = screentest.score(series, on, width)
        weighed, caught = screentest.sensitivity(series, on, width, rng)
    except KeyboardInterrupt:
        print("The test was stopped. Nothing is concluded.", file=sys.stderr)
        return 2
    except connpoll.PollError as e:
        print(f"The test stopped: {e}. Nothing is concluded.", file=sys.stderr)
        return 2
    if not result.destinations():
        print(
            f"The TV sent nothing to the internet in {screentest.minutes(seconds)} minutes, so there was"
            " nothing to test. Nothing is concluded.",
            file=sys.stderr,
        )
        return 2
    followed = [f.key for f in result.followed()]
    if a.json:
        doc = {"dry_run": True, "slots": n, "width": width, "seconds": seconds}
        doc |= {"destinations": result.destinations(), "p": result.p, "followed": followed}
        print(
            json.dumps(
                {**doc, "active": weighed, "caught": caught, "failed": poll.failed, "unread": poll.unread},
                indent=1,
            )
        )
    else:
        for line in screentest.render(result, weighed, caught, played=False):
            print(clean(line))
        if poll.failed or poll.unread:
            print(
                f"Along the way {poll.failed} listings of the connection table failed and {poll.unread}"
                " of its lines could not be read; what was sent then is counted late or not at all."
            )
    return 1 if followed else 0


def _add_mint_parser(sub) -> None:
    """(mint) `tvgw mint`: one address per name (design decision 85). So far a replay over the record."""
    mi = sub.add_parser("mint", help="one address per name: what it would have refused, from the record")
    actions = mi.add_subparsers(dest="mint_action", required=True)
    rp = actions.add_parser("replay", help="run the stored answers and connections through the table")
    rp.add_argument(
        "--days", type=int, help=f"days of connections to judge (default {MINT_DAYS}, or DB_DAYS if shorter)"
    )
    rp.add_argument("--json", action="store_true")
    mi.set_defaults(fn=cmd_mint)


def _lifetime(seconds: float) -> str:
    """(mint) A ticket's lifetime in its largest whole unit: `1 minute`, `6 hours`."""
    unit, size = next((u for u in (("hour", 3600), ("minute", 60)) if seconds % u[1] == 0), ("second", 1))
    n = f"{seconds / size:g}"
    return f"{n} {unit}" + ("" if n == "1" else "s")


def cmd_mint(a, s, prof) -> int:
    """(mint) `tvgw mint replay`: what the minting table would have held for each connection the TV began
    in the last --days days (mintreplay's classes). It reads the store and changes nothing."""
    from tvgw import mintreplay

    days = min(MINT_DAYS, s.db_days) if a.days is None else a.days
    if not 1 <= days <= s.db_days:
        return _usage(f"--days must be 1 to {s.db_days} (DB_DAYS)", "mint replay")
    now = time.time()
    result = mintreplay.replay(_ro(s), now - days * 86400, now, prof)
    if result is None:
        print("The record of answered addresses has not started: the hourly ingest starts it.")
        return 1
    if a.json:
        print(json.dumps(result, indent=1))
        return 0
    judged, rows = result["judged"], result["lifetimes"]
    print(
        "One address per name, replayed over the record. Nothing is changed.\n"
        f"Judged: {_count(judged, 'connection')} the TV began in the last {_count(days, 'day')}."
        f" Left out: {result['local']} (to the gateway, the home network or port 53).\n"
        f"The tables were given every address the record's answers gave the TV: {result['answers']} in"
        " all, an address answered again counted again. The record is complete since"
        f" {ts(result['since'], '%Y-%m-%d %H:%M')}."
    )
    if not judged:
        print("There is no connection to judge in that window.")
        return 0
    print()
    table(
        [
            [
                _lifetime(row["lifetime"]),
                *(row["connections"][c] for c in mintreplay.JUDGED),
                row["tickets"]["peak"],
                row["tickets"]["widest"],
            ]
            for row in rows
        ],
        [
            "a ticket lives",
            "one name",
            "several names",
            "listed",
            "crowded out",
            "lapsed",
            "never",
            "not assessed",
            "most tickets",
            "most for one name",
        ],
    )
    print("\n" + MINT_LEGEND)
    own = rows[-1]  # the table's own lifetime
    refused = sum(own["connections"][c] for c in mintreplay.REFUSED)
    print(
        f"\nWith a ticket that lives {_lifetime(own['lifetime'])}, a strict stage would have refused"
        f" {refused} of the {judged} judged" + (":" if refused else ".")
    )
    for case in own["refused"]:
        port = f"{case['proto'] or '?'}" + ("" if case["dport"] is None else f"/{case['dport']}")
        ages = (
            ""
            if case["oldest"] is None
            else f"  last answered {case['newest'] / 3600:.0f} to {case['oldest'] / 3600:.0f} hours before"
        )
        print(f"  {case['class']}  {clean(port)}  {case['n']}{ages}")
    if result["ttl"]["known"]:
        print(
            f"Of the {result['ttl']['known']} whose answer's own lifetime the record holds,"
            f" {result['ttl']['past']} began more than a minute after that lifetime had passed."
        )
    full = [
        f"{row['tickets']['refused']} with {_lifetime(row['lifetime'])}"
        for row in rows
        if row["tickets"]["refused"]
    ]
    print(
        f"The pool holds {result['pool']:,} addresses; "
        + (
            f"answers that got no ticket because it was full: {', '.join(full)}."
            if full
            else "every answer got a ticket."
        )
    )
    return 0


def _add_resolver_parser(sub) -> None:
    """(resolver) `tvgw resolver`: who answers the TV's lookups, and a change of it (decision 81)."""
    r = sub.add_parser("resolver", help="who answers the TV's lookups: the choices, the one now, a change")
    actions = r.add_subparsers(dest="resolver_action", required=True)
    actions.add_parser("list", help="the services the gateway offers, the one answering now marked")
    sh = actions.add_parser("show", help="who answers the TV's lookups now, and what it sees and keeps")
    sh.add_argument("--json", action="store_true")
    for name, help_ in (
        ("set", "change who answers (root): it tests the new service and puts the old one back on a failure"),
        ("test", "ask a service from this computer whether it answers, changing nothing"),
    ):
        sp = actions.add_parser(name, help=help_)
        sp.add_argument("name", metavar="NAME", help="a name from tvgw resolver list, or custom")
        sp.add_argument(
            "urls",
            nargs="?",
            default="",
            metavar="URL[,URL]",
            help="with custom: https://<address>/dns-query",
        )
    r.set_defaults(fn=cmd_resolver)


def cmd_resolver(a, s, prof) -> int:
    """(resolver) list and show read the settings (adm); set writes them and restarts AdGuard (root);
    test asks a service directly and changes nothing. Exit 0 done, 1 refused or put back with nothing
    changed, 3 AdGuard held its restart back because the current upstreams are down and the new ones did
    not answer a direct test at that moment either, with the settings file as it was."""
    from tvgw import resolver

    if a.resolver_action == "list":
        print("\n".join(resolver.list_lines(s)))
        return 0
    if a.resolver_action == "show":
        live = resolver.adguard_upstreams(s.adguard_yaml)
        if a.json:
            print(json.dumps(resolver.show_json(s, live), indent=1))
        else:
            print("\n".join(resolver.show_lines(s, live)))
        return 0
    held = resolver.by_name(a.name, offered_only=False)
    if a.resolver_action == "test" and held is not None and not a.urls:  # a held candidate: tried, never set
        target = resolver.Target(held.name, held.label, held.upstreams, held.bootstrap)
    else:
        try:
            target = resolver.target_for(a.name, a.urls, s.gw_ip)
        except ValueError as e:
            print(f"{resolver.SAY}{e}")
            return 1
    if a.resolver_action == "test":
        return _print_outcome(resolver.trial(target, next(iter(prof.must_allow), "example.com")))
    if os.geteuid() != 0:
        more = f" {a.urls}" if a.urls else ""
        print(
            f"{resolver.SAY}it changes the settings and restarts AdGuard Home; run it with sudo:"
            f" sudo tvgw resolver set {a.name}{more}"
        )
        return 1
    return _print_outcome(resolver.change(s, prof, a.conf, target))


def _add_adguard_parser(sub) -> None:
    g = sub.add_parser("adguard", help="AdGuard Home: install it, and its lists, rules and settings")
    g.add_argument(
        "action",
        # (lists) upgrade and service; (adguard) install and ui
        choices=["diff", "apply", "upgrade", "service", "install", "ui"],
        help="diff: show drift (exit 1 if any); apply: write it; upgrade NEWBIN or --fetch: swap in a new"
        " binary after its own config check; service: run AdGuard with --no-check-update; install: install"
        " AdGuard Home's pinned release and set it up without its wizard; ui: how to open its page",
    )
    g.add_argument("newbin", nargs="?", metavar="NEWBIN", help="with upgrade: the new AdGuardHome binary")
    g.add_argument(
        "--dry-run", action="store_true", help="with apply: show what would change, change nothing"
    )
    g.add_argument(
        "--fetch",
        action="store_true",
        help="with upgrade: download the release this tvgw pins, checked by its SHA-256, instead of NEWBIN",
    )
    g.add_argument(
        "--take-over",
        action="store_true",
        help="with apply: take over an AdGuard Home tvgw did not set up, though it serves other devices"
        " (as ADGUARD_TAKE_OVER=yes does)",
    )
    g.set_defaults(fn=cmd_adguard)


def cmd_guard(a, s, prof) -> int:
    """(guard) Print one line per file changed, nothing when nothing changed: install.sh reloads
    systemd, or restarts avahi, only on output."""
    from pathlib import Path

    from tvgw import guard

    units = config.co_tenants(s.co_tenant_units)
    if a.action == "avahi":
        tv_if = s.tv_if if "avahi-daemon" in units else None  # not listed: tvgw's own line comes out
        if a.dry_run:
            try:
                text = Path(a.avahi_conf).read_text(encoding="utf-8")
            except FileNotFoundError:
                return 0
            if guard.avahi_deny(text, tv_if) is not None:
                print(f"would change {a.avahi_conf}")
            return 0
        if guard.edit_avahi(a.avahi_conf, tv_if):
            print(f"changed {a.avahi_conf}")
        return 0
    files, sockets = guard.gather(units)
    plan = guard.plan(units, files, sockets, guard.present_dropins(a.unit_dir), s.tv_net, s.gw_ip, a.unit_dir)
    if not a.dry_run:
        guard.apply(plan)
    if plan.changed:
        print("\n".join(plan.lines(dry_run=a.dry_run)))
    return 0


DEFERRED_EXIT = 3  # (lists) `tvgw adguard` held a restart back because the upstreams are down
# (adguard) `tvgw adguard apply` refused an AdGuard Home tvgw did not set up that serves other devices;
# install.sh tells it from a failure and says how to go on (aghinstall.takeover_evidence and refused)
TAKEOVER_EXIT = 4


def _takeover_lines(others, s) -> list[str]:
    """(adguard) The refusal of a take-over, with what it would do and the two ways on."""
    moves = "its page to this computer alone"
    if s.adguard_listen == "gateway":
        moves = "its DNS and its page to this computer and the TV alone"
    if others.strong:
        found = f"and it serves more than the TV: {others.why()}"
    else:  # the weak evidence, refused because the settings say ADGUARD_TAKE_OVER=no
        found = f"and it may serve more than the TV ({others.why()}), which ADGUARD_TAKE_OVER=no refuses"
    return [
        f"tvgw adguard: AdGuard Home on this computer was not set up by tvgw, {found}. Taking it over"
        f" moves {moves} and replaces its blocklists, rules and upstreams, for every device that uses it."
        " Nothing was changed.",
        "tvgw adguard: if nothing else depends on it, set ADGUARD_TAKE_OVER=yes in /etc/tvgw/tvgw.conf (or"
        " run this apply with --take-over); otherwise put tvgw on a computer of its own"
        " (docs/install/choosing-a-gateway.md)",
    ]


def cmd_adguard(a, s, prof) -> int:
    from tvgw import adguardcfg, aghinstall, listpause

    if a.fetch and a.action != "upgrade":  # (adguard)
        return _usage(f"adguard {a.action} takes no --fetch", "adguard")
    if a.take_over and a.action != "apply":  # (adguard)
        return _usage(f"adguard {a.action} takes no --take-over", "adguard")
    if a.action in ("install", "ui"):  # (adguard)
        if a.newbin:
            return _usage(f"adguard {a.action} takes no NEWBIN", "adguard")
        return _adguard_install(s, prof) if a.action == "install" else _adguard_ui(s)
    if a.action in ("upgrade", "service"):  # (lists)
        return _adguard_binary(a, s, prof)
    if a.newbin:
        return _usage(f"adguard {a.action} takes no NEWBIN", "adguard")
    problems = prof.lint()  # the CI guard, applied to the profile this gateway is about to run
    if problems:
        sys.exit("tvgw adguard: the profile does not lint: " + "; ".join(clean(x) for x in problems))
    try:
        d = adguardcfg.desired(prof, s)
    except OSError as e:  # (site rules) planning without the owner's rules, or the machine's, would undo them
        sys.exit(
            f"tvgw adguard: cannot read {e.filename or s.local_rules}: {e.strerror or e}; nothing was planned"
        )
    except ValueError as e:
        sys.exit(f"tvgw adguard: {e}")
    try:
        current = adguardcfg.load_yaml(s.adguard_yaml)
    except OSError as e:
        sys.exit(f"cannot read {s.adguard_yaml}: {e} (is AdGuard Home installed and set up?)")
    diff = adguardcfg.changes(current, adguardcfg.plan(current, d))
    try:  # (lists) a schema newer than tvgw knows: diff still reports, apply would refuse
        adguardcfg.check_schema(current, s.adguard_yaml)
    except RuntimeError as e:
        if a.action == "apply" and not a.dry_run:  # a dry run changes nothing: it warns, as diff does
            sys.exit(f"tvgw adguard: {e}")
        print(f"tvgw adguard: warning: {e}", file=sys.stderr)
    # (adguard) a foreign AdGuard Home that answered another device is taken over only on the owner's
    # yes; one that only listens beyond the TV side is taken over with one line, unless the setting says no
    others = None if (a.take_over or not diff) else aghinstall.takeover_evidence(s, prof, current)
    refuse = aghinstall.refused(others, s)
    pause = listpause.diff_note(prof, s)  # (pause) a pause in force is planned, so its lists are no drift
    if a.action == "diff" or a.dry_run:
        print("\n".join(diff) if diff else "AdGuard Home matches the profile and settings")
        for line in _rule_sources(current, prof, s):  # (site rules) the rules by the file each comes from
            print(line)
        if pause:
            print(pause)
        if refuse:  # a dry run changes nothing: it says what the apply would do, as diff does
            print("tvgw adguard: warning: tvgw adguard apply would refuse:", file=sys.stderr)
            for line in _takeover_lines(others, s):
                print(line, file=sys.stderr)
        elif others:
            print(f"tvgw adguard: note: the apply would take it over. {others.note()}", file=sys.stderr)
        return 1 if (diff and a.action == "diff") else 0
    if pause:
        print(pause)
    if not diff:
        print("AdGuard Home already matches; nothing to do")
        return 0
    if refuse:
        for line in _takeover_lines(others, s):
            print(line, file=sys.stderr)
        return TAKEOVER_EXIT
    if others:  # the weak evidence alone, under ask: taken over, and said so
        print(others.note(), file=sys.stderr)
    try:
        applied = adguardcfg.apply(
            s.adguard_yaml,
            d,
            # ready means the TV's clock host resolves through the new config, not that the port answers
            ready=lambda: adguardcfg.dns_ready(name=next(iter(prof.must_allow), "example.com")),
        )
    except adguardcfg.Deferred as e:  # (lists) upstreams down: reported, not retried, nothing changed
        print(f"tvgw adguard: {e}", file=sys.stderr)
        return DEFERRED_EXIT
    except RuntimeError as e:  # rejected by AdGuard, rolled back, or another apply is running
        sys.exit(f"tvgw adguard: {e}")
    print(f"tvgw adguard: applied {len(applied)} change(s) to {s.adguard_yaml} and restarted AdGuard Home")
    for c in applied:
        print("  " + c)
    return 0


def _rule_sources(current: dict, prof, s) -> list[str]:
    """(site rules) `user_rules`' difference grouped by source: the profile, the owner's site rules and
    the machine's, each named with its file, so the owner's own rules show as their own group."""
    from tvgw import adguardcfg

    labels = {
        "profile": f"the profile ({s.profile})",
        "local": f"your site rules ({s.local_rules})",
        "machine": f"the gateway's own rules ({s.auto_rules})",
    }
    return adguardcfg.rule_changes(current, adguardcfg.rule_groups(prof, s), labels)


def _adguard_binary(a, s, prof) -> int:
    """(lists) `tvgw adguard upgrade NEWBIN` and `tvgw adguard service`: the two ways the gateway
    changes AdGuard Home's binary or how it is started, each restart behind the restart guard.
    (adguard) `upgrade --fetch` takes the release this tvgw pins in place of NEWBIN."""
    from tvgw import adguardcfg, verify

    if a.action == "service" and a.newbin:
        return _usage("adguard service takes no NEWBIN", "adguard")
    if a.action == "upgrade" and not (a.newbin or a.fetch):
        return _usage("adguard upgrade needs NEWBIN, the new AdGuardHome binary, or --fetch", "adguard")
    if a.action == "upgrade" and a.newbin and a.fetch:
        return _usage("adguard upgrade takes NEWBIN or --fetch, not both", "adguard")
    try:
        d = adguardcfg.desired(prof, s)
    except ValueError as e:
        sys.exit(f"tvgw adguard: {e}")
    ready = lambda: adguardcfg.dns_ready(name=d.probe_name)  # noqa: E731
    # probes under the must-allow name, listens past the live YAML's upstream timeout, and asks a name
    # the profile's own rules block to tell an outage from a hung AdGuard
    guard = adguardcfg.guard_for(s.adguard_yaml, d)
    try:
        if a.action == "service":
            fragment = verify.run_cmd(["systemctl", "show", "-P", "FragmentPath", "AdGuardHome"]).strip()
            if not fragment:
                sys.exit("tvgw adguard: systemd knows no AdGuardHome unit (is AdGuard Home installed?)")
            lock_dir = os.path.dirname(os.path.abspath(s.adguard_yaml))
            print(
                "tvgw adguard: "
                + adguardcfg.ensure_service(fragment, ready=ready, guard=guard, lock_dir=lock_dir)
            )
            return 0

        def failing() -> set[str]:
            return {c.name for c in verify.check(s, prof).checks if not c.ok}

        def upgrade(newbin: str) -> list[str]:
            return adguardcfg.upgrade(
                s.adguard_yaml, newbin, ready=ready, verify=failing, guard=guard, floor=verify.ADGUARD_MIN
            )

        if a.fetch:  # (adguard)
            return _adguard_fetch(s, upgrade)
        done = upgrade(a.newbin)
    except adguardcfg.Deferred as e:
        print(f"tvgw adguard: {e}", file=sys.stderr)
        return DEFERRED_EXIT
    except RuntimeError as e:
        sys.exit(f"tvgw adguard: {e}")
    print("tvgw adguard: upgraded AdGuard Home")
    for line in done:
        print("  " + line)
    return 0


def _adguard_fetch(s, upgrade) -> int:
    """(adguard) `tvgw adguard upgrade --fetch`: the pinned release into a temporary directory, checked
    and unpacked by aghinstall, then the same upgrade as with NEWBIN. Nothing is downloaded when the
    installed binary already reports the pinned version or a newer one, nor where there is no AdGuard
    Home set up to upgrade. Deferred and RuntimeError propagate to the caller, which reports them as for
    NEWBIN."""
    import tempfile

    from tvgw import adguardcfg, aghinstall

    if os.geteuid() != 0:
        sys.exit("tvgw adguard: upgrade --fetch replaces AdGuard Home's binary; run it as root (sudo)")
    home = os.path.dirname(os.path.abspath(s.adguard_yaml))
    exe = os.path.join(home, "AdGuardHome")
    if not (os.path.isfile(exe) and os.path.isfile(s.adguard_yaml)):  # nothing to upgrade: say so first
        sys.exit(
            f"tvgw adguard: AdGuard Home is not set up in {home}, so there is nothing to upgrade;"
            " sudo tvgw adguard install installs the pinned release"
        )
    have, pin = adguardcfg.binary_version(exe), aghinstall.pin_version()
    if have is not None and have >= pin:
        print(
            f"tvgw adguard: AdGuard Home is v{'.'.join(map(str, have))}; this tvgw pins"
            f" v{aghinstall.PIN['version']}, so there is nothing to fetch"
        )
        return 0
    with tempfile.TemporaryDirectory(prefix="tvgw-adguard-") as tmp:
        try:
            newbin = aghinstall.fetch_release(tmp)
        except aghinstall.InstallError as e:
            sys.exit(f"tvgw adguard: {e}")
        print(
            f"tvgw adguard: downloaded AdGuard Home v{aghinstall.PIN['version']},"
            " checked against its pinned SHA-256"
        )
        done = upgrade(str(newbin))
    print("tvgw adguard: upgraded AdGuard Home")
    for line in done:
        print("  " + line)
    return 0


def _adguard_install(s, prof) -> int:
    """(adguard) `tvgw adguard install`: aghinstall.install(), a line per thing done (design decision 52)."""
    from tvgw import aghinstall

    if os.geteuid() != 0:
        sys.exit("tvgw adguard: install writes /opt/AdGuardHome and starts units; run it as root (sudo)")
    try:
        done = aghinstall.install(s, prof)
    except aghinstall.InstallError as e:
        sys.exit(f"tvgw adguard: {e}")
    for line in done:
        print(f"tvgw adguard: {line}")
    return 0


def _adguard_ui(s) -> int:
    """(adguard) `tvgw adguard ui`: how to open AdGuard's page from another computer."""
    from tvgw import aghinstall

    lines, code = aghinstall.ui_lines(s)
    print("\n".join(lines), file=sys.stdout if code == 0 else sys.stderr)
    return code


def _usage(msg: str, command: str = "report") -> int:
    print(f"tvgw {command}: error: {msg}", file=sys.stderr)
    return 2  # argparse's own exit status for a usage error


def _rule_use(conn, prof, s, since: float, until: float, o: dict) -> dict | None:
    """(rule use) The weekly report's Rule use section (design decision 82), or None with a report
    warning: a part nothing else needs must not cost the rest of the report."""
    from tvgw import rulestats

    try:
        return rulestats.weekly(s, prof, conn, since, until)
    except (OSError, sqlite3.Error, ValueError) as e:
        o.setdefault("warnings", []).append(f"Rule use could not be computed ({type(e).__name__}: {e})")
        return None


def cmd_report(a, s, prof) -> int:
    if a.until is not None and (a.day or a.week):
        return _usage("--until goes with --since")
    if a.with_plain and not a.day:
        return _usage("--with-plain goes with --day")
    until = a.until if a.until is not None else time.time()
    since = a.since if a.since is not None else until - 86400
    if since >= until:
        return _usage("--since must be before --until")
    conn = _ro(s)
    kw = {"gw_ip": s.gw_ip, "ledger_on": s.ledger == "on", "clean_hours": s.judge2_clean_hours}  # (ledger)
    kw["upload_ceiling"] = s.upload_ceiling  # (budget)
    kw["uplink_if"] = s.wan_if  # (uplink quality)
    if a.week:
        o = queries.weekly(conn, a.week, prof, **kw)
        o["rule_use"] = _rule_use(conn, prof, s, *queries.week_bounds(a.week), o)  # (rule use)
    elif a.day:
        o = queries.brief(conn, a.day, prof, **kw)
    elif a.since is None and a.until is None:
        o = queries.latest(conn, 24, prof, **kw)
    else:
        o = queries.window_report(conn, since, until, prof, **kw)
    _with_resolver(o, s)
    # (plain) a day's JSON always carries its plain brief; its text starts with it only on request
    if a.json:
        print(json.dumps({**o, "plain": plain_lines(conn, o, prof)} if a.day else o, indent=1))
        return 0
    if a.with_plain:
        print_plain(plain_lines(conn, o, prof))
        print()
    render_brief(o)
    return 0


def _load_profile(name: str, s=None) -> profile.Profile:
    """The profile by bundled name or TOML path, (W12) with its must-allow hosts filled for TV_COUNTRY
    when the settings name one. A profile that cannot be read whole is one line and exit 1, never a
    traceback and never a profile with fewer rules than were written."""
    try:
        p = profile.load(name)
        return p.for_country(s.tv_country) if s is not None and s.tv_country else p
    except (OSError, ValueError) as e:  # tomllib.TOMLDecodeError is a ValueError
        sys.exit(f"tvgw: profile {name}: {e}")


def cmd_discover(a, s, prof) -> int:
    """Find the TV on the TV-side network and, with --write, record its identity in the settings file."""
    from pathlib import Path

    from tvgw import discover as disc

    cands = disc.gather(a.iface or s.tv_if, s.gw_ip, with_ssdp=not a.no_ssdp)
    if a.json:
        print(json.dumps([c.__dict__ for c in cands], indent=1))
        return 0 if cands else 1
    if not cands:
        print("no device found on the TV side: is the TV plugged into the gateway's TV port and switched on?")
        return 1
    print("\n".join(clean(line) for line in disc.render(cands)))
    if not a.write:
        return 0
    pick = cands[0] if (len(cands) == 1 or a.yes) else None
    if pick is None:
        if not sys.stdin.isatty():
            sys.exit("several devices found: run with --yes to take the first, or choose interactively")
        choice = input(f"which one is the TV? [1-{len(cands)}] ").strip()
        if not choice.isdigit() or not 1 <= int(choice) <= len(cands):
            sys.exit("no device chosen")
        pick = cands[int(choice) - 1]
    if not pick.mac:
        sys.exit(f"{pick.ip} has no MAC address in the lease or neighbour table yet; wait a minute and retry")
    name = a.name or disc.safe_name(pick.hostname)
    path = Path(a.conf)
    text = path.read_text(encoding="utf-8") if path.exists() else ""
    disc.write_conf(path, disc.write_identity(text, pick.mac, pick.ip, name, pick.profile))
    keys = "TV_MAC, TV_IP, TV_NAME" + (", PROFILE" if pick.profile else "")
    print(f"wrote {keys} to {a.conf} for {clean(pick.label)}")
    if not pick.profile:
        # (profile) a profile only on evidence; one signal names a vendor, and its owner decides
        offer = disc.vendor_profile(pick.vendor, disc.bundled_profiles())
        brand = (
            f"; if it is {disc.vendor_phrase(clean(pick.vendor))} TV, set PROFILE={offer}" if offer else ""
        )
        left = "no profile assigned on the evidence; PROFILE was left as it was"
        print(f"{left}{brand} (docs/project/adding-a-profile.md)")
    return 0


def stored_model(s) -> str | None:
    """The model number the hourly LAN-API reading recorded, if the store has one."""
    if not os.path.exists(s.db_path):
        return None
    try:
        conn = db.connect(s.db_path, readonly=True)
        row = conn.execute(
            "SELECT value FROM tvsettings WHERE key='model' ORDER BY t DESC LIMIT 1"
        ).fetchone()
        conn.close()
    except Exception:
        return None
    return row[0] if row and row[0] and not str(row[0]).startswith("ERR") else None


def _print_records(p: profile.Profile) -> None:
    """(profiles) The LAN APIs and privacy settings a profile knows, each with its provenance, so an
    operator sees at a glance which facts were seen on hardware and which are only cited."""
    if p.lan_apis:
        print("\nLAN APIs:")
    for api in p.lan_apis:
        tls = f", TLS {api.tls}" if api.tls else ""
        gens = f"; generations {', '.join(api.generations)}" if api.generations else ""
        print(f"  {clean(api.name)}: {api.protocol}/{api.port}{tls} ({api.provenance.label()}{gens})")
        for label, value in (("pairing", api.pairing), ("discovery", api.discovery), ("gate", api.gate)):
            if value:
                print(f"    {label}: {clean(value)}")
        if api.reads:
            print(f"    reads: {clean(', '.join(api.reads))}")
        print(f"    writes: {api.write}" + (f"; read-only: {clean(api.read_only)}" if api.read_only else ""))
        for x in api.notes:
            print(f"    note: {clean(x)}")
        for url in api.provenance.sources:
            print(f"    source: {clean(url)}")
    if p.privacy_settings:
        print("\nPrivacy settings:")
    for ps in p.privacy_settings:
        key = f"; key {ps.key}" if ps.key else ""
        print(f"  {clean(ps.name)}: {clean(ps.recommended)} ({ps.provenance.label()}{key})")
        print(f"    controls: {clean(ps.controls)}")
        for where, path in ps.menu:
            print(f"    {clean(where)}: {clean(path)}")
        if ps.opt_out_effective:
            print(f"    opt-out: {clean(ps.opt_out_effective)}")
        for x in ps.notes:
            print(f"    note: {clean(x)}")
        for url in ps.provenance.sources:
            print(f"    source: {clean(url)}")


def cmd_profile(a, s, prof) -> int:
    """What this profile knows: must-allow names, expected categories, lint, generations, hardware."""
    p = _load_profile(a.profile) if a.profile else prof
    if getattr(a, "firewall", False):  # (ports) what tvgw-apply reads, and nothing else
        print(f"ntp={p.ntp}")
        return 0
    print(f"{p.name}: {p.description}" + (f" (vendor {p.vendor})" if p.vendor else ""))
    if p.support:  # (profile)
        tested = f", on {'; '.join(clean(x) for x in p.tested_on)}" if p.tested_on else ""
        print(f"support: {profile.SUPPORT[p.support]}{tested}")
    if p.you_check:
        print(f"you check on the TV: {clean(p.you_check)}")
    if p.does:  # (samsung)
        print(f"tvgw does: {clean(p.does)}")
    if p.can_check:
        print(f"it reads every hour: {'; '.join(clean(x) for x in p.can_check)}")
    if p.cannot_check:
        print(f"it cannot read: {'; '.join(clean(x) for x in p.cannot_check)}")
    clock = (", ".join(p.clock_hosts) or "-") + (f" (clock model {p.clock_model})" if p.clock_model else "")
    print(f"expected categories: {', '.join(p.expected_categories)}; clock hosts: {clock}")
    print(f"clock port (NTP, [firewall] ntp): {p.ntp}")  # (ports)
    if p.wifi_off:
        checked = "checked on a set of this profile" if p.wifi_off_confirmed else "not checked on a set yet"
        print(f"Wi-Fi off ({checked}): {clean(p.wifi_off)}")
    problems = p.lint()
    print("rules lint: " + ("clean" if not problems else "; ".join(clean(x) for x in problems)))
    # (listguard) the blocks no subscribed list can lift, which the load held (design decision 68)
    held = [r for r in p.custom_rules if r.endswith(profile.IMPORTANT) and not r.startswith("@@")]
    print(
        f"held against the lists: {len(held)} block{'' if len(held) == 1 else 's'} in the red-line categories"
        " carry $important, so no list's plain exception lifts them; tvgw allow still does"
    )
    print(f"\nMust stay allowed ({len(p.must_allow)}):")
    table(sorted(p.must_allow.items()), ["name", "why"])
    asked = a.webos or a.firmware or a.release
    gen = p.generation_for(a.webos, a.firmware, a.release) if asked else None
    if asked:
        asked_for = f"webOS {a.webos or '?'} / firmware {a.firmware or '?'} / release {a.release or '?'}"
        print(f"\nGeneration for {asked_for}:")
        if gen is None:
            print("  unknown to this profile")
    gens = [gen] if gen else list(p.generations)
    if gens:
        print("\nGenerations:" if not gen else "")
        for g in gens:
            years = ("-".join(str(y) for y in dict.fromkeys((g.years[0], g.years[-1])))) if g.years else "?"
            flag = "verified here" if g.verified else f"{g.confidence} confidence"
            print(
                f"  webOS {g.webos} ({years}, {g.codename or '-'}; {flag})"
                + (f" models {', '.join(g.models)}" if g.models else "")
            )
            if g.os_major:  # (W12) the OS the TV reports, the pairing that works, and what it will say
                words = profile.SUPPORT.get(g.support, g.support) if g.support else ""
                print(
                    f"    reports: release {clean(g.release_range) or g.os_major + '.x'}"
                    + (f"; {words}" if words else "")
                )
            if g.manifest:
                print(f"    pairing manifest: {g.manifest}")
            if g.readable:
                print(f"    readable settings: {', '.join(g.readable)}")
            for topic, path in g.menu:
                print(f"    menu {topic.replace('_', ' ')}: {clean(path)}")
            if g.clock_hosts:
                print(f"    clock: {', '.join(g.clock_hosts)}")
            if g.lan_api:
                print(f"    LAN API: {clean(g.lan_api)}")
            for x in g.dns_bypass:
                print(f"    DNS bypass: {clean(x)}")
            for x in g.hardcoded:
                print(f"    hardcoded: {clean(x)}")
            for x in g.notes:
                print(f"    note: {clean(x)}")
    _print_records(p)  # (profiles) [[lan_api]] and [[privacy_setting]], design decision 31
    model = a.model or stored_model(s)
    if model:
        h = p.hardware_for(model)
        source = "" if a.model else " (the model the TV reported over its LAN API)"
        print(f"\nHardware for {clean(model)}{source}:")
        if h is None:
            print("  model unknown to this profile; treat it as having a microphone until checked")
        else:
            mic = (
                "YES, built-in far-field microphone"
                if h.far_field_mic
                else "no built-in microphone (remote mic is push-to-talk)"
            )
            print(f"  {h.year}: {mic} ({h.confidence} confidence)")
            if h.assistants:
                print(f"  assistants: {', '.join(h.assistants)}")
            if h.notes:
                print(f"  note: {clean(h.notes)}")
        for topic, steps in p.checklist.items():
            print(f"\n{topic} checklist:")
            for i, step in enumerate(steps, 1):
                print(f"  {i}. {clean(step)}")
    return 1 if problems else 0


def cmd_verify(a, s, prof) -> int:
    from tvgw import verify

    return verify.main(s, prof, record_to_store=a.record, as_json=a.json)


def cmd_setup(a, s, prof) -> int:
    """(setup) The guided installer; the flow lives in setup.py."""
    from tvgw import setup

    return setup.main(a, s)


def cmd_tvcheck(a, s, prof) -> int:
    """The hourly reading: 4, having asked the TV nothing, when the gateway is not paired with it. (samsung)
    A Samsung on the samsung-tizen profile is read without pairing by tizen.read(), which no other
    profile ever runs; every other profile keeps LG's reader, which asks nothing without a key."""
    from tvgw import lgwebos, tizen

    reading = tizen.read(s.tv_ip) if s.profile == tizen.PROFILE else lgwebos.read(s.tv_ip, a.key_file)
    print("\n".join(reading.lines()))
    return reading.exit_code()


def cmd_tv_pair(a, s, prof) -> int:
    """(pairing) `tvgw tv pair`: say what the prompt is, as setup does, then pair and print the first
    reading. 4 when the profile has no LAN-API reader; 1 without root, without the key's directory, or
    when the TV did not pair; otherwise the reading's code, as `tvcheck` gives it."""
    from tvgw import lgwebos, setup

    if s.profile in setup.READ_WITHOUT_PAIRING:  # (samsung)
        print(
            f"tvgw tv pair: the gateway reads this TV ({s.profile}) without pairing, every hour; nothing to"
            " pair. sudo tvgw tvcheck reads it now"
        )
        return 4
    if s.profile not in setup.PAIRABLE_PROFILES:
        print(f"tvgw tv pair: no LAN-API reader for profile {s.profile}; nothing to pair")
        return 4
    if os.geteuid() != 0:
        print(
            "tvgw tv pair: needs root, which alone may reach the TV's LAN API and hold its key:"
            f" run `{setup.PAIR_LATER}`",
            file=sys.stderr,
        )
        return 1
    key_dir = os.path.dirname(a.key_file)
    if not os.path.isdir(key_dir):
        print(f"tvgw tv pair: {key_dir} does not exist; run the installer first", file=sys.stderr)
        return 1
    from tvgw import lgkeys

    rec = lgkeys.record(a.key_file, s.tv_ip)
    if lgwebos.has_key(a.key_file, s.tv_ip) and not (rec and rec.refused):
        print(
            f"already paired with the TV at {s.tv_ip}; reading it with the stored key (a prompt on the TV"
            " now means it forgot the gateway: accept it to pair again)"
        )
    else:
        if rec and rec.refused:  # (W12) the hourly reading stopped at the refusal; this is the way back
            when = ts(rec.refused_at, "%Y-%m-%d")
            print(f"the TV refused the gateway's key on {when} ({rec.refused_why}); pairing again")
        print(setup.PAIRING_EXPLAINED)
        print(f"pairing with {s.tv_ip}: look at the TV and accept the connection prompt...")
    manifest = a.manifest or (rec.manifest if rec and not rec.refused else "unsigned")
    print(f"the pairing asks for tvgw's read-only permissions ({manifest} manifest)")
    reading = lgwebos.pair(s.tv_ip, a.key_file, manifest=a.manifest)
    if not reading.reachable:
        hint = (
            "; LG's newer software refuses the signed manifest and shows no prompt: try again without"
            " --manifest signed"
            if manifest == "signed"
            else ""
        )
        print(
            f"tvgw tv pair: the TV did not answer over its LAN API ({reading.error}): it may be off, or the"
            f" prompt was not accepted in time{hint}",
            file=sys.stderr,
        )
        return 1
    print("paired; the TV reads:")
    print("\n".join(reading.lines()))
    return reading.exit_code()


# (depth) an account outside the adm group, which may not read the settings file or the store (design 4.3)
NEEDS_SETTINGS = (
    "tvgw: this needs the gateway's settings: run it with sudo, or ask the computer's owner to add your"
    " account to the adm group"
)


def main(argv: Sequence[str] | None = None) -> int:
    # what the gateway prints is UTF-8 whatever the locale says (the Pi's was en_US with no charset,
    # which is latin-1), and a character the stream cannot carry becomes a '?' instead of a crash
    for stream in (sys.stdout, sys.stderr):
        with contextlib.suppress(AttributeError, ValueError, OSError):
            stream.reconfigure(encoding="utf-8", errors="replace")
    p = build_parser()
    a = p.parse_args(argv)
    if not getattr(a, "needs_conf", True):  # (depth) tvgw status: no settings, no profile
        return a.fn(a, None, None)
    overrides = {"db_path": a.db} if a.db else {}
    try:
        s = config.load(a.conf, **overrides)
    except ValueError as e:
        sys.exit(f"tvgw: {e}")
    except PermissionError as e:
        _needs_settings(e)
    prof = _load_profile(s.profile, s)
    try:
        return a.fn(a, s, prof)
    except PermissionError as e:  # (depth) a file of the gateway's this account may not read or write
        _needs_settings(e)
    except db.StoreTooNew as e:  # (reliability) a store a newer tvgw wrote: said in one line, never written
        print(f"tvgw: {e}", file=sys.stderr)
        return 1


def _needs_settings(e: PermissionError) -> NoReturn:
    """(depth) A PermissionError, said in one sentence to an account that is not root. Root reads every
    file of the gateway's, so for root it is something else (a sandboxed unit's limits, an access rule):
    "run it with sudo" would be wrong there, and the traceback says what it is."""
    if os.geteuid() == 0:
        raise e
    sys.exit(NEEDS_SETTINGS)


if __name__ == "__main__":
    sys.exit(main())
