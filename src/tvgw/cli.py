"""`tvgw` command line: ingest the sources, then ask the store questions."""

from __future__ import annotations

import argparse
import contextlib
import glob
import json
import os
import re
import sqlite3
import sys
import time
from collections.abc import Iterable, Sequence
from datetime import datetime
from typing import NoReturn

from tvgw import __version__, budget, config, db, ingest, ledger, pcaps, profile, queries


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
    if o.get("changes_in_effect"):  # (ledger) what changed, read before what the machine concluded
        try:
            lines = ledger.render(o["changes_in_effect"])
        except Exception as e:  # the rest of the brief is still worth printing
            lines = [f"Changes in effect: could not be shown ({type(e).__name__}: {e})"]
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


def cmd_ingest(a, s, prof) -> int:
    stats = ingest.run(s, prof)
    for w in stats.warnings:
        print(f"tvgw ingest: WARNING {clean(w)}", file=sys.stderr)
    size = os.path.getsize(s.db_path) / 1e6 if os.path.exists(s.db_path) else 0
    print(f"tvgw ingest: {stats.summary()}; db {size:.1f} MB")
    return 1 if stats.warnings else 0


def cmd_prune_pcaps(a, s, prof) -> int:
    """Retention for the raw captures: only files ingest has read, never the one the capture is writing."""
    deletable: set[str] = set()
    if os.path.exists(s.db_path):  # no store yet means nothing has been read
        conn = _ro(s)
        deletable = ingest.deletable_pcaps(conn)
        conn.close()
    budget = int(s.pcap_max_gb * 2**30)
    deleted, warnings = pcaps.prune(s.pcap_dir, deletable, s.pcap_days, budget, pcaps.live_files(s.pcap_dir))
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
    o = queries.brief(conn, a.day or queries.yesterday(), prof, gw_ip=s.gw_ip, **kw)
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


def cmd_host(a, s, prof) -> int:
    conn = _ro(s)
    h = queries.host_detail(conn, a.name)
    if not h:
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
    return 0


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
        from tvgw import localrules

        return _print_outcome(localrules.listing(s, prof))
    conn = _ro(s)
    table(
        [
            (k, t, ts(f, "%Y-%m-%d %H:%M"), ts(r, "%Y-%m-%d %H:%M") if r else "")
            for k, t, f, r in queries.rules_history(conn)
        ],
        ["kind", "rule", "since", "removed"],
    )
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
        print("tvgw undo: run `tvgw adguard apply`")
        return 1
    else:
        # (fin-release) AdGuard held its restart back because the upstreams are down: the revert stands
        # in the file and the record, and the next hourly check pushes it
        deferred = bool(gone) and autoblock.push_owed(conn)
    finally:
        conn.close()
    if deferred:
        print(
            f"tvgw undo: {', '.join(gone)} removed from the rules file; AdGuard held its restart back"
            " (deferred: upstream down) and the next hourly check re-applies it"
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
            return 0
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


def cmd_dnsgate_feed(a, s, prof) -> int:
    from tvgw import dnsgate

    return dnsgate.main(s)


def cmd_dnsgate_inpath(a, s, prof) -> int:
    """(inpath) The in-path filler of design decision 64; exits 0 at once unless DNSGATE_FILL=inpath."""
    from tvgw import inpath

    return inpath.main(s)


def cmd_backup(a, s, prof) -> int:
    """A checked copy of the store; (depth) its outcome is recorded in the store for verify's store_backup."""
    from tvgw import backup

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
        print("tvgw forget deletes every viewing-derived row and file (tvgw forget --dry-run lists them).")
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
    an.set_defaults(fn=cmd_analyst)
    sub.add_parser(
        "dnsgate-feed", help="feed the DNS-gate set from the resolver's answers to the TV (runs as a service)"
    ).set_defaults(fn=cmd_dnsgate_feed)
    sub.add_parser(
        "dnsgate-inpath",
        help="hold each DNS answer to the TV until its addresses are in the gate's in-path set"
        " (runs as a service, with DNSGATE_FILL=inpath)",
    ).set_defaults(fn=cmd_dnsgate_inpath)
    bk = sub.add_parser(
        "backup", help="a checked copy of the store in <STATE_DIR>/backup (VACUUM INTO + quick_check)"
    )
    bk.add_argument(
        "--keep",
        type=int,
        default=7,
        help="days to keep a copy of, newest first, plus the newest copy (default 7)",
    )
    bk.set_defaults(fn=cmd_backup)
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
    _add_check_parser(sub)
    _add_refused_parser(sub)
    _add_activity_parser(sub)
    bu = sub.add_parser("budget", help="the upload budget's ceiling and how it was set")  # (budget)
    bu.add_argument("--json", action="store_true")
    bu.add_argument(
        "--rederive", action="store_true", help="set the ceiling again from the 14 days before today (root)"
    )
    bu.set_defaults(fn=cmd_budget)
    _add_receipt_parser(sub)  # (app in front) design decision 67
    _add_tvlive_parser(sub)
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
    """(deploy window) `tvgw tv quiet`: the CI hardware job's check before a deploy that changes the
    network (design decision 63). Read-only; one line out, never the reason."""
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

    def failed(lines: list[str]) -> int:
        if a.json:
            print(json.dumps({"error": " ".join(lines), "code": refused.UNREAD}, indent=1))
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
        return failed(done.lines)
    if a.json:
        print(json.dumps(refused.as_json(done.report), indent=1))
    else:
        for line in refused.render(done.report, show_all=a.all):
            print(clean(line))
    return done.code


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
        return show({"day": ev["day"], "blocks": ev["blocks"]}, receipt.render_evening(rec, ev))
    rec = receipt.gather(conn, prof, s.gw_ip, a.since, now, events, known_until, now)
    found = receipt.receipts(rec)
    gaps = receipt.gap_summary(rec)
    return show({"sessions": found, "gaps": gaps}, receipt.render(rec, found, gaps, since_arg))


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
    from tvgw import adguardcfg, aghinstall

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
    if a.action == "diff" or a.dry_run:
        print("\n".join(diff) if diff else "AdGuard Home matches the profile and settings")
        for line in _rule_sources(current, prof, s):  # (site rules) the rules by the file each comes from
            print(line)
        if refuse:  # a dry run changes nothing: it says what the apply would do, as diff does
            print("tvgw adguard: warning: tvgw adguard apply would refuse:", file=sys.stderr)
            for line in _takeover_lines(others, s):
                print(line, file=sys.stderr)
        elif others:
            print(f"tvgw adguard: note: the apply would take it over. {others.note()}", file=sys.stderr)
        return 1 if (diff and a.action == "diff") else 0
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
    if a.week:
        o = queries.weekly(conn, a.week, prof, **kw)
    elif a.day:
        o = queries.brief(conn, a.day, prof, **kw)
    elif a.since is None and a.until is None:
        o = queries.latest(conn, 24, prof, **kw)
    else:
        o = queries.window_report(conn, since, until, prof, **kw)
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
    if p.wifi_off:
        checked = "checked on a set of this profile" if p.wifi_off_confirmed else "not checked on a set yet"
        print(f"Wi-Fi off ({checked}): {clean(p.wifi_off)}")
    problems = p.lint()
    print("rules lint: " + ("clean" if not problems else "; ".join(clean(x) for x in problems)))
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


def _needs_settings(e: PermissionError) -> NoReturn:
    """(depth) A PermissionError, said in one sentence to an account that is not root. Root reads every
    file of the gateway's, so for root it is something else (a sandboxed unit's limits, an access rule):
    "run it with sudo" would be wrong there, and the traceback says what it is."""
    if os.geteuid() == 0:
        raise e
    sys.exit(NEEDS_SETTINGS)


if __name__ == "__main__":
    sys.exit(main())
