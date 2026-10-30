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

from tvgw import __version__, config, db, ingest, pcaps, profile, queries


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
        print(f"Coverage: {', '.join(parts)}; last ingest {ts(cov['last_run'], '%m-%d %H:%M')}", file=out)
        if cov["not_assessed"]:
            print(f"NOT ASSESSED (source not read recently): {', '.join(cov['not_assessed'])}", file=out)
        for w in cov["warnings"]:
            print(f"ingest warning: {clean(w)}", file=out)
    for line in o.get("red_lines", []):
        print(f"RED LINE: {clean(line)}", file=out)
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
    sb = o.get("standby")
    if sb and sb["off_hours"]:
        print(
            f"While off/asleep ({sb['off_hours']:g} h): {sb['lookups']} lookups, {sb['conns']} connections, "
            f"up {hb(sb['bytes_up'])}",
            file=out,
        )
    ptr = o.get("ptr")
    if ptr and ptr["lookups"]:
        print(
            f"Private reverse lookups (LAN inventory): {ptr['lookups']} for {ptr['names']} names",
            file=out,
        )
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
    gate = o.get("gate") or {}
    if gate.get("new_connections") or gate.get("examples"):
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
    auto = o.get("autonomous") or {}
    if auto.get("blocked") or auto.get("decided"):
        print(
            "\nRules the gateway added on its own (design decision 20; `tvgw undo` takes the newest out):",
            file=out,
        )
        seen: set[str] = set()
        rows = []
        for r in auto.get("blocked", []) + auto.get("decided", []):
            if r["rule"] in seen:
                continue
            seen.add(r["rule"])
            why = clean(r["reason"] or r["verifier_reason"] or "")[:70]
            rows.append((r["rule"], ts(r["added_t"], "%m-%d %H:%M"), r["verdict"] or "on probation", why))
        table(rows, ["machine rule", "added", "verdict", "why"], out)
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
    print("\nTV: " + (clean(shown) if runs else "no readings"), file=out)
    if o.get("settings_changes"):
        print("\nTV settings (first reading or change):", file=out)
        table(
            [(ts(r["t"], "%m-%d %H:%M"), r["key"], r["value"]) for r in o["settings_changes"]],
            ["time", "key", "value"],
            out,
        )
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
    """Retention for the raw captures: only files ingest has read, never the one tcpdump is writing."""
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
    try:
        return db.connect(s.db_path, readonly=True)
    except Exception as e:  # any open failure means the same thing to the operator
        sys.exit(f"cannot open {s.db_path}: {e} (run `sudo tvgw ingest` first?)")


def cmd_brief(a, s, prof) -> int:
    conn = _ro(s)
    o = queries.brief(conn, a.day or queries.yesterday(), prof, gw_ip=s.gw_ip)
    if a.json:
        print(json.dumps(o, indent=1))
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
    from tvgw import analyst

    conn = db.connect(s.db_path)
    try:
        gone = analyst.undo(conn, s, prof, everything=a.all)
    except Exception as e:  # the file is already changed; AdGuard is not
        print(
            f"tvgw undo: the rules file was changed but AdGuard was not re-applied ({type(e).__name__}: {e})"
        )
        print("tvgw undo: run `tvgw adguard apply`")
        return 1
    finally:
        conn.close()
    print(
        "tvgw undo: "
        + (", ".join(gone) + " removed and AdGuard re-applied" if gone else "no machine rule to remove")
    )
    return 0


def cmd_autoblock(a, s, prof) -> int:
    from tvgw import analyst, autoblock

    conn = db.connect(s.db_path)
    try:
        if a.action == "check":
            decisions = analyst.check(conn, s, prof)
            for d in decisions:
                print(f"tvgw autoblock: {d['verdict']} {d['rule']} ({d['reason']})")
            if any(d.get("reapply_failed") for d in decisions):
                print(
                    "tvgw autoblock: WARNING: a reverted rule is still in AdGuard; run `tvgw adguard apply`"
                )
                return 1
            if not decisions:
                print(
                    f"tvgw autoblock: {len(autoblock.pending(conn))} rule(s) on probation, nothing to decide"
                )
            return 0
        table(
            [
                (
                    r["rule"],
                    ts(r["added_t"]),
                    r["verdict"] or "on probation",
                    clean(r["reason"] or r["verifier_reason"] or "")[:60],
                )
                for r in autoblock.rows(conn)
            ],
            ["machine rule", "added", "verdict", "why"],
        )
        return 0
    finally:
        conn.close()


def cmd_dnsgate_feed(a, s, prof) -> int:
    from tvgw import dnsgate

    return dnsgate.main(s)


def cmd_backup(a, s, prof) -> int:
    from tvgw import backup

    try:
        b = backup.run(s.db_path, os.path.join(s.state_dir, "backup"), keep=a.keep)
    except (sqlite3.Error, OSError, RuntimeError, ValueError) as e:
        print(f"tvgw backup: FAILED: {e}", file=sys.stderr)
        return 1
    removed = f"; removed {', '.join(b.removed)}" if b.removed else ""
    print(f"tvgw backup: {b.path} ({b.size / 1e6:.1f} MB, quick_check ok); {len(b.kept)} kept{removed}")
    return 0


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
    b.add_argument("--json", action="store_true")
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
    sub.add_parser("rules", help="our policy as history").set_defaults(fn=cmd_rules)
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
    ab.add_argument("action", choices=["check", "list"])
    ab.set_defaults(fn=cmd_autoblock)
    an.set_defaults(fn=cmd_analyst)
    sub.add_parser(
        "dnsgate-feed", help="feed the DNS-gate set from the resolver's answers to the TV (runs as a service)"
    ).set_defaults(fn=cmd_dnsgate_feed)
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
    pr.set_defaults(fn=cmd_profile)
    v = sub.add_parser("verify", help="check that firewall, routing, resolver and services still hold")
    v.add_argument("--record", action="store_true", help="also store the verdict and firewall counters")
    v.add_argument("--json", action="store_true")
    v.set_defaults(fn=cmd_verify)
    t = sub.add_parser("tvcheck", help="read the TV's privacy settings over its LAN API (LG webOS)")
    t.add_argument("--key-file", default="/var/lib/tvgw/lgtv-keys.sqlite")
    t.set_defaults(fn=cmd_tvcheck)
    g = sub.add_parser("adguard", help="AdGuard Home blocklists, rules and settings from the profile")
    g.add_argument(
        "action", choices=["diff", "apply"], help="diff: show drift (exit 1 if any); apply: write it"
    )
    g.add_argument(
        "--dry-run", action="store_true", help="with apply: show what would change, change nothing"
    )
    g.set_defaults(fn=cmd_adguard)
    return p


def cmd_adguard(a, s, prof) -> int:
    from tvgw import adguardcfg

    problems = prof.lint()  # the CI guard, applied to the profile this gateway is about to run
    if problems:
        sys.exit("tvgw adguard: the profile does not lint: " + "; ".join(clean(x) for x in problems))
    try:
        d = adguardcfg.desired(prof, s)
        current = adguardcfg.load_yaml(s.adguard_yaml)
    except OSError as e:
        sys.exit(f"cannot read {s.adguard_yaml}: {e} (is AdGuard Home installed and set up?)")
    except ValueError as e:
        sys.exit(f"tvgw adguard: {e}")
    diff = adguardcfg.changes(current, adguardcfg.plan(current, d))
    if a.action == "diff" or a.dry_run:
        print("\n".join(diff) if diff else "AdGuard Home matches the profile and settings")
        return 1 if (diff and a.action == "diff") else 0
    if not diff:
        print("AdGuard Home already matches; nothing to do")
        return 0
    try:
        applied = adguardcfg.apply(
            s.adguard_yaml,
            d,
            # ready means the TV's clock host resolves through the new config, not that the port answers
            ready=lambda: adguardcfg.dns_ready(name=next(iter(prof.must_allow), "example.com")),
        )
    except RuntimeError as e:  # rejected by AdGuard, rolled back, or another apply is running
        sys.exit(f"tvgw adguard: {e}")
    print(f"tvgw adguard: applied {len(applied)} change(s) to {s.adguard_yaml} and restarted AdGuard Home")
    for c in applied:
        print("  " + c)
    return 0


def _usage(msg: str) -> int:
    print(f"tvgw report: error: {msg}", file=sys.stderr)
    return 2  # argparse's own exit status for a usage error


def cmd_report(a, s, prof) -> int:
    if a.until is not None and (a.day or a.week):
        return _usage("--until goes with --since")
    until = a.until if a.until is not None else time.time()
    since = a.since if a.since is not None else until - 86400
    if since >= until:
        return _usage("--since must be before --until")
    conn = _ro(s)
    if a.week:
        o = queries.weekly(conn, a.week, prof, gw_ip=s.gw_ip)
    elif a.day:
        o = queries.brief(conn, a.day, prof, gw_ip=s.gw_ip)
    elif a.since is None and a.until is None:
        o = queries.latest(conn, 24, prof, gw_ip=s.gw_ip)
    else:
        o = queries.window_report(conn, since, until, prof, gw_ip=s.gw_ip)
    if a.json:
        print(json.dumps(o, indent=1))
    else:
        render_brief(o)
    return 0


def _load_profile(name: str) -> profile.Profile:
    """The profile by bundled name or TOML path. A profile that cannot be read whole is one line and
    exit 1, never a traceback and never a profile with fewer rules than were written."""
    try:
        return profile.load(name)
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
        print("no bundled profile matches this vendor; PROFILE was left as it was (docs/adding-a-profile.md)")
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


def cmd_profile(a, s, prof) -> int:
    """What this profile knows: must-allow names, expected categories, lint, generations, hardware."""
    p = _load_profile(a.profile) if a.profile else prof
    print(f"{p.name}: {p.description}" + (f" (vendor {p.vendor})" if p.vendor else ""))
    clock = ", ".join(p.clock_hosts) or "-"
    print(f"expected categories: {', '.join(p.expected_categories)}; clock hosts: {clock}")
    problems = p.lint()
    print("rules lint: " + ("clean" if not problems else "; ".join(clean(x) for x in problems)))
    print(f"\nMust stay allowed ({len(p.must_allow)}):")
    table(sorted(p.must_allow.items()), ["name", "why"])
    gen = p.generation_for(a.webos, a.firmware) if (a.webos or a.firmware) else None
    if a.webos or a.firmware:
        print(f"\nGeneration for webOS {a.webos or '?'} / firmware {a.firmware or '?'}:")
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


def cmd_tvcheck(a, s, prof) -> int:
    from tvgw import lgwebos

    reading = lgwebos.read(s.tv_ip, a.key_file)
    print("\n".join(reading.lines()))
    return reading.exit_code()


def main(argv: Sequence[str] | None = None) -> int:
    # what the gateway prints is UTF-8 whatever the locale says (the Pi's was en_US with no charset,
    # which is latin-1), and a character the stream cannot carry becomes a '?' instead of a crash
    for stream in (sys.stdout, sys.stderr):
        with contextlib.suppress(AttributeError, ValueError, OSError):
            stream.reconfigure(encoding="utf-8", errors="replace")
    p = build_parser()
    a = p.parse_args(argv)
    overrides = {"db_path": a.db} if a.db else {}
    try:
        s = config.load(a.conf, **overrides)
    except ValueError as e:
        sys.exit(f"tvgw: {e}")
    prof = _load_profile(s.profile)
    return a.fn(a, s, prof)


if __name__ == "__main__":
    sys.exit(main())
