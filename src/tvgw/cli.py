"""`tvgw` command line: ingest the sources, then ask the store questions."""

from __future__ import annotations

import argparse
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
    for unit in ("B", "K", "M", "G"):
        if n < 1024 or unit == "G":
            return f"{n:.0f}B" if unit == "B" else f"{n:.1f}{unit}"
        n /= 1024
    return f"{n:.1f}G"


def ts(t: float | None, fmt: str = "%m-%d %H:%M") -> str:
    return datetime.fromtimestamp(t).strftime(fmt) if t else "-"


_CTRL = {c: f"\\x{c:02x}" for c in [*range(0x20), 0x7F, *range(0x80, 0xA0)]}


def clean(v) -> str:
    """Text for the terminal. Names, URIs and user agents come from the TV and from servers it
    talks to; control characters in them must not reach the terminal as control characters."""
    return str(v).translate(_CTRL)


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
    title = o.get("label") or o["day"]
    print(
        f"=== {title}: {d['lookups']} lookups ({d['blocked']} blocked, {d['names']} names), "
        f"{f['conns']} connections, up {hb(f['bytes_up'])} down {hb(f['bytes_down'])}",
        file=out,
    )
    cov = o.get("coverage")
    if cov:
        parts = [f"{src} {v['rows']}" for src, v in cov["sources"].items()]
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
            f"While off/asleep ({sb['off_hours']} h): {sb['lookups']} lookups, {sb['conns']} connections, "
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
    print("\nAllowed, outside the expected categories:", file=out)
    table(
        [(r["name"], r["category"], r["lookups"]) for r in o["allowed_unexpected"]],
        ["name", "category", "lookups"],
        out,
    )
    print("\nTop upload (per TLS name; IP when no hello was captured):", file=out)
    table(
        [
            (
                r["name"] or "(no TLS name)",
                r["dst"] if r["ips"] == 1 else f"{r['dst']} +{r['ips'] - 1}",
                r["dport"],
                r["conns"],
                hb(r["bytes_up"]),
                hb(r["bytes_down"]),
            )
            for r in o["top_upload"]
        ],
        ["name", "dst", "port", "conns", "up", "down"],
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
        print("\nUnresolved flows (no DNS answer, TLS name or HTTP host explains the address):", file=out)
        table(
            [
                (u["dst"], u["dport"], u["conns"], hb(u["bytes_up"]), hb(u["bytes_down"]))
                for u in o["unresolved"]
            ],
            ["dst", "port", "conns", "up", "down"],
            out,
        )
    for fc in o.get("firmware_changes", []):
        print(
            f"\nFirmware {fc['firmware']} seen {ts(fc['t'], '%m-%d %H:%M')}; new names in the 72 h after:",
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
    print(
        "\nTV: "
        + (
            ", ".join(f"{s['time']}={s['power'] or '?'}" for s in o["tvstate"])
            if o["tvstate"]
            else "no readings"
        ),
        file=out,
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
    rows = queries.new_hosts(conn, queries.since_epoch(a.since))
    table(
        [(r[0], r[1], ts(r[2], "%Y-%m-%d %H:%M"), r[3], r[4], r[5], state_word(r[6]), r[7]) for r in rows],
        ["name", "category", "first seen", "dns", "tls", "http", "state", "rule"],
    )
    return 0


def cmd_retries(a, s, prof) -> int:
    conn = _ro(s)
    rows = queries.blocked_retries(conn, queries.since_epoch(a.since))
    table(
        [(r[0], r[1], ts(r[2]), ts(r[3]), r[4]) for r in rows],
        ["blocked name", "lookups", "first", "last", "rule"],
    )
    return 0


def cmd_allowed(a, s, prof) -> int:
    conn = _ro(s)
    rows = queries.allowed_unexpected(conn, queries.since_epoch(a.since), None, prof)
    table(
        [(r[0], r[1], r[2], ts(r[3]), r[4]) for r in rows],
        ["allowed name (unexpected category)", "category", "lookups", "last", "allow rule"],
    )
    return 0


def cmd_top_upload(a, s, prof) -> int:
    conn = _ro(s)
    rows = queries.top_upload(conn, queries.since_epoch(a.since))
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
    rows = queries.gfts_summary(conn, queries.since_epoch(a.since))
    table([(r[0], r[1], r[2], hb(r[3])) for r in rows], ["status", "biz_code", "requests", "bytes"])
    return 0


def cmd_tvstate(a, s, prof) -> int:
    conn = _ro(s)
    since = queries.since_epoch(a.since)
    table(
        [(ts(t, "%Y-%m-%d %H:%M"), p, app) for t, p, app in queries.tvstate(conn, since)],
        ["time", "power", "app"],
    )
    ch = queries.settings_changes(conn, since)
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
    b.add_argument("day", nargs="?")
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
        sp.add_argument("since", nargs="?", default="1d", help="2h, 1d, 7d or an ISO time (default 1d)")
        sp.set_defaults(fn=fn)
    h = sub.add_parser("host", help="everything about one name")
    h.add_argument("name")
    h.set_defaults(fn=cmd_host)
    sub.add_parser("rules", help="our policy as history").set_defaults(fn=cmd_rules)
    sub.add_parser("size", help="row counts and file size").set_defaults(fn=cmd_size)
    q = sub.add_parser("sql", help="read-only SQL")
    q.add_argument("query", nargs="+")
    q.set_defaults(fn=cmd_sql)
    r = sub.add_parser(
        "report", help="the brief over a window: a day, an ISO week, or --since/--until (default: last 24 h)"
    )
    r.add_argument("--day", help="YYYY-MM-DD")
    r.add_argument("--week", help="ISO week, e.g. 2026-W44 (Monday to Sunday)")
    r.add_argument("--since", help="2h, 1d, 7d or an ISO time")
    r.add_argument("--until", help="same forms; default now")
    r.add_argument("--json", action="store_true")
    r.set_defaults(fn=cmd_report)
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

    d = adguardcfg.desired(prof, s)
    try:
        current = adguardcfg.load_yaml(s.adguard_yaml)
    except OSError as e:
        sys.exit(f"cannot read {s.adguard_yaml}: {e} (is AdGuard Home installed and set up?)")
    diff = adguardcfg.changes(current, adguardcfg.plan(current, d))
    if a.action == "diff" or a.dry_run:
        print("\n".join(diff) if diff else "AdGuard Home matches the profile and settings")
        return 1 if (diff and a.action == "diff") else 0
    if not diff:
        print("AdGuard Home already matches; nothing to do")
        return 0
    applied = adguardcfg.apply(s.adguard_yaml, d)
    print(f"tvgw adguard: applied {len(applied)} change(s) to {s.adguard_yaml} and restarted AdGuard Home")
    for c in applied:
        print("  " + c)
    return 0


def cmd_report(a, s, prof) -> int:
    conn = _ro(s)
    if a.week:
        o = queries.weekly(conn, a.week, prof, gw_ip=s.gw_ip)
    elif a.day:
        o = queries.brief(conn, a.day, prof, gw_ip=s.gw_ip)
    elif a.since or a.until:
        until = queries.since_epoch(a.until) if a.until else time.time()
        since = queries.since_epoch(a.since) if a.since else until - 86400
        o = queries.window_report(conn, since, until, prof, gw_ip=s.gw_ip)
    else:
        o = queries.latest(conn, 24, prof, gw_ip=s.gw_ip)
    if a.json:
        print(json.dumps(o, indent=1))
    else:
        render_brief(o)
    return 0


def cmd_profile(a, s, prof) -> int:
    """What this profile knows: must-allow names, expected categories, lint, generations, hardware."""
    p = profile.load(a.profile) if a.profile else prof
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
    if a.model:
        h = p.hardware_for(a.model)
        print(f"\nHardware for {clean(a.model)}:")
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
    p = build_parser()
    a = p.parse_args(argv)
    overrides = {"db_path": a.db} if a.db else {}
    try:
        s = config.load(a.conf, **overrides)
    except ValueError as e:
        sys.exit(f"tvgw: {e}")
    prof = profile.load(s.profile)
    return a.fn(a, s, prof)


if __name__ == "__main__":
    sys.exit(main())
