"""`tvgw` command line: ingest the sources, then ask the store questions."""

from __future__ import annotations

import argparse
import json
import os
import re
import sys
from collections.abc import Iterable, Sequence
from datetime import datetime

from tvgw import __version__, config, db, ingest, profile, queries


def hb(n: float | None) -> str:
    n = float(n or 0)
    for unit in ("B", "K", "M", "G"):
        if n < 1024 or unit == "G":
            return f"{n:.0f}B" if unit == "B" else f"{n:.1f}{unit}"
        n /= 1024
    return f"{n:.1f}G"


def ts(t: float | None, fmt: str = "%m-%d %H:%M") -> str:
    return datetime.fromtimestamp(t).strftime(fmt) if t else "-"


def table(rows: Iterable[Sequence], headers: Sequence[str], out=None) -> None:
    out = out or sys.stdout  # resolved at call time so pytest's capture (and redirects) see it
    rows = [[str(c) for c in r] for r in rows]
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
    print(
        f"=== {o['day']}: {d['lookups']} lookups ({d['blocked']} blocked, {d['names']} names), "
        f"{f['conns']} connections, up {hb(f['bytes_up'])} down {hb(f['bytes_down'])}",
        file=out,
    )
    print(f"\nNew hosts ({len(o['new_hosts'])}):", file=out)
    table(
        [
            (h["name"], h["category"], h["dns"], h["tls"], h["http"], state_word(h["blocked"]))
            for h in o["new_hosts"]
        ],
        ["name", "category", "dns", "tls", "http", "state"],
        out,
    )
    print("\nBlocked and still retried:", file=out)
    table(
        [(r["name"], r["lookups"], r["rule"]) for r in o["blocked_retries"]], ["name", "lookups", "rule"], out
    )
    print("\nAllowed, non-streaming:", file=out)
    table([(r["name"], r["lookups"]) for r in o["allowed_non_streaming"]], ["name", "lookups"], out)
    print("\nTop upload:", file=out)
    table(
        [
            (
                r["name"] or "(no TLS name)",
                f"{r['dst']}:{r['dport']}",
                r["conns"],
                hb(r["bytes_up"]),
                hb(r["bytes_down"]),
            )
            for r in o["top_upload"]
        ],
        ["name", "dst", "conns", "up", "down"],
        out,
    )
    gf = ", ".join(f"{g['status']} {g['biz_code']}: {g['requests']} ({hb(g['bytes'])})" for g in o["gfts"])
    print(f"\nURL filter: {gf or '(no requests)'}", file=out)
    odd = ", ".join(f"{x['proto']}/{x['dport']} -> {x['dst']} x{x['n']}" for x in o["oddports"])
    print(f"Unexpected ports: {odd or 'none'}", file=out)
    print(
        "TV by hour: "
        + (" ".join(f"{s['time']}={s['power'] or '?'}" for s in o["tvstate"]) or "(no readings)"),
        file=out,
    )
    if o["rule_changes"]:
        print("Rule changes:", file=out)
        table(
            [
                (
                    c["kind"],
                    c["text"],
                    ts(c["added"], "%Y-%m-%d %H:%M"),
                    ts(c["removed"], "%Y-%m-%d %H:%M") if c["removed"] else "",
                )
                for c in o["rule_changes"]
            ],
            ["kind", "rule", "added", "removed"],
            out,
        )


def cmd_ingest(a, s, prof) -> int:
    stats = ingest.run(s, prof)
    for w in stats.warnings:
        print(f"tvgw ingest: {w}", file=sys.stderr)
    size = os.path.getsize(s.db_path) / 1e6 if os.path.exists(s.db_path) else 0
    print(f"tvgw ingest: {stats.summary()}; db {size:.1f} MB")
    return 0


def _ro(s):
    try:
        return db.connect(s.db_path, readonly=True)
    except Exception as e:  # any open failure means the same thing to the operator
        sys.exit(f"cannot open {s.db_path}: {e} (run `sudo tvgw ingest` first?)")


def cmd_brief(a, s, prof) -> int:
    conn = _ro(s)
    o = queries.brief(conn, a.day or queries.yesterday())
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
    rows = queries.allowed_non_streaming(conn, queries.since_epoch(a.since))
    table(
        [(r[0], r[1], ts(r[2]), r[3]) for r in rows],
        ["allowed name (non-streaming)", "lookups", "last", "allow rule"],
    )
    return 0


def cmd_top_upload(a, s, prof) -> int:
    conn = _ro(s)
    rows = queries.top_upload(conn, queries.since_epoch(a.since))
    table(
        [(r[0] or "(no TLS name)", f"{r[1]}:{r[2]}", r[3], hb(r[4]), hb(r[5])) for r in rows],
        ["name", "dst", "conns", "up", "down"],
    )
    return 0


def cmd_host(a, s, prof) -> int:
    conn = _ro(s)
    h = queries.host_detail(conn, a.name)
    if not h:
        print("not seen")
        return 1
    print(
        f"{h['name']}  category={h['category']}  first={ts(h['first_seen'], '%Y-%m-%d %H:%M')}  "
        f"last={ts(h['last_seen'], '%Y-%m-%d %H:%M')}  dns={h['dns_n']} tls={h['tls_n']} http={h['http_n']}  "
        f"state={state_word(h['last_blocked'])}"
    )
    print("rules seen in answers:", ", ".join(h["rules"]) or "(none)")
    if h["ips"]:
        print("TLS to:", ", ".join(f"{ip} x{n}" for ip, n in h["ips"]))
        print(f"flows to those IPs: up {hb(h['bytes_up'])} down {hb(h['bytes_down'])}")
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
    if not re.match(r"\s*(select|with|explain|pragma)\b", sql, re.I):
        sys.exit("read-only: SELECT/WITH only")
    conn = _ro(s)
    cur = conn.execute(sql)
    table(cur.fetchall(), [d[0] for d in cur.description or []])
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
    b = sub.add_parser("brief", help="one-screen daily brief (default: yesterday)")
    b.add_argument("day", nargs="?")
    b.add_argument("--json", action="store_true")
    b.set_defaults(fn=cmd_brief)
    for name, fn, help_ in (
        ("new-hosts", cmd_new_hosts, "names first seen since SINCE"),
        ("retries", cmd_retries, "blocked names the TV keeps asking for"),
        ("allowed", cmd_allowed, "allowed, non-streaming names by lookups"),
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
        "report", help="traffic report from the hourly report files (tvgw report --help)", add_help=False
    )
    r.add_argument("args", nargs=argparse.REMAINDER)
    r.set_defaults(fn=cmd_report)
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
    from tvgw import report

    return report.main([*a.args, "--profile", s.profile] if "--profile" not in a.args else a.args)


def cmd_tvcheck(a, s, prof) -> int:
    from tvgw import lgwebos

    reading = lgwebos.read(s.tv_ip, a.key_file)
    print("\n".join(reading.lines()))
    return reading.exit_code()


def main(argv: Sequence[str] | None = None) -> int:
    p = build_parser()
    a, rest = p.parse_known_args(argv)
    if a.cmd == "report":
        a.args = [*rest, *a.args]  # argparse.REMAINDER drops options before the first positional
    elif rest:
        p.error(f"unrecognized arguments: {' '.join(rest)}")
    overrides = {"db_path": a.db} if a.db else {}
    s = config.load(a.conf, **overrides)
    prof = profile.load(s.profile)
    return a.fn(a, s, prof)


if __name__ == "__main__":
    sys.exit(main())
