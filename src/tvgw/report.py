#!/usr/bin/env python3
"""tvgw-report: who does the LG TV talk to, how much does it SEND, and which of it is
LG telemetry / ads / ACR vs. normal streaming.

Inputs (each optional; a missing one just thins out the report):
  flows.log      conntrack -E -e DESTROY -o timestamp,extended   (bytes per connection)
  querylog.json  AdGuard Home GET /control/querylog response       (names, blocked?)
  sni.tsv        tshark TLS ClientHello: epoch src sport dst dport sni
  http.tsv       tshark plain HTTP: epoch dst method host uri user_agent content_length

Examples:
  tvgw-report.py --since 2h
  tvgw-report.py --since 2026-10-25 --until 2026-10-26     # one calendar day
  tvgw-report.py --dir ./tvdata --top 40
  tvgw-report.py --json | jq .categories
Times print in local time (TZ=America/Chicago to override). Stdlib only, Python 3.11+.
"""

import argparse
import bisect
import gzip
import ipaddress
import json
import os
import re
import signal
import sys
import time
from collections import Counter, defaultdict
from datetime import datetime

from tvgw import profile as _profile

# Categories come from the TV profile (tvgw.profile); set_profile() swaps it in.
OTHER, UNRES, DNS, LOCAL = "Other", "UNRESOLVED", "DNS", "Local"
PROFILE = _profile.load("lg-webos")
CAT_ORDER = [*PROFILE.category_order, OTHER, UNRES, DNS, LOCAL]


def set_profile(p):
    """Use another TV profile for categorization (CAT_ORDER follows it)."""
    global PROFILE, CAT_ORDER
    PROFILE = p
    CAT_ORDER = [*p.category_order, OTHER, UNRES, DNS, LOCAL]


DEFAULTS = {
    "flows": "/var/log/tvgw/flows.log",
    "querylog": "/var/lib/tvgw/querylog.json",
    "sni": "/var/lib/tvgw/sni.tsv",
    "http": "/var/lib/tvgw/http.tsv",
}
URI_W = 88  # plain-HTTP URIs are cut here; requests sharing a cut URI are grouped


def warn(msg):
    print(f"tvgw-report: {msg}", file=sys.stderr)


def read_lines(path):
    """Lines of a text file (.gz ok); [] plus a warning if it can't be read."""
    try:
        opener = gzip.open if path.endswith(".gz") else open
        with opener(path, "rt", encoding="utf-8", errors="replace") as fh:
            return fh.read().splitlines()
    except OSError as e:
        warn(f"skipping {path}: {e.strerror or e}")
        return []


def parse_time(s):
    """RFC3339 with any number of fraction digits (AdGuard sends 9) -> epoch."""
    m = re.match(r"(\d{4}-\d\d-\d\d[T ]\d\d:\d\d:\d\d)(?:\.(\d+))?(Z|[+-]\d\d:?\d\d)?$", s.strip())
    if not m:
        return None
    frac = (m.group(2) or "0")[:6].ljust(6, "0")
    tz = (m.group(3) or "").replace("Z", "+00:00")
    try:
        return datetime.fromisoformat(f"{m.group(1)}.{frac}{tz}").timestamp()
    except ValueError:
        return None


def parse_since(s):
    m = re.fullmatch(r"(\d+(?:\.\d+)?)\s*([smhdw])", s.strip().lower())
    if m:
        unit = {"s": 1, "m": 60, "h": 3600, "d": 86400, "w": 604800}[m.group(2)]
        return time.time() - float(m.group(1)) * unit
    try:  # naive ISO times are local
        return datetime.fromisoformat(s.strip().replace("Z", "+00:00")).timestamp()
    except ValueError:
        if (t := parse_time(s)) is None:
            raise argparse.ArgumentTypeError(f"bad time {s!r}; use 2h, 30m, 1d or ISO 8601") from None
        return t


# ---- Parsers --------------------------------------------------------------------
FLOW_KEYS = ("src", "dst", "sport", "dport", "packets", "bytes")


def parse_flow(line):
    """One `conntrack -E -o timestamp,extended` DESTROY line -> dict, or None.
    First src/dst/.../bytes tuple = original direction (TV -> world = upload), second =
    reply (download). UDP/ICMP have no state word; ICMP has no ports."""
    toks = line.split()
    if len(toks) < 6 or not toks[0].startswith("[") or "[DESTROY]" not in toks:
        return None
    try:
        end = float(toks[0].strip("[]"))
        fam = next(i for i, t in enumerate(toks) if t in ("ipv4", "ipv6"))
        proto = toks[fam + 2]
    except (ValueError, StopIteration, IndexError):
        return None
    orig, reply, extra, flags, state = {}, {}, {}, [], ""
    cur = orig
    for t in toks[fam + 4 :]:
        if t.startswith("[") and t.endswith("]"):
            flags.append(t[1:-1])  # ASSURED, UNREPLIED
            continue
        k, eq, v = t.partition("=")
        if not eq:
            state = state or t  # ESTABLISHED, CLOSE, LAST_ACK, ...
            continue
        if k == "src" and cur is orig and "src" in orig:
            cur = reply
        if k in FLOW_KEYS and k not in cur:
            cur[k] = v
        else:
            extra.setdefault(k, v)  # delta-time, id, mark, zone, ...
    if "src" not in orig or "dst" not in orig:
        return None

    def num(d, k):
        return int(d[k]) if d.get(k, "").isdigit() else 0

    try:
        dur = float(extra["delta-time"])
    except (KeyError, ValueError):
        dur = None
    return {
        "end": end,
        "dur": dur,
        "start": end - (dur or 0),
        "proto": proto,
        "state": state,
        "src": orig["src"],
        "dst": orig["dst"],
        "sport": num(orig, "sport"),
        "dport": num(orig, "dport"),
        "up": num(orig, "bytes"),
        "down": num(reply, "bytes"),
        "up_pkts": num(orig, "packets"),
        "down_pkts": num(reply, "packets"),
        "reply_src": reply.get("src", ""),
        "flags": flags,
    }


def load_querylog(path, tv_ip):
    """AdGuard querylog JSON ({"data": [...]} or a bare list) -> list of query dicts."""
    text = "\n".join(read_lines(path))
    try:
        doc = json.loads(text) if text.strip() else []
    except json.JSONDecodeError as e:
        warn(f"skipping {path}: bad JSON ({e})")
        return []
    rows = doc.get("data") if isinstance(doc, dict) else doc
    out = []
    for e in rows if isinstance(rows, list) else []:
        if not isinstance(e, dict) or e.get("client", tv_ip) != tv_ip:
            continue
        name = str((e.get("question") or {}).get("name") or "").lower().rstrip(".")
        t = parse_time(str(e.get("time", "")))
        if not name or t is None:
            continue
        # A/AAAA answers map IP -> queried name; CNAME targets are ignored on purpose
        ips = [
            a.get("value")
            for a in e.get("answer") or []
            if isinstance(a, dict) and a.get("type") in ("A", "AAAA")
        ]
        reason = str(e.get("reason") or "")
        out.append(
            {
                "t": t,
                "name": name,
                "blocked": reason.startswith("Filtered"),
                "ips": [ip for ip in ips if isinstance(ip, str) and ip not in ("0.0.0.0", "::")],
            }
        )
    return out


def load_sni(path, tv_ip):
    """sni.tsv -> {(sport, dst, dport): [(epoch, sni), ...]}; retransmits dropped."""
    idx = defaultdict(list)
    for line in read_lines(path):
        f = line.split("\t")
        if len(f) < 6 or f[1] != tv_ip:
            continue
        try:
            t, key = float(f[0]), (int(f[2]), f[3], int(f[4]))
        except ValueError:
            continue
        sni = f[5].split(",")[0].strip().lower().rstrip(".")
        if sni and not (idx[key] and idx[key][-1][1] == sni and t - idx[key][-1][0] < 10):
            idx[key].append((t, sni))
    return idx


def split_n(s, n):
    """tshark joins repeated fields with ','; split back into n values when possible."""
    parts = s.split(",")
    if n == 1:
        return [s]
    if len(parts) % n == 0:  # also copes with values that contain commas themselves
        k = len(parts) // n
        return [",".join(parts[i * k : (i + 1) * k]) for i in range(n)]
    return parts + [""] * (n - len(parts)) if len(parts) < n else [s] + [""] * (n - 1)


def load_http(path):
    """http.tsv -> one dict per request (pipelined requests in one packet are split)."""
    out = []
    for line in read_lines(path):
        f = (line.split("\t") + [""] * 7)[:7]
        try:
            t = float(f[0])
        except ValueError:
            continue
        if not f[2].strip():  # no request method: not a request line
            continue
        n = len(f[2].split(","))
        for m, host, uri, ua, cl in zip(f[2].split(","), *(split_n(x, n) for x in f[3:7]), strict=False):
            host = host.strip().lower()
            out.append(
                {
                    "t": t,
                    "dst": f[1],
                    "method": m.strip(),
                    "name": re.sub(r":\d+$", "", host) or f[1],
                    "uri": uri.strip(),
                    "ua": ua.strip(),
                    "clen": int(cl) if cl.strip().isdigit() else 0,
                }
            )
    return out


# ---- Naming & categories ----------------------------------------------------------
def categorize(host):
    return PROFILE.categorize(host)


def is_local(ip):
    try:
        a = ipaddress.ip_address(ip)
    except ValueError:
        return False
    return a.is_multicast or not a.is_global


def dns_lookup(dns_idx, ip, t):
    """Most recent AdGuard answer for ip at/before t (2 s slack) -> (name, how)."""
    entries = dns_idx.get(ip)
    if not entries:
        return None, None
    i = bisect.bisect_right(entries, (t + 2, "\uffff"))
    return (entries[i - 1][1], "dns") if i else (entries[0][1], "dns-late")  # querylog may not reach back


def resolve(f, sni_idx, http_idx, dns_idx, gw, used_sni):
    """-> (name, category, how). Order: TLS SNI, HTTP Host, AdGuard answer, unresolved."""
    dst, dport = f["dst"], f["dport"]
    if dport in (53, 853) and f["proto"] in ("udp", "tcp"):
        label = f"{'DoT' if dport == 853 else 'DNS'} -> {dst}" + (" (tvgw)" if dst == gw else "")
        return label, DNS, "dns-flow"
    if is_local(dst):
        return (f"{dst}:{dport}" if dport else dst), LOCAL, "lan"
    # conntrack's start (end - delta-time) runs a few seconds late: DESTROY events arrive
    # in GC batches and delta-time is whole seconds. So allow 30 s of slack before it.
    lo = f["start"] - 30 if f["dur"] is not None else f["end"] - 86400
    key = (f["sport"], dst, dport)
    cands = [(abs(t - f["start"]), t, n) for t, n in sni_idx.get(key, ()) if lo <= t <= f["end"] + 5]
    if cands:
        _, t, name = min(cands)
        used_sni.add((*key, t))
        return name, categorize(name), "sni"
    reqs = http_idx.get(dst, [])
    near = [h for t, h in reqs if lo <= t <= f["end"] + 5] or ([h for _, h in reqs] if dport == 80 else [])
    if near:
        name = Counter(near).most_common(1)[0][0]
        return name, categorize(name), "http"
    name, how = dns_lookup(dns_idx, dst, f["start"])
    return (name, categorize(name), how) if name else (f"UNRESOLVED {dst}", UNRES, "none")


# ---- Report -------------------------------------------------------------------------
def agg(d, key, t0, t1, base, **add):
    """Add numeric fields into bucket d[key] (created from base); track first/last seen."""
    b = d.setdefault(key, dict(base, first=t0, last=t1))
    b["first"], b["last"] = min(b["first"], t0), max(b["last"], t1)
    for k, v in add.items():
        b[k] += v
    return b


def build_report(a):
    def in_win(t):
        return (a.since is None or t >= a.since) and (a.until is None or t < a.until)

    raw = [parse_flow(ln) for path in a.flows for ln in read_lines(path) if ln.strip()]
    flows = [f for f in raw if f and f["src"] == a.tv_ip and in_win(f["end"])]
    queries = load_querylog(a.querylog, a.tv_ip)
    sni_idx = load_sni(a.sni, a.tv_ip)
    http_all = load_http(a.http)
    http = [r for r in http_all if in_win(r["t"])]
    dns_idx, http_idx = defaultdict(list), defaultdict(list)
    for q in queries:  # all queries/requests help name flows, even ones before --since
        for ip in q["ips"]:
            dns_idx[ip].append((q["t"], q["name"]))
    for v in dns_idx.values():
        v.sort()
    for r in http_all:
        http_idx[r["dst"]].append((r["t"], r["name"]))
    q_win = [q for q in queries if in_win(q["t"])]
    q_oldest = min((q["t"] for q in queries), default=None)

    # connections = closed flows (with bytes) + TLS handshakes with no flow record yet
    conns, used = [], set()
    for f in flows:
        name, cat, how = resolve(f, sni_idx, http_idx, dns_idx, a.gw_ip, used)
        conns.append(dict(f, name=name, cat=cat, how=how, open=0))
    sni_rows = [(k, t, n) for k, rows in sni_idx.items() for t, n in rows if in_win(t)]
    conns += [
        {"start": t, "end": t, "name": n, "cat": categorize(n), "how": "sni", "open": 1, "up": 0, "down": 0}
        for k, t, n in sni_rows
        if (*k, t) not in used
    ]

    qstats = defaultdict(lambda: [0, 0])  # name -> [queries, blocked]
    for q in q_win:
        qstats[q["name"]][0] += 1
        qstats[q["name"]][1] += q["blocked"]

    hosts, ssdp, zero = {}, 0, dict(conns=0, open=0, up=0, down=0, http=0)
    for c in conns:
        agg(
            hosts,
            c["name"],
            c["start"],
            c["end"],
            dict(zero, name=c["name"], category=c["cat"]),
            conns=1,
            open=c["open"],
            up=c["up"],
            down=c["down"],
        )
    for r in http:
        if is_local(r["dst"]):
            ssdp += 1  # SSDP M-SEARCH etc. on the LAN, not internet
        else:
            base = dict(zero, name=r["name"], category=categorize(r["name"]))
            agg(hosts, r["name"], r["t"], r["t"], base, http=1)
    for h in hosts.values():
        n, b = qstats.get(h["name"], (0, 0))
        h["blocked"] = "yes" if n and b == n else "partly" if b else ""

    cats = {c: dict(zero, category=c, hosts=0, queries=0, blocked=0) for c in CAT_ORDER}
    for h in hosts.values():
        cats[h["category"]]["hosts"] += 1
        for k in zero:
            cats[h["category"]][k] += h[k]
    for name, (n, b) in qstats.items():
        cats[categorize(name)]["queries"] += n
        cats[categorize(name)]["blocked"] += b

    unres = {}
    for c in conns:
        if c["cat"] == UNRES:
            base = dict(
                dst=c["dst"], dport=c["dport"], proto=c["proto"], conns=0, up=0, down=0, noreply=0, pre_dns=0
            )
            agg(
                unres,
                (c["dst"], c["dport"], c["proto"]),
                c["start"],
                c["end"],
                base,
                conns=1,
                up=c["up"],
                down=c["down"],
                noreply=c["down_pkts"] == 0,
                pre_dns=q_oldest is None or c["start"] < q_oldest,
            )

    dns_gw = [c for c in conns if c["cat"] == DNS and c["dst"] == a.gw_ip]
    gw_sizes = {(c["up_pkts"], c["up"]) for c in dns_gw}
    bypass = {}
    for c in conns:
        if c["cat"] == DNS and c["dst"] != a.gw_ip:
            base = dict(
                resolver=c["dst"],
                dport=c["dport"],
                proto=c["proto"],
                flows=0,
                up_pkts=0,
                up=0,
                redirected=0,
                rejected=0,
                leaked=0,
                twins=0,
            )
            # twin = same packets+bytes as a tvgw flow: the TV asked both resolvers in parallel
            b = agg(
                bypass,
                (c["dst"], c["dport"], c["proto"]),
                c["start"],
                c["end"],
                base,
                flows=1,
                up_pkts=c["up_pkts"],
                up=c["up"],
                twins=(c["up_pkts"], c["up"]) in gw_sizes,
            )
            # DNAT'd to AdGuard: the reply comes from tvgw. No reply at all: rejected (e.g. DoT)
            redirected = c["reply_src"] == a.gw_ip
            b["rejected" if not c["down_pkts"] else "redirected" if redirected else "leaked"] += 1

    groups = {}
    for r in http:
        if not is_local(r["dst"]):
            uri = r["uri"] if len(r["uri"]) <= URI_W else r["uri"][: URI_W - 1] + "~"
            base = dict(
                host=r["name"],
                category=categorize(r["name"]),
                method=r["method"],
                uri=uri,
                ua=r["ua"],
                count=0,
                body=0,
                uris=set(),
            )
            agg(
                groups, (r["name"], r["method"], uri, r["ua"]), r["t"], r["t"], base, count=1, body=r["clen"]
            )["uris"].add(r["uri"])
    for g in groups.values():
        g["distinct"] = len(g.pop("uris"))

    def rng(ts):
        return [min(ts), max(ts)] if ts else None

    rank = {c: i for i, c in enumerate(CAT_ORDER)}
    times = (
        [c["start"] for c in conns]
        + [c["end"] for c in conns]
        + [q["t"] for q in q_win]
        + [r["t"] for r in http]
    )
    return {
        "tv_ip": a.tv_ip,
        "gateway": a.gw_ip,
        "since": a.since,
        "until": a.until,
        "generated": time.time(),
        "window": rng(times),
        "querylog_oldest": q_oldest,
        "inputs": {
            "flows": [len(flows), rng([f["end"] for f in flows])],
            "dns": [len(q_win), rng([q["t"] for q in q_win])],
            "tls": [len(sni_rows), rng([t for _, t, _ in sni_rows])],
            "http": [len(http), rng([r["t"] for r in http])],
            "bad_flow_lines": raw.count(None),
            "other_src_flows": sum(1 for f in raw if f and f["src"] != a.tv_ip and in_win(f["end"])),
        },
        "totals": {
            "conns": len(conns),
            "flows": len(flows),
            "open": len(conns) - len(flows),
            "up": sum(f["up"] for f in flows),
            "down": sum(f["down"] for f in flows),
            "noreply": sum(1 for f in flows if f["down_pkts"] == 0),
            "named_by": dict(Counter(c["how"] for c in conns).most_common()),
        },
        "categories": [c for c in cats.values() if c["conns"] or c["queries"] or c["http"]],
        "hosts": sorted(hosts.values(), key=lambda h: (-h["up"], -h["conns"], -h["http"], h["name"])),
        "unresolved": sorted(unres.values(), key=lambda u: (-u["up"], -u["conns"])),
        "dns_bypass": {
            "to_gateway": len(dns_gw),
            "attempts": sorted(bypass.values(), key=lambda b: -b["flows"]),
        },
        "http": {
            "requests": len(http),
            "lan_multicast": ssdp,
            "groups": sorted(
                groups.values(), key=lambda g: (rank[g["category"]], g["host"], -g["count"], g["first"])
            ),
        },
        "dns_names": sorted(
            (
                {
                    "name": n,
                    "category": categorize(n),
                    "queries": q,
                    "blocked": b,
                    "conns": hosts.get(n, {}).get("conns", 0),
                }
                for n, (q, b) in qstats.items()
            ),
            key=lambda n: (rank[n["category"]], -n["queries"], n["name"]),
        ),
    }


# ---- Text output --------------------------------------------------------------------
def hb(n):
    """Human-readable bytes: 512B, 2.6K, 14.1M."""
    for unit in "BKMGT":
        if n < 1024 or unit == "T":
            return f"{n:.0f}{unit}" if unit == "B" else f"{n:.1f}{unit}"
        n /= 1024


def table(headers, rows, right=()):
    cells = [[str(c) for c in r] for r in [headers, *rows]]
    w = [max(len(r[i]) for r in cells) for i in range(len(headers))]

    def fmt(r):
        return (
            "  " + "  ".join(c.rjust(w[i]) if i in right else c.ljust(w[i]) for i, c in enumerate(r)).rstrip()
        )

    return "\n".join([fmt(cells[0]), fmt(["-" * x for x in w])] + [fmt(r) for r in cells[1:]])


def render_text(r, top):
    win, tot, inp = r["window"], r["totals"], r["inputs"]
    short = not win or win[1] - win[0] < 20 * 3600
    tf = "%H:%M:%S" if short else "%m-%d %H:%M"

    def ts(t, f=None):
        return datetime.fromtimestamp(t).strftime(f or tf) if t else "-"

    def span(k):
        n, rg = inp[k]
        f = "%H:%M" if short else tf
        return f"{k} {n} ({ts(rg[0], f)}-{ts(rg[1], f)})" if rg else f"{k} 0"

    out = [f"=== LG TV traffic report: {r['tv_ip']} ==="]
    p = out.append
    if win:
        s = int(win[1] - win[0])
        dur = f"{s // 60}m{s % 60:02d}s" if s < 3600 else f"{s // 3600}h{s // 60 % 60:02d}m"
        p(f"Window   {ts(win[0], '%Y-%m-%d %H:%M:%S')} -> {ts(win[1])} {time.strftime('%Z')} ({dur})")
    p("Inputs   " + " | ".join(span(k) for k in ("flows", "dns", "tls", "http")))
    p(
        f"Totals   {tot['conns']} connections ({tot['flows']} closed flows with bytes, {tot['open']} open),"
        f" UP {hb(tot['up'])}, down {hb(tot['down'])}"
    )
    p("Named by " + ", ".join(f"{k} {v}" for k, v in tot["named_by"].items()))
    notes = [
        f"{inp['other_src_flows']} flows not from the TV ignored" if inp["other_src_flows"] else "",
        f"{inp['bad_flow_lines']} unparsable flow lines" if inp["bad_flow_lines"] else "",
        f"{tot['noreply']} flows got no reply (rejected/blocked?)" if tot["noreply"] else "",
    ]
    if any(notes):
        p("Notes    " + "; ".join(n for n in notes if n))
    p(
        "  (open = TLS handshake seen but no conntrack DESTROY yet: still open, or outside"
        " flows.log; bytes unknown)"
    )

    p("\n1) By category")
    p(
        table(
            ["category", "conns", "open", "up", "down", "hosts", "http", "dns q", "blocked"],
            [
                [
                    c["category"],
                    c["conns"],
                    c["open"] or "",
                    hb(c["up"]),
                    hb(c["down"]),
                    c["hosts"],
                    c["http"] or "",
                    c["queries"],
                    c["blocked"] or "-",
                ]
                for c in r["categories"]
            ],
            right=range(1, 9),
        )
    )

    p(f"\n2) Top hosts by UPLOAD ({min(top, len(r['hosts']))} of {len(r['hosts'])})")
    p(
        table(
            ["host", "category", "conns", "open", "up", "down", "http", "first", "last", "blocked"],
            [
                [
                    h["name"] if len(h["name"]) <= 40 else "~" + h["name"][-39:],
                    h["category"],
                    h["conns"],
                    h["open"] or "",
                    hb(h["up"]),
                    hb(h["down"]),
                    h["http"] or "",
                    ts(h["first"]),
                    ts(h["last"]),
                    h["blocked"],
                ]
                for h in r["hosts"][:top]
            ],
            right=range(2, 7),
        )
    )

    p("\n3) Unresolved / hardcoded-IP flows (no SNI, HTTP Host or DNS answer: DNS blocking can't stop these)")
    if r["unresolved"]:
        p(
            table(
                ["dst ip", "port", "conns", "up", "down", "noreply", "first", "last"],
                [
                    [
                        u["dst"],
                        f"{u['proto']}/{u['dport']}",
                        u["conns"],
                        hb(u["up"]),
                        hb(u["down"]),
                        u["noreply"] or "",
                        ts(u["first"]),
                        ts(u["last"]),
                    ]
                    for u in r["unresolved"]
                ],
                right=range(2, 6),
            )
        )
        if pre := sum(u["pre_dns"] for u in r["unresolved"]):
            p(f"  ({pre} of these started before the querylog's oldest entry; may just be cached DNS)")
    else:
        p("  none: every internet flow mapped to a name")

    p("\n4) DNS bypass attempts (TV DNS to anything but tvgw)")
    if att := r["dns_bypass"]["attempts"]:
        p(
            table(
                [
                    "resolver",
                    "port",
                    "flows",
                    "pkts up",
                    "up",
                    "redirected",
                    "rejected",
                    "LEAKED",
                    "twins",
                    "first",
                    "last",
                ],
                [
                    [
                        b["resolver"],
                        f"{b['proto']}/{b['dport']}",
                        b["flows"],
                        b["up_pkts"],
                        hb(b["up"]),
                        b["redirected"],
                        b["rejected"] or "-",
                        b["leaked"] or "-",
                        b["twins"],
                        ts(b["first"]),
                        ts(b["last"]),
                    ]
                    for b in att
                ],
                right=range(2, 9),
            )
        )
        p(
            "  redirected = DNAT'd to AdGuard (still filtered); LEAKED = answered by the real resolver.\n"
            "  twins = same packets/bytes as a normal tvgw flow: the TV asks both resolvers in parallel.\n"
            f"  For comparison, {r['dns_bypass']['to_gateway']} DNS flows went to tvgw ({r['gateway']})."
        )
    else:
        p("  none")

    h = r["http"]
    p(
        f"\n5) Plain-HTTP requests (unencrypted): {h['requests'] - h['lan_multicast']} to the internet"
        + (f", plus {h['lan_multicast']} SSDP/LAN multicast" if h["lan_multicast"] else "")
    )
    last = None
    for g in h["groups"]:
        if g["host"] != last:
            p(f"  {g['host']}  [{g['category']}]")
            last = g["host"]
        p(
            f"    {g['count']:>3}x {g['method']} {g['uri']}"
            + (f"  ({g['distinct']} distinct)" if g["distinct"] > 1 else "")
            + (f"  body {hb(g['body'])}" if g["body"] else "")
        )
        if g["ua"]:
            p(f"         UA: {g['ua'][:100]}")

    p("\n6) DNS queries by category (AdGuard; conns 0 = queried but never connected, e.g. blocked)")
    by_cat = defaultdict(list)
    for n in r["dns_names"]:
        by_cat[n["category"]].append(n)
    p(f"  {'queries':>9} {'blocked':>8} {'conns':>6}  name")
    for cat, ns in by_cat.items():
        q, b = sum(n["queries"] for n in ns), sum(n["blocked"] for n in ns)
        p(f"  {cat}: {q} queries, {b} blocked, {len(ns)} names")
        for n in ns[:top]:
            p(f"  {n['queries']:>9} {n['blocked'] or '-':>8} {n['conns']:>6}  {n['name']}")
        if len(ns) > top:
            p(f"  {'':>9} ... +{len(ns) - top} more names")
    return "\n".join(out)


# ---- Self test ------------------------------------------------------------------------
def selftest():
    tcp = (
        "[1792976548.503576]\t[DESTROY] ipv4     2 tcp      6 CLOSE src=10.10.10.17 dst=44.229.174.42 "
        "sport=37378 dport=443 packets=18 bytes=2667 src=44.229.174.42 dst=192.168.4.48 sport=443 "
        "dport=37378 packets=20 bytes=16361 [ASSURED] delta-time=10"
    )
    udp = (
        "[1792976293.241125]\t[DESTROY] ipv4     2 udp      17 src=10.10.10.17 dst=8.8.8.8 sport=39331 "
        "dport=53 packets=18 bytes=1236 src=10.10.10.1 dst=10.10.10.17 sport=53 dport=39331 packets=18 "
        "bytes=4154 delta-time=30"
    )
    icmp = (
        "[1792975986.042255]\t[DESTROY] ipv4     2 icmp     1 src=10.10.10.1 dst=10.10.10.17 type=8 "
        "code=0 id=31842 packets=1 bytes=48 [UNREPLIED] src=10.10.10.17 dst=10.10.10.1 type=0 code=0 "
        "id=31842 packets=0 bytes=0"
    )
    t, u, i = parse_flow(tcp), parse_flow(udp), parse_flow(icmp)
    assert (t["proto"], t["state"], t["sport"], t["dport"]) == ("tcp", "CLOSE", 37378, 443)
    assert (t["up"], t["down"], t["start"], t["flags"]) == (2667, 16361, t["end"] - 10, ["ASSURED"])
    assert (u["proto"], u["state"], u["dst"], u["reply_src"]) == ("udp", "", "8.8.8.8", "10.10.10.1")
    assert (u["up"], u["down"], u["up_pkts"]) == (1236, 4154, 18)
    assert i["sport"] == 0 and i["dur"] is None and i["down_pkts"] == 0 and "UNREPLIED" in i["flags"]
    assert parse_flow("garbage") is None and parse_flow("[1.0] [NEW] ipv4 2 tcp 6 src=1") is None
    gw, nf = "10.10.10.1", "lg-tv-2020.prod.partner.netflix.net"
    assert resolve(t, {(37378, "44.229.174.42", 443): [(1792976536.5, nf)]}, {}, {}, gw, set())[:2] == (
        nf,
        "Streaming",
    )
    assert resolve(u, {}, {}, {}, gw, set()) == ("DNS -> 8.8.8.8", DNS, "dns-flow")
    dns = {"44.229.174.42": [(1792976530.0, "x.example.com")]}
    assert resolve(t, {}, {}, dns, gw, set()) == ("x.example.com", OTHER, "dns")
    assert resolve(t, {}, {}, {}, gw, set())[1] == UNRES
    for host, cat in [
        ("US.ibsstat.lgappstv.com", "LG ads"),
        ("lgappstv.com", "LG core"),
        ("aic.cdpbeacon2.lgtvcommon.com", "LG telemetry"),
        ("aic-ngfts.lge.com", "LG core"),
        ("ocsp.digicert.com", "Infra"),
        ("api-global.netflix.com", "Streaming"),
        ("tvx.alphonso.tv", "ACR"),
        ("college.com", OTHER),
        ("ads.smartclip.net", "3rd-party ads"),
    ]:
        assert categorize(host) == cat, (host, categorize(host))
    assert split_n("GET,GET", 2) == ["GET", "GET"]
    assert split_n("Moz (a, b),Moz (a, b)", 2) == ["Moz (a, b)"] * 2
    assert abs(parse_time("2026-10-25T20:02:49.123456789-05:00") - 1792976569.123456) < 1e-5
    assert hb(512) == "512B" and hb(2667) == "2.6K"
    print("selftest OK")


def main(argv=None):
    signal.signal(signal.SIGPIPE, signal.SIG_DFL)  # quiet when piped into head/less
    ap = argparse.ArgumentParser(
        prog="tvgw report",
        description="TV traffic report from tvgw logs.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="Examples:" + __doc__.split("Examples:")[1],
    )
    ap.add_argument("--profile", default="lg-webos", help="TV profile for categories (default lg-webos)")
    ap.add_argument(
        "--flows",
        action="append",
        metavar="FILE",
        help=f"conntrack log; repeatable, .gz ok (default {DEFAULTS['flows']})",
    )
    ap.add_argument(
        "--querylog", metavar="FILE", help=f"AdGuard querylog JSON (default {DEFAULTS['querylog']})"
    )
    ap.add_argument("--sni", metavar="FILE", help=f"TLS SNI tsv (default {DEFAULTS['sni']})")
    ap.add_argument("--http", metavar="FILE", help=f"plain-HTTP tsv (default {DEFAULTS['http']})")
    ap.add_argument("--dir", help="read flows.log, querylog.json, sni.tsv, http.tsv from DIR instead")
    ap.add_argument("--since", type=parse_since, help="only traffic since 2h / 30m / 1d / an ISO time")
    ap.add_argument("--until", type=parse_since, help="only traffic before this time (same forms as --since)")
    ap.add_argument("--top", type=int, default=25, help="rows in host and DNS lists (default 25)")
    ap.add_argument("--tv-ip", default="10.10.10.17")
    ap.add_argument("--gw-ip", default="10.10.10.1", help="tvgw address on the TV LAN (AdGuard)")
    ap.add_argument("--json", action="store_true", help="machine-readable output")
    ap.add_argument("--selftest", action="store_true", help="run parser self-test and exit")
    a = ap.parse_args(argv)
    if a.profile != PROFILE.name:
        set_profile(_profile.load(a.profile))
    if a.selftest:
        selftest()
        return 0
    for k, path in DEFAULTS.items():
        if getattr(a, k) is None:
            path = os.path.join(a.dir, os.path.basename(path)) if a.dir else path
            setattr(a, k, [path] if k == "flows" else path)
    r = build_report(a)
    print(json.dumps(r, indent=1) if a.json else render_text(r, a.top))
    return 0


if __name__ == "__main__":
    sys.exit(main())
