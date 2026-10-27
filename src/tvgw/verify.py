"""`tvgw verify`: does the gateway still hold?

Read-only checks of the firewall, routing, resolver and services, one line each; `--record` also
stores the verdict and a snapshot of every firewall counter in the store, so the daily brief can
say how many packets each rule actually stopped. A rule that matched nothing looks exactly like a
rule that works, and a quiet log is not evidence; counters are. Every command is a parameter, so
the logic is testable away from the gateway.
"""

from __future__ import annotations

import json
import os
import sqlite3
import subprocess
import time
from collections.abc import Callable
from dataclasses import dataclass, field

from tvgw import db, dnsq
from tvgw.config import Settings
from tvgw.profile import Profile

Runner = Callable[[list[str]], str]
Resolver = Callable[[str], list[str] | None]
APPLIED = "/run/tvgw/ruleset.applied"
SERVICES = ("AdGuardHome", "dnsmasq", "nginx", "tvgw-pcap", "tvgw-flowlog")
MIN_DOH_ELEMENTS = 50


def run_cmd(cmd: list[str]) -> str:
    """stdout of a command, '' when it fails or is missing (every check treats '' as 'not there')."""
    try:
        return subprocess.run(cmd, capture_output=True, text=True, errors="replace", timeout=30).stdout
    except (OSError, subprocess.TimeoutExpired):
        return ""


def read_file(path: str) -> str:
    try:
        with open(path) as fh:
            return fh.read()
    except OSError:
        return ""


@dataclass
class Check:
    name: str
    ok: bool
    detail: str = ""

    def line(self) -> str:
        return f"{'OK  ' if self.ok else 'FAIL'} {self.name}" + (f": {self.detail}" if self.detail else "")


@dataclass
class Result:
    checks: list[Check] = field(default_factory=list)
    counters: list[tuple[str, int, int]] = field(default_factory=list)  # (rule comment, packets, bytes)
    t: float = 0.0

    @property
    def ok(self) -> bool:
        return all(c.ok for c in self.checks)

    @property
    def failures(self) -> list[str]:
        return [c.line() for c in self.checks if not c.ok]


def _json(text: str):
    try:
        return json.loads(text) if text.strip() else None
    except ValueError:
        return None


def counters_from_table(text: str) -> list[tuple[str, int, int]]:
    """(comment, packets, bytes) for every commented rule with a counter in an `nft -j list table`
    listing, in first-seen order. A comment is one series: rules sharing it are summed (the UDP and
    TCP DNS redirects in tvgw-apply share "TV DNS aimed elsewhere -> AdGuard")."""
    data = _json(text)
    series: dict[str, list[int]] = {}
    for obj in (data or {}).get("nftables", []):
        rule = obj.get("rule")
        if not rule or not rule.get("comment"):
            continue
        for expr in rule.get("expr", []):
            c = expr.get("counter") if isinstance(expr, dict) else None
            if isinstance(c, dict):
                acc = series.setdefault(rule["comment"], [0, 0])
                acc[0] += int(c.get("packets", 0))
                acc[1] += int(c.get("bytes", 0))
                break
    return [(comment, packets, nbytes) for comment, (packets, nbytes) in series.items()]


def check(
    s: Settings,
    profile: Profile,
    run: Runner = run_cmd,
    read: Callable[[str], str] = read_file,
    resolve: Resolver | None = None,
) -> Result:
    resolve = resolve or (lambda name: dnsq.a_records(name, s.gw_ip))
    r = Result(t=time.time())
    tv_if = s.tv_if
    out_if = s.wan_if if s.uplink == "direct" else "tun0"

    # 1. the ruleset is loaded and still what tvgw-apply wrote (stateless listing: counters excluded)
    ruleset = run(["nft", "-s", "list", "table", "inet", "tvgw"])
    if not ruleset.strip():
        r.checks.append(Check("ruleset", False, "table inet tvgw is not loaded"))
    else:
        needles = {
            f"dnat ip to {s.gw_ip}:53": "TV DNS forced to AdGuard",
            "dport { 784, 853, 8853 }": "DoT/DoQ rejected",
            "@doh4": "DoH resolver set",
            "@lan4": "home LAN isolated",
            "masquerade": "NAT",
            "ct state invalid": "invalid dropped",
        }
        if s.block_quic == "yes":
            needles["udp dport 443"] = "QUIC rejected"
        missing = [why for needle, why in needles.items() if needle not in ruleset]
        r.checks.append(Check("ruleset", not missing, "missing: " + ", ".join(missing) if missing else ""))
        applied = read(APPLIED)
        if applied:
            same = applied.strip() == ruleset.strip()
            r.checks.append(Check("ruleset_unchanged", same, "" if same else "differs from the last apply"))

    # 2. kernel switches
    fwd = read("/proc/sys/net/ipv4/ip_forward").strip()
    offs = [d for d in (tv_if, out_if) if read(f"/proc/sys/net/ipv4/conf/{d}/forwarding").strip() != "1"]
    detail = (f"ip_forward={fwd or '?'} " if fwd != "1" else "") + (
        f"{','.join(offs)} not forwarding" if offs else ""
    )
    r.checks.append(
        Check("forwarding", fwd == "1" and not offs, detail.strip() + (" (TV offline)" if detail else ""))
    )
    v6 = read(f"/proc/sys/net/ipv6/conf/{tv_if}/disable_ipv6").strip()
    r.checks.append(Check("ipv6_off", v6 == "1", "" if v6 == "1" else f"disable_ipv6={v6 or '?'} on {tv_if}"))

    # 3. the TV's packets leave by the chosen uplink, through our policy table
    route = _json(run(["ip", "-j", "route", "get", "1.1.1.1", "from", s.tv_ip, "iif", tv_if])) or []
    dev = route[0].get("dev") if route and isinstance(route[0], dict) else None
    r.checks.append(Check("tv_route", dev == out_if, f"via {dev or 'nothing'}, expected {out_if}"))
    if s.uplink == "direct":
        rules = _json(run(["ip", "-j", "rule"])) or []
        has60 = any(
            isinstance(x, dict) and x.get("priority") == 60 and str(x.get("table")) == "100" for x in rules
        )
        r.checks.append(
            Check("policy_rule", has60, "" if has60 else "ip rule priority 60 -> table 100 missing")
        )

    # 4. PIA's own DNS redirect for forwarded packets must never see a TV packet
    everything = _json(run(["nft", "-j", "list", "ruleset"])) or {}
    hits, seen = 0, False
    for obj in everything.get("nftables", []):
        rule = obj.get("rule")
        if rule and "fwdsplitdns" in str(rule.get("chain", "")).lower():
            seen = True
            for expr in rule.get("expr", []):
                c = expr.get("counter") if isinstance(expr, dict) else None
                if isinstance(c, dict):
                    hits += int(c.get("packets", 0))
    r.checks.append(
        Check(
            "vpn_dnat_idle",
            hits == 0,
            f"{hits} TV DNS packets reached the VPN's DNAT"
            if hits
            else ("" if seen else "no VPN DNAT chain present"),
        )
    )

    # 5. the DoH block set is populated
    doh = _json(run(["nft", "-j", "list", "set", "inet", "tvgw", "doh4"])) or {}
    n = 0
    for obj in doh.get("nftables", []):
        if "set" in obj:
            n = len(obj["set"].get("elem", []) or [])
    r.checks.append(Check("doh4_loaded", n >= MIN_DOH_ELEMENTS, f"{n} elements"))

    # 6. the resolver answers, rewrites the URL-filter names to us, and allows what must be allowed
    bad = []
    for host in profile.url_filter.hosts if profile.url_filter else ():
        got = resolve(host)
        if got != [s.gw_ip]:
            bad.append(f"{host}->{got}")
    r.checks.append(Check("resolver_rewrite", not bad, ", ".join(bad)))
    bad = []
    for host in profile.must_allow:
        got = resolve(host)
        if got is None or got == ["0.0.0.0"]:
            bad.append(f"{host}->{'no answer' if got is None else 'blocked'}")
    r.checks.append(Check("resolver_must_allow", not bad, ", ".join(bad)))

    # 7. services
    states = run(["systemctl", "is-active", *SERVICES]).split()
    down = [u for u, st in zip(SERVICES, states, strict=False) if st != "active"]
    if len(states) < len(SERVICES):
        down += list(SERVICES[len(states) :])
    r.checks.append(Check("services", not down, "down: " + ", ".join(down) if down else ""))

    # 8. counters, for the record
    r.counters = counters_from_table(run(["nft", "-j", "list", "table", "inet", "tvgw"]))
    return r


def record(conn: sqlite3.Connection, r: Result) -> None:
    conn.execute(
        "INSERT OR REPLACE INTO verify(t, ok, failures) VALUES (?,?,?)",
        (r.t, int(r.ok), json.dumps(r.failures)),
    )
    conn.executemany(
        "INSERT INTO fw_counters(t, rule, packets, bytes) VALUES (?,?,?,?)",
        [(r.t, rule, p, b) for rule, p, b in r.counters],
    )
    conn.commit()


def main(s: Settings, profile: Profile, record_to_store: bool = False, as_json: bool = False) -> int:
    r = check(s, profile)
    if record_to_store and os.path.exists(os.path.dirname(s.db_path) or "."):
        conn = db.connect(s.db_path)
        try:
            record(conn, r)
        finally:
            conn.close()
    if as_json:
        print(
            json.dumps(
                {"ok": r.ok, "checks": [c.__dict__ for c in r.checks], "counters": r.counters}, indent=1
            )
        )
    else:
        for c in r.checks:
            print(c.line())
    return 0 if r.ok else 1
