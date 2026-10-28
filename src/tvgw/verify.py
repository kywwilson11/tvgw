"""`tvgw verify`: does the gateway still hold?

Read-only checks of the firewall, routing, resolver and services, one line each; `--record` also
stores the verdict and a snapshot of every firewall counter in the store, so the daily brief can
say how many packets each rule actually stopped. A rule that matched nothing looks exactly like a
rule that works, and a quiet log is not evidence; counters are. Every command is a parameter, so
the logic is testable away from the gateway.
"""

from __future__ import annotations

import ipaddress
import json
import os
import re
import sqlite3
import subprocess
import sys
import time
from collections.abc import Callable
from dataclasses import dataclass, field

from tvgw import config, db, dnsq
from tvgw.config import Settings
from tvgw.profile import Profile

Runner = Callable[[list[str]], str]
Resolver = Callable[[str], list[str] | None]
APPLIED = "/run/tvgw/ruleset.applied"
# tvgw-apply's counter listings either side of its last reload, published together once it succeeded
RELOADS = ("/run/tvgw/counters.before-apply", "/run/tvgw/counters.after-apply")
SETTINGS_APPLIED = "/run/tvgw/settings.applied"  # the conf keys the last apply used, as it used them
CONF = "/etc/tvgw/tvgw.conf"
# the conf keys tvgw-apply reads; the rest of the conf (the TV's identity, retention, the analyst)
# takes effect without an apply
APPLY_KEYS = ("UPLINK", "WAN_IF", "WAN_GW", "BLOCK_QUIC", "STRICT_PORTS", "DNSGATE")
# the rules whose absence is an outage, as the stateless listing prints them (GW_IP stands for the
# gateway address); tests/unit/test_deploy_lint.py checks each against tvgw-apply's text, so a
# reworded rule fails there before it fails here on the gateway
KEY_RULES = {
    "dnat ip to GW_IP:53": "TV DNS forced to AdGuard",
    "dport { 784, 853, 8853 }": "DoT/DoQ rejected",
    "@doh4": "DoH resolver set",
    "@lan4": "home LAN isolated",
    "masquerade": "NAT",
    "ct state invalid": "invalid dropped",
}
QUIC_RULE = {"udp dport 443": "QUIC rejected"}  # present only with BLOCK_QUIC=yes
IPV6_GUARD = "no IPv6 from the TV"  # the comment of netdev tvgw_l2's drop of every IPv6 frame on eth0
# tvgw.service is oneshot with RemainAfterExit, so `is-active` says active; install.sh enables the timers
SERVICES = (
    "AdGuardHome",
    "dnsmasq",
    "nginx",
    "tvgw",
    "tvgw-pcap",
    "tvgw-flowlog",
    "tvgw-analyze.timer",
    "tvgw-prune.timer",
    "tvgw-doh-update.timer",
    "tvgw-verify.timer",
    "tvgw-backup.timer",
    "tvgw-analyst.timer",
    "tvgw-analyst-weekly.timer",
    "tvgw-autoblock.timer",
)
MIN_DOH_ADDRESSES = 50  # the same floor tvgw-doh-update refuses below
APPLY_GRACE = (
    120  # seconds an input may be newer than the apply: the updater's write-then-apply, an edit in progress
)
DOH_MAX_AGE = 8 * 86400  # the daily updater has missed a week
ADGUARD_MIN = (0, 107, 73)  # the release that fixed an authentication bypass over h2c


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


def apply_settings(conf_text: str) -> dict[str, str]:
    """The values tvgw-apply would take from this conf: its keys, empty or missing ones defaulted as
    the script defaults them (`${KEY:=value}`, kept equal to Settings by the deploy lint)."""
    conf, defaults = config.parse_conf(conf_text), Settings()
    return {
        key: conf.get(key)
        or (str(getattr(defaults, config.CONF_KEYS[key])) if key in config.CONF_KEYS else "")
        for key in APPLY_KEYS
    }


def file_mtime(path: str) -> float | None:
    try:
        return os.stat(path).st_mtime
    except OSError:
        return None


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
    reloads: list[tuple[float, list[tuple[str, int, int]]]] = field(default_factory=list)  # (t, counters)
    versions: dict[str, str] = field(default_factory=dict)  # component -> version, for the store
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


def _addresses(elem) -> int:
    """How many addresses one element of an interval set covers: nft merges neighbours into prefixes
    and ranges, so counting elements would undercount what the set covers."""
    if not isinstance(elem, dict):
        return 1
    try:
        if "prefix" in elem:
            return 2 ** (32 - int(elem["prefix"]["len"]))
        if "range" in elem:
            lo, hi = (int(ipaddress.ip_address(x)) for x in elem["range"])
            return hi - lo + 1
    except (TypeError, KeyError, ValueError):
        pass
    return 1


def check(
    s: Settings,
    profile: Profile,
    run: Runner = run_cmd,
    read: Callable[[str], str] = read_file,
    resolve: Resolver | None = None,
    mtime: Callable[[str], float | None] = file_mtime,
) -> Result:
    resolve = resolve or (lambda name: dnsq.a_records(name, s.gw_ip))
    r = Result(t=time.time())
    tv_if = s.tv_if
    out_if = s.wan_if if s.uplink == "direct" else "tun0"
    doh4 = os.path.join(s.state_dir, "doh4.txt")

    # 1. the ruleset is loaded, holds the key rules, and is still what tvgw-apply last wrote from
    #    inputs nobody has changed since (stateless listing: counters excluded)
    ruleset = run(["nft", "-s", "list", "table", "inet", "tvgw"])
    if not ruleset.strip():
        r.checks.append(Check("ruleset", False, "table inet tvgw is not loaded"))
    else:
        needles = {**KEY_RULES, **(QUIC_RULE if s.block_quic == "yes" else {})}
        missing = [why for needle, why in needles.items() if needle.replace("GW_IP", s.gw_ip) not in ruleset]
        r.checks.append(Check("ruleset", not missing, "missing: " + ", ".join(missing) if missing else ""))
        applied = read(APPLIED).strip()
        if not applied:  # the table is loaded, so an apply ran; its listing should be here
            detail = f"no baseline: {APPLIED} missing (run tvgw-apply)"
            r.checks.append(Check("ruleset_unchanged", False, detail))
        else:
            same = applied == ruleset.strip()
            r.checks.append(Check("ruleset_unchanged", same, "" if same else "differs from the last apply"))
            # an input edited after the last successful apply is invisible to ruleset_unchanged: the
            # live rules still equal the baseline, and neither is what the files now say (a list nft
            # rejected and left the old set loaded, a conf nobody re-applied)
            applied_at = mtime(APPLIED)
            used = read(SETTINGS_APPLIED)
            stale = [
                os.path.basename(path)
                for path in (CONF, s.block4, doh4)
                if applied_at is not None
                and (changed := mtime(path)) is not None
                and changed > applied_at
                and r.t - changed > APPLY_GRACE
                # a conf edit counts only when a key tvgw-apply reads now differs from what it used;
                # without that record (an apply from before it was kept) any edit counts
                and not (path == CONF and used.strip() and apply_settings(read(CONF)) == apply_settings(used))
            ]
            detail = "changed after the last apply: " + ", ".join(stale) if stale else ""
            r.checks.append(Check("applied_current", not stale, detail))

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
    # the wire-level IPv6 drop: tvgw-apply only warns when it does not load (it cannot while eth0 is
    # down), and nothing else notices it gone. disable_ipv6 still holds, so this is the second wall,
    # and the source of the brief's IPv6 line
    l2 = run(["nft", "-j", "list", "table", "netdev", "tvgw_l2"])
    guard = any(
        rule.get("comment") == IPV6_GUARD
        and any(isinstance(e, dict) and "drop" in e for e in rule.get("expr", []))
        for obj in (_json(l2) or {}).get("nftables", [])
        if isinstance(obj, dict) and isinstance(rule := obj.get("rule"), dict)
    )
    r.checks.append(
        Check("ipv6_guard", guard, "" if guard else f"netdev tvgw_l2 is not dropping IPv6 on {tv_if}")
    )

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
            n = sum(_addresses(e) for e in obj["set"].get("elem", []) or [])
    r.checks.append(Check("doh4_loaded", n >= MIN_DOH_ADDRESSES, f"{n} addresses"))
    # a list the daily updater stopped refreshing passes doh4_loaded for ever
    written = mtime(doh4)
    age = r.t - written if written is not None else None
    detail = f"{age / 86400:.1f} days old" if age is not None else "doh4.txt missing"
    r.checks.append(Check("doh4_fresh", age is not None and age < DOH_MAX_AGE, detail))

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
        # [] is NXDOMAIN, REFUSED, SERVFAIL or NODATA: AdGuard's nxdomain and refused blocking modes
        # answer that way, and so does an upstream outage
        if not got or got == ["0.0.0.0"]:
            bad.append(f"{host}->{'no answer' if got is None else 'blocked' if got else 'empty answer'}")
    r.checks.append(Check("resolver_must_allow", not bad, ", ".join(bad)))

    # 7. services (the DNS-gate feeder only while the gate is on)
    services = (*SERVICES, "tvgw-dnsgate") if s.dnsgate != "off" else SERVICES
    states = run(["systemctl", "is-active", *services]).split()
    down = [u for u, st in zip(services, states, strict=False) if st != "active"]
    if len(states) < len(services):
        down += list(services[len(states) :])
    r.checks.append(Check("services", not down, "down: " + ", ".join(down) if down else ""))

    # 7b. the resolver's version: AdGuard's security fixes of 2026 start at ADGUARD_MIN, and a
    #     resolver below it is one with a known hole on the TV segment
    exe = os.path.join(os.path.dirname(s.adguard_yaml), "AdGuardHome")
    m = re.search(r"\bv?(\d+)\.(\d+)\.(\d+)\b", run([exe, "--version"]))
    if not m:
        r.checks.append(Check("adguard_version", False, f"could not read it from {exe} --version"))
    else:
        ver = tuple(int(x) for x in m.groups())
        r.versions["adguard"] = "v" + ".".join(m.groups())
        floor = "v" + ".".join(map(str, ADGUARD_MIN))
        detail = r.versions["adguard"] if ver >= ADGUARD_MIN else f"{r.versions['adguard']} is below {floor}"
        r.checks.append(Check("adguard_version", ver >= ADGUARD_MIN, detail))

    # 7c. the DNS gate (count-only): its table carries the set and the counting rule. An empty set
    #     with the TV on would mean the feeder sees nothing, which verify cannot tell from a TV that
    #     is off, so the address count is the detail and the structure is the check
    if s.dnsgate != "off":
        gate = run(["nft", "list", "table", "inet", "tvgw_gate"])
        needles = (("set resolved4", "set"), ("TV to an address DNS never returned", "counting rule"))
        missing = [what for needle, what in needles if needle not in gate]
        n = set_size(run(["nft", "-j", "list", "set", "inet", "tvgw_gate", "resolved4"]))
        detail = "missing: " + ", ".join(missing) if missing else f"{n} addresses in the set"
        r.checks.append(Check("dnsgate", not missing, detail))

    # 8. counters, for the record: the inet table, the wire-level IPv6 drop and the DNS gate; and
    #    tvgw-apply's listings either side of its last reload, so record() can store the reset itself.
    #    The pair counts only whole: one file, or an after older than its before (caught between the
    #    two renames), would read as a reset that never happened
    for table in (("inet", "tvgw"), ("netdev", "tvgw_l2"), ("inet", "tvgw_gate")):
        listing = l2 if table == ("netdev", "tvgw_l2") else run(["nft", "-j", "list", "table", *table])
        r.counters += counters_from_table(listing)
    pair = [(mtime(path), read(path)) for path in RELOADS]
    (t0, before), (t1, after) = pair
    if t0 is not None and t1 is not None and t1 > t0 and before.strip() and after.strip():
        r.reloads = [
            (t, [c for line in text.splitlines() for c in counters_from_table(line)]) for t, text in pair
        ]
    return r


def set_size(listing: str) -> int:
    """Elements in an `nft -j list set` listing (timeout sets list each element as an object)."""
    doc = _json(listing) or {}
    for obj in doc.get("nftables", []) if isinstance(doc, dict) else []:
        if isinstance(obj, dict) and "set" in obj:
            return len(obj["set"].get("elem") or [])
    return 0


def record(conn: sqlite3.Connection, r: Result) -> None:
    # the reload pair first, so it sits between the last snapshot and this one in the order taken;
    # once only, and only when newer than every snapshot stored (an apply that ran while the last run
    # took its snapshot must not be stored after it)
    newest = conn.execute("SELECT MAX(t) FROM fw_counters").fetchone()[0]
    conn.executemany(
        "INSERT INTO fw_counters(t, rule, packets, bytes) VALUES (?,?,?,?)",
        [
            (t, rule, p, b)
            for t, counters in r.reloads
            if newest is None or t > newest
            for rule, p, b in counters
        ],
    )
    conn.execute(
        "INSERT OR REPLACE INTO verify(t, ok, failures) VALUES (?,?,?)",
        (r.t, int(r.ok), json.dumps(r.failures)),
    )
    conn.executemany(
        "INSERT INTO fw_counters(t, rule, packets, bytes) VALUES (?,?,?,?)",
        [(r.t, rule, p, b) for rule, p, b in r.counters],
    )
    conn.executemany(
        "INSERT OR REPLACE INTO meta(key, value) VALUES (?, ?)",
        [(f"{what}_version", ver) for what, ver in r.versions.items()],
    )
    conn.commit()


def main(s: Settings, profile: Profile, record_to_store: bool = False, as_json: bool = False) -> int:
    # the module attributes, looked up now rather than bound as check()'s defaults, so tests can patch them
    r = check(s, profile, run=run_cmd, read=read_file, mtime=file_mtime)
    # the verdict first: the 10-minute run's only output is the journal, and a store in trouble must
    # not take the checks down with it
    if as_json:
        print(
            json.dumps(
                {"ok": r.ok, "checks": [c.__dict__ for c in r.checks], "counters": r.counters}, indent=1
            )
        )
    else:
        for c in r.checks:
            print(c.line())
    ok = r.ok
    if record_to_store:
        try:
            conn = db.connect(s.db_path)
            try:
                record(conn, r)
            finally:
                conn.close()
        except (sqlite3.Error, OSError) as e:  # stderr keeps --json's stdout parseable
            print(f"tvgw verify: could not record the run: {e}", file=sys.stderr)
            ok = False
    return 0 if ok else 1
