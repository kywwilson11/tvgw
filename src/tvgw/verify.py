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

from tvgw import config, db, dnsq, flowlog, guard, ledger, lgwebos
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
APPLY_KEYS = (
    "UPLINK",
    "WAN_IF",
    "WAN_GW",
    "BLOCK_QUIC",
    "STRICT_PORTS",
    "DNSGATE",
    *("TV_IF", "TV_NET", "GW_IP"),  # (packaging) the TV side, which tvgw-apply now reads from the conf
    "CAPTURE_MODE",  # (capture)
    *("TV_IP", "TV_MAC"),  # (guard) the forward chain pins the TV's address once its MAC is known
    "VPN_IF",  # (events)
    "ADTECH_PORT_WALL",  # (acr)
)
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
# (capture) the unit that captures in each CAPTURE_MODE; SERVICES names the full one, and a gateway in
# headers mode expects the other in its place (docs/capture.md)
CAPTURE_UNITS = {"full": "tvgw-pcap", "headers": "tvgw-pcap-headers"}
# the comment of the rule tvgw-apply loads into inet tvgw_capture with CAPTURE_MODE=headers
CAPTURE_RULE = "capture: the first packets of each TV connection"
MIN_DOH_ADDRESSES = 50  # the same floor tvgw-doh-update refuses below
APPLY_GRACE = (
    120  # seconds an input may be newer than the apply: the updater's write-then-apply, an edit in progress
)
DOH_MAX_AGE = 8 * 86400  # the daily updater has missed a week
# (lists) 0.107.79: 0.107.78 removed h2c (the authentication bypass 0.107.73 fixed) and tightened DoH
# upstream validation, and 0.107.79 fixed a DoQ resource exhaustion (GHSA-w6v6-f44j-3rj2)
ADGUARD_MIN = (0, 107, 79)
ADGUARD_FLOOR_WHY = "the release with the 2026 DoH and DoQ fixes"
# (lists) the sentinel name each HaGeZi list carries, by a piece of the list's URL: a list AdGuard has
# loaded answers its sentinel with 0.0.0.0, so "is the list in force" is one lookup (docs/adguard.md)
SENTINELS = (
    ("filter_48.txt", "h4g3z1-pro.web.app"),  # HaGeZi Pro through AdGuard's registry
    ("/adblock/pro.txt", "h4g3z1-pro.web.app"),
    ("filter_72.txt", "h4g3z1-native-lgwebos.web.app"),  # HaGeZi LG webOS through the registry
    ("native.lgwebos.txt", "h4g3z1-native-lgwebos.web.app"),
    ("/adblock/doh.txt", "h4g3z1-doh.web.app"),  # HaGeZi DoH/VPN bypass, from jsDelivr
)
# (packaging) AdGuard Home is a checked dependency, never bundled: what to do when it is missing or old
ADGUARD_INSTALL = (
    "install it natively with its own script (curl -s -S -L "
    "https://raw.githubusercontent.com/AdguardTeam/AdGuardHome/master/scripts/install.sh | sh -s -- -v)"
)
# (events) the flow log and the gate (design decision 43); the VPN boundary (44)
EVENTS_KEY = "/proc/sys/net/netfilter/nf_conntrack_events"
CT_EVENTS_RULE = "ct event set destroy"  # tvgw-apply's ct_events chain, as the listing prints it
GATE_SIZE = 65536  # resolved4's size in tvgw-apply, when a listing does not say
GATE_FULL = 0.5  # the share of the set past which verify warns: a full set loses addresses
# PIA's command-line client; `timeout` bounds it, since a daemon that does not answer must not hold
# the 10-minute run. Absent tool or daemon: no output, and nothing is recorded
PIA_STATE = ["timeout", "5", "piactl", "get", "connectionstate"]
# the states `piactl get connectionstate` prints; any other first line (an error, a usage message, a
# banner) is not PIA's state and is not recorded, so it cannot reach the Coverage line or the red line
PIA_STATES = frozenset(
    {
        "Disconnected",
        "Connecting",
        "StillConnecting",
        "Connected",
        "Interrupted",
        "Reconnecting",
        "StillReconnecting",
        "DisconnectingToReconnect",
        "Disconnecting",
    }
)


def pia_state(out: str) -> str | None:
    """(events) PIA's connection state from piactl's output: its first line when that is one of
    PIA_STATES, else None."""
    lines = out.strip().splitlines()
    first = lines[0].strip() if lines else ""
    return first if first in PIA_STATES else None


# (lists) the service runs with --no-check-update, so the UI offers no update: a new binary goes in
# through tvgw's own path, which checks the live config with it first (docs/adguard.md)
ADGUARD_UPDATE = "download the new release and run: sudo tvgw adguard upgrade <its AdGuardHome binary>"


def run_cmd(cmd: list[str]) -> str:
    """stdout of a command, '' when it fails or is missing (every check treats '' as 'not there')."""
    try:
        return subprocess.run(
            cmd, capture_output=True, text=True, encoding="utf-8", errors="replace", timeout=30
        ).stdout
    except (OSError, subprocess.TimeoutExpired):
        return ""


def read_file(path: str) -> str:
    try:
        with open(path, encoding="utf-8", errors="replace") as fh:
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
    # (guard) a finding that is not an outage: printed as WARN, and the run still passes. A sandbox
    # that did not take, or a counter that moved where it should not, is worth reading, never a
    # reason for an install to stop with the TV in use
    warn: bool = False

    def line(self) -> str:
        head = "FAIL" if not self.ok else "WARN" if self.warn else "OK  "
        return f"{head} {self.name}" + (f": {self.detail}" if self.detail else "")


@dataclass
class Result:
    checks: list[Check] = field(default_factory=list)
    counters: list[tuple[str, int, int]] = field(default_factory=list)  # (rule comment, packets, bytes)
    reloads: list[tuple[float, list[tuple[str, int, int]]]] = field(default_factory=list)  # (t, counters)
    versions: dict[str, str] = field(default_factory=dict)  # component -> version, for the store
    # (events) the VPN boundary as this run saw it, for the brief: VPN_IF, the tunnel it resolved to
    # and PIA's own state (None without piactl)
    vpn: dict = field(default_factory=dict)
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


def reading_paths(text: str) -> tuple[str, dict[str, str]]:
    """The TV's network paths from the hourly reading file (`read <time>`, then `key = value` lines, as
    tvgw-analyze writes it): (the time, {key: value} for lgwebos.PATH_KEYS). No file: ('', {})."""
    lines = text.splitlines()
    if not lines or not lines[0].startswith("read "):
        return "", {}
    found = {}
    for ln in lines[1:]:
        k, eq, v = ln.partition(" = ")
        if eq and k in lgwebos.PATH_KEYS:
            found[k] = v.strip()
    return lines[0][5:].strip(), found


def check(
    s: Settings,
    profile: Profile,
    run: Runner = run_cmd,
    read: Callable[[str], str] = read_file,
    resolve: Resolver | None = None,
    mtime: Callable[[str], float | None] = file_mtime,
    sockets: Callable[[int], list[flowlog.NetlinkSocket]] = flowlog.event_sockets,
) -> Result:
    resolve = resolve or (lambda name: dnsq.a_records(name, s.gw_ip))
    r = Result(t=time.time())
    tv_if = s.tv_if

    def exists(dev: str) -> bool:  # an interface is there when its IPv4 switches are
        return read(f"/proc/sys/net/ipv4/conf/{dev}/forwarding") != ""

    out_if = config.uplink_interface(s, exists)  # (events) the tunnel VPN_IF names or finds
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

    # 7. services (the DNS-gate feeder only while the gate is on; the capture unit CAPTURE_MODE picks)
    services = tuple(CAPTURE_UNITS[s.capture_mode] if u == CAPTURE_UNITS["full"] else u for u in SERVICES)
    services = (*services, "tvgw-dnsgate") if s.dnsgate != "off" else services
    states = run(["systemctl", "is-active", *services]).split()
    down = [u for u, st in zip(services, states, strict=False) if st != "active"]
    if len(states) < len(services):
        down += list(services[len(states) :])
    r.checks.append(Check("services", not down, "down: " + ", ".join(down) if down else ""))

    # 6b. the TV's own account of its network paths, from the last hourly reading: Wi-Fi, Wi-Fi Direct
    #     or tethering in any state but off is traffic that leaves around the gateway (decision 40).
    #     No reading, or one from a TV that does not answer the question, is not a FAIL: verify says
    #     what it knows, and the brief's red line takes over once a reading exists
    stamp, paths = reading_paths(read(s.tvcheck_txt))
    second = [
        f"{label} {paths[key]}"
        for key, label in lgwebos.SECOND_PATHS.items()
        if lgwebos.is_second_path(key, paths.get(key))
    ]
    if second:
        detail = "second path: " + ", ".join(second) + f" (read {stamp})"
    elif paths:
        detail = (
            f"wired {paths.get('network.wired.state', '?')}, Wi-Fi {paths.get('network.wifi.state', '?')},"
            f" Wi-Fi Direct {paths.get('network.wifiDirect.state', '?')} (read {stamp})"
        )
    else:
        detail = f"the reading at {stamp} has no network paths" if stamp else "no TV reading yet"
    r.checks.append(Check("tv_paths", not second, detail))

    # 7b. the resolver's version: AdGuard's security fixes of 2026 start at ADGUARD_MIN, and a
    #     resolver below it is one with a known hole on the TV segment
    exe = os.path.join(os.path.dirname(s.adguard_yaml), "AdGuardHome")
    m = re.search(r"\bv?(\d+)\.(\d+)\.(\d+)\b", run([exe, "--version"]))
    if not m and mtime(exe) is None:  # (packaging) not there at all: say how to get it
        detail = f"AdGuard Home is not installed ({exe} missing); {ADGUARD_INSTALL}"
        r.checks.append(Check("adguard_version", False, detail))
    elif not m:
        r.checks.append(Check("adguard_version", False, f"could not read it from {exe} --version"))
    else:
        ver = tuple(int(x) for x in m.groups())
        r.versions["adguard"] = "v" + ".".join(m.groups())
        floor = "v" + ".".join(map(str, ADGUARD_MIN))
        detail = (
            r.versions["adguard"]
            if ver >= ADGUARD_MIN
            else f"{r.versions['adguard']} is below {floor}, {ADGUARD_FLOOR_WHY};"
            f" {ADGUARD_UPDATE.format(exe=exe)}"
        )
        r.checks.append(Check("adguard_version", ver >= ADGUARD_MIN, detail))

    # 7b2. (lists) the blocklists are in force: each subscribed HaGeZi list's sentinel answers 0.0.0.0.
    #      A list AdGuard emptied (an empty 200 replaces it) or never loaded answers it with an address
    r.checks.append(sentinel_check(profile, resolve))
    # 7b3. (lists) the binary changes only through `tvgw adguard upgrade`: the service runs with
    #      --no-check-update (tvgw adguard service, run by install.sh)
    r.checks.append(no_update_check(run, read))

    # 7c. the DNS gate (count-only): its table carries the set and the counting rule. An empty set
    #     with the TV on would mean the feeder sees nothing, which verify cannot tell from a TV that
    #     is off, so the address count is the detail and the structure is the check
    if s.dnsgate != "off":
        gate = run(["nft", "list", "table", "inet", "tvgw_gate"])
        needles = (("set resolved4", "set"), ("TV to an address DNS never returned", "counting rule"))
        missing = [what for needle, what in needles if needle not in gate]
        n, size = set_fill(run(["nft", "-j", "list", "set", "inet", "tvgw_gate", "resolved4"]))
        detail = "missing: " + ", ".join(missing) if missing else f"{n} addresses in the set"
        # (events) a set near its size loses addresses: deep dive 06 F2 reports a 2026 stable fix for
        # elements removed without a grace period when the set is full, unverified for the Pi's 6.18.y.
        # With the refresh a day's distinct answers stay in it, so more than half is a TV or a feeder
        # doing something new
        full = not missing and n > size * GATE_FULL
        if full:
            detail = f"{n} of {size} addresses in the set, over {GATE_FULL:.0%}: what is the TV resolving?"
        r.checks.append(Check("dnsgate", not missing, detail, warn=full))

    # 7d. the capture: exactly one of the two units, and in headers mode the rule that feeds it
    r.checks.append(capture_check(s, run))

    # 7e. (guard) the guard table, its quiet, the co-tenants' filters and dnsmasq's capabilities
    guard_json = run(["nft", "-j", "list", "table", "inet", "tvgw_guard"])
    r.checks.append(guard_present_check(run, read))
    r.checks.append(guard_quiet_check(bool(ruleset.strip()), guard_json, read(RELOADS[1])))
    r.checks.append(cotenants_check(s, run))
    r.checks.append(dnsmasq_caps_check(run, read))
    # 7f. (events) the flow log hears the TV: the switch and the rule that choose its events, and the
    #     logger's event socket with the count of events the kernel dropped on it (for the store)
    events_check, drops = flowlog_check(run, read, ruleset, sockets)
    r.checks.append(events_check)
    # 7g. (events) the VPN boundary, for the brief: the tunnel and PIA's own state; never a check
    r.vpn = {
        "vpn_if": s.vpn_if,
        "device": config.vpn_interface(s, exists),
        "pia": pia_state(run(PIA_STATE)),
    }

    # 8. counters, for the record: the inet table, the wire-level IPv6 drop and the DNS gate; and
    #    tvgw-apply's listings either side of its last reload, so record() can store the reset itself.
    #    The pair counts only whole: one file, or an after older than its before (caught between the
    #    two renames), would read as a reset that never happened
    tables = [("inet", "tvgw"), ("netdev", "tvgw_l2"), ("inet", "tvgw_gate")]
    if s.capture_mode == "headers":  # (capture) the table exists only then
        tables.append(("inet", "tvgw_capture"))
    tables.append(("inet", "tvgw_guard"))  # (guard)
    known = {("netdev", "tvgw_l2"): l2, ("inet", "tvgw_guard"): guard_json}
    for table in tables:
        listing = known[table] if table in known else run(["nft", "-j", "list", "table", *table])
        r.counters += counters_from_table(listing)
    if drops is not None:  # (events) a series of its own, read as the counters are (flowlog.DROPS_RULE)
        r.counters.append((flowlog.DROPS_RULE, drops, 0))
    pair = [(mtime(path), read(path)) for path in RELOADS]
    (t0, before), (t1, after) = pair
    if t0 is not None and t1 is not None and t1 > t0 and before.strip() and after.strip():
        r.reloads = [
            (t, [c for line in text.splitlines() for c in counters_from_table(line)]) for t, text in pair
        ]
    return r


def sentinels(profile: Profile) -> list[str]:
    """(lists) The sentinel names of the lists the profile subscribes, in its order, each once. A list
    with no known sentinel adds none."""
    out: list[str] = []
    for _name, url in profile.adguard_filters:
        for piece, sentinel in SENTINELS:
            if piece in url and sentinel not in out:
                out.append(sentinel)
                break
    return out


def sentinel_check(profile: Profile, resolve: Resolver) -> Check:
    """(lists) Every sentinel must come back blocked. A renamed sentinel upstream is a loud false alarm,
    never an outage; a list that went empty is otherwise invisible until a tracker gets through."""
    names = sentinels(profile)
    bad = []
    for name in names:
        got = resolve(name)
        if got != ["0.0.0.0"]:
            bad.append(f"{name}->{'no answer' if got is None else got or 'empty answer'}")
    if bad:
        return Check("list_sentinels", False, "list not in force: " + ", ".join(bad))
    detail = f"{len(names)} lists in force" if names else "no subscribed list has a known sentinel"
    return Check("list_sentinels", True, detail)


def no_update_check(run: Runner, read: Callable[[str], str] = read_file) -> Check:
    """(lists) AdGuard Home's effective ExecStart carries --no-check-update, and so does the process that
    runs: a drop-in reloaded but never restarted into leaves the old process able to update itself. A
    process verify cannot read (none running, /proc hidden) is judged by the ExecStart alone."""
    out = run(["systemctl", "show", "-P", "ExecStart", "AdGuardHome"])
    if not out.strip():
        return Check("adguard_pinned", False, "could not read AdGuardHome's ExecStart from systemd")
    if "--no-check-update" not in out:
        return Check("adguard_pinned", False, "AdGuard Home may update itself: run sudo tvgw adguard service")
    pid = run(["systemctl", "show", "-P", "MainPID", "AdGuardHome"]).strip()
    argv = read(f"/proc/{pid}/cmdline").split("\0") if pid.isdigit() and pid != "0" else []
    if any(argv) and "--no-check-update" not in argv:
        return Check(
            "adguard_pinned",
            False,
            f"the running AdGuard Home (pid {pid}) was started without --no-check-update:"
            " run sudo tvgw adguard service",
        )
    return Check("adguard_pinned", True, "")


def capture_check(s: Settings, run: Runner) -> Check:
    """The capture as CAPTURE_MODE says it should be. The expected unit's being up is the services
    check; this one fails when the other unit runs as well, which happens when the setting changed
    and only one unit was restarted: two captures write into the same directory and every hello is
    counted twice. In headers mode the unit records only what the firewall hands it, so the rule in
    inet tvgw_capture is checked too: without it the capture runs and writes empty hours."""
    mode = s.capture_mode
    other = CAPTURE_UNITS["headers" if mode == "full" else "full"]
    if run(["systemctl", "is-active", other]).strip() == "active":
        return Check(
            "capture",
            False,
            f"{other} is running with CAPTURE_MODE={mode}: sudo systemctl restart tvgw-pcap",
        )
    if mode == "headers" and CAPTURE_RULE not in run(["nft", "list", "table", "inet", "tvgw_capture"]):
        detail = "CAPTURE_MODE=headers but inet tvgw_capture has no capture rule: sudo tvgw-apply"
        return Check("capture", False, detail)
    detail = f"full: tvgw-pcap on {s.tv_if}" if mode == "full" else "headers: tvgw-pcap-headers on nflog:7"
    return Check("capture", True, detail)


# (guard) design decision 42
GUARD_APPLIED = "/run/tvgw/guard.applied"  # tvgw-guard.service's listing of what it loaded


def guard_present_check(run: Runner, read: Callable[[str], str]) -> Check:
    """The guard table with its three base chains at filter + 10 and the rules it exists for, and, when
    tvgw-guard.service left its listing, the live table still equal to what it loaded. Without the
    guard the Pi is open to the TV whenever inet tvgw is absent: a FAIL, like a missing inet tvgw."""
    listing = run(["nft", "-s", "list", "table", "inet", "tvgw_guard"])
    if not listing.strip():
        return Check(
            "guard_present",
            False,
            "table inet tvgw_guard is not loaded: sudo systemctl reload-or-restart tvgw-guard",
        )
    hooked = guard.chains_hooked(listing)
    missing = [f"chain {c}" for c in guard.CHAINS if c not in hooked]
    missing += [f'"{rule}"' for rule in guard.KEY_RULES if f'comment "{rule}"' not in listing]
    if missing:
        return Check("guard_present", False, "missing: " + ", ".join(missing))
    loaded = read(GUARD_APPLIED).strip()
    if loaded and loaded != listing.strip():
        return Check("guard_present", False, "differs from what tvgw-guard loaded")
    return Check("guard_present", True, "" if loaded else f"no baseline in {GUARD_APPLIED} yet")


def _series(text: str, comment: str) -> int | None:
    """One counter's packets from `nft -j` listings (one table per line, as tvgw-apply writes them)."""
    found = None
    for line in text.splitlines():
        for rule, packets, _ in counters_from_table(line):
            if rule == comment:
                found = (found or 0) + packets
    return found


def guard_quiet_check(tvgw_loaded: bool, guard_listing: str, after_apply: str) -> Check:
    """While inet tvgw is loaded it drops before the guard, so the guard's last input counter should not
    move: a packet there is one inet tvgw's input chain accepted and should not have. Compared with the
    value tvgw-apply listed right after its last load, which is the start of the stretch inet tvgw has
    been loaded for. A WARN, not a FAIL: the guard did its job, and the finding is that tvgw's own
    chain needs reading."""
    now = _series(guard_listing, guard.FINAL_DROP)
    if now is None:
        return Check("guard_quiet", True, "no guard counter to read")
    if not tvgw_loaded:
        return Check("guard_quiet", True, f"inet tvgw is not loaded: the guard holds alone ({now} dropped)")
    base = _series(after_apply, guard.FINAL_DROP)
    if base is None:
        return Check("guard_quiet", True, "no guard counter in the last apply's listing yet")
    if now < base:
        return Check("guard_quiet", True, "the guard was reloaded since the last apply")
    if now > base:
        detail = (
            f"{now - base} packets inet tvgw accepted were dropped by the guard since the last apply: "
            "read inet tvgw's input chain (nft list chain inet tvgw input)"
        )
        return Check("guard_quiet", True, detail, warn=True)
    return Check("guard_quiet", True, "nothing past inet tvgw since the last apply")


def cotenants_check(s: Settings, run: Runner) -> Check:
    """Every co-tenant unit that is loaded carries IPAddressDeny over the TV subnet, as systemd itself
    reports it (so a drop-in written but never daemon-reloaded counts as missing), and so does an
    active socket unit of one of them. A WARN when one does not: the guard table still holds."""
    units = guard.wanted_units(config.co_tenants(s.co_tenant_units))
    names = [f"{u}.service" for u in units if not u.endswith("@")]
    names += [f"{u}.socket" for u in units if not u.endswith("@")]
    for template in (u for u in units if u.endswith("@")):  # the instances that are loaded
        listing = run(
            ["systemctl", "list-units", "--all", "--no-legend", "--plain", "--full", f"{template}*.service"]
        )
        names += sorted(guard.parse_active_units(listing))
    if not names:
        return Check("cotenants_denied", True, "no co-tenant installed")
    shown = run(
        [
            "systemctl",
            "show",
            "-p",
            "Id",
            "-p",
            "LoadState",
            "-p",
            "ActiveState",
            "-p",
            "IPAddressDeny",
            "--",
            *names,
        ]
    )
    filtered, bare = [], []
    for block in guard.show_blocks(shown):
        unit = block.get("Id", "")
        if block.get("LoadState") != "loaded":
            continue
        if unit.endswith(".socket") and block.get("ActiveState") != "active":
            continue
        (filtered if guard.denies(block.get("IPAddressDeny", ""), s.tv_net) else bare).append(unit)
    if bare:
        detail = f"no IPAddressDeny={s.tv_net}: {', '.join(bare)} (sudo ./install.sh writes it)"
        return Check("cotenants_denied", True, detail, warn=True)
    return Check("cotenants_denied", True, ", ".join(filtered) if filtered else "no co-tenant installed")


def dnsmasq_caps_check(run: Runner, read: Callable[[str], str]) -> Check:
    """The running dnsmasq without CAP_NET_ADMIN, the capability that rewrites the firewall: dnsmasq
    parses every DHCP packet the TV sends. Two readings, because either alone can pass falsely: CapEff
    after its privilege drop holds net_admin or net_raw only when dhcp-broadcast or no-ping is missing
    (dnsmasq 2.91 asks for neither with both), with or without the drop-in; CapBnd, the bounding set,
    still holds them only when the hardening drop-in is not in place (install.sh took it out, or it
    was never written). A WARN either way; a dnsmasq that is down is the services check's FAIL."""
    pid = run(["systemctl", "show", "-p", "MainPID", "--value", "dnsmasq.service"]).strip()
    status = read(f"/proc/{pid}/status") if pid.isdigit() and pid != "0" else ""
    mask = guard.cap_eff(status)
    if mask is None:
        return Check("dnsmasq_caps", True, "dnsmasq is not running")
    held = guard.cap_names(mask)
    detail = f"CapEff {mask:016x}: " + (", ".join(held) if held else "none")
    bad = [c for c in ("net_admin", "net_raw") if c in held]
    if bad:
        return Check("dnsmasq_caps", True, f"{detail}; holds {' and '.join(bad)}", warn=True)
    bounding = guard.cap_mask(status, "CapBnd")
    unbounded = [
        c for c in ("net_admin", "net_raw") if bounding is not None and c in guard.cap_names(bounding)
    ]
    if unbounded:
        detail += f"; bounding set keeps {' and '.join(unbounded)}: the hardening drop-in is not in place"
        return Check("dnsmasq_caps", True, detail, warn=True)
    return Check("dnsmasq_caps", True, detail)


def flowlog_check(
    run: Runner,
    read: Callable[[str], str],
    ruleset: str,
    sockets: Callable[[int], list[flowlog.NetlinkSocket]] = flowlog.event_sockets,
) -> tuple[Check, int | None]:
    """(events) Does the flow log hear the TV, and how many events has its socket dropped? With
    nf_conntrack_events=0 only connections the ruleset marks make events, so the switch without the
    ct_events rule is a flow log that records nothing. The switch at any other value with the rule
    works, but every connection on the box reaches the socket again: a WARN. The drop count is the
    second value, None when no event socket was read (the store then gets no snapshot, not a zero)."""
    events = read(EVENTS_KEY).strip()
    marked = CT_EVENTS_RULE in ruleset
    if events == "0" and ruleset.strip() and not marked:
        detail = "nf_conntrack_events=0 and no ct_events rule: the flow log records nothing (sudo tvgw-apply)"
        return Check("flowlog_events", False, detail), None
    pid = run(["systemctl", "show", "-p", "MainPID", "--value", "tvgw-flowlog"]).strip()
    if not pid.isdigit() or pid == "0":
        return Check("flowlog_events", False, "tvgw-flowlog has no running process"), None
    try:
        held = sockets(int(pid))
    except PermissionError:
        return Check("flowlog_events", False, f"cannot read /proc/{pid}/fd (run as root)"), None
    if not held:
        detail = f"tvgw-flowlog (pid {pid}) holds no conntrack event socket"
        return Check("flowlog_events", False, detail), None
    drops = sum(sock.drops for sock in held)
    if events != "0":
        detail = (
            f"nf_conntrack_events={events or '?'}: every connection on the box reaches the flow log's"
            f" socket ({drops} dropped); sudo tvgw-apply sets it to 0"
        )
        return Check("flowlog_events", True, detail, warn=True), drops
    detail = f"TV connections only; {drops} events dropped since the logger started"
    return Check("flowlog_events", True, detail), drops


def set_fill(listing: str) -> tuple[int, int]:
    """(elements, size) of an `nft -j list set` listing; the size is GATE_SIZE when it is not printed."""
    doc = _json(listing) or {}
    for obj in doc.get("nftables", []) if isinstance(doc, dict) else []:
        if isinstance(obj, dict) and "set" in obj:
            size = obj["set"].get("size")
            n = len(obj["set"].get("elem") or [])
            return n, size if isinstance(size, int) and size > 0 else GATE_SIZE
    return 0, GATE_SIZE


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
    if r.vpn:  # (events) the brief's Coverage line and the leak red line read it (queries.coverage)
        db.set_meta(conn, "vpn_boundary", json.dumps({**r.vpn, "t": r.t}))
        # the last run that saw a VPN at all: the red line keeps its gate through a run made with the
        # daemon down, when there is no tunnel and piactl answers nothing (queries.VPN_SEEN)
        if r.vpn.get("device") or r.vpn.get("pia"):
            db.set_meta(conn, "vpn_seen_t", repr(float(r.t)))
    conn.commit()


def main(s: Settings, profile: Profile, record_to_store: bool = False, as_json: bool = False) -> int:
    # the module attributes, looked up now rather than bound as check()'s defaults, so tests can patch them
    r = check(s, profile, run=run_cmd, read=read_file, mtime=file_mtime, sockets=flowlog.event_sockets)
    # the verdict first: the 10-minute run's only output is the journal, and a store in trouble must
    # not take the checks down with it
    if as_json:
        print(
            json.dumps(
                # (events) `warn` only where it is set, so a reader of the old shape sees no change
                {
                    "ok": r.ok,
                    "checks": [{k: v for k, v in c.__dict__.items() if k != "warn" or v} for c in r.checks],
                    "counters": r.counters,
                },
                indent=1,
            )
        )
    else:
        for c in r.checks:
            print(c.line())
    ok = r.ok
    if record_to_store:
        smp = gw_sample(s)  # (ledger) before the store is opened: its commands may take seconds
        try:
            conn = db.connect(s.db_path)
            try:
                record(conn, r)
                if smp is not None:  # (ledger) a sample that cannot be stored is not a failed check
                    try:
                        ledger.record_sample(conn, smp)
                    except sqlite3.Error as e:
                        print(f"tvgw verify: could not store the gateway sample: {e}", file=sys.stderr)
            finally:
                conn.close()
        except (sqlite3.Error, OSError) as e:  # stderr keeps --json's stdout parseable
            print(f"tvgw verify: could not record the run: {e}", file=sys.stderr)
            ok = False
    return 0 if ok else 1


def gw_sample(s: Settings) -> ledger.Sample | None:
    """(ledger) The gateway's own counters for the change ledger (design decision 48), or None with
    LEDGER=off or when sampling failed: every source is optional, and nothing here may fail verify."""
    if s.ledger != "on":
        return None
    try:
        return ledger.sample(s)
    except Exception as e:  # a sampler bug must never take the firewall check down with it
        print(f"tvgw verify: the gateway sample failed: {type(e).__name__}: {e}", file=sys.stderr)
        return None
