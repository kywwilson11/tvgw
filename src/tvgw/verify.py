"""`tvgw verify`: does the gateway still hold?

Read-only checks of the firewall, routing, resolver and services, one line each; `--record` also
stores the verdict and a snapshot of every firewall counter in the store, so the daily brief can
say how many packets each rule actually stopped. A rule that matched nothing looks exactly like a
rule that works, and a quiet log is not evidence; counters are. Every command is a parameter, so
the logic is testable away from the gateway.
"""

from __future__ import annotations

import contextvars
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

from tvgw import (
    attention,
    backup,
    config,
    db,
    dnsq,
    flowlog,
    guard,
    inpath,
    ledger,
    lgkeys,
    lgwebos,
    queries,
    scrub,
)
from tvgw import probe as tvprobe
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
    "PROFILE",  # (profile) the port wall is LG's, so it follows the profile (design decision 62)
    "WAN_GW_MODE",  # (uplink) how tvgw-apply finds the router; absent is literal
    "DNSGATE_FILL",  # (inpath) whether the in-path filler's rules are loaded; absent is passive
    *("TV_PROBE", "TV_PROBE_IP"),  # (probe) the probe's rules stand only while it is on, for its address
    # (attention) the attention count's table stands only where the live reading runs (design decision 69)
    *("LIVE_READING", "ATTENTION_WALL"),
)
# (profile) the one profile tvgw-apply builds LG's port wall for: any other gets none, whatever
# ADTECH_PORT_WALL says, and its settings.applied records the wall as off
WALL_PROFILE = "lg-webos"
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
# headers mode expects the other in its place (docs/how-it-works/capture.md)
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
# loaded answers its sentinel with 0.0.0.0, so "is the list in force" is one lookup
# (docs/how-it-works/adguard.md)
SENTINELS = (
    ("filter_48.txt", "h4g3z1-pro.web.app"),  # HaGeZi Pro through AdGuard's registry
    ("/adblock/pro.txt", "h4g3z1-pro.web.app"),
    ("filter_72.txt", "h4g3z1-native-lgwebos.web.app"),  # HaGeZi LG webOS through the registry
    ("native.lgwebos.txt", "h4g3z1-native-lgwebos.web.app"),
    ("/adblock/doh.txt", "h4g3z1-doh.web.app"),  # HaGeZi DoH/VPN bypass, from jsDelivr
)
# (packaging) AdGuard Home is a checked dependency, never bundled: what to do when it is missing or old
ADGUARD_INSTALL = (
    "install it with sudo tvgw adguard install, which fetches the release tvgw pins, checks its SHA-256 and"
    " sets it up without its first-run page"
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
# through tvgw's own path, which checks the live config with it first (docs/how-it-works/adguard.md)
ADGUARD_UPDATE = "download the new release and run: sudo tvgw adguard upgrade <its AdGuardHome binary>"


def run_cmd(cmd: list[str]) -> str:
    """stdout of a command, '' when it fails or is missing (every check treats '' as 'not there')."""
    try:
        return subprocess.run(
            cmd, capture_output=True, text=True, encoding="utf-8", errors="replace", timeout=30
        ).stdout
    except (OSError, subprocess.TimeoutExpired):
        return ""


# (depth) the free space of a directory and the pause before the must-allow names are asked again: module
# attributes, so main() looks them up when it runs and the tests can point them elsewhere
free_space = os.statvfs
pause = time.sleep


def read_file(path: str) -> str:
    try:
        with open(path, encoding="utf-8", errors="replace") as fh:
            return fh.read()
    except OSError:
        return ""


def apply_settings(conf_text: str) -> dict[str, str]:
    """The values tvgw-apply would take from this conf: its keys, empty or missing ones defaulted as
    the script defaults them (`${KEY:=value}`, kept equal to Settings by the deploy lint), and the port
    wall off for a profile it does not stand in front of, as the script turns it off."""
    conf, defaults = config.parse_conf(conf_text), Settings()
    used = {
        key: conf.get(key)
        or (str(getattr(defaults, config.CONF_KEYS[key])) if key in config.CONF_KEYS else "")
        for key in APPLY_KEYS
    }
    if used["PROFILE"] != WALL_PROFILE:  # (profile)
        used["ADTECH_PORT_WALL"] = "no"
    return used


def file_mtime(path: str) -> float | None:
    try:
        return os.stat(path).st_mtime
    except OSError:
        return None


# (scrub) what a check's detail is scrubbed with: check() sets this gateway's scrubber for its run, and a
# Check made outside a run gets the default TV subnet's (design decision 63)
_SCRUBBER: contextvars.ContextVar[Callable[[str], str]] = contextvars.ContextVar("verify_scrubber")
_DEFAULT_SCRUBBER = scrub.Scrubber(keep=scrub.SHIPPED)


@dataclass
class Check:
    name: str
    ok: bool
    detail: str = ""
    # (guard) a finding that is not an outage: printed as WARN, and the run still passes. A sandbox
    # that did not take, or a counter that moved where it should not, is worth reading, never a
    # reason for an install to stop with the TV in use
    warn: bool = False
    # (scrub) the detail as the check wrote it, before scrubbing, for a reader on the gateway itself. It
    # is never printed, stored or serialized, and stays out of the repr, which pytest prints when an
    # assertion about a check fails
    raw: str = field(default="", repr=False, compare=False)

    def __post_init__(self) -> None:
        # (scrub) the detail is what `tvgw verify` prints, stores and hands to the install log, which CI
        # publishes: no address outside TV_NET, no MAC, no host, TV or Wi-Fi name in it
        self.raw = self.raw or self.detail
        self.detail = _SCRUBBER.get(_DEFAULT_SCRUBBER)(self.detail)

    def line(self) -> str:
        head = "FAIL" if not self.ok else "WARN" if self.warn else "OK  "
        return f"{head} {self.name}" + (f": {self.detail}" if self.detail else "")

    def as_dict(self) -> dict:
        """What `--json` prints: every field but `raw`, and (events) `warn` only where it is set, so a
        reader of the old shape sees no change."""
        return {k: v for k, v in self.__dict__.items() if k != "raw" and (k != "warn" or v)}


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
    # (probe) the verdict of the test client beside the TV's port, when this run made one, for the sample
    probe: tvprobe.Verdict | None = None

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


# (ntp) the table tvgw-apply counts the TV's NTP in, by server, and its set (design decision 17's note)
NTP_TABLE = ("inet", "tvgw_ntp")
NTP_SET = "ntp4"


def ntp_counters(text: str, stored: int | None = None) -> list[tuple[str, int, int]]:
    """(ntp) What `tvgw verify --record` keeps of the NTP count's set, from an `nft -j list table inet
    tvgw_ntp` listing. First `queries.NTP_SET_ROW`: (it, how many addresses the set holds, its size), the
    mark that the set was listed at this snapshot. Then the `stored` (`queries.NTP_STORED`) addresses
    requested most recently (the latest expiry first, then the most requests), each as
    (`queries.NTP_SERIES` + the address, its requests, its seconds to expiry), from the element's own
    counter and expiry; -1 when nft gave no expiry. nft lists an element that carries statements as
    `{"elem": {"val": ..., "expires": ..., "counter": {...}}}`; one without a counter is held but not
    stored. A value that is not an IPv4 address is skipped, so nothing but an address reaches a row's
    name. No set in the listing: no rows."""
    stored = queries.NTP_STORED if stored is None else stored
    out: list[tuple[str, int, int]] = []
    for obj in (_json(text) or {}).get("nftables", []):
        s = obj.get("set") if isinstance(obj, dict) else None
        if not isinstance(s, dict) or s.get("name") != NTP_SET:
            continue
        elems = s.get("elem") or []
        found: dict[ipaddress.IPv4Address, tuple[int, int]] = {}
        for item in elems:
            e = item.get("elem") if isinstance(item, dict) else None
            c = e.get("counter") if isinstance(e, dict) else None
            if not isinstance(c, dict) or not isinstance(e.get("val"), str):
                continue
            try:
                expires = int(e["expires"]) if "expires" in e else -1
                found[ipaddress.IPv4Address(e["val"])] = (int(c.get("packets", 0)), expires)
            except (TypeError, ValueError):
                continue
        try:
            size = int(s.get("size") or 0)
        except (TypeError, ValueError):
            size = 0
        out.append((queries.NTP_SET_ROW, len(elems), size))
        # the most recently requested: `update` gives each request a whole timeout again, so the latest
        # expiry is the latest request. By lifetime count, a pool's old addresses, kept 10 days, would
        # crowd out the ones the TV uses today
        top = sorted(found, key=lambda a: (-found[a][1], -found[a][0], int(a)))[:stored]
        out += [(f"{queries.NTP_SERIES}{addr}", *found[addr]) for addr in top]
        break
    return out


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
    statvfs: Callable[[str], os.statvfs_result] | None = None,
    meta: Callable[[], dict[str, str] | None] | None = None,
    sleep: Callable[[float], None] | None = None,
    pairing: Callable[[], lgkeys.Pairing | None] | None = None,
    probe: Callable[[], tvprobe.Verdict] | None = None,
) -> Result:
    """Every check, each detail scrubbed with this gateway's own scrubber, built through the same
    `run` and `read` the checks use (design decision 63). `statvfs`, `meta` and `sleep` are the depth
    checks' seams: the free space of the state directory, what the store records (store_meta) and the
    pause before the must-allow names are asked again. Left out, they are free_space, store_meta and
    pause, looked up when the run starts. (W12) `pairing` is the key store's row for the TV (lgkeys.record),
    read when the run starts; left out, the row of the LG key file in the state directory. (probe) `probe`
    runs the test from the TV's position (probe.run); left out, the run has no `tv_probe` check: the test
    sends packets, so only the caller that means to (`tvgw verify --record`, with TV_PROBE=on) passes it."""
    token = _SCRUBBER.set(scrub.scrub_for(s, run=run, read=read))
    try:
        return _check(s, profile, run, read, resolve, mtime, sockets, statvfs, meta, sleep, pairing, probe)
    finally:
        _SCRUBBER.reset(token)


def _pairing_record(s: Settings) -> lgkeys.Pairing | None:
    """(W12) The LG key store's row for the TV, None for any other profile or no row."""
    if s.profile != "lg-webos":
        return None
    try:
        return lgkeys.record(os.path.join(s.state_dir, "lgtv-keys.sqlite"), s.tv_ip)
    except Exception:  # a locked or unreadable key file: no record, never a failed run
        return None


def _check(
    s: Settings,
    profile: Profile,
    run: Runner,
    read: Callable[[str], str],
    resolve: Resolver | None,
    mtime: Callable[[str], float | None],
    sockets: Callable[[int], list[flowlog.NetlinkSocket]],
    statvfs: Callable[[str], os.statvfs_result] | None,
    meta: Callable[[], dict[str, str] | None] | None,
    sleep: Callable[[float], None] | None,
    pairing: Callable[[], lgkeys.Pairing | None] | None = None,
    probe: Callable[[], tvprobe.Verdict] | None = None,
) -> Result:
    resolve = resolve or (lambda name: dnsq.a_records(name, s.gw_ip))
    statvfs = statvfs or free_space
    meta = meta or (lambda: store_meta(s.db_path, backup_dir=backup.directory(s.state_dir)))
    sleep = sleep or pause
    pairing = pairing or (lambda: _pairing_record(s))
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

    # 3. the TV's packets leave by the chosen uplink, through our policy table, and the gateway's own
    #    answers to the TV come back by the TV port
    route = _json(run(["ip", "-j", "route", "get", "1.1.1.1", "from", s.tv_ip, "iif", tv_if])) or []
    dev = route[0].get("dev") if route and isinstance(route[0], dict) else None
    r.checks.append(Check("tv_route", dev == out_if, f"via {dev or 'nothing'}, expected {out_if}"))
    r.checks.append(gw_reply_route_check(s, run))
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
    r.checks.append(must_allow_check(profile, resolve, sleep))

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
    #     (W12) A TV that refused the gateway's key is read no more: the last reading is stale, so the
    #     check is WARN, not checked, with the way back (tvgw tv pair), never a FAIL that stands forever
    stamp, paths = reading_paths(read(s.tvcheck_txt))
    second = [
        f"{label} {paths[key]}"
        for key, label in lgwebos.SECOND_PATHS.items()
        if lgwebos.is_second_path(key, paths.get(key))
    ]
    rec = pairing()
    if rec is not None and rec.refused:
        when = time.strftime("%Y-%m-%d", time.localtime(rec.refused_at))
        detail = (
            f"not checked: the TV refuses the gateway's key since {when}; pair again with sudo tvgw tv pair"
        )
        r.checks.append(Check("tv_paths", True, detail, warn=True))
        second, paths = [], {}
    elif second:
        detail = "second path: " + ", ".join(second) + f" (read {stamp})"
    elif paths:
        detail = (
            f"wired {paths.get('network.wired.state', '?')}, Wi-Fi {paths.get('network.wifi.state', '?')},"
            f" Wi-Fi Direct {paths.get('network.wifiDirect.state', '?')} (read {stamp})"
        )
    elif rec is None or not rec.refused:
        detail = f"the reading at {stamp} has no network paths" if stamp else "no TV reading yet"
    if rec is None or not rec.refused:
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
    # 7c2. (inpath) the gate's in-path filler (design decision 64): OK when the settings do not ask for
    #      it; with DNSGATE_FILL=inpath, whether it is bound and what it has held. A WARN at most
    fill, fill_series = inpath_check(s, run, read, r.t, gate if s.dnsgate != "off" else None)
    r.checks.append(fill)
    # 7c3. (attention) the attention count (design decision 69): OK when it is not in use here; where the
    #      live reading runs, whether its table is loaded and its holder runs. A WARN at most
    r.checks.append(attention_check(s, run, read, r.t))

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
    # 7h. (depth) the gateway's blind spots: its disk, its clock, its record, its own uplink, the router's
    #     address, other firewalls and other devices on the TV's port. Each is a WARN at most until a later
    #     change promotes it (FAIL_AFTER, PROMOTED; design 7.2)
    r.checks += depth_checks(s, run, read, everything, statvfs, meta(), r.t, mtime(CONF))
    # 7i. (probe) the gateway's path for the TV, by the test client beside the TV's port (design decision 65)
    if probe is not None:
        r.probe = probe()
        r.checks.append(probe_check(r.probe))

    # 8. counters, for the record: the inet table, the wire-level IPv6 drop and the DNS gate; and
    #    tvgw-apply's listings either side of its last reload, so record() can store the reset itself.
    #    The pair counts only whole: one file, or an after older than its before (caught between the
    #    two renames), would read as a reset that never happened
    tables = [("inet", "tvgw"), ("netdev", "tvgw_l2"), ("inet", "tvgw_gate")]
    if s.capture_mode == "headers":  # (capture) the table exists only then
        tables.append(("inet", "tvgw_capture"))
    if attention.wanted(s):  # (attention) the table exists only where the live reading runs
        tables.append(("inet", attention.TABLE))
    tables.append(("inet", "tvgw_guard"))  # (guard)
    known = {("netdev", "tvgw_l2"): l2, ("inet", "tvgw_guard"): guard_json}
    for table in tables:
        listing = known[table] if table in known else run(["nft", "-j", "list", "table", *table])
        r.counters += counters_from_table(listing)
    if drops is not None:  # (events) a series of its own, read as the counters are (flowlog.DROPS_RULE)
        r.counters.append((flowlog.DROPS_RULE, drops, 0))
    # 8b. (ntp) the clock servers' count, from one listing of its table: the rule's total and a series
    #     per address in its set, each from the element's own counter, which a re-apply keeps
    ntp = run(["nft", "-j", "list", "table", *NTP_TABLE])
    r.counters += counters_from_table(ntp) + ntp_counters(ntp)
    r.counters += fill_series  # (inpath) the filler's own counts, when it is bound and its status fresh
    pair = [(mtime(path), read(path)) for path in RELOADS]
    (t0, before), (t1, after) = pair
    if t0 is not None and t1 is not None and t1 > t0 and before.strip() and after.strip():
        r.reloads = [
            (t, [c for line in text.splitlines() for c in counters_from_table(line)]) for t, text in pair
        ]
    return r


def probe_check(v: tvprobe.Verdict) -> Check:
    """(probe) The probe's verdict as a check: a pass is OK, an unknown a WARN (it could not tell, which is
    no finding about the TV's path), and a failure of FAIL level, held at WARN while the check is new
    (FAIL_AFTER). The detail is the stage that decided it, in the probe's own fixed words: no name it
    asked for and no address."""
    if v.verdict == tvprobe.PASS:
        return Check("tv_probe", *held("tv_probe", OK, tvprobe.VERDICT_PLAIN[tvprobe.PASS]))
    level = FAIL if v.verdict == tvprobe.FAIL else WARN
    return Check("tv_probe", *held("tv_probe", level, f"{v.verdict}: {v.reason}"))


def gw_reply_route_check(s: Settings, run: Runner) -> Check:
    """What the gateway itself sends to the TV (the resolver's answers, nginx's replies) leaves by the TV
    port (design decision 49). Rule 60 sends those packets, from GW_IP, into table 100 too, and a table
    without the TV subnet sent them out the uplink: the TV had an address and no answers while every other
    check passed. The ICMP of a reject is routed before it has a source address (unless
    icmp_errors_use_inbound_ifaddr is set), so by the main table: this lookup is the stricter of the two,
    and what it cannot see is the kernel's ICMP rate limit, which is no route's (decision 49's note of
    2026-11-04). Checked in both uplink modes, and a failure is an outage. The detail names interfaces
    only; the route's gateway and addresses stay out of it."""
    route = _json(run(["ip", "-j", "route", "get", s.tv_ip, "from", s.gw_ip])) or []
    dev = route[0].get("dev") if isinstance(route, list) and route and isinstance(route[0], dict) else None
    dev = dev if isinstance(dev, str) and dev else None
    detail = f"the gateway's answers to the TV leave by {dev or 'nothing'}, expected {s.tv_if}"
    return Check("gw_reply_route", dev == s.tv_if, detail)


def sentinels(profile: Profile) -> list[str]:
    """(lists) The sentinel names of the lists the profile subscribes, in its order, each once: the one a
    filters entry names, else the one SENTINELS knows for its URL. A list with neither adds none."""
    out: list[str] = []
    for _name, url in profile.adguard_filters:
        if own := profile.filter_sentinels.get(url):  # (profile)
            if own not in out:
                out.append(own)
            continue
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


# (inpath) what tvgw-apply's in-path block loads into inet tvgw_gate, as the listing prints it
INPATH_NEEDLES = (
    ("set resolved4_inpath", "the in-path set"),
    ("set inpath_live", "the live switch"),
    (inpath.OFFERED_RULES[0], "the UDP queue rule"),
    (inpath.OFFERED_RULES[1], "the TCP queue rule"),
    (inpath.MISS_RULE, "the second counting rule"),
)
INPATH_UNIT = "tvgw-dnsgate-inpath"


def inpath_check(
    s: Settings, run: Runner, read: Callable[[str], str], now: float, gate_listing: str | None = None
) -> tuple[Check, list[tuple[str, int, int]]]:
    """(inpath) The DNS gate's in-path filler (design decision 64), and its counts for the store.

    OK, saying so, when the settings do not ask for it. With DNSGATE_FILL=inpath: its rules and sets are
    in inet tvgw_gate, a process is bound to its queue (the kernel's own table of queues), that process
    wrote its status within the last minute and is live, and the kernel dropped nothing. The detail then
    then says how long it has run and its median hold, and names no count of answers (the detail is
    printed where others may read it). None of it is an outage: without the filler the kernel passes the
    TV's DNS answers itself, so every finding is a WARN, and the one of FAIL level (the kernel's own drop
    counters moving, which only a queue without fail-open does) is held at WARN until the check is
    promoted. The second value is the status file's counts as fw_counters series, among them the
    verdicts the kernel refused (answers it had dropped), empty unless the filler is bound and its
    status fresh: a stale file must not repeat an old count as a new snapshot."""
    name = "dnsgate_inpath"  # held()'s key
    if not inpath.wanted(s):
        why = "DNSGATE=off" if s.dnsgate == "off" else "DNSGATE_FILL=passive"
        return Check(
            "dnsgate_inpath", True, f"not in use ({why}): the passive feeder alone fills the gate's set"
        ), []
    gate = run(["nft", "list", "table", "inet", "tvgw_gate"]) if gate_listing is None else gate_listing
    missing = [what for needle, what in INPATH_NEEDLES if needle not in gate]
    if missing:
        detail = "missing: " + ", ".join(missing) + "; answers pass unheld (sudo tvgw-apply)"
        return Check("dnsgate_inpath", *held(name, WARN, detail)), []
    q = inpath.bound_queues(read(inpath.PROC_QUEUES)).get(inpath.QUEUE)
    if q is None:
        detail = (
            f"no process is bound to queue {inpath.QUEUE}: the kernel passes the TV's DNS answers itself,"
            f" unheld (systemctl status {INPATH_UNIT})"
        )
        return Check("dnsgate_inpath", *held(name, WARN, detail)), []
    dropped = q["dropped"] + q["user_dropped"]
    if dropped:
        # the kernel counts a drop here only when a queue is not configured fail-open; the filler's is,
        # so this says the queue was bound by something that is not the filler, or the filler changed
        detail = (
            f"the kernel dropped {dropped} DNS answers for want of room in the queue: it is not configured"
            " fail-open, as the filler configures it"
        )
        return Check("dnsgate_inpath", *held(name, FAIL, detail)), []
    doc = _json(read(inpath.STATUS))
    stats = doc.get("stats") if isinstance(doc, dict) else None
    written = _number(doc.get("t")) if isinstance(doc, dict) else None
    if not isinstance(stats, dict) or written is None or not 0 <= now - written <= inpath.STATUS_STALE:
        age = "missing" if written is None else f"{_ago(max(now - written, 0))} old"
        detail = f"bound, but its status file is {age} (journalctl -u {INPATH_UNIT} -n 20)"
        return Check("dnsgate_inpath", *held(name, WARN, detail)), []

    def n(*fields: str) -> int:
        return sum(int(v) for f in fields if (v := _number(stats.get(f))) is not None)

    series = [(rule, n(*fields), 0) for _key, fields, rule in inpath.SERIES]
    # The detail names no count of answers: `tvgw verify` is printed where others may read it (the
    # hardware job's log), and how many answers the TV received over a known time is how much TV was
    # watched (design decision 63). The counts go to the store as the series above, and the brief shows
    # them; the status file has them for a reader on the gateway.
    if not doc.get("live"):
        detail = "bound, but no answer is offered to it: inpath_live is empty (as for seconds after an apply)"
        return Check("dnsgate_inpath", *held(name, WARN, detail)), series
    if q["waiting"] >= inpath.MAXLEN // 2:
        detail = "DNS answers are piling up in the queue: the filler is not keeping up"
        return Check("dnsgate_inpath", *held(name, WARN, detail)), series
    dropped_1h = _number(doc.get("dropped_1h")) or 0
    if dropped_1h:
        # the kernel drops what waits in a queue when any hook is removed, and its own counters never
        # show it; the filler sees it as a verdict the kernel refuses, for an answer it no longer holds
        detail = (
            "in the last hour the kernel dropped DNS answers that were waiting in the queue, a hook"
            " removed while they waited (the TV asks again); the number is in the store and in"
            f" {inpath.STATUS}"
        )
        return Check("dnsgate_inpath", *held(name, WARN, detail)), series
    fill_n, fill_size = set_fill(run(["nft", "-j", "list", "set", "inet", "tvgw_gate", inpath.SET]))
    if fill_n > fill_size * GATE_FULL:
        detail = f"over {GATE_FULL:.0%} of {inpath.SET} is in use: an add past its size would be refused"
        return Check("dnsgate_inpath", *held(name, WARN, detail)), series
    hold = doc.get("hold_us") if isinstance(doc.get("hold_us"), dict) else {}
    median = _number(hold.get("p50")) or 0.0
    detail = (
        f"bound and holding, up {_ago(max(now - (_number(doc.get('started')) or now), 0))}; the median"
        f" hold is {median / 1000:.2f} ms; its counts are in the store (tvgw verify --record) and in"
        f" {inpath.STATUS}"
    )
    return Check("dnsgate_inpath", True, detail), series


# (attention) what tvgw-apply's attention block loads into inet tvgw_attn, as the listing prints it
ATTENTION_NEEDLES = (
    (f"set {attention.PLATFORM_SET}", "the essentials' set"),
    *((f"set {attention.STATE_SETS[st]}", f"the {st} entry") for st in attention.STATES),
    *((attention.RULES[st], f"the {st} count") for st in attention.COUNTED),
)
ATTENTION_UNIT = "tvgw-attention"


def attention_check(s: Settings, run: Runner, read: Callable[[str], str], now: float) -> Check:
    """(attention) The attention count (design decision 69). OK, saying so, where it is not in use (the
    live reading off, another profile, ATTENTION_WALL=off). Where it is: its table holds the essentials'
    set, the four dead-man entries' sets and the three counting rules, and its holder wrote its status in
    the last minute. Never an outage: without the holder the entries expire and nothing is counted, so
    every finding is a WARN. The detail never says which state the TV is in (it reaches the public
    hardware log, and the state is the live record's)."""
    why = attention.not_in_use(s)
    if why is not None:
        return Check("attention", True, f"not in use ({why}): nothing is counted by the TV's state")
    listing = run(["nft", "list", "table", "inet", attention.TABLE])
    missing = [what for needle, what in ATTENTION_NEEDLES if needle not in listing]
    if missing:
        detail = "missing: " + ", ".join(missing) + "; nothing is counted (sudo tvgw-apply)"
        return Check("attention", *held("attention", WARN, detail))
    doc = _json(read(attention.STATUS))
    written = _number(doc.get("t")) if isinstance(doc, dict) else None
    if written is None or not 0 <= now - written <= attention.STATUS_STALE:
        age = "missing" if written is None else f"{_ago(max(now - written, 0))} old"
        detail = (
            f"its holder's status is {age}: the TV is in no state, and nothing is counted"
            f" (systemctl status {ATTENTION_UNIT})"
        )
        return Check("attention", *held("attention", WARN, detail))
    detail = f"loaded, and its holder runs, up {_ago(max(now - (_number(doc.get('started')) or now), 0))}"
    if s.attention_wall == "refuse":
        detail += "; ATTENTION_WALL=refuse counts, as count: it is not supported on a live gateway yet"
    return Check("attention", True, detail + "; its counts are in the store (tvgw brief --full)")


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


# ---- (depth) the must-allow names, asked twice before they fail ---------------------------------------
# One SERVFAIL on 2026-11-01 failed resolver_must_allow in one run and kept a red line in the brief for 24
# hours. A name that fails is asked once more after MUST_ALLOW_RETRY seconds: an answer then is a WARN,
# "transient", and the run passes. The second round stops at the first name that fails again, so a run
# in an outage waits the pause and one more lookup before it fails, not one more lookup per name.
MUST_ALLOW_RETRY = 3.0


def _must_allow_why(got: list[str] | None) -> str | None:
    """Why one must-allow answer fails, or None when it is an address. [] is NXDOMAIN, REFUSED, SERVFAIL
    or NODATA: AdGuard's nxdomain and refused blocking modes answer that way, and so does an upstream
    outage."""
    if got and got != ["0.0.0.0"]:
        return None
    return "no answer" if got is None else "blocked" if got else "empty answer"


def must_allow_check(
    profile: Profile, resolve: Resolver, sleep: Callable[[float], None] = time.sleep
) -> Check:
    """Every must-allow name answers with an address; one that does not is asked again once, after
    MUST_ALLOW_RETRY seconds, and passes with a WARN when it answers then."""
    bad = [(host, why) for host in profile.must_allow if (why := _must_allow_why(resolve(host)))]
    if not bad:
        return Check("resolver_must_allow", True, "")
    sleep(MUST_ALLOW_RETRY)
    still: list[tuple[str, str]] = []
    for i, (host, _first) in enumerate(bad):
        why = _must_allow_why(resolve(host))
        if why:
            # the first name to fail twice ends the round: the rest keep the reason of their first try
            still = [(host, why), *bad[i + 1 :]]
            break
    first = ", ".join(f"{host}->{why}" for host, why in bad)
    if still:
        return Check("resolver_must_allow", False, ", ".join(f"{host}->{why}" for host, why in still))
    detail = f"transient: {first}; answered when asked again {MUST_ALLOW_RETRY:.0f} s later"
    return Check("resolver_must_allow", True, detail, warn=True)


# ---- (depth) the gateway's blind spots (design 7.2) ------------------------------------------------------
# A new check is a WARN at most until a later change promotes it, whatever it finds, so a gateway gains no
# red line from a check nobody has yet watched pass on the reference. FAIL_AFTER names the level each
# check's worst finding takes once promoted; PROMOTED lists the checks whose promotion has merged (one
# change per check, after 7 days of OK in the hardware job's log, each listed in the changelog). Until
# then a finding of FAIL level says so in its detail (HELD). Every detail here is built from counts,
# check names, interface names, paths of tvgw's own and fixed words: never an address, a MAC or a host
# name, which is what the CI log of the hardware job may print.
OK, WARN, FAIL = "ok", "warn", "fail"
FAIL_AFTER: dict[str, str] = {
    "disk": FAIL,  # under DISK_FAIL free, or the state directory's filesystem is read-only
    "clock_synced": FAIL,  # the system clock is not synchronized
    "store_backup": FAIL,  # the last backup's copy failed its integrity check; age alone is a WARN
    "ingest_fresh": FAIL,  # no ingest for INGEST_FAIL_AGE on a gateway up for INGEST_BOOT_GRACE
    "uplink_ipv4": FAIL,  # no IPv4 address on the uplink
    "wan_gateway": FAIL,  # table 100 has no default route while the uplink is up
    "forward_policy": FAIL,  # another forward-hook chain drops by default and never accepts the TV
    "input_policy": FAIL,  # another input-hook chain drops by default and not the TV's DHCP and DNS
    "tv_port_neighbours": WARN,  # never more (design 4.6): another device there is not an outage
    # (inpath) the kernel dropped DNS answers it had queued for the filler; every other finding is a WARN
    "dnsgate_inpath": FAIL,
    "tv_probe": FAIL,  # (probe) the test from the TV's position failed, with the gateway's own uplink working
    "attention": WARN,  # (attention) never more: the attention count refuses nothing (design decision 69)
}
PROMOTED: frozenset[str] = frozenset()
HELD = " (a FAIL once this check is promoted; a warning while it is new)"
DISK_WARN = 2 * 2**30  # bytes free under which the record has days, not weeks, before it stops
DISK_FAIL = 512 * 2**20  # bytes free under which the next hour's capture or backup may not fit
BACKUP_MAX_AGE = 2 * 86400  # the daily copy (tvgw-backup.timer) has missed a day
INGEST_WARN_AGE = 2 * 3600  # the hourly ingest (tvgw-analyze.timer, at :20) has missed a run
INGEST_FAIL_AGE = 12 * 3600  # half a day of the TV's traffic is missing from the record
INGEST_BOOT_GRACE = 3600  # up this long, a gateway has had its catch-up run (the timer is Persistent)
NEIGH_STATES = frozenset({"REACHABLE", "STALE", "DELAY"})  # a device that answered on the port lately
RT_TABLE = "100"  # tvgw-apply's table for the TV's traffic in direct mode
META_KEYS = ("last_run", "backup_ok_t", "backup_error")  # what the depth checks read from the store
# what store_meta adds besides the meta table, under names the table never holds: the time of the first
# check the store recorded (its verify table, which tvgw-verify.timer writes from minutes after the
# install on) and of the newest copy in the backup directory, from its UTC name
FIRST_CHECK, NEWEST_COPY = "first_check_t", "newest_copy_t"


def held(name: str, level: str, detail: str) -> tuple[bool, str, bool]:
    """A finding of `level` as Check's (ok, detail, warn): OK passes, WARN warns, and FAIL fails only once
    `name` is in PROMOTED and FAIL_AFTER says FAIL; until then it warns, saying it is held (HELD)."""
    if level == OK:
        return True, detail, False
    if level == FAIL and FAIL_AFTER.get(name) == FAIL:
        if name in PROMOTED:
            return False, detail, False
        return True, detail + HELD, True
    return True, detail, True


def store_meta(
    db_path: str, keys: tuple[str, ...] = META_KEYS, backup_dir: str | None = None
) -> dict[str, str] | None:
    """What the depth checks read of the record: the store's meta values, from a read-only connection,
    with FIRST_CHECK and, given `backup_dir`, NEWEST_COPY. An empty record when there is no store yet (a
    new gateway's first recorded check creates it; none is created here); None when the store is there
    but cannot be read (no permission, still locked after 10 seconds). Never raises."""
    out: dict[str, str] = {}
    if os.path.exists(db_path):
        try:
            conn = db.connect(db_path, readonly=True, timeout=10)
            try:
                marks = ",".join("?" * len(keys))
                rows = conn.execute(f"SELECT key, value FROM meta WHERE key IN ({marks})", keys).fetchall()
                try:
                    first = conn.execute("SELECT MIN(t) FROM verify").fetchone()[0]
                except sqlite3.OperationalError:  # a store from before the verify table: no first check
                    first = None
            finally:
                conn.close()
        except sqlite3.Error:
            return None
        out = {str(k): str(v) for k, v in rows}
        if _number(first) is not None:
            out[FIRST_CHECK] = repr(float(first))
    newest = backup.newest_copy(backup_dir) if backup_dir else None
    if newest is not None:
        out[NEWEST_COPY] = repr(newest)
    return out


def _number(value) -> float | None:
    try:
        n = float(value)
    except (TypeError, ValueError):
        return None
    return n if n == n else None  # NaN is no time


def _bytes(n: float) -> str:
    return f"{n / 2**30:.1f} GiB" if n >= 2**30 else f"{n / 2**20:.0f} MiB"


def _ago(seconds: float) -> str:
    if seconds < 2 * 3600:
        return f"{max(seconds, 0) / 60:.0f} minutes"
    if seconds < 2 * 86400:
        return f"{seconds / 3600:.0f} hours"
    return f"{seconds / 86400:.1f} days"


def disk_level(path: str, statvfs: Callable[[str], os.statvfs_result]) -> tuple[str, str]:
    """The free space where the store, the captures and the copies are kept (STATE_DIR, `path`). The
    detail says "where the record is kept", never the path: STATE_DIR is the owner's to choose, and a
    path can carry a name."""
    where = "where the record is kept"
    try:
        st = statvfs(path)
    except OSError as e:
        return WARN, f"cannot read the free space {where}: {e.strerror or type(e).__name__}"
    if st.f_flag & os.ST_RDONLY:
        return FAIL, f"the filesystem {where} is read-only"
    free = st.f_bavail * st.f_frsize
    if free < DISK_FAIL:
        return FAIL, f"{_bytes(free)} free {where}, under {_bytes(DISK_FAIL)}"
    if free < DISK_WARN:
        return WARN, f"{_bytes(free)} free {where}, under {_bytes(DISK_WARN)}"
    return OK, f"{_bytes(free)} free {where}"


def clock_level(run: Runner) -> tuple[str, str]:
    """systemd's word on the clock (the kernel's synchronized flag, set by timesyncd, chrony or ntpd)."""
    said = run(["timedatectl", "show", "-p", "NTPSynchronized", "--value"]).strip()
    if said == "yes":
        return OK, "the system clock is synchronized"
    if said == "no":
        return FAIL, "the system clock is not synchronized"
    return WARN, "timedatectl did not say whether the clock is synchronized"


def backup_level(meta: dict[str, str] | None, now: float, since: float | None = None) -> tuple[str, str]:
    """The newest copy, as `tvgw backup` recorded it (meta.backup_ok_t) or as the backup directory holds
    it (NEWEST_COPY: a copy is named only once it passed its check, so copies made before outcomes were
    recorded count), or the failure recorded after it (meta.backup_error: its time and one of
    backup.FAILURES). Only a copy that failed its integrity check is of FAIL level: the store itself may
    be damaged. With no copy at all, a gateway installed (`since`) under BACKUP_MAX_AGE ago has had no
    daily copy due yet."""
    if meta is None:
        return WARN, "the store could not be read"
    times = [n for n in (_number(meta.get("backup_ok_t")), _number(meta.get(NEWEST_COPY))) if n is not None]
    ok_t = max(times) if times else None
    err = _json(meta.get("backup_error") or "")
    err = err if isinstance(err, dict) else {}
    err_t = _number(err.get("t"))
    if err_t is not None and (ok_t is None or err_t >= ok_t):
        why = err.get("why") if err.get("why") in backup.FAILURES else "it failed"
        level = FAIL if why == backup.CHECK_FAILED else WARN
        return level, f"the last backup, {_ago(now - err_t)} ago, failed: {why}"
    if ok_t is None:
        if since is not None and now - since <= BACKUP_MAX_AGE:
            return OK, f"no backup yet; none was due in the {_ago(now - since)} since the install"
        return WARN, "no backup recorded yet"
    if now - ok_t > BACKUP_MAX_AGE:
        return WARN, f"the newest backup is {_ago(now - ok_t)} old"
    return OK, f"the newest backup is {_ago(now - ok_t)} old"


def ingest_level(
    meta: dict[str, str] | None, now: float, uptime: float | None, since: float | None = None
) -> tuple[str, str]:
    """When the hourly ingest last ran (meta.last_run, its start). Half a day without one is of FAIL level
    only on a gateway that has been up for INGEST_BOOT_GRACE: the timer catches up after a power cut. A
    gateway where no ingest has run yet is measured the same way from its install (`since`), so the first
    two hours are no finding and a first ingest that never comes is."""
    if meta is None:
        return WARN, "the store could not be read"
    last = _number(meta.get("last_run"))
    if last is None:
        if since is None:
            return WARN, "no ingest has run yet"
        age = now - since
        said = f"no ingest has run in the {_ago(age)} since the install"
        if age > INGEST_FAIL_AGE and (uptime is None or uptime > INGEST_BOOT_GRACE):
            return FAIL, said
        if age > INGEST_WARN_AGE:
            return WARN, said
        return OK, f"no ingest has run yet; none was due in the {_ago(age)} since the install"
    age = now - last
    if age > INGEST_FAIL_AGE and (uptime is None or uptime > INGEST_BOOT_GRACE):
        return FAIL, f"the last ingest ran {_ago(age)} ago"
    if age > INGEST_WARN_AGE:
        return WARN, f"the last ingest ran {_ago(age)} ago"
    return OK, f"the last ingest ran {_ago(age)} ago"


def uplink_level(run: Runner, wan_if: str, exists: Callable[[str], bool]) -> tuple[str, str]:
    """An IPv4 address of global scope on WAN_IF: the gateway forwards IPv4 only, so an uplink with only
    IPv6, or only a link-local address, leaves the TV with no way out."""
    if not exists(wan_if):
        return FAIL, f"{wan_if} does not exist"
    links = _json(run(["ip", "-j", "-4", "addr", "show", "dev", wan_if])) or []
    for link in links if isinstance(links, list) else []:
        for a in link.get("addr_info", []) if isinstance(link, dict) else []:
            local = str(a.get("local", "")) if isinstance(a, dict) else ""
            if a.get("family") == "inet" and a.get("scope") == "global" and not local.startswith("169.254."):
                return OK, f"{wan_if} has an IPv4 address"
    return FAIL, f"{wan_if} has no IPv4 address"


def wan_gateway_level(s: Settings, run: Runner, read: Callable[[str], str]) -> tuple[str, str]:
    """(direct mode) Table 100 holds the TV's default route while the uplink has carrier, and, with
    WAN_GW_MODE=literal, WAN_GW is a router WAN_IF's own default route in the main table uses: a router
    that moved to a new address leaves the literal pointing at nothing, and the TV dark at the next apply."""
    up = read(f"/sys/class/net/{s.wan_if}/carrier").strip() == "1"
    table = _json(run(["ip", "-j", "route", "show", "table", RT_TABLE, "default"])) or []
    routed = any(isinstance(x, dict) and x.get("dst") == "default" for x in table if isinstance(table, list))
    if up and not routed:
        return FAIL, f"table {RT_TABLE} has no default route while {s.wan_if} is up"
    if s.wan_gw_mode == "literal":
        try:
            literal = config.parse_conf(read(CONF)).get("WAN_GW", "")
        except ValueError:  # applied_current and every command say what is wrong with the file
            literal = ""
        main = _json(run(["ip", "-j", "route", "show", "default", "dev", s.wan_if])) or []
        via = {x.get("gateway") for x in main if isinstance(x, dict) and x.get("gateway")}
        if not literal:
            return WARN, "WAN_GW is not set in tvgw.conf"
        if via and literal not in via:
            return (
                WARN,
                f"WAN_GW is not the router {s.wan_if}'s own default route uses: did its address change?",
            )
    if not up:
        return OK, f"{s.wan_if} has no carrier; the dispatcher restores table {RT_TABLE} when it comes back"
    return OK, f"table {RT_TABLE} routes the TV out by {s.wan_if}"


def neighbours_level(run: Runner, tv_if: str, tv_mac: str) -> tuple[str, str]:
    """Hardware addresses other than TV_MAC that answered on the TV's port lately (design 4.6): a switch,
    a second device, or a router cable in the TV's port. The detail is a count, never an address."""
    if not tv_mac or tv_mac == config.PLACEHOLDER_MAC:
        return OK, "the TV's hardware address is not recorded yet: not checked"
    entries = _json(run(["ip", "-j", "neigh", "show", "dev", tv_if])) or []
    others = set()
    for e in entries if isinstance(entries, list) else []:
        if not isinstance(e, dict):
            continue
        state = e.get("state")
        states = {state} if isinstance(state, str) else set(state) if isinstance(state, list) else set()
        mac = str(e.get("lladdr") or "").lower()
        if mac and mac != tv_mac.lower() and states & NEIGH_STATES:
            others.add(mac)
    if others:
        n = len(others)
        return WARN, f"{n} other device{'s' if n > 1 else ''} answered on the TV's port"
    return OK, "only the TV answered on the TV's port"


# ---- (depth) other firewalls on the path of the TV's packets (forward_policy, input_policy) ----------
# A packet must be accepted by every base chain on its hook, so a chain of another firewall (ufw, Docker,
# a VPN client's) with policy drop stops the TV unless one of its rules accepts the TV's packets: on the
# TV's port by name, directly or through a jump or goto, or with no condition at all. The rules are read
# from `nft -j list ruleset`; tvgw's own tables (inet tvgw*) are left out. A condition the evaluation does
# not read (a connection state, an address, an extension iptables could not translate) proves an accept
# only on a path that already matched the TV's port. The details count chains and never name one, since a
# VPN client's chains carry its product's name.
@dataclass(frozen=True)
class Want:
    """The TV's packets a path must accept: in on `iface`, and when given, of `proto` to `port`."""

    iface: str
    proto: str | None = None
    port: int | None = None
    label: str = ""


TV_INPUT = (
    Want("", "udp", 67, "DHCP (UDP 67)"),
    Want("", "udp", 53, "DNS (UDP 53)"),
    Want("", "tcp", 53, "DNS (TCP 53)"),
)
_PROTOS = {"tcp": "tcp", "udp": "udp", 6: "tcp", 17: "udp", "6": "tcp", "17": "udp"}
_NEUTRAL = ("counter", "log", "comment", "notrack")  # statements that neither choose packets nor decide
_VERDICTS = ("accept", "drop", "reject", "jump", "goto", "return", "queue", "continue")


def _values(right) -> list | None:
    """The values a match's right side names (a value, a list, a set); None for a named set (`@name`) or
    another form the evaluation does not read."""
    if isinstance(right, dict) and "set" in right:
        right = right["set"]
    if isinstance(right, list):
        return right
    if isinstance(right, (str, int)) and not (isinstance(right, str) and right.startswith("@")):
        return [right]
    if isinstance(right, dict) and "range" in right:
        return [right]
    return None


def _iface_named(right, iface: str) -> bool | None:
    vals = _values(right)
    if vals is None:
        return None
    for v in vals:
        if isinstance(v, str) and (v == iface or (v.endswith("*") and iface.startswith(v[:-1]))):
            return True
    return False


def _port_in(right, port: int) -> bool | None:
    vals = _values(right)
    if vals is None:
        return None
    for v in vals:
        if isinstance(v, dict) and isinstance(v.get("range"), list) and len(v["range"]) == 2:
            lo, hi = v["range"]
            if isinstance(lo, int) and isinstance(hi, int) and lo <= port <= hi:
                return True
        elif (isinstance(v, int) and v == port) or (isinstance(v, str) and v.isdigit() and int(v) == port):
            return True
    return False


@dataclass
class _Rule:
    """One rule read against a Want: whether it can match the TV's packets at all (`excluded`), whether
    it names the TV's port (`tv`), whether it has a condition the evaluation does not read (`other`) or one
    that takes only some of the TV's packets when the Want names no port (`narrow`), and its verdict."""

    excluded: bool = False
    tv: bool = False
    other: bool = False
    narrow: bool = False
    verdict: str = ""
    target: str = ""


def _read_rule(rule: dict, want: Want) -> _Rule:
    out = _Rule()
    for expr in rule.get("expr", []) if isinstance(rule.get("expr"), list) else []:
        if not isinstance(expr, dict) or not expr:
            continue
        key = next(iter(expr))
        body = expr[key]
        if key in _NEUTRAL:
            continue
        if key in _VERDICTS:
            out.verdict = key
            if key in ("jump", "goto") and isinstance(body, dict):
                out.target = str(body.get("target", ""))
            continue
        if key != "match" or not isinstance(body, dict):
            out.other = True  # limit, xt, a set lookup, a mangle: chooses packets by what is not read here
            continue
        left, right, op = body.get("left"), body.get("right"), body.get("op", "==")
        meta = (
            left.get("meta", {}).get("key")
            if isinstance(left, dict) and isinstance(left.get("meta"), dict)
            else None
        )
        payload = (
            left.get("payload") if isinstance(left, dict) and isinstance(left.get("payload"), dict) else None
        )
        if meta in ("iifname", "iif") and op in ("==", "in", "!="):
            named = _iface_named(right, want.iface)
            if named is None:
                out.other = True
            elif (op == "!=") == named:
                out.excluded = True  # names another port, or every port but the TV's
            elif op != "!=":
                out.tv = True
            continue
        proto_match = meta == "l4proto" or (
            payload is not None and payload.get("protocol") == "ip" and payload.get("field") == "protocol"
        )
        if proto_match and op in ("==", "in"):
            vals = _values(right)
            protos = {_PROTOS.get(v) for v in vals} if vals is not None else None
            if want.proto is None:
                out.narrow = True
            elif protos is None:
                out.excluded = True  # cannot show it takes the protocol asked for
            elif want.proto not in protos:
                out.excluded = True
            continue
        if payload is not None and payload.get("field") == "dport" and op in ("==", "in"):
            proto = payload.get("protocol")
            if want.port is None:
                out.narrow = True
            elif (proto in ("tcp", "udp") and want.proto != proto) or _port_in(right, want.port) is not True:
                out.excluded = True
            continue
        out.other = True  # a connection state, an address, oifname: some packets, not provably the TV's
    return out


def _outcomes(
    rules: dict[tuple, list[dict]],
    key: tuple,
    want: Want,
    tv: bool = False,
    narrowed: bool = False,
    depth: int = 0,
    seen: frozenset = frozenset(),
) -> set[str]:
    """What can become of the Want's packets in chain `key`: some set of "accept" (a path accepts them),
    "drop" (a drop, reject or queue ends a path) and "return" (a path falls off the end or returns to the
    caller). A rule with a condition the evaluation does not read takes only some packets, so the rest
    go on to the next rule; a rule with none ends every path through it. A jump or goto is followed, 16
    deep at most and each chain once per path. An accept counts only on a path that matched the TV's port,
    or on one where no condition was left unread."""
    if depth > 16 or key in seen:
        return {"return"}
    out: set[str] = set()
    for rule in rules.get(key, []):
        r = _read_rule(rule, want)
        if r.excluded:
            continue
        on_tv = tv or r.tv
        unread = narrowed or r.other
        whole = not r.other and not r.narrow  # takes every packet of the Want that reached it
        if r.verdict == "accept":
            if on_tv or not unread:
                out.add("accept")
            if whole:
                return out
        elif r.verdict in ("drop", "reject", "queue"):
            if whole:
                return out | {"drop"}
        elif r.verdict == "return":
            out.add("return")
            if whole:
                return out
        elif r.verdict in ("jump", "goto") and r.target:
            sub = _outcomes(rules, (key[0], key[1], r.target), want, on_tv, unread, depth + 1, seen | {key})
            out |= sub - {"return"}
            if "return" in sub and r.verdict == "goto":
                out.add("return")  # a goto's chain returns to this chain's caller, not here
                if whole:
                    return out
            elif "return" not in sub and whole:
                return out  # every packet ended in the called chain
    return out | {"return"}


def _accepts(rules: dict[tuple, list[dict]], key: tuple, want: Want) -> bool:
    """A base chain lets some of the Want's packets through: a return from it is its policy, drop."""
    return "accept" in _outcomes(rules, key, want)


def _drop_chains(doc, hook: str) -> tuple[list[tuple], dict[tuple, list[dict]]]:
    """The base chains on `hook`, outside tvgw's own tables, whose policy is drop, and every rule by its
    (family, table, chain). IPv4 only: families ip and inet."""
    chains, rules = [], {}
    for obj in doc.get("nftables", []) if isinstance(doc, dict) else []:
        if not isinstance(obj, dict):
            continue
        c, rule = obj.get("chain"), obj.get("rule")
        if isinstance(c, dict) and c.get("hook") == hook and c.get("policy") == "drop":
            family, table = c.get("family"), str(c.get("table", ""))
            if family in ("ip", "inet") and not (family == "inet" and table.startswith("tvgw")):
                chains.append((family, table, c.get("name")))
        if isinstance(rule, dict):
            rules.setdefault((rule.get("family"), rule.get("table"), rule.get("chain")), []).append(rule)
    return chains, rules


NO_RULESET = "nft printed no ruleset to read (run as root)"  # both policy checks' word for no listing


def _chains(n: int, hook: str) -> str:
    return f"{n} other {hook}-hook chain{'s' if n > 1 else ''} drop{'' if n > 1 else 's'} by default"


def forward_policy_level(doc, tv_if: str) -> tuple[str, str]:
    """FAIL level when a forward-hook chain of another firewall drops by default and no path through it
    accepts the TV's packets; WARN when every such chain accepts them; OK when there is none."""
    if not isinstance(doc, dict) or not doc.get("nftables"):
        return WARN, NO_RULESET
    chains, rules = _drop_chains(doc, "forward")
    if not chains:
        return OK, "no other forward-hook chain drops by default"
    want = Want(tv_if)
    closed = sum(1 for key in chains if not _accepts(rules, key, want))
    n = len(chains)
    if closed:
        return (
            FAIL,
            f"{_chains(n, 'forward')}; {closed} of them accept{'s' if closed == 1 else ''}"
            " nothing from the TV's port",
        )
    return WARN, f"{_chains(n, 'forward')}; {'it accepts' if n == 1 else 'each accepts'} the TV's port"


def input_policy_level(doc, tv_if: str) -> tuple[str, str]:
    """input_policy, forward_policy's twin at the input hook: the TV's DHCP requests (UDP 67) and its
    lookups (UDP and TCP 53) must each be accepted by every input-hook chain that drops by default."""
    if not isinstance(doc, dict) or not doc.get("nftables"):
        return WARN, NO_RULESET
    chains, rules = _drop_chains(doc, "input")
    if not chains:
        return OK, "no other input-hook chain drops by default"
    missing = []
    for want in TV_INPUT:
        w = Want(tv_if, want.proto, want.port, want.label)
        if any(not _accepts(rules, key, w) for key in chains) and w.label not in missing:
            missing.append(w.label)
    n = len(chains)
    if missing:
        return FAIL, f"{_chains(n, 'input')}; the TV's {', '.join(missing)} is not accepted"
    return WARN, f"{_chains(n, 'input')}; {'it accepts' if n == 1 else 'each accepts'} the TV's DHCP and DNS"


def _uptime(read: Callable[[str], str]) -> float | None:
    return _number((read("/proc/uptime").split() or [None])[0])


PRUNE_LAG = 3600  # the hourly ingest prunes the store, so its oldest rows may be up to this much older


def installed_at(
    meta: dict[str, str] | None, conf_t: float | None, now: float, keep_days: int
) -> float | None:
    """When this gateway was installed, as near as its record says: the first check the store recorded
    (tvgw-verify.timer's first run, minutes after the install), or, before the store holds one, when the
    settings file last changed (setup writes it just before the install). A first check as old as the
    store's retention (DB_DAYS) dates nothing: older checks were pruned, so the gateway is older still."""
    first = _number((meta or {}).get(FIRST_CHECK))
    if first is None:
        return conf_t
    return first if now - first < keep_days * 86400 - PRUNE_LAG else None


def depth_checks(
    s: Settings,
    run: Runner,
    read: Callable[[str], str],
    ruleset_doc,
    statvfs: Callable[[str], os.statvfs_result],
    meta: dict[str, str] | None,
    now: float,
    conf_t: float | None = None,
) -> list[Check]:
    """The checks of design 7.2, in their run order; wan_gateway only in direct mode, as policy_rule.
    `conf_t` is the settings file's mtime, for installed_at()."""

    def exists(dev: str) -> bool:
        return read(f"/proc/sys/net/ipv4/conf/{dev}/forwarding") != ""

    since = installed_at(meta, conf_t, now, s.db_days)
    out = [
        Check("disk", *held("disk", *disk_level(s.state_dir, statvfs))),
        Check("clock_synced", *held("clock_synced", *clock_level(run))),
        Check("store_backup", *held("store_backup", *backup_level(meta, now, since))),
        Check("ingest_fresh", *held("ingest_fresh", *ingest_level(meta, now, _uptime(read), since))),
        Check("uplink_ipv4", *held("uplink_ipv4", *uplink_level(run, s.wan_if, exists))),
    ]
    if s.uplink == "direct":
        out.append(Check("wan_gateway", *held("wan_gateway", *wan_gateway_level(s, run, read))))
    out += [
        Check("forward_policy", *held("forward_policy", *forward_policy_level(ruleset_doc, s.tv_if))),
        Check("input_policy", *held("input_policy", *input_policy_level(ruleset_doc, s.tv_if))),
        Check("tv_port_neighbours", *held("tv_port_neighbours", *neighbours_level(run, s.tv_if, s.tv_mac))),
    ]
    return out


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
    r = check(
        s,
        profile,
        run=run_cmd,
        read=read_file,
        mtime=file_mtime,
        sockets=flowlog.event_sockets,
        statvfs=free_space,
        meta=lambda: store_meta(s.db_path, backup_dir=backup.directory(s.state_dir)),
        sleep=pause,
        # (probe) only the recorded 10-minute run sends the probe's packets, and only when it is on
        # (its connection out only when one is due: probe.path_due)
        probe=(lambda: tvprobe.run(s, profile, connect=None))
        if record_to_store and s.tv_probe == "on"
        else None,
    )
    # the verdict first: the 10-minute run's only output is the journal, and a store in trouble must
    # not take the checks down with it
    if as_json:
        print(
            json.dumps(
                {"ok": r.ok, "checks": [c.as_dict() for c in r.checks], "counters": r.counters},
                indent=1,
            )
        )
    else:
        for c in r.checks:
            print(c.line())
    # (plain) the verdict for readers without the store; looked up now, so tests can point it elsewhere
    write_status(r, STATUS)
    ok = r.ok
    if record_to_store:
        smp = gw_sample(s)  # (ledger) before the store is opened: its commands may take seconds
        if smp is not None and r.probe is not None:  # (probe) the series of verdicts beside the samples
            smp.tv_probe = r.probe.compact()
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


# ---- the plain layer: what each check means to someone who is not an engineer -------------------------
# check name -> (what it means, what you notice, the fix), in run order: the words for a reader of setup
# or the doctor, beside a check that did not pass. tests/unit/test_verify_plain.py fails when a check has
# no entry or no group, the way test_deploy_lint.py fails on a KEY_RULES needle tvgw-apply lacks; when a
# fix names a command, a subcommand or a unit this version does not have; and when the plain table in
# docs/reference/verify-checks.md differs from these words. "The filter" is AdGuard Home throughout.
_INSTALLER = "sudo /usr/lib/tvgw/deploy/install.sh (from a source checkout, sudo deploy/install.sh)"
PLAIN: dict[str, tuple[str, str, str]] = {
    "ruleset": (
        "The gateway's firewall is not loaded, or one of its main rules is missing.",
        "Usually the TV has no internet. If the firewall was removed by hand, "
        "the TV may be online unfiltered.",
        "Run sudo systemctl start tvgw, then sudo tvgw-apply, and read any error it prints.",
    ),
    "ruleset_unchanged": (
        "The firewall rules were changed after the gateway last set them.",
        "Nothing on the TV, unless the change lets something through.",
        "Run sudo tvgw-apply. It sets the gateway's own rules again.",
    ),
    "applied_current": (
        "A firewall setting or list was changed, and the gateway has not put the change in force.",
        "Nothing on the TV: the rules from before the change still hold.",
        "Run sudo tvgw-apply, and read any error it prints.",
    ),
    "forwarding": (
        "The gateway is not passing the TV's traffic on to the internet.",
        "The TV has no internet.",
        "Run sudo systemctl start tvgw, then sudo tvgw-apply.",
    ),
    "ipv6_off": (
        "IPv6, the newer kind of internet address, is switched on for the TV's port. "
        "The gateway handles only the older kind, so IPv6 must stay off there.",
        "Nothing on the TV. One of the two walls against IPv6 is down.",
        "Run sudo tvgw-apply.",
    ),
    "ipv6_guard": (
        "The second wall against IPv6 on the TV's port is missing. "
        "The first, IPv6 switched off, still holds.",
        "Nothing on the TV.",
        "Check that the TV's cable is plugged in and the TV is on, then run sudo tvgw-apply. "
        "It cannot add this wall while the TV's port is down.",
    ),
    "tv_route": (
        "The TV's traffic has no way out to the internet, or would leave by the wrong connection.",
        "The TV has no internet.",
        "Check that the gateway itself is online, then run sudo tvgw-apply. "
        "It also runs on its own when the gateway's connection comes back.",
    ),
    "gw_reply_route": (
        "The gateway's own answers to the TV, such as the answers to its lookups, "
        "would leave by the wrong connection and never reach it.",
        "The TV gets an address but no answers to its lookups, so it has no internet.",
        "Run sudo tvgw-apply. If it says the TV's port is not up yet, wait a minute: "
        "the gateway puts this right itself once the port is up. "
        f"If the check still fails, run the installer again: {_INSTALLER}.",
    ),
    "policy_rule": (
        "The rule that sends the TV's traffic out by the gateway's direct connection is missing.",
        "The TV's traffic may leave by another route, such as a VPN on the gateway.",
        "Check that the gateway itself is online, then run sudo tvgw-apply.",
    ),
    "vpn_dnat_idle": (
        "Some of the TV's lookups reached the VPN program's own redirect instead of the filter.",
        "Nothing on the TV. Those lookups were not filtered.",
        "Run sudo tvgw-apply. The check passes again once the VPN program reloads its rules, "
        "which starts its count from zero.",
    ),
    "doh4_loaded": (
        "The list of encrypted lookup services the TV may not use is empty or too short.",
        "Nothing on the TV, but it could look names up around the filter.",
        "Run sudo systemctl start tvgw-doh-update, then check again with sudo tvgw verify. "
        "If it still fails, see why with journalctl -u tvgw-doh-update -n 20.",
    ),
    "doh4_fresh": (
        "That list of encrypted lookup services has not been updated for over a week, or is missing.",
        "Nothing on the TV. Services added to the list since then are not blocked.",
        "Run sudo systemctl start tvgw-doh-update. "
        "If it fails, see why with journalctl -u tvgw-doh-update -n 20.",
    ),
    "resolver_rewrite": (
        "The filter does not send the TV's requests for its maker's file service "
        "to the gateway's web filter.",
        "App installs and updates may fail, or those requests go out unchecked.",
        "Run sudo tvgw adguard apply, then check again with sudo tvgw verify.",
    ),
    "resolver_must_allow": (
        "A name the TV needs, such as its clock or its app store, is blocked or gets no answer.",
        "The TV may show the wrong time or certificate errors, apps may not load, "
        "or it may say it has no internet.",
        "Right after setup or a restart, wait 5 minutes and check again with sudo tvgw verify. "
        "If it still fails, check that the gateway is online, then run sudo tvgw adguard apply.",
    ),
    "services": (
        "One of the gateway's programs or scheduled jobs is not running. "
        "Its name is on this check's line in the output of sudo tvgw verify.",
        "It depends on which. If tvgw itself or the filter stopped, the TV has no internet. "
        "If the program that gives the TV its address stopped, the TV loses the internet "
        "the next time it asks for an address. If a scheduled job stopped, the brief stops updating.",
        "Start it with sudo systemctl start <name>, or for a name ending in .timer, "
        "sudo systemctl enable --now <name>. Then see why it stopped with journalctl -u <name> -n 20.",
    ),
    "tv_paths": (
        "The TV reports a second connection, such as Wi-Fi or Wi-Fi Direct, that goes around the gateway. "
        "As a warning: the TV no longer accepts the gateway's key, "
        "so nothing has been read from it since the date shown.",
        "Nothing on the TV. Whatever it sends that way is neither filtered nor recorded.",
        "On the TV, switch Wi-Fi off, forget every saved network, "
        "and switch off Wi-Fi Direct and any tethering. "
        "Then see what the TV reports now with sudo tvgw tvcheck. "
        "This check clears with the next hourly reading. "
        "For the warning, with the TV on, accept the prompt on the TV after running sudo tvgw tv pair.",
    ),
    "adguard_version": (
        "The filter (AdGuard Home) is missing, older than the release with the 2026 security fixes, "
        "or does not say which version it is.",
        "If it is missing, the TV gets no answers to its lookups. "
        "If it is old, it has a known security hole.",
        "Install or update it with the command on this check's line in the output of sudo tvgw verify, "
        "then check again with sudo tvgw verify. "
        "If the line names no command, ask for help on the project's issue tracker.",
    ),
    "list_sentinels": (
        "The filter has not loaded one of its blocklists, or a list arrived empty.",
        "Nothing on the TV. The trackers on that list are not refused.",
        "Right after setup, wait 5 minutes: the lists may still be downloading. "
        "Then check again with sudo tvgw verify. "
        "If it still fails, see why a download failed with journalctl -u AdGuardHome -n 50.",
    ),
    "adguard_pinned": (
        "The filter (AdGuard Home) could replace itself with a new version that tvgw has not checked.",
        "Nothing on the TV.",
        "Run sudo tvgw adguard service.",
    ),
    "dnsgate": (
        "The gateway's count of connections to addresses the TV never looked up is missing. "
        "A warning instead says its list is more than half full.",
        "Nothing on the TV. Without the count, the brief cannot show those connections.",
        "Run sudo tvgw-apply. A warning alone needs no fix: the TV, or the program that fills the list, "
        "is doing something new.",
    ),
    "dnsgate_inpath": (
        "The part that holds each of the TV's lookup answers until its addresses are on the gateway's "
        "list is switched on in the settings but is not working.",
        "Nothing on the TV: its lookups are answered as before. "
        "The gateway's second count of connections to addresses the TV never looked up is wrong meanwhile.",
        "Run sudo tvgw-apply, then sudo systemctl restart tvgw-dnsgate-inpath. "
        "If the warning stays, see why with journalctl -u tvgw-dnsgate-inpath -n 20.",
    ),
    "attention": (
        "The gateway's count of what the TV reaches while its screen saver is on, or an input is in front, "
        "is switched on in the settings but is not working.",
        "Nothing on the TV: nothing is stopped either way. "
        "The brief's Attention section is missing or short meanwhile.",
        "Run sudo tvgw-apply, then sudo systemctl restart tvgw-attention. "
        "If the warning stays, see why with journalctl -u tvgw-attention -n 20.",
    ),
    "capture": (
        "The recording of the TV's traffic is set up wrong: two recorders run at once, "
        "or the one in use receives nothing.",
        "Nothing on the TV. The brief counts some connections twice, or the recording stays empty.",
        "Run sudo systemctl restart tvgw-pcap, then sudo tvgw-apply.",
    ),
    "guard_present": (
        "The gateway's second firewall, which keeps the TV away from this computer's own services, "
        "is missing or changed.",
        "Nothing on the TV. If the main firewall also goes, "
        "the TV could reach this computer's other services.",
        "Run sudo systemctl reload-or-restart tvgw-guard.",
    ),
    "guard_quiet": (
        "The second firewall stopped traffic from the TV that the main firewall let through: "
        "the two disagree.",
        "Nothing on the TV: the second firewall held.",
        "Run sudo tvgw-apply. If the warning comes back, ask for help on the project's issue tracker.",
    ),
    "cotenants_denied": (
        "Another program on this computer is kept from the TV only by the firewall, not also by a setting "
        "of its own.",
        "Nothing on the TV.",
        f"Run the installer again, which adds that setting: {_INSTALLER}.",
    ),
    "dnsmasq_caps": (
        "The program that gives the TV its address kept a permission it does not need, "
        "one that could change the firewall.",
        "Nothing on the TV.",
        f"Run the installer again: {_INSTALLER}. "
        "If the warning stays, ask for help on the project's issue tracker.",
    ),
    "flowlog_events": (
        "The gateway's log of the TV's connections is not recording, "
        "or it hears every connection on this computer instead of the TV's alone.",
        "Nothing on the TV. The brief misses connections, "
        "or the log can lose some when this computer is busy.",
        "Run sudo tvgw-apply, then sudo systemctl start tvgw-flowlog. "
        "Check again with sudo tvgw verify: this check needs root.",
    ),
    # (depth) the gateway's blind spots, each a warning at most while it is new (FAIL_AFTER)
    "disk": (
        "The disk where the gateway keeps its record is nearly full, or it can no longer be written to.",
        "Nothing on the TV at first. When the disk is full, the record and the daily brief stop.",
        "Run sudo tvgw doctor, which can delete old recordings and old copies of the record. "
        "If the disk cannot be written to at all, the memory card or disk may be failing.",
    ),
    "clock_synced": (
        "This computer's clock is not set from the internet, so it may be wrong.",
        "The TV may lose its lookups: with a wrong clock the gateway cannot check its secure connections. "
        "The brief's times may be off.",
        "Check that the gateway is online: the clock sets itself within a few minutes once it is. "
        "Then check again with sudo tvgw verify.",
    ),
    "store_backup": (
        "The daily copy of the gateway's record is missing, old, or failed its check.",
        "Nothing on the TV. Without a recent copy, a failing disk would take the record with it.",
        "Run sudo tvgw backup, and read what it prints. If it says the copy did not pass its check, "
        "the record itself may be damaged: ask for help on the project's issue tracker.",
    ),
    "ingest_fresh": (
        "The gateway has not added the TV's recent traffic to its record for a while.",
        "Nothing on the TV. The daily brief is missing the latest hours.",
        "Run sudo tvgw ingest, and read any error it prints. "
        "Then make sure the hourly job runs with sudo systemctl enable --now tvgw-analyze.timer.",
    ),
    "uplink_ipv4": (
        "This computer's connection to your router has no address of the older kind (IPv4), "
        "the only kind the gateway passes on.",
        "The TV has no internet.",
        "Check that the gateway is connected to your router, by its cable or its Wi-Fi. "
        "If your router gives out only the newer kind of address, the gateway cannot work with it yet.",
    ),
    "wan_gateway": (
        "The gateway's note of your router's address does not match the router this computer uses, "
        "or the TV's way out to the router is missing.",
        "The TV may lose the internet, at once or the next time the gateway sets its rules.",
        "Run sudo tvgw-apply. If the warning stays, your router's address changed, as it can with a new "
        "router. Run sudo tvgw setup. When it asks for the home router's address, "
        "type the address of your router's settings page.",
    ),
    "forward_policy": (
        "Another firewall on this computer, such as ufw or Docker's, "
        "blocks the traffic this computer passes on.",
        "If it does not let the TV's traffic through, the TV has no internet. "
        "A warning means it lets the TV's traffic through.",
        "Run sudo tvgw doctor, which says what to change in that firewall. "
        "The gateway does not change another firewall itself.",
    ),
    "input_policy": (
        "Another firewall on this computer, such as ufw, blocks requests to this computer.",
        "If it blocks the TV's requests for its address or its lookups, the TV has no internet. "
        "A warning means it lets them through.",
        "Run sudo tvgw doctor, which says what to open in that firewall. "
        "The gateway does not change another firewall itself.",
    ),
    "tv_port_neighbours": (
        "A device other than the TV answered on the gateway's port for the TV.",
        "Nothing on the TV. If a cable there leads to your home network, "
        "phones and laptops may get addresses from the gateway and lose their internet.",
        "Make sure only the TV's cable is in the gateway's port for the TV. "
        "If you replaced the TV, run sudo tvgw setup.",
    ),
    # (probe) the test from the TV's position; present only in the recorded run of a gateway with TV_PROBE=on
    "tv_probe": (
        "The gateway's own test did not pass. A test client beside the TV's port, which is not the TV, "
        "found the gateway's path for the TV broken at one step, or was not refused where it must be. "
        "As a warning that says unknown, the test could not tell, for example while your internet was down.",
        "If the test failed, the TV may have no internet, or one of the walls around it is open.",
        "Run sudo tvgw probe. It says which step fails. Then run sudo tvgw verify, "
        "and follow the fix of any check that fails there. "
        "If your home internet was down, wait until it is back, then check again with sudo tvgw probe.",
    ),
}
# plain sentence -> the checks it stands for, in the order setup prints them (design 4.4). A check in
# no group would vanish from setup's summary, so the test above fails on one
GROUPS: dict[str, tuple[str, ...]] = {
    "the TV's cable leads to the internet only through this computer": (
        "ruleset",
        "ruleset_unchanged",
        "applied_current",
        "forwarding",
        "ipv6_off",
        "ipv6_guard",
        "tv_route",
        "gw_reply_route",
        "policy_rule",
        "guard_present",
        "guard_quiet",
        "cotenants_denied",
        "dnsmasq_caps",
        "forward_policy",  # (depth)
        "input_policy",
        "tv_port_neighbours",
        "tv_probe",  # (probe)
    ),
    "the TV's lookups go through the filter": (
        "vpn_dnat_idle",
        "resolver_rewrite",
        "resolver_must_allow",
        "list_sentinels",
        "doh4_loaded",
        "doh4_fresh",
        "adguard_version",
        "adguard_pinned",
        "dnsgate",
        "dnsgate_inpath",  # (inpath)
    ),
    "recording what the TV does": ("capture", "flowlog_events", "attention"),  # (attention)
    "every service is running": (
        "services",
        "disk",  # (depth)
        "clock_synced",
        "store_backup",
        "ingest_fresh",
        "uplink_ipv4",
        "wan_gateway",
    ),
    "the TV has no second way out": ("tv_paths",),
}
UNGROUPED = "other checks"  # by_group()'s heading for a check GROUPS does not name
# the checks that can fail for a few minutes after an install or a restart and then pass on their own:
# the blocklists and the DoH list still downloading, the services and the capture still starting, the
# flow log not yet listening. They are worth waiting on before a FAIL is reported (design 4.4); a FAIL of
# any other check is real at once
SETTLING = frozenset(
    {
        "list_sentinels",
        "doh4_loaded",
        "doh4_fresh",
        "services",
        "capture",
        "flowlog_events",
        "resolver_must_allow",
    }
)


def by_group(r: Result) -> list[tuple[str, list[Check]]]:
    """The run's checks under GROUPS' sentences, in GROUPS' order and each group in run order; a group
    with no check in the run is left out. A check GROUPS does not name comes last under UNGROUPED, so a
    summary never hides it."""
    group = {name: sentence for sentence, names in GROUPS.items() for name in names}
    out: dict[str, list[Check]] = {}
    for sentence in (*GROUPS, UNGROUPED):
        members = [c for c in r.checks if group.get(c.name, UNGROUPED) == sentence]
        if members:
            out[sentence] = members
    return list(out.items())


def settling_failures(r: Result) -> list[str]:
    """The names of the run's failed checks that SETTLING says may still pass on their own, in run order."""
    return [c.name for c in r.checks if not c.ok and c.name in SETTLING]


# ---- the status file: the last run's verdict for readers without the store --------------------------
# One line, `ok <epoch> <checks run>` or `fail <epoch> <failed check names>`, mode 644. Check names only,
# never a detail: a detail can carry an interface, an address or a host name, and this file is readable
# by every account on the gateway. A WARN counts as passed, as in the exit status
STATUS = "/run/tvgw/status.txt"


def status_line(r: Result) -> str:
    failed = [c.name for c in r.checks if not c.ok]
    if failed:
        return f"fail {int(r.t)} {' '.join(failed)}\n"
    return f"ok {int(r.t)} {len(r.checks)}\n"


def write_status(r: Result, path: str) -> None:
    """Replace `path` with the run's status line, whole (guard.write_atomic: a temporary file beside it,
    fsynced and renamed over it). Never raises: a status that cannot be written must not change verify's
    verdict. Root says why on stderr; any other account cannot replace root's file and says nothing, so
    an unprivileged `tvgw verify` leaves the last root run's status in place."""
    try:
        guard.write_atomic(path, status_line(r), 0o644)
    except OSError as e:
        if os.geteuid() == 0:
            print(f"tvgw verify: could not write {path}: {e}", file=sys.stderr)
