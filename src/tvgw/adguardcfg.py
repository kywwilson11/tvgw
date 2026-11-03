"""AdGuard Home as configuration: lists, rules and settings the gateway needs, applied to AdGuardHome.yaml.

The profile says which blocklists and custom rules; the gateway settings say which upstreams and
which TV. `plan()` merges that into AdGuard's current config (only the keys we own change),
`changes()` describes the difference, `apply()` validates it, writes it with the service stopped and
restarts, and puts the backup back if anything goes wrong from the stop onwards.
AdGuard rewrites its own YAML, so we go through PyYAML rather than editing text.

(lists) Three disciplines sit around that: `apply()` refuses a YAML above `SCHEMA_CEILING`, the newest
schema tvgw has been tested with; every restart of AdGuard for a change first asks whether the
upstreams answer at all (`restart_guard()`), because a restart empties the cache the TV lives on during
an upstream outage, and raises `Deferred` instead; and the binary changes only through `upgrade()`,
which runs the new binary's own `--check-config` on a copy of the live YAML before it swaps anything.
"""

from __future__ import annotations

import contextlib
import copy
import fcntl
import itertools
import os
import re
import secrets
import shutil
import signal
import subprocess
import sys
import tempfile
import time
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path

import yaml

from tvgw import dnsmsg, dnsq
from tvgw.config import Settings
from tvgw.profile import Profile

FILTER_ID_BASE = 1792975975  # AdGuard's own ids for user-added lists start in this range
# (lists) the newest AdGuardHome.yaml schema this release has been tested with: v0.107.79 writes 34
# (configmigrate.LastSchemaVersion at that tag). A newer one comes with a binary whose keys and
# validation the plan has never met, so apply and upgrade refuse it until tvgw is updated
SCHEMA_CEILING = 34
# (lists) AdGuard re-downloads each list this many hours after its last attempt. tvgw owns the key
# because 0 (accepted since v0.107.78) freezes every list silently; 24 is AdGuard's own default
FILTERS_UPDATE_HOURS = 24
# (lists) the optimistic cache's two bounds (schema 32, v0.107.71): an expired answer is served with
# this TTL while it is refreshed, for at most this long past its expiry. AdGuard's defaults, pinned so a
# UI edit cannot shorten how long the TV rides out an upstream outage (decision 9)
OPTIMISTIC_TTL = "30s"
OPTIMISTIC_MAX_AGE = "12h"
SCHEMA_PATH = "docs/adguard.md#the-schema-ceiling"
# (adguard) with ADGUARD_LISTEN=gateway the plan owns where AdGuard answers DNS: GW_IP for the TV and
# loopback for the gateway's own lookups and tvgw's probes, on port 53. Never the wildcard, which
# collides with systemd-resolved's stub on 127.0.0.53 and answers the home network (design decision 52)
LISTEN_LOOPBACK = "127.0.0.1"
DNS_PORT = 53


class Deferred(RuntimeError):
    """(lists) A restart of AdGuard was not attempted because its upstreams are down: the message starts
    `deferred: upstream down`. Callers report it and do not retry; nothing was changed. A subclass of
    RuntimeError, so every caller that handles a refused apply handles this one too."""


@dataclass(frozen=True)
class Desired:
    filters: tuple[tuple[str, str], ...]  # (name, url), all enabled
    user_rules: tuple[str, ...]
    upstreams: tuple[str, ...]
    bootstrap: tuple[str, ...]
    tv_ip: str
    tv_mac: str
    tv_name: str
    http_address: str = "127.0.0.1:3000"
    blocked_response_ttl: int = 60
    log_interval: str = "90d"
    stats_interval: str = "90d"  # (lists) STATS_DAYS; it was log_interval before, with the same 90 days
    fallback: tuple[str, ...] = ()  # (lists) DNS_FALLBACK: a second operator, by address
    # (lists) the name the restart guard and the readiness wait resolve: the profile's first must-allow
    probe_name: str = "example.com"
    # (lists) a name the profile's own rules block (`||name^`): AdGuard answers it 0.0.0.0 from its
    # filter at once, never asking an upstream, so it tells a live AdGuard from a hung one
    local_name: str | None = None
    # querylog.size_memory: lookups AdGuard holds in memory before it appends them to the log file the
    # ingest reads. Its default of 1000 kept the file two hours behind the TV while one app ran (a few
    # dozen lookups an hour); ten is a write every few minutes at that pace and at once under app churn
    log_buffer: int = 10
    # (adguard) dns.bind_hosts under ADGUARD_LISTEN=gateway, with dns.port 53; empty (keep) leaves both
    # as AdGuard has them
    dns_bind_hosts: tuple[str, ...] = ()


def _csv(text: str) -> tuple[str, ...]:
    """Comma-separated items, trimmed, empties dropped: `a, b` used to yield ` b`, which AdGuard rejects."""
    return tuple(x for x in (item.strip() for item in text.split(",")) if x)


def _with_auto_rules(rules: list[str], profile: Profile, s: Settings) -> list[str]:
    """The profile's rules plus the machine's (design decision 20), each of the latter linted beside
    the profile first: a rule that would cover a must-allow host never reaches AdGuard, whatever wrote it."""
    from tvgw import autoblock  # here, not at module level: autoblock imports queries

    ok, refused = autoblock.admissible(s.auto_rules, profile)
    for line in refused:
        print(f"tvgw adguard: machine rule dropped: {line}", file=sys.stderr)
    return rules + [r for r in ok if r not in rules]


def desired(profile: Profile, s: Settings) -> Desired:
    upstreams = _csv(s.dns_upstreams)
    if not upstreams:
        raise ValueError("DNS_UPSTREAMS is empty")
    return Desired(
        filters=tuple(profile.adguard_filters),
        user_rules=tuple(_with_auto_rules(profile.adguard_rules(s.gw_ip, s.tv_ip), profile, s)),
        upstreams=upstreams,
        bootstrap=_csv(s.dns_bootstrap),
        tv_ip=s.tv_ip,
        tv_mac=s.tv_mac,
        tv_name=s.tv_name,
        log_interval=f"{s.querylog_days}d",  # (lists)
        stats_interval=f"{s.stats_days}d",
        fallback=_csv(s.dns_fallback),
        probe_name=next(iter(profile.must_allow), "example.com"),
        local_name=_locally_blocked(profile.adguard_rules(s.gw_ip, s.tv_ip)),
        dns_bind_hosts=listen_hosts(s),
    )


def listen_hosts(s: Settings) -> tuple[str, ...]:
    """(adguard) The DNS listen addresses the plan owns: GW_IP and loopback with ADGUARD_LISTEN=gateway;
    none with keep, the default, so a gateway whose settings predate the key plans what it did."""
    if s.adguard_listen != "gateway":
        return ()
    return tuple(dict.fromkeys((s.gw_ip, LISTEN_LOOPBACK)))


def _locally_blocked(rules: list[str]) -> str | None:
    """(lists) The name the first plain block rule (`||name^`, no modifier) of the profile blocks."""
    for rule in rules:
        m = re.fullmatch(r"\|\|([a-z0-9.-]+)\^", rule.strip())
        if m:
            return m.group(1)
    return None


def _ensure(d: dict, key: str) -> dict:
    v = d.get(key)
    if not isinstance(v, dict):
        v = d[key] = {}
    return v


def _client_id(value: object) -> str:
    return str(value).strip().lower()


def plan(current: dict, d: Desired) -> dict:
    """The config AdGuard should have: `current` with the keys we own set. Pure; returns a copy.

    Owned means every key that could unfilter the TV, because `changes()` reports drift only on
    what plan() sets: a key it left alone would keep its UI edit through every deploy.
    """
    cfg = copy.deepcopy(current) if current else {}
    _ensure(cfg, "http")["address"] = d.http_address
    dns = _ensure(cfg, "dns")
    if d.dns_bind_hosts:  # (adguard) ADGUARD_LISTEN=gateway; with keep both keys stay as they are
        dns["bind_hosts"] = list(d.dns_bind_hosts)
        dns["port"] = DNS_PORT
    dns["upstream_dns"] = list(d.upstreams)
    dns["upstream_dns_file"] = ""  # a file here replaces the list above
    dns["bootstrap_dns"] = list(d.bootstrap)
    # (lists) the cache is what the TV lives on while the upstreams are away: on, optimistic, and with
    # AdGuard's own bounds pinned (schema 30 added cache_enabled, 32 the two bounds)
    dns["cache_enabled"] = True
    dns["cache_optimistic"] = True
    dns["cache_optimistic_answer_ttl"] = OPTIMISTIC_TTL
    dns["cache_optimistic_max_age"] = OPTIMISTIC_MAX_AGE
    dns["anonymize_client_ip"] = False
    # the TV sweeps reverse lookups across remembered LANs at power-on; answer those here, never
    # forward them (they would tell the upstream resolver what the TV is probing)
    dns["use_private_ptr_resolvers"] = False
    dns["local_ptr_upstreams"] = []
    # the TV segment is v4-only with IPv6 dropped at the wire, so AAAA answers are withheld here
    # instead of fetched: half the upstream queries disappear and no v6 hints reach the TV. The
    # resolver-upgrade probe (DDR, _dns.resolver.arpa) is answered locally, never forwarded
    dns["aaaa_disabled"] = True
    dns["handle_ddr"] = True
    # every client may ask (a list naming only some refuses the TV), and nothing is asked in plain
    # DNS of a resolver nobody configured when the DoH upstreams fail
    dns["allowed_clients"] = []
    dns["disallowed_clients"] = []
    # (lists) or the one second operator DNS_FALLBACK names, by address: asked only when the upstreams
    # return an error, and an owner decision (docs/adguard.md#a-fallback-resolver)
    dns["fallback_dns"] = list(d.fallback)
    for section, interval in (("querylog", d.log_interval), ("statistics", d.stats_interval)):
        sec = _ensure(cfg, section)
        sec["enabled"] = True
        sec["interval"] = interval
        # (lists) schema 33: with this on, the names in `ignored` vanish from the log, which is evidence
        sec["ignored_enabled"] = False
    cfg["querylog"]["file_enabled"] = True
    cfg["querylog"]["size_memory"] = d.log_buffer
    filt = _ensure(cfg, "filtering")
    filt["filtering_enabled"] = True
    filt["protection_enabled"] = True
    filt["protection_disabled_until"] = None  # the UI's "pause protection" (under filtering since schema 23)
    # 0.0.0.0 answers are what dnsmsg.is_blocked_answer, verify and the hardware suite read as blocked
    filt["blocking_mode"] = "default"
    filt["blocked_response_ttl"] = d.blocked_response_ttl
    filt["rewrites"] = []  # rewrites are rule-based ($dnsrewrite) so they live with the rules
    filt["rewrites_enabled"] = True  # (lists) schema 31's switch for the list above, owned, not the UI's
    filt["filters_update_interval"] = FILTERS_UPDATE_HOURS  # (lists) 0 would freeze every list
    # blocklists: keep whatever else is there, make sure ours exist and are enabled
    filters = cfg.get("filters") if isinstance(cfg.get("filters"), list) else []
    by_url = {f.get("url"): f for f in filters if isinstance(f, dict)}
    next_id = max([FILTER_ID_BASE - 1, *(int(f.get("id") or 0) for f in filters if isinstance(f, dict))]) + 1
    for name, url in d.filters:
        if url not in by_url:
            by_url[url] = {"enabled": True, "url": url, "name": name, "id": next_id}
            filters.append(by_url[url])
            next_id += 1
        by_url[url]["enabled"] = True
        by_url[url]["name"] = name
    cfg["filters"] = filters
    # AdGuard checks its DNS allowlists before any rule, so one entry there unfilters every name it
    # lists, past the URL-filter rewrite and the HTTPS/SVCB strip too; a profile has none
    cfg["whitelist_filters"] = []
    cfg["user_rules"] = list(d.user_rules)
    # the TV as a named client, so the query log and per-client settings attribute to it. It may have
    # changed address or name since the last apply, so every entry that carries our name or one of
    # our ids is a match (ids compared case-insensitively: AdGuard upper-cases nothing, people do);
    # the first becomes ours and the others give our ids up, since AdGuard refuses to start on a
    # duplicate id and on a client with no ids at all
    clients = _ensure(cfg, "clients")
    persistent = clients.get("persistent") if isinstance(clients.get("persistent"), list) else []
    ids = [x for x in (d.tv_ip, d.tv_mac) if x]
    ours = {_client_id(i) for i in ids}
    matches = [
        c
        for c in persistent
        if isinstance(c, dict)
        and (c.get("name") == d.tv_name or ours & {_client_id(i) for i in c.get("ids") or []})
    ]
    if matches:
        mine = matches[0]
    else:
        mine = {"name": d.tv_name, "tags": ["device_tv"]}
        persistent.append(mine)
    emptied = []
    for other in matches[1:]:
        other["ids"] = [i for i in other.get("ids") or [] if _client_id(i) not in ours]
        if not other["ids"]:
            emptied.append(id(other))
    mine["ids"] = ids
    mine["use_global_settings"] = True
    mine["filtering_enabled"] = True
    mine["use_global_blocked_services"] = True
    mine["upstreams"] = []  # per-client upstreams would bypass ours
    mine["ignore_querylog"] = False
    mine["ignore_statistics"] = False
    clients["persistent"] = [c for c in persistent if id(c) not in emptied]
    return cfg


def _flatten(d, prefix=""):
    out = {}
    if isinstance(d, dict):
        for k, v in d.items():
            out.update(_flatten(v, f"{prefix}{k}."))
    elif isinstance(d, list) and d and all(isinstance(x, dict) for x in d):
        for i, v in enumerate(d):
            out.update(_flatten(v, f"{prefix}{i}."))
    else:
        out[prefix.rstrip(".")] = d
    return out


MANAGED_PREFIXES = (
    "http.address",
    "dns.",
    "querylog.",
    "statistics.",
    "filtering.",
    "filters.",
    "whitelist_filters",
    "user_rules",
    "clients.",
)


def changes(current: dict, planned: dict) -> list[str]:
    """Human-readable differences on the keys we own ('path: old -> new')."""
    a, b = _flatten(current or {}), _flatten(planned)
    out = []
    for key in sorted(set(a) | set(b)):
        if not key.startswith(MANAGED_PREFIXES):
            continue
        if a.get(key, "<unset>") != b.get(key, "<unset>"):
            out.append(f"{key}: {a.get(key, '<unset>')!r} -> {b.get(key, '<unset>')!r}")
    return out


# PyYAML speaks YAML 1.1; AdGuard Home (yaml.v3) writes and reads 1.2. In 1.1 an all-digit MAC such
# as 10:20:30:40:50:59 is a sexagesimal integer, `on` is a boolean and an RFC 3339 stamp is a
# datetime; in 1.2 `1e3` and `0o17` are numbers, which 1.1 would write unquoted. The 1.2 scalar
# rules, as (tag, pattern, first characters):
_TAG = "tag:yaml.org,2002:"
_RESOLVERS_12 = (
    (_TAG + "bool", re.compile(r"^(?:true|True|TRUE|false|False|FALSE)$"), list("tTfF")),
    (_TAG + "int", re.compile(r"^(?:[-+]?[0-9]+|0o[0-7]+|0x[0-9a-fA-F]+)$"), list("-+0123456789")),
    (
        _TAG + "float",
        re.compile(
            r"^(?:[-+]?(?:\.[0-9]+|[0-9]+(?:\.[0-9]*)?)(?:[eE][-+]?[0-9]+)?|[-+]?\.(?:inf|Inf|INF)|\.(?:nan|NaN|NAN))$"
        ),
        list("-+.0123456789"),
    ),
)


def _without(resolvers: dict, *kinds: str) -> dict:
    """A copy of a SafeLoader/SafeDumper `yaml_implicit_resolvers` table without those tags."""
    tags = {_TAG + k for k in kinds}
    return {first: [(tag, rx) for tag, rx in rules if tag not in tags] for first, rules in resolvers.items()}


class Yaml12Loader(yaml.SafeLoader):
    """Resolves scalars the 1.2 way: the MAC and `on` are strings, and a timestamp stays text, so it
    is written back as it was (`protection_disabled_until` holds one while protection is paused)."""


class Yaml12Dumper(yaml.SafeDumper):
    """Keeps the 1.1 number and boolean rules, so `on` and an all-digit MAC are still quoted, and adds
    the 1.2 ones, so `1e3` and `0o17` are quoted too; without the timestamp rule an RFC 3339 string is
    written plain, which is how yaml.v3 decodes a *time.Time (a quoted one is an error there)."""


Yaml12Loader.yaml_implicit_resolvers = _without(
    yaml.SafeLoader.yaml_implicit_resolvers, "int", "bool", "float", "timestamp", "value", "merge"
)
Yaml12Dumper.yaml_implicit_resolvers = _without(
    yaml.SafeDumper.yaml_implicit_resolvers, "timestamp", "value", "merge"
)
for _cls in (Yaml12Loader, Yaml12Dumper):
    for _tag, _rx, _first in _RESOLVERS_12:
        _cls.add_implicit_resolver(_tag, _rx, _first)


def load_yaml(path: str) -> dict:
    with open(path, encoding="utf-8") as fh:
        return yaml.load(fh, Loader=Yaml12Loader) or {}


def dump_yaml(cfg: dict) -> str:
    return yaml.dump(cfg, Dumper=Yaml12Dumper, sort_keys=False, default_flow_style=False, allow_unicode=True)


def systemctl(*args: str) -> None:
    subprocess.run(["systemctl", *args], check=True, timeout=120)


def dns_ready(
    server: str = "127.0.0.1", name: str = "example.com", timeout: float = 30.0, port: int = 53
) -> bool:
    """True once the resolver resolves `name` over plain UDP: NOERROR or NXDOMAIN, which only a working
    upstream path produces. SERVFAIL or REFUSED is a resolver that is up and cannot answer (unreachable
    DoH upstreams, a broken config), so it counts as not ready until the deadline. AdGuard needs
    seconds to load big lists."""
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        reply = dnsq.query(name, server, timeout=1.0, port=port)
        if reply is not None and dnsmsg.rcode(reply) in (0, 3):
            return True
        time.sleep(0.5)
    return False


# ---- (lists) the schema ceiling and the restart guard ----------------------------------------------


def schema_version(cfg: dict) -> int | None:
    """The YAML's `schema_version` as a number, or None when it has none or it is not a number."""
    v = cfg.get("schema_version") if isinstance(cfg, dict) else None
    if isinstance(v, bool) or not isinstance(v, int | str):
        return None
    try:
        return int(v)
    except ValueError:
        return None


def check_schema(cfg: dict, path: str) -> None:
    """Refuse, with the way forward, a YAML newer than SCHEMA_CEILING. A newer schema means a newer
    AdGuard Home than tvgw was tested with (one that updated itself, or a 1.x install); the plan's keys
    may have moved under it, so writing it could undo a migration or start AdGuard on a config it no
    longer reads. Nothing is changed; the resolver keeps running as it is."""
    n = schema_version(cfg)
    if n is not None and n > SCHEMA_CEILING:
        raise RuntimeError(
            f"{path} is at schema_version {n}, above {SCHEMA_CEILING}, the newest this tvgw release has been"
            " tested with; nothing changed. Update tvgw to a release that knows it, or go back by hand:"
            " stop AdGuardHome, copy the AdGuardHome.bak-* binary and the AdGuardHome.yaml.bak-* of the same"
            f" stamp into place, start it ({SCHEMA_PATH}); tvgw adguard upgrade refuses this state too"
        )


# AdGuard's dns.upstream_timeout when the YAML has none (dnsforward.DefaultTimeout at v0.107.79)
UPSTREAM_TIMEOUT = 10.0
_DURATION = re.compile(r"(\d+(?:\.\d+)?)(ns|us|µs|ms|s|m|h|d)")
_UNIT_SECONDS = {
    "ns": 1e-9,
    "us": 1e-6,
    "µs": 1e-6,
    "ms": 1e-3,
    "s": 1.0,
    "m": 60.0,
    "h": 3600.0,
    "d": 86400.0,
}


def duration_seconds(value: object) -> float | None:
    """A Go/golibs duration (`10s`, `1m30s`, `1.5s`, `90d`) in seconds, or None when it is not one."""
    text = value.strip() if isinstance(value, str) else ""
    if not text or _DURATION.sub("", text) != "":
        return None
    return sum(float(n) * _UNIT_SECONDS[u] for n, u in _DURATION.findall(text))


def upstream_wait(cfg: dict) -> float:
    """(lists) How long the guard's first probe waits: AdGuard's own `dns.upstream_timeout` plus 2 s, so
    the SERVFAIL AdGuard sends when an upstream drops packets (it gives up only after that timeout)
    arrives while the probe still listens. Capped at 32 s; past that the local-name check decides."""
    dns = cfg.get("dns") if isinstance(cfg, dict) else None
    secs = duration_seconds(dns.get("upstream_timeout")) if isinstance(dns, dict) else None
    return min((secs if secs and secs > 0 else UPSTREAM_TIMEOUT) + 2.0, 32.0)


def upstream_state(
    name: str,
    server: str = "127.0.0.1",
    tries: int = 3,
    port: int = 53,
    wait: float | None = None,
    local: str | None = None,
) -> str:
    """'up', 'down' or 'unknown': can the resolver reach its upstreams right now? It asks for a fresh,
    random label under `name` (a must-allow host), so neither the cache nor the optimistic cache can
    answer for the upstreams: NOERROR or NXDOMAIN came from them. SERVFAIL on every try, with nothing
    better, is 'down'.

    An upstream that drops packets (a tunnel down behind a drop-rule kill switch, a hung DoH connection)
    makes AdGuard wait its own upstream timeout before it SERVFAILs, so the first try listens `wait`
    seconds (default `upstream_wait({})`, 12 s) and the others 1.5 s. When no try got any answer, `local`
    (a name AdGuard's own rules block) tells the two silences apart: AdGuard answering it at once while
    the probes go unanswered is 'down'; AdGuard silent on both is 'unknown': AdGuard itself may be what is
    broken, and an apply may be the cure, so that is not a reason to hold one back. The made-up label
    carries nothing about the household; the upstream and the zone's own servers see a lookup that
    cannot exist."""
    first = upstream_wait({}) if wait is None else wait
    servfail = answered = False
    for i in range(max(1, tries)):
        probe = f"tvgw-probe-{secrets.token_hex(4)}.{name.strip('.')}"
        reply = dnsq.query(probe, server, timeout=first if i == 0 else min(first, 1.5), port=port)
        code = dnsmsg.rcode(reply) if reply is not None else None
        if code in (0, 3):
            return "up"
        servfail = servfail or code == 2
        answered = answered or reply is not None
    if servfail:
        return "down"
    if not answered and local and dnsq.query(local, server, timeout=1.5, port=port) is not None:
        return "down"  # AdGuard is alive and answers its own rules; only the upstreams are silent
    return "unknown"


def restart_guard(
    name: str,
    state: Callable[[str], str] | None = None,
    local: str | None = None,
    wait: float | None = None,
) -> None:
    """Raise Deferred when the upstreams are down. Every AdGuard restart empties its cache, and during
    an upstream outage that cache is all the TV has: a restart then turns stale answers into failures
    and, because the readiness wait cannot pass, the apply rolls back with a second restart. Whatever
    asked for the restart (a machine rule, a revert, an undo, a deploy) waits for the next run.
    `local` and `wait` go to `upstream_state()`; `state` stands in for it in tests."""
    # upstream_state is looked up now, so a test can monkeypatch it
    got = state(name) if state is not None else upstream_state(name, wait=wait, local=local)
    if got == "down":
        raise Deferred(
            f"deferred: upstream down (a fresh lookup under {name} SERVFAILs, or goes unanswered while"
            " AdGuard answers its own rules); AdGuard Home was not restarted and nothing changed; run it"
            " again once lookups resolve"
        )


def guard_for(path: str, d: Desired) -> Callable[[], None]:
    """(lists) The restart guard for the AdGuard whose YAML is `path`: probes under `d.probe_name`,
    listens past that YAML's own upstream timeout (read when the guard runs), checks `d.local_name`."""

    def guard() -> None:
        try:
            cfg = load_yaml(path)
        except (OSError, yaml.YAMLError):
            cfg = {}
        restart_guard(d.probe_name, local=d.local_name, wait=upstream_wait(cfg))

    return guard


@contextlib.contextmanager
def _locked(directory: str, busy: str):
    """(lists) The one AdGuard lock (`.tvgw-adguard.lock` beside AdGuardHome.yaml), taken without waiting:
    apply, upgrade and the service drop-in never restart AdGuard under each other."""
    lock = os.open(os.path.join(directory, ".tvgw-adguard.lock"), os.O_RDWR | os.O_CREAT, 0o600)
    try:
        try:
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            raise RuntimeError(busy) from None
        yield
    finally:
        os.close(lock)  # releases the flock


def check_config(path: str, binary: str | None = None) -> tuple[bool, str]:
    """`AdGuardHome --check-config` on a candidate file: (True, '') when it passes, (False, AdGuard's own
    reason) when it does not, and (True, a note) when the binary is not there to ask."""
    exe = binary or os.path.join(os.path.dirname(os.path.abspath(path)), "AdGuardHome")
    if not os.access(exe, os.X_OK):
        note = f"not validated: {exe} not found"
        print(f"tvgw adguard: {note}; the planned config was not validated before writing", file=sys.stderr)
        return True, note
    try:
        r = subprocess.run(
            [exe, "--check-config", "-c", path, "-w", os.path.dirname(exe), "--no-check-update"],
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=120,
        )
    except subprocess.TimeoutExpired:
        return False, "AdGuardHome --check-config did not finish in 120 s"
    return (True, "") if r.returncode == 0 else (False, (r.stderr + r.stdout)[-1500:])


def _stage(beside: str, data: bytes, mode_from: str) -> str:
    """`data` in a new file in the directory of `beside`, fsynced, with the permissions of `mode_from`.
    The caller moves it into place or unlinks it; the live file is never written in place."""
    fd, tmp = tempfile.mkstemp(
        prefix=".AdGuardHome.", suffix=".yaml", dir=os.path.dirname(os.path.abspath(beside))
    )
    try:
        with os.fdopen(fd, "wb") as fh:
            fh.write(data)
            fh.flush()
            os.fsync(fh.fileno())
        shutil.copymode(mode_from, tmp)
    except BaseException:
        os.unlink(tmp)
        raise
    return tmp


def _commit(tmp: str, path: str) -> None:
    """Move a staged file over `path`; the directory is fsynced so the rename survives a power loss."""
    os.replace(tmp, path)
    fd = os.open(os.path.dirname(os.path.abspath(path)), os.O_RDONLY)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def _backup(path: str, now: float | None) -> str:
    """A copy of the live file as `<path>.bak-<UTC stamp>Z-<pid>`, never written over an earlier one."""
    stamp = time.strftime("%Y%m%d%H%M%SZ", time.gmtime(time.time() if now is None else now))
    base = f"{path}.bak-{stamp}-{os.getpid()}"
    for n in itertools.count():
        name = base if n == 0 else f"{base}.{n}"
        try:
            os.close(os.open(name, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600))
        except FileExistsError:
            continue
        shutil.copy2(path, name)
        return name


def _restore(path: str, backup: str, control: Callable[..., None], unit: str) -> None:
    """Put `backup` back as `path`, atomically, and start the unit. The stop may fail (the unit may
    already be down); that is no reason to leave the planned file live."""
    with contextlib.suppress(Exception):
        control("stop", unit)
    tmp = _stage(path, Path(backup).read_bytes(), backup)
    try:
        _commit(tmp, path)
    except BaseException:
        with contextlib.suppress(OSError):
            os.unlink(tmp)
        raise
    control("start", unit)


def apply(
    path: str,
    d: Desired,
    control: Callable[..., None] = systemctl,
    ready: Callable[[], bool] = dns_ready,
    check: Callable[[str], tuple[bool, str]] = check_config,
    unit: str = "AdGuardHome",
    now: float | None = None,
    guard: Callable[[], None] | None = None,
) -> list[str]:
    """Write the planned config and restart AdGuard, without ever leaving the resolver worse off.

    One apply at a time (a lock beside the file). The candidate is written beside the real file and
    validated by AdGuard itself before the service is touched, and the live file is copied to a
    backup first. Then, with SIGTERM, SIGHUP and SIGINT held off, AdGuard is stopped, the candidate
    moved into place atomically and AdGuard started. Any failure from the stop onwards, a resolver
    that does not come back within the readiness timeout included, puts the backup back the same
    atomic way and restarts AdGuard. Returns the changes made; raises RuntimeError, with the reason,
    when nothing changed or the rollback happened.

    (lists) Before anything is staged it refuses a YAML above SCHEMA_CEILING, and when there is a
    change to make it runs `guard` (by default `restart_guard()` on `d.probe_name`, listening past the
    live YAML's own upstream timeout and checking `d.local_name`), which raises
    `Deferred` while the upstreams are down: the restart would cost the TV its cache for nothing.
    """
    directory = os.path.dirname(os.path.abspath(path))
    with _locked(directory, "another tvgw adguard apply is running"):
        current = load_yaml(path)
        if not isinstance(current, dict) or "schema_version" not in current:
            # plan() would complete a destroyed config from the template, and AdGuard would start on it
            raise RuntimeError(
                f"{path} has no schema_version (empty or truncated); restore a .bak-* file or rerun"
                " AdGuard's wizard; nothing changed"
            )
        check_schema(current, path)  # (lists)
        planned = plan(current, d)
        diff = changes(current, planned)
        if not diff:
            return []
        # (lists) Deferred: nothing staged, no restart
        (guard or (lambda: restart_guard(d.probe_name, local=d.local_name, wait=upstream_wait(current))))()
        tmp = _stage(path, dump_yaml(planned).encode(), path)
        try:
            ok, detail = check(tmp)
            if not ok:
                raise RuntimeError(f"AdGuard Home rejected the planned {path}; nothing changed\n{detail}")
            backup = _backup(path, now)
        except BaseException:
            os.unlink(tmp)
            raise
        held = signal.pthread_sigmask(signal.SIG_BLOCK, {signal.SIGTERM, signal.SIGHUP, signal.SIGINT})
        try:
            control("stop", unit)
            _commit(tmp, path)
            control("start", unit)
            if not ready():
                raise RuntimeError(f"{unit} did not answer DNS after the change")
        except BaseException as e:
            try:
                _restore(path, backup, control, unit)
            except Exception as e2:
                raise RuntimeError(f"{e}; restoring {backup} also failed: {e2}") from e
            raise RuntimeError(f"{e}; the previous config ({backup}) was put back") from e
        finally:
            with contextlib.suppress(FileNotFoundError):
                os.unlink(tmp)  # still there only when the stop failed before the move
            signal.pthread_sigmask(signal.SIG_SETMASK, held)
        return diff


# ---- (lists) upgrading the binary --------------------------------------------------------------------
VERSION_RE = re.compile(r"\bv?(\d+)\.(\d+)\.(\d+)\b")


def binary_version(exe: str) -> tuple[int, int, int] | None:
    """`exe --version` as (major, minor, patch), or None when it does not run or says no version."""
    try:
        r = subprocess.run(
            [exe, "--version"], capture_output=True, text=True, encoding="utf-8", errors="replace", timeout=30
        )
    except (OSError, subprocess.TimeoutExpired):
        return None
    m = VERSION_RE.search(r.stdout + r.stderr)
    return (int(m.group(1)), int(m.group(2)), int(m.group(3))) if m else None


def _copy_beside(src: str, beside: str, prefix: str, mode_from: str | None = None) -> str:
    """A copy of `src` in a new file in the directory of `beside` (so a later rename is atomic),
    fsynced, with the permissions of `mode_from` (default: of `src`)."""
    fd, tmp = tempfile.mkstemp(prefix=prefix, dir=os.path.dirname(os.path.abspath(beside)))
    try:
        with os.fdopen(fd, "wb") as out, open(src, "rb") as fh:
            shutil.copyfileobj(fh, out)
            out.flush()
            os.fsync(out.fileno())
        shutil.copymode(mode_from or src, tmp)
    except BaseException:
        os.unlink(tmp)
        raise
    return tmp


def upgrade(
    path: str,
    newbin: str,
    binary: str | None = None,
    control: Callable[..., None] = systemctl,
    ready: Callable[[], bool] = dns_ready,
    check: Callable[[str, str], tuple[bool, str]] | None = None,
    verify: Callable[[], set[str]] | None = None,
    guard: Callable[[], None] | None = None,
    version: Callable[[str], tuple[int, int, int] | None] = binary_version,
    floor: tuple[int, int, int] = (0, 107, 79),
    unit: str = "AdGuardHome",
    now: float | None = None,
) -> list[str]:
    """Replace AdGuard Home's binary with `newbin` without ever leaving the TV without a resolver.

    In order, under the apply lock: the new binary must report a version at the floor; the live YAML
    must be within SCHEMA_CEILING; the new binary's own `--check-config` must pass on a copy of the live
    YAML (a copy, because the check runs the migrations, and a newer schema there is refused too);
    `guard` must not report the upstreams down. Then the binary and the YAML are backed up, AdGuard is
    stopped, the new binary moved into place atomically and AdGuard started; it must answer within the
    readiness wait, and `verify` (the names of the checks that FAIL) must name no check that did not
    already fail before the swap. Any failure from the stop onwards puts both backups back and starts
    the old binary. Returns what was done; raises RuntimeError (Deferred when the upstreams are down)
    with the reason when nothing changed or the rollback happened."""
    exe = binary or os.path.join(os.path.dirname(os.path.abspath(path)), "AdGuardHome")
    check = check or (lambda candidate, bin_: check_config(candidate, binary=bin_))
    verify = verify or (lambda: set())
    if not (os.path.isfile(newbin) and os.access(newbin, os.X_OK)):
        raise RuntimeError(f"{newbin} is not an executable file; nothing changed")
    if os.path.realpath(newbin) == os.path.realpath(exe):
        raise RuntimeError(f"{newbin} is the installed binary; nothing to do")
    got = version(newbin)
    if got is None:
        raise RuntimeError(f"{newbin} --version names no version; nothing changed")
    if got < floor:
        have, want = ".".join(map(str, got)), ".".join(map(str, floor))
        raise RuntimeError(f"{newbin} is v{have}, below the floor v{want}; nothing changed")
    old = version(exe)
    directory = os.path.dirname(os.path.abspath(path))
    with _locked(directory, "another tvgw adguard apply or upgrade is running"):
        current = load_yaml(path)
        if not isinstance(current, dict) or "schema_version" not in current:
            raise RuntimeError(f"{path} has no schema_version (empty or truncated); nothing changed")
        check_schema(current, path)
        trial = _copy_beside(path, path, ".AdGuardHome.upgrade-check.")
        try:
            ok, detail = check(trial, newbin)
            migrated = load_yaml(trial)
        finally:
            with contextlib.suppress(FileNotFoundError):
                os.unlink(trial)
        if not ok:
            raise RuntimeError(f"{newbin} --check-config rejected the live {path}; nothing changed\n{detail}")
        check_schema(migrated, f"{path} as {newbin} migrates it")
        (guard or (lambda: restart_guard("example.com", wait=upstream_wait(current))))()
        failing_before = verify()
        stamp = time.strftime("%Y%m%d%H%M%SZ", time.gmtime(time.time() if now is None else now))
        bin_backup = f"{exe}.bak-{stamp}-{os.getpid()}"
        shutil.copy2(exe, bin_backup)
        yaml_backup = _backup(path, now)
        staged = _copy_beside(newbin, exe, ".AdGuardHome.new.", mode_from=exe)
        held = signal.pthread_sigmask(signal.SIG_BLOCK, {signal.SIGTERM, signal.SIGHUP, signal.SIGINT})
        try:
            control("stop", unit)
            _commit(staged, exe)
            control("start", unit)
            if not ready():
                raise RuntimeError(f"{unit} did not answer DNS on the new binary")
            new_failures = sorted(verify() - failing_before)
            if new_failures:
                raise RuntimeError("tvgw verify fails on the new binary: " + ", ".join(new_failures))
        except BaseException as e:
            try:
                with contextlib.suppress(Exception):
                    control("stop", unit)
                _commit(_copy_beside(bin_backup, exe, ".AdGuardHome.old."), exe)
                _commit(_stage(path, Path(yaml_backup).read_bytes(), yaml_backup), path)
                control("start", unit)
            except Exception as e2:
                raise RuntimeError(f"{e}; restoring {bin_backup} and {yaml_backup} also failed: {e2}") from e
            raise RuntimeError(f"{e}; the previous binary ({bin_backup}) and config were put back") from e
        finally:
            with contextlib.suppress(FileNotFoundError):
                os.unlink(staged)  # still there only when the stop failed before the move
            signal.pthread_sigmask(signal.SIG_SETMASK, held)
        was = f"v{'.'.join(map(str, old))}" if old else "an unknown version"
        return [
            f"binary: {was} -> v{'.'.join(map(str, got))}",
            f"backups: {bin_backup}, {yaml_backup}",
        ]


# ---- (adguard) install.sh step 12's drop-in, by ADGUARD_LISTEN ------------------------------------------
# install.sh writes one of these two texts with printf (tests/unit/test_adguard_listen.py runs its lines
# and compares); the hardware suite compares the live file with workdir_dropin(). With gateway AdGuard
# binds GW_IP, which exists only once the TV port has its address, so it starts after the network and is
# restarted every 5 s without a start limit until it binds. With keep it is the text install.sh always
# wrote, so the owner's drop-in does not change
WORKDIR_DROPIN = "/etc/systemd/system/AdGuardHome.service.d/workdir.conf"
WORKDIR_KEEP = "[Service]\nWorkingDirectory=/opt/AdGuardHome\n"
WORKDIR_GATEWAY = (
    "[Unit]\nAfter=network-online.target\nWants=network-online.target\nStartLimitIntervalSec=0\n\n"
    "[Service]\nWorkingDirectory=/opt/AdGuardHome\nRestart=always\nRestartSec=5\n"
)


def workdir_dropin(s: Settings) -> str:
    """(adguard) The text of AdGuard's `workdir.conf` drop-in that install.sh writes for these settings."""
    return WORKDIR_GATEWAY if s.adguard_listen == "gateway" else WORKDIR_KEEP


# ---- (lists) the service runs with --no-check-update -------------------------------------------------
NO_UPDATE = "--no-check-update"
SERVICE_DROPIN = "/etc/systemd/system/AdGuardHome.service.d/20-tvgw-no-update.conf"


def exec_start(unit_text: str) -> str | None:
    """The one ExecStart= value of a unit file's [Service] section (backslash continuations joined), or
    None when there is not exactly one: then the drop-in cannot know what to repeat."""
    text = unit_text.replace("\\\n", " ")
    section, found = "", []
    for line in text.splitlines():
        s = line.strip()
        if s.startswith("[") and s.endswith("]"):
            section = s
        elif section == "[Service]" and s.startswith("ExecStart="):
            found.append(s.removeprefix("ExecStart=").strip())
    found = [v for v in found if v]
    return found[0] if len(found) == 1 else None


def dropin_text(unit_text: str) -> str | None:
    """The drop-in that runs AdGuard's own ExecStart with --no-check-update, or None when the unit
    already passes it or its ExecStart cannot be read. A drop-in replaces ExecStart only after an empty
    `ExecStart=` resets the list (systemd.service(5)); without the reset systemd refuses a second
    ExecStart for a simple service."""
    cmd = exec_start(unit_text)
    if cmd is None or NO_UPDATE in (w.strip("\"'") for w in cmd.split()):  # an argument may be quoted
        return None
    return (
        "# written by tvgw (tvgw adguard service): AdGuard Home changes only through tvgw adguard upgrade\n"
        "[Service]\nExecStart=\n"
        f"ExecStart={cmd} {NO_UPDATE}\n"
    )


def _read(path: str) -> str | None:
    try:
        with open(path, encoding="utf-8") as fh:
            return fh.read()
    except FileNotFoundError:
        return None


def _write_text(path: str, text: str) -> None:
    os.makedirs(os.path.dirname(path), mode=0o755, exist_ok=True)
    fd, tmp = tempfile.mkstemp(prefix=".tvgw-", dir=os.path.dirname(path))
    with os.fdopen(fd, "w", encoding="utf-8") as fh:
        fh.write(text)
        fh.flush()
        os.fsync(fh.fileno())
    os.chmod(tmp, 0o644)
    _commit(tmp, path)


def running_argv(unit: str = "AdGuardHome") -> list[str] | None:
    """(lists) The argv the unit's running main process was started with (/proc/<MainPID>/cmdline), or
    None when it is not running or the process cannot be read."""
    try:
        pid = subprocess.run(
            ["systemctl", "show", "-P", "MainPID", unit],
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=30,
        ).stdout.strip()
    except (OSError, subprocess.TimeoutExpired):
        return None
    if not pid.isdigit() or pid == "0":
        return None
    try:
        with open(f"/proc/{pid}/cmdline", "rb") as fh:
            raw = fh.read()
    except OSError:
        return None
    argv = [a.decode("utf-8", "replace") for a in raw.split(b"\0") if a]
    return argv or None


def ensure_service(
    fragment: str,
    dropin: str = SERVICE_DROPIN,
    control: Callable[..., None] = systemctl,
    ready: Callable[[], bool] = dns_ready,
    effective: Callable[[], str] | None = None,
    guard: Callable[[], None] | None = None,
    unit: str = "AdGuardHome",
    lock_dir: str | None = None,
    running: Callable[[], list[str] | None] | None = None,
) -> str:
    """Make AdGuard's service run with --no-check-update, so the binary never updates itself and
    changes only through `upgrade()`. `fragment` is the unit file systemd loaded. Nothing happens when
    the drop-in is already what it should be and the running process (`running`, by default its
    /proc/<MainPID>/cmdline) carries the flag. Otherwise, under the apply lock (in `lock_dir`, the
    directory of AdGuardHome.yaml) and after the restart guard, the drop-in is written, systemd reloaded
    and AdGuard restarted; the effective ExecStart (`effective`, by default `systemctl show -P
    ExecStart`) must carry the flag and the resolver must answer, or the previous drop-in (or none) is
    put back, systemd reloaded, and AdGuard restarted on it if it had been restarted. Returns a one-line
    account; raises RuntimeError when the unit's ExecStart cannot be read."""
    try:
        with open(fragment, encoding="utf-8") as fh:
            unit_text = fh.read()
    except OSError as e:
        raise RuntimeError(f"cannot read {fragment}: {e}") from None
    cmd = exec_start(unit_text)
    if cmd is None:
        raise RuntimeError(f"cannot read one ExecStart from {fragment}; add {NO_UPDATE} by hand")
    want = dropin_text(unit_text)
    have = _read(dropin)
    if want is None:  # the unit's own command already carries the flag
        return f"{unit} already runs with {NO_UPDATE}" if have is None else f"{dropin} is in place"
    running = running or (lambda: running_argv(unit))
    if have == want:
        argv = running()
        if argv is None or NO_UPDATE in argv:
            return f"{dropin} is in place"
        # the drop-in is there but the process predates it (a reload whose restart never happened)
    effective = effective or (
        lambda: (
            subprocess.run(
                ["systemctl", "show", "-P", "ExecStart", unit],
                capture_output=True,
                text=True,
                encoding="utf-8",
                errors="replace",
                timeout=30,
            ).stdout
        )
    )
    directory = lock_dir or os.path.dirname(os.path.abspath(Settings().adguard_yaml))
    with _locked(directory, "another tvgw adguard apply or upgrade is running"):
        (guard or (lambda: restart_guard("example.com")))()
        restarted = False
        try:
            _write_text(dropin, want)
            control("daemon-reload")
            if NO_UPDATE not in effective():
                raise RuntimeError(
                    f"systemd does not show {NO_UPDATE} in {unit}'s ExecStart after the reload"
                )
            restarted = True
            control("restart", unit)
            if not ready():
                raise RuntimeError(f"{unit} did not answer DNS after the restart")
        except BaseException as e:
            try:
                if have is None:
                    with contextlib.suppress(FileNotFoundError):
                        os.unlink(dropin)
                else:
                    _write_text(dropin, have)
                control("daemon-reload")
                if restarted:  # AdGuard is running as it was otherwise: no restart, no lost cache
                    control("restart", unit)
            except Exception as e2:
                raise RuntimeError(f"{e}; putting the previous drop-in back also failed: {e2}") from e
            raise RuntimeError(f"{e}; the previous service definition was put back") from e
    return f"{unit} restarted with {NO_UPDATE} ({dropin})"
