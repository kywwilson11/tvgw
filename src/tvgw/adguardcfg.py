"""AdGuard Home as configuration: lists, rules and settings the gateway needs, applied to AdGuardHome.yaml.

The profile says which blocklists and custom rules; the gateway settings say which upstreams and
which TV. `plan()` merges that into AdGuard's current config (only the keys we own change),
`changes()` describes the difference, `apply()` validates it, writes it with the service stopped and
restarts, and puts the backup back if anything goes wrong from the stop onwards.
AdGuard rewrites its own YAML, so we go through PyYAML rather than editing text.
"""

from __future__ import annotations

import contextlib
import copy
import fcntl
import itertools
import os
import re
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
    )


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
    dns["upstream_dns"] = list(d.upstreams)
    dns["upstream_dns_file"] = ""  # a file here replaces the list above
    dns["bootstrap_dns"] = list(d.bootstrap)
    dns["cache_optimistic"] = True
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
    dns["fallback_dns"] = []
    for section in ("querylog", "statistics"):
        sec = _ensure(cfg, section)
        sec["enabled"] = True
        sec["interval"] = d.log_interval
    cfg["querylog"]["file_enabled"] = True
    filt = _ensure(cfg, "filtering")
    filt["filtering_enabled"] = True
    filt["protection_enabled"] = True
    filt["protection_disabled_until"] = None  # the UI's "pause protection" (under filtering since schema 23)
    # 0.0.0.0 answers are what dnsmsg.is_blocked_answer, verify and the hardware suite read as blocked
    filt["blocking_mode"] = "default"
    filt["blocked_response_ttl"] = d.blocked_response_ttl
    filt["rewrites"] = []  # rewrites are rule-based ($dnsrewrite) so they live with the rules
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
) -> list[str]:
    """Write the planned config and restart AdGuard, without ever leaving the resolver worse off.

    One apply at a time (a lock beside the file). The candidate is written beside the real file and
    validated by AdGuard itself before the service is touched, and the live file is copied to a
    backup first. Then, with SIGTERM, SIGHUP and SIGINT held off, AdGuard is stopped, the candidate
    moved into place atomically and AdGuard started. Any failure from the stop onwards, a resolver
    that does not come back within the readiness timeout included, puts the backup back the same
    atomic way and restarts AdGuard. Returns the changes made; raises RuntimeError, with the reason,
    when nothing changed or the rollback happened.
    """
    directory = os.path.dirname(os.path.abspath(path))
    lock = os.open(os.path.join(directory, ".tvgw-adguard.lock"), os.O_RDWR | os.O_CREAT, 0o600)
    try:
        try:
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            raise RuntimeError("another tvgw adguard apply is running") from None
        current = load_yaml(path)
        if not isinstance(current, dict) or "schema_version" not in current:
            # plan() would complete a destroyed config from the template, and AdGuard would start on it
            raise RuntimeError(
                f"{path} has no schema_version (empty or truncated); restore a .bak-* file or rerun"
                " AdGuard's wizard; nothing changed"
            )
        planned = plan(current, d)
        diff = changes(current, planned)
        if not diff:
            return []
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
    finally:
        os.close(lock)  # releases the flock
