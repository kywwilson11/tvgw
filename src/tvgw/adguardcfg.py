"""AdGuard Home as configuration: lists, rules and settings the gateway needs, applied to AdGuardHome.yaml.

The profile says which blocklists and custom rules; the gateway settings say which upstreams and
which TV. `plan()` merges that into AdGuard's current config (only the keys we own change),
`changes()` describes the difference, `apply()` writes it with the service stopped and restarts.
AdGuard rewrites its own YAML, so we go through PyYAML rather than editing text.
"""

from __future__ import annotations

import copy
import os
import re
import shutil
import subprocess
import tempfile
import time
from collections.abc import Callable
from dataclasses import dataclass, field
from pathlib import Path

import yaml

from tvgw import dnsq
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
    extra_rules: tuple[str, ...] = field(default_factory=tuple)


def desired(profile: Profile, s: Settings) -> Desired:
    return Desired(
        filters=tuple(profile.adguard_filters),
        user_rules=tuple(profile.adguard_rules()),
        upstreams=tuple(x for x in s.dns_upstreams.split(",") if x),
        bootstrap=tuple(x for x in s.dns_bootstrap.split(",") if x),
        tv_ip=s.tv_ip,
        tv_mac=s.tv_mac,
        tv_name=s.tv_name,
    )


def _ensure(d: dict, key: str) -> dict:
    v = d.get(key)
    if not isinstance(v, dict):
        v = d[key] = {}
    return v


def plan(current: dict, d: Desired) -> dict:
    """The config AdGuard should have: `current` with the keys we own set. Pure; returns a copy."""
    cfg = copy.deepcopy(current) if current else {}
    _ensure(cfg, "http")["address"] = d.http_address
    dns = _ensure(cfg, "dns")
    dns["upstream_dns"] = list(d.upstreams)
    dns["bootstrap_dns"] = list(d.bootstrap)
    dns["cache_optimistic"] = True
    dns["anonymize_client_ip"] = False
    # the TV sweeps reverse lookups across remembered LANs at power-on; answer those here, never
    # forward them (they would tell the upstream resolver what the TV is probing)
    dns["use_private_ptr_resolvers"] = False
    dns["local_ptr_upstreams"] = []
    for section in ("querylog", "statistics"):
        sec = _ensure(cfg, section)
        sec["enabled"] = True
        sec["interval"] = d.log_interval
    cfg["querylog"]["file_enabled"] = True
    filt = _ensure(cfg, "filtering")
    filt["filtering_enabled"] = True
    filt["protection_enabled"] = True
    filt["blocked_response_ttl"] = d.blocked_response_ttl
    filt["rewrites"] = []  # rewrites are rule-based ($dnsrewrite) so they live with the rules
    # blocklists: keep whatever else is there, make sure ours exist and are enabled
    filters = cfg.get("filters") if isinstance(cfg.get("filters"), list) else []
    by_url = {f.get("url"): f for f in filters if isinstance(f, dict)}
    next_id = max([FILTER_ID_BASE - 1, *(int(f.get("id", 0)) for f in filters if isinstance(f, dict))]) + 1
    for name, url in d.filters:
        if url in by_url:
            by_url[url]["enabled"] = True
            by_url[url]["name"] = name
        else:
            filters.append({"enabled": True, "url": url, "name": name, "id": next_id})
            next_id += 1
    cfg["filters"] = filters
    cfg["user_rules"] = list(d.user_rules) + [r for r in d.extra_rules if r not in d.user_rules]
    # the TV as a named client, so the query log and per-client settings attribute to it
    clients = _ensure(cfg, "clients")
    persistent = clients.get("persistent") if isinstance(clients.get("persistent"), list) else []
    ids = [x for x in (d.tv_ip, d.tv_mac) if x]
    # the TV may have changed address or name since the last apply: match on anything we know,
    # then make the entry ours (AdGuard refuses to start on duplicate client ids or names)
    mine = next(
        (
            c
            for c in persistent
            if isinstance(c, dict)
            and (c.get("name") == d.tv_name or set(str(i) for i in c.get("ids") or []) & set(ids))
        ),
        None,
    )
    if mine is None:
        mine = {
            "name": d.tv_name,
            "ids": ids,
            "tags": ["device_tv"],
            "use_global_settings": True,
            "filtering_enabled": True,
            "use_global_blocked_services": True,
        }
        persistent.append(mine)
    mine["ids"] = ids
    mine["ignore_querylog"] = False
    mine["ignore_statistics"] = False
    clients["persistent"] = persistent
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


class Yaml12Loader(yaml.SafeLoader):
    """PyYAML speaks YAML 1.1, AdGuard Home writes YAML 1.2. In 1.1 an all-digit MAC such as
    10:20:30:40:50:59 is a sexagesimal integer and `on`/`off`/`yes`/`no` are booleans; a round
    trip through those rules would corrupt a client id. This loader resolves scalars the 1.2 way."""


Yaml12Loader.yaml_implicit_resolvers = {
    first: [
        (tag, rx)
        for tag, rx in resolvers
        if tag not in ("tag:yaml.org,2002:int", "tag:yaml.org,2002:bool", "tag:yaml.org,2002:float")
    ]
    for first, resolvers in yaml.SafeLoader.yaml_implicit_resolvers.items()
}
Yaml12Loader.add_implicit_resolver(
    "tag:yaml.org,2002:bool", re.compile(r"^(?:true|True|TRUE|false|False|FALSE)$"), list("tTfF")
)
Yaml12Loader.add_implicit_resolver(
    "tag:yaml.org,2002:int", re.compile(r"^(?:[-+]?[0-9]+|0o[0-7]+|0x[0-9a-fA-F]+)$"), list("-+0123456789")
)
Yaml12Loader.add_implicit_resolver(
    "tag:yaml.org,2002:float",
    re.compile(
        r"^(?:[-+]?(?:\.[0-9]+|[0-9]+(?:\.[0-9]*)?)(?:[eE][-+]?[0-9]+)?|[-+]?\.(?:inf|Inf|INF)|\.(?:nan|NaN|NAN))$"
    ),
    list("-+.0123456789"),
)


def load_yaml(path: str) -> dict:
    with open(path) as fh:
        return yaml.load(fh, Loader=Yaml12Loader) or {}


def dump_yaml(cfg: dict) -> str:
    return yaml.safe_dump(cfg, sort_keys=False, default_flow_style=False, allow_unicode=True)


def systemctl(*args: str) -> None:
    subprocess.run(["systemctl", *args], check=True, timeout=120)


def dns_ready(server: str = "127.0.0.1", name: str = "example.com", timeout: float = 30.0) -> bool:
    """True once the resolver answers a plain UDP query; AdGuard needs seconds to load big lists."""
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if dnsq.query(name, server, timeout=1.0) is not None:
            return True
        time.sleep(0.5)
    return False


def check_config(path: str, binary: str | None = None) -> bool:
    """`AdGuardHome --check-config` on a candidate file; True when the binary is not there to ask."""
    exe = binary or os.path.join(os.path.dirname(os.path.abspath(path)), "AdGuardHome")
    if not os.access(exe, os.X_OK):
        return True
    r = subprocess.run(
        [exe, "--check-config", "-c", path, "-w", os.path.dirname(exe), "--no-check-update"],
        capture_output=True,
        text=True,
        errors="replace",
        timeout=120,
    )
    return r.returncode == 0


def apply(
    path: str,
    d: Desired,
    control: Callable[..., None] = systemctl,
    ready: Callable[[], bool] = dns_ready,
    check: Callable[[str], bool] = check_config,
    unit: str = "AdGuardHome",
    now: float | None = None,
) -> list[str]:
    """Write the planned config and restart AdGuard, without ever leaving the resolver worse off.

    The candidate is written next to the real file and validated by AdGuard itself before the
    service is touched; then AdGuard is stopped, the old file backed up, the candidate moved into
    place atomically and AdGuard started. If the resolver does not answer within the readiness
    timeout the backup is put back and AdGuard restarted. Returns the changes made; raises
    RuntimeError when the candidate is rejected or the rollback had to happen.
    """
    current = load_yaml(path)
    planned = plan(current, d)
    diff = changes(current, planned)
    if not diff:
        return []
    target = Path(path)
    fd, tmp = tempfile.mkstemp(prefix=".AdGuardHome.", suffix=".yaml", dir=str(target.parent))
    try:
        with os.fdopen(fd, "w") as fh:
            fh.write(dump_yaml(planned))
            fh.flush()
            os.fsync(fh.fileno())
        shutil.copymode(path, tmp)
        if not check(tmp):
            raise RuntimeError(f"AdGuard Home rejected the planned {path}; nothing changed")
    except BaseException:
        os.unlink(tmp)
        raise
    stamp = time.strftime("%Y%m%d%H%M%S", time.localtime(now or time.time()))
    backup = f"{path}.bak-{stamp}"
    control("stop", unit)
    try:
        shutil.copy2(path, backup)
        os.replace(tmp, path)
    finally:
        control("start", unit)
    if not ready():
        control("stop", unit)
        shutil.copy2(backup, path)
        control("start", unit)
        raise RuntimeError(
            f"{unit} did not answer DNS after the change; the previous config ({backup}) was put back"
        )
    return diff
