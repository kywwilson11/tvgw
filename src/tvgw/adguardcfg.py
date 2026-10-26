"""AdGuard Home as configuration: lists, rules and settings the gateway needs, applied to AdGuardHome.yaml.

The profile says which blocklists and custom rules; the gateway settings say which upstreams and
which TV. `plan()` merges that into AdGuard's current config (only the keys we own change),
`changes()` describes the difference, `apply()` writes it with the service stopped and restarts.
AdGuard rewrites its own YAML, so we go through PyYAML rather than editing text.
"""

from __future__ import annotations

import copy
import shutil
import socket
import struct
import subprocess
import time
from collections.abc import Callable
from dataclasses import dataclass, field
from pathlib import Path

import yaml

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
    mine = next((c for c in persistent if isinstance(c, dict) and d.tv_ip in (c.get("ids") or [])), None)
    if mine is None:
        persistent.append(
            {
                "name": d.tv_name,
                "ids": ids,
                "tags": ["device_tv"],
                "use_global_settings": True,
                "filtering_enabled": True,
                "use_global_blocked_services": True,
                "ignore_querylog": False,
                "ignore_statistics": False,
            }
        )
    else:
        for i in ids:
            if i not in mine["ids"]:
                mine["ids"].append(i)
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


def load_yaml(path: str) -> dict:
    with open(path) as fh:
        return yaml.safe_load(fh) or {}


def dump_yaml(cfg: dict) -> str:
    return yaml.safe_dump(cfg, sort_keys=False, default_flow_style=False, allow_unicode=True)


def systemctl(*args: str) -> None:
    subprocess.run(["systemctl", *args], check=True, timeout=120)


def dns_ready(server: str = "127.0.0.1", name: str = "example.com", timeout: float = 30.0) -> bool:
    """True once the resolver answers a plain UDP query; AdGuard needs seconds to load big lists."""
    labels = b"".join(bytes([len(x)]) + x.encode() for x in name.split("."))
    query = struct.pack(">HHHHHH", 0x7476, 0x0100, 1, 0, 0, 0) + labels + b"\x00" + struct.pack(">HH", 1, 1)
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(1.0)
        try:
            sock.sendto(query, (server, 53))
            sock.recvfrom(512)
            return True
        except OSError:
            time.sleep(0.5)
        finally:
            sock.close()
    return False


def apply(
    path: str,
    d: Desired,
    control: Callable[..., None] = systemctl,
    ready: Callable[[], bool] = dns_ready,
    unit: str = "AdGuardHome",
    now: float | None = None,
) -> list[str]:
    """Stop AdGuard, back the YAML up, write the planned config, start AdGuard and wait until it answers.

    Returns the changes made; raises RuntimeError if the resolver is not back within the readiness timeout
    (the service has been started regardless, so the caller can decide how loud to be).
    """
    current = load_yaml(path)
    planned = plan(current, d)
    diff = changes(current, planned)
    if not diff:
        return []
    control("stop", unit)
    try:
        stamp = time.strftime("%Y%m%d%H%M%S", time.localtime(now or time.time()))
        shutil.copy2(path, f"{path}.bak-{stamp}")
        Path(path).write_text(dump_yaml(planned))
    finally:
        control("start", unit)
    if not ready():
        raise RuntimeError(f"{unit} restarted but is not answering DNS yet; check `systemctl status {unit}`")
    return diff
