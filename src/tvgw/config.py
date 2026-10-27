"""Gateway settings: `/etc/tvgw/tvgw.conf` (KEY=VALUE, shell-style) plus the paths everything uses.

Every path is a field so tests and other deployments can point the tools elsewhere; the
defaults are the layout `deploy/install.sh` creates on the Pi.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, fields, replace
from pathlib import Path

_LINE = re.compile(r'^\s*([A-Z][A-Z0-9_]*)=("([^"]*)"|\'([^\']*)\'|([^#\n]*?))\s*(#.*)?$')


@dataclass(frozen=True)
class Settings:
    tv_ip: str = "10.10.10.17"
    tv_mac: str = ""
    tv_name: str = "tv"
    gw_ip: str = "10.10.10.1"
    tv_if: str = "eth0"
    wan_if: str = "wlan0"
    uplink: str = "direct"  # direct | vpn (tun0)
    block_quic: str = "yes"
    strict_ports: str = "no"
    profile: str = "lg-webos"
    dns_upstreams: str = "https://1.1.1.1/dns-query,https://1.0.0.1/dns-query"  # DoH by IP (comma-separated)
    dns_bootstrap: str = "1.1.1.1,1.0.0.1"
    db_days: int = 365
    state_dir: str = "/var/lib/tvgw"
    db_path: str = "/var/lib/tvgw/tvgw.db"
    pcap_dir: str = "/var/lib/tvgw/pcap"
    flows_log: str = "/var/log/tvgw/flows.log"
    gfts_log: str = "/var/log/tvgw/gfts.log"
    adguard_querylog: str = "/opt/AdGuardHome/data/querylog.json"
    adguard_yaml: str = "/opt/AdGuardHome/AdGuardHome.yaml"
    nginx_conf: str = "/etc/nginx/conf.d/tvgw-gfts.conf"
    block4: str = "/etc/tvgw/block4.txt"
    tvcheck_history: str = "/var/lib/tvgw/tvcheck-history.log"
    tvcheck_txt: str = "/var/lib/tvgw/tvcheck.txt"
    reports_dir: str = "/var/lib/tvgw/reports"


# conf key -> Settings field (only the keys an operator is meant to set)
CONF_KEYS = {
    "TV_IP": "tv_ip",
    "TV_MAC": "tv_mac",
    "TV_NAME": "tv_name",
    "GW_IP": "gw_ip",
    "WAN_IF": "wan_if",
    "UPLINK": "uplink",
    "BLOCK_QUIC": "block_quic",
    "STRICT_PORTS": "strict_ports",
    "PROFILE": "profile",
    "DNS_UPSTREAMS": "dns_upstreams",
    "DNS_BOOTSTRAP": "dns_bootstrap",
    "DB_DAYS": "db_days",
    "STATE_DIR": "state_dir",
    "DB_PATH": "db_path",
}


def parse_conf(text: str) -> dict[str, str]:
    """KEY=VALUE lines; quotes and trailing comments handled; other lines ignored."""
    out: dict[str, str] = {}
    for line in text.splitlines():
        m = _LINE.match(line)
        if m:
            out[m.group(1)] = next(g for g in (m.group(3), m.group(4), m.group(5)) if g is not None).strip()
    return out


def load(path: str | Path = "/etc/tvgw/tvgw.conf", **overrides) -> Settings:
    """Settings from the conf file (missing file = defaults), then keyword overrides."""
    s = Settings()
    try:
        conf = parse_conf(Path(path).read_text())
    except OSError:
        conf = {}
    changes: dict[str, object] = {}
    for key, name in CONF_KEYS.items():
        if key in conf and conf[key] != "":
            ftype = next(f.type for f in fields(Settings) if f.name == name)
            changes[name] = _int(key, conf[key]) if ftype == "int" else conf[key]
    changes.update(overrides)
    return replace(s, **changes)


def _int(key: str, value: str) -> int:
    try:
        n = int(value)
    except ValueError:
        raise ValueError(f"{key}={value!r} in tvgw.conf: expected a whole number") from None
    if n < 1:
        raise ValueError(f"{key}={value!r} in tvgw.conf: must be at least 1")
    return n
