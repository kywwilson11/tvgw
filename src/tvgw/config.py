"""Gateway settings: `/etc/tvgw/tvgw.conf` (KEY=VALUE, shell-style) plus the paths everything uses.

Every path is a field so tests and other deployments can point the tools elsewhere; the
defaults are the layout `deploy/install.sh` creates on the Pi.
"""

from __future__ import annotations

import ipaddress
import math
import re
from dataclasses import dataclass, replace
from pathlib import Path

_LINE = re.compile(r'^\s*([A-Z][A-Z0-9_]*)=("([^"]*)"|\'([^\']*)\'|([^#\n]*?))\s*(#.*)?$')


@dataclass(frozen=True)
class Settings:
    tv_ip: str = "10.10.10.17"
    tv_mac: str = ""
    tv_name: str = "tv"
    gw_ip: str = "10.10.10.1"
    tv_if: str = "eth0"
    tv_net: str = "10.10.10.0/24"  # (packaging) the TV subnet; GW_IP and TV_IP sit inside it
    wan_if: str = "wlan0"
    uplink: str = "direct"  # direct | vpn (tun0)
    block_quic: str = "yes"
    strict_ports: str = "no"
    dnsgate: str = "count"  # off | count: addresses the TV connects to that no lookup returned
    analyst_model: str = "claude-opus-5-5"  # the model `tvgw analyst` asks
    analyst_effort: str = "high"  # low | medium | high | xhigh | max: its reasoning depth
    analyst_window: str = "day"  # day (the previous calendar day) | Nh (the last N hours)
    analyst_schedule: str = "03:50"  # HH:MM daily | hourly | a systemd calendar expression
    analyst_weekly_model: str = "claude-fable-5-1"  # the weekly pass over the whole week; off disables it
    analyst_weekly_effort: str = "high"
    analyst_weekly_schedule: str = "Mon 04:10"  # Day HH:MM | a systemd calendar expression
    analyst_apply: str = "off"  # off | auto: vetted, verified block proposals are applied on their own
    analyst_verifier_model: str = (
        "claude-fable-5-1"  # the second key: tries to refute each block before it lands
    )
    analyst_verifier_effort: str = "xhigh"
    auto_rules: str = (
        "/var/lib/tvgw/auto.rules"  # the machine-owned rules file; the profile's .rules is never touched
    )
    profile: str = "lg-webos"
    dns_upstreams: str = "https://1.1.1.1/dns-query,https://1.0.0.1/dns-query"  # DoH by IP (comma-separated)
    dns_bootstrap: str = "1.1.1.1,1.0.0.1"
    db_days: int = 365
    pcap_days: int = 7
    pcap_max_gb: float = 1.5
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
    "TV_IF": "tv_if",  # (packaging) the TV side, templated: deploy/README.md#the-settings-file
    "TV_NET": "tv_net",
    "WAN_IF": "wan_if",
    "UPLINK": "uplink",
    "BLOCK_QUIC": "block_quic",
    "STRICT_PORTS": "strict_ports",
    "DNSGATE": "dnsgate",
    "PROFILE": "profile",
    "DNS_UPSTREAMS": "dns_upstreams",
    "DNS_BOOTSTRAP": "dns_bootstrap",
    "DB_DAYS": "db_days",
    "PCAP_DAYS": "pcap_days",
    "PCAP_MAX_GB": "pcap_max_gb",
    "STATE_DIR": "state_dir",
    "DB_PATH": "db_path",
    "REPORTS_DIR": "reports_dir",
    "ANALYST_MODEL": "analyst_model",
    "ANALYST_EFFORT": "analyst_effort",
    "ANALYST_WINDOW": "analyst_window",
    "ANALYST_SCHEDULE": "analyst_schedule",
    "ANALYST_WEEKLY_MODEL": "analyst_weekly_model",
    "ANALYST_WEEKLY_EFFORT": "analyst_weekly_effort",
    "ANALYST_WEEKLY_SCHEDULE": "analyst_weekly_schedule",
    "ANALYST_APPLY": "analyst_apply",
    "ANALYST_VERIFIER_MODEL": "analyst_verifier_model",
    "ANALYST_VERIFIER_EFFORT": "analyst_verifier_effort",
    "AUTO_RULES": "auto_rules",
}
# switches tvgw-apply reads with an exact `case`; a near miss (`Yes`, `on`) must fail here, not there
# the analyst's reasoning depth, checked here (tvgw-apply never reads it, so it is not in CHOICES)
EFFORTS = ("low", "medium", "high", "xhigh", "max")
APPLY_MODES = ("off", "auto")
CHOICES = {
    "UPLINK": ("direct", "vpn"),
    "BLOCK_QUIC": ("yes", "no"),
    "STRICT_PORTS": ("yes", "no"),
    "DNSGATE": ("off", "count"),
}


def parse_conf(text: str) -> dict[str, str]:
    """KEY=VALUE lines; quotes and trailing comments handled; other lines ignored. An unquoted value
    with a space in it is refused: the shell scripts source this file, and to the shell `KEY=Mon 04:10`
    sets KEY for a command named `04:10`, which stops them under `set -e` while Python read the value."""
    out: dict[str, str] = {}
    for line in text.splitlines():
        m = _LINE.match(line)
        if m:
            if m.group(5) is not None and any(ch.isspace() for ch in m.group(5)):
                raise ValueError(
                    f"{m.group(1)}={m.group(5).strip()!r} in tvgw.conf: a value with a space must be quoted"
                )
            out[m.group(1)] = next(g for g in (m.group(3), m.group(4), m.group(5)) if g is not None).strip()
    return out


def load(path: str | Path = "/etc/tvgw/tvgw.conf", **overrides) -> Settings:
    """Settings from the conf file (missing file = defaults), then keyword overrides. The two
    addresses are checked: every source keeps only the rows that equal `tv_ip`, so a typo there
    would record nothing from any source while every source counted as read. Any other failure to
    read the file propagates: a conf that is there but unreadable must not become the defaults."""
    try:
        conf = parse_conf(Path(path).read_text(encoding="utf-8"))
    except FileNotFoundError:
        conf = {}
    defaults = Settings()
    changes: dict[str, object] = {}
    for key, name in CONF_KEYS.items():
        value = conf.get(key, "")
        if value != "":  # an empty value keeps the default
            # the annotations are strings under `from __future__ import annotations`; the default's
            # type is the fact
            parse = _PARSE.get(type(getattr(defaults, name)))
            changes[name] = parse(key, value) if parse else value
    changes.update(overrides)
    s = replace(defaults, **changes)
    for key, value in (("TV_IP", s.tv_ip), ("GW_IP", s.gw_ip)):
        try:
            ipaddress.ip_address(value)
        except ValueError:
            raise ValueError(f"{key}={value!r} in tvgw.conf: not an IP address") from None
    _check_tv_shape(s)
    for key, allowed in CHOICES.items():
        value = getattr(s, CONF_KEYS[key])
        if value not in allowed:
            raise ValueError(f"{key}={value!r} in tvgw.conf: expected one of {', '.join(allowed)}")
    for key, effort in (
        ("ANALYST_EFFORT", s.analyst_effort),
        ("ANALYST_WEEKLY_EFFORT", s.analyst_weekly_effort),
        ("ANALYST_VERIFIER_EFFORT", s.analyst_verifier_effort),
    ):
        if effort not in EFFORTS:
            raise ValueError(f"{key}={effort!r} in tvgw.conf: expected one of {', '.join(EFFORTS)}")
    if not re.fullmatch(r"[a-z0-9][a-z0-9.-]{2,60}", s.analyst_model):
        raise ValueError(f"ANALYST_MODEL={s.analyst_model!r} in tvgw.conf: not a model id")
    if s.analyst_weekly_model != "off" and not re.fullmatch(
        r"[a-z0-9][a-z0-9.-]{2,60}", s.analyst_weekly_model
    ):
        raise ValueError(
            f"ANALYST_WEEKLY_MODEL={s.analyst_weekly_model!r} in tvgw.conf: not a model id (or off)"
        )
    if not re.fullmatch(r"[a-z0-9][a-z0-9.-]{2,60}", s.analyst_verifier_model):
        raise ValueError(f"ANALYST_VERIFIER_MODEL={s.analyst_verifier_model!r} in tvgw.conf: not a model id")
    if s.analyst_apply not in APPLY_MODES:
        raise ValueError(
            f"ANALYST_APPLY={s.analyst_apply!r} in tvgw.conf: expected one of {', '.join(APPLY_MODES)}"
        )
    w = s.analyst_window
    if w != "day" and not (re.fullmatch(r"\d{1,3}h", w) and 1 <= int(w[:-1]) <= 168):
        raise ValueError(f"ANALYST_WINDOW={w!r} in tvgw.conf: expected day or 1h..168h")
    schedules = (
        ("ANALYST_SCHEDULE", s.analyst_schedule),
        ("ANALYST_WEEKLY_SCHEDULE", s.analyst_weekly_schedule),
    )
    for key, sched in schedules:
        if not sched or len(sched) > 80 or any(ch in sched for ch in "\n;&|"):
            raise ValueError(
                f"{key}={sched!r} in tvgw.conf: a time, a day and time, or a calendar expression"
            )
    return s


def _int(key: str, value: str) -> int:
    try:
        n = int(value)
    except ValueError:
        raise ValueError(f"{key}={value!r} in tvgw.conf: expected a whole number") from None
    if n < 1:
        raise ValueError(f"{key}={value!r} in tvgw.conf: must be at least 1")
    return n


def _float(key: str, value: str) -> float:
    try:
        x = float(value)
    except ValueError:
        raise ValueError(f"{key}={value!r} in tvgw.conf: expected a number") from None
    if not (math.isfinite(x) and x > 0):  # a typo must never become "keep nothing"
        raise ValueError(f"{key}={value!r} in tvgw.conf: must be more than 0")
    return x


_PARSE = {int: _int, float: _float}  # by the default's type; every other field is text


# (packaging) The TV side: TV_IF, TV_NET and GW_IP feed tvgw-apply, the dnsmasq, nginx and NetworkManager
# files and the units, so a second site with other interfaces needs no edited script. The shell side
# checks the same rules in the `tvgw-net` block that install.sh and tvgw-apply share
# (tests/unit/test_packaging.py runs both on the same cases).
IFNAME = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,14}")  # a kernel interface name: at most 15 bytes, no `/`
TV_PREFIXES = range(16, 28)  # /27 is the smallest subnet that holds the DHCP pool at .10 to .20
PRIVATE_NETS = tuple(ipaddress.IPv4Network(n) for n in ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"))
DHCP_POOL = (10, 20)  # the pool's first and last host, as offsets into TV_NET (the shipped .10 to .20)


@dataclass(frozen=True)
class TvSide:
    """What the shell side derives from TV_NET: the values the dnsmasq template and nmcli need."""

    network: ipaddress.IPv4Network
    gw: ipaddress.IPv4Address
    prefix: int
    netmask: str
    broadcast: str
    dhcp_first: str
    dhcp_last: str


def _check_tv_shape(s: Settings) -> None:
    """The two TV-side keys on their own, checked by every command: a typo in either would otherwise
    surface only when tvgw-apply refuses it at the next boot."""
    if not IFNAME.fullmatch(s.tv_if) or s.tv_if in ("lo", "tun0"):
        raise ValueError(f"TV_IF={s.tv_if!r} in tvgw.conf: not an interface name for the TV")
    _tv_network(s.tv_net)


def _tv_network(value: str) -> ipaddress.IPv4Network:
    bad = f"TV_NET={value!r} in tvgw.conf: not an IPv4 network such as 10.10.10.0/24"
    try:
        net = ipaddress.IPv4Network(value, strict=True)
    except ValueError:
        raise ValueError(bad) from None
    if value != str(net):  # `10.10.10.0/08` or no prefix: the shell side reads only the canonical form
        raise ValueError(bad)
    if net.prefixlen not in TV_PREFIXES:
        raise ValueError(f"TV_NET={value!r} in tvgw.conf: the prefix must be /16 to /27")
    if not any(net.subnet_of(p) for p in PRIVATE_NETS):
        raise ValueError(f"TV_NET={value!r} in tvgw.conf: must be inside 10/8, 172.16/12 or 192.168/16")
    return net


def tv_side(s: Settings, with_tv_ip: bool = True) -> TvSide:
    """The TV side as the shell side builds it, or ValueError naming the first rule broken. Not part of
    `load`: membership is enforced where the values are written (install.sh, tvgw-apply), and a reader
    must still work on a conf the installer would refuse. A settings writer calls this before writing."""
    _check_tv_shape(s)
    if s.tv_if == s.wan_if:
        raise ValueError(f"TV_IF={s.tv_if!r} in tvgw.conf: the TV and the uplink need different interfaces")
    net = _tv_network(s.tv_net)
    first, last = (net.network_address + n for n in DHCP_POOL)
    try:
        gw = ipaddress.IPv4Address(s.gw_ip)
    except ValueError:
        raise ValueError(f"GW_IP={s.gw_ip!r} in tvgw.conf: not an IPv4 address") from None
    if gw not in net or gw in (net.network_address, net.broadcast_address):
        raise ValueError(f"GW_IP={s.gw_ip} in tvgw.conf: must be a host address in TV_NET {net}")
    if first <= gw <= last:
        raise ValueError(f"GW_IP={s.gw_ip} in tvgw.conf: inside the DHCP pool {first} to {last}")
    if with_tv_ip:
        try:
            tv = ipaddress.IPv4Address(s.tv_ip)
        except ValueError:
            raise ValueError(f"TV_IP={s.tv_ip!r} in tvgw.conf: not an IPv4 address") from None
        if tv not in net or tv in (net.network_address, net.broadcast_address) or tv == gw:
            raise ValueError(
                f"TV_IP={s.tv_ip} in tvgw.conf: must be a host address in TV_NET {net}, not GW_IP"
            )
    return TvSide(net, gw, net.prefixlen, str(net.netmask), str(net.broadcast_address), str(first), str(last))
