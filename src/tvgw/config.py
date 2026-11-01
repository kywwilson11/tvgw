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
    # (capture) full: tvgw-pcap filters eth0 by byte patterns; headers: the first packets of each
    # connection from NFLOG (docs/capture.md)
    capture_mode: str = "full"
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
    # (lists) a second operator for AdGuard's fallback_dns, by address and encrypted; empty keeps the
    # fallback list empty, as decision 6 had it (an owner decision: docs/adguard.md#a-fallback-resolver)
    dns_fallback: str = ""
    querylog_days: int = 90  # (lists) AdGuard's querylog.interval, in days (1 to 365)
    stats_days: int = 90  # (lists) AdGuard's statistics.interval, in days (1 to 365)
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
    "CAPTURE_MODE": "capture_mode",  # (capture)
    "PROFILE": "profile",
    "DNS_UPSTREAMS": "dns_upstreams",
    "DNS_BOOTSTRAP": "dns_bootstrap",
    "DNS_FALLBACK": "dns_fallback",  # (lists)
    "QUERYLOG_DAYS": "querylog_days",  # (lists)
    "STATS_DAYS": "stats_days",  # (lists)
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
    "CAPTURE_MODE": ("full", "headers"),  # (capture) tvgw-apply and both capture units read it
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
    _check_adguard_keys(s)  # (lists)
    return s


# (lists) AdGuard Home takes a query-log and statistics interval between an hour and a year (its
# configuration reference: 1h to 8760h); the settings count whole days
ADGUARD_DAYS = range(1, 366)
# (lists) the forms a fallback resolver may take: encrypted, and named by address, so it needs no
# bootstrap lookup and no resolver nobody configured is ever asked in plain DNS
_FALLBACK = re.compile(
    r"(?:https://(?P<h>[0-9.]+)(?::\d{1,5})?/\S*|(?:tls|quic)://(?P<t>[0-9.]+)(?::\d{1,5})?)"
)


def fallback_host(item: str) -> str | None:
    """The IPv4 address an encrypted upstream written by address names (`https://198.51.100.9/dns-query`,
    `tls://198.51.100.9`), or None for any other form: a host name, plain DNS, another scheme."""
    m = _FALLBACK.fullmatch(item)
    if not m:
        return None
    host = m.group("h") or m.group("t")
    try:
        return str(ipaddress.IPv4Address(host))
    except ValueError:
        return None


def _check_adguard_keys(s: Settings) -> None:
    """(lists) The AdGuard settings the plan writes: intervals AdGuard accepts, and a fallback that is a
    second resolver by address, encrypted, and not one of the upstreams again (a fallback on the same
    addresses fails with them, which is the outage it exists for)."""
    for key, days in (("QUERYLOG_DAYS", s.querylog_days), ("STATS_DAYS", s.stats_days)):
        if days not in ADGUARD_DAYS:
            raise ValueError(f"{key}={days} in tvgw.conf: AdGuard Home keeps 1 to 365 days")
    items = [x.strip() for x in s.dns_fallback.split(",") if x.strip()]
    upstreams = {fallback_host(x.strip()) or x.strip() for x in s.dns_upstreams.split(",") if x.strip()}
    for item in items:
        host = fallback_host(item)
        if host is None:
            raise ValueError(
                f"DNS_FALLBACK={item!r} in tvgw.conf: expected an encrypted resolver by IPv4 address,"
                " such as https://198.51.100.9/dns-query or tls://198.51.100.9"
            )
        if host in upstreams:
            raise ValueError(
                f"DNS_FALLBACK={item!r} in tvgw.conf: {host} is already an upstream; the fallback must be"
                " a second operator"
            )


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


# ---- writing the settings file (tvgw setup) -------------------------------------------------------
# (setup) The writer edits the owner's file in place: comments, blank lines, order, keys it does not
# know and lines it cannot parse all stay as they were, and only the value of a changed key moves.
# Keys the shell scripts read but Settings does not, each with the check the scripts rely on.
SHELL_KEYS = {
    "WAN_GW": "ipv4",  # tvgw-apply: the home router, the direct uplink's next hop
    "URL_FILTER_RESOLVER": "ipv4",  # install.sh writes it into nginx with sed
    "DOH_LIST_URL": "url",  # tvgw-doh-update fetches it
}
PLACEHOLDER_MAC = "00:00:00:00:00:00"  # the template's "TV not identified yet"
_MAC = re.compile(r"(?:[0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}")
_TV_NAME = re.compile(r"[A-Za-z0-9_-]{1,63}")  # what install.sh lets through to dnsmasq
# What a value may contain. The file is sourced by bash as root, so a value must never be shell syntax:
# no `$`, backtick, quote, backslash, `;&|<>()`, `~` (tilde expansion runs in an assignment), `#`
# (parse_conf ends an unquoted value there) or a newline. A space is allowed and forces quotes.
_SAFE_VALUE = re.compile(r"[A-Za-z0-9 _.,:/@%+=*-]*")
_KEY_AT = re.compile(r"^\s*([A-Z][A-Z0-9_]*)=")
ADDED_HEADER = "# ---- set by tvgw setup ----"
BASH = "/bin/bash"  # check_conf syntax-checks the result with it where it exists


def writable_keys() -> frozenset[str]:
    """Every key the writer accepts: the operator keys Settings reads plus the shell-only ones. Read at
    call time, so a key another change adds to CONF_KEYS is writable without touching the writer."""
    return frozenset(CONF_KEYS) | frozenset(SHELL_KEYS)


def check_value(key: str, value: str) -> None:
    """Refuse one value before it reaches the file: an unknown key (an answers-file typo must not
    vanish into the file unread), shell syntax, and the formats the shell side checks itself
    (install.sh stops on a malformed TV_MAC or TV_NAME only after it has started changing things)."""
    if key not in writable_keys():
        raise ValueError(f"{key}: not a tvgw.conf setting (known: {', '.join(sorted(writable_keys()))})")
    if not _SAFE_VALUE.fullmatch(value):
        raise ValueError(
            f"{key}={value!r}: letters, digits, spaces and _ . , : / @ % + = * - only "
            "(the shell scripts source this file)"
        )
    if key == "TV_MAC" and value and not _MAC.fullmatch(value):
        raise ValueError(f"TV_MAC={value!r}: expected six hex pairs, aa:bb:cc:dd:ee:ff")
    if key == "TV_NAME" and value and not _TV_NAME.fullmatch(value):
        raise ValueError(f"TV_NAME={value!r}: 1 to 63 letters, digits, - and _")
    kind = SHELL_KEYS.get(key)
    if kind == "ipv4" and value:
        try:
            ipaddress.IPv4Address(value)
        except ValueError:
            raise ValueError(f"{key}={value!r}: not an IPv4 address") from None
    if kind == "url" and value and not re.fullmatch(r"https://[A-Za-z0-9.-]+(?::\d{1,5})?/\S*", value):
        raise ValueError(f"{key}={value!r}: expected an https:// URL")


def _render(value: str, quote: str) -> str:
    """The value as the file carries it: in the quotes the line already used, else in double quotes
    when it holds a space (bash would run the rest as a command), else bare."""
    if quote or " " in value:
        q = quote or '"'
        return f"{q}{value}{q}"
    return value


def update_conf(text: str, changes: dict[str, str]) -> str:
    """`text` with each key in `changes` set, everything else byte for byte as it was. A key already in
    the file keeps its line, its quoting and, where the new value fits, the column its comment started
    in; a key the file lacks is appended under one header. Every occurrence of a repeated key is set, so
    whichever one a reader takes, it reads the new value. The result must load: it is refused whole,
    and nothing is returned, when `load()` would refuse it, so no file the writer produced can stop the
    next command."""
    for key, value in changes.items():
        check_value(key, value)
    lines = text.splitlines(keepends=True)
    seen: set[str] = set()
    for i, line in enumerate(lines):
        km = _KEY_AT.match(line)
        if not km or km.group(1) not in changes:
            continue
        key = km.group(1)
        body = line.rstrip("\r\n")
        end = line[len(body) :]
        m = _LINE.match(body)
        # `KEY=` followed by something parse_conf never read (an unquoted `#`), or a bare value with a
        # quote in it (the first line of a quoted value that runs on over several lines): what bash
        # reads there is not what parse_conf reads, so the writer cannot know which lines the value
        # spans. Replacing the line could leave the rest of the value behind as shell syntax.
        if m is None or (m.group(5) is not None and any(q in m.group(5) for q in "\"'")):
            raise ValueError(f"{key}: line {i + 1} is not a plain KEY=VALUE line; edit it by hand")
        quote = '"' if m.group(3) is not None else "'" if m.group(4) is not None else ""
        start, stop = m.span(2)
        new = _render(changes[key], quote)
        rest = body[stop:]
        if m.group(6) is not None:  # keep the comment's column when the new value leaves room for it
            gap = len(rest) - len(rest.lstrip())
            pad = max(1, gap + (stop - start) - len(new))
            rest = " " * pad + rest.lstrip()
        lines[i] = body[:start] + new + rest + (end or "\n")
        seen.add(key)
    missing = [k for k in changes if k not in seen]
    if missing:
        if lines and not lines[-1].endswith("\n"):
            lines[-1] += "\n"
        if not any(line.rstrip("\r\n") == ADDED_HEADER for line in lines):
            lines.append(("\n" if lines else "") + ADDED_HEADER + "\n")
        lines.extend(f"{k}={_render(changes[k], '')}\n" for k in missing)
    out = "".join(lines)
    check_conf(out)
    return out


def check_conf(text: str) -> Settings:
    """The Settings `text` gives, through the very `load()` every command starts with, or ValueError.
    The text goes through a private temporary file because `load()` reads a path; nothing else is
    written. Where bash is installed, the text must also pass `bash -n`: install.sh and tvgw-apply
    source it under `set -e`, and parse_conf skips lines it cannot read, so a file it accepts can
    still be one bash cannot parse. The TV side must pass `tv_side()`, the rules install.sh and
    tvgw-apply refuse a conf by: a file that broke them would leave the TV dark at the next boot."""
    import tempfile  # only the writer needs it

    with tempfile.TemporaryDirectory(prefix="tvgw-conf-") as d:
        p = Path(d) / "tvgw.conf"
        p.write_text(text, encoding="utf-8")
        settings = load(p)
    tv_side(settings)  # TV_IF, TV_NET, GW_IP and TV_IP together, as install.sh checks them
    if Path(BASH).exists():
        import subprocess

        r = subprocess.run(
            [BASH, "-n"], input=text, capture_output=True, encoding="utf-8", errors="replace", check=False
        )
        if r.returncode != 0:
            why = (r.stderr.strip().splitlines() or ["syntax error"])[-1]
            raise ValueError(f"the shell scripts could not source the result (bash -n: {why})")
    return settings


def conf_diff(old: str, new: str, path: str = "tvgw.conf") -> list[str]:
    """A unified diff of two versions of the settings file, for the owner to read before it is
    written: empty when they are the same."""
    import difflib

    return list(
        difflib.unified_diff(
            old.splitlines(), new.splitlines(), f"{path} (now)", f"{path} (after)", lineterm=""
        )
    )


def save_conf(
    path: str | Path, changes: dict[str, str], template: str = "", dry_run: bool = False
) -> list[str]:
    """Set `changes` in the settings file at `path` and return the diff (empty: nothing to do, nothing
    written). A missing file starts from `template`, the shipped example, so its comments come along, and
    the diff is against the template.
    The write is atomic and keeps the file's mode and owner (discover.write_conf), and `dry_run`
    computes the same diff without writing."""
    p = Path(path)
    try:
        old = p.read_text(encoding="utf-8")
        exists = True
    except FileNotFoundError:
        old, exists = template, False
    new = update_conf(old, changes)
    if exists and new == old:
        return []
    diff = conf_diff(old, new, str(p))
    if not dry_run:
        from tvgw import discover  # the one atomic writer of this file, shared with `tvgw discover --write`

        p.parent.mkdir(mode=0o755, parents=True, exist_ok=True)
        discover.write_conf(p, new)
    # a missing file is always written, even when the template needs no change: say so in one line
    return diff or [f"+++ {p} (new, the template as it is)"]
