"""Hostname and address hygiene: which names belong to the internet, as opposed to the LAN, mDNS,
reverse lookups or bare IP literals (`239.255.255.250:1900` from SSDP, the TV asking for its own short
name), and which addresses the firewall calls the home LAN."""

from __future__ import annotations

import ipaddress
import math
import re

LOCAL_SUFFIXES = (".local", ".arpa", ".lan", ".home", ".internal", ".localdomain", ".localhost")
_LABEL = re.compile(r"^[a-z0-9_](?:[a-z0-9_-]*[a-z0-9_])?$")

# tvgw-apply's lan4 set: what the firewall drops as "the home LAN"
LAN_NETS = tuple(
    ipaddress.ip_network(n)
    for n in ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "100.64.0.0/10", "169.254.0.0/16")
)
# ...plus the ranges no internet host answers from (240/4 covers the broadcast address). Explicit
# networks on purpose: `ipaddress.is_private` differs between 3.11 (the Pi) and 3.13 (CI) for
# 100.64/10 and 0/8, and calls the documentation ranges private
_NOT_PUBLIC = LAN_NETS + tuple(
    ipaddress.ip_network(n) for n in ("0.0.0.0/8", "127.0.0.0/8", "224.0.0.0/4", "240.0.0.0/4")
)


def _addr(ip: str) -> ipaddress.IPv4Address | None:
    try:
        a = ipaddress.ip_address(ip)
    except ValueError:
        return None
    return a if isinstance(a, ipaddress.IPv4Address) else None


def is_lan_address(ip: str) -> bool:
    """True for an IPv4 address in the firewall's lan4 set: the ranges the TV may never reach."""
    a = _addr(ip)
    return a is not None and any(a in net for net in LAN_NETS)


def is_local_address(ip: str) -> bool:
    """True for an IPv4 address no internet host answers from: the LAN ranges, loopback, multicast,
    the "this network" and broadcast ranges. A TV connecting to one is probing its surroundings."""
    a = _addr(ip)
    return a is not None and any(a in net for net in _NOT_PUBLIC)


def is_public_address(ip: str) -> bool:
    """True for an IPv4 address an internet host can answer from."""
    a = _addr(ip)
    return a is not None and not any(a in net for net in _NOT_PUBLIC)


def reverse_ptr(qname: str) -> str | None:
    """The address a reverse lookup asks about: `4.3.2.1.in-addr.arpa` -> `1.2.3.4`; None for any
    other name."""
    labels = normalize(qname).split(".")
    if len(labels) != 6 or labels[4:] != ["in-addr", "arpa"]:
        return None
    return ".".join(reversed(labels[:4]))


def normalize(name: str) -> str:
    """Lower-case, no surrounding space, no trailing dot, no `:port` suffix."""
    n = name.strip().lower().rstrip(".")
    if n.count(":") == 1:  # host:port (an IPv6 literal has more colons)
        n = n.split(":", 1)[0]
    return n


def is_public_name(name: str) -> bool:
    """True for a DNS name that lives on the internet: at least one dot, an alphabetic (or punycode)
    last label, valid labels within the RFC 1035 lengths (a longer string is not a name), no local
    suffix and not an IP literal."""
    n = normalize(name)
    if not n or "." not in n or n.endswith(LOCAL_SUFFIXES) or len(n) > 253:
        return False
    try:
        ipaddress.ip_address(n)
    except ValueError:
        pass
    else:
        return False
    labels = n.split(".")
    if not (labels[-1].isalpha() or labels[-1].startswith("xn--")):
        return False
    return all(len(lb) <= 63 and _LABEL.match(lb) for lb in labels)


# Suffixes under which the next label is a separate tenant, not a sub-service: the country
# second-level suffixes a TV meets plus the cloud/CDN ones (the Public Suffix List says the same;
# a full copy is not worth a dependency for grouping the few hundred names a TV talks to).
PUBLIC_SUFFIXES = frozenset(
    {
        "co.uk",
        "org.uk",
        "ac.uk",
        "gov.uk",
        "com.au",
        "net.au",
        "org.au",
        "co.jp",
        "ne.jp",
        "or.jp",
        "co.kr",
        "com.br",
        "com.cn",
        "com.mx",
        "com.tw",
        "co.nz",
        "co.in",
        "com.sg",
        "com.hk",
        "co.za",
        "com.ar",
        "com.tr",
        "cloudfront.net",
        "amazonaws.com",
        "azure-devices.net",
        "azurewebsites.net",
        "akamaized.net",
        "akamaihd.net",
        "edgesuite.net",
        "edgekey.net",
        "fastly.net",
        "herokuapp.com",
        "github.io",
        "googleusercontent.com",
        "cdn77.org",
    }
)


def registrable_domain(name: str) -> str:
    """The part of a name its owner registered: `cdn-0.nflximg.com` -> `nflximg.com`,
    `d1.cloudfront.net` stays itself (each tenant is a different party)."""
    n = normalize(name)
    labels = n.split(".")
    if len(labels) <= 2:
        return n
    for k in (3, 2):
        if len(labels) > k and ".".join(labels[-k:]) in PUBLIC_SUFFIXES:
            return ".".join(labels[-(k + 1) :])
    return ".".join(labels[-2:])


def shannon_entropy(text: str) -> float:
    """Bits per character; 0 for the empty string or a single repeated character."""
    if not text:
        return 0.0
    counts: dict[str, int] = {}
    for ch in text:
        counts[ch] = counts.get(ch, 0) + 1
    n = len(text)
    return -sum(c / n * math.log2(c / n) for c in counts.values())
