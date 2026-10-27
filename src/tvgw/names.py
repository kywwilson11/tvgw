"""Hostname hygiene: which names belong to the internet, as opposed to the LAN, mDNS, reverse lookups
or bare IP literals (`239.255.255.250:1900` from SSDP, the TV asking for its own short name)."""

from __future__ import annotations

import ipaddress
import math
import re

LOCAL_SUFFIXES = (".local", ".arpa", ".lan", ".home", ".internal", ".localdomain", ".localhost")
_LABEL = re.compile(r"^[a-z0-9_](?:[a-z0-9_-]*[a-z0-9_])?$")


def normalize(name: str) -> str:
    """Lower-case, no surrounding space, no trailing dot, no `:port` suffix."""
    n = name.strip().lower().rstrip(".")
    if n.count(":") == 1:  # host:port (an IPv6 literal has more colons)
        n = n.split(":", 1)[0]
    return n


def is_public_name(name: str) -> bool:
    """True for a DNS name that lives on the internet: at least one dot, an alphabetic last label,
    valid labels within the RFC 1035 lengths (a longer string is not a name), no local suffix and
    not an IP literal."""
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
    return labels[-1].isalpha() and all(len(lb) <= 63 and _LABEL.match(lb) for lb in labels)


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
