"""Hostname and address hygiene: public names, LAN and public addresses, reverse names, registrable
domains, entropy."""

import pytest

from tvgw.names import (
    is_lan_address,
    is_local_address,
    is_public_address,
    is_public_name,
    normalize,
    registrable_domain,
    reverse_ptr,
    shannon_entropy,
)


@pytest.mark.parametrize(
    ("name", "public"),
    [
        ("us.lgtvsdp.com", True),
        ("US.LGTVSDP.COM.", True),
        ("29773.v.fwmrm.net", True),
        ("_dns-sd._udp.example.com", True),
        ("xn--bcher-kva.example", True),
        ("data.exfil.xn--p1ai", True),  # a punycode TLD is still a TLD
        ("lgcx", False),  # the TV asking for its own short name
        ("239.255.255.250:1900", False),  # SSDP over HTTP
        ("10.10.10.1", False),
        ("fe80::1", False),
        ("pi.local", False),
        ("17.10.10.10.in-addr.arpa", False),
        ("printer.lan", False),
        ("router.home", False),
        ("example.com123", False),  # a numeric-looking TLD is not a TLD
        ("bad-.example.com", False),
        ("", False),
        (" . ", False),
        # RFC 1035: 63 characters per label, 253 for the whole name; longer strings are not names
        ("a" * 64 + ".example.com", False),
        ("a" * 63 + ".example.com", True),
        (".".join(["a" * 62] * 4) + ".a", True),  # 253 characters: the longest a name can be
        (".".join(["a" * 62] * 4) + ".ab", False),  # 254
        ("b" * 300, False),
    ],
)
def test_is_public_name(name, public):
    assert is_public_name(name) is public


@pytest.mark.parametrize(
    ("ip", "lan", "public"),
    [
        ("10.1.2.3", True, False),
        ("172.15.0.1", False, True),  # just below 172.16/12
        ("172.16.0.1", True, False),
        ("172.18.0.1", True, False),  # the old LIKE patterns missed 172.18 and 172.19
        ("172.19.0.1", True, False),
        ("172.31.255.255", True, False),
        ("172.32.0.1", False, True),  # the old patterns counted 172.32 to 172.39
        ("192.168.77.69", True, False),
        ("169.254.1.1", True, False),
        ("100.64.0.1", True, False),  # CGNAT: in the firewall's lan4 set, not private to Python 3.13
        ("100.127.255.255", True, False),
        ("100.128.0.1", False, True),
        ("224.0.0.1", False, False),  # multicast: neither
        ("127.0.0.1", False, False),
        ("0.0.0.0", False, False),
        ("255.255.255.255", False, False),
        ("240.0.0.1", False, False),
        ("203.0.113.4", False, True),  # TEST-NET-3: private to Python's ipaddress, public to the firewall
        ("8.8.8.8", False, True),
        ("garbage", False, False),
        ("fe80::1", False, False),
    ],
)
def test_lan_and_public_addresses_follow_the_firewall_not_the_python_version(ip, lan, public):
    assert is_lan_address(ip) is lan and is_public_address(ip) is public


@pytest.mark.parametrize(
    ("ip", "local"),
    [
        ("239.255.255.250", True),  # multicast (SSDP)
        ("169.254.7.7", True),  # link-local
        ("0.0.0.0", True),  # unspecified
        ("255.255.255.255", True),  # broadcast
        ("192.168.77.69", True),  # private
        ("100.64.0.1", True),  # CGNAT: in the firewall's lan4 set
        ("203.0.113.4", False),  # TEST-NET-3: not a LAN, whatever Python's is_private says
        ("23.5.6.43", False),  # the internet
        ("not an address", False),
    ],
)
def test_local_addresses_cover_every_class_a_lan_probe_can_aim_at(ip, local):
    """ingest records a TV SYN to one of these (the gateway excepted) as a LAN probe."""
    assert is_local_address(ip) is local


def test_reverse_ptr_reads_a_full_in_addr_arpa_name_only():
    assert reverse_ptr("4.3.2.1.in-addr.arpa") == "1.2.3.4"
    assert reverse_ptr("69.77.168.192.IN-ADDR.ARPA.") == "192.168.77.69"
    assert reverse_ptr("x.in-addr.arpa") is None and reverse_ptr("1.2.3.in-addr.arpa") is None
    assert reverse_ptr("1.2.3.4.5.in-addr.arpa") is None and reverse_ptr("us.lgtvsdp.com") is None


def test_normalize_strips_port_case_and_trailing_dot():
    assert normalize(" Example.COM:8080. ") == "example.com"  # trailing dot first, then nothing else to strip
    assert normalize("Example.COM.") == "example.com"
    assert normalize("[::1]:53") == "[::1]:53"  # an IPv6 literal keeps its colons


@pytest.mark.parametrize(
    ("name", "domain"),
    [
        ("cdn-0.nflximg.com", "nflximg.com"),
        ("rr4---sn-bvvbaxivnuxqjvhj5nu-n4v6.googlevideo.com", "googlevideo.com"),
        ("example.com", "example.com"),
        ("com", "com"),
        ("www.bbc.co.uk", "bbc.co.uk"),
        ("d184dfn36gombl.cloudfront.net", "d184dfn36gombl.cloudfront.net"),
        ("a16i6ajbm83mvw-ats.iot.us-west-2.amazonaws.com", "us-west-2.amazonaws.com"),
        ("yt3.googleusercontent.com", "yt3.googleusercontent.com"),
        ("AIC.service.lgtvcommon.com.", "lgtvcommon.com"),
    ],
)
def test_registrable_domain(name, domain):
    assert registrable_domain(name) == domain


def test_shannon_entropy():
    assert shannon_entropy("") == 0.0 and shannon_entropy("aaaa") == 0.0
    assert shannon_entropy("ab") == 1.0
    assert 3.5 < shannon_entropy("x7k2p9q4m1z8w3v6") <= 4.0
    assert shannon_entropy("googlevideo") < shannon_entropy("x7k2p9q4m1z8w3v6")
