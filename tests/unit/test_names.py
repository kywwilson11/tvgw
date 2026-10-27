"""Hostname hygiene: public names, registrable domains, entropy."""

import pytest

from tvgw.names import is_public_name, normalize, registrable_domain, shannon_entropy


@pytest.mark.parametrize(
    ("name", "public"),
    [
        ("us.lgtvsdp.com", True),
        ("US.LGTVSDP.COM.", True),
        ("29773.v.fwmrm.net", True),
        ("_dns-sd._udp.example.com", True),
        ("xn--bcher-kva.example", True),
        ("lgcx", False),  # the TV asking for its own short name
        ("239.255.255.250:1900", False),  # SSDP over HTTP
        ("10.10.10.1", False),
        ("fe80::1", False),
        ("kylepi5.local", False),
        ("17.10.10.10.in-addr.arpa", False),
        ("printer.lan", False),
        ("router.home", False),
        ("example.com123", False),  # a numeric-looking TLD is not a TLD
        ("bad-.example.com", False),
        ("", False),
        (" . ", False),
    ],
)
def test_is_public_name(name, public):
    assert is_public_name(name) is public


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
