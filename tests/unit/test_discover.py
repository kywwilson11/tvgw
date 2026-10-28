"""TV discovery: every source is parsed from captured text and the network is a fake."""

import json

import pytest

from tvgw import cli
from tvgw import discover as disc

LEASES = "1793175057 b4:b2:91:aa:bb:cc 10.10.10.17 LGwebOSTV 01:b4:b2:91:aa:bb:cc\n1793175000 02:11:22:33:44:55 10.10.10.12 * 01:02:11:22:33:44:55\n"
NEIGH = json.dumps(
    [
        {"dst": "10.10.10.17", "dev": "eth0", "lladdr": "B4:B2:91:AA:BB:CC", "state": ["REACHABLE"]},
        {"dst": "10.10.10.99", "dev": "eth0", "lladdr": "aa:aa:aa:aa:aa:aa", "state": ["STALE"]},
        {"dst": "10.10.10.1", "dev": "eth0", "state": ["FAILED"]},
    ]
)
JOURNAL = (
    "DHCPDISCOVER(eth0) 02:11:22:33:44:55\nDHCPOFFER(eth0) 10.10.10.12 02:11:22:33:44:55\n"
    "DHCPREQUEST(eth0) 10.10.10.12 02:11:22:33:44:55\nclient provides name: Roku-Ultra\nDHCPACK(eth0) 10.10.10.12 02:11:22:33:44:55 Roku-Ultra\n"
)
SSDP = (
    b"HTTP/1.1 200 OK\r\nCACHE-CONTROL: max-age=1800\r\nLOCATION: http://10.10.10.17:1140/description.xml\r\n"
    b"SERVER: WebOS/5.6.2 UPnP/1.0\r\nST: urn:lge-com:service:webos-second-screen:1\r\nUSN: uuid:abc::urn:lge-com:service:webos-second-screen:1\r\n\r\n"
)
XML = """<?xml version="1.0"?><root xmlns="urn:schemas-upnp-org:device-1-0"><device>
<deviceType>urn:schemas-upnp-org:device:Basic:1</deviceType><friendlyName>[LG] webOS TV OLED55CXPUA</friendlyName>
<manufacturer>LG Electronics</manufacturer><modelName>OLED55CXPUA</modelName><modelNumber>
  1.0 </modelNumber><UDN>uuid:abc</UDN></device></root>"""


def lg_ports(ip, port):
    return ip == "10.10.10.17" and port in (3000, 3001)


def test_parse_leases_and_neigh_and_dhcp_names():
    assert disc.parse_leases(LEASES) == [
        ("b4:b2:91:aa:bb:cc", "10.10.10.17", "LGwebOSTV"),
        ("02:11:22:33:44:55", "10.10.10.12", ""),
    ]
    assert disc.parse_leases("garbage\n1 notamac 1.2.3.4 x\n") == []
    assert disc.parse_neigh(NEIGH) == [
        ("10.10.10.17", "b4:b2:91:aa:bb:cc", "REACHABLE"),
        ("10.10.10.99", "aa:aa:aa:aa:aa:aa", "STALE"),
    ]
    assert disc.parse_neigh("not json") == [] and disc.parse_neigh("") == []
    assert disc.dhcp_names(JOURNAL) == {"02:11:22:33:44:55": "Roku-Ultra"}


def test_fingerprint_and_hostname_hints():
    sig, ev = disc.fingerprint("10.10.10.17", lg_ports)
    assert sig == ("LG", "webOS", "lg-webos") and ev == ["tcp 3000/3001 open (webOS LAN API)"]
    sig, ev = disc.fingerprint(
        "10.10.10.12", lambda ip, p: p == 3000
    )  # half a signature is evidence, not a verdict
    assert sig is None and ev == ["tcp 3000 open"]
    assert disc.fingerprint("10.10.10.12", lambda ip, p: False) == (None, [])
    assert disc.hostname_hint("LGwebOSTV") == ("LG", "webOS", "lg-webos")
    assert disc.hostname_hint("Roku-Ultra") == ("Roku", "Roku OS", None)
    assert disc.hostname_hint("printer") is None


def test_ssdp_and_description_parsing():
    hdr = disc.parse_ssdp(SSDP)
    assert hdr["location"] == "http://10.10.10.17:1140/description.xml" and hdr["st"].startswith(
        "urn:lge-com"
    )
    d = disc.parse_description(XML)
    assert d == {
        "friendlyName": "[LG] webOS TV OLED55CXPUA",
        "manufacturer": "LG Electronics",
        "modelName": "OLED55CXPUA",
        "modelNumber": "1.0",
        "UDN": "uuid:abc",
    }


def test_discover_merges_sources_and_excludes_the_gateway():
    cands = disc.discover(
        "eth0",
        "10.10.10.1",
        leases_text=LEASES,
        neigh_json=NEIGH,
        journal_text=JOURNAL,
        probe=lg_ports,
        ssdp=lambda bind_ip: {"10.10.10.17": disc.parse_ssdp(SSDP)},
        describe=lambda url: disc.parse_description(XML),
    )
    by_ip = {c.ip: c for c in cands}
    assert "10.10.10.1" not in by_ip
    tv = by_ip["10.10.10.17"]
    assert (tv.mac, tv.hostname, tv.vendor, tv.platform, tv.model, tv.profile) == (
        "b4:b2:91:aa:bb:cc",
        "LGwebOSTV",
        "LG",
        "webOS",
        "OLED55CXPUA",
        "lg-webos",
    )
    assert (
        "DHCP lease (announced as LGwebOSTV)" in tv.evidence and "neighbour table (REACHABLE)" in tv.evidence
    )
    assert any(e.startswith("SSDP: [LG] webOS TV") for e in tv.evidence)
    roku = by_ip["10.10.10.12"]
    assert (roku.hostname, roku.vendor, roku.profile) == (
        "Roku-Ultra",
        "Roku",
        None,
    )  # name from the DHCP log
    assert by_ip["10.10.10.99"].mac == "aa:aa:aa:aa:aa:aa" and by_ip["10.10.10.99"].vendor == ""
    assert cands[0].ip == "10.10.10.17"  # the one with a profile sorts first


def test_discover_without_a_network_still_lists_leases():
    cands = disc.discover("eth0", "10.10.10.1", leases_text=LEASES, probe=lambda ip, p: False)
    assert [c.ip for c in cands] == ["10.10.10.17", "10.10.10.12"]
    assert cands[0].profile == "lg-webos"  # the announced hostname alone identifies webOS


def test_safe_name_and_write_identity_keep_the_file_readable():
    assert disc.safe_name("LGwebOSTV") == "lgwebostv" and disc.safe_name("[LG] TV") == "lgtv"
    assert disc.safe_name("") == "tv" and len(disc.safe_name("x" * 100)) == 32
    conf = "# site\nTV_MAC=00:00:00:00:00:00   # wired MAC of the TV\nTV_IP=10.10.10.17\nTV_NAME=tv\nWAN_IF=wlan0\n"
    out = disc.write_identity(conf, "b4:b2:91:aa:bb:cc", "10.10.10.17", "lgwebostv", "lg-webos")
    assert out.splitlines() == [
        "# site",
        "TV_MAC=b4:b2:91:aa:bb:cc   # wired MAC of the TV",
        "TV_IP=10.10.10.17",
        "TV_NAME=lgwebostv",
        "WAN_IF=wlan0",
        "PROFILE=lg-webos",
    ]
    again = disc.write_identity(out, "b4:b2:91:aa:bb:cc", "10.10.10.17", "lgwebostv", None)
    assert again == out  # idempotent; an unknown profile leaves PROFILE alone
    assert disc.write_identity("", "aa:bb:cc:dd:ee:ff", "10.10.10.12", "roku", None).splitlines() == [
        "TV_MAC=aa:bb:cc:dd:ee:ff",
        "TV_IP=10.10.10.12",
        "TV_NAME=roku",
    ]


def test_render_lists_evidence():
    c = disc.Candidate(
        ip="10.10.10.17",
        mac="b4:b2:91:aa:bb:cc",
        hostname="LGwebOSTV",
        vendor="LG",
        platform="webOS",
        profile="lg-webos",
        evidence=["DHCP lease"],
    )
    lines = disc.render([c])
    assert (
        lines[0].startswith("1. 10.10.10.17  b4:b2:91:aa:bb:cc  LGwebOSTV  LG webOS")
        and lines[-1] == "      profile: lg-webos"
    )


def test_cli_discover_json_and_write(monkeypatch, tmp_path, capsys):
    conf = tmp_path / "tvgw.conf"
    conf.write_text("TV_MAC=00:00:00:00:00:00\nTV_IP=10.10.10.17\nTV_NAME=tv\nPROFILE=lg-webos\n")
    tv = disc.Candidate(
        ip="10.10.10.17",
        mac="b4:b2:91:aa:bb:cc",
        hostname="LGwebOSTV",
        vendor="LG",
        platform="webOS",
        profile="lg-webos",
        evidence=["DHCP lease"],
    )
    monkeypatch.setattr(disc, "gather", lambda iface, gw_ip, with_ssdp=True: [tv])
    assert cli.main(["--conf", str(conf), "discover", "--json"]) == 0
    assert json.loads(capsys.readouterr().out)[0]["profile"] == "lg-webos"
    assert cli.main(["--conf", str(conf), "discover", "--write", "--yes"]) == 0
    out = capsys.readouterr().out
    assert "wrote TV_MAC, TV_IP, TV_NAME, PROFILE" in out
    assert "TV_MAC=b4:b2:91:aa:bb:cc" in conf.read_text() and "TV_NAME=lgwebostv" in conf.read_text()
    monkeypatch.setattr(disc, "gather", lambda iface, gw_ip, with_ssdp=True: [])
    assert cli.main(["--conf", str(conf), "discover"]) == 1
    assert "no device found" in capsys.readouterr().out


def test_cli_discover_refuses_to_guess_between_several_without_a_terminal(monkeypatch, tmp_path):
    conf = tmp_path / "tvgw.conf"
    conf.write_text("TV_MAC=00:00:00:00:00:00\n")
    two = [
        disc.Candidate(ip="10.10.10.17", mac="b4:b2:91:aa:bb:cc"),
        disc.Candidate(ip="10.10.10.12", mac="02:11:22:33:44:55"),
    ]
    monkeypatch.setattr(disc, "gather", lambda iface, gw_ip, with_ssdp=True: two)
    monkeypatch.setattr("sys.stdin", type("S", (), {"isatty": staticmethod(lambda: False)})())
    with pytest.raises(SystemExit, match="several devices"):
        cli.main(["--conf", str(conf), "discover", "--write"])


@pytest.mark.parametrize(
    "url",
    [
        "file:///etc/shadow",
        "http://127.0.0.1:3000/control/status",
        "http://10.10.10.1/description.xml",
        "https://10.10.10.17/description.xml",
        "http://root@10.10.10.17/description.xml",
        "http://10.10.10.17:99999/description.xml",
        "http://10.10.10.17:abc/description.xml",
        "http://lgtv.local/description.xml",
        "http:///description.xml",
        "",
    ],
)
def test_location_ok_refuses_anything_but_http_to_the_responder(url):
    assert not disc.location_ok(url, "10.10.10.17")


def test_location_ok_accepts_the_responder_itself():
    assert disc.location_ok("http://10.10.10.17:1140/description.xml", "10.10.10.17")
    assert disc.location_ok("http://10.10.10.17/", "10.10.10.17")


def test_fetch_description_is_pinned_and_http_only(monkeypatch):
    opened = []

    class Resp:
        def __init__(self, body):
            self.body = body

        def __enter__(self):
            return self

        def __exit__(self, *a):
            return False

        def read(self, n):
            return self.body[:n]

    class Opener:
        def open(self, url, timeout):
            opened.append(url)
            return Resp(XML.encode())

    monkeypatch.setattr(disc, "_OPENER", Opener())
    assert disc.fetch_description("file:///etc/shadow") == {}
    assert disc.fetch_description("http://127.0.0.1:3000/", responder_ip="10.10.10.17") == {}
    assert disc.fetch_description("http://10.10.10.17:1140/d.xml", responder_ip="10.10.10.17")[
        "modelName"
    ] == ("OLED55CXPUA")
    assert opened == ["http://10.10.10.17:1140/d.xml"]


def test_redirects_are_refused_and_the_opener_speaks_only_http():
    assert disc._NoRedirect().redirect_request(None, None, 302, "Found", {}, "http://10.10.10.1/") is None
    kinds = {type(h).__name__ for h in disc._OPENER.handlers}
    assert "FileHandler" not in kinds and "HTTPSHandler" not in kinds and "ProxyHandler" not in kinds
    assert "HTTPHandler" in kinds and "_NoRedirect" in kinds
    # a file:// URL is an "unknown url type" to this opener, which fetch_description turns into nothing
    with pytest.raises(OSError):
        disc._OPENER.open("file:///etc/hostname", timeout=1)


def test_discover_does_not_fetch_a_location_that_points_elsewhere():
    hdr = disc.parse_ssdp(SSDP.replace(b"http://10.10.10.17:1140", b"http://127.0.0.1:3000"))

    def never(url):
        raise AssertionError(f"fetched {url}")

    cands = disc.discover(
        "eth0",
        "10.10.10.1",
        leases_text=LEASES,
        probe=lambda ip, port: False,
        ssdp=lambda bind_ip: {"10.10.10.17": hdr},
        describe=never,
    )
    tv = {c.ip: c for c in cands}["10.10.10.17"]
    assert tv.model is None or tv.model == ""
    assert any("points off-device" in e for e in tv.evidence)


class FakeNft:
    """`nft` as run_cmd sees it: insert, `-a list chain` with handles, delete by handle."""

    def __init__(self, loaded=True):
        self.loaded, self.rules, self.next = loaded, {}, 40

    def __call__(self, cmd):
        if cmd[:3] == ["nft", "insert", "rule"] and self.loaded:
            self.next += 1
            self.rules[self.next] = (cmd[5], " ".join(cmd[6:]))
        elif cmd[:4] == ["nft", "-a", "list", "chain"] and self.loaded:
            return "".join(
                f"\t\t{text} # handle {h}\n" for h, (chain, text) in self.rules.items() if chain == cmd[6]
            )
        elif cmd[:3] == ["nft", "delete", "rule"]:
            self.rules.pop(int(cmd[-1]))
        return ""

    def chain(self, name):
        return [text for chain, text in self.rules.values() if chain == name]


def test_the_ssdp_exemption_lets_the_answers_in_and_closes_both_ways(monkeypatch):
    """The output chain drops the Pi's multicast into the TV subnet and the input chain drops what the
    TV sends to any other Pi port: an answer to the search comes back by unicast from the TV to the
    socket's port, which conntrack cannot tie to a search sent to 239.255.255.250, so only an output
    exemption let every search out and no answer in. Both holes are the socket's, for the search only."""
    nft = FakeNft()
    monkeypatch.setattr(disc, "run_cmd", nft)
    seen = {}

    def search(bind_ip, timeout=4.0, on_bound=None):
        on_bound(54321)  # the port the socket was bound to, before anything is sent
        seen["input"], seen["output"] = nft.chain("input"), nft.chain("output")
        return {"10.10.10.17": {"location": "http://10.10.10.17:1140/description.xml"}}

    monkeypatch.setattr(disc, "ssdp_search", search)
    assert disc._ssdp_with_exemption("eth0")("10.10.10.1") == {
        "10.10.10.17": {"location": "http://10.10.10.17:1140/description.xml"}
    }
    assert seen["output"] == ["oifname eth0 udp dport 1900 counter accept comment tvgw-discover"]
    assert seen["input"] == [
        "iifname eth0 ip daddr 10.10.10.1 udp dport 54321 counter accept comment tvgw-discover"
    ]
    assert nft.rules == {}  # both closed again


def test_without_the_firewall_the_search_runs_with_no_exemption(monkeypatch):
    nft = FakeNft(loaded=False)
    monkeypatch.setattr(disc, "run_cmd", nft)
    calls = []

    def search(bind_ip, timeout=4.0, on_bound=None):
        calls.append(on_bound)
        if on_bound:
            on_bound(54321)
        return {}

    monkeypatch.setattr(disc, "ssdp_search", search)
    assert disc._ssdp_with_exemption("eth0")("10.10.10.1") == {} and nft.rules == {}
    assert calls == [None]


def test_the_search_socket_reports_its_port_before_it_sends(monkeypatch):
    """The input exemption names the port, so the socket is bound before the first M-SEARCH."""
    events = []

    class Sock:
        def __init__(self, *a):
            pass

        def setsockopt(self, *a):
            pass

        def settimeout(self, t):
            pass

        def bind(self, addr):
            events.append(("bind", addr))

        def getsockname(self):
            return ("0.0.0.0", 54321)

        def sendto(self, msg, addr):
            events.append(("sendto", addr))
            raise OSError("no route")  # ends the search here, with nothing on the wire

        def close(self):
            events.append(("close",))

    monkeypatch.setattr(disc.socket, "socket", Sock)
    assert disc.ssdp_search("10.10.10.1", on_bound=lambda port: events.append(("bound", port))) == {}
    assert events == [("bind", ("", 0)), ("bound", 54321), ("sendto", disc.SSDP_GROUP), ("close",)]
