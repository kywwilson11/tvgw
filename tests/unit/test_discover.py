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
    assert [c.ip for c in cands] == ["10.10.10.12", "10.10.10.17"]  # no profile either: by address
    # (profile) the announced host name alone names the vendor, never the profile (design decision 62)
    lg = cands[1]
    assert (lg.vendor, lg.platform, lg.profile) == ("LG", "webOS", None)


# ---- (profile) assignment on evidence (design decision 62) -------------------------------------------
PROFILES = disc.bundled_profiles()


def device(hostname="", ports=(), targets=(), vendor="", rest="") -> disc.Candidate:
    return disc.Candidate(
        ip="10.10.10.17", hostname=hostname, vendor=vendor, open_ports=list(ports), ssdp_targets=list(targets),
        rest=rest,
    )  # fmt: skip


@pytest.mark.parametrize(
    ("dev", "profile", "vendor"),
    [
        (device("LGwebOSTV", (3000, 3001)), "lg-webos", "LG"),  # the CX: the ports and the name agree
        (device(targets=["urn:lge-com:service:webos-second-screen:1"]), "lg-webos", "LG"),  # LG's own target
        (device(ports=(3000, 3001)), None, "LG"),  # the ports alone
        (device("LGwebOSTV"), None, "LG"),  # the name alone
        (device("LGwebOSTV", (3000,)), None, "LG"),  # half the ports and the name
        (device("Roku-1", (3000, 3001)), None, "LG"),  # rows that disagree: the ports' vendor
        (device("Samsung-TV", (8001, 8002)), None, "Samsung"),  # ports and name: Samsung, no profile
        (
            device("Samsung-TV", (8001, 8002), rest="tv"),
            "samsung-tizen",
            "Samsung",
        ),  # (samsung) its own reply
        (device(rest="tv"), "samsung-tizen", "Samsung"),  # the reply is the one signal that is enough
        (device("Samsung-Soundbar", (8001, 8002), vendor="Samsung", rest="not-tv"), None, "Samsung"),
        (device(ports=(8060,)), None, "Roku"),
        (device(ports=(8008, 8009)), None, "Google"),  # Cast only
        (device("localhost"), None, ""),  # no signal
        (device(targets=["upnp:rootdevice", "urn:dial-multiscreen-org:service:dial:1"]), None, ""),
        (device(vendor="Samsung"), None, "Samsung"),  # a UPnP manufacturer alone
    ],
    ids=lambda v: str(v) if not isinstance(v, disc.Candidate) else f"{v.hostname}-{v.open_ports}",
)
def test_a_profile_is_assigned_only_on_evidence(dev, profile, vendor):
    a = disc.assign(dev, PROFILES)
    assert (a.profile, a.vendor) == (profile, vendor) and a.evidence


def test_the_evidence_says_what_decided():
    cx = disc.assign(device("LGwebOSTV", (3000, 3001)), PROFILES)
    assert cx.evidence == ("tcp 3000/3001 open and the host name 'LGwebOSTV' agree",)
    ports = disc.assign(device(ports=(3000, 3001)), PROFILES)
    assert ports.evidence == ("one signal names LG (tcp 3000/3001 open): no profile on that alone",)
    target = disc.assign(device(targets=[disc.SSDP_SIGNATURES[0][0]]), PROFILES)
    assert target.evidence == ("answered LG's own SSDP search target",)
    mixed = disc.assign(device("Roku-1", (3000, 3001)), PROFILES)
    assert mixed.evidence == (
        "tcp 3000/3001 open and the host name 'Roku-1' name different vendors: no profile",
    )
    assert disc.assign(device(), PROFILES).evidence == ("no signal names a vendor",)
    samsung = disc.assign(device("Samsung-TV", (8001, 8002)), PROFILES)
    assert samsung.evidence == (
        "tcp 8001/8002 open and the host name 'Samsung-TV' name Samsung, and no discovery row gives it a "
        "profile offered here",
    )
    upnp = disc.assign(device(vendor="Samsung"), PROFILES)
    assert upnp.evidence == ("one signal names Samsung (its UPnP description): no profile on that alone",)


def test_a_profile_that_is_not_offered_is_never_assigned():
    others = [p for p in PROFILES if p.name != "lg-webos"]
    a = disc.assign(device("LGwebOSTV", (3000, 3001), [disc.SSDP_SIGNATURES[0][0]]), others)
    assert (a.profile, a.vendor) == (None, "LG")
    no_samsung = [p for p in PROFILES if p.name != "samsung-tizen"]  # (samsung)
    assert disc.assign(device("Samsung-TV", (8001, 8002), rest="tv"), no_samsung).profile is None


def test_a_vendor_names_its_bundled_profile_and_the_general_one_has_no_vendor():
    assert disc.vendor_profile("LG", PROFILES) == "lg-webos"
    assert disc.vendor_profile("Samsung", PROFILES) == "samsung-tizen"
    assert disc.vendor_profile("Roku", PROFILES) == "roku"
    assert disc.vendor_profile("VIZIO", PROFILES) == "vizio-smartcast"  # as a UPnP description writes it
    assert disc.vendor_profile("Google", PROFILES) is None and disc.vendor_profile("Sony", PROFILES) is None
    assert disc.vendor_profile("", PROFILES) is None  # generic-tv's empty vendor never matches
    assert "generic-tv" in {p.name for p in PROFILES}


@pytest.mark.parametrize(
    ("vendor", "phrase"),
    [("LG", "an LG"), ("Samsung", "a Samsung"), ("Roku", "a Roku"), ("Vizio", "a Vizio"), ("TCL", "a TCL"),
     ("Amazon", "an Amazon"), ("Hisense", "a Hisense")],
)  # fmt: skip
def test_the_vendor_phrase_takes_the_article_it_is_said_with(vendor, phrase):
    assert disc.vendor_phrase(vendor) == phrase


def test_discover_records_the_ports_and_targets_it_assigns_by():
    """The probes' open ports and the SSDP targets answered reach the candidate, and the assignment
    over them is its profile: the CX fixture is lg-webos on its ports and name, as before."""
    targets = {
        "10.10.10.17": {**disc.parse_ssdp(SSDP), "st": "upnp:rootdevice " + disc.SSDP_SIGNATURES[0][0]}
    }
    cands = disc.discover(
        "eth0", "10.10.10.1", leases_text=LEASES, journal_text=JOURNAL, probe=lg_ports,
        ssdp=lambda ip: targets, describe=lambda url: disc.parse_description(XML),
    )  # fmt: skip
    tv = next(c for c in cands if c.ip == "10.10.10.17")
    assert tv.open_ports == [3000, 3001] and tv.ssdp_targets == [
        "upnp:rootdevice",
        disc.SSDP_SIGNATURES[0][0],
    ]
    assert tv.profile == "lg-webos"
    alone = disc.discover("eth0", "10.10.10.1", leases_text=LEASES, probe=lambda ip, p: False,
                          ssdp=lambda ip: targets, describe=lambda url: {})  # fmt: skip
    assert next(c for c in alone if c.ip == "10.10.10.17").profile == "lg-webos"  # the target alone
    roku = next(c for c in cands if c.ip == "10.10.10.12")
    assert (roku.vendor, roku.profile, roku.open_ports) == ("Roku", None, [])


def test_the_search_keeps_every_target_a_responder_answered(monkeypatch):
    """(profile) One TV answers several searches, and its vendor's own target may not be the first."""
    replies = [
        (
            SSDP.replace(b"urn:lge-com:service:webos-second-screen:1", b"upnp:rootdevice"),
            ("10.10.10.17", 1900),
        ),
        (SSDP, ("10.10.10.17", 1900)),
        (SSDP, ("10.10.10.17", 1900)),  # a repeat adds nothing
    ]

    class Sock:
        def __init__(self, *a):
            pass

        def setsockopt(self, *a):
            pass

        def settimeout(self, t):
            pass

        def bind(self, addr):
            pass

        def getsockname(self):
            return ("0.0.0.0", 54321)

        def sendto(self, msg, addr):
            pass

        def recvfrom(self, n):
            if replies:
                return replies.pop(0)
            raise OSError("closed")  # ends the wait

        def close(self):
            pass

    monkeypatch.setattr(disc.socket, "socket", Sock)
    seen = disc.ssdp_search("10.10.10.1", timeout=5)
    assert seen["10.10.10.17"]["st"] == "upnp:rootdevice urn:lge-com:service:webos-second-screen:1"
    assert seen["10.10.10.17"]["location"] == "http://10.10.10.17:1140/description.xml"


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


def test_cli_discover_write_leaves_the_profile_on_one_signal_and_names_the_vendors(
    monkeypatch, tmp_path, capsys
):
    """(profile) A Samsung that gave only its ports: the identity is written, PROFILE is not, and the
    line says which profile to set if it is one; a Cast device gets no suggestion."""
    conf = tmp_path / "tvgw.conf"
    conf.write_text("TV_MAC=00:00:00:00:00:00\nPROFILE=generic-tv\n")
    tv = disc.Candidate(ip="10.10.10.17", mac="02:00:00:00:00:17", vendor="Samsung", platform="Tizen")
    monkeypatch.setattr(disc, "gather", lambda iface, gw_ip, with_ssdp=True: [tv])
    assert cli.main(["--conf", str(conf), "discover", "--write", "--yes"]) == 0
    out = capsys.readouterr().out
    assert "wrote TV_MAC, TV_IP, TV_NAME to" in out and "PROFILE=generic-tv" in conf.read_text()
    assert "PROFILE was left as it was; if it is a Samsung TV, set PROFILE=samsung-tizen" in out
    cast = disc.Candidate(ip="10.10.10.17", mac="02:00:00:00:00:17", vendor="Google", platform="Cast")
    monkeypatch.setattr(disc, "gather", lambda iface, gw_ip, with_ssdp=True: [cast])
    assert cli.main(["--conf", str(conf), "discover", "--write", "--yes"]) == 0
    out = capsys.readouterr().out
    assert "PROFILE was left as it was (docs/project/adding-a-profile.md)" in out and "set PROFILE" not in out


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
    """`nft` as run_cmd sees it: insert, `list chain`, `-a list chain` with handles, delete by handle,
    for each loaded table (inet tvgw, and (guard) inet tvgw_guard)."""

    def __init__(self, loaded=True, guard=False):
        self.tables = {"tvgw"} if loaded else set()
        if guard:
            self.tables.add("tvgw_guard")
        self.rules, self.next = {}, 40

    def __call__(self, cmd):
        if cmd[:3] == ["nft", "insert", "rule"] and cmd[4] in self.tables:
            self.next += 1
            self.rules[self.next] = (cmd[4], cmd[5], " ".join(cmd[6:]))
        elif cmd[:4] == ["nft", "-a", "list", "chain"] and cmd[5] in self.tables:
            return "".join(
                f"\t\t{text} # handle {h}\n"
                for h, (table, chain, text) in self.rules.items()
                if (table, chain) == (cmd[5], cmd[6])
            )
        elif cmd[:3] == ["nft", "list", "chain"] and cmd[4] in self.tables:
            return f"table inet {cmd[4]} {{\n\tchain {cmd[5]} {{\n\t}}\n}}\n"
        elif cmd[:3] == ["nft", "delete", "rule"]:
            assert self.rules.pop(int(cmd[-1]))[:2] == (cmd[4], cmd[5])  # a handle is per table
        return ""

    def chain(self, name, table="tvgw"):
        return [text for t, chain, text in self.rules.values() if (t, chain) == (table, name)]


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


def test_discover_replaces_the_settings_file_whole_and_keeps_its_mode(monkeypatch, tmp_path):
    """`--write` rewrote /etc/tvgw/tvgw.conf in place: a power cut mid-write left a truncated conf, and
    tvgw-apply stops at boot on a missing WAN_GW, leaving the TV dark. A new file is fsynced beside it
    with its mode and owner, then renamed over it; a failure before the rename leaves the old one."""
    import os
    import stat

    conf = tmp_path / "tvgw.conf"
    conf.write_text("TV_MAC=00:00:00:00:00:00\nWAN_IF=wlan0\n")
    conf.chmod(0o640)
    before = os.stat(conf).st_ino
    tv = disc.Candidate(ip="10.10.10.17", mac="b4:b2:91:aa:bb:cc", hostname="LGwebOSTV", profile="lg-webos")
    monkeypatch.setattr(disc, "gather", lambda iface, gw_ip, with_ssdp=True: [tv])
    assert cli.main(["--conf", str(conf), "discover", "--write", "--yes"]) == 0
    st = os.stat(conf)
    assert st.st_ino != before and stat.S_IMODE(st.st_mode) == 0o640
    assert "TV_MAC=b4:b2:91:aa:bb:cc" in conf.read_text() and "WAN_IF=wlan0" in conf.read_text()
    assert os.listdir(tmp_path) == ["tvgw.conf"]  # nothing staged left behind

    def cut(src, dst):
        raise OSError("power cut")

    monkeypatch.setattr(disc.os, "replace", cut)
    text = conf.read_text()
    with pytest.raises(OSError, match="power cut"):
        disc.write_conf(conf, "TV_MAC=")
    assert conf.read_text() == text and os.listdir(tmp_path) == ["tvgw.conf"]


# (guard) design decision 42: the guard runs after inet tvgw, so the answers need the hole in it too


def test_the_answer_hole_is_opened_in_the_guard_as_well_and_closed_with_the_rest(monkeypatch):
    nft = FakeNft(guard=True)
    monkeypatch.setattr(disc, "run_cmd", nft)
    seen = {}

    def search(bind_ip, timeout=4.0, on_bound=None):
        on_bound(54321)
        seen.update(tvgw=nft.chain("input"), guard=nft.chain("input", "tvgw_guard"), out=nft.chain("output"))
        return {}

    monkeypatch.setattr(disc, "ssdp_search", search)
    disc._ssdp_with_exemption("eth0")("10.10.10.1")
    hole = "iifname eth0 ip daddr 10.10.10.1 udp dport 54321 counter accept comment tvgw-discover"
    assert seen == {
        "tvgw": [hole],
        "guard": [hole],
        "out": ["oifname eth0 udp dport 1900 counter accept comment tvgw-discover"],
    }
    assert nft.rules == {}


def test_with_only_the_guard_loaded_a_first_install_still_hears_the_answers(monkeypatch):
    """A first install runs discovery before tvgw-apply: the guard is the only input chain then, and
    there is no output chain to stop the search."""
    nft = FakeNft(loaded=False, guard=True)
    monkeypatch.setattr(disc, "run_cmd", nft)
    seen = {}

    def search(bind_ip, timeout=4.0, on_bound=None):
        on_bound(54321)
        seen["guard"] = nft.chain("input", "tvgw_guard")
        return {}

    monkeypatch.setattr(disc, "ssdp_search", search)
    disc._ssdp_with_exemption("eth0")("10.10.10.1")
    assert seen["guard"] == [
        "iifname eth0 ip daddr 10.10.10.1 udp dport 54321 counter accept comment tvgw-discover"
    ]
    assert nft.rules == {}


# ---- (samsung) Samsung: signals name the vendor, the TV's own REST reply gives the profile ------------------
from tvgw import tizen  # noqa: E402

SAMSUNG_MAC = "02:00:00:00:00:17"
SAMSUNG_LEASE = f"1793175057 {SAMSUNG_MAC} 10.10.10.17 localhost 01:{SAMSUNG_MAC}\n"
# dnsmasq with log-dhcp: every line starts with the transaction id, and the options a client sent come
# before the DHCPREQUEST line that names its MAC
SAMSUNG_JOURNAL = (
    "2915174447 available DHCP range: 10.10.10.10 -- 10.10.10.20\n"
    "2915174447 vendor class: VD Linux VDLinux\n"
    "2915174447 client provides name: localhost\n"
    f"2915174447 DHCPREQUEST(eth0) 10.10.10.17 {SAMSUNG_MAC}\n"
    f"2915174447 DHCPACK(eth0) 10.10.10.17 {SAMSUNG_MAC}\n"
)


def samsung_ssdp(server: str = "SHP, UPnP/1.0, Samsung UPnP SDK/1.0", st: str = "upnp:rootdevice") -> dict:
    return {
        "10.10.10.17": {
            "location": "http://10.10.10.17:7678/nservice/",
            "server": server,
            "st": st,
            "usn": "",
        }
    }


def samsung_ports(ip, port):
    return ip == "10.10.10.17" and port in (8001, 8002)


def samsung_xml(udn: str) -> str:
    return (
        "<root><device><friendlyName>[TV] Samsung Q60 Series (55)</friendlyName><manufacturer>Samsung"
        f" Electronics</manufacturer><modelName>QN55Q60TAFXZA</modelName><UDN>uuid:{udn}</UDN></device></root>"
    )


def answering(kind: str, asked: list | None = None):
    """A stand-in for tizen.identify: what the device's REST interface says, and who was asked."""

    def identify(ip):
        if asked is not None:
            asked.append(ip)
        return {"tv": tizen.Identity("tv", "QN55Q60TAFXZA", "2020"), "not-tv": tizen.Identity("not-tv")}.get(
            kind
        )

    return identify


def find(**kw) -> disc.Candidate:
    kw.setdefault("probe", lambda ip, p: False)
    (c,) = [c for c in disc.discover("eth0", "10.10.10.1", **kw) if c.ip == "10.10.10.17"]
    return c


@pytest.mark.parametrize(
    "server",
    ["SHP, UPnP/1.0, Samsung UPnP SDK/1.0", "Samsung-Linux/4.1, UPnP/1.0, Samsung_UPnP_SDK/1.0"],
    ids=["space", "underscore"],
)
def test_both_spellings_of_samsungs_ssdp_server_name_the_vendor_and_no_profile(server):
    hdr = samsung_ssdp(server)["10.10.10.17"]
    assert disc.ssdp_hint(hdr) == ("Samsung", "Tizen", None)
    c = find(ssdp=lambda ip: samsung_ssdp(server), describe=lambda url: {})
    assert (c.vendor, c.platform, c.profile) == ("Samsung", "Tizen", None)  # no REST question: no profile


def test_a_samsung_search_target_and_the_host_names_name_the_vendor():
    assert disc.ssdp_hint({"st": "urn:samsung.com:device:RemoteControlReceiver:1"}) == (
        "Samsung",
        "Tizen",
        None,
    )
    assert disc.ssdp_hint({"server": "WebOS/5.6.2 UPnP/1.0", "st": "upnp:rootdevice"}) is None
    assert disc.hostname_hint("Tizen-TV") == ("Samsung", "Tizen", None)
    assert disc.hostname_hint("Samsung") == ("Samsung", "Tizen", None)
    assert disc.hostname_hint("localhost") is None


def test_the_dhcp_vendor_class_names_samsung_by_its_transaction():
    tx = disc.dhcp_transactions(SAMSUNG_JOURNAL + JOURNAL)
    assert tx[SAMSUNG_MAC] == {"vendor class": "VD Linux VDLinux", "name": "localhost"}
    assert tx["02:11:22:33:44:55"] == {"name": "Roku-Ultra"}  # a log without ids, as before
    assert disc.vendor_class_hint("VD Linux VDLinux") == ("Samsung", "Tizen", None)
    assert disc.vendor_class_hint("android-dhcp-11") is None
    c = find(leases_text=SAMSUNG_LEASE, journal_text=SAMSUNG_JOURNAL)
    assert (c.vendor, c.profile) == ("Samsung", None) and "DHCP vendor class names Samsung" in c.evidence


def test_localhost_names_nothing_and_never_becomes_the_tvs_name():
    """dnsmasq refuses `localhost` as a lease name (it is in /etc/hosts) and logs it; tvgw reads it as no
    name, so setup proposes TV_NAME=tv, never a name the scrubber would hunt through every bundle."""
    assert disc.parse_leases(SAMSUNG_LEASE) == [(SAMSUNG_MAC, "10.10.10.17", "")]
    assert disc.dhcp_names(SAMSUNG_JOURNAL) == {}
    assert disc.dhcp_names(SAMSUNG_JOURNAL.replace("name: localhost", "name: LOCALHOST.localdomain")) == {}
    c = find(leases_text=SAMSUNG_LEASE.replace("localhost", "*"), journal_text=SAMSUNG_JOURNAL)
    assert c.hostname == "" and c.evidence[0] == "DHCP lease" and disc.safe_name(c.hostname) == "tv"


@pytest.mark.parametrize(
    ("kind", "profile", "evidence"),
    [
        ("tv", "samsung-tizen", "answered as a Samsung SmartTV on its own interface (port 8001, no pairing)"),
        (
            "not-tv",
            None,
            "answered Samsung's TV interface (port 8001), but not as a Samsung SmartTV: no profile",
        ),
        (None, None, "tcp 8001/8002 open and the host name 'Samsung-TV' name Samsung"),
    ],
    ids=["tv", "soundbar", "no-answer"],
)
def test_only_the_tvs_own_rest_reply_gives_the_samsung_profile(kind, profile, evidence):
    asked: list[str] = []
    c = find(
        leases_text=SAMSUNG_LEASE.replace("localhost", "Samsung-TV"), probe=samsung_ports,
        ssdp=lambda ip: samsung_ssdp(), describe=lambda url: {}, rest=answering(kind, asked),
    )  # fmt: skip
    assert c.profile == profile and c.vendor == "Samsung" and asked == ["10.10.10.17"]
    assert disc.assign(c, PROFILES).evidence[0].startswith(evidence)
    if kind == "tv":
        assert (c.model, c.platform, c.rest) == ("QN55Q60TAFXZA", "Tizen", "tv")
        assert "REST: a Samsung SmartTV made in 2020" in c.evidence


def test_a_samsung_soundbar_never_gets_the_profile_whatever_else_agrees():
    """Every signal a Samsung TV gives, from a soundbar: its reply says what it is."""
    bar = disc.Candidate(
        ip="10.10.10.17", mac=SAMSUNG_MAC, hostname="Samsung-Soundbar", vendor="Samsung", open_ports=[8001, 8002],
        ssdp_targets=["urn:samsung.com:device:RemoteControlReceiver:1"], rest="not-tv",
    )  # fmt: skip
    a = disc.assign(bar, PROFILES)
    assert (a.profile, a.vendor) == (None, "Samsung") and "soundbar" in a.evidence[0]


def test_the_rest_question_goes_only_to_a_device_another_signal_names_samsung():
    asked: list[str] = []
    rest = answering("tv", asked)
    # the LG CX: LG's ports, its own search target and manufacturer: never read as a Samsung
    lg = find(leases_text=LEASES, probe=lambda ip, p: lg_ports(ip, p) or p == 8001,
              ssdp=lambda ip: {"10.10.10.17": disc.parse_ssdp(SSDP)}, describe=lambda url: disc.parse_description(XML),
              rest=rest)  # fmt: skip
    assert lg.profile == "lg-webos" and asked == []
    # a device with no Samsung signal at all, port 8001 alone open
    quiet = find(leases_text=SAMSUNG_LEASE, probe=lambda ip, p: p == 8001, rest=rest)
    assert quiet.vendor == "" and quiet.profile is None and asked == []
    # a Samsung signal and an LG one together: LG's evidence wins and nothing is asked
    mixed = disc.Candidate(ip="10.10.10.17", vendor="Samsung", open_ports=[3000, 3001, 8001, 8002])
    assert not disc._asks_samsung(mixed)


def test_a_udn_that_changes_at_every_boot_changes_nothing():
    """Some sets make a new UPnP UUID at each boot: the candidate is its MAC, the profile its reply."""
    seen = []
    for udn in ("00000000-0000-0000-0000-000000000001", "00000000-0000-0000-0000-000000000002"):
        c = find(
            leases_text=SAMSUNG_LEASE, journal_text=SAMSUNG_JOURNAL, probe=samsung_ports,
            ssdp=lambda ip: samsung_ssdp(), describe=lambda url, u=udn: disc.parse_description(samsung_xml(u)),
            rest=answering("tv"),
        )  # fmt: skip
        seen.append((c.mac, c.ip, c.vendor, c.model, c.profile))
        assert all(udn not in e for e in c.evidence)
    assert seen[0] == seen[1] == (SAMSUNG_MAC, "10.10.10.17", "Samsung", "QN55Q60TAFXZA", "samsung-tizen")


def test_the_live_gather_asks_with_the_hourly_readings_get(monkeypatch):
    """gather() hands discover the reader's identify, the one GET to /api/v2/."""
    got = {}
    monkeypatch.setattr(disc, "discover", lambda *a, **k: got.update(k) or [])
    monkeypatch.setattr(disc, "run_cmd", lambda cmd: "")
    disc.gather("eth0", "10.10.10.1", leases_path="/nonexistent", with_ssdp=False)
    assert got["rest"] is tizen.identify
