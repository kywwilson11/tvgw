"""The scrubber (design decision 63): what the gateway prints where others read it holds no address
outside TV_NET, no MAC, no USB adapter name, no host, TV, Wi-Fi or user name, and keeps the TV subnet,
the addresses tvgw ships and everything else as written. Every value here is a documentation address
(RFC 5737, RFC 3849), a documentation MAC (RFC 7042) or a made-up name."""

import io
import json
import subprocess
import sys

import pytest
from conftest import ROOT

from tvgw import scrub
from tvgw.config import Settings
from tvgw.scrub import DOMAIN, HOST, LAN, MAC, PUBLIC, ROUTER, SERIAL, TV, USER, UUID, WIFI, Scrubber

NET = "10.10.10.0/24"


def full() -> Scrubber:
    return Scrubber(
        NET,
        router="192.0.2.1",
        uplink_addrs=["192.0.2.10", "2001:db8::10"],
        hostname="gateway-under-test.example",
        tv_name="living-room-tv",
        ssids=["example-wifi"],
        keep=scrub.SHIPPED,
    )


@pytest.mark.parametrize(
    "address",
    [
        "192.0.2.48",  # RFC 5737
        "198.51.100.7",
        "203.0.113.200",
        "192.168.77.20",  # RFC 1918, a home LAN range
        "172.16.4.4",
        "10.0.0.5",  # inside 10/8, outside TV_NET
        "10.10.11.17",  # next to TV_NET
        "169.254.10.10",  # link-local
        "100.64.1.1",  # carrier-grade NAT, a tunnel's address
    ],
)
def test_every_private_or_documentation_address_outside_the_tv_net_is_a_lan_address(address):
    assert scrub.scrub(f"src={address} dst {address}:443 [{address}]", NET) == (
        f"src={LAN} dst {LAN}:443 [{LAN}]"
    )


def test_a_public_address_that_tvgw_does_not_ship_is_a_public_address():
    """The uplink's public address or a VPN exit names the home as surely as a LAN address does."""
    assert scrub.scrub("answer 23.0.0.1, exit 8.8.8.8", NET) == f"answer {PUBLIC}, exit {PUBLIC}"


def test_the_router_is_named_as_the_router():
    s = full()
    assert s("default via 192.0.2.1 dev wlan0 src 192.0.2.10") == f"default via {ROUTER} dev wlan0 src {LAN}"
    assert Scrubber(NET, router=["192.0.2.1", "fe80::1"])("via fe80::1 and 192.0.2.1") == (
        f"via {ROUTER} and {ROUTER}"
    )


def test_tv_net_addresses_and_networks_are_kept():
    line = "TV 10.10.10.17 gateway 10.10.10.1 net 10.10.10.0/24 pool 10.10.10.100-10.10.10.200"
    assert full()(line) == line
    assert Scrubber("10.42.0.0/24")("tv 10.42.0.17 and 10.10.10.17") == f"tv 10.42.0.17 and {LAN}"


def test_a_prefix_length_stays_with_the_replaced_network():
    assert scrub.scrub("192.168.77.0/24 dev eth1, 2001:db8:1::/48", NET) == f"{LAN}/24 dev eth1, {LAN}/48"


def test_the_addresses_tvgw_ships_are_kept():
    """decision 9's DoH upstreams and bootstrap, Quad9 and LG's firmware fallback, by name; the DoH
    block list by address or network. A home address offered as one to keep is still replaced."""
    s = Scrubber(NET, keep=[*scrub.SHIPPED, "94.140.14.0/24", "192.168.77.5", "not an address"])
    line = "1.1.1.1 1.0.0.1 8.8.8.8 8.8.4.4 9.9.9.9 156.147.69.32 94.140.14.14"
    assert s(line) == line
    assert s("lan 192.168.77.5") == f"lan {LAN}"


def test_addresses_that_name_no_site_are_kept():
    line = "blocked 0.0.0.0, local 127.0.0.1 and ::1, any ::, broadcast 255.255.255.255, mdns 224.0.0.251 ff02::fb"
    assert full()(line) == line


def test_the_gateways_own_home_addresses_go_whatever_else_would_keep_them():
    s = Scrubber(NET, uplink_addrs=["10.10.10.5", "8.8.8.8"], keep=scrub.SHIPPED)
    assert s("on 10.10.10.5 from 8.8.8.8 to 10.10.10.17") == f"on {LAN} from {PUBLIC} to 10.10.10.17"


@pytest.mark.parametrize(
    ("text", "out"),
    [
        ("inet6 fe80::200:5eff:fe00:5301/64 scope link", f"inet6 {LAN}/64 scope link"),
        ("from 2001:db8::7 port 53", f"from {LAN} port 53"),
        ("[2001:db8:0:0:0:0:0:7]:443", f"[{LAN}]:443"),
        ("zone fe80::1%wlan0 up", f"zone {LAN} up"),
        ("mapped ::ffff:192.0.2.9 and ::ffff:10.10.10.17", f"mapped {LAN} and ::ffff:10.10.10.17"),
        ("public 2606:4700:4700::1111", f"public {PUBLIC}"),
    ],
)
def test_ipv6_addresses_outside_the_tv_net_are_replaced(text, out):
    assert scrub.scrub(text, NET) == out


@pytest.mark.parametrize(
    "mac",
    [
        "00:00:5e:00:53:01",
        "00:00:5E:00:53:AF",
        "00-00-5e-00-53-02",  # the Windows form
        "01:00:00:5e:00:53:03",  # a DHCP client id that holds the MAC
        "b4:b2:91:aa:bb:cc",  # the house rules' placeholder
    ],
)
def test_documentation_macs_are_replaced_in_every_form(mac):
    assert scrub.scrub(f"lladdr {mac} REACHABLE, (mac={mac})", NET) == f"lladdr {MAC} REACHABLE, (mac={MAC})"


def test_a_mac_after_a_word_and_a_dash_is_still_a_mac():
    assert scrub.scrub("tv-00:00:5e:00:53:04 joined", NET) == f"tv-{MAC} joined"


def test_an_enx_name_is_a_numbered_usb_adapter_and_keeps_its_number():
    s = Scrubber(NET)
    out = s("enx00005e005301 up; enx00005e005302 down; dev=enx00005e005301; wlx00005e005303")
    assert out == "usb-ethernet-1 up; usb-ethernet-2 down; dev=usb-ethernet-1; usb-wifi-1"
    assert s("again enx00005e005302") == "again usb-ethernet-2"  # one scrubber, one numbering
    assert "00005e" not in scrub.scrub("/sys/class/net/enx00005e005301/carrier", NET)


def test_the_host_tv_and_wifi_names_are_replaced_whole():
    s = full()
    assert s("gateway-under-test.example (Gateway-Under-Test) runs tvgw") == f"{HOST} ({HOST}) runs tvgw"
    assert s("TV_NAME=living-room-tv, Living-Room-TV") == f"TV_NAME={TV}, {TV}"
    assert s("joined example-wifi; example-wifi-5G") == f"joined {WIFI}; {WIFI}-5G"
    assert s("a gateway-under-testing box") == "a gateway-under-testing box"  # a longer word is another word


def test_a_vendor_default_tv_name_a_generic_host_and_short_names_are_left_alone():
    """`lgwebostv` is what every LG announces; `tvgw` and `gateway` are words tvgw prints itself."""
    for tv in ("tv", "lgwebostv", "samsung-q80", "Roku-Ultra"):
        assert scrub.vendor_slug(tv)
        assert scrub.scrub(f"TV {tv}", NET, tv_name=tv) == f"TV {tv}"
    for host in ("tvgw", "gateway", "localhost", "raspberrypi", "pi"):
        assert scrub.scrub(f"the gateway tvgw on {host}", NET, hostname=host) == f"the gateway tvgw on {host}"
    assert scrub.scrub("ab and cd", NET, ssids=["ab"], tv_name="cd") == "ab and cd"


def test_the_home_networks_dns_domain_is_replaced_after_the_host_and_on_its_own():
    """The router's domain (an ISP's, or one the household chose) names the home as the host name does:
    the FQDN reads `<this computer>.<domain>`, the domain alone `<domain>`; the generic local suffixes
    every router uses and a dotted FQDN of another host stay."""
    s = Scrubber(NET, hostname="gateway-under-test", domains=["home-isp.example", "lan", ".home.arpa", "ab"])
    assert s("gateway-under-test.home-isp.example") == f"{HOST}.{DOMAIN}"
    assert s("search Home-ISP.example lan home.arpa") == f"search {DOMAIN} lan home.arpa"
    assert s("printer.home-isp.example and tv.lan") == f"printer.{DOMAIN} and tv.lan"
    assert s("ab.example") == "ab.example"  # a two-letter domain is too short to be replaced
    assert scrub.home_domains(["Home-ISP.example.", "lan", "", "home.arpa", "ab"]) == {"home-isp.example"}


def test_scrub_for_learns_the_domain_from_the_fqdn_and_resolv_conf():
    s = scrub.scrub_for(
        Settings(),
        **fake_system(
            files={scrub.RESOLV_CONF: "nameserver 127.0.0.53\nsearch attlocal.example other.example\n"}
        ),
        hostname=lambda: "unused",
        fqdn=lambda: "gateway-under-test.home-isp.example",
    )
    text = "gateway-under-test.home-isp.example attlocal.example other.example localhost.localdomain"
    assert s(text) == f"{HOST}.{DOMAIN} {DOMAIN} {DOMAIN} localhost.localdomain"
    assert scrub.domains_of("box.corp.example", "box.corp.example", "domain d.example # x\n") == [
        "corp.example",
        "corp.example",
        "d.example",
    ]
    silent = scrub.scrub_for(
        Settings(), run=lambda c: "", read=lambda p: "", hostname=lambda: "", fqdn=lambda: ""
    )
    assert silent("a.example") == "a.example"


def test_a_upnp_udn_uuid_and_a_serial_number_are_replaced():
    """A TV's UPnP description carries its UDN (a uuid) and often its serialNumber; both single out one
    set, in XML, in `tvgw discover --json` and in a line someone pastes."""
    s = Scrubber(NET)
    xml = "<UDN>uuid:0a1b2c3d-4e5f-6071-8293-a4b5c6d7e8f9</UDN><serialNumber>012RMZZ3A123</serialNumber>"
    assert s(xml) == f"<UDN>uuid:{UUID}</UDN><serialNumber>{SERIAL}</serialNumber>"
    assert s("serialNumber: 012RMZZ3A123, serial_number=ABCD1234, Serial Number: X1-234") == (
        f"serialNumber: {SERIAL}, serial_number={SERIAL}, Serial Number: {SERIAL}"
    )
    assert s("boot_id 0a1b2c3d-4e5f-6071-8293-a4b5c6d7e8f9 at 10:40:05") == f"boot_id {UUID} at 10:40:05"
    # a hex run that is not a UUID, a serial word without a value and a too-short value stay
    assert s("0a1b2c3d-4e5f-6071 serial port; serial: ab") == "0a1b2c3d-4e5f-6071 serial port; serial: ab"


def test_a_wifi_name_that_is_a_common_word_is_replaced_wherever_the_word_stands():
    """Documented, not a bug to fix: an SSID of at least MIN_NAME letters is replaced as a whole word
    wherever it appears, so a network called `the` turns every `the` into `<wifi name>`. Nothing leaks;
    the log reads oddly, and a shorter SSID is never replaced (test above)."""
    s = Scrubber(NET, ssids=["the"])
    assert s("the TV is on; theme theory") == f"{WIFI} TV is on; theme theory"


def test_a_home_directory_names_no_user():
    out = scrub.scrub("/home/someone/actions-runner/_work/tvgw and /Users/another/x and /home/<user>/y", NET)
    assert out == f"/home/{USER}/actions-runner/_work/tvgw and /Users/{USER}/x and /home/{USER}/y"


@pytest.mark.parametrize(
    "line",
    [
        "12:30:45 2026-10-26T15:20:00-05:00 window 03:30-05:30",
        "AdGuard Home v0.107.79, nft v1.1.3, kernel 6.12.47, 1.0 days old, 76 addresses",
        "version 1.2.3 and 999.1.1.1, build 2026.11.03",
        "Class::method and std::chrono::seconds, 04:30:00,123",
        "CapEff 0000000000000000: none; std::string",
        "OK   ruleset_unchanged",
    ],
)
def test_text_that_only_looks_like_an_identifier_is_kept(line):
    assert full()(line) == line


@pytest.mark.parametrize(
    ("text", "out"),
    [
        # tcpdump writes the port as a fifth dotted number: the address before it still goes
        ("IP 192.0.2.10.51234 > 10.10.10.17.53: A?", f"IP {LAN}.51234 > 10.10.10.17.53: A?"),
        ("version 1.2.3.4.5", f"version {PUBLIC}.5"),  # the price of the rule above
        ("ptr.192.0.2.10 and 5.1.168.192.in-addr.arpa", f"ptr.{LAN} and {PUBLIC}.in-addr.arpa"),
        ("addr:2001:db8::7 src:fe80::1", f"addr:{LAN} src:{LAN}"),
        ("mac:00:00:5e:00:53:01 hw-00-00-5e-00-53-02", f"mac:{MAC} hw-{MAC}"),
        ("GENERAL.HWADDR:00\\:00\\:5E\\:00\\:53\\:01", f"GENERAL.HWADDR:{MAC}"),  # nmcli -t
        ("lladdr 00:00:5e:00:53:01: up", f"lladdr {MAC}: up"),
        ("2001:db8:aa:bb:cc:dd:ee:ff", LAN),  # an address of two-digit groups goes whole, as an address
        ("ff02::1%enx00005e005301", "ff02::1%usb-ethernet-1"),  # a kept address keeps no adapter name
    ],
)
def test_an_identifier_in_a_label_a_port_suffix_or_an_escaped_form_is_still_replaced(text, out):
    assert Scrubber(NET)(text) == out


def test_scrubbing_twice_changes_nothing_more():
    s = full()
    text = "via 192.0.2.1 from 00:00:5e:00:53:01 on enx00005e005301 at gateway-under-test.example"
    assert s(s(text)) == s(text)


def test_an_unusable_tv_net_falls_back_to_the_default():
    assert Scrubber("not a network").tv_net == Scrubber(Settings.tv_net).tv_net


def fake_system(cmds=None, files=None):
    outs = {
        ("ip", "-j", "route", "show", "default"): json.dumps([{"dst": "default", "gateway": "192.0.2.1"}]),
        ("ip", "-j", "-6", "route", "show", "default"): json.dumps([{"gateway": "fe80::1"}]),
        ("ip", "-j", "addr", "show"): json.dumps(
            [
                {"ifname": "lo", "addr_info": [{"local": "127.0.0.1"}]},
                {"ifname": "eth0", "addr_info": [{"local": "10.10.10.1"}]},
                {"ifname": "wlan0", "addr_info": [{"local": "192.0.2.10"}, {"local": "2001:db8::10"}]},
                {"ifname": "wgpia0", "addr_info": [{"local": "198.51.100.2"}]},
            ]
        ),
        ("nmcli", "-t", "-f", "NAME,TYPE", "connection", "show"): (
            "example-wifi:802-11-wireless\ntv-lan:802-3-ethernet\nmy\\:net:802-11-wireless\n"
        ),
        ("nmcli", "-t", "-f", "ACTIVE,SSID", "device", "wifi", "list", "--rescan", "no"): (
            "yes:example-wifi\nno:a-neighbours-wifi\n"
        ),
    }
    outs.update(cmds or {})
    fs = {
        scrub.CONF: "WAN_GW=192.0.2.254\nTV_NAME=living-room-tv\nURL_FILTER_RESOLVER=203.0.113.53\n",
        scrub.HOSTNAME: "gateway-under-test\n",
        "/var/lib/tvgw/doh4.txt": "94.140.14.0/24\n# a comment\n185.228.168.9\n",
    }
    fs.update(files or {})
    return {"run": lambda cmd: outs.get(tuple(cmd), ""), "read": lambda path: fs.get(path, "")}


def test_scrub_for_reads_the_router_addresses_names_and_shipped_list_from_the_gateway():
    s = scrub.scrub_for(Settings(tv_name="living-room-tv"), **fake_system(), hostname=lambda: "unused")
    text = (
        "via 192.0.2.1, old router 192.0.2.254, ll fe80::1, on 192.0.2.10 and 2001:db8::10, tunnel 198.51.100.2,"
        " gateway 10.10.10.1, host gateway-under-test, TV living-room-tv, Wi-Fi example-wifi and my:net,"
        " DoH 94.140.14.14 185.228.168.9 1.1.1.1, nginx resolver 203.0.113.53"
    )
    assert s(text) == (
        f"via {ROUTER}, old router {ROUTER}, ll {ROUTER}, on {LAN} and {LAN}, tunnel {LAN},"
        f" gateway 10.10.10.1, host {HOST}, TV {TV}, Wi-Fi {WIFI} and {WIFI},"
        f" DoH 94.140.14.14 185.228.168.9 1.1.1.1, nginx resolver {LAN}"
    )
    assert "a-neighbours-wifi" not in scrub.wifi_names(fake_system()["run"])  # only the active one


def test_scrub_for_asks_the_system_for_the_host_name_when_proc_is_silent():
    s = scrub.scrub_for(
        Settings(), **fake_system(files={scrub.HOSTNAME: ""}), hostname=lambda: "box-under-test"
    )
    assert s("on box-under-test") == f"on {HOST}"


def test_scrub_for_survives_a_system_that_answers_nothing():
    s = scrub.scrub_for(Settings(), run=lambda cmd: "", read=lambda path: "", hostname=lambda: "")
    assert (
        s("tv 10.10.10.17 home 192.168.77.2 mac 00:00:5e:00:53:01") == f"tv 10.10.10.17 home {LAN} mac {MAC}"
    )
    garbled = scrub.scrub_for(
        Settings(), run=lambda cmd: "{not json", read=lambda path: "KEY=a b\n", hostname=lambda: ""
    )
    assert garbled("192.0.2.1") == LAN


def test_the_stream_filter_scrubs_line_by_line_and_withholds_a_line_it_fails_on():
    out = io.BytesIO()
    scrub.filter_stream(full(), io.BytesIO(b"one 192.0.2.1\ntwo \xff 00:00:5e:00:53:01\nthree"), out)
    assert out.getvalue().decode() == f"one {ROUTER}\ntwo � {MAC}\nthree"

    def broken(line):
        raise RuntimeError(line)  # the line must not reach the output, even in the message

    out = io.BytesIO()
    scrub.filter_stream(broken, io.BytesIO(b"secret 192.0.2.1\n"), out)
    assert out.getvalue() == b"<line withheld: the scrubber failed on it (RuntimeError)>\n"


def test_the_module_filters_stdin_from_an_isolated_interpreter_with_an_unreadable_settings_file(tmp_path):
    """`python3 -m tvgw.scrub --stdin` as the CI job runs it: the checkout's code, the working directory
    off the path, and a settings file it cannot use falls back to the default TV subnet."""
    conf = tmp_path / "tvgw.conf"
    conf.write_text("TV_NET=this is not valid\n", encoding="utf-8")
    out = subprocess.run(
        [sys.executable, "-B", "-P", "-s", "-m", "tvgw.scrub", "--stdin", "--conf", str(conf)],
        input=b"tv 10.10.10.17 router 192.168.77.1 mac 00:00:5e:00:53:01\n",
        capture_output=True,
        env={"PYTHONPATH": str(ROOT / "src")},
        cwd=tmp_path,
        timeout=60,
    )
    assert out.returncode == 0, out.stderr
    assert out.stdout == f"tv 10.10.10.17 router {LAN} mac {MAC}\n".encode()


def test_the_module_needs_its_flag():
    with pytest.raises(SystemExit) as e:
        scrub.main([])
    assert e.value.code == 2
