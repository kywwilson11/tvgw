"""(web) What `tvgw verify` and `tvgw doctor` say of the page on the home network (design decision 76): its
`web` check, a WARN at most while it is new; the parser of the kernel's listening sockets it reads; the
co-tenant check, which reads tvgw-web's address filter beside the co-tenants'; and the doctor's notes."""

from __future__ import annotations

import json
import socket
import struct
import time

import pytest

from tvgw import doctor, verify, web, webauth
from tvgw.config import Settings

NOW = 1_800_000_000.0
STORED = webauth.hash_password("correct horse battery")
UPLINK = "172.20.40.7"  # stands for the gateway's home-network address in these tests only


def tcp(*rows: tuple[str, int, str]) -> str:
    """/proc/net/tcp as the kernel writes it, in this machine's byte order: (address, port, state)."""
    out = ["  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode"]
    for i, (addr, port, st) in enumerate(rows):
        word = struct.unpack("=I", socket.inet_aton(addr))[0]
        out.append(
            f"   {i}: {word:08X}:{port:04X} 00000000:0000 {st} 00000000:00000000 00:00000000 00000000 999 0 1"
        )
    return "\n".join(out) + "\n"


def tcp6(*rows: tuple[str, int, str]) -> str:
    out = ["  sl  local_address                         remote_address                        st"]
    for i, (addr, port, st) in enumerate(rows):
        raw = socket.inet_pton(socket.AF_INET6, addr)
        words = struct.unpack("=4I", raw)
        hexaddr = "".join(f"{w:08X}" for w in words)
        out.append(f"   {i}: {hexaddr}:{port:04X} 00000000000000000000000000000000:0000 {st} 0 0 0")
    return "\n".join(out) + "\n"


def stamp(days: float) -> str:
    return time.strftime("%b %d %H:%M:%S %Y GMT", time.gmtime(NOW + days * 86400))


def host(listening=(), listening6=(), active=True, cert_days: float | None = 400, password=STORED):
    """The run and read seams of a gateway whose page is set up as the arguments say."""
    files = {
        "/proc/net/tcp": tcp(*listening),
        "/proc/net/tcp6": tcp6(*listening6),
        "/etc/tvgw/web-password": password or "",
    }

    def run(cmd):
        if cmd == ["systemctl", "is-active", "tvgw-web.service"]:
            return "active\n" if active else "inactive\n"
        if cmd[:2] == ["openssl", "x509"]:
            return "" if cert_days is None else f"notAfter={stamp(cert_days)}\n"
        if cmd[:6] == ["ip", "-j", "-4", "addr", "show", "dev"]:
            return json.dumps([{"addr_info": [{"family": "inet", "local": UPLINK, "scope": "global"}]}])
        return ""

    return run, lambda path: files.get(path, "")


ON = Settings(web="on")


def check(s=ON, **kw):
    run, read = host(**kw)
    return verify.web_check(s, run, read, NOW)


def test_the_listener_parser_reads_ipv4_and_ipv6_listening_sockets_only():
    text = tcp(("127.0.0.1", 8443, "0A"), (UPLINK, 8443, "0A"), ("0.0.0.0", 22, "0A"), (UPLINK, 8443, "01"))
    assert web.tcp_listeners(text, "", 8443) == ["127.0.0.1", UPLINK]
    assert web.tcp_listeners(text, tcp6(("::", 8443, "0A"), ("::1", 9000, "0A")), 8443)[-1] == "::"
    assert web.tcp_listeners("garbage\n0: zz:yy 0 0A\n", None, 8443) == []


def test_off_and_nothing_listening_is_ok():
    c = check(Settings(), listening=(), active=False)
    assert c.ok and not c.warn and c.detail == "off: nothing listens on port 8443"


def test_off_but_something_on_its_port_warns():
    c = check(Settings(), listening=(("172.20.40.7", 8443, "0A"),), active=False)
    assert c.ok and c.warn and "another program listens on port 8443" in c.detail
    c = check(Settings(), listening=(("0.0.0.0", 8443, "0A"),), active=True)
    assert c.ok and c.warn and "disable --now tvgw-web" in c.detail and c.detail.endswith(verify.HELD)


def test_on_and_right_is_ok_and_names_no_address():
    c = check(listening=((UPLINK, 8443, "0A"),))
    assert c.ok and not c.warn, c.detail
    assert (
        c.detail
        == "on: port 8443 on the uplink's address only; the certificate has 400 days left; a password is set"
    )
    assert UPLINK not in c.raw
    loop = check(Settings(web="on", web_bind="loopback"), listening=(("127.0.0.1", 8443, "0A"),))
    assert loop.ok and not loop.warn and "loopback only" in loop.detail


@pytest.mark.parametrize(
    ("listening", "listening6", "says"),
    [
        ((("0.0.0.0", 8443, "0A"),), (), "every address"),
        ((), (("::", 8443, "0A"),), "every address"),
        ((("10.10.10.1", 8443, "0A"),), (), "the TV's side"),
        ((("10.10.10.44", 8443, "0A"),), (), "the TV's side"),
    ],
)
def test_on_and_open_toward_the_tv_is_of_fail_level_held_at_warn_while_new(listening, listening6, says):
    c = check(listening=listening, listening6=listening6)
    assert c.ok and c.warn and says in c.detail and c.detail.endswith(verify.HELD)
    assert verify.FAIL_AFTER["web"] == verify.FAIL and "web" not in verify.PROMOTED


def test_once_promoted_the_tv_side_fails(monkeypatch):
    monkeypatch.setattr(verify, "PROMOTED", frozenset({"web"}))
    assert not check(listening=(("0.0.0.0", 8443, "0A"),)).ok
    assert check(listening=((UPLINK, 8443, "0A"),), cert_days=3).ok  # a certificate ending is never more


@pytest.mark.parametrize(
    ("kw", "says"),
    [
        ({"active": False, "listening": ()}, "not running"),
        ({"listening": ()}, "nothing listens on port 8443"),
        ({"listening": (("172.20.40.99", 8443, "0A"),)}, "an address the uplink no longer has"),
        ({"listening": ((UPLINK, 8443, "0A"),), "cert_days": 12}, "the certificate ends in 12 days"),
        ({"listening": ((UPLINK, 8443, "0A"),), "cert_days": -1}, "the certificate has ended"),
        ({"listening": ((UPLINK, 8443, "0A"),), "cert_days": None}, "no certificate could be read"),
        ({"listening": ((UPLINK, 8443, "0A"),), "password": "hunter2"}, "no password is set"),
    ],
)
def test_on_with_something_amiss_warns_with_the_fix(kw, says):
    c = check(**kw)
    assert c.ok and c.warn and says in c.detail, c.detail
    assert not c.detail.endswith(verify.HELD)


def test_the_page_is_filtered_beside_the_cotenants_and_an_allow_that_opens_the_tv_subnet_warns():
    s = Settings(co_tenant_units="smbd")

    def run_with(blocks):
        def run(cmd):
            if cmd[:2] == ["systemctl", "show"]:
                assert verify.WEB_UNIT in cmd and "IPAddressAllow" in cmd
                return "\n\n".join(blocks)
            return ""

        return run

    smbd = "Id=smbd.service\nLoadState=loaded\nActiveState=active\nIPAddressDeny=10.10.10.0/24\nIPAddressAllow=10.10.10.1/32"
    good = (
        "Id=tvgw-web.service\nLoadState=loaded\nActiveState=inactive\nIPAddressDeny=0.0.0.0/0 ::/0\n"
        "IPAddressAllow=127.0.0.0/8 10.0.0.0/13 172.16.0.0/12"
    )
    c = verify.cotenants_check(s, run_with([smbd, good]))
    assert c.ok and not c.warn and c.detail == "smbd.service, tvgw-web.service"
    opened = good.replace("10.0.0.0/13", "10.0.0.0/8")
    c = verify.cotenants_check(s, run_with([smbd, opened]))
    assert c.warn and c.detail == "an IPAddressAllow opens 10.10.10.0/24 again: tvgw-web.service"
    missing = "Id=tvgw-web.service\nLoadState=loaded\nActiveState=inactive\nIPAddressDeny=\nIPAddressAllow="
    c = verify.cotenants_check(s, run_with([smbd, missing]))
    assert c.warn and c.detail.startswith("no IPAddressDeny=10.10.10.0/24: tvgw-web.service")
    gone = "Id=tvgw-web.service\nLoadState=not-found\nActiveState=inactive\nIPAddressDeny=\nIPAddressAllow="
    assert verify.cotenants_check(s, run_with([smbd, gone])).detail == "smbd.service"


def test_the_doctor_sends_the_owner_to_the_commands_that_ask_or_print_and_restarts_the_rest():
    s = Settings(web="on")

    def plan(detail):
        c = verify.Check("web", True, detail, warn=True)
        return doctor.plan_for(c, s, None, None, {})

    p = plan("no password is set: sudo tvgw web password")
    assert not p.fixes and any("sudo tvgw web password" in n for n in p.notes)
    p = plan("the certificate ends in 3 days: sudo tvgw web cert")
    assert not p.fixes and any(
        "sudo tvgw web cert" in n for n in p.notes
    )  # its fingerprint must be seen whole
    p = plan("on, but tvgw-web is not running (journalctl -u tvgw-web -n 20)")
    assert [f.steps[0].argv for f in p.fixes] == [("systemctl", "restart", "tvgw-web")]
    assert all("TV is not affected" in n for n in p.notes[:1])
