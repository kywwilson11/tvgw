"""(web) The page on the home network in the namespace gateway (design decision 76).

The `direct` scenario is applied and the guard loaded over it, as on the gateway. The real server (`web.Server`
with `web.App`, as `tvgw web serve` builds them) runs in the `gw` namespace on WAN_IF's own address, found by
`web.bind_address` as the unit finds it, with a certificate made by `web.openssl_command`. From the TV's
namespace no TCP connection opens to that address on its port, nor to the gateway's address there, with
inet tvgw loaded and with it deleted (the weak-host path: the TV routes the uplink's address by the gateway,
and the guard's `ip daddr != GW_IP` drop holds it); from the internet side, which stands for the home
network, the sign-in page comes back over TLS with its Content-Security-Policy.

The runner does not call `web.check_bind`: the topology's uplink is a documentation range, which the page
refuses as an address outside the home, and that refusal is tested in tests/unit/test_web.py. Here the
question is the firewall's.

Run as root on a Linux machine or VM (tests/virtual/README.md):

    sudo env PYTHONPATH=src python3 -m pytest -m virtual tests/virtual -q -p no:cacheprovider
"""

from __future__ import annotations

import os
import shutil
import subprocess
import sys

import pytest
import vnet

pytestmark = pytest.mark.virtual

PORT = 8443
TEMPLATE = vnet.ROOT / "deploy" / "nftables" / "guard.nft.template"
WEAK_HOST = "guard: the gateway address only (weak host)"
FINAL = "guard: TV may not reach other Pi services"
RUNNER = (
    "import sys\n"
    "sys.path.insert(0, sys.argv[1])\n"
    "from tvgw import config, profile, web\n"
    "s = config.Settings(web='on', web_bind='uplink', wan_if=sys.argv[2], gw_ip=sys.argv[3],"
    " web_port=int(sys.argv[4]), web_cert=sys.argv[5], web_key=sys.argv[6], web_password=sys.argv[7],"
    " db_path=sys.argv[8])\n"
    "address = web.bind_address(s)\n"
    "app = web.App(s, profile.load('lg-webos'), address, hostname='gw')\n"
    "httpd = web.Server((address, s.web_port), app, web.tls_context(s.web_cert, s.web_key))\n"
    "print('ready', address, flush=True)\n"
    "httpd.serve_forever(poll_interval=0.2)\n"
)
CLIENT = (  # standard library only: connect, or connect and fetch the sign-in page over TLS
    "import socket, ssl, sys\n"
    "host, port, mode, ca = sys.argv[1], int(sys.argv[2]), sys.argv[3], sys.argv[4]\n"
    "try:\n"
    "    s = socket.create_connection((host, port), timeout=1.5)\n"
    "except TimeoutError:\n"
    "    print('drop'); sys.exit(0)\n"
    "except ConnectionRefusedError:\n"
    "    print('reject'); sys.exit(0)\n"
    "except OSError as e:\n"
    "    print('error:' + type(e).__name__); sys.exit(0)\n"
    "if mode == 'connect':\n"
    "    print('connected'); sys.exit(0)\n"
    "ctx = ssl.create_default_context(cafile=ca)\n"
    "with ctx.wrap_socket(s, server_hostname='gw.local') as t:\n"
    "    t.sendall(b'GET /login HTTP/1.0\\r\\nHost: gw.local\\r\\n\\r\\n')\n"
    "    data = b''\n"
    "    while True:\n"
    "        c = t.recv(65536)\n"
    "        if not c:\n"
    "            break\n"
    "        data += c\n"
    "head = data.split(b'\\r\\n\\r\\n')[0].decode('latin-1')\n"
    "print(head.splitlines()[0])\n"
    "print('csp' if \"Content-Security-Policy: default-src 'none'\" in head else 'no-csp')\n"
)


def render(text: str) -> str:
    """The guard as install.sh's render_guard fills it, for the virtual topology's TV side."""
    return (
        text.replace("__TV_IF__", vnet.TV_IF)
        .replace("__TV_NET__", "10.10.10.0/24")
        .replace("__GW_IP__", vnet.GW_TV)
    )


def guard_counters(net) -> dict[str, int]:
    out = net.ns(net.gw, "nft", "-j", "list", "table", "inet", "tvgw_guard").stdout
    return {comment: n for comment, (n, _) in vnet.counters(out).items()}


def client(net, ns: str, host: str, mode: str, ca: str = "") -> list[str]:
    out = vnet.run(
        ["ip", "netns", "exec", ns, sys.executable, "-I", "-c", CLIENT, host, str(PORT), mode, ca], timeout=30
    )
    return out.stdout.split("\n")[:-1]


@pytest.fixture(scope="module")
def page(net, artifacts):
    openssl = shutil.which("openssl")
    if openssl is None:
        why = "the page's certificate needs the openssl command"
        if os.environ.get("TVGW_VIRTUAL_REQUIRED") == "1":
            pytest.fail(why)
        pytest.skip(why)
    sys.path.insert(0, str(vnet.ROOT / "src"))
    from tvgw import web, webauth

    s = {"UPLINK": "direct", "BLOCK_QUIC": "yes", "STRICT_PORTS": "no", "DNSGATE": "count"}
    conf = vnet.render_conf(s)
    out = net.apply(net.gw, conf)
    assert out.returncode == 0, out.stderr
    rendered = net.save("web/guard.nft", render(TEMPLATE.read_text(encoding="utf-8")))
    loaded = net.ns(net.gw, "nft", "-f", str(rendered), check=False)
    assert loaded.returncode == 0, loaded.stderr
    d = net.sandbox / "web"
    d.mkdir(exist_ok=True)
    cert, key, pw = d / "web-cert.pem", d / "web-key.pem", d / "web-password"
    vnet.run(web.openssl_command(str(key), str(cert), ["gw.local", "gw", "localhost"], [vnet.GW_WLAN]))
    pw.write_text(webauth.hash_password("namespace test password") + "\n", encoding="utf-8")
    log = (artifacts / "services").joinpath("web.log")
    log.parent.mkdir(parents=True, exist_ok=True)
    with log.open("w", encoding="utf-8") as fh:
        argv = [str(vnet.ROOT / "src"), vnet.WAN_IF, vnet.GW_TV, str(PORT), str(cert), str(key), str(pw)]
        argv.append(str(d / "no-store.db"))
        p = subprocess.Popen(
            ["ip", "netns", "exec", net.gw, sys.executable, "-I", "-c", RUNNER, *argv],
            stdout=subprocess.PIPE,
            stderr=fh,
            text=True,
            encoding="utf-8",
        )
        try:
            line = p.stdout.readline().split()
            assert line == ["ready", vnet.GW_WLAN], line  # WAN_IF's own address, read as the unit reads it
            yield str(cert)
        finally:
            p.kill()
            p.communicate(timeout=5)
            net.ns(net.gw, "nft", "delete", "table", "inet", "tvgw_guard", check=False)
            again = net.apply(net.gw, conf)
            assert again.returncode == 0, again.stderr


def test_the_home_side_gets_the_sign_in_page_over_tls(page, net):
    assert client(net, net.wan, vnet.GW_WLAN, "tls", page) == ["HTTP/1.0 200 OK", "csp"]


def test_the_tv_cannot_open_a_connection_to_the_page_with_tvgw_loaded(page, net):
    before = guard_counters(net)
    assert client(net, net.tv, vnet.GW_WLAN, "connect") == ["drop"]  # the weak-host path
    assert client(net, net.tv, vnet.GW_TV, "connect") == ["drop"]
    assert guard_counters(net) == before, "inet tvgw dropped both; the guard must not have seen them"


def test_the_tv_cannot_open_a_connection_to_the_page_with_tvgw_gone(page, net):
    """The stop, a failed boot apply: inet tvgw deleted, the guard alone."""
    net.ns(net.gw, "nft", "delete", "table", "inet", "tvgw")
    try:
        before = guard_counters(net)
        assert client(net, net.tv, vnet.GW_WLAN, "connect") == ["drop"]
        assert client(net, net.tv, vnet.GW_TV, "connect") == ["drop"]
        after = guard_counters(net)
        assert after[WEAK_HOST] > before[WEAK_HOST], "the uplink's address must end at the weak-host rule"
        assert after[FINAL] > before[FINAL], "the gateway's address must end at the guard's last rule"
        assert client(net, net.wan, vnet.GW_WLAN, "tls", page) == ["HTTP/1.0 200 OK", "csp"]
    finally:
        out = net.apply(
            net.gw,
            vnet.render_conf(
                {"UPLINK": "direct", "BLOCK_QUIC": "yes", "STRICT_PORTS": "no", "DNSGATE": "count"}
            ),
        )
        assert out.returncode == 0, out.stderr
