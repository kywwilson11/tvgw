"""`tvgw verify` prints no home identifier (design decision 63). Its output ends every deploy's log,
which may be shared, and its details are stored and shown in the brief. The fake gateway here has a
router, uplink and VPN tunnel on documentation addresses, documentation MACs, a USB adapter named
after its MAC, a host name and a Wi-Fi network, and plants them wherever a check prints what it read;
no detail, no `--json` field and no stored failure may carry one. This audits every check there is,
the ones added later included, since each is a `Check`."""

import dataclasses
import json
import sqlite3

import pytest
from test_verify import S, gateway, resolver

from tvgw import db, dnsq, flowlog, scrub, verify

ROUTER, UPLINK, UPLINK6, TUNNEL = "192.0.2.1", "192.0.2.10", "2001:db8::10", "198.51.100.2"
TV_MAC, ADAPTER = "00:00:5e:00:53:01", "enx00005e005303"
HOST, WIFI, TV_NAME = "gateway-under-test", "example-wifi", "living-room-tv"
SITE = (
    ROUTER,
    UPLINK,
    UPLINK6,
    TUNNEL,
    "198.51.100.7",
    TV_MAC,
    "00:00:5e:00:53",
    ADAPTER,
    HOST,
    WIFI,
    TV_NAME,
)
SETTINGS = dataclasses.replace(S, tv_mac=TV_MAC, tv_name=TV_NAME)
ROUTE_GET = ("ip", "-j", "route", "get", "1.1.1.1", "from", "10.10.10.17", "iif", "eth0")


def site_gateway():
    """test_verify's healthy gateway, on a home with identifiers, several of which reach a detail: the
    TV's route leaves by the USB adapter, the URL filter's names answer with the router, the host name
    and the Wi-Fi name, a list sentinel answers with an address, and the uplink stops forwarding."""
    host = gateway(
        {
            ("ip", "-j", "route", "show", "default"): json.dumps([{"gateway": ROUTER, "dev": "wlan0"}]),
            ("ip", "-j", "addr", "show"): json.dumps(
                [
                    {"ifname": "eth0", "addr_info": [{"local": "10.10.10.1"}]},
                    {"ifname": "wlan0", "addr_info": [{"local": UPLINK}, {"local": UPLINK6}]},
                    {"ifname": "wgpia0", "addr_info": [{"local": TUNNEL}]},
                ]
            ),
            ("nmcli", "-t", "-f", "NAME,TYPE", "connection", "show"): f"{WIFI}:802-11-wireless\n",
            ROUTE_GET: json.dumps([{"dst": "1.1.1.1", "dev": ADAPTER, "gateway": ROUTER}]),
        },
        files={
            scrub.HOSTNAME: f"{HOST}\n",
            verify.CONF: f"WAN_GW={ROUTER}\nTV_MAC={TV_MAC}\nTV_NAME={TV_NAME}\n",
            "/proc/sys/net/ipv4/conf/wlan0/forwarding": "0\n",
        },
    )
    answers = {name: [ROUTER, HOST, WIFI] for name in ("ngfts.lge.com", "gfts.lge.com")}
    answers["h4g3z1-pro.web.app"] = ["198.51.100.7"]
    answers["us.lgtvsdp.com"] = [f"{TV_NAME}.{WIFI}"]  # a name typed on the TV, as an answer
    return host, resolver(answers)


def leaks(text: str) -> list[str]:
    return [value for value in SITE if value.lower() in text.lower()]


def test_no_detail_or_line_names_the_home(lg):
    host, resolve = site_gateway()
    r = verify.check(SETTINGS, lg, **host, resolve=resolve)
    assert {c.name: leaks(c.detail) for c in r.checks if leaks(c.detail)} == {}
    assert [c.line() for c in r.checks if leaks(c.line())] == []
    assert leaks(json.dumps(r.failures)) == []
    by_name = {c.name: c for c in r.checks}
    # the planted values were there to leak, and each came out as its placeholder
    assert by_name["tv_route"].detail == "via usb-ethernet-1, expected wlan0"
    assert "->['<router>', '<this computer>', '<wifi name>']" in by_name["resolver_rewrite"].detail
    assert "h4g3z1-pro.web.app->['<lan address>']" in by_name["list_sentinels"].detail
    assert "wlan0 not forwarding" in by_name["forwarding"].detail


def test_the_raw_detail_stays_for_the_gateway_and_out_of_every_printed_form(lg):
    host, resolve = site_gateway()
    r = verify.check(SETTINGS, lg, **host, resolve=resolve)
    route = next(c for c in r.checks if c.name == "tv_route")
    assert route.raw == f"via {ADAPTER}, expected wlan0"
    assert ADAPTER not in repr(route) and "raw" not in route.as_dict()
    assert route == dataclasses.replace(route, raw="")  # raw takes no part in comparing checks


def test_scrubbing_never_changes_a_verdict(lg, monkeypatch):
    """The same failing gateway with and without the scrubber: every check keeps its name, its pass
    or fail and its WARN."""
    host, resolve = site_gateway()
    scrubbed = verify.check(SETTINGS, lg, **host, resolve=resolve)
    monkeypatch.setattr(scrub, "scrub_for", lambda s, **kw: lambda text: text)
    plain = verify.check(SETTINGS, lg, **host, resolve=resolve)
    assert [(c.name, c.ok, c.warn) for c in scrubbed.checks] == [(c.name, c.ok, c.warn) for c in plain.checks]
    assert leaks(" ".join(c.detail for c in plain.checks))  # without it the fixture does leak
    assert not scrubbed.ok


def test_the_json_output_names_nothing_of_the_home(lg, monkeypatch, capsys):
    host, resolve = site_gateway()
    monkeypatch.setattr(verify, "run_cmd", host["run"])
    monkeypatch.setattr(verify, "read_file", host["read"])
    monkeypatch.setattr(verify, "file_mtime", host["mtime"])
    monkeypatch.setattr(flowlog, "event_sockets", host["sockets"])
    monkeypatch.setattr(dnsq, "a_records", lambda name, server, timeout=4.0: resolve(name))
    assert verify.main(SETTINGS, lg, as_json=True) == 1
    out = capsys.readouterr().out
    doc = json.loads(out)
    assert leaks(out) == [] and all(set(c) <= {"name", "ok", "detail", "warn"} for c in doc["checks"])
    assert verify.main(SETTINGS, lg) == 1
    assert leaks(capsys.readouterr().out) == []


def test_the_stored_failures_name_nothing_of_the_home(lg, tmp_path):
    host, resolve = site_gateway()
    r = verify.check(SETTINGS, lg, **host, resolve=resolve)
    conn = db.connect(str(tmp_path / "tvgw.db"))
    try:
        verify.record(conn, r)
        (stored,) = conn.execute("SELECT failures FROM verify").fetchone()
    finally:
        conn.close()
    assert json.loads(stored) and leaks(stored) == []


def test_a_check_made_outside_a_run_is_scrubbed_for_the_default_tv_subnet(lg):
    """A check function called on its own (the hardware suite, a test) gets the default scrubber, and
    a run's own scrubber does not outlive the run."""
    loose = verify.Check("x", False, f"via {ROUTER} from {TV_MAC} on {ADAPTER}, to 10.10.10.17 and 1.1.1.1")
    assert loose.detail == "via <lan address> from <mac> on usb-ethernet-1, to 10.10.10.17 and 1.1.1.1"
    host, resolve = site_gateway()
    verify.check(SETTINGS, lg, **host, resolve=resolve)
    assert verify.Check("x", True, HOST).detail == HOST  # the run's host name went with the run


def test_a_failing_run_still_resets_the_scrubber(lg):
    host, _ = site_gateway()

    def broken(name):
        raise sqlite3.OperationalError("database is locked")

    with pytest.raises(sqlite3.OperationalError):
        verify.check(SETTINGS, lg, **host, resolve=broken)
    assert verify.Check("x", True, HOST).detail == HOST
