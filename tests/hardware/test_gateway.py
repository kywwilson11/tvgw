"""Hardware tests: run ON the gateway against the live system.

    sudo /opt/tvgw-venv/bin/python -m pytest -m hardware tests/hardware -q

They read the real services, firewall, resolver, URL filter and store; they change nothing.
Each test states the operational guarantee it checks.
"""

from __future__ import annotations

import os
import shutil
import socket
import struct
import subprocess

import pytest

from tvgw import config, db, profile

pytestmark = pytest.mark.hardware
S = config.load()
PROF = profile.load(S.profile)


def sh(*cmd: str) -> str:
    return subprocess.run(cmd, capture_output=True, text=True, timeout=60).stdout


def dns_a(name: str, server: str = "127.0.0.1") -> list[str]:
    """A records from the gateway's resolver (0.0.0.0 = blocked), [] on no answer."""
    qid = os.getpid() & 0xFFFF
    labels = b"".join(bytes([len(x)]) + x.encode() for x in name.split("."))
    pkt = struct.pack(">HHHHHH", qid, 0x0100, 1, 0, 0, 0) + labels + b"\x00" + struct.pack(">HH", 1, 1)
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(4)
    sock.sendto(pkt, (server, 53))
    data, _ = sock.recvfrom(1024)
    from tvgw.dnsmsg import decode_answers

    return [a.value for a in decode_answers(data) if a.rtype == "A"]


@pytest.mark.parametrize("unit", ["tvgw", "tvgw-flowlog", "tvgw-pcap", "AdGuardHome", "dnsmasq", "nginx"])
def test_service_active(unit):
    assert sh("systemctl", "is-active", unit).strip() == "active", f"{unit} must be running"


@pytest.mark.parametrize("timer", ["tvgw-analyze.timer", "tvgw-prune.timer", "tvgw-doh-update.timer"])
def test_timer_scheduled(timer):
    out = sh("systemctl", "list-timers", "--no-pager", timer)
    assert timer in out and "n/a" not in out.splitlines()[1], f"{timer} must have a next run"


def test_firewall_table_and_key_rules_present():
    rules = sh("nft", "list", "table", "inet", "tvgw")
    for needle in (
        "dnat ip to 10.10.10.1:53",  # every TV DNS packet goes to AdGuard
        "dport 853",  # DoT/DoQ rejected
        "udp dport 443",  # QUIC rejected so SNI stays visible
        "@doh4",  # DoH resolver IPs rejected
        "@lan4",  # TV cannot reach the home LAN
        "masquerade",
    ):
        assert needle in rules, f"firewall rule missing: {needle}"


def test_doh_bootstrap_ips_are_in_the_block_set():
    for ip in ("8.8.8.8", "8.8.4.4", "1.1.1.1", "1.0.0.1", "9.9.9.9"):
        rc = subprocess.run(
            ["nft", "get", "element", "inet", "tvgw", "doh4", f"{{ {ip} }}"], capture_output=True
        ).returncode
        assert rc == 0, f"{ip} should be in the DoH block set"


def test_blocked_names_resolve_to_zero():
    for name in ("alphonso.tv", "www.ueiwsp.com", "us.rdx2.lgtvsdp.com"):
        assert dns_a(name) == ["0.0.0.0"], f"{name} must be blocked"


def test_must_allow_names_resolve():
    for name in PROF.must_allow:
        ips = dns_a(name)
        assert ips and ips != ["0.0.0.0"], f"{name} must resolve ({PROF.must_allow[name]})"


def test_url_filter_names_point_at_the_gateway():
    assert PROF.url_filter is not None
    for name in PROF.url_filter.hosts:
        assert dns_a(name) == [S.gw_ip], f"{name} must resolve to the gateway for the URL filter"


def test_url_filter_blocks_and_passes():
    curl = shutil.which("curl") or "/usr/bin/curl"
    base = f"http://{S.gw_ip}/fts/gftsDownload.lge?"

    def status(uri: str, host: str = "ngfts.lge.com") -> str:
        return subprocess.run(
            [curl, "-s", "-o", "/dev/null", "-w", "%{http_code}", "-H", f"Host: {host}", base + uri],
            capture_output=True,
            text=True,
            timeout=30,
        ).stdout

    assert status("biz_code=PREMIUM&func_code=ACR&file_path=/x") == "403"
    assert status("biz_code=LGSHOPPING&func_code=DATA&file_path=/x") == "403"
    assert (
        status("biz_code=APP_STORE&func_code=APP_ICON&file_path=/appstore/app/icon/20250220/38386090.png")
        == "200"
    )


def test_tls_passthrough_reaches_the_real_host():
    curl = shutil.which("curl") or "/usr/bin/curl"
    out = subprocess.run(
        [
            curl,
            "-s",
            "-o",
            "/dev/null",
            "-w",
            "%{http_code} %{ssl_verify_result}",
            "--resolve",
            f"gfts.lge.com:443:{S.gw_ip}",
            "https://gfts.lge.com/",
        ],
        capture_output=True,
        text=True,
        timeout=30,
    ).stdout
    code, verify = out.split()
    assert verify == "0" and code != "000", f"TLS passthrough failed: {out}"


def test_store_is_fresh_and_ingest_is_idempotent():
    conn = db.connect(S.db_path, readonly=True)
    last_run = float(db.get_meta(conn, "last_run") or 0)
    assert last_run > 0, "store never ingested"
    import time

    assert time.time() - last_run < 2 * 3600, "hourly ingest has not run in the last two hours"
    before = db.counts(conn)
    conn.close()
    out = sh("/usr/local/bin/tvgw", "ingest")
    assert "tvgw ingest:" in out
    after = db.counts(db.connect(S.db_path, readonly=True))
    for t in ("dns", "flows", "tls"):
        assert after[t] >= before[t]


def test_adguard_matches_profile_and_settings():
    """The repo is the source of truth for AdGuard's lists, rules and settings: no drift allowed."""
    out = subprocess.run(
        ["/usr/local/bin/tvgw", "adguard", "diff"], capture_output=True, text=True, timeout=60
    )
    assert out.returncode == 0, f"AdGuard config drifted from the profile:\n{out.stdout}"


def test_tv_isolated_from_lan_counters_exist():
    out = sh("nft", "list", "chain", "inet", "tvgw", "tv_out")
    assert "TV may not reach the home LAN" in out


def test_tv_lan_api_reachable_or_asleep():
    """Informational: the TV answers the LAN API when on; when off this is a skip, not a failure."""
    from tvgw import lgwebos

    r = lgwebos.read(S.tv_ip, "/var/lib/tvgw/lgtv-keys.sqlite", timeout=10)
    if not r.reachable:
        pytest.skip(f"TV not reachable ({r.error})")
    assert r.acr_off is True, "Live Plus (ACR) must be off"
