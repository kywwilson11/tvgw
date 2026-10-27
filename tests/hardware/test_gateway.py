"""Hardware tests: run ON the gateway against the live system.

    sudo /opt/tvgw-venv/bin/python -m pytest -m hardware tests/hardware -q

They read the real services, firewall, resolver, URL filter and store; they change nothing.
Each test states the operational guarantee it checks.
"""

from __future__ import annotations

import glob
import os
import shutil
import subprocess
import time
from pathlib import Path

import pytest

from tvgw import config, db, dnsq, profile

pytestmark = pytest.mark.hardware
if not shutil.which("nft") or os.geteuid() != 0:
    pytest.skip("hardware tests run as root on the gateway", allow_module_level=True)
assert os.path.exists("/etc/tvgw/tvgw.conf"), (
    "no /etc/tvgw/tvgw.conf: config.load() would silently use defaults"
)
S = config.load()
PROF = profile.load(S.profile)
DAY = 86400


def sh(*cmd: str) -> str:
    return subprocess.run(cmd, capture_output=True, text=True, timeout=60).stdout


def dns_a(name: str, server: str = "127.0.0.1") -> list[str]:
    """A records from the gateway's resolver (0.0.0.0 = blocked), [] on no answer."""
    return dnsq.a_records(name, server) or []


@pytest.mark.parametrize("unit", ["tvgw", "tvgw-flowlog", "tvgw-pcap", "AdGuardHome", "dnsmasq", "nginx"])
def test_service_active(unit):
    assert sh("systemctl", "is-active", unit).strip() == "active", f"{unit} must be running"


@pytest.mark.parametrize(
    "timer", ["tvgw-analyze.timer", "tvgw-prune.timer", "tvgw-doh-update.timer", "tvgw-verify.timer"]
)
def test_timer_scheduled(timer):
    out = sh("systemctl", "list-timers", "--no-pager", timer)
    lines = out.splitlines()
    assert len(lines) > 1 and timer in out, f"{timer} is not scheduled"
    assert "n/a" not in lines[1], f"{timer} must have a next run"


def test_firewall_table_and_key_rules_present():
    rules = sh("nft", "list", "table", "inet", "tvgw")
    for needle in (
        "dnat ip to 10.10.10.1:53",  # every TV DNS packet goes to AdGuard
        "dport { 784, 853, 8853 }",  # DoT/DoQ rejected
        "ct state invalid",  # never forwarded un-NATed
        "no GRE/ESP/6in4 tunnels",
        "TV DNS aimed elsewhere",  # the bypass counter the brief reports
        "no NetBIOS/SSDP chatter",  # the Pi stays quiet on the TV subnet
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


def _store():
    return db.connect(S.db_path, readonly=True)


def test_store_is_fresh_sound_and_at_the_current_schema():
    conn = _store()
    last_run = float(db.get_meta(conn, "last_run") or 0)
    assert last_run > 0, "store never ingested"
    assert time.time() - last_run < 2 * 3600, "hourly ingest has not run in the last two hours"
    assert conn.execute("PRAGMA quick_check").fetchone()[0] == "ok"
    assert db.get_meta(conn, "schema") == str(db.SCHEMA_VERSION)
    assert db.get_meta(conn, "last_warnings") in (None, "[]"), db.get_meta(conn, "last_warnings")


def test_ingest_twice_adds_nothing_the_second_time():
    """The ingest is idempotent: the second run right after the first finds no new rows at all."""
    first = subprocess.run(["/usr/local/bin/tvgw", "ingest"], capture_output=True, text=True, timeout=900)
    assert first.returncode == 0, first.stdout + first.stderr
    before = db.counts(_store())
    second = subprocess.run(["/usr/local/bin/tvgw", "ingest"], capture_output=True, text=True, timeout=900)
    assert second.returncode == 0, second.stdout + second.stderr
    after = db.counts(_store())
    for t in ("dns", "flows", "tls", "http", "lanprobe", "oddport", "hosts", "rules"):
        assert after[t] == before[t], f"{t}: {before[t]} -> {after[t]} on an immediate re-run"


def test_no_acr_name_answered_and_no_traffic_to_its_addresses_in_24h():
    c, since = _store(), time.time() - DAY
    answered = [q for (q,) in c.execute("SELECT DISTINCT qname FROM dns WHERE blocked=0 AND t>?", (since,))]
    assert [q for q in answered if PROF.categorize(q) == "ACR"] == []
    acr_ips = [
        ip for ip, name in c.execute("SELECT ip, name FROM v_ip_names") if PROF.categorize(name) == "ACR"
    ]
    if acr_ips:
        marks = ",".join("?" * len(acr_ips))
        n = c.execute(
            f"SELECT COUNT(*) FROM flows WHERE t_end>? AND dst IN ({marks})", (since, *acr_ips)
        ).fetchone()[0]
        assert n == 0, f"{n} flows to ACR addresses in the last day"


def test_must_allow_names_were_never_blocked_in_24h():
    names = tuple(PROF.must_allow)
    marks = ",".join("?" * len(names))
    rows = (
        _store()
        .execute(
            f"SELECT qname, COUNT(*) FROM dns WHERE blocked=1 AND t>? AND qname IN ({marks}) GROUP BY qname",
            (time.time() - DAY, *names),
        )
        .fetchall()
    )
    assert rows == [], f"must-allow names came back blocked: {rows}"


def test_capture_is_live_and_the_disk_is_healthy():
    newest = max(glob.glob(os.path.join(S.pcap_dir, "*.pcap")), key=os.path.getmtime)
    power = _store().execute("SELECT power FROM tvstate ORDER BY t DESC LIMIT 1").fetchone()
    if power and power[0] == "Active":
        assert time.time() - os.path.getmtime(newest) < 2 * 3600, (
            "TV is on but no packet captured for two hours"
        )
    assert shutil.disk_usage(S.state_dir).free > 2 * 1024**3, "under 2 GB free where the store and pcaps live"
    errs = sh(
        "journalctl", "-k", "-p", "err", "--since", "-1h", "-g", "I/O error|EXT4-fs error", "--no-pager", "-q"
    )
    assert errs.strip() == "", f"kernel disk errors in the last hour: {errs[:300]}"


def test_tv_has_its_dhcp_reservation_and_acr_is_off_in_the_store():
    conf = Path("/etc/dnsmasq.d/tvgw.conf").read_text()
    assert S.tv_mac and S.tv_mac.lower() in conf.lower() and S.tv_ip in conf
    c = _store()
    row = c.execute(
        "SELECT t, value FROM tvsettings WHERE key='option.livePlus' ORDER BY t DESC LIMIT 1"
    ).fetchone()
    if row is None:
        pytest.skip("no LAN-API reading stored yet")
    assert row[1] == "off", f"Live Plus (ACR) is {row[1]!r} in the latest reading"


def test_nginx_listens_only_on_the_tv_facing_address():
    listeners = [ln for ln in sh("ss", "-ltnH").splitlines() if ln.split()[3].endswith((":80", ":443"))]
    assert listeners, "nginx is not listening"
    for ln in listeners:
        assert ln.split()[3].startswith(S.gw_ip + ":"), f"web listener not bound to the TV side only: {ln}"


def test_dns_redirect_counters_tick_while_the_tv_is_on():
    c = _store()
    active = c.execute(
        "SELECT COUNT(*) FROM tvstate WHERE power='Active' AND t > ?", (time.time() - DAY,)
    ).fetchone()[0]
    if not active:
        pytest.skip("TV not seen on in the last day")
    out = sh("nft", "list", "chain", "inet", "tvgw", "pre_nat")
    import re

    packets = [int(x) for x in re.findall(r"packets (\d+)", out)]
    assert packets and sum(packets) > 0, out


def test_adguard_matches_profile_and_settings():
    """The repo is the source of truth for AdGuard's lists, rules and settings: no drift allowed."""
    out = subprocess.run(
        ["/usr/local/bin/tvgw", "adguard", "diff"], capture_output=True, text=True, timeout=60
    )
    assert out.returncode == 0, f"AdGuard config drifted from the profile:\n{out.stdout}"


def test_tv_isolated_from_lan_counters_exist():
    out = sh("nft", "list", "chain", "inet", "tvgw", "tv_out")
    assert "TV may not reach the home LAN" in out


def test_verify_passes_on_the_live_gateway():
    """`tvgw verify` is what the 10-minute timer runs; on a healthy gateway every check is OK."""
    out = subprocess.run(["/usr/local/bin/tvgw", "verify"], capture_output=True, text=True, timeout=120)
    assert out.returncode == 0, out.stdout + out.stderr
    assert "FAIL" not in out.stdout


def test_ipv6_guard_and_fail_closed_state():
    assert "ether type ip6" in sh("nft", "list", "table", "netdev", "tvgw_l2")
    assert Path("/proc/sys/net/ipv4/ip_forward").read_text().strip() == "1"
    # the per-interface switches are what actually forward the TV's packets (a stop turns eth0 off)
    for dev in (S.tv_if, S.wan_if):
        assert Path(f"/proc/sys/net/ipv4/conf/{dev}/forwarding").read_text().strip() == "1", dev


def test_tv_has_a_route_out():
    """What the TV sees: a packet from its address, entering on its interface, has a way out."""
    out = sh("ip", "-j", "route", "get", "1.1.1.1", "from", S.tv_ip, "iif", S.tv_if)
    assert S.wan_if in out or "tun0" in out, f"no route for the TV's packets: {out!r}"
    assert sh("systemctl", "is-enabled", "nftables.service").strip() in ("masked", "masked-runtime", "")


def test_state_is_not_world_readable():
    import os
    import stat

    st = os.stat("/var/lib/tvgw")
    assert not st.st_mode & stat.S_IROTH, "/var/lib/tvgw must not be world-readable"
    assert not os.stat(S.db_path).st_mode & stat.S_IROTH, "the store must not be world-readable"
    if os.path.exists("/var/lib/tvgw/lgtv-keys.sqlite"):
        assert oct(os.stat("/var/lib/tvgw/lgtv-keys.sqlite").st_mode & 0o777) == "0o600"


def test_tv_lan_api_reachable_or_asleep():
    """Informational: the TV answers the LAN API when on; when off this is a skip, not a failure."""
    from tvgw import lgwebos

    r = lgwebos.read(S.tv_ip, "/var/lib/tvgw/lgtv-keys.sqlite", timeout=10)
    if not r.reachable:
        pytest.skip(f"TV not reachable ({r.error})")
    assert r.acr_off is True, "Live Plus (ACR) must be off"
