"""Hardware tests: run ON the gateway against the live system.

    sudo /opt/tvgw-venv/bin/python -m pytest -m hardware tests/hardware -q

They read the real services, firewall, resolver, URL filter and store; they change nothing.
Each test states the operational guarantee it checks.
"""

from __future__ import annotations

import glob
import json
import os
import shutil
import sqlite3
import stat
import subprocess
import time
from pathlib import Path

import pytest

from tvgw import config, db, dnsq, profile, queries, verify

pytestmark = pytest.mark.hardware
if not shutil.which("nft") or os.geteuid() != 0:
    pytest.skip("hardware tests run as root on the gateway", allow_module_level=True)
assert os.path.exists("/etc/tvgw/tvgw.conf"), (
    "no /etc/tvgw/tvgw.conf: config.load() would silently use defaults"
)
S = config.load()
PROF = profile.load(S.profile)
DAY = 86400
REPO = Path(__file__).resolve().parents[2]
# what install.sh copies byte for byte (checkout path -> installed path); the generated configs and
# the site files (tvgw.conf, block4.txt) are judged apart. tests/unit/test_deploy_lint.py checks the
# sources exist, so a renamed file fails before a deploy
INSTALLED = {
    "deploy/nftables/tvgw-apply": "/usr/local/sbin/tvgw-apply",
    "deploy/bin/tvgw-analyze": "/usr/local/sbin/tvgw-analyze",
    "deploy/bin/tvgw-doh-update": "/usr/local/sbin/tvgw-doh-update",
    "deploy/networkmanager/90-tvgw.conf": "/etc/NetworkManager/conf.d/90-tvgw.conf",
    "deploy/networkmanager/90-tvgw-dispatcher": "/etc/NetworkManager/dispatcher.d/90-tvgw",
    "deploy/logrotate/tvgw": "/etc/logrotate.d/tvgw",
    "deploy/nftables/doh-exclude.txt": "/etc/tvgw/doh-exclude.txt",
}
INSTALLED.update(
    {
        f"deploy/systemd/{unit.name}": f"/etc/systemd/system/{unit.name}"
        for unit in (REPO / "deploy" / "systemd").iterdir()
        if unit.suffix in (".service", ".timer")
    }
)
ENABLED = (
    "tvgw.service",
    "tvgw-flowlog.service",
    "tvgw-pcap.service",
    "tvgw-dnsgate.service",
    "tvgw-analyze.timer",
    "tvgw-prune.timer",
    "tvgw-doh-update.timer",
    "tvgw-verify.timer",
    "tvgw-backup.timer",
)
# rules whose text must be in the live table, as `nft list table` prints them; the deploy lint checks
# each against tvgw-apply's text with the gateway address as $TV_ADDR
KEY_RULES = (
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
)
# one row per event: the key a re-read of the same source would repeat
NATURAL_KEYS = {
    "flows": ("t_end", "dst", "dport", "sport"),
    "dns": ("t", "qname", "qtype"),
    "tls": ("t", "dst", "sport"),
    "http": ("t", "host", "uri", "src"),
    "lanprobe": ("t", "dst", "dport"),
    "oddport": ("t", "raw"),
    "gate": ("t", "raw"),
}


def sh(*cmd: str) -> str:
    return subprocess.run(cmd, capture_output=True, text=True, timeout=60).stdout


def dns_a(name: str, server: str = "127.0.0.1") -> list[str]:
    """A records from the gateway's resolver (0.0.0.0 = blocked), [] on no answer."""
    return dnsq.a_records(name, server) or []


@pytest.mark.parametrize("unit", ["tvgw", "tvgw-flowlog", "tvgw-pcap", "AdGuardHome", "dnsmasq", "nginx"])
def test_service_active(unit):
    assert sh("systemctl", "is-active", unit).strip() == "active", f"{unit} must be running"


@pytest.mark.parametrize("unit", ENABLED)
def test_unit_enabled(unit):
    """It comes back at boot. install.sh's enable was `|| true` once, so a unit that failed to enable
    passed every test until the next reboot."""
    assert sh("systemctl", "is-enabled", unit).strip() == "enabled", f"{unit} would not start at boot"


@pytest.mark.parametrize("source", sorted(INSTALLED))
def test_installed_file_matches_the_checkout(source):
    """The gateway runs what the repository says. `ruleset_unchanged` compares the live rules against
    the last apply, which is circular; nothing linked the installed tree to the checkout, and
    doh-exclude.txt had drifted from it for a month."""
    installed = INSTALLED[source]
    assert Path(installed).read_bytes() == (REPO / source).read_bytes(), f"{installed} differs from {source}"


def test_generated_configs_match_the_templates():
    """The dnsmasq and nginx files are the templates with this gateway's settings filled in."""
    dnsmasq = (REPO / "deploy" / "dnsmasq" / "tvgw.conf.template").read_text()
    for placeholder, value in (("__TV_MAC__", S.tv_mac), ("__TV_IP__", S.tv_ip), ("__TV_NAME__", S.tv_name)):
        dnsmasq = dnsmasq.replace(placeholder, value)
    assert Path("/etc/dnsmasq.d/tvgw.conf").read_text() == dnsmasq
    conf = config.parse_conf(Path("/etc/tvgw/tvgw.conf").read_text())
    resolver = conf.get("URL_FILTER_RESOLVER") or "1.1.1.1"  # install.sh's default
    for template, installed in (
        ("tvgw-gfts.conf", "/etc/nginx/conf.d/tvgw-gfts.conf"),
        ("stream.conf", "/etc/nginx/tvgw/stream.conf"),
    ):
        expected = (REPO / "deploy" / "nginx" / template).read_text().replace("__RESOLVER__", resolver)
        assert Path(installed).read_text() == expected, f"{installed} differs from deploy/nginx/{template}"


def test_stock_nftables_service_is_masked():
    """Its `flush ruleset` would wipe the VPN client's rules and ours the day someone enabled it."""
    assert sh("systemctl", "is-enabled", "nftables.service").strip() in ("masked", "masked-runtime")


@pytest.mark.parametrize(
    "timer",
    [
        "tvgw-analyze.timer",
        "tvgw-prune.timer",
        "tvgw-doh-update.timer",
        "tvgw-verify.timer",
        "tvgw-backup.timer",
        "tvgw-analyst.timer",
    ],
)
def test_timer_scheduled(timer):
    out = sh("systemctl", "list-timers", "--no-pager", timer)
    lines = out.splitlines()
    assert len(lines) > 1 and timer in out, f"{timer} is not scheduled"
    assert "n/a" not in lines[1], f"{timer} must have a next run"


def test_firewall_table_and_key_rules_present():
    rules = sh("nft", "list", "table", "inet", "tvgw")
    for needle in KEY_RULES:
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
    if PROF.url_filter is None:
        pytest.skip("profile has no URL filter")
    for name in PROF.url_filter.hosts:
        assert dns_a(name) == [S.gw_ip], f"{name} must resolve to the gateway for the URL filter"


def test_nginx_filter_regex_matches_the_profile():
    """The nginx config is static; it must carry the profile's block_regex verbatim."""
    if PROF.url_filter is None:
        pytest.skip("profile has no URL filter")
    conf = Path("/etc/nginx/conf.d/tvgw-gfts.conf").read_text()
    assert PROF.url_filter.block_regex in conf, (
        "deploy/nginx/tvgw-gfts.conf regex differs from the profile's block_regex"
    )


def test_url_filter_blocks_and_passes():
    if PROF.url_filter is None:
        pytest.skip("profile has no URL filter")
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


def test_ingest_twice_duplicates_nothing():
    """Ingest is idempotent: the second run stores no event the first already had. Raw counts could
    not say so while conntrack and the query log keep arriving (the old test failed exactly when the
    TV was in use), so each table is judged by its natural key against the rows that were there
    before the second run; `IS` is NULL-safe equality."""

    def ingest():
        r = subprocess.run(["/usr/local/bin/tvgw", "ingest"], capture_output=True, text=True, timeout=900)
        assert r.returncode == 0, r.stdout + r.stderr

    ingest()
    c = _store()
    high = {t: c.execute(f"SELECT COALESCE(MAX(id), 0) FROM {t}").fetchone()[0] for t in NATURAL_KEYS}
    rules = db.counts(c)["rules"]
    ingest()
    c = _store()
    for table, cols in NATURAL_KEYS.items():
        same = " AND ".join(f"n.{col} IS o.{col}" for col in cols)
        n = c.execute(
            f"SELECT COUNT(*) FROM {table} n JOIN {table} o ON {same} WHERE n.id > ? AND o.id <= ?",
            (high[table], high[table]),
        ).fetchone()[0]
        assert n == 0, f"{table}: the second run stored {n} row(s) the first already had"
    assert db.counts(c)["rules"] == rules, "a re-run must not change the rule history"


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


def test_must_allow_names_were_never_blocked_since_the_exceptions_were_applied():
    """Within the last day, and only since the current @@ exceptions exist (an earlier experiment may
    legitimately have blocked a name before it was declared must-allow)."""
    c = _store()
    names = tuple(PROF.must_allow)
    marks = ",".join("?" * len(names))
    applied = c.execute(
        "SELECT MAX(first_seen) FROM rules WHERE kind='adguard' AND text LIKE '@@%'"
    ).fetchone()[0]
    since = max(time.time() - DAY, applied or 0)
    rows = c.execute(
        f"SELECT qname, COUNT(*) FROM dns WHERE blocked=1 AND t>? AND qname IN ({marks}) GROUP BY qname",
        (since, *names),
    ).fetchall()
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


def test_dns_chain_counted_packets_while_the_tv_was_on():
    """The DNS chain is live and recorded: the store's counter snapshots, the brief's own evidence,
    show TV DNS reaching the gateway in the last day and the bypass counter being recorded. The live
    counters are no use here: install.sh re-applies, and zeroes them, seconds before this runs."""
    c = _store()
    active = c.execute(
        "SELECT COUNT(*) FROM tvstate WHERE power='Active' AND t > ?", (time.time() - DAY,)
    ).fetchone()[0]
    if not active:
        pytest.skip("TV not seen on in the last day")
    activity = dict(queries.fw_activity(c, time.time() - DAY))
    assert activity.get("TV DNS to the gateway", 0) > 0, (
        f"no TV DNS counted at the gateway in a day: {activity}"
    )
    assert "TV DNS aimed elsewhere -> AdGuard" in activity, "the DNS bypass counter is not being recorded"


def test_adguard_matches_profile_and_settings():
    """The repo is the source of truth for AdGuard's lists, rules and settings: no drift allowed."""
    out = subprocess.run(
        ["/usr/local/bin/tvgw", "adguard", "diff"], capture_output=True, text=True, timeout=60
    )
    assert out.returncode == 0, f"AdGuard config drifted from the profile:\n{out.stdout}"


def test_tv_isolated_from_lan_counters_exist():
    out = sh("nft", "list", "chain", "inet", "tvgw", "tv_out")
    assert "TV may not reach the home LAN" in out


def test_reports_are_written_from_the_store():
    """tvgw-analyze writes reports/latest (last 24 h) every run and one daily file per finished day."""
    latest = Path(S.reports_dir) / "latest.txt"
    assert latest.exists(), "reports/latest.txt missing: tvgw-analyze has not run"
    assert time.time() - latest.stat().st_mtime < 2 * 3600, "reports/latest.txt is stale"
    text = latest.read_text()
    assert text.startswith("=== last 24 h") and "Coverage:" in text and "By category:" in text
    oldest = _store().execute("SELECT MIN(t) FROM dns").fetchone()[0]
    import datetime as dt

    yesterday = (dt.date.today() - dt.timedelta(days=1)).isoformat()
    day_start = time.mktime(dt.date.today().timetuple())
    # yesterday's file is written from 03:20, once idle connections and the last pcap have landed
    if oldest and oldest < day_start and time.time() - day_start >= 3 * 3600 + 20 * 60:
        assert (Path(S.reports_dir) / "daily" / f"{yesterday}.txt").exists(), (
            "yesterday's daily report missing"
        )
    assert not Path("/var/lib/tvgw/archive").exists() and not Path("/usr/local/sbin/tvgw-extract").exists()


def test_verify_passes_on_the_live_gateway():
    """`tvgw verify` is what the 10-minute timer runs; on a healthy gateway every check is OK."""
    out = subprocess.run(["/usr/local/bin/tvgw", "verify"], capture_output=True, text=True, timeout=120)
    assert out.returncode == 0, out.stdout + out.stderr
    assert "FAIL" not in out.stdout


def test_doh_list_is_current():
    """tvgw-doh-update replaced the list within the last eight days and kept at least 50 entries;
    `tvgw verify` fails doh4_fresh and doh4_loaded on the same facts."""
    doh4 = Path(S.state_dir) / "doh4.txt"
    assert doh4.exists(), "no doh4.txt: tvgw-doh-update has never succeeded"
    assert time.time() - doh4.stat().st_mtime < 8 * DAY, "doh4.txt is over a week old"
    assert len(doh4.read_text().splitlines()) >= 50


def test_ipv6_guard_and_fail_closed_state():
    assert "ether type ip6" in sh("nft", "list", "table", "netdev", "tvgw_l2")
    assert Path("/proc/sys/net/ipv4/ip_forward").read_text().strip() == "1"
    # the per-interface switches are what actually forward the TV's packets (a stop turns eth0 off)
    for dev in (S.tv_if, S.wan_if):
        assert Path(f"/proc/sys/net/ipv4/conf/{dev}/forwarding").read_text().strip() == "1", dev


def test_tv_has_a_route_out():
    """What the TV sees: a packet from its address, entering on its interface, leaves by the uplink the
    settings name. `wan_if in out or "tun0" in out` passed with the TV's packets going into the tunnel
    in direct mode, where tv_out drops them: a dark TV."""
    expected = S.wan_if if S.uplink == "direct" else "tun0"
    out = sh("ip", "-j", "route", "get", "1.1.1.1", "from", S.tv_ip, "iif", S.tv_if)
    route = json.loads(out or "[]")
    assert route and route[0].get("dev") == expected, f"expected a route out {expected}: {out!r}"


def test_state_is_not_world_readable():
    assert not os.stat("/etc/tvgw/tvgw.conf").st_mode & stat.S_IROTH, "the settings file holds the TV's MAC"
    st = os.stat("/var/lib/tvgw")
    assert not st.st_mode & stat.S_IROTH, "/var/lib/tvgw must not be world-readable"
    assert not os.stat(S.db_path).st_mode & stat.S_IROTH, "the store must not be world-readable"
    if os.path.exists("/var/lib/tvgw/lgtv-keys.sqlite"):
        assert oct(os.stat("/var/lib/tvgw/lgtv-keys.sqlite").st_mode & 0o777) == "0o600"
    for log in glob.glob("/var/log/tvgw/*.log"):
        assert not os.stat(log).st_mode & stat.S_IROTH, f"{log} is world-readable"
    assert not os.stat(S.pcap_dir).st_mode & stat.S_IROTH, "pcap dir must not be world-readable"
    for f in glob.glob(os.path.join(S.state_dir, "*")):  # the dir is traversable, so each file matters
        if os.path.isfile(f):
            assert not os.stat(f).st_mode & stat.S_IROTH, f"{f} is world-readable"
    assert glob.glob(os.path.join(S.state_dir, ".doh4.*")) == [], "tvgw-doh-update left a staged list behind"
    for pcap in glob.glob(os.path.join(S.pcap_dir, "*.pcap")):
        assert not os.stat(pcap).st_mode & stat.S_IROTH, f"{pcap} is world-readable"


def test_pcaps_are_readable_by_the_extractor_and_owned_by_the_capture_user():
    """tcpdump chowns its files to its -Z user; with root that made them unreadable to the unprivileged
    tshark (2026-10-27, second incident). Every pcap must be readable as nobody and owned by tvgw-pcap."""
    import pwd

    files = sorted(glob.glob(os.path.join(S.pcap_dir, "*.pcap")), key=os.path.getmtime)
    assert files, "no pcaps at all"
    newest = files[-1]
    assert pwd.getpwuid(os.stat(newest).st_uid).pw_name == "tvgw-pcap", f"{newest} is not owned by tvgw-pcap"
    rc = subprocess.run(
        ["setpriv", "--reuid=nobody", "--regid=nogroup", "--clear-groups", "--", "test", "-r", newest]
    ).returncode
    assert rc == 0, f"nobody cannot read {newest}"
    rc = subprocess.run(
        ["setpriv", "--reuid=nobody", "--regid=nogroup", "--clear-groups", "--", "test", "-w", newest]
    ).returncode
    assert rc != 0, f"nobody can write {newest}: a compromised extractor could alter evidence"


def test_finished_pcaps_yield_rows_while_the_tv_is_on():
    """The unprivileged tshark must be able to read the pcaps: a finished hour with the TV on and
    zero TLS rows means the extraction is silently broken (2026-10-27)."""
    c = _store()
    recent = c.execute(
        "SELECT name, tls_rows FROM pcaps_done WHERE error IS NULL AND done_at > ? ORDER BY name DESC LIMIT 3",
        (time.time() - 4 * 3600,),
    ).fetchall()
    active = c.execute(
        "SELECT COUNT(*) FROM tvstate WHERE power='Active' AND t > ?", (time.time() - 4 * 3600,)
    ).fetchone()[0]
    if not recent or not active:
        pytest.skip("no finished pcap in the last four hours, or TV not on")
    assert any(rows > 0 for _, rows in recent), f"finished pcaps yielded no TLS rows: {recent}"


def test_tv_lan_api_reachable_or_asleep():
    """Informational: the TV answers the LAN API when on; when off this is a skip, not a failure."""
    from tvgw import lgwebos

    r = lgwebos.read(S.tv_ip, "/var/lib/tvgw/lgtv-keys.sqlite", timeout=10)
    if not r.reachable:
        pytest.skip(f"TV not reachable ({r.error})")
    assert r.acr_off is True, "Live Plus (ACR) must be off"


def test_backup_copy_is_fresh_and_sound():
    """A checked copy of the store exists beside it (install.sh runs the first one), is under 36 hours
    old, passes quick_check, holds the data, and is readable by root and the admin group only."""
    copies = sorted(glob.glob(os.path.join(S.state_dir, "backup", "tvgw-*.db")))
    assert copies, "no backup copy: did tvgw-backup.service run?"
    newest = copies[-1]
    assert time.time() - os.path.getmtime(newest) < 36 * 3600, f"{newest} is stale"
    st = os.stat(newest)
    assert stat.S_IMODE(st.st_mode) == 0o640 and st.st_uid == 0, oct(st.st_mode)
    conn = sqlite3.connect(f"file:{newest}?mode=ro", uri=True)
    try:
        assert [r[0] for r in conn.execute("PRAGMA quick_check")] == ["ok"]
        assert conn.execute("SELECT COUNT(*) FROM dns").fetchone()[0] > 0
    finally:
        conn.close()


def test_capture_runs_as_the_capture_user_with_two_capabilities():
    """tcpdump never runs as root: the unit starts as tvgw-pcap holding only CAP_NET_RAW and
    CAP_NET_ADMIN, so a bug in the dissector of a frame the TV sent cannot become root."""
    import pwd

    pid = int(sh("systemctl", "show", "-p", "MainPID", "--value", "tvgw-pcap.service").strip() or 0)
    assert pid > 0, "tvgw-pcap has no main process"
    status = dict(
        line.split(":\t", 1) for line in Path(f"/proc/{pid}/status").read_text().splitlines() if ":\t" in line
    )
    assert int(status["Uid"].split()[0]) == pwd.getpwnam("tvgw-pcap").pw_uid, status["Uid"]
    assert int(status["CapBnd"], 16) == (1 << 12) | (1 << 13), status["CapBnd"]  # NET_ADMIN, NET_RAW


def test_dns_gate_table_set_rule_and_feeder_are_in_place():
    """DNSGATE=count: the gate table holds the set and the counting rule, the feeder runs, and after an
    hour of the TV being on the set holds addresses (the TV looks names up every few minutes)."""
    if S.dnsgate == "off":
        pytest.skip("DNSGATE=off")
    listing = sh("nft", "list", "table", "inet", "tvgw_gate")
    assert "set resolved4" in listing and "TV to an address DNS never returned" in listing, listing[:400]
    assert sh("systemctl", "is-active", "tvgw-dnsgate.service").strip() == "active"
    n = verify.set_size(sh("nft", "-j", "list", "set", "inet", "tvgw_gate", "resolved4"))
    states = _store().execute("SELECT power FROM tvstate ORDER BY t DESC LIMIT 2").fetchall()
    # the set starts empty when the feeder (re)starts, which every deploy does: judge it only once the
    # feeder has had a quarter of an hour of the TV's lookups to collect
    started = sh(
        "systemctl", "show", "-p", "ActiveEnterTimestampMonotonic", "--value", "tvgw-dnsgate.service"
    )
    uptime = float(Path("/proc/uptime").read_text().split()[0])
    feeder_age = uptime - float(started or 0) / 1e6 if started.strip() else 0.0
    if len(states) == 2 and all(p == ("Active",) for p in states) and feeder_age > 900:
        assert n > 0, (
            "TV on for an hour but the gate set is empty: is tvgw-dnsgate seeing the resolver's answers?"
        )


def test_analyst_dry_run_pack_carries_no_home_identifier():
    """What the analyst would send is built from the live store and must hold no address, MAC or name
    of the home: the scrub is the guarantee and this is its test on real data."""
    import datetime
    import socket

    day = (datetime.date.today() - datetime.timedelta(days=1)).isoformat()
    out = subprocess.run(
        ["tvgw", "analyst", "--dry-run", "--day", day], capture_output=True, text=True, timeout=300
    )
    assert out.returncode == 0, out.stdout + out.stderr
    path = Path(S.reports_dir, "proposals", f"{day}.pack.json")
    pack = path.read_text().lower()
    for leak in (S.tv_mac, "10.10.10.", "192.168.", socket.gethostname()):
        assert not leak or leak.lower() not in pack, f"the pack carries {leak!r}"
    if len(S.tv_name) >= 3:
        assert S.tv_name.lower() not in pack
    assert not os.stat(path).st_mode & stat.S_IROTH


def test_analyst_timer_follows_the_conf_schedule():
    """install.sh renders ANALYST_SCHEDULE into a timer drop-in; the live timer must say the same."""
    sched = S.analyst_schedule
    expected = {"hourly": "hourly"}.get(
        sched, f"*-*-* {sched}:00" if len(sched) == 5 and sched[2] == ":" else sched
    )
    shown = sh("systemctl", "show", "-p", "TimersCalendar", "--value", "tvgw-analyst.timer")
    assert expected.replace(" ", "") in shown.replace(" ", ""), (expected, shown)
