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

from tvgw import config, db, dnsq, guard, pcaps, profile, queries, verify

pytestmark = pytest.mark.hardware
if not shutil.which("nft") or os.geteuid() != 0:
    pytest.skip("hardware tests run as root on the gateway", allow_module_level=True)
assert os.path.exists("/etc/tvgw/tvgw.conf"), (
    "no /etc/tvgw/tvgw.conf: config.load() would silently use defaults"
)
S = config.load()
PROF = profile.load(S.profile)
DAY = 86400
PCAP_HEADER = 24  # (capture) bytes in a pcap's global header, the size of a file with no packet
REPO = Path(__file__).resolve().parents[2]
# what install.sh copies byte for byte (checkout path -> installed path); the generated configs and
# the site files (tvgw.conf, block4.txt) are judged apart. tests/unit/test_deploy_lint.py checks the
# sources exist, so a renamed file fails before a deploy
INSTALLED = {
    "deploy/nftables/tvgw-apply": "/usr/local/sbin/tvgw-apply",
    "deploy/bin/tvgw-analyze": "/usr/local/sbin/tvgw-analyze",
    "deploy/bin/tvgw-doh-update": "/usr/local/sbin/tvgw-doh-update",
    "deploy/networkmanager/90-tvgw-dispatcher": "/etc/NetworkManager/dispatcher.d/90-tvgw",
    "deploy/logrotate/tvgw": "/etc/logrotate.d/tvgw",
    "deploy/sysctl/60-tvgw.conf": "/etc/sysctl.d/60-tvgw.conf",  # (events)
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
    "tvgw-analyst.timer",
    "tvgw-analyst-weekly.timer",
    "tvgw-autoblock.timer",
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
    "tls_noname": ("t", "dst", "sport"),  # (extractor) schema 8
    "http": ("t", "host", "uri", "src"),
    "lanprobe": ("t", "dst", "dport"),
    "oddport": ("t", "raw"),
    "gate": ("t", "raw"),
    "adport": ("t", "raw"),  # (acr) schema 9
    "changes": ("t", "source", "kind", "subject"),  # (ledger) schema 9: the spool read once
}


def sh(*cmd: str) -> str:
    return subprocess.run(cmd, capture_output=True, text=True, timeout=60).stdout


def dns_a(name: str, server: str = "127.0.0.1") -> list[str]:
    """A records from the gateway's resolver (0.0.0.0 = blocked), [] on no answer."""
    return dnsq.a_records(name, server) or []


# (capture) the capture unit CAPTURE_MODE picks: tvgw-pcap (full) or tvgw-pcap-headers (headers)
CAPTURE_UNIT = verify.CAPTURE_UNITS[S.capture_mode]


@pytest.mark.parametrize("unit", ["tvgw", "tvgw-flowlog", CAPTURE_UNIT, "AdGuardHome", "dnsmasq", "nginx"])
def test_service_active(unit):
    assert sh("systemctl", "is-active", unit).strip() == "active", f"{unit} must be running"


def test_exactly_one_capture_runs_and_it_is_dumpcap():
    """(capture) capture v2: dumpcap writes the ring, and the unit CAPTURE_MODE does not pick stands
    aside (its ExecCondition skipped it), or every hello would be written twice."""
    other = next(u for u in verify.CAPTURE_UNITS.values() if u != CAPTURE_UNIT)
    assert sh("systemctl", "is-active", other).strip() != "active", f"{other} runs beside {CAPTURE_UNIT}"
    pid = int(sh("systemctl", "show", "-p", "MainPID", "--value", f"{CAPTURE_UNIT}.service").strip() or 0)
    assert pid > 0, f"{CAPTURE_UNIT} has no main process"
    assert Path(f"/proc/{pid}/comm").read_text(encoding="utf-8").strip() == "dumpcap"
    live = pcaps.live_files(S.pcap_dir)  # none for a moment at the hour: dumpcap closes, then opens
    assert live is not None and len(live) <= 1, f"the capture holds more than one file open: {live}"


def test_the_headers_capture_table_is_loaded_in_headers_mode_only():
    """(capture) tvgw-apply loads inet tvgw_capture only with CAPTURE_MODE=headers, and removes it
    otherwise."""
    listing = sh("nft", "list", "table", "inet", "tvgw_capture")
    if S.capture_mode == "full":
        assert listing.strip() == "", "a capture table is loaded with CAPTURE_MODE=full"
        return
    assert verify.CAPTURE_RULE in listing and "log group 7" in listing, listing[:400]


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
    """The dnsmasq, nginx and NetworkManager files are the templates with this gateway's settings filled
    in, the TV side (TV_IF, GW_IP, and the pool and netmask from TV_NET) included, and the capture's
    drop-in names the same TV side."""
    side = config.tv_side(S)
    dnsmasq = (REPO / "deploy" / "dnsmasq" / "tvgw.conf.template").read_text(encoding="utf-8")
    for placeholder, value in (
        ("__TV_MAC__", S.tv_mac),
        ("__TV_IP__", S.tv_ip),
        ("__TV_NAME__", S.tv_name),
        ("__TV_IF__", S.tv_if),
        ("__GW_IP__", S.gw_ip),
        ("__TV_NETMASK__", side.netmask),
        ("__DHCP_FIRST__", side.dhcp_first),
        ("__DHCP_LAST__", side.dhcp_last),
    ):
        dnsmasq = dnsmasq.replace(placeholder, value)
    assert Path("/etc/dnsmasq.d/tvgw.conf").read_text(encoding="utf-8") == dnsmasq
    nm = (
        (REPO / "deploy" / "networkmanager" / "90-tvgw.conf")
        .read_text(encoding="utf-8")
        .replace("__TV_IF__", S.tv_if)
    )
    assert Path("/etc/NetworkManager/conf.d/90-tvgw.conf").read_text(encoding="utf-8") == nm
    conf = config.parse_conf(Path("/etc/tvgw/tvgw.conf").read_text(encoding="utf-8"))
    resolver = conf.get("URL_FILTER_RESOLVER") or "1.1.1.1"  # install.sh's default
    for template, installed in (
        ("tvgw-gfts.conf", "/etc/nginx/conf.d/tvgw-gfts.conf"),
        ("stream.conf", "/etc/nginx/tvgw/stream.conf"),
    ):
        expected = (
            (REPO / "deploy" / "nginx" / template)
            .read_text(encoding="utf-8")
            .replace("__RESOLVER__", resolver)
        )
        expected = expected.replace("__GW_IP__", S.gw_ip)
        assert Path(installed).read_text(encoding="utf-8") == expected, (
            f"{installed} differs from deploy/nginx/{template}"
        )
    # (packaging) the capture's TV side, which systemd fills into dumpcap's interface and filter
    pcap = Path("/etc/systemd/system/tvgw-pcap.service.d/tv-side.conf").read_text(encoding="utf-8")
    assert pcap == f"[Service]\nEnvironment=TV_IF={S.tv_if} TV_NET={S.tv_net} GW_IP={S.gw_ip}\n"


def test_tv_lan_is_where_the_settings_put_the_tv_side():
    """(packaging) install.sh compares tv-lan's interface and address with TV_IF and GW_IP/prefix and
    moves the connection when they differ; nmcli's answer must read exactly so on the gateway, or every
    deploy would bring tv-lan up again and drop GW_IP for a moment."""
    side = config.tv_side(S)
    assert sh("nmcli", "-g", "connection.interface-name", "con", "show", "tv-lan").strip() == S.tv_if
    assert sh("nmcli", "-g", "ipv4.addresses", "con", "show", "tv-lan").strip() == f"{S.gw_ip}/{side.prefix}"
    applied = config.parse_conf(Path("/run/tvgw/settings.applied").read_text(encoding="utf-8"))
    assert (applied.get("TV_IF"), applied.get("TV_NET"), applied.get("GW_IP")) == (S.tv_if, S.tv_net, S.gw_ip)


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
        "tvgw-analyst-weekly.timer",
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


def test_the_adtech_port_wall_is_loaded_as_the_settings_say():
    """(acr) With ADTECH_PORT_WALL=yes (the default) tv_out resets the TV's connections to LG's ad-tech
    ports under its own counter and samples them to the journal, before the odd-port rules; with no,
    neither rule is there (design decision 45)."""
    rules = sh("nft", "list", "table", "inet", "tvgw")
    on = S.adtech_port_wall == "yes"
    assert ('reject with tcp reset comment "LG adtech port"' in rules) == on
    assert ('log prefix "tvgw-adport: "' in rules) == on
    if on:
        assert rules.index("LG adtech port") < rules.index("tvgw-oddport")


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
    files = glob.glob(os.path.join(S.pcap_dir, "*.pcap"))
    assert files, f"no pcap in {S.pcap_dir}"
    power = _store().execute("SELECT power FROM tvstate ORDER BY t DESC LIMIT 1").fetchone()
    if power and power[0] == "Active":
        # (capture) dumpcap opens a new file every hour whether or not a packet comes, so a recent
        # file proves nothing alone: a wrong interface or filter leaves only the 24-byte pcap header
        with_packets = [f for f in files if os.path.getsize(f) > PCAP_HEADER]
        assert with_packets, "TV is on but no pcap holds a packet"
        assert time.time() - max(map(os.path.getmtime, with_packets)) < 2 * 3600, (
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
    expected = config.uplink_interface(S)  # (events) WAN_IF, or the tunnel VPN_IF names or finds
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
    """tcpdump chowned its files to its -Z user; with root that made them unreadable to the unprivileged
    tshark (2026-10-27, second incident), and dumpcap without -g makes them 0600. Every pcap must be
    readable as nobody and owned by tvgw-pcap."""
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
    zero TLS rows means the extraction is silently broken (2026-10-27). (extractor) A failed read is
    recorded with its error and a fresh done_at, so when every file of the last 4 hours failed the
    rows check would find nothing to judge and skip: that is the extraction broken, and it fails."""
    c = _store()
    since = time.time() - 4 * 3600
    done = c.execute(
        "SELECT name, tls_rows, error FROM pcaps_done WHERE done_at > ? ORDER BY name DESC", (since,)
    ).fetchall()
    failed = [(name, error) for name, _, error in done if error is not None]
    assert not done or len(failed) < len(done), f"every pcap read in the last 4 hours failed: {failed[:3]}"
    recent = [(name, rows) for name, rows, error in done if error is None][:3]
    active = c.execute("SELECT COUNT(*) FROM tvstate WHERE power='Active' AND t > ?", (since,)).fetchone()[0]
    if not recent or not active:
        pytest.skip("no finished pcap in the last four hours, or TV not on")
    assert any(rows > 0 for _, rows in recent), f"finished pcaps yielded no TLS rows: {recent}"


def test_the_sandboxed_tshark_reads_the_newest_finished_pcap():
    """(extractor) The ingest runs tshark through systemd-run with the HARDENING properties; one
    property the Pi's systemd or kernel refuses (a seccomp kill, a namespace it cannot make) fails
    every file, and the ingest only warns and retries. This runs the real sandbox on the newest file
    the capture has finished: it must not fail, and must find a hello where the stored read found one."""
    from tvgw import ingest, pcaps, tshark

    live = pcaps.live_files(S.pcap_dir)
    assert live is not None, "cannot tell which pcap the capture is writing (needs /proc and root)"
    # a file shorter than a capture header (the capture stopped before writing one) is no test of tshark
    files = [f for f in pcaps.finished(S.pcap_dir, live) if os.path.getsize(f) >= ingest.PCAP_HEADER]
    if not files:
        pytest.skip("no finished pcap yet")
    newest = files[-1]
    try:
        rows = tshark.extract(newest)  # as root this is the sandbox, never tshark as root
    except RuntimeError as e:
        pytest.fail(f"the sandboxed tshark failed on {newest}: {e} (see docs/extractor.md)")
    stored = (
        _store()
        .execute(
            "SELECT tls_rows FROM pcaps_done WHERE name=? AND error IS NULL", (os.path.basename(newest),)
        )
        .fetchone()
    )
    if stored and stored[0] > 0:
        named = [r for r in rows if isinstance(r, tshark.TlsHello) and r.src == S.tv_ip and r.sni]
        assert named, f"{newest}: the store holds {stored[0]} named hellos from it, the sandbox read none"


def test_tv_lan_api_reachable_or_asleep():
    """Informational: the TV answers the LAN API when on; when off this is a skip, not a failure."""
    from tvgw import lgwebos

    r = lgwebos.read(S.tv_ip, "/var/lib/tvgw/lgtv-keys.sqlite", timeout=10)
    if not r.reachable:
        pytest.skip(f"TV not reachable ({r.error})")
    assert r.acr_off is True, "Live Plus (ACR) must be off"
    # design decision 40: the TV's one road is the cable; a firmware that cannot say so is a skip, not a FAIL
    if "network.paths" in r.values:
        pytest.skip(f"this firmware does not report its network paths ({r.values['network.paths']})")
    assert r.values.get("network.wired.state") == "connected", r.values
    assert r.second_paths == [], f"the TV reports a path around the gateway: {r.second_paths}"


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
        # (record) `tvgw forget` leaves one fresh copy of an emptied store: it holds no lookup until the
        # next day's copy, and that is the copy working, not failing
        forgot = conn.execute("SELECT value FROM meta WHERE key='forget_before'").fetchone()
        if not (forgot and time.time() - float(forgot[0]) < 36 * 3600):
            assert conn.execute("SELECT COUNT(*) FROM dns").fetchone()[0] > 0
    finally:
        conn.close()


def test_capture_runs_as_the_capture_user_with_two_capabilities():
    """The capture never runs as root: the unit starts as tvgw-pcap holding only CAP_NET_RAW and
    CAP_NET_ADMIN, so a bug in the dissector of a frame the TV sent cannot become root."""
    import pwd

    pid = int(sh("systemctl", "show", "-p", "MainPID", "--value", f"{CAPTURE_UNIT}.service").strip() or 0)
    assert pid > 0, f"{CAPTURE_UNIT} has no main process"
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
    of the home: the scrub is the guarantee and this is its test on real data. The ZIP code the TV
    holds and the name typed on it are read from the store, and the day each was first read (when the
    pack's settings changes would carry it) is packed too, beside yesterday."""
    import datetime
    import socket

    conn = _store()
    try:
        identities = conn.execute(
            "SELECT value, MIN(t) FROM tvsettings WHERE key IN ('option.zipcode', 'network.deviceName')"
            " GROUP BY value"
        ).fetchall()
    finally:
        conn.close()
    days = {(datetime.date.today() - datetime.timedelta(days=1)).isoformat()}
    days |= {datetime.date.fromtimestamp(t).isoformat() for _, t in identities}
    leaks = [S.tv_mac, "10.10.10.", "192.168.", socket.gethostname()]
    leaks += [v for v in (S.tv_name, *(v for v, _ in identities)) if v and len(v) >= 3]
    for day in sorted(days):
        out = subprocess.run(
            ["tvgw", "analyst", "--dry-run", "--day", day], capture_output=True, text=True, timeout=300
        )
        assert out.returncode == 0, out.stdout + out.stderr
        path = Path(S.reports_dir, "proposals", f"{day}.pack.json")
        pack = path.read_text(encoding="utf-8").lower()
        for leak in leaks:
            assert not leak or leak.lower() not in pack, f"the pack for {day} carries a home identifier"
        assert not os.stat(path).st_mode & stat.S_IROTH


def test_analyst_timer_follows_the_conf_schedule():
    """install.sh renders ANALYST_SCHEDULE into a timer drop-in; the live timer must say the same."""
    sched = S.analyst_schedule
    expected = {"hourly": "hourly"}.get(
        sched, f"*-*-* {sched}:00" if len(sched) == 5 and sched[2] == ":" else sched
    )
    shown = sh("systemctl", "show", "-p", "TimersCalendar", "--value", "tvgw-analyst.timer")
    assert expected.replace(" ", "") in shown.replace(" ", ""), (expected, shown)


def test_autoblock_file_record_and_resolver_tell_one_story():
    """The machine's rules file, the store's record and the live resolver must agree (design decision
    20), and the hourly check must run clean: it is what reverts a bad block while the owner sleeps."""
    from tvgw import analyst, autoblock

    prof = profile.load(S.profile)
    ok, refused = autoblock.admissible(S.auto_rules, prof)
    assert refused == [], refused
    conn = _store()
    try:
        assert {r["rule"] for r in autoblock.active(conn)} == set(ok)
    finally:
        conn.close()
    # --no-watch: the suite must never watch the TV (an armed canary runs about 11 minutes) nor revert
    # a rule from a watch; the timer's own check, under the same lock, does that
    out = subprocess.run(
        ["tvgw", "autoblock", "check", "--no-watch"], capture_output=True, text=True, timeout=900
    )
    assert out.returncode == 0, out.stdout + out.stderr
    out = subprocess.run(["tvgw", "autoblock", "list"], capture_output=True, text=True, timeout=120)
    assert out.returncode == 0, out.stdout + out.stderr
    if S.analyst_apply == "auto":
        assert analyst.verifier_for(S, S.analyst_model) != S.analyst_model
    # a revert re-applies AdGuard from inside the sandbox: its config must be writable there
    for unit in ("tvgw-autoblock.service", "tvgw-analyst.service", "tvgw-analyst-weekly.service"):
        assert "/opt/AdGuardHome" in Path("/etc/systemd/system", unit).read_text(), unit


def test_the_guard_is_loaded_enabled_and_cannot_be_stopped():
    """(guard) design decision 42: inet tvgw_guard holds its three chains after inet tvgw, its unit
    comes back at boot and refuses a stop, and dnsmasq dropped the capability that rewrites the
    firewall. Read-only: nothing here stops or reloads anything."""
    listing = sh("nft", "-s", "list", "table", "inet", "tvgw_guard")
    for chain in ("input", "forward", "output"):
        assert f"type filter hook {chain} priority filter + 10;" in listing, chain
    assert 'comment "guard: TV may not reach other Pi services"' in listing
    assert sh("systemctl", "is-enabled", "tvgw-guard.service").strip() == "enabled"
    assert sh("systemctl", "show", "-p", "RefuseManualStop", "--value", "tvgw-guard.service").strip() == "yes"
    assert Path("/etc/tvgw/guard.nft").read_text(encoding="utf-8").count(f'"{S.tv_if}"') >= 3


def test_cotenant_ip_filters_are_attached_to_their_running_cgroups():
    """(guard) design decision 42: install.sh applies a co-tenant's new IPAddressDeny with a
    `systemctl daemon-reload` and no restart, on the reading that systemd invalidates and re-realizes
    a deserialized unit's cgroup BPF on reload. `systemctl show` only reports the loaded property;
    this checks the kernel: each active co-tenant with the filter has an ingress and an egress
    program attached to its own cgroup. Needs bpftool (skips without it); read-only."""
    bpftool = shutil.which("bpftool") or shutil.which("bpftool", path="/usr/sbin:/sbin")
    if not bpftool:
        pytest.skip("bpftool is not installed (apt install bpftool)")
    names = [
        f"{u}.service"
        for u in guard.wanted_units(config.co_tenants(S.co_tenant_units))
        if not u.endswith("@")
    ]
    if not names:
        pytest.skip("CO_TENANT_UNITS lists none")
    shown = sh(
        "systemctl",
        "show",
        "-p",
        "Id",
        "-p",
        "ActiveState",
        "-p",
        "ControlGroup",
        "-p",
        "IPAddressDeny",
        "--",
        *names,
    )
    checked = []
    for block in guard.show_blocks(shown):
        cgroup = block.get("ControlGroup", "")
        if (
            block.get("ActiveState") != "active"
            or not cgroup
            or not guard.denies(block.get("IPAddressDeny", ""), S.tv_net)
        ):
            continue
        attached = sh(bpftool, "cgroup", "show", f"/sys/fs/cgroup{cgroup}")
        assert "ingress" in attached and "egress" in attached, f"{block.get('Id')}: no IP filter on {cgroup}"
        checked.append(block.get("Id"))
    if not checked:
        pytest.skip("no active co-tenant carries IPAddressDeny yet")
