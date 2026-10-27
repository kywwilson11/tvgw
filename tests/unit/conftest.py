"""Shared fixtures: a fake gateway on disk (logs, pcaps, policy files), a fixed time zone, and the
deployed unit files as systemd reads them."""

import os
import shlex
import struct
import time
from pathlib import Path

import pytest

from tvgw import pcaps
from tvgw import profile as profile_mod
from tvgw.config import Settings

TV = "10.10.10.17"

# all fixture timestamps fall on 2026-10-26 America/Chicago (the brief is per calendar day)
FLOW_TCP = (
    "[1793020052.120409]\t[DESTROY] ipv4     2 tcp      6 TIME_WAIT src=10.10.10.17 dst=142.251.219.1 "
    "sport=58998 dport=443 packets=18 bytes=2259 src=142.251.219.1 dst=192.0.2.48 sport=443 dport=58998 "
    "packets=23 bytes=10742 [ASSURED] delta-time=360\n"
)
FLOW_UDP = (
    "[1793020052.120776]\t[DESTROY] ipv4     2 udp      17 src=10.10.10.17 dst=10.10.10.1 sport=45806 "
    "dport=53 packets=1 bytes=64 src=10.10.10.1 dst=10.10.10.17 sport=53 dport=45806 packets=1 bytes=145 "
    "delta-time=30\n"
)
FLOW_OTHER_SRC = FLOW_TCP.replace("src=10.10.10.17 dst=142.251.219.1", "src=10.10.10.1 dst=142.251.219.1")
DNS_BLOCKED = (
    '{"T":"2026-10-26T09:14:37.101138599-05:00","QH":"aic.recommend.lgtvcommon.com","QT":"AAAA","QC":"IN","CP":"",'
    '"Answer":"80CBgAABAAEAAAAAA0FJQwlyZWNvbW1lbmQKbGd0dmNvbW1vbgNjb20AABwAAcAMABwAAQAAADwAEAAAAAAAAAAAAAAAAAAAAAA=",'
    '"IP":"10.10.10.17","Result":{"Rules":[{"Text":"||recommend.lgtvcommon.com^"}],"Reason":3,"IsFiltered":true},'
    '"Elapsed":264779}\n'
)
DNS_ALLOWED = (
    '{"T":"2026-10-26T09:14:37.101045506-05:00","QH":"us.lgtvsdp.com","QT":"A","QC":"IN","CP":"",'
    '"Upstream":"https://1.0.0.1:443/dns-query",'
    '"Answer":"FhyBgAABAAIAAAAAAlVTB2xndHZzZHADY29tAAABAAHADAAFAAEAAAAMABwOdXMtbGd0dnNkcC1jb20HYXdzLXByZANuZXQAwCwAAQABAAAADAAEI6a9RA==",'
    '"IP":"10.10.10.17","Result":{"Rules":[{"Text":"@@||us.lgtvsdp.com^"}],"Reason":1},"Elapsed":34704,"Cached":true}\n'
)
DNS_OTHER_CLIENT = DNS_ALLOWED.replace('"IP":"10.10.10.17"', '"IP":"192.0.2.33"')
GFTS_TV_BLOCKED = (
    '2026-10-26T09:11:13-05:00 10.10.10.17 403 153 0.000 "ngfts.lge.com" '
    '"/fts/gftsDownload.lge?biz_code=PREMIUM&func_code=ACR&file_path=/premium/acr/x.xml" "Mozila/4.0"\n'
)
GFTS_TV_ALLOWED = (
    '2026-10-26T09:15:30-05:00 10.10.10.17 200 6488 0.5 "ngfts.lge.com" '
    '"/fts/gftsDownload.lge?biz_code=APP_STORE&func_code=APP_ICON&file_path=/a.png" "-"\n'
)
GFTS_PI_TEST = '2026-10-26T09:06:37-05:00 10.10.10.1 444 0 0.000 "example.com" "/" "curl/7.88.1"\n'
ADGUARD_YAML = """http:
  address: 127.0.0.1:3000
user_rules:
  - '@@||us.lgtvsdp.com^$important'
  - '||alphonso.tv^'
  - '||ngfts.lge.com^$dnsrewrite=10.10.10.1'
dhcp:
  enabled: false
"""
NGINX_CONF = """server {
	if ($request_uri ~* "biz_code=(PREMIUM|CDP|LGSHOPPING|MAS|IBS)([&_]|$)") {
		return 403;
	}
}
"""
ODDPORT_LINE = (
    "1793020200.123456 gateway kernel: tvgw-oddport: IN=eth0 OUT=wlan0 MAC=00:11 SRC=10.10.10.17 "
    "DST=156.147.69.32 LEN=60 TOS=0x00 PREC=0x00 TTL=63 ID=1 DF PROTO=TCP SPT=40000 DPT=8080 WINDOW=1 RES=0x00 SYN"
)


EMPTY_PCAP = struct.pack(
    "<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1
)  # a capture with no frames: the 24-byte header

NOW = 1793026800.0  # 2026-10-26 10:00 CDT: just after every timestamp in the fixtures


@pytest.fixture(autouse=True)
def chicago_time(monkeypatch):
    """The gateway lives in America/Chicago; day boundaries in tests must not depend on the CI box."""
    monkeypatch.setenv("TZ", "America/Chicago")
    time.tzset()
    yield
    monkeypatch.undo()  # restore the caller's TZ first, then re-read it
    time.tzset()


@pytest.fixture(autouse=True)
def frozen_now(monkeypatch):
    """ingest stamps rule history, last_run and the prune cutoff with time.time(): pin it next to the
    data, or the suite starts failing when the fixture day is a year old."""
    monkeypatch.setattr(time, "time", lambda: NOW)


@pytest.fixture(autouse=True)
def fake_live(monkeypatch):
    """ingest asks /proc which pcap tcpdump holds open; the fake gateway runs no tcpdump, so its newest
    file is declared live. A test that wants another answer passes `live=`."""
    monkeypatch.setattr(
        pcaps, "live_files", lambda d: {os.path.realpath(os.path.join(d, "tv-20261026-0900.pcap"))}
    )


@pytest.fixture()
def lg():
    return profile_mod.load("lg-webos")


@pytest.fixture()
def gateway(tmp_path):
    """A fake gateway directory tree with one hour of plausible data, plus matching Settings."""
    (tmp_path / "log").mkdir()
    (tmp_path / "pcap").mkdir()
    (tmp_path / "state").mkdir()
    (tmp_path / "log" / "flows.log").write_text(FLOW_TCP + FLOW_UDP + FLOW_OTHER_SRC)
    (tmp_path / "querylog.json").write_text(
        DNS_BLOCKED + DNS_ALLOWED + DNS_OTHER_CLIENT + '{"T":"2026-10-26T09:1'
    )
    (tmp_path / "pcap" / "tv-20261026-0800.pcap").write_bytes(EMPTY_PCAP)  # finished
    (tmp_path / "pcap" / "tv-20261026-0900.pcap").write_bytes(EMPTY_PCAP)  # the one tcpdump is writing
    (tmp_path / "log" / "gfts.log").write_text(GFTS_TV_BLOCKED + GFTS_TV_ALLOWED + GFTS_PI_TEST)
    (tmp_path / "state" / "tvcheck-history.log").write_text(
        "2026-10-26 08:20 unreachable\n2026-10-26 09:19 Active youtube.leanback.v4\n"
    )
    (tmp_path / "state" / "tvcheck.txt").write_text(
        "read 2026-10-26 09:19\noption.livePlus = off\noption.zipcode = 10001\npower = Active\napp = youtube.leanback.v4\n"
    )
    (tmp_path / "AdGuardHome.yaml").write_text(ADGUARD_YAML)
    (tmp_path / "tvgw-gfts.conf").write_text(NGINX_CONF)
    (tmp_path / "block4.txt").write_text("# manual blocks\n203.0.113.9\n")
    return Settings(
        tv_ip=TV,
        state_dir=str(tmp_path / "state"),
        db_path=str(tmp_path / "state" / "tvgw.db"),
        pcap_dir=str(tmp_path / "pcap"),
        flows_log=str(tmp_path / "log" / "flows.log"),
        gfts_log=str(tmp_path / "log" / "gfts.log"),
        adguard_querylog=str(tmp_path / "querylog.json"),
        adguard_yaml=str(tmp_path / "AdGuardHome.yaml"),
        nginx_conf=str(tmp_path / "tvgw-gfts.conf"),
        block4=str(tmp_path / "block4.txt"),
        tvcheck_history=str(tmp_path / "state" / "tvcheck-history.log"),
        tvcheck_txt=str(tmp_path / "state" / "tvcheck.txt"),
        reports_dir=str(tmp_path / "state" / "reports"),
    )


def fake_extract(pcap: str):
    """Stand-in for tshark: one TLS hello and one HTTP request per finished pcap, plus a foreign one."""
    from tvgw.tshark import HttpRequest, Syn, TlsHello

    assert os.path.basename(pcap) == "tv-20261026-0800.pcap", "only the finished pcap may be extracted"
    return [
        TlsHello(1793020100.0, TV, 40001, "23.5.6.43", 443, "gfts.lge.com"),
        TlsHello(1793020101.0, "10.10.10.1", 1, "2.2.2.2", 443, "not-the-tv.example"),
        HttpRequest(
            1793020102.0,
            TV,
            "23.5.6.43",
            "GET",
            "ngfts.lge.com",
            "/fts/x?biz_code=MAS",
            "Mozilla/5.0 (Web0S)",
        ),
        HttpRequest(1793020103.0, TV, "239.255.255.250", "M-SEARCH", "239.255.255.250:1900", "*", "UDAP/2.0"),
        Syn(1793020104.0, TV, 40002, "192.168.8.69", 80),  # a remembered LAN device: probe
        Syn(
            1793020105.0, TV, 40002, "192.168.8.69", 80
        ),  # the same attempt, retransmitted: not another probe
        Syn(1793020105.0, TV, 40003, "10.10.10.1", 53),  # the gateway: not a probe
        Syn(1793020106.0, TV, 40004, "23.5.6.43", 443),  # the internet: not a probe
    ]


def fake_oddport(since: str):
    """Stand-in for journalctl: honours --since like the real one (nothing new after the first run)."""
    if since.startswith("@"):
        return [] if float(since[1:]) > 1793020200 else [ODDPORT_LINE]
    return [ODDPORT_LINE, "garbage line without a timestamp"]


def statements(conn, fn) -> list[str]:
    """The SQL `fn` ran on `conn`, as SQLite saw it (parameters bound), ready for EXPLAIN QUERY PLAN."""
    seen: list[str] = []
    conn.set_trace_callback(seen.append)
    try:
        fn()
    finally:
        conn.set_trace_callback(None)
    return seen


def plan(conn, sql: str) -> str:
    return " ".join(r[3] for r in conn.execute("EXPLAIN QUERY PLAN " + sql))


UNITS = Path(__file__).resolve().parents[2] / "deploy" / "systemd"


def exec_lines(unit: str) -> list[tuple[str, str]]:
    """(directive, raw value) of every Exec* line in deploy/systemd/<unit>, with backslash-continued
    lines joined the way systemd joins them: the backslash becomes a space."""
    text = (UNITS / unit).read_text().replace("\\\n", " ")
    parts = (line.partition("=") for line in text.splitlines())
    return [(key, value.strip()) for key, eq, value in parts if eq and key.startswith("Exec")]


def capture_argv() -> list[str]:
    """tcpdump's argv from tvgw-pcap.service: specifiers unescaped, words split as systemd splits them."""
    (value,) = [v for k, v in exec_lines("tvgw-pcap.service") if k == "ExecStart"]
    return shlex.split(value.replace("%%", "%"))
