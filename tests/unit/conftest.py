"""Shared fixtures: a fake gateway on disk (logs, pcaps, policy files), a fixed time zone, the
deployed unit files as systemd reads them, and a stand-in for the LG LAN-API library."""

import importlib.util
import os
import pickle
import shlex
import sqlite3
import stat
import struct
import sys
import tempfile
import time
import types
from pathlib import Path

import pytest

from tvgw import forget, ingest, pcaps, verify, walls
from tvgw import profile as profile_mod
from tvgw.config import Settings

# hypothesis keeps a cache of what it read and found. In the working directory, which is the repository,
# the tests that walk the tree would read it as part of the tree: it goes with the other temporary files
os.environ.setdefault("HYPOTHESIS_STORAGE_DIRECTORY", os.path.join(tempfile.gettempdir(), "tvgw-hypothesis"))

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
def fixed_time_zone(monkeypatch):
    """One fixed zone with daylight-saving transitions for every test, so day boundaries and the
    spring-forward cases never depend on the CI box's clock (the gateway's own zone is its own)."""
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
    """ingest asks /proc which pcap the capture holds open; the fake gateway runs no capture, so its
    newest file is declared live. A test that wants another answer passes `live=`."""
    monkeypatch.setattr(
        pcaps, "live_files", lambda d: {os.path.realpath(os.path.join(d, "tv-20261026-0900.pcap"))}
    )


@pytest.fixture(autouse=True)
def quiet_flowlog(monkeypatch):
    """ingest asks tvgw-flowlog's journal whether conntrack lost events; the test box has no such
    journal, and may have no journalctl, so it reports none. A test that wants losses passes
    `flowlog_lines=`."""
    monkeypatch.setattr(ingest, "journal_flowlog_lines", lambda since: [])


JOURNAL_ADPORT_LINES = ingest.journal_adport_lines  # (acr) the real reader, for the test of its argv


@pytest.fixture(autouse=True)
def quiet_adport(monkeypatch):
    """(acr) ingest reads the adtech port wall's samples from the kernel journal; the test box has none,
    so the wall stopped nothing. A test that wants samples passes `adport_lines=`."""
    monkeypatch.setattr(ingest, "journal_adport_lines", lambda since: [])


JOURNAL_INPATH_LINES = ingest.journal_inpath_lines  # (inpath) the real reader, for the test of its argv


@pytest.fixture(autouse=True)
def quiet_inpath(monkeypatch):
    """(inpath) ingest reads the in-path gate count's samples from the kernel journal; the test box has
    none. A test that wants samples passes `inpath_lines=`."""
    monkeypatch.setattr(ingest, "journal_inpath_lines", lambda since: [])


READ_LIVE = walls.read_live  # (ports) the real reader, for the test that hands it fakes


@pytest.fixture(autouse=True)
def quiet_firewall(monkeypatch):
    """(ports) `tvgw refused` reads the firewall's counters and the kernel journal beside AdGuard's log
    (walls.read_live); the test box is no gateway, so there is no firewall to read. A test that wants a
    reading passes `firewall=`."""
    monkeypatch.setattr(walls, "read_live", lambda since, until: None)


FLUSH_NTP_SET = forget.flush_ntp_set  # (forget) the real flush, for the test that hands it a fake nft


@pytest.fixture(autouse=True)
def kernel_untouched(monkeypatch):
    """(forget) `tvgw forget` empties the kernel's list of the TV's time servers; a test run must never
    do that to a gateway it happens to run on, as root or not. The stand-in says it was emptied; a test
    that wants another answer passes `flush=`. It returns the calls made."""
    calls: list[None] = []
    monkeypatch.setattr(forget, "flush_ntp_set", lambda: calls.append(None))
    return calls


@pytest.fixture(scope="session")
def status_dir(tmp_path_factory):
    return tmp_path_factory.mktemp("run-tvgw")


@pytest.fixture(autouse=True)
def status_file(monkeypatch, status_dir):
    """(plain) every `tvgw verify` run writes its status line, and a test run must never replace the
    status of a real gateway it happens to run on: tests write it into the session's own directory,
    removed before each test. A test that reads the file asks for this fixture by name."""
    path = status_dir / "status.txt"
    path.unlink(missing_ok=True)
    (status_dir / "counting.txt").unlink(missing_ok=True)  # (counting) verify --record writes it beside
    monkeypatch.setattr(verify, "STATUS", str(path))
    return path


@pytest.fixture(autouse=True)
def no_retry_pause(monkeypatch):
    """(depth) verify asks a failing must-allow name again after a 3-second pause; a test's fake resolver
    answers at once, so the pause is skipped. A test that counts the pauses passes its own `sleep`."""
    monkeypatch.setattr(verify, "pause", lambda seconds: None)


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
    (tmp_path / "pcap" / "tv-20261026-0900.pcap").write_bytes(EMPTY_PCAP)  # the one the capture is writing
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
        Syn(1793020104.0, TV, 40002, "192.168.77.69", 80),  # a remembered LAN device: probe
        Syn(
            1793020105.0, TV, 40002, "192.168.77.69", 80
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


def find_root(start: Path) -> Path:
    """The checkout a test file belongs to: the nearest folder above `start` that holds both
    deploy/nftables/tvgw-apply and pyproject.toml, else the folder two above it. mutmut runs the suite
    from mutants/, a copy of tests/ and pyproject.toml beside the mutated src/ with no deploy/, so the
    folder two above a test file there is mutants/ and the checkout is the one above it."""
    start = start.resolve()
    for folder in start.parents:
        apply = folder / "deploy" / "nftables" / "tvgw-apply"
        if apply.is_file() and (folder / "pyproject.toml").is_file():
            return folder
    return start.parents[2]


ROOT = find_root(Path(__file__))  # the checkout, also when mutmut runs the tests from mutants/
UNITS = ROOT / "deploy" / "systemd"


def load_tool(name: str) -> types.ModuleType:
    """A script of tools/ as a module, loaded once: `load_tool("docgen")` is tools/docgen.py."""
    if name not in sys.modules:
        spec = importlib.util.spec_from_file_location(name, ROOT / "tools" / f"{name}.py")
        module = importlib.util.module_from_spec(spec)
        sys.modules[name] = module  # a dataclass looks its module up by name
        spec.loader.exec_module(module)
    return sys.modules[name]


def exec_lines(unit: str) -> list[tuple[str, str]]:
    """(directive, raw value) of every Exec* line in deploy/systemd/<unit>, with backslash-continued
    lines joined the way systemd joins them: the backslash becomes a space."""
    text = (UNITS / unit).read_text(encoding="utf-8").replace("\\\n", " ")
    parts = (line.partition("=") for line in text.splitlines())
    return [(key, value.strip()) for key, eq, value in parts if eq and key.startswith("Exec")]


# (packaging) the TV side install.sh writes into tvgw-pcap's drop-in, with the shipped defaults
CAPTURE_ENV = {"TV_IF": Settings().tv_if, "TV_NET": Settings().tv_net, "GW_IP": Settings().gw_ip}


def capture_argv(
    unit: str = "tvgw-pcap.service", directive: str = "ExecStart", env: dict[str, str] | None = None
) -> list[str]:
    """The argv of one Exec line of a capture unit (dumpcap's, by default): the drop-in's ${TV_IF},
    ${TV_NET} and ${GW_IP} filled in as systemd fills them (the shipped defaults unless `env` says
    otherwise), specifiers and variables unescaped, words split as systemd splits them. A `+` (run as
    root) prefix is dropped."""
    (value,) = [v for k, v in exec_lines(unit) if k == directive]
    for key, val in (env or CAPTURE_ENV).items():
        value = value.replace("${" + key + "}", val)
    return shlex.split(value.removeprefix("+").replace("%%", "%").replace("$$", "$"))


# ---- (pairing) bscpylgtv replaced: the test's client, and a key store over a JSON file ----------------


class LgtvKeyStore:
    """bscpylgtv's `StorageSqliteDict` as lgwebos and the library use it: the library's SQLite layout
    (sqlitedict's table `unnamed`, `key TEXT PRIMARY KEY, value BLOB` with pickled values), so that
    tvgw's own table (lgkeys.py) sits beside it as it does on a gateway. `create()` makes the file when
    it is missing, as SQLite does, under the caller's umask."""

    def __init__(self, path: str):
        self.path, self.db = path, self

    @classmethod
    async def create(cls, path: str) -> "LgtvKeyStore":
        write_lgtv_keys(path, {})
        return cls(path)

    def _keys(self) -> dict:
        return read_lgtv_keys(self.path)

    async def get_key(self, ip: str):
        return self._keys().get(ip)

    async def set_key(self, ip: str, key: str) -> None:
        write_lgtv_keys(self.path, {ip: key})

    def close(self) -> None:
        pass


def write_lgtv_keys(path, keys: dict) -> None:
    """Put `keys` ({TV address: key}) into the library's table of the key file at `path`, making the file
    and the table when missing, in sqlitedict's layout."""
    conn = sqlite3.connect(str(path))
    try:
        with conn:
            conn.execute('CREATE TABLE IF NOT EXISTS "unnamed" (key TEXT PRIMARY KEY, value BLOB)')
            for ip, key in keys.items():
                conn.execute(
                    'INSERT OR REPLACE INTO "unnamed" (key, value) VALUES (?, ?)',
                    (ip, sqlite3.Binary(pickle.dumps(key, protocol=pickle.HIGHEST_PROTOCOL))),
                )
    finally:
        conn.close()


def read_lgtv_keys(path) -> dict:
    """The library's table of the key file at `path` as {TV address: key}; {} for a missing table."""
    conn = sqlite3.connect(str(path))
    try:
        tables = {r[0] for r in conn.execute("SELECT name FROM sqlite_master WHERE type='table'")}
        if "unnamed" not in tables:
            return {}
        return {k: pickle.loads(bytes(v)) for k, v in conn.execute('SELECT key, value FROM "unnamed"')}
    finally:
        conn.close()


def fake_handshake(release: str = "5.6.2", os_version: str = "4.9.3", registered=True):
    """A `lgwebos.handshake` that reaches no TV: the CX's `hello` answer and a key the TV takes."""

    async def handshake(ip, key, manifest, timeout=5.0):
        from tvgw import lgwebos

        return lgwebos.Handshake(
            release=release, os_version=os_version, registered=None if key is None else registered
        )

    return handshake


def fake_lgtv(monkeypatch, client, keys: dict[str, str] | None = None, key_file=None) -> None:
    """Replace bscpylgtv: `client` is its `WebOsClient` and `LgtvKeyStore` its key store. With `keys`
    ({TV address: key}) the key file holds them first, so the gateway is paired with those TVs."""
    from tvgw import lgwebos

    lib = types.ModuleType("bscpylgtv")
    lib.__path__ = []  # a package, so that `bscpylgtv.storage_sqlitedict` imports
    lib.WebOsClient = client
    storage = types.ModuleType("bscpylgtv.storage_sqlitedict")
    storage.StorageSqliteDict = LgtvKeyStore
    manifest = types.ModuleType("bscpylgtv.manifest")
    manifest.MANIFEST = {"permissions": ["READ_SETTINGS"], "signatures": [{"signature": "x"}], "signed": {}}
    monkeypatch.setitem(sys.modules, "bscpylgtv", lib)
    monkeypatch.setitem(sys.modules, "bscpylgtv.storage_sqlitedict", storage)
    monkeypatch.setitem(sys.modules, "bscpylgtv.manifest", manifest)
    # (W12) the handshake of tvgw's own reaches no TV here: the CX's hello and a key the TV takes
    monkeypatch.setattr(lgwebos, "handshake", fake_handshake())
    if keys is not None:
        write_lgtv_keys(key_file, keys)


def counting_lgtv(accept: bool = True):
    """A `WebOsClient` that counts what the TV sees. Every `connect()` sends `register`, as the library
    does; with no key stored the TV shows its pairing prompt (`prompts`) and, once the owner accepts,
    sends the key the library stores. `create()` opens the key store as the library does, and records
    the mode of a key file it created (`born`)."""
    counts = {"create": 0, "connect": 0, "register": 0, "prompts": 0, "manifests": []}

    class CountingTv:
        @classmethod
        async def create(cls, ip, states, key_file_path, manifest_file_path=None):
            counts["create"] += 1
            # (W12) the manifest the connection sends: the library's signed default, or tvgw's file
            counts["manifests"].append("unsigned" if manifest_file_path else "signed")
            new = not os.path.exists(key_file_path)
            c = cls()
            c.ip, c.storage = ip, await LgtvKeyStore.create(key_file_path)
            if new:
                counts["born"] = stat.S_IMODE(os.stat(key_file_path).st_mode)
            c.key = await c.storage.get_key(ip)
            return c

        async def connect(self):
            counts["connect"] += 1
            counts["register"] += 1
            if self.key:
                return
            counts["prompts"] += 1
            if not accept:
                raise RuntimeError("Unable to pair")  # what the library raises when the TV says no
            self.key = "key-from-the-tv"
            await self.storage.set_key(self.ip, self.key)

        async def get_system_settings(self, cat, keys):
            return {"settings": {keys[0]: "off"}}

        async def request(self, uri):  # connectionmanager/getstatus: wired, every other path off
            off = {"state": "disconnected", "tetheringEnabled": False}
            return {"wired": {"state": "connected"}, "wifi": off, "wifiDirect": off, "bluetooth": off}

        async def get_software_info(self):
            return {"major_ver": "04", "minor_ver": "64"}

        async def get_system_info(self):
            return {}

        async def get_power_state(self):
            return {"state": "Active"}

        async def get_current_app(self):
            return "com.webos.app.home"

        async def disconnect(self):
            pass

    return CountingTv, counts
