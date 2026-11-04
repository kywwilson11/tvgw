"""(adguard) AdGuard Home without the wizard: the pinned release, its archive, the wizard's API, whose
AdGuard a computer runs, and the install with its run-scoped rollback (design decision 52).

Everything here runs without AdGuard, systemd or a network: the release is a tarball built here, the
wizard is a small HTTP server on loopback that answers as AdGuard v0.107.79 does (its configure and
login answer a plain `OK`), and the units are a recorded fake. The real binary's first run is
tests/virtual/test_virtual_adguard_seed.py; `install()` with systemd is the container tier's."""

import dataclasses
import hashlib
import io
import json
import os
import re
import shutil
import stat
import subprocess
import tarfile
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

import pytest
import yaml
from conftest import ROOT

from tvgw import adguardcfg, aghinstall, profile, verify
from tvgw.config import Settings

PROFILE = profile.load("lg-webos")
FLOOR = verify.ADGUARD_MIN
BCRYPT = "$2a$10$" + "x" * 53  # the shape of the hash AdGuard keeps; nothing checks it is one


def settings(tmp_path: Path, **kw) -> Settings:
    home = tmp_path / "opt" / "AdGuardHome"
    return Settings(
        tv_ip="10.10.10.17",
        tv_mac="b4:b2:91:aa:bb:cc",
        tv_name="tv",
        adguard_yaml=str(home / "AdGuardHome.yaml"),
        **kw,
    )


# ---- the pin ------------------------------------------------------------------------------------------

# the schema each pinned release writes (configmigrate.LastSchemaVersion at its tag): a new pin needs a
# line here, and so a look at adguardcfg.SCHEMA_CEILING
SCHEMA_OF = {"0.107.79": 34}


def test_the_pin_names_both_assets_with_their_hashes_and_is_at_the_floor():
    assert aghinstall.pin_version() >= FLOOR
    assert set(aghinstall.PIN["assets"]) == {"arm64", "amd64"}
    for arch_name, (name, sha256) in aghinstall.PIN["assets"].items():
        assert name == f"AdGuardHome_linux_{arch_name}.tar.gz"
        assert re.fullmatch(r"[0-9a-f]{64}", sha256), arch_name
        assert aghinstall.asset_url(arch_name) == (
            f"https://github.com/AdguardTeam/AdGuardHome/releases/download/v{aghinstall.PIN['version']}/{name}"
        )
    # the amd64 hash the virtual job checked before it read the pin from here
    assert (
        aghinstall.PIN["assets"]["amd64"][1]
        == "c48f4a43000665484c5ec28177de11a004759b620dae8f77b2aabefc9ef3687f"
    )


def test_the_pinned_release_writes_a_schema_the_plan_has_been_tested_with():
    assert SCHEMA_OF[aghinstall.PIN["version"]] <= adguardcfg.SCHEMA_CEILING


@pytest.mark.parametrize(
    ("machine", "bits", "want"),
    [("aarch64", 64, "arm64"), ("arm64", 64, "arm64"), ("x86_64", 64, "amd64"), ("AMD64", 64, "amd64")],
)
def test_the_asset_follows_the_machine(machine, bits, want):
    assert aghinstall.arch(machine, bits) == want


@pytest.mark.parametrize(("machine", "bits"), [("armv7l", 32), ("aarch64", 32), ("riscv64", 64), ("", 64)])
def test_a_machine_with_no_pinned_asset_is_refused(machine, bits):
    with pytest.raises(aghinstall.InstallError, match="arm64 and amd64"):
        aghinstall.arch(machine, bits)


# ---- the download ---------------------------------------------------------------------------------------


class Opener:
    """urlopen's stand-in: the bytes given, with the URL asked for recorded."""

    def __init__(self, data: bytes = b"", error: Exception | None = None):
        self.data, self.error, self.urls = data, error, []

    def __call__(self, url, timeout):
        self.urls.append(url)
        if self.error is not None:
            raise self.error
        return io.BytesIO(self.data)


def pinned_to(monkeypatch, data: bytes, arch_name: str = "arm64") -> None:
    name, _ = aghinstall.PIN["assets"][arch_name]
    assets = {**aghinstall.PIN["assets"], arch_name: (name, hashlib.sha256(data).hexdigest())}
    monkeypatch.setitem(aghinstall.PIN, "assets", assets)


def test_fetch_keeps_the_release_only_when_its_hash_is_the_pin(tmp_path, monkeypatch):
    data = b"release bytes"
    pinned_to(monkeypatch, data)
    opener = Opener(data)
    path = aghinstall.fetch("arm64", tmp_path, opener=opener)
    assert path == tmp_path / "AdGuardHome_linux_arm64.tar.gz" and path.read_bytes() == data
    assert opener.urls == [aghinstall.asset_url("arm64")]
    assert sorted(p.name for p in tmp_path.iterdir()) == [path.name]


def test_a_bad_hash_is_refused_and_nothing_is_left(tmp_path, monkeypatch):
    pinned_to(monkeypatch, b"the real release")
    with pytest.raises(aghinstall.InstallError) as e:
        aghinstall.fetch("arm64", tmp_path, opener=Opener(b"something else"))
    assert (
        str(e.value) == "the downloaded AdGuard Home does not match tvgw's pinned hash; nothing was installed"
    )
    assert list(tmp_path.iterdir()) == []


def test_a_download_over_the_cap_is_refused_before_it_is_hashed(tmp_path, monkeypatch):
    monkeypatch.setattr(aghinstall, "MAX_DOWNLOAD", 1 << 20)
    with pytest.raises(aghinstall.InstallError, match="over 1 MB; nothing was installed"):
        aghinstall.fetch("amd64", tmp_path, opener=Opener(b"x" * ((1 << 20) + 1)))
    assert list(tmp_path.iterdir()) == []


def test_a_network_failure_is_one_line(tmp_path):
    import urllib.error

    with pytest.raises(aghinstall.InstallError, match="could not download AdGuard Home from https://github"):
        aghinstall.fetch("amd64", tmp_path, opener=Opener(error=urllib.error.URLError("no route")))
    with pytest.raises(aghinstall.InstallError, match="pins no AdGuard Home release for 'mips'"):
        aghinstall.fetch("mips", tmp_path, opener=Opener(b""))


# ---- the archive ---------------------------------------------------------------------------------------

BINARY = b"#!/bin/sh\necho 'AdGuard Home, version v0.107.79'\n"


def tar_of(path: Path, members) -> Path:
    """A .tar.gz of (name, kind, payload) members: kind is file, exe, dir, symlink, hardlink, chr or fifo."""
    with tarfile.open(path, "w:gz") as tf:
        for name, kind, payload in members:
            info = tarfile.TarInfo(name)
            data = b""
            if kind in ("file", "exe"):
                data = payload
                info.size = len(data)
                info.mode = 0o755 if kind == "exe" else 0o640
            elif kind == "dir":
                info.type, info.mode = tarfile.DIRTYPE, 0o755
            elif kind == "symlink":
                info.type, info.linkname = tarfile.SYMTYPE, payload
            elif kind == "hardlink":
                info.type, info.linkname = tarfile.LNKTYPE, payload
            elif kind == "chr":
                info.type, info.devmajor, info.devminor = tarfile.CHRTYPE, 1, 3
            elif kind == "fifo":
                info.type = tarfile.FIFOTYPE
            tf.addfile(info, io.BytesIO(data) if data else None)
    return path


RELEASE = [  # the layout of the real archives, `./` included
    ("./AdGuardHome/", "dir", None),
    ("./AdGuardHome/AdGuardHome", "exe", BINARY),
    ("./AdGuardHome/CHANGELOG.md", "file", b"changes\n"),
    ("./AdGuardHome/AdGuardHome.sig", "file", b"sig\n"),
    ("./AdGuardHome/LICENSE.txt", "file", b"GPL-3.0\n"),
    ("./AdGuardHome/README.md", "file", b"readme\n"),
]


def at_floor(path):
    return FLOOR


def test_extract_unpacks_the_release_layout(tmp_path):
    tar = tar_of(tmp_path / "r.tar.gz", RELEASE)
    stage = tmp_path / "stage"
    stage.mkdir()
    exe = aghinstall.extract(tar, stage, version=at_floor)
    assert exe == stage / "AdGuardHome" / "AdGuardHome" and exe.read_bytes() == BINARY
    assert stat.S_IMODE(exe.stat().st_mode) == 0o755
    assert stat.S_IMODE((stage / "AdGuardHome" / "LICENSE.txt").stat().st_mode) == 0o644
    assert sorted(p.name for p in (stage / "AdGuardHome").iterdir()) == sorted(
        ["AdGuardHome", "AdGuardHome.sig", "CHANGELOG.md", "LICENSE.txt", "README.md"]
    )


@pytest.mark.parametrize(
    ("member", "says"),
    [
        (("./AdGuardHome/x", "symlink", "/etc/shadow"), "not a plain file"),
        (("./AdGuardHome/x", "hardlink", "./AdGuardHome/AdGuardHome"), "not a plain file"),
        (("./AdGuardHome/null", "chr", None), "not a plain file"),
        (("./AdGuardHome/pipe", "fifo", None), "not a plain file"),
        (("/etc/cron.d/x", "file", b"x"), "outside AdGuardHome/"),
        (("./AdGuardHome/../../etc/x", "file", b"x"), "outside AdGuardHome/"),
        (("../AdGuardHome/x", "file", b"x"), "outside AdGuardHome/"),
        (("./other/x", "file", b"x"), "outside AdGuardHome/"),
        (("./AdGuardHome/./x", "file", b"x"), "outside AdGuardHome/"),
        (("./AdGuardHome/CHANGELOG.md", "file", b"again"), "twice"),
    ],
)
def test_one_bad_member_refuses_the_whole_archive_before_anything_is_written(tmp_path, member, says):
    tar = tar_of(tmp_path / "r.tar.gz", [*RELEASE, member])
    stage = tmp_path / "stage"
    stage.mkdir()
    with pytest.raises(aghinstall.InstallError, match=f"{says}.*nothing was installed"):
        aghinstall.extract(tar, stage, version=at_floor)
    assert list(stage.iterdir()) == []
    assert not (tmp_path.parent / "etc").exists()


def test_a_file_where_a_directory_must_go_is_one_line(tmp_path):
    tar = tar_of(tmp_path / "r.tar.gz", [*RELEASE, ("./AdGuardHome/AdGuardHome/x", "file", b"x")])
    stage = tmp_path / "stage"
    stage.mkdir()
    with pytest.raises(aghinstall.InstallError, match=r"could not unpack .*nothing was installed"):
        aghinstall.extract(tar, stage, version=at_floor)


def test_an_archive_that_unpacks_too_large_is_refused(tmp_path, monkeypatch):
    monkeypatch.setattr(aghinstall, "MAX_UNPACKED", len(BINARY))
    tar = tar_of(tmp_path / "r.tar.gz", RELEASE)
    stage = tmp_path / "stage"
    stage.mkdir()
    with pytest.raises(aghinstall.InstallError, match="unpacks to over"):
        aghinstall.extract(tar, stage, version=at_floor)
    assert list(stage.iterdir()) == []


@pytest.mark.parametrize(("got", "says"), [((0, 107, 78), "reports v0.107.78"), (None, "reports no version")])
def test_a_binary_below_the_floor_is_refused(tmp_path, got, says):
    tar = tar_of(tmp_path / "r.tar.gz", RELEASE)
    stage = tmp_path / "stage"
    stage.mkdir()
    with pytest.raises(aghinstall.InstallError, match=f"{says}, not at least v0.107.79"):
        aghinstall.extract(tar, stage, version=lambda exe: got)


def test_an_archive_without_the_binary_is_refused(tmp_path):
    tar = tar_of(tmp_path / "r.tar.gz", [m for m in RELEASE if not m[0].endswith("/AdGuardHome")])
    stage = tmp_path / "stage"
    stage.mkdir()
    with pytest.raises(aghinstall.InstallError, match="has no AdGuardHome/AdGuardHome"):
        aghinstall.extract(tar, stage, version=at_floor)


def test_the_real_version_line_is_read_by_the_binary_version_reader(tmp_path):
    """extract's default reader is adguardcfg.binary_version, which `tvgw adguard upgrade` uses too."""
    tar = tar_of(tmp_path / "r.tar.gz", RELEASE)
    stage = tmp_path / "stage"
    stage.mkdir()
    assert aghinstall.extract(tar, stage) == stage / "AdGuardHome" / "AdGuardHome"


def test_fetch_release_downloads_checks_and_unpacks(tmp_path):
    tar = tar_of(tmp_path / "built.tar.gz", RELEASE)
    asked = []

    def fetcher(arch_name, dest):
        asked.append(arch_name)
        return Path(shutil.copy(tar, Path(dest) / "AdGuardHome_linux_arm64.tar.gz"))

    dest = tmp_path / "dl"
    dest.mkdir()
    exe = aghinstall.fetch_release(dest, "arm64", fetcher=fetcher, version=at_floor)
    assert asked == ["arm64"] and exe == dest / "stage" / "AdGuardHome" / "AdGuardHome"


# ---- the wizard ------------------------------------------------------------------------------------------


class Wizard(BaseHTTPRequestHandler):
    """AdGuard Home's first-run API as v0.107.79 answers it: JSON for get_addresses and check_config, a
    plain `OK` for configure and login. Configure writes the YAML, as AdGuard does, to `yaml_path`."""

    calls: list = []
    dns_busy = web_busy = ""
    yaml_path: Path | None = None
    extra_users: list = []
    configured: dict = {}

    def log_message(self, *a):
        pass

    def _send(self, code, body):
        raw = (json.dumps(body) if isinstance(body, dict) else body).encode()
        self.send_response(code)
        self.send_header("Content-Length", str(len(raw)))
        self.end_headers()
        self.wfile.write(raw)

    def do_GET(self):
        Wizard.calls.append((self.path, None))
        self._send(200, {"web_port": 3000, "dns_port": 53, "interfaces": {}, "version": "v0.107.79"})

    def do_POST(self):
        body = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
        Wizard.calls.append((self.path, body))
        if self.path.endswith("check_config"):
            self._send(200, {"web": {"status": Wizard.web_busy}, "dns": {"status": Wizard.dns_busy}})
        elif self.path.endswith("configure"):
            Wizard.configured = body
            if Wizard.yaml_path is not None:
                users = [{"name": body["username"], "password": BCRYPT}, *Wizard.extra_users]
                address = f"{body['web']['ip']}:{body['web']['port']}"
                cfg = {"http": {"address": address}, "users": users, "schema_version": 34}
                Wizard.yaml_path.write_text(yaml.safe_dump(cfg), encoding="utf-8")
            self._send(200, "OK\n")
        elif self.path == "/control/login":
            ok = body == {
                "name": Wizard.configured.get("username"),
                "password": Wizard.configured.get("password"),
            }
            self._send(200, "OK\n") if ok else self._send(403, "invalid username or password\n")
        else:
            self._send(404, "not found\n")


@pytest.fixture
def wizard(tmp_path):
    Wizard.calls, Wizard.dns_busy, Wizard.web_busy = [], "", ""
    Wizard.yaml_path, Wizard.extra_users, Wizard.configured = tmp_path / "AdGuardHome.yaml", [], {}
    srv = ThreadingHTTPServer(("127.0.0.1", 0), Wizard)  # a slow request never holds up the next
    srv.daemon_threads = True
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    yield srv.server_port
    srv.shutdown()
    srv.server_close()


def test_seed_binds_the_page_and_dns_to_loopback_with_tvgws_password(wizard):
    base = f"http://127.0.0.1:{wizard}"
    aghinstall.wait_for_wizard(base)
    password = aghinstall.new_password()
    aghinstall.seed(base, password)
    path, body = Wizard.calls[-1]
    assert path == "/control/install/configure"
    assert body["web"] == {"ip": "127.0.0.1", "port": 3000} and body["dns"] == {"ip": "127.0.0.1", "port": 53}
    assert body["username"] == "admin" and body["password"] == password and len(password) == 32
    check = dict(Wizard.calls)["/control/install/check_config"]
    assert check["set_static_ip"] is False  # tvgw never lets AdGuard change the computer's addresses
    assert aghinstall.new_password() != password


def test_a_busy_port_53_stops_before_anything_is_configured(wizard):
    Wizard.dns_busy = "listen udp 127.0.0.1:53: bind: address already in use"
    with pytest.raises(aghinstall.Port53Busy, match=r"port 53 on 127\.0\.0\.1 is not free"):
        aghinstall.seed(f"http://127.0.0.1:{wizard}", "p" * 32)
    assert [p for p, _ in Wizard.calls] == ["/control/install/check_config"]


def test_a_busy_page_port_stops_before_anything_is_configured(wizard):
    Wizard.web_busy = "listen tcp 127.0.0.1:3000: bind: address already in use"
    with pytest.raises(
        aghinstall.SeedError, match=r"port 3000 on 127\.0\.0\.1 is not free for AdGuard Home.s page"
    ):
        aghinstall.seed(f"http://127.0.0.1:{wizard}", "p" * 32)
    assert [p for p, _ in Wizard.calls] == ["/control/install/check_config"]


def test_first_run_seeds_checks_the_one_user_and_logs_in(wizard, tmp_path):
    password = aghinstall.new_password()
    aghinstall.first_run(
        f"http://127.0.0.1:{wizard}", str(tmp_path / "AdGuardHome.yaml"), password, web=("127.0.0.1", wizard)
    )
    assert [p for p, _ in Wizard.calls][-3:] == [
        "/control/install/check_config",
        "/control/install/configure",
        "/control/login",
    ]
    assert (
        yaml.safe_load((tmp_path / "AdGuardHome.yaml").read_text())["http"]["address"]
        == f"127.0.0.1:{wizard}"
    )


def test_a_yaml_with_a_second_user_is_refused(wizard, tmp_path):
    """Review E-F28: the wizard asks for no password, so a local process could answer it first."""
    Wizard.extra_users = [{"name": "intruder", "password": BCRYPT}]
    with pytest.raises(aghinstall.SeedError, match=r"holds 2 user\(s\) \(admin, intruder\), not tvgw's one"):
        aghinstall.first_run(
            f"http://127.0.0.1:{wizard}",
            str(tmp_path / "AdGuardHome.yaml"),
            "p" * 32,
            web=("127.0.0.1", wizard),
        )


@pytest.mark.parametrize(
    "users",
    [[], [{"name": "someone", "password": BCRYPT}], [{"name": "admin", "password": "plain"}], None, "admin"],
)
def test_check_users_wants_exactly_tvgws_one_user_with_a_hash(tmp_path, users):
    path = tmp_path / "AdGuardHome.yaml"
    path.write_text(yaml.safe_dump({"users": users, "schema_version": 34}), encoding="utf-8")
    with pytest.raises(aghinstall.SeedError, match="not tvgw's one 'admin'"):
        aghinstall.check_users(str(path))
    path.write_text(yaml.safe_dump({"users": [{"name": "admin", "password": BCRYPT}]}), encoding="utf-8")
    aghinstall.check_users(str(path))


def test_a_password_that_does_not_open_the_page_is_refused(wizard):
    Wizard.configured = {"username": "admin", "password": "the other one"}
    with pytest.raises(aghinstall.SeedError, match="does not open AdGuard Home's page \\(403"):
        aghinstall.confirm_login(f"http://127.0.0.1:{wizard}", "p" * 32)


def pause(seconds: float) -> None:
    """A short real pause between attempts on a closed port: a loop with none sends the kernel hundreds of
    connections a second, and macOS then rate-limits its resets and stalls the connections that follow."""
    time.sleep(0.05)


def test_a_page_that_never_comes_up_is_a_seed_error(tmp_path):
    port = aghinstall.free_port()  # nothing listens there
    with pytest.raises(aghinstall.SeedError, match="did not come up"):
        aghinstall.confirm_login(f"http://127.0.0.1:{port}", "p" * 32, wait=0.2, sleep=pause)


def test_the_wait_ends_at_once_when_the_first_run_stopped():
    port = aghinstall.free_port()
    with pytest.raises(aghinstall.SeedError, match="stopped before its wizard answered"):
        aghinstall.wait_for_wizard(f"http://127.0.0.1:{port}", wait=30, sleep=pause, alive=lambda: False)
    with pytest.raises(aghinstall.SeedError, match="did not start its first run within 0 seconds"):
        aghinstall.wait_for_wizard(f"http://127.0.0.1:{port}", wait=0.2, sleep=pause)


def test_the_wizard_is_never_asked_through_a_proxy(wizard, monkeypatch):
    """A proxy named in the environment would receive the 127.0.0.1 requests of a plain urlopen. The
    proxy here is a second server on loopback that counts what reaches it, so a request sent through it
    is a plain failure rather than a wait on an address nobody answers."""
    import urllib.request

    proxies = [h for h in aghinstall._LOCAL.handlers if isinstance(h, urllib.request.ProxyHandler)]
    assert all(h.proxies == {} for h in proxies)  # an empty one adds no handler and keeps the default out
    reached = []

    class Proxy(BaseHTTPRequestHandler):
        def log_message(self, *a):
            pass

        def do_GET(self):
            reached.append(self.path)
            self.send_response(502)
            self.send_header("Content-Length", "0")
            self.end_headers()

    proxy = ThreadingHTTPServer(("127.0.0.1", 0), Proxy)
    proxy.daemon_threads = True
    threading.Thread(target=proxy.serve_forever, daemon=True).start()
    try:
        for name in ("http_proxy", "HTTP_PROXY"):
            monkeypatch.setenv(name, f"http://127.0.0.1:{proxy.server_port}")
        monkeypatch.delenv("no_proxy", raising=False)
        monkeypatch.delenv("NO_PROXY", raising=False)
        assert aghinstall._call(f"http://127.0.0.1:{wizard}", "/control/install/get_addresses")[0] == 200
        assert reached == []
    finally:
        proxy.shutdown()
        proxy.server_close()


# ---- whose AdGuard it is ----------------------------------------------------------------------------------


def adguard_at(
    tmp_path: Path, cfg: dict | None, version_line: str = "AdGuard Home, version v0.107.79"
) -> Settings:
    s = settings(tmp_path)
    home = Path(s.adguard_yaml).parent
    home.mkdir(parents=True, exist_ok=True)
    exe = home / "AdGuardHome"
    exe.write_text(f"#!/bin/sh\necho '{version_line}'\n", encoding="utf-8")
    exe.chmod(0o755)
    if cfg is not None:
        Path(s.adguard_yaml).write_text(adguardcfg.dump_yaml(cfg), encoding="utf-8")
    return s


OWNER_LIKE = {  # a gateway set up by hand under decision 25 and applied since: no marker
    "users": [{"name": "someone", "password": BCRYPT}],
    "dns": {"bind_hosts": ["0.0.0.0"], "port": 53},
    "user_rules": ["||ads.example^"],
    "clients": {
        "persistent": [{"name": "lgcx", "ids": ["10.10.10.17", "B4:B2:91:AA:BB:CC"], "tags": ["device_tv"]}]
    },
    "schema_version": 34,
}
HOUSEHOLD = {  # someone's AdGuard serving their home network
    "users": [{"name": "someone", "password": BCRYPT}],
    "dns": {"bind_hosts": ["0.0.0.0"], "port": 53},
    "user_rules": ["||ads.example^"],
    "clients": {"persistent": [{"name": "laptop", "ids": ["192.0.2.20"]}]},
    "schema_version": 34,
}


def test_state_absent_and_unconfigured(tmp_path):
    s = settings(tmp_path)
    marker = str(tmp_path / "marker")
    assert aghinstall.state(s.adguard_yaml, marker, PROFILE, s) == "absent"
    Path(s.adguard_yaml).parent.mkdir(parents=True)
    Path(s.adguard_yaml).write_text("schema_version: 34\n")  # a YAML with no binary is still absent
    assert aghinstall.state(s.adguard_yaml, marker, PROFILE, s) == "absent"
    s = adguard_at(tmp_path / "b", None)
    assert aghinstall.state(s.adguard_yaml, marker, PROFILE, s) == "unconfigured"


def test_an_owner_like_yaml_without_the_marker_is_tvgws(tmp_path):
    """Review E-F13 and U-F19: every gateway installed by hand has no marker; its client entry says it."""
    s = adguard_at(tmp_path, OWNER_LIKE)
    assert aghinstall.state(s.adguard_yaml, str(tmp_path / "no-marker"), PROFILE, s) == "tvgw"


def test_the_must_allow_exceptions_alone_say_tvgw(tmp_path):
    cfg = {**HOUSEHOLD, "user_rules": PROFILE.adguard_rules(), "clients": {"persistent": []}}
    s = adguard_at(tmp_path, cfg)
    assert aghinstall.state(s.adguard_yaml, str(tmp_path / "no-marker"), PROFILE, s) == "tvgw"
    cfg["user_rules"] = PROFILE.adguard_rules()[1:]  # one exception missing: not what apply writes
    s = adguard_at(tmp_path, cfg)
    assert aghinstall.state(s.adguard_yaml, str(tmp_path / "no-marker"), PROFILE, s) == "foreign"


def test_under_the_general_profile_only_the_client_entry_or_the_marker_says_tvgw(tmp_path):
    """(profile) generic-tv has no must-allow hosts, so `tvgw adguard apply` writes no exceptions to
    recognise, and the empty set of them is in every YAML: a household AdGuard must not read as tvgw's
    by it, or the install would take it over without asking (design decisions 52 and 62)."""
    generic = profile.load(profile.GENERIC)
    assert not generic.must_allow and not generic.adguard_rules()
    s = adguard_at(tmp_path, HOUSEHOLD)
    assert aghinstall.state(s.adguard_yaml, str(tmp_path / "no-marker"), generic, s) == "foreign"
    s = adguard_at(tmp_path / "owner", OWNER_LIKE)
    assert aghinstall.state(s.adguard_yaml, str(tmp_path / "no-marker"), generic, s) == "tvgw"
    marker = tmp_path / "marker"
    marker.write_text("0.107.79\n")
    s = adguard_at(tmp_path / "marked", HOUSEHOLD)
    assert aghinstall.state(s.adguard_yaml, str(marker), generic, s) == "tvgw"


def test_a_yaml_with_neither_is_foreign_and_the_marker_makes_it_tvgws(tmp_path):
    s = adguard_at(tmp_path, HOUSEHOLD)
    marker = tmp_path / "marker"
    assert aghinstall.state(s.adguard_yaml, str(marker), PROFILE, s) == "foreign"
    marker.write_text("0.107.79\n")
    assert aghinstall.state(s.adguard_yaml, str(marker), PROFILE, s) == "tvgw"


def test_the_placeholder_mac_identifies_nothing(tmp_path):
    cfg = {**HOUSEHOLD, "clients": {"persistent": [{"name": "x", "ids": ["00:00:00:00:00:00"]}]}}
    s = adguard_at(tmp_path, cfg)
    s = dataclasses.replace(s, tv_mac="00:00:00:00:00:00", tv_ip="10.10.10.99")
    assert aghinstall.state(s.adguard_yaml, str(tmp_path / "m"), PROFILE, s) == "foreign"


def test_tvgws_below_the_floor_is_old_and_a_foreign_one_stays_foreign(tmp_path):
    s = adguard_at(tmp_path, OWNER_LIKE, "AdGuard Home, version v0.107.73")
    assert aghinstall.state(s.adguard_yaml, str(tmp_path / "m"), PROFILE, s) == "old"
    s = adguard_at(tmp_path / "f", HOUSEHOLD, "AdGuard Home, version v0.107.73")
    assert aghinstall.state(s.adguard_yaml, str(tmp_path / "m"), PROFILE, s) == "foreign"


def test_an_unreadable_yaml_is_never_taken_for_tvgws(tmp_path):
    s = adguard_at(tmp_path, None)
    Path(s.adguard_yaml).write_text("users: [unclosed\n")
    assert aghinstall.state(s.adguard_yaml, str(tmp_path / "m"), PROFILE, s) == "foreign"


# ---- (adguard) the take-over guard ------------------------------------------------------------------------

NOW_T = 1_793_026_800.0  # conftest.NOW: 2026-10-26 10:00 CDT
DAY = 86400.0
NARROW = {"bind_hosts": ["10.10.10.1", "127.0.0.1"], "port": 53}


def stamp(t: float) -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%S", time.gmtime(t)) + ".123456789Z"  # AdGuard writes nine digits


def logged(path: Path, *records: tuple[str, float]) -> None:
    """A query log with one record per (client, time), in the order AdGuard appends them."""
    path.parent.mkdir(parents=True, exist_ok=True)
    lines = [json.dumps({"T": stamp(t), "IP": ip, "QH": "example.com", "QT": "A"}) for ip, t in records]
    path.write_text("".join(line + "\n" for line in lines), encoding="utf-8")


def foreign_at(tmp_path: Path, dns: dict | None, *log: tuple[str, float], cfg: dict | None = None, **kw):
    """A household's AdGuard (no marker, no TV client, no must-allow exceptions) listening as `dns` says,
    with `log` in its query log, and the settings that point at both."""
    base = dict(cfg or HOUSEHOLD)
    if dns is None:
        base.pop("dns", None)
    else:
        base["dns"] = dns
    s = adguard_at(tmp_path, base)
    s = dataclasses.replace(s, adguard_querylog=str(tmp_path / "data" / "querylog.json"), **kw)
    logged(Path(s.adguard_querylog), *log)
    return s


def refusal(s: Settings, tmp_path: Path, marker: str = "no-marker") -> str | None:
    return aghinstall.takeover_refusal(s, PROFILE, marker=str(tmp_path / marker), now=NOW_T)


@pytest.mark.parametrize(
    "dns",
    [
        {"bind_hosts": ["0.0.0.0"], "port": 53},  # the wizard's usual answer, every interface
        {"bind_hosts": ["::"], "port": 53},
        {"bind_hosts": [], "port": 53},
        {"port": 53},
        None,
    ],
)
def test_a_foreign_adguard_that_listens_everywhere_is_refused(tmp_path, dns):
    """H1: its DNS and its page would move to this computer and the TV alone, so every other device of
    the house would lose its resolver. No query log is needed to say so: it answers whoever asks."""
    s = foreign_at(tmp_path, dns)
    assert aghinstall.state(s.adguard_yaml, str(tmp_path / "no-marker"), PROFILE, s) == "foreign"
    assert refusal(s, tmp_path) == "it answers DNS on every address of this computer"


def test_a_foreign_adguard_on_a_home_address_is_refused_and_named(tmp_path):
    s = foreign_at(tmp_path, {"bind_hosts": ["127.0.0.1", "192.0.2.50", "198.51.100.7"], "port": 53})
    assert refusal(s, tmp_path) == "it also answers DNS on 192.0.2.50 and 198.51.100.7"


def test_a_foreign_adguard_whose_log_shows_other_devices_is_refused_newest_first(tmp_path):
    """H1: listening on the TV side and loopback alone, it still answered other devices this week (a
    router forwarding to it, a phone over its encrypted DNS): those, newest first, three named."""
    log = [
        ("10.10.10.17", NOW_T - 6 * DAY),  # the TV
        ("127.0.0.1", NOW_T - 5 * DAY),  # this computer
        ("192.0.2.20", NOW_T - 4 * DAY),
        ("192.0.2.31", NOW_T - 3 * DAY),
        ("198.51.100.4", NOW_T - 2 * DAY),
        ("192.0.2.20", NOW_T - 1 * DAY),  # again, later: once, at its newest
        ("2001:db8::5", NOW_T - 60),
    ]
    s = foreign_at(tmp_path, NARROW, *log)
    assert refusal(s, tmp_path) == (
        "in the last 7 days it answered 2001:db8::5, 192.0.2.20, 198.51.100.4 and 1 more"
    )
    s = foreign_at(tmp_path / "wide", {"bind_hosts": ["0.0.0.0"]}, ("192.0.2.20", NOW_T - 60))
    assert refusal(s, tmp_path / "wide") == (
        "it answers DNS on every address of this computer, and in the last 7 days it answered 192.0.2.20"
    )


def test_a_foreign_adguard_for_the_tv_and_this_computer_alone_is_taken_over(tmp_path):
    """Only the TV side and loopback in the log of the last 7 days, and no other address to listen on:
    nothing else depends on it, and the apply goes ahead as it always did."""
    log = [
        ("192.0.2.20", NOW_T - 8 * DAY),  # a laptop, before the week the guard reads
        ("10.10.10.17", NOW_T - 3 * DAY),
        ("10.10.10.12", NOW_T - 2 * DAY),  # another address of the TV side, from the pool
        ("127.0.0.1", NOW_T - DAY),
        ("::1", NOW_T - 60),
        ("::ffff:127.0.0.1", NOW_T - 30),
    ]
    s = foreign_at(tmp_path, NARROW, *log)
    assert aghinstall.state(s.adguard_yaml, str(tmp_path / "no-marker"), PROFILE, s) == "foreign"
    assert refusal(s, tmp_path) is None
    s = foreign_at(tmp_path / "lo", {"bind_hosts": ["127.0.0.1"]})  # set up for this computer alone
    assert refusal(s, tmp_path / "lo") is None


def test_tvgws_own_adguard_is_never_refused_whatever_it_listens_on_and_answered(tmp_path):
    """The owner's gateway and every one set up by hand: its YAML carries the TV's client entry (or tvgw
    installed it), so it is tvgw's, listening on 0.0.0.0 under keep included."""
    s = foreign_at(tmp_path, {"bind_hosts": ["0.0.0.0"]}, ("192.0.2.20", NOW_T - 60), cfg=OWNER_LIKE)
    assert refusal(s, tmp_path) is None
    s = foreign_at(tmp_path / "marked", {"bind_hosts": ["0.0.0.0"]}, ("192.0.2.20", NOW_T - 60))
    (tmp_path / "marked" / "marker").write_text("0.107.79\n", encoding="utf-8")
    assert refusal(s, tmp_path / "marked", marker="marker") is None
    s = dataclasses.replace(settings(tmp_path / "none"), adguard_querylog=str(tmp_path / "none" / "q"))
    assert refusal(s, tmp_path / "none") is None  # no AdGuard Home at all: nothing to take over


def test_the_owners_yes_lets_tvgw_take_it_over(tmp_path):
    s = foreign_at(tmp_path, {"bind_hosts": ["0.0.0.0"]}, ("192.0.2.20", NOW_T - 60), adguard_take_over="yes")
    assert refusal(s, tmp_path) is None


def test_the_guard_reads_the_query_log_where_adguard_writes_it(tmp_path):
    """A config naming its own querylog.dir_path keeps the log there, relative to AdGuard's directory."""
    cfg = {**HOUSEHOLD, "querylog": {"dir_path": "logs"}}
    s = foreign_at(tmp_path, NARROW, cfg=cfg)
    logged(Path(s.adguard_yaml).parent / "logs" / "querylog.json", ("192.0.2.20", NOW_T - 60))
    assert refusal(s, tmp_path) == "in the last 7 days it answered 192.0.2.20"


def test_an_unreadable_yaml_reads_as_listening_everywhere(tmp_path):
    s = foreign_at(tmp_path, NARROW)
    Path(s.adguard_yaml).write_text("dns: [unclosed\n", encoding="utf-8")
    assert refusal(s, tmp_path) == "it answers DNS on every address of this computer"


def test_install_refuses_a_foreign_adguard_with_the_way_on_and_never_offers_a_blind_take_over():
    """The refusal of `tvgw adguard install` names the cost and the owner's yes, not a bare command."""
    text = aghinstall.FOREIGN
    assert "not by tvgw" in text and "computer of its own" in text
    assert "ADGUARD_TAKE_OVER=yes in /etc/tvgw/tvgw.conf" in text
    assert "run sudo tvgw adguard apply to let tvgw take it over" not in text


# ---- install --------------------------------------------------------------------------------------------


class FakeHost:
    """The computer as install() sees it: every command recorded, systemd and `-s install` answering 0,
    and a first run that writes the YAML AdGuard's wizard would, or raises what the test says."""

    def __init__(self, tmp_path: Path, service_loaded=False, fail=None, extra_users=(), ss=""):
        self.tar = tar_of(tmp_path / "release.tar.gz", RELEASE)
        self.calls: list[tuple[list[str], str | None]] = []
        self.service_loaded, self.fail, self.extra_users, self.ss = (
            service_loaded,
            fail,
            list(extra_users),
            ss,
        )
        self.passwords: list[str] = []
        self.fetched = 0
        self.host = aghinstall.Host(
            run=self.run,
            fetch=self.fetch,
            version=at_floor,
            first_run=self.first_run,
            free_port=lambda: 24567,
            arch=lambda: "arm64",
        )

    def run(self, argv, cwd=None):
        self.calls.append((list(argv), cwd))
        out = ""
        if argv[:3] == ["systemctl", "show", "-P"]:
            out = "loaded\n" if self.service_loaded else "not-found\n"
        elif argv[0] == "ss":
            out = self.ss if "u" in argv[1] else ""
        return subprocess.CompletedProcess(argv, 0, out, "")

    def fetch(self, arch_name, dest):
        self.fetched += 1
        return Path(shutil.copy(self.tar, Path(dest) / "AdGuardHome_linux_arm64.tar.gz"))

    def first_run(self, base, yaml_path, password, alive=None):
        assert base == "http://127.0.0.1:24567" and alive is not None
        self.passwords.append(password)
        users = [{"name": "admin", "password": BCRYPT}, *self.extra_users]
        Path(yaml_path).write_text(yaml.safe_dump({"users": users, "schema_version": 34}), encoding="utf-8")
        if self.extra_users:
            aghinstall.check_users(yaml_path)
        if self.fail is not None:
            raise self.fail

    def argvs(self):
        return [argv for argv, _ in self.calls]


def paths(tmp_path):
    return str(tmp_path / "var" / "marker"), str(tmp_path / "etc" / "adguard-admin")


def test_install_from_nothing_fetches_seeds_on_loopback_registers_and_marks(tmp_path):
    s, fake = settings(tmp_path), FakeHost(tmp_path)
    marker, admin = paths(tmp_path)
    done = aghinstall.install(s, PROFILE, host=fake.host, marker=marker, admin=admin)
    home = Path(s.adguard_yaml).parent
    exe = str(home / "AdGuardHome")
    assert (home / "AdGuardHome").read_bytes() == BINARY and fake.fetched == 1
    firstrun = next(a for a in fake.argvs() if a[0] == "systemd-run")
    assert firstrun == [
        "systemd-run",
        "--unit=tvgw-adguard-firstrun",
        "--collect",
        f"--property=WorkingDirectory={home}",
        "--",
        exe,
        "--web-addr",
        "127.0.0.1:24567",
        "--no-check-update",
        "-w",
        str(home),
        "-c",
        s.adguard_yaml,
    ]
    assert not [a for a in fake.argvs() if any("0.0.0.0" in x for x in a)]
    assert fake.calls[-1] == ([exe, "-s", "install", "--no-check-update"], str(home))
    stops = [a for a in fake.argvs() if a == ["systemctl", "stop", "tvgw-adguard-firstrun"]]
    assert len(stops) == 2  # one left by an interrupted run, then the wizard's own once it is done
    assert Path(marker).read_text() == "0.107.79\n" and stat.S_IMODE(os.stat(marker).st_mode) == 0o640
    assert stat.S_IMODE(os.stat(admin).st_mode) == 0o600
    assert aghinstall.read_admin(admin) == {"user": "admin", "password": fake.passwords[0]}
    assert done[0].startswith("installed AdGuard Home v0.107.79 in ") and "pinned SHA-256" in done[0]
    assert any("127.0.0.1:3000" in line for line in done) and not any(
        fake.passwords[0] in line for line in done
    )
    assert aghinstall.state(s.adguard_yaml, marker, PROFILE, s, version=at_floor) == "tvgw"


def test_install_under_keep_says_the_tv_gets_no_answer_until_the_setting_is_gateway(tmp_path):
    """The wizard puts DNS on 127.0.0.1 alone and `keep` leaves it there, while the firewall sends the
    TV's lookups to GW_IP: the install says so, with the fix, and says nothing of it under gateway."""
    marker, admin = paths(tmp_path)
    done = aghinstall.install(
        settings(tmp_path), PROFILE, host=FakeHost(tmp_path).host, marker=marker, admin=admin
    )
    assert done[-1] == (
        "ADGUARD_LISTEN is keep, so AdGuard Home answers DNS on 127.0.0.1 alone and the TV, which asks"
        " 10.10.10.1, gets no answer: set ADGUARD_LISTEN=gateway in /etc/tvgw/tvgw.conf before that apply"
    )
    assert done[-2].startswith("next: sudo tvgw adguard apply")
    other = tmp_path / "gateway"
    other.mkdir()
    marker, admin = paths(other)
    s = settings(other, adguard_listen="gateway")
    done = aghinstall.install(s, PROFILE, host=FakeHost(other).host, marker=marker, admin=admin)
    assert done[-1].startswith("next: sudo tvgw adguard apply")
    assert not [line for line in done if "ADGUARD_LISTEN" in line]


def test_install_is_idempotent_on_tvgws_adguard(tmp_path):
    s, fake = adguard_at(tmp_path, OWNER_LIKE), FakeHost(tmp_path)
    marker, admin = paths(tmp_path)
    before = Path(s.adguard_yaml).read_bytes()
    assert aghinstall.install(s, PROFILE, host=fake.host, marker=marker, admin=admin) == [
        f"AdGuard Home in {Path(s.adguard_yaml).parent} is already set up for tvgw; nothing to do"
    ]
    assert fake.calls == [] and fake.fetched == 0 and Path(s.adguard_yaml).read_bytes() == before
    assert not os.path.exists(marker) and not os.path.exists(admin)


def test_a_foreign_adguard_is_refused_and_left_alone(tmp_path):
    """D3: an AdGuard that serves a household is taken over only on an explicit yes, which is running
    `tvgw adguard apply` on it, never by install()."""
    s, fake = adguard_at(tmp_path, HOUSEHOLD), FakeHost(tmp_path)
    marker, admin = paths(tmp_path)
    before = Path(s.adguard_yaml).read_bytes()
    with pytest.raises(
        aghinstall.InstallError, match=r"not by tvgw.*every device that uses it.*ADGUARD_TAKE_OVER=yes"
    ):
        aghinstall.install(s, PROFILE, host=fake.host, marker=marker, admin=admin)
    assert fake.calls == [] and Path(s.adguard_yaml).read_bytes() == before


def test_tvgws_adguard_below_the_floor_is_sent_to_upgrade_fetch(tmp_path):
    s, fake = adguard_at(tmp_path, OWNER_LIKE), FakeHost(tmp_path)
    fake.host.version = lambda exe: (0, 107, 73)
    marker, admin = paths(tmp_path)
    with pytest.raises(aghinstall.InstallError, match="sudo tvgw adguard upgrade --fetch"):
        aghinstall.install(s, PROFILE, host=fake.host, marker=marker, admin=admin)
    assert fake.calls == []


def test_an_unconfigured_adguard_is_seeded_and_its_own_unit_restarted(tmp_path):
    """AdGuard's install script ran, its wizard did not: its unit serves that wizard on AdGuard's
    default address, so it is stopped before tvgw's first run and started again on the new YAML."""
    s, fake = adguard_at(tmp_path, None), FakeHost(tmp_path, service_loaded=True)
    marker, admin = paths(tmp_path)
    before = Path(s.adguard_yaml).parent.joinpath("AdGuardHome").read_bytes()
    done = aghinstall.install(s, PROFILE, host=fake.host, marker=marker, admin=admin)
    argvs = fake.argvs()
    assert fake.fetched == 0 and Path(s.adguard_yaml).parent.joinpath("AdGuardHome").read_bytes() == before
    assert argvs.index(["systemctl", "stop", "AdGuardHome"]) < next(
        i for i, a in enumerate(argvs) if a[0] == "systemd-run"
    )
    assert argvs[-1] == ["systemctl", "start", "AdGuardHome"]
    assert not [a for a in argvs if "-s" in a]
    assert done[-3:-1] == [  # then the line ADGUARD_LISTEN=keep adds
        "started AdGuardHome.service",
        "next: sudo tvgw adguard apply, which install.sh also runs at its AdGuard step",
    ]


def test_an_unconfigured_binary_below_the_floor_is_replaced_first(tmp_path):
    s, fake = adguard_at(tmp_path, None, "AdGuard Home, version v0.107.70"), FakeHost(tmp_path)
    fake.host.version = lambda exe: (0, 107, 70) if "stage" not in exe else FLOOR
    marker, admin = paths(tmp_path)
    done = aghinstall.install(s, PROFILE, host=fake.host, marker=marker, admin=admin)
    assert Path(s.adguard_yaml).parent.joinpath("AdGuardHome").read_bytes() == BINARY
    assert done[0].startswith("replaced the AdGuard Home binary") and fake.fetched == 1


def test_a_yaml_left_without_its_binary_is_never_answered_for(tmp_path):
    s, fake = settings(tmp_path), FakeHost(tmp_path)
    marker, admin = paths(tmp_path)
    Path(s.adguard_yaml).parent.mkdir(parents=True)
    Path(s.adguard_yaml).write_text(adguardcfg.dump_yaml(HOUSEHOLD))
    before = Path(s.adguard_yaml).read_bytes()
    done = aghinstall.install(s, PROFILE, host=fake.host, marker=marker, admin=admin)
    assert "its wizard was not run (state: foreign)" in done[-1]
    assert not [a for a in fake.argvs() if a[0] == "systemd-run"]
    assert Path(s.adguard_yaml).read_bytes() == before and not os.path.exists(marker)


def test_a_busy_port_53_rolls_back_this_runs_files_keeps_the_binary_and_names_the_holder(tmp_path):
    ss = 'UNCONN 0 0 0.0.0.0:53 0.0.0.0:* users:(("dnsmasq",pid=812,fd=4))\n'
    fake = FakeHost(tmp_path, fail=aghinstall.Port53Busy("port 53 on 127.0.0.1 is not free"), ss=ss)
    s = settings(tmp_path)
    marker, admin = paths(tmp_path)
    with pytest.raises(aghinstall.InstallError) as e:
        aghinstall.install(s, PROFILE, host=fake.host, marker=marker, admin=admin)
    message = str(e.value)
    assert "port 53 is held by dnsmasq (pid 812) on 0.0.0.0:53" in message
    assert f"removed {s.adguard_yaml}, {admin}" in message and "the binary in" in message
    assert not os.path.exists(s.adguard_yaml) and not os.path.exists(admin) and not os.path.exists(marker)
    assert Path(s.adguard_yaml).parent.joinpath("AdGuardHome").exists()
    argvs = fake.argvs()
    started = next(i for i, a in enumerate(argvs) if a[0] == "systemd-run")
    assert ["systemctl", "stop", "tvgw-adguard-firstrun"] in argvs[started:]
    assert [a[0] for a in argvs[-2:]] == ["ss", "ss"]  # the holder, asked once everything was put back
    assert not [a for a in argvs if "-s" in a]
    assert aghinstall.state(s.adguard_yaml, marker, PROFILE, s, version=at_floor) == "unconfigured"


def test_a_yaml_with_a_user_tvgw_did_not_make_is_removed_with_the_run(tmp_path):
    fake = FakeHost(tmp_path, extra_users=[{"name": "intruder", "password": BCRYPT}])
    s = settings(tmp_path)
    marker, admin = paths(tmp_path)
    with pytest.raises(aghinstall.InstallError, match="something else may have answered"):
        aghinstall.install(s, PROFILE, host=fake.host, marker=marker, admin=admin)
    assert not os.path.exists(s.adguard_yaml) and not os.path.exists(admin)


def test_a_service_that_does_not_start_is_stopped_so_no_open_wizard_is_left(tmp_path):
    fake = FakeHost(tmp_path)
    real = fake.run

    def run(argv, cwd=None):
        out = real(argv, cwd)
        if "-s" in argv:
            return subprocess.CompletedProcess(argv, 1, "", "Init already exists")
        return out

    fake.host.run = run
    s = settings(tmp_path)
    marker, admin = paths(tmp_path)
    with pytest.raises(aghinstall.InstallError, match="service did not start: Init already exists"):
        aghinstall.install(s, PROFILE, host=fake.host, marker=marker, admin=admin)
    assert fake.argvs()[-1] == ["systemctl", "stop", "AdGuardHome"]
    assert not os.path.exists(s.adguard_yaml) and not os.path.exists(marker)


def test_a_failure_before_the_first_run_removes_only_the_admin_file(tmp_path):
    fake = FakeHost(tmp_path)
    real = fake.run
    fake.host.run = lambda argv, cwd=None: (
        subprocess.CompletedProcess(argv, 1, "", "Failed to start transient service unit")
        if argv[0] == "systemd-run"
        else real(argv, cwd)
    )
    s = settings(tmp_path)
    marker, admin = paths(tmp_path)
    with pytest.raises(
        aghinstall.InstallError, match=f"systemd-run could not start.*; removed {re.escape(admin)};"
    ):
        aghinstall.install(s, PROFILE, host=fake.host, marker=marker, admin=admin)
    assert not os.path.exists(admin)


def test_the_rollback_removes_only_what_this_run_created(tmp_path):
    yaml_path, admin = tmp_path / "AdGuardHome.yaml", tmp_path / "adguard-admin"
    yaml_path.write_text("schema_version: 34\n")
    admin.write_text("user=admin\n")
    calls = []

    def run(argv, cwd=None):
        calls.append(argv)
        return subprocess.CompletedProcess(argv, 0, "", "")

    said = aghinstall._roll_back(run, str(yaml_path), str(admin), False, False, False, False)
    assert yaml_path.exists() and admin.exists() and calls == []
    assert said == f"nothing was removed; the binary in {tmp_path} stays"
    said = aghinstall._roll_back(run, str(yaml_path), str(admin), True, True, True, True, had_service=True)
    assert not yaml_path.exists() and not admin.exists()
    assert calls == [["systemctl", "stop", "tvgw-adguard-firstrun"], ["systemctl", "stop", "AdGuardHome"]]
    assert said.endswith("stays and AdGuardHome.service stays stopped")


def test_an_open_wizard_left_by_adguards_own_unit_stays_stopped_after_a_failure(tmp_path):
    s = adguard_at(tmp_path, None)
    fake = FakeHost(tmp_path, service_loaded=True, fail=aghinstall.SeedError("AdGuard Home refused"))
    marker, admin = paths(tmp_path)
    with pytest.raises(aghinstall.InstallError, match=r"AdGuardHome\.service stays stopped"):
        aghinstall.install(s, PROFILE, host=fake.host, marker=marker, admin=admin)
    assert ["systemctl", "start", "AdGuardHome"] not in fake.argvs()


def test_one_install_at_a_time(tmp_path):
    import fcntl

    s, fake = settings(tmp_path), FakeHost(tmp_path)
    marker, admin = paths(tmp_path)
    os.makedirs(os.path.dirname(marker))
    fd = os.open(os.path.join(os.path.dirname(marker), ".adguard-install.lock"), os.O_RDWR | os.O_CREAT)
    try:
        fcntl.flock(fd, fcntl.LOCK_EX)
        with pytest.raises(aghinstall.InstallError, match="another tvgw adguard install is running"):
            aghinstall.install(s, PROFILE, host=fake.host, marker=marker, admin=admin)
    finally:
        os.close(fd)
    assert fake.calls == []


# ---- the computer around it --------------------------------------------------------------------------------


def test_port53_holder_reads_ss(tmp_path):
    def run(argv, cwd=None):
        out = {
            "-Hlnup": 'UNCONN 0 0 127.0.0.53%lo:53 0.0.0.0:* users:(("systemd-resolve",pid=401,fd=14))\n'
            "UNCONN 0 0 0.0.0.0:53 0.0.0.0:*\n",
            "-Hltnp": 'LISTEN 0 32 127.0.0.53%lo:53 0.0.0.0:* users:(("systemd-resolve",pid=401,fd=15))\n',
        }[argv[1]]
        return subprocess.CompletedProcess(argv, 0, out, "")

    assert (
        aghinstall.port53_holder(run)
        == "systemd-resolve (pid 401) on 127.0.0.53%lo:53; a process on 0.0.0.0:53"
    )
    assert (
        aghinstall.port53_holder(lambda argv, cwd=None: subprocess.CompletedProcess(argv, 0, "", ""))
        == "nothing"
    )


def test_free_port_skips_a_port_something_holds():
    import socket

    held = socket.socket()
    held.bind(("127.0.0.1", 0))
    try:
        taken = held.getsockname()[1]
        free = aghinstall.free_port()
        picks = iter([taken, free])
        assert aghinstall.free_port(pick=lambda ports: next(picks)) == free
        with pytest.raises(aghinstall.InstallError, match="no free port"):
            aghinstall.free_port(tries=3, pick=lambda ports: taken)
    finally:
        held.close()


def test_the_admin_password_is_read_by_aghinstall_alone():
    """The password never reaches a backup, a report, an analyst pack or a bundle: no other module names
    the file, and `tvgw backup` copies the store and nothing else."""
    named = sorted(
        p.name
        for p in (ROOT / "src" / "tvgw").rglob("*.py")
        if "adguard-admin" in p.read_text(encoding="utf-8")
    )
    assert named == ["aghinstall.py"]
    readers = sorted(
        p.name
        for p in (ROOT / "src" / "tvgw").rglob("*.py")
        if "read_admin(" in p.read_text(encoding="utf-8")
    )
    assert readers == ["aghinstall.py"]


# ---- the page --------------------------------------------------------------------------------------------


def test_ui_says_how_to_reach_the_page_where_the_password_is_and_that_apply_undoes_changes(tmp_path):
    s = adguard_at(tmp_path, {**OWNER_LIKE, "http": {"address": "127.0.0.1:3000"}})
    admin = tmp_path / "adguard-admin"
    aghinstall.write_admin(str(admin), "admin", "p" * 32)
    lines, code = aghinstall.ui_lines(s, admin=str(admin))
    text = "\n".join(lines)
    assert code == 0
    assert "open only on this computer, at http://127.0.0.1:3000" in text
    assert "ssh -L 3000:127.0.0.1:3000 <you>@<this computer>" in text
    assert f"sudo cat {admin}" in text and "p" * 32 not in text
    assert "puts its lists, rules and settings back at its next apply" in text


def test_ui_on_a_hand_installed_adguard_points_at_its_own_wizard_and_warns_of_a_wide_page(tmp_path):
    s = adguard_at(tmp_path, {**OWNER_LIKE, "http": {"address": "0.0.0.0:3000"}})
    lines, code = aghinstall.ui_lines(s, admin=str(tmp_path / "none"))
    text = "\n".join(lines)
    assert code == 0 and "listens on 0.0.0.0:3000, where other computers can reach it" in text
    assert "chosen in AdGuard Home's own wizard" in text


def test_ui_without_adguard_says_how_to_install_it(tmp_path):
    lines, code = aghinstall.ui_lines(settings(tmp_path))
    assert code == 1 and lines == [
        "AdGuard Home is not set up on this computer yet: sudo tvgw adguard install"
    ]


# ---- the command line --------------------------------------------------------------------------------


@pytest.fixture
def cli_conf(tmp_path, monkeypatch):
    from tvgw import cli

    real_load = cli.config.load
    yaml_path = tmp_path / "opt" / "AdGuardHome" / "AdGuardHome.yaml"
    monkeypatch.setattr(
        cli.config, "load", lambda path, **kw: real_load(path, adguard_yaml=str(yaml_path), **kw)
    )
    return ["--conf", str(tmp_path / "none.conf")], yaml_path


def test_cli_install_needs_root_and_prints_a_line_per_thing_done(cli_conf, monkeypatch, capsys):
    from tvgw import cli

    conf, _ = cli_conf
    monkeypatch.setattr(cli.os, "geteuid", lambda: 1000)
    with pytest.raises(SystemExit, match="run it as root"):
        cli.main([*conf, "adguard", "install"])
    monkeypatch.setattr(cli.os, "geteuid", lambda: 0)
    asked = []
    monkeypatch.setattr(aghinstall, "install", lambda s, prof: asked.append(s.adguard_yaml) or ["one", "two"])
    assert cli.main([*conf, "adguard", "install"]) == 0
    assert capsys.readouterr().out == "tvgw adguard: one\ntvgw adguard: two\n" and len(asked) == 1

    def refused(s, prof):
        raise aghinstall.InstallError(aghinstall.FOREIGN)

    monkeypatch.setattr(aghinstall, "install", refused)
    with pytest.raises(SystemExit, match=r"^tvgw adguard: AdGuard Home is already set up on this computer"):
        cli.main([*conf, "adguard", "install"])


def test_cli_ui_prints_the_way_to_the_page(cli_conf, capsys):
    from tvgw import cli

    conf, yaml_path = cli_conf
    assert cli.main([*conf, "adguard", "ui"]) == 1
    assert "sudo tvgw adguard install" in capsys.readouterr().err
    yaml_path.parent.mkdir(parents=True)
    yaml_path.write_text(adguardcfg.dump_yaml({**OWNER_LIKE, "http": {"address": "127.0.0.1:3000"}}))
    assert cli.main([*conf, "adguard", "ui"]) == 0
    assert "ssh -L 3000:127.0.0.1:3000" in capsys.readouterr().out


@pytest.mark.parametrize(
    "argv",
    [
        ["adguard", "install", "/tmp/AdGuardHome"],
        ["adguard", "ui", "/tmp/AdGuardHome"],
        ["adguard", "diff", "--fetch"],
        ["adguard", "install", "--fetch"],
        ["adguard", "upgrade", "/tmp/AdGuardHome", "--fetch"],
        ["adguard", "upgrade"],
    ],
)
def test_cli_usage_errors_exit_2(cli_conf, capsys, argv):
    from tvgw import cli

    conf, _ = cli_conf
    assert cli.main([*conf, *argv]) == 2
    assert "tvgw adguard: error: " in capsys.readouterr().err


def set_up_at(yaml_path: Path) -> None:
    """An AdGuard Home that is set up: its binary and its YAML."""
    yaml_path.parent.mkdir(parents=True, exist_ok=True)
    yaml_path.write_text(adguardcfg.dump_yaml(OWNER_LIKE), encoding="utf-8")
    exe = yaml_path.parent / "AdGuardHome"
    exe.write_bytes(BINARY)
    exe.chmod(0o755)


@pytest.mark.parametrize("has", ["nothing", "binary", "yaml"])
def test_upgrade_fetch_without_adguard_set_up_downloads_nothing_and_names_install(cli_conf, monkeypatch, has):
    from tvgw import cli

    conf, yaml_path = cli_conf
    monkeypatch.setattr(cli.os, "geteuid", lambda: 0)
    if has != "nothing":
        set_up_at(yaml_path)
        (yaml_path if has == "binary" else yaml_path.parent / "AdGuardHome").unlink()

    def never(*a, **kw):
        raise AssertionError("downloaded")

    monkeypatch.setattr(aghinstall, "fetch_release", never)
    with pytest.raises(SystemExit, match=r"not set up in .*nothing to upgrade; sudo tvgw adguard install"):
        cli.main([*conf, "adguard", "upgrade", "--fetch"])


def test_upgrade_fetch_downloads_nothing_when_the_pin_is_already_there(cli_conf, monkeypatch, capsys):
    from tvgw import cli

    conf, yaml_path = cli_conf
    set_up_at(yaml_path)
    monkeypatch.setattr(cli.os, "geteuid", lambda: 0)
    monkeypatch.setattr(adguardcfg, "binary_version", lambda exe: (0, 107, 80))

    def never(*a, **kw):
        raise AssertionError("downloaded")

    monkeypatch.setattr(aghinstall, "fetch_release", never)
    assert cli.main([*conf, "adguard", "upgrade", "--fetch"]) == 0
    assert (
        "AdGuard Home is v0.107.80; this tvgw pins v0.107.79, so there is nothing to fetch"
        in capsys.readouterr().out
    )


def test_upgrade_fetch_hands_the_checked_release_to_the_upgrade(cli_conf, monkeypatch, capsys):
    from tvgw import cli

    conf, yaml_path = cli_conf
    set_up_at(yaml_path)
    monkeypatch.setattr(cli.os, "geteuid", lambda: 0)
    monkeypatch.setattr(adguardcfg, "binary_version", lambda exe: (0, 107, 73))
    fetched, upgraded = [], []

    def fetch_release(dest):
        exe = Path(dest) / "stage" / "AdGuardHome" / "AdGuardHome"
        exe.parent.mkdir(parents=True)
        exe.write_bytes(BINARY)
        fetched.append(dest)
        return exe

    def upgrade(path, newbin, **kw):
        upgraded.append((newbin, Path(newbin).exists(), kw["floor"]))
        return ["binary: v0.107.73 -> v0.107.79", "backups: a, b"]

    monkeypatch.setattr(aghinstall, "fetch_release", fetch_release)
    monkeypatch.setattr(adguardcfg, "upgrade", upgrade)
    assert cli.main([*conf, "adguard", "upgrade", "--fetch"]) == 0
    out = capsys.readouterr().out
    assert "downloaded AdGuard Home v0.107.79, checked against its pinned SHA-256" in out
    assert "upgraded AdGuard Home\n  binary: v0.107.73 -> v0.107.79" in out
    ((newbin, existed, floor),) = upgraded
    assert newbin.startswith(fetched[0]) and existed and floor == FLOOR
    assert not Path(fetched[0]).exists()  # the temporary directory is gone afterwards

    def refused(dest):
        raise aghinstall.InstallError(
            "the downloaded AdGuard Home does not match tvgw's pinned hash; nothing was installed"
        )

    monkeypatch.setattr(aghinstall, "fetch_release", refused)
    with pytest.raises(SystemExit, match="does not match tvgw's pinned hash"):
        cli.main([*conf, "adguard", "upgrade", "--fetch"])
    monkeypatch.setattr(cli.os, "geteuid", lambda: 1000)
    with pytest.raises(SystemExit, match="run it as root"):
        cli.main([*conf, "adguard", "upgrade", "--fetch"])
