"""(updates) What the gateway installs on its own, what it asks GitHub and what it tells the owner (design
decision 77). Every request goes through a fake opener and every command through a fake runner: no test
here reaches the network or the system."""

import contextlib
import hashlib
import io
import json
import shutil
import sqlite3
import subprocess
import urllib.error
from dataclasses import replace
from pathlib import Path

import pytest
from conftest import NOW

from tvgw import db, ledger, updates
from tvgw.config import Settings

S = Settings()
DAY = 86400.0
REPO = "kywwilson11/tvgw"
AGH = updates.ADGUARD_REPO
AGH_TAR = "AdGuardHome_linux_arm64.tar.gz"
TAR_BYTES = b"adguard home release, arm64"
DEB_NEW, DEB_OLD = b"tvgw 0.4.0 package", b"tvgw 0.3.2 package"


def sha(b: bytes) -> str:
    return hashlib.sha256(b).hexdigest()


def release_json(
    repo: str,
    tag: str,
    assets: dict[str, bytes] | None = None,
    *,
    prerelease=False,
    draft=False,
    immutable=True,
    digests: dict[str, str] | None = None,
    published="2026-11-01T15:04:05Z",
) -> bytes:
    """GitHub's release object, cut to the fields tvgw reads, with each asset's digest as GitHub reports it."""
    out = []
    for name, data in (assets or {}).items():
        digest = (digests or {}).get(name, sha(data))
        out.append(
            {
                "name": name,
                "browser_download_url": f"https://github.com/{repo}/releases/download/{tag}/{name}",
                "digest": f"sha256:{digest}" if digest else None,
            }
        )
    return json.dumps(
        {
            "tag_name": tag,
            "prerelease": prerelease,
            "draft": draft,
            "immutable": immutable,
            "published_at": published,
            "body": "x" * 4000,
            "assets": out,
        }
    ).encode()


class FakeHttp:
    """URL -> bytes, an exception to raise, or nothing (a 404). Every URL asked is kept, in order."""

    def __init__(self, answers: dict[str, object] | None = None):
        self.answers = dict(answers or {})
        self.asked: list[str] = []

    def __call__(self, url, timeout):
        self.asked.append(url)
        got = self.answers.get(url)
        if isinstance(got, BaseException):
            raise got
        if got is None:
            raise urllib.error.HTTPError(url, 404, "Not Found", {}, None)
        return contextlib.closing(io.BytesIO(got))


def api(repo: str, which: str = "latest") -> str:
    return updates.API.format(repo=repo, which=which)


def asset_url(repo: str, tag: str, name: str) -> str:
    return f"https://github.com/{repo}/releases/download/{tag}/{name}"


def store(tmp_path) -> sqlite3.Connection:
    return db.connect(str(tmp_path / "tvgw.db"))


# ---- versions ----------------------------------------------------------------------------------------
@pytest.mark.parametrize(
    "text, want",
    [
        ("v0.4.0", ((0, 4, 0), False)),
        ("0.10.0", ((0, 10, 0), False)),
        ("v0.107.81", ((0, 107, 81), False)),
        ("v0.4.0-rc.1", ((0, 4, 0), True)),
        ("v1.0.0-b.2", ((1, 0, 0), True)),
        ("0.4", None),
        ("latest", None),
        ("v0.4.0 ; rm -rf /", None),
        ("", None),
    ],
)
def test_a_version_is_three_numbers_and_a_suffix_marks_a_pre_release(text, want):
    assert updates.parse_version(text) == want


def test_versions_compare_as_numbers_so_ten_is_newer_than_nine():
    assert updates.parse_version("0.10.0")[0] > updates.parse_version("0.9.9")[0]
    assert updates.upstream("0.3.2-1") == "0.3.2" and updates.upstream("0.3.2") == "0.3.2"


# ---- a release, as GitHub describes it -----------------------------------------------------------------
def test_a_release_keeps_only_this_repositorys_own_downloads_and_githubs_digest():
    raw = json.loads(release_json(REPO, "v0.4.0", {"SHA256SUMS": b"x"}))
    raw["assets"].append({"name": "evil.deb", "browser_download_url": "https://example.com/evil.deb"})
    raw["assets"].append(
        {"name": "odd", "browser_download_url": asset_url(REPO, "v0.4.0", "odd"), "digest": "md5:1"}
    )
    rel = updates.parse_release(json.dumps(raw).encode(), REPO)
    assert rel.version == (0, 4, 0) and not rel.prerelease and rel.immutable
    assert set(rel.assets) == {"SHA256SUMS", "odd"} and rel.assets["odd"].digest is None
    assert rel.assets["SHA256SUMS"].digest == sha(b"x")


@pytest.mark.parametrize(
    "raw, why",
    [
        (b"<html>rate limited</html>", "not JSON"),
        (b"[]", "not a release"),
        (
            json.dumps({"tag_name": "nightly", "published_at": "2026-11-01T00:00:00Z"}).encode(),
            "not a version",
        ),
        (release_json(REPO, "v0.4.0", draft=True), "a draft"),
        (release_json(REPO, "v0.4.0", published="yesterday"), "no publication time"),
    ],
)
def test_a_malformed_answer_is_a_failed_check_in_fixed_words(raw, why):
    with pytest.raises(updates.CheckError, match=why):
        updates.parse_release(raw, REPO)


def test_a_pre_release_is_marked_by_githubs_flag_or_its_tag():
    assert updates.parse_release(release_json(REPO, "v0.4.0", prerelease=True), REPO).prerelease
    assert updates.parse_release(release_json(REPO, "v0.4.0-rc.1"), REPO).prerelease


@pytest.mark.parametrize(
    "answer, why",
    [
        (b"x" * (updates.MAX_RELEASE + 1), "over 1024 KB"),
        (TimeoutError("timed out"), "did not answer in time"),
        (urllib.error.URLError(TimeoutError("timed out")), "did not answer in time"),
        (urllib.error.URLError("Name or service not known"), "could not be reached"),
        (None, "answered HTTP 404"),
    ],
)
def test_an_oversized_timed_out_or_missing_answer_is_a_failed_check(answer, why):
    http = FakeHttp({api(REPO): answer})
    with pytest.raises(updates.CheckError, match=why):
        updates.fetch_release(REPO, http)
    assert http.asked == [api(REPO)]  # one request, never a retry


def test_the_request_carries_the_user_agent_and_the_apis_two_headers_and_nothing_else(monkeypatch):
    seen = {}

    class Opener:
        def open(self, req, timeout):
            seen.update(url=req.full_url, headers=dict(req.header_items()), timeout=timeout)
            return contextlib.closing(io.BytesIO(b"{}"))

    monkeypatch.setattr(updates, "_OPENER", Opener())
    updates.open_url(api(REPO), 20)
    assert seen["url"] == "https://api.github.com/repos/kywwilson11/tvgw/releases/latest"
    assert {k.lower(): v for k, v in seen["headers"].items()} == {
        "user-agent": f"tvgw/{updates.__version__}",
        "accept": "application/vnd.github+json",
        "x-github-api-version": "2022-11-28",
    }
    updates.open_url(asset_url(REPO, "v0.4.0", "SHA256SUMS"), 20)  # a download: the User-Agent alone
    assert {k.lower() for k in seen["headers"]} == {"user-agent"}
    with pytest.raises(updates.CheckError, match="https"):
        updates.open_url("http://api.github.com/x", 20)


def test_a_redirect_away_from_https_is_refused():
    handler = updates._HttpsOnly()
    with pytest.raises(urllib.error.HTTPError):
        handler.redirect_request(None, None, 302, "Found", {}, "http://example.com/x")


# ---- the weekly check ----------------------------------------------------------------------------------
def test_the_weekly_check_stores_the_version_its_date_and_the_time_and_nothing_else(tmp_path):
    conn = store(tmp_path)
    http = FakeHttp({api(REPO): release_json(REPO, "v0.4.0", {"tvgw_0.4.0-1_arm64.deb": b"d"})})
    row = updates.weekly_check(S, conn, NOW, http)
    assert row == {
        "t": NOW,
        "ok": True,
        "latest": "0.4.0",
        "published": "2026-11-01T15:04:05Z",
        "seen_t": NOW,
        "failures": 0,
    }
    assert json.loads(db.get_meta(conn, updates.META_CHECK)) == row
    # within the week: no request at all
    assert updates.weekly_check(S, conn, NOW + 6 * DAY, http) == row and len(http.asked) == 1
    # a week on, the same version keeps the day it was first seen
    row2 = updates.weekly_check(S, conn, NOW + 7 * DAY, http)
    assert row2["seen_t"] == NOW and row2["t"] == NOW + 7 * DAY and len(http.asked) == 2


def test_a_failed_check_is_remembered_counted_and_waits_its_week(tmp_path):
    conn = store(tmp_path)
    good = FakeHttp({api(REPO): release_json(REPO, "v0.4.0")})
    updates.weekly_check(S, conn, NOW, good)
    bad = FakeHttp({api(REPO): TimeoutError()})
    t = NOW
    for n in (1, 2, 3, 4):
        t += 7 * DAY
        row = updates.weekly_check(S, conn, t, bad)
        assert row["failures"] == n and not row["ok"] and row["latest"] == "0.4.0"
        assert updates.weekly_check(S, conn, t + DAY, bad)["failures"] == n  # no retry the next day
    assert len(bad.asked) == 4
    assert row["why"] == "GitHub did not answer in time"


def test_a_settings_file_without_the_keys_never_makes_a_request(tmp_path):
    """Decision 53, item 6: an old file means what it meant; the timer's command says so and asks nobody."""
    said = []
    env = fake_env(tmp_path, http=Exploding(), say=said.append)
    assert updates.scheduled(S, env) == 0
    assert env.calls == [] and env.stored == [] and "nothing asked" in said[0]


class Exploding:
    def __call__(self, url, timeout):
        raise AssertionError(f"a request was made: {url}")


def test_the_timers_command_with_the_check_on_and_installs_off_makes_one_request_and_installs_nothing(
    tmp_path,
):
    s = replace(S, update_check="weekly")
    http = FakeHttp({api(REPO): release_json(REPO, "v0.4.0")})
    env = fake_env(tmp_path, http=http)
    assert updates.scheduled(s, env) == 0
    assert http.asked == [api(REPO)] and env.calls == []


# ---- the system's own updates --------------------------------------------------------------------------
DEBIAN_13 = """NOTE: This is only a simulation!
      apt-get needs root privileges for real execution.
Reading package lists...
Building dependency tree...
Reading state information...
Calculating upgrade...
The following packages will be upgraded:
  libssl3t64 openssl tzdata
3 upgraded, 0 newly installed, 0 to remove and 0 not upgraded.
Inst libssl3t64 [3.5.1-1] (3.5.1-1+deb13u1 Debian-Security:13/stable-security [arm64])
Inst openssl [3.5.1-1] (3.5.1-1+deb13u1 Debian-Security:13/stable-security [arm64])
Inst tzdata [2025b-4] (2025b-4+deb13u1 Debian:13.2/stable [all])
Conf libssl3t64 (3.5.1-1+deb13u1 Debian-Security:13/stable-security [arm64])
Conf openssl (3.5.1-1+deb13u1 Debian-Security:13/stable-security [arm64])
Conf tzdata (2025b-4+deb13u1 Debian:13.2/stable [all])
"""
RPI_OS = """Reading package lists...
Calculating upgrade...
Inst linux-image-rpi-2712 [1:6.12.47-1+rpt1] (1:6.12.62-1+rpt1 Raspberry Pi Foundation:stable [arm64])
Inst raspi-config [20250707] (20251017 Raspberry Pi Foundation:stable [all])
Inst libc6 [2.41-12] (2.41-12+deb13u1 Debian:13.2/stable, Debian-Security:13/stable-security [arm64]) []
Inst nginx-common [1.26.3-3] (1.26.3-3+deb13u1 Debian:13.2/stable [all])
4 upgraded, 0 newly installed, 0 to remove and 0 not upgraded.
"""
UBUNTU = """Inst libssl3t64 [3.0.13-0ubuntu3.4] (3.0.13-0ubuntu3.5 Ubuntu:24.04/noble-updates, Ubuntu:24.04/noble-security [arm64])
Inst snapd [2.66] (2.67 Ubuntu:24.04/noble-updates [arm64])
Inst newdep (1.0 Ubuntu:24.04/noble-security [arm64])
2 upgraded, 1 newly installed, 0 to remove and 0 not upgraded.
"""


@pytest.mark.parametrize(
    "text, every, security",
    [
        (DEBIAN_13, 3, 2),
        (RPI_OS, 4, 3),  # the Pi's kernel and raspi-config come from Raspberry Pi's archive: security
        (UBUNTU, 3, 2),
        ("Reading package lists...\n0 upgraded, 0 newly installed, 0 to remove and 0 not upgraded.\n", 0, 0),
    ],
)
def test_apts_simulation_says_what_waits_and_what_of_it_is_for_security(text, every, security):
    waiting, sec = updates.parse_apt_sim(text)
    assert (len(waiting), len(sec)) == (every, security)


def test_the_reading_is_taken_once_a_day_or_when_the_lists_or_dpkg_changed():
    runs = []

    def run(argv):
        runs.append(argv)
        return DEBIAN_13

    times = {updates.LISTS: NOW - 3 * DAY}
    first, new = updates.system_state(None, run, NOW, times.get, lambda p: [])
    assert new and first == {"t": NOW, "waiting": 3, "security": 2, "lists_t": NOW - 3 * DAY, "since": NOW}
    assert runs == [list(updates.APT_SIM)]
    again, new = updates.system_state(first, run, NOW + 3600, times.get, lambda p: [])
    assert not new and again is first and len(runs) == 1  # the 10-minute verify asks apt nothing
    times[updates.DPKG_STATUS] = NOW + 7200  # a package was installed: read again, keep the first sighting
    third, new = updates.system_state(first, run, NOW + 3 * 3600, times.get, lambda p: [])
    assert new and third["since"] == NOW and len(runs) == 2
    later, new = updates.system_state(third, run, NOW + 2 * DAY, times.get, lambda p: [])
    assert new and later["since"] == NOW  # a day later: read again, still waiting since the first
    cleared, _ = updates.system_state(
        later,
        lambda argv: "0 upgraded, 0 newly installed, 0 to remove and 0 not upgraded.\n",
        NOW + 3 * DAY,
        times.get,
        lambda p: [],
    )
    assert cleared["security"] == 0 and cleared["since"] is None


def test_the_simulation_locks_nothing_and_writes_no_cache():
    argv = " ".join(updates.APT_SIM)
    assert argv.startswith("env LC_ALL=C apt-get -s ") and "Debug::NoLocking=1" in argv
    assert "Dir::Cache::pkgcache=" in argv and "Dir::Cache::srcpkgcache=" in argv


def test_the_lists_age_is_the_newest_of_the_directory_its_release_files_and_apts_stamp():
    times = {updates.LISTS: 100.0, updates.UPDATE_STAMP: 300.0, "/var/lib/apt/lists/x_InRelease": 200.0}
    assert updates.lists_time(times.get, lambda p: ["/var/lib/apt/lists/x_InRelease"]) == 300.0
    assert updates.lists_time({}.get, lambda p: []) is None


def test_no_apt_or_an_unfinished_simulation_is_no_reading_and_keeps_the_first_sighting():
    assert updates.read_system(lambda argv: "", NOW) is None
    half = "Reading package lists...\nE: The package lists or status file could not be parsed or opened.\n"
    stored = {
        "t": NOW - 2 * DAY,
        "waiting": 3,
        "security": 2,
        "lists_t": NOW - 3 * DAY,
        "since": NOW - 2 * DAY,
    }
    got, new = updates.system_state(stored, lambda argv: half, NOW, {}.get, lambda p: [])
    assert got is stored and not new


# ---- unattended-upgrades as tvgw configures it ---------------------------------------------------------
def dump_of(conf: str) -> str:
    """`apt-config dump` of a system whose only configuration is `conf`: what apt would print."""
    out = []
    for line in conf.splitlines():
        line = line.strip()
        if line.startswith(("//", "#clear")) or not line:
            continue
        if line.startswith("Dpkg::Options"):
            out += [
                'Dpkg::Options "";',
                'Dpkg::Options:: "--force-confdef";',
                'Dpkg::Options:: "--force-confold";',
            ]
        elif line.endswith("{"):
            out.append(f'{line.split()[0]} "";')
        elif line.startswith('"'):
            out.append(f"Unattended-Upgrade::Origins-Pattern:: {line.rstrip(';')};")
        elif line != "};":
            out.append(line)
    return "\n".join(out) + "\n"


@pytest.mark.parametrize("mode", ["security", "all"])
def test_the_configuration_tvgw_writes_reads_back_as_tvgws(mode):
    conf = updates.apt_conf(mode)
    assert updates.apt_conf_problems(dump_of(conf), mode) == []
    assert '"origin=Debian,codename=${distro_codename}-security,label=Debian-Security";' in conf
    assert "Raspberry Pi Foundation" in conf
    assert ('label=Debian";' in conf) == (mode == "all")  # the point releases only with all
    for line in (
        'APT::Periodic::Unattended-Upgrade "0";',
        'Unattended-Upgrade::Automatic-Reboot "false";',
        'Unattended-Upgrade::Remove-Unused-Dependencies "false";',
        'Unattended-Upgrade::Mail "";',
        "#clear Unattended-Upgrade::Origins-Pattern;",
        "#clear Unattended-Upgrade::Allowed-Origins;",
    ):
        assert line in conf, line  # fmt: skip


@pytest.mark.skipif(shutil.which("apt-config") is None, reason="apt itself, on a Debian-family system")
@pytest.mark.parametrize("mode", ["security", "all"])
def test_apt_itself_reads_the_configuration_as_tvgw_wrote_it_over_the_systems_own(tmp_path, mode):
    """The real apt, on CI's Ubuntu runner (whose unattended-upgrades has origins of its own) and in the
    distro tier: it parses the file, and its dump, read back, is tvgw's whatever the system had before."""
    conf = tmp_path / "90tvgw-updates"
    conf.write_text(updates.apt_conf(mode), encoding="utf-8")
    out = subprocess.run(["apt-config", "-c", str(conf), "dump"], capture_output=True, text=True, timeout=60)
    assert out.returncode == 0, out.stderr
    assert updates.apt_conf_problems(out.stdout, mode) == []


def test_off_writes_no_configuration_and_checks_none():
    assert updates.apt_conf("off") is None and updates.apt_conf_problems("", "off") == []


@pytest.mark.parametrize(
    "change, problem",
    [
        (
            lambda d: d.replace('Automatic-Reboot "false"', 'Automatic-Reboot "true"'),
            "Automatic-Reboot is 'true'",
        ),
        (
            lambda d: d.replace('Periodic::Unattended-Upgrade "0"', 'Periodic::Unattended-Upgrade "1"'),
            "'1', not '0'",
        ),
        (
            lambda d: d.replace('Dpkg::Options:: "--force-confold";\n', ""),
            "could stop an update with a question",
        ),
        (
            lambda d: d + 'Unattended-Upgrade::Allowed-Origins:: "${distro_id}:${distro_codename}";\n',
            "Allowed",
        ),
        (lambda d: d + 'Unattended-Upgrade::Origins-Pattern:: "origin=*";\n', "origins"),
        (lambda d: "", "could not be read"),
    ],
)
def test_a_change_to_the_effective_configuration_is_named(change, problem):
    dump = change(dump_of(updates.apt_conf("all")))
    assert any(problem in p for p in updates.apt_conf_problems(dump, "all")), updates.apt_conf_problems(
        dump, "all"
    )


@pytest.mark.parametrize(
    "window, at, delay",
    [("03:30-05:30", "03:30", 75), ("23:00-01:00", "23:00", 75), ("02:00-02:30", "02:00", 0)],
)
def test_the_timer_starts_in_the_window_and_leaves_time_for_the_run(window, at, delay):
    text = updates.timer_dropin(window)
    assert text == f"[Timer]\nOnCalendar=\nOnCalendar=*-*-* {at}:00\nRandomizedDelaySec={delay}min\n"


def test_configure_writes_both_files_and_off_removes_apts(tmp_path):
    files = {}
    lines = updates.configure(replace(S, update_install="security"), files.__setitem__, files.pop)
    assert set(files) == {updates.APT_CONF, updates.TIMER_DROPIN} and len(lines) == 2
    updates.configure(S, files.__setitem__, lambda p: files.pop(p, None))
    assert set(files) == {updates.TIMER_DROPIN}


# ---- the installs ----------------------------------------------------------------------------------------
def fake_env(tmp_path, **kw) -> updates.Env:
    """A gateway with nothing waiting: every command answers as on a quiet night, unless `run` says."""
    calls: list[list[str]] = []
    stored: list[dict] = []
    files: dict[str, str] = kw.pop("files", {})
    tmp_path.mkdir(parents=True, exist_ok=True)
    conn = store(tmp_path)
    spool: list[list[str]] = []
    order: list[str] = []
    answers = kw.pop("answers", {})

    def run(argv, timeout=60, env=None):
        calls.append(list(argv))
        words = argv[2:] if argv[0] == "env" else argv  # apt's simulation runs under env LC_ALL=C
        key = words[0] if words[0] != "apt-get" else " ".join(words[:3])
        got = answers.get(key, (0, ""))
        return got(argv) if callable(got) else got

    def do_store(fn):
        out = fn(conn)
        conn.commit()
        stored.append(fn)
        order.append("store")
        return out

    def reboot():
        order.append("reboot")

    e = updates.Env(
        run=kw.pop("run", run),
        http=kw.pop("http", FakeHttp()),
        quiet=kw.pop("quiet", lambda: True),
        verify=kw.pop("verify", lambda: []),
        exists=kw.pop("exists", lambda p: p in files),
        read=lambda p: files[p],
        write=lambda p, text: (files.__setitem__(p, text), order.append(f"write {Path(p).name}")),
        remove=lambda p: files.pop(p, None),
        store=do_store,
        spool=lambda fields: (spool.append(fields), order.append("spool")),
        reboot=kw.pop("reboot", reboot),
        lock=lambda: contextlib.nullcontext(),
        adguard_version=kw.pop("adguard_version", lambda: (0, 107, 80)),
        adguard_upgrade=kw.pop("adguard_upgrade", lambda newbin: ["binary: v0.107.80 -> v0.107.81"]),
        adguard_extract=kw.pop("adguard_extract", lambda tar, stage, floor: Path(stage) / "AdGuardHome"),
        arch=lambda: "arm64",
        installed=kw.pop("installed", lambda: ("source", "")),
        now=lambda: NOW,
        say=kw.pop("say", lambda line: None),
        tmpdir=lambda: contextlib.nullcontext(str(tmp_path / "work")),
    )
    (tmp_path / "work").mkdir(exist_ok=True)
    e.calls, e.stored, e.files, e.conn, e.spooled, e.order = calls, stored, files, conn, spool, order
    assert not kw, kw
    return e


def dpkg_lists(before: str, after: str):
    seen = []

    def answer(argv):
        seen.append(1)
        return 0, before if len(seen) == 1 else after

    return answer


def test_a_night_with_system_updates_installs_them_counts_the_security_ones_and_checks_after(tmp_path):
    before = "libssl3t64\t3.5.1-1\nopenssl\t3.5.1-1\ntzdata\t2025b-4\nbash\t5.2\n"
    after = "libssl3t64\t3.5.1-1+deb13u1\nopenssl\t3.5.1-1+deb13u1\ntzdata\t2025b-4+deb13u1\nbash\t5.2\n"
    env = fake_env(
        tmp_path,
        files={updates.UNATTENDED: ""},
        answers={"apt-get -s -q": (0, DEBIAN_13), "dpkg-query": dpkg_lists(before, after)},
    )
    run = updates.install(replace(S, update_install="security"), env, "night")
    assert run["system"] == {
        "outcome": "installed", "count": 3, "security": 2, "names": ["libssl3t64", "openssl", "tzdata"],
    }  # fmt: skip
    assert run["verify"] == "held" and run["result"] == "installed" and "tvgw" not in run
    assert ["apt-get", "-q", "update"] in env.calls and [updates.UNATTENDED, "-v"] in env.calls
    assert env.spooled == [["update", "installed", "system", "3"]]
    assert updates.load_runs(env.conn) == [run]
    assert "unattended" not in updates.run_sentence(run)  # plain words, no internals
    assert updates.run_sentence(run, "") == (
        "The gateway installed 3 system updates (2 for security); its checks held afterwards."
    )


def test_unattended_upgrades_missing_installs_nothing_of_the_systems(tmp_path):
    env = fake_env(tmp_path)
    run = updates.install(replace(S, update_install="security"), env, "night")
    assert run["system"] == {"outcome": "skipped", "why": "unattended-upgrades is not installed"}
    assert not any(c[0] in (updates.UNATTENDED, "apt-get") for c in env.calls)


def adguard_http(tag="v0.107.81", tar=TAR_BYTES, sums=None, digests=None):
    sums = (
        sums
        if sums is not None
        else f"{sha(TAR_BYTES)}  {AGH_TAR}\n{'0' * 64}  AdGuardHome_linux_amd64.tar.gz\n"
    )
    rel = release_json(AGH, tag, {AGH_TAR: TAR_BYTES, "checksums.txt": sums.encode()}, digests=digests)
    return FakeHttp(
        {
            api(AGH): rel,
            asset_url(AGH, tag, "checksums.txt"): sums.encode(),
            asset_url(AGH, tag, AGH_TAR): tar,
        }
    )


def test_a_newer_adguard_patch_is_checked_two_ways_and_installed_through_the_upgrade_path(tmp_path):
    got = {}
    http = adguard_http()
    env = fake_env(
        tmp_path,
        http=http,
        adguard_extract=lambda tar, stage, floor: (
            got.update(tar=tar.read_bytes(), floor=floor),
            stage / "bin",
        )[1],
        adguard_upgrade=lambda newbin: (got.update(newbin=newbin), [])[1],
    )
    run = updates.install(replace(S, update_install="security"), env, "night")
    assert run["adguard"] == {"outcome": "installed", "before": "0.107.80", "after": "0.107.81"}
    assert got["tar"] == TAR_BYTES and got["floor"] == (0, 107, 81) and got["newbin"].endswith("bin")
    assert ["update", "installed", "adguard", "0.107.81"] in env.spooled


def test_a_newer_adguard_minor_version_is_held_for_the_owner_and_nothing_is_downloaded(tmp_path):
    http = adguard_http(tag="v0.108.0")
    env = fake_env(tmp_path, http=http, adguard_upgrade=lambda newbin: pytest.fail("upgraded"))
    run = updates.install(replace(S, update_install="security"), env, "night")
    assert run["adguard"]["outcome"] == "held" and "larger change" in run["adguard"]["why"]
    assert http.asked == [api(AGH)]


@pytest.mark.parametrize(
    "http, why",
    [
        (adguard_http(tar=b"tampered"), "does not match its checksum"),
        (adguard_http(digests={AGH_TAR: "1" * 64}), "disagree"),
        (adguard_http(sums=f"{'2' * 64}  AdGuardHome_linux_amd64.tar.gz\n"), "has no line for"),
    ],
)
def test_an_adguard_release_that_fails_its_checksums_installs_nothing(tmp_path, http, why):
    env = fake_env(tmp_path, http=http, adguard_upgrade=lambda newbin: pytest.fail("upgraded"))
    run = updates.install(replace(S, update_install="security"), env, "night")
    assert run["adguard"]["outcome"] == "skipped" and why in run["adguard"]["why"]
    assert not list((tmp_path / "work" / "adguard").glob("*.tar.gz*"))  # nothing left of the download
    assert env.spooled == []


def test_an_adguard_upgrade_that_fails_its_checks_is_put_back_and_said(tmp_path):
    def fails(newbin):
        raise RuntimeError("tvgw verify fails on the new binary: resolver_must_allow; the previous binary"
                           " (x.bak) and config were put back")  # fmt: skip

    env = fake_env(tmp_path, http=adguard_http(), adguard_upgrade=fails)
    run = updates.install(replace(S, update_install="security"), env, "night")
    assert run["adguard"]["outcome"] == "rolled_back" and run["result"] == "rolled_back"
    assert ["update", "rolled_back", "adguard", "0.107.81"] in env.spooled
    assert (
        "AdGuard Home 0.107.81 failed the gateway's checks, so 0.107.80 was put back"
        in updates.run_sentence(run)
    )


def test_an_adguard_held_back_by_its_upstreams_waits(tmp_path):
    from tvgw import adguardcfg

    def deferred(newbin):
        raise adguardcfg.Deferred("deferred: upstream down")

    env = fake_env(tmp_path, http=adguard_http(), adguard_upgrade=deferred)
    run = updates.install(replace(S, update_install="security"), env, "night")
    assert run["adguard"]["outcome"] == "waited" and env.spooled == []


# ---- tvgw's own package --------------------------------------------------------------------------------
def tvgw_http(immutable=True, old=True, new_bytes=DEB_NEW):
    new_deb, old_deb = "tvgw_0.4.0-1_arm64.deb", "tvgw_0.3.2-1_arm64.deb"
    sums_new = f"{sha(DEB_NEW)}  {new_deb}\n".encode()
    sums_old = f"{sha(DEB_OLD)}  {old_deb}\n".encode()
    answers = {
        api(REPO): release_json(
            REPO, "v0.4.0", {new_deb: DEB_NEW, "SHA256SUMS": sums_new}, immutable=immutable
        ),
        asset_url(REPO, "v0.4.0", "SHA256SUMS"): sums_new,
        asset_url(REPO, "v0.4.0", new_deb): new_bytes,
        api(AGH): release_json(AGH, "v0.107.80"),
    }
    if old:
        answers[api(REPO, "tags/v0.3.2")] = release_json(
            REPO, "v0.3.2", {old_deb: DEB_OLD, "SHA256SUMS": sums_old}
        )
        answers[asset_url(REPO, "v0.3.2", "SHA256SUMS")] = sums_old
        answers[asset_url(REPO, "v0.3.2", old_deb)] = DEB_OLD
    return FakeHttp(answers)


def all_mode(tmp_path):
    return replace(S, update_install="all", state_dir=str(tmp_path / "state"))


def apt_installs(env) -> list[list[str]]:
    return [c for c in env.calls if c[:2] == ["apt-get", "install"]]


def test_a_source_checkout_is_never_updated_by_the_gateway(tmp_path):
    env = fake_env(tmp_path, http=tvgw_http())
    run = updates.install(all_mode(tmp_path), env, "night")
    assert run["tvgw"]["outcome"] == "skipped" and "source checkout" in run["tvgw"]["why"]
    assert apt_installs(env) == [] and api(REPO) not in env.http.asked


def test_a_release_that_can_still_be_changed_is_not_installed(tmp_path):
    env = fake_env(tmp_path, http=tvgw_http(immutable=False), installed=lambda: ("package", "0.3.2-1"))
    run = updates.install(all_mode(tmp_path), env, "night")
    assert run["tvgw"]["outcome"] == "held" and apt_installs(env) == []
    assert json.loads(db.get_meta(env.conn, updates.META_CHECK))["latest"] == "0.4.0"  # still a notice


def test_a_newer_package_is_installed_judged_by_verify_and_kept_for_next_time(tmp_path):
    s = all_mode(tmp_path)
    env = fake_env(tmp_path, http=tvgw_http(), installed=lambda: ("package", "0.3.2-1"))
    run = updates.install(s, env, "night")
    assert run["tvgw"] == {"outcome": "installed", "before": "0.3.2", "after": "0.4.0"}
    (install,) = apt_installs(env)
    assert install[-1].endswith("tvgw_0.4.0-1_arm64.deb") and "--allow-downgrades" not in install
    assert "Dpkg::Options::=--force-confold" in install
    kept = sorted(p.name for p in (Path(s.state_dir) / updates.PACKAGES).iterdir())
    assert kept == ["tvgw_0.4.0-1_arm64.deb"]  # the next run's way back; the older one goes
    assert ["update", "installed", "tvgw", "0.4.0"] in env.spooled


def test_a_package_that_fails_verify_is_replaced_by_the_kept_one(tmp_path):
    s = all_mode(tmp_path)
    verdicts = iter([["resolver_must_allow"], []])
    env = fake_env(
        tmp_path, http=tvgw_http(), installed=lambda: ("package", "0.3.2-1"), verify=lambda: next(verdicts)
    )
    run = updates.install(s, env, "night")
    assert (
        run["tvgw"]["outcome"] == "rolled_back" and "verify failed: resolver_must_allow" in run["tvgw"]["why"]
    )
    new, back = apt_installs(env)
    assert new[-1].endswith("tvgw_0.4.0-1_arm64.deb")
    assert back[-1] == str(Path(s.state_dir) / updates.PACKAGES / "tvgw_0.3.2-1_arm64.deb")
    assert "--allow-downgrades" in back and Path(back[-1]).read_bytes() == DEB_OLD
    assert ["update", "rolled_back", "tvgw", "0.4.0"] in env.spooled


def test_a_package_apt_refuses_is_replaced_by_the_kept_one_without_asking_verify(tmp_path):
    answers = {"apt-get install -y": lambda argv: (100, "") if "--allow-downgrades" not in argv else (0, "")}
    env = fake_env(
        tmp_path,
        http=tvgw_http(),
        installed=lambda: ("package", "0.3.2-1"),
        answers=answers,
        verify=lambda: [],
    )
    run = updates.install(all_mode(tmp_path), env, "night")
    assert run["tvgw"]["outcome"] == "rolled_back" and run["tvgw"]["why"].startswith(
        "apt stopped with status 100"
    )


def test_no_way_back_means_no_install(tmp_path):
    env = fake_env(tmp_path, http=tvgw_http(old=False), installed=lambda: ("package", "0.3.2-1"))
    run = updates.install(all_mode(tmp_path), env, "night")
    assert run["tvgw"]["outcome"] == "skipped" and apt_installs(env) == []


def test_a_tampered_package_installs_nothing(tmp_path):
    env = fake_env(tmp_path, http=tvgw_http(new_bytes=b"evil"), installed=lambda: ("package", "0.3.2-1"))
    run = updates.install(all_mode(tmp_path), env, "night")
    assert run["tvgw"]["outcome"] == "skipped" and "does not match" in run["tvgw"]["why"]
    assert apt_installs(env) == []


def test_security_mode_never_asks_about_tvgw(tmp_path):
    env = fake_env(tmp_path, http=tvgw_http(), installed=lambda: ("package", "0.3.2-1"))
    run = updates.install(replace(S, update_install="security"), env, "night")
    assert "tvgw" not in run and api(REPO) not in env.http.asked


# ---- the restart -----------------------------------------------------------------------------------------
def test_a_restart_comes_only_at_night_while_the_tv_is_quiet_and_after_the_record(tmp_path):
    s = replace(S, update_install="security", state_dir=str(tmp_path))
    env = fake_env(
        tmp_path, files={updates.REBOOT_FLAG: "", updates.REBOOT_FLAG + ".pkgs": "linux-image\nlibc6\n"}
    )
    run = updates.install(s, env, "night")
    assert run["reboot"] == "done" and env.order[-1] == "reboot"
    assert env.order.index("store") < env.order.index("reboot")  # what it did is stored first
    assert json.loads(env.files[str(tmp_path / updates.REBOOT_MARKER)]) == {"t": NOW, "packages": 2}
    assert ["update", "reboot", "system", "2"] in env.spooled


def test_no_restart_when_the_tv_woke_meanwhile_or_the_owner_ran_it(tmp_path):
    s = replace(S, update_install="security", state_dir=str(tmp_path))
    flags = {updates.REBOOT_FLAG: ""}
    for trigger, quiet in (("night", False), ("owner", True)):
        env = fake_env(tmp_path / trigger, files=dict(flags), quiet=lambda q=quiet: q,
                       reboot=lambda: pytest.fail("restarted"))  # fmt: skip
        run = updates.install(s, env, trigger)
        assert run["reboot"] == "needed" and "a restart is still needed" in updates.run_sentence(run)


def test_after_the_restart_verify_is_recorded_and_the_marker_goes(tmp_path):
    s = replace(S, state_dir=str(tmp_path))
    marker = str(tmp_path / updates.REBOOT_MARKER)
    env = fake_env(tmp_path, files={marker: "{}"}, verify=lambda: ["ingest_fresh"])
    run = updates.after_reboot(s, env)
    assert run["result"] == "failed" and run["verify"] == "failed: ingest_fresh"
    assert marker not in env.files and env.spooled == [["update", "verified", "reboot", "failed"]]
    assert "found trouble (ingest_fresh)" in updates.run_sentence(run)
    assert updates.after_reboot(s, fake_env(tmp_path / "none")) is None


# ---- the timer's run -------------------------------------------------------------------------------------
def test_a_night_the_tv_is_in_use_installs_nothing_and_says_why_only_when_something_waits(tmp_path):
    s = replace(S, update_install="all")
    env = fake_env(tmp_path, quiet=lambda: False, http=Exploding())
    assert updates.scheduled(s, env) == 0
    assert env.calls == [] and updates.load_runs(env.conn) == []  # nothing known waits: nothing said
    db.set_meta(env.conn, updates.META_SYSTEM, json.dumps({"t": NOW, "waiting": 2, "security": 1}))
    env.conn.commit()
    updates.scheduled(s, env)
    (run,) = updates.load_runs(env.conn)
    assert run["result"] == "waited" and run["system"] == {"outcome": "waited", "count": 2, "security": 1}
    assert (
        updates.run_sentence(run, "")
        == "The gateway waited: the TV was in use, or the night window had passed."
    )


def test_settling_failures_are_asked_again_and_any_other_failure_stands_at_once():
    from tvgw import verify

    slept = []
    answers = iter(
        [{"checks": [{"name": "list_sentinels", "ok": False}]}, {"checks": [{"name": "x", "ok": True}]}]
    )
    assert updates.settled_failures(lambda: next(answers), slept.append) == [] and slept == [
        updates.SETTLE_STEP
    ]
    slept.clear()
    stuck = {"checks": [{"name": "services", "ok": False}]}
    assert updates.settled_failures(lambda: stuck, slept.append) == ["services"]
    assert sum(slept) == updates.SETTLE_WAIT and "services" in verify.SETTLING
    real = {"checks": [{"name": "ruleset", "ok": False}, {"name": "services", "ok": False}]}
    assert updates.settled_failures(lambda: real, pytest.fail) == ["ruleset", "services"]
    assert updates.settled_failures(lambda: {}, pytest.fail) == ["verify"]  # it printed nothing to read


# ---- the ledger --------------------------------------------------------------------------------------------
@pytest.mark.parametrize(
    "line, kind, cls",
    [
        ("update\tinstalled\tsystem\t12", "update_installed", "A"),
        ("update\tinstalled\tadguard\t0.107.81", "update_installed", "A"),
        ("update\trolled_back\ttvgw\t0.4.0", "update_rolled_back", "A"),
        ("update\treboot\tsystem\t2", "update_reboot", "A"),
        ("update\tverified\treboot\tok", "update_verified", "B"),
    ],
)
def test_each_spool_line_is_a_ledger_row_of_the_gateway(line, kind, cls):
    c = ledger._spool_row([str(NOW), *line.split("\t")], S, None)
    assert c.kind == kind and ledger.KINDS[kind][0] == cls and kind in ledger.GROUPS["Gateway"]
    assert ledger._spool_row([str(NOW), "update", "installed", "kernel", "1"], S, None) is None


# ---- what the owner reads ----------------------------------------------------------------------------------
def test_the_report_names_each_command_the_owner_needs():
    sys_ = {"t": NOW, "waiting": 3, "security": 1, "lists_t": NOW - 20 * DAY, "since": NOW - 9 * DAY}
    check = {
        "t": NOW - DAY,
        "ok": True,
        "latest": "0.4.0",
        "published": "2026-11-01T15:04:05Z",
        "seen_t": NOW - DAY,
    }
    rep = updates.report(S, NOW, check, sys_, [], "package", "0.3.2", (0, 107, 79), None)
    tvgw, agh, system = rep.lines
    assert "0.3.2 installed; the latest release is 0.4.0" in tvgw and "TVGW_NO_SETUP=1 sh" in tvgw
    assert "older. Run: sudo tvgw adguard upgrade --fetch" in agh
    assert (
        "1 of them for security, waiting since" in system
        and "has not looked for system updates since" in system
    )
    assert "sudo apt update && sudo apt upgrade" in system
    auto = updates.report(replace(S, update_install="all"), NOW, check, sys_, [], "package", "0.3.2",
                          (0, 107, 80), 2)  # fmt: skip
    assert all("next quiet night window" in line for line in auto.lines[:1] + auto.lines[2:])
    assert auto.lines[-1].startswith("Restart:")
    src = updates.report(S, NOW, check, sys_, [], "source", "0.3.2", (0, 107, 80), None)
    assert "git pull" in src.lines[0]
    assert rep.data["tvgw"]["installed"] == "0.3.2" and rep.data["adguard"]["tested"] == "0.107.80"


def test_the_weekly_rule_counts_days_from_the_first_sighting():
    from datetime import datetime

    def bounds(y, m, d):
        a = datetime(y, m, d).timestamp()
        return a, datetime(y, m, d + 1).timestamp()

    seen = datetime(2026, 11, 2, 4, 0).timestamp()
    assert updates.weekly(seen, *bounds(2026, 11, 2)) and updates.weekly(seen, *bounds(2026, 11, 9))
    assert not updates.weekly(seen, *bounds(2026, 11, 5)) and not updates.weekly(seen, *bounds(2026, 11, 1))
    assert not updates.weekly(None, *bounds(2026, 11, 2))


def test_a_step_that_raises_is_a_failed_step_and_the_night_is_still_recorded(tmp_path):
    def broken(*_a):
        raise OSError("No space left on device")

    env = fake_env(tmp_path, adguard_version=broken)
    run = updates.install(replace(S, update_install="security"), env, "night")
    assert run["adguard"] == {"outcome": "failed", "why": "OSError: No space left on device"}
    assert run["result"] == "failed" and updates.load_runs(env.conn) == [run]


def test_a_run_that_could_not_start_is_recorded_and_fails_the_unit(tmp_path):
    from tvgw import setup

    env = fake_env(tmp_path)

    def locked():
        raise setup.SetupError("another install is running (waited 10 minutes)")

    env.lock = locked
    assert updates.scheduled(replace(S, update_install="all"), env) == 1
    (run,) = updates.load_runs(env.conn)
    assert run["result"] == "failed" and "another install is running" in run["why"]
