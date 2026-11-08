"""(updates) What the gateway keeps current on its own, and what it tells the owner (design decision 77).

Three things on a gateway grow old: tvgw itself, AdGuard Home, and the computer's own system. A typical
owner never runs apt, and a gateway on the home network that goes years without its system's security
fixes is worse than none. So, with `UPDATE_INSTALL`:

- `security` installs the system's security updates (Debian's and Ubuntu's security archives, and
  Raspberry Pi's own archive, where a Pi's kernel and firmware fixes come with no security suite of
  their own) through the system's own unattended-upgrades, with a configuration tvgw writes
  (`APT_CONF`), and AdGuard Home's newer patch releases of the minor version it runs, checked against
  the release's own checksums and GitHub's digest, through the upgrade path that already rolls back;
- `all` adds the system's other updates from its release (Debian's point releases and `-updates`) and,
  on a gateway installed from the package, tvgw's own newer releases, published immutable and checked
  against their SHA256SUMS, with the running version's package kept to go back to;
- `off`, which a settings file without the key means, installs nothing, as before.

Nothing is installed outside the deploy window while the TV is quiet (`quiet.decide`, design decision
63), except by the owner's own `tvgw updates --now`. A restart that an update needs waits for the same
window and is followed by `tvgw verify` once the gateway is back. Never a minor or major version of AdGuard
Home without the owner, never a pre-release, never unattended-upgrades' own reboot, mail or removal of
packages. Every install, rollback and restart is a line in the change ledger and in the store's
`update_runs`, which the brief and `tvgw updates` read; nothing else is told, and nothing is sent anywhere
beyond the requests listed in docs/how-it-works/privacy-and-retention.md.

`UPDATE_CHECK=weekly` is the notice alone: one request a week for tvgw's latest release, stored in `meta`
as `update_check` (the version, its publication date and the time of the check) for the brief's New line.
The system's own state is read locally from apt (`apt-get -s`), never by a request of its own, and kept
as `system_updates` with the day its security updates were first seen waiting.

Everything that touches the system is a parameter (`Env`), so every decision is tested without one.
"""

from __future__ import annotations

import contextlib
import glob
import hashlib
import json
import os
import re
import shutil
import sqlite3
import ssl
import subprocess
import tempfile
import time
import urllib.error
import urllib.request
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import BinaryIO

from tvgw import __version__, db, ledger, quiet
from tvgw.config import Settings

# ---- the requests -------------------------------------------------------------------------------------
API = "https://api.github.com/repos/{repo}/releases/{which}"  # which: latest, or tags/v<version>
ADGUARD_REPO = "AdguardTeam/AdGuardHome"
# the headers every request to GitHub's API carries, and nothing else: no account, no token, no cookie
API_HEADERS = {"Accept": "application/vnd.github+json", "X-GitHub-Api-Version": "2022-11-28"}
USER_AGENT = f"tvgw/{__version__}"
TIMEOUT = 20.0  # seconds for one answer of the API
DOWNLOAD_TIMEOUT = 120.0
MAX_RELEASE = 1 << 20  # bytes: a release's JSON, notes included, is tens of kilobytes
MAX_SUMS = 64 << 10  # a checksums file
MAX_PACKAGE = 64 << 20  # a .deb or AdGuard's tarball (about 12 MB)
WEEK = 7 * 86400
CHECK_SLACK = 3600  # a daily timer at a random minute of the window: a week less this is a week
FAILED_CHECKS_WARN = 4  # weekly checks failed in a row before verify warns
_SHA256 = re.compile(r"[0-9a-f]{64}")
_PUBLISHED = re.compile(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z")
_VERSION = re.compile(r"v?(\d{1,6})\.(\d{1,6})\.(\d{1,6})([-+.~]?[0-9A-Za-z.~+-]*)")

Version = tuple[int, int, int]


class CheckError(Exception):
    """A request that did not give a release: its reason in a few fixed words, never the server's text."""


def parse_version(text: str) -> tuple[Version, bool] | None:
    """`v0.4.0` or `0.4.0` as ((0, 4, 0), False); a suffix (`-rc.1`, `b2`) marks a pre-release, True;
    anything else None. Numbers compare as numbers, so 0.10.0 is newer than 0.9.9."""
    m = _VERSION.fullmatch(text.strip()) if isinstance(text, str) else None
    if not m:
        return None
    nums = (int(m.group(1)), int(m.group(2)), int(m.group(3)))
    return nums, bool(m.group(4))


def dotted(v: Version | None) -> str:
    return ".".join(map(str, v)) if v else "unknown"


def upstream(deb_version: str) -> str:
    """The upstream part of a Debian version: `0.3.2-1` is `0.3.2`."""
    return deb_version.rsplit("-", 1)[0] if "-" in deb_version else deb_version


class _HttpsOnly(urllib.request.HTTPRedirectHandler):
    """A release asset answers with a redirect to GitHub's download host; only to https."""

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        if not newurl.startswith("https://"):
            raise urllib.error.HTTPError(newurl, code, "redirect away from https", headers, fp)
        return super().redirect_request(req, fp, code, msg, headers, newurl)


_OPENER = urllib.request.build_opener(
    _HttpsOnly(), urllib.request.HTTPSHandler(context=ssl.create_default_context())
)
Http = Callable[[str, float], BinaryIO]


def open_url(url: str, timeout: float) -> BinaryIO:
    """One HTTPS GET with the system's certificates: the User-Agent with tvgw's version, and for the API
    its two documented headers. Nothing that names the household goes with it."""
    if not url.startswith("https://"):
        raise CheckError("not an https address")
    headers = {"User-Agent": USER_AGENT, **(API_HEADERS if url.startswith("https://api.github.com/") else {})}
    return _OPENER.open(urllib.request.Request(url, headers=headers), timeout=timeout)


def read_capped(resp: BinaryIO, cap: int) -> bytes:
    data = resp.read(cap + 1)
    if len(data) > cap:
        raise CheckError(f"the answer is over {cap >> 10} KB")
    return data


def _get(http: Http, url: str, cap: int, timeout: float = TIMEOUT) -> bytes:
    try:
        with http(url, timeout) as resp:
            return read_capped(resp, cap)
    except CheckError:
        raise
    except urllib.error.HTTPError as e:
        raise CheckError(f"GitHub answered HTTP {e.code}") from None
    except TimeoutError:
        raise CheckError("GitHub did not answer in time") from None
    except (OSError, ValueError) as e:  # URLError, a reset, a TLS failure
        reason = getattr(e, "reason", None)
        if isinstance(reason, TimeoutError) or "timed out" in str(e):
            raise CheckError("GitHub did not answer in time") from None
        raise CheckError("GitHub could not be reached") from None


# ---- a release, as GitHub's API describes it ------------------------------------------------------------
@dataclass(frozen=True)
class Asset:
    name: str
    url: str
    digest: str | None  # the SHA-256 GitHub reports for it, hex, when it reports one


@dataclass(frozen=True)
class Release:
    tag: str
    version: Version
    prerelease: bool
    published: str
    immutable: bool  # GitHub says the release can no longer be changed (immutable releases)
    assets: dict[str, Asset] = field(default_factory=dict)


def parse_release(raw: bytes, repo: str) -> Release:
    """GitHub's release JSON, checked: a tag that is a version, a publication time, and assets whose
    addresses are this repository's own release downloads. A draft is no release; a pre-release is
    marked, by GitHub's flag or by its version, and is never installed."""
    try:
        o = json.loads(raw)
    except (ValueError, UnicodeDecodeError):
        raise CheckError("the answer is not JSON") from None
    if not isinstance(o, dict) or not isinstance(o.get("tag_name"), str):
        raise CheckError("the answer is not a release")
    parsed = parse_version(o["tag_name"])
    if parsed is None:
        raise CheckError("the release's tag is not a version")
    if o.get("draft") is True:
        raise CheckError("the release is a draft")
    published = o.get("published_at")
    if not isinstance(published, str) or not _PUBLISHED.fullmatch(published):
        raise CheckError("the release has no publication time")
    prefix = f"https://github.com/{repo}/releases/download/"
    assets: dict[str, Asset] = {}
    for a in o.get("assets") or []:
        if not isinstance(a, dict):
            continue
        name, url, digest = a.get("name"), a.get("browser_download_url"), a.get("digest")
        if not (isinstance(name, str) and isinstance(url, str) and url.startswith(prefix)):
            continue
        hexd = None
        if isinstance(digest, str) and digest.startswith("sha256:") and _SHA256.fullmatch(digest[7:]):
            hexd = digest[7:]
        assets[name] = Asset(name, url, hexd)
    return Release(
        tag=o["tag_name"],
        version=parsed[0],
        prerelease=parsed[1] or o.get("prerelease") is True,
        published=published,
        immutable=o.get("immutable") is True,
        assets=assets,
    )


def fetch_release(repo: str, http: Http = open_url, which: str = "latest") -> Release:
    """One GET of the repository's latest release (or `tags/v<version>`): CheckError when there is none."""
    return parse_release(_get(http, API.format(repo=repo, which=which), MAX_RELEASE), repo)


def parse_sums(text: str) -> dict[str, str]:
    """`<sha256>  <name>` lines (sha256sum's format, `*name` for binary mode too) as {name: sha256}."""
    out: dict[str, str] = {}
    for line in text.splitlines():
        parts = line.split()
        if len(parts) == 2 and _SHA256.fullmatch(parts[0].lower()):
            out[parts[1].lstrip("*").removeprefix("./")] = parts[0].lower()
    return out


def expected_hash(rel: Release, asset: str, sums_name: str, http: Http) -> str:
    """The SHA-256 a download must have: the release's own checksums file's line for it, which GitHub's
    digest of the asset, where GitHub reports one, must equal. CheckError when either is missing or they
    disagree: then nothing is downloaded."""
    if asset not in rel.assets:
        raise CheckError(f"the release has no {asset}")
    if sums_name not in rel.assets:
        raise CheckError(f"the release has no {sums_name}")
    raw = _get(http, rel.assets[sums_name].url, MAX_SUMS, DOWNLOAD_TIMEOUT)
    want = parse_sums(raw.decode("utf-8", "replace")).get(asset)
    if want is None:
        raise CheckError(f"{sums_name} has no line for {asset}")
    digest = rel.assets[asset].digest
    if digest is not None and digest != want:
        raise CheckError(f"{sums_name} and GitHub's digest of {asset} disagree")
    return want


def download_checked(http: Http, url: str, want: str, path: Path, cap: int = MAX_PACKAGE) -> Path:
    """The file at `url` saved as `path`, hashed as it arrives and capped; anything but `want` is deleted
    and refused (CheckError)."""
    part = path.with_name(path.name + ".part")
    digest, size = hashlib.sha256(), 0
    try:
        with http(url, DOWNLOAD_TIMEOUT) as resp, open(part, "wb") as out:
            while chunk := resp.read(1 << 16):
                size += len(chunk)
                if size > cap:
                    raise CheckError(f"the download is over {cap >> 20} MB")
                digest.update(chunk)
                out.write(chunk)
    except CheckError:
        part.unlink(missing_ok=True)
        raise
    except (OSError, ValueError):
        part.unlink(missing_ok=True)
        raise CheckError("the download was cut short") from None
    if digest.hexdigest() != want:
        part.unlink(missing_ok=True)
        raise CheckError("the download does not match its checksum")
    os.replace(part, path)
    return path


# ---- the weekly check: the latest tvgw, in meta --------------------------------------------------------
META_CHECK = "update_check"
META_SYSTEM = "system_updates"
META_RUNS = "update_runs"
RUNS_KEPT = 60  # nights with something done or waiting: two months


def _load(conn: sqlite3.Connection, key: str):
    try:
        raw = db.get_meta(conn, key)
    except sqlite3.Error:
        return None
    try:
        return json.loads(raw) if raw else None
    except ValueError:
        return None


def load_check(conn: sqlite3.Connection) -> dict | None:
    got = _load(conn, META_CHECK)
    return got if isinstance(got, dict) else None


def check_state(prev: dict | None, now: float, rel: Release | None, why: str | None) -> dict:
    """The new `update_check` row: the latest version, its publication date, when the check ran and when
    it first saw this version; a failed check keeps what the last good one found and counts the failures
    in a row. Nothing else is kept."""
    prev = prev or {}
    if rel is not None:
        latest = dotted(rel.version)
        seen = prev.get("seen_t") if prev.get("latest") == latest else now
        return {
            "t": now,
            "ok": True,
            "latest": latest,
            "published": rel.published,
            "seen_t": seen,
            "failures": 0,
        }
    kept = {k: prev[k] for k in ("latest", "published", "seen_t") if k in prev}
    return {"t": now, "ok": False, "why": why, "failures": int(prev.get("failures") or 0) + 1, **kept}


def check_due(prev: dict | None, now: float) -> bool:
    """A week since the last attempt, good or failed: a failure waits its week, never retried sooner."""
    t = (prev or {}).get("t")
    return not isinstance(t, (int, float)) or now - t >= WEEK - CHECK_SLACK


def weekly_check(s: Settings, conn: sqlite3.Connection, now: float, http: Http, force: bool = False) -> dict:
    """The one request of UPDATE_CHECK=weekly (or `--check-now`), recorded; with the setting off, none
    (the caller says so). Returns the stored row."""
    prev = load_check(conn)
    if not force and not check_due(prev, now):
        return prev or {}
    try:
        rel = fetch_release(s.update_repo, http)
        if rel.prerelease:  # GitHub's latest is never one; a tag that reads as one is not news
            raise CheckError("the latest release is a pre-release")
        row = check_state(prev, now, rel, None)
    except CheckError as e:
        row = check_state(prev, now, None, str(e))
    db.set_meta(conn, META_CHECK, json.dumps(row))
    conn.commit()
    return row


# ---- the system's own updates, read locally ------------------------------------------------------------
# apt's simulation with the lists it has: no lock (a running apt is never waited on or disturbed), and no
# cache file written (apt builds it in memory), so the reading changes nothing on the system
APT_SIM = (
    "apt-get", "-s", "-q", "-o", "Debug::NoLocking=1", "-o", "Dir::Cache::pkgcache=",
    "-o", "Dir::Cache::srcpkgcache=", "dist-upgrade",
)  # fmt: skip
LISTS = "/var/lib/apt/lists"
DPKG_STATUS = "/var/lib/dpkg/status"
UPDATE_STAMP = "/var/lib/apt/periodic/update-success-stamp"
READING_MAX_AGE = 86400  # a stored reading older than this is read again
LISTS_STALE = 14 * 86400  # "the gateway has not looked for system updates since ..."
LISTS_WARN = 30 * 86400
SECURITY_WARN = 14 * 86400  # verify warns on security updates waiting longer
SECURITY_NEW = 7 * 86400  # the brief's New line names them after this
_INST = re.compile(r"^Inst (\S+)(?: \[[^\]]*\])? \(([^)]*)\)")


def _is_security(release: str) -> bool:
    """One `Label:Version/Archive` of apt's simulation: from a security archive, or Raspberry Pi's own
    archive, which carries a Pi's kernel and firmware fixes and has no security suite."""
    label, _, rest = release.strip().partition(":")
    archive = rest.rpartition("/")[2]
    return (
        archive.endswith("-security")
        or label.endswith("-Security")
        or label.startswith("UbuntuESM")
        or label == "Raspberry Pi Foundation"
    )


def parse_apt_sim(text: str) -> tuple[list[str], list[str]]:
    """(every package the simulation would install or upgrade, those of them from a security source)."""
    every, security = [], []
    for line in text.splitlines():
        m = _INST.match(line.strip())
        if not m:
            continue
        name, inside = m.group(1), m.group(2)
        body = re.sub(r" \[[^\]]*\]$", "", inside)  # the architecture
        releases = body.split(" ", 1)[1] if " " in body else ""
        every.append(name)
        if any(_is_security(r) for r in releases.split(", ") if r):
            security.append(name)
    return every, security


def file_mtime(path: str) -> float | None:
    try:
        return os.stat(path).st_mtime
    except OSError:
        return None


def lists_time(
    mtime: Callable[[str], float | None] = file_mtime, globber: Callable[[str], list[str]] = glob.glob
) -> float | None:
    """When the system last fetched its package lists, as near as the files say: the newest of the lists'
    directory, its Release files and apt's own success stamp."""
    paths = [LISTS, UPDATE_STAMP, *globber(f"{LISTS}/*Release")]
    times = [t for t in (mtime(p) for p in paths) if t is not None]
    return max(times) if times else None


def fold(prev: dict | None, cur: dict) -> dict:
    """The reading with `since`, the time security updates were first seen waiting: kept while any wait,
    set by the first reading that shows some, and gone once none does."""
    if not cur.get("security"):
        return {**cur, "since": None}
    prev = prev or {}
    since = prev.get("since") if prev.get("security") and prev.get("since") else cur["t"]
    return {**cur, "since": since}


def load_system(conn: sqlite3.Connection | None) -> dict | None:
    got = _load(conn, META_SYSTEM) if conn is not None else None
    return got if isinstance(got, dict) else None


def read_system(
    run: Callable[[list[str]], str],
    now: float,
    prev: dict | None = None,
    mtime: Callable[[str], float | None] = file_mtime,
    globber: Callable[[str], list[str]] = glob.glob,
) -> dict | None:
    """The system's waiting updates from apt's simulation, or None where apt says nothing (no apt-get, or
    a run that failed: a simulation always prints its banner)."""
    out = run(list(APT_SIM))
    if not out.strip():
        return None
    every, security = parse_apt_sim(out)
    cur = {"t": now, "waiting": len(every), "security": len(security), "lists_t": lists_time(mtime, globber)}
    return fold(prev, cur)


def system_state(
    stored: dict | None,
    run: Callable[[list[str]], str],
    now: float,
    mtime: Callable[[str], float | None] = file_mtime,
    globber: Callable[[str], list[str]] = glob.glob,
) -> tuple[dict | None, bool]:
    """(the reading, whether it is new): the stored one while it is under a day old and neither the lists
    nor dpkg's status changed after it, else a new one folded onto it. Running apt's simulation once a day
    or after a change keeps the 10-minute verify cheap."""
    t = (stored or {}).get("t")
    if isinstance(t, (int, float)) and now - t < READING_MAX_AGE:
        changed = [m for m in (lists_time(mtime, globber), mtime(DPKG_STATUS)) if m is not None and m > t]
        if not changed:
            return stored, False
    got = read_system(run, now, stored, mtime, globber)
    return (got, True) if got is not None else (stored, False)


# ---- unattended-upgrades as tvgw configures it -----------------------------------------------------------
APT_CONF = "/etc/apt/apt.conf.d/90tvgw-updates"
UNATTENDED = "/usr/bin/unattended-upgrade"
SECURITY_ORIGINS = (
    "origin=Debian,codename=${distro_codename}-security,label=Debian-Security",
    "origin=Debian,codename=${distro_codename},label=Debian-Security",
    "origin=Raspberry Pi Foundation,codename=${distro_codename},label=Raspberry Pi Foundation",
    "origin=Ubuntu,archive=${distro_codename}-security,label=Ubuntu",
    "origin=UbuntuESMApps,archive=${distro_codename}-apps-security",
    "origin=UbuntuESM,archive=${distro_codename}-infra-security",
)
ALL_ORIGINS = (
    *SECURITY_ORIGINS,
    "origin=Debian,codename=${distro_codename},label=Debian",
    "origin=Debian,codename=${distro_codename}-updates",
    "origin=Ubuntu,archive=${distro_codename}-updates,label=Ubuntu",
)
ORIGINS = {"security": SECURITY_ORIGINS, "all": ALL_ORIGINS}
# the values tvgw holds, as `apt-config dump` prints them; the checks of verify's `updates` read them back
APT_VALUES = {
    "APT::Periodic::Update-Package-Lists": "1",  # apt's daily job fetches the lists, and only that
    "APT::Periodic::Unattended-Upgrade": "0",  # tvgw's own run installs, in the window
    "Unattended-Upgrade::Automatic-Reboot": "false",  # tvgw restarts the gateway, in the window
    "Unattended-Upgrade::Remove-Unused-Dependencies": "false",  # never a package tvgw needs
    "Unattended-Upgrade::Remove-New-Unused-Dependencies": "false",
    "Unattended-Upgrade::Mail": "",  # nothing is sent to anyone
    "Unattended-Upgrade::OnlyOnACPower": "false",  # a Pi has no battery to ask about
}
CONFOLD = "--force-confold"  # a changed configuration file is kept, never asked about


def apt_conf(mode: str) -> str | None:
    """The text of APT_CONF for UPDATE_INSTALL, or None for off (the file is removed, and the system's own
    configuration is what it was). Each list is cleared first, so a pattern of the system's own does not
    widen what is installed; the patterns that match no archive of this system match nothing."""
    if mode not in ORIGINS:
        return None
    lines = [
        f"// tvgw: written by install.sh for UPDATE_INSTALL={mode} (design decision 77). Change the setting",
        "// in /etc/tvgw/tvgw.conf, not this file. tvgw-update.timer runs unattended-upgrade in the deploy",
        "// window while the TV is quiet; apt's own daily job only fetches the package lists.",
        *(f'{key} "{value}";' for key, value in APT_VALUES.items()),
        "#clear Unattended-Upgrade::Allowed-Origins;",
        "#clear Unattended-Upgrade::Origins-Pattern;",
        "Unattended-Upgrade::Origins-Pattern {",
        *(f'\t"{pattern}";' for pattern in ORIGINS[mode]),
        "};",
        f'Dpkg::Options {{ "--force-confdef"; "{CONFOLD}"; }};',
    ]
    return "\n".join(lines) + "\n"


def parse_apt_dump(text: str) -> tuple[dict[str, str], dict[str, list[str]]]:
    """`apt-config dump`: (single values, lists), a list being the `Name:: "value";` lines under a name."""
    single: dict[str, str] = {}
    lists: dict[str, list[str]] = {}
    for line in text.splitlines():
        m = re.fullmatch(r'(\S+?)(::)? "(.*)";', line.strip())
        if not m:
            continue
        if m.group(2):
            lists.setdefault(m.group(1), []).append(m.group(3))
        else:
            single[m.group(1)] = m.group(3)
    return single, lists


def apt_conf_problems(dump: str, mode: str) -> list[str]:
    """What the effective apt configuration (`apt-config dump`) holds against UPDATE_INSTALL, as short
    plain phrases; none when it is as tvgw writes it. A file of the owner's sorted after APT_CONF shows
    here, as anything else that changes the effective value does."""
    if mode not in ORIGINS:
        return []
    if not dump.strip():
        return ["apt's configuration could not be read"]
    single, lists = parse_apt_dump(dump)
    out = [
        f"{key} is {single[key]!r}, not {value!r}"
        for key, value in APT_VALUES.items()
        if key in single and single[key] != value
    ]
    out += [f"{key} is not set" for key, value in APT_VALUES.items() if key not in single and value]
    if lists.get("Unattended-Upgrade::Origins-Pattern", []) != list(ORIGINS[mode]):
        out.append("the origins unattended-upgrades installs from are not tvgw's")
    if lists.get("Unattended-Upgrade::Allowed-Origins"):
        out.append("unattended-upgrades also has origins of its own (Allowed-Origins)")
    if CONFOLD not in lists.get("Dpkg::Options", []):
        out.append("a changed configuration file could stop an update with a question")
    return out


# ---- the timer, inside the deploy window ----------------------------------------------------------------
TIMER = "tvgw-update.timer"
TIMER_DROPIN = "/etc/systemd/system/tvgw-update.timer.d/window.conf"
RUN_MARGIN = 45  # minutes the window keeps after the latest start, for the run itself


def timer_dropin(window: str) -> str:
    """The drop-in that starts tvgw-update.timer at the window's start, at a random minute up to
    RUN_MARGIN before its end (none for a shorter window): the run checks the window again itself."""
    start, end = quiet.parse_window(window)
    delay = max(0, (end - start) % 1440 - RUN_MARGIN)
    return (
        "[Timer]\nOnCalendar=\n"
        f"OnCalendar=*-*-* {start // 60:02d}:{start % 60:02d}:00\nRandomizedDelaySec={delay}min\n"
    )


def configure(
    s: Settings,
    write: Callable[[str, str], None],
    remove: Callable[[str], None],
) -> list[str]:
    """install.sh's step: APT_CONF for UPDATE_INSTALL (removed for off) and the timer's window drop-in.
    Returns a line per file."""
    text = apt_conf(s.update_install)
    if text is None:
        remove(APT_CONF)
        lines = [f"removed {APT_CONF} (UPDATE_INSTALL=off): the system's own configuration applies"]
    else:
        write(APT_CONF, text)
        lines = [f"wrote {APT_CONF} (UPDATE_INSTALL={s.update_install})"]
    write(TIMER_DROPIN, timer_dropin(s.deploy_window))
    lines.append(f"wrote {TIMER_DROPIN} (DEPLOY_WINDOW={s.deploy_window})")
    return lines


def _write(path: str, text: str) -> None:
    from tvgw import guard

    guard.write_atomic(path, text, 0o644)


def _remove(path: str) -> None:
    with contextlib.suppress(FileNotFoundError):
        os.unlink(path)


# ---- the installs -------------------------------------------------------------------------------------
REBOOT_FLAG = "/run/reboot-required"  # written by the packages that need a restart (Debian, Ubuntu)
REBOOT_MARKER = "reboot-pending.json"  # under STATE_DIR: the restart the gateway made, until checked
PACKAGES = "packages"  # under STATE_DIR: the tvgw package installed last, kept to go back to
TVGW_BIN = "/usr/local/bin/tvgw"
NONINTERACTIVE = {"DEBIAN_FRONTEND": "noninteractive", "LC_ALL": "C", "NEEDRESTART_MODE": "a"}
NAMES_KEPT = 30  # package names a run keeps
SETTLE_WAIT = 300.0  # seconds verify's settling checks get after an install (decision 53, item 5)
SETTLE_STEP = 30.0
APT_UPDATE_TIMEOUT = 600
UNATTENDED_TIMEOUT = 45 * 60
APT_INSTALL_TIMEOUT = 30 * 60
INSTALLED, ROLLED_BACK, WAITED, FAILED, NOTHING, HELD, SKIPPED = (
    "installed", "rolled_back", "waited", "failed", "nothing", "held", "skipped",
)  # fmt: skip


@dataclass
class Step:
    """What one component's step did: its outcome, the versions, a count and a reason in plain words."""

    outcome: str
    why: str = ""
    before: str = ""
    after: str = ""
    count: int = 0
    security: int = 0
    names: list[str] = field(default_factory=list)

    def as_dict(self) -> dict:
        d = {"outcome": self.outcome}
        for k in ("why", "before", "after"):
            if getattr(self, k):
                d[k] = getattr(self, k)
        if self.count:
            d["count"], d["security"] = self.count, self.security
        if self.names:  # the system's package names, never the household's: for tvgw updates --json
            d["names"] = self.names[:NAMES_KEPT]
        return d


@dataclass
class Env:
    """Every way the installs touch the machine; live_env() is the real one, the tests pass fakes."""

    run: Callable[..., tuple[int, str]]  # (argv, timeout=, env=) -> (exit status, output); 127 not found
    http: Http
    quiet: Callable[[], bool]
    verify: Callable[[], list[str]]  # the checks that FAIL once the settling ones had their time
    exists: Callable[[str], bool]
    read: Callable[[str], str]
    write: Callable[[str, str], None]
    remove: Callable[[str], None]
    store: Callable[[Callable[[sqlite3.Connection], object]], object]  # fn on a writer, committed
    spool: Callable[[list[str]], None]
    reboot: Callable[[], None]
    lock: Callable[[], contextlib.AbstractContextManager]
    adguard_version: Callable[[], Version | None]
    adguard_upgrade: Callable[[str], list[str]]  # newbin -> what was done; RuntimeError rolled back
    adguard_extract: Callable[[Path, Path, Version], Path]  # tarball, stage, floor -> the new binary
    arch: Callable[[], str]
    installed: Callable[[], tuple[str | None, str]]  # ("package" | "source" | None, dpkg version)
    now: Callable[[], float] = time.time
    say: Callable[[str], None] = print
    tmpdir: Callable[[], contextlib.AbstractContextManager] = lambda: tempfile.TemporaryDirectory(
        prefix="tvgw-update-"
    )


def dpkg_versions(text: str) -> dict[str, str]:
    out = {}
    for line in text.splitlines():
        name, _, version = line.partition("\t")
        if name and version:
            out[name] = version
    return out


DPKG_LIST = ["dpkg-query", "-W", "-f", "${Package}\t${Version}\n"]


def system_step(env: Env) -> Step:
    """The system's updates through unattended-upgrade with tvgw's configuration: the package lists
    fetched first, then what changed told from dpkg's own list before and after. No rollback: apt has
    none, so verify's result is recorded and its warning stands."""
    if not env.exists(UNATTENDED):
        return Step(SKIPPED, "unattended-upgrades is not installed")
    rc, _ = env.run(["apt-get", "-q", "update"], timeout=APT_UPDATE_TIMEOUT, env=NONINTERACTIVE)
    stale = rc != 0
    _, sim = env.run(list(APT_SIM), timeout=120, env=NONINTERACTIVE)
    _, security = parse_apt_sim(sim)
    _, listed = env.run(DPKG_LIST, timeout=60)
    before = dpkg_versions(listed)
    rc, _ = env.run([UNATTENDED, "-v"], timeout=UNATTENDED_TIMEOUT, env=NONINTERACTIVE)
    _, listed = env.run(DPKG_LIST, timeout=60)
    after = dpkg_versions(listed)
    changed = sorted(p for p, v in after.items() if before.get(p) != v)
    sec = len(set(changed) & set(security))
    note = " (the package lists could not be fetched, so the ones from before were used)" if stale else ""
    if rc != 0:
        why = f"unattended-upgrade stopped with status {rc}{note}"
        return Step(FAILED, why, count=len(changed), security=sec)
    if not changed:
        return Step(NOTHING, "no system update was waiting" + note)
    return Step(INSTALLED, note.strip(" ()"), count=len(changed), security=sec, names=changed)


def adguard_step(env: Env, workdir: Path) -> Step:
    """A newer patch release of the AdGuard Home minor version that runs, from AdGuard's latest release:
    checked against its checksums.txt and GitHub's digest, unpacked by aghinstall (which refuses a binary
    that does not report that version), then adguardcfg.upgrade, which checks the live configuration
    with it first and puts the old binary back on any failure. A newer minor or major version is held for
    the owner."""
    running = env.adguard_version()
    if running is None:
        return Step(SKIPPED, "AdGuard Home is not installed or does not say its version")
    try:
        rel = fetch_release(ADGUARD_REPO, env.http)
    except CheckError as e:
        return Step(SKIPPED, f"its latest release could not be read: {e}", before=dotted(running))
    have, new = dotted(running), dotted(rel.version)
    if rel.prerelease or rel.version <= running:
        return Step(NOTHING, before=have)
    if rel.version[:2] != running[:2]:
        return Step(
            HELD, f"{new} is a larger change than a patch, which the gateway leaves to you", have, new
        )
    asset = f"AdGuardHome_linux_{env.arch()}.tar.gz"
    try:
        want = expected_hash(rel, asset, "checksums.txt", env.http)
        tar = download_checked(env.http, rel.assets[asset].url, want, workdir / asset)
    except CheckError as e:
        return Step(SKIPPED, f"not installed: {e}", have, new)
    stage = workdir / "stage"
    stage.mkdir(mode=0o755)
    try:
        newbin = env.adguard_extract(tar, stage, rel.version)
    except Exception as e:  # aghinstall.InstallError: a bad archive, or a binary of another version
        return Step(SKIPPED, f"not installed: {e}", have, new)
    try:
        env.adguard_upgrade(str(newbin))
    except (ValueError, OSError) as e:  # the profile's plan or the files, before anything changed
        return Step(SKIPPED, f"not installed: {e}"[:200], have, new)
    except RuntimeError as e:
        deferred = type(e).__name__ == "Deferred"  # adguardcfg.Deferred: the upstreams are down
        if deferred:
            return Step(WAITED, "its upstream servers did not answer, so nothing was changed", have, new)
        put_back = "put back" in str(e)
        return Step(ROLLED_BACK if put_back else FAILED, str(e).splitlines()[0][:200], have, new)
    return Step(INSTALLED, before=have, after=new)


def tvgw_step(s: Settings, env: Env, workdir: Path, conn_check: Callable[[dict], None]) -> Step:
    """A newer tvgw release on a gateway installed from the package: published immutable, its package
    checked against SHA256SUMS and GitHub's digest, the running version's package at hand to go back to
    (kept from the last install, or fetched from its own release and checked), installed with apt, then
    judged by verify once the settling checks have had their time; a failure reinstalls the kept package.
    A gateway that runs from a source checkout is updated from that checkout and skipped."""
    kind, have_deb = env.installed()
    if kind == "source":
        return Step(SKIPPED, "this gateway runs tvgw from a source checkout, which is updated there")
    if kind != "package":
        return Step(SKIPPED, "tvgw's package is not installed")
    have = parse_version(upstream(have_deb))
    try:
        rel = fetch_release(s.update_repo, env.http)
    except CheckError as e:
        conn_check({"why": str(e)})
        return Step(SKIPPED, f"its latest release could not be read: {e}", before=upstream(have_deb))
    conn_check({"release": rel})
    new = dotted(rel.version)
    if have is None or rel.prerelease or rel.version <= have[0]:
        return Step(NOTHING, before=upstream(have_deb))
    if not rel.immutable:
        why = "the release can still be changed after publication, so the gateway does not install it itself"
        return Step(HELD, why, upstream(have_deb), new)
    arch = env.arch()
    deb = f"tvgw_{new}-1_{arch}.deb"
    keep_dir = Path(s.state_dir) / PACKAGES
    kept = keep_dir / f"tvgw_{have_deb}_{arch}.deb"
    try:
        want = expected_hash(rel, deb, "SHA256SUMS", env.http)
        if not env.exists(str(kept)):
            old = fetch_release(s.update_repo, env.http, f"tags/v{upstream(have_deb)}")
            old_deb = f"tvgw_{have_deb}_{arch}.deb"
            old_want = expected_hash(old, old_deb, "SHA256SUMS", env.http)
            keep_dir.mkdir(mode=0o700, parents=True, exist_ok=True)
            download_checked(env.http, old.assets[old_deb].url, old_want, kept)
        newpath = download_checked(env.http, rel.assets[deb].url, want, workdir / deb)
    except CheckError as e:
        return Step(SKIPPED, f"not installed: {e}", upstream(have_deb), new)
    rc, _ = env.run(_apt_install(newpath), timeout=APT_INSTALL_TIMEOUT, env=NONINTERACTIVE)
    failing = env.verify() if rc == 0 else []
    if rc == 0 and not failing:
        with contextlib.suppress(OSError):  # the next run fetches its way back if this copy fails
            shutil.copy2(newpath, keep_dir / deb)
            for old_file in keep_dir.glob("tvgw_*.deb"):
                if old_file.name != deb:
                    old_file.unlink(missing_ok=True)
        return Step(INSTALLED, before=upstream(have_deb), after=new)
    why = f"apt stopped with status {rc}" if rc != 0 else "verify failed: " + ", ".join(failing)
    rc2, _ = env.run(_apt_install(kept, downgrade=True), timeout=APT_INSTALL_TIMEOUT, env=NONINTERACTIVE)
    if rc2 != 0:
        return Step(FAILED, f"{why}; putting {upstream(have_deb)} back also failed", upstream(have_deb), new)
    still = env.verify()
    after = f"; after it, verify fails: {', '.join(still)}" if still else ""
    return Step(ROLLED_BACK, f"{why}; {upstream(have_deb)} was put back{after}", upstream(have_deb), new)


def _apt_install(path: Path, downgrade: bool = False) -> list[str]:
    argv = ["apt-get", "install", "-y", "-q", "-o", f"Dpkg::Options::={CONFOLD}"]
    return [*argv, *(["--allow-downgrades"] if downgrade else []), str(path)]


def reboot_needed(env: Env) -> int | None:
    """None without the flag; else the number of packages that asked for the restart (0 when unnamed)."""
    if not env.exists(REBOOT_FLAG):
        return None
    pkgs = env.read(REBOOT_FLAG + ".pkgs") if env.exists(REBOOT_FLAG + ".pkgs") else ""
    return len({p for p in pkgs.split() if p})


def remember(conn: sqlite3.Connection, run: dict) -> None:
    runs = _load(conn, META_RUNS)
    runs = [r for r in runs if isinstance(r, dict)] if isinstance(runs, list) else []
    db.set_meta(conn, META_RUNS, json.dumps([*runs, run][-RUNS_KEPT:]))


def load_runs(conn: sqlite3.Connection | None) -> list[dict]:
    runs = _load(conn, META_RUNS) if conn is not None else None
    return [r for r in runs if isinstance(r, dict)] if isinstance(runs, list) else []


def _spool_step(env: Env, component: str, st: Step) -> None:
    if st.outcome == INSTALLED:
        env.spool(["update", "installed", component, st.after or str(st.count)])
    elif st.outcome == ROLLED_BACK:
        env.spool(["update", "rolled_back", component, st.after or "-"])


def _guarded(step: Callable[[], Step]) -> Step:
    """A step that raised is a failed step, said in its own words, so the run is still recorded and the
    next step still runs: a full disk or a refused file must not lose the night's record."""
    try:
        return step()
    except Exception as e:
        return Step(FAILED, f"{type(e).__name__}: {e}"[:200])


def install(s: Settings, env: Env, trigger: str) -> dict:
    """One run of the installs, `trigger` being `night` (the timer, in the window while the TV is quiet:
    the caller has asked) or `owner` (`tvgw updates --now`, which never restarts the gateway itself).
    Returns the run as stored in `update_runs`."""
    mode = s.update_install
    t0 = env.now()
    run: dict = {"t": t0, "trigger": trigger, "mode": mode}
    with env.lock(), env.tmpdir() as tmp:
        system = _guarded(lambda: system_step(env))
        run["system"] = system.as_dict()
        _spool_step(env, "system", system)
        agh_dir = Path(tmp) / "adguard"
        agh_dir.mkdir()
        adguard = _guarded(lambda: adguard_step(env, agh_dir))
        run["adguard"] = adguard.as_dict()
        _spool_step(env, "adguard", adguard)
        if system.outcome in (INSTALLED, FAILED) and system.count:
            failing = env.verify()
            run["verify"] = "held" if not failing else "failed: " + ", ".join(failing)
    # tvgw last and outside the lock: its package's own install takes the lock, and from here on this
    # process may run beside a newer tvgw on disk, so it only runs commands and writes the store
    if mode == "all":

        def check(found: dict) -> None:
            rel = found.get("release")
            env.store(
                lambda conn: db.set_meta(
                    conn,
                    META_CHECK,
                    json.dumps(check_state(load_check(conn), env.now(), rel, found.get("why"))),
                )
            )

        with env.tmpdir() as tmp:
            tv = _guarded(lambda: tvgw_step(s, env, Path(tmp), check))
        run["tvgw"] = tv.as_dict()
        _spool_step(env, "tvgw", tv)
    outcomes = [run[k]["outcome"] for k in ("system", "adguard", "tvgw") if k in run]
    run["result"] = next(
        (o for o in (ROLLED_BACK, FAILED, INSTALLED, WAITED, HELD) if o in outcomes), NOTHING
    )
    pending = reboot_needed(env)
    if pending is not None:
        run["reboot"] = "needed"
        if trigger == "night" and env.quiet():
            run["reboot"] = "done"
    env.store(lambda conn: remember(conn, run))
    if run.get("reboot") == "done":
        env.write(os.path.join(s.state_dir, REBOOT_MARKER), json.dumps({"t": env.now(), "packages": pending}))
        env.spool(["update", "reboot", "system", str(pending)])
        env.say("tvgw updates: restarting the gateway to finish the updates")
        env.reboot()
    return run


NOT_QUIET = "the TV was in use, or the night window had passed"


def scheduled(s: Settings, env: Env) -> int:
    """tvgw-update.service: the weekly check when one is due (UPDATE_CHECK=weekly), then the installs when
    UPDATE_INSTALL allows them and the TV is quiet in the deploy window. With both off it asks nothing and
    installs nothing. Exits 0: what it did or could not do is in the record, which verify reads."""
    if s.update_check == "off" and s.update_install == "off":
        env.say("tvgw updates: UPDATE_CHECK and UPDATE_INSTALL are off: nothing asked, nothing installed")
        return 0
    if s.update_check == "weekly":
        row = env.store(lambda conn: weekly_check(s, conn, env.now(), env.http))
        if isinstance(row, dict) and row.get("t") is not None:
            said = f"latest {row.get('latest')}" if row.get("ok") else f"failed: {row.get('why')}"
            env.say(f"tvgw updates: the weekly check: {said}")
    if s.update_install == "off":
        return 0
    if not env.quiet():
        waited(s, env, NOT_QUIET, env.store(load_system))
        env.say(f"tvgw updates: nothing installed: {NOT_QUIET}")
        return 0
    try:
        run = install(s, env, "night")
    except Exception as e:  # the install lock not had in 10 minutes, a store that cannot be written
        run = {"t": env.now(), "trigger": "night", "mode": s.update_install, "result": FAILED}
        run["why"] = f"{type(e).__name__}: {e}"[:200]
        with contextlib.suppress(Exception):
            env.store(lambda conn: remember(conn, run))
        env.say(f"tvgw updates: the run stopped: {run['why']}")
        return 1
    env.say("tvgw updates: " + run_sentence(run, ""))
    return 0


def waited(s: Settings, env: Env, why: str, reading: dict | None) -> dict | None:
    """A night the installs did not run: remembered only when something is known to wait (the system's
    own updates, read locally, or a restart), so the brief can say why; None otherwise."""
    pending = reboot_needed(env)
    if not (reading and reading.get("waiting")) and pending is None:
        return None
    run = {"t": env.now(), "trigger": "night", "mode": s.update_install, "result": WAITED, "why": why}
    if reading and reading.get("waiting"):
        run["system"] = {
            "outcome": WAITED,
            "count": reading["waiting"],
            "security": reading.get("security", 0),
        }
    if pending is not None:
        run["reboot"] = "waiting"
    env.store(lambda conn: remember(conn, run))
    return run


def after_reboot(s: Settings, env: Env) -> dict | None:
    """tvgw-update-boot.service: after a restart the gateway made, verify once the settling checks have had
    their time, and record it; the marker goes either way. None when the gateway made no restart."""
    marker = os.path.join(s.state_dir, REBOOT_MARKER)
    if not env.exists(marker):
        return None
    failing = env.verify()
    run = {
        "t": env.now(),
        "trigger": "reboot",
        "mode": s.update_install,
        "result": "held" if not failing else FAILED,
        "verify": "held" if not failing else "failed: " + ", ".join(failing),
    }
    env.store(lambda conn: remember(conn, run))
    env.spool(["update", "verified", "reboot", "ok" if not failing else "failed"])
    env.remove(marker)
    return run


def settled_failures(check: Callable[[], dict], sleep: Callable[[float], None] = time.sleep) -> list[str]:
    """The checks that FAIL, asked again every SETTLE_STEP seconds for up to SETTLE_WAIT while every one of
    them is a settling check (verify.SETTLING: lists still downloading, services still starting)."""
    from tvgw import verify  # here: verify imports this module

    waited_for = 0.0
    while True:
        result = check()
        failing = [c["name"] for c in result.get("checks", []) if not c.get("ok")]
        if not failing and result.get("checks") is None:
            return ["verify"]  # it printed nothing to read
        if not failing or not set(failing) <= verify.SETTLING or waited_for >= SETTLE_WAIT:
            return failing
        sleep(SETTLE_STEP)
        waited_for += SETTLE_STEP


def _run(argv: list[str], timeout: float = 60, env: dict | None = None) -> tuple[int, str]:
    try:
        r = subprocess.run(
            argv,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=timeout,
            env={**os.environ, **(env or {})},
        )
    except FileNotFoundError:
        return 127, ""
    except (OSError, subprocess.TimeoutExpired) as e:
        return 124, str(e)
    return r.returncode, r.stdout + r.stderr


def installed_kind(run: Callable[..., tuple[int, str]] = _run) -> tuple[str | None, str]:
    """("package", its dpkg version) when dpkg has tvgw installed; ("source", "") when a checkout's
    install.sh put it in /usr/local/bin (get.sh's test); else (None, "")."""
    rc, out = run(["dpkg-query", "-W", "-f", "${db:Status-Status}\t${Version}\n", "tvgw"])
    status, _, version = (out.splitlines() or [""])[0].partition("\t")
    if rc == 0 and status == "installed" and version:
        return "package", version.strip()
    if os.path.lexists(TVGW_BIN):
        return "source", ""
    return None, ""


def _quiet(s: Settings) -> bool:
    """quiet.decide with the TV port watched for 2 minutes too, so a store without samples still
    measures; a reading that cannot be opened is never quiet, as for `tvgw tv quiet`."""
    try:
        return quiet.decide(s, wait=120)
    except (OSError, ValueError):
        return False


def live_env(s: Settings, prof, conf: str) -> Env:
    """The real system."""
    from tvgw import adguardcfg, aghinstall, setup

    def store(fn):
        conn = db.connect(s.db_path)
        try:
            out = fn(conn)
            conn.commit()
            return out
        finally:
            conn.close()

    def verify_json() -> dict:
        _, out = _run([TVGW_BIN, "--conf", conf, "verify", "--json"], timeout=600)
        try:
            return json.loads(out[out.index("{") :])
        except ValueError:
            return {}

    def upgrade(newbin: str) -> list[str]:
        d = adguardcfg.desired(prof, s)

        def failing() -> set[str]:
            return set(settled_failures(verify_json))

        return adguardcfg.upgrade(
            s.adguard_yaml,
            newbin,
            ready=lambda: adguardcfg.dns_ready(name=d.probe_name),
            verify=failing,
            guard=adguardcfg.guard_for(s.adguard_yaml, d),
        )

    exe = os.path.join(os.path.dirname(s.adguard_yaml), "AdGuardHome")
    return Env(
        run=_run,
        http=open_url,
        quiet=lambda: _quiet(s),
        verify=lambda: settled_failures(verify_json),
        exists=os.path.exists,
        read=lambda p: Path(p).read_text(encoding="utf-8", errors="replace"),
        write=_write,
        remove=_remove,
        store=store,
        spool=lambda fields: ledger.append_spool(ledger.spool_path(s), fields),
        reboot=lambda: _run(["systemctl", "reboot"]),
        lock=lambda: setup.install_lock(say=print),
        adguard_version=lambda: adguardcfg.binary_version(exe),
        adguard_upgrade=upgrade,
        adguard_extract=lambda tar, stage, floor: aghinstall.extract(tar, stage, floor=floor),
        arch=aghinstall.arch,
        installed=installed_kind,
    )


# ---- what the owner reads: tvgw updates, the brief, verify ----------------------------------------------
WEEKDAYS = ("Monday", "Tuesday", "Wednesday", "Thursday", "Friday", "Saturday", "Sunday")
MONTHS = (
    "January", "February", "March", "April", "May", "June",
    "July", "August", "September", "October", "November", "December",
)  # fmt: skip
INSTALL_BY_HAND = "sudo apt update && sudo apt upgrade, while nobody is watching the TV"
TVGW_BY_HAND_PACKAGE = (
    "curl -fsSL https://github.com/{repo}/releases/latest/download/get.sh | sudo TVGW_NO_SETUP=1 sh"
)
TVGW_BY_HAND_SOURCE = "git pull in its checkout, then sudo ./install.sh in its deploy folder"


def day(t: float) -> str:
    d = datetime.fromtimestamp(t)
    return f"{WEEKDAYS[d.weekday()]} {d.day} {MONTHS[d.month - 1]}"


def when(t: float) -> str:
    return f"{day(t)} at {datetime.fromtimestamp(t):%H:%M}"


def _pin() -> str:
    from tvgw import aghinstall

    return aghinstall.PIN["version"]


@dataclass
class Report:
    """`tvgw updates`: what each line says, and the same as JSON."""

    lines: list[str]
    data: dict


def report(
    s: Settings,
    now: float,
    check: dict | None,
    system: dict | None,
    runs: list[dict],
    kind: str | None,
    installed: str,
    adguard: Version | None,
    reboot: int | None,
) -> Report:
    """The three lines of `tvgw updates`, then the last night's run and a restart that waits. Each line
    that needs the owner names the command."""
    auto = s.update_install
    lines = [
        _tvgw_line(s, check, kind, installed, auto),
        _adguard_line(adguard, auto),
        _system_line(system, now, auto),
    ]
    if runs:
        lines.append("Last run: " + run_sentence(runs[-1]))
    if reboot is not None:
        then = (
            "The gateway restarts in its next quiet night window."
            if auto != "off"
            else "Run: sudo systemctl reboot"
        )
        lines.append(f"Restart: an update needs the gateway restarted to finish. {then}")
    data = {
        "tvgw": {"installed": installed, "kind": kind, "latest": (check or {}).get("latest"), "check": check},
        "adguard": {"running": dotted(adguard) if adguard else None, "tested": _pin()},
        "system": system,
        "install": auto,
        "check": s.update_check,
        "runs": runs[-5:],
        "reboot_needed": reboot is not None,
    }
    return Report(lines, data)


def _tvgw_line(s: Settings, check: dict | None, kind: str | None, installed: str, auto: str) -> str:
    head = f"tvgw: {installed} installed"
    latest = (check or {}).get("latest")
    have = parse_version(installed)
    newer = latest and have and (parse_version(latest) or ((0, 0, 0), True))[0] > have[0]
    if check and check.get("t"):
        head += f"; the latest release is {latest or 'not known yet'}, checked {when(check['t'])}"
        if not check.get("ok"):
            head += f" (that check failed: {check.get('why') or 'no answer'})"
    elif s.update_check == "off" and auto != "all":
        head += "; the gateway does not ask GitHub for newer releases (UPDATE_CHECK=off)"
    else:
        head += "; not checked yet"
    if not newer:
        return head + "."
    if kind == "source":
        return head + f". This gateway runs from a source checkout; to update it: {TVGW_BY_HAND_SOURCE}."
    if auto == "all" and kind == "package":
        return head + ". The gateway installs it in its next quiet night window."
    return head + ". To update: " + TVGW_BY_HAND_PACKAGE.format(repo=s.update_repo)


def _adguard_line(adguard: Version | None, auto: str) -> str:
    pin = parse_version(_pin())
    if adguard is None:
        return "AdGuard Home: not installed, or it does not say its version. Run: sudo tvgw adguard install"
    line = f"AdGuard Home: v{dotted(adguard)} running; this tvgw was tested with v{_pin()}"
    if pin and adguard < pin[0]:
        return line + ", so the running one is older. Run: sudo tvgw adguard upgrade --fetch"
    if auto != "off":
        return line + ". The gateway installs its newer patch releases in its quiet night window."
    return line + "."


def _system_line(system: dict | None, now: float, auto: str) -> str:
    if system is None:
        return "System: apt could not say whether updates are waiting."
    waiting, sec = system.get("waiting", 0), system.get("security", 0)
    if waiting:
        line = f"System: {waiting} update{'s' if waiting != 1 else ''} waiting"
        if sec:
            line += f", {sec} of them for security"
            if system.get("since"):
                line += f", waiting since {day(system['since'])}"
    else:
        line = "System: no updates waiting"
    lists_t = system.get("lists_t")
    if lists_t is None:
        line += "; the gateway cannot tell when it last looked for them"
    elif now - lists_t > LISTS_STALE:
        line += f"; the gateway has not looked for system updates since {day(lists_t)}"
    else:
        line += f"; the package lists are from {when(lists_t)}"
    if waiting and auto != "off":
        return line + ". The gateway installs them in its next quiet night window."
    if waiting:
        return line + f". To install them: {INSTALL_BY_HAND}."
    return line + "."


def run_sentence(run: dict, head: str | None = None) -> str:
    """One run in plain words, for `tvgw updates` and the brief's Updates line: after `head`, by default
    the run's day and time, or as a sentence of its own when the head is empty."""
    t = run.get("t")
    if head is None:
        head = f"{when(t)}: " if isinstance(t, (int, float)) else ""
    if run.get("trigger") == "reboot":
        v = run.get("verify", "")
        held = "the gateway's checks held" if v == "held" else f"the gateway's checks found trouble ({v[8:]})"
        return _sentence(head, f"after its restart for an update, {held}")
    if run.get("result") == WAITED:
        return _sentence(head, f"the gateway waited: {run.get('why') or 'the TV was in use'}")
    parts = []
    sysd, agh, tv = run.get("system") or {}, run.get("adguard") or {}, run.get("tvgw") or {}
    if sysd.get("outcome") == INSTALLED:
        n, k = sysd.get("count", 0), sysd.get("security", 0)
        parts.append(f"{n} system update{'s' if n != 1 else ''}" + (f" ({k} for security)" if k else ""))
    if agh.get("outcome") == INSTALLED:
        parts.append(f"AdGuard Home {agh.get('after')}")
    if tv.get("outcome") == INSTALLED:
        parts.append(f"tvgw {tv.get('after')}")
    out = []
    if parts:
        out.append("the gateway installed " + _and(parts))
    for name, d in (("AdGuard Home", agh), ("tvgw", tv)):
        if d.get("outcome") == ROLLED_BACK:
            out.append(
                f"{name} {d.get('after')} failed the gateway's checks, so {d.get('before')} was put back"
            )
        elif d.get("outcome") == FAILED:
            out.append(f"installing {name} {d.get('after')} failed: {d.get('why')}")
    if sysd.get("outcome") == FAILED:
        out.append(f"the system's updates stopped: {sysd.get('why')}")
    v = run.get("verify")
    if v and v != "held":
        out.append(f"afterwards the gateway's checks found trouble ({v[8:]})")
    elif v == "held" and parts:
        out.append("its checks held afterwards")
    if run.get("reboot") == "done":
        out.append("it restarted to finish them")
    elif run.get("reboot") in ("needed", "waiting"):
        out.append("a restart is still needed to finish them")
    return _sentence(head, "; ".join(out) if out else "nothing needed installing")


def _sentence(head: str, text: str) -> str:
    return head + text + "." if head else text[0].upper() + text[1:] + "."


def _and(parts: list[str]) -> str:
    return parts[0] if len(parts) == 1 else ", ".join(parts[:-1]) + " and " + parts[-1]


def brief_section(conn: sqlite3.Connection, a: float, b: float) -> dict:
    """The brief's `updates`: the runs in [a, b), what the weekly check found and the system's reading,
    all from the store's meta (no request, no command)."""
    runs = [r for r in load_runs(conn) if isinstance(r.get("t"), (int, float)) and a <= r["t"] < b]
    check = load_check(conn) or {}
    system = load_system(conn) or {}
    every = load_runs(conn)
    return {
        "runs": runs,
        "running": __version__,
        "latest": check.get("latest"),
        "latest_seen_t": check.get("seen_t"),
        "security": system.get("security", 0),
        "security_since": system.get("since"),
        "previous": next(
            (r for r in reversed(every) if isinstance(r.get("t"), (int, float)) and r["t"] < a), None
        ),
    }


def weekly(first_t: float | None, a: float, b: float) -> bool:
    """Whether a day [a, b) is one of the weekly days counted from `first_t`'s day: that day, 7 days on,
    14 days on... Read-only, so a brief written twice says the same."""
    if not isinstance(first_t, (int, float)) or first_t >= b:
        return False
    first = datetime.fromtimestamp(first_t).date()
    days = (datetime.fromtimestamp(a).date() - first).days
    return days >= 0 and days % 7 == 0
