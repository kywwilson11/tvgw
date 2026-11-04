"""AdGuard Home without the wizard: AdGuard's own release, pinned and hash-checked, set up through its
first-run API on loopback (design decision 52).

AdGuard Home with no AdGuardHome.yaml starts a first-run wizard that asks for no password. Started with
`--web-addr 127.0.0.1:<port>`, the wizard listens on loopback only, so nothing on the home network can
reach it, and tvgw answers it through AdGuard's own install API (`/control/install/check_config`, then
`/control/install/configure`, openapi.yaml at the pinned tag). AdGuard then writes a complete
AdGuardHome.yaml in its own schema: its page on 127.0.0.1:3000, DNS on 127.0.0.1:53 and one user,
`admin`, whose random password is kept root-only in /etc/tvgw/adguard-admin. `tvgw adguard apply` owns
the configuration from there (design decision 6); the package carries none of AdGuard (decision 25).

`state()` tells whose AdGuard a computer runs from what its YAML holds, so a gateway set up by hand
before this module existed reads as tvgw's. `install()` acts only where there is no AdGuard, or one
whose wizard never ran, and on a failure takes back only what its own run created.
"""

from __future__ import annotations

import base64
import contextlib
import fcntl
import hashlib
import ipaddress
import json
import os
import platform
import re
import secrets
import shutil
import socket
import ssl
import struct
import subprocess
import tarfile
import tempfile
import time
import urllib.error
import urllib.parse
import urllib.request
from collections.abc import Callable, Iterator
from dataclasses import dataclass
from pathlib import Path
from typing import BinaryIO

import yaml

from tvgw import __version__, adguard, adguardcfg
from tvgw.config import Settings
from tvgw.profile import Profile

# The release this tvgw installs. Each hash is the release's own checksums.txt line for the asset, and
# GitHub's API reports the same `sha256:` digest for it (both read 2026-11-03). tests/unit/test_aghinstall.py
# keeps the version at or above verify.ADGUARD_MIN, and .github/workflows/virtual.yml reads it from here
PIN = {
    "version": "0.107.79",
    "assets": {
        "arm64": (
            "AdGuardHome_linux_arm64.tar.gz",
            "3f7893c18e8aaadc456d0452839190561c306ca95175a2254958be80a769c1ae",
        ),
        "amd64": (
            "AdGuardHome_linux_amd64.tar.gz",
            "c48f4a43000665484c5ec28177de11a004759b620dae8f77b2aabefc9ef3687f",
        ),
    },
}
RELEASE_URL = "https://github.com/AdguardTeam/AdGuardHome/releases/download/v{version}/{asset}"
MAX_DOWNLOAD = 64 * 1024 * 1024  # the release is about 12 MB; a larger answer is not it
MAX_UNPACKED = 256 * 1024 * 1024  # the binary is about 36 MB unpacked
MARKER = "/var/lib/tvgw/.adguard-installed-by-tvgw"  # holds the version this module installed
ADMIN_FILE = "/etc/tvgw/adguard-admin"  # the page's user and password, root only
ADMIN_USER = "admin"
FIRSTRUN_UNIT = "tvgw-adguard-firstrun"  # the transient unit the wizard runs in
SERVICE = "AdGuardHome"
WEB = ("127.0.0.1", 3000)  # AdGuard's page once set up; `tvgw adguard apply` owns it as http.address
DNS = ("127.0.0.1", 53)  # where the wizard puts DNS; ADGUARD_LISTEN=gateway adds GW_IP at the apply
FIRSTRUN_PORTS = range(20000, 30000)  # the wizard's own loopback port, chosen at random among free ones
WIZARD_WAIT = 30.0  # seconds AdGuard has to start its wizard
LOGIN_WAIT = 10.0  # seconds its page has to move to WEB after the wizard (it rebinds in the background)
STATES = ("absent", "unconfigured", "tvgw", "old", "foreign")
FOREIGN = (
    "AdGuard Home is already set up on this computer, and not by tvgw, so tvgw installs no second one."
    " Taking it over would replace its blocklists, custom rules and upstreams, and move its page to this"
    " computer alone, for every device that uses it, not only the TV. If other devices use it, put tvgw on"
    " a computer of its own. If nothing else does, sudo tvgw adguard apply takes it over as it is, and"
    " stops first when it sees other devices; ADGUARD_TAKE_OVER=yes in /etc/tvgw/tvgw.conf then says"
    " nothing else depends on it"
)
# (adguard) what the take-over guard reads (takeover_refusal): the days of the query log, and how many of
# the other devices found a refusal names
OTHERS_DAYS = 7
OTHERS_NAMED = 3


# install() with ADGUARD_LISTEN=keep: the wizard put DNS on 127.0.0.1 alone, `tvgw adguard apply` then
# leaves dns.bind_hosts as it is, and the firewall sends the TV's lookups to GW_IP, where nothing answers
KEEP_NOTE = (
    "ADGUARD_LISTEN is keep, so AdGuard Home answers DNS on 127.0.0.1 alone and the TV, which asks"
    " {gw_ip}, gets no answer: set ADGUARD_LISTEN=gateway in /etc/tvgw/tvgw.conf before that apply"
)


class InstallError(RuntimeError):
    """A plain one-line reason, saying what was left as it was."""


class SeedError(InstallError):
    """AdGuard's wizard did not take tvgw's answers; nothing of AdGuard's configuration is tvgw's."""


class Port53Busy(SeedError):
    """Something else holds port 53 where AdGuard must answer."""


# ---- the release -------------------------------------------------------------------------------------


def pin_version() -> tuple[int, int, int]:
    major, minor, patch = (int(x) for x in PIN["version"].split("."))
    return major, minor, patch


def asset_url(arch_name: str) -> str:
    return RELEASE_URL.format(version=PIN["version"], asset=_asset(arch_name)[0])


def _asset(arch_name: str) -> tuple[str, str]:
    try:
        return PIN["assets"][arch_name]
    except KeyError:
        raise InstallError(
            f"tvgw pins no AdGuard Home release for {arch_name!r}; nothing was installed"
        ) from None


_MACHINES = {"aarch64": "arm64", "arm64": "arm64", "x86_64": "amd64", "amd64": "amd64"}


def arch(machine: str | None = None, bits: int | None = None) -> str:
    """`arm64` or `amd64`, the pinned asset for this computer. A 64-bit kernel under a 32-bit system
    (`aarch64` with 32-bit Python) gets neither: the binary would not run there."""
    m = (machine if machine is not None else platform.machine()).lower()
    b = bits if bits is not None else struct.calcsize("P") * 8
    name = _MACHINES.get(m)
    if name is None or b != 64:
        raise InstallError(
            f"tvgw pins AdGuard Home for 64-bit arm64 and amd64 Linux; this computer is {m or 'unknown'}"
            f" with a {b}-bit system; nothing was installed"
        )
    return name


def _open(url: str, timeout: float) -> BinaryIO:
    """The release over HTTPS with the system's certificates (the default SSL context)."""
    req = urllib.request.Request(url, headers={"User-Agent": f"tvgw/{__version__}"})
    return urllib.request.urlopen(req, timeout=timeout, context=ssl.create_default_context())


def fetch(
    arch_name: str,
    dest: str | Path,
    opener: Callable[[str, float], BinaryIO] = _open,
    timeout: float = 60.0,
) -> Path:
    """Download the pinned release for `arch_name` into `dest` and return its path. The bytes are hashed
    as they arrive and capped at MAX_DOWNLOAD; anything but the pinned hash is deleted and refused."""
    name, want = _asset(arch_name)
    url = asset_url(arch_name)
    path = Path(dest) / name
    part = path.with_name(path.name + ".part")
    digest, size = hashlib.sha256(), 0
    try:
        with opener(url, timeout) as resp, open(part, "wb") as out:
            while chunk := resp.read(1 << 16):
                size += len(chunk)
                if size > MAX_DOWNLOAD:
                    raise InstallError(
                        f"the download from {url} is over {MAX_DOWNLOAD >> 20} MB; nothing was installed"
                    )
                digest.update(chunk)
                out.write(chunk)
    except InstallError:
        part.unlink(missing_ok=True)
        raise
    except (OSError, ValueError) as e:  # urllib's URLError and HTTPError are OSErrors
        part.unlink(missing_ok=True)
        raise InstallError(
            f"could not download AdGuard Home from {url}: {e}; nothing was installed"
        ) from None
    except BaseException:
        part.unlink(missing_ok=True)
        raise
    if digest.hexdigest() != want:
        part.unlink(missing_ok=True)
        raise InstallError(
            "the downloaded AdGuard Home does not match tvgw's pinned hash; nothing was installed"
        )
    os.replace(part, path)
    return path


def _member_name(raw: str) -> str:
    """A member's path inside AdGuardHome/, without the `./` the release puts in front, or InstallError:
    an absolute path, a `..` or `.` part, or anything outside AdGuardHome/ is never written."""
    name = raw
    while name.startswith("./"):
        name = name[2:]
    name = name.rstrip("/")
    parts = name.split("/")
    if (
        raw.startswith("/")
        or "\0" in raw
        or any(p in ("", ".", "..") for p in parts)
        or parts[0] != "AdGuardHome"
    ):
        raise InstallError(
            f"the AdGuard Home archive holds {raw!r}, outside AdGuardHome/; nothing was installed"
        )
    return name


def extract(
    tar_path: str | Path,
    stage: str | Path,
    version: Callable[[str], tuple[int, int, int] | None] = adguardcfg.binary_version,
    floor: tuple[int, int, int] | None = None,
) -> Path:
    """Unpack the release into `stage` (an empty directory) and return the binary's path. Only regular
    files and directories under AdGuardHome/ are accepted: a link, a device, a FIFO, a member outside it
    or more than MAX_UNPACKED bytes refuses the whole archive, written by tvgw itself rather than by
    tarfile's own extraction. The binary must then report at least the floor (verify.ADGUARD_MIN)."""
    from tvgw import verify  # here: verify imports most of the package

    stage = Path(stage)
    with tarfile.open(tar_path, "r:gz") as tf:
        members, files, total = [], set(), 0
        for m in tf:
            name = _member_name(m.name)
            if not (m.isreg() or m.isdir()):
                raise InstallError(
                    f"the AdGuard Home archive holds {m.name!r}, which is not a plain file or directory;"
                    " nothing was installed"
                )
            if m.isreg():
                if name in files:  # a second copy would replace the first one checked
                    raise InstallError(
                        f"the AdGuard Home archive holds {m.name!r} twice; nothing was installed"
                    )
                files.add(name)
            total += m.size if m.isreg() else 0
            if total > MAX_UNPACKED:
                raise InstallError(
                    f"the AdGuard Home archive unpacks to over {MAX_UNPACKED >> 20} MB; nothing was installed"
                )
            members.append((name, m))
        for name, m in members:
            try:
                _unpack(tf, m, stage / name)
            except OSError as e:  # a file where a directory must go, or the reverse
                raise InstallError(
                    f"could not unpack {m.name!r} from the AdGuard Home archive: {e}; nothing was installed"
                ) from None
    exe = stage / "AdGuardHome" / "AdGuardHome"
    if not exe.is_file():
        raise InstallError("the AdGuard Home archive has no AdGuardHome/AdGuardHome; nothing was installed")
    os.chmod(exe.parent, 0o755)
    want = floor or verify.ADGUARD_MIN
    got = version(str(exe))
    if got is None or got < want:
        have = "no version" if got is None else "v" + ".".join(map(str, got))
        raise InstallError(
            f"the unpacked AdGuard Home reports {have}, not at least v{'.'.join(map(str, want))};"
            " nothing was installed"
        )
    return exe


def _unpack(tf: tarfile.TarFile, m: tarfile.TarInfo, target: Path) -> None:
    """One checked member of the archive written under the stage, as a new file or a directory."""
    if m.isdir():
        target.mkdir(mode=0o755, parents=True, exist_ok=True)
        return
    target.parent.mkdir(mode=0o755, parents=True, exist_ok=True)
    src = tf.extractfile(m)
    if src is None:
        raise InstallError(f"the AdGuard Home archive's {m.name!r} has no data; nothing was installed")
    # a new file, never through a link: the stage is empty and tvgw's own
    fd = os.open(target, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, "wb") as out:
        shutil.copyfileobj(src, out)
    os.chmod(target, 0o755 if m.mode & 0o111 else 0o644)


def fetch_release(
    dest: str | Path,
    arch_name: str | None = None,
    fetcher: Callable[[str, Path], Path] = fetch,
    version: Callable[[str], tuple[int, int, int] | None] = adguardcfg.binary_version,
) -> Path:
    """The pinned release downloaded into `dest`, checked and unpacked under `dest/stage`: the path of
    its AdGuardHome binary (`tvgw adguard upgrade --fetch` and `install()`)."""
    dest = Path(dest)
    tar = fetcher(arch_name or arch(), dest)
    stage = dest / "stage"
    stage.mkdir(mode=0o755)
    return extract(tar, stage, version=version)


# ---- the wizard ----------------------------------------------------------------------------------------

# loopback only, so never through a proxy the environment names (urllib would send 127.0.0.1 there)
_LOCAL = urllib.request.build_opener(urllib.request.ProxyHandler({}))


def _call(
    base: str,
    path: str,
    body: dict | None = None,
    timeout: float = 10.0,
    auth: tuple[str, str] | None = None,
) -> tuple[int, dict]:
    """One request to AdGuard's API on loopback: (status, the JSON answer, or {"text": ...} for the plain
    `OK` the wizard and the login answer with). (adguard) `auth`, a user and password, goes as HTTP
    basic auth, which AdGuard's page takes beside its login cookie (home/authhttp.go at the pinned tag)."""
    data = None if body is None else json.dumps(body).encode()
    req = urllib.request.Request(base + path, data=data, method="GET" if body is None else "POST")
    req.add_header("Content-Type", "application/json")
    if auth is not None:
        token = base64.b64encode(f"{auth[0]}:{auth[1]}".encode()).decode("ascii")
        req.add_header("Authorization", f"Basic {token}")
    try:
        with _LOCAL.open(req, timeout=timeout) as r:
            return r.status, _decoded(r.read(65536))
    except urllib.error.HTTPError as e:
        return e.code, {"error": e.read(4096).decode("utf-8", "replace").strip()}


def _decoded(raw: bytes) -> dict:
    text = raw.decode("utf-8", "replace")
    try:
        value = json.loads(text) if text.strip() else {}
    except ValueError:
        return {"text": text.strip()}
    return value if isinstance(value, dict) else {"value": value}


def wait_for_wizard(
    base: str,
    wait: float = WIZARD_WAIT,
    sleep: Callable[[float], None] = time.sleep,
    alive: Callable[[], bool] | None = None,
) -> None:
    """Return once the wizard answers at `base`; SeedError after `wait` seconds, or at once when `alive`
    says the process running it stopped."""
    deadline = time.monotonic() + wait
    while time.monotonic() < deadline:
        try:
            code, _ = _call(base, "/control/install/get_addresses", timeout=2.0)
            if code == 200:
                return
        except OSError:
            pass
        if alive is not None and not alive():
            raise SeedError(
                f"AdGuard Home's first run stopped before its wizard answered (journalctl -u {FIRSTRUN_UNIT})"
            )
        sleep(0.5)
    raise SeedError(
        f"AdGuard Home did not start its first run within {wait:.0f} seconds (journalctl -u {FIRSTRUN_UNIT})"
    )


def new_password() -> str:
    """32 random characters from the URL-safe alphabet (24 bytes)."""
    return secrets.token_urlsafe(24)


def seed(
    base: str,
    password: str,
    username: str = ADMIN_USER,
    web: tuple[str, int] = WEB,
    dns: tuple[str, int] = DNS,
) -> None:
    """Answer the wizard at `base`: its page on `web`, DNS on `dns`, one user. AdGuard checks both
    addresses first, and a taken one stops here with AdGuard's own reason, before anything is written."""
    want = {"web": {"ip": web[0], "port": web[1]}, "dns": {"ip": dns[0], "port": dns[1]}}
    code, chk = _call(base, "/control/install/check_config", {**want, "set_static_ip": False})
    if code != 200:
        raise SeedError(f"AdGuard Home refused tvgw's first-run settings ({code}): {_why(chk)}")
    dns_status = str((chk.get("dns") or {}).get("status") or "")
    if dns_status:
        raise Port53Busy(f"port {dns[1]} on {dns[0]} is not free for AdGuard Home: {dns_status[:200]}")
    web_status = str((chk.get("web") or {}).get("status") or "")
    if web_status:
        raise SeedError(f"port {web[1]} on {web[0]} is not free for AdGuard Home's page: {web_status[:200]}")
    code, out = _call(
        base, "/control/install/configure", {**want, "username": username, "password": password}
    )
    if code != 200:
        raise SeedError(f"AdGuard Home did not take tvgw's first-run settings ({code}): {_why(out)}")


def _why(answer: dict) -> str:
    return str(answer.get("error") or answer.get("text") or answer)[:200]


def check_users(yaml_path: str, username: str = ADMIN_USER) -> None:
    """The YAML AdGuard wrote must hold exactly tvgw's one user. The wizard asks for no password, so a
    local process could have answered it first and made a user of its own (review E-F28)."""
    try:
        cfg = adguardcfg.load_yaml(yaml_path)
    except (OSError, yaml.YAMLError) as e:
        raise SeedError(f"cannot read the {yaml_path} AdGuard Home wrote: {e}") from None
    users = cfg.get("users") if isinstance(cfg, dict) else None
    names = [u.get("name") for u in users if isinstance(u, dict)] if isinstance(users, list) else []
    ok = isinstance(users, list) and len(users) == 1 and names == [username]
    if ok and not str(users[0].get("password") or "").startswith("$2"):  # AdGuard keeps a bcrypt hash
        ok = False
    if not ok:
        raise SeedError(
            f"{yaml_path} holds {len(names)} user(s) ({', '.join(map(str, names)) or 'none'}), not tvgw's one"
            f" {username!r}: something else may have answered AdGuard Home's wizard first"
        )


def confirm_login(
    base: str,
    password: str,
    username: str = ADMIN_USER,
    wait: float = LOGIN_WAIT,
    sleep: Callable[[float], None] = time.sleep,
) -> None:
    """The page at `base` must let tvgw's user in with tvgw's password: the user in the YAML is then the
    one tvgw made, not one with the same name. AdGuard moves its page to the new address in the
    background after the wizard, so a refused connection is retried for `wait` seconds."""
    deadline = time.monotonic() + wait
    while True:
        try:
            code, out = _call(base, "/control/login", {"name": username, "password": password}, timeout=5.0)
        except OSError:
            if time.monotonic() >= deadline:
                raise SeedError(f"AdGuard Home's page did not come up at {base} after its wizard") from None
            sleep(0.5)
            continue
        if code == 200:
            return
        raise SeedError(
            f"the password tvgw set does not open AdGuard Home's page ({code}: {_why(out)}): something"
            " else may have answered its wizard first"
        )


def first_run(
    base: str,
    yaml_path: str,
    password: str,
    username: str = ADMIN_USER,
    web: tuple[str, int] = WEB,
    dns: tuple[str, int] = DNS,
    alive: Callable[[], bool] | None = None,
    wait: float = WIZARD_WAIT,
) -> None:
    """Everything between AdGuard's start in wizard mode at `base` and a configuration that is tvgw's:
    wait for the wizard, answer it, check the YAML holds tvgw's one user, and log in with it. The
    namespace test runs this against the real binary; `install()` adds the units around it."""
    wait_for_wizard(base, wait=wait, alive=alive)
    seed(base, password, username=username, web=web, dns=dns)
    check_users(yaml_path, username)
    confirm_login(f"http://{web[0]}:{web[1]}", password, username)


# ---- whose AdGuard it is --------------------------------------------------------------------------------


def _client_ids(s: Settings) -> set[str]:
    from tvgw.config import PLACEHOLDER_MAC

    return {x.strip().lower() for x in (s.tv_ip, s.tv_mac) if x and x.strip() and x != PLACEHOLDER_MAC}


def carries_tvgw(cfg: object, profile: Profile | None, s: Settings) -> bool:
    """Does this AdGuard configuration hold what `tvgw adguard apply` writes? Either the TV's client entry
    (a persistent client carrying TV_IP or TV_MAC among its ids), or every must-allow exception the
    profile generates in `user_rules`. Every gateway set up by hand under decision 25 has both."""
    if not isinstance(cfg, dict):
        return False
    ours = _client_ids(s)
    clients = cfg.get("clients")
    persistent = clients.get("persistent") if isinstance(clients, dict) else None
    for c in persistent if isinstance(persistent, list) else []:
        ids = c.get("ids") if isinstance(c, dict) else None
        if isinstance(ids, list) and ours & {str(i).strip().lower() for i in ids}:
            return True
    if profile is None or not profile.must_allow:
        return False
    rules = cfg.get("user_rules")
    have = {str(r).strip() for r in rules} if isinstance(rules, list) else set()
    must = {f"@@||{host}^$important" for host in profile.must_allow}
    return must <= have


def state(
    yaml_path: str,
    marker: str,
    profile: Profile | None,
    s: Settings,
    version: Callable[[str], tuple[int, int, int] | None] = adguardcfg.binary_version,
    floor: tuple[int, int, int] | None = None,
) -> str:
    """`absent`: no AdGuard Home binary beside `yaml_path`. `unconfigured`: a binary and no YAML, so its
    wizard never ran. `tvgw`: tvgw's marker is there, or the YAML holds what `tvgw adguard apply` writes
    (`carries_tvgw()`). `old`: tvgw's, below the floor. `foreign`: set up, and none of that, which
    includes a YAML that cannot be read."""
    from tvgw import verify

    exe = os.path.join(os.path.dirname(os.path.abspath(yaml_path)), "AdGuardHome")
    if not (os.path.isfile(exe) and os.access(exe, os.X_OK)):
        return "absent"
    if not os.path.lexists(yaml_path):
        return "unconfigured"
    ours = os.path.exists(marker)
    if not ours:
        try:
            ours = carries_tvgw(adguardcfg.load_yaml(yaml_path), profile, s)
        except (OSError, yaml.YAMLError):
            ours = False
    if not ours:
        return "foreign"
    got = version(exe)
    return "old" if got is None or got < (floor or verify.ADGUARD_MIN) else "tvgw"


# ---- whether tvgw may take it over ----------------------------------------------------------------------
# (adguard) `tvgw adguard apply` puts AdGuard's page on loopback, owns its custom rules, lists and upstreams
# and, with ADGUARD_LISTEN=gateway, its DNS addresses. On an AdGuard Home the household uses, every other
# device loses its resolver and the admin the page, while `tvgw verify` says OK. So an AdGuard Home that is
# `foreign` and serves more than the TV and this computer is taken over only on the owner's yes: the
# evidence is where it listens and whom its query log answered (design decision 52, its note of 2026-11-04)


@dataclass(frozen=True)
class Others:
    """(adguard) What says an AdGuard Home serves more than the TV and this computer."""

    everywhere: bool = False  # dns.bind_hosts is missing, empty, or holds 0.0.0.0 or ::
    addresses: tuple[str, ...] = ()  # the bind_hosts beyond GW_IP and loopback
    clients: tuple[str, ...] = ()  # the query log's clients outside TV_NET and loopback, newest first

    def __bool__(self) -> bool:
        return self.everywhere or bool(self.addresses) or bool(self.clients)

    def why(self) -> str:
        """The evidence in one clause, for a refusal or setup's question."""
        parts = []
        if self.everywhere:
            parts.append("it answers DNS on every address of this computer")
        elif self.addresses:
            parts.append(f"it also answers DNS on {_and(list(self.addresses))}")
        if self.clients:
            named = list(self.clients[:OTHERS_NAMED])
            more = len(self.clients) - len(named)
            who = _and([*named, f"{more} more"]) if more else _and(named)
            parts.append(f"in the last {OTHERS_DAYS} days it answered {who}")
        return ", and ".join(parts)


def _and(items: list[str]) -> str:
    return items[0] if len(items) == 1 else ", ".join(items[:-1]) + " and " + items[-1]


def _address(host: str) -> ipaddress.IPv4Address | ipaddress.IPv6Address | None:
    try:
        a = ipaddress.ip_address(host.strip().strip("[]"))
    except ValueError:
        return None
    if isinstance(a, ipaddress.IPv6Address) and a.ipv4_mapped is not None:
        return a.ipv4_mapped
    return a


def _ours(host: str, s: Settings) -> bool:
    """A client that is this computer (loopback) or on the TV side (TV_NET, GW_IP among it)."""
    a = _address(host)
    if a is None:
        return False
    if a.is_loopback:
        return True
    try:
        return isinstance(a, ipaddress.IPv4Address) and a in ipaddress.IPv4Network(s.tv_net)
    except ValueError:
        return str(a) == s.gw_ip


def listens_beyond(cfg: object, s: Settings) -> Others:
    """(adguard) Where an AdGuard config answers DNS beyond GW_IP and loopback. A config whose
    `dns.bind_hosts` is missing, empty or not a list listens everywhere, as do 0.0.0.0 and ::; an entry
    that is not an address is named as it is."""
    dns = cfg.get("dns") if isinstance(cfg, dict) else None
    hosts = dns.get("bind_hosts") if isinstance(dns, dict) else None
    if not isinstance(hosts, list) or not hosts:
        return Others(everywhere=True)
    wide: list[str] = []
    for h in hosts:
        text = str(h).strip()
        a = _address(text)
        if a is not None and a.is_unspecified:
            return Others(everywhere=True)
        if a is None or not (a.is_loopback or str(a) == s.gw_ip):
            wide.append(text)
    return Others(addresses=tuple(dict.fromkeys(wide)))


def querylog_path(cfg: object, s: Settings) -> str:
    """(adguard) The query-log file AdGuard writes: in `querylog.dir_path` when its config names one (a
    relative one from AdGuard's own directory), else the settings' (AdGuard's data directory)."""
    log = cfg.get("querylog") if isinstance(cfg, dict) else None
    folder = log.get("dir_path") if isinstance(log, dict) else None
    if isinstance(folder, str) and folder.strip():
        home = os.path.dirname(os.path.abspath(s.adguard_yaml))
        return os.path.join(home, folder.strip(), os.path.basename(s.adguard_querylog))
    return s.adguard_querylog


def answered_others(s: Settings, cfg: object = None, now: float | None = None) -> tuple[str, ...]:
    """(adguard) The clients AdGuard's query log answered in the last OTHERS_DAYS days that are neither the
    TV side (TV_NET) nor this computer (loopback), newest first: `adguard.clients_since()` reads the
    end of the log and its rotated copy, at most `adguard.CLIENTS_MAX_BYTES` of each."""
    since = (time.time() if now is None else now) - OTHERS_DAYS * 86400
    clients, _ = adguard.clients_since(querylog_path(cfg, s), since)
    others = [ip for ip in clients if not _ours(ip, s)]
    return tuple(sorted(others, key=lambda ip: -clients[ip]))


def takeover_refusal(
    s: Settings,
    profile: Profile | None,
    cfg: object = None,
    marker: str | None = None,
    now: float | None = None,
) -> str | None:
    """(adguard) Why `tvgw adguard apply` must not take this AdGuard Home over, in one clause, or None.
    None when ADGUARD_TAKE_OVER=yes, when the AdGuard is not `foreign` (tvgw's by its marker or its
    content, or not set up), and when a foreign one serves the TV and this computer alone: it listens on
    nothing beyond GW_IP and loopback, and its query log answered no other client in the last
    OTHERS_DAYS days. `cfg` is the YAML already read, else it is read here; `marker` is MARKER unless
    given; the binary is never run."""
    if s.adguard_take_over == "yes":
        return None
    mark = MARKER if marker is None else marker
    if state(s.adguard_yaml, mark, profile, s, version=lambda exe: None) != "foreign":
        return None
    if cfg is None:
        try:
            cfg = adguardcfg.load_yaml(s.adguard_yaml)
        except (OSError, yaml.YAMLError):
            cfg = None  # where it listens is unknown: as everywhere
    binds = listens_beyond(cfg, s)
    others = Others(binds.everywhere, binds.addresses, answered_others(s, cfg, now))
    return others.why() if others else None


# ---- the computer around it ---------------------------------------------------------------------------


def _run(argv: list[str], cwd: str | None = None) -> subprocess.CompletedProcess:
    try:
        return subprocess.run(
            argv,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=120,
            cwd=cwd,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired) as e:
        return subprocess.CompletedProcess(argv, 127, "", str(e))


def free_port(
    ports: range = FIRSTRUN_PORTS, tries: int = 20, pick: Callable[[range], int] = secrets.choice
) -> int:
    """A random port of `ports` that nothing holds on 127.0.0.1 now, for the wizard's own address."""
    for _ in range(tries):
        port = pick(ports)
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            try:
                sock.bind(("127.0.0.1", port))
            except OSError:
                continue
        return port
    raise InstallError(
        f"no free port from {ports.start} to {ports.stop - 1} on 127.0.0.1 for AdGuard Home's first run"
    )


_SS_USER = re.compile(r'\("([^"]+)",pid=(\d+)')


def port53_holder(run: Callable[..., subprocess.CompletedProcess] = _run) -> str:
    """What holds port 53 (UDP or TCP), as `ss` sees it: `dnsmasq (pid 812) on 0.0.0.0:53`, several joined
    with `; `, or `nothing` when ss shows none. Without root, ss names the address and not the process."""
    found: list[str] = []
    for flags in ("-Hlnup", "-Hltnp"):
        out = run(["ss", flags, "sport = :53"])
        for line in (out.stdout or "").splitlines():
            fields = line.split()
            if len(fields) < 5:
                continue
            procs = [f"{name} (pid {pid})" for name, pid in _SS_USER.findall(line)]
            item = f"{', '.join(procs) or 'a process'} on {fields[3]}"
            if item not in found:
                found.append(item)
    return "; ".join(found) or "nothing"


def _unit_loaded(run: Callable[..., subprocess.CompletedProcess], unit: str) -> bool:
    out = run(["systemctl", "show", "-P", "LoadState", unit])
    return out.returncode == 0 and (out.stdout or "").strip() == "loaded"


def _unit_active(run: Callable[..., subprocess.CompletedProcess], unit: str) -> bool:
    return run(["systemctl", "is-active", "--quiet", unit]).returncode == 0


def _write_private(path: str, text: str, mode: int) -> None:
    """`text` in a new file beside `path`, fsynced, with `mode`, then renamed over it: no reader ever sees
    a partial file, and the mode is set before the first byte is written."""
    directory = os.path.dirname(os.path.abspath(path))
    fd, tmp = tempfile.mkstemp(prefix=".tvgw-", dir=directory)  # created 0600
    try:
        os.fchmod(fd, mode)
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            fh.write(text)
            fh.flush()
            os.fsync(fh.fileno())
        os.replace(tmp, path)
    except BaseException:
        with contextlib.suppress(FileNotFoundError):
            os.unlink(tmp)
        raise
    dfd = os.open(directory, os.O_RDONLY)
    try:
        os.fsync(dfd)
    finally:
        os.close(dfd)


def write_admin(path: str, username: str, password: str) -> None:
    """The page's user and password, root-only (0600), atomically. `sudo tvgw adguard ui` names it."""
    os.makedirs(os.path.dirname(os.path.abspath(path)), mode=0o755, exist_ok=True)
    _write_private(
        path,
        f"# AdGuard Home's page (sudo tvgw adguard ui), written by tvgw adguard install\n"
        f"user={username}\npassword={password}\n",
        0o600,
    )


def read_admin(path: str = ADMIN_FILE) -> dict[str, str]:
    """The `user` and `password` lines of the admin file."""
    out: dict[str, str] = {}
    for line in Path(path).read_text(encoding="utf-8").splitlines():
        key, sep, value = line.partition("=")
        if sep and key in ("user", "password"):
            out[key] = value
    return out


def write_marker(path: str, version: str) -> None:
    """tvgw's marker: AdGuard Home was installed by tvgw, at this version (0640, the state directory's
    group, like the other files there)."""
    os.makedirs(os.path.dirname(os.path.abspath(path)), mode=0o751, exist_ok=True)
    _write_private(path, f"{version}\n", 0o640)


@contextlib.contextmanager
def _install_lock(marker: str) -> Iterator[None]:
    """One install at a time, beside the marker; refused at once rather than waited for."""
    directory = os.path.dirname(os.path.abspath(marker))
    os.makedirs(directory, mode=0o751, exist_ok=True)
    fd = os.open(os.path.join(directory, ".adguard-install.lock"), os.O_RDWR | os.O_CREAT, 0o600)
    try:
        try:
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            raise InstallError("another tvgw adguard install is running") from None
        yield
    finally:
        os.close(fd)


@dataclass
class Host:
    """What `install()` does to the computer beyond its own files. The defaults are the live system;
    the unit tests pass fakes, and the container tier (W22) runs the defaults."""

    run: Callable[..., subprocess.CompletedProcess] = _run
    fetch: Callable[[str, Path], Path] = fetch
    version: Callable[[str], tuple[int, int, int] | None] = adguardcfg.binary_version
    first_run: Callable[..., None] = first_run
    free_port: Callable[[], int] = free_port
    arch: Callable[[], str] = arch


def _put_release(home: str, host: Host, binary_only: bool) -> None:
    """Download, check and unpack the pinned release beside `home`, then move it into place: the whole
    directory when there is none, else each file into it with the binary last, or (`binary_only`) the
    binary alone over one that is too old. The download never touches `home` until it has passed."""
    parent = os.path.dirname(os.path.abspath(home))
    os.makedirs(parent, mode=0o755, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix=".tvgw-adguard-", dir=parent) as tmp:
        exe = fetch_release(tmp, arch_name=host.arch(), fetcher=host.fetch, version=host.version)
        src = exe.parent
        if not os.path.exists(home):
            os.replace(src, home)
            return
        names = ["AdGuardHome"] if binary_only else sorted(os.listdir(src), key=lambda n: n == "AdGuardHome")
        for name in names:
            os.replace(src / name, os.path.join(home, name))


def install(
    s: Settings,
    profile: Profile | None,
    host: Host | None = None,
    marker: str = MARKER,
    admin: str = ADMIN_FILE,
) -> list[str]:
    """Install AdGuard Home's pinned release and set it up without its wizard, or say why not. Returns
    what was done, a line each; raises InstallError with the reason otherwise.

    It acts only from `absent` (it installs the release, then sets it up) or `unconfigured` (it sets the
    binary up, replacing it first with the pinned release when it is below the floor). `tvgw` returns at
    once; `old` and `foreign` are refused with the way forward. The wizard runs in a transient unit on
    127.0.0.1 at a random port. After it, the YAML must hold tvgw's one user and the password must open
    the page; then the unit stops, AdGuard's own `-s install --no-check-update` registers and starts the
    service (or the existing unit is started), and the marker is written last.

    A failure stops the transient unit and the service it started, removes the YAML and the admin file
    only when this run created them, keeps the binary, and names what holds port 53 when that was it.
    With ADGUARD_LISTEN other than gateway the last line says the TV gets no answer until it is."""
    from tvgw import verify

    host = host or Host()
    yaml_path = os.path.abspath(s.adguard_yaml)
    home = os.path.dirname(yaml_path)
    exe = os.path.join(home, "AdGuardHome")
    floor = verify.ADGUARD_MIN
    floor_text = "v" + ".".join(map(str, floor))
    with _install_lock(marker):
        st = state(yaml_path, marker, profile, s, version=host.version)
        if st == "tvgw":
            return [f"AdGuard Home in {home} is already set up for tvgw; nothing to do"]
        if st == "old":
            raise InstallError(
                f"AdGuard Home in {home} is tvgw's but below {floor_text};"
                " run sudo tvgw adguard upgrade --fetch"
            )
        if st == "foreign":
            raise InstallError(FOREIGN)
        done: list[str] = []
        if st == "absent":
            _put_release(home, host, binary_only=False)
            done.append(
                f"installed AdGuard Home v{PIN['version']} in {home}, checked against tvgw's pinned SHA-256"
            )
            if os.path.lexists(yaml_path):  # a YAML without its binary: someone's, never answered for them
                after = state(yaml_path, marker, profile, s, version=host.version)
                done.append(f"{yaml_path} was already there, so its wizard was not run (state: {after})")
                return done
        else:
            got = host.version(exe)
            if got is None or got < floor:
                _put_release(home, host, binary_only=True)
                done.append(
                    f"replaced the AdGuard Home binary in {home}, below {floor_text} and never set up,"
                    f" with v{PIN['version']}"
                )
        done += _set_up(host, yaml_path, home, exe, marker, admin)
        if s.adguard_listen != "gateway":  # the wizard put DNS on loopback, and keep leaves it there
            done.append(KEEP_NOTE.format(gw_ip=s.gw_ip))
        return done


def _set_up(host: Host, yaml_path: str, home: str, exe: str, marker: str, admin: str) -> list[str]:
    """The first run, for `install()`: the wizard, the checks, the service, the marker; on any failure
    the run-scoped rollback."""
    run = host.run
    service = _unit_loaded(run, SERVICE)  # AdGuard's own unit from an install whose wizard never ran
    if service:  # it is serving that wizard, unauthenticated, on AdGuard's default address: stop it
        run(["systemctl", "stop", SERVICE])
    run(["systemctl", "stop", FIRSTRUN_UNIT])  # one an interrupted install left running
    created_yaml = not os.path.lexists(yaml_path)
    wrote_admin = started = served = False
    port = host.free_port()
    password = new_password()
    try:
        write_admin(admin, ADMIN_USER, password)
        wrote_admin = True
        argv = [
            "systemd-run",
            f"--unit={FIRSTRUN_UNIT}",
            "--collect",
            f"--property=WorkingDirectory={home}",
            "--",
            exe,
            "--web-addr",
            f"127.0.0.1:{port}",
            "--no-check-update",
            "-w",
            home,
            "-c",
            yaml_path,
        ]
        out = run(argv)
        if out.returncode != 0:
            raise InstallError(f"systemd-run could not start AdGuard Home's first run: {_tail(out)}")
        started = True
        host.first_run(
            f"http://127.0.0.1:{port}", yaml_path, password, alive=lambda: _unit_active(run, FIRSTRUN_UNIT)
        )
        out = run(["systemctl", "stop", FIRSTRUN_UNIT])
        if out.returncode != 0:
            raise InstallError(f"could not stop AdGuard Home's first run: {_tail(out)}")
        started = False
        served = True
        if service:
            out = run(["systemctl", "start", SERVICE])
            how = f"started {SERVICE}.service"
        else:
            out = run([exe, "-s", "install", "--no-check-update"], cwd=home)
            how = (
                f"registered {SERVICE}.service with AdGuard's own -s install --no-check-update and started it"
            )
        if out.returncode != 0:
            raise InstallError(f"AdGuard Home's service did not start: {_tail(out)}")
        write_marker(marker, PIN["version"])
    except BaseException as e:
        undone = _roll_back(run, yaml_path, admin, created_yaml, wrote_admin, started, served, service)
        why = str(e) if isinstance(e, InstallError) else f"{type(e).__name__}: {e}"
        if isinstance(e, Port53Busy):
            why += f"; port 53 is held by {port53_holder(run)}"
        if isinstance(e, Exception):
            raise InstallError(f"{why}; {undone}") from e
        raise
    return [
        f"set it up without its wizard: its page on {WEB[0]}:{WEB[1]} (sudo tvgw adguard ui),"
        f" DNS on {DNS[0]}:{DNS[1]}",
        f"its user and password are in {admin} (root only)",
        how,
        "next: sudo tvgw adguard apply, which install.sh also runs at its AdGuard step",
    ]


def _roll_back(
    run: Callable[..., subprocess.CompletedProcess],
    yaml_path: str,
    admin: str,
    created_yaml: bool,
    wrote_admin: bool,
    started: bool,
    served: bool,
    had_service: bool = False,
) -> str:
    """Take back what this run did, and say what was kept. The binary always stays, and so does a YAML
    this run did not create. AdGuard's own unit, when it was there before and served the open wizard,
    stays stopped: started again with no YAML it would serve that wizard on AdGuard's default address."""
    if started:
        run(["systemctl", "stop", FIRSTRUN_UNIT])
    if served:  # without the YAML it would serve an open wizard on AdGuard's default address
        run(["systemctl", "stop", SERVICE])
    removed = []
    if created_yaml and os.path.lexists(yaml_path):
        with contextlib.suppress(FileNotFoundError):
            os.unlink(yaml_path)
        removed.append(yaml_path)
    if wrote_admin:
        with contextlib.suppress(FileNotFoundError):
            os.unlink(admin)
        removed.append(admin)
    kept = f"the binary in {os.path.dirname(yaml_path)} stays"
    if had_service:
        kept += f" and {SERVICE}.service stays stopped"
    return f"removed {', '.join(removed)}; {kept}" if removed else f"nothing was removed; {kept}"


def _tail(out: subprocess.CompletedProcess) -> str:
    text = ((out.stderr or "") + (out.stdout or "")).strip().splitlines()
    return (text[-1] if text else f"exit {out.returncode}")[:200]


# ---- the page --------------------------------------------------------------------------------------------


def _http_address(cfg: dict) -> tuple[str, str, str]:
    """(the YAML's `http.address` as written, its host, its port); WEB's host and port when it names no
    port."""
    http = cfg.get("http") if isinstance(cfg, dict) else None
    address = str(http.get("address") or "") if isinstance(http, dict) else ""
    ip, _, port = address.rpartition(":")
    if not port.isdigit():
        ip, port = WEB[0], str(WEB[1])
    return address, ip, port


def ui_lines(s: Settings, admin: str = ADMIN_FILE) -> tuple[list[str], int]:
    """How to open AdGuard Home's page from another computer, where its password is, and that tvgw puts
    its own keys back (`sudo tvgw adguard ui`), with the exit status."""
    try:
        cfg = adguardcfg.load_yaml(s.adguard_yaml)
    except FileNotFoundError:
        return ["AdGuard Home is not set up on this computer yet: sudo tvgw adguard install"], 1
    except PermissionError:
        return [f"cannot read {s.adguard_yaml}: run sudo tvgw adguard ui"], 1
    except (OSError, yaml.YAMLError) as e:
        return [f"cannot read {s.adguard_yaml}: {e}"], 1
    address, ip, port = _http_address(cfg)
    lines = []
    if ip.strip("[]") in ("127.0.0.1", "::1", "localhost"):
        lines.append(f"AdGuard Home's page is open only on this computer, at http://127.0.0.1:{port}.")
    else:
        lines.append(
            f"AdGuard Home's page listens on {address}, where other computers can reach it;"
            f" sudo tvgw adguard apply moves it to {WEB[0]}:{WEB[1]}."
        )
    lines += [
        "To see it from another computer, run this on that computer:",
        f"  ssh -L {port}:127.0.0.1:{port} <you>@<this computer>",
        f"then open http://127.0.0.1:{port} there.",
    ]
    if os.path.exists(admin):
        lines.append(f"Its user and password: sudo cat {admin}")
    else:
        lines.append(
            "Its user and password are the ones chosen in AdGuard Home's own wizard; tvgw did not set it up."
        )
    lines.append(
        "Look, do not change: tvgw puts its lists, rules and settings back at its next apply"
        " (sudo tvgw adguard diff shows what differs)."
    )
    return lines, 0


# ---- (adguard) asking AdGuard Home about one name: tvgw check ---------------------------------------------

CHECK_HOST = "/control/filtering/check_host"  # GET ?name=&client=, openapi.yaml at the pinned tag
NO_PASSWORD = (
    "AdGuard Home's page needs its password, and tvgw keeps none for this one: it was set up through its"
    " own first-run page, not sudo tvgw adguard install. Run the command at a terminal, which asks for it"
    " and keeps it nowhere, or put it in {admin} as two lines, user=<name> and password=<password>,"
    " readable by root alone"
)


class AskError(RuntimeError):
    """AdGuard Home could not be asked, said in one plain line."""


def page_base(cfg: dict) -> str:
    """The base URL of AdGuard Home's page on this computer, from the YAML's `http.address`: loopback
    when the page listens there or on every address, which is where tvgw asks it."""
    _, ip, port = _http_address(cfg)
    ip = ip.strip("[]")
    if ip in ("", "0.0.0.0", "::", "localhost", "::1"):
        ip = "127.0.0.1"
    return f"http://[{ip}]:{port}" if ":" in ip else f"http://{ip}:{port}"


def credentials(
    cfg: dict, admin: str = ADMIN_FILE, ask: Callable[[str, bool], str] | None = None
) -> tuple[str, str]:
    """(user, password) for AdGuard Home's API: the admin file `install()` wrote, or, for an AdGuard set
    up through its own wizard, the YAML's user with the password `ask(prompt, secret)` reads from the
    terminal, used for one request and kept nowhere. ('', '') when the YAML has no user, since AdGuard
    then asks for none. AskError when there is no way to the password."""
    try:
        found = read_admin(admin)
    except FileNotFoundError:
        found = None
    except OSError as e:
        raise AskError(f"cannot read {admin}: {e.strerror or e}") from None
    if found is not None:
        if not found.get("user") or not found.get("password"):
            raise AskError(f"{admin} holds no user= and password= lines")
        return found["user"], found["password"]
    users = cfg.get("users") if isinstance(cfg, dict) else None
    names = (
        [str(u["name"]) for u in users if isinstance(u, dict) and u.get("name")]
        if isinstance(users, list)
        else []
    )
    if not names:
        return "", ""
    if ask is None:
        raise AskError(NO_PASSWORD.format(admin=admin))
    try:
        user = (
            names[0] if len(names) == 1 else ask(f"AdGuard Home's user ({', '.join(names)}): ", False).strip()
        )
        password = ask(f"AdGuard Home's password for {user}: ", True)
    except (EOFError, KeyboardInterrupt):
        raise AskError("no password was given; nothing was asked") from None
    if not password:
        raise AskError("no password was given; nothing was asked")
    return user, password


def check_host(base: str, name: str, client: str, user: str, password: str, timeout: float = 10.0) -> dict:
    """AdGuard Home's own verdict on `name` for `client` (`GET /control/filtering/check_host`): its
    `reason`, the `rules` that decided with their `filter_list_id`, and `service_name` for a blocked
    service. With a user, the request carries it as HTTP basic auth, which AdGuard's page takes beside
    its login. Raises AskError with the reason when AdGuard could not be asked or did not answer."""
    query = urllib.parse.urlencode({"name": name, **({"client": client} if client else {})})
    auth = (user, password) if user else None
    try:
        code, answer = _call(base, f"{CHECK_HOST}?{query}", timeout=timeout, auth=auth)
    except OSError as e:  # refused, timed out or unreachable: urllib's errors are OSErrors
        why = getattr(e, "reason", None) or e.strerror or e
        raise AskError(
            f"AdGuard Home's page at {base} did not answer ({why}): is it running?"
            " systemctl status AdGuardHome"
        ) from None
    if code in (401, 403):
        raise AskError(
            f"AdGuard Home did not take the user and password ({code}); after several refusals it takes no"
            " login from this computer for a while"
        )
    if code != 200:
        raise AskError(f"AdGuard Home answered {code}: {_why(answer)}")
    if not isinstance(answer.get("reason"), str):
        raise AskError(f"AdGuard Home's answer names no reason: {str(answer)[:200]}")
    return answer
