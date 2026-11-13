"""`tvgw setup`: the guided installer. Find the TV, let the owner pick it, pair its LAN API read-only, write
the settings file, run the installer, verify, and say in plain words whether the gateway holds.

It adds no install logic of its own. Discovery is `discover.gather()`, pairing and the first reading
are `lgwebos.pair()`, the settings file is written by `config.save_conf()`, applying is the installer
(`deploy/install.sh`, which renders dnsmasq, nginx and AdGuard Home and loads the firewall), and the
verdict is `verify.check()`. What this module owns is the order, the questions and their defaults, the
answers file for unattended runs, the dry run, and the install lock held across the write and the
install so a deploy cannot read a half-made decision.

The flow is a small state machine (`Step`), and everything that touches the system is a field of `Env`,
so the unit tests drive every path with fakes: no network, no root, no Pi.
"""

from __future__ import annotations

import contextlib
import dataclasses
import enum
import fcntl
import importlib.util
import json
import os
import re
import subprocess
import sys
import time
from collections.abc import Callable, Iterator
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, TextIO

from tvgw import config, lgwebos
from tvgw.discover import Candidate, render, safe_name

PAIRABLE_PROFILES = ("lg-webos",)  # profiles whose TV `lgwebos` can read; others skip pairing
# (samsung) profiles whose TV the hourly reading reads with nothing to pair: `tizen` for samsung-tizen
READ_WITHOUT_PAIRING = ("samsung-tizen",)
# (samsung) what setup says for such a TV, where an LG's owner is asked to pair
READ_WITHOUT_PAIRING_SAID = (
    "the gateway reads this TV every hour without pairing, and nothing appears on its screen: its model,\n"
    "whether it is on, and whether it is on its cable or on Wi-Fi. It cannot read the privacy settings;\n"
    "check them on the TV and record each with: sudo tvgw tv confirm SETTING VALUE"
)
# where the installer lives when this code does not run from a checkout: the tree the package installs
# (packaging/nfpm.yaml puts deploy/ at /usr/lib/tvgw/deploy and the postinst runs install.sh from there;
# tests/unit/test_setup.py holds the two to each other), then the documented clone
INSTALLERS = ("/usr/lib/tvgw/deploy/install.sh", "/opt/tvgw/src/deploy/install.sh")
VENV_PYTHONS = ("/opt/tvgw-venv/bin/python", "/usr/lib/tvgw/venv/bin/python")
INSTALLED_MARK = "/usr/local/sbin/tvgw-apply"  # present once install.sh has run to its scripts step
# (uplink) the closing's last sentence when the router lends the uplink its address (2026-11-02, 19:46: an
# address the router moved cut the TV's streams; the gateway was not the cause)
RESERVE = (
    "So that the TV's streams survive a router restart, reserve this computer's address in your router's"
    " settings."
)
LOCK = "/run/tvgw/install.lock"  # the lock install.sh and sync-install.sh take
LOCK_WAIT = 600.0  # the same 10 minutes install.sh waits
PAIR_TIMEOUT = lgwebos.PAIR_TIMEOUT  # per LAN-API call: how long the owner has to accept the prompt
RETRY_EVERY = 10.0  # seconds between unattended discovery attempts
# (setup) the installer's two passes of a first install (deploy/README.md#the-setup-passes): the TV side
# alone, nothing forwarded, then everything once the TV is known. The apply pass exits 76 when it
# completed and its closing `tvgw verify` still saw a FAIL, which setup then waits out (SETTLE_WAIT)
BRINGUP, APPLY_PASS = "bringup", "apply"
APPLY_VERIFY_FAILED = 76
# (setup) how long setup waits, after its apply pass, for the checks verify.SETTLING names (the filter's
# lists, the services starting) before it reports a FAIL, and how often it looks again
SETTLE_WAIT = 180.0
SETTLE_EVERY = 10.0
VPN_IFACES = ("tun", "wg", "tailscale", "ppp")  # never proposed as WAN_IF: the TV's direct uplink
IFACE_RE = re.compile(r"[A-Za-z0-9_.-]{1,15}")  # a Linux interface name (IFNAMSIZ 16 with the NUL)
SETUP_KEYS = (
    *("SETUP_TV", "SETUP_PAIR", "SETUP_APPLY", "SETUP_SSDP", "SETUP_WAIT", "SETUP_INSTALLER"),
    "SETUP_PROFILE",  # (profile)
    "SETUP_RESOLVER",  # (resolver)
)
# (profile) design decision 62: one question when one signal names a vendor that has a profile, and the
# general profile, said in plain words, whenever no vendor profile is assigned or answered for
PROMPT_BRAND_CONFIRM = "This looks like {vendor} TV. Is it?"
MSG_GENERIC = (
    "tvgw has no profile for this TV yet. It will keep the TV isolated, record what it does, brief you\n"
    "every day, and block well-known trackers from shared lists. Not yet tested."
)
NOT_AN_AGREEMENT = (
    "The TV will ask whether to allow a connection from the gateway: accept that one prompt with the\n"
    "remote. It only lets the gateway read the TV's settings. It is not one of the TV's user agreements:\n"
    "leave Viewing Information, Voice Information and the advertising agreements declined."
)
# what pairing is, said before the TV shows its prompt (setup's pairing step and `tvgw tv pair`)
PAIRING_EXPLAINED = (
    "Pairing lets the gateway read the TV's privacy settings every hour, read-only. The key the TV hands\n"
    "over could also control the TV, so the gateway keeps it readable by its administrator alone\n"
    "(/var/lib/tvgw/lgtv-keys.sqlite).\n" + NOT_AN_AGREEMENT
)
PAIR_LATER = "sudo tvgw tv pair"  # the command that pairs after setup, with the same explanation
# (adguard) asked only when AdGuard Home was not set up by tvgw and may serve more than the TV
# (aghinstall.takeover_evidence). When its log answered another device, yes is the default, so --yes never
# takes it over; when it only listens on every address (a fresh wizard's answer), no is
PROMPT_TAKE_OVER = "Does anything else in the house use this AdGuard Home?"
TAKE_OVER_EXPLAINED = (
    "AdGuard Home on this computer was not set up by tvgw, and {found}: {why}.\n"
    "If tvgw takes it over, it answers the TV and this computer alone, with tvgw's lists and rules,\n"
    "and every other device that uses it loses it."
)
# by the evidence: it only listens beyond the TV side (weak), or its log answered another device (strong)
TAKE_OVER_FOUND = {
    False: "tvgw cannot tell whether anything else uses it",
    True: "it serves more than the TV",
}
TAKE_OVER_SAID_NO = (
    "ADGUARD_TAKE_OVER=no in the settings, so tvgw leaves this AdGuard Home as it is: set it to ask, or"
    " to yes, if nothing else uses it; nothing was written"
)
TAKE_OVER_REFUSED = (
    "this AdGuard Home serves other devices, so tvgw leaves it as it is: put tvgw on a computer of its"
    " own, with an AdGuard Home for the TV alone (docs/install/choosing-a-gateway.md){unattended};"
    " nothing was written"
)
# the settings the take-over check reads, from the plan: the TV, its side, its profile and the two keys
TAKE_OVER_KEYS = ("TV_IP", "TV_MAC", "TV_NET", "GW_IP", "PROFILE", "ADGUARD_LISTEN", "ADGUARD_TAKE_OVER")
# (resolver) who answers the TV's lookups (design decision 81): one question, the choice the settings
# hold as its default, so Enter, a re-run and an unattended run without SETUP_RESOLVER keep it
PROMPT_RESOLVER = "Who should answer the TV's lookups?"
RESOLVER_EXPLAINED = (
    "Every name the filter lets through is looked up by one outside service, which sees it with this\n"
    "home's internet address. None of these filters anything itself. Pressing Enter keeps the one now."
)
RESOLVER_TRIES = 3  # choices that did not answer before an attended run stops


class SetupError(Exception):
    """A stop with a one-line reason for the owner; nothing after the failing step is done."""


class Step(enum.Enum):
    PREFLIGHT = "preflight"
    DISCOVER = "discover"
    BRING_UP = "bring_up"
    PICK = "pick"
    SETTINGS = "settings"
    PAIR = "pair"
    WRITE = "write"
    APPLY = "apply"
    PAIR_LATE = "pair_late"
    VERIFY = "verify"
    DONE = "done"


# ---- the answers file ------------------------------------------------------------------------------
@dataclass
class Answers:
    """What an unattended run would otherwise ask. `conf` holds tvgw.conf keys to set; the SETUP_ keys
    steer the run itself and are never written to the settings file."""

    tv: str = "auto"  # auto | configured | an IP address | a MAC address (a real TV_MAC sets it)
    pair: str = "auto"  # auto (asked when interactive; unattended, only an existing key is read) | yes | no
    apply: str = "auto"  # auto (when the settings changed or the gateway was never installed) | yes | no
    ssdp: bool = True
    wait: float = 120.0  # how long an unattended run keeps looking for the TV
    installer: str = ""
    profile: str = "auto"  # (profile) auto (evidence, else asked, else the general profile) | a profile
    resolver: str = ""  # (resolver) a preset's name; empty asks, with the settings' choice as default
    conf: dict[str, str] = field(default_factory=dict)


def parse_answers(text: str) -> Answers:
    """An answers file is the settings file's own format (KEY=VALUE, `#` comments), so a copy of a working
    tvgw.conf is a valid one. Every value is checked here, before anything runs: a typo in an unattended
    install must stop it at the start, not leave a gateway half set up.

    A TV_MAC in the answers names the TV: the template's placeholder counts as not given (a copy of the
    template names no TV), and a real one is SETUP_TV unless SETUP_TV names the TV itself, so it must
    match a device discovery finds and can never be written beside another device's address."""
    raw = config.parse_conf(text)
    a = Answers()
    for key, value in raw.items():
        if key.startswith("SETUP_"):
            if key not in SETUP_KEYS:
                raise ValueError(f"{key}: not a setup answer (known: {', '.join(SETUP_KEYS)})")
            continue
        config.check_value(key, value)
        a.conf[key] = value
    mac = a.conf.pop("TV_MAC", "").lower()
    if mac and mac != config.PLACEHOLDER_MAC:
        a.conf["TV_MAC"] = mac
    tv = raw.get("SETUP_TV", "auto").strip() or "auto"
    if tv not in ("auto", "configured") and not (_is_ip(tv) or _is_mac(tv)):
        raise ValueError(f"SETUP_TV={tv!r}: expected auto, configured, an IP address or a MAC address")
    a.tv = tv.lower() if _is_mac(tv) else tv
    if "TV_MAC" in a.conf:
        if a.tv == "auto":
            a.tv = a.conf["TV_MAC"]
        elif _is_mac(a.tv) and a.tv != a.conf["TV_MAC"]:
            raise ValueError(f"SETUP_TV={a.tv} and TV_MAC={a.conf['TV_MAC']} name different devices")
    for key, attr in (("SETUP_PAIR", "pair"), ("SETUP_APPLY", "apply")):
        v = raw.get(key, "auto").strip() or "auto"
        if v not in ("auto", "yes", "no"):
            raise ValueError(f"{key}={v!r}: expected auto, yes or no")
        setattr(a, attr, v)
    ssdp = raw.get("SETUP_SSDP", "yes").strip() or "yes"
    if ssdp not in ("yes", "no"):
        raise ValueError(f"SETUP_SSDP={ssdp!r}: expected yes or no")
    a.ssdp = ssdp == "yes"
    wait = raw.get("SETUP_WAIT", "120").strip() or "120"
    if not wait.isdigit() or not 0 <= int(wait) <= 3600:
        raise ValueError(f"SETUP_WAIT={wait!r}: expected seconds, 0 to 3600")
    a.wait = float(wait)
    a.installer = raw.get("SETUP_INSTALLER", "").strip()
    _profile_answer(a, raw.get("SETUP_PROFILE", "auto").strip() or "auto")
    _resolver_answer(a, raw.get("SETUP_RESOLVER", "").strip())
    return a


def _resolver_answer(a: Answers, value: str) -> None:
    """(resolver) SETUP_RESOLVER: one of the offered services by name. The owner's own goes in the
    answers as DNS_UPSTREAMS, so `custom` is not taken here; DNS_UPSTREAMS or DNS_BOOTSTRAP beside a
    name must be that service's own."""
    from tvgw import resolver

    if not value:
        return
    p = resolver.by_name(value)
    if p is None:
        raise ValueError(
            f"SETUP_RESOLVER={value!r}: expected one of {', '.join(x.name for x in resolver.PRESETS)}"
            " (your own service goes in the answers as DNS_UPSTREAMS)"
        )
    for key, mine in (("DNS_UPSTREAMS", p.upstreams), ("DNS_BOOTSTRAP", p.bootstrap)):
        if key in a.conf and set(resolver.csv(a.conf[key])) != set(mine):
            raise ValueError(f"SETUP_RESOLVER={p.name} and {key}={a.conf[key]} name different services")
    a.resolver = p.name


def _profile_answer(a: Answers, value: str) -> None:
    """(profile) SETUP_PROFILE: `auto`, a bundled profile or the path of a profile's TOML. A named one
    is written as PROFILE in the answers would be, and the two must agree. The template's general
    profile names no brand, as its TV_MAC placeholder names no TV: under `auto`, a copy of the
    template leaves the choice to the evidence (design decision 62)."""
    from tvgw import profile

    if value != "auto":
        try:
            config.check_value("PROFILE", value)
        except ValueError as e:
            raise ValueError(f"SETUP_PROFILE: {e}") from None
        if value not in profile.bundled_names() and not (os.path.isabs(value) and value.endswith(".toml")):
            raise ValueError(
                f"SETUP_PROFILE={value!r}: expected auto, a bundled profile "
                f"({', '.join(profile.bundled_names())}) or the absolute path of a .toml file"
            )
        if a.conf.get("PROFILE", value) != value:
            raise ValueError(f"SETUP_PROFILE={value} and PROFILE={a.conf['PROFILE']} name different profiles")
        a.conf["PROFILE"] = value
    elif a.conf.get("PROFILE") == profile.GENERIC:
        del a.conf["PROFILE"]
    a.profile = value


def _is_ip(v: str) -> bool:
    import ipaddress

    try:
        ipaddress.ip_address(v)
    except ValueError:
        return False
    return True


def _is_mac(v: str) -> bool:
    return bool(config._MAC.fullmatch(v))


def has_identity(values: dict[str, str]) -> bool:
    """A settings file that already names a TV: a real MAC, not the template's placeholder."""
    mac = values.get("TV_MAC", "")
    return _is_mac(mac) and mac != config.PLACEHOLDER_MAC


# ---- the questions -----------------------------------------------------------------------------------
class Prompter:
    """Plain-text questions, each with a default in brackets: an empty answer takes it. No colour and no
    cursor control, so it reads the same over a bare SSH session, in a log and on a serial console.
    Unattended, every question prints with the answer it took, so the log of an unattended run shows
    each decision."""

    def __init__(self, out: TextIO, ask: Callable[[str], str] | None = None, unattended: bool = False):
        self.out = out
        self.ask = ask
        self.unattended = unattended

    def say(self, line: str = "") -> None:
        print(line, file=self.out, flush=True)

    def text(self, question: str, default: str, check: Callable[[str], str | None] | None = None) -> str:
        """The answer, or the default. `check` returns a reason to ask again, or None."""
        if self.unattended or self.ask is None:
            reason = check(default) if check else None
            if reason:
                raise SetupError(f"{question}: {default!r} is not usable: {reason}")
            self.say(f"{question} [{default}]: {default}")
            return default
        for _ in range(5):
            try:
                got = self.ask(f"{question} [{default}]: ").strip()
            except EOFError:
                raise SetupError("no answer (end of input); stopped") from None
            value = got or default
            reason = check(value) if check else None
            if not reason:
                return value
            self.say(f"  {reason}")
        raise SetupError(f"{question}: no usable answer after five tries")

    def yes_no(self, question: str, default: bool) -> bool:
        hint = "Y/n" if default else "y/N"
        if self.unattended or self.ask is None:
            self.say(f"{question} [{hint}]: {'yes' if default else 'no'}")
            return default
        for _ in range(5):
            try:
                got = self.ask(f"{question} [{hint}]: ").strip().lower()
            except EOFError:
                raise SetupError("no answer (end of input); stopped") from None
            if not got:
                return default
            if got in ("y", "yes"):
                return True
            if got in ("n", "no"):
                return False
            self.say("  answer y or n")
        raise SetupError(f"{question}: no usable answer after five tries")


# ---- the system --------------------------------------------------------------------------------------
@dataclass
class Env:
    """Every way setup touches the machine. The defaults (`live_env()`) are the real system; the tests
    pass fakes for each."""

    discover: Callable[[str, str, bool], list[Candidate]]
    tv_side_up: Callable[[str, str], bool]
    # (path, lock fd to hand down, setup pass: BRINGUP or APPLY_PASS) -> exit status
    run_installer: Callable[[str, int | None, str], int]
    can_pair: Callable[[str], bool]  # (key file) -> the LAN-API library is here and the key's dir exists
    pair: Callable[[str, str], Any]  # (TV address, key file) -> lgwebos.TvReading
    secure_key: Callable[[str], None]
    key_exists: Callable[[str], bool]
    verify: Callable[[config.Settings], Any]  # -> verify.Result
    wan_route: Callable[[], tuple[str, str]]  # the default route's (interface, gateway)
    installed: Callable[[], bool]
    lock: Callable[[], contextlib.AbstractContextManager[int | None]]
    is_root: Callable[[], bool]
    sleep: Callable[[float], None] = time.sleep
    clock: Callable[[], float] = time.monotonic
    # (uplink) whether the router lends the interface its address (DHCP): then the address, and the
    # router's own, can move, and setup writes WAN_GW_MODE=auto on a new install
    dhcp_uplink: Callable[[str], bool] = lambda iface: False
    # (adguard) what says this computer's AdGuard Home serves more than the TV, with these settings, or
    # None (aghinstall.takeover_evidence)
    adguard_takeover: Callable[[config.Settings], Any] = lambda st: None
    # (resolver) (url, why) for each address of a new choice that did not answer a made-up name under
    # the given one from this computer (resolver.precheck); empty when all did
    resolver_test: Callable[[tuple[str, ...], str], list[tuple[str, str]]] = lambda urls, name: []
    # (resolver) `tvgw resolver set NAME [URLS]` on the settings file once the installer ran: (exit, lines)
    resolver_set: Callable[[str, str, str], tuple[int, list[str]]] = lambda conf, name, urls: (0, [])


def default_route(run: Callable[[list[str]], str] | None = None, tv_if: str = "eth0") -> tuple[str, str]:
    """The interface and next hop of the first default route that is a real uplink: not the TV side and
    not a VPN tunnel (the TV's direct uplink is the router, whatever the Pi's own traffic takes)."""
    from tvgw import discover

    text = (run or discover.run_cmd)(["ip", "-j", "route", "show", "default"])
    try:
        routes = json.loads(text) if text.strip() else []
    except ValueError:
        return "", ""
    for r in routes if isinstance(routes, list) else []:
        dev, gw = str(r.get("dev", "")), str(r.get("gateway", ""))
        if dev and gw and dev != tv_if and not dev.startswith(VPN_IFACES):
            return dev, gw
    return "", ""


def uplink_is_dhcp(iface: str, run: Callable[[list[str]], str] | None = None) -> bool:
    """(uplink) The interface's global IPv4 address is a lease (the kernel marks it `dynamic`, whoever
    runs DHCP for it: NetworkManager, dhclient, systemd-networkd), so the router can move it."""
    from tvgw import discover

    text = (run or discover.run_cmd)(["ip", "-j", "-4", "addr", "show", "dev", iface])
    try:
        links = json.loads(text) if text.strip() else []
    except ValueError:
        return False
    return any(
        a.get("family") == "inet" and a.get("scope") == "global" and a.get("dynamic") is True
        for link in (links if isinstance(links, list) else [])
        if isinstance(link, dict)
        for a in link.get("addr_info", [])
        if isinstance(a, dict)
    )


def tv_side_is_up(iface: str, gw_ip: str, run: Callable[[list[str]], str] | None = None) -> bool:
    """The TV-side interface carries the gateway's address: dnsmasq can hand the TV a lease there."""
    from tvgw import discover

    text = (run or discover.run_cmd)(["ip", "-j", "addr", "show", "dev", iface])
    try:
        links = json.loads(text) if text.strip() else []
    except ValueError:
        return False
    return any(
        a.get("local") == gw_ip
        for link in (links if isinstance(links, list) else [])
        for a in link.get("addr_info", [])
    )


@contextlib.contextmanager
def install_lock(
    path: str = LOCK, wait: float = LOCK_WAIT, say: Callable[[str], None] = print
) -> Iterator[int]:
    """The installer's own lock, held from before the settings file is written until the installer is
    done, so a `make deploy` can never read a settings file setup is halfway through. The
    descriptor is handed to install.sh as its fd 8 with TVGW_INSTALL_LOCKED=1, the way sync-install.sh
    hands it down; a second flock on a new descriptor would wait on itself."""
    os.makedirs(os.path.dirname(path), mode=0o755, exist_ok=True)
    fd = os.open(path, os.O_WRONLY | os.O_CREAT, 0o644)
    try:
        deadline = time.monotonic() + wait
        told = False
        while True:
            try:
                fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
                break
            except BlockingIOError:
                if time.monotonic() > deadline:
                    raise SetupError("another install is running (waited 10 minutes)") from None
                if not told:
                    say("waiting for another install to finish...")
                    told = True
                time.sleep(1.0)
        yield fd
    finally:
        os.close(fd)


def run_installer(path: str, lock_fd: int | None, setup_pass: str = "") -> int:
    """Run install.sh from its directory with no terminal on stdin (its own interactive discovery must not
    start under setup's), UTF-8 forced, the held lock passed down as fd 8, and TVGW_SETUP_PASS set to
    `setup_pass` (BRINGUP or APPLY_PASS; empty, the installer's own full run), whatever the caller's
    environment held."""
    env = {**os.environ, "PYTHONUTF8": "1", "TVGW_SETUP_PASS": setup_pass}
    if lock_fd is None:
        cmd = ["bash", path]
        fds: tuple[int, ...] = ()
    else:
        env["TVGW_INSTALL_LOCKED"] = "1"
        # bash puts the held lock on fd 8, where install.sh's `flock -w 600 8` finds it already taken by us
        cmd = ["bash", "-c", 'exec 8>&"$1" && exec bash "$2"', "tvgw-setup", str(lock_fd), path]
        fds = (lock_fd,)
    try:
        return subprocess.run(
            cmd,
            cwd=os.path.dirname(path) or ".",
            stdin=subprocess.DEVNULL,
            env=env,
            pass_fds=fds,
            check=False,
        ).returncode
    except OSError as e:
        raise SetupError(f"cannot run {path}: {e}") from None


def _venv_python() -> str | None:
    return next((p for p in VENV_PYTHONS if os.access(p, os.X_OK)), None)


_PAIR_CODE = (
    "import json, sys\n"
    "from tvgw import lgwebos\n"
    "r = lgwebos.pair(sys.argv[1], sys.argv[2], float(sys.argv[3]))\n"
    "print(json.dumps({'reachable': r.reachable, 'values': r.values, 'error': r.error}))\n"
)


def can_pair(key_file: str) -> bool:
    """Pairing can run now: the key's directory exists (the installer creates it with its modes) and the
    optional LAN-API library is importable here or in the gateway's virtualenv."""
    if not os.path.isdir(os.path.dirname(key_file)):
        return False
    if importlib.util.find_spec("bscpylgtv") is not None:
        return True
    py = _venv_python()
    if py is None:
        return False
    # -I and cwd=/: as root, never import a json.py or bscpylgtv.py from the directory sudo ran in
    probe = subprocess.run(
        [py, "-I", "-c", "import bscpylgtv, tvgw.lgwebos"],
        cwd="/",
        capture_output=True,
        encoding="utf-8",
        check=False,
    )
    return probe.returncode == 0


def pair(ip: str, key_file: str):
    """Pair with the TV over its LAN API and read it once: `lgwebos.pair()`, never `lgwebos.read()`,
    which asks nothing of a TV it holds no key for. With no key yet, the library registers first and the
    TV shows its prompt; the reading is read-only either way (lgwebos only reads). In this Python when
    the library is here, else in the gateway's virtualenv, where the installer put it. The key controls
    the TV, so it is created under umask 077, here and in the virtualenv's Python, which inherits it and
    sets it again: readable by root alone from its first byte, not only once `_secure_key` runs."""
    old = os.umask(0o077)
    try:
        return _pair(ip, key_file)
    finally:
        os.umask(old)


def _pair(ip: str, key_file: str):
    if importlib.util.find_spec("bscpylgtv") is not None:
        return lgwebos.pair(ip, key_file, timeout=PAIR_TIMEOUT)
    py = _venv_python()
    if py is None:
        return lgwebos.TvReading(False, error="bscpylgtv not installed")
    try:
        p = subprocess.run(
            [py, "-I", "-c", _PAIR_CODE, ip, key_file, str(PAIR_TIMEOUT)],
            cwd="/",
            capture_output=True,
            encoding="utf-8",
            errors="replace",
            timeout=PAIR_TIMEOUT * 5,
            check=False,
        )
        d = json.loads(p.stdout.strip().splitlines()[-1])
        return lgwebos.TvReading(bool(d["reachable"]), dict(d["values"]), d.get("error"))
    except (OSError, subprocess.TimeoutExpired, ValueError, IndexError, KeyError) as e:
        return lgwebos.TvReading(False, error=type(e).__name__)


def adguard_takeover(st: config.Settings):
    """(adguard) `aghinstall.takeover_evidence()` for the settings the plan writes, or None when it cannot
    be told (no PyYAML here, a profile or a YAML this user cannot read): the apply checks it again."""
    try:
        from tvgw import aghinstall, profile

        return aghinstall.takeover_evidence(st, profile.load(st.profile))
    except (ImportError, OSError, ValueError):
        return None


def _secure_key(path: str) -> None:
    """The key controls the TV: root only, as install.sh keeps it."""
    with contextlib.suppress(FileNotFoundError):
        os.chmod(path, 0o600)


def live_env(s: config.Settings) -> Env:
    from tvgw import discover, verify

    return Env(
        discover=lambda iface, gw, ssdp: discover.gather(iface, gw, with_ssdp=ssdp),
        tv_side_up=tv_side_is_up,
        run_installer=run_installer,
        can_pair=can_pair,
        pair=pair,
        secure_key=_secure_key,
        key_exists=os.path.exists,
        verify=lambda st: verify.check(
            st,
            _profile(st.profile),
            run=verify.run_cmd,
            read=verify.read_file,
            mtime=verify.file_mtime,
        ),
        wan_route=lambda: default_route(tv_if=s.tv_if),
        installed=lambda: os.path.exists(INSTALLED_MARK),
        lock=install_lock,
        is_root=lambda: os.geteuid() == 0,
        dhcp_uplink=uplink_is_dhcp,
        adguard_takeover=adguard_takeover,
        resolver_test=_resolver_test,
        resolver_set=_resolver_set,
    )


def _resolver_test(urls: tuple[str, ...], name: str) -> list[tuple[str, str]]:
    from tvgw import resolver

    return resolver.precheck(urls, name)


def _resolver_set(conf_path: str, name: str, urls: str) -> tuple[int, list[str]]:
    """(resolver) `tvgw resolver set` on the settings file setup has just written and installed."""
    from tvgw import profile, resolver

    try:
        s = config.load(conf_path)
        prof = profile.load(s.profile)
        target = resolver.target_for(name, urls, s.gw_ip)
    except (OSError, ValueError) as e:
        return resolver.REFUSED, [f"{resolver.SAY}{e}; nothing changed"]
    done = resolver.change(s, prof.for_country(s.tv_country) if s.tv_country else prof, conf_path, target)
    return done.code, done.lines


def _profile(name: str):
    from tvgw import profile

    return profile.load(name)


def find_installer(explicit: str = "") -> str | None:
    """install.sh: the one given, else the checkout this code runs from (so `PYTHONPATH=src` runs the
    installer of the same tree), else the documented clone location."""
    if explicit:
        return explicit if os.path.isfile(explicit) else None
    here = Path(__file__).resolve().parents[2] / "deploy" / "install.sh"
    return next((str(p) for p in (here, *map(Path, INSTALLERS)) if p.is_file()), None)


# ---- the flow ----------------------------------------------------------------------------------------
@dataclass
class Plan:
    """What the run has decided so far; the dry run prints it and the real run carries it out."""

    pick: Candidate | None = None
    changes: dict[str, str] = field(default_factory=dict)
    diff: list[str] = field(default_factory=list)
    write: bool = False
    apply: bool = False
    pair: str = ""  # "" none | now | late | check
    settling: bool = False  # (setup) the wait ran out with only checks verify.SETTLING names failing
    brought_up: bool = False
    installer_rc: int | None = None
    reading: Any = None
    verified: Any = None
    dhcp_uplink: bool = False  # (uplink) the router lends the uplink its address: the closing says reserve it
    resolver: Any = (
        None  # (resolver) resolver.Target: who should answer the TV's lookups, made after the install
    )
    resolver_rc: int | None = None  # (resolver) what that change returned; None when it did not run


class Setup:
    """The guided installer as a state machine: each `step_*` does one thing and returns the next step.
    `trail` records the steps taken, which is what the tests assert on."""

    def __init__(
        self,
        s: config.Settings,
        conf_path: str,
        env: Env,
        ui: Prompter,
        answers: Answers | None = None,
        dry_run: bool = False,
        installer: str | None = None,
        template: str = "",
    ):
        self.s = s
        self.conf_path = conf_path
        self.env = env
        self.ui = ui
        self.answers = answers or Answers()
        self.dry_run = dry_run
        self.installer = installer
        self.template = template
        self.plan = Plan()
        self.trail: list[Step] = []
        self._deadline: float | None = None
        self.key_file = os.path.join(s.state_dir, "lgtv-keys.sqlite")

    # the settings file as it stands (or the template it will start from)
    def current(self) -> dict[str, str]:
        try:
            text = Path(self.conf_path).read_text(encoding="utf-8")
        except FileNotFoundError:
            text = self.template
        return config.parse_conf(text)

    def target(self) -> dict[str, str]:
        """The settings file's values once the plan is written."""
        return {**self.current(), **self.plan.changes}

    def run(self) -> int:
        step = Step.PREFLIGHT
        try:
            while step is not Step.DONE:
                self.trail.append(step)
                step = getattr(self, f"step_{step.value}")()
        except SetupError as e:
            self.ui.say(f"tvgw setup: {e}")
            return 1
        except KeyboardInterrupt:
            self.ui.say("\ntvgw setup: interrupted; " + self._done_so_far())
            return 130
        self.trail.append(Step.DONE)
        return self._exit_code()

    def _done_so_far(self) -> str:
        if self.dry_run:
            return "nothing was changed (dry run)"
        if self.plan.installer_rc is not None:
            return "the settings were written and the installer ran; run `sudo tvgw verify` to check"
        if Step.APPLY in self.trail:
            return "the settings may have been written; run `sudo tvgw setup` again to finish"
        return "nothing was written"

    def _installed_ok(self) -> bool:
        """The installer did not run, or ran to its end: 0, or 76, its closing verify still failing, which
        setup's own verify then judges."""
        return self.plan.installer_rc in (None, 0, APPLY_VERIFY_FAILED)

    def _exit_code(self) -> int:
        if self.dry_run:
            return 0
        if not self._installed_ok():
            return 1
        if self.plan.resolver_rc not in (None, 0):  # (resolver) the choice did not take
            return 1
        v = self.plan.verified
        return 0 if v is None or v.ok else 1

    # ---- steps ----
    def step_preflight(self) -> Step:
        if not self.env.is_root():
            if not self.dry_run:
                raise SetupError(
                    "setup changes the system and needs root: run `sudo tvgw setup`, "
                    "or `tvgw setup --dry-run` to see what it would do"
                )
            self.ui.say(
                "not running as root: discovery reads only what this user can, and the SSDP search is skipped"
            )
        self.ui.say(f"tvgw setup: settings file {self.conf_path}")
        if self.dry_run:
            self.ui.say("dry run: every change is printed and nothing is written, paired or installed")
        self.ui.say("")
        return Step.DISCOVER

    def _configured(self) -> dict[str, str]:
        """The TV identity the answers or the settings file already give."""
        return {**self.current(), **self.answers.conf}

    def step_discover(self) -> Step:
        if self.answers.tv == "configured":
            if not has_identity(self._configured()):
                raise SetupError("SETUP_TV=configured, but neither the answers nor the settings name a TV")
            self.ui.say("using the TV the settings already name (SETUP_TV=configured); discovery skipped")
            return Step.SETTINGS
        ssdp = self.answers.ssdp and self.env.is_root() and not self.dry_run
        self.ui.say(f"looking for the TV on {self.s.tv_if}" + ("" if ssdp else " (no SSDP search)") + "...")
        self.cands = self.env.discover(self.s.tv_if, self.s.gw_ip, ssdp)
        if self.cands:
            return Step.PICK
        if not self.env.tv_side_up(self.s.tv_if, self.s.gw_ip):
            if self.plan.brought_up:
                raise SetupError(
                    f"the installer ran but {self.s.tv_if} still does not carry {self.s.gw_ip}; "
                    "see its output above"
                )
            return Step.BRING_UP
        return self._nothing_found()

    def _nothing_found(self) -> Step:
        self.ui.say(
            f"no device found on {self.s.tv_if}: is the TV cabled to the gateway's TV port and switched on?"
        )
        if self.ui.unattended:
            if self._deadline is None:
                self._deadline = self.env.clock() + self.answers.wait
            if self.env.clock() < self._deadline:
                self.env.sleep(RETRY_EVERY)
                return Step.DISCOVER
        elif self.ui.yes_no("Look again?", True):
            return Step.DISCOVER
        if has_identity(self._configured()):
            self.ui.say("keeping the TV the settings already name")
            return Step.SETTINGS
        raise SetupError("no TV found and none configured; nothing was written")

    def step_bring_up(self) -> Step:
        self.ui.say(
            f"{self.s.tv_if} does not carry the gateway's address ({self.s.gw_ip}) yet, so the TV has had\n"
            "no address to be found at. The installer brings the TV side up first: the TV's port gets the\n"
            "gateway's address and gives the TV one, and this step does not pass the TV's traffic on (on a\n"
            "gateway set up before, its firewall comes back as it was). Setup then looks for the TV again."
        )
        installer = self._installer()
        if self.dry_run:
            self.ui.say(f"(dry run) would run {installer} to bring the TV side up, then look for the TV")
            if not has_identity(self._configured()):
                self.ui.say(
                    "(dry run) the TV can only be found once the TV side is up; the plan goes on without it"
                )
            return Step.SETTINGS
        if self.answers.apply == "no":
            if has_identity(self._configured()):
                self.ui.say("SETUP_APPLY=no: the installer is not run; going on with the TV already named")
                return Step.SETTINGS
            raise SetupError("the TV side is not up and SETUP_APPLY=no; nothing was installed")
        if not self.ui.yes_no("Run the installer now to bring the TV side up?", True):
            raise SetupError("the TV side is not up; nothing was written")
        with self.env.lock() as fd:
            rc = self.env.run_installer(installer, fd, BRINGUP)
        if rc != 0:
            raise SetupError(
                f"the installer could not bring the TV side up (exit {rc}); its output above says why"
            )
        self.ui.say("the TV side is up; looking for the TV again")
        self.plan.brought_up = True
        self._deadline = None
        return Step.DISCOVER

    def _default_pick(self) -> int | None:
        """The index the owner most likely means, or None when that is a guess: the TV already configured,
        else the only device, else the only device a profile is assigned to on its evidence."""
        mac = self._configured().get("TV_MAC", "").lower()
        for i, c in enumerate(self.cands):
            if mac and c.mac == mac:
                return i
        if len(self.cands) == 1:
            return 0
        profiled = [i for i, c in enumerate(self.cands) if c.profile]
        return profiled[0] if len(profiled) == 1 else None

    def step_pick(self) -> Step:
        from tvgw.cli import clean  # every string the TV announced reaches the terminal through clean()

        self.ui.say("found:")
        for line in render(self.cands):
            self.ui.say(clean(line))
        wanted = self.answers.tv
        if wanted not in ("auto", "configured"):
            match = [c for c in self.cands if wanted in (c.ip, c.mac)]
            if not match:
                if self.ui.unattended:
                    return self._retry_or_fail(f"SETUP_TV={wanted} is not among the devices found")
                self.ui.say(f"SETUP_TV={wanted} is not among them")
            else:
                return self._picked(match[0])
        guess = self._default_pick()
        if self.ui.unattended and guess is None:
            raise SetupError(
                "several devices could be the TV; name it in the answers file: SETUP_TV=<its MAC or address>"
            )
        n = len(self.cands)
        default = str((guess or 0) + 1)
        choice = self.ui.text(
            f"Which one is the TV? (1-{n})",
            default,
            lambda v: None if v.isdigit() and 1 <= int(v) <= n else f"a number from 1 to {n}",
        )
        return self._picked(self.cands[int(choice) - 1])

    def _retry_or_fail(self, reason: str) -> Step:
        if self._deadline is None:
            self._deadline = self.env.clock() + self.answers.wait
        if self.env.clock() < self._deadline:
            self.ui.say(f"{reason}; looking again")
            self.env.sleep(RETRY_EVERY)
            return Step.DISCOVER
        raise SetupError(reason)

    def _picked(self, c: Candidate) -> Step:
        from tvgw.cli import clean

        if not c.mac:
            if self.ui.unattended:
                return self._retry_or_fail(f"{c.ip} has no MAC address in the lease or neighbour table yet")
            self.ui.say(f"{c.ip} has no MAC address in the lease or neighbour table yet; wait a minute")
            return Step.DISCOVER if self.ui.yes_no("Look again?", True) else self._no_tv()
        self.plan.pick = c
        self.ui.say(f"the TV: {clean(c.label)}")
        return Step.SETTINGS

    def _no_tv(self) -> Step:
        raise SetupError("no TV chosen; nothing was written")

    def step_settings(self) -> Step:
        """The values to write: the TV's identity, the uplink, and every key the answers file sets. Only a
        key whose value differs from the file's lands in the plan, so a re-run with nothing new plans
        nothing."""
        cur = self.current()
        given = dict(self.answers.conf)
        want: dict[str, str] = {}
        c = self.plan.pick
        if c is not None:
            # the identity is the device picked, never the answers': a MAC from one device beside the
            # address of another would pin the wrong device in dnsmasq
            if given.get("TV_MAC", c.mac) != c.mac:
                raise SetupError(
                    f"the answers say TV_MAC={given['TV_MAC']}, but the TV picked is {c.mac}; "
                    "nothing was written"
                )
            given.pop("TV_MAC", None)
            # the answers' TV_IP counts only when the answers named this device (SETUP_TV or TV_MAC)
            if "TV_IP" in given and self.answers.tv not in (c.ip, c.mac):
                self.ui.say(
                    f"TV_IP={given.pop('TV_IP')} in the answers is not used: they do not name this TV "
                    "(SETUP_TV or TV_MAC)"
                )
            same_tv = c.mac == cur.get("TV_MAC", "").lower()
            want["TV_MAC"] = c.mac
            # the same TV keeps the address it is pinned to, its name and its profile; a new one takes
            # its lease's address, the name it announced and a profile chosen below
            want["TV_IP"] = given.pop("TV_IP", cur.get("TV_IP", c.ip) if same_tv else c.ip)
            name_default = given.get(
                "TV_NAME", cur.get("TV_NAME", "tv") if same_tv else safe_name(c.hostname, "tv")
            )
            want["TV_NAME"] = self.ui.text("Name for the TV (DHCP and logs)", name_default, _valid("TV_NAME"))
            # (profile) the answers' profile, or the one the same TV already has, stands: a file without
            # PROFILE means lg-webos, and a re-run writes nothing that would change that meaning. Any
            # other TV gets one on evidence or its owner's word, else the general profile (design
            # decision 62)
            if "PROFILE" not in given and not same_tv:
                want["PROFILE"] = self._profile_for(c)
        elif "TV_IP" in given and "TV_MAC" not in given:
            # no device picked, and the answers name none: their TV_IP would move the configured TV
            self.ui.say(f"TV_IP={given.pop('TV_IP')} in the answers is not used: they name no TV (TV_MAC)")
        tmpl = config.parse_conf(self.template)
        det_if, det_gw = self.env.wan_route()
        # on an installed gateway every value in the file is the owner's, even one that equals the
        # template's example (the reference gateway's uplink is the template's wlan0)
        installed = self.env.installed()

        unsure: list[str] = []

        def default(key: str, detected: str, fallback: str) -> str:
            # the answers win; then a value the owner set (on a gateway not installed yet, one that
            # differs from the shipped template); then what the routing table says; then the file's
            # value, whatever it is. That last is a guess (the template's example router), noted as one.
            if key in given:
                return given[key]
            mine = cur.get(key, "")
            if mine and (installed or mine != tmpl.get(key)):
                return mine
            if detected:
                return detected
            unsure.append(key)
            if not self.ui.unattended:
                self.ui.say(f"  no default route to read {key} from: the value offered is a guess, check it")
            return mine or fallback

        want["WAN_IF"] = self.ui.text(
            "Interface toward the home router (WAN_IF)",
            default("WAN_IF", det_if, self.s.wan_if),
            self._valid_wan_if,
        )
        if "WAN_GW" not in given and want["WAN_IF"] != cur.get("WAN_IF"):
            # a new uplink interface: the router in the file belongs to the old one
            if want["WAN_IF"] == det_if and det_gw:
                gw = det_gw
            else:
                unsure.append("WAN_GW")
                if not self.ui.unattended:
                    self.ui.say(
                        f"  WAN_GW in the file is the router of {cur.get('WAN_IF') or 'another interface'}: "
                        "check it"
                    )
                gw = cur.get("WAN_GW", "")
        else:
            gw = default("WAN_GW", det_gw if want["WAN_IF"] == det_if else "", "")
        # the direct uplink routes the TV through it (tvgw-apply stops without it); a VPN uplink does not
        direct = given.get("UPLINK", cur.get("UPLINK", self.s.uplink)) != "vpn"
        want["WAN_GW"] = self.ui.text("Home router's address (WAN_GW)", gw, _valid("WAN_GW", required=direct))
        # (uplink) a router that lends this computer its address can move it, and its own: on a new install
        # the routes follow the router (WAN_GW_MODE=auto; WAN_GW stays written for an older release to read).
        # An installed gateway keeps what its file says (decision 53), and the answers win
        self.plan.dhcp_uplink = self.env.dhcp_uplink(want["WAN_IF"])
        decided = "WAN_GW_MODE" in given or "WAN_GW_MODE" in cur
        if self.plan.dhcp_uplink and not installed and not decided:
            want["WAN_GW_MODE"] = "auto"
        if unsure and self.ui.unattended:
            # an unattended run never installs the template's example router: the TV would have no way out
            msg = f"{' and '.join(unsure)}: no default route to read them from; set them in the answers file"
            if not self.dry_run:
                raise SetupError(msg)
            self.ui.say(f"(dry run) a real run would stop here: {msg}")
        self._resolver(cur, given, want)  # (resolver)
        for key, value in given.items():
            want.setdefault(key, value)
        self._take_over(cur, want)  # (adguard)
        self.plan.changes = {k: v for k, v in want.items() if cur.get(k) != v}
        return Step.PAIR

    def _take_over(self, cur: dict[str, str], want: dict[str, str]) -> None:
        """(adguard) When the AdGuard Home here is not tvgw's and may serve more than the TV, ask whether
        anything else uses it, before anything is written. Its log answered another device: yes is the
        default and stops, as the installer's apply would; no writes ADGUARD_TAKE_OVER=yes, the owner's
        word. It only listens on every address: no is the default, and the apply takes it over with one
        line; yes stops. ADGUARD_TAKE_OVER=no stops without a question."""
        if self.answers.apply == "no":  # the installer never runs, so nothing is taken over
            return
        target = {**cur, **want}
        st = dataclasses.replace(
            self.s, **{config.CONF_KEYS[k]: target[k] for k in TAKE_OVER_KEYS if target.get(k)}
        )
        others = self.env.adguard_takeover(st)
        if not others:
            return
        strong = others.strong
        self.ui.say(TAKE_OVER_EXPLAINED.format(found=TAKE_OVER_FOUND[strong], why=others.why()))
        if st.adguard_take_over == "no":
            msg = TAKE_OVER_SAID_NO
        elif not self.ui.yes_no(PROMPT_TAKE_OVER, strong):
            if strong:
                want["ADGUARD_TAKE_OVER"] = "yes"
                self.ui.say("tvgw takes it over when the installer runs (ADGUARD_TAKE_OVER=yes)")
            else:
                self.ui.say("tvgw takes it over when the installer runs (ADGUARD_TAKE_OVER=no refuses that)")
            return
        else:
            hint = ""
            if self.ui.unattended:
                hint = "; ADGUARD_TAKE_OVER=yes in the answers file says nothing else uses it"
            msg = TAKE_OVER_REFUSED.format(unattended=hint)
        if self.dry_run:
            self.ui.say(f"(dry run) a real run would stop here: {msg}")
            return
        raise SetupError(msg)

    def _resolver(self, cur: dict[str, str], given: dict[str, str], want: dict[str, str]) -> None:
        """(resolver) Who answers the TV's lookups: one question, one plain line a choice. The choice the
        settings hold now is the default (Cloudflare when they name none), or "keep" when it is the
        owner's own, so Enter, a re-run and an unattended run without SETUP_RESOLVER change nothing.

        DNS_UPSTREAMS in an answers file is the owner's own and is not asked about: it is written with the
        other settings as before this question existed, whatever form config.load takes (a loopback DoH
        proxy, `tls://`, a host name), SETUP_APPLY=no included. Where the gateway can ask it, it is asked,
        and a failure is a warning, never a stop (`_answers_upstreams`).

        A choice made here is not written with the other settings. A new choice is asked from this computer at
        once (`Env.resolver_test`), so a pick that does not answer is asked again, or stops an unattended
        run, and is kept in the plan: once the installer has run, `_switch_resolver` changes it the way
        `tvgw resolver set` does, all or nothing. Written before the installer, a choice AdGuard Home's
        readiness wait then refused would stay in the settings while AdGuard kept the old one, and every
        later apply would try it again (design decision 81)."""
        from tvgw import resolver

        defaults = config.Settings()
        now_up = resolver.csv(cur.get("DNS_UPSTREAMS") or defaults.dns_upstreams)
        now_boot = resolver.csv(cur.get("DNS_BOOTSTRAP") or defaults.dns_bootstrap)
        if "DNS_UPSTREAMS" in given:  # written as given, with the rest; SETUP_RESOLVER names the same
            if self.answers.resolver:
                p = resolver.by_name(self.answers.resolver)
                self.ui.say(f"{PROMPT_RESOLVER} {p.label} (SETUP_RESOLVER={p.name})")
                if set(p.upstreams) != set(now_up):
                    self._resolver_check(
                        resolver.Target(p.name, p.label, p.upstreams, p.bootstrap), cur, given, want
                    )
            else:
                self._answers_upstreams(given["DNS_UPSTREAMS"], now_up, cur, given, want)
            return
        if self.answers.resolver:  # its DNS_BOOTSTRAP, if any, is its own (parse_answers): set with it later
            given.pop("DNS_BOOTSTRAP", None)
        exact = next(
            (
                p
                for p in resolver.PRESETS
                if set(p.upstreams) == set(now_up) and set(p.bootstrap) == set(now_boot)
            ),
            None,
        )
        options: list[resolver.Preset | None] = [*resolver.PRESETS] + ([] if exact else [None])
        for _ in range(RESOLVER_TRIES):
            pick = self._resolver_pick(options, exact, now_up)
            if pick is None or pick is exact:
                return
            target = resolver.Target(pick.name, pick.label, pick.upstreams, pick.bootstrap)
            if self._resolver_check(target, cur, given, want):
                self.plan.resolver = target
                return
        raise SetupError("no service that answers was chosen; nothing was written")

    def _resolver_check(self, target, cur, given, want) -> bool:
        """(resolver) True when every address of `target` answered from this computer (or in a dry run,
        which asks nothing). Unattended, or named in the answers, a failure stops setup."""
        from tvgw import resolver

        if self.dry_run:
            self.ui.say(f"(dry run) a real run first asks {target.label} for a lookup from this computer")
            return True
        failed = self.env.resolver_test(target.upstreams, self._probe_name(cur, given, want))
        if not failed:
            return True
        url, why = failed[0]
        msg = f"{target.label} did not answer from this computer ({resolver.address(url)}: {why})"
        if self.ui.unattended or self.answers.resolver:
            raise SetupError(f"SETUP_RESOLVER={target.name}: {msg}; nothing was written")
        self.ui.say(f"  {msg}; choose another, or press Enter to keep the one now")
        return False

    def _answers_upstreams(self, urls: str, now_up, cur, given, want) -> None:
        """(resolver) DNS_UPSTREAMS from an answers file, written as given: asked from this computer when
        it is encrypted DNS by address and new, and a failure said as a warning. Any other form is said
        to be written untested."""
        from tvgw import resolver

        if set(resolver.csv(urls)) == set(now_up):
            return
        gw_ip = want.get("GW_IP") or given.get("GW_IP") or cur.get("GW_IP") or self.s.gw_ip
        try:
            target = resolver.custom_target(urls, gw_ip)
        except ValueError as e:
            self.ui.say(
                f"DNS_UPSTREAMS from the answers is written as given; the gateway cannot test it ({e})"
            )
            return
        if self.dry_run:
            self.ui.say("(dry run) a real run asks DNS_UPSTREAMS from the answers from this computer first")
            return
        failed = self.env.resolver_test(target.upstreams, self._probe_name(cur, given, want))
        if failed:
            url, why = failed[0]
            self.ui.say(
                f"warning: DNS_UPSTREAMS from the answers did not answer from this computer"
                f" ({resolver.address(url)}: {why}); it is written as given"
            )

    def _switch_resolver(self) -> None:
        """(resolver) The choice the plan holds, made once the installer has run: `Env.resolver_set`, which
        is `tvgw resolver set`, all or nothing. It does not run when the installer stopped, when the
        answers say SETUP_APPLY=no, or when the filter is not installed yet; each says what to run later."""
        from tvgw import resolver

        target = self.plan.resolver
        if target is None:
            return
        urls = ",".join(target.upstreams) if target.name == resolver.CUSTOM else ""
        later = f"sudo tvgw resolver set {target.name}{' ' + urls if urls else ''}"
        stays = f"the TV's lookups stay where they go now; to move them to {target.label} later: {later}"
        if self.answers.apply == "no":
            self.ui.say(f"SETUP_APPLY=no: {stays}")
            return
        if self.plan.installer_rc not in (None, 0):
            self.ui.say(f"the installer stopped first: {stays}")
            return
        if not self.env.installed():
            self.ui.say(f"the filter is not installed yet: {stays}")
            return
        self.ui.say(
            f"moving the TV's lookups to {target.label}; it is tested first, and put back if it fails"
        )
        code, lines = self.env.resolver_set(self.conf_path, target.name, urls)
        for line in lines:
            self.ui.say(line)
        self.plan.resolver_rc = code

    def _resolver_pick(self, options, exact, now_up):
        """(resolver) The answers' service, or the one picked from the list (None: keep the owner's own)."""
        from tvgw import resolver

        if self.answers.resolver:
            p = resolver.by_name(self.answers.resolver)
            self.ui.say(f"{PROMPT_RESOLVER} {p.label} (SETUP_RESOLVER={p.name})")
            return p
        self.ui.say(RESOLVER_EXPLAINED)
        for i, p in enumerate(options, 1):
            if p is None:
                self.ui.say(f"  [{i}] keep your own: {', '.join(now_up)}")
            else:
                default = " (the default)" if p.name == resolver.DEFAULT else ""
                self.ui.say(
                    f"  [{i}] {p.label}, {p.country}{default}: by its own policy (read {p.read}),"
                    f" it {p.keeps}"
                )
                if p.shares:
                    self.ui.say(f"      {p.shares}")
        n = len(options)
        choice = self.ui.text(
            f"{PROMPT_RESOLVER} (1-{n})",
            str(options.index(exact) + 1 if exact else n),
            lambda v: None if v.isdigit() and 1 <= int(v) <= n else f"a number from 1 to {n}",
        )
        return options[int(choice) - 1]

    def _probe_name(self, cur: dict[str, str], given: dict[str, str], want: dict[str, str]) -> str:
        """(resolver) The first must-allow host of the profile the settings will name, under which the
        test makes up a name; example.com when that profile cannot be read here."""
        name = want.get("PROFILE") or given.get("PROFILE") or cur.get("PROFILE") or self.s.profile
        try:
            return next(iter(_profile(name).must_allow), "example.com")
        except (OSError, ValueError):
            return "example.com"

    def _profile_for(self, c: Candidate) -> str:
        """(profile) The profile for a TV the settings do not name yet: the one assigned on evidence; when
        one signal names a vendor that has a profile, that one on the owner's yes (never unattended,
        where nobody can answer); otherwise the general profile, said in plain words."""
        from tvgw import discover, profile

        if c.profile:
            return c.profile
        profiles = discover.bundled_profiles()
        offer = discover.vendor_profile(c.vendor, profiles)
        if offer:
            brand = discover.vendor_phrase(next(p.vendor for p in profiles if p.name == offer))
            if not self.ui.unattended:
                if self.ui.yes_no(PROMPT_BRAND_CONFIRM.format(vendor=brand), True):
                    return offer
            else:
                self.ui.say(
                    f"this looks like {brand} TV; unattended, SETUP_PROFILE=auto takes no profile on that "
                    f"alone (SETUP_PROFILE={offer} names it)"
                )
        self.ui.say(MSG_GENERIC)
        return profile.GENERIC

    def _valid_wan_if(self, v: str) -> str | None:
        if not IFACE_RE.fullmatch(v):
            return "an interface name: letters, digits, . _ - (at most 15)"
        if v == self.s.tv_if:
            return f"{v} is the TV side; the uplink must be another interface"
        return None

    def step_pair(self) -> Step:
        # (profile) the profile the settings will name: with a pick, the one the settings step chose for
        # it (a Roku is never paired with as an LG), the answers' or the one the same TV already has
        c = self.plan.pick
        prof = self.target().get("PROFILE", self.s.profile)
        if c is None and not has_identity(self.target()):
            self.ui.say("no TV identified yet; pairing skipped")
            return Step.WRITE
        if prof in READ_WITHOUT_PAIRING:  # (samsung) never paired, whatever SETUP_PAIR says
            self.ui.say(READ_WITHOUT_PAIRING_SAID)
            return Step.WRITE
        if self.answers.pair == "no":
            self.ui.say("LAN-API pairing skipped (SETUP_PAIR=no)")
            return Step.WRITE
        if prof not in PAIRABLE_PROFILES:
            self.ui.say(f"no LAN-API reader for this TV (profile {prof or 'none'}); pairing skipped")
            return Step.WRITE
        ip = c.ip if c else self.target().get("TV_IP", self.s.tv_ip)
        self.pair_ip = ip
        if self.env.key_exists(self.key_file):
            self.ui.say(f"the TV's LAN API is already paired ({self.key_file})")
            self.plan.pair = "check"
        elif self.ui.unattended and self.answers.pair == "auto":
            # nobody may be at the TV to accept its prompt, and each LAN-API call would wait for it
            self.ui.say(
                "LAN-API pairing skipped: unattended, SETUP_PAIR=auto pairs only when a key exists "
                "(SETUP_PAIR=yes pairs unattended; someone must accept the prompt on the TV)"
            )
            return Step.WRITE
        else:
            self.ui.say(PAIRING_EXPLAINED)
            if self.answers.pair == "yes":
                self.ui.say("pairing (SETUP_PAIR=yes)")
            elif not self.ui.yes_no("Pair the TV's LAN API now?", True):
                self.ui.say(f"pairing skipped; pair later with `{PAIR_LATER}`")
                return Step.WRITE
            self.plan.pair = "now"
        if self.dry_run:
            verb = "read" if self.plan.pair == "check" else "pair with"
            self.ui.say(f"(dry run) would {verb} the TV at {ip}")
            return Step.WRITE
        if not self.env.can_pair(self.key_file):
            self.ui.say("the LAN-API library is not installed yet; pairing follows the install")
            self.plan.pair = "late" if self.plan.pair == "now" else "late-check"
            return Step.WRITE
        self._pair_now()
        return Step.WRITE

    def _pair_now(self) -> None:
        if self.plan.pair in ("now", "late"):
            self.ui.say(f"pairing with {self.pair_ip}: look at the TV and accept the connection prompt...")
        r = self.env.pair(self.pair_ip, self.key_file)
        self.plan.reading = r
        if self.env.key_exists(self.key_file):
            self.env.secure_key(self.key_file)
        if not r.reachable:
            self.ui.say(
                f"the TV did not answer over its LAN API ({r.error}): it may be off, or the prompt was not\n"
                f"accepted in time. Setup goes on; pair later with `{PAIR_LATER}`."
            )
            return
        # (W12) the TV's country, for the must-allow hosts LG names by country: written once, on a new
        # install whose settings do not name one; the brief says when the TV and the settings disagree
        cc = lgwebos.country_code(r.values.get("country") or r.values.get("option.country"))
        if cc and cc != "us" and not self.s.tv_country and "TV_COUNTRY" not in self.plan.changes:
            self.plan.changes["TV_COUNTRY"] = cc
            self.ui.say(
                f"the TV says its country is {cc.upper()}: TV_COUNTRY={cc} keeps its service names reachable"
            )
        acr = r.acr_off
        if acr is True:
            self.ui.say("paired; Live Plus (LG's viewing-data collection) is off")
        elif acr is False:
            self.ui.say(
                "paired; Live Plus (LG's viewing-data collection) is ON. Turn it off on the TV under\n"
                "General > Additional Settings > Live Plus. The gateway blocks its servers either way."
            )
        else:
            self.ui.say("paired; the TV did not report Live Plus")

    def step_write(self) -> Step:
        try:
            self.plan.diff = config.save_conf(self.conf_path, self.plan.changes, self.template, dry_run=True)
        except ValueError as e:
            raise SetupError(f"refused, nothing written: {e}") from None
        installed = self.env.installed()
        if self.plan.diff:
            new_file = not os.path.exists(self.conf_path)
            self.ui.say(
                f"\n{self.conf_path} does not exist yet; it is created from the shipped template, with:"
                if new_file
                else f"\nchanges to {self.conf_path}:"
            )
            for line in self.plan.diff:
                self.ui.say("  " + line)
            question = f"Write these changes to {self.conf_path}?"
            self.plan.write = self.dry_run or self.ui.yes_no(question, True)
            if not self.plan.write:
                raise SetupError("nothing written")
        else:
            self.ui.say(f"\n{self.conf_path} already holds these settings; nothing to write")
        auto = bool(self.plan.diff) or not installed or self.plan.brought_up
        want = {"yes": True, "no": False}.get(self.answers.apply, auto)
        if self.dry_run:
            self.plan.apply = want
            return Step.APPLY
        if not want and not self.ui.unattended:
            self.ui.say("the gateway already runs with these settings")
        if self.plan.resolver is not None:  # (resolver)
            self.ui.say(f"after that, the TV's lookups move to {self.plan.resolver.label}, tested first")
        self.plan.apply = self.ui.yes_no("Run the installer to apply them now?", want)
        if self.plan.apply:
            self._installer()  # fail before anything is written when there is none
        return Step.APPLY

    def _installer(self) -> str:
        if self.installer is None:
            self.installer = find_installer(self.answers.installer)
            if self.installer is None:
                raise SetupError(
                    "install.sh not found: give its path with --installer (deploy/install.sh in the repo)"
                )
        return self.installer

    def step_apply(self) -> Step:
        if self.dry_run:
            if self.plan.diff:
                self.ui.say(f"(dry run) would write {self.conf_path}")
            if self.plan.apply:
                self.ui.say(f"(dry run) would run {self._installer()}")
            if self.plan.resolver is not None:  # (resolver)
                self.ui.say(
                    f"(dry run) would then move the TV's lookups to {self.plan.resolver.label}, tested first"
                    " and put back if it fails"
                )
            return Step.PAIR_LATE
        if not self.plan.write and not self.plan.apply:
            self._switch_resolver()  # (resolver) an installed gateway whose only change is the lookups
            return Step.PAIR_LATE
        with self.env.lock() as fd:
            if self.plan.write:
                config.save_conf(self.conf_path, self.plan.changes, self.template)
                self.ui.say(f"wrote {self.conf_path}")
            if self.plan.apply:
                self.ui.say(f"running {self._installer()} (a few minutes on a first install)...")
                self.plan.installer_rc = self.env.run_installer(self._installer(), fd, APPLY_PASS)
        if self.plan.installer_rc == APPLY_VERIFY_FAILED:
            self.ui.say(
                "the installer finished; a check still failed at its end, often the filter still loading\n"
                "its lists, so setup checks again below"
            )
        elif not self._installed_ok():
            self.ui.say(f"the installer stopped (exit {self.plan.installer_rc}); its output above says why")
        elif not self.plan.apply:
            self.ui.say("settings written; apply them later with the installer (sudo ./install.sh)")
        self._switch_resolver()  # (resolver) after the installer and its lock, never before
        return Step.PAIR_LATE

    def step_pair_late(self) -> Step:
        if self.dry_run or self.plan.pair not in ("late", "late-check"):
            return Step.VERIFY
        self.plan.pair = "late" if self.plan.pair == "late" else "check"
        if self.env.can_pair(self.key_file):
            self._pair_now()
        else:
            self.ui.say(
                "pairing still cannot run (the LAN-API library is missing); "
                f"after the install, pair with `{PAIR_LATER}`"
            )
        return Step.VERIFY

    def step_verify(self) -> Step:
        if self.dry_run:
            self.ui.say("(dry run) would run tvgw verify")
            self._summary_dry()
            return Step.DONE
        try:
            s2 = config.load(self.conf_path)
        except ValueError as e:  # cannot happen through the writer; a hand edit made meanwhile can
            raise SetupError(f"the settings file no longer loads: {e}") from None
        self.ui.say("\nchecking the gateway (tvgw verify):")
        r = self._verify(s2)
        if self.plan.installer_rc in (0, APPLY_VERIFY_FAILED):  # an install ran to its end just now
            r = self._settle(s2, r)
        self.plan.verified = r
        for c in r.checks:
            self.ui.say("  " + c.line())
        self.ui.say("")
        self._summary(r)
        return Step.DONE

    def _verify(self, s2: config.Settings):
        try:
            return self.env.verify(s2)
        except (OSError, ValueError) as e:  # the profile the settings now name cannot be loaded
            raise SetupError(f"tvgw verify could not run: {e}") from None

    def _settle(self, s2: config.Settings, r):
        """After an install, a FAIL of a check verify.SETTLING names (the filter's lists, the DoH list,
        the services and the capture starting) is waited on, every SETTLE_EVERY seconds for up to
        SETTLE_WAIT; any other FAIL is reported at once, since waiting would only hide it."""
        from tvgw.verify import SETTLING

        deadline = self.env.clock() + SETTLE_WAIT
        told = False
        while True:
            failed = [c.name for c in r.checks if not c.ok]
            if not failed or any(name not in SETTLING for name in failed):
                return r
            if self.env.clock() + SETTLE_EVERY > deadline:
                self.plan.settling = True
                return r
            if not told:
                self.ui.say(
                    "some checks are still settling (the filter loading its lists, a service starting); "
                    f"checking again every {SETTLE_EVERY:.0f} s for up to {SETTLE_WAIT / 60:.0f} min"
                )
                told = True
            self.env.sleep(SETTLE_EVERY)
            r = self._verify(s2)

    def _summary_dry(self) -> None:
        n = len(self.plan.changes)
        self.ui.say(
            f"\ndry run done: {n} setting(s) would change"
            + (", then the installer would run" if self.plan.apply else "")
            + ". Nothing was written."
        )

    def _summary(self, r) -> None:
        fails = [c for c in r.checks if not c.ok]
        if not fails and self._installed_ok():
            self.ui.say(
                f"Result: the gateway holds. All {len(r.checks)} checks passed: the TV's only way out is\n"
                "through the gateway, its DNS goes through the filter, and the services are running.\n"
                "Read the first brief tomorrow with `tvgw brief`."
            )
            if self.plan.dhcp_uplink:  # (uplink) a moved address cuts every stream the TV has open
                self.ui.say(RESERVE)
            self._summary_resolver()
            return
        self.ui.say(
            f"Result: NOT done. {len(fails)} of {len(r.checks)} checks failed"
            + (f" and the installer exited {self.plan.installer_rc}" if not self._installed_ok() else "")
            + ".\nEach FAIL line above names what is wrong; docs/reference/verify-checks.md explains"
            " every check.\nFix it and run `sudo tvgw setup` again: it is safe to repeat."
        )
        if self.plan.settling:
            self.ui.say(
                "These checks can still pass on their own once the filter has its lists and the services\n"
                "have started. Check again in a few minutes with: sudo tvgw verify"
            )
        self._summary_resolver()

    def _summary_resolver(self) -> None:
        """(resolver) A choice of who answers the TV's lookups that did not take is said last."""
        if self.plan.resolver is not None and self.plan.resolver_rc not in (None, 0):
            self.ui.say(
                f"The TV's lookups did not move to {self.plan.resolver.label}: the lines above say why,"
                " and they go where they went before."
            )


def _valid(key: str, required: bool = False) -> Callable[[str], str | None]:
    """A prompt check that is the writer's own check for the key, so a prompt can never accept a value
    the write would refuse."""

    def check(v: str) -> str | None:
        if required and not v:
            return f"{key} is needed"
        try:
            config.check_value(key, v)
        except ValueError as e:
            return str(e)
        return None

    return check


def main(a, s: config.Settings, env: Env | None = None, out: TextIO | None = None) -> int:
    """`tvgw setup` from the parsed arguments: read the answers, decide whether questions can be asked,
    build the live system and run the flow."""
    out = out or sys.stdout
    answers = Answers()
    if a.answers:
        try:
            answers = parse_answers(Path(a.answers).read_text(encoding="utf-8"))
        except (OSError, ValueError) as e:
            print(f"tvgw setup: answers file {a.answers}: {e}", file=out)
            return 1
    if a.no_ssdp:
        answers.ssdp = False
    interactive = sys.stdin.isatty() and not a.yes
    if not interactive and not a.yes:
        print(
            "tvgw setup: no terminal to ask on; give the answers with --answers FILE --yes "
            "(or --yes alone to take every default)",
            file=out,
        )
        return 1
    ui = Prompter(out, ask=input if interactive else None, unattended=not interactive)
    installer = a.installer or answers.installer or None
    if installer and not os.path.isfile(installer):
        print(f"tvgw setup: installer {installer} not found", file=out)
        return 1
    found = installer or find_installer()
    template = ""
    if found:
        ex = Path(found).with_name("tvgw.conf.example")
        with contextlib.suppress(OSError):
            template = ex.read_text(encoding="utf-8")
    return Setup(
        s,
        a.conf,
        env or live_env(s),
        ui,
        answers=answers,
        dry_run=a.dry_run,
        installer=installer,
        template=template,
    ).run()
