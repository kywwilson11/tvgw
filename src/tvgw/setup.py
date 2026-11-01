"""`tvgw setup`: the guided installer. Find the TV, let the owner pick it, pair its LAN API read-only, write
the settings file, run the installer, verify, and say in plain words whether the gateway holds.

It adds no install logic of its own. Discovery is `discover.gather()`, the TV reading and pairing are
`lgwebos.read()`, the settings file is written by `config.save_conf()`, applying is the installer
(`deploy/install.sh`, which renders dnsmasq, nginx and AdGuard Home and loads the firewall), and the
verdict is `verify.check()`. What this module owns is the order, the questions and their defaults, the
answers file for unattended runs, the dry run, and the install lock held across the write and the
install so a deploy cannot read a half-made decision.

The flow is a small state machine (`Step`), and everything that touches the system is a field of `Env`,
so the unit tests drive every path with fakes: no network, no root, no Pi.
"""

from __future__ import annotations

import contextlib
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

from tvgw import config
from tvgw.discover import Candidate, render, safe_name

PAIRABLE_PROFILES = ("lg-webos",)  # profiles whose TV `lgwebos` can read; others skip pairing
# where the installer lives when this code does not run from a checkout; packaging adds its own path here
INSTALLERS = ("/opt/tvgw/src/deploy/install.sh",)
VENV_PYTHONS = ("/opt/tvgw-venv/bin/python", "/usr/lib/tvgw/venv/bin/python")
INSTALLED_MARK = "/usr/local/sbin/tvgw-apply"  # present once install.sh has run to its scripts step
LOCK = "/run/tvgw/install.lock"  # the lock install.sh and sync-install.sh take
LOCK_WAIT = 600.0  # the same 10 minutes install.sh waits
PAIR_TIMEOUT = 60.0  # per LAN-API call: how long the owner has to accept the prompt on the TV
RETRY_EVERY = 10.0  # seconds between unattended discovery attempts
VPN_IFACES = ("tun", "wg", "tailscale", "ppp")  # never proposed as WAN_IF: the TV's direct uplink
IFACE_RE = re.compile(r"[A-Za-z0-9_.-]{1,15}")  # a Linux interface name (IFNAMSIZ 16 with the NUL)
SETUP_KEYS = ("SETUP_TV", "SETUP_PAIR", "SETUP_APPLY", "SETUP_SSDP", "SETUP_WAIT", "SETUP_INSTALLER")
NOT_AN_AGREEMENT = (
    "The TV will ask whether to allow a connection from the gateway: accept that one prompt with the\n"
    "remote. It only lets the gateway read the TV's settings. It is not one of the TV's user agreements:\n"
    "leave Viewing Information, Voice Information and the advertising agreements declined."
)


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

    tv: str = "auto"  # auto | configured | an IP address | a MAC address
    pair: str = "auto"  # auto (pair an LG webOS TV that has no key yet) | yes | no
    apply: str = "auto"  # auto (when the settings changed or the gateway was never installed) | yes | no
    ssdp: bool = True
    wait: float = 120.0  # how long an unattended run keeps looking for the TV
    installer: str = ""
    conf: dict[str, str] = field(default_factory=dict)


def parse_answers(text: str) -> Answers:
    """An answers file is the settings file's own format (KEY=VALUE, `#` comments), so a copy of a working
    tvgw.conf is a valid one. Every value is checked here, before anything runs: a typo in an unattended
    install must stop it at the start, not leave a gateway half set up."""
    raw = config.parse_conf(text)
    a = Answers()
    for key, value in raw.items():
        if key.startswith("SETUP_"):
            if key not in SETUP_KEYS:
                raise ValueError(f"{key}: not a setup answer (known: {', '.join(SETUP_KEYS)})")
            continue
        config.check_value(key, value)
        a.conf[key] = value
    tv = raw.get("SETUP_TV", "auto").strip() or "auto"
    if tv not in ("auto", "configured") and not (_is_ip(tv) or _is_mac(tv)):
        raise ValueError(f"SETUP_TV={tv!r}: expected auto, configured, an IP address or a MAC address")
    a.tv = tv.lower() if _is_mac(tv) else tv
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
    return a


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
    run_installer: Callable[[str, int | None], int]  # (path, lock fd to hand down) -> exit status
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
    done, so a `make deploy` or CI deploy can never read a settings file setup is halfway through. The
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


def run_installer(path: str, lock_fd: int | None) -> int:
    """Run install.sh from its directory with no terminal on stdin (its own interactive discovery must not
    start under setup's), UTF-8 forced, and the held lock passed down as fd 8."""
    env = {**os.environ, "PYTHONUTF8": "1"}
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
    "r = lgwebos.read(sys.argv[1], sys.argv[2], float(sys.argv[3]))\n"
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
    probe = subprocess.run(
        [py, "-c", "import bscpylgtv, tvgw.lgwebos"], capture_output=True, encoding="utf-8", check=False
    )
    return probe.returncode == 0


def pair(ip: str, key_file: str):
    """One reading of the TV over its LAN API. With no key yet, the library registers first and the TV shows
    its prompt; the reading is read-only either way (lgwebos only reads). In this Python when the library
    is here, else in the gateway's virtualenv, where the installer put it."""
    from tvgw import lgwebos

    if importlib.util.find_spec("bscpylgtv") is not None:
        return lgwebos.read(ip, key_file, timeout=PAIR_TIMEOUT)
    py = _venv_python()
    if py is None:
        return lgwebos.TvReading(False, error="bscpylgtv not installed")
    try:
        p = subprocess.run(
            [py, "-c", _PAIR_CODE, ip, key_file, str(PAIR_TIMEOUT)],
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
    )


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
    brought_up: bool = False
    installer_rc: int | None = None
    reading: Any = None
    verified: Any = None


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

    def _exit_code(self) -> int:
        if self.dry_run:
            return 0
        if self.plan.installer_rc not in (None, 0):
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
            "no address to be found at. The installer brings the TV side up first. With no TV known it\n"
            "stops after that with `TV not identified`, which is expected here; setup then looks again."
        )
        installer = self._installer()
        if self.dry_run:
            self.ui.say(f"(dry run) would run {installer} to bring the TV side up, then look for the TV")
            if not has_identity(self._configured()):
                self.ui.say(
                    "(dry run) the TV can only be found once the TV side is up; the plan goes on without it"
                )
            return Step.SETTINGS
        if not self.ui.yes_no("Run the installer now to bring the TV side up?", True):
            raise SetupError("the TV side is not up; nothing was written")
        with self.env.lock() as fd:
            rc = self.env.run_installer(installer, fd)
        self.ui.say(f"installer finished (exit {rc}); looking for the TV again")
        self.plan.brought_up = True
        self._deadline = None
        return Step.DISCOVER

    def _default_pick(self) -> int | None:
        """The index the owner most likely means, or None when that is a guess: the TV already configured,
        else the only device, else the only device a bundled profile recognises."""
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
        given = self.answers.conf
        want: dict[str, str] = {}
        c = self.plan.pick
        if c is not None:
            same_tv = c.mac == cur.get("TV_MAC", "").lower()
            want["TV_MAC"] = given.get("TV_MAC", c.mac)
            # the same TV keeps the address it is pinned to and its name; a new one takes its lease's
            want["TV_IP"] = given.get("TV_IP", cur.get("TV_IP", c.ip) if same_tv else c.ip)
            name_default = given.get(
                "TV_NAME", cur.get("TV_NAME", "tv") if same_tv else safe_name(c.hostname, "tv")
            )
            want["TV_NAME"] = self.ui.text("Name for the TV (DHCP and logs)", name_default, _valid("TV_NAME"))
            if c.profile and "PROFILE" not in given:
                want["PROFILE"] = c.profile
            elif not c.profile:
                self.ui.say(
                    "no bundled profile matches this device; PROFILE stays as it is "
                    "(docs/adding-a-profile.md)"
                )
        tmpl = config.parse_conf(self.template)
        det_if, det_gw = self.env.wan_route()

        unsure: list[str] = []

        def default(key: str, detected: str, fallback: str) -> str:
            # the answers win; then a value the owner set (one that differs from the shipped template);
            # then what the routing table says; then the file's value, whatever it is. That last is a
            # guess (the template's example router), and noted as one.
            if key in given:
                return given[key]
            mine = cur.get(key, "")
            if mine and mine != tmpl.get(key):
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
        gw = default("WAN_GW", det_gw if want["WAN_IF"] == det_if else "", "")
        # the direct uplink routes the TV through it (tvgw-apply stops without it); a VPN uplink does not
        direct = given.get("UPLINK", cur.get("UPLINK", self.s.uplink)) != "vpn"
        want["WAN_GW"] = self.ui.text("Home router's address (WAN_GW)", gw, _valid("WAN_GW", required=direct))
        if unsure and self.ui.unattended:
            # an unattended run never installs the template's example router: the TV would have no way out
            msg = f"{' and '.join(unsure)}: no default route to read them from; set them in the answers file"
            if not self.dry_run:
                raise SetupError(msg)
            self.ui.say(f"(dry run) a real run would stop here: {msg}")
        for key, value in given.items():
            want.setdefault(key, value)
        self.plan.changes = {k: v for k, v in want.items() if cur.get(k) != v}
        return Step.PAIR

    def _valid_wan_if(self, v: str) -> str | None:
        if not IFACE_RE.fullmatch(v):
            return "an interface name: letters, digits, . _ - (at most 15)"
        if v == self.s.tv_if:
            return f"{v} is the TV side; the uplink must be another interface"
        return None

    def step_pair(self) -> Step:
        # the device picked decides (a Roku under the template's PROFILE=lg-webos must not be paired with);
        # without a pick, the profile the settings will name
        c = self.plan.pick
        prof = (c.profile or "") if c else self.target().get("PROFILE", self.s.profile)
        if c is None and not has_identity(self.target()):
            self.ui.say("no TV identified yet; pairing skipped")
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
        else:
            self.ui.say(
                "Pairing lets the gateway read the TV's privacy settings every hour, read-only.\n"
                + NOT_AN_AGREEMENT
            )
            if not self.ui.yes_no("Pair the TV's LAN API now?", True):
                self.ui.say("pairing skipped; run `sudo tvgw setup` again to pair later")
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
                "accepted in time. Setup goes on; run `sudo tvgw setup` again to pair."
            )
            return
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
            return Step.PAIR_LATE
        if not self.plan.write and not self.plan.apply:
            return Step.PAIR_LATE
        with self.env.lock() as fd:
            if self.plan.write:
                config.save_conf(self.conf_path, self.plan.changes, self.template)
                self.ui.say(f"wrote {self.conf_path}")
            if self.plan.apply:
                self.ui.say(f"running {self._installer()} (a few minutes on a first install)...")
                self.plan.installer_rc = self.env.run_installer(self._installer(), fd)
        if self.plan.installer_rc not in (None, 0):
            self.ui.say(f"the installer stopped (exit {self.plan.installer_rc}); its output above says why")
        elif not self.plan.apply:
            self.ui.say("settings written; apply them later with the installer (sudo ./install.sh)")
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
                "after the install, run `sudo tvgw setup` again"
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
        try:
            r = self.env.verify(s2)
        except (OSError, ValueError) as e:  # the profile the settings now name cannot be loaded
            raise SetupError(f"tvgw verify could not run: {e}") from None
        self.plan.verified = r
        for c in r.checks:
            self.ui.say("  " + c.line())
        self.ui.say("")
        self._summary(r)
        return Step.DONE

    def _summary_dry(self) -> None:
        n = len(self.plan.changes)
        self.ui.say(
            f"\ndry run done: {n} setting(s) would change"
            + (", then the installer would run" if self.plan.apply else "")
            + ". Nothing was written."
        )

    def _summary(self, r) -> None:
        fails = [c for c in r.checks if not c.ok]
        if not fails and self.plan.installer_rc in (None, 0):
            self.ui.say(
                f"Result: the gateway holds. All {len(r.checks)} checks passed: the TV's only way out is\n"
                "through the gateway, its DNS goes through the filter, and the services are running.\n"
                "Read the first brief tomorrow with `tvgw brief`."
            )
            return
        self.ui.say(
            f"Result: NOT done. {len(fails)} of {len(r.checks)} checks failed"
            + (f" and the installer exited {self.plan.installer_rc}" if self.plan.installer_rc else "")
            + ".\nEach FAIL line above names what is wrong; docs/troubleshooting.md explains every check.\n"
            "Fix it and run `sudo tvgw setup` again: it is safe to repeat."
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
