"""The systemd container tier: a whole gateway in one privileged container, and a TV in a namespace inside it.

    container (debian:13, systemd as PID 1)                      TV namespace `tv`
    eth0  Docker's bridge: the uplink, WAN_IF                      tvnic  the TV's MAC, DHCP client
    eth1  the TV port, TV_IF: a veth  -----------------------------
          tv-lan 10.10.10.1/24 once the bringup pass made it

The image (Dockerfile) holds what a new Debian 13 computer holds once the package's dependencies are
installed: systemd, udev, NetworkManager, dnsmasq, nginx with its stream module, the capture tools and
Python. The container runs with the checkout mounted read-only at /mnt/checkout, which the gateway copies
to /opt/tvgw/src as deploy/sync-install.sh does, and with the runner's /lib/modules, so `modprobe` in
tvgw-apply finds the kernel's modules. The TV port is a veth named `eth1`, a name NetworkManager's own
udev rules manage (they leave every other veth name alone), so the bringup pass meets NetworkManager's
automatic DHCP profile on it, as on a computer with a second network port.

Everything that needs Docker runs only in tests/container; the pure parts here (the `docker run` line,
the settings file, the route and listener parsers, the settle loop, the stale-container rule) are
unit-tested in tests/unit/test_container_harness.py, which runs in every `make gate`."""

from __future__ import annotations

import contextlib
import json
import os
import re
import shlex
import subprocess
import time
from collections.abc import Callable, Iterable
from dataclasses import dataclass, field
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]
TEMPLATE = ROOT / "deploy" / "tvgw.conf.example"
APPLY = ROOT / "deploy" / "nftables" / "tvgw-apply"
PREFIX = "tvgwc-"  # every container this tier starts; a killed run's are recognised by it
LABEL = "tvgw.container"  # and labelled, so CI's cleanup step can find them without the name

CHECKOUT = "/mnt/checkout"  # the repository, mounted read-only
SRC = "/opt/tvgw/src"  # where the gateway runs from, as on the reference (deploy/sync-install.sh)
VENV = "/opt/tvgw-venv"
PYTHON = f"{VENV}/bin/python"
INSTALL = f"{SRC}/deploy/install.sh"
GUEST = f"{CHECKOUT}/tests/container/guest"  # the scripts that run inside the container

TV_NS = "tv"
TV_NIC = "tvnic"  # the TV's end of the veth, inside its namespace
TV_IF = "eth1"  # the gateway's end: the TV port
WAN_IF = "eth0"  # Docker's own interface: the uplink
TV_MAC = "00:00:5e:00:53:17"  # RFC 7042's documentation range: a TV no network has
# the TV port's own, from the same range: a network adapter keeps its MAC when it is plugged in again, and
# NetworkManager remembers the profiles it made for a port by it
PORT_MAC = "00:00:5e:00:53:01"
TV_IP = "10.10.10.17"
GW_IP = "10.10.10.1"
TV_NET = "10.10.10.0/24"
TV_LEASE = "/run/tvgw-container/tv-lease"  # what the TV's DHCP client was given (guest/tv-dhcp.sh)
LISTENERS = "/run/tvgw-container/listeners"  # every listening socket seen (guest/listeners.py)
# a host outside every network here that a GitHub-hosted runner always reaches on HTTPS, and no DNS
# resolver, which the firewall would refuse: the TV's connections to it are what "a route out" means
OUTSIDE = "github.com"

# The settings of a new install with the TV already named, as setup writes them after its discovery: the
# template, then these keys. WAN_GW is the container's own default gateway, read at run time
SETTINGS = {
    "TV_MAC": TV_MAC,
    "TV_IP": TV_IP,
    "TV_NAME": "tv",
    "PROFILE": "lg-webos",
    "TV_IF": TV_IF,
    "TV_NET": TV_NET,
    "GW_IP": GW_IP,
    "WAN_IF": WAN_IF,
    "UPLINK": "direct",
    "VPN_IF": "none",  # no VPN client on this computer: nothing hides the gateway's own replies
    "ADGUARD_LISTEN": "gateway",
}


# ---- pure helpers ----------------------------------------------------------------------------------


def run_argv(image: str, name: str, checkout: str | Path, label: str = LABEL) -> list[str]:
    """`docker run` for one gateway: privileged, so systemd, udev, nftables and network namespaces work as
    on a computer; its own cgroup namespace, so systemd owns a cgroup tree; /run and /run/lock as tmpfs, as
    systemd expects; the checkout read-only; the runner's kernel modules read-only, for modprobe."""
    return [
        "run",
        "--detach",
        "--name",
        name,
        "--label",
        f"{label}=1",
        "--hostname",
        "tvgw-container",
        "--privileged",
        "--cgroupns=private",
        "--tmpfs",
        "/run",
        "--tmpfs",
        "/run/lock",
        "--volume",
        "/lib/modules:/lib/modules:ro",
        "--volume",
        f"{Path(checkout).resolve()}:{CHECKOUT}:ro",
        image,
    ]


def image_files() -> list[Path]:
    """The image's build context, as .dockerignore leaves it: the Dockerfile and everything under image/."""
    return [HERE / "Dockerfile", *sorted(p for p in (HERE / "image").rglob("*") if p.is_file())]


def container_name(module: str, pid: int | None = None) -> str:
    """`tvgwc-<pid>-<module>`: one container per test module, named for this run."""
    slug = re.sub(r"[^a-z0-9]+", "-", module.lower()).strip("-")
    return f"{PREFIX}{os.getpid() if pid is None else pid}-{slug}"


def _pid_alive(pid: int) -> bool:
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return False
    except PermissionError:
        return True
    return True


def stale(names: Iterable[str], alive: Callable[[int], bool] = _pid_alive) -> list[str]:
    """The containers a killed run of this tier left: ours by name, and their run's process gone."""
    out = []
    for name in names:
        m = re.fullmatch(re.escape(PREFIX) + r"(\d+)-[a-z0-9-]+", name.strip())
        if m and not alive(int(m.group(1))):
            out.append(name.strip())
    return out


def render_settings(template: str, values: dict[str, str]) -> str:
    """The settings template with each key in `values` set: its line replaced (the comment after it goes,
    since it describes the template's value), a commented reserved line left as it is, and a key the
    template lacks appended."""
    seen: set[str] = set()
    lines = []
    for line in template.splitlines():
        m = re.match(r"([A-Z][A-Z0-9_]*)=", line)
        if m and m.group(1) in values:
            key = m.group(1)
            lines.append(f"{key}={values[key]}")
            seen.add(key)
        else:
            lines.append(line)
    lines += [f"{k}={v}" for k, v in values.items() if k not in seen]
    return "\n".join(lines) + "\n"


def default_gateway(route_text: str, dev: str = WAN_IF) -> str:
    """The next hop of `ip -4 route show default` on `dev`: what WAN_GW is on this container."""
    for line in route_text.splitlines():
        m = re.match(r"default via (\d{1,3}(?:\.\d{1,3}){3}) dev (\S+)", line.strip())
        if m and m.group(2) == dev:
            return m.group(1)
    raise ValueError(f"no default route via {dev} in: {route_text.strip()!r}")


def reply_route_in_apply(text: str) -> bool:
    """Does tvgw-apply put the TV subnet in table 100 (design decision 49)? Without it, rule 60 sends the
    gateway's own packets to the TV, from GW_IP, out by the uplink. On a computer with no VPN client the
    TV's ARP for the gateway then fails the TV port's strict reverse-path check, so after the first apply
    the TV reaches neither the gateway nor the internet."""
    return bool(re.search(r'ip route replace "\$TV_NET" dev "\$TV_IF"[^\n]*table "\$RT_TABLE"', text))


def parse_lease(text: str) -> dict[str, str]:
    """guest/tv-dhcp.sh's lease file, `key=value` lines."""
    out = {}
    for line in text.splitlines():
        key, sep, value = line.partition("=")
        if sep:
            out[key.strip()] = value.strip()
    return out


@dataclass(frozen=True)
class Listener:
    proto: str  # tcp or udp
    address: str  # as guest/listeners.py writes it: 0.0.0.0, ::, 127.0.0.1, 10.10.10.1, ...
    port: int

    @property
    def wildcard(self) -> bool:
        return self.address in ("0.0.0.0", "::", "*")


def parse_listeners(text: str) -> set[Listener]:
    """guest/listeners.py's file: one `proto address port` line per listening socket ever seen."""
    out = set()
    for line in text.splitlines():
        parts = line.split()
        if len(parts) == 3 and parts[0] in ("tcp", "udp") and parts[2].isdigit():
            out.add(Listener(parts[0], parts[1], int(parts[2])))
    return out


def exposed(listeners: Iterable[Listener], ports: Iterable[int] | range) -> list[Listener]:
    """The wildcard listeners on any of `ports`: what would answer the home network."""
    wanted = set(ports)
    return sorted((x for x in listeners if x.wildcard and x.port in wanted), key=lambda x: (x.port, x.proto))


@dataclass
class Verdict:
    """The last `tvgw verify --json` of a settle loop."""

    rc: int
    checks: list[dict] = field(default_factory=list)
    runs: int = 0

    @property
    def failed(self) -> list[str]:
        return [str(c.get("name")) for c in self.checks if not c.get("ok")]

    def summary(self) -> str:
        bad = [f"{c.get('name')}: {c.get('detail', '')}" for c in self.checks if not c.get("ok")]
        return f"exit {self.rc} after {self.runs} run(s)" + (": " + "; ".join(bad) if bad else "")


def parse_verify(rc: int, stdout: str) -> Verdict:
    """`tvgw verify --json`'s output as a Verdict; output that is not its JSON is a failed run."""
    try:
        doc = json.loads(stdout)
        checks = [c for c in doc.get("checks", []) if isinstance(c, dict)]
    except (ValueError, AttributeError):
        checks = [{"name": "verify-output", "ok": False, "detail": stdout.strip()[-300:]}]
    return Verdict(rc, checks)


def poll(
    probe: Callable[[], bool],
    timeout: float,
    interval: float = 1.0,
    clock: Callable[[], float] = time.monotonic,
    sleep: Callable[[float], None] = time.sleep,
) -> float | None:
    """The seconds until `probe()` first held, run every `interval` from now; None when it still did not
    hold `timeout` seconds after the start. A probe that ends after the deadline does not count."""
    start = clock()
    while True:
        held = probe()
        took = clock() - start
        if took > timeout:
            return None
        if held:
            return took
        sleep(interval)


def settle(
    verify: Callable[[], Verdict],
    settling: frozenset[str],
    timeout: float,
    interval: float = 10.0,
    patience: int = 3,
    clock: Callable[[], float] = time.monotonic,
    sleep: Callable[[float], None] = time.sleep,
) -> Verdict:
    """Run verify until it exits 0, as setup's settle-then-verify does after its apply pass (design 4.4):
    a failure verify.SETTLING names (the lists, the DoH list, the services still starting) is waited on
    until `timeout`; any other failure is given `patience` runs in a row, then returned at once, since it
    is real and waiting the whole timeout would only hide where it went wrong."""
    deadline = clock() + timeout
    runs = streak = 0
    while True:
        v = verify()
        runs += 1
        v.runs = runs
        if v.rc == 0:
            return v
        streak = streak + 1 if any(name not in settling for name in v.failed) else 0
        if streak >= patience or clock() + interval > deadline:
            return v
        sleep(interval)


# ---- the container -----------------------------------------------------------------------------------


class Docker:
    """The docker CLI. `run` is subprocess.run by default; the unit tests pass a recorder."""

    def __init__(self, exe: str = "docker", run: Callable[..., subprocess.CompletedProcess] = subprocess.run):
        self.exe = exe
        self._run = run

    def __call__(
        self, *args: str, input: str | None = None, timeout: float = 600, check: bool = True
    ) -> subprocess.CompletedProcess:
        argv = [self.exe, *args]
        out = self._run(argv, input=input, capture_output=True, text=True, encoding="utf-8", timeout=timeout)
        if check and out.returncode != 0:
            raise RuntimeError(
                f"{shlex.join(argv)[:300]} exited {out.returncode}: {(out.stderr or out.stdout).strip()[-2000:]}"
            )
        return out

    def available(self) -> str:
        """Empty when the daemon answers; otherwise why not."""
        try:
            out = self("info", "--format", "{{.ServerVersion}}", timeout=30, check=False)
        except (OSError, subprocess.TimeoutExpired) as e:
            return f"docker: {e}"
        return "" if out.returncode == 0 else f"docker info: {(out.stderr or out.stdout).strip()[:200]}"


class Gateway:
    """One running container, addressed by name. Each call is a `docker exec` of bash, as root. With
    `artifacts`, what the installer printed and save()'s captures go to `artifacts/<name>/`."""

    def __init__(self, docker: Docker, name: str, artifacts: Path | None = None):
        self.docker = docker
        self.name = name
        self.artifacts = artifacts

    def keep(self, filename: str, text: str) -> None:
        """`text` into this container's artifacts, when there are any."""
        if self.artifacts is not None:
            dest = self.artifacts / self.name
            dest.mkdir(parents=True, exist_ok=True)
            (dest / filename).write_text(text, encoding="utf-8")

    def sh(
        self, script: str, *, check: bool = True, timeout: float = 600, input: str | None = None
    ) -> subprocess.CompletedProcess:
        args = ["exec", *(["--interactive"] if input is not None else []), self.name]
        return self.docker(
            *args, "bash", "-o", "pipefail", "-c", script, input=input, timeout=timeout, check=check
        )

    def read(self, path: str) -> str:
        return self.sh(f"cat {shlex.quote(path)}").stdout

    def write(self, path: str, text: str, mode: str = "0644") -> None:
        q = shlex.quote(path)
        self.sh(f'install -d -m 755 "$(dirname {q})" && cat >{q} && chmod {mode} {q}', input=text)

    def py(
        self, code: str, *args: str, check: bool = True, timeout: float = 120
    ) -> subprocess.CompletedProcess:
        """`code` in the gateway's virtualenv: the tvgw the gateway runs."""
        argv = shlex.join([PYTHON, "-c", code, *args])
        return self.sh(argv, check=check, timeout=timeout)

    def in_tv(self, script: str, *, check: bool = False, timeout: float = 60) -> subprocess.CompletedProcess:
        """`script` in the TV's network namespace."""
        return self.sh(f"ip netns exec {TV_NS} bash -c {shlex.quote(script)}", check=check, timeout=timeout)

    # lifecycle

    def wait_booted(self, timeout: float = 180, sleep: Callable[[float], None] = time.sleep) -> str:
        """systemd's own word once boot is over: `running`, or `degraded` with the failed units named."""
        deadline = time.monotonic() + timeout
        state = ""
        while time.monotonic() < deadline:
            out = self.sh("systemctl is-system-running", check=False, timeout=30)
            state = out.stdout.strip()
            if state in ("running", "degraded"):
                return state
            sleep(1)
        raise RuntimeError(
            f"systemd in {self.name} did not finish booting in {timeout:.0f} s (state: {state})"
        )

    def reboot(self, timeout: float = 180) -> str:
        """`docker restart`: systemd shuts the computer down and boots it again, from the same disk. The
        TV port, a veth, and the TV's namespace do not survive it, so this is a boot with the TV's network
        adapter unplugged; add_tv() plugs it in again. Returns systemd's word once the boot is over."""
        self.docker("restart", "-t", "60", self.name, timeout=300)
        state = self.wait_booted(timeout)
        self.keep(
            "reboot.txt", f"systemd: {state}\n" + self.sh("systemctl --failed --no-pager", check=False).stdout
        )
        return state

    def prepare(self) -> None:
        """The source at /opt/tvgw/src, copied as deploy/sync-install.sh copies it, and tvgw in its virtualenv
        on PATH, so that `tvgw adguard install` runs before the installer, in setup's order. install.sh
        installs into the same virtualenv when it runs."""
        self.sh(
            f"install -d -m 755 {SRC} && rsync -a --delete --exclude-from={CHECKOUT}/deploy/rsync.exclude"
            f" {CHECKOUT}/ {SRC}/"
        )
        self.sh(
            f"python3 -m venv {VENV} && {VENV}/bin/pip install -q --disable-pip-version-check {SRC}"
            f" && ln -sf {VENV}/bin/tvgw /usr/local/bin/tvgw",
            timeout=900,
        )

    def write_settings(self, extra: dict[str, str] | None = None) -> str:
        """/etc/tvgw/tvgw.conf: the template with SETTINGS, WAN_GW and `extra`; returns the text."""
        wan_gw = default_gateway(self.sh("ip -4 route show default").stdout)
        values = {**SETTINGS, "WAN_GW": wan_gw, **(extra or {})}
        text = render_settings(TEMPLATE.read_text(encoding="utf-8"), values)
        self.sh("install -d -m 755 /etc/tvgw")
        self.write("/etc/tvgw/tvgw.conf", text, mode="0640")
        return text

    def add_tv(self) -> None:
        """The TV: a namespace, a veth whose gateway end is the TV port with PORT_MAC, the TV's MAC on its
        end, and its DHCP client kept running by systemd (a transient unit in the TV's namespace), as a TV
        asks for an address from the moment its cable has a link. After reboot() it is the TV port plugged
        in again."""
        self.sh(
            f"ip netns add {TV_NS}"
            f" && ip link add {TV_IF} address {PORT_MAC} type veth peer name {TV_NIC} netns {TV_NS}"
            f" && ip -n {TV_NS} link set {TV_NIC} address {TV_MAC}"
            f" && ip -n {TV_NS} link set lo up && ip -n {TV_NS} link set {TV_NIC} up"
            f" && ip link set {TV_IF} up"
        )
        self.sh(
            f"install -d -m 755 {Path(TV_LEASE).parent} && systemd-run --unit tvgw-container-tv-dhcp"
            f" --property NetworkNamespacePath=/run/netns/{TV_NS} --setenv TV_LEASE={TV_LEASE}"
            f" busybox udhcpc -f -i {TV_NIC} -t 5 -T 2 -A 5 -x hostname:tv -s {GUEST}/tv-dhcp.sh"
        )

    def watch_listeners(self) -> None:
        """guest/listeners.py from now on: every listening socket the gateway ever has, in LISTENERS."""
        self.sh(
            f"install -d -m 755 {Path(LISTENERS).parent} && systemd-run --unit tvgw-container-listeners"
            f" python3 -I {GUEST}/listeners.py {LISTENERS}"
        )

    def listeners(self) -> set[Listener]:
        """Every listening socket seen since watch_listeners(), the sampler's last pass included."""
        self.sh("sleep 0.5")  # one more pass of the sampler, which reads every 0.1 s
        return parse_listeners(self.read(LISTENERS))

    def lease(self, timeout: float = 90, sleep: Callable[[float], None] = time.sleep) -> dict[str, str]:
        """The TV's lease, once it has one."""
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            out = self.sh(f"cat {TV_LEASE}", check=False)
            if out.returncode == 0 and parse_lease(out.stdout).get("ip"):
                return parse_lease(out.stdout)
            sleep(2)
        raise AssertionError(f"the TV got no lease in {timeout:.0f} s")

    def installer(self, setup_pass: str | None, timeout: float = 1800) -> subprocess.CompletedProcess:
        """install.sh as setup runs it: from /opt/tvgw/src, no terminal on stdin, the pass in
        TVGW_SETUP_PASS (None: unset, the deploy path)."""
        env = f"TVGW_SETUP_PASS={shlex.quote(setup_pass)} " if setup_pass is not None else ""
        out = self.sh(f"{env}{INSTALL} </dev/null", check=False, timeout=timeout)
        tag = setup_pass or "deploy"
        self.keep(
            f"install-{tag}.txt", f"exit {out.returncode}\n--- stdout\n{out.stdout}--- stderr\n{out.stderr}"
        )
        return out

    def verify(self) -> Verdict:
        out = self.sh("tvgw verify --json", check=False, timeout=300)
        return parse_verify(out.returncode, out.stdout)

    def settling(self) -> frozenset[str]:
        out = self.py("from tvgw import verify; print(' '.join(sorted(verify.SETTLING)))")
        return frozenset(out.stdout.split())

    def resolve(self, name: str, server: str, in_tv: bool = False, timeout: float = 4.0) -> list[str] | None:
        """`dnsq.a_records(name, server, timeout)`, from the gateway or from the TV's namespace: None when
        nothing answered in time, [] for a negative answer, ['0.0.0.0'] for a name AdGuard blocks."""
        code = (
            "import json, sys; from tvgw import dnsq;"
            " print(json.dumps(dnsq.a_records(sys.argv[1], sys.argv[2], float(sys.argv[3]))))"
        )
        cmd = shlex.join([PYTHON, "-c", code, name, server, str(timeout)])
        out = self.in_tv(cmd, check=True) if in_tv else self.sh(cmd)
        return json.loads(out.stdout)

    def outside_address(self) -> str:
        """OUTSIDE's first IPv4 address, from the container's own resolver (Docker's), never AdGuard."""
        out = self.sh(f"getent ahostsv4 {OUTSIDE} | awk 'NR == 1 {{ print $1 }}'")
        address = out.stdout.strip()
        if not re.fullmatch(r"\d{1,3}(?:\.\d{1,3}){3}", address):
            raise RuntimeError(f"{OUTSIDE} did not resolve in the container: {out.stdout!r} {out.stderr!r}")
        return address

    def tv_connects(self, address: str, port: int = 443, timeout: float = 5) -> tuple[bool, str]:
        """Whether a TCP connection from the TV to address:port opens, and what the attempt said."""
        code = (
            "import socket, sys\n"
            "try:\n"
            "    s = socket.create_connection((sys.argv[1], int(sys.argv[2])), float(sys.argv[3]))\n"
            "except OSError as e:\n"
            "    print(type(e).__name__, e); sys.exit(1)\n"
            "print('connected from', s.getsockname()[0])\n"
        )
        out = self.in_tv(shlex.join(["python3", "-I", "-c", code, address, str(port), str(timeout)]))
        return out.returncode == 0, (out.stdout + out.stderr).strip()

    def save(self) -> None:
        """What a reader of a failed CI run needs, into the artifacts: the journal, NetworkManager's and the
        TV's view, the ruleset, the routes, the listeners, the settings and a last verify. Best effort: a
        container that is gone saves nothing."""
        captures = {
            "journal.txt": "journalctl -b --no-pager -o short-iso",
            "units-failed.txt": "systemctl --failed --no-pager",
            "nmcli.txt": "nmcli -f NAME,DEVICE,AUTOCONNECT,ACTIVE con; nmcli dev",
            "ruleset.nft": "nft list ruleset",
            "routes.txt": "ip rule; ip route show table all",
            "tv.txt": f"ip -n {TV_NS} addr; ip -n {TV_NS} route; cat {TV_LEASE}",
            "listeners.txt": f"cat {LISTENERS}",
            "settings.txt": "cat /etc/tvgw/tvgw.conf",
            "verify.json": "tvgw verify --json",
        }
        for filename, script in captures.items():
            with contextlib.suppress(Exception):
                out = self.sh(script, check=False, timeout=120)
                self.keep(filename, out.stdout + out.stderr)

    def remove(self) -> None:
        with contextlib.suppress(Exception):
            self.docker("rm", "--force", "--volumes", self.name, check=False, timeout=120)
