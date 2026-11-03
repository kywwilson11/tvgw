"""(adguard) The wizard-free first run against the real AdGuard Home, started directly in a namespace
(design decision 52; review E-F12: `install()` itself needs systemd, the container tier runs it).

AdGuard Home with no YAML is started as `aghinstall.install()` starts it, `--web-addr 127.0.0.1:<port>
--no-check-update`, in a namespace pair of its own (`tvgwv-<pid>-seed` on 10.10.10.1 and
`tvgwv-<pid>-seedtv` on 10.10.10.60). `aghinstall.first_run()` then answers its wizard from inside the
namespace. Checked: the wizard and, after it, the page and DNS listen on 127.0.0.1 alone, never on a
wildcard, at any point a sampler sees; the YAML holds tvgw's one user and the page's address;
`adguardcfg.apply()` with `ADGUARD_LISTEN=gateway` takes it over and AdGuard then answers at GW_IP
from the TV's side and on loopback; and a port 53 something else holds is reported, with its holder.

It needs the binary named by TVGW_VIRTUAL_ADGUARD (CI's virtual job fetches the pinned release through
aghinstall); without it the module skips, or fails under TVGW_VIRTUAL_REQUIRED=1. Off Linux, or
without root, the suite's conftest skips it. To run it on a Mac, use the privileged container of
tests/virtual/README.md with the arm64 release."""

from __future__ import annotations

import contextlib
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import threading
import time
from pathlib import Path

import pytest
import vnet

from tvgw import adguardcfg, aghinstall, profile
from tvgw.config import Settings

pytestmark = pytest.mark.virtual

PROBE = Path(__file__).resolve().parent / "dnsprobe.py"
GW, TV = "10.10.10.1", "10.10.10.60"
WIZARD_PORT = 24567  # the namespace is new: nothing else holds anything there
SETTINGS = Settings(
    tv_ip=TV,
    gw_ip=GW,
    tv_name="tv",
    adguard_listen="gateway",
    dns_upstreams="https://192.0.2.53/dns-query",  # unreachable: every answer is AdGuard's own
    dns_bootstrap="192.0.2.53",
)
# runs inside the namespace with the suite's interpreter, so it imports the tvgw under test; it prints
# what happened and never the password
DRIVER = """
import json, sys
from tvgw import aghinstall
base, yaml_path, hold = sys.argv[1], sys.argv[2], sys.argv[3] == "1"
try:
    aghinstall.first_run(base, yaml_path, aghinstall.new_password())
    print(json.dumps({"ok": True}))
except aghinstall.SeedError as e:
    print(json.dumps({"ok": False, "kind": type(e).__name__, "message": str(e),
                      "holder": aghinstall.port53_holder() if hold else ""}))
"""
WILDCARD = re.compile(r"^(?:0\.0\.0\.0|\*|\[::\]|::):(\d+)$")
WATCHED = {WIZARD_PORT, 3000, 53}  # the wizard, the page and DNS: none may ever be on a wildcard


def wide(addresses) -> list[str]:
    """The listeners on a wildcard address among the watched ports."""
    return sorted({a for a in addresses if (m := WILDCARD.match(a)) and int(m.group(1)) in WATCHED})


def blocked_name(d: adguardcfg.Desired) -> str:
    for rule in d.user_rules:
        m = re.fullmatch(r"\|\|([a-z0-9.-]+)\^", rule)
        if m:
            return m.group(1)
    raise AssertionError("the profile has no plain block rule to probe")


class Box:
    """A namespace with nothing in it but AdGuard Home, and a TV namespace beside it."""

    def __init__(self, binary: str, artifacts: Path, role: str):
        tag = f"{vnet.PREFIX}{os.getpid()}"
        self.ns, self.tv = f"{tag}-{role}", f"{tag}-{role}tv"
        self.binary, self.artifacts, self.role = binary, artifacts, role
        self.work = Path(tempfile.mkdtemp(prefix=f"tvgw-virtual-{role}-"))
        self.yaml = self.work / "AdGuardHome.yaml"
        self.procs: list[subprocess.Popen] = []
        self.agh: subprocess.Popen | None = None
        self.made: list[str] = []
        self.logs: list = []
        self.seen: list[str] = []  # the local address of every TCP and UDP listener a sample saw

    def build(self) -> None:
        for name in (self.ns, self.tv):
            vnet.run(["ip", "netns", "add", name])
            self.made.append(name)
            vnet.run(["ip", "-n", name, "link", "set", "lo", "up"])
        veth = ["link", "add", "eth0", "type", "veth", "peer", "name", "eth0", "netns", self.tv]
        vnet.run(["ip", "-n", self.ns, *veth])
        for name, addr in ((self.ns, GW), (self.tv, TV)):
            vnet.run(["ip", "-n", name, "addr", "add", f"{addr}/24", "dev", "eth0"])
            vnet.run(["ip", "-n", name, "link", "set", "eth0", "up"])

    def exec(self, *argv: str, **kw) -> subprocess.CompletedProcess:
        return vnet.run(["ip", "netns", "exec", self.ns, *argv], **kw)

    def _log(self, name: str):
        path = self.artifacts / "adguard" / f"{self.role}-{name}.log"
        path.parent.mkdir(parents=True, exist_ok=True)
        fh = path.open("a", encoding="utf-8")
        self.logs.append(fh)
        return fh

    def start(self, *extra: str) -> None:
        """AdGuard Home in the namespace, as install() starts its first run (with `--web-addr`) or as
        its service then runs it (without)."""
        argv = ["ip", "netns", "exec", self.ns, self.binary, *extra, "--no-check-update"]
        argv += ["-w", str(self.work), "-c", str(self.yaml)]
        log = self._log("adguard")
        self.agh = subprocess.Popen(argv, stdout=log, stderr=subprocess.STDOUT)

    def stop(self) -> None:
        if self.agh is not None:
            with contextlib.suppress(OSError):
                self.agh.terminate()
            with contextlib.suppress(OSError, subprocess.TimeoutExpired):
                self.agh.wait(timeout=15)
            with contextlib.suppress(OSError):
                self.agh.kill()
            self.agh = None

    def control(self, action: str, unit: str) -> None:
        """adguardcfg.apply()'s systemctl, for the AdGuard of this namespace."""
        if action == "stop":
            self.stop()
        elif action == "start":
            self.start()
        else:
            raise AssertionError(f"unexpected control {action} {unit}")

    def check(self, candidate: str) -> tuple[bool, str]:
        out = self.exec(
            self.binary,
            "--check-config",
            "-c",
            candidate,
            "-w",
            str(self.work),
            "--no-check-update",
            check=False,
            timeout=120,
        )
        return out.returncode == 0, out.stdout + out.stderr

    def local_addresses(self) -> list[str]:
        """The local address of every listener, from `ss -Hltnu` (netid state recv send local peer)."""
        out = self.exec("ss", "-Hltnu", check=False, timeout=10)
        return [line.split()[4] for line in out.stdout.splitlines() if len(line.split()) >= 6]

    def sample(self, stop: threading.Event) -> None:
        while not stop.is_set():
            self.seen.extend(self.local_addresses())
            time.sleep(0.1)

    def wait_listening(self, address: str, wait: float = 30.0) -> None:
        deadline = time.monotonic() + wait
        while time.monotonic() < deadline:
            if address in self.local_addresses():
                return
            if self.agh is not None and self.agh.poll() is not None:
                raise AssertionError(
                    f"AdGuard Home exited {self.agh.returncode}; see adguard/{self.role}-adguard.log"
                )
            time.sleep(0.2)
        raise AssertionError(
            f"nothing listens on {address} after {wait:.0f} s; see adguard/{self.role}-adguard.log"
        )

    def drive(self, hold: bool = False) -> dict:
        out = self.exec(
            sys.executable,
            "-c",
            DRIVER,
            f"http://127.0.0.1:{WIZARD_PORT}",
            str(self.yaml),
            "1" if hold else "0",
            check=False,
            timeout=120,
        )
        (self.artifacts / "adguard" / f"{self.role}-driver.txt").write_text(
            out.stdout + out.stderr, encoding="utf-8"
        )
        assert out.returncode == 0, out.stderr
        return json.loads(out.stdout.strip().splitlines()[-1])

    def ask(self, server: str, name: str, from_tv: bool = True) -> dict | None:
        ns = self.tv if from_tv else self.ns
        argv = ["ip", "netns", "exec", ns, sys.executable, "-I", str(PROBE), server, "A", name]
        out = vnet.run(argv, check=False, timeout=30)
        return json.loads(out.stdout) if out.returncode == 0 and out.stdout.strip() else None

    def hold_port_53(self) -> None:
        """A UDP and a TCP socket on 127.0.0.1:53 inside the namespace, held by a process of its own."""
        code = (
            "import socket, time\n"
            "u = socket.socket(socket.AF_INET, socket.SOCK_DGRAM); u.bind(('127.0.0.1', 53))\n"
            "t = socket.socket(); t.bind(('127.0.0.1', 53)); t.listen()\n"
            "print('held', flush=True); time.sleep(600)\n"
        )
        p = subprocess.Popen(
            ["ip", "netns", "exec", self.ns, sys.executable, "-I", "-c", code],
            stdout=subprocess.PIPE,
            text=True,
        )
        self.procs.append(p)
        assert p.stdout is not None and p.stdout.readline().strip() == "held"

    def save_yaml(self, name: str) -> None:
        if self.yaml.exists():
            (self.artifacts / "adguard" / f"{self.role}-{name}.yaml").write_text(
                self.yaml.read_text(encoding="utf-8"), encoding="utf-8"
            )

    def destroy(self) -> None:
        self.stop()
        for p in self.procs:
            with contextlib.suppress(OSError):
                p.kill()
            with contextlib.suppress(OSError, subprocess.TimeoutExpired):
                p.wait(timeout=5)
        for fh in self.logs:
            fh.close()
        for name in reversed(self.made):
            vnet.run(["ip", "netns", "del", name], check=False)
        self.made = []
        shutil.rmtree(self.work, ignore_errors=True)


def adguard_binary() -> str:
    binary = os.environ.get("TVGW_VIRTUAL_ADGUARD", "")
    if not (binary and os.access(binary, os.X_OK)):
        why = "TVGW_VIRTUAL_ADGUARD does not name an AdGuard Home binary"
        if os.environ.get("TVGW_VIRTUAL_REQUIRED") == "1":
            pytest.fail(why)
        pytest.skip(why)
    return binary


@pytest.fixture(scope="module")
def seeded(artifacts):
    """One first run, sampled throughout: the wizard started, answered by aghinstall.first_run()."""
    box = Box(adguard_binary(), artifacts, "seed")
    stop = threading.Event()
    sampler = threading.Thread(target=box.sample, args=(stop,), daemon=True)
    try:
        box.build()
        sampler.start()
        box.start("--web-addr", f"127.0.0.1:{WIZARD_PORT}")
        box.wait_listening(f"127.0.0.1:{WIZARD_PORT}")
        box.wizard_listeners = box.local_addresses()
        box.result = box.drive()
        box.wait_listening("127.0.0.1:3000")
        box.wait_listening("127.0.0.1:53")
        time.sleep(0.5)  # a few more samples of the configured AdGuard
        box.save_yaml("seeded")
        yield box
    finally:
        stop.set()
        if sampler.is_alive():
            sampler.join(timeout=5)
        box.save_yaml("after")
        box.destroy()


def test_the_wizard_listens_on_loopback_alone(seeded):
    assert f"127.0.0.1:{WIZARD_PORT}" in seeded.wizard_listeners
    assert wide(seeded.wizard_listeners) == [], seeded.wizard_listeners
    assert not [
        a for a in seeded.wizard_listeners if a.endswith((":3000", ":53"))
    ]  # no DNS before the wizard


def test_seed_succeeds_and_no_listener_was_ever_on_a_wildcard(seeded):
    assert seeded.result == {"ok": True}, seeded.result
    assert seeded.seen, "the sampler saw nothing"
    assert wide(seeded.seen) == [], f"listeners on a wildcard during the first run: {wide(seeded.seen)}"


def test_the_yaml_holds_tvgws_one_user_and_the_page_on_loopback(seeded):
    cfg = adguardcfg.load_yaml(str(seeded.yaml))
    assert [u["name"] for u in cfg["users"]] == ["admin"] and cfg["users"][0]["password"].startswith("$2")
    assert cfg["http"]["address"] == "127.0.0.1:3000"
    assert cfg["dns"]["bind_hosts"] == ["127.0.0.1"] and cfg["dns"]["port"] == 53
    assert (
        adguardcfg.schema_version(cfg) is not None
        and adguardcfg.schema_version(cfg) <= adguardcfg.SCHEMA_CEILING
    )
    aghinstall.check_users(str(seeded.yaml))


def test_apply_with_gateway_takes_it_over_and_answers_at_gw_ip(seeded):
    """The YAML the wizard wrote, taken over by `tvgw adguard apply`: AdGuard is restarted as its service
    would run it, now on GW_IP and 127.0.0.1, and answers the TV."""
    d = adguardcfg.desired(profile.load("lg-webos"), SETTINGS)
    name = blocked_name(d)

    def ready() -> bool:
        deadline = time.monotonic() + 45
        while time.monotonic() < deadline:
            got = seeded.ask(GW, name)
            if got is not None and got["addresses"] == ["0.0.0.0"]:
                return True
            time.sleep(0.5)
        return False

    done = adguardcfg.apply(
        str(seeded.yaml), d, control=seeded.control, ready=ready, check=seeded.check, guard=lambda: None
    )
    seeded.save_yaml("applied")
    assert any(c.startswith("dns.bind_hosts: ['127.0.0.1'] -> ['10.10.10.1', '127.0.0.1']") for c in done), (
        done
    )
    live = adguardcfg.load_yaml(str(seeded.yaml))
    assert live["dns"]["bind_hosts"] == [GW, "127.0.0.1"] and live["dns"]["port"] == 53
    assert adguardcfg.changes(live, adguardcfg.plan(live, d)) == []  # `tvgw adguard diff` is empty
    from_tv = seeded.ask(GW, name)
    on_loopback = seeded.ask("127.0.0.1", name, from_tv=False)
    assert from_tv is not None and from_tv["addresses"] == ["0.0.0.0"], from_tv
    assert on_loopback is not None and on_loopback["addresses"] == ["0.0.0.0"], on_loopback
    addresses = seeded.local_addresses()
    assert f"{GW}:53" in addresses and "127.0.0.1:53" in addresses
    assert wide(addresses) == [], addresses


def test_a_busy_port_53_is_reported_with_its_holder(artifacts):
    box = Box(adguard_binary(), artifacts, "busy")
    try:
        box.build()
        box.hold_port_53()
        box.start("--web-addr", f"127.0.0.1:{WIZARD_PORT}")
        box.wait_listening(f"127.0.0.1:{WIZARD_PORT}")
        got = box.drive(hold=True)
        assert got["ok"] is False and got["kind"] == "Port53Busy", got
        assert "port 53 on 127.0.0.1 is not free for AdGuard Home" in got["message"]
        assert "python" in got["holder"] and "127.0.0.1:53" in got["holder"], got["holder"]
        assert not box.yaml.exists()  # nothing was configured
    finally:
        box.destroy()
