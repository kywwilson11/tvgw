"""(lists) The real AdGuard Home, configured by `adguardcfg.plan`, asked from a namespace TV.

The HTTPS/SVCB strip and every blocked answer the gateway reads depend on `blocking_mode: default`
(design decision 6). The unit suite checks that the plan writes it; this checks what the binary then
says on the wire (report 02's test T4): a blocked HTTPS query is NOERROR with an empty answer and no
SOA, a blocked SVCB query is NODATA (NOERROR with an SOA), and a name a rule blocks answers 0.0.0.0. It
also runs the binary's own `--check-config` on the plan's output, which is the check `tvgw adguard
upgrade` relies on, and, after making AdGuard write its own YAML through a settings save, checks that
the file it wrote still matches the plan on every key the plan owns.

It needs the AdGuard Home binary: CI's virtual job downloads the pinned release and names it in
TVGW_VIRTUAL_ADGUARD. Without it the tests skip, or fail under TVGW_VIRTUAL_REQUIRED=1. The two
namespaces are its own (`tvgwv-<pid>-agh` and `tvgwv-<pid>-aghtv`), separate from the gateway
topology, and nothing on the host is written outside a temporary directory."""

from __future__ import annotations

import contextlib
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import time
from pathlib import Path

import pytest
import vnet

from tvgw import adguardcfg, profile
from tvgw.config import Settings

pytestmark = pytest.mark.virtual

PROBE = Path(__file__).resolve().parent / "dnsprobe.py"
GW, TV = "10.10.10.1", "10.10.10.50"
# no upstream is reachable from the namespace: every answer below must come from AdGuard's own rules
SETTINGS = Settings(
    tv_ip=TV,
    gw_ip=GW,
    tv_name="tv",
    dns_upstreams="https://192.0.2.53/dns-query",
    dns_bootstrap="192.0.2.53",
)
BASE = {
    "http": {"address": "127.0.0.1:3000"},
    "users": [],
    "dns": {"bind_hosts": [GW], "port": 53},
    "schema_version": adguardcfg.SCHEMA_CEILING,
}


class Resolver:
    """AdGuard Home in its own namespace on GW, and a TV namespace beside it on TV."""

    def __init__(self, binary: str, artifacts: Path):
        tag = f"{vnet.PREFIX}{os.getpid()}"
        self.agh, self.tv = f"{tag}-agh", f"{tag}-aghtv"
        self.binary, self.artifacts = binary, artifacts
        self.work = Path(tempfile.mkdtemp(prefix="tvgw-virtual-agh-"))
        self.yaml = self.work / "AdGuardHome.yaml"
        self.proc: subprocess.Popen | None = None
        self.log = None
        self.made: list[str] = []
        self.desired = adguardcfg.desired(profile.load("lg-webos"), SETTINGS)
        self.planned = adguardcfg.plan(BASE, self.desired)

    def ns(self, name: str, *argv: str, **kw) -> subprocess.CompletedProcess:
        return vnet.run(["ip", "netns", "exec", name, *argv], **kw)

    def build(self) -> None:
        for name in (self.agh, self.tv):
            vnet.run(["ip", "netns", "add", name])
            self.made.append(name)
            vnet.run(["ip", "-n", name, "link", "set", "lo", "up"])
        veth = ["link", "add", "eth0", "type", "veth", "peer", "name", "eth0", "netns", self.tv]
        vnet.run(["ip", "-n", self.agh, *veth])
        for name, addr in ((self.agh, GW), (self.tv, TV)):
            vnet.run(["ip", "-n", name, "addr", "add", f"{addr}/24", "dev", "eth0"])
            vnet.run(["ip", "-n", name, "link", "set", "eth0", "up"])
        self.yaml.write_text(adguardcfg.dump_yaml(self.planned), encoding="utf-8")
        self.save("adguard/AdGuardHome.planned.yaml", self.yaml.read_text(encoding="utf-8"))

    def check_config(self) -> subprocess.CompletedProcess:
        """The binary's own check, with the argv adguardcfg.check_config uses, inside the namespace
        where the bind address exists."""
        argv = [
            self.binary,
            "--check-config",
            "-c",
            str(self.yaml),
            "-w",
            str(self.work),
            "--no-check-update",
        ]
        return self.ns(self.agh, *argv, check=False, timeout=120)

    def start(self) -> None:
        log_path = self.artifacts / "services" / "adguard.log"
        log_path.parent.mkdir(parents=True, exist_ok=True)
        self.log = log_path.open("w", encoding="utf-8")
        argv = ["ip", "netns", "exec", self.agh, self.binary, "-c", str(self.yaml), "-w", str(self.work)]
        self.proc = subprocess.Popen([*argv, "--no-check-update"], stdout=self.log, stderr=subprocess.STDOUT)
        deadline = time.monotonic() + 45
        while time.monotonic() < deadline:
            if self.proc.poll() is not None:
                raise RuntimeError(f"AdGuard Home exited {self.proc.returncode}; see services/adguard.log")
            if self.ask("HTTPS", "ready.example.com") is not None:
                return
            time.sleep(0.5)
        raise RuntimeError("AdGuard Home did not answer within 45 s; see services/adguard.log")

    def ask(self, qtype: str, name: str) -> dict | None:
        out = self.ns(self.tv, sys.executable, "-I", str(PROBE), GW, qtype, name, check=False, timeout=30)
        return json.loads(out.stdout) if out.returncode == 0 and out.stdout.strip() else None

    def save_settings(self) -> int:
        """A settings save through AdGuard's own API, as the web UI does it: `POST /control/dns_config`
        with nothing to change. AdGuard then writes its whole YAML from memory, which is the
        serialization a UI save would leave behind. `users: []` means no authentication. Returns the
        HTTP status."""
        code = (
            "import sys, urllib.request\n"
            "r = urllib.request.Request('http://127.0.0.1:3000/control/dns_config', data=b'{}',"
            " headers={'Content-Type': 'application/json'}, method='POST')\n"
            "print(urllib.request.urlopen(r, timeout=20).status)\n"
        )
        out = self.ns(self.agh, sys.executable, "-I", "-c", code, check=False, timeout=30)
        self.save("adguard/dns_config.txt", out.stdout + out.stderr)
        return int(out.stdout.strip() or 0) if out.returncode == 0 else 0

    def save(self, relative: str, text: str) -> None:
        path = self.artifacts / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text, encoding="utf-8")

    def destroy(self) -> None:
        if self.proc is not None:
            with contextlib.suppress(OSError):
                self.proc.terminate()
            with contextlib.suppress(OSError, subprocess.TimeoutExpired):
                self.proc.wait(timeout=10)
            with contextlib.suppress(OSError):
                self.proc.kill()
            self.proc = None
        if self.log is not None:
            self.log.close()
            self.log = None
        with contextlib.suppress(OSError):
            if self.yaml.exists():
                self.save("adguard/AdGuardHome.after.yaml", self.yaml.read_text(encoding="utf-8"))
        for name in reversed(self.made):
            vnet.run(["ip", "netns", "del", name], check=False)
        self.made = []
        shutil.rmtree(self.work, ignore_errors=True)


@pytest.fixture(scope="module")
def resolver(artifacts):
    binary = os.environ.get("TVGW_VIRTUAL_ADGUARD", "")
    if not (binary and os.access(binary, os.X_OK)):
        why = "TVGW_VIRTUAL_ADGUARD does not name an AdGuard Home binary"
        if os.environ.get("TVGW_VIRTUAL_REQUIRED") == "1":
            pytest.fail(why)
        pytest.skip(why)
    r = Resolver(binary, artifacts)
    try:
        r.build()
        checked = r.check_config()
        r.save("adguard/check-config.txt", checked.stdout + checked.stderr)
        r.checked = checked
        if checked.returncode == 0:
            r.start()
        yield r
    finally:
        r.destroy()


def blocked_name(d: adguardcfg.Desired) -> str:
    """A name one of the profile's own plain rules blocks (`||name^`, no modifier)."""
    for rule in d.user_rules:
        m = re.fullmatch(r"\|\|([a-z0-9.-]+)\^", rule)
        if m:
            return m.group(1)
    raise AssertionError("the profile has no plain block rule to probe")


def test_the_binary_accepts_the_plan(resolver):
    assert resolver.checked.returncode == 0, resolver.checked.stdout + resolver.checked.stderr


def test_https_from_the_tv_is_noerror_with_no_answer_and_no_soa(resolver):
    """Report 02's T4: the strip's answer in `default` mode. An SOA here would be the NODATA path, and
    an RCODE other than NOERROR an RFC 9460 resolution failure a client may give up on."""
    got = resolver.ask("HTTPS", "crypto.example.com")
    assert got is not None and got["rcode"] == 0, got
    assert got["answer"] == [] and got["authority"] == [], got


def test_svcb_from_the_tv_is_nodata_with_an_soa(resolver):
    got = resolver.ask("SVCB", "svc.example.com")
    assert got is not None and got["rcode"] == 0, got
    assert got["answer"] == [] and got["authority"][:1] == [6], got  # 6: SOA


def test_a_name_a_rule_blocks_answers_0_0_0_0(resolver):
    """The answer dnsmsg.is_blocked_answer, tvgw verify's sentinels and the hardware suite read."""
    got = resolver.ask("A", blocked_name(resolver.desired))
    assert got is not None and got["rcode"] == 0 and got["addresses"] == ["0.0.0.0"], got


def test_adguard_keeps_the_owned_keys_as_the_plan_wrote_them(resolver):
    """AdGuard rewrites its YAML on every settings save, from its own in-memory config. The file it
    writes must not differ from the plan on a key the plan owns, or `tvgw adguard diff` would report
    drift for ever after a UI save: this is where `30s`, `12h` and `90d` meet AdGuard's own duration
    writer (report 06, F5). At schema 34 nothing migrates at start, so without the save the file would
    still be the plan's own text and the comparison would prove nothing."""
    assert resolver.proc is not None and resolver.proc.poll() is None
    written = resolver.yaml.read_text(encoding="utf-8")
    assert resolver.save_settings() == 200, "see adguard/dns_config.txt"
    deadline = time.monotonic() + 10
    while resolver.yaml.read_text(encoding="utf-8") == written and time.monotonic() < deadline:
        time.sleep(0.2)
    after = resolver.yaml.read_text(encoding="utf-8")
    resolver.save("adguard/AdGuardHome.saved.yaml", after)
    assert after != written, "AdGuard did not rewrite its YAML after the settings save"
    live = adguardcfg.load_yaml(str(resolver.yaml))
    assert adguardcfg.changes(live, adguardcfg.plan(live, resolver.desired)) == []  # what `diff` computes
    assert live["filtering"]["blocking_mode"] == "default"
