"""(pause) The real AdGuard Home through a pause of the shared lists, asked from a namespace TV (design
decision 79).

`tvgw pause` changes AdGuard only through the plan: `listpause.start()` and `listpause.end()` run here as on
the gateway, with the real `adguardcfg.apply()`, whose stop and start are the namespace's AdGuard process
and whose check is the binary's own `--check-config`. The three lists of the shipped LG profile are files
AdGuard has already downloaded (`data/filters/<id>.txt`, fresh, so no refresh is due), each blocking a name
of its own; a stand-in upstream (`agent.py serve --dns`) answers every other name with 198.51.100.7, so
a name a paused list no longer blocks gets an address. During the pause: a name only the HaGeZi Pro or the
LG list blocks resolves to an address; a name the profile's own rules block still answers 0.0.0.0; a
URL-filter name still answers with the gateway's address; a name only the encrypted-DNS list blocks stays
blocked, because that list is never paused. After the end, the Pro list's name answers 0.0.0.0 again, and
the report built from AdGuard's own query log and its check_host names the two lists' names. The time each
of the pause's two restarts took is written to `pause/timings.json` in the artifacts, an estimate of what
they take on a gateway.

It needs the AdGuard Home binary: CI's virtual job downloads the pinned release and names it in
TVGW_VIRTUAL_ADGUARD. Without it the tests skip, or fail under TVGW_VIRTUAL_REQUIRED=1. The two namespaces
are its own (`tvgwv-<pid>-aghpause` and `tvgwv-<pid>-aghpausetv`), and nothing on the host is written
outside a temporary directory."""

from __future__ import annotations

import contextlib
import json
import os
import shutil
import subprocess
import sys
import tempfile
import time
from pathlib import Path

import pytest
import vnet

from tvgw import adguardcfg, aghinstall, listpause, profile
from tvgw.config import Settings

pytestmark = pytest.mark.virtual

HERE = Path(__file__).resolve().parent
PROBE, AGENT = HERE / "dnsprobe.py", HERE / "agent.py"
GW, TV = "10.10.10.1", "10.10.10.52"
UPSTREAM, UPSTREAM_PORT, ANSWER = "127.0.0.1", 5300, "198.51.100.7"
LG_LIST = "https://adguardteam.github.io/HostlistsRegistry/assets/filter_72.txt"
PRO = "https://adguardteam.github.io/HostlistsRegistry/assets/filter_48.txt"
DOH = "https://cdn.jsdelivr.net/gh/hagezi/dns-blocklists@latest/adblock/doh.txt"
# the lists' files as AdGuard keeps them, by id, each with a name of the test's own; no list's text enters
# the repository
LISTS = {
    LG_LIST: (adguardcfg.FILTER_ID_BASE + 801, "pause-native.example"),
    DOH: (adguardcfg.FILTER_ID_BASE + 802, "pause-doh.example"),
    PRO: (adguardcfg.FILTER_ID_BASE + 803, "pause-pro.example"),
}
PROFILE_BLOCK = "alphonso.tv"  # one of lg-webos.rules' own blocks, which a pause never lifts
URL_FILTER = "ngfts.lge.com"  # answered with the gateway's address by the URL filter's rewrite


class Paused:
    """AdGuard Home in its own namespace on GW, a TV namespace beside it, and a stand-in upstream."""

    def __init__(self, binary: str, artifacts: Path):
        tag = f"{vnet.PREFIX}{os.getpid()}"
        self.agh, self.tv = f"{tag}-aghpause", f"{tag}-aghpausetv"
        self.binary, self.artifacts = binary, artifacts
        self.work = Path(tempfile.mkdtemp(prefix="tvgw-virtual-pause-"))
        (self.work / "state").mkdir()
        self.s = Settings(
            tv_ip=TV,
            gw_ip=GW,
            tv_name="tv",
            dns_upstreams=f"{UPSTREAM}:{UPSTREAM_PORT}",
            dns_bootstrap="192.0.2.53",
            adguard_yaml=str(self.work / "AdGuardHome.yaml"),
            adguard_querylog=str(self.work / "data" / "querylog.json"),
            db_path=str(self.work / "tvgw.db"),
            state_dir=str(self.work / "state"),
            local_rules=str(self.work / "local.rules"),
            auto_rules=str(self.work / "auto.rules"),
        )
        self.prof = profile.load("lg-webos")
        self.proc: subprocess.Popen | None = None
        self.upstream: subprocess.Popen | None = None
        self.logs: list = []
        self.made: list[str] = []
        self.restarts: list[float] = []

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
        folder = self.work / "data" / "filters"
        folder.mkdir(parents=True)
        for list_id, name in LISTS.values():
            (folder / f"{list_id}.txt").write_text(f"! Title: a test list\n||{name}^\n", encoding="utf-8")
        base = {
            "http": {"address": "127.0.0.1:3000"},
            "users": [],
            "dns": {"bind_hosts": [GW], "port": 53},
            "schema_version": adguardcfg.SCHEMA_CEILING,
            "filters": [
                {"enabled": True, "url": url, "name": url, "id": list_id}
                for url, (list_id, _) in LISTS.items()
            ],
        }
        plan = adguardcfg.plan(base, adguardcfg.desired(self.prof, self.s, ()))
        Path(self.s.adguard_yaml).write_text(adguardcfg.dump_yaml(plan), encoding="utf-8")
        log = self.log("upstream")
        argv = [sys.executable, "-I", str(AGENT), "serve", "--bind", UPSTREAM, "--dns", ANSWER]
        self.upstream = subprocess.Popen(
            ["ip", "netns", "exec", self.agh, *argv, "--dns-port", str(UPSTREAM_PORT)],
            stdout=subprocess.PIPE,
            stderr=log,
            text=True,
        )
        assert self.upstream.stdout is not None and self.upstream.stdout.readline().strip() == "ready"

    def log(self, name: str):
        path = self.artifacts / "pause" / f"{name}.log"
        path.parent.mkdir(parents=True, exist_ok=True)
        fh = path.open("a", encoding="utf-8")
        self.logs.append(fh)
        return fh

    # ---- the stand-ins for what touches the gateway, inside the namespace --------------------------------
    def control(self, action: str, unit: str) -> None:
        if action == "stop" and self.proc is not None:
            self.proc.terminate()
            self.proc.wait(timeout=30)
            self.proc = None
        elif action == "start":
            argv = [
                "ip",
                "netns",
                "exec",
                self.agh,
                self.binary,
                "-c",
                self.s.adguard_yaml,
                "-w",
                str(self.work),
            ]
            self.proc = subprocess.Popen(
                [*argv, "--no-check-update"], stdout=self.log("adguard"), stderr=subprocess.STDOUT
            )

    def ready(self) -> bool:
        deadline = time.monotonic() + 45
        while time.monotonic() < deadline:
            if self.proc is None or self.proc.poll() is not None:
                return False
            got = self.ask("ready.example.com")
            if got is not None and got["rcode"] == 0:
                return True
            time.sleep(0.3)
        return False

    def check(self, path: str) -> tuple[bool, str]:
        argv = [self.binary, "--check-config", "-c", path, "-w", str(self.work), "--no-check-update"]
        out = self.ns(self.agh, *argv, check=False, timeout=120)
        return out.returncode == 0, out.stdout + out.stderr

    def apply(self, paused: tuple[str, ...]) -> list[str]:
        """The real apply, as `analyst.adguardcfg_apply` makes it, timed from the stop to an answer."""
        began = time.monotonic()
        done = adguardcfg.apply(
            self.s.adguard_yaml,
            adguardcfg.desired(self.prof, self.s, paused),
            control=self.control,
            ready=self.ready,
            check=self.check,
            guard=lambda: None,  # the stand-in upstream answers; the guard's own probe is unit-tested
        )
        self.restarts.append(round(time.monotonic() - began, 2))
        return done

    def check_host(self, base: str, name: str, client: str, user: str, password: str) -> dict:
        code = (
            "import json, sys, urllib.parse, urllib.request\n"
            "q = urllib.parse.urlencode({'name': sys.argv[1], 'client': sys.argv[2]})\n"
            "url = 'http://127.0.0.1:3000/control/filtering/check_host?' + q\n"
            "with urllib.request.urlopen(url, timeout=20) as r:\n"
            "    print(json.dumps(json.load(r)))\n"
        )
        out = self.ns(self.agh, sys.executable, "-I", "-c", code, name, client, check=False, timeout=60)
        assert out.returncode == 0, out.stderr
        return json.loads(out.stdout)

    def ask(self, name: str) -> dict | None:
        out = self.ns(self.tv, sys.executable, "-I", str(PROBE), GW, "A", name, check=False, timeout=30)
        return json.loads(out.stdout) if out.returncode == 0 and out.stdout.strip() else None

    def addresses(self, name: str) -> list[str] | None:
        got = self.ask(name)
        return got["addresses"] if got is not None and got["rcode"] == 0 else None

    def destroy(self) -> None:
        for proc in (self.proc, self.upstream):
            if proc is not None:
                with contextlib.suppress(OSError):
                    proc.terminate()
                with contextlib.suppress(OSError, subprocess.TimeoutExpired):
                    proc.wait(timeout=10)
                with contextlib.suppress(OSError):
                    proc.kill()
        for fh in self.logs:
            fh.close()
        with contextlib.suppress(OSError):
            shutil.copy(self.s.adguard_yaml, self.artifacts / "pause" / "AdGuardHome.after.yaml")
        for name in reversed(self.made):
            vnet.run(["ip", "netns", "del", name], check=False)
        shutil.rmtree(self.work, ignore_errors=True)


@pytest.fixture(scope="module")
def paused(artifacts):
    binary = os.environ.get("TVGW_VIRTUAL_ADGUARD", "")
    if not (binary and os.access(binary, os.X_OK)):
        why = "TVGW_VIRTUAL_ADGUARD does not name an AdGuard Home binary"
        if os.environ.get("TVGW_VIRTUAL_REQUIRED") == "1":
            pytest.fail(why)
        pytest.skip(why)
    r = Paused(binary, artifacts)
    try:
        r.build()
        r.control("start", "AdGuardHome")
        assert r.ready(), "AdGuard Home did not answer within 45 s; see pause/adguard.log"
        yield r
    finally:
        r.destroy()


def test_a_pause_lifts_the_tracker_lists_alone_and_its_end_puts_them_back(paused):
    names = {url: name for url, (_, name) in LISTS.items()}
    # before: every list in force, the profile's block and the URL filter as always
    for url, name in names.items():
        assert paused.addresses(name) == ["0.0.0.0"], (url, name)
    assert paused.addresses(PROFILE_BLOCK) == ["0.0.0.0"]
    assert paused.addresses(URL_FILTER) == [GW]
    assert paused.addresses("free.example") == [ANSWER]

    done = listpause.start(
        paused.s,
        paused.prof,
        10,
        argv=["tvgw", "pause", "--end", "--timer"],
        apply_fn=paused.apply,
        arm_fn=lambda seconds, argv: None,
        disarm_fn=lambda: None,
    )
    assert done.code == listpause.OK, done.lines
    # during: the two tracker lists' names resolve; everything else holds
    assert paused.addresses(names[PRO]) == [ANSWER]
    assert paused.addresses(names[LG_LIST]) == [ANSWER]
    assert paused.addresses(names[DOH]) == ["0.0.0.0"], "the encrypted-DNS list must never be paused"
    assert paused.addresses(PROFILE_BLOCK) == ["0.0.0.0"]
    assert paused.addresses(URL_FILTER) == [GW]
    for _ in range(12):  # enough for AdGuard to write a batch of the log (querylog.size_memory)
        paused.ask(names[PRO])
        paused.ask(names[LG_LIST])

    ended = listpause.end(
        paused.s, paused.prof, listpause.EARLY, apply_fn=paused.apply, disarm_fn=lambda: None
    )
    assert ended.code == listpause.OK, ended.lines
    assert paused.addresses(names[PRO]) == ["0.0.0.0"]
    assert paused.addresses(names[LG_LIST]) == ["0.0.0.0"]
    assert paused.addresses(PROFILE_BLOCK) == ["0.0.0.0"]
    timings = {"start_restart_s": paused.restarts[0], "end_restart_s": paused.restarts[1]}
    (paused.artifacts / "pause" / "timings.json").write_text(json.dumps(timings, indent=1), encoding="utf-8")
    print(f"pause restarts: {timings}")

    report = listpause.report(
        paused.s,
        paused.prof,
        ended.pause,
        check=paused.check_host,
        page=no_page,
        admin=str(paused.work / "no-admin-file"),
    )
    (paused.artifacts / "pause" / "report.txt").write_text("\n".join(report.lines), encoding="utf-8")
    assert report.code == listpause.NAMED, report.lines
    listed = {line.split(",")[0].strip() for line in report.lines[1:] if line.startswith("  ")}
    assert {names[PRO], names[LG_LIST]} <= listed and names[DOH] not in listed
    assert any(
        line.startswith("If the app worked during the pause, the likely cause is") for line in report.lines
    )


def no_page(*args, **kw) -> dict:
    """The API's page is asked from outside the namespace, where AdGuard cannot be reached: the report
    reads the file alone, as it does whenever the page does not answer."""
    raise aghinstall.AskError("the page is inside the namespace")
