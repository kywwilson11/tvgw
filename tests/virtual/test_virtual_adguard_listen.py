"""(adguard) ADGUARD_LISTEN=gateway beside systemd-resolved: AdGuard Home on GW_IP and 127.0.0.1 while
resolved's stub holds 127.0.0.53 (design decision 52).

AdGuard's own documentation says systemd-resolved "prevents AdGuard Home from binding to 127.0.0.1:53";
ordinary socket rules say two specific addresses do not collide. This settles it on the machine itself,
not in a namespace, because resolved's sockets live in the machine's own network namespace: a dummy
interface `tvgwv-d<n>` gets 10.10.10.1/32, AdGuard starts on the YAML `adguardcfg.plan` writes for
`ADGUARD_LISTEN=gateway`, and it must hold both addresses and answer on both, with the stub still
holding 127.0.0.53. If AdGuard cannot bind 127.0.0.1 here, the plan must own GW_IP alone (the design's
fallback) and this test says so.

It changes the machine's network (an interface, two sockets on port 53), so it runs only with
TVGW_VIRTUAL_HOST_NET=1, which CI's virtual job sets on its throwaway `ubuntu-latest` runner, where
resolved runs. There, under TVGW_VIRTUAL_REQUIRED=1, the holder of 127.0.0.53 must be
systemd-resolved. It needs the binary TVGW_VIRTUAL_ADGUARD names, as the other resolver tests do."""

from __future__ import annotations

import contextlib
import os
import shutil
import subprocess
import tempfile
import time
from pathlib import Path

import dnsprobe
import pytest
import vnet

from tvgw import adguardcfg, aghinstall, profile
from tvgw.config import Settings

pytestmark = pytest.mark.virtual

GW = "10.10.10.1"
SETTINGS = Settings(
    tv_ip="10.10.10.17",
    gw_ip=GW,
    tv_name="tv",
    adguard_listen="gateway",
    dns_upstreams="https://192.0.2.53/dns-query",  # nothing upstream is asked: the probe names are blocked
    dns_bootstrap="192.0.2.53",
)
REQUIRED = os.environ.get("TVGW_VIRTUAL_REQUIRED") == "1"


def holders(port: int = 53) -> str:
    """`ss` for every UDP and TCP socket bound to `port`, with its process."""
    return "".join(
        vnet.run(["ss", flags, f"sport = :{port}"], check=False).stdout for flags in ("-Hlnup", "-Hltnp")
    )


def blocked_name(d: adguardcfg.Desired) -> str:
    import re

    for rule in d.user_rules:
        m = re.fullmatch(r"\|\|([a-z0-9.-]+)\^", rule)
        if m:
            return m.group(1)
    raise AssertionError("the profile has no plain block rule to probe")


def unusable(why: str):
    if REQUIRED:
        pytest.fail(why)
    pytest.skip(why)


@pytest.fixture(scope="module")
def beside_resolved(artifacts):
    if os.environ.get("TVGW_VIRTUAL_HOST_NET") != "1":
        pytest.skip("TVGW_VIRTUAL_HOST_NET=1 is not set: this test changes the machine's own network")
    binary = os.environ.get("TVGW_VIRTUAL_ADGUARD", "")
    if not (binary and os.access(binary, os.X_OK)):
        unusable("TVGW_VIRTUAL_ADGUARD does not name an AdGuard Home binary")
    before = holders()
    if "127.0.0.53" not in before:
        unusable(f"nothing holds 127.0.0.53:53 here, so there is no stub to bind beside: {before!r}")
    if REQUIRED and "systemd-resolve" not in before:
        pytest.fail(f"127.0.0.53:53 is not systemd-resolved's here: {before!r}")
    taken = [line for line in before.splitlines() if "127.0.0.1:53 " in line or f"{GW}:53 " in line]
    if taken:
        unusable(f"port 53 on 127.0.0.1 or {GW} is already held here: {taken}")
    if f" {GW}/" in vnet.run(["ip", "-4", "-o", "addr", "show"]).stdout:  # not 10.10.10.10 and the like
        unusable(f"{GW} is already an address of this machine")

    dummy = f"{vnet.PREFIX}d{os.getpid() % 100000}"
    work = Path(tempfile.mkdtemp(prefix="tvgw-virtual-listen-"))
    log_path = artifacts / "adguard" / "listen-adguard.log"
    log_path.parent.mkdir(parents=True, exist_ok=True)
    proc = None
    log = log_path.open("w", encoding="utf-8")
    d = adguardcfg.desired(profile.load("lg-webos"), SETTINGS)
    try:
        vnet.run(["ip", "link", "add", dummy, "type", "dummy"])
        vnet.run(["ip", "addr", "add", f"{GW}/32", "dev", dummy])
        vnet.run(["ip", "link", "set", dummy, "up"])
        base = {
            "http": {"address": f"127.0.0.1:{aghinstall.free_port()}"},
            "users": [],
            "dns": {"bind_hosts": ["127.0.0.1"], "port": 53},
            "schema_version": adguardcfg.SCHEMA_CEILING,
        }
        yaml_path = work / "AdGuardHome.yaml"
        yaml_path.write_text(adguardcfg.dump_yaml(adguardcfg.plan(base, d)), encoding="utf-8")
        argv = [binary, "-c", str(yaml_path), "-w", str(work), "--no-check-update"]
        proc = subprocess.Popen(argv, stdout=log, stderr=subprocess.STDOUT)
        name = blocked_name(d)
        deadline = time.monotonic() + 45
        while time.monotonic() < deadline:
            if proc.poll() is not None:
                break
            got = dnsprobe.ask(GW, "A", name, timeout=1.0)
            if got is not None and got["addresses"] == ["0.0.0.0"]:
                break
            time.sleep(0.5)
        during = holders()
        (artifacts / "adguard" / "listen-ss.txt").write_text(
            f"before:\n{before}\nduring:\n{during}", encoding="utf-8"
        )
        yield {"proc": proc, "name": name, "during": during, "before": before, "log": log_path}
    finally:
        if proc is not None:
            with contextlib.suppress(OSError):
                proc.terminate()
            with contextlib.suppress(OSError, subprocess.TimeoutExpired):
                proc.wait(timeout=15)
            with contextlib.suppress(OSError):
                proc.kill()
        log.close()
        vnet.run(["ip", "link", "del", dummy], check=False)
        shutil.rmtree(work, ignore_errors=True)


def test_adguard_holds_gw_ip_and_loopback_beside_the_stub(beside_resolved):
    proc, during = beside_resolved["proc"], beside_resolved["during"]
    assert proc.poll() is None, f"AdGuard Home exited {proc.returncode}: see {beside_resolved['log'].name}"
    for address in (f"{GW}:53", "127.0.0.1:53"):
        lines = [line for line in during.splitlines() if f"{address} " in line]
        assert lines and all("AdGuardHome" in line for line in lines), (address, during)
        kinds = {line.split()[0] for line in lines}  # UNCONN for UDP, LISTEN for TCP
        assert kinds == {"UNCONN", "LISTEN"}, (address, during)
    assert "127.0.0.53" in during, "the stub lost its socket"
    assert not [line for line in during.splitlines() if "0.0.0.0:53 " in line or "*:53 " in line], during


def test_it_answers_on_both_addresses(beside_resolved):
    for server in (GW, "127.0.0.1"):
        got = dnsprobe.ask(server, "A", beside_resolved["name"])
        assert got is not None and got["addresses"] == ["0.0.0.0"], (server, got)
