"""(uplink) The NetworkManager dispatcher's words on the uplink's address and router: `addr=` and `gw=`
(changed, same or new) on the spool line of the uplink's `up` and `dhcp4-change`, the addresses kept in
/run/tvgw/wan.last and never in the spool, and the ledger rows the words become.

The dispatcher is a POSIX script NetworkManager runs with `sh`: it runs here under dash where the machine
has it, else under sh, with NetworkManager's own variables (IP4_ADDRESS_0 as "address/prefix gateway",
IP4_GATEWAY) set as it sets them."""

import os
import shutil
import stat
import subprocess
from pathlib import Path

import pytest
from conftest import ROOT
from ledger_store import Synth

from tvgw import ingest, ledger, plain
from tvgw.config import Settings

SHELL = shutil.which("dash") or shutil.which("sh")
pytestmark = pytest.mark.skipif(SHELL is None, reason="the dispatcher is a POSIX script")
ADDR, NEW_ADDR = "192.0.2.48", "192.0.2.53"
ROUTER, NEW_ROUTER = "192.0.2.1", "192.0.2.254"


class Dispatcher:
    """The shipped dispatcher with its paths moved under tmp_path and the apply replaced by a stub."""

    def __init__(self, tmp_path: Path):
        self.tmp = tmp_path
        text = (ROOT / "deploy" / "networkmanager" / "90-tvgw-dispatcher").read_text(encoding="utf-8")
        (tmp_path / "tvgw.conf").write_text("TV_IF=enp1s0\nWAN_IF=wlan1\n", encoding="utf-8")
        apply = tmp_path / "apply"
        apply.write_text(f"#!/bin/sh\necho applied >>{tmp_path}/applied\n", encoding="utf-8")
        apply.chmod(0o755)
        self.run_dir = tmp_path / "rundir" / "tvgw"
        self.spool = tmp_path / "changes.spool"
        script = (
            text.replace("/etc/tvgw/tvgw.conf", str(tmp_path / "tvgw.conf"))
            .replace("/usr/local/sbin/tvgw-apply", str(apply))
            .replace("/var/lib/tvgw/changes.spool", str(self.spool))
            .replace("/run/tvgw", str(self.run_dir))
        )
        assert "/run/tvgw" not in script
        self.path = tmp_path / "dispatcher"
        self.path.write_text(script, encoding="utf-8")
        (tmp_path / "rundir").mkdir()

    def __call__(self, iface: str, action: str, addr: str | None = None, gw: str | None = None) -> None:
        env = {"PATH": os.environ["PATH"]}
        if addr is not None:
            env["IP4_ADDRESS_0"] = f"{addr}/24 {gw or ''}".rstrip()
        if gw is not None:
            env["IP4_GATEWAY"] = gw
        out = subprocess.run(
            [SHELL, str(self.path), iface, action], capture_output=True, text=True, encoding="utf-8", env=env
        )
        assert out.returncode == 0 and out.stderr == "", out.stderr

    def rows(self) -> list[list[str]]:
        return [line.split("\t")[1:] for line in self.spool.read_text(encoding="utf-8").splitlines()]


def test_the_uplinks_events_say_whether_its_address_and_router_moved_and_never_which(tmp_path):
    d = Dispatcher(tmp_path)
    d("wlan1", "up", ADDR, ROUTER)  # the first since boot: nothing to compare with
    d("wlan1", "dhcp4-change", ADDR, ROUTER)  # a renewal
    d("wlan1", "dhcp4-change", NEW_ADDR, ROUTER)  # 2026-11-02, 19:46: the router moved the address
    d("wlan1", "dhcp4-change", NEW_ADDR, NEW_ROUTER)  # a new router on the same lease
    d("wlan1", "down")
    d("enp1s0", "up", "10.10.10.1", None)  # the TV port: never compared
    assert d.rows() == [
        ["dispatcher", "wlan1", "up", "addr=new", "gw=new"],
        ["dispatcher", "wlan1", "dhcp4-change", "addr=same", "gw=same"],
        ["dispatcher", "wlan1", "dhcp4-change", "addr=changed", "gw=same"],
        ["dispatcher", "wlan1", "dhcp4-change", "addr=same", "gw=changed"],
        ["dispatcher", "wlan1", "down"],
        ["dispatcher", "enp1s0", "up"],
    ]
    spool = d.spool.read_text(encoding="utf-8")
    assert not any(a in spool for a in (ADDR, NEW_ADDR, ROUTER, NEW_ROUTER))
    last = d.run_dir / "wan.last"
    assert last.read_text(encoding="utf-8") == f"{NEW_ADDR}/24 {NEW_ROUTER}\n"
    assert stat.S_IMODE(last.stat().st_mode) == 0o600
    assert stat.S_IMODE(d.run_dir.stat().st_mode) == 0o755  # the dispatcher made it as tvgw-apply would
    assert (tmp_path / "applied").read_text(encoding="utf-8").count("applied") == 5  # every up and DHCP


def test_an_event_without_an_address_compares_nothing_and_still_applies(tmp_path):
    d = Dispatcher(tmp_path)
    d("wlan1", "up")
    assert d.rows() == [["dispatcher", "wlan1", "up"]]
    assert not (d.run_dir / "wan.last").exists()
    assert (tmp_path / "applied").exists()


def test_a_router_without_a_gateway_reads_as_its_own_value(tmp_path):
    d = Dispatcher(tmp_path)
    d("wlan1", "up", ADDR, None)
    d("wlan1", "dhcp4-change", ADDR, ROUTER)
    assert d.rows()[1] == ["dispatcher", "wlan1", "dhcp4-change", "addr=same", "gw=changed"]


# ---- the ledger rows -----------------------------------------------------------------------------------------
S = Settings(tv_if="enp1s0", wan_if="wlan1")


@pytest.mark.parametrize(
    ("words", "kind", "detail"),
    [
        (["addr=changed", "gw=same"], "wan_addr_change", {"addr": "changed", "gw": "same", "router": "same"}),
        (["addr=changed", "gw=changed"], "wan_addr_change", {"addr": "changed", "gw": "changed", "router": "changed"}),
        (["addr=same", "gw=changed"], "wan_gw_change", {"addr": "same", "gw": "changed"}),
        (["addr=same", "gw=same"], "dhcp_change", {"addr": "same", "gw": "same"}),
        (["addr=new", "gw=new"], "dhcp_change", {"addr": "new", "gw": "new"}),
        ([], "dhcp_change", {}),  # a line from a dispatcher before the words
        (["addr=192.0.2.1", "junk"], "dhcp_change", {}),  # nothing but the three words is read
    ],
)  # fmt: skip
def test_spool_row_maps_the_words_of_a_dhcp_line(words, kind, detail):
    row = ledger._spool_row(["1793020000", "dispatcher", "wlan1", "dhcp4-change", *words], S, None)
    assert (row.kind, row.subject, row.source, row.t_precision) == (kind, "wlan1", "dispatcher", 1.0)
    assert row.detail == {"action": "dhcp4-change", **detail}
    assert ledger.KINDS[kind][0] == ("A" if kind.startswith("wan_") else "B")


def test_spool_row_keeps_up_and_the_tv_port_as_before():
    up = ledger._spool_row(["1", "dispatcher", "wlan1", "up", "addr=changed", "gw=same"], S, None)
    assert up.kind == "wan_link_up" and up.detail == {"action": "up", "addr": "changed", "gw": "same"}
    tv = ledger._spool_row(["1", "dispatcher", "enp1s0", "dhcp4-change", "addr=changed"], S, None)
    assert tv.kind == "dhcp_change"


# ---- the 2026-11-02 evening, with the dispatcher's words ---------------------------------------------------------
def at(hms: str) -> float:
    from datetime import datetime

    h, m, sec = (int(x) for x in hms.split(":"))
    return datetime(2026, 11, 2, h, m, sec).timestamp()


SALT = b"k" * 32


def test_the_dispatchers_row_is_the_cause_and_the_samplers_twin_is_not_written(tmp_path, lg):
    """The DHCP line at 19:46:31 now carries addr=changed: the change has the dispatcher's own time, the
    sampler's tag-derived row of the same change (seen at 19:52:10) is its explained twin and is not
    written, the five cut connections are put down to it, and the plain brief says so."""
    s = Settings(state_dir=str(tmp_path), db_path=str(tmp_path / "s.db"))
    synth = Synth(s.db_path)
    try:
        lines = [
            f"{at('19:46:31')}\tdispatcher\twlan0\tdhcp4-change\taddr=changed\tgw=same",
            f"{at('19:46:36')}\tapply\tnm-dispatcher\tchanged",
        ]
        Path(ledger.spool_path(s)).write_text("".join(line + "\n" for line in lines), encoding="utf-8")
        ledger.load_spool(synth.conn, s, ingest._tail, lambda w: None)
        for t, addr in (("19:32:10", "192.0.2.48"), ("19:42:10", "192.0.2.48"), ("19:52:10", "192.0.2.53")):
            synth.sample(at(t), wan_addr_tag=ledger.wan_addr_tag(SALT, addr, ROUTER))
        ledger.derive_all(synth.conn, s)
        for i in range(5):
            synth.conn.execute(
                "INSERT INTO flows(t_start, t_end, proto, dst, dport, sport, bytes_down, state, timeout_left)"
                " VALUES (?, ?, 'tcp', '203.0.113.9', 443, ?, 1000, 'ESTABLISHED', 431000)",
                (at("19:30:00"), at("19:46:36"), 41000 + i),
            )
        synth.conn.commit()
        rows = synth.conn.execute("SELECT source, t FROM changes WHERE kind = 'wan_addr_change'").fetchall()
        assert rows == [("dispatcher", at("19:46:31"))]
        sec = ledger.section(synth.conn, lg, at("19:40:00"), at("20:10:00"), at("21:00:00"))
        assert sec["evidence"]["by_cause"] == {"uplink address changed": 5}
        assert sec["evidence"]["cut_first"]["uplink address changed"] == at("19:46:36")
        tier, text = plain.action({"changes_in_effect": sec}, lg)
        assert tier == "act" and text.endswith("reserve this computer's address in your router's settings.")
    finally:
        synth.close()
