"""(reliability) VPN_DNS_SEAL: the gateway's own plain lookups held off the uplink while the VPN's tunnel
is down, for a bounded time (design decision 73). The table it writes, which never names the TV, its
lookups' DoH or a held port but 53; each action with the setting off, on, and with no VPN; the users who
are never held; the dispatcher's two calls; and the unit that holds before the VPN client stops."""

import os
import pwd
import re
import subprocess

import pytest
from conftest import ROOT, exec_lines

from tvgw import cli, config, seal
from tvgw.config import Settings

ON = Settings(vpn_dns_seal="on", wan_if="wlan0", vpn_if="auto")


def fake_pw(table: dict[str, int]):
    def getpwnam(name):
        if name not in table:
            raise KeyError(name)
        return pwd.struct_passwd((name, "x", table[name], table[name], "", "/", "/bin/false"))

    return getpwnam


def only(cmds):
    (cmd,) = cmds
    return cmd


def test_the_setting_is_off_by_default_and_refused_when_misspelt(tmp_path):
    assert Settings().vpn_dns_seal == "off"
    conf = tmp_path / "tvgw.conf"
    conf.write_text("VPN_DNS_SEAL=On\n", encoding="utf-8")
    with pytest.raises(ValueError, match="VPN_DNS_SEAL='On'"):
        config.load(conf)
    conf.write_text("VPN_DNS_SEAL=on\n", encoding="utf-8")
    assert config.load(conf).vpn_dns_seal == "on"


@pytest.mark.parametrize("s", [Settings(), Settings(vpn_dns_seal="on", vpn_if="none")])
@pytest.mark.parametrize("action", seal.ACTIONS)
def test_off_or_without_a_vpn_every_action_removes_the_table_and_nothing_else(s, action):
    argv, stdin, required = only(seal.plan(s, action, lambda dev: True, [33]))
    assert argv == ["nft", "delete", "table", "inet", "tvgw_seal"] and stdin is None
    assert required is False  # a table that is not there is no failure


def test_the_hold_is_one_transaction_that_refuses_only_port_53_on_the_uplink_for_a_bounded_time():
    argv, text, required = only(seal.plan(ON, "hold", lambda dev: False, [33, 997]))
    assert argv == ["nft", "-f", "-"] and required
    rule = next(line for line in text.splitlines() if line.startswith("add rule"))
    assert rule == (
        'add rule inet tvgw_seal output oifname "wlan0" meta skuid != { 33, 997 } meta l4proto { tcp, udp }'
        ' th dport @held counter reject comment "seal: the gateway\'s own plain lookups while the tunnel is down"'
    )
    assert "hook output" in text  # the gateway's own packets: the TV's forwarded ones never pass here
    assert text.endswith(
        "flush set inet tvgw_seal held\nadd element inet tvgw_seal held { 53 timeout 300s }\n"
    )
    # never the TV's lookups, their DoH, or anything but plain DNS
    for never in ("eth0", "10.10.10", "443", "delete table", "forward", "prerouting"):
        assert never not in text, never
    assert re.findall(r"\{ (\d+) timeout", text) == ["53"]


def test_the_table_is_loaded_without_ending_a_hold_that_runs():
    """`add` keeps an existing set and its elements; the chain's one rule is replaced whole. A sync or a
    release therefore never deletes the table, and only a release or a tunnel that is up flushes."""
    text = seal.ruleset("wlan0", [])
    assert text.startswith(
        "add table inet tvgw_seal\nadd set inet tvgw_seal held { type inet_service; flags timeout; }"
    )
    assert "flush chain inet tvgw_seal output\n" in text and "meta skuid" not in text
    down = only(seal.plan(ON, "sync", lambda dev: False, []))[1]
    assert "flush set" not in down and "add element" not in down
    up = only(seal.plan(ON, "sync", lambda dev: dev == "tun0", []))[1]
    assert up.endswith("flush set inet tvgw_seal held\n")
    released = only(seal.plan(ON, "release", lambda dev: False, []))[1]
    assert released.endswith("flush set inet tvgw_seal held\n") and "add element" not in released


def test_a_named_tunnel_counts_as_up_only_when_it_exists():
    named = Settings(vpn_dns_seal="on", vpn_if="wg0")
    assert seal.tunnel_up(named, lambda dev: dev == "wg0")
    assert not seal.tunnel_up(named, lambda dev: False)
    assert seal.tunnel_up(ON, lambda dev: dev == "wgpia0")


def test_nginx_and_the_clock_are_never_held_and_a_missing_user_is_left_out():
    assert seal.exempt_uids(fake_pw({"www-data": 33, "systemd-timesync": 997})) == [33, 997]
    assert seal.exempt_uids(fake_pw({"www-data": 33})) == [33]
    assert seal.exempt_uids(fake_pw({})) == []
    assert seal.EXEMPT_USERS == ("www-data", "systemd-timesync")


def test_an_unknown_action_is_refused():
    with pytest.raises(ValueError):
        seal.plan(ON, "open", lambda dev: True, [])


def test_main_runs_the_plan_and_says_why_when_nft_refuses(capsys):
    calls = []

    def run(argv, stdin):
        calls.append((argv, stdin))
        return (1, "Error: Could not process rule") if argv[1] == "-f" else (1, "No such file")

    assert seal.main(ON, "hold", run=run, exists=lambda d: False, uids=[]) == 1
    assert "tvgw seal hold: nft refused the table: Error: Could not process rule" in capsys.readouterr().err
    assert (
        seal.main(Settings(), "hold", run=run, exists=lambda d: False, uids=[]) == 0
    )  # off: nothing to fail
    assert [c[0][:2] for c in calls] == [["nft", "-f"], ["nft", "delete"]]


def test_the_command_runs_the_module(tmp_path, monkeypatch):
    seen = []
    monkeypatch.setattr(seal, "main", lambda s, action: seen.append((s.vpn_dns_seal, action)) or 0)
    conf = tmp_path / "tvgw.conf"
    conf.write_text("VPN_DNS_SEAL=on\n", encoding="utf-8")
    assert cli.main(["--conf", str(conf), "seal", "release"]) == 0
    assert seen == [("on", "release")]


# ---- the dispatcher and the unit ------------------------------------------------------------------------
def dispatch(tmp_path, conf: str, iface: str, action: str) -> list[str]:
    """Run the dispatcher for one event; the commands it ran, in order."""
    text = (ROOT / "deploy" / "networkmanager" / "90-tvgw-dispatcher").read_text(encoding="utf-8")
    (tmp_path / "tvgw.conf").write_text(conf, encoding="utf-8")
    log = tmp_path / "log"
    for name in ("tvgw", "tvgw-apply"):
        stub = tmp_path / name
        stub.write_text(f'#!/bin/sh\necho "{name} $*" >>"{log}"\n', encoding="utf-8")
        stub.chmod(0o755)
    script = (
        text.replace("/etc/tvgw/tvgw.conf", str(tmp_path / "tvgw.conf"))
        .replace("/usr/local/sbin/tvgw-apply", str(tmp_path / "tvgw-apply"))
        .replace("/usr/local/bin/tvgw", str(tmp_path / "tvgw"))
    )
    (tmp_path / "dispatcher").write_text(script, encoding="utf-8")
    out = subprocess.run(
        ["sh", str(tmp_path / "dispatcher"), iface, action],
        capture_output=True,
        text=True,
        encoding="utf-8",
        env={"PATH": os.environ["PATH"]},
    )
    assert out.returncode == 0, out.stderr
    calls = log.read_text(encoding="utf-8").splitlines() if log.exists() else []
    log.unlink(missing_ok=True)
    return calls


@pytest.mark.parametrize(
    ("conf", "iface", "action", "calls"),
    [
        ("VPN_DNS_SEAL=on\n", "wlan0", "up", ["tvgw seal hold", "tvgw-apply "]),
        ("VPN_DNS_SEAL=on\n", "tun0", "up", ["tvgw seal release", "tvgw-apply "]),
        ("VPN_DNS_SEAL=on\nVPN_IF=wg0\n", "wg0", "up", ["tvgw seal release", "tvgw-apply "]),
        ("VPN_DNS_SEAL=on\n", "wlan0", "dhcp4-change", ["tvgw-apply "]),  # a renewal: the tunnel stands
        ("VPN_DNS_SEAL=on\n", "eth0", "up", ["tvgw-apply "]),
        ("VPN_DNS_SEAL=on\n", "tun0", "down", []),
        ("", "wlan0", "up", ["tvgw-apply "]),  # off, the default: the dispatcher as it was
        ("", "tun0", "up", ["tvgw-apply "]),
    ],
)
def test_the_dispatcher_holds_at_the_uplinks_start_and_releases_when_the_tunnel_is_up(
    tmp_path, conf, iface, action, calls
):
    assert dispatch(tmp_path, conf, iface, action) == calls


def test_a_seal_that_fails_never_stops_the_apply(tmp_path):
    text = (ROOT / "deploy" / "networkmanager" / "90-tvgw-dispatcher").read_text(encoding="utf-8")
    assert text.count("/usr/local/bin/tvgw seal") == 2
    assert all("|| true" in line for line in text.splitlines() if "/usr/local/bin/tvgw seal" in line)


def test_the_unit_holds_before_the_vpn_client_stops_and_never_fails_for_it():
    text = (ROOT / "deploy" / "systemd" / "tvgw-vpnseal.service").read_text(encoding="utf-8")
    unit = dict(line.split("=", 1) for line in text.splitlines() if "=" in line and not line.startswith("#"))
    assert unit["After"] == "piavpn.service" and unit["PartOf"] == "piavpn.service"
    assert unit["WantedBy"] == "multi-user.target piavpn.service"
    assert unit["Type"] == "oneshot" and unit["RemainAfterExit"] == "yes"
    assert exec_lines("tvgw-vpnseal.service") == [
        ("ExecStart", "-/usr/local/bin/tvgw seal sync"),
        ("ExecStop", "-/usr/local/bin/tvgw seal hold"),
    ]
    assert unit["CapabilityBoundingSet"] == "CAP_NET_ADMIN" and unit["ProtectSystem"] == "strict"


def test_install_enables_and_restarts_the_unit_and_never_stops_for_it():
    text = (ROOT / "deploy" / "install.sh").read_text(encoding="utf-8")
    assert "systemctl -q enable tvgw-vpnseal.service 2>/dev/null || true" in text
    assert re.search(r"systemctl restart tvgw-vpnseal\.service \|\|\n\techo ", text)
