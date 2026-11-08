"""A first install with no setup pass on a new computer, as `sudo ./install.sh` and the package's postinst run
it: the TV not named yet, so the installer brings the TV side up and stops with 75, the exit the postinst
reports, and nothing the TV sends is forwarded. Then `tvgw discover --write` names the TV from the lease it
holds, as the installer's last line says to, and the installer runs again with no pass, to its end in
`exec tvgw verify`.

The TV is the same documentation-MAC TV as in test_container_first_run.py, on a container of its own;
AdGuard Home is installed from the pin first, which the installer needs before it writes anything."""

from __future__ import annotations

import ipaddress
import shlex

import ctr
import pytest
from ctr import GW_IP, TV_IF, TV_MAC, TV_NET

pytestmark = pytest.mark.container

DISPATCHER = "/etc/NetworkManager/dispatcher.d/90-tvgw"
UNKNOWN = "00:00:00:00:00:00"  # the template's placeholder: the TV not identified yet


@pytest.fixture(scope="module")
def gw(gateway) -> ctr.Gateway:
    """The settings of a new computer before the TV is found: the tier's, with the placeholder MAC; the TV
    on its port asking for an address."""
    gateway.keep("settings.conf", gateway.write_settings({"TV_MAC": UNKNOWN}))
    gateway.add_tv()
    return gateway


@pytest.fixture(scope="module")
def outside(gw) -> str:
    return gw.outside_address()


def tail(out, n: int = 40) -> str:
    return "\n".join((out.stdout + out.stderr).strip().splitlines()[-n:])


def absent(gw: ctr.Gateway, path: str) -> bool:
    return gw.sh(f"test -e {shlex.quote(path)}", check=False).returncode != 0


def firewall_loaded(gw: ctr.Gateway) -> bool:
    return gw.sh("nft list table inet tvgw", check=False).returncode == 0


def sysctl(gw: ctr.Gateway, key: str) -> str:
    return gw.read("/proc/sys/" + key.replace(".", "/")).strip()


def setting(gw: ctr.Gateway, key: str) -> str:
    out = gw.sh(f"sed -n 's/^{key}=\\([^ #]*\\).*/\\1/p' /etc/tvgw/tvgw.conf | tail -n 1")
    return out.stdout.strip()


def test_adguard_home_is_installed_from_the_pin(gw):
    out = gw.sh("tvgw adguard install", check=False, timeout=600)
    gw.keep("adguard-install.txt", out.stdout + out.stderr)
    assert out.returncode == 0, tail(out)


def test_with_no_pass_and_no_tv_named_the_installer_stops_at_75_and_forwards_nothing(gw, outside):
    """The postinst's run on a new computer: the TV side comes up and serves DHCP from the pool, and the
    NetworkManager dispatcher, which would run tvgw-apply as tv-lan comes up, is not installed yet."""
    out = gw.installer(None)
    assert out.returncode == 75, tail(out)
    assert "TV not identified and no terminal to ask on" in out.stderr
    assert gw.sh("nmcli -g GENERAL.STATE con show tv-lan").stdout.strip() == "activated"
    lease = gw.lease()
    assert ipaddress.ip_address(lease["ip"]) in ipaddress.ip_network(TV_NET), lease
    assert (lease["router"], lease["dns"]) == (GW_IP, GW_IP), lease
    assert absent(gw, DISPATCHER), "the dispatcher is installed before the TV is known"
    assert not firewall_loaded(gw)
    assert sysctl(gw, "net.ipv4.ip_forward") == "0" and sysctl(gw, f"net.ipv4.conf.{TV_IF}.forwarding") == "0"
    opened, said = gw.tv_connects(outside)
    assert not opened, said


def test_discover_names_the_tv_from_the_lease_it_holds(gw):
    """`tvgw discover --write`, as the installer's 75 says to run: one device on the TV's port, so it is
    taken (--yes says so for an unattended run), and SSDP is not asked, since this TV answers none."""
    lease = gw.lease()
    out = gw.sh("tvgw discover --write --yes --no-ssdp </dev/null", check=False, timeout=300)
    gw.keep("discover.txt", out.stdout + out.stderr)
    assert out.returncode == 0, tail(out)
    assert (setting(gw, "TV_MAC").lower(), setting(gw, "TV_IP")) == (TV_MAC, lease["ip"])


def test_the_installer_again_with_no_pass_runs_to_its_end_and_verify_exits_0(gw, outside):
    """The full install with the TV known: the dispatcher installed, the firewall loaded, and `exec tvgw
    verify` as its last step, whose 1 while the lists load is waited out as setup would wait it out."""
    out = gw.installer(None)
    assert "tvgw: installed (tvgw " in out.stdout, tail(out)
    assert out.returncode in (0, 1), tail(out)  # 1 is verify's own verdict here, settled below
    assert not absent(gw, DISPATCHER) and firewall_loaded(gw)
    verdict = ctr.settle(gw.verify, gw.settling(), timeout=900)
    gw.keep("verify-settled.json", "\n".join(f"{c.get('name')} {c.get('ok')}" for c in verdict.checks))
    assert verdict.rc == 0, verdict.summary()
    assert gw.lease()["ip"] == setting(gw, "TV_IP")
    opened, said = gw.tv_connects(outside)
    assert opened, said
