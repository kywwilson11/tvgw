"""A first install on a new computer, stage by stage, in the order setup takes it (design 4.4 and 4.5).

The computer has the package's dependencies and tvgw's source, no AdGuard Home, no firewall and no
forwarding; its settings file is the template with the TV named by a documentation MAC, an LG TV
(`PROFILE=lg-webos`, so the URL filter and nginx are in the install too) and no VPN client. AdGuard Home
is installed and seeded first, then install.sh's bringup pass, the TV's lease, the apply pass, verify, a
deploy over the installed gateway the way `make deploy` deploys, and last a boot with the TV port
unplugged. Each test is one stage and needs the ones before it (conftest.py skips the rest after a
failure)."""

from __future__ import annotations

import json
import shlex

import ctr
import pytest
from ctr import GW_IP, TV_IF, TV_IP, TV_MAC, Listener

pytestmark = pytest.mark.container

AGH_YAML = "/opt/AdGuardHome/AdGuardHome.yaml"
ADMIN = "/etc/tvgw/adguard-admin"
MARKER = "/var/lib/tvgw/.adguard-installed-by-tvgw"
DISPATCHER = "/etc/NetworkManager/dispatcher.d/90-tvgw"
GFTS = "/etc/nginx/conf.d/tvgw-gfts.conf"
STATE = (
    "import sys; from tvgw import aghinstall, config, profile; s = config.load();"
    " print(aghinstall.state(s.adguard_yaml, sys.argv[1], profile.load(s.profile), s))"
)
# What the TV is expected to reach through the gateway once it is applied needs table 100 to carry the TV
# subnet. tvgw-apply decides that, so the mark reads it: without the route the test must fail (strict), and
# once tvgw-apply has it the condition is false and the test runs as any other
needs_reply_route = pytest.mark.xfail(
    not ctr.reply_route_in_apply(ctr.APPLY.read_text(encoding="utf-8")),
    strict=True,
    raises=AssertionError,  # only the assertions: a harness that broke on the way is a failure of its own
    reason="tvgw-apply leaves the TV subnet out of table 100 (design decision 49): rule 60 sends the "
    "gateway's replies to the TV out by the uplink, and the TV's ARP for the gateway fails the TV port's "
    "strict reverse-path check once the firewall is applied",
)


@pytest.fixture(scope="module")
def gw(gateway) -> ctr.Gateway:
    """The gateway of this scenario: the settings file, the TV on its port asking for an address, and the
    listener sampler running from before anything of AdGuard Home exists."""
    gateway.keep("settings.conf", gateway.write_settings())
    gateway.watch_listeners()
    gateway.add_tv()
    return gateway


@pytest.fixture(scope="module")
def outside(gw) -> str:
    return gw.outside_address()


def tail(out, n: int = 40) -> str:
    return "\n".join((out.stdout + out.stderr).strip().splitlines()[-n:])


def sha256(gw: ctr.Gateway, path: str) -> str:
    return gw.sh(f"sha256sum {shlex.quote(path)}").stdout.split()[0]


def absent(gw: ctr.Gateway, path: str) -> bool:
    return gw.sh(f"test -e {shlex.quote(path)}", check=False).returncode != 0


def firewall_loaded(gw: ctr.Gateway) -> bool:
    return gw.sh("nft list table inet tvgw", check=False).returncode == 0


def sysctl(gw: ctr.Gateway, key: str) -> str:
    return gw.read("/proc/sys/" + key.replace(".", "/")).strip()


def profile_value(gw: ctr.Gateway, expr: str) -> str:
    """`expr` evaluated in the gateway's tvgw with `p` the profile its settings name and `verify` imported."""
    code = f"from tvgw import config, profile, verify; p = profile.load(config.load().profile); print({expr})"
    return gw.py(code).stdout.strip()


def test_the_computer_starts_without_adguard_a_firewall_or_forwarding(gw):
    assert gw.py(STATE, MARKER).stdout.strip() == "absent"
    assert not firewall_loaded(gw)
    assert sysctl(gw, "net.ipv4.ip_forward") == "0"
    # dnsmasq is running, as apt left it, and answers nothing until install.sh renders its file
    assert gw.sh("systemctl is-active dnsmasq.service", check=False).stdout.strip() == "active"
    assert not [x for x in gw.listeners() if x.port in (53, 67)]


def test_adguard_home_is_installed_from_the_pin_and_seeded_without_its_wizard(gw):
    """`tvgw adguard install` is aghinstall.install(): the pinned release checked by its hash, the wizard
    answered on loopback, exactly one user, the service registered by AdGuard's own installer, the marker
    last (design decision 52)."""
    out = gw.sh("tvgw adguard install", check=False, timeout=600)
    gw.keep("adguard-install.txt", out.stdout + out.stderr)
    assert out.returncode == 0, tail(out)
    version = gw.py("from tvgw import aghinstall; print(aghinstall.PIN['version'])").stdout.strip()
    assert f"installed AdGuard Home v{version}" in out.stdout and "pinned SHA-256" in out.stdout
    assert gw.py(STATE, MARKER).stdout.strip() == "tvgw"
    assert gw.read(MARKER).strip() == version
    assert gw.sh(f"stat -c '%a %U %G' {ADMIN}").stdout.split() == ["600", "root", "root"]
    seeded = json.loads(
        gw.py(
            "import json, yaml; d = yaml.safe_load(open('/opt/AdGuardHome/AdGuardHome.yaml'));"
            " print(json.dumps({'users': [u.get('name') for u in d.get('users') or []],"
            " 'http': (d.get('http') or {}).get('address')}))"
        ).stdout
    )
    assert seeded == {"users": ["admin"], "http": "127.0.0.1:3000"}
    unit = gw.sh("systemctl is-enabled AdGuardHome.service; systemctl is-active AdGuardHome.service")
    assert unit.stdout.split() == ["enabled", "active"]
    assert "--no-check-update" in gw.sh("systemctl show -p ExecStart --value AdGuardHome.service").stdout
    listening = gw.listeners()
    assert {Listener("tcp", "127.0.0.1", 3000), Listener("udp", "127.0.0.1", 53)} <= listening
    # an answer of any kind: before the apply AdGuard asks its wizard's default upstream, and when it cannot
    # reach that one it still answers, with SERVFAIL, once it gives up on it
    assert gw.resolve(ctr.OUTSIDE, "127.0.0.1", timeout=30) is not None, "AdGuard Home does not answer"
    # a second run finds tvgw's AdGuard and leaves it as it is
    again = gw.sh("tvgw adguard install", check=False)
    assert again.returncode == 0 and "already set up for tvgw; nothing to do" in again.stdout, tail(again)


def test_the_bringup_pass_brings_the_tv_side_up_and_stops_there(gw):
    """Design 4.5: the TV port's profile, the guard and DHCP, and none of the apply pass: no AdGuard
    configuration, no URL filter, no firewall, no units, and no NetworkManager dispatcher, whose re-apply
    when the TV port comes up would switch forwarding on before setup has waited for the lists."""
    before = sha256(gw, AGH_YAML)
    out = gw.installer("bringup")
    assert out.returncode == 0, tail(out)
    assert out.stdout.splitlines()[-1] == f"tvgw: TV side up on {TV_IF} ({GW_IP})"
    tv_lan = gw.sh("nmcli -g connection.interface-name,ipv4.addresses con show tv-lan").stdout.split()
    assert tv_lan == [TV_IF, f"{GW_IP}/24"]
    assert gw.sh("nmcli -g GENERAL.STATE con show tv-lan").stdout.strip() == "activated"
    # NetworkManager's own DHCP profile for the port stood aside (stand_aside), and stays aside
    others = [n for n in gw.sh("nmcli -g NAME con show").stdout.splitlines() if n and n != "tv-lan"]
    bound = {
        n: gw.sh(
            f"nmcli -g connection.interface-name,connection.autoconnect con show {shlex.quote(n)}"
        ).stdout.split()
        for n in others
    }
    on_port = {n: v[-1] for n, v in bound.items() if v and v[0] == TV_IF}
    assert on_port and set(on_port.values()) == {"no"}, bound
    assert any(x.proto == "udp" and x.port == 67 for x in gw.listeners()), "dnsmasq serves no DHCP"
    assert sha256(gw, AGH_YAML) == before, "the bringup pass changed AdGuard Home's configuration"
    assert absent(gw, GFTS) and absent(gw, DISPATCHER)
    assert gw.sh("systemctl is-enabled tvgw.service", check=False).stdout.strip() != "enabled"
    assert not firewall_loaded(gw)


def test_the_tv_gets_its_pinned_address_with_the_gateway_as_router_and_resolver(gw):
    lease = gw.lease()
    assert (lease["ip"], lease["router"], lease["dns"]) == (TV_IP, GW_IP, GW_IP), lease
    assert f" {TV_MAC} {TV_IP} tv " in gw.read("/var/lib/misc/dnsmasq.leases")


def test_the_tv_has_no_route_out_before_the_apply_pass(gw, outside):
    """The TV is on its network and has its lease, and nothing it sends is forwarded: the kernel itself has
    no route for it, and a connection to the outside opens nowhere."""
    assert sysctl(gw, "net.ipv4.ip_forward") == "0"
    assert sysctl(gw, f"net.ipv4.conf.{TV_IF}.forwarding") == "0"
    assert not firewall_loaded(gw)
    route = gw.sh(f"ip route get {outside} from {TV_IP} iif {TV_IF}", check=False)
    assert route.returncode != 0, route.stdout
    opened, said = gw.tv_connects(outside)
    assert not opened, said


def test_the_apply_pass_installs_everything_and_ends_as_the_postinst_does(gw):
    """0 when verify passed at its end, 76 when a check was still failing (AdGuard Home loading its lists):
    setup waits the second out (the next stage)."""
    out = gw.installer("apply")
    assert out.returncode in (0, 76), tail(out)
    assert "tvgw: installed (tvgw " in out.stdout
    assert firewall_loaded(gw) and sysctl(gw, f"net.ipv4.conf.{TV_IF}.forwarding") == "1"
    assert gw.sh("systemctl is-enabled tvgw.service").stdout.strip() == "enabled"
    assert not absent(gw, GFTS) and not absent(gw, DISPATCHER)
    listening = gw.listeners()
    assert {Listener("tcp", GW_IP, 80), Listener("tcp", GW_IP, 443)} <= listening, "nginx is not on GW_IP"


def test_tvgw_verify_exits_0_once_the_lists_are_in(gw):
    """setup's settle-then-verify: the checks verify.SETTLING names are waited on, any other is not."""
    verdict = ctr.settle(gw.verify, gw.settling(), timeout=900)
    gw.keep("verify-settled.json", json.dumps(verdict.checks, indent=1))
    assert verdict.rc == 0, verdict.summary()


def test_adguard_answers_at_the_gateway_and_on_loopback_and_never_on_a_wildcard(gw):
    """ADGUARD_LISTEN=gateway: DNS on GW_IP and 127.0.0.1 only, the page on 127.0.0.1:3000 only, and the
    sampler, which has watched since before AdGuard Home existed, never saw 53, 3000 or the wizard's port
    range on a wildcard address. `tvgw adguard diff` has nothing to do, and the YAML alone says tvgw's."""
    listening = gw.listeners()
    for proto in ("udp", "tcp"):
        assert {Listener(proto, GW_IP, 53), Listener(proto, "127.0.0.1", 53)} <= listening, proto
    assert Listener("tcp", "127.0.0.1", 3000) in listening
    start, stop = gw.py(
        "from tvgw import aghinstall; print(aghinstall.FIRSTRUN_PORTS.start, aghinstall.FIRSTRUN_PORTS.stop)"
    ).stdout.split()
    assert ctr.exposed(listening, [53, 3000, *range(int(start), int(stop))]) == []
    host = profile_value(gw, "sorted(p.must_allow)[0]")
    for server in (GW_IP, "127.0.0.1"):
        got = gw.resolve(host, server)
        assert got and got != ["0.0.0.0"], (host, server, got)
    diff = gw.sh("tvgw adguard diff", check=False)
    assert diff.returncode == 0 and "matches" in diff.stdout, tail(diff)
    # a gateway set up by hand has no marker: its YAML is what makes it tvgw's (design 4.13)
    assert gw.py(STATE, "/nonexistent/marker").stdout.strip() == "tvgw"


@needs_reply_route
def test_the_tv_reaches_the_internet_and_the_filter_after_the_apply_pass(gw, outside):
    opened, said = gw.tv_connects(outside)
    assert opened, said
    host = profile_value(gw, "sorted(p.must_allow)[0]")
    got = gw.resolve(host, GW_IP, in_tv=True)
    assert got and got != ["0.0.0.0"], (host, got)
    sentinel = profile_value(gw, "verify.sentinels(p)[0]")
    assert gw.resolve(sentinel, GW_IP, in_tv=True) == ["0.0.0.0"], sentinel


def test_a_deploy_over_the_installed_gateway_takes_make_deploys_path_and_ends_in_verifys_0(gw):
    """deploy/sync-install.sh from the checkout, as `make deploy` runs it from its staging copy: the copy into
    /opt/tvgw/src under the install lock, install.sh with no pass, and `exec tvgw verify` as its verdict.
    The TV keeps its address."""
    out = gw.sh(f"{ctr.CHECKOUT}/deploy/sync-install.sh </dev/null", check=False, timeout=1800)
    gw.keep("install-sync.txt", f"exit {out.returncode}\n--- stdout\n{out.stdout}--- stderr\n{out.stderr}")
    assert out.returncode == 0, tail(out)
    assert out.stdout.rstrip().splitlines()[-1].startswith("OK "), tail(out)
    assert gw.lease()["ip"] == TV_IP


def test_after_a_boot_with_the_tv_port_unplugged_adguard_answers_at_the_gateway_once_it_is_plugged_in(gw):
    """With ADGUARD_LISTEN=gateway AdGuard Home can listen only once GW_IP exists, so install.sh's drop-in
    restarts it every 5 seconds without a limit (docs/how-it-works/adguard.md, the listen setting). A restart of the
    container is a boot with the TV's adapter unplugged, since the veth does not survive it; plugged in
    again with the MAC it had, AdGuard must answer at GW_IP within 30 seconds."""
    host = profile_value(gw, "sorted(p.must_allow)[0]")
    gw.reboot()
    assert absent(gw, f"/sys/class/net/{TV_IF}")
    assert f" inet {GW_IP}/" not in gw.sh("ip -4 -o addr show").stdout
    gw.add_tv()

    def answers() -> bool:
        got = gw.resolve(host, GW_IP, timeout=2)
        return bool(got) and got != ["0.0.0.0"]

    took = ctr.poll(answers, timeout=30)
    gw.keep("adguard-after-plug.txt", f"{host} at {GW_IP}: {took}\n")
    assert took is not None, gw.sh("journalctl -b -u AdGuardHome --no-pager | tail -n 20", check=False).stdout


def test_after_the_boot_the_tv_has_its_address_again_and_tvgw_verify_exits_0(gw):
    """The gateway holds again with nothing done by hand: dnsmasq answers the TV on the port that came
    back, and verify's settle loop ends in 0."""
    assert gw.lease()["ip"] == TV_IP
    verdict = ctr.settle(gw.verify, gw.settling(), timeout=600)
    gw.keep("verify-after-boot.json", json.dumps(verdict.checks, indent=1))
    assert verdict.rc == 0, verdict.summary()
