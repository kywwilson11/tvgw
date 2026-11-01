"""The guard (design decision 42): the template and its unit as text, the co-tenant drop-ins, avahi's
deny line, and the four `tvgw verify` checks, with every system call faked and every file in tmp_path."""

import json
import os
import re
import stat

import pytest
from conftest import ROOT

from tvgw import cli, config, guard, verify
from tvgw.config import Settings

DEPLOY = ROOT / "deploy"
TEMPLATE = (DEPLOY / "nftables" / "guard.nft.template").read_text(encoding="utf-8")
UNIT = (DEPLOY / "systemd" / "tvgw-guard.service").read_text(encoding="utf-8")
APPLY = (DEPLOY / "nftables" / "tvgw-apply").read_text(encoding="utf-8")
INSTALL = (DEPLOY / "install.sh").read_text(encoding="utf-8")
COMMENT = re.compile(r'comment "([^"]+)"')
S = Settings()


# ---- the setting ----------------------------------------------------------------------------------


def test_the_default_co_tenants_are_the_ones_the_gateway_measured():
    assert config.co_tenants(S.co_tenant_units) == (
        "smbd",
        "nmbd",
        "xrdp",
        "shairport-sync",
        "nqptp",
        "avahi-daemon",
        "ssh",
        "jupyterhub",
    )
    assert config.co_tenants("none") == ()
    assert config.co_tenants("smbd.service smbd qbittorrent-nox@ ") == ("smbd", "qbittorrent-nox@")


@pytest.mark.parametrize(
    "value", ["dnsmasq", "nginx.service", "AdGuardHome", "tvgw-pcap", "tvgw", "a/b", "-x"]
)
def test_a_unit_the_tv_depends_on_or_no_unit_name_is_refused(value):
    """A filter on dnsmasq or AdGuard Home would take the TV's DHCP or DNS away."""
    with pytest.raises(ValueError, match="CO_TENANT_UNITS"):
        config.co_tenants(f"smbd {value}")


def test_the_setting_is_read_and_checked_by_load(tmp_path):
    conf = tmp_path / "tvgw.conf"
    conf.write_text('CO_TENANT_UNITS="smbd xrdp"\n', encoding="utf-8")
    assert config.load(conf).co_tenant_units == "smbd xrdp"
    conf.write_text('CO_TENANT_UNITS="smbd dnsmasq"\n', encoding="utf-8")
    with pytest.raises(ValueError, match="dnsmasq serves the TV"):
        config.load(conf)
    conf.write_text("CO_TENANT_UNITS=\n", encoding="utf-8")  # empty keeps the default, as the shell's :=
    assert config.load(conf).co_tenant_units == S.co_tenant_units


def test_the_example_conf_names_the_default():
    example = config.parse_conf((DEPLOY / "tvgw.conf.example").read_text(encoding="utf-8"))
    assert example["CO_TENANT_UNITS"] == S.co_tenant_units


# ---- the template and its unit --------------------------------------------------------------------


def rendered(tv_if="eth0", tv_net="10.10.10.0/24", gw_ip="10.10.10.1") -> str:
    return TEMPLATE.replace("__TV_IF__", tv_if).replace("__TV_NET__", tv_net).replace("__GW_IP__", gw_ip)


def test_the_template_takes_exactly_the_three_tv_side_placeholders_and_no_site_address():
    assert set(re.findall(r"__[A-Z_]+__", TEMPLATE)) == {"__TV_IF__", "__TV_NET__", "__GW_IP__"}
    assert not re.search(r"\b10\.10\.10\.\d", TEMPLATE)  # the TV side comes from the settings only
    assert "__" not in rendered()


def test_install_renders_the_guard_with_render_dnsmasqs_convention(tmp_path):
    """The sed in install.sh fills each placeholder the template has, for any TV side."""
    import shutil
    import subprocess

    bash = shutil.which("bash")
    if bash is None:
        pytest.skip("bash is not installed here")
    start = INSTALL.index("render_guard() {")
    fn = INSTALL[start : INSTALL.index("\n}\n", start) + 3]
    script = f"TV_IF=lan1 TV_NET=172.16.4.0/22 GW_IP=172.16.4.1\n{fn}\nrender_guard\n"
    out = subprocess.run([bash, "-euo", "pipefail", "-c", script], cwd=DEPLOY, capture_output=True, text=True)
    assert out.returncode == 0, out.stderr
    assert out.stdout == rendered("lan1", "172.16.4.0/22", "172.16.4.1")


def test_the_guard_is_one_transaction_of_adds_and_flushes():
    """`add` keeps what exists and `flush chain` empties it in the same transaction: a reload never
    leaves a moment with no chain. No `delete table`, which would."""
    statements = [ln for ln in TEMPLATE.splitlines() if ln.strip() and not ln.startswith("#")]
    assert all(ln.startswith(("add table ", "add chain ", "flush chain ", "add rule ")) for ln in statements)
    assert "delete" not in "\n".join(statements)
    for chain in guard.CHAINS:
        assert (
            f"add chain inet tvgw_guard {chain} {{ type filter hook {chain} priority filter + 10;" in TEMPLATE
        )
        assert f"flush chain inet tvgw_guard {chain}" in TEMPLATE
    first_rule = next(i for i, ln in enumerate(statements) if ln.startswith("add rule"))
    assert all(not ln.startswith("add rule") for ln in statements[:first_rule])
    assert all(ln.startswith("add rule") for ln in statements[first_rule:])


def test_every_guard_counter_has_a_comment_of_its_own():
    """verify stores counters by comment, so each must be unique, and none may be one of inet tvgw's,
    or the brief would add the guard's packets to a tvgw line."""
    counted = [ln for ln in TEMPLATE.splitlines() if " counter " in ln and ln.startswith("add rule")]
    comments = [COMMENT.search(ln).group(1) for ln in counted if COMMENT.search(ln)]
    assert len(comments) == len(counted), "a counter without a comment"
    assert len(set(comments)) == len(comments)
    assert all(c.startswith("guard: ") for c in comments)
    tvgw = set(re.findall(r'comment \\?"([^"\\]+)\\?"', APPLY))
    assert not tvgw & set(comments)
    for rule in guard.KEY_RULES:
        assert f'comment "{rule}"' in TEMPLATE, rule


def test_the_guards_input_chain_allows_what_inet_tvgws_does_and_drops_last():
    """In the order 11 F6 gives: the source check before anything answers, DHCP before the address
    check (a DISCOVER goes to 255.255.255.255), the final drop last."""
    rules = [
        ln.split("input ", 1)[1]
        for ln in TEMPLATE.splitlines()
        if ln.startswith("add rule inet tvgw_guard input")
    ]
    order = [
        'iifname != "__TV_IF__" accept',
        "ip saddr != { 0.0.0.0, __TV_NET__ }",
        "ct state established,related accept",
        "udp sport 68 udp dport 67 accept",
        "ip daddr != __GW_IP__",
        "th dport 53 accept",
        "tcp dport { 80, 443 } accept",
        "icmp type echo-request limit rate 5/second accept",
    ]
    at = [next(i for i, r in enumerate(rules) if needle in r) for needle in order]
    assert at == sorted(at)
    assert rules[-1] == f'counter drop comment "{guard.FINAL_DROP}"'


def test_the_tv_api_rule_lives_in_the_guard_and_spares_root():
    rule = next(ln for ln in TEMPLATE.splitlines() if "TV API from root only" in ln)
    assert rule.startswith("add rule inet tvgw_guard output") and "meta skuid != 0" in rule
    assert "tcp dport { 3000, 3001 }" in rule


def test_the_unit_is_never_stopped_and_loads_before_the_network():
    """Modelled on Debian trixie's nftables.service (DefaultDependencies=no, Wants= and Before=
    network-pre.target, Conflicts= and Before= shutdown.target, WantedBy=sysinit.target), with no
    ExecStop and manual stops refused, so nothing but `nft delete table` lifts the guard."""
    lines = UNIT.splitlines()
    for want in (
        "DefaultDependencies=no",
        "Wants=network-pre.target",
        "Before=network-pre.target tvgw.service shutdown.target",
        "Conflicts=shutdown.target",
        "RefuseManualStop=yes",
        "Type=oneshot",
        "RemainAfterExit=yes",
        "ExecStart=/usr/sbin/nft -f /etc/tvgw/guard.nft",
        "ExecReload=/usr/sbin/nft -f /etc/tvgw/guard.nft",
        "WantedBy=sysinit.target",
    ):
        assert want in lines, want
    assert not [ln for ln in lines if ln.startswith("ExecStop")]
    assert "GUARD=/etc/tvgw/guard.nft" in INSTALL.splitlines()


def test_nothing_restarts_or_stops_the_guard():
    """A restart is refused (RefuseManualStop also refuses restarts) and a stop would be one too; the
    install reloads an active guard and starts an inactive one."""
    for path in (DEPLOY / "install.sh", *(ROOT / "packaging" / "scripts").iterdir()):
        text = path.read_text(encoding="utf-8")
        for verb in ("restart", "stop", "disable --now", "try-restart"):
            assert not re.search(rf"systemctl (-q )?{verb} tvgw-guard", text), (path.name, verb)
    assert "systemctl reload-or-restart tvgw-guard.service" in INSTALL


# ---- the co-tenant drop-ins -----------------------------------------------------------------------


def test_the_dropin_denies_the_tv_subnet_and_keeps_the_gateways_own_address():
    text = guard.dropin("10.10.10.0/24", "10.10.10.1")
    assert "[Service]\nIPAddressDeny=10.10.10.0/24\nIPAddressAllow=10.10.10.1/32\n" in text
    assert "[Socket]\n" in guard.dropin("10.10.10.0/24", "10.10.10.1", "Socket")


def test_the_plan_writes_what_is_installed_and_removes_what_is_no_longer_wanted(tmp_path):
    d = str(tmp_path)
    old = os.path.join(d, "cups.service.d", guard.DROPIN)
    same = os.path.join(d, "smbd.service.d", guard.DROPIN)
    p = guard.plan(
        ["smbd", "xrdp", "ssh", "nqptp"],
        unit_files={"smbd.service", "xrdp.service", "ssh.service", "qbittorrent-nox@.service"},
        active_sockets={"ssh.socket"},
        present={old: "x", same: guard.dropin("10.10.10.0/24", "10.10.10.1")},
        tv_net="10.10.10.0/24",
        gw_ip="10.10.10.1",
        unit_dir=d,
    )
    assert sorted(os.path.relpath(x, d) for x in p.writes) == [
        f"qbittorrent-nox@.service.d/{guard.DROPIN}",  # a template, whatever the setting says
        f"ssh.service.d/{guard.DROPIN}",
        f"ssh.socket.d/{guard.DROPIN}",  # socket-activated: the socket systemd listens on too
        f"xrdp.service.d/{guard.DROPIN}",
    ]
    assert "[Socket]" in p.writes[os.path.join(d, "ssh.socket.d", guard.DROPIN)]
    assert p.removes == [old]  # nqptp is not installed: skipped without a word; smbd's is already right
    assert (
        p.changed and p.lines()[0].startswith("wrote ") and p.lines(dry_run=True)[0].startswith("would write")
    )


def test_apply_writes_atomically_and_removes_an_empty_directory(tmp_path):
    d = str(tmp_path)
    p = guard.plan(["smbd"], {"smbd.service"}, set(), {}, "10.10.10.0/24", "10.10.10.1", d)
    guard.apply(p)
    present = guard.present_dropins(d)
    assert list(present) == [os.path.join(d, "smbd.service.d", guard.DROPIN)]
    assert stat.S_IMODE(os.stat(next(iter(present))).st_mode) == 0o644
    again = guard.plan(["smbd"], {"smbd.service"}, set(), present, "10.10.10.0/24", "10.10.10.1", d)
    assert not again.changed
    gone = guard.plan(["none-here"], set(), set(), present, "10.10.10.0/24", "10.10.10.1", d)
    guard.apply(gone)
    assert guard.present_dropins(d) == {} and not (tmp_path / "smbd.service.d").exists()


def test_gather_asks_systemd_once_for_files_and_once_for_sockets():
    calls = []

    def run(cmd):
        calls.append(cmd)
        if cmd[1] == "list-unit-files":
            return "smbd.service enabled enabled\nxrdp.service masked enabled\n"
        return "ssh.socket loaded active listening OpenBSD SSH\n"

    files, sockets = guard.gather(["smbd", "xrdp", "ssh"], run)
    assert files == {"smbd.service"} and sockets == {"ssh.socket"}  # a masked unit cannot run
    assert calls[0][-4:] == ["smbd.service", "xrdp.service", "ssh.service", "qbittorrent-nox@.service"]
    calls.clear()
    assert guard.gather([], run)[1] == set()  # the template only: no list-units with no pattern
    assert [c[1] for c in calls] == ["list-unit-files"]


# ---- avahi ----------------------------------------------------------------------------------------

AVAHI = "[server]\n#host-name=foo\nuse-ipv4=yes\n#deny-interfaces=eth1\n\n[wide-area]\nenable-wide-area=yes\n"


def test_avahi_gets_the_tv_port_in_its_server_section_once():
    out = guard.avahi_deny(AVAHI, "eth0")
    assert out.startswith(f"[server]\n{guard.AVAHI_MARK}\ndeny-interfaces=eth0\n#host-name=foo")
    assert "#deny-interfaces=eth1" in out  # the commented example is left alone
    assert guard.avahi_deny(out, "eth0") is None


def test_an_existing_deny_list_keeps_its_entries():
    text = "[server]\ndeny-interfaces=wg0 , docker0\r\n[reflector]\n"
    assert guard.avahi_deny(text, "eth0") == "[server]\ndeny-interfaces=wg0, docker0, eth0\r\n[reflector]\n"
    assert guard.avahi_deny("[server]\ndeny-interfaces = eth0,wg0\n", "eth0") is None
    assert guard.avahi_deny("[wide-area]\nx=1", "eth0") == (
        f"[wide-area]\nx=1\n\n[server]\n{guard.AVAHI_MARK}\ndeny-interfaces=eth0\n"
    )


def test_editing_avahi_keeps_the_mode_and_backs_up_once(tmp_path):
    conf = tmp_path / "avahi-daemon.conf"
    conf.write_text(AVAHI, encoding="utf-8")
    conf.chmod(0o640)
    assert guard.edit_avahi(str(conf), "eth0") is True
    assert (tmp_path / "avahi-daemon.conf.tvgw-backup").read_text(encoding="utf-8") == AVAHI
    assert stat.S_IMODE(conf.stat().st_mode) == 0o640 and "deny-interfaces=eth0" in conf.read_text(
        encoding="utf-8"
    )
    assert guard.edit_avahi(str(conf), "eth0") is False  # nothing to do
    assert guard.edit_avahi(str(conf), "eth1") is True
    assert (tmp_path / "avahi-daemon.conf.tvgw-backup").read_text(
        encoding="utf-8"
    ) == AVAHI  # still the first
    assert guard.edit_avahi(str(tmp_path / "missing.conf"), "eth0") is False


# ---- the CLI install.sh runs ------------------------------------------------------------------------


def test_tvgw_guard_prints_only_what_it_changed(tmp_path, monkeypatch, capsys):
    conf = tmp_path / "tvgw.conf"
    conf.write_text('CO_TENANT_UNITS="smbd avahi-daemon"\nTV_IF=eth1\n', encoding="utf-8")
    units, avahi = tmp_path / "units", tmp_path / "avahi.conf"
    avahi.write_text(AVAHI, encoding="utf-8")
    monkeypatch.setattr(
        guard, "run_cmd", lambda cmd: "smbd.service enabled enabled\n" if "list-unit-files" in cmd else ""
    )
    base = ["--conf", str(conf), "guard"]
    extra = ["--unit-dir", str(units), "--avahi-conf", str(avahi)]
    assert cli.main([*base, "cotenants", "--dry-run", *extra]) == 0
    assert capsys.readouterr().out.startswith("would write ") and not units.exists()
    assert cli.main([*base, "cotenants", *extra]) == 0
    assert capsys.readouterr().out == f"wrote {units}/smbd.service.d/{guard.DROPIN}\n"
    assert cli.main([*base, "cotenants", *extra]) == 0
    assert capsys.readouterr().out == ""  # install.sh daemon-reloads only on output
    assert cli.main([*base, "avahi", *extra]) == 0
    assert capsys.readouterr().out == f"changed {avahi}\n" and "deny-interfaces=eth1" in avahi.read_text(
        encoding="utf-8"
    )
    assert cli.main([*base, "avahi", *extra]) == 0 and capsys.readouterr().out == ""
    conf.write_text('CO_TENANT_UNITS="smbd"\n', encoding="utf-8")
    other = tmp_path / "other.conf"
    other.write_text(AVAHI, encoding="utf-8")
    assert cli.main([*base, "avahi", "--avahi-conf", str(other)]) == 0  # avahi not listed: left alone
    assert other.read_text(encoding="utf-8") == AVAHI


# ---- what verify reads ----------------------------------------------------------------------------

LISTING = rendered()  # stands in for nft's own listing: verify looks for the same spellings
NFT_LISTING = """table inet tvgw_guard {
	chain input {
		type filter hook input priority filter + 10; policy accept;
		counter drop comment "guard: TV may not reach other Pi services"
		ip saddr != { 0.0.0.0, 10.10.10.0/24 } counter drop comment "guard: spoofed source"
		ip daddr != 10.10.10.1 counter drop comment "guard: the gateway address only (weak host)"
	}
	chain forward {
		type filter hook forward priority filter + 10; policy accept;
		counter drop comment "guard: TV never to the LAN"
	}
	chain output {
		type filter hook output priority filter + 10; policy accept;
		counter drop comment "guard: TV API from root only"
	}
}
"""


def present(listing=NFT_LISTING, baseline=""):
    run = lambda cmd: listing if cmd == ["nft", "-s", "list", "table", "inet", "tvgw_guard"] else ""  # noqa: E731
    return verify.guard_present_check(run, lambda path: baseline if path == verify.GUARD_APPLIED else "")


def test_guard_present_needs_the_table_its_three_hooks_and_its_key_rules():
    assert present().ok and present().detail.startswith("no baseline")
    assert present(baseline=NFT_LISTING).ok and present(baseline=NFT_LISTING).detail == ""
    gone = present("")
    assert not gone.ok and "not loaded" in gone.detail
    unhooked = present(NFT_LISTING.replace("hook output priority filter + 10", "hook output priority filter"))
    assert not unhooked.ok and unhooked.detail == "missing: chain output"
    no_api = present(NFT_LISTING.replace("TV API from root only", "x"))
    assert not no_api.ok and '"guard: TV API from root only"' in no_api.detail
    edited = present(baseline=NFT_LISTING + "\n# by hand")
    assert not edited.ok and edited.detail == "differs from what tvgw-guard loaded"


def guard_listing(final: int) -> str:
    rule = {
        "rule": {
            "comment": guard.FINAL_DROP,
            "expr": [{"counter": {"packets": final, "bytes": 0}}, {"drop": None}],
        }
    }
    return json.dumps({"nftables": [{"table": {"name": "tvgw_guard"}}, rule]})


def after_apply(final: int | None) -> str:
    tvgw = json.dumps({"nftables": [{"rule": {"comment": "DoT/DoQ", "expr": [{"counter": {"packets": 9}}]}}]})
    return tvgw + ("\n" + guard_listing(final) if final is not None else "") + "\n"


@pytest.mark.parametrize(
    ("loaded", "now", "base", "warn", "says"),
    [
        (True, 7, 7, False, "nothing past inet tvgw"),
        (True, 9, 7, True, "2 packets inet tvgw accepted"),
        (True, 3, 7, False, "reloaded since"),
        (True, 3, None, False, "no guard counter in the last apply"),
        (False, 40, 7, False, "the guard holds alone (40 dropped)"),
    ],
)
def test_guard_quiet_warns_only_when_the_guard_dropped_what_tvgw_accepted(loaded, now, base, warn, says):
    c = verify.guard_quiet_check(loaded, guard_listing(now), after_apply(base))
    assert c.ok and c.warn is warn and says in c.detail
    assert c.line().startswith("WARN" if warn else "OK  ")
    assert verify.guard_quiet_check(True, "", after_apply(1)).detail == "no guard counter to read"


def shown(units: dict[str, tuple[str, str, str]]) -> str:
    return "\n\n".join(
        f"Id={u}\nLoadState={load}\nActiveState={state}\nIPAddressDeny={deny}"
        for u, (load, state, deny) in units.items()
    )


def cotenants(s, units, instances=""):
    def run(cmd):
        if cmd[:2] == ["systemctl", "list-units"]:
            return instances
        if cmd[:2] == ["systemctl", "show"]:
            return shown(units)
        return ""

    return verify.cotenants_check(s, run)


def test_cotenants_denied_reads_systemds_own_view_of_each_unit():
    s = Settings(co_tenant_units="smbd xrdp ssh")
    ok = cotenants(
        s,
        {
            "smbd.service": ("loaded", "active", "10.10.10.0/24"),
            "xrdp.service": ("loaded", "active", "any"),
            "ssh.service": ("not-found", "inactive", ""),
            "ssh.socket": ("loaded", "inactive", ""),  # installed, not in use: no filter needed
        },
    )
    assert ok.ok and not ok.warn and ok.detail == "smbd.service, xrdp.service"
    bare = cotenants(
        s,
        {
            "smbd.service": ("loaded", "active", "10.10.0.0/16"),
            "xrdp.service": ("loaded", "active", "192.0.2.0/24"),
        },
    )
    assert bare.ok and bare.warn and bare.detail.startswith("no IPAddressDeny=10.10.10.0/24: xrdp.service")
    instance = cotenants(
        s,
        {"qbittorrent-nox@media.service": ("loaded", "active", "")},
        instances="qbittorrent-nox@media.service loaded active running qBittorrent\n",
    )
    assert instance.warn and "qbittorrent-nox@media.service" in instance.detail
    assert cotenants(Settings(co_tenant_units="none"), {}).detail == "no co-tenant installed"


def test_guard_denies_covers_a_supernet_and_any_but_not_a_smaller_prefix():
    assert guard.denies("10.10.10.0/24", "10.10.10.0/24") and guard.denies(
        "10.0.0.0/8 ::1/128", "10.10.10.0/24"
    )
    assert guard.denies("any", "10.10.10.0/24") and not guard.denies("10.10.10.0/25", "10.10.10.0/24")
    assert not guard.denies("", "10.10.10.0/24") and not guard.denies("junk", "10.10.10.0/24")


@pytest.mark.parametrize(
    ("cap", "warn", "says"),
    [
        ("0000000000000000", False, "CapEff 0000000000000000: none"),
        ("0000000000000400", False, "net_bind_service"),
        ("0000000000003000", True, "holds net_admin and net_raw"),
        ("0000000000001000", True, "holds net_admin"),
    ],
)
def test_dnsmasq_caps_decodes_the_running_daemons_mask(cap, warn, says):
    def run(cmd):
        return "77\n" if cmd[-1] == "dnsmasq.service" else ""

    c = verify.dnsmasq_caps_check(
        run, lambda path: f"Name:\tdnsmasq\nCapEff:\t{cap}\n" if path == "/proc/77/status" else ""
    )
    assert c.ok and c.warn is warn and says in c.detail
    down = verify.dnsmasq_caps_check(lambda cmd: "0\n", lambda path: "")
    assert down.ok and down.detail == "dnsmasq is not running"


def test_cap_names_follow_the_kernels_numbering():
    assert guard.cap_names(1 << 12 | 1 << 13) == ["net_admin", "net_raw"]
    assert guard.cap_names(1 << 40) == ["checkpoint_restore"] and guard.cap_names(1 << 50) == ["cap50"]
    assert (
        guard.cap_eff("CapInh:\t0\nCapEff:\t00000000a80425fb\n") == 0xA80425FB and guard.cap_eff("") is None
    )


def test_a_warning_is_not_a_failure():
    r = verify.Result(checks=[verify.Check("x", True, "d", warn=True), verify.Check("y", True)])
    assert r.ok and r.failures == [] and r.checks[0].line() == "WARN x: d"
