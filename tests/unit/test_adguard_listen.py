"""(adguard) ADGUARD_LISTEN: which addresses AdGuard Home answers DNS on (design decision 52).

Absent means `keep`, so a gateway whose settings file predates the key, the owner's included, plans and
installs exactly what it did before. `gateway` is what new installs get from the template."""

import re
import shutil
import subprocess

import pytest
from conftest import ROOT

from tvgw import config

INSTALL = (ROOT / "deploy" / "install.sh").read_text(encoding="utf-8")


def test_absent_means_keep_and_both_values_load(tmp_path):
    conf = tmp_path / "tvgw.conf"
    assert config.Settings().adguard_listen == "keep"
    assert config.load(tmp_path / "missing.conf").adguard_listen == "keep"
    for value in ("keep", "gateway"):
        conf.write_text(f"ADGUARD_LISTEN={value}\n", encoding="utf-8")
        assert config.load(conf).adguard_listen == value
    conf.write_text("ADGUARD_LISTEN=\n", encoding="utf-8")  # an empty value keeps the default, as every key
    assert config.load(conf).adguard_listen == "keep"


@pytest.mark.parametrize("value", ["Gateway", "all", "0.0.0.0", "yes"])
def test_any_other_value_is_refused_by_every_command(tmp_path, value):
    conf = tmp_path / "tvgw.conf"
    conf.write_text(f"ADGUARD_LISTEN={value}\n", encoding="utf-8")
    with pytest.raises(ValueError, match=r"ADGUARD_LISTEN=.* expected keep or gateway"):
        config.load(conf)


def test_the_key_is_a_setting_the_writer_accepts():
    assert config.CONF_KEYS["ADGUARD_LISTEN"] == "adguard_listen"
    assert "ADGUARD_LISTEN" in config.writable_keys()
    config.check_value("ADGUARD_LISTEN", "gateway")


def test_install_sh_defaults_it_as_settings_does_and_refuses_what_load_refuses():
    defaults = dict(re.findall(r"\$\{([A-Z_]+):=([^}]*)\}", INSTALL))
    assert defaults["ADGUARD_LISTEN"] == config.Settings().adguard_listen
    (pattern,) = re.findall(r"\[\[ \$ADGUARD_LISTEN =~ \^\(([a-z|]+)\)\$ \]\]", INSTALL)
    assert tuple(pattern.split("|")) == config.ADGUARD_LISTEN_MODES


@pytest.mark.parametrize(("value", "ok"), [("keep", True), ("gateway", True), ("Gateway", False), ("", True)])
def test_install_sh_check_runs_as_written(value, ok):
    """The two lines as install.sh has them, run by bash: the default fills an empty value, a near miss
    stops the install before anything is written."""
    bash = shutil.which("bash")
    if bash is None:
        pytest.skip("bash is not installed here")
    lines = [
        line
        for line in INSTALL.splitlines()
        if line.startswith(': "${ADGUARD_LISTEN:=') or line.startswith("[[ $ADGUARD_LISTEN =~")
    ]
    assert len(lines) == 2
    script = 'die() { echo "$1" >&2; exit 1; }\n' + "\n".join(lines) + '\necho "$ADGUARD_LISTEN"\n'
    env = {"PATH": "/usr/bin:/bin"}
    if value:
        env["ADGUARD_LISTEN"] = value
    out = subprocess.run([bash, "-c", script], capture_output=True, text=True, env=env)
    assert (out.returncode == 0) == ok, out.stderr
    if ok:
        assert out.stdout.strip() == (value or "keep")
    else:
        assert "ADGUARD_LISTEN must be keep or gateway" in out.stderr


# ---- the plan --------------------------------------------------------------------------------------

STOCK = {
    "http": {"address": "0.0.0.0:3000"},
    "dns": {"bind_hosts": ["0.0.0.0"], "port": 53, "upstream_dns": ["https://9.9.9.9/dns-query"]},
    "clients": {"persistent": []},
    "schema_version": 34,
}
TV = {"tv_ip": "10.10.10.17", "tv_mac": "b4:b2:91:aa:bb:cc", "tv_name": "tv"}


def desired(listen: str, **kw):
    from tvgw import adguardcfg, profile

    return adguardcfg.desired(profile.load("lg-webos"), config.Settings(adguard_listen=listen, **TV, **kw))


@pytest.mark.parametrize(
    "dns",
    [
        {"bind_hosts": ["0.0.0.0"], "port": 53},  # the wizard's "All interfaces"
        {"bind_hosts": ["10.10.10.1", "127.0.0.1"], "port": 53},  # what the quick start asked for
        {"bind_hosts": ["192.0.2.10"], "port": 5353},
        {},  # neither key: keep never adds them
    ],
)
def test_keep_leaves_the_listen_keys_exactly_as_adguard_has_them(dns):
    """The owner's gateway: whatever its wizard chose stays, and the plan is the one it had."""
    import copy

    from tvgw import adguardcfg

    current = copy.deepcopy(STOCK)
    current["dns"] = {**dns, "upstream_dns": ["https://9.9.9.9/dns-query"]}
    planned = adguardcfg.plan(current, desired("keep"))
    for key in ("bind_hosts", "port"):
        assert planned["dns"].get(key, "<unset>") == dns.get(key, "<unset>"), key
    assert not [
        c for c in adguardcfg.changes(current, planned) if c.startswith(("dns.bind_hosts", "dns.port"))
    ]


def test_keep_plans_byte_for_byte_what_the_plan_did_before_the_setting():
    """With the key absent the desired state carries no listen addresses at all, so plan() takes the
    branch it always took and writes the same bytes."""
    import dataclasses

    from tvgw import adguardcfg

    keep, gateway = desired("keep"), desired("gateway")
    assert keep.dns_bind_hosts == ()
    before = dataclasses.replace(gateway, dns_bind_hosts=())  # everything else as the gateway form has it
    assert keep == before
    assert adguardcfg.dump_yaml(adguardcfg.plan(STOCK, keep)) == adguardcfg.dump_yaml(
        adguardcfg.plan(STOCK, before)
    )


def test_gateway_owns_gw_ip_and_loopback_on_port_53_and_diff_reports_the_drift():
    from tvgw import adguardcfg

    current = {**STOCK, "dns": {"bind_hosts": ["0.0.0.0"], "port": 5353}}
    d = desired("gateway")
    assert d.dns_bind_hosts == ("10.10.10.1", "127.0.0.1")
    planned = adguardcfg.plan(current, d)
    assert planned["dns"]["bind_hosts"] == ["10.10.10.1", "127.0.0.1"] and planned["dns"]["port"] == 53
    diff = adguardcfg.changes(current, planned)
    assert "dns.bind_hosts: ['0.0.0.0'] -> ['10.10.10.1', '127.0.0.1']" in diff
    assert "dns.port: 5353 -> 53" in diff
    assert adguardcfg.changes(planned, adguardcfg.plan(planned, d)) == []  # applied: nothing left


def test_gateway_follows_gw_ip():
    from tvgw import adguardcfg

    d = desired("gateway", gw_ip="10.20.30.1", tv_net="10.20.30.0/24")
    assert adguardcfg.plan(STOCK, d)["dns"]["bind_hosts"] == ["10.20.30.1", "127.0.0.1"]


# ---- install.sh step 12: the drop-in -----------------------------------------------------------------

WORKDIR = "/etc/systemd/system/AdGuardHome.service.d/workdir.conf"


def step12_dropin(value: str, tmp_path) -> str:
    """install.sh's own if/else for the drop-in, run by bash with the setting given and the file
    written under tmp_path: the text a deploy writes."""
    bash = shutil.which("bash")
    if bash is None:
        pytest.skip("bash is not installed here")
    start = INSTALL.index('\tif [ "$ADGUARD_LISTEN" = gateway ]; then')
    end = INSTALL.index("\tfi\n", start) + len("\tfi\n")
    target = tmp_path / "workdir.conf"
    script = INSTALL[start:end].replace(WORKDIR, str(target))
    subprocess.run([bash, "-c", script], check=True, env={"PATH": "/usr/bin:/bin", "ADGUARD_LISTEN": value})
    return target.read_text(encoding="utf-8")


def test_keep_writes_the_drop_in_install_sh_always_wrote(tmp_path):
    """The owner's gateway (the key absent, so keep): the same bytes as before the setting, so the deploy
    reloads systemd as it always did and restarts nothing."""
    from tvgw import adguardcfg

    assert step12_dropin("keep", tmp_path) == "[Service]\nWorkingDirectory=/opt/AdGuardHome\n"
    assert adguardcfg.WORKDIR_KEEP == "[Service]\nWorkingDirectory=/opt/AdGuardHome\n"
    assert adguardcfg.workdir_dropin(config.Settings()) == adguardcfg.WORKDIR_KEEP


def test_gateway_orders_adguard_after_the_network_and_restarts_it_without_a_limit(tmp_path):
    from tvgw import adguardcfg

    text = step12_dropin("gateway", tmp_path)
    assert text == adguardcfg.WORKDIR_GATEWAY
    assert adguardcfg.workdir_dropin(config.Settings(adguard_listen="gateway")) == text
    unit, service = text.split("\n\n")
    assert unit.splitlines() == [
        "[Unit]",
        "After=network-online.target",
        "Wants=network-online.target",
        "StartLimitIntervalSec=0",  # a [Unit] key: in [Service] systemd ignores it
    ]
    assert service.splitlines() == [
        "[Service]",
        "WorkingDirectory=/opt/AdGuardHome",
        "Restart=always",
        "RestartSec=5",
    ]


def test_the_drop_in_is_written_only_where_install_sh_writes_it_and_once_per_value():
    """One writer of workdir.conf, inside the AdGuard step, and the step keys on the setting alone, not
    on what the YAML holds (review U-F15: keyed on the YAML it would have fired on the owner's gateway)."""
    assert INSTALL.count(WORKDIR) == 2
    step = INSTALL[INSTALL.index("if [ -f /opt/AdGuardHome/AdGuardHome.yaml ]; then") :]
    step = step[: step.index("\nfi\n")]
    assert step.count(WORKDIR) == 2 and "bind_hosts" not in step


def test_the_template_asks_new_installs_for_gateway():
    """install.sh copies the template only when /etc/tvgw/tvgw.conf is missing, and setup starts from it
    the same way, so `gateway` reaches new installs alone."""
    example = config.parse_conf((ROOT / "deploy" / "tvgw.conf.example").read_text(encoding="utf-8"))
    assert example["ADGUARD_LISTEN"] == "gateway"
    assert (
        "[ -f /etc/tvgw/tvgw.conf ] || install -m 640 -g adm tvgw.conf.example /etc/tvgw/tvgw.conf" in INSTALL
    )
