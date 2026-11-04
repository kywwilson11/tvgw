"""(lists) AdGuard Home's upgrade and outage discipline: the keys the plan now owns, the schema ceiling,
the restart guard, `upgrade()` with its rollback, and the --no-check-update drop-in. Every binary,
service call and resolver is a stand-in; nothing here touches the host or the network."""

from __future__ import annotations

import contextlib
import fcntl
import os
import re
import socket
import struct
import threading
from pathlib import Path

import pytest
import yaml

from tvgw import adguardcfg, cli, config, profile, verify
from tvgw.config import Settings

ROOT = Path(__file__).resolve().parents[2]
BASE = {
    "http": {"address": "127.0.0.1:3000"},
    "dns": {"upstream_dns": ["https://192.0.2.53/dns-query"]},
    "filtering": {"blocking_mode": "default"},
    "schema_version": 34,
}
S = Settings(tv_ip="10.10.10.17", tv_mac="aa:bb:cc:dd:ee:ff", tv_name="lgcx")


@pytest.fixture()
def lg():
    return profile.load("lg-webos")


def desired(lg, **settings) -> adguardcfg.Desired:
    return adguardcfg.desired(lg, Settings(**{**S.__dict__, **settings}))


# ---- the keys the plan owns ---------------------------------------------------------------------


def test_the_plan_owns_the_list_interval_the_ignore_switches_and_the_cache(lg):
    cfg = adguardcfg.plan(BASE, desired(lg))
    assert cfg["filtering"]["filters_update_interval"] == 24
    assert cfg["filtering"]["rewrites_enabled"] is True
    assert cfg["querylog"]["ignored_enabled"] is False and cfg["statistics"]["ignored_enabled"] is False
    dns = cfg["dns"]
    assert dns["cache_enabled"] is True and dns["cache_optimistic"] is True
    # the strings AdGuard itself writes for these durations, so a save in its UI is not drift
    assert dns["cache_optimistic_answer_ttl"] == "30s" and dns["cache_optimistic_max_age"] == "12h"
    assert dns["fallback_dns"] == []


@pytest.mark.parametrize(
    ("section", "key", "ui_value", "owned"),
    [
        ("filtering", "filters_update_interval", 0, 24),  # 0 freezes every list
        ("querylog", "ignored_enabled", True, False),  # ignored names vanish from the evidence
        ("statistics", "ignored_enabled", True, False),
        ("dns", "cache_enabled", False, True),
        ("dns", "cache_optimistic_max_age", "1h", "12h"),
        ("filtering", "rewrites_enabled", False, True),
        ("filtering", "blocking_mode", "refused", "default"),  # never refused (report section 17)
        ("filtering", "blocking_mode", "nxdomain", "default"),
    ],
)
def test_a_ui_edit_of_an_owned_key_is_drift_and_the_plan_puts_it_back(lg, section, key, ui_value, owned):
    edited = {**BASE, section: {**BASE.get(section, {}), key: ui_value}}
    planned = adguardcfg.plan(edited, desired(lg))
    assert planned[section][key] == owned
    assert f"{section}.{key}: {ui_value!r} -> {owned!r}" in adguardcfg.changes(edited, planned)
    assert adguardcfg.changes(planned, adguardcfg.plan(planned, desired(lg))) == []  # idempotent


def test_blocking_mode_default_is_an_invariant_of_every_plan(lg):
    """The 0.0.0.0 answers dnsmsg.is_blocked_answer, verify and the hardware suite read as blocked, and
    the empty NOERROR the HTTPS strip relies on, exist only in `default` mode."""
    for start in ({}, BASE, {"filtering": {"blocking_mode": "custom_ip", "blocking_ipv4": "203.0.113.1"}}):
        assert adguardcfg.plan(start, desired(lg))["filtering"]["blocking_mode"] == "default"


def test_retention_and_fallback_come_from_the_settings(lg):
    d = desired(lg, querylog_days=3, stats_days=7, dns_fallback="https://198.51.100.9/dns-query")
    cfg = adguardcfg.plan(BASE, d)
    assert cfg["querylog"]["interval"] == "3d" and cfg["statistics"]["interval"] == "7d"
    assert cfg["dns"]["fallback_dns"] == ["https://198.51.100.9/dns-query"]
    defaults = adguardcfg.plan(BASE, desired(lg))
    assert defaults["querylog"]["interval"] == "90d" == defaults["statistics"]["interval"]  # today's


def test_the_probe_name_is_the_first_must_allow_host(lg):
    assert desired(lg).probe_name == next(iter(lg.must_allow))


def test_the_local_name_is_one_the_profiles_own_rules_block(lg):
    """The guard's proof that AdGuard is alive: a name its filter answers without an upstream."""
    d = desired(lg)
    assert d.local_name and f"||{d.local_name}^" in d.user_rules
    assert adguardcfg._locally_blocked(
        ["@@||a.example^$important", "||b.example^$client=x", "||c.example^"]
    ) == ("c.example")
    assert adguardcfg._locally_blocked(["@@||a.example^"]) is None


def test_the_settings_defaults_keep_todays_behaviour():
    s = Settings()
    assert (s.querylog_days, s.stats_days, s.dns_fallback) == (90, 90, "")
    for key in ("QUERYLOG_DAYS", "STATS_DAYS", "DNS_FALLBACK"):
        assert key in config.CONF_KEYS and key in config.writable_keys()


@pytest.mark.parametrize(
    ("line", "error"),
    [
        ("QUERYLOG_DAYS=0", "must be at least 1"),
        ("QUERYLOG_DAYS=366", "1 to 365 days"),
        ("STATS_DAYS=1000", "1 to 365 days"),
        ("DNS_FALLBACK=198.51.100.9", "encrypted resolver by IPv4 address"),  # plain DNS
        ("DNS_FALLBACK=https://dns.example/dns-query", "encrypted resolver by IPv4 address"),  # a name
        ("DNS_FALLBACK=https://1.1.1.1/dns-query", "already an upstream"),  # the same operator
        ("DNS_FALLBACK=tls://300.1.1.1", "encrypted resolver by IPv4 address"),
    ],
)
def test_settings_the_plan_cannot_use_are_refused(tmp_path, line, error):
    conf = tmp_path / "tvgw.conf"
    conf.write_text(line + "\n", encoding="utf-8")
    with pytest.raises(ValueError, match=error):
        config.load(conf)


def test_a_second_operator_by_address_is_accepted(tmp_path):
    conf = tmp_path / "tvgw.conf"
    conf.write_text(
        "DNS_FALLBACK=https://198.51.100.9/dns-query,tls://203.0.113.9:853\nQUERYLOG_DAYS=3\n",
        encoding="utf-8",
    )
    s = config.load(conf)
    assert s.dns_fallback.startswith("https://198.51.100.9/") and s.querylog_days == 3
    assert config.fallback_host("quic://203.0.113.9") == "203.0.113.9"


# ---- the schema ceiling -------------------------------------------------------------------------


def test_a_schema_above_the_ceiling_is_refused_with_the_way_forward():
    adguardcfg.check_schema({"schema_version": 34}, "x.yaml")
    adguardcfg.check_schema({"schema_version": "30"}, "x.yaml")  # older: AdGuard migrates it at start
    with pytest.raises(
        RuntimeError, match=r"schema_version 35, above 34.*nothing changed.*docs/how-it-works/adguard.md"
    ):
        adguardcfg.check_schema({"schema_version": 35}, "x.yaml")
    assert adguardcfg.schema_version({"schema_version": True}) is None


def test_apply_refuses_a_newer_schema_before_the_service_is_touched(tmp_path, lg):
    path = tmp_path / "AdGuardHome.yaml"
    path.write_text(yaml.safe_dump({**BASE, "schema_version": 35}), encoding="utf-8")
    calls: list = []
    with pytest.raises(RuntimeError, match="above 34"):
        adguardcfg.apply(
            str(path), desired(lg), control=lambda *a: calls.append(a), check=lambda p: (True, "")
        )
    assert calls == [] and not list(tmp_path.glob("*.bak-*"))


# ---- the restart guard --------------------------------------------------------------------------


def test_the_guard_defers_only_on_a_down_upstream():
    adguardcfg.restart_guard("us.example.com", state=lambda n: "up")
    adguardcfg.restart_guard("us.example.com", state=lambda n: "unknown")  # AdGuard may be the problem
    with pytest.raises(adguardcfg.Deferred, match=r"^deferred: upstream down") as e:
        adguardcfg.restart_guard("us.example.com", state=lambda n: "down")
    assert isinstance(e.value, RuntimeError)  # every caller that handles a refused apply handles this


def test_a_deferred_apply_changes_nothing_and_restarts_nothing(tmp_path, lg):
    path = tmp_path / "AdGuardHome.yaml"
    path.write_text(yaml.safe_dump(BASE), encoding="utf-8")
    before = path.read_text(encoding="utf-8")
    calls: list = []

    def down():
        raise adguardcfg.Deferred("deferred: upstream down (test)")

    with pytest.raises(adguardcfg.Deferred):
        adguardcfg.apply(
            str(path), desired(lg), control=lambda *a: calls.append(a), check=lambda p: (True, ""), guard=down
        )
    assert calls == [] and path.read_text(encoding="utf-8") == before
    assert not list(tmp_path.glob("*.bak-*")) and not list(tmp_path.glob(".AdGuardHome.*"))


def test_the_guard_is_not_asked_when_there_is_nothing_to_apply(tmp_path, lg):
    path = tmp_path / "AdGuardHome.yaml"
    path.write_text(adguardcfg.dump_yaml(adguardcfg.plan(BASE, desired(lg))), encoding="utf-8")
    asked: list = []
    assert adguardcfg.apply(str(path), desired(lg), control=None, guard=lambda: asked.append(1)) == []
    assert asked == []


@pytest.mark.parametrize(("timeout", "wait"), [(None, 12.0), ("5s", 7.0), ("1m", 32.0)])
def test_the_default_guard_probes_the_must_allow_name_past_adguards_own_timeout(
    tmp_path, lg, monkeypatch, timeout, wait
):
    """The first probe listens past dns.upstream_timeout (10 s when unset), so the SERVFAIL AdGuard sends
    only after giving up on a silent upstream is still heard; the local name goes along."""
    path = tmp_path / "AdGuardHome.yaml"
    dns = {**BASE["dns"], **({"upstream_timeout": timeout} if timeout else {})}
    path.write_text(yaml.safe_dump({**BASE, "dns": dns}), encoding="utf-8")
    seen: list = []
    monkeypatch.setattr(adguardcfg, "upstream_state", lambda name, **kw: seen.append((name, kw)) or "down")
    with pytest.raises(adguardcfg.Deferred):
        adguardcfg.apply(str(path), desired(lg), control=lambda *a: None, check=lambda p: (True, ""))
    assert seen == [(next(iter(lg.must_allow)), {"wait": wait, "local": desired(lg).local_name})]
    seen.clear()
    with pytest.raises(adguardcfg.Deferred):  # the CLI's guard for upgrade and service reads the same
        adguardcfg.guard_for(str(path), desired(lg))()
    assert seen == [(next(iter(lg.must_allow)), {"wait": wait, "local": desired(lg).local_name})]


@pytest.mark.parametrize(
    ("text", "secs"),
    [
        ("10s", 10.0),
        ("1m30s", 90.0),
        ("1.5s", 1.5),
        ("500ms", 0.5),
        ("90d", 7776000.0),
        ("10", None),
        ("", None),
    ],
)
def test_durations_read_the_way_adguard_writes_them(text, secs):
    assert adguardcfg.duration_seconds(text) == secs


def responder(flags: int, delay: float = 0.0, probes: bool = True, others: bool = True):
    """A UDP server on 127.0.0.1 answering every question with these header flags after `delay` seconds,
    the guard's probes only when `probes` and any other name only when `others`; (port, stop, seen)."""
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind(("127.0.0.1", 0))
    sock.settimeout(0.2)
    stop, seen = threading.Event(), []

    def answer(q, peer):
        with contextlib.suppress(OSError):
            sock.sendto(q[:2] + struct.pack(">HHHHH", flags, 1, 0, 0, 0) + q[12:], peer)

    def serve():
        while not stop.is_set():
            try:
                q, peer = sock.recvfrom(512)
            except TimeoutError:
                continue
            seen.append(q)
            if probes if b"tvgw-probe-" in q else others:
                threading.Timer(delay, answer, (q, peer)).start()
        stop.wait(delay + 0.5)
        sock.close()

    threading.Thread(target=serve, daemon=True).start()
    return sock.getsockname()[1], stop, seen


@pytest.mark.parametrize(("flags", "state"), [(0x8182, "down"), (0x8183, "up"), (0x8180, "up")])
def test_upstream_state_reads_the_rcode_of_a_fresh_label(flags, state):
    port, stop, seen = responder(flags)
    try:
        assert adguardcfg.upstream_state("us.example.com", port=port, tries=2) == state
    finally:
        stop.set()
    # a label the cache cannot hold: new on every try, under the must-allow name
    labels = [q[13 : 13 + q[12]].decode() for q in seen]
    assert all(re.fullmatch(r"tvgw-probe-[0-9a-f]{8}", x) for x in labels) and len(set(labels)) == len(labels)
    assert all(b"\x02us\x07example\x03com\x00" in q for q in seen)


def test_a_slow_servfail_is_down():
    """An upstream that drops packets: AdGuard SERVFAILs only after its own upstream timeout (10 s by
    default), long after the 1.5 s the probe used to wait. The first try listens past it."""
    port, stop, _ = responder(0x8182, delay=2.0)
    try:
        assert adguardcfg.upstream_state("us.example.com", port=port, tries=2, wait=3.5) == "down"
    finally:
        stop.set()


def test_silent_probes_while_adguard_answers_its_own_rules_is_down():
    """Upstreams that never answer within the wait (several silent upstreams tried in turn): AdGuard is
    alive, its filter answers a locally blocked name at once, so the silence is the upstreams'."""
    port, stop, seen = responder(0x8180, probes=False)
    try:
        got = adguardcfg.upstream_state(
            "us.example.com", port=port, tries=2, wait=0.5, local="blocked.example"
        )
        assert got == "down"
        assert sum(b"tvgw-probe-" in q for q in seen) == 2 and any(
            b"\x07blocked\x07example\x00" in q for q in seen
        )
    finally:
        stop.set()


def test_upstream_state_is_unknown_without_a_resolver():
    """Silent on the probe and on the local name: AdGuard itself may be broken, and an apply the cure."""
    probe = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    probe.bind(("127.0.0.1", 0))
    port = probe.getsockname()[1]
    probe.close()
    assert adguardcfg.upstream_state("us.example.com", port=port, tries=1, wait=0.3) == "unknown"
    got = adguardcfg.upstream_state("us.example.com", port=port, tries=1, wait=0.3, local="blocked.example")
    assert got == "unknown"


# ---- upgrade() ----------------------------------------------------------------------------------


def fake_bin(path: Path, text: str) -> Path:
    path.write_text(f"#!/bin/sh\n# {text}\n", encoding="utf-8")
    path.chmod(0o755)
    return path


@pytest.fixture()
def site(tmp_path):
    """A live install (binary and YAML) and a new binary beside it in a download directory."""
    live = tmp_path / "opt"
    live.mkdir()
    exe = fake_bin(live / "AdGuardHome", "old")
    yml = live / "AdGuardHome.yaml"
    yml.write_text(yaml.safe_dump(BASE), encoding="utf-8")
    new = fake_bin(tmp_path / "AdGuardHome.new", "new")
    return exe, yml, new


def run_upgrade(site, **kw):
    exe, yml, new = site
    calls: list = []
    defaults = dict(
        binary=str(exe),
        control=lambda *a: calls.append(a),
        ready=lambda: True,
        check=lambda candidate, bin_: (True, ""),
        verify=lambda: set(),
        guard=lambda: None,
        version=lambda path: (0, 107, 80) if "new" in path else (0, 107, 79),
        now=1793020000,
    )
    defaults.update(kw)
    return adguardcfg.upgrade(str(yml), str(new), **defaults), calls


def test_upgrade_checks_then_swaps_with_backups(site):
    exe, yml, new = site
    checked: list = []
    done, calls = run_upgrade(
        site, check=lambda candidate, bin_: checked.append((candidate, bin_)) or (True, "")
    )
    assert "new" in exe.read_text(encoding="utf-8") and os.access(exe, os.X_OK)
    assert calls == [("stop", "AdGuardHome"), ("start", "AdGuardHome")]
    ((candidate, bin_),) = checked
    assert bin_ == str(new) and candidate != str(yml) and not os.path.exists(candidate)  # a copy, gone
    assert done[0] == "binary: v0.107.79 -> v0.107.80"
    (bak,) = exe.parent.glob("AdGuardHome.bak-*")
    assert "old" in bak.read_text(encoding="utf-8") and list(exe.parent.glob("AdGuardHome.yaml.bak-*"))


@pytest.mark.parametrize(
    ("kw", "message"),
    [
        ({"check": lambda c, b: (False, "unknown field clients.persistent.ids")}, "rejected the live"),
        ({"version": lambda p: (0, 107, 78)}, "below the floor v0.107.79"),
        ({"version": lambda p: None}, "names no version"),
        (
            {"guard": lambda: (_ for _ in ()).throw(adguardcfg.Deferred("deferred: upstream down"))},
            "deferred",
        ),
    ],
)
def test_an_upgrade_refused_before_the_swap_changes_nothing(site, kw, message):
    exe, yml, _ = site
    before = yml.read_text(encoding="utf-8")
    with pytest.raises(RuntimeError, match=message):
        run_upgrade(site, **kw)
    assert "old" in exe.read_text(encoding="utf-8") and yml.read_text(encoding="utf-8") == before
    assert not list(exe.parent.glob("*.bak-*"))


def test_a_check_that_migrates_past_the_ceiling_is_refused(site):
    def migrates(candidate, bin_):
        Path(candidate).write_text(yaml.safe_dump({**BASE, "schema_version": 35}), encoding="utf-8")
        return True, ""

    exe, yml, _ = site
    with pytest.raises(RuntimeError, match="above 34"):
        run_upgrade(site, check=migrates)
    assert (
        "old" in exe.read_text(encoding="utf-8")
        and yaml.safe_load(yml.read_text(encoding="utf-8"))["schema_version"] == 34
    )


@pytest.mark.parametrize(
    ("kw", "message"),
    [
        ({"ready": lambda: False}, "did not answer DNS on the new binary"),
        (
            {"verify": iter([{"tv_paths"}, {"tv_paths", "resolver_must_allow"}]).__next__},
            "resolver_must_allow",
        ),
    ],
)
def test_a_new_binary_that_does_not_hold_is_rolled_back(site, kw, message):
    exe, yml, _ = site
    before = yml.read_text(encoding="utf-8")

    def started_and_migrated(*a):
        calls.append(a)
        if a[0] == "start" and len(calls) == 2:  # the new binary rewrites its YAML at start
            yml.write_text(yaml.safe_dump({**BASE, "schema_version": 34, "migrated": True}), encoding="utf-8")

    calls: list = []
    with pytest.raises(RuntimeError, match=rf"{message}.*were put back"):
        run_upgrade(site, control=started_and_migrated, **kw)
    assert "old" in exe.read_text(encoding="utf-8") and yml.read_text(encoding="utf-8") == before
    assert calls == [("stop", "AdGuardHome"), ("start", "AdGuardHome")] * 2


def test_a_check_that_already_failed_does_not_block_the_upgrade(site):
    exe, _, _ = site
    run_upgrade(site, verify=lambda: {"tv_paths"})  # failing before and after: not the new binary's doing
    assert "new" in exe.read_text(encoding="utf-8")


def test_upgrade_refuses_the_installed_binary_itself(site):
    exe, yml, _ = site
    with pytest.raises(RuntimeError, match="is the installed binary"):
        adguardcfg.upgrade(str(yml), str(exe), binary=str(exe), version=lambda p: (0, 107, 79))


# ---- the --no-check-update drop-in --------------------------------------------------------------

UNIT = """[Unit]
Description=AdGuard Home: Network-level blocker
ConditionFileIsExecutable=/opt/AdGuardHome/AdGuardHome

[Service]
StartLimitInterval=5
StartLimitBurst=10
ExecStart=/opt/AdGuardHome/AdGuardHome "-s" "run"
WorkingDirectory=/opt/AdGuardHome
Restart=always
RestartSec=10

[Install]
WantedBy=multi-user.target
"""


def test_the_drop_in_resets_execstart_and_repeats_it_with_the_flag():
    text = adguardcfg.dropin_text(UNIT)
    lines = text.splitlines()
    assert lines[1:] == [
        "[Service]",
        "ExecStart=",
        'ExecStart=/opt/AdGuardHome/AdGuardHome "-s" "run" --no-check-update',
    ]
    assert adguardcfg.dropin_text(UNIT.replace('"run"', '"run" "--no-check-update"')) is None  # quoted
    assert adguardcfg.dropin_text(UNIT.replace('"run"', '"run" --no-check-update')) is None
    assert adguardcfg.dropin_text(UNIT.replace("ExecStart=", "ExecStart=x\nExecStart=", 1)) is None
    assert adguardcfg.dropin_text("[Service]\nRestart=always\n") is None


@pytest.mark.parametrize(
    "unit",
    [UNIT.replace("ExecStart=", "ExecStart=/bin/true\nExecStart=", 1), "[Service]\nRestart=always\n"],
)
def test_ensure_service_refuses_a_unit_whose_execstart_it_cannot_read(tmp_path, unit):
    """Two ExecStart lines, or none: there is no one command to repeat with the flag, and reporting
    'already runs with' would be a success verify's adguard_pinned contradicts on its next run."""
    fragment, dropin = service_site(tmp_path, unit)
    with pytest.raises(RuntimeError, match=r"cannot read one ExecStart from .*add --no-check-update by hand"):
        adguardcfg.ensure_service(str(fragment), dropin=str(dropin), control=None, lock_dir=str(tmp_path))
    assert not dropin.exists()


def test_a_unit_that_passes_the_flag_itself_needs_no_drop_in(tmp_path):
    fragment, dropin = service_site(tmp_path, UNIT.replace('"run"', '"run" --no-check-update'))
    got = adguardcfg.ensure_service(str(fragment), dropin=str(dropin), control=None, lock_dir=str(tmp_path))
    assert got == "AdGuardHome already runs with --no-check-update" and not dropin.exists()


def service_site(tmp_path, unit=UNIT):
    fragment = tmp_path / "AdGuardHome.service"
    fragment.write_text(unit, encoding="utf-8")
    return fragment, tmp_path / "AdGuardHome.service.d" / "20-tvgw-no-update.conf"


def test_ensure_service_writes_reloads_and_restarts_once(tmp_path):
    fragment, dropin = service_site(tmp_path)
    calls: list = []
    common = dict(
        dropin=str(dropin),
        control=lambda *a: calls.append(a),
        ready=lambda: True,
        effective=lambda: "argv[]=/opt/AdGuardHome/AdGuardHome -s run --no-check-update ;",
        guard=lambda: None,
        lock_dir=str(tmp_path),
        running=lambda: ["/opt/AdGuardHome/AdGuardHome", "-s", "run", "--no-check-update"],
    )
    assert "restarted with --no-check-update" in adguardcfg.ensure_service(str(fragment), **common)
    assert calls == [("daemon-reload",), ("restart", "AdGuardHome")]
    assert dropin.read_text(encoding="utf-8") == adguardcfg.dropin_text(UNIT)
    calls.clear()
    assert adguardcfg.ensure_service(str(fragment), **common).endswith("is in place") and calls == []


def test_a_drop_in_the_running_process_predates_is_restarted_into(tmp_path):
    """The drop-in is right and systemd reloaded, but the restart never happened (killed in between, or
    a drop-in written by hand): the running AdGuard still lacks the flag, so it is restarted once."""
    fragment, dropin = service_site(tmp_path)
    dropin.parent.mkdir()
    dropin.write_text(adguardcfg.dropin_text(UNIT), encoding="utf-8")
    calls: list = []
    got = adguardcfg.ensure_service(
        str(fragment),
        dropin=str(dropin),
        control=lambda *a: calls.append(a),
        ready=lambda: True,
        effective=lambda: "argv[]=/opt/AdGuardHome/AdGuardHome -s run --no-check-update ;",
        guard=lambda: None,
        lock_dir=str(tmp_path),
        running=lambda: ["/opt/AdGuardHome/AdGuardHome", "-s", "run"],
    )
    assert "restarted with" in got and calls == [("daemon-reload",), ("restart", "AdGuardHome")]
    calls.clear()
    stopped = adguardcfg.ensure_service(  # not running: nothing to restart into, and nothing started
        str(fragment),
        dropin=str(dropin),
        control=lambda *a: calls.append(a),
        lock_dir=str(tmp_path),
        running=lambda: None,
    )
    assert stopped.endswith("is in place") and calls == []


def test_ensure_service_waits_for_no_apply_or_upgrade(tmp_path):
    """The hourly re-apply must not stop and start AdGuard while the drop-in's restart is under way."""
    fragment, dropin = service_site(tmp_path)
    held = os.open(tmp_path / ".tvgw-adguard.lock", os.O_RDWR | os.O_CREAT, 0o600)
    try:
        fcntl.flock(held, fcntl.LOCK_EX)
        with pytest.raises(RuntimeError, match="another tvgw adguard apply or upgrade is running"):
            adguardcfg.ensure_service(
                str(fragment), dropin=str(dropin), control=None, guard=lambda: None, lock_dir=str(tmp_path)
            )
    finally:
        os.close(held)
    assert not dropin.exists()


@pytest.mark.parametrize(
    ("kw", "message", "tail"),
    [
        # failed before any restart: AdGuard still runs as it was, so it keeps its cache
        ({"effective": lambda: "argv[]=/opt/AdGuardHome/AdGuardHome -s run ;"}, "does not show", []),
        ({"ready": lambda: False}, "did not answer DNS", [("restart", "AdGuardHome")]),
    ],
)
def test_ensure_service_puts_the_previous_unit_back_on_failure(tmp_path, kw, message, tail):
    fragment, dropin = service_site(tmp_path)
    dropin.parent.mkdir()
    dropin.write_text("[Service]\n# an older drop-in\n", encoding="utf-8")
    calls: list = []
    args = dict(
        dropin=str(dropin),
        control=lambda *a: calls.append(a),
        ready=lambda: True,
        effective=lambda: "--no-check-update",
        guard=lambda: None,
        lock_dir=str(tmp_path),
    )
    args.update(kw)
    with pytest.raises(RuntimeError, match=rf"{message}.*put back"):
        adguardcfg.ensure_service(str(fragment), **args)
    assert dropin.read_text(encoding="utf-8") == "[Service]\n# an older drop-in\n"
    restarts = [("restart", "AdGuardHome")] if tail else []
    assert calls == [("daemon-reload",), *restarts, ("daemon-reload",), *tail]


def test_ensure_service_with_no_previous_drop_in_removes_its_own_on_failure(tmp_path):
    fragment, dropin = service_site(tmp_path)
    with pytest.raises(RuntimeError, match="put back"):
        adguardcfg.ensure_service(
            str(fragment),
            dropin=str(dropin),
            control=lambda *a: None,
            ready=lambda: False,
            effective=lambda: "--no-check-update",
            guard=lambda: None,
            lock_dir=str(tmp_path),
        )
    assert not dropin.exists()


def test_ensure_service_is_deferred_while_the_upstreams_are_down(tmp_path):
    fragment, dropin = service_site(tmp_path)

    def down():
        raise adguardcfg.Deferred("deferred: upstream down")

    with pytest.raises(adguardcfg.Deferred):
        adguardcfg.ensure_service(
            str(fragment), dropin=str(dropin), control=None, guard=down, lock_dir=str(tmp_path)
        )
    assert not dropin.exists()


# ---- verify: the sentinels and the pinned service -----------------------------------------------


def test_the_sentinels_are_those_of_the_subscribed_lists(lg):
    assert verify.sentinels(lg) == [
        "h4g3z1-native-lgwebos.web.app",
        "h4g3z1-doh.web.app",
        "h4g3z1-pro.web.app",
    ]
    assert verify.sentinels(profile.load("roku")) == ["h4g3z1-doh.web.app", "h4g3z1-pro.web.app"]


def test_a_sentinel_that_resolves_means_a_list_is_not_in_force(lg):
    blocked = {n: ["0.0.0.0"] for n in verify.sentinels(lg)}
    ok = verify.sentinel_check(lg, blocked.get)
    assert ok.ok and ok.detail == "3 lists in force"
    emptied = {**blocked, "h4g3z1-pro.web.app": ["198.51.100.7"], "h4g3z1-doh.web.app": None}
    bad = verify.sentinel_check(lg, emptied.get)
    assert not bad.ok
    # (scrub) the printed detail names no address outside TV_NET; the answer stays in `raw`
    assert bad.detail == (
        "list not in force: h4g3z1-doh.web.app->no answer, h4g3z1-pro.web.app->['<lan address>']"
    )
    assert bad.raw.endswith("h4g3z1-pro.web.app->['198.51.100.7']")


def test_the_service_must_run_with_no_check_update():
    assert verify.no_update_check(lambda cmd: "argv[]=/x -s run --no-check-update ;").ok
    off = verify.no_update_check(lambda cmd: "argv[]=/x -s run ;")
    assert not off.ok and "tvgw adguard service" in off.detail
    assert not verify.no_update_check(lambda cmd: "").ok


def test_the_running_process_must_carry_the_flag_too():
    """A drop-in reloaded but never restarted into: systemd shows the flag, the process lacks it."""
    shows = {"ExecStart": "argv[]=/x -s run --no-check-update ;", "MainPID": "812\n"}

    def run(cmd):
        return shows[cmd[3]]

    old = verify.no_update_check(run, {"/proc/812/cmdline": "/x\0-s\0run\0"}.get)
    assert not old.ok and "pid 812" in old.detail and "tvgw adguard service" in old.detail
    assert verify.no_update_check(run, {"/proc/812/cmdline": "/x\0-s\0run\0--no-check-update\0"}.get).ok
    assert verify.no_update_check(run, lambda path: "").ok  # /proc unreadable: the ExecStart decides
    shows["MainPID"] = "0\n"  # not running: the services check reports that
    assert verify.no_update_check(run, lambda path: "/x\0").ok


def test_the_floor_is_the_one_the_report_set():
    assert verify.ADGUARD_MIN == (0, 107, 79) and adguardcfg.SCHEMA_CEILING == 34


# ---- the command line and the installer ---------------------------------------------------------


@pytest.fixture()
def conf_with(gateway, tmp_path, monkeypatch):
    real_load = cli.config.load
    monkeypatch.setattr(
        cli.config, "load", lambda path, **kw: real_load(path, adguard_yaml=gateway.adguard_yaml, **kw)
    )
    return ["--conf", str(tmp_path / "none.conf")]


def test_a_deferred_apply_exits_3_and_says_so(conf_with, monkeypatch, capsys):
    def deferred(*a, **kw):
        raise adguardcfg.Deferred("deferred: upstream down (test)")

    monkeypatch.setattr(adguardcfg, "apply", deferred)
    assert cli.main([*conf_with, "adguard", "apply"]) == cli.DEFERRED_EXIT == 3
    assert "tvgw adguard: deferred: upstream down" in capsys.readouterr().err


def test_apply_refuses_a_newer_schema_from_the_command_line(conf_with, gateway, capsys):
    text = Path(gateway.adguard_yaml).read_text(encoding="utf-8")
    Path(gateway.adguard_yaml).write_text(text + "schema_version: 35\n", encoding="utf-8")
    with pytest.raises(SystemExit, match="schema_version 35, above 34"):
        cli.main([*conf_with, "adguard", "apply"])
    assert cli.main([*conf_with, "adguard", "diff"]) == 1  # diff still reports, with a warning
    assert "warning: " in capsys.readouterr().err
    assert cli.main([*conf_with, "adguard", "apply", "--dry-run"]) == 0  # changes nothing: warns too
    assert "warning: " in capsys.readouterr().err


def test_upgrade_needs_its_binary_and_diff_takes_none(conf_with, capsys):
    assert cli.main([*conf_with, "adguard", "upgrade"]) == 2
    assert cli.main([*conf_with, "adguard", "diff", "/tmp/AdGuardHome"]) == 2
    assert cli.main([*conf_with, "adguard", "service", "/tmp/AdGuardHome"]) == 2
    err = capsys.readouterr().err
    assert err.count("tvgw adguard: error: ") == 3 and "tvgw report" not in err


def test_install_sets_the_service_up_before_the_apply_and_survives_a_deferral():
    text = (ROOT / "deploy" / "install.sh").read_text(encoding="utf-8")
    service, apply_ = (
        text.index("tvgw adguard service || agh_rc=$?"),
        text.index("tvgw adguard apply || agh_rc=$?"),
    )
    assert text.index("workdir.conf") < service < apply_
    tail = text[apply_ : apply_ + 400]
    assert "3) echo" in tail and '*) die "tvgw adguard apply failed' in tail
