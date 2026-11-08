"""(depth) verify's checks of the gateway's blind spots, and the must-allow names asked twice.

Every new check is a WARN at most while it is new, whatever it finds (FAIL_AFTER, PROMOTED), so the
reference gateway cannot gain a red line from one; each is tested at each of its levels through fakes of
statvfs, the store's meta values, the commands and the files. forward_policy and input_policy read `nft -j
list ruleset` listings shaped as iptables-nft prints ufw's and Docker's chains. No detail of any of them
carries an address, a MAC or a host name.
"""

import dataclasses
import json
import os
import re

import pytest
from conftest import NOW, ROOT
from test_verify import INPATH_TABLE, ROUTER, S, gateway, resolver, vfs

from tvgw import backup, health, inpath, probe, verify

NEW = (
    "disk",
    "clock_synced",
    "store_backup",
    "ingest_fresh",
    "uplink_ipv4",
    "wan_gateway",
    "forward_policy",
    "input_policy",
    "tv_port_neighbours",
    "dnsgate_inpath",  # (inpath) design decision 64
    "tv_probe",  # (probe) the test from the TV's position: its own tests are in test_probe.py
    "gateway_health",  # (reliability) design decision 73: its own tests are in test_health.py
    "quic_fallback",  # (reliability) its own tests are in test_quic_fallback.py
    "iptables_legacy",  # (reliability) a legacy table: below
    "names_tap",  # (namebound) design decision 70: a WARN at most, always; its own tests are in test_nametap.py
)
TV_MAC = "00:00:5e:00:53:17"  # documentation MACs (RFC 7042)
OTHER_MAC = "00:00:5e:00:53:99"


def failed_probe() -> probe.Verdict:
    """(probe) The worst the probe can say, as the recorded run of a gateway with TV_PROBE=on gets it."""
    why = "a must-allow connection fails from the TV's position and works from the gateway itself"
    return probe.Verdict(probe.FAIL, [probe.Stage("allowed", probe.FAIL, why)])


def run_checks(lg, s=S, **host):
    found = verify.check(s, lg, **gateway(**host), resolve=resolver(), probe=failed_probe)
    return {c.name: c for c in found.checks}


def one(name, lg, s=S, **host) -> verify.Check:
    return run_checks(lg, s, **host)[name]


def level(c: verify.Check) -> str:
    """The level a check's finding has, held or not."""
    if not c.ok:
        return "fail"
    if c.warn:
        return "fail" if c.detail.endswith(verify.HELD) else "warn"
    return "ok"


# ---- the promotion rule ---------------------------------------------------------------------------------
def test_every_new_check_names_the_level_it_is_promoted_to_and_none_is_promoted_yet():
    assert tuple(verify.FAIL_AFTER) == NEW
    assert set(verify.FAIL_AFTER.values()) <= {verify.WARN, verify.FAIL}
    assert verify.FAIL_AFTER["tv_port_neighbours"] == verify.WARN  # never more (design 4.6)
    assert set(verify.FAIL_AFTER) >= verify.PROMOTED


def test_each_promotion_is_listed_in_the_changelog():
    """A promotion is one change per check, after 7 days of OK on the reference, and says so."""
    log = (ROOT / "CHANGELOG.md").read_text(encoding="utf-8")
    for name in verify.PROMOTED:
        assert f"`{name}` promoted" in log, name


def test_held_findings_warn_until_promoted_and_fail_after(monkeypatch):
    assert verify.held("disk", verify.OK, "fine") == (True, "fine", False)
    assert verify.held("disk", verify.WARN, "low") == (True, "low", True)
    assert verify.held("disk", verify.FAIL, "full") == (True, "full" + verify.HELD, True)
    monkeypatch.setattr(verify, "PROMOTED", frozenset({"disk", "tv_port_neighbours"}))
    assert verify.held("disk", verify.FAIL, "full") == (False, "full", False)
    # a WARN-only check stays a warning, promoted or not
    assert verify.held("tv_port_neighbours", verify.FAIL, "x") == (True, "x", True)


def broken_host():
    """A gateway where every new check finds the worst it can, with RFC 5737 addresses, documentation MACs
    and a host name planted in everything those checks read."""
    ufw = ruleset(UFW_PLAIN)
    return {
        "overrides": {
            ("timedatectl", "show", "-p", "NTPSynchronized", "--value"): "no\n",
            ("ip", "-j", "-4", "addr", "show", "dev", "wlan0"): json.dumps(
                [
                    {
                        "ifname": "wlan0",
                        "addr_info": [{"family": "inet6", "local": "2001:db8::2", "scope": "global"}],
                    }
                ]
            ),
            ("ip", "-j", "route", "show", "table", "100", "default"): "[]",
            ("nft", "-j", "list", "ruleset"): ufw,
            # (inpath) the in-path rules loaded, and a queue the kernel dropped answers from
            ("nft", "list", "table", "inet", "tvgw_gate"): INPATH_TABLE,
            ("ip", "-j", "neigh", "show", "dev", "eth0"): json.dumps(
                [
                    {"dst": "10.10.10.17", "lladdr": TV_MAC, "state": ["REACHABLE"]},
                    {"dst": "192.0.2.77", "lladdr": OTHER_MAC, "state": ["STALE"]},
                ]
            ),
        },
        "files": {
            "/proc/net/ip_tables_names": "filter\nnat\n",  # (reliability) a legacy iptables user
            "/etc/hostname": "gateway-under-test\n",
            inpath.PROC_QUEUES: f"{inpath.QUEUE}   4242     0 2 65531     3     0     1234  1\n",
        },
        "free": vfs(100 * 2**20),
        # (reliability) a name that never fell back to TCP
        "quic_view": {
            "attempts": 4,
            "fell_back": 0,
            "names": [{"name": "moq.example", "attempts": 4, "fell_back": 0}],
            "never": [{"name": "moq.example", "attempts": 4, "fell_back": 0}],
        },
        # (reliability) the firmware slowed it and the card logged errors
        "health_view": health.Summary(
            samples=144, findings=["the firmware slowed the gateway: under-voltage"], throttle_known=True
        ),
        "meta": {
            "last_run": str(NOW - 3 * 86400),
            "backup_ok_t": str(NOW - 9 * 86400),
            "backup_error": json.dumps({"t": NOW - 3600, "why": backup.CHECK_FAILED}),
        },
    }


def test_whatever_they_find_the_new_checks_never_fail_a_run_and_carry_no_identifier(lg):
    # (inpath) with DNSGATE_FILL=inpath, so the in-path filler's check has something to find; (namebound)
    # and NAME_BINDING=count, so the live name count's has too
    s = dataclasses.replace(S, tv_mac=TV_MAC, dnsgate_fill="inpath", name_binding="count")
    checks = run_checks(lg, s, **broken_host())
    for name in NEW:
        c = checks[name]
        assert c.ok and c.warn, c.line()
        for planted in ("192.0.2", "198.51.100", "2001:db8", "00:00:5e", "gateway-under-test", ROUTER):
            assert planted not in c.detail, c.line()
    held = [n for n in NEW if checks[n].detail.endswith(verify.HELD)]
    assert held == [n for n in NEW if verify.FAIL_AFTER[n] == verify.FAIL]


# ---- disk -----------------------------------------------------------------------------------------------
def test_disk_reports_the_free_space_where_the_record_is_kept(lg):
    assert one("disk", lg).line() == "OK   disk: 50.0 GiB free where the record is kept"
    low = one("disk", lg, free=vfs(1536 * 2**20))
    assert level(low) == "warn" and low.detail == "1.5 GiB free where the record is kept, under 2.0 GiB"
    full = one("disk", lg, free=vfs(300 * 2**20))
    assert level(full) == "fail"
    assert full.detail == "300 MiB free where the record is kept, under 512 MiB" + verify.HELD
    ro = one("disk", lg, free=vfs(40 * 2**30, flag=os.ST_RDONLY))
    assert level(ro) == "fail" and ro.detail.startswith(
        "the filesystem where the record is kept is read-only"
    )


def test_disk_never_names_the_state_directory(lg):
    """STATE_DIR is the owner's to choose, and a path can carry a name: the detail says where in words."""
    s = dataclasses.replace(S, state_dir="/srv/gateway-under-test/tvgw")
    seen = []

    def statvfs(path):
        seen.append(path)
        return vfs(300 * 2**20)

    host = gateway()
    host["statvfs"] = statvfs
    c = next(c for c in verify.check(s, lg, **host, resolve=resolver()).checks if c.name == "disk")
    assert seen == ["/srv/gateway-under-test/tvgw"]
    assert "gateway-under-test" not in c.detail and "/srv" not in c.detail, c.line()


def test_disk_says_when_it_cannot_read_the_free_space(lg):
    def missing(path):
        raise FileNotFoundError(2, "No such file or directory", path)

    host = gateway()
    host["statvfs"] = missing
    c = next(c for c in verify.check(S, lg, **host, resolve=resolver()).checks if c.name == "disk")
    assert (
        level(c) == "warn"
        and c.detail == "cannot read the free space where the record is kept: No such file or directory"
    )


# ---- the clock --------------------------------------------------------------------------------------------
@pytest.mark.parametrize(
    ("said", "want"),
    [("yes\n", "ok"), ("no\n", "fail"), ("", "warn"), ("garbage\n", "warn")],
)
def test_clock_synced_is_systemds_word(lg, said, want):
    c = one("clock_synced", lg, overrides={("timedatectl", "show", "-p", "NTPSynchronized", "--value"): said})
    assert level(c) == want, c.line()


# ---- the store's backup and ingest ---------------------------------------------------------------------------
def test_store_backup_reads_the_outcome_backup_recorded(lg):
    assert one("store_backup", lg).line() == "OK   store_backup: the newest backup is 6 hours old"
    old = one("store_backup", lg, meta={"backup_ok_t": str(NOW - 3 * 86400)})
    assert level(old) == "warn" and old.detail == "the newest backup is 3.0 days old"
    installed = {verify.FIRST_CHECK: str(NOW - 30 * 86400)}
    none = one("store_backup", lg, meta=installed)
    assert level(none) == "warn" and none.detail == "no backup recorded yet"
    assert one("store_backup", lg, meta="unreadable").detail == "the store could not be read"
    for why, want in (
        (backup.NO_SPACE, "warn"),
        (backup.WRITE_FAILED, "warn"),
        (backup.CHECK_FAILED, "fail"),
    ):
        err = json.dumps({"t": NOW - 1800, "why": why})
        c = one("store_backup", lg, meta={"backup_ok_t": str(NOW - 86400), "backup_error": err})
        assert level(c) == want and c.detail.startswith(f"the last backup, 30 minutes ago, failed: {why}")
    # a failure older than the last good copy is history, and an unknown reason is not repeated
    older = json.dumps({"t": NOW - 7200, "why": backup.CHECK_FAILED})
    assert one("store_backup", lg, meta={"backup_ok_t": str(NOW - 600), "backup_error": older}).ok
    odd = json.dumps({"t": NOW - 60, "why": "/var/lib/tvgw/backup: disk I/O error at 192.0.2.4"})
    c = one("store_backup", lg, meta={"backup_error": odd})
    assert c.detail == "the last backup, 1 minutes ago, failed: it failed"


def test_store_backup_counts_the_copies_made_before_outcomes_were_recorded(lg):
    """A gateway upgraded to this version has checked copies in its backup directory and no backup_ok_t
    until its next daily run: the newest copy's name dates it, so the check is OK from the first run."""
    installed = {verify.FIRST_CHECK: str(NOW - 30 * 86400)}
    copy = one("store_backup", lg, meta={**installed, verify.NEWEST_COPY: str(NOW - 5 * 3600)})
    assert copy.line() == "OK   store_backup: the newest backup is 5 hours old"
    # the newer of the recorded copy and the newest one on disk
    both = {"backup_ok_t": str(NOW - 3 * 86400), verify.NEWEST_COPY: str(NOW - 3600)}
    assert one("store_backup", lg, meta={**installed, **both}).detail == "the newest backup is 60 minutes old"
    # a failure after the newest copy on disk is still the last word
    err = json.dumps({"t": NOW - 600, "why": backup.NO_SPACE})
    failed = one(
        "store_backup", lg, meta={**installed, verify.NEWEST_COPY: str(NOW - 3600), "backup_error": err}
    )
    assert level(failed) == "warn" and failed.detail.startswith("the last backup, 10 minutes ago, failed")


def test_a_new_gateway_has_no_backup_and_no_ingest_due_yet(lg):
    """Just installed, before any daily copy or hourly ingest was due, there is nothing to warn about:
    the install is dated by the store's first recorded check, or, before there is one, by the settings
    file setup has just written."""
    fresh = {verify.FIRST_CHECK: str(NOW - 1200)}
    c = one("store_backup", lg, meta=fresh)
    assert c.line() == "OK   store_backup: no backup yet; none was due in the 20 minutes since the install"
    c = one("ingest_fresh", lg, meta=fresh)
    assert (
        c.line()
        == "OK   ingest_fresh: no ingest has run yet; none was due in the 20 minutes since the install"
    )
    # no store yet: the settings file's change dates the install (an hour ago in the fake gateway)
    assert one("store_backup", lg, meta={}).ok and not one("store_backup", lg, meta={}).warn
    assert one("ingest_fresh", lg, meta={}).detail.endswith(
        "none was due in the 60 minutes since the install"
    )
    # nothing dates it: the old words, a warning
    undated = one("ingest_fresh", lg, meta={}, mtimes={verify.CONF: None})
    assert level(undated) == "warn" and undated.detail == "no ingest has run yet"
    assert level(one("store_backup", lg, meta={}, mtimes={verify.CONF: None})) == "warn"
    # a copy is due within BACKUP_MAX_AGE of the install, and is a warning after it
    late = one("store_backup", lg, meta={verify.FIRST_CHECK: str(NOW - 3 * 86400)})
    assert level(late) == "warn" and late.detail == "no backup recorded yet"


def test_a_first_check_as_old_as_the_stores_retention_dates_nothing(lg):
    """The hourly ingest prunes checks older than DB_DAYS, so on a gateway that keeps one day the first
    check left is always about a day old: it says the gateway is at least that old, not that it is new."""
    short = dataclasses.replace(S, db_days=1)
    pruned = {verify.FIRST_CHECK: str(NOW - 86400 + 600)}
    assert level(one("store_backup", lg, short, meta=pruned)) == "warn"
    assert one("ingest_fresh", lg, short, meta=pruned).detail == "no ingest has run yet"
    # the same first check on a gateway that keeps a year is a gateway installed a day ago
    assert one("store_backup", lg, meta=pruned).ok and not one("store_backup", lg, meta=pruned).warn
    assert verify.installed_at({verify.FIRST_CHECK: "100.0"}, 50.0, 200.0, 1) == 100.0
    assert verify.installed_at({}, 50.0, 200.0, 1) == 50.0
    assert verify.installed_at(None, None, 200.0, 1) is None


def test_a_first_ingest_that_never_comes_is_a_stopped_ingest(lg):
    meta = {verify.FIRST_CHECK: str(NOW - 3 * 3600)}
    late = one("ingest_fresh", lg, meta=meta)
    assert level(late) == "warn" and late.detail == "no ingest has run in the 3 hours since the install"
    never = one("ingest_fresh", lg, meta={verify.FIRST_CHECK: str(NOW - 13 * 3600)})
    assert level(never) == "fail" and never.detail.startswith("no ingest has run in the 13 hours")
    # the first check is a better date than the settings file, which a later edit makes new
    edited = one("ingest_fresh", lg, meta=meta, mtimes={verify.CONF: NOW - 60})
    assert level(edited) == "warn"
    # just booted: the Persistent timer has its hour to catch up, as for a stopped ingest
    booted = one(
        "ingest_fresh",
        lg,
        meta={verify.FIRST_CHECK: str(NOW - 13 * 3600)},
        files={"/proc/uptime": "600.0 1.0\n"},
    )
    assert level(booted) == "warn"


def test_ingest_fresh_waits_out_a_power_cut_before_it_is_of_fail_level(lg):
    assert one("ingest_fresh", lg).line() == "OK   ingest_fresh: the last ingest ran 10 minutes ago"
    late = one("ingest_fresh", lg, meta={"last_run": str(NOW - 3 * 3600)})
    assert level(late) == "warn" and late.detail == "the last ingest ran 3 hours ago"
    stopped = one("ingest_fresh", lg, meta={"last_run": str(NOW - 13 * 3600)})
    assert level(stopped) == "fail"
    # just booted after a night off: the timer is Persistent and catches up within the hour
    booted = one(
        "ingest_fresh", lg, meta={"last_run": str(NOW - 13 * 3600)}, files={"/proc/uptime": "600.0 1.0\n"}
    )
    assert level(booted) == "warn"
    undated = {"mtimes": {verify.CONF: None}}
    assert one("ingest_fresh", lg, meta={}, **undated).detail == "no ingest has run yet"
    assert (
        one("ingest_fresh", lg, meta={"last_run": "not a time"}, **undated).detail == "no ingest has run yet"
    )


def test_store_meta_reads_the_store_read_only_and_never_raises(tmp_path):
    from tvgw import db

    path = tmp_path / "tvgw.db"
    assert verify.store_meta(str(path)) == {}  # no store yet: an empty record, and none is created
    assert not path.exists()
    conn = db.connect(str(path))
    db.set_meta(conn, "last_run", "1793026000.0")
    db.set_meta(conn, "schema", "9")
    conn.commit()
    # (reliability) the recorded version comes too, for store_version
    assert verify.store_meta(str(path)) == {"last_run": "1793026000.0", "schema": "9"}
    for t in (1793020000.5, 1793010000.25, 1793030000.0):
        conn.execute("INSERT INTO verify(t, ok, failures) VALUES (?, 1, '[]')", (t,))
    conn.commit()
    conn.close()
    assert verify.store_meta(str(path)) == {
        "last_run": "1793026000.0",
        "schema": "9",
        verify.FIRST_CHECK: "1793010000.25",
    }
    # the newest named copy in the backup directory; a temporary file is not a copy
    copies = tmp_path / "backup"
    copies.mkdir()
    for name in ("tvgw-20261101T094000Z.db", "tvgw-20261103T094000Z.db", ".tvgw-20261104T094000Z.db.tmp"):
        (copies / name).write_bytes(b"")
    got = verify.store_meta(str(path), backup_dir=str(copies))
    assert got[verify.NEWEST_COPY] == repr(1793698800.0)  # 2026-11-03 09:40 UTC
    assert verify.store_meta(str(path), backup_dir=str(tmp_path / "none")) == verify.store_meta(str(path))
    # there but not a store: unreadable, never an exception
    bad = tmp_path / "bad.db"
    bad.write_bytes(b"not a database, not even close" * 100)
    assert verify.store_meta(str(bad)) is None


# ---- the uplink and the router ---------------------------------------------------------------------------------
def test_uplink_ipv4_needs_a_global_ipv4_address(lg):
    assert one("uplink_ipv4", lg).line() == "OK   uplink_ipv4: wlan0 has an IPv4 address"
    cmd = ("ip", "-j", "-4", "addr", "show", "dev", "wlan0")
    linklocal = [{"addr_info": [{"family": "inet", "local": "169.254.3.4", "scope": "global"}]}]
    for out in ("", "[]", json.dumps(linklocal), "not json"):
        c = one("uplink_ipv4", lg, overrides={cmd: out})
        assert level(c) == "fail" and c.detail.startswith("wlan0 has no IPv4 address"), out
    gone = one("uplink_ipv4", lg, files={"/proc/sys/net/ipv4/conf/wlan0/forwarding": ""})
    assert gone.detail.startswith("wlan0 does not exist")


def test_wan_gateway_checks_table_100_and_the_literal_router(lg):
    assert one("wan_gateway", lg).line() == "OK   wan_gateway: table 100 routes the TV out by wlan0"
    table = ("ip", "-j", "route", "show", "table", "100", "default")
    empty = one("wan_gateway", lg, overrides={table: "[]"})
    assert level(empty) == "fail" and empty.detail.startswith(
        "table 100 has no default route while wlan0 is up"
    )
    # no carrier: the dispatcher restores the route when it comes back, and uplink_ipv4 says the rest
    down = one("wan_gateway", lg, overrides={table: "[]"}, files={"/sys/class/net/wlan0/carrier": "0\n"})
    assert down.ok and not down.warn
    moved = json.dumps([{"dst": "default", "gateway": "198.51.100.254", "dev": "wlan0"}])
    main = ("ip", "-j", "route", "show", "default", "dev", "wlan0")
    c = one("wan_gateway", lg, overrides={main: moved})
    assert level(c) == "warn" and c.detail.startswith(
        "WAN_GW is not the router wlan0's own default route uses"
    )
    unset = one("wan_gateway", lg, files={verify.CONF: "WAN_IF=wlan0\n"})
    assert level(unset) == "warn" and unset.detail == "WAN_GW is not set in tvgw.conf"
    # no default in the main table by the uplink (a VPN client's routes): nothing to compare with
    assert one("wan_gateway", lg, overrides={main: "[]"}).ok
    # with WAN_GW_MODE=auto the literal is not the router tvgw-apply uses, so it is not compared
    auto = dataclasses.replace(S, wan_gw_mode="auto")
    assert not one("wan_gateway", lg, auto, overrides={main: moved}).warn
    # a settings file the shell would refuse is applied_current's to report
    assert (
        one("wan_gateway", lg, files={verify.CONF: "WAN_GW=two words\n"}).detail
        == "WAN_GW is not set in tvgw.conf"
    )


def test_wan_gateway_runs_only_where_table_100_carries_the_tv(lg):
    vpn = dataclasses.replace(S, uplink="vpn")
    assert "wan_gateway" not in run_checks(lg, vpn)


# ---- other devices on the TV's port -------------------------------------------------------------------------
def test_tv_port_neighbours_counts_other_devices_and_never_names_one(lg):
    s = dataclasses.replace(S, tv_mac=TV_MAC.upper())  # the settings may carry it in capitals
    assert (
        one("tv_port_neighbours", lg, s).line()
        == "OK   tv_port_neighbours: only the TV answered on the TV's port"
    )
    cmd = ("ip", "-j", "neigh", "show", "dev", "eth0")
    entries = [
        {"dst": "10.10.10.17", "lladdr": TV_MAC, "state": ["REACHABLE"]},
        {"dst": "10.10.10.42", "lladdr": OTHER_MAC, "state": ["STALE"]},
        {"dst": "10.10.10.43", "lladdr": "00:00:5e:00:53:98", "state": "DELAY"},
        {"dst": "10.10.10.44", "lladdr": "00:00:5e:00:53:97", "state": ["FAILED"]},  # never answered
        {"dst": "10.10.10.45", "state": ["INCOMPLETE"]},
        {"dst": "10.10.10.46", "lladdr": OTHER_MAC, "state": ["REACHABLE"]},  # the same device again
    ]
    c = one("tv_port_neighbours", lg, s, overrides={cmd: json.dumps(entries)})
    assert level(c) == "warn" and c.detail == "2 other devices answered on the TV's port"
    one_other = one("tv_port_neighbours", lg, s, overrides={cmd: json.dumps(entries[:2])})
    assert one_other.detail == "1 other device answered on the TV's port"
    for mac in ("", "00:00:00:00:00:00"):  # not identified yet: nothing to tell the TV from
        c = one(
            "tv_port_neighbours", lg, dataclasses.replace(S, tv_mac=mac), overrides={cmd: json.dumps(entries)}
        )
        assert c.ok and not c.warn and c.detail.endswith("not checked")


# ---- other firewalls: forward_policy and input_policy -------------------------------------------------------------
def chain(family, table, name, hook=None, policy=None):
    c = {"family": family, "table": table, "name": name, "handle": 1}
    if hook:
        c.update({"type": "filter", "hook": hook, "prio": 0, "policy": policy})
    return {"chain": c}


def rule(family, table, name, *expr):
    return {"rule": {"family": family, "table": table, "chain": name, "handle": 2, "expr": list(expr)}}


def iif(name, op="=="):
    return {"match": {"op": op, "left": {"meta": {"key": "iifname"}}, "right": name}}


def oif(name, op="=="):
    return {"match": {"op": op, "left": {"meta": {"key": "oifname"}}, "right": name}}


def l4(proto):
    return {"match": {"op": "==", "left": {"meta": {"key": "l4proto"}}, "right": proto}}


def dport(proto, ports):
    right = {"set": ports} if isinstance(ports, list) else ports
    return {"match": {"op": "==", "left": {"payload": {"protocol": proto, "field": "dport"}}, "right": right}}


def sport(proto, port):
    return {"match": {"op": "==", "left": {"payload": {"protocol": proto, "field": "sport"}}, "right": port}}


def daddr(addr):
    return {"match": {"op": "==", "left": {"payload": {"protocol": "ip", "field": "daddr"}}, "right": addr}}


def ctstate(*states):
    return {"match": {"op": "in", "left": {"ct": {"key": "state"}}, "right": list(states)}}


def local_daddr():
    return {"match": {"op": "==", "left": {"fib": {"result": "type", "flags": ["daddr"]}}, "right": "local"}}


COUNTER = {"counter": {"packets": 0, "bytes": 0}}
ACCEPT, DROP, RETURN = {"accept": None}, {"drop": None}, {"return": None}


def jump(target):
    return {"jump": {"target": target}}


def ruleset(*parts) -> str:
    """An `nft -j list ruleset` listing: tvgw's own tables first, which the checks leave out (inet tvgw's
    forward and input chains drop by default), then the parts given."""
    ours = [
        chain("inet", "tvgw", "forward", "forward", "drop"),
        chain("inet", "tvgw", "input", "input", "drop"),
        chain("inet", "tvgw_guard", "input", "input", "accept"),
    ]
    return json.dumps(
        {"nftables": [{"metainfo": {"version": "1.1.3"}}, *ours, *[x for p in parts for x in p]]}
    )


def ip(name, *expr):
    return rule("ip", "filter", name, *expr)


# ufw as iptables-nft lists it after `ufw enable` on a computer with nothing allowed, in its own order
UFW_BASE = [
    chain("ip", "filter", "INPUT", "input", "drop"),
    chain("ip", "filter", "FORWARD", "forward", "drop"),
    chain("ip", "filter", "OUTPUT", "output", "accept"),
    *(
        chain("ip", "filter", n)
        for n in (
            "ufw-before-input",
            "ufw-before-forward",
            "ufw-not-local",
            "ufw-user-input",
            "ufw-user-forward",
            "ufw-after-input",
            "ufw-after-forward",
            "ufw-skip-to-policy-input",
            "ufw-reject-input",
            "ufw-reject-forward",
        )
    ),
    ip("INPUT", jump("ufw-before-input")),
    ip("INPUT", jump("ufw-after-input")),
    ip("INPUT", jump("ufw-reject-input")),
    ip("FORWARD", jump("ufw-before-forward")),
    ip("FORWARD", jump("ufw-after-forward")),
    ip("FORWARD", jump("ufw-reject-forward")),
    ip("ufw-before-input", iif("lo"), COUNTER, ACCEPT),
    ip("ufw-before-input", ctstate("established", "related"), COUNTER, ACCEPT),
    ip("ufw-before-input", ctstate("invalid"), COUNTER, DROP),
    ip("ufw-before-input", l4("udp"), sport("udp", 67), dport("udp", 68), COUNTER, ACCEPT),  # its own DHCP
    ip("ufw-before-input", jump("ufw-not-local")),
    ip("ufw-before-input", l4("udp"), daddr("224.0.0.251"), dport("udp", 5353), COUNTER, ACCEPT),
    ip("ufw-before-input", jump("ufw-user-input")),
    ip("ufw-not-local", local_daddr(), COUNTER, RETURN),
    ip("ufw-not-local", COUNTER, DROP),
    ip("ufw-before-forward", ctstate("established", "related"), COUNTER, ACCEPT),
    ip("ufw-before-forward", jump("ufw-user-forward")),
    ip("ufw-after-input", l4("udp"), dport("udp", 137), COUNTER, jump("ufw-skip-to-policy-input")),
    ip("ufw-after-input", l4("udp"), dport("udp", 67), COUNTER, jump("ufw-skip-to-policy-input")),
    ip("ufw-skip-to-policy-input", COUNTER, DROP),
]
UFW_PLAIN = UFW_BASE
# the five commands setup runs on a yes (design 4.14), as ufw writes them into its user chains
UFW_OPENED = [
    *UFW_BASE,
    ip("ufw-user-input", iif("eth0"), l4("udp"), dport("udp", 67), COUNTER, ACCEPT),
    ip("ufw-user-input", iif("eth0"), l4("udp"), daddr("10.10.10.1"), dport("udp", 53), COUNTER, ACCEPT),
    ip("ufw-user-input", iif("eth0"), l4("tcp"), daddr("10.10.10.1"), dport("tcp", 53), COUNTER, ACCEPT),
    ip(
        "ufw-user-input",
        iif("eth0"),
        l4("tcp"),
        daddr("10.10.10.1"),
        dport("tcp", [80, 443]),
        COUNTER,
        ACCEPT,
    ),
    ip("ufw-user-forward", iif("eth0"), oif("wlan0"), COUNTER, ACCEPT),
]
# Docker's own chains: FORWARD drops by default and accepts only its bridges
DOCKER = [
    chain("ip", "filter", "FORWARD", "forward", "drop"),
    *(chain("ip", "filter", n) for n in ("DOCKER-USER", "DOCKER-FORWARD", "DOCKER")),
    ip("FORWARD", jump("DOCKER-USER")),
    ip("FORWARD", jump("DOCKER-FORWARD")),
    ip("DOCKER-USER", COUNTER, RETURN),
    ip("DOCKER-FORWARD", oif("docker0"), ctstate("established", "related"), COUNTER, ACCEPT),
    ip("DOCKER-FORWARD", oif("docker0"), jump("DOCKER")),
    ip("DOCKER-FORWARD", iif("docker0"), COUNTER, ACCEPT),
]
# with ip-forward-no-drop Docker leaves FORWARD's policy at accept
DOCKER_NO_DROP = [chain("ip", "filter", "FORWARD", "forward", "accept"), *DOCKER[1:]]
# an nftables-native firewall that sends the TV's port to a chain of its own
NATIVE = [
    chain("inet", "filter", "forward", "forward", "drop"),
    chain("inet", "filter", "input", "input", "drop"),
    chain("inet", "filter", "from_tv"),
    rule("inet", "filter", "forward", ctstate("established", "related"), ACCEPT),
    rule("inet", "filter", "forward", iif("eth0"), jump("from_tv")),
    rule("inet", "filter", "input", iif("eth0"), jump("from_tv")),
    rule("inet", "filter", "from_tv", COUNTER, ACCEPT),
]


def policy(doc: str, which: str = "forward") -> tuple[str, str]:
    fn = verify.forward_policy_level if which == "forward" else verify.input_policy_level
    return fn(json.loads(doc), "eth0")


def test_plain_ufw_stops_the_tv_at_both_hooks():
    assert policy(ruleset(UFW_PLAIN)) == (
        verify.FAIL,
        "1 other forward-hook chain drops by default; 1 of them accepts nothing from the TV's port",
    )
    assert policy(ruleset(UFW_PLAIN), "input") == (
        verify.FAIL,
        "1 other input-hook chain drops by default; the TV's DHCP (UDP 67), DNS (UDP 53), DNS (TCP 53)"
        " is not accepted",
    )


def test_ufw_after_setups_commands_lets_the_tv_through_and_says_so():
    assert policy(ruleset(UFW_OPENED)) == (
        verify.WARN,
        "1 other forward-hook chain drops by default; it accepts the TV's port",
    )
    assert policy(ruleset(UFW_OPENED), "input") == (
        verify.WARN,
        "1 other input-hook chain drops by default; it accepts the TV's DHCP and DNS",
    )


def test_one_missing_port_is_named():
    no_tcp_dns = [x for x in UFW_OPENED if "53" not in json.dumps(x) or '"udp"' in json.dumps(x)]
    level_, detail = policy(ruleset(no_tcp_dns), "input")
    assert level_ == verify.FAIL and detail.endswith("the TV's DNS (TCP 53) is not accepted")


def test_dockers_forward_drop_stops_the_tv_and_ip_forward_no_drop_does_not():
    assert policy(ruleset(DOCKER))[0] == verify.FAIL
    assert policy(ruleset(DOCKER_NO_DROP)) == (verify.OK, "no other forward-hook chain drops by default")
    assert policy(ruleset(DOCKER_NO_DROP), "input") == (
        verify.OK,
        "no other input-hook chain drops by default",
    )


def test_a_chain_reached_by_jump_counts_and_tvgws_own_tables_do_not():
    assert policy(ruleset(NATIVE))[0] == verify.WARN
    assert policy(ruleset(NATIVE), "input")[0] == verify.WARN
    assert policy(ruleset())[0] == verify.OK  # inet tvgw drops by default and is tvgw's own
    two = [*NATIVE, *UFW_PLAIN]
    assert policy(ruleset(two)) == (
        verify.FAIL,
        "2 other forward-hook chains drop by default; 1 of them accepts nothing from the TV's port",
    )


def test_conditions_the_evaluation_cannot_read_prove_nothing_off_the_tvs_port():
    """A connection-state accept or another port's accept is not the TV's; a drop for every packet ends
    the path before a later accept; an accept for every packet is one; a goto's chain returns past it."""
    base = [chain("ip", "t", "fwd", "forward", "drop"), chain("ip", "t", "sub")]

    def fwd(*rules):
        return policy(ruleset([*base, *rules]))[0]

    assert fwd(rule("ip", "t", "fwd", ctstate("established"), ACCEPT)) == verify.FAIL
    assert fwd(rule("ip", "t", "fwd", iif("wlan0"), ACCEPT)) == verify.FAIL
    assert fwd(rule("ip", "t", "fwd", iif("eth0", "!="), ACCEPT)) == verify.FAIL
    assert fwd(rule("ip", "t", "fwd", iif("eth*"), ACCEPT)) == verify.WARN  # a wildcard name
    assert fwd(rule("ip", "t", "fwd", iif({"set": ["eth0", "eth1"]}), ACCEPT)) == verify.WARN
    assert fwd(rule("ip", "t", "fwd", ACCEPT)) == verify.WARN  # everything
    assert fwd(rule("ip", "t", "fwd", DROP), rule("ip", "t", "fwd", iif("eth0"), ACCEPT)) == verify.FAIL
    assert fwd(rule("ip", "t", "fwd", iif("eth0"), DROP), rule("ip", "t", "fwd", ACCEPT)) == verify.FAIL
    sub_drop = rule("ip", "t", "sub", DROP)
    assert fwd(rule("ip", "t", "fwd", jump("sub")), sub_drop, rule("ip", "t", "fwd", ACCEPT)) == verify.FAIL
    # a drop on a conditional path (some packets) leaves the others to a later accept
    cond = rule("ip", "t", "fwd", ctstate("new"), jump("sub"))
    assert fwd(cond, sub_drop, rule("ip", "t", "fwd", iif("eth0"), ACCEPT)) == verify.WARN
    loop = rule("ip", "t", "sub", jump("fwd"))  # a loop ends, it does not hang
    assert fwd(rule("ip", "t", "fwd", jump("sub")), loop) == verify.FAIL
    # a goto: its chain's return goes to fwd's caller, so fwd's later accept is never reached
    goto = rule("ip", "t", "fwd", {"goto": {"target": "sub"}})
    assert fwd(goto, rule("ip", "t", "sub", RETURN), rule("ip", "t", "fwd", ACCEPT)) == verify.FAIL


def test_the_input_ports_are_matched_by_value_set_and_range():
    base = [chain("ip", "t", "in", "input", "drop")]

    def inp(*rules):
        return policy(ruleset([*base, *rules]), "input")

    ranged = {"set": [{"range": [50, 70]}]}
    both = rule(
        "ip",
        "t",
        "in",
        iif("eth0"),
        {"match": {"op": "==", "left": {"meta": {"key": "l4proto"}}, "right": {"set": ["tcp", "udp"]}}},
        {"match": {"op": "==", "left": {"payload": {"protocol": "th", "field": "dport"}}, "right": ranged}},
        ACCEPT,
    )
    assert inp(both)[0] == verify.WARN
    udp_only = rule("ip", "t", "in", iif("eth0"), l4("udp"), dport("udp", [53, 67]), ACCEPT)
    assert inp(udp_only) == (
        verify.FAIL,
        "1 other input-hook chain drops by default; the TV's DNS (TCP 53) is not accepted",
    )
    named_set = rule("ip", "t", "in", iif("eth0"), dport("udp", "@allowed"), ACCEPT)
    assert inp(named_set)[0] == verify.FAIL  # a named set cannot be read, so it proves nothing
    anywhere = rule("ip", "t", "in", l4("udp"), dport("udp", [53, 67]), ACCEPT)
    tcp53 = rule("ip", "t", "in", l4("tcp"), dport("tcp", 53), ACCEPT)
    assert inp(anywhere, tcp53)[0] == verify.WARN  # `ufw allow 53`: every port of the computer, the TV's too


def test_an_unreadable_listing_is_a_warning_not_a_pass():
    for doc in ({}, {"nftables": []}, None, []):
        assert verify.forward_policy_level(doc, "eth0")[0] == verify.WARN
        assert verify.input_policy_level(doc, "eth0")[0] == verify.WARN


def test_the_policy_checks_read_the_ruleset_verify_already_listed(lg):
    calls = []
    host = gateway(overrides={("nft", "-j", "list", "ruleset"): ruleset(UFW_OPENED)})
    real = host["run"]
    host["run"] = lambda cmd: calls.append(tuple(cmd)) or real(cmd)
    checks = {c.name: c for c in verify.check(S, lg, **host, resolve=resolver()).checks}
    assert calls.count(("nft", "-j", "list", "ruleset")) == 1
    assert checks["forward_policy"].line() == (
        "WARN forward_policy: 1 other forward-hook chain drops by default; it accepts the TV's port"
    )
    assert level(checks["input_policy"]) == "warn"
    assert not re.search(
        r"ufw|filter|FORWARD|INPUT", checks["forward_policy"].detail + checks["input_policy"].detail
    )


# ---- the must-allow names, asked twice ------------------------------------------------------------------------
def flaky(fail_first: dict[str, list[str] | None], then=None):
    """A resolver whose named answers are wrong the first time (and `then` after, when given)."""
    asked: list[str] = []
    base = resolver()

    def resolve(name):
        asked.append(name)
        if name in fail_first:
            if asked.count(name) == 1:
                return fail_first[name]
            if then is not None:
                return then.get(name, base(name))
        return base(name)

    return resolve, asked


def must_allow(lg, resolve, pauses):
    host = gateway(pauses=pauses)
    return next(
        c for c in verify.check(S, lg, **host, resolve=resolve).checks if c.name == "resolver_must_allow"
    )


def test_one_servfail_is_a_transient_warning_after_one_pause(lg):
    """Reproduced: one SERVFAIL on 2026-11-01 at 20:18 failed the run and kept a red line in the brief for
    24 hours. Asked again 3 seconds later, the name answered."""
    resolve, asked = flaky({"us.lgtvsdp.com": []})
    pauses = []
    c = must_allow(lg, resolve, pauses)
    assert c.ok and c.warn and pauses == [verify.MUST_ALLOW_RETRY] == [3.0]
    assert c.line() == (
        "WARN resolver_must_allow: transient: us.lgtvsdp.com->empty answer; answered when asked again 3 s later"
    )
    assert asked.count("us.lgtvsdp.com") == 2 and len(asked) == len(set(asked)) + 1  # only it, again


def test_a_name_that_fails_twice_fails_and_the_second_round_stops_there(lg):
    names = list(lg.must_allow)
    resolve, asked = flaky({names[0]: None, names[1]: ["0.0.0.0"]}, then={names[0]: None})
    pauses = []
    c = must_allow(lg, resolve, pauses)
    assert not c.ok and pauses == [3.0]
    assert c.detail == f"{names[0]}->no answer, {names[1]}->blocked"
    assert asked.count(names[1]) == 1  # the round ended at the first name that failed again


def test_every_answer_right_the_first_time_asks_nothing_again(lg):
    pauses = []
    c = must_allow(lg, resolver(), pauses)
    assert c.ok and not c.warn and c.detail == "" and pauses == []


def test_the_run_and_the_status_file_count_a_transient_as_passed(lg, monkeypatch, status_file):
    from test_verify import patch_gateway

    patch_gateway(monkeypatch, gateway())
    seen = {}

    def a_records(name, server, timeout=4.0):
        seen[name] = seen.get(name, 0) + 1
        return [] if name == "us.lgtvsdp.com" and seen[name] == 1 else resolver()(name)

    monkeypatch.setattr(verify.dnsq, "a_records", a_records)
    assert verify.main(S, lg) == 0
    assert status_file.read_text(encoding="utf-8").startswith("ok ")


# ---- (reliability) iptables_legacy -----------------------------------------------------------------------
@pytest.mark.parametrize(
    ("files", "version", "level", "detail"),
    [
        ({}, "iptables v1.8.11 (nf_tables)\n", verify.OK,
         "no legacy iptables table in the kernel; iptables is the nf_tables variant"),
        ({}, "", verify.OK, "no legacy iptables table in the kernel; no iptables command answered"),
        ({"/proc/net/ip_tables_names": "nat\nfilter\n", "/proc/net/ip6_tables_names": "filter\n"},
         "iptables v1.8.11 (nf_tables)\n", verify.WARN,
         "the kernel holds legacy iptables tables (filter, nat): a kernel built without legacy iptables, as from"
         " Linux 6.17 a distribution's may be, would drop those rules; find what made them before a kernel upgrade"),
        ({}, "iptables v1.8.9 (legacy)\n", verify.WARN,
         "iptables on this computer is the legacy variant: a kernel built without legacy iptables, as from Linux"
         " 6.17 a distribution's may be, would drop those rules; find what made them before a kernel upgrade"),
    ],
)  # fmt: skip
def test_a_legacy_iptables_table_or_variant_is_a_warning_before_a_kernel_upgrade(
    files, version, level, detail
):
    run = lambda cmd: version if cmd == ["iptables", "--version"] else ""  # noqa: E731
    assert verify.iptables_legacy_level(run, lambda path: files.get(path, "")) == (level, detail)
