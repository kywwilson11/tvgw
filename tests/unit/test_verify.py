"""`tvgw verify` against a scripted gateway: every command and file is faked, nothing touches the host."""

import json
import os
import sqlite3

import pytest
from conftest import NOW, plan, statements

from tvgw import config, db, dnsq, flowlog, guard, ingest, queries, verify
from tvgw.config import Settings


def no_kernel_lines(since):
    return []  # the DNS gate's kernel log: nothing, unless a test says otherwise


S = Settings(tv_ip="10.10.10.17", gw_ip="10.10.10.1", wan_if="wlan0", uplink="direct", block_quic="yes")
DOH4 = f"{S.state_dir}/doh4.txt"

RULESET = """table inet tvgw {
	chain ct_events {
		iifname "eth0" ip saddr 10.10.10.0/24 ct state new ct event set destroy comment "flow log: TV connections only"
	}
	chain pre_nat {
		iifname "eth0" ip daddr != 10.10.10.1 udp dport 53 counter dnat ip to 10.10.10.1:53 comment "TV DNS aimed elsewhere -> AdGuard"
	}
	chain forward { ct state invalid counter drop comment "invalid: would leave un-NATed" }
	chain tv_out {
		ip daddr @lan4 counter drop comment "TV may not reach the home LAN"
		meta l4proto { tcp, udp } th dport { 784, 853, 8853 } counter reject comment "DoT/DoQ"
		udp dport 443 counter reject comment "QUIC: force TCP+TLS so SNI is visible"
		tcp dport 443 ip daddr @doh4 counter reject with tcp reset comment "DoH resolvers"
	}
	chain post_nat { oifname "wlan0" ip saddr 10.10.10.0/24 masquerade }
}
"""
TABLE_JSON = json.dumps(
    {
        "nftables": [
            {"metainfo": {}},
            {"table": {"family": "inet", "name": "tvgw"}},
            {
                "rule": {
                    "chain": "tv_out",
                    "comment": "DoT/DoQ",
                    "expr": [{"match": {}}, {"counter": {"packets": 12, "bytes": 960}}, {"reject": None}],
                }
            },
            {
                "rule": {
                    "chain": "tv_out",
                    "comment": "QUIC: force TCP+TLS so SNI is visible",
                    "expr": [{"counter": {"packets": 3, "bytes": 300}}],
                }
            },
            {
                "rule": {
                    "chain": "tv_out",
                    "expr": [{"counter": {"packets": 99, "bytes": 1}}, {"accept": None}],
                }
            },  # no comment: not recorded
        ]
    }
)
RULESET_JSON = json.dumps(
    {
        "nftables": [
            {
                "rule": {
                    "family": "ip",
                    "table": "nat",
                    "chain": "piavpn.r.80.fwdSplitDNS",
                    "expr": [{"counter": {"packets": 0, "bytes": 0}}],
                }
            },
            {
                "rule": {
                    "family": "ip",
                    "table": "nat",
                    "chain": "piavpn.r.80.fwdSplitDNS",
                    "expr": [{"counter": {"packets": 0, "bytes": 0}}],
                }
            },
        ]
    }
)
NETDEV_JSON = json.dumps(
    {
        "nftables": [
            {"table": {"family": "netdev", "name": "tvgw_l2"}},
            {
                "rule": {
                    "family": "netdev",
                    "table": "tvgw_l2",
                    "chain": "in",
                    "comment": "no IPv6 from the TV",
                    "expr": [{"match": {}}, {"counter": {"packets": 5, "bytes": 430}}, {"drop": None}],
                }
            },
        ]
    }
)
DOH_JSON = json.dumps({"nftables": [{"set": {"name": "doh4", "elem": [f"1.0.0.{i}" for i in range(60)]}}]})
GATE_TABLE = """table inet tvgw_gate {
	set resolved4 {
		type ipv4_addr
		flags timeout
		size 65536
	}
	chain forward {
		type filter hook forward priority filter - 5; policy accept;
		iifname "eth0" ip saddr 10.10.10.0/24 ct state new ip daddr != 10.10.10.1 ip daddr != @resolved4 counter packets 0 bytes 0 limit rate 6/minute log prefix "tvgw-gate: " comment "TV to an address DNS never returned"
	}
}
"""
# (inpath) inet tvgw_gate as nft lists it after an apply with DNSGATE_FILL=inpath, the filler live
INPATH_TABLE = (
    GATE_TABLE[: GATE_TABLE.rindex("}")]
    + """	set resolved4_inpath {
		type ipv4_addr
		size 65536
		flags timeout
	}
	set inpath_live {
		type inet_service
		elements = { 53 }
	}
	chain answers {
		type filter hook output priority filter + 5; policy accept;
		oifname "eth0" ip daddr 10.10.10.0/24 udp sport @inpath_live counter packets 41 bytes 4100 queue flags bypass to 53053 comment "in-path: UDP answers offered to the filler"
		oifname "eth0" ip daddr 10.10.10.0/24 tcp sport @inpath_live tcp flags & (syn | rst) == 0 counter packets 1 bytes 90 queue flags bypass to 53053 comment "in-path: TCP answers offered to the filler"
	}
	chain forward_inpath {
		type filter hook forward priority filter - 4; policy accept;
		iifname "eth0" ip saddr 10.10.10.0/24 ct state new ip daddr != 10.10.10.1 ip daddr != @resolved4_inpath counter packets 2 bytes 120 limit rate 6/minute log prefix "tvgw-inpath: " comment "in-path: TV to an address the filler never added"
	}
}
"""
)
GATE_SET_JSON = json.dumps(
    {
        "nftables": [
            {"metainfo": {"version": "1.1.3"}},
            {
                "set": {
                    "family": "inet",
                    "name": "resolved4",
                    "table": "tvgw_gate",
                    "type": "ipv4_addr",
                    "flags": ["timeout"],
                    "elem": [
                        {"elem": {"val": f"203.0.113.{i}", "timeout": 86400, "expires": 1000}}
                        for i in range(3)
                    ],
                }
            },
        ]
    }
)


# (guard) the guard table as `nft -s list` prints it, and its counters as `nft -j list` does
GUARD_LISTING = """table inet tvgw_guard {
	chain input {
		type filter hook input priority filter + 10; policy accept;
		iifname != "eth0" accept
		ip saddr != { 0.0.0.0, 10.10.10.0/24 } counter drop comment "guard: spoofed source"
		ip daddr != 10.10.10.1 counter drop comment "guard: the gateway address only (weak host)"
		counter drop comment "guard: TV may not reach other Pi services"
	}
	chain forward {
		type filter hook forward priority filter + 10; policy accept;
		iifname "eth0" ip daddr { 10.0.0.0/8 } counter drop comment "guard: TV never to the LAN"
	}
	chain output {
		type filter hook output priority filter + 10; policy accept;
		oifname "eth0" ip daddr 10.10.10.0/24 tcp dport { 3000, 3001 } meta skuid != 0 counter drop comment "guard: TV API from root only"
	}
}
"""


def guard_json(final: int = 0) -> str:
    rules = (("guard: spoofed source", 1), (guard.FINAL_DROP, final))
    return json.dumps(
        {
            "nftables": [
                {"table": {"family": "inet", "name": "tvgw_guard"}},
                *(
                    {
                        "rule": {
                            "chain": "input",
                            "comment": c,
                            "expr": [{"counter": {"packets": n, "bytes": 0}}, {"drop": None}],
                        }
                    }
                    for c, n in rules
                ),
            ]
        }
    )


COTENANT_NAMES = [
    *(f"{u}.service" for u in config.co_tenants(S.co_tenant_units)),
    *(f"{u}.socket" for u in config.co_tenants(S.co_tenant_units)),
]
SHOW = ("systemctl", "show", "-p", "Id", "-p", "LoadState", "-p", "ActiveState", "-p", "IPAddressDeny", "--")
# two co-tenants installed and filtered, ssh.socket installed but not in use, the rest not installed
COTENANTS_SHOWN = "\n\n".join(
    f"Id={u}\nLoadState={'loaded' if u in ('smbd.service', 'xrdp.service', 'ssh.socket') else 'not-found'}\n"
    f"ActiveState={'active' if u.endswith('.service') else 'inactive'}\n"
    f"IPAddressDeny={'10.10.10.0/24' if u.endswith('.service') and u in ('smbd.service', 'xrdp.service') else ''}"
    for u in COTENANT_NAMES
)
DNSMASQ_PID = ("systemctl", "show", "-p", "MainPID", "--value", "dnsmasq.service")
# the route of what the gateway itself sends to the TV, from GW_IP (design decision 49)
REPLY_ROUTE = ("ip", "-j", "route", "get", "10.10.10.17", "from", "10.10.10.1")
EXEC_START = (  # (lists)
    "{ path=/opt/AdGuardHome/AdGuardHome ; argv[]=/opt/AdGuardHome/AdGuardHome -s run --no-check-update ;"
    " ignore_errors=no ; start_time=[n/a] ; stop_time=[n/a] ; pid=0 ; code=(null) ; status=0/0 }\n"
)


def vfs(free: int, flag: int = 0) -> os.statvfs_result:
    """(depth) What os.statvfs returns for a filesystem with `free` bytes available, in 4 KiB blocks."""
    blocks = free // 4096
    return os.statvfs_result((4096, 4096, blocks * 4, blocks, blocks, 1000, 900, 900, flag, 255))


ROUTER = "198.51.100.1"  # (depth) the router WAN_GW names, an RFC 5737 address
WAN_ADDR = json.dumps(
    [
        {
            "ifname": "wlan0",
            "addr_info": [{"family": "inet", "local": "198.51.100.2", "prefixlen": 24, "scope": "global"}],
        }
    ]
)
DEFAULT_VIA_ROUTER = json.dumps([{"dst": "default", "gateway": ROUTER, "dev": "wlan0", "flags": []}])
HEALTHY_META = {"last_run": str(NOW - 600), "backup_ok_t": str(NOW - 6 * 3600)}  # (depth)


def gateway(overrides=None, files=None, mtimes=None, free=50 * 2**30, meta=None, pauses=None):
    """The `run`, `read` and `mtime` seams of check() describing a healthy gateway, with per-test
    overrides; pass them with `**gateway(...)`. (depth) `free` is the state directory's free space (a
    statvfs_result for a read-only one), `meta` the store's meta values (HEALTHY_META when None, and a
    store that cannot be read with "unreadable"), and `pauses` collects the pauses check() asks for."""
    cmds = {
        ("nft", "-s", "list", "table", "inet", "tvgw"): RULESET,
        ("nft", "-j", "list", "table", "inet", "tvgw"): TABLE_JSON,
        ("nft", "-j", "list", "ruleset"): RULESET_JSON,
        ("nft", "-j", "list", "table", "netdev", "tvgw_l2"): NETDEV_JSON,
        ("nft", "-j", "list", "set", "inet", "tvgw", "doh4"): DOH_JSON,
        ("ip", "-j", "route", "get", "1.1.1.1", "from", "10.10.10.17", "iif", "eth0"): json.dumps(
            [{"dst": "1.1.1.1", "dev": "wlan0", "table": "100"}]
        ),
        REPLY_ROUTE: json.dumps(
            [
                {
                    "dst": "10.10.10.17",
                    "from": "10.10.10.1",
                    "dev": "eth0",
                    "table": "100",
                    "prefsrc": "10.10.10.1",
                }
            ]
        ),
        ("ip", "-j", "rule"): json.dumps(
            [{"priority": 50, "table": "main"}, {"priority": 60, "table": "100"}]
        ),
        ("systemctl", "is-active", *verify.SERVICES): "active\n" * len(verify.SERVICES),
        ("systemctl", "is-active", *verify.SERVICES, "tvgw-dnsgate"): "active\n" * (len(verify.SERVICES) + 1),
        ("nft", "list", "table", "inet", "tvgw_gate"): GATE_TABLE,
        ("nft", "-j", "list", "set", "inet", "tvgw_gate", "resolved4"): GATE_SET_JSON,
        ("/opt/AdGuardHome/AdGuardHome", "--version"): "AdGuard Home, version v0.107.79\n",
        # (guard)
        ("nft", "-s", "list", "table", "inet", "tvgw_guard"): GUARD_LISTING,
        ("nft", "-j", "list", "table", "inet", "tvgw_guard"): guard_json(),
        (*SHOW, *COTENANT_NAMES): COTENANTS_SHOWN,
        DNSMASQ_PID: "4242\n",
        # (events) the flow logger's main process, whose event socket `sockets` below describes
        ("systemctl", "show", "-p", "MainPID", "--value", "tvgw-flowlog"): "4242\n",
        # (lists) the effective ExecStart, as `systemctl show -P ExecStart` prints it
        ("systemctl", "show", "-P", "ExecStart", "AdGuardHome"): EXEC_START,
        ("systemctl", "show", "-P", "MainPID", "AdGuardHome"): "812\n",  # and the process it started
        # (depth) the clock, the uplink's address, table 100 and the main table's default, the TV's port
        ("timedatectl", "show", "-p", "NTPSynchronized", "--value"): "yes\n",
        ("ip", "-j", "-4", "addr", "show", "dev", "wlan0"): WAN_ADDR,
        ("ip", "-j", "route", "show", "table", "100", "default"): DEFAULT_VIA_ROUTER,
        ("ip", "-j", "route", "show", "default", "dev", "wlan0"): DEFAULT_VIA_ROUTER,
        ("ip", "-j", "neigh", "show", "dev", "eth0"): json.dumps(
            [{"dst": "10.10.10.17", "lladdr": "00:00:5e:00:53:17", "state": ["REACHABLE"]}]
        ),
    }
    cmds.update(overrides or {})
    fs = {
        "/proc/sys/net/ipv4/ip_forward": "1\n",
        "/proc/sys/net/ipv4/conf/eth0/forwarding": "1\n",
        "/proc/sys/net/ipv4/conf/wlan0/forwarding": "1\n",
        "/proc/sys/net/ipv6/conf/eth0/disable_ipv6": "1\n",
        verify.EVENTS_KEY: "0\n",  # (events)
        verify.APPLIED: RULESET,
        # (guard) it dropped them all, under the drop-in's bounding set (chown dac_override setgid setuid
        # net_bind_service)
        "/proc/4242/status": "Name:\tdnsmasq\nCapEff:\t0000000000000000\nCapBnd:\t00000000000004c3\n",
        "/proc/812/cmdline": "/opt/AdGuardHome/AdGuardHome\0-s\0run\0--no-check-update\0",  # (lists)
        "/sys/class/net/wlan0/carrier": "1\n",  # (depth)
        verify.CONF: f"WAN_IF=wlan0\nWAN_GW={ROUTER}\n",
        "/proc/uptime": "86400.00 170000.00\n",
    }
    fs.update(files or {})
    # applied half an hour ago from inputs edited an hour ago; the DoH list was refreshed yesterday
    ages = {verify.APPLIED: NOW - 1800, verify.CONF: NOW - 3600, S.block4: NOW - 3600, DOH4: NOW - 86400}
    ages.update(mtimes or {})
    return {
        "run": lambda cmd: cmds.get(tuple(cmd), ""),
        "read": lambda path: fs.get(path, ""),
        "mtime": lambda path: ages.get(path),
        # (events) the logger holds one event socket that has dropped 7 events since it started
        "sockets": lambda pid: (
            [flowlog.NetlinkSocket(inode=900, protocol=12, portid=pid, groups=4, drops=7)]
            if pid == 4242
            else []
        ),
        # (depth)
        "statvfs": lambda path: free if isinstance(free, os.statvfs_result) else vfs(free),
        "meta": lambda: None if meta == "unreadable" else dict(HEALTHY_META if meta is None else meta),
        "sleep": (pauses if pauses is not None else []).append,
    }


def resolver(answers=None):
    answers = answers or {}

    def resolve(name):
        if name in answers:
            return answers[name]
        if "gfts" in name:
            return ["10.10.10.1"]
        if name.startswith("h4g3z1-"):  # (lists) the list sentinels, blocked
            return ["0.0.0.0"]
        return ["23.0.0.1"]

    return resolve


def test_healthy_gateway_passes_every_check(lg):
    host = gateway()
    r = verify.check(S, lg, **host, resolve=resolver())
    assert r.ok, r.failures
    names = [c.name for c in r.checks]
    assert names == [
        "ruleset",
        "ruleset_unchanged",
        "applied_current",
        "forwarding",
        "ipv6_off",
        "ipv6_guard",
        "tv_route",
        "gw_reply_route",
        "policy_rule",
        "vpn_dnat_idle",
        "doh4_loaded",
        "doh4_fresh",
        "resolver_rewrite",
        "resolver_must_allow",
        "services",
        "tv_paths",
        "adguard_version",
        "list_sentinels",  # (lists)
        "adguard_pinned",
        "dnsgate",
        "dnsgate_inpath",  # (inpath) OK, "not in use", on a gateway that never asked for it
        "attention",  # (attention) OK, "not in use", where the live reading is off
        "capture",
        "guard_present",  # (guard)
        "guard_quiet",
        "cotenants_denied",
        "dnsmasq_caps",
        "flowlog_events",  # (events)
        "disk",  # (depth)
        "clock_synced",
        "store_backup",
        "ingest_fresh",
        "uplink_ipv4",
        "wan_gateway",
        "forward_policy",
        "input_policy",
        "tv_port_neighbours",
    ]
    assert not any(c.warn for c in r.checks), [c.line() for c in r.checks if c.warn]
    assert r.versions == {"adguard": "v0.107.79"}
    assert [c.detail for c in r.checks if c.name == "dnsgate"] == ["3 addresses in the set"]
    assert not any(c.warn for c in r.checks)
    assert r.counters == [
        ("DoT/DoQ", 12, 960),
        ("QUIC: force TCP+TLS so SNI is visible", 3, 300),
        ("no IPv6 from the TV", 5, 430),
        ("guard: spoofed source", 1, 0),  # (guard) stored beside inet tvgw's
        (guard.FINAL_DROP, 0, 0),
        (flowlog.DROPS_RULE, 7, 0),  # (events) the event socket's drops, a series of its own
    ]
    assert r.vpn == {"vpn_if": "auto", "device": None, "pia": None}


def test_each_failure_is_named(lg):
    host = gateway(
        {
            ("nft", "-j", "list", "ruleset"): json.dumps(
                {
                    "nftables": [
                        {
                            "rule": {
                                "chain": "piavpn.r.80.fwdSplitDNS",
                                "expr": [{"counter": {"packets": 7, "bytes": 1}}],
                            }
                        }
                    ]
                }
            ),
            ("ip", "-j", "rule"): "[]",
            ("systemctl", "is-active", *verify.SERVICES, "tvgw-dnsgate"): "active\ninactive\nactive\n",
            ("nft", "-j", "list", "set", "inet", "tvgw", "doh4"): json.dumps(
                {"nftables": [{"set": {"name": "doh4", "elem": ["1.1.1.1"]}}]}
            ),
        },
        {"/proc/sys/net/ipv4/ip_forward": "0\n", verify.APPLIED: RULESET + "\n# edited by hand\n"},
    )
    bad = resolver({"ngfts.lge.com": ["0.0.0.0"], "us.lgtvsdp.com": None, "snu.lge.com": ["0.0.0.0"]})
    r = verify.check(S, lg, **host, resolve=bad)
    failed = {c.name: c.detail for c in r.checks if not c.ok}
    assert "ip_forward=0" in failed["forwarding"]
    assert failed["ruleset_unchanged"] == "differs from the last apply"
    assert "7 TV DNS packets" in failed["vpn_dnat_idle"]
    assert failed["doh4_loaded"] == "1 addresses"
    assert "ngfts.lge.com->['0.0.0.0']" in failed["resolver_rewrite"]
    assert (
        "us.lgtvsdp.com->no answer" in failed["resolver_must_allow"]
        and "snu.lge.com->blocked" in failed["resolver_must_allow"]
    )
    assert "policy_rule" in failed
    assert (
        failed["services"].startswith("down: ")
        and "dnsmasq" in failed["services"]
        and "tvgw-flowlog" in failed["services"]
    )


def test_an_empty_answer_for_a_must_allow_name_fails(lg):
    """AdGuard's nxdomain and refused blocking modes, and an upstream outage, answer with no records
    rather than 0.0.0.0; the hardware suite already demands a real address for every must-allow name."""
    host = gateway()
    r = verify.check(S, lg, **host, resolve=resolver({"us.lgtvsdp.com": []}))
    must_allow = next(c for c in r.checks if c.name == "resolver_must_allow")
    assert not must_allow.ok and "us.lgtvsdp.com->empty answer" in must_allow.detail


def test_a_loaded_table_without_its_apply_baseline_fails(lg):
    host = gateway(files={verify.APPLIED: ""})
    r = verify.check(S, lg, **host, resolve=resolver())
    unchanged = next(c for c in r.checks if c.name == "ruleset_unchanged")
    assert not unchanged.ok and unchanged.detail.startswith("no baseline: /run/tvgw/ruleset.applied missing")
    assert "applied_current" not in [c.name for c in r.checks]  # nothing to compare the inputs against


def named(check: str, lg, **host) -> verify.Check:
    """One check of a healthy gateway with `gateway(**host)` overrides."""
    return next(
        c for c in verify.check(S, lg, **gateway(**host), resolve=resolver()).checks if c.name == check
    )


def test_an_input_edited_after_the_last_apply_fails_until_it_is_applied(lg):
    """Reproduced: a block4.txt line nft rejects leaves the old set loaded and ruleset.applied
    unwritten, so ruleset_unchanged kept passing while every later apply failed only in the journal."""
    stale = named("applied_current", lg, mtimes={verify.CONF: NOW - 600})
    assert not stale.ok and stale.detail == "changed after the last apply: tvgw.conf"
    both = named("applied_current", lg, mtimes={S.block4: NOW - 300, DOH4: NOW - 200})
    assert both.detail == "changed after the last apply: block4.txt, doh4.txt"
    # tvgw-doh-update writes the list and then applies; an operator mid-edit gets the same grace
    assert named("applied_current", lg, mtimes={verify.CONF: NOW - 30}).ok
    assert named("applied_current", lg, mtimes={verify.CONF: None}).ok  # unreadable: not judged


def test_a_conf_edit_to_a_key_tvgw_apply_never_reads_needs_no_apply(lg):
    """Reproduced: changing ANALYST_EFFORT, which the docs say takes effect at the next analyst run,
    failed applied_current on every 10-minute run and put a firewall red line in the brief until some
    unrelated apply. tvgw-apply records the settings it used; only a difference in those counts."""
    used = "UPLINK=direct\nWAN_IF=wlan0\nWAN_GW=203.0.113.1\nBLOCK_QUIC=yes\nSTRICT_PORTS=no\nDNSGATE=count\n"
    conf = "WAN_GW=203.0.113.1\nANALYST_EFFORT=medium\nTV_NAME=lounge\n"  # the rest at their defaults
    files = {verify.SETTINGS_APPLIED: used, verify.CONF: conf}
    assert named("applied_current", lg, files=files, mtimes={verify.CONF: NOW - 600}).ok
    files[verify.CONF] = conf + "STRICT_PORTS=yes\n"
    stale = named("applied_current", lg, files=files, mtimes={verify.CONF: NOW - 600})
    assert not stale.ok and stale.detail == "changed after the last apply: tvgw.conf"


def test_a_doh_list_the_updater_stopped_refreshing_fails(lg):
    assert named("doh4_fresh", lg).detail == "1.0 days old"
    assert named("doh4_fresh", lg, mtimes={DOH4: NOW - 7 * 86400}).ok
    old = named("doh4_fresh", lg, mtimes={DOH4: NOW - 9 * 86400})
    assert not old.ok and old.detail == "9.0 days old"
    missing = named("doh4_fresh", lg, mtimes={DOH4: None})
    assert not missing.ok and missing.detail == "doh4.txt missing"


def test_the_netdev_ipv6_drop_is_a_counter_series_too(lg):
    netdev = json.dumps(
        {
            "nftables": [
                {"table": {"family": "netdev", "name": "tvgw_l2"}},
                {
                    "rule": {
                        "chain": "in",
                        "comment": "no IPv6 from the TV",
                        "expr": [{"match": {}}, {"counter": {"packets": 41, "bytes": 3526}}, {"drop": None}],
                    }
                },
            ]
        }
    )
    host = gateway({("nft", "-j", "list", "table", "netdev", "tvgw_l2"): netdev})
    r = verify.check(S, lg, **host, resolve=resolver())
    # (guard) the guard's two series follow it, then (events) the flow log's drops
    assert r.counters[-4] == ("no IPv6 from the TV", 41, 3526) and len(r.counters) == 6
    host = gateway({("nft", "-j", "list", "table", "netdev", "tvgw_l2"): ""})  # eth0 down: not loaded
    assert len(verify.check(S, lg, **host, resolve=resolver()).counters) == 5


def test_a_missing_ipv6_wire_guard_fails(lg):
    """Reproduced: with netdev tvgw_l2 deleted (by hand, or a load that failed while eth0 was up: the
    apply only warns) every check passed and the brief's IPv6 series simply vanished. disable_ipv6
    still drops IPv6, so this is the second wall and its evidence, not an open path."""
    netdev = ("nft", "-j", "list", "table", "netdev", "tvgw_l2")
    gone = named("ipv6_guard", lg, overrides={netdev: ""})
    assert not gone.ok and gone.detail == "netdev tvgw_l2 is not dropping IPv6 on eth0"
    accepting = NETDEV_JSON.replace('{"drop": null}', '{"accept": null}')
    assert not named("ipv6_guard", lg, overrides={netdev: accepting}).ok
    assert named("ipv6_guard", lg).ok


def test_doh_set_is_measured_in_addresses_not_merged_elements(lg):
    """nft's auto-merge folds neighbouring addresses into prefixes and ranges, so a healthy list of
    hundreds of resolvers can be a few dozen elements."""
    merged = json.dumps(
        {
            "nftables": [
                {
                    "set": {
                        "name": "doh4",
                        "elem": [f"1.0.0.{i}" for i in range(10)]
                        + [{"prefix": {"addr": "1.2.3.0", "len": 26}}, {"range": ["5.5.5.1", "5.5.5.2"]}],
                    }
                }
            ]
        }
    )
    host = gateway({("nft", "-j", "list", "set", "inet", "tvgw", "doh4"): merged})
    doh = next(c for c in verify.check(S, lg, **host, resolve=resolver()).checks if c.name == "doh4_loaded")
    assert doh.ok and doh.detail == "76 addresses"
    thirty = json.dumps({"nftables": [{"set": {"name": "doh4", "elem": [f"1.0.0.{i}" for i in range(30)]}}]})
    host = gateway({("nft", "-j", "list", "set", "inet", "tvgw", "doh4"): thirty})
    doh = next(c for c in verify.check(S, lg, **host, resolve=resolver()).checks if c.name == "doh4_loaded")
    assert not doh.ok and doh.detail == "30 addresses"


def test_missing_table_and_missing_key_rules(lg):
    host = gateway({("nft", "-s", "list", "table", "inet", "tvgw"): ""})
    r = verify.check(S, lg, **host, resolve=resolver())
    assert next(c for c in r.checks if c.name == "ruleset").detail == "table inet tvgw is not loaded"
    assert "ruleset_unchanged" not in [c.name for c in r.checks]
    host = gateway(
        {
            ("nft", "-s", "list", "table", "inet", "tvgw"): RULESET.replace("@lan4", "@nope").replace(
                "udp dport 443", "udp dport 444"
            )
        }
    )
    r = verify.check(S, lg, **host, resolve=resolver())
    detail = next(c for c in r.checks if c.name == "ruleset").detail
    assert "home LAN isolated" in detail and "QUIC rejected" in detail
    quiet = Settings(**{**S.__dict__, "block_quic": "no"})
    r = verify.check(quiet, lg, **host, resolve=resolver())
    assert "QUIC" not in next(c for c in r.checks if c.name == "ruleset").detail


def test_interface_forwarding_off_is_the_outage_we_had(lg):
    host = gateway(files={"/proc/sys/net/ipv4/conf/eth0/forwarding": "0\n"})
    r = verify.check(S, lg, **host, resolve=resolver())
    fwd = next(c for c in r.checks if c.name == "forwarding")
    assert not fwd.ok and fwd.detail == "eth0 not forwarding (TV offline)"


def test_vpn_uplink_expects_tun0_and_no_policy_rule(lg):
    vpn = Settings(**{**S.__dict__, "uplink": "vpn"})
    host = gateway()
    r = verify.check(vpn, lg, **host, resolve=resolver())
    route = next(c for c in r.checks if c.name == "tv_route")
    assert not route.ok and "expected tun0" in route.detail
    assert "policy_rule" not in [c.name for c in r.checks]
    # the gateway's own answers to the TV are checked in vpn mode too, and pass by the main table
    assert next(c for c in r.checks if c.name == "gw_reply_route").ok


def reply_check(r: verify.Result) -> verify.Check:
    return next(c for c in r.checks if c.name == "gw_reply_route")


def test_the_gateways_answers_to_the_tv_must_leave_by_the_tv_port(lg):
    """Design decision 49: rule 60 also sends what the gateway itself sends to the TV, from GW_IP, into
    table 100. With only the default route there those answers leave by the uplink, and the TV has an
    address and no DNS while every other check passes. No route at all (GW_IP on no port, an `ip` that
    printed an error) is no answer either. The detail names interfaces, never the route's addresses."""
    healthy = reply_check(verify.check(S, lg, **gateway(), resolve=resolver()))
    assert healthy.ok and not healthy.warn
    assert healthy.detail == "the gateway's answers to the TV leave by eth0, expected eth0"
    by_uplink = json.dumps(
        [
            {
                "dst": "10.10.10.17",
                "from": "10.10.10.1",
                "gateway": "198.51.100.1",
                "dev": "wlan0",
                "table": "100",
            }
        ]
    )
    for out, dev in ((by_uplink, "wlan0"), ("", "nothing"), ("[]", "nothing"), ('[{"dev": 7}]', "nothing")):
        r = verify.check(S, lg, **gateway({REPLY_ROUTE: out}), resolve=resolver())
        check = reply_check(r)
        assert not check.ok and not check.warn and not r.ok, out
        assert check.detail == f"the gateway's answers to the TV leave by {dev}, expected eth0"
        assert "198.51.100.1" not in check.line() and "10.10.10." not in check.line()


def test_the_reply_route_is_asked_for_the_tv_side_the_settings_name():
    site = Settings(
        **{
            **S.__dict__,
            "tv_if": "enp1s0",
            "tv_net": "10.20.30.0/24",
            "gw_ip": "10.20.30.1",
            "tv_ip": "10.20.30.17",
        }
    )
    asked: list[list[str]] = []

    def run(cmd: list[str]) -> str:
        asked.append(cmd)
        return '[{"dst": "10.20.30.17", "dev": "enp1s0"}]'

    check = verify.gw_reply_route_check(site, run)
    assert asked == [["ip", "-j", "route", "get", "10.20.30.17", "from", "10.20.30.1"]]
    assert check.ok and check.detail == "the gateway's answers to the TV leave by enp1s0, expected enp1s0"
    assert not verify.gw_reply_route_check(site, lambda cmd: '[{"dev": "eth0"}]').ok


def test_record_and_fw_activity_handle_resets(gateway, lg):
    conn = db.connect(gateway.db_path)
    r1 = verify.Result(checks=[verify.Check("x", True)], counters=[("DoT/DoQ", 10, 1)], t=1000.0)
    r2 = verify.Result(checks=[verify.Check("x", True)], counters=[("DoT/DoQ", 15, 1)], t=2000.0)
    r3 = verify.Result(
        checks=[verify.Check("x", False, "boom")], counters=[("DoT/DoQ", 2, 1)], t=3000.0
    )  # re-apply reset
    r4 = verify.Result(checks=[verify.Check("x", True)], counters=[("DoT/DoQ", 6, 1)], t=4000.0)
    for r in (r1, r2, r3, r4):
        verify.record(conn, r)
    assert queries.fw_activity(conn, 1500, 5000) == [("DoT/DoQ", 5 + 2 + 4)]  # 10->15, reset to 2, 2->6
    assert queries.fw_activity(conn, 0, 5000) == [
        ("DoT/DoQ", 5 + 2 + 4)
    ]  # first sample is a baseline, not a delta
    vs = queries.verify_summary(conn, 0, 5000)
    assert (vs["runs"], vs["failed"], vs["last_failures"]) == (4, 1, ["FAIL x: boom"])
    conn.close()


def test_counters_from_table_ignores_uncommented_rules_and_garbage():
    assert verify.counters_from_table("not json") == []
    assert verify.counters_from_table(TABLE_JSON)[0] == ("DoT/DoQ", 12, 960)


DNS_REDIRECT = "TV DNS aimed elsewhere -> AdGuard"  # the UDP and TCP redirects in tvgw-apply share it


def listing(*rules: tuple[str, int, int]) -> str:
    """An `nft -j list table` document with one counted, commented rule per (comment, packets, bytes)."""
    return json.dumps(
        {
            "nftables": [
                {"rule": {"chain": "c", "comment": c, "expr": [{"counter": {"packets": p, "bytes": b}}]}}
                for c, p, b in rules
            ]
        }
    )


def test_counters_from_table_sums_rules_sharing_a_comment_in_first_seen_order():
    doc = listing(("DoT/DoQ", 12, 960), (DNS_REDIRECT, 100, 1), ("QUIC", 3, 300), (DNS_REDIRECT, 5, 2))
    assert verify.counters_from_table(doc) == [
        ("DoT/DoQ", 12, 960),
        (DNS_REDIRECT, 105, 3),
        ("QUIC", 3, 300),
    ]


def test_rules_sharing_a_comment_are_one_series(tmp_path):
    """Reproduced: summed per row, the (udp, tcp) pairs read as 100, 5, 130, 5, 160, 6: a reset at every
    snapshot and 296 packets where 61 were counted."""
    conn = db.connect(str(tmp_path / "v.db"))
    for t, udp, tcp in ((1000.0, 100, 5), (1600.0, 130, 5), (2200.0, 160, 6)):
        counters = verify.counters_from_table(listing((DNS_REDIRECT, udp, 0), (DNS_REDIRECT, tcp, 0)))
        verify.record(conn, verify.Result(counters=counters, t=t))
    assert queries.fw_activity(conn, 0, 3000) == [(DNS_REDIRECT, 61)]
    # the baseline is the snapshot before the window, so the window's first step is a delta too
    assert queries.fw_activity(conn, 2000, 3000) == [(DNS_REDIRECT, 31)]
    rows_per_snapshot = conn.execute(
        "SELECT COUNT(*) FROM fw_counters WHERE rule=? GROUP BY t", (DNS_REDIRECT,)
    ).fetchall()
    assert rows_per_snapshot == [(1,)] * 3


def test_legacy_duplicate_rows_are_folded_per_snapshot(tmp_path):
    """The live store holds two rows per (t, comment) from before the fold; the window query sums them."""
    conn = db.connect(str(tmp_path / "v.db"))
    conn.executemany(
        "INSERT INTO fw_counters(t, rule, packets, bytes) VALUES (?,?,?,0)",
        [
            (t, DNS_REDIRECT, p)
            for t, pair in ((1000, (100, 5)), (1600, (130, 5)), (2200, (160, 6)))
            for p in pair
        ],
    )
    assert queries.fw_activity(conn, 0, 3000) == [(DNS_REDIRECT, 61)]


def test_snapshots_are_compared_in_the_order_taken_not_by_the_clock(tmp_path):
    """fake-hwclock steps the clock back after a power loss: a snapshot stamped earlier than its
    predecessor is still the next reading, not a reset (which would have counted 160)."""
    conn = db.connect(str(tmp_path / "v.db"))
    for t, packets in ((1000.0, 100), (1600.0, 130), (900.0, 131), (2800.0, 160)):
        verify.record(conn, verify.Result(counters=[("DoT/DoQ", packets, 0)], t=t))
    assert queries.fw_activity(conn, 0, 3000) == [("DoT/DoQ", 60)]


def test_fw_activity_reads_through_the_time_index_on_a_fresh_store(tmp_path):
    """Reproduced: the per-rule baseline was a correlated scan, 0.1 s at 100 days and linear in history."""
    conn = db.connect(str(tmp_path / "v.db"))
    ran = statements(conn, lambda: queries.fw_activity(conn, 1000, 2000))
    assert len(ran) == 2  # the baseline and the window
    for sql in ran:
        assert "fw_counters_t" in plan(conn, sql) and "SCAN" not in plan(conn, sql), sql


def test_dns_question_and_answer_decoding():
    q = dnsq.question("us.lgtvsdp.com", qid=0x1234)
    assert q[:2] == b"\x12\x34" and q.endswith(b"\x02us\x07lgtvsdp\x03com\x00\x00\x01\x00\x01")
    # a response: question echoed, one A record 10.10.10.1 via a compression pointer
    resp = (
        b"\x12\x34\x81\x80\x00\x01\x00\x01\x00\x00\x00\x00"
        + b"\x05ngfts\x03lge\x03com\x00\x00\x01\x00\x01"
        + b"\xc0\x0c\x00\x01\x00\x01\x00\x00\x00\x3c\x00\x04\x0a\x0a\x0a\x01"
    )
    from tvgw import dnsmsg

    assert [a.value for a in dnsmsg.decode_answers(resp) if a.rtype == "A"] == ["10.10.10.1"]


def test_cli_verify_uses_the_store_when_recording(gateway, lg, monkeypatch, capsys, tmp_path):
    from tvgw import cli

    ingest.run(
        gateway, lg, extract=lambda p: [], oddport_lines=lambda s: [], gate_lines=no_kernel_lines, lock=False
    )
    commands = []
    monkeypatch.setattr(verify, "run_cmd", lambda cmd: commands.append(cmd) or "")
    monkeypatch.setattr(verify, "read_file", lambda path: "")
    monkeypatch.setattr(verify, "file_mtime", lambda path: None)
    monkeypatch.setattr(dnsq, "a_records", lambda name, server, timeout=4.0: None)
    conf = tmp_path / "tvgw.conf"
    conf.write_text(f'TV_IP={gateway.tv_ip}\nDB_PATH="{gateway.db_path}"\n')
    assert cli.main(["--conf", str(conf), "verify", "--record"]) == 1
    out = capsys.readouterr().out
    assert "FAIL ruleset: table inet tvgw is not loaded" in out
    assert ["nft", "-s", "list", "table", "inet", "tvgw"] in commands  # the seam: no real nft was run
    conn = db.connect(gateway.db_path, readonly=True)
    assert conn.execute("SELECT ok FROM verify").fetchone() == (0,)


def patch_gateway(monkeypatch, host):
    """main() reads the host through the module's run_cmd, read_file, file_mtime and dnsq.a_records."""
    monkeypatch.setattr(verify, "run_cmd", host["run"])
    monkeypatch.setattr(verify, "read_file", host["read"])
    monkeypatch.setattr(verify, "file_mtime", host["mtime"])
    monkeypatch.setattr(flowlog, "event_sockets", host["sockets"])  # (events)
    monkeypatch.setattr(dnsq, "a_records", lambda name, server, timeout=4.0: resolver()(name))
    monkeypatch.setattr(verify, "free_space", host["statvfs"])  # (depth)
    monkeypatch.setattr(
        verify, "store_meta", lambda path, keys=verify.META_KEYS, backup_dir=None: host["meta"]()
    )
    monkeypatch.setattr(verify, "pause", host["sleep"])


def test_a_run_that_cannot_be_recorded_still_prints_every_check_and_exits_1(
    lg, monkeypatch, capsys, tmp_path
):
    """Reproduced: with the directory missing, the checks printed and nothing said the run was lost;
    with record() raising, a traceback replaced the checks."""
    patch_gateway(monkeypatch, gateway())
    s = Settings(**{**S.__dict__, "db_path": str(tmp_path / "no-such-dir" / "tvgw.db")})
    assert verify.main(s, lg, record_to_store=True) == 1
    out, err = capsys.readouterr()
    lines = out.splitlines()
    assert len(lines) == 37 and all(
        ln.startswith("OK   ") for ln in lines
    )  # (guard) 4, (events) 1, (lists) 2, (depth) 9, the reply route 1, (inpath) 1, (attention) 1
    assert err.startswith("tvgw verify: could not record the run: ")


def test_a_locked_store_is_reported_after_the_checks(lg, monkeypatch, capsys, tmp_path):
    patch_gateway(monkeypatch, gateway())

    def locked(conn, r):
        raise sqlite3.OperationalError("database is locked")

    monkeypatch.setattr(verify, "record", locked)
    s = Settings(**{**S.__dict__, "db_path": str(tmp_path / "tvgw.db")})
    assert verify.main(s, lg, record_to_store=True) == 1
    out, err = capsys.readouterr()
    assert (
        out.splitlines()[0] == "OK   ruleset" and len(out.splitlines()) == 37
    )  # (guard) 4, (events) 1, (lists) 2, (depth) 9, the reply route 1, (attention) 1
    assert err == "tvgw verify: could not record the run: database is locked\n"
    assert verify.main(s, lg, record_to_store=True, as_json=True) == 1
    out, err = capsys.readouterr()
    doc = json.loads(out)  # stdout stays parseable
    assert set(doc) == {"ok", "checks", "counters"} and doc["ok"] is True and "could not record" in err
    assert (
        doc["checks"][0] == {"name": "ruleset", "ok": True, "detail": ""}  # (events) warn only where set
        and doc["counters"][0][0] == "DoT/DoQ"
    )


def test_an_old_or_unreadable_adguard_fails_the_version_floor(lg):
    exe = ("/opt/AdGuardHome/AdGuardHome", "--version")
    old = verify.check(S, lg, **gateway({exe: "AdGuard Home, version v0.107.70\n"}), resolve=resolver())
    assert old.failures == [
        "FAIL adguard_version: v0.107.70 is below v0.107.79, the release with the 2026 DoH and DoQ fixes;"
        " download the new release and run: sudo tvgw adguard upgrade <its AdGuardHome binary>"
    ]
    assert old.versions == {"adguard": "v0.107.70"}  # still recorded: the brief says what is running
    there = gateway({exe: ""}, mtimes={exe[0]: 1.0})  # the binary is there but says nothing usable
    mute = verify.check(S, lg, **there, resolve=resolver())
    assert mute.failures == [
        "FAIL adguard_version: could not read it from /opt/AdGuardHome/AdGuardHome --version"
    ]
    assert mute.versions == {}


def test_a_gateway_one_release_behind_the_pin_passes_both_adguard_checks(lg):
    """(pass 4) The pin moved to v0.107.80 on 2026-11-05 and the floor stayed at v0.107.79, so the reference
    gateway runs a release behind the pin until its owner upgrades. adguard_version judges the floor
    alone and adguard_pinned only that AdGuard cannot update itself: neither may FAIL, nor WARN, a
    working gateway for being behind the pin, or every gateway would turn red on the day a pin moves."""
    from tvgw import aghinstall

    behind = verify.ADGUARD_MIN
    if behind >= aghinstall.pin_version():  # a floor raised to the pin leaves no gateway behind it
        pytest.skip("the floor is the pin: no working gateway runs a release behind it")
    line = f"AdGuard Home, version v{'.'.join(map(str, behind))}\n"
    r = verify.check(
        S, lg, **gateway({("/opt/AdGuardHome/AdGuardHome", "--version"): line}), resolve=resolver()
    )
    by = {c.name: c for c in r.checks}
    for name in ("adguard_version", "adguard_pinned"):
        assert by[name].ok and not by[name].warn, by[name].line()
    assert by["adguard_version"].detail == "v" + ".".join(map(str, behind))
    assert r.ok, r.failures


def test_a_missing_adguard_is_named_with_the_install_hint(lg):
    """(packaging) AdGuard Home is a checked dependency, never bundled: when the binary is not there at
    all the line says so and how to install it, instead of a version it could not read."""
    gone = verify.check(
        S, lg, **gateway({("/opt/AdGuardHome/AdGuardHome", "--version"): ""}), resolve=resolver()
    )
    (line,) = [f for f in gone.failures if "adguard_version" in f]
    assert line.startswith(
        "FAIL adguard_version: AdGuard Home is not installed (/opt/AdGuardHome/AdGuardHome missing);"
    )
    assert "install it with sudo tvgw adguard install, which fetches the release tvgw pins" in line
    assert gone.versions == {}


def test_record_stores_the_versions_for_the_brief(lg, tmp_path):
    from tvgw import db, queries

    r = verify.check(S, lg, **gateway(), resolve=resolver())
    conn = db.connect(str(tmp_path / "t.db"))
    verify.record(conn, r)
    assert conn.execute("SELECT value FROM meta WHERE key='adguard_version'").fetchone() == ("v0.107.79",)
    cov = queries.coverage(conn, r.t - 60, r.t + 60, now=r.t + 60)
    assert cov["adguard_version"] == "v0.107.79"


def test_the_dns_gate_is_checked_only_while_on_and_its_structure_is_the_check(lg):
    from dataclasses import replace

    off = verify.check(replace(S, dnsgate="off"), lg, **gateway(), resolve=resolver())
    assert "dnsgate" not in [c.name for c in off.checks] and off.ok
    gone = verify.check(
        S, lg, **gateway({("nft", "list", "table", "inet", "tvgw_gate"): ""}), resolve=resolver()
    )
    assert gone.failures == ["FAIL dnsgate: missing: set, counting rule"]
    down = gateway(
        {
            ("systemctl", "is-active", *verify.SERVICES, "tvgw-dnsgate"): "active\n" * len(verify.SERVICES)
            + "inactive\n"
        }
    )
    assert verify.check(S, lg, **down, resolve=resolver()).failures == ["FAIL services: down: tvgw-dnsgate"]
    assert verify.set_size(GATE_SET_JSON) == 3 and verify.set_size("") == 0 and verify.set_size("junk") == 0


GATE = "TV to an address DNS never returned"


def reload_files(before: int, after: int, t: float) -> tuple[dict, dict]:
    """tvgw-apply's counter listings either side of a reload at `t`: (files, mtimes) for gateway()."""
    files = {
        verify.RELOADS[0]: listing((GATE, before, 0)) + "\n",
        verify.RELOADS[1]: listing((GATE, after, 0)),
    }
    return files, {verify.RELOADS[0]: t, verify.RELOADS[1]: t + 0.05}


def test_a_reload_between_two_snapshots_loses_nothing(lg, tmp_path):
    """Reproduced on the live store: ten applies a day each zeroed every counter, and a step that
    accrued since the last 10-minute snapshot was lost at each one (the gate read 3 with 11 samples
    logged). The listings tvgw-apply takes either side of its reload are stored as snapshots of their
    own, once, so fw_activity sees the reset itself."""
    conn = db.connect(str(tmp_path / "v.db"))
    verify.record(conn, verify.Result(counters=[(GATE, 100, 0)], t=NOW - 600))
    files, mtimes = reload_files(130, 0, NOW - 300)  # 30 more before the reload, then zero
    host = gateway(
        {("nft", "-j", "list", "table", "inet", "tvgw_gate"): listing((GATE, 20, 0))}, files, mtimes
    )
    r = verify.check(S, lg, **host, resolve=resolver())
    assert [t for t, _ in r.reloads] == [NOW - 300, NOW - 299.95]
    verify.record(conn, r)
    assert dict(queries.fw_activity(conn, NOW - 3600, NOW + 1))[GATE] == 30 + 20  # was 20: the 30 were lost
    verify.record(conn, verify.check(S, lg, **host, resolve=resolver()))  # the same pair again: stored once
    assert conn.execute("SELECT COUNT(*) FROM fw_counters WHERE t < ?", (NOW - 200,)).fetchone() == (3,)


def test_a_reload_pair_older_than_the_last_snapshot_or_half_written_is_not_stored(lg, tmp_path):
    """An apply that ran while the last run was taking its snapshot, or a pair caught between its two
    renames, would read as a reset that never happened: counted twice is worse than lost."""
    conn = db.connect(str(tmp_path / "v.db"))
    verify.record(conn, verify.Result(counters=[(GATE, 100, 0)], t=NOW - 600))
    files, mtimes = reload_files(130, 0, NOW - 900)
    verify.record(conn, verify.check(S, lg, **gateway(files=files, mtimes=mtimes), resolve=resolver()))
    assert conn.execute("SELECT COUNT(*) FROM fw_counters WHERE t < ?", (NOW - 600,)).fetchone() == (0,)
    files, mtimes = reload_files(130, 0, NOW - 300)
    mtimes[verify.RELOADS[1]] = NOW - 900  # the after listing is the previous apply's
    assert verify.check(S, lg, **gateway(files=files, mtimes=mtimes), resolve=resolver()).reloads == []
    only_before = gateway(files={verify.RELOADS[0]: files[verify.RELOADS[0]]}, mtimes=mtimes)
    assert verify.check(S, lg, **only_before, resolve=resolver()).reloads == []


def test_a_second_network_path_in_the_tv_reading_fails_verify_and_an_unknown_one_does_not(lg):
    """Design decision 40. verify reads the last hourly TV reading file, never the TV."""
    reading = "read 2026-10-26T15:20:00-05:00\noption.livePlus = off\n"
    good = reading + "network.wired.state = connected\nnetwork.wifi.state = disconnected\n"
    good += "network.wifiDirect.state = disconnected\n"
    good += "network.wifi.tethering = off\nnetwork.bluetooth.tethering = off\npower = Active\n"
    r = verify.check(S, lg, **gateway(files={S.tvcheck_txt: good}), resolve=resolver())
    (c,) = [c for c in r.checks if c.name == "tv_paths"]
    assert c.ok and c.detail == (
        "wired connected, Wi-Fi disconnected, Wi-Fi Direct disconnected (read 2026-10-26T15:20:00-05:00)"
    )
    bad = good.replace("network.wifi.state = disconnected", "network.wifi.state = connected").replace(
        "network.bluetooth.tethering = off", "network.bluetooth.tethering = on"
    )
    r = verify.check(S, lg, **gateway(files={S.tvcheck_txt: bad}), resolve=resolver())
    (c,) = [c for c in r.checks if c.name == "tv_paths"]
    assert not c.ok and not r.ok
    assert c.detail == "second path: Wi-Fi connected, Bluetooth tethering on (read 2026-10-26T15:20:00-05:00)"
    # no reading, a reading without the keys, and a reading with a read error all pass and say why
    for text, detail in (
        ("", "no TV reading yet"),
        (reading, "the reading at 2026-10-26T15:20:00-05:00 has no network paths"),
        (
            reading + "network.paths = ERR RuntimeError 404\n",
            "the reading at 2026-10-26T15:20:00-05:00 has no network paths",
        ),
    ):
        r = verify.check(S, lg, **gateway(files={S.tvcheck_txt: text}), resolve=resolver())
        (c,) = [c for c in r.checks if c.name == "tv_paths"]
        assert c.ok and c.detail == detail, (text, c.detail)
    assert verify.reading_paths("garbage\nnetwork.wifi.state = connected\n") == ("", {})


# ---- (events) the flow log, the gate's fill and the VPN boundary (design decisions 43 and 44) ----


def flowlog_check(files=None, cmds=None, sockets=None, ruleset=RULESET):
    host = gateway(cmds, files)
    return verify.flowlog_check(host["run"], host["read"], ruleset, sockets or host["sockets"])


def test_the_flow_log_hears_the_tv_and_its_drop_count_is_a_counter_series(lg):
    check, drops = flowlog_check()
    assert check.ok and not check.warn and drops == 7
    assert check.detail == "TV connections only; 7 events dropped since the logger started"
    # two event sockets (a logger that subscribed twice) are summed
    two = [flowlog.NetlinkSocket(900 + i, 12, 1, 4, 3) for i in range(2)]
    assert flowlog_check(sockets=lambda pid: two)[1] == 6


def test_events_off_without_the_rule_is_a_flow_log_that_records_nothing():
    """nf_conntrack_events=0 gives events only to connections a rule marks: with the rule gone (a
    hand-edited table, an old tvgw-apply after a rollback) the logger runs and hears nothing."""
    bare = RULESET.replace("ct event set destroy", "accept")
    check, drops = flowlog_check(ruleset=bare)
    assert not check.ok and "no ct_events rule" in check.detail and drops is None
    # with the table not loaded at all the ruleset check is the one that fails; this one goes on
    assert flowlog_check(ruleset="")[0].ok


def test_events_at_the_kernel_default_work_but_warn():
    check, drops = flowlog_check(files={verify.EVENTS_KEY: "2\n"})
    assert check.ok and check.warn and drops == 7
    assert "nf_conntrack_events=2: every connection on the box" in check.detail
    assert check.line().startswith("WARN flowlog_events: ")


@pytest.mark.parametrize(
    ("pid", "sockets", "says"),
    [
        ("0\n", None, "has no running process"),
        ("", None, "has no running process"),
        ("4242\n", lambda pid: [], "holds no conntrack event socket"),
    ],
)
def test_a_logger_without_an_event_socket_fails(pid, sockets, says):
    cmds = {("systemctl", "show", "-p", "MainPID", "--value", "tvgw-flowlog"): pid}
    check, drops = flowlog_check(cmds=cmds, sockets=sockets)
    assert not check.ok and says in check.detail and drops is None


def test_descriptors_verify_may_not_read_say_so():
    def denied(pid):
        raise PermissionError(13, "Permission denied")

    check, drops = flowlog_check(sockets=denied)
    assert not check.ok and check.detail == "cannot read /proc/4242/fd (run as root)" and drops is None


def test_no_drop_snapshot_is_stored_when_no_socket_was_read(lg):
    cmds = {("systemctl", "show", "-p", "MainPID", "--value", "tvgw-flowlog"): "0\n"}
    r = verify.check(S, lg, **gateway(cmds), resolve=resolver())
    assert flowlog.DROPS_RULE not in [rule for rule, _, _ in r.counters]  # unknown, not zero


def test_the_flow_log_check_reads_a_real_proc_tree(lg, tmp_path):
    """main() hands check() flowlog.event_sockets; with a fake /proc it finds the logger's socket."""
    from test_flowlog import fake_proc

    proc = fake_proc(tmp_path)
    host = {**gateway(), "sockets": lambda pid: flowlog.event_sockets(pid, proc)}
    r = verify.check(S, lg, **host, resolve=resolver())
    assert (flowlog.DROPS_RULE, 31, 0) in r.counters


def gate_listing(n: int, size: int | None) -> str:
    s = {"name": "resolved4", "elem": [{"elem": {"val": f"203.0.113.{i}"}} for i in range(n)]}
    if size is not None:
        s["size"] = size
    return json.dumps({"nftables": [{"set": s}]})


def test_a_gate_set_over_half_full_warns_and_never_fails(lg):
    """A set near its size loses addresses; with the refresh it holds a day of distinct answers, so
    half full is the TV or the feeder doing something new. A warning: nothing about it is an outage."""
    key = ("nft", "-j", "list", "set", "inet", "tvgw_gate", "resolved4")
    full = verify.check(S, lg, **gateway({key: gate_listing(3, 4)}), resolve=resolver())
    gate = next(c for c in full.checks if c.name == "dnsgate")
    assert full.ok and gate.ok and gate.warn
    assert gate.detail == "3 of 4 addresses in the set, over 50%: what is the TV resolving?"
    half = verify.check(S, lg, **gateway({key: gate_listing(2, 4)}), resolve=resolver())
    assert not next(c for c in half.checks if c.name == "dnsgate").warn  # exactly half: no
    assert verify.set_fill(gate_listing(5, None)) == (5, verify.GATE_SIZE)  # size not printed
    assert verify.set_fill("") == (0, verify.GATE_SIZE)


def test_a_warning_reaches_the_json_and_a_plain_check_keeps_its_old_shape(lg, monkeypatch, capsys):
    key = ("nft", "-j", "list", "set", "inet", "tvgw_gate", "resolved4")
    patch_gateway(monkeypatch, gateway({key: gate_listing(3, 4)}))
    assert verify.main(S, lg, as_json=True) == 0
    checks = {c["name"]: c for c in json.loads(capsys.readouterr().out)["checks"]}
    assert checks["dnsgate"]["warn"] is True and "warn" not in checks["ruleset"]


def test_the_vpn_uplink_follows_the_tunnel_vpn_if_finds(lg):
    """PIA 3.8.0 makes WireGuard the default: with wgpia0 there and no tun0, auto expects wgpia0; a
    named tunnel is expected whether or not it is up."""
    vpn = Settings(**{**S.__dict__, "uplink": "vpn"})
    wg = {"/proc/sys/net/ipv4/conf/wgpia0/forwarding": "1\n"}
    route = {
        ("ip", "-j", "route", "get", "1.1.1.1", "from", "10.10.10.17", "iif", "eth0"): '[{"dev": "wgpia0"}]'
    }
    r = verify.check(vpn, lg, **gateway(route, wg), resolve=resolver())
    assert next(c for c in r.checks if c.name == "tv_route").ok
    assert next(c for c in r.checks if c.name == "forwarding").ok
    assert r.vpn == {"vpn_if": "auto", "device": "wgpia0", "pia": None}
    named = Settings(**{**vpn.__dict__, "vpn_if": "wg0"})
    r = verify.check(named, lg, **gateway(route, wg), resolve=resolver())
    assert "expected wg0" in next(c for c in r.checks if c.name == "tv_route").detail
    assert r.vpn["device"] == "wg0"


def test_pia_state_is_read_when_the_tool_answers_and_recorded_for_the_brief(lg, tmp_path):
    host = gateway(
        {tuple(verify.PIA_STATE): "Connected\n"}, {"/proc/sys/net/ipv4/conf/tun0/forwarding": "0\n"}
    )
    r = verify.check(S, lg, **host, resolve=resolver())
    assert r.vpn == {"vpn_if": "auto", "device": "tun0", "pia": "Connected"}
    assert verify.PIA_STATE[:2] == ["timeout", "5"]  # a daemon that hangs cannot hold the run
    conn = db.connect(str(tmp_path / "v.db"))
    verify.record(conn, r)
    assert queries.vpn_boundary(conn) == {**r.vpn, "t": r.t, "seen_t": r.t}
    # no tool: nothing to say, and the brief says nothing
    r = verify.check(S, lg, **gateway(), resolve=resolver())
    assert r.vpn["pia"] is None


@pytest.mark.parametrize(
    "out",
    [
        "Error: unable to connect to the daemon\n",
        "usage: piactl [options] command\n",
        "Private Internet Access 3.8.0\nConnected\n",  # a banner first is not a state
        "connected\n",
        "",
    ],
)
def test_only_a_state_piactl_knows_is_recorded_as_pias(lg, out):
    """An error, a usage message or a banner on stdout would otherwise read as PIA's state on the
    Coverage line, and turn on the leak red line's gate."""
    host = gateway({tuple(verify.PIA_STATE): out}, {"/proc/sys/net/ipv4/conf/tun0/forwarding": "0\n"})
    assert verify.check(S, lg, **host, resolve=resolver()).vpn["pia"] is None


def test_every_state_piactl_prints_is_kept(lg):
    for state in sorted(verify.PIA_STATES):
        assert verify.pia_state(f"  {state}\n") == state


def test_a_run_that_sees_a_vpn_marks_the_store_as_having_one_and_a_run_that_does_not_keeps_it(lg, tmp_path):
    conn = db.connect(str(tmp_path / "v.db"))
    host = gateway(
        {tuple(verify.PIA_STATE): "Connected\n"}, {"/proc/sys/net/ipv4/conf/tun0/forwarding": "0\n"}
    )
    seen = verify.check(S, lg, **host, resolve=resolver())
    verify.record(conn, seen)
    # the daemon down: no tunnel, and piactl answers nothing
    down = verify.check(S, lg, **gateway(), resolve=resolver())
    down.t = seen.t + 600
    verify.record(conn, down)
    boundary = queries.vpn_boundary(conn)
    assert boundary["device"] is None and boundary["pia"] is None
    assert boundary["seen_t"] == seen.t
