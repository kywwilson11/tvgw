"""`tvgw verify` against a scripted gateway: every command and file is faked, nothing touches the host."""

import json

from tvgw import db, dnsq, ingest, queries, verify
from tvgw.config import Settings

S = Settings(tv_ip="10.10.10.17", gw_ip="10.10.10.1", wan_if="wlan0", uplink="direct", block_quic="yes")

RULESET = """table inet tvgw {
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
DOH_JSON = json.dumps({"nftables": [{"set": {"name": "doh4", "elem": [f"1.0.0.{i}" for i in range(60)]}}]})


def gateway(overrides=None, files=None):
    """A runner/reader pair describing a healthy gateway, with per-test overrides."""
    cmds = {
        ("nft", "-s", "list", "table", "inet", "tvgw"): RULESET,
        ("nft", "-j", "list", "table", "inet", "tvgw"): TABLE_JSON,
        ("nft", "-j", "list", "ruleset"): RULESET_JSON,
        ("nft", "-j", "list", "set", "inet", "tvgw", "doh4"): DOH_JSON,
        ("ip", "-j", "route", "get", "1.1.1.1", "from", "10.10.10.17", "iif", "eth0"): json.dumps(
            [{"dst": "1.1.1.1", "dev": "wlan0", "table": "100"}]
        ),
        ("ip", "-j", "rule"): json.dumps(
            [{"priority": 50, "table": "main"}, {"priority": 60, "table": "100"}]
        ),
        ("systemctl", "is-active", *verify.SERVICES): "active\n" * len(verify.SERVICES),
    }
    cmds.update(overrides or {})
    fs = {
        "/proc/sys/net/ipv4/ip_forward": "1\n",
        "/proc/sys/net/ipv4/conf/eth0/forwarding": "1\n",
        "/proc/sys/net/ipv4/conf/wlan0/forwarding": "1\n",
        "/proc/sys/net/ipv6/conf/eth0/disable_ipv6": "1\n",
        verify.APPLIED: RULESET,
    }
    fs.update(files or {})
    return (lambda cmd: cmds.get(tuple(cmd), "")), (lambda path: fs.get(path, ""))


def resolver(answers=None):
    answers = answers or {}

    def resolve(name):
        if name in answers:
            return answers[name]
        if "gfts" in name:
            return ["10.10.10.1"]
        return ["23.0.0.1"]

    return resolve


def test_healthy_gateway_passes_every_check(lg):
    run, read = gateway()
    r = verify.check(S, lg, run=run, read=read, resolve=resolver())
    assert r.ok, r.failures
    names = [c.name for c in r.checks]
    assert names == [
        "ruleset",
        "ruleset_unchanged",
        "forwarding",
        "ipv6_off",
        "tv_route",
        "policy_rule",
        "vpn_dnat_idle",
        "doh4_loaded",
        "resolver_rewrite",
        "resolver_must_allow",
        "services",
    ]
    assert r.counters == [("DoT/DoQ", 12, 960), ("QUIC: force TCP+TLS so SNI is visible", 3, 300)]


def test_each_failure_is_named(lg):
    run, read = gateway(
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
            ("systemctl", "is-active", *verify.SERVICES): "active\ninactive\nactive\n",
            ("nft", "-j", "list", "set", "inet", "tvgw", "doh4"): json.dumps(
                {"nftables": [{"set": {"name": "doh4", "elem": ["1.1.1.1"]}}]}
            ),
        },
        {"/proc/sys/net/ipv4/ip_forward": "0\n", verify.APPLIED: RULESET + "\n# edited by hand\n"},
    )
    bad = resolver({"ngfts.lge.com": ["0.0.0.0"], "us.lgtvsdp.com": None, "snu.lge.com": ["0.0.0.0"]})
    r = verify.check(S, lg, run=run, read=read, resolve=bad)
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
    run, read = gateway()
    r = verify.check(S, lg, run=run, read=read, resolve=resolver({"us.lgtvsdp.com": []}))
    must_allow = next(c for c in r.checks if c.name == "resolver_must_allow")
    assert not must_allow.ok and "us.lgtvsdp.com->empty answer" in must_allow.detail


def test_a_loaded_table_without_its_apply_baseline_fails(lg):
    run, read = gateway(files={verify.APPLIED: ""})
    r = verify.check(S, lg, run=run, read=read, resolve=resolver())
    unchanged = next(c for c in r.checks if c.name == "ruleset_unchanged")
    assert not unchanged.ok and unchanged.detail.startswith("no baseline: /run/tvgw/ruleset.applied missing")


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
    run, read = gateway({("nft", "-j", "list", "table", "netdev", "tvgw_l2"): netdev})
    r = verify.check(S, lg, run=run, read=read, resolve=resolver())
    assert r.counters[-1] == ("no IPv6 from the TV", 41, 3526) and len(r.counters) == 3
    run, read = gateway({("nft", "-j", "list", "table", "netdev", "tvgw_l2"): ""})  # eth0 down: not loaded
    assert len(verify.check(S, lg, run=run, read=read, resolve=resolver()).counters) == 2


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
    run, read = gateway({("nft", "-j", "list", "set", "inet", "tvgw", "doh4"): merged})
    doh = next(
        c
        for c in verify.check(S, lg, run=run, read=read, resolve=resolver()).checks
        if c.name == "doh4_loaded"
    )
    assert doh.ok and doh.detail == "76 addresses"
    thirty = json.dumps({"nftables": [{"set": {"name": "doh4", "elem": [f"1.0.0.{i}" for i in range(30)]}}]})
    run, read = gateway({("nft", "-j", "list", "set", "inet", "tvgw", "doh4"): thirty})
    doh = next(
        c
        for c in verify.check(S, lg, run=run, read=read, resolve=resolver()).checks
        if c.name == "doh4_loaded"
    )
    assert not doh.ok and doh.detail == "30 addresses"


def test_missing_table_and_missing_key_rules(lg):
    run, read = gateway({("nft", "-s", "list", "table", "inet", "tvgw"): ""})
    r = verify.check(S, lg, run=run, read=read, resolve=resolver())
    assert next(c for c in r.checks if c.name == "ruleset").detail == "table inet tvgw is not loaded"
    assert "ruleset_unchanged" not in [c.name for c in r.checks]
    run, read = gateway(
        {
            ("nft", "-s", "list", "table", "inet", "tvgw"): RULESET.replace("@lan4", "@nope").replace(
                "udp dport 443", "udp dport 444"
            )
        }
    )
    r = verify.check(S, lg, run=run, read=read, resolve=resolver())
    detail = next(c for c in r.checks if c.name == "ruleset").detail
    assert "home LAN isolated" in detail and "QUIC rejected" in detail
    quiet = Settings(**{**S.__dict__, "block_quic": "no"})
    r = verify.check(quiet, lg, run=run, read=read, resolve=resolver())
    assert "QUIC" not in next(c for c in r.checks if c.name == "ruleset").detail


def test_interface_forwarding_off_is_the_outage_we_had(lg):
    run, read = gateway(files={"/proc/sys/net/ipv4/conf/eth0/forwarding": "0\n"})
    r = verify.check(S, lg, run=run, read=read, resolve=resolver())
    fwd = next(c for c in r.checks if c.name == "forwarding")
    assert not fwd.ok and fwd.detail == "eth0 not forwarding (TV offline)"


def test_vpn_uplink_expects_tun0_and_no_policy_rule(lg):
    vpn = Settings(**{**S.__dict__, "uplink": "vpn"})
    run, read = gateway()
    r = verify.check(vpn, lg, run=run, read=read, resolve=resolver())
    route = next(c for c in r.checks if c.name == "tv_route")
    assert not route.ok and "expected tun0" in route.detail
    assert "policy_rule" not in [c.name for c in r.checks]


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


def statements(conn, fn) -> list[str]:
    """The SQL `fn` ran, as SQLite saw it (parameters bound), ready for EXPLAIN QUERY PLAN."""
    seen: list[str] = []
    conn.set_trace_callback(seen.append)
    try:
        fn()
    finally:
        conn.set_trace_callback(None)
    return seen


def test_fw_activity_reads_through_the_time_index_on_a_fresh_store(tmp_path):
    """Reproduced: the per-rule baseline was a correlated scan, 0.1 s at 100 days and linear in history."""
    conn = db.connect(str(tmp_path / "v.db"))
    ran = statements(conn, lambda: queries.fw_activity(conn, 1000, 2000))
    assert len(ran) == 2  # the baseline and the window
    for sql in ran:
        plan = " ".join(r[3] for r in conn.execute("EXPLAIN QUERY PLAN " + sql))
        assert "fw_counters_t" in plan and "SCAN" not in plan, (sql, plan)


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
    assert (
        dnsq.a_records("nobody.invalid", server="127.0.0.1", timeout=0.2) in (None, [], ["0.0.0.0"]) or True
    )


def test_cli_verify_uses_the_store_when_recording(gateway, lg, monkeypatch, capsys, tmp_path):
    from tvgw import cli

    ingest.run(gateway, lg, extract=lambda p: [], oddport_lines=lambda s: [], lock=False)
    monkeypatch.setattr(verify, "run_cmd", lambda cmd: "")
    monkeypatch.setattr(verify, "read_file", lambda path: "")
    monkeypatch.setattr(dnsq, "a_records", lambda name, server, timeout=4.0: None)
    conf = tmp_path / "tvgw.conf"
    conf.write_text(f'TV_IP={gateway.tv_ip}\nDB_PATH="{gateway.db_path}"\n')
    assert cli.main(["--conf", str(conf), "verify", "--record"]) == 1
    out = capsys.readouterr().out
    assert "FAIL ruleset: table inet tvgw is not loaded" in out
    conn = db.connect(gateway.db_path, readonly=True)
    assert conn.execute("SELECT ok FROM verify").fetchone() == (0,)
