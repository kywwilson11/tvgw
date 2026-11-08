"""(inpath) What the gateway records of the DNS gate's in-path filler (design decision 64) and what it
ships to run it: verify's check and the counts it stores, the second count's samples in the store, both
counts side by side in the brief, and the deploy tree (tvgw-apply's block, the unit, the installer) as
text and against stub commands. The filler itself is tests/unit/test_inpath.py's."""

import io
import json
import re
import shutil
import sqlite3
import subprocess
from dataclasses import asdict, replace

import pytest
import test_apply
from conftest import JOURNAL_INPATH_LINES, ROOT, UNITS
from test_apply import CONF, STUBS, run_apply
from test_apply import scripts as nft_scripts
from test_apply_check import checked, run_check
from test_verify import GATE_TABLE, INPATH_TABLE, NOW, S, resolver
from test_verify import gateway as scripted

from tvgw import cli, config, db, forget, ingest, inpath, queries, verify

APPLY = (ROOT / "deploy" / "nftables" / "tvgw-apply").read_text(encoding="utf-8")
INSTALL = (ROOT / "deploy" / "install.sh").read_text(encoding="utf-8")
UNIT = (UNITS / "tvgw-dnsgate-inpath.service").read_text(encoding="utf-8")
ON = replace(S, dnsgate_fill="inpath")
LIST_GATE = ("nft", "list", "table", "inet", "tvgw_gate")
QUEUES = "53053   4242     0 2 65531     0     0     1234  1\n"


def status(**changes) -> str:
    stats = {**asdict(inpath.Stats()), "received": 42, "held": 30, "known": 8, "empty": 2}
    stats.update({"late": 1, "unparsed_tcp": 1, "addresses": 55})
    doc = {
        "v": 1,
        "pid": 4242,
        "started": NOW - 3 * 3600,
        "t": NOW - 5,
        "queue": inpath.QUEUE,
        "live": True,
        "set_missing": False,
        "stats": stats,
        "hold_us": {"n": 30, "p50": 410, "p99": 900, "max": 1200},
    }
    doc.update(changes)
    return json.dumps(doc)


LIST_FILL = ("nft", "-j", "list", "set", "inet", "tvgw_gate", inpath.SET)


def fill_json(n: int) -> str:
    elems = [{"elem": {"val": f"203.0.{i // 250}.{i % 250 + 1}"}} for i in range(n)]
    return json.dumps({"nftables": [{"set": {"name": inpath.SET, "size": 65536, "elem": elems}}]})


HALF_EMPTY = fill_json(55)


def check(s=ON, table=INPATH_TABLE, queues=QUEUES, doc=None, now=NOW, fill=HALF_EMPTY):
    files = {inpath.PROC_QUEUES: queues, inpath.STATUS: status() if doc is None else doc}
    cmds = {LIST_GATE: table, LIST_FILL: fill}
    return verify.inpath_check(s, lambda cmd: cmds.get(tuple(cmd), ""), lambda p: files.get(p, ""), now)


# ---- verify's check -----------------------------------------------------------------------------------


def test_a_gateway_that_never_asked_for_the_filler_passes_and_stores_nothing():
    c, series = check(S)
    assert (c.ok, c.warn, series) == (True, False, [])
    assert c.detail == "not in use (DNSGATE_FILL=passive): the passive feeder alone fills the gate's set"
    c, _ = check(replace(S, dnsgate="off", dnsgate_fill="inpath"))
    assert c.ok and not c.warn and "DNSGATE=off" in c.detail


def test_a_bound_live_filler_passes_and_its_counts_go_to_the_store_not_the_line():
    """The line names no count of answers: `tvgw verify` reaches the public hardware log, and how many
    answers the TV got over a known time is how much TV was watched (design decision 63)."""
    c, series = check()
    assert c.line() == (
        "OK   dnsgate_inpath: bound and holding, up 3 hours; the median hold is 0.41 ms; its counts are in"
        " the store (tvgw verify --record) and in /run/tvgw-dnsgate-inpath/status.json"
    )
    assert not re.search(r"\b(30|42|8)\b", c.detail)
    assert dict((rule, n) for rule, n, _ in series) == {
        "in-path: packets the filler received": 42,
        "in-path: answers held until their add": 30,
        "in-path: answers released at once, their addresses known": 8,
        "in-path: answers released late": 1,
        "in-path: answers released unadded": 0,
        "in-path: answers not parsed": 1,
        "in-path: packets the kernel passed itself": 0,
        "in-path: verdicts the kernel refused (answers it had dropped)": 0,
        "in-path: adds the kernel refused": 0,
        "in-path: adds not tried, the adder behind": 0,
        "in-path: internal errors": 0,
    }
    assert all(rule.startswith(inpath.RULE_PREFIX) for rule, _, _ in series)
    fields = {f for _, fs, _ in inpath.SERIES for f in fs}
    assert fields >= {"verdict_errors", "adds_failed", "adds_dropped", "errors"}


@pytest.mark.parametrize(
    ("kw", "says", "stored"),
    [
        ({"table": GATE_TABLE}, "missing: the in-path set, the live switch, the UDP queue rule", False),
        (
            {"queues": ""},
            "no process is bound to queue 53053: the kernel passes the TV's DNS answers itself",
            False,
        ),
        ({"queues": "    7   4242     0 2 65531     0     0     1234  1\n"}, "no process is bound", False),
        ({"doc": ""}, "bound, but its status file is missing", False),
        ({"doc": "not json"}, "bound, but its status file is missing", False),
        ({"doc": status(t=NOW - 600)}, "bound, but its status file is 10 minutes old", False),
        ({"doc": status(t=NOW + 600)}, "bound, but its status file is", False),  # a clock that stepped back
        ({"doc": status(stats="x")}, "bound, but its status file is", False),
        ({"doc": status(live=False)}, "bound, but no answer is offered to it: inpath_live is empty", True),
        (
            {"queues": "53053   4242    64 2 65531     0     0     1234  1\n"},
            "DNS answers are piling up in the queue",
            True,
        ),
        # the admitted drop: a hook removed while answers waited; the kernel's counters never show it
        (
            {"doc": status(dropped_1h=2)},
            "in the last hour the kernel dropped DNS answers that were waiting",
            True,
        ),
        ({"fill": fill_json(40000)}, "over 50% of resolved4_inpath is in use", True),
    ],
)
def test_every_other_finding_is_a_warning_and_never_fails_the_run(kw, says, stored):
    c, series = check(**kw)
    assert c.ok and c.warn and says in c.detail, c.line()
    assert not c.detail.endswith(verify.HELD)
    assert bool(series) == stored


def test_answers_the_kernel_dropped_are_the_one_finding_of_fail_level_held_while_the_check_is_new(
    monkeypatch,
):
    dropped = "53053   4242     0 2 65531     3     1     1234  1\n"
    c, series = check(queues=dropped)
    assert c.ok and c.warn and series == []
    assert c.detail == (
        "the kernel dropped 4 DNS answers for want of room in the queue: it is not configured fail-open,"
        " as the filler configures it" + verify.HELD
    )
    monkeypatch.setattr(verify, "PROMOTED", frozenset({"dnsgate_inpath"}))
    c, _ = check(queues=dropped)
    assert not c.ok and not c.detail.endswith(verify.HELD)
    c, _ = check(queues="")  # promoted or not, a filler that is down is a warning: the answers pass
    assert c.ok and c.warn


def test_a_status_file_with_odd_values_never_raises():
    for doc in (
        status(stats={"held": "many", "late": None}),
        status(hold_us=7),
        status(started="then"),
        "[]",
        "7",
    ):
        c, _ = check(doc=doc)
        assert c.ok, c.line()
    c, _ = check(doc=status(dropped_1h="many"))
    assert c.ok and not c.warn


def test_the_whole_run_carries_the_check_and_stores_the_fillers_counts(lg, tmp_path):
    files = {inpath.PROC_QUEUES: QUEUES, inpath.STATUS: status()}
    host = scripted({LIST_GATE: INPATH_TABLE}, files=files)
    r = verify.check(ON, lg, **host, resolve=resolver())
    assert r.ok, r.failures
    (c,) = [c for c in r.checks if c.name == "dnsgate_inpath"]
    assert c.ok and not c.warn and c.detail.startswith("bound and holding")
    names = [name for name, _, _ in r.counters]
    assert {rule for _, _, rule in inpath.SERIES} <= set(names)
    # a passive gateway's run stores none of them, and its services check never names the unit
    passive = verify.check(S, lg, **scripted(), resolve=resolver())
    assert not [name for name, _, _ in passive.counters if name.startswith(inpath.RULE_PREFIX)]
    conn = db.connect(str(tmp_path / "v.db"))
    verify.record(conn, r)
    stored = dict(conn.execute("SELECT rule, packets FROM fw_counters WHERE rule LIKE 'in-path:%'"))
    assert stored["in-path: answers held until their add"] == 30


def test_the_check_is_explained_grouped_and_among_the_new_ones():
    assert "dnsgate_inpath" in verify.PLAIN and verify.FAIL_AFTER["dnsgate_inpath"] == verify.FAIL
    assert "dnsgate_inpath" not in verify.PROMOTED and "dnsgate_inpath" not in verify.SETTLING
    assert "dnsgate_inpath" in verify.GROUPS["the TV's lookups go through the filter"]
    assert list(verify.PLAIN).index("dnsgate_inpath") == list(verify.PLAIN).index("dnsgate") + 1
    assert "tvgw-dnsgate-inpath" not in verify.SERVICES  # a filler that is down is no outage


# ---- the second count's samples in the store ------------------------------------------------------------

LINE = (
    "{t} homepi kernel: {prefix}: IN=eth0 OUT=wlan0 MAC=00:11:22:33:44:55:66:77:88:99:aa:bb:08:00 "
    "SRC=10.10.10.17 DST={dst} LEN=60 TOS=0x00 PREC=0x00 TTL=63 ID=0 DF PROTO=TCP SPT=4{n:04d} DPT={dport} "
    "WINDOW=65535 RES=0x00 SYN URGP=0"
)
BASE = 1793020000


def lines(rows, prefix="tvgw-inpath"):
    return [
        LINE.format(t=t, prefix=prefix, dst=dst, dport=dport, n=i) for i, (t, dst, dport) in enumerate(rows)
    ]


def test_the_two_log_prefixes_cannot_be_taken_for_each_other():
    """Each reader greps the kernel journal for its prefix; a prefix that held the other's would put
    the in-path samples into the passive table, or the passive ones into this."""
    assert inpath.LOG_PREFIX == "tvgw-inpath"
    assert "tvgw-gate" not in inpath.LOG_PREFIX and inpath.LOG_PREFIX not in "tvgw-gate"
    seen = []

    def run(argv, **kw):
        seen.append(argv)
        return subprocess.CompletedProcess(argv, 0, "", "")

    ingest.journal_gate_lines("-1h", run)
    JOURNAL_INPATH_LINES("-1h", run)  # the real reader: an autouse fixture stands in for it elsewhere
    assert [a[a.index("-g") + 1] for a in seen] == ["tvgw-gate", "tvgw-inpath"]
    assert all("_TRANSPORT=kernel" in a for a in seen)  # the kernel's lines only, never a unit's journal
    assert not re.search("tvgw-gate", lines([(BASE, "203.0.113.9", 443)])[0])
    assert f'log prefix "{inpath.LOG_PREFIX}: "' in APPLY


def test_in_path_samples_land_once_in_a_table_of_their_own(tmp_path):
    conn = db.connect(str(tmp_path / "g.db"))
    rows = [(BASE + 10.25, "203.0.113.9", 443), (BASE + 20.5, "198.51.100.4", 8080)]
    assert ingest.ingest_gate_inpath(conn, lambda since: lines(rows)) == 2
    assert ingest.ingest_gate_inpath(conn, lambda since: lines(rows)) == 0  # the cursor skips what is stored
    assert conn.execute("SELECT t, proto, dst, dport FROM gate_inpath ORDER BY t").fetchall() == [
        (BASE + 10.25, "TCP", "203.0.113.9", 443),
        (BASE + 20.5, "TCP", "198.51.100.4", 8080),
    ]
    assert conn.execute("SELECT COUNT(*) FROM gate").fetchone() == (0,)  # the passive table is untouched
    raw = conn.execute("SELECT raw FROM gate_inpath").fetchone()[0]
    assert "homepi" not in raw and "00:11:22" not in raw  # scrubbed at ingest, as gate's lines are
    assert conn.execute("SELECT last_t FROM ingest_state WHERE source='gate_inpath'").fetchone() == (
        BASE + 20.5,
    )


def test_the_hourly_run_reads_the_samples_and_prunes_them(gateway, lg, monkeypatch):
    monkeypatch.setattr(ingest, "journal_gate_lines", lambda since: [])
    st = ingest.run(
        gateway,
        lg,
        extract=lambda path: [],
        oddport_lines=lambda since: [],
        gate_lines=lambda since: [],
        inpath_lines=lambda since: lines([(1793020250.0, "203.0.113.8", 443)]),
    )
    assert st.gate_inpath == 1 and st.gate == 0
    conn = db.connect(gateway.db_path)
    assert conn.execute("SELECT dport FROM gate_inpath").fetchall() == [(443,)]
    assert "gate_inpath" in json.loads(db.get_meta(conn, "sources_read"))
    ingest.prune(conn, 1, now=1793020250.0 + 3 * 86400)
    assert conn.execute("SELECT COUNT(*) FROM gate_inpath").fetchone() == (0,)
    conn.close()


def test_a_schema_10_store_gains_the_table_and_keeps_its_rows(tmp_path):
    cut = (
        "-- (inpath) schema 11: gate's twin for the in-path filler's count (design decision 64)\n"
        "CREATE TABLE IF NOT EXISTS gate_inpath(id INTEGER PRIMARY KEY, t REAL NOT NULL, proto TEXT, dst TEXT,\n"
        "  dport INTEGER, raw TEXT);\nCREATE INDEX IF NOT EXISTS gate_inpath_t ON gate_inpath(t);\n"
    )
    assert cut in db.SCHEMA
    path = str(tmp_path / "old.db")
    old = sqlite3.connect(path)
    old.executescript(db.SCHEMA.replace(cut, ""))
    old.execute("INSERT INTO meta(key, value) VALUES ('schema', '10')")
    old.execute("INSERT INTO gate(t, proto, dst, dport, raw) VALUES (1, 'TCP', '203.0.113.9', 443, 'x')")
    old.commit()
    assert not old.execute("SELECT 1 FROM sqlite_master WHERE name='gate_inpath'").fetchone()
    # a read-only reader of that store still gets its brief's gate section, with no in-path half
    assert queries.gate_inpath(old, 0, 10, {}) is None
    old.close()
    conn = db.connect(path)
    assert db.SCHEMA_VERSION >= 11 and db.get_meta(conn, "schema") == str(db.SCHEMA_VERSION)
    assert [r[1] for r in conn.execute("PRAGMA table_info(gate_inpath)")] == [
        "id", "t", "proto", "dst", "dport", "raw",
    ]  # fmt: skip
    assert conn.execute("SELECT COUNT(*) FROM gate").fetchone() == (1,)
    assert "gate_inpath" in db.counts(conn)
    plan = [r[3] for r in conn.execute("EXPLAIN QUERY PLAN SELECT * FROM gate_inpath WHERE t >= 1 AND t < 2")]
    assert any("gate_inpath_t" in step for step in plan)
    assert forget.TABLES["gate_inpath"][0] == forget.FORGET and forget.TIME_COLUMNS["gate_inpath"] == "t"


# ---- both counts in the brief ---------------------------------------------------------------------------


def snapshots(conn, rows):
    conn.executemany("INSERT INTO fw_counters(t, rule, packets, bytes) VALUES (?, ?, ?, 0)", rows)


def test_a_series_gains_what_its_own_snapshots_say_through_a_restart(tmp_path):
    conn = db.connect(str(tmp_path / "s.db"))
    rule = "in-path: answers held until their add"
    snapshots(
        conn,
        [(BASE - 600, rule, 100), (BASE + 600, rule, 130), (BASE + 1200, rule, 5), (BASE + 1800, rule, 9)],
    )
    # another rule's snapshot between them (an apply's reload listing) is no baseline of this series
    snapshots(conn, [(BASE - 60, "TV to an address DNS never returned", 0)])
    assert queries.series_gain(conn, rule, BASE, BASE + 3600) == 30 + 5 + 4
    assert queries.series_gain(conn, rule, BASE + 700, BASE + 3600) == 5 + 4  # a restart: all of 5 is new
    assert queries.series_gain(conn, "in-path: answers released late", BASE, BASE + 3600) == 0
    fresh = db.connect(str(tmp_path / "t.db"))
    snapshots(fresh, [(BASE + 600, rule, 130), (BASE + 1200, rule, 140)])
    assert queries.series_gain(fresh, rule, BASE, BASE + 3600) == 10  # no baseline: the first is one


def both_counts(tmp_path):
    conn = db.connect(str(tmp_path / "b.db"))
    ingest.ingest_gate(conn, lambda since: lines([(BASE + 10, "96.6.235.59", 443)] * 1, "tvgw-gate"))
    rows = [
        (BASE + 40, "203.0.113.9", 443),
        (BASE + 70, "198.51.100.4", 443),
        (BASE + 75, "198.51.100.4", 443),
    ]
    ingest.ingest_gate_inpath(conn, lambda since: lines(rows))
    conn.execute(
        "INSERT INTO dns(t, qname, qtype, answers, blocked) VALUES (?, 'cdn.example', 'A', 'A:203.0.113.9', 0)",
        (BASE + 39.9,),
    )
    for t, passive, miss, udp, tcp in ((BASE - 600, 0, 0, 0, 0), (BASE + 600, 80, 3, 400, 2)):
        snapshots(
            conn,
            [
                (t, "TV to an address DNS never returned", passive),
                (t, inpath.MISS_RULE, miss),
                (t, inpath.OFFERED_RULES[0], udp),
                (t, inpath.OFFERED_RULES[1], tcp),
                (t, "DoT/DoQ", 4),
            ],
        )
    for key, _fields, rule in inpath.SERIES:
        gained = {"received": 399, "held": 300, "known": 90, "late": 1, "unparsed": 2}.get(key, 0)
        snapshots(conn, [(BASE - 600, rule, 1000), (BASE + 600, rule, 1000 + gained)])
    conn.commit()
    return conn


def test_the_brief_shows_both_counts_side_by_side(tmp_path, lg):
    conn = both_counts(tmp_path)
    o = queries.window_report(conn, BASE - 1000, BASE + 1000, lg, now=BASE + 1000)
    gate = o["gate"]
    assert gate["new_connections"] == 80  # the passive count, as before
    fill = gate["inpath"]
    assert (fill["new_connections"], fill["offered"]) == (3, 402)
    assert fill["filler"] == {
        "received": 399, "held": 300, "known": 90, "late": 1, "failed": 0, "unparsed": 2, "kernel_passed": 0,
        "verdict_errors": 0, "adds_failed": 0, "adds_dropped": 0, "errors": 0,
    }  # fmt: skip
    by_dst = {e["dst"]: e for e in fill["examples"]}
    assert by_dst["203.0.113.9"]["late"] == 1  # 100 ms after an answer naming it: the filler did not hold it
    assert (by_dst["198.51.100.4"]["n"], by_dst["198.51.100.4"]["late"]) == (2, 0)
    # the filler's counters are no firewall evidence: not in the activity, so not in the analyst's pack
    rules = [x["rule"] for x in o["firewall"]["activity"]]
    assert "DoT/DoQ" in rules and not [r for r in rules if r.startswith(inpath.RULE_PREFIX)]
    buf = io.StringIO()
    cli.render_brief(o, buf)
    text = buf.getvalue()
    assert "DNS-gated egress (count-only): 80 new connections" in text
    assert (
        "  in-path filler (count-only, beside the passive feeder): passive feeder 80 misses, in-path 3 misses;"
        " answers offered 402: held 300, released at once 90, late 1, unadded 0, not parsed 2,"
        " passed by the kernel 3" in text
    )
    assert "in-path misses, logged samples" in text and "198.51.100.4" in text
    assert "Firewall held:" in text and "in-path" not in text.split("Firewall held:")[1].splitlines()[0]


def test_the_in_path_count_is_never_below_its_logged_samples(tmp_path, lg):
    conn = both_counts(tmp_path)
    conn.execute("DELETE FROM fw_counters WHERE rule = ? AND t > ?", (inpath.MISS_RULE, BASE))
    snapshots(conn, [(BASE + 600, inpath.MISS_RULE, 1)])  # an apply zeroed the counter after two of three
    conn.commit()
    o = queries.window_report(conn, BASE - 1000, BASE + 1000, lg, now=BASE + 1000)
    assert o["gate"]["inpath"]["new_connections"] == 3


def test_a_passive_gateways_brief_has_no_in_path_half(tmp_path, lg):
    conn = db.connect(str(tmp_path / "p.db"))
    ingest.ingest_gate(conn, lambda since: lines([(BASE + 10, "96.6.235.59", 443)], "tvgw-gate"))
    snapshots(conn, [(BASE - 600, queries.GATE_RULE, 0), (BASE + 600, queries.GATE_RULE, 7)])
    conn.commit()
    o = queries.window_report(conn, BASE - 1000, BASE + 1000, lg, now=BASE + 1000)
    assert "inpath" not in o["gate"] and o["gate"]["new_connections"] == 7
    buf = io.StringIO()
    cli.render_brief(o, buf)
    assert "in-path" not in buf.getvalue()


def test_an_in_path_count_of_zero_is_still_shown_beside_the_passive_one(tmp_path, lg):
    """The result the comparison is for: the passive feeder counts its race, the in-path rule nothing."""
    conn = db.connect(str(tmp_path / "z.db"))
    snapshots(conn, [(BASE - 600, queries.GATE_RULE, 0), (BASE + 600, queries.GATE_RULE, 67)])
    snapshots(conn, [(BASE - 600, inpath.MISS_RULE, 0), (BASE + 600, inpath.MISS_RULE, 0)])
    conn.commit()
    o = queries.window_report(conn, BASE - 1000, BASE + 1000, lg, now=BASE + 1000)
    assert o["gate"]["inpath"]["new_connections"] == 0 and o["gate"]["inpath"]["examples"] == []
    buf = io.StringIO()
    cli.render_brief(o, buf)
    assert "passive feeder 67 misses, in-path 0 misses" in buf.getvalue()


def test_the_names_the_store_and_the_script_share():
    assert queries.INPATH_RULE == inpath.RULE_PREFIX
    assert not inpath.MISS_RULE.startswith(queries.GATE_RULE) and queries.GATE_RULE not in inpath.MISS_RULE
    comments = set(re.findall(r'comment "(in-path: [^"]+)"', APPLY))
    assert comments == {inpath.MISS_RULE, *inpath.OFFERED_RULES}
    for _key, fields, rule in inpath.SERIES:
        assert rule.startswith(inpath.RULE_PREFIX) and rule not in comments
        assert set(fields) <= set(asdict(inpath.Stats()))
    assert len({rule for _, _, rule in inpath.SERIES}) == len(inpath.SERIES)
    assert not any(c.startswith(p) for c in comments for p, _ in queries.FW_LINES)


# ---- tvgw-apply -------------------------------------------------------------------------------------------

BLOCK = re.compile(r"# ---- \(inpath\) begin.*?# ---- \(inpath\) end ----\n", re.S)
APPLIED_LINE = re.compile(r"^printf '%s=%s\\n' DNSGATE_FILL .*\n", re.M)
needs_bash = pytest.mark.skipif(shutil.which("bash") is None, reason="tvgw-apply is a bash script")


def test_the_script_and_the_filler_agree_on_every_name():
    (queue,) = re.findall(r"^INPATH_QUEUE=(\d+)", APPLY, re.M)
    assert int(queue) == inpath.QUEUE and "bypass to $INPATH_QUEUE" in APPLY
    assert (
        f"add set inet {inpath.TABLE} {inpath.SET} {{ type ipv4_addr; flags timeout; size 65536; }}" in APPLY
    )
    assert f"add set inet {inpath.TABLE} {inpath.LIVE_SET} {{ type inet_service; }}" in APPLY
    assert APPLY.count(f"sport @{inpath.LIVE_SET}") == 2 and inpath.LIVE_KEY == b"\x00\x35"
    # (revert) the fourth quiets the queue before a held apply's restore
    assert len(BLOCK.findall(APPLY)) == 4 and len(APPLIED_LINE.findall(APPLY)) == 1
    # no rule of the block can refuse or change a packet: it counts, logs and queues with bypass
    (rules,) = re.findall(
        r"add table inet tvgw_gate\nadd set inet tvgw_gate resolved4_inpath.*?\nEOF", APPLY, re.S
    )
    assert not re.search(r"\b(drop|reject|dnat|snat|masquerade|redirect|notrack|jump|goto)\b|mark set", rules)
    assert rules.count("queue flags bypass to") == rules.count(" queue ") == 2
    assert verify.GATE_SIZE == 65536


QUIET = [  # inpath_quiet's commands where an earlier apply left the in-path half, in order
    "list chain inet tvgw_gate forward_inpath",
    # one transaction: no answer is offered to the queue any more, and the filler cannot switch on again
    "flush chain inet tvgw_gate answers; delete set inet tvgw_gate inpath_live",
    "delete chain inet tvgw_gate answers",  # the first hook to go, after the wait for the queue
]
REST = [  # after them, when the settings no longer ask for the filler; the chain it looks for goes last
    "delete set inet tvgw_gate inpath_live",
    "flush chain inet tvgw_gate forward_inpath",
    "delete set inet tvgw_gate resolved4_inpath",
    "delete set inet tvgw_gate seen4_inpath",
    "delete chain inet tvgw_gate forward_inpath",
]


def nft_calls(tmp_path) -> list[str]:
    return (tmp_path / "stub" / "nft.calls").read_text(encoding="utf-8").splitlines()


@needs_bash
def test_inpath_loads_its_block_last_and_leaves_the_gates_load_alone(tmp_path):
    assert run_apply(tmp_path / "passive").returncode == 0
    out = run_apply(tmp_path / "inpath", conf=CONF + "DNSGATE_FILL=inpath\n")
    assert out.returncode == 0, out.stderr
    passive, loaded = nft_scripts(tmp_path / "passive"), nft_scripts(tmp_path / "inpath")
    assert len(loaded) == len(passive) + 1 and loaded[:4] == passive[:4]  # the four loads, byte for byte
    block = loaded[4].splitlines()
    assert block[0] == "add table inet tvgw_gate"
    assert block[4:] == [
        "add chain inet tvgw_gate answers { type filter hook output priority filter + 5; policy accept; }",
        "flush chain inet tvgw_gate answers",
        'add rule inet tvgw_gate answers oifname "eth0" ip daddr 10.10.10.0/24 udp sport @inpath_live counter'
        ' queue flags bypass to 53053 comment "in-path: UDP answers offered to the filler"',
        'add rule inet tvgw_gate answers oifname "eth0" ip daddr 10.10.10.0/24 tcp sport @inpath_live tcp flags'
        " & (syn | rst) == 0 counter queue flags bypass to 53053"
        ' comment "in-path: TCP answers offered to the filler"',
        "add chain inet tvgw_gate forward_inpath { type filter hook forward priority filter - 4; policy accept; }",
        "flush chain inet tvgw_gate forward_inpath",
        'add rule inet tvgw_gate forward_inpath iifname "eth0" ip saddr 10.10.10.0/24 ct state new ip daddr !='
        " 10.10.10.1 ip daddr != @resolved4_inpath ip saddr . ip daddr . meta l4proto . th sport . th dport !="
        " @seen4_inpath add @seen4_inpath { ip saddr . ip daddr . meta l4proto . th sport . th dport } counter"
        ' limit rate 6/minute log prefix "tvgw-inpath: " comment "in-path: TV to an address the filler never added"',
    ]
    used = config.parse_conf(
        (tmp_path / "inpath" / "run" / "tvgw" / "settings.applied").read_text(encoding="utf-8")
    )
    assert used["DNSGATE_FILL"] == "inpath"
    used.pop("WAN_GW_USED")
    assert used == verify.apply_settings(CONF + "DNSGATE_FILL=inpath\n")
    # before the first load (the stub says an earlier apply left the switch): the switch off, the queue
    # rules and the set away, and nothing of the second count, which this apply keeps
    calls = nft_calls(tmp_path / "inpath")
    at = calls.index(QUIET[0])
    assert calls[at : at + len(QUIET)] == QUIET and at < calls.index("-f -")
    assert not [c for c in calls if any(rest == c for rest in REST)]
    # with the headers capture, whose load deletes a table, the block still comes last
    out = run_apply(tmp_path / "headers", conf=CONF + "DNSGATE_FILL=inpath\nCAPTURE_MODE=headers\n")
    assert out.returncode == 0, out.stderr
    last = nft_scripts(tmp_path / "headers")
    assert "tvgw_capture" in last[-2] and last[-1] == loaded[4]


@needs_bash
def test_passive_is_byte_for_byte_the_script_without_the_blocks(tmp_path, monkeypatch):
    """DNSGATE_FILL=passive, said or not: every script handed to nft, and every other nft call but
    inpath_quiet's, is what the script with the three (inpath) blocks and the settings line cut out
    hands it. The stub says an earlier inpath apply left its switch, so everything of it is deleted, by
    plain commands, in order, before the first load."""
    cut = APPLIED_LINE.sub("", BLOCK.sub("", APPLY))
    assert "inpath" not in cut and "DNSGATE_FILL" not in cut
    for n, conf in enumerate(
        (CONF, CONF + "DNSGATE_FILL=passive\n", CONF + "UPLINK=vpn\nCAPTURE_MODE=headers\n")
    ):
        now, before = tmp_path / f"now{n}", tmp_path / f"cut{n}"
        assert run_apply(now, conf=conf).returncode == 0
        with monkeypatch.context() as m:  # the same run with the script as it was before the blocks existed
            m.setattr(test_apply, "APPLY", cut)
            assert run_apply(before, conf=conf).returncode == 0
        assert nft_scripts(now) == nft_scripts(before)
        calls = nft_calls(now)
        left_over = [*QUIET, *REST]
        at = calls.index(left_over[0])
        assert calls[at : at + len(left_over)] == left_over and at < calls.index("-f -")
        assert calls[:at] + calls[at + len(left_over) :] == nft_calls(before)
        used = (now / "run" / "tvgw" / "settings.applied").read_text(encoding="utf-8")
        assert used == (before / "run" / "tvgw" / "settings.applied").read_text() + "DNSGATE_FILL=passive\n"


@needs_bash
def test_a_gateway_with_no_switch_left_asks_once_and_deletes_nothing(tmp_path):
    no_set = STUBS["nft"].replace(
        'case "$*" in\n', 'case "$*" in\n"list chain inet tvgw_gate forward_inpath") exit 1 ;;\n', 1
    )
    for name, conf in (("passive", CONF), ("inpath", CONF + "DNSGATE_FILL=inpath\n")):
        assert run_apply(tmp_path / name, conf=conf, stubs={"nft": no_set}).returncode == 0
        calls = nft_calls(tmp_path / name)
        assert calls.count(QUIET[0]) == 1 and calls.index(QUIET[0]) < calls.index("-f -")
        assert not [c for c in calls if c in QUIET[1:] or c in REST]


def test_the_queue_is_quieted_after_the_counters_are_listed_and_before_every_load():
    """The listing first, so the queue rules' counts reach the store before their chain goes; then
    inpath_quiet; then the loads. And the in-path block is the last load: after it the filler may
    switch on again, so nothing after it may delete a table."""
    listed = APPLY.index("counters >/run/tvgw/counters.before-apply.tmp")
    quiet = APPLY.index("\ninpath_quiet\n")
    # (probe) the filter is rendered first (inet_ruleset) and loaded from INET_RULES; the render is after the quiet too
    first_load = APPLY.index("INET_RULES=$(inet_ruleset && echo .)")
    assert quiet < APPLY.index("inet_ruleset() {")
    block = APPLY.index("add set inet tvgw_gate resolved4_inpath")
    assert listed < quiet < first_load < block
    after = APPLY[block:]
    after = after[after.index("\nEOF\n") :]
    assert "delete table" not in after and "nft -f" not in after
    assert "sleep 0.01" in APPLY and "nfnetlink_queue" in APPLY  # it waits for the queue to empty


@needs_bash
def test_the_block_needs_the_gate_and_a_refusal_only_warns(tmp_path):
    off = run_apply(tmp_path / "off", conf=CONF + "DNSGATE=off\nDNSGATE_FILL=inpath\n")
    assert off.returncode == 0 and not [s for s in nft_scripts(tmp_path / "off") if "inpath" in s]
    keep = 'cat >"$STUB_DIR/nft-script.$n" ;;'
    refuses = STUBS["nft"].replace(
        keep, 'cat >"$STUB_DIR/nft-script.$n"; ! grep -q inpath_live "$STUB_DIR/nft-script.$n" || exit 1 ;;'
    )
    out = run_apply(tmp_path / "refused", conf=CONF + "DNSGATE_FILL=inpath\n", stubs={"nft": refuses})
    assert out.returncode == 0, out.stderr
    assert "tvgw: in-path gate rules not loaded; DNS answers pass unheld" in out.stderr
    forwarding = tmp_path / "refused" / "proc" / "sys" / "net" / "ipv4" / "conf" / "eth0" / "forwarding"
    assert forwarding.read_text(encoding="utf-8") == "1\n"  # the TV is online all the same
    bad = run_apply(tmp_path / "bad", conf=CONF + "DNSGATE_FILL=enforce\n")
    assert bad.returncode == 1 and "DNSGATE_FILL must be passive or inpath" in bad.stderr
    assert not (tmp_path / "bad" / "stub" / "nft.calls").exists()  # refused before anything was loaded


@needs_bash
def test_the_check_renders_the_block_only_for_inpath_and_never_the_clean_up(tmp_path):
    out = run_check(tmp_path / "in", conf=CONF + "DNSGATE_FILL=inpath\n")
    assert out.returncode == 0, out.stderr
    rendered = checked(tmp_path / "in")
    assert len(rendered) == 5 and rendered[4].startswith(
        "add table inet tvgw_gate\nadd set inet tvgw_gate resolved4_inpath"
    )
    assert out.stdout == "".join(rendered)
    plain = run_check(tmp_path / "plain")
    said = run_check(tmp_path / "said", conf=CONF + "DNSGATE_FILL=passive\n")
    assert plain.stdout == said.stdout and "inpath" not in plain.stdout and "in-path" not in plain.stdout
    assert out.stdout.startswith(plain.stdout)  # the four loads as they were, then the block


# ---- the unit and the installer ---------------------------------------------------------------------------


def unit_value(key: str) -> str:
    (value,) = re.findall(rf"^{key}=(.*)$", UNIT, re.M)
    return value


def test_the_watchdog_outlasts_four_pings_and_kills_with_a_signal_that_cannot_wait():
    assert (unit_value("Type"), unit_value("NotifyAccess")) == ("notify", "main")
    assert float(unit_value("WatchdogSec")) >= 4 * inpath.PING_EVERY
    assert float(unit_value("WatchdogSec")) <= 2  # the longest a hung filler may hold the TV's answers
    assert unit_value("WatchdogSignal") == "SIGKILL"
    assert unit_value("Restart") == "on-failure" and unit_value("RestartSteps") == "6"
    assert unit_value("ExecStart") == "/usr/local/bin/tvgw dnsgate-inpath"
    assert f"/run/{unit_value('RuntimeDirectory')}/status.json" == inpath.STATUS
    assert (
        unit_value("RuntimeDirectory") != "tvgw"
    )  # systemd removes it at stop: never the firewall's /run/tvgw


def test_the_unit_is_sandboxed_like_the_feeder_with_one_capability_fewer():
    feeder = (UNITS / "tvgw-dnsgate.service").read_text(encoding="utf-8").splitlines()
    mine = UNIT.splitlines()
    for line in feeder:
        if line.startswith(
            ("NoNewPrivileges", "Protect", "PrivateTmp", "SystemCallArch", "RestrictRealtime", "MemoryMax")
        ):
            assert line in mine, line
    assert unit_value("CapabilityBoundingSet") == unit_value("AmbientCapabilities") == "CAP_NET_ADMIN"
    assert unit_value("RestrictAddressFamilies") == "AF_NETLINK AF_UNIX"  # no packet socket, no network
    assert "After=tvgw.service" in mine and "Wants=tvgw.service" in mine
    assert not [line for line in mine if line.startswith(("Requires=", "BindsTo=", "Requisite="))]


@pytest.mark.parametrize(
    ("conf", "status"),
    [
        (None, 1),  # no settings file: passive
        ("", 1),
        ("DNSGATE_FILL=passive\n", 1),
        ("DNSGATE_FILL=inpath\n", 0),
        ("DNSGATE_FILL=\n", 1),
        ("DNSGATE=count\nDNSGATE_FILL=inpath\n", 0),
        ("DNSGATE=off\nDNSGATE_FILL=inpath\n", 1),  # no gate, nothing to fill
        ("DNSGATE_FILL=Inpath\n", 255),
        ("DNSGATE_FILL=inpath # both fillers\n", 0),
    ],
)
def test_the_units_condition_runs_it_only_when_the_settings_ask(tmp_path, conf, status):
    sh = shutil.which("sh")
    if sh is None:
        pytest.skip("needs sh")
    line = unit_value("ExecCondition")
    assert line.startswith("/bin/sh -c '") and line.endswith("'")
    script = line[len("/bin/sh -c '") : -1].replace("$$", "$")
    path = tmp_path / "tvgw.conf"
    if conf is not None:
        path.write_text(conf, encoding="utf-8")
    out = subprocess.run(
        [sh, "-c", script.replace("/etc/tvgw/tvgw.conf", str(path))], capture_output=True, text=True
    )
    assert out.returncode == status, out.stderr


def installer_block(tmp_path, settings: str, enable_fails: bool = False) -> tuple[int, list[str], str]:
    """install.sh's (inpath) block, run under its own `set -euo pipefail` with a fake systemctl and a
    restart_changed that records its call."""
    bash = shutil.which("bash")
    if bash is None:
        pytest.skip("install.sh is a bash script")
    (block,) = re.findall(r"# \(inpath\) The DNS gate's in-path filler.*?\nfi\n", INSTALL, re.S)
    fake = tmp_path / "systemctl"
    fails = "enable" if enable_fails else "never"
    fake.write_text(f'#!/bin/sh\necho "$*" >>{tmp_path}/calls\n[ "$1" != {fails} ]\n', encoding="utf-8")
    fake.chmod(0o755)
    (tmp_path / "calls").write_text("", encoding="utf-8")
    script = (
        f"set -euo pipefail\nPATH={tmp_path}:$PATH\n{settings}\n"
        f'restart_changed() {{ echo "restart_changed $*" >>{tmp_path}/calls; }}\n{block}echo done\n'
    )
    out = subprocess.run([bash, "-c", script], capture_output=True, text=True, encoding="utf-8")
    return (
        out.returncode,
        (tmp_path / "calls").read_text(encoding="utf-8").splitlines(),
        out.stdout + out.stderr,
    )


@pytest.mark.parametrize(
    "settings", ["", "DNSGATE_FILL=passive", "DNSGATE=off; DNSGATE_FILL=inpath", "DNSGATE_FILL="]
)
def test_the_installer_leaves_the_unit_disabled_unless_the_settings_ask(tmp_path, settings):
    rc, calls, out = installer_block(tmp_path, settings)
    assert rc == 0 and calls == ["disable --now tvgw-dnsgate-inpath.service"] and out.strip() == "done"


def test_the_installer_enables_and_restarts_the_unit_for_inpath_and_never_fails_on_it(tmp_path):
    (tmp_path / "ok").mkdir()
    rc, calls, out = installer_block(tmp_path / "ok", "DNSGATE_FILL=inpath")
    assert rc == 0 and calls == [
        "enable --now tvgw-dnsgate-inpath.service",
        "restart_changed tvgw-dnsgate-inpath",
    ]
    (tmp_path / "bad").mkdir()
    rc, calls, out = installer_block(tmp_path / "bad", "DNSGATE_FILL=inpath", enable_fails=True)
    assert rc == 0 and calls == ["enable --now tvgw-dnsgate-inpath.service"]
    assert "WARNING: tvgw-dnsgate-inpath did not start" in out and "done" in out.splitlines()


def test_the_unit_is_enabled_nowhere_else_and_removed_with_the_package():
    assert INSTALL.count("tvgw-dnsgate-inpath.service") == 2  # the enable and the disable of the block
    enable_all = next(
        line for line in INSTALL.splitlines() if line.startswith("systemctl enable --now tvgw-flowlog")
    )
    assert "inpath" not in enable_all
    case = next(ln for ln in INSTALL.splitlines() if ln.strip().startswith("tvgw-dnsgate |"))
    assert "tvgw-dnsgate-inpath" in case.split(")")[0].split(" | ")  # restarted on the feeder's changes
    prerm = (ROOT / "packaging" / "scripts" / "prerm").read_text(encoding="utf-8")
    assert "systemctl disable --now tvgw-dnsgate-inpath.service >/dev/null 2>&1 || true" in prerm
    example = (ROOT / "deploy" / "tvgw.conf.example").read_text(encoding="utf-8")
    assert re.search(r"^DNSGATE_FILL=passive$", example, re.M)


def test_the_command_exists_and_does_nothing_on_a_passive_gateway(tmp_path, capsys):
    conf = tmp_path / "tvgw.conf"
    conf.write_text("TV_IP=10.10.10.17\n", encoding="utf-8")
    assert cli.main(["--conf", str(conf), "dnsgate-inpath"]) == 0
    assert "DNSGATE_FILL=passive, nothing to hold" in capsys.readouterr().out
