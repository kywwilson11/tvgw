"""Autonomous blocking (design decision 20): the traffic-shape gate, the machine's own rules file, the
second key, the live canary, the hourly judge, the owner's undo, and the novelty gate that keeps quiet
days free of requests."""

import json
import pathlib
from contextlib import contextmanager
from datetime import datetime
from types import SimpleNamespace

import pytest

from tvgw import adguardcfg, analyst, autoblock, cli, db
from tvgw.config import Settings

DAY = "2026-10-26"
T0 = datetime.strptime(DAY, "%Y-%m-%d").timestamp() + 12 * 3600  # noon, local time
APP = "com.peacock.tv"


class FakeStream:
    def __init__(self, msg):
        self.msg = msg

    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False

    def get_final_message(self):
        return self.msg


class FakeClient:
    def __init__(self, msg):
        self.msg, self.calls = msg, []
        self.messages = SimpleNamespace(stream=self._stream)

    @contextmanager
    def _stream(self, **kw):
        self.calls.append(kw)
        yield FakeStream(self.msg)


def message(obj):
    return SimpleNamespace(
        stop_reason="end_turn",
        stop_details=None,
        content=[SimpleNamespace(type="text", text=json.dumps(obj))],
        usage=SimpleNamespace(input_tokens=12000, output_tokens=900, cache_read_input_tokens=0),
    )


def store(tmp_path):
    """Two days of a telemetry host (small, periodic, up-heavy), a content host (big downloads) seen
    on two days as well, the clock host, and five hours of the TV on with a streaming app up."""
    path = tmp_path / "s.db"
    conn = db.connect(str(path))

    def visit(t, name, ip, sport, up, down, seconds):
        conn.execute(
            "INSERT INTO dns(t,qname,qtype,answers,blocked) VALUES (?,?,?,?,0)", (t - 2, name, "A", f"A:{ip}")
        )
        conn.execute("INSERT INTO tls(t,dst,dport,sport,sni) VALUES (?,?,443,?,?)", (t - 1, ip, sport, name))
        conn.execute(
            "INSERT INTO flows(t_start,t_end,proto,dst,dport,sport,bytes_up,pkts_up,bytes_down)"
            " VALUES (?,?,'tcp',?,443,?,?,?,?)",
            (t, t + seconds, ip, sport, up, 8, down),
        )

    for day_off in (0, -1):
        base = T0 + day_off * 86400
        for i in range(12):
            visit(
                base + i * 600, "tracker.example", "203.0.113.5", 40000 + i + (day_off + 1) * 100, 700, 300, 3
            )
    for i in range(6):
        visit(T0 + i * 1200, "cdn.example", "203.0.113.9", 50000 + i, 20000, 50_000_000, 600)
    conn.execute(
        "INSERT INTO dns(t,qname,qtype,answers,blocked) VALUES (?,?,?,?,0)",
        (T0 - 86400, "cdn.example", "A", "A:203.0.113.9"),
    )
    conn.execute(
        "INSERT INTO dns(t,qname,qtype,answers,blocked) VALUES (?,?,?,?,0)",
        (T0 + 100, "us.lgtvsdp.com", "A", "A:203.0.113.20"),
    )
    conn.executemany(
        "INSERT INTO hosts(name, category, first_seen, last_seen, dns_n) VALUES (?,?,?,?,?)",
        [
            ("tracker.example", "Other", T0 - 86400, T0, 24),
            ("cdn.example", "Streaming", T0 - 86400, T0, 7),
            ("us.lgtvsdp.com", "LG core", T0 - 86400, T0, 2),
        ],
    )
    conn.executemany(
        "INSERT INTO tvstate(t, power, app) VALUES (?,?,?)",
        [(T0 + (h - 2) * 3600, "Active", APP) for h in range(5)],
    )
    conn.commit()
    conn.close()
    return str(path)


@pytest.fixture
def auto(tmp_path):
    key = tmp_path / "k"
    key.write_text("sk-ant-test\n")
    key.chmod(0o600)
    s = Settings(
        tv_mac="b4:b2:91:aa:bb:cc",
        tv_name="lgcx",
        state_dir=str(tmp_path),
        db_path=store(tmp_path),
        reports_dir=str(tmp_path / "reports"),
        auto_rules=str(tmp_path / "auto.rules"),
        analyst_apply="auto",
    )
    return s, str(key)


def proposals(*items):
    return {"summary": "two names", "nothing_to_do": False, "proposals": list(items)}


def block(name, reason="telemetry"):
    return {
        "kind": "block",
        "name": name,
        "rule": f"||{name}^",
        "reason": reason,
        "evidence": ["x"],
        "risk": "low",
        "rollback": "remove the rule",
    }


def agree(*a, **k):
    return {
        "safe_to_block": True,
        "confidence": "high",
        "reason": "pure telemetry",
        "watch_for": "retries",
    }, {}


def veto(*a, **k):
    return {
        "safe_to_block": False,
        "confidence": "high",
        "reason": "it serves the captions",
        "watch_for": "",
    }, {}


def steady_sampler(step_bytes=30_000_000, step_seconds=30):
    """A TV streaming at a constant rate: every sample is step_seconds later and step_bytes further on."""
    state = {"n": 0}

    def sample():
        state["n"] += 1
        return autoblock.Sample(
            T0 + 90000 + state["n"] * step_seconds, state["n"] * step_bytes, "Active", APP
        )

    return sample


# ---- the shape of the traffic ------------------------------------------------------------------------------
def test_shapes_tell_telemetry_from_content(auto):
    s, _ = auto
    conn = db.connect(s.db_path, readonly=True)
    sh = autoblock.shapes(conn, ["tracker.example", "cdn.example", "never.example", ""], T0 - 1, T0 + 86400)
    tracker, cdn = sh["tracker.example"], sh["cdn.example"]
    assert tracker["conns"] == 12 and tracker["median_down"] == 300 and tracker["total_down"] == 3600
    assert tracker["median_up"] == 700 and tracker["median_seconds"] == 3.0 and tracker["hours"] == 2
    assert tracker["days_seen"] == 2 and tracker["apps"] == [APP]
    assert cdn["median_down"] == 50_000_000 and cdn["total_down"] == 300_000_000 and cdn["days_seen"] == 2
    assert sh["never.example"]["conns"] == 0 and sh["never.example"]["days_seen"] == 0
    assert "" not in sh and autoblock.shapes(conn, [], 0, 1) == {}
    conn.close()


def test_gate_refuses_payload_new_names_high_risk_and_the_daily_cap():
    ok = {"kind": "block", "vetted": "ok", "risk": "low", "rule": "||t.example^"}
    small = {"days_seen": 3, "median_down": 300, "total_down": 4000}
    assert autoblock.gate(ok, small, [], 0) == "ok"
    assert autoblock.gate(ok, {**small, "median_down": 500_000}, [], 0).startswith("refused: carried payload")
    assert autoblock.gate(ok, {**small, "total_down": 5_000_000}, [], 0).startswith(
        "refused: carried payload"
    )
    assert autoblock.gate(ok, {**small, "days_seen": 1}, [], 0).startswith("refused: seen on 1 day")
    assert autoblock.gate(ok, None, [], 0) == "refused: no evidence of how the TV used this name"
    assert (
        autoblock.gate({**ok, "risk": "medium"}, small, [], 0)
        == "refused: the proposer rated the risk medium"
    )
    assert autoblock.gate({**ok, "kind": "allow"}, small, [], 0).startswith("refused: only a vetted block")
    assert autoblock.gate({**ok, "vetted": "refused: x"}, small, [], 0).startswith(
        "refused: only a vetted block"
    )
    assert autoblock.gate(ok, small, ["||t.example^"], 0) == "refused: already in place"
    assert autoblock.gate(ok, small, [], autoblock.MAX_PER_DAY).startswith("refused: 3 autonomous blocks")


# ---- the machine's file -------------------------------------------------------------------------------------
def test_machine_rules_file_round_trip_lint_and_adguard(tmp_path, lg):
    path = str(tmp_path / "auto.rules")
    assert autoblock.read_rules(path) == []
    autoblock.add_rule(path, "||t.example^", "2026-10-28 day: t.example")
    autoblock.add_rule(path, "||us.lgtvsdp.com^", "a bad idea")
    autoblock.add_rule(path, "||t.example^", "twice")  # no duplicate
    assert autoblock.read_rules(path) == ["||t.example^", "||us.lgtvsdp.com^"]
    ok, refused = autoblock.admissible(path, lg)
    assert ok == ["||t.example^"] and len(refused) == 1
    assert refused[0].startswith("||us.lgtvsdp.com^: ") and "covers must-allow us.lgtvsdp.com" in refused[0]
    s = Settings(auto_rules=path)
    rules = adguardcfg.desired(lg, s).user_rules
    assert "||t.example^" in rules and "||us.lgtvsdp.com^" not in rules  # the lint stands between the two
    assert rules.count("||t.example^") == 1
    assert autoblock.remove_rule(path, "||us.lgtvsdp.com^") and not autoblock.remove_rule(path, "||none^")
    text = pathlib.Path(path).read_text()
    assert text.startswith(autoblock.HEADER) and "a bad idea" not in text and "||t.example^" in text
    assert (pathlib.Path(path).stat().st_mode & 0o777) == 0o640
    assert (
        "||t.example^" not in adguardcfg.desired(lg, Settings(auto_rules=str(tmp_path / "none"))).user_rules
    )


# ---- the live canary -------------------------------------------------------------------------------------------
def test_canary_reverts_on_collapse_or_launcher_and_passes_otherwise():
    S = autoblock.Sample
    before = [S(0, 0, "Active", APP), S(60, 60_000_000, "Active", APP)]  # 60 MB/min before the block
    seq = iter([S(90 + 30 * i, 60_000_000 + 30_000_000 * (i + 1), "Active", APP) for i in range(20)])
    assert autoblock.canary(before, lambda: next(seq), sleep=lambda x: None) == (
        "passed",
        "10 minutes: downloads held, app stayed up",
    )
    flat = iter([S(90 + 30 * i, 60_000_000 + 1000 * i, "Active", APP) for i in range(20)])
    verdict, why = autoblock.canary(before, lambda: next(flat), sleep=lambda x: None)
    assert verdict == "reverted" and why.startswith("downloads to the TV fell to 0%")
    home = iter([S(90, 90_000_000, "Active", APP), S(120, 120_000_000, "Active", "com.webos.app.home")])
    verdict, why = autoblock.canary(before, lambda: next(home), sleep=lambda x: None)
    assert verdict == "reverted" and "gave way to the launcher" in why
    off = iter([S(90, 90_000_000, "Standby", "")])
    assert autoblock.canary(before, lambda: next(off), sleep=lambda x: None)[0] == "unobserved"
    assert autoblock.canary([S(0, 0, "Standby", "")], lambda: None, sleep=lambda x: None)[0] == "unobserved"
    assert autoblock.canary([S(0, 0, "Active", APP)], lambda: None, sleep=lambda x: None)[0] == "unobserved"
    idle = [S(0, 0, "Active", ""), S(60, 1000, "Active", "")]  # on but not streaming: only the app is watched
    samples = iter([S(90 + 30 * i, 2000, "Active", "") for i in range(20)])
    verdict, why = autoblock.canary(idle, lambda: next(samples), sleep=lambda x: None)
    assert verdict == "passed" and "not streaming" in why
    slept = []
    one = iter([S(90 + 30 * i, 60_000_000 * (i + 2), "Active", APP) for i in range(2)])
    autoblock.canary(before, lambda: next(one), minutes=1, interval=30, sleep=slept.append)
    assert slept == [30, 30]


# ---- the whole autonomous pass -------------------------------------------------------------------------------
def test_autonomous_run_blocks_telemetry_refuses_content_and_remembers(auto, lg, capsys):
    s, key = auto
    answer = proposals(
        block("tracker.example"),
        block("cdn.example", "looks like ads"),
        {
            "kind": "watch",
            "name": "odd.example",
            "rule": "",
            "reason": "unclear",
            "evidence": [],
            "risk": "low",
            "rollback": "",
        },
    )
    verifier_calls, applies = [], []

    def second_key(client, system, user, model, effort, schema=None):
        body = json.loads(user.split("\n", 1)[1])
        verifier_calls.append((model, effort, body["proposal"]["name"], body["traffic_shape"]["days_seen"]))
        assert system == autoblock.VERIFIER_SYSTEM and schema is autoblock.VERIFY_SCHEMA
        assert body["context"]["must_allow"] and "b4:b2:91" not in user
        return agree()

    hooks = {
        "call": second_key,
        "apply": lambda: applies.append(1),
        "sampler": steady_sampler(),
        "sleep": lambda x: None,
    }
    client = FakeClient(message(answer))
    assert analyst.run(s, lg, DAY, make_client=lambda k: client, key_path=key, hooks=hooks) == 0
    out = capsys.readouterr().out
    assert "3 proposal(s), 3 vetted ok, 1 applied on their own" in out
    assert verifier_calls == [
        ("claude-fable-5-1", "xhigh", "tracker.example", 2)
    ]  # cdn never reached the second key
    assert applies == [1]
    assert autoblock.read_rules(s.auto_rules) == ["||tracker.example^"]
    assert "||tracker.example^" in adguardcfg.desired(lg, s).user_rules
    conn = db.connect(s.db_path)
    (row,) = autoblock.rows(conn)
    assert (
        row["name"] == "tracker.example" and row["verdict"] is None and row["verifier"] == "claude-fable-5-1"
    )
    assert row["trial_until"] - row["added_t"] == autoblock.TRIAL and row["source"] == DAY
    md = (pathlib.Path(s.reports_dir) / "proposals" / f"{DAY}.md").read_text()
    assert "- Applied: yes; claude-fable-5-1 agreed (pure telemetry); canary passed: 10 minutes" in md
    assert "- Applied: no: carried payload (median 50000000 B down per connection" in md
    assert "put in by the gateway itself" in md and "Nothing here is applied" not in md
    record = json.loads((pathlib.Path(s.reports_dir) / "proposals" / f"{DAY}.json").read_text())
    assert [x["outcome"] for x in record["autonomous"]] == ["applied", "refused"] and record["reasons"]
    judged = autoblock.judged_recently(conn, T0 + 90000)
    assert {n: j["kind"] for n, j in judged.items()} == {
        "tracker.example": "block",
        "cdn.example": "block",
        "odd.example": "watch",
    }
    conn.close()
    # the same window again: every name is now recognized, so no request is made and nothing is spent
    assert (
        analyst.run(
            s, lg, DAY, make_client=lambda k: pytest.fail("a second request"), key_path=key, hooks=hooks
        )
        == 0
    )
    assert "nothing new, no request sent" in capsys.readouterr().out
    assert "nothing new" in (pathlib.Path(s.reports_dir) / "proposals" / f"{DAY}.md").read_text()


def test_apply_off_only_proposes(auto, lg, capsys):
    from dataclasses import replace

    s, key = auto
    s = replace(s, analyst_apply="off")
    client = FakeClient(message(proposals(block("tracker.example"))))
    hooks = {"call": lambda *a, **k: pytest.fail("verifier asked"), "apply": lambda: pytest.fail("applied")}
    assert analyst.run(s, lg, DAY, make_client=lambda k: client, key_path=key, hooks=hooks) == 0
    assert "0 applied on their own" in capsys.readouterr().out
    assert autoblock.read_rules(s.auto_rules) == []
    assert "Applied:" not in (pathlib.Path(s.reports_dir) / "proposals" / f"{DAY}.md").read_text()


def test_verifier_veto_and_canary_revert(auto, lg):
    s, key = auto
    applies = []
    client = FakeClient(message(proposals(block("tracker.example"))))
    hooks = {
        "call": veto,
        "apply": lambda: applies.append(1),
        "sampler": steady_sampler(),
        "sleep": lambda x: None,
    }
    assert analyst.run(s, lg, DAY, make_client=lambda k: client, key_path=key, hooks=hooks, force=True) == 0
    assert applies == [] and autoblock.read_rules(s.auto_rules) == []
    md = (pathlib.Path(s.reports_dir) / "proposals" / f"{DAY}.md").read_text()
    assert "- Applied: no: claude-fable-5-1 did not clear it: it serves the captions" in md
    conn = db.connect(s.db_path)
    assert autoblock.rows(conn) == []  # a veto leaves no rule to judge
    # the second key agrees, but the TV's downloads stop right after: the rule comes out again within minutes
    state = {"n": 0}

    def collapsing():
        state["n"] += 1
        tx = 60_000_000 * min(state["n"], 2)  # 60 MB/min before the block, flat afterwards
        return autoblock.Sample(T0 + 90000 + state["n"] * 60, tx, "Active", APP)

    hooks = {
        "call": agree,
        "apply": lambda: applies.append(1),
        "sampler": collapsing,
        "sleep": lambda x: None,
    }
    assert analyst.run(s, lg, DAY, make_client=lambda k: client, key_path=key, hooks=hooks, force=True) == 0
    assert applies == [1, 1] and autoblock.read_rules(s.auto_rules) == []  # applied, then taken out
    (row,) = autoblock.rows(conn)
    assert row["verdict"] == "reverted" and row["reason"].startswith("canary: downloads to the TV fell to 0%")
    md = (pathlib.Path(s.reports_dir) / "proposals" / f"{DAY}.md").read_text()
    assert "- Applied: reverted within minutes: downloads to the TV fell" in md
    conn.close()


def test_verifier_failure_low_confidence_and_adguard_failure_apply_nothing(auto, lg):
    s, key = auto
    client = FakeClient(message(proposals(block("tracker.example"))))

    def boom(*a, **k):
        raise TimeoutError("slow")

    hooks = {
        "call": boom,
        "apply": lambda: pytest.fail("applied"),
        "sampler": steady_sampler(),
        "sleep": lambda x: None,
    }
    assert analyst.run(s, lg, DAY, make_client=lambda k: client, key_path=key, hooks=hooks, force=True) == 0
    md = (pathlib.Path(s.reports_dir) / "proposals" / f"{DAY}.md").read_text()
    assert "- Applied: no: the second model could not be asked (TimeoutError)" in md

    def unsure(*a, **k):
        return {"safe_to_block": True, "confidence": "low", "reason": "maybe", "watch_for": ""}, {}

    hooks["call"] = unsure
    assert analyst.run(s, lg, DAY, make_client=lambda k: client, key_path=key, hooks=hooks, force=True) == 0
    assert (
        "- Applied: no: claude-fable-5-1 did not clear it: maybe"
        in (pathlib.Path(s.reports_dir) / "proposals" / f"{DAY}.md").read_text()
    )

    def adguard_down():
        raise RuntimeError("AdGuard did not come back")

    hooks = {"call": agree, "apply": adguard_down, "sampler": steady_sampler(), "sleep": lambda x: None}
    assert analyst.run(s, lg, DAY, make_client=lambda k: client, key_path=key, hooks=hooks, force=True) == 0
    assert autoblock.read_rules(s.auto_rules) == []  # the rule came back out of the file
    assert (
        "- Applied: no: AdGuard did not take it (AdGuard did not come back)"
        in (pathlib.Path(s.reports_dir) / "proposals" / f"{DAY}.md").read_text()
    )
    conn = db.connect(s.db_path)
    assert autoblock.rows(conn) == []
    conn.close()


def test_daily_cap_and_same_model_fallback(auto, lg):
    from dataclasses import replace

    s, key = auto
    conn = db.connect(s.db_path)
    for i in range(autoblock.MAX_PER_DAY):
        autoblock.record(conn, f"||old{i}.example^", f"old{i}.example", DAY, "o", "f", "x", T0 + 90000 + i)
    conn.close()
    client = FakeClient(message(proposals(block("tracker.example"))))
    hooks = {
        "call": lambda *a, **k: pytest.fail("the cap comes before the second key"),
        "apply": lambda: pytest.fail("applied"),
        "now": lambda: T0 + 90000 + 3600,
    }
    assert analyst.run(s, lg, DAY, make_client=lambda k: client, key_path=key, hooks=hooks, force=True) == 0
    assert (
        "- Applied: no: 3 autonomous blocks in 24 h already"
        in (pathlib.Path(s.reports_dir) / "proposals" / f"{DAY}.md").read_text()
    )
    # the verifier is never the proposer: with Fable proposing, the daily model refutes
    seen = []

    def who(client, system, user, model, effort, schema=None):
        seen.append(model)
        return veto()

    s2 = replace(s, analyst_model="claude-fable-5-1")
    hooks = {
        "call": who,
        "apply": lambda: pytest.fail("applied"),
        "now": lambda: T0 + 90000 + 2 * autoblock.TRIAL,
    }
    assert analyst.run(s2, lg, DAY, make_client=lambda k: client, key_path=key, hooks=hooks, force=True) == 0
    assert seen == ["claude-opus-5-5"]
    assert analyst.verifier_for(s, "claude-opus-5-5") == "claude-fable-5-1"
    assert analyst.verifier_for(s2, "claude-fable-5-1") == "claude-opus-5-5"
    assert (
        analyst.verifier_for(replace(s2, analyst_weekly_model="off"), "claude-fable-5-1") == "claude-opus-5-5"
    )
    assert (
        analyst.verifier_for(replace(s, analyst_verifier_model="claude-x-1"), "claude-opus-5-5")
        == "claude-x-1"
    )


# ---- the hourly judge and the owner's undo ------------------------------------------------------------------------
def test_hourly_judge_and_owner_undo(auto, lg):
    s, _ = auto
    conn = db.connect(s.db_path)
    autoblock.add_rule(s.auto_rules, "||tracker.example^", "test")
    added = T0 + 3 * 3600
    autoblock.record(
        conn,
        "||tracker.example^",
        "tracker.example",
        DAY,
        "claude-opus-5-5",
        "claude-fable-5-1",
        "telemetry",
        added,
    )
    applies = []
    # inside the trial with no TV hour to compare yet: keep watching
    assert analyst.check(conn, s, lg, now=added + 2 * 3600, apply_fn=lambda: applies.append(1)) == []
    assert autoblock.pending(conn) and applies == []
    # the trial window closes with the TV hardly on since: passed, nothing to compare, no red line
    decisions = analyst.check(
        conn, s, lg, now=added + autoblock.TRIAL + 1, apply_fn=lambda: applies.append(1)
    )
    assert [(d["verdict"], d["name"]) for d in decisions] == [("passed", "tracker.example")]
    assert decisions[0]["reason"].startswith("TV on 0 h in the trial and 5 h before: too little to compare")
    assert autoblock.rows(conn)[0]["verdict"] == "passed" and applies == []
    assert autoblock.active(conn) and not autoblock.pending(conn)
    assert (
        analyst.check(conn, s, lg, now=added + 2 * autoblock.TRIAL) == []
    )  # decided rules are not re-judged
    gone = analyst.undo(conn, s, lg, apply_fn=lambda: applies.append(1), now=T0 + 90000)
    assert gone == ["||tracker.example^"] and applies == [1] and autoblock.read_rules(s.auto_rules) == []
    assert (
        autoblock.rows(conn)[0]["reason"] == "owner undo" and autoblock.rows(conn)[0]["verdict"] == "reverted"
    )
    assert analyst.undo(conn, s, lg, apply_fn=lambda: applies.append(1)) == [] and applies == [1]
    conn.close()


def test_hourly_judge_reverts_when_streaming_collapses_in_an_hour(auto, lg):
    s, _ = auto
    conn = db.connect(s.db_path)
    autoblock.add_rule(s.auto_rules, "||tracker.example^", "test")
    added = T0 + 2 * 3600  # right after the last streaming hour (cdn flows end by T0 + 6600)
    autoblock.record(conn, "||tracker.example^", "tracker.example", DAY, "o", "f", "telemetry", added)
    # the TV is on for the whole next hour, and nothing in the expected categories flows
    conn.executemany(
        "INSERT INTO tvstate(t, power, app) VALUES (?,?,?)",
        [(added + 600, "Active", APP), (added + 3000, "Active", APP)],
    )
    conn.commit()
    applies = []
    decisions = analyst.check(conn, s, lg, now=added + 3600 + 60, apply_fn=lambda: applies.append(1))
    assert [d["verdict"] for d in decisions] == ["reverted"] and applies == [1]
    assert "streaming volume in the last TV hour fell to 0%" in decisions[0]["reason"]
    assert autoblock.read_rules(s.auto_rules) == [] and autoblock.active(conn) == []
    conn.close()


def test_hourly_judge_reverts_on_a_must_allow_red_line(auto, lg):
    s, _ = auto
    conn = db.connect(s.db_path)
    added = T0 + 3 * 3600
    autoblock.add_rule(s.auto_rules, "||tracker.example^", "test")
    autoblock.record(conn, "||tracker.example^", "tracker.example", DAY, "o", "f", "telemetry", added)
    conn.execute(
        "INSERT INTO dns(t,qname,qtype,answers,blocked,rule) VALUES (?,?,?,?,1,?)",
        (added + 100, "snu.lge.com", "A", "A:0.0.0.0", "||lge.com^"),
    )
    conn.commit()
    decisions = analyst.check(conn, s, lg, now=added + 7200, apply_fn=lambda: None)
    assert [(d["verdict"], d["reason"]) for d in decisions] == [
        ("reverted", "a must-allow name was blocked after this rule")
    ]
    conn.close()


def test_summary_for_the_brief(auto):
    s, _ = auto
    conn = db.connect(s.db_path)
    autoblock.record(conn, "||a.example^", "a.example", DAY, "o", "f", "x", T0)
    autoblock.record(conn, "||b.example^", "b.example", DAY, "o", "f", "x", T0 + 10)
    autoblock.decide(conn, "||a.example^", "reverted", "canary: fell", T0 + 700)
    o = autoblock.summary(conn, T0 - 1, T0 + 86400)
    assert [r["name"] for r in o["blocked"]] == ["a.example", "b.example"]
    assert [r["name"] for r in o["decided"]] == ["a.example"] and o["pending"] == 1
    assert autoblock.added_in(conn, T0 - 1, T0 + 5) == 1
    conn.close()


# ---- the novelty gate ---------------------------------------------------------------------------------------------
def test_novelty_gate_is_quiet_when_nothing_new():
    quiet = {"tv": {"readings_on": 0}, "totals": {"dns": {"lookups": 0}}}
    assert analyst.novelty(quiet) == []
    known = {
        "tv": {"readings_on": 5},
        "totals": {"dns": {"lookups": 100}},
        "previous_judgments": [{"name": "a.example"}],
        "new_hosts": [{"name": "a.example"}],
        "allowed_unexpected": [{"name": "a.example"}],
        "red_lines": ["firewall checks failed 1 of 9 times; last: x"],
        "dns_gate": {"new_connections": 0, "examples": []},
        "dns_anomalies": [{"name": "a.example"}],
    }
    assert analyst.novelty(known) == []
    assert analyst.novelty({**known, "new_hosts": [{"name": "b.example"}]}) == ["1 name(s) first seen"]
    assert analyst.novelty({**known, "allowed_unexpected": [{"name": "b.example"}]}) == [
        "1 allowed name(s) outside the expected categories, not judged in a week"
    ]
    assert analyst.novelty({**known, "red_lines": ["must-allow name blocked: x"]}) == ["1 red line(s)"]
    assert analyst.novelty({**known, "must_allow_blocked": [{"name": "x"}]}) == [
        "a must-allow name was blocked"
    ]
    assert analyst.novelty({**known, "blocked_reached": [{"name": "x"}]}) == ["blocked names still reached"]
    assert analyst.novelty({**known, "acr_cadence": [{"name": "x"}]}) == ["ACR-like cadence"]
    assert analyst.novelty({**known, "dns_gate": {"new_connections": 3}}) == [
        "connections to addresses no lookup returned"
    ]
    assert analyst.novelty({**known, "unresolved_destinations": [{"dst": "x"}]}) == [
        "unresolved destinations"
    ]
    assert analyst.novelty({**known, "dns_anomalies": [{"name": "b.example"}]}) == ["DNS oddities"]
    assert analyst.novelty({**known, "tv": {"readings_on": 5, "firmware_changes": [{"firmware": "x"}]}}) == [
        "firmware or settings changed"
    ]
    assert analyst.novelty(
        {"tv": {"readings_on": 0}, "totals": {"dns": {"lookups": 3}}, "new_hosts": [{"name": "n"}]}
    )


def test_quiet_day_makes_no_request_unless_forced(auto, lg, capsys):
    from dataclasses import replace

    s, key = auto
    quiet = replace(s, db_path=str(pathlib.Path(s.state_dir) / "empty.db"))
    db.connect(quiet.db_path).close()
    assert analyst.run(quiet, lg, DAY, make_client=lambda k: pytest.fail("asked"), key_path=key) == 0
    assert "nothing new, no request sent (use --force to ask anyway)" in capsys.readouterr().out
    client = FakeClient(message({"summary": "quiet", "nothing_to_do": True, "proposals": []}))
    assert analyst.run(quiet, lg, DAY, make_client=lambda k: client, key_path=key, force=True) == 0
    assert len(client.calls) == 1 and "0 proposal(s)" in capsys.readouterr().out


# ---- the CLI ---------------------------------------------------------------------------------------------------------
def test_cli_undo_and_autoblock_commands(auto, lg, capsys, monkeypatch):
    s, _ = auto
    conf = pathlib.Path(s.state_dir) / "tvgw.conf"
    conf.write_text(
        f"STATE_DIR={s.state_dir}\nDB_PATH={s.db_path}\nREPORTS_DIR={s.reports_dir}\nAUTO_RULES={s.auto_rules}\n"
        "ANALYST_APPLY=auto\n"
    )
    applied = []
    monkeypatch.setattr(analyst, "adguardcfg_apply", lambda s, prof: applied.append(1))
    conn = db.connect(s.db_path)
    autoblock.add_rule(s.auto_rules, "||tracker.example^", "test")
    autoblock.record(conn, "||tracker.example^", "tracker.example", DAY, "o", "f", "telemetry", T0)
    conn.close()
    assert cli.main(["--conf", str(conf), "autoblock", "list"]) == 0
    out = capsys.readouterr().out
    assert "||tracker.example^" in out and "on probation" in out
    assert cli.main(["--conf", str(conf), "autoblock", "check"]) == 0
    assert "1 rule(s) on probation, nothing to decide" in capsys.readouterr().out
    assert cli.main(["--conf", str(conf), "undo"]) == 0
    assert "tvgw undo: ||tracker.example^ removed and AdGuard re-applied" in capsys.readouterr().out
    assert applied == [1] and autoblock.read_rules(s.auto_rules) == []
    assert cli.main(["--conf", str(conf), "undo", "--all"]) == 0
    assert "no machine rule to remove" in capsys.readouterr().out
    assert cli.main(["--conf", str(conf), "autoblock", "check"]) == 0
    assert "0 rule(s) on probation" in capsys.readouterr().out
    assert cli.main(["--conf", str(conf), "autoblock", "list"]) == 0
    assert "reverted" in capsys.readouterr().out


def test_check_follows_the_owner_who_deleted_the_file_and_reports_a_failed_reapply(auto, lg):
    s, _ = auto
    conn = db.connect(s.db_path)
    autoblock.add_rule(s.auto_rules, "||a.example^", "test")
    autoblock.add_rule(s.auto_rules, "||b.example^", "test")
    autoblock.record(conn, "||a.example^", "a.example", DAY, "o", "f", "x", T0)
    autoblock.record(conn, "||b.example^", "b.example", DAY, "o", "f", "x", T0)
    autoblock.decide(conn, "||b.example^", "passed", "fine", T0 + 90000)
    pathlib.Path(s.auto_rules).unlink()  # the documented kill switch
    applies = []
    decisions = analyst.check(conn, s, lg, now=T0 + 100000, apply_fn=lambda: applies.append(1))
    assert sorted((d["rule"], d["verdict"], d["reason"]) for d in decisions) == [
        ("||a.example^", "reverted", "owner removed it from the file"),
        ("||b.example^", "reverted", "owner removed it from the file"),
    ]
    assert applies == [1] and autoblock.active(conn) == []
    # a revert whose re-apply fails is still a revert, but it says so, in the decision and in the store
    autoblock.add_rule(s.auto_rules, "||c.example^", "test")
    autoblock.record(conn, "||c.example^", "c.example", DAY, "o", "f", "x", T0)
    conn.execute(
        "INSERT INTO dns(t,qname,qtype,answers,blocked,rule) VALUES (?,?,?,?,1,?)",
        (T0 + 100, "snu.lge.com", "A", "A:0.0.0.0", "||lge.com^"),
    )
    conn.commit()

    def down():
        raise RuntimeError("AdGuard did not start")

    (d,) = analyst.check(conn, s, lg, now=T0 + 7200, apply_fn=down)
    assert d["verdict"] == "reverted" and d["reapply_failed"].startswith(
        "RuntimeError: AdGuard did not start"
    )
    assert (
        "AdGuard re-apply failed" in d["reason"]
        and "run tvgw adguard apply" in autoblock.rows(conn)[-1]["reason"]
    )
    assert autoblock.read_rules(s.auto_rules) == []
    conn.close()


def test_cli_check_and_undo_exit_1_when_adguard_will_not_take_the_revert(auto, lg, capsys, monkeypatch):
    s, _ = auto
    conf = pathlib.Path(s.state_dir) / "tvgw.conf"
    conf.write_text(
        f"STATE_DIR={s.state_dir}\nDB_PATH={s.db_path}\nREPORTS_DIR={s.reports_dir}\nAUTO_RULES={s.auto_rules}\n"
    )

    def down(s, prof):
        raise RuntimeError("AdGuard did not start")

    monkeypatch.setattr(analyst, "adguardcfg_apply", down)
    conn = db.connect(s.db_path)
    autoblock.record(conn, "||gone.example^", "gone.example", DAY, "o", "f", "x", T0)  # not in the file
    autoblock.add_rule(s.auto_rules, "||kept.example^", "test")
    autoblock.record(conn, "||kept.example^", "kept.example", DAY, "o", "f", "x", T0)
    conn.close()
    assert cli.main(["--conf", str(conf), "autoblock", "check"]) == 1
    out = capsys.readouterr().out
    assert "reverted ||gone.example^ (owner removed it from the file; AdGuard re-apply failed" in out
    assert "WARNING: a reverted rule is still in AdGuard" in out
    assert cli.main(["--conf", str(conf), "undo"]) == 1
    out = capsys.readouterr().out
    assert (
        "AdGuard was not re-applied (RuntimeError: AdGuard did not start)" in out
        and "tvgw adguard apply" in out
    )
    assert autoblock.read_rules(s.auto_rules) == []


def test_brief_section_lists_what_the_machine_did(auto, lg, capsys):
    from tvgw import queries

    s, _ = auto
    conn = db.connect(s.db_path)
    autoblock.record(conn, "||a.example^", "a.example", DAY, "o", "f", "pure telemetry", T0)
    autoblock.record(conn, "||b.example^", "b.example", DAY, "o", "f", "beacon", T0 + 10)
    autoblock.decide(conn, "||a.example^", "reverted", "canary: downloads to the TV fell to 3%", T0 + 700)
    o = queries.window_report(conn, T0 - 3600, T0 + 3600, lg)
    assert [r["name"] for r in o["autonomous"]["blocked"]] == ["a.example", "b.example"]
    cli.render_brief(o)
    out = capsys.readouterr().out
    assert "Rules the gateway added on its own" in out
    assert "||a.example^" in out and "reverted" in out and "canary: downloads to the TV fell" in out
    assert "||b.example^" in out and "on probation" in out
    conn.close()


def test_summary_and_judgments_tolerate_a_store_without_the_tables(tmp_path):
    import sqlite3

    conn = sqlite3.connect(str(tmp_path / "old.db"))
    assert autoblock.summary(conn, 0, 1) == {"blocked": [], "decided": [], "pending": 0}
    assert autoblock.judged_recently(conn, 1) == {}
    conn.close()
