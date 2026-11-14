"""(fin-release) The autonomy's own applies, reverts and undos meet `adguardcfg.Deferred`, the restart
guard's answer while AdGuard's upstreams are down: an `apply` row says `deferred: upstream down`, the
rule's state is left so the next run tries again, and nothing is reported as a failure."""

import io
import pathlib

from test_autoblock import (  # noqa: F401  (auto is a fixture)
    DAY,
    T0,
    FakeClient,
    agree,
    auto,
    block,
    message,
    proposals,
    steady_sampler,
)

from tvgw import adguardcfg, analyst, autoblock, cli, db


def deferred():
    raise adguardcfg.Deferred("deferred: upstream down (a fresh lookup under snu.lge.com SERVFAILs)")


def applies_rows(conn):
    return [(r["outcome"], r["rule"]) for r in autoblock.decisions(conn, "stage = 'apply'")]


def test_a_deferred_autonomous_block_waits_in_the_queue_and_the_next_run_applies_it(auto, lg):  # noqa: F811
    s, key = auto
    client = FakeClient(message(proposals(block("tracker.example"))))
    hooks = {"call": agree, "apply": deferred, "sampler": steady_sampler(), "sleep": lambda x: None}
    assert analyst.run(s, lg, DAY, make_client=lambda k: client, key_path=key, hooks=hooks) == 0
    assert autoblock.read_rules(s.auto_rules) == []  # the file is as it was
    conn = db.connect(s.db_path)
    assert autoblock.rows(conn) == []  # no rule recorded, so no trial and no judge
    assert applies_rows(conn) == [(autoblock.BLOCK_DEFERRED, "||tracker.example^")]
    assert not autoblock.push_owed(conn)  # the file never held the rule: AdGuard is owed nothing
    (q,) = autoblock.queued(conn)
    assert q["rule"] == "||tracker.example^"
    queue = autoblock.decisions(conn, "stage = 'queue'")
    assert [r["outcome"] for r in queue] == ["queued"] and "upstream down" in queue[0]["reason"]
    # nothing is owed to AdGuard: the file never held the rule
    conn.close()
    md = (pathlib.Path(s.reports_dir) / "proposals" / f"{DAY}.md").read_text(encoding="utf-8")
    assert "queued: AdGuard held its restart back (upstream down)" in md
    # the next run, with the upstreams back, takes it from the queue and applies it
    applied = []
    hooks.update(apply=lambda: applied.append(1), now=lambda: T0 + 90000)
    out = io.StringIO()
    (d,) = analyst._drain_quiet(s, lg, {}, "m", key, lambda k: client, DAY, hooks, out)
    assert d["outcome"] == "applied" and d["from_queue"] and applied == [1]
    conn = db.connect(s.db_path)
    assert autoblock.queued(conn) == [] and autoblock.read_rules(s.auto_rules) == ["||tracker.example^"]
    assert not autoblock.push_owed(conn)
    conn.close()


def test_a_deferred_block_from_the_queue_keeps_its_place(auto, lg):  # noqa: F811
    s, key = auto
    conn = db.connect(s.db_path)
    queued_t, since = T0 + 3600, T0 - 86400 - 3600
    autoblock.enqueue(
        conn, {"rule": "||tracker.example^", "name": "tracker.example", "risk": "low"}, DAY, "o", since,
        queued_t,
    )  # fmt: skip
    conn.close()
    hooks = {"call": agree, "apply": deferred, "sampler": steady_sampler(), "sleep": lambda x: None}
    hooks["now"] = lambda: T0 + 90000
    out = io.StringIO()
    client = FakeClient(message({}))
    (d,) = analyst._drain_quiet(s, lg, {}, "m", key, lambda k: client, DAY, hooks, out)
    assert d["applied"].startswith("no: deferred: upstream down")
    assert d["applied"].endswith("; it waits in the queue for the next run")
    conn = db.connect(s.db_path)
    (q,) = autoblock.queued(conn)
    assert (q["queued_t"], q["since"]) == (queued_t, since)
    assert applies_rows(conn) == [(autoblock.BLOCK_DEFERRED, "||tracker.example^")]
    assert not autoblock.push_owed(conn)
    conn.close()
    assert autoblock.read_rules(s.auto_rules) == []


def test_a_deferred_revert_stands_is_no_failure_and_the_next_check_pushes_it(auto, lg):  # noqa: F811
    s, _ = auto
    conn = db.connect(s.db_path)
    autoblock.record(conn, "||gone.example^", "gone.example", DAY, "o", "f", "x", T0)  # not in the file
    (d,) = analyst.check(conn, s, lg, now=T0 + 7200, apply_fn=deferred)
    assert d["verdict"] == "reverted" and "reapply_failed" not in d
    assert d["deferred"].startswith(autoblock.DEFERRED) and analyst.DEFERRED_NOTE in d["reason"]
    assert autoblock.active(conn) == []  # the verdict stands
    (row,) = autoblock.rows(conn)  # and the stored reason says the revert waits for AdGuard
    assert row["reason"] == f"owner removed it from the file; {analyst.DEFERRED_NOTE}"
    assert applies_rows(conn) == [(autoblock.DEFERRED, "||gone.example^")]
    assert autoblock.push_owed(conn)
    # still down an hour later: one more deferred row, owed still, nothing reverted again
    assert analyst.check(conn, s, lg, now=T0 + 10800, apply_fn=deferred) == []
    assert applies_rows(conn)[-1] == (autoblock.DEFERRED, None) and autoblock.push_owed(conn)
    # the upstreams are back: the hourly check pushes the file once and the debt is paid
    pushes = []
    assert analyst.check(conn, s, lg, now=T0 + 14400, apply_fn=lambda: pushes.append(1)) == [
        {"rule": None, "name": None, "verdict": "pushed", "reason": analyst.PUSH_TOOK}
    ]  # and says so: the hour after a WARNING shows it was put right
    assert pushes == [1] and applies_rows(conn)[-1] == ("pushed", None) and not autoblock.push_owed(conn)
    # and nothing more to push the hour after
    assert analyst.check(conn, s, lg, now=T0 + 18000, apply_fn=lambda: pushes.append(1)) == []
    assert pushes == [1]
    conn.close()


def test_an_owed_push_that_fails_for_another_reason_stays_owed(auto, lg):  # noqa: F811
    s, _ = auto
    conn = db.connect(s.db_path)
    autoblock.log_decision(conn, "apply", autoblock.DEFERRED, T0, "||x.example^", "x.example")

    def broken():
        raise RuntimeError("AdGuard did not start")

    (d,) = analyst.check(conn, s, lg, now=T0 + 3600, apply_fn=broken)
    assert d["rule"] is None and d["verdict"] == "reapply_failed" and "AdGuard did not start" in d["reason"]
    assert applies_rows(conn)[-1] == ("reapply_failed", None) and autoblock.push_owed(conn)
    conn.close()


def test_an_owed_push_that_fails_for_another_reason_exits_1_with_the_warning(auto, lg, capsys, monkeypatch):  # noqa: F811
    s, _ = auto
    conf = pathlib.Path(s.state_dir) / "tvgw.conf"
    conf.write_text(
        f"STATE_DIR={s.state_dir}\nDB_PATH={s.db_path}\nREPORTS_DIR={s.reports_dir}\nAUTO_RULES={s.auto_rules}\n",
        encoding="utf-8",
    )
    conn = db.connect(s.db_path)
    autoblock.log_decision(conn, "apply", autoblock.DEFERRED, T0, "||x.example^", "x.example")
    conn.close()

    def broken(s, prof):
        raise RuntimeError("AdGuard rolled back")

    monkeypatch.setattr(analyst, "adguardcfg_apply", broken)
    assert cli.main(["--conf", str(conf), "autoblock", "check"]) == 1
    out = capsys.readouterr().out
    assert (
        "tvgw autoblock: reapply_failed (the owed re-apply failed (RuntimeError: AdGuard rolled back)" in out
    )
    assert "WARNING: a reverted rule is still in AdGuard" in out
    assert "None" not in out


def test_a_canary_revert_whose_push_is_deferred_is_owed_not_failed(auto, lg):  # noqa: F811
    s, key = auto
    calls = {"n": 0}

    def first_ok_then_deferred():
        calls["n"] += 1
        if calls["n"] > 1:
            deferred()

    def collapse():  # streaming at first, then the TV's downloads stop: the canary reverts
        state = collapse.state
        state["n"] += 1
        step = 30_000_000 if state["n"] <= 2 else 0
        state["bytes"] += step
        return autoblock.Sample(T0 + 90000 + state["n"] * 30, state["bytes"], "Active", "com.peacock.tv")

    collapse.state = {"n": 0, "bytes": 0}
    client = FakeClient(message(proposals(block("tracker.example"))))
    hooks = {"call": agree, "apply": first_ok_then_deferred, "sampler": collapse, "sleep": lambda x: None}
    assert analyst.run(s, lg, DAY, make_client=lambda k: client, key_path=key, hooks=hooks) == 0
    conn = db.connect(s.db_path)
    (row,) = autoblock.rows(conn)
    assert row["verdict"] == "reverted" and analyst.DEFERRED_NOTE in row["reason"]
    assert [o for o, _ in applies_rows(conn)] == ["applied", autoblock.DEFERRED]
    assert autoblock.push_owed(conn) and autoblock.read_rules(s.auto_rules) == []
    conn.close()


def test_a_deferred_undo_keeps_the_owners_revert_and_exits_3(auto, lg, capsys, monkeypatch):  # noqa: F811
    s, _ = auto
    conf = pathlib.Path(s.state_dir) / "tvgw.conf"
    conf.write_text(
        f"STATE_DIR={s.state_dir}\nDB_PATH={s.db_path}\nREPORTS_DIR={s.reports_dir}\nAUTO_RULES={s.auto_rules}\n",
        encoding="utf-8",
    )
    monkeypatch.setattr(analyst, "adguardcfg_apply", lambda s, prof: deferred())
    conn = db.connect(s.db_path)
    autoblock.add_rule(s.auto_rules, "||kept.example^", "test")
    autoblock.record(conn, "||kept.example^", "kept.example", DAY, "o", "f", "x", T0)
    conn.close()
    assert cli.main(["--conf", str(conf), "undo"]) == cli.DEFERRED_EXIT
    out = capsys.readouterr().out
    assert "||kept.example^ removed from the rules file; AdGuard held its restart back" in out
    assert "next hourly check re-applies it" in out
    assert autoblock.read_rules(s.auto_rules) == []
    conn = db.connect(s.db_path)
    assert autoblock.active(conn) == [] and autoblock.push_owed(conn)
    assert applies_rows(conn) == [(autoblock.DEFERRED, "||kept.example^")]
    conn.close()
    # the hourly check, still deferred, exits 0: a deferral is no failure of the unit
    assert cli.main(["--conf", str(conf), "autoblock", "check"]) == 0
    assert "WARNING" not in capsys.readouterr().out
    # with the upstreams back, an undo with nothing to remove does not claim a deferral
    monkeypatch.setattr(analyst, "adguardcfg_apply", lambda s, prof: None)
    assert cli.main(["--conf", str(conf), "undo"]) == 0
    assert "no machine rule to remove" in capsys.readouterr().out


def test_a_successful_undo_pays_an_owed_push(auto, lg):  # noqa: F811
    s, _ = auto
    conn = db.connect(s.db_path)
    autoblock.log_decision(conn, "apply", autoblock.DEFERRED, T0, "||old.example^", "old.example")
    autoblock.add_rule(s.auto_rules, "||kept.example^", "test")
    autoblock.record(conn, "||kept.example^", "kept.example", DAY, "o", "f", "x", T0)
    assert analyst.undo(conn, s, lg, apply_fn=lambda: None, now=T0 + 60) == ["||kept.example^"]
    assert applies_rows(conn)[-1] == ("pushed", None) and not autoblock.push_owed(conn)
    conn.close()


def test_the_decisions_days_prune_keeps_an_owed_push(tmp_path):
    from tvgw import ingest

    conn = db.connect(str(tmp_path / "p.db"))
    autoblock.log_decision(conn, "judge", "reverted", T0, "||x.example^", "x.example")
    owed = autoblock.log_decision(conn, "apply", autoblock.DEFERRED, T0, "||x.example^", "x.example")
    ingest.prune(conn, 365, now=T0 + 86400 * 400, decisions_days=30)
    assert [r["id"] for r in autoblock.decisions(conn)] == [owed] and autoblock.push_owed(conn)
    autoblock.log_decision(conn, "apply", "pushed", T0 + 86400 * 400)  # paid: the old row may go now
    ingest.prune(conn, 365, now=T0 + 86400 * 401, decisions_days=30)
    assert [r["outcome"] for r in autoblock.decisions(conn)] == ["pushed"]
    conn.close()


def test_push_owed_reads_an_old_store_as_nothing_owed(tmp_path):
    import sqlite3

    conn = sqlite3.connect(str(tmp_path / "old.db"))
    assert autoblock.push_owed(conn) is False
    conn.close()
