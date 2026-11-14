"""(record) tvgw forget: every table and file tree is classified, the viewing record is gone in every
encoding (the store file's raw bytes included), the gateway's own state is untouched, and late
evidence of the forgotten time cannot come back through the next ingest."""

import dataclasses
import gzip
import json
import os
import re
import sqlite3
import subprocess
import sys
from pathlib import Path

import pytest
from conftest import DNS_BLOCKED, FLOW_TCP, NOW, ROOT, fake_extract, fake_oddport

from tvgw import backup, cli, config, db, forget, ingest, mintshadow, pcaps, ports, queries

CANARY = "zz-forget-canary-7f3a.example"
FORMS = [CANARY.encode(), b"\x15zz-forget-canary-7f3a\x07example", CANARY.upper().encode()]
KEPT = "kept-marker-1b2c"


def fresh_tables(tmp_path) -> set[str]:
    conn = db.connect(str(tmp_path / "fresh.db"))
    try:
        return {r[0] for r in conn.execute("SELECT name FROM sqlite_master WHERE type='table'")}
    finally:
        conn.close()


# ---- 1. everything is classified ----------------------------------------------------------------------


def test_every_table_of_the_schema_is_kept_or_forgotten(tmp_path):
    """A table another change adds to db.SCHEMA fails here until forget.TABLES says what to do with it."""
    tables = fresh_tables(tmp_path)
    assert tables == set(forget.TABLES), tables ^ set(forget.TABLES)
    for table, col in forget.TIME_COLUMNS.items():
        assert forget.TABLES[table][0] == forget.FORGET, table
        names = set(col) if isinstance(col, tuple) else {col}
        conn = db.connect(str(tmp_path / "fresh.db"))
        have = {r[1] for r in conn.execute(f"PRAGMA table_info({table})")}
        conn.close()
        assert names <= have, (table, col)
    # every forgotten table with a time column is trimmed after a forget; the rest have none or are bookkeeping
    conn = db.connect(str(tmp_path / "fresh.db"))
    for table, (policy, _) in forget.TABLES.items():
        cols = {r[1] for r in conn.execute(f"PRAGMA table_info({table})")}
        if policy == forget.FORGET and cols & {"t", "t_end"}:
            assert table in forget.TIME_COLUMNS, table
    conn.close()


def _repo_paths() -> set[tuple[str, str]]:
    """(root, first component) of every literal /var/lib/tvgw/... and /var/log/tvgw/... path in the code
    and the deploy files: the trees the units write."""
    found: set[tuple[str, str]] = set()
    pattern = re.compile(r"/var/(lib|log)/tvgw/([A-Za-z0-9_.*<>{}-][A-Za-z0-9_.*<>{}-]*)")
    for base in ("src", "deploy", "packaging"):
        for path in (ROOT / base).rglob("*"):
            if not path.is_file() or path.suffix in (".png", ".md") or "__pycache__" in path.parts:
                continue
            text = path.read_text(encoding="utf-8", errors="replace")
            for kind, first in pattern.findall(text):
                found.add((kind, first))
    found.add(("make", "backup"))  # make backup pulls this tree off the Pi
    return found


def test_every_file_tree_the_units_write_is_kept_or_forgotten():
    """A path under the state or log directory that a new unit, script or module writes fails here
    until forget.STATE_ENTRIES or LOG_ENTRIES classifies it."""
    unclassified = []
    for kind, first in sorted(_repo_paths()):
        entries = forget.LOG_ENTRIES if kind == "log" else forget.STATE_ENTRIES
        name = first.split("<")[0] or first
        if "*" in name:
            continue  # a glob (install.sh's chgrp of the logs there) names no file of its own
        if forget.classify(name, entries) is None:
            unclassified.append(f"/var/{kind}/tvgw/{first}")
    assert not unclassified, unclassified
    # the Settings paths under the state directory, as a test tree or a moved install would put them
    s = config.Settings()
    for field in ("db_path", "pcap_dir", "tvcheck_history", "tvcheck_txt", "reports_dir", "auto_rules"):
        rel = os.path.relpath(getattr(s, field), s.state_dir).split(os.sep)[0]
        assert forget.classify(rel, forget.STATE_ENTRIES) is not None, field
    assert forget.classify("name-keys", forget.STATE_ENTRIES)[0] == forget.FORGET


# ---- 2. a whole gateway tree, forgotten ----------------------------------------------------------------


def fill(conn: sqlite3.Connection, t: float) -> None:
    """One row in every table: the canary in the forgotten ones, a marker in the kept ones."""
    for table, (policy, _) in forget.TABLES.items():
        text = CANARY if policy == forget.FORGET else KEPT
        cols = conn.execute(f"PRAGMA table_info({table})").fetchall()
        names, values = [], []
        for _cid, name, ctype, _notnull, _dflt, pk in cols:
            if pk and ctype == "INTEGER":
                continue
            names.append(name)
            if ctype == "TEXT":
                values.append(f"{text}-{name}" if pk else text)
            elif ctype == "BLOB":
                values.append(text.encode())
            elif ctype == "REAL":
                values.append(t)
            else:
                values.append(1)
        if table == "meta":
            values[0] = "hosts_wm" if policy == forget.FORGET else "kept_key"
            conn.execute("INSERT OR REPLACE INTO meta(key, value) VALUES ('hosts_wm', ?)", (CANARY,))
            values = ["kept_key", KEPT]
        if table == "ingest_state":
            conn.execute(
                "INSERT OR REPLACE INTO ingest_state(source, head) VALUES ('flows', ?)", (CANARY.encode(),)
            )
            values[0] = "oddport"
        q = f"INSERT OR REPLACE INTO {table}({','.join(names)}) VALUES ({','.join('?' * len(names))})"
        conn.execute(q, values)
    conn.commit()


@pytest.fixture()
def tree(gateway, lg):
    """The fake gateway after one ingest, with every table filled and every file tree present."""
    ingest.run(
        gateway, lg, extract=fake_extract, oddport_lines=fake_oddport, gate_lines=lambda _: [], lock=False
    )
    conn = db.connect(gateway.db_path)
    fill(conn, NOW - 86400)
    conn.close()
    state, log, pcap = Path(gateway.state_dir), Path(gateway.flows_log).parent, Path(gateway.pcap_dir)
    (pcap / "tv-20261026-0800.pcap").write_bytes(
        b"\xd4\xc3\xb2\xa1" + b"\x15zz-forget-canary-7f3a\x07example"
    )
    (log / "flows.log.1").write_text(CANARY + "\n", encoding="utf-8")
    (log / "flows.log.2.gz").write_bytes(gzip.compress(CANARY.encode()))
    (log / "gfts-tls.log").write_text(CANARY + "\n", encoding="utf-8")
    with open(gateway.flows_log, "a", encoding="utf-8") as fh:
        fh.write(CANARY + "\n")
    with open(gateway.tvcheck_history, "a", encoding="utf-8") as fh:
        fh.write(f"2026-10-26T09:30:00-05:00\tActive\t{CANARY}\n")
    (state / "tvcheck-history.log.1").write_text(CANARY, encoding="utf-8")
    reports = Path(gateway.reports_dir)
    for sub in ("daily", "weekly", "proposals"):
        (reports / sub).mkdir(parents=True)
        (reports / sub / "2026-10-26.json").write_text(CANARY, encoding="utf-8")
    (reports / "latest.txt").write_text(CANARY, encoding="utf-8")
    (reports / ".from-the-store").write_text("", encoding="utf-8")
    backup.run(gateway.db_path, str(state / "backup"), now=NOW - 86400)
    backup.run(gateway.db_path, str(state / "backup"), now=NOW - 3600)
    (state / "name-keys").mkdir(mode=0o700)
    (state / "name-keys" / "1.key").write_bytes(os.urandom(32))
    # (plain) onscreen.log holds the owner's on-screen confirmations, kept like the TV's settings history
    for kept in ("doh4.txt", "lgtv-keys.sqlite", "auto.rules", "onscreen.log"):
        (state / kept).write_text(KEPT, encoding="utf-8")
    (state / ".unit-stamps").mkdir()
    (state / ".unit-stamps" / "tvgw-pcap").write_text(KEPT, encoding="utf-8")
    return gateway


def live(s):
    return lambda d: {os.path.realpath(os.path.join(s.pcap_dir, "tv-20261026-0900.pcap"))}


def every_file(*roots):
    for root in roots:
        for path in Path(root).rglob("*"):
            if path.is_file():
                yield path


def roots(s):
    return (Path(s.state_dir), Path(s.flows_log).parent, Path(s.pcap_dir))


def contains_canary(path: Path) -> bool:
    data = path.read_bytes()
    if path.suffix == ".gz" and data:
        data = gzip.decompress(data)
    return any(f.lower() in data.lower() for f in FORMS)


def snapshot(s):
    return {str(p): p.read_bytes() for p in every_file(*roots(s))}


def counts(s):
    conn = db.connect(s.db_path, readonly=True)
    try:
        return {t: conn.execute(f"SELECT COUNT(*) FROM {t}").fetchone()[0] for t in forget.TABLES}
    finally:
        conn.close()


def test_a_dry_run_lists_what_would_go_and_changes_nothing(tree):
    before, rows = snapshot(tree), counts(tree)
    r = forget.run(tree, dry_run=True, live=live(tree))
    assert snapshot(tree) == before and counts(tree) == rows
    actions = {(st.action, os.path.basename(st.what)) for st in r.steps}
    assert ("delete-rows", "dns") in actions and ("keep", "rules") in actions
    assert ("delete", "tv-20261026-0800.pcap") in actions and ("keep", "tv-20261026-0900.pcap") in actions
    assert ("empty", "flows.log") in actions and ("delete", "flows.log.2.gz") in actions
    assert ("keep", "lgtv-keys.sqlite") in actions and ("delete", "name-keys") in actions
    assert not any(st.action == "unclassified" for st in r.steps)


def test_forget_leaves_no_trace_of_the_canary_and_keeps_the_gateway(tree):
    rows = counts(tree)
    kept_files = {
        p: (Path(tree.state_dir) / p).read_bytes()
        for p in ("doh4.txt", "lgtv-keys.sqlite", "auto.rules", "onscreen.log")
    }
    r = forget.run(tree, live=live(tree), lock=False)
    assert r.warnings == [], r.warnings
    after = counts(tree)
    for table, (policy, _) in forget.TABLES.items():
        if policy == forget.FORGET:
            assert after[table] == 0, table
        elif table not in ("meta", "ingest_state"):
            assert after[table] == rows[table], table
    # no form of the canary in any file under the tree: the store's raw bytes (secure_delete + VACUUM),
    # the backup made afterwards, gz members, the logs and the pcaps
    leaks = [str(p) for p in every_file(*roots(tree)) if contains_canary(p)]
    assert leaks == []
    conn = db.connect(tree.db_path, readonly=True)
    assert conn.execute("PRAGMA integrity_check").fetchone() == ("ok",)
    assert db.get_meta(conn, "kept_key") == KEPT and db.get_meta(conn, "hosts_wm") is None
    assert float(db.get_meta(conn, forget.FLOOR_KEY)) == NOW
    sources = {r[0] for r in conn.execute("SELECT source FROM ingest_state")}
    assert not sources & set(forget.CURSORS) and "oddport" in sources
    conn.close()
    state, log, pcap = Path(tree.state_dir), Path(tree.flows_log).parent, Path(tree.pcap_dir)
    assert sorted(os.listdir(pcap)) == ["tv-20261026-0900.pcap"]  # the capture's open file stays
    assert sorted(os.listdir(log)) == ["flows.log", "gfts-tls.log", "gfts.log"]
    assert all((log / f).stat().st_size == 0 for f in os.listdir(log))
    assert Path(tree.tvcheck_history).stat().st_size == 0 and not Path(tree.tvcheck_txt).exists()
    assert not (state / "tvcheck-history.log.1").exists() and not (state / "name-keys").exists()
    reports = [p for p in every_file(tree.reports_dir)]
    assert [p.name for p in reports] == [".from-the-store"]
    copies = os.listdir(state / "backup")
    assert len(copies) == 1 and r.steps[-1].action == "backup"
    assert backup._quick_check(str(state / "backup" / copies[0])) == ["ok"]
    for name, data in kept_files.items():
        assert (state / name).read_bytes() == data
    assert (state / ".unit-stamps" / "tvgw-pcap").read_text(encoding="utf-8") == KEPT
    assert any("journal" in line for line in r.residue) and any("Anthropic" in line for line in r.residue)


def test_late_evidence_of_the_forgotten_time_does_not_come_back(tree, lg):
    forget.run(tree, live=live(tree), lock=False)
    # conntrack's late report, a buffered lookup and an hourly reading, all from before the forget
    with open(tree.flows_log, "a", encoding="utf-8") as fh:
        fh.write(FLOW_TCP)
    with open(tree.adguard_querylog, "a", encoding="utf-8") as fh:
        fh.write("\n" + DNS_BLOCKED)
    with open(tree.tvcheck_history, "a", encoding="utf-8") as fh:
        fh.write("2026-10-26T09:40:00-05:00\tActive\tsome.app\n")
    ingest.run(
        tree, lg, extract=fake_extract, oddport_lines=fake_oddport, gate_lines=lambda _: [], lock=False
    )
    after = counts(tree)
    assert all(after[t] == 0 for t in forget.TIME_COLUMNS if t != "ingest_runs"), after
    assert after["ingest_runs"] == 1  # the new run's own row, after the floor
    assert after["hosts"] == 0


def test_a_new_row_after_the_forget_is_kept_and_one_begun_before_it_is_not(tree, lg):
    forget.run(tree, live=live(tree), lock=False)
    # the fixture flow lasted 360 s: ending 60 s after the forget it began before it, and goes
    before = FLOW_TCP.replace("[1793020052.120409]", f"[{NOW + 60:.6f}]")
    after = FLOW_TCP.replace("[1793020052.120409]", f"[{NOW + 1000:.6f}]")
    with open(tree.flows_log, "a", encoding="utf-8") as fh:
        fh.write(before + after)
    ingest.run(
        tree, lg, extract=fake_extract, oddport_lines=fake_oddport, gate_lines=lambda _: [], lock=False
    )
    conn = db.connect(tree.db_path, readonly=True)
    assert conn.execute("SELECT t_end FROM flows").fetchall() == [(NOW + 1000,)]


def test_a_running_filler_is_asked_to_empty_the_minted_address_shadow(tree, monkeypatch, tmp_path):
    """(mint) The shadow's table holds the last day's names and addresses in the in-path filler's memory
    (design decision 96): where the filler runs, forget leaves the stamp that has it empty that memory;
    where it does not, there is no memory and nothing to say."""
    stamp = tmp_path / "filler" / "mint-forget"
    monkeypatch.setattr(mintshadow, "FORGET", str(stamp))

    def shadow(r):
        return [step.action for step in r.steps if step.what == forget.SHADOW_WHAT]

    assert shadow(forget.run(tree, dry_run=True, live=live(tree))) == []
    stamp.parent.mkdir()
    assert shadow(forget.run(tree, dry_run=True, live=live(tree))) == ["empty"] and not stamp.exists()
    assert shadow(forget.run(tree, live=live(tree), lock=False)) == ["empty"] and stamp.exists()


def test_an_unknown_file_is_kept_and_reported(tree):
    odd = Path(tree.state_dir) / "something-new.db"
    odd.write_text(CANARY, encoding="utf-8")
    r = forget.run(tree, live=live(tree), lock=False)
    assert odd.exists()
    assert [st.what for st in r.steps if st.action == "unclassified"] == [str(odd)]


def test_without_knowing_the_live_capture_no_pcap_is_deleted(tree):
    r = forget.run(tree, live=lambda d: None, lock=False)
    assert len(os.listdir(tree.pcap_dir)) == 2
    assert any("pcaps" in w for w in r.warnings) and any("pcaps" in line for line in r.residue)


def test_querylog_empties_adguard_s_log_and_resets_its_cursor(tree):
    Path(tree.adguard_querylog + ".1").write_text(CANARY, encoding="utf-8")
    forget.run(tree, live=live(tree), querylog=True, lock=False)
    assert Path(tree.adguard_querylog).stat().st_size == 0 and not Path(tree.adguard_querylog + ".1").exists()
    conn = db.connect(tree.db_path, readonly=True)
    assert conn.execute("SELECT 1 FROM ingest_state WHERE source='adguard'").fetchone() is None


def test_drop_late_is_a_no_op_on_a_store_never_forgotten(tmp_path):
    conn = db.connect(str(tmp_path / "x.db"))
    conn.execute("INSERT INTO dns(t, qname, blocked) VALUES (1, 'a.example', 0)")
    assert forget.drop_late(conn) == 0
    assert conn.execute("SELECT COUNT(*) FROM dns").fetchone() == (1,)


def test_drop_late_trims_with_the_time_indexes_restores_secure_delete_and_retires_its_floor(tmp_path):
    conn = db.connect(str(tmp_path / "x.db"))
    db.set_meta(conn, forget.FLOOR_KEY, repr(NOW))
    rows = [(NOW - 10, NOW + 5), (None, NOW - 1), (None, NOW + 1), (NOW + 1, NOW + 2)]
    conn.executemany("INSERT INTO flows(t_start, t_end, dst) VALUES (?, ?, '192.0.2.1')", rows)
    before = conn.execute("PRAGMA secure_delete").fetchone()[0]
    assert forget.drop_late(conn, NOW + 60) == 2  # begun before the floor, or ended before it unbegun
    assert conn.execute("SELECT t_start, t_end FROM flows ORDER BY t_end").fetchall() == rows[2:]
    assert conn.execute("PRAGMA secure_delete").fetchone()[0] == before
    plan = " ".join(
        r[-1]
        for r in conn.execute(
            "EXPLAIN QUERY PLAN DELETE FROM flows WHERE t_start < ? OR (t_start IS NULL AND t_end < ?)",
            (NOW, NOW),
        )
    )
    assert "flows_start" in plan and "SCAN flows" not in plan, plan
    # past LATE_DAYS no source can still deliver rows of the forgotten time: the floor goes
    conn.execute("INSERT INTO flows(t_start, t_end, dst) VALUES (?, ?, '192.0.2.1')", (NOW - 10, NOW - 5))
    assert forget.drop_late(conn, NOW + forget.LATE_DAYS * 86400 + 1) == 0
    assert db.get_meta(conn, forget.FLOOR_KEY) is None
    assert conn.execute("SELECT COUNT(*) FROM flows").fetchone() == (3,)


# ---- 3. the command ------------------------------------------------------------------------------------


def test_the_command_refuses_without_yes_when_nobody_can_answer(tree, monkeypatch, capsys):
    monkeypatch.setattr(sys.stdin, "isatty", lambda: False)
    monkeypatch.setattr(cli.config, "load", lambda *a, **k: tree)
    assert cli.main(["forget"]) == 2
    assert "pass --yes" in capsys.readouterr().err
    assert counts(tree)["dns"] > 0


def test_the_dry_run_prints_counts_and_never_the_rows(tree, monkeypatch, capsys):
    monkeypatch.setattr(cli.config, "load", lambda *a, **k: tree)
    monkeypatch.setattr(forget.pcaps, "live_files", live(tree))
    monkeypatch.setattr(forget, "run", _with_live(forget.run, live(tree)))
    assert cli.main(["forget", "--dry-run"]) == 0
    out = capsys.readouterr().out
    assert "would go" in out and "dns" in out and "not reached by tvgw" in out
    assert CANARY not in out


def _with_live(fn, live_fn):
    def wrapped(s, **kw):
        kw.setdefault("live", live_fn)
        return fn(s, **kw)

    return wrapped


def test_the_command_forgets_with_yes(tree, monkeypatch, capsys):
    monkeypatch.setattr(cli.config, "load", lambda *a, **k: tree)
    monkeypatch.setattr(forget, "run", _with_live(lambda s, **kw: _real_run(s, lock=False, **kw), live(tree)))
    assert cli.main(["forget", "--yes"]) == 0, capsys.readouterr().err
    assert counts(tree)["dns"] == 0
    assert "gone" in capsys.readouterr().out


_real_run = forget.run


def test_the_cli_lists_forget():
    assert (
        "forget"
        in subprocess.run(
            [sys.executable, "-m", "tvgw", "--help"],
            capture_output=True,
            encoding="utf-8",
            env={**os.environ, "PYTHONPATH": str(ROOT / "src")},
        ).stdout
    )


def test_a_push_owed_to_adguard_outlives_the_forget_under_no_name(tree):
    """(fin-release) A revert deferred while the upstreams were down is remembered only in `decisions`,
    which forget empties: the debt is kept as one nameless row at the floor, so the next hourly check
    still pushes the reverted rule out of AdGuard and `drop_late` does not take the row back."""
    from tvgw import autoblock

    conn = db.connect(tree.db_path)
    autoblock.log_decision(conn, "apply", autoblock.DEFERRED, NOW - 600, f"||{CANARY}^", CANARY)
    conn.close()
    forget.run(tree, live=live(tree), lock=False)
    conn = db.connect(tree.db_path)
    assert autoblock.push_owed(conn)
    (row,) = autoblock.decisions(conn)
    assert (row["stage"], row["rule"], row["name"], row["t"]) == ("apply", None, None, NOW)
    forget.drop_late(conn, now=NOW + 3600)
    assert autoblock.push_owed(conn)
    conn.close()
    assert [str(p) for p in every_file(*roots(tree)) if contains_canary(p)] == []


def test_a_push_owed_by_a_row_written_late_stays_owed_under_no_name_when_the_late_rows_go(tree):
    """An hourly check that began before the forget stamps its rows with its start, and with a canary
    it runs for minutes: its revert's row is a late one. `drop_late` took the debt with the row, and
    AdGuard kept a rule the file no longer held."""
    from tvgw import autoblock

    forget.run(tree, live=live(tree), lock=False)
    conn = db.connect(tree.db_path)
    autoblock.log_decision(conn, "judge", "reverted", NOW - 60, f"||{CANARY}^", CANARY)
    assert forget.drop_late(conn, now=NOW + 600) == 1
    (row,) = autoblock.decisions(conn)
    assert (row["stage"], row["outcome"], row["rule"], row["name"], row["t"]) == (
        "apply",
        autoblock.DEFERRED,
        None,
        None,
        NOW,
    )
    assert autoblock.push_owed(conn) and forget.drop_late(conn, now=NOW + 1200) == 0
    assert autoblock.decisions(conn) == [row]  # kept once, however often the late rows are swept
    conn.close()


def test_nothing_owed_leaves_decisions_empty_after_the_forget(tree):
    from tvgw import autoblock

    conn = db.connect(tree.db_path)
    autoblock.log_decision(conn, "apply", autoblock.DEFERRED, NOW - 900, "||a.example^", "a.example")
    autoblock.log_decision(conn, "apply", "pushed", NOW - 600)
    conn.close()
    forget.run(tree, live=live(tree), lock=False)
    conn = db.connect(tree.db_path)
    assert autoblock.decisions(conn) == [] and not autoblock.push_owed(conn)
    conn.close()


# ---- 4. what forget must not keep (design decision 90) ---------------------------------------------------
# On 0.4.0 the firewall's counters, the time servers' rows, two kinds of cursor and the open capture file
# each still said when the TV was used. The first tests below are the ones that showed it.

DNS_RULE = "TV DNS to the gateway"  # an accept counter: one count per lookup of the TV's
NTP_ADDR = "203.0.113.77"
REFUSAL = "DoT/DoQ"  # a refusal counter, kept as one total


def _watched_evenings(conn: sqlite3.Connection, day0: float) -> set[int]:
    """Three days of `verify --record` snapshots every 10 minutes, the TV watched 19:00 to 23:00: the
    hours watched, as hour numbers."""
    watched: set[int] = set()
    dns_total = ntp_total = refused = 0
    for step in range(3 * 144):
        t = day0 + step * 600
        on = 19 <= int((t - day0) // 3600) % 24 < 23
        if on:
            dns_total, ntp_total, refused = dns_total + 40, ntp_total + 1, refused + 2
            watched.add(int(t // 3600))
        conn.executemany(
            "INSERT INTO fw_counters(t, rule, packets, bytes) VALUES (?,?,?,?)",
            [
                (t, DNS_RULE, dns_total, dns_total * 70),
                (t, REFUSAL, refused, refused * 60),
                (t, queries.NTP_RULE, ntp_total, ntp_total * 76),
                (t, queries.NTP_SET_ROW, 1, 1024),
                (t, queries.NTP_SERIES + NTP_ADDR, ntp_total, 864000),
            ],
        )
    conn.commit()
    return watched


@pytest.fixture()
def evenings(gateway, lg):
    ingest.run(
        gateway, lg, extract=fake_extract, oddport_lines=fake_oddport, gate_lines=lambda _: [], lock=False
    )
    conn = db.connect(gateway.db_path)
    day0 = NOW - 3 * 86400
    watched = _watched_evenings(conn, day0)
    conn.close()
    return gateway, day0, watched


def test_no_hour_the_tv_was_used_can_be_rebuilt_from_the_counters_after_a_forget(evenings):
    s, day0, watched = evenings
    forget.run(s, live=live(s), lock=False, now=lambda: NOW)
    conn = db.connect(s.db_path, readonly=True)
    rebuilt = {
        h
        for h in range(int(day0 // 3600), int(day0 // 3600) + 72)
        if any(n > 0 for _rule, n in queries.fw_activity(conn, h * 3600, (h + 1) * 3600))
    }
    conn.close()
    assert len(watched) == 12
    assert rebuilt & watched == set()  # 0.4.0: 12 of 12


def test_no_clock_server_of_the_tv_survives_a_forget(evenings):
    s, day0, _ = evenings
    forget.run(s, live=live(s), lock=False, now=lambda: NOW)
    conn = db.connect(s.db_path, readonly=True)
    left = conn.execute(
        "SELECT rule FROM fw_counters WHERE rule LIKE 'ntp: %' OR rule = ?", (queries.NTP_RULE,)
    )
    assert left.fetchall() == []  # 0.4.0: 432 rows of `ntp: 203.0.113.77`, and the rule's total
    served = queries.ntp_servers(conn, day0, NOW)
    conn.close()
    assert served["servers"] == [] and served["requests"] == 0  # 0.4.0: 203.0.113.77, 72 requests


def test_a_refusal_counter_keeps_one_total_at_the_floor_and_no_timeline(evenings):
    s, _, _ = evenings
    conn = db.connect(s.db_path, readonly=True)
    last = conn.execute(
        "SELECT packets, bytes FROM fw_counters WHERE rule=? ORDER BY t DESC, rowid DESC LIMIT 1", (REFUSAL,)
    ).fetchone()
    conn.close()
    forget.run(s, live=live(s), lock=False, now=lambda: NOW)
    conn = db.connect(s.db_path, readonly=True)
    rows = conn.execute("SELECT t, packets, bytes FROM fw_counters WHERE rule=?", (REFUSAL,)).fetchall()
    conn.close()
    assert rows == [(NOW, *last)]  # 0.4.0: all 432 snapshots


def test_no_cursor_keeps_bytes_of_a_file_forget_deleted(gateway, lg):
    from tvgw import ledger

    ledger.append_spool(ledger.spool_path(gateway), ["dispatcher", gateway.tv_if, "up"], now=NOW - 3000)
    ingest.run(
        gateway, lg, extract=fake_extract, oddport_lines=fake_oddport, gate_lines=lambda _: [], lock=False
    )
    forget.run(gateway, live=live(gateway), lock=False, now=lambda: NOW)
    assert not os.path.exists(ledger.spool_path(gateway))
    conn = sqlite3.connect(gateway.db_path)
    heads = dict(conn.execute("SELECT source, head FROM ingest_state"))
    conn.close()
    assert b"dispatcher" not in bytes(heads.get("changes") or b"")  # 0.4.0: b'1793023800\tdispatcher\t...'


@pytest.mark.parametrize("source", ["oddport", "gate", "adport", "gate_inpath", "flowlog"])
@pytest.mark.parametrize(
    ("before", "after"),
    [(NOW - 2799.876544, NOW), (NOW + 5.0, NOW + 5.0), (None, NOW)],
    ids=["the second of the TV's last sample", "past the floor already: it stays", "no cursor yet"],
)
def test_a_journal_cursor_keeps_no_time_from_before_the_floor(gateway, lg, source, before, after):
    """0.4.0 kept each one's last sample to the second. A source with no cursor yet is given one at the
    floor: its first read would otherwise go thirty days back and leave a sample's second there."""
    ingest.run(
        gateway, lg, extract=fake_extract, oddport_lines=fake_oddport, gate_lines=lambda _: [], lock=False
    )
    conn = sqlite3.connect(gateway.db_path)
    conn.execute("DELETE FROM ingest_state WHERE source = ?", (source,))
    if before is not None:
        conn.execute(
            "INSERT INTO ingest_state(source, inode, offset, last_t) VALUES (?, 0, 0, ?)", (source, before)
        )
    conn.commit()
    conn.close()
    forget.run(gateway, live=live(gateway), lock=False, now=lambda: NOW)
    conn = sqlite3.connect(gateway.db_path)
    cursors = dict(conn.execute("SELECT source, last_t FROM ingest_state"))
    conn.close()
    assert cursors[source] == after


def test_the_open_capture_file_is_named_and_goes_once_it_is_finished_and_read(tree):
    """Forget cannot delete the file the capture is writing. It names it, the residue says how long it
    stays, and the hourly prune deletes it as soon as the capture has moved on and ingest has read it,
    whatever PCAP_DAYS says. The file that is open then is never touched."""
    held = Path(tree.pcap_dir) / "tv-20261026-0900.pcap"
    r = forget.run(tree, live=live(tree), lock=False, now=lambda: NOW)
    assert held.exists() and any("open file" in line and "about two hours" in line for line in r.residue)
    conn = db.connect(tree.db_path)
    doomed = forget.doomed_pcaps(conn)
    assert doomed == {held.name}
    new = Path(tree.pcap_dir) / "tv-20261026-1000.pcap"
    new.write_bytes(b"\0" * 64)

    def prune(read: set[str], open_now: Path) -> tuple[list[str], list[str]]:
        return pcaps.prune(tree.pcap_dir, read, 7, 1 << 40, {str(open_now)}, now=NOW + 3600, doomed=doomed)

    assert prune(set(), new) == ([], []) and held.exists()  # finished, and not read yet
    assert prune({held.name}, held) == ([], []) and held.exists()  # read, and still open
    assert prune({held.name, new.name}, new) == ([held.name], []) and new.exists()
    forget.drop_late(conn, now=NOW + (forget.LATE_DAYS + 1) * 86400)
    assert forget.doomed_pcaps(conn) == frozenset()  # the names go with the floor
    conn.close()


def test_without_knowing_the_open_file_every_capture_is_named(tree):
    r = forget.run(tree, live=lambda d: None, lock=False, now=lambda: NOW)
    conn = db.connect(tree.db_path, readonly=True)
    named = forget.doomed_pcaps(conn)
    assert named and named == {p.name for p in Path(tree.pcap_dir).glob("*.pcap")}
    conn.close()
    assert any("none was deleted now" in line and "about two hours" in line for line in r.residue)


# ---- what must read the same after a forget (design decision 90) ------------------------------------
def test_the_clock_ports_guard_reads_the_same_count_before_and_after_a_forget(evenings, kernel_untouched):
    """tvgw-apply closes the clock port only when neither the kernel's list nor the record shows the TV
    using NTP. Forget empties both, so it keeps the record's count as one number for the two weeks the
    guard looks back, and empties the kernel's list only after that number is kept."""
    s, _day0, _watched = evenings

    def seen(now: float) -> int:
        conn = db.connect(s.db_path, readonly=True)
        try:
            since = now - ports.READY_DAYS * 86400
            return queries.ntp_servers(conn, since, now)["requests"] + ports.ntp_seen_kept(conn, now)
        finally:
            conn.close()

    before = seen(NOW)
    assert before > 0 and kernel_untouched == []
    forget.run(s, live=live(s), lock=False, now=lambda: NOW)
    assert kernel_untouched == [None]  # the kernel's list was emptied, once
    assert seen(NOW + 60) == before == seen(NOW + ports.READY_DAYS * 86400 - 1)
    assert seen(NOW + ports.READY_DAYS * 86400) == 0  # and stops vouching when the two weeks are over
    forget.run(s, live=live(s), lock=False, now=lambda: NOW + 3600)  # a second forget keeps the first's
    assert seen(NOW + 3700) == before == seen(NOW + 3600 + ports.READY_DAYS * 86400 - 1)
    conn = sqlite3.connect(s.db_path)
    kept = conn.execute("SELECT value FROM meta WHERE key=?", (ports.NTP_KEPT,)).fetchone()[0]
    conn.close()
    assert NTP_ADDR not in kept and set(json.loads(kept)) == {"requests", "until"}


def test_the_command_the_guard_asks_adds_what_a_forget_kept(evenings, monkeypatch, capsys):
    s, _day0, _watched = evenings
    conn = db.connect(s.db_path, readonly=True)
    before = queries.ntp_servers(conn, NOW - ports.READY_DAYS * 86400, NOW)["requests"]
    conn.close()
    forget.run(s, live=live(s), lock=False, now=lambda: NOW)
    monkeypatch.setattr(cli.time, "time", lambda: NOW + 60)
    assert cli.cmd_ports(type("Asked", (), {"ntp_seen": True})(), s, None) == 0
    assert capsys.readouterr().out == f"ntp_requests={before}\nntp_record=counted\n"


@pytest.mark.parametrize("why", [None, "it needs root"], ids=["emptied", "not emptied"])
def test_a_kernel_list_that_could_not_be_emptied_is_residue_with_its_reason(tree, why):
    assert not any("time servers" in line for line in forget.run(tree, dry_run=True, live=live(tree)).residue)
    r = forget.run(tree, live=live(tree), lock=False, now=lambda: NOW, flush=lambda: why)
    said = [line.partition(":")[0] for line in r.residue if "time servers" in line]
    assert said == ([f"the kernel's list of the TV's time servers was not emptied ({why})"] if why else [])


@pytest.mark.parametrize(
    ("uid", "nft", "answer"),
    [
        (1000, None, "it needs root"),
        (0, 0, None),
        (0, 1, "nft refused, or the gateway does not count NTP"),
        (0, FileNotFoundError(), "nft could not be run (FileNotFoundError)"),
    ],
    ids=["not root", "emptied", "no such list", "no nft"],
)
def test_the_kernels_list_is_emptied_by_root_with_one_nft_command(monkeypatch, uid, nft, answer):
    from conftest import FLUSH_NTP_SET

    ran = []

    def run(argv, **kw):
        ran.append(argv)
        if isinstance(nft, Exception):
            raise nft
        return subprocess.CompletedProcess(argv, nft, "", "")

    monkeypatch.setattr(forget.os, "geteuid", lambda: uid)
    monkeypatch.setattr(forget.subprocess, "run", run)
    assert FLUSH_NTP_SET() == answer
    assert ran == ([] if uid else [["nft", "flush", "set", "inet", "tvgw_ntp", "ntp4"]])


def test_a_series_the_firewall_no_longer_has_is_not_dated_to_the_forget(gateway, lg):
    """A rule that stopped being counted over a day before the newest snapshot (a wall since switched
    on) would, moved to the floor, say it was there at the forget. It goes whole. One a snapshot or two
    missed stays. Two rules that share a comment keep both rows."""
    ingest.run(
        gateway, lg, extract=fake_extract, oddport_lines=fake_oddport, gate_lines=lambda _: [], lock=False
    )
    newest = NOW - 600
    rows = [
        (NOW - 3 * 86400, "STRICT_PORTS=no: count only", 7, 420),
        (newest - forget.FW_STALE - 60, "seen a day and a minute before the newest", 8, 0),
        (newest - forget.FW_STALE, "seen a day before the newest", 9, 0),
    ]
    for t, n in ((NOW - 1200, 4), (newest, 6)):
        rows += [(t, "QUIC", n, 60 * n), (t, "shared comment", n, 0), (t, "shared comment", 2 * n, 0)]
    conn = db.connect(gateway.db_path)
    conn.executemany("INSERT INTO fw_counters(t, rule, packets, bytes) VALUES (?,?,?,?)", rows)
    conn.commit()
    conn.close()
    assert forget.FW_STALE == 86400.0
    forget.run(gateway, live=live(gateway), lock=False, now=lambda: NOW)
    conn = db.connect(gateway.db_path, readonly=True)
    left = conn.execute("SELECT t, rule, packets FROM fw_counters ORDER BY rule, packets").fetchall()
    kept = conn.execute("SELECT COUNT(*) FROM meta WHERE key=?", (ports.NTP_KEPT,)).fetchone()[0]
    conn.close()
    assert left == [
        (NOW, "QUIC", 6),
        (NOW, "seen a day before the newest", 9),
        (NOW, "shared comment", 6),
        (NOW, "shared comment", 12),
    ]
    assert kept == 0  # the TV asked no time server: nothing to keep a count of, and no date to keep


def test_the_day_of_a_forget_and_the_day_after_read_as_a_store_never_forgotten(tmp_path, gateway, lg):
    """Two stores take the same snapshots. One is forgotten at NOW. Afterwards both take the same later
    snapshots. What the firewall is reported to have done after NOW is the same in both, on the day of
    the forget and on the next: the totals kept at the floor are the baseline the kernel's running
    counters are read against."""
    rules = {"TV DNS to the gateway": 40, "DoT/DoQ": 2, "QUIC": 3}

    def snapshots(conn: sqlite3.Connection, t0: float, t1: float, totals: dict[str, int]) -> None:
        t = t0
        while t < t1:
            if 19 <= int(t // 3600) % 24 < 23:
                for rule, step in rules.items():
                    totals[rule] += step
            conn.executemany(
                "INSERT INTO fw_counters(t, rule, packets, bytes) VALUES (?,?,?,?)",
                [(t, rule, n, 60 * n) for rule, n in totals.items()],
            )
            t += 600
        conn.commit()

    stores = {}
    for name in ("forgotten", "kept"):
        s = dataclasses.replace(gateway, db_path=str(tmp_path / f"{name}.db"))
        conn = db.connect(s.db_path)
        totals = dict.fromkeys(rules, 0)
        snapshots(conn, NOW - 3 * 86400, NOW, totals)
        conn.close()
        if name == "forgotten":
            forget.run(s, live=live(gateway), lock=False, now=lambda: NOW)
        conn = db.connect(s.db_path)
        snapshots(conn, NOW + 600, NOW + 2 * 86400, totals)
        stores[name] = conn
    for since, until in ((NOW, NOW + 86400), (NOW + 86400, NOW + 2 * 86400), (NOW - 3600, NOW + 86400)):
        truth = dict(queries.fw_activity(stores["kept"], max(since, NOW), until))
        assert dict(queries.fw_activity(stores["forgotten"], since, until)) == truth
        assert sum(truth.values()) > 0
    for conn in stores.values():
        conn.close()


def test_a_snapshot_that_lands_below_the_floor_after_the_forget_is_dropped_as_late(evenings):
    """A `verify --record` that began before the forget writes its rows after it, the time servers'
    addresses among them. The hourly ingest drops them; the totals at the floor stay."""
    s, _day0, _watched = evenings
    forget.run(s, live=live(s), lock=False, now=lambda: NOW)
    conn = db.connect(s.db_path)
    at_floor = conn.execute("SELECT COUNT(*) FROM fw_counters").fetchone()[0]
    conn.executemany(
        "INSERT INTO fw_counters(t, rule, packets, bytes) VALUES (?,?,?,?)",
        [(NOW - 5, queries.NTP_SERIES + NTP_ADDR, 72, 864000), (NOW - 5, REFUSAL, 24, 1440)],
    )
    assert forget.drop_late(conn, now=NOW + 3600) == 2
    assert conn.execute("SELECT COUNT(*), MIN(t), MAX(t) FROM fw_counters").fetchone() == (at_floor, NOW, NOW)
    conn.close()


def test_every_cursor_the_ingest_keeps_is_reset_moved_to_the_floor_or_kept_for_a_reason(tree, lg):
    """A new cursor must be given its place here: one can hold the first bytes of a file, or the second
    of the TV's last sample. The cursors are read from a store after ingests of every source's file."""
    kept = {
        "adguard": "AdGuard's query log is emptied only with --querylog, which resets it (QUERYLOG_CURSOR)",
        "flowlog_drops": "where the flow logger's drop counts were read to, in the firewall's counters",
        "onscreen": "the owner's own answers about the TV's settings, kept like the settings history",
    }
    from tvgw import ledger, onscreen, tvlive

    ledger.append_spool(ledger.spool_path(tree), ["dispatcher", tree.tv_if, "up"], now=NOW - 3000)
    onscreen.record("voice", "off", onscreen.log_path(tree.state_dir))
    Path(tree.state_dir, tvlive.EVENTS_FILE).write_text(f"{NOW - 100:.3f}\tconn\tup\t\n", encoding="utf-8")
    ingest.run(
        tree, lg, extract=fake_extract, oddport_lines=fake_oddport, gate_lines=lambda _: [], lock=False
    )
    conn = sqlite3.connect(tree.db_path)
    written = {source for (source,) in conn.execute("SELECT source FROM ingest_state")}
    conn.close()
    placed = {*forget.CURSORS, *forget.JOURNAL_CURSORS, *kept}
    assert written <= placed, written - placed
    assert written >= {
        "flows",
        "adguard",
        "tvstate",
        "changes",
        "oddport",
        "onscreen",
    }  # the fixture ingests them
    assert not set(forget.CURSORS) & set(forget.JOURNAL_CURSORS) and forget.QUERYLOG_CURSOR in kept


def test_the_dry_run_counts_the_timeline_that_would_go(evenings):
    s, _day0, _watched = evenings
    plan = {st.what: st.count for st in forget.run(s, dry_run=True, live=live(s)).steps}
    conn = db.connect(s.db_path, readonly=True)
    total = conn.execute("SELECT COUNT(*) FROM fw_counters").fetchone()[0]
    conn.close()
    ntp = next(n for what, n in plan.items() if "ntp: " in what)
    assert (total, ntp, plan[forget.FW_TIMELINE]) == (432 * 5, 432 * 3, 431 * 2)  # two series keep one row


def test_the_hourly_prune_deletes_the_capture_a_forget_named_once_it_is_read(tree, monkeypatch, capsys):
    """`tvgw prune-pcaps` itself: the file that was open at the forget is half an hour old, far under
    PCAP_DAYS, and goes as soon as the capture has moved on to a new file and the ingest has read it."""
    held = Path(tree.pcap_dir) / "tv-20261026-0900.pcap"
    forget.run(tree, live=live(tree), lock=False, now=lambda: NOW)
    new = Path(tree.pcap_dir) / "tv-20261026-1000.pcap"
    new.write_bytes(b"\0" * 64)
    conn = db.connect(tree.db_path)
    conn.execute("INSERT INTO pcaps_done(name, done_at, attempts) VALUES (?, ?, 1)", (held.name, NOW + 3600))
    conn.commit()
    conn.close()
    monkeypatch.setattr(pcaps, "live_files", lambda pcap_dir: {str(new)})
    assert cli.cmd_prune_pcaps(None, tree, None) == 0
    assert capsys.readouterr().out.startswith("tvgw prune-pcaps: deleted 1, kept 1 ")
    assert not held.exists() and new.exists()


def test_the_dry_run_counts_what_the_run_deletes_even_when_the_newest_snapshot_is_of_time_servers_alone(
    evenings,
):
    """The run deletes the time servers' rows first and judges "the newest of all" by what is left. The
    dry run must judge by the same rows, or a newest snapshot that held only such rows would make every
    other series look a day stale."""
    s, _day0, _watched = evenings
    conn = db.connect(s.db_path)
    conn.execute(
        "INSERT INTO fw_counters(t, rule, packets, bytes) VALUES (?, ?, 1, 1024)",
        (NOW + 2 * 86400, queries.NTP_SET_ROW),
    )
    conn.commit()
    before = conn.execute("SELECT COUNT(*) FROM fw_counters").fetchone()[0]
    conn.close()
    steps = forget.run(s, dry_run=True, live=live(s)).steps
    planned = sum(st.count for st in steps if st.action == "delete-rows" and "fw_counters" in st.what)
    forget.run(s, live=live(s), lock=False, now=lambda: NOW)
    conn = db.connect(s.db_path, readonly=True)
    after = conn.execute("SELECT COUNT(*) FROM fw_counters").fetchone()[0]
    conn.close()
    assert (planned, after) == (before - after, 2)  # the two series that are not the time servers' stay


# ---- the clock port's guard must never read "no NTP" because of a forget ---------------------------------
@pytest.mark.parametrize(
    ("listed", "kept"),
    [(0, 72), (71, 72), (500, 500)],
    ids=["an empty list", "a list that holds less", "a list that holds more than the record"],
)
def test_the_count_kept_is_the_larger_of_the_records_and_the_kernels(evenings, listed, kept):
    """The TV's request since the last snapshot is in the kernel's list alone. Forget reads the list
    before it touches the store, keeps the larger count, and empties the list only when that count is
    in the store."""
    s, _day0, _watched = evenings
    at_the_flush = []

    def flush():
        conn = sqlite3.connect(s.db_path)
        at_the_flush.append(ports.ntp_seen_kept(conn, NOW))
        conn.close()

    forget.run(s, live=live(s), lock=False, now=lambda: NOW, listed=lambda: listed, flush=flush)
    assert at_the_flush == [kept]


def test_the_list_is_read_as_the_store_work_ends_and_emptied_before_the_store_is_compacted(
    evenings, monkeypatch
):
    """A request the TV makes while forget works on the store must be in the count. So the list is read
    last, after every row has gone and before the commit; it is emptied as soon as that commit holds
    the count; and the slow part, VACUUM and the integrity check, comes after. Before, the list was read
    first and emptied last, with all of that between."""
    s, _day0, _watched = evenings
    connect, said, at = db.connect, [], {}

    def traced(*args, **kwargs):
        conn = connect(*args, **kwargs)
        conn.set_trace_callback(said.append)
        return conn

    monkeypatch.setattr(forget.db, "connect", traced)
    forget.run(
        s,
        live=live(s),
        lock=False,
        now=lambda: NOW,
        listed=lambda: at.setdefault("the read", list(said)) and 500,
        flush=lambda: at.setdefault("the flush", list(said)) and None,
    )

    def done(when: str, statement: str) -> bool:
        return any(sql.startswith(statement) for sql in at[when])

    assert done("the read", "DELETE FROM fw_counters") and not done("the read", "COMMIT")
    assert done("the flush", "COMMIT") and not done("the flush", "VACUUM")
    assert any(sql.startswith("VACUUM") for sql in said)


def test_a_store_that_fails_after_the_list_was_read_keeps_its_rows_and_the_list(evenings, monkeypatch):
    s, _day0, _watched = evenings

    def full(conn, floor, seen):
        raise sqlite3.OperationalError("database or disk is full")

    monkeypatch.setattr(ports, "keep_ntp_seen", full)
    conn = db.connect(s.db_path, readonly=True)
    before = conn.execute("SELECT COUNT(*) FROM dns").fetchone()[0]
    conn.close()
    with pytest.raises(sqlite3.OperationalError, match="full"):
        forget.run(s, live=live(s), lock=False, now=lambda: NOW, flush=lambda: pytest.fail("emptied"))
    conn = db.connect(s.db_path, readonly=True)
    assert conn.execute("SELECT COUNT(*) FROM dns").fetchone()[0] == before > 0
    conn.close()


def test_a_list_that_cannot_be_read_is_left_alone_and_said_so(evenings, kernel_untouched):
    s, _day0, _watched = evenings
    r = forget.run(s, live=live(s), lock=False, now=lambda: NOW, listed=lambda: None)
    assert kernel_untouched == [] and [line for line in r.residue if "time servers" in line] == [
        "the kernel's list of the TV's time servers was not emptied (what it holds could not be read"
        " first: that needs root, and a gateway that counts NTP): `tvgw verify --record` stores its"
        " addresses again for as long as the list holds them"
    ]


def test_a_forget_run_with_the_clock_behind_the_newest_snapshot_still_keeps_the_count(evenings):
    """The record is read to its newest snapshot, wherever the clock stands at the forget."""
    s, _day0, _watched = evenings
    behind = NOW - 2 * 86400
    forget.run(s, live=live(s), lock=False, now=lambda: behind)
    conn = sqlite3.connect(s.db_path)
    assert ports.ntp_seen_kept(conn, behind + 60) == 72
    conn.close()


def test_with_no_store_there_is_nowhere_to_keep_the_count_so_the_list_is_left(gateway, kernel_untouched):
    assert not os.path.exists(gateway.db_path)
    asked = []
    r = forget.run(gateway, live=lambda d: {"open.pcap"}, lock=False, listed=lambda: asked.append(1) or 5)
    assert asked == [] and kernel_untouched == []
    assert any("there is no store to keep the count" in line for line in r.residue)
    assert any("with no store yet there is nowhere to note them" in line for line in r.residue)


@pytest.mark.parametrize(
    ("named", "open_files", "said"),
    [(False, {"open.pcap"}, True), (False, None, True), (False, set(), False), (True, {"open.pcap"}, False)],
    ids=["a file open", "it cannot be told", "no capture running", "noted in the store"],
)
def test_the_capture_is_residue_only_when_a_file_may_be_open_and_nothing_could_note_it(
    tree, named, open_files, said
):
    lines = forget.residue(tree, live=open_files, named=named)
    assert any("nowhere to note them for deletion" in line for line in lines) == said


def nft_listing(*servers: tuple[str, int | None]) -> str:
    """`nft -j list table inet tvgw_ntp` with these addresses in the list, each with its requests (None:
    an element with no counter)."""
    elems = [
        {
            "elem": {
                "val": address,
                "expires": 600,
                **({} if n is None else {"counter": {"packets": n, "bytes": 76 * n}}),
            }
        }
        for address, n in servers
    ]
    return json.dumps({"nftables": [{"set": {"name": "ntp4", "size": 1024, "elem": elems}}]})


@pytest.mark.parametrize(
    ("uid", "nft", "holds"),
    [
        (1000, (0, nft_listing(("203.0.113.77", 9))), None),
        (0, (0, nft_listing(("203.0.113.77", 9), ("203.0.113.78", 4))), 13),
        (0, (0, nft_listing(("203.0.113.77", None), ("203.0.113.78", None))), 2),
        (0, (0, nft_listing()), 0),
        (0, (0, json.dumps({"nftables": []})), None),
        (0, (1, nft_listing(("203.0.113.77", 9))), None),
        (0, FileNotFoundError(), None),
        (0, subprocess.TimeoutExpired("nft", 30), None),
    ],
    ids=[
        "not root",
        "two servers",
        "addresses without counters count once each",
        "an empty list",
        "no such list",
        "nft fails, whatever it printed",
        "no nft",
        "nft does not answer",
    ],
)
def test_the_kernels_list_is_read_by_root_as_the_requests_it_holds(monkeypatch, uid, nft, holds):
    from conftest import NTP_SET_REQUESTS

    ran = []

    def run(argv, **kw):
        ran.append(argv)
        if isinstance(nft, Exception):
            raise nft
        return subprocess.CompletedProcess(argv, nft[0], nft[1], "")

    monkeypatch.setattr(forget.os, "geteuid", lambda: uid)
    monkeypatch.setattr(forget.subprocess, "run", run)
    assert NTP_SET_REQUESTS() == holds
    assert ran == ([] if uid else [["nft", "-j", "list", "table", "inet", "tvgw_ntp"]])


@pytest.mark.parametrize(
    ("stored", "kept"),
    [
        (json.dumps({"requests": 9, "until": NOW + 1}), 9),
        (json.dumps({"requests": 9, "until": NOW}), 0),
        (json.dumps({"requests": 9}), 0),
        (json.dumps({"until": NOW + 1}), 0),
        (json.dumps({"requests": "many", "until": NOW + 1}), 0),
        ("not json", 0),
        ("[9]", 0),
        (None, 0),
    ],
    ids=[
        "vouching",
        "at its last second",
        "no until",
        "no requests",
        "no number",
        "no JSON",
        "a list",
        "none",
    ],
)
def test_the_kept_count_is_read_with_care_and_goes_when_its_two_weeks_are_over(tmp_path, stored, kept):
    """It is stored under `ntp_seen_kept`. The hourly ingest removes it once it vouches for nothing,
    whether or not the forget's floor is still there."""
    conn = db.connect(str(tmp_path / "tvgw.db"))
    if stored is not None:
        db.set_meta(conn, "ntp_seen_kept", stored)
    assert ports.NTP_KEPT == "ntp_seen_kept" and ports.ntp_seen_kept(conn, NOW) == kept
    forget.drop_late(conn, now=NOW)
    assert (db.get_meta(conn, "ntp_seen_kept") is not None) == bool(kept)
    conn.close()


def test_the_guards_command_stops_adding_the_kept_count_when_it_no_longer_vouches(
    evenings, monkeypatch, capsys
):
    s, _day0, _watched = evenings
    forget.run(s, live=live(s), lock=False, now=lambda: NOW)
    monkeypatch.setattr(cli.time, "time", lambda: NOW + ports.READY_DAYS * 86400)
    assert cli.cmd_ports(type("Asked", (), {"ntp_seen": True})(), s, None) == 0
    assert capsys.readouterr().out == "ntp_requests=0\nntp_record=none\n"


# ---- the kept verify history names no time of a TV reading -----------------------------------------------
def test_a_stored_failure_that_named_its_readings_time_is_rewritten_without_it(tree):
    """Until design decision 90 a failing `tv_paths` check said when the TV was read, and the TV is read
    only while it is on: the kept history marked the hours of use."""
    was = ["tv_paths: second path: Wi-Fi connected (read 2026-10-26T15:20:00-05:00)", "other: as it was"]
    conn = db.connect(tree.db_path)
    conn.execute("INSERT INTO verify(t, ok, failures) VALUES (?, 0, ?)", (NOW - 7200, json.dumps(was)))
    conn.execute("INSERT INTO verify(t, ok, failures) VALUES (?, 0, ?)", (NOW - 6600, json.dumps(was[1:])))
    conn.commit()
    conn.close()
    forget.run(tree, live=live(tree), lock=False, now=lambda: NOW)
    conn = db.connect(tree.db_path, readonly=True)
    stored = [
        json.loads(f)
        for (f,) in conn.execute("SELECT failures FROM verify WHERE t >= ? ORDER BY t", (NOW - 7200,))
    ]
    conn.close()
    assert stored == [["tv_paths: second path: Wi-Fi connected", "other: as it was"], ["other: as it was"]]


@pytest.mark.parametrize(
    ("was", "cleaned"),
    [
        (["a: (as) it (read 15:20) was", "b (read 15:30) c (read 15:40) d"], ["a: (as) it was", "b c d"]),
        (["a: (read with no end", 'b: (x) and "y"'], ["a: (read with no end", 'b: (x) and "y"']),
        ("not a list (read 15:20) of failures", "not a list of failures"),
        ('"one failure (read 15:20) as a JSON string"', '"one failure as a JSON string"'),
        ('{"tv_paths": "Wi-Fi (read 15:20) connected"}', '{"tv_paths": "Wi-Fi connected"}'),
        ('["a (read 15:20) b", 7]', '["a b", 7]'),
    ],
    ids=[
        "each reading time, and no other bracket",
        "one failure takes no words from the next",
        "text",
        "a string",
        "an object",
        "a list of more than strings",
    ],
)
def test_reading_times_are_taken_out_of_each_failure_by_itself(was, cleaned):
    """What `tvgw verify --record` stores is a JSON list of strings; anything else is cleaned as text."""
    stored = was if isinstance(was, str) else json.dumps(was)
    got = forget._without_reading_times(stored)
    assert (got if isinstance(was, str) else json.loads(got)) == cleaned


# ---- the names of the capture files left open ------------------------------------------------------------
@pytest.mark.parametrize(
    ("stored", "names"),
    [
        ('["a.pcap", "b.pcap"]', {"a.pcap", "b.pcap"}),
        ('["a.pcap", 7, null]', {"a.pcap"}),
        ('{"a.pcap": 1}', set()),
        ("not json", set()),
        (None, set()),
    ],
    ids=["two names", "only the names among them", "no list", "no JSON", "nothing stored"],
)
def test_the_named_capture_files_are_read_with_care(tmp_path, stored, names):
    conn = db.connect(str(tmp_path / "tvgw.db"))
    if stored is not None:
        db.set_meta(conn, "forget_pcaps", stored)
    assert forget.PCAPS_KEY == "forget_pcaps" and forget.doomed_pcaps(conn) == names
    conn.close()


def test_only_capture_files_are_named_and_a_missing_capture_directory_names_none(tmp_path):
    (tmp_path / "tv-1.pcap").write_bytes(b"")
    (tmp_path / "notes.txt").write_bytes(b"")
    assert forget._open_pcaps(str(tmp_path), None) == ["tv-1.pcap"]
    assert forget._open_pcaps(str(tmp_path), {str(tmp_path / "tv-1.pcap")}) == ["tv-1.pcap"]
    assert forget._open_pcaps(str(tmp_path), set()) == [] == forget._open_pcaps(str(tmp_path / "none"), None)


def test_a_named_capture_file_older_than_pcap_days_is_deleted_once(tmp_path):
    old = tmp_path / "tv-old.pcap"
    old.write_bytes(b"\0" * 8)
    os.utime(old, (NOW - 30 * 86400, NOW - 30 * 86400))
    deleted, warnings = pcaps.prune(
        str(tmp_path), {old.name}, 7, 1 << 40, set(), now=NOW, doomed=frozenset({old.name})
    )
    assert (deleted, warnings) == ([old.name], [])
