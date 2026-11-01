"""(record) tvgw forget: every table and file tree is classified, the viewing record is gone in every
encoding (the store file's raw bytes included), the gateway's own state is untouched, and late
evidence of the forgotten time cannot come back through the next ingest."""

import gzip
import os
import re
import sqlite3
import subprocess
import sys
from pathlib import Path

import pytest
from conftest import DNS_BLOCKED, FLOW_TCP, NOW, fake_extract, fake_oddport

from tvgw import backup, cli, config, db, forget, ingest

ROOT = Path(__file__).resolve().parents[2]
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
        names = {c for c in re.findall(r"[a-z_]+", col)} - {"coalesce"}
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
    for kept in ("doh4.txt", "lgtv-keys.sqlite", "auto.rules"):
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
        p: (Path(tree.state_dir) / p).read_bytes() for p in ("doh4.txt", "lgtv-keys.sqlite", "auto.rules")
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
