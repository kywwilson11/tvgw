"""Schema 9, research pass 2's one bump: a populated schema 8 store migrates once, keeps every row, and
ends with the same tables, columns, indexes and trigger as a store created at 9 (design decisions 41,
45 and 48; docs/reference/data-model.md, schema versions)."""

import os
import sqlite3

from tvgw import autoblock, db

HERE = os.path.dirname(__file__)
V8_TABLES = (
    "flows", "dns", "tls", "tls_noname", "http", "lanprobe", "tvstate", "tvsettings", "oddport", "gate",
    "hosts", "rules", "auto_rules", "judgments", "verify", "fw_counters", "pcaps_done", "ingest_runs",
)  # fmt: skip
NEW_TABLES = {"adport", "decisions", "auto_queue", "changes", "gw_samples", "judge_shadow"}


def old_store(path: str) -> dict[str, int]:
    """A schema 8 store with one row in every table (two in auto_rules), as the Pi holds it today."""
    with open(os.path.join(HERE, "schema8.sql"), encoding="utf-8") as fh:
        script = fh.read()
    c = sqlite3.connect(path)
    c.executescript(script)
    c.execute("INSERT INTO meta(key, value) VALUES ('schema', '8')")
    for table in V8_TABLES:
        cols = c.execute(f"PRAGMA table_info({table})").fetchall()
        names, values = [], []
        for _cid, name, ctype, _notnull, _dflt, pk in cols:
            if pk and ctype == "INTEGER":
                continue
            names.append(name)
            values.append({"TEXT": f"{table}-{name}", "REAL": 1_761_955_200.0, "BLOB": b"x"}.get(ctype, 1))
        marks = ", ".join("?" * len(values))
        c.execute(f"INSERT INTO {table}({', '.join(names)}) VALUES ({marks})", values)
    c.execute(
        "INSERT INTO auto_rules(rule, name, added_t, trial_until, verdict) VALUES (?, ?, ?, ?, ?)",
        ("||b.example^", "b.example", 1_761_955_200.0, 1_762_041_600.0, None),
    )
    c.commit()
    counts = {t: c.execute(f"SELECT COUNT(*) FROM {t}").fetchone()[0] for t in V8_TABLES}
    c.close()
    return counts


def shape(conn: sqlite3.Connection) -> dict:
    """Every table's columns, and the names of every index, trigger and view."""
    objs = conn.execute("SELECT type, name FROM sqlite_master WHERE name NOT LIKE 'sqlite_%'").fetchall()
    tables = sorted(n for t, n in objs if t == "table")
    return {
        "tables": {t: sorted(r[1] for r in conn.execute(f"PRAGMA table_info({t})")) for t in tables},
        "others": sorted((t, n) for t, n in objs if t != "table"),
    }


def test_a_populated_schema_8_store_migrates_to_9_once(tmp_path):
    old = str(tmp_path / "old.db")
    counts = old_store(old)
    conn = db.connect(old)
    assert db.get_meta(conn, "schema") == "9" == str(db.SCHEMA_VERSION)
    # every row of schema 8 is still there
    assert {t: conn.execute(f"SELECT COUNT(*) FROM {t}").fetchone()[0] for t in V8_TABLES} == counts
    # the new tables, empty, and the two new auto_rules columns, NULL on the rows that predate them
    names = {r[0] for r in conn.execute("SELECT name FROM sqlite_master WHERE type='table'")}
    assert names >= NEW_TABLES and set(db.TABLES) == names - {"meta", "ingest_state"}
    assert all(conn.execute(f"SELECT COUNT(*) FROM {t}").fetchone()[0] == 0 for t in NEW_TABLES)
    rows = {r["rule"]: r for r in autoblock.rows(conn)}
    assert set(rows) == {"auto_rules-rule", "||b.example^"}
    assert all(r["canary"] is None and r["trial_id"] is None for r in rows.values())
    conn.close()
    # the migrated store has exactly the shape of one created at 9
    fresh = db.connect(str(tmp_path / "new.db"))
    migrated = db.connect(old)
    assert shape(migrated) == shape(fresh)
    # decisions stays append-only after the migration
    migrated.execute("INSERT INTO decisions(t, stage, outcome) VALUES (0, 'gate', 'ok')")
    try:
        migrated.execute("UPDATE decisions SET outcome = 'x'")
        raise AssertionError("an UPDATE of decisions went through")
    except sqlite3.DatabaseError as e:
        assert "append-only" in str(e)
    migrated.rollback()
    before = shape(migrated)
    migrated.close()
    again = db.connect(old)  # a second open changes nothing
    assert shape(again) == before and db.get_meta(again, "schema") == "9"
    again.close()


def test_a_reader_of_an_unmigrated_store_still_opens_it(tmp_path):
    """The brief runs read-only and may open the store before any writer migrated it (install.sh's
    first writer is tvgw-analyze, at its end): the read-only open must not need schema 9."""
    old = str(tmp_path / "old.db")
    old_store(old)
    conn = db.connect(old, readonly=True)
    assert db.get_meta(conn, "schema") == "8"
    conn.close()
