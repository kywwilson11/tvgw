"""(reliability) The store's version is never lowered: a writer refuses a store a newer tvgw wrote, having
written nothing to it, and says so in one line; an up-to-date store's open writes nothing (design decision
73)."""

import hashlib
import os
import sqlite3

import pytest

from tvgw import cli, db


def fingerprint(path) -> tuple[str, int, list[str]]:
    """The file's bytes, its mtime and what lies beside it: a refused open must change none of them."""
    with open(path, "rb") as fh:
        data = hashlib.sha256(fh.read()).hexdigest()
    return data, os.stat(path).st_mtime_ns, sorted(os.listdir(os.path.dirname(path)))


def stamped(path, value: str) -> None:
    """A store as a tvgw that records `value` left it: built by this one, then relabelled by hand."""
    db.connect(str(path)).close()
    raw = sqlite3.connect(path)
    raw.execute("UPDATE meta SET value = ? WHERE key = 'schema'", (value,))
    raw.execute("CREATE TABLE from_the_future(x)")  # what a newer tvgw added, which must stay untouched
    raw.commit()
    raw.close()


def test_a_writer_refuses_a_newer_store_and_writes_nothing_to_it(tmp_path):
    path = tmp_path / "tvgw.db"
    newer = str(db.SCHEMA_VERSION + 1)
    stamped(path, newer)
    before = fingerprint(path)
    with pytest.raises(db.StoreTooNew) as e:
        db.connect(str(path))
    assert fingerprint(path) == before  # no byte, no journal left beside it, no new mtime
    assert e.value.found == newer
    said = str(e.value)
    assert f"schema {newer}" in said and f"schema {db.SCHEMA_VERSION} at most" in said
    assert "does not write to it" in said and "tvgw restore --check" in said
    assert isinstance(e.value, sqlite3.Error)  # every caller that survives a store it cannot open survives it
    conn = db.connect(str(path), readonly=True)  # a reader still opens it: reading changes nothing
    assert db.get_meta(conn, "schema") == newer
    conn.close()


@pytest.mark.parametrize("value", ["seventeen", "", "12.5", "-1", "1e3"])
def test_a_version_that_is_not_a_whole_number_is_refused_too(tmp_path, value):
    """It cannot be shown to be lower, so it is not written over."""
    path = tmp_path / "tvgw.db"
    stamped(path, value)
    before = fingerprint(path)
    with pytest.raises(db.StoreTooNew):
        db.connect(str(path))
    assert fingerprint(path) == before


@pytest.mark.parametrize("found", range(1, db.SCHEMA_VERSION + 4))
def test_the_recorded_version_never_goes_down(tmp_path, found):
    """Every version a store can carry, opened by this code: the version after is never below the one
    before, and a lower one is raised to this code's."""
    path = tmp_path / "tvgw.db"
    stamped(path, str(found))
    try:
        db.connect(str(path)).close()
    except db.StoreTooNew:
        assert found > db.SCHEMA_VERSION
    else:
        assert found <= db.SCHEMA_VERSION
    raw = sqlite3.connect(path)
    after = int(raw.execute("SELECT value FROM meta WHERE key = 'schema'").fetchone()[0])
    raw.close()
    assert after >= found
    assert after == max(found, db.SCHEMA_VERSION) if found <= db.SCHEMA_VERSION else after == found


def test_an_up_to_date_store_is_opened_without_a_write(tmp_path):
    """The version row used to be replaced at every writer's open: a journal written and three fsyncs on the
    card, every ten minutes and every hour, for nothing."""
    path = tmp_path / "tvgw.db"
    db.connect(str(path)).close()
    os.utime(path, ns=(1, 1))  # an mtime no write can keep
    before = fingerprint(path)
    conn = db.connect(str(path))
    assert conn.in_transaction is False  # and holds no write lock for the next writer to wait on
    conn.close()
    assert fingerprint(path) == before


def test_a_new_store_and_an_old_one_get_this_codes_version(tmp_path):
    new = tmp_path / "new.db"
    conn = db.connect(str(new))
    assert db.get_meta(conn, "schema") == str(db.SCHEMA_VERSION)
    conn.close()
    old = tmp_path / "old.db"
    raw = sqlite3.connect(old)
    raw.execute("CREATE TABLE meta(key TEXT PRIMARY KEY, value TEXT)")  # a store from before the version row
    raw.commit()
    raw.close()
    conn = db.connect(str(old))
    assert db.get_meta(conn, "schema") == str(db.SCHEMA_VERSION)
    conn.close()


def test_the_command_says_why_in_one_line_and_exits_1(tmp_path, capsys):
    path = tmp_path / "tvgw.db"
    stamped(path, str(db.SCHEMA_VERSION + 4))
    conf = tmp_path / "tvgw.conf"
    conf.write_text(f"STATE_DIR={tmp_path}\nDB_PATH={path}\n", encoding="utf-8")
    before = fingerprint(path)[:2]
    assert cli.main(["--conf", str(conf), "ingest"]) == 1
    err = capsys.readouterr().err
    assert err.startswith(f"tvgw: the store {path} was written by a newer tvgw") and err.count("\n") == 1
    assert "Traceback" not in err
    assert fingerprint(path)[:2] == before
