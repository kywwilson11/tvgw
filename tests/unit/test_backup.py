"""The checked store copy: VACUUM INTO, quick_check before the name, rotation, failure leaves nothing."""

import os
import stat

import pytest

from tvgw import backup, cli, db

NOW = 1793000000  # 2026-10-26T07:33:20Z


def seed(path, n=5):
    conn = db.connect(str(path))
    conn.executemany(
        "INSERT INTO dns(t,qname,qtype,answers,blocked) VALUES (?,?,?,?,?)",
        [(NOW + i, f"h{i}.example", "A", "A:192.0.2.1", 0) for i in range(n)],
    )
    conn.commit()
    conn.close()


def rows(path):
    conn = db.connect(str(path), readonly=True)
    try:
        return conn.execute("SELECT COUNT(*) FROM dns").fetchone()[0]
    finally:
        conn.close()


def test_copy_is_complete_checked_named_in_utc_and_rotated(tmp_path):
    seed(tmp_path / "t.db")
    out = tmp_path / "backup"
    b1 = backup.run(str(tmp_path / "t.db"), str(out), keep=2, now=NOW)
    assert os.path.basename(b1.path) == "tvgw-20261026T073320Z.db" and b1.size > 0
    assert rows(b1.path) == 5 and stat.S_IMODE(os.stat(b1.path).st_mode) == 0o640
    assert (b1.kept, b1.removed) == (["tvgw-20261026T073320Z.db"], [])
    b2 = backup.run(str(tmp_path / "t.db"), str(out), keep=2, now=NOW + 86400)
    b3 = backup.run(str(tmp_path / "t.db"), str(out), keep=2, now=NOW + 2 * 86400)
    assert b2.removed == [] and b3.removed == ["tvgw-20261026T073320Z.db"]
    assert sorted(os.listdir(out)) == [os.path.basename(b2.path), os.path.basename(b3.path)]
    assert not any(f.startswith(".") for f in os.listdir(out))  # no temp file left behind


def test_a_burst_of_copies_in_one_day_keeps_every_earlier_day(tmp_path):
    """Rotation is by UTC day. Kept by name alone, six deploys in one morning, each taking a copy,
    removed that day's 03:40 copy and every earlier day: the burst became the only restore points."""
    seed(tmp_path / "t.db")
    out = tmp_path / "backup"
    daily = [backup.run(str(tmp_path / "t.db"), str(out), now=NOW + d * 86400) for d in range(7)]
    burst = [backup.run(str(tmp_path / "t.db"), str(out), now=NOW + 6 * 86400 + h * 600) for h in range(1, 8)]
    names = sorted(os.listdir(out))
    assert names == sorted(os.path.basename(b.path) for b in (*daily, burst[-1]))  # the day's first + newest
    assert burst[-1].kept == names and burst[-1].removed == [os.path.basename(burst[-2].path)]
    nxt = backup.run(str(tmp_path / "t.db"), str(out), now=NOW + 7 * 86400)
    assert nxt.removed == [os.path.basename(daily[0].path), os.path.basename(burst[-1].path)]
    assert len(os.listdir(out)) == 7


def test_a_copy_that_fails_its_check_is_never_named(tmp_path, monkeypatch):
    seed(tmp_path / "t.db")
    out = tmp_path / "backup"
    monkeypatch.setattr(
        backup, "_quick_check", lambda path: ["*** in database main ***", "Page 3: never used"]
    )
    with pytest.raises(RuntimeError, match="quick_check on the copy"):
        backup.run(str(tmp_path / "t.db"), str(out), now=NOW)
    assert os.listdir(out) == []


def test_keep_must_be_positive_and_source_may_be_missing(tmp_path):
    with pytest.raises(ValueError):
        backup.run(str(tmp_path / "t.db"), str(tmp_path / "b"), keep=0)
    with pytest.raises(Exception):  # noqa: B017 - sqlite reports a missing read-only source its own way
        backup.run(str(tmp_path / "missing.db"), str(tmp_path / "b"))


def test_cli_backup_reports_the_copy(tmp_path, capsys):
    seed(tmp_path / "t.db")
    conf = tmp_path / "tvgw.conf"
    conf.write_text(f"STATE_DIR={tmp_path}\nDB_PATH={tmp_path / 't.db'}\n")
    assert cli.main(["--conf", str(conf), "backup", "--keep", "3"]) == 0
    out = capsys.readouterr().out
    assert out.startswith("tvgw backup: ") and "quick_check ok" in out and "1 kept" in out
    assert len(os.listdir(tmp_path / "backup")) == 1


def test_a_copy_is_on_disk_before_it_is_named_and_an_abandoned_one_is_cleared(tmp_path, monkeypatch):
    """VACUUM INTO does not fsync what it writes, so a power cut after the rename could leave a named,
    empty copy counted as a restore point; the copy is fsynced before its rename and the directory
    after it. A run killed at its timeout (SIGTERM skips the cleanup) left a store-sized temp file no
    later run removed: one over an hour old is removed, a fresh one (a run in progress) is not."""
    import stat
    import time

    seed(tmp_path / "t.db")
    out = tmp_path / "backup"
    out.mkdir()
    stale, fresh = out / ".tvgw-20261020T034000Z.db.tmp", out / ".tvgw-20261026T073000Z.db.tmp"
    stale.write_bytes(b"x" * 100)
    fresh.write_bytes(b"x" * 100)
    os.utime(stale, (time.time() - 7200, time.time() - 7200))
    events = []
    real_fsync, real_replace = os.fsync, os.replace

    def fsync(fd):
        events.append("fsync dir" if stat.S_ISDIR(os.fstat(fd).st_mode) else "fsync file")
        real_fsync(fd)

    def replace(src, dst):
        events.append("replace")
        real_replace(src, dst)

    monkeypatch.setattr(backup.os, "fsync", fsync)
    monkeypatch.setattr(backup.os, "replace", replace)
    b = backup.run(str(tmp_path / "t.db"), str(out), now=NOW)
    assert events == ["fsync file", "replace", "fsync dir"]
    assert sorted(os.listdir(out)) == [fresh.name, os.path.basename(b.path)]


# ---- (depth) the outcome in the store, and the free space a copy needs ----------------------------------------
def meta(path):
    conn = db.connect(str(path), readonly=True)
    try:
        return dict(conn.execute("SELECT key, value FROM meta WHERE key LIKE 'backup_%'").fetchall())
    finally:
        conn.close()


def space(free):
    return lambda path: os.statvfs_result((4096, 4096, 10**6, free // 4096, free // 4096, 0, 0, 0, 0, 255))


def test_a_copy_is_refused_without_twice_the_store_plus_a_gib_free(tmp_path):
    seed(tmp_path / "t.db")
    size = os.path.getsize(tmp_path / "t.db")
    need = 2 * size + backup.HEADROOM
    out = tmp_path / "backup"
    with pytest.raises(backup.NoSpace, match="a copy needs twice the store's size plus 1 GiB"):
        backup.run(str(tmp_path / "t.db"), str(out), now=NOW, statvfs=space(need - 4096))
    assert os.listdir(out) == []  # nothing was written
    b = backup.run(str(tmp_path / "t.db"), str(out), now=NOW, statvfs=space(need + 4096))
    assert os.path.exists(b.path)


def test_each_failure_has_its_fixed_words():
    assert backup.failure(backup.CheckFailed("quick_check on the copy: x")) == backup.CHECK_FAILED
    assert backup.failure(backup.NoSpace("1 MiB free")) == backup.NO_SPACE
    assert backup.failure(OSError(5, "Input/output error")) == backup.WRITE_FAILED
    assert set(backup.FAILURES) == {backup.CHECK_FAILED, backup.NO_SPACE, backup.WRITE_FAILED}
    assert issubclass(backup.CheckFailed, RuntimeError)  # callers that caught RuntimeError still do


def test_record_keeps_the_last_good_copy_and_the_failure_after_it(tmp_path):
    import json

    path = tmp_path / "t.db"
    seed(path)
    backup.record(str(path), None, t=NOW)
    assert meta(path) == {"backup_ok_t": repr(float(NOW))}
    backup.record(str(path), backup.NO_SPACE, t=NOW + 86400)
    got = meta(path)
    assert got["backup_ok_t"] == repr(float(NOW))
    assert json.loads(got["backup_error"]) == {"t": float(NOW + 86400), "why": backup.NO_SPACE}
    backup.record(str(path), None, t=NOW + 2 * 86400)  # a good copy clears the failure
    assert meta(path) == {"backup_ok_t": repr(float(NOW + 2 * 86400))}
    backup.record(str(tmp_path / "none.db"), None)  # no store: none is created for it
    assert not (tmp_path / "none.db").exists()


def test_cli_backup_records_its_outcome_for_verify(tmp_path, monkeypatch, capsys):
    import json

    seed(tmp_path / "t.db")
    conf = tmp_path / "tvgw.conf"
    conf.write_text(f"STATE_DIR={tmp_path}\nDB_PATH={tmp_path / 't.db'}\n")
    assert cli.main(["--conf", str(conf), "backup"]) == 0
    assert set(meta(tmp_path / "t.db")) == {"backup_ok_t"}
    monkeypatch.setattr(backup, "_quick_check", lambda path: ["*** in database main ***"])
    assert cli.main(["--conf", str(conf), "backup"]) == 1
    assert "FAILED: quick_check on the copy" in capsys.readouterr().err
    assert json.loads(meta(tmp_path / "t.db")["backup_error"])["why"] == backup.CHECK_FAILED
    assert cli.main(["--conf", str(conf), "backup", "--keep", "0"]) == 2  # a usage error is no outcome
    assert "--keep must be at least 1" in capsys.readouterr().err


def test_a_result_that_cannot_be_recorded_is_said_and_the_copy_stands(tmp_path, monkeypatch, capsys):
    import sqlite3

    seed(tmp_path / "t.db")
    conf = tmp_path / "tvgw.conf"
    conf.write_text(f"STATE_DIR={tmp_path}\nDB_PATH={tmp_path / 't.db'}\n")

    def locked(path, why=None, t=None):
        raise sqlite3.OperationalError("database is locked")

    monkeypatch.setattr(backup, "record", locked)
    assert cli.main(["--conf", str(conf), "backup"]) == 0
    assert "could not record the result in the store: database is locked" in capsys.readouterr().err


def test_trim_keeps_the_newest_copies_for_the_doctor(tmp_path):
    d = tmp_path / "backup"
    d.mkdir()
    for name in (
        "tvgw-20261020T034000Z.db",
        "tvgw-20261021T034000Z.db",
        "tvgw-20261022T034000Z.db",
        ".tvgw-x.db.tmp",
        "notes.txt",
    ):
        (d / name).write_text("x")
    assert backup.trim(str(d), 2) == ["tvgw-20261020T034000Z.db"]
    assert sorted(p.name for p in d.iterdir()) == [
        ".tvgw-x.db.tmp",
        "notes.txt",
        "tvgw-20261021T034000Z.db",
        "tvgw-20261022T034000Z.db",
    ]
    assert backup.trim(str(tmp_path / "none"), 2) == []
    with pytest.raises(ValueError):
        backup.trim(str(d), 0)


def test_the_newest_copy_is_dated_by_its_name(tmp_path):
    """(depth) What verify's store_backup reads when no run recorded its outcome: the newest named copy,
    which is a checked one, in UTC. Temporary files and anything else are not copies."""
    seed(tmp_path / "t.db")
    out = tmp_path / "backup"
    assert backup.directory(str(tmp_path)) == str(out)
    assert backup.newest_copy(str(out)) is None  # no directory yet
    for d in (0, 2, 1):
        backup.run(str(tmp_path / "t.db"), str(out), now=NOW + d * 86400)
    (out / ".tvgw-20991231T000000Z.db.tmp").write_text("x")
    (out / "notes.txt").write_text("x")
    assert backup.newest_copy(str(out)) == float(NOW + 2 * 86400)
