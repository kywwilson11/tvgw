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
