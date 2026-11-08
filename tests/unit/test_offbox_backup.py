"""(reliability) The copy that leaves the box and the drill that proves a copy restores (design decision
73): `tvgw backup --export` hands the newest checked copy to age, encrypted to the owner's key, on standard
output, and refuses without a key, age or a copy; `tvgw restore --check` opens a plain or an encrypted copy
in a scratch store, checks it, migrates it, counts it, removes the scratch, and refuses a damaged copy, a
newer one and a file that is no copy; `make backup` pulls the encrypted copy. A stand-in for age keeps the
plumbing testable without it; with the real age installed, a round trip runs too."""

import hashlib
import os
import shutil
import sqlite3
import subprocess
import sys

import pytest
from conftest import NOW, ROOT

from tvgw import backup, cli, config, db

RECIPIENT = ("age1" + "qpzry9x8gf2tvdw0s3jn54khce6mua7l" * 2)[:62]  # an X25519 recipient's shape
# a stand-in for age: the same arguments, a header, and the bytes turned over; --decrypt needs a key file
STUB = """#!{python}
import sys
a = sys.argv[1:]
if a[0] == "--encrypt":
    data = open(a[3], "rb").read()
    sys.stdout.buffer.write(b"age-encryption.org/v1\\n-> X25519 " + a[2].encode() + b"\\n---\\n" + bytes(b ^ 0x5A for b in data))
elif a[0] == "--decrypt":
    if "AGE-SECRET-KEY-" not in open(a[2]).read():
        sys.exit("age: error: no identity matched any of the recipients")
    body = open(a[5], "rb").read().split(b"\\n---\\n", 1)[1]
    open(a[4], "wb").write(bytes(b ^ 0x5A for b in body))
"""


@pytest.fixture
def age(tmp_path):
    path = tmp_path / "bin" / "age"
    path.parent.mkdir()
    path.write_text(STUB.format(python=sys.executable), encoding="utf-8")
    path.chmod(0o755)
    return str(path)


@pytest.fixture
def copies(tmp_path):
    """A store with rows, and one checked copy of it in its backup directory."""
    store = tmp_path / "tvgw.db"
    conn = db.connect(str(store))
    conn.executemany(
        "INSERT INTO dns(t, qname, blocked) VALUES (?, ?, 0)",
        [(NOW - 7200 + k, f"n{k}.example") for k in range(5)],
    )
    conn.execute(
        "INSERT INTO flows(t_start, t_end, dst) VALUES (?, ?, '203.0.113.10')", (NOW - 100, NOW - 50)
    )
    conn.commit()
    conn.close()
    directory = tmp_path / "backup"
    made = backup.run(str(store), str(directory), now=NOW - 3 * 3600)
    return directory, made.path


def digest(path) -> str:
    with open(path, "rb") as fh:
        return hashlib.sha256(fh.read()).hexdigest()


def test_the_export_is_the_newest_copy_encrypted_and_nothing_in_plain(tmp_path, age, copies):
    directory, copy = copies
    out = tmp_path / "pulled.db.age"
    with open(out, "wb") as fh:
        code, said = backup.export(str(directory), RECIPIENT, fh.fileno(), which=lambda n: age, now=NOW)
    assert code == 0 and said == f"{os.path.basename(copy)}, made 3 hours ago, encrypted to your age key"
    blob = out.read_bytes()
    assert blob.startswith(b"age-encryption.org/v1\n") and backup.SQLITE_MAGIC not in blob
    assert sorted(os.listdir(directory)) == [os.path.basename(copy)]  # nothing new beside the copies


@pytest.mark.parametrize(
    ("recipient", "has_age", "with_copy", "code", "said"),
    [
        ("", True, True, 2, backup.NO_RECIPIENT),
        (RECIPIENT, False, True, 1, backup.NO_AGE),
        (RECIPIENT, True, False, 1, "no checked copy yet: run sudo tvgw backup first"),
    ],
)
def test_the_export_refuses_without_a_key_age_or_a_copy(
    tmp_path, age, recipient, has_age, with_copy, code, said
):
    directory = tmp_path / "backup"
    directory.mkdir()
    if with_copy:
        (directory / "tvgw-20261108T034000Z.db").write_bytes(backup.SQLITE_MAGIC)
    with open(tmp_path / "out", "wb") as fh:
        got = backup.export(str(directory), recipient, fh.fileno(), which=lambda n: age if has_age else None)
    assert got == (code, said)
    assert (tmp_path / "out").read_bytes() == b""


def test_a_failed_age_is_a_failed_export(tmp_path, copies):
    directory, _ = copies
    broken = tmp_path / "age-broken"
    broken.write_text("#!/bin/sh\necho 'age: error: malformed recipient' >&2\nexit 1\n", encoding="utf-8")
    broken.chmod(0o755)
    with open(tmp_path / "out", "wb") as fh:
        code, said = backup.export(str(directory), RECIPIENT, fh.fileno(), which=lambda n: str(broken))
    assert code == 1 and said == "age could not encrypt the copy: age: error: malformed recipient"


def test_a_plain_copy_restores_into_a_scratch_store_that_goes(tmp_path, copies):
    _, copy = copies
    before = digest(copy)
    scratch = tmp_path / "scratch"
    scratch.mkdir()
    drill = backup.restore_check(copy, scratch_root=str(scratch))
    assert drill.ok, drill.lines
    assert drill.lines[0] == (
        f"{os.path.basename(copy)} restores: integrity ok, schema {db.SCHEMA_VERSION} opened as"
        f" {db.SCHEMA_VERSION} by this tvgw, checked again"
    )
    assert drill.lines[1].startswith("rows: 5 lookups, 1 connections, ") and "lookups from " in drill.lines[1]
    assert os.listdir(scratch) == []  # the scratch store is gone
    assert digest(copy) == before  # the copy itself only read


def test_an_encrypted_copy_round_trips_with_its_key_and_says_why_without_one(tmp_path, age, copies):
    directory, _ = copies
    pulled = tmp_path / "tvgw.db.age"
    with open(pulled, "wb") as fh:
        assert backup.export(str(directory), RECIPIENT, fh.fileno(), which=lambda n: age)[0] == 0
    key = tmp_path / "tvgw-backup.key"
    key.write_text("# public key: " + RECIPIENT + "\nAGE-SECRET-KEY-1STANDIN\n", encoding="utf-8")
    ok = backup.restore_check(str(pulled), str(key), which=lambda n: age)
    assert ok.ok and ok.lines[1].startswith("rows: 5 lookups")
    wrong = tmp_path / "other.key"
    wrong.write_text("not a key\n", encoding="utf-8")
    bad = backup.restore_check(str(pulled), str(wrong), which=lambda n: age)
    assert not bad.ok and bad.lines == [
        "age could not decrypt tvgw.db.age: age: error: no identity matched any of the recipients"
    ]
    none = backup.restore_check(str(pulled), None, which=lambda n: age)
    assert not none.ok and "give --identity" in none.lines[0]
    assert backup.restore_check(str(pulled), str(key), which=lambda n: None).lines == [backup.NO_AGE]


def test_a_damaged_copy_a_newer_one_and_a_file_that_is_no_copy_are_refused(tmp_path, copies):
    _, copy = copies
    damaged = tmp_path / "damaged.db"
    with open(copy, "rb") as fh:
        data = bytearray(fh.read())
    for i in range(4096 + 100, len(data), 997):  # every page but the header page, garbled
        data[i] ^= 0xFF
    damaged.write_bytes(bytes(data))
    drill = backup.restore_check(str(damaged))
    assert not drill.ok and ("is damaged" in drill.lines[0] or "does not open as a store" in drill.lines[0])
    newer = tmp_path / "newer.db"
    shutil.copyfile(copy, newer)
    raw = sqlite3.connect(newer)
    raw.execute("UPDATE meta SET value = ? WHERE key = 'schema'", (str(db.SCHEMA_VERSION + 1),))
    raw.commit()
    raw.close()
    drill = backup.restore_check(str(newer))
    assert drill.lines == [
        f"newer.db was written by a newer tvgw (schema {db.SCHEMA_VERSION + 1}); this one restores up to schema"
        f" {db.SCHEMA_VERSION}"
    ]
    text = tmp_path / "notes.txt"
    text.write_text("hello\n", encoding="utf-8")
    assert backup.restore_check(str(text)).lines == [
        "notes.txt is neither a copy of the store nor an age-encrypted one"
    ]
    assert not backup.restore_check(str(tmp_path / "missing.db")).ok


def test_restore_check_needs_no_settings_and_exits_by_its_verdict(tmp_path, copies, capsys, monkeypatch):
    _, copy = copies
    missing = tmp_path / "no-such.conf"  # the owner's computer has no settings file
    assert cli.main(["--conf", str(missing), "restore", "--check", copy]) == 0
    assert capsys.readouterr().out.startswith(f"tvgw restore --check: {os.path.basename(copy)} restores")
    blob = tmp_path / "x.db.age"
    blob.write_bytes(b"age-encryption.org/v1\n...")
    assert cli.main(["restore", "--check", str(blob)]) == 2  # encrypted, and no --identity
    (tmp_path / "junk.db").write_bytes(b"junk")
    assert cli.main(["restore", "--check", str(tmp_path / "junk.db")]) == 1


def test_the_export_refuses_a_terminal(tmp_path, capsys, monkeypatch):
    conf = tmp_path / "tvgw.conf"
    conf.write_text(f"STATE_DIR={tmp_path}\nBACKUP_RECIPIENT={RECIPIENT}\n", encoding="utf-8")
    monkeypatch.setattr(sys.stdout, "isatty", lambda: True)
    assert cli.main(["--conf", str(conf), "backup", "--export"]) == 2
    assert "the copy is binary" in capsys.readouterr().err


def test_the_recipient_is_an_age_public_key_or_nothing(tmp_path):
    conf = tmp_path / "tvgw.conf"
    assert config.load(conf).backup_recipient == ""
    conf.write_text(f"BACKUP_RECIPIENT={RECIPIENT}\n", encoding="utf-8")
    assert config.load(conf).backup_recipient == RECIPIENT
    for bad in (
        "age1short",
        "ssh-ed25519",
        RECIPIENT.upper(),
        RECIPIENT + "x",
        RECIPIENT.replace("q", "b", 1),
    ):
        conf.write_text(f"BACKUP_RECIPIENT={bad}\n", encoding="utf-8")
        with pytest.raises(ValueError, match="BACKUP_RECIPIENT"):
            config.load(conf)


def test_make_backup_pulls_the_encrypted_copy_and_names_it_only_on_success():
    text = (ROOT / "Makefile").read_text(encoding="utf-8")
    recipe = text[text.index("\nbackup:") : text.index("\nbackup-plain:")]
    assert "ssh $(PI) 'sudo tvgw backup --export' >\"$$part\"" in recipe
    assert 'then mv "$$part" "backups/tvgw-$$stamp.db.age"' in recipe and "exit 1" in recipe
    assert "rsync" not in recipe  # the plain pull is backup-plain's, by name
    assert 'rsync -a --rsync-path="sudo rsync" $(PI):/var/lib/tvgw/backup/ backups/' in text


@pytest.mark.skipif(
    shutil.which("age") is None or shutil.which("age-keygen") is None, reason="age is not installed"
)
def test_a_round_trip_through_the_real_age(tmp_path, copies):
    directory, _ = copies
    key = tmp_path / "k"
    subprocess.run(["age-keygen", "-o", str(key)], check=True, capture_output=True)
    public = next(line.split(": ")[1] for line in key.read_text().splitlines() if "public key" in line)
    pulled = tmp_path / "p.db.age"
    with open(pulled, "wb") as fh:
        assert backup.export(str(directory), public, fh.fileno())[0] == 0
    assert backup.restore_check(str(pulled), str(key)).ok
