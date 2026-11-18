"""The LG key store's key (design decision 106): the key is copied once from the library's pickled row into
tvgw's own column, read as data so that a row which is code runs nothing, and kept in the library's row for
an older tvgw. The pairing is the thing not to lose: the reference gateway's file, as it is today, must
read with the same key after the change, and a migration that cannot be made must change nothing. No TV:
the library is conftest's stand-in (counting_lgtv), its key file written in the pinned library's format."""

import asyncio
import os
import pickle
import sqlite3

import pytest
from conftest import NOW, counting_lgtv, fake_lgtv, write_lgtv_keys

from tvgw import lgkeys, lgwebos

TV, OTHER = "192.0.2.17", "192.0.2.18"
KEY = "0123456789abcdef0123456789abcdef"  # a webOS client key's shape
# tvgw's tables at schema 1, word for word as every tvgw before decision 106 made them
SCHEMA_1 = """
CREATE TABLE IF NOT EXISTS tvgw_pairing(
    ip TEXT PRIMARY KEY,
    manifest TEXT NOT NULL CHECK (manifest IN ('signed', 'unsigned')),
    paired_at REAL,
    refused_at REAL,
    refused_why TEXT,
    release TEXT,
    os_version TEXT,
    generation TEXT,
    seen_at REAL,
    unreadable TEXT NOT NULL DEFAULT ''
);
CREATE TABLE IF NOT EXISTS tvgw_meta(key TEXT PRIMARY KEY, value TEXT);
INSERT INTO tvgw_meta(key, value) VALUES ('schema', '1');
"""


def reference_file(path):
    """A key file as the reference gateway holds it: the library's table with the TV's pickled key (made
    at pairing), then tvgw's tables at schema 1 with the TV's row, signed, as its migration left it."""
    write_lgtv_keys(path, {TV: KEY})
    sql(path, SCHEMA_1)
    sql(
        path,
        f"INSERT INTO tvgw_pairing(ip, manifest, paired_at, release) VALUES ('{TV}', 'signed', 1, '5.6.2')",
    )
    return path


def sql(path, script: str) -> None:
    conn = sqlite3.connect(path)
    try:
        conn.executescript(script)
    finally:
        conn.close()


def rows(path, query: str) -> list[tuple]:
    conn = sqlite3.connect(path)
    try:
        return conn.execute(query).fetchall()
    finally:
        conn.close()


def changes(path) -> int:
    """SQLite's file change counter (bytes 24 to 27 of the header): one more per committed write."""
    with open(path, "rb") as fh:
        fh.seek(24)
        return int.from_bytes(fh.read(4), "big")


class Code:
    """A row that is code: unpickled, it makes the directory `marker`."""

    def __init__(self, marker):
        self.marker = str(marker)

    def __reduce__(self):
        return os.mkdir, (self.marker,)


def test_the_reference_key_file_migrates_once_and_its_first_reading_hands_the_library_the_same_key(
    monkeypatch, tmp_path
):
    """After the deploy the first reading must find the key and read the TV with no new pairing. The key
    is copied into tvgw's column, the library's row stays byte for byte (an older tvgw rolled back to
    reads it there), the row's record is kept, and the library is handed the key the TV knows. A key the
    library holds for an address with no row gets a `signed` row, as every key from before the table."""
    keys = reference_file(tmp_path / "lgtv-keys.sqlite")
    write_lgtv_keys(keys, {OTHER: "other", "": "no address"})
    library = rows(keys, "SELECT key, value FROM unnamed")
    tv, counts = counting_lgtv()
    fake_lgtv(monkeypatch, tv)
    assert lgwebos.read(TV, str(keys), timeout=0.5).exit_code() == 0
    assert counts["keys"] == [KEY] and counts["prompts"] == 0
    assert rows(keys, "SELECT ip, client_key, manifest, paired_at FROM tvgw_pairing ORDER BY ip") == [
        (TV, KEY, "signed", 1.0),
        (OTHER, "other", "signed", NOW),
    ]
    assert rows(keys, "SELECT key, value FROM unnamed") == library
    assert rows(keys, "SELECT value FROM tvgw_meta") == [("2",)] and lgkeys.migrate(str(keys)) == []


@pytest.mark.parametrize(
    "value",
    [
        pytest.param(lambda marker: pickle.dumps(Code(marker)), id="code"),
        pytest.param(lambda marker: pickle.dumps([KEY]), id="not a string"),
        pytest.param(lambda marker: pickle.dumps(KEY)[:-4], id="cut short"),
        pytest.param(lambda marker: KEY, id="text, not a pickle"),
    ],
)
def test_a_library_row_that_is_not_a_plain_key_is_no_key_and_nothing_in_it_runs(monkeypatch, tmp_path, value):
    """sqlitedict unpickled the row as root on every read (CVE-2024-35515): a row that names a function
    ran it. The row is read as data now: anything but a pickled string is no key, so the reading asks
    the TV nothing, and the row is left where it is."""
    marker = tmp_path / "ran"
    keys = reference_file(tmp_path / "lgtv-keys.sqlite")
    conn = sqlite3.connect(keys)
    with conn:
        conn.execute("UPDATE unnamed SET value = ? WHERE key = ?", (value(marker), TV))
    conn.close()
    tv, counts = counting_lgtv()
    fake_lgtv(monkeypatch, tv)
    assert lgwebos.read(TV, str(keys)).error == lgwebos.NOT_PAIRED and not marker.exists()
    assert counts["create"] == 0 and lgkeys.keys(str(keys)) == {}
    assert (
        rows(keys, "SELECT key FROM unnamed") == [(TV,)] and lgkeys.record(str(keys), TV).manifest == "signed"
    )


def test_once_copied_the_librarys_row_is_never_read_again(tmp_path):
    marker = tmp_path / "ran"
    keys = reference_file(tmp_path / "lgtv-keys.sqlite")
    lgkeys.migrate(str(keys))
    write_lgtv_keys(
        keys, {TV: Code(marker)}
    )  # whoever writes the library's row now writes nothing tvgw reads
    assert lgkeys.keys(str(keys)) == {TV: KEY} and not marker.exists()


def test_no_file_and_a_file_that_is_not_a_database_hold_no_key_and_stay_as_they_are(tmp_path):
    text = tmp_path / "text"
    text.write_text("not the library's database", encoding="utf-8")
    assert lgkeys.keys(str(tmp_path / "none")) == {} and lgkeys.keys(str(text)) == {}
    assert sorted(os.listdir(tmp_path)) == ["text"] and text.read_text(encoding="utf-8").startswith("not")


def test_a_migration_that_cannot_be_made_changes_nothing_and_the_reading_goes_on_with_the_key(
    monkeypatch, tmp_path
):
    """A write the disk refuses, at the migration's last step after the column was added: the whole
    migration is rolled back, the file is as it was to the byte, and the key is read from the library's
    row as data, so the reading goes on as it did before the change. Its own records are written to the
    old table, never with half a migration, and the next open tries again."""
    keys = reference_file(tmp_path / "lgtv-keys.sqlite")
    sql(
        keys,
        "CREATE TRIGGER refused BEFORE INSERT ON tvgw_meta BEGIN SELECT RAISE(ABORT, 'disk I/O error'); END",
    )
    before = keys.read_bytes()
    with pytest.raises(sqlite3.IntegrityError, match="disk I/O error"):
        lgkeys.migrate(str(keys))
    assert lgkeys.keys(str(keys)) == {TV: KEY} and lgkeys.record(str(keys), TV).release == "5.6.2"
    assert keys.read_bytes() == before
    tv, counts = counting_lgtv()
    fake_lgtv(monkeypatch, tv)
    assert lgwebos.read(TV, str(keys), timeout=0.5).exit_code() == 0 and counts["keys"] == [KEY]
    assert "client_key" not in {c[1] for c in rows(keys, "PRAGMA table_info(tvgw_pairing)")}
    sql(keys, "DROP TRIGGER refused")
    assert lgkeys.migrate(str(keys)) == [TV]


def test_a_file_from_before_tvgws_tables_whose_migration_fails_still_reads_the_key_and_no_record(
    monkeypatch, tmp_path
):
    class Clock:
        def time(self):  # a fault inside the transaction, once the tables were made
            raise OSError("the clock cannot be read")

    keys = tmp_path / "lgtv-keys.sqlite"
    write_lgtv_keys(keys, {TV: KEY})
    before = keys.read_bytes()
    monkeypatch.setattr(lgkeys, "time", Clock())
    assert lgkeys.keys(str(keys)) == {TV: KEY} and lgkeys.record(str(keys), TV) is None
    assert keys.read_bytes() == before


@pytest.mark.parametrize("schema", ["DELETE FROM tvgw_meta", "UPDATE tvgw_meta SET value = 'x'"])
def test_a_schema_row_that_is_missing_or_not_a_number_is_migrated(tmp_path, schema):
    keys = reference_file(tmp_path / "lgtv-keys.sqlite")
    sql(keys, schema)
    assert lgkeys.keys(str(keys)) == {TV: KEY} and rows(keys, "SELECT value FROM tvgw_meta") == [("2",)]


@pytest.mark.parametrize("schema", ["2", "3"])  # this tvgw's, and a later one's: read, never written back
def test_once_the_file_is_current_a_read_commits_nothing(tmp_path, schema):
    """Every read of the record ran the schema and wrote the schema row: the live reading reads it every
    60 s, so 1,440 synced writes a day, and a write lock where a read lock would do."""
    keys = reference_file(tmp_path / "lgtv-keys.sqlite")
    lgkeys.migrate(str(keys))
    sql(keys, f"UPDATE tvgw_meta SET value = '{schema}'")
    before = changes(keys)
    for _ in range(5):
        assert lgkeys.record(str(keys), TV) is not None and lgkeys.keys(str(keys)) == {TV: KEY}
    assert changes(keys) == before and rows(keys, "SELECT value FROM tvgw_meta") == [(schema,)]


def test_a_pairing_stores_its_key_where_this_tvgw_and_an_older_one_read_it(tmp_path):
    """The library hands the key a TV sends at a pairing to its storage, which is tvgw's own: the key goes
    into tvgw's column and into the library's row in the library's own format, for an older tvgw."""
    keys = tmp_path / "lgtv-keys.sqlite"
    store = lgwebos._KeyStore(str(keys))
    for sent in ("first", "second", {"client-key": "x"}, ""):  # what a TV sends is not always a key
        asyncio.run(store.set_key(TV, sent))
    assert asyncio.run(store.list_keys()) == {TV: "second"} and asyncio.run(store.get_key(TV)) == "second"
    as_the_library_wrote_it = pickle.dumps("second", protocol=pickle.HIGHEST_PROTOCOL)
    assert rows(keys, "SELECT key, value FROM unnamed") == [(TV, as_the_library_wrote_it)]
    assert lgkeys.record(str(keys), TV).manifest == "signed"


def test_a_key_an_older_tvgw_paired_after_a_rollback_is_copied_again(tmp_path):
    """An older tvgw keeps the key in the library's row and writes schema 1 back on every open: the
    library's row is then the newer key, and the next open of this tvgw copies it again."""
    keys = reference_file(tmp_path / "lgtv-keys.sqlite")
    assert lgkeys.keys(str(keys)) == {TV: KEY}
    write_lgtv_keys(keys, {TV: "paired-under-the-older-tvgw"})
    sql(keys, "UPDATE tvgw_meta SET value = '1'")
    assert lgkeys.keys(str(keys)) == {TV: "paired-under-the-older-tvgw"}
