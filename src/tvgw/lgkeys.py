"""tvgw's half of the LG key store: the client key itself, which manifest a pairing was made with, and
whether the TV still takes the key.

The key file (`/var/lib/tvgw/lgtv-keys.sqlite`) is a SQLite database the LAN-API library made: its table
`unnamed` maps the TV's address to the client key the TV handed out at pairing, as a pickle (sqlitedict's
format). Unpickling runs whatever the pickle names, so tvgw does not read the key through the library
(design decision 106). This module keeps one table of its own beside the library's, `tvgw_pairing`, one
row per TV address:

- `client_key`: the key, as plain text. tvgw reads it here and hands it to the library.
- `manifest`: `signed` (the library's "LG Remote App" manifest, which LG's newer firmware refuses with
  `403 ... blacklisted certificate`) or `unsigned` (tvgw's read-only manifest). LG checks the manifest on
  every connection, not at pairing, so the reading must send the manifest the key was made with.
- `refused_at` and `refused_why`: set when the TV refused the stored key. While they are set the hourly
  reading connects to nothing: a registration with a refused key puts the pairing prompt on the screen
  every hour, and LG's "403 too many pairing requests" lock clears only by unplugging the TV. Only
  `tvgw tv pair`, the owner's command, clears them (design decision 54, note of 2026-11-04).
- `release`, `os_version`, `generation`: what the TV's `hello` reply said last, for the brief's TV line.
- `unreadable`: settings keys the TV answered 401 to, so a key the firmware will not give is asked once.

The migration runs once, in one transaction, on the first open of a file whose schema row is older than
SCHEMA_VERSION. It gives every address the library holds a key for a row (`manifest = signed`, because
every tvgw before the table paired with the library's signed manifest) and copies the key into
`client_key`. The library's rows are read as data: an unpickler that refuses every class and function,
which a pickled string never needs, so a row that is anything else is no key and nothing in it runs. The
library's rows are kept as they are, so an older tvgw rolled back to still finds the key. A migration
that cannot be made (a locked or read-only file) leaves the file as it was, and the key is read from the
library's rows the same safe way until it can. After it, an open only reads.

A key file that is not there is never created here, except by `save_key()` at a pairing: `has_key()` in
lgwebos.py says a missing file is a gateway that never paired, and opening it would make it one that did.
"""

from __future__ import annotations

import contextlib
import io
import os
import pickle
import sqlite3
import time
from dataclasses import dataclass

MANIFESTS = ("signed", "unsigned")
SCHEMA_VERSION = 2  # 1: the pairing record (W12); 2: the key in `client_key` (design decision 106)
LIBRARY_TABLE = "unnamed"  # bscpylgtv's StorageSqliteDict(table="unnamed")
# sqlitedict's own table, byte for byte, made only when a pairing writes the first key into a new file
_LIBRARY_SCHEMA = f'CREATE TABLE IF NOT EXISTS "{LIBRARY_TABLE}" (key TEXT PRIMARY KEY, value BLOB)'
_SCHEMA = (
    """CREATE TABLE IF NOT EXISTS tvgw_pairing(
    ip TEXT PRIMARY KEY,
    manifest TEXT NOT NULL CHECK (manifest IN ('signed', 'unsigned')),
    paired_at REAL,
    refused_at REAL,
    refused_why TEXT,
    release TEXT,
    os_version TEXT,
    generation TEXT,
    seen_at REAL,
    unreadable TEXT NOT NULL DEFAULT '',
    client_key TEXT
)""",
    "CREATE TABLE IF NOT EXISTS tvgw_meta(key TEXT PRIMARY KEY, value TEXT)",
)
_COLUMNS = "ip, manifest, paired_at, refused_at, refused_why, release, os_version, generation, unreadable"


@dataclass(frozen=True)
class Pairing:
    ip: str
    manifest: str = "signed"
    paired_at: float | None = None
    refused_at: float | None = None
    refused_why: str = ""
    release: str = ""  # deviceOSReleaseVersion from the last hello, e.g. 5.6.2
    os_version: str = ""  # deviceOSVersion, kept for the record (4.1.0 on webOS 25 and 26: not the release)
    generation: str = ""  # the webOS marketing name the release maps to: 5, 6, 22 .. 26
    unreadable: tuple[str, ...] = ()

    @property
    def refused(self) -> bool:
        return self.refused_at is not None


class NotAKeyStore(Exception):
    """The file is there but it is not the library's SQLite database."""


def _connect(path: str) -> sqlite3.Connection | None:
    """The key file opened read-write, None when it is not there. A file that is not SQLite raises
    NotAKeyStore after the connection is closed."""
    if not os.path.isfile(path):
        return None
    conn = sqlite3.connect(path, timeout=5.0)
    try:
        conn.execute("SELECT name FROM sqlite_master LIMIT 1").fetchall()
    except sqlite3.DatabaseError as e:
        conn.close()
        raise NotAKeyStore(str(e)) from None
    return conn


def _tables(conn: sqlite3.Connection) -> set[str]:
    return {r[0] for r in conn.execute("SELECT name FROM sqlite_master WHERE type='table'")}


class _Data(pickle.Unpickler):
    """An unpickler that builds plain values only: every class or function a pickle names is refused, so
    a row of the library's table is read as data and nothing in it runs (CVE-2024-35515 is sqlitedict's
    plain `pickle.loads`)."""

    def find_class(self, module, name):
        raise pickle.UnpicklingError(f"refused {module}.{name}")


def _library_key(value) -> str | None:
    """The key one row of the library's table holds: a pickled string, or None for anything else (a row
    that names a class or function, is cut short, is not bytes at all, or holds another type)."""
    try:
        key = _Data(io.BytesIO(value)).load()
    except Exception:  # whatever the row holds, one that is not a plain string is no key
        return None
    return key if isinstance(key, str) else None


def _library_keys(conn: sqlite3.Connection) -> dict[str, str]:
    """{address: key} for every row of the library's table that holds a plain key, read as data."""
    if LIBRARY_TABLE not in _tables(conn):
        return {}
    rows = conn.execute(f'SELECT key, value FROM "{LIBRARY_TABLE}"').fetchall()
    return {ip: key for ip, value in rows if ip and (key := _library_key(value))}


def _schema(conn: sqlite3.Connection) -> int:
    """The schema of tvgw's half of the file: 0 before its tables, or when the row is not a number."""
    if "tvgw_meta" not in _tables(conn):
        return 0
    row = conn.execute("SELECT value FROM tvgw_meta WHERE key = 'schema'").fetchone()
    try:
        return int(row[0])
    except (TypeError, ValueError):  # no schema row, or one that is not a number
        return 0


def _migrate(conn: sqlite3.Connection) -> list[str]:
    """Bring an open key file to SCHEMA_VERSION, in one transaction: the tables, the `client_key` column,
    a `signed` row for each address the library holds a key for, the key copied into it, the schema row.
    Returns the addresses whose key was copied. A file at SCHEMA_VERSION or later is only read, so a read
    commits nothing. Raises when a step fails, with the transaction rolled back: the file is as it was."""
    if _schema(conn) >= SCHEMA_VERSION:
        return []
    # every statement of the upgrade, the DDL included, is in this transaction. A process that waited for
    # it while another migrated upgrades again, to the same rows: one write more, never a wrong one
    conn.execute("BEGIN IMMEDIATE")
    try:
        copied = _upgrade(conn)
        conn.commit()
    except BaseException:
        conn.rollback()
        raise
    return copied


def _upgrade(conn: sqlite3.Connection) -> list[str]:
    for ddl in _SCHEMA:
        conn.execute(ddl)
    if "client_key" not in {r[1] for r in conn.execute("PRAGMA table_info(tvgw_pairing)")}:
        conn.execute("ALTER TABLE tvgw_pairing ADD COLUMN client_key TEXT")  # a schema 1 table
    # the library's rows are the truth here: an older tvgw kept the key there, and wrote schema 1 back
    keys = _library_keys(conn)
    now = time.time()
    conn.executemany(
        "INSERT OR IGNORE INTO tvgw_pairing(ip, manifest, paired_at) VALUES (?, 'signed', ?)",
        [(ip, now) for ip in keys],
    )
    conn.executemany(
        "UPDATE tvgw_pairing SET client_key = ? WHERE ip = ?", [(k, ip) for ip, k in keys.items()]
    )
    conn.execute("INSERT OR REPLACE INTO tvgw_meta(key, value) VALUES ('schema', ?)", (str(SCHEMA_VERSION),))
    return list(keys)


def _open(path: str) -> sqlite3.Connection | None:
    """The key file, open, after the migration where it can be made. One that cannot be made leaves the
    file as it was, and what the file holds is read and written as before it. None when it is missing;
    NotAKeyStore when it is not SQLite."""
    conn = _connect(path)
    if conn is not None:
        with contextlib.suppress(Exception):  # a locked or read-only file: the next open tries again
            _migrate(conn)
    return conn


def migrate(path: str) -> list[str]:
    """Bring the key file to SCHEMA_VERSION (see `_migrate`). Returns the addresses whose key was copied
    this time ([] when the file is current or missing). Raises when the migration fails, with the file as
    it was. Idempotent."""
    conn = _connect(path)
    if conn is None:
        return []
    try:
        return _migrate(conn)
    finally:
        conn.close()


def keys(path: str) -> dict[str, str]:
    """{TV address: client key}: tvgw's column, once the migration has copied the keys into it; until it
    can, the library's rows read as data, so a reading goes on with the key it would have had. A row that
    is not a plain key is no key. {} for a missing file or one that is not SQLite."""
    try:
        conn = _open(path)
    except NotAKeyStore:
        return {}
    if conn is None:
        return {}
    try:
        if _schema(conn) < SCHEMA_VERSION:
            return _library_keys(conn)
        rows = conn.execute("SELECT ip, client_key FROM tvgw_pairing").fetchall()
        return {ip: key for ip, key in rows if key}
    finally:
        conn.close()


def save_key(path: str, ip: str, key: str) -> None:
    """Store the key the TV handed out at a pairing: in `client_key`, and in the library's row in the
    library's own format, so that an older tvgw rolled back to reads the key this pairing made, not an
    older one the TV no longer takes. The one write that may make the file: under `pair()`'s umask 077."""
    conn = sqlite3.connect(path, timeout=5.0)
    try:
        _migrate(conn)
        with conn:
            conn.execute(_LIBRARY_SCHEMA)
            conn.execute("INSERT OR IGNORE INTO tvgw_pairing(ip, manifest) VALUES (?, 'signed')", (ip,))
            conn.execute("UPDATE tvgw_pairing SET client_key = ? WHERE ip = ?", (key, ip))
            conn.execute(
                f'INSERT OR REPLACE INTO "{LIBRARY_TABLE}"(key, value) VALUES (?, ?)',
                (ip, pickle.dumps(key, protocol=pickle.HIGHEST_PROTOCOL)),
            )
    finally:
        conn.close()


def record(path: str, ip: str) -> Pairing | None:
    """The pairing record for `ip`, None when the file is missing, is not the library's database, or has
    no row for the address. Migrates on the way, so a key file from before this table reads as `signed`."""
    try:
        conn = _open(path)
    except NotAKeyStore:
        return None
    if conn is None:
        return None
    try:
        if "tvgw_pairing" not in _tables(conn):  # a file from before the table, not migrated yet
            return None
        row = conn.execute(f"SELECT {_COLUMNS} FROM tvgw_pairing WHERE ip = ?", (ip,)).fetchone()
    finally:
        conn.close()
    if row is None:
        return None
    ip, manifest, paired_at, refused_at, why, release, os_version, generation, unreadable = row
    return Pairing(
        ip,
        manifest if manifest in MANIFESTS else "signed",
        paired_at,
        refused_at,
        why or "",
        release or "",
        os_version or "",
        generation or "",
        tuple(k for k in (unreadable or "").split(",") if k),
    )


def _update(path: str, ip: str, **fields) -> None:
    """Set `fields` on the row for `ip`, making the row (manifest `signed`, as a key of unknown origin
    must be read) when there is none. A missing file stays missing; a file that is not SQLite is left."""
    try:
        conn = _open(path)
    except NotAKeyStore:
        return
    if conn is None:
        return
    try:
        with conn:
            conn.execute("INSERT OR IGNORE INTO tvgw_pairing(ip, manifest) VALUES (?, 'signed')", (ip,))
            sets = ", ".join(f"{k} = ?" for k in fields)
            conn.execute(f"UPDATE tvgw_pairing SET {sets} WHERE ip = ?", (*fields.values(), ip))
    finally:
        conn.close()


def paired(path: str, ip: str, manifest: str, now: float | None = None) -> None:
    """Record a pairing made now with `manifest`, and clear any refusal: the TV took a key again."""
    if manifest not in MANIFESTS:
        raise ValueError(f"manifest {manifest!r}: expected one of {', '.join(MANIFESTS)}")
    _update(
        path,
        ip,
        manifest=manifest,
        paired_at=time.time() if now is None else now,
        refused_at=None,
        refused_why="",
        unreadable="",
    )


def refused(path: str, ip: str, why: str, now: float | None = None) -> None:
    """Record that the TV refused the stored key, with the reason in the TV's words. The first refusal's
    time is kept: later readings do not connect, so there is no later refusal to record."""
    rec = record(path, ip)
    if rec is not None and rec.refused:
        return
    _update(path, ip, refused_at=time.time() if now is None else now, refused_why=why[:200])


def seen(
    path: str, ip: str, release: str, os_version: str, generation: str, now: float | None = None
) -> None:
    """Record what the TV's `hello` reply said: its release version, its OS version and the generation
    the release maps to. Empty strings are kept as they are: a TV that does not answer `hello` has none."""
    _update(
        path,
        ip,
        release=release[:40],
        os_version=os_version[:40],
        generation=generation[:10],
        seen_at=time.time() if now is None else now,
    )


def unreadable(path: str, ip: str, key: str) -> None:
    """Record a settings key the TV refused (401): the next reading does not ask for it again."""
    rec = record(path, ip)
    keys = set(rec.unreadable if rec else ())
    keys.add(key)
    _update(path, ip, unreadable=",".join(sorted(keys)))
