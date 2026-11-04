"""tvgw's half of the LG key store: which manifest a pairing was made with, and whether the TV still
takes the key.

The key file (`/var/lib/tvgw/lgtv-keys.sqlite`) is the LAN-API library's SQLite database: its table
`unnamed` maps the TV's address to the client key the TV handed out at pairing, and only the library
writes it. This module adds one table of its own beside it, `tvgw_pairing`, one row per TV address:

- `manifest`: `signed` (the library's "LG Remote App" manifest, which LG's newer firmware refuses with
  `403 ... blacklisted certificate`) or `unsigned` (tvgw's read-only manifest). LG checks the manifest on
  every connection, not at pairing, so the reading must send the manifest the key was made with.
- `refused_at` and `refused_why`: set when the TV refused the stored key. While they are set the hourly
  reading connects to nothing: a registration with a refused key puts the pairing prompt on the screen
  every hour, and LG's "403 too many pairing requests" lock clears only by unplugging the TV. Only
  `tvgw tv pair`, the owner's command, clears them (design decision 54, note of 2026-11-04).
- `release`, `os_version`, `generation`: what the TV's `hello` reply said last, for the brief's TV line.
- `unreadable`: settings keys the TV answered 401 to, so a key the firmware will not give is asked once.

The first open of a key file that has keys but no `tvgw_pairing` table is the migration: every address
with a key gets a row with `manifest = signed`, because every tvgw before this table paired with the
library's signed manifest. The reference CX's key is read, never rewritten, and its row says `signed`.

A key file that is not there is never created here: `has_key()` in lgwebos.py says a missing file is a
gateway that never paired, and opening it would make it one that did.
"""

from __future__ import annotations

import os
import sqlite3
import time
from dataclasses import dataclass

MANIFESTS = ("signed", "unsigned")
SCHEMA_VERSION = 1
LIBRARY_TABLE = "unnamed"  # bscpylgtv's StorageSqliteDict(table="unnamed")
_SCHEMA = """
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
"""
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


def _library_ips(conn: sqlite3.Connection) -> list[str]:
    """The addresses the library holds a key for, read from its table (the keys themselves are pickled
    and are not read here)."""
    tables = {r[0] for r in conn.execute("SELECT name FROM sqlite_master WHERE type='table'")}
    if LIBRARY_TABLE not in tables:
        return []
    rows = conn.execute(f'SELECT key, value FROM "{LIBRARY_TABLE}"').fetchall()
    return [str(k) for k, v in rows if isinstance(k, str) and k and v is not None and len(v) > 0]


def migrate(path: str) -> list[str]:
    """Make sure the key file holds tvgw's table, and give every address the library already holds a key
    for a `signed` row when the table is new. Returns the addresses migrated this time ([] when the table
    was there, or the file is missing). Idempotent."""
    conn = _connect(path)
    if conn is None:
        return []
    try:
        with conn:
            tables = {r[0] for r in conn.execute("SELECT name FROM sqlite_master WHERE type='table'")}
            conn.executescript(_SCHEMA)
            conn.execute(
                "INSERT OR REPLACE INTO tvgw_meta(key, value) VALUES ('schema', ?)", (str(SCHEMA_VERSION),)
            )
            if "tvgw_pairing" in tables:
                return []
            migrated = _library_ips(conn)
            now = time.time()
            conn.executemany(
                "INSERT OR IGNORE INTO tvgw_pairing(ip, manifest, paired_at) VALUES (?, 'signed', ?)",
                [(ip, now) for ip in migrated],
            )
            return migrated
    finally:
        conn.close()


def record(path: str, ip: str) -> Pairing | None:
    """The pairing record for `ip`, None when the file is missing, is not the library's database, or has
    no row for the address. Migrates on the way, so a key file from before this table reads as `signed`."""
    try:
        migrate(path)
        conn = _connect(path)
    except NotAKeyStore:
        return None
    if conn is None:
        return None
    try:
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
        migrate(path)
        conn = _connect(path)
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
