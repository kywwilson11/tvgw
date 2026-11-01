"""Minimization at ingest: the store keeps the least of a row that the detectors need.

Three reductions, each applied by `ingest` before a row is inserted, and once to the rows already
stored (`rewrite_stored`), so a switch thrown today also cleans the rows of the days before it:

- **Kernel log lines** (`oddport.raw`, `gate.raw`): the Pi's host name, which journalctl prints as the
  line's second word, and the frame's link-layer header after `MAC=`, which holds the TV's and the
  Pi's hardware addresses. No query reads `raw`; the fields the brief needs are parsed out first.
  Always on: nothing is lost.
- **Query values in `http.uri`** (`URI_VALUES=lengths`): each value becomes its length, `?id=<12>`.
  A query string is the part of a request a court is most likely to call the contents of a
  communication; no detector reads the values. `biz_code` stays, because it is the vendor's service
  code the URL filter and the brief's GFTS table are keyed on, not anything the household typed.
- **Title-bearing names** (`NAME_HMAC=on`): a name under one of the profile's zones whose labels
  carry what is on screen (a FAST channel's show slug) becomes `t-<epoch>-<tag>.<zone>`, where the
  tag is a keyed HMAC of everything left of the zone. The detectors need name equality, which the
  tag keeps within a key epoch; the owner's reading loses the title, which is the point. The zone is
  kept, so must-allow, categories and the DNS gate still match. The keys live in
  `<STATE_DIR>/name-keys/`, which `tvgw backup` never copies and `make backup` never pulls.

Everything here is pure except the key files, which `NameHasher` reads and writes through its own
directory, so the unit tests run it on a temporary tree.
"""

from __future__ import annotations

import contextlib
import fnmatch
import hashlib
import hmac
import json
import os
import re
import sqlite3
import time
from collections.abc import Callable, Iterable

from tvgw import db
from tvgw.names import normalize

# ---- kernel log lines ------------------------------------------------------------------------------
# journalctl -o short-unix: "<epoch> <host> kernel: <message>". The host is the Pi's own name.
_KERNEL_HOST = re.compile(r"^(\d+(?:\.\d+)?) \S+ (kernel: )")
# netfilter's LOG target prints the frame's link-layer header as one colon-separated hex run
_MAC_FIELD = re.compile(r"\bMAC=\S*")


def scrub_kernel_line(line: str) -> str:
    """A kernel log line without the Pi's host name and with `MAC=` emptied. Everything the store
    parses out of the line (time, protocol, destination, port) is untouched."""
    return _MAC_FIELD.sub("MAC=", _KERNEL_HOST.sub(r"\1 \2", line, count=1))


# ---- http.uri query values -------------------------------------------------------------------------
# parameters whose value is kept: the vendor file service's own category, read by the GFTS table and
# matched by the URL filter's regex; it names a service of the TV maker, never something of the house
KEEP_PARAMS = frozenset({"biz_code"})
_LENGTH = re.compile(r"<\d+>")
_SEP = re.compile(r"([&;])")  # both separators a server may read, kept as they were


def uri_lengths(uri: str, keep: frozenset[str] = KEEP_PARAMS) -> str:
    """`/a?id=abc&t=12345&biz_code=MAS` -> `/a?id=<3>&t=<5>&biz_code=MAS`. A bare word with no `=` is
    a value too. The path and the parameter names stay: a path tells which service was asked, the
    values are what was asked of it. Idempotent: a value already shaped `<n>` is kept as it is."""
    path, mark, query = uri.partition("?")
    if not mark or not query:
        return uri
    query, hashmark, fragment = query.partition("#")
    out = []
    for part in _SEP.split(query):
        if part in ("&", ";"):
            out.append(part)
            continue
        key, eq, value = part.partition("=")
        if not eq:
            out.append(key if not key or _LENGTH.fullmatch(key) else f"<{len(key)}>")
        elif key.lower() in keep or _LENGTH.fullmatch(value):
            out.append(part)
        else:
            out.append(f"{key}=<{len(value)}>")
    tail = f"#<{len(fragment)}>" if hashmark and not _LENGTH.fullmatch(fragment) else hashmark + fragment
    return f"{path}?{''.join(out)}{tail}"


def minimize_uri(uri: str, mode: str) -> str:
    """The URI as the store keeps it under URI_VALUES=`mode`."""
    return uri_lengths(uri) if mode == "lengths" else uri


# ---- title-bearing names ---------------------------------------------------------------------------
# the profile category whose plain zone patterns are title-bearing: added by the profile, read if there
TITLE_CATEGORY = "FAST"
EPOCH = 90 * 86400  # a key's life: the detectors' longest window (56 days) fits inside one
OVERLAP = 35 * 86400  # how long the previous epoch's key outlives its epoch, for late evidence
KEY_BYTES = 32
TAG_HEX = 10  # 40 bits: no collision among the few thousand titles a household meets in an epoch
_TAG = re.compile(rf"t-\d+-[0-9a-f]{{{TAG_HEX}}}")
_WILD = re.compile(r"[*?\[]")
# a tag as the leftmost label of a name, found inside a name or a rule's text
_TAGGED = re.compile(rf"(?<![\w.-]){_TAG.pattern}\.[a-z0-9]", re.IGNORECASE)


def is_tagged(text: str | None) -> bool:
    """Whether a name or a rule's text names a tag: no real lookup is ever for a tag, so a rule
    written for one would never match, and a tag stands for one title, not for a service."""
    return bool(text) and bool(_TAGGED.search(text))


def title_zones(profile) -> tuple[str, ...]:
    """The zones of the profile's TITLE_CATEGORY, longest first, so a nested zone wins. Only plain
    patterns count: a wildcard pattern names no zone to keep."""
    zones = {
        pat.lower().rstrip(".")
        for pat, cat in getattr(profile, "rules", ())
        if cat == TITLE_CATEGORY and not _WILD.search(pat)
    }
    return tuple(sorted(zones, key=lambda z: (-len(z), z)))


def protected_names(profile) -> Callable[[str], bool]:
    """Names that are never hashed whatever zone they sit in: the must-allow hosts and the clock
    hosts, which the red lines look up by their clear name."""
    must = set(getattr(profile, "must_allow", {}) or {})
    clocks = tuple(getattr(profile, "clock_hosts", ()) or ())

    def check(name: str) -> bool:
        return name in must or any(fnmatch.fnmatchcase(name, pat) for pat in clocks)

    return check


class NameHasher:
    """Title-bearing names to `t-<epoch>-<tag>.<zone>`. A row is hashed with the key of the epoch
    its own time falls in, so equality holds for every row of an epoch however late it arrives; a
    row whose epoch's key is gone is hashed with the current one. `retire()` deletes the keys past
    their life: once a key is gone, its tags can no longer be linked to any later sighting."""

    def __init__(
        self,
        zones: Iterable[str],
        key_dir: str,
        protected: Callable[[str], bool] = lambda name: False,
        now: Callable[[], float] | None = None,  # time.time, looked up at each call (the tests pin it)
    ) -> None:
        self.zones = tuple(zones)
        self.key_dir = key_dir
        self.protected = protected
        self.now = now or (lambda: time.time())
        self._keys: dict[int, bytes] = {}

    @property
    def active(self) -> bool:
        return bool(self.zones)

    def name(self, qname: str | None, t: float) -> str | None:
        """`qname` as the store keeps it: tagged when it sits under a title zone, else unchanged."""
        if not qname or not self.zones:
            return qname
        n = normalize(qname)
        for zone in self.zones:
            if n.endswith("." + zone):
                left = n[: -len(zone) - 1]
                if _TAG.fullmatch(left) or self.protected(n):
                    return qname
                epoch, key = self._key(t)
                tag = hmac.new(key, left.encode("utf-8"), hashlib.sha256).hexdigest()[:TAG_HEX]
                return f"t-{epoch}-{tag}.{zone}"
        return qname

    def answers(self, text: str | None, t: float) -> str | None:
        """The stored `A:1.2.3.4,CNAME:x.y` form with each CNAME target passed through `name`."""
        if not text or not self.zones:
            return text
        parts = []
        for part in text.split(","):
            kind, colon, value = part.partition(":")
            parts.append(f"{kind}:{self.name(value, t)}" if colon and kind == "CNAME" else part)
        return ",".join(parts)

    # ---- keys --------------------------------------------------------------------------------------
    def _path(self, epoch: int) -> str:
        return os.path.join(self.key_dir, f"{epoch}.key")

    def _key(self, t: float) -> tuple[int, bytes]:
        current = int(self.now() // EPOCH)
        epoch = int(t // EPOCH)
        if epoch > current or epoch < current - 1:
            epoch = current  # a clock from the future, or a row older than any key kept
        elif epoch == current - 1 and self.now() - current * EPOCH > OVERLAP:
            epoch = current  # the previous key has been retired
        if epoch not in self._keys:
            # only the current epoch's key, or the previous one inside its overlap, is ever made: a key
            # retired past that is never made again, so its tags stay unlinkable
            key = self._read(epoch) or self._create(epoch)
            self._keys[epoch] = key
        return epoch, self._keys[epoch]

    def _read(self, epoch: int) -> bytes | None:
        try:
            with open(self._path(epoch), "rb") as fh:
                key = fh.read()
        except FileNotFoundError:
            return None
        if len(key) != KEY_BYTES:
            raise ValueError(f"{self._path(epoch)}: expected {KEY_BYTES} bytes, found {len(key)}")
        return key

    def _create(self, epoch: int) -> bytes:
        """32 random bytes, root-only from the first byte, flushed before use: a key lost in a power
        cut after rows were tagged with it would split one name into two."""
        os.makedirs(self.key_dir, mode=0o700, exist_ok=True)
        with contextlib.suppress(OSError):
            os.chmod(self.key_dir, 0o700)
        key = os.urandom(KEY_BYTES)
        try:
            fd = os.open(self._path(epoch), os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        except FileExistsError:
            existing = self._read(epoch)
            assert existing is not None
            return existing
        try:
            os.write(fd, key)
            os.fsync(fd)
        finally:
            os.close(fd)
        return key

    def retire(self) -> list[str]:
        """Delete every key past its life (older than the previous epoch, or the previous one once
        OVERLAP into the current epoch). Returns the files removed."""
        current = int(self.now() // EPOCH)
        keep = {current}
        if self.now() - current * EPOCH <= OVERLAP:
            keep.add(current - 1)
        removed = []
        try:
            names = os.listdir(self.key_dir)
        except FileNotFoundError:
            return removed
        for f in names:
            stem, _, ext = f.partition(".")
            if ext == "key" and stem.isdigit() and int(stem) not in keep:
                os.unlink(os.path.join(self.key_dir, f))
                self._keys.pop(int(stem), None)
                removed.append(f)
        return removed


def key_dir(state_dir: str) -> str:
    """Where the name keys live: in the state directory, which the ingest unit may write, and outside
    the copies `tvgw backup` makes, which hold the store file only."""
    return os.path.join(state_dir, "name-keys")


def hasher(s, profile, now: Callable[[], float] | None = None) -> NameHasher:
    """The hasher the settings call for: one with no zones (a no-op) unless NAME_HMAC=on and the
    profile has a TITLE_CATEGORY."""
    zones = title_zones(profile) if getattr(s, "name_hmac", "off") == "on" else ()
    return NameHasher(zones, key_dir(s.state_dir), protected_names(profile), now)


# ---- the rows already stored ------------------------------------------------------------------------
def rewrite_stored(conn: sqlite3.Connection, s, names: NameHasher) -> dict[str, int]:
    """Apply today's reductions once to the rows stored before them. Each is keyed in `meta` by what
    it applied (`minimized_raw`, `minimized_uri`, `minimized_names`), so it runs again only when the
    setting or the zone list changes. Returns the rows rewritten per kind. The caller commits."""
    done: dict[str, int] = {}
    if db.get_meta(conn, "minimized_raw") != "1":
        n = 0
        for table in ("oddport", "gate"):
            rows = conn.execute(f"SELECT id, raw FROM {table} WHERE raw IS NOT NULL").fetchall()
            for rid, raw in rows:
                clean = scrub_kernel_line(raw)
                if clean != raw:
                    conn.execute(f"UPDATE {table} SET raw=? WHERE id=?", (clean, rid))
                    n += 1
        db.set_meta(conn, "minimized_raw", "1")
        done["raw"] = n
    mode = getattr(s, "uri_values", "keep")
    if mode == "lengths" and db.get_meta(conn, "minimized_uri") != mode:
        n = 0
        for rid, uri in conn.execute("SELECT id, uri FROM http WHERE uri LIKE '%?%'").fetchall():
            short = uri_lengths(uri)
            if short != uri:
                conn.execute("UPDATE http SET uri=? WHERE id=?", (short, rid))
                n += 1
        db.set_meta(conn, "minimized_uri", mode)
        done["uri"] = n
    if names.active:
        mark = json.dumps(list(names.zones))
        if db.get_meta(conn, "minimized_names") != mark:
            done["names"] = _rewrite_names(conn, names)
            db.set_meta(conn, "minimized_names", mark)
    return done


def _rewrite_names(conn: sqlite3.Connection, names: NameHasher) -> int:
    """Tag the clear title names in every column that holds a name. `hosts` rows under a title zone
    are deleted rather than renamed: the counted rows are below its watermark, so a renamed row would
    keep counts the tagged rows never earned; the tags get their own rows from the next sighting.

    The SQL only narrows: a zone anywhere in the text selects the row (a CNAME target sits before the
    A records that follow it, a name may end in a dot), and `names.name` and `names.answers`, which
    parse each name, decide what changes."""
    n = 0
    likes = " OR ".join(["{col} LIKE ?"] * len(names.zones))
    args = [f"%{z}%" for z in names.zones]
    for table, col, extra in (("dns", "qname", "answers"), ("tls", "sni", None), ("http", "host", None)):
        q = f"SELECT id, t, {col}{', ' + extra if extra else ''} FROM {table} WHERE " + likes.format(col=col)
        if extra:
            q += " OR " + likes.format(col=extra)
        for row in conn.execute(q, args + (args if extra else [])).fetchall():
            rid, t, name = row[0], row[1], row[2]
            new = names.name(name, t)
            sets, vals = [], []
            if new != name:
                sets.append(f"{col}=?")
                vals.append(new)
            if extra:
                tagged = names.answers(row[3], t)
                if tagged != row[3]:
                    sets.append(f"{extra}=?")
                    vals.append(tagged)
            if sets:
                conn.execute(f"UPDATE {table} SET {', '.join(sets)} WHERE id=?", (*vals, rid))
                n += 1
    for (name,) in conn.execute("SELECT name FROM hosts WHERE " + likes.format(col="name"), args).fetchall():
        if names.name(name, names.now()) != name:  # a clear title name, not a tag or a protected host
            conn.execute("DELETE FROM hosts WHERE name=?", (name,))
            n += 1
    for name, t in conn.execute(
        "SELECT name, t FROM judgments WHERE " + likes.format(col="name"), args
    ).fetchall():
        new = names.name(name, t)
        if new != name:
            conn.execute("DELETE FROM judgments WHERE name=?", (new,))
            conn.execute("UPDATE judgments SET name=? WHERE name=?", (new, name))
            n += 1
    return n
