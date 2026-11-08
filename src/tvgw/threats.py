"""(threats) Does the TV talk to known-bad servers? Threat and new-domain lists, counted (design decision 80).

Count-only. Nothing here blocks, refuses or slows anything, and no name the TV looked up ever leaves the
gateway: the lists are downloaded whole, and every match is made here, against the local copies. No
lookup service is asked about any name.

The lists. With THREAT_LISTS=count, `update()` (`sudo tvgw threats --update`, run once a day by
tvgw-threat-update.timer) downloads each list THREAT_LIST_URLS names, by default HaGeZi's Threat
Intelligence Feeds in their mini form and the two youngest of HaGeZi's bands of newly registered domains
(registered in the last 7 days, and 8 to 14 days ago). Each download is HTTPS only, redirects included,
capped at MAX_BYTES and FETCH_SECONDS, read line by line from curl's output and written, one name per
line, to a staged file beside its copy under `<STATE_DIR>/threat/`, which then replaces the copy in one
rename. A list that fails to download, parses to fewer than MIN_ENTRIES names, to less than
DECLARED_SHARE of the count its own header declares, or to less than SHRINK of the copy it would
replace, keeps the old copy and says so. With THREAT_LISTS=off the update downloads nothing and removes
the copies it made; nothing else reads them then.

The formats (`entries()`): adblock (`||name^`, with no modifier but `$important`), plain domains,
wildcards (`*.name`), hosts files (`0.0.0.0 name`) and dnsmasq (`local=/name/`); comments, exception
rules, cosmetic rules, regular expressions, addresses and a whole top-level domain are skipped. Every
entry covers the name and every name under it, as `||name^` does.

Matching (`match()`). The names to look for are few, the lists long: the TV's distinct names of one day,
a few thousand at most, each with its parent domains, go into one dictionary, and each list streams
past it a line at a time. The gateway's memory therefore grows with the TV's names, never with a list's
size, whatever the list holds (the hand-back of decision 80 gives the measurement). The hourly ingest's
`threats` step (`step()`) matches each local day once, SETTLE after it ends, as tvgw-analyze writes its
daily file then, and up to BACKFILL_DAYS back. A day's rows go into `threat_hits` with the list, the
entry that matched (the most specific), the lookups, how many the filter answered, the first and last
time, the copy's date and whether the name is a must-allow host: such a hit is recorded and marked,
never held against the TV. The days matched are kept in meta under META_KEY, so that a day that was
matched and had no hit is told apart from a day that was never matched.

Where it shows. `report()` gives the brief its `threats` key: the engineering brief's "Known-bad names"
section, one red line per threat-list name the filter answered (`queries.red_lines()`), and the plain
brief's New line, which marks a new service on a list of newly registered domains. `lookup()` gives
`tvgw check` its lines, and `listing()` gives `tvgw threats` its rows.

Failure. A failed download keeps the old copy; a missing or damaged copy matches nothing and says so;
the brief computes its part in a try, so a failure is a report warning and the rest of the brief stands.
"""

from __future__ import annotations

import contextlib
import fcntl
import json
import os
import re
import sqlite3
import subprocess
import tempfile
import time
from collections.abc import Callable, Iterable, Iterator
from dataclasses import dataclass
from datetime import date, datetime, timedelta
from urllib.parse import urlsplit

from tvgw import db
from tvgw.names import LOCAL_SUFFIXES, is_public_name, normalize
from tvgw.profile import Profile, covers

# the two kinds of list: known malware, botnet and phishing servers, and newly registered domains
TIF, NRD = "tif", "nrd"
KINDS = (TIF, NRD)
SUBDIR = "threat"  # under STATE_DIR: the copies, MANIFEST and the update's lock
MANIFEST = "lists.json"  # per copy: its kind, URL, names, the time it was fetched, its last error
LOCK = ".update.lock"
MAX_URLS = 8
# bytes a download may have: the full TIF list was 30.8 MB and the youngest NRD band 52.4 MB on 2026-11-08
MAX_BYTES = 100 * 1024**2
FETCH_SECONDS = 600  # curl's limit for one download: 100 MB at 1.4 Mbit/s
MIN_ENTRIES = 1000  # the floor: fewer names is an error page or a cut-off download, not a list
DECLARED_SHARE = 0.9  # a list that declares its count ("! Number of entries:") and parses to less is cut off
SHRINK = 0.5  # a list that parses to less than half the copy it would replace keeps that copy
SETTLE = 10800  # seconds after a day ends before it is matched: tvgw-analyze writes the daily file then
BACKFILL_DAYS = 7  # settled days the step matches when it starts, or after it missed some
STALE_DAYS = 8  # a copy older than this: the daily update has missed a week (verify's DOH_MAX_AGE)
META_KEY = "threat_matched"  # day -> when it was matched and against which copies
# the red line's start: `queries.red_lines()` writes it, plain.RED_LINE_PLAIN gives its plain words, and the
# analyst's pack leaves it out, so that no model proposes a block from a list before the count says to
RED_LINE = "known-bad name answered:"

_URL = re.compile(r"https://[A-Za-z0-9.-]+(?::\d{1,5})?/[A-Za-z0-9._~%/@+-]*")
_FILE = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,79}")
_NRD_BAND = re.compile(r"nrd(\d{1,3})(?:-\d{1,3})?\.txt")
_DECLARED = re.compile(r"^[!#]\s*Number of entries:\s*([0-9][0-9,]*)", re.IGNORECASE)
_MODIFIED = re.compile(r"^[!#]\s*Last modified:\s*(.{1,40}?)\s*$", re.IGNORECASE)
_HOSTS_ADDR = re.compile(r"(?:0\.0\.0\.0|127\.0\.0\.1|::1?|0)$")
_DNSMASQ = re.compile(r"(?:local|address|server)=/(.+)/")
_COSMETIC = ("##", "#@#", "#?#", "#$#")
# a name of at least two labels, each as names._LABEL allows it, the last letters or punycode
_HOST = re.compile(r"(?:[a-z0-9_](?:[a-z0-9_-]{0,61}[a-z0-9_])?\.)+(?:[a-z]{1,63}|xn--[a-z0-9-]{1,59})")


@dataclass(frozen=True)
class Source:
    """One list THREAT_LIST_URLS names: its kind, its URL and the file its copy is kept in."""

    kind: str
    url: str
    file: str


def parse_urls(value: str) -> tuple[Source, ...]:
    """THREAT_LIST_URLS: `kind=https://...` entries, separated by commas or spaces, each kind `tif` or
    `nrd`, each URL HTTPS and ending in a file name no other entry has. ValueError names the first fault,
    as every settings check does."""
    items = [x for x in re.split(r"[\s,]+", value.strip()) if x]
    if not items:
        raise ValueError("THREAT_LIST_URLS in tvgw.conf: names no list")
    if len(items) > MAX_URLS:
        raise ValueError(f"THREAT_LIST_URLS in tvgw.conf: {len(items)} lists, more than {MAX_URLS}")
    out: list[Source] = []
    for item in items:
        kind, sep, url = item.partition("=")
        if not sep or kind not in KINDS:
            raise ValueError(
                f"THREAT_LIST_URLS={item!r} in tvgw.conf: expected tif=URL or nrd=URL, such as"
                " tif=https://lists.example/tif.txt"
            )
        if not _URL.fullmatch(url):
            raise ValueError(f"THREAT_LIST_URLS={item!r} in tvgw.conf: expected an https:// URL")
        name = url.rpartition("/")[2]
        if not _FILE.fullmatch(name) or name == MANIFEST:
            raise ValueError(f"THREAT_LIST_URLS={item!r} in tvgw.conf: the URL must end in a file name")
        if any(s.file == name for s in out):
            raise ValueError(f"THREAT_LIST_URLS in tvgw.conf: two lists end in the same file name, {name}")
        out.append(Source(kind, url, name))
    return tuple(out)


def label(kind: str, url: str, short: bool = False) -> str:
    """A list as the brief names it: HaGeZi's by their own names, any other by its file and host."""
    if "hagezi" in url.lower():
        if short:
            return "HaGeZi TIF" if kind == TIF else "HaGeZi NRD"
        return "HaGeZi Threat Intelligence Feeds" if kind == TIF else "HaGeZi newly registered domains"
    parts = urlsplit(url)
    return f"{parts.path.rpartition('/')[2]} from {parts.hostname}"


def nrd_days(sources: Iterable[Source]) -> int | None:
    """The span the newly-registered lists cover, in days, from HaGeZi's band names (`nrd7.txt`,
    `nrd14-8.txt`: the oldest band's first number), or None when no list is named that way."""
    spans = [int(m.group(1)) for s in sources if s.kind == NRD and (m := _NRD_BAND.fullmatch(s.file))]
    return max(spans) if spans else None


# ---- parsing --------------------------------------------------------------------------------------------
def _name(text: str) -> str | None:
    """An entry as a name, or None: `names.is_public_name()`'s rule in one expression, ASCII only, since a
    list holds millions of entries and the update reads every one."""
    n = normalize(text).removeprefix("*.")
    return n if len(n) <= 253 and _HOST.fullmatch(n) and not n.endswith(LOCAL_SUFFIXES) else None


def entries(line: str) -> list[str]:
    """The names one line of a list blocks, each covering the name and every name under it; [] for a
    comment, an exception, a cosmetic or regular-expression rule, an address, a single label (a whole
    top-level domain, which belongs to another kind of list) or anything else that names no domain."""
    s = line.strip()
    if not s or s[0] in "!#[" or s.startswith("@@"):
        return []
    if "#" in s:  # a cosmetic rule, or a comment after the entry
        if any(c in s for c in _COSMETIC):
            return []
        s = re.split(r"\s+#", s, maxsplit=1)[0].strip()
    if s.startswith("||"):  # adblock: ||name^ with no modifier but $important
        body, _, mods = s[2:].partition("$")
        if mods and mods.strip() != "important":
            return []
        body = body.removesuffix("^").removesuffix("|")
        return [n] if (n := _name(body)) else []
    if s.startswith(("|", "/")):  # an anchored URL or a regular expression: no domain list entry
        return []
    m = _DNSMASQ.match(s)
    if m:
        return [n for part in m.group(1).split("/") if (n := _name(part))]
    words = s.split()
    if len(words) > 1 and _HOSTS_ADDR.match(words[0]):  # a hosts file: the names after the address
        return [n for w in words[1:] if (n := _name(w))]
    return [n] if len(words) == 1 and (n := _name(words[0])) else []


@dataclass
class Parsed:
    """What one download parsed to: the names written, the lines skipped, and what its header said."""

    entries: int = 0
    skipped: int = 0
    declared: int | None = None
    modified: str | None = None


def parse(lines: Iterable[bytes | str], out) -> Parsed:
    """Write the names `lines` block to `out`, one a line, and count them; the header's declared count
    and date are kept when the list carries them."""
    got = Parsed()
    for raw in lines:
        line = raw.decode("utf-8", "replace") if isinstance(raw, bytes) else raw
        if got.declared is None and (m := _DECLARED.match(line.strip())):
            got.declared = int(m.group(1).replace(",", ""))
        if got.modified is None and (m := _MODIFIED.match(line.strip())):
            got.modified = m.group(1)
        found = entries(line)
        if not found:
            got.skipped += bool(line.strip()) and not line.lstrip().startswith(("!", "#", "["))
            continue
        for n in found:
            out.write(n + "\n")
            got.entries += 1
    return got


# ---- downloading ----------------------------------------------------------------------------------------
class FetchError(Exception):
    """A download that did not complete: curl failed, or it was larger than allowed."""


def curl_lines(
    url: str, max_bytes: int = MAX_BYTES, seconds: int = FETCH_SECONDS, popen: Callable = subprocess.Popen
) -> Iterator[bytes]:
    """The lines of `url`, from curl as tvgw-doh-update runs it: HTTPS only, redirects included, a size
    and a time limit, and an HTTP error is a failure. The size is counted here too, since curl can only
    refuse a size the server declares. FetchError when it did not complete; the lines read before that
    are already yielded, so the caller keeps nothing until the generator has finished."""
    cmd = [
        "curl", "-fsSL", "--proto", "=https", "--proto-redir", "=https",
        "--max-filesize", str(max_bytes), "--max-time", str(seconds), "--", url,
    ]  # fmt: skip
    try:
        proc = popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    except OSError as e:
        raise FetchError(f"curl could not start: {e}") from None
    with proc:
        n = 0
        for line in proc.stdout:
            n += len(line)
            if n > max_bytes:
                proc.kill()
                raise FetchError(f"larger than {max_bytes:,} bytes")
            yield line
        err = proc.stderr.read().decode("utf-8", "replace").strip()
        rc = proc.wait()
    if rc != 0:
        raise FetchError(f"curl exited {rc}" + (f": {err.splitlines()[-1][:160]}" if err else ""))


class Refused(Exception):
    """A download that completed but does not look like the list: the floor or a guard refused it."""


def threat_dir(state_dir: str) -> str:
    return os.path.join(state_dir, SUBDIR)


def load_manifest(d: str) -> dict[str, dict]:
    """The manifest: per copy's file, its kind, URL, names and fetch time, and its last error; {} when
    there is none or it cannot be read (a damaged manifest matches nothing: the next update writes it)."""
    try:
        with open(os.path.join(d, MANIFEST), encoding="utf-8") as fh:
            got = json.load(fh)
    except (OSError, ValueError):
        return {}
    return {k: v for k, v in got.items() if isinstance(v, dict)} if isinstance(got, dict) else {}


def _write_atomic(path: str, text: str) -> None:
    fd, tmp = tempfile.mkstemp(dir=os.path.dirname(path), prefix=f".{os.path.basename(path)}.")
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            fh.write(text)
            fh.flush()
            os.fsync(fh.fileno())
        os.chmod(tmp, 0o640)
        os.replace(tmp, path)
    except BaseException:
        with contextlib.suppress(OSError):
            os.unlink(tmp)
        raise


def _fetch_one(d: str, src: Source, fetch: Callable[[str], Iterable], before: int | None) -> Parsed:
    """Download one list into a staged file beside its copy, check it, and rename it over the copy; the
    copy is untouched unless every check passed."""
    fd, staged = tempfile.mkstemp(dir=d, prefix=f".{src.file}.")
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as out:
            got = parse(fetch(src.url), out)
            out.flush()
            os.fsync(out.fileno())
        if got.entries < MIN_ENTRIES:
            raise Refused(f"only {got.entries:,} names, fewer than the floor of {MIN_ENTRIES:,}")
        if got.declared and got.entries < DECLARED_SHARE * got.declared:
            raise Refused(f"{got.entries:,} names of the {got.declared:,} it declares: cut off")
        if before and got.entries < SHRINK * before:
            raise Refused(f"{got.entries:,} names, under half the {before:,} of the copy it would replace")
        os.chmod(staged, 0o640)
        os.replace(staged, os.path.join(d, src.file))
        return got
    except BaseException:
        with contextlib.suppress(OSError):
            os.unlink(staged)
        raise


@dataclass
class Outcome:
    """What `tvgw threats --update` prints and its exit status."""

    code: int
    lines: list[str]


def update(
    state_dir: str, setting: str, urls: str, fetch: Callable[[str], Iterable] = curl_lines, now=None
) -> Outcome:
    """Download every list `urls` names into `<state_dir>/threat/` (THREAT_LISTS=count), or remove the
    copies (off). Exit status 1 when a list kept its old copy or has none, as tvgw-doh-update's is, so a
    failing day shows in `systemctl --failed`."""
    now = time.time() if now is None else now
    d = threat_dir(state_dir)
    if setting != "count":
        removed = remove_copies(d)
        said = f"; removed {removed} old cop{'y' if removed == 1 else 'ies'}" if removed else ""
        return Outcome(0, [f"tvgw threats: THREAT_LISTS is off, so nothing was downloaded{said}"])
    sources = parse_urls(urls)
    # no chmod: the unit holds no capability, and a chmod by root outside the group would clear the setgid
    # bit the directory takes from the state directory, with its group (adm)
    os.makedirs(d, mode=0o750, exist_ok=True)
    lines, failed = [], 0
    with open(os.path.join(d, LOCK), "w", encoding="utf-8") as lock:
        fcntl.flock(lock, fcntl.LOCK_EX)
        manifest = load_manifest(d)
        for src in sources:
            old = manifest.get(src.file) or {}
            same = old.get("url") == src.url and old.get("kind") == src.kind
            have = same and os.path.exists(os.path.join(d, src.file)) and old.get("fetched")
            try:
                got = _fetch_one(d, src, fetch, old.get("entries") if have else None)
            except (FetchError, Refused, OSError) as e:
                failed += 1
                kept = f"kept the copy of {_day(old['fetched'])}" if have else "no copy yet"
                lines.append(f"tvgw threats: {src.file}: {e}; {kept}")
                entry = {**old} if have else {"kind": src.kind, "url": src.url}
                manifest[src.file] = {**entry, "error": str(e)[:200], "tried": now}
                continue
            manifest[src.file] = {
                "kind": src.kind,
                "url": src.url,
                "entries": got.entries,
                "fetched": now,
                "declared": got.declared,
                "modified": got.modified,
                "tried": now,
            }
            lines.append(f"tvgw threats: {src.file}: {got.entries:,} names ({label(src.kind, src.url)})")
        for gone in sorted(set(manifest) - {s.file for s in sources}):  # a list no longer named
            with contextlib.suppress(FileNotFoundError):
                os.unlink(os.path.join(d, gone))
            del manifest[gone]
            lines.append(f"tvgw threats: {gone}: removed, since THREAT_LIST_URLS no longer names it")
        _write_atomic(os.path.join(d, MANIFEST), json.dumps(manifest, indent=1, sort_keys=True))
    return Outcome(1 if failed else 0, lines)


def remove_copies(d: str) -> int:
    """Remove the copies and the manifest an update made; the number of copies removed."""
    manifest = load_manifest(d)
    n = 0
    for name in [*manifest, MANIFEST]:
        if _FILE.fullmatch(name):
            with contextlib.suppress(FileNotFoundError):
                os.unlink(os.path.join(d, name))
                n += name != MANIFEST
    return n


@dataclass(frozen=True)
class Copy:
    """A list copy on disk that matching reads."""

    kind: str
    file: str
    path: str
    url: str
    entries: int
    fetched: float

    @property
    def day(self) -> str:
        return _day(self.fetched)

    def stored(self) -> list:
        """The copy as META_KEY keeps it: kind, file, the day it was fetched, names, its label."""
        return [self.kind, self.file, self.day, self.entries, label(self.kind, self.url)]


def copies(state_dir: str, sources: Iterable[Source]) -> list[Copy]:
    """The copies matching may read: each list still named whose file and manifest entry both exist."""
    d = threat_dir(state_dir)
    manifest = load_manifest(d)
    out = []
    for src in sources:
        m = manifest.get(src.file) or {}
        path = os.path.join(d, src.file)
        named = m.get("url") == src.url and m.get("kind") == src.kind and m.get("fetched")
        if named and os.path.isfile(path):
            entries_ = int(m.get("entries") or 0)
            out.append(Copy(src.kind, src.file, path, src.url, entries_, float(m["fetched"])))
    return out


def _day(t: float) -> str:
    return datetime.fromtimestamp(t).strftime("%Y-%m-%d")


# ---- matching -------------------------------------------------------------------------------------------
def parents(name: str) -> list[str]:
    """The name and each domain above it with at least two labels: an entry for any of them covers it."""
    labels = name.split(".")
    return [".".join(labels[i:]) for i in range(len(labels) - 1)]


@dataclass(frozen=True)
class Match:
    name: str
    kind: str
    entry: str  # the list's entry that covers the name: the most specific one
    copy: Copy


def match(names: Iterable[str], found_in: Iterable[Copy]) -> dict[tuple[str, str], Match]:
    """(name, kind) -> the match, for every name some copy covers. The names and their parents go into
    one dictionary and each copy streams past it a line at a time, so memory grows with the names and
    never with a list (the module docstring)."""
    wanted: dict[str, list[str]] = {}
    for n in names:
        for p in parents(n):
            wanted.setdefault(p + "\n", []).append(n)
    found: dict[tuple[str, str], Match] = {}
    if not wanted:
        return found
    for c in found_in:
        with open(c.path, encoding="utf-8", errors="replace") as fh:
            for line in fh:
                hit = wanted.get(line)
                if hit is None:
                    continue
                e = line[:-1]
                for n in hit:
                    prev = found.get((n, c.kind))
                    if prev is None or len(e) > len(prev.entry):
                        found[(n, c.kind)] = Match(n, c.kind, e, c)
    return found


def day_names(conn: sqlite3.Connection, a: float, b: float) -> dict[str, list]:
    """The TV's distinct internet names in [a, b), allowed and refused: name -> [lookups, refused,
    first, last]. Local names, addresses and a name the ingest replaced by a keyed tag never match."""
    out: dict[str, list] = {}
    rows = conn.execute(
        "SELECT qname, COUNT(*), COALESCE(SUM(blocked),0), MIN(t), MAX(t) FROM dns WHERE t >= ? AND t < ?"
        " GROUP BY qname",
        (a, b),
    )
    for qname, n, refused, first, last in rows:
        name = normalize(qname or "")
        if not is_public_name(name):
            continue
        have = out.get(name)
        if have is None:
            out[name] = [n, refused, first, last]
        else:
            out[name] = [have[0] + n, have[1] + refused, min(have[2], first), max(have[3], last)]
    return out


def _bounds(day: str) -> tuple[float, float]:
    d = datetime.strptime(day, "%Y-%m-%d")
    return d.timestamp(), (d + timedelta(days=1)).timestamp()


def load_meta(conn: sqlite3.Connection) -> dict[str, dict]:
    raw = db.get_meta(conn, META_KEY)
    try:
        got = json.loads(raw) if raw else {}
    except ValueError:
        return {}
    return {k: v for k, v in got.items() if isinstance(v, dict)} if isinstance(got, dict) else {}


def match_day(
    conn: sqlite3.Connection,
    day: str,
    prof: Profile,
    found_in: list[Copy],
    now: float,
    record: bool = True,
    nrd_span: int | None = None,
) -> int:
    """Match one local day's names against the copies and replace its rows in `threat_hits`; with
    `record`, mark the day matched in META_KEY (an on-demand match of a day not yet settled is not
    marked, so the settled one still runs). The number of rows written."""
    a, b = _bounds(day)
    names = day_names(conn, a, b)
    found = match(names, found_in)
    conn.execute("DELETE FROM threat_hits WHERE day = ?", (day,))
    for (name, kind), m in sorted(found.items()):
        lookups, refused, first, last = names[name]
        must = any(covers(host, name) for host in prof.must_allow)
        conn.execute(
            "INSERT INTO threat_hits(day, name, list, entry, source, copy, lookups, answered, first, last,"
            " must_allow) VALUES (?,?,?,?,?,?,?,?,?,?,?)",
            (day, name, kind, m.entry, label(kind, m.copy.url), m.copy.day, lookups, lookups - refused,
             first, last, int(must)),
        )  # fmt: skip
    if record:
        meta = load_meta(conn)
        meta[day] = {"t": now, "copies": [c.stored() for c in found_in], "nrd_days": nrd_span}
        db.set_meta(conn, META_KEY, json.dumps(meta, sort_keys=True))
    return len(found)


def step(conn: sqlite3.Connection, s, prof: Profile, now: float | None = None) -> list[str]:
    """The hourly ingest's `threats` step: with THREAT_LISTS=count, match each settled day of the last
    BACKFILL_DAYS that was not matched yet; with off, forget which days were matched (the rows stay
    until DB_DAYS prunes them). Warnings for the ingest: a gateway with no copy after an update failed."""
    now = time.time() if now is None else now
    meta = load_meta(conn)
    if s.threat_lists != "count":
        if meta:
            conn.execute("DELETE FROM meta WHERE key = ?", (META_KEY,))
        return []
    sources = parse_urls(s.threat_list_urls)
    found_in = copies(s.state_dir, sources)
    if not found_in:
        failed = [m for m in load_manifest(threat_dir(s.state_dir)).values() if m.get("error")]
        return [f"no list copy to match against: {failed[0]['error'][:120]}"] if failed else []
    span = nrd_days(sources)
    today = date.fromtimestamp(now)
    for back in range(BACKFILL_DAYS, 0, -1):
        day = (today - timedelta(days=back)).isoformat()
        if day in meta or _bounds(day)[1] > now - SETTLE:
            continue
        match_day(conn, day, prof, found_in, now, nrd_span=span)
    keep = {d: v for d, v in load_meta(conn).items() if d >= (today - timedelta(days=s.db_days)).isoformat()}
    db.set_meta(conn, META_KEY, json.dumps(keep, sort_keys=True))
    return []


# ---- reading --------------------------------------------------------------------------------------------
COLUMNS = (
    "day", "name", "list", "entry", "source", "copy", "lookups", "answered", "first", "last", "must_allow",
)  # fmt: skip


def rows(conn: sqlite3.Connection, a: float, b: float) -> list[dict]:
    """`threat_hits` rows whose lookups fall in [a, b), oldest first; [] on a store from before it."""
    try:
        got = conn.execute(
            f"SELECT {', '.join(COLUMNS)} FROM threat_hits WHERE last >= ? AND first < ?"
            " ORDER BY day, list, name",
            (a, b),
        ).fetchall()
    except sqlite3.OperationalError:  # a read-only store a writer has not brought to this schema yet
        return []
    return [dict(zip(COLUMNS, r, strict=True)) for r in got]


def _days(a: float, b: float) -> list[str]:
    out, d = [], date.fromtimestamp(a)
    while datetime(d.year, d.month, d.day).timestamp() < b:
        out.append(d.isoformat())
        d += timedelta(days=1)
    return out


def report(conn: sqlite3.Connection, a: float, b: float, now: float | None = None) -> dict | None:
    """The brief's `threats` key for [a, b), or None on a gateway that never matched and has no row, so
    a brief there is byte for byte what it was. `hits` holds one entry per name and list, summed over
    the window's days; `matched` the window's days that were matched; `copies` the copies the newest of
    them was matched against; `stale` when that copy is older than STALE_DAYS."""
    now = time.time() if now is None else now
    meta = load_meta(conn)
    found = rows(conn, a, b)
    if not meta and not found:
        return None
    hits: dict[tuple[str, str], dict] = {}
    for r in found:
        key = (r["name"], r["list"])
        h = hits.get(key)
        if h is None:
            hits[key] = {k: r[k] for k in COLUMNS if k != "day"} | {"must_allow": bool(r["must_allow"])}
            continue
        h["lookups"] += r["lookups"]
        h["answered"] += r["answered"]
        h["first"], h["last"] = min(h["first"], r["first"]), max(h["last"], r["last"])
        h["must_allow"] = h["must_allow"] or bool(r["must_allow"])
        if r["copy"] and r["copy"] > (h["copy"] or ""):
            h["entry"], h["source"], h["copy"] = r["entry"], r["source"], r["copy"]
    ordered = sorted(
        hits.values(),
        key=lambda h: (h["list"] != TIF, h["must_allow"], -h["answered"], -h["lookups"], h["name"]),
    )
    days = _days(a, b)
    matched = [d for d in days if d in meta]
    newest = meta.get(matched[-1]) if matched else (meta[max(meta)] if meta else None)
    copies_ = [c for c in (newest or {}).get("copies") or [] if isinstance(c, list) and len(c) == 5]
    oldest_copy = min((c[2] for c in copies_), default=None)
    stale = bool(oldest_copy) and date.fromtimestamp(now) - date.fromisoformat(oldest_copy) > timedelta(
        days=STALE_DAYS
    )
    return {
        "hits": ordered,
        "days": days,
        "matched": matched,
        "copies": [dict(zip(("list", "file", "copy", "names", "source"), c, strict=True)) for c in copies_],
        "nrd_days": (newest or {}).get("nrd_days"),
        "stale": stale,
    }


def red_hits(sec: dict | None) -> list[dict]:
    """The hits that make a red line: a threat-list name the filter answered at least once, not a
    must-allow host. A refused one, a must-allow one and a newly registered one stay in the section."""
    hits = (sec or {}).get("hits") or []
    return [h for h in hits if h["list"] == TIF and h["answered"] and not h["must_allow"]]


def lookup(name: str, s) -> list[tuple[str, str, str]]:
    """(kind, short label, copy day) for each kind of list whose copy covers `name`, for `tvgw check`;
    [] with THREAT_LISTS=off, or when no copy is there."""
    if s.threat_lists != "count":
        return []
    n = normalize(name)
    if not is_public_name(n):
        return []
    found = match([n], copies(s.state_dir, parse_urls(s.threat_list_urls)))
    out = []
    for kind in KINDS:
        m = found.get((n, kind))
        if m:
            out.append((kind, label(kind, m.copy.url, short=True), m.copy.day))
    return out


def check_lines(found: list[tuple[str, str, str]], span: int | None) -> list[str]:
    """`tvgw check`'s lines for `lookup()`'s result: one per kind of list that covers the name."""
    out = []
    for kind, src, day in found:
        if kind == TIF:
            out.append(f"  On a threat list: yes ({src}, copy of {day})")
        else:
            within = f", in the last {span} days" if span else ""
            out.append(f"  Newly registered: yes{within} ({src}, copy of {day})")
    return out
