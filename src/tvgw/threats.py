"""(threats) Does the TV talk to known-bad servers? Threat and new-domain lists, counted (design decision 80).

Count-only. Nothing here blocks, refuses or slows anything, and no name the TV looked up ever leaves the
gateway: the lists are downloaded whole, and every match is made here, against the local copies. No
lookup service is asked about any name.

The lists. With THREAT_LISTS=count, `update()` (`sudo tvgw threats --update`, run once a day and at boot
by tvgw-threat-update.timer) downloads each list THREAT_LIST_URLS names: by default HaGeZi's Threat
Intelligence Feeds in their mini form alone (the `tif` kind, about 4 MB). Lists of newly registered
domains (the `nrd` kind, about 50 MB a band) are the owner's to add; their copies go to RUN_DIR, a tmpfs
the unit keeps until the next boot, so the card is not written 100 MB a day for a tag and a section. Each
download is HTTPS only, redirects included, capped at MAX_BYTES and FETCH_SECONDS, read line by line from
curl's output and written, one entry a line, to a staged file beside its copy, which then replaces the
copy in one rename, or is dropped when it hashes as the copy does. A list that fails to download, parses
to fewer than MIN_ENTRIES names, to less than DECLARED_SHARE of the count its own header declares, or to
less than SHRINK of the copy it would replace, keeps the old copy and says so. With THREAT_LISTS=off the
update downloads nothing and removes the copies it made; nothing else reads them then.

The formats (`entries()`), with what each covers, as AdGuard Home reads them: adblock `||name^` (with no
modifier but `$important`), plain domains and dnsmasq lines cover the name and every name under it;
`*.name` covers the names under it only; a hosts-file line covers its name only; an exception `@@||name^`
takes the name and the names under it back out of that list. Comments, cosmetic rules, regular
expressions, addresses, a whole top-level domain and a public suffix (`names.PUBLIC_SUFFIXES`: `co.uk`,
`github.io`, a CDN's shared domain) are skipped; a Unicode name is kept in punycode.

Matching (`match()`). The names to look for are few, the lists long: the TV's distinct names of one day,
a few thousand at most, each with its parent domains, go into one dictionary, and each list streams
past it a line at a time. The gateway's memory therefore grows with the TV's names, never with a list's
size (decision 80 gives the measurement). The hourly ingest's `threats` step (`step()`) matches each local
day SETTLE after it ends, as tvgw-analyze writes its daily file then, up to BACKFILL_DAYS back, and again
when a newer copy arrives for a day matched against one fetched before the day ended. A day's rows go
into `threat_hits`: the list, the entry that matched (the most specific), the lookups, how many of them
the filter answered with a public address (an answer of 0.0.0.0, no address or an error never reached a
server), the first and last time, the copy's day, a newly-registered band, and a doubt: why the hit is
more likely the list's error than the TV's (`doubt_of()`: a must-allow host, an expected category, a zone
the profile never blocks at its apex, an answer by an allow rule, or a name the TV looked up on most of
the 14 days before). The days matched are kept in meta under META_KEY.

Where it shows. `report()` gives the brief its `threats` key. A threat-list name the filter answered with
no doubt is a red line of the act tier, up to MAX_NAMED of them (`red_hits()`); more than that at once,
or one with a doubt, makes one red line of the doctor tier that the list may be wrong (`doubt_hits()`),
which `tvgw doctor` explains (`doctor_notes()`). A refused name stays in the section. Newly registered
names have a section of their own and tag the plain New line. `lookup()` gives `tvgw check` its lines.

Failure. A failed download keeps the old copy; a missing or damaged copy matches nothing and says so;
the brief computes its part in a try, so a failure is a report warning and the rest of the brief stands.
"""

from __future__ import annotations

import contextlib
import fcntl
import hashlib
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
from tvgw.names import LOCAL_SUFFIXES, PUBLIC_SUFFIXES, is_public_address, is_public_name, normalize
from tvgw.profile import Profile, covers

# the two kinds of list: known malware, botnet and phishing servers, and newly registered domains
TIF, NRD = "tif", "nrd"
KINDS = (TIF, NRD)
SUBDIR = "threat"  # under STATE_DIR: the threat lists' copies, MANIFEST and the update's lock
# the newly-registered lists' copies: a tmpfs the unit keeps until the next boot (RuntimeDirectory with
# RuntimeDirectoryPreserve=yes), refetched by the timer's run at boot
RUN_DIR = "/run/tvgw-threat"
MANIFEST = "lists.json"  # per copy: its kind, URL, names, hash, the time it was fetched, its last error
LOCK = ".update.lock"
MAX_URLS = 8
# bytes a download may have: the full TIF list was 30.8 MB and the youngest NRD band 52.4 MB on 2026-11-08
MAX_BYTES = 100 * 1024**2
FETCH_SECONDS = 600  # curl's limit for one download: 100 MB at 1.4 Mbit/s
MIN_ENTRIES = 1000  # the floor: fewer names is an error page or a cut-off download, not a list
DECLARED_SHARE = 0.9  # a list that declares its count ("! Number of entries:") and parses to less is cut off
SHRINK = 0.5  # a list that parses to less than half the copy it would replace keeps that copy
SETTLE = 10800  # seconds after a day ends before it is matched: tvgw-analyze writes the daily file then
BACKFILL_DAYS = 7  # settled days the step matches when it starts, after a gap, or when a newer copy comes
STALE_DAYS = 8  # a copy older than this: the daily update has missed a week (verify's DOH_MAX_AGE)
META_KEY = "threat_matched"  # day -> when it was matched and against which copies
# a name looked up on at least this many of the FAMILIAR_SPAN days before is one the TV uses routinely: a
# list that names it is more likely wrong than the TV newly infected
FAMILIAR_DAYS, FAMILIAR_SPAN = 8, 14
# answered threat-list names a window may name one by one, as act-tier red lines; more at once is one
# doctor-tier line that the list may be wrong
MAX_NAMED = 3
DOCTOR_DAYS = 7  # the days `tvgw doctor` looks back over for a list that may be wrong
# the red lines' starts: `queries.red_lines()` writes them, plain.RED_LINE_PLAIN gives their plain words,
# and the analyst's pack leaves both out, so that no model proposes a block before the count says to
RED_LINE = "known-bad name answered:"
DOUBT_LINE = "threat list may be wrong:"

_URL = re.compile(r"https://[A-Za-z0-9.-]+(?::\d{1,5})?/[A-Za-z0-9._~%/@+-]*")
_FILE = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,79}")
_NRD_BAND = re.compile(r"nrd(\d{1,3})(?:-(\d{1,3}))?\.txt")
_DECLARED = re.compile(r"^[!#]\s*Number of entries:\s*([0-9][0-9,]*)", re.IGNORECASE)
_MODIFIED = re.compile(r"^[!#]\s*Last modified:\s*(.{1,40}?)\s*$", re.IGNORECASE)
_HOSTS_ADDR = re.compile(r"(?:0\.0\.0\.0|127\.0\.0\.1|::1?|0)$")
_DNSMASQ = re.compile(r"(?:local|address|server)=/(.+)/")
_COSMETIC = ("##", "#@#", "#?#", "#$#")
# a name of at least two labels, each as names._LABEL allows it, the last letters or punycode
_HOST = re.compile(r"(?:[a-z0-9_](?:[a-z0-9_-]{0,61}[a-z0-9_])?\.)+(?:[a-z]{1,63}|xn--[a-z0-9-]{1,59})")
# how an entry is kept in a copy, one a line: a bare name covers itself and every name under it; these
# marks narrow it (EXACT: a hosts-file line; UNDER: `*.name`) or take names back out (EXCEPT: `@@||name^`)
EXACT, UNDER, EXCEPT = "=", ".", "!"


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


def band(file: str) -> str | None:
    """A newly-registered list's band, `<youngest>-<oldest>` in days before its copy, from HaGeZi's file
    names (`nrd7.txt`: 1 to 7 days, `nrd14-8.txt`: 8 to 14), or None for a name that does not say."""
    m = _NRD_BAND.fullmatch(file)
    if not m:
        return None
    return f"{int(m.group(2) or 1)}-{int(m.group(1))}"


# ---- parsing --------------------------------------------------------------------------------------------
def _name(text: str) -> str | None:
    """An entry as a name, or None: `names.is_public_name()`'s rule in one expression, since a list holds
    millions of entries and the update reads every one; a Unicode name in punycode; a public suffix, which
    names no one tenant, is no entry."""
    n = normalize(text)
    if not n.isascii():
        try:
            n = n.encode("idna").decode("ascii")
        except UnicodeError:
            return None
    if len(n) > 253 or not _HOST.fullmatch(n) or n.endswith(LOCAL_SUFFIXES) or n in PUBLIC_SUFFIXES:
        return None
    return n


def entries(line: str) -> list[str]:
    """The entries one line of a list holds, as a copy keeps them: a bare name covers itself and every
    name under it, `=name` itself alone (a hosts-file line), `.name` the names under it alone (`*.name`),
    and `!name` takes itself and the names under it back out (an exception). [] for a comment, a cosmetic
    or regular-expression rule, an address, a single label, a public suffix, or anything else that names
    no domain."""
    s = line.strip()
    if not s or s[0] in "!#[":
        return []
    if "#" in s:  # a cosmetic rule, or a comment after the entry
        if any(c in s for c in _COSMETIC):
            return []
        s = re.split(r"\s+#", s, maxsplit=1)[0].strip()
    mark = ""
    if s.startswith("@@"):  # an exception: adblock form only
        mark, s = EXCEPT, s[2:]
        if not s.startswith("||"):
            return []
    if s.startswith("||"):  # adblock: ||name^ with no modifier but $important
        body, _, mods = s[2:].partition("$")
        if mods and mods.strip() != "important":
            return []
        body = body.removesuffix("|").removesuffix("^")
        if body.startswith("*."):
            mark, body = mark or UNDER, body[2:]
        return [mark + n] if (n := _name(body)) else []
    if s.startswith(("|", "/")):  # an anchored URL or a regular expression: no domain list entry
        return []
    m = _DNSMASQ.match(s)
    if m:
        return [n for part in m.group(1).split("/") if (n := _name(part))]
    words = s.split()
    if len(words) > 1 and _HOSTS_ADDR.match(words[0]):  # a hosts file: each name after the address alone
        return [EXACT + n for w in words[1:] if (n := _name(w))]
    if len(words) != 1:
        return []
    if words[0].startswith("*."):
        return [UNDER + n] if (n := _name(words[0][2:])) else []
    return [n] if (n := _name(words[0])) else []


@dataclass
class Parsed:
    """What one download parsed to: the names written, the exceptions, the lines skipped, what its header
    said, and the SHA-256 of the copy written."""

    entries: int = 0
    exceptions: int = 0
    skipped: int = 0
    declared: int | None = None
    modified: str | None = None
    sha256: str = ""


def parse(lines: Iterable[bytes | str], out) -> Parsed:
    """Write the entries `lines` hold to `out`, one a line, and count them; the header's declared count
    and date are kept when the list carries them."""
    got = Parsed()
    digest = hashlib.sha256()
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
            digest.update(n.encode() + b"\n")
            if n[0] == EXCEPT:
                got.exceptions += 1
            else:
                got.entries += 1
    got.sha256 = digest.hexdigest()
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


def copy_dir(kind: str, state_dir: str, run_dir: str | None = None) -> str:
    """Where a kind's copies live: a threat list's under the state directory, a newly-registered list's
    in RUN_DIR, the tmpfs."""
    return (run_dir or RUN_DIR) if kind == NRD else threat_dir(state_dir)


def load_manifest(d: str) -> dict[str, dict]:
    """The manifest: per copy's file, its kind, URL, names, hash and fetch time, and its last error; {}
    when there is none or it cannot be read (a damaged manifest matches nothing: the next update writes
    it)."""
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


def _fetch_one(
    d: str, src: Source, fetch: Callable[[str], Iterable], old: dict | None
) -> tuple[Parsed, bool]:
    """Download one list into a staged file beside its copy, check it, and rename it over the copy: the
    copy is untouched unless every check passed, and is kept as it is when the new one hashes the same.
    (what it parsed to, whether the copy changed)."""
    fd, staged = tempfile.mkstemp(dir=d, prefix=f".{src.file}.")
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as out:
            got = parse(fetch(src.url), out)
            out.flush()
            os.fsync(out.fileno())
        before = (old or {}).get("entries")
        if got.entries < MIN_ENTRIES:
            raise Refused(f"only {got.entries:,} names, fewer than the floor of {MIN_ENTRIES:,}")
        if got.declared and got.entries < DECLARED_SHARE * got.declared:
            raise Refused(f"{got.entries:,} names of the {got.declared:,} it declares: cut off")
        if before and got.entries < SHRINK * before:
            raise Refused(f"{got.entries:,} names, under half the {before:,} of the copy it would replace")
        if old and old.get("sha256") == got.sha256:
            os.unlink(staged)
            return got, False
        os.chmod(staged, 0o640)
        os.replace(staged, os.path.join(d, src.file))
        return got, True
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
    state_dir: str,
    setting: str,
    urls: str,
    fetch: Callable[[str], Iterable] = curl_lines,
    now: float | None = None,
    run_dir: str | None = None,
) -> Outcome:
    """Download every list `urls` names (THREAT_LISTS=count), or remove the copies (off). Exit status 1
    when a list kept its old copy or has none, as tvgw-doh-update's is, so a failing day shows in
    `systemctl --failed`."""
    now = time.time() if now is None else now
    d = threat_dir(state_dir)
    if setting != "count":
        removed = remove_copies(state_dir, run_dir)
        said = f"; removed {removed} old cop{'y' if removed == 1 else 'ies'}" if removed else ""
        return Outcome(0, [f"tvgw threats: THREAT_LISTS is off, so nothing was downloaded{said}"])
    sources = parse_urls(urls)
    os.makedirs(d, mode=0o750, exist_ok=True)  # the unit's StateDirectory makes it; a run by hand may not
    lines, failed = [], 0
    with open(os.path.join(d, LOCK), "w", encoding="utf-8") as lock:
        fcntl.flock(lock, fcntl.LOCK_EX)
        manifest = load_manifest(d)
        for src in sources:
            where = copy_dir(src.kind, state_dir, run_dir)
            old = manifest.get(src.file) or {}
            same = old.get("url") == src.url and old.get("kind") == src.kind
            have = same and os.path.exists(os.path.join(where, src.file)) and old.get("fetched")
            try:
                os.makedirs(where, mode=0o750, exist_ok=True)
                got, changed = _fetch_one(where, src, fetch, old if have else None)
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
                "exceptions": got.exceptions,
                "sha256": got.sha256,
                "fetched": now,
                "declared": got.declared,
                "modified": got.modified,
                "tried": now,
            }
            how = "" if changed else ", unchanged"
            lines.append(f"tvgw threats: {src.file}: {got.entries:,} names ({label(src.kind, src.url)}{how})")
        for gone in sorted(set(manifest) - {s.file for s in sources}):  # a list no longer named
            kind = manifest[gone].get("kind")
            with contextlib.suppress(FileNotFoundError):
                os.unlink(os.path.join(copy_dir(kind, state_dir, run_dir), gone))
            del manifest[gone]
            lines.append(f"tvgw threats: {gone}: removed, since THREAT_LIST_URLS no longer names it")
        _write_atomic(os.path.join(d, MANIFEST), json.dumps(manifest, indent=1, sort_keys=True))
    return Outcome(1 if failed else 0, lines)


def remove_copies(state_dir: str, run_dir: str | None = None) -> int:
    """Remove the copies and the manifest an update made; the number of copies removed."""
    d = threat_dir(state_dir)
    manifest = load_manifest(d)
    n = 0
    for name, m in manifest.items():
        if _FILE.fullmatch(name):
            with contextlib.suppress(FileNotFoundError):
                os.unlink(os.path.join(copy_dir(m.get("kind"), state_dir, run_dir), name))
                n += 1
    with contextlib.suppress(FileNotFoundError):
        os.unlink(os.path.join(d, MANIFEST))
    return n


@dataclass(frozen=True)
class Copy:
    """A list copy that matching reads."""

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
        """The copy as META_KEY keeps it: kind, file, the day it was fetched, names, label, fetch time."""
        return [self.kind, self.file, self.day, self.entries, label(self.kind, self.url), self.fetched]


def copies(state_dir: str, sources: Iterable[Source], run_dir: str | None = None) -> list[Copy]:
    """The copies matching may read: each list still named whose file and manifest entry both exist (a
    newly-registered list's copy is gone after a reboot until the timer's run at boot fetches it)."""
    manifest = load_manifest(threat_dir(state_dir))
    out = []
    for src in sources:
        m = manifest.get(src.file) or {}
        path = os.path.join(copy_dir(src.kind, state_dir, run_dir), src.file)
        named = m.get("url") == src.url and m.get("kind") == src.kind and m.get("fetched")
        if named and os.path.isfile(path):
            entries_ = int(m.get("entries") or 0)
            out.append(Copy(src.kind, src.file, path, src.url, entries_, float(m["fetched"])))
    return out


def _day(t: float) -> str:
    return datetime.fromtimestamp(t).strftime("%Y-%m-%d")


# ---- matching -------------------------------------------------------------------------------------------
def parents(name: str) -> list[str]:
    """The domains strictly above a name with at least two labels, a public suffix left out: an entry for
    any of them that covers the names under it covers this one."""
    labels = name.split(".")
    return [p for i in range(1, len(labels) - 1) if (p := ".".join(labels[i:])) not in PUBLIC_SUFFIXES]


@dataclass(frozen=True)
class Match:
    name: str
    kind: str
    entry: str  # the list's entry that covers the name: the most specific one
    copy: Copy


def match(names: Iterable[str], found_in: Iterable[Copy]) -> dict[tuple[str, str], Match]:
    """(name, kind) -> the match, for every name some copy covers and no exception of that copy takes back.
    The names, with the keys each could be covered under, go into one dictionary, and each copy streams
    past it a line at a time, so memory grows with the names and never with a list (the module
    docstring)."""
    wanted: dict[str, list[str]] = {}
    for n in names:
        for key in (n, EXACT + n, EXCEPT + n):
            wanted.setdefault(key + "\n", []).append(n)
        for p in parents(n):
            for key in (p, UNDER + p, EXCEPT + p):
                wanted.setdefault(key + "\n", []).append(n)
    found: dict[tuple[str, str], Match] = {}
    if not wanted:
        return found
    for c in found_in:
        here: dict[str, str] = {}
        excepted: set[str] = set()
        with open(c.path, encoding="utf-8", errors="replace") as fh:
            for line in fh:
                hit = wanted.get(line)
                if hit is None:
                    continue
                if line[0] == EXCEPT:
                    excepted.update(hit)
                    continue
                e = line[:-1].lstrip(EXACT + UNDER)
                for n in hit:
                    if len(e) > len(here.get(n, "")):
                        here[n] = e
        for n, e in here.items():
            prev = found.get((n, c.kind))
            if n not in excepted and (prev is None or len(e) > len(prev.entry)):
                found[(n, c.kind)] = Match(n, c.kind, e, c)
    return found


def _reached(answers: str | None) -> bool:
    """Whether a lookup's answers hold a public address: what an answer that let the TV reach a server
    holds. 0.0.0.0, an error with no address and the gateway's own rewrite never reached one."""
    for part in (answers or "").split(","):
        kind, _, value = part.partition(":")
        if kind == "A" and is_public_address(value):
            return True
    return False


def day_names(conn: sqlite3.Connection, a: float, b: float) -> dict[str, dict]:
    """The TV's distinct internet names in [a, b), allowed and refused: name -> lookups, answered (with a
    public address), by_rule (of those, answered under an allow rule), first, last. Local names, addresses
    and a name the ingest replaced by a keyed tag never match."""
    out: dict[str, dict] = {}
    rows = conn.execute(
        "SELECT qname, blocked, answers, rule, COUNT(*), MIN(t), MAX(t) FROM dns WHERE t >= ? AND t < ?"
        " GROUP BY qname, blocked, answers, rule",
        (a, b),
    )
    for qname, blocked, answers, rule, n, first, last in rows:
        name = normalize(qname or "")
        if not is_public_name(name):
            continue
        reached = n if not blocked and _reached(answers) else 0
        by_rule = reached if (rule or "").startswith("@@") else 0
        have = out.setdefault(name, {"lookups": 0, "answered": 0, "by_rule": 0, "first": first, "last": last})
        have["lookups"] += n
        have["answered"] += reached
        have["by_rule"] += by_rule
        have["first"], have["last"] = min(have["first"], first), max(have["last"], last)
    return out


def familiar_days(conn: sqlite3.Connection, name: str, a: float) -> int:
    """The local days among the FAMILIAR_SPAN before `a` on which the TV looked `name` up."""
    return conn.execute(
        "SELECT COUNT(DISTINCT date(t, 'unixepoch', 'localtime')) FROM dns"
        " WHERE qname = ? AND t >= ? AND t < ?",
        (name, a - FAMILIAR_SPAN * 86400, a),
    ).fetchone()[0]


def doubt_of(conn: sqlite3.Connection, name: str, info: dict, prof: Profile, a: float) -> str | None:
    """Why a hit is more likely the list's error than the TV's, or None: the name is a must-allow host,
    in one of the profile's expected categories, in a zone it never blocks at its apex, was answered under
    an allow rule, or was looked up on at least FAMILIAR_DAYS of the FAMILIAR_SPAN days before. The first
    that holds, as `kind` or `kind:detail`."""
    if any(covers(host, name) for host in prof.must_allow):
        return "must-allow"
    if prof.is_expected(name):
        return f"expected:{prof.categorize(name)}"
    apex = next((x for x in prof.never_block_apex if covers(x, name)), None)
    if apex:
        return f"apex:{apex}"
    if info["by_rule"]:
        return "allow-rule"
    days = familiar_days(conn, name, a)
    return f"familiar:{days}" if days >= FAMILIAR_DAYS else None


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
    conn: sqlite3.Connection, day: str, prof: Profile, found_in: list[Copy], now: float, record: bool = True
) -> int:
    """Match one local day's names against the copies and replace its rows in `threat_hits`; with
    `record`, mark the day matched in META_KEY (an on-demand match of a day not yet settled is not
    marked, so the settled one still runs). The number of rows written."""
    a, b = _bounds(day)
    names = day_names(conn, a, b)
    found = match(names, found_in)
    conn.execute("DELETE FROM threat_hits WHERE day = ?", (day,))
    for (name, kind), m in sorted(found.items()):
        info = names[name]
        conn.execute(
            "INSERT INTO threat_hits(day, name, list, entry, source, copy, band, lookups, answered, first,"
            " last, doubt) VALUES (?,?,?,?,?,?,?,?,?,?,?,?)",
            (day, name, kind, m.entry, label(kind, m.copy.url), m.copy.day,
             band(m.copy.file) if kind == NRD else None, info["lookups"], info["answered"], info["first"],
             info["last"], doubt_of(conn, name, info, prof, a)),
        )  # fmt: skip
    if record:
        meta = load_meta(conn)
        meta[day] = {"t": now, "copies": [c.stored() for c in found_in]}
        db.set_meta(conn, META_KEY, json.dumps(meta, sort_keys=True))
    return len(found)


def _outdated(entry: dict, found_in: list[Copy], day_end: float) -> bool:
    """Whether a matched day should be matched again: a copy has come that the match did not read, or a
    newer copy of one it read, which was fetched before the day ended (a night whose download failed
    left the day matched against the day before's list). A copy gone missing is no news."""
    read = {c[1]: c[5] for c in entry.get("copies") or [] if isinstance(c, list) and len(c) >= 6}
    return any(c.file not in read or (c.fetched > read[c.file] and read[c.file] < day_end) for c in found_in)


def step(
    conn: sqlite3.Connection, s, prof: Profile, now: float | None = None, run_dir: str | None = None
) -> list[str]:
    """The hourly ingest's `threats` step: with THREAT_LISTS=count, match each settled day of the last
    BACKFILL_DAYS that was not matched yet, or was matched against copies a newer one replaces; with off,
    forget which days were matched (the rows stay until DB_DAYS prunes them). Warnings for the ingest: a
    gateway with no copy after an update failed."""
    now = time.time() if now is None else now
    meta = load_meta(conn)
    if s.threat_lists != "count":
        if meta:
            conn.execute("DELETE FROM meta WHERE key = ?", (META_KEY,))
        return []
    sources = parse_urls(s.threat_list_urls)
    found_in = copies(s.state_dir, sources, run_dir)
    if not found_in:
        failed = [m for m in load_manifest(threat_dir(s.state_dir)).values() if m.get("error")]
        return [f"no list copy to match against: {failed[0]['error'][:120]}"] if failed else []
    today = date.fromtimestamp(now)
    for back in range(BACKFILL_DAYS, 0, -1):
        day = (today - timedelta(days=back)).isoformat()
        end = _bounds(day)[1]
        if end > now - SETTLE or (day in meta and not _outdated(meta[day], found_in, end)):
            continue
        match_day(conn, day, prof, found_in, now)
    keep = {d: v for d, v in load_meta(conn).items() if d >= (today - timedelta(days=s.db_days)).isoformat()}
    db.set_meta(conn, META_KEY, json.dumps(keep, sort_keys=True))
    return []


# ---- reading --------------------------------------------------------------------------------------------
COLUMNS = (
    "day", "name", "list", "entry", "source", "copy", "band", "lookups", "answered", "first", "last", "doubt",
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
    the window's days, with the newest day's entry, copy, band and doubt; `matched` the window's days
    that were matched; `copies` the copies the newest of them was matched against; `stale` when one of
    them is older than STALE_DAYS."""
    now = time.time() if now is None else now
    meta = load_meta(conn)
    found = rows(conn, a, b)
    if not meta and not found:
        return None
    hits: dict[tuple[str, str], dict] = {}
    for r in found:  # oldest day first, so a later day's entry, copy, band and doubt replace an earlier's
        key = (r["name"], r["list"])
        h = hits.get(key)
        if h is None:
            hits[key] = {k: r[k] for k in COLUMNS if k != "day"}
            continue
        h["lookups"] += r["lookups"]
        h["answered"] += r["answered"]
        h["first"], h["last"] = min(h["first"], r["first"]), max(h["last"], r["last"])
        for k in ("entry", "source", "copy", "band", "doubt"):
            h[k] = r[k]
    ordered = sorted(
        hits.values(),
        key=lambda h: (h["list"] != TIF, h["doubt"] is not None, -h["answered"], -h["lookups"], h["name"]),
    )
    days = _days(a, b)
    matched = [d for d in days if d in meta]
    newest = meta.get(matched[-1]) if matched else (meta[max(meta)] if meta else None)
    copies_ = [c[:5] for c in (newest or {}).get("copies") or [] if isinstance(c, list) and len(c) >= 5]
    oldest_copy = min((c[2] for c in copies_), default=None)
    stale = bool(oldest_copy) and date.fromtimestamp(now) - date.fromisoformat(oldest_copy) > timedelta(
        days=STALE_DAYS
    )
    return {
        "hits": ordered,
        "days": days,
        "matched": matched,
        "copies": [dict(zip(("list", "file", "copy", "names", "source"), c, strict=True)) for c in copies_],
        "stale": stale,
    }


def _answered_tif(sec: dict | None) -> list[dict]:
    return [h for h in (sec or {}).get("hits") or [] if h["list"] == TIF and h["answered"]]


def red_hits(sec: dict | None) -> list[dict]:
    """The hits that make act-tier red lines: threat-list names the filter answered with a public address
    and that have no doubt, when there are at most MAX_NAMED of them. A refused name, a newly registered
    one, one with a doubt, and every one of more than MAX_NAMED at once go elsewhere (`doubt_hits()`)."""
    clean = [h for h in _answered_tif(sec) if not h["doubt"]]
    return clean if len(clean) <= MAX_NAMED else []


def doubt_hits(sec: dict | None) -> list[dict]:
    """The answered threat-list names that make the one doctor-tier line that the list may be wrong: each
    with a doubt, and every one when more than MAX_NAMED without a doubt came at once."""
    answered = _answered_tif(sec)
    clean = [h for h in answered if not h["doubt"]]
    return [h for h in answered if h["doubt"]] + (clean if len(clean) > MAX_NAMED else [])


def why(h: dict, many: int = 0) -> str:
    """A hit's doubt in a few plain words, or, with no doubt, `one of N at once`."""
    kind, _, detail = (h.get("doubt") or "").partition(":")
    return {
        "must-allow": "kept reachable on purpose",
        "expected": f"its profile expects it ({detail})",
        "apex": f"under {detail}, never blocked at its apex",
        "allow-rule": "let through by an allow rule",
        "familiar": f"looked up on {detail} of the {FAMILIAR_SPAN} days before",
    }.get(kind, f"one of {many} at once")


def doubt_line(sec: dict | None) -> str | None:
    """The doctor-tier red line after its start (DOUBT_LINE), or None: the list, its copy, and the names
    with why each is doubted."""
    hits = doubt_hits(sec)
    if not hits:
        return None
    many = sum(1 for h in hits if not h["doubt"])
    shown = ", ".join(f"{h['name']} ({why(h, many)})" for h in hits[:MAX_NAMED])
    more = f" and {len(hits) - MAX_NAMED} more" if len(hits) > MAX_NAMED else ""
    return (
        f"{hits[0]['source']} (copy of {hits[0]['copy']}) names {len(hits)} name"
        f"{'' if len(hits) == 1 else 's'} the filter answered that the TV uses on purpose or that came too"
        f" many at once: {shown}{more}; see Known-bad names"
    )


def lookup(name: str, s, run_dir: str | None = None) -> list[tuple[str, str, str, str | None]]:
    """(kind, short label, copy day, band) for each kind of list whose copy covers `name`, for `tvgw
    check`; [] with THREAT_LISTS=off, or when no copy is there."""
    if s.threat_lists != "count":
        return []
    n = normalize(name)
    if not is_public_name(n):
        return []
    found = match([n], copies(s.state_dir, parse_urls(s.threat_list_urls), run_dir))
    out = []
    for kind in KINDS:
        m = found.get((n, kind))
        if m:
            out.append((kind, label(kind, m.copy.url, short=True), m.copy.day, band(m.copy.file)))
    return out


def band_words(b: str | None, day: str) -> str:
    """A newly-registered band in words, by the day of the copy: `registered in the 7 days before
    2026-11-07`, `registered 8 to 14 days before 2026-11-07`, or `on a list of newly registered names of
    2026-11-07` when the list's file name does not say."""
    if not b:
        return f"on a list of newly registered names of {day}"
    lo, _, hi = b.partition("-")
    return (
        f"registered in the {hi} days before {day}"
        if lo == "1"
        else f"registered {lo} to {hi} days before {day}"
    )


def check_lines(found: list[tuple[str, str, str, str | None]]) -> list[str]:
    """`tvgw check`'s lines for `lookup()`'s result: one per kind of list that covers the name."""
    out = []
    for kind, src, day, b in found:
        if kind == TIF:
            out.append(f"  On a threat list: yes ({src}, copy of {day})")
        else:
            out.append(f"  Newly registered: yes, {band_words(b, day)} ({src})")
    return out


def doctor_notes(s, now: float | None = None, run_dir: str | None = None) -> list[str]:
    """What `tvgw doctor` says about the threat lists, in plain words, with THREAT_LISTS=count: each name
    of the last DOCTOR_DAYS days that makes the list-may-be-wrong line and why, how to stop it, and a copy
    a week old or more. [] when there is nothing to say, the setting is off or the store cannot be read."""
    if s.threat_lists != "count":
        return []
    now = time.time() if now is None else now
    out: list[str] = []
    try:
        conn = db.connect(s.db_path, readonly=True)
        try:
            sec = report(conn, now - DOCTOR_DAYS * 86400, now, now)
        finally:
            conn.close()
    except (sqlite3.Error, OSError):
        sec = None
    hits = doubt_hits(sec)
    if hits:
        many = sum(1 for h in hits if not h["doubt"])
        for h in hits:
            out.append(
                f"  {h['source']} names {h['name']}, which the gateway let through: {why(h, many)}. The list"
                " is probably wrong about it."
            )
        if many:
            out.append(
                f"  So many names at once ({many}) more often means the list is wrong than that the TV is"
                " infected. If the TV also acts strangely, follow the brief's steps for one name."
            )
        out.append(
            "  Nothing was blocked. The gateway goes on counting them; to stop, point THREAT_LIST_URLS at"
            " another list, or set THREAT_LISTS=off, in /etc/tvgw/tvgw.conf."
        )
    try:
        found_in = copies(s.state_dir, parse_urls(s.threat_list_urls), run_dir)
    except ValueError:
        found_in = []
    for c in found_in:
        age = (now - c.fetched) / 86400
        if age > STALE_DAYS:
            out.append(
                f"  The copy of {c.file} is {int(age)} days old. Run sudo tvgw threats --update; to see why"
                " the daily download failed, run journalctl -u tvgw-threat-update -n 5."
            )
    return ["Threat lists (counting only):", *out] if out else []
