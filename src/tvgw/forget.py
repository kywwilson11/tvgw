"""`tvgw forget`: delete the gateway's viewing record, keep the gateway.

The store and the files beside it are, together, an hour-by-hour record of what the household watched
(docs/how-it-works/privacy-and-retention.md). `forget` removes every part of it that tvgw itself
keeps: the store's rows that hold names, addresses or times of use, the pcaps, the reports and
proposals, the flow, URL-filter and TV-reading logs with their rotations, the copies in `backup/` and
the name keys. It keeps what makes the gateway work and what proves it held: the settings, the rules
and their history, the machine's rules, the owner's site rules (`LOCAL_RULES`, wherever it points), the
verify history and firewall counters, the TV's settings history and the owner's on-screen
confirmations, the schema and the ingest cursors of the sources it did not empty.

Every table and every file tree is classified here, as data (`TABLES`, `STATE_ENTRIES`,
`LOG_ENTRIES`), and tests/unit/test_forget.py fails when `db.SCHEMA` gains a table, or the code and
the deploy files gain a path under /var/lib/tvgw or /var/log/tvgw, that these do not name: a new store
cannot escape it unnoticed. At run time an entry nobody classified is kept and reported, never deleted.

Late evidence comes back on its own: conntrack reports an idle connection two hours after its last
packet, the capture's open file holds up to an hour, AdGuard flushes its query log in batches. So the
run records `meta.forget_before`, and every ingest after it deletes any row older than that
(`drop_late`), whatever source it came from, for `LATE_DAYS`; then the floor is removed.

What tvgw cannot reach (the journal, AdGuard's statistics, copies pulled off the Pi, the analyst's
requests at Anthropic, CI logs, the card's freed blocks) is listed by `residue()` on every run.
"""

from __future__ import annotations

import contextlib
import fcntl
import fnmatch
import os
import shutil
import sqlite3
import time
from collections.abc import Callable
from dataclasses import dataclass, field

from tvgw import db, pcaps

FORGET, KEEP = "forget", "keep"

# ---- the store, table by table ----------------------------------------------------------------------
# table -> (policy, why). A table db.SCHEMA creates and this does not name fails the CI test.
TABLES: dict[str, tuple[str, str]] = {
    "meta": (KEEP, "the schema version and the gateway's bookkeeping; its viewing keys are removed"),
    "ingest_state": (KEEP, "read positions; those of the logs forget empties are reset"),
    "ingest_runs": (FORGET, "per-run counts and warnings: when the TV was busy"),
    "pcaps_done": (FORGET, "the names of the captures read, which are deleted with them"),
    "flows": (FORGET, "every connection, its destination, times and bytes"),
    "dns": (FORGET, "every lookup and its answers"),
    "tls": (FORGET, "every TLS server name"),
    "tls_noname": (FORGET, "every nameless TLS hello: destination and time"),
    "http": (FORGET, "every plain-HTTP request"),
    "lanprobe": (FORGET, "the TV's connection attempts into private ranges"),
    "tvstate": (FORGET, "the power state and foreground app, hour by hour"),
    "tv_events": (FORGET, "(app in front) the power state and the app in front, to the second"),
    "tvsettings": (KEEP, "the TV's configuration and its changes; the Live Plus and radio red lines read it"),
    "oddport": (FORGET, "connections to unexpected ports"),
    "gate": (FORGET, "connections to addresses no lookup returned"),
    "auto_rules": (KEEP, "the rules the gateway added on its own: policy, not viewing"),
    "judgments": (FORGET, "the analyst's verdict on each name it was shown"),
    "hosts": (FORGET, "every name ever seen, with first and last sighting"),
    "rules": (KEEP, "the policy's history"),
    "verify": (KEEP, "the verify history"),
    "fw_counters": (KEEP, "the firewall's counters, the proof that it held"),
    # research pass 2 (schema 9)
    "adport": (FORGET, "(acr) the TV's attempts on LG's ad-tech ports: destinations and times"),
    "decisions": (FORGET, "(autonomy) every step the autonomy took, with the names and margins it was shown"),
    "auto_queue": (FORGET, "(autonomy) blocks waiting their turn: names the analyst was shown"),
    "changes": (FORGET, "(ledger) the change ledger: TV link edges and consent flips say when it was used"),
    "gw_samples": (FORGET, "(ledger) ten-minute samples with the TV port's byte counters"),
    "judge_shadow": (FORGET, "(ledger) judge v2's verdict per hour, with the hour's TV class"),
    # research pass 4 (schema 11)
    "gate_inpath": (FORGET, "(inpath) connections to addresses the in-path gate set did not hold"),
    # research pass 5 (schema 15)
    "answer_ip": (FORGET, "(namebound) the addresses each lookup's answer named, and when"),
    # the competitive-gap pass (schema 16)
    "threat_hits": (FORGET, "(threats) names the TV looked up that a threat list covers, with their times"),
}
# forgotten tables with a time column: what `drop_late` trims below meta.forget_before. A pair is
# (column, fallback when it is NULL): a flow's start, or its end when conntrack never saw it begin
TIME_COLUMNS: dict[str, str | tuple[str, str]] = {
    "flows": ("t_start", "t_end"),
    "dns": "t",
    "tls": "t",
    "tls_noname": "t",
    "http": "t",
    "lanprobe": "t",
    "tvstate": "t",
    "tv_events": "t",
    "oddport": "t",
    "gate": "t",
    "judgments": "t",
    "ingest_runs": "t",
    "adport": "t",
    "decisions": "t",
    "auto_queue": "queued_t",
    "changes": "t",
    "gw_samples": "t",
    "judge_shadow": "t",
    "gate_inpath": "t",
    "answer_ip": "t",  # (namebound)
    "threat_hits": "first",
}
# meta keys that carry viewing: the hosts watermark (row ids of forgotten rows), the last warnings
# (which can name a pcap or a host), (budget) the upload budget's ceiling, whose derivation names a
# destination and an hour; the next clean history sets the ceiling again (budget.META_KEY),
# (listguard) the list-update previews, which name what the TV looked up (listguard.PREVIEW_KEY), and
# (counting) the runs of the count-only mechanisms, whose two weeks are judged by rows forget empties: the
# next `verify --record` begins each again from what its own record still holds (counting.META_KEY). The
# list guard's own state, the lists' lines and the TV's rules, is policy and stays. (namebound) The answer
# table's record of what it covers goes with its rows, so no window before the forget is read as covered;
# (threats) the days the threat lists were matched, which without their rows would read as matched with nothing found
META_FORGET = (
    "hosts_wm",
    "last_warnings",
    "upload_budget",
    "list_preview",
    "counting",
    "answer_ip_from",  # (namebound) namebound.META_KEYS: the next ingest starts the table's record again
    "answer_ip_done",
    "answer_ip_since",
    "threat_matched",  # (threats)
)
FLOOR_KEY = "forget_before"
# how long after a forget a source can still deliver rows of the time before it: conntrack's default
# timeout for an established TCP connection is 5 days, the journal's cursor waits out an ingest outage.
# Past this the floor goes, and the hourly ingest stops paying for the trim.
LATE_DAYS = 7
# ingest_state cursors of the logs forget empties: reset, so the next ingest reads the emptied file from
# its start (logtail would otherwise look for the lost lines in a `.1` that is gone)
CURSORS = ("flows", "gfts", "tvstate", "tvlive")
QUERYLOG_CURSOR = "adguard"

# ---- the files, by name under the state and log directories ---------------------------------------
# (app in front) tvlive.ATTEMPTS_FILE: emptied in place, never removed. The hourly reading writes only to a
# file that exists, and the live reading reads it before every attempt, so a removed file would stop both
# counting
ATTEMPTS = "tvlive-attempts"
# (fnmatch pattern of the first path component, policy, why). The first matching pattern wins.
STATE_ENTRIES: tuple[tuple[str, str, str], ...] = (
    ("tvgw.db", FORGET, "the store: its rows go table by table, the file stays"),
    ("tvgw.db-journal", KEEP, "SQLite's rollback journal; removing a live one corrupts the store"),
    ("backup", FORGET, "whole copies of the store; one fresh copy is made afterwards"),
    ("pcap", FORGET, "the captures; the file the capture is writing stays"),
    ("reports", FORGET, "every brief, report, proposal and pack; the directories stay"),
    ("tvcheck.txt", FORGET, "the last reading of the TV, with the app in front"),
    ("tvcheck-history.log", FORGET, "one power and app line an hour: emptied in place"),
    ("tvcheck-history.log.*", FORGET, "its rotations"),
    (".tvcheck.tmp", FORGET, "a reading in progress"),
    ("tvlive-events.log", FORGET, "(app in front) the live reading's events: emptied in place"),
    ("tvlive-events.log.*", FORGET, "(app in front) their rotations"),
    (
        ATTEMPTS,
        FORGET,
        "(app in front) the times the TV's API was reached in the last hour, which say when the TV was on:"
        " emptied in place, so the live reading and the hourly reading go on counting in it",
    ),
    ("tvlive-progress", FORGET, "(app in front) the live reading's give-up counts: operational, regenerated"),
    ("tvlive-stood-down", KEEP, "(app in front) why the live reading stood down, until the owner resumes it"),
    ("name-keys", FORGET, "the name keys: once gone, no tag left anywhere can be linked again"),
    ("archive", FORGET, "the retired text pipeline's archive"),
    ("sni.tsv", FORGET, "retired"),
    ("http.tsv", FORGET, "retired"),
    ("querylog.json", FORGET, "a retired copy of AdGuard's query log"),
    ("doh4.txt", KEEP, "the public DoH resolver list"),
    ("threat", KEEP, "(threats) the public threat and newly-registered-domain lists and their manifest"),
    (".doh4.*", KEEP, "the DoH list being written"),
    ("doh4.held", KEEP, "(listguard) a DoH list refresh held back: counts of public addresses, and when"),
    ("doh4.base", KEEP, "(listguard) while a DoH refresh is held back, the public list last taken"),
    (
        "lists",
        KEEP,
        "(listguard) a copy of each subscribed blocklist, public text, for the next update's preview",
    ),
    ("lgtv-keys.sqlite", KEEP, "the LAN-API pairing key"),
    ("auto.rules", KEEP, "the machine's rules"),
    ("auto.rules.tmp", KEEP, "the machine's rules being written"),
    (".unit-stamps", KEEP, "what each long-running unit started with"),
    (".ingest.lock", KEEP, "the ingest lock"),
    ("autoblock.lock", KEEP, "(autonomy) the hourly check's lock"),
    ("deploy-deferred", KEEP, "(deploy window) the commit a CI deploy waits for the quiet window with"),
    ("changes.spool", FORGET, "(ledger) change lines not yet read: TV link edges among them"),
    ("changes.spool.1", FORGET, "(ledger) the spool's rotation"),
    ("probe", FORGET, "(ledger) tvgw tvprobe's record: power and app changes, a viewing record"),
    ("onscreen.log", KEEP, "(plain) the owner's dated word on TV settings the TV does not report"),
    (".adguard-installed-by-tvgw", KEEP, "(adguard) the AdGuard Home version tvgw adguard install installed"),
    (".adguard-install.lock", KEEP, "(adguard) tvgw adguard install's lock"),
    (".installed-by-tvgw", KEEP, "(uninstall) what the install changed that removing the package gives back"),
    (".installed-by-tvgw.new", KEEP, "(uninstall) that record being written"),
    (
        "evidence",
        FORGET,
        "(evidence) the hash-chained file of each day's facts: tracking domains, uploads, consent readings",
    ),
    ("requests", FORGET, "(requests) the request drafts: the companies the TV reached, by day"),
)
# each log by name, as deploy/logrotate/tvgw names them: a new log is unclassified, and the CI test
# fails, until someone decides whether it is kept or forgotten
LOG_ENTRIES: tuple[tuple[str, str, str], ...] = (
    ("flows.log", FORGET, "every connection the TV made: emptied in place, its writer keeps the file open"),
    ("flows.log.*", FORGET, "a rotated copy"),
    ("gfts.log", FORGET, "every URL the vendor file filter saw: emptied in place"),
    ("gfts.log.*", FORGET, "a rotated copy"),
    ("gfts-tls.log", FORGET, "the TLS passthrough's server names and times: emptied in place"),
    ("gfts-tls.log.*", FORGET, "a rotated copy"),
)
REPORTS_KEEP = (".from-the-store",)  # install.sh's mark that the legacy reports were moved once
# (site rules) LOCAL_RULES, kept wherever the settings put it (design decision 59)
LOCAL_RULES_WHY = "(site rules) the owner's own allow and block rules: policy, not a viewing record"


def classify(name: str, entries: tuple[tuple[str, str, str], ...]) -> tuple[str, str] | None:
    """(policy, why) for a first path component, or None when no entry names it."""
    for pattern, policy, why in entries:
        if fnmatch.fnmatchcase(name, pattern):
            return policy, why
    return None


@dataclass
class Step:
    """One thing forget does or would do: what (a table or a path), how many rows or files, bytes."""

    action: str  # delete-rows | empty | delete | keep | unclassified | backup
    what: str
    count: int = 0
    size: int = 0
    why: str = ""


@dataclass
class Result:
    steps: list[Step] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)
    residue: list[str] = field(default_factory=list)


def log_dir(s) -> str:
    return os.path.dirname(s.flows_log)


def _size(path: str) -> int:
    try:
        return os.path.getsize(path)
    except OSError:
        return 0


def _tree(path: str) -> tuple[int, int]:
    """(files, bytes) under `path`, a file or a directory."""
    if os.path.isfile(path):
        return 1, _size(path)
    n = size = 0
    for root, _dirs, files in os.walk(path):
        for f in files:
            n, size = n + 1, size + _size(os.path.join(root, f))
    return n, size


# ---- planning: what would go ------------------------------------------------------------------------
def plan_store(conn: sqlite3.Connection) -> list[Step]:
    steps = []
    tables = [
        r[0]
        for r in conn.execute(
            "SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%' ORDER BY name"
        )
    ]
    for t in tables:
        policy = TABLES.get(t)
        if policy is None:
            steps.append(Step("unclassified", t, why="a table forget does not know: kept"))
            continue
        n = conn.execute(f"SELECT COUNT(*) FROM {t}").fetchone()[0]
        steps.append(Step("delete-rows" if policy[0] == FORGET else "keep", t, n, why=policy[1]))
    return steps


def plan_files(s, live: set[str] | None, querylog: bool = False) -> list[Step]:
    """Every entry of the state and log directories with what forget does to it, plus the pcap and
    report directories and the TV readings wherever the settings put them. `live` is the set of
    realpaths the capture holds open (None: unknown, so no pcap is touched)."""
    steps: list[Step] = []
    seen: set[str] = {os.path.realpath(s.db_path)}  # the store goes row by row (plan_store)
    local = getattr(s, "local_rules", "")
    if local and os.path.isfile(local):  # (site rules) kept, even under the state directory
        seen.add(os.path.realpath(local))
        steps.append(Step("keep", local, *_tree(local), why=LOCAL_RULES_WHY))

    def special(path: str) -> bool:
        real = os.path.realpath(path)
        if real == os.path.realpath(s.pcap_dir):
            steps.extend(_plan_pcaps(path, live))
        elif real == os.path.realpath(s.reports_dir):
            steps.extend(_plan_reports(path))
        else:
            return False
        return True

    dirs = [(s.state_dir, STATE_ENTRIES), (log_dir(s), LOG_ENTRIES)]
    if os.path.dirname(s.gfts_log) != log_dir(s):
        dirs.append((os.path.dirname(s.gfts_log), LOG_ENTRIES))
    for directory, entries in dirs:
        try:
            names = sorted(os.listdir(directory))
        except FileNotFoundError:
            continue
        for name in names:
            path = os.path.join(directory, name)
            if os.path.realpath(path) in seen:
                continue
            seen.add(os.path.realpath(path))
            got = classify(name, entries)
            if got is None:
                steps.append(Step("unclassified", path, *_tree(path), why="not classified: kept"))
                continue
            policy, why = got
            if policy == KEEP:
                steps.append(Step("keep", path, *_tree(path), why=why))
            elif special(path):
                pass
            elif _is_live_log(name, path, s):
                steps.append(Step("empty", path, 1, _size(path), why))
            else:
                steps.append(Step("delete", path, *_tree(path), why=why))
    # the same trees where the settings put them outside the state directory (a test tree, a moved dir)
    for path in (s.pcap_dir, s.reports_dir):
        if os.path.isdir(path) and os.path.realpath(path) not in seen:
            seen.add(os.path.realpath(path))
            special(path)
    for path, why in (
        (s.tvcheck_history, "one power and app line an hour"),
        (s.tvcheck_txt, "the last reading"),
    ):
        if os.path.isfile(path) and os.path.realpath(path) not in seen:
            seen.add(os.path.realpath(path))
            steps.append(Step("empty" if path == s.tvcheck_history else "delete", path, 1, _size(path), why))
    if querylog:
        for path in (s.adguard_querylog, s.adguard_querylog + ".1"):
            if os.path.exists(path):
                act = "empty" if path == s.adguard_querylog else "delete"
                steps.append(Step(act, path, 1, _size(path), "AdGuard's query log (--querylog)"))
    return steps


def _is_live_log(name: str, path: str, s) -> bool:
    """A log a running writer appends to: emptied in place, never unlinked, or the writer would go on
    writing into a file nobody can open (conntrack's redirect, nginx, tvgw-analyze's `>>`). The live
    reading's attempts file too: its writers count only in a file that is there."""
    return os.path.isfile(path) and (name.endswith(".log") or name == ATTEMPTS or path == s.tvcheck_history)


def _plan_pcaps(pcap_dir: str, live: set[str] | None) -> list[Step]:
    if live is None:
        return [Step("keep", pcap_dir, *_tree(pcap_dir), why="cannot tell which file the capture writes")]
    steps = []
    for name in sorted(os.listdir(pcap_dir)):
        path = os.path.join(pcap_dir, name)
        if os.path.realpath(path) in live:
            steps.append(Step("keep", path, 1, _size(path), "the file the capture is writing"))
        elif os.path.isfile(path):
            steps.append(Step("delete", path, 1, _size(path), "a capture"))
    return steps


def _plan_reports(reports: str) -> list[Step]:
    steps = []
    for root, _dirs, files in os.walk(reports):
        for f in sorted(files):
            path = os.path.join(root, f)
            if root == reports and f in REPORTS_KEEP:
                continue
            steps.append(Step("delete", path, 1, _size(path), "a report, proposal or pack"))
    return steps


# ---- the run -----------------------------------------------------------------------------------------
def run(
    s,
    *,
    dry_run: bool = False,
    querylog: bool = False,
    live: Callable[[str], set[str] | None] = pcaps.live_files,
    backup: Callable[[str, str], object] | None = None,
    lock: bool = True,
    now: Callable[[], float] | None = None,  # time.time, read at the call (the tests pin it)
) -> Result:
    """Forget, or with `dry_run` only say what would go. Holds the ingest lock for the whole run, so
    no ingest writes between the store and the files. `backup(db_path, backup_dir)` makes the one
    fresh copy afterwards (`backup.run` by default)."""
    out = Result()
    lock_fh = None
    if lock and not dry_run:
        os.makedirs(s.state_dir, exist_ok=True)
        lock_path = os.path.join(s.state_dir, ".ingest.lock")
        lock_fh = open(lock_path, "a", encoding="utf-8")  # noqa: SIM115 - held to the end
        with contextlib.suppress(OSError):
            os.chmod(lock_path, 0o600)  # as ingest.run leaves it
        fcntl.flock(lock_fh, fcntl.LOCK_EX)
    try:
        held = live(s.pcap_dir) if os.path.isdir(s.pcap_dir) else set()
        if held is None:
            out.warnings.append("pcaps: cannot tell which file the capture writes (needs root); none deleted")
        conn = db.connect(s.db_path, readonly=dry_run) if os.path.exists(s.db_path) else None
        try:
            if conn is not None:
                out.steps.extend(plan_store(conn))
            out.steps.extend(plan_files(s, held, querylog))
            if not dry_run:
                if conn is not None:
                    _forget_store(conn, s, (now or time.time)(), querylog, out)
                _forget_files(s, out)
        finally:
            if conn is not None:
                conn.close()
        if not dry_run:
            _fresh_backup(s, backup, out)
    finally:
        if lock_fh:
            lock_fh.close()
    out.residue = residue(s, querylog, held)
    return out


def _forget_store(conn: sqlite3.Connection, s, t: float, querylog: bool, out: Result) -> None:
    """Every forgotten table emptied with secure_delete on, in one transaction with the floor and the
    cursor resets; then VACUUM when the card has room for it, and an integrity check."""
    from tvgw import autoblock

    conn.execute("PRAGMA secure_delete=ON")  # deleted content is overwritten with zeros, not just freed
    owed = autoblock.owed_push_id(conn) is not None
    with conn:
        for table, (policy, _why) in TABLES.items():
            if policy == FORGET and _exists(conn, table):
                conn.execute(f"DELETE FROM {table}")
        if owed:  # (fin-release) a revert still owed to AdGuard stays owed, under no name, at the floor
            conn.execute(
                "INSERT INTO decisions(t, stage, outcome, reason) VALUES (?, 'apply', ?, ?)",
                (t, autoblock.DEFERRED, "an owed re-apply, kept across tvgw forget"),
            )
        conn.executemany("DELETE FROM meta WHERE key=?", [(k,) for k in META_FORGET])
        db.set_meta(conn, FLOOR_KEY, repr(t))
        cursors = (*CURSORS, QUERYLOG_CURSOR) if querylog else CURSORS
        conn.executemany("DELETE FROM ingest_state WHERE source=?", [(c,) for c in cursors])
    size = _size(s.db_path)
    try:
        st = os.statvfs(os.path.dirname(os.path.abspath(s.db_path)))
        room = st.f_bavail * st.f_frsize
    except OSError:
        room = 0
    if room > 2 * size:  # VACUUM writes a whole copy, and the rollback journal beside it
        conn.execute("VACUUM")
    else:
        out.warnings.append(
            f"store: VACUUM skipped, {room // 2**20} MB free for a {size // 2**20} MB file; the deleted rows"
            " are zeroed in place and the file shrinks at the next 30-day check"
        )
    verdict = [r[0] for r in conn.execute("PRAGMA integrity_check")]
    if verdict != ["ok"]:
        out.warnings.append("store: integrity_check after forget: " + "; ".join(verdict)[:200])


def _exists(conn: sqlite3.Connection, table: str) -> bool:
    return (
        conn.execute("SELECT 1 FROM sqlite_master WHERE type='table' AND name=?", (table,)).fetchone()
        is not None
    )


def _forget_files(s, out: Result) -> None:
    for step in out.steps:
        if step.action not in ("empty", "delete") or step.what == s.db_path:
            continue
        try:
            if step.action == "empty":
                _empty(step.what)
            elif os.path.isdir(step.what) and not os.path.islink(step.what):
                if os.path.realpath(step.what) == os.path.realpath(os.path.join(s.state_dir, "backup")):
                    for f in os.listdir(step.what):  # the directory stays, with its group and mode
                        _unlink(os.path.join(step.what, f))
                else:
                    shutil.rmtree(step.what)
            else:
                _unlink(step.what)
        except OSError as e:
            out.warnings.append(f"{step.what}: {e.strerror or e}")


def _empty(path: str) -> None:
    """Truncate in place under an exclusive lock: the live reading's attempts file is rewritten under its
    writer's lock, which would otherwise put the forgotten lines back between its read and its write."""
    fd = os.open(path, os.O_WRONLY)
    try:
        fcntl.flock(fd, fcntl.LOCK_EX)
        os.ftruncate(fd, 0)
    finally:
        os.close(fd)


def _unlink(path: str) -> None:
    if os.path.isdir(path) and not os.path.islink(path):
        shutil.rmtree(path)
    else:
        with contextlib.suppress(FileNotFoundError):
            os.unlink(path)


def _fresh_backup(s, backup: Callable[[str, str], object] | None, out: Result) -> None:
    """One copy of the store as it now is, so the daily copy and its check do not wait a day; then any
    copy a backup run made meanwhile from the store before the forget goes too."""
    if not os.path.exists(s.db_path):
        return
    if backup is None:
        from tvgw import backup as backup_mod

        def backup(db_path: str, backup_dir: str) -> object:
            return backup_mod.run(db_path, backup_dir)

    backup_dir = os.path.join(s.state_dir, "backup")
    try:
        made = backup(s.db_path, backup_dir)
    except (OSError, sqlite3.Error, RuntimeError, ValueError) as e:
        out.warnings.append(f"backup: no fresh copy: {e}")
        return
    keep = os.path.basename(getattr(made, "path", "") or "")
    for f in os.listdir(backup_dir):
        if f != keep:
            _unlink(os.path.join(backup_dir, f))
    out.steps.append(Step("backup", os.path.join(backup_dir, keep), 1, _size(os.path.join(backup_dir, keep))))


# ---- after the run -----------------------------------------------------------------------------------
def drop_late(conn: sqlite3.Connection, now: float | None = None) -> int:
    """Delete any row older than the last forget: late evidence (an idle connection's report, the
    capture's open file, AdGuard's buffered lookups) of the time the owner asked to forget. A no-op
    on a store that was never forgotten; LATE_DAYS after the forget the floor is removed and it is a
    no-op again. Each predicate can use its table's time index. The caller commits."""
    floor = db.get_meta(conn, FLOOR_KEY)
    if not floor:
        return 0
    t = float(floor)
    if (time.time() if now is None else now) - t > LATE_DAYS * 86400:
        conn.execute("DELETE FROM meta WHERE key=?", (FLOOR_KEY,))
        return 0
    before = conn.execute("PRAGMA secure_delete").fetchone()[0]
    conn.execute("PRAGMA secure_delete=ON")  # the late rows are zeroed like the ones forget deleted
    n = 0
    try:
        for table, col in TIME_COLUMNS.items():
            if not _exists(conn, table):
                continue
            if isinstance(col, tuple):
                first, fallback = col
                where, args = f"{first} < ? OR ({first} IS NULL AND {fallback} < ?)", (t, t)
            else:
                where, args = f"{col} < ?", (t,)
            n += conn.execute(f"DELETE FROM {table} WHERE {where}", args).rowcount
    finally:
        # the prune that follows in the same ingest frees its rows the ordinary way
        conn.execute(f"PRAGMA secure_delete={int(before)}")
    return n


def residue(s, querylog: bool = False, live: set[str] | None = frozenset()) -> list[str]:
    """What tvgw cannot reach, each with how long it lasts: printed on every run, dry or not."""
    days = getattr(s, "journal_days", "14")
    out = [
        f"the systemd journal: kernel log lines and dnsmasq's DHCP lines, kept {days} days by"
        " /etc/systemd/journald.conf.d/60-tvgw.conf (JOURNAL_DAYS); journald cannot delete chosen"
        " entries, and `journalctl --vacuum-time` removes every service's history",
        "AdGuard Home's statistics (top names and clients), until its own interval",
        "copies pulled to a workstation with `make backup`: delete them there",
        "(evidence, requests) copies of the evidence file or the request drafts made by hand, and drafts"
        " `tvgw requests --draft --out` wrote outside the state directory: delete them there",
        "the analyst's requests at Anthropic: 30 days on the standard API, at least 30 days on a"
        " Covered Model such as claude-fable-5-1, 29 days for a Message Batch",
        "GitHub Actions logs of the hardware job, if a failing test quoted a live value",
        "the card's freed blocks, the rollback journal's among them: flash keeps what was overwritten"
        " until it reuses the block, and only encryption from the start allows a reliable erase",
    ]
    if not querylog:
        out.insert(1, "AdGuard Home's query log: run again with --querylog to empty it")
    if live is None:
        out.append("the pcaps: which file the capture writes could not be told, so none was deleted")
    elif live:
        out.append("the capture's open file: up to an hour before now; ingest drops its rows")
    return out
