"""Ingest behaviours the first suite never pinned: persisted keys, cursors, limits, boundaries, locking."""

import fcntl
import json
import os
import time
from datetime import UTC, datetime
from pathlib import Path

import pytest
from conftest import GFTS_TV_ALLOWED, ODDPORT_LINE, TV, fake_extract, fake_oddport

from tvgw import db, ingest
from tvgw.adguard import parse_time
from tvgw.tshark import HttpRequest, TlsHello

pytestmark = pytest.mark.usefixtures("clock")  # every test here runs at a fixed "now"

NOW = 1793026800.0  # 2026-10-26 10:00 CDT: after every timestamp in the fake gateway
DAY = 86400.0


def local(stamp: str) -> float:
    """Epoch of a Chicago wall-clock time written with its explicit offset (host TZ independent)."""
    return parse_time(stamp)


@pytest.fixture()
def clock(monkeypatch):
    """Freeze time.time(): ingest stamps rows, rule history, last_run and the prune cutoff with it."""

    class Clock:
        now = NOW

        def __call__(self):
            return self.now

    c = Clock()
    monkeypatch.setattr(time, "time", c)
    return c


# ---- the hourly run -----------------------------------------------------------------------------
def test_run_persists_cursors_meta_and_timing(gateway, lg, clock):
    def slow_extract(pcap):
        clock.now += 5  # tshark took five seconds
        return fake_extract(pcap)

    st = ingest.run(gateway, lg, extract=slow_extract, oddport_lines=fake_oddport, lock=False)
    assert st.seconds == 5.0 and st.pruned == 0
    conn = db.connect(gateway.db_path, readonly=True)
    assert db.get_meta(conn, "last_run") == str(NOW) and db.get_meta(conn, "schema") == "1"
    cursors = {r[0]: r[1:] for r in conn.execute("SELECT source, inode, offset, last_t FROM ingest_state")}
    # these source names are a persisted contract: renaming one makes the next run re-read the whole log
    assert set(cursors) == {"flows", "adguard", "gfts", "tvstate", "oddport"}
    for source in ("flows", "adguard", "gfts", "tvstate"):
        inode, offset, last_t = cursors[source]
        assert inode and offset > 0 and last_t in (NOW, NOW + 5)
    assert cursors["oddport"][2] == 1793020200.123456  # the journal cursor is the newest event time


def test_default_run_takes_the_exclusive_lock(gateway, lg, monkeypatch):
    calls = []
    real_flock = fcntl.flock

    def spy(fh, op):
        calls.append((os.path.basename(fh.name), op))
        return real_flock(fh, op)

    monkeypatch.setattr(fcntl, "flock", spy)
    ingest.run(gateway, lg, extract=fake_extract, oddport_lines=fake_oddport)  # lock defaults to on
    assert calls == [(".ingest.lock", fcntl.LOCK_EX)]
    assert (Path(gateway.state_dir) / ".ingest.lock").exists()


@pytest.mark.xfail(strict=True, reason="refresh_hosts adds the overlap hour twice (see report)")
def test_second_run_inside_the_overlap_window_does_not_inflate_host_counters(gateway, lg, clock):
    """refresh_hosts re-reads the last hour and ADDS its counts: a second run doubles them."""
    ingest.run(gateway, lg, extract=fake_extract, oddport_lines=fake_oddport, lock=False)
    conn = db.connect(gateway.db_path, readonly=True)
    q = "SELECT name, dns_n, tls_n, http_n FROM hosts ORDER BY name"
    first = conn.execute(q).fetchall()
    clock.now += 60
    ingest.run(gateway, lg, extract=fake_extract, oddport_lines=fake_oddport, lock=False)
    assert conn.execute(q).fetchall() == first


def test_rows_stamped_before_the_previous_run_still_reach_the_hosts_table(gateway, lg, clock):
    """refresh_hosts looks back an hour from the last run, so a late flushed record is not missed."""

    def dns_line(name, t):
        iso = datetime.fromtimestamp(t, UTC).strftime("%Y-%m-%dT%H:%M:%SZ")
        return json.dumps({"T": iso, "QH": name, "QT": "A", "IP": TV, "Result": {}}) + "\n"

    ingest.run(gateway, lg, extract=fake_extract, oddport_lines=fake_oddport, lock=False)
    clock.now += 60
    with open(gateway.adguard_querylog, "a") as fh:
        fh.write(
            f'4:40Z","QH":"filler.example","QT":"A","IP":"{TV}","Result":{{}}}}\n'
        )  # completes the fixture's half line
        fh.write(dns_line("late.example", NOW - 1800) + dns_line("after.example", NOW + 30))
    ingest.run(gateway, lg, extract=fake_extract, oddport_lines=fake_oddport, lock=False)
    conn = db.connect(gateway.db_path, readonly=True)
    assert {"late.example", "after.example"} <= {r[0] for r in conn.execute("SELECT name FROM hosts")}


# ---- pcaps ------------------------------------------------------------------------------------
def test_pcaps_are_extracted_once_failures_do_not_block_later_files(gateway, lg):
    pcaps = Path(gateway.pcap_dir)
    for f in pcaps.iterdir():
        f.unlink()
    for n in (1, 2, 3, 4):  # 1 already done, 2 fails first time, 3 fine, 4 is still being written
        (pcaps / f"tv-{n}.pcap").write_bytes(b"x")
    conn = db.connect(gateway.db_path)
    conn.execute("INSERT INTO pcaps_done(name, done_at, tls_rows, http_rows) VALUES ('tv-1.pcap', 1, 0, 0)")
    long_http = HttpRequest(1793020102.0, TV, "1.2.3.4", "GET", "h.example", "/" + "u" * 2500, "a" * 400)
    calls, warnings, broken = [], [], {"tv-2.pcap"}

    def extract(path):
        name = os.path.basename(path)
        calls.append(name)
        if name in broken:
            raise RuntimeError("tshark rc=1")
        return [TlsHello(1793020100.0, TV, 40001, "1.2.3.4", 443, "h.example"), long_http]

    assert ingest.ingest_pcaps(conn, gateway, extract, warnings.append) == (1, 1, 1)
    assert calls == ["tv-2.pcap", "tv-3.pcap"] and len(warnings) == 1 and "tv-2.pcap" in warnings[0]
    broken.clear()
    assert ingest.ingest_pcaps(conn, gateway, extract, warnings.append) == (1, 1, 1)
    assert calls == ["tv-2.pcap", "tv-3.pcap", "tv-2.pcap"]  # only the previously failed one was retried
    done = conn.execute("SELECT name, tls_rows, http_rows FROM pcaps_done ORDER BY name").fetchall()
    assert done == [("tv-1.pcap", 0, 0), ("tv-2.pcap", 1, 1), ("tv-3.pcap", 1, 1)]
    method, src, n_uri, n_ua = conn.execute(
        "SELECT method, src, length(uri), length(ua) FROM http"
    ).fetchone()
    assert (method, src, n_uri, n_ua) == ("GET", "pcap", 2000, 300)  # long fields are cut, not rejected


def test_gfts_rows_are_get_requests_and_long_fields_are_cut(gateway, lg):
    long_line = GFTS_TV_ALLOWED.replace('"/fts/', '"/fts/' + "p" * 2500 + "/").replace(
        '"-"', '"' + "u" * 400 + '"'
    )
    with open(gateway.gfts_log, "a") as fh:
        fh.write(long_line)
    ingest.run(gateway, lg, extract=fake_extract, oddport_lines=fake_oddport, lock=False)
    conn = db.connect(gateway.db_path, readonly=True)
    row = conn.execute(
        "SELECT method, src, length(uri), length(ua), status, bytes FROM http WHERE length(uri) > 100"
    )
    assert row.fetchall() == [("GET", "gfts", 2000, 300, 200, 6488)]


# ---- oddport journal --------------------------------------------------------------------------
def test_oddport_cursor_and_unparseable_lines():
    conn = db.connect(":memory:")
    long_tail = "1793020400.0 kernel: tvgw-oddport: " + "x" * 500 + " DST=1.2.3.4 PROTO=UDP DPT=99"
    batches = [
        [
            "junk without a timestamp",
            ODDPORT_LINE,
            "1793020300.5 kernel: tvgw-oddport: no addresses here",
            long_tail,
        ],
        [],
    ]
    since_seen = []

    def journal(since):
        since_seen.append(since)
        return batches.pop(0)

    assert ingest.ingest_oddport(conn, journal) == 3  # the junk line does not stop the ones after it
    rows = conn.execute("SELECT t, proto, dst, dport, length(raw) FROM oddport ORDER BY t").fetchall()
    assert rows == [
        (1793020200.123456, "TCP", "156.147.69.32", 8080, len(ODDPORT_LINE)),
        (1793020300.5, None, None, None, len("1793020300.5 kernel: tvgw-oddport: no addresses here")),
        (1793020400.0, "UDP", "1.2.3.4", 99, 400),
    ]
    assert conn.execute("SELECT raw FROM oddport WHERE dport=99").fetchone()[0] == long_tail[-400:]
    assert ingest.ingest_oddport(conn, journal) == 0
    assert since_seen == [
        "-30d",
        "@1793020401",
    ]  # first run looks back 30 days, then resumes after the last event
    assert conn.execute("SELECT last_t FROM ingest_state WHERE source='oddport'").fetchone() == (
        1793020400.0,
    )


@pytest.mark.parametrize("exc", [OSError("no journalctl"), __import__("subprocess").TimeoutExpired("j", 60)])
def test_oddport_journal_failure_is_not_fatal(exc):
    def journal(since):
        raise exc

    conn = db.connect(":memory:")
    assert ingest.ingest_oddport(conn, journal) == 0
    assert conn.execute("SELECT COUNT(*) FROM ingest_state").fetchone()[0] == 0


@pytest.mark.xfail(strict=True, reason="int(last_t)+1 drops events that share the last event's second")
def test_oddport_events_in_the_same_second_are_not_lost():
    conn = db.connect(":memory:")
    first = "1793020300.100 kernel: tvgw-oddport: DST=1.1.1.1 PROTO=TCP DPT=1"
    second = "1793020300.900 kernel: tvgw-oddport: DST=2.2.2.2 PROTO=TCP DPT=2"
    log = [first]

    def journal(since):  # like journalctl: whole-second cursor, inclusive
        cut = 0.0 if since.startswith("-") else float(since[1:])
        return [ln for ln in log if float(ln.split()[0]) >= cut]

    ingest.ingest_oddport(conn, journal)
    log.append(second)
    ingest.ingest_oddport(conn, journal)
    assert conn.execute("SELECT COUNT(*) FROM oddport").fetchone()[0] == 2


# ---- tv state / settings ---------------------------------------------------------------------------
def test_tvstate_history_skips_bad_lines_and_keeps_multiword_apps(gateway):
    Path(gateway.tvcheck_history).write_text(
        "too short\n"
        "not-a-date 09:19 Active x\n"
        "2026-10-26 08:20 unreachable\n"
        "2026-10-26 09:19 Active com.webos.app.home extra words\n"
    )
    conn = db.connect(gateway.db_path)
    assert ingest.ingest_tvstate(conn, gateway) == 2
    assert conn.execute("SELECT t, power, app FROM tvstate ORDER BY t").fetchall() == [
        (local("2026-10-26T08:20:00-05:00"), "unreachable", None),
        (local("2026-10-26T09:19:00-05:00"), "Active", "com.webos.app.home extra words"),
    ]


def test_tvsettings_parsing_edge_cases(gateway):
    Path(gateway.tvcheck_txt).write_text(
        "read 2026-10-26 09:19\n"
        "option.a = 1\n"
        "line without separator\n"
        "power = Active\n"
        "option.b = x = y\n"
        "app = home\n"
        "option.c = 3\n"
    )
    conn = db.connect(gateway.db_path)
    ingest.ingest_tvstate(conn, gateway)
    t = local("2026-10-26T09:19:00-05:00")
    assert conn.execute("SELECT t, key, value FROM tvsettings ORDER BY key").fetchall() == [
        (t, "option.a", "1"),
        (t, "option.b", "x = y"),
        (t, "option.c", "3"),
    ]


@pytest.mark.parametrize("text", ["", "no read header\noption.a = 1\n", "read yesterday\noption.a = 1\n"])
def test_unusable_tvcheck_txt_records_nothing(gateway, text):
    Path(gateway.tvcheck_txt).write_text(text)
    conn = db.connect(gateway.db_path)
    ingest.ingest_tvstate(conn, gateway)
    assert conn.execute("SELECT COUNT(*) FROM tvsettings").fetchone()[0] == 0


# ---- policy history ---------------------------------------------------------------------------------
def test_current_rules_kinds_are_stable_and_missing_files_are_tolerated(gateway):
    assert ingest.current_rules(gateway) == {
        ("adguard", "@@||us.lgtvsdp.com^"),
        ("adguard", "||alphonso.tv^"),
        ("adguard", "||ngfts.lge.com^$dnsrewrite=10.10.10.1"),
        ("gfts-block", "biz_code=(PREMIUM|CDP|LGSHOPPING|MAS|IBS)([&_]|$)"),
        ("block4", "203.0.113.9"),
    }
    os.remove(gateway.nginx_conf)
    assert ("block4", "203.0.113.9") in ingest.current_rules(
        gateway
    )  # one missing file must not hide the rest
    os.remove(gateway.block4)
    os.remove(gateway.adguard_yaml)
    assert ingest.current_rules(gateway) == set()


def test_rule_history_timestamps_and_multiple_removals(tmp_path):
    conn = db.connect(str(tmp_path / "r.db"))
    a, b = ("adguard", "||a^"), ("adguard", "||b^")
    assert ingest.ingest_rules(conn, {a, b}, now=100.0) == (2, 0)
    assert ingest.ingest_rules(conn, {a, b}, now=200.0) == (0, 0)
    assert ingest.ingest_rules(conn, set(), now=300.0) == (0, 2)
    q = "SELECT kind, text, first_seen, last_seen, removed_at FROM rules ORDER BY text, id"
    assert conn.execute(q).fetchall() == [
        ("adguard", "||a^", 100.0, 200.0, 300.0),
        ("adguard", "||b^", 100.0, 200.0, 300.0),
    ]
    assert ingest.ingest_rules(conn, {a}, now=400.0) == (
        1,
        0,
    )  # a removed rule that returns is a new history row
    assert conn.execute("SELECT COUNT(*) FROM rules WHERE text='||a^'").fetchone()[0] == 2


# ---- hosts dimension -------------------------------------------------------------------------------
def test_refresh_hosts_merges_the_three_tables(tmp_path, lg):
    conn = db.connect(str(tmp_path / "h.db"))
    conn.executemany(
        "INSERT INTO dns(t, qname, blocked, rule) VALUES (?,?,?,?)",
        [(200.0, "x.lgtvsdp.com", 0, "@@a"), (300.0, "x.lgtvsdp.com", 1, "||b^"), (250.0, "", 0, None)],
    )
    conn.execute(
        "INSERT INTO tls(t, dst, dport, sport, sni) VALUES (100.0, '1.1.1.1', 443, 1, 'x.lgtvsdp.com')"
    )
    conn.execute(
        "INSERT INTO http(t, host, method, uri, ua, status, bytes, src) VALUES "
        "(400.0, 'x.lgtvsdp.com', 'GET', '/', 'u', 200, 1, 'gfts')"
    )
    assert ingest.refresh_hosts(conn, lg, since=0) == 1  # the empty qname is ignored
    q = "SELECT first_seen, last_seen, category, dns_n, tls_n, http_n, last_blocked, last_rule FROM hosts"
    assert conn.execute(q).fetchall() == [(100.0, 400.0, "LG core", 2, 1, 1, 1, "||b^")]


# ---- retention --------------------------------------------------------------------------------------
def test_prune_cutoffs_per_table(tmp_path):
    conn = db.connect(str(tmp_path / "p.db"))
    now, cutoff = 1_800_000_000.0, 1_800_000_000.0 - 10 * DAY
    for old, new in ((cutoff - 1, cutoff + 1),):
        conn.executemany("INSERT INTO flows(t_end, dst) VALUES (?, 'd')", [(old,), (new,)])
        conn.executemany("INSERT INTO dns(t, qname, blocked) VALUES (?, 'q', 0)", [(old,), (new,)])
        conn.executemany("INSERT INTO tls(t, sni) VALUES (?, 's')", [(old,), (new,)])
        conn.executemany("INSERT INTO http(t, host, src) VALUES (?, 'h', 'pcap')", [(old,), (new,)])
        conn.executemany("INSERT INTO oddport(t) VALUES (?)", [(old,), (new,)])
    done_cut = now - 30 * DAY
    conn.executemany(
        "INSERT INTO pcaps_done(name, done_at) VALUES (?, ?)",
        [("old", done_cut - 10), ("new", done_cut + 10)],
    )
    assert ingest.prune(conn, days=10, now=now) == 5  # one stale row in each of five tables
    for table in ("flows", "dns", "tls", "http", "oddport"):
        assert conn.execute(f"SELECT COUNT(*) FROM {table}").fetchone()[0] == 1, table
    assert conn.execute("SELECT name FROM pcaps_done").fetchall() == [("new",)]


def test_vacuum_runs_at_most_every_thirty_days(tmp_path):
    conn = db.connect(str(tmp_path / "v.db"))
    stmts: list[str] = []
    conn.set_trace_callback(stmts.append)
    now = 1_800_000_000.0

    def vacuums():
        return sum(s.strip().upper() == "VACUUM" for s in stmts)

    ingest.prune(conn, 10, now)
    assert vacuums() == 1 and db.get_meta(conn, "last_vacuum") == str(now)
    ingest.prune(conn, 10, now + 29 * DAY)
    assert vacuums() == 1
    ingest.prune(conn, 10, now + 30 * DAY)  # exactly thirty days is not yet "older than thirty days"
    assert vacuums() == 1
    ingest.prune(conn, 10, now + 30 * DAY + 10)
    assert vacuums() == 2
