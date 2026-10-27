"""Ingest behaviours the first suite never pinned: persisted keys, cursors, limits, boundaries, locking."""

import fcntl
import json
import os
import subprocess
import time
from datetime import UTC, datetime
from pathlib import Path

import pytest
from conftest import EMPTY_PCAP, FLOW_TCP, GFTS_TV_ALLOWED, ODDPORT_LINE, TV, fake_extract, fake_oddport

from tvgw import db, ingest, queries
from tvgw.adguard import parse_time
from tvgw.tshark import HttpRequest, Syn, TlsHello

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
    assert db.get_meta(conn, "last_run") == str(NOW) and db.get_meta(conn, "schema") == "3"
    cursors = {r[0]: r[1:] for r in conn.execute("SELECT source, inode, offset, last_t FROM ingest_state")}
    # these source names are a persisted contract: renaming one makes the next run re-read the whole log
    assert set(cursors) == {"flows", "adguard", "gfts", "tvstate", "oddport"}
    for source in ("flows", "adguard", "gfts", "tvstate"):
        inode, offset, last_t = cursors[source]
        assert inode and offset > 0 and last_t in (NOW, NOW + 5)
    assert cursors["oddport"][2] == 1793020200.123456  # the journal cursor is the newest event time
    # the run's bookkeeping: which sources were read when, and what went wrong (nothing, here)
    assert json.loads(db.get_meta(conn, "last_warnings")) == []
    assert json.loads(db.get_meta(conn, "sources_read")) == {k: NOW for k in ingest.SOURCES}
    assert set(json.loads(db.get_meta(conn, "hosts_wm"))) == {"dns", "tls", "http"}


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


def test_second_run_does_not_inflate_host_counters(gateway, lg, clock):
    """Counters advance by row-id watermark: a row is counted once, however often the run repeats."""
    ingest.run(gateway, lg, extract=fake_extract, oddport_lines=fake_oddport, lock=False)
    conn = db.connect(gateway.db_path, readonly=True)
    q = "SELECT name, dns_n, tls_n, http_n FROM hosts ORDER BY name"
    first = conn.execute(q).fetchall()
    clock.now += 60
    ingest.run(gateway, lg, extract=fake_extract, oddport_lines=fake_oddport, lock=False)
    assert conn.execute(q).fetchall() == first


def test_rows_stamped_before_the_previous_run_still_reach_the_hosts_table(gateway, lg, clock):
    """The watermark is a row id, not a time, so a late-flushed record stamped earlier is not missed."""

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


# ---- batches ------------------------------------------------------------------------------------
def ten_flows(gateway) -> list[str]:
    lines = [FLOW_TCP.replace("sport=58998", f"sport={1000 + i}") for i in range(10)]
    Path(gateway.flows_log).write_text("".join(lines))
    return lines


def test_a_tail_source_commits_every_batch_with_its_cursor(gateway, monkeypatch):
    """A long backlog (the whole 90-day query log after a lost store) is read in bounded batches, each
    committed with the cursor that covers it, so memory and the write lock are bounded per batch."""
    monkeypatch.setattr(ingest, "BATCH", 3)
    ten_flows(gateway)
    conn = db.connect(gateway.db_path)
    stmts: list[str] = []
    conn.set_trace_callback(stmts.append)
    assert ingest.ingest_flows(conn, gateway, print) == 10
    assert sum(s.strip().upper() == "COMMIT" for s in stmts) >= 4  # 3 + 3 + 3 + 1
    assert conn.execute("SELECT COUNT(*) FROM flows").fetchone() == (10,)
    offset = conn.execute("SELECT offset FROM ingest_state WHERE source='flows'").fetchone()[0]
    assert offset == os.path.getsize(gateway.flows_log)
    assert ingest.ingest_flows(conn, gateway, print) == 0


def test_a_crash_mid_stream_keeps_the_committed_batches_and_resumes_after_them(gateway, lg, monkeypatch):
    monkeypatch.setattr(ingest, "BATCH", 3)
    lines = ten_flows(gateway)
    real_parse, calls, broken = ingest.conntrack.parse_flow, [], [True]

    def parse(line):
        calls.append(line)
        if broken[0] and len(calls) == 8:
            raise RuntimeError("a parser bug")
        return real_parse(line)

    monkeypatch.setattr(ingest.conntrack, "parse_flow", parse)
    st = ingest.run(gateway, lg, extract=fake_extract, oddport_lines=fake_oddport, lock=False)
    assert st.warnings == ["flows: RuntimeError: a parser bug"]
    conn = db.connect(gateway.db_path, readonly=True)
    assert conn.execute("SELECT COUNT(*) FROM flows").fetchone() == (6,)  # batches 1 and 2
    offset = conn.execute("SELECT offset FROM ingest_state WHERE source='flows'").fetchone()[0]
    assert offset == len("".join(lines[:6]).encode())
    broken[0] = False
    st = ingest.run(gateway, lg, extract=fake_extract, oddport_lines=fake_oddport, lock=False)
    assert (st.flows, st.warnings) == (4, [])
    assert conn.execute("SELECT COUNT(DISTINCT sport) FROM flows").fetchone() == (10,)


# ---- pcaps ------------------------------------------------------------------------------------
def test_pcaps_are_extracted_once_failures_do_not_block_later_files(gateway, lg):
    pcaps = Path(gateway.pcap_dir)
    for f in pcaps.iterdir():
        f.unlink()
    for n in (1, 2, 3, 4):  # 1 already done, 2 fails first time, 3 fine, 4 is still being written
        (pcaps / f"tv-{n}.pcap").write_bytes(EMPTY_PCAP)

    def live(_pcap_dir):
        return {os.path.realpath(pcaps / "tv-4.pcap")}

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

    assert ingest.ingest_pcaps(conn, gateway, extract, warnings.append, live) == (1, 1, 1, 0)
    assert calls == ["tv-2.pcap", "tv-3.pcap"] and len(warnings) == 1 and "tv-2.pcap" in warnings[0]
    broken.clear()
    assert ingest.ingest_pcaps(conn, gateway, extract, warnings.append, live) == (1, 1, 1, 0)
    assert calls == ["tv-2.pcap", "tv-3.pcap", "tv-2.pcap"]  # only the previously failed one was retried
    done = conn.execute("SELECT name, tls_rows, http_rows FROM pcaps_done ORDER BY name").fetchall()
    assert done == [("tv-1.pcap", 0, 0), ("tv-2.pcap", 1, 1), ("tv-3.pcap", 1, 1)]
    method, src, n_uri, n_ua = conn.execute(
        "SELECT method, src, length(uri), length(ua) FROM http"
    ).fetchone()
    assert (method, src, n_uri, n_ua) == ("GET", "pcap", 2000, 300)  # long fields are cut, not rejected


def finished_pcaps(gateway, *names: str) -> None:
    """Replace the fixture's pcap directory with `names`, each an empty capture, none of them live."""
    pcaps = Path(gateway.pcap_dir)
    for f in pcaps.iterdir():
        f.unlink()
    for name in names:
        (pcaps / name).write_bytes(EMPTY_PCAP)


def none_live(_pcap_dir):
    return set()


def test_read_failures_are_one_warning_per_run_and_a_bounded_number_per_file(gateway, lg, clock):
    """An environment fault (tshark, setpriv, permissions) shows as one line per hour while it lasts;
    after PCAP_MAX_ATTEMPTS a file is recorded as unreadable and neither read nor nagged about again."""
    finished_pcaps(gateway, "tv-1.pcap", "tv-2.pcap", "tv-3.pcap")
    conn = db.connect(gateway.db_path)
    calls, warnings = [], []

    def broken(path):
        calls.append(os.path.basename(path))
        raise RuntimeError("tshark rc=1: boom")

    for attempt in range(1, ingest.PCAP_MAX_ATTEMPTS + 1):
        warnings.clear()
        assert ingest.ingest_pcaps(conn, gateway, broken, warnings.append, none_live) == (0, 0, 0, 0)
        if attempt < ingest.PCAP_MAX_ATTEMPTS:
            assert warnings == [
                "3 pcap(s) could not be read (tv-1.pcap: tshark rc=1: boom); will retry next run"
            ]
        clock.now += 3600
    assert sorted(warnings) == [
        f"tv-{n}.pcap: tshark rc=1: boom; recorded as unreadable after 24 attempts" for n in (1, 2, 3)
    ]
    marks = conn.execute(
        "SELECT name, error, attempts, done_at, tls_rows FROM pcaps_done ORDER BY name"
    ).fetchall()
    assert marks == [(f"tv-{n}.pcap", "tshark rc=1: boom", 24, NOW + 23 * 3600, 0) for n in (1, 2, 3)]
    assert len(calls) == 3 * ingest.PCAP_MAX_ATTEMPTS
    warnings.clear()
    assert ingest.ingest_pcaps(conn, gateway, broken, warnings.append, none_live) == (0, 0, 0, 0)
    assert len(calls) == 3 * ingest.PCAP_MAX_ATTEMPTS and warnings == []


def test_a_file_too_short_to_be_a_capture_is_recorded_without_asking_tshark(gateway, lg):
    finished_pcaps(gateway, "tv-1.pcap")
    (Path(gateway.pcap_dir) / "tv-1.pcap").write_bytes(EMPTY_PCAP[:10])
    conn = db.connect(gateway.db_path)
    warnings = []

    def extract(path):
        raise AssertionError("tshark must not be asked to read what was never a capture")

    assert ingest.ingest_pcaps(conn, gateway, extract, warnings.append, none_live) == (0, 0, 0, 0)
    assert warnings == ["tv-1.pcap: not a capture file (10 bytes)"]
    marks = conn.execute(
        "SELECT error, attempts, tls_rows, http_rows, syn443_rows FROM pcaps_done"
    ).fetchall()
    assert marks == [("not a capture file (10 bytes)", ingest.PCAP_MAX_ATTEMPTS, 0, 0, 0)]
    warnings.clear()
    assert ingest.ingest_pcaps(conn, gateway, extract, warnings.append, none_live) == (0, 0, 0, 0)
    assert warnings == []


def test_a_file_that_fails_twice_then_reads_keeps_its_attempt_count_and_no_error(gateway, lg):
    finished_pcaps(gateway, "tv-1.pcap")
    conn = db.connect(gateway.db_path)
    outcomes = [
        RuntimeError("tshark rc=1"),
        OSError("busy"),
        [TlsHello(1793020100.0, TV, 40001, "1.2.3.4", 443, "h.example")],
    ]
    warnings = []

    def extract(path):
        outcome = outcomes.pop(0)
        if isinstance(outcome, Exception):
            raise outcome
        return outcome

    for _ in range(3):
        ingest.ingest_pcaps(conn, gateway, extract, warnings.append, none_live)
    assert conn.execute("SELECT error, attempts, tls_rows, syn443_rows FROM pcaps_done").fetchall() == [
        (None, 2, 1, 0)
    ]
    assert len(warnings) == 2 and all("will retry" in w for w in warnings)


def test_pcaps_past_the_time_budget_wait_for_the_next_run(gateway, lg):
    """A backlog of slow files used to run the step into the unit's timeout, and the sources after it
    were skipped every hour until it cleared."""
    finished_pcaps(gateway, *(f"tv-{n}.pcap" for n in range(1, 6)))
    conn = db.connect(gateway.db_path)
    now = [0.0]

    def extract(path):  # ten minutes of tshark per file
        now[0] += 600
        return []

    warnings = []
    files, *_ = ingest.ingest_pcaps(
        conn, gateway, extract, warnings.append, none_live, budget=1500, clock=lambda: now[0]
    )
    assert files == 3 and warnings == ["pcaps: 2 file(s) deferred to the next run (time budget)"]
    done = [r[0] for r in conn.execute("SELECT name FROM pcaps_done WHERE error IS NULL ORDER BY name")]
    assert done == ["tv-1.pcap", "tv-2.pcap", "tv-3.pcap"]
    warnings.clear()
    files, *_ = ingest.ingest_pcaps(
        conn, gateway, extract, warnings.append, none_live, budget=1500, clock=lambda: now[0]
    )
    assert files == 2 and warnings == []


def test_the_cheap_sources_are_read_before_the_pcaps(gateway, lg, monkeypatch):
    order = []
    monkeypatch.setattr(ingest, "ingest_oddport", lambda conn, lines: order.append("oddport") or 0)

    def extract(path):
        order.append("pcaps")
        return []

    ingest.run(gateway, lg, extract=extract, oddport_lines=fake_oddport, lock=False)
    assert order == ["oddport", "pcaps"]


def test_coverage_counts_only_the_pcaps_that_were_read(tmp_path):
    conn = db.connect(str(tmp_path / "c.db"))
    conn.executemany(
        "INSERT INTO pcaps_done(name, done_at, error) VALUES (?,?,?)",
        [("a.pcap", 100.0, None), ("b.pcap", 100.0, "tshark rc=1"), ("c.pcap", 100.0, None)],
    )
    assert queries.coverage(conn, 0.0, 200.0, now=200.0)["sources"]["pcaps"]["rows"] == 2


def test_a_connection_attempt_is_counted_once_however_often_its_syn_is_retransmitted(gateway, lg):
    finished_pcaps(gateway, "tv-1.pcap")
    conn = db.connect(gateway.db_path)
    rows = [
        Syn(t, TV, 40002, "192.168.8.69", 80) for t in (1.0, 2.0, 4.0)
    ]  # one dropped probe, retried by the kernel
    rows += [Syn(5.0, TV, 40003, "192.168.8.69", 80), Syn(6.0, TV, 40004, "192.168.8.70", 80)]
    assert ingest.ingest_pcaps(conn, gateway, lambda path: rows, print, none_live) == (1, 0, 0, 3)
    probes = conn.execute("SELECT t, dst FROM lanprobe ORDER BY t").fetchall()
    assert probes == [(1.0, "192.168.8.69"), (5.0, "192.168.8.69"), (6.0, "192.168.8.70")]


@pytest.mark.parametrize(("syns", "hellos", "warned"), [(25, 0, True), (25, 1, False), (19, 0, False)])
def test_many_443_attempts_and_not_one_hello_is_a_warning(gateway, lg, syns, hellos, warned):
    """The 2026-10-27 fault looked like twelve quiet hours: zero hellos must be judged for plausibility."""
    finished_pcaps(gateway, "tv-1.pcap")
    conn = db.connect(gateway.db_path)
    rows = [Syn(float(i), TV, 40000 + i, "203.0.113.10", 443) for i in range(syns)]
    rows += [TlsHello(100.0, TV, 40000, "203.0.113.10", 443, "h.example")] * hellos
    warnings = []
    ingest.ingest_pcaps(conn, gateway, lambda path: rows, warnings.append, none_live)
    assert conn.execute("SELECT syn443_rows, error FROM pcaps_done").fetchone() == (syns, None)
    expected = [
        f"tv-1.pcap: {syns} connection attempts to :443 but no TLS hello: check the capture filter and tshark"
    ]
    assert warnings == (expected if warned else [])


def test_a_hostile_server_name_is_cut_and_never_becomes_a_host(gateway, lg):
    """A 70 KB ClientHello name is stored as evidence, bounded, and is not a public name, so the
    hosts table (keyed by name and never pruned) does not grow a row for it."""
    finished_pcaps(gateway, "tv-1.pcap")
    conn = db.connect(gateway.db_path)
    rows = [TlsHello(1793020100.0, TV, 40001, "1.2.3.4", 443, "a" * 70_000 + ".example")]
    assert ingest.ingest_pcaps(conn, gateway, lambda path: rows, print, none_live) == (1, 1, 0, 0)
    assert conn.execute("SELECT length(sni) FROM tls").fetchone() == (2000,)
    ingest.refresh_hosts(conn, lg)
    assert conn.execute("SELECT COUNT(*) FROM hosts").fetchone() == (0,)


def test_a_request_to_the_gateway_is_stored_once_from_nginx_not_again_from_the_pcap(gateway, lg):
    """The URL-filter hosts resolve to the gateway, so exactly the requests the filter exists to watch
    would otherwise land twice; nginx's copy carries the status and bytes."""
    Path(gateway.gfts_log).write_text(GFTS_TV_ALLOWED)
    uri = "/fts/gftsDownload.lge?biz_code=APP_STORE&func_code=APP_ICON&file_path=/a.png"
    rows = [
        HttpRequest(1793020102.0, TV, gateway.gw_ip, "GET", "ngfts.lge.com", uri, "-"),
        HttpRequest(1793020103.0, TV, "23.5.6.43", "GET", "example.net", "/plain", "ua"),
    ]
    st = ingest.run(gateway, lg, extract=lambda path: rows, oddport_lines=fake_oddport, lock=False)
    assert (st.http, st.gfts) == (1, 1)
    conn = db.connect(gateway.db_path, readonly=True)
    assert conn.execute("SELECT host, src, status FROM http ORDER BY host").fetchall() == [
        ("example.net", "pcap", None),
        ("ngfts.lge.com", "gfts", 200),
    ]
    assert conn.execute("SELECT http_n FROM hosts WHERE name='ngfts.lge.com'").fetchone() == (1,)


def test_only_finished_pcaps_are_read_whatever_their_names_sort_like(gateway, lg):
    """A stray file that sorts last is not 'the live one', and the live file is never read."""
    (Path(gateway.pcap_dir) / "zz.pcap").write_bytes(EMPTY_PCAP)
    seen = []

    def extract(path):
        seen.append(os.path.basename(path))
        return []

    live = {os.path.realpath(os.path.join(gateway.pcap_dir, "tv-20261026-0900.pcap"))}
    st = ingest.run(gateway, lg, extract=extract, oddport_lines=fake_oddport, lock=False, live=lambda d: live)
    assert (st.pcaps, seen, st.warnings) == (2, ["tv-20261026-0800.pcap", "zz.pcap"], [])


def test_unknown_live_file_skips_the_pcaps_with_one_warning_and_the_other_sources_land(gateway, lg):
    st = ingest.run(
        gateway, lg, extract=fake_extract, oddport_lines=fake_oddport, lock=False, live=lambda d: None
    )
    assert (st.pcaps, st.flows, st.dns, st.gfts) == (0, 2, 2, 2)
    assert len(st.warnings) == 1 and "cannot tell which file tcpdump is writing" in st.warnings[0]
    conn = db.connect(gateway.db_path, readonly=True)
    assert conn.execute("SELECT COUNT(*) FROM pcaps_done").fetchone()[0] == 0


def test_with_no_tcpdump_running_every_file_is_finished(gateway, lg):
    seen = []

    def extract(path):
        seen.append(os.path.basename(path))
        return []

    st = ingest.run(
        gateway, lg, extract=extract, oddport_lines=fake_oddport, lock=False, live=lambda d: set()
    )
    assert st.pcaps == 2 and seen == ["tv-20261026-0800.pcap", "tv-20261026-0900.pcap"]


def test_gfts_rows_carry_no_method_and_long_fields_are_cut(gateway, lg):
    """The nginx log format has no $request_method, so the column is NULL rather than an invented GET."""
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
    assert row.fetchall() == [(None, "gfts", 2000, 300, 200, 6488)]


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
        "@1793020400",
    ]  # first run looks back 30 days, then resumes from the second of the last event (inclusive)
    assert conn.execute("SELECT last_t FROM ingest_state WHERE source='oddport'").fetchone() == (
        1793020400.0,
    )


def test_journal_is_asked_for_every_boots_kernel_lines_and_failures_raise():
    """`-k` implies `-b`, which hid the lines between the last run and each reboot; `_TRANSPORT=kernel`
    is the same filter without that. A non-zero exit with an error is raised; one with nothing on
    stderr is a quiet journal (some versions exit 1 for no matches)."""
    argvs = []

    def fake_run(rc, stdout="", stderr=""):
        def run(argv, **kw):
            argvs.append(argv)
            return subprocess.CompletedProcess(argv, rc, stdout, stderr)

        return run

    assert ingest.journal_oddport_lines("@1793020200", fake_run(0, "a\nb\n")) == ["a", "b"]
    argv = argvs[0]
    assert (
        "-k" not in argv and "_TRANSPORT=kernel" in argv and argv[argv.index("--since") + 1] == "@1793020200"
    )
    assert argv[argv.index("-g") + 1] == "tvgw-oddport"
    assert ingest.journal_oddport_lines("-30d", fake_run(1)) == []
    with pytest.raises(RuntimeError, match="journalctl rc=2: No persistent journal"):
        ingest.journal_oddport_lines("-30d", fake_run(2, stderr="No persistent journal was found.\n"))


def test_a_journal_that_cannot_be_read_is_a_warning_and_the_source_is_not_read(gateway, lg):
    """Today 'Unexpected ports: none' is the evidence decision 17 rests on; a dead reader must not
    look like a quiet month."""

    def no_journal(since):
        raise OSError("journalctl: not found")

    st = ingest.run(gateway, lg, extract=fake_extract, oddport_lines=no_journal, lock=False)
    assert [w for w in st.warnings if w.startswith("oddport: OSError")] == st.warnings and len(
        st.warnings
    ) == 1
    assert (st.flows, st.dns, st.gfts, st.oddport) == (2, 2, 2, 0)
    conn = db.connect(gateway.db_path, readonly=True)
    assert "oddport" not in json.loads(db.get_meta(conn, "sources_read"))


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
    ingest.ingest_oddport(conn, journal)  # the inclusive cursor re-reads both: neither is stored twice
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


@pytest.mark.parametrize(
    ("line", "row"),
    [
        (
            "2026-10-26T09:19:00-05:00\tActive Standby\tcom.webos.app.home",
            ("Active Standby", "com.webos.app.home"),
        ),
        ("2026-10-26T09:19:00-05:00\tScreen Off\t", ("Screen Off", None)),
        ("2026-10-26T09:19:00-05:00\tunreachable\t", ("unreachable", None)),
        ("2026-10-26T09:19:00-05:00\tunknown\t", ("unknown", None)),
        ("2026-10-26T09:19:00-05:00 Active youtube.leanback.v4", ("Active", "youtube.leanback.v4")),
    ],
)
def test_tvstate_power_states_with_spaces_are_stored_whole(gateway, line, row):
    """webOS reports 'Active Standby' and 'Screen Off'; split on spaces those read as power 'Active'
    with app 'Standby ...'. tvgw-analyze writes tabs now; the space-separated lines already written
    still read, with the state as the first word."""
    Path(gateway.tvcheck_history).write_text(line + "\n")
    conn = db.connect(gateway.db_path)
    assert ingest.ingest_tvstate(conn, gateway) == 1
    stored = conn.execute("SELECT t, power, app FROM tvstate").fetchone()
    assert stored == (local("2026-10-26T09:19:00-05:00"), *row)


def test_a_history_line_read_again_replaces_the_reading(gateway):
    """The same stamp seen twice (a cursor reset, a replayed log) is one row carrying the later value."""
    Path(gateway.tvcheck_history).write_text("2026-10-26T09:19:00-05:00\tActive\tyoutube.leanback.v4\n")
    conn = db.connect(gateway.db_path)
    ingest.ingest_tvstate(conn, gateway)
    conn.execute("DELETE FROM ingest_state WHERE source='tvstate'")
    Path(gateway.tvcheck_history).write_text("2026-10-26T09:19:00-05:00\tActive Standby\t\n")
    ingest.ingest_tvstate(conn, gateway)
    assert conn.execute("SELECT power, app FROM tvstate").fetchall() == [("Active Standby", None)]


def test_the_repeated_hour_of_the_fall_back_night_is_two_readings(gateway):
    """01:20 happens twice on 2026-11-01; the UTC offset in the stamp keeps the readings apart."""
    Path(gateway.tvcheck_history).write_text(
        "2026-11-01T01:20:00-05:00\tActive\t\n2026-11-01T01:20:00-06:00\tActive\t\n"
    )
    conn = db.connect(gateway.db_path)
    assert ingest.ingest_tvstate(conn, gateway) == 2
    first, second = (r[0] for r in conn.execute("SELECT t FROM tvstate ORDER BY t"))
    assert second - first == 3600


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


def test_read_errors_are_not_settings_and_do_not_flap_the_history(gateway):
    """lgwebos writes 'ERR <type> <msg>' for a key the TV stalled on, and the hardware suite judges
    the latest option.livePlus: a transient read error must not become a stored value."""
    conn = db.connect(gateway.db_path)
    ingest.ingest_tvstate(conn, gateway)  # the fixture's reading: livePlus off, zipcode 10001
    Path(gateway.tvcheck_txt).write_text(
        "read 2026-10-26T10:19:00-05:00\noption.livePlus = ERR TimeoutError x\noption.zipcode = 10001\n"
        "info = ERR OSError y\n"
    )
    ingest.ingest_tvstate(conn, gateway)
    Path(gateway.tvcheck_txt).write_text(
        "read 2026-10-26T11:19:00-05:00\noption.livePlus = off\noption.zipcode = 10001\n"
    )
    ingest.ingest_tvstate(conn, gateway)
    rows = conn.execute("SELECT key, value FROM tvsettings ORDER BY t, key").fetchall()
    assert rows == [("option.livePlus", "off"), ("option.zipcode", "10001")]


@pytest.mark.parametrize("text", ["", "no read header\noption.a = 1\n", "read yesterday\noption.a = 1\n"])
def test_unusable_tvcheck_txt_records_nothing(gateway, text):
    Path(gateway.tvcheck_txt).write_text(text)
    conn = db.connect(gateway.db_path)
    ingest.ingest_tvstate(conn, gateway)
    assert conn.execute("SELECT COUNT(*) FROM tvsettings").fetchone()[0] == 0


# ---- policy history ---------------------------------------------------------------------------------
def test_current_rules_kinds_are_stable_and_missing_files_are_tolerated(gateway):
    warnings = []
    rules, readable = ingest.current_rules(gateway, warnings.append)
    assert rules == {
        ("adguard", "@@||us.lgtvsdp.com^"),
        ("adguard", "||alphonso.tv^"),
        ("adguard", "||ngfts.lge.com^$dnsrewrite=10.10.10.1"),
        ("gfts-block", "biz_code=(PREMIUM|CDP|LGSHOPPING|MAS|IBS)([&_]|$)"),
        ("block4", "203.0.113.9"),
    }
    assert readable == {"adguard", "gfts-block", "block4"} and warnings == []
    os.remove(gateway.nginx_conf)
    rules, readable = ingest.current_rules(gateway, warnings.append)
    assert ("block4", "203.0.113.9") in rules  # one missing file must not hide the rest
    assert readable == {"adguard", "block4"}  # ... but its kind is unknown, not empty, and said so
    assert (
        len(warnings) == 1
        and warnings[0].startswith("rules: gfts-block:")
        and gateway.nginx_conf in warnings[0]
    )
    os.remove(gateway.block4)
    os.remove(gateway.adguard_yaml)
    warnings.clear()
    assert ingest.current_rules(gateway, warnings.append) == (set(), set())
    assert sorted(w.split(":")[1].strip() for w in warnings) == ["adguard", "block4", "gfts-block"]


def test_unparseable_adguard_yaml_is_unknown_not_empty(gateway):
    Path(gateway.adguard_yaml).write_text("user_rules: [unclosed\n  - : :\n")
    warnings = []
    rules, readable = ingest.current_rules(gateway, warnings.append)
    assert "adguard" not in readable and not any(k == "adguard" for k, _ in rules)
    assert readable == {"gfts-block", "block4"}
    assert warnings == ["rules: adguard: not in a form we can read"]


def test_unreadable_kinds_keep_their_rules_open(tmp_path):
    conn = db.connect(str(tmp_path / "r.db"))
    a, b = ("adguard", "||a^"), ("block4", "203.0.113.9")
    assert ingest.ingest_rules(conn, {a, b}, now=100.0) == (2, 0)
    # adguard could not be read this time: its rule is not retired, the readable block4 one is
    assert ingest.ingest_rules(conn, set(), readable={"block4"}, now=200.0) == (0, 1)
    q = "SELECT text, removed_at FROM rules ORDER BY text"
    assert conn.execute(q).fetchall() == [("203.0.113.9", 200.0), ("||a^", None)]
    # with no explicit `readable`, only the kinds present in `current` count as read
    assert ingest.ingest_rules(conn, {b}, now=300.0) == (1, 0)
    assert conn.execute("SELECT COUNT(*) FROM rules WHERE removed_at IS NULL").fetchone()[0] == 2


def test_rule_history_timestamps_and_multiple_removals(tmp_path):
    conn = db.connect(str(tmp_path / "r.db"))
    a, b = ("adguard", "||a^"), ("adguard", "||b^")
    assert ingest.ingest_rules(conn, {a, b}, now=100.0) == (2, 0)
    assert ingest.ingest_rules(conn, {a, b}, now=200.0) == (0, 0)
    assert ingest.ingest_rules(conn, set(), readable={"adguard"}, now=300.0) == (0, 2)
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
    assert ingest.refresh_hosts(conn, lg) == 1  # the empty qname is ignored
    q = "SELECT first_seen, last_seen, category, dns_n, tls_n, http_n, last_blocked, last_rule FROM hosts"
    assert conn.execute(q).fetchall() == [(100.0, 400.0, "LG core", 2, 1, 1, 1, "||b^")]
    wm = json.loads(db.get_meta(conn, "hosts_wm"))
    assert wm == {"dns": [3, 250.0], "tls": [1, 100.0], "http": [1, 400.0]}  # last counted id and its time
    assert ingest.refresh_hosts(conn, lg) == 0  # nothing past the watermarks
    assert conn.execute(q).fetchall() == [(100.0, 400.0, "LG core", 2, 1, 1, 1, "||b^")]
    conn.execute("INSERT INTO dns(t, qname, blocked, rule) VALUES (500.0, 'x.lgtvsdp.com', 0, '@@c')")
    conn.execute(
        "INSERT INTO tls(t, dst, dport, sport, sni) VALUES (50.0, '1.1.1.1', 443, 2, 'y.lgtvsdp.com')"
    )
    assert ingest.refresh_hosts(conn, lg) == 2  # only the new rows are counted, added to the old totals
    q = "SELECT name, first_seen, last_seen, dns_n, tls_n, http_n, last_blocked, last_rule FROM hosts ORDER BY name"
    assert conn.execute(q).fetchall() == [
        ("x.lgtvsdp.com", 100.0, 500.0, 3, 1, 1, 0, "@@c"),
        ("y.lgtvsdp.com", 50.0, 50.0, 0, 1, 0, None, None),
    ]


def test_reused_row_ids_after_a_table_emptied_trigger_a_rebuild_not_a_silent_miss(tmp_path, lg):
    """Reproduced: prune emptied dns, the next rows got ids 1 and 2, below the watermark of 3, and
    refresh_hosts counted nothing. The watermark remembers its row's time; a gone or re-stamped row
    means the ids are not the ones that were counted."""
    conn = db.connect(str(tmp_path / "h.db"))
    conn.executemany(
        "INSERT INTO dns(t, qname, blocked) VALUES (?, ?, 0)",
        [(100.0, "a.lgtvsdp.com"), (200.0, "b.lgtvsdp.com"), (300.0, "c.lgtvsdp.com")],
    )
    ingest.refresh_hosts(conn, lg)
    conn.execute("DELETE FROM dns")  # everything pruned
    conn.executemany(
        "INSERT INTO dns(t, qname, blocked) VALUES (?, ?, 0)", [(400.0, "d.example"), (500.0, "e.example")]
    )
    assert conn.execute("SELECT MAX(id) FROM dns").fetchone() == (2,)  # SQLite reused the ids
    ingest.refresh_hosts(conn, lg)
    names = {r[0]: r[1] for r in conn.execute("SELECT name, dns_n FROM hosts")}
    assert names == {"d.example": 1, "e.example": 1}  # rebuilt: the pruned names are gone too


def test_an_intact_watermark_row_means_no_rebuild(tmp_path, lg):
    conn = db.connect(str(tmp_path / "h.db"))
    conn.execute("INSERT INTO dns(t, qname, blocked) VALUES (100.0, 'a.lgtvsdp.com', 0)")
    ingest.refresh_hosts(conn, lg)
    stmts: list[str] = []
    conn.set_trace_callback(stmts.append)
    ingest.refresh_hosts(conn, lg)
    assert not any(s.startswith("DELETE FROM hosts") for s in stmts)


def test_the_bare_id_watermark_of_earlier_versions_is_accepted_once_and_rewritten(tmp_path, lg):
    conn = db.connect(str(tmp_path / "h.db"))
    conn.execute("INSERT INTO dns(t, qname, blocked) VALUES (100.0, 'a.lgtvsdp.com', 0)")
    conn.execute("INSERT INTO hosts(name, dns_n, category) VALUES ('a.lgtvsdp.com', 7, 'LG core')")
    db.set_meta(conn, "hosts_wm", json.dumps({"dns": 1, "tls": 0, "http": 0}))
    stmts: list[str] = []
    conn.set_trace_callback(stmts.append)
    assert ingest.refresh_hosts(conn, lg) == 0
    assert not any(s.startswith("DELETE FROM hosts") for s in stmts)
    assert conn.execute("SELECT dns_n FROM hosts").fetchone() == (7,)  # trusted, not recounted
    assert json.loads(db.get_meta(conn, "hosts_wm")) == {
        "dns": [1, 100.0],
        "tls": [0, None],
        "http": [0, None],
    }


def test_a_late_row_never_lowers_last_seen(tmp_path, lg):
    conn = db.connect(str(tmp_path / "h.db"))
    conn.execute("INSERT INTO dns(t, qname, blocked) VALUES (500.0, 'x.lgtvsdp.com', 0)")
    ingest.refresh_hosts(conn, lg)
    conn.execute("INSERT INTO dns(t, qname, blocked) VALUES (50.0, 'x.lgtvsdp.com', 0)")  # flushed late
    ingest.refresh_hosts(conn, lg)
    assert conn.execute("SELECT first_seen, last_seen, dns_n FROM hosts").fetchone() == (50.0, 500.0, 2)


def test_refresh_hosts_rebuilds_without_a_watermark_and_recategorizes(tmp_path, lg):
    conn = db.connect(str(tmp_path / "h.db"))
    conn.execute("INSERT INTO dns(t, qname, blocked) VALUES (200.0, 'x.lgtvsdp.com', 0)")
    conn.execute(
        "INSERT INTO hosts(name, dns_n, tls_n, http_n, category) VALUES ('x.lgtvsdp.com', 9, 9, 9, 'stale')"
    )
    conn.execute(
        "INSERT INTO hosts(name, dns_n, tls_n, http_n, category) VALUES ('gone.example', 1, 1, 1, 'x')"
    )
    conn.execute(
        "INSERT INTO hosts(name, dns_n, tls_n, http_n, category, notes) VALUES ('kept.example', 4, 0, 0, 'x', 'mine')"
    )
    ingest.refresh_hosts(conn, lg)  # no watermark: rebuilt from the base tables
    q = "SELECT name, category, dns_n, tls_n, http_n, notes FROM hosts ORDER BY name"
    assert conn.execute(q).fetchall() == [
        ("kept.example", "Other", 0, 0, 0, "mine"),  # hand-annotated rows survive, counters rebuilt
        ("x.lgtvsdp.com", "LG core", 1, 0, 0, None),
    ]
    conn.execute("UPDATE hosts SET category='stale' WHERE name='x.lgtvsdp.com'")
    stmts: list[str] = []
    conn.set_trace_callback(stmts.append)
    ingest.refresh_hosts(conn, lg)  # the same profile: every name is left as it is
    assert not any(s.startswith("UPDATE hosts SET category") for s in stmts)
    conn.set_trace_callback(None)
    conn.execute("DELETE FROM meta WHERE key='hosts_profile'")  # what a changed profile looks like
    ingest.refresh_hosts(conn, lg)  # a profile change shows up without the name being seen again
    assert conn.execute("SELECT category FROM hosts WHERE name='x.lgtvsdp.com'").fetchone() == ("LG core",)
    db.set_meta(conn, "hosts_wm", "not json")  # a damaged watermark means rebuild, not crash
    ingest.refresh_hosts(conn, lg)
    assert conn.execute("SELECT dns_n FROM hosts WHERE name='x.lgtvsdp.com'").fetchone() == (1,)


# ---- retention --------------------------------------------------------------------------------------
def test_prune_cutoffs_per_table(tmp_path):
    conn = db.connect(str(tmp_path / "p.db"))
    now, cutoff = 1_800_000_000.0, 1_800_000_000.0 - 10 * DAY
    old, new = cutoff - 1, cutoff + 1
    conn.executemany("INSERT INTO flows(t_end, dst) VALUES (?, 'd')", [(old,), (new,)])
    conn.executemany("INSERT INTO dns(t, qname, blocked) VALUES (?, 'q', 0)", [(old,), (new,)])
    conn.executemany("INSERT INTO tls(t, sni) VALUES (?, 's')", [(old,), (new,)])
    conn.executemany("INSERT INTO http(t, host, src) VALUES (?, 'h', 'pcap')", [(old,), (new,)])
    conn.executemany("INSERT INTO lanprobe(t, dst) VALUES (?, 'd')", [(old,), (new,)])
    conn.executemany("INSERT INTO oddport(t) VALUES (?)", [(old,), (new,)])
    assert ingest.prune(conn, days=10, now=now) == 6  # one stale row in each of six tables
    for table in ("flows", "dns", "tls", "http", "lanprobe", "oddport"):
        assert conn.execute(f"SELECT COUNT(*) FROM {table}").fetchone()[0] == 1, table
        assert conn.execute(f"SELECT COUNT(*) FROM {table} WHERE id IS NOT NULL").fetchone()[0] == 1


def test_prune_done_marks_without_pcap_dir_go_after_seven_days(tmp_path):
    conn = db.connect(str(tmp_path / "p.db"))
    now = 1_800_000_000.0
    done_cut = now - 7 * DAY
    conn.executemany(
        "INSERT INTO pcaps_done(name, done_at) VALUES (?, ?)",
        [("old", done_cut - 10), ("new", done_cut + 10)],
    )
    ingest.prune(conn, days=10, now=now)
    assert conn.execute("SELECT name FROM pcaps_done").fetchall() == [("new",)]


def test_prune_keeps_done_marks_of_pcaps_still_on_disk(tmp_path):
    """Dropping the mark of a file that is still there would ingest it a second time."""
    conn = db.connect(str(tmp_path / "p.db"))
    pcaps = tmp_path / "pcap"
    pcaps.mkdir()
    (pcaps / "still-here.pcap").write_bytes(b"x")
    now = 1_800_000_000.0
    stale = now - 8 * DAY
    conn.executemany(
        "INSERT INTO pcaps_done(name, done_at) VALUES (?, ?)",
        [("still-here.pcap", stale), ("gone.pcap", stale), ("recent.pcap", now - DAY)],
    )
    ingest.prune(conn, days=10, now=now, pcap_dir=str(pcaps))
    names = conn.execute("SELECT name FROM pcaps_done ORDER BY name").fetchall()
    assert names == [("recent.pcap",), ("still-here.pcap",)]


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
