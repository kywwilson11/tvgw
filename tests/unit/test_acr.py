"""(acr) The ACR red line: the upload test, daily and hourly, on synthetic flows built from published
statistics (acr_synth), and the adtech port wall's counter and samples. Every fixture of the November
research's section 13, 1.7, behaves as its row says, and the shapes that are not ACR stay silent."""

import random
import sqlite3

import acr_synth as synth
import pytest

from tvgw import analyst, db, ingest, queries

SEEDS = range(1, 9)


@pytest.fixture()
def conn(tmp_path):
    c = db.connect(str(tmp_path / "acr.db"))
    yield c
    c.close()


def day0() -> float:
    """Midnight of the fixture day, computed under the test time zone (not at import time)."""
    return queries.day_bounds("2026-10-26")[0]


def findings(conn, lg, a: float | None = None, b: float | None = None) -> list[dict]:
    a = day0() if a is None else a
    return queries.acr_uploader(conn, a, a + 86400 if b is None else b, lg)


def report(conn, lg, a: float | None = None, b: float | None = None) -> dict:
    a = day0() if a is None else a
    b = a + 86400 if b is None else b
    return queries.window_report(conn, a, b, lg, now=b + 3600)


def acr_lines(o: dict) -> list[str]:
    return [x for x in o["red_lines"] if x.startswith(("ACR-shaped upload:", "ACR port attempts:"))]


# ---- the fixtures are the published shape ---------------------------------------------------------


@pytest.mark.parametrize("seed", SEEDS)
def test_the_synthetic_acr_day_has_the_published_shape(seed):
    """13, 1.1: 10-39 MB up on an ACR day at 7-17 times the bytes down, about a third of the connections
    carrying fingerprints, none of them as long as 951 s plus the FIN linger."""
    flows = synth.lg_acr_day(random.Random(seed), day0() + 8 * 3600)
    up, down = sum(f.payload_up for f in flows), sum(f.payload_down for f in flows)
    assert 10e6 <= up <= 39e6 and 6.5 <= up / down <= 17
    assert {f.dport for f in flows} == {synth.ACR_PORT} and all(f.sni in synth.ACR_NAMES for f in flows)
    fingerprints = [f for f in flows if f.payload_up > 10_000]
    assert 0.25 <= len(fingerprints) / len(flows) <= 0.42
    assert max(f.t_end - f.t_start for f in flows) <= synth.FP_DURATION[2] + synth.FIN_LINGER


# ---- B and B': what fires ---------------------------------------------------------------------------


@pytest.mark.parametrize("seed", SEEDS)
def test_an_acr_day_fires_the_daily_test_once_for_the_whole_day(conn, lg, seed):
    synth.insert(conn, synth.lg_acr_day(random.Random(seed), day0() + 8 * 3600))
    (x,) = findings(conn, lg)
    assert (x["key"], x["dport"], x["bucket"], x["named"]) == ("alphonso.tv", 4431, "day", True)
    assert x["payload_up"] >= queries.ACR_DAILY[0] and x["conns"] >= queries.ACR_DAILY[2]
    assert x["ratio"] >= queries.ACR_DAILY[1]
    assert x["hours"] >= 12  # the hourly twin passed in nearly every hour of the 14, folded into one line


def test_the_red_line_reads_as_the_spec_says(conn, lg):
    synth.insert(conn, synth.lg_acr_day(random.Random(1), day0() + 8 * 3600))
    conn.execute("INSERT INTO tvsettings(t, key, value) VALUES (?, 'option.livePlus', 'off')", (day0(),))
    (line,) = acr_lines(report(conn, lg))
    x = findings(conn, lg)[0]
    assert line == (
        f"ACR-shaped upload: alphonso.tv:4431 sent {x['payload_up'] / 1e6:.1f} MB up ({x['ratio']:.1f}x down)"
        f" in {x['conns']} connections on 2026-10-26; Live Plus reads off"
    )


@pytest.mark.parametrize("seed", SEEDS)
def test_an_unnamed_acr_day_is_keyed_by_its_servers_slash_24(conn, lg, seed):
    """No hello captured (a capture gap, or a firmware that hides the name): the /24 and the port still
    make one cell, and an unnamed server is in scope whatever it is."""
    synth.insert(conn, synth.lg_acr_day(random.Random(seed), day0() + 8 * 3600, named=False))
    (x,) = findings(conn, lg)
    assert (x["key"], x["dport"], x["bucket"], x["named"]) == ("203.0.113.0/24", 4431, "day", False)


@pytest.mark.parametrize("seed", SEEDS)
def test_a_ninety_minute_stub_fires_the_hourly_test_and_not_the_daily(conn, lg, seed):
    """1.1's 04-22: a day of 0.7 MB is under the daily megabyte; its busiest hour is ACR-shaped."""
    hour = day0() + 22 * 3600
    synth.insert(conn, synth.lg_acr_stub(random.Random(seed), hour))
    (x,) = findings(conn, lg)
    assert (x["key"], x["bucket"], x["start"], x["hours"]) == ("alphonso.tv", "hour", hour, 1)
    assert sum(1 for c in findings(conn, lg) if c["bucket"] == "day") == 0
    (line,) = acr_lines(report(conn, lg))
    assert " in hour 22 of 2026-10-26; Live Plus reads unknown (no reading)" in line


def test_a_telemetry_hour_fires_hourly_only(conn, lg):
    """Nine connections are too few for a day, and one upload-heavy hour on a telemetry name is a true
    ACR-shaped alarm: the line says what it saw, not that it is ACR."""
    hour = day0() + 15 * 3600
    synth.insert(conn, synth.telemetry_burst(random.Random(3), hour))
    (x,) = findings(conn, lg)
    assert (x["key"], x["dport"], x["bucket"], x["conns"]) == ("example.com", 443, "hour", 9)
    assert x["ratio"] >= 19


def test_flows_are_bucketed_by_their_start(conn, lg):
    """A connection's t_end runs late by its idle timeout; an ACR connection opened at 23:58 belongs to
    the day and hour it opened in."""
    late = day0() + 86400 - 120
    flows = [
        synth.connection(late - i * 10, 400.0, "203.0.113.41", 4431, 30_000 + i, [100_000], [5_000], None)
        for i in range(6)
    ]
    synth.insert(conn, flows)
    assert all(f.t_end >= day0() + 86400 for f in flows[:1])
    (x,) = findings(conn, lg)
    assert (x["bucket"], x["start"]) == ("hour", day0() + 23 * 3600)
    assert findings(conn, lg, day0() + 86400) == []


# ---- what must stay silent --------------------------------------------------------------------------


@pytest.mark.parametrize("seed", SEEDS)
def test_a_streaming_day_is_silent_named_or_not(conn, lg, seed):
    """YouTube's best lab day, 11.8 MB up at 3.07: out of scope when named (Streaming is expected), and
    under the 4x ratio when unnamed. The video itself is all down."""
    synth.insert(conn, synth.streaming_day(random.Random(seed), day0() + 8 * 3600))
    assert findings(conn, lg) == []
    conn.execute("DELETE FROM tls")
    conn.commit()
    assert findings(conn, lg) == []
    assert acr_lines(report(conn, lg)) == []


@pytest.mark.parametrize("seed", SEEDS)
def test_a_hue_style_poller_is_a_timer_and_nothing_more(conn, lg, seed):
    """A 30 s portal probe and a 90 s bridge poll: periodic rows, no red line, no mark and no reason to
    ask the analyst (cadence marks 15 non-ACR domains in the lab set)."""
    synth.insert(conn, synth.hue_style_poller(random.Random(seed), day0() + 9 * 3600))
    o = report(conn, lg)
    periodic = {x["name"]: x for x in o["beacons"]}
    assert {"portal.example.net", "bridge.example.org"} <= set(periodic)
    assert 27 <= periodic["portal.example.net"]["period"] <= 33
    assert not any(x["acr_like"] for x in o["beacons"]) and o["acr_upload"] == []
    assert acr_lines(o) == []
    pack = {"tv": {"readings_on": 3}, "red_lines": o["red_lines"], "periodic": o["beacons"], "_judged": {}}
    assert analyst.novelty(pack) == []


def test_the_control_plane_the_mqtt_hub_and_a_firmware_download_are_silent(conn, lg):
    flows, lookups = synth.lg_control_plane(random.Random(4), day0() + 8 * 3600)
    flows += synth.mqtt_long(day0() + 7 * 3600) + synth.firmware_download(day0() + 3 * 3600)
    synth.insert(conn, flows, lookups)
    assert findings(conn, lg) == []
    assert acr_lines(report(conn, lg)) == []


def test_a_name_in_an_expected_category_is_out_of_scope_whatever_it_uploads(conn, lg):
    flows = synth.lg_acr_day(random.Random(2), day0() + 8 * 3600)
    synth.insert(conn, [synth.Flow(**{**f.__dict__, "sni": "api.netflix.com"}) for f in flows])
    assert lg.is_expected("api.netflix.com") and findings(conn, lg) == []


def test_the_gateway_and_the_home_lan_are_never_a_cell(conn, lg):
    flows = [
        synth.connection(day0() + 3600 + i * 60, 30.0, dst, 443, 31_000 + i, [80_000], [1_000], None)
        for i in range(30)
        for dst in ("10.10.10.1", "192.168.1.20")
    ]
    synth.insert(conn, flows)
    assert findings(conn, lg) == []


def test_a_timer_on_an_acr_shaped_cell_is_marked(conn, lg):
    """The cadence is an attribute of a finding: a periodic row whose name and port are an ACR-shaped
    cell carries the mark; the line still comes from the upload, once."""
    start = day0() + 8 * 3600
    flows = [
        synth.connection(
            start + i * 60, 40.0, "203.0.113.41", 4431, 30_000 + i, [60_000], [4_000], "tk.alphonso.tv"
        )
        for i in range(30)
    ]
    synth.insert(conn, flows)
    o = report(conn, lg)
    (b,) = [x for x in o["beacons"] if x["name"] == "tk.alphonso.tv"]
    assert b["acr_like"] and 59 <= b["period"] <= 61
    assert len(acr_lines(o)) == 1


# ---- A: the port wall ---------------------------------------------------------------------------------


def wall(conn, packets_by_t: list[tuple[float, int]]) -> None:
    """fw_counters snapshots of the wall's counter, as `tvgw verify --record` stores them."""
    conn.executemany(
        "INSERT INTO fw_counters(t, rule, packets, bytes) VALUES (?, ?, ?, 0)",
        [(t, queries.ADTECH_RULE, n) for t, n in packets_by_t],
    )
    conn.commit()


def adport_line(t: float, dst: str, dport: int) -> str:
    return (
        f"{t:.6f} gateway kernel: tvgw-adport: IN=eth0 OUT=wlan0 SRC=10.10.10.17 DST={dst} LEN=60 "
        f"TOS=0x00 PREC=0x00 TTL=63 ID=1 DF PROTO=TCP SPT=41000 DPT={dport} WINDOW=1 RES=0x00 SYN"
    )


def test_the_wall_counter_drives_the_second_form_and_names_the_address_from_dns(conn, lg):
    """lg_control_plane with its 4001 connection reset: no flow row, a counter step and a sample, and
    the sample's address is named by the A answers of the week before."""
    flows, lookups = synth.lg_control_plane(random.Random(5), day0() + 8 * 3600, with_4001=False)
    early = [(t - 3 * 86400, q, qt, a, b) for t, q, qt, a, b in lookups[:3]]  # three days before
    synth.insert(conn, flows, early)
    t = day0() + 9 * 3600
    lines = [adport_line(t, synth.CONTROL_SERVER, 4001), adport_line(t + 1, "198.51.100.99", 8883)]
    assert ingest.ingest_adport(conn, lambda since: lines) == 2
    wall(conn, [(day0() + 600, 0), (day0() + 12 * 3600, 7)])
    o = report(conn, lg)
    assert findings(conn, lg) == []  # nothing upload-shaped: only the wall speaks
    assert o["acr_port"]["attempts"] == 7 and o["acr_port"]["ports"] == [4001, 8883]
    assert o["acr_port"]["names"] == ["bl-server.alphonso.tv", "clockskew.alphonso.tv", "prov-lg.alphonso.tv"]
    (line,) = acr_lines(o)
    assert line == (
        "ACR port attempts: 7 connections to TCP 4001, 8883 rejected (bl-server.alphonso.tv,"
        " clockskew.alphonso.tv, prov-lg.alphonso.tv; 1 address(es) no lookup named)"
    )


def test_a_wall_step_with_no_sample_and_a_sample_with_no_answer(conn, lg):
    wall(conn, [(day0() + 600, 2), (day0() + 1200, 5)])  # three packets, the journal lost the samples
    (line,) = acr_lines(report(conn, lg))
    assert (
        line
        == "ACR port attempts: 3 connections to TCP one of 4001, 4431, 4445, 4447, 8180, 8883 rejected (no lookup)"
    )
    conn.execute("DELETE FROM fw_counters")
    # a sample the counter does not show (a re-apply zeroed it): the samples are a floor
    ingest.ingest_adport(conn, lambda since: [adport_line(day0() + 3600, "203.0.113.200", 4431)])
    conn.commit()
    (line,) = acr_lines(report(conn, lg))
    assert line == "ACR port attempts: 1 connections to TCP 4431 rejected (no lookup)"


def test_an_answer_names_an_address_only_as_a_whole_token(conn, lg):
    synth.insert(conn, [], [(day0() + 60, "near.example", "A", "A:203.0.113.45", 0)])
    ingest.ingest_adport(conn, lambda since: [adport_line(day0() + 3600, "203.0.113.4", 4431)])
    conn.commit()
    assert report(conn, lg)["acr_port"]["names"] == []


def test_an_answer_older_than_a_week_names_nothing(conn, lg):
    old = day0() - (queries.KNOWN_DAYS + 1) * 86400
    synth.insert(conn, [], [(old, "old.example", "A", "A:203.0.113.7", 0)])
    ingest.ingest_adport(conn, lambda since: [adport_line(day0() + 3600, "203.0.113.7", 4431)])
    conn.commit()
    assert report(conn, lg)["acr_port"]["names"] == []


def test_a_quiet_wall_raises_nothing(conn, lg):
    wall(conn, [(day0() + 600, 4), (day0() + 1200, 4)])
    o = report(conn, lg)
    assert o["acr_port"]["attempts"] == 0 and acr_lines(o) == []


def test_the_wall_has_a_line_among_the_firewall_counters():
    assert ("LG adtech port", "adtech ports") in queries.FW_LINES
    assert queries.ADTECH_RULE == "LG adtech port"


# ---- the adport source and its table --------------------------------------------------------------


def test_adport_samples_are_ingested_once_with_a_cursor(conn):
    lines = [
        adport_line(1793020300.25, "203.0.113.8", 4431),
        "junk without a time",
        adport_line(1793020301.5, "203.0.113.8", 4445),
    ]
    assert ingest.ingest_adport(conn, lambda since: lines) == 2
    assert ingest.ingest_adport(conn, lambda since: lines) == 0  # the cursor skips what is stored
    rows = conn.execute("SELECT t, proto, dst, dport FROM adport ORDER BY t").fetchall()
    assert rows == [(1793020300.25, "TCP", "203.0.113.8", 4431), (1793020301.5, "TCP", "203.0.113.8", 4445)]
    assert conn.execute("SELECT last_t FROM ingest_state WHERE source='adport'").fetchone() == (1793020301.5,)


def test_the_journal_reader_asks_for_the_adport_prefix():
    seen = []

    def run(argv, **kw):
        seen.append(argv)
        import subprocess

        return subprocess.CompletedProcess(argv, 0, stdout="a\n", stderr="")

    from conftest import JOURNAL_ADPORT_LINES  # the autouse fixture has stood the module's one in

    assert JOURNAL_ADPORT_LINES("@1", run) == ["a"]
    assert seen[0][seen[0].index("-g") + 1] == "tvgw-adport"


def test_the_hourly_run_reads_adport_and_prunes_it(gateway, lg, monkeypatch):
    from conftest import fake_extract, fake_oddport

    st = ingest.run(
        gateway,
        lg,
        extract=fake_extract,
        oddport_lines=fake_oddport,
        gate_lines=lambda since: [],
        adport_lines=lambda since: [adport_line(1793020250.0, "203.0.113.8", 4431)],
        lock=False,
    )
    assert st.adport == 1 and not st.warnings
    conn = db.connect(gateway.db_path)
    assert conn.execute("SELECT dport FROM adport").fetchall() == [(4431,)]
    assert ingest.prune(conn, 1, now=1793020250.0 + 2 * 86400) >= 1
    assert conn.execute("SELECT COUNT(*) FROM adport").fetchone() == (0,)
    conn.close()


def test_a_schema_8_store_gains_the_adport_table_and_keeps_its_rows(tmp_path):
    path = tmp_path / "v8.db"
    old = sqlite3.connect(path)
    v8 = db.SCHEMA.replace(
        "CREATE TABLE IF NOT EXISTS adport(id INTEGER PRIMARY KEY, t REAL NOT NULL, proto TEXT, dst TEXT,\n"
        "  dport INTEGER, raw TEXT);\nCREATE INDEX IF NOT EXISTS adport_t ON adport(t);\n",
        "",
    )
    assert "adport" not in v8
    old.executescript(v8)
    old.execute("INSERT INTO meta VALUES ('schema', '8')")
    old.execute("INSERT INTO oddport(t, proto, dst, dport) VALUES (1, 'TCP', '203.0.113.1', 8080)")
    old.commit()
    old.close()
    conn = db.connect(str(path))
    assert db.get_meta(conn, "schema") == str(db.SCHEMA_VERSION) and db.SCHEMA_VERSION >= 9
    assert [r[1] for r in conn.execute("PRAGMA table_info(adport)")] == [
        "id",
        "t",
        "proto",
        "dst",
        "dport",
        "raw",
    ]
    indexes = {r[0] for r in conn.execute("SELECT name FROM sqlite_master WHERE type='index'")}
    assert "adport_t" in indexes and conn.execute("SELECT COUNT(*) FROM oddport").fetchone() == (1,)
    assert "adport" in db.counts(conn)
    plan = " ".join(
        r[3] for r in conn.execute("EXPLAIN QUERY PLAN SELECT * FROM adport WHERE t >= 1 AND t < 2")
    )
    assert "adport_t" in plan
    conn.close()
    db.connect(str(path)).close()  # a second open is a no-op


def test_a_reader_of_a_store_no_writer_has_migrated_still_gets_a_brief(tmp_path, lg):
    """`tvgw brief` opens the store read-only and applies no schema: between a deploy and the first
    ingest the adport table may not exist yet, and the counter alone must still speak."""
    path = tmp_path / "v8.db"
    db.connect(str(path)).close()
    raw = sqlite3.connect(path)
    raw.execute("DROP TABLE adport")
    raw.execute(
        "INSERT INTO fw_counters(t, rule, packets, bytes) VALUES (?, 'LG adtech port', 0, 0)", (day0() + 60,)
    )
    raw.execute(
        "INSERT INTO fw_counters(t, rule, packets, bytes) VALUES (?, 'LG adtech port', 2, 0)", (day0() + 660,)
    )
    raw.commit()
    raw.close()
    ro = db.connect(str(path), readonly=True)
    o = report(ro, lg)
    ro.close()
    assert o["acr_port"]["attempts"] == 2 and o["acr_port"]["samples"] == 0
    assert any(x.startswith("ACR port attempts: 2 connections") for x in o["red_lines"])
