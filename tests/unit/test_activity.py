"""(activity) Passive TV activity from the TV port's byte counters: the intervals, the hours on, the
calibration against the TV's own readings, and the two places that use it once it is calibrated (the
standby section) or when the TV gives no readings at all (the hour classifier, the plain brief)."""

import io
import json

import pytest

from tvgw import activity, cli, db, ledger, plain, queries
from tvgw.config import Settings

H0 = 1792990800  # 2026-10-26 00:00 CDT, hour-aligned
STEP = 600
STREAM = 8_000_000  # bytes per 10 minutes: over activity.STREAM_BYTES
TRICKLE = 20_000  # under activity.AWAKE_BYTES


class Port:
    """The sampler's rows for the TV port: one call per 10 minutes, the counter running on."""

    def __init__(self, conn, boot="boot-1"):
        self.conn, self.boot, self.tx = conn, boot, 1_000_000

    def run(self, t0: float, steps: int, per_step: int) -> float:
        """`steps` intervals from t0, each carrying `per_step` bytes to the TV; returns the end time."""
        t = t0
        for _ in range(steps + 1):
            ledger.record_sample(self.conn, ledger.Sample(t=t, boot_id=self.boot, tv_tx_bytes=self.tx))
            self.tx += per_step
            t += STEP
        self.tx -= per_step  # the last sample's interval was not run
        self.conn.commit()
        return t - STEP


@pytest.fixture
def conn(tmp_path):
    c = db.connect(str(tmp_path / "s.db"))
    yield c
    c.close()


def reading(conn, t, power, app=None):
    conn.execute("INSERT INTO tvstate(t, power, app) VALUES (?,?,?)", (t, power, app))
    conn.commit()


# ---- the intervals --------------------------------------------------------------------------------
def test_each_interval_is_streaming_awake_or_quiet_by_what_the_tv_downloaded(conn):
    port = Port(conn)
    port.run(H0, 1, STREAM)
    port.run(H0 + STEP, 1, 300_000)
    port.run(H0 + 2 * STEP, 1, TRICKLE)
    found = activity.buckets(conn, H0, H0 + 3 * STEP)
    assert [(iv.start - H0, iv.end - H0, iv.label) for iv in found] == [
        (0, 600, "streaming"),
        (600, 1200, "awake"),
        (1200, 1800, "quiet"),
    ]
    # three connections opened in a quiet interval make it awake
    for i in range(3):
        conn.execute(
            "INSERT INTO flows(t_start, t_end, proto, dst, dport, sport, bytes_up, bytes_down)"
            " VALUES (?, ?, 'tcp', '203.0.113.9', 443, ?, 100, 100)",
            (H0 + 1300 + i, H0 + 1400, 50000 + i),
        )
    assert activity.buckets(conn, H0, H0 + 3 * STEP)[-1].label == "awake"


def test_a_reboot_a_reset_counter_and_a_gap_split_the_pairs(conn):
    Port(conn, "boot-1").run(H0, 1, STREAM)  # 0 .. 600
    Port(conn, "boot-2").run(H0 + 2 * STEP, 1, STREAM)  # a new boot at 1200, its counter from scratch
    later = Port(conn, "boot-2")
    later.tx = 99_000_000
    gap_end = H0 + 3 * STEP + int(activity.MAX_GAP) + STEP  # more than MAX_GAP after the last sample
    end = later.run(gap_end, 1, STREAM)
    reset = Port(conn, "boot-2")  # the same boot, a counter lower than the last: not a download
    reset.run(end + STEP, 1, STREAM)
    found = activity.buckets(conn, H0, H0 + 86400)
    assert [(iv.start - H0, iv.label) for iv in found] == [
        (0, "streaming"),
        (1200, "streaming"),
        (gap_end - H0, "streaming"),
        (end + STEP - H0, "streaming"),
    ]
    assert activity.buckets(conn, H0 + 86400, H0 + 2 * 86400) == []


def test_hours_on_counts_streaming_and_awake_and_is_none_without_samples(conn):
    port = Port(conn)
    end = port.run(H0, 3, STREAM)  # 30 minutes streaming
    end = port.run(end, 3, 300_000)  # 30 minutes awake
    port.run(end, 6, TRICKLE)  # an hour quiet
    assert activity.hours_on(conn, H0, H0 + 2 * 3600) == pytest.approx(1.0)
    assert activity.hours_on(conn, H0 + 900, H0 + 1800) == pytest.approx(0.25)  # clipped to the window
    assert activity.hours_on(conn, H0 + 86400, H0 + 2 * 86400) is None
    assert activity.streaming_hours(conn, H0, H0 + 2 * 3600) == {H0}


# ---- the calibration -------------------------------------------------------------------------------
def calibration_days(conn, port, start, hours=40, quiet=None):
    """`hours` hours of the TV streaming with an app in front, then `quiet` hours (as many by default)
    unreachable and quiet, each with one reading in its middle: 40 of each is enough for both of
    calibrate's bars. Returns the end."""
    t = start
    for _ in range(hours):
        reading(conn, t + 1800, "Active", "com.netflix.ninja")
        t = port.run(t, 6, STREAM)
    for _ in range(hours if quiet is None else quiet):
        reading(conn, t + 1800, "unreachable")
        t = port.run(t, 6, TRICKLE)
    return t


def test_calibration_meets_its_bars_only_on_enough_readings_that_agree(conn):
    port = Port(conn)
    end = calibration_days(conn, port, H0)
    got = activity.calibrate(conn, end)
    assert (got["active"], got["active_on"], got["unreachable"], got["unreachable_quiet"]) == (40, 40, 40, 40)
    assert got["met"] and got["active_share"] == 1.0 and got["active_low"] == pytest.approx(0.912, abs=5e-4)
    # launcher and input readings say nothing about streaming, and are not counted
    reading(conn, H0 + 1200, "Active", "com.webos.app.home")
    reading(conn, H0 + 1300, "Active", "com.webos.app.hdmi1")
    assert activity.calibrate(conn, end)["active"] == 40
    # one reading out of 41 in the wrong kind of interval: 97.6%, with a lower bound of 87.4%
    reading(conn, H0 + 40 * 3600 + 900, "Active", "com.netflix.ninja")
    assert not activity.calibrate(conn, end)["met"]
    # a store without enough readings never calibrates, however well they agree
    assert not activity.calibrate(conn, H0 + 10 * 3600)["met"]
    lines = activity.summary_lines(activity.calibrate(conn, end))
    assert lines[1] == (
        "Active readings with an app in front, in a streaming or awake interval: 40 of 41: 97.6% (at least"
        " 87.4%); at least 90% needed"
    )
    assert lines[-1].startswith("not met")


@pytest.mark.parametrize(("hours", "quiet", "met"), [(35, 40, True), (34, 40, False), (40, 34, False)])
def test_no_miss_in_35_readings_of_each_kind_is_the_least_that_meets_the_bar(conn, hours, quiet, met):
    end = calibration_days(conn, Port(conn), H0, hours=hours, quiet=quiet)
    assert activity.calibrate(conn, end)["met"] is met


def test_twenty_three_readings_of_twenty_four_no_longer_meet_the_bar(conn):
    """L2-15: 23 of 24 is 95.8% and met a bar of 95%, though the share could be 79.8%: a sample that
    small cannot carry the bar the brief's standby section then rests on."""
    port = Port(conn)
    end = calibration_days(conn, port, H0, hours=23, quiet=40)
    reading(conn, H0 + 23 * 3600 + 900, "Active", "com.netflix.ninja")  # in a quiet hour
    got = activity.calibrate(conn, end)
    assert not got["met"]
    assert (got["active_on"], got["active"]) == (23, 24) and got[
        "unreachable_low"
    ] >= activity.CALIBRATION_BAR
    assert "23 of 24: 95.8% (at least 79.8%)" in activity.summary_lines(got)[1]


# ---- standby: a session the readings missed ----------------------------------------------------------
def missed_session(conn, port, t):
    """Two hourly readings that say off, and a 20-minute stream between them that both missed: the
    stream's lookups and connections, and one standby lookup in a quiet moment."""
    reading(conn, t, "unreachable")
    reading(conn, t + 3600, "unreachable")
    s = port.run(t, 2, TRICKLE)
    s = port.run(s, 2, STREAM)  # t+1200 .. t+2400
    port.run(s, 2, TRICKLE)
    for k in range(4):
        conn.execute(
            "INSERT INTO dns(t, qname, qtype, answers, blocked) VALUES (?, 'cdn.example', 'A', 'A:203.0.113.9', 0)",
            (t + 1300 + k * 60,),
        )
        conn.execute(
            "INSERT INTO flows(t_start, t_end, proto, dst, dport, sport, bytes_up, bytes_down)"
            " VALUES (?, ?, 'tcp', '203.0.113.9', 443, ?, 2000, 9000000)",
            (t + 1310 + k * 60, t + 2300, 51000 + k),
        )
    conn.execute(
        "INSERT INTO dns(t, qname, qtype, answers, blocked) VALUES (?, 'standby.example', 'A', 'A:203.0.113.7', 0)",
        (t + 300,),
    )
    conn.commit()


def test_a_missed_session_stays_in_standby_until_the_counters_are_calibrated(conn):
    port = Port(conn)
    t = H0 + 5 * 86400
    missed_session(conn, port, t)
    before = queries.standby_activity(conn, t, t + 3601)
    assert before == {"off_hours": 1.0, "lookups": 5, "conns": 4, "bytes_up": 8000}


def test_a_missed_session_leaves_standby_once_the_counters_are_calibrated(conn, lg):
    port = Port(conn)
    end = calibration_days(conn, port, H0)
    t = end + 7200
    port.run(end, 12, TRICKLE)
    missed_session(conn, port, t)
    got = queries.standby_activity(conn, t, t + 3601)
    assert got == {
        "off_hours": round(2400 / 3600, 1),
        "lookups": 1,  # the standby lookup, not the stream's four
        "conns": 0,
        "bytes_up": 0,
        "streaming_left_out_hours": round(1200 / 3600, 1),
    }
    day = queries.datetime.fromtimestamp(t).strftime("%Y-%m-%d")
    o = queries.brief(conn, day, lg)
    buf = io.StringIO()
    cli.render_brief(o, out=buf)
    (line,) = [x for x in buf.getvalue().splitlines() if x.startswith("While off/asleep")]
    assert line.endswith("; 0.3 h of streaming between readings left out")


# ---- a TV with no readings -----------------------------------------------------------------------------
def test_a_store_without_readings_gets_demand_hours_from_the_port(conn, lg):
    """A Samsung store: no tvstate at all. An hour the port streamed is on with demand; an hour it was
    quiet is off. With readings present they decide, and the port's hours count for nothing."""
    port = Port(conn)
    end = port.run(H0, 6, STREAM)
    port.run(end, 6, TRICKLE)
    c = ledger.Classifier(conn, lg, H0, H0 + 2 * 3600)
    on, off = c.facts(H0), c.facts(H0 + 3600)
    assert (on.on, on.streaming, off.on) == (True, True, False)
    assert c.classify(H0 + 3600) == ("off", ["no reading says the TV was on"])
    cls, why = c.classify(H0)
    assert cls in ("clean", "confounded") and (cls == "confounded" or "streaming traffic" in why)
    reading(conn, H0 - 86400, "unreachable")  # one reading anywhere: the TV gives readings
    c = ledger.Classifier(conn, lg, H0, H0 + 2 * 3600)
    assert not c.facts(H0).on and not c.facts(H0).streaming


def test_the_plain_brief_estimates_hours_on_from_the_port_when_the_tv_gives_no_readings(conn):
    port = Port(conn)
    end = port.run(H0 + 3600, 12, STREAM)  # two hours
    port.run(end, 6, TRICKLE)
    o = {"since": H0, "until": H0 + 86400, "tvstate": []}
    got = cli._activity(conn, o)
    assert got == plain.Activity(hours=pytest.approx(2.0), estimated=True)
    assert "on about 2 hours (estimated from its traffic)" in plain._the_tv({"categories": []}, got)
    # readings, when there are any, are the TV's own word
    o["tvstate"] = [{"time": "20:00", "power": "Active", "app": "x"}]
    assert cli._activity(conn, o) == plain.Activity(hours=1.0)
    assert cli._activity(conn, {"since": H0 + 86400, "until": H0 + 2 * 86400, "tvstate": []}) is None


def test_the_command_prints_the_calibration(tmp_path, capsys):
    s = Settings(db_path=str(tmp_path / "s.db"), state_dir=str(tmp_path))
    c = db.connect(s.db_path)
    calibration_days(c, Port(c), H0 - 3 * 86400)  # ends before the suite's pinned clock (conftest.NOW)
    c.close()
    conf = tmp_path / "tvgw.conf"
    conf.write_text(f"DB_PATH={s.db_path}\nSTATE_DIR={s.state_dir}\n")
    assert cli.main(["--conf", str(conf), "activity", "calibrate"]) == 0
    out = capsys.readouterr().out.splitlines()
    assert out[0] == "tvgw activity calibrate: 14 days, 480 intervals (streaming 240, awake 0, quiet 240)"
    assert out[-1].startswith("met:")
    assert cli.main(["--conf", str(conf), "activity", "calibrate", "--json"]) == 0
    assert json.loads(capsys.readouterr().out)["met"] is True
    assert cli.main(["--conf", str(conf), "activity", "calibrate", "--days", "0"]) == 2
